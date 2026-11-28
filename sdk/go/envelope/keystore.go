package envelope

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	synccrypto "github.com/yellowdking/synctool/sdk/go/crypto"
)

const (
	// DefaultSeenMsgRetentionDays is the 30-day rolling replay protection window (ENVELOPE_AND_SDK.md §5.1).
	DefaultSeenMsgRetentionDays = 30
	// DefaultSeenMsgMinEntries guarantees at least 4,096 most recent msg_ids are retained.
	DefaultSeenMsgMinEntries = 4096
	// DefaultSeenMsgMaxEntries caps SeenMsgs growth and advances ReplayWatermarkTS on eviction.
	DefaultSeenMsgMaxEntries = 65536

	manifestCacheAADPrefix = "synctool-v1/manifest-cache:"
)

// DeviceCard represents a trusted paired device persisted in KeyStore (ENVELOPE_AND_SDK.md §5.1).
// MailboxID, OutboundDepositToken, and InboundTokenID are conditionally optional (empty when paired under --spool=off).
type DeviceCard struct {
	DeviceID             string `json:"device_id"`
	Label                string `json:"label"`
	Platform             string `json:"platform,omitempty"`
	SignPK               string `json:"sign_pk"` // 43-char b64u (32B)
	KEMPK                string `json:"kem_pk"`  // 43-char b64u (32B)
	IssuedAt             int64  `json:"issued_at"`
	CardSig              string `json:"card_sig"` // 86-char b64u (64B)
	RelayOrigin          string `json:"relay_origin,omitempty"`
	RelayID              string `json:"relay_id,omitempty"`
	MailboxID            string `json:"mailbox_id,omitempty"`
	OutboundDepositToken string `json:"outbound_deposit_token,omitempty"`
	InboundTokenID       string `json:"inbound_token_id,omitempty"`
	InboundTokenHash     string `json:"inbound_token_hash,omitempty"` // 64-char SHA-256 hex for self-healing
	PendingTokenDelete   bool   `json:"pending_token_delete,omitempty"`
	PairedAt             int64  `json:"paired_at"`
	Revoked              bool   `json:"revoked"`
}

// SeenMsgEntry tracks a delivered msg_id in the rolling replay window.
type SeenMsgEntry struct {
	MsgID     string `json:"msg_id"`
	CreatedAt int64  `json:"created_at"`
	SeenAt    int64  `json:"seen_at"`
}

// CachedManifestEntry caches decrypted part_id=0 Manifest summaries by item_id
// so repeated ListInbox refreshes do not exhaust the relay's 16-download limit.
type CachedManifestEntry struct {
	ItemID         string   `json:"item_id"`
	CachedAt       int64    `json:"cached_at"`
	ExpiresAt      int64    `json:"expires_at"`
	ManifestSHA256 string   `json:"manifest_sha256,omitempty"` // Verified raw manifest SHA-256 hex
	Manifest       Manifest `json:"manifest"`
}

type diskCachedManifestEntry struct {
	ItemID             string    `json:"item_id"`
	CachedAt           int64     `json:"cached_at"`
	ExpiresAt          int64     `json:"expires_at"`
	ManifestSHA256     string    `json:"manifest_sha256,omitempty"`
	SealedManifestB64U string    `json:"sealed_manifest_b64u,omitempty"`
	Manifest           *Manifest `json:"manifest,omitempty"`
}

type diskRelayProfile struct {
	RelayProfile
	Origin string `json:"origin,omitempty"`
}

// TransferCheckpoint tracks resumable per-part upload/download progress.
type TransferCheckpoint struct {
	Key          string `json:"key"` // "<direction>:<msg_id>:<part_id>"
	Direction    string `json:"direction"`
	MsgID        string `json:"msg_id"`
	ItemID       string `json:"item_id,omitempty"`
	PartID       uint32 `json:"part_id"`
	NextTxIdx    int    `json:"next_tx_idx"`
	NextBlockIdx uint32 `json:"next_block_idx"`
	UploadToken  string `json:"upload_token,omitempty"`
	ExpiresAt    int64  `json:"expires_at"`
}

// KeyStore is the minimal host storage interface (ENVELOPE_AND_SDK.md §5.1).
type KeyStore interface {
	LoadOrCreateMasterSeed() ([32]byte, error)
	GetLocalLabel() (string, error)
	SetLocalLabel(label string) error

	GetRelayProfile(relayIDOrAlias string) (*RelayProfile, error)
	GetDefaultRelayProfile() (*RelayProfile, error)
	ListRelayProfiles() ([]RelayProfile, error)
	SaveRelayProfile(profile RelayProfile) error

	ListDevices() ([]DeviceCard, error)
	GetDevice(deviceID string) (*DeviceCard, error)
	PutDevice(card DeviceCard) error
	DeleteDevice(deviceID string) error

	HasSeenMsgID(msgID string) (bool, error)
	MarkSeenMsgID(msgID string, createdAt, seenAt int64) error

	GetCachedManifest(itemID string) (*CachedManifestEntry, error)
	PutCachedManifest(entry CachedManifestEntry) error
	DeleteCachedManifest(itemID string) error
	PruneCachedManifests(activeItemIDs map[string]struct{}) error

	GetCheckpoint(direction, msgID string, partID uint32) (*TransferCheckpoint, error)
	PutCheckpoint(cp TransferCheckpoint) error
	DeleteCheckpoint(direction, msgID string, partID uint32) error
}

type fileKeyStoreState struct {
	Version             int                            `json:"version"`
	MasterSeedB64U      string                         `json:"master_seed_b64u"`
	LocalLabel          string                         `json:"local_label,omitempty"`
	ReplayWatermarkTS   int64                          `json:"replay_watermark_ts,omitempty"`
	PendingTokenDeletes []string                       `json:"pending_token_deletes,omitempty"`
	Relays              map[string]RelayProfile        `json:"relays"`
	Devices             map[string]DeviceCard          `json:"devices"`
	SeenMsgs            map[string]SeenMsgEntry        `json:"seen_msgs"`
	ManifestCache       map[string]CachedManifestEntry `json:"-"`
	Checkpoints         map[string]TransferCheckpoint  `json:"checkpoints"`
}

type diskKeyStoreWire struct {
	Version             int                                `json:"version"`
	MasterSeedB64U      string                             `json:"master_seed_b64u"`
	LocalLabel          string                             `json:"local_label,omitempty"`
	ReplayWatermarkTS   int64                              `json:"replay_watermark_ts,omitempty"`
	PendingTokenDeletes []string                           `json:"pending_token_deletes,omitempty"`
	Relays              map[string]diskRelayProfile        `json:"relays"`
	Devices             map[string]DeviceCard              `json:"devices"`
	SeenMsgs            map[string]SeenMsgEntry            `json:"seen_msgs"`
	ManifestCache       map[string]diskCachedManifestEntry `json:"manifest_cache"`
	Checkpoints         map[string]TransferCheckpoint      `json:"checkpoints"`
}

// FileKeyStore is a secure local-file reference KeyStore implementation (dir 0700, file 0600,
// .keystore.lock cross-process coordination, 5x Windows rename retry, and LocalMetaKey cache sealing).
type FileKeyStore struct {
	mu          sync.Mutex
	dir         string
	path        string
	lastModUnix int64
	lastSize    int64
	st          *fileKeyStoreState
}

// NewFileKeyStore opens or initializes a FileKeyStore under dir (mode 0700).
func NewFileKeyStore(dir string) (*FileKeyStore, error) {
	if fi, err := os.Lstat(dir); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
			return nil, NewError(ErrCodeKeystoreError, false, 0, "keystore dir must be a real directory, not a symlink", nil)
		}
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, WrapError(ErrCodeKeystoreError, false, 0, "create keystore dir", err)
	}
	_ = os.Chmod(dir, 0o700)
	fs := &FileKeyStore{
		dir:  dir,
		path: filepath.Join(dir, "keystore.json"),
	}
	if err := fs.loadLocked(); err != nil {
		return nil, err
	}
	return fs, nil
}

// Dir returns the backing directory path for disk-backed FileKeyStore (or empty for in-memory store).
func (f *FileKeyStore) Dir() string {
	if f == nil {
		return ""
	}
	return f.dir
}

// NewMemoryKeyStore creates an in-memory KeyStore (convenient for tests and ephemeral tooling).
func NewMemoryKeyStore() *FileKeyStore {
	return &FileKeyStore{
		st: newEmptyState(),
	}
}

func newEmptyState() *fileKeyStoreState {
	return &fileKeyStoreState{
		Version:       1,
		Relays:        make(map[string]RelayProfile),
		Devices:       make(map[string]DeviceCard),
		SeenMsgs:      make(map[string]SeenMsgEntry),
		ManifestCache: make(map[string]CachedManifestEntry),
		Checkpoints:   make(map[string]TransferCheckpoint),
	}
}

// RenameWithRetry performs atomic file replacement with up to 5 bounded retries (10ms..160ms)
// to survive transient Windows Defender / Search Indexer sharing violations.
func RenameWithRetry(src, dst string) error {
	var lastErr error
	for attempt := 0; attempt < 5; attempt++ {
		if err := os.Rename(src, dst); err == nil {
			return nil
		} else {
			lastErr = err
		}
		if _, statErr := os.Stat(src); os.IsNotExist(statErr) {
			break
		}
		time.Sleep((10 * time.Millisecond) << attempt)
	}
	return lastErr
}

func (f *FileKeyStore) acquireLockFile() (func(), error) {
	if f.dir == "" {
		return func() {}, nil
	}
	lockPath := filepath.Join(f.dir, ".keystore.lock")
	deadline := time.Now().Add(5 * time.Second)
	delay := 5 * time.Millisecond
	for {
		lf, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			_, _ = lf.WriteString(strconv.Itoa(os.Getpid()))
			_ = lf.Close()
			return func() {
				_ = os.Remove(lockPath)
			}, nil
		}
		if fi, stErr := os.Stat(lockPath); stErr == nil && time.Since(fi.ModTime()) > 10*time.Second {
			_ = os.Remove(lockPath)
			continue
		}
		if time.Now().After(deadline) {
			return nil, WrapError(ErrCodeKeystoreError, true, 0, "timed out acquiring .keystore.lock", err)
		}
		time.Sleep(delay)
		if delay < 50*time.Millisecond {
			delay *= 2
		}
	}
}

func deriveLocalMetaKeyFromSeedB64U(seedB64U string) ([32]byte, bool) {
	var zero [32]byte
	if seedB64U == "" {
		return zero, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(seedB64U)
	if err != nil || len(raw) != 32 {
		clear(raw)
		return zero, false
	}
	dk, err := synccrypto.DeriveDeviceKeys(raw)
	clear(raw)
	if err != nil {
		return zero, false
	}
	out := dk.LocalMetaKey
	dk.Zero()
	return out, true
}

func sealCachedManifest(metaKey [32]byte, itemID string, m Manifest) (string, error) {
	raw, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(metaKey[:])
	if err != nil {
		return "", err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce, err := synccrypto.GenerateRandomBytes(12)
	if err != nil {
		return "", err
	}
	aad := []byte(manifestCacheAADPrefix + itemID)
	ct := aead.Seal(nonce, nonce, raw, aad)
	return base64.RawURLEncoding.EncodeToString(ct), nil
}

func openCachedManifest(metaKey [32]byte, itemID, sealedB64U string) (Manifest, bool) {
	var m Manifest
	combined, err := base64.RawURLEncoding.DecodeString(sealedB64U)
	if err != nil || len(combined) < 12+16 {
		return m, false
	}
	block, err := aes.NewCipher(metaKey[:])
	if err != nil {
		return m, false
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return m, false
	}
	aad := []byte(manifestCacheAADPrefix + itemID)
	pt, err := aead.Open(nil, combined[:12], combined[12:], aad)
	if err != nil {
		return m, false
	}
	if err := json.Unmarshal(pt, &m); err != nil {
		clear(pt)
		return m, false
	}
	clear(pt)
	return m, true
}

func (f *FileKeyStore) refreshIfChangedLocked() error {
	if f.path == "" {
		return nil
	}
	fi, err := os.Stat(f.path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return nil
	}
	if f.st != nil && fi.ModTime().UnixNano() == f.lastModUnix && fi.Size() == f.lastSize {
		return nil
	}
	return f.loadLocked()
}

func (f *FileKeyStore) loadLocked() error {
	if f.path == "" {
		if f.st == nil {
			f.st = newEmptyState()
		}
		return nil
	}
	fi, statErr := os.Lstat(f.path)
	if os.IsNotExist(statErr) {
		f.st = newEmptyState()
		f.lastModUnix = 0
		f.lastSize = 0
		return nil
	}
	if statErr != nil {
		return WrapError(ErrCodeKeystoreError, false, 0, "stat keystore file", statErr)
	}
	if !fi.Mode().IsRegular() {
		return NewError(ErrCodeKeystoreError, false, 0, "keystore.json must be a regular file", nil)
	}
	data, err := os.ReadFile(f.path)
	if err != nil {
		return WrapError(ErrCodeKeystoreError, false, 0, "read keystore file", err)
	}
	var wire diskKeyStoreWire
	if err := json.Unmarshal(data, &wire); err != nil {
		return WrapError(ErrCodeKeystoreError, false, 0, "parse keystore json", err)
	}
	st := &fileKeyStoreState{
		Version:             wire.Version,
		MasterSeedB64U:      wire.MasterSeedB64U,
		LocalLabel:          wire.LocalLabel,
		ReplayWatermarkTS:   wire.ReplayWatermarkTS,
		PendingTokenDeletes: wire.PendingTokenDeletes,
		Relays:              make(map[string]RelayProfile, len(wire.Relays)),
		Devices:             make(map[string]DeviceCard, len(wire.Devices)),
		SeenMsgs:            make(map[string]SeenMsgEntry, len(wire.SeenMsgs)),
		ManifestCache:       make(map[string]CachedManifestEntry, len(wire.ManifestCache)),
		Checkpoints:         make(map[string]TransferCheckpoint, len(wire.Checkpoints)),
	}
	if st.Version == 0 {
		st.Version = 1
	}
	for id, rp := range wire.Relays {
		prof := rp.RelayProfile
		if prof.Endpoint == "" && rp.Origin != "" {
			prof.Endpoint = rp.Origin
		}
		if prof.RelayID == "" {
			prof.RelayID = id
		}
		_ = prof.SyncPins()
		st.Relays[id] = prof
	}
	for id, dc := range wire.Devices {
		normID := strings.ToLower(strings.TrimSpace(id))
		dc.DeviceID = strings.ToLower(strings.TrimSpace(dc.DeviceID))
		if dc.DeviceID == "" {
			dc.DeviceID = normID
		}
		st.Devices[dc.DeviceID] = dc
	}
	for id, sm := range wire.SeenMsgs {
		normID := strings.ToLower(strings.TrimSpace(id))
		sm.MsgID = normID
		st.SeenMsgs[normID] = sm
	}
	for k, cp := range wire.Checkpoints {
		st.Checkpoints[k] = cp
	}

	metaKey, hasMetaKey := deriveLocalMetaKeyFromSeedB64U(st.MasterSeedB64U)
	defer clear(metaKey[:])
	for id, ce := range wire.ManifestCache {
		itemID := ce.ItemID
		if itemID == "" {
			itemID = id
		}
		if ce.SealedManifestB64U != "" {
			if hasMetaKey {
				if m, ok := openCachedManifest(metaKey, itemID, ce.SealedManifestB64U); ok {
					st.ManifestCache[itemID] = CachedManifestEntry{
						ItemID:         itemID,
						CachedAt:       ce.CachedAt,
						ExpiresAt:      ce.ExpiresAt,
						ManifestSHA256: ce.ManifestSHA256,
						Manifest:       m,
					}
				}
			}
			continue
		}
		if ce.Manifest != nil {
			st.ManifestCache[itemID] = CachedManifestEntry{
				ItemID:         itemID,
				CachedAt:       ce.CachedAt,
				ExpiresAt:      ce.ExpiresAt,
				ManifestSHA256: ce.ManifestSHA256,
				Manifest:       *ce.Manifest,
			}
		}
	}
	f.st = st
	f.lastModUnix = fi.ModTime().UnixNano()
	f.lastSize = fi.Size()
	return nil
}

func (f *FileKeyStore) mutateAndPersistLocked(mut func(*fileKeyStoreState) error) error {
	if f.path == "" {
		if f.st == nil {
			f.st = newEmptyState()
		}
		return mut(f.st)
	}
	unlock, err := f.acquireLockFile()
	if err != nil {
		return err
	}
	defer unlock()
	if err := f.refreshIfChangedLocked(); err != nil {
		return err
	}
	if err := mut(f.st); err != nil {
		return err
	}
	return f.writeDiskUnlocked()
}

func (f *FileKeyStore) persistLocked() error {
	if f.path == "" {
		return nil
	}
	unlock, err := f.acquireLockFile()
	if err != nil {
		return err
	}
	defer unlock()
	return f.writeDiskUnlocked()
}

func (f *FileKeyStore) writeDiskUnlocked() error {
	now := time.Now().Unix()
	for k, cp := range f.st.Checkpoints {
		if cp.ExpiresAt > 0 && cp.ExpiresAt < now {
			delete(f.st.Checkpoints, k)
		}
	}

	wire := diskKeyStoreWire{
		Version:             1,
		MasterSeedB64U:      f.st.MasterSeedB64U,
		LocalLabel:          f.st.LocalLabel,
		ReplayWatermarkTS:   f.st.ReplayWatermarkTS,
		PendingTokenDeletes: f.st.PendingTokenDeletes,
		Relays:              make(map[string]diskRelayProfile, len(f.st.Relays)),
		Devices:             f.st.Devices,
		SeenMsgs:            f.st.SeenMsgs,
		ManifestCache:       make(map[string]diskCachedManifestEntry, len(f.st.ManifestCache)),
		Checkpoints:         f.st.Checkpoints,
	}
	for id, rp := range f.st.Relays {
		_ = rp.SyncPins()
		wire.Relays[id] = diskRelayProfile{RelayProfile: rp}
	}

	metaKey, hasMetaKey := deriveLocalMetaKeyFromSeedB64U(f.st.MasterSeedB64U)
	defer clear(metaKey[:])
	for id, ce := range f.st.ManifestCache {
		itemID := ce.ItemID
		if itemID == "" {
			itemID = id
		}
		if hasMetaKey {
			if sealedB64, err := sealCachedManifest(metaKey, itemID, ce.Manifest); err == nil {
				wire.ManifestCache[itemID] = diskCachedManifestEntry{
					ItemID:             itemID,
					CachedAt:           ce.CachedAt,
					ExpiresAt:          ce.ExpiresAt,
					ManifestSHA256:     ce.ManifestSHA256,
					SealedManifestB64U: sealedB64,
				}
				continue
			}
		}
		mCopy := ce.Manifest
		wire.ManifestCache[itemID] = diskCachedManifestEntry{
			ItemID:         itemID,
			CachedAt:       ce.CachedAt,
			ExpiresAt:      ce.ExpiresAt,
			ManifestSHA256: ce.ManifestSHA256,
			Manifest:       &mCopy,
		}
	}

	data, err := json.MarshalIndent(wire, "", "  ")
	if err != nil {
		return WrapError(ErrCodeKeystoreError, false, 0, "marshal keystore", err)
	}
	tf, err := os.CreateTemp(f.dir, ".keystore-*.tmp")
	if err != nil {
		return WrapError(ErrCodeKeystoreError, false, 0, "create keystore tmp", err)
	}
	tmp := tf.Name()
	_ = tf.Chmod(0o600)
	if _, err := tf.Write(data); err != nil {
		_ = tf.Close()
		_ = os.Remove(tmp)
		return WrapError(ErrCodeKeystoreError, false, 0, "write keystore tmp", err)
	}
	if err := tf.Sync(); err != nil {
		_ = tf.Close()
		_ = os.Remove(tmp)
		return WrapError(ErrCodeKeystoreError, false, 0, "sync keystore tmp", err)
	}
	if err := tf.Close(); err != nil {
		_ = os.Remove(tmp)
		return WrapError(ErrCodeKeystoreError, false, 0, "close keystore tmp", err)
	}
	if err := RenameWithRetry(tmp, f.path); err != nil {
		_ = os.Remove(tmp)
		return WrapError(ErrCodeKeystoreError, false, 0, "rename keystore", err)
	}
	_ = os.Chmod(f.path, 0o600)
	if fi, err := os.Stat(f.path); err == nil {
		f.lastModUnix = fi.ModTime().UnixNano()
		f.lastSize = fi.Size()
	}
	return nil
}

func (f *FileKeyStore) LoadOrCreateMasterSeed() ([32]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var seed [32]byte
	if f.path != "" {
		_ = f.refreshIfChangedLocked()
	}
	if f.st.MasterSeedB64U != "" {
		raw, err := base64.RawURLEncoding.DecodeString(f.st.MasterSeedB64U)
		if err != nil || len(raw) != 32 {
			clear(raw)
			return seed, NewError(ErrCodeKeystoreError, false, 0, "corrupted master seed in keystore", nil)
		}
		copy(seed[:], raw)
		clear(raw)
		return seed, nil
	}
	var out [32]byte
	err := f.mutateAndPersistLocked(func(st *fileKeyStoreState) error {
		if st.MasterSeedB64U != "" {
			raw, err := base64.RawURLEncoding.DecodeString(st.MasterSeedB64U)
			if err != nil || len(raw) != 32 {
				clear(raw)
				return NewError(ErrCodeKeystoreError, false, 0, "corrupted master seed in keystore", nil)
			}
			copy(out[:], raw)
			clear(raw)
			return nil
		}
		generated, err := synccrypto.GenerateMasterSeed()
		if err != nil {
			return WrapError(ErrCodeKeystoreError, false, 0, "generate master seed", err)
		}
		st.MasterSeedB64U = base64.RawURLEncoding.EncodeToString(generated[:])
		out = generated
		return nil
	})
	if err != nil {
		clear(out[:])
		return seed, err
	}
	return out, nil
}

func (f *FileKeyStore) GetLocalLabel() (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	_ = f.refreshIfChangedLocked()
	return f.st.LocalLabel, nil
}

func (f *FileKeyStore) SetLocalLabel(label string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.mutateAndPersistLocked(func(st *fileKeyStoreState) error {
		st.LocalLabel = strings.TrimSpace(label)
		return nil
	})
}

func cloneRelayProfile(p RelayProfile) *RelayProfile {
	cp := p
	if len(p.SPKIPins) > 0 {
		cp.SPKIPins = append([]string(nil), p.SPKIPins...)
	}
	return &cp
}

func (f *FileKeyStore) GetRelayProfile(relayIDOrAlias string) (*RelayProfile, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	_ = f.refreshIfChangedLocked()
	if p, ok := f.st.Relays[relayIDOrAlias]; ok {
		return cloneRelayProfile(p), nil
	}
	for _, p := range f.st.Relays {
		if p.Alias != "" && strings.EqualFold(p.Alias, relayIDOrAlias) {
			return cloneRelayProfile(p), nil
		}
	}
	return nil, nil
}

func (f *FileKeyStore) GetDefaultRelayProfile() (*RelayProfile, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	_ = f.refreshIfChangedLocked()
	var first *RelayProfile
	for _, p := range f.st.Relays {
		if p.IsDefault {
			return cloneRelayProfile(p), nil
		}
		if first == nil || p.RelayID < first.RelayID {
			first = cloneRelayProfile(p)
		}
	}
	return first, nil
}

func (f *FileKeyStore) ListRelayProfiles() ([]RelayProfile, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	_ = f.refreshIfChangedLocked()
	out := make([]RelayProfile, 0, len(f.st.Relays))
	for _, p := range f.st.Relays {
		out = append(out, *cloneRelayProfile(p))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RelayID < out[j].RelayID })
	return out, nil
}

func (f *FileKeyStore) SaveRelayProfile(profile RelayProfile) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := profile.SyncPins(); err != nil {
		return err
	}
	return f.mutateAndPersistLocked(func(st *fileKeyStoreState) error {
		if profile.IsDefault || len(st.Relays) == 0 {
			profile.IsDefault = true
			for id, existing := range st.Relays {
				if id != profile.RelayID && existing.IsDefault {
					existing.IsDefault = false
					st.Relays[id] = existing
				}
			}
		}
		st.Relays[profile.RelayID] = *cloneRelayProfile(profile)
		return nil
	})
}

func (f *FileKeyStore) ListDevices() ([]DeviceCard, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	_ = f.refreshIfChangedLocked()
	out := make([]DeviceCard, 0, len(f.st.Devices))
	for _, c := range f.st.Devices {
		if !c.Revoked {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PairedAt < out[j].PairedAt })
	return out, nil
}

// ListAllDevices returns all stored DeviceCards including cards marked Revoked=true awaiting relay token deletion.
func (f *FileKeyStore) ListAllDevices() ([]DeviceCard, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	_ = f.refreshIfChangedLocked()
	out := make([]DeviceCard, 0, len(f.st.Devices))
	for _, c := range f.st.Devices {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PairedAt < out[j].PairedAt })
	return out, nil
}

func (f *FileKeyStore) GetDevice(deviceID string) (*DeviceCard, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	_ = f.refreshIfChangedLocked()
	id := strings.ToLower(strings.TrimSpace(deviceID))
	if c, ok := f.st.Devices[id]; ok {
		cp := c
		return &cp, nil
	}
	return nil, nil
}

func (f *FileKeyStore) PutDevice(card DeviceCard) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	card.DeviceID = strings.ToLower(strings.TrimSpace(card.DeviceID))
	return f.mutateAndPersistLocked(func(st *fileKeyStoreState) error {
		st.Devices[card.DeviceID] = card
		return nil
	})
}

func (f *FileKeyStore) DeleteDevice(deviceID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	id := strings.ToLower(strings.TrimSpace(deviceID))
	return f.mutateAndPersistLocked(func(st *fileKeyStoreState) error {
		delete(st.Devices, id)
		return nil
	})
}

// AddPendingTokenDelete records a superseded or revoked deposit token_id for deferred relay DELETE cleanup.
func (f *FileKeyStore) AddPendingTokenDelete(tokenID string) error {
	tok := strings.TrimSpace(tokenID)
	if tok == "" {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.mutateAndPersistLocked(func(st *fileKeyStoreState) error {
		if !slices.Contains(st.PendingTokenDeletes, tok) {
			st.PendingTokenDeletes = append(st.PendingTokenDeletes, tok)
		}
		return nil
	})
}

// ListPendingTokenDeletes returns queued deposit token_ids awaiting relay DELETE cleanup.
func (f *FileKeyStore) ListPendingTokenDeletes() ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	_ = f.refreshIfChangedLocked()
	return append([]string(nil), f.st.PendingTokenDeletes...), nil
}

// RemovePendingTokenDelete removes a cleaned-up deposit token_id from the pending queue.
func (f *FileKeyStore) RemovePendingTokenDelete(tokenID string) error {
	tok := strings.TrimSpace(tokenID)
	if tok == "" {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.mutateAndPersistLocked(func(st *fileKeyStoreState) error {
		idx := slices.Index(st.PendingTokenDeletes, tok)
		if idx >= 0 {
			st.PendingTokenDeletes = slices.Delete(st.PendingTokenDeletes, idx, idx+1)
		}
		return nil
	})
}

// GetReplayWatermark returns the highest CreatedAt timestamp evicted from SeenMsgs.
func (f *FileKeyStore) GetReplayWatermark() (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	_ = f.refreshIfChangedLocked()
	return f.st.ReplayWatermarkTS, nil
}

func (f *FileKeyStore) HasSeenMsgID(msgID string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	_ = f.refreshIfChangedLocked()
	_, ok := f.st.SeenMsgs[strings.ToLower(msgID)]
	return ok, nil
}

func (f *FileKeyStore) MarkSeenMsgID(msgID string, createdAt, seenAt int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	id := strings.ToLower(msgID)
	return f.mutateAndPersistLocked(func(st *fileKeyStoreState) error {
		st.SeenMsgs[id] = SeenMsgEntry{
			MsgID:     id,
			CreatedAt: createdAt,
			SeenAt:    seenAt,
		}
		// Prune entries older than 30 days when count exceeds DefaultSeenMsgMinEntries,
		// and enforce DefaultSeenMsgMaxEntries hard cap — advancing ReplayWatermarkTS on any eviction.
		if len(st.SeenMsgs) > DefaultSeenMsgMinEntries {
			cutoff := time.Now().Unix() - int64(DefaultSeenMsgRetentionDays*86400)
			entries := make([]SeenMsgEntry, 0, len(st.SeenMsgs))
			for _, e := range st.SeenMsgs {
				entries = append(entries, e)
			}
			sort.Slice(entries, func(i, j int) bool { return entries[i].SeenAt < entries[j].SeenAt })
			for _, e := range entries {
				needCapEvict := len(st.SeenMsgs) > DefaultSeenMsgMaxEntries
				if !needCapEvict && len(st.SeenMsgs) <= DefaultSeenMsgMinEntries {
					break
				}
				if needCapEvict || e.SeenAt < cutoff {
					if e.CreatedAt > st.ReplayWatermarkTS {
						st.ReplayWatermarkTS = e.CreatedAt
					}
					delete(st.SeenMsgs, e.MsgID)
				}
			}
		}
		return nil
	})
}

func (f *FileKeyStore) GetCachedManifest(itemID string) (*CachedManifestEntry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	_ = f.refreshIfChangedLocked()
	if e, ok := f.st.ManifestCache[itemID]; ok {
		cp := e
		return &cp, nil
	}
	return nil, nil
}

func (f *FileKeyStore) PutCachedManifest(entry CachedManifestEntry) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.mutateAndPersistLocked(func(st *fileKeyStoreState) error {
		st.ManifestCache[entry.ItemID] = entry
		return nil
	})
}

func (f *FileKeyStore) DeleteCachedManifest(itemID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.path != "" {
		_ = f.refreshIfChangedLocked()
	}
	if _, ok := f.st.ManifestCache[itemID]; !ok {
		return nil
	}
	return f.mutateAndPersistLocked(func(st *fileKeyStoreState) error {
		delete(st.ManifestCache, itemID)
		return nil
	})
}

func (f *FileKeyStore) PruneCachedManifests(activeItemIDs map[string]struct{}) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.path != "" {
		_ = f.refreshIfChangedLocked()
	}
	hasDead := false
	for id := range f.st.ManifestCache {
		if _, ok := activeItemIDs[id]; !ok {
			hasDead = true
			break
		}
	}
	if !hasDead {
		return nil
	}
	return f.mutateAndPersistLocked(func(st *fileKeyStoreState) error {
		for id := range st.ManifestCache {
			if _, ok := activeItemIDs[id]; !ok {
				delete(st.ManifestCache, id)
			}
		}
		return nil
	})
}

func checkpointKey(direction, msgID string, partID uint32) string {
	return direction + ":" + strings.ToLower(msgID) + ":" + strconv.FormatUint(uint64(partID), 10)
}

func (f *FileKeyStore) GetCheckpoint(direction, msgID string, partID uint32) (*TransferCheckpoint, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	_ = f.refreshIfChangedLocked()
	k := checkpointKey(direction, msgID, partID)
	if cp, ok := f.st.Checkpoints[k]; ok {
		c := cp
		return &c, nil
	}
	return nil, nil
}

func (f *FileKeyStore) PutCheckpoint(cp TransferCheckpoint) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp.Key = checkpointKey(cp.Direction, cp.MsgID, cp.PartID)
	return f.mutateAndPersistLocked(func(st *fileKeyStoreState) error {
		st.Checkpoints[cp.Key] = cp
		return nil
	})
}

func (f *FileKeyStore) DeleteCheckpoint(direction, msgID string, partID uint32) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.path != "" {
		_ = f.refreshIfChangedLocked()
	}
	k := checkpointKey(direction, msgID, partID)
	if _, ok := f.st.Checkpoints[k]; !ok {
		return nil
	}
	return f.mutateAndPersistLocked(func(st *fileKeyStoreState) error {
		delete(st.Checkpoints, k)
		return nil
	})
}
