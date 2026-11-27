package envelope

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
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
	ItemID    string   `json:"item_id"`
	CachedAt  int64    `json:"cached_at"`
	ExpiresAt int64    `json:"expires_at"`
	Manifest  Manifest `json:"manifest"`
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
	Version        int                            `json:"version"`
	MasterSeedB64U string                         `json:"master_seed_b64u"`
	LocalLabel     string                         `json:"local_label,omitempty"`
	Relays         map[string]RelayProfile        `json:"relays"`
	Devices        map[string]DeviceCard          `json:"devices"`
	SeenMsgs       map[string]SeenMsgEntry        `json:"seen_msgs"`
	ManifestCache  map[string]CachedManifestEntry `json:"manifest_cache"`
	Checkpoints    map[string]TransferCheckpoint  `json:"checkpoints"`
}

// FileKeyStore is a secure local-file reference KeyStore implementation (dir 0700, file 0600, atomic rename).
type FileKeyStore struct {
	mu   sync.Mutex
	dir  string
	path string
	st   *fileKeyStoreState
}

// NewFileKeyStore opens or initializes a FileKeyStore under dir (mode 0700).
func NewFileKeyStore(dir string) (*FileKeyStore, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, WrapError(ErrCodeKeystoreError, false, 0, "create keystore dir", err)
	}
	fs := &FileKeyStore{
		dir:  dir,
		path: filepath.Join(dir, "keystore.json"),
	}
	if err := fs.loadLocked(); err != nil {
		return nil, err
	}
	return fs, nil
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

func (f *FileKeyStore) loadLocked() error {
	if f.path == "" {
		if f.st == nil {
			f.st = newEmptyState()
		}
		return nil
	}
	data, err := os.ReadFile(f.path)
	if os.IsNotExist(err) {
		f.st = newEmptyState()
		return nil
	}
	if err != nil {
		return WrapError(ErrCodeKeystoreError, false, 0, "read keystore file", err)
	}
	var st fileKeyStoreState
	if err := json.Unmarshal(data, &st); err != nil {
		return WrapError(ErrCodeKeystoreError, false, 0, "parse keystore json", err)
	}
	if st.Relays == nil {
		st.Relays = make(map[string]RelayProfile)
	}
	if st.Devices == nil {
		st.Devices = make(map[string]DeviceCard)
	}
	if st.SeenMsgs == nil {
		st.SeenMsgs = make(map[string]SeenMsgEntry)
	}
	if st.ManifestCache == nil {
		st.ManifestCache = make(map[string]CachedManifestEntry)
	}
	if st.Checkpoints == nil {
		st.Checkpoints = make(map[string]TransferCheckpoint)
	}
	f.st = &st
	return nil
}

func (f *FileKeyStore) persistLocked() error {
	if f.path == "" {
		return nil
	}
	data, err := json.MarshalIndent(f.st, "", "  ")
	if err != nil {
		return WrapError(ErrCodeKeystoreError, false, 0, "marshal keystore", err)
	}
	tmp := f.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return WrapError(ErrCodeKeystoreError, false, 0, "write keystore tmp", err)
	}
	if err := os.Rename(tmp, f.path); err != nil {
		_ = os.Remove(tmp)
		return WrapError(ErrCodeKeystoreError, false, 0, "rename keystore", err)
	}
	return nil
}

func (f *FileKeyStore) LoadOrCreateMasterSeed() ([32]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var seed [32]byte
	if f.st.MasterSeedB64U != "" {
		raw, err := base64.RawURLEncoding.DecodeString(f.st.MasterSeedB64U)
		if err != nil || len(raw) != 32 {
			return seed, NewError(ErrCodeKeystoreError, false, 0, "corrupted master seed in keystore", nil)
		}
		copy(seed[:], raw)
		clear(raw)
		return seed, nil
	}
	generated, err := synccrypto.GenerateMasterSeed()
	if err != nil {
		return seed, WrapError(ErrCodeKeystoreError, false, 0, "generate master seed", err)
	}
	f.st.MasterSeedB64U = base64.RawURLEncoding.EncodeToString(generated[:])
	if err := f.persistLocked(); err != nil {
		clear(generated[:])
		return seed, err
	}
	return generated, nil
}

func (f *FileKeyStore) GetLocalLabel() (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.st.LocalLabel, nil
}

func (f *FileKeyStore) SetLocalLabel(label string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.st.LocalLabel = strings.TrimSpace(label)
	return f.persistLocked()
}

func (f *FileKeyStore) GetRelayProfile(relayIDOrAlias string) (*RelayProfile, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if p, ok := f.st.Relays[relayIDOrAlias]; ok {
		cp := p
		return &cp, nil
	}
	for _, p := range f.st.Relays {
		if p.Alias != "" && strings.EqualFold(p.Alias, relayIDOrAlias) {
			cp := p
			return &cp, nil
		}
	}
	return nil, nil
}

func (f *FileKeyStore) GetDefaultRelayProfile() (*RelayProfile, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var first *RelayProfile
	for _, p := range f.st.Relays {
		cp := p
		if cp.IsDefault {
			return &cp, nil
		}
		if first == nil || cp.RelayID < first.RelayID {
			first = &cp
		}
	}
	return first, nil
}

func (f *FileKeyStore) ListRelayProfiles() ([]RelayProfile, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]RelayProfile, 0, len(f.st.Relays))
	for _, p := range f.st.Relays {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RelayID < out[j].RelayID })
	return out, nil
}

func (f *FileKeyStore) SaveRelayProfile(profile RelayProfile) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if profile.IsDefault || len(f.st.Relays) == 0 {
		profile.IsDefault = true
		for id, existing := range f.st.Relays {
			if id != profile.RelayID && existing.IsDefault {
				existing.IsDefault = false
				f.st.Relays[id] = existing
			}
		}
	}
	f.st.Relays[profile.RelayID] = profile
	return f.persistLocked()
}

func (f *FileKeyStore) ListDevices() ([]DeviceCard, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]DeviceCard, 0, len(f.st.Devices))
	for _, c := range f.st.Devices {
		if !c.Revoked {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PairedAt < out[j].PairedAt })
	return out, nil
}

func (f *FileKeyStore) GetDevice(deviceID string) (*DeviceCard, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
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
	f.st.Devices[card.DeviceID] = card
	return f.persistLocked()
}

func (f *FileKeyStore) DeleteDevice(deviceID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	id := strings.ToLower(strings.TrimSpace(deviceID))
	delete(f.st.Devices, id)
	return f.persistLocked()
}

func (f *FileKeyStore) HasSeenMsgID(msgID string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.st.SeenMsgs[strings.ToLower(msgID)]
	return ok, nil
}

func (f *FileKeyStore) MarkSeenMsgID(msgID string, createdAt, seenAt int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	id := strings.ToLower(msgID)
	f.st.SeenMsgs[id] = SeenMsgEntry{
		MsgID:     id,
		CreatedAt: createdAt,
		SeenAt:    seenAt,
	}
	// Prune entries older than 30 days only when count exceeds DefaultSeenMsgMinEntries.
	if len(f.st.SeenMsgs) > DefaultSeenMsgMinEntries {
		cutoff := time.Now().Unix() - int64(DefaultSeenMsgRetentionDays*86400)
		entries := make([]SeenMsgEntry, 0, len(f.st.SeenMsgs))
		for _, e := range f.st.SeenMsgs {
			entries = append(entries, e)
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].SeenAt < entries[j].SeenAt })
		for _, e := range entries {
			if len(f.st.SeenMsgs) <= DefaultSeenMsgMinEntries {
				break
			}
			if e.SeenAt < cutoff {
				delete(f.st.SeenMsgs, e.MsgID)
			}
		}
	}
	return f.persistLocked()
}

func (f *FileKeyStore) GetCachedManifest(itemID string) (*CachedManifestEntry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if e, ok := f.st.ManifestCache[itemID]; ok {
		cp := e
		return &cp, nil
	}
	return nil, nil
}

func (f *FileKeyStore) PutCachedManifest(entry CachedManifestEntry) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.st.ManifestCache[entry.ItemID] = entry
	return f.persistLocked()
}

func (f *FileKeyStore) DeleteCachedManifest(itemID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.st.ManifestCache[itemID]; !ok {
		return nil
	}
	delete(f.st.ManifestCache, itemID)
	return f.persistLocked()
}

func (f *FileKeyStore) PruneCachedManifests(activeItemIDs map[string]struct{}) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	changed := false
	for id := range f.st.ManifestCache {
		if _, ok := activeItemIDs[id]; !ok {
			delete(f.st.ManifestCache, id)
			changed = true
		}
	}
	if !changed {
		return nil
	}
	return f.persistLocked()
}

func checkpointKey(direction, msgID string, partID uint32) string {
	return direction + ":" + strings.ToLower(msgID) + ":" + string(rune('0'+partID/10)) + string(rune('0'+partID%10))
}

func (f *FileKeyStore) GetCheckpoint(direction, msgID string, partID uint32) (*TransferCheckpoint, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
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
	f.st.Checkpoints[cp.Key] = cp
	return f.persistLocked()
}

func (f *FileKeyStore) DeleteCheckpoint(direction, msgID string, partID uint32) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	k := checkpointKey(direction, msgID, partID)
	if _, ok := f.st.Checkpoints[k]; !ok {
		return nil
	}
	delete(f.st.Checkpoints, k)
	return f.persistLocked()
}
