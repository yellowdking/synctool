package relay

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type SpoolPartSpec struct {
	PartID     int   `json:"part_id"`
	TotalBytes int64 `json:"total_bytes"`
	ChunkCount int   `json:"chunk_count"`
}

type SpoolInitRequest struct {
	MailboxID          string          `json:"mailbox_id"`
	DeclaredTotalBytes int64           `json:"declared_total_bytes"`
	TTLSec             int64           `json:"ttl_sec"`
	SealedHeader       string          `json:"sealed_header"`
	Parts              []SpoolPartSpec `json:"parts"`
}

type SpoolInitResponse struct {
	ItemID                 string `json:"item_id"`
	UploadToken            string `json:"upload_token"`
	MaxTransportChunkBytes int64  `json:"max_transport_chunk_bytes"`
	UploadExpiresAt        int64  `json:"upload_expires_at"`
	ExpiresAt              int64  `json:"expires_at"`
}

type MailboxItemSummary struct {
	ItemID       string          `json:"item_id"`
	CreatedAt    int64           `json:"created_at"`
	ExpiresAt    int64           `json:"expires_at"`
	TotalBytes   int64           `json:"total_bytes"`
	SealedHeader string          `json:"sealed_header"`
	Parts        []SpoolPartSpec `json:"parts"`
}

type MailboxListResponse struct {
	MailboxID  string               `json:"mailbox_id"`
	UsedBytes  int64                `json:"used_bytes"`
	QuotaBytes int64                `json:"quota_bytes"`
	Items      []MailboxItemSummary `json:"items"`
}

type MailboxEventItem struct {
	ItemID     string `json:"item_id"`
	TotalBytes int64  `json:"total_bytes"`
	CreatedAt  int64  `json:"created_at"`
	ExpiresAt  int64  `json:"expires_at"`
}

type DepositTokenEntry struct {
	TokenID      string `json:"token_id"`
	TokenHashHex string `json:"token_hash_hex"`
}

type mailboxDiskMeta struct {
	AuthPKB64     string              `json:"auth_pk_b64"`
	DepositTokens []DepositTokenEntry `json:"deposit_tokens"`
}

type itemDiskMeta struct {
	ItemID             string          `json:"item_id"`
	MailboxID          string          `json:"mailbox_id"`
	SealedHeader       string          `json:"sealed_header"`
	DeclaredTotalBytes int64           `json:"declared_total_bytes"`
	Committed          bool            `json:"committed"`
	CreatedAt          int64           `json:"created_at"`
	CommittedAt        int64           `json:"committed_at,omitempty"`
	UploadExpiresAt    int64           `json:"upload_expires_at"`
	ExpiresAt          int64           `json:"expires_at"`
	Parts              []SpoolPartSpec `json:"parts"`
}

type chunkKey struct {
	partID int
	txIdx  uint32
}

type spoolItem struct {
	id                 string
	mailboxID          string
	sealedHeader       string
	declaredTotalBytes int64
	committed          bool
	destroyed          bool
	activeIO           int
	uploadToken        string
	createdAt          time.Time
	committedAt        time.Time
	uploadExpiresAt    time.Time
	expiresAt          time.Time
	parts              map[int]SpoolPartSpec
	partOrder          []SpoolPartSpec
	receivedSizes      map[chunkKey]int64
	memChunks          map[chunkKey][]byte
	downloads          map[chunkKey]int
}

type mailboxRecord struct {
	id            string
	authPK        ed25519.PublicKey
	depositTokens map[string]string // token_id -> token_hash_hex
	usedBytes     int64
	itemCount     int
	notifyCh      chan struct{}
}

type SpoolStore struct {
	mu                     sync.Mutex
	backend                SpoolBackend
	rootDir                string
	maxTotalBytes          int64
	maxMailboxBytes        int64
	maxItemBytes           int64
	maxItemsPerMailbox     int
	defaultTTLSec          int64
	maxTTLSec              int64
	maxTransportChunkBytes int64
	maxDownloadsPerChunk   int
	stallTimeout           time.Duration
	bufPool                sync.Pool
	bw                     *BandwidthLimiter

	mailboxes       map[string]*mailboxRecord
	items           map[string]*spoolItem
	globalUsedBytes int64
	onActivity      func()
}

func NewSpoolStore(cfg ResolvedConfig, bw *BandwidthLimiter, onActivity func()) (*SpoolStore, error) {
	s := &SpoolStore{
		backend:                cfg.SpoolMode,
		maxTotalBytes:          cfg.Preset.SpoolMaxTotalBytes,
		maxMailboxBytes:        cfg.Preset.SpoolMaxMailboxBytes,
		maxItemBytes:           cfg.Preset.SpoolMaxItemBytes,
		maxItemsPerMailbox:     cfg.Preset.SpoolMaxItemsPerMailbox,
		defaultTTLSec:          cfg.Preset.SpoolDefaultTTLSec,
		maxTTLSec:              cfg.Preset.SpoolMaxTTLSec,
		maxTransportChunkBytes: cfg.Preset.MaxTransportChunkBytes,
		maxDownloadsPerChunk:   cfg.Preset.MaxDownloadsPerChunk,
		stallTimeout:           cfg.StallTimeout,
		bw:                     bw,
		mailboxes:              make(map[string]*mailboxRecord, 16),
		items:                  make(map[string]*spoolItem, 32),
		onActivity:             onActivity,
	}
	bufSz := cfg.Preset.CopyBufBytes
	if bufSz <= 0 {
		bufSz = 64 << 10
	}
	s.bufPool.New = func() any {
		b := make([]byte, bufSz)
		return &b
	}

	if s.backend == SpoolDisk {
		s.rootDir = filepath.Join(cfg.DataDir, "spool")
		if err := os.MkdirAll(s.rootDir, 0o700); err != nil {
			return nil, fmt.Errorf("create spool dir: %w", err)
		}
		if err := s.loadFromDisk(cfg.NowFunc()); err != nil {
			return nil, fmt.Errorf("load spool from disk: %w", err)
		}
	}
	return s, nil
}

func (s *SpoolStore) Enabled() bool {
	return s.backend != SpoolOff
}

func (s *SpoolStore) Backend() SpoolBackend {
	return s.backend
}

func (s *SpoolStore) mailboxDir(mailboxID string) string {
	return filepath.Join(s.rootDir, mailboxID[:2], mailboxID)
}

func (s *SpoolStore) itemDir(mailboxID, itemID string) string {
	return filepath.Join(s.mailboxDir(mailboxID), itemID)
}

func (s *SpoolStore) chunkFilePath(mailboxID, itemID string, partID int, txIdx uint32) string {
	return filepath.Join(s.itemDir(mailboxID, itemID), fmt.Sprintf("p%d_c%d.enc", partID, txIdx))
}

func (s *SpoolStore) loadFromDisk(now time.Time) error {
	prefixEntries, err := os.ReadDir(s.rootDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	for _, pe := range prefixEntries {
		pName := pe.Name()
		fullPrefix := filepath.Join(s.rootDir, pName)
		if !pe.IsDir() || !isLowerHexLen(pName, 2) {
			if strings.HasSuffix(pName, ".tmp") {
				_ = os.Remove(fullPrefix)
			}
			continue
		}
		mbEntries, err := os.ReadDir(fullPrefix)
		if err != nil {
			continue
		}
		for _, me := range mbEntries {
			mbID := me.Name()
			mbPath := filepath.Join(fullPrefix, mbID)
			if !me.IsDir() || !isLowerHexLen(mbID, 32) || mbID[:2] != pName {
				if strings.HasSuffix(mbID, ".tmp") {
					_ = os.Remove(mbPath)
				}
				continue
			}
			metaBytes, err := os.ReadFile(filepath.Join(mbPath, "mailbox.json"))
			if err != nil {
				_ = os.RemoveAll(mbPath)
				continue
			}
			var meta mailboxDiskMeta
			if err := json.Unmarshal(metaBytes, &meta); err != nil {
				_ = os.RemoveAll(mbPath)
				continue
			}
			pk, err := base64.RawURLEncoding.DecodeString(meta.AuthPKB64)
			if err != nil || len(pk) != ed25519.PublicKeySize || DeriveMailboxID(pk) != mbID {
				_ = os.RemoveAll(mbPath)
				continue
			}

			mb := &mailboxRecord{
				id:            mbID,
				authPK:        ed25519.PublicKey(pk),
				depositTokens: make(map[string]string, len(meta.DepositTokens)),
				notifyCh:      make(chan struct{}),
			}
			for _, dt := range meta.DepositTokens {
				if isValidTokenID(dt.TokenID) && isLowerHexLen(dt.TokenHashHex, 64) && len(mb.depositTokens) < MaxDepositTokensPerMailbox {
					mb.depositTokens[dt.TokenID] = dt.TokenHashHex
				}
			}
			s.mailboxes[mbID] = mb

			// Scan item directories inside mailbox.
			itemEntries, err := os.ReadDir(mbPath)
			if err != nil {
				continue
			}
			for _, ie := range itemEntries {
				ieName := ie.Name()
				itemPath := filepath.Join(mbPath, ieName)
				if ieName == "mailbox.json" {
					continue
				}
				if !ie.IsDir() || !isValidItemID(ieName) {
					_ = os.RemoveAll(itemPath)
					continue
				}
				imBytes, err := os.ReadFile(filepath.Join(itemPath, "item.json"))
				if err != nil {
					_ = os.RemoveAll(itemPath)
					continue
				}
				var im itemDiskMeta
				if err := json.Unmarshal(imBytes, &im); err != nil || im.ItemID != ieName || im.MailboxID != mbID {
					_ = os.RemoveAll(itemPath)
					continue
				}

				expiresAt := time.Unix(im.ExpiresAt, 0)
				uploadExp := time.Unix(im.UploadExpiresAt, 0)
				if !im.Committed || !now.Before(expiresAt) || im.DeclaredTotalBytes <= 0 || len(im.Parts) == 0 || len(im.Parts) > MaxPartsPerItem {
					// Discard uncommitted, expired, or malformed items on startup recovery.
					_ = os.RemoveAll(itemPath)
					continue
				}
				if hdr, herr := base64.RawURLEncoding.DecodeString(im.SealedHeader); herr != nil || len(hdr) != SealedHeaderLen {
					_ = os.RemoveAll(itemPath)
					continue
				}

				commAt := im.CommittedAt
				if commAt <= 0 {
					commAt = im.CreatedAt
				}
				it := &spoolItem{
					id:                 im.ItemID,
					mailboxID:          mbID,
					sealedHeader:       im.SealedHeader,
					declaredTotalBytes: im.DeclaredTotalBytes,
					committed:          true,
					createdAt:          time.Unix(im.CreatedAt, 0),
					committedAt:        time.Unix(commAt, 0),
					uploadExpiresAt:    uploadExp,
					expiresAt:          expiresAt,
					parts:              make(map[int]SpoolPartSpec, len(im.Parts)),
					partOrder:          im.Parts,
					receivedSizes:      make(map[chunkKey]int64),
					downloads:          make(map[chunkKey]int),
				}
				metaValid := true
				for _, p := range im.Parts {
					if p.PartID < 0 || p.PartID >= MaxPartsPerItem || p.ChunkCount <= 0 || p.ChunkCount > MaxChunksPerPart || p.TotalBytes <= 0 {
						metaValid = false
						break
					}
					if _, dup := it.parts[p.PartID]; dup {
						metaValid = false
						break
					}
					it.parts[p.PartID] = p
				}
				if !metaValid {
					_ = os.RemoveAll(itemPath)
					continue
				}

				files, _ := os.ReadDir(itemPath)
				for _, f := range files {
					fn := f.Name()
					if fn == "item.json" {
						continue
					}
					if strings.HasSuffix(fn, ".tmp") || f.IsDir() {
						_ = os.RemoveAll(filepath.Join(itemPath, fn))
						continue
					}
					if strings.HasPrefix(fn, "p") && strings.HasSuffix(fn, ".enc") {
						inner := strings.TrimSuffix(strings.TrimPrefix(fn, "p"), ".enc")
						parts := strings.Split(inner, "_c")
						if len(parts) == 2 {
							pid, e1 := strconv.Atoi(parts[0])
							cid, e2 := strconv.ParseUint(parts[1], 10, 32)
							if e1 == nil && e2 == nil {
								if info, serr := f.Info(); serr == nil && info.Size() > 0 {
									it.receivedSizes[chunkKey{partID: pid, txIdx: uint32(cid)}] = info.Size()
									continue
								}
							}
						}
					}
					_ = os.RemoveAll(filepath.Join(itemPath, fn))
				}

				// Verify every declared chunk file is intact on disk (purges half-deleted/truncated zombie items).
				var diskSum int64
				for _, p := range it.partOrder {
					var partSum int64
					for c := 0; c < p.ChunkCount; c++ {
						sz, ok := it.receivedSizes[chunkKey{partID: p.PartID, txIdx: uint32(c)}]
						if !ok || sz <= 0 || sz > s.maxTransportChunkBytes {
							metaValid = false
							break
						}
						partSum += sz
					}
					if !metaValid || partSum != p.TotalBytes {
						metaValid = false
						break
					}
					diskSum += partSum
				}
				if !metaValid || diskSum != it.declaredTotalBytes {
					_ = os.RemoveAll(itemPath)
					continue
				}

				s.items[it.id] = it
				mb.usedBytes += it.declaredTotalBytes
				mb.itemCount++
				s.globalUsedBytes += it.declaredTotalBytes
			}
		}
	}
	return nil
}

func (s *SpoolStore) persistMailboxLocked(mb *mailboxRecord) error {
	if s.backend != SpoolDisk {
		return nil
	}
	dir := s.mailboxDir(mb.id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tokens := make([]DepositTokenEntry, 0, len(mb.depositTokens))
	for id, h := range mb.depositTokens {
		tokens = append(tokens, DepositTokenEntry{TokenID: id, TokenHashHex: h})
	}
	sort.Slice(tokens, func(i, j int) bool { return tokens[i].TokenID < tokens[j].TokenID })
	meta := mailboxDiskMeta{
		AuthPKB64:     base64.RawURLEncoding.EncodeToString(mb.authPK),
		DepositTokens: tokens,
	}
	data, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	return atomicWriteFile(filepath.Join(dir, "mailbox.json"), data, 0o600)
}

func (s *SpoolStore) persistItemLocked(it *spoolItem) error {
	if s.backend != SpoolDisk {
		return nil
	}
	dir := s.itemDir(it.mailboxID, it.id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	var commUnix int64
	if !it.committedAt.IsZero() {
		commUnix = it.committedAt.Unix()
	}
	meta := itemDiskMeta{
		ItemID:             it.id,
		MailboxID:          it.mailboxID,
		SealedHeader:       it.sealedHeader,
		DeclaredTotalBytes: it.declaredTotalBytes,
		Committed:          it.committed,
		CreatedAt:          it.createdAt.Unix(),
		CommittedAt:        commUnix,
		UploadExpiresAt:    it.uploadExpiresAt.Unix(),
		ExpiresAt:          it.expiresAt.Unix(),
		Parts:              it.partOrder,
	}
	data, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	return atomicWriteFile(filepath.Join(dir, "item.json"), data, 0o600)
}

func (s *SpoolStore) RegisterMailbox(mailboxID string, authPK ed25519.PublicKey) (int, error) {
	return s.RegisterMailboxWithTokens(mailboxID, authPK, nil)
}

func (s *SpoolStore) RegisterMailboxWithTokens(mailboxID string, authPK ed25519.PublicKey, tokens []DepositTokenEntry) (int, error) {
	if s.backend == SpoolOff {
		return 0, errSpoolDisabled()
	}
	if !isLowerHexLen(mailboxID, 32) || len(authPK) != ed25519.PublicKeySize || DeriveMailboxID(authPK) != mailboxID {
		return 0, newAPIError(400, "ERR_BAD_REQUEST", "mailbox_id does not match derived auth_pk", false)
	}

	incoming := make(map[string]string, len(tokens))
	for _, dt := range tokens {
		if !isValidTokenID(dt.TokenID) {
			return 0, newAPIError(400, "ERR_BAD_REQUEST", "token_id must be 8..32 chars of [A-Za-z0-9_-]", false)
		}
		if !isLowerHexLen(dt.TokenHashHex, 64) {
			return 0, newAPIError(400, "ERR_BAD_REQUEST", "token_hash_hex must be 64 lowercase hex chars", false)
		}
		if prev, dup := incoming[dt.TokenID]; dup && !ConstantTimeStringEqual(prev, dt.TokenHashHex) {
			return 0, newAPIError(409, "ERR_CONFLICT", "conflicting token_hash_hex for duplicate token_id", false)
		}
		incoming[dt.TokenID] = dt.TokenHashHex
	}
	if len(incoming) > MaxDepositTokensPerMailbox {
		return 0, newAPIError(409, "ERR_CONFLICT", "mailbox deposit token limit (16) reached", false)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if existing, ok := s.mailboxes[mailboxID]; ok {
		if !bytes.Equal(existing.authPK, authPK) {
			return 0, newAPIError(409, "ERR_CONFLICT", "mailbox already registered with different auth_pk", false)
		}
		if len(incoming) == 0 {
			return len(existing.depositTokens), nil
		}
		// Gracefully merge deposit_tokens without touching unread spooled items!
		merged := make(map[string]string, len(existing.depositTokens)+len(incoming))
		for k, v := range existing.depositTokens {
			merged[k] = v
		}
		changed := false
		for id, hashHex := range incoming {
			if cur, exists := merged[id]; exists {
				if !ConstantTimeStringEqual(cur, hashHex) {
					return 0, newAPIError(409, "ERR_CONFLICT", "token_id already bound to different token_hash_hex", false)
				}
				continue
			}
			merged[id] = hashHex
			changed = true
		}
		if len(merged) > MaxDepositTokensPerMailbox {
			return 0, newAPIError(409, "ERR_CONFLICT", "mailbox deposit token limit (16) reached", false)
		}
		if changed {
			prev := existing.depositTokens
			existing.depositTokens = merged
			if err := s.persistMailboxLocked(existing); err != nil {
				existing.depositTokens = prev
				return 0, err
			}
		}
		return len(existing.depositTokens), nil
	}

	pkCopy := make(ed25519.PublicKey, ed25519.PublicKeySize)
	copy(pkCopy, authPK)
	mb := &mailboxRecord{
		id:            mailboxID,
		authPK:        pkCopy,
		depositTokens: incoming,
		notifyCh:      make(chan struct{}),
	}
	if err := s.persistMailboxLocked(mb); err != nil {
		return 0, err
	}
	s.mailboxes[mailboxID] = mb
	return len(mb.depositTokens), nil
}

func (s *SpoolStore) GetMailboxAuthPK(mailboxID string) (ed25519.PublicKey, error) {
	if s.backend == SpoolOff {
		return nil, errSpoolDisabled()
	}
	if !isLowerHexLen(mailboxID, 32) {
		return nil, newAPIError(400, "ERR_BAD_REQUEST", "invalid mailbox_id", false)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	mb, ok := s.mailboxes[mailboxID]
	if !ok {
		return nil, errMailboxNotFound("mailbox not found")
	}
	return mb.authPK, nil
}

func (s *SpoolStore) AddDepositToken(mailboxID, tokenID, tokenHashHex string) (int, error) {
	if s.backend == SpoolOff {
		return 0, errSpoolDisabled()
	}
	if !isLowerHexLen(mailboxID, 32) {
		return 0, newAPIError(400, "ERR_BAD_REQUEST", "invalid mailbox_id", false)
	}
	if !isValidTokenID(tokenID) {
		return 0, newAPIError(400, "ERR_BAD_REQUEST", "token_id must be 8..32 chars of [A-Za-z0-9_-]", false)
	}
	if !isLowerHexLen(tokenHashHex, 64) {
		return 0, newAPIError(400, "ERR_BAD_REQUEST", "token_hash_hex must be 64 lowercase hex chars", false)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	mb, ok := s.mailboxes[mailboxID]
	if !ok {
		return 0, errMailboxNotFound("mailbox not found")
	}
	if curHash, dup := mb.depositTokens[tokenID]; dup {
		if ConstantTimeStringEqual(curHash, tokenHashHex) {
			return len(mb.depositTokens), nil
		}
		return 0, newAPIError(409, "ERR_CONFLICT", "token_id already exists with different hash", false)
	}
	if len(mb.depositTokens) >= MaxDepositTokensPerMailbox {
		return 0, newAPIError(409, "ERR_CONFLICT", "mailbox deposit token limit (16) reached", false)
	}
	mb.depositTokens[tokenID] = tokenHashHex
	if err := s.persistMailboxLocked(mb); err != nil {
		delete(mb.depositTokens, tokenID)
		return 0, err
	}
	return len(mb.depositTokens), nil
}

func (s *SpoolStore) DeleteDepositToken(mailboxID, tokenID string) (int, error) {
	if s.backend == SpoolOff {
		return 0, errSpoolDisabled()
	}
	if !isLowerHexLen(mailboxID, 32) {
		return 0, newAPIError(400, "ERR_BAD_REQUEST", "invalid mailbox_id", false)
	}
	if !isValidTokenID(tokenID) {
		return 0, newAPIError(400, "ERR_BAD_REQUEST", "invalid token_id", false)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	mb, ok := s.mailboxes[mailboxID]
	if !ok {
		return 0, errMailboxNotFound("mailbox not found")
	}
	if _, exists := mb.depositTokens[tokenID]; !exists {
		return 0, newAPIError(404, "ERR_NOT_FOUND", "deposit token not found", false)
	}
	old := mb.depositTokens[tokenID]
	delete(mb.depositTokens, tokenID)
	if err := s.persistMailboxLocked(mb); err != nil {
		mb.depositTokens[tokenID] = old
		return 0, err
	}
	return len(mb.depositTokens), nil
}

func (s *SpoolStore) ListItems(mailboxID string, now time.Time) (MailboxListResponse, error) {
	if s.backend == SpoolOff {
		return MailboxListResponse{}, errSpoolDisabled()
	}
	if !isLowerHexLen(mailboxID, 32) {
		return MailboxListResponse{}, newAPIError(400, "ERR_BAD_REQUEST", "invalid mailbox_id", false)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked(now)

	mb, ok := s.mailboxes[mailboxID]
	if !ok {
		return MailboxListResponse{}, errMailboxNotFound("mailbox not found")
	}

	items := make([]MailboxItemSummary, 0)
	for _, it := range s.items {
		if it.mailboxID == mailboxID && it.committed && !it.destroyed && now.Before(it.expiresAt) {
			partsCopy := make([]SpoolPartSpec, len(it.partOrder))
			copy(partsCopy, it.partOrder)
			items = append(items, MailboxItemSummary{
				ItemID:       it.id,
				CreatedAt:    it.createdAt.Unix(),
				ExpiresAt:    it.expiresAt.Unix(),
				TotalBytes:   it.declaredTotalBytes,
				SealedHeader: it.sealedHeader,
				Parts:        partsCopy,
			})
		}
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].CreatedAt == items[j].CreatedAt {
			return items[i].ItemID < items[j].ItemID
		}
		return items[i].CreatedAt < items[j].CreatedAt
	})

	return MailboxListResponse{
		MailboxID:  mailboxID,
		UsedBytes:  mb.usedBytes,
		QuotaBytes: s.maxMailboxBytes,
		Items:      items,
	}, nil
}

func (s *SpoolStore) SnapshotMailboxEvents(mailboxID string, sinceTS int64, now time.Time) ([]MailboxEventItem, <-chan struct{}, error) {
	if s.backend == SpoolOff {
		return nil, nil, errSpoolDisabled()
	}
	if !isLowerHexLen(mailboxID, 32) {
		return nil, nil, newAPIError(400, "ERR_BAD_REQUEST", "invalid mailbox_id", false)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked(now)

	mb, ok := s.mailboxes[mailboxID]
	if !ok {
		return nil, nil, errMailboxNotFound("mailbox not found")
	}
	out := make([]MailboxEventItem, 0)
	for _, it := range s.items {
		if it.mailboxID == mailboxID && it.committed && !it.destroyed && now.Before(it.expiresAt) {
			evTS := it.committedAt.Unix()
			if evTS <= 0 {
				evTS = it.createdAt.Unix()
			}
			if evTS > sinceTS {
				out = append(out, MailboxEventItem{
					ItemID:     it.id,
					TotalBytes: it.declaredTotalBytes,
					CreatedAt:  evTS,
					ExpiresAt:  it.expiresAt.Unix(),
				})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt == out[j].CreatedAt {
			return out[i].ItemID < out[j].ItemID
		}
		return out[i].CreatedAt < out[j].CreatedAt
	})
	return out, mb.notifyCh, nil
}

func (s *SpoolStore) HasActiveItems() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.items) > 0
}

func (s *SpoolStore) SweepExpired(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked(now)
}

func (s *SpoolStore) sweepLocked(now time.Time) {
	for _, it := range s.items {
		expired := !now.Before(it.expiresAt) || (!it.committed && !now.Before(it.uploadExpiresAt))
		if expired {
			s.destroyItemLocked(it)
		}
	}
}

func (s *SpoolStore) destroyItemLocked(it *spoolItem) {
	if it.destroyed {
		return
	}
	it.destroyed = true
	delete(s.items, it.id)
	if mb, ok := s.mailboxes[it.mailboxID]; ok {
		mb.usedBytes -= it.declaredTotalBytes
		if mb.usedBytes < 0 {
			mb.usedBytes = 0
		}
		mb.itemCount--
		if mb.itemCount < 0 {
			mb.itemCount = 0
		}
	}
	s.globalUsedBytes -= it.declaredTotalBytes
	if s.globalUsedBytes < 0 {
		s.globalUsedBytes = 0
	}
	if s.backend == SpoolMemory {
		for k, b := range it.memChunks {
			clear(b)
			delete(it.memChunks, k)
		}
	} else if s.backend == SpoolDisk {
		// On Linux unlink succeeds immediately; on Windows if activeIO > 0 holds an open file handle,
		// releaseItemIO will run a second RemoveAll right after the last file handle closes.
		_ = os.RemoveAll(s.itemDir(it.mailboxID, it.id))
	}
}

func (s *SpoolStore) releaseItemIO(it *spoolItem) {
	var purgeDir string
	s.mu.Lock()
	if it.activeIO > 0 {
		it.activeIO--
	}
	if it.destroyed && it.activeIO == 0 && s.backend == SpoolDisk {
		purgeDir = s.itemDir(it.mailboxID, it.id)
	}
	s.mu.Unlock()
	if purgeDir != "" {
		_ = os.RemoveAll(purgeDir)
	}
}

func errMailboxNotFound(msg string) error {
	return &apiError{
		Status:    404,
		Code:      "ERR_NOT_FOUND",
		Message:   msg,
		Retryable: false,
		Scope:     "mailbox",
	}
}

func errSpoolDisabled() error {
	return &apiError{
		Status:      403,
		Code:        "ERR_SPOOL_DISABLED",
		Message:     "offline spool is disabled on this relay",
		Retryable:   false,
		SuggestMode: "pipe",
	}
}
