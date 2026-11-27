package relay

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"sort"
	"strconv"
	"time"
)

func (s *SpoolStore) InitUpload(req SpoolInitRequest, depositToken string, now time.Time) (SpoolInitResponse, error) {
	if s.backend == SpoolOff {
		return SpoolInitResponse{}, errSpoolDisabled()
	}
	if !isLowerHexLen(req.MailboxID, 32) {
		return SpoolInitResponse{}, newAPIError(400, "ERR_BAD_REQUEST", "invalid mailbox_id", false)
	}
	if depositToken == "" {
		return SpoolInitResponse{}, newAPIError(401, "ERR_UNAUTHORIZED_TOKEN", "missing X-Sync-Deposit-Token", false)
	}
	hdrBytes, err := base64.RawURLEncoding.DecodeString(req.SealedHeader)
	if err != nil || len(hdrBytes) != SealedHeaderLen {
		return SpoolInitResponse{}, newAPIError(400, "ERR_BAD_REQUEST", "sealed_header must decode to exactly 208 bytes", false)
	}
	if len(req.Parts) == 0 || len(req.Parts) > MaxPartsPerItem {
		return SpoolInitResponse{}, newAPIError(400, "ERR_BAD_REQUEST", "parts must contain 1..64 entries", false)
	}

	seenPart := make(map[int]bool, len(req.Parts))
	hasPart0 := false
	var sumBytes int64
	for _, p := range req.Parts {
		if p.PartID < 0 || p.PartID >= MaxPartsPerItem {
			return SpoolInitResponse{}, newAPIError(400, "ERR_BAD_REQUEST", "part_id must be in range 0..63", false)
		}
		if seenPart[p.PartID] {
			return SpoolInitResponse{}, newAPIError(400, "ERR_BAD_REQUEST", "duplicate part_id", false)
		}
		seenPart[p.PartID] = true
		if p.PartID == 0 {
			hasPart0 = true
		}
		if p.ChunkCount <= 0 || p.ChunkCount > MaxChunksPerPart || p.TotalBytes <= 0 || int64(p.ChunkCount) > p.TotalBytes {
			return SpoolInitResponse{}, newAPIError(400, "ERR_BAD_REQUEST", "part total_bytes and chunk_count out of valid bounds", false)
		}
		minChunks := (p.TotalBytes + s.maxTransportChunkBytes - 1) / s.maxTransportChunkBytes
		if int64(p.ChunkCount) < minChunks {
			return SpoolInitResponse{}, newAPIError(400, "ERR_BAD_REQUEST", "part total_bytes exceeds chunk_count * max_transport_chunk_bytes", false)
		}
		if p.TotalBytes > math.MaxInt64-sumBytes {
			return SpoolInitResponse{}, newAPIError(400, "ERR_BAD_REQUEST", "declared part sizes overflow int64", false)
		}
		sumBytes += p.TotalBytes
	}
	if !hasPart0 {
		return SpoolInitResponse{}, newAPIError(400, "ERR_BAD_REQUEST", "parts must include part_id 0 (manifest)", false)
	}
	if sumBytes != req.DeclaredTotalBytes || req.DeclaredTotalBytes <= 0 {
		return SpoolInitResponse{}, newAPIError(400, "ERR_BAD_REQUEST", "declared_total_bytes must equal sum of parts", false)
	}

	ttlSec := req.TTLSec
	if ttlSec < 0 {
		return SpoolInitResponse{}, newAPIError(400, "ERR_BAD_REQUEST", "ttl_sec must be non-negative", false)
	}
	if ttlSec == 0 {
		ttlSec = s.defaultTTLSec
	} else if ttlSec < 60 {
		ttlSec = 60
	} else if ttlSec > s.maxTTLSec {
		ttlSec = s.maxTTLSec
	}

	gotHash := HashDepositToken(depositToken)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked(now)

	mb, ok := s.mailboxes[req.MailboxID]
	if !ok {
		return SpoolInitResponse{}, errMailboxNotFound("target mailbox not found")
	}

	// Constant-time scan over mailbox deposit tokens (<=16).
	matched := false
	for _, storedHash := range mb.depositTokens {
		if ConstantTimeStringEqual(storedHash, gotHash) {
			matched = true
		}
	}
	if !matched {
		return SpoolInitResponse{}, newAPIError(401, "ERR_UNAUTHORIZED_TOKEN", "deposit token rejected or revoked", false)
	}

	// Enforce 4-tier atomic quotas (NEVER silently evict unread items!).
	if req.DeclaredTotalBytes > s.maxItemBytes {
		return SpoolInitResponse{}, &apiError{
			Status:       413,
			Code:         "ERR_OFFLINE_QUOTA_EXCEEDED",
			Message:      "declared item size exceeds relay max_item_bytes",
			Retryable:    false,
			Scope:        "item",
			MaxItemBytes: s.maxItemBytes,
			SuggestMode:  "pipe",
		}
	}
	if mb.itemCount >= s.maxItemsPerMailbox {
		return SpoolInitResponse{}, &apiError{
			Status:      507,
			Code:        "ERR_OFFLINE_QUOTA_EXCEEDED",
			Message:     "mailbox item count limit reached",
			Retryable:   false,
			Scope:       "item_count",
			SuggestMode: "pipe",
		}
	}
	if mb.usedBytes+req.DeclaredTotalBytes > s.maxMailboxBytes {
		return SpoolInitResponse{}, &apiError{
			Status:      507,
			Code:        "ERR_OFFLINE_QUOTA_EXCEEDED",
			Message:     "mailbox byte quota exceeded",
			Retryable:   false,
			Scope:       "mailbox",
			SuggestMode: "pipe",
		}
	}
	if s.globalUsedBytes+req.DeclaredTotalBytes > s.maxTotalBytes {
		return SpoolInitResponse{}, &apiError{
			Status:      507,
			Code:        "ERR_OFFLINE_QUOTA_EXCEEDED",
			Message:     "relay global spool quota exceeded",
			Retryable:   false,
			Scope:       "global",
			SuggestMode: "pipe",
		}
	}

	hexPart, err := randomHex16()
	if err != nil {
		return SpoolInitResponse{}, err
	}
	uploadTok, err := randomB64u32()
	if err != nil {
		return SpoolInitResponse{}, err
	}

	partsCopy := make([]SpoolPartSpec, len(req.Parts))
	copy(partsCopy, req.Parts)
	sort.Slice(partsCopy, func(i, j int) bool { return partsCopy[i].PartID < partsCopy[j].PartID })

	partsMap := make(map[int]SpoolPartSpec, len(partsCopy))
	for _, p := range partsCopy {
		partsMap[p.PartID] = p
	}

	it := &spoolItem{
		id:                 "itm_" + hexPart,
		mailboxID:          req.MailboxID,
		sealedHeader:       req.SealedHeader,
		declaredTotalBytes: req.DeclaredTotalBytes,
		committed:          false,
		uploadToken:        uploadTok,
		createdAt:          now,
		uploadExpiresAt:    now.Add(UncommittedTTLSec * time.Second),
		expiresAt:          now.Add(time.Duration(ttlSec) * time.Second),
		parts:              partsMap,
		partOrder:          partsCopy,
		receivedSizes:      make(map[chunkKey]int64),
		downloads:          make(map[chunkKey]int),
	}
	if s.backend == SpoolMemory {
		it.memChunks = make(map[chunkKey][]byte)
	} else {
		if err := s.persistItemLocked(it); err != nil {
			return SpoolInitResponse{}, err
		}
	}

	s.items[it.id] = it
	mb.usedBytes += it.declaredTotalBytes
	mb.itemCount++
	s.globalUsedBytes += it.declaredTotalBytes

	if s.onActivity != nil {
		s.onActivity()
	}

	return SpoolInitResponse{
		ItemID:                 it.id,
		UploadToken:            uploadTok,
		MaxTransportChunkBytes: s.maxTransportChunkBytes,
		UploadExpiresAt:        it.uploadExpiresAt.Unix(),
		ExpiresAt:              it.expiresAt.Unix(),
	}, nil
}

func (s *SpoolStore) PrecheckPutChunk(itemID, uploadToken string, partID int, txIdx uint32, contentLen int64, now time.Time) error {
	if s.backend == SpoolOff {
		return errSpoolDisabled()
	}
	if !isValidItemID(itemID) {
		return newAPIError(400, "ERR_BAD_REQUEST", "invalid item_id", false)
	}
	if contentLen <= 0 {
		return newAPIError(400, "ERR_BAD_REQUEST", "Content-Length must be positive", false)
	}
	if contentLen > s.maxTransportChunkBytes {
		return &apiError{
			Status:                 413,
			Code:                   "ERR_CHUNK_TOO_LARGE",
			Message:                "chunk exceeds max_transport_chunk_bytes",
			Retryable:              false,
			MaxTransportChunkBytes: s.maxTransportChunkBytes,
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked(now)
	it, ok := s.items[itemID]
	if !ok || it.destroyed {
		return newAPIError(404, "ERR_NOT_FOUND", "spool item not found or expired", false)
	}
	if it.committed {
		return newAPIError(409, "ERR_INVALID_STATE", "spool item already committed", false)
	}
	if !ConstantTimeStringEqual(it.uploadToken, uploadToken) {
		return newAPIError(401, "ERR_UNAUTHORIZED_TOKEN", "invalid upload token", false)
	}
	partSpec, ok := it.parts[partID]
	if !ok || int(txIdx) >= partSpec.ChunkCount {
		return newAPIError(400, "ERR_BAD_REQUEST", "part_id or tx_idx out of declared bounds", false)
	}
	ck := chunkKey{partID: partID, txIdx: txIdx}
	var otherBytes int64
	for k, sz := range it.receivedSizes {
		if k.partID == partID && k != ck {
			otherBytes += sz
		}
	}
	if otherBytes+contentLen > partSpec.TotalBytes {
		return newAPIError(400, "ERR_BAD_REQUEST", "uploaded chunk bytes exceed declared part total_bytes", false)
	}
	return nil
}

func (s *SpoolStore) PutChunk(
	ctx context.Context,
	itemID, uploadToken string,
	partID int,
	txIdx uint32,
	contentLen int64,
	body io.Reader,
	rc *http.ResponseController,
	now time.Time,
) (int64, error) {
	if s.backend == SpoolOff {
		return 0, errSpoolDisabled()
	}
	if !isValidItemID(itemID) {
		return 0, newAPIError(400, "ERR_BAD_REQUEST", "invalid item_id", false)
	}
	if contentLen <= 0 {
		return 0, newAPIError(400, "ERR_BAD_REQUEST", "Content-Length must be positive", false)
	}
	if contentLen > s.maxTransportChunkBytes {
		return 0, &apiError{
			Status:                 413,
			Code:                   "ERR_CHUNK_TOO_LARGE",
			Message:                "chunk exceeds max_transport_chunk_bytes",
			Retryable:              false,
			MaxTransportChunkBytes: s.maxTransportChunkBytes,
		}
	}

	// Validate item & permissions under lock without holding lock during network I/O.
	s.mu.Lock()
	s.sweepLocked(now)
	it, ok := s.items[itemID]
	if !ok || it.destroyed {
		s.mu.Unlock()
		return 0, newAPIError(404, "ERR_NOT_FOUND", "spool item not found or expired", false)
	}
	if it.committed {
		s.mu.Unlock()
		return 0, newAPIError(409, "ERR_INVALID_STATE", "spool item already committed", false)
	}
	if !ConstantTimeStringEqual(it.uploadToken, uploadToken) {
		s.mu.Unlock()
		return 0, newAPIError(401, "ERR_UNAUTHORIZED_TOKEN", "invalid upload token", false)
	}
	partSpec, ok := it.parts[partID]
	if !ok || int(txIdx) >= partSpec.ChunkCount {
		s.mu.Unlock()
		return 0, newAPIError(400, "ERR_BAD_REQUEST", "part_id or tx_idx out of declared bounds", false)
	}
	ck := chunkKey{partID: partID, txIdx: txIdx}
	var otherBytes int64
	for k, sz := range it.receivedSizes {
		if k.partID == partID && k != ck {
			otherBytes += sz
		}
	}
	if otherBytes+contentLen > partSpec.TotalBytes {
		s.mu.Unlock()
		return 0, newAPIError(400, "ERR_BAD_REQUEST", "uploaded chunk bytes exceed declared part total_bytes", false)
	}
	mbID := it.mailboxID
	if s.backend == SpoolDisk {
		it.activeIO++
	}
	s.mu.Unlock()
	if s.backend == SpoolDisk {
		defer s.releaseItemIO(it)
	}

	var reader io.Reader = io.LimitReader(body, contentLen)
	if s.bw != nil {
		reader = &rateLimitedReader{ctx: ctx, r: reader, bl: s.bw}
	}

	bufPtr := s.bufPool.Get().(*[]byte)
	buf := *bufPtr
	defer func() {
		clear(buf)
		s.bufPool.Put(bufPtr)
	}()

	var memData []byte
	var diskTarget string

	if s.backend == SpoolMemory {
		memData = make([]byte, 0, contentLen)
		var total int64
		for total < contentLen {
			if rc != nil {
				_ = rc.SetReadDeadline(time.Now().Add(s.stallTimeout))
			}
			nr, rerr := reader.Read(buf)
			if nr > 0 {
				memData = append(memData, buf[:nr]...)
				total += int64(nr)
			}
			if rerr != nil {
				if errors.Is(rerr, io.EOF) {
					break
				}
				clear(memData)
				return total, rerr
			}
		}
		if rc != nil {
			_ = rc.SetReadDeadline(time.Time{})
		}
		if total != contentLen {
			clear(memData)
			return total, newAPIError(400, "ERR_BAD_REQUEST", "unexpected EOF before Content-Length bytes received", false)
		}
	} else {
		diskTarget = s.chunkFilePath(mbID, itemID, partID, txIdx)
		var rnd [8]byte
		_, _ = rand.Read(rnd[:])
		tmpPath := fmt.Sprintf("%s.%x.tmp", diskTarget, rnd[:])
		// Do NOT call os.MkdirAll unlocked here: itemDir was created in InitUpload,
		// so if item was concurrently aborted/burned we never recreate an orphan directory!
		f, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			if os.IsNotExist(err) {
				return 0, newAPIError(404, "ERR_NOT_FOUND", "spool item vanished during upload", false)
			}
			return 0, err
		}
		var total int64
		var copyErr error
		for total < contentLen {
			if rc != nil {
				_ = rc.SetReadDeadline(time.Now().Add(s.stallTimeout))
			}
			nr, rerr := reader.Read(buf)
			if nr > 0 {
				nw, werr := f.Write(buf[:nr])
				total += int64(nw)
				if werr != nil {
					copyErr = werr
					break
				}
				if nw != nr {
					copyErr = io.ErrShortWrite
					break
				}
			}
			if rerr != nil {
				if errors.Is(rerr, io.EOF) {
					break
				}
				copyErr = rerr
				break
			}
		}
		if rc != nil {
			_ = rc.SetReadDeadline(time.Time{})
		}
		cerr := f.Close()
		if copyErr != nil || cerr != nil || total != contentLen {
			_ = os.Remove(tmpPath)
			if copyErr != nil {
				return total, copyErr
			}
			if cerr != nil {
				return total, cerr
			}
			return total, newAPIError(400, "ERR_BAD_REQUEST", "unexpected EOF before Content-Length bytes received", false)
		}

		// Re-check state before finalizing rename.
		s.mu.Lock()
		cur, stillExists := s.items[itemID]
		if !stillExists || cur.destroyed || cur.committed {
			s.mu.Unlock()
			_ = os.Remove(tmpPath)
			if !stillExists || (cur != nil && cur.destroyed) {
				return total, newAPIError(404, "ERR_NOT_FOUND", "spool item vanished during upload", false)
			}
			return total, newAPIError(409, "ERR_INVALID_STATE", "spool item already committed", false)
		}
		if err := os.Rename(tmpPath, diskTarget); err != nil {
			s.mu.Unlock()
			_ = os.Remove(tmpPath)
			return total, err
		}
		cur.receivedSizes[ck] = contentLen
		s.mu.Unlock()
		return contentLen, nil
	}

	// Commit memory chunk under lock.
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, stillExists := s.items[itemID]
	if !stillExists || cur.destroyed || cur.committed {
		clear(memData)
		if !stillExists || (cur != nil && cur.destroyed) {
			return contentLen, newAPIError(404, "ERR_NOT_FOUND", "spool item vanished during upload", false)
		}
		return contentLen, newAPIError(409, "ERR_INVALID_STATE", "spool item already committed", false)
	}
	if old, existed := cur.memChunks[ck]; existed {
		clear(old)
	}
	cur.memChunks[ck] = memData
	cur.receivedSizes[ck] = contentLen
	return contentLen, nil
}

func (s *SpoolStore) Commit(itemID, uploadToken string, now time.Time) (int64, error) {
	if s.backend == SpoolOff {
		return 0, errSpoolDisabled()
	}
	if !isValidItemID(itemID) {
		return 0, newAPIError(400, "ERR_BAD_REQUEST", "invalid item_id", false)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked(now)

	it, ok := s.items[itemID]
	if !ok {
		return 0, newAPIError(404, "ERR_NOT_FOUND", "spool item not found or expired", false)
	}
	if it.committed {
		return 0, newAPIError(409, "ERR_INVALID_STATE", "spool item already committed", false)
	}
	if !ConstantTimeStringEqual(it.uploadToken, uploadToken) {
		return 0, newAPIError(401, "ERR_UNAUTHORIZED_TOKEN", "invalid upload token", false)
	}

	var missing []string
	var totalRecv int64
	for _, p := range it.partOrder {
		var partSum int64
		for c := 0; c < p.ChunkCount; c++ {
			sz, present := it.receivedSizes[chunkKey{partID: p.PartID, txIdx: uint32(c)}]
			if !present {
				if len(missing) < 16 {
					missing = append(missing, fmt.Sprintf("%d:%d", p.PartID, c))
				}
			} else {
				partSum += sz
			}
		}
		totalRecv += partSum
		if partSum != p.TotalBytes && len(missing) == 0 {
			return 0, newAPIError(409, "ERR_INVALID_STATE", fmt.Sprintf("part %d received %d bytes != declared %d", p.PartID, partSum, p.TotalBytes), false)
		}
	}
	if len(missing) > 0 {
		return 0, &apiError{
			Status:        409,
			Code:          "ERR_INVALID_STATE",
			Message:       "cannot commit item with missing chunks",
			Retryable:     false,
			MissingChunks: missing,
		}
	}
	if totalRecv != it.declaredTotalBytes {
		return 0, newAPIError(409, "ERR_INVALID_STATE", "total uploaded bytes do not match declared_total_bytes", false)
	}

	prevTok := it.uploadToken
	it.committed = true
	it.committedAt = now
	it.uploadToken = ""
	if err := s.persistItemLocked(it); err != nil {
		it.committed = false
		it.committedAt = time.Time{}
		it.uploadToken = prevTok
		return 0, err
	}

	// Notify any foreground SSE/Long-Poll subscribers on target mailbox.
	if mb, exists := s.mailboxes[it.mailboxID]; exists {
		close(mb.notifyCh)
		mb.notifyCh = make(chan struct{})
	}
	return it.expiresAt.Unix(), nil
}

func (s *SpoolStore) Abort(itemID, uploadToken string, now time.Time) error {
	if s.backend == SpoolOff {
		return errSpoolDisabled()
	}
	if !isValidItemID(itemID) {
		return newAPIError(400, "ERR_BAD_REQUEST", "invalid item_id", false)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked(now)

	it, ok := s.items[itemID]
	if !ok {
		return newAPIError(404, "ERR_NOT_FOUND", "spool item not found or expired", false)
	}
	if it.committed {
		return newAPIError(409, "ERR_INVALID_STATE", "cannot abort an already committed item", false)
	}
	if !ConstantTimeStringEqual(it.uploadToken, uploadToken) {
		return newAPIError(401, "ERR_UNAUTHORIZED_TOKEN", "invalid upload token", false)
	}

	s.destroyItemLocked(it)
	return nil
}

func (s *SpoolStore) ResolveItemOwner(itemID string, now time.Time) (mailboxID string, authPK ed25519.PublicKey, err error) {
	if s.backend == SpoolOff {
		return "", nil, errSpoolDisabled()
	}
	if !isValidItemID(itemID) {
		return "", nil, newAPIError(400, "ERR_BAD_REQUEST", "invalid item_id", false)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked(now)

	it, ok := s.items[itemID]
	if !ok || !it.committed || it.destroyed {
		return "", nil, newAPIError(404, "ERR_NOT_FOUND", "spool item not found or not committed", false)
	}
	mb, ok := s.mailboxes[it.mailboxID]
	if !ok {
		return "", nil, errMailboxNotFound("mailbox not found")
	}
	return mb.id, mb.authPK, nil
}

func (s *SpoolStore) streamReaderWithDeadline(w http.ResponseWriter, r *http.Request, rc *http.ResponseController, src io.Reader, size int64) error {
	h := w.Header()
	h.Set("Content-Type", "application/octet-stream")
	h.Set("Content-Length", strconv.FormatInt(size, 10))
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	if rc != nil {
		_ = rc.SetWriteDeadline(time.Now().Add(s.stallTimeout))
	}
	w.WriteHeader(http.StatusOK)

	var reader io.Reader = io.LimitReader(src, size)
	if s.bw != nil {
		reader = &rateLimitedReader{ctx: r.Context(), r: reader, bl: s.bw}
	}
	bufPtr := s.bufPool.Get().(*[]byte)
	buf := *bufPtr
	defer func() {
		clear(buf)
		s.bufPool.Put(bufPtr)
		if rc != nil {
			_ = rc.SetWriteDeadline(time.Time{})
		}
	}()

	for {
		if r.Context().Err() != nil {
			return errors.New("client cancelled chunk download")
		}
		nr, rerr := reader.Read(buf)
		if nr > 0 {
			if rc != nil {
				_ = rc.SetWriteDeadline(time.Now().Add(s.stallTimeout))
			}
			if _, werr := w.Write(buf[:nr]); werr != nil {
				return errors.New("write error after headers sent")
			}
		}
		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				return nil
			}
			return errors.New("read error after headers sent")
		}
	}
}

func (s *SpoolStore) ServeChunk(w http.ResponseWriter, r *http.Request, rc *http.ResponseController, itemID string, partID int, txIdx uint32, now time.Time) error {
	if s.backend == SpoolOff {
		return errSpoolDisabled()
	}
	if !isValidItemID(itemID) {
		return newAPIError(400, "ERR_BAD_REQUEST", "invalid item_id", false)
	}
	if partID < 0 || partID >= MaxPartsPerItem {
		return newAPIError(400, "ERR_BAD_REQUEST", "part_id must be in 0..63", false)
	}

	s.mu.Lock()
	s.sweepLocked(now)
	it, ok := s.items[itemID]
	if !ok || !it.committed || it.destroyed {
		s.mu.Unlock()
		return newAPIError(404, "ERR_NOT_FOUND", "spool item not found", false)
	}
	ck := chunkKey{partID: partID, txIdx: txIdx}
	if _, exists := it.receivedSizes[ck]; !exists {
		s.mu.Unlock()
		return newAPIError(404, "ERR_NOT_FOUND", "chunk not found", false)
	}

	limit := s.maxDownloadsPerChunk
	if partID == 0 {
		limit = MaxManifestDownloads // Independent 16-download cap for manifest (part_id=0).
	}
	if it.downloads[ck] >= limit {
		s.mu.Unlock()
		return newAPIError(403, "ERR_DOWNLOAD_LIMIT_EXCEEDED", "chunk download limit exceeded", false)
	}
	it.downloads[ck]++

	if s.backend == SpoolMemory {
		data := it.memChunks[ck]
		snap := make([]byte, len(data))
		copy(snap, data)
		s.mu.Unlock()
		defer clear(snap)
		return s.streamReaderWithDeadline(w, r, rc, bytes.NewReader(snap), int64(len(snap)))
	}

	// Disk mode: track activeIO so concurrent AckBurn on Windows cleans up right after f.Close()!
	it.activeIO++
	chunkPath := s.chunkFilePath(it.mailboxID, it.id, partID, txIdx)
	modTime := it.createdAt
	s.mu.Unlock()

	f, err := os.Open(chunkPath)
	if err != nil {
		s.releaseItemIO(it)
		if os.IsNotExist(err) {
			return newAPIError(404, "ERR_NOT_FOUND", "chunk file not found", false)
		}
		return err
	}

	var serveErr error
	if s.bw != nil {
		info, serr := f.Stat()
		if serr != nil {
			_ = f.Close()
			s.releaseItemIO(it)
			return serr
		}
		serveErr = s.streamReaderWithDeadline(w, r, rc, f, info.Size())
	} else {
		// Serve directly via http.ServeContent (uses Linux sendfile zero-copy) with bounded write deadline.
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if rc != nil {
			dl := s.stallTimeout * 2
			if dl < 2*time.Minute {
				dl = 2 * time.Minute
			}
			_ = rc.SetWriteDeadline(time.Now().Add(dl))
		}
		http.ServeContent(w, r, "", modTime, f)
		if rc != nil {
			_ = rc.SetWriteDeadline(time.Time{})
		}
	}

	// Close f strictly BEFORE releaseItemIO so Windows releases file lock before deferred RemoveAll!
	_ = f.Close()
	s.releaseItemIO(it)
	return serveErr
}

func (s *SpoolStore) AckBurn(itemID string, now time.Time) error {
	if s.backend == SpoolOff {
		return errSpoolDisabled()
	}
	if !isValidItemID(itemID) {
		return newAPIError(400, "ERR_BAD_REQUEST", "invalid item_id", false)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked(now)

	it, ok := s.items[itemID]
	if !ok || !it.committed || it.destroyed {
		return newAPIError(404, "ERR_NOT_FOUND", "spool item not found or already burned", false)
	}
	s.destroyItemLocked(it)
	return nil
}
