package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	synccrypto "github.com/yellowdking/synctool/sdk/go/crypto"
	"github.com/yellowdking/synctool/sdk/go/envelope"
)

const watchDedupRingCap = 4096

type watchDedupRing struct {
	ring  [watchDedupRingCap]string
	head  int
	count int
	set   map[string]struct{}
}

func newWatchDedupRing() *watchDedupRing {
	return &watchDedupRing{
		set: make(map[string]struct{}, 128),
	}
}

func (r *watchDedupRing) seenOrAdd(id string) bool {
	if _, ok := r.set[id]; ok {
		return true
	}
	if r.count == watchDedupRingCap {
		oldest := r.ring[r.head]
		delete(r.set, oldest)
		r.ring[r.head] = id
		r.head = (r.head + 1) % watchDedupRingCap
	} else {
		idx := (r.head + r.count) % watchDedupRingCap
		r.ring[idx] = id
		r.count++
	}
	r.set[id] = struct{}{}
	return false
}

// EnsureMailboxRegistered idempotently registers this device's blinded mailbox (PUT /v1/mailboxes/{mailbox_id}).
// Gracefully treats 403 ERR_SPOOL_DISABLED as non-fatal so --spool=off relays work cleanly.
func (c *Client) EnsureMailboxRegistered(ctx context.Context) error {
	return c.SyncMailbox(ctx)
}

// RegisterMailbox is an ergonomic alias for EnsureMailboxRegistered.
func (c *Client) RegisterMailbox(ctx context.Context) error {
	return c.SyncMailbox(ctx)
}

func (c *Client) registerPeerDepositToken(ctx context.Context) (tokenID string, tokenHashHex string, rawToken string, err error) {
	rawToken, err = synccrypto.GenerateTokenB64U()
	if err != nil {
		return "", "", "", envelope.WrapError(envelope.ErrCodeCryptoHandshakeFailed, false, 0, "generate deposit token", err)
	}
	idBytes, err := synccrypto.GenerateRandomBytes(8)
	if err != nil {
		return "", "", "", envelope.WrapError(envelope.ErrCodeCryptoHandshakeFailed, false, 0, "generate token id", err)
	}
	tokenID = "dt_" + hex.EncodeToString(idBytes)
	tokenHashHex = synccrypto.HashDepositToken(rawToken)
	body := map[string]string{
		"token_id":       tokenID,
		"token_hash_hex": tokenHashHex,
	}
	path := "/v1/mailboxes/" + c.mailboxKeys.MailboxID + "/deposit-tokens"
	_, err = c.doControl(ctx, http.MethodPost, path, body, reqOptions{
		MailboxID:     c.mailboxKeys.MailboxID,
		MailboxAuthSK: c.mailboxKeys.AuthPriv,
	})
	if err != nil {
		return "", "", "", err
	}
	return tokenID, tokenHashHex, rawToken, nil
}

// RevokeDevice performs a crash-safe 2-phase single-device revocation (ST-P1-8):
//  1. Immediately persists Revoked=true + PendingTokenDelete in KeyStore so local trust is revoked offline
//     and SyncMailbox will never re-upload the revoked token hash.
//  2. Deletes only that peer's deposit_token on the relay; once confirmed (200/404/403), removes the tombstone.
func (c *Client) RevokeDevice(ctx context.Context, deviceID string) error {
	done, err := c.beginOp()
	if err != nil {
		return err
	}
	defer done()

	card, err := c.keyStore.GetDevice(deviceID)
	if err != nil {
		return err
	}
	if card == nil {
		return envelope.NewError(envelope.ErrCodeDeviceUntrusted, false, 0, "device not found in keystore", nil)
	}

	// Phase 1: Persist Revoked=true + PendingTokenDelete locally FIRST.
	card.Revoked = true
	card.PendingTokenDelete = card.InboundTokenID != ""
	if err := c.keyStore.PutDevice(*card); err != nil {
		return err
	}
	if card.InboundTokenID != "" {
		if pks, ok := c.keyStore.(pendingTokenDeletesKeyStore); ok {
			_ = pks.AddPendingTokenDelete(card.InboundTokenID)
		}
	}

	// Phase 2: Delete peer's deposit_token on relay (if any); retryable via SyncMailbox or RevokeDevice if offline.
	if card.InboundTokenID != "" {
		if err := c.deleteRelayDepositToken(ctx, card.InboundTokenID); err != nil {
			return err
		}
		if pks, ok := c.keyStore.(pendingTokenDeletesKeyStore); ok {
			_ = pks.RemovePendingTokenDelete(card.InboundTokenID)
		}
	}
	return c.keyStore.DeleteDevice(card.DeviceID)
}

// --- Flow 2 Paired Send (Mode B Spool + Mode A Direct) ---

// SendToDevice sends an authenticated 0-RTT encrypted parcel to a trusted paired device.
func (c *Client) SendToDevice(ctx context.Context, targetDeviceID string, parcel envelope.ParcelInput, opts SendOptions) (*SendResult, error) {
	done, err := c.beginOp()
	if err != nil {
		return nil, err
	}
	defer done()

	mode := opts.DeliveryMode
	if mode == "" {
		mode = DeliveryAuto
	}
	if mode != DeliveryAuto && mode != DeliverySpool && mode != DeliveryPipe {
		return nil, envelope.NewError(envelope.ErrCodeBadRequest, false, 0, fmt.Sprintf("invalid delivery mode %q (expected auto, spool, or pipe)", opts.DeliveryMode), nil)
	}

	card, err := c.keyStore.GetDevice(targetDeviceID)
	if err != nil {
		return nil, err
	}
	if card == nil || card.Revoked {
		return nil, envelope.NewError(envelope.ErrCodeDeviceUntrusted, false, 0, "target device is untrusted or revoked", nil)
	}
	kemPK, err := base64.RawURLEncoding.DecodeString(card.KEMPK)
	if err != nil || len(kemPK) != 32 {
		return nil, envelope.NewError(envelope.ErrCodeCryptoSignatureInvalid, false, 0, "invalid target kem_pk", nil)
	}
	recipIDBytes, err := hex.DecodeString(card.DeviceID)
	if err != nil || len(recipIDBytes) != 16 {
		return nil, envelope.NewError(envelope.ErrCodeDeviceUntrusted, false, 0, "invalid target device_id", nil)
	}
	var recipIDRaw [16]byte
	copy(recipIDRaw[:], recipIDBytes)

	caps, err := c.capabilitiesInternal(ctx)
	if err != nil {
		return nil, err
	}
	blocksPerChunk := caps.Streaming.BlocksPerChunk
	if blocksPerChunk <= 0 {
		blocksPerChunk = 16
	}
	prep, err := c.prepareParcel(parcel, blocksPerChunk)
	if err != nil {
		return nil, err
	}
	defer prep.Zero()

	ephPriv, err := synccrypto.GenerateEphemeralX25519()
	if err != nil {
		return nil, envelope.WrapError(envelope.ErrCodeCryptoHandshakeFailed, false, 0, "generate ephemeral x25519", err)
	}
	sealedHdr, _, p0Key, p0NP, err := synccrypto.Seal0RTTHeaderDeterministic(
		c.deviceKeys, ephPriv, prep.MsgIDRaw, recipIDRaw, kemPK, prep.CreatedAt, prep.ManifestSHA,
	)
	if err != nil {
		return nil, envelope.WrapError(envelope.ErrCodeCryptoHandshakeFailed, false, 0, "seal 0-RTT header", err)
	}
	defer clear(p0Key[:])
	defer clear(p0NP[:])
	sealedB64 := base64.RawURLEncoding.EncodeToString(sealedHdr[:])

	if mode == DeliveryPipe {
		return c.sendDirectViaPipe(ctx, prep, sealedB64, p0Key, p0NP, blocksPerChunk, opts)
	}

	// Mode B spool path ("auto" or "spool")
	if !caps.Spool.Enabled {
		return nil, envelope.NewError(envelope.ErrCodeSpoolDisabled, false, 403, "relay spool is disabled (--spool=off); use pipe mode", map[string]any{
			"suggest_mode": "pipe",
		})
	}
	if card.MailboxID == "" || card.OutboundDepositToken == "" {
		return nil, envelope.NewError(envelope.ErrCodeSpoolDisabled, false, 403, "peer device was paired without mailbox; use pipe mode", map[string]any{
			"suggest_mode": "pipe",
		})
	}
	if caps.Spool.MaxItemBytes > 0 && prep.TotalEnc > caps.Spool.MaxItemBytes {
		return nil, envelope.NewError(envelope.ErrCodeOfflineQuotaExceeded, false, 413, "parcel exceeds relay spool max_item_bytes", map[string]any{
			"scope":          "item",
			"max_item_bytes": caps.Spool.MaxItemBytes,
			"total_bytes":    prep.TotalEnc,
			"suggest_mode":   "pipe",
		})
	}

	initBody := map[string]any{
		"mailbox_id":           card.MailboxID,
		"declared_total_bytes": prep.TotalEnc,
		"ttl_sec":              opts.TTLSec,
		"sealed_header":        sealedB64,
		"parts":                prep.Parts,
	}
	initResp, err := c.doControl(ctx, http.MethodPost, "/v1/spool/init", initBody, reqOptions{
		DepositToken: card.OutboundDepositToken,
	})
	if err != nil {
		return nil, err
	}
	var initOut struct {
		ItemID          string `json:"item_id"`
		UploadToken     string `json:"upload_token"`
		UploadExpiresAt int64  `json:"upload_expires_at"`
		ExpiresAt       int64  `json:"expires_at"`
	}
	if err := json.Unmarshal(initResp.Body, &initOut); err != nil {
		return nil, envelope.WrapError(envelope.ErrCodeBadRequest, false, initResp.StatusCode, "decode spool init", err)
	}

	// ST-P1-10: Best-effort cleanup of uncommitted relay spool quota on any aborted/failed upload step!
	committed := false
	defer func() {
		if !committed && initOut.ItemID != "" && initOut.UploadToken != "" {
			abortCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer cancel()
			_, _ = c.doControl(abortCtx, http.MethodDelete, "/v1/spool/"+initOut.ItemID, nil, reqOptions{UploadToken: initOut.UploadToken})
		}
	}()

	var totalSent int64
	emitProgress := func(partID uint32, partDone, partTotal int64) {
		if opts.OnProgress == nil {
			return
		}
		opts.OnProgress(envelope.TransferEvent{
			Type:           "event",
			Event:          "transfer_progress",
			Stage:          "transferring",
			Direction:      "send",
			Mode:           "spool",
			MsgID:          prep.MsgID,
			PartID:         partID,
			PartsTotal:     len(prep.Parts),
			BytesDone:      totalSent,
			BytesTotal:     prep.TotalEnc,
			PartBytesDone:  partDone,
			PartBytesTotal: partTotal,
			TS:             time.Now().Unix(),
		})
	}

	putSpoolChunk := func(partID uint32, txIdx int, data []byte) error {
		path := fmt.Sprintf("/v1/spool/%s/parts/%d/chunks/%d", initOut.ItemID, partID, txIdx)
		chunkCopy := data
		_, err := c.doSignedWithSkewRetry(ctx, http.MethodPut, path, nil, reqOptions{
			ContentType: "application/octet-stream",
			UploadToken: initOut.UploadToken,
			IsStream:    true,
			StreamLen:   int64(len(chunkCopy)),
			StreamFactory: func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(chunkCopy)), nil
			},
		})
		return err
	}

	// Upload part_id = 0 (Manifest)
	var p0Done int64
	if err := streamUploadPart(bytes.NewReader(prep.ManifestPad), int64(len(prep.ManifestPad)), p0Key, p0NP, prep.MsgIDRaw, 0, blocksPerChunk, 0, func(txIdx int, chunk []byte) error {
		if err := putSpoolChunk(0, txIdx, chunk); err != nil {
			return err
		}
		p0Done += int64(len(chunk))
		totalSent += int64(len(chunk))
		emitProgress(0, p0Done, prep.Parts[0].TotalBytes)
		return nil
	}); err != nil {
		return nil, err
	}

	// Upload part_id = 1..N (Blobs) — ST-P1-13: no dead per-chunk "send" keystore rewrites!
	for i, b := range prep.Blobs {
		encKey, np, err := synccrypto.DeriveBlobPartKeys(prep.MsgIDRaw, b.PartID, b.BlobKey[:])
		if err != nil {
			return nil, err
		}
		rc, _, err := b.Input.OpenStream()
		if err != nil {
			clear(encKey[:])
			return nil, err
		}
		var partDone int64
		partTotal := prep.Parts[i+1].TotalBytes
		upErr := streamUploadPart(rc, b.Desc.Size, encKey, np, prep.MsgIDRaw, b.PartID, blocksPerChunk, 0, func(txIdx int, chunk []byte) error {
			if err := putSpoolChunk(b.PartID, txIdx, chunk); err != nil {
				return err
			}
			partDone += int64(len(chunk))
			totalSent += int64(len(chunk))
			emitProgress(b.PartID, partDone, partTotal)
			return nil
		})
		_ = rc.Close()
		clear(encKey[:])
		if upErr != nil {
			return nil, upErr
		}
	}

	commitResp, err := c.doControl(ctx, http.MethodPost, "/v1/spool/"+initOut.ItemID+"/commit", map[string]any{}, reqOptions{
		UploadToken: initOut.UploadToken,
	})
	if err != nil {
		return nil, err
	}
	committed = true

	var commitOut struct {
		ExpiresAt int64 `json:"expires_at"`
	}
	_ = json.Unmarshal(commitResp.Body, &commitOut)
	if commitOut.ExpiresAt == 0 {
		commitOut.ExpiresAt = initOut.ExpiresAt
	}

	return &SendResult{
		Mode:       "spool",
		MsgID:      prep.MsgID,
		ItemID:     initOut.ItemID,
		TotalBytes: prep.TotalEnc,
		ExpiresAt:  commitOut.ExpiresAt,
	}, nil
}

// --- Mode B Two-Phase Inbox: ListInbox, FetchParcel, WatchInbox ---

func (c *Client) listRawInboxItems(ctx context.Context) ([]InboxItemMeta, error) {
	path := "/v1/mailboxes/" + c.mailboxKeys.MailboxID + "/items"
	opts := reqOptions{
		MailboxID:     c.mailboxKeys.MailboxID,
		MailboxAuthSK: c.mailboxKeys.AuthPriv,
	}
	resp, err := c.doControl(ctx, http.MethodGet, path, nil, opts)
	// Self-healing: if memory-spool relay restarted and returned 404 ERR_NOT_FOUND for our mailbox,
	// transparently re-register the mailbox + peer deposit_tokens once and retry!
	if envelope.IsCode(err, envelope.ErrCodeNotFound) {
		if healErr := c.syncMailboxInternal(ctx); healErr == nil {
			resp, err = c.doControl(ctx, http.MethodGet, path, nil, opts)
		}
	}
	if err != nil {
		return nil, err
	}
	var out struct {
		Items []InboxItemMeta `json:"items"`
	}
	if err := json.Unmarshal(resp.Body, &out); err != nil {
		return nil, envelope.WrapError(envelope.ErrCodeBadRequest, false, resp.StatusCode, "decode mailbox items", err)
	}
	return out.Items, nil
}

// ListInbox lists committed inbox parcels (Phase 1: Manifest preview ONLY, cached locally by item_id
// so repeated refreshes never exhaust the relay's 16-download cap for part_id=0).
// ST-P0-3: ALWAYS verifies inline SealedHeader, !card.Revoked, !HasSeenMsgID, and cached ManifestSHA256
// BEFORE consulting or returning GetCachedManifest!
func (c *Client) ListInbox(ctx context.Context, filterAppID string) ([]InboxPreview, error) {
	done, err := c.beginOp()
	if err != nil {
		return nil, err
	}
	defer done()

	items, err := c.listRawInboxItems(ctx)
	if err != nil {
		return nil, err
	}
	activeIDs := make(map[string]struct{}, len(items))
	for _, it := range items {
		activeIDs[it.ItemID] = struct{}{}
	}
	_ = c.keyStore.PruneCachedManifests(activeIDs)

	previews := make([]InboxPreview, 0, len(items))
	for _, it := range items {
		hdrBytes, err := base64.RawURLEncoding.DecodeString(it.SealedHeader)
		if err != nil || len(hdrBytes) != synccrypto.SealedHeaderSize {
			_ = c.keyStore.DeleteCachedManifest(it.ItemID)
			continue
		}
		opened, err := c.openAndVerifySealedHeader(hdrBytes)
		if err != nil {
			_ = c.keyStore.DeleteCachedManifest(it.ItemID)
			continue
		}

		wantManifestSHA := hex.EncodeToString(opened.ManifestSHA256[:])
		if cached, _ := c.keyStore.GetCachedManifest(it.ItemID); cached != nil {
			cacheValid := false
			if cached.Manifest.MsgID == opened.MsgID &&
				cached.Manifest.Sender.DeviceID == opened.SenderDeviceID &&
				cached.Manifest.CreatedAt == opened.CreatedAt {
				if cached.ManifestSHA256 != "" {
					cacheValid = cached.ManifestSHA256 == wantManifestSHA
				} else if raw, merr := envelope.MarshalManifest(&cached.Manifest); merr == nil && sha256.Sum256(raw) == opened.ManifestSHA256 {
					cacheValid = true
				}
			}
			if cacheValid {
				opened.Zero()
				if filterAppID == "" || cached.Manifest.AppID == filterAppID {
					previews = append(previews, InboxPreview{
						ItemID:     it.ItemID,
						CreatedAt:  it.CreatedAt,
						ExpiresAt:  it.ExpiresAt,
						TotalBytes: it.TotalBytes,
						Cached:     true,
						Manifest:   cached.Manifest,
					})
				}
				continue
			}
			// Evict substituted or mismatched cache entry!
			_ = c.keyStore.DeleteCachedManifest(it.ItemID)
		}

		var p0Layout envelope.PartLayout
		hasP0 := false
		for _, p := range it.Parts {
			if p.PartID == 0 {
				p0Layout = p
				hasP0 = true
				break
			}
		}
		if !hasP0 {
			opened.Zero()
			continue
		}
		manifest, manifestSHA, err := c.pullAndVerifyManifest(opened.MsgIDRaw, opened.MsgID, opened.Part0Key, opened.Part0NoncePrefix, p0Layout, opened, func(txIdx int) ([]byte, error) {
			return c.getSpoolChunk(ctx, it.ItemID, 0, txIdx)
		})
		opened.Zero()
		if err != nil {
			continue
		}

		_ = c.keyStore.PutCachedManifest(envelope.CachedManifestEntry{
			ItemID:         it.ItemID,
			CachedAt:       time.Now().Unix(),
			ExpiresAt:      it.ExpiresAt,
			ManifestSHA256: hex.EncodeToString(manifestSHA[:]),
			Manifest:       *manifest,
		})
		if filterAppID == "" || manifest.AppID == filterAppID {
			previews = append(previews, InboxPreview{
				ItemID:     it.ItemID,
				CreatedAt:  it.CreatedAt,
				ExpiresAt:  it.ExpiresAt,
				TotalBytes: it.TotalBytes,
				Cached:     false,
				Manifest:   *manifest,
			})
		}
	}
	return previews, nil
}

// FetchParcel performs Phase 2 resumable download of itemID, verifies all STREAM AEAD blocks & SHA-256 hashes,
// invokes handler, records seen_msg_ids, and sends an Ed25519-signed ACK to physically burn the relay copy.
func (c *Client) FetchParcel(ctx context.Context, itemID string, handler ParcelHandler, opts ReceiveOptions) (*envelope.Manifest, error) {
	done, err := c.beginOp()
	if err != nil {
		return nil, err
	}
	defer done()

	items, err := c.listRawInboxItems(ctx)
	if err != nil {
		return nil, err
	}
	var target *InboxItemMeta
	for i := range items {
		if items[i].ItemID == itemID {
			target = &items[i]
			break
		}
	}
	if target == nil {
		return nil, envelope.NewError(envelope.ErrCodeNotFound, false, 404, "inbox item not found", nil)
	}
	hdrBytes, err := base64.RawURLEncoding.DecodeString(target.SealedHeader)
	if err != nil || len(hdrBytes) != synccrypto.SealedHeaderSize {
		return nil, envelope.NewError(envelope.ErrCodeCryptoSignatureInvalid, false, 0, "decode sealed_header", nil)
	}
	opened, err := c.openAndVerifySealedHeader(hdrBytes)
	if err != nil {
		_ = c.keyStore.DeleteCachedManifest(itemID)
		return nil, err
	}
	defer opened.Zero()

	// ST-P1-7: Per-client inFlightMsgIDs guard across concurrent FetchParcel calls.
	releaseMsg, claimed := c.claimInFlightMsgID(opened.MsgID)
	if !claimed {
		return nil, envelope.NewError(envelope.ErrCodeMsgReplayDetected, false, 0, "msg_id is already being processed concurrently", map[string]any{"msg_id": opened.MsgID})
	}
	defer releaseMsg()

	if seen, err := c.keyStore.HasSeenMsgID(opened.MsgID); err != nil {
		return nil, err
	} else if seen {
		return nil, envelope.NewError(envelope.ErrCodeMsgReplayDetected, false, 0, "msg_id already processed (replay rejected)", map[string]any{"msg_id": opened.MsgID})
	}

	partMap := make(map[uint32]envelope.PartLayout, len(target.Parts))
	for _, p := range target.Parts {
		if _, dup := partMap[p.PartID]; dup {
			return nil, envelope.NewError(envelope.ErrCodeManifestInvalid, false, 0, fmt.Sprintf("duplicate part_id=%d in spool item parts", p.PartID), nil)
		}
		partMap[p.PartID] = p
	}
	p0Layout, ok := partMap[0]
	if !ok {
		return nil, envelope.NewError(envelope.ErrCodeManifestInvalid, false, 0, "spool item missing part_id=0", nil)
	}

	var manifest *envelope.Manifest
	wantManifestSHA := hex.EncodeToString(opened.ManifestSHA256[:])
	if cached, _ := c.keyStore.GetCachedManifest(itemID); cached != nil {
		if cached.Manifest.MsgID == opened.MsgID &&
			cached.Manifest.Sender.DeviceID == opened.SenderDeviceID &&
			cached.Manifest.CreatedAt == opened.CreatedAt {
			if cached.ManifestSHA256 != "" {
				if cached.ManifestSHA256 == wantManifestSHA {
					m := cached.Manifest
					manifest = &m
				}
			} else if raw, err := envelope.MarshalManifest(&cached.Manifest); err == nil && sha256.Sum256(raw) == opened.ManifestSHA256 {
				m := cached.Manifest
				manifest = &m
			}
		}
		if manifest == nil {
			_ = c.keyStore.DeleteCachedManifest(itemID)
		}
	}
	if manifest == nil {
		var manifestSHA [32]byte
		manifest, manifestSHA, err = c.pullAndVerifyManifest(opened.MsgIDRaw, opened.MsgID, opened.Part0Key, opened.Part0NoncePrefix, p0Layout, opened, func(txIdx int) ([]byte, error) {
			return c.getSpoolChunk(ctx, itemID, 0, txIdx)
		})
		if err != nil {
			return nil, err
		}
		_ = c.keyStore.PutCachedManifest(envelope.CachedManifestEntry{
			ItemID:         itemID,
			CachedAt:       time.Now().Unix(),
			ExpiresAt:      target.ExpiresAt,
			ManifestSHA256: hex.EncodeToString(manifestSHA[:]),
			Manifest:       *manifest,
		})
	}

	// ST-P2-1: Pre-filter by ReceiveOptions.AppID BEFORE downloading blobs, invoking handler, or burning item!
	if opts.AppID != "" && manifest.AppID != opts.AppID {
		return nil, envelope.NewError(envelope.ErrCodeManifestInvalid, false, 0,
			fmt.Sprintf("parcel app_id %q does not match requested app_id %q", manifest.AppID, opts.AppID),
			map[string]any{
				"parcel_app_id":   manifest.AppID,
				"expected_app_id": opts.AppID,
			})
	}

	if len(partMap) != 1+len(manifest.Blobs) {
		return nil, envelope.NewError(envelope.ErrCodeManifestInvalid, false, 0, "spool item parts count does not match signed manifest blobs count", nil)
	}

	var doneBytes int64 = p0Layout.TotalBytes
	receivedBlobs, err := c.pullAndVerifyBlobs(ctx, itemID, opened.MsgIDRaw, manifest, partMap, 0, target.TotalBytes, &doneBytes, "spool", func(partID uint32, txIdx int) ([]byte, error) {
		return c.getSpoolChunk(ctx, itemID, partID, txIdx)
	}, opts.OnProgress)
	if err != nil {
		return nil, err
	}

	if handler != nil {
		if err := handler(envelope.ReceivedParcel{
			ItemID:   itemID,
			Manifest: *manifest,
			Blobs:    receivedBlobs,
		}); err != nil {
			return nil, err
		}
	}

	// Only after handler confirms persistence: record seen_msg_ids, clear cache, send signed ACK to burn.
	if err := c.keyStore.MarkSeenMsgID(opened.MsgID, opened.CreatedAt, time.Now().Unix()); err != nil {
		return nil, err
	}
	_ = c.keyStore.DeleteCachedManifest(itemID)

	ackPath := "/v1/spool/" + itemID + "/ack"
	_, err = c.doControl(ctx, http.MethodPost, ackPath, map[string]any{}, reqOptions{
		MailboxID:     c.mailboxKeys.MailboxID,
		MailboxAuthSK: c.mailboxKeys.AuthPriv,
	})
	if err != nil && !envelope.IsCode(err, envelope.ErrCodeNotFound) {
		return nil, err
	}
	return manifest, nil
}

// WatchInbox subscribes to GET /v1/mailboxes/{mailbox_id}/events via SSE (reopening cleanly
// on 90s reconnect events with since_ts-1 + 4096 FIFO dedup, 60s SSE idle read timeout,
// 250ms..5s backoff, falling back to 20s Long-Poll if SSE is unavailable, and self-healing
// automatically if a memory-spool relay restarts).
func (c *Client) WatchInbox(ctx context.Context, onEvent func(InboxWatchEvent) error) error {
	done, err := c.beginOp()
	if err != nil {
		return err
	}
	defer done()

	watermarkTS := time.Now().Unix()
	if watermarkTS < 0 {
		watermarkTS = 0
	}
	dedup := newWatchDedupRing()
	usePoll := false
	healed404 := false
	backoffAttempt := 0
	var lastFastReconnect time.Time

	for {
		if err := ctx.Err(); err != nil {
			return envelope.WrapError(envelope.ErrCodeCancelled, false, 0, "watch inbox cancelled", err)
		}
		if c.closeCtx != nil && c.closeCtx.Err() != nil {
			return envelope.NewError(envelope.ErrCodeCancelled, false, 0, "client closed", nil)
		}

		querySince := watermarkTS - 1
		if querySince < 0 {
			querySince = 0
		}

		if !usePoll {
			path := fmt.Sprintf("/v1/mailboxes/%s/events?mode=sse&since_ts=%d", c.mailboxKeys.MailboxID, querySince)
			streamBody, err := c.openSSEStreamWithIdleTimeout(ctx, path, reqOptions{
				MailboxID:     c.mailboxKeys.MailboxID,
				MailboxAuthSK: c.mailboxKeys.AuthPriv,
			})
			if err != nil {
				if ctx.Err() != nil {
					return envelope.WrapError(envelope.ErrCodeCancelled, false, 0, "watch inbox cancelled", ctx.Err())
				}
				if c.closeCtx != nil && c.closeCtx.Err() != nil {
					return envelope.NewError(envelope.ErrCodeCancelled, false, 0, "client closed", nil)
				}
				if envelope.IsCode(err, envelope.ErrCodeNotFound) && !healed404 {
					healed404 = true
					if healErr := c.syncMailboxInternal(ctx); healErr == nil {
						continue
					}
				}
				if isFatalWatchOrRoomErr(err) || envelope.IsCode(err, envelope.ErrCodeSpoolDisabled) || envelope.IsCode(err, envelope.ErrCodeNotFound) {
					return err
				}
				if serr := sleepWithBackoff(ctx, backoffAttempt, err); serr != nil {
					return envelope.WrapError(envelope.ErrCodeCancelled, false, 0, "watch inbox cancelled", serr)
				}
				backoffAttempt++
				usePoll = true
				continue
			}
			healed404 = false

			var cbErr error
			sawReconnect := false
			sawAnyEvent := false
			parseErr := parseSSEStream(streamBody, func(ev sseEvent) error {
				sawAnyEvent = true
				switch ev.Event {
				case "new_item":
					var item InboxWatchEvent
					if err := json.Unmarshal([]byte(ev.Data), &item); err != nil {
						return nil
					}
					if item.CreatedAt > watermarkTS {
						watermarkTS = item.CreatedAt
					}
					if dedup.seenOrAdd(item.ItemID) {
						return nil
					}
					if onEvent != nil {
						if err := onEvent(item); err != nil {
							cbErr = err
							return errStopSSE
						}
					}
				case "reconnect":
					sawReconnect = true
					return errStopSSE
				}
				return nil
			})
			_ = streamBody.Close()

			if cbErr != nil {
				return cbErr
			}
			if ctx.Err() != nil {
				return envelope.WrapError(envelope.ErrCodeCancelled, false, 0, "watch inbox cancelled", ctx.Err())
			}
			if c.closeCtx != nil && c.closeCtx.Err() != nil {
				return envelope.NewError(envelope.ErrCodeCancelled, false, 0, "client closed", nil)
			}
			if sawReconnect {
				backoffAttempt = 0
				now := time.Now()
				if !lastFastReconnect.IsZero() && now.Sub(lastFastReconnect) < 100*time.Millisecond {
					if serr := sleepWithBackoff(ctx, 0, nil); serr != nil {
						return envelope.WrapError(envelope.ErrCodeCancelled, false, 0, "watch inbox cancelled", serr)
					}
				}
				lastFastReconnect = now
				continue
			}
			if parseErr != nil && !errors.Is(parseErr, errStopSSE) {
				usePoll = true
			} else if !sawAnyEvent {
				usePoll = true
			}
			if serr := sleepWithBackoff(ctx, backoffAttempt, parseErr); serr != nil {
				return envelope.WrapError(envelope.ErrCodeCancelled, false, 0, "watch inbox cancelled", serr)
			}
			backoffAttempt++
			continue
		}

		// Long-poll fallback
		path := fmt.Sprintf("/v1/mailboxes/%s/events?mode=poll&wait_sec=20&since_ts=%d", c.mailboxKeys.MailboxID, querySince)
		resp, err := c.doControl(ctx, http.MethodGet, path, nil, reqOptions{
			MailboxID:     c.mailboxKeys.MailboxID,
			MailboxAuthSK: c.mailboxKeys.AuthPriv,
		})
		if err != nil {
			if ctx.Err() != nil {
				return envelope.WrapError(envelope.ErrCodeCancelled, false, 0, "watch inbox cancelled", ctx.Err())
			}
			if c.closeCtx != nil && c.closeCtx.Err() != nil {
				return envelope.NewError(envelope.ErrCodeCancelled, false, 0, "client closed", nil)
			}
			if envelope.IsCode(err, envelope.ErrCodeNotFound) && !healed404 {
				healed404 = true
				if healErr := c.syncMailboxInternal(ctx); healErr == nil {
					continue
				}
			}
			if isFatalWatchOrRoomErr(err) || envelope.IsCode(err, envelope.ErrCodeSpoolDisabled) || envelope.IsCode(err, envelope.ErrCodeNotFound) {
				return err
			}
			if serr := sleepWithBackoff(ctx, backoffAttempt, err); serr != nil {
				return envelope.WrapError(envelope.ErrCodeCancelled, false, 0, "watch inbox cancelled", serr)
			}
			backoffAttempt++
			continue
		}
		healed404 = false
		backoffAttempt = 0
		var out struct {
			Items    []InboxWatchEvent `json:"items"`
			ServerTS int64             `json:"server_ts"`
		}
		if err := json.Unmarshal(resp.Body, &out); err != nil {
			return envelope.WrapError(envelope.ErrCodeBadRequest, false, resp.StatusCode, "decode mailbox poll", err)
		}
		for _, item := range out.Items {
			if item.CreatedAt > watermarkTS {
				watermarkTS = item.CreatedAt
			}
			if dedup.seenOrAdd(item.ItemID) {
				continue
			}
			if onEvent != nil {
				if err := onEvent(item); err != nil {
					return err
				}
			}
		}
		if out.ServerTS > watermarkTS {
			watermarkTS = out.ServerTS
		}
		// Retry SSE after a healthy poll cycle so temporary SSE proxy blips self-recover.
		usePoll = false
	}
}

func (c *Client) getSpoolChunk(ctx context.Context, itemID string, partID uint32, txIdx int) ([]byte, error) {
	path := fmt.Sprintf("/v1/spool/%s/parts/%d/chunks/%d", itemID, partID, txIdx)
	resp, err := c.doSignedWithSkewRetry(ctx, http.MethodGet, path, nil, reqOptions{
		MailboxID:     c.mailboxKeys.MailboxID,
		MailboxAuthSK: c.mailboxKeys.AuthPriv,
		MaxRespBytes:  maxChunkRespBytes,
		IsBinaryChunk: true,
	})
	if err != nil {
		return nil, err
	}
	return resp.Body, nil
}
