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

func (c *Client) EnsureMailboxRegistered(ctx context.Context) error {
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

// RevokeDevice removes a lost/retired peer DeviceCard locally and, if a mailbox deposit token
// was registered for that peer, deletes only that single token hash on the relay (zero impact on other peers).
func (c *Client) RevokeDevice(ctx context.Context, deviceID string) error {
	card, err := c.keyStore.GetDevice(deviceID)
	if err != nil {
		return err
	}
	if card == nil {
		return envelope.NewError(envelope.ErrCodeDeviceUntrusted, false, 0, "device not found in keystore", nil)
	}
	// Always remove local trust first so subsequent traffic is immediately blocked even if relay is offline.
	if err := c.keyStore.DeleteDevice(card.DeviceID); err != nil {
		return err
	}
	if card.InboundTokenID != "" {
		path := "/v1/mailboxes/" + c.mailboxKeys.MailboxID + "/deposit-tokens/" + card.InboundTokenID
		_, err := c.doControl(ctx, http.MethodDelete, path, nil, reqOptions{
			MailboxID:     c.mailboxKeys.MailboxID,
			MailboxAuthSK: c.mailboxKeys.AuthPriv,
		})
		if err != nil && !envelope.IsCode(err, envelope.ErrCodeNotFound) && !envelope.IsCode(err, envelope.ErrCodeSpoolDisabled) {
			return err
		}
	}
	return nil
}

// --- Flow 2 Paired Send (Mode B Spool + Mode A Direct) ---

// SendToDevice sends an authenticated 0-RTT encrypted parcel to a trusted paired device.
func (c *Client) SendToDevice(ctx context.Context, targetDeviceID string, parcel envelope.ParcelInput, opts SendOptions) (*SendResult, error) {
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

	caps, err := c.Capabilities(ctx)
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
	sealedB64 := base64.RawURLEncoding.EncodeToString(sealedHdr[:])

	mode := opts.DeliveryMode
	if mode == "" {
		mode = "auto"
	}

	if mode == "pipe" {
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

	// Upload part_id = 1..N (Blobs) with checkpoint persistence
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
			_ = c.keyStore.PutCheckpoint(envelope.TransferCheckpoint{
				Direction:    "send",
				MsgID:        prep.MsgID,
				ItemID:       initOut.ItemID,
				PartID:       b.PartID,
				NextTxIdx:    txIdx + 1,
				NextBlockIdx: uint32((txIdx + 1) * blocksPerChunk),
				UploadToken:  initOut.UploadToken,
				ExpiresAt:    initOut.UploadExpiresAt,
			})
			emitProgress(b.PartID, partDone, partTotal)
			return nil
		})
		_ = rc.Close()
		clear(encKey[:])
		_ = c.keyStore.DeleteCheckpoint("send", prep.MsgID, b.PartID)
		if upErr != nil {
			abortCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			_, _ = c.doControl(abortCtx, http.MethodDelete, "/v1/spool/"+initOut.ItemID, nil, reqOptions{UploadToken: initOut.UploadToken})
			cancel()
			return nil, upErr
		}
	}

	commitResp, err := c.doControl(ctx, http.MethodPost, "/v1/spool/"+initOut.ItemID+"/commit", map[string]any{}, reqOptions{
		UploadToken: initOut.UploadToken,
	})
	if err != nil {
		return nil, err
	}
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
		if healErr := c.SyncMailbox(ctx); healErr == nil {
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
func (c *Client) ListInbox(ctx context.Context, filterAppID string) ([]InboxPreview, error) {
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
		// Check local Manifest cache first to avoid re-downloading part_id=0.
		if cached, _ := c.keyStore.GetCachedManifest(it.ItemID); cached != nil {
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

		hdrBytes, err := base64.RawURLEncoding.DecodeString(it.SealedHeader)
		if err != nil {
			continue
		}
		opened, err := c.openAndVerifySealedHeader(hdrBytes)
		if err != nil {
			continue
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
	if err != nil {
		return nil, envelope.NewError(envelope.ErrCodeCryptoSignatureInvalid, false, 0, "decode sealed_header", nil)
	}
	opened, err := c.openAndVerifySealedHeader(hdrBytes)
	if err != nil {
		return nil, err
	}
	defer opened.Zero()

	partMap := make(map[uint32]envelope.PartLayout, len(target.Parts))
	for _, p := range target.Parts {
		partMap[p.PartID] = p
	}
	p0Layout, ok := partMap[0]
	if !ok {
		return nil, envelope.NewError(envelope.ErrCodeManifestInvalid, false, 0, "spool item missing part_id=0", nil)
	}

	var manifest *envelope.Manifest
	wantManifestSHA := hex.EncodeToString(opened.ManifestSHA256[:])
	if cached, _ := c.keyStore.GetCachedManifest(itemID); cached != nil && cached.Manifest.MsgID == opened.MsgID {
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
		manifest, _, err = c.pullAndVerifyManifest(opened.MsgIDRaw, opened.MsgID, opened.Part0Key, opened.Part0NoncePrefix, p0Layout, opened, func(txIdx int) ([]byte, error) {
			return c.getSpoolChunk(ctx, itemID, 0, txIdx)
		})
		if err != nil {
			return nil, err
		}
	}

	var doneBytes int64 = p0Layout.TotalBytes
	receivedBlobs, err := c.pullAndVerifyBlobs(ctx, itemID, opened.MsgIDRaw, manifest, partMap, target.TotalBytes, &doneBytes, "spool", func(partID uint32, txIdx int) ([]byte, error) {
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
// on 90s reconnect events, falling back to 20s Long-Poll if SSE is unavailable, and self-healing
// automatically if a memory-spool relay restarts).
func (c *Client) WatchInbox(ctx context.Context, onEvent func(InboxWatchEvent) error) error {
	sinceTS := c.effectiveUnixNow() - 1
	if sinceTS < 0 {
		sinceTS = 0
	}
	seenItems := make(map[string]struct{})
	usePoll := false
	healed404 := false
	for {
		if err := ctx.Err(); err != nil {
			return envelope.WrapError(envelope.ErrCodeCancelled, false, 0, "watch inbox cancelled", err)
		}
		if !usePoll {
			path := fmt.Sprintf("/v1/mailboxes/%s/events?mode=sse&since_ts=%d", c.mailboxKeys.MailboxID, sinceTS)
			httpResp, err := c.openSignedStream(ctx, http.MethodGet, path, reqOptions{
				MailboxID:     c.mailboxKeys.MailboxID,
				MailboxAuthSK: c.mailboxKeys.AuthPriv,
				AcceptSSE:     true,
			})
			if err != nil {
				if envelope.IsCode(err, envelope.ErrCodeNotFound) && !healed404 {
					healed404 = true
					if healErr := c.SyncMailbox(ctx); healErr == nil {
						continue
					}
				}
				if envelope.IsCode(err, envelope.ErrCodeSpoolDisabled) || envelope.IsCode(err, envelope.ErrCodeAuthFailed) || envelope.IsCode(err, envelope.ErrCodeUnauthorizedToken) || envelope.IsCode(err, envelope.ErrCodeNotFound) {
					return err
				}
				usePoll = true
				continue
			}
			healed404 = false
			var cbErr error
			parseErr := parseSSEStream(httpResp.Body, func(ev sseEvent) error {
				switch ev.Event {
				case "new_item":
					var item InboxWatchEvent
					if err := json.Unmarshal([]byte(ev.Data), &item); err != nil {
						return nil
					}
					if item.CreatedAt > sinceTS {
						sinceTS = item.CreatedAt
					}
					if _, dup := seenItems[item.ItemID]; dup {
						return nil
					}
					seenItems[item.ItemID] = struct{}{}
					if onEvent != nil {
						if err := onEvent(item); err != nil {
							cbErr = err
							return errStopSSE
						}
					}
				case "reconnect":
					return errStopSSE
				}
				return nil
			})
			_ = httpResp.Body.Close()
			if cbErr != nil {
				return cbErr
			}
			if parseErr != nil && !errors.Is(parseErr, errStopSSE) {
				usePoll = true
			}
			continue
		}

		// Long-poll fallback
		path := fmt.Sprintf("/v1/mailboxes/%s/events?mode=poll&wait_sec=20&since_ts=%d", c.mailboxKeys.MailboxID, sinceTS)
		resp, err := c.doControl(ctx, http.MethodGet, path, nil, reqOptions{
			MailboxID:     c.mailboxKeys.MailboxID,
			MailboxAuthSK: c.mailboxKeys.AuthPriv,
		})
		if err != nil {
			if envelope.IsCode(err, envelope.ErrCodeNotFound) && !healed404 {
				healed404 = true
				if healErr := c.SyncMailbox(ctx); healErr == nil {
					continue
				}
			}
			return err
		}
		healed404 = false
		var out struct {
			Items    []InboxWatchEvent `json:"items"`
			ServerTS int64             `json:"server_ts"`
		}
		if err := json.Unmarshal(resp.Body, &out); err != nil {
			return envelope.WrapError(envelope.ErrCodeBadRequest, false, resp.StatusCode, "decode mailbox poll", err)
		}
		for _, item := range out.Items {
			if item.CreatedAt > sinceTS {
				sinceTS = item.CreatedAt
			}
			if _, dup := seenItems[item.ItemID]; dup {
				continue
			}
			seenItems[item.ItemID] = struct{}{}
			if onEvent != nil {
				if err := onEvent(item); err != nil {
					return err
				}
			}
		}
		if out.ServerTS > sinceTS {
			sinceTS = out.ServerTS
		}
	}
}

func (c *Client) getSpoolChunk(ctx context.Context, itemID string, partID uint32, txIdx int) ([]byte, error) {
	path := fmt.Sprintf("/v1/spool/%s/parts/%d/chunks/%d", itemID, partID, txIdx)
	resp, err := c.doSignedWithSkewRetry(ctx, http.MethodGet, path, nil, reqOptions{
		MailboxID:     c.mailboxKeys.MailboxID,
		MailboxAuthSK: c.mailboxKeys.AuthPriv,
	})
	if err != nil {
		return nil, err
	}
	return resp.Body, nil
}
