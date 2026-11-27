package relay

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

func (s *Server) handlePing(w http.ResponseWriter, ac reqAuthContext) {
	exp, rot := s.certs.Status(ac.now)
	writeJSON(w, http.StatusOK, map[string]any{
		"proto_v":                 ProtoVersion,
		"server_ts":               ac.now.Unix(),
		"profile":                 string(s.cfg.Preset.Name),
		"spool_backend":           string(s.spool.Backend()),
		"cert_expires_at":         exp,
		"cert_rotate_recommended": rot,
	})
}

func (s *Server) handleCaps(w http.ResponseWriter, ac reqAuthContext) {
	exp, rot := s.certs.Status(ac.now)
	p := s.cfg.Preset
	spoolCaps := map[string]any{
		"enabled":                        false,
		"backend":                        string(SpoolOff),
		"max_item_bytes":                 int64(0),
		"max_mailbox_bytes":              int64(0),
		"max_total_bytes":                int64(0),
		"max_items_per_mailbox":          0,
		"default_ttl_sec":                int64(0),
		"max_ttl_sec":                    int64(0),
		"uncommitted_ttl_sec":            0,
		"max_manifest_downloads":         0,
		"max_downloads_per_chunk":        0,
		"max_deposit_tokens_per_mailbox": 0,
	}
	if s.spool.Enabled() {
		spoolCaps = map[string]any{
			"enabled":                        true,
			"backend":                        string(s.spool.Backend()),
			"max_item_bytes":                 p.SpoolMaxItemBytes,
			"max_mailbox_bytes":              p.SpoolMaxMailboxBytes,
			"max_total_bytes":                p.SpoolMaxTotalBytes,
			"max_items_per_mailbox":          p.SpoolMaxItemsPerMailbox,
			"default_ttl_sec":                p.SpoolDefaultTTLSec,
			"max_ttl_sec":                    p.SpoolMaxTTLSec,
			"uncommitted_ttl_sec":            UncommittedTTLSec,
			"max_manifest_downloads":         MaxManifestDownloads,
			"max_downloads_per_chunk":        p.MaxDownloadsPerChunk,
			"max_deposit_tokens_per_mailbox": MaxDepositTokensPerMailbox,
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"proto_v":                      ProtoVersion,
		"profile":                      string(p.Name),
		"server_ts":                    ac.now.Unix(),
		"cert_expires_at":              exp,
		"cert_rotate_recommended":      rot,
		"crypto_plaintext_block_bytes": CryptoPlaintextBlockBytes,
		"crypto_block_bytes":           CryptoBlockBytes,
		"streaming": map[string]any{
			"enabled":                     true,
			"blocks_per_chunk":            p.BlocksPerChunk,
			"max_transport_chunk_bytes":   p.MaxTransportChunkBytes,
			"recommended_parallel_chunks": p.RecommendedParallelChunks,
			"max_parallel_chunks":         p.MaxParallelChunks,
			"rendezvous_timeout_sec":      int(s.cfg.RendezvousTimeout.Seconds()),
			"room_ttl_max_sec":            RoomTTLMaxSec,
		},
		"spool": spoolCaps,
	})
}

func (s *Server) handleRoomCreate(w http.ResponseWriter, ac reqAuthContext) {
	var req struct {
		RoomID        string `json:"room_id"`
		TTLSec        int64  `json:"ttl_sec"`
		InitialMsgB64 string `json:"initial_msg_b64"`
	}
	if err := json.Unmarshal(ac.rawBody, &req); err != nil {
		writeAPIError(w, newAPIError(400, "ERR_BAD_REQUEST", "invalid JSON body", false))
		return
	}
	res, err := s.rooms.Create(req.RoomID, req.TTLSec, req.InitialMsgB64, ac.now)
	if err != nil {
		writeHandlerError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, res)
}

func (s *Server) handleRoomJoin(w http.ResponseWriter, roomID string, ac reqAuthContext) {
	var req struct {
		MsgB64 string `json:"msg_b64"`
	}
	if len(ac.rawBody) > 0 {
		if err := json.Unmarshal(ac.rawBody, &req); err != nil {
			writeAPIError(w, newAPIError(400, "ERR_BAD_REQUEST", "invalid JSON body", false))
			return
		}
	}
	res, err := s.rooms.Join(roomID, req.MsgB64, ac.now)
	if err != nil {
		writeHandlerError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleRoomMessages(w http.ResponseWriter, roomID string, ac reqAuthContext) {
	var req struct {
		Kind   string `json:"kind"`
		MsgB64 string `json:"msg_b64"`
	}
	if err := json.Unmarshal(ac.rawBody, &req); err != nil {
		writeAPIError(w, newAPIError(400, "ERR_BAD_REQUEST", "invalid JSON body", false))
		return
	}
	seq, err := s.rooms.PostMessage(roomID, ac.roomTok, req.Kind, req.MsgB64, ac.now)
	if err != nil {
		writeHandlerError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"seq": seq})
}

func (s *Server) handleRoomEvents(w http.ResponseWriter, r *http.Request, roomID string, ac reqAuthContext) {
	q := r.URL.Query()
	since := 0
	if sv := q.Get("since"); sv != "" {
		v, err := strconv.Atoi(sv)
		if err != nil || v < 0 {
			writeAPIError(w, newAPIError(400, "ERR_BAD_REQUEST", "invalid since query param", false))
			return
		}
		since = v
	}
	mode := q.Get("mode")
	if mode == "" {
		mode = "sse"
	}
	if mode != "sse" && mode != "poll" {
		writeAPIError(w, newAPIError(400, "ERR_BAD_REQUEST", "mode must be sse or poll", false))
		return
	}

	if mode == "poll" {
		waitSec := LongPollDefaultSec
		if wv := q.Get("wait_sec"); wv != "" {
			v, err := strconv.Atoi(wv)
			if err != nil || v < 1 || v > LongPollMaxSec {
				writeAPIError(w, newAPIError(400, "ERR_BAD_REQUEST", "wait_sec must be 1..25", false))
				return
			}
			waitSec = v
		}
		snap, ch, err := s.rooms.SnapshotAndWatch(roomID, ac.roomTok, since, s.cfg.NowFunc())
		if err != nil {
			writeHandlerError(w, err)
			return
		}
		if len(snap.Messages) > 0 || snap.State == RoomClosed || snap.State == RoomBurned {
			writeJSON(w, http.StatusOK, snap)
			return
		}
		timer := time.NewTimer(time.Duration(waitSec) * time.Second)
		defer timer.Stop()
		select {
		case <-ch:
			snap, _, err = s.rooms.SnapshotAndWatch(roomID, ac.roomTok, since, s.cfg.NowFunc())
			if err != nil {
				writeHandlerError(w, err)
				return
			}
			writeJSON(w, http.StatusOK, snap)
		case <-timer.C:
			writeJSON(w, http.StatusOK, snap)
		case <-r.Context().Done():
		}
		return
	}

	// SSE mode.
	snap, ch, err := s.rooms.SnapshotAndWatch(roomID, ac.roomTok, since, s.cfg.NowFunc())
	if err != nil {
		writeHandlerError(w, err)
		return
	}

	h := w.Header()
	h.Set("Content-Type", "text/event-stream; charset=utf-8")
	h.Set("Cache-Control", "no-cache, no-transform")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)

	lastSeq := since
	emitSnapshot := func(sn RoomEventsSnapshot) (done bool) {
		for _, m := range sn.Messages {
			b, _ := json.Marshal(m)
			fmt.Fprintf(w, "id: %d\nevent: message\ndata: %s\n\n", m.Seq, b)
			if m.Seq > lastSeq {
				lastSeq = m.Seq
			}
		}
		if sn.State == RoomBurned {
			b, _ := json.Marshal(map[string]string{"reason": sn.Reason})
			fmt.Fprintf(w, "event: burned\ndata: %s\n\n", b)
			if flusher != nil {
				flusher.Flush()
			}
			return true
		}
		if sn.State == RoomClosed {
			b, _ := json.Marshal(map[string]string{"reason": sn.Reason})
			fmt.Fprintf(w, "event: closed\ndata: %s\n\n", b)
			if flusher != nil {
				flusher.Flush()
			}
			return true
		}
		if flusher != nil {
			flusher.Flush()
		}
		return false
	}

	if emitSnapshot(snap) {
		return
	}

	keepalive := time.NewTicker(s.cfg.SSEKeepaliveInterval)
	defer keepalive.Stop()
	maxTimer := time.NewTimer(s.cfg.SSEMaxDuration)
	defer maxTimer.Stop()

	for {
		select {
		case <-ch:
			snap, ch, err = s.rooms.SnapshotAndWatch(roomID, ac.roomTok, lastSeq, s.cfg.NowFunc())
			if err != nil {
				fmt.Fprintf(w, "event: closed\ndata: {\"reason\":\"expired\"}\n\n")
				if flusher != nil {
					flusher.Flush()
				}
				return
			}
			if emitSnapshot(snap) {
				return
			}
		case <-keepalive.C:
			fmt.Fprint(w, ": ping\n\n")
			if flusher != nil {
				flusher.Flush()
			}
		case <-maxTimer.C:
			fmt.Fprintf(w, "event: reconnect\ndata: {\"since\":%d}\n\n", lastSeq)
			if flusher != nil {
				flusher.Flush()
			}
			return
		case <-r.Context().Done():
			return
		}
	}
}

func (s *Server) handleRoomClose(w http.ResponseWriter, roomID string, ac reqAuthContext) {
	var req struct {
		Reason string `json:"reason"`
	}
	if err := json.Unmarshal(ac.rawBody, &req); err != nil {
		writeAPIError(w, newAPIError(400, "ERR_BAD_REQUEST", "invalid JSON body", false))
		return
	}
	state, err := s.rooms.Close(roomID, ac.roomTok, req.Reason, ac.now)
	if err != nil {
		writeHandlerError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"room_id": roomID,
		"state":   string(state),
	})
}

func (s *Server) handlePipePut(w http.ResponseWriter, r *http.Request, rt matchedRoute, ac reqAuthContext) {
	if rt.partID < 0 || rt.partID >= MaxPartsPerItem {
		writeAPIError(w, newAPIError(400, "ERR_BAD_REQUEST", "part_id must be in 0..63 and tx_idx valid uint32", false))
		return
	}
	if r.ContentLength <= 0 {
		writeAPIError(w, newAPIError(400, "ERR_BAD_REQUEST", "Content-Length must be positive", false))
		return
	}
	if r.ContentLength > s.cfg.Preset.MaxTransportChunkBytes {
		writeAPIError(w, &apiError{
			Status:                 413,
			Code:                   "ERR_CHUNK_TOO_LARGE",
			Message:                "chunk exceeds max_transport_chunk_bytes",
			Retryable:              false,
			MaxTransportChunkBytes: s.cfg.Preset.MaxTransportChunkBytes,
		})
		return
	}
	roomCtx, err := s.rooms.AuthorizePipe(rt.param1, ac.roomTok, true, ac.now)
	if err != nil {
		writeHandlerError(w, err)
		return
	}
	n, err := s.pipes.PutChunk(r.Context(), roomCtx, rt.param1, rt.partID, rt.txIdx, r.ContentLength, r.Body, ac.rc, ac.clientIP)
	if err != nil {
		writeHandlerError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"pipe_id":       rt.param1,
		"part_id":       rt.partID,
		"tx_idx":        rt.txIdx,
		"bytes_relayed": n,
	})
}

func (s *Server) handlePipeGet(w http.ResponseWriter, r *http.Request, rt matchedRoute, ac reqAuthContext) {
	if rt.partID < 0 || rt.partID >= MaxPartsPerItem {
		writeAPIError(w, newAPIError(400, "ERR_BAD_REQUEST", "part_id must be in 0..63 and tx_idx valid uint32", false))
		return
	}
	roomCtx, err := s.rooms.AuthorizePipe(rt.param1, ac.roomTok, false, ac.now)
	if err != nil {
		writeHandlerError(w, err)
		return
	}
	if err := s.pipes.GetChunk(r.Context(), roomCtx, rt.param1, rt.partID, rt.txIdx, w, ac.rc, ac.clientIP); err != nil {
		// Only write error JSON if headers were not already written by streaming start.
		var ae *apiError
		if errors.As(err, &ae) {
			writeHandlerError(w, ae)
		}
	}
}

func (s *Server) handleMailboxPut(w http.ResponseWriter, mailboxID string, ac reqAuthContext) {
	if !s.spool.Enabled() {
		writeHandlerError(w, errSpoolDisabled())
		return
	}
	var req struct {
		AuthPKB64 string `json:"auth_pk_b64"`
	}
	if err := json.Unmarshal(ac.rawBody, &req); err != nil {
		writeAPIError(w, newAPIError(400, "ERR_BAD_REQUEST", "invalid JSON body", false))
		return
	}
	pk, err := base64.RawURLEncoding.DecodeString(req.AuthPKB64)
	if err != nil || len(pk) != ed25519.PublicKeySize {
		writeAPIError(w, newAPIError(400, "ERR_BAD_REQUEST", "auth_pk_b64 must decode to 32-byte Ed25519 public key", false))
		return
	}
	if !isLowerHexLen(mailboxID, 32) || DeriveMailboxID(pk) != mailboxID {
		writeAPIError(w, newAPIError(400, "ERR_BAD_REQUEST", "mailbox_id does not match derived auth_pk", false))
		return
	}
	if !VerifyMailboxSig(ed25519.PublicKey(pk), ac.mailboxSig, ac.method, ac.pathAndQuery, mailboxID, ac.tsHeader, ac.nonceHeader, ac.bodyBinding) {
		writeAPIError(w, newAPIError(401, "ERR_UNAUTHORIZED_TOKEN", "invalid X-Sync-Mailbox-Sig", false))
		return
	}
	count, err := s.spool.RegisterMailbox(mailboxID, ed25519.PublicKey(pk))
	if err != nil {
		writeHandlerError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"mailbox_id":          mailboxID,
		"registered":          true,
		"deposit_token_count": count,
	})
}

func (s *Server) verifyExistingMailboxOwner(mailboxID string, ac reqAuthContext) error {
	pk, err := s.spool.GetMailboxAuthPK(mailboxID)
	if err != nil {
		return err
	}
	if !VerifyMailboxSig(pk, ac.mailboxSig, ac.method, ac.pathAndQuery, mailboxID, ac.tsHeader, ac.nonceHeader, ac.bodyBinding) {
		return newAPIError(401, "ERR_UNAUTHORIZED_TOKEN", "invalid X-Sync-Mailbox-Sig", false)
	}
	return nil
}

func (s *Server) handleMailboxTokenAdd(w http.ResponseWriter, mailboxID string, ac reqAuthContext) {
	if err := s.verifyExistingMailboxOwner(mailboxID, ac); err != nil {
		writeHandlerError(w, err)
		return
	}
	var req struct {
		TokenID      string `json:"token_id"`
		TokenHashHex string `json:"token_hash_hex"`
	}
	if err := json.Unmarshal(ac.rawBody, &req); err != nil {
		writeAPIError(w, newAPIError(400, "ERR_BAD_REQUEST", "invalid JSON body", false))
		return
	}
	active, err := s.spool.AddDepositToken(mailboxID, req.TokenID, req.TokenHashHex)
	if err != nil {
		writeHandlerError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"token_id":     req.TokenID,
		"active_count": active,
	})
}

func (s *Server) handleMailboxTokenDel(w http.ResponseWriter, mailboxID, tokenID string, ac reqAuthContext) {
	if err := s.verifyExistingMailboxOwner(mailboxID, ac); err != nil {
		writeHandlerError(w, err)
		return
	}
	active, err := s.spool.DeleteDepositToken(mailboxID, tokenID)
	if err != nil {
		writeHandlerError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"token_id":     tokenID,
		"revoked":      true,
		"active_count": active,
	})
}

func (s *Server) handleMailboxItems(w http.ResponseWriter, mailboxID string, ac reqAuthContext) {
	if err := s.verifyExistingMailboxOwner(mailboxID, ac); err != nil {
		writeHandlerError(w, err)
		return
	}
	res, err := s.spool.ListItems(mailboxID, ac.now)
	if err != nil {
		writeHandlerError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleMailboxEvents(w http.ResponseWriter, r *http.Request, mailboxID string, ac reqAuthContext) {
	if err := s.verifyExistingMailboxOwner(mailboxID, ac); err != nil {
		writeHandlerError(w, err)
		return
	}
	q := r.URL.Query()
	var sinceTS int64
	if sv := q.Get("since_ts"); sv != "" {
		v, err := strconv.ParseInt(sv, 10, 64)
		if err != nil || v < 0 {
			writeAPIError(w, newAPIError(400, "ERR_BAD_REQUEST", "invalid since_ts", false))
			return
		}
		sinceTS = v
	}
	mode := q.Get("mode")
	if mode == "" {
		mode = "sse"
	}
	if mode != "sse" && mode != "poll" {
		writeAPIError(w, newAPIError(400, "ERR_BAD_REQUEST", "mode must be sse or poll", false))
		return
	}

	if mode == "poll" {
		waitSec := LongPollDefaultSec
		if wv := q.Get("wait_sec"); wv != "" {
			v, err := strconv.Atoi(wv)
			if err != nil || v < 1 || v > LongPollMaxSec {
				writeAPIError(w, newAPIError(400, "ERR_BAD_REQUEST", "wait_sec must be 1..25", false))
				return
			}
			waitSec = v
		}
		items, ch, err := s.spool.SnapshotMailboxEvents(mailboxID, sinceTS, s.cfg.NowFunc())
		if err != nil {
			writeHandlerError(w, err)
			return
		}
		if len(items) > 0 {
			writeJSON(w, http.StatusOK, map[string]any{"items": items, "server_ts": s.cfg.NowFunc().Unix()})
			return
		}
		timer := time.NewTimer(time.Duration(waitSec) * time.Second)
		defer timer.Stop()
		select {
		case <-ch:
			items, _, err = s.spool.SnapshotMailboxEvents(mailboxID, sinceTS, s.cfg.NowFunc())
			if err != nil {
				writeHandlerError(w, err)
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"items": items, "server_ts": s.cfg.NowFunc().Unix()})
		case <-timer.C:
			writeJSON(w, http.StatusOK, map[string]any{"items": []MailboxEventItem{}, "server_ts": s.cfg.NowFunc().Unix()})
		case <-r.Context().Done():
		}
		return
	}

	// SSE mode.
	items, ch, err := s.spool.SnapshotMailboxEvents(mailboxID, sinceTS, s.cfg.NowFunc())
	if err != nil {
		writeHandlerError(w, err)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "text/event-stream; charset=utf-8")
	h.Set("Cache-Control", "no-cache, no-transform")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)

	seen := make(map[string]bool)
	emitItems := func(list []MailboxEventItem) {
		for _, it := range list {
			if seen[it.ItemID] {
				continue
			}
			seen[it.ItemID] = true
			if it.CreatedAt > sinceTS {
				sinceTS = it.CreatedAt
			}
			b, _ := json.Marshal(it)
			fmt.Fprintf(w, "event: new_item\ndata: %s\n\n", b)
		}
		if flusher != nil {
			flusher.Flush()
		}
	}

	emitItems(items)

	keepalive := time.NewTicker(s.cfg.SSEKeepaliveInterval)
	defer keepalive.Stop()
	maxTimer := time.NewTimer(s.cfg.SSEMaxDuration)
	defer maxTimer.Stop()

	for {
		select {
		case <-ch:
			items, ch, err = s.spool.SnapshotMailboxEvents(mailboxID, sinceTS-1, s.cfg.NowFunc())
			if err != nil {
				return
			}
			emitItems(items)
		case <-keepalive.C:
			fmt.Fprint(w, ": ping\n\n")
			if flusher != nil {
				flusher.Flush()
			}
		case <-maxTimer.C:
			fmt.Fprintf(w, "event: reconnect\ndata: {\"since_ts\":%d}\n\n", sinceTS)
			if flusher != nil {
				flusher.Flush()
			}
			return
		case <-r.Context().Done():
			return
		}
	}
}

func (s *Server) handleSpoolInit(w http.ResponseWriter, ac reqAuthContext) {
	var req SpoolInitRequest
	if err := json.Unmarshal(ac.rawBody, &req); err != nil {
		writeAPIError(w, newAPIError(400, "ERR_BAD_REQUEST", "invalid JSON body", false))
		return
	}
	res, err := s.spool.InitUpload(req, ac.depositTok, ac.now)
	if err != nil {
		writeHandlerError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, res)
}

func (s *Server) handleSpoolPutChunk(w http.ResponseWriter, r *http.Request, rt matchedRoute, ac reqAuthContext) {
	if rt.partID < 0 || rt.partID >= MaxPartsPerItem {
		writeAPIError(w, newAPIError(400, "ERR_BAD_REQUEST", "part_id must be in 0..63 and tx_idx valid uint32", false))
		return
	}
	release, ok := s.gate.Acquire(r.Context(), ac.clientIP, TransferSemWait)
	if !ok {
		w.Header().Set("Retry-After", "5")
		writeAPIError(w, newAPIError(429, "ERR_RATE_LIMITED", "concurrent transfer stream limit reached", true))
		return
	}
	defer release()

	n, err := s.spool.PutChunk(r.Context(), rt.param1, ac.uploadTok, rt.partID, rt.txIdx, r.ContentLength, r.Body, ac.rc, ac.now)
	if err != nil {
		writeHandlerError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"item_id":        rt.param1,
		"part_id":        rt.partID,
		"tx_idx":         rt.txIdx,
		"received_bytes": n,
	})
}

func (s *Server) handleSpoolCommit(w http.ResponseWriter, itemID string, ac reqAuthContext) {
	exp, err := s.spool.Commit(itemID, ac.uploadTok, ac.now)
	if err != nil {
		writeHandlerError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"item_id":    itemID,
		"committed":  true,
		"expires_at": exp,
	})
}

func (s *Server) handleSpoolAbort(w http.ResponseWriter, itemID string, ac reqAuthContext) {
	if err := s.spool.Abort(itemID, ac.uploadTok, ac.now); err != nil {
		writeHandlerError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"item_id": itemID,
		"aborted": true,
	})
}

func (s *Server) handleSpoolGetChunk(w http.ResponseWriter, r *http.Request, rt matchedRoute, ac reqAuthContext) {
	if rt.partID < 0 || rt.partID >= MaxPartsPerItem {
		writeAPIError(w, newAPIError(400, "ERR_BAD_REQUEST", "part_id must be in 0..63 and tx_idx valid uint32", false))
		return
	}
	mbID, authPK, err := s.spool.ResolveItemOwner(rt.param1, ac.now)
	if err != nil {
		writeHandlerError(w, err)
		return
	}
	if !VerifyMailboxSig(authPK, ac.mailboxSig, ac.method, ac.pathAndQuery, mbID, ac.tsHeader, ac.nonceHeader, ac.bodyBinding) {
		writeAPIError(w, newAPIError(401, "ERR_UNAUTHORIZED_TOKEN", "invalid X-Sync-Mailbox-Sig", false))
		return
	}
	release, ok := s.gate.Acquire(r.Context(), ac.clientIP, TransferSemWait)
	if !ok {
		w.Header().Set("Retry-After", "5")
		writeAPIError(w, newAPIError(429, "ERR_RATE_LIMITED", "concurrent transfer stream limit reached", true))
		return
	}
	defer release()

	if err := s.spool.ServeChunk(w, r, rt.param1, rt.partID, rt.txIdx, ac.now); err != nil {
		writeHandlerError(w, err)
	}
}

func (s *Server) handleSpoolAck(w http.ResponseWriter, itemID string, ac reqAuthContext) {
	mbID, authPK, err := s.spool.ResolveItemOwner(itemID, ac.now)
	if err != nil {
		writeHandlerError(w, err)
		return
	}
	if !VerifyMailboxSig(authPK, ac.mailboxSig, ac.method, ac.pathAndQuery, mbID, ac.tsHeader, ac.nonceHeader, ac.bodyBinding) {
		writeAPIError(w, newAPIError(401, "ERR_UNAUTHORIZED_TOKEN", "invalid X-Sync-Mailbox-Sig", false))
		return
	}
	if err := s.spool.AckBurn(itemID, ac.now); err != nil {
		writeHandlerError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"item_id": itemID,
		"burned":  true,
	})
}
