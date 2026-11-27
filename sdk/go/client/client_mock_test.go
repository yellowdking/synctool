package client

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	synccrypto "github.com/yellowdking/synctool/sdk/go/crypto"
	"github.com/yellowdking/synctool/sdk/go/envelope"
)

// mockRelay implements the frozen PROTOCOL.md endpoints in-process so sdk/go/client tests
// run standalone with zero dependency on internal/relay.
type mockRelay struct {
	mu          sync.Mutex
	accessKey   string
	spoolOff    bool
	blocksChunk int
	certExpAt   int64
	clockShift  int64
	part0Gets   map[string]int
	failChunkAt map[string]int // "item:part:tx" -> remaining failures

	rooms     map[string]*mockRoom
	pipes     map[string]*mockPipe
	mailboxes map[string]*mockMailbox
	items     map[string]*mockSpoolItem
}

type mockRoom struct {
	id        string
	pipeID    string
	senderTok string
	recvTok   string
	joined    bool
	state     string // waiting | joined | closed | burned
	reason    string
	msgs      []roomMessageWire
	notifyCh  chan struct{}
}

type mockPipe struct {
	roomID   string
	channels map[string]chan mockPipeTransfer
}

type mockPipeTransfer struct {
	data []byte
	done chan struct{}
}

type mockMailbox struct {
	authPK ed25519.PublicKey
	tokens map[string]string // token_id -> hash_hex
}

type mockSpoolItem struct {
	itemID        string
	mailboxID     string
	uploadToken   string
	sealedHeader  string
	declaredBytes int64
	parts         []envelope.PartLayout
	chunks        map[string][]byte // "part:tx" -> bytes
	committed     bool
	createdAt     int64
	expiresAt     int64
}

func newMockRelay(t *testing.T, accessKey string, spoolOff bool, blocksChunk int) (*mockRelay, *httptest.Server, string) {
	t.Helper()
	if blocksChunk <= 0 {
		blocksChunk = 4
	}
	mr := &mockRelay{
		accessKey:   accessKey,
		spoolOff:    spoolOff,
		blocksChunk: blocksChunk,
		certExpAt:   time.Now().Add(730 * 24 * time.Hour).Unix(),
		part0Gets:   make(map[string]int),
		failChunkAt: make(map[string]int),
		rooms:       make(map[string]*mockRoom),
		pipes:       make(map[string]*mockPipe),
		mailboxes:   make(map[string]*mockMailbox),
		items:       make(map[string]*mockSpoolItem),
	}

	// Generate self-signed ECDSA P-256 cert with 127.0.0.1 IP SAN & TLS 1.3
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Unix(mr.certExpAt, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	pinSum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	pinHex := hex.EncodeToString(pinSum[:])

	srv := httptest.NewUnstartedServer(mr)
	srv.TLS = &tls.Config{
		MinVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{der},
			PrivateKey:  priv,
		}},
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return mr, srv, pinHex
}

func (m *mockRelay) writeErr(w http.ResponseWriter, status int, code, msg string, extra map[string]any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	resp := map[string]any{"error": code, "message": msg, "retryable": code == envelope.ErrCodeClockSkew}
	for k, v := range extra {
		resp[k] = v
	}
	_ = json.NewEncoder(w).Encode(resp)
}

func (m *mockRelay) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	tsStr := r.Header.Get(synccrypto.HeaderRelayTS)
	nonce := r.Header.Get(synccrypto.HeaderRelayNonce)
	sig := r.Header.Get(synccrypto.HeaderRelaySig)
	if tsStr == "" || len(nonce) != 32 || len(sig) != 64 {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	isStreamPut := r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/chunks/")
	var bodyBytes []byte
	var bodyBinding string
	if isStreamPut {
		if r.ContentLength < 0 {
			m.writeErr(w, 400, envelope.ErrCodeBadRequest, "missing content-length", nil)
			return
		}
		bodyBinding = synccrypto.BodyBindingStream(r.ContentLength)
	} else {
		bodyBytes, _ = io.ReadAll(io.LimitReader(r.Body, 64*1024))
		bodyBinding = synccrypto.BodyBindingControl(bodyBytes)
	}
	extra := synccrypto.ExtraTokenBinding(r.Header.Get(synccrypto.HeaderDepositToken), r.Header.Get(synccrypto.HeaderUploadToken))
	if !synccrypto.VerifyRelayRequest(m.accessKey, r.Method, r.URL.RequestURI(), tsStr, nonce, bodyBinding, extra, sig) {
		w.WriteHeader(http.StatusNotFound) // Silent stealth 404
		return
	}
	tsVal, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	now := time.Now().Unix() + m.clockShift
	if tsVal-now > 60 || now-tsVal > 60 {
		m.writeErr(w, 409, envelope.ErrCodeClockSkew, "clock skew", map[string]any{
			"server_ts":    now,
			"max_skew_sec": 60,
		})
		return
	}

	p := r.URL.Path
	switch {
	case r.Method == http.MethodGet && p == "/v1/ping":
		_ = json.NewEncoder(w).Encode(map[string]any{
			"proto_v":                 1,
			"server_ts":               now,
			"profile":                 "nano",
			"spool_backend":           m.spoolBackendName(),
			"cert_expires_at":         m.certExpAt,
			"cert_rotate_recommended": m.certExpAt-now < 30*86400,
		})
	case r.Method == http.MethodGet && p == "/v1/caps":
		_ = json.NewEncoder(w).Encode(map[string]any{
			"proto_v":                      1,
			"profile":                      "nano",
			"server_ts":                    now,
			"cert_expires_at":              m.certExpAt,
			"cert_rotate_recommended":      m.certExpAt-now < 30*86400,
			"crypto_plaintext_block_bytes": 65536,
			"crypto_block_bytes":           65552,
			"streaming": map[string]any{
				"enabled":                   true,
				"blocks_per_chunk":          m.blocksChunk,
				"max_transport_chunk_bytes": m.blocksChunk * 65552,
			},
			"spool": map[string]any{
				"enabled":                        !m.spoolOff,
				"backend":                        m.spoolBackendName(),
				"max_item_bytes":                 int64(10 * 1024 * 1024),
				"max_manifest_downloads":         16,
				"max_downloads_per_chunk":        5,
				"max_deposit_tokens_per_mailbox": 16,
			},
		})
	case r.Method == http.MethodPost && p == "/v1/rooms":
		m.handleCreateRoom(w, bodyBytes)
	case strings.HasPrefix(p, "/v1/rooms/"):
		m.handleRoomRoutes(w, r, bodyBytes)
	case strings.HasPrefix(p, "/v1/pipe/"):
		m.handlePipeRoutes(w, r)
	case strings.HasPrefix(p, "/v1/mailboxes/") || strings.HasPrefix(p, "/v1/spool/"):
		if m.spoolOff {
			m.writeErr(w, 403, envelope.ErrCodeSpoolDisabled, "spool disabled", map[string]any{"suggest_mode": "pipe"})
			return
		}
		m.handleSpoolRoutes(w, r, bodyBytes, bodyBinding, tsStr, nonce)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (m *mockRelay) spoolBackendName() string {
	if m.spoolOff {
		return "off"
	}
	return "memory"
}

func (m *mockRelay) handleCreateRoom(w http.ResponseWriter, body []byte) {
	var req struct {
		RoomID        string `json:"room_id"`
		TTLSec        int    `json:"ttl_sec"`
		InitialMsgB64 string `json:"initial_msg_b64"`
	}
	_ = json.Unmarshal(body, &req)
	pipeBytes, _ := synccrypto.GenerateRandomBytes(16)
	pipeID := hex.EncodeToString(pipeBytes)
	sTok, _ := synccrypto.GenerateTokenB64U()
	rTok, _ := synccrypto.GenerateTokenB64U()

	rm := &mockRoom{
		id:        req.RoomID,
		pipeID:    pipeID,
		senderTok: sTok,
		recvTok:   rTok,
		state:     "waiting",
		notifyCh:  make(chan struct{}),
	}
	if req.InitialMsgB64 != "" {
		rm.msgs = append(rm.msgs, roomMessageWire{Seq: 1, From: "sender", Kind: "handshake", MsgB64: req.InitialMsgB64})
	}
	m.mu.Lock()
	m.rooms[req.RoomID] = rm
	m.pipes[pipeID] = &mockPipe{roomID: req.RoomID, channels: make(map[string]chan mockPipeTransfer)}
	m.mu.Unlock()

	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"room_id":      rm.id,
		"pipe_id":      rm.pipeID,
		"sender_token": rm.senderTok,
		"expires_at":   time.Now().Unix() + 300,
		"seq":          len(rm.msgs),
	})
}

func (m *mockRelay) handleRoomRoutes(w http.ResponseWriter, r *http.Request, body []byte) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/rooms/"), "/")
	if len(parts) != 2 {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	roomID, action := parts[0], parts[1]
	m.mu.Lock()
	rm, ok := m.rooms[roomID]
	m.mu.Unlock()
	if !ok {
		m.writeErr(w, 404, envelope.ErrCodeNotFound, "room not found", nil)
		return
	}

	switch action {
	case "join":
		m.mu.Lock()
		defer m.mu.Unlock()
		if rm.state == "burned" {
			m.writeErr(w, 410, envelope.ErrCodeRoomBurned, "burned", nil)
			return
		}
		if rm.joined {
			m.writeErr(w, 409, envelope.ErrCodeRoomBusy, "busy", nil)
			return
		}
		rm.joined = true
		rm.state = "joined"
		_ = json.NewEncoder(w).Encode(map[string]any{
			"room_id":        rm.id,
			"pipe_id":        rm.pipeID,
			"receiver_token": rm.recvTok,
			"expires_at":     time.Now().Unix() + 300,
			"seq":            len(rm.msgs),
			"messages":       rm.msgs,
		})
	case "messages":
		tok := r.Header.Get(synccrypto.HeaderRoomToken)
		var req struct {
			Kind   string `json:"kind"`
			MsgB64 string `json:"msg_b64"`
		}
		_ = json.Unmarshal(body, &req)
		m.mu.Lock()
		defer m.mu.Unlock()
		if rm.state == "burned" {
			m.writeErr(w, 410, envelope.ErrCodeRoomBurned, "burned", nil)
			return
		}
		from := ""
		if tok == rm.senderTok {
			from = "sender"
		} else if tok == rm.recvTok {
			from = "receiver"
		} else {
			m.writeErr(w, 401, envelope.ErrCodeUnauthorizedToken, "bad room token", nil)
			return
		}
		seq := len(rm.msgs) + 1
		rm.msgs = append(rm.msgs, roomMessageWire{Seq: seq, From: from, Kind: req.Kind, MsgB64: req.MsgB64})
		close(rm.notifyCh)
		rm.notifyCh = make(chan struct{})
		_ = json.NewEncoder(w).Encode(map[string]any{"seq": seq})
	case "events":
		since, _ := strconv.Atoi(r.URL.Query().Get("since"))
		mode := r.URL.Query().Get("mode")
		if mode == "sse" {
			w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
			w.Header().Set("X-Accel-Buffering", "no")
			flusher, _ := w.(http.Flusher)
			for {
				m.mu.Lock()
				var toSend []roomMessageWire
				for _, msg := range rm.msgs {
					if msg.Seq > since {
						toSend = append(toSend, msg)
					}
				}
				state := rm.state
				reason := rm.reason
				ch := rm.notifyCh
				m.mu.Unlock()

				for _, msg := range toSend {
					b, _ := json.Marshal(msg)
					fmt.Fprintf(w, "id: %d\nevent: message\ndata: %s\n\n", msg.Seq, b)
					since = msg.Seq
				}
				if flusher != nil {
					flusher.Flush()
				}
				if state == "burned" {
					fmt.Fprintf(w, "event: burned\ndata: {\"reason\":%q}\n\n", reason)
					if flusher != nil {
						flusher.Flush()
					}
					return
				}
				if state == "closed" {
					fmt.Fprintf(w, "event: closed\ndata: {\"reason\":%q}\n\n", reason)
					if flusher != nil {
						flusher.Flush()
					}
					return
				}
				select {
				case <-ch:
				case <-r.Context().Done():
					return
				case <-time.After(2 * time.Second):
					fmt.Fprintf(w, "event: reconnect\ndata: {\"since\":%d}\n\n", since)
					if flusher != nil {
						flusher.Flush()
					}
					return
				}
			}
		}
		m.mu.Lock()
		var out []roomMessageWire
		for _, msg := range rm.msgs {
			if msg.Seq > since {
				out = append(out, msg)
			}
		}
		state := rm.state
		reason := rm.reason
		m.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"state": state, "seq": len(rm.msgs), "messages": out, "reason": reason})
	case "close":
		var req struct {
			Reason string `json:"reason"`
		}
		_ = json.Unmarshal(body, &req)
		m.mu.Lock()
		if req.Reason == "verify_failed" || req.Reason == "rejected" {
			rm.state = "burned"
		} else {
			rm.state = "closed"
		}
		rm.reason = req.Reason
		close(rm.notifyCh)
		rm.notifyCh = make(chan struct{})
		m.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"room_id": rm.id, "state": rm.state})
	}
}

func (m *mockRelay) handlePipeRoutes(w http.ResponseWriter, r *http.Request) {
	// /v1/pipe/{pipe_id}/parts/{part_id}/chunks/{tx_idx}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/pipe/"), "/")
	if len(parts) != 5 {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	pipeID, partID, txIdx := parts[0], parts[2], parts[4]
	key := partID + ":" + txIdx

	m.mu.Lock()
	pipe, ok := m.pipes[pipeID]
	if !ok {
		m.mu.Unlock()
		m.writeErr(w, 404, envelope.ErrCodeNotFound, "pipe not found", nil)
		return
	}
	ch, exists := pipe.channels[key]
	if !exists {
		ch = make(chan mockPipeTransfer)
		pipe.channels[key] = ch
	}
	m.mu.Unlock()

	if r.Method == http.MethodPut {
		data, _ := io.ReadAll(r.Body)
		done := make(chan struct{})
		select {
		case ch <- mockPipeTransfer{data: data, done: done}:
			<-done
			_ = json.NewEncoder(w).Encode(map[string]any{"pipe_id": pipeID, "bytes_relayed": len(data)})
		case <-r.Context().Done():
			return
		case <-time.After(5 * time.Second):
			m.writeErr(w, 504, envelope.ErrCodePipePeerTimeout, "peer timeout", nil)
		}
		return
	}
	if r.Method == http.MethodGet {
		select {
		case tr := <-ch:
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Content-Length", strconv.Itoa(len(tr.data)))
			_, _ = w.Write(tr.data)
			close(tr.done)
		case <-r.Context().Done():
			return
		case <-time.After(5 * time.Second):
			m.writeErr(w, 504, envelope.ErrCodePipePeerTimeout, "peer timeout", nil)
		}
	}
}

func (m *mockRelay) verifyMboxSig(r *http.Request, mailboxID, ts, nonce, bodyBinding string) bool {
	m.mu.Lock()
	mb, ok := m.mailboxes[mailboxID]
	m.mu.Unlock()
	if !ok {
		return false
	}
	return synccrypto.VerifyMailboxRequest(mb.authPK, r.Method, r.URL.RequestURI(), mailboxID, ts, nonce, bodyBinding, r.Header.Get(synccrypto.HeaderMailboxSig))
}

func (m *mockRelay) handleSpoolRoutes(w http.ResponseWriter, r *http.Request, body []byte, bodyBinding, ts, nonce string) {
	p := r.URL.Path
	if strings.HasPrefix(p, "/v1/mailboxes/") {
		segs := strings.Split(strings.TrimPrefix(p, "/v1/mailboxes/"), "/")
		mbID := segs[0]
		if r.Method == http.MethodPut && len(segs) == 1 {
			var req struct {
				AuthPKB64 string `json:"auth_pk_b64"`
			}
			_ = json.Unmarshal(body, &req)
			pk, err := base64.RawURLEncoding.DecodeString(req.AuthPKB64)
			if err != nil || len(pk) != 32 || synccrypto.DeriveMailboxID(pk) != mbID {
				m.writeErr(w, 400, envelope.ErrCodeBadRequest, "mailbox_id derivation mismatch", nil)
				return
			}
			if !synccrypto.VerifyMailboxRequest(ed25519.PublicKey(pk), r.Method, r.URL.RequestURI(), mbID, ts, nonce, bodyBinding, r.Header.Get(synccrypto.HeaderMailboxSig)) {
				m.writeErr(w, 401, envelope.ErrCodeUnauthorizedToken, "bad mailbox sig", nil)
				return
			}
			m.mu.Lock()
			if _, exists := m.mailboxes[mbID]; !exists {
				m.mailboxes[mbID] = &mockMailbox{authPK: ed25519.PublicKey(pk), tokens: make(map[string]string)}
			}
			cnt := len(m.mailboxes[mbID].tokens)
			m.mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{"mailbox_id": mbID, "registered": true, "deposit_token_count": cnt})
			return
		}
		if !m.verifyMboxSig(r, mbID, ts, nonce, bodyBinding) {
			m.writeErr(w, 401, envelope.ErrCodeUnauthorizedToken, "bad mailbox sig", nil)
			return
		}
		if len(segs) == 2 && segs[1] == "deposit-tokens" && r.Method == http.MethodPost {
			var req struct {
				TokenID      string `json:"token_id"`
				TokenHashHex string `json:"token_hash_hex"`
			}
			_ = json.Unmarshal(body, &req)
			m.mu.Lock()
			m.mailboxes[mbID].tokens[req.TokenID] = req.TokenHashHex
			cnt := len(m.mailboxes[mbID].tokens)
			m.mu.Unlock()
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"token_id": req.TokenID, "active_count": cnt})
			return
		}
		if len(segs) == 3 && segs[1] == "deposit-tokens" && r.Method == http.MethodDelete {
			m.mu.Lock()
			delete(m.mailboxes[mbID].tokens, segs[2])
			cnt := len(m.mailboxes[mbID].tokens)
			m.mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{"token_id": segs[2], "revoked": true, "active_count": cnt})
			return
		}
		if len(segs) == 2 && segs[1] == "items" && r.Method == http.MethodGet {
			m.mu.Lock()
			var list []InboxItemMeta
			for _, it := range m.items {
				if it.mailboxID == mbID && it.committed {
					list = append(list, InboxItemMeta{
						ItemID:       it.itemID,
						CreatedAt:    it.createdAt,
						ExpiresAt:    it.expiresAt,
						TotalBytes:   it.declaredBytes,
						SealedHeader: it.sealedHeader,
						Parts:        it.parts,
					})
				}
			}
			m.mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{"mailbox_id": mbID, "items": list})
			return
		}
	}

	if p == "/v1/spool/init" && r.Method == http.MethodPost {
		var req struct {
			MailboxID          string                `json:"mailbox_id"`
			DeclaredTotalBytes int64                 `json:"declared_total_bytes"`
			SealedHeader       string                `json:"sealed_header"`
			Parts              []envelope.PartLayout `json:"parts"`
		}
		_ = json.Unmarshal(body, &req)
		tokHash := synccrypto.HashDepositToken(r.Header.Get(synccrypto.HeaderDepositToken))
		m.mu.Lock()
		mb, ok := m.mailboxes[req.MailboxID]
		allowed := false
		if ok {
			for _, h := range mb.tokens {
				if h == tokHash {
					allowed = true
					break
				}
			}
		}
		if !allowed {
			m.mu.Unlock()
			m.writeErr(w, 401, envelope.ErrCodeUnauthorizedToken, "invalid or revoked deposit token", nil)
			return
		}
		idRaw, _ := synccrypto.GenerateRandomBytes(16)
		itemID := "itm_" + hex.EncodeToString(idRaw)
		upTok, _ := synccrypto.GenerateTokenB64U()
		now := time.Now().Unix()
		m.items[itemID] = &mockSpoolItem{
			itemID:        itemID,
			mailboxID:     req.MailboxID,
			uploadToken:   upTok,
			sealedHeader:  req.SealedHeader,
			declaredBytes: req.DeclaredTotalBytes,
			parts:         req.Parts,
			chunks:        make(map[string][]byte),
			createdAt:     now,
			expiresAt:     now + 3600,
		}
		m.mu.Unlock()
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"item_id":                   itemID,
			"upload_token":              upTok,
			"max_transport_chunk_bytes": m.blocksChunk * 65552,
			"upload_expires_at":         now + 1800,
			"expires_at":                now + 3600,
		})
		return
	}

	if strings.HasPrefix(p, "/v1/spool/") {
		segs := strings.Split(strings.TrimPrefix(p, "/v1/spool/"), "/")
		itemID := segs[0]
		m.mu.Lock()
		it, ok := m.items[itemID]
		m.mu.Unlock()
		if !ok {
			m.writeErr(w, 404, envelope.ErrCodeNotFound, "item not found", nil)
			return
		}
		if r.Method == http.MethodPut && len(segs) == 5 {
			if r.Header.Get(synccrypto.HeaderUploadToken) != it.uploadToken {
				m.writeErr(w, 401, envelope.ErrCodeUnauthorizedToken, "bad upload token", nil)
				return
			}
			data, _ := io.ReadAll(r.Body)
			m.mu.Lock()
			it.chunks[segs[2]+":"+segs[4]] = data
			m.mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{"item_id": itemID, "received_bytes": len(data)})
			return
		}
		if r.Method == http.MethodPost && len(segs) == 2 && segs[1] == "commit" {
			if r.Header.Get(synccrypto.HeaderUploadToken) != it.uploadToken {
				m.writeErr(w, 401, envelope.ErrCodeUnauthorizedToken, "bad upload token", nil)
				return
			}
			m.mu.Lock()
			it.committed = true
			exp := it.expiresAt
			m.mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{"item_id": itemID, "committed": true, "expires_at": exp})
			return
		}
		if r.Method == http.MethodGet && len(segs) == 5 {
			if !m.verifyMboxSig(r, it.mailboxID, ts, nonce, bodyBinding) {
				m.writeErr(w, 401, envelope.ErrCodeUnauthorizedToken, "bad mailbox sig", nil)
				return
			}
			key := segs[2] + ":" + segs[4]
			failKey := itemID + ":" + key
			m.mu.Lock()
			if m.failChunkAt[failKey] > 0 {
				m.failChunkAt[failKey]--
				m.mu.Unlock()
				m.writeErr(w, 504, envelope.ErrCodeRelayUnreachable, "simulated transient chunk drop", nil)
				return
			}
			if segs[2] == "0" {
				m.part0Gets[itemID]++
			}
			data, exists := it.chunks[key]
			m.mu.Unlock()
			if !exists {
				m.writeErr(w, 404, envelope.ErrCodeNotFound, "chunk not found", nil)
				return
			}
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Content-Length", strconv.Itoa(len(data)))
			_, _ = w.Write(data)
			return
		}
		if r.Method == http.MethodPost && len(segs) == 2 && segs[1] == "ack" {
			if !m.verifyMboxSig(r, it.mailboxID, ts, nonce, bodyBinding) {
				m.writeErr(w, 401, envelope.ErrCodeUnauthorizedToken, "bad mailbox sig", nil)
				return
			}
			m.mu.Lock()
			delete(m.items, itemID)
			m.mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{"item_id": itemID, "burned": true})
			return
		}
	}
	w.WriteHeader(http.StatusNotFound)
}
