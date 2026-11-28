package relay

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

type connCtxKey struct{}

const (
	corsExposeHeaders = "Retry-After, Content-Length, Content-Type"
	corsAllowMethods  = "GET, POST, PUT, DELETE, OPTIONS"
	corsAllowHeaders  = "Authorization, Content-Type, X-Sync-TS, X-Sync-Nonce, X-Sync-Sig, X-Sync-Client, X-Sync-Room-Token, X-Sync-Mailbox-Sig, X-Sync-Deposit-Token, X-Sync-Upload-Token, Last-Event-ID"
	corsMaxAge        = "86400"
)

type apiError struct {
	Status                 int      `json:"-"`
	Code                   string   `json:"error"`
	Message                string   `json:"message"`
	Retryable              bool     `json:"retryable"`
	ServerTS               int64    `json:"server_ts,omitempty"`
	MaxSkewSec             int      `json:"max_skew_sec,omitempty"`
	Scope                  string   `json:"scope,omitempty"`
	MaxItemBytes           int64    `json:"max_item_bytes,omitempty"`
	MaxTransportChunkBytes int64    `json:"max_transport_chunk_bytes,omitempty"`
	SuggestMode            string   `json:"suggest_mode,omitempty"`
	MissingChunks          []string `json:"missing_chunks,omitempty"`
}

func (e *apiError) Error() string {
	return fmt.Sprintf("%s (%d): %s", e.Code, e.Status, e.Message)
}

func newAPIError(status int, code, msg string, retryable bool) *apiError {
	return &apiError{
		Status:    status,
		Code:      code,
		Message:   msg,
		Retryable: retryable,
	}
}

type routeKind int

const (
	routeUnknown routeKind = iota
	routePing
	routeCaps
	routeRoomCreate
	routeRoomJoin
	routeRoomMessages
	routeRoomEvents
	routeRoomClose
	routePipePut
	routePipeGet
	routeMailboxPut
	routeMailboxTokenAdd
	routeMailboxTokenDel
	routeMailboxItems
	routeMailboxEvents
	routeSpoolInit
	routeSpoolPutChunk
	routeSpoolCommit
	routeSpoolAbort
	routeSpoolGetChunk
	routeSpoolAck
)

type matchedRoute struct {
	kind          routeKind
	isDataUpload  bool
	isDataOrEvent bool
	param1        string
	param2        string
	partID        int
	txIdx         uint32
}

func matchRoute(method, rawPath string) (matchedRoute, bool) {
	if !strings.HasPrefix(rawPath, "/v1/") {
		return matchedRoute{}, false
	}
	if strings.Contains(rawPath, "..") || strings.Contains(rawPath, `\`) || strings.Contains(rawPath, "//") {
		return matchedRoute{}, false
	}
	trimmed := strings.TrimPrefix(rawPath, "/v1/")
	if trimmed == "" || strings.HasSuffix(trimmed, "/") {
		return matchedRoute{}, false
	}
	segs := strings.Split(trimmed, "/")
	for _, seg := range segs {
		if seg == "" || seg == "." {
			return matchedRoute{}, false
		}
	}

	switch segs[0] {
	case "ping":
		if len(segs) == 1 && method == http.MethodGet {
			return matchedRoute{kind: routePing}, true
		}
	case "caps":
		if len(segs) == 1 && method == http.MethodGet {
			return matchedRoute{kind: routeCaps}, true
		}
	case "rooms":
		if len(segs) == 1 && method == http.MethodPost {
			return matchedRoute{kind: routeRoomCreate}, true
		}
		if len(segs) == 3 {
			roomID, action := segs[1], segs[2]
			switch {
			case action == "join" && method == http.MethodPost:
				return matchedRoute{kind: routeRoomJoin, param1: roomID}, true
			case action == "messages" && method == http.MethodPost:
				return matchedRoute{kind: routeRoomMessages, param1: roomID}, true
			case action == "events" && method == http.MethodGet:
				return matchedRoute{kind: routeRoomEvents, isDataOrEvent: true, param1: roomID}, true
			case action == "close" && method == http.MethodPost:
				return matchedRoute{kind: routeRoomClose, param1: roomID}, true
			}
		}
	case "pipe":
		// /v1/pipe/{pipe_id}/parts/{part_id}/chunks/{tx_idx}
		if len(segs) == 6 && segs[2] == "parts" && segs[4] == "chunks" {
			partID, ok1 := parsePartID(segs[3])
			txIdx, ok2 := parseTxIdx(segs[5])
			if !ok1 || !ok2 {
				partID = -1
			}
			if method == http.MethodPut {
				return matchedRoute{kind: routePipePut, isDataUpload: true, isDataOrEvent: true, param1: segs[1], partID: partID, txIdx: txIdx}, true
			}
			if method == http.MethodGet {
				return matchedRoute{kind: routePipeGet, isDataOrEvent: true, param1: segs[1], partID: partID, txIdx: txIdx}, true
			}
		}
	case "mailboxes":
		if len(segs) == 2 && method == http.MethodPut {
			return matchedRoute{kind: routeMailboxPut, param1: segs[1]}, true
		}
		if len(segs) == 3 {
			mbID, action := segs[1], segs[2]
			switch {
			case action == "deposit-tokens" && method == http.MethodPost:
				return matchedRoute{kind: routeMailboxTokenAdd, param1: mbID}, true
			case action == "items" && method == http.MethodGet:
				return matchedRoute{kind: routeMailboxItems, param1: mbID}, true
			case action == "events" && method == http.MethodGet:
				return matchedRoute{kind: routeMailboxEvents, isDataOrEvent: true, param1: mbID}, true
			}
		}
		if len(segs) == 4 && segs[2] == "deposit-tokens" && method == http.MethodDelete {
			return matchedRoute{kind: routeMailboxTokenDel, param1: segs[1], param2: segs[3]}, true
		}
	case "spool":
		if len(segs) == 2 && segs[1] == "init" && method == http.MethodPost {
			return matchedRoute{kind: routeSpoolInit}, true
		}
		if len(segs) == 2 && method == http.MethodDelete {
			return matchedRoute{kind: routeSpoolAbort, param1: segs[1]}, true
		}
		if len(segs) == 3 {
			itemID, action := segs[1], segs[2]
			if action == "commit" && method == http.MethodPost {
				return matchedRoute{kind: routeSpoolCommit, param1: itemID}, true
			}
			if action == "ack" && method == http.MethodPost {
				return matchedRoute{kind: routeSpoolAck, param1: itemID}, true
			}
		}
		// /v1/spool/{item_id}/parts/{part_id}/chunks/{tx_idx}
		if len(segs) == 6 && segs[2] == "parts" && segs[4] == "chunks" {
			partID, ok1 := parsePartID(segs[3])
			txIdx, ok2 := parseTxIdx(segs[5])
			if !ok1 || !ok2 {
				partID = -1
			}
			if method == http.MethodPut {
				return matchedRoute{kind: routeSpoolPutChunk, isDataUpload: true, isDataOrEvent: true, param1: segs[1], partID: partID, txIdx: txIdx}, true
			}
			if method == http.MethodGet {
				return matchedRoute{kind: routeSpoolGetChunk, isDataOrEvent: true, param1: segs[1], partID: partID, txIdx: txIdx}, true
			}
		}
	}
	return matchedRoute{}, false
}

func parsePartID(s string) (int, bool) {
	v, err := strconv.Atoi(s)
	if err != nil || v < 0 || v >= MaxPartsPerItem {
		return -1, false
	}
	return v, true
}

func parseTxIdx(s string) (uint32, bool) {
	v, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, false
	}
	return uint32(v), true
}

type Server struct {
	cfg     ResolvedConfig
	hmacKey [32]byte
	certs   *CertManager
	guard   *IPGuard
	gate    *TransferGate
	bw      *BandwidthLimiter
	nonces  *NonceCache
	rooms   *RoomManager
	pipes   *PipeHub
	spool   *SpoolStore
	logger  *log.Logger

	gcWake chan struct{}
	gcStop chan struct{}
	gcOnce sync.Once
}

func NewServer(cfg ResolvedConfig, logger *log.Logger) (*Server, error) {
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}
	if !cfg.DisableMemTune {
		ApplyMemoryTuning(cfg.Preset)
	}
	certs, err := NewCertManager(cfg)
	if err != nil {
		return nil, err
	}

	s := &Server{
		cfg:     cfg,
		hmacKey: DeriveRelayHMACKey(cfg.AccessKey),
		certs:   certs,
		guard:   NewIPGuard(cfg.Preset, cfg.TrustedProxies),
		gate:    NewTransferGate(cfg.Preset.MaxTransferStreams, cfg.Preset.MaxTransferStreamsPerIP),
		bw:      NewBandwidthLimiter(cfg.MaxBandwidthMbps),
		nonces:  NewNonceCache(cfg.Preset.MaxNonceEntries, NonceCacheTTL),
		logger:  logger,
		gcWake:  make(chan struct{}, 1),
		gcStop:  make(chan struct{}),
	}

	wake := func() {
		select {
		case s.gcWake <- struct{}{}:
		default:
		}
	}

	s.rooms = NewRoomManager(cfg.Preset.MaxActiveRooms, wake)
	s.pipes = NewPipeHubWithMaxDuration(cfg.Preset.CopyBufBytes, cfg.RendezvousTimeout, cfg.StallTimeout, cfg.MaxChunkDuration, s.gate, s.bw)
	spool, err := NewSpoolStore(cfg, s.bw, wake)
	if err != nil {
		return nil, err
	}
	s.spool = spool

	go s.runLazyGC()
	if s.rooms.HasActive() || s.spool.HasActiveItems() {
		wake()
	}
	return s, nil
}

func (s *Server) Config() ResolvedConfig {
	return s.cfg
}

func (s *Server) Certs() *CertManager {
	return s.certs
}

func (s *Server) Guard() *IPGuard {
	return s.guard
}

func (s *Server) Close() {
	s.gcOnce.Do(func() {
		close(s.gcStop)
		clear(s.hmacKey[:])
	})
}

// runLazyGC sleeps completely with zero timer ticks while no rooms or spool items exist.
func (s *Server) runLazyGC() {
	for {
		if !s.rooms.HasActive() && !s.spool.HasActiveItems() {
			select {
			case <-s.gcStop:
				return
			case <-s.gcWake:
			}
		}

		ticker := time.NewTicker(15 * time.Second)
		for s.rooms.HasActive() || s.spool.HasActiveItems() {
			select {
			case <-s.gcStop:
				ticker.Stop()
				return
			case <-ticker.C:
				now := s.cfg.NowFunc()
				s.rooms.SweepExpired(now)
				s.spool.SweepExpired(now)
			}
		}
		ticker.Stop()
	}
}

func (s *Server) NewHTTPServer() *http.Server {
	return &http.Server{
		Addr:              s.cfg.ListenAddr,
		Handler:           s,
		TLSConfig:         s.certs.TLSConfig(),
		MaxHeaderBytes:    MaxHeaderBytes,
		ReadHeaderTimeout: ReadHeaderTimeout,
		IdleTimeout:       HTTPIdleTimeout,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, connCtxKey{}, c)
		},
		// Explicitly NO global ReadTimeout/WriteTimeout so large slow-link media streams are never killed.
	}
}

func isCleanV1Path(rawPath string) bool {
	if !strings.HasPrefix(rawPath, "/v1/") {
		return false
	}
	if strings.Contains(rawPath, "..") || strings.Contains(rawPath, `\`) || strings.Contains(rawPath, "//") {
		return false
	}
	trimmed := strings.TrimPrefix(rawPath, "/v1/")
	if trimmed == "" || strings.HasSuffix(trimmed, "/") {
		return false
	}
	for _, seg := range strings.Split(trimmed, "/") {
		if seg == "" || seg == "." {
			return false
		}
	}
	return true
}

func (s *Server) applyCORSHeaders(w http.ResponseWriter, r *http.Request) bool {
	if len(s.cfg.CORSOrigins) == 0 {
		return false
	}
	vals := r.Header.Values("Origin")
	if len(vals) != 1 {
		return false
	}
	allowOrigin, ok := MatchCORSOrigin(s.cfg.CORSOrigins, vals[0])
	if !ok {
		return false
	}
	h := w.Header()
	h.Set("Access-Control-Allow-Origin", allowOrigin)
	h.Set("Vary", "Origin")
	h.Set("Access-Control-Expose-Headers", corsExposeHeaders)
	return true
}

// abortBannedConn cleanly flushes the stealth 404 frame and tears down direct HTTP/2 (or HTTP/1.1) connections
// without disrupting shared trusted reverse-proxy connections.
func (s *Server) abortBannedConn(r *http.Request, rc *http.ResponseController) {
	if rc != nil {
		_ = rc.Flush()
	}
	if remoteIP, ok := ParseRemoteAddrIP(r.RemoteAddr); ok && s.guard.isTrusted(remoteIP) {
		return
	}
	if c, ok := r.Context().Value(connCtxKey{}).(net.Conn); ok && c != nil {
		_ = c.SetReadDeadline(time.Now())
		if r.ProtoMajor >= 2 {
			time.AfterFunc(15*time.Millisecond, func() {
				_ = c.Close()
			})
		}
	}
}

func (s *Server) WrapListener(ln net.Listener) net.Listener {
	return NewLimitListener(ln, s.guard, s.cfg.Preset.MaxConns, s.cfg.Preset.MaxConnsPerIP, s.cfg.NowFunc)
}

func hasSingleOrZeroHeader(h http.Header, keys ...string) bool {
	for _, k := range keys {
		if len(h.Values(k)) > 1 {
			return false
		}
	}
	return true
}

func abortUnreadUploadBody(w http.ResponseWriter, r *http.Request, rc *http.ResponseController) {
	if r.ProtoMajor == 1 {
		w.Header().Set("Connection", "close")
	}
	if rc != nil {
		_ = rc.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	}
}

// ServeHTTP executes the normative 7-step validation pipeline (PROTOCOL.md §3.3).
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	now := s.cfg.NowFunc()
	clientIP := s.guard.ExtractClientIP(r)
	rc := http.NewResponseController(w)

	// Baseline defense-in-depth security headers on every response.
	wh := w.Header()
	wh.Del("Server")
	wh.Set("X-Content-Type-Options", "nosniff")
	wh.Set("Referrer-Policy", "no-referrer")
	wh.Set("Cache-Control", "no-store")

	// Default control-plane write deadline prevents Slow-Read (TCP 0-window) tarpits;
	// streaming/SSE/long-poll handlers manage rolling write deadlines explicitly.
	_ = rc.SetWriteDeadline(time.Now().Add(ControlDeadline))

	// Step 3 (partial): Reject percent-encoded path tricks + route/method syntactic check.
	var rt matchedRoute
	var matched bool
	if r.URL.RawPath == "" {
		rt, matched = matchRoute(r.Method, r.URL.Path)
	}

	// Step 2: Real IP rate limiting & ban enforcement.
	allowed, banned := s.guard.AllowRequest(clientIP, matched && rt.isDataOrEvent, now)
	if banned {
		abortUnreadUploadBody(w, r, rc)
		writeStealth404(w, r)
		s.abortBannedConn(r, rc)
		return
	}

	// Optional opt-in CORS header & preflight handling (zero headers emitted when --cors-origins is unset).
	corsMatched := s.applyCORSHeaders(w, r)
	if corsMatched &&
		r.Method == http.MethodOptions &&
		r.URL.RawPath == "" &&
		isCleanV1Path(r.URL.Path) &&
		strings.TrimSpace(r.Header.Get("Access-Control-Request-Method")) != "" {
		if !allowed {
			wh.Set("Retry-After", "5")
			writeAPIError(w, newAPIError(429, "ERR_RATE_LIMITED", "request rate limit exceeded", true))
			return
		}
		wh.Set("Access-Control-Allow-Methods", corsAllowMethods)
		wh.Set("Access-Control-Allow-Headers", corsAllowHeaders)
		wh.Set("Access-Control-Max-Age", corsMaxAge)
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if !matched {
		bannedNow := s.guard.RecordStrike(clientIP, now)
		abortUnreadUploadBody(w, r, rc)
		writeStealth404(w, r)
		if bannedNow {
			s.abortBannedConn(r, rc)
		}
		return
	}

	// Step 3: Header syntactic pre-check BEFORE reading body.
	if !hasSingleOrZeroHeader(r.Header,
		HeaderSyncTS, HeaderSyncNonce, HeaderSyncSig, HeaderSyncClient,
		HeaderSyncDepositToken, HeaderSyncUploadToken, HeaderSyncRoomToken, HeaderSyncMailboxSig,
	) {
		bannedNow := s.guard.RecordStrike(clientIP, now)
		abortUnreadUploadBody(w, r, rc)
		writeStealth404(w, r)
		if bannedNow {
			s.abortBannedConn(r, rc)
		}
		return
	}

	tsHeader := r.Header.Get(HeaderSyncTS)
	nonceHeader := r.Header.Get(HeaderSyncNonce)
	sigHeader := r.Header.Get(HeaderSyncSig)
	clientHeader := r.Header.Get(HeaderSyncClient)
	depositTok := r.Header.Get(HeaderSyncDepositToken)
	uploadTok := r.Header.Get(HeaderSyncUploadToken)
	roomTok := r.Header.Get(HeaderSyncRoomToken)
	mailboxSig := r.Header.Get(HeaderSyncMailboxSig)

	clientTS, tsErr := strconv.ParseInt(tsHeader, 10, 64)
	if tsErr != nil || clientTS <= 0 ||
		!isLowerHexLen(nonceHeader, 32) ||
		!isLowerHexLen(sigHeader, 64) ||
		!isValidClientHeader(clientHeader) ||
		(depositTok != "" && uploadTok != "") ||
		!isValidAuthHeaderToken(depositTok) ||
		!isValidAuthHeaderToken(uploadTok) ||
		!isValidAuthHeaderToken(roomTok) ||
		!isValidAuthHeaderToken(mailboxSig) {
		bannedNow := s.guard.RecordStrike(clientIP, now)
		abortUnreadUploadBody(w, r, rc)
		writeStealth404(w, r)
		if bannedNow {
			s.abortBannedConn(r, rc)
		}
		return
	}

	// Prepare BODY_BINDING without buffering data-plane chunk bodies!
	var rawBody []byte
	var bodyBinding string

	if rt.isDataUpload {
		// Data-plane chunk PUT: require single explicit non-negative Content-Length (strictly reject chunked TE).
		clVals := r.Header.Values("Content-Length")
		if len(r.TransferEncoding) > 0 || len(clVals) != 1 || clVals[0] == "" || r.ContentLength < 0 {
			bannedNow := s.guard.RecordStrike(clientIP, now)
			abortUnreadUploadBody(w, r, rc)
			writeStealth404(w, r)
			if bannedNow {
				s.abortBannedConn(r, rc)
			}
			return
		}
		bodyBinding = StreamBodyBinding(r.ContentLength)
	} else {
		// Control-plane / GET / SSE: bounded read <= 16 KiB with control deadline.
		_ = rc.SetReadDeadline(time.Now().Add(ControlDeadline))
		if r.Body != nil {
			limited := io.LimitReader(r.Body, MaxControlBodyBytes+1)
			b, err := io.ReadAll(limited)
			if err != nil || len(b) > MaxControlBodyBytes {
				bannedNow := s.guard.RecordStrike(clientIP, now)
				abortUnreadUploadBody(w, r, rc)
				writeStealth404(w, r)
				if bannedNow {
					s.abortBannedConn(r, rc)
				}
				return
			}
			rawBody = b
		}
		_ = rc.SetReadDeadline(time.Time{})
		bodyBinding = ControlBodyBinding(rawBody)
	}

	extraBinding := ExtraTokenBinding(depositTok, uploadTok)
	pathAndQuery := CanonicalPathAndQuery(r)

	// Step 4: Constant-time X-Sync-Sig HMAC verification FIRST (before clock skew & nonce!).
	if !VerifyRelaySig(s.hmacKey, sigHeader, r.Method, pathAndQuery, tsHeader, nonceHeader, bodyBinding, extraBinding) {
		bannedNow := s.guard.RecordStrike(clientIP, now)
		abortUnreadUploadBody(w, r, rc)
		writeStealth404(w, r)
		if bannedNow {
			s.abortBannedConn(r, rc)
		}
		return
	}

	// Authenticated rate limit check (now safe to return JSON 429 + Retry-After).
	if !allowed {
		if rt.isDataUpload {
			abortUnreadUploadBody(w, r, rc)
		}
		w.Header().Set("Retry-After", "5")
		writeAPIError(w, newAPIError(429, "ERR_RATE_LIMITED", "request rate limit exceeded", true))
		return
	}

	// Step 5: Overflow-safe clock skew check (±60s) AFTER HMAC, BEFORE nonce cache (zero side-effects!).
	nowUnix := now.Unix()
	if clientTS < nowUnix-ClockSkewMaxSec || clientTS > nowUnix+ClockSkewMaxSec {
		if rt.isDataUpload {
			abortUnreadUploadBody(w, r, rc)
		}
		writeAPIError(w, &apiError{
			Status:     409,
			Code:       "ERR_CLOCK_SKEW",
			Message:    "client clock skew exceeds 60s window",
			Retryable:  true,
			ServerTS:   nowUnix,
			MaxSkewSec: ClockSkewMaxSec,
		})
		return
	}

	// Step 6: Bounded replay nonce check (only written after valid HMAC + valid clock window!).
	switch s.nonces.CheckAndAddStatus(nonceHeader, now) {
	case NonceAccepted:
	case NonceReplay:
		bannedNow := s.guard.RecordStrike(clientIP, now)
		if rt.isDataUpload {
			abortUnreadUploadBody(w, r, rc)
		}
		writeAPIError(w, newAPIError(401, "ERR_REPLAY_DETECTED", "nonce already consumed", true))
		if bannedNow {
			s.abortBannedConn(r, rc)
		}
		return
	case NonceCacheFull:
		if rt.isDataUpload {
			abortUnreadUploadBody(w, r, rc)
		}
		w.Header().Set("Retry-After", "5")
		writeAPIError(w, newAPIError(429, "ERR_RATE_LIMITED", "replay nonce cache saturated", true))
		return
	}

	// Step 7: Dispatch authenticated endpoint handler.
	authCtx := reqAuthContext{
		now:          now,
		clientIP:     clientIP,
		method:       r.Method,
		pathAndQuery: pathAndQuery,
		tsHeader:     tsHeader,
		nonceHeader:  nonceHeader,
		bodyBinding:  bodyBinding,
		rawBody:      rawBody,
		depositTok:   depositTok,
		uploadTok:    uploadTok,
		roomTok:      roomTok,
		mailboxSig:   mailboxSig,
		rc:           rc,
	}

	s.dispatch(w, r, rt, authCtx)
}

type reqAuthContext struct {
	now          time.Time
	clientIP     netip.Addr
	method       string
	pathAndQuery string
	tsHeader     string
	nonceHeader  string
	bodyBinding  string
	rawBody      []byte
	depositTok   string
	uploadTok    string
	roomTok      string
	mailboxSig   string
	rc           *http.ResponseController
}

func (s *Server) dispatch(w http.ResponseWriter, r *http.Request, rt matchedRoute, ac reqAuthContext) {
	switch rt.kind {
	case routePing:
		s.handlePing(w, ac)
	case routeCaps:
		s.handleCaps(w, ac)
	case routeRoomCreate:
		s.handleRoomCreate(w, ac)
	case routeRoomJoin:
		s.handleRoomJoin(w, rt.param1, ac)
	case routeRoomMessages:
		s.handleRoomMessages(w, rt.param1, ac)
	case routeRoomEvents:
		s.handleRoomEvents(w, r, rt.param1, ac)
	case routeRoomClose:
		s.handleRoomClose(w, rt.param1, ac)
	case routePipePut:
		s.handlePipePut(w, r, rt, ac)
	case routePipeGet:
		s.handlePipeGet(w, r, rt, ac)
	case routeMailboxPut:
		s.handleMailboxPut(w, rt.param1, ac)
	case routeMailboxTokenAdd:
		s.handleMailboxTokenAdd(w, rt.param1, ac)
	case routeMailboxTokenDel:
		s.handleMailboxTokenDel(w, rt.param1, rt.param2, ac)
	case routeMailboxItems:
		s.handleMailboxItems(w, rt.param1, ac)
	case routeMailboxEvents:
		s.handleMailboxEvents(w, r, rt.param1, ac)
	case routeSpoolInit:
		s.handleSpoolInit(w, ac)
	case routeSpoolPutChunk:
		s.handleSpoolPutChunk(w, r, rt, ac)
	case routeSpoolCommit:
		s.handleSpoolCommit(w, rt.param1, ac)
	case routeSpoolAbort:
		s.handleSpoolAbort(w, rt.param1, ac)
	case routeSpoolGetChunk:
		s.handleSpoolGetChunk(w, r, rt, ac)
	case routeSpoolAck:
		s.handleSpoolAck(w, rt.param1, ac)
	default:
		writeStealth404(w, r)
	}
}

func writeStealth404(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Del("Server")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Length", "0")
	if r.ProtoMajor == 1 {
		h.Set("Connection", "close")
	}
	w.WriteHeader(http.StatusNotFound)
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	b, err := json.Marshal(payload)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Length", strconv.Itoa(len(b)))
	w.WriteHeader(status)
	_, _ = w.Write(b)
}

func writeAPIError(w http.ResponseWriter, ae *apiError) {
	if ae.Status == 429 && w.Header().Get("Retry-After") == "" {
		w.Header().Set("Retry-After", "5")
	}
	writeJSON(w, ae.Status, ae)
}

func writeHandlerError(w http.ResponseWriter, err error) {
	var ae *apiError
	if errors.As(err, &ae) {
		writeAPIError(w, ae)
		return
	}
	writeAPIError(w, newAPIError(500, "ERR_INTERNAL", "internal relay error", true))
}
