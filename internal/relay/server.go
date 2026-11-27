package relay

import (
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
	trimmed := strings.TrimPrefix(rawPath, "/v1/")
	if trimmed == "" || strings.HasSuffix(trimmed, "/") {
		return matchedRoute{}, false
	}
	segs := strings.Split(trimmed, "/")

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
		nonces:  NewNonceCache(NonceCacheMaxEntries, NonceCacheTTL),
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
	s.pipes = NewPipeHub(cfg.Preset.CopyBufBytes, cfg.RendezvousTimeout, cfg.StallTimeout, s.gate, s.bw)
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
		ReadHeaderTimeout: ReadHeaderTimeout,
		IdleTimeout:       HTTPIdleTimeout,
		// Explicitly NO global ReadTimeout/WriteTimeout so large slow-link media streams are never killed.
	}
}

func (s *Server) WrapListener(ln net.Listener) net.Listener {
	return NewLimitListener(ln, s.guard, s.cfg.Preset.MaxConns, s.cfg.Preset.MaxConnsPerIP, s.cfg.NowFunc)
}

// ServeHTTP executes the normative 7-step validation pipeline (PROTOCOL.md §3.3).
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	now := s.cfg.NowFunc()
	clientIP := s.guard.ExtractClientIP(r)

	// Step 3 (partial): Route/method syntactic check + rate limit bucket classification.
	rt, matched := matchRoute(r.Method, r.URL.Path)

	// Step 2: Real IP rate limiting & ban enforcement.
	allowed, banned := s.guard.AllowRequest(clientIP, matched && rt.isDataOrEvent, now)
	if banned {
		writeStealth404(w, r)
		return
	}
	if !matched {
		s.guard.RecordStrike(clientIP, now)
		writeStealth404(w, r)
		return
	}

	// Step 3: Header syntactic pre-check BEFORE reading body.
	tsHeader := r.Header.Get(HeaderSyncTS)
	nonceHeader := r.Header.Get(HeaderSyncNonce)
	sigHeader := r.Header.Get(HeaderSyncSig)
	clientHeader := r.Header.Get(HeaderSyncClient)

	clientTS, tsErr := strconv.ParseInt(tsHeader, 10, 64)
	if tsErr != nil || !isLowerHexLen(nonceHeader, 32) || !isLowerHexLen(sigHeader, 64) || !isValidClientHeader(clientHeader) {
		s.guard.RecordStrike(clientIP, now)
		writeStealth404(w, r)
		return
	}

	// Prepare BODY_BINDING without buffering data-plane chunk bodies!
	var rawBody []byte
	var bodyBinding string
	rc := http.NewResponseController(w)

	if rt.isDataUpload {
		// Data-plane chunk PUT: require explicit non-negative Content-Length (reject chunked TE).
		clStr := r.Header.Get("Content-Length")
		if clStr == "" || r.ContentLength < 0 {
			s.guard.RecordStrike(clientIP, now)
			writeStealth404(w, r)
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
				s.guard.RecordStrike(clientIP, now)
				writeStealth404(w, r)
				return
			}
			rawBody = b
		}
		_ = rc.SetReadDeadline(time.Time{})
		bodyBinding = ControlBodyBinding(rawBody)
	}

	depositTok := r.Header.Get(HeaderSyncDepositToken)
	uploadTok := r.Header.Get(HeaderSyncUploadToken)
	extraBinding := ExtraTokenBinding(depositTok, uploadTok)
	pathAndQuery := CanonicalPathAndQuery(r)

	// Step 4: Constant-time X-Sync-Sig HMAC verification FIRST (before clock skew & nonce!).
	if !VerifyRelaySig(s.hmacKey, sigHeader, r.Method, pathAndQuery, tsHeader, nonceHeader, bodyBinding, extraBinding) {
		s.guard.RecordStrike(clientIP, now)
		writeStealth404(w, r)
		return
	}

	// Authenticated rate limit check (now safe to return JSON 429 + Retry-After).
	if !allowed {
		w.Header().Set("Retry-After", "5")
		writeAPIError(w, newAPIError(429, "ERR_RATE_LIMITED", "request rate limit exceeded", true))
		return
	}

	// Step 5: Clock skew check (±60s) AFTER HMAC, BEFORE nonce cache (zero side-effects!).
	skew := clientTS - now.Unix()
	if skew < 0 {
		skew = -skew
	}
	if skew > ClockSkewMaxSec {
		writeAPIError(w, &apiError{
			Status:     409,
			Code:       "ERR_CLOCK_SKEW",
			Message:    "client clock skew exceeds 60s window",
			Retryable:  true,
			ServerTS:   now.Unix(),
			MaxSkewSec: ClockSkewMaxSec,
		})
		return
	}

	// Step 6: Bounded replay nonce check (only written after valid HMAC + valid clock window!).
	if !s.nonces.CheckAndAdd(nonceHeader, now) {
		s.guard.RecordStrike(clientIP, now)
		writeAPIError(w, newAPIError(401, "ERR_REPLAY_DETECTED", "nonce already consumed", true))
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
		roomTok:      r.Header.Get(HeaderSyncRoomToken),
		mailboxSig:   r.Header.Get(HeaderSyncMailboxSig),
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
	w.Header().Del("Server")
	w.Header().Set("Content-Length", "0")
	if r.ProtoMajor == 1 {
		w.Header().Set("Connection", "close")
	}
	w.WriteHeader(http.StatusNotFound)
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	b, err := json.Marshal(payload)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Length", strconv.Itoa(len(b)))
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
