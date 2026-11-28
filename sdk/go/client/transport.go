package client

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	synccrypto "github.com/yellowdking/synctool/sdk/go/crypto"
	"github.com/yellowdking/synctool/sdk/go/envelope"
)

const (
	clientAgentHeader    = "synctool-go/1.0"
	maxAutoClockSkewSec  = int64(365 * 86400) // ±365 days max auto-calibration skew
	maxControlRespBytes  = int64(4 * 1024 * 1024)
	maxChunkRespBytes    = int64(8 * 1024 * 1024)
	minWatchBackoff      = 250 * time.Millisecond
	maxWatchBackoff      = 5 * time.Second
)

// sseIdleTimeout bounds silent half-open SSE connections (relay sends ": ping" every 20s).
// Package variable so unit tests can verify idle timeout recovery rapidly without sleeping 60s.
var sseIdleTimeout = 60 * time.Second

func buildHTTPClient(profile *envelope.RelayProfile) (*http.Client, error) {
	if profile == nil {
		return nil, envelope.NewError(envelope.ErrCodeURIInvalid, false, 0, "relay profile is nil", nil)
	}
	origin, err := synccrypto.CanonicalRelayOrigin(profile.Endpoint)
	if err != nil {
		return nil, envelope.NewError(envelope.ErrCodeURIInvalid, false, 0, err.Error(), nil)
	}
	parsedOrigin, _ := url.Parse(origin)
	pins, err := envelope.NormalizeSPKIPins(profile.SPKIPins, profile.SPKISHA256, profile.SPKIPin)
	if err != nil {
		return nil, err
	}

	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
	}
	switch profile.TLSMode {
	case "", envelope.TLSModeSystemCA:
		if parsedOrigin.Scheme == "https" && synccrypto.IsIPHost(parsedOrigin.Hostname()) {
			return nil, envelope.NewError(envelope.ErrCodeURIInvalid, false, 0, "bare IP relay requires spki_pin mode and 64-hex SPKI pin", nil)
		}
	case envelope.TLSModeSPKIPin:
		if len(pins) == 0 || len(pins) > envelope.MaxSPKIPins {
			return nil, envelope.NewError(envelope.ErrCodeURIInvalid, false, 0, "spki_pin mode requires 1..8 valid 64-hex SPKI pins", nil)
		}
		expectedPins := append([]string(nil), pins...)
		// Self-signed certs do not chain to system CAs, so Go requires InsecureSkipVerify=true
		// paired with a mandatory VerifyConnection hook that enforces exact leaf SPKI SHA-256 pinning
		// (constant-time across all configured pins) and certificate validity window.
		tlsCfg.InsecureSkipVerify = true
		tlsCfg.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return envelope.NewError(envelope.ErrCodeTLSCertInvalid, false, 0, "relay presented no TLS certificate", nil)
			}
			leaf := cs.PeerCertificates[0]
			now := time.Now()
			if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
				return envelope.NewError(envelope.ErrCodeTLSCertInvalid, false, 0, "relay certificate expired or not yet valid", nil)
			}
			sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
			gotPin := hex.EncodeToString(sum[:])
			matched := 0
			for _, expPin := range expectedPins {
				matched |= subtle.ConstantTimeCompare([]byte(gotPin), []byte(expPin))
			}
			if matched != 1 {
				return envelope.NewError(envelope.ErrCodeTLSPinMismatch, false, 0, "relay leaf SPKI SHA-256 pin mismatch", map[string]any{
					"expected_pin":  expectedPins[0],
					"expected_pins": expectedPins,
					"got_pin":       gotPin,
				})
			}
			return nil
		}
	default:
		return nil, envelope.NewError(envelope.ErrCodeURIInvalid, false, 0, "unsupported tls_mode", nil)
	}

	tr := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   15 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		TLSClientConfig:       tlsCfg,
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: 35 * time.Second,
		IdleConnTimeout:       60 * time.Second,
		MaxIdleConns:          16,
		MaxIdleConnsPerHost:   8,
		DisableCompression:    true,
	}
	return &http.Client{
		Transport: tr,
		// Security hard-block: NEVER follow HTTP 3xx redirects (prevents X-Sync-* credential leak & SPKI pin bypass).
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, nil
}

type reqOptions struct {
	ContentType   string
	RoomToken     string
	DepositToken  string
	UploadToken   string
	MailboxID     string
	MailboxAuthSK ed25519.PrivateKey
	IsStream      bool
	StreamLen     int64
	// StreamFactory produces a fresh io.ReadCloser for stream PUT requests so 409 ERR_CLOCK_SKEW can retry cleanly.
	StreamFactory func() (io.ReadCloser, error)
	AcceptSSE     bool
	MaxRespBytes  int64
	IsBinaryChunk bool
}

type rawHTTPResponse struct {
	StatusCode int
	Header     http.Header
	Body       []byte
}

// authNowUnix returns the HTTP transport timestamp (X-Sync-TS ONLY).
// NEVER use authNowUnix() for Ed25519-signed Manifest.CreatedAt, DeviceCard.IssuedAt, or SealedHeader.CreatedAt!
func (c *Client) authNowUnix() int64 {
	return time.Now().Unix() + c.clockOffsetSec.Load()
}

func (c *Client) calibrateClockFromSkewErr(se *envelope.SyncError) bool {
	if se == nil || se.Details == nil {
		return false
	}
	serverTS, ok := extractSafeUnixDetail(se.Details, "server_ts")
	if !ok {
		serverTS, ok = extractSafeUnixDetail(se.Details, "server_unix")
	}
	if !ok {
		return false
	}
	localNow := time.Now().Unix()
	skew := serverTS - localNow
	if skew < -maxAutoClockSkewSec || skew > maxAutoClockSkewSec {
		return false
	}
	c.clockOffsetSec.Store(skew)
	return true
}

// doControl performs a signed control-plane HTTP request with automatic 1x 409 ERR_CLOCK_SKEW calibration & retry.
func (c *Client) doControl(ctx context.Context, method, pathAndQuery string, reqBody any, opts reqOptions) (*rawHTTPResponse, error) {
	var bodyBytes []byte
	if reqBody != nil {
		b, err := json.Marshal(reqBody)
		if err != nil {
			return nil, envelope.WrapError(envelope.ErrCodeBadRequest, false, 0, "marshal request json", err)
		}
		bodyBytes = b
		if opts.ContentType == "" {
			opts.ContentType = "application/json; charset=utf-8"
		}
	}
	return c.doSignedWithSkewRetry(ctx, method, pathAndQuery, bodyBytes, opts)
}

func (c *Client) doSignedWithSkewRetry(ctx context.Context, method, pathAndQuery string, bodyBytes []byte, opts reqOptions) (*rawHTTPResponse, error) {
	for attempt := 0; attempt < 2; attempt++ {
		resp, err := c.doSignedOnce(ctx, method, pathAndQuery, bodyBytes, opts)
		if err != nil {
			if se, ok := envelope.AsSyncError(err); ok && se.Code == envelope.ErrCodeClockSkew && attempt == 0 {
				if c.calibrateClockFromSkewErr(se) {
					continue
				}
			}
			return nil, err
		}
		return resp, nil
	}
	return nil, envelope.NewError(envelope.ErrCodeClockSkew, false, 409, "clock skew persisted after calibration retry", nil)
}

func (c *Client) doSignedOnce(ctx context.Context, method, pathAndQuery string, bodyBytes []byte, opts reqOptions) (*rawHTTPResponse, error) {
	reqCtx, cancel := c.bindCtx(ctx)
	defer cancel()

	httpResp, err := c.sendSignedHTTP(reqCtx, method, pathAndQuery, bodyBytes, opts)
	if err != nil {
		return nil, err
	}
	defer httpResp.Body.Close()

	maxBytes := opts.MaxRespBytes
	if maxBytes <= 0 {
		maxBytes = maxControlRespBytes
	}
	respBody, err := io.ReadAll(io.LimitReader(httpResp.Body, maxBytes+1))
	if err != nil {
		return nil, c.classifyNetErr(ctx, err)
	}
	if int64(len(respBody)) > maxBytes {
		if opts.IsBinaryChunk {
			return nil, envelope.NewError(envelope.ErrCodeChunkTooLarge, false, httpResp.StatusCode, "chunk response exceeded maximum transport chunk byte limit", nil)
		}
		return nil, envelope.NewError(envelope.ErrCodeBadRequest, false, httpResp.StatusCode, "relay control response exceeded 4 MiB byte limit", nil)
	}
	if httpResp.StatusCode >= 200 && httpResp.StatusCode < 300 {
		return &rawHTTPResponse{
			StatusCode: httpResp.StatusCode,
			Header:     httpResp.Header,
			Body:       respBody,
		}, nil
	}
	if httpResp.StatusCode >= 300 && httpResp.StatusCode < 400 {
		return nil, envelope.NewError(envelope.ErrCodeRelayUnreachable, false, httpResp.StatusCode, "relay HTTP redirect blocked for credential and SPKI pin safety", nil)
	}
	return nil, decodeWireError(httpResp.StatusCode, httpResp.Header, respBody)
}

func (c *Client) openSignedStream(ctx context.Context, method, pathAndQuery string, opts reqOptions) (*http.Response, error) {
	for attempt := 0; attempt < 2; attempt++ {
		httpResp, err := c.sendSignedHTTP(ctx, method, pathAndQuery, nil, opts)
		if err != nil {
			return nil, err
		}
		if httpResp.StatusCode >= 200 && httpResp.StatusCode < 300 {
			return httpResp, nil
		}
		respBody, _ := io.ReadAll(io.LimitReader(httpResp.Body, 64*1024+1))
		_ = httpResp.Body.Close()
		if len(respBody) > 64*1024 {
			respBody = respBody[:64*1024]
		}
		if httpResp.StatusCode >= 300 && httpResp.StatusCode < 400 {
			return nil, envelope.NewError(envelope.ErrCodeRelayUnreachable, false, httpResp.StatusCode, "relay HTTP redirect blocked for credential and SPKI pin safety", nil)
		}
		werr := decodeWireError(httpResp.StatusCode, httpResp.Header, respBody)
		if se, ok := envelope.AsSyncError(werr); ok && se.Code == envelope.ErrCodeClockSkew && attempt == 0 {
			if c.calibrateClockFromSkewErr(se) {
				continue
			}
		}
		return nil, werr
	}
	return nil, envelope.NewError(envelope.ErrCodeClockSkew, false, 409, "clock skew persisted after calibration retry", nil)
}

type idleWatchReadCloser struct {
	rc       io.ReadCloser
	timeout  time.Duration
	timer    *time.Timer
	cancelFn context.CancelFunc
	mu       sync.Mutex
	timedOut bool
	closed   bool
}

func (r *idleWatchReadCloser) Read(p []byte) (int, error) {
	n, err := r.rc.Read(p)
	r.mu.Lock()
	if n > 0 && !r.closed && r.timer != nil {
		r.timer.Reset(r.timeout)
	}
	timedOut := r.timedOut
	r.mu.Unlock()
	if err != nil && timedOut {
		return n, envelope.NewError(envelope.ErrCodeRelayUnreachable, true, 0, "SSE stream idle read timeout exceeded", nil)
	}
	return n, err
}

func (r *idleWatchReadCloser) Close() error {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil
	}
	r.closed = true
	if r.timer != nil {
		r.timer.Stop()
	}
	cancel := r.cancelFn
	r.mu.Unlock()
	err := r.rc.Close()
	if cancel != nil {
		cancel()
	}
	return err
}

func (c *Client) openSSEStreamWithIdleTimeout(ctx context.Context, pathAndQuery string, opts reqOptions) (io.ReadCloser, error) {
	opts.AcceptSSE = true
	boundCtx, cancelBound := c.bindCtx(ctx)
	idleTimeout := sseIdleTimeout
	if idleTimeout <= 0 {
		idleTimeout = 60 * time.Second
	}
	httpResp, err := c.openSignedStream(boundCtx, http.MethodGet, pathAndQuery, opts)
	if err != nil {
		cancelBound()
		if ctx.Err() == nil && c.closeCtx != nil && c.closeCtx.Err() != nil {
			return nil, envelope.NewError(envelope.ErrCodeCancelled, false, 0, "client closed", nil)
		}
		return nil, err
	}
	iw := &idleWatchReadCloser{
		rc:       httpResp.Body,
		timeout:  idleTimeout,
		cancelFn: cancelBound,
	}
	iw.timer = time.AfterFunc(idleTimeout, func() {
		iw.mu.Lock()
		if iw.closed {
			iw.mu.Unlock()
			return
		}
		iw.timedOut = true
		iw.mu.Unlock()
		cancelBound()
	})
	return iw, nil
}

func (c *Client) sendSignedHTTP(ctx context.Context, method, pathAndQuery string, bodyBytes []byte, opts reqOptions) (*http.Response, error) {
	ts := strconv.FormatInt(c.authNowUnix(), 10)
	nonce, err := synccrypto.GenerateNonceHex()
	if err != nil {
		return nil, envelope.WrapError(envelope.ErrCodeCryptoHandshakeFailed, false, 0, "generate nonce", err)
	}

	var bodyBinding string
	var reqReader io.Reader
	var contentLen int64
	if opts.IsStream {
		bodyBinding = synccrypto.BodyBindingStream(opts.StreamLen)
		contentLen = opts.StreamLen
		if opts.StreamFactory != nil {
			rc, err := opts.StreamFactory()
			if err != nil {
				return nil, err
			}
			reqReader = rc
		} else {
			reqReader = bytes.NewReader(bodyBytes)
		}
	} else {
		bodyBinding = synccrypto.BodyBindingControl(bodyBytes)
		contentLen = int64(len(bodyBytes))
		if len(bodyBytes) > 0 {
			reqReader = bytes.NewReader(bodyBytes)
		}
	}

	extraBinding := synccrypto.ExtraTokenBinding(opts.DepositToken, opts.UploadToken)
	sig := synccrypto.SignRelayRequest(c.profile.AccessKey, method, pathAndQuery, ts, nonce, bodyBinding, extraBinding)

	fullURL := c.profile.Endpoint + pathAndQuery
	req, err := http.NewRequestWithContext(ctx, method, fullURL, reqReader)
	if err != nil {
		if rc, ok := reqReader.(io.Closer); ok {
			_ = rc.Close()
		}
		return nil, envelope.WrapError(envelope.ErrCodeURIInvalid, false, 0, "create http request", err)
	}
	req.ContentLength = contentLen
	if opts.ContentType != "" {
		req.Header.Set("Content-Type", opts.ContentType)
	}
	if opts.AcceptSSE {
		req.Header.Set("Accept", "text/event-stream")
	}
	req.Header.Set(synccrypto.HeaderClientAgent, clientAgentHeader)
	req.Header.Set(synccrypto.HeaderRelayTS, ts)
	req.Header.Set(synccrypto.HeaderRelayNonce, nonce)
	req.Header.Set(synccrypto.HeaderRelaySig, sig)
	if opts.RoomToken != "" {
		req.Header.Set(synccrypto.HeaderRoomToken, opts.RoomToken)
	}
	if opts.DepositToken != "" {
		req.Header.Set(synccrypto.HeaderDepositToken, opts.DepositToken)
	}
	if opts.UploadToken != "" {
		req.Header.Set(synccrypto.HeaderUploadToken, opts.UploadToken)
	}
	if opts.MailboxID != "" && len(opts.MailboxAuthSK) == ed25519.PrivateKeySize {
		mbSig := synccrypto.SignMailboxRequest(opts.MailboxAuthSK, method, pathAndQuery, opts.MailboxID, ts, nonce, bodyBinding)
		req.Header.Set(synccrypto.HeaderMailboxSig, mbSig)
	}

	httpResp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, c.classifyNetErr(ctx, err)
	}
	return httpResp, nil
}

func (c *Client) classifyNetErr(ctx context.Context, err error) error {
	if se, ok := envelope.AsSyncError(err); ok {
		return se
	}
	if ctx != nil && ctx.Err() == context.Canceled {
		return envelope.WrapError(envelope.ErrCodeCancelled, false, 0, "operation cancelled", err)
	}
	if c != nil && c.closeCtx != nil && c.closeCtx.Err() != nil {
		return envelope.WrapError(envelope.ErrCodeCancelled, false, 0, "client closed", err)
	}
	if errors.Is(err, context.Canceled) {
		return envelope.WrapError(envelope.ErrCodeCancelled, false, 0, "operation cancelled", err)
	}
	var certErr interface{ Error() string }
	if errors.As(err, &certErr) && (strings.Contains(err.Error(), "x509:") || strings.Contains(err.Error(), "tls:")) {
		return envelope.WrapError(envelope.ErrCodeTLSCertInvalid, false, 0, "tls certificate verification failed", err)
	}
	return envelope.WrapError(envelope.ErrCodeRelayUnreachable, true, 0, "relay unreachable", err)
}

func isFatalWatchOrRoomErr(err error) bool {
	se, ok := envelope.AsSyncError(err)
	if !ok {
		return false
	}
	switch se.Code {
	case envelope.ErrCodeTLSPinMismatch,
		envelope.ErrCodeTLSCertInvalid,
		envelope.ErrCodeAuthFailed,
		envelope.ErrCodeUnauthorizedToken,
		envelope.ErrCodeCancelled,
		envelope.ErrCodeUnsupportedVersion,
		envelope.ErrCodeBadRequest:
		return true
	case envelope.ErrCodeRelayUnreachable:
		// Non-retryable ERR_RELAY_UNREACHABLE (e.g. HTTP 3xx redirect block) is fatal.
		return !se.Retryable
	default:
		return false
	}
}

func sleepWithBackoff(ctx context.Context, attempt int, causeErr error) error {
	shift := attempt
	if shift < 0 {
		shift = 0
	}
	if shift > 5 {
		shift = 5
	}
	delay := minWatchBackoff << shift
	if delay > maxWatchBackoff {
		delay = maxWatchBackoff
	}
	// Deterministic-safe jitter (0..25% derived from monotonic nanosecond low bits) to prevent synchronized thundering herds.
	jitter := time.Duration(time.Now().UnixNano()&0x3f) * (delay / 256)
	delay += jitter
	if delay > maxWatchBackoff {
		delay = maxWatchBackoff
	}
	if se, ok := envelope.AsSyncError(causeErr); ok && se.Details != nil {
		if raStr, ok := se.Details["retry_after"].(string); ok {
			if raSec, err := strconv.Atoi(strings.TrimSpace(raStr)); err == nil && raSec > 0 && raSec <= 30 {
				if raDur := time.Duration(raSec) * time.Second; raDur > delay {
					delay = raDur
				}
			}
		}
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func decodeWireError(statusCode int, hdr http.Header, body []byte) error {
	// Silent stealth empty 404 from relay auth gate -> ERR_AUTH_FAILED.
	if statusCode == http.StatusNotFound && len(bytes.TrimSpace(body)) == 0 {
		return envelope.NewError(envelope.ErrCodeAuthFailed, false, statusCode, "relay rejected authentication (silent 404)", nil)
	}
	var raw map[string]any
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if err := dec.Decode(&raw); err == nil {
		if code, ok := raw["error"].(string); ok && code != "" {
			msg, _ := raw["message"].(string)
			retryable, _ := raw["retryable"].(bool)
			details := make(map[string]any)
			for k, v := range raw {
				if k == "error" || k == "message" || k == "retryable" {
					continue
				}
				details[k] = v
			}
			if ra := hdr.Get("Retry-After"); ra != "" {
				details["retry_after"] = ra
			}
			if len(details) == 0 {
				details = nil
			}
			return envelope.NewError(code, retryable, statusCode, msg, details)
		}
	}
	if statusCode == http.StatusNotFound {
		return envelope.NewError(envelope.ErrCodeAuthFailed, false, statusCode, "relay returned stealth 404", nil)
	}
	return envelope.NewError(envelope.ErrCodeRelayUnreachable, statusCode >= 500, statusCode, "unexpected relay status "+strconv.Itoa(statusCode), nil)
}

func extractSafeUnixDetail(details map[string]any, key string) (int64, bool) {
	if details == nil {
		return 0, false
	}
	v, ok := details[key]
	if !ok {
		return 0, false
	}
	switch n := v.(type) {
	case json.Number:
		if i, err := strconv.ParseInt(n.String(), 10, 64); err == nil && i > 0 && i <= envelope.MaxSafeIntJS {
			return i, true
		}
		if f, err := strconv.ParseFloat(n.String(), 64); err == nil {
			return safeFloat64ToUnix(f)
		}
		return 0, false
	case float64:
		return safeFloat64ToUnix(n)
	case int64:
		if n <= 0 || n > envelope.MaxSafeIntJS {
			return 0, false
		}
		return n, true
	case int:
		v64 := int64(n)
		if v64 <= 0 || v64 > envelope.MaxSafeIntJS {
			return 0, false
		}
		return v64, true
	case string:
		if i, err := strconv.ParseInt(strings.TrimSpace(n), 10, 64); err == nil && i > 0 && i <= envelope.MaxSafeIntJS {
			return i, true
		}
		return 0, false
	default:
		return 0, false
	}
}

func safeFloat64ToUnix(f float64) (int64, bool) {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return 0, false
	}
	if f < 1 || f > float64(envelope.MaxSafeIntJS) {
		return 0, false
	}
	return int64(f), true
}

type sseEvent struct {
	ID    string
	Event string
	Data  string
}

func parseSSEStream(r io.Reader, handle func(sseEvent) error) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 16*1024), 256*1024)
	var cur sseEvent
	var dataLines []string
	flush := func() error {
		if cur.Event == "" && len(dataLines) == 0 && cur.ID == "" {
			return nil
		}
		cur.Data = strings.Join(dataLines, "\n")
		ev := cur
		cur = sseEvent{}
		dataLines = dataLines[:0]
		return handle(ev)
	}
	for scanner.Scan() {
		line := strings.TrimSuffix(scanner.Text(), "\r")
		if line == "" {
			if err := flush(); err != nil {
				return err
			}
			continue
		}
		if strings.HasPrefix(line, ":") {
			// Comment / ": ping" keepalive.
			continue
		}
		field, val, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		val = strings.TrimPrefix(val, " ")
		switch field {
		case "event":
			cur.Event = val
		case "data":
			dataLines = append(dataLines, val)
		case "id":
			cur.ID = val
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return flush()
}
