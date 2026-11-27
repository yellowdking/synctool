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
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	synccrypto "github.com/yellowdking/synctool/sdk/go/crypto"
	"github.com/yellowdking/synctool/sdk/go/envelope"
)

const clientAgentHeader = "synctool-go/1.0"

func buildHTTPClient(profile *envelope.RelayProfile) (*http.Client, error) {
	if profile == nil {
		return nil, envelope.NewError(envelope.ErrCodeURIInvalid, false, 0, "relay profile is nil", nil)
	}
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
	}
	switch profile.TLSMode {
	case "", envelope.TLSModeSystemCA:
		// Standard system root CA verification.
	case envelope.TLSModeSPKIPin:
		expectedPin := strings.ToLower(strings.TrimSpace(profile.SPKISHA256))
		if len(expectedPin) != 64 {
			return nil, envelope.NewError(envelope.ErrCodeURIInvalid, false, 0, "spki_pin mode requires 64-hex pin", nil)
		}
		// Self-signed certs do not chain to system CAs, so Go requires InsecureSkipVerify=true
		// paired with a mandatory VerifyConnection hook that enforces exact leaf SPKI SHA-256 pinning
		// and certificate validity window. Unpinned bypass is strictly forbidden.
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
			if subtle.ConstantTimeCompare([]byte(gotPin), []byte(expectedPin)) != 1 {
				return envelope.NewError(envelope.ErrCodeTLSPinMismatch, false, 0, "relay leaf SPKI SHA-256 pin mismatch", map[string]any{
					"expected_pin": expectedPin,
					"got_pin":      gotPin,
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
}

type rawHTTPResponse struct {
	StatusCode int
	Header     http.Header
	Body       []byte
}

func (c *Client) effectiveUnixNow() int64 {
	return time.Now().Unix() + c.clockOffsetSec.Load()
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
				if serverTS, ok := extractInt64Detail(se.Details, "server_ts"); ok {
					c.clockOffsetSec.Store(serverTS - time.Now().Unix())
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
	httpResp, err := c.sendSignedHTTP(ctx, method, pathAndQuery, bodyBytes, opts)
	if err != nil {
		return nil, err
	}
	defer httpResp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(httpResp.Body, 4*1024*1024))
	if err != nil {
		return nil, c.classifyNetErr(ctx, err)
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
		respBody, _ := io.ReadAll(io.LimitReader(httpResp.Body, 64*1024))
		_ = httpResp.Body.Close()
		if httpResp.StatusCode >= 300 && httpResp.StatusCode < 400 {
			return nil, envelope.NewError(envelope.ErrCodeRelayUnreachable, false, httpResp.StatusCode, "relay HTTP redirect blocked for credential and SPKI pin safety", nil)
		}
		werr := decodeWireError(httpResp.StatusCode, httpResp.Header, respBody)
		if se, ok := envelope.AsSyncError(werr); ok && se.Code == envelope.ErrCodeClockSkew && attempt == 0 {
			if serverTS, ok := extractInt64Detail(se.Details, "server_ts"); ok {
				c.clockOffsetSec.Store(serverTS - time.Now().Unix())
				continue
			}
		}
		return nil, werr
	}
	return nil, envelope.NewError(envelope.ErrCodeClockSkew, false, 409, "clock skew persisted after calibration retry", nil)
}

func (c *Client) sendSignedHTTP(ctx context.Context, method, pathAndQuery string, bodyBytes []byte, opts reqOptions) (*http.Response, error) {
	ts := strconv.FormatInt(c.effectiveUnixNow(), 10)
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
	if errors.Is(err, context.Canceled) || ctx.Err() == context.Canceled {
		return envelope.WrapError(envelope.ErrCodeCancelled, false, 0, "operation cancelled", err)
	}
	var certErr interface{ Error() string }
	if errors.As(err, &certErr) && (strings.Contains(err.Error(), "x509:") || strings.Contains(err.Error(), "tls:")) {
		return envelope.WrapError(envelope.ErrCodeTLSCertInvalid, false, 0, "tls certificate verification failed", err)
	}
	return envelope.WrapError(envelope.ErrCodeRelayUnreachable, true, 0, "relay unreachable", err)
}

func decodeWireError(statusCode int, hdr http.Header, body []byte) error {
	// Silent stealth empty 404 from relay auth gate -> ERR_AUTH_FAILED.
	if statusCode == http.StatusNotFound && len(bytes.TrimSpace(body)) == 0 {
		return envelope.NewError(envelope.ErrCodeAuthFailed, false, statusCode, "relay rejected authentication (silent 404)", nil)
	}
	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err == nil {
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

func extractInt64Detail(details map[string]any, key string) (int64, bool) {
	if details == nil {
		return 0, false
	}
	v, ok := details[key]
	if !ok {
		return 0, false
	}
	switch n := v.(type) {
	case float64:
		return int64(n), true
	case int64:
		return n, true
	case int:
		return int64(n), true
	default:
		return 0, false
	}
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
