package relay

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func newTestClock(t time.Time) *testClock { return &testClock{now: t} }
func (c *testClock) Now() time.Time       { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

type testClient struct {
	t         *testing.T
	baseURL   string
	accessKey string
	hmacKey   [32]byte
	http      *http.Client
	clock     *testClock
}

func newTestServerAndClient(t *testing.T, modify func(*Config)) (*Server, *httptest.Server, *testClient, *testClock) {
	t.Helper()
	clk := newTestClock(time.Unix(1764246000, 0).UTC())
	cfg := Config{
		ListenAddr:           "127.0.0.1:0",
		PublicHost:           "127.0.0.1",
		Profile:              ProfileStandard,
		Spool:                SpoolMemory,
		TLSMode:              TLSOff,
		DataDir:              t.TempDir(),
		AccessKey:            "test_access_key_must_be_at_least_32_characters_long_0001",
		NowFunc:              clk.Now,
		DisableMemTune:       true,
		RendezvousTimeout:    2 * time.Second,
		StallTimeout:         5 * time.Second,
		SSEKeepaliveInterval: 100 * time.Millisecond,
		SSEMaxDuration:       800 * time.Millisecond,
	}
	if modify != nil {
		modify(&cfg)
	}
	rc, err := cfg.Resolve()
	if err != nil {
		t.Fatalf("cfg.Resolve: %v", err)
	}
	srv, err := NewServer(rc, nil)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(srv.Close)
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)

	cli := &testClient{
		t:         t,
		baseURL:   ts.URL,
		accessKey: rc.AccessKey,
		hmacKey:   DeriveRelayHMACKey(rc.AccessKey),
		http:      ts.Client(),
		clock:     clk,
	}
	return srv, ts, cli, clk
}

func randNonceHex(t *testing.T) string {
	t.Helper()
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

func signMailboxEd25519(sk ed25519.PrivateKey, method, pathAndQuery, mailboxID, ts, nonce, bodyBinding string) string {
	msg := "synctool-v1/mailbox-auth\n" + method + "\n" + pathAndQuery + "\n" + mailboxID + "\n" + ts + "\n" + nonce + "\n" + bodyBinding
	sig := ed25519.Sign(sk, []byte(msg))
	return base64.RawURLEncoding.EncodeToString(sig)
}

type reqOpts struct {
	body         []byte
	isStream     bool
	roomToken    string
	depositToken string
	uploadToken  string
	mailboxID    string
	mailboxSK    ed25519.PrivateKey
	tsOverride   *int64
	nonce        string
	sigOverride  string
	extraHeaders map[string]string
}

func (c *testClient) do(method, pathAndQuery string, opts reqOpts) (*http.Response, []byte) {
	c.t.Helper()
	var bodyReader io.Reader
	if opts.body != nil {
		bodyReader = bytes.NewReader(opts.body)
	}
	req, err := http.NewRequest(method, c.baseURL+pathAndQuery, bodyReader)
	if err != nil {
		c.t.Fatal(err)
	}
	if opts.isStream {
		req.Header.Set("Content-Type", "application/octet-stream")
		req.ContentLength = int64(len(opts.body))
	} else if opts.body != nil {
		req.Header.Set("Content-Type", "application/json; charset=utf-8")
	}

	ts := c.clock.Now().Unix()
	if opts.tsOverride != nil {
		ts = *opts.tsOverride
	}
	tsStr := strconv.FormatInt(ts, 10)
	nonce := opts.nonce
	if nonce == "" {
		nonce = randNonceHex(c.t)
	}

	var bodyBinding string
	if opts.isStream {
		bodyBinding = StreamBodyBinding(int64(len(opts.body)))
	} else {
		bodyBinding = ControlBodyBinding(opts.body)
	}
	extraBinding := ExtraTokenBinding(opts.depositToken, opts.uploadToken)
	sig := ComputeRelaySig(c.hmacKey, method, pathAndQuery, tsStr, nonce, bodyBinding, extraBinding)
	if opts.sigOverride != "" {
		sig = opts.sigOverride
	}

	req.Header.Set(HeaderSyncClient, "synctool-test/1.0")
	req.Header.Set(HeaderSyncTS, tsStr)
	req.Header.Set(HeaderSyncNonce, nonce)
	req.Header.Set(HeaderSyncSig, sig)
	if opts.roomToken != "" {
		req.Header.Set(HeaderSyncRoomToken, opts.roomToken)
	}
	if opts.depositToken != "" {
		req.Header.Set(HeaderSyncDepositToken, opts.depositToken)
	}
	if opts.uploadToken != "" {
		req.Header.Set(HeaderSyncUploadToken, opts.uploadToken)
	}
	if opts.mailboxSK != nil {
		req.Header.Set(HeaderSyncMailboxSig, signMailboxEd25519(opts.mailboxSK, method, pathAndQuery, opts.mailboxID, tsStr, nonce, bodyBinding))
	}
	for k, v := range opts.extraHeaders {
		req.Header.Set(k, v)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		c.t.Fatalf("http %s %s failed: %v", method, pathAndQuery, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		c.t.Fatalf("read body %s %s: %v", method, pathAndQuery, err)
	}
	return resp, data
}

func makeValidSealedHeaderB64() string {
	b := make([]byte, SealedHeaderLen)
	copy(b[:4], "ST01")
	b[4] = 0x02
	_, _ = rand.Read(b[8:])
	return base64.RawURLEncoding.EncodeToString(b)
}

func TestProfileAutoAndConfigGuards(t *testing.T) {
	if got := ResolveAutoProfileName(192 << 20); got != ProfileNano {
		t.Fatalf("192MiB (<224MiB) should resolve to nano, got %s", got)
	}
	if got := ResolveAutoProfileName(224 << 20); got != ProfileStandard {
		t.Fatalf("224MiB should resolve to standard, got %s", got)
	}
	if got := ResolveAutoProfileName(256 << 20); got != ProfileStandard {
		t.Fatalf("256MiB container limit should resolve to standard (NOT nano), got %s", got)
	}
	if got := ResolveAutoProfileName(1024 << 20); got != ProfileStandard {
		t.Fatalf("1GiB should resolve to standard, got %s", got)
	}
	if got := ResolveAutoProfileName(1536 << 20); got != ProfileMedia {
		t.Fatalf("1536MiB should resolve to media, got %s", got)
	}
	if got := ResolveAutoProfileName(4096 << 20); got != ProfileMedia {
		t.Fatalf("4GiB should resolve to media, got %s", got)
	}

	// Exact N * 65,552 B alignment, MaxConnsPerIP, MaxMailboxes, MaxNonceEntries & safe GOMEMLIMIT.
	nano, _ := PresetFor(ProfileNano)
	std, _ := PresetFor(ProfileStandard)
	med, _ := PresetFor(ProfileMedia)
	if nano.MaxTransportChunkBytes != 262208 || std.MaxTransportChunkBytes != 1048832 || med.MaxTransportChunkBytes != 2097664 {
		t.Fatalf("unexpected chunk sizes: nano=%d std=%d med=%d", nano.MaxTransportChunkBytes, std.MaxTransportChunkBytes, med.MaxTransportChunkBytes)
	}
	if nano.MaxConnsPerIP != 16 {
		t.Fatalf("expected nano MaxConnsPerIP=16, got %d", nano.MaxConnsPerIP)
	}
	if nano.MaxMailboxes != 256 || std.MaxMailboxes != 4096 || med.MaxMailboxes != 32768 {
		t.Fatalf("unexpected MaxMailboxes: nano=%d std=%d med=%d", nano.MaxMailboxes, std.MaxMailboxes, med.MaxMailboxes)
	}
	if nano.MaxNonceEntries != 16384 || std.MaxNonceEntries != 65536 || med.MaxNonceEntries != 262144 {
		t.Fatalf("unexpected MaxNonceEntries: nano=%d std=%d med=%d", nano.MaxNonceEntries, std.MaxNonceEntries, med.MaxNonceEntries)
	}
	safe256 := ComputeSafeGoMemLimit(256<<20, std)
	if safe256 < 144<<20 || safe256 > 156<<20 {
		t.Fatalf("expected 256MiB safe GOMEMLIMIT in [144MiB, 156MiB], got %d bytes", safe256)
	}

	// Hard guard: --tls=off on non-loopback without TRUSTED_PROXIES must fail.
	badCfg := Config{
		ListenAddr: ":54843",
		Profile:    ProfileStandard,
		Spool:      SpoolMemory,
		TLSMode:    TLSOff,
		DataDir:    t.TempDir(),
	}
	if _, err := badCfg.Resolve(); err == nil {
		t.Fatal("expected --tls=off on :54843 without trusted proxies to fail")
	}

	// With TRUSTED_PROXIES, --tls=off on :54843 succeeds.
	proxies, err := ParseTrustedProxies("127.0.0.1/32,172.16.0.0/12")
	if err != nil {
		t.Fatal(err)
	}
	badCfg.TrustedProxies = proxies
	rc, err := badCfg.Resolve()
	if err != nil {
		t.Fatalf("expected --tls=off with trusted proxies to succeed: %v", err)
	}
	if len(rc.AccessKey) < 32 || !rc.KeyCreated {
		t.Fatalf("expected auto-generated >=32 char access key, got len=%d created=%v", len(rc.AccessKey), rc.KeyCreated)
	}

	// Explicit --spool=off overrides standard profile default (disk).
	offCfg := Config{
		ListenAddr: "127.0.0.1:54843",
		Profile:    ProfileStandard,
		Spool:      SpoolOff,
		TLSMode:    TLSOff,
		DataDir:    t.TempDir(),
	}
	rcOff, err := offCfg.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	if rcOff.SpoolMode != SpoolOff {
		t.Fatalf("expected explicit --spool=off, got %s", rcOff.SpoolMode)
	}
}

func TestSelfSignedCert730DaysAndTLS13Pinning(t *testing.T) {
	dir := t.TempDir()
	now := time.Unix(1764246000, 0).UTC()
	b, err := GenerateSelfSignedCert("203.0.113.10,sync.example.com", now, filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem"))
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert: %v", err)
	}
	if !isLowerHexLen(b.SPKISHA256Hex, 64) {
		t.Fatalf("expected 64-hex SPKI pin, got %q", b.SPKISHA256Hex)
	}
	validity := b.Leaf.NotAfter.Sub(b.Leaf.NotBefore)
	if validity != 730*24*time.Hour {
		t.Fatalf("expected exactly 730 days validity, got %v", validity)
	}
	if len(b.Leaf.ExtKeyUsage) != 1 || b.Leaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Fatalf("expected ExtKeyUsageServerAuth, got %v", b.Leaf.ExtKeyUsage)
	}
	foundIP, foundDNS := false, false
	for _, ip := range b.Leaf.IPAddresses {
		if ip.String() == "203.0.113.10" {
			foundIP = true
		}
	}
	for _, d := range b.Leaf.DNSNames {
		if d == "sync.example.com" {
			foundDNS = true
		}
	}
	if !foundIP || !foundDNS {
		t.Fatalf("missing SANs: ip=%v dns=%v", b.Leaf.IPAddresses, b.Leaf.DNSNames)
	}

	uri := BuildRelayURI("https://203.0.113.10:54843", b.SPKISHA256Hex, "my_secret_key_01234567890123456789")
	wantPrefix := "synctool://relay?v=1&u=https%3A%2F%2F203.0.113.10%3A54843&pin=" + b.SPKISHA256Hex + "#k="
	if !strings.HasPrefix(uri, wantPrefix) {
		t.Fatalf("unexpected relay URI:\n got: %s\nwant: %s...", uri, wantPrefix)
	}

	// Start real TLS 1.3 server with self-signed cert & verify SPKI pin + cert_rotate_recommended.
	clk := newTestClock(now)
	cfg := Config{
		ListenAddr:     "127.0.0.1:0",
		PublicHost:     "127.0.0.1",
		Profile:        ProfileNano,
		Spool:          SpoolMemory,
		TLSMode:        TLSSelfSigned,
		DataDir:        dir,
		AccessKey:      "tls_test_access_key_32_bytes_minimum_value_xyz",
		NowFunc:        clk.Now,
		DisableMemTune: true,
	}
	rc, err := cfg.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	srv, err := NewServer(rc, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	rawLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsLn := tls.NewListener(srv.WrapListener(rawLn), srv.Certs().TLSConfig())
	httpSrv := srv.NewHTTPServer()
	go func() { _ = httpSrv.Serve(tlsLn) }()
	defer httpSrv.Close()

	expectedPin := srv.Certs().Current().SPKISHA256Hex
	tlsClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion:         tls.VersionTLS13,
				InsecureSkipVerify: true,
				VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
					leaf, err := x509.ParseCertificate(rawCerts[0])
					if err != nil {
						return err
					}
					if SPKISHA256Hex(leaf) != expectedPin {
						return errors.New("spki mismatch")
					}
					return nil
				},
			},
		},
	}

	cli := &testClient{
		t:         t,
		baseURL:   "https://" + rawLn.Addr().String(),
		accessKey: rc.AccessKey,
		hmacKey:   DeriveRelayHMACKey(rc.AccessKey),
		http:      tlsClient,
		clock:     clk,
	}

	resp, body := cli.do(http.MethodGet, "/v1/ping", reqOpts{})
	if resp.StatusCode != 200 {
		t.Fatalf("TLS ping expected 200, got %d: %s", resp.StatusCode, body)
	}
	var ping map[string]any
	_ = json.Unmarshal(body, &ping)
	if ping["cert_rotate_recommended"].(bool) {
		t.Fatal("fresh 730d cert should not recommend rotation yet")
	}

	// Advance clock to 20 days before expiry -> cert_rotate_recommended MUST flip true.
	clk.Advance(710 * 24 * time.Hour)
	resp, body = cli.do(http.MethodGet, "/v1/ping", reqOpts{})
	if resp.StatusCode != 200 {
		t.Fatalf("TLS ping2 expected 200, got %d", resp.StatusCode)
	}
	_ = json.Unmarshal(body, &ping)
	if !ping["cert_rotate_recommended"].(bool) {
		t.Fatal("expected cert_rotate_recommended=true when <30d remain")
	}
}

func TestAuth7StepPipelineStealth404ClockSkewReplayAndTrustedProxies(t *testing.T) {
	proxies, _ := ParseTrustedProxies("127.0.0.1/32")
	srv, _, cli, clk := newTestServerAndClient(t, func(c *Config) {
		c.TrustedProxies = proxies
	})

	// 1. Unknown route -> silent empty 404.
	resp, body := cli.do(http.MethodGet, "/v1/does-not-exist", reqOpts{extraHeaders: map[string]string{"X-Forwarded-For": "198.51.100.1"}})
	if resp.StatusCode != 404 || len(body) != 0 {
		t.Fatalf("expected silent empty 404 for unknown route, got %d body=%q", resp.StatusCode, body)
	}

	// 2. Wrong method -> silent empty 404 (not 405).
	resp, body = cli.do(http.MethodPost, "/v1/ping", reqOpts{extraHeaders: map[string]string{"X-Forwarded-For": "198.51.100.1"}})
	if resp.StatusCode != 404 || len(body) != 0 {
		t.Fatalf("expected silent empty 404 for wrong method, got %d body=%q", resp.StatusCode, body)
	}

	// 3. Invalid HMAC with skewed timestamp -> STILL silent empty 404 (must NOT leak server_ts!).
	skewedTS := clk.Now().Unix() - 300
	resp, body = cli.do(http.MethodGet, "/v1/ping", reqOpts{
		tsOverride:   &skewedTS,
		sigOverride:  strings.Repeat("a", 64),
		extraHeaders: map[string]string{"X-Forwarded-For": "198.51.100.2"},
	})
	if resp.StatusCode != 404 || len(body) != 0 {
		t.Fatalf("invalid HMAC must return silent 404 even if skewed, got %d body=%q", resp.StatusCode, body)
	}
	if srv.nonces.Len() != 0 {
		t.Fatalf("failed HMAC must not insert into nonce cache, len=%d", srv.nonces.Len())
	}

	// 4. Valid HMAC with >60s skew -> 409 ERR_CLOCK_SKEW with server_ts and ZERO nonce cache write!
	skewNonce := randNonceHex(t)
	skewTS61 := clk.Now().Unix() - 61
	resp, body = cli.do(http.MethodGet, "/v1/ping", reqOpts{
		tsOverride:   &skewTS61,
		nonce:        skewNonce,
		extraHeaders: map[string]string{"X-Forwarded-For": "198.51.100.3"},
	})
	if resp.StatusCode != 409 {
		t.Fatalf("expected 409 ERR_CLOCK_SKEW, got %d body=%s", resp.StatusCode, body)
	}
	var errResp apiError
	_ = json.Unmarshal(body, &errResp)
	if errResp.Code != "ERR_CLOCK_SKEW" || errResp.ServerTS != clk.Now().Unix() || errResp.MaxSkewSec != 60 {
		t.Fatalf("unexpected clock skew payload: %+v", errResp)
	}
	if srv.nonces.Len() != 0 {
		t.Fatalf("409 ERR_CLOCK_SKEW must NOT write nonce cache, len=%d", srv.nonces.Len())
	}

	// 5. Valid HMAC with exact ±60s boundary -> 200 OK; replaying same nonce -> 401 ERR_REPLAY_DETECTED.
	okTS60 := clk.Now().Unix() + 60
	resp, _ = cli.do(http.MethodGet, "/v1/ping", reqOpts{
		tsOverride:   &okTS60,
		nonce:        skewNonce,
		extraHeaders: map[string]string{"X-Forwarded-For": "198.51.100.3"},
	})
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200 at exact +60s boundary, got %d", resp.StatusCode)
	}
	resp, body = cli.do(http.MethodGet, "/v1/ping", reqOpts{
		tsOverride:   &okTS60,
		nonce:        skewNonce,
		extraHeaders: map[string]string{"X-Forwarded-For": "198.51.100.3"},
	})
	if resp.StatusCode != 401 || !strings.Contains(string(body), "ERR_REPLAY_DETECTED") {
		t.Fatalf("expected 401 ERR_REPLAY_DETECTED, got %d %s", resp.StatusCode, body)
	}

	// 6. Strike ban via trusted proxy IP extraction (IPv6 /64 aggregation!).
	for i := 0; i < StrikeBanThreshold; i++ {
		cli.do(http.MethodGet, "/v1/ping", reqOpts{
			sigOverride:  strings.Repeat("0", 64),
			extraHeaders: map[string]string{"X-Forwarded-For": "2001:db8:abcd:1234::1, 127.0.0.1"},
		})
	}
	// Sibling IP in same /64 must now be banned even with valid HMAC!
	resp, body = cli.do(http.MethodGet, "/v1/ping", reqOpts{
		extraHeaders: map[string]string{"X-Forwarded-For": "2001:db8:abcd:1234::9999"},
	})
	if resp.StatusCode != 404 || len(body) != 0 {
		t.Fatalf("expected banned /64 sibling IP to receive stealth 404, got %d", resp.StatusCode)
	}
	// Unrelated IP still passes fine (proves TRUSTED_PROXIES did NOT ban proxy 127.0.0.1!).
	resp, _ = cli.do(http.MethodGet, "/v1/ping", reqOpts{
		extraHeaders: map[string]string{"X-Forwarded-For": "198.51.100.77"},
	})
	if resp.StatusCode != 200 {
		t.Fatalf("expected unrelated client IP behind trusted proxy to pass, got %d", resp.StatusCode)
	}
}

func TestNonceCacheBoundedEvictionAndIPExtraction(t *testing.T) {
	if NonceCacheTTL != 125*time.Second {
		t.Fatalf("expected NonceCacheTTL=125s, got %v", NonceCacheTTL)
	}
	nc := NewNonceCache(4, NonceCacheTTL)
	now := time.Unix(1764246000, 0)
	for i := 0; i < 4; i++ {
		if got := nc.CheckAndAddStatus(fmt.Sprintf("%032x", i), now); got != NonceAccepted {
			t.Fatalf("expected NonceAccepted on %d, got %v", i, got)
		}
	}
	if nc.Len() != 4 {
		t.Fatalf("expected bounded nonce cache len 4, got %d", nc.Len())
	}
	// At t+121s (<125s TTL), boundary replay MUST still be caught!
	if got := nc.CheckAndAddStatus(fmt.Sprintf("%032x", 0), now.Add(121*time.Second)); got != NonceReplay {
		t.Fatalf("expected boundary replay at +121s to return NonceReplay, got %v", got)
	}
	// When full of live nonces, fresh 5th nonce MUST return NonceCacheFull (never evict live nonce #0!).
	if got := nc.CheckAndAddStatus(fmt.Sprintf("%032x", 4), now.Add(10*time.Second)); got != NonceCacheFull {
		t.Fatalf("expected NonceCacheFull when all 4 entries are live, got %v", got)
	}
	if got := nc.CheckAndAddStatus(fmt.Sprintf("%032x", 0), now.Add(10*time.Second)); got != NonceReplay {
		t.Fatalf("live nonce #0 must NOT be evicted when full, got %v", got)
	}
	// Once TTL (125s) expires, old entries are evicted and new nonces succeed.
	if got := nc.CheckAndAddStatus(fmt.Sprintf("%032x", 4), now.Add(126*time.Second)); got != NonceAccepted {
		t.Fatalf("expected NonceAccepted after 125s TTL expiry, got %v", got)
	}

	// Verify Server returns 429 ERR_RATE_LIMITED (Retry-After: 5) on NonceCacheFull.
	srv, _, cli, _ := newTestServerAndClient(t, nil)
	srv.nonces = NewNonceCache(2, NonceCacheTTL)
	n0 := randNonceHex(t)
	if r, _ := cli.do(http.MethodGet, "/v1/ping", reqOpts{nonce: n0}); r.StatusCode != 200 {
		t.Fatalf("expected 1st ping 200, got %d", r.StatusCode)
	}
	if r, _ := cli.do(http.MethodGet, "/v1/ping", reqOpts{}); r.StatusCode != 200 {
		t.Fatalf("expected 2nd ping 200, got %d", r.StatusCode)
	}
	rFull, bFull := cli.do(http.MethodGet, "/v1/ping", reqOpts{})
	if rFull.StatusCode != 429 || rFull.Header.Get("Retry-After") != "5" || !strings.Contains(string(bFull), "ERR_RATE_LIMITED") {
		t.Fatalf("expected 429 ERR_RATE_LIMITED + Retry-After: 5 on live full NonceCache, got %d hdr=%v body=%s", rFull.StatusCode, rFull.Header, bFull)
	}
	rRep, bRep := cli.do(http.MethodGet, "/v1/ping", reqOpts{nonce: n0})
	if rRep.StatusCode != 401 || !strings.Contains(string(bRep), "ERR_REPLAY_DETECTED") {
		t.Fatalf("expected replay of live n0 to still return 401 ERR_REPLAY_DETECTED when full, got %d %s", rRep.StatusCode, bRep)
	}

	// Untrusted proxy must NOT honor X-Forwarded-For, and trusted proxy without XFF must NOT honor CF-Connecting-IP.
	std, _ := PresetFor(ProfileStandard)
	g := NewIPGuard(std, nil)
	req := httptest.NewRequest(http.MethodGet, "/v1/ping", nil)
	req.RemoteAddr = "203.0.113.5:12345"
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	if got := g.ExtractClientIP(req); got != netip.MustParseAddr("203.0.113.5") {
		t.Fatalf("untrusted XFF should be ignored, got %s", got)
	}
	proxies, _ := ParseTrustedProxies("127.0.0.1/32")
	gTrusted := NewIPGuard(std, proxies)
	reqNoXFF := httptest.NewRequest(http.MethodGet, "/v1/ping", nil)
	reqNoXFF.RemoteAddr = "127.0.0.1:54321"
	reqNoXFF.Header.Set("CF-Connecting-IP", "198.51.100.99")
	reqNoXFF.Header.Set("X-Real-IP", "198.51.100.98")
	if got := gTrusted.ExtractClientIP(reqNoXFF); got != netip.MustParseAddr("127.0.0.1") {
		t.Fatalf("XFF-only default must ignore spoofed CF-Connecting-IP/X-Real-IP when XFF is absent, got %s", got)
	}
}

func TestRateLimitAndPipeRendezvousTimeout(t *testing.T) {
	_, _, cli, clk := newTestServerAndClient(t, func(c *Config) {
		c.Profile = ProfileNano
		c.Spool = SpoolOff
		c.RendezvousTimeout = 120 * time.Millisecond
	})

	// Exhaust nano control burst (40), 41st returns 429 ERR_RATE_LIMITED with Retry-After.
	nanoPreset, _ := PresetFor(ProfileNano)
	for i := 0; i < nanoPreset.ControlBurst; i++ {
		r, _ := cli.do(http.MethodGet, "/v1/ping", reqOpts{})
		if r.StatusCode != 200 {
			t.Fatalf("ping #%d expected 200, got %d", i+1, r.StatusCode)
		}
	}
	r, body := cli.do(http.MethodGet, "/v1/ping", reqOpts{})
	if r.StatusCode != 429 || r.Header.Get("Retry-After") == "" || !strings.Contains(string(body), "ERR_RATE_LIMITED") {
		t.Fatalf("expected 429 ERR_RATE_LIMITED + Retry-After, got %d hdr=%v body=%s", r.StatusCode, r.Header, body)
	}

	// Advance clock to refill bucket and verify Mode A 504 ERR_PIPE_PEER_TIMEOUT.
	clk.Advance(30 * time.Second)
	r, body = cli.do(http.MethodPost, "/v1/rooms", reqOpts{body: []byte(`{"room_id":"Z2X4C6V8"}`)})
	if r.StatusCode != 201 {
		t.Fatalf("create room failed: %d %s", r.StatusCode, body)
	}
	var created RoomCreateResult
	_ = json.Unmarshal(body, &created)
	r, _ = cli.do(http.MethodPost, "/v1/rooms/Z2X4C6V8/join", reqOpts{body: []byte(`{}`)})
	if r.StatusCode != 200 {
		t.Fatalf("join failed: %d", r.StatusCode)
	}

	r, body = cli.do(http.MethodPut, fmt.Sprintf("/v1/pipe/%s/parts/0/chunks/0", created.PipeID), reqOpts{
		body:      []byte("hello-timeout"),
		isStream:  true,
		roomToken: created.SenderToken,
	})
	if r.StatusCode != 504 || !strings.Contains(string(body), "ERR_PIPE_PEER_TIMEOUT") {
		t.Fatalf("expected 504 ERR_PIPE_PEER_TIMEOUT, got %d %s", r.StatusCode, body)
	}
}

func TestModeADirectPipeSenderBeforeJoin(t *testing.T) {
	_, _, cli, _ := newTestServerAndClient(t, func(c *Config) {
		c.Profile = ProfileStandard
		c.Spool = SpoolOff
		c.RendezvousTimeout = 2 * time.Second
	})

	// Flow 2 Mode A Direct: Sender creates room (RoomWaiting) and IMMEDIATELY starts PUT before Receiver calls /join.
	directM1 := base64.RawURLEncoding.EncodeToString([]byte(`{"proto_v":1,"mode":0,"purpose":"direct"}`))
	r, body := cli.do(http.MethodPost, "/v1/rooms", reqOpts{
		body: []byte(fmt.Sprintf(`{"room_id":"D4F6G8H2","ttl_sec":300,"initial_msg_b64":%q}`, directM1)),
	})
	if r.StatusCode != 201 {
		t.Fatalf("create direct room failed: %d %s", r.StatusCode, body)
	}
	var created RoomCreateResult
	_ = json.Unmarshal(body, &created)

	payload := bytes.Repeat([]byte("DIRECT01"), 512)
	putErrCh := make(chan error, 1)
	go func() {
		pr, pb := cli.do(http.MethodPut, fmt.Sprintf("/v1/pipe/%s/parts/0/chunks/0", created.PipeID), reqOpts{
			body:      payload,
			isStream:  true,
			roomToken: created.SenderToken,
		})
		if pr.StatusCode != 200 {
			putErrCh <- fmt.Errorf("sender PUT while RoomWaiting failed: %d %s", pr.StatusCode, pb)
			return
		}
		putErrCh <- nil
	}()

	// Wait so Sender PUT is definitely parked while room is still RoomWaiting.
	time.Sleep(60 * time.Millisecond)

	// Receiver joins and pulls chunk 0.
	r, body = cli.do(http.MethodPost, "/v1/rooms/D4F6G8H2/join", reqOpts{body: []byte(`{}`)})
	if r.StatusCode != 200 {
		t.Fatalf("join direct room failed: %d %s", r.StatusCode, body)
	}
	var joined RoomJoinResult
	_ = json.Unmarshal(body, &joined)

	r, got := cli.do(http.MethodGet, fmt.Sprintf("/v1/pipe/%s/parts/0/chunks/0", created.PipeID), reqOpts{
		roomToken: joined.ReceiverToken,
	})
	if r.StatusCode != 200 || !bytes.Equal(got, payload) {
		t.Fatalf("receiver direct GET mismatch: status=%d len=%d", r.StatusCode, len(got))
	}
	if err := <-putErrCh; err != nil {
		t.Fatal(err)
	}
}
