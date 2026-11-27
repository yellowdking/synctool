package relay

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestIPUnmapZoneMultiXFFAndBanEvictionProtection(t *testing.T) {
	// 1. IPv4-in-IPv6 Unmap & IPv6 %zone stripping.
	v4Key := NormalizeIPKey(netip.MustParseAddr("203.0.113.9"))
	v4In6Key := NormalizeIPKey(netip.MustParseAddr("::ffff:203.0.113.9"))
	if v4Key != v4In6Key || !v4Key.IsValid() {
		t.Fatalf("expected IPv4 and ::ffff:IPv4 to map to identical /32 bucket: %v vs %v", v4Key, v4In6Key)
	}

	zoned := netip.MustParseAddr("2001:db8:abcd:1234::5%eth0")
	zKey := NormalizeIPKey(zoned)
	if !zKey.IsValid() || zKey.String() != "2001:db8:abcd:1234::/64" {
		t.Fatalf("expected zoned IPv6 to normalize to valid /64 prefix, got %v (valid=%v)", zKey, zKey.IsValid())
	}

	if !IsLoopbackListenAddr("[::ffff:127.0.0.1]:54843") {
		t.Fatal("expected [::ffff:127.0.0.1]:54843 to be recognized as loopback")
	}

	// 2. ParseTrustedProxies with IPv4-in-IPv6 CIDR & ExtractClientIP hardening.
	proxies, err := ParseTrustedProxies("::ffff:172.16.0.0/108, 10.0.0.0/8, 127.0.0.1/32")
	if err != nil {
		t.Fatalf("ParseTrustedProxies failed: %v", err)
	}
	nano, _ := PresetFor(ProfileNano)
	g := NewIPGuard(nano, proxies)

	// 2a. Multiple X-Forwarded-For headers: attacker injects first header, proxy appends second.
	reqMulti := httptest.NewRequest(http.MethodGet, "/v1/ping", nil)
	reqMulti.RemoteAddr = "172.16.5.4:44321"
	reqMulti.Header.Add("X-Forwarded-For", "1.1.1.1")
	reqMulti.Header.Add("X-Forwarded-For", "::ffff:198.51.100.42, 172.16.5.4")
	if got := g.ExtractClientIP(reqMulti); got != netip.MustParseAddr("198.51.100.42") {
		t.Fatalf("expected real client IP 198.51.100.42 from second XFF header, got %s", got)
	}

	// 2b. Malformed right-hand XFF token must NOT skip left to attacker-controlled IP.
	reqBad := httptest.NewRequest(http.MethodGet, "/v1/ping", nil)
	reqBad.RemoteAddr = "127.0.0.1:50000"
	reqBad.Header.Set("X-Forwarded-For", "1.1.1.1, not-an-ip")
	reqBad.Header.Set("CF-Connecting-IP", "8.8.8.8")
	if got := g.ExtractClientIP(reqBad); got != netip.MustParseAddr("127.0.0.1") {
		t.Fatalf("malformed XFF should stop and return remoteIP 127.0.0.1, got %s", got)
	}

	// 2c. All-trusted XFF chain must return leftmost trusted IP and NEVER fall through to spoofed CF-Connecting-IP.
	reqInternal := httptest.NewRequest(http.MethodGet, "/v1/ping", nil)
	reqInternal.RemoteAddr = "172.16.0.2:40000"
	reqInternal.Header.Set("X-Forwarded-For", "10.1.2.3, 172.16.0.2")
	reqInternal.Header.Set("CF-Connecting-IP", "8.8.8.8")
	reqInternal.Header.Set("X-Real-IP", "9.9.9.9")
	if got := g.ExtractClientIP(reqInternal); got != netip.MustParseAddr("10.1.2.3") {
		t.Fatalf("all-trusted XFF must return 10.1.2.3 without reading spoofed CF-Connecting-IP, got %s", got)
	}

	// 3. Ban eviction protection: flooding MaxTrackedIPs with unbanned IPs must NOT evict active bans!
	now := time.Unix(1764246000, 0)
	attackerV4 := netip.MustParseAddr("203.0.113.99")
	attacker4in6 := netip.MustParseAddr("::ffff:203.0.113.99")
	for i := 0; i < StrikeBanThreshold; i++ {
		g.RecordStrike(attackerV4, now)
	}
	if !g.IsBanned(attackerV4, now) || !g.IsBanned(attacker4in6, now) {
		t.Fatal("expected both IPv4 and ::ffff:IPv4 to be banned")
	}

	for i := 0; i < nano.MaxTrackedIPs+512; i++ {
		ip := netip.AddrFrom4([4]byte{192, 0, byte(i >> 8), byte(i & 0xff)})
		g.AllowRequest(ip, false, now.Add(time.Second))
	}
	if !g.IsBanned(attackerV4, now.Add(2*time.Second)) {
		t.Fatal("active banned IP was prematurely evicted under tracking table pressure!")
	}
}

func TestHeaderSecurityGuardsOverflowAndPathTraversal(t *testing.T) {
	_, _, cli, clk := newTestServerAndClient(t, func(c *Config) {
		c.ServerVersion = "0.2.0"
	})

	// 1. Baseline security headers on 200 JSON & 404 stealth.
	resp, _ := cli.do(http.MethodGet, "/v1/ping", reqOpts{})
	if resp.StatusCode != 200 || resp.Header.Get("X-Content-Type-Options") != "nosniff" || resp.Header.Get("Referrer-Policy") != "no-referrer" || resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("missing security headers on 200 JSON: %v", resp.Header)
	}

	// 2. Dual token headers (X-Sync-Deposit-Token + X-Sync-Upload-Token) MUST be rejected with silent 404!
	resp, body := cli.do(http.MethodPost, "/v1/spool/init", reqOpts{
		body:         []byte(`{}`),
		depositToken: "tok_deposit_1234567890",
		extraHeaders: map[string]string{HeaderSyncUploadToken: "tok_upload_unverified"},
	})
	if resp.StatusCode != 404 || len(body) != 0 || resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("expected silent 404 for dual token headers, got %d body=%q", resp.StatusCode, body)
	}

	// 3. Two's complement MinInt64 clock-skew overflow attempt: clientTS = MinInt64 + serverNow!
	overflowTS := int64(math.MinInt64) + clk.Now().Unix()
	resp, body = cli.do(http.MethodGet, "/v1/ping", reqOpts{tsOverride: &overflowTS})
	if resp.StatusCode != 404 || len(body) != 0 {
		t.Fatalf("expected non-positive / overflow timestamp to return silent 404, got %d %q", resp.StatusCode, body)
	}
	zeroTS := int64(0)
	resp, _ = cli.do(http.MethodGet, "/v1/ping", reqOpts{tsOverride: &zeroTS})
	if resp.StatusCode != 404 {
		t.Fatalf("expected zero timestamp to return silent 404, got %d", resp.StatusCode)
	}

	// 4. Duplicate X-Sync-Nonce header values -> silent 404.
	dupReq, _ := http.NewRequest(http.MethodGet, cli.baseURL+"/v1/ping", nil)
	tsStr := strconv.FormatInt(clk.Now().Unix(), 10)
	n1 := randNonceHex(t)
	dupReq.Header.Set(HeaderSyncTS, tsStr)
	dupReq.Header.Add(HeaderSyncNonce, n1)
	dupReq.Header.Add(HeaderSyncNonce, randNonceHex(t))
	dupReq.Header.Set(HeaderSyncSig, ComputeRelaySig(cli.hmacKey, http.MethodGet, "/v1/ping", tsStr, n1, EmptyBodySHA256Binding, ""))
	dupResp, err := cli.http.Do(dupReq)
	if err != nil {
		t.Fatal(err)
	}
	_ = dupResp.Body.Close()
	if dupResp.StatusCode != 404 {
		t.Fatalf("expected silent 404 for duplicate auth header, got %d", dupResp.StatusCode)
	}

	// 5. Encoded slash / path traversal attempts & strict parameter whitelisting.
	for _, p := range []string{
		"/v1/rooms/K7M9P2XQ%2Fjoin",
		"/v1/mailboxes/..%2Fping",
		"/v1//ping",
	} {
		r, b := cli.do(http.MethodGet, p, reqOpts{})
		if r.StatusCode != 404 || len(b) != 0 {
			t.Fatalf("path %q expected silent 404, got %d", p, r.StatusCode)
		}
	}

	// Invalid mailbox_id on GET /v1/mailboxes/{bad}/items -> 400 ERR_BAD_REQUEST.
	_, sk, _ := ed25519.GenerateKey(rand.Reader)
	resp, body = cli.do(http.MethodGet, "/v1/mailboxes/NOT_HEX_32/items", reqOpts{
		mailboxID: "NOT_HEX_32",
		mailboxSK: sk,
	})
	if resp.StatusCode != 400 || !strings.Contains(string(body), "ERR_BAD_REQUEST") {
		t.Fatalf("expected 400 ERR_BAD_REQUEST for malformed mailbox_id, got %d %s", resp.StatusCode, body)
	}

	// Chunked Transfer-Encoding on data-plane PUT -> silent 404.
	putPath := "/v1/pipe/0123456789abcdef0123456789abcdef/parts/0/chunks/0"
	chunkedReq, _ := http.NewRequest(http.MethodPut, cli.baseURL+putPath, io.NopCloser(strings.NewReader("abcd")))
	chunkedReq.ContentLength = -1 // forces Transfer-Encoding: chunked
	n2 := randNonceHex(t)
	chunkedReq.Header.Set(HeaderSyncTS, tsStr)
	chunkedReq.Header.Set(HeaderSyncNonce, n2)
	chunkedReq.Header.Set(HeaderSyncSig, ComputeRelaySig(cli.hmacKey, http.MethodPut, putPath, tsStr, n2, StreamBodyBinding(4), ""))
	cResp, err := cli.http.Do(chunkedReq)
	if err != nil {
		t.Fatal(err)
	}
	_ = cResp.Body.Close()
	if cResp.StatusCode != 404 {
		t.Fatalf("expected chunked data-plane PUT to fail with silent 404, got %d", cResp.StatusCode)
	}
}

func TestSpoolChunkCountDoSBoundsAndZombieDiskRecovery(t *testing.T) {
	dataDir := t.TempDir()
	accessKey := "zombie_recovery_test_access_key_32_characters_minimum"

	_, _, cli, clk := newTestServerAndClient(t, func(c *Config) {
		c.Spool = SpoolDisk
		c.DataDir = dataDir
		c.AccessKey = accessKey
	})

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	mbID := DeriveMailboxID(pub)
	tok, _ := GenerateAccessKey()

	// Register mailbox with deposit_tokens directly in PUT.
	regBytes, _ := json.Marshal(map[string]any{
		"auth_pk_b64": base64.RawURLEncoding.EncodeToString(pub),
		"deposit_tokens": []map[string]string{
			{"token_id": "dt_sender01", "token_hash_hex": HashDepositToken(tok)},
		},
	})
	resp, body := cli.do(http.MethodPut, "/v1/mailboxes/"+mbID, reqOpts{body: regBytes, mailboxID: mbID, mailboxSK: priv})
	if resp.StatusCode != 200 {
		t.Fatalf("register mailbox failed: %d %s", resp.StatusCode, body)
	}

	// 1. CPU DoS attempt: 100 bytes declared across 2,147,483,647 chunks -> MUST fail 400 immediately!
	dosInit, _ := json.Marshal(SpoolInitRequest{
		MailboxID:          mbID,
		DeclaredTotalBytes: 100,
		SealedHeader:       makeValidSealedHeaderB64(),
		Parts:              []SpoolPartSpec{{PartID: 0, TotalBytes: 100, ChunkCount: math.MaxInt32}},
	})
	resp, body = cli.do(http.MethodPost, "/v1/spool/init", reqOpts{body: dosInit, depositToken: tok})
	if resp.StatusCode != 400 {
		t.Fatalf("expected 400 for billion-chunk CPU DoS init, got %d %s", resp.StatusCode, body)
	}

	// 2. int64 addition overflow across parts -> MUST fail 400!
	ovfInit, _ := json.Marshal(SpoolInitRequest{
		MailboxID:          mbID,
		DeclaredTotalBytes: 100,
		SealedHeader:       makeValidSealedHeaderB64(),
		Parts: []SpoolPartSpec{
			{PartID: 0, TotalBytes: math.MaxInt64 - 10, ChunkCount: MaxChunksPerPart},
			{PartID: 1, TotalBytes: 111, ChunkCount: 1},
		},
	})
	resp, body = cli.do(http.MethodPost, "/v1/spool/init", reqOpts{body: ovfInit, depositToken: tok})
	if resp.StatusCode != 400 {
		t.Fatalf("expected 400 for int64 overflow part sum, got %d %s", resp.StatusCode, body)
	}

	// 3. Create two real committed items on disk, then corrupt one (delete p0_c0.enc simulating interrupted AckBurn)
	//    and plant a corrupted mailbox dir + stray .tmp files.
	createCommitted := func() string {
		payload := bytes.Repeat([]byte("G"), 4096)
		ib, _ := json.Marshal(SpoolInitRequest{
			MailboxID:          mbID,
			DeclaredTotalBytes: int64(len(payload)),
			SealedHeader:       makeValidSealedHeaderB64(),
			Parts:              []SpoolPartSpec{{PartID: 0, TotalBytes: int64(len(payload)), ChunkCount: 1}},
		})
		r, b := cli.do(http.MethodPost, "/v1/spool/init", reqOpts{body: ib, depositToken: tok})
		if r.StatusCode != 201 {
			t.Fatalf("init failed: %d %s", r.StatusCode, b)
		}
		var ir SpoolInitResponse
		_ = json.Unmarshal(b, &ir)
		cli.do(http.MethodPut, "/v1/spool/"+ir.ItemID+"/parts/0/chunks/0", reqOpts{body: payload, isStream: true, uploadToken: ir.UploadToken})
		cr, cb := cli.do(http.MethodPost, "/v1/spool/"+ir.ItemID+"/commit", reqOpts{body: []byte(`{}`), uploadToken: ir.UploadToken})
		if cr.StatusCode != 200 {
			t.Fatalf("commit failed: %d %s", cr.StatusCode, cb)
		}
		return ir.ItemID
	}

	goodItem := createCommitted()
	zombieItem := createCommitted()

	zombieDir := filepath.Join(dataDir, "spool", mbID[:2], mbID, zombieItem)
	_ = os.Remove(filepath.Join(zombieDir, "p0_c0.enc")) // half-deleted zombie!

	corruptMBDir := filepath.Join(dataDir, "spool", "aa", strings.Repeat("a", 32))
	_ = os.MkdirAll(corruptMBDir, 0o700)
	_ = os.WriteFile(filepath.Join(corruptMBDir, "mailbox.json"), []byte("{truncated-json"), 0o600)

	strayTmp := filepath.Join(dataDir, "spool", mbID[:2], mbID, "mailbox.json.dead.tmp")
	_ = os.WriteFile(strayTmp, []byte("orphan"), 0o600)

	// Restart server on same dataDir.
	_, _, cli2, _ := newTestServerAndClient(t, func(c *Config) {
		c.Spool = SpoolDisk
		c.DataDir = dataDir
		c.AccessKey = accessKey
		c.NowFunc = clk.Now
	})
	cli2.clock = clk

	resp, body = cli2.do(http.MethodGet, "/v1/mailboxes/"+mbID+"/items", reqOpts{mailboxID: mbID, mailboxSK: priv})
	if resp.StatusCode != 200 {
		t.Fatalf("list after recovery failed: %d %s", resp.StatusCode, body)
	}
	var list MailboxListResponse
	_ = json.Unmarshal(body, &list)
	if len(list.Items) != 1 || list.Items[0].ItemID != goodItem || list.UsedBytes != 4096 {
		t.Fatalf("expected only intact goodItem after recovery, got %+v", list)
	}
	if _, err := os.Stat(zombieDir); !os.IsNotExist(err) {
		t.Fatalf("expected half-deleted zombie item dir %s to be purged on startup", zombieDir)
	}
	if _, err := os.Stat(corruptMBDir); !os.IsNotExist(err) {
		t.Fatalf("expected corrupted mailbox dir %s to be purged on startup", corruptMBDir)
	}
	if _, err := os.Stat(strayTmp); !os.IsNotExist(err) {
		t.Fatalf("expected stray .tmp file %s to be purged on startup", strayTmp)
	}
}

func TestConcurrentDiskServeChunkAndAckBurnAndPipeBurnCleanStream(t *testing.T) {
	dataDir := t.TempDir()
	_, _, cli, _ := newTestServerAndClient(t, func(c *Config) {
		c.Spool = SpoolDisk
		c.DataDir = dataDir
		c.MaxBandwidthMbps = 4.0 // paces 128 KiB stream over ~250ms so ACK overlaps open file handle!
	})

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	mbID := DeriveMailboxID(pub)
	tok, _ := GenerateAccessKey()
	regBytes, _ := json.Marshal(map[string]any{
		"auth_pk_b64":    base64.RawURLEncoding.EncodeToString(pub),
		"deposit_tokens": []DepositTokenEntry{{TokenID: "dt_peer_win", TokenHashHex: HashDepositToken(tok)}},
	})
	cli.do(http.MethodPut, "/v1/mailboxes/"+mbID, reqOpts{body: regBytes, mailboxID: mbID, mailboxSK: priv})

	blob := bytes.Repeat([]byte("W"), 131072) // 128 KiB
	ib, _ := json.Marshal(SpoolInitRequest{
		MailboxID:          mbID,
		DeclaredTotalBytes: int64(len(blob)),
		SealedHeader:       makeValidSealedHeaderB64(),
		Parts:              []SpoolPartSpec{{PartID: 0, TotalBytes: int64(len(blob)), ChunkCount: 1}},
	})
	_, b := cli.do(http.MethodPost, "/v1/spool/init", reqOpts{body: ib, depositToken: tok})
	var ir SpoolInitResponse
	_ = json.Unmarshal(b, &ir)
	cli.do(http.MethodPut, "/v1/spool/"+ir.ItemID+"/parts/0/chunks/0", reqOpts{body: blob, isStream: true, uploadToken: ir.UploadToken})
	cli.do(http.MethodPost, "/v1/spool/"+ir.ItemID+"/commit", reqOpts{body: []byte(`{}`), uploadToken: ir.UploadToken})

	// Open GET stream and pause after reading first 1 KiB so file handle on Windows stays open during ACK!
	getPath := "/v1/spool/" + ir.ItemID + "/parts/0/chunks/0"
	req, _ := http.NewRequest(http.MethodGet, cli.baseURL+getPath, nil)
	tsStr := strconv.FormatInt(cli.clock.Now().Unix(), 10)
	nonce := randNonceHex(t)
	req.Header.Set(HeaderSyncTS, tsStr)
	req.Header.Set(HeaderSyncNonce, nonce)
	req.Header.Set(HeaderSyncSig, ComputeRelaySig(cli.hmacKey, http.MethodGet, getPath, tsStr, nonce, EmptyBodySHA256Binding, ""))
	req.Header.Set(HeaderSyncMailboxSig, signMailboxEd25519(priv, http.MethodGet, getPath, mbID, tsStr, nonce, EmptyBodySHA256Binding))

	getResp, err := cli.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if getResp.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("expected nosniff on binary chunk GET, got %v", getResp.Header)
	}
	firstBuf := make([]byte, 1024)
	if _, err := io.ReadFull(getResp.Body, firstBuf); err != nil {
		t.Fatalf("read first 1KiB failed: %v", err)
	}

	// Trigger signed ACK burn while ServeChunk still holds the open file handle!
	ackResp, ackBody := cli.do(http.MethodPost, "/v1/spool/"+ir.ItemID+"/ack", reqOpts{
		body:      []byte(`{}`),
		mailboxID: mbID,
		mailboxSK: priv,
	})
	if ackResp.StatusCode != 200 || !strings.Contains(string(ackBody), `"burned":true`) {
		t.Fatalf("concurrent ACK failed: %d %s", ackResp.StatusCode, ackBody)
	}

	// Drain & close GET stream, then verify item directory is 100% physically removed (even on Windows!).
	_, _ = io.Copy(io.Discard, getResp.Body)
	_ = getResp.Body.Close()

	itemDir := filepath.Join(dataDir, "spool", mbID[:2], mbID, ir.ItemID)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(itemDir); os.IsNotExist(err) {
			break
		}
		time.Sleep(15 * time.Millisecond)
	}
	if _, err := os.Stat(itemDir); !os.IsNotExist(err) {
		t.Fatalf("expected item directory %s to be physically purged after concurrent ServeChunk+ACK", itemDir)
	}

	// Also verify Mode A mid-stream burn never appends JSON into receiver's binary stream!
	_, crBody := cli.do(http.MethodPost, "/v1/rooms", reqOpts{body: []byte(`{"room_id":"B2N4M6P8"}`)})
	var rm RoomCreateResult
	_ = json.Unmarshal(crBody, &rm)
	_, jnBody := cli.do(http.MethodPost, "/v1/rooms/B2N4M6P8/join", reqOpts{body: []byte(`{}`)})
	var jn RoomJoinResult
	_ = json.Unmarshal(jnBody, &jn)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		// Slow sender reader that stalls after 2 KiB while room gets burned.
		pr, pw := io.Pipe()
		go func() {
			_, _ = pw.Write(bytes.Repeat([]byte("C"), 2048))
			time.Sleep(80 * time.Millisecond)
			cli.do(http.MethodPost, "/v1/rooms/B2N4M6P8/close", reqOpts{
				roomToken: rm.SenderToken,
				body:      []byte(`{"reason":"verify_failed"}`),
			})
			_ = pw.Close()
		}()
		putURL := fmt.Sprintf("/v1/pipe/%s/parts/0/chunks/0", rm.PipeID)
		pReq, _ := http.NewRequest(http.MethodPut, cli.baseURL+putURL, pr)
		pReq.ContentLength = 65536
		pNonce := randNonceHex(t)
		pReq.Header.Set("Content-Type", "application/octet-stream")
		pReq.Header.Set(HeaderSyncTS, tsStr)
		pReq.Header.Set(HeaderSyncNonce, pNonce)
		pReq.Header.Set(HeaderSyncSig, ComputeRelaySig(cli.hmacKey, http.MethodPut, putURL, tsStr, pNonce, StreamBodyBinding(65536), ""))
		pReq.Header.Set(HeaderSyncRoomToken, rm.SenderToken)
		if pResp, perr := cli.http.Do(pReq); perr == nil {
			_ = pResp.Body.Close()
		}
	}()

	getPipeURL := fmt.Sprintf("/v1/pipe/%s/parts/0/chunks/0", rm.PipeID)
	gReq, _ := http.NewRequest(http.MethodGet, cli.baseURL+getPipeURL, nil)
	gNonce := randNonceHex(t)
	gReq.Header.Set(HeaderSyncTS, tsStr)
	gReq.Header.Set(HeaderSyncNonce, gNonce)
	gReq.Header.Set(HeaderSyncSig, ComputeRelaySig(cli.hmacKey, http.MethodGet, getPipeURL, tsStr, gNonce, EmptyBodySHA256Binding, ""))
	gReq.Header.Set(HeaderSyncRoomToken, jn.ReceiverToken)
	gResp, gErr := cli.http.Do(gReq)
	if gErr == nil {
		gotBytes, _ := io.ReadAll(gResp.Body)
		_ = gResp.Body.Close()
		if bytes.Contains(gotBytes, []byte("ERR_ROOM_BURNED")) {
			t.Fatalf("binary pipe GET stream was corrupted with JSON error payload: %q", gotBytes)
		}
	}
	wg.Wait()
}

func TestCapsNegotiationForwardCompatSelfHealMergeAndCommitEventTS(t *testing.T) {
	_, _, cli, clk := newTestServerAndClient(t, func(c *Config) {
		c.Profile = ProfileNano
		c.Spool = SpoolMemory
		c.ServerVersion = "0.2.0"
	})

	// 1. Check /v1/ping and /v1/caps expose min_proto_v, max_proto_v, server_version, and features.
	_, pingRaw := cli.do(http.MethodGet, "/v1/ping", reqOpts{})
	var ping map[string]any
	_ = json.Unmarshal(pingRaw, &ping)
	if int(ping["min_proto_v"].(float64)) != 1 || int(ping["max_proto_v"].(float64)) != 1 || ping["server_version"].(string) != "0.2.0" {
		t.Fatalf("unexpected /v1/ping version metadata: %v", ping)
	}

	_, capsRaw := cli.do(http.MethodGet, "/v1/caps", reqOpts{})
	var caps map[string]any
	_ = json.Unmarshal(capsRaw, &caps)
	if int(caps["min_proto_v"].(float64)) != 1 || int(caps["max_proto_v"].(float64)) != 1 || caps["server_version"].(string) != "0.2.0" {
		t.Fatalf("unexpected /v1/caps version metadata: %v", caps)
	}
	featsRaw, ok := caps["features"].([]any)
	if !ok || len(featsRaw) < 5 {
		t.Fatalf("expected features array in /v1/caps, got %v", caps["features"])
	}

	// 2. Unregistered mailbox returns 404 ERR_NOT_FOUND with scope="mailbox".
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	mbID := DeriveMailboxID(pub)
	resp, body := cli.do(http.MethodGet, "/v1/mailboxes/"+mbID+"/items", reqOpts{mailboxID: mbID, mailboxSK: priv})
	if resp.StatusCode != 404 || !strings.Contains(string(body), `"error":"ERR_NOT_FOUND"`) || !strings.Contains(string(body), `"scope":"mailbox"`) {
		t.Fatalf("expected 404 ERR_NOT_FOUND with scope=mailbox, got %d %s", resp.StatusCode, body)
	}

	// 3. Self-heal PUT /v1/mailboxes/{id} with deposit_tokens + unknown v1.1 extension fields!
	tok1, _ := GenerateAccessKey()
	tok2, _ := GenerateAccessKey()
	tok3, _ := GenerateAccessKey()
	put1, _ := json.Marshal(map[string]any{
		"auth_pk_b64": base64.RawURLEncoding.EncodeToString(pub),
		"deposit_tokens": []DepositTokenEntry{
			{TokenID: "dt_peer_01", TokenHashHex: HashDepositToken(tok1)},
			{TokenID: "dt_peer_02", TokenHashHex: HashDepositToken(tok2)},
		},
		"future_v1_1_hint": map[string]any{"auto_heal": true},
	})
	resp, body = cli.do(http.MethodPut, "/v1/mailboxes/"+mbID, reqOpts{body: put1, mailboxID: mbID, mailboxSK: priv})
	if resp.StatusCode != 200 || !strings.Contains(string(body), `"deposit_token_count":2`) {
		t.Fatalf("atomic mailbox register+tokens failed: %d %s", resp.StatusCode, body)
	}

	// 4. Slow upload (Init at T+0, WatchInbox starts at T+10, Commit at T+20) + unknown JSON fields.
	chunk := bytes.Repeat([]byte("S"), 2048)
	initJSON := fmt.Sprintf(`{"mailbox_id":%q,"declared_total_bytes":2048,"sealed_header":%q,"parts":[{"part_id":0,"total_bytes":2048,"chunk_count":1}],"v1_1_ext":"ignored"}`,
		mbID, makeValidSealedHeaderB64())
	resp, body = cli.do(http.MethodPost, "/v1/spool/init", reqOpts{body: []byte(initJSON), depositToken: tok1})
	if resp.StatusCode != 201 {
		t.Fatalf("spool init with unknown ext field failed: %d %s", resp.StatusCode, body)
	}
	var ir SpoolInitResponse
	_ = json.Unmarshal(body, &ir)
	cli.do(http.MethodPut, "/v1/spool/"+ir.ItemID+"/parts/0/chunks/0", reqOpts{body: chunk, isStream: true, uploadToken: ir.UploadToken})

	// Advance clock 10s (WatchInbox connects at T+10 with since_ts = T+10), then Commit at T+20!
	clk.Advance(10 * time.Second)
	watchSinceTS := clk.Now().Unix()
	clk.Advance(10 * time.Second)
	commitTS := clk.Now().Unix()

	resp, body = cli.do(http.MethodPost, "/v1/spool/"+ir.ItemID+"/commit", reqOpts{
		body:        []byte(`{"v1_1_commit_ext":123}`),
		uploadToken: ir.UploadToken,
	})
	if resp.StatusCode != 200 {
		t.Fatalf("commit with unknown ext field failed: %d %s", resp.StatusCode, body)
	}

	// Poll events with since_ts = watchSinceTS (T+10): item initialized at T+0 but committed at T+20 MUST be returned!
	pollPath := fmt.Sprintf("/v1/mailboxes/%s/events?mode=poll&wait_sec=1&since_ts=%d", mbID, watchSinceTS)
	resp, body = cli.do(http.MethodGet, pollPath, reqOpts{mailboxID: mbID, mailboxSK: priv})
	if resp.StatusCode != 200 {
		t.Fatalf("events poll failed: %d %s", resp.StatusCode, body)
	}
	var pollOut struct {
		Items []MailboxEventItem `json:"items"`
	}
	_ = json.Unmarshal(body, &pollOut)
	if len(pollOut.Items) != 1 || pollOut.Items[0].ItemID != ir.ItemID || pollOut.Items[0].CreatedAt != commitTS {
		t.Fatalf("expected slow-uploaded item to emit with committedAt=%d, got %+v", commitTS, pollOut.Items)
	}

	// 5. Re-register PUT /v1/mailboxes/{id} merging [tok2, tok3] MUST preserve unread item & tok1!
	put2, _ := json.Marshal(map[string]any{
		"auth_pk_b64": base64.RawURLEncoding.EncodeToString(pub),
		"deposit_tokens": []DepositTokenEntry{
			{TokenID: "dt_peer_02", TokenHashHex: HashDepositToken(tok2)},
			{TokenID: "dt_peer_03", TokenHashHex: HashDepositToken(tok3)},
		},
	})
	resp, body = cli.do(http.MethodPut, "/v1/mailboxes/"+mbID, reqOpts{body: put2, mailboxID: mbID, mailboxSK: priv})
	if resp.StatusCode != 200 || !strings.Contains(string(body), `"deposit_token_count":3`) {
		t.Fatalf("re-register merge failed: %d %s", resp.StatusCode, body)
	}

	// Idempotent POST /deposit-tokens with identical hash succeeds; conflicting hash returns 409!
	dupSame, _ := json.Marshal(DepositTokenEntry{TokenID: "dt_peer_02", TokenHashHex: HashDepositToken(tok2)})
	resp, body = cli.do(http.MethodPost, "/v1/mailboxes/"+mbID+"/deposit-tokens", reqOpts{body: dupSame, mailboxID: mbID, mailboxSK: priv})
	if resp.StatusCode != 201 || !strings.Contains(string(body), `"active_count":3`) {
		t.Fatalf("idempotent AddDepositToken failed: %d %s", resp.StatusCode, body)
	}
	dupConflict, _ := json.Marshal(DepositTokenEntry{TokenID: "dt_peer_02", TokenHashHex: HashDepositToken(tok1)})
	resp, _ = cli.do(http.MethodPost, "/v1/mailboxes/"+mbID+"/deposit-tokens", reqOpts{body: dupConflict, mailboxID: mbID, mailboxSK: priv})
	if resp.StatusCode != 409 {
		t.Fatalf("expected 409 on conflicting hash for existing token_id, got %d", resp.StatusCode)
	}

	// Unread item MUST still be intact in mailbox!
	resp, body = cli.do(http.MethodGet, "/v1/mailboxes/"+mbID+"/items", reqOpts{mailboxID: mbID, mailboxSK: priv})
	var listRes MailboxListResponse
	_ = json.Unmarshal(body, &listRes)
	if len(listRes.Items) != 1 || listRes.Items[0].ItemID != ir.ItemID {
		t.Fatalf("mailbox re-registration must NOT wipe unread items, got %+v", listRes)
	}
}

func TestParseProcSelfCgroupPaths(t *testing.T) {
	v2, v1 := ParseProcSelfCgroupPaths("0::/system.slice/synctool-relay.service\n")
	if v2 != "/system.slice/synctool-relay.service" || v1 != "" {
		t.Fatalf("unexpected cgroup v2 parse: v2=%q v1=%q", v2, v1)
	}
	v2, v1 = ParseProcSelfCgroupPaths("11:pids:/user.slice\n4:cpu,memory:/docker/abcdef123\n0::/\n")
	if v2 != "" || v1 != "/docker/abcdef123" {
		t.Fatalf("unexpected cgroup v1 parse: v2=%q v1=%q", v2, v1)
	}
}
