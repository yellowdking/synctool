package relay

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRoomsSSELongPollAndModeAZeroDiskPipe(t *testing.T) {
	_, _, cli, _ := newTestServerAndClient(t, func(c *Config) {
		c.Profile = ProfileNano
		c.Spool = SpoolOff // Also verifies Mode A works cleanly with --spool=off!
	})

	// Check /v1/caps reports spool.enabled=false and nano chunk size 262,208 B.
	resp, body := cli.do(http.MethodGet, "/v1/caps", reqOpts{})
	if resp.StatusCode != 200 {
		t.Fatalf("caps failed: %d %s", resp.StatusCode, body)
	}
	var caps map[string]any
	_ = json.Unmarshal(body, &caps)
	spoolCaps := caps["spool"].(map[string]any)
	streamCaps := caps["streaming"].(map[string]any)
	if spoolCaps["enabled"].(bool) || spoolCaps["backend"].(string) != "off" {
		t.Fatalf("expected spool disabled in caps: %v", spoolCaps)
	}
	if int(streamCaps["max_transport_chunk_bytes"].(float64)) != 262208 {
		t.Fatalf("expected nano chunk cap 262208, got %v", streamCaps["max_transport_chunk_bytes"])
	}

	// Verify Mode B returns 403 ERR_SPOOL_DISABLED when --spool=off.
	resp, body = cli.do(http.MethodPost, "/v1/spool/init", reqOpts{body: []byte(`{}`)})
	if resp.StatusCode != 403 || !strings.Contains(string(body), "ERR_SPOOL_DISABLED") {
		t.Fatalf("expected 403 ERR_SPOOL_DISABLED, got %d %s", resp.StatusCode, body)
	}

	// Create room with initial M1.
	m1 := base64.RawURLEncoding.EncodeToString([]byte(`{"proto_v":1,"mode":2,"commit_a":"abc"}`))
	resp, body = cli.do(http.MethodPost, "/v1/rooms", reqOpts{
		body: []byte(fmt.Sprintf(`{"room_id":"K7M9P2XQ","ttl_sec":300,"initial_msg_b64":%q}`, m1)),
	})
	if resp.StatusCode != 201 {
		t.Fatalf("create room failed: %d %s", resp.StatusCode, body)
	}
	var created RoomCreateResult
	_ = json.Unmarshal(body, &created)
	if created.Seq != 1 || created.PipeID == "" || created.SenderToken == "" {
		t.Fatalf("unexpected create result: %+v", created)
	}

	// Receiver joins WITHOUT msg_b64 -> seq MUST stay 1 (not increment!) and return M1.
	resp, body = cli.do(http.MethodPost, "/v1/rooms/K7M9P2XQ/join", reqOpts{body: []byte(`{}`)})
	if resp.StatusCode != 200 {
		t.Fatalf("join failed: %d %s", resp.StatusCode, body)
	}
	var joined RoomJoinResult
	_ = json.Unmarshal(body, &joined)
	if joined.Seq != 1 || len(joined.Messages) != 1 || joined.Messages[0].MsgB64 != m1 {
		t.Fatalf("join without msg_b64 should keep seq=1 and return M1, got %+v", joined)
	}

	// Second joiner -> 409 ERR_ROOM_BUSY.
	resp, body = cli.do(http.MethodPost, "/v1/rooms/K7M9P2XQ/join", reqOpts{body: []byte(`{}`)})
	if resp.StatusCode != 409 || !strings.Contains(string(body), "ERR_ROOM_BUSY") {
		t.Fatalf("expected 409 ERR_ROOM_BUSY, got %d %s", resp.StatusCode, body)
	}

	// Test Long-Poll waking up immediately on M2.
	pollDone := make(chan RoomEventsSnapshot, 1)
	go func() {
		r, b := cli.do(http.MethodGet, "/v1/rooms/K7M9P2XQ/events?since=1&mode=poll&wait_sec=5", reqOpts{roomToken: created.SenderToken})
		if r.StatusCode != 200 {
			t.Errorf("poll expected 200, got %d %s", r.StatusCode, b)
			return
		}
		var snap RoomEventsSnapshot
		_ = json.Unmarshal(b, &snap)
		pollDone <- snap
	}()
	time.Sleep(40 * time.Millisecond)

	m2 := base64.RawURLEncoding.EncodeToString([]byte(`{"proto_v":1,"mode":2,"e_b":"xyz"}`))
	resp, body = cli.do(http.MethodPost, "/v1/rooms/K7M9P2XQ/messages", reqOpts{
		roomToken: joined.ReceiverToken,
		body:      []byte(fmt.Sprintf(`{"kind":"handshake","msg_b64":%q}`, m2)),
	})
	if resp.StatusCode != 200 {
		t.Fatalf("post M2 failed: %d %s", resp.StatusCode, body)
	}
	snap := <-pollDone
	if len(snap.Messages) != 1 || snap.Messages[0].Seq != 2 || snap.Messages[0].MsgB64 != m2 {
		t.Fatalf("unexpected long-poll snapshot: %+v", snap)
	}

	// Test SSE headers (X-Accel-Buffering: no), keepalive ping, and message delivery.
	ssePath := "/v1/rooms/K7M9P2XQ/events?since=2&mode=sse"
	sseReq, _ := http.NewRequest(http.MethodGet, cli.baseURL+ssePath, nil)
	tsStr := strconv.FormatInt(cli.clock.Now().Unix(), 10)
	nonce := randNonceHex(t)
	sseReq.Header.Set(HeaderSyncTS, tsStr)
	sseReq.Header.Set(HeaderSyncNonce, nonce)
	sseReq.Header.Set(HeaderSyncSig, ComputeRelaySig(cli.hmacKey, http.MethodGet, ssePath, tsStr, nonce, EmptyBodySHA256Binding, ""))
	sseReq.Header.Set(HeaderSyncRoomToken, joined.ReceiverToken)
	sseResp, err := cli.http.Do(sseReq)
	if err != nil {
		t.Fatalf("SSE connect failed: %v", err)
	}
	defer sseResp.Body.Close()
	if sseResp.StatusCode != 200 || sseResp.Header.Get("X-Accel-Buffering") != "no" || !strings.HasPrefix(sseResp.Header.Get("Content-Type"), "text/event-stream") {
		t.Fatalf("unexpected SSE headers: status=%d hdr=%v", sseResp.StatusCode, sseResp.Header)
	}
	go func() {
		time.Sleep(150 * time.Millisecond) // allow at least one : ping keepalive first
		m3 := base64.RawURLEncoding.EncodeToString([]byte(`{"op":"pipe_start"}`))
		cli.do(http.MethodPost, "/v1/rooms/K7M9P2XQ/messages", reqOpts{
			roomToken: created.SenderToken,
			body:      []byte(fmt.Sprintf(`{"kind":"control","msg_b64":%q}`, m3)),
		})
	}()
	scanner := bufio.NewScanner(sseResp.Body)
	sawPing, sawMsg := false, false
	for scanner.Scan() {
		line := scanner.Text()
		if line == ": ping" {
			sawPing = true
		}
		if strings.HasPrefix(line, "event: message") {
			sawMsg = true
			break
		}
	}
	if !sawPing || !sawMsg {
		t.Fatalf("expected SSE keepalive ping (%v) and message event (%v)", sawPing, sawMsg)
	}

	// Test Mode A zero-disk chunked pipe: BOTH Sender-first AND Receiver-first arrival orders!
	chunk0 := bytes.Repeat([]byte("A1B2C3D4"), 16384) // 128 KiB <= 262,208 B
	chunk1 := bytes.Repeat([]byte("Z9Y8X7W6"), 8192)  // 64 KiB

	// Case 1: Sender PUT arrives first, Receiver GET joins 40ms later.
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		r, b := cli.do(http.MethodPut, fmt.Sprintf("/v1/pipe/%s/parts/1/chunks/0", created.PipeID), reqOpts{
			body:      chunk0,
			isStream:  true,
			roomToken: created.SenderToken,
		})
		if r.StatusCode != 200 {
			t.Errorf("pipe PUT 0 failed: %d %s", r.StatusCode, b)
		}
	}()
	go func() {
		defer wg.Done()
		time.Sleep(40 * time.Millisecond)
		r, b := cli.do(http.MethodGet, fmt.Sprintf("/v1/pipe/%s/parts/1/chunks/0", created.PipeID), reqOpts{
			roomToken: joined.ReceiverToken,
		})
		if r.StatusCode != 200 || !bytes.Equal(b, chunk0) {
			t.Errorf("pipe GET 0 mismatch: status=%d len=%d", r.StatusCode, len(b))
		}
	}()
	wg.Wait()

	// Case 2: Receiver GET arrives first, Sender PUT joins 40ms later.
	wg.Add(2)
	go func() {
		defer wg.Done()
		r, b := cli.do(http.MethodGet, fmt.Sprintf("/v1/pipe/%s/parts/1/chunks/1", created.PipeID), reqOpts{
			roomToken: joined.ReceiverToken,
		})
		if r.StatusCode != 200 || !bytes.Equal(b, chunk1) {
			t.Errorf("pipe GET 1 mismatch: status=%d len=%d", r.StatusCode, len(b))
		}
	}()
	go func() {
		defer wg.Done()
		time.Sleep(40 * time.Millisecond)
		r, b := cli.do(http.MethodPut, fmt.Sprintf("/v1/pipe/%s/parts/1/chunks/1", created.PipeID), reqOpts{
			body:      chunk1,
			isStream:  true,
			roomToken: created.SenderToken,
		})
		if r.StatusCode != 200 {
			t.Errorf("pipe PUT 1 failed: %d %s", r.StatusCode, b)
		}
	}()
	wg.Wait()

	// Oversized chunk (>262,208 B on nano) -> 413 ERR_CHUNK_TOO_LARGE.
	tooBig := make([]byte, 262209)
	resp, body = cli.do(http.MethodPut, fmt.Sprintf("/v1/pipe/%s/parts/1/chunks/2", created.PipeID), reqOpts{
		body:      tooBig,
		isStream:  true,
		roomToken: created.SenderToken,
	})
	if resp.StatusCode != 413 || !strings.Contains(string(body), "ERR_CHUNK_TOO_LARGE") {
		t.Fatalf("expected 413 ERR_CHUNK_TOO_LARGE, got %d %s", resp.StatusCode, body)
	}

	// Invalid part_id=64 -> 400 ERR_BAD_REQUEST.
	resp, body = cli.do(http.MethodPut, fmt.Sprintf("/v1/pipe/%s/parts/64/chunks/0", created.PipeID), reqOpts{
		body:      []byte("abc"),
		isStream:  true,
		roomToken: created.SenderToken,
	})
	if resp.StatusCode != 400 || !strings.Contains(string(body), "ERR_BAD_REQUEST") {
		t.Fatalf("expected 400 ERR_BAD_REQUEST for part_id=64, got %d %s", resp.StatusCode, body)
	}

	// Single-failure circuit breaker: verify_failed burns room immediately -> 410 ERR_ROOM_BURNED.
	resp, body = cli.do(http.MethodPost, "/v1/rooms/K7M9P2XQ/close", reqOpts{
		roomToken: created.SenderToken,
		body:      []byte(`{"reason":"verify_failed"}`),
	})
	if resp.StatusCode != 200 || !strings.Contains(string(body), `"burned"`) {
		t.Fatalf("expected burned close response, got %d %s", resp.StatusCode, body)
	}
	resp, body = cli.do(http.MethodPost, "/v1/rooms/K7M9P2XQ/messages", reqOpts{
		roomToken: joined.ReceiverToken,
		body:      fmt.Appendf(nil, `{"kind":"control","msg_b64":%q}`, m2),
	})
	if resp.StatusCode != 410 || !strings.Contains(string(body), "ERR_ROOM_BURNED") {
		t.Fatalf("expected 410 ERR_ROOM_BURNED after verify_failed, got %d %s", resp.StatusCode, body)
	}
}

func TestModeBSpoolDiskRestartRevocationQuotasAndDownloadCaps(t *testing.T) {
	dataDir := t.TempDir()
	accessKey := "disk_spool_test_access_key_must_be_32_plus_chars_long"

	// Start with disk spool + nano download limit (3 for blobs, 16 for manifest) + custom tight quotas.
	_, _, cli, clk := newTestServerAndClient(t, func(c *Config) {
		c.Profile = ProfileNano
		c.Spool = SpoolDisk
		c.DataDir = dataDir
		c.AccessKey = accessKey
		c.SpoolMaxItemBytes = 100000
		c.SpoolMaxMailboxBytes = 150000
		c.SpoolMaxTotalBytes = 200000
		c.SpoolMaxItemsPerMailbox = 2
	})

	pubB, privB, _ := ed25519.GenerateKey(rand.Reader)
	mbID := DeriveMailboxID(pubB)

	// 1. Register mailbox B.
	regBody, _ := json.Marshal(map[string]string{"auth_pk_b64": base64.RawURLEncoding.EncodeToString(pubB)})
	resp, body := cli.do(http.MethodPut, "/v1/mailboxes/"+mbID, reqOpts{
		body:      regBody,
		mailboxID: mbID,
		mailboxSK: privB,
	})
	if resp.StatusCode != 200 {
		t.Fatalf("register mailbox failed: %d %s", resp.StatusCode, body)
	}

	// 2. Register two independent deposit tokens (Device B1 and Device B2).
	tok1, _ := GenerateAccessKey()
	tok2, _ := GenerateAccessKey()
	addTok := func(id, raw string) {
		b, _ := json.Marshal(map[string]string{"token_id": id, "token_hash_hex": HashDepositToken(raw)})
		r, rb := cli.do(http.MethodPost, "/v1/mailboxes/"+mbID+"/deposit-tokens", reqOpts{
			body:      b,
			mailboxID: mbID,
			mailboxSK: privB,
		})
		if r.StatusCode != 201 {
			t.Fatalf("add token %s failed: %d %s", id, r.StatusCode, rb)
		}
	}
	addTok("dt_dev_001", tok1)
	addTok("dt_dev_002", tok2)

	// 3. Revoke Device 1 -> Device 1 rejected (401), Device 2 STILL works!
	resp, body = cli.do(http.MethodDelete, "/v1/mailboxes/"+mbID+"/deposit-tokens/dt_dev_001", reqOpts{
		mailboxID: mbID,
		mailboxSK: privB,
	})
	if resp.StatusCode != 200 {
		t.Fatalf("revoke token failed: %d %s", resp.StatusCode, body)
	}

	manifestChunk := bytes.Repeat([]byte("M"), 4112)
	blobChunk0 := bytes.Repeat([]byte("V"), 20000)
	blobChunk1 := bytes.Repeat([]byte("W"), 15000)
	initReq := SpoolInitRequest{
		MailboxID:          mbID,
		DeclaredTotalBytes: int64(len(manifestChunk) + len(blobChunk0) + len(blobChunk1)),
		TTLSec:             3600,
		SealedHeader:       makeValidSealedHeaderB64(),
		Parts: []SpoolPartSpec{
			{PartID: 0, TotalBytes: int64(len(manifestChunk)), ChunkCount: 1},
			{PartID: 1, TotalBytes: int64(len(blobChunk0) + len(blobChunk1)), ChunkCount: 2},
		},
	}
	initBytes, _ := json.Marshal(initReq)

	// Revoked tok1 MUST fail with 401.
	resp, body = cli.do(http.MethodPost, "/v1/spool/init", reqOpts{body: initBytes, depositToken: tok1})
	if resp.StatusCode != 401 {
		t.Fatalf("expected revoked tok1 to fail 401, got %d %s", resp.StatusCode, body)
	}

	// Active tok2 succeeds!
	resp, body = cli.do(http.MethodPost, "/v1/spool/init", reqOpts{body: initBytes, depositToken: tok2})
	if resp.StatusCode != 201 {
		t.Fatalf("expected active tok2 spool init 201, got %d %s", resp.StatusCode, body)
	}
	var initRes SpoolInitResponse
	_ = json.Unmarshal(body, &initRes)

	// Incomplete commit before uploading all chunks -> 409 ERR_INVALID_STATE with missing_chunks.
	resp, body = cli.do(http.MethodPost, "/v1/spool/"+initRes.ItemID+"/commit", reqOpts{
		body:        []byte(`{}`),
		uploadToken: initRes.UploadToken,
	})
	if resp.StatusCode != 409 || !strings.Contains(string(body), "missing_chunks") {
		t.Fatalf("expected 409 with missing_chunks, got %d %s", resp.StatusCode, body)
	}

	// Upload chunks (including idempotent retry of part 1 chunk 0).
	uploadChunk := func(partID, txIdx int, payload []byte) {
		r, b := cli.do(http.MethodPut, fmt.Sprintf("/v1/spool/%s/parts/%d/chunks/%d", initRes.ItemID, partID, txIdx), reqOpts{
			body:        payload,
			isStream:    true,
			uploadToken: initRes.UploadToken,
		})
		if r.StatusCode != 200 {
			t.Fatalf("upload part %d chunk %d failed: %d %s", partID, txIdx, r.StatusCode, b)
		}
	}
	uploadChunk(0, 0, manifestChunk)
	uploadChunk(1, 0, blobChunk0)
	uploadChunk(1, 0, blobChunk0) // idempotent retry
	uploadChunk(1, 1, blobChunk1)

	// Commit succeeds!
	resp, body = cli.do(http.MethodPost, "/v1/spool/"+initRes.ItemID+"/commit", reqOpts{
		body:        []byte(`{}`),
		uploadToken: initRes.UploadToken,
	})
	if resp.StatusCode != 200 {
		t.Fatalf("commit failed: %d %s", resp.StatusCode, body)
	}

	// 4. Test 4-tier quotas (advance virtual clock so nano control token bucket refills cleanly):
	clk.Advance(30 * time.Second)
	// 4a. Single-item quota -> 413 ERR_OFFLINE_QUOTA_EXCEEDED (scope=item).
	bigReq := initReq
	bigReq.DeclaredTotalBytes = 100001
	bigReq.Parts = []SpoolPartSpec{{PartID: 0, TotalBytes: 100001, ChunkCount: 1}}
	bigBytes, _ := json.Marshal(bigReq)
	resp, body = cli.do(http.MethodPost, "/v1/spool/init", reqOpts{body: bigBytes, depositToken: tok2})
	if resp.StatusCode != 413 || !strings.Contains(string(body), `"scope":"item"`) {
		t.Fatalf("expected 413 item quota exceeded, got %d %s", resp.StatusCode, body)
	}

	// 4b. Uncommitted upload + abort releases quota cleanly.
	smallReq := initReq
	smallReq.DeclaredTotalBytes = 50000
	smallReq.Parts = []SpoolPartSpec{{PartID: 0, TotalBytes: 50000, ChunkCount: 1}}
	smallBytes, _ := json.Marshal(smallReq)
	resp, body = cli.do(http.MethodPost, "/v1/spool/init", reqOpts{body: smallBytes, depositToken: tok2})
	if resp.StatusCode != 201 {
		t.Fatalf("expected second item init 201, got %d %s", resp.StatusCode, body)
	}
	var secondRes SpoolInitResponse
	_ = json.Unmarshal(body, &secondRes)

	// Third item hits item_count=2 cap -> 507 ERR_OFFLINE_QUOTA_EXCEEDED (scope=item_count).
	resp, body = cli.do(http.MethodPost, "/v1/spool/init", reqOpts{body: smallBytes, depositToken: tok2})
	if resp.StatusCode != 507 || !strings.Contains(string(body), `"scope":"item_count"`) {
		t.Fatalf("expected 507 item_count quota exceeded, got %d %s", resp.StatusCode, body)
	}

	// Abort uncommitted second item -> reclaims item slot!
	resp, _ = cli.do(http.MethodDelete, "/v1/spool/"+secondRes.ItemID, reqOpts{uploadToken: secondRes.UploadToken})
	if resp.StatusCode != 200 {
		t.Fatalf("abort failed: %d", resp.StatusCode)
	}

	// Create an uncommitted item to verify restart purges uncommitted & preserves committed.
	uncommReq := initReq
	uncommReq.DeclaredTotalBytes = 90000
	uncommReq.Parts = []SpoolPartSpec{{PartID: 0, TotalBytes: 90000, ChunkCount: 1}}
	uncommBytes, _ := json.Marshal(uncommReq)
	resp, body = cli.do(http.MethodPost, "/v1/spool/init", reqOpts{body: uncommBytes, depositToken: tok2})
	if resp.StatusCode != 201 {
		t.Fatalf("expected uncommitted item init 201, got %d %s", resp.StatusCode, body)
	}

	// 5. Simulate server RESTART pointing at same dataDir!
	_, _, cli2, _ := newTestServerAndClient(t, func(c *Config) {
		c.Profile = ProfileNano
		c.Spool = SpoolDisk
		c.DataDir = dataDir
		c.AccessKey = accessKey
		c.NowFunc = clk.Now
	})
	cli2.clock = clk

	// Mailbox list MUST contain committed item (and NOT uncommitted item!).
	resp, body = cli2.do(http.MethodGet, "/v1/mailboxes/"+mbID+"/items", reqOpts{
		mailboxID: mbID,
		mailboxSK: privB,
	})
	if resp.StatusCode != 200 {
		t.Fatalf("list after restart failed: %d %s", resp.StatusCode, body)
	}
	var listRes MailboxListResponse
	_ = json.Unmarshal(body, &listRes)
	if len(listRes.Items) != 1 || listRes.Items[0].ItemID != initRes.ItemID || listRes.UsedBytes != initReq.DeclaredTotalBytes {
		t.Fatalf("unexpected items after disk restart: %+v", listRes)
	}

	// 6. Verify independent download limits: part_id=0 allows 16 downloads (17th -> 403),
	//    while part_id=1 on nano allows 3 downloads (4th -> 403), and GET NEVER deletes item!
	for i := 0; i < MaxManifestDownloads; i++ {
		clk.Advance(time.Second)
		r, b := cli2.do(http.MethodGet, fmt.Sprintf("/v1/spool/%s/parts/0/chunks/0", initRes.ItemID), reqOpts{
			mailboxID: mbID,
			mailboxSK: privB,
		})
		if r.StatusCode != 200 || !bytes.Equal(b, manifestChunk) {
			t.Fatalf("manifest download #%d failed: %d", i+1, r.StatusCode)
		}
	}
	clk.Advance(time.Second)
	resp, body = cli2.do(http.MethodGet, fmt.Sprintf("/v1/spool/%s/parts/0/chunks/0", initRes.ItemID), reqOpts{
		mailboxID: mbID,
		mailboxSK: privB,
	})
	if resp.StatusCode != 403 || !strings.Contains(string(body), "ERR_DOWNLOAD_LIMIT_EXCEEDED") {
		t.Fatalf("expected 17th manifest download to hit 403 ERR_DOWNLOAD_LIMIT_EXCEEDED, got %d %s", resp.StatusCode, body)
	}

	for i := 0; i < 3; i++ {
		clk.Advance(time.Second)
		r, b := cli2.do(http.MethodGet, fmt.Sprintf("/v1/spool/%s/parts/1/chunks/0", initRes.ItemID), reqOpts{
			mailboxID: mbID,
			mailboxSK: privB,
		})
		if r.StatusCode != 200 || !bytes.Equal(b, blobChunk0) {
			t.Fatalf("blob download #%d failed: %d", i+1, r.StatusCode)
		}
	}
	clk.Advance(time.Second)
	resp, body = cli2.do(http.MethodGet, fmt.Sprintf("/v1/spool/%s/parts/1/chunks/0", initRes.ItemID), reqOpts{
		mailboxID: mbID,
		mailboxSK: privB,
	})
	if resp.StatusCode != 403 || !strings.Contains(string(body), "ERR_DOWNLOAD_LIMIT_EXCEEDED") {
		t.Fatalf("expected 4th nano blob download to hit 403, got %d %s", resp.StatusCode, body)
	}
	clk.Advance(30 * time.Second)

	// 7. Forged ACK signature by wrong key MUST fail 401 and leave item intact!
	_, wrongPriv, _ := ed25519.GenerateKey(rand.Reader)
	resp, _ = cli2.do(http.MethodPost, "/v1/spool/"+initRes.ItemID+"/ack", reqOpts{
		body:      []byte(`{}`),
		mailboxID: mbID,
		mailboxSK: wrongPriv,
	})
	if resp.StatusCode != 401 {
		t.Fatalf("expected forged ACK to fail 401, got %d", resp.StatusCode)
	}

	// 8. Valid signed ACK burns item physically from disk & reclaims quota!
	resp, body = cli2.do(http.MethodPost, "/v1/spool/"+initRes.ItemID+"/ack", reqOpts{
		body:      []byte(`{}`),
		mailboxID: mbID,
		mailboxSK: privB,
	})
	if resp.StatusCode != 200 || !strings.Contains(string(body), `"burned":true`) {
		t.Fatalf("valid ACK failed: %d %s", resp.StatusCode, body)
	}
	itemDir := filepath.Join(dataDir, "spool", mbID[:2], mbID, initRes.ItemID)
	if _, err := os.Stat(itemDir); !os.IsNotExist(err) {
		t.Fatalf("expected item directory %s to be physically removed after ACK", itemDir)
	}

	// Subsequent GET or ACK returns 404 ERR_NOT_FOUND.
	resp, _ = cli2.do(http.MethodGet, fmt.Sprintf("/v1/spool/%s/parts/1/chunks/1", initRes.ItemID), reqOpts{
		mailboxID: mbID,
		mailboxSK: privB,
	})
	if resp.StatusCode != 404 {
		t.Fatalf("expected 404 after burn, got %d", resp.StatusCode)
	}
}

func TestModeBGlobalAndMailboxQuotasAndEventsSSE(t *testing.T) {
	_, _, cli, _ := newTestServerAndClient(t, func(c *Config) {
		c.Profile = ProfileStandard
		c.Spool = SpoolMemory
		c.SpoolMaxItemBytes = 10000
		c.SpoolMaxMailboxBytes = 12000
		c.SpoolMaxTotalBytes = 15000
		c.SpoolMaxItemsPerMailbox = 10
	})

	register := func() (string, ed25519.PrivateKey, string) {
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		mb := DeriveMailboxID(pub)
		rb, _ := json.Marshal(map[string]string{"auth_pk_b64": base64.RawURLEncoding.EncodeToString(pub)})
		r, _ := cli.do(http.MethodPut, "/v1/mailboxes/"+mb, reqOpts{body: rb, mailboxID: mb, mailboxSK: priv})
		if r.StatusCode != 200 {
			t.Fatalf("register %s failed: %d", mb, r.StatusCode)
		}
		tok, _ := GenerateAccessKey()
		tb, _ := json.Marshal(map[string]string{"token_id": "dt_peer_001", "token_hash_hex": HashDepositToken(tok)})
		r, _ = cli.do(http.MethodPost, "/v1/mailboxes/"+mb+"/deposit-tokens", reqOpts{body: tb, mailboxID: mb, mailboxSK: priv})
		if r.StatusCode != 201 {
			t.Fatalf("add token failed: %d", r.StatusCode)
		}
		return mb, priv, tok
	}

	mb1, priv1, tok1 := register()
	mb2, _, tok2 := register()

	// Subscribe SSE on mb1 before commit.
	ssePath := "/v1/mailboxes/" + mb1 + "/events?mode=sse&since_ts=0"
	sseReq, _ := http.NewRequest(http.MethodGet, cli.baseURL+ssePath, nil)
	tsStr := strconv.FormatInt(cli.clock.Now().Unix(), 10)
	nonce := randNonceHex(t)
	sseReq.Header.Set(HeaderSyncTS, tsStr)
	sseReq.Header.Set(HeaderSyncNonce, nonce)
	sseReq.Header.Set(HeaderSyncSig, ComputeRelaySig(cli.hmacKey, http.MethodGet, ssePath, tsStr, nonce, EmptyBodySHA256Binding, ""))
	sseReq.Header.Set(HeaderSyncMailboxSig, signMailboxEd25519(priv1, http.MethodGet, ssePath, mb1, tsStr, nonce, EmptyBodySHA256Binding))
	sseResp, err := cli.http.Do(sseReq)
	if err != nil {
		t.Fatal(err)
	}
	defer sseResp.Body.Close()

	// Upload & commit 8000B item to mb1.
	chunk := bytes.Repeat([]byte("X"), 8000)
	initBytes, _ := json.Marshal(SpoolInitRequest{
		MailboxID:          mb1,
		DeclaredTotalBytes: 8000,
		SealedHeader:       makeValidSealedHeaderB64(),
		Parts:              []SpoolPartSpec{{PartID: 0, TotalBytes: 8000, ChunkCount: 1}},
	})
	resp, body := cli.do(http.MethodPost, "/v1/spool/init", reqOpts{body: initBytes, depositToken: tok1})
	if resp.StatusCode != 201 {
		t.Fatalf("init mb1 failed: %d %s", resp.StatusCode, body)
	}
	var ir SpoolInitResponse
	_ = json.Unmarshal(body, &ir)
	cli.do(http.MethodPut, "/v1/spool/"+ir.ItemID+"/parts/0/chunks/0", reqOpts{body: chunk, isStream: true, uploadToken: ir.UploadToken})
	cli.do(http.MethodPost, "/v1/spool/"+ir.ItemID+"/commit", reqOpts{body: []byte(`{}`), uploadToken: ir.UploadToken})

	// SSE on mb1 MUST receive event: new_item.
	sc := bufio.NewScanner(sseResp.Body)
	gotNewItem := false
	for sc.Scan() {
		if strings.HasPrefix(sc.Text(), "event: new_item") {
			gotNewItem = true
			break
		}
	}
	if !gotNewItem {
		t.Fatal("expected mailbox SSE to emit event: new_item")
	}

	// Second 5000B item to mb1 exceeds mailbox cap (8000+5000 > 12000) -> 507 scope=mailbox.
	initMB1Over, _ := json.Marshal(SpoolInitRequest{
		MailboxID:          mb1,
		DeclaredTotalBytes: 5000,
		SealedHeader:       makeValidSealedHeaderB64(),
		Parts:              []SpoolPartSpec{{PartID: 0, TotalBytes: 5000, ChunkCount: 1}},
	})
	resp, body = cli.do(http.MethodPost, "/v1/spool/init", reqOpts{body: initMB1Over, depositToken: tok1})
	if resp.StatusCode != 507 || !strings.Contains(string(body), `"scope":"mailbox"`) {
		t.Fatalf("expected 507 mailbox quota exceeded, got %d %s", resp.StatusCode, body)
	}

	// 8000B item to mb2 fits mb2 (<=12000) but exceeds global cap (8000+8000 > 15000) -> 507 scope=global!
	initMB2Global, _ := json.Marshal(SpoolInitRequest{
		MailboxID:          mb2,
		DeclaredTotalBytes: 8000,
		SealedHeader:       makeValidSealedHeaderB64(),
		Parts:              []SpoolPartSpec{{PartID: 0, TotalBytes: 8000, ChunkCount: 1}},
	})
	resp, body = cli.do(http.MethodPost, "/v1/spool/init", reqOpts{body: initMB2Global, depositToken: tok2})
	if resp.StatusCode != 507 || !strings.Contains(string(body), `"scope":"global"`) {
		t.Fatalf("expected 507 global quota exceeded, got %d %s", resp.StatusCode, body)
	}
}
