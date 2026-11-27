package e2e

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yellowdking/synctool/internal/relay"
	"github.com/yellowdking/synctool/sdk/go/client"
	synccrypto "github.com/yellowdking/synctool/sdk/go/crypto"
	"github.com/yellowdking/synctool/sdk/go/envelope"
)

func startRelayWithState(t *testing.T, listenAddr, dataDir string, modify func(*relay.Config)) (*runningRelay, string) {
	t.Helper()
	if dataDir == "" {
		dataDir = t.TempDir()
	}
	var rawLn net.Listener
	var err error
	for i := 0; i < 30; i++ {
		rawLn, err = net.Listen("tcp", listenAddr)
		if err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("listen %s: %v", listenAddr, err)
	}
	boundAddr := rawLn.Addr().String()

	cfg := relay.DefaultConfig()
	cfg.ListenAddr = boundAddr
	cfg.PublicHost = "127.0.0.1"
	cfg.Profile = relay.ProfileNano
	cfg.Spool = relay.SpoolMemory
	cfg.TLSMode = relay.TLSSelfSigned
	cfg.DataDir = dataDir
	cfg.ServerVersion = "0.2.0-e2e"
	cfg.DisableMemTune = true
	if modify != nil {
		modify(&cfg)
	}

	rc, err := cfg.Resolve()
	if err != nil {
		_ = rawLn.Close()
		t.Fatalf("resolve relay config: %v", err)
	}
	srv, err := relay.NewServer(rc, nil)
	if err != nil {
		_ = rawLn.Close()
		t.Fatalf("new relay server: %v", err)
	}
	ln := srv.WrapListener(rawLn)
	httpSrv := srv.NewHTTPServer()

	serveLn := ln
	scheme := "https"
	spkiPin := ""
	if rc.TLSMode == relay.TLSOff {
		scheme = "http"
	} else {
		serveLn = tls.NewListener(ln, httpSrv.TLSConfig)
		if b := srv.Certs().Current(); b != nil {
			spkiPin = b.SPKISHA256Hex
		}
	}
	go func() {
		_ = httpSrv.Serve(serveLn)
	}()

	rr := &runningRelay{
		Origin:    fmt.Sprintf("%s://%s", scheme, boundAddr),
		SPKIPin:   spkiPin,
		AccessKey: rc.AccessKey,
		DataDir:   dataDir,
		Server:    srv,
		HTTP:      httpSrv,
	}
	var stopped atomic.Bool
	rr.Cleanup = func() {
		if !stopped.CompareAndSwap(false, true) {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(ctx)
		_ = rawLn.Close()
		srv.Close()
	}
	t.Cleanup(rr.Cleanup)
	return rr, boundAddr
}

func TestE2E_SelfHealing_NanoMemoryRestart_FromEnv_SendText_And_SafeSave(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// 1. Start Relay #1 (--profile=nano --spool=memory) and pair Alice <-> Bob using persistent FileKeyStores.
	relayDataDir := t.TempDir()
	rr1, boundAddr := startRelayWithState(t, "127.0.0.1:0", relayDataDir, nil)
	relayURI := relay.BuildRelayURI(rr1.Origin, rr1.SPKIPin, rr1.AccessKey)

	aliceCfgDir := t.TempDir()
	bobCfgDir := t.TempDir()
	bobTempDir := t.TempDir()

	t.Setenv("SYNCTOOL_RELAY", relayURI)
	t.Setenv("SYNCTOOL_CONFIG", aliceCfgDir)
	t.Setenv("SYNCTOOL_APP", "com.yellowdking.notes")
	alice, err := client.NewFromEnv(client.Config{DeviceLabel: "Alice-Laptop"})
	if err != nil {
		t.Fatalf("NewFromEnv(alice) failed: %v", err)
	}
	defer alice.Close()

	bobKS, err := envelope.NewFileKeyStore(bobCfgDir)
	if err != nil {
		t.Fatalf("NewFileKeyStore(bob): %v", err)
	}
	bobProf, err := envelope.ParseRelayURI(relayURI)
	if err != nil {
		t.Fatalf("ParseRelayURI: %v", err)
	}
	bob, err := client.New(client.Config{
		AppID:       "com.yellowdking.notes",
		DeviceLabel: "Bob-Nano",
		Relay:       bobProf,
		KeyStore:    bobKS,
		TempDir:     bobTempDir,
	})
	if err != nil {
		t.Fatalf("client.New(bob): %v", err)
	}

	_, bobCardOfAlice := pairTwoClients(t, ctx, alice, bob, synccrypto.ModeQROOB)
	if len(bobCardOfAlice.InboundTokenHash) != 64 {
		t.Fatalf("expected 64-hex InboundTokenHash persisted on Bob's DeviceCard, got %q", bobCardOfAlice.InboundTokenHash)
	}

	// 2. Reboot the nano memory-spool relay on the exact same port & DataDir (certs/key preserved, RAM wiped!).
	rr1.Cleanup()
	rr2, _ := startRelayWithState(t, boundAddr, relayDataDir, nil)
	if rr2.Origin != rr1.Origin || rr2.SPKIPin != rr1.SPKIPin {
		t.Fatalf("restarted relay identity changed unexpectedly")
	}

	// Before Bob heals, Alice attempting Mode B spool delivery hits 404 ERR_NOT_FOUND (mailbox wiped in RAM).
	if _, err := alice.SendText(ctx, "Bob-Nano", "before-heal"); !envelope.IsCode(err, envelope.ErrCodeNotFound) {
		t.Fatalf("expected 404 ERR_NOT_FOUND before Bob self-heals, got: %v", err)
	}

	// 3. Bob calls ListInbox -> transparently runs 1-RTT SyncMailbox (restoring mailbox + Alice's deposit token)!
	emptyInbox, err := bob.ListInbox(ctx, "")
	if err != nil || len(emptyInbox) != 0 {
		t.Fatalf("expected transparent self-healing ListInbox to succeed empty, got len=%d err=%v", len(emptyInbox), err)
	}

	// 4. Now Alice sends via ergonomic SendText + tricky Windows-reserved/Bidi filename attachment without re-pairing!
	if _, err := alice.SendText(ctx, "Bob-Nano", "healed-after-nano-reboot"); err != nil {
		t.Fatalf("Alice SendText after self-healing failed: %v", err)
	}
	attBytes := []byte("confidential-ssh-config-payload")
	resAtt, err := alice.SendToDevice(ctx, mustResolveID(t, alice, "Bob-Nano"), envelope.ParcelJSON(
		"com.yellowdking.notes",
		"note.item.v1",
		map[string]any{"title": "reserved-name-check"},
		envelope.BlobFromReader("file", "..\\CON.txt", "text/plain", int64(len(attBytes)), func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(attBytes)), nil
		}),
	), client.WithDeliveryMode(client.DeliveryAuto))
	if err != nil {
		t.Fatalf("Alice SendToDevice(CON.txt) failed: %v", err)
	}

	previews, err := bob.ListInbox(ctx, "com.yellowdking.notes")
	if err != nil || len(previews) != 2 {
		t.Fatalf("expected 2 parcels in Bob's healed inbox, got len=%d err=%v", len(previews), err)
	}

	outDir := t.TempDir()
	// Pre-create _CON.txt to prove SaveToDir never overwrites existing files (allocates _CON_1.txt).
	existingTarget := filepath.Join(outDir, "_CON.txt")
	if err := os.WriteFile(existingTarget, []byte("KEEP_EXISTING"), 0o600); err != nil {
		t.Fatalf("write existing file: %v", err)
	}

	var gotText string
	var savedAttPath string
	for _, it := range previews {
		_, err := bob.FetchParcel(ctx, it.ItemID, func(p envelope.ReceivedParcel) error {
			if txt, ok := p.Manifest.InlinePayload["text"].(string); ok {
				gotText = txt
			}
			for _, b := range p.Blobs {
				if b.SafeName != "_CON.txt" {
					return fmt.Errorf("expected Windows reserved CON.txt sanitized to _CON.txt, got %q", b.SafeName)
				}
				// Verify SafePath uses .verified staging suffix before SaveToDir moves it.
				if !strings.HasSuffix(b.SafePath, ".verified") {
					return fmt.Errorf("expected .verified staging path, got %q", b.SafePath)
				}
				saved, err := b.SaveToDir(outDir)
				if err != nil {
					return err
				}
				savedAttPath = saved
			}
			return nil
		}, client.ReceiveOptions{})
		if err != nil {
			t.Fatalf("FetchParcel(%s) failed: %v", it.ItemID, err)
		}
	}
	if gotText != "healed-after-nano-reboot" {
		t.Fatalf("unexpected text payload: %q", gotText)
	}
	if filepath.Base(savedAttPath) != "_CON_1.txt" {
		t.Fatalf("expected non-clobbering collision name _CON_1.txt, got %q", savedAttPath)
	}
	if keep, _ := os.ReadFile(existingTarget); string(keep) != "KEEP_EXISTING" {
		t.Fatalf("existing file was overwritten!")
	}
	if gotAtt, _ := os.ReadFile(savedAttPath); !bytes.Equal(gotAtt, attBytes) {
		t.Fatalf("saved attachment content mismatch")
	}

	// Verify Client.Close() sweeps tracked TempDir/<msg_id> directories cleanly.
	bob.Close()
	if _, err := os.Stat(filepath.Join(bobTempDir, resAtt.MsgID)); !os.IsNotExist(err) {
		t.Fatalf("expected Client.Close() to clean TempDir/<msg_id>, stat err=%v", err)
	}
}

func mustResolveID(t *testing.T, cli *client.Client, label string) string {
	t.Helper()
	c, err := client.ResolveDeviceByIDOrLabel(cli.KeyStoreHint(), label)
	if err != nil {
		t.Fatalf("ResolveDeviceByIDOrLabel(%s): %v", label, err)
	}
	return c.DeviceID
}

func TestE2E_SecurityHardening_Redirect_Headers_Overflow_XFF_SlowWatch_And_VersionCompat(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// 1. HTTP 307 Redirect Credential-Leak Block: X-Sync-* headers MUST NEVER follow redirects!
	var canaryHits atomic.Int32
	canarySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		canaryHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer canarySrv.Close()

	maliciousRedirectSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, canarySrv.URL+"/steal", http.StatusTemporaryRedirect)
	}))
	defer maliciousRedirectSrv.Close()

	redirCli, err := client.New(client.Config{
		Relay: &envelope.RelayProfile{
			Endpoint:  maliciousRedirectSrv.URL,
			AccessKey: "REDIRECT-TEST-ACCESS-KEY-0123456789ABCDEF",
			TLSMode:   envelope.TLSModeSystemCA,
		},
		KeyStore: envelope.NewMemoryKeyStore(),
	})
	if err != nil {
		t.Fatalf("new redir client: %v", err)
	}
	defer redirCli.Close()

	_, redirErr := redirCli.Ping(ctx)
	if !envelope.IsCode(redirErr, envelope.ErrCodeRelayUnreachable) || envelope.IsRetryable(redirErr) {
		t.Fatalf("expected non-retryable ERR_RELAY_UNREACHABLE on 307 redirect, got %v", redirErr)
	}
	if canaryHits.Load() != 0 {
		t.Fatalf("CRITICAL: SDK followed HTTP redirect and leaked request to canary (%d hits)!", canaryHits.Load())
	}

	// 2. Relay Protocol Version Negotiation, Security Headers, Dual-Token Confusion & MinInt64 Clock Skew Block.
	rr := startRealRelay(t, func(cfg *relay.Config) {
		cfg.Profile = relay.ProfileNano
		cfg.Spool = relay.SpoolMemory
		cfg.ServerVersion = "0.2.0"
	})
	alice, _ := newSDKClient(t, rr, "alice-sec", nil)
	bob, _ := newSDKClient(t, rr, "bob-sec", nil)

	pingRes, err := alice.Ping(ctx)
	if err != nil {
		t.Fatalf("Ping: %v", err)
	}
	if pingRes.MinProtoV != 1 || pingRes.MaxProtoV != 1 || pingRes.ServerVersion != "0.2.0" {
		t.Fatalf("unexpected version negotiation fields in Ping: %+v", pingRes)
	}
	capsRes, err := alice.Capabilities(ctx)
	if err != nil {
		t.Fatalf("Capabilities: %v", err)
	}
	if !slices.Contains(capsRes.Features, "mailbox_rebind_merge") || !slices.Contains(capsRes.Features, "spool_v1") {
		t.Fatalf("expected mailbox_rebind_merge and spool_v1 in caps.features, got %v", capsRes.Features)
	}

	rawTLSClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13},
		},
	}
	doRawSigned := func(path string, tsStr string, extraHeaders map[string]string) *http.Response {
		nonce, _ := synccrypto.GenerateNonceHex()
		dep := extraHeaders[synccrypto.HeaderDepositToken]
		up := extraHeaders[synccrypto.HeaderUploadToken]
		sig := synccrypto.SignRelayRequest(rr.AccessKey, http.MethodGet, path, tsStr, nonce, synccrypto.BodyBindingControl(nil), synccrypto.ExtraTokenBinding(dep, up))
		req, _ := http.NewRequest(http.MethodGet, rr.Origin+path, nil)
		req.Header.Set(synccrypto.HeaderClientAgent, "synctool-e2e/1.0")
		req.Header.Set(synccrypto.HeaderRelayTS, tsStr)
		req.Header.Set(synccrypto.HeaderRelayNonce, nonce)
		req.Header.Set(synccrypto.HeaderRelaySig, sig)
		for k, v := range extraHeaders {
			req.Header.Set(k, v)
		}
		resp, err := rawTLSClient.Do(req)
		if err != nil {
			t.Fatalf("raw signed request failed: %v", err)
		}
		return resp
	}

	// Verify X-Content-Type-Options: nosniff & Cache-Control: no-store on valid 200 response.
	okResp := doRawSigned("/v1/ping", strconv.FormatInt(time.Now().Unix(), 10), nil)
	_ = okResp.Body.Close()
	if okResp.StatusCode != http.StatusOK || okResp.Header.Get("X-Content-Type-Options") != "nosniff" || okResp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("missing security headers on 200 response: status=%d hdr=%v", okResp.StatusCode, okResp.Header)
	}

	// Simultaneous X-Sync-Deposit-Token + X-Sync-Upload-Token MUST return stealth 404.
	dualResp := doRawSigned("/v1/ping", strconv.FormatInt(time.Now().Unix(), 10), map[string]string{
		synccrypto.HeaderDepositToken: "tok_deposit_1234567890",
		synccrypto.HeaderUploadToken:  "tok_upload_1234567890",
	})
	dualBody, _ := io.ReadAll(dualResp.Body)
	_ = dualResp.Body.Close()
	if dualResp.StatusCode != http.StatusNotFound || len(dualBody) != 0 {
		t.Fatalf("expected stealth 404 on simultaneous deposit+upload tokens, got %d %q", dualResp.StatusCode, string(dualBody))
	}

	// math.MinInt64 X-Sync-TS overflow attempt MUST return stealth 404.
	minIntResp := doRawSigned("/v1/ping", strconv.FormatInt(math.MinInt64, 10), nil)
	_ = minIntResp.Body.Close()
	if minIntResp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected stealth 404 on MinInt64 X-Sync-TS, got %d", minIntResp.StatusCode)
	}

	// URL-encoded path traversal MUST return stealth 404.
	encPathResp := doRawSigned("/v1/mailboxes/..%2fping", strconv.FormatInt(time.Now().Unix(), 10), nil)
	_ = encPathResp.Body.Close()
	if encPathResp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected stealth 404 on encoded path traversal, got %d", encPathResp.StatusCode)
	}

	// 3. Trusted Proxy All-Trusted XFF Chain MUST NOT fall through to spoofed CF-Connecting-IP!
	rrProxy := startRealRelay(t, func(cfg *relay.Config) {
		cfg.TLSMode = relay.TLSOff
		cfg.TrustedProxies = []netip.Prefix{
			netip.MustParsePrefix("127.0.0.1/32"),
			netip.MustParsePrefix("10.0.0.0/8"),
		}
	})
	plainCli := &http.Client{}
	for i := 0; i < 12; i++ {
		req, _ := http.NewRequest(http.MethodGet, rrProxy.Origin+"/v1/ping", nil)
		// Internal client 10.1.2.3 via proxy 127.0.0.1 trying to frame victim 198.51.100.88 via CF-Connecting-IP:
		req.Header.Set("X-Forwarded-For", "10.1.2.3")
		req.Header.Set("CF-Connecting-IP", "198.51.100.88")
		resp, err := plainCli.Do(req)
		if err != nil {
			t.Fatalf("proxy spoof probe failed: %v", err)
		}
		_ = resp.Body.Close()
	}
	if rrProxy.Server.Guard().IsBanned(netip.MustParseAddr("198.51.100.88"), time.Now()) {
		t.Fatalf("spoofed CF-Connecting-IP framed innocent IP 198.51.100.88 under all-trusted XFF!")
	}
	if !rrProxy.Server.Guard().IsBanned(netip.MustParseAddr("10.1.2.3"), time.Now()) {
		t.Fatalf("expected true internal sender 10.1.2.3 to be banned after 12 bad strikes")
	}

	// 4. WatchInbox Slow-Upload (>1.2s between InitUpload and Commit) MUST deliver event without missing!
	aliceOfBob, _ := pairTwoClients(t, ctx, alice, bob, synccrypto.ModeQROOB)
	watchCtx, cancelWatch := context.WithTimeout(ctx, 10*time.Second)
	defer cancelWatch()
	gotEventCh := make(chan string, 1)
	go func() {
		_ = bob.WatchInbox(watchCtx, func(ev client.InboxWatchEvent) error {
			select {
			case gotEventCh <- ev.ItemID:
			default:
			}
			cancelWatch()
			return nil
		})
	}()
	time.Sleep(150 * time.Millisecond)

	slowPayload := bytes.Repeat([]byte("S"), 4096)
	var streamCalls atomic.Int32
	slowSendRes, err := alice.SendToDevice(ctx, aliceOfBob.DeviceID, envelope.ParcelJSON(
		"com.yellowdking.notes",
		"note.slow.v1",
		map[string]any{"slow": true},
		envelope.BlobFromReader("file", "slow.bin", "application/octet-stream", int64(len(slowPayload)), func() (io.ReadCloser, error) {
			// Delay on the 2nd open (actual chunk upload after InitUpload) so Commit happens >1.1s after InitUpload!
			if streamCalls.Add(1) == 2 {
				time.Sleep(1200 * time.Millisecond)
			}
			return io.NopCloser(bytes.NewReader(slowPayload)), nil
		}),
	), client.WithDeliveryMode(client.DeliverySpool))
	if err != nil {
		t.Fatalf("slow SendToDevice failed: %v", err)
	}

	select {
	case evItemID := <-gotEventCh:
		if evItemID != slowSendRes.ItemID {
			t.Fatalf("WatchInbox received unexpected item_id %q, want %q", evItemID, slowSendRes.ItemID)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("WatchInbox missed slow-upload committed item %s!", slowSendRes.ItemID)
	}

	// 5. Forward Compatibility (unknown v1.1 fields) + ERR_UNSUPPORTED_VERSION + Secret Auto-Redaction.
	v11JSON, _ := json.Marshal(map[string]any{
		"envelope_version": 1,
		"msg_id":           strings.Repeat("a", 32),
		"app_id":           "com.yellowdking.notes",
		"schema":           "note.item.v2",
		"created_at":       time.Now().Unix(),
		"sender":           map[string]any{"device_id": strings.Repeat("b", 32), "label": "FuturePeer", "future_badge": "pro"},
		"blobs":            []any{},
		"future_v1_1_ext":  map[string]any{"priority": "high"},
	})
	if _, err := envelope.ParseManifest(v11JSON); err != nil {
		t.Fatalf("v1.1 unknown extension field should be ignored cleanly, got: %v", err)
	}

	v2JSON, _ := json.Marshal(map[string]any{
		"envelope_version": 2,
		"msg_id":           strings.Repeat("a", 32),
		"app_id":           "com.yellowdking.notes",
		"schema":           "note.item.v1",
		"created_at":       time.Now().Unix(),
		"sender":           map[string]any{"device_id": strings.Repeat("b", 32), "label": "V2Peer"},
		"blobs":            []any{},
	})
	_, v2Err := envelope.ParseManifest(v2JSON)
	if !envelope.IsVersionMismatch(v2Err) || envelope.ExitCode(v2Err) != 2 {
		t.Fatalf("expected IsVersionMismatch (exit 2) for envelope_version=2, got err=%v exit=%d", v2Err, envelope.ExitCode(v2Err))
	}

	secretErr := envelope.NewError(envelope.ErrCodeURIInvalid, false, 0, "bad uri synctool://relay?v=1&u=https%3A%2F%2F1.2.3.4%3A443#k=SUPER_SECRET_KEY_VALUE", nil)
	if strings.Contains(secretErr.Error(), "SUPER_SECRET_KEY_VALUE") {
		t.Fatalf("SyncError leaked #k= secret: %s", secretErr.Error())
	}
}
