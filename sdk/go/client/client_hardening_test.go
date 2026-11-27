package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	synccrypto "github.com/yellowdking/synctool/sdk/go/crypto"
	"github.com/yellowdking/synctool/sdk/go/envelope"
)

func TestRedirectBlockedNeverLeaksAuthHeaders(t *testing.T) {
	var leakedHits atomic.Int32
	attacker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(synccrypto.HeaderRelaySig) != "" || r.Header.Get(synccrypto.HeaderDepositToken) != "" {
			leakedHits.Add(1)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer attacker.Close()

	// Malicious gateway issuing 307 Temporary Redirect to attacker server
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, attacker.URL+"/steal", http.StatusTemporaryRedirect)
	}))
	defer gateway.Close()

	cli, err := New(Config{
		AppID: "com.yellowdking.test",
		Relay: &envelope.RelayProfile{
			Endpoint:  gateway.URL, // http://127.0.0.1:<port> loopback allowed
			AccessKey: strings.Repeat("K", 43),
			TLSMode:   envelope.TLSModeSystemCA,
		},
		KeyStore: envelope.NewMemoryKeyStore(),
	})
	if err != nil {
		t.Fatalf("New client: %v", err)
	}
	defer cli.Close()

	_, pingErr := cli.Ping(context.Background())
	if !envelope.IsCode(pingErr, envelope.ErrCodeRelayUnreachable) || envelope.IsRetryable(pingErr) {
		t.Fatalf("expected non-retryable ERR_RELAY_UNREACHABLE on 307 redirect, got %v", pingErr)
	}
	wErr := cli.WatchInbox(context.Background(), nil)
	if !envelope.IsCode(wErr, envelope.ErrCodeRelayUnreachable) || envelope.IsRetryable(wErr) {
		t.Fatalf("expected SSE WatchInbox to block 307 redirect, got %v", wErr)
	}
	if leakedHits.Load() != 0 {
		t.Fatalf("CRITICAL: auth headers leaked to redirect target (%d hits)!", leakedHits.Load())
	}
}

func TestNanoMemorySpoolRestartSelfHealingAndSendText(t *testing.T) {
	accessKey := "TEST-KEY-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	mr, srv, pinHex := newMockRelay(t, accessKey, false, 4)

	// Make mockRelay return 404 ERR_NOT_FOUND (matching real relay spool.go:416) when mailbox is missing!
	alice := makeTestClient(t, srv.URL, pinHex, accessKey, "Alice")
	bob := makeTestClient(t, srv.URL, pinHex, accessKey, "Bob")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// 1. Pair Alice <-> Bob (records InboundTokenID + InboundTokenHash in Bob's KeyStore)
	offerCh := make(chan string, 1)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = alice.StartDeviceBind(ctx, PairOptions{
			Mode:         synccrypto.ModeQROOB,
			OnOfferReady: func(info OfferReadyInfo) { offerCh <- info.PairURI },
		})
	}()
	if _, err := bob.AcceptDeviceBind(ctx, <-offerCh, PairOptions{}); err != nil {
		t.Fatalf("Bob AcceptDeviceBind: %v", err)
	}
	wg.Wait()

	// 2. Simulate nano memory-spool relay restart: wipe ALL relay-side mailboxes & deposit tokens!
	mr.mu.Lock()
	mr.mailboxes = make(map[string]*mockMailbox)
	mr.return404OnMissingMailbox = true
	mr.mu.Unlock()

	// 3. Bob calls ListInbox -> receives 404 ERR_NOT_FOUND -> SDK self-heals mailbox + Alice's deposit_token transparently!
	items, err := bob.ListInbox(ctx, "")
	if err != nil || len(items) != 0 {
		t.Fatalf("expected seamless ListInbox self-healing after relay memory wipe, got items=%v err=%v", items, err)
	}

	// 4. Alice immediately sends text using SendText("Bob", ...) WITHOUT re-pairing -> succeeds!
	sendRes, err := alice.SendText(ctx, "Bob", "self-healed after nano restart!")
	if err != nil {
		t.Fatalf("expected Alice SendText to succeed after Bob self-healed mailbox, got %v", err)
	}

	// 5. Bob pulls and verifies the text parcel
	var gotText string
	if _, err := bob.FetchParcel(ctx, sendRes.ItemID, func(p envelope.ReceivedParcel) error {
		gotText, _ = p.Manifest.InlinePayload["text"].(string)
		return nil
	}, ReceiveOptions{}); err != nil || gotText != "self-healed after nano restart!" {
		t.Fatalf("Bob FetchParcel failed: err=%v text=%q", err, gotText)
	}
}

func TestPart0OOMGuardAndTempDirCleanupOnClose(t *testing.T) {
	accessKey := "TEST-KEY-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	_, srv, pinHex := newMockRelay(t, accessKey, false, 4)
	cli := makeTestClient(t, srv.URL, pinHex, accessKey, "GuardTest")

	// Oversized part_id=0 layout MUST be rejected BEFORE calling fetchChunk!
	fetchCount := 0
	_, _, err := cli.pullAndVerifyManifest(
		[16]byte{}, strings.Repeat("a", 32), [32]byte{}, [7]byte{},
		envelope.PartLayout{PartID: 0, TotalBytes: 500_000, ChunkCount: 50},
		nil,
		func(txIdx int) ([]byte, error) {
			fetchCount++
			return nil, nil
		},
	)
	if !envelope.IsCode(err, envelope.ErrCodeManifestInvalid) || fetchCount != 0 {
		t.Fatalf("expected immediate ERR_MANIFEST_INVALID with 0 chunk fetches, got err=%v fetches=%d", err, fetchCount)
	}

	// Verify Client.Close() cleans up verified parcel temp dirs while keeping them readable before Close()
	ksDir := t.TempDir()
	ks, err := envelope.NewFileKeyStore(ksDir)
	if err != nil {
		t.Fatal(err)
	}
	sender := makeTestClient(t, srv.URL, pinHex, accessKey, "Sender")
	receiver, err := New(Config{
		AppID:       "com.yellowdking.notes",
		DeviceLabel: "Receiver",
		Relay: &envelope.RelayProfile{
			Endpoint:   srv.URL,
			AccessKey:  accessKey,
			TLSMode:    envelope.TLSModeSPKIPin,
			SPKISHA256: pinHex,
		},
		KeyStore: ks,
	})
	if err != nil {
		t.Fatal(err)
	}

	blobSrc := filepath.Join(t.TempDir(), "hello.bin")
	_ = os.WriteFile(blobSrc, []byte("hello atomic verified"), 0o600)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	uriCh := make(chan string, 1)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = sender.StartOneShotSend(ctx, envelope.ParcelJSON(
			"com.yellowdking.notes", "note.v1", map[string]any{"ok": true},
			envelope.BlobFromFile("file", blobSrc),
		), PairOptions{
			Mode:         synccrypto.ModeQROOB,
			OnOfferReady: func(info OfferReadyInfo) { uriCh <- info.PairURI },
		})
	}()

	var verifiedPath string
	if _, err := receiver.ReceiveFromRoom(ctx, <-uriCh, func(p envelope.ReceivedParcel) error {
		verifiedPath = p.Blobs[0].SafePath
		return nil
	}, ReceiveOptions{}); err != nil {
		t.Fatalf("ReceiveFromRoom: %v", err)
	}
	wg.Wait()

	if !strings.HasSuffix(verifiedPath, ".verified") {
		t.Fatalf("expected atomic .verified suffix, got %q", verifiedPath)
	}
	if _, err := os.Stat(verifiedPath); err != nil {
		t.Fatalf("expected SafePath readable until Client.Close(): %v", err)
	}
	receiver.Close()
	if _, err := os.Stat(filepath.Dir(verifiedPath)); !os.IsNotExist(err) {
		t.Fatalf("expected msgDir cleaned up upon Client.Close(), stat err=%v", err)
	}
}
