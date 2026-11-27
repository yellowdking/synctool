package client

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	synccrypto "github.com/yellowdking/synctool/sdk/go/crypto"
	"github.com/yellowdking/synctool/sdk/go/envelope"
)

func makeTestClient(t *testing.T, srvURL, pinHex, accessKey, label string) *Client {
	t.Helper()
	ks := envelope.NewMemoryKeyStore()
	prof := &envelope.RelayProfile{
		Endpoint:   srvURL,
		AccessKey:  accessKey,
		TLSMode:    envelope.TLSModeSPKIPin,
		SPKISHA256: pinHex,
	}
	cli, err := New(Config{
		AppID:       "com.yellowdking.notes",
		DeviceLabel: label,
		Relay:       prof,
		KeyStore:    ks,
		TempDir:     t.TempDir(),
	})
	if err != nil {
		t.Fatalf("New client: %v", err)
	}
	t.Cleanup(cli.Close)
	return cli
}

func TestSPKIPinAndClockSkewRetry(t *testing.T) {
	accessKey := "TEST-KEY-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	mr, srv, pinHex := newMockRelay(t, accessKey, false, 4)

	// Wrong SPKI pin MUST fail with ERR_TLS_PIN_MISMATCH
	badPin := strings.Repeat("0", 64)
	if badPin == pinHex {
		badPin = strings.Repeat("1", 64)
	}
	badCli := makeTestClient(t, srv.URL, badPin, accessKey, "BadPin")
	if _, err := badCli.Ping(context.Background()); !envelope.IsCode(err, envelope.ErrCodeTLSPinMismatch) {
		t.Fatalf("expected ERR_TLS_PIN_MISMATCH, got %v", err)
	}

	// Wrong AccessKey MUST map silent 404 to ERR_AUTH_FAILED
	wrongKeyCli := makeTestClient(t, srv.URL, pinHex, "WRONG-KEY-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ", "WrongKey")
	if _, err := wrongKeyCli.Ping(context.Background()); !envelope.IsCode(err, envelope.ErrCodeAuthFailed) {
		t.Fatalf("expected ERR_AUTH_FAILED on silent 404, got %v", err)
	}

	// Clock skew > 60s MUST auto-calibrate via 409 ERR_CLOCK_SKEW and succeed on retry
	mr.clockShift = 300
	cli := makeTestClient(t, srv.URL, pinHex, accessKey, "Skewed")
	res, err := cli.Ping(context.Background())
	if err != nil {
		t.Fatalf("expected auto clock skew recovery, got %v", err)
	}
	if res.Profile != "nano" || cli.ClockOffsetSec() < 250 {
		t.Fatalf("unexpected ping result or offset: %+v offset=%d", res, cli.ClockOffsetSec())
	}
}

func TestFullFlowPairingSpoolResumeRevoke(t *testing.T) {
	accessKey := "TEST-KEY-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	mr, srv, pinHex := newMockRelay(t, accessKey, false, 4) // nano 4-block chunks (262,208 B)

	alice := makeTestClient(t, srv.URL, pinHex, accessKey, "Alice Laptop")
	bob := makeTestClient(t, srv.URL, pinHex, accessKey, "Bob Phone")
	carol := makeTestClient(t, srv.URL, pinHex, accessKey, "Carol Tablet")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// 1. Pair Alice <-> Bob via Flow 1A (QR OOB)
	offerCh := make(chan string, 1)
	var bobCardFromAlice *envelope.DeviceCard
	var wg sync.WaitGroup
	wg.Add(1)
	var alicePairErr error
	go func() {
		defer wg.Done()
		bobCardFromAlice, alicePairErr = alice.StartDeviceBind(ctx, PairOptions{
			Mode: synccrypto.ModeQROOB,
			OnOfferReady: func(info OfferReadyInfo) {
				offerCh <- info.PairURI
			},
		})
	}()
	uri := <-offerCh
	aliceCardFromBob, err := bob.AcceptDeviceBind(ctx, uri, PairOptions{})
	if err != nil {
		t.Fatalf("Bob AcceptDeviceBind: %v", err)
	}
	wg.Wait()
	if alicePairErr != nil {
		t.Fatalf("Alice StartDeviceBind: %v", alicePairErr)
	}
	if bobCardFromAlice.Label != "Bob Phone" || aliceCardFromBob.Label != "Alice Laptop" {
		t.Fatalf("unexpected paired labels: %+v / %+v", bobCardFromAlice, aliceCardFromBob)
	}

	// 2. Pair Alice <-> Carol via Flow 1B (Commit-Reveal SAS)
	sasOfferCh := make(chan string, 1)
	sasDispCh := make(chan string, 1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, alicePairErr = alice.StartDeviceBind(ctx, PairOptions{
			Mode: synccrypto.ModeCommitSAS,
			OnOfferReady: func(info OfferReadyInfo) {
				sasOfferCh <- info.DisplayCode
			},
			OnSASInput: func() (string, error) {
				return <-sasDispCh, nil
			},
		})
	}()
	code := <-sasOfferCh
	if _, err := carol.AcceptDeviceBind(ctx, code, PairOptions{
		OnSASDisplay: func(s string) { sasDispCh <- s },
	}); err != nil {
		t.Fatalf("Carol AcceptDeviceBind (SAS): %v", err)
	}
	wg.Wait()
	if alicePairErr != nil {
		t.Fatalf("Alice StartDeviceBind (SAS): %v", alicePairErr)
	}

	// 3. Bob sends multi-chunk binary attachment (600 KB -> 10 blocks -> 3 nano chunks) to Alice via Mode B
	bigFile := filepath.Join(t.TempDir(), "clip.bin")
	bigData := make([]byte, 600*1024+123)
	for i := range bigData {
		bigData[i] = byte((i*17 + 3) & 0xff)
	}
	if err := os.WriteFile(bigFile, bigData, 0o600); err != nil {
		t.Fatal(err)
	}
	sendRes, err := bob.SendToDevice(ctx, aliceCardFromBob.DeviceID, envelope.ParcelInput{
		Schema:        "note.item.v1",
		InlinePayload: map[string]any{"title": "Multi-chunk test"},
		Blobs:         []envelope.BlobInput{{Role: "video", Name: "clip.bin", MIME: "application/octet-stream", FilePath: bigFile}},
	}, SendOptions{DeliveryMode: "auto"})
	if err != nil {
		t.Fatalf("Bob SendToDevice: %v", err)
	}

	// 4. Alice calls ListInbox TWICE -> verify Manifest cached locally (part_id=0 downloaded only ONCE!)
	p1, err := alice.ListInbox(ctx, "")
	if err != nil || len(p1) != 1 || p1[0].Cached {
		t.Fatalf("first ListInbox unexpected: %+v err=%v", p1, err)
	}
	p2, err := alice.ListInbox(ctx, "")
	if err != nil || len(p2) != 1 || !p2[0].Cached {
		t.Fatalf("second ListInbox should hit cache: %+v err=%v", p2, err)
	}
	if mr.part0Gets[sendRes.ItemID] != 1 {
		t.Fatalf("expected part_id=0 GET count=1 due to cache, got %d", mr.part0Gets[sendRes.ItemID])
	}

	// 5. Simulate mid-download drop on chunk 1, then verify resumable FetchParcel succeeds & burns relay item
	mr.mu.Lock()
	mr.failChunkAt[sendRes.ItemID+":1:1"] = 1
	mr.mu.Unlock()
	if _, err := alice.FetchParcel(ctx, sendRes.ItemID, nil, ReceiveOptions{}); !envelope.IsCode(err, envelope.ErrCodeInterruptedResumable) {
		t.Fatalf("expected ERR_INTERRUPTED_RESUMABLE on simulated chunk 1 drop, got %v", err)
	}

	var receivedBytes []byte
	if _, err := alice.FetchParcel(ctx, sendRes.ItemID, func(p envelope.ReceivedParcel) error {
		b, err := os.ReadFile(p.Blobs[0].SafePath)
		if err != nil {
			return err
		}
		receivedBytes = b
		return nil
	}, ReceiveOptions{}); err != nil {
		t.Fatalf("resumed FetchParcel failed: %v", err)
	}
	if !bytes.Equal(receivedBytes, bigData) {
		t.Fatal("resumed blob plaintext does not match original")
	}
	// Verify item physically burned on relay
	afterList, _ := alice.ListInbox(ctx, "")
	if len(afterList) != 0 {
		t.Fatalf("expected item burned after signed ACK, still found %d", len(afterList))
	}

	// 6. Single-device revocation: Alice revokes Bob -> Bob rejected, Carol STILL works!
	if err := alice.RevokeDevice(ctx, bobCardFromAlice.DeviceID); err != nil {
		t.Fatalf("Alice RevokeDevice(Bob): %v", err)
	}
	if _, err := bob.SendToDevice(ctx, aliceCardFromBob.DeviceID, envelope.ParcelInput{
		Schema:        "note.item.v1",
		InlinePayload: map[string]any{"text": "should fail"},
	}, SendOptions{DeliveryMode: "spool"}); !envelope.IsCode(err, envelope.ErrCodeUnauthorizedToken) {
		t.Fatalf("expected revoked Bob to fail with ERR_UNAUTHORIZED_TOKEN, got %v", err)
	}
	// Carol still succeeds!
	if _, err := carol.SendToDevice(ctx, aliceCardFromBob.DeviceID, envelope.ParcelInput{
		Schema:        "note.item.v1",
		InlinePayload: map[string]any{"text": "carol still trusted"},
	}, SendOptions{DeliveryMode: "spool"}); err != nil {
		t.Fatalf("expected non-revoked Carol to still succeed, got %v", err)
	}
}

func TestSpoolOffPairingAndDirectModeA(t *testing.T) {
	accessKey := "TEST-KEY-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	_, srv, pinHex := newMockRelay(t, accessKey, true, 4) // --spool=off

	alice := makeTestClient(t, srv.URL, pinHex, accessKey, "Alice")
	bob := makeTestClient(t, srv.URL, pinHex, accessKey, "Bob")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// 1. Pair under --spool=off (PairBindPayload.mailbox == nil)
	uriCh := make(chan string, 1)
	var wg sync.WaitGroup
	var aErr error
	var bobCard *envelope.DeviceCard
	wg.Add(1)
	go func() {
		defer wg.Done()
		bobCard, aErr = alice.StartDeviceBind(ctx, PairOptions{
			Mode:         synccrypto.ModeQROOB,
			OnOfferReady: func(info OfferReadyInfo) { uriCh <- info.PairURI },
		})
	}()
	if _, err := bob.AcceptDeviceBind(ctx, <-uriCh, PairOptions{}); err != nil {
		t.Fatalf("Bob pair under --spool=off: %v", err)
	}
	wg.Wait()
	if aErr != nil {
		t.Fatalf("Alice pair under --spool=off: %v", aErr)
	}
	if bobCard.MailboxID != "" {
		t.Fatalf("expected empty mailbox_id under --spool=off, got %q", bobCard.MailboxID)
	}

	// 2. Mode auto returns ERR_SPOOL_DISABLED
	if _, err := alice.SendToDevice(ctx, bobCard.DeviceID, envelope.ParcelInput{
		InlinePayload: map[string]any{"msg": "hi"},
	}, SendOptions{DeliveryMode: "auto"}); !envelope.IsCode(err, envelope.ErrCodeSpoolDisabled) {
		t.Fatalf("expected ERR_SPOOL_DISABLED, got %v", err)
	}

	// 3. Flow 2 Mode A Direct streaming (m=0&p=direct + direct_ack HMAC) succeeds!
	directURICh := make(chan string, 1)
	wg.Add(1)
	var sendErr error
	go func() {
		defer wg.Done()
		_, sendErr = alice.SendToDevice(ctx, bobCard.DeviceID, envelope.ParcelInput{
			Schema:        "note.item.v1",
			InlinePayload: map[string]any{"direct": "zero-disk-ok"},
		}, SendOptions{
			DeliveryMode: "pipe",
			OnOfferReady: func(info OfferReadyInfo) { directURICh <- info.PairURI },
		})
	}()
	var gotText string
	if _, err := bob.ReceiveDirect(ctx, <-directURICh, func(p envelope.ReceivedParcel) error {
		gotText, _ = p.Manifest.InlinePayload["direct"].(string)
		return nil
	}, ReceiveOptions{}); err != nil {
		t.Fatalf("Bob ReceiveDirect: %v", err)
	}
	wg.Wait()
	if sendErr != nil || gotText != "zero-disk-ok" {
		t.Fatalf("direct transfer failed sendErr=%v gotText=%q", sendErr, gotText)
	}

	// 4. Flow 1 One-Shot Mode A streaming (QR OOB) also works seamlessly
	oneshotCh := make(chan string, 1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, sendErr = alice.StartOneShotSend(ctx, envelope.ParcelInput{
			Schema:        "vault.snapshot.v1",
			InlinePayload: map[string]any{"ssh": "migrated"},
		}, PairOptions{
			Mode:         synccrypto.ModeQROOB,
			OnOfferReady: func(info OfferReadyInfo) { oneshotCh <- info.PairURI },
		})
	}()
	var gotSSH string
	if _, err := bob.ReceiveOneShot(ctx, <-oneshotCh, func(p envelope.ReceivedParcel) error {
		gotSSH, _ = p.Manifest.InlinePayload["ssh"].(string)
		return nil
	}, ReceiveOptions{}); err != nil {
		t.Fatalf("Bob ReceiveOneShot: %v", err)
	}
	wg.Wait()
	if sendErr != nil || gotSSH != "migrated" {
		t.Fatalf("oneshot transfer failed sendErr=%v gotSSH=%q", sendErr, gotSSH)
	}
}
