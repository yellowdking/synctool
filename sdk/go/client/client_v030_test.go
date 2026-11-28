package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"math"
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

func pairTestClientsQR(t *testing.T, ctx context.Context, alice, bob *Client) (*envelope.DeviceCard, *envelope.DeviceCard) {
	t.Helper()
	uriCh := make(chan string, 1)
	var wg sync.WaitGroup
	var cardB *envelope.DeviceCard
	var errA error
	wg.Add(1)
	go func() {
		defer wg.Done()
		cardB, errA = alice.StartDeviceBind(ctx, PairOptions{
			Mode:         synccrypto.ModeQROOB,
			OnOfferReady: func(info OfferReadyInfo) { uriCh <- info.PairURI },
		})
	}()
	cardA, errB := bob.AcceptDeviceBind(ctx, <-uriCh, PairOptions{})
	wg.Wait()
	if errA != nil || errB != nil {
		t.Fatalf("pairTestClientsQR failed: errA=%v errB=%v", errA, errB)
	}
	return cardB, cardA
}

func TestV030_P0_1_ResponderOnSASConfirmMandatoryGate(t *testing.T) {
	accessKey := "TEST-KEY-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	mr, srv, pinHex := newMockRelay(t, accessKey, false, 4)
	alice := makeTestClient(t, srv.URL, pinHex, accessKey, "Alice")
	bob := makeTestClient(t, srv.URL, pinHex, accessKey, "Bob")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 1. Responder AcceptDeviceBind in mode=2 with nil OnSASConfirm MUST fail closed with ERR_SAS_MISMATCH
	// and burn room BEFORE registering deposit_token or saving DeviceCard!
	codeCh := make(chan string, 1)
	var wg sync.WaitGroup
	var errA error
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, errA = alice.StartDeviceBind(ctx, PairOptions{
			Mode:         synccrypto.ModeCommitSAS,
			OnOfferReady: func(info OfferReadyInfo) { codeCh <- info.DisplayCode },
			OnSASInput:   func() (string, error) { return "000000", nil },
		})
	}()
	_, errB := bob.AcceptDeviceBind(ctx, <-codeCh, PairOptions{})
	wg.Wait()
	if !envelope.IsCode(errB, envelope.ErrCodeSASMismatch) {
		t.Fatalf("expected ERR_SAS_MISMATCH when OnSASConfirm is nil, got %v", errB)
	}
	if !envelope.IsCode(errA, envelope.ErrCodeRoomBurned) {
		t.Fatalf("expected initiator ERR_ROOM_BURNED, got %v", errA)
	}
	if devs, _ := bob.KeyStoreHint().ListDevices(); len(devs) != 0 {
		t.Fatalf("DeviceCard saved despite nil OnSASConfirm: %+v", devs)
	}
	mr.mu.Lock()
	mbCount := len(mr.mailboxes)
	mr.mu.Unlock()
	if mbCount != 0 {
		t.Fatalf("expected 0 mailbox registrations when OnSASConfirm is nil, got %d", mbCount)
	}

	// 2. Responder ReceiveOneShot in mode=2 where OnSASDisplay fires and OnSASConfirm rejects:
	// ParcelHandler MUST NEVER be called!
	codeCh2 := make(chan string, 1)
	sasCh := make(chan string, 1)
	handlerCalled := false
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = alice.StartOneShotSend(ctx, envelope.ParcelText("com.yellowdking.notes", "mitm-payload"), PairOptions{
			Mode:         synccrypto.ModeCommitSAS,
			OnOfferReady: func(info OfferReadyInfo) { codeCh2 <- info.DisplayCode },
			OnSASInput:   func() (string, error) { return <-sasCh, nil },
		})
	}()
	_, recvErr := bob.ReceiveOneShot(ctx, <-codeCh2, func(p envelope.ReceivedParcel) error {
		handlerCalled = true
		return nil
	}, ReceiveOptions{
		OnSASDisplay: func(sas string) { sasCh <- sas },
		OnSASConfirm: func(sas string) error { return errors.New("rejected") },
	})
	wg.Wait()
	if !envelope.IsCode(recvErr, envelope.ErrCodeSASMismatch) || handlerCalled {
		t.Fatalf("expected ERR_SAS_MISMATCH and handlerCalled=false, got err=%v called=%v", recvErr, handlerCalled)
	}
}

func TestV030_P0_2_PartLayoutValidationAndSawFinalHardStop(t *testing.T) {
	accessKey := "TEST-KEY-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	_, srv, pinHex := newMockRelay(t, accessKey, false, 4)
	cli := makeTestClient(t, srv.URL, pinHex, accessKey, "StreamGuard")
	ctx := context.Background()

	var bk [32]byte
	copy(bk[:], bytes.Repeat([]byte{0x44}, 32))
	var msgID [16]byte
	copy(msgID[:], bytes.Repeat([]byte{0x55}, 16))
	msgHex := hex.EncodeToString(msgID[:])

	manifest := &envelope.Manifest{
		EnvelopeVersion: 1,
		MsgID:           msgHex,
		AppID:           "com.yellowdking.notes",
		Schema:          "note.v1",
		CreatedAt:       time.Now().Unix(),
		Sender:          envelope.SenderInfo{DeviceID: strings.Repeat("a", 32), Label: "Peer"},
		Blobs: []envelope.BlobDescriptor{{
			PartID: 1,
			Role:   "file",
			Name:   "tiny.bin",
			MIME:   "application/octet-stream",
			Size:   1, // EncryptedPartSize(1) == 17B, TotalBlocks == 1
			SHA256: hex.EncodeToString(func() []byte { s := sha256.Sum256([]byte("x")); return s[:] }()),
			Key:    base64.RawURLEncoding.EncodeToString(bk[:]),
		}},
	}

	// 1. Inflated TotalBytes or ChunkCount MUST fail BEFORE calling fetchChunk!
	fetches := 0
	var done int64
	_, err := cli.pullAndVerifyBlobs(ctx, "itm_bad", msgID, manifest, map[uint32]envelope.PartLayout{
		0: {PartID: 0, TotalBytes: 4112, ChunkCount: 1},
		1: {PartID: 1, TotalBytes: 65552 * 100, ChunkCount: 25},
	}, 4, 65552*100+4112, &done, "spool", func(partID uint32, txIdx int) ([]byte, error) {
		fetches++
		return nil, nil
	}, nil)
	if !envelope.IsCode(err, envelope.ErrCodeManifestInvalid) || fetches != 0 {
		t.Fatalf("expected immediate ERR_MANIFEST_INVALID with 0 fetches, got err=%v fetches=%d", err, fetches)
	}

	// 2. Trailing bytes appended after authenticated is_final=0x01 block MUST fail immediately with ErrIntegrityMismatch!
	encKey, np, _ := synccrypto.DeriveBlobPartKeys(msgID, 1, bk[:])
	sc, _ := synccrypto.NewStreamCipher(encKey, np, msgID, 1)
	finalCT, _ := sc.SealBlockAt(0, true, []byte("x"), nil)
	trailingCT := append(append([]byte(nil), finalCT...), bytes.Repeat([]byte{0xaa}, 17)...)
	var sink bytes.Buffer
	_, _, _, decErr := decryptChunkIntoStream(sc, trailingCT, 0, 1, 1, true, &sink)
	if !envelope.IsCode(decErr, envelope.ErrCodeCryptoDecryptFailed) || !errors.Is(decErr, synccrypto.ErrIntegrityMismatch) {
		t.Fatalf("expected ErrIntegrityMismatch on trailing bytes after final block, got %v", decErr)
	}
	if sink.Len() != 0 {
		t.Fatalf("expected 0 plaintext bytes written when trailing bytes detected, got %d", sink.Len())
	}

	// 3. Premature is_final on tx=0 when relay inflated ChunkCount=2 (on a 2-block blob) MUST NOT request tx=1 or return ERR_INTERRUPTED_RESUMABLE!
	twoBlkPlain := bytes.Repeat([]byte("A"), synccrypto.ChunkPlaintextMax+5)
	twoSum := sha256.Sum256(twoBlkPlain)
	manifest2 := *manifest
	manifest2.Blobs = []envelope.BlobDescriptor{{
		PartID: 1,
		Role:   "file",
		Name:   "two.bin",
		MIME:   "application/octet-stream",
		Size:   int64(len(twoBlkPlain)),
		SHA256: hex.EncodeToString(twoSum[:]),
		Key:    base64.RawURLEncoding.EncodeToString(bk[:]),
	}}
	b0, _ := sc.SealBlockAt(0, false, twoBlkPlain[:synccrypto.ChunkPlaintextMax], nil)
	b1, _ := sc.SealBlockAt(1, true, twoBlkPlain[synccrypto.ChunkPlaintextMax:], nil)
	fullChunk0 := append(b0, b1...)
	txCalls := 0
	done = 0
	_, premErr := cli.pullAndVerifyBlobs(ctx, "itm_prem", msgID, &manifest2, map[uint32]envelope.PartLayout{
		0: {PartID: 0, TotalBytes: 4112, ChunkCount: 1},
		1: {PartID: 1, TotalBytes: int64(len(fullChunk0)), ChunkCount: 2}, // Relay inflated ChunkCount 1 -> 2!
	}, 0, int64(len(fullChunk0))+4112, &done, "spool", func(partID uint32, txIdx int) ([]byte, error) {
		txCalls++
		if txIdx == 0 {
			return fullChunk0, nil
		}
		return nil, envelope.NewError(envelope.ErrCodeNotFound, false, 404, "missing chunk 1", nil)
	}, nil)
	if !envelope.IsCode(premErr, envelope.ErrCodeCryptoDecryptFailed) || envelope.IsRetryable(premErr) || txCalls != 1 {
		t.Fatalf("expected immediate non-retryable ERR_CRYPTO_DECRYPT_FAILED after tx=0 (txCalls=1), got err=%v txCalls=%d", premErr, txCalls)
	}
}

func TestV030_P0_3_ListInboxVerifiesSealedHeaderAndRevocationBeforeCache(t *testing.T) {
	accessKey := "TEST-KEY-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	_, srv, pinHex := newMockRelay(t, accessKey, false, 4)
	alice := makeTestClient(t, srv.URL, pinHex, accessKey, "Alice")
	bob := makeTestClient(t, srv.URL, pinHex, accessKey, "Bob")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	aliceOfBob, bobOfAlice := pairTestClientsQR(t, ctx, alice, bob)
	sendRes, err := alice.SendToDevice(ctx, aliceOfBob.DeviceID, envelope.ParcelText("com.yellowdking.notes", "cached-before-revoke"), SendOptions{})
	if err != nil {
		t.Fatal(err)
	}

	// Populate Bob's local ManifestCache via ListInbox.
	list1, err := bob.ListInbox(ctx, "")
	if err != nil || len(list1) != 1 {
		t.Fatalf("expected 1 item in ListInbox, got %+v err=%v", list1, err)
	}
	if cached, _ := bob.KeyStoreHint().GetCachedManifest(sendRes.ItemID); cached == nil {
		t.Fatal("expected item cached after first ListInbox")
	}

	// Bob revokes Alice -> subsequent ListInbox MUST reject SealedHeader (revoked sender) and evict cache!
	if err := bob.RevokeDevice(ctx, bobOfAlice.DeviceID); err != nil {
		t.Fatal(err)
	}
	listAfterRevoke, err := bob.ListInbox(ctx, "")
	if err != nil || len(listAfterRevoke) != 0 {
		t.Fatalf("CRITICAL P0-3 regression: ListInbox returned revoked sender's cached parcel: %+v err=%v", listAfterRevoke, err)
	}
	if cached, _ := bob.KeyStoreHint().GetCachedManifest(sendRes.ItemID); cached != nil {
		t.Fatal("expected revoked sender's cached manifest to be evicted")
	}
}

func TestV030_P1_1_6_7_MultiPin_ClockSkewScope_Freshness_And_InFlight(t *testing.T) {
	accessKey := "TEST-KEY-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	mr, srv, pinHex := newMockRelay(t, accessKey, false, 4)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 1. Multi-pin TLS: [wrongPin, realPin] succeeds; bare IP without pin rejected by New()!
	wrongPin := strings.Repeat("0", 64)
	if wrongPin == pinHex {
		wrongPin = strings.Repeat("1", 64)
	}
	multiCli, err := New(Config{
		Relay: &envelope.RelayProfile{
			Endpoint:  srv.URL,
			AccessKey: accessKey,
			TLSMode:   envelope.TLSModeSPKIPin,
			SPKIPins:  []string{wrongPin, pinHex},
		},
		KeyStore: envelope.NewMemoryKeyStore(),
	})
	if err != nil {
		t.Fatalf("New multi-pin client: %v", err)
	}
	defer multiCli.Close()
	if _, err := multiCli.Ping(ctx); err != nil {
		t.Fatalf("multi-pin Ping failed when 2nd pin matched leaf cert: %v", err)
	}

	// Bare IP with system_ca MUST be rejected programmatically in client.New!
	if _, err := New(Config{
		Relay: &envelope.RelayProfile{
			Endpoint:  srv.URL,
			AccessKey: accessKey,
			TLSMode:   envelope.TLSModeSystemCA,
		},
		KeyStore: envelope.NewMemoryKeyStore(),
	}); !envelope.IsCode(err, envelope.ErrCodeURIInvalid) {
		t.Fatalf("expected bare IP without SPKI pin to fail in client.New, got %v", err)
	}

	// 2. ST-P1-6: Clock skew calibration only affects X-Sync-TS, NEVER signed Manifest.CreatedAt or DeviceCard.IssuedAt!
	mr.mu.Lock()
	mr.clockShift = 300
	mr.mu.Unlock()
	skewCli := makeTestClient(t, srv.URL, pinHex, accessKey, "SkewCheck")
	if _, err := skewCli.Ping(ctx); err != nil {
		t.Fatalf("Ping skew calibration: %v", err)
	}
	localNow := time.Now().Unix()
	prep, err := skewCli.prepareParcel(envelope.ParcelText("com.yellowdking.notes", "ts-check"), 4)
	if err != nil {
		t.Fatal(err)
	}
	defer prep.Zero()
	if math.Abs(float64(prep.CreatedAt-localNow)) > 5 {
		t.Fatalf("ST-P1-6 regression: relay clockOffsetSec (%d) tainted signed Manifest.CreatedAt (%d vs local %d)", skewCli.ClockOffsetSec(), prep.CreatedAt, localNow)
	}
	// Extreme >365d skew or float64 overflow in calibrateClockFromSkewErr MUST be rejected!
	prevOff := skewCli.ClockOffsetSec()
	if skewCli.calibrateClockFromSkewErr(envelope.NewError(envelope.ErrCodeClockSkew, true, 409, "bad", map[string]any{"server_ts": float64(1e30)})) {
		t.Fatal("expected float64 overflow server_ts to be rejected")
	}
	if skewCli.calibrateClockFromSkewErr(envelope.NewError(envelope.ErrCodeClockSkew, true, 409, "bad", map[string]any{"server_unix": localNow + 400*86400})) {
		t.Fatal("expected >365d server_unix skew to be rejected")
	}
	if skewCli.ClockOffsetSec() != prevOff {
		t.Fatal("clockOffsetSec was mutated by rejected extreme skew")
	}
	mr.mu.Lock()
	mr.clockShift = 0
	mr.mu.Unlock()

	// 3. ST-P1-7: SealedHeader.CreatedAt freshness window & concurrent inFlightMsgIDs guard!
	alice := makeTestClient(t, srv.URL, pinHex, accessKey, "Alice")
	bob := makeTestClient(t, srv.URL, pinHex, accessKey, "Bob")
	aliceOfBob, _ := pairTestClientsQR(t, ctx, alice, bob)

	// Forge a valid Ed25519-signed SealedHeader from Alice with CreatedAt = now - 31 days (stale) and now + 900s (future).
	var recipRaw [16]byte
	rb, _ := hex.DecodeString(aliceOfBob.DeviceID)
	copy(recipRaw[:], rb)
	kemPK, _ := base64.RawURLEncoding.DecodeString(aliceOfBob.KEMPK)
	for _, badTS := range []int64{localNow - 31*86400, localNow + 900} {
		hdr, _, p0k, p0n, err := synccrypto.Seal0RTTHeader(alice.deviceKeys, recipRaw, kemPK, badTS, [32]byte{})
		clear(p0k[:])
		clear(p0n[:])
		if err != nil {
			t.Fatal(err)
		}
		if _, err := bob.openAndVerifySealedHeader(hdr[:]); !envelope.IsCode(err, envelope.ErrCodeMsgReplayDetected) {
			t.Fatalf("expected bad SealedHeader.CreatedAt=%d to fail with ERR_MSG_REPLAY_DETECTED, got %v", badTS, err)
		}
	}

	// Concurrent FetchParcel TOCTOU test: clone committed spool item under a second item_id with the SAME SealedHeader/msg_id!
	resOrig, err := alice.SendToDevice(ctx, aliceOfBob.DeviceID, envelope.ParcelText("com.yellowdking.notes", "once-only"), SendOptions{})
	if err != nil {
		t.Fatal(err)
	}
	mr.mu.Lock()
	origItem := mr.items[resOrig.ItemID]
	dupChunks := make(map[string][]byte, len(origItem.chunks))
	for k, v := range origItem.chunks {
		dupChunks[k] = v
	}
	dupItemID := "itm_dup_concurrent"
	mr.items[dupItemID] = &mockSpoolItem{
		itemID:        dupItemID,
		mailboxID:     origItem.mailboxID,
		uploadToken:   "up_dup",
		sealedHeader:  origItem.sealedHeader,
		declaredBytes: origItem.declaredBytes,
		parts:         origItem.parts,
		chunks:        dupChunks,
		committed:     true,
		createdAt:     origItem.createdAt,
		expiresAt:     origItem.expiresAt,
	}
	mr.mu.Unlock()

	var handlerCount atomic.Int32
	enterBarrier := make(chan struct{})
	releaseBarrier := make(chan struct{})
	var wg sync.WaitGroup
	errs := make([]error, 2)
	ids := []string{resOrig.ItemID, dupItemID}
	for idx := 0; idx < 2; idx++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = bob.FetchParcel(ctx, ids[i], func(p envelope.ReceivedParcel) error {
				if handlerCount.Add(1) == 1 {
					close(enterBarrier)
				}
				<-releaseBarrier
				return nil
			}, ReceiveOptions{})
		}(idx)
	}
	<-enterBarrier
	time.Sleep(50 * time.Millisecond)
	close(releaseBarrier)
	wg.Wait()
	if handlerCount.Load() != 1 {
		t.Fatalf("CRITICAL ST-P1-7 TOCTOU: ParcelHandler invoked %d times for same msg_id (errs=%v)!", handlerCount.Load(), errs)
	}
	if !envelope.IsCode(errs[0], envelope.ErrCodeMsgReplayDetected) && !envelope.IsCode(errs[1], envelope.ErrCodeMsgReplayDetected) {
		t.Fatalf("expected duplicate concurrent FetchParcel to fail with ERR_MSG_REPLAY_DETECTED, got %v", errs)
	}
}

func TestV030_P1_8_9_10_13_RePair_TwoPhaseRevoke_WatchIdle_AbortedSpool_SkipVerified_And_AppFilter(t *testing.T) {
	accessKey := "TEST-KEY-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	mr, srv, pinHex := newMockRelay(t, accessKey, false, 4)
	alice := makeTestClient(t, srv.URL, pinHex, accessKey, "Alice")
	bob := makeTestClient(t, srv.URL, pinHex, accessKey, "Bob")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	_, _, _, _, bobMboxID := bob.Identity()

	// 1. ST-P1-8: Re-pairing Alice <-> Bob MUST delete superseded deposit_token on relay!
	pairTestClientsQR(t, ctx, alice, bob)
	aliceOfBob2, bobOfAlice2 := pairTestClientsQR(t, ctx, alice, bob)
	mr.mu.Lock()
	activeBobTokens := len(mr.mailboxes[bobMboxID].tokens)
	mr.mu.Unlock()
	if activeBobTokens != 1 {
		t.Fatalf("ST-P1-8 regression: expected 1 active deposit token after re-pair, got %d", activeBobTokens)
	}

	// 2. ST-P1-10 & ST-P1-13: Aborted Mode B upload cleans up uncommitted spool item & writes 0 "send" checkpoints!
	goodPath := filepath.Join(t.TempDir(), "good.bin")
	_ = os.WriteFile(goodPath, bytes.Repeat([]byte("G"), 1024), 0o600)
	var openCount atomic.Int32
	_, abortErr := alice.SendToDevice(ctx, aliceOfBob2.DeviceID, envelope.ParcelInput{
		AppID:  "com.yellowdking.notes",
		Schema: "note.v1",
		Blobs: []envelope.BlobInput{
			envelope.BlobFromFile("file", goodPath),
			envelope.BlobFromReader("file", "fail.bin", "application/octet-stream", 1024, func() (io.ReadCloser, error) {
				if openCount.Add(1) == 2 {
					return nil, errors.New("simulated disk read failure mid-upload")
				}
				return io.NopCloser(bytes.NewReader(bytes.Repeat([]byte("F"), 1024))), nil
			}),
		},
	}, SendOptions{DeliveryMode: DeliverySpool})
	if abortErr == nil {
		t.Fatal("expected aborted SendToDevice error")
	}
	mr.mu.Lock()
	remItems := len(mr.items)
	mr.mu.Unlock()
	if remItems != 0 {
		t.Fatalf("ST-P1-10 regression: uncommitted spool item leaked on relay (%d items remaining)", remItems)
	}

	// 3. ST-P1-13 & ST-P2-1 & ST-Opt-5: Multi-blob resume skips already-.verified part_1 + FetchParcel AppID pre-filter!
	blob1 := filepath.Join(t.TempDir(), "b1.bin")
	blob2 := filepath.Join(t.TempDir(), "b2.bin")
	d1 := bytes.Repeat([]byte("1"), 300*1024+19) // 2 chunks on nano
	d2 := bytes.Repeat([]byte("2"), 600*1024+29) // 3 chunks on nano
	_ = os.WriteFile(blob1, d1, 0o600)
	_ = os.WriteFile(blob2, d2, 0o600)
	multiSend, err := alice.SendToDevice(ctx, aliceOfBob2.DeviceID, envelope.ParcelInput{
		AppID:  "com.yellowdking.notes",
		Schema: "multi.v1",
		Blobs:  []envelope.BlobInput{envelope.BlobFromFile("file", blob1), envelope.BlobFromFile("file", blob2)},
	}, SendOptions{DeliveryMode: DeliverySpool})
	if err != nil {
		t.Fatal(err)
	}

	// ST-P2-1: FetchParcel with wrong AppID MUST NOT pull blobs or burn item!
	if _, err := bob.FetchParcel(ctx, multiSend.ItemID, nil, ReceiveOptions{AppID: "com.other.app"}); !envelope.IsCode(err, envelope.ErrCodeManifestInvalid) {
		t.Fatalf("expected AppID mismatch rejection, got %v", err)
	}

	// Drop on part_2 chunk 1 AFTER part_1 is completely .verified!
	mr.mu.Lock()
	mr.failChunkAt[multiSend.ItemID+":2:1"] = 1
	mr.mu.Unlock()
	if _, err := bob.FetchParcel(ctx, multiSend.ItemID, nil, ReceiveOptions{AppID: "com.yellowdking.notes"}); !envelope.IsCode(err, envelope.ErrCodeInterruptedResumable) {
		t.Fatalf("expected ERR_INTERRUPTED_RESUMABLE on part 2 chunk 1 drop, got %v", err)
	}

	// Poison part_1 chunk 0 on relay to PROVE resumed FetchParcel skips re-downloading already-.verified part_1!
	mr.mu.Lock()
	mr.failChunkAt[multiSend.ItemID+":1:0"] = 99
	mr.mu.Unlock()
	var finalEvent envelope.TransferEvent
	if _, err := bob.FetchParcel(ctx, multiSend.ItemID, func(p envelope.ReceivedParcel) error {
		if len(p.Blobs) != 2 {
			return errors.New("expected 2 blobs")
		}
		got1, _ := os.ReadFile(p.Blobs[0].SafePath)
		got2, _ := os.ReadFile(p.Blobs[1].SafePath)
		if !bytes.Equal(got1, d1) || !bytes.Equal(got2, d2) {
			return errors.New("blob bytes mismatch")
		}
		return nil
	}, ReceiveOptions{
		AppID:      "com.yellowdking.notes",
		OnProgress: func(ev envelope.TransferEvent) { finalEvent = ev },
	}); err != nil {
		t.Fatalf("ST-P1-13 multi-blob resume failed (re-downloaded verified part_1?): %v", err)
	}
	if finalEvent.BytesDone != finalEvent.BytesTotal {
		t.Fatalf("ST-Opt-5 resumed BytesDone mismatch: got %d, want %d", finalEvent.BytesDone, finalEvent.BytesTotal)
	}

	// 4. ST-P1-8: Offline 2-phase RevokeDevice -> local trust revoked immediately, relay DELETE retried on SyncMailbox!
	offlineCli, err := New(Config{
		Relay: &envelope.RelayProfile{
			Endpoint:  "http://127.0.0.1:1",
			AccessKey: accessKey,
			TLSMode:   envelope.TLSModeSystemCA,
		},
		KeyStore: bob.KeyStoreHint(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer offlineCli.Close()
	// Relay is unreachable on 127.0.0.1:1 -> RevokeDevice returns network error, BUT local Revoked=true + PendingTokenDelete is persisted!
	if err := offlineCli.RevokeDevice(ctx, bobOfAlice2.DeviceID); err == nil {
		t.Fatal("expected network error when revoking while offline")
	}
	if devs, _ := bob.KeyStoreHint().ListDevices(); len(devs) != 0 {
		t.Fatalf("expected revoked device hidden immediately while offline, got %+v", devs)
	}
	// When Bob comes back online and calls SyncMailbox, pending token delete is executed on relay and tombstone deleted!
	if err := bob.SyncMailbox(ctx); err != nil {
		t.Fatalf("SyncMailbox retry delete failed: %v", err)
	}
	mr.mu.Lock()
	remBobTokens := len(mr.mailboxes[bobMboxID].tokens)
	mr.mu.Unlock()
	if remBobTokens != 0 {
		t.Fatalf("expected SyncMailbox to delete pending revoked deposit_token on relay, still %d", remBobTokens)
	}
	if tomb, _ := bob.KeyStoreHint().GetDevice(bobOfAlice2.DeviceID); tomb != nil {
		t.Fatalf("expected tombstone deleted after SyncMailbox drained pending token delete, got %+v", tomb)
	}

	// 5. ST-P1-9 & ST-P2-12: 60s SSE idle read timeout, >4MiB response limit, ERR_HANDSHAKE_TIMEOUT, & dedup ring!
	ring := newWatchDedupRing()
	for i := 0; i < watchDedupRingCap+10; i++ {
		id := strings.Repeat("x", 8) + string(rune(i))
		if ring.seenOrAdd(id) {
			t.Fatal("unexpected duplicate on fresh id")
		}
	}
	if len(ring.set) != watchDedupRingCap {
		t.Fatalf("expected FIFO dedup ring capped at %d, got %d", watchDedupRingCap, len(ring.set))
	}

	// Handshake timeout on room wait maps DeadlineExceeded -> ERR_HANDSHAKE_TIMEOUT.
	shortCtx, cancelShort := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancelShort()
	created, err := alice.createRoom(ctx, "01234567", 60, []byte(`{"proto_v":1}`))
	if err != nil {
		t.Fatal(err)
	}
	_, _, hsTimeoutErr := alice.waitForPeerRoomMessage(shortCtx, created.RoomID, created.SenderToken, "receiver", created.Seq)
	if !envelope.IsCode(hsTimeoutErr, envelope.ErrCodeHandshakeTimeout) {
		t.Fatalf("expected ERR_HANDSHAKE_TIMEOUT on DeadlineExceeded, got %v", hsTimeoutErr)
	}

	// Stalled SSE + oversized >4MiB control response test server.
	prevIdle := sseIdleTimeout
	sseIdleTimeout = 120 * time.Millisecond
	defer func() { sseIdleTimeout = prevIdle }()

	var sseHits, pollHits atomic.Int32
	customSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/oversized" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(bytes.Repeat([]byte("A"), int(maxControlRespBytes)+1024))
			return
		}
		if strings.HasSuffix(r.URL.Path, "/events") {
			if r.URL.Query().Get("mode") == "sse" {
				sseHits.Add(1)
				w.Header().Set("Content-Type", "text/event-stream")
				w.WriteHeader(http.StatusOK)
				if f, ok := w.(http.Flusher); ok {
					f.Flush()
				}
				// Half-open stall: send zero bytes until client's idle timer cancels stream!
				<-r.Context().Done()
				return
			}
			pollHits.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"server_ts":1764246000,"items":[{"item_id":"itm_after_stall","total_bytes":100,"created_at":1764246000,"expires_at":1764249600}]}`)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer customSrv.Close()

	stallCli, err := New(Config{
		Relay: &envelope.RelayProfile{
			Endpoint:  customSrv.URL,
			AccessKey: accessKey,
			TLSMode:   envelope.TLSModeSystemCA,
		},
		KeyStore: envelope.NewMemoryKeyStore(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer stallCli.Close()

	// >4 MiB response MUST fail with ERR_BAD_REQUEST instead of silently truncating!
	if _, err := stallCli.doControl(ctx, http.MethodGet, "/v1/oversized", nil, reqOptions{}); !envelope.IsCode(err, envelope.ErrCodeBadRequest) {
		t.Fatalf("expected ERR_BAD_REQUEST on >4MiB control response, got %v", err)
	}

	// Stalled SSE stream MUST hit 120ms idle timeout, backoff cleanly, fall back to poll, and deliver event!
	wCtx, cancelW := context.WithTimeout(ctx, 3*time.Second)
	defer cancelW()
	gotAfterStall := ""
	wErr := stallCli.WatchInbox(wCtx, func(ev InboxWatchEvent) error {
		gotAfterStall = ev.ItemID
		cancelW()
		return nil
	})
	if gotAfterStall != "itm_after_stall" || sseHits.Load() == 0 || pollHits.Load() == 0 {
		t.Fatalf("expected stalled SSE to idle-timeout and recover via poll: got=%q sseHits=%d pollHits=%d err=%v", gotAfterStall, sseHits.Load(), pollHits.Load(), wErr)
	}
}
