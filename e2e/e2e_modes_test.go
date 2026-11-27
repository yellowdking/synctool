package e2e

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/yellowdking/synctool/internal/relay"
	"github.com/yellowdking/synctool/sdk/go/client"
	synccrypto "github.com/yellowdking/synctool/sdk/go/crypto"
	"github.com/yellowdking/synctool/sdk/go/envelope"
)

func TestE2E_Flow2_ModeB_MultiChunk_TwoPhase_Resume_PhysicalBurn_And_Replay(t *testing.T) {
	// nano profile + disk spool => 262,208 B chunks so 900 KiB file spans 4 transport chunks / 15 AEAD blocks.
	rr := startRealRelay(t, func(cfg *relay.Config) {
		cfg.Profile = relay.ProfileNano
		cfg.Spool = relay.SpoolDisk
	})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	alice, _ := newSDKClient(t, rr, "alice-phone", nil)
	bob, bobKS := newSDKClient(t, rr, "bob-desktop", nil)
	_, _, _, _, bobMailboxID := bob.Identity()

	aliceCardOfBob, _ := pairTwoClients(t, ctx, alice, bob, synccrypto.ModeQROOB)

	// Send multi-chunk note (inline UTF-8 + 900 KiB binary blob) while Bob is "offline".
	filePath, rawBytes, wantSHA := writeRandomFile(t, 900*1024+77)
	sendRes, err := alice.SendToDevice(ctx, aliceCardOfBob.DeviceID, envelope.ParcelInput{
		AppID:         "com.yellowdking.notes",
		Schema:        "note.item.v1",
		InlinePayload: map[string]any{"title": "跨端多媒体笔记", "markdown": "含多块加密附件"},
		Blobs: []envelope.BlobInput{
			{Role: "video", Name: "../../evil/clip.mp4", MIME: "video/mp4", FilePath: filePath},
		},
	}, client.SendOptions{DeliveryMode: "auto"})
	if err != nil {
		t.Fatalf("Alice SendToDevice failed: %v", err)
	}
	if sendRes.Mode != "spool" || sendRes.ItemID == "" {
		t.Fatalf("expected Mode B spool send, got %+v", sendRes)
	}

	// Verify relay disk holds the encrypted item directory before Bob pulls.
	itemDiskDir := filepath.Join(rr.DataDir, "spool", bobMailboxID[:2], bobMailboxID, sendRes.ItemID)
	if _, err := os.Stat(filepath.Join(itemDiskDir, "item.json")); err != nil {
		t.Fatalf("expected item.json on relay disk before pull: %v", err)
	}

	// Phase 1: Two-phase ListInbox called 20 times (>16 manifest download limit) MUST hit local cache!
	for i := 0; i < 20; i++ {
		previews, err := bob.ListInbox(ctx, "com.yellowdking.notes")
		if err != nil {
			t.Fatalf("ListInbox iteration %d failed: %v", i, err)
		}
		if len(previews) != 1 || previews[0].ItemID != sendRes.ItemID {
			t.Fatalf("unexpected previews on iteration %d: %+v", i, previews)
		}
		if i == 0 && previews[0].Cached {
			t.Fatalf("expected first ListInbox to fetch from relay (Cached=false)")
		}
		if i > 0 && !previews[0].Cached {
			t.Fatalf("expected ListInbox iteration %d to hit local Manifest cache", i)
		}
	}

	// Phase 2A: Simulate network drop after 2 transport chunks -> checkpoint saved!
	dropCtx, cancelDrop := context.WithCancel(ctx)
	chunkCallbacks := 0
	_, dropErr := bob.FetchParcel(dropCtx, sendRes.ItemID, func(p envelope.ReceivedParcel) error {
		return errors.New("handler must not be invoked on partial interrupted download")
	}, client.ReceiveOptions{
		OnProgress: func(ev envelope.TransferEvent) {
			if ev.PartID == 1 {
				chunkCallbacks++
				if chunkCallbacks == 2 {
					cancelDrop()
				}
			}
		},
	})
	cancelDrop()
	if dropErr == nil {
		t.Fatalf("expected interrupted FetchParcel error")
	}
	cp, err := bobKS.GetCheckpoint("recv", sendRes.MsgID, 1)
	if err != nil || cp == nil || cp.NextTxIdx < 2 {
		t.Fatalf("expected recv checkpoint >= 2 saved after interruption, got cp=%+v err=%v", cp, err)
	}

	// Phase 2B: Resume download from checkpoint -> verify full SHA-256, safe filename, and ACK physical burn!
	sawResumed := false
	var gotSafeName, gotSafePath string
	manifest, err := bob.FetchParcel(ctx, sendRes.ItemID, func(p envelope.ReceivedParcel) error {
		if len(p.Blobs) != 1 {
			return fmt.Errorf("expected 1 blob, got %d", len(p.Blobs))
		}
		gotSafeName = p.Blobs[0].SafeName
		gotSafePath = p.Blobs[0].SafePath
		return nil
	}, client.ReceiveOptions{
		OnProgress: func(ev envelope.TransferEvent) {
			if ev.Resumed {
				sawResumed = true
			}
		},
	})
	if err != nil {
		t.Fatalf("resumed FetchParcel failed: %v", err)
	}
	if !sawResumed {
		t.Fatalf("expected resumed=true progress event on checkpoint recovery")
	}
	if gotSafeName != "clip.mp4" {
		t.Fatalf("path traversal filename not sanitized: got %q", gotSafeName)
	}
	gotBytes, err := os.ReadFile(gotSafePath)
	if err != nil || !bytes.Equal(gotBytes, rawBytes) {
		t.Fatalf("resumed blob content mismatch (want sha=%s, err=%v)", wantSHA, err)
	}
	if manifest.MsgID != sendRes.MsgID {
		t.Fatalf("manifest msg_id mismatch")
	}

	// Verify signed ACK physically burned item on relay disk and inbox is now empty.
	if _, err := os.Stat(itemDiskDir); !os.IsNotExist(err) {
		t.Fatalf("expected relay item directory %s to be physically deleted after ACK, stat err=%v", itemDiskDir, err)
	}
	afterList, err := bob.ListInbox(ctx, "")
	if err != nil || len(afterList) != 0 {
		t.Fatalf("expected empty inbox after ACK burn, got len=%d err=%v", len(afterList), err)
	}

	// Verify msg_id is recorded in seen_msg_ids replay defense window.
	seen, err := bobKS.HasSeenMsgID(sendRes.MsgID)
	if err != nil || !seen {
		t.Fatalf("expected msg_id recorded in seen_msg_ids after delivery")
	}
}

func TestE2E_PrecisionSingleDeviceRevocation(t *testing.T) {
	rr := startRealRelay(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	alice, _ := newSDKClient(t, rr, "alice-pc", nil)
	bob, _ := newSDKClient(t, rr, "bob-lost-phone", nil)
	carol, _ := newSDKClient(t, rr, "carol-tablet", nil)

	aliceOfBob, bobOfAlice := pairTwoClients(t, ctx, alice, bob, synccrypto.ModeQROOB)
	_, carolOfAlice := pairTwoClients(t, ctx, alice, carol, synccrypto.ModeCommitSAS)

	// Both Bob and Carol can send before revocation.
	if _, err := bob.SendToDevice(ctx, bobOfAlice.DeviceID, envelope.ParcelInput{
		Schema: "note.v1", InlinePayload: map[string]any{"from": "bob-before"},
	}, client.SendOptions{}); err != nil {
		t.Fatalf("bob pre-revoke send failed: %v", err)
	}

	// Alice revokes ONLY Bob (lost phone).
	if err := alice.RevokeDevice(ctx, aliceOfBob.DeviceID); err != nil {
		t.Fatalf("Alice RevokeDevice(bob) failed: %v", err)
	}

	// Bob's subsequent deposit MUST be rejected by relay with 401 ERR_UNAUTHORIZED_TOKEN.
	_, err := bob.SendToDevice(ctx, bobOfAlice.DeviceID, envelope.ParcelInput{
		Schema: "note.v1", InlinePayload: map[string]any{"from": "bob-after-revoke"},
	}, client.SendOptions{})
	if !envelope.IsCode(err, envelope.ErrCodeUnauthorizedToken) {
		t.Fatalf("expected revoked Bob to get ERR_UNAUTHORIZED_TOKEN, got: %v", err)
	}

	// Carol MUST remain 100% unaffected!
	resC, err := carol.SendToDevice(ctx, carolOfAlice.DeviceID, envelope.ParcelInput{
		Schema: "note.v1", InlinePayload: map[string]any{"from": "carol-still-trusted"},
	}, client.SendOptions{})
	if err != nil {
		t.Fatalf("Carol send after revoking Bob failed: %v", err)
	}

	// Alice lists inbox -> Bob's pre-revoke item is ignored (untrusted sender), Carol's item succeeds!
	previews, err := alice.ListInbox(ctx, "")
	if err != nil {
		t.Fatalf("Alice ListInbox failed: %v", err)
	}
	if len(previews) != 1 || previews[0].ItemID != resC.ItemID {
		t.Fatalf("expected only Carol's parcel in Alice's verified inbox, got %+v", previews)
	}
	var gotFrom string
	if _, err := alice.FetchParcel(ctx, resC.ItemID, func(p envelope.ReceivedParcel) error {
		gotFrom, _ = p.Manifest.InlinePayload["from"].(string)
		return nil
	}, client.ReceiveOptions{}); err != nil || gotFrom != "carol-still-trusted" {
		t.Fatalf("Alice FetchParcel(Carol) failed: err=%v from=%q", err, gotFrom)
	}
}

func TestE2E_SecurityBoundaries_ClockSkew_Replay_Tamper_Truncation(t *testing.T) {
	rr := startRealRelay(t, func(cfg *relay.Config) {
		cfg.Profile = relay.ProfileNano
		cfg.Spool = relay.SpoolDisk
	})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	alice, _ := newSDKClient(t, rr, "alice", nil)
	bob, _ := newSDKClient(t, rr, "bob", nil)
	_, _, _, _, bobMailboxID := bob.Identity()

	// 1. Clock Skew > 60s triggers 409 ERR_CLOCK_SKEW and client auto-calibrates & retries cleanly.
	bob.SetClockOffsetSec(-300)
	if _, err := bob.Ping(ctx); err != nil {
		t.Fatalf("expected auto clock-skew calibration to succeed, got: %v", err)
	}
	if off := bob.ClockOffsetSec(); off < -5 || off > 5 {
		t.Fatalf("expected clock offset calibrated near 0, got %d", off)
	}

	// 2. HTTP Nonce Replay returns 401 ERR_REPLAY_DETECTED.
	rawCli := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13},
		},
	}
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	fixedNonce, _ := synccrypto.GenerateNonceHex()
	sig := synccrypto.SignRelayRequest(rr.AccessKey, http.MethodGet, "/v1/ping", ts, fixedNonce, synccrypto.BodyBindingControl(nil), "")
	doFixedNonce := func() (int, string) {
		req, _ := http.NewRequest(http.MethodGet, rr.Origin+"/v1/ping", nil)
		req.Header.Set(synccrypto.HeaderRelayTS, ts)
		req.Header.Set(synccrypto.HeaderRelayNonce, fixedNonce)
		req.Header.Set(synccrypto.HeaderRelaySig, sig)
		resp, err := rawCli.Do(req)
		if err != nil {
			t.Fatalf("fixed nonce req failed: %v", err)
		}
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		var out struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(b, &out)
		return resp.StatusCode, out.Error
	}
	if st, _ := doFixedNonce(); st != http.StatusOK {
		t.Fatalf("expected 1st nonce request 200, got %d", st)
	}
	if st, code := doFixedNonce(); st != http.StatusUnauthorized || code != envelope.ErrCodeReplayDetected {
		t.Fatalf("expected 2nd identical nonce 401 ERR_REPLAY_DETECTED, got %d %q", st, code)
	}

	// Pair Alice <-> Bob for tamper & truncation tests.
	aliceOfBob, _ := pairTwoClients(t, ctx, alice, bob, synccrypto.ModeQROOB)

	// 3. Ciphertext 1-byte tamper on relay disk MUST be rejected by STREAM AEAD without ACK!
	filePath, _, _ := writeRandomFile(t, 400*1024+11) // 2 chunks on nano
	resTamper, err := alice.SendToDevice(ctx, aliceOfBob.DeviceID, envelope.ParcelInput{
		Schema: "note.v1",
		Blobs:  []envelope.BlobInput{{Role: "file", Name: "secret.bin", FilePath: filePath}},
	}, client.SendOptions{})
	if err != nil {
		t.Fatalf("send tamper fixture failed: %v", err)
	}
	chunk0Path := filepath.Join(rr.DataDir, "spool", bobMailboxID[:2], bobMailboxID, resTamper.ItemID, "p1_c0.enc")
	c0, err := os.ReadFile(chunk0Path)
	if err != nil {
		t.Fatalf("read p1_c0.enc: %v", err)
	}
	c0[len(c0)/2] ^= 0x01 // Flip 1 bit in ciphertext!
	if err := os.WriteFile(chunk0Path, c0, 0o600); err != nil {
		t.Fatalf("tamper p1_c0.enc: %v", err)
	}
	handlerCalled := false
	_, tamperErr := bob.FetchParcel(ctx, resTamper.ItemID, func(p envelope.ReceivedParcel) error {
		handlerCalled = true
		return nil
	}, client.ReceiveOptions{})
	if !envelope.IsCode(tamperErr, envelope.ErrCodeCryptoDecryptFailed) || handlerCalled {
		t.Fatalf("expected ERR_CRYPTO_DECRYPT_FAILED without invoking handler, got err=%v called=%v", tamperErr, handlerCalled)
	}

	// 4. Truncated final chunk (missing is_final=0x01 block) MUST be rejected without delivery!
	resTrunc, err := alice.SendToDevice(ctx, aliceOfBob.DeviceID, envelope.ParcelInput{
		Schema: "note.v1",
		Blobs:  []envelope.BlobInput{{Role: "file", Name: "trunc.bin", FilePath: filePath}},
	}, client.SendOptions{})
	if err != nil {
		t.Fatalf("send trunc fixture failed: %v", err)
	}
	// Replace final chunk p1_c1.enc with a truncated slice missing its final authenticated block.
	chunk1Path := filepath.Join(rr.DataDir, "spool", bobMailboxID[:2], bobMailboxID, resTrunc.ItemID, "p1_c1.enc")
	c1, err := os.ReadFile(chunk1Path)
	if err != nil || len(c1) < 32 {
		t.Fatalf("read p1_c1.enc: len=%d err=%v", len(c1), err)
	}
	if err := os.WriteFile(chunk1Path, c1[:len(c1)-16], 0o600); err != nil {
		t.Fatalf("truncate p1_c1.enc: %v", err)
	}
	handlerCalled = false
	_, truncErr := bob.FetchParcel(ctx, resTrunc.ItemID, func(p envelope.ReceivedParcel) error {
		handlerCalled = true
		return nil
	}, client.ReceiveOptions{})
	if truncErr == nil || handlerCalled {
		t.Fatalf("expected truncation rejection without handler invocation, got err=%v called=%v", truncErr, handlerCalled)
	}
	if !envelope.IsCode(truncErr, envelope.ErrCodeCryptoDecryptFailed) && !envelope.IsCode(truncErr, envelope.ErrCodeStreamTruncated) {
		t.Fatalf("expected decrypt/truncation error, got %v", truncErr)
	}
}

func TestE2E_ManualSpoolOff_ModeADirect_And_NanoQuotas(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Part A: Explicit manual --spool=off kill-switch + Device Bind + Flow 2 Mode A Direct zero-disk pipe!
	rrOff := startRealRelay(t, func(cfg *relay.Config) {
		cfg.Profile = relay.ProfileNano
		cfg.Spool = relay.SpoolOff
	})
	aliceOff, _ := newSDKClient(t, rrOff, "alice-off", nil)
	bobOff, _ := newSDKClient(t, rrOff, "bob-off", nil)

	capsOff, err := aliceOff.Capabilities(ctx)
	if err != nil || capsOff.Spool.Enabled || capsOff.Spool.Backend != "off" {
		t.Fatalf("expected spool disabled in caps, got %+v err=%v", capsOff, err)
	}

	// Verify direct Mode B API call fails with 403 ERR_SPOOL_DISABLED.
	if _, err := aliceOff.ListInbox(ctx, ""); !envelope.IsCode(err, envelope.ErrCodeSpoolDisabled) {
		t.Fatalf("expected ERR_SPOOL_DISABLED on ListInbox with --spool=off, got %v", err)
	}

	// Bind Alice <-> Bob cleanly under --spool=off (mailbox fields omitted/empty).
	aliceOfBobOff, _ := pairTwoClients(t, ctx, aliceOff, bobOff, synccrypto.ModeQROOB)
	if aliceOfBobOff.MailboxID != "" || aliceOfBobOff.OutboundDepositToken != "" {
		t.Fatalf("expected empty mailbox/deposit_token under --spool=off, got %+v", aliceOfBobOff)
	}

	// DeliveryMode "auto" reports ERR_SPOOL_DISABLED suggesting "pipe".
	_, err = aliceOff.SendToDevice(ctx, aliceOfBobOff.DeviceID, envelope.ParcelInput{
		Schema: "note.v1", InlinePayload: map[string]any{"text": "hi"},
	}, client.SendOptions{DeliveryMode: "auto"})
	if !envelope.IsCode(err, envelope.ErrCodeSpoolDisabled) {
		t.Fatalf("expected ERR_SPOOL_DISABLED on auto send with --spool=off, got %v", err)
	}

	// DeliveryMode "pipe" (Flow 2 Mode A direct m=0&p=direct) transfers 600 KiB multi-chunk file with zero spool!
	filePath, rawBytes, _ := writeRandomFile(t, 600*1024+33)
	offerCh := make(chan client.OfferReadyInfo, 1)
	var wg sync.WaitGroup
	var sendErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, sendErr = aliceOff.SendToDevice(ctx, aliceOfBobOff.DeviceID, envelope.ParcelInput{
			Schema:        "note.direct.v1",
			InlinePayload: map[string]any{"msg": "zero-disk-direct-pipe"},
			Blobs:         []envelope.BlobInput{{Role: "video", Name: "direct.mp4", FilePath: filePath}},
		}, client.SendOptions{
			DeliveryMode: "pipe",
			OnOfferReady: func(info client.OfferReadyInfo) { offerCh <- info },
		})
	}()
	offer := <-offerCh
	var gotPath, gotMsg string
	_, recvErr := bobOff.ReceiveDirect(ctx, offer.PairURI, func(p envelope.ReceivedParcel) error {
		gotMsg, _ = p.Manifest.InlinePayload["msg"].(string)
		gotPath = p.Blobs[0].SafePath
		return nil
	}, client.ReceiveOptions{})
	wg.Wait()
	if sendErr != nil || recvErr != nil {
		t.Fatalf("Flow 2 Mode A direct failed under --spool=off: sendErr=%v recvErr=%v", sendErr, recvErr)
	}
	gotBytes, err := os.ReadFile(gotPath)
	if err != nil || gotMsg != "zero-disk-direct-pipe" || !bytes.Equal(gotBytes, rawBytes) {
		t.Fatalf("Flow 2 Mode A direct payload mismatch: msg=%q err=%v", gotMsg, err)
	}

	// Part B: --profile=nano quota enforcement (item cap 4 MiB + item_count cap without evicting unread items).
	rrNano := startRealRelay(t, func(cfg *relay.Config) {
		cfg.Profile = relay.ProfileNano
		cfg.Spool = relay.SpoolMemory
		cfg.SpoolMaxItemsPerMailbox = 2
	})
	aliceN, _ := newSDKClient(t, rrNano, "alice-nano", nil)
	bobN, _ := newSDKClient(t, rrNano, "bob-nano", nil)
	aliceOfBobN, _ := pairTwoClients(t, ctx, aliceN, bobN, synccrypto.ModeQROOB)

	// Exceeding nano 4 MiB single-item cap returns ERR_OFFLINE_QUOTA_EXCEEDED.
	bigPath, _, _ := writeRandomFile(t, 4*1024*1024+1024)
	_, err = aliceN.SendToDevice(ctx, aliceOfBobN.DeviceID, envelope.ParcelInput{
		Schema: "video.v1",
		Blobs:  []envelope.BlobInput{{Role: "video", Name: "too_big.mp4", FilePath: bigPath}},
	}, client.SendOptions{DeliveryMode: "auto"})
	if !envelope.IsCode(err, envelope.ErrCodeOfflineQuotaExceeded) {
		t.Fatalf("expected ERR_OFFLINE_QUOTA_EXCEEDED for >4MiB on nano, got %v", err)
	}

	// Fill 2 items (cap=2), verify 3rd item fails with 507 ERR_OFFLINE_QUOTA_EXCEEDED and first 2 stay intact!
	for i := 1; i <= 2; i++ {
		if _, err := aliceN.SendToDevice(ctx, aliceOfBobN.DeviceID, envelope.ParcelInput{
			Schema: "note.v1", InlinePayload: map[string]any{"n": i},
		}, client.SendOptions{}); err != nil {
			t.Fatalf("nano send %d failed: %v", i, err)
		}
	}
	_, err = aliceN.SendToDevice(ctx, aliceOfBobN.DeviceID, envelope.ParcelInput{
		Schema: "note.v1", InlinePayload: map[string]any{"n": 3},
	}, client.SendOptions{})
	if !envelope.IsCode(err, envelope.ErrCodeOfflineQuotaExceeded) {
		t.Fatalf("expected 507 ERR_OFFLINE_QUOTA_EXCEEDED on 3rd item, got %v", err)
	}
	previews, err := bobN.ListInbox(ctx, "")
	if err != nil || len(previews) != 2 {
		t.Fatalf("expected first 2 unread items preserved (never silently evicted), got len=%d err=%v", len(previews), err)
	}
}
