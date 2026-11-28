package e2e

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
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

type runningRelay struct {
	Origin    string
	SPKIPin   string
	AccessKey string
	DataDir   string
	Server    *relay.Server
	HTTP      *http.Server
	Cleanup   func()
}

func startRealRelay(t *testing.T, modify func(*relay.Config)) *runningRelay {
	t.Helper()
	dataDir := t.TempDir()
	rawLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := rawLn.Addr().String()

	cfg := relay.DefaultConfig()
	cfg.ListenAddr = addr
	cfg.PublicHost = "127.0.0.1"
	cfg.Profile = relay.ProfileStandard
	cfg.Spool = relay.SpoolDisk
	cfg.TLSMode = relay.TLSSelfSigned
	cfg.DataDir = dataDir
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

	origin := fmt.Sprintf("%s://%s", scheme, addr)
	rr := &runningRelay{
		Origin:    origin,
		SPKIPin:   spkiPin,
		AccessKey: rc.AccessKey,
		DataDir:   dataDir,
		Server:    srv,
		HTTP:      httpSrv,
	}
	rr.Cleanup = func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(ctx)
		srv.Close()
	}
	t.Cleanup(rr.Cleanup)
	return rr
}

func newSDKClient(t *testing.T, rr *runningRelay, label string, mutateProfile func(*envelope.RelayProfile)) (*client.Client, *envelope.FileKeyStore) {
	t.Helper()
	ks, err := envelope.NewFileKeyStore(t.TempDir())
	if err != nil {
		t.Fatalf("new keystore: %v", err)
	}
	tlsMode := envelope.TLSModeSPKIPin
	if rr.SPKIPin == "" {
		tlsMode = envelope.TLSModeSystemCA
	}
	prof := &envelope.RelayProfile{
		Endpoint:   rr.Origin,
		AccessKey:  rr.AccessKey,
		TLSMode:    tlsMode,
		SPKISHA256: rr.SPKIPin,
	}
	if mutateProfile != nil {
		mutateProfile(prof)
	}
	cli, err := client.New(client.Config{
		AppID:       "com.yellowdking.e2e",
		DeviceLabel: label,
		Relay:       prof,
		KeyStore:    ks,
		TempDir:     t.TempDir(),
	})
	if err != nil {
		t.Fatalf("new client %s: %v", label, err)
	}
	t.Cleanup(cli.Close)
	return cli, ks
}

func writeRandomFile(t *testing.T, size int) (path string, raw []byte, shaHex string) {
	t.Helper()
	raw = make([]byte, size)
	if _, err := rand.Read(raw); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	sum := sha256.Sum256(raw)
	shaHex = hex.EncodeToString(sum[:])
	path = filepath.Join(t.TempDir(), fmt.Sprintf("payload_%d.bin", size))
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write payload file: %v", err)
	}
	return path, raw, shaHex
}

func pairTwoClients(t *testing.T, ctx context.Context, alice, bob *client.Client, mode int) (aliceCardOfBob, bobCardOfAlice *envelope.DeviceCard) {
	t.Helper()
	offerCh := make(chan client.OfferReadyInfo, 1)
	sasCh := make(chan string, 1)

	var wg sync.WaitGroup
	var errA, errB error
	wg.Add(1)
	go func() {
		defer wg.Done()
		aliceCardOfBob, errA = alice.StartDeviceBind(ctx, client.PairOptions{
			Mode: mode,
			OnOfferReady: func(info client.OfferReadyInfo) {
				offerCh <- info
			},
			OnSASInput: func() (string, error) {
				select {
				case s := <-sasCh:
					return s, nil
				case <-ctx.Done():
					return "", ctx.Err()
				}
			},
		})
	}()

	var offer client.OfferReadyInfo
	select {
	case offer = <-offerCh:
	case <-ctx.Done():
		t.Fatalf("timed out waiting for pair offer")
	}

	pairInput := offer.PairURI
	if mode == synccrypto.ModeCommitSAS {
		pairInput = offer.DisplayCode
	}
	bobCardOfAlice, errB = bob.AcceptDeviceBind(ctx, pairInput, client.PairOptions{
		OnSASDisplay: func(sas string) {
			sasCh <- sas
		},
		OnSASConfirm: func(sas string) error {
			return nil
		},
	})
	wg.Wait()
	if errA != nil {
		t.Fatalf("alice StartDeviceBind (mode=%d) failed: %v", mode, errA)
	}
	if errB != nil {
		t.Fatalf("bob AcceptDeviceBind (mode=%d) failed: %v", mode, errB)
	}
	return aliceCardOfBob, bobCardOfAlice
}

func TestE2E_TLS13_SPKIPin_And_Stealth404(t *testing.T) {
	rr := startRealRelay(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Verify onboarding URI round-trip between relay and Go SDK URI parser.
	uri := relay.BuildRelayURI(rr.Origin, rr.SPKIPin, rr.AccessKey)
	parsed, err := envelope.ParseRelayURI(uri)
	if err != nil {
		t.Fatalf("ParseRelayURI failed: %v", err)
	}
	if parsed.SPKISHA256 != rr.SPKIPin || parsed.AccessKey != rr.AccessKey {
		t.Fatalf("parsed relay URI mismatch")
	}

	// 1. Valid SPKI Pin + AccessKey succeeds over TLS 1.3.
	cli, _ := newSDKClient(t, rr, "alice", nil)
	pingRes, err := cli.Ping(ctx)
	if err != nil {
		t.Fatalf("Ping failed: %v", err)
	}
	if pingRes.ProtoV != 1 || pingRes.Profile != "standard" || pingRes.SpoolBackend != "disk" {
		t.Fatalf("unexpected ping response: %+v", pingRes)
	}
	if pingRes.CertExpiresAt <= time.Now().Unix() || pingRes.CertRotateRecommended {
		t.Fatalf("expected fresh 730-day cert, got exp=%d rotate=%v", pingRes.CertExpiresAt, pingRes.CertRotateRecommended)
	}

	// 2. Wrong SPKI Pin MUST be rejected before any HTTP bytes are sent.
	wrongPin := "0000000000000000000000000000000000000000000000000000000000000000"
	if rr.SPKIPin == wrongPin {
		wrongPin = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	}
	badPinCli, _ := newSDKClient(t, rr, "bad-pin", func(p *envelope.RelayProfile) {
		p.SPKISHA256 = wrongPin
	})
	if _, err := badPinCli.Ping(ctx); !envelope.IsCode(err, envelope.ErrCodeTLSPinMismatch) {
		t.Fatalf("expected ERR_TLS_PIN_MISMATCH, got: %v", err)
	}

	// 3. Wrong AccessKey MUST return silent empty 404 (ERR_AUTH_FAILED).
	badKeyCli, _ := newSDKClient(t, rr, "bad-key", func(p *envelope.RelayProfile) {
		p.AccessKey = "wrong-access-key-0123456789abcdef0123456789"
	})
	if _, err := badKeyCli.Ping(ctx); !envelope.IsCode(err, envelope.ErrCodeAuthFailed) {
		t.Fatalf("expected ERR_AUTH_FAILED on bad AccessKey, got: %v", err)
	}

	// Confirm raw HTTP response for unauthenticated probe is strictly silent empty 404 without Server header.
	rawClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13},
		},
	}
	resp, err := rawClient.Get(rr.Origin + "/v1/ping")
	if err != nil {
		t.Fatalf("raw probe failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound || len(body) != 0 || resp.Header.Get("Server") != "" {
		t.Fatalf("expected silent empty 404 without Server header, got status=%d body=%q server=%q", resp.StatusCode, string(body), resp.Header.Get("Server"))
	}
}

func TestE2E_ReverseProxy_TLSOff_TrustedProxies(t *testing.T) {
	// Guard check: --tls=off on non-loopback without TRUSTED_PROXIES MUST fail to resolve.
	badCfg := relay.DefaultConfig()
	badCfg.ListenAddr = "0.0.0.0:54843"
	badCfg.TLSMode = relay.TLSOff
	badCfg.DataDir = t.TempDir()
	if _, err := badCfg.Resolve(); err == nil {
		t.Fatalf("expected Resolve() to refuse --tls=off on non-loopback without TRUSTED_PROXIES")
	}

	// Start real reverse-proxy mode relay (--tls=off + TRUSTED_PROXIES=127.0.0.1/32).
	rr := startRealRelay(t, func(cfg *relay.Config) {
		cfg.TLSMode = relay.TLSOff
		cfg.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cli, _ := newSDKClient(t, rr, "behind-proxy", nil)
	pingRes, err := cli.Ping(ctx)
	if err != nil {
		t.Fatalf("Ping over tls=off failed: %v", err)
	}
	if pingRes.CertExpiresAt != 0 {
		t.Fatalf("expected cert_expires_at=0 in tls=off mode, got %d", pingRes.CertExpiresAt)
	}

	// Send 10 bad probes claiming X-Forwarded-For: 203.0.113.55 to ban that real client IP.
	httpCli := &http.Client{}
	for i := 0; i < 11; i++ {
		req, _ := http.NewRequest(http.MethodGet, rr.Origin+"/v1/ping", nil)
		req.Header.Set("X-Forwarded-For", "203.0.113.55")
		resp, err := httpCli.Do(req)
		if err != nil {
			t.Fatalf("proxy probe %d failed: %v", i, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("expected 404, got %d", resp.StatusCode)
		}
	}

	// Verify 203.0.113.55 is banned even with a valid signature, while 198.51.100.77 is unaffected!
	signedPing := func(xff string) int {
		ts := strconv.FormatInt(time.Now().Unix(), 10)
		nonce, _ := synccrypto.GenerateNonceHex()
		sig := synccrypto.SignRelayRequest(rr.AccessKey, http.MethodGet, "/v1/ping", ts, nonce, synccrypto.BodyBindingControl(nil), "")
		req, _ := http.NewRequest(http.MethodGet, rr.Origin+"/v1/ping", nil)
		req.Header.Set("X-Forwarded-For", xff)
		req.Header.Set(synccrypto.HeaderRelayTS, ts)
		req.Header.Set(synccrypto.HeaderRelayNonce, nonce)
		req.Header.Set(synccrypto.HeaderRelaySig, sig)
		resp, err := httpCli.Do(req)
		if err != nil {
			t.Fatalf("signed proxy ping (%s) failed: %v", xff, err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	if st := signedPing("203.0.113.55"); st != http.StatusNotFound {
		t.Fatalf("expected banned real IP 203.0.113.55 to get stealth 404, got %d", st)
	}
	if st := signedPing("198.51.100.77"); st != http.StatusOK {
		t.Fatalf("expected innocent real IP 198.51.100.77 behind same proxy to get 200, got %d", st)
	}
}

func TestE2E_Flow1A_QROOB_And_Flow1B_CommitSAS_OneShot_And_Burn(t *testing.T) {
	rr := startRealRelay(t, func(cfg *relay.Config) {
		cfg.Profile = relay.ProfileNano // 4 blocks = 262,208 B chunks -> 850 KiB spans 4 chunks / 14 AEAD blocks!
		cfg.Spool = relay.SpoolMemory
	})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	alice, _ := newSDKClient(t, rr, "alice-laptop", nil)
	bob, _ := newSDKClient(t, rr, "bob-phone", nil)

	// 1. Flow 1A (QR OOB) multi-chunk One-Shot over Mode A zero-disk pipe.
	filePath, rawBytes, wantSHA := writeRandomFile(t, 850*1024+123)
	offerCh := make(chan client.OfferReadyInfo, 1)
	var wg sync.WaitGroup
	var sendRes *client.SendResult
	var sendErr error

	wg.Add(1)
	go func() {
		defer wg.Done()
		sendRes, sendErr = alice.StartOneShotSend(ctx, envelope.ParcelInput{
			Schema:        "vault.snapshot.v1",
			InlinePayload: map[string]any{"note": "GravitySSH 换机测试"},
			Blobs:         []envelope.BlobInput{{Role: "vault_dump", Name: "ssh_vault.bin", MIME: "application/octet-stream", FilePath: filePath}},
		}, client.PairOptions{
			Mode:         synccrypto.ModeQROOB,
			OnOfferReady: func(info client.OfferReadyInfo) { offerCh <- info },
		})
	}()

	offer := <-offerCh
	var gotBlobPath string
	manifest, err := bob.ReceiveOneShot(ctx, offer.PairURI, func(p envelope.ReceivedParcel) error {
		if p.Manifest.InlinePayload["note"] != "GravitySSH 换机测试" {
			return fmt.Errorf("inline payload mismatch: %v", p.Manifest.InlinePayload)
		}
		if len(p.Blobs) != 1 {
			return fmt.Errorf("expected 1 blob, got %d", len(p.Blobs))
		}
		gotBlobPath = p.Blobs[0].SafePath
		return nil
	}, client.ReceiveOptions{})
	wg.Wait()
	if err != nil || sendErr != nil {
		t.Fatalf("Flow 1A oneshot failed: sendErr=%v recvErr=%v", sendErr, err)
	}
	if manifest.MsgID != sendRes.MsgID {
		t.Fatalf("msg_id mismatch: %s vs %s", manifest.MsgID, sendRes.MsgID)
	}
	gotBytes, err := os.ReadFile(gotBlobPath)
	if err != nil || !bytes.Equal(gotBytes, rawBytes) {
		t.Fatalf("Flow 1A received blob bytes mismatch (want sha=%s, err=%v)", wantSHA, err)
	}

	// 2. Flow 1B (Commit-Reveal X25519 + 6-digit SAS) One-Shot.
	offerCh2 := make(chan client.OfferReadyInfo, 1)
	sasCh := make(chan string, 1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, sendErr = alice.StartOneShotSend(ctx, envelope.ParcelInput{
			Schema:        "clip.text.v1",
			InlinePayload: map[string]any{"secret": "commit-reveal-sas-verified"},
		}, client.PairOptions{
			Mode:         synccrypto.ModeCommitSAS,
			OnOfferReady: func(info client.OfferReadyInfo) { offerCh2 <- info },
			OnSASInput:   func() (string, error) { return <-sasCh, nil },
		})
	}()
	offer2 := <-offerCh2
	var gotSecret string
	_, err = bob.ReceiveOneShot(ctx, offer2.DisplayCode, func(p envelope.ReceivedParcel) error {
		gotSecret, _ = p.Manifest.InlinePayload["secret"].(string)
		return nil
	}, client.ReceiveOptions{
		OnSASDisplay: func(sas string) { sasCh <- sas },
		OnSASConfirm: func(sas string) error { return nil },
	})
	wg.Wait()
	if err != nil || sendErr != nil || gotSecret != "commit-reveal-sas-verified" {
		t.Fatalf("Flow 1B SAS oneshot failed: sendErr=%v recvErr=%v got=%q", sendErr, err, gotSecret)
	}

	// 3. Flow 1B SAS mismatch -> single-failure room burn (410 ERR_ROOM_BURNED).
	offerCh3 := make(chan client.OfferReadyInfo, 1)
	sasCh3 := make(chan string, 1)
	var badSendErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, badSendErr = alice.StartOneShotSend(ctx, envelope.ParcelInput{
			Schema:        "clip.text.v1",
			InlinePayload: map[string]any{"secret": "must-never-upload"},
		}, client.PairOptions{
			Mode:         synccrypto.ModeCommitSAS,
			OnOfferReady: func(info client.OfferReadyInfo) { offerCh3 <- info },
			OnSASInput: func() (string, error) {
				realSAS := <-sasCh3
				// Return intentionally wrong SAS on all 3 attempts.
				sasCh3 <- realSAS
				if realSAS == "000000" {
					return "999999", nil
				}
				return "000000", nil
			},
		})
	}()
	offer3 := <-offerCh3
	_, badRecvErr := bob.ReceiveOneShot(ctx, offer3.DisplayCode, func(p envelope.ReceivedParcel) error {
		return errors.New("handler must never be called on SAS mismatch")
	}, client.ReceiveOptions{
		OnSASDisplay: func(sas string) { sasCh3 <- sas },
		OnSASConfirm: func(sas string) error { return nil },
	})
	wg.Wait()
	if !envelope.IsCode(badSendErr, envelope.ErrCodeSASMismatch) {
		t.Fatalf("expected initiator ERR_SAS_MISMATCH, got %v", badSendErr)
	}
	if !envelope.IsCode(badRecvErr, envelope.ErrCodeRoomBurned) {
		t.Fatalf("expected responder ERR_ROOM_BURNED, got %v", badRecvErr)
	}
}

func TestE2E_Flow1B_ResponderOnSASConfirmMandatoryGate(t *testing.T) {
	rr := startRealRelay(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	alice, _ := newSDKClient(t, rr, "alice-initiator", nil)
	bobHijack, bobHijackKS := newSDKClient(t, rr, "bob-responder-gate", nil)

	var wg sync.WaitGroup

	// 4a. AcceptDeviceBind with OnSASConfirm == nil fails immediately and burns room.
	offerCh4a := make(chan client.OfferReadyInfo, 1)
	var initErr4a error
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, initErr4a = alice.StartDeviceBind(ctx, client.PairOptions{
			Mode:         synccrypto.ModeCommitSAS,
			OnOfferReady: func(info client.OfferReadyInfo) { offerCh4a <- info },
			OnSASInput:   func() (string, error) { return "000000", nil },
		})
	}()
	offer4a := <-offerCh4a
	_, respErr4a := bobHijack.AcceptDeviceBind(ctx, offer4a.DisplayCode, client.PairOptions{})
	wg.Wait()
	if !envelope.IsCode(respErr4a, envelope.ErrCodeSASMismatch) {
		t.Fatalf("expected responder ERR_SAS_MISMATCH when OnSASConfirm is nil, got %v", respErr4a)
	}
	if !envelope.IsCode(initErr4a, envelope.ErrCodeRoomBurned) {
		t.Fatalf("expected initiator ERR_ROOM_BURNED when responder rejects nil OnSASConfirm, got %v", initErr4a)
	}
	if devs, _ := bobHijackKS.ListDevices(); len(devs) != 0 {
		t.Fatalf("CRITICAL: peer DeviceCard saved despite nil OnSASConfirm: %+v", devs)
	}

	// 4b. AcceptDeviceBind where OnSASConfirm rejects even when Initiator enters SAS and sends pair_bind.
	offerCh4b := make(chan client.OfferReadyInfo, 1)
	sasCh4b := make(chan string, 1)
	var initErr4b error
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, initErr4b = alice.StartDeviceBind(ctx, client.PairOptions{
			Mode:         synccrypto.ModeCommitSAS,
			OnOfferReady: func(info client.OfferReadyInfo) { offerCh4b <- info },
			OnSASInput:   func() (string, error) { return <-sasCh4b, nil },
		})
	}()
	offer4b := <-offerCh4b
	_, respErr4b := bobHijack.AcceptDeviceBind(ctx, offer4b.DisplayCode, client.PairOptions{
		OnSASDisplay: func(sas string) { sasCh4b <- sas },
		OnSASConfirm: func(sas string) error { return errors.New("user spotted MITM SAS mismatch") },
	})
	wg.Wait()
	if !envelope.IsCode(respErr4b, envelope.ErrCodeSASMismatch) {
		t.Fatalf("expected responder ERR_SAS_MISMATCH when OnSASConfirm rejects, got %v", respErr4b)
	}
	if initErr4b == nil {
		t.Fatal("expected initiator StartDeviceBind to fail when responder rejects OnSASConfirm")
	}
	if devs, _ := bobHijackKS.ListDevices(); len(devs) != 0 {
		t.Fatalf("CRITICAL: peer DeviceCard saved despite rejected OnSASConfirm: %+v", devs)
	}

	// 4c. ReceiveOneShot where OnSASConfirm rejects MUST NEVER invoke ParcelHandler.
	offerCh4c := make(chan client.OfferReadyInfo, 1)
	sasCh4c := make(chan string, 1)
	handlerInvoked := false
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = alice.StartOneShotSend(ctx, envelope.ParcelText("com.yellowdking.e2e", "forged-mitm-payload"), client.PairOptions{
			Mode:         synccrypto.ModeCommitSAS,
			OnOfferReady: func(info client.OfferReadyInfo) { offerCh4c <- info },
			OnSASInput:   func() (string, error) { return <-sasCh4c, nil },
		})
	}()
	offer4c := <-offerCh4c
	_, respErr4c := bobHijack.ReceiveOneShot(ctx, offer4c.DisplayCode, func(p envelope.ReceivedParcel) error {
		handlerInvoked = true
		return nil
	}, client.ReceiveOptions{
		OnSASDisplay: func(sas string) { sasCh4c <- sas },
		OnSASConfirm: func(sas string) error { return errors.New("responder rejected SAS") },
	})
	wg.Wait()
	if !envelope.IsCode(respErr4c, envelope.ErrCodeSASMismatch) || handlerInvoked {
		t.Fatalf("expected ERR_SAS_MISMATCH with handlerInvoked=false, got err=%v invoked=%v", respErr4c, handlerInvoked)
	}
}
