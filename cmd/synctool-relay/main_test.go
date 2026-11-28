package main

import (
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yellowdking/synctool/internal/relay"
)

func captureStdout(t *testing.T, fn func() int) (int, string) {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	code := fn()
	_ = w.Close()
	os.Stdout = orig
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	_ = r.Close()
	return code, buf.String()
}

func TestCLIInitRotateAndHealthcheck(t *testing.T) {
	dir := t.TempDir()

	// 0. Test `version --json` subcommand.
	if code := run([]string{"version", "--json"}); code != 0 {
		t.Fatalf("version --json returned non-zero code: %d", code)
	}

	// 1. Test `init` subcommand generates access.key + 730-day self-signed cert.
	if code := run([]string{"init", "--data-dir", dir, "--public-host", "127.0.0.1", "--listen", "127.0.0.1:54843"}); code != 0 {
		t.Fatalf("init returned non-zero code: %d", code)
	}
	b1, err := relay.LoadCertBundle(filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem"))
	if err != nil {
		t.Fatalf("expected persisted cert after init: %v", err)
	}

	// 2. Corrupt cert.pem and verify `cert-rotate` self-heals and mints a fresh SPKI pin!
	if err := os.WriteFile(filepath.Join(dir, "cert.pem"), []byte("corrupted-pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := run([]string{"cert-rotate", "--data-dir", dir, "--public-host", "127.0.0.1", "--listen", "127.0.0.1:54843"}); code != 0 {
		t.Fatalf("cert-rotate self-heal returned non-zero code: %d", code)
	}
	b2, err := relay.LoadCertBundle(filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem"))
	if err != nil {
		t.Fatalf("expected rotated cert: %v", err)
	}
	if b1.SPKISHA256Hex == b2.SPKISHA256Hex {
		t.Fatal("expected cert-rotate to produce a new SPKI pin")
	}

	// 3. Spin up real TLS 1.3 server on ephemeral loopback port and verify `healthcheck` passes with SPKI pinning,
	//    and FAILS if an expired certificate is loaded!
	rawLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listenAddr := rawLn.Addr().String()

	cfg := relay.Config{
		ListenAddr:     listenAddr,
		PublicHost:     "127.0.0.1",
		Profile:        relay.ProfileNano,
		Spool:          relay.SpoolOff,
		TLSMode:        relay.TLSSelfSigned,
		DataDir:        dir,
		DisableMemTune: true,
	}
	rc, err := cfg.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	srv, err := relay.NewServer(rc, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	httpSrv := srv.NewHTTPServer()
	tlsLn := tls.NewListener(srv.WrapListener(rawLn), srv.Certs().TLSConfig())
	go func() { _ = httpSrv.Serve(tlsLn) }()
	defer httpSrv.Close()

	if code := run([]string{"healthcheck", "--data-dir", dir, "--listen", listenAddr, "--tls", "selfsigned"}); code != 0 {
		t.Fatalf("healthcheck against live TLS 1.3 relay failed with code %d", code)
	}

	// Mint an already-expired cert (created 800 days ago -> expired 70 days ago), reload server, and verify healthcheck rejects it!
	pastNow := time.Now().Add(-800 * 24 * time.Hour)
	if _, err := srv.Certs().RotateSelfSigned("127.0.0.1", pastNow); err != nil {
		t.Fatal(err)
	}
	if code := run([]string{"healthcheck", "--data-dir", dir, "--listen", listenAddr, "--tls", "selfsigned"}); code == 0 {
		t.Fatal("expected healthcheck to fail against expired self-signed TLS certificate")
	}
}

func TestCertRotateReuseKeyStageNextPromoteSANInheritanceAndCertHealthcheckSNI(t *testing.T) {
	dir := t.TempDir()

	// 1. Initialize with explicit IP + DNS SANs.
	code, initOut := captureStdout(t, func() int {
		return run([]string{"init", "--data-dir", dir, "--public-host", "203.0.113.42,sync.example.com", "--listen", "127.0.0.1:54843"})
	})
	if code != 0 {
		t.Fatalf("init failed: %d", code)
	}
	bInit, err := relay.LoadCertBundle(filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(initOut, "pin="+bInit.SPKISHA256Hex) {
		t.Fatalf("init output missing pin: %s", initOut)
	}

	// 2. `cert-rotate --reuse-key` WITHOUT `--public-host`: MUST keep identical SPKI pin AND inherit IP+DNS SANs!
	code, reuseOut := captureStdout(t, func() int {
		return run([]string{"cert-rotate", "--reuse-key", "--data-dir", dir, "--listen", "127.0.0.1:54843"})
	})
	if code != 0 {
		t.Fatalf("cert-rotate --reuse-key failed: %d", code)
	}
	bReuse, err := relay.LoadCertBundle(filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if bReuse.SPKISHA256Hex != bInit.SPKISHA256Hex {
		t.Fatalf("expected --reuse-key to preserve SPKI pin %s, got %s", bInit.SPKISHA256Hex, bReuse.SPKISHA256Hex)
	}
	inherited := relay.ExtractCertPublicHosts(bReuse.Leaf)
	if !strings.Contains(inherited, "203.0.113.42") || !strings.Contains(inherited, "sync.example.com") {
		t.Fatalf("expected cert-rotate without --public-host to inherit SANs, got %q", inherited)
	}
	if !strings.Contains(reuseOut, "https%3A%2F%2F203.0.113.42%3A54843") {
		t.Fatalf("expected URI origin to inherit primary public host 203.0.113.42, got:\n%s", reuseOut)
	}

	// 3. `cert-rotate --stage-next --print-uri=false` redacts #k=; `--stage-next` emits dual-pin `pin=<cur>,<next>#k=...`.
	rawKey, _ := os.ReadFile(filepath.Join(dir, "access.key"))
	secretKey := strings.TrimSpace(string(rawKey))

	code, redactedOut := captureStdout(t, func() int {
		return run([]string{"cert-rotate", "--stage-next", "--print-uri=false", "--data-dir", dir})
	})
	if code != 0 {
		t.Fatalf("cert-rotate --stage-next --print-uri=false failed: %d", code)
	}
	if strings.Contains(redactedOut, secretKey) || !strings.Contains(redactedOut, "#k=<redacted>") {
		t.Fatalf("--print-uri=false must redact secret access key! output:\n%s", redactedOut)
	}

	code, stageOut := captureStdout(t, func() int {
		return run([]string{"cert-rotate", "--stage-next", "--print-uri", "--data-dir", dir})
	})
	if code != 0 {
		t.Fatalf("cert-rotate --stage-next failed: %d", code)
	}
	bStaged, err := relay.LoadCertBundle(filepath.Join(dir, "tls-next.crt"), filepath.Join(dir, "tls-next.key"))
	if err != nil {
		t.Fatalf("expected staged tls-next.crt/key: %v", err)
	}
	if bStaged.SPKISHA256Hex == bReuse.SPKISHA256Hex {
		t.Fatal("expected staged cert to have a fresh SPKI pin")
	}
	// Active cert.pem MUST remain untouched before promotion!
	bStillActive, _ := relay.LoadCertBundle(filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem"))
	if bStillActive.SPKISHA256Hex != bReuse.SPKISHA256Hex {
		t.Fatal("--stage-next must not overwrite active cert.pem")
	}
	wantDualPin := "&pin=" + bReuse.SPKISHA256Hex + "," + bStaged.SPKISHA256Hex + "#k=" + secretKey
	if !strings.Contains(stageOut, wantDualPin) {
		t.Fatalf("expected dual-pin URI containing %q, got:\n%s", wantDualPin, stageOut)
	}

	// 4. `cert-rotate --promote-staged` atomically promotes staged cert/key and cleans up tls-next.*.
	code, promOut := captureStdout(t, func() int {
		return run([]string{"cert-rotate", "--promote-staged", "--data-dir", dir})
	})
	if code != 0 {
		t.Fatalf("cert-rotate --promote-staged failed: %d", code)
	}
	bPromoted, err := relay.LoadCertBundle(filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if bPromoted.SPKISHA256Hex != bStaged.SPKISHA256Hex || !strings.Contains(promOut, bStaged.SPKISHA256Hex) {
		t.Fatalf("expected promoted cert to match staged SPKI %s, got %s", bStaged.SPKISHA256Hex, bPromoted.SPKISHA256Hex)
	}
	if _, err := os.Stat(filepath.Join(dir, "tls-next.crt")); !os.IsNotExist(err) {
		t.Fatal("expected tls-next.crt removed after promotion")
	}
	if _, err := os.Stat(filepath.Join(dir, "tls-next.key")); !os.IsNotExist(err) {
		t.Fatal("expected tls-next.key removed after promotion")
	}

	// 5. Verify --tls=cert ServerName derivation from cert SAN and --public-host.
	certOnlyDir := t.TempDir()
	certFile := filepath.Join(certOnlyDir, "fullchain.pem")
	keyFile := filepath.Join(certOnlyDir, "privkey.pem")
	if _, err := relay.GenerateSelfSignedCert("sync.domain.example", time.Now(), certFile, keyFile); err != nil {
		t.Fatal(err)
	}
	if sn := relay.ResolveCertServerName("", ":54843", certFile); sn != "sync.domain.example" {
		t.Fatalf("expected ServerName derived from cert DNS SAN sync.domain.example, got %q", sn)
	}
	if sn := relay.ResolveCertServerName("https://override.example.com:443", ":54843", certFile); sn != "override.example.com" {
		t.Fatalf("expected ServerName derived from --public-host override.example.com, got %q", sn)
	}
}
