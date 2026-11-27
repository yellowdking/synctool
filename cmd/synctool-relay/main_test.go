package main

import (
	"crypto/tls"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/yellowdking/synctool/internal/relay"
)

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
