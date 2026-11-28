package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/yellowdking/synctool/internal/relay"
)

var (
	version = "dev"
	commit  = "none"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	sub := "serve"
	rest := args
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		sub = args[0]
		rest = args[1:]
	}

	switch sub {
	case "serve":
		return runServe(rest)
	case "init":
		return runInit(rest)
	case "cert-rotate":
		return runCertRotate(rest)
	case "healthcheck":
		return runHealthcheck(rest)
	case "version", "-v", "--version":
		jsonOut := false
		for _, a := range rest {
			if a == "--json" {
				jsonOut = true
			}
		}
		if jsonOut {
			b, _ := json.Marshal(map[string]any{
				"version":     version,
				"commit":      commit,
				"proto_v":     relay.ProtoVersion,
				"min_proto_v": relay.MinProtoVersion,
				"max_proto_v": relay.MaxProtoVersion,
			})
			fmt.Println(string(b))
			return 0
		}
		fmt.Printf("synctool-relay %s (%s)\n", version, commit)
		return 0
	case "help", "-h", "--help":
		printUsage()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n", sub)
		printUsage()
		return 2
	}
}

func printUsage() {
	fmt.Fprintln(os.Stderr, `synctool-relay — Zero-trust on-demand encrypted sync relay (synctool-v1)

Usage:
  synctool-relay [serve] [flags]        Start relay server (default)
  synctool-relay init [flags]           Generate private AccessKey, 730-day self-signed cert & onboarding URI
  synctool-relay cert-rotate [flags]    Rotate 730-day self-signed TLS certificate & print updated URI
  synctool-relay healthcheck [flags]    Probe local relay health (for Docker scratch HEALTHCHECK)
  synctool-relay version                Print version

Key Flags (env SYNCTOOL_* also supported):
  --listen             Listen address (default ":54843", env SYNCTOOL_LISTEN)
  --public-host        Public IP or domain for cert SAN & onboarding URI (env SYNCTOOL_PUBLIC_HOST)
  --profile            VPS preset: auto|nano|standard|media (default "auto", env SYNCTOOL_PROFILE)
  --spool              Offline spool backend: auto|off|memory|disk (default "auto", env SYNCTOOL_SPOOL)
  --tls                TLS mode: selfsigned|cert|off (default "selfsigned", env SYNCTOOL_TLS)
  --tls-cert           Certificate PEM path for --tls=cert (env SYNCTOOL_TLS_CERT)
  --tls-key            Private key PEM path for --tls=cert (env SYNCTOOL_TLS_KEY)
  --data-dir           State/cert/spool directory (default "/data", env SYNCTOOL_DATA_DIR)
  --access-key         Private relay access key >=32 chars (env SYNCTOOL_ACCESS_KEY)
  --trust-proxies      Comma-separated trusted reverse-proxy CIDRs (env SYNCTOOL_TRUSTED_PROXIES)
  --cors-origins       Comma-separated allowed CORS origins or * (env SYNCTOOL_CORS_ORIGINS)
  --max-bandwidth-mbps Optional global bandwidth cap in Mbps (env SYNCTOOL_MAX_BANDWIDTH_MBPS)

cert-rotate Flags:
  --reuse-key          Re-sign fresh 730-day cert reusing existing P-256 key (SPKI pin unchanged)
  --stage-next         Stage tls-next.crt / tls-next.key and output dual-pin URI (pin=<cur>,<next>)
  --promote-staged     Atomically promote staged tls-next.crt / tls-next.key to cert.pem / key.pem
  --print-uri          Include #k= onboarding URI in stdout (default true; false prints #k=<redacted>)`)
}

type extraCLIFlags struct {
	reuseKey      bool
	stageNext     bool
	promoteStaged bool
	printURI      bool
}

func parseConfigFlags(name string, args []string) (relay.Config, error) {
	cfg, _, err := parseConfigFlagsExt(name, args, false)
	return cfg, err
}

func parseConfigFlagsExt(name string, args []string, withRotateFlags bool) (relay.Config, extraCLIFlags, error) {
	var ext extraCLIFlags
	ext.printURI = true

	cfg, err := relay.LoadConfigFromEnv(relay.DefaultConfig())
	if err != nil {
		return cfg, ext, err
	}

	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	var (
		profileStr = string(cfg.Profile)
		spoolStr   = string(cfg.Spool)
		tlsStr     = string(cfg.TLSMode)
		proxiesStr = ""
		corsStr    = ""
	)
	fs.StringVar(&cfg.ListenAddr, "listen", cfg.ListenAddr, "listen address")
	fs.StringVar(&cfg.PublicHost, "public-host", cfg.PublicHost, "public IP or domain for SAN and onboarding URI")
	fs.StringVar(&profileStr, "profile", profileStr, "VPS profile: auto|nano|standard|media")
	fs.StringVar(&spoolStr, "spool", spoolStr, "offline spool mode: auto|off|memory|disk")
	fs.StringVar(&tlsStr, "tls", tlsStr, "TLS mode: selfsigned|cert|off")
	fs.StringVar(&cfg.TLSCertPath, "tls-cert", cfg.TLSCertPath, "TLS certificate PEM path")
	fs.StringVar(&cfg.TLSKeyPath, "tls-key", cfg.TLSKeyPath, "TLS private key PEM path")
	fs.StringVar(&cfg.DataDir, "data-dir", cfg.DataDir, "persistent data directory")
	fs.StringVar(&cfg.AccessKey, "access-key", cfg.AccessKey, "private relay access key (>=32 chars)")
	fs.StringVar(&proxiesStr, "trust-proxies", "", "comma-separated trusted proxy CIDRs")
	fs.StringVar(&corsStr, "cors-origins", "", "comma-separated allowed CORS origins or *")
	fs.Float64Var(&cfg.MaxBandwidthMbps, "max-bandwidth-mbps", cfg.MaxBandwidthMbps, "optional global bandwidth cap (Mbps)")
	fs.BoolVar(&ext.printURI, "print-uri", true, "print onboarding URI with #k= access key")
	if withRotateFlags {
		fs.BoolVar(&ext.reuseKey, "reuse-key", false, "re-sign fresh 730-day cert reusing existing ECDSA P-256 private key")
		fs.BoolVar(&ext.stageNext, "stage-next", false, "stage tls-next.crt and tls-next.key and print dual-pin URI")
		fs.BoolVar(&ext.promoteStaged, "promote-staged", false, "atomically promote staged tls-next.crt/key to active cert.pem/key.pem")
	}

	if err := fs.Parse(args); err != nil {
		return cfg, ext, err
	}
	cfg.Profile = relay.ProfileName(strings.ToLower(strings.TrimSpace(profileStr)))
	cfg.Spool = relay.SpoolBackend(strings.ToLower(strings.TrimSpace(spoolStr)))
	cfg.TLSMode = relay.TLSMode(strings.ToLower(strings.TrimSpace(tlsStr)))
	if strings.TrimSpace(proxiesStr) != "" {
		prefixes, perr := relay.ParseTrustedProxies(proxiesStr)
		if perr != nil {
			return cfg, ext, perr
		}
		cfg.TrustedProxies = prefixes
	}
	if strings.TrimSpace(corsStr) != "" {
		origins, cerr := relay.ParseCORSOrigins(corsStr)
		if cerr != nil {
			return cfg, ext, cerr
		}
		cfg.CORSOrigins = origins
	}
	cfg.ServerVersion = version
	return cfg, ext, nil
}

func isTTY(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return (info.Mode() & os.ModeCharDevice) != 0
}

func formatOutputRelayURI(origin, pinField, accessKey string, printURI bool) string {
	if printURI {
		return relay.BuildRelayURI(origin, pinField, accessKey)
	}
	return relay.BuildRedactedRelayURI(origin, pinField)
}

func runInit(args []string) int {
	cfg, ext, err := parseConfigFlagsExt("init", args, false)
	if err != nil {
		fmt.Fprintf(os.Stderr, "init error: %v\n", err)
		return 2
	}
	rc, err := cfg.Resolve()
	if err != nil {
		fmt.Fprintf(os.Stderr, "init config error: %v\n", err)
		return 1
	}
	cm, err := relay.NewCertManager(rc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "init cert error: %v\n", err)
		return 1
	}

	effectiveHost := strings.TrimSpace(rc.PublicHost)
	spkiHex := ""
	var expUnix int64
	if b := cm.Current(); b != nil {
		spkiHex = b.SPKISHA256Hex
		expUnix = b.ExpiresAt
		if effectiveHost == "" && b.Leaf != nil {
			effectiveHost = relay.ExtractCertPublicHosts(b.Leaf)
		}
	}
	origin := relay.CanonicalOrigin(effectiveHost, rc.ListenAddr, rc.TLSMode)
	uri := formatOutputRelayURI(origin, spkiHex, rc.AccessKey, ext.printURI)

	fmt.Printf("synctool-relay initialized (profile=%s, spool=%s, tls=%s)\n", rc.Preset.Name, rc.SpoolMode, rc.TLSMode)
	fmt.Printf("Data directory : %s\n", rc.DataDir)
	fmt.Printf("Origin         : %s\n", origin)
	if spkiHex != "" {
		fmt.Printf("SPKI SHA-256   : %s\n", spkiHex)
		fmt.Printf("Cert Expires   : %s (730-day leaf cert)\n", time.Unix(expUnix, 0).UTC().Format(time.RFC3339))
	}
	fmt.Println("")
	if ext.printURI {
		fmt.Println("Onboarding URI (KEEP SECRET — do NOT paste into public logs):")
	} else {
		fmt.Println("Onboarding URI (access key redacted; pass --print-uri to reveal #k=):")
	}
	fmt.Println(uri)
	return 0
}

func runCertRotate(args []string) int {
	cfg, ext, err := parseConfigFlagsExt("cert-rotate", args, true)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cert-rotate error: %v\n", err)
		return 2
	}
	modeCount := 0
	if ext.reuseKey {
		modeCount++
	}
	if ext.stageNext {
		modeCount++
	}
	if ext.promoteStaged {
		modeCount++
	}
	if modeCount > 1 {
		fmt.Fprintln(os.Stderr, "cert-rotate error: --reuse-key, --stage-next, and --promote-staged are mutually exclusive")
		return 2
	}

	rc, err := cfg.Resolve()
	if err != nil {
		fmt.Fprintf(os.Stderr, "cert-rotate config error: %v\n", err)
		return 1
	}
	if rc.TLSMode != relay.TLSSelfSigned {
		fmt.Fprintf(os.Stderr, "cert-rotate failed: only applies to --tls=selfsigned (current: %s)\n", rc.TLSMode)
		return 1
	}
	now := time.Now()

	if ext.stageNext {
		cur, next, serr := relay.StageNextSelfSignedCert(rc.DataDir, rc.PublicHost, now)
		if serr != nil {
			fmt.Fprintf(os.Stderr, "cert-rotate --stage-next failed: %v\n", serr)
			return 1
		}
		effectiveHost := strings.TrimSpace(rc.PublicHost)
		if effectiveHost == "" {
			effectiveHost = relay.ExtractCertPublicHosts(next.Leaf)
		}
		origin := relay.CanonicalOrigin(effectiveHost, rc.ListenAddr, rc.TLSMode)
		dualPin := cur.SPKISHA256Hex + "," + next.SPKISHA256Hex
		uri := formatOutputRelayURI(origin, dualPin, rc.AccessKey, ext.printURI)

		fmt.Printf("Staged next 730-day self-signed certificate in %s (%s / %s)\n", rc.DataDir, relay.StagedCertFileName, relay.StagedKeyFileName)
		fmt.Printf("Current SPKI SHA-256 : %s\n", cur.SPKISHA256Hex)
		fmt.Printf("Staged SPKI SHA-256  : %s\n", next.SPKISHA256Hex)
		fmt.Printf("Staged Expires At    : %s\n", time.Unix(next.ExpiresAt, 0).UTC().Format(time.RFC3339))
		fmt.Println("")
		fmt.Println("Zero-Downtime Dual-Pin Onboarding URI (import on clients BEFORE running --promote-staged):")
		fmt.Println(uri)
		return 0
	}

	if ext.promoteStaged {
		promoted, perr := relay.PromoteStagedCert(rc.DataDir, now)
		if perr != nil {
			fmt.Fprintf(os.Stderr, "cert-rotate --promote-staged failed: %v\n", perr)
			return 1
		}
		effectiveHost := strings.TrimSpace(rc.PublicHost)
		if effectiveHost == "" {
			effectiveHost = relay.ExtractCertPublicHosts(promoted.Leaf)
		}
		origin := relay.CanonicalOrigin(effectiveHost, rc.ListenAddr, rc.TLSMode)
		uri := formatOutputRelayURI(origin, promoted.SPKISHA256Hex, rc.AccessKey, ext.printURI)

		fmt.Printf("Promoted staged certificate to active cert.pem / key.pem in %s\n", rc.DataDir)
		fmt.Printf("Active SPKI SHA-256 : %s\n", promoted.SPKISHA256Hex)
		fmt.Printf("Active Expires At   : %s\n", time.Unix(promoted.ExpiresAt, 0).UTC().Format(time.RFC3339))
		fmt.Println("Send SIGHUP to running synctool-relay (or restart) to serve the promoted certificate.")
		fmt.Println("")
		fmt.Println("Active Onboarding URI:")
		fmt.Println(uri)
		return 0
	}

	var certPath, keyPath string
	if rc.DataDir != "" {
		certPath = filepath.Join(rc.DataDir, "cert.pem")
		keyPath = filepath.Join(rc.DataDir, "key.pem")
	}

	var b *relay.CertBundle
	if ext.reuseKey {
		b, err = relay.RotateSelfSignedReuseKey(rc.PublicHost, now, certPath, keyPath)
	} else {
		// Mint directly (inheriting SANs if old cert.pem is readable, or self-healing corrupted/expired files).
		b, err = relay.GenerateSelfSignedCert(rc.PublicHost, now, certPath, keyPath)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "cert-rotate failed: %v\n", err)
		return 1
	}

	effectiveHost := strings.TrimSpace(rc.PublicHost)
	if effectiveHost == "" && b.Leaf != nil {
		effectiveHost = relay.ExtractCertPublicHosts(b.Leaf)
	}
	origin := relay.CanonicalOrigin(effectiveHost, rc.ListenAddr, rc.TLSMode)
	uri := formatOutputRelayURI(origin, b.SPKISHA256Hex, rc.AccessKey, ext.printURI)
	if ext.reuseKey {
		fmt.Printf("Re-signed 730-day self-signed certificate in %s (reusing existing key; SPKI pin unchanged)\n", rc.DataDir)
	} else {
		fmt.Printf("Rotated 730-day self-signed certificate in %s\n", rc.DataDir)
	}
	fmt.Printf("SPKI SHA-256   : %s\n", b.SPKISHA256Hex)
	fmt.Printf("New Expires At : %s\n", time.Unix(b.ExpiresAt, 0).UTC().Format(time.RFC3339))
	fmt.Println("")
	fmt.Println("Updated Onboarding URI:")
	fmt.Println(uri)
	return 0
}

func runServe(args []string) int {
	cfg, err := parseConfigFlags("serve", args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "flag error: %v\n", err)
		return 2
	}
	rc, err := cfg.Resolve()
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		return 1
	}

	logger := log.New(os.Stderr, "[synctool-relay] ", log.LstdFlags|log.LUTC)
	for _, w := range rc.Warnings {
		logger.Printf("WARN: %s", w)
	}

	srv, err := relay.NewServer(rc, logger)
	if err != nil {
		logger.Printf("startup error: %v", err)
		return 1
	}
	defer srv.Close()

	// Security rule: NEVER log access_key to runtime logs.
	// Only display one-time onboarding URI if freshly generated AND stdout is an interactive TTY.
	if rc.KeyCreated && isTTY(os.Stdout) {
		origin := relay.CanonicalOrigin(rc.PublicHost, rc.ListenAddr, rc.TLSMode)
		spkiHex := ""
		if b := srv.Certs().Current(); b != nil {
			spkiHex = b.SPKISHA256Hex
		}
		fmt.Fprintf(os.Stdout, "\n[first-run TTY only] Onboarding URI:\n%s\n\n", relay.BuildRelayURI(origin, spkiHex, rc.AccessKey))
	}

	exp, rot := srv.Certs().Status(time.Now())
	if rot {
		logger.Printf("WARN: TLS certificate expires at %s (<30 days remaining); run 'synctool-relay cert-rotate'", time.Unix(exp, 0).UTC().Format(time.RFC3339))
	}

	rawLn, err := net.Listen("tcp", rc.ListenAddr)
	if err != nil {
		logger.Printf("listen %s failed: %v", rc.ListenAddr, err)
		return 1
	}
	ln := srv.WrapListener(rawLn)
	httpSrv := srv.NewHTTPServer()

	stopReload := watchCertReload(srv.Certs(), logger)
	defer stopReload()

	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	errCh := make(chan error, 1)
	go func() {
		logger.Printf("listening on %s (profile=%s spool=%s tls=%s chunk=%dB)",
			rc.ListenAddr, rc.Preset.Name, rc.SpoolMode, rc.TLSMode, rc.Preset.MaxTransportChunkBytes)
		if rc.TLSMode == relay.TLSOff {
			errCh <- httpSrv.Serve(ln)
		} else {
			tlsLn := tls.NewListener(ln, httpSrv.TLSConfig)
			errCh <- httpSrv.Serve(tlsLn)
		}
	}()

	select {
	case sig := <-sigCh:
		logger.Printf("received signal %s, shutting down...", sig)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(ctx)
		return 0
	case serveErr := <-errCh:
		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			logger.Printf("server error: %v", serveErr)
			return 1
		}
		return 0
	}
}

func resolveHealthcheckTarget(listenAddr string, tlsMode relay.TLSMode) string {
	host, port, err := net.SplitHostPort(listenAddr)
	if err != nil {
		port = "54843"
	}
	if port == "" {
		port = "54843"
	}
	trimmed := strings.Trim(host, "[]")
	targetHost := "127.0.0.1"
	if trimmed != "" && trimmed != "0.0.0.0" && trimmed != "::" {
		targetHost = trimmed
	}
	scheme := "https"
	if tlsMode == relay.TLSOff {
		scheme = "http"
	}
	return fmt.Sprintf("%s://%s/v1/ping", scheme, net.JoinHostPort(targetHost, port))
}

func runHealthcheck(args []string) int {
	cfg, err := parseConfigFlags("healthcheck", args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "healthcheck flag error: %v\n", err)
		return 2
	}

	targetURL := resolveHealthcheckTarget(cfg.ListenAddr, cfg.TLSMode)

	// Load access key (must already exist via env or dataDir/access.key).
	accessKey := strings.TrimSpace(cfg.AccessKey)
	if accessKey == "" && cfg.DataDir != "" {
		if raw, rerr := os.ReadFile(filepath.Join(cfg.DataDir, "access.key")); rerr == nil {
			accessKey = strings.TrimSpace(string(raw))
			clear(raw)
		}
	}
	if len(accessKey) < 32 {
		fmt.Fprintln(os.Stderr, "healthcheck failed: access key unavailable")
		return 1
	}

	transport := &http.Transport{
		DialContext: (&net.Dialer{Timeout: 3 * time.Second}).DialContext,
	}
	if cfg.TLSMode == relay.TLSSelfSigned {
		// Pin strictly to local cert.pem SPKI SHA-256 (never skip verification!).
		certPath := filepath.Join(cfg.DataDir, "cert.pem")
		keyPath := filepath.Join(cfg.DataDir, "key.pem")
		bundle, lerr := relay.LoadCertBundle(certPath, keyPath)
		if lerr != nil {
			fmt.Fprintf(os.Stderr, "healthcheck failed: cannot load local cert for pinning: %v\n", lerr)
			return 1
		}
		expectedPin := bundle.SPKISHA256Hex
		transport.TLSClientConfig = &tls.Config{
			MinVersion:         tls.VersionTLS13,
			InsecureSkipVerify: true, // Strictly verified in VerifyPeerCertificate against SPKI pin.
			VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
				if len(rawCerts) == 0 {
					return errors.New("empty peer certificate")
				}
				leaf, perr := x509.ParseCertificate(rawCerts[0])
				if perr != nil {
					return perr
				}
				now := time.Now()
				if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
					return errors.New("TLS certificate expired or not yet valid")
				}
				if !relay.ConstantTimeStringEqual(relay.SPKISHA256Hex(leaf), expectedPin) {
					return errors.New("SPKI pin mismatch")
				}
				return nil
			},
		}
	} else if cfg.TLSMode == relay.TLSCert {
		serverName := relay.ResolveCertServerName(cfg.PublicHost, cfg.ListenAddr, cfg.TLSCertPath)
		transport.TLSClientConfig = &tls.Config{
			MinVersion: tls.VersionTLS13,
			ServerName: serverName,
		}
	}

	req, err := http.NewRequest(http.MethodGet, targetURL, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "healthcheck request error: %v\n", err)
		return 1
	}

	nonceBytes := make([]byte, 16)
	_, _ = rand.Read(nonceBytes)
	nonceHex := hex.EncodeToString(nonceBytes)
	tsStr := strconv.FormatInt(time.Now().Unix(), 10)
	hmacKey := relay.DeriveRelayHMACKey(accessKey)
	sig := relay.ComputeRelaySig(hmacKey, http.MethodGet, "/v1/ping", tsStr, nonceHex, relay.EmptyBodySHA256Binding, "")
	clear(hmacKey[:])

	req.Header.Set(relay.HeaderSyncClient, "synctool-healthcheck/1.0")
	req.Header.Set(relay.HeaderSyncTS, tsStr)
	req.Header.Set(relay.HeaderSyncNonce, nonceHex)
	req.Header.Set(relay.HeaderSyncSig, sig)

	client := &http.Client{
		Transport: transport,
		Timeout:   5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "healthcheck failed: %v\n", err)
		return 1
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "healthcheck failed: HTTP %d\n", resp.StatusCode)
		return 1
	}
	return 0
}
