package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/yellowdking/synctool/sdk/go/client"
	synccrypto "github.com/yellowdking/synctool/sdk/go/crypto"
	"github.com/yellowdking/synctool/sdk/go/envelope"
)

var (
	version = "dev"
	commit  = "none"
)

type globalOpts struct {
	configDir     string
	relayRef      string
	relayFromArgv bool
	appID         string
	jsonMode      bool
	quiet         bool
}

type multiStringFlag []string

func (m *multiStringFlag) String() string { return strings.Join(*m, ",") }
func (m *multiStringFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}

func main() {
	rawArgs := append([]string(nil), os.Args[1:]...)
	scrubProcessArgs(os.Args)
	os.Exit(run(rawArgs, os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	opts, rest, err := parseGlobalFlags(args)
	if err != nil {
		return emitErr(opts, stdout, stderr, err)
	}
	if len(rest) == 0 || rest[0] == "-h" || rest[0] == "--help" || rest[0] == "help" {
		printUsage(stderr)
		return 0
	}

	sub := rest[0]
	subArgs := rest[1:]

	switch sub {
	case "init":
		err = cmdInit(ctx, opts, subArgs, stdin, stdout, stderr)
	case "ping":
		err = cmdPing(ctx, opts, subArgs, stdout, stderr)
	case "pair":
		err = cmdPair(ctx, opts, subArgs, stdin, stdout, stderr)
	case "send":
		err = cmdSend(ctx, opts, subArgs, stdin, stdout, stderr)
	case "recv":
		err = cmdRecv(ctx, opts, subArgs, stdin, stdout, stderr)
	case "inbox":
		err = cmdInbox(ctx, opts, subArgs, stdout, stderr)
	case "device":
		err = cmdDevice(ctx, opts, subArgs, stdout, stderr)
	case "version", "--version", "-v":
		err = cmdVersion(opts, subArgs, stdout)
	default:
		err = envelope.NewError(envelope.ErrCodeBadRequest, false, 0, fmt.Sprintf("unknown subcommand %q", sub), nil)
	}
	if err != nil {
		return emitErr(opts, stdout, stderr, err)
	}
	return 0
}

func defaultConfigDir() string {
	if envDir := strings.TrimSpace(os.Getenv(envConfig)); envDir != "" {
		return envDir
	}
	if d, err := os.UserConfigDir(); err == nil && d != "" {
		return filepath.Join(d, "synctool")
	}
	return filepath.Join(os.TempDir(), "synctool-config")
}

func defaultRelayRefFromEnv() string {
	if v := strings.TrimSpace(os.Getenv(envRelay)); v != "" {
		return v
	}
	return strings.TrimSpace(os.Getenv(envRelayURI))
}

func defaultAppID() string {
	if v := strings.TrimSpace(os.Getenv(envApp)); v != "" {
		return v
	}
	return "synctool.cli"
}

func parseGlobalFlags(args []string) (globalOpts, []string, error) {
	opts := globalOpts{
		configDir: defaultConfigDir(),
		relayRef:  defaultRelayRefFromEnv(),
		appID:     defaultAppID(),
	}
	i := 0
	for i < len(args) {
		a := args[i]
		if !strings.HasPrefix(a, "-") || a == "-" {
			break
		}
		if a == "--" {
			i++
			break
		}
		switch {
		case a == "--json":
			opts.jsonMode = true
			i++
		case a == "--quiet" || a == "-q":
			opts.quiet = true
			i++
		case a == "--config":
			if i+1 >= len(args) {
				return opts, nil, envelope.NewError(envelope.ErrCodeBadRequest, false, 0, "--config requires a directory", nil)
			}
			opts.configDir = args[i+1]
			i += 2
		case strings.HasPrefix(a, "--config="):
			opts.configDir = strings.TrimPrefix(a, "--config=")
			i++
		case a == "--relay":
			if i+1 >= len(args) {
				return opts, nil, envelope.NewError(envelope.ErrCodeBadRequest, false, 0, "--relay requires an id or alias", nil)
			}
			opts.relayRef = args[i+1]
			opts.relayFromArgv = true
			i += 2
		case strings.HasPrefix(a, "--relay="):
			opts.relayRef = strings.TrimPrefix(a, "--relay=")
			opts.relayFromArgv = true
			i++
		case a == "--app":
			if i+1 >= len(args) {
				return opts, nil, envelope.NewError(envelope.ErrCodeBadRequest, false, 0, "--app requires an app_id", nil)
			}
			opts.appID = args[i+1]
			i += 2
		case strings.HasPrefix(a, "--app="):
			opts.appID = strings.TrimPrefix(a, "--app=")
			i++
		case a == "-h" || a == "--help":
			return opts, []string{"help"}, nil
		default:
			// Stop at first unknown flag so subcommand can parse it.
			return opts, args[i:], nil
		}
	}
	return opts, args[i:], nil
}

func emitResult(opts globalOpts, stdout io.Writer, data any, human string) {
	if opts.jsonMode {
		_ = json.NewEncoder(stdout).Encode(map[string]any{
			"type": "result",
			"data": data,
		})
		return
	}
	if human != "" {
		_, _ = fmt.Fprintln(stdout, human)
	}
}

func emitEvent(opts globalOpts, stdout io.Writer, ev any) {
	if opts.jsonMode {
		_ = json.NewEncoder(stdout).Encode(ev)
	}
}

func emitErr(opts globalOpts, stdout, stderr io.Writer, err error) int {
	se, ok := envelope.AsSyncError(err)
	if !ok {
		se = envelope.WrapError(envelope.ErrCodeStorageIO, false, 0, redactSecretsInText(err.Error()), err)
	} else {
		se = sanitizeSyncError(se)
	}
	if opts.jsonMode {
		_ = json.NewEncoder(stdout).Encode(map[string]any{
			"type":  "error",
			"error": se,
		})
	} else {
		_, _ = fmt.Fprintf(stderr, "error [%s]: %s\n", se.Code, se.Message)
	}
	return envelope.ExitCode(se)
}

func openKeyStore(opts globalOpts) (*envelope.FileKeyStore, error) {
	if err := ensurePrivateDir(opts.configDir); err != nil {
		return nil, err
	}
	return envelope.NewFileKeyStore(opts.configDir)
}

func resolveRelayProfile(opts globalOpts, ks envelope.KeyStore, stderr io.Writer) (*envelope.RelayProfile, error) {
	ref := strings.TrimSpace(opts.relayRef)
	if ref != "" {
		if opts.relayFromArgv {
			warnSecretOnArgv(opts, stderr, ref)
		}
		if hasCaseInsensitivePrefix(ref, "synctool://") {
			return envelope.ParseRelayURI(ref)
		}
		prof, err := ks.GetRelayProfile(ref)
		if err != nil {
			return nil, err
		}
		if prof != nil {
			return prof, nil
		}
		return nil, envelope.NewError(envelope.ErrCodeKeystoreError, false, 0, fmt.Sprintf("relay profile %q not found in keystore", redactSecretsInText(ref)), nil)
	}
	return ks.GetDefaultRelayProfile()
}

func openClient(opts globalOpts, ks envelope.KeyStore, overrideProfile *envelope.RelayProfile, stdout, stderr io.Writer) (*client.Client, error) {
	prof := overrideProfile
	var err error
	if prof == nil {
		prof, err = resolveRelayProfile(opts, ks, stderr)
		if err != nil {
			return nil, err
		}
		if prof == nil {
			return nil, envelope.NewError(envelope.ErrCodeKeystoreError, false, 0, "no relay configured; run 'synctool init' or set SYNCTOOL_RELAY", nil)
		}
	}
	tmpDir := filepath.Join(opts.configDir, "tmp")
	if err := ensurePrivateDir(tmpDir); err != nil {
		return nil, err
	}
	return client.New(client.Config{
		AppID:    opts.appID,
		Relay:    prof,
		KeyStore: ks,
		TempDir:  tmpDir,
		OnCertExpiring: func(ev envelope.RelayCertExpiringEvent) {
			if opts.jsonMode {
				emitEvent(opts, stdout, ev)
			} else if !opts.quiet {
				_, _ = fmt.Fprintf(stderr, "warning: relay TLS cert expires in %d days (%s); run 'synctool-relay cert-rotate'\n", ev.DaysRemaining, ev.Severity)
			}
		},
	})
}

func readSecretLineFromBufio(br *bufio.Reader) (string, error) {
	line, err := br.ReadString('\n')
	if err != nil && len(line) == 0 {
		if err == io.EOF {
			return "", envelope.NewError(envelope.ErrCodeBadRequest, false, 0, "empty stdin input", nil)
		}
		return "", envelope.WrapError(envelope.ErrCodeStorageIO, false, 0, "read stdin", err)
	}
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return "", envelope.NewError(envelope.ErrCodeBadRequest, false, 0, "empty stdin input", nil)
	}
	return trimmed, nil
}

func readSecretLine(r io.Reader) (string, error) {
	if br, ok := r.(*bufio.Reader); ok {
		return readSecretLineFromBufio(br)
	}
	return readSecretLineFromBufio(bufio.NewReader(r))
}

func promptInitiatorSAS(opts globalOpts, br *bufio.Reader, stdout, stderr io.Writer) (string, error) {
	if opts.jsonMode {
		emitEvent(opts, stdout, map[string]any{
			"type":  "event",
			"event": "awaiting_sas",
			"role":  "initiator",
		})
	} else if !opts.quiet {
		_, _ = fmt.Fprint(stderr, "Enter 6-digit SAS shown on peer device: ")
	}
	line, err := br.ReadString('\n')
	if err != nil && len(line) == 0 {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

func confirmResponderSAS(opts globalOpts, br *bufio.Reader, stdout, stderr io.Writer, sas string) error {
	if opts.jsonMode {
		emitEvent(opts, stdout, map[string]any{
			"type":  "event",
			"event": "awaiting_sas",
			"sas":   sas,
			"role":  "responder",
		})
	} else if !opts.quiet {
		_, _ = fmt.Fprintf(stderr, "Confirm SAS %s %s matches initiator device [y/yes or 6-digit SAS]: ", sas[:3], sas[3:])
	}
	line, err := br.ReadString('\n')
	if err != nil && len(line) == 0 {
		return envelope.NewError(envelope.ErrCodeSASMismatch, false, 0, "SAS confirmation rejected (EOF)", nil)
	}
	ans := strings.TrimSpace(line)
	if strings.EqualFold(ans, "y") || strings.EqualFold(ans, "yes") || synccrypto.VerifySAS(sas, ans) == nil {
		return nil
	}
	return envelope.NewError(envelope.ErrCodeSASMismatch, false, 0, "SAS confirmation rejected", nil)
}

// --- Subcommands ---

func cmdInit(ctx context.Context, opts globalOpts, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	relayURI := fs.String("relay-uri", "", "synctool://relay URI")
	useStdin := fs.Bool("stdin", false, "read synctool://relay URI from stdin")
	useRelayStdin := fs.Bool("relay-stdin", false, "read synctool://relay URI from stdin (alias for --stdin)")
	alias := fs.String("alias", "", "optional alias for this relay")
	label := fs.String("label", "", "local device label")
	if err := fs.Parse(args); err != nil {
		return envelope.NewError(envelope.ErrCodeBadRequest, false, 0, err.Error(), nil)
	}

	br := bufio.NewReader(stdin)
	rawURI := strings.TrimSpace(*relayURI)
	switch {
	case *useStdin || *useRelayStdin:
		var err error
		rawURI, err = readSecretLineFromBufio(br)
		if err != nil {
			return err
		}
	case rawURI != "":
		warnSecretOnArgv(opts, stderr, rawURI)
	case fs.NArg() > 0:
		rawURI = strings.TrimSpace(fs.Arg(0))
		warnSecretOnArgv(opts, stderr, rawURI)
	default:
		envURI := strings.TrimSpace(os.Getenv(envRelayURI))
		if envURI == "" && hasCaseInsensitivePrefix(strings.TrimSpace(os.Getenv(envRelay)), "synctool://") {
			envURI = strings.TrimSpace(os.Getenv(envRelay))
		}
		if envURI != "" {
			rawURI = envURI
		} else {
			var err error
			rawURI, err = readSecretLineFromBufio(br)
			if err != nil {
				return err
			}
		}
	}

	prof, err := envelope.ParseRelayURI(rawURI)
	if err != nil {
		return err
	}
	prof.Alias = strings.TrimSpace(*alias)
	prof.IsDefault = true

	ks, err := openKeyStore(opts)
	if err != nil {
		return err
	}
	if _, err := ks.LoadOrCreateMasterSeed(); err != nil {
		return err
	}
	if strings.TrimSpace(*label) != "" {
		if err := ks.SetLocalLabel(*label); err != nil {
			return err
		}
	}

	cli, err := openClient(opts, ks, prof, stdout, stderr)
	if err != nil {
		return err
	}
	defer cli.Close()

	pingRes, err := cli.Ping(ctx)
	if err != nil {
		return err
	}
	caps, err := cli.Capabilities(ctx)
	if err != nil {
		return err
	}
	if caps.Spool.Enabled {
		if err := cli.EnsureMailboxRegistered(ctx); err != nil && !envelope.IsCode(err, envelope.ErrCodeSpoolDisabled) {
			return err
		}
	}
	if err := ks.SaveRelayProfile(*prof); err != nil {
		return err
	}

	devID, devLabel, _, _, mbID := cli.Identity()
	data := map[string]any{
		"device_id":     devID,
		"label":         devLabel,
		"relay_id":      prof.RelayID,
		"endpoint":      prof.Endpoint,
		"tls_mode":      prof.TLSMode,
		"profile":       pingRes.Profile,
		"spool_enabled": caps.Spool.Enabled,
		"spool_backend": caps.Spool.Backend,
		"mailbox_id":    mbID,
		"rtt_ms":        pingRes.RTTMs,
	}
	emitResult(opts, stdout, data, fmt.Sprintf("initialized device %s (%s) on relay %s [%s, spool=%s, rtt=%dms]", devID, devLabel, prof.Endpoint, pingRes.Profile, caps.Spool.Backend, pingRes.RTTMs))
	return nil
}

func cmdPing(ctx context.Context, opts globalOpts, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("ping", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	relayFlag := fs.String("relay", opts.relayRef, "relay id or alias")
	if err := fs.Parse(args); err != nil {
		return envelope.NewError(envelope.ErrCodeBadRequest, false, 0, err.Error(), nil)
	}
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "relay" {
			opts.relayFromArgv = true
		}
	})
	opts.relayRef = *relayFlag

	ks, err := openKeyStore(opts)
	if err != nil {
		return err
	}
	cli, err := openClient(opts, ks, nil, stdout, stderr)
	if err != nil {
		return err
	}
	defer cli.Close()

	pingRes, err := cli.Ping(ctx)
	if err != nil {
		return err
	}
	caps, err := cli.Capabilities(ctx)
	if err != nil {
		return err
	}
	data := map[string]any{
		"rtt_ms":                    pingRes.RTTMs,
		"profile":                   pingRes.Profile,
		"spool_enabled":             caps.Spool.Enabled,
		"spool_backend":             caps.Spool.Backend,
		"spool_max_item_bytes":      caps.Spool.MaxItemBytes,
		"blocks_per_chunk":          caps.Streaming.BlocksPerChunk,
		"max_transport_chunk_bytes": caps.Streaming.MaxTransportChunkBytes,
		"clock_offset_sec":          pingRes.ClockOffsetSec,
		"cert_expires_at":           pingRes.CertExpiresAt,
		"cert_rotate_recommended":   pingRes.CertRotateRecommended,
	}
	emitResult(opts, stdout, data, fmt.Sprintf("pong %dms profile=%s spool=%s(max=%dB) chunk=%dB clock_offset=%ds",
		pingRes.RTTMs, pingRes.Profile, caps.Spool.Backend, caps.Spool.MaxItemBytes, caps.Streaming.MaxTransportChunkBytes, pingRes.ClockOffsetSec))
	return nil
}

func cmdPair(ctx context.Context, opts globalOpts, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return envelope.NewError(envelope.ErrCodeBadRequest, false, 0, "pair requires subcommand: offer | accept", nil)
	}
	action := args[0]
	subArgs := args[1:]

	ks, err := openKeyStore(opts)
	if err != nil {
		return err
	}

	switch action {
	case "offer":
		fs := flag.NewFlagSet("pair offer", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		label := fs.String("label", "", "device label")
		modeStr := fs.String("mode", "qr", "qr | sas")
		includeRelay := fs.Bool("include-relay", false, "embed relay profile in pair URI")
		if err := fs.Parse(subArgs); err != nil {
			return envelope.NewError(envelope.ErrCodeBadRequest, false, 0, err.Error(), nil)
		}
		mode := synccrypto.ModeQROOB
		if *modeStr == "sas" {
			mode = synccrypto.ModeCommitSAS
		} else if *modeStr != "qr" {
			return envelope.NewError(envelope.ErrCodeBadRequest, false, 0, "mode must be qr or sas", nil)
		}
		cli, err := openClient(opts, ks, nil, stdout, stderr)
		if err != nil {
			return err
		}
		defer cli.Close()

		reader := bufio.NewReader(stdin)
		card, err := cli.StartDeviceBind(ctx, client.PairOptions{
			Mode:         mode,
			Label:        *label,
			IncludeRelay: *includeRelay,
			OnOfferReady: func(info client.OfferReadyInfo) {
				if opts.jsonMode {
					emitEvent(opts, stdout, map[string]any{
						"type":         "event",
						"event":        "offer_ready",
						"room_id":      info.RoomID,
						"display_code": info.DisplayCode,
						"mode":         info.Mode,
						"pair_uri":     info.PairURI,
						"expires_at":   info.ExpiresAt,
					})
				} else if !opts.quiet {
					if mode == synccrypto.ModeQROOB {
						_, _ = fmt.Fprintf(stderr, "Pair URI (scan or paste privately): %s\n", info.PairURI)
					} else {
						_, _ = fmt.Fprintf(stderr, "Room Code: %s (do NOT send SAS over the same chat!)\n", info.DisplayCode)
					}
				}
			},
			OnSASInput: func() (string, error) {
				return promptInitiatorSAS(opts, reader, stdout, stderr)
			},
		})
		if err != nil {
			return err
		}
		emitResult(opts, stdout, card, fmt.Sprintf("paired device %s (%s)", card.DeviceID, card.Label))
		return nil

	case "accept":
		fs := flag.NewFlagSet("pair accept", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		label := fs.String("label", "", "device label")
		useStdin := fs.Bool("stdin", false, "read pair URI or room code from stdin")
		if err := fs.Parse(subArgs); err != nil {
			return envelope.NewError(envelope.ErrCodeBadRequest, false, 0, err.Error(), nil)
		}
		reader := bufio.NewReader(stdin)
		var pairIn string
		switch {
		case *useStdin:
			pairIn, err = readSecretLineFromBufio(reader)
			if err != nil {
				return err
			}
		case fs.NArg() > 0:
			pairIn = strings.TrimSpace(fs.Arg(0))
			warnSecretOnArgv(opts, stderr, pairIn)
		case strings.TrimSpace(os.Getenv(envPairURI)) != "":
			pairIn = strings.TrimSpace(os.Getenv(envPairURI))
		default:
			return envelope.NewError(envelope.ErrCodeBadRequest, false, 0, "pair accept requires URI/room code, --stdin, or SYNCTOOL_PAIR_URI", nil)
		}
		var overrideProf *envelope.RelayProfile
		if p, ok, err := client.ParseRelayFromPairURI(pairIn); err != nil {
			return err
		} else if ok {
			overrideProf = p
		}
		cli, err := openClient(opts, ks, overrideProf, stdout, stderr)
		if err != nil {
			return err
		}
		defer cli.Close()

		card, err := cli.AcceptDeviceBind(ctx, pairIn, client.PairOptions{
			Label: *label,
			OnSASDisplay: func(sas string) {
				formatted := sas[:3] + " " + sas[3:]
				if opts.jsonMode {
					emitEvent(opts, stdout, map[string]any{"type": "event", "event": "sas_ready", "sas": sas})
				} else if !opts.quiet {
					_, _ = fmt.Fprintf(stderr, "Verify SAS on initiator device: %s\n", formatted)
				}
			},
			OnSASConfirm: func(sas string) error {
				return confirmResponderSAS(opts, reader, stdout, stderr, sas)
			},
		})
		if err != nil {
			return err
		}
		// Only persist embedded relay profile AFTER handshake + SAS + DeviceCard verification succeed!
		if overrideProf != nil {
			existingDefault, _ := ks.GetDefaultRelayProfile()
			overrideProf.IsDefault = existingDefault == nil
			if err := ks.SaveRelayProfile(*overrideProf); err != nil {
				return err
			}
		}
		emitResult(opts, stdout, card, fmt.Sprintf("paired device %s (%s)", card.DeviceID, card.Label))
		return nil

	default:
		return envelope.NewError(envelope.ErrCodeBadRequest, false, 0, "pair expects offer or accept", nil)
	}
}
