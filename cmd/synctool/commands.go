package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/yellowdking/synctool/sdk/go/client"
	synccrypto "github.com/yellowdking/synctool/sdk/go/crypto"
	"github.com/yellowdking/synctool/sdk/go/envelope"
)

func parseFileFlags(specs []string) ([]envelope.BlobInput, error) {
	out := make([]envelope.BlobInput, 0, len(specs))
	for _, s := range specs {
		path := s
		role := "file"
		// Support "<path>:<role>" while preserving Windows drive letters like "C:\foo\bar.mp4:video".
		if idx := strings.LastIndexByte(s, ':'); idx > 1 {
			candRole := s[idx+1:]
			if !strings.ContainsAny(candRole, `/\`) && len(candRole) > 0 && len(candRole) <= 32 {
				path = s[:idx]
				role = candRole
			}
		}
		if _, err := os.Stat(path); err != nil {
			return nil, envelope.WrapError(envelope.ErrCodeStorageIO, false, 0, "stat input file "+path, err)
		}
		out = append(out, envelope.BlobInput{
			Role:     role,
			Name:     filepath.Base(path),
			FilePath: path,
		})
	}
	return out, nil
}

func cmdSend(ctx context.Context, opts globalOpts, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("send", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	toDev := fs.String("to", "", "target paired device_id or label")
	oneshot := fs.Bool("oneshot", false, "one-shot anonymous Mode A transfer")
	schema := fs.String("schema", "generic.parcel.v1", "business schema identifier")
	textVal := fs.String("text", "", "inline UTF-8 text payload")
	inlineJSON := fs.String("inline-json", "", "JSON file path or '-' for stdin")
	modeStr := fs.String("mode", "", "paired: auto|spool|pipe; oneshot: qr|sas")
	includeRelay := fs.Bool("include-relay", false, "embed relay info in pair URI")
	var files multiStringFlag
	fs.Var(&files, "file", "file path (optional :role suffix), repeatable")
	if err := fs.Parse(args); err != nil {
		return envelope.NewError(envelope.ErrCodeBadRequest, false, 0, err.Error(), nil)
	}

	if (*toDev == "") == !*oneshot {
		return envelope.NewError(envelope.ErrCodeBadRequest, false, 0, "specify exactly one of --to <device> or --oneshot", nil)
	}

	// ST-P2-13: Strict --mode validation + stdin collision check BEFORE consuming stdin or opening network!
	hsMode := synccrypto.ModeQROOB
	deliveryMode := client.DeliveryAuto
	if *oneshot {
		m := strings.ToLower(strings.TrimSpace(*modeStr))
		if m == "" || m == "qr" {
			hsMode = synccrypto.ModeQROOB
		} else if m == "sas" {
			hsMode = synccrypto.ModeCommitSAS
		} else {
			return envelope.NewError(envelope.ErrCodeBadRequest, false, 0, fmt.Sprintf("invalid oneshot --mode %q (expected qr or sas)", *modeStr), nil)
		}
		if hsMode == synccrypto.ModeCommitSAS && *inlineJSON == "-" {
			return envelope.NewError(envelope.ErrCodeBadRequest, false, 0, "cannot combine --inline-json - with --oneshot --mode sas because both read from stdin; pass a JSON file path instead", nil)
		}
	} else {
		m := strings.ToLower(strings.TrimSpace(*modeStr))
		switch m {
		case "", "auto":
			deliveryMode = client.DeliveryAuto
		case "spool":
			deliveryMode = client.DeliverySpool
		case "pipe":
			deliveryMode = client.DeliveryPipe
		default:
			return envelope.NewError(envelope.ErrCodeBadRequest, false, 0, fmt.Sprintf("invalid paired --mode %q (expected auto, spool, or pipe)", *modeStr), nil)
		}
	}

	var inline map[string]any
	if *inlineJSON != "" {
		var raw []byte
		var err error
		exceedMsg := fmt.Sprintf("inline_payload exceeds %d bytes", envelope.MaxInlinePayloadBytes)
		if *inlineJSON == "-" {
			raw, err = readBoundedBytes(stdin, envelope.MaxInlinePayloadBytes, exceedMsg)
		} else {
			f, oerr := os.Open(*inlineJSON)
			if oerr != nil {
				return envelope.WrapError(envelope.ErrCodeStorageIO, false, 0, "read inline json", oerr)
			}
			raw, err = readBoundedBytes(f, envelope.MaxInlinePayloadBytes, exceedMsg)
			_ = f.Close()
		}
		if err != nil {
			return err
		}
		if err := json.Unmarshal(raw, &inline); err != nil {
			return envelope.WrapError(envelope.ErrCodeManifestInvalid, false, 0, "parse inline json", err)
		}
	} else if *textVal != "" {
		inline = map[string]any{"text": *textVal}
	}

	blobs, err := parseFileFlags(files)
	if err != nil {
		return err
	}
	parcel := envelope.ParcelInput{
		AppID:         opts.appID,
		Schema:        *schema,
		InlinePayload: inline,
		Blobs:         blobs,
	}

	ks, err := openKeyStore(opts)
	if err != nil {
		return err
	}
	cli, err := openClient(opts, ks, nil, stdout, stderr)
	if err != nil {
		return err
	}
	defer cli.Close()

	progressCB := func(ev envelope.TransferEvent) {
		if opts.jsonMode {
			emitEvent(opts, stdout, ev)
		}
	}

	if *oneshot {
		reader := bufio.NewReader(stdin)
		res, err := cli.StartOneShotSend(ctx, parcel, client.PairOptions{
			Mode:         hsMode,
			IncludeRelay: *includeRelay,
			OnOfferReady: func(info client.OfferReadyInfo) {
				if opts.jsonMode {
					emitEvent(opts, stdout, map[string]any{
						"type": "event", "event": "offer_ready", "room_id": info.RoomID, "display_code": info.DisplayCode, "pair_uri": info.PairURI,
					})
				} else if !opts.quiet {
					if hsMode == synccrypto.ModeQROOB {
						_, _ = fmt.Fprintf(stderr, "One-shot URI: %s\n", info.PairURI)
					} else {
						_, _ = fmt.Fprintf(stderr, "One-shot Room Code: %s\n", info.DisplayCode)
					}
				}
			},
			OnSASInput: func() (string, error) {
				return promptInitiatorSAS(opts, reader, stdout, stderr)
			},
			OnProgress: progressCB,
		})
		if err != nil {
			return err
		}
		emitResult(opts, stdout, res, fmt.Sprintf("sent oneshot parcel msg_id=%s (%d bytes)", res.MsgID, res.TotalBytes))
		return nil
	}

	card, err := client.ResolveDeviceByIDOrLabel(ks, *toDev)
	if err != nil {
		return err
	}
	res, err := cli.SendToDevice(ctx, card.DeviceID, parcel, client.SendOptions{
		DeliveryMode: deliveryMode,
		IncludeRelay: *includeRelay,
		OnOfferReady: func(info client.OfferReadyInfo) {
			if opts.jsonMode {
				emitEvent(opts, stdout, map[string]any{
					"type": "event", "event": "offer_ready", "room_id": info.RoomID, "display_code": info.DisplayCode, "pair_uri": info.PairURI,
				})
			} else if !opts.quiet {
				_, _ = fmt.Fprintf(stderr, "Direct Pipe Code: %s (%s)\n", info.DisplayCode, info.PairURI)
			}
		},
		OnProgress: progressCB,
	})
	if err != nil {
		return err
	}
	emitResult(opts, stdout, res, fmt.Sprintf("sent via %s msg_id=%s item_id=%s (%d bytes)", res.Mode, res.MsgID, res.ItemID, res.TotalBytes))
	return nil
}

func cmdRecv(ctx context.Context, opts globalOpts, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("recv", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	itemID := fs.String("item", "", "spool item_id to pull")
	appFilter := fs.String("app", "", "optional app_id filter when pulling spool --item")
	outDir := fs.String("out", ".", "output directory for verified attachments")
	useStdin := fs.Bool("stdin", false, "read pair URI or room code from stdin")
	if err := fs.Parse(args); err != nil {
		return envelope.NewError(envelope.ErrCodeBadRequest, false, 0, err.Error(), nil)
	}

	ks, err := openKeyStore(opts)
	if err != nil {
		return err
	}
	var savedFiles []string
	handler := func(p envelope.ReceivedParcel) error {
		files, err := saveReceivedParcelToOutDir(*outDir, p)
		if err != nil {
			return err
		}
		savedFiles = files
		return nil
	}
	progressCB := func(ev envelope.TransferEvent) {
		if opts.jsonMode {
			emitEvent(opts, stdout, ev)
		}
	}

	if *itemID != "" {
		cli, err := openClient(opts, ks, nil, stdout, stderr)
		if err != nil {
			return err
		}
		defer cli.Close()
		m, err := cli.FetchParcel(ctx, *itemID, handler, client.ReceiveOptions{
			AppID:      *appFilter,
			OnProgress: progressCB,
		})
		if err != nil {
			return err
		}
		emitResult(opts, stdout, map[string]any{"manifest": m, "files": savedFiles},
			fmt.Sprintf("received item=%s msg_id=%s app=%s blobs=%d", *itemID, m.MsgID, m.AppID, len(savedFiles)))
		return nil
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
		return envelope.NewError(envelope.ErrCodeBadRequest, false, 0, "recv requires <pair_uri_or_room_code>, --stdin, SYNCTOOL_PAIR_URI, or --item <id>", nil)
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

	m, err := cli.ReceiveFromRoom(ctx, pairIn, handler, client.ReceiveOptions{
		OnSASDisplay: func(sas string) {
			if opts.jsonMode {
				emitEvent(opts, stdout, map[string]any{"type": "event", "event": "sas_ready", "sas": sas})
			} else if !opts.quiet {
				_, _ = fmt.Fprintf(stderr, "Verify SAS on sender device: %s %s\n", sas[:3], sas[3:])
			}
		},
		OnSASConfirm: func(sas string) error {
			return confirmResponderSAS(opts, reader, stdout, stderr, sas)
		},
		OnProgress: progressCB,
	})
	if err != nil {
		return err
	}
	emitResult(opts, stdout, map[string]any{"manifest": m, "files": savedFiles},
		fmt.Sprintf("received msg_id=%s app=%s schema=%s blobs=%d", m.MsgID, m.AppID, m.Schema, len(savedFiles)))
	return nil
}

func isAppIDFilterMismatch(err error) bool {
	se, ok := envelope.AsSyncError(err)
	if !ok || se.Code != envelope.ErrCodeManifestInvalid || se.Details == nil {
		return false
	}
	_, hasParcelApp := se.Details["parcel_app_id"]
	return hasParcelApp
}

func cmdInbox(ctx context.Context, opts globalOpts, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return envelope.NewError(envelope.ErrCodeBadRequest, false, 0, "inbox requires subcommand: list | pull | watch", nil)
	}
	action := args[0]
	subArgs := args[1:]

	ks, err := openKeyStore(opts)
	if err != nil {
		return err
	}
	cli, err := openClient(opts, ks, nil, stdout, stderr)
	if err != nil {
		return err
	}
	defer cli.Close()

	switch action {
	case "list":
		fs := flag.NewFlagSet("inbox list", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		appFilter := fs.String("app", "", "filter by app_id")
		if err := fs.Parse(subArgs); err != nil {
			return envelope.NewError(envelope.ErrCodeBadRequest, false, 0, err.Error(), nil)
		}
		previews, err := cli.ListInbox(ctx, *appFilter)
		if err != nil {
			return err
		}
		var sb strings.Builder
		for _, p := range previews {
			fmt.Fprintf(&sb, "%s  from=%s  app=%s  schema=%s  blobs=%d  bytes=%d\n",
				p.ItemID, p.Manifest.Sender.Label, p.Manifest.AppID, p.Manifest.Schema, len(p.Manifest.Blobs), p.TotalBytes)
		}
		if len(previews) == 0 {
			sb.WriteString("(inbox empty)")
		}
		emitResult(opts, stdout, previews, strings.TrimRight(sb.String(), "\n"))
		return nil

	case "pull":
		fs := flag.NewFlagSet("inbox pull", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		appFilter := fs.String("app", "", "filter by app_id")
		all := fs.Bool("all", false, "pull all matching items")
		itemID := fs.String("item", "", "pull specific item_id")
		outDir := fs.String("out", ".", "output directory")
		if err := fs.Parse(subArgs); err != nil {
			return envelope.NewError(envelope.ErrCodeBadRequest, false, 0, err.Error(), nil)
		}
		var targetIDs []string
		if *itemID != "" {
			targetIDs = []string{*itemID}
		} else if *all {
			previews, err := cli.ListInbox(ctx, *appFilter)
			if err != nil {
				return err
			}
			for _, p := range previews {
				targetIDs = append(targetIDs, p.ItemID)
			}
		} else {
			return envelope.NewError(envelope.ErrCodeBadRequest, false, 0, "inbox pull requires --all or --item <id>", nil)
		}
		var results []map[string]any
		for _, id := range targetIDs {
			var files []string
			m, err := cli.FetchParcel(ctx, id, func(p envelope.ReceivedParcel) error {
				f, err := saveReceivedParcelToOutDir(*outDir, p)
				if err != nil {
					return err
				}
				files = f
				return nil
			}, client.ReceiveOptions{
				AppID: *appFilter,
				OnProgress: func(ev envelope.TransferEvent) {
					if opts.jsonMode {
						emitEvent(opts, stdout, ev)
					}
				},
			})
			if err != nil {
				return err
			}
			results = append(results, map[string]any{"item_id": id, "manifest": m, "files": files})
		}
		emitResult(opts, stdout, results, fmt.Sprintf("pulled and burned %d parcel(s)", len(results)))
		return nil

	case "watch":
		fs := flag.NewFlagSet("inbox watch", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		appFilter := fs.String("app", "", "filter by app_id")
		outDir := fs.String("out", ".", "output dir when --auto-pull is set")
		autoPull := fs.Bool("auto-pull", false, "automatically fetch and burn incoming items")
		if err := fs.Parse(subArgs); err != nil {
			return envelope.NewError(envelope.ErrCodeBadRequest, false, 0, err.Error(), nil)
		}
		return cli.WatchInbox(ctx, func(ev client.InboxWatchEvent) error {
			emitEvent(opts, stdout, map[string]any{"type": "event", "event": "new_item", "item": ev})
			if !opts.jsonMode {
				_, _ = fmt.Fprintf(stdout, "new_item %s (%d bytes)\n", ev.ItemID, ev.TotalBytes)
			}
			if *autoPull {
				var files []string
				m, err := cli.FetchParcel(ctx, ev.ItemID, func(p envelope.ReceivedParcel) error {
					saved, err := saveReceivedParcelToOutDir(*outDir, p)
					if err != nil {
						return err
					}
					files = saved
					return nil
				}, client.ReceiveOptions{
					AppID: *appFilter,
				})
				if err != nil {
					if *appFilter != "" && isAppIDFilterMismatch(err) {
						return nil
					}
					return err
				}
				emitEvent(opts, stdout, map[string]any{"type": "event", "event": "auto_pulled", "item_id": ev.ItemID, "msg_id": m.MsgID, "files": files})
			}
			return nil
		})

	default:
		return envelope.NewError(envelope.ErrCodeBadRequest, false, 0, "inbox expects list | pull | watch", nil)
	}
}

func cmdDevice(ctx context.Context, opts globalOpts, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return envelope.NewError(envelope.ErrCodeBadRequest, false, 0, "device requires subcommand: whoami | list | rename | revoke", nil)
	}
	action := args[0]
	subArgs := args[1:]

	ks, err := openKeyStore(opts)
	if err != nil {
		return err
	}

	switch action {
	case "whoami":
		seed, err := ks.LoadOrCreateMasterSeed()
		if err != nil {
			return err
		}
		dk, err := synccrypto.DeriveDeviceKeys(seed[:])
		clear(seed[:])
		if err != nil {
			return err
		}
		defer dk.Zero()
		label, _ := ks.GetLocalLabel()
		var mbID string
		if prof, _ := resolveRelayProfile(opts, ks, stderr); prof != nil {
			if mk, err := dk.DeriveMailboxKeys(prof.RelayID); err == nil {
				mbID = mk.MailboxID
				mk.Zero()
			}
		}
		data := map[string]any{
			"device_id":  dk.DeviceID,
			"label":      label,
			"sign_pk":    base64.RawURLEncoding.EncodeToString(dk.SignPub),
			"kem_pk":     base64.RawURLEncoding.EncodeToString(dk.KEMPubBytes[:]),
			"mailbox_id": mbID,
		}
		emitResult(opts, stdout, data, fmt.Sprintf("device_id=%s label=%q mailbox_id=%s", dk.DeviceID, label, mbID))
		return nil

	case "list":
		cards, err := ks.ListDevices()
		if err != nil {
			return err
		}
		// Strip outbound_deposit_token from display output.
		type safeCard struct {
			DeviceID    string `json:"device_id"`
			Label       string `json:"label"`
			Platform    string `json:"platform,omitempty"`
			PairedAt    int64  `json:"paired_at"`
			RelayOrigin string `json:"relay_origin,omitempty"`
		}
		out := make([]safeCard, 0, len(cards))
		var sb strings.Builder
		for _, c := range cards {
			out = append(out, safeCard{
				DeviceID:    c.DeviceID,
				Label:       c.Label,
				Platform:    c.Platform,
				PairedAt:    c.PairedAt,
				RelayOrigin: c.RelayOrigin,
			})
			fmt.Fprintf(&sb, "%s  %s  (%s)  paired=%s\n", c.DeviceID, c.Label, c.Platform, time.Unix(c.PairedAt, 0).UTC().Format(time.RFC3339))
		}
		if len(out) == 0 {
			sb.WriteString("(no paired devices)")
		}
		emitResult(opts, stdout, out, strings.TrimRight(sb.String(), "\n"))
		return nil

	case "rename":
		if len(subArgs) < 2 {
			return envelope.NewError(envelope.ErrCodeBadRequest, false, 0, "device rename requires <device_id> <new_label>", nil)
		}
		card, err := client.ResolveDeviceByIDOrLabel(ks, subArgs[0])
		if err != nil {
			return err
		}
		card.Label = strings.TrimSpace(subArgs[1])
		if err := ks.PutDevice(*card); err != nil {
			return err
		}
		emitResult(opts, stdout, map[string]any{"device_id": card.DeviceID, "label": card.Label},
			fmt.Sprintf("renamed %s -> %s", card.DeviceID, card.Label))
		return nil

	case "revoke":
		if len(subArgs) < 1 {
			return envelope.NewError(envelope.ErrCodeBadRequest, false, 0, "device revoke requires <device_id>", nil)
		}
		card, err := client.ResolveDeviceByIDOrLabel(ks, subArgs[0])
		if err != nil {
			// Also allow retrying revoke on an already locally-revoked tombstone awaiting relay delete.
			if existing, gerr := ks.GetDevice(subArgs[0]); gerr == nil && existing != nil && existing.Revoked {
				card = existing
			} else {
				return err
			}
		}
		cli, err := openClient(opts, ks, nil, stdout, stderr)
		if err != nil {
			// Fallback to local 2-phase tombstone if no relay configured.
			card.Revoked = true
			card.PendingTokenDelete = card.InboundTokenID != ""
			if card.PendingTokenDelete {
				if err := ks.PutDevice(*card); err != nil {
					return err
				}
				_ = ks.AddPendingTokenDelete(card.InboundTokenID)
			} else if err := ks.DeleteDevice(card.DeviceID); err != nil {
				return err
			}
			emitResult(opts, stdout, map[string]any{"device_id": card.DeviceID, "revoked": true},
				fmt.Sprintf("revoked device %s locally", card.DeviceID))
			return nil
		}
		defer cli.Close()
		if err := cli.RevokeDevice(ctx, card.DeviceID); err != nil {
			return err
		}
		emitResult(opts, stdout, map[string]any{"device_id": card.DeviceID, "revoked": true},
			fmt.Sprintf("revoked device %s (%s)", card.DeviceID, card.Label))
		return nil

	default:
		return envelope.NewError(envelope.ErrCodeBadRequest, false, 0, "device expects whoami | list | rename | revoke", nil)
	}
}

func cmdVersion(opts globalOpts, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("version", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonFlag := fs.Bool("json", opts.jsonMode, "output JSON")
	if err := fs.Parse(args); err != nil {
		return envelope.NewError(envelope.ErrCodeBadRequest, false, 0, err.Error(), nil)
	}
	opts.jsonMode = *jsonFlag
	data := map[string]any{
		"version": version,
		"commit":  commit,
	}
	emitResult(opts, stdout, data, fmt.Sprintf("synctool %s (commit %s)", version, commit))
	return nil
}

func printUsage(w io.Writer) {
	_, _ = fmt.Fprintln(w, `synctool — zero-trust on-demand encrypted sync CLI (v1)

Global flags & environment variables:
  --config <dir>     Keystore/state directory (0700; env: SYNCTOOL_CONFIG)
  --relay <id|alias> Active relay profile or URI (env: SYNCTOOL_RELAY / SYNCTOOL_RELAY_URI)
  --app <app_id>     Application namespace (default: synctool.cli; env: SYNCTOOL_APP)
  --json             Machine-readable JSON/NDJSON output on stdout
  --quiet, -q        Suppress non-essential stderr messages

Subcommands:
  init               Initialize device identity and connect to a relay (--stdin / --relay-stdin / SYNCTOOL_RELAY)
  ping               Check relay RTT, profile, spool switch, clock skew, and cert expiry
  pair offer|accept  Pair two devices (--stdin or SYNCTOOL_PAIR_URI recommended for accept)
  send               Send encrypted parcel (--to <device> | --oneshot, --text/--inline-json/--file)
  recv               Receive Mode A room transfer (--stdin / SYNCTOOL_PAIR_URI) or spool parcel (--item <id>)
  inbox list|pull|watch  Inspect, pull & burn, or watch Mode B encrypted inbox
  device whoami|list|rename|revoke  Manage local identity and trusted devices
  version            Print CLI version and git commit`)
}
