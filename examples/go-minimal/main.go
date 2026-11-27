// Minimal Go SDK integration example (~40 lines of core logic, zero third-party dependencies).
//
// Run offline self-check:
//
//	go run ./examples/go-minimal --self-test
//
// Run against a live self-hosted relay (never pass #k= on command line!):
//
//	export SYNCTOOL_RELAY='synctool://relay?v=1&u=https%3A%2F%2F1.2.3.4%3A54843&pin=<64hex>#k=<key>'
//	export SYNCTOOL_CONFIG="$HOME/.config/synctool-notes-demo"
//	go run ./examples/go-minimal --to "My Desktop" --text "Hello from Go SDK"
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/yellowdking/synctool/sdk/go/client"
	"github.com/yellowdking/synctool/sdk/go/envelope"
)

func main() {
	selfTest := flag.Bool("self-test", false, "run offline SDK contract self-check")
	toDevice := flag.String("to", "", "target paired device_id or label")
	text := flag.String("text", "Hello from synctool Go SDK", "UTF-8 text note")
	filePath := flag.String("file", "", "optional attachment file path")
	outDir := flag.String("out", "./received", "directory to save pulled inbox attachments")
	flag.Parse()

	if *selfTest || (os.Getenv("SYNCTOOL_RELAY") == "" && os.Getenv("SYNCTOOL_RELAY_URI") == "") {
		p := envelope.ParcelText("com.example.notes", *text)
		safe := envelope.SanitizeFilename("..\\NUL.txt")
		red := envelope.RedactMessage("err synctool://relay?v=1&u=https%3A%2F%2F127.0.0.1%3A8443#k=SECRET_KEY_123456789012345678901234")
		fmt.Printf("ok: app=%s schema=%s safe_name=%s redacted=%s\n", p.AppID, p.Schema, safe, red)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// 1. Zero-boilerplate client from SYNCTOOL_RELAY + SYNCTOOL_CONFIG
	cli, err := client.NewFromEnv(client.Config{AppID: "com.example.notes"})
	if err != nil {
		fatalf(err)
	}
	defer cli.Close()

	// 2. Send encrypted parcel if --to is provided
	if *toDevice != "" {
		parcel := envelope.Parcel{
			AppID:         "com.example.notes",
			Schema:        "note.item.v1",
			InlinePayload: map[string]any{"text": *text},
		}
		if *filePath != "" {
			parcel.Blobs = []envelope.BlobInput{envelope.BlobFromFile("attachment", *filePath)}
		}
		card, err := client.ResolveDeviceByIDOrLabel(cli.KeyStoreHint(), *toDevice)
		if err != nil {
			// Or use cli.SendText(ctx, *toDevice, *text) for text-only!
			fatalf(err)
		}
		res, err := cli.SendToDevice(ctx, card.DeviceID, parcel, client.WithDeliveryMode(client.DeliveryAuto))
		if err != nil {
			fatalf(err)
		}
		fmt.Printf("sent msg_id=%s mode=%s (%d bytes)\n", res.MsgID, res.Mode, res.TotalBytes)
		return
	}

	// 3. Pull & burn unread inbox parcels (auto self-heals if nano memory-spool restarted!)
	previews, err := cli.ListInbox(ctx, "com.example.notes")
	if err != nil {
		fatalf(err)
	}
	for _, item := range previews {
		_, err := cli.FetchParcel(ctx, item.ItemID, func(p envelope.ReceivedParcel) error {
			fmt.Printf("received from %s: %v\n", p.Manifest.Sender.Label, p.Manifest.InlinePayload)
			for _, b := range p.Blobs {
				saved, err := b.SaveToDir(*outDir)
				if err != nil {
					return err
				}
				fmt.Printf("saved verified attachment: %s\n", saved)
			}
			return nil
		}, client.ReceiveOptions{})
		if err != nil {
			fatalf(err)
		}
	}
}

func fatalf(err error) {
	switch {
	case envelope.IsVersionMismatch(err):
		fmt.Fprintf(os.Stderr, "upgrade required: %v\n", err)
	case envelope.SuggestPipeMode(err):
		fmt.Fprintf(os.Stderr, "offline spool full/disabled (switch to DeliveryPipe): %v\n", err)
	case envelope.IsRetryable(err):
		fmt.Fprintf(os.Stderr, "transient error (safe to retry): %v\n", err)
	default:
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
	}
	os.Exit(envelope.ExitCode(err))
}
