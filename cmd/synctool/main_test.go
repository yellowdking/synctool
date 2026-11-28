package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/yellowdking/synctool/sdk/go/client"
	synccrypto "github.com/yellowdking/synctool/sdk/go/crypto"
	"github.com/yellowdking/synctool/sdk/go/envelope"
)

func TestCLIWhoamiAndDeviceListJSON(t *testing.T) {
	cfgDir := t.TempDir()
	var stdout, stderr bytes.Buffer

	code := run([]string{"--config", cfgDir, "--json", "device", "whoami"}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("whoami exit=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	var res struct {
		Type string         `json:"type"`
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &res); err != nil {
		t.Fatalf("unmarshal json: %v (%s)", err, stdout.String())
	}
	if res.Type != "result" {
		t.Fatalf("expected type=result, got %+v", res)
	}
	devID, _ := res.Data["device_id"].(string)
	if len(devID) != 32 {
		t.Fatalf("expected 32-hex device_id, got %q", devID)
	}
	if strings.Contains(stdout.String(), "master_seed") || strings.Contains(stdout.String(), "sign_sk") {
		t.Fatal("CLI output must never contain private keys or master seed")
	}

	// Verify exit code 2 on invalid relay URI
	stdout.Reset()
	stderr.Reset()
	code = run([]string{"--config", cfgDir, "--json", "init", "--stdin"}, strings.NewReader("synctool://relay?v=1&u=https%3A%2F%2F1.2.3.4%3A54843#k=0123456789abcdef0123456789abcdef\n"), &stdout, &stderr)
	if code != 2 {
		t.Fatalf("expected exit code 2 for bare IP without pin, got %d stdout=%s", code, stdout.String())
	}
	if !strings.Contains(stdout.String(), "ERR_URI_INVALID") {
		t.Fatalf("expected ERR_URI_INVALID in json stdout, got %s", stdout.String())
	}
}

func TestCLIVersionCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"version"}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 || !strings.Contains(stdout.String(), version) || !strings.Contains(stdout.String(), commit) {
		t.Fatalf("version text failed code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}

	for _, argv := range [][]string{{"--json", "version"}, {"version", "--json"}} {
		stdout.Reset()
		stderr.Reset()
		code = run(argv, strings.NewReader(""), &stdout, &stderr)
		if code != 0 {
			t.Fatalf("%v exit=%d stderr=%s", argv, code, stderr.String())
		}
		var res struct {
			Type string `json:"type"`
			Data struct {
				Version string `json:"version"`
				Commit  string `json:"commit"`
			} `json:"data"`
		}
		if err := json.Unmarshal(stdout.Bytes(), &res); err != nil {
			t.Fatalf("%v unmarshal: %v (%s)", argv, err, stdout.String())
		}
		if res.Type != "result" || res.Data.Version != version || res.Data.Commit != commit {
			t.Fatalf("%v unexpected output: %+v", argv, res)
		}
	}
}

func TestCLISecretRedactionAndArgvScrubbing(t *testing.T) {
	argv := []string{
		"synctool",
		"init",
		"synctool://relay?v=1&u=http%3A%2F%2F127.0.0.1%3A8080#k=SECRET_ACCESS_KEY_123",
		"synctool://pair?v=1&s=SECRET_QUERY_TYPO#s=SECRET_OOB_456",
		"--json",
	}
	scrubProcessArgs(argv)
	joined := strings.Join(argv, " ")
	if strings.Contains(joined, "SECRET_") {
		t.Fatalf("scrubProcessArgs leaked secret in argv: %q", joined)
	}
	if argv[1] != "init" || argv[4] != "--json" {
		t.Fatalf("scrubProcessArgs altered non-secret arguments: %v", argv)
	}

	samples := []string{
		"bad uri synctool://relay?v=1&u=https%3A%2F%2Fexample.com#k=TOPSECRET_K",
		"auth failed for https://admin:TOPSECRET_PW@relay.example.com:443/v1/ping#TOPSECRET_FRAG",
		"typo synctool://pair?v=1&k=TOPSECRET_QK&r=01234567#s=TOPSECRET_S",
		"standalone fragment #s=TOPSECRET_RAW in error",
	}
	for _, s := range samples {
		got := redactSecretsInText(s)
		if strings.Contains(got, "TOPSECRET") {
			t.Fatalf("redactSecretsInText(%q) leaked secret: %q", s, got)
		}
	}

	// Passing secret URI on CLI argv: warning MUST go to stderr ONLY so --json stdout stays parseable,
	// and error output MUST NOT leak the secret!
	cfgDir := t.TempDir()
	var stdout, stderr bytes.Buffer
	badArgURI := "synctool://relay?v=1&u=https%3A%2F%2F1.2.3.4%3A8443#k=MY_SUPER_SECRET_KEY_999"
	code := run([]string{"--config", cfgDir, "--json", "init", badArgURI}, strings.NewReader(""), &stdout, &stderr)
	if code == 0 {
		t.Fatal("expected init with unpinned IP URI to fail")
	}
	if strings.Contains(stdout.String(), "MY_SUPER_SECRET_KEY_999") || strings.Contains(stderr.String(), "MY_SUPER_SECRET_KEY_999") {
		t.Fatalf("secret leaked in stdout=%q or stderr=%q", stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "warning:") {
		t.Fatalf("expected argv secret warning on stderr, got %q", stderr.String())
	}
	var errEnv map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &errEnv); err != nil {
		t.Fatalf("expected --json stdout to remain pure valid JSON despite stderr warning, got %q (%v)", stdout.String(), err)
	}

	// --quiet suppresses the stderr argv warning.
	stdout.Reset()
	stderr.Reset()
	_ = run([]string{"--config", cfgDir, "--json", "--quiet", "init", badArgURI}, strings.NewReader(""), &stdout, &stderr)
	if stderr.Len() != 0 {
		t.Fatalf("expected --quiet to suppress stderr warning, got %q", stderr.String())
	}
}

func TestCLIEnvVarsAndRelayStdin(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/v1/ping":
			_ = json.NewEncoder(w).Encode(map[string]any{"server_ts": time.Now().Unix(), "profile": "lite"})
		case r.URL.Path == "/v1/caps":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"spool":     map[string]any{"enabled": true, "backend": "memory", "max_item_bytes": 67108864},
				"streaming": map[string]any{"blocks_per_chunk": 4, "max_transport_chunk_bytes": 262208},
			})
		case strings.HasPrefix(r.URL.Path, "/v1/mailboxes/"):
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	relayURI := fmt.Sprintf("synctool://relay?v=1&u=%s&insecure=1#k=0123456789abcdef0123456789abcdef", url.QueryEscape(srv.URL))
	cfgDir := filepath.Join(t.TempDir(), "env-cfg")
	t.Setenv(envConfig, cfgDir)
	t.Setenv(envApp, "acme.notes.v1")
	t.Setenv(envRelay, relayURI)

	opts, _, err := parseGlobalFlags(nil)
	if err != nil {
		t.Fatal(err)
	}
	if opts.configDir != cfgDir || opts.appID != "acme.notes.v1" || opts.relayRef != relayURI {
		t.Fatalf("unexpected env globalOpts: %+v", opts)
	}

	// Stateless SYNCTOOL_RELAY URI resolves mailbox_id in `device whoami` without prior `init`.
	var stdout, stderr bytes.Buffer
	if code := run([]string{"--json", "device", "whoami"}, strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("whoami with SYNCTOOL_RELAY failed: code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	var who struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &who); err != nil {
		t.Fatal(err)
	}
	mbID, _ := who.Data["mailbox_id"].(string)
	if len(mbID) != 32 {
		t.Fatalf("expected 32-hex mailbox_id from SYNCTOOL_RELAY, got %q", mbID)
	}

	// `init --relay-stdin` initializes cleanly without exposing URI in argv.
	t.Setenv(envRelay, "")
	initCfg := filepath.Join(t.TempDir(), "stdin-cfg")
	stdout.Reset()
	stderr.Reset()
	code := run([]string{"--config", initCfg, "--json", "init", "--relay-stdin", "--label", "workstation"}, strings.NewReader(relayURI+"\n"), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("init --relay-stdin failed: code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected zero stderr warnings for --relay-stdin, got %q", stderr.String())
	}
}

func TestCLISanitizeFilenameAndSafeParcelSave(t *testing.T) {
	cases := map[string]string{
		"../../evil/clip.mp4":     "clip.mp4",
		"..\\..\\evil\\clip.mp4":  "clip.mp4",
		"...":                     "blob.bin",
		" . . ":                   "blob.bin",
		"":                        "blob.bin",
		"NUL":                     "_NUL",
		"con.txt":                 "_con.txt",
		"COM1.tar.gz":             "_COM1.tar.gz",
		"lpt9":                    "_lpt9",
		"LPT\u00b9.log":           "_LPT\u00b9.log",
		"NUL .txt":                "_NUL .txt",
		"_NUL.txt":                "_NUL.txt", // idempotent when SDK already sanitized
		"invoice_\u202egnp.exe":   "invoice_gnp.exe",
		"clean\x00\x1fname.json":  "cleanname.json",
		"bad:chars*in?file|a.txt": "bad_chars_in_file_a.txt",
	}
	for in, want := range cases {
		if got := sanitizeOutputFilename(in); got != want {
			t.Fatalf("sanitizeOutputFilename(%q) = %q, want %q", in, got, want)
		}
	}

	longUTF8 := strings.Repeat("测", 100) + ".pdf"
	trunc := sanitizeOutputFilename(longUTF8)
	if len(trunc) > maxSafeFilenameBytes || !utf8.ValidString(trunc) || !strings.HasSuffix(trunc, ".pdf") {
		t.Fatalf("UTF-8 truncation broken: len=%d valid=%v val=%q", len(trunc), utf8.ValidString(trunc), trunc)
	}

	// Exclusive non-clobbering save: existing files MUST NEVER be overwritten!
	outDir := filepath.Join(t.TempDir(), "downloads")
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		t.Fatal(err)
	}
	origPath := filepath.Join(outDir, "report.txt")
	if err := os.WriteFile(origPath, []byte("ORIGINAL_DO_NOT_CLOBBER"), 0o600); err != nil {
		t.Fatal(err)
	}

	makeTempBlob := func(content string) string {
		p := filepath.Join(t.TempDir(), "verified.part")
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}

	saved1, err := saveReceivedParcelToOutDir(outDir, envelope.ReceivedParcel{
		Blobs: []envelope.ReceivedBlob{{
			Descriptor: envelope.BlobDescriptor{Name: "../../report.txt"},
			SafeName:   "../../report.txt",
			SafePath:   makeTempBlob("NEW_CONTENT_1"),
		}},
	})
	if err != nil || len(saved1) != 1 || filepath.Base(saved1[0]) != "report_1.txt" {
		t.Fatalf("expected non-clobbering report_1.txt, got %v err=%v", saved1, err)
	}

	saved2, err := saveReceivedParcelToOutDir(outDir, envelope.ReceivedParcel{
		Blobs: []envelope.ReceivedBlob{{
			Descriptor: envelope.BlobDescriptor{Name: "report.txt"},
			SafeName:   "report.txt",
			SafePath:   makeTempBlob("NEW_CONTENT_2"),
		}},
	})
	if err != nil || len(saved2) != 1 || filepath.Base(saved2[0]) != "report_2.txt" {
		t.Fatalf("expected non-clobbering report_2.txt, got %v err=%v", saved2, err)
	}

	origGot, _ := os.ReadFile(origPath)
	if string(origGot) != "ORIGINAL_DO_NOT_CLOBBER" {
		t.Fatalf("existing file was clobbered! got %q", origGot)
	}
	got1, _ := os.ReadFile(saved1[0])
	got2, _ := os.ReadFile(saved2[0])
	if string(got1) != "NEW_CONTENT_1" || string(got2) != "NEW_CONTENT_2" {
		t.Fatalf("unexpected saved contents: %q / %q", got1, got2)
	}

	// Symlink defense test (runs whenever OS/privilege allows creating symlinks).
	victim := filepath.Join(t.TempDir(), "victim.txt")
	_ = os.WriteFile(victim, []byte("VICTIM_SAFE"), 0o600)
	trapLink := filepath.Join(outDir, "trap.txt")
	if symErr := os.Symlink(victim, trapLink); symErr == nil {
		savedTrap, err := saveReceivedParcelToOutDir(outDir, envelope.ReceivedParcel{
			Blobs: []envelope.ReceivedBlob{{
				Descriptor: envelope.BlobDescriptor{Name: "trap.txt"},
				SafeName:   "trap.txt",
				SafePath:   makeTempBlob("ATTACKER_PAYLOAD"),
			}},
		})
		if err != nil || filepath.Base(savedTrap[0]) != "trap_1.txt" {
			t.Fatalf("expected symlink collision to deflect to trap_1.txt, got %v err=%v", savedTrap, err)
		}
		vBytes, _ := os.ReadFile(victim)
		if string(vBytes) != "VICTIM_SAFE" {
			t.Fatalf("symlink target was overwritten! got %q", vBytes)
		}
	}
}

func TestCLISendInlineJSONSizeLimit(t *testing.T) {
	cfgDir := t.TempDir()
	oversized := `{"pad":"` + strings.Repeat("A", envelope.MaxInlinePayloadBytes+128) + `"}`
	bigFile := filepath.Join(t.TempDir(), "huge.json")
	if err := os.WriteFile(bigFile, []byte(oversized), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, arg := range []string{bigFile, "-"} {
		var stdout, stderr bytes.Buffer
		code := run([]string{"--config", cfgDir, "--json", "send", "--oneshot", "--inline-json", arg}, strings.NewReader(oversized), &stdout, &stderr)
		if code != 2 || !strings.Contains(stdout.String(), "ERR_MANIFEST_INVALID") {
			t.Fatalf("inline-json=%s expected exit=2 ERR_MANIFEST_INVALID, got code=%d stdout=%s stderr=%s", arg, code, stdout.String(), stderr.String())
		}
	}
}

func TestCLIPairAcceptDoesNotPersistUntrustedRelayOnFailure(t *testing.T) {
	cfgDir := t.TempDir()
	pairURI := "synctool://pair?v=1&r=01234567&m=1&u=http%3A%2F%2F127.0.0.1%3A1&insecure=1#s=00112233445566778899aabbccddeeff&k=fedcba9876543210fedcba9876543210"
	var stdout, stderr bytes.Buffer
	code := run([]string{"--config", cfgDir, "--json", "pair", "accept", "--stdin"}, strings.NewReader(pairURI+"\n"), &stdout, &stderr)
	if code == 0 {
		t.Fatal("expected pair accept against closed port to fail")
	}
	ks, err := envelope.NewFileKeyStore(cfgDir)
	if err != nil {
		t.Fatal(err)
	}
	defProf, err := ks.GetDefaultRelayProfile()
	if err != nil {
		t.Fatal(err)
	}
	profs, err := ks.ListRelayProfiles()
	if err != nil {
		t.Fatal(err)
	}
	if defProf != nil || len(profs) != 0 {
		t.Fatalf("unauthenticated embedded relay profile must NOT be saved on failed pair accept: default=%+v list=%+v", defProf, profs)
	}
}

type miniSpoolItem struct {
	ItemID       string                `json:"item_id"`
	SealedHeader string                `json:"sealed_header"`
	TotalBytes   int64                 `json:"total_bytes"`
	CreatedAt    int64                 `json:"created_at"`
	ExpiresAt    int64                 `json:"expires_at"`
	Parts        []envelope.PartLayout `json:"parts"`
	chunks       map[string][]byte
	acked        bool
}

func TestCLIInboxWatchAutoPullAppFilterProtectsOtherApps(t *testing.T) {
	var mu sync.Mutex
	items := make(map[string]*miniSpoolItem)
	var itemOrder []string
	ackTargetCh := make(chan struct{}, 1)
	seq := 0

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/v1/ping":
			_ = json.NewEncoder(w).Encode(map[string]any{"server_ts": time.Now().Unix(), "profile": "lite"})
		case r.URL.Path == "/v1/caps":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"spool":     map[string]any{"enabled": true, "backend": "memory", "max_item_bytes": 67108864},
				"streaming": map[string]any{"blocks_per_chunk": 4, "max_transport_chunk_bytes": 262208},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/spool/init":
			var body struct {
				DeclaredTotalBytes int64                 `json:"declared_total_bytes"`
				SealedHeader       string                `json:"sealed_header"`
				Parts              []envelope.PartLayout `json:"parts"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			mu.Lock()
			seq++
			id := fmt.Sprintf("it_%d", seq)
			now := time.Now().Unix()
			items[id] = &miniSpoolItem{
				ItemID:       id,
				SealedHeader: body.SealedHeader,
				TotalBytes:   body.DeclaredTotalBytes,
				CreatedAt:    now,
				ExpiresAt:    now + 3600,
				Parts:        body.Parts,
				chunks:       make(map[string][]byte),
			}
			itemOrder = append(itemOrder, id)
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{
				"item_id":           id,
				"upload_token":      "uptok_" + id,
				"upload_expires_at": now + 600,
				"expires_at":        now + 3600,
			})
		case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/v1/spool/"):
			// /v1/spool/{id}/parts/{p}/chunks/{c}
			segs := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/spool/"), "/")
			raw, _ := io.ReadAll(r.Body)
			mu.Lock()
			items[segs[0]].chunks[segs[2]+":"+segs[4]] = raw
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/commit"):
			_ = json.NewEncoder(w).Encode(map[string]any{"expires_at": time.Now().Unix() + 3600})
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/items"):
			mu.Lock()
			var list []*miniSpoolItem
			for _, id := range itemOrder {
				if it := items[id]; it != nil && !it.acked {
					list = append(list, it)
				}
			}
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{"items": list})
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/spool/"):
			segs := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/spool/"), "/")
			mu.Lock()
			data := items[segs[0]].chunks[segs[2]+":"+segs[4]]
			mu.Unlock()
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write(data)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/ack"):
			id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/spool/"), "/ack")
			mu.Lock()
			if it := items[id]; it != nil {
				it.acked = true
			}
			mu.Unlock()
			if id == "it_2" {
				select {
				case ackTargetCh <- struct{}{}:
				default:
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/events"):
			w.Header().Set("Content-Type", "text/event-stream")
			flusher, _ := w.(http.Flusher)
			mu.Lock()
			orderCopy := append([]string(nil), itemOrder...)
			mu.Unlock()
			for _, id := range orderCopy {
				mu.Lock()
				it := items[id]
				mu.Unlock()
				evJSON, _ := json.Marshal(map[string]any{
					"item_id":     it.ItemID,
					"created_at":  it.CreatedAt,
					"expires_at":  it.ExpiresAt,
					"total_bytes": it.TotalBytes,
				})
				_, _ = fmt.Fprintf(w, "event: new_item\ndata: %s\n\n", evJSON)
			}
			if flusher != nil {
				flusher.Flush()
			}
			<-r.Context().Done()
		default:
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
		}
	}))
	defer srv.Close()

	parsedProf, err := envelope.ParseRelayURI(fmt.Sprintf("synctool://relay?v=1&u=%s&insecure=1#k=0123456789abcdef0123456789abcdef", url.QueryEscape(srv.URL)))
	if err != nil {
		t.Fatal(err)
	}
	parsedProf.IsDefault = true
	prof := *parsedProf

	setupPeer := func(dir, label string) (*envelope.FileKeyStore, *synccrypto.DeviceKeys, *synccrypto.MailboxKeys) {
		ks, err := envelope.NewFileKeyStore(dir)
		if err != nil {
			t.Fatal(err)
		}
		_ = ks.SaveRelayProfile(prof)
		_ = ks.SetLocalLabel(label)
		seed, _ := ks.LoadOrCreateMasterSeed()
		dk, _ := synccrypto.DeriveDeviceKeys(seed[:])
		clear(seed[:])
		mk, _ := dk.DeriveMailboxKeys(prof.RelayID)
		return ks, dk, mk
	}

	aliceDir := t.TempDir()
	bobDir := t.TempDir()
	aliceKS, aliceDK, aliceMK := setupPeer(aliceDir, "alice")
	defer aliceDK.Zero()
	defer aliceMK.Zero()
	bobKS, bobDK, bobMK := setupPeer(bobDir, "bob")
	defer bobDK.Zero()
	defer bobMK.Zero()

	now := time.Now().Unix()
	aliceSig, _ := synccrypto.SignDeviceCard(aliceDK.SignPriv, aliceDK.KEMPubBytes[:], now)
	bobSig, _ := synccrypto.SignDeviceCard(bobDK.SignPriv, bobDK.KEMPubBytes[:], now)
	_ = aliceKS.PutDevice(envelope.DeviceCard{
		DeviceID:             bobDK.DeviceID,
		Label:                "bob",
		SignPK:               base64.RawURLEncoding.EncodeToString(bobDK.SignPub),
		KEMPK:                base64.RawURLEncoding.EncodeToString(bobDK.KEMPubBytes[:]),
		IssuedAt:             now,
		CardSig:              base64.RawURLEncoding.EncodeToString(bobSig),
		MailboxID:            bobMK.MailboxID,
		OutboundDepositToken: "dep_token_bob",
		PairedAt:             now,
	})
	_ = bobKS.PutDevice(envelope.DeviceCard{
		DeviceID: aliceDK.DeviceID,
		Label:    "alice",
		SignPK:   base64.RawURLEncoding.EncodeToString(aliceDK.SignPub),
		KEMPK:    base64.RawURLEncoding.EncodeToString(aliceDK.KEMPubBytes[:]),
		IssuedAt: now,
		CardSig:  base64.RawURLEncoding.EncodeToString(aliceSig),
		PairedAt: now,
	})

	// 1. Alice deposits it_1 for "other.app" (MUST NOT be pulled or burned by --app target.app!).
	cliOther, err := client.New(client.Config{AppID: "other.app", Relay: &prof, KeyStore: aliceKS})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cliOther.SendToDevice(context.Background(), bobDK.DeviceID, envelope.ParcelInput{
		AppID:         "other.app",
		Schema:        "other.v1",
		InlinePayload: map[string]any{"msg": "keep-untouched"},
	}, client.SendOptions{DeliveryMode: "spool"}); err != nil {
		t.Fatalf("send other.app parcel: %v", err)
	}
	cliOther.Close()

	// 2. Alice deposits it_2 for "target.app" with an attachment.
	srcAttachment := filepath.Join(t.TempDir(), "note.txt")
	if err := os.WriteFile(srcAttachment, []byte("VERIFIED_TARGET_APP_BLOB"), 0o600); err != nil {
		t.Fatal(err)
	}
	cliTarget, err := client.New(client.Config{AppID: "target.app", Relay: &prof, KeyStore: aliceKS})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cliTarget.SendToDevice(context.Background(), bobDK.DeviceID, envelope.ParcelInput{
		AppID:         "target.app",
		Schema:        "target.v1",
		InlinePayload: map[string]any{"msg": "pull-me"},
		Blobs:         []envelope.BlobInput{{Role: "file", Name: "note.txt", FilePath: srcAttachment}},
	}, client.SendOptions{DeliveryMode: "spool"}); err != nil {
		t.Fatalf("send target.app parcel: %v", err)
	}
	cliTarget.Close()

	// 3. Bob runs `inbox watch --auto-pull --app target.app --out <outDir>`.
	watchCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() {
		select {
		case <-ackTargetCh:
			cancel()
		case <-watchCtx.Done():
		}
	}()

	outDir := filepath.Join(t.TempDir(), "pulled")
	var stdout, stderr bytes.Buffer
	watchErr := cmdInbox(watchCtx, globalOpts{
		configDir: bobDir,
		appID:     "target.app",
		jsonMode:  true,
	}, []string{"watch", "--auto-pull", "--app", "target.app", "--out", outDir}, &stdout, &stderr)
	if watchErr != nil && !envelope.IsCode(watchErr, envelope.ErrCodeCancelled) {
		t.Fatalf("inbox watch unexpected error: %v (stderr=%s)", watchErr, stderr.String())
	}

	mu.Lock()
	it1Acked := items["it_1"].acked
	it2Acked := items["it_2"].acked
	mu.Unlock()

	if it1Acked {
		t.Fatal("CRITICAL: inbox watch --auto-pull --app target.app burned non-matching other.app parcel (it_1)!")
	}
	if !it2Acked {
		t.Fatal("expected matching target.app parcel (it_2) to be auto-pulled and ACKed")
	}
	gotBlob, err := os.ReadFile(filepath.Join(outDir, "note.txt"))
	if err != nil || string(gotBlob) != "VERIFIED_TARGET_APP_BLOB" {
		t.Fatalf("expected verified attachment in outDir, got %q err=%v", gotBlob, err)
	}
}

func TestCLIV030_ModeStrictness_StdinSASGuard_RelayArgvWarn_And_ResponderSASGate(t *testing.T) {
	cfgDir := t.TempDir()
	var stdout, stderr bytes.Buffer

	// 1. ST-P2-13: --oneshot --mode sas --inline-json - MUST fail with exit code 2 (ERR_BAD_REQUEST) BEFORE reading stdin!
	code := run([]string{"--config", cfgDir, "--json", "send", "--oneshot", "--mode", "sas", "--inline-json", "-"}, strings.NewReader(`{"a":1}`), &stdout, &stderr)
	if code != 2 || !strings.Contains(stdout.String(), "ERR_BAD_REQUEST") {
		t.Fatalf("expected exit=2 ERR_BAD_REQUEST for --inline-json - + --mode sas, got code=%d stdout=%s", code, stdout.String())
	}

	// 2. ST-P2-13: Invalid --mode values MUST fail strictly with exit code 2!
	for _, argv := range [][]string{
		{"--config", cfgDir, "--json", "send", "--oneshot", "--mode", "auto", "--text", "hi"},
		{"--config", cfgDir, "--json", "send", "--oneshot", "--mode", "typo", "--text", "hi"},
		{"--config", cfgDir, "--json", "send", "--to", "some-dev", "--mode", "qr", "--text", "hi"},
		{"--config", cfgDir, "--json", "send", "--to", "some-dev", "--mode", "typo", "--text", "hi"},
	} {
		stdout.Reset()
		stderr.Reset()
		if c := run(argv, strings.NewReader(""), &stdout, &stderr); c != 2 || !strings.Contains(stdout.String(), "ERR_BAD_REQUEST") {
			t.Fatalf("expected exit=2 ERR_BAD_REQUEST for %v, got code=%d stdout=%s", argv, c, stdout.String())
		}
	}

	// 3. ST-P2-10: Passing secret URI via global --relay flag emits stderr warning (unless --quiet) and never leaks secret!
	stdout.Reset()
	stderr.Reset()
	badRelayArg := "synctool://relay?v=1&u=https%3A%2F%2F1.2.3.4%3A8443#k=SECRET_GLOBAL_RELAY_ARG_777"
	code = run([]string{"--config", cfgDir, "--relay", badRelayArg, "--json", "ping"}, strings.NewReader(""), &stdout, &stderr)
	if code == 0 {
		t.Fatal("expected unpinned bare IP --relay to fail")
	}
	if strings.Contains(stdout.String(), "SECRET_GLOBAL_RELAY_ARG_777") || strings.Contains(stderr.String(), "SECRET_GLOBAL_RELAY_ARG_777") {
		t.Fatalf("secret leaked in stdout=%q or stderr=%q", stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "warning:") {
		t.Fatalf("expected stderr warning when passing secret URI to --relay, got %q", stderr.String())
	}

	// 4. ST-P0-1: CLI `pair accept` in Flow 1B (mode=2 SAS) emits sas_ready + awaiting_sas (role=responder),
	// rejects "no" without saving DeviceCard, and succeeds on "y"!
	var mu sync.Mutex
	type cliRoom struct {
		msgs  []map[string]any
		state string
	}
	rooms := make(map[string]*cliRoom)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/v1/ping":
			_ = json.NewEncoder(w).Encode(map[string]any{"proto_v": 1, "server_ts": time.Now().Unix(), "profile": "nano", "spool_backend": "off"})
		case r.URL.Path == "/v1/caps":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"proto_v":   1,
				"spool":     map[string]any{"enabled": false, "backend": "off"},
				"streaming": map[string]any{"enabled": true, "blocks_per_chunk": 4, "max_transport_chunk_bytes": 262208},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/rooms":
			var req struct {
				RoomID        string `json:"room_id"`
				InitialMsgB64 string `json:"initial_msg_b64"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			mu.Lock()
			rooms[req.RoomID] = &cliRoom{
				state: "waiting",
				msgs:  []map[string]any{{"seq": 1, "from": "sender", "kind": "handshake", "msg_b64": req.InitialMsgB64}},
			}
			mu.Unlock()
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"room_id": req.RoomID, "pipe_id": "p_" + req.RoomID, "sender_token": "stok", "expires_at": time.Now().Unix() + 300, "seq": 1})
		case strings.HasPrefix(r.URL.Path, "/v1/rooms/"):
			segs := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/rooms/"), "/")
			rid, act := segs[0], segs[1]
			mu.Lock()
			rm := rooms[rid]
			mu.Unlock()
			if rm == nil {
				w.WriteHeader(http.StatusNotFound)
				_ = json.NewEncoder(w).Encode(map[string]any{"error": "ERR_NOT_FOUND"})
				return
			}
			switch act {
			case "join":
				mu.Lock()
				rm.state = "joined"
				msgs := append([]map[string]any(nil), rm.msgs...)
				mu.Unlock()
				_ = json.NewEncoder(w).Encode(map[string]any{"room_id": rid, "pipe_id": "p_" + rid, "receiver_token": "rtok", "expires_at": time.Now().Unix() + 300, "seq": len(msgs), "messages": msgs})
			case "messages":
				from := "receiver"
				if r.Header.Get(synccrypto.HeaderRoomToken) == "stok" {
					from = "sender"
				}
				var req struct {
					Kind   string `json:"kind"`
					MsgB64 string `json:"msg_b64"`
				}
				_ = json.NewDecoder(r.Body).Decode(&req)
				mu.Lock()
				if rm.state == "burned" {
					mu.Unlock()
					w.WriteHeader(http.StatusGone)
					_ = json.NewEncoder(w).Encode(map[string]any{"error": "ERR_ROOM_BURNED"})
					return
				}
				seq := len(rm.msgs) + 1
				rm.msgs = append(rm.msgs, map[string]any{"seq": seq, "from": from, "kind": req.Kind, "msg_b64": req.MsgB64})
				mu.Unlock()
				_ = json.NewEncoder(w).Encode(map[string]any{"seq": seq})
			case "events":
				if r.URL.Query().Get("mode") == "sse" {
					w.WriteHeader(http.StatusNotImplemented)
					return
				}
				var since int
				_, _ = fmt.Sscanf(r.URL.Query().Get("since"), "%d", &since)
				deadline := time.Now().Add(2 * time.Second)
				for time.Now().Before(deadline) {
					mu.Lock()
					var out []map[string]any
					for _, m := range rm.msgs {
						if m["seq"].(int) > since {
							out = append(out, m)
						}
					}
					st := rm.state
					seq := len(rm.msgs)
					mu.Unlock()
					if len(out) > 0 || st == "burned" || st == "closed" {
						_ = json.NewEncoder(w).Encode(map[string]any{"state": st, "seq": seq, "messages": out})
						return
					}
					time.Sleep(15 * time.Millisecond)
				}
				mu.Lock()
				_ = json.NewEncoder(w).Encode(map[string]any{"state": rm.state, "seq": len(rm.msgs), "messages": []any{}})
				mu.Unlock()
			case "close":
				var req struct {
					Reason string `json:"reason"`
				}
				_ = json.NewDecoder(r.Body).Decode(&req)
				mu.Lock()
				if req.Reason == "verify_failed" || req.Reason == "rejected" {
					rm.state = "burned"
				} else {
					rm.state = "closed"
				}
				mu.Unlock()
				_ = json.NewEncoder(w).Encode(map[string]any{"state": "closed"})
			}
		}
	}))
	defer srv.Close()

	relayURI := fmt.Sprintf("synctool://relay?v=1&u=%s#k=%s", url.QueryEscape(srv.URL), strings.Repeat("K", 43))
	aliceCfg := t.TempDir()
	bobCfg := t.TempDir()
	for _, d := range []string{aliceCfg, bobCfg} {
		var o, e bytes.Buffer
		if c := run([]string{"--config", d, "--json", "init", "--stdin"}, strings.NewReader(relayURI+"\n"), &o, &e); c != 0 {
			t.Fatalf("init %s failed: %s %s", d, o.String(), e.String())
		}
	}

	aliceKS, _ := envelope.NewFileKeyStore(aliceCfg)
	prof, _ := aliceKS.GetDefaultRelayProfile()
	aliceCli, _ := client.New(client.Config{AppID: "synctool.cli", DeviceLabel: "Alice", Relay: prof, KeyStore: aliceKS})
	defer aliceCli.Close()

	// Case A: Responder types "no" -> exit code 4 (ERR_SAS_MISMATCH) and 0 devices saved!
	codeChA := make(chan string, 1)
	sasChA := make(chan string, 1)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = aliceCli.StartDeviceBind(context.Background(), client.PairOptions{
			Mode:         synccrypto.ModeCommitSAS,
			OnOfferReady: func(info client.OfferReadyInfo) { codeChA <- info.DisplayCode },
			OnSASInput:   func() (string, error) { return <-sasChA, nil },
		})
	}()
	roomCodeA := <-codeChA
	close(sasChA) // empty -> initiator rejects or sees burned room
	stdout.Reset()
	stderr.Reset()
	exitReject := run([]string{"--config", bobCfg, "--json", "pair", "accept", "--stdin"}, strings.NewReader(roomCodeA+"\nno\n"), &stdout, &stderr)
	wg.Wait()
	if exitReject != 4 || !strings.Contains(stdout.String(), "ERR_SAS_MISMATCH") || !strings.Contains(stdout.String(), `"event":"awaiting_sas"`) {
		t.Fatalf("expected exit=4 ERR_SAS_MISMATCH with awaiting_sas event on 'no', got exit=%d stdout=%s stderr=%s", exitReject, stdout.String(), stderr.String())
	}
	bobKSCheck, _ := envelope.NewFileKeyStore(bobCfg)
	if devs, _ := bobKSCheck.ListDevices(); len(devs) != 0 {
		t.Fatalf("Bob saved DeviceCard despite rejecting SAS in CLI: %+v", devs)
	}

	// Case B: Responder types "yes" (via shared --stdin reader after room code!) -> exit code 0!
	codeChB := make(chan string, 1)
	sasFromStdout := make(chan string, 1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = aliceCli.StartDeviceBind(context.Background(), client.PairOptions{
			Mode:         synccrypto.ModeCommitSAS,
			OnOfferReady: func(info client.OfferReadyInfo) { codeChB <- info.DisplayCode },
			OnSASInput:   func() (string, error) { return <-sasFromStdout, nil },
		})
	}()
	roomCodeB := <-codeChB
	pr, pw := io.Pipe()
	var acceptOut, acceptErr bytes.Buffer
	acceptDone := make(chan int, 1)
	go func() {
		mw := io.MultiWriter(&acceptOut, pw)
		c := run([]string{"--config", bobCfg, "--json", "pair", "accept", "--stdin"}, strings.NewReader(roomCodeB+"\nyes\n"), mw, &acceptErr)
		_ = pw.Close()
		acceptDone <- c
	}()
	go func() {
		defer pr.Close()
		dec := json.NewDecoder(pr)
		for {
			var ev map[string]any
			if err := dec.Decode(&ev); err != nil {
				return
			}
			if ev["event"] == "sas_ready" {
				if s, ok := ev["sas"].(string); ok {
					sasFromStdout <- s
				}
			}
		}
	}()
	exitAccept := <-acceptDone
	wg.Wait()
	if exitAccept != 0 {
		t.Fatalf("expected exit=0 when responder confirms 'yes', got exit=%d stdout=%s stderr=%s", exitAccept, acceptOut.String(), acceptErr.String())
	}
	bobKSFinal, _ := envelope.NewFileKeyStore(bobCfg)
	if devs, _ := bobKSFinal.ListDevices(); len(devs) != 1 {
		t.Fatalf("expected 1 paired device in Bob's keystore after 'yes', got %+v", devs)
	}
}
