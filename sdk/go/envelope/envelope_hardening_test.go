package envelope

import (
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestSanitizeFilenameWindowsReservedBidiAndUTF8(t *testing.T) {
	// Anchor compatibility checks
	if got := SanitizeFilename("../../evil/clip.mp4"); got != "clip.mp4" {
		t.Fatalf("expected clip.mp4, got %q", got)
	}
	if got := SanitizeFilename("..."); got != "blob.bin" {
		t.Fatalf("expected blob.bin for ..., got %q", got)
	}

	// Windows reserved device names (with and without extensions, case-insensitive)
	reserved := []string{"CON", "prn", "Aux", "NUL.txt", "com1.tar.gz", "LPT9.log", "COM\u00b9.txt"}
	for _, r := range reserved {
		got := SanitizeFilename(r)
		if !strings.HasPrefix(got, "_") {
			t.Fatalf("expected Windows reserved name %q to be prefixed with '_', got %q", r, got)
		}
	}

	// Trailing dots and spaces (forbidden on Windows NTFS/FAT)
	if got := SanitizeFilename("  .report.pdf. .  "); got != "report.pdf" {
		t.Fatalf("expected clean report.pdf, got %q", got)
	}

	// Right-to-Left Override (U+202E) extension spoofing stripped
	if got := SanitizeFilename("invoice\u202Ecod.exe"); strings.ContainsRune(got, '\u202E') || got != "invoicecod.exe" {
		t.Fatalf("expected bidi override stripped, got %q", got)
	}

	// Long multi-byte UTF-8 truncation must never split a multi-byte rune or exceed 200 bytes
	longCJK := strings.Repeat("跨端加密笔记🚀", 30) + ".mp4"
	gotCJK := SanitizeFilename(longCJK)
	if len(gotCJK) > 200 || !utf8.ValidString(gotCJK) || !strings.HasSuffix(gotCJK, ".mp4") {
		t.Fatalf("invalid UTF-8 truncation: len=%d valid=%v got=%q", len(gotCJK), utf8.ValidString(gotCJK), gotCJK)
	}
}

func TestSecretAutoRedactionAndErrorClassifiers(t *testing.T) {
	secretKey := "SUPER_SECRET_ACCESS_KEY_0123456789ABCDEF"
	secretOOB := "SECRET_OOB_1234567890AB"
	rawCause := errors.New("parse \"synctool://relay?v=1&u=https%3A%2F%2F1.2.3.4%3A8443#k=" + secretKey + "\": invalid port")
	wrapped := WrapError(ErrCodeURIInvalid, false, 0, "", rawCause)
	if strings.Contains(wrapped.Message, secretKey) || strings.Contains(wrapped.Error(), secretKey) {
		t.Fatalf("SyncError leaked #k= secret: %q", wrapped.Error())
	}

	directErr := NewError(ErrCodeURIInvalid, false, 0, "bad pair synctool://pair?r=K7M9P2XQ&m=1&p=pair#s="+secretOOB, nil)
	if strings.Contains(directErr.Error(), secretOOB) {
		t.Fatalf("SyncError leaked #s= secret: %q", directErr.Error())
	}

	// Classification helpers
	quotaErr := NewError(ErrCodeOfflineQuotaExceeded, false, 507, "quota full", map[string]any{"suggest_mode": "pipe"})
	if !IsQuotaExceeded(quotaErr) || !SuggestPipeMode(quotaErr) || IsRetryable(quotaErr) {
		t.Fatalf("unexpected quota classifier results")
	}
	rateErr := NewError(ErrCodeRateLimited, true, 429, "slow down", nil)
	if !IsRetryable(rateErr) {
		t.Fatalf("expected rate limit to be retryable")
	}
	pinErr := NewError(ErrCodeTLSPinMismatch, false, 0, "pin mismatch", nil)
	if !IsAuthError(pinErr) || !IsSecurityAlert(pinErr) {
		t.Fatalf("expected pin mismatch to trigger both auth and security alert")
	}
	verErr := NewError(ErrCodeUnsupportedVersion, false, 0, "v2", nil)
	if !IsVersionMismatch(verErr) || ExitCode(verErr) != 2 {
		t.Fatalf("unexpected version mismatch classification or exit code: %d", ExitCode(verErr))
	}
}

func TestVersionEvolutionAndUnknownFieldsForwardCompat(t *testing.T) {
	// v1.1 Manifest with unknown fields at top-level, sender, and blobs[] MUST parse cleanly!
	rawV11 := `{
		"envelope_version": 1,
		"msg_id": "` + strings.Repeat("a", 32) + `",
		"app_id": "com.yellowdking.notes",
		"schema": "note.item.v2",
		"created_at": 1764246000,
		"future_top_field": {"feature": "tags", "v": 11},
		"sender": {
			"device_id": "` + strings.Repeat("b", 32) + `",
			"label": "Future Phone",
			"platform": "android",
			"future_sender_os_ver": "16.0"
		},
		"inline_payload": {"title": "Forward Compat"},
		"blobs": [{
			"part_id": 1,
			"role": "image",
			"name": "pic.jpg",
			"mime": "image/jpeg",
			"size": 128,
			"sha256": "` + strings.Repeat("c", 64) + `",
			"key": "` + base64.RawURLEncoding.EncodeToString(make([]byte, 32)) + `",
			"future_blob_hint": "hdr10"
		}]
	}`
	m, err := ParseManifest([]byte(rawV11))
	if err != nil || m.AppID != "com.yellowdking.notes" || len(m.Blobs) != 1 {
		t.Fatalf("expected v1.1 unknown fields ignored cleanly, got err=%v", err)
	}

	// Higher major envelope_version (> 1) MUST return ERR_UNSUPPORTED_VERSION
	rawV2 := strings.Replace(rawV11, `"envelope_version": 1`, `"envelope_version": 2`, 1)
	if _, err := ParseManifest([]byte(rawV2)); !IsVersionMismatch(err) {
		t.Fatalf("expected ERR_UNSUPPORTED_VERSION for envelope_version=2, got %v", err)
	}
	// Invalid <= 0 envelope_version still returns ERR_MANIFEST_INVALID
	rawV0 := strings.Replace(rawV11, `"envelope_version": 1`, `"envelope_version": 0`, 1)
	if _, err := ParseManifest([]byte(rawV0)); !IsCode(err, ErrCodeManifestInvalid) {
		t.Fatalf("expected ERR_MANIFEST_INVALID for envelope_version=0, got %v", err)
	}

	// URI v > 1 -> ERR_UNSUPPORTED_VERSION; v=0 -> ERR_URI_INVALID
	key := strings.Repeat("K", 43)
	if _, err := ParseRelayURI("synctool://relay?v=2&u=https%3A%2F%2Fsync.example.com%3A443#k=" + key); !IsVersionMismatch(err) {
		t.Fatalf("expected ERR_UNSUPPORTED_VERSION for relay URI v=2, got %v", err)
	}
	if _, err := ParsePairURI("synctool://pair?r=K7M9P2XQ&m=2&p=oneshot&v=3"); !IsVersionMismatch(err) {
		t.Fatalf("expected ERR_UNSUPPORTED_VERSION for pair URI v=3, got %v", err)
	}
	if _, err := ParsePairURI("synctool://pair?r=K7M9P2XQ&m=2&p=oneshot&v=0"); !IsCode(err, ErrCodeURIInvalid) {
		t.Fatalf("expected ERR_URI_INVALID for pair URI v=0, got %v", err)
	}
}

func TestReceivedBlobSaveToDirAndEnvHelpers(t *testing.T) {
	tmp := t.TempDir()
	srcPath := filepath.Join(tmp, "part_1.verified")
	payload := []byte("verified plaintext payload")
	if err := os.WriteFile(srcPath, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	srcPath2 := filepath.Join(tmp, "part_2.verified")
	if err := os.WriteFile(srcPath2, payload, 0o600); err != nil {
		t.Fatal(err)
	}

	outDir := filepath.Join(tmp, "downloads")
	b1 := ReceivedBlob{SafePath: srcPath, SafeName: "NUL.txt"}
	saved1, err := b1.SaveToDir(outDir)
	if err != nil || filepath.Base(saved1) != "_NUL.txt" {
		t.Fatalf("SaveToDir 1 unexpected: path=%q err=%v", saved1, err)
	}
	// Second save with identical name MUST NOT clobber existing file -> _NUL_1.txt
	b2 := ReceivedBlob{SafePath: srcPath2, SafeName: "NUL.txt"}
	saved2, err := b2.SaveToDir(outDir)
	if err != nil || filepath.Base(saved2) != "_NUL_1.txt" {
		t.Fatalf("SaveToDir collision suffix failed: path=%q err=%v", saved2, err)
	}

	t.Setenv("SYNCTOOL_RELAY", "synctool://relay?v=1&u=https%3A%2F%2Fsync.example.com%3A443#k="+strings.Repeat("A", 43))
	prof, err := RelayProfileFromEnv()
	if err != nil || prof.Endpoint != "https://sync.example.com:443" {
		t.Fatalf("RelayProfileFromEnv failed: %+v %v", prof, err)
	}
}

func TestMultiPinSPKIURIRoundTripAndStrictPairValidation(t *testing.T) {
	pin1 := strings.Repeat("a", 64)
	pin2 := strings.Repeat("b", 64)
	key := strings.Repeat("K", 43)

	// Uppercase & whitespace in comma-separated pins normalize to lowercase and sync SPKIPins[0] <-> SPKISHA256 / SPKIPin.
	rawRelay := "synctool://relay?v=1&u=https%3A%2F%2F1.2.3.4%3A54843&pin=" + strings.ToUpper(pin1) + ",%20" + pin2 + "#k=" + key
	prof, err := ParseRelayURI(rawRelay)
	if err != nil {
		t.Fatalf("ParseRelayURI multi-pin failed: %v", err)
	}
	if len(prof.SPKIPins) != 2 || prof.SPKIPins[0] != pin1 || prof.SPKIPins[1] != pin2 || prof.SPKISHA256 != pin1 || prof.SPKIPin != pin1 {
		t.Fatalf("unexpected multi-pin RelayProfile: %+v", prof)
	}
	formatted, err := FormatRelayURI(prof)
	if err != nil || !strings.Contains(formatted, "&pin="+pin1+","+pin2+"#k=") {
		t.Fatalf("FormatRelayURI multi-pin mismatch: %q err=%v", formatted, err)
	}

	// 9 pins (> MaxSPKIPins=8) MUST fail.
	nine := make([]string, 9)
	for i := range nine {
		nine[i] = strings.Repeat(string(rune('0'+i)), 64)
	}
	if _, err := ParseRelayURI("synctool://relay?v=1&u=https%3A%2F%2F1.2.3.4%3A54843&pin=" + strings.Join(nine, ",") + "#k=" + key); !IsCode(err, ErrCodeURIInvalid) {
		t.Fatalf("expected >8 pins to fail with ERR_URI_INVALID, got %v", err)
	}
	if _, err := ParseRelayURI("synctool://relay?v=1&u=https%3A%2F%2Frelay.example.com%3A443&pin=#k=" + key); !IsCode(err, ErrCodeURIInvalid) {
		t.Fatalf("expected empty pin= to fail, got %v", err)
	}

	// PairURI multi-pin round-trip + strict bare-IP, orphan-pin, exp<=0, and short #k= checks.
	pairStr, err := FormatPairURI(&PairOffer{
		RoomID:    "K7M9P2XQ",
		Mode:      2,
		Purpose:   "pair",
		Endpoint:  "https://1.2.3.4:54843",
		SPKIPins:  []string{pin1, pin2},
		ExpiresAt: 1764246000,
		AccessKey: key,
	})
	if err != nil {
		t.Fatalf("FormatPairURI multi-pin: %v", err)
	}
	po, err := ParsePairURI(pairStr)
	if err != nil || len(po.SPKIPins) != 2 || po.SPKISHA256 != pin1 || po.SPKIPin != pin1 {
		t.Fatalf("ParsePairURI multi-pin: %+v err=%v", po, err)
	}
	if _, err := FormatPairURI(&PairOffer{RoomID: "K7M9P2XQ", Mode: 2, Purpose: "pair", Endpoint: "https://1.2.3.4:54843"}); !IsCode(err, ErrCodeURIInvalid) {
		t.Fatalf("expected FormatPairURI bare IP without pin to fail, got %v", err)
	}
	if _, err := ParsePairURI("synctool://pair?r=K7M9P2XQ&m=2&p=pair&pin=" + pin1); !IsCode(err, ErrCodeURIInvalid) {
		t.Fatalf("expected ParsePairURI orphan pin without u to fail, got %v", err)
	}
	if _, err := ParsePairURI("synctool://pair?r=K7M9P2XQ&m=2&p=pair&exp=0"); !IsCode(err, ErrCodeURIInvalid) {
		t.Fatalf("expected ParsePairURI exp=0 to fail, got %v", err)
	}
}

func TestFullRedactionDetailsCauseAndKeyStoreSealing(t *testing.T) {
	// 1. Full redaction of multi-param fragments, uppercase #K=, query ?k=/&s=, Details, and Cause.
	msg := "err #s=SEC_ONE&k=SEC_TWO and #K=SEC_THREE and https://admin:SEC_PW@host:443/p?k=SEC_QK&x=1#SEC_F"
	red := RedactMessage(msg)
	if strings.Contains(red, "SEC_") {
		t.Fatalf("RedactMessage leaked secret: %q", red)
	}
	se := NewError(ErrCodeURIInvalid, false, 0, "ok", map[string]any{
		"nested": map[string]any{"uri": "synctool://relay?v=1&k=SEC_DET_Q#k=SEC_DET_F"},
	})
	nested := se.Details["nested"].(map[string]any)["uri"].(string)
	if strings.Contains(nested, "SEC_DET") {
		t.Fatalf("NewError failed to redact Details: %q", nested)
	}
	we := WrapError(ErrCodeURIInvalid, false, 0, "failed", errors.New("raw #k=SEC_CAUSE_KEY"))
	if strings.Contains(errors.Unwrap(we).Error(), "SEC_CAUSE_KEY") {
		t.Fatalf("WrapError Unwrap leaked secret: %q", errors.Unwrap(we).Error())
	}

	// 2. CONIN$ / CONOUT$ reserved Windows console stems.
	for _, in := range []string{"CONIN$", "conout$.log"} {
		if got := SanitizeFilename(in); !strings.HasPrefix(got, "_") {
			t.Fatalf("expected %q to be prefixed with '_', got %q", in, got)
		}
	}

	// 3. FileKeyStore LocalMetaKey AES-256-GCM sealing for ManifestCache on disk!
	ksDir := t.TempDir()
	ks, err := NewFileKeyStore(ksDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ks.LoadOrCreateMasterSeed(); err != nil {
		t.Fatal(err)
	}
	err = ks.PutCachedManifest(CachedManifestEntry{
		ItemID:         "itm_test1",
		CachedAt:       1764246000,
		ExpiresAt:      1764249600,
		ManifestSHA256: strings.Repeat("f", 64),
		Manifest: Manifest{
			EnvelopeVersion: 1,
			MsgID:           strings.Repeat("1", 32),
			AppID:           "com.yellowdking.notes",
			Schema:          "note.v1",
			CreatedAt:       1764246000,
			Sender:          SenderInfo{DeviceID: strings.Repeat("2", 32), Label: "SecretLabel"},
			InlinePayload:   map[string]any{"secret_note": "PLAINTEXT_MUST_NOT_APPEAR_ON_DISK"},
			Blobs:           []BlobDescriptor{},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	rawDisk, err := os.ReadFile(filepath.Join(ksDir, "keystore.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(rawDisk), "PLAINTEXT_MUST_NOT_APPEAR_ON_DISK") || strings.Contains(string(rawDisk), "SecretLabel") {
		t.Fatalf("CachedManifestEntry leaked plaintext Manifest onto disk: %s", string(rawDisk))
	}
	ksReopen, err := NewFileKeyStore(ksDir)
	if err != nil {
		t.Fatal(err)
	}
	gotCached, err := ksReopen.GetCachedManifest("itm_test1")
	if err != nil || gotCached == nil || gotCached.Manifest.InlinePayload["secret_note"] != "PLAINTEXT_MUST_NOT_APPEAR_ON_DISK" {
		t.Fatalf("failed to decrypt sealed cached manifest on reopen: %+v err=%v", gotCached, err)
	}
}
