package envelope

import (
	"encoding/base64"
	"strings"
	"testing"

	synccrypto "github.com/yellowdking/synctool/sdk/go/crypto"
)

func TestRelayURIRoundTripAndBareIPPinRule(t *testing.T) {
	pin := strings.Repeat("a", 64)
	key := "SYNCTOOL-TEST-ACCESS-KEY-0123456789ABCDEF"
	uri := "synctool://relay?v=1&u=https%3A%2F%2F1.2.3.4%3A54843&pin=" + pin + "#k=" + key

	prof, err := ParseRelayURI(uri)
	if err != nil {
		t.Fatalf("ParseRelayURI: %v", err)
	}
	if prof.TLSMode != TLSModeSPKIPin || prof.SPKISHA256 != pin || prof.Endpoint != "https://1.2.3.4:54843" {
		t.Fatalf("unexpected profile: %+v", prof)
	}
	formatted, err := FormatRelayURI(prof)
	if err != nil {
		t.Fatalf("FormatRelayURI: %v", err)
	}
	if formatted != uri {
		t.Fatalf("roundtrip mismatch:\ngot:  %s\nwant: %s", formatted, uri)
	}
	if red := RedactURI(uri); strings.Contains(red, key) || !strings.HasSuffix(red, "#[REDACTED]") {
		t.Fatalf("RedactURI leaked secret: %s", red)
	}

	// Bare IP without pin MUST fail
	if _, err := ParseRelayURI("synctool://relay?v=1&u=https%3A%2F%2F1.2.3.4%3A54843#k=" + key); !IsCode(err, ErrCodeURIInvalid) {
		t.Fatalf("expected ERR_URI_INVALID for bare IP without pin, got %v", err)
	}
	// Secret k in query string instead of fragment MUST fail
	if _, err := ParseRelayURI("synctool://relay?v=1&u=https%3A%2F%2Frelay.example.com%3A443&k=" + key); !IsCode(err, ErrCodeURIInvalid) {
		t.Fatalf("expected ERR_URI_INVALID when k in query, got %v", err)
	}
}

func TestPairURIModes(t *testing.T) {
	oob := make([]byte, 16)
	for i := range oob {
		oob[i] = byte(i + 1)
	}
	// Mode 1 QR OOB requires #s=
	u1, err := FormatPairURI(&PairOffer{RoomID: "k7m9-p2xq", Mode: synccrypto.ModeQROOB, Purpose: synccrypto.PurposePair, OOBSecret: oob})
	if err != nil {
		t.Fatalf("FormatPairURI m=1: %v", err)
	}
	p1, err := ParsePairURI(u1)
	if err != nil || p1.RoomID != "K7M9P2XQ" || len(p1.OOBSecret) != 16 {
		t.Fatalf("ParsePairURI m=1: %+v %v", p1, err)
	}
	// Mode 1 missing #s= fails
	if _, err := ParsePairURI("synctool://pair?r=K7M9P2XQ&m=1&p=oneshot"); !IsCode(err, ErrCodeURIInvalid) {
		t.Fatalf("expected ERR_URI_INVALID for m=1 without #s=, got %v", err)
	}
	// Mode 2 SAS must NOT have #s=
	u2, err := FormatPairURI(&PairOffer{RoomID: "K7M9P2XQ", Mode: synccrypto.ModeCommitSAS, Purpose: synccrypto.PurposeOneshot})
	if err != nil || strings.Contains(u2, "#") {
		t.Fatalf("FormatPairURI m=2 unexpected: %q %v", u2, err)
	}
	if _, err := ParsePairURI("synctool://pair?r=K7M9P2XQ&m=2&p=oneshot#s=" + base64.RawURLEncoding.EncodeToString(oob)); !IsCode(err, ErrCodeURIInvalid) {
		t.Fatalf("expected ERR_URI_INVALID for m=2 with #s=, got %v", err)
	}
	// Mode 0 direct
	u0, err := FormatPairURI(&PairOffer{RoomID: "K7M9P2XQ", Mode: synccrypto.ModeDirect, Purpose: synccrypto.PurposeDirect})
	if err != nil {
		t.Fatalf("FormatPairURI m=0: %v", err)
	}
	p0, err := ParsePairURI(u0)
	if err != nil || p0.Mode != 0 || p0.Purpose != "direct" {
		t.Fatalf("ParsePairURI m=0: %+v %v", p0, err)
	}
}

func TestManifestValidationAndSanitizeFilename(t *testing.T) {
	m := &Manifest{
		EnvelopeVersion: 1,
		MsgID:           strings.Repeat("a", 32),
		AppID:           "com.yellowdking.notes",
		Schema:          "note.item.v1",
		CreatedAt:       1764246000,
		Sender:          SenderInfo{DeviceID: strings.Repeat("b", 32), Label: "My Phone", Platform: "android"},
		InlinePayload:   map[string]any{"title": "hello"},
		Blobs: []BlobDescriptor{
			{
				PartID: 1,
				Role:   "image",
				Name:   "../../etc/passwd",
				MIME:   "image/jpeg",
				Size:   1024,
				SHA256: strings.Repeat("c", 64),
				Key:    base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
			},
		},
	}
	raw, err := MarshalManifest(m)
	if err != nil {
		t.Fatalf("MarshalManifest: %v", err)
	}
	parsed, err := ParseManifest(raw)
	if err != nil || parsed.AppID != m.AppID {
		t.Fatalf("ParseManifest: %v", err)
	}
	if safe := SanitizeFilename("../../etc/passwd"); strings.Contains(safe, "..") || strings.Contains(safe, "/") {
		t.Fatalf("SanitizeFilename failed: %q", safe)
	}

	// InlinePayload > 64KiB must fail
	m.InlinePayload = map[string]any{"big": strings.Repeat("x", 70000)}
	if _, err := MarshalManifest(m); !IsCode(err, ErrCodeManifestInvalid) {
		t.Fatalf("expected ERR_MANIFEST_INVALID for >64KiB inline_payload, got %v", err)
	}
}

func TestFileKeyStorePersistence(t *testing.T) {
	dir := t.TempDir()
	ks, err := NewFileKeyStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	seed1, err := ks.LoadOrCreateMasterSeed()
	if err != nil {
		t.Fatal(err)
	}
	if err := ks.MarkSeenMsgID(strings.Repeat("d", 32), 1764246000, 1764246001); err != nil {
		t.Fatal(err)
	}
	if err := ks.PutDevice(DeviceCard{DeviceID: strings.Repeat("e", 32), Label: "Desktop"}); err != nil {
		t.Fatal(err)
	}

	// Re-open from disk
	ks2, err := NewFileKeyStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	seed2, err := ks2.LoadOrCreateMasterSeed()
	if err != nil || seed1 != seed2 {
		t.Fatalf("master seed not persisted: err=%v", err)
	}
	seen, _ := ks2.HasSeenMsgID(strings.Repeat("d", 32))
	if !seen {
		t.Fatal("seen_msg_id not persisted")
	}
	dev, _ := ks2.GetDevice(strings.Repeat("e", 32))
	if dev == nil || dev.Label != "Desktop" {
		t.Fatalf("device not persisted: %+v", dev)
	}
}
