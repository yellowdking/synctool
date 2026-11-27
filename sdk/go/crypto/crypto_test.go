package crypto

import (
	"bytes"
	"testing"
)

func TestVerifySAS(t *testing.T) {
	if err := VerifySAS("042819", "042 819"); err != nil {
		t.Fatalf("expected space-formatted SAS to pass: %v", err)
	}
	if err := VerifySAS("042819", "042-819"); err != nil {
		t.Fatalf("expected hyphen-formatted SAS to pass: %v", err)
	}
	if err := VerifySAS("042819", "042818"); err == nil {
		t.Fatal("expected mismatched SAS to fail")
	}
	if err := VerifySAS("042819", "42819"); err == nil {
		t.Fatal("expected short SAS to fail")
	}
	if err := VerifySAS("042819", "04281a"); err == nil {
		t.Fatal("expected non-digit SAS to fail")
	}
}

func TestCanonicalRelayOriginRules(t *testing.T) {
	okCases := map[string]string{
		"https://relay.example.com":       "https://relay.example.com:443",
		"HTTPS://Relay.Example.COM:8443/": "https://relay.example.com:8443",
		"https://1.2.3.4:54843":           "https://1.2.3.4:54843",
		"http://127.0.0.1:8080":           "http://127.0.0.1:8080",
		"http://localhost":                "http://localhost:80",
		"http://[::1]:9000":               "http://[::1]:9000",
	}
	for in, want := range okCases {
		got, err := CanonicalRelayOrigin(in)
		if err != nil || got != want {
			t.Fatalf("CanonicalRelayOrigin(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	badCases := []string{
		"http://1.2.3.4:54843",
		"http://relay.example.com",
		"https://relay.example.com/v1",
		"https://relay.example.com?a=1",
		"https://relay.example.com#frag",
		"https://user:pass@relay.example.com",
		"ftp://relay.example.com",
	}
	for _, in := range badCases {
		if got, err := CanonicalRelayOrigin(in); err == nil {
			t.Fatalf("expected CanonicalRelayOrigin(%q) to fail, got %q", in, got)
		}
	}
}

func TestGenerateAndZeroKeys(t *testing.T) {
	seed, err := GenerateMasterSeed()
	if err != nil {
		t.Fatal(err)
	}
	dk, err := DeriveDeviceKeys(seed[:])
	if err != nil {
		t.Fatal(err)
	}
	mk1, err := dk.DeriveMailboxKeys(DeriveRelayID("https://a.example.com:443"))
	if err != nil {
		t.Fatal(err)
	}
	mk2, err := dk.DeriveMailboxKeys(DeriveRelayID("https://b.example.com:443"))
	if err != nil {
		t.Fatal(err)
	}
	if mk1.MailboxID == mk2.MailboxID {
		t.Fatal("different relays must derive distinct mailbox_ids")
	}
	dk.Zero()
	mk1.Zero()
	var zeros [32]byte
	if !bytes.Equal(dk.MasterSeed[:], zeros[:]) || !bytes.Equal(dk.SignSeed[:], zeros[:]) || !bytes.Equal(mk1.AuthSeed[:], zeros[:]) {
		t.Fatal("Zero() did not clear key material")
	}
}

func TestGenerateRoomIDRandom(t *testing.T) {
	r1, err := GenerateRoomID()
	if err != nil || !IsCanonicalRoomID(r1) {
		t.Fatalf("GenerateRoomID invalid: %q %v", r1, err)
	}
	r2, err := GenerateRoomID()
	if err != nil || !IsCanonicalRoomID(r2) {
		t.Fatalf("GenerateRoomID invalid: %q %v", r2, err)
	}
	if r1 == r2 {
		t.Fatal("two random 40-bit room IDs unexpectedly collided")
	}
}
