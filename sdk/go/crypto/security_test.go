package crypto

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"math"
	"math/big"
	"strings"
	"testing"
)

func TestX25519LowOrderPointsRejected(t *testing.T) {
	priv, err := GenerateEphemeralX25519()
	if err != nil {
		t.Fatal(err)
	}
	// RFC 7748 Curve25519 canonical & non-canonical low-order points that yield an all-zero shared secret.
	lowOrderHexes := []string{
		"0000000000000000000000000000000000000000000000000000000000000000", // 0
		"0100000000000000000000000000000000000000000000000000000000000000", // 1
		"e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800", // order 8
		"5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157", // order 8
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // p - 1
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // p
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // p + 1
		"0000000000000000000000000000000000000000000000000000000000000080", // 0 + 2^255
		"0100000000000000000000000000000000000000000000000000000000000080", // 1 + 2^255
	}
	nonce := bytes.Repeat([]byte{0x42}, HSNonceSize)
	oob := bytes.Repeat([]byte{0x77}, OOBSecretSize)
	seed, _ := GenerateMasterSeed()
	dk, _ := DeriveDeviceKeys(seed[:])
	defer dk.Zero()

	for _, h := range lowOrderHexes {
		pt := mustHex(t, h)
		if _, err := X25519SharedSecret(priv, pt); !errors.Is(err, ErrAllZeroSharedKey) {
			t.Fatalf("X25519SharedSecret(%s): got %v, want ErrAllZeroSharedKey", h, err)
		}
		if _, err := DeriveQROOBSession(PurposeOneshot, "01234567", priv, pt, priv.PublicKey().Bytes(), nonce, pt, nonce, oob); !errors.Is(err, ErrAllZeroSharedKey) {
			t.Fatalf("DeriveQROOBSession(%s): got %v, want ErrAllZeroSharedKey", h, err)
		}
		commitA, _ := ComputeCommitA(PurposePair, "01234567", priv.PublicKey().Bytes(), nonce)
		if _, err := DeriveSASSession(PurposePair, "01234567", priv, pt, commitA[:], priv.PublicKey().Bytes(), nonce, pt, nonce); !errors.Is(err, ErrAllZeroSharedKey) {
			t.Fatalf("DeriveSASSession(%s): got %v, want ErrAllZeroSharedKey", h, err)
		}
		var hdr [SealedHeaderSize]byte
		copy(hdr[0:4], "ST01")
		hdr[4] = 0x02
		copy(hdr[24:56], pt)
		if _, err := Open0RTTHeader(dk, hdr[:], func(string) (ed25519.PublicKey, error) { return dk.SignPub, nil }); !errors.Is(err, ErrAllZeroSharedKey) {
			t.Fatalf("Open0RTTHeader(%s): got %v, want ErrAllZeroSharedKey", h, err)
		}
	}
}

func makeMalleableEd25519Sig(t *testing.T, validSig []byte) []byte {
	t.Helper()
	if len(validSig) != 64 {
		t.Fatalf("invalid sig len %d", len(validSig))
	}
	// Ed25519 group order L = 2^252 + 27742317777372353535851937790883648493
	orderL, ok := new(big.Int).SetString("1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed", 16)
	if !ok {
		t.Fatal("parse orderL")
	}
	var sBE [32]byte
	for i := 0; i < 32; i++ {
		sBE[i] = validSig[63-i]
	}
	sInt := new(big.Int).SetBytes(sBE[:])
	sPlusL := new(big.Int).Add(sInt, orderL)
	sPlusLBE := sPlusL.Bytes()
	if len(sPlusLBE) > 32 {
		t.Fatalf("unexpected S+L overflow (%d bytes)", len(sPlusLBE))
	}
	var sPlusLLE [32]byte
	for i := 0; i < len(sPlusLBE); i++ {
		sPlusLLE[i] = sPlusLBE[len(sPlusLBE)-1-i]
	}
	out := make([]byte, 64)
	copy(out[0:32], validSig[0:32])
	copy(out[32:64], sPlusLLE[:])
	return out
}

func TestEd25519NonCanonicalAndCaseStrictness(t *testing.T) {
	seedA := bytes.Repeat([]byte{0x11}, 32)
	seedB := bytes.Repeat([]byte{0x22}, 32)
	alice, err := DeriveDeviceKeys(seedA)
	if err != nil {
		t.Fatal(err)
	}
	defer alice.Zero()
	bob, err := DeriveDeviceKeys(seedB)
	if err != nil {
		t.Fatal(err)
	}
	defer bob.Zero()

	// 1. DeviceCard strictness: non-canonical S+L signature and uppercase deviceID must be rejected.
	cardSig, err := SignDeviceCard(alice.SignPriv, alice.KEMPubBytes[:], 1700000000)
	if err != nil {
		t.Fatal(err)
	}
	malCardSig := makeMalleableEd25519Sig(t, cardSig)
	if err := VerifyDeviceCard(alice.DeviceID, alice.SignPub, alice.KEMPubBytes[:], 1700000000, malCardSig); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected non-canonical S+L DeviceCard sig to fail with ErrInvalidSignature, got %v", err)
	}
	if err := VerifyDeviceCard(strings.ToUpper(alice.DeviceID), alice.SignPub, alice.KEMPubBytes[:], 1700000000, cardSig); !errors.Is(err, ErrDeviceIDMismatch) {
		t.Fatalf("expected uppercase DeviceID to fail with ErrDeviceIDMismatch, got %v", err)
	}

	// 2. Mailbox Ed25519 auth: non-canonical S+L signature must be rejected.
	mb, err := alice.DeriveMailboxKeys(DeriveRelayID("https://relay.example.com:443"))
	if err != nil {
		t.Fatal(err)
	}
	defer mb.Zero()
	bodyBind := BodyBindingControl(nil)
	mbSigB64 := SignMailboxRequest(mb.AuthPriv, "GET", "/v1/mailboxes/"+mb.MailboxID+"/items", mb.MailboxID, "1700000000", "00112233445566778899aabbccddeeff", bodyBind)
	if !VerifyMailboxRequest(mb.AuthPub, "GET", "/v1/mailboxes/"+mb.MailboxID+"/items", mb.MailboxID, "1700000000", "00112233445566778899aabbccddeeff", bodyBind, mbSigB64) {
		t.Fatal("expected valid mailbox signature to verify")
	}
	rawMbSig, _ := base64.RawURLEncoding.DecodeString(mbSigB64)
	malMbSigB64 := base64.RawURLEncoding.EncodeToString(makeMalleableEd25519Sig(t, rawMbSig))
	if VerifyMailboxRequest(mb.AuthPub, "GET", "/v1/mailboxes/"+mb.MailboxID+"/items", mb.MailboxID, "1700000000", "00112233445566778899aabbccddeeff", bodyBind, malMbSigB64) {
		t.Fatal("expected non-canonical S+L mailbox signature to be rejected")
	}

	// 3. Open0RTTHeader: non-canonical S+L sender_sig inside AEAD-valid sealed_box must be rejected.
	ephPriv, _ := GenerateEphemeralX25519()
	var msgID [16]byte
	copy(msgID[:], bytes.Repeat([]byte{0x33}, 16))
	var manifestSHA [32]byte
	copy(manifestSHA[:], bytes.Repeat([]byte{0x44}, 32))
	var clearHdr [ClearHeaderSize]byte
	copy(clearHdr[0:4], sealedHeaderMagic)
	clearHdr[4] = sealedMode0RTT
	copy(clearHdr[8:24], msgID[:])
	copy(clearHdr[24:56], ephPriv.PublicKey().Bytes())
	dh, _ := X25519SharedSecret(ephPriv, bob.KEMPubBytes[:])
	hdrKey, hdrNonce, _, _, _ := derive0RTTKeys(clearHdr[:], dh)
	sigIn, _ := BuildZeroRTTSigInput(clearHdr[:], alice.DeviceIDRaw, bob.DeviceIDRaw, 1700000000, manifestSHA)
	malSenderSig := makeMalleableEd25519Sig(t, ed25519.Sign(alice.SignPriv, sigIn[:]))

	var boxPT [SealedBoxPlaintextSize]byte
	copy(boxPT[0:16], alice.DeviceIDRaw[:])
	copy(boxPT[16:32], bob.DeviceIDRaw[:])
	binary.BigEndian.PutUint64(boxPT[32:40], 1700000000)
	copy(boxPT[40:72], manifestSHA[:])
	copy(boxPT[72:136], malSenderSig)
	boxCT, _ := aesGCMSeal(hdrKey[:], hdrNonce[:], boxPT[:], clearHdr[:])
	var forgedHdr [SealedHeaderSize]byte
	copy(forgedHdr[0:ClearHeaderSize], clearHdr[:])
	copy(forgedHdr[ClearHeaderSize:], boxCT)

	if _, err := Open0RTTHeader(bob, forgedHdr[:], func(id string) (ed25519.PublicKey, error) {
		return alice.SignPub, nil
	}); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected non-canonical S+L 0RTT sender_sig to fail with ErrInvalidSignature, got %v", err)
	}
}

func TestVerifyRelayRequestStrictLowerHex(t *testing.T) {
	ak := "super-secret-access-key-0123456789"
	bodyBind := BodyBindingControl([]byte(`{"ok":true}`))
	sig := SignRelayRequest(ak, "POST", "/v1/rooms", "1700000000", "0123456789abcdef0123456789abcdef", bodyBind, "")
	if !VerifyRelayRequest(ak, "POST", "/v1/rooms", "1700000000", "0123456789abcdef0123456789abcdef", bodyBind, "", sig) {
		t.Fatal("expected valid lowercase hex X-Sync-Sig to verify")
	}
	if VerifyRelayRequest(ak, "POST", "/v1/rooms", "1700000000", "0123456789abcdef0123456789abcdef", bodyBind, "", strings.ToUpper(sig)) {
		t.Fatal("expected uppercase hex X-Sync-Sig to be rejected")
	}
	if VerifyRelayRequest(ak, "POST", "/v1/rooms", "1700000000", "0123456789abcdef0123456789abcdef", bodyBind, "", sig[:62]) {
		t.Fatal("expected truncated X-Sync-Sig to be rejected")
	}
}

func TestCanonicalRelayOriginHardeningAndNoSecretLeak(t *testing.T) {
	okCases := map[string]string{
		"https://relay.example.com:0443":       "https://relay.example.com:443",
		"http://127.0.0.1:00080":               "http://127.0.0.1:80",
		"http://127.0.0.2:9000":                "http://127.0.0.2:9000",
		"http://[0:0:0:0:0:0:0:1]:8080/":       "http://[::1]:8080",
		"http://[::ffff:127.0.0.1]:8080":       "http://[::ffff:127.0.0.1]:8080",
		"https://[2001:0db8:0:0:0:0:0:1]:8443": "https://[2001:db8::1]:8443",
	}
	for in, want := range okCases {
		got, err := CanonicalRelayOrigin(in)
		if err != nil || got != want {
			t.Fatalf("CanonicalRelayOrigin(%q) = %q, %v; want %q", in, got, err, want)
		}
	}

	badInputs := []string{
		"",
		"   ",
		"https://relay.example.com:0",
		"https://relay.example.com:65536",
		"https://relay.example.com:",
		"https://relay.example.com:abc",
		"https://relay.example.com?",
		"https://[fe80::1%25eth0]:443",
		"https://[fe80::1%eth0]:443",
		"https://[not:an:ipv6]:443",
		"https://relay.example.com:443\x00",
		"https://relay\texample.com:443",
		"https://admin:SUPER_SECRET_PASS@relay.example.com:443",
		"https://relay.example.com:443#k=SUPER_SECRET_KEY",
		"ht!tp://relay.example.com#k=SUPER_SECRET_KEY",
	}
	for _, in := range badInputs {
		got, err := CanonicalRelayOrigin(in)
		if !errors.Is(err, ErrInvalidRelayURL) {
			t.Fatalf("CanonicalRelayOrigin(%q) = %q, %v; want ErrInvalidRelayURL", in, got, err)
		}
		if strings.Contains(err.Error(), "SUPER_SECRET") {
			t.Fatalf("CanonicalRelayOrigin error leaked secret from input %q: %v", in, err)
		}
	}
}

func TestPipeCtrlSeqParityAndMonotonicity(t *testing.T) {
	var th, sk [32]byte
	copy(th[:], bytes.Repeat([]byte{0xaa}, 32))
	copy(sk[:], bytes.Repeat([]byte{0xbb}, 32))
	ctrlKey, ctrlNP, err := DerivePipeCtrlKeys(th[:], sk[:])
	if err != nil {
		t.Fatal(err)
	}

	// Initiator must send even sequences (0, 2, 4...) strictly increasing.
	ct0, err := SealPipeCtrl(ctrlKey, ctrlNP, th[:], 0, []byte(`{"op":"part_meta"}`))
	if err != nil {
		t.Fatal(err)
	}
	pt0, err := OpenPipeCtrlVerified(ctrlKey, ctrlNP, th[:], 0, true, -1, ct0)
	if err != nil || string(pt0) != `{"op":"part_meta"}` {
		t.Fatalf("expected seq=0 from initiator to succeed, got %q, %v", pt0, err)
	}
	// Replay of seq=0 when lastSeenSeq=0 must fail.
	if _, err := OpenPipeCtrlVerified(ctrlKey, ctrlNP, th[:], 0, true, 0, ct0); !errors.Is(err, ErrInvalidCtrlSeq) {
		t.Fatalf("expected replay seq=0 to fail with ErrInvalidCtrlSeq, got %v", err)
	}
	// Role confusion: opening initiator's even seq=0 as responder (fromInitiator=false) must fail before AEAD.
	if _, err := OpenPipeCtrlVerified(ctrlKey, ctrlNP, th[:], 0, false, -1, ct0); !errors.Is(err, ErrInvalidCtrlSeq) {
		t.Fatalf("expected wrong parity to fail with ErrInvalidCtrlSeq, got %v", err)
	}

	// Responder must send odd sequences (1, 3, 5...).
	ct1, err := SealPipeCtrl(ctrlKey, ctrlNP, th[:], 1, []byte(`{"op":"ack"}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenPipeCtrlVerified(ctrlKey, ctrlNP, th[:], 1, true, -1, ct1); !errors.Is(err, ErrInvalidCtrlSeq) {
		t.Fatalf("expected odd seq=1 claimed from initiator to fail, got %v", err)
	}
	if _, err := OpenPipeCtrlVerified(ctrlKey, ctrlNP, th[:], 1, false, -1, ct1); err != nil {
		t.Fatalf("expected odd seq=1 from responder to pass, got %v", err)
	}
	if _, err := OpenPipeCtrlVerified(ctrlKey, ctrlNP, th[:], 1, false, 3, ct1); !errors.Is(err, ErrInvalidCtrlSeq) {
		t.Fatalf("expected out-of-order seq=1 after lastSeen=3 to fail, got %v", err)
	}
}

func TestSealedHeaderOverflowAndWiping(t *testing.T) {
	seedA := bytes.Repeat([]byte{0x51}, 32)
	seedB := bytes.Repeat([]byte{0x52}, 32)
	alice, _ := DeriveDeviceKeys(seedA)
	defer alice.Zero()
	bob, _ := DeriveDeviceKeys(seedB)
	defer bob.Zero()

	ephPriv, _ := GenerateEphemeralX25519()
	var msgID [16]byte
	copy(msgID[:], bytes.Repeat([]byte{0x61}, 16))
	var manifestSHA [32]byte
	copy(manifestSHA[:], bytes.Repeat([]byte{0x62}, 32))

	// Negative createdAt in Seal0RTTHeaderDeterministic must fail and return zeroed keys.
	_, outID, p0K, p0N, err := Seal0RTTHeaderDeterministic(alice, ephPriv, msgID, bob.DeviceIDRaw, bob.KEMPubBytes[:], -1, manifestSHA)
	if err == nil {
		t.Fatal("expected negative createdAt to fail")
	}
	if outID != ([16]byte{}) || p0K != ([32]byte{}) || p0N != ([7]byte{}) {
		t.Fatal("expected derived keys and msgID to be wiped on Seal0RTTHeaderDeterministic error")
	}

	// Forged uint64 createdAt > math.MaxInt64 (MSB set) inside valid AEAD box must fail with ErrInvalidSealedHeader.
	var clearHdr [ClearHeaderSize]byte
	copy(clearHdr[0:4], sealedHeaderMagic)
	clearHdr[4] = sealedMode0RTT
	copy(clearHdr[8:24], msgID[:])
	copy(clearHdr[24:56], ephPriv.PublicKey().Bytes())
	dh, _ := X25519SharedSecret(ephPriv, bob.KEMPubBytes[:])
	hdrKey, hdrNonce, _, _, _ := derive0RTTKeys(clearHdr[:], dh)

	var boxPT [SealedBoxPlaintextSize]byte
	copy(boxPT[0:16], alice.DeviceIDRaw[:])
	copy(boxPT[16:32], bob.DeviceIDRaw[:])
	binary.BigEndian.PutUint64(boxPT[32:40], uint64(math.MaxInt64)+1)
	copy(boxPT[40:72], manifestSHA[:])
	boxCT, _ := aesGCMSeal(hdrKey[:], hdrNonce[:], boxPT[:], clearHdr[:])

	var forged [SealedHeaderSize]byte
	copy(forged[0:ClearHeaderSize], clearHdr[:])
	copy(forged[ClearHeaderSize:], boxCT)
	if _, err := Open0RTTHeader(bob, forged[:], func(string) (ed25519.PublicKey, error) {
		return alice.SignPub, nil
	}); !errors.Is(err, ErrInvalidSealedHeader) {
		t.Fatalf("expected createdAt > MaxInt64 to fail with ErrInvalidSealedHeader, got %v", err)
	}

	// Valid header open + Zero() must clear both Part0Key and Part0NoncePrefix.
	validHdr, _, _, _, err := Seal0RTTHeaderDeterministic(alice, ephPriv, msgID, bob.DeviceIDRaw, bob.KEMPubBytes[:], 1700000000, manifestSHA)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := Open0RTTHeader(bob, validHdr[:], func(id string) (ed25519.PublicKey, error) {
		if id == alice.DeviceID {
			return alice.SignPub, nil
		}
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	opened.Zero()
	if opened.Part0Key != ([32]byte{}) || opened.Part0NoncePrefix != ([7]byte{}) {
		t.Fatal("SealedHeaderOpenResult.Zero() failed to wipe Part0Key or Part0NoncePrefix")
	}
}

func TestManifestPaddingStrictness(t *testing.T) {
	raw := []byte(`{"proto_v":1,"app_id":"test.app"}`)
	padded, err := PadManifest(raw)
	if err != nil || len(padded) != ManifestPadBucket {
		t.Fatalf("PadManifest: len=%d err=%v", len(padded), err)
	}
	got, err := UnpadManifest(padded)
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatalf("UnpadManifest valid failed: %v", err)
	}

	// Excess 4 KiB zero bucket (malleability vector: L=33 inside 8192B instead of 4096B) MUST be rejected!
	overPadded := make([]byte, 2*ManifestPadBucket)
	copy(overPadded, padded)
	if _, err := UnpadManifest(overPadded); !errors.Is(err, ErrInvalidPadding) {
		t.Fatalf("expected excess 4 KiB padding bucket to fail with ErrInvalidPadding, got %v", err)
	}

	// Non-zero byte in trailing padding MUST be rejected!
	dirty := append([]byte(nil), padded...)
	dirty[len(dirty)-1] = 0x01
	if _, err := UnpadManifest(dirty); !errors.Is(err, ErrInvalidPadding) {
		t.Fatalf("expected non-zero padding byte to fail with ErrInvalidPadding, got %v", err)
	}

	// Zero length prefix and >128 KiB length prefix MUST be rejected!
	zeroLen := make([]byte, ManifestPadBucket)
	if _, err := UnpadManifest(zeroLen); !errors.Is(err, ErrInvalidPadding) {
		t.Fatalf("expected L=0 to fail with ErrInvalidPadding, got %v", err)
	}
	tooBig := make([]byte, MaxManifestPaddedBytes+ManifestPadBucket)
	binary.BigEndian.PutUint32(tooBig[0:4], ManifestMaxRawBytes+1)
	if _, err := UnpadManifest(tooBig); !errors.Is(err, ErrInvalidPadding) {
		t.Fatalf("expected L>ManifestMaxRawBytes to fail with ErrInvalidPadding, got %v", err)
	}
}

func TestStreamOverflowAndNonceWrapGuard(t *testing.T) {
	// 1. Arithmetic helpers must never overflow or wrap negative near math.MaxInt64.
	if got := TotalBlocks(math.MaxInt64); got != math.MaxUint32 {
		t.Fatalf("TotalBlocks(MaxInt64) = %d, want MaxUint32 (%d)", got, uint32(math.MaxUint32))
	}
	if got := EncryptedPartSize(math.MaxInt64); got != math.MaxInt64 {
		t.Fatalf("EncryptedPartSize(MaxInt64) = %d, want MaxInt64", got)
	}
	if got := TransportChunkCount(math.MaxInt64, 16); got <= 0 {
		t.Fatalf("TransportChunkCount(MaxInt64, 16) = %d, must be positive", got)
	}

	// 2. Stream encryption/decryption near uint32 block ceiling (math.MaxUint32):
	// Starting at MaxUint32-1:
	// - 2 blocks (MaxUint32-1 non-final, MaxUint32 final) MUST succeed.
	// - 2 blocks + 1 byte (which would make MaxUint32 non-final and wrap to 0!) MUST fail with ErrStreamTooLarge!
	var key [32]byte
	var np [7]byte
	var msgID [16]byte
	copy(key[:], bytes.Repeat([]byte{0x91}, 32))
	copy(np[:], bytes.Repeat([]byte{0x92}, 7))
	copy(msgID[:], bytes.Repeat([]byte{0x93}, 16))

	sc, err := NewStreamCipher(key, np, msgID, 1)
	if err != nil {
		t.Fatal(err)
	}

	twoBlocksPT := detPatternBytes(2 * ChunkPlaintextMax)
	var ctBuf bytes.Buffer
	ptN, ctN, err := encryptPartStreamFrom(bytes.NewReader(twoBlocksPT), &ctBuf, sc, math.MaxUint32-1)
	if err != nil || ptN != int64(len(twoBlocksPT)) || ctN != 2*ChunkCiphertextMax {
		t.Fatalf("expected exact 2 blocks ending at MaxUint32 to succeed: pt=%d ct=%d err=%v", ptN, ctN, err)
	}
	var decBuf bytes.Buffer
	decN, err := decryptPartStreamFrom(bytes.NewReader(ctBuf.Bytes()), &decBuf, sc, math.MaxUint32-1)
	if err != nil || decN != int64(len(twoBlocksPT)) || !bytes.Equal(decBuf.Bytes(), twoBlocksPT) {
		t.Fatalf("expected decrypt at MaxUint32-1..MaxUint32 to succeed: n=%d err=%v", decN, err)
	}

	overflowPT := make([]byte, 2*ChunkPlaintextMax+1)
	var badCT bytes.Buffer
	if _, _, err := encryptPartStreamFrom(bytes.NewReader(overflowPT), &badCT, sc, math.MaxUint32-1); !errors.Is(err, ErrStreamTooLarge) {
		t.Fatalf("expected encrypt wrap past MaxUint32 to fail with ErrStreamTooLarge, got %v", err)
	}

	// Craft ciphertext stream with >1 block starting at MaxUint32 so decryptPartStreamFrom hits the same guard.
	b0, _ := sc.SealBlockAt(math.MaxUint32, false, twoBlocksPT[:ChunkPlaintextMax], nil)
	forgedOverflowCT := append(b0, byte(0x00))
	var sink bytes.Buffer
	if _, err := decryptPartStreamFrom(bytes.NewReader(forgedOverflowCT), &sink, sc, math.MaxUint32); !errors.Is(err, ErrStreamTooLarge) {
		t.Fatalf("expected decrypt wrap past MaxUint32 to fail with ErrStreamTooLarge, got %v", err)
	}
}

func TestSmallOrderAndNonCanonicalEd25519PublicKeysRejected(t *testing.T) {
	badPKHexes := []string{
		"0000000000000000000000000000000000000000000000000000000000000000", // y=0 (order 4)
		"0000000000000000000000000000000000000000000000000000000000000080", // y=0, sign=1
		"0100000000000000000000000000000000000000000000000000000000000000", // y=1 (identity)
		"0100000000000000000000000000000000000000000000000000000000000080", // y=1, sign=1
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05", // order 8
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85", // order 8, sign=1
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a", // order 8
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa", // order 8, sign=1
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // y=p-1 (order 2)
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", // y=p-1, sign=1
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // y=p (non-canonical)
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // y=p+1 (non-canonical)
		"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", // non-canonical > p
	}
	var zeroSig [64]byte
	// Forged trivial (R=I, S=0) signature that naive non-torsion-checked verifiers might accept for pk=I:
	zeroSig[0] = 0x01
	kem := bytes.Repeat([]byte{0x42}, 32)
	for _, h := range badPKHexes {
		pk := mustHex(t, h)
		if !IsSmallOrderOrNonCanonicalEd25519PK(pk) {
			t.Fatalf("expected IsSmallOrderOrNonCanonicalEd25519PK(%s) == true", h)
		}
		_, devID := DeriveDeviceID(pk)
		if err := VerifyDeviceCard(devID, pk, kem, 1700000000, zeroSig[:]); !errors.Is(err, ErrInvalidSignature) {
			t.Fatalf("VerifyDeviceCard(%s) got %v, want ErrInvalidSignature", h, err)
		}
		mbID := DeriveMailboxID(pk)
		if VerifyMailboxRequest(ed25519.PublicKey(pk), "GET", "/v1/ping", mbID, "1700000000", strings.Repeat("a", 32), BodyBindingControl(nil), base64.RawURLEncoding.EncodeToString(zeroSig[:])) {
			t.Fatalf("VerifyMailboxRequest(%s) unexpectedly succeeded", h)
		}
	}
}
