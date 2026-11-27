package crypto

import (
	"bytes"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func testVectorsDir(t *testing.T) string {
	t.Helper()
	// sdk/go/crypto -> ../../../spec/test-vectors
	return filepath.Join("..", "..", "..", "spec", "test-vectors")
}

func writeOrVerifyVector(t *testing.T, filename string, v any) {
	t.Helper()
	dir := testVectorsDir(t)
	path := filepath.Join(dir, filename)

	gotJSON, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatalf("marshal %s: %v", filename, err)
	}
	gotJSON = append(gotJSON, '\n')

	regen := os.Getenv("SYNCTOOL_REGEN_VECTORS") == "1"
	if _, statErr := os.Stat(path); os.IsNotExist(statErr) || regen {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
		if err := os.WriteFile(path, gotJSON, 0o644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}

	wantJSON, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if !bytes.Equal(bytes.ReplaceAll(wantJSON, []byte("\r\n"), []byte("\n")), gotJSON) {
		t.Fatalf("golden vector %s drifted from deterministic output (run with SYNCTOOL_REGEN_VECTORS=1 to update)", filename)
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex decode %q: %v", s, err)
	}
	return b
}

func detPatternBytes(n int) []byte {
	b := make([]byte, n)
	for i := 0; i < n; i++ {
		b[i] = byte((i*31 + 7) & 0xff)
	}
	return b
}

func TestVector01SeedAndKeys(t *testing.T) {
	seed := mustHex(t, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	origin := "https://relay.example.com:443"
	var issuedAt int64 = 1764246000

	dk, err := DeriveDeviceKeys(seed)
	if err != nil {
		t.Fatalf("DeriveDeviceKeys: %v", err)
	}
	canon, err := CanonicalRelayOrigin("HTTPS://Relay.Example.COM/")
	if err != nil || canon != origin {
		t.Fatalf("CanonicalRelayOrigin got %q err %v", canon, err)
	}
	relayID := DeriveRelayID(canon)
	mk, err := dk.DeriveMailboxKeys(relayID)
	if err != nil {
		t.Fatalf("DeriveMailboxKeys: %v", err)
	}
	cardInput, err := DeviceCardSignInput(dk.SignPub, dk.KEMPubBytes[:], issuedAt)
	if err != nil {
		t.Fatalf("DeviceCardSignInput: %v", err)
	}
	cardSig, err := SignDeviceCard(dk.SignPriv, dk.KEMPubBytes[:], issuedAt)
	if err != nil {
		t.Fatalf("SignDeviceCard: %v", err)
	}
	if err := VerifyDeviceCard(dk.DeviceID, dk.SignPub, dk.KEMPubBytes[:], issuedAt, cardSig); err != nil {
		t.Fatalf("VerifyDeviceCard: %v", err)
	}

	edPKCS8, _ := EncodeEd25519PKCS8(dk.SignSeed[:])
	xPKCS8, _ := EncodeX25519PKCS8(dk.KEMPrivBytes[:])
	edSPKI, _ := EncodeEd25519SPKI(dk.SignPub)
	xSPKI, _ := EncodeX25519SPKI(dk.KEMPubBytes[:])

	badSig := append([]byte(nil), cardSig...)
	badSig[0] ^= 0x01
	if err := VerifyDeviceCard(dk.DeviceID, dk.SignPub, dk.KEMPubBytes[:], issuedAt, badSig); err == nil {
		t.Fatal("expected VerifyDeviceCard to reject tampered sig")
	}
	if err := VerifyDeviceCard("00000000000000000000000000000000", dk.SignPub, dk.KEMPubBytes[:], issuedAt, cardSig); err == nil {
		t.Fatal("expected VerifyDeviceCard to reject mismatched device_id")
	}

	vec := map[string]any{
		"vector":                 "01_seed_and_keys",
		"proto_v":                1,
		"device_master_seed_hex": hex.EncodeToString(seed),
		"canonical_relay_origin": origin,
		"issued_at":              issuedAt,
		"expected": map[string]any{
			"master_prk_hex":        hex.EncodeToString(dk.MasterPRK[:]),
			"sign_seed_hex":         hex.EncodeToString(dk.SignSeed[:]),
			"sign_pk_hex":           hex.EncodeToString(dk.SignPub),
			"sign_pk_b64u":          base64.RawURLEncoding.EncodeToString(dk.SignPub),
			"kem_sk_hex":            hex.EncodeToString(dk.KEMPrivBytes[:]),
			"kem_pk_hex":            hex.EncodeToString(dk.KEMPubBytes[:]),
			"kem_pk_b64u":           base64.RawURLEncoding.EncodeToString(dk.KEMPubBytes[:]),
			"local_meta_key_hex":    hex.EncodeToString(dk.LocalMetaKey[:]),
			"device_id":             dk.DeviceID,
			"relay_id":              relayID,
			"mailbox_auth_seed_hex": hex.EncodeToString(mk.AuthSeed[:]),
			"mailbox_auth_pk_hex":   hex.EncodeToString(mk.AuthPub),
			"mailbox_auth_pk_b64u":  base64.RawURLEncoding.EncodeToString(mk.AuthPub),
			"mailbox_id":            mk.MailboxID,
			"card_sig_input_hex":    hex.EncodeToString(cardInput),
			"card_sig_hex":          hex.EncodeToString(cardSig),
			"card_sig_b64u":         base64.RawURLEncoding.EncodeToString(cardSig),
			"ed25519_pkcs8_der_hex": hex.EncodeToString(edPKCS8),
			"x25519_pkcs8_der_hex":  hex.EncodeToString(xPKCS8),
			"ed25519_spki_der_hex":  hex.EncodeToString(edSPKI),
			"x25519_spki_der_hex":   hex.EncodeToString(xSPKI),
		},
		"negative_cases": map[string]any{
			"wrong_device_id":  "00000000000000000000000000000000",
			"tampered_sig_hex": hex.EncodeToString(badSig),
		},
	}
	writeOrVerifyVector(t, "01_seed_and_keys.json", vec)
}

func TestVector02RelayAuthSig(t *testing.T) {
	accessKey := "SYNCTOOL-TEST-ACCESS-KEY-0123456789ABCDEF"
	hmacKey := DeriveRelayHMACKey(accessKey)

	type reqCase struct {
		Name                   string `json:"name"`
		Method                 string `json:"method"`
		PathAndRawQuery        string `json:"path_and_raw_query"`
		TS                     string `json:"ts"`
		Nonce                  string `json:"nonce"`
		IsStream               bool   `json:"is_stream"`
		RawBodyUTF8            string `json:"raw_body_utf8,omitempty"`
		StreamContentLength    int64  `json:"stream_content_length,omitempty"`
		DepositToken           string `json:"deposit_token,omitempty"`
		UploadToken            string `json:"upload_token,omitempty"`
		ExpectedBodyBinding    string `json:"expected_body_binding"`
		ExpectedExtraTokenBind string `json:"expected_extra_token_binding"`
		ExpectedCanonicalReq   string `json:"expected_canonical_req"`
		ExpectedSigHex         string `json:"expected_sig_hex"`
	}

	rawCases := []reqCase{
		{
			Name:            "control_empty_get_ping",
			Method:          "GET",
			PathAndRawQuery: "/v1/ping",
			TS:              "1764246000",
			Nonce:           "0102030405060708090a0b0c0d0e0f10",
		},
		{
			Name:            "control_query_get_events",
			Method:          "GET",
			PathAndRawQuery: "/v1/mailboxes/9f8e7d6c5b4a39281706f5e4d3c2b1a0/events?since_ts=0",
			TS:              "1764246005",
			Nonce:           "1112131415161718191a1b1c1d1e1f20",
		},
		{
			Name:            "control_post_spool_init_with_deposit",
			Method:          "POST",
			PathAndRawQuery: "/v1/spool/init",
			TS:              "1764246010",
			Nonce:           "2122232425262728292a2b2c2d2e2f30",
			RawBodyUTF8:     `{"mailbox_id":"9f8e7d6c5b4a39281706f5e4d3c2b1a0","declared_total_bytes":4112}`,
			DepositToken:    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		},
		{
			Name:                "data_stream_put_spool_with_upload",
			Method:              "PUT",
			PathAndRawQuery:     "/v1/spool/itm_11223344556677889900aabbccddeeff/parts/1/chunks/0",
			TS:                  "1764246015",
			Nonce:               "3132333435363738393a3b3c3d3e3f40",
			IsStream:            true,
			StreamContentLength: 1048832,
			UploadToken:         "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
		},
		{
			Name:                "data_stream_put_pipe_no_extra_token",
			Method:              "PUT",
			PathAndRawQuery:     "/v1/pipe/a1b2c3d4e5f60718293a4b5c6d7e8f90/parts/0/chunks/0",
			TS:                  "1764246020",
			Nonce:               "4142434445464748494a4b4c4d4e4f50",
			IsStream:            true,
			StreamContentLength: 4112,
		},
		{
			Name:            "control_delete_spool_with_upload",
			Method:          "DELETE",
			PathAndRawQuery: "/v1/spool/itm_11223344556677889900aabbccddeeff",
			TS:              "1764246025",
			Nonce:           "5152535455565758595a5b5c5d5e5f60",
			UploadToken:     "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
		},
	}

	for i := range rawCases {
		c := &rawCases[i]
		if c.IsStream {
			c.ExpectedBodyBinding = BodyBindingStream(c.StreamContentLength)
		} else {
			c.ExpectedBodyBinding = BodyBindingControl([]byte(c.RawBodyUTF8))
		}
		c.ExpectedExtraTokenBind = ExtraTokenBinding(c.DepositToken, c.UploadToken)
		c.ExpectedCanonicalReq = BuildCanonicalRequest(c.Method, c.PathAndRawQuery, c.TS, c.Nonce, c.ExpectedBodyBinding, c.ExpectedExtraTokenBind)
		c.ExpectedSigHex = SignRelayRequest(accessKey, c.Method, c.PathAndRawQuery, c.TS, c.Nonce, c.ExpectedBodyBinding, c.ExpectedExtraTokenBind)
		if !VerifyRelayRequest(accessKey, c.Method, c.PathAndRawQuery, c.TS, c.Nonce, c.ExpectedBodyBinding, c.ExpectedExtraTokenBind, c.ExpectedSigHex) {
			t.Fatalf("VerifyRelayRequest failed on %s", c.Name)
		}
	}

	seed := mustHex(t, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	dk, _ := DeriveDeviceKeys(seed)
	mk, _ := dk.DeriveMailboxKeys(DeriveRelayID("https://relay.example.com:443"))
	mbBody := `{}`
	mbBodyBind := BodyBindingControl([]byte(mbBody))
	mbPath := "/v1/spool/itm_11223344556677889900aabbccddeeff/ack"
	mbTS := "1764246030"
	mbNonce := "6162636465666768696a6b6c6d6e6f70"
	mbSigIn := BuildMailboxSigInput("POST", mbPath, mk.MailboxID, mbTS, mbNonce, mbBodyBind)
	mbSig := SignMailboxRequest(mk.AuthPriv, "POST", mbPath, mk.MailboxID, mbTS, mbNonce, mbBodyBind)
	if !VerifyMailboxRequest(mk.AuthPub, "POST", mbPath, mk.MailboxID, mbTS, mbNonce, mbBodyBind, mbSig) {
		t.Fatal("VerifyMailboxRequest failed")
	}

	vec := map[string]any{
		"vector":                      "02_relay_auth_sig",
		"proto_v":                     1,
		"access_key":                  accessKey,
		"expected_relay_hmac_key_hex": hex.EncodeToString(hmacKey[:]),
		"deposit_token_sample_hash":   HashDepositToken("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
		"upload_token_sample_hash":    HashUploadToken("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"),
		"cases":                       rawCases,
		"mailbox_sig_case": map[string]any{
			"mailbox_auth_seed_hex":     hex.EncodeToString(mk.AuthSeed[:]),
			"mailbox_auth_pk_b64u":      base64.RawURLEncoding.EncodeToString(mk.AuthPub),
			"mailbox_id":                mk.MailboxID,
			"method":                    "POST",
			"path_and_raw_query":        mbPath,
			"ts":                        mbTS,
			"nonce":                     mbNonce,
			"raw_body_utf8":             mbBody,
			"expected_body_binding":     mbBodyBind,
			"expected_sig_input":        mbSigIn,
			"expected_mailbox_sig_b64u": mbSig,
		},
		"clock_skew_cases": map[string]any{
			"server_ts":    1764246000,
			"max_skew_sec": 60,
			"cases": []map[string]any{
				{"ts": 1764245940, "expect_clock_skew_409": false},
				{"ts": 1764246060, "expect_clock_skew_409": false},
				{"ts": 1764245939, "expect_clock_skew_409": true},
				{"ts": 1764246061, "expect_clock_skew_409": true},
			},
		},
	}
	writeOrVerifyVector(t, "02_relay_auth_sig.json", vec)
}

func TestVector03HandshakeQROOB(t *testing.T) {
	roomID := "K7M9P2XQ"
	eASk := mustHex(t, "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f")
	eBSk := mustHex(t, "303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f")
	nA := mustHex(t, "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf")
	nB := mustHex(t, "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf")
	oob := mustHex(t, "0f1e2d3c4b5a69788796a5b4c3d2e1f0")

	privA, err := ecdh.X25519().NewPrivateKey(eASk)
	if err != nil {
		t.Fatal(err)
	}
	privB, err := ecdh.X25519().NewPrivateKey(eBSk)
	if err != nil {
		t.Fatal(err)
	}
	pubA := privA.PublicKey().Bytes()
	pubB := privB.PublicKey().Bytes()

	shared, err := X25519SharedSecret(privA, pubB)
	if err != nil {
		t.Fatal(err)
	}
	t1, err := BuildQRTranscript(PurposeOneshot, roomID, pubA, nA, pubB, nB)
	if err != nil || len(t1) != 154 {
		t.Fatalf("BuildQRTranscript len=%d err=%v", len(t1), err)
	}
	resA, err := DeriveQROOBSession(PurposeOneshot, roomID, privA, pubB, pubA, nA, pubB, nB, oob)
	if err != nil {
		t.Fatal(err)
	}
	resB, err := DeriveQROOBSession(PurposeOneshot, roomID, privB, pubA, pubA, nA, pubB, nB, oob)
	if err != nil {
		t.Fatal(err)
	}
	if resA.SessionKey != resB.SessionKey || resA.MacA != resB.MacA || resA.MacB != resB.MacB {
		t.Fatal("initiator and responder QR OOB results mismatch")
	}

	msgID := mustHex(t, "9f86d081884c7d659a2feaa0c55ad015")
	p0Key, p0NP, err := DeriveOneshotPart0Keys(resA.SessionKey[:], msgID)
	if err != nil {
		t.Fatal(err)
	}
	ctrlKey, ctrlNP, err := DerivePipeCtrlKeys(resA.TH[:], resA.SessionKey[:])
	if err != nil {
		t.Fatal(err)
	}
	startPT := `{"op":"pipe_start","msg_id":"9f86d081884c7d659a2feaa0c55ad015","blocks_per_chunk":16,"parts":[{"part_id":0,"total_bytes":4112,"chunk_count":1}]}`
	ackPT := `{"op":"pipe_ack","msg_id":"9f86d081884c7d659a2feaa0c55ad015"}`
	startCT, err := SealPipeCtrl(ctrlKey, ctrlNP, resA.TH[:], 0, []byte(startPT))
	if err != nil {
		t.Fatal(err)
	}
	ackCT, err := SealPipeCtrl(ctrlKey, ctrlNP, resA.TH[:], 1, []byte(ackPT))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := OpenPipeCtrl(ctrlKey, ctrlNP, resB.TH[:], 0, startCT); err != nil || string(got) != startPT {
		t.Fatalf("OpenPipeCtrl(0) failed: %v", err)
	}
	if got, err := OpenPipeCtrl(ctrlKey, ctrlNP, resA.TH[:], 1, ackCT); err != nil || string(got) != ackPT {
		t.Fatalf("OpenPipeCtrl(1) failed: %v", err)
	}
	aad0, _ := BuildPipeCtrlAAD(resA.TH[:], 0)
	aad1, _ := BuildPipeCtrlAAD(resA.TH[:], 1)

	// PairBindPayload encryption (including mailbox: null case for --spool=off)
	resPair, err := DeriveQROOBSession(PurposePair, roomID, privA, pubB, pubA, nA, pubB, nB, oob)
	if err != nil {
		t.Fatal(err)
	}
	pairNA, pairNB, err := DerivePairBindNonces(resPair.PRK[:])
	if err != nil {
		t.Fatal(err)
	}
	bindAJSON := `{"device_card":{"device_id":"11111111111111111111111111111111","label":"Desktop","platform":"windows"},"mailbox":{"relay_origin":"https://relay.example.com:443","mailbox_id":"22222222222222222222222222222222","deposit_token":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}}`
	bindBJSON := `{"device_card":{"device_id":"33333333333333333333333333333333","label":"Phone","platform":"android"},"mailbox":null}`
	ctBindA, err := SealPairBind(resPair.SessionKey, resPair.PRK[:], resPair.TH[:], true, []byte(bindAJSON))
	if err != nil {
		t.Fatal(err)
	}
	ctBindB, err := SealPairBind(resPair.SessionKey, resPair.PRK[:], resPair.TH[:], false, []byte(bindBJSON))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := OpenPairBind(resPair.SessionKey, resPair.PRK[:], resPair.TH[:], true, ctBindA); err != nil || string(got) != bindAJSON {
		t.Fatalf("OpenPairBind(A) failed: %v", err)
	}
	if got, err := OpenPairBind(resPair.SessionKey, resPair.PRK[:], resPair.TH[:], false, ctBindB); err != nil || string(got) != bindBJSON {
		t.Fatalf("OpenPairBind(B) failed: %v", err)
	}

	// Negative tests
	wrongOOB := append([]byte(nil), oob...)
	wrongOOB[0] ^= 0x01
	resWrong, err := DeriveQROOBSession(PurposeOneshot, roomID, privB, pubA, pubA, nA, pubB, nB, wrongOOB)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyMAC(resA.MacB, resWrong.MacB[:]); err == nil {
		t.Fatal("expected VerifyMAC to fail on 1-bit flipped oob_secret")
	}
	lowOrderPK := make([]byte, 32) // all zeros low-order point
	if _, err := X25519SharedSecret(privA, lowOrderPK); err == nil {
		t.Fatal("expected all-zero X25519 peer public key to be rejected")
	}

	vec := map[string]any{
		"vector":         "03_handshake_qr_oob",
		"proto_v":        1,
		"mode":           1,
		"purpose":        PurposeOneshot,
		"purpose_code":   PurposeCodeOneshot,
		"room_id":        roomID,
		"e_a_sk_hex":     hex.EncodeToString(eASk),
		"e_a_pk_hex":     hex.EncodeToString(pubA),
		"n_a_hex":        hex.EncodeToString(nA),
		"e_b_sk_hex":     hex.EncodeToString(eBSk),
		"e_b_pk_hex":     hex.EncodeToString(pubB),
		"n_b_hex":        hex.EncodeToString(nB),
		"oob_secret_hex": hex.EncodeToString(oob),
		"expected": map[string]any{
			"shared_hex":        hex.EncodeToString(shared),
			"transcript_1_hex":  hex.EncodeToString(t1),
			"th_hex":            hex.EncodeToString(resA.TH[:]),
			"prk_hex":           hex.EncodeToString(resA.PRK[:]),
			"session_key_hex":   hex.EncodeToString(resA.SessionKey[:]),
			"confirm_key_a_hex": hex.EncodeToString(resA.ConfirmKeyA[:]),
			"confirm_key_b_hex": hex.EncodeToString(resA.ConfirmKeyB[:]),
			"mac_a_b64u":        base64.RawURLEncoding.EncodeToString(resA.MacA[:]),
			"mac_b_b64u":        base64.RawURLEncoding.EncodeToString(resA.MacB[:]),
		},
		"oneshot_part0": map[string]any{
			"msg_id_hex":                      hex.EncodeToString(msgID),
			"expected_part0_key_hex":          hex.EncodeToString(p0Key[:]),
			"expected_part0_nonce_prefix_hex": hex.EncodeToString(p0NP[:]),
		},
		"pipe_ctrl": map[string]any{
			"expected_ctrl_key_hex": hex.EncodeToString(ctrlKey[:]),
			"expected_ctrl_np_hex":  hex.EncodeToString(ctrlNP[:]),
			"frames": []map[string]any{
				{
					"ctrl_seq":         0,
					"plaintext_utf8":   startPT,
					"expected_aad_hex": hex.EncodeToString(aad0[:]),
					"expected_ct_b64u": base64.RawURLEncoding.EncodeToString(startCT),
				},
				{
					"ctrl_seq":         1,
					"plaintext_utf8":   ackPT,
					"expected_aad_hex": hex.EncodeToString(aad1[:]),
					"expected_ct_b64u": base64.RawURLEncoding.EncodeToString(ackCT),
				},
			},
		},
		"pair_bind": map[string]any{
			"purpose":                   PurposePair,
			"purpose_code":              PurposeCodePair,
			"expected_th_hex":           hex.EncodeToString(resPair.TH[:]),
			"expected_prk_hex":          hex.EncodeToString(resPair.PRK[:]),
			"expected_session_key_hex":  hex.EncodeToString(resPair.SessionKey[:]),
			"expected_pair_nonce_a_hex": hex.EncodeToString(pairNA[:]),
			"expected_pair_nonce_b_hex": hex.EncodeToString(pairNB[:]),
			"plaintext_a_utf8":          bindAJSON,
			"plaintext_b_utf8":          bindBJSON,
			"expected_ct_a_b64u":        base64.RawURLEncoding.EncodeToString(ctBindA),
			"expected_ct_b_b64u":        base64.RawURLEncoding.EncodeToString(ctBindB),
		},
		"negative_cases": map[string]any{
			"wrong_oob_secret_hex":      hex.EncodeToString(wrongOOB),
			"low_order_all_zero_pk_hex": hex.EncodeToString(lowOrderPK),
		},
	}
	writeOrVerifyVector(t, "03_handshake_qr_oob.json", vec)
}

func TestVector04HandshakeCommitSAS(t *testing.T) {
	roomID := "9F2W4C8H"
	eASk := mustHex(t, "505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f")
	eBSk := mustHex(t, "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f")
	nB := mustHex(t, "d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef")

	privA, _ := ecdh.X25519().NewPrivateKey(eASk)
	privB, _ := ecdh.X25519().NewPrivateKey(eBSk)
	pubA := privA.PublicKey().Bytes()
	pubB := privB.PublicKey().Bytes()

	// Deterministically select a fixed nA that yields a leading-zero 6-digit SAS (< 10000)
	// so all SDKs are explicitly verified for zero-padding ("00xxxx").
	nA := make([]byte, 32)
	var commitA [32]byte
	var resA *HandshakeResult
	for ctr := 0; ctr < 2000; ctr++ {
		for i := 0; i < 32; i++ {
			nA[i] = byte((i + ctr) & 0xff)
		}
		nA[0] = byte(ctr >> 8)
		nA[1] = byte(ctr & 0xff)
		c, err := ComputeCommitA(PurposePair, roomID, pubA, nA)
		if err != nil {
			t.Fatal(err)
		}
		r, err := DeriveSASSession(PurposePair, roomID, privA, pubB, c[:], pubA, nA, pubB, nB)
		if err != nil {
			t.Fatal(err)
		}
		if r.SASInt < 10000 {
			commitA = c
			resA = r
			break
		}
	}
	if resA == nil || len(resA.SASStr) != 6 || resA.SASStr[0] != '0' || resA.SASStr[1] != '0' {
		t.Fatalf("failed to find leading-zero SAS vector: got %+v", resA)
	}

	resB, err := DeriveSASSession(PurposePair, roomID, privB, pubA, commitA[:], pubA, nA, pubB, nB)
	if err != nil {
		t.Fatal(err)
	}
	if resA.SessionKey != resB.SessionKey || resA.SASStr != resB.SASStr || resA.MacA != resB.MacA || resA.MacB != resB.MacB {
		t.Fatal("initiator and responder SAS handshake results mismatch")
	}

	shared, _ := X25519SharedSecret(privA, pubB)
	t2, _ := BuildSASTranscript(PurposePair, roomID, commitA[:], pubA, nA, pubB, nB)
	if len(t2) != 187 {
		t.Fatalf("expected transcript_2 len 187, got %d", len(t2))
	}

	ctrlKey, ctrlNP, _ := DerivePipeCtrlKeys(resA.TH[:], resA.SessionKey[:])
	ctrlPT := `{"op":"pipe_start","msg_id":"00112233445566778899aabbccddeeff","blocks_per_chunk":4,"parts":[{"part_id":0,"total_bytes":4112,"chunk_count":1}]}`
	ctrlCT, err := SealPipeCtrl(ctrlKey, ctrlNP, resA.TH[:], 0, []byte(ctrlPT))
	if err != nil {
		t.Fatal(err)
	}

	// Negative test: mutated E_a fails commit_a check
	tamperedPubA := append([]byte(nil), pubA...)
	tamperedPubA[0] ^= 0x80
	if err := VerifyCommitA(PurposePair, roomID, tamperedPubA, nA, commitA[:]); err == nil {
		t.Fatal("expected VerifyCommitA to fail on tampered E_a")
	}

	vec := map[string]any{
		"vector":       "04_handshake_commit_sas",
		"proto_v":      1,
		"mode":         2,
		"purpose":      PurposePair,
		"purpose_code": PurposeCodePair,
		"room_id":      roomID,
		"e_a_sk_hex":   hex.EncodeToString(eASk),
		"e_a_pk_hex":   hex.EncodeToString(pubA),
		"n_a_hex":      hex.EncodeToString(nA),
		"e_b_sk_hex":   hex.EncodeToString(eBSk),
		"e_b_pk_hex":   hex.EncodeToString(pubB),
		"n_b_hex":      hex.EncodeToString(nB),
		"expected": map[string]any{
			"commit_a_hex":           hex.EncodeToString(commitA[:]),
			"commit_a_b64u":          base64.RawURLEncoding.EncodeToString(commitA[:]),
			"shared_hex":             hex.EncodeToString(shared),
			"transcript_2_hex":       hex.EncodeToString(t2),
			"th_hex":                 hex.EncodeToString(resA.TH[:]),
			"prk_hex":                hex.EncodeToString(resA.PRK[:]),
			"session_key_hex":        hex.EncodeToString(resA.SessionKey[:]),
			"sas_bytes_hex":          hex.EncodeToString(resA.SASBytes[:]),
			"sas_int":                resA.SASInt,
			"sas_str":                resA.SASStr,
			"confirm_key_a_hex":      hex.EncodeToString(resA.ConfirmKeyA[:]),
			"confirm_key_b_hex":      hex.EncodeToString(resA.ConfirmKeyB[:]),
			"mac_a_b64u":             base64.RawURLEncoding.EncodeToString(resA.MacA[:]),
			"mac_b_b64u":             base64.RawURLEncoding.EncodeToString(resA.MacB[:]),
			"pipe_ctrl_key_hex":      hex.EncodeToString(ctrlKey[:]),
			"pipe_ctrl_np_hex":       hex.EncodeToString(ctrlNP[:]),
			"pipe_ctrl_seq0_pt_utf8": ctrlPT,
			"pipe_ctrl_seq0_ct_b64u": base64.RawURLEncoding.EncodeToString(ctrlCT),
		},
		"negative_cases": map[string]any{
			"tampered_e_a_pk_hex": hex.EncodeToString(tamperedPubA),
		},
	}
	writeOrVerifyVector(t, "04_handshake_commit_sas.json", vec)
}
