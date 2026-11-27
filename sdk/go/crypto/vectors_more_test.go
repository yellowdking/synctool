package crypto

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"testing"
)

func TestVector05Paired0RTTEnvelope(t *testing.T) {
	senderSeed := mustHex(t, "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
	recipSeed := mustHex(t, "a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0")
	wrongSeed := mustHex(t, "f1f2f3f4f5f6f7f8f9fafbfcfdfeff000102030405060708090a0b0c0d0e0f10")
	ephSk := mustHex(t, "2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40")

	var msgID [16]byte
	copy(msgID[:], mustHex(t, "9f86d081884c7d659a2feaa0c55ad015"))
	var createdAt int64 = 1764246000
	manifestJSON := `{"envelope_version":1,"msg_id":"9f86d081884c7d659a2feaa0c55ad015","app_id":"synctool.system","schema":"device.ping.v1","created_at":1764246000,"sender":{"device_id":"placeholder","label":"Phone"},"inline_payload":{"echo":"ok"},"blobs":[]}`
	manifestSHA := sha256.Sum256([]byte(manifestJSON))

	senderDK, _ := DeriveDeviceKeys(senderSeed)
	recipDK, _ := DeriveDeviceKeys(recipSeed)
	wrongDK, _ := DeriveDeviceKeys(wrongSeed)
	ephPriv, _ := ecdh.X25519().NewPrivateKey(ephSk)

	sealedHdr, _, p0Key, p0NP, err := Seal0RTTHeaderDeterministic(
		senderDK, ephPriv, msgID, recipDK.DeviceIDRaw, recipDK.KEMPubBytes[:], createdAt, manifestSHA,
	)
	if err != nil {
		t.Fatalf("Seal0RTTHeaderDeterministic: %v", err)
	}
	sealedB64 := base64.RawURLEncoding.EncodeToString(sealedHdr[:])
	if len(sealedHdr) != 208 || len(sealedB64) != 278 {
		t.Fatalf("unexpected sealed header size bytes=%d b64u=%d", len(sealedHdr), len(sealedB64))
	}

	opened, err := Open0RTTHeader(recipDK, sealedHdr[:], func(senderID string) (ed25519.PublicKey, error) {
		if senderID == senderDK.DeviceID {
			return senderDK.SignPub, nil
		}
		return nil, ErrUntrustedSender
	})
	if err != nil {
		t.Fatalf("Open0RTTHeader: %v", err)
	}
	if opened.Part0Key != p0Key || opened.Part0NoncePrefix != p0NP || opened.ManifestSHA256 != manifestSHA {
		t.Fatal("opened 0-RTT header mismatch")
	}

	sigInput, _ := BuildZeroRTTSigInput(sealedHdr[:ClearHeaderSize], senderDK.DeviceIDRaw, recipDK.DeviceIDRaw, createdAt, manifestSHA)
	directAck := ComputeDirectAckMAC(p0Key, msgID)
	if err := VerifyDirectAckMAC(p0Key, msgID, directAck[:]); err != nil {
		t.Fatalf("VerifyDirectAckMAC: %v", err)
	}

	// Negative cases
	tamperedHdr := sealedHdr
	tamperedHdr[10] ^= 0x01 // mutate clear_header msg_id byte (AAD + sig failure)
	if _, err := Open0RTTHeader(recipDK, tamperedHdr[:], func(string) (ed25519.PublicKey, error) { return senderDK.SignPub, nil }); err == nil {
		t.Fatal("expected tampered clear_header to fail")
	}
	if _, err := Open0RTTHeader(wrongDK, sealedHdr[:], func(string) (ed25519.PublicKey, error) { return senderDK.SignPub, nil }); err == nil {
		t.Fatal("expected wrong recipient key to fail")
	}
	badAck := directAck
	badAck[0] ^= 0x01
	if err := VerifyDirectAckMAC(p0Key, msgID, badAck[:]); err == nil {
		t.Fatal("expected tampered direct_ack to fail")
	}

	vec := map[string]any{
		"vector":                    "05_paired_0rtt_envelope",
		"proto_v":                   1,
		"sender_master_seed_hex":    hex.EncodeToString(senderSeed),
		"recipient_master_seed_hex": hex.EncodeToString(recipSeed),
		"ephemeral_sk_hex":          hex.EncodeToString(ephSk),
		"ephemeral_pk_hex":          hex.EncodeToString(ephPriv.PublicKey().Bytes()),
		"msg_id_hex":                hex.EncodeToString(msgID[:]),
		"created_at":                createdAt,
		"manifest_utf8":             manifestJSON,
		"manifest_sha256_hex":       hex.EncodeToString(manifestSHA[:]),
		"expected": map[string]any{
			"sender_device_id":       senderDK.DeviceID,
			"sender_sign_pk_b64u":    base64.RawURLEncoding.EncodeToString(senderDK.SignPub),
			"recipient_device_id":    recipDK.DeviceID,
			"recipient_kem_pk_b64u":  base64.RawURLEncoding.EncodeToString(recipDK.KEMPubBytes[:]),
			"clear_header_hex":       hex.EncodeToString(sealedHdr[:ClearHeaderSize]),
			"sig_input_hex":          hex.EncodeToString(sigInput[:]),
			"sender_sig_b64u":        base64.RawURLEncoding.EncodeToString(opened.SenderSig[:]),
			"sealed_header_hex":      hex.EncodeToString(sealedHdr[:]),
			"sealed_header_b64u":     sealedB64,
			"part0_key_hex":          hex.EncodeToString(p0Key[:]),
			"part0_nonce_prefix_hex": hex.EncodeToString(p0NP[:]),
			"direct_ack_mac_b64u":    base64.RawURLEncoding.EncodeToString(directAck[:]),
		},
		"negative_cases": map[string]any{
			"tampered_clear_header_b64u":      base64.RawURLEncoding.EncodeToString(tamperedHdr[:]),
			"wrong_recipient_master_seed_hex": hex.EncodeToString(wrongSeed),
			"tampered_direct_ack_mac_b64u":    base64.RawURLEncoding.EncodeToString(badAck[:]),
		},
	}
	writeOrVerifyVector(t, "05_paired_0rtt_envelope.json", vec)
}

func TestVector06StreamAEADAndPadding(t *testing.T) {
	// 1. Manifest 4 KiB padding cases
	padLens := []struct {
		name string
		size int
	}{
		{"len_1", 1},
		{"len_4092_exact_1_bucket", 4092},
		{"len_4093_rolls_2_buckets", 4093},
		{"len_65532_exact_16_buckets", 65532},
	}
	var padCases []map[string]any
	for _, tc := range padLens {
		raw := detPatternBytes(tc.size)
		padded, err := PadManifest(raw)
		if err != nil {
			t.Fatalf("PadManifest(%s): %v", tc.name, err)
		}
		got, err := UnpadManifest(padded)
		if err != nil || !bytes.Equal(got, raw) {
			t.Fatalf("UnpadManifest(%s) mismatch: err=%v", tc.name, err)
		}
		sum := sha256.Sum256(padded)
		padCases = append(padCases, map[string]any{
			"name":                   tc.name,
			"raw_len":                tc.size,
			"pattern":                "byte((i*31 + 7) & 0xff)",
			"expected_padded_len":    len(padded),
			"expected_padded_sha256": hex.EncodeToString(sum[:]),
			"expected_prefix_16_hex": hex.EncodeToString(padded[:16]),
		})
	}
	// Invalid padding vectors
	nonZeroTail := make([]byte, 4096)
	nonZeroTail[3] = 1
	nonZeroTail[4] = 'a'
	nonZeroTail[4095] = 0x01
	if _, err := UnpadManifest(nonZeroTail); err == nil {
		t.Fatal("expected non-zero tail padding to fail")
	}
	zeroLenPadded := make([]byte, 4096)
	if _, err := UnpadManifest(zeroLenPadded); err == nil {
		t.Fatal("expected L=0 padded manifest to fail")
	}

	// 2. STREAM AEAD multi-block cases
	var msgID [16]byte
	copy(msgID[:], mustHex(t, "9f86d081884c7d659a2feaa0c55ad015"))
	var partID uint32 = 1
	blobKey := mustHex(t, "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
	encKey, noncePfx, err := DeriveBlobPartKeys(msgID, partID, blobKey)
	if err != nil {
		t.Fatal(err)
	}

	streamLens := []struct {
		name string
		size int
	}{
		{"empty_0B", 0},
		{"small_100B", 100},
		{"exact_1block_65536B", 65536},
		{"two_blocks_65537B", 65537},
		{"multi_chunk_300000B", 300000},
	}

	var streamCases []map[string]any
	for _, tc := range streamLens {
		pt := detPatternBytes(tc.size)
		var ctBuf bytes.Buffer
		ptN, ctN, err := EncryptPartStream(bytes.NewReader(pt), &ctBuf, encKey, noncePfx, msgID, partID)
		if err != nil {
			t.Fatalf("EncryptPartStream(%s): %v", tc.name, err)
		}
		if ptN != int64(tc.size) || ctN != EncryptedPartSize(int64(tc.size)) {
			t.Fatalf("%s size mismatch pt=%d ct=%d want=%d", tc.name, ptN, ctN, EncryptedPartSize(int64(tc.size)))
		}
		ctBytes := ctBuf.Bytes()

		var decBuf bytes.Buffer
		decN, err := DecryptPartStream(bytes.NewReader(ctBytes), &decBuf, encKey, noncePfx, msgID, partID)
		if err != nil || decN != int64(tc.size) || !bytes.Equal(decBuf.Bytes(), pt) {
			t.Fatalf("DecryptPartStream(%s) mismatch: err=%v decN=%d", tc.name, err, decN)
		}

		totalBlk := TotalBlocks(int64(tc.size))
		lastBlkIdx := totalBlk - 1
		var lastPTLen uint32
		if tc.size > 0 {
			lastPTLen = uint32(((tc.size - 1) % ChunkPlaintextMax) + 1)
		}
		firstPTLen := uint32(tc.size)
		firstFinal := totalBlk == 1
		if !firstFinal {
			firstPTLen = ChunkPlaintextMax
		}
		firstNonce := BuildChunkNonce(noncePfx, 0, firstFinal)
		firstAAD := BuildChunkAAD(msgID, partID, 0, firstFinal, firstPTLen)
		lastNonce := BuildChunkNonce(noncePfx, lastBlkIdx, true)
		lastAAD := BuildChunkAAD(msgID, partID, lastBlkIdx, true, lastPTLen)
		ctSHA := sha256.Sum256(ctBytes)
		ptSHA := sha256.Sum256(pt)

		entry := map[string]any{
			"name":                       tc.name,
			"plaintext_len":              tc.size,
			"pattern":                    "byte((i*31 + 7) & 0xff)",
			"plaintext_sha256":           hex.EncodeToString(ptSHA[:]),
			"expected_total_blocks":      totalBlk,
			"expected_ciphertext_len":    len(ctBytes),
			"expected_ciphertext_sha256": hex.EncodeToString(ctSHA[:]),
			"expected_nano_chunk_count":  TransportChunkCount(int64(len(ctBytes)), 4),
			"expected_std_chunk_count":   TransportChunkCount(int64(len(ctBytes)), 16),
			"first_block_nonce_hex":      hex.EncodeToString(firstNonce[:]),
			"first_block_aad_hex":        hex.EncodeToString(firstAAD[:]),
			"last_block_nonce_hex":       hex.EncodeToString(lastNonce[:]),
			"last_block_aad_hex":         hex.EncodeToString(lastAAD[:]),
		}
		if tc.size <= 100 {
			entry["ciphertext_hex"] = hex.EncodeToString(ctBytes)
		} else {
			entry["ciphertext_first_32_hex"] = hex.EncodeToString(ctBytes[:32])
			entry["ciphertext_last_32_hex"] = hex.EncodeToString(ctBytes[len(ctBytes)-32:])
		}
		streamCases = append(streamCases, entry)

		// Negative checks on multi-block streams
		if tc.name == "two_blocks_65537B" {
			// Truncation: drop block 1, leaving only block 0 (encrypted with is_final=0x00)
			if _, err := DecryptPartStream(bytes.NewReader(ctBytes[:ChunkCiphertextMax]), &bytes.Buffer{}, encKey, noncePfx, msgID, partID); err == nil {
				t.Fatal("expected truncated stream to fail")
			}
			// Tamper 1 bit in tag
			tamp := append([]byte(nil), ctBytes...)
			tamp[len(tamp)-1] ^= 0x01
			if _, err := DecryptPartStream(bytes.NewReader(tamp), &bytes.Buffer{}, encKey, noncePfx, msgID, partID); err == nil {
				t.Fatal("expected 1-bit tag tamper to fail")
			}
			// Splice under wrong part_id
			if _, err := DecryptPartStream(bytes.NewReader(ctBytes), &bytes.Buffer{}, encKey, noncePfx, msgID, 2); err == nil {
				t.Fatal("expected cross-part_id splice to fail")
			}
		}
		if tc.name == "multi_chunk_300000B" {
			// Reorder block 0 and block 1
			reordered := append([]byte(nil), ctBytes...)
			copy(reordered[0:ChunkCiphertextMax], ctBytes[ChunkCiphertextMax:2*ChunkCiphertextMax])
			copy(reordered[ChunkCiphertextMax:2*ChunkCiphertextMax], ctBytes[0:ChunkCiphertextMax])
			if _, err := DecryptPartStream(bytes.NewReader(reordered), &bytes.Buffer{}, encKey, noncePfx, msgID, partID); err == nil {
				t.Fatal("expected reordered blocks to fail")
			}
		}
	}

	vec := map[string]any{
		"vector":  "06_stream_aead_and_padding",
		"proto_v": 1,
		"manifest_padding": map[string]any{
			"bucket_bytes": ManifestPadBucket,
			"cases":        padCases,
			"negative_cases": []map[string]any{
				{"name": "len_zero_rejected", "padded_len": 4096, "first_4_hex": "00000000"},
				{"name": "non_zero_tail_rejected", "raw_len": 1, "last_byte_hex": "01"},
				{"name": "misaligned_len_rejected", "padded_len": 4095},
			},
		},
		"stream_aead": map[string]any{
			"msg_id_hex":                hex.EncodeToString(msgID[:]),
			"part_id":                   partID,
			"blob_key_hex":              hex.EncodeToString(blobKey),
			"expected_enc_key_hex":      hex.EncodeToString(encKey[:]),
			"expected_nonce_prefix_hex": hex.EncodeToString(noncePfx[:]),
			"cases":                     streamCases,
		},
	}
	writeOrVerifyVector(t, "06_stream_aead_and_padding.json", vec)
}

func TestVector07CrockfordRoomID(t *testing.T) {
	rawHexes := []string{
		"0000000000",
		"ffffffffff",
		"93a99b0bd7",
		"0123456789",
		"a55aa55aa5",
	}
	var encCases []map[string]any
	for _, rh := range rawHexes {
		b := mustHex(t, rh)
		var arr [5]byte
		copy(arr[:], b)
		canon := EncodeRoomID(arr)
		disp, err := FormatRoomID(canon)
		if err != nil {
			t.Fatal(err)
		}
		dec, err := DecodeRoomID(disp)
		if err != nil || dec != arr {
			t.Fatalf("roundtrip %s -> %s failed: %v", rh, canon, err)
		}
		encCases = append(encCases, map[string]any{
			"raw_hex":   rh,
			"canonical": canon,
			"display":   disp,
		})
	}

	normCases := []map[string]string{
		{"input": "k7m9-p2xq", "expected": "K7M9P2XQ"},
		{"input": " oilO-iIlL ", "expected": "01101111"},
		{"input": "0000-zzzz", "expected": "0000ZZZZ"},
	}
	for _, nc := range normCases {
		got, err := NormalizeRoomID(nc["input"])
		if err != nil || got != nc["expected"] {
			t.Fatalf("NormalizeRoomID(%q) = %q, %v; want %q", nc["input"], got, err, nc["expected"])
		}
	}

	invalidCases := []string{
		"",
		"1234567",
		"123456789",
		"K7M9P2XU",
		"K7M9P2X!",
		"K7M9P2X中",
	}
	for _, inv := range invalidCases {
		if _, err := NormalizeRoomID(inv); err == nil {
			t.Fatalf("expected NormalizeRoomID(%q) to fail", inv)
		}
	}

	vec := map[string]any{
		"vector":              "07_crockford_room_id",
		"alphabet":            CrockfordAlphabet,
		"encode_decode_cases": encCases,
		"normalize_cases":     normCases,
		"invalid_cases":       invalidCases,
	}
	writeOrVerifyVector(t, "07_crockford_room_id.json", vec)
}
