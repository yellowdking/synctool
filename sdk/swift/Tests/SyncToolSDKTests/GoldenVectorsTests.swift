import Foundation
import XCTest
@testable import SyncToolSDK

final class GoldenVectorsTests: XCTestCase {

    private func resolveVectorsDir() throws -> URL {
        var dir = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        for _ in 0..<8 {
            let cand = dir.appendingPathComponent("spec/test-vectors", isDirectory: true)
            if FileManager.default.fileExists(atPath: cand.appendingPathComponent("01_seed_and_keys.json").path) {
                return cand
            }
            dir = dir.deletingLastPathComponent()
        }
        throw NSError(domain: "GoldenVectorsTests", code: 1, userInfo: [NSLocalizedDescriptionKey: "spec/test-vectors not found"])
    }

    private func loadVector(_ name: String) throws -> [String: Any] {
        let url = try resolveVectorsDir().appendingPathComponent(name)
        let data = try Data(contentsOf: url)
        guard let dict = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw NSError(domain: "GoldenVectorsTests", code: 2, userInfo: [NSLocalizedDescriptionKey: "invalid JSON in \(name)"])
        }
        return dict
    }

    private func s(_ d: [String: Any], _ k: String) -> String { (d[k] as? String) ?? "" }
    private func i(_ d: [String: Any], _ k: String) -> Int { (d[k] as? NSNumber)?.intValue ?? 0 }
    private func i64(_ d: [String: Any], _ k: String) -> Int64 { (d[k] as? NSNumber)?.int64Value ?? 0 }
    private func b(_ d: [String: Any], _ k: String) -> Bool { (d[k] as? NSNumber)?.boolValue ?? false }
    private func o(_ d: [String: Any], _ k: String) -> [String: Any] { (d[k] as? [String: Any]) ?? [:] }
    private func a(_ d: [String: Any], _ k: String) -> [[String: Any]] { (d[k] as? [[String: Any]]) ?? [] }

    private func detPatternBytes(_ n: Int) -> Data {
        var out = [UInt8](repeating: 0, count: n)
        for idx in 0..<n { out[idx] = UInt8((idx * 31 + 7) & 0xff) }
        return Data(out)
    }

    func testVector01SeedAndKeys() throws {
        let vec = try loadVector("01_seed_and_keys.json")
        XCTAssertEqual("01_seed_and_keys", s(vec, "vector"))
        XCTAssertEqual(1, i(vec, "proto_v"))

        let seed = try SyncCrypto.hexDecode(s(vec, "device_master_seed_hex"))
        let issuedAt = i64(vec, "issued_at")
        let exp = o(vec, "expected")

        let dk = try DeviceKeys.fromMasterSeed(seed)
        let canon = try SyncCrypto.canonicalRelayOrigin("HTTPS://Relay.Example.COM/")
        XCTAssertEqual(s(vec, "canonical_relay_origin"), canon)

        let relayId = SyncCrypto.deriveRelayId(canon)
        let mk = try dk.deriveMailboxKeys(relayId: relayId)

        XCTAssertEqual(s(exp, "master_prk_hex"), SyncCrypto.hexEncode(dk.masterPrk))
        XCTAssertEqual(s(exp, "sign_seed_hex"), SyncCrypto.hexEncode(dk.sigSeed))
        XCTAssertEqual(s(exp, "sign_pk_hex"), SyncCrypto.hexEncode(dk.sigPk))
        XCTAssertEqual(s(exp, "sign_pk_b64u"), SyncCrypto.b64uEncode(dk.sigPk))
        XCTAssertEqual(s(exp, "kem_sk_hex"), SyncCrypto.hexEncode(dk.kemSk))
        XCTAssertEqual(s(exp, "kem_pk_hex"), SyncCrypto.hexEncode(dk.kemPk))
        XCTAssertEqual(s(exp, "kem_pk_b64u"), SyncCrypto.b64uEncode(dk.kemPk))
        XCTAssertEqual(s(exp, "local_meta_key_hex"), SyncCrypto.hexEncode(dk.localMetaKey))
        XCTAssertEqual(s(exp, "device_id"), dk.deviceId)
        XCTAssertEqual(s(exp, "relay_id"), relayId)
        XCTAssertEqual(s(exp, "mailbox_auth_seed_hex"), SyncCrypto.hexEncode(mk.authSeed))
        XCTAssertEqual(s(exp, "mailbox_auth_pk_hex"), SyncCrypto.hexEncode(mk.authPk))
        XCTAssertEqual(s(exp, "mailbox_auth_pk_b64u"), SyncCrypto.b64uEncode(mk.authPk))
        XCTAssertEqual(s(exp, "mailbox_id"), mk.mailboxId)

        let cardSigInput = try SyncCrypto.deviceCardSignInput(signPk: dk.sigPk, kemPk: dk.kemPk, issuedAt: issuedAt)
        XCTAssertEqual(s(exp, "card_sig_input_hex"), SyncCrypto.hexEncode(cardSigInput))
        let goldenCardSig = try SyncCrypto.hexDecode(s(exp, "card_sig_hex"))
        XCTAssertEqual(s(exp, "card_sig_b64u"), SyncCrypto.b64uEncode(goldenCardSig))
        try SyncCrypto.verifyDeviceCard(deviceId: dk.deviceId, signPk: dk.sigPk, kemPk: dk.kemPk, issuedAt: issuedAt, cardSig: goldenCardSig)

        let liveCardSig = try SyncCrypto.signDeviceCard(signSeed32: dk.sigSeed, kemPk32: dk.kemPk, issuedAt: issuedAt)
        try SyncCrypto.verifyDeviceCard(deviceId: dk.deviceId, signPk: dk.sigPk, kemPk: dk.kemPk, issuedAt: issuedAt, cardSig: liveCardSig)

        XCTAssertEqual(s(exp, "ed25519_pkcs8_der_hex"), SyncCrypto.hexEncode(try SyncCrypto.encodeEd25519Pkcs8(dk.sigSeed)))
        XCTAssertEqual(s(exp, "x25519_pkcs8_der_hex"), SyncCrypto.hexEncode(try SyncCrypto.encodeX25519Pkcs8(dk.kemSk)))
        XCTAssertEqual(s(exp, "ed25519_spki_der_hex"), SyncCrypto.hexEncode(try SyncCrypto.encodeEd25519Spki(dk.sigPk)))
        XCTAssertEqual(s(exp, "x25519_spki_der_hex"), SyncCrypto.hexEncode(try SyncCrypto.encodeX25519Spki(dk.kemPk)))

        let neg = o(vec, "negative_cases")
        XCTAssertThrowsError(try SyncCrypto.verifyDeviceCard(deviceId: s(neg, "wrong_device_id"), signPk: dk.sigPk, kemPk: dk.kemPk, issuedAt: issuedAt, cardSig: goldenCardSig))
        XCTAssertThrowsError(try SyncCrypto.verifyDeviceCard(deviceId: dk.deviceId, signPk: dk.sigPk, kemPk: dk.kemPk, issuedAt: issuedAt, cardSig: try SyncCrypto.hexDecode(s(neg, "tampered_sig_hex"))))
    }

    func testVector02RelayAuthSig() throws {
        let vec = try loadVector("02_relay_auth_sig.json")
        let accessKey = s(vec, "access_key")
        XCTAssertEqual(s(vec, "expected_relay_hmac_key_hex"), SyncCrypto.hexEncode(SyncCrypto.deriveRelayHmacKey(accessKey)))
        XCTAssertEqual(s(vec, "deposit_token_sample_hash"), SyncCrypto.hashDepositToken("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"))
        XCTAssertEqual(s(vec, "upload_token_sample_hash"), SyncCrypto.hashUploadToken("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"))

        let cases = a(vec, "cases")
        XCTAssertEqual(6, cases.count)
        for c in cases {
            let method = s(c, "method"), path = s(c, "path_and_raw_query"), ts = s(c, "ts"), nonce = s(c, "nonce")
            let bodyBind = b(c, "is_stream")
                ? SyncCrypto.bodyBindingStream(i64(c, "stream_content_length"))
                : SyncCrypto.bodyBindingControl(Data(s(c, "raw_body_utf8").utf8))
            let extraBind = SyncCrypto.extraTokenBinding(depositToken: s(c, "deposit_token"), uploadToken: s(c, "upload_token"))
            let canon = SyncCrypto.buildCanonicalRequest(method: method, pathAndRawQuery: path, ts: ts, nonce: nonce, bodyBinding: bodyBind, extraTokenBinding: extraBind)
            let sigHex = SyncCrypto.signRelayRequest(accessKey: accessKey, method: method, pathAndRawQuery: path, ts: ts, nonce: nonce, bodyBinding: bodyBind, extraTokenBinding: extraBind)

            XCTAssertEqual(s(c, "expected_body_binding"), bodyBind)
            XCTAssertEqual(s(c, "expected_extra_token_binding"), extraBind)
            XCTAssertEqual(s(c, "expected_canonical_req"), canon)
            XCTAssertEqual(s(c, "expected_sig_hex"), sigHex)
            XCTAssertTrue(SyncCrypto.verifyRelayRequest(accessKey: accessKey, method: method, pathAndRawQuery: path, ts: ts, nonce: nonce, bodyBinding: bodyBind, extraTokenBinding: extraBind, sigHex: sigHex))
            XCTAssertFalse(SyncCrypto.verifyRelayRequest(accessKey: accessKey, method: method, pathAndRawQuery: path, ts: ts, nonce: nonce, bodyBinding: bodyBind, extraTokenBinding: extraBind, sigHex: sigHex.uppercased()))
        }

        let mb = o(vec, "mailbox_sig_case")
        let mbSeed = try SyncCrypto.hexDecode(s(mb, "mailbox_auth_seed_hex"))
        let mbPk = try SyncCrypto.ed25519PublicKeyFromSeed(mbSeed)
        XCTAssertEqual(s(mb, "mailbox_auth_pk_b64u"), SyncCrypto.b64uEncode(mbPk))
        let mbId = s(mb, "mailbox_id")
        XCTAssertEqual(mbId, try SyncCrypto.deriveMailboxId(mbPk))

        let mbMethod = s(mb, "method"), mbPath = s(mb, "path_and_raw_query"), mbTs = s(mb, "ts"), mbNonce = s(mb, "nonce")
        let mbBodyBind = SyncCrypto.bodyBindingControl(Data(s(mb, "raw_body_utf8").utf8))
        let mbSigInput = SyncCrypto.buildMailboxSigInput(method: mbMethod, pathAndRawQuery: mbPath, mailboxId: mbId, ts: mbTs, nonce: mbNonce, bodyBinding: mbBodyBind)
        XCTAssertEqual(s(mb, "expected_body_binding"), mbBodyBind)
        XCTAssertEqual(s(mb, "expected_sig_input"), mbSigInput)
        XCTAssertTrue(SyncCrypto.verifyMailboxRequest(mailboxAuthPk32: mbPk, method: mbMethod, pathAndRawQuery: mbPath, mailboxId: mbId, ts: mbTs, nonce: mbNonce, bodyBinding: mbBodyBind, sigB64u: s(mb, "expected_mailbox_sig_b64u")))
        let liveMbSig = try SyncCrypto.signMailboxRequest(mailboxAuthSeed32: mbSeed, method: mbMethod, pathAndRawQuery: mbPath, mailboxId: mbId, ts: mbTs, nonce: mbNonce, bodyBinding: mbBodyBind)
        XCTAssertTrue(SyncCrypto.verifyMailboxRequest(mailboxAuthPk32: mbPk, method: mbMethod, pathAndRawQuery: mbPath, mailboxId: mbId, ts: mbTs, nonce: mbNonce, bodyBinding: mbBodyBind, sigB64u: liveMbSig))

        let skew = o(vec, "clock_skew_cases")
        let srvTs = i64(skew, "server_ts"), maxSkew = i64(skew, "max_skew_sec")
        for sc in a(skew, "cases") {
            XCTAssertEqual(b(sc, "expect_clock_skew_409"), abs(i64(sc, "ts") - srvTs) > maxSkew)
        }
    }

    func testVector03HandshakeQrOob() throws {
        let vec = try loadVector("03_handshake_qr_oob.json")
        let roomId = s(vec, "room_id"), purpose = s(vec, "purpose")
        let eASk = try SyncCrypto.hexDecode(s(vec, "e_a_sk_hex")), eBSk = try SyncCrypto.hexDecode(s(vec, "e_b_sk_hex"))
        let nA = try SyncCrypto.hexDecode(s(vec, "n_a_hex")), nB = try SyncCrypto.hexDecode(s(vec, "n_b_hex"))
        let oob = try SyncCrypto.hexDecode(s(vec, "oob_secret_hex"))

        let pubA = try SyncCrypto.x25519PublicKeyFromPrivate(eASk), pubB = try SyncCrypto.x25519PublicKeyFromPrivate(eBSk)
        XCTAssertEqual(s(vec, "e_a_pk_hex"), SyncCrypto.hexEncode(pubA))
        XCTAssertEqual(s(vec, "e_b_pk_hex"), SyncCrypto.hexEncode(pubB))

        let shared = try SyncCrypto.x25519DiffieHellman(sk32: eASk, peerPk32: pubB)
        let t1 = try SyncHandshake.buildQrTranscript(purpose: purpose, roomId: roomId, eAPub: pubA, nA: nA, eBPub: pubB, nB: nB)
        XCTAssertEqual(154, t1.count)

        let resA = try SyncHandshake.deriveQrOobSession(purpose: purpose, roomId: roomId, localPriv32: eASk, remotePub32: pubB, eAPub: pubA, nA: nA, eBPub: pubB, nB: nB, oobSecret: oob)
        let resB = try SyncHandshake.deriveQrOobSession(purpose: purpose, roomId: roomId, localPriv32: eBSk, remotePub32: pubA, eAPub: pubA, nA: nA, eBPub: pubB, nB: nB, oobSecret: oob)
        XCTAssertEqual(resA, resB)

        let exp = o(vec, "expected")
        XCTAssertEqual(s(exp, "shared_hex"), SyncCrypto.hexEncode(shared))
        XCTAssertEqual(s(exp, "transcript_1_hex"), SyncCrypto.hexEncode(t1))
        XCTAssertEqual(s(exp, "th_hex"), SyncCrypto.hexEncode(resA.th))
        XCTAssertEqual(s(exp, "prk_hex"), SyncCrypto.hexEncode(resA.prk))
        XCTAssertEqual(s(exp, "session_key_hex"), SyncCrypto.hexEncode(resA.sessionKey))
        XCTAssertEqual(s(exp, "confirm_key_a_hex"), SyncCrypto.hexEncode(resA.confirmKeyA))
        XCTAssertEqual(s(exp, "confirm_key_b_hex"), SyncCrypto.hexEncode(resA.confirmKeyB))
        XCTAssertEqual(s(exp, "mac_a_b64u"), SyncCrypto.b64uEncode(resA.macA))
        XCTAssertEqual(s(exp, "mac_b_b64u"), SyncCrypto.b64uEncode(resA.macB))

        let p0Obj = o(vec, "oneshot_part0")
        let (p0Key, p0Np) = try SyncHandshake.deriveOneshotPart0Keys(sessionKey32: resA.sessionKey, msgId16: try SyncCrypto.hexDecode(s(p0Obj, "msg_id_hex")))
        XCTAssertEqual(s(p0Obj, "expected_part0_key_hex"), SyncCrypto.hexEncode(p0Key))
        XCTAssertEqual(s(p0Obj, "expected_part0_nonce_prefix_hex"), SyncCrypto.hexEncode(p0Np))

        let ctrlObj = o(vec, "pipe_ctrl")
        let (ctrlKey, ctrlNp) = try SyncHandshake.derivePipeCtrlKeys(th32: resA.th, sessionKey32: resA.sessionKey)
        XCTAssertEqual(s(ctrlObj, "expected_ctrl_key_hex"), SyncCrypto.hexEncode(ctrlKey))
        XCTAssertEqual(s(ctrlObj, "expected_ctrl_np_hex"), SyncCrypto.hexEncode(ctrlNp))
        for f in a(ctrlObj, "frames") {
            let seq = i64(f, "ctrl_seq"), ptUtf8 = s(f, "plaintext_utf8")
            let aad = try SyncHandshake.buildPipeCtrlAad(th32: resA.th, ctrlSeq: UInt32(seq))
            XCTAssertEqual(57, aad.count)
            XCTAssertEqual(s(f, "expected_aad_hex"), SyncCrypto.hexEncode(aad))
            let ct = try SyncHandshake.sealPipeCtrl(ctrlKey32: ctrlKey, ctrlNp7: ctrlNp, th32: resA.th, ctrlSeq: UInt32(seq), plaintext: Data(ptUtf8.utf8))
            XCTAssertEqual(s(f, "expected_ct_b64u"), SyncCrypto.b64uEncode(ct))
            let opened = try SyncHandshake.openPipeCtrlVerified(ctrlKey32: ctrlKey, ctrlNp7: ctrlNp, th32: resB.th, ctrlSeq: seq, fromInitiator: (seq % 2 == 0), lastSeenSeq: -1, ciphertext: ct)
            XCTAssertEqual(ptUtf8, String(decoding: opened, as: UTF8.self))
        }

        let pbObj = o(vec, "pair_bind")
        let resPair = try SyncHandshake.deriveQrOobSession(purpose: s(pbObj, "purpose"), roomId: roomId, localPriv32: eASk, remotePub32: pubB, eAPub: pubA, nA: nA, eBPub: pubB, nB: nB, oobSecret: oob)
        let (na, nb) = try SyncHandshake.derivePairBindNonces(prk32: resPair.prk)
        XCTAssertEqual(s(pbObj, "expected_th_hex"), SyncCrypto.hexEncode(resPair.th))
        XCTAssertEqual(s(pbObj, "expected_prk_hex"), SyncCrypto.hexEncode(resPair.prk))
        XCTAssertEqual(s(pbObj, "expected_session_key_hex"), SyncCrypto.hexEncode(resPair.sessionKey))
        XCTAssertEqual(s(pbObj, "expected_pair_nonce_a_hex"), SyncCrypto.hexEncode(na))
        XCTAssertEqual(s(pbObj, "expected_pair_nonce_b_hex"), SyncCrypto.hexEncode(nb))

        let ptA = s(pbObj, "plaintext_a_utf8"), ptB = s(pbObj, "plaintext_b_utf8")
        let ctA = try SyncHandshake.sealPairBind(sessionKey32: resPair.sessionKey, prk32: resPair.prk, th32: resPair.th, isInitiator: true, plaintext: Data(ptA.utf8))
        let ctB = try SyncHandshake.sealPairBind(sessionKey32: resPair.sessionKey, prk32: resPair.prk, th32: resPair.th, isInitiator: false, plaintext: Data(ptB.utf8))
        XCTAssertEqual(s(pbObj, "expected_ct_a_b64u"), SyncCrypto.b64uEncode(ctA))
        XCTAssertEqual(s(pbObj, "expected_ct_b_b64u"), SyncCrypto.b64uEncode(ctB))
        XCTAssertEqual(ptA, String(decoding: try SyncHandshake.openPairBind(sessionKey32: resPair.sessionKey, prk32: resPair.prk, th32: resPair.th, fromInitiator: true, ciphertext: ctA), as: UTF8.self))
        XCTAssertEqual(ptB, String(decoding: try SyncHandshake.openPairBind(sessionKey32: resPair.sessionKey, prk32: resPair.prk, th32: resPair.th, fromInitiator: false, ciphertext: ctB), as: UTF8.self))

        let neg = o(vec, "negative_cases")
        let resWrong = try SyncHandshake.deriveQrOobSession(purpose: purpose, roomId: roomId, localPriv32: eBSk, remotePub32: pubA, eAPub: pubA, nA: nA, eBPub: pubB, nB: nB, oobSecret: try SyncCrypto.hexDecode(s(neg, "wrong_oob_secret_hex")))
        XCTAssertThrowsError(try SyncHandshake.verifyMac(expected32: resA.macB, got: resWrong.macB))
        XCTAssertThrowsError(try SyncCrypto.x25519DiffieHellman(sk32: eASk, peerPk32: try SyncCrypto.hexDecode(s(neg, "low_order_all_zero_pk_hex"))))
    }

    func testVector04HandshakeCommitSas() throws {
        let vec = try loadVector("04_handshake_commit_sas.json")
        let roomId = s(vec, "room_id"), purpose = s(vec, "purpose")
        let eASk = try SyncCrypto.hexDecode(s(vec, "e_a_sk_hex")), eBSk = try SyncCrypto.hexDecode(s(vec, "e_b_sk_hex"))
        let nA = try SyncCrypto.hexDecode(s(vec, "n_a_hex")), nB = try SyncCrypto.hexDecode(s(vec, "n_b_hex"))
        let pubA = try SyncCrypto.x25519PublicKeyFromPrivate(eASk), pubB = try SyncCrypto.x25519PublicKeyFromPrivate(eBSk)
        XCTAssertEqual(s(vec, "e_a_pk_hex"), SyncCrypto.hexEncode(pubA))
        XCTAssertEqual(s(vec, "e_b_pk_hex"), SyncCrypto.hexEncode(pubB))

        let commitA = try SyncHandshake.computeCommitA(purpose: purpose, roomId: roomId, eAPub: pubA, nA: nA)
        let t2 = try SyncHandshake.buildSasTranscript(purpose: purpose, roomId: roomId, commitA: commitA, eAPub: pubA, nA: nA, eBPub: pubB, nB: nB)
        XCTAssertEqual(187, t2.count)

        let resA = try SyncHandshake.deriveSasSession(purpose: purpose, roomId: roomId, localPriv32: eASk, remotePub32: pubB, commitA: commitA, eAPub: pubA, nA: nA, eBPub: pubB, nB: nB)
        let resB = try SyncHandshake.deriveSasSession(purpose: purpose, roomId: roomId, localPriv32: eBSk, remotePub32: pubA, commitA: commitA, eAPub: pubA, nA: nA, eBPub: pubB, nB: nB)
        XCTAssertEqual(resA, resB)
        XCTAssertEqual("001807", resA.sasStr)

        let exp = o(vec, "expected")
        XCTAssertEqual(s(exp, "commit_a_hex"), SyncCrypto.hexEncode(commitA))
        XCTAssertEqual(s(exp, "commit_a_b64u"), SyncCrypto.b64uEncode(commitA))
        XCTAssertEqual(s(exp, "transcript_2_hex"), SyncCrypto.hexEncode(t2))
        XCTAssertEqual(s(exp, "th_hex"), SyncCrypto.hexEncode(resA.th))
        XCTAssertEqual(s(exp, "prk_hex"), SyncCrypto.hexEncode(resA.prk))
        XCTAssertEqual(s(exp, "session_key_hex"), SyncCrypto.hexEncode(resA.sessionKey))
        XCTAssertEqual(s(exp, "sas_bytes_hex"), SyncCrypto.hexEncode(resA.sasBytes))
        XCTAssertEqual(i(exp, "sas_int"), resA.sasInt)
        XCTAssertEqual(s(exp, "sas_str"), resA.sasStr)
        XCTAssertEqual(s(exp, "confirm_key_a_hex"), SyncCrypto.hexEncode(resA.confirmKeyA))
        XCTAssertEqual(s(exp, "confirm_key_b_hex"), SyncCrypto.hexEncode(resA.confirmKeyB))
        XCTAssertEqual(s(exp, "mac_a_b64u"), SyncCrypto.b64uEncode(resA.macA))
        XCTAssertEqual(s(exp, "mac_b_b64u"), SyncCrypto.b64uEncode(resA.macB))

        let (ctrlKey, ctrlNp) = try SyncHandshake.derivePipeCtrlKeys(th32: resA.th, sessionKey32: resA.sessionKey)
        XCTAssertEqual(s(exp, "pipe_ctrl_key_hex"), SyncCrypto.hexEncode(ctrlKey))
        XCTAssertEqual(s(exp, "pipe_ctrl_np_hex"), SyncCrypto.hexEncode(ctrlNp))
        let ctrlCt = try SyncHandshake.sealPipeCtrl(ctrlKey32: ctrlKey, ctrlNp7: ctrlNp, th32: resA.th, ctrlSeq: 0, plaintext: Data(s(exp, "pipe_ctrl_seq0_pt_utf8").utf8))
        XCTAssertEqual(s(exp, "pipe_ctrl_seq0_ct_b64u"), SyncCrypto.b64uEncode(ctrlCt))

        let tamperedEa = try SyncCrypto.hexDecode(s(o(vec, "negative_cases"), "tampered_e_a_pk_hex"))
        XCTAssertThrowsError(try SyncHandshake.verifyCommitA(purpose: purpose, roomId: roomId, eAPub: tamperedEa, nA: nA, commitA: commitA))
    }

    func testVector05Paired0RttEnvelope() throws {
        let vec = try loadVector("05_paired_0rtt_envelope.json")
        let senderDk = try DeviceKeys.fromMasterSeed(SyncCrypto.hexDecode(s(vec, "sender_master_seed_hex")))
        let recipDk = try DeviceKeys.fromMasterSeed(SyncCrypto.hexDecode(s(vec, "recipient_master_seed_hex")))
        let ephSk = try SyncCrypto.hexDecode(s(vec, "ephemeral_sk_hex"))
        let msgId = try SyncCrypto.hexDecode(s(vec, "msg_id_hex"))
        let createdAt = i64(vec, "created_at")
        let manifestSha = SyncCrypto.sha256(Data(s(vec, "manifest_utf8").utf8))
        XCTAssertEqual(s(vec, "manifest_sha256_hex"), SyncCrypto.hexEncode(manifestSha))

        let exp = o(vec, "expected")
        let fixedSenderSig = try SyncCrypto.b64uDecode(s(exp, "sender_sig_b64u"))
        let sealed = try SyncSealedHeader.seal0RttHeaderDeterministic(
            senderKeys: senderDk, ephemeralSk32: ephSk, msgIdRaw16: msgId, recipientIdRaw16: recipDk.deviceIdRaw,
            recipientKemPub32: recipDk.kemPk, createdAt: createdAt, manifestSha256: manifestSha, testFixedSenderSig: fixedSenderSig
        )
        XCTAssertEqual(208, sealed.sealedHeader.count)
        let sealedB64 = SyncCrypto.b64uEncode(sealed.sealedHeader)
        XCTAssertEqual(278, sealedB64.count)
        XCTAssertEqual(s(exp, "sender_device_id"), senderDk.deviceId)
        XCTAssertEqual(s(exp, "sender_sign_pk_b64u"), SyncCrypto.b64uEncode(senderDk.sigPk))
        XCTAssertEqual(s(exp, "recipient_device_id"), recipDk.deviceId)
        XCTAssertEqual(s(exp, "recipient_kem_pk_b64u"), SyncCrypto.b64uEncode(recipDk.kemPk))

        let clearHdr = Data(sealed.sealedHeader.prefix(SyncSealedHeader.clearHeaderSize))
        let sigInput = try SyncSealedHeader.buildZeroRttSigInput(clearHeader56: clearHdr, senderIdRaw16: senderDk.deviceIdRaw, recipientIdRaw16: recipDk.deviceIdRaw, createdAt: createdAt, manifestSha256: manifestSha)
        XCTAssertEqual(149, sigInput.count)
        XCTAssertEqual(s(exp, "clear_header_hex"), SyncCrypto.hexEncode(clearHdr))
        XCTAssertEqual(s(exp, "sig_input_hex"), SyncCrypto.hexEncode(sigInput))
        XCTAssertEqual(s(exp, "sealed_header_hex"), SyncCrypto.hexEncode(sealed.sealedHeader))
        XCTAssertEqual(s(exp, "sealed_header_b64u"), sealedB64)
        XCTAssertEqual(s(exp, "part0_key_hex"), SyncCrypto.hexEncode(sealed.part0Key))
        XCTAssertEqual(s(exp, "part0_nonce_prefix_hex"), SyncCrypto.hexEncode(sealed.part0NoncePrefix))

        let opened = try SyncSealedHeader.open0RttHeader(recipientKeys: recipDk, sealedHeader: sealed.sealedHeader) { $0 == senderDk.deviceId ? senderDk.sigPk : nil }
        XCTAssertEqual(s(exp, "sender_sig_b64u"), SyncCrypto.b64uEncode(opened.senderSig))
        XCTAssertEqual(sealed.part0Key, opened.part0Key)

        // Live CryptoKit randomized-nonce sign -> open roundtrip
        let liveSealed = try SyncSealedHeader.seal0RttHeaderDeterministic(
            senderKeys: senderDk, ephemeralSk32: ephSk, msgIdRaw16: msgId, recipientIdRaw16: recipDk.deviceIdRaw,
            recipientKemPub32: recipDk.kemPk, createdAt: createdAt, manifestSha256: manifestSha
        )
        let liveOpened = try SyncSealedHeader.open0RttHeader(recipientKeys: recipDk, sealedHeader: liveSealed.sealedHeader) { $0 == senderDk.deviceId ? senderDk.sigPk : nil }
        XCTAssertEqual(sealed.part0Key, liveOpened.part0Key)

        let directAck = try SyncSealedHeader.computeDirectAckMac(part0Key32: sealed.part0Key, msgIdRaw16: msgId)
        XCTAssertEqual(s(exp, "direct_ack_mac_b64u"), SyncCrypto.b64uEncode(directAck))
        try SyncSealedHeader.verifyDirectAckMac(part0Key32: sealed.part0Key, msgIdRaw16: msgId, gotMac: directAck)

        let neg = o(vec, "negative_cases")
        XCTAssertThrowsError(try SyncSealedHeader.open0RttHeader(recipientKeys: recipDk, sealedHeader: SyncCrypto.b64uDecode(s(neg, "tampered_clear_header_b64u"))) { _ in senderDk.sigPk })
        let wrongRecip = try DeviceKeys.fromMasterSeed(SyncCrypto.hexDecode(s(neg, "wrong_recipient_master_seed_hex")))
        XCTAssertThrowsError(try SyncSealedHeader.open0RttHeader(recipientKeys: wrongRecip, sealedHeader: sealed.sealedHeader) { _ in senderDk.sigPk })
        XCTAssertThrowsError(try SyncSealedHeader.verifyDirectAckMac(part0Key32: sealed.part0Key, msgIdRaw16: msgId, gotMac: SyncCrypto.b64uDecode(s(neg, "tampered_direct_ack_mac_b64u"))))
    }

    func testVector06StreamAeadAndPadding() throws {
        let vec = try loadVector("06_stream_aead_and_padding.json")
        for c in a(o(vec, "manifest_padding"), "cases") {
            let raw = detPatternBytes(i(c, "raw_len"))
            let padded = try StreamCipher.padManifest4K(raw)
            XCTAssertEqual(i(c, "expected_padded_len"), padded.count)
            XCTAssertEqual(s(c, "expected_padded_sha256"), SyncCrypto.hexEncode(SyncCrypto.sha256(padded)))
            XCTAssertEqual(s(c, "expected_prefix_16_hex"), SyncCrypto.hexEncode(Data(padded.prefix(16))))
            XCTAssertEqual(raw, try StreamCipher.unpadManifest4K(padded))
        }
        XCTAssertThrowsError(try StreamCipher.unpadManifest4K(Data(count: 4096)))
        var dirtyTail = try StreamCipher.padManifest4K(detPatternBytes(1))
        dirtyTail[dirtyTail.count - 1] = 0x01
        XCTAssertThrowsError(try StreamCipher.unpadManifest4K(dirtyTail))
        XCTAssertThrowsError(try StreamCipher.unpadManifest4K(Data(count: 4095)))
        var overPadded = try StreamCipher.padManifest4K(detPatternBytes(10))
        overPadded.append(Data(count: 4096))
        XCTAssertThrowsError(try StreamCipher.unpadManifest4K(overPadded))

        let stObj = o(vec, "stream_aead")
        let msgId = try SyncCrypto.hexDecode(s(stObj, "msg_id_hex")), partId = i(stObj, "part_id")
        let (encKey, noncePfx) = try StreamCipher.deriveBlobPartKeys(msgIdRaw16: msgId, partId: partId, blobKey32: try SyncCrypto.hexDecode(s(stObj, "blob_key_hex")))
        XCTAssertEqual(s(stObj, "expected_enc_key_hex"), SyncCrypto.hexEncode(encKey))
        XCTAssertEqual(s(stObj, "expected_nonce_prefix_hex"), SyncCrypto.hexEncode(noncePfx))

        for c in a(stObj, "cases") {
            let name = s(c, "name"), ptLen = i(c, "plaintext_len"), pt = detPatternBytes(ptLen)
            XCTAssertEqual(s(c, "plaintext_sha256"), SyncCrypto.hexEncode(SyncCrypto.sha256(pt)))
            let totalBlocks = StreamCipher.totalBlocks(plaintextLen: Int64(ptLen))
            XCTAssertEqual(i64(c, "expected_total_blocks"), Int64(totalBlocks))

            let firstPtLen = totalBlocks == 1 ? ptLen : StreamCipher.chunkPlaintextMax
            XCTAssertEqual(s(c, "first_block_nonce_hex"), SyncCrypto.hexEncode(try StreamCipher.buildChunkNonce(noncePrefix7: noncePfx, blockIdx: 0, isFinal: totalBlocks == 1)))
            XCTAssertEqual(s(c, "first_block_aad_hex"), SyncCrypto.hexEncode(try StreamCipher.buildChunkAad(msgIdRaw16: msgId, partId: partId, blockIdx: 0, isFinal: totalBlocks == 1, plaintextLen: firstPtLen)))

            let lastBlk = totalBlocks - 1
            let lastPtLen = ptLen == 0 ? 0 : (((ptLen - 1) % StreamCipher.chunkPlaintextMax) + 1)
            XCTAssertEqual(s(c, "last_block_nonce_hex"), SyncCrypto.hexEncode(try StreamCipher.buildChunkNonce(noncePrefix7: noncePfx, blockIdx: lastBlk, isFinal: true)))
            XCTAssertEqual(s(c, "last_block_aad_hex"), SyncCrypto.hexEncode(try StreamCipher.buildChunkAad(msgIdRaw16: msgId, partId: partId, blockIdx: lastBlk, isFinal: true, plaintextLen: lastPtLen)))

            let ctBytes = try StreamCipher.encryptPartData(pt, encKey32: encKey, noncePrefix7: noncePfx, msgIdRaw16: msgId, partId: partId)
            XCTAssertEqual(i64(c, "expected_ciphertext_len"), Int64(ctBytes.count))
            XCTAssertEqual(s(c, "expected_ciphertext_sha256"), SyncCrypto.hexEncode(SyncCrypto.sha256(ctBytes)))
            XCTAssertEqual(i(c, "expected_nano_chunk_count"), StreamCipher.transportChunkCount(encryptedSize: Int64(ctBytes.count), blocksPerChunk: 4))
            XCTAssertEqual(i(c, "expected_std_chunk_count"), StreamCipher.transportChunkCount(encryptedSize: Int64(ctBytes.count), blocksPerChunk: 16))
            if !s(c, "ciphertext_hex").isEmpty { XCTAssertEqual(s(c, "ciphertext_hex"), SyncCrypto.hexEncode(ctBytes)) }
            if !s(c, "ciphertext_first_32_hex").isEmpty { XCTAssertEqual(s(c, "ciphertext_first_32_hex"), SyncCrypto.hexEncode(Data(ctBytes.prefix(32)))) }
            if !s(c, "ciphertext_last_32_hex").isEmpty { XCTAssertEqual(s(c, "ciphertext_last_32_hex"), SyncCrypto.hexEncode(Data(ctBytes.suffix(32)))) }
            XCTAssertEqual(pt, try StreamCipher.decryptPartData(ctBytes, encKey32: encKey, noncePrefix7: noncePfx, msgIdRaw16: msgId, partId: partId))

            if name == "two_blocks_65537B" {
                XCTAssertThrowsError(try StreamCipher.decryptPartData(Data(ctBytes.prefix(StreamCipher.chunkCiphertextMax)), encKey32: encKey, noncePrefix7: noncePfx, msgIdRaw16: msgId, partId: partId))
                var tampered = [UInt8](ctBytes); tampered[tampered.count - 1] ^= 0x01
                XCTAssertThrowsError(try StreamCipher.decryptPartData(Data(tampered), encKey32: encKey, noncePrefix7: noncePfx, msgIdRaw16: msgId, partId: partId))
                XCTAssertThrowsError(try StreamCipher.decryptPartData(ctBytes, encKey32: encKey, noncePrefix7: noncePfx, msgIdRaw16: msgId, partId: 2))
            }
            if name == "multi_chunk_300000B" {
                var reordered = Data()
                let blkSz = StreamCipher.chunkCiphertextMax
                reordered.append(ctBytes[blkSz..<(2 * blkSz)])
                reordered.append(ctBytes[0..<blkSz])
                reordered.append(ctBytes[(2 * blkSz)...])
                XCTAssertThrowsError(try StreamCipher.decryptPartData(reordered, encKey32: encKey, noncePrefix7: noncePfx, msgIdRaw16: msgId, partId: partId))
            }
        }
    }

    func testVector07CrockfordRoomIdAndLuhnMod32() throws {
        let vec = try loadVector("07_crockford_room_id.json")
        XCTAssertEqual(Crockford.alphabet, s(vec, "alphabet"))
        for c in a(vec, "encode_decode_cases") {
            let raw = try SyncCrypto.hexDecode(s(c, "raw_hex"))
            let canon = try Crockford.encodeRoomId(raw), disp = try Crockford.formatRoomId(canon)
            XCTAssertEqual(s(c, "canonical"), canon)
            XCTAssertEqual(s(c, "display"), disp)
            XCTAssertEqual(raw, try Crockford.decodeRoomId(disp))
            let withCheck = try Crockford.appendLuhnMod32(canon)
            XCTAssertEqual(9, withCheck.count)
            XCTAssertTrue(Crockford.verifyLuhnMod32(withCheck))
            let flipped = (withCheck.first == "0" ? "1" : "0") + String(withCheck.dropFirst())
            XCTAssertFalse(Crockford.verifyLuhnMod32(flipped))
        }
        for n in a(vec, "normalize_cases") {
            XCTAssertEqual(s(n, "expected"), try Crockford.normalizeRoomId(s(n, "input")))
        }
        for inv in (vec["invalid_cases"] as? [String] ?? []) + ["K7M9P2\u{fb01}", "K7M9P2X\u{017f}", "K7M9P2X\u{212a}"] {
            XCTAssertThrowsError(try Crockford.normalizeRoomId(inv))
        }
    }

    func testCryptoEnvelopeAndX509DerHardening() async throws {
        // 1. All 9 RFC 7748 X25519 low-order points rejected with ERR_CRYPTO_HANDSHAKE_FAILED
        let (sk, _) = try SyncCrypto.x25519Generate()
        for h in [
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0100000000000000000000000000000000000000000000000000000000000000",
            "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
            "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "0000000000000000000000000000000000000000000000000000000000000080",
            "0100000000000000000000000000000000000000000000000000000000000080",
        ] {
            XCTAssertThrowsError(try SyncCrypto.x25519DiffieHellman(sk32: sk, peerPk32: SyncCrypto.hexDecode(h))) { err in
                XCTAssertEqual(ErrorCode.errCryptoHandshakeFailed, (err as? SyncError)?.code)
            }
        }

        // 2. Ed25519 S + L malleability & small-order / non-canonical y >= p rejection
        let dk = try DeviceKeys.fromMasterSeed(Data(repeating: 0x11, count: 32))
        var malleable = [UInt8](try SyncCrypto.signDeviceCard(signSeed32: dk.sigSeed, kemPk32: dk.kemPk, issuedAt: 1_700_000_000))
        let orderLLE: [UInt8] = [0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14] + [UInt8](repeating: 0, count: 15) + [0x10]
        var carry: UInt16 = 0
        for idx in 0..<32 {
            let sum = UInt16(malleable[32 + idx]) + UInt16(orderLLE[idx]) + carry
            malleable[32 + idx] = UInt8(sum & 0xff); carry = sum >> 8
        }
        XCTAssertThrowsError(try SyncCrypto.verifyDeviceCard(deviceId: dk.deviceId, signPk: dk.sigPk, kemPk: dk.kemPk, issuedAt: 1_700_000_000, cardSig: Data(malleable)))
        XCTAssertFalse(SyncCrypto.ed25519VerifyStrict(publicKey: try SyncCrypto.hexDecode("0100000000000000000000000000000000000000000000000000000000000000"), message: Data(count: 8), signature: Data(count: 64)))
        XCTAssertFalse(SyncCrypto.ed25519VerifyStrict(publicKey: try SyncCrypto.hexDecode("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"), message: Data(count: 8), signature: Data(count: 64)))

        // 3. RFC 5952 IPv6 canonicalRelayOrigin, Multi-Pin SyncUri, Redact & sanitizeFilename
        XCTAssertEqual("http://[::1]:8080", try SyncCrypto.canonicalRelayOrigin("http://[0:0:0:0:0:0:0:1]:8080/"))
        XCTAssertEqual("http://[::ffff:127.0.0.1]:8080", try SyncCrypto.canonicalRelayOrigin("http://[::ffff:127.0.0.1]:8080"))
        XCTAssertEqual("https://[2001:db8::1]:8443", try SyncCrypto.canonicalRelayOrigin("https://[2001:0db8:0:0:0:0:0:1]:8443"))
        XCTAssertThrowsError(try SyncCrypto.canonicalRelayOrigin("https://admin:SUPER_SECRET@relay.example.com:443#k=TOP_SECRET")) { err in
            XCTAssertFalse("\(err)".contains("SECRET"))
        }

        let pin1 = String(repeating: "a", count: 64), pin2 = String(repeating: "b", count: 64)
        let relayUri = "synctool://relay?v=1&u=https%3A%2F%2F43.155.231.14%3A54843&pin=\(pin1.uppercased()),\(pin2)#k=\(String(repeating: "K", count: 43))"
        let parsedRelay = try SyncUri.parseRelayUri(relayUri)
        XCTAssertEqual([pin1, pin2], parsedRelay.spkiPins)
        XCTAssertFalse("\(parsedRelay)".contains("KKKKKKKK"))
        XCTAssertFalse(Redact.message("failed on \(relayUri)").contains("KKKKKKKK"))
        XCTAssertEqual("_CON.txt", ManifestCodec.sanitizeFilename("../../\u{202E}CON.txt"))

        // 4. ST-P0-2 sawFinal post-final block injection guard & RollingBlockDecryptor
        let sc = try StreamCipher(encKey32: Data(repeating: 1, count: 32), noncePrefix7: Data(repeating: 2, count: 7), msgIdRaw16: Data(repeating: 3, count: 16), partId: 1)
        let malicious = try sc.sealBlockAt(blockIdx: 0, isFinal: true, plaintext: Data([0x42])) + sc.sealBlockAt(blockIdx: 1, isFinal: false, plaintext: Data(count: StreamCipher.chunkPlaintextMax))
        XCTAssertThrowsError(try StreamCipher.decryptChunkBuffer(cipher: sc, chunkBytes: malicious, startBlockIdx: 0, totalBlocks: 1, isLastTransportChunk: true, alreadySawFinal: false) { _ in })

        // 5. X509SpkiExtractor DER SPKI & Validity slicing (v3 certificate with Ed25519 SPKI & UTCTime/GeneralizedTime)
        let expectedSpki = try SyncCrypto.encodeEd25519Spki(dk.sigPk)
        func der(_ tag: UInt8, _ body: Data) -> Data {
            var out = Data([tag])
            if body.count < 128 { out.append(UInt8(body.count)) }
            else { out.append(contentsOf: [0x81, UInt8(body.count)]) }
            out.append(body); return out
        }
        let tbsBody = der(0xA0, der(0x02, Data([0x02]))) + der(0x02, Data([0x01])) + der(0x30, Data([0x06, 0x03, 0x2b, 0x65, 0x70]))
            + der(0x30, Data()) + der(0x30, der(0x17, Data("251127122000Z".utf8)) + der(0x18, Data("20271127122000Z".utf8)))
            + der(0x30, Data()) + expectedSpki
        let fakeCertDER = der(0x30, der(0x30, tbsBody) + der(0x30, Data([0x06, 0x03, 0x2b, 0x65, 0x70])) + der(0x03, Data([0x00])))
        let sliced = try X509SpkiExtractor.extractSpkiAndValidity(certDER: fakeCertDER)
        XCTAssertEqual(expectedSpki, sliced.spkiDER)
        XCTAssertEqual(1_764_246_000, sliced.notBeforeUnix)
        XCTAssertEqual(1_827_318_000, sliced.notAfterUnix)

        // 6. MemoryKeyStore & FileKeyStore LocalMetaKey cache encryption roundtrip
        let tmpDir = FileManager.default.temporaryDirectory.appendingPathComponent("synctool-ks-test-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: tmpDir) }
        let fks = try FileKeyStore(directoryURL: tmpDir)
        let manifest = Manifest(msgId: "9f86d081884c7d659a2feaa0c55ad015", appId: "com.yellowdking.gravityssh", schema: "gravityssh.vault.v1", createdAt: 1_764_246_000, sender: SenderInfo(deviceId: dk.deviceId, label: "Mac"))
        try await fks.putCachedManifest(CachedManifestEntry(itemId: "itm_test", cachedAt: 1_764_246_000, expiresAt: 1_764_332_400, manifestSha256: String(repeating: "33", count: 32), manifest: manifest))
        let loaded = try await fks.getCachedManifest("itm_test")
        XCTAssertEqual(manifest.msgId, loaded?.manifest.msgId)

        // 7. v0.4.0 client header, bounded server_ts float-overflow guard, and forward-compat wire probes
        XCTAssertEqual("synctool-swift/0.4.0", SyncTransport.clientAgentHeader)
        XCTAssertNil(SyncTransport.extractBoundedServerTs(["server_ts": "1e30"]))
        XCTAssertEqual(1_764_246_000, SyncTransport.extractBoundedServerTs(["server_ts": "1764246000"]))
        XCTAssertEqual(2, try JSONDecoder().decode(RoomM1Probe.self, from: Data(#"{"proto_v":2}"#.utf8)).protoV)
        XCTAssertTrue(try JSONDecoder().decode(MailboxItemsResp.self, from: Data(#"{"items":null}"#.utf8)).items.isEmpty)
    }
}
