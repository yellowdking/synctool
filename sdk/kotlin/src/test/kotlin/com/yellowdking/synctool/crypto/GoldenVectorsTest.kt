package com.yellowdking.synctool.crypto

import com.yellowdking.synctool.client.decryptChunkBufferInto
import com.yellowdking.synctool.envelope.CachedManifestEntry
import com.yellowdking.synctool.envelope.ErrorCode
import com.yellowdking.synctool.envelope.Manifest
import com.yellowdking.synctool.envelope.ManifestCodec
import com.yellowdking.synctool.envelope.MemoryKeyStore
import com.yellowdking.synctool.envelope.PairOffer
import com.yellowdking.synctool.envelope.Redact
import com.yellowdking.synctool.envelope.SenderInfo
import com.yellowdking.synctool.envelope.SyncError
import com.yellowdking.synctool.envelope.SyncUri
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import kotlinx.serialization.json.longOrNull
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class GoldenVectorsTest {

    private fun resolveVectorsDir(): File {
        val candidates = listOf(
            File("../../spec/test-vectors"),
            File("../spec/test-vectors"),
            File("spec/test-vectors"),
        )
        for (cand in candidates) {
            if (cand.isDirectory && File(cand, "01_seed_and_keys.json").isFile) {
                return cand
            }
        }
        var cur: File? = File(System.getProperty("user.dir", ".")).canonicalFile
        while (cur != null) {
            val check = File(cur, "spec/test-vectors")
            if (check.isDirectory && File(check, "01_seed_and_keys.json").isFile) {
                return check
            }
            cur = cur.parentFile
        }
        throw IllegalStateException("Could not locate spec/test-vectors directory from ${System.getProperty("user.dir")}")
    }

    private fun loadVectorJson(filename: String): JsonObject {
        val file = File(resolveVectorsDir(), filename)
        assertTrue("Expected golden vector file ${file.absolutePath}", file.isFile)
        return ManifestCodec.json.parseToJsonElement(file.readText(StandardCharsets.UTF_8)).jsonObject
    }

    private fun detPatternBytes(n: Int): ByteArray {
        val out = ByteArray(n)
        for (i in 0 until n) {
            out[i] = ((i * 31 + 7) and 0xff).toByte()
        }
        return out
    }

    @Test
    fun testVector01SeedAndKeys(): Unit {
        val vec = loadVectorJson("01_seed_and_keys.json")
        assertEquals("01_seed_and_keys", vec["vector"]!!.jsonPrimitive.content)
        assertEquals(1, vec["proto_v"]!!.jsonPrimitive.int)

        val seed = KeysAndAuth.fromHex(vec["device_master_seed_hex"]!!.jsonPrimitive.content)
        val origin = vec["canonical_relay_origin"]!!.jsonPrimitive.content
        val issuedAt = vec["issued_at"]!!.jsonPrimitive.long
        val exp = vec["expected"]!!.jsonObject

        val dk = KeysAndAuth.deriveDeviceKeys(seed)
        val canon = KeysAndAuth.canonicalRelayOrigin("HTTPS://Relay.Example.COM/")
        assertEquals(origin, canon)

        val relayId = KeysAndAuth.deriveRelayId(canon)
        val mk = dk.deriveMailboxKeys(relayId)

        assertEquals(exp["master_prk_hex"]!!.jsonPrimitive.content, KeysAndAuth.toLowerHex(dk.masterPrk))
        assertEquals(exp["sign_seed_hex"]!!.jsonPrimitive.content, KeysAndAuth.toLowerHex(dk.signSeed))
        assertEquals(exp["sign_pk_hex"]!!.jsonPrimitive.content, KeysAndAuth.toLowerHex(dk.signPub))
        assertEquals(exp["sign_pk_b64u"]!!.jsonPrimitive.content, KeysAndAuth.b64uEncode(dk.signPub))
        assertEquals(exp["kem_sk_hex"]!!.jsonPrimitive.content, KeysAndAuth.toLowerHex(dk.kemPrivBytes))
        assertEquals(exp["kem_pk_hex"]!!.jsonPrimitive.content, KeysAndAuth.toLowerHex(dk.kemPubBytes))
        assertEquals(exp["kem_pk_b64u"]!!.jsonPrimitive.content, KeysAndAuth.b64uEncode(dk.kemPubBytes))
        assertEquals(exp["local_meta_key_hex"]!!.jsonPrimitive.content, KeysAndAuth.toLowerHex(dk.localMetaKey))
        assertEquals(exp["device_id"]!!.jsonPrimitive.content, dk.deviceId)
        assertEquals(exp["relay_id"]!!.jsonPrimitive.content, relayId)
        assertEquals(exp["mailbox_auth_seed_hex"]!!.jsonPrimitive.content, KeysAndAuth.toLowerHex(mk.authSeed))
        assertEquals(exp["mailbox_auth_pk_hex"]!!.jsonPrimitive.content, KeysAndAuth.toLowerHex(mk.authPub))
        assertEquals(exp["mailbox_auth_pk_b64u"]!!.jsonPrimitive.content, KeysAndAuth.b64uEncode(mk.authPub))
        assertEquals(exp["mailbox_id"]!!.jsonPrimitive.content, mk.mailboxId)

        val cardSigInput = KeysAndAuth.deviceCardSignInput(dk.signPub, dk.kemPubBytes, issuedAt)
        val cardSig = KeysAndAuth.signDeviceCard(dk.signSeed, dk.kemPubBytes, issuedAt)
        assertEquals(exp["card_sig_input_hex"]!!.jsonPrimitive.content, KeysAndAuth.toLowerHex(cardSigInput))
        assertEquals(exp["card_sig_hex"]!!.jsonPrimitive.content, KeysAndAuth.toLowerHex(cardSig))
        assertEquals(exp["card_sig_b64u"]!!.jsonPrimitive.content, KeysAndAuth.b64uEncode(cardSig))

        KeysAndAuth.verifyDeviceCard(dk.deviceId, dk.signPub, dk.kemPubBytes, issuedAt, cardSig)

        assertEquals(
            exp["ed25519_pkcs8_der_hex"]!!.jsonPrimitive.content,
            KeysAndAuth.toLowerHex(KeysAndAuth.encodeEd25519Pkcs8(dk.signSeed))
        )
        assertEquals(
            exp["x25519_pkcs8_der_hex"]!!.jsonPrimitive.content,
            KeysAndAuth.toLowerHex(KeysAndAuth.encodeX25519Pkcs8(dk.kemPrivBytes))
        )
        assertEquals(
            exp["ed25519_spki_der_hex"]!!.jsonPrimitive.content,
            KeysAndAuth.toLowerHex(KeysAndAuth.encodeEd25519Spki(dk.signPub))
        )
        assertEquals(
            exp["x25519_spki_der_hex"]!!.jsonPrimitive.content,
            KeysAndAuth.toLowerHex(KeysAndAuth.encodeX25519Spki(dk.kemPubBytes))
        )

        // Negative cases from 01_seed_and_keys.json
        val neg = vec["negative_cases"]!!.jsonObject
        val wrongDevId = neg["wrong_device_id"]!!.jsonPrimitive.content
        val tamperedSig = KeysAndAuth.fromHex(neg["tampered_sig_hex"]!!.jsonPrimitive.content)

        try {
            KeysAndAuth.verifyDeviceCard(wrongDevId, dk.signPub, dk.kemPubBytes, issuedAt, cardSig)
            fail("Expected wrong_device_id to fail")
        } catch (_: CryptoException.DeviceIdMismatch) {
        }

        try {
            KeysAndAuth.verifyDeviceCard(dk.deviceId, dk.signPub, dk.kemPubBytes, issuedAt, tamperedSig)
            fail("Expected tampered_sig_hex to fail")
        } catch (_: CryptoException.InvalidSignature) {
        }

        dk.zero()
        mk.zero()
    }

    @Test
    fun testVector02RelayAuthSig(): Unit {
        val vec = loadVectorJson("02_relay_auth_sig.json")
        val accessKey = vec["access_key"]!!.jsonPrimitive.content
        val hmacKey = KeysAndAuth.deriveRelayHmacKey(accessKey)
        assertEquals(vec["expected_relay_hmac_key_hex"]!!.jsonPrimitive.content, KeysAndAuth.toLowerHex(hmacKey))
        assertEquals(
            vec["deposit_token_sample_hash"]!!.jsonPrimitive.content,
            KeysAndAuth.hashDepositToken("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
        )
        assertEquals(
            vec["upload_token_sample_hash"]!!.jsonPrimitive.content,
            KeysAndAuth.hashUploadToken("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")
        )

        val cases = vec["cases"]!!.jsonArray
        assertEquals(6, cases.size)
        for (el in cases) {
            val c = el.jsonObject
            val name = c["name"]!!.jsonPrimitive.content
            val method = c["method"]!!.jsonPrimitive.content
            val pathAndQuery = c["path_and_raw_query"]!!.jsonPrimitive.content
            val ts = c["ts"]!!.jsonPrimitive.content
            val nonce = c["nonce"]!!.jsonPrimitive.content
            val isStream = c["is_stream"]!!.jsonPrimitive.boolean
            val rawBody = c["raw_body_utf8"]?.jsonPrimitive?.content.orEmpty()
            val streamLen = c["stream_content_length"]?.jsonPrimitive?.longOrNull ?: 0L
            val depositToken = c["deposit_token"]?.jsonPrimitive?.content.orEmpty()
            val uploadToken = c["upload_token"]?.jsonPrimitive?.content.orEmpty()

            val bodyBind = if (isStream) {
                KeysAndAuth.bodyBindingStream(streamLen)
            } else {
                KeysAndAuth.bodyBindingControl(rawBody.toByteArray(StandardCharsets.UTF_8))
            }
            val extraBind = KeysAndAuth.extraTokenBinding(depositToken, uploadToken)
            val canonReq = KeysAndAuth.buildCanonicalRequest(method, pathAndQuery, ts, nonce, bodyBind, extraBind)
            val sigHex = KeysAndAuth.signRelayRequest(accessKey, method, pathAndQuery, ts, nonce, bodyBind, extraBind)

            assertEquals("$name body_binding", c["expected_body_binding"]!!.jsonPrimitive.content, bodyBind)
            assertEquals("$name extra_token_binding", c["expected_extra_token_binding"]!!.jsonPrimitive.content, extraBind)
            assertEquals("$name canonical_req", c["expected_canonical_req"]!!.jsonPrimitive.content, canonReq)
            assertEquals("$name sig_hex", c["expected_sig_hex"]!!.jsonPrimitive.content, sigHex)
            assertTrue(KeysAndAuth.verifyRelayRequest(accessKey, method, pathAndQuery, ts, nonce, bodyBind, extraBind, sigHex))
            assertFalse(KeysAndAuth.verifyRelayRequest(accessKey, method, pathAndQuery, ts, nonce, bodyBind, extraBind, sigHex.uppercase()))
        }

        val mbCase = vec["mailbox_sig_case"]!!.jsonObject
        val mbSeed = KeysAndAuth.fromHex(mbCase["mailbox_auth_seed_hex"]!!.jsonPrimitive.content)
        val mbPk = KeysAndAuth.ed25519PublicKeyFromSeed(mbSeed)
        assertEquals(mbCase["mailbox_auth_pk_b64u"]!!.jsonPrimitive.content, KeysAndAuth.b64uEncode(mbPk))
        val mbId = mbCase["mailbox_id"]!!.jsonPrimitive.content
        assertEquals(mbId, KeysAndAuth.deriveMailboxId(mbPk))

        val mbMethod = mbCase["method"]!!.jsonPrimitive.content
        val mbPath = mbCase["path_and_raw_query"]!!.jsonPrimitive.content
        val mbTs = mbCase["ts"]!!.jsonPrimitive.content
        val mbNonce = mbCase["nonce"]!!.jsonPrimitive.content
        val mbBody = mbCase["raw_body_utf8"]!!.jsonPrimitive.content.toByteArray(StandardCharsets.UTF_8)
        val mbBodyBind = KeysAndAuth.bodyBindingControl(mbBody)
        val mbSigInput = KeysAndAuth.buildMailboxSigInput(mbMethod, mbPath, mbId, mbTs, mbNonce, mbBodyBind)
        val mbSig = KeysAndAuth.signMailboxRequest(mbSeed, mbMethod, mbPath, mbId, mbTs, mbNonce, mbBodyBind)

        assertEquals(mbCase["expected_body_binding"]!!.jsonPrimitive.content, mbBodyBind)
        assertEquals(mbCase["expected_sig_input"]!!.jsonPrimitive.content, mbSigInput)
        assertEquals(mbCase["expected_mailbox_sig_b64u"]!!.jsonPrimitive.content, mbSig)
        assertTrue(KeysAndAuth.verifyMailboxRequest(mbPk, mbMethod, mbPath, mbId, mbTs, mbNonce, mbBodyBind, mbSig))

        val skewObj = vec["clock_skew_cases"]!!.jsonObject
        val serverTs = skewObj["server_ts"]!!.jsonPrimitive.long
        val maxSkew = skewObj["max_skew_sec"]!!.jsonPrimitive.long
        for (sc in skewObj["cases"]!!.jsonArray) {
            val ts = sc.jsonObject["ts"]!!.jsonPrimitive.long
            val expect409 = sc.jsonObject["expect_clock_skew_409"]!!.jsonPrimitive.boolean
            val skewed = kotlin.math.abs(ts - serverTs) > maxSkew
            assertEquals(expect409, skewed)
        }
    }

    @Test
    fun testVector03HandshakeQrOob(): Unit {
        val vec = loadVectorJson("03_handshake_qr_oob.json")
        val roomId = vec["room_id"]!!.jsonPrimitive.content
        val purpose = vec["purpose"]!!.jsonPrimitive.content
        val eASk = KeysAndAuth.fromHex(vec["e_a_sk_hex"]!!.jsonPrimitive.content)
        val eBSk = KeysAndAuth.fromHex(vec["e_b_sk_hex"]!!.jsonPrimitive.content)
        val nA = KeysAndAuth.fromHex(vec["n_a_hex"]!!.jsonPrimitive.content)
        val nB = KeysAndAuth.fromHex(vec["n_b_hex"]!!.jsonPrimitive.content)
        val oob = KeysAndAuth.fromHex(vec["oob_secret_hex"]!!.jsonPrimitive.content)

        val pubA = KeysAndAuth.x25519PublicKeyFromPrivate(eASk)
        val pubB = KeysAndAuth.x25519PublicKeyFromPrivate(eBSk)
        assertEquals(vec["e_a_pk_hex"]!!.jsonPrimitive.content, KeysAndAuth.toLowerHex(pubA))
        assertEquals(vec["e_b_pk_hex"]!!.jsonPrimitive.content, KeysAndAuth.toLowerHex(pubB))

        val shared = KeysAndAuth.x25519SharedSecret(eASk, pubB)
        val t1 = Handshake.buildQrTranscript(purpose, roomId, pubA, nA, pubB, nB)
        assertEquals(154, t1.size)

        val resA = Handshake.deriveQrOobSession(purpose, roomId, eASk, pubB, pubA, nA, pubB, nB, oob)
        val resB = Handshake.deriveQrOobSession(purpose, roomId, eBSk, pubA, pubA, nA, pubB, nB, oob)
        assertArrayEquals(resA.sessionKey, resB.sessionKey)
        assertArrayEquals(resA.macA, resB.macA)
        assertArrayEquals(resA.macB, resB.macB)

        val exp = vec["expected"]!!.jsonObject
        assertEquals(exp["shared_hex"]!!.jsonPrimitive.content, KeysAndAuth.toLowerHex(shared))
        assertEquals(exp["transcript_1_hex"]!!.jsonPrimitive.content, KeysAndAuth.toLowerHex(t1))
        assertEquals(exp["th_hex"]!!.jsonPrimitive.content, KeysAndAuth.toLowerHex(resA.th))
        assertEquals(exp["prk_hex"]!!.jsonPrimitive.content, KeysAndAuth.toLowerHex(resA.prk))
        assertEquals(exp["session_key_hex"]!!.jsonPrimitive.content, KeysAndAuth.toLowerHex(resA.sessionKey))
        assertEquals(exp["confirm_key_a_hex"]!!.jsonPrimitive.content, KeysAndAuth.toLowerHex(resA.confirmKeyA))
        assertEquals(exp["confirm_key_b_hex"]!!.jsonPrimitive.content, KeysAndAuth.toLowerHex(resA.confirmKeyB))
        assertEquals(exp["mac_a_b64u"]!!.jsonPrimitive.content, KeysAndAuth.b64uEncode(resA.macA))
        assertEquals(exp["mac_b_b64u"]!!.jsonPrimitive.content, KeysAndAuth.b64uEncode(resA.macB))

        // oneshot_part0
        val p0Obj = vec["oneshot_part0"]!!.jsonObject
        val msgId = KeysAndAuth.fromHex(p0Obj["msg_id_hex"]!!.jsonPrimitive.content)
        val (p0Key, p0Np) = Handshake.deriveOneshotPart0Keys(resA.sessionKey, msgId)
        assertEquals(p0Obj["expected_part0_key_hex"]!!.jsonPrimitive.content, KeysAndAuth.toLowerHex(p0Key))
        assertEquals(p0Obj["expected_part0_nonce_prefix_hex"]!!.jsonPrimitive.content, KeysAndAuth.toLowerHex(p0Np))

        // pipe_ctrl
        val ctrlObj = vec["pipe_ctrl"]!!.jsonObject
        val (ctrlKey, ctrlNp) = Handshake.derivePipeCtrlKeys(resA.th, resA.sessionKey)
        assertEquals(ctrlObj["expected_ctrl_key_hex"]!!.jsonPrimitive.content, KeysAndAuth.toLowerHex(ctrlKey))
        assertEquals(ctrlObj["expected_ctrl_np_hex"]!!.jsonPrimitive.content, KeysAndAuth.toLowerHex(ctrlNp))

        for (frameEl in ctrlObj["frames"]!!.jsonArray) {
            val f = frameEl.jsonObject
            val seq = f["ctrl_seq"]!!.jsonPrimitive.long
            val ptUtf8 = f["plaintext_utf8"]!!.jsonPrimitive.content
            val aad = Handshake.buildPipeCtrlAad(resA.th, seq)
            assertEquals(57, aad.size)
            assertEquals(f["expected_aad_hex"]!!.jsonPrimitive.content, KeysAndAuth.toLowerHex(aad))

            val ct = Handshake.sealPipeCtrl(ctrlKey, ctrlNp, resA.th, seq, ptUtf8.toByteArray(StandardCharsets.UTF_8))
            assertEquals(f["expected_ct_b64u"]!!.jsonPrimitive.content, KeysAndAuth.b64uEncode(ct))

            val opened = Handshake.openPipeCtrlVerified(
                ctrlKey32 = ctrlKey,
                ctrlNp7 = ctrlNp,
                th32 = resB.th,
                ctrlSeq = seq,
                fromInitiator = (seq % 2L == 0L),
                lastSeenSeq = -1L,
                ciphertext = ct,
            )
            assertEquals(ptUtf8, String(opened, StandardCharsets.UTF_8))
        }

        // pair_bind
        val pbObj = vec["pair_bind"]!!.jsonObject
        val resPair = Handshake.deriveQrOobSession(
            pbObj["purpose"]!!.jsonPrimitive.content,
            roomId,
            eASk,
            pubB,
            pubA,
            nA,
            pubB,
            nB,
            oob,
        )
        val (pairNa, pairNb) = Handshake.derivePairBindNonces(resPair.prk)
        assertEquals(pbObj["expected_th_hex"]!!.jsonPrimitive.content, KeysAndAuth.toLowerHex(resPair.th))
        assertEquals(pbObj["expected_prk_hex"]!!.jsonPrimitive.content, KeysAndAuth.toLowerHex(resPair.prk))
        assertEquals(pbObj["expected_session_key_hex"]!!.jsonPrimitive.content, KeysAndAuth.toLowerHex(resPair.sessionKey))
        assertEquals(pbObj["expected_pair_nonce_a_hex"]!!.jsonPrimitive.content, KeysAndAuth.toLowerHex(pairNa))
        assertEquals(pbObj["expected_pair_nonce_b_hex"]!!.jsonPrimitive.content, KeysAndAuth.toLowerHex(pairNb))

        val ptA = pbObj["plaintext_a_utf8"]!!.jsonPrimitive.content
        val ptB = pbObj["plaintext_b_utf8"]!!.jsonPrimitive.content
        val ctA = Handshake.sealPairBind(resPair.sessionKey, resPair.prk, resPair.th, isInitiator = true, ptA.toByteArray(StandardCharsets.UTF_8))
        val ctB = Handshake.sealPairBind(resPair.sessionKey, resPair.prk, resPair.th, isInitiator = false, ptB.toByteArray(StandardCharsets.UTF_8))
        assertEquals(pbObj["expected_ct_a_b64u"]!!.jsonPrimitive.content, KeysAndAuth.b64uEncode(ctA))
        assertEquals(pbObj["expected_ct_b_b64u"]!!.jsonPrimitive.content, KeysAndAuth.b64uEncode(ctB))
        assertEquals(ptA, String(Handshake.openPairBind(resPair.sessionKey, resPair.prk, resPair.th, fromInitiator = true, ctA), StandardCharsets.UTF_8))
        assertEquals(ptB, String(Handshake.openPairBind(resPair.sessionKey, resPair.prk, resPair.th, fromInitiator = false, ctB), StandardCharsets.UTF_8))

        // Negative cases
        val neg = vec["negative_cases"]!!.jsonObject
        val wrongOob = KeysAndAuth.fromHex(neg["wrong_oob_secret_hex"]!!.jsonPrimitive.content)
        val resWrong = Handshake.deriveQrOobSession(purpose, roomId, eBSk, pubA, pubA, nA, pubB, nB, wrongOob)
        try {
            Handshake.verifyMac(resA.macB, resWrong.macB)
            fail("Expected MAC mismatch for wrong oob_secret")
        } catch (_: CryptoException.MacMismatch) {
        }

        val lowOrderPk = KeysAndAuth.fromHex(neg["low_order_all_zero_pk_hex"]!!.jsonPrimitive.content)
        try {
            KeysAndAuth.x25519SharedSecret(eASk, lowOrderPk)
            fail("Expected all-zero shared secret rejection")
        } catch (_: CryptoException.AllZeroSharedKey) {
        }
    }

    @Test
    fun testVector04HandshakeCommitSas(): Unit {
        val vec = loadVectorJson("04_handshake_commit_sas.json")
        val roomId = vec["room_id"]!!.jsonPrimitive.content
        val purpose = vec["purpose"]!!.jsonPrimitive.content
        val eASk = KeysAndAuth.fromHex(vec["e_a_sk_hex"]!!.jsonPrimitive.content)
        val eBSk = KeysAndAuth.fromHex(vec["e_b_sk_hex"]!!.jsonPrimitive.content)
        val nA = KeysAndAuth.fromHex(vec["n_a_hex"]!!.jsonPrimitive.content)
        val nB = KeysAndAuth.fromHex(vec["n_b_hex"]!!.jsonPrimitive.content)

        val pubA = KeysAndAuth.x25519PublicKeyFromPrivate(eASk)
        val pubB = KeysAndAuth.x25519PublicKeyFromPrivate(eBSk)
        assertEquals(vec["e_a_pk_hex"]!!.jsonPrimitive.content, KeysAndAuth.toLowerHex(pubA))
        assertEquals(vec["e_b_pk_hex"]!!.jsonPrimitive.content, KeysAndAuth.toLowerHex(pubB))

        val commitA = Handshake.computeCommitA(purpose, roomId, pubA, nA)
        val t2 = Handshake.buildSasTranscript(purpose, roomId, commitA, pubA, nA, pubB, nB)
        assertEquals(187, t2.size)

        val resA = Handshake.deriveSasSession(purpose, roomId, eASk, pubB, commitA, pubA, nA, pubB, nB)
        val resB = Handshake.deriveSasSession(purpose, roomId, eBSk, pubA, commitA, pubA, nA, pubB, nB)
        assertArrayEquals(resA.sessionKey, resB.sessionKey)
        assertEquals(resA.sasStr, resB.sasStr)

        val exp = vec["expected"]!!.jsonObject
        assertEquals(exp["commit_a_hex"]!!.jsonPrimitive.content, KeysAndAuth.toLowerHex(commitA))
        assertEquals(exp["commit_a_b64u"]!!.jsonPrimitive.content, KeysAndAuth.b64uEncode(commitA))
        assertEquals(exp["transcript_2_hex"]!!.jsonPrimitive.content, KeysAndAuth.toLowerHex(t2))
        assertEquals(exp["th_hex"]!!.jsonPrimitive.content, KeysAndAuth.toLowerHex(resA.th))
        assertEquals(exp["prk_hex"]!!.jsonPrimitive.content, KeysAndAuth.toLowerHex(resA.prk))
        assertEquals(exp["session_key_hex"]!!.jsonPrimitive.content, KeysAndAuth.toLowerHex(resA.sessionKey))
        assertEquals(exp["sas_bytes_hex"]!!.jsonPrimitive.content, KeysAndAuth.toLowerHex(resA.sasBytes))
        assertEquals(exp["sas_int"]!!.jsonPrimitive.int, resA.sasInt)
        assertEquals(exp["sas_str"]!!.jsonPrimitive.content, resA.sasStr)
        assertEquals("001807", resA.sasStr)
        assertEquals(exp["confirm_key_a_hex"]!!.jsonPrimitive.content, KeysAndAuth.toLowerHex(resA.confirmKeyA))
        assertEquals(exp["confirm_key_b_hex"]!!.jsonPrimitive.content, KeysAndAuth.toLowerHex(resA.confirmKeyB))
        assertEquals(exp["mac_a_b64u"]!!.jsonPrimitive.content, KeysAndAuth.b64uEncode(resA.macA))
        assertEquals(exp["mac_b_b64u"]!!.jsonPrimitive.content, KeysAndAuth.b64uEncode(resA.macB))

        val (ctrlKey, ctrlNp) = Handshake.derivePipeCtrlKeys(resA.th, resA.sessionKey)
        assertEquals(exp["pipe_ctrl_key_hex"]!!.jsonPrimitive.content, KeysAndAuth.toLowerHex(ctrlKey))
        assertEquals(exp["pipe_ctrl_np_hex"]!!.jsonPrimitive.content, KeysAndAuth.toLowerHex(ctrlNp))

        val ctrlPt = exp["pipe_ctrl_seq0_pt_utf8"]!!.jsonPrimitive.content
        val ctrlCt = Handshake.sealPipeCtrl(ctrlKey, ctrlNp, resA.th, 0L, ctrlPt.toByteArray(StandardCharsets.UTF_8))
        assertEquals(exp["pipe_ctrl_seq0_ct_b64u"]!!.jsonPrimitive.content, KeysAndAuth.b64uEncode(ctrlCt))

        // Negative case: tampered E_a fails commit_a verification
        val tamperedEa = KeysAndAuth.fromHex(vec["negative_cases"]!!.jsonObject["tampered_e_a_pk_hex"]!!.jsonPrimitive.content)
        try {
            Handshake.verifyCommitA(purpose, roomId, tamperedEa, nA, commitA)
            fail("Expected tampered E_a to fail commit_a verification")
        } catch (_: CryptoException.CommitMismatch) {
        }
    }

    @Test
    fun testVector05Paired0RttEnvelope(): Unit {
        val vec = loadVectorJson("05_paired_0rtt_envelope.json")
        val senderSeed = KeysAndAuth.fromHex(vec["sender_master_seed_hex"]!!.jsonPrimitive.content)
        val recipSeed = KeysAndAuth.fromHex(vec["recipient_master_seed_hex"]!!.jsonPrimitive.content)
        val ephSk = KeysAndAuth.fromHex(vec["ephemeral_sk_hex"]!!.jsonPrimitive.content)
        val msgId = KeysAndAuth.fromHex(vec["msg_id_hex"]!!.jsonPrimitive.content)
        val createdAt = vec["created_at"]!!.jsonPrimitive.long
        val manifestUtf8 = vec["manifest_utf8"]!!.jsonPrimitive.content.toByteArray(StandardCharsets.UTF_8)
        val manifestSha = KeysAndAuth.sha256(manifestUtf8)
        assertEquals(vec["manifest_sha256_hex"]!!.jsonPrimitive.content, KeysAndAuth.toLowerHex(manifestSha))

        val senderDk = KeysAndAuth.deriveDeviceKeys(senderSeed)
        val recipDk = KeysAndAuth.deriveDeviceKeys(recipSeed)

        val sealed = SealedHeader.seal0RttHeaderDeterministic(
            senderKeys = senderDk,
            ephemeralSk32 = ephSk,
            msgIdRaw16 = msgId,
            recipientIdRaw16 = recipDk.deviceIdRaw,
            recipientKemPub32 = recipDk.kemPubBytes,
            createdAt = createdAt,
            manifestSha256 = manifestSha,
        )
        assertEquals(208, sealed.sealedHeader.size)
        val sealedB64 = KeysAndAuth.b64uEncode(sealed.sealedHeader)
        assertEquals(278, sealedB64.length)

        val exp = vec["expected"]!!.jsonObject
        assertEquals(exp["sender_device_id"]!!.jsonPrimitive.content, senderDk.deviceId)
        assertEquals(exp["sender_sign_pk_b64u"]!!.jsonPrimitive.content, KeysAndAuth.b64uEncode(senderDk.signPub))
        assertEquals(exp["recipient_device_id"]!!.jsonPrimitive.content, recipDk.deviceId)
        assertEquals(exp["recipient_kem_pk_b64u"]!!.jsonPrimitive.content, KeysAndAuth.b64uEncode(recipDk.kemPubBytes))

        val clearHdr = sealed.sealedHeader.copyOfRange(0, SealedHeader.CLEAR_HEADER_SIZE)
        val sigInput = SealedHeader.buildZeroRttSigInput(clearHdr, senderDk.deviceIdRaw, recipDk.deviceIdRaw, createdAt, manifestSha)
        assertEquals(149, sigInput.size)
        assertEquals(exp["clear_header_hex"]!!.jsonPrimitive.content, KeysAndAuth.toLowerHex(clearHdr))
        assertEquals(exp["sig_input_hex"]!!.jsonPrimitive.content, KeysAndAuth.toLowerHex(sigInput))
        assertEquals(exp["sealed_header_hex"]!!.jsonPrimitive.content, KeysAndAuth.toLowerHex(sealed.sealedHeader))
        assertEquals(exp["sealed_header_b64u"]!!.jsonPrimitive.content, sealedB64)
        assertEquals(exp["part0_key_hex"]!!.jsonPrimitive.content, KeysAndAuth.toLowerHex(sealed.part0Key))
        assertEquals(exp["part0_nonce_prefix_hex"]!!.jsonPrimitive.content, KeysAndAuth.toLowerHex(sealed.part0NoncePrefix))

        val opened = SealedHeader.open0RttHeader(recipDk, sealed.sealedHeader) { sid ->
            if (sid == senderDk.deviceId) senderDk.signPub else null
        }
        assertEquals(exp["sender_sig_b64u"]!!.jsonPrimitive.content, KeysAndAuth.b64uEncode(opened.senderSig))
        assertArrayEquals(sealed.part0Key, opened.part0Key)
        assertArrayEquals(sealed.part0NoncePrefix, opened.part0NoncePrefix)

        val directAck = SealedHeader.computeDirectAckMac(sealed.part0Key, msgId)
        assertEquals(exp["direct_ack_mac_b64u"]!!.jsonPrimitive.content, KeysAndAuth.b64uEncode(directAck))
        SealedHeader.verifyDirectAckMac(sealed.part0Key, msgId, directAck)

        // Negative cases
        val neg = vec["negative_cases"]!!.jsonObject
        val tamperedHdr = KeysAndAuth.b64uDecode(neg["tampered_clear_header_b64u"]!!.jsonPrimitive.content)
        try {
            SealedHeader.open0RttHeader(recipDk, tamperedHdr) { senderDk.signPub }
            fail("Expected tampered clear_header to fail")
        } catch (_: CryptoException) {
        }

        val wrongRecipDk = KeysAndAuth.deriveDeviceKeys(KeysAndAuth.fromHex(neg["wrong_recipient_master_seed_hex"]!!.jsonPrimitive.content))
        try {
            SealedHeader.open0RttHeader(wrongRecipDk, sealed.sealedHeader) { senderDk.signPub }
            fail("Expected wrong recipient key to fail")
        } catch (_: CryptoException) {
        }

        val badAck = KeysAndAuth.b64uDecode(neg["tampered_direct_ack_mac_b64u"]!!.jsonPrimitive.content)
        try {
            SealedHeader.verifyDirectAckMac(sealed.part0Key, msgId, badAck)
            fail("Expected tampered direct_ack_mac to fail")
        } catch (_: CryptoException.MacMismatch) {
        }
    }

    @Test
    fun testVector06StreamAeadAndPadding(): Unit {
        val vec = loadVectorJson("06_stream_aead_and_padding.json")
        val padObj = vec["manifest_padding"]!!.jsonObject
        for (cEl in padObj["cases"]!!.jsonArray) {
            val c = cEl.jsonObject
            val rawLen = c["raw_len"]!!.jsonPrimitive.int
            val raw = detPatternBytes(rawLen)
            val padded = StreamCipher.padManifest(raw)
            assertEquals(c["expected_padded_len"]!!.jsonPrimitive.int, padded.size)
            assertEquals(c["expected_padded_sha256"]!!.jsonPrimitive.content, KeysAndAuth.toLowerHex(KeysAndAuth.sha256(padded)))
            assertEquals(c["expected_prefix_16_hex"]!!.jsonPrimitive.content, KeysAndAuth.toLowerHex(padded.copyOfRange(0, 16)))
            assertArrayEquals(raw, StreamCipher.unpadManifest(padded))
        }

        // Manifest padding negative cases
        try {
            StreamCipher.unpadManifest(ByteArray(4096))
            fail("Expected L=0 padded manifest rejection")
        } catch (_: CryptoException.InvalidPadding) {
        }
        val dirtyTail = StreamCipher.padManifest(detPatternBytes(1))
        dirtyTail[dirtyTail.lastIndex] = 0x01
        try {
            StreamCipher.unpadManifest(dirtyTail)
            fail("Expected non-zero tail padding rejection")
        } catch (_: CryptoException.InvalidPadding) {
        }
        try {
            StreamCipher.unpadManifest(ByteArray(4095))
            fail("Expected misaligned padded length rejection")
        } catch (_: CryptoException.InvalidPadding) {
        }
        // Over-padded extra 4 KiB bucket rejection
        val valid1Bucket = StreamCipher.padManifest(detPatternBytes(10))
        val overPadded2Buckets = ByteArray(8192).also { System.arraycopy(valid1Bucket, 0, it, 0, valid1Bucket.size) }
        try {
            StreamCipher.unpadManifest(overPadded2Buckets)
            fail("Expected excess 4 KiB bucket rejection")
        } catch (_: CryptoException.InvalidPadding) {
        }

        // STREAM AEAD cases
        val streamObj = vec["stream_aead"]!!.jsonObject
        val msgId = KeysAndAuth.fromHex(streamObj["msg_id_hex"]!!.jsonPrimitive.content)
        val partId = streamObj["part_id"]!!.jsonPrimitive.int
        val blobKey = KeysAndAuth.fromHex(streamObj["blob_key_hex"]!!.jsonPrimitive.content)
        val (encKey, noncePfx) = StreamCipher.deriveBlobPartKeys(msgId, partId, blobKey)
        assertEquals(streamObj["expected_enc_key_hex"]!!.jsonPrimitive.content, KeysAndAuth.toLowerHex(encKey))
        assertEquals(streamObj["expected_nonce_prefix_hex"]!!.jsonPrimitive.content, KeysAndAuth.toLowerHex(noncePfx))

        for (cEl in streamObj["cases"]!!.jsonArray) {
            val c = cEl.jsonObject
            val name = c["name"]!!.jsonPrimitive.content
            val ptLen = c["plaintext_len"]!!.jsonPrimitive.int
            val pt = detPatternBytes(ptLen)
            assertEquals("$name pt sha", c["plaintext_sha256"]!!.jsonPrimitive.content, KeysAndAuth.toLowerHex(KeysAndAuth.sha256(pt)))

            val totalBlocks = StreamCipher.totalBlocks(ptLen.toLong())
            assertEquals("$name total_blocks", c["expected_total_blocks"]!!.jsonPrimitive.long, totalBlocks.toLong())

            val firstPtLen = if (totalBlocks == 1u) ptLen else StreamCipher.CHUNK_PLAINTEXT_MAX
            val firstNonce = StreamCipher.buildChunkNonce(noncePfx, 0u, totalBlocks == 1u)
            val firstAad = StreamCipher.buildChunkAad(msgId, partId, 0u, totalBlocks == 1u, firstPtLen)
            assertEquals(46, firstAad.size)
            assertEquals("$name first nonce", c["first_block_nonce_hex"]!!.jsonPrimitive.content, KeysAndAuth.toLowerHex(firstNonce))
            assertEquals("$name first aad", c["first_block_aad_hex"]!!.jsonPrimitive.content, KeysAndAuth.toLowerHex(firstAad))

            val lastBlkIdx = totalBlocks - 1u
            val lastPtLen = if (ptLen == 0) 0 else (((ptLen - 1) % StreamCipher.CHUNK_PLAINTEXT_MAX) + 1)
            val lastNonce = StreamCipher.buildChunkNonce(noncePfx, lastBlkIdx, true)
            val lastAad = StreamCipher.buildChunkAad(msgId, partId, lastBlkIdx, true, lastPtLen)
            assertEquals("$name last nonce", c["last_block_nonce_hex"]!!.jsonPrimitive.content, KeysAndAuth.toLowerHex(lastNonce))
            assertEquals("$name last aad", c["last_block_aad_hex"]!!.jsonPrimitive.content, KeysAndAuth.toLowerHex(lastAad))

            val ctOut = ByteArrayOutputStream()
            val (ptN, ctN) = StreamCipher.encryptPartStream(ByteArrayInputStream(pt), ctOut, encKey, noncePfx, msgId, partId)
            val ctBytes = ctOut.toByteArray()
            assertEquals(ptLen.toLong(), ptN)
            assertEquals(c["expected_ciphertext_len"]!!.jsonPrimitive.long, ctN)
            assertEquals(c["expected_ciphertext_sha256"]!!.jsonPrimitive.content, KeysAndAuth.toLowerHex(KeysAndAuth.sha256(ctBytes)))
            assertEquals(c["expected_nano_chunk_count"]!!.jsonPrimitive.int, StreamCipher.transportChunkCount(ctN, 4))
            assertEquals(c["expected_std_chunk_count"]!!.jsonPrimitive.int, StreamCipher.transportChunkCount(ctN, 16))

            c["ciphertext_hex"]?.jsonPrimitive?.content?.let { wantHex ->
                assertEquals(wantHex, KeysAndAuth.toLowerHex(ctBytes))
            }
            c["ciphertext_first_32_hex"]?.jsonPrimitive?.content?.let { wantFirst ->
                assertEquals(wantFirst, KeysAndAuth.toLowerHex(ctBytes.copyOfRange(0, 32)))
            }
            c["ciphertext_last_32_hex"]?.jsonPrimitive?.content?.let { wantLast ->
                assertEquals(wantLast, KeysAndAuth.toLowerHex(ctBytes.copyOfRange(ctBytes.size - 32, ctBytes.size)))
            }

            val decOut = ByteArrayOutputStream()
            val decN = StreamCipher.decryptPartStream(ByteArrayInputStream(ctBytes), decOut, encKey, noncePfx, msgId, partId)
            assertEquals(ptLen.toLong(), decN)
            assertArrayEquals(pt, decOut.toByteArray())

            if (name == "two_blocks_65537B") {
                // Truncation missing is_final=0x01
                try {
                    StreamCipher.decryptPartStream(
                        ByteArrayInputStream(ctBytes.copyOfRange(0, StreamCipher.CHUNK_CIPHERTEXT_MAX)),
                        ByteArrayOutputStream(),
                        encKey,
                        noncePfx,
                        msgId,
                        partId,
                    )
                    fail("Expected truncated stream rejection")
                } catch (_: CryptoException) {
                }
                // 1-bit tag tamper
                val tampered = ctBytes.copyOf()
                tampered[tampered.lastIndex] = (tampered[tampered.lastIndex].toInt() xor 0x01).toByte()
                try {
                    StreamCipher.decryptPartStream(ByteArrayInputStream(tampered), ByteArrayOutputStream(), encKey, noncePfx, msgId, partId)
                    fail("Expected tampered tag rejection")
                } catch (_: CryptoException) {
                }
                // Cross-part_id splice
                try {
                    StreamCipher.decryptPartStream(ByteArrayInputStream(ctBytes), ByteArrayOutputStream(), encKey, noncePfx, msgId, 2)
                    fail("Expected cross-part_id splice rejection")
                } catch (_: CryptoException) {
                }
            }
            if (name == "multi_chunk_300000B") {
                // Reorder block 0 and block 1
                val reordered = ctBytes.copyOf()
                System.arraycopy(ctBytes, StreamCipher.CHUNK_CIPHERTEXT_MAX, reordered, 0, StreamCipher.CHUNK_CIPHERTEXT_MAX)
                System.arraycopy(ctBytes, 0, reordered, StreamCipher.CHUNK_CIPHERTEXT_MAX, StreamCipher.CHUNK_CIPHERTEXT_MAX)
                try {
                    StreamCipher.decryptPartStream(ByteArrayInputStream(reordered), ByteArrayOutputStream(), encKey, noncePfx, msgId, partId)
                    fail("Expected reordered STREAM blocks rejection")
                } catch (_: CryptoException) {
                }
            }
        }
    }

    @Test
    fun testVector07CrockfordRoomIdAndLuhnMod32(): Unit {
        val vec = loadVectorJson("07_crockford_room_id.json")
        assertEquals(Crockford.CROCKFORD_ALPHABET, vec["alphabet"]!!.jsonPrimitive.content)

        for (cEl in vec["encode_decode_cases"]!!.jsonArray) {
            val c = cEl.jsonObject
            val raw = KeysAndAuth.fromHex(c["raw_hex"]!!.jsonPrimitive.content)
            val canon = Crockford.encodeRoomId(raw)
            val disp = Crockford.formatRoomId(canon)
            assertEquals(c["canonical"]!!.jsonPrimitive.content, canon)
            assertEquals(c["display"]!!.jsonPrimitive.content, disp)
            assertArrayEquals(raw, Crockford.decodeRoomId(disp))

            // Verify Luhn-mod-32 check character roundtrip & single-char corruption catch
            val withCheck = Crockford.appendLuhnMod32(canon)
            assertEquals(9, withCheck.length)
            assertTrue(Crockford.verifyLuhnMod32(withCheck))
            val flipped = (if (withCheck[0] == '0') "1" else "0") + withCheck.substring(1)
            assertFalse(Crockford.verifyLuhnMod32(flipped))
        }

        for (nEl in vec["normalize_cases"]!!.jsonArray) {
            val n = nEl.jsonObject
            assertEquals(n["expected"]!!.jsonPrimitive.content, Crockford.normalizeRoomId(n["input"]!!.jsonPrimitive.content))
        }

        for (invEl in vec["invalid_cases"]!!.jsonArray) {
            val inv = invEl.jsonPrimitive.content
            try {
                Crockford.normalizeRoomId(inv)
                fail("Expected invalid room_id '$inv' to fail")
            } catch (_: CryptoException.InvalidRoomId) {
            }
        }

        // Unicode ligature / non-ASCII pre-check (`#378` P2-1)
        for (bad in listOf("K7M9P2\ufb01", "K7M9P2X\u017f", "K7M9P2X\u212a")) {
            try {
                Crockford.normalizeRoomId(bad)
                fail("Expected non-ASCII room_id '$bad' to fail")
            } catch (_: CryptoException.InvalidRoomId) {
            }
        }
    }

    @Test
    fun testCryptoHardeningMultiPinAndLocalMetaCache(): Unit = runBlocking {
        // 1. All 9 X25519 low-order points rejected
        val (sk, _) = KeysAndAuth.generateEphemeralX25519()
        val lowOrderHexes = listOf(
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0100000000000000000000000000000000000000000000000000000000000000",
            "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
            "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "0000000000000000000000000000000000000000000000000000000000000080",
            "0100000000000000000000000000000000000000000000000000000000000080",
        )
        for (h in lowOrderHexes) {
            try {
                KeysAndAuth.x25519SharedSecret(sk, KeysAndAuth.fromHex(h))
                fail("Expected low-order X25519 point $h to fail")
            } catch (_: CryptoException.AllZeroSharedKey) {
            }
        }

        // 2. Non-canonical Ed25519 S+L malleability & small-order public key rejection
        val dk = KeysAndAuth.deriveDeviceKeys(ByteArray(32) { 0x11 })
        val sig = KeysAndAuth.signDeviceCard(dk.signSeed, dk.kemPubBytes, 1700000000L)
        val orderL = BigInteger("1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed", 16)
        val sBe = ByteArray(32) { i -> sig[63 - i] }
        val sPlusLBe = BigInteger(1, sBe).add(orderL).toByteArray().let { raw ->
            if (raw.size == 33 && raw[0].toInt() == 0) raw.copyOfRange(1, 33) else raw
        }
        val malleableSig = sig.copyOf()
        for (i in 0 until 32) malleableSig[32 + i] = 0
        for (i in sPlusLBe.indices) {
            malleableSig[32 + i] = sPlusLBe[sPlusLBe.size - 1 - i]
        }
        try {
            KeysAndAuth.verifyDeviceCard(dk.deviceId, dk.signPub, dk.kemPubBytes, 1700000000L, malleableSig)
            fail("Expected S+L non-canonical Ed25519 signature to fail")
        } catch (_: CryptoException.InvalidSignature) {
        }

        val smallOrderEdPk = KeysAndAuth.fromHex("0100000000000000000000000000000000000000000000000000000000000000")
        assertFalse(KeysAndAuth.ed25519VerifyStrict(smallOrderEdPk, ByteArray(10), ByteArray(64)))

        // 3. CanonicalRelayOrigin IPv6 RFC 5952 + IPv4-mapped IPv6 + no secret leak
        assertEquals("http://[::1]:8080", KeysAndAuth.canonicalRelayOrigin("http://[0:0:0:0:0:0:0:1]:8080/"))
        assertEquals("http://[::ffff:127.0.0.1]:8080", KeysAndAuth.canonicalRelayOrigin("http://[::ffff:127.0.0.1]:8080"))
        assertEquals("https://[2001:db8::1]:8443", KeysAndAuth.canonicalRelayOrigin("https://[2001:0db8:0:0:0:0:0:1]:8443"))
        try {
            KeysAndAuth.canonicalRelayOrigin("https://admin:SUPER_SECRET@relay.example.com:443#k=TOP_SECRET")
            fail("Expected userinfo/fragment URL rejection")
        } catch (e: CryptoException.InvalidRelayUrl) {
            assertFalse(e.message.orEmpty().contains("SECRET"))
        }

        // 4. Multi-pin URI roundtrip & Redact
        val pin1 = "a".repeat(64)
        val pin2 = "b".repeat(64)
        val relayUri = "synctool://relay?v=1&u=https%3A%2F%2F43.155.231.14%3A54843&pin=${pin1.uppercase()},$pin2#k=${"K".repeat(43)}"
        val parsedRelay = SyncUri.parseRelayUri(relayUri)
        assertEquals(listOf(pin1, pin2), parsedRelay.spkiPins)
        assertEquals(pin1, parsedRelay.spkiPin)
        assertFalse(parsedRelay.toString().contains("KKKKKKKK"))
        assertFalse(Redact.redactMessage("failed on $relayUri").contains("KKKKKKKK"))

        val pairOffer = PairOffer(
            roomId = "K7M9P2XQ",
            mode = 1,
            purpose = "pair",
            endpoint = "https://43.155.231.14:54843",
            spkiPins = listOf(pin1, pin2),
            oobSecret = ByteArray(16) { 0x55 },
            accessKey = "A".repeat(43),
        )
        val formattedPair = SyncUri.formatPairUri(pairOffer)
        val reparsedPair = SyncUri.parsePairUri(formattedPair)
        assertEquals(listOf(pin1, pin2), reparsedPair.spkiPins)
        assertEquals(pin1, reparsedPair.spkiPin)

        // 5. ST-P0-2 sawFinal post-final block injection guard
        val sc = StreamCipher(ByteArray(32) { 1 }, ByteArray(7) { 2 }, ByteArray(16) { 3 }, 1)
        val finalBlk0 = sc.sealBlockAt(0u, isFinal = true, plaintext = byteArrayOf(0x42))
        val forgedBlk1 = sc.sealBlockAt(1u, isFinal = false, plaintext = ByteArray(StreamCipher.CHUNK_PLAINTEXT_MAX))
        val maliciousConcat = finalBlk0 + forgedBlk1
        try {
            decryptChunkBufferInto(
                sc = sc,
                chunkBytes = maliciousConcat,
                startBlockIdx = 0u,
                totalBlocks = 1u,
                isLastTransportChunk = true,
                alreadySawFinal = false,
                sink = ByteArrayOutputStream(),
            )
            fail("Expected ST-P0-2 post-final block injection to fail")
        } catch (se: SyncError) {
            assertTrue(se.code == ErrorCode.ERR_STREAM_TRUNCATED || se.code == ErrorCode.ERR_CRYPTO_DECRYPT_FAILED)
        }

        // 6. MemoryKeyStore LocalMetaKey AES-GCM cache encryption roundtrip
        val ks = MemoryKeyStore()
        val m = Manifest(
            msgId = "9f86d081884c7d659a2feaa0c55ad015",
            appId = "com.yellowdking.gravityssh",
            schema = "gravityssh.vault.v1",
            createdAt = 1764246000L,
            sender = SenderInfo(deviceId = dk.deviceId, label = "Desktop"),
            blobs = emptyList(),
        )
        ks.putCachedManifest(
            CachedManifestEntry(
                itemId = "itm_test",
                cachedAt = 1764246000L,
                expiresAt = 1764332400L,
                manifestSha256 = "33".repeat(32),
                manifest = m,
            )
        )
        val loaded = ks.getCachedManifest("itm_test")
        assertNotNull(loaded)
        assertEquals(m.msgId, loaded!!.manifest.msgId)
        ks.pruneCachedManifests(emptySet())
        assertNull(ks.getCachedManifest("itm_test"))
        dk.zero()
        Unit
    }
}
