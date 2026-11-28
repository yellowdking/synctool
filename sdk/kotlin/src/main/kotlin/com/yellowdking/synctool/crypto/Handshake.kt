package com.yellowdking.synctool.crypto

import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.util.Locale

class HandshakeResult(
    val th: ByteArray,
    val prk: ByteArray,
    val sessionKey: ByteArray,
    val confirmKeyA: ByteArray,
    val confirmKeyB: ByteArray,
    val macA: ByteArray,
    val macB: ByteArray,
    val sasBytes: ByteArray = ByteArray(4),
    val sasInt: Int = 0,
    val sasStr: String = "",
) {
    fun zero() {
        KeysAndAuth.zeroBytes(prk, sessionKey, confirmKeyA, confirmKeyB, sasBytes)
    }
}

object Handshake {
    const val PROTO_VERSION: Int = 1

    const val MODE_DIRECT: Int = 0
    const val MODE_QR_OOB: Int = 1
    const val MODE_COMMIT_SAS: Int = 2

    const val PURPOSE_DIRECT: String = "direct"
    const val PURPOSE_ONESHOT: String = "oneshot"
    const val PURPOSE_PAIR: String = "pair"

    const val PURPOSE_CODE_ONESHOT: Byte = 0x01
    const val PURPOSE_CODE_PAIR: Byte = 0x02

    const val OOB_SECRET_SIZE: Int = 16
    const val HS_NONCE_SIZE: Int = 32

    private val PREFIX_HS_QR = "synctool-v1/hs-qr".toByteArray(StandardCharsets.UTF_8)
    private val PREFIX_COMMIT = "synctool-v1/commit".toByteArray(StandardCharsets.UTF_8)
    private val PREFIX_HS_SAS = "synctool-v1/hs-sas".toByteArray(StandardCharsets.UTF_8)
    private val INFO_SESSION_KEY = "synctool-v1/session-key".toByteArray(StandardCharsets.UTF_8)
    private val INFO_CONFIRM_A = "synctool-v1/confirm-a".toByteArray(StandardCharsets.UTF_8)
    private val INFO_CONFIRM_B = "synctool-v1/confirm-b".toByteArray(StandardCharsets.UTF_8)
    private val INFO_SAS = "synctool-v1/sas".toByteArray(StandardCharsets.UTF_8)
    private val INFO_ONESHOT_PART0_KEY = "synctool-v1/oneshot-part0-key".toByteArray(StandardCharsets.UTF_8)
    private val INFO_ONESHOT_PART0_NP = "synctool-v1/oneshot-part0-np".toByteArray(StandardCharsets.UTF_8)
    private val INFO_PIPE_CTRL_KEY = "synctool-v1/pipe-ctrl-key".toByteArray(StandardCharsets.UTF_8)
    private val INFO_PIPE_CTRL_NP = "synctool-v1/pipe-ctrl-np".toByteArray(StandardCharsets.UTF_8)
    private val PREFIX_PIPE_CTRL_AAD = "synctool-v1/pipe-ctrl".toByteArray(StandardCharsets.UTF_8)
    private val INFO_PAIR_NONCE_A = "synctool-v1/pair-nonce-a".toByteArray(StandardCharsets.UTF_8)
    private val INFO_PAIR_NONCE_B = "synctool-v1/pair-nonce-b".toByteArray(StandardCharsets.UTF_8)
    private val PREFIX_PAIR_BIND_A = "synctool-v1/pair-bind/a".toByteArray(StandardCharsets.UTF_8)
    private val PREFIX_PAIR_BIND_B = "synctool-v1/pair-bind/b".toByteArray(StandardCharsets.UTF_8)

    fun purposeCode(purpose: String): Byte = when (purpose) {
        PURPOSE_ONESHOT -> PURPOSE_CODE_ONESHOT
        PURPOSE_PAIR -> PURPOSE_CODE_PAIR
        else -> throw CryptoException.InvalidPurpose("invalid handshake purpose: $purpose")
    }

    /**
     * Constructs the exact 154-byte ordered transcript_1 for Flow 1A (mode=1, qr_oob_x25519):
     * "synctool-v1/hs-qr"(17B) || purpose_code(1B) || room_id(8B) || E_a(32B) || n_a(32B) || E_b(32B) || n_b(32B).
     * Strictly ordered E_a || n_a || E_b || n_b — NEVER sorted!
     */
    fun buildQrTranscript(
        purpose: String,
        roomId: String,
        eAPub: ByteArray,
        nA: ByteArray,
        eBPub: ByteArray,
        nB: ByteArray,
    ): ByteArray {
        val pCode = purposeCode(purpose)
        if (!Crockford.isCanonicalRoomId(roomId)) {
            throw CryptoException.InvalidRoomId()
        }
        if (eAPub.size != 32 || nA.size != HS_NONCE_SIZE || eBPub.size != 32 || nB.size != HS_NONCE_SIZE) {
            throw CryptoException.InvalidKeyLength()
        }
        val buf = ByteBuffer.allocate(154)
        buf.put(PREFIX_HS_QR)
        buf.put(pCode)
        buf.put(roomId.toByteArray(StandardCharsets.US_ASCII))
        buf.put(eAPub)
        buf.put(nA)
        buf.put(eBPub)
        buf.put(nB)
        return buf.array()
    }

    fun deriveQrOobSession(
        purpose: String,
        roomId: String,
        localPriv32: ByteArray,
        remotePub32: ByteArray,
        eAPub: ByteArray,
        nA: ByteArray,
        eBPub: ByteArray,
        nB: ByteArray,
        oobSecret: ByteArray,
    ): HandshakeResult {
        if (oobSecret.size != OOB_SECRET_SIZE) {
            throw CryptoException.InvalidOobSecret()
        }
        val shared = KeysAndAuth.x25519SharedSecret(localPriv32, remotePub32)
        val ikm = ByteArray(48)
        try {
            val transcript = buildQrTranscript(purpose, roomId, eAPub, nA, eBPub, nB)
            val th = KeysAndAuth.sha256(transcript)
            System.arraycopy(shared, 0, ikm, 0, 32)
            System.arraycopy(oobSecret, 0, ikm, 32, 16)
            val prk = KeysAndAuth.hkdfExtract(th, ikm)
            return buildSessionAndConfirm(th, prk, withSas = false)
        } finally {
            KeysAndAuth.zeroBytes(shared, ikm)
        }
    }

    /**
     * Computes exact 32-byte commitment for Flow 1B (mode=2, commit_sas_x25519):
     * SHA256("synctool-v1/commit"(18B) || purpose_code(1B) || room_id(8B) || E_a(32B) || n_a(32B)).
     */
    fun computeCommitA(
        purpose: String,
        roomId: String,
        eAPub: ByteArray,
        nA: ByteArray,
    ): ByteArray {
        val pCode = purposeCode(purpose)
        if (!Crockford.isCanonicalRoomId(roomId)) {
            throw CryptoException.InvalidRoomId()
        }
        if (eAPub.size != 32 || nA.size != HS_NONCE_SIZE) {
            throw CryptoException.InvalidKeyLength()
        }
        val buf = ByteBuffer.allocate(91)
        buf.put(PREFIX_COMMIT)
        buf.put(pCode)
        buf.put(roomId.toByteArray(StandardCharsets.US_ASCII))
        buf.put(eAPub)
        buf.put(nA)
        return KeysAndAuth.sha256(buf.array())
    }

    fun verifyCommitA(
        purpose: String,
        roomId: String,
        eAPub: ByteArray,
        nA: ByteArray,
        commitA: ByteArray,
    ) {
        if (commitA.size != 32) {
            throw CryptoException.CommitMismatch()
        }
        val expected = computeCommitA(purpose, roomId, eAPub, nA)
        if (!KeysAndAuth.constantTimeEquals(expected, commitA)) {
            throw CryptoException.CommitMismatch()
        }
    }

    /**
     * Constructs the exact 187-byte ordered transcript_2 for Flow 1B (mode=2, commit_sas_x25519):
     * "synctool-v1/hs-sas"(18B) || purpose_code(1B) || room_id(8B) || commit_a(32B) || E_a(32B) || n_a(32B) || E_b(32B) || n_b(32B).
     * Strictly ordered E_a || n_a || E_b || n_b — NEVER sorted!
     */
    fun buildSasTranscript(
        purpose: String,
        roomId: String,
        commitA: ByteArray,
        eAPub: ByteArray,
        nA: ByteArray,
        eBPub: ByteArray,
        nB: ByteArray,
    ): ByteArray {
        val pCode = purposeCode(purpose)
        if (!Crockford.isCanonicalRoomId(roomId)) {
            throw CryptoException.InvalidRoomId()
        }
        if (commitA.size != 32 || eAPub.size != 32 || nA.size != HS_NONCE_SIZE || eBPub.size != 32 || nB.size != HS_NONCE_SIZE) {
            throw CryptoException.InvalidKeyLength()
        }
        val buf = ByteBuffer.allocate(187)
        buf.put(PREFIX_HS_SAS)
        buf.put(pCode)
        buf.put(roomId.toByteArray(StandardCharsets.US_ASCII))
        buf.put(commitA)
        buf.put(eAPub)
        buf.put(nA)
        buf.put(eBPub)
        buf.put(nB)
        return buf.array()
    }

    fun deriveSasSession(
        purpose: String,
        roomId: String,
        localPriv32: ByteArray,
        remotePub32: ByteArray,
        commitA: ByteArray,
        eAPub: ByteArray,
        nA: ByteArray,
        eBPub: ByteArray,
        nB: ByteArray,
    ): HandshakeResult {
        verifyCommitA(purpose, roomId, eAPub, nA, commitA)
        val shared = KeysAndAuth.x25519SharedSecret(localPriv32, remotePub32)
        try {
            val transcript = buildSasTranscript(purpose, roomId, commitA, eAPub, nA, eBPub, nB)
            val th = KeysAndAuth.sha256(transcript)
            val prk = KeysAndAuth.hkdfExtract(th, shared)
            return buildSessionAndConfirm(th, prk, withSas = true)
        } finally {
            KeysAndAuth.zeroBytes(shared)
        }
    }

    private fun buildSessionAndConfirm(th: ByteArray, prk: ByteArray, withSas: Boolean): HandshakeResult {
        val sessionKey = KeysAndAuth.hkdfExpand(prk, INFO_SESSION_KEY, 32)
        val confirmKeyA = KeysAndAuth.hkdfExpand(prk, INFO_CONFIRM_A, 32)
        val confirmKeyB = KeysAndAuth.hkdfExpand(prk, INFO_CONFIRM_B, 32)
        val macA = KeysAndAuth.hmacSha256(confirmKeyA, th)
        val macB = KeysAndAuth.hmacSha256(confirmKeyB, th)
        if (!withSas) {
            return HandshakeResult(
                th = th,
                prk = prk,
                sessionKey = sessionKey,
                confirmKeyA = confirmKeyA,
                confirmKeyB = confirmKeyB,
                macA = macA,
                macB = macB,
            )
        }
        val sasBytes = KeysAndAuth.hkdfExpand(prk, INFO_SAS, 4)
        val uint32Val = ((sasBytes[0].toLong() and 0xffL) shl 24) or
            ((sasBytes[1].toLong() and 0xffL) shl 16) or
            ((sasBytes[2].toLong() and 0xffL) shl 8) or
            (sasBytes[3].toLong() and 0xffL)
        val sasInt = (uint32Val % 1_000_000L).toInt()
        val sasStr = String.format(Locale.ROOT, "%06d", sasInt)
        return HandshakeResult(
            th = th,
            prk = prk,
            sessionKey = sessionKey,
            confirmKeyA = confirmKeyA,
            confirmKeyB = confirmKeyB,
            macA = macA,
            macB = macB,
            sasBytes = sasBytes,
            sasInt = sasInt,
            sasStr = sasStr,
        )
    }

    fun verifyMac(expected32: ByteArray, got: ByteArray) {
        if (expected32.size != 32 || !KeysAndAuth.constantTimeEquals(expected32, got)) {
            throw CryptoException.MacMismatch()
        }
    }

    fun verifySas(expected6Digits: String, entered: String) {
        val clean = ByteArray(6)
        var n = 0
        for (c in entered) {
            if (c == ' ' || c == '-' || c == '\t' || c == '\r' || c == '\n') continue
            if (c !in '0'..'9' || n >= 6) {
                throw CryptoException.SasMismatch()
            }
            clean[n] = c.code.toByte()
            n++
        }
        if (n != 6 || expected6Digits.length != 6) {
            throw CryptoException.SasMismatch()
        }
        if (!KeysAndAuth.constantTimeEquals(expected6Digits.toByteArray(StandardCharsets.US_ASCII), clean)) {
            throw CryptoException.SasMismatch()
        }
    }

    fun deriveOneshotPart0Keys(sessionKey32: ByteArray, msgId16: ByteArray): Pair<ByteArray, ByteArray> {
        if (sessionKey32.size != 32 || msgId16.size != KeysAndAuth.MSG_ID_RAW_SIZE) {
            throw CryptoException.InvalidKeyLength()
        }
        val prk = KeysAndAuth.hkdfExtract(msgId16, sessionKey32)
        try {
            val part0Key = KeysAndAuth.hkdfExpand(prk, INFO_ONESHOT_PART0_KEY, 32)
            val part0Np = KeysAndAuth.hkdfExpand(prk, INFO_ONESHOT_PART0_NP, 7)
            return part0Key to part0Np
        } finally {
            KeysAndAuth.zeroBytes(prk)
        }
    }

    fun derivePipeCtrlKeys(th32: ByteArray, sessionKey32: ByteArray): Pair<ByteArray, ByteArray> {
        if (th32.size != 32 || sessionKey32.size != 32) {
            throw CryptoException.InvalidKeyLength()
        }
        val prk = KeysAndAuth.hkdfExtract(th32, sessionKey32)
        try {
            val ctrlKey = KeysAndAuth.hkdfExpand(prk, INFO_PIPE_CTRL_KEY, 32)
            val ctrlNp = KeysAndAuth.hkdfExpand(prk, INFO_PIPE_CTRL_NP, 7)
            return ctrlKey to ctrlNp
        } finally {
            KeysAndAuth.zeroBytes(prk)
        }
    }

    fun validatePipeCtrlSeq(ctrlSeq: Long, fromInitiator: Boolean, lastSeenSeq: Long) {
        if (ctrlSeq < 0L || ctrlSeq > 0xffff_ffffL) {
            throw CryptoException.InvalidCtrlSeq()
        }
        val wantParity = if (fromInitiator) 0L else 1L
        if ((ctrlSeq and 1L) != wantParity || ctrlSeq <= lastSeenSeq) {
            throw CryptoException.InvalidCtrlSeq()
        }
    }

    /**
     * Exact 57-byte AAD: "synctool-v1/pipe-ctrl"(21B) || th(32B) || uint32_be(ctrl_seq)(4B).
     */
    fun buildPipeCtrlAad(th32: ByteArray, ctrlSeq: Long): ByteArray {
        if (th32.size != 32) throw CryptoException.InvalidKeyLength()
        if (ctrlSeq < 0L || ctrlSeq > 0xffff_ffffL) throw CryptoException.InvalidCtrlSeq()
        val buf = ByteBuffer.allocate(57)
        buf.put(PREFIX_PIPE_CTRL_AAD)
        buf.put(th32)
        buf.putInt(ctrlSeq.toInt())
        return buf.array()
    }

    fun sealPipeCtrl(
        ctrlKey32: ByteArray,
        ctrlNp7: ByteArray,
        th32: ByteArray,
        ctrlSeq: Long,
        plaintext: ByteArray,
    ): ByteArray {
        if (ctrlKey32.size != 32 || ctrlNp7.size != 7) throw CryptoException.InvalidKeyLength()
        val aad = buildPipeCtrlAad(th32, ctrlSeq)
        val nonce = ByteBuffer.allocate(12)
            .put(ctrlNp7)
            .putInt(ctrlSeq.toInt())
            .put(0x00.toByte())
            .array()
        try {
            return KeysAndAuth.aesGcmSeal(ctrlKey32, nonce, plaintext, aad)
        } finally {
            KeysAndAuth.zeroBytes(nonce)
        }
    }

    fun openPipeCtrl(
        ctrlKey32: ByteArray,
        ctrlNp7: ByteArray,
        th32: ByteArray,
        ctrlSeq: Long,
        ciphertext: ByteArray,
    ): ByteArray {
        if (ctrlKey32.size != 32 || ctrlNp7.size != 7) throw CryptoException.InvalidKeyLength()
        val aad = buildPipeCtrlAad(th32, ctrlSeq)
        val nonce = ByteBuffer.allocate(12)
            .put(ctrlNp7)
            .putInt(ctrlSeq.toInt())
            .put(0x00.toByte())
            .array()
        try {
            return KeysAndAuth.aesGcmOpen(ctrlKey32, nonce, ciphertext, aad)
        } finally {
            KeysAndAuth.zeroBytes(nonce)
        }
    }

    fun openPipeCtrlVerified(
        ctrlKey32: ByteArray,
        ctrlNp7: ByteArray,
        th32: ByteArray,
        ctrlSeq: Long,
        fromInitiator: Boolean,
        lastSeenSeq: Long,
        ciphertext: ByteArray,
    ): ByteArray {
        validatePipeCtrlSeq(ctrlSeq, fromInitiator, lastSeenSeq)
        return openPipeCtrl(ctrlKey32, ctrlNp7, th32, ctrlSeq, ciphertext)
    }

    fun derivePairBindNonces(prk32: ByteArray): Pair<ByteArray, ByteArray> {
        if (prk32.size != 32) throw CryptoException.InvalidKeyLength()
        val nonceA = KeysAndAuth.hkdfExpand(prk32, INFO_PAIR_NONCE_A, 12)
        val nonceB = KeysAndAuth.hkdfExpand(prk32, INFO_PAIR_NONCE_B, 12)
        return nonceA to nonceB
    }

    fun sealPairBind(
        sessionKey32: ByteArray,
        prk32: ByteArray,
        th32: ByteArray,
        isInitiator: Boolean,
        plaintext: ByteArray,
    ): ByteArray {
        if (sessionKey32.size != 32 || th32.size != 32) throw CryptoException.InvalidKeyLength()
        val (na, nb) = derivePairBindNonces(prk32)
        try {
            val nonce = if (isInitiator) na else nb
            val prefix = if (isInitiator) PREFIX_PAIR_BIND_A else PREFIX_PAIR_BIND_B
            val aad = prefix + th32
            return KeysAndAuth.aesGcmSeal(sessionKey32, nonce, plaintext, aad)
        } finally {
            KeysAndAuth.zeroBytes(na, nb)
        }
    }

    fun openPairBind(
        sessionKey32: ByteArray,
        prk32: ByteArray,
        th32: ByteArray,
        fromInitiator: Boolean,
        ciphertext: ByteArray,
    ): ByteArray {
        if (sessionKey32.size != 32 || th32.size != 32) throw CryptoException.InvalidKeyLength()
        val (na, nb) = derivePairBindNonces(prk32)
        try {
            val nonce = if (fromInitiator) na else nb
            val prefix = if (fromInitiator) PREFIX_PAIR_BIND_A else PREFIX_PAIR_BIND_B
            val aad = prefix + th32
            return KeysAndAuth.aesGcmOpen(sessionKey32, nonce, ciphertext, aad)
        } finally {
            KeysAndAuth.zeroBytes(na, nb)
        }
    }
}
