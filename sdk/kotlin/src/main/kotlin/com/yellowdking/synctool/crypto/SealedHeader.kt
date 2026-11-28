package com.yellowdking.synctool.crypto

import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets

class SealedHeaderSealOutput(
    val sealedHeader: ByteArray,
    val msgIdRaw: ByteArray,
    val part0Key: ByteArray,
    val part0NoncePrefix: ByteArray,
)

class SealedHeaderOpenResult(
    val msgIdRaw: ByteArray,
    val msgId: String,
    val ephemeralPk: ByteArray,
    val senderDeviceIdRaw: ByteArray,
    val senderDeviceId: String,
    val recipientIdRaw: ByteArray,
    val recipientDeviceId: String,
    val createdAt: Long,
    val manifestSha256: ByteArray,
    val senderSig: ByteArray,
    val part0Key: ByteArray,
    val part0NoncePrefix: ByteArray,
) {
    fun zero() {
        KeysAndAuth.zeroBytes(part0Key, part0NoncePrefix)
    }
}

object SealedHeader {
    const val SEALED_HEADER_SIZE: Int = 208
    const val CLEAR_HEADER_SIZE: Int = 56
    const val SEALED_BOX_PLAINTEXT_SIZE: Int = 136
    const val SEALED_BOX_SIZE: Int = 152
    const val ZERO_RTT_SIG_INPUT_SIZE: Int = 149

    private val SEALED_HEADER_MAGIC = "ST01".toByteArray(StandardCharsets.US_ASCII)
    private const val SEALED_MODE_0RTT: Byte = 0x02

    private val INFO_0RTT_HDR_KEY = "synctool-v1/0rtt-hdr-key".toByteArray(StandardCharsets.UTF_8)
    private val INFO_0RTT_HDR_NONCE = "synctool-v1/0rtt-hdr-nonce".toByteArray(StandardCharsets.UTF_8)
    private val INFO_0RTT_PART0_KEY = "synctool-v1/0rtt-part0-key".toByteArray(StandardCharsets.UTF_8)
    private val INFO_0RTT_PART0_NP = "synctool-v1/0rtt-part0-np".toByteArray(StandardCharsets.UTF_8)
    private val PREFIX_0RTT_SIG = "synctool-v1/0rtt-sig\n".toByteArray(StandardCharsets.UTF_8)
    private val PREFIX_DIRECT_ACK = "synctool-v1/direct-ack".toByteArray(StandardCharsets.UTF_8)

    /**
     * Builds the exact 149-byte Ed25519 signing input (CRYPTO_AND_AUTH.md §5.2):
     * "synctool-v1/0rtt-sig\n"(21B) || clear_header(56B) || sender_id(16B) || recipient_id(16B) || uint64_be(created_at)(8B) || manifest_sha256(32B).
     */
    fun buildZeroRttSigInput(
        clearHeader56: ByteArray,
        senderIdRaw16: ByteArray,
        recipientIdRaw16: ByteArray,
        createdAt: Long,
        manifestSha256: ByteArray,
    ): ByteArray {
        if (clearHeader56.size != CLEAR_HEADER_SIZE) throw CryptoException.InvalidSealedHeader()
        if (senderIdRaw16.size != 16 || recipientIdRaw16.size != 16 || manifestSha256.size != 32) {
            throw CryptoException.InvalidKeyLength()
        }
        if (createdAt < 0L) {
            throw IllegalArgumentException("created_at must be non-negative")
        }
        val buf = ByteBuffer.allocate(ZERO_RTT_SIG_INPUT_SIZE)
        buf.put(PREFIX_0RTT_SIG)
        buf.put(clearHeader56)
        buf.put(senderIdRaw16)
        buf.put(recipientIdRaw16)
        buf.putLong(createdAt)
        buf.put(manifestSha256)
        return buf.array()
    }

    fun seal0RttHeader(
        senderKeys: DeviceKeys,
        recipientIdRaw16: ByteArray,
        recipientKemPub32: ByteArray,
        createdAt: Long,
        manifestSha256: ByteArray,
    ): SealedHeaderSealOutput {
        val msgIdRaw = KeysAndAuth.randomBytes(16)
        val (ephSk, _) = KeysAndAuth.generateEphemeralX25519()
        return try {
            seal0RttHeaderDeterministic(
                senderKeys = senderKeys,
                ephemeralSk32 = ephSk,
                msgIdRaw16 = msgIdRaw,
                recipientIdRaw16 = recipientIdRaw16,
                recipientKemPub32 = recipientKemPub32,
                createdAt = createdAt,
                manifestSha256 = manifestSha256,
            )
        } finally {
            KeysAndAuth.zeroBytes(ephSk)
        }
    }

    fun seal0RttHeaderDeterministic(
        senderKeys: DeviceKeys,
        ephemeralSk32: ByteArray,
        msgIdRaw16: ByteArray,
        recipientIdRaw16: ByteArray,
        recipientKemPub32: ByteArray,
        createdAt: Long,
        manifestSha256: ByteArray,
    ): SealedHeaderSealOutput {
        if (ephemeralSk32.size != 32 || msgIdRaw16.size != 16 || recipientIdRaw16.size != 16 ||
            recipientKemPub32.size != 32 || manifestSha256.size != 32
        ) {
            throw CryptoException.InvalidKeyLength()
        }
        if (createdAt < 0L) {
            throw IllegalArgumentException("created_at must be non-negative")
        }

        val ephPk = KeysAndAuth.x25519PublicKeyFromPrivate(ephemeralSk32)
        val clearHdr = ByteArray(CLEAR_HEADER_SIZE)
        System.arraycopy(SEALED_HEADER_MAGIC, 0, clearHdr, 0, 4)
        clearHdr[4] = SEALED_MODE_0RTT
        clearHdr[5] = 0x00 // flags
        clearHdr[6] = 0x00
        clearHdr[7] = 0x00
        System.arraycopy(msgIdRaw16, 0, clearHdr, 8, 16)
        System.arraycopy(ephPk, 0, clearHdr, 24, 32)

        val dh = KeysAndAuth.x25519SharedSecret(ephemeralSk32, recipientKemPub32)
        val keys = derive0RttKeys(clearHdr, dh)
        KeysAndAuth.zeroBytes(dh)

        var succeeded = false
        val boxPt = ByteArray(SEALED_BOX_PLAINTEXT_SIZE)
        try {
            val sigInput = buildZeroRttSigInput(
                clearHeader56 = clearHdr,
                senderIdRaw16 = senderKeys.deviceIdRaw,
                recipientIdRaw16 = recipientIdRaw16,
                createdAt = createdAt,
                manifestSha256 = manifestSha256,
            )
            val senderSig = KeysAndAuth.ed25519Sign(senderKeys.signSeed, sigInput)

            val ptBuf = ByteBuffer.wrap(boxPt)
            ptBuf.put(senderKeys.deviceIdRaw)
            ptBuf.put(recipientIdRaw16)
            ptBuf.putLong(createdAt)
            ptBuf.put(manifestSha256)
            ptBuf.put(senderSig)

            val sealedBox = KeysAndAuth.aesGcmSeal(keys.hdrKey, keys.hdrNonce, boxPt, clearHdr)
            val sealedHdr = ByteArray(SEALED_HEADER_SIZE)
            System.arraycopy(clearHdr, 0, sealedHdr, 0, CLEAR_HEADER_SIZE)
            System.arraycopy(sealedBox, 0, sealedHdr, CLEAR_HEADER_SIZE, SEALED_BOX_SIZE)
            succeeded = true
            return SealedHeaderSealOutput(
                sealedHeader = sealedHdr,
                msgIdRaw = msgIdRaw16.copyOf(),
                part0Key = keys.part0Key,
                part0NoncePrefix = keys.part0Np,
            )
        } finally {
            KeysAndAuth.zeroBytes(keys.hdrKey, keys.hdrNonce, boxPt)
            if (!succeeded) {
                KeysAndAuth.zeroBytes(keys.part0Key, keys.part0Np)
            }
        }
    }

    fun parseClearHeaderMsgId(sealedHeader: ByteArray): Pair<ByteArray, String> {
        if (sealedHeader.size != SEALED_HEADER_SIZE) {
            throw CryptoException.InvalidSealedHeader()
        }
        if (sealedHeader[0] != SEALED_HEADER_MAGIC[0] ||
            sealedHeader[1] != SEALED_HEADER_MAGIC[1] ||
            sealedHeader[2] != SEALED_HEADER_MAGIC[2] ||
            sealedHeader[3] != SEALED_HEADER_MAGIC[3] ||
            sealedHeader[4] != SEALED_MODE_0RTT ||
            sealedHeader[5] != 0x00.toByte() ||
            sealedHeader[6] != 0x00.toByte() ||
            sealedHeader[7] != 0x00.toByte()
        ) {
            throw CryptoException.InvalidSealedHeader()
        }
        val id = sealedHeader.copyOfRange(8, 24)
        return id to KeysAndAuth.toLowerHex(id)
    }

    fun open0RttHeader(
        recipientKeys: DeviceKeys,
        sealedHeader: ByteArray,
        lookupSenderSignPk: (senderDeviceId: String) -> ByteArray?,
    ): SealedHeaderOpenResult {
        val (msgIdRaw, msgIdHex) = parseClearHeaderMsgId(sealedHeader)
        val clearHdr = sealedHeader.copyOfRange(0, CLEAR_HEADER_SIZE)
        val sealedBox = sealedHeader.copyOfRange(CLEAR_HEADER_SIZE, SEALED_HEADER_SIZE)
        val ephPub = clearHdr.copyOfRange(24, 56)

        val dh = KeysAndAuth.x25519SharedSecret(recipientKeys.kemPrivBytes, ephPub)
        val keys = derive0RttKeys(clearHdr, dh)
        KeysAndAuth.zeroBytes(dh)

        var boxPt: ByteArray? = null
        var succeeded = false
        try {
            boxPt = KeysAndAuth.aesGcmOpen(keys.hdrKey, keys.hdrNonce, sealedBox, clearHdr)
            if (boxPt.size != SEALED_BOX_PLAINTEXT_SIZE) {
                throw CryptoException.InvalidSealedHeader()
            }

            val senderIdRaw = boxPt.copyOfRange(0, 16)
            val recipIdRaw = boxPt.copyOfRange(16, 32)
            val createdAt = ByteBuffer.wrap(boxPt, 32, 8).long
            // Unsigned uint64 > Long.MAX_VALUE wraps negative in signed Long
            if (createdAt < 0L) {
                throw CryptoException.InvalidSealedHeader("created_at overflow (> MaxInt64)")
            }
            val manifestSha = boxPt.copyOfRange(40, 72)
            val senderSig = boxPt.copyOfRange(72, 136)

            if (!KeysAndAuth.constantTimeEquals(recipIdRaw, recipientKeys.deviceIdRaw)) {
                throw CryptoException.RecipientMismatch()
            }

            val senderIdHex = KeysAndAuth.toLowerHex(senderIdRaw)
            val senderSignPk = lookupSenderSignPk(senderIdHex)
                ?: throw CryptoException.UntrustedSender()
            if (senderSignPk.size != 32) {
                throw CryptoException.UntrustedSender()
            }
            // Defense-in-depth: ensure sender_device_id matches senderSignPk derivation
            val (_, derivedSenderId) = KeysAndAuth.deriveDeviceId(senderSignPk)
            if (!KeysAndAuth.constantTimeEquals(
                    senderIdHex.toByteArray(StandardCharsets.US_ASCII),
                    derivedSenderId.toByteArray(StandardCharsets.US_ASCII)
                )
            ) {
                throw CryptoException.InvalidSignature("sender_device_id does not match sender sign_pk")
            }

            val sigInput = buildZeroRttSigInput(clearHdr, senderIdRaw, recipIdRaw, createdAt, manifestSha)
            if (!KeysAndAuth.ed25519VerifyStrict(senderSignPk, sigInput, senderSig)) {
                throw CryptoException.InvalidSignature()
            }

            succeeded = true
            return SealedHeaderOpenResult(
                msgIdRaw = msgIdRaw,
                msgId = msgIdHex,
                ephemeralPk = ephPub,
                senderDeviceIdRaw = senderIdRaw,
                senderDeviceId = senderIdHex,
                recipientIdRaw = recipIdRaw,
                recipientDeviceId = KeysAndAuth.toLowerHex(recipIdRaw),
                createdAt = createdAt,
                manifestSha256 = manifestSha,
                senderSig = senderSig,
                part0Key = keys.part0Key,
                part0NoncePrefix = keys.part0Np,
            )
        } finally {
            KeysAndAuth.zeroBytes(keys.hdrKey, keys.hdrNonce, boxPt)
            if (!succeeded) {
                KeysAndAuth.zeroBytes(keys.part0Key, keys.part0Np)
            }
        }
    }

    private class Derived0RttKeys(
        val hdrKey: ByteArray,
        val hdrNonce: ByteArray,
        val part0Key: ByteArray,
        val part0Np: ByteArray,
    )

    private fun derive0RttKeys(clearHdr: ByteArray, dh: ByteArray): Derived0RttKeys {
        val prk = KeysAndAuth.hkdfExtract(clearHdr, dh)
        try {
            return Derived0RttKeys(
                hdrKey = KeysAndAuth.hkdfExpand(prk, INFO_0RTT_HDR_KEY, 32),
                hdrNonce = KeysAndAuth.hkdfExpand(prk, INFO_0RTT_HDR_NONCE, 12),
                part0Key = KeysAndAuth.hkdfExpand(prk, INFO_0RTT_PART0_KEY, 32),
                part0Np = KeysAndAuth.hkdfExpand(prk, INFO_0RTT_PART0_NP, 7),
            )
        } finally {
            KeysAndAuth.zeroBytes(prk)
        }
    }

    fun computeDirectAckMac(part0Key32: ByteArray, msgIdRaw16: ByteArray): ByteArray {
        if (part0Key32.size != 32 || msgIdRaw16.size != 16) throw CryptoException.InvalidKeyLength()
        return KeysAndAuth.hmacSha256(part0Key32, PREFIX_DIRECT_ACK, msgIdRaw16)
    }

    fun verifyDirectAckMac(part0Key32: ByteArray, msgIdRaw16: ByteArray, gotMac: ByteArray) {
        val expected = computeDirectAckMac(part0Key32, msgIdRaw16)
        try {
            if (!KeysAndAuth.constantTimeEquals(expected, gotMac)) {
                throw CryptoException.MacMismatch()
            }
        } finally {
            KeysAndAuth.zeroBytes(expected)
        }
    }
}
