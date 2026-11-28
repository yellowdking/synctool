package com.yellowdking.synctool.crypto

import java.io.InputStream
import java.io.OutputStream
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets

class StreamCipher(
    encKey32: ByteArray,
    noncePrefix7: ByteArray,
    msgIdRaw16: ByteArray,
    val partId: Int,
) {
    private val encKey: ByteArray
    private val noncePrefix: ByteArray
    private val msgIdRaw: ByteArray

    init {
        if (partId < 0 || partId > MAX_PART_ID) {
            throw CryptoException.InvalidPartId()
        }
        if (encKey32.size != 32 || noncePrefix7.size != 7 || msgIdRaw16.size != 16) {
            throw CryptoException.InvalidKeyLength()
        }
        encKey = encKey32.copyOf()
        noncePrefix = noncePrefix7.copyOf()
        msgIdRaw = msgIdRaw16.copyOf()
    }

    fun zero() {
        KeysAndAuth.zeroBytes(encKey, noncePrefix)
    }

    fun sealBlockAt(blockIdx: UInt, isFinal: Boolean, plaintext: ByteArray): ByteArray {
        if (plaintext.size > CHUNK_PLAINTEXT_MAX || (!isFinal && plaintext.size != CHUNK_PLAINTEXT_MAX)) {
            throw CryptoException.InvalidBlockSize()
        }
        val nonce = buildChunkNonce(noncePrefix, blockIdx, isFinal)
        val aad = buildChunkAad(msgIdRaw, partId, blockIdx, isFinal, plaintext.size)
        return KeysAndAuth.aesGcmSeal(encKey, nonce, plaintext, aad)
    }

    fun openBlockAt(blockIdx: UInt, isFinal: Boolean, ciphertext: ByteArray): ByteArray {
        if (ciphertext.size < AEAD_TAG_LEN || ciphertext.size > CHUNK_CIPHERTEXT_MAX) {
            throw CryptoException.InvalidBlockSize()
        }
        val ptLen = ciphertext.size - AEAD_TAG_LEN
        if (!isFinal && ptLen != CHUNK_PLAINTEXT_MAX) {
            throw CryptoException.InvalidBlockSize()
        }
        val nonce = buildChunkNonce(noncePrefix, blockIdx, isFinal)
        val aad = buildChunkAad(msgIdRaw, partId, blockIdx, isFinal, ptLen)
        return KeysAndAuth.aesGcmOpen(encKey, nonce, ciphertext, aad)
    }

    companion object {
        const val CHUNK_PLAINTEXT_MAX: Int = 65536
        const val AEAD_TAG_LEN: Int = 16
        const val CHUNK_CIPHERTEXT_MAX: Int = CHUNK_PLAINTEXT_MAX + AEAD_TAG_LEN // 65552
        const val CHUNK_AAD_LEN: Int = 46

        const val MANIFEST_PAD_BUCKET: Int = 4096
        const val MANIFEST_MAX_RAW_BYTES: Int = 131072
        const val MAX_MANIFEST_PADDED_BYTES: Int =
            ((4 + MANIFEST_MAX_RAW_BYTES + MANIFEST_PAD_BUCKET - 1) / MANIFEST_PAD_BUCKET) * MANIFEST_PAD_BUCKET // 135168
        const val MAX_MANIFEST_CIPHERTEXT_BYTES: Int = MAX_MANIFEST_PADDED_BYTES + 3 * AEAD_TAG_LEN // 135216
        const val MAX_PART_ID: Int = 63

        private val PREFIX_CHUNK_AAD = "synctool-chunk-v1".toByteArray(StandardCharsets.US_ASCII)
        private val INFO_BLOB_ENC_KEY = "synctool-v1/blob-enc-key".toByteArray(StandardCharsets.UTF_8)
        private val INFO_BLOB_NONCE_PFX = "synctool-v1/blob-nonce-prefix".toByteArray(StandardCharsets.UTF_8)

        fun deriveBlobPartKeys(msgIdRaw16: ByteArray, partId: Int, blobKey32: ByteArray): Pair<ByteArray, ByteArray> {
            if (partId <= 0 || partId > MAX_PART_ID) {
                throw CryptoException.InvalidPartId()
            }
            if (msgIdRaw16.size != 16 || blobKey32.size != 32) {
                throw CryptoException.InvalidKeyLength()
            }
            val salt = ByteBuffer.allocate(20)
                .put(msgIdRaw16)
                .putInt(partId)
                .array()
            val prk = KeysAndAuth.hkdfExtract(salt, blobKey32)
            try {
                val encKey = KeysAndAuth.hkdfExpand(prk, INFO_BLOB_ENC_KEY, 32)
                val np = KeysAndAuth.hkdfExpand(prk, INFO_BLOB_NONCE_PFX, 7)
                return encKey to np
            } finally {
                KeysAndAuth.zeroBytes(prk)
            }
        }

        /**
         * 12-byte deterministic STREAM nonce:
         * nonce_prefix(7B) || uint32_be(block_idx)(4B) || uint8(is_final)(1B).
         */
        fun buildChunkNonce(noncePrefix7: ByteArray, blockIdx: UInt, isFinal: Boolean): ByteArray {
            if (noncePrefix7.size != 7) throw CryptoException.InvalidKeyLength()
            val buf = ByteBuffer.allocate(12)
            buf.put(noncePrefix7)
            buf.putInt(blockIdx.toInt())
            buf.put(if (isFinal) 0x01.toByte() else 0x00.toByte())
            return buf.array()
        }

        /**
         * Exact 46-byte binary STREAM AAD:
         * "synctool-chunk-v1"(17B) || msg_id(16B) || uint32_be(part_id)(4B) ||
         * uint32_be(block_idx)(4B) || uint8(is_final)(1B) || uint32_be(plaintext_len)(4B).
         */
        fun buildChunkAad(
            msgIdRaw16: ByteArray,
            partId: Int,
            blockIdx: UInt,
            isFinal: Boolean,
            plaintextLen: Int,
        ): ByteArray {
            if (msgIdRaw16.size != 16) throw CryptoException.InvalidKeyLength()
            val buf = ByteBuffer.allocate(CHUNK_AAD_LEN)
            buf.put(PREFIX_CHUNK_AAD)
            buf.put(msgIdRaw16)
            buf.putInt(partId)
            buf.putInt(blockIdx.toInt())
            buf.put(if (isFinal) 0x01.toByte() else 0x00.toByte())
            buf.putInt(plaintextLen)
            return buf.array()
        }

        fun totalBlocks(plaintextLen: Long): UInt {
            if (plaintextLen <= 0L) return 1u
            val blocks = ((plaintextLen.toULong() - 1uL) / CHUNK_PLAINTEXT_MAX.toULong()) + 1uL
            return if (blocks > UInt.MAX_VALUE.toULong()) UInt.MAX_VALUE else blocks.toUInt()
        }

        fun encryptedPartSize(plaintextLen: Long): Long {
            if (plaintextLen <= 0L) return AEAD_TAG_LEN.toLong()
            val blocks = ((plaintextLen.toULong() - 1uL) / CHUNK_PLAINTEXT_MAX.toULong()) + 1uL
            val overhead = blocks * AEAD_TAG_LEN.toULong()
            val maxLongU = Long.MAX_VALUE.toULong()
            if (overhead > maxLongU - plaintextLen.toULong()) {
                return Long.MAX_VALUE
            }
            return (plaintextLen.toULong() + overhead).toLong()
        }

        fun transportChunkCount(encryptedSize: Long, blocksPerChunk: Int): Int {
            val bpc = if (blocksPerChunk <= 0) 16 else blocksPerChunk
            if (encryptedSize <= 0L) return 1
            val chunkCap = bpc.toULong() * CHUNK_CIPHERTEXT_MAX.toULong()
            val chunks = ((encryptedSize.toULong() - 1uL) / chunkCap) + 1uL
            return if (chunks > Int.MAX_VALUE.toULong()) Int.MAX_VALUE else chunks.toInt()
        }

        fun sealBlock(
            encKey32: ByteArray,
            noncePrefix7: ByteArray,
            msgIdRaw16: ByteArray,
            partId: Int,
            blockIdx: UInt,
            isFinal: Boolean,
            plaintext: ByteArray,
        ): ByteArray {
            val sc = StreamCipher(encKey32, noncePrefix7, msgIdRaw16, partId)
            return try {
                sc.sealBlockAt(blockIdx, isFinal, plaintext)
            } finally {
                sc.zero()
            }
        }

        fun openBlock(
            encKey32: ByteArray,
            noncePrefix7: ByteArray,
            msgIdRaw16: ByteArray,
            partId: Int,
            blockIdx: UInt,
            isFinal: Boolean,
            ciphertext: ByteArray,
        ): ByteArray {
            val sc = StreamCipher(encKey32, noncePrefix7, msgIdRaw16, partId)
            return try {
                sc.openBlockAt(blockIdx, isFinal, ciphertext)
            } finally {
                sc.zero()
            }
        }

        fun encryptPartStream(
            input: InputStream,
            output: OutputStream,
            encKey32: ByteArray,
            noncePrefix7: ByteArray,
            msgIdRaw16: ByteArray,
            partId: Int,
            startBlockIdx: UInt = 0u,
        ): Pair<Long, Long> {
            val sc = StreamCipher(encKey32, noncePrefix7, msgIdRaw16, partId)
            try {
                return encryptPartStreamFrom(input, output, sc, startBlockIdx)
            } finally {
                sc.zero()
            }
        }

        internal fun encryptPartStreamFrom(
            input: InputStream,
            output: OutputStream,
            sc: StreamCipher,
            startBlockIdx: UInt,
        ): Pair<Long, Long> {
            val buf = ByteArray(CHUNK_PLAINTEXT_MAX + 1)
            var ptTotal = 0L
            var ctTotal = 0L
            var blockIdx = startBlockIdx
            var carry = 0
            try {
                while (true) {
                    val (n, eof) = readUpTo(input, buf, carry, buf.size - carry)
                    val have = carry + n
                    if (have == 0 && eof) {
                        val ct = sc.sealBlockAt(blockIdx, true, ByteArray(0))
                        output.write(ct)
                        ctTotal += ct.size
                        return ptTotal to ctTotal
                    }
                    if (have <= CHUNK_PLAINTEXT_MAX) {
                        val pt = buf.copyOfRange(0, have)
                        try {
                            val ct = sc.sealBlockAt(blockIdx, true, pt)
                            output.write(ct)
                            ptTotal += pt.size
                            ctTotal += ct.size
                            return ptTotal to ctTotal
                        } finally {
                            KeysAndAuth.zeroBytes(pt)
                        }
                    }
                    if (blockIdx == UInt.MAX_VALUE) {
                        throw CryptoException.StreamTooLarge()
                    }
                    val pt = buf.copyOfRange(0, CHUNK_PLAINTEXT_MAX)
                    try {
                        val ct = sc.sealBlockAt(blockIdx, false, pt)
                        output.write(ct)
                        ptTotal += pt.size
                        ctTotal += ct.size
                    } finally {
                        KeysAndAuth.zeroBytes(pt)
                    }
                    blockIdx++
                    buf[0] = buf[CHUNK_PLAINTEXT_MAX]
                    carry = 1
                }
            } finally {
                KeysAndAuth.zeroBytes(buf)
            }
        }

        fun decryptPartStream(
            input: InputStream,
            output: OutputStream,
            encKey32: ByteArray,
            noncePrefix7: ByteArray,
            msgIdRaw16: ByteArray,
            partId: Int,
            startBlockIdx: UInt = 0u,
        ): Long {
            val sc = StreamCipher(encKey32, noncePrefix7, msgIdRaw16, partId)
            try {
                return decryptPartStreamFrom(input, output, sc, startBlockIdx)
            } finally {
                sc.zero()
            }
        }

        internal fun decryptPartStreamFrom(
            input: InputStream,
            output: OutputStream,
            sc: StreamCipher,
            startBlockIdx: UInt,
        ): Long {
            val buf = ByteArray(CHUNK_CIPHERTEXT_MAX + 1)
            var ptTotal = 0L
            var blockIdx = startBlockIdx
            var carry = 0
            try {
                while (true) {
                    val (n, eof) = readUpTo(input, buf, carry, buf.size - carry)
                    val have = carry + n
                    if (have == 0 && eof) {
                        throw CryptoException.StreamTruncated()
                    }
                    if (have <= CHUNK_CIPHERTEXT_MAX) {
                        val ctSlice = buf.copyOfRange(0, have)
                        val pt = try {
                            sc.openBlockAt(blockIdx, true, ctSlice)
                        } catch (e: CryptoException) {
                            throw CryptoException.StreamTruncated("final stream block authentication failed", e)
                        }
                        try {
                            if (pt.isNotEmpty()) {
                                output.write(pt)
                                ptTotal += pt.size
                            }
                            return ptTotal
                        } finally {
                            KeysAndAuth.zeroBytes(pt)
                        }
                    }
                    if (blockIdx == UInt.MAX_VALUE) {
                        throw CryptoException.StreamTooLarge()
                    }
                    val ctSlice = buf.copyOfRange(0, CHUNK_CIPHERTEXT_MAX)
                    val pt = sc.openBlockAt(blockIdx, false, ctSlice)
                    try {
                        output.write(pt)
                        ptTotal += pt.size
                    } finally {
                        KeysAndAuth.zeroBytes(pt)
                    }
                    blockIdx++
                    buf[0] = buf[CHUNK_CIPHERTEXT_MAX]
                    carry = 1
                }
            } finally {
                KeysAndAuth.zeroBytes(buf)
            }
        }

        private fun readUpTo(input: InputStream, dst: ByteArray, offset: Int, len: Int): Pair<Int, Boolean> {
            var readTotal = 0
            while (readTotal < len) {
                val r = input.read(dst, offset + readTotal, len - readTotal)
                if (r < 0) {
                    return readTotal to true
                }
                readTotal += r
            }
            return readTotal to false
        }

        /**
         * Wraps raw Manifest UTF-8 JSON bytes into minimal 4 KiB-aligned padded plaintext:
         * uint32_be(L) || manifest_utf8_bytes(L) || (0x00 * pad_len).
         */
        fun padManifest(raw: ByteArray): ByteArray {
            val l = raw.size
            if (l <= 0 || l > MANIFEST_MAX_RAW_BYTES) {
                throw CryptoException.InvalidPadding()
            }
            val need = 4 + l
            val totalLen = ((need + MANIFEST_PAD_BUCKET - 1) / MANIFEST_PAD_BUCKET) * MANIFEST_PAD_BUCKET
            val out = ByteArray(totalLen)
            ByteBuffer.wrap(out, 0, 4).putInt(l)
            System.arraycopy(raw, 0, out, 4, l)
            return out
        }

        /**
         * Validates exact minimal 4 KiB bucket alignment, length prefix, and constant-time all-zero tail padding.
         */
        fun unpadManifest(padded: ByteArray): ByteArray {
            if (padded.size < MANIFEST_PAD_BUCKET || padded.size % MANIFEST_PAD_BUCKET != 0) {
                throw CryptoException.InvalidPadding()
            }
            val lLong = ByteBuffer.wrap(padded, 0, 4).int.toLong() and 0xffff_ffffL
            if (lLong <= 0L || lLong > MANIFEST_MAX_RAW_BYTES.toLong() || (4L + lLong) > padded.size.toLong()) {
                throw CryptoException.InvalidPadding()
            }
            val l = lLong.toInt()
            val expectedTotal = ((4 + l + MANIFEST_PAD_BUCKET - 1) / MANIFEST_PAD_BUCKET) * MANIFEST_PAD_BUCKET
            if (padded.size != expectedTotal) {
                throw CryptoException.InvalidPadding()
            }
            var nonZero = 0
            for (i in (4 + l) until padded.size) {
                nonZero = nonZero or (padded[i].toInt() and 0xff)
            }
            if (nonZero != 0) {
                throw CryptoException.InvalidPadding()
            }
            return padded.copyOfRange(4, 4 + l)
        }

        /**
         * Local metadata / manifest cache sealing using 32B LocalMetaKey (12B CSPRNG IV || AES-256-GCM ciphertext+tag).
         */
        fun sealLocalMeta(localMetaKey32: ByteArray, aad: ByteArray, plaintext: ByteArray): ByteArray {
            if (localMetaKey32.size != 32) throw CryptoException.InvalidKeyLength()
            val iv = KeysAndAuth.randomBytes(12)
            val ct = KeysAndAuth.aesGcmSeal(localMetaKey32, iv, plaintext, aad)
            return iv + ct
        }

        fun openLocalMeta(localMetaKey32: ByteArray, aad: ByteArray, sealedBlob: ByteArray): ByteArray {
            if (localMetaKey32.size != 32) throw CryptoException.InvalidKeyLength()
            if (sealedBlob.size < 12 + AEAD_TAG_LEN) {
                throw CryptoException.DecryptFailed("sealed local metadata too short")
            }
            val iv = sealedBlob.copyOfRange(0, 12)
            val ct = sealedBlob.copyOfRange(12, sealedBlob.size)
            return KeysAndAuth.aesGcmOpen(localMetaKey32, iv, ct, aad)
        }
    }
}
