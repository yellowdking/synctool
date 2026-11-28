package com.yellowdking.synctool.crypto

import java.security.SecureRandom

object Crockford {
    const val CROCKFORD_ALPHABET: String = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
    const val ROOM_ID_LENGTH: Int = 8
    const val ROOM_ID_RAW_BYTES: Int = 5

    private val decodeTable = IntArray(128) { -1 }.also { tbl ->
        for (i in CROCKFORD_ALPHABET.indices) {
            val c = CROCKFORD_ALPHABET[i]
            tbl[c.code] = i
            if (c in 'A'..'Z') {
                tbl[c.lowercaseChar().code] = i
            }
        }
        // Standard Crockford equivalences: O/o -> 0, I/i/L/l -> 1
        tbl['O'.code] = 0
        tbl['o'.code] = 0
        tbl['I'.code] = 1
        tbl['i'.code] = 1
        tbl['L'.code] = 1
        tbl['l'.code] = 1
    }

    private val csprng = SecureRandom()

    fun generateRoomId(): String {
        val raw = ByteArray(ROOM_ID_RAW_BYTES)
        csprng.nextBytes(raw)
        return encodeRoomId(raw)
    }

    fun encodeRoomId(raw: ByteArray): String {
        require(raw.size == ROOM_ID_RAW_BYTES) {
            "room_id raw input must be exactly $ROOM_ID_RAW_BYTES bytes"
        }
        var v = 0L
        for (i in 0 until ROOM_ID_RAW_BYTES) {
            v = (v shl 8) or (raw[i].toLong() and 0xffL)
        }
        val out = CharArray(ROOM_ID_LENGTH)
        for (i in ROOM_ID_LENGTH - 1 downTo 0) {
            out[i] = CROCKFORD_ALPHABET[(v and 0x1fL).toInt()]
            v = v ushr 5
        }
        return String(out)
    }

    fun normalizeRoomId(input: String): String {
        val out = CharArray(ROOM_ID_LENGTH)
        var n = 0
        for (i in input.indices) {
            val c = input[i]
            if (c == '-' || c == ' ' || c == '\t' || c == '\r' || c == '\n') {
                continue
            }
            if (c.code >= 128) {
                throw CryptoException.InvalidRoomId("non-ASCII character in room_id")
            }
            val v = decodeTable[c.code]
            if (v < 0) {
                throw CryptoException.InvalidRoomId("invalid Crockford Base32 character in room_id")
            }
            if (n >= ROOM_ID_LENGTH) {
                throw CryptoException.InvalidRoomId("room_id exceeds $ROOM_ID_LENGTH characters")
            }
            out[n] = CROCKFORD_ALPHABET[v]
            n++
        }
        if (n != ROOM_ID_LENGTH) {
            throw CryptoException.InvalidRoomId("room_id must be $ROOM_ID_LENGTH characters")
        }
        return String(out)
    }

    fun decodeRoomId(input: String): ByteArray {
        val norm = normalizeRoomId(input)
        var v = 0L
        for (i in 0 until ROOM_ID_LENGTH) {
            val digit = decodeTable[norm[i].code]
            v = (v shl 5) or digit.toLong()
        }
        val raw = ByteArray(ROOM_ID_RAW_BYTES)
        for (i in ROOM_ID_RAW_BYTES - 1 downTo 0) {
            raw[i] = (v and 0xffL).toByte()
            v = v ushr 8
        }
        return raw
    }

    fun formatRoomId(input: String): String {
        val norm = normalizeRoomId(input)
        return "${norm.substring(0, 4)}-${norm.substring(4, 8)}"
    }

    fun isCanonicalRoomId(s: String): Boolean {
        if (s.length != ROOM_ID_LENGTH) return false
        for (i in 0 until ROOM_ID_LENGTH) {
            val c = s[i]
            if (c.code >= 128 || CROCKFORD_ALPHABET.indexOf(c) < 0) {
                return false
            }
        }
        return true
    }

    /**
     * Computes Luhn-mod-32 check character over any canonical or normalizable Crockford Base32 string.
     */
    fun computeLuhnMod32CheckChar(input: String): Char {
        val cleaned = normalizeArbitraryCrockford(input)
        require(cleaned.isNotEmpty()) { "empty Crockford string" }
        var factor = 2
        var sum = 0
        for (i in cleaned.length - 1 downTo 0) {
            val codePoint = decodeTable[cleaned[i].code]
            var addend = factor * codePoint
            factor = if (factor == 2) 1 else 2
            addend = (addend / 32) + (addend % 32)
            sum += addend
        }
        val remainder = sum % 32
        val checkCodePoint = (32 - remainder) % 32
        return CROCKFORD_ALPHABET[checkCodePoint]
    }

    fun appendLuhnMod32(input: String): String {
        val cleaned = normalizeArbitraryCrockford(input)
        return cleaned + computeLuhnMod32CheckChar(cleaned)
    }

    fun verifyLuhnMod32(inputWithCheck: String): Boolean {
        val cleaned = try {
            normalizeArbitraryCrockford(inputWithCheck)
        } catch (_: Exception) {
            return false
        }
        if (cleaned.length < 2) return false
        val body = cleaned.substring(0, cleaned.length - 1)
        val expected = computeLuhnMod32CheckChar(body)
        return cleaned.last() == expected
    }

    private fun normalizeArbitraryCrockford(input: String): String {
        val sb = StringBuilder(input.length)
        for (c in input) {
            if (c == '-' || c == ' ' || c == '\t' || c == '\r' || c == '\n') continue
            if (c.code >= 128) throw CryptoException.InvalidRoomId("non-ASCII character")
            val v = decodeTable[c.code]
            if (v < 0) throw CryptoException.InvalidRoomId("invalid Crockford character")
            sb.append(CROCKFORD_ALPHABET[v])
        }
        return sb.toString()
    }
}
