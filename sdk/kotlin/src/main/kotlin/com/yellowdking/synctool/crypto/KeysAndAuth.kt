package com.yellowdking.synctool.crypto

import java.math.BigInteger
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.URI
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.security.GeneralSecurityException
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import org.bouncycastle.math.ec.rfc7748.X25519
import org.bouncycastle.math.ec.rfc8032.Ed25519

sealed class CryptoException(message: String, cause: Throwable? = null) : Exception(message, cause) {
    class InvalidSeed(message: String = "device_master_seed must be 32 bytes") : CryptoException(message)
    class InvalidKeyLength(message: String = "invalid key length") : CryptoException(message)
    class AllZeroSharedKey(message: String = "x25519 shared secret is all zeros") : CryptoException(message)
    class InvalidRelayUrl(message: String = "invalid canonical relay origin") : CryptoException(message)
    class InvalidSignature(message: String = "invalid ed25519 signature") : CryptoException(message)
    class DeviceIdMismatch(message: String = "device_id does not match sign_pk") : CryptoException(message)
    class MailboxIdMismatch(message: String = "mailbox_id does not match mailbox_auth_pk") : CryptoException(message)
    class InvalidRoomId(message: String = "invalid crockford base32 room_id") : CryptoException(message)
    class InvalidPurpose(message: String = "invalid handshake purpose") : CryptoException(message)
    class CommitMismatch(message: String = "handshake commit_a verification failed") : CryptoException(message)
    class MacMismatch(message: String = "handshake key confirmation mac mismatch") : CryptoException(message)
    class SasMismatch(message: String = "handshake sas mismatch") : CryptoException(message)
    class DecryptFailed(message: String = "aead decryption failed", cause: Throwable? = null) : CryptoException(message, cause)
    class InvalidCtrlSeq(message: String = "invalid pipe control sequence number") : CryptoException(message)
    class InvalidOobSecret(message: String = "oob_secret must be 16 bytes") : CryptoException(message)
    class InvalidSealedHeader(message: String = "invalid 208-byte sealed header") : CryptoException(message)
    class RecipientMismatch(message: String = "sealed header recipient_device_id mismatch") : CryptoException(message)
    class UntrustedSender(message: String = "sealed header sender_device_id not trusted") : CryptoException(message)
    class StreamTruncated(message: String = "stream truncated: missing authenticated final block", cause: Throwable? = null) : CryptoException(message, cause)
    class StreamTooLarge(message: String = "stream exceeds maximum 2^32 block limit") : CryptoException(message)
    class InvalidPadding(message: String = "invalid manifest 4 KiB padding") : CryptoException(message)
    class InvalidBlockSize(message: String = "invalid ciphertext block length") : CryptoException(message)
    class InvalidPartId(message: String = "part_id out of range 0..63") : CryptoException(message)
}

class DeviceKeys(
    val masterSeed: ByteArray,
    val masterPrk: ByteArray,
    val signSeed: ByteArray,
    val signPub: ByteArray,
    val kemPrivBytes: ByteArray,
    val kemPubBytes: ByteArray,
    val localMetaKey: ByteArray,
    val deviceIdRaw: ByteArray,
    val deviceId: String,
) {
    fun deriveMailboxKeys(relayId: String): MailboxKeys {
        return KeysAndAuth.deriveMailboxKeys(masterPrk, relayId)
    }

    fun zero() {
        KeysAndAuth.zeroBytes(masterSeed, masterPrk, signSeed, kemPrivBytes, localMetaKey)
    }
}

class MailboxKeys(
    val relayId: String,
    val authSeed: ByteArray,
    val authPub: ByteArray,
    val mailboxId: String,
) {
    fun zero() {
        KeysAndAuth.zeroBytes(authSeed)
    }
}

object KeysAndAuth {
    const val MASTER_SEED_SIZE: Int = 32
    const val DEVICE_ID_RAW_SIZE: Int = 16
    const val MSG_ID_RAW_SIZE: Int = 16

    const val HEADER_RELAY_TS: String = "X-Sync-TS"
    const val HEADER_RELAY_NONCE: String = "X-Sync-Nonce"
    const val HEADER_RELAY_SIG: String = "X-Sync-Sig"
    const val HEADER_ROOM_TOKEN: String = "X-Sync-Room-Token"
    const val HEADER_MAILBOX_SIG: String = "X-Sync-Mailbox-Sig"
    const val HEADER_DEPOSIT_TOKEN: String = "X-Sync-Deposit-Token"
    const val HEADER_UPLOAD_TOKEN: String = "X-Sync-Upload-Token"
    const val HEADER_CLIENT_AGENT: String = "X-Sync-Client"

    private val MASTER_SEED_SALT = "synctool-v1/master-seed-salt".toByteArray(StandardCharsets.UTF_8)
    private val INFO_ED25519_SIGN = "synctool-v1/ed25519-sign".toByteArray(StandardCharsets.UTF_8)
    private val INFO_X25519_KEM = "synctool-v1/x25519-kem".toByteArray(StandardCharsets.UTF_8)
    private const val INFO_MAILBOX_AUTH_PFX = "synctool-v1/mailbox-auth/"
    private val INFO_LOCAL_META_KEY = "synctool-v1/local-storage-key".toByteArray(StandardCharsets.UTF_8)

    private val PREFIX_RELAY_ID = "synctool-v1/relay-id:".toByteArray(StandardCharsets.UTF_8)
    private val PREFIX_DEVICE_ID = "synctool-v1/device-id:".toByteArray(StandardCharsets.UTF_8)
    private val PREFIX_MAILBOX_ID = "synctool-v1/mailbox-id:".toByteArray(StandardCharsets.UTF_8)
    private val PREFIX_DEVICE_CARD = "synctool-v1/device-card\n".toByteArray(StandardCharsets.UTF_8)

    private val PREFIX_ACCESS_KEY = "synctool-v1/access-key:".toByteArray(StandardCharsets.UTF_8)
    private val PREFIX_DEPOSIT_TOKEN = "synctool-v1/deposit-token:".toByteArray(StandardCharsets.UTF_8)
    private val PREFIX_UPLOAD_TOKEN = "synctool-v1/upload-token:".toByteArray(StandardCharsets.UTF_8)
    private const val PREFIX_MAILBOX_AUTH_IN = "synctool-v1/mailbox-auth\n"

    // RFC 8410 DER prefixes (CRYPTO_AND_AUTH.md §2.2)
    val ED25519_PKCS8_PREFIX: ByteArray = byteArrayOf(
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20
    )
    val X25519_PKCS8_PREFIX: ByteArray = byteArrayOf(
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20
    )
    val ED25519_SPKI_PREFIX: ByteArray = byteArrayOf(
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00
    )
    val X25519_SPKI_PREFIX: ByteArray = byteArrayOf(
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00
    )

    // Ed25519 group order L = 2^252 + 27742317777372353535851937790883648493
    private val ED25519_ORDER_L = BigInteger("1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed", 16)
    // Ed25519 field prime p = 2^255 - 19
    private val ED25519_FIELD_P = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19))

    // Canonical & sign-flipped encodings of all 8 Ed25519 small-order torsion points
    private val ED25519_SMALL_ORDER_PKS: List<ByteArray> = listOf(
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000080",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000080",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
    ).map { fromHex(it) }

    private val ZERO_32 = ByteArray(32)
    private val HEX_CHARS = "0123456789abcdef".toCharArray()
    private val B64U_ENCODER = Base64.getUrlEncoder().withoutPadding()
    private val B64U_DECODER = Base64.getUrlDecoder()
    private val csprng = SecureRandom()

    fun randomBytes(n: Int): ByteArray {
        require(n >= 0) { "negative byte length" }
        val buf = ByteArray(n)
        if (n > 0) csprng.nextBytes(buf)
        return buf
    }

    fun generateMasterSeed(): ByteArray = randomBytes(MASTER_SEED_SIZE)

    fun zeroBytes(vararg arrays: ByteArray?) {
        for (a in arrays) {
            a?.fill(0)
        }
    }

    fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean {
        return a.size == b.size && MessageDigest.isEqual(a, b)
    }

    fun toLowerHex(bytes: ByteArray): String {
        val out = CharArray(bytes.size * 2)
        for (i in bytes.indices) {
            val v = bytes[i].toInt() and 0xff
            out[i * 2] = HEX_CHARS[v ushr 4]
            out[i * 2 + 1] = HEX_CHARS[v and 0x0f]
        }
        return String(out)
    }

    fun fromHex(hex: String): ByteArray {
        if (hex.length % 2 != 0) {
            throw IllegalArgumentException("odd-length hex string")
        }
        val out = ByteArray(hex.length / 2)
        for (i in out.indices) {
            val hi = hexDigit(hex[i * 2])
            val lo = hexDigit(hex[i * 2 + 1])
            out[i] = ((hi shl 4) or lo).toByte()
        }
        return out
    }

    private fun hexDigit(c: Char): Int = when (c) {
        in '0'..'9' -> c.code - '0'.code
        in 'a'..'f' -> c.code - 'a'.code + 10
        in 'A'..'F' -> c.code - 'A'.code + 10
        else -> throw IllegalArgumentException("invalid hex char")
    }

    fun isLowerHex(s: String, wantLen: Int): Boolean {
        if (s.length != wantLen) return false
        for (i in s.indices) {
            val c = s[i]
            if (c !in '0'..'9' && c !in 'a'..'f') return false
        }
        return true
    }

    fun b64uEncode(bytes: ByteArray): String = B64U_ENCODER.encodeToString(bytes)

    fun b64uDecode(s: String): ByteArray {
        if (s.isEmpty()) return ByteArray(0)
        for (i in s.indices) {
            val c = s[i]
            val ok = (c in 'A'..'Z') || (c in 'a'..'z') || (c in '0'..'9') || c == '-' || c == '_'
            if (!ok) throw IllegalArgumentException("invalid unpadded base64url character")
        }
        if (s.length % 4 == 1) {
            throw IllegalArgumentException("invalid base64url length")
        }
        val decoded = B64U_DECODER.decode(s)
        // Enforce canonical unpadded base64url (reject non-zero trailing pad bits)
        if (B64U_ENCODER.encodeToString(decoded) != s) {
            throw IllegalArgumentException("non-canonical base64url encoding")
        }
        return decoded
    }

    fun sha256(vararg parts: ByteArray): ByteArray {
        val md = MessageDigest.getInstance("SHA-256")
        for (p in parts) {
            md.update(p)
        }
        return md.digest()
    }

    fun hmacSha256(key: ByteArray, vararg parts: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        val actualKey = if (key.isEmpty()) ZERO_32 else key
        mac.init(SecretKeySpec(actualKey, "HmacSHA256"))
        for (p in parts) {
            mac.update(p)
        }
        return mac.doFinal()
    }

    /**
     * RFC 5869 HKDF-Extract(salt, ikm) with SHA-256.
     */
    fun hkdfExtract(salt: ByteArray, ikm: ByteArray): ByteArray {
        val actualSalt = if (salt.isEmpty()) ZERO_32 else salt
        return hmacSha256(actualSalt, ikm)
    }

    /**
     * RFC 5869 HKDF-Expand(prk, info, length) with SHA-256.
     */
    fun hkdfExpand(prk: ByteArray, info: ByteArray, length: Int): ByteArray {
        if (prk.size != 32) throw CryptoException.InvalidKeyLength("HKDF PRK must be 32 bytes")
        require(length in 0..(255 * 32)) { "HKDF length out of bounds: $length" }
        if (length == 0) return ByteArray(0)

        val mac = Mac.getInstance("HmacSHA256")
        val keySpec = SecretKeySpec(prk, "HmacSHA256")
        val out = ByteArray(length)
        var t = ByteArray(0)
        var offset = 0
        var counter = 1
        try {
            while (offset < length) {
                mac.init(keySpec)
                if (t.isNotEmpty()) mac.update(t)
                if (info.isNotEmpty()) mac.update(info)
                mac.update(counter.toByte())
                val nextT = mac.doFinal()
                zeroBytes(t)
                t = nextT
                val take = minOf(32, length - offset)
                System.arraycopy(t, 0, out, offset, take)
                offset += take
                counter++
            }
        } finally {
            zeroBytes(t)
        }
        return out
    }

    fun aesGcmSeal(key: ByteArray, nonce: ByteArray, plaintext: ByteArray, aad: ByteArray?): ByteArray {
        if (key.size != 32 || nonce.size != 12) {
            throw CryptoException.InvalidKeyLength("AES-256-GCM requires 32B key and 12B nonce")
        }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        if (aad != null && aad.isNotEmpty()) {
            cipher.updateAAD(aad)
        }
        return cipher.doFinal(plaintext)
    }

    fun aesGcmOpen(key: ByteArray, nonce: ByteArray, ciphertext: ByteArray, aad: ByteArray?): ByteArray {
        if (key.size != 32 || nonce.size != 12) {
            throw CryptoException.InvalidKeyLength("AES-256-GCM requires 32B key and 12B nonce")
        }
        if (ciphertext.size < 16) {
            throw CryptoException.DecryptFailed("ciphertext shorter than 16B GCM tag")
        }
        return try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
            if (aad != null && aad.isNotEmpty()) {
                cipher.updateAAD(aad)
            }
            cipher.doFinal(ciphertext)
        } catch (e: GeneralSecurityException) {
            throw CryptoException.DecryptFailed("AES-256-GCM authentication failed", e)
        }
    }

    // --- Direct Low-Level BouncyCastle X25519 & Ed25519 (ZERO JCA Provider Registration!) ---

    fun generateEphemeralX25519(): Pair<ByteArray, ByteArray> {
        val sk = randomBytes(32)
        val pk = x25519PublicKeyFromPrivate(sk)
        return sk to pk
    }

    fun x25519PublicKeyFromPrivate(sk32: ByteArray): ByteArray {
        if (sk32.size != 32) throw CryptoException.InvalidKeyLength("X25519 private key must be 32 bytes")
        val pk = ByteArray(32)
        X25519.scalarMultBase(sk32, 0, pk, 0)
        return pk
    }

    fun x25519SharedSecret(localPriv32: ByteArray, peerPub32: ByteArray): ByteArray {
        if (localPriv32.size != 32 || peerPub32.size != 32) {
            throw CryptoException.InvalidKeyLength("X25519 keys must be 32 bytes")
        }
        val shared = ByteArray(32)
        X25519.scalarMult(localPriv32, 0, peerPub32, 0, shared, 0)
        if (MessageDigest.isEqual(shared, ZERO_32)) {
            zeroBytes(shared)
            throw CryptoException.AllZeroSharedKey()
        }
        return shared
    }

    fun ed25519PublicKeyFromSeed(seed32: ByteArray): ByteArray {
        if (seed32.size != 32) throw CryptoException.InvalidKeyLength("Ed25519 seed must be 32 bytes")
        val pk = ByteArray(32)
        Ed25519.generatePublicKey(seed32, 0, pk, 0)
        return pk
    }

    fun ed25519Sign(seed32: ByteArray, message: ByteArray): ByteArray {
        if (seed32.size != 32) throw CryptoException.InvalidKeyLength("Ed25519 seed must be 32 bytes")
        val sig = ByteArray(64)
        Ed25519.sign(seed32, 0, message, 0, message.size, sig, 0)
        return sig
    }

    fun isSmallOrderOrNonCanonicalEd25519Pk(pk32: ByteArray): Boolean {
        if (pk32.size != 32) return true
        for (torsion in ED25519_SMALL_ORDER_PKS) {
            if (MessageDigest.isEqual(pk32, torsion)) {
                return true
            }
        }
        // Check canonical y < 2^255 - 19 (little-endian with sign bit cleared)
        val yBigEndian = ByteArray(32)
        for (i in 0 until 32) {
            yBigEndian[i] = pk32[31 - i]
        }
        yBigEndian[0] = (yBigEndian[0].toInt() and 0x7f).toByte()
        val y = BigInteger(1, yBigEndian)
        return y >= ED25519_FIELD_P
    }

    fun isCanonicalEd25519Scalar(sig64: ByteArray, scalarOffset: Int = 32): Boolean {
        if (sig64.size < scalarOffset + 32) return false
        val sBigEndian = ByteArray(32)
        for (i in 0 until 32) {
            sBigEndian[i] = sig64[scalarOffset + 31 - i]
        }
        val s = BigInteger(1, sBigEndian)
        return s >= BigInteger.ZERO && s < ED25519_ORDER_L
    }

    fun ed25519VerifyStrict(pk32: ByteArray, message: ByteArray, sig64: ByteArray): Boolean {
        if (pk32.size != 32 || sig64.size != 64) return false
        if (isSmallOrderOrNonCanonicalEd25519Pk(pk32)) return false
        if (!isCanonicalEd25519Scalar(sig64, 32)) return false
        return Ed25519.verify(sig64, 0, pk32, 0, message, 0, message.size)
    }

    // --- Single-Seed Key Hierarchy (CRYPTO_AND_AUTH.md §3) ---

    fun deriveDeviceKeys(seed: ByteArray): DeviceKeys {
        if (seed.size != MASTER_SEED_SIZE) {
            throw CryptoException.InvalidSeed()
        }
        val masterPrk = hkdfExtract(MASTER_SEED_SALT, seed)
        val signSeed = hkdfExpand(masterPrk, INFO_ED25519_SIGN, 32)
        val kemSk = hkdfExpand(masterPrk, INFO_X25519_KEM, 32)
        val localMeta = hkdfExpand(masterPrk, INFO_LOCAL_META_KEY, 32)
        val signPub = ed25519PublicKeyFromSeed(signSeed)
        val kemPub = x25519PublicKeyFromPrivate(kemSk)
        val (devRaw, devHex) = deriveDeviceId(signPub)
        return DeviceKeys(
            masterSeed = seed.copyOf(),
            masterPrk = masterPrk,
            signSeed = signSeed,
            signPub = signPub,
            kemPrivBytes = kemSk,
            kemPubBytes = kemPub,
            localMetaKey = localMeta,
            deviceIdRaw = devRaw,
            deviceId = devHex,
        )
    }

    fun deriveMailboxKeys(masterPrk: ByteArray, relayId: String): MailboxKeys {
        if (masterPrk.size != 32) throw CryptoException.InvalidSeed("masterPrk must be 32 bytes")
        require(relayId.isNotEmpty()) { "relay_id must not be empty" }
        val info = (INFO_MAILBOX_AUTH_PFX + relayId).toByteArray(StandardCharsets.UTF_8)
        val authSeed = hkdfExpand(masterPrk, info, 32)
        val authPub = ed25519PublicKeyFromSeed(authSeed)
        val mailboxId = deriveMailboxId(authPub)
        return MailboxKeys(
            relayId = relayId,
            authSeed = authSeed,
            authPub = authPub,
            mailboxId = mailboxId,
        )
    }

    fun deriveRelayId(canonicalOrigin: String): String {
        val sum = sha256(PREFIX_RELAY_ID, canonicalOrigin.toByteArray(StandardCharsets.UTF_8))
        return toLowerHex(sum.copyOfRange(0, 16))
    }

    fun deriveDeviceId(signPk: ByteArray): Pair<ByteArray, String> {
        if (signPk.size != 32) throw CryptoException.InvalidKeyLength("sign_pk must be 32 bytes")
        val sum = sha256(PREFIX_DEVICE_ID, signPk)
        val raw = sum.copyOfRange(0, 16)
        return raw to toLowerHex(raw)
    }

    fun deriveMailboxId(mailboxAuthPk: ByteArray): String {
        if (mailboxAuthPk.size != 32) throw CryptoException.InvalidKeyLength("mailbox_auth_pk must be 32 bytes")
        val sum = sha256(PREFIX_MAILBOX_ID, mailboxAuthPk)
        return toLowerHex(sum.copyOfRange(0, 16))
    }

    fun deviceCardSignInput(signPk: ByteArray, kemPk: ByteArray, issuedAt: Long): ByteArray {
        if (signPk.size != 32 || kemPk.size != 32) {
            throw CryptoException.InvalidKeyLength("sign_pk and kem_pk must be 32 bytes")
        }
        if (issuedAt < 0L) {
            throw IllegalArgumentException("issued_at must be non-negative")
        }
        val buf = ByteBuffer.allocate(PREFIX_DEVICE_CARD.size + 32 + 32 + 8)
        buf.put(PREFIX_DEVICE_CARD)
        buf.put(signPk)
        buf.put(kemPk)
        buf.putLong(issuedAt)
        return buf.array()
    }

    fun signDeviceCard(signSeed32: ByteArray, kemPk32: ByteArray, issuedAt: Long): ByteArray {
        if (signSeed32.size != 32) throw CryptoException.InvalidKeyLength("signSeed must be 32 bytes")
        val signPk = ed25519PublicKeyFromSeed(signSeed32)
        val input = deviceCardSignInput(signPk, kemPk32, issuedAt)
        return ed25519Sign(signSeed32, input)
    }

    fun verifyDeviceCard(
        deviceId: String,
        signPk: ByteArray,
        kemPk: ByteArray,
        issuedAt: Long,
        cardSig: ByteArray,
    ) {
        if (signPk.size != 32 || kemPk.size != 32 || cardSig.size != 64) {
            throw CryptoException.InvalidKeyLength()
        }
        if (!isLowerHex(deviceId, 32)) {
            throw CryptoException.DeviceIdMismatch()
        }
        val (_, expectedId) = deriveDeviceId(signPk)
        if (!constantTimeEquals(
                deviceId.toByteArray(StandardCharsets.US_ASCII),
                expectedId.toByteArray(StandardCharsets.US_ASCII)
            )
        ) {
            throw CryptoException.DeviceIdMismatch()
        }
        if (issuedAt < 0L) {
            throw CryptoException.InvalidSignature("issued_at must be non-negative")
        }
        val input = deviceCardSignInput(signPk, kemPk, issuedAt)
        if (!ed25519VerifyStrict(signPk, input, cardSig)) {
            throw CryptoException.InvalidSignature()
        }
    }

    fun encodeEd25519Pkcs8(seed32: ByteArray): ByteArray {
        if (seed32.size != 32) throw CryptoException.InvalidKeyLength()
        return ED25519_PKCS8_PREFIX + seed32
    }

    fun encodeX25519Pkcs8(sk32: ByteArray): ByteArray {
        if (sk32.size != 32) throw CryptoException.InvalidKeyLength()
        return X25519_PKCS8_PREFIX + sk32
    }

    fun encodeEd25519Spki(pk32: ByteArray): ByteArray {
        if (pk32.size != 32) throw CryptoException.InvalidKeyLength()
        return ED25519_SPKI_PREFIX + pk32
    }

    fun encodeX25519Spki(pk32: ByteArray): ByteArray {
        if (pk32.size != 32) throw CryptoException.InvalidKeyLength()
        return X25519_SPKI_PREFIX + pk32
    }

    // --- Canonical Relay Origin & IP Helpers (Never echoes raw input in exceptions!) ---

    fun canonicalRelayOrigin(raw: String): String {
        val trimmed = raw.trim()
        if (trimmed.isEmpty()) {
            throw CryptoException.InvalidRelayUrl("empty URL")
        }
        for (i in trimmed.indices) {
            val c = trimmed[i].code
            if (c <= 0x20 || c >= 0x7f) {
                throw CryptoException.InvalidRelayUrl("URL contains control, whitespace, or non-ASCII characters")
            }
        }
        if ('#' in trimmed || '?' in trimmed) {
            throw CryptoException.InvalidRelayUrl("origin must not contain query or fragment")
        }
        val uri = try {
            URI(trimmed)
        } catch (_: Exception) {
            throw CryptoException.InvalidRelayUrl("malformed URL")
        }
        val scheme = uri.scheme?.lowercase()
            ?: throw CryptoException.InvalidRelayUrl("missing scheme")
        if (scheme != "https" && scheme != "http") {
            throw CryptoException.InvalidRelayUrl("unsupported scheme")
        }
        if (uri.isOpaque || uri.rawUserInfo != null || uri.rawQuery != null || uri.rawFragment != null) {
            throw CryptoException.InvalidRelayUrl("origin must not contain userinfo, query, or fragment")
        }
        val rawPath = uri.rawPath ?: ""
        if (rawPath.isNotEmpty() && rawPath != "/") {
            throw CryptoException.InvalidRelayUrl("origin must not contain path")
        }
        val authority = uri.rawAuthority
            ?: throw CryptoException.InvalidRelayUrl("missing host authority")
        if ('@' in authority || '%' in authority) {
            throw CryptoException.InvalidRelayUrl("origin authority must not contain userinfo or zone/percent escapes")
        }

        val (rawHost, rawPortStr) = splitHostPortAuthority(authority)
        if (rawHost.isEmpty() || '/' in rawHost || '\\' in rawHost) {
            throw CryptoException.InvalidRelayUrl("invalid host")
        }

        val canonicalHost = canonicalizeHost(rawHost)
        val portNum = if (rawPortStr == null) {
            if (scheme == "https") 443 else 80
        } else {
            if (rawPortStr.isEmpty() || !rawPortStr.all { it in '0'..'9' }) {
                throw CryptoException.InvalidRelayUrl("invalid port")
            }
            val parsed = rawPortStr.toIntOrNull()
                ?: throw CryptoException.InvalidRelayUrl("port out of range")
            if (parsed !in 1..65535) {
                throw CryptoException.InvalidRelayUrl("port must be in 1..65535")
            }
            parsed
        }

        if (scheme == "http" && !isLoopbackHost(canonicalHost)) {
            throw CryptoException.InvalidRelayUrl("http scheme only permitted for loopback")
        }

        val formattedHost = if (':' in canonicalHost && !canonicalHost.startsWith("[")) {
            "[$canonicalHost]"
        } else {
            canonicalHost
        }
        return "$scheme://$formattedHost:$portNum"
    }

    private fun splitHostPortAuthority(authority: String): Pair<String, String?> {
        if (authority.startsWith("[")) {
            val closeIdx = authority.indexOf(']')
            if (closeIdx < 0) {
                throw CryptoException.InvalidRelayUrl("unclosed IPv6 bracket")
            }
            val inside = authority.substring(1, closeIdx)
            if (inside.isEmpty()) {
                throw CryptoException.InvalidRelayUrl("empty IPv6 literal")
            }
            val rest = authority.substring(closeIdx + 1)
            return when {
                rest.isEmpty() -> "[${inside}]" to null
                rest.startsWith(":") -> {
                    val portPart = rest.substring(1)
                    if (portPart.isEmpty()) {
                        throw CryptoException.InvalidRelayUrl("empty port after colon")
                    }
                    "[${inside}]" to portPart
                }
                else -> throw CryptoException.InvalidRelayUrl("invalid characters after IPv6 literal")
            }
        }
        val firstColon = authority.indexOf(':')
        if (firstColon < 0) {
            return authority to null
        }
        if (authority.indexOf(':', firstColon + 1) >= 0) {
            throw CryptoException.InvalidRelayUrl("unbracketed IPv6 literal")
        }
        val hostPart = authority.substring(0, firstColon)
        val portPart = authority.substring(firstColon + 1)
        if (portPart.isEmpty()) {
            throw CryptoException.InvalidRelayUrl("empty port after colon")
        }
        return hostPart to portPart
    }

    private fun canonicalizeHost(rawHost: String): String {
        if (rawHost.startsWith("[") && rawHost.endsWith("]")) {
            val inner = rawHost.substring(1, rawHost.length - 1)
            if ('%' in inner || inner.isEmpty()) {
                throw CryptoException.InvalidRelayUrl("invalid IPv6 literal")
            }
            val bytes16 = parseStrictIpv6(inner)
                ?: throw CryptoException.InvalidRelayUrl("invalid IPv6 literal")
            return formatRfc5952Ipv6(bytes16)
        }
        val lower = rawHost.lowercase()
        val ipv4 = parseStrictIpv4(lower)
        if (ipv4 != null) {
            return "${ipv4[0].toInt() and 0xff}.${ipv4[1].toInt() and 0xff}.${ipv4[2].toInt() and 0xff}.${ipv4[3].toInt() and 0xff}"
        }
        // Reject partial numeric / malformed IPv4 lookalikes if needed, or validate hostname chars
        for (c in lower) {
            val ok = (c in 'a'..'z') || (c in '0'..'9') || c == '.' || c == '-'
            if (!ok) throw CryptoException.InvalidRelayUrl("invalid hostname character")
        }
        return lower
    }

    fun isLoopbackHost(host: String): Boolean {
        val h = host.trim().removeSurrounding("[", "]").lowercase()
        if (h == "localhost") return true
        val v4 = parseStrictIpv4(h)
        if (v4 != null) {
            return (v4[0].toInt() and 0xff) == 127
        }
        val v6 = parseStrictIpv6(h) ?: return false
        // ::1
        var allZeroPrefix = true
        for (i in 0 until 15) {
            if (v6[i].toInt() != 0) {
                allZeroPrefix = false
                break
            }
        }
        if (allZeroPrefix && v6[15].toInt() == 1) return true
        // ::ffff:127.x.x.x (IPv4-mapped loopback)
        if (isIpv4MappedIpv6(v6) && (v6[12].toInt() and 0xff) == 127) {
            return true
        }
        return false
    }

    fun isIpHost(host: String): Boolean {
        var h = host.trim().removeSurrounding("[", "]")
        val pct = h.indexOf('%')
        if (pct >= 0) h = h.substring(0, pct)
        if (h.isEmpty()) return false
        return parseStrictIpv4(h) != null || parseStrictIpv6(h) != null
    }

    private fun parseStrictIpv4(s: String): ByteArray? {
        val parts = s.split('.')
        if (parts.size != 4) return null
        val out = ByteArray(4)
        for (i in 0 until 4) {
            val p = parts[i]
            if (p.isEmpty() || p.length > 3 || !p.all { it in '0'..'9' }) return null
            if (p.length > 1 && p.startsWith("0")) return null
            val n = p.toIntOrNull() ?: return null
            if (n !in 0..255) return null
            out[i] = n.toByte()
        }
        return out
    }

    private fun parseStrictIpv6(s: String): ByteArray? {
        if (s.isEmpty() || '%' in s) return null
        // Delegate strict literal parsing without DNS lookup by validating characters first:
        for (c in s) {
            val ok = (c in '0'..'9') || (c in 'a'..'f') || (c in 'A'..'F') || c == ':' || c == '.'
            if (!ok) return null
        }
        if (':' !in s) return null
        return try {
            // InetAddress.getByName on bracketed "[...]" IPv6 literals NEVER performs DNS lookups.
            val addr = InetAddress.getByName("[$s]")
            when (addr) {
                is Inet6Address -> addr.address
                is Inet4Address -> {
                    // Java InetAddress.getByName("[::ffff:127.0.0.1]") unwraps IPv4-mapped IPv6 into Inet4Address!
                    // Reconstruct the exact 16-byte ::ffff:w.x.y.z representation so RelayID matches Go netip.Addr!
                    val v4 = addr.address
                    ByteArray(16).also { b ->
                        b[10] = 0xff.toByte()
                        b[11] = 0xff.toByte()
                        System.arraycopy(v4, 0, b, 12, 4)
                    }
                }
                else -> null
            }
        } catch (_: Exception) {
            null
        }
    }

    private fun isIpv4MappedIpv6(bytes16: ByteArray): Boolean {
        for (i in 0 until 10) {
            if (bytes16[i].toInt() != 0) return false
        }
        return (bytes16[10].toInt() and 0xff) == 0xff && (bytes16[11].toInt() and 0xff) == 0xff
    }

    private fun formatRfc5952Ipv6(bytes16: ByteArray): String {
        if (isIpv4MappedIpv6(bytes16)) {
            val a = bytes16[12].toInt() and 0xff
            val b = bytes16[13].toInt() and 0xff
            val c = bytes16[14].toInt() and 0xff
            val d = bytes16[15].toInt() and 0xff
            return "::ffff:$a.$b.$c.$d"
        }
        val groups = IntArray(8)
        for (i in 0 until 8) {
            groups[i] = ((bytes16[i * 2].toInt() and 0xff) shl 8) or (bytes16[i * 2 + 1].toInt() and 0xff)
        }
        var bestStart = -1
        var bestLen = 0
        var curStart = -1
        var curLen = 0
        for (i in 0 until 8) {
            if (groups[i] == 0) {
                if (curStart < 0) {
                    curStart = i
                    curLen = 1
                } else {
                    curLen++
                }
                if (curLen > bestLen && curLen >= 2) {
                    bestStart = curStart
                    bestLen = curLen
                }
            } else {
                curStart = -1
                curLen = 0
            }
        }
        val sb = StringBuilder()
        var i = 0
        while (i < 8) {
            if (i == bestStart) {
                sb.append("::")
                i += bestLen
                continue
            }
            if (sb.isNotEmpty() && !sb.endsWith("::")) {
                sb.append(':')
            }
            sb.append(groups[i].toString(16))
            i++
        }
        return sb.toString()
    }

    // --- Relay Access & Mailbox Ownership Request Signing (CRYPTO_AND_AUTH.md §7) ---

    fun deriveRelayHmacKey(accessKey: String): ByteArray {
        return sha256(PREFIX_ACCESS_KEY, accessKey.toByteArray(StandardCharsets.UTF_8))
    }

    fun hashDepositToken(rawToken: String): String {
        return toLowerHex(sha256(PREFIX_DEPOSIT_TOKEN, rawToken.toByteArray(StandardCharsets.UTF_8)))
    }

    fun hashUploadToken(rawToken: String): String {
        return toLowerHex(sha256(PREFIX_UPLOAD_TOKEN, rawToken.toByteArray(StandardCharsets.UTF_8)))
    }

    fun bodyBindingControl(rawBody: ByteArray?): String {
        val sum = sha256(rawBody ?: ByteArray(0))
        return "sha256:${toLowerHex(sum)}"
    }

    fun bodyBindingStream(contentLength: Long): String {
        return "stream:$contentLength"
    }

    fun extraTokenBinding(depositToken: String = "", uploadToken: String = ""): String {
        if (depositToken.isNotEmpty()) {
            return "deposit:${hashDepositToken(depositToken)}"
        }
        if (uploadToken.isNotEmpty()) {
            return "upload:${hashUploadToken(uploadToken)}"
        }
        return ""
    }

    fun buildCanonicalRequest(
        method: String,
        pathAndRawQuery: String,
        ts: String,
        nonce: String,
        bodyBinding: String,
        extraTokenBinding: String,
    ): String {
        return buildString(
            method.length + pathAndRawQuery.length + ts.length + nonce.length +
                bodyBinding.length + extraTokenBinding.length + 5
        ) {
            append(method.uppercase())
            append('\n')
            append(pathAndRawQuery)
            append('\n')
            append(ts)
            append('\n')
            append(nonce)
            append('\n')
            append(bodyBinding)
            append('\n')
            append(extraTokenBinding)
        }
    }

    fun signRelayRequest(
        accessKey: String,
        method: String,
        pathAndRawQuery: String,
        ts: String,
        nonce: String,
        bodyBinding: String,
        extraTokenBinding: String,
    ): String {
        val hmacKey = deriveRelayHmacKey(accessKey)
        try {
            val canon = buildCanonicalRequest(method, pathAndRawQuery, ts, nonce, bodyBinding, extraTokenBinding)
            val mac = hmacSha256(hmacKey, canon.toByteArray(StandardCharsets.UTF_8))
            return toLowerHex(mac)
        } finally {
            zeroBytes(hmacKey)
        }
    }

    fun verifyRelayRequest(
        accessKey: String,
        method: String,
        pathAndRawQuery: String,
        ts: String,
        nonce: String,
        bodyBinding: String,
        extraTokenBinding: String,
        sigHex: String,
    ): Boolean {
        if (!isLowerHex(sigHex, 64)) return false
        val got = try {
            fromHex(sigHex)
        } catch (_: Exception) {
            return false
        }
        val hmacKey = deriveRelayHmacKey(accessKey)
        try {
            val canon = buildCanonicalRequest(method, pathAndRawQuery, ts, nonce, bodyBinding, extraTokenBinding)
            val expected = hmacSha256(hmacKey, canon.toByteArray(StandardCharsets.UTF_8))
            return constantTimeEquals(expected, got)
        } finally {
            zeroBytes(hmacKey)
        }
    }

    fun buildMailboxSigInput(
        method: String,
        pathAndRawQuery: String,
        mailboxId: String,
        ts: String,
        nonce: String,
        bodyBinding: String,
    ): String {
        return buildString {
            append(PREFIX_MAILBOX_AUTH_IN)
            append(method.uppercase())
            append('\n')
            append(pathAndRawQuery)
            append('\n')
            append(mailboxId)
            append('\n')
            append(ts)
            append('\n')
            append(nonce)
            append('\n')
            append(bodyBinding)
        }
    }

    fun signMailboxRequest(
        mailboxAuthSeed32: ByteArray,
        method: String,
        pathAndRawQuery: String,
        mailboxId: String,
        ts: String,
        nonce: String,
        bodyBinding: String,
    ): String {
        val input = buildMailboxSigInput(method, pathAndRawQuery, mailboxId, ts, nonce, bodyBinding)
        val sig = ed25519Sign(mailboxAuthSeed32, input.toByteArray(StandardCharsets.UTF_8))
        return b64uEncode(sig)
    }

    fun verifyMailboxRequest(
        mailboxAuthPk32: ByteArray,
        method: String,
        pathAndRawQuery: String,
        mailboxId: String,
        ts: String,
        nonce: String,
        bodyBinding: String,
        sigB64u: String,
    ): Boolean {
        if (mailboxAuthPk32.size != 32) return false
        val sig = try {
            b64uDecode(sigB64u)
        } catch (_: Exception) {
            return false
        }
        if (sig.size != 64) return false
        val input = buildMailboxSigInput(method, pathAndRawQuery, mailboxId, ts, nonce, bodyBinding)
        return ed25519VerifyStrict(mailboxAuthPk32, input.toByteArray(StandardCharsets.UTF_8), sig)
    }

    fun generateNonceHex(): String {
        val b = randomBytes(16)
        try {
            return toLowerHex(b)
        } finally {
            zeroBytes(b)
        }
    }

    fun generateTokenB64u(): String {
        val b = randomBytes(32)
        try {
            return b64uEncode(b)
        } finally {
            zeroBytes(b)
        }
    }
}
