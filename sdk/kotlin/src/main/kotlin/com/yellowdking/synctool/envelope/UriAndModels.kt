package com.yellowdking.synctool.envelope

import com.yellowdking.synctool.crypto.Crockford
import com.yellowdking.synctool.crypto.CryptoException
import com.yellowdking.synctool.crypto.Handshake
import com.yellowdking.synctool.crypto.KeysAndAuth
import java.net.URI
import java.net.URLDecoder
import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonPrimitive

object TlsMode {
    const val SYSTEM_CA: String = "system_ca"
    const val CA_ALIAS: String = "ca"
    const val SPKI_PIN: String = "spki_pin"
}

@Serializable
data class RelayProfile(
    @SerialName("relay_id") val relayId: String = "",
    val alias: String = "",
    val endpoint: String,
    @SerialName("access_key") val accessKey: String,
    @SerialName("tls_mode") val tlsMode: String = TlsMode.SYSTEM_CA,
    @SerialName("spki_pins") val spkiPins: List<String> = emptyList(),
    @SerialName("spki_sha256") val legacySpkiSha256: String = "",
    @SerialName("is_default") val isDefault: Boolean = false,
) {
    constructor(
        endpoint: String,
        accessKey: String,
        tlsMode: String = "",
        spkiPin: String = "",
        spkiPins: List<String> = emptyList(),
        relayId: String = "",
        alias: String = "",
        isDefault: Boolean = false,
    ) : this(
        relayId = relayId,
        alias = alias,
        endpoint = endpoint,
        accessKey = accessKey,
        tlsMode = tlsMode.ifEmpty {
            if (spkiPins.isNotEmpty() || spkiPin.isNotBlank()) TlsMode.SPKI_PIN else TlsMode.SYSTEM_CA
        },
        spkiPins = mergePins(spkiPins, spkiPin),
        legacySpkiSha256 = spkiPins.firstOrNull()?.lowercase()?.trim() ?: spkiPin.lowercase().trim(),
        isDefault = isDefault,
    )

    val resolvedPins: List<String>
        get() = mergePins(spkiPins, legacySpkiSha256)

    val spkiPin: String
        get() = resolvedPins.firstOrNull().orEmpty()

    override fun toString(): String {
        return "RelayProfile(relayId=$relayId, alias=$alias, endpoint=$endpoint, tlsMode=$tlsMode, spkiPins=$resolvedPins, accessKey=[REDACTED])"
    }

    companion object {
        internal fun mergePins(pins: List<String>, singlePin: String): List<String> {
            val out = LinkedHashSet<String>()
            for (p in pins) {
                for (part in p.split(',')) {
                    val clean = part.trim().lowercase()
                    if (clean.isNotEmpty()) out.add(clean)
                }
            }
            if (singlePin.isNotBlank()) {
                for (part in singlePin.split(',')) {
                    val clean = part.trim().lowercase()
                    if (clean.isNotEmpty()) out.add(clean)
                }
            }
            return out.toList()
        }
    }
}

class PairOffer(
    val version: Int = 1,
    val roomId: String,
    val mode: Int,
    val purpose: String,
    val endpoint: String = "",
    val spkiPins: List<String> = emptyList(),
    val expiresAt: Long = 0L,
    val oobSecret: ByteArray = ByteArray(0),
    val accessKey: String = "",
) {
    val spkiPin: String
        get() = spkiPins.firstOrNull().orEmpty()

    fun zeroSecrets() {
        KeysAndAuth.zeroBytes(oobSecret)
    }

    override fun toString(): String {
        return "PairOffer(v=$version, r=$roomId, m=$mode, p=$purpose, u=$endpoint, spkiPins=$spkiPins, exp=$expiresAt, secrets=[REDACTED])"
    }
}

object SyncUri {
    const val MAX_SPKI_PINS: Int = 8
    private val RE_HEX_64 = Regex("^[0-9a-f]{64}$")

    fun parseAndValidateSpkiPins(rawPinParam: String): List<String> {
        val trimmed = rawPinParam.trim()
        if (trimmed.isEmpty()) return emptyList()
        val parts = trimmed.split(',')
        if (parts.isEmpty() || parts.size > MAX_SPKI_PINS) {
            throw SyncError(
                code = ErrorCode.ERR_URI_INVALID,
                rawMessage = "SPKI pin list must contain 1..$MAX_SPKI_PINS comma-separated 64-hex pins",
            )
        }
        val dedup = LinkedHashSet<String>(parts.size)
        for (rawPart in parts) {
            val pin = rawPart.trim().lowercase()
            if (!RE_HEX_64.matches(pin)) {
                throw SyncError(
                    code = ErrorCode.ERR_URI_INVALID,
                    rawMessage = "each SPKI pin must be exactly 64 lowercase hex characters",
                )
            }
            dedup.add(pin)
        }
        return dedup.toList()
    }

    fun parseRelayUri(raw: String): RelayProfile {
        val trimmed = raw.trim()
        val uri = parseStrictSyncUri(trimmed, expectedHost = "relay")
        val query = parseQueryPairs(uri.rawQuery)
        val frag = parseQueryPairs(uri.rawFragment)

        if (!query["k"].isNullOrEmpty() || !query["s"].isNullOrEmpty()) {
            throw SyncError(
                code = ErrorCode.ERR_URI_INVALID,
                rawMessage = "access key k must be placed in #fragment, not query",
            )
        }

        validateUriVersion(query["v"])

        val rawOrigin = query["u"]?.takeIf { it.isNotEmpty() }
            ?: throw SyncError(ErrorCode.ERR_URI_INVALID, rawMessage = "missing required parameter u")
        val origin = try {
            KeysAndAuth.canonicalRelayOrigin(rawOrigin)
        } catch (e: CryptoException) {
            throw SyncError(ErrorCode.ERR_URI_INVALID, rawMessage = e.message.orEmpty())
        }

        val originUri = URI(origin)
        val rawPin = query["pin"].orEmpty().trim()
        val pins = if (rawPin.isNotEmpty()) {
            parseAndValidateSpkiPins(rawPin)
        } else {
            emptyList()
        }
        val tlsMode = if (pins.isNotEmpty()) {
            TlsMode.SPKI_PIN
        } else {
            if (originUri.scheme == "https" && KeysAndAuth.isIpHost(originUri.host.orEmpty())) {
                throw SyncError(
                    code = ErrorCode.ERR_URI_INVALID,
                    rawMessage = "bare IP relay requires 64-hex SPKI pin",
                )
            }
            TlsMode.SYSTEM_CA
        }

        val accessKey = frag["k"].orEmpty()
        if (accessKey.length < 32) {
            throw SyncError(
                code = ErrorCode.ERR_URI_INVALID,
                rawMessage = "missing or short access key k in #fragment (min 32 chars)",
            )
        }

        val relayId = KeysAndAuth.deriveRelayId(origin)
        return RelayProfile(
            relayId = relayId,
            endpoint = origin,
            accessKey = accessKey,
            tlsMode = tlsMode,
            spkiPins = pins,
            legacySpkiSha256 = pins.firstOrNull().orEmpty(),
        )
    }

    fun formatRelayUri(profile: RelayProfile): String {
        val origin = try {
            KeysAndAuth.canonicalRelayOrigin(profile.endpoint)
        } catch (e: CryptoException) {
            throw SyncError(ErrorCode.ERR_URI_INVALID, rawMessage = e.message.orEmpty())
        }
        if (profile.accessKey.length < 32) {
            throw SyncError(ErrorCode.ERR_URI_INVALID, rawMessage = "access key must be >= 32 chars")
        }
        val originUri = URI(origin)
        val pins = if (profile.resolvedPins.isNotEmpty()) {
            parseAndValidateSpkiPins(profile.resolvedPins.joinToString(","))
        } else {
            emptyList()
        }
        if (pins.isEmpty() && originUri.scheme == "https" && KeysAndAuth.isIpHost(originUri.host.orEmpty())) {
            throw SyncError(ErrorCode.ERR_URI_INVALID, rawMessage = "bare IP relay requires SPKI pin")
        }

        return buildString {
            append("synctool://relay?v=1&u=")
            append(queryEscape(origin))
            if (pins.isNotEmpty()) {
                append("&pin=")
                append(pins.joinToString(","))
            }
            append("#k=")
            append(queryEscape(profile.accessKey))
        }
    }

    fun parsePairUri(raw: String): PairOffer {
        val trimmed = raw.trim()
        val uri = parseStrictSyncUri(trimmed, expectedHost = "pair")
        val query = parseQueryPairs(uri.rawQuery)
        val frag = parseQueryPairs(uri.rawFragment)

        if (!query["s"].isNullOrEmpty() || !query["k"].isNullOrEmpty()) {
            throw SyncError(
                code = ErrorCode.ERR_URI_INVALID,
                rawMessage = "secrets s/k must be in #fragment, not query",
            )
        }

        validateUriVersion(query["v"])

        val roomId = try {
            Crockford.normalizeRoomId(query["r"].orEmpty())
        } catch (_: CryptoException) {
            throw SyncError(ErrorCode.ERR_URI_INVALID, rawMessage = "invalid room_id r")
        }

        val modeStr = query["m"].orEmpty()
        val mode = modeStr.toIntOrNull()
            ?: throw SyncError(ErrorCode.ERR_URI_INVALID, rawMessage = "invalid mode m")
        val purpose = query["p"].orEmpty()
        when (mode) {
            Handshake.MODE_DIRECT -> {
                if (purpose != Handshake.PURPOSE_DIRECT) {
                    throw SyncError(ErrorCode.ERR_URI_INVALID, rawMessage = "mode=0 requires p=direct")
                }
            }
            Handshake.MODE_QR_OOB, Handshake.MODE_COMMIT_SAS -> {
                if (purpose != Handshake.PURPOSE_ONESHOT && purpose != Handshake.PURPOSE_PAIR) {
                    throw SyncError(ErrorCode.ERR_URI_INVALID, rawMessage = "mode=1/2 requires p=oneshot or p=pair")
                }
            }
            else -> throw SyncError(ErrorCode.ERR_URI_INVALID, rawMessage = "unsupported pair mode")
        }

        val rawOrigin = query["u"].orEmpty()
        val rawPin = query["pin"].orEmpty().trim()
        var origin = ""
        var pins: List<String> = emptyList()
        if (rawOrigin.isNotEmpty()) {
            origin = try {
                KeysAndAuth.canonicalRelayOrigin(rawOrigin)
            } catch (e: CryptoException) {
                throw SyncError(ErrorCode.ERR_URI_INVALID, rawMessage = e.message.orEmpty())
            }
            val originUri = URI(origin)
            if (rawPin.isNotEmpty()) {
                pins = parseAndValidateSpkiPins(rawPin)
            } else if (originUri.scheme == "https" && KeysAndAuth.isIpHost(originUri.host.orEmpty())) {
                throw SyncError(ErrorCode.ERR_URI_INVALID, rawMessage = "bare IP in pair URI requires SPKI pin")
            }
        } else if (rawPin.isNotEmpty()) {
            throw SyncError(ErrorCode.ERR_URI_INVALID, rawMessage = "pin parameter requires relay origin u")
        }

        var exp = 0L
        val expStr = query["exp"].orEmpty()
        if (expStr.isNotEmpty()) {
            val parsedExp = expStr.toLongOrNull()
            if (parsedExp == null || parsedExp <= 0L) {
                throw SyncError(ErrorCode.ERR_URI_INVALID, rawMessage = "invalid exp timestamp")
            }
            exp = parsedExp
        }

        val sStr = frag["s"].orEmpty()
        val oob = if (mode == Handshake.MODE_QR_OOB) {
            if (sStr.isEmpty()) {
                throw SyncError(ErrorCode.ERR_URI_INVALID, rawMessage = "mode=1 requires #s= oob_secret")
            }
            val decoded = try {
                KeysAndAuth.b64uDecode(sStr)
            } catch (_: Exception) {
                throw SyncError(ErrorCode.ERR_URI_INVALID, rawMessage = "invalid #s= oob_secret base64url")
            }
            if (decoded.size != Handshake.OOB_SECRET_SIZE) {
                KeysAndAuth.zeroBytes(decoded)
                throw SyncError(ErrorCode.ERR_URI_INVALID, rawMessage = "invalid #s= oob_secret (expected 16 bytes)")
            }
            decoded
        } else {
            if (sStr.isNotEmpty()) {
                throw SyncError(ErrorCode.ERR_URI_INVALID, rawMessage = "mode=0/2 must omit #s=")
            }
            ByteArray(0)
        }

        val accessKey = frag["k"].orEmpty()
        if (accessKey.isNotEmpty()) {
            if (origin.isEmpty()) {
                KeysAndAuth.zeroBytes(oob)
                throw SyncError(ErrorCode.ERR_URI_INVALID, rawMessage = "access key #k= requires relay origin u")
            }
            if (accessKey.length < 32) {
                KeysAndAuth.zeroBytes(oob)
                throw SyncError(ErrorCode.ERR_URI_INVALID, rawMessage = "access key #k= too short")
            }
        }

        return PairOffer(
            version = 1,
            roomId = roomId,
            mode = mode,
            purpose = purpose,
            endpoint = origin,
            spkiPins = pins,
            expiresAt = exp,
            oobSecret = oob,
            accessKey = accessKey,
        )
    }

    fun formatPairUri(offer: PairOffer): String {
        val roomId = try {
            Crockford.normalizeRoomId(offer.roomId)
        } catch (_: CryptoException) {
            throw SyncError(ErrorCode.ERR_URI_INVALID, rawMessage = "invalid room_id")
        }
        when (offer.mode) {
            Handshake.MODE_DIRECT -> {
                if (offer.purpose != Handshake.PURPOSE_DIRECT || offer.oobSecret.isNotEmpty()) {
                    throw SyncError(ErrorCode.ERR_URI_INVALID, rawMessage = "mode=0 requires p=direct and no oob_secret")
                }
            }
            Handshake.MODE_QR_OOB -> {
                if ((offer.purpose != Handshake.PURPOSE_ONESHOT && offer.purpose != Handshake.PURPOSE_PAIR) ||
                    offer.oobSecret.size != Handshake.OOB_SECRET_SIZE
                ) {
                    throw SyncError(ErrorCode.ERR_URI_INVALID, rawMessage = "mode=1 requires p=oneshot|pair and 16B oob_secret")
                }
            }
            Handshake.MODE_COMMIT_SAS -> {
                if ((offer.purpose != Handshake.PURPOSE_ONESHOT && offer.purpose != Handshake.PURPOSE_PAIR) ||
                    offer.oobSecret.isNotEmpty()
                ) {
                    throw SyncError(ErrorCode.ERR_URI_INVALID, rawMessage = "mode=2 requires p=oneshot|pair and no oob_secret")
                }
            }
            else -> throw SyncError(ErrorCode.ERR_URI_INVALID, rawMessage = "unsupported pair mode")
        }

        var origin = ""
        var pins: List<String> = emptyList()
        if (offer.endpoint.isNotEmpty()) {
            origin = try {
                KeysAndAuth.canonicalRelayOrigin(offer.endpoint)
            } catch (e: CryptoException) {
                throw SyncError(ErrorCode.ERR_URI_INVALID, rawMessage = e.message.orEmpty())
            }
            val originUri = URI(origin)
            if (offer.spkiPins.isNotEmpty()) {
                pins = parseAndValidateSpkiPins(offer.spkiPins.joinToString(","))
            } else if (originUri.scheme == "https" && KeysAndAuth.isIpHost(originUri.host.orEmpty())) {
                throw SyncError(ErrorCode.ERR_URI_INVALID, rawMessage = "bare IP in pair URI requires SPKI pin")
            }
        } else if (offer.spkiPins.isNotEmpty() || offer.accessKey.isNotEmpty()) {
            throw SyncError(ErrorCode.ERR_URI_INVALID, rawMessage = "spkiPins/accessKey in pair URI requires endpoint u")
        }

        if (offer.accessKey.isNotEmpty() && offer.accessKey.length < 32) {
            throw SyncError(ErrorCode.ERR_URI_INVALID, rawMessage = "access key must be >= 32 chars")
        }

        return buildString {
            append("synctool://pair?r=")
            append(roomId)
            append("&m=")
            append(offer.mode)
            append("&p=")
            append(offer.purpose)
            append("&v=1")
            if (origin.isNotEmpty()) {
                append("&u=")
                append(queryEscape(origin))
                if (pins.isNotEmpty()) {
                    append("&pin=")
                    append(pins.joinToString(","))
                }
            }
            if (offer.expiresAt > 0L) {
                append("&exp=")
                append(offer.expiresAt)
            }
            val frags = ArrayList<String>(2)
            if (offer.mode == Handshake.MODE_QR_OOB) {
                frags.add("s=${KeysAndAuth.b64uEncode(offer.oobSecret)}")
            }
            if (offer.accessKey.isNotEmpty()) {
                frags.add("k=${queryEscape(offer.accessKey)}")
            }
            if (frags.isNotEmpty()) {
                append('#')
                append(frags.joinToString("&"))
            }
        }
    }

    fun extractRelayFromPairUri(raw: String): RelayProfile? {
        val trimmed = raw.trim()
        if (!trimmed.lowercase().startsWith("synctool://pair")) return null
        val offer = parsePairUri(trimmed)
        try {
            if (offer.endpoint.isEmpty() || offer.accessKey.isEmpty()) return null
            val tlsMode = if (offer.spkiPins.isNotEmpty()) TlsMode.SPKI_PIN else TlsMode.SYSTEM_CA
            return RelayProfile(
                relayId = KeysAndAuth.deriveRelayId(offer.endpoint),
                endpoint = offer.endpoint,
                accessKey = offer.accessKey,
                tlsMode = tlsMode,
                spkiPins = offer.spkiPins,
                legacySpkiSha256 = offer.spkiPin,
            )
        } finally {
            offer.zeroSecrets()
        }
    }

    private fun parseStrictSyncUri(trimmed: String, expectedHost: String): URI {
        if (trimmed.isEmpty()) {
            throw SyncError(ErrorCode.ERR_URI_INVALID, rawMessage = "empty synctool URI")
        }
        for (c in trimmed) {
            if (c.code <= 0x20 || c.code >= 0x7f) {
                throw SyncError(ErrorCode.ERR_URI_INVALID, rawMessage = "URI contains whitespace or non-ASCII characters")
            }
        }
        val uri = try {
            URI(trimmed)
        } catch (_: Exception) {
            throw SyncError(ErrorCode.ERR_URI_INVALID, rawMessage = "malformed synctool URI")
        }
        if (uri.scheme?.lowercase() != "synctool" || uri.host?.lowercase() != expectedHost) {
            throw SyncError(ErrorCode.ERR_URI_INVALID, rawMessage = "expected synctool://$expectedHost URI")
        }
        val path = uri.rawPath.orEmpty()
        if (path.isNotEmpty() && path != "/") {
            throw SyncError(ErrorCode.ERR_URI_INVALID, rawMessage = "unexpected path in synctool://$expectedHost URI")
        }
        return uri
    }

    private fun validateUriVersion(v: String?) {
        if (v.isNullOrEmpty() || v == "1") return
        val vInt = v.toIntOrNull()
        if (vInt != null && vInt > 1) {
            throw SyncError(
                code = ErrorCode.ERR_UNSUPPORTED_VERSION,
                rawMessage = "unsupported URI version $vInt (supported: 1)",
                rawDetails = mapOf(
                    "version" to JsonPrimitive(vInt),
                    "supported_version" to JsonPrimitive(1),
                ),
            )
        }
        throw SyncError(ErrorCode.ERR_URI_INVALID, rawMessage = "unsupported URI version")
    }

    private fun parseQueryPairs(raw: String?): Map<String, String> {
        if (raw.isNullOrEmpty()) return emptyMap()
        val out = LinkedHashMap<String, String>()
        for (pair in raw.split('&')) {
            if (pair.isEmpty()) continue
            val eqIdx = pair.indexOf('=')
            val rawKey = if (eqIdx >= 0) pair.substring(0, eqIdx) else pair
            val rawVal = if (eqIdx >= 0) pair.substring(eqIdx + 1) else ""
            val key = try {
                URLDecoder.decode(rawKey, StandardCharsets.UTF_8)
            } catch (_: Exception) {
                throw SyncError(ErrorCode.ERR_URI_INVALID, rawMessage = "malformed percent-encoding in URI")
            }
            val value = try {
                URLDecoder.decode(rawVal, StandardCharsets.UTF_8)
            } catch (_: Exception) {
                throw SyncError(ErrorCode.ERR_URI_INVALID, rawMessage = "malformed percent-encoding in URI")
            }
            if (!out.containsKey(key)) {
                out[key] = value
            }
        }
        return out
    }

    private fun queryEscape(s: String): String {
        return URLEncoder.encode(s, StandardCharsets.UTF_8)
    }
}
