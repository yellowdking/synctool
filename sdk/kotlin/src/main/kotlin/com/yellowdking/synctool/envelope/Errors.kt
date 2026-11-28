package com.yellowdking.synctool.envelope

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonPrimitive

object ErrorCode {
    // A. 15 Normative Relay Wire Error Codes (PROTOCOL.md §4)
    const val ERR_BAD_REQUEST: String = "ERR_BAD_REQUEST"
    const val ERR_REPLAY_DETECTED: String = "ERR_REPLAY_DETECTED"
    const val ERR_UNAUTHORIZED_TOKEN: String = "ERR_UNAUTHORIZED_TOKEN"
    const val ERR_SPOOL_DISABLED: String = "ERR_SPOOL_DISABLED"
    const val ERR_DOWNLOAD_LIMIT_EXCEEDED: String = "ERR_DOWNLOAD_LIMIT_EXCEEDED"
    const val ERR_NOT_FOUND: String = "ERR_NOT_FOUND"
    const val ERR_CLOCK_SKEW: String = "ERR_CLOCK_SKEW"
    const val ERR_ROOM_BUSY: String = "ERR_ROOM_BUSY"
    const val ERR_INVALID_STATE: String = "ERR_INVALID_STATE"
    const val ERR_CONFLICT: String = "ERR_CONFLICT"
    const val ERR_ROOM_BURNED: String = "ERR_ROOM_BURNED"
    const val ERR_CHUNK_TOO_LARGE: String = "ERR_CHUNK_TOO_LARGE"
    const val ERR_OFFLINE_QUOTA_EXCEEDED: String = "ERR_OFFLINE_QUOTA_EXCEEDED"
    const val ERR_RATE_LIMITED: String = "ERR_RATE_LIMITED"
    const val ERR_PIPE_PEER_TIMEOUT: String = "ERR_PIPE_PEER_TIMEOUT"

    // B. Client, Crypto & Host Error Codes (ENVELOPE_AND_SDK.md §4.2)
    const val ERR_RELAY_UNREACHABLE: String = "ERR_RELAY_UNREACHABLE"
    const val ERR_TLS_PIN_MISMATCH: String = "ERR_TLS_PIN_MISMATCH"
    const val ERR_TLS_CERT_INVALID: String = "ERR_TLS_CERT_INVALID"
    const val ERR_AUTH_FAILED: String = "ERR_AUTH_FAILED"
    const val ERR_HANDSHAKE_TIMEOUT: String = "ERR_HANDSHAKE_TIMEOUT"
    const val ERR_SAS_MISMATCH: String = "ERR_SAS_MISMATCH"
    const val ERR_CRYPTO_HANDSHAKE_FAILED: String = "ERR_CRYPTO_HANDSHAKE_FAILED"
    const val ERR_CRYPTO_DECRYPT_FAILED: String = "ERR_CRYPTO_DECRYPT_FAILED"
    const val ERR_CRYPTO_SIGNATURE_INVALID: String = "ERR_CRYPTO_SIGNATURE_INVALID"
    const val ERR_STREAM_TRUNCATED: String = "ERR_STREAM_TRUNCATED"
    const val ERR_MSG_REPLAY_DETECTED: String = "ERR_MSG_REPLAY_DETECTED"
    const val ERR_HASH_MISMATCH: String = "ERR_HASH_MISMATCH"
    const val ERR_MANIFEST_INVALID: String = "ERR_MANIFEST_INVALID"
    const val ERR_UNSUPPORTED_VERSION: String = "ERR_UNSUPPORTED_VERSION"
    const val ERR_DEVICE_UNTRUSTED: String = "ERR_DEVICE_UNTRUSTED"
    const val ERR_INTERRUPTED_RESUMABLE: String = "ERR_INTERRUPTED_RESUMABLE"
    const val ERR_URI_INVALID: String = "ERR_URI_INVALID"
    const val ERR_KEYSTORE_ERROR: String = "ERR_KEYSTORE_ERROR"
    const val ERR_STORAGE_IO: String = "ERR_STORAGE_IO"
    const val ERR_CANCELLED: String = "ERR_CANCELLED"
}

object Redact {
    private val RE_SYNC_URI_FRAGMENT = Regex("""(?i)(synctool://[^\s"'<>#]*)#[^\s"'<>]*""")
    private val RE_STANDALONE_FRAGMENT = Regex("""(?i)#(?:(?:k|s)=[^\s"'<>]*|[^\s"'<>]*?(?:&|^)(?:k|s)=[^\s"'<>]*)""")
    private val RE_QUERY_SECRET = Regex("""(?i)([?&](?:k|s)=)[^&#\s"'<>]+""")

    fun redactUri(raw: String): String {
        if (raw.isEmpty()) return ""
        val hashIdx = raw.indexOf('#')
        val withoutFrag = if (hashIdx >= 0) {
            raw.substring(0, hashIdx) + "#[REDACTED]"
        } else {
            raw
        }
        return RE_QUERY_SECRET.replace(withoutFrag, "$1[REDACTED]")
    }

    fun redactMessage(msg: String): String {
        if (msg.isEmpty()) return ""
        var out = RE_SYNC_URI_FRAGMENT.replace(msg, "$1#[REDACTED]")
        out = RE_STANDALONE_FRAGMENT.replace(out, "#[REDACTED]")
        out = RE_QUERY_SECRET.replace(out, "$1[REDACTED]")
        return out
    }

    fun redactJsonElement(el: JsonElement): JsonElement = when (el) {
        is JsonNull -> JsonNull
        is JsonPrimitive -> if (el.isString) JsonPrimitive(redactMessage(el.content)) else el
        is JsonArray -> JsonArray(el.map { redactJsonElement(it) })
        is JsonObject -> JsonObject(el.mapValues { (_, v) -> redactJsonElement(v) })
    }

    fun redactDetails(details: Map<String, JsonElement>?): Map<String, JsonElement>? {
        if (details == null) return null
        return details.mapValues { (_, v) -> redactJsonElement(v) }
    }
}

@Serializable
data class SyncErrorPayload(
    val code: String,
    val retryable: Boolean,
    @SerialName("http_status") val httpStatus: Int = 0,
    val message: String,
    val details: Map<String, JsonElement>? = null,
)

class SyncError(
    val code: String,
    val retryable: Boolean = false,
    val httpStatus: Int = 0,
    rawMessage: String = "",
    rawDetails: Map<String, JsonElement>? = null,
    rawCause: Throwable? = null,
) : Exception(
    buildFormattedMessage(code, rawMessage, rawCause),
    sanitizeCause(rawCause),
) {
    val cleanMessage: String = Redact.redactMessage(
        rawMessage.ifEmpty { rawCause?.message.orEmpty() }
    )
    val details: Map<String, JsonElement>? = Redact.redactDetails(rawDetails)

    fun toPayload(): SyncErrorPayload = SyncErrorPayload(
        code = code,
        retryable = retryable,
        httpStatus = httpStatus,
        message = cleanMessage,
        details = details,
    )

    val isAuthError: Boolean
        get() = code in setOf(
            ErrorCode.ERR_AUTH_FAILED,
            ErrorCode.ERR_UNAUTHORIZED_TOKEN,
            ErrorCode.ERR_DEVICE_UNTRUSTED,
            ErrorCode.ERR_TLS_PIN_MISMATCH,
            ErrorCode.ERR_TLS_CERT_INVALID,
        )

    val isSecurityAlert: Boolean
        get() = code in setOf(
            ErrorCode.ERR_TLS_PIN_MISMATCH,
            ErrorCode.ERR_SAS_MISMATCH,
            ErrorCode.ERR_ROOM_BURNED,
            ErrorCode.ERR_CRYPTO_HANDSHAKE_FAILED,
            ErrorCode.ERR_CRYPTO_DECRYPT_FAILED,
            ErrorCode.ERR_CRYPTO_SIGNATURE_INVALID,
            ErrorCode.ERR_STREAM_TRUNCATED,
            ErrorCode.ERR_HASH_MISMATCH,
            ErrorCode.ERR_MSG_REPLAY_DETECTED,
        )

    val isQuotaExceeded: Boolean
        get() = code in setOf(
            ErrorCode.ERR_OFFLINE_QUOTA_EXCEEDED,
            ErrorCode.ERR_SPOOL_DISABLED,
            ErrorCode.ERR_CHUNK_TOO_LARGE,
            ErrorCode.ERR_DOWNLOAD_LIMIT_EXCEEDED,
        )

    val suggestPipeMode: Boolean
        get() {
            if (code == ErrorCode.ERR_SPOOL_DISABLED || code == ErrorCode.ERR_OFFLINE_QUOTA_EXCEEDED) {
                return true
            }
            val sm = details?.get("suggest_mode")?.jsonPrimitive?.contentOrNull
            return sm == "pipe"
        }

    val isVersionMismatch: Boolean
        get() = code == ErrorCode.ERR_UNSUPPORTED_VERSION

    fun exitCode(): Int = when (code) {
        ErrorCode.ERR_URI_INVALID,
        ErrorCode.ERR_BAD_REQUEST,
        ErrorCode.ERR_MANIFEST_INVALID,
        ErrorCode.ERR_UNSUPPORTED_VERSION -> 2

        ErrorCode.ERR_RELAY_UNREACHABLE,
        ErrorCode.ERR_AUTH_FAILED,
        ErrorCode.ERR_RATE_LIMITED,
        ErrorCode.ERR_PIPE_PEER_TIMEOUT,
        ErrorCode.ERR_HANDSHAKE_TIMEOUT,
        ErrorCode.ERR_REPLAY_DETECTED,
        ErrorCode.ERR_CLOCK_SKEW,
        ErrorCode.ERR_ROOM_BUSY,
        ErrorCode.ERR_INVALID_STATE,
        ErrorCode.ERR_CONFLICT,
        ErrorCode.ERR_CHUNK_TOO_LARGE,
        ErrorCode.ERR_DOWNLOAD_LIMIT_EXCEEDED -> 3

        ErrorCode.ERR_TLS_PIN_MISMATCH,
        ErrorCode.ERR_TLS_CERT_INVALID,
        ErrorCode.ERR_SAS_MISMATCH,
        ErrorCode.ERR_ROOM_BURNED,
        ErrorCode.ERR_CRYPTO_HANDSHAKE_FAILED,
        ErrorCode.ERR_CRYPTO_DECRYPT_FAILED,
        ErrorCode.ERR_CRYPTO_SIGNATURE_INVALID,
        ErrorCode.ERR_STREAM_TRUNCATED,
        ErrorCode.ERR_HASH_MISMATCH,
        ErrorCode.ERR_MSG_REPLAY_DETECTED,
        ErrorCode.ERR_DEVICE_UNTRUSTED,
        ErrorCode.ERR_UNAUTHORIZED_TOKEN -> 4

        ErrorCode.ERR_SPOOL_DISABLED,
        ErrorCode.ERR_OFFLINE_QUOTA_EXCEEDED,
        ErrorCode.ERR_NOT_FOUND -> 5

        ErrorCode.ERR_INTERRUPTED_RESUMABLE -> 6
        else -> 1
    }

    companion object {
        private fun buildFormattedMessage(code: String, rawMsg: String, rawCause: Throwable?): String {
            val base = rawMsg.ifEmpty { rawCause?.message.orEmpty() }
            val safe = Redact.redactMessage(base)
            return if (safe.isNotEmpty()) "$code: $safe" else code
        }

        private fun sanitizeCause(cause: Throwable?): Throwable? {
            if (cause == null) return null
            if (cause is SyncError) return cause
            val msg = cause.message ?: return cause
            val redacted = Redact.redactMessage(msg)
            return if (redacted != msg) {
                Exception(redacted)
            } else {
                cause
            }
        }

        fun isCode(err: Throwable?, wantCode: String): Boolean {
            return (err as? SyncError)?.code == wantCode
        }

        fun isRetryable(err: Throwable?): Boolean {
            return (err as? SyncError)?.retryable == true
        }
    }
}
