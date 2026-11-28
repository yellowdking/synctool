package com.yellowdking.synctool.client

import com.yellowdking.synctool.crypto.CryptoException
import com.yellowdking.synctool.crypto.KeysAndAuth
import com.yellowdking.synctool.envelope.ErrorCode
import com.yellowdking.synctool.envelope.ManifestCodec
import com.yellowdking.synctool.envelope.RelayProfile
import com.yellowdking.synctool.envelope.SyncError
import com.yellowdking.synctool.envelope.SyncUri
import com.yellowdking.synctool.envelope.TlsMode
import java.io.BufferedReader
import java.io.ByteArrayOutputStream
import java.io.Closeable
import java.io.IOException
import java.io.InputStream
import java.io.InputStreamReader
import java.io.InterruptedIOException
import java.net.SocketTimeoutException
import java.net.URI
import java.nio.charset.StandardCharsets
import java.security.KeyStore
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLException
import javax.net.ssl.SSLHandshakeException
import javax.net.ssl.SSLPeerUnverifiedException
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.doubleOrNull
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull
import okhttp3.Call
import okhttp3.Callback
import okhttp3.ConnectionSpec
import okhttp3.Headers
import okhttp3.MediaType
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import okhttp3.TlsVersion
import okio.BufferedSink

internal class PinnedTlsException(
    val syncCode: String,
    val cleanReason: String,
    val details: Map<String, JsonElement>? = null,
    cause: Throwable? = null,
) : CertificateException(cleanReason, cause)

internal data class RequestAuthOptions(
    val contentType: String = "",
    val roomToken: String = "",
    val depositToken: String = "",
    val uploadToken: String = "",
    val mailboxId: String = "",
    val mailboxAuthSeed32: ByteArray? = null,
    val isStream: Boolean = false,
    val streamLength: Long = 0L,
    val streamFactory: (() -> InputStream)? = null,
    val acceptSse: Boolean = false,
)

internal class RawHttpResponse(
    val statusCode: Int,
    val headers: Headers,
    val body: ByteArray,
)

internal data class SseEvent(
    val id: String = "",
    val event: String = "",
    val data: String = "",
)

internal object StopSseException : Exception("stop sse") {
    private fun readResolve(): Any = StopSseException
}

/**
 * O(1)-heap streaming RequestBody with explicit Content-Length (never Transfer-Encoding: chunked).
 */
internal class ChunkStreamRequestBody(
    private val byteLength: Long,
    private val streamFactory: () -> InputStream,
) : RequestBody() {
    override fun contentType(): MediaType = OCTET_STREAM

    override fun contentLength(): Long = byteLength

    override fun writeTo(sink: BufferedSink) {
        streamFactory().use { input ->
            val buf = ByteArray(32 * 1024)
            var remaining = byteLength
            while (remaining > 0L) {
                val want = minOf(buf.size.toLong(), remaining).toInt()
                val read = input.read(buf, 0, want)
                if (read < 0) {
                    throw IOException("stream ended prematurely ($remaining bytes remaining)")
                }
                if (read > 0) {
                    sink.write(buf, 0, read)
                    remaining -= read.toLong()
                }
            }
        }
    }

    companion object {
        private val OCTET_STREAM: MediaType = "application/octet-stream".toMediaType()
    }
}

/**
 * HTTP/1.1 + HTTP/2 TLS 1.3 transport with multi-pin SPKI X509TrustManager,
 * scoped `409 ERR_CLOCK_SKEW` calibration (`X-Sync-TS` ONLY), 3xx redirect blocking,
 * O(1)-heap streaming, and 60s rolling SSE read timeout.
 */
class SyncTransport(rawProfile: RelayProfile) : Closeable {
    val profile: RelayProfile
    private val httpClient: OkHttpClient
    private val sseHttpClient: OkHttpClient

    /**
     * Scoped EXCLUSIVELY to HTTP `X-Sync-TS` request signing headers (`ST-P1-6`).
     * Never used for E2EE signed `Manifest.createdAt`, `SealedHeader.createdAt`, or `DeviceCard.issuedAt`.
     */
    private val clockOffsetSec = AtomicLong(0L)

    init {
        val canonicalOrigin = try {
            KeysAndAuth.canonicalRelayOrigin(rawProfile.endpoint)
        } catch (e: CryptoException) {
            throw SyncError(ErrorCode.ERR_URI_INVALID, rawMessage = e.message.orEmpty())
        }
        if (rawProfile.accessKey.length < 32) {
            throw SyncError(ErrorCode.ERR_URI_INVALID, rawMessage = "relay access_key must be >= 32 characters")
        }
        val originUri = URI(canonicalOrigin)
        val scheme = originUri.scheme.lowercase()
        val host = originUri.host.orEmpty()

        val rawPins = rawProfile.resolvedPins
        val validatedPins = if (rawPins.isNotEmpty()) {
            SyncUri.parseAndValidateSpkiPins(rawPins.joinToString(","))
        } else {
            emptyList()
        }

        val normalizedTlsMode = when (rawProfile.tlsMode.trim().lowercase()) {
            "" -> if (validatedPins.isNotEmpty()) TlsMode.SPKI_PIN else TlsMode.SYSTEM_CA
            TlsMode.SYSTEM_CA, TlsMode.CA_ALIAS -> TlsMode.SYSTEM_CA
            TlsMode.SPKI_PIN -> TlsMode.SPKI_PIN
            else -> throw SyncError(ErrorCode.ERR_URI_INVALID, rawMessage = "unsupported tls_mode")
        }

        if (scheme == "https") {
            if (normalizedTlsMode == TlsMode.SPKI_PIN && validatedPins.isEmpty()) {
                throw SyncError(ErrorCode.ERR_URI_INVALID, rawMessage = "spki_pin mode requires at least 1 64-hex SPKI pin")
            }
            if (normalizedTlsMode == TlsMode.SYSTEM_CA && KeysAndAuth.isIpHost(host)) {
                throw SyncError(ErrorCode.ERR_URI_INVALID, rawMessage = "bare IP relay requires spki_pin mode and 64-hex SPKI pin")
            }
        }

        val relayId = rawProfile.relayId.ifEmpty { KeysAndAuth.deriveRelayId(canonicalOrigin) }
        profile = RelayProfile(
            relayId = relayId,
            alias = rawProfile.alias,
            endpoint = canonicalOrigin,
            accessKey = rawProfile.accessKey,
            tlsMode = normalizedTlsMode,
            spkiPins = validatedPins,
            legacySpkiSha256 = validatedPins.firstOrNull().orEmpty(),
            isDefault = rawProfile.isDefault,
        )

        httpClient = buildOkHttpClient(scheme, normalizedTlsMode, validatedPins)
        sseHttpClient = httpClient.newBuilder()
            .readTimeout(SSE_READ_IDLE_TIMEOUT_SEC, TimeUnit.SECONDS)
            .build()
    }

    fun getClockOffsetSec(): Long = clockOffsetSec.get()

    fun setClockOffsetSec(offsetSec: Long) {
        clockOffsetSec.set(offsetSec.coerceIn(-MAX_CALIBRATED_OFFSET_SEC, MAX_CALIBRATED_OFFSET_SEC))
    }

    fun relayAuthUnixNow(): Long {
        return (System.currentTimeMillis() / 1000L) + clockOffsetSec.get()
    }

    internal suspend fun doControl(
        method: String,
        pathAndQuery: String,
        jsonBodyBytes: ByteArray? = null,
        opts: RequestAuthOptions = RequestAuthOptions(),
    ): RawHttpResponse {
        val effectiveOpts = if (jsonBodyBytes != null && opts.contentType.isEmpty()) {
            opts.copy(contentType = "application/json; charset=utf-8")
        } else {
            opts
        }
        return doSignedWithSkewRetry(method, pathAndQuery, jsonBodyBytes, effectiveOpts)
    }

    internal suspend fun doSignedWithSkewRetry(
        method: String,
        pathAndQuery: String,
        bodyBytes: ByteArray?,
        opts: RequestAuthOptions,
    ): RawHttpResponse {
        for (attempt in 0 until 2) {
            try {
                return doSignedOnce(method, pathAndQuery, bodyBytes, opts)
            } catch (se: SyncError) {
                if (se.code == ErrorCode.ERR_CLOCK_SKEW && attempt == 0) {
                    val serverTs = extractBoundedServerTs(se.details)
                    if (serverTs != null) {
                        calibrateClockOffset(serverTs)
                        continue
                    }
                }
                throw se
            }
        }
        throw SyncError(
            code = ErrorCode.ERR_CLOCK_SKEW,
            retryable = false,
            httpStatus = 409,
            rawMessage = "clock skew persisted after calibration retry",
        )
    }

    private suspend fun doSignedOnce(
        method: String,
        pathAndQuery: String,
        bodyBytes: ByteArray?,
        opts: RequestAuthOptions,
    ): RawHttpResponse {
        val response = executeSignedCall(httpClient, method, pathAndQuery, bodyBytes, opts)
        return withContext(Dispatchers.IO) {
            response.use { resp ->
                val status = resp.code
                if (status in 300..399) {
                    throw SyncError(
                        code = ErrorCode.ERR_RELAY_UNREACHABLE,
                        retryable = false,
                        httpStatus = status,
                        rawMessage = "relay HTTP redirect blocked for credential and SPKI pin safety",
                    )
                }
                val rawBytes = try {
                    readBoundedWithOverflowCheck(resp.body?.byteStream(), MAX_CONTROL_RESPONSE_BYTES)
                } catch (se: SyncError) {
                    throw se
                } catch (e: Throwable) {
                    throw classifyIoException(e)
                }
                if (status in 200..299) {
                    RawHttpResponse(
                        statusCode = status,
                        headers = resp.headers,
                        body = rawBytes,
                    )
                } else {
                    throw decodeWireError(status, resp.headers, rawBytes)
                }
            }
        }
    }

    /**
     * Opens a signed streaming HTTP response (for O(1)-heap chunk downloads or SSE event streams),
     * automatically calibrating `X-Sync-TS` once on `409 ERR_CLOCK_SKEW`.
     */
    internal suspend fun openSignedStream(
        method: String,
        pathAndQuery: String,
        opts: RequestAuthOptions,
    ): Response {
        val client = if (opts.acceptSse) sseHttpClient else httpClient
        for (attempt in 0 until 2) {
            val resp = executeSignedCall(client, method, pathAndQuery, null, opts)
            val status = resp.code
            if (status in 200..299) {
                return resp
            }
            val errBytes = withContext(Dispatchers.IO) {
                resp.use { r ->
                    readUpToCap(r.body?.byteStream(), 64 * 1024)
                }
            }
            if (status in 300..399) {
                throw SyncError(
                    code = ErrorCode.ERR_RELAY_UNREACHABLE,
                    retryable = false,
                    httpStatus = status,
                    rawMessage = "relay HTTP redirect blocked for credential and SPKI pin safety",
                )
            }
            val wireErr = decodeWireError(status, resp.headers, errBytes)
            if (wireErr.code == ErrorCode.ERR_CLOCK_SKEW && attempt == 0) {
                val serverTs = extractBoundedServerTs(wireErr.details)
                if (serverTs != null) {
                    calibrateClockOffset(serverTs)
                    continue
                }
            }
            throw wireErr
        }
        throw SyncError(
            code = ErrorCode.ERR_CLOCK_SKEW,
            retryable = false,
            httpStatus = 409,
            rawMessage = "clock skew persisted after calibration retry",
        )
    }

    private suspend fun executeSignedCall(
        client: OkHttpClient,
        method: String,
        pathAndQuery: String,
        bodyBytes: ByteArray?,
        opts: RequestAuthOptions,
    ): Response {
        val ts = relayAuthUnixNow().toString()
        val nonce = KeysAndAuth.generateNonceHex()

        val bodyBinding: String
        val requestBody: RequestBody?
        if (opts.isStream) {
            bodyBinding = KeysAndAuth.bodyBindingStream(opts.streamLength)
            val factory = opts.streamFactory
                ?: throw SyncError(ErrorCode.ERR_BAD_REQUEST, rawMessage = "missing streamFactory for stream request")
            requestBody = ChunkStreamRequestBody(opts.streamLength, factory)
        } else {
            bodyBinding = KeysAndAuth.bodyBindingControl(bodyBytes)
            val ctMedia = opts.contentType.takeIf { it.isNotEmpty() }?.toMediaType()
            requestBody = when {
                bodyBytes != null -> bodyBytes.toRequestBody(ctMedia)
                method.uppercase() in METHODS_REQUIRING_BODY -> ByteArray(0).toRequestBody(ctMedia)
                else -> null
            }
        }

        val extraBinding = KeysAndAuth.extraTokenBinding(opts.depositToken, opts.uploadToken)
        val sig = KeysAndAuth.signRelayRequest(
            accessKey = profile.accessKey,
            method = method,
            pathAndRawQuery = pathAndQuery,
            ts = ts,
            nonce = nonce,
            bodyBinding = bodyBinding,
            extraTokenBinding = extraBinding,
        )

        val fullUrl = profile.endpoint + pathAndQuery
        val reqBuilder = Request.Builder()
            .url(fullUrl)
            .method(method.uppercase(), requestBody)
            .header(KeysAndAuth.HEADER_CLIENT_AGENT, CLIENT_AGENT_HEADER)
            .header(KeysAndAuth.HEADER_RELAY_TS, ts)
            .header(KeysAndAuth.HEADER_RELAY_NONCE, nonce)
            .header(KeysAndAuth.HEADER_RELAY_SIG, sig)

        if (opts.contentType.isNotEmpty()) {
            reqBuilder.header("Content-Type", opts.contentType)
        }
        if (opts.acceptSse) {
            reqBuilder.header("Accept", "text/event-stream")
        }
        if (opts.roomToken.isNotEmpty()) {
            reqBuilder.header(KeysAndAuth.HEADER_ROOM_TOKEN, opts.roomToken)
        }
        if (opts.depositToken.isNotEmpty()) {
            reqBuilder.header(KeysAndAuth.HEADER_DEPOSIT_TOKEN, opts.depositToken)
        }
        if (opts.uploadToken.isNotEmpty()) {
            reqBuilder.header(KeysAndAuth.HEADER_UPLOAD_TOKEN, opts.uploadToken)
        }
        if (opts.mailboxId.isNotEmpty() && opts.mailboxAuthSeed32 != null) {
            val mbSig = KeysAndAuth.signMailboxRequest(
                mailboxAuthSeed32 = opts.mailboxAuthSeed32,
                method = method,
                pathAndRawQuery = pathAndQuery,
                mailboxId = opts.mailboxId,
                ts = ts,
                nonce = nonce,
                bodyBinding = bodyBinding,
            )
            reqBuilder.header(KeysAndAuth.HEADER_MAILBOX_SIG, mbSig)
        }

        val call = client.newCall(reqBuilder.build())
        return suspendCancellableCoroutine { cont ->
            cont.invokeOnCancellation {
                call.cancel()
            }
            call.enqueue(object : Callback {
                override fun onFailure(call: Call, e: IOException) {
                    if (cont.isCancelled) return
                    cont.resumeWithException(classifyIoException(e))
                }

                override fun onResponse(call: Call, response: Response) {
                    if (cont.isCancelled) {
                        response.close()
                        return
                    }
                    cont.resume(response)
                }
            })
        }
    }

    internal suspend fun consumeSseStream(
        response: Response,
        onEvent: suspend (SseEvent) -> Unit,
    ) {
        withContext(Dispatchers.IO) {
            response.use { resp ->
                val stream = resp.body?.byteStream() ?: return@use
                val reader = BufferedReader(InputStreamReader(stream, StandardCharsets.UTF_8), 16 * 1024)
                var curId = ""
                var curEvent = ""
                val dataLines = ArrayList<String>(4)

                suspend fun flush() {
                    if (curEvent.isEmpty() && dataLines.isEmpty() && curId.isEmpty()) return
                    val ev = SseEvent(
                        id = curId,
                        event = curEvent,
                        data = dataLines.joinToString("\n"),
                    )
                    curId = ""
                    curEvent = ""
                    dataLines.clear()
                    onEvent(ev)
                }

                try {
                    while (true) {
                        coroutineContext.ensureActive()
                        val rawLine = reader.readLine() ?: break
                        val line = rawLine.trimEnd('\r')
                        if (line.isEmpty()) {
                            flush()
                            continue
                        }
                        if (line.startsWith(":")) {
                            // Keepalive `: ping` comment
                            continue
                        }
                        val colon = line.indexOf(':')
                        if (colon < 0) continue
                        val field = line.substring(0, colon)
                        var value = line.substring(colon + 1)
                        if (value.startsWith(" ")) value = value.substring(1)
                        when (field) {
                            "event" -> curEvent = value
                            "data" -> dataLines.add(value)
                            "id" -> curId = value
                        }
                    }
                    flush()
                } catch (_: StopSseException) {
                    // Clean intentional stop (message matched or server sent event: reconnect)
                } catch (ce: CancellationException) {
                    throw ce
                } catch (se: SyncError) {
                    throw se
                } catch (ioe: Throwable) {
                    throw classifyIoException(ioe)
                }
            }
        }
    }

    internal fun classifyIoException(t: Throwable): SyncError {
        if (t is SyncError) return t
        if (t is CancellationException) {
            return SyncError(ErrorCode.ERR_CANCELLED, retryable = false, rawMessage = "operation cancelled", rawCause = t)
        }
        var cur: Throwable? = t
        while (cur != null) {
            if (cur is PinnedTlsException) {
                return SyncError(
                    code = cur.syncCode,
                    retryable = false,
                    rawMessage = cur.cleanReason,
                    rawDetails = cur.details,
                    rawCause = cur,
                )
            }
            if (cur is SyncError) return cur
            cur = cur.cause
        }
        if (t is SSLPeerUnverifiedException || t is SSLHandshakeException || t is SSLException || t is CertificateException) {
            return SyncError(
                code = ErrorCode.ERR_TLS_CERT_INVALID,
                retryable = false,
                rawMessage = "TLS certificate or handshake verification failed",
                rawCause = t,
            )
        }
        if (t is SocketTimeoutException || t is InterruptedIOException) {
            return SyncError(
                code = ErrorCode.ERR_RELAY_UNREACHABLE,
                retryable = true,
                rawMessage = "relay request timed out",
                rawCause = t,
            )
        }
        return SyncError(
            code = ErrorCode.ERR_RELAY_UNREACHABLE,
            retryable = true,
            rawMessage = "relay unreachable",
            rawCause = t,
        )
    }

    override fun close() {
        httpClient.dispatcher.cancelAll()
        sseHttpClient.dispatcher.cancelAll()
        httpClient.connectionPool.evictAll()
    }

    private fun calibrateClockOffset(serverTs: Long) {
        val localNow = System.currentTimeMillis() / 1000L
        val rawOffset = serverTs - localNow
        val clamped = rawOffset.coerceIn(-MAX_CALIBRATED_OFFSET_SEC, MAX_CALIBRATED_OFFSET_SEC)
        clockOffsetSec.set(clamped)
    }

    companion object {
        const val CLIENT_AGENT_HEADER: String = "synctool-kotlin/0.3.0"
        private const val MAX_CONTROL_RESPONSE_BYTES: Int = 4 * 1024 * 1024
        private const val SSE_READ_IDLE_TIMEOUT_SEC: Long = 60L
        private const val MIN_VALID_SERVER_TS: Long = 1_700_000_000L
        private const val MAX_VALID_SERVER_TS: Long = 4_102_444_800L
        private const val MAX_CALIBRATED_OFFSET_SEC: Long = 86_400L
        private val METHODS_REQUIRING_BODY = setOf("POST", "PUT", "PATCH")

        private fun buildOkHttpClient(
            scheme: String,
            tlsMode: String,
            validatedPins: List<String>,
        ): OkHttpClient {
            val builder = OkHttpClient.Builder()
                .connectTimeout(15, TimeUnit.SECONDS)
                .readTimeout(35, TimeUnit.SECONDS)
                .writeTimeout(35, TimeUnit.SECONDS)
                .callTimeout(0, TimeUnit.MILLISECONDS)
                .followRedirects(false)
                .followSslRedirects(false)
                .retryOnConnectionFailure(false)

            if (scheme == "http") {
                builder.connectionSpecs(listOf(ConnectionSpec.CLEARTEXT))
                return builder.build()
            }

            val tls13Only = ConnectionSpec.Builder(ConnectionSpec.MODERN_TLS)
                .tlsVersions(TlsVersion.TLS_1_3)
                .build()
            builder.connectionSpecs(listOf(tls13Only))

            if (tlsMode == TlsMode.SPKI_PIN) {
                val expectedPinPairs = validatedPins.map { it to KeysAndAuth.fromHex(it) }
                val trustManager = object : X509TrustManager {
                    override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {
                        throw CertificateException("client certificates unsupported")
                    }

                    override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {
                        if (chain.isNullOrEmpty()) {
                            throw PinnedTlsException(
                                syncCode = ErrorCode.ERR_TLS_CERT_INVALID,
                                cleanReason = "relay presented no TLS certificate",
                            )
                        }
                        val leaf = chain[0]
                        try {
                            leaf.checkValidity()
                        } catch (e: CertificateException) {
                            throw PinnedTlsException(
                                syncCode = ErrorCode.ERR_TLS_CERT_INVALID,
                                cleanReason = "relay certificate expired or not yet valid",
                                cause = e,
                            )
                        }
                        val spkiDer = leaf.publicKey?.encoded
                            ?: throw PinnedTlsException(
                                syncCode = ErrorCode.ERR_TLS_CERT_INVALID,
                                cleanReason = "relay leaf certificate missing SPKI",
                            )
                        val gotDigest = KeysAndAuth.sha256(spkiDer)
                        var matched = false
                        for ((_, wantDigest) in expectedPinPairs) {
                            if (MessageDigest.isEqual(gotDigest, wantDigest)) {
                                matched = true
                            }
                        }
                        if (!matched) {
                            val gotHex = KeysAndAuth.toLowerHex(gotDigest)
                            throw PinnedTlsException(
                                syncCode = ErrorCode.ERR_TLS_PIN_MISMATCH,
                                cleanReason = "relay leaf SPKI SHA-256 pin mismatch",
                                details = mapOf(
                                    "expected_pin" to JsonPrimitive(expectedPinPairs.first().first),
                                    "got_pin" to JsonPrimitive(gotHex),
                                ),
                            )
                        }
                    }

                    override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
                }

                val sslContext = SSLContext.getInstance("TLSv1.3")
                sslContext.init(null, arrayOf(trustManager), SecureRandom())
                builder.sslSocketFactory(sslContext.socketFactory, trustManager)

                // Custom HostnameVerifier ONLY in spki_pin mode, re-verifying SPKI pin match on the TLS session!
                builder.hostnameVerifier { _, session ->
                    val peerCerts = try {
                        session.peerCertificates
                    } catch (_: SSLPeerUnverifiedException) {
                        return@hostnameVerifier false
                    }
                    val leaf = peerCerts.firstOrNull() as? X509Certificate ?: return@hostnameVerifier false
                    val spkiDer = leaf.publicKey?.encoded ?: return@hostnameVerifier false
                    val gotDigest = KeysAndAuth.sha256(spkiDer)
                    var matched = false
                    for ((_, wantDigest) in expectedPinPairs) {
                        if (MessageDigest.isEqual(gotDigest, wantDigest)) {
                            matched = true
                        }
                    }
                    matched
                }
            } else {
                val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
                tmf.init(null as KeyStore?)
                val sysTrustManager = tmf.trustManagers.filterIsInstance<X509TrustManager>().firstOrNull()
                    ?: throw SyncError(ErrorCode.ERR_TLS_CERT_INVALID, rawMessage = "no system X509TrustManager available")
                val sslContext = SSLContext.getInstance("TLSv1.3")
                sslContext.init(null, arrayOf(sysTrustManager), SecureRandom())
                builder.sslSocketFactory(sslContext.socketFactory, sysTrustManager)
                // Standard hostname verification in system_ca / ca mode!
                builder.hostnameVerifier(HttpsURLConnection.getDefaultHostnameVerifier())
            }

            return builder.build()
        }

        private fun readBoundedWithOverflowCheck(input: InputStream?, maxBytes: Int): ByteArray {
            if (input == null) return ByteArray(0)
            val out = ByteArrayOutputStream()
            val buf = ByteArray(16 * 1024)
            var total = 0
            while (true) {
                val n = input.read(buf)
                if (n < 0) break
                total += n
                if (total > maxBytes) {
                    throw SyncError(
                        code = ErrorCode.ERR_BAD_REQUEST,
                        retryable = false,
                        rawMessage = "control response exceeded $maxBytes-byte limit",
                    )
                }
                out.write(buf, 0, n)
            }
            return out.toByteArray()
        }

        private fun readUpToCap(input: InputStream?, capBytes: Int): ByteArray {
            if (input == null) return ByteArray(0)
            val out = ByteArrayOutputStream()
            val buf = ByteArray(8 * 1024)
            var rem = capBytes
            while (rem > 0) {
                val r = input.read(buf, 0, minOf(buf.size, rem))
                if (r < 0) break
                out.write(buf, 0, r)
                rem -= r
            }
            return out.toByteArray()
        }

        internal fun decodeWireError(statusCode: Int, headers: Headers, body: ByteArray): SyncError {
            val trimmed = String(body, StandardCharsets.UTF_8).trim()
            if (statusCode == 404 && trimmed.isEmpty()) {
                return SyncError(
                    code = ErrorCode.ERR_AUTH_FAILED,
                    retryable = false,
                    httpStatus = statusCode,
                    rawMessage = "relay rejected authentication (silent 404)",
                )
            }
            if (trimmed.isNotEmpty()) {
                val obj = try {
                    ManifestCodec.json.parseToJsonElement(trimmed) as? JsonObject
                } catch (_: Exception) {
                    null
                }
                val wireCode = obj?.get("error")?.jsonPrimitive?.contentOrNull.orEmpty()
                if (wireCode.isNotEmpty()) {
                    val msg = obj?.get("message")?.jsonPrimitive?.contentOrNull.orEmpty()
                    val retryable = obj?.get("retryable")?.jsonPrimitive?.booleanOrNull ?: false
                    val details = LinkedHashMap<String, JsonElement>()
                    for ((k, v) in obj.orEmpty()) {
                        if (k == "error" || k == "message" || k == "retryable") continue
                        details[k] = v
                    }
                    val retryAfter = headers["Retry-After"]
                    if (!retryAfter.isNullOrBlank()) {
                        details["retry_after"] = JsonPrimitive(retryAfter.trim())
                        retryAfter.trim().toLongOrNull()?.let { sec ->
                            details["retry_after_sec"] = JsonPrimitive(sec)
                        }
                    }
                    return SyncError(
                        code = wireCode,
                        retryable = retryable,
                        httpStatus = statusCode,
                        rawMessage = msg,
                        rawDetails = details.takeIf { it.isNotEmpty() },
                    )
                }
            }
            if (statusCode == 404) {
                return SyncError(
                    code = ErrorCode.ERR_AUTH_FAILED,
                    retryable = false,
                    httpStatus = statusCode,
                    rawMessage = "relay returned stealth 404",
                )
            }
            return SyncError(
                code = ErrorCode.ERR_RELAY_UNREACHABLE,
                retryable = statusCode >= 500,
                httpStatus = statusCode,
                rawMessage = "unexpected relay status $statusCode",
            )
        }

        private fun extractBoundedServerTs(details: Map<String, JsonElement>?): Long? {
            val prim = details?.get("server_ts")?.jsonPrimitive ?: return null
            val asLong = prim.longOrNull ?: prim.doubleOrNull?.takeIf { it.isFinite() }?.toLong() ?: return null
            return asLong.takeIf { it in MIN_VALID_SERVER_TS..MAX_VALID_SERVER_TS }
        }
    }
}
