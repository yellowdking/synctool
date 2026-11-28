@file:OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)

package com.yellowdking.synctool.envelope

import com.yellowdking.synctool.crypto.KeysAndAuth
import com.yellowdking.synctool.crypto.StreamCipher
import java.io.ByteArrayInputStream
import java.io.File
import java.io.FileInputStream
import java.io.InputStream
import java.nio.channels.Channels
import java.nio.channels.FileChannel
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.StandardOpenOption
import kotlinx.serialization.EncodeDefault
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject

object ManifestCodec {
    const val ENVELOPE_VERSION: Int = 1
    const val MAX_INLINE_PAYLOAD_BYTES: Int = 65536
    const val MAX_MANIFEST_BYTES: Int = StreamCipher.MANIFEST_MAX_RAW_BYTES // 131072
    const val MAX_PADDED_MANIFEST_BYTES: Int = StreamCipher.MAX_MANIFEST_PADDED_BYTES // 135168
    const val MAX_ENCRYPTED_MANIFEST_BYTES: Int = StreamCipher.MAX_MANIFEST_CIPHERTEXT_BYTES // 135216
    const val MAX_MANIFEST_CHUNKS: Int = 4
    const val MAX_BLOBS: Int = StreamCipher.MAX_PART_ID // 63
    const val MAX_BLOB_META_BYTES: Int = 2048
    const val MAX_SAFE_INT_JS: Long = 9007199254740991L

    private val RE_APP_OR_SCHEMA = Regex("^[a-z0-9][a-z0-9._-]{1,63}$")
    private val RE_ROLE = Regex("^[a-z0-9][a-z0-9._-]{0,31}$")
    private val RE_HEX_32 = Regex("^[0-9a-f]{32}$")
    private val RE_HEX_64 = Regex("^[0-9a-f]{64}$")

    val json: Json = Json {
        ignoreUnknownKeys = true
        explicitNulls = false
    }

    fun validate(m: Manifest): ByteArray {
        if (m.envelopeVersion > ENVELOPE_VERSION) {
            throw SyncError(
                code = ErrorCode.ERR_UNSUPPORTED_VERSION,
                rawMessage = "unsupported envelope_version ${m.envelopeVersion} (supported: $ENVELOPE_VERSION)",
                rawDetails = mapOf(
                    "envelope_version" to JsonPrimitive(m.envelopeVersion),
                    "supported_version" to JsonPrimitive(ENVELOPE_VERSION),
                ),
            )
        }
        if (m.envelopeVersion != ENVELOPE_VERSION) {
            throw SyncError(ErrorCode.ERR_MANIFEST_INVALID, rawMessage = "unsupported envelope_version ${m.envelopeVersion}")
        }
        if (!RE_HEX_32.matches(m.msgId)) {
            throw SyncError(ErrorCode.ERR_MANIFEST_INVALID, rawMessage = "msg_id must be 32 lowercase hex chars")
        }
        if (!RE_APP_OR_SCHEMA.matches(m.appId)) {
            throw SyncError(ErrorCode.ERR_MANIFEST_INVALID, rawMessage = "invalid app_id")
        }
        if (!RE_APP_OR_SCHEMA.matches(m.schema)) {
            throw SyncError(ErrorCode.ERR_MANIFEST_INVALID, rawMessage = "invalid schema")
        }
        if (m.createdAt < 0L) {
            throw SyncError(ErrorCode.ERR_MANIFEST_INVALID, rawMessage = "created_at must be non-negative")
        }
        if (!RE_HEX_32.matches(m.sender.deviceId)) {
            throw SyncError(ErrorCode.ERR_MANIFEST_INVALID, rawMessage = "sender.device_id must be 32 lowercase hex chars")
        }
        val labelCodePoints = m.sender.label.codePointCount(0, m.sender.label.length)
        if (labelCodePoints !in 1..64) {
            throw SyncError(ErrorCode.ERR_MANIFEST_INVALID, rawMessage = "sender.label must be 1..64 UTF-8 chars")
        }
        if (m.inlinePayload != null) {
            val inlineBytes = json.encodeToString(JsonObject.serializer(), m.inlinePayload)
                .toByteArray(StandardCharsets.UTF_8)
            if (inlineBytes.size > MAX_INLINE_PAYLOAD_BYTES) {
                throw SyncError(
                    ErrorCode.ERR_MANIFEST_INVALID,
                    rawMessage = "inline_payload exceeds $MAX_INLINE_PAYLOAD_BYTES bytes",
                )
            }
        }
        if (m.blobs.size > MAX_BLOBS) {
            throw SyncError(
                ErrorCode.ERR_MANIFEST_INVALID,
                rawMessage = "blobs count ${m.blobs.size} exceeds max $MAX_BLOBS",
            )
        }
        val seenParts = HashSet<Int>(m.blobs.size)
        for ((i, blob) in m.blobs.withIndex()) {
            if (blob.partId !in 1..MAX_BLOBS) {
                throw SyncError(ErrorCode.ERR_MANIFEST_INVALID, rawMessage = "blobs[$i].part_id out of range 1..$MAX_BLOBS")
            }
            if (!seenParts.add(blob.partId)) {
                throw SyncError(ErrorCode.ERR_MANIFEST_INVALID, rawMessage = "duplicate blobs part_id ${blob.partId}")
            }
            if (!RE_ROLE.matches(blob.role)) {
                throw SyncError(ErrorCode.ERR_MANIFEST_INVALID, rawMessage = "blobs[$i].role invalid")
            }
            val nameCodePoints = blob.name.codePointCount(0, blob.name.length)
            if (nameCodePoints !in 1..255) {
                throw SyncError(ErrorCode.ERR_MANIFEST_INVALID, rawMessage = "blobs[$i].name must be 1..255 chars")
            }
            if (blob.mime.length !in 1..128) {
                throw SyncError(ErrorCode.ERR_MANIFEST_INVALID, rawMessage = "blobs[$i].mime must be 1..128 chars")
            }
            if (blob.size < 0L || blob.size > MAX_SAFE_INT_JS) {
                throw SyncError(ErrorCode.ERR_MANIFEST_INVALID, rawMessage = "blobs[$i].size out of range")
            }
            if (!RE_HEX_64.matches(blob.sha256)) {
                throw SyncError(ErrorCode.ERR_MANIFEST_INVALID, rawMessage = "blobs[$i].sha256 must be 64 lowercase hex")
            }
            val rawKey = try {
                KeysAndAuth.b64uDecode(blob.key)
            } catch (_: Exception) {
                throw SyncError(ErrorCode.ERR_MANIFEST_INVALID, rawMessage = "blobs[$i].key must be 43-char b64u (32B)")
            }
            val keyLen = rawKey.size
            KeysAndAuth.zeroBytes(rawKey)
            if (keyLen != 32) {
                throw SyncError(ErrorCode.ERR_MANIFEST_INVALID, rawMessage = "blobs[$i].key must be 32 bytes")
            }
            val enc = blob.encoding
            if (!enc.isNullOrEmpty() && enc != "identity" && enc != "gzip" && enc != "zstd") {
                throw SyncError(ErrorCode.ERR_MANIFEST_INVALID, rawMessage = "blobs[$i].encoding invalid")
            }
            if (blob.meta != null) {
                val metaBytes = json.encodeToString(JsonObject.serializer(), blob.meta)
                    .toByteArray(StandardCharsets.UTF_8)
                if (metaBytes.size > MAX_BLOB_META_BYTES) {
                    throw SyncError(ErrorCode.ERR_MANIFEST_INVALID, rawMessage = "blobs[$i].meta exceeds $MAX_BLOB_META_BYTES bytes")
                }
            }
        }
        val raw = json.encodeToString(Manifest.serializer(), m).toByteArray(StandardCharsets.UTF_8)
        if (raw.isEmpty() || raw.size > MAX_MANIFEST_BYTES) {
            throw SyncError(ErrorCode.ERR_MANIFEST_INVALID, rawMessage = "manifest exceeds $MAX_MANIFEST_BYTES bytes")
        }
        return raw
    }

    fun marshalManifest(m: Manifest): ByteArray = validate(m)

    fun parseManifest(raw: ByteArray): Manifest {
        if (raw.isEmpty() || raw.size > MAX_MANIFEST_BYTES) {
            throw SyncError(ErrorCode.ERR_MANIFEST_INVALID, rawMessage = "manifest byte length out of bounds")
        }
        val utf8 = try {
            String(raw, StandardCharsets.UTF_8)
        } catch (e: Exception) {
            throw SyncError(ErrorCode.ERR_MANIFEST_INVALID, rawMessage = "invalid UTF-8 manifest", rawCause = e)
        }
        val rootObj = try {
            json.parseToJsonElement(utf8) as? JsonObject
        } catch (e: Exception) {
            throw SyncError(ErrorCode.ERR_MANIFEST_INVALID, rawMessage = "parse manifest json", rawCause = e)
        } ?: throw SyncError(ErrorCode.ERR_MANIFEST_INVALID, rawMessage = "manifest root must be a JSON object")

        val blobsEl = rootObj["blobs"]
        if (blobsEl == null || blobsEl is JsonNull || blobsEl !is JsonArray) {
            throw SyncError(ErrorCode.ERR_MANIFEST_INVALID, rawMessage = "blobs must be an array (use [] when empty)")
        }

        val m = try {
            json.decodeFromJsonElement(Manifest.serializer(), rootObj)
        } catch (e: Exception) {
            throw SyncError(ErrorCode.ERR_MANIFEST_INVALID, rawMessage = "parse manifest fields", rawCause = e)
        }
        validate(m)
        return m
    }

    fun sanitizeFilename(rawName: String): String {
        var name = rawName.replace('\\', '/')
        val slash = name.lastIndexOf('/')
        if (slash >= 0) {
            name = name.substring(slash + 1)
        }
        val sb = StringBuilder()
        var idx = 0
        while (idx < name.length) {
            val cp = name.codePointAt(idx)
            idx += Character.charCount(cp)
            if (cp == 0xFFFD) continue
            if ((cp in 0x202A..0x202E) || (cp in 0x2066..0x2069) || cp == 0x200E || cp == 0x200F || cp == 0x061C) {
                continue
            }
            if (cp == 0 || Character.isISOControl(cp) ||
                cp == '/'.code || cp == '\\'.code || cp == ':'.code || cp == '*'.code ||
                cp == '?'.code || cp == '"'.code || cp == '<'.code || cp == '>'.code || cp == '|'.code
            ) {
                sb.append('_')
                continue
            }
            sb.appendCodePoint(cp)
        }
        var out = sb.toString().trim { it == '.' || it.isWhitespace() }
        if (out.isEmpty() || out.trim('.', '_').isEmpty()) {
            return "blob.bin"
        }
        out = truncateUtf8Safe(out, 199).trim { it == '.' || it.isWhitespace() }
        if (out.isEmpty() || out == "." || out == "..") {
            return "blob.bin"
        }
        val dot = out.indexOf('.')
        val stem = if (dot >= 0) out.substring(0, dot) else out
        if (isWindowsReservedDeviceStem(stem)) {
            out = "_$out"
        }
        return out
    }

    private fun isWindowsReservedDeviceStem(stem: String): Boolean {
        return when (stem.trim().uppercase()) {
            "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$",
            "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
            "COM\u00B9", "COM\u00B2", "COM\u00B3",
            "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
            "LPT\u00B9", "LPT\u00B2", "LPT\u00B3" -> true
            else -> false
        }
    }

    private fun truncateUtf8Safe(s: String, maxBytes: Int): String {
        if (s.toByteArray(StandardCharsets.UTF_8).size <= maxBytes) return s
        val dot = s.lastIndexOf('.')
        val ext = if (dot > 0) s.substring(dot) else ""
        val safeExt = if (ext.toByteArray(StandardCharsets.UTF_8).size in 1..16 && ext.toByteArray(StandardCharsets.UTF_8).size < maxBytes) ext else ""
        val stem = if (safeExt.isNotEmpty()) s.substring(0, s.length - safeExt.length) else s
        val budget = maxBytes - safeExt.toByteArray(StandardCharsets.UTF_8).size
        val sb = StringBuilder()
        var usedBytes = 0
        var idx = 0
        while (idx < stem.length) {
            val cp = stem.codePointAt(idx)
            idx += Character.charCount(cp)
            val cpBytes = String(Character.toChars(cp)).toByteArray(StandardCharsets.UTF_8).size
            if (usedBytes + cpBytes > budget) break
            sb.appendCodePoint(cp)
            usedBytes += cpBytes
        }
        val trimmedStem = sb.toString().trimEnd { it == '.' || it.isWhitespace() }
        return if (trimmedStem.isEmpty()) "blob.bin" else trimmedStem + safeExt
    }
}

@Serializable
data class SenderInfo(
    @SerialName("device_id") val deviceId: String,
    val label: String,
    val platform: String? = null,
)

@Serializable
data class BlobDescriptor(
    @SerialName("part_id") val partId: Int,
    val role: String,
    val name: String,
    val mime: String,
    val size: Long,
    val sha256: String,
    val key: String,
    val encoding: String? = "identity",
    val meta: JsonObject? = null,
)

@Serializable
data class Manifest(
    @EncodeDefault(EncodeDefault.Mode.ALWAYS)
    @SerialName("envelope_version") val envelopeVersion: Int = ManifestCodec.ENVELOPE_VERSION,
    @SerialName("msg_id") val msgId: String,
    @SerialName("app_id") val appId: String,
    val schema: String,
    @SerialName("created_at") val createdAt: Long,
    val sender: SenderInfo,
    @SerialName("inline_payload") val inlinePayload: JsonObject? = null,
    @EncodeDefault(EncodeDefault.Mode.ALWAYS)
    val blobs: List<BlobDescriptor> = emptyList(),
)

/**
 * Outbound binary attachment strictly backed by a repeatable streaming opener or local File
 * (prevents mobile OOM on large videos).
 */
class BlobInput(
    val role: String = "file",
    val name: String,
    val mime: String = "application/octet-stream",
    val encoding: String = "identity",
    val meta: JsonObject? = null,
    private val opener: () -> Pair<InputStream, Long>,
) {
    fun openStream(): Pair<InputStream, Long> = opener()

    companion object {
        fun fromFile(
            file: File,
            role: String = "file",
            name: String = file.name,
            mime: String = inferBasicMime(file.name),
            encoding: String = "identity",
            meta: JsonObject? = null,
        ): BlobInput {
            return BlobInput(
                role = role.ifEmpty { "file" },
                name = name.ifEmpty { file.name },
                mime = mime.ifEmpty { "application/octet-stream" },
                encoding = encoding.ifEmpty { "identity" },
                meta = meta,
                opener = {
                    if (!file.exists() || !file.isFile || Files.isSymbolicLink(file.toPath())) {
                        throw SyncError(ErrorCode.ERR_STORAGE_IO, rawMessage = "blob file must be an existing regular file")
                    }
                    FileInputStream(file) to file.length()
                },
            )
        }

        fun fromStream(
            name: String,
            size: Long,
            role: String = "file",
            mime: String = "application/octet-stream",
            encoding: String = "identity",
            meta: JsonObject? = null,
            open: () -> InputStream,
        ): BlobInput {
            return BlobInput(
                role = role.ifEmpty { "file" },
                name = name,
                mime = mime.ifEmpty { "application/octet-stream" },
                encoding = encoding.ifEmpty { "identity" },
                meta = meta,
                opener = { open() to size },
            )
        }

        fun fromBytes(
            bytes: ByteArray,
            name: String,
            role: String = "file",
            mime: String = "application/octet-stream",
            encoding: String = "identity",
            meta: JsonObject? = null,
        ): BlobInput {
            val copy = bytes.copyOf()
            return BlobInput(
                role = role.ifEmpty { "file" },
                name = name,
                mime = mime.ifEmpty { "application/octet-stream" },
                encoding = encoding.ifEmpty { "identity" },
                meta = meta,
                opener = { ByteArrayInputStream(copy) to copy.size.toLong() },
            )
        }

        private fun inferBasicMime(fileName: String): String {
            val ext = fileName.substringAfterLast('.', "").lowercase()
            return when (ext) {
                "txt", "md", "log" -> "text/plain; charset=utf-8"
                "json" -> "application/json"
                "gz" -> "application/gzip"
                "png" -> "image/png"
                "jpg", "jpeg" -> "image/jpeg"
                "webp" -> "image/webp"
                "gif" -> "image/gif"
                "mp4" -> "video/mp4"
                "m4a" -> "audio/mp4"
                "mp3" -> "audio/mpeg"
                "pdf" -> "application/pdf"
                else -> "application/octet-stream"
            }
        }
    }
}

data class ParcelInput(
    val appId: String = "",
    val schema: String = "generic.parcel.v1",
    val inlinePayload: JsonObject? = null,
    val blobs: List<BlobInput> = emptyList(),
) {
    companion object {
        fun text(appId: String, text: String): ParcelInput = ParcelInput(
            appId = appId,
            schema = "clip.text.v1",
            inlinePayload = buildJsonObject { put("text", JsonPrimitive(text)) },
        )
    }
}

data class ReceivedBlob(
    val descriptor: BlobDescriptor,
    val safeFile: File,
    val safeName: String,
) {
    val safePath: String
        get() = safeFile.absolutePath

    fun openStream(): InputStream = FileInputStream(safeFile)

    fun readBytesVerified(maxBytes: Int = 64 * 1024 * 1024): ByteArray {
        val len = safeFile.length()
        if (len > maxBytes.toLong()) {
            throw SyncError(
                ErrorCode.ERR_STORAGE_IO,
                rawMessage = "blob exceeds max in-memory read limit ($len > $maxBytes); use openStream() or saveToDir()",
            )
        }
        return safeFile.readBytes()
    }

    /**
     * Safely persists the verified attachment into outDir without following symlinks or overwriting files,
     * forcing fsync to disk before deleting the temporary verified file.
     */
    fun saveToDir(outDir: File): File {
        val outPath = outDir.toPath()
        if (Files.exists(outPath, LinkOption.NOFOLLOW_LINKS)) {
            if (Files.isSymbolicLink(outPath) || !Files.isDirectory(outPath, LinkOption.NOFOLLOW_LINKS)) {
                throw SyncError(ErrorCode.ERR_STORAGE_IO, rawMessage = "output directory must be a real directory, not a symlink or file")
            }
        } else {
            try {
                Files.createDirectories(outPath)
            } catch (e: Exception) {
                throw SyncError(ErrorCode.ERR_STORAGE_IO, rawMessage = "create output directory", rawCause = e)
            }
        }

        val cleanName = ManifestCodec.sanitizeFilename(safeName.ifEmpty { descriptor.name })
        val dot = cleanName.lastIndexOf('.')
        val ext = if (dot > 0) cleanName.substring(dot) else ""
        val stem = if (ext.isNotEmpty()) cleanName.substring(0, cleanName.length - ext.length) else cleanName

        var targetPath: java.nio.file.Path? = null
        var outChannel: FileChannel? = null
        for (i in 0 until 10_000) {
            val candName = if (i == 0) cleanName else "${stem}_$i$ext"
            val cand = outPath.resolve(candName)
            if (Files.exists(cand, LinkOption.NOFOLLOW_LINKS)) {
                continue
            }
            try {
                outChannel = FileChannel.open(cand, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)
                targetPath = cand
                break
            } catch (_: java.nio.file.FileAlreadyExistsException) {
                continue
            } catch (e: Exception) {
                throw SyncError(ErrorCode.ERR_STORAGE_IO, rawMessage = "create destination file", rawCause = e)
            }
        }
        if (outChannel == null || targetPath == null) {
            throw SyncError(ErrorCode.ERR_STORAGE_IO, rawMessage = "too many filename collisions in output directory")
        }

        try {
            FileInputStream(safeFile).use { fis ->
                val inCh = fis.channel
                var pos = 0L
                val total = inCh.size()
                while (pos < total) {
                    val transferred = inCh.transferTo(pos, total - pos, outChannel)
                    if (transferred <= 0L) {
                        val buf = ByteArray(65536)
                        val outStream = Channels.newOutputStream(outChannel)
                        fis.channel.position(pos)
                        while (true) {
                            val r = fis.read(buf)
                            if (r < 0) break
                            outStream.write(buf, 0, r)
                        }
                        break
                    }
                    pos += transferred
                }
            }
            outChannel.force(true)
            outChannel.close()
        } catch (e: Exception) {
            try {
                outChannel.close()
            } catch (_: Exception) {
            }
            try {
                Files.deleteIfExists(targetPath)
            } catch (_: Exception) {
            }
            throw SyncError(ErrorCode.ERR_STORAGE_IO, rawMessage = "write destination file", rawCause = e)
        }
        safeFile.delete()
        return targetPath.toFile()
    }
}

data class ReceivedParcel(
    val itemId: String = "",
    val manifest: Manifest,
    val blobs: List<ReceivedBlob> = emptyList(),
)

@Serializable
data class DeviceCardPayload(
    @SerialName("device_id") val deviceId: String,
    @SerialName("sign_pk") val signPk: String,
    @SerialName("kem_pk") val kemPk: String,
    @SerialName("issued_at") val issuedAt: Long,
    @SerialName("card_sig") val cardSig: String,
    val label: String,
    val platform: String? = null,
)

@Serializable
data class MailboxBindPayload(
    @SerialName("relay_origin") val relayOrigin: String,
    @SerialName("mailbox_id") val mailboxId: String,
    @SerialName("deposit_token") val depositToken: String,
)

@Serializable
data class PairBindPayload(
    @SerialName("device_card") val deviceCard: DeviceCardPayload,
    @EncodeDefault(EncodeDefault.Mode.ALWAYS)
    val mailbox: MailboxBindPayload? = null,
)

@Serializable
data class PartLayout(
    @SerialName("part_id") val partId: Int,
    @SerialName("total_bytes") val totalBytes: Long,
    @SerialName("chunk_count") val chunkCount: Int,
)

@Serializable
data class PipeStartPayload(
    @EncodeDefault(EncodeDefault.Mode.ALWAYS)
    val op: String = "pipe_start",
    @SerialName("msg_id") val msgId: String,
    @SerialName("blocks_per_chunk") val blocksPerChunk: Int,
    @EncodeDefault(EncodeDefault.Mode.ALWAYS)
    val parts: List<PartLayout>,
)

@Serializable
data class PipeAckPayload(
    @EncodeDefault(EncodeDefault.Mode.ALWAYS)
    val op: String = "pipe_ack",
    @SerialName("msg_id") val msgId: String,
    @SerialName("ack_mac") val ackMac: String? = null,
)

@Serializable
data class DirectRoomInitPayload(
    @EncodeDefault(EncodeDefault.Mode.ALWAYS)
    @SerialName("proto_v") val protoV: Int = 1,
    @EncodeDefault(EncodeDefault.Mode.ALWAYS)
    val mode: Int = 0,
    @EncodeDefault(EncodeDefault.Mode.ALWAYS)
    val purpose: String = "direct",
    @SerialName("sealed_header") val sealedHeader: String,
    @SerialName("blocks_per_chunk") val blocksPerChunk: Int,
    @EncodeDefault(EncodeDefault.Mode.ALWAYS)
    val parts: List<PartLayout>,
)

@Serializable
data class TransferEvent(
    @EncodeDefault(EncodeDefault.Mode.ALWAYS)
    val type: String = "event",
    @EncodeDefault(EncodeDefault.Mode.ALWAYS)
    val event: String = "transfer_progress",
    val stage: String,
    val direction: String,
    val mode: String,
    @SerialName("msg_id") val msgId: String = "",
    @SerialName("part_id") val partId: Int = 0,
    @SerialName("parts_total") val partsTotal: Int = 0,
    @SerialName("bytes_done") val bytesDone: Long = 0L,
    @SerialName("bytes_total") val bytesTotal: Long = 0L,
    @SerialName("part_bytes_done") val partBytesDone: Long = 0L,
    @SerialName("part_bytes_total") val partBytesTotal: Long = 0L,
    @SerialName("speed_bps") val speedBps: Long = 0L,
    val resumed: Boolean = false,
    val ts: Long = System.currentTimeMillis() / 1000L,
)

@Serializable
data class RelayCertExpiringEvent(
    @EncodeDefault(EncodeDefault.Mode.ALWAYS)
    val type: String = "event",
    @EncodeDefault(EncodeDefault.Mode.ALWAYS)
    val event: String = "relay_cert_expiring_soon",
    @SerialName("relay_id") val relayId: String,
    @SerialName("expires_at") val expiresAt: Long,
    @SerialName("days_remaining") val daysRemaining: Int,
    val severity: String,
)
