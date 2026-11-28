package com.yellowdking.synctool.client

import com.yellowdking.synctool.crypto.Crockford
import com.yellowdking.synctool.crypto.CryptoException
import com.yellowdking.synctool.crypto.HandshakeResult
import com.yellowdking.synctool.crypto.KeysAndAuth
import com.yellowdking.synctool.crypto.SealedHeader
import com.yellowdking.synctool.crypto.SealedHeaderOpenResult
import com.yellowdking.synctool.crypto.StreamCipher
import com.yellowdking.synctool.envelope.BlobDescriptor
import com.yellowdking.synctool.envelope.BlobInput
import com.yellowdking.synctool.envelope.DEFAULT_SEEN_MSG_RETENTION_DAYS
import com.yellowdking.synctool.envelope.ErrorCode
import com.yellowdking.synctool.envelope.Manifest
import com.yellowdking.synctool.envelope.ManifestCodec
import com.yellowdking.synctool.envelope.PairBindPayload
import com.yellowdking.synctool.envelope.ParcelInput
import com.yellowdking.synctool.envelope.PartLayout
import com.yellowdking.synctool.envelope.SenderInfo
import com.yellowdking.synctool.envelope.SyncError
import com.yellowdking.synctool.envelope.SyncUri
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileInputStream
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.StandardCopyOption
import java.security.MessageDigest
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull

internal class ActiveRoomSession(
    val roomId: String,
    val pipeId: String,
    val token: String,
    var lastSeq: Int,
    val hs: HandshakeResult,
)

internal class LocalPairBindBundle(
    val payload: PairBindPayload,
    val inboundTokenId: String,
    val inboundTokenHash: String,
)

internal class PreparedBlob(
    val partId: Int,
    val blobKey32: ByteArray,
    val desc: BlobDescriptor,
    val input: BlobInput,
)

internal class PreparedParcel(
    val msgIdRaw: ByteArray,
    val msgId: String,
    val createdAt: Long,
    val manifest: Manifest,
    val manifestUtf8: ByteArray,
    val manifestPad: ByteArray,
    val manifestSha256: ByteArray,
    val blobs: List<PreparedBlob>,
    val parts: List<PartLayout>,
    val totalEnc: Long,
) {
    fun zero() {
        KeysAndAuth.zeroBytes(manifestUtf8, manifestPad)
        for (b in blobs) {
            KeysAndAuth.zeroBytes(b.blobKey32)
        }
    }
}

private const val MAX_FUTURE_CREATED_AT_SKEW_SEC: Long = 600L

internal fun mailboxAuthOpts(
    st: SyncClient.InitializedState,
    acceptSse: Boolean = false,
): RequestAuthOptions = RequestAuthOptions(
    mailboxId = st.mailboxKeys.mailboxId,
    mailboxAuthSeed32 = st.mailboxKeys.authSeed,
    acceptSse = acceptSse,
)

// --- Room Signaling, Polling & Events ---

internal suspend fun SyncClient.createRoom(
    roomId: String,
    ttlSec: Int,
    initialMsg: ByteArray?,
): RoomCreateResp {
    val effectiveTtl = if (ttlSec <= 0) 300 else ttlSec
    val reqBytes = ManifestCodec.json.encodeToString(
        RoomCreateReq.serializer(),
        RoomCreateReq(
            roomId = roomId,
            ttlSec = effectiveTtl,
            initialMsgB64 = initialMsg?.takeIf { it.isNotEmpty() }?.let { KeysAndAuth.b64uEncode(it) },
        ),
    ).toByteArray(StandardCharsets.UTF_8)

    val resp = transport.doControl("POST", "/v1/rooms", reqBytes)
    return ManifestCodec.json.decodeFromString(
        RoomCreateResp.serializer(),
        String(resp.body, StandardCharsets.UTF_8),
    )
}

internal suspend fun SyncClient.joinRoom(roomId: String): RoomJoinResp {
    val resp = transport.doControl(
        method = "POST",
        pathAndQuery = "/v1/rooms/$roomId/join",
        jsonBodyBytes = "{}".toByteArray(StandardCharsets.UTF_8),
    )
    return ManifestCodec.json.decodeFromString(
        RoomJoinResp.serializer(),
        String(resp.body, StandardCharsets.UTF_8),
    )
}

internal suspend fun SyncClient.postRoomMessage(
    roomId: String,
    roomToken: String,
    kind: String,
    payload: ByteArray,
): Int {
    val reqBytes = ManifestCodec.json.encodeToString(
        RoomPostMsgReq.serializer(),
        RoomPostMsgReq(
            kind = kind,
            msgB64 = KeysAndAuth.b64uEncode(payload),
        ),
    ).toByteArray(StandardCharsets.UTF_8)

    val resp = transport.doControl(
        method = "POST",
        pathAndQuery = "/v1/rooms/$roomId/messages",
        jsonBodyBytes = reqBytes,
        opts = RequestAuthOptions(roomToken = roomToken),
    )
    return runCatching {
        ManifestCodec.json.decodeFromString(
            RoomPostMsgResp.serializer(),
            String(resp.body, StandardCharsets.UTF_8),
        ).seq
    }.getOrDefault(0)
}

internal suspend fun SyncClient.closeRoomBestEffort(roomId: String, roomToken: String, reason: String) {
    if (roomId.isEmpty() || roomToken.isEmpty()) return
    withContext(NonCancellable) {
        withTimeoutOrNull(5_000L) {
            runCatching {
                val reqBytes = ManifestCodec.json.encodeToString(
                    RoomCloseReq.serializer(),
                    RoomCloseReq(reason = reason),
                ).toByteArray(StandardCharsets.UTF_8)
                transport.doControl(
                    method = "POST",
                    pathAndQuery = "/v1/rooms/$roomId/close",
                    jsonBodyBytes = reqBytes,
                    opts = RequestAuthOptions(roomToken = roomToken),
                )
            }
        }
    }
}

internal suspend fun SyncClient.waitForPeerRoomMessage(
    roomId: String,
    roomToken: String,
    expectedFrom: String,
    sinceSeq: Int,
): Pair<RoomMessageWire, Int> {
    var curSince = sinceSeq
    var usePoll = false
    var backoffMs = 250L

    while (true) {
        currentCoroutineContext().ensureActive()
        if (!usePoll) {
            val path = "/v1/rooms/$roomId/events?since=$curSince&mode=sse"
            val streamStartMs = System.currentTimeMillis()
            var found: RoomMessageWire? = null
            var terminalErr: SyncError? = null
            var gotReconnect = false

            try {
                val httpResp = transport.openSignedStream(
                    method = "GET",
                    pathAndQuery = path,
                    opts = RequestAuthOptions(roomToken = roomToken, acceptSse = true),
                )
                transport.consumeSseStream(httpResp) { ev ->
                    when (ev.event) {
                        "message" -> {
                            val m = runCatching {
                                ManifestCodec.json.decodeFromString(RoomMessageWire.serializer(), ev.data)
                            }.getOrNull() ?: return@consumeSseStream
                            if (m.seq > curSince) curSince = m.seq
                            if (m.from == expectedFrom) {
                                found = m
                                throw StopSseException
                            }
                        }
                        "burned" -> {
                            terminalErr = SyncError(ErrorCode.ERR_ROOM_BURNED, httpStatus = 410, rawMessage = "room burned by peer")
                            throw StopSseException
                        }
                        "closed" -> {
                            terminalErr = SyncError(ErrorCode.ERR_NOT_FOUND, httpStatus = 404, rawMessage = "room closed by peer")
                            throw StopSseException
                        }
                        "reconnect" -> {
                            gotReconnect = true
                            throw StopSseException
                        }
                    }
                }
            } catch (ce: CancellationException) {
                throw ce
            } catch (se: SyncError) {
                if (se.isAuthError || se.isSecurityAlert || se.isVersionMismatch ||
                    se.code == ErrorCode.ERR_ROOM_BURNED || se.code == ErrorCode.ERR_NOT_FOUND
                ) {
                    throw se
                }
                usePoll = true
                delayWithRetryAfter(se, backoffMs)
                backoffMs = (backoffMs * 2).coerceAtMost(5_000L)
                continue
            }

            found?.let { return it to curSince }
            terminalErr?.let { throw it }

            if (gotReconnect) {
                backoffMs = 250L
                continue
            }
            // Immediate EOF without `reconnect`: apply backoff before falling back to poll to avoid 0ms spin!
            if (System.currentTimeMillis() - streamStartMs < 1_000L) {
                usePoll = true
                delay(backoffMs)
                backoffMs = (backoffMs * 2).coerceAtMost(5_000L)
            }
            continue
        }

        // Long-Poll fallback
        val pollPath = "/v1/rooms/$roomId/events?since=$curSince&mode=poll&wait_sec=20"
        val resp = try {
            transport.doControl("GET", pollPath, opts = RequestAuthOptions(roomToken = roomToken))
        } catch (ce: CancellationException) {
            throw ce
        } catch (se: SyncError) {
            if (se.isAuthError || se.isSecurityAlert || se.isVersionMismatch ||
                se.code == ErrorCode.ERR_ROOM_BURNED || se.code == ErrorCode.ERR_NOT_FOUND || !se.retryable
            ) {
                throw se
            }
            delayWithRetryAfter(se, backoffMs)
            backoffMs = (backoffMs * 2).coerceAtMost(5_000L)
            continue
        }

        backoffMs = 250L
        val pr = try {
            ManifestCodec.json.decodeFromString(
                RoomPollResp.serializer(),
                String(resp.body, StandardCharsets.UTF_8),
            )
        } catch (e: Exception) {
            throw SyncError(ErrorCode.ERR_BAD_REQUEST, httpStatus = resp.statusCode, rawMessage = "decode room poll", rawCause = e)
        }

        for (m in pr.messages) {
            if (m.seq > curSince) curSince = m.seq
            if (m.from == expectedFrom) {
                return m to curSince
            }
        }
        if (pr.state == "burned") {
            throw SyncError(ErrorCode.ERR_ROOM_BURNED, httpStatus = 410, rawMessage = "room burned: ${pr.reason}")
        }
        if (pr.state == "closed") {
            throw SyncError(ErrorCode.ERR_NOT_FOUND, httpStatus = 404, rawMessage = "room closed: ${pr.reason}")
        }
    }
}

internal suspend fun delayWithRetryAfter(se: SyncError, defaultMs: Long) {
    val retrySec = se.details?.get("retry_after_sec")?.jsonPrimitive?.longOrNull
    val waitMs = if (retrySec != null && retrySec > 0L) {
        (retrySec * 1000L).coerceAtMost(15_000L)
    } else {
        defaultMs
    }
    delay(waitMs)
}

internal fun parseRoomInput(pairInput: String): Pair<String, ByteArray> {
    val trimmed = pairInput.trim()
    if (trimmed.lowercase().startsWith("synctool://")) {
        val offer = SyncUri.parsePairUri(trimmed)
        return offer.roomId to offer.oobSecret
    }
    val roomId = try {
        Crockford.normalizeRoomId(trimmed)
    } catch (_: CryptoException) {
        throw SyncError(ErrorCode.ERR_URI_INVALID, rawMessage = "invalid pair URI or 8-char room code")
    }
    return roomId to ByteArray(0)
}

internal suspend fun SyncClient.joinAndReadRawM1(roomId: String): Pair<RoomJoinResp, ByteArray> {
    var joined = joinRoom(roomId)
    if (joined.messages.isEmpty()) {
        val (m1Wire, nextSeq) = waitForPeerRoomMessage(roomId, joined.receiverToken, "sender", joined.seq)
        joined = joined.copy(seq = nextSeq, messages = listOf(m1Wire))
    }
    val rawM1 = try {
        KeysAndAuth.b64uDecode(joined.messages[0].msgB64)
    } catch (_: Exception) {
        closeRoomBestEffort(roomId, joined.receiverToken, "verify_failed")
        throw SyncError(ErrorCode.ERR_CRYPTO_HANDSHAKE_FAILED, rawMessage = "decode M1 base64url")
    }
    return joined to rawM1
}

internal suspend fun SyncClient.joinAndReadM1(roomId: String): Pair<RoomJoinResp, HsM1Wire> {
    val (joined, rawM1) = joinAndReadRawM1(roomId)
    val m1 = try {
        ManifestCodec.json.decodeFromString(HsM1Wire.serializer(), String(rawM1, StandardCharsets.UTF_8))
    } catch (_: Exception) {
        closeRoomBestEffort(roomId, joined.receiverToken, "verify_failed")
        throw SyncError(ErrorCode.ERR_CRYPTO_HANDSHAKE_FAILED, rawMessage = "invalid M1 json")
    }
    if (m1.protoV > 1) {
        closeRoomBestEffort(roomId, joined.receiverToken, "verify_failed")
        throw SyncError(
            code = ErrorCode.ERR_UNSUPPORTED_VERSION,
            rawMessage = "unsupported M1 proto_v ${m1.protoV}",
            rawDetails = mapOf("proto_v" to JsonPrimitive(m1.protoV), "supported_proto_v" to JsonPrimitive(1)),
        )
    }
    if (m1.protoV != 1) {
        closeRoomBestEffort(roomId, joined.receiverToken, "verify_failed")
        throw SyncError(ErrorCode.ERR_CRYPTO_HANDSHAKE_FAILED, rawMessage = "invalid M1 proto_v")
    }
    return joined to m1
}

// --- Identity, KeyStore & Deposit Token Helpers ---

internal suspend fun SyncClient.deleteRelayDepositTokenStrict(
    st: SyncClient.InitializedState,
    tokenId: String,
) {
    if (tokenId.isEmpty()) return
    try {
        transport.doControl(
            method = "DELETE",
            pathAndQuery = "/v1/mailboxes/${st.mailboxKeys.mailboxId}/deposit-tokens/$tokenId",
            opts = mailboxAuthOpts(st),
        )
    } catch (se: SyncError) {
        if (se.code != ErrorCode.ERR_NOT_FOUND && se.code != ErrorCode.ERR_SPOOL_DISABLED) {
            throw se
        }
    }
}

internal suspend fun SyncClient.registerPeerDepositToken(
    st: SyncClient.InitializedState,
): Triple<String, String, String> {
    val rawToken = KeysAndAuth.generateTokenB64u()
    val idBytes = KeysAndAuth.randomBytes(8)
    val tokenId = "dt_${KeysAndAuth.toLowerHex(idBytes)}"
    val tokenHashHex = KeysAndAuth.hashDepositToken(rawToken)
    val reqBytes = ManifestCodec.json.encodeToString(
        MailboxDepositTokenSpec.serializer(),
        MailboxDepositTokenSpec(tokenId = tokenId, tokenHashHex = tokenHashHex),
    ).toByteArray(StandardCharsets.UTF_8)

    transport.doControl(
        method = "POST",
        pathAndQuery = "/v1/mailboxes/${st.mailboxKeys.mailboxId}/deposit-tokens",
        jsonBodyBytes = reqBytes,
        opts = mailboxAuthOpts(st),
    )
    return Triple(tokenId, tokenHashHex, rawToken)
}

internal suspend fun SyncClient.deleteRelayDepositTokenBestEffort(
    st: SyncClient.InitializedState,
    tokenId: String,
) {
    if (tokenId.isEmpty()) return
    withContext(NonCancellable) {
        withTimeoutOrNull(5_000L) {
            runCatching {
                transport.doControl(
                    method = "DELETE",
                    pathAndQuery = "/v1/mailboxes/${st.mailboxKeys.mailboxId}/deposit-tokens/$tokenId",
                    opts = mailboxAuthOpts(st),
                )
            }
        }
    }
}

// --- Replay Guard, SealedHeader Verification, Parcel Preparation & Storage Helpers ---

internal suspend fun SyncClient.claimInFlightMsgId(msgId: String) {
    val norm = msgId.lowercase()
    inFlightMutex.withLock {
        if (!inFlightMsgIds.add(norm)) {
            throw SyncError(
                code = ErrorCode.ERR_MSG_REPLAY_DETECTED,
                rawMessage = "msg_id is already being processed concurrently",
                rawDetails = mapOf("msg_id" to JsonPrimitive(norm)),
            )
        }
    }
}

internal suspend fun SyncClient.releaseInFlightMsgId(msgId: String) {
    val norm = msgId.lowercase()
    inFlightMutex.withLock {
        inFlightMsgIds.remove(norm)
    }
}

internal suspend fun SyncClient.openAndVerifySealedHeader(
    st: SyncClient.InitializedState,
    hdrBytes: ByteArray,
): SealedHeaderOpenResult {
    val (_, msgIdHex) = try {
        SealedHeader.parseClearHeaderMsgId(hdrBytes)
    } catch (e: CryptoException) {
        throw SyncError(ErrorCode.ERR_CRYPTO_SIGNATURE_INVALID, rawMessage = "parse sealed_header", rawCause = e)
    }
    if (keyStore.hasSeenMsgId(msgIdHex)) {
        throw SyncError(
            code = ErrorCode.ERR_MSG_REPLAY_DETECTED,
            rawMessage = "msg_id already processed (replay rejected)",
            rawDetails = mapOf("msg_id" to JsonPrimitive(msgIdHex)),
        )
    }

    // Snapshot non-revoked trusted sender device cards before synchronous crypto open
    val candidateDevices = keyStore.listDevices().associateBy { it.deviceId.lowercase() }
    val opened = try {
        SealedHeader.open0RttHeader(st.deviceKeys, hdrBytes) { senderId ->
            val card = candidateDevices[senderId.lowercase()]
            if (card == null || card.revoked) {
                null
            } else {
                runCatching { KeysAndAuth.b64uDecode(card.signPk) }.getOrNull()?.takeIf { it.size == 32 }
            }
        }
    } catch (e: CryptoException.UntrustedSender) {
        throw SyncError(ErrorCode.ERR_DEVICE_UNTRUSTED, rawMessage = "sender device untrusted or revoked", rawCause = e)
    } catch (e: CryptoException.DecryptFailed) {
        throw SyncError(ErrorCode.ERR_CRYPTO_DECRYPT_FAILED, rawMessage = "decrypt sealed_header", rawCause = e)
    } catch (e: CryptoException) {
        throw SyncError(ErrorCode.ERR_CRYPTO_SIGNATURE_INVALID, rawMessage = "verify sealed_header", rawCause = e)
    }

    // Enforce signed `created_at` freshness window `[max(now - 30*86400, watermark), now + 600]` (`ST-P1-7`)
    val nowSec = System.currentTimeMillis() / 1000L
    val watermark = keyStore.getReplayWatermark()
    val minAllowed = maxOf(0L, nowSec - DEFAULT_SEEN_MSG_RETENTION_DAYS * 86_400L, watermark)
    val maxAllowed = nowSec + MAX_FUTURE_CREATED_AT_SKEW_SEC
    if (opened.createdAt < minAllowed || opened.createdAt > maxAllowed) {
        opened.zero()
        throw SyncError(
            code = ErrorCode.ERR_MSG_REPLAY_DETECTED,
            rawMessage = "sealed_header created_at (${opened.createdAt}) outside freshness window [$minAllowed, $maxAllowed]",
            rawDetails = mapOf(
                "msg_id" to JsonPrimitive(opened.msgId),
                "created_at" to JsonPrimitive(opened.createdAt),
            ),
        )
    }
    return opened
}

internal suspend fun SyncClient.prepareParcel(
    st: SyncClient.InitializedState,
    input: ParcelInput,
    blocksPerChunk: Int,
): PreparedParcel = withContext(Dispatchers.IO) {
    if (input.blobs.size > ManifestCodec.MAX_BLOBS) {
        throw SyncError(ErrorCode.ERR_MANIFEST_INVALID, rawMessage = "blobs count exceeds max ${ManifestCodec.MAX_BLOBS}")
    }
    val bpc = if (blocksPerChunk <= 0) 16 else blocksPerChunk
    val msgIdRaw = KeysAndAuth.randomBytes(KeysAndAuth.MSG_ID_RAW_SIZE)
    val msgIdHex = KeysAndAuth.toLowerHex(msgIdRaw)

    val parcelAppId = input.appId.ifBlank { appId }
    val schema = input.schema.ifBlank { "generic.parcel.v1" }
    // Pure local wall-clock for E2EE signed timestamps (`ST-P1-6`)
    val createdAt = System.currentTimeMillis() / 1000L

    val blobs = ArrayList<PreparedBlob>(input.blobs.size)
    val descs = ArrayList<BlobDescriptor>(input.blobs.size)
    val hashBuf = ByteArray(64 * 1024)

    try {
        for ((idx, bi) in input.blobs.withIndex()) {
            currentCoroutineContext().ensureActive()
            val partId = idx + 1
            val (stream, declaredSize) = bi.openStream()
            val md = MessageDigest.getInstance("SHA-256")
            var counted = 0L
            try {
                stream.use { ins ->
                    while (true) {
                        val r = ins.read(hashBuf)
                        if (r < 0) break
                        if (r > 0) {
                            md.update(hashBuf, 0, r)
                            counted += r.toLong()
                        }
                    }
                }
            } catch (se: SyncError) {
                throw se
            } catch (e: Exception) {
                throw SyncError(ErrorCode.ERR_STORAGE_IO, rawMessage = "hash blob stream", rawCause = e)
            }
            val actualSize = if (declaredSize >= 0L && counted != declaredSize) counted else counted
            val blobKey = KeysAndAuth.randomBytes(32)
            val desc = BlobDescriptor(
                partId = partId,
                role = bi.role.ifEmpty { "file" },
                name = bi.name.ifEmpty { "part_$partId.bin" },
                mime = bi.mime.ifEmpty { "application/octet-stream" },
                size = actualSize,
                sha256 = KeysAndAuth.toLowerHex(md.digest()),
                key = KeysAndAuth.b64uEncode(blobKey),
                encoding = bi.encoding.ifEmpty { "identity" },
                meta = bi.meta,
            )
            blobs.add(PreparedBlob(partId = partId, blobKey32 = blobKey, desc = desc, input = bi))
            descs.add(desc)
        }

        val manifest = Manifest(
            envelopeVersion = ManifestCodec.ENVELOPE_VERSION,
            msgId = msgIdHex,
            appId = parcelAppId,
            schema = schema,
            createdAt = createdAt,
            sender = SenderInfo(deviceId = st.deviceKeys.deviceId, label = st.deviceLabel, platform = platform),
            inlinePayload = input.inlinePayload,
            blobs = descs,
        )
        val manifestUtf8 = ManifestCodec.marshalManifest(manifest)
        val manifestPad = try {
            StreamCipher.padManifest(manifestUtf8)
        } catch (e: CryptoException) {
            throw SyncError(ErrorCode.ERR_MANIFEST_INVALID, rawMessage = "pad manifest", rawCause = e)
        }
        val manifestSha = KeysAndAuth.sha256(manifestUtf8)

        val parts = ArrayList<PartLayout>(1 + blobs.size)
        val p0Enc = StreamCipher.encryptedPartSize(manifestPad.size.toLong())
        parts.add(PartLayout(partId = 0, totalBytes = p0Enc, chunkCount = StreamCipher.transportChunkCount(p0Enc, bpc)))
        var totalEnc = p0Enc
        for (b in blobs) {
            val encSz = StreamCipher.encryptedPartSize(b.desc.size)
            parts.add(PartLayout(partId = b.partId, totalBytes = encSz, chunkCount = StreamCipher.transportChunkCount(encSz, bpc)))
            totalEnc += encSz
        }

        PreparedParcel(
            msgIdRaw = msgIdRaw, msgId = msgIdHex, createdAt = createdAt, manifest = manifest,
            manifestUtf8 = manifestUtf8, manifestPad = manifestPad, manifestSha256 = manifestSha,
            blobs = blobs, parts = parts, totalEnc = totalEnc,
        )
    } catch (t: Throwable) {
        for (b in blobs) KeysAndAuth.zeroBytes(b.blobKey32)
        throw t
    }
}

internal suspend fun SyncClient.pullAndVerifyManifest(
    msgIdRaw16: ByteArray,
    msgIdHex: String,
    p0Key32: ByteArray,
    p0Np7: ByteArray,
    p0Layout: PartLayout,
    opened: SealedHeaderOpenResult?,
    fetchChunk: suspend (txIdx: Int) -> ByteArray,
): Pair<Manifest, ByteArray> {
    if (p0Layout.totalBytes <= 0L ||
        p0Layout.totalBytes > ManifestCodec.MAX_ENCRYPTED_MANIFEST_BYTES.toLong() ||
        p0Layout.chunkCount < 1 ||
        p0Layout.chunkCount > ManifestCodec.MAX_MANIFEST_CHUNKS
    ) {
        throw SyncError(
            code = ErrorCode.ERR_MANIFEST_INVALID,
            rawMessage = "part_id=0 layout out of bounds (bytes=${p0Layout.totalBytes} chunks=${p0Layout.chunkCount})",
        )
    }

    val sc = StreamCipher(p0Key32, p0Np7, msgIdRaw16, 0)
    val paddedOut = ByteArrayOutputStream()
    var blkIdx = 0u
    var sawFinal = false
    var totalEncSeen = 0L
    try {
        for (tx in 0 until p0Layout.chunkCount) {
            if (sawFinal) {
                throw SyncError(ErrorCode.ERR_STREAM_TRUNCATED, rawMessage = "extra transport chunks after final manifest block")
            }
            val chunkBytes = fetchChunk(tx)
            totalEncSeen += chunkBytes.size.toLong()
            if (totalEncSeen > p0Layout.totalBytes || totalEncSeen > ManifestCodec.MAX_ENCRYPTED_MANIFEST_BYTES.toLong()) {
                throw SyncError(ErrorCode.ERR_MANIFEST_INVALID, rawMessage = "part_id=0 stream exceeded manifest byte budget")
            }
            val (blocksDone, isFin) = decryptChunkBufferInto(
                sc = sc,
                chunkBytes = chunkBytes,
                startBlockIdx = blkIdx,
                totalBlocks = 0u,
                isLastTransportChunk = tx == p0Layout.chunkCount - 1,
                alreadySawFinal = sawFinal,
                sink = paddedOut,
            )
            blkIdx += blocksDone
            if (isFin) sawFinal = true
        }
    } finally {
        sc.zero()
    }

    if (!sawFinal || totalEncSeen != p0Layout.totalBytes) {
        throw SyncError(ErrorCode.ERR_STREAM_TRUNCATED, rawMessage = "manifest stream missing final block or byte count mismatch")
    }

    val rawManifest = try {
        StreamCipher.unpadManifest(paddedOut.toByteArray())
    } catch (e: CryptoException) {
        throw SyncError(ErrorCode.ERR_STREAM_TRUNCATED, rawMessage = "unpad manifest", rawCause = e)
    }
    val rawSha = KeysAndAuth.sha256(rawManifest)
    if (opened != null && !KeysAndAuth.constantTimeEquals(rawSha, opened.manifestSha256)) {
        throw SyncError(ErrorCode.ERR_CRYPTO_SIGNATURE_INVALID, rawMessage = "manifest SHA-256 does not match signed SealedHeader")
    }

    val manifest = ManifestCodec.parseManifest(rawManifest)
    if (manifest.msgId != msgIdHex) {
        throw SyncError(ErrorCode.ERR_MANIFEST_INVALID, rawMessage = "manifest msg_id mismatch")
    }
    if (opened != null) {
        if (manifest.sender.deviceId != opened.senderDeviceId) {
            throw SyncError(ErrorCode.ERR_CRYPTO_SIGNATURE_INVALID, rawMessage = "manifest sender.device_id does not match SealedHeader")
        }
        if (manifest.createdAt != opened.createdAt) {
            throw SyncError(ErrorCode.ERR_CRYPTO_SIGNATURE_INVALID, rawMessage = "manifest created_at does not match SealedHeader")
        }
    }
    return manifest to rawSha
}

internal fun ensureSafeRealDir(dir: File) {
    val p = dir.toPath()
    if (Files.exists(p, LinkOption.NOFOLLOW_LINKS)) {
        if (Files.isSymbolicLink(p) || !Files.isDirectory(p, LinkOption.NOFOLLOW_LINKS)) {
            throw SyncError(ErrorCode.ERR_STORAGE_IO, rawMessage = "temp directory must be a real directory, not a symlink")
        }
    } else {
        try {
            Files.createDirectories(p)
        } catch (e: Exception) {
            throw SyncError(ErrorCode.ERR_STORAGE_IO, rawMessage = "create temp directory", rawCause = e)
        }
    }
}

internal fun verifyExistingFileSha256(file: File, expectedSize: Long, expectedShaHex: String): Boolean {
    val p = file.toPath()
    if (!Files.exists(p, LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(p) || !Files.isRegularFile(p, LinkOption.NOFOLLOW_LINKS)) {
        return false
    }
    if (file.length() != expectedSize) return false
    val md = MessageDigest.getInstance("SHA-256")
    val buf = ByteArray(64 * 1024)
    FileInputStream(file).use { fis ->
        while (true) {
            val r = fis.read(buf)
            if (r < 0) break
            if (r > 0) md.update(buf, 0, r)
        }
    }
    return KeysAndAuth.toLowerHex(md.digest()) == expectedShaHex
}

internal fun atomicMoveWithRetry(src: File, dst: File) {
    val srcPath = src.toPath()
    val dstPath = dst.toPath()
    var lastErr: Exception? = null
    var delayMs = 10L
    for (attempt in 0 until 5) {
        try {
            Files.move(srcPath, dstPath, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
            return
        } catch (_: java.nio.file.AtomicMoveNotSupportedException) {
            try {
                Files.move(srcPath, dstPath, StandardCopyOption.REPLACE_EXISTING)
                return
            } catch (e: Exception) {
                lastErr = e
            }
        } catch (e: Exception) {
            lastErr = e
        }
        if (attempt < 4) {
            try {
                Thread.sleep(delayMs)
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
                break
            }
            delayMs *= 2
        }
    }
    throw SyncError(ErrorCode.ERR_STORAGE_IO, rawMessage = "atomic finalize verified blob", rawCause = lastErr)
}
