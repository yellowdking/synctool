package com.yellowdking.synctool.client

import com.yellowdking.synctool.crypto.Crockford
import com.yellowdking.synctool.crypto.CryptoException
import com.yellowdking.synctool.crypto.Handshake
import com.yellowdking.synctool.crypto.KeysAndAuth
import com.yellowdking.synctool.crypto.SealedHeader
import com.yellowdking.synctool.crypto.SealedHeaderOpenResult
import com.yellowdking.synctool.crypto.StreamCipher
import com.yellowdking.synctool.envelope.DirectRoomInitPayload
import com.yellowdking.synctool.envelope.ErrorCode
import com.yellowdking.synctool.envelope.ManifestCodec
import com.yellowdking.synctool.envelope.PairOffer
import com.yellowdking.synctool.envelope.PartLayout
import com.yellowdking.synctool.envelope.PipeAckPayload
import com.yellowdking.synctool.envelope.PipeStartPayload
import com.yellowdking.synctool.envelope.ReceivedParcel
import com.yellowdking.synctool.envelope.SyncError
import com.yellowdking.synctool.envelope.SyncUri
import com.yellowdking.synctool.envelope.TransferEvent
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.nio.charset.StandardCharsets
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext

// --- Mode A Live Pipe Send & Receive ---

internal suspend fun SyncClient.verifyOneshotPipeAck(
    sess: ActiveRoomSession,
    ctrlKey32: ByteArray,
    ctrlNp7: ByteArray,
    ackWire: RoomMessageWire,
    expectedMsgId: String,
) {
    val cw = try {
        val raw = KeysAndAuth.b64uDecode(ackWire.msgB64)
        ManifestCodec.json.decodeFromString(PipeCtrlWire.serializer(), String(raw, StandardCharsets.UTF_8))
    } catch (_: Exception) {
        closeRoomBestEffort(sess.roomId, sess.token, "verify_failed")
        throw SyncError(ErrorCode.ERR_CRYPTO_DECRYPT_FAILED, rawMessage = "decode pipe_ack")
    }
    val ctBytes = try {
        KeysAndAuth.b64uDecode(cw.ct)
    } catch (_: Exception) {
        closeRoomBestEffort(sess.roomId, sess.token, "verify_failed")
        throw SyncError(ErrorCode.ERR_CRYPTO_DECRYPT_FAILED, rawMessage = "decode pipe_ack ct")
    }
    val ptAck = try {
        Handshake.openPipeCtrlVerified(
            ctrlKey32, ctrlNp7, sess.hs.th, cw.ctrlSeq,
            fromInitiator = false, lastSeenSeq = -1L, ciphertext = ctBytes,
        )
    } catch (e: CryptoException) {
        closeRoomBestEffort(sess.roomId, sess.token, "verify_failed")
        throw SyncError(ErrorCode.ERR_CRYPTO_DECRYPT_FAILED, rawMessage = "decrypt pipe_ack", rawCause = e)
    }
    val ack = try {
        ManifestCodec.json.decodeFromString(PipeAckPayload.serializer(), String(ptAck, StandardCharsets.UTF_8))
    } catch (_: Exception) {
        closeRoomBestEffort(sess.roomId, sess.token, "verify_failed")
        throw SyncError(ErrorCode.ERR_CRYPTO_DECRYPT_FAILED, rawMessage = "parse pipe_ack JSON")
    }
    if (ack.op != "pipe_ack" || ack.msgId != expectedMsgId) {
        closeRoomBestEffort(sess.roomId, sess.token, "verify_failed")
        throw SyncError(ErrorCode.ERR_CRYPTO_DECRYPT_FAILED, rawMessage = "invalid pipe_ack payload")
    }
}

internal suspend fun SyncClient.receiveOneShotJoined(
    st: SyncClient.InitializedState,
    joined: RoomJoinResp,
    m1: HsM1Wire,
    oob: ByteArray,
    options: ReceiveOptions,
    handler: (suspend (ReceivedParcel) -> Unit)?,
): ReceivedParcel {
    // ST-P0-1: runResponderHandshake enforces upfront non-null onSASConfirm before M2 and invokes onSASConfirm immediately after M4!
    val sess = runResponderHandshake(joined, m1, oob, options.onSASDisplay, options.onSASConfirm)
    val (ctrlKey, ctrlNp) = Handshake.derivePipeCtrlKeys(sess.hs.th, sess.hs.sessionKey)
    try {
        val (startWire, nextSeq) = waitForPeerRoomMessage(sess.roomId, sess.token, "sender", sess.lastSeq)
        sess.lastSeq = nextSeq

        val cw = try {
            val raw = KeysAndAuth.b64uDecode(startWire.msgB64)
            ManifestCodec.json.decodeFromString(PipeCtrlWire.serializer(), String(raw, StandardCharsets.UTF_8))
        } catch (_: Exception) {
            closeRoomBestEffort(sess.roomId, sess.token, "verify_failed")
            throw SyncError(ErrorCode.ERR_CRYPTO_DECRYPT_FAILED, rawMessage = "decode pipe_start")
        }
        val ctBytes = try {
            KeysAndAuth.b64uDecode(cw.ct)
        } catch (_: Exception) {
            closeRoomBestEffort(sess.roomId, sess.token, "verify_failed")
            throw SyncError(ErrorCode.ERR_CRYPTO_DECRYPT_FAILED, rawMessage = "decode pipe_start ct")
        }
        val ptStart = try {
            Handshake.openPipeCtrlVerified(
                ctrlKey, ctrlNp, sess.hs.th, cw.ctrlSeq,
                fromInitiator = true, lastSeenSeq = -1L, ciphertext = ctBytes,
            )
        } catch (e: CryptoException) {
            closeRoomBestEffort(sess.roomId, sess.token, "verify_failed")
            throw SyncError(ErrorCode.ERR_CRYPTO_DECRYPT_FAILED, rawMessage = "decrypt pipe_start", rawCause = e)
        }
        val startCmd = try {
            ManifestCodec.json.decodeFromString(PipeStartPayload.serializer(), String(ptStart, StandardCharsets.UTF_8))
        } catch (_: Exception) {
            closeRoomBestEffort(sess.roomId, sess.token, "verify_failed")
            throw SyncError(ErrorCode.ERR_CRYPTO_DECRYPT_FAILED, rawMessage = "parse pipe_start JSON")
        }
        if (startCmd.op != "pipe_start" || !KeysAndAuth.isLowerHex(startCmd.msgId, 32)) {
            closeRoomBestEffort(sess.roomId, sess.token, "verify_failed")
            throw SyncError(ErrorCode.ERR_MANIFEST_INVALID, rawMessage = "invalid pipe_start payload")
        }

        val msgIdRaw = KeysAndAuth.fromHex(startCmd.msgId)
        val (p0Key, p0Np) = Handshake.deriveOneshotPart0Keys(sess.hs.sessionKey, msgIdRaw)
        try {
            val parcel = try {
                downloadAndDeliverPipeParcel(
                    st, sess.pipeId, sess.token, msgIdRaw, startCmd.msgId,
                    p0Key, p0Np, opened = null, parts = startCmd.parts, options = options, handler = handler,
                )
            } catch (t: Throwable) {
                closeRoomBestEffort(sess.roomId, sess.token, "cancelled")
                throw t
            }

            val ackCmd = ManifestCodec.json.encodeToString(PipeAckPayload.serializer(), PipeAckPayload(msgId = startCmd.msgId))
                .toByteArray(StandardCharsets.UTF_8)
            val ackCt = Handshake.sealPipeCtrl(ctrlKey, ctrlNp, sess.hs.th, 1L, ackCmd)
            val ackFrame = ManifestCodec.json.encodeToString(
                PipeCtrlWire.serializer(),
                PipeCtrlWire(ctrlSeq = 1L, ct = KeysAndAuth.b64uEncode(ackCt)),
            ).toByteArray(StandardCharsets.UTF_8)
            // Post pipe_ack and let Sender read it before closing the room (avoiding relay RoomManager.Close message wipe race).
            postRoomMessage(sess.roomId, sess.token, "control", ackFrame)
            return parcel
        } finally {
            KeysAndAuth.zeroBytes(p0Key, p0Np)
        }
    } finally {
        KeysAndAuth.zeroBytes(ctrlKey, ctrlNp)
        sess.hs.zero()
    }
}

internal suspend fun SyncClient.receiveDirectJoined(
    st: SyncClient.InitializedState,
    joined: RoomJoinResp,
    initPayload: DirectRoomInitPayload,
    options: ReceiveOptions,
    handler: (suspend (ReceivedParcel) -> Unit)?,
): ReceivedParcel {
    val roomId = joined.roomId
    val token = joined.receiverToken
    val hdrBytes = try {
        KeysAndAuth.b64uDecode(initPayload.sealedHeader)
    } catch (_: Exception) {
        closeRoomBestEffort(roomId, token, "verify_failed")
        throw SyncError(ErrorCode.ERR_CRYPTO_SIGNATURE_INVALID, rawMessage = "invalid sealed_header base64url")
    }
    if (hdrBytes.size != SealedHeader.SEALED_HEADER_SIZE) {
        closeRoomBestEffort(roomId, token, "verify_failed")
        throw SyncError(ErrorCode.ERR_CRYPTO_SIGNATURE_INVALID, rawMessage = "invalid sealed_header length")
    }

    val opened = try {
        openAndVerifySealedHeader(st, hdrBytes)
    } catch (t: Throwable) {
        closeRoomBestEffort(roomId, token, "verify_failed")
        throw t
    }

    claimInFlightMsgId(opened.msgId)
    try {
        val parcel = try {
            downloadAndDeliverPipeParcel(
                st, joined.pipeId, token, opened.msgIdRaw, opened.msgId,
                opened.part0Key, opened.part0NoncePrefix, opened, initPayload.parts, options, handler,
            )
        } catch (se: SyncError) {
            val reason = if (se.isSecurityAlert || se.isAuthError) "verify_failed" else "cancelled"
            closeRoomBestEffort(roomId, token, reason)
            throw se
        } catch (t: Throwable) {
            closeRoomBestEffort(roomId, token, "cancelled")
            throw t
        }

        keyStore.markSeenMsgId(opened.msgId, opened.createdAt, System.currentTimeMillis() / 1000L)
        val ackMac = SealedHeader.computeDirectAckMac(opened.part0Key, opened.msgIdRaw)
        val ackBytes = ManifestCodec.json.encodeToString(
            PipeAckPayload.serializer(),
            PipeAckPayload(msgId = opened.msgId, ackMac = KeysAndAuth.b64uEncode(ackMac)),
        ).toByteArray(StandardCharsets.UTF_8)
        KeysAndAuth.zeroBytes(ackMac)
        // Post direct pipe_ack and let Sender verify it before closing the room (avoiding relay RoomManager.Close message wipe race).
        postRoomMessage(roomId, token, "control", ackBytes)
        return parcel
    } finally {
        releaseInFlightMsgId(opened.msgId)
        opened.zero()
    }
}

internal suspend fun SyncClient.sendDirectViaPipe(
    prep: PreparedParcel,
    sealedB64: String,
    p0Key: ByteArray,
    p0Np: ByteArray,
    blocksPerChunk: Int,
    options: SendOptions,
): SendResult {
    val roomId = Crockford.generateRoomId()
    val m1Bytes = ManifestCodec.json.encodeToString(
        DirectRoomInitPayload.serializer(),
        DirectRoomInitPayload(sealedHeader = sealedB64, blocksPerChunk = blocksPerChunk, parts = prep.parts),
    ).toByteArray(StandardCharsets.UTF_8)

    val created = createRoom(roomId, options.ttlSec, m1Bytes)
    val offer = PairOffer(
        version = 1,
        roomId = roomId,
        mode = Handshake.MODE_DIRECT,
        purpose = Handshake.PURPOSE_DIRECT,
        endpoint = if (options.includeRelay) transport.profile.endpoint else "",
        spkiPins = if (options.includeRelay) transport.profile.resolvedPins else emptyList(),
        expiresAt = created.expiresAt,
        accessKey = if (options.includeRelay) transport.profile.accessKey else "",
    )
    val pairUri = try {
        SyncUri.formatPairUri(offer)
    } catch (t: Throwable) {
        closeRoomBestEffort(roomId, created.senderToken, "cancelled")
        throw t
    }
    val dispCode = Crockford.formatRoomId(roomId)
    try {
        options.onOfferReady?.invoke(
            OfferReadyInfo(
                roomId = roomId, displayCode = dispCode, mode = Handshake.MODE_DIRECT,
                purpose = Handshake.PURPOSE_DIRECT, pairUri = pairUri, expiresAt = created.expiresAt,
            )
        )
    } catch (t: Throwable) {
        closeRoomBestEffort(roomId, created.senderToken, "cancelled")
        throw t
    }

    try {
        uploadAllPipeParts(created.pipeId, created.senderToken, prep, p0Key, p0Np, blocksPerChunk, options.onProgress)
    } catch (t: Throwable) {
        closeRoomBestEffort(roomId, created.senderToken, "cancelled")
        throw t
    }

    val (ackWire, _) = waitForPeerRoomMessage(roomId, created.senderToken, "receiver", created.seq)
    val ack = try {
        val raw = KeysAndAuth.b64uDecode(ackWire.msgB64)
        ManifestCodec.json.decodeFromString(PipeAckPayload.serializer(), String(raw, StandardCharsets.UTF_8))
    } catch (_: Exception) {
        closeRoomBestEffort(roomId, created.senderToken, "verify_failed")
        throw SyncError(ErrorCode.ERR_CRYPTO_DECRYPT_FAILED, rawMessage = "decode direct pipe_ack")
    }
    if (ack.op != "pipe_ack" || ack.msgId != prep.msgId || ack.ackMac.isNullOrEmpty()) {
        closeRoomBestEffort(roomId, created.senderToken, "verify_failed")
        throw SyncError(ErrorCode.ERR_CRYPTO_SIGNATURE_INVALID, rawMessage = "invalid direct pipe_ack payload")
    }
    val macBytes = try {
        KeysAndAuth.b64uDecode(ack.ackMac)
    } catch (_: Exception) {
        closeRoomBestEffort(roomId, created.senderToken, "verify_failed")
        throw SyncError(ErrorCode.ERR_CRYPTO_SIGNATURE_INVALID, rawMessage = "invalid direct pipe_ack mac encoding")
    }
    try {
        SealedHeader.verifyDirectAckMac(p0Key, prep.msgIdRaw, macBytes)
    } catch (_: CryptoException) {
        closeRoomBestEffort(roomId, created.senderToken, "verify_failed")
        throw SyncError(ErrorCode.ERR_CRYPTO_SIGNATURE_INVALID, rawMessage = "direct pipe_ack MAC verification failed")
    }
    closeRoomBestEffort(roomId, created.senderToken, "completed")
    return SendResult(mode = DeliveryMode.PIPE, msgId = prep.msgId, roomId = roomId, totalBytes = prep.totalEnc)
}

internal suspend fun SyncClient.downloadAndDeliverPipeParcel(
    st: SyncClient.InitializedState,
    pipeId: String,
    recvToken: String,
    msgIdRaw16: ByteArray,
    msgIdHex: String,
    p0Key32: ByteArray,
    p0Np7: ByteArray,
    opened: SealedHeaderOpenResult?,
    parts: List<PartLayout>,
    options: ReceiveOptions,
    handler: (suspend (ReceivedParcel) -> Unit)?,
): ReceivedParcel {
    val partMap = parts.associateBy { it.partId }
    if (parts.size != partMap.size) {
        throw SyncError(ErrorCode.ERR_MANIFEST_INVALID, rawMessage = "duplicate part_id in pipe parts")
    }
    val totalBytes = parts.sumOf { it.totalBytes }
    val p0Layout = partMap[0]
        ?: throw SyncError(ErrorCode.ERR_MANIFEST_INVALID, rawMessage = "missing part_id=0 layout")
    if (p0Layout.chunkCount <= 0) {
        throw SyncError(ErrorCode.ERR_MANIFEST_INVALID, rawMessage = "invalid part_id=0 chunk_count")
    }

    suspend fun getPipeChunkBytes(txIdx: Int): ByteArray {
        val out = ByteArrayOutputStream()
        streamPipeChunk(pipeId, recvToken, 0, txIdx) { buf, len ->
            out.write(buf, 0, len)
        }
        return out.toByteArray()
    }

    val (manifest, _) = pullAndVerifyManifest(
        msgIdRaw16, msgIdHex, p0Key32, p0Np7, p0Layout, opened, ::getPipeChunkBytes,
    )

    if (parts.size != 1 + manifest.blobs.size || partMap.size != 1 + manifest.blobs.size) {
        throw SyncError(
            code = ErrorCode.ERR_MANIFEST_INVALID,
            rawMessage = "pipe parts count (${parts.size}) does not match 1 + manifest.blobs.size (${1 + manifest.blobs.size})",
        )
    }

    if (!options.appId.isNullOrEmpty() && manifest.appId != options.appId) {
        throw SyncError(
            code = ErrorCode.ERR_MANIFEST_INVALID,
            rawMessage = "parcel app_id ${manifest.appId} does not match expected ${options.appId}",
        )
    }

    val receivedBlobs = pullAndVerifyBlobs(
        st = st, itemId = "", expiresAt = 0L, msgIdRaw16 = msgIdRaw16, manifest = manifest,
        partMap = partMap, totalBytes = totalBytes, initialDoneBytes = p0Layout.totalBytes,
        mode = DeliveryMode.PIPE,
        streamChunkToSink = { partId, txIdx, sink -> streamPipeChunk(pipeId, recvToken, partId, txIdx, sink) },
        onProgress = options.onProgress,
    )

    val parcel = ReceivedParcel(manifest = manifest, blobs = receivedBlobs)
    handler?.invoke(parcel)
    return parcel
}

// --- O(1)-Heap Chunk Streaming Engine ---

internal suspend fun SyncClient.uploadAllPipeParts(
    pipeId: String,
    senderToken: String,
    prep: PreparedParcel,
    p0Key: ByteArray,
    p0Np: ByteArray,
    blocksPerChunk: Int,
    onProgress: ((TransferEvent) -> Unit)?,
) {
    uploadAllParcelParts(DeliveryMode.PIPE, prep, p0Key, p0Np, blocksPerChunk, onProgress) { partId, txIdx, chunkBytes ->
        val path = "/v1/pipe/$pipeId/parts/$partId/chunks/$txIdx"
        var peerTimeoutRetries = 0
        val maxRetries = if (partId == 0 && txIdx == 0) 6 else 2
        while (true) {
            currentCoroutineContext().ensureActive()
            try {
                transport.doSignedWithSkewRetry(
                    method = "PUT",
                    pathAndQuery = path,
                    bodyBytes = null,
                    opts = RequestAuthOptions(
                        contentType = "application/octet-stream", roomToken = senderToken,
                        isStream = true, streamLength = chunkBytes.size.toLong(),
                        streamFactory = { ByteArrayInputStream(chunkBytes) },
                    ),
                )
                break
            } catch (se: SyncError) {
                if (se.code == ErrorCode.ERR_PIPE_PEER_TIMEOUT && peerTimeoutRetries < maxRetries) {
                    peerTimeoutRetries++
                    delay(50L)
                    continue
                }
                throw se
            }
        }
    }
}

internal suspend fun SyncClient.uploadAllParcelParts(
    mode: String,
    prep: PreparedParcel,
    p0Key: ByteArray,
    p0Np: ByteArray,
    blocksPerChunk: Int,
    onProgress: ((TransferEvent) -> Unit)?,
    putChunk: suspend (partId: Int, txIdx: Int, chunkBytes: ByteArray) -> Unit,
) {
    var totalSent = 0L
    val startedAtNs = System.nanoTime()

    fun emitProgress(partId: Int, partDone: Long, partTotal: Long) {
        onProgress ?: return
        val elapsedSec = ((System.nanoTime() - startedAtNs) / 1_000_000_000.0).coerceAtLeast(0.001)
        val bps = (totalSent / elapsedSec).toLong()
        onProgress(
            TransferEvent(
                stage = "transferring", direction = "send", mode = mode, msgId = prep.msgId,
                partId = partId, partsTotal = prep.parts.size, bytesDone = totalSent, bytesTotal = prep.totalEnc,
                partBytesDone = partDone, partBytesTotal = partTotal, speedBps = bps,
            )
        )
    }

    var p0Done = 0L
    val p0Total = prep.parts[0].totalBytes
    streamUploadPart(
        ByteArrayInputStream(prep.manifestPad), prep.manifestPad.size.toLong(),
        p0Key, p0Np, prep.msgIdRaw, 0, blocksPerChunk,
    ) { txIdx, chunk ->
        putChunk(0, txIdx, chunk)
        p0Done += chunk.size
        totalSent += chunk.size
        emitProgress(0, p0Done, p0Total)
    }

    for ((i, b) in prep.blobs.withIndex()) {
        val (encKey, np) = StreamCipher.deriveBlobPartKeys(prep.msgIdRaw, b.partId, b.blobKey32)
        try {
            val (stream, _) = b.input.openStream()
            val partTotal = prep.parts[i + 1].totalBytes
            var partDone = 0L
            stream.use { ins ->
                streamUploadPart(ins, b.desc.size, encKey, np, prep.msgIdRaw, b.partId, blocksPerChunk) { txIdx, chunk ->
                    putChunk(b.partId, txIdx, chunk)
                    partDone += chunk.size
                    totalSent += chunk.size
                    emitProgress(b.partId, partDone, partTotal)
                }
            }
        } finally {
            KeysAndAuth.zeroBytes(encKey, np)
        }
    }
}

internal suspend fun streamUploadPart(
    input: InputStream,
    plaintextSize: Long,
    encKey32: ByteArray,
    noncePrefix7: ByteArray,
    msgIdRaw16: ByteArray,
    partId: Int,
    blocksPerChunk: Int,
    putChunk: suspend (txIdx: Int, chunkBytes: ByteArray) -> Unit,
) {
    val sc = StreamCipher(encKey32, noncePrefix7, msgIdRaw16, partId)
    val totalBlocks = StreamCipher.totalBlocks(plaintextSize)
    val ptBuf = ByteArray(StreamCipher.CHUNK_PLAINTEXT_MAX)
    val chunkOut = ByteArrayOutputStream(blocksPerChunk * StreamCipher.CHUNK_CIPHERTEXT_MAX)
    try {
        var blockIdx = 0u
        var txIdx = 0
        while (blockIdx < totalBlocks) {
            currentCoroutineContext().ensureActive()
            val isFinal = blockIdx == totalBlocks - 1u
            val wantPt = if (isFinal) {
                if (plaintextSize == 0L) 0 else (((plaintextSize - 1L) % StreamCipher.CHUNK_PLAINTEXT_MAX) + 1L).toInt()
            } else {
                StreamCipher.CHUNK_PLAINTEXT_MAX
            }
            val ptSlice = if (wantPt > 0) {
                withContext(Dispatchers.IO) {
                    readExactOrThrow(input, ptBuf, wantPt)
                }
                ptBuf.copyOfRange(0, wantPt)
            } else {
                ByteArray(0)
            }
            val ct = try {
                sc.sealBlockAt(blockIdx, isFinal, ptSlice)
            } finally {
                KeysAndAuth.zeroBytes(ptSlice)
            }
            chunkOut.write(ct)
            blockIdx++
            val atBoundary = ((blockIdx.toLong() % blocksPerChunk.toLong()) == 0L) || (blockIdx == totalBlocks)
            if (atBoundary) {
                val bytes = chunkOut.toByteArray()
                chunkOut.reset()
                putChunk(txIdx, bytes)
                txIdx++
            }
        }
    } finally {
        KeysAndAuth.zeroBytes(ptBuf)
        sc.zero()
    }
}

private fun readExactOrThrow(input: InputStream, buf: ByteArray, want: Int) {
    var off = 0
    while (off < want) {
        val r = input.read(buf, off, want - off)
        if (r < 0) {
            throw SyncError(ErrorCode.ERR_STORAGE_IO, rawMessage = "unexpected EOF while reading blob plaintext")
        }
        off += r
    }
}

private suspend fun SyncClient.streamPipeChunk(
    pipeId: String,
    recvToken: String,
    partId: Int,
    txIdx: Int,
    onSlice: (ByteArray, Int) -> Unit,
): Long {
    val path = "/v1/pipe/$pipeId/parts/$partId/chunks/$txIdx"
    var peerTimeoutRetries = 0
    val maxRetries = if (partId == 0 && txIdx == 0) 6 else 2
    while (true) {
        currentCoroutineContext().ensureActive()
        val resp = try {
            transport.openSignedStream(
                method = "GET",
                pathAndQuery = path,
                opts = RequestAuthOptions(roomToken = recvToken),
            )
        } catch (se: SyncError) {
            if (se.code == ErrorCode.ERR_PIPE_PEER_TIMEOUT && peerTimeoutRetries < maxRetries) {
                peerTimeoutRetries++
                delay(50L)
                continue
            }
            throw se
        }
        return drainResponseStream(resp, onSlice)
    }
}

internal suspend fun SyncClient.drainResponseStream(
    response: okhttp3.Response,
    onSlice: (ByteArray, Int) -> Unit,
): Long = withContext(Dispatchers.IO) {
    response.use { resp ->
        val ins = resp.body?.byteStream() ?: return@use 0L
        val buf = ByteArray(32 * 1024)
        var total = 0L
        try {
            while (true) {
                currentCoroutineContext().ensureActive()
                val n = ins.read(buf)
                if (n < 0) break
                if (n > 0) {
                    onSlice(buf, n)
                    total += n.toLong()
                }
            }
            total
        } catch (se: SyncError) {
            throw se
        } catch (ce: CancellationException) {
            throw ce
        } catch (t: Throwable) {
            throw transport.classifyIoException(t)
        }
    }
}

/**
 * Decrypts a single transport chunk buffer with strict `ST-P0-2` guards:
 * - Rejects empty chunks
 * - Rejects any bytes after `sawFinal` (`alreadySawFinal` or trailing bytes in the same chunk)
 * - Rejects `blk >= totalBlocks` when `totalBlocks > 0u`
 * - Rejects `UInt.MAX_VALUE` counter wrap-around
 */
internal fun decryptChunkBufferInto(
    sc: StreamCipher,
    chunkBytes: ByteArray,
    startBlockIdx: UInt,
    totalBlocks: UInt,
    isLastTransportChunk: Boolean,
    alreadySawFinal: Boolean,
    sink: OutputStream,
): Pair<UInt, Boolean> {
    if (chunkBytes.isEmpty()) {
        throw SyncError(ErrorCode.ERR_STREAM_TRUNCATED, rawMessage = "empty transport chunk")
    }
    if (alreadySawFinal) {
        throw SyncError(ErrorCode.ERR_STREAM_TRUNCATED, rawMessage = "unexpected ciphertext after authenticated final block")
    }

    var off = 0
    var blk = startBlockIdx
    var blocksDone = 0u
    var sawFinal = false

    while (off < chunkBytes.size) {
        if (sawFinal) {
            throw SyncError(ErrorCode.ERR_STREAM_TRUNCATED, rawMessage = "trailing bytes after final STREAM block")
        }
        if (totalBlocks > 0u && blk >= totalBlocks) {
            throw SyncError(ErrorCode.ERR_MANIFEST_INVALID, rawMessage = "stream block count exceeded signed manifest blob size")
        }
        val rem = chunkBytes.size - off
        val take = minOf(StreamCipher.CHUNK_CIPHERTEXT_MAX, rem)
        if (blk == UInt.MAX_VALUE && off + take < chunkBytes.size) {
            throw SyncError(ErrorCode.ERR_MANIFEST_INVALID, rawMessage = "stream block index overflow")
        }

        val isFinal = when {
            totalBlocks > 0u -> blk == totalBlocks - 1u
            isLastTransportChunk && (off + take == chunkBytes.size) -> true
            else -> false
        }

        val ctSlice = chunkBytes.copyOfRange(off, off + take)
        val pt = try {
            sc.openBlockAt(blk, isFinal, ctSlice)
        } catch (e: CryptoException) {
            throw SyncError(ErrorCode.ERR_CRYPTO_DECRYPT_FAILED, rawMessage = "decrypt stream block", rawCause = e)
        }
        try {
            if (pt.isNotEmpty()) {
                sink.write(pt)
            }
        } catch (e: Exception) {
            throw SyncError(ErrorCode.ERR_STORAGE_IO, rawMessage = "write decrypted block", rawCause = e)
        } finally {
            KeysAndAuth.zeroBytes(pt)
        }

        if (isFinal) {
            sawFinal = true
        }
        off += take
        blk++
        blocksDone++
    }
    return blocksDone to sawFinal
}

internal class RollingBlockDecryptor(
    private val sc: StreamCipher,
    private val totalBlocks: UInt,
    initialBlockIdx: UInt,
    private val sink: OutputStream,
) {
    private val blockAccum = ByteArray(StreamCipher.CHUNK_CIPHERTEXT_MAX)
    private var accumLen = 0
    var blkIdx: UInt = initialBlockIdx
        private set
    var sawFinal: Boolean = false
        private set

    fun ensureNotFinalBeforeChunk() {
        if (sawFinal) {
            throw SyncError(ErrorCode.ERR_STREAM_TRUNCATED, rawMessage = "extra transport chunks after final STREAM block")
        }
    }

    fun feedSlice(slice: ByteArray, len: Int) {
        var srcOff = 0
        while (srcOff < len) {
            if (sawFinal) {
                throw SyncError(ErrorCode.ERR_STREAM_TRUNCATED, rawMessage = "trailing bytes after final STREAM block")
            }
            val copyN = minOf(StreamCipher.CHUNK_CIPHERTEXT_MAX - accumLen, len - srcOff)
            System.arraycopy(slice, srcOff, blockAccum, accumLen, copyN)
            accumLen += copyN
            srcOff += copyN

            // If we have a full 65,552B block AND this is NOT the final block, decrypt immediately in O(1) RAM!
            if (accumLen == StreamCipher.CHUNK_CIPHERTEXT_MAX && blkIdx < totalBlocks - 1u) {
                val pt = try {
                    sc.openBlockAt(blkIdx, isFinal = false, ciphertext = blockAccum)
                } catch (e: CryptoException) {
                    throw SyncError(ErrorCode.ERR_CRYPTO_DECRYPT_FAILED, rawMessage = "decrypt stream block", rawCause = e)
                }
                try {
                    sink.write(pt)
                } finally {
                    KeysAndAuth.zeroBytes(pt)
                }
                blkIdx++
                accumLen = 0
            }
        }
    }

    fun finishTransportChunk() {
        if (accumLen > 0) {
            if (blkIdx != totalBlocks - 1u) {
                throw SyncError(ErrorCode.ERR_STREAM_TRUNCATED, rawMessage = "truncated non-final transport chunk")
            }
            val ctFinal = blockAccum.copyOfRange(0, accumLen)
            val pt = try {
                sc.openBlockAt(blkIdx, isFinal = true, ciphertext = ctFinal)
            } catch (e: CryptoException) {
                throw SyncError(ErrorCode.ERR_CRYPTO_DECRYPT_FAILED, rawMessage = "decrypt final stream block", rawCause = e)
            }
            try {
                if (pt.isNotEmpty()) sink.write(pt)
            } finally {
                KeysAndAuth.zeroBytes(pt)
            }
            blkIdx++
            accumLen = 0
            sawFinal = true
        }
    }
}
