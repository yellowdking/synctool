package com.yellowdking.synctool.client

import com.yellowdking.synctool.crypto.KeysAndAuth
import com.yellowdking.synctool.crypto.StreamCipher
import com.yellowdking.synctool.envelope.CachedManifestEntry
import com.yellowdking.synctool.envelope.DeviceCard
import com.yellowdking.synctool.envelope.ErrorCode
import com.yellowdking.synctool.envelope.Manifest
import com.yellowdking.synctool.envelope.ManifestCodec
import com.yellowdking.synctool.envelope.PartLayout
import com.yellowdking.synctool.envelope.ReceivedBlob
import com.yellowdking.synctool.envelope.ReceivedParcel
import com.yellowdking.synctool.envelope.SyncError
import com.yellowdking.synctool.envelope.TransferCheckpoint
import com.yellowdking.synctool.envelope.TransferEvent
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.OutputStream
import java.io.RandomAccessFile
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.LinkOption
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull

private const val WATCH_DEDUP_FIFO_CAP: Int = 4096

// --- Mode B 0-RTT Spool Upload & Chunk Helpers ---

internal suspend fun SyncClient.abortUncommittedSpoolBestEffort(itemId: String, uploadToken: String) {
    if (itemId.isEmpty() || uploadToken.isEmpty()) return
    withContext(NonCancellable) {
        withTimeoutOrNull(5_000L) {
            runCatching {
                transport.doControl(
                    method = "DELETE",
                    pathAndQuery = "/v1/spool/$itemId",
                    opts = RequestAuthOptions(uploadToken = uploadToken),
                )
            }
        }
    }
}

internal suspend fun SyncClient.uploadAllSpoolParts(
    itemId: String,
    uploadToken: String,
    prep: PreparedParcel,
    p0Key: ByteArray,
    p0Np: ByteArray,
    blocksPerChunk: Int,
    onProgress: ((TransferEvent) -> Unit)?,
) {
    uploadAllParcelParts(
        mode = DeliveryMode.SPOOL,
        prep = prep,
        p0Key = p0Key,
        p0Np = p0Np,
        blocksPerChunk = blocksPerChunk,
        onProgress = onProgress,
    ) { partId, txIdx, chunkBytes ->
        transport.doSignedWithSkewRetry(
            method = "PUT",
            pathAndQuery = "/v1/spool/$itemId/parts/$partId/chunks/$txIdx",
            bodyBytes = null,
            opts = RequestAuthOptions(
                contentType = "application/octet-stream",
                uploadToken = uploadToken,
                isStream = true,
                streamLength = chunkBytes.size.toLong(),
                streamFactory = { ByteArrayInputStream(chunkBytes) },
            ),
        )
    }
}

internal suspend fun SyncClient.getSpoolChunkBytes(
    st: SyncClient.InitializedState,
    itemId: String,
    partId: Int,
    txIdx: Int,
): ByteArray {
    val out = ByteArrayOutputStream()
    streamSpoolChunk(st, itemId, partId, txIdx) { buf, len ->
        out.write(buf, 0, len)
    }
    return out.toByteArray()
}

internal suspend fun SyncClient.streamSpoolChunk(
    st: SyncClient.InitializedState,
    itemId: String,
    partId: Int,
    txIdx: Int,
    onSlice: (ByteArray, Int) -> Unit,
): Long {
    val resp = transport.openSignedStream(
        method = "GET",
        pathAndQuery = "/v1/spool/$itemId/parts/$partId/chunks/$txIdx",
        opts = mailboxAuthOpts(st),
    )
    return drainResponseStream(resp, onSlice)
}

// --- Mode B Mailbox Sync, Two-Phase Inbox, Fetch, Ack & Watch ---

internal suspend fun SyncClient.syncMailboxInternal(st: SyncClient.InitializedState): Boolean {
    val allCards = keyStore.listAllDevices()
    val specs = ArrayList<MailboxDepositTokenSpec>(minOf(allCards.size, 16))
    val seenTok = HashSet<String>()
    val revokedPendingCards = ArrayList<DeviceCard>()

    for (rawCard in allCards) {
        var card = rawCard
        // ST-Opt-8: Backfill missing relayId on legacy/synthetic DeviceCards.
        if (card.relayId.isEmpty()) {
            val backfilled = if (card.relayOrigin.isNotEmpty()) {
                runCatching { KeysAndAuth.canonicalRelayOrigin(card.relayOrigin) }.getOrNull()?.let { canon ->
                    card.copy(relayOrigin = canon, relayId = KeysAndAuth.deriveRelayId(canon))
                }
            } else {
                card.copy(relayOrigin = transport.profile.endpoint, relayId = transport.profile.relayId)
            }
            if (backfilled != null) {
                card = backfilled
                runCatching { keyStore.putDevice(card) }
            }
        }
        if (card.relayId != transport.profile.relayId) continue
        if (card.revoked) {
            if (card.inboundTokenId.isNotEmpty()) {
                revokedPendingCards.add(card)
            }
            continue
        }
        if (card.pendingTokenDelete || card.inboundTokenId.isEmpty() || card.inboundTokenHash.length != 64) continue
        if (!seenTok.add(card.inboundTokenId)) continue
        specs.add(
            MailboxDepositTokenSpec(
                tokenId = card.inboundTokenId,
                tokenHashHex = card.inboundTokenHash.lowercase(),
            )
        )
        if (specs.size >= 16) break
    }

    val reqBytes = ManifestCodec.json.encodeToString(
        MailboxPutReq.serializer(),
        MailboxPutReq(
            authPkB64 = KeysAndAuth.b64uEncode(st.mailboxKeys.authPub),
            depositTokens = specs.takeIf { it.isNotEmpty() },
        ),
    ).toByteArray(StandardCharsets.UTF_8)

    val resp = try {
        transport.doControl(
            method = "PUT",
            pathAndQuery = "/v1/mailboxes/${st.mailboxKeys.mailboxId}",
            jsonBodyBytes = reqBytes,
            opts = mailboxAuthOpts(st),
        )
    } catch (se: SyncError) {
        if (se.code == ErrorCode.ERR_SPOOL_DISABLED) {
            return false
        }
        throw se
    }

    val regOut = runCatching {
        ManifestCodec.json.decodeFromString(
            MailboxRegisterResponse.serializer(),
            String(resp.body, StandardCharsets.UTF_8),
        )
    }.getOrNull()

    if (specs.isNotEmpty() && (regOut?.depositTokenCount ?: 0) < specs.size) {
        val tokPath = "/v1/mailboxes/${st.mailboxKeys.mailboxId}/deposit-tokens"
        for (sp in specs) {
            val spBytes = ManifestCodec.json.encodeToString(MailboxDepositTokenSpec.serializer(), sp)
                .toByteArray(StandardCharsets.UTF_8)
            try {
                transport.doControl(
                    method = "POST",
                    pathAndQuery = tokPath,
                    jsonBodyBytes = spBytes,
                    opts = mailboxAuthOpts(st),
                )
            } catch (se: SyncError) {
                if (se.code != ErrorCode.ERR_CONFLICT && se.code != ErrorCode.ERR_SPOOL_DISABLED) {
                    throw se
                }
            }
        }
    }

    // ST-P1-8: Retry pending 2-phase deposit token deletes now that we are online.
    val pendingDeletes = LinkedHashSet<String>()
    for (tokId in keyStore.listPendingTokenDeletes()) {
        if (tokId.isNotEmpty()) pendingDeletes.add(tokId)
    }
    for (rc in revokedPendingCards) {
        if (rc.inboundTokenId.isNotEmpty()) pendingDeletes.add(rc.inboundTokenId)
    }
    for (tokId in pendingDeletes) {
        if (tokId in seenTok) {
            keyStore.removePendingTokenDelete(tokId)
            continue
        }
        val deletedOk = try {
            deleteRelayDepositTokenStrict(st, tokId)
            true
        } catch (_: Throwable) {
            false
        }
        if (deletedOk) {
            keyStore.removePendingTokenDelete(tokId)
            for (rc in revokedPendingCards) {
                if (rc.inboundTokenId == tokId) {
                    keyStore.deleteDevice(rc.deviceId)
                }
            }
        }
    }

    return true
}

internal suspend fun SyncClient.listRawInboxItems(st: SyncClient.InitializedState): List<InboxItemMeta> {
    val path = "/v1/mailboxes/${st.mailboxKeys.mailboxId}/items"
    val opts = mailboxAuthOpts(st)
    val resp = try {
        transport.doControl("GET", path, opts = opts)
    } catch (se: SyncError) {
        if (se.code == ErrorCode.ERR_NOT_FOUND && runCatching { syncMailboxInternal(st) }.getOrDefault(false)) {
            transport.doControl("GET", path, opts = opts)
        } else {
            throw se
        }
    }
    return try {
        ManifestCodec.json.decodeFromString(
            MailboxItemsResp.serializer(),
            String(resp.body, StandardCharsets.UTF_8),
        ).items
    } catch (e: Exception) {
        throw SyncError(ErrorCode.ERR_BAD_REQUEST, httpStatus = resp.statusCode, rawMessage = "decode mailbox items", rawCause = e)
    }
}

internal suspend fun SyncClient.fetchParcelInternal(
    itemId: String,
    options: ReceiveOptions,
    handler: (suspend (ReceivedParcel) -> Unit)?,
): ReceivedParcel {
    val st = ensureInitialized()
    val items = listRawInboxItems(st)
    val target = items.firstOrNull { it.itemId == itemId }
        ?: throw SyncError(ErrorCode.ERR_NOT_FOUND, httpStatus = 404, rawMessage = "inbox item not found: $itemId")

    val hdrBytes = try {
        KeysAndAuth.b64uDecode(target.sealedHeader)
    } catch (_: Exception) {
        keyStore.deleteCachedManifest(itemId)
        throw SyncError(ErrorCode.ERR_CRYPTO_SIGNATURE_INVALID, rawMessage = "decode sealed_header")
    }
    val opened = try {
        openAndVerifySealedHeader(st, hdrBytes)
    } catch (se: SyncError) {
        keyStore.deleteCachedManifest(itemId)
        throw se
    }
    claimInFlightMsgId(opened.msgId)

    try {
        val partMap = target.parts.associateBy { it.partId }
        if (target.parts.size != partMap.size) {
            throw SyncError(ErrorCode.ERR_MANIFEST_INVALID, rawMessage = "duplicate part_id in spool item parts")
        }
        val p0Layout = partMap[0]
            ?: throw SyncError(ErrorCode.ERR_MANIFEST_INVALID, rawMessage = "spool item missing part_id=0")

        val wantManifestShaHex = KeysAndAuth.toLowerHex(opened.manifestSha256)
        val cached = keyStore.getCachedManifest(itemId)
        val manifest: Manifest = if (
            cached != null &&
            cached.manifest.msgId == opened.msgId &&
            cached.manifestSha256.isNotEmpty() &&
            cached.manifestSha256 == wantManifestShaHex
        ) {
            cached.manifest
        } else {
            val (pulled, pulledSha) = pullAndVerifyManifest(
                msgIdRaw16 = opened.msgIdRaw,
                msgIdHex = opened.msgId,
                p0Key32 = opened.part0Key,
                p0Np7 = opened.part0NoncePrefix,
                p0Layout = p0Layout,
                opened = opened,
                fetchChunk = { txIdx -> getSpoolChunkBytes(st, itemId, 0, txIdx) },
            )
            keyStore.putCachedManifest(
                CachedManifestEntry(
                    itemId = itemId,
                    cachedAt = System.currentTimeMillis() / 1000L,
                    expiresAt = target.expiresAt,
                    manifestSha256 = KeysAndAuth.toLowerHex(pulledSha),
                    manifest = pulled,
                )
            )
            pulled
        }

        if (target.parts.size != 1 + manifest.blobs.size || partMap.size != 1 + manifest.blobs.size) {
            throw SyncError(
                code = ErrorCode.ERR_MANIFEST_INVALID,
                rawMessage = "spool item parts count (${target.parts.size}) does not match 1 + manifest.blobs.size (${1 + manifest.blobs.size})",
            )
        }

        // AppID pre-filter BEFORE downloading any attachment blobs (`ST-P2-1`)
        if (!options.appId.isNullOrEmpty() && manifest.appId != options.appId) {
            throw SyncError(
                code = ErrorCode.ERR_MANIFEST_INVALID,
                rawMessage = "parcel app_id ${manifest.appId} does not match expected ${options.appId}",
            )
        }

        val receivedBlobs = pullAndVerifyBlobs(
            st = st,
            itemId = itemId,
            expiresAt = target.expiresAt,
            msgIdRaw16 = opened.msgIdRaw,
            manifest = manifest,
            partMap = partMap,
            totalBytes = target.totalBytes,
            initialDoneBytes = p0Layout.totalBytes,
            mode = DeliveryMode.SPOOL,
            streamChunkToSink = { partId, txIdx, sink ->
                streamSpoolChunk(st, itemId, partId, txIdx, sink)
            },
            onProgress = options.onProgress,
        )

        val parcel = ReceivedParcel(
            itemId = itemId,
            manifest = manifest,
            blobs = receivedBlobs,
        )
        handler?.invoke(parcel)

        pendingAckItems[itemId] = opened.msgId to opened.createdAt
        if (options.autoAck) {
            ackItemInternal(st, itemId)
        }
        return parcel
    } finally {
        releaseInFlightMsgId(opened.msgId)
        opened.zero()
    }
}

internal suspend fun SyncClient.ackItemInternal(st: SyncClient.InitializedState, itemId: String) {
    val pending = pendingAckItems.remove(itemId)
    if (pending != null) {
        keyStore.markSeenMsgId(pending.first, pending.second, System.currentTimeMillis() / 1000L)
    }
    keyStore.deleteCachedManifest(itemId)

    try {
        transport.doControl(
            method = "POST",
            pathAndQuery = "/v1/spool/$itemId/ack",
            jsonBodyBytes = "{}".toByteArray(StandardCharsets.UTF_8),
            opts = mailboxAuthOpts(st),
        )
    } catch (se: SyncError) {
        // Retry against already-burned item returns 404 ERR_NOT_FOUND, which SDK treats idempotently as burned
        if (se.code != ErrorCode.ERR_NOT_FOUND) {
            throw se
        }
    }
}

internal suspend fun SyncClient.watchInboxInternal(
    initialSinceTs: Long?,
    onEvent: suspend (InboxWatchEvent) -> Unit,
) {
    val st = ensureInitialized()
    var sinceTs = initialSinceTs?.coerceAtLeast(0L)
        ?: ((System.currentTimeMillis() / 1000L) - 1L).coerceAtLeast(0L)
    val seenItems = LinkedHashSet<String>()
    var usePoll = false
    var pollCyclesSinceSse = 0
    var healed404 = false
    var backoffMs = 250L

    fun recordAndCheckDup(itemId: String): Boolean {
        if (itemId.isEmpty()) return false
        if (seenItems.contains(itemId)) return true
        if (seenItems.size >= WATCH_DEDUP_FIFO_CAP) {
            val eldest = seenItems.iterator().next()
            seenItems.remove(eldest)
        }
        seenItems.add(itemId)
        return false
    }

    while (true) {
        currentCoroutineContext().ensureActive()
        // Always query max(0, sinceTs - 1) across reconnect/poll boundaries so same-second commits are never dropped (`ST-P1-9`)
        val querySince = (sinceTs - 1L).coerceAtLeast(0L)

        if (!usePoll) {
            val path = "/v1/mailboxes/${st.mailboxKeys.mailboxId}/events?mode=sse&since_ts=$querySince"
            val streamStartMs = System.currentTimeMillis()
            var gotReconnect = false
            try {
                val httpResp = transport.openSignedStream(
                    method = "GET",
                    pathAndQuery = path,
                    opts = mailboxAuthOpts(st, acceptSse = true),
                )
                healed404 = false
                backoffMs = 250L
                transport.consumeSseStream(httpResp) { ev ->
                    when (ev.event) {
                        "new_item" -> {
                            val item = runCatching {
                                ManifestCodec.json.decodeFromString(InboxWatchEvent.serializer(), ev.data)
                            }.getOrNull() ?: return@consumeSseStream
                            if (item.createdAt > sinceTs) {
                                sinceTs = item.createdAt
                            }
                            if (!recordAndCheckDup(item.itemId)) {
                                onEvent(item)
                            }
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
                if (se.code == ErrorCode.ERR_NOT_FOUND && !healed404) {
                    healed404 = true
                    if (runCatching { syncMailboxInternal(st) }.getOrDefault(false)) {
                        continue
                    }
                }
                if (se.isAuthError || se.isSecurityAlert || se.isVersionMismatch ||
                    se.code == ErrorCode.ERR_SPOOL_DISABLED || se.code == ErrorCode.ERR_NOT_FOUND
                ) {
                    throw se
                }
                usePoll = true
                pollCyclesSinceSse = 0
                delayWithRetryAfter(se, backoffMs)
                backoffMs = (backoffMs * 2).coerceAtMost(5_000L)
                continue
            }

            if (!gotReconnect && System.currentTimeMillis() - streamStartMs < 1_000L) {
                usePoll = true
                pollCyclesSinceSse = 0
                delay(backoffMs)
                backoffMs = (backoffMs * 2).coerceAtMost(5_000L)
            }
            continue
        }

        // Long-Poll fallback (periodically re-attempts SSE every 6 cycles)
        val pollPath = "/v1/mailboxes/${st.mailboxKeys.mailboxId}/events?mode=poll&wait_sec=20&since_ts=$querySince"
        val resp = try {
            transport.doControl("GET", pollPath, opts = mailboxAuthOpts(st))
        } catch (ce: CancellationException) {
            throw ce
        } catch (se: SyncError) {
            if (se.code == ErrorCode.ERR_NOT_FOUND && !healed404) {
                healed404 = true
                if (runCatching { syncMailboxInternal(st) }.getOrDefault(false)) {
                    continue
                }
            }
            if (se.isAuthError || se.isSecurityAlert || se.isVersionMismatch ||
                se.code == ErrorCode.ERR_SPOOL_DISABLED || se.code == ErrorCode.ERR_NOT_FOUND
            ) {
                throw se
            }
            delayWithRetryAfter(se, backoffMs)
            backoffMs = (backoffMs * 2).coerceAtMost(5_000L)
            continue
        }

        healed404 = false
        backoffMs = 250L
        val out = try {
            ManifestCodec.json.decodeFromString(
                MailboxPollResp.serializer(),
                String(resp.body, StandardCharsets.UTF_8),
            )
        } catch (e: Exception) {
            throw SyncError(ErrorCode.ERR_BAD_REQUEST, httpStatus = resp.statusCode, rawMessage = "decode mailbox poll", rawCause = e)
        }
        for (item in out.items) {
            if (item.createdAt > sinceTs) sinceTs = item.createdAt
            if (!recordAndCheckDup(item.itemId)) {
                onEvent(item)
            }
        }
        if (out.serverTs > sinceTs) {
            sinceTs = out.serverTs
        }
        pollCyclesSinceSse++
        if (pollCyclesSinceSse >= 6) {
            usePoll = false
            pollCyclesSinceSse = 0
        }
    }
}

// --- Streaming Blob Verification & Resumable Checkpoints (`ST-P0-2` Hardened) ---

internal suspend fun SyncClient.pullAndVerifyBlobs(
    st: SyncClient.InitializedState,
    itemId: String,
    expiresAt: Long,
    msgIdRaw16: ByteArray,
    manifest: Manifest,
    partMap: Map<Int, PartLayout>,
    totalBytes: Long,
    initialDoneBytes: Long,
    mode: String,
    streamChunkToSink: suspend (partId: Int, txIdx: Int, onSlice: (ByteArray, Int) -> Unit) -> Long,
    onProgress: ((TransferEvent) -> Unit)?,
): List<ReceivedBlob> {
    // STRICT `ST-P0-2` Upfront Part-Set & Signed `blob.size` Layout Validation BEFORE creating temp dirs or downloading any blob!
    if (partMap.size != 1 + manifest.blobs.size || !partMap.containsKey(0)) {
        throw SyncError(
            code = ErrorCode.ERR_MANIFEST_INVALID,
            rawMessage = "part layout count (${partMap.size}) does not match 1 + manifest.blobs.size (${1 + manifest.blobs.size})",
        )
    }
    if (manifest.blobs.isEmpty()) return emptyList()

    val seenBlobPartIds = HashSet<Int>(manifest.blobs.size)
    for (blob in manifest.blobs) {
        if (blob.partId <= 0 || !seenBlobPartIds.add(blob.partId)) {
            throw SyncError(ErrorCode.ERR_MANIFEST_INVALID, rawMessage = "invalid or duplicate blob part_id=${blob.partId}")
        }
        val layout = partMap[blob.partId]
            ?: throw SyncError(ErrorCode.ERR_MANIFEST_INVALID, rawMessage = "missing part layout for part_id=${blob.partId}")
        val wantEnc = StreamCipher.encryptedPartSize(blob.size)
        val totalBlocks = StreamCipher.totalBlocks(blob.size)
        if (layout.totalBytes != wantEnc || layout.chunkCount < 1 || layout.chunkCount.toLong() > totalBlocks.toLong()) {
            throw SyncError(
                code = ErrorCode.ERR_MANIFEST_INVALID,
                rawMessage = "part_id=${blob.partId} layout (bytes=${layout.totalBytes}, chunks=${layout.chunkCount}) mismatches signed blob size (${blob.size} -> enc=$wantEnc, blocks=$totalBlocks)",
            )
        }
    }

    ensureSafeRealDir(st.tempDir)
    val msgDir = File(st.tempDir, manifest.msgId)
    ensureSafeRealDir(msgDir)
    trackMsgDir(msgDir)

    var doneBytes = initialDoneBytes
    val startedAtNs = System.nanoTime()
    val out = ArrayList<ReceivedBlob>(manifest.blobs.size)

    for (blob in manifest.blobs) {
        currentCoroutineContext().ensureActive()
        val layout = partMap.getValue(blob.partId)
        val wantEnc = StreamCipher.encryptedPartSize(blob.size)
        val totalBlocks = StreamCipher.totalBlocks(blob.size)

        val partFile = File(msgDir, "part_${blob.partId}.part")
        val verifiedFile = File(msgDir, "part_${blob.partId}.verified")

        // Skip re-downloading already-verified blobs on multi-part resume (`ST-P1-13`)
        if (mode == DeliveryMode.SPOOL && withContext(Dispatchers.IO) { verifyExistingFileSha256(verifiedFile, blob.size, blob.sha256) }) {
            doneBytes += wantEnc
            out.add(
                ReceivedBlob(
                    descriptor = blob,
                    safeFile = verifiedFile,
                    safeName = ManifestCodec.sanitizeFilename(blob.name),
                )
            )
            continue
        }

        val rawKey = try {
            KeysAndAuth.b64uDecode(blob.key)
        } catch (_: Exception) {
            msgDir.deleteRecursively()
            throw SyncError(ErrorCode.ERR_MANIFEST_INVALID, rawMessage = "invalid blob key")
        }
        val (encKey, np) = try {
            StreamCipher.deriveBlobPartKeys(msgIdRaw16, blob.partId, rawKey)
        } finally {
            KeysAndAuth.zeroBytes(rawKey)
        }
        val sc = StreamCipher(encKey, np, msgIdRaw16, blob.partId)
        KeysAndAuth.zeroBytes(encKey, np)

        try {
            if (Files.exists(partFile.toPath(), LinkOption.NOFOLLOW_LINKS) &&
                (!Files.isRegularFile(partFile.toPath(), LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(partFile.toPath()))
            ) {
                msgDir.deleteRecursively()
                throw SyncError(ErrorCode.ERR_STORAGE_IO, rawMessage = "refusing non-regular temp part file")
            }

            var startTx = 0
            var initialBlkIdx = 0u
            var resumed = false
            if (mode == DeliveryMode.SPOOL) {
                val cp = keyStore.getCheckpoint("recv", manifest.msgId, blob.partId)
                // Require strictly `nextTxIdx < layout.chunkCount` (`#378` P2-4)
                if (cp != null && cp.nextTxIdx in 1 until layout.chunkCount && cp.nextBlockIdx > 0L) {
                    val expectedPartialPlaintext = cp.nextBlockIdx * StreamCipher.CHUNK_PLAINTEXT_MAX.toLong()
                    if (partFile.exists() && partFile.isFile && partFile.length() == expectedPartialPlaintext) {
                        startTx = cp.nextTxIdx
                        initialBlkIdx = cp.nextBlockIdx.toUInt()
                        resumed = true
                    }
                }
            }

            var partDone = if (resumed) initialBlkIdx.toLong() * StreamCipher.CHUNK_CIPHERTEXT_MAX.toLong() else 0L
            if (resumed) {
                doneBytes += partDone
            }

            var sawFinal = false
            withContext(Dispatchers.IO) {
                RandomAccessFile(partFile, "rw").use { raf ->
                    if (resumed) {
                        raf.seek(raf.length())
                    } else {
                        raf.setLength(0L)
                    }
                    val fileSink = object : OutputStream() {
                        override fun write(b: Int) = raf.write(b)
                        override fun write(b: ByteArray, off: Int, len: Int) = raf.write(b, off, len)
                    }
                    val dec = RollingBlockDecryptor(sc, totalBlocks, initialBlkIdx, fileSink)

                    for (tx in startTx until layout.chunkCount) {
                        dec.ensureNotFinalBeforeChunk()
                        var chunkBytesSeen = 0L
                        try {
                            streamChunkToSink(blob.partId, tx) { slice, len ->
                                chunkBytesSeen += len.toLong()
                                if (partDone + chunkBytesSeen > wantEnc) {
                                    throw SyncError(
                                        code = ErrorCode.ERR_MANIFEST_INVALID,
                                        rawMessage = "part_id=${blob.partId} ciphertext stream exceeded signed EncryptedPartSize ($wantEnc)",
                                    )
                                }
                                dec.feedSlice(slice, len)
                            }
                        } catch (se: SyncError) {
                            if (se.isSecurityAlert || se.code == ErrorCode.ERR_MANIFEST_INVALID) {
                                throw se
                            }
                            if (mode == DeliveryMode.SPOOL && tx > 0) {
                                throw SyncError(
                                    code = ErrorCode.ERR_INTERRUPTED_RESUMABLE,
                                    retryable = true,
                                    rawMessage = "blob download interrupted with checkpoint saved",
                                    rawCause = se,
                                )
                            }
                            throw se
                        }

                        if (chunkBytesSeen == 0L) {
                            throw SyncError(ErrorCode.ERR_STREAM_TRUNCATED, rawMessage = "empty transport chunk")
                        }
                        dec.finishTransportChunk()

                        partDone += chunkBytesSeen
                        doneBytes += chunkBytesSeen

                        if (mode == DeliveryMode.SPOOL && tx + 1 < layout.chunkCount) {
                            keyStore.putCheckpoint(
                                TransferCheckpoint(
                                    direction = "recv", msgId = manifest.msgId, itemId = itemId,
                                    partId = blob.partId, nextTxIdx = tx + 1, nextBlockIdx = dec.blkIdx.toLong(),
                                    expiresAt = expiresAt,
                                )
                            )
                        }

                        if (onProgress != null) {
                            val elapsedSec = ((System.nanoTime() - startedAtNs) / 1_000_000_000.0).coerceAtLeast(0.001)
                            val bps = (doneBytes / elapsedSec).toLong()
                            onProgress(
                                TransferEvent(
                                    stage = "transferring", direction = "recv", mode = mode, msgId = manifest.msgId,
                                    partId = blob.partId, partsTotal = partMap.size, bytesDone = doneBytes,
                                    bytesTotal = totalBytes, partBytesDone = partDone, partBytesTotal = layout.totalBytes,
                                    speedBps = bps, resumed = resumed,
                                )
                            )
                        }
                    }

                    sawFinal = dec.sawFinal
                    raf.fd.sync()
                }
            }

            if (!sawFinal || partDone != wantEnc) {
                msgDir.deleteRecursively()
                keyStore.deleteCheckpoint("recv", manifest.msgId, blob.partId)
                throw SyncError(ErrorCode.ERR_STREAM_TRUNCATED, rawMessage = "blob stream missing authenticated final block")
            }

            val shaMatches = withContext(Dispatchers.IO) {
                verifyExistingFileSha256(partFile, blob.size, blob.sha256)
            }
            if (!shaMatches) {
                msgDir.deleteRecursively()
                keyStore.deleteCheckpoint("recv", manifest.msgId, blob.partId)
                throw SyncError(ErrorCode.ERR_HASH_MISMATCH, rawMessage = "part_id=${blob.partId} size/sha256 mismatch")
            }

            keyStore.deleteCheckpoint("recv", manifest.msgId, blob.partId)
            withContext(Dispatchers.IO) {
                atomicMoveWithRetry(partFile, verifiedFile)
            }

            out.add(
                ReceivedBlob(
                    descriptor = blob,
                    safeFile = verifiedFile,
                    safeName = ManifestCodec.sanitizeFilename(blob.name),
                )
            )
        } catch (se: SyncError) {
            if (se.code != ErrorCode.ERR_INTERRUPTED_RESUMABLE && !se.retryable) {
                runCatching { msgDir.deleteRecursively() }
                keyStore.deleteCheckpoint("recv", manifest.msgId, blob.partId)
            }
            throw se
        } finally {
            sc.zero()
        }
    }
    return out
}
