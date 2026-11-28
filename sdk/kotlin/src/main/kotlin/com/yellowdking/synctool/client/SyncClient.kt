package com.yellowdking.synctool.client

import com.yellowdking.synctool.crypto.CryptoException
import com.yellowdking.synctool.crypto.DeviceKeys
import com.yellowdking.synctool.crypto.Handshake
import com.yellowdking.synctool.crypto.KeysAndAuth
import com.yellowdking.synctool.crypto.MailboxKeys
import com.yellowdking.synctool.crypto.SealedHeader
import com.yellowdking.synctool.crypto.StreamCipher
import com.yellowdking.synctool.envelope.CachedManifestEntry
import com.yellowdking.synctool.envelope.DeviceCard
import com.yellowdking.synctool.envelope.DirectRoomInitPayload
import com.yellowdking.synctool.envelope.ErrorCode
import com.yellowdking.synctool.envelope.KeyStore
import com.yellowdking.synctool.envelope.Manifest
import com.yellowdking.synctool.envelope.ManifestCodec
import com.yellowdking.synctool.envelope.MemoryKeyStore
import com.yellowdking.synctool.envelope.PairBindPayload
import com.yellowdking.synctool.envelope.ParcelInput
import com.yellowdking.synctool.envelope.PartLayout
import com.yellowdking.synctool.envelope.PipeAckPayload
import com.yellowdking.synctool.envelope.PipeStartPayload
import com.yellowdking.synctool.envelope.ReceivedParcel
import com.yellowdking.synctool.envelope.RelayCertExpiringEvent
import com.yellowdking.synctool.envelope.RelayProfile
import com.yellowdking.synctool.envelope.SyncError
import com.yellowdking.synctool.envelope.SyncUri
import java.io.ByteArrayInputStream
import java.io.Closeable
import java.io.File
import java.net.InetAddress
import java.nio.charset.StandardCharsets
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.longOrNull
import kotlinx.serialization.json.jsonPrimitive

/**
 * Canonical pure-JVM / Android-compatible `synctool-v1` SDK client.
 */
class SyncClient(
    private val config: SyncClientConfig,
) : Closeable {

    constructor(
        relayUri: String,
        keyStore: KeyStore = MemoryKeyStore(),
        appId: String = "synctool.sdk",
        deviceLabel: String = "",
        platform: String = SyncClientConfig.defaultPlatform(),
        tempDir: File? = null,
        onCertExpiring: ((RelayCertExpiringEvent) -> Unit)? = null,
    ) : this(
        SyncClientConfig(
            relay = SyncUri.parseRelayUri(relayUri),
            keyStore = keyStore,
            appId = appId,
            deviceLabel = deviceLabel,
            platform = platform,
            tempDir = tempDir,
            onCertExpiring = onCertExpiring,
        )
    )

    internal val transport: SyncTransport = SyncTransport(config.relay)
    val keyStore: KeyStore = config.keyStore
    val appId: String = config.appId.ifBlank { "synctool.sdk" }
    val platform: String = config.platform.ifBlank { SyncClientConfig.defaultPlatform() }

    private val initMutex = Mutex()
    private var deviceKeysInternal: DeviceKeys? = null
    private var mailboxKeysInternal: MailboxKeys? = null
    private var resolvedLabelInternal: String = config.deviceLabel.trim()
    private var resolvedTempDirInternal: File? = config.tempDir

    private val closed = AtomicBoolean(false)
    private val activeCalls = AtomicInteger(0)

    internal val tempDirsMutex = Mutex()
    internal val createdMsgDirs = LinkedHashSet<File>()

    internal val inFlightMutex = Mutex()
    internal val inFlightMsgIds = HashSet<String>()

    // Tracks verified (msgId, createdAt) for two-step fetchParcel(..., autoAck=false) -> ackItem(itemId)
    internal val pendingAckItems = ConcurrentHashMap<String, Pair<String, Long>>()

    val relayProfile: RelayProfile
        get() = transport.profile

    fun getClockOffsetSec(): Long = transport.getClockOffsetSec()

    fun setClockOffsetSec(offsetSec: Long) {
        transport.setClockOffsetSec(offsetSec)
    }

    internal data class InitializedState(
        val deviceKeys: DeviceKeys,
        val mailboxKeys: MailboxKeys,
        val deviceLabel: String,
        val tempDir: File,
    )

    internal suspend fun ensureInitialized(): InitializedState {
        initMutex.withLock {
            if (closed.get()) {
                throw SyncError(ErrorCode.ERR_CANCELLED, rawMessage = "SyncClient is closed")
            }
            val existingDk = deviceKeysInternal
            val existingMk = mailboxKeysInternal
            val existingTmp = resolvedTempDirInternal
            if (existingDk != null && existingMk != null && existingTmp != null) {
                return InitializedState(existingDk, existingMk, resolvedLabelInternal, existingTmp)
            }

            val seed = keyStore.loadOrCreateMasterSeed()
            val dk = try {
                KeysAndAuth.deriveDeviceKeys(seed)
            } catch (e: Exception) {
                throw SyncError(ErrorCode.ERR_KEYSTORE_ERROR, rawMessage = "derive device keys", rawCause = e)
            } finally {
                KeysAndAuth.zeroBytes(seed)
            }
            val mk = try {
                dk.deriveMailboxKeys(transport.profile.relayId)
            } catch (e: Exception) {
                dk.zero()
                throw SyncError(ErrorCode.ERR_KEYSTORE_ERROR, rawMessage = "derive mailbox keys", rawCause = e)
            }

            if (resolvedLabelInternal.isEmpty()) {
                val stored = keyStore.getLocalLabel()?.trim().orEmpty()
                resolvedLabelInternal = when {
                    stored.isNotEmpty() -> stored
                    else -> runCatching { InetAddress.getLocalHost().hostName?.trim().orEmpty() }
                        .getOrDefault("")
                        .ifEmpty { "synctool-device" }
                }
            }

            val tmp = resolvedTempDirInternal ?: File(
                System.getProperty("java.io.tmpdir", "."),
                "synctool-tmp-${dk.deviceId.take(12)}",
            )

            deviceKeysInternal = dk
            mailboxKeysInternal = mk
            resolvedTempDirInternal = tmp
            return InitializedState(dk, mk, resolvedLabelInternal, tmp)
        }
    }

    internal suspend inline fun <T> withActiveCall(crossinline block: suspend () -> T): T {
        if (closed.get()) {
            throw SyncError(ErrorCode.ERR_CANCELLED, rawMessage = "SyncClient is closed")
        }
        activeCalls.incrementAndGet()
        try {
            if (closed.get()) {
                throw SyncError(ErrorCode.ERR_CANCELLED, rawMessage = "SyncClient is closed")
            }
            return block()
        } finally {
            activeCalls.decrementAndGet()
        }
    }

    suspend fun getIdentity(): DeviceIdentity = withActiveCall {
        val st = ensureInitialized()
        DeviceIdentity(
            deviceId = st.deviceKeys.deviceId,
            label = st.deviceLabel,
            signPkB64u = KeysAndAuth.b64uEncode(st.deviceKeys.signPub),
            kemPkB64u = KeysAndAuth.b64uEncode(st.deviceKeys.kemPubBytes),
            mailboxId = st.mailboxKeys.mailboxId,
            relayId = transport.profile.relayId,
        )
    }

    // --- System Probe & Capabilities ---

    suspend fun ping(): PingResult = withActiveCall {
        val startNs = System.nanoTime()
        val resp = transport.doControl("GET", "/v1/ping")
        val parsed = try {
            ManifestCodec.json.decodeFromString(
                PingResult.serializer(),
                String(resp.body, StandardCharsets.UTF_8),
            )
        } catch (e: Exception) {
            throw SyncError(
                code = ErrorCode.ERR_BAD_REQUEST,
                httpStatus = resp.statusCode,
                rawMessage = "decode ping response",
                rawCause = e,
            )
        }
        val rttMs = (System.nanoTime() - startNs) / 1_000_000L
        val offset = parsed.serverTs - (System.currentTimeMillis() / 1000L)
        checkCertRotation(parsed.certExpiresAt, parsed.certRotateRecommended)
        parsed.copy(rttMs = rttMs, clockOffsetSec = offset)
    }

    suspend fun capabilities(): RelayCaps = withActiveCall {
        val resp = transport.doControl("GET", "/v1/caps")
        val parsed = try {
            ManifestCodec.json.decodeFromString(
                RelayCaps.serializer(),
                String(resp.body, StandardCharsets.UTF_8),
            )
        } catch (e: Exception) {
            throw SyncError(
                code = ErrorCode.ERR_BAD_REQUEST,
                httpStatus = resp.statusCode,
                rawMessage = "decode caps response",
                rawCause = e,
            )
        }
        checkCertRotation(parsed.certExpiresAt, parsed.certRotateRecommended)
        parsed
    }

    internal fun checkCertRotation(expiresAt: Long, recommended: Boolean) {
        val cb = config.onCertExpiring ?: return
        if (expiresAt <= 0L) return
        val remSec = expiresAt - (System.currentTimeMillis() / 1000L)
        val days = (remSec / 86_400L).toInt()
        if (recommended || days < 30) {
            val sev = if (days <= 7) "urgent" else "warning"
            cb(
                RelayCertExpiringEvent(
                    relayId = transport.profile.relayId,
                    expiresAt = expiresAt,
                    daysRemaining = days,
                    severity = sev,
                )
            )
        }
    }

    // --- Mode A: Flow 1 Device Binding & One-Shot Streaming ---

    suspend fun initiateDeviceBind(options: PairOptions = PairOptions()): DeviceCard = withActiveCall {
        val st = ensureInitialized()
        val sess = runInitiatorHandshake(st, Handshake.PURPOSE_PAIR, options)
        var registeredTokenId = ""
        var bindSucceeded = false
        try {
            val localBind = buildLocalPairBind(st, options.label)
            registeredTokenId = localBind.inboundTokenId

            val myJson = ManifestCodec.json.encodeToString(PairBindPayload.serializer(), localBind.payload)
                .toByteArray(StandardCharsets.UTF_8)
            val ctA = Handshake.sealPairBind(sess.hs.sessionKey, sess.hs.prk, sess.hs.th, isInitiator = true, plaintext = myJson)
            val frameA = ManifestCodec.json.encodeToString(
                PairBindWire.serializer(),
                PairBindWire(ct = KeysAndAuth.b64uEncode(ctA)),
            ).toByteArray(StandardCharsets.UTF_8)

            sess.lastSeq = postRoomMessage(sess.roomId, sess.token, "handshake", frameA)

            val (peerMsg, _) = waitForPeerRoomMessage(sess.roomId, sess.token, "receiver", sess.lastSeq)
            val peerBind = decodeAndOpenPeerPairBind(sess, peerMsg, fromInitiator = false)
            val card = verifyAndSavePeerBind(st, peerBind, localBind.inboundTokenId, localBind.inboundTokenHash)
            bindSucceeded = true
            closeRoomBestEffort(sess.roomId, sess.token, "completed")
            card
        } finally {
            sess.hs.zero()
            if (!bindSucceeded && registeredTokenId.isNotEmpty()) {
                deleteRelayDepositTokenBestEffort(st, registeredTokenId)
            }
        }
    }

    suspend fun startDeviceBind(options: PairOptions = PairOptions()): DeviceCard = initiateDeviceBind(options)

    suspend fun acceptDeviceBind(pairInput: String, options: PairOptions = PairOptions()): DeviceCard = withActiveCall {
        val st = ensureInitialized()
        val (roomId, oob) = parseRoomInput(pairInput)
        try {
            val (joined, m1) = joinAndReadM1(roomId)
            if (m1.purpose != Handshake.PURPOSE_PAIR) {
                closeRoomBestEffort(roomId, joined.receiverToken, "verify_failed")
                throw SyncError(ErrorCode.ERR_INVALID_STATE, rawMessage = "room purpose is not pair")
            }
            // ST-P0-1: runResponderHandshake enforces upfront non-null onSASConfirm before M2 and invokes onSASConfirm immediately after M4!
            val sess = runResponderHandshake(joined, m1, oob, options.onSASDisplay, options.onSASConfirm)
            var registeredTokenId = ""
            var bindSucceeded = false
            try {
                // Wait for Initiator's encrypted pair_bind frame (after both sides confirmed SAS in mode=2)
                val (peerMsg, nextSeq) = waitForPeerRoomMessage(sess.roomId, sess.token, "sender", sess.lastSeq)
                sess.lastSeq = nextSeq
                val peerBind = decodeAndOpenPeerPairBind(sess, peerMsg, fromInitiator = true)
                // Validate peer DeviceCard signature before saving or registering deposit token
                verifyPeerBindCardOnly(peerBind, sess.roomId, sess.token)

                val localBind = buildLocalPairBind(st, options.label)
                registeredTokenId = localBind.inboundTokenId
                val card = verifyAndSavePeerBind(st, peerBind, localBind.inboundTokenId, localBind.inboundTokenHash)

                val myJson = ManifestCodec.json.encodeToString(PairBindPayload.serializer(), localBind.payload)
                    .toByteArray(StandardCharsets.UTF_8)
                val ctB = Handshake.sealPairBind(sess.hs.sessionKey, sess.hs.prk, sess.hs.th, isInitiator = false, plaintext = myJson)
                val frameB = ManifestCodec.json.encodeToString(
                    PairBindWire.serializer(),
                    PairBindWire(ct = KeysAndAuth.b64uEncode(ctB)),
                ).toByteArray(StandardCharsets.UTF_8)

                postRoomMessage(sess.roomId, sess.token, "handshake", frameB)
                bindSucceeded = true
                card
            } finally {
                sess.hs.zero()
                if (!bindSucceeded && registeredTokenId.isNotEmpty()) {
                    deleteRelayDepositTokenBestEffort(st, registeredTokenId)
                }
            }
        } finally {
            KeysAndAuth.zeroBytes(oob)
        }
    }

    suspend fun startOneShotSend(parcel: ParcelInput, options: PairOptions = PairOptions()): SendResult = withActiveCall {
        val st = ensureInitialized()
        val caps = capabilities()
        val blocksPerChunk = caps.streaming.blocksPerChunk.takeIf { it > 0 } ?: 16
        val prep = prepareParcel(st, parcel, blocksPerChunk)
        try {
            val sess = runInitiatorHandshake(st, Handshake.PURPOSE_ONESHOT, options)
            val (p0Key, p0Np) = Handshake.deriveOneshotPart0Keys(sess.hs.sessionKey, prep.msgIdRaw)
            val (ctrlKey, ctrlNp) = Handshake.derivePipeCtrlKeys(sess.hs.th, sess.hs.sessionKey)
            try {
                val startCmd = ManifestCodec.json.encodeToString(
                    PipeStartPayload.serializer(),
                    PipeStartPayload(
                        msgId = prep.msgId,
                        blocksPerChunk = blocksPerChunk,
                        parts = prep.parts,
                    ),
                ).toByteArray(StandardCharsets.UTF_8)
                val startCt = Handshake.sealPipeCtrl(ctrlKey, ctrlNp, sess.hs.th, 0L, startCmd)
                val ctrlFrame = ManifestCodec.json.encodeToString(
                    PipeCtrlWire.serializer(),
                    PipeCtrlWire(ctrlSeq = 0L, ct = KeysAndAuth.b64uEncode(startCt)),
                ).toByteArray(StandardCharsets.UTF_8)
                sess.lastSeq = postRoomMessage(sess.roomId, sess.token, "control", ctrlFrame)

                try {
                    uploadAllPipeParts(sess.pipeId, sess.token, prep, p0Key, p0Np, blocksPerChunk, options.onProgress)
                } catch (t: Throwable) {
                    closeRoomBestEffort(sess.roomId, sess.token, "cancelled")
                    throw t
                }

                val (ackWire, _) = waitForPeerRoomMessage(sess.roomId, sess.token, "receiver", sess.lastSeq)
                verifyOneshotPipeAck(sess, ctrlKey, ctrlNp, ackWire, prep.msgId)
                closeRoomBestEffort(sess.roomId, sess.token, "completed")
                SendResult(
                    mode = DeliveryMode.PIPE,
                    msgId = prep.msgId,
                    roomId = sess.roomId,
                    totalBytes = prep.totalEnc,
                )
            } finally {
                KeysAndAuth.zeroBytes(p0Key, p0Np, ctrlKey, ctrlNp)
                sess.hs.zero()
            }
        } finally {
            prep.zero()
        }
    }

    suspend fun receiveOneShot(
        pairInput: String,
        options: ReceiveOptions = ReceiveOptions(),
        handler: (suspend (ReceivedParcel) -> Unit)? = null,
    ): ReceivedParcel = receiveFromRoom(pairInput, options, handler)

    suspend fun receiveDirect(
        pairInput: String,
        options: ReceiveOptions = ReceiveOptions(),
        handler: (suspend (ReceivedParcel) -> Unit)? = null,
    ): ReceivedParcel = receiveFromRoom(pairInput, options, handler)

    suspend fun receiveFromRoom(
        pairInput: String,
        options: ReceiveOptions = ReceiveOptions(),
        handler: (suspend (ReceivedParcel) -> Unit)? = null,
    ): ReceivedParcel = withActiveCall {
        val st = ensureInitialized()
        val (roomId, oob) = parseRoomInput(pairInput)
        try {
            val (joined, rawM1) = joinAndReadRawM1(roomId)
            val probe = try {
                ManifestCodec.json.decodeFromString(
                    RoomM1Probe.serializer(),
                    String(rawM1, StandardCharsets.UTF_8),
                )
            } catch (_: Exception) {
                closeRoomBestEffort(roomId, joined.receiverToken, "verify_failed")
                throw SyncError(ErrorCode.ERR_CRYPTO_HANDSHAKE_FAILED, rawMessage = "invalid room M1 frame")
            }
            if (probe.protoV > 1) {
                closeRoomBestEffort(roomId, joined.receiverToken, "verify_failed")
                throw SyncError(
                    code = ErrorCode.ERR_UNSUPPORTED_VERSION,
                    rawMessage = "unsupported room M1 proto_v ${probe.protoV}",
                    rawDetails = mapOf(
                        "proto_v" to JsonPrimitive(probe.protoV),
                        "supported_proto_v" to JsonPrimitive(1),
                    ),
                )
            }
            if (probe.protoV != 1) {
                closeRoomBestEffort(roomId, joined.receiverToken, "verify_failed")
                throw SyncError(ErrorCode.ERR_CRYPTO_HANDSHAKE_FAILED, rawMessage = "invalid room M1 proto_v")
            }

            if (probe.mode == Handshake.MODE_DIRECT && probe.purpose == Handshake.PURPOSE_DIRECT) {
                val initPayload = try {
                    ManifestCodec.json.decodeFromString(
                        DirectRoomInitPayload.serializer(),
                        String(rawM1, StandardCharsets.UTF_8),
                    )
                } catch (_: Exception) {
                    closeRoomBestEffort(roomId, joined.receiverToken, "verify_failed")
                    throw SyncError(ErrorCode.ERR_CRYPTO_HANDSHAKE_FAILED, rawMessage = "invalid direct M1 payload")
                }
                return@withActiveCall receiveDirectJoined(st, joined, initPayload, options, handler)
            }

            val m1 = try {
                ManifestCodec.json.decodeFromString(
                    HsM1Wire.serializer(),
                    String(rawM1, StandardCharsets.UTF_8),
                )
            } catch (_: Exception) {
                closeRoomBestEffort(roomId, joined.receiverToken, "verify_failed")
                throw SyncError(ErrorCode.ERR_CRYPTO_HANDSHAKE_FAILED, rawMessage = "invalid handshake M1")
            }
            if (m1.purpose != Handshake.PURPOSE_ONESHOT) {
                closeRoomBestEffort(roomId, joined.receiverToken, "verify_failed")
                throw SyncError(ErrorCode.ERR_INVALID_STATE, rawMessage = "unexpected room purpose for receive")
            }
            receiveOneShotJoined(st, joined, m1, oob, options, handler)
        } finally {
            KeysAndAuth.zeroBytes(oob)
        }
    }

    // --- Mode B: Blinded Mailboxes, 0-RTT Spool, Two-Phase Inbox, Watch & Revoke ---

    suspend fun registerMailbox(): MailboxRegisterResponse = withActiveCall {
        val st = ensureInitialized()
        val path = "/v1/mailboxes/${st.mailboxKeys.mailboxId}"
        val reqBytes = ManifestCodec.json.encodeToString(
            MailboxPutReq.serializer(),
            MailboxPutReq(authPkB64 = KeysAndAuth.b64uEncode(st.mailboxKeys.authPub)),
        ).toByteArray(StandardCharsets.UTF_8)

        val resp = try {
            transport.doControl(
                method = "PUT",
                pathAndQuery = path,
                jsonBodyBytes = reqBytes,
                opts = RequestAuthOptions(
                    mailboxId = st.mailboxKeys.mailboxId,
                    mailboxAuthSeed32 = st.mailboxKeys.authSeed,
                ),
            )
        } catch (se: SyncError) {
            if (se.code == ErrorCode.ERR_SPOOL_DISABLED) {
                return@withActiveCall MailboxRegisterResponse(
                    mailboxId = st.mailboxKeys.mailboxId,
                    registered = false,
                    depositTokenCount = 0,
                )
            }
            throw se
        }
        ManifestCodec.json.decodeFromString(
            MailboxRegisterResponse.serializer(),
            String(resp.body, StandardCharsets.UTF_8),
        )
    }

    /**
     * Idempotently registers this device's blinded mailbox and restores all active non-revoked
     * peer `deposit_token` hashes. Gracefully returns `false` without throwing when the relay
     * runs with `--spool=off` (`403 ERR_SPOOL_DISABLED`).
     */
    suspend fun syncMailbox(): Boolean = withActiveCall {
        val st = ensureInitialized()
        syncMailboxInternal(st)
    }

    suspend fun sendToPeer(
        targetDeviceId: String,
        parcel: ParcelInput,
        options: SendOptions = SendOptions(),
    ): SendResult = withActiveCall {
        val st = ensureInitialized()
        val mode = options.deliveryMode.ifEmpty { DeliveryMode.AUTO }
        if (mode != DeliveryMode.AUTO && mode != DeliveryMode.SPOOL && mode != DeliveryMode.PIPE) {
            throw SyncError(ErrorCode.ERR_BAD_REQUEST, rawMessage = "invalid deliveryMode: $mode")
        }

        val card = keyStore.getDevice(targetDeviceId)
        if (card == null || card.revoked) {
            throw SyncError(ErrorCode.ERR_DEVICE_UNTRUSTED, rawMessage = "target device is untrusted or revoked")
        }
        val kemPk = try {
            KeysAndAuth.b64uDecode(card.kemPk)
        } catch (_: Exception) {
            throw SyncError(ErrorCode.ERR_CRYPTO_SIGNATURE_INVALID, rawMessage = "invalid target kem_pk")
        }
        if (kemPk.size != 32) {
            throw SyncError(ErrorCode.ERR_CRYPTO_SIGNATURE_INVALID, rawMessage = "invalid target kem_pk length")
        }
        val recipIdRaw = try {
            KeysAndAuth.fromHex(card.deviceId)
        } catch (_: Exception) {
            throw SyncError(ErrorCode.ERR_DEVICE_UNTRUSTED, rawMessage = "invalid target device_id")
        }
        if (recipIdRaw.size != 16) {
            throw SyncError(ErrorCode.ERR_DEVICE_UNTRUSTED, rawMessage = "invalid target device_id length")
        }

        val caps = capabilities()
        val blocksPerChunk = caps.streaming.blocksPerChunk.takeIf { it > 0 } ?: 16
        val prep = prepareParcel(st, parcel, blocksPerChunk)
        try {
            val (ephSk, _) = KeysAndAuth.generateEphemeralX25519()
            val sealed = try {
                SealedHeader.seal0RttHeaderDeterministic(
                    senderKeys = st.deviceKeys,
                    ephemeralSk32 = ephSk,
                    msgIdRaw16 = prep.msgIdRaw,
                    recipientIdRaw16 = recipIdRaw,
                    recipientKemPub32 = kemPk,
                    createdAt = prep.createdAt,
                    manifestSha256 = prep.manifestSha256,
                )
            } catch (e: CryptoException) {
                throw SyncError(ErrorCode.ERR_CRYPTO_HANDSHAKE_FAILED, rawMessage = "seal 0-RTT header", rawCause = e)
            } finally {
                KeysAndAuth.zeroBytes(ephSk)
            }

            try {
                val sealedB64 = KeysAndAuth.b64uEncode(sealed.sealedHeader)
                if (mode == DeliveryMode.PIPE) {
                    return@withActiveCall sendDirectViaPipe(
                        prep = prep,
                        sealedB64 = sealedB64,
                        p0Key = sealed.part0Key,
                        p0Np = sealed.part0NoncePrefix,
                        blocksPerChunk = blocksPerChunk,
                        options = options,
                    )
                }

                if (!caps.spool.enabled) {
                    throw SyncError(
                        code = ErrorCode.ERR_SPOOL_DISABLED,
                        retryable = false,
                        httpStatus = 403,
                        rawMessage = "relay spool is disabled (--spool=off); use pipe mode",
                        rawDetails = mapOf("suggest_mode" to JsonPrimitive("pipe")),
                    )
                }
                if (card.mailboxId.isEmpty() || card.outboundDepositToken.isEmpty()) {
                    throw SyncError(
                        code = ErrorCode.ERR_SPOOL_DISABLED,
                        retryable = false,
                        httpStatus = 403,
                        rawMessage = "peer device was paired without mailbox; use pipe mode",
                        rawDetails = mapOf("suggest_mode" to JsonPrimitive("pipe")),
                    )
                }
                if (caps.spool.maxItemBytes > 0L && prep.totalEnc > caps.spool.maxItemBytes) {
                    throw SyncError(
                        code = ErrorCode.ERR_OFFLINE_QUOTA_EXCEEDED,
                        retryable = false,
                        httpStatus = 413,
                        rawMessage = "parcel exceeds relay spool max_item_bytes",
                        rawDetails = mapOf(
                            "scope" to JsonPrimitive("item"),
                            "max_item_bytes" to JsonPrimitive(caps.spool.maxItemBytes),
                            "total_bytes" to JsonPrimitive(prep.totalEnc),
                            "suggest_mode" to JsonPrimitive("pipe"),
                        ),
                    )
                }

                val initReqBytes = ManifestCodec.json.encodeToString(
                    SpoolInitReq.serializer(),
                    SpoolInitReq(
                        mailboxId = card.mailboxId,
                        declaredTotalBytes = prep.totalEnc,
                        ttlSec = options.ttlSec,
                        sealedHeader = sealedB64,
                        parts = prep.parts,
                    ),
                ).toByteArray(StandardCharsets.UTF_8)

                val initResp = transport.doControl(
                    method = "POST",
                    pathAndQuery = "/v1/spool/init",
                    jsonBodyBytes = initReqBytes,
                    opts = RequestAuthOptions(depositToken = card.outboundDepositToken),
                )
                val initOut = ManifestCodec.json.decodeFromString(
                    SpoolInitResp.serializer(),
                    String(initResp.body, StandardCharsets.UTF_8),
                )

                var committed = false
                try {
                    uploadAllSpoolParts(
                        itemId = initOut.itemId,
                        uploadToken = initOut.uploadToken,
                        prep = prep,
                        p0Key = sealed.part0Key,
                        p0Np = sealed.part0NoncePrefix,
                        blocksPerChunk = blocksPerChunk,
                        onProgress = options.onProgress,
                    )

                    val commitResp = transport.doControl(
                        method = "POST",
                        pathAndQuery = "/v1/spool/${initOut.itemId}/commit",
                        jsonBodyBytes = "{}".toByteArray(StandardCharsets.UTF_8),
                        opts = RequestAuthOptions(uploadToken = initOut.uploadToken),
                    )
                    committed = true
                    val commitOut = runCatching {
                        ManifestCodec.json.decodeFromString(
                            SpoolCommitResp.serializer(),
                            String(commitResp.body, StandardCharsets.UTF_8),
                        )
                    }.getOrNull()
                    val finalExp = commitOut?.expiresAt?.takeIf { it > 0L } ?: initOut.expiresAt

                    SendResult(
                        mode = DeliveryMode.SPOOL,
                        msgId = prep.msgId,
                        itemId = initOut.itemId,
                        totalBytes = prep.totalEnc,
                        expiresAt = finalExp,
                    )
                } finally {
                    if (!committed) {
                        abortUncommittedSpoolBestEffort(initOut.itemId, initOut.uploadToken)
                    }
                }
            } finally {
                KeysAndAuth.zeroBytes(sealed.part0Key, sealed.part0NoncePrefix)
            }
        } finally {
            prep.zero()
        }
    }

    suspend fun sendToDevice(
        targetDeviceId: String,
        parcel: ParcelInput,
        options: SendOptions = SendOptions(),
    ): SendResult = sendToPeer(targetDeviceId, parcel, options)

    /**
     * Phase 1 Two-Phase Inbox Listing:
     * Strictly verifies `SealedHeader` (`Open0RTTHeader`, `!card.revoked`, `hasSeenMsgId`, freshness window)
     * BEFORE returning any cached `Manifest` (`ST-P0-3`), preventing revoked sender leaks and `item_id` substitution.
     */
    suspend fun listInbox(filterAppId: String? = null): List<InboxPreview> = withActiveCall {
        val st = ensureInitialized()
        val items = try {
            listRawInboxItems(st)
        } catch (se: SyncError) {
            if (se.code == ErrorCode.ERR_SPOOL_DISABLED) {
                return@withActiveCall emptyList()
            }
            throw se
        }
        val activeIds = items.mapTo(HashSet(items.size)) { it.itemId }
        keyStore.pruneCachedManifests(activeIds)

        val previews = ArrayList<InboxPreview>(items.size)
        for (it in items) {
            val hdrBytes = try {
                KeysAndAuth.b64uDecode(it.sealedHeader)
            } catch (_: Exception) {
                keyStore.deleteCachedManifest(it.itemId)
                continue
            }
            val opened = try {
                openAndVerifySealedHeader(st, hdrBytes)
            } catch (_: SyncError) {
                keyStore.deleteCachedManifest(it.itemId)
                continue
            }

            try {
                val wantManifestShaHex = KeysAndAuth.toLowerHex(opened.manifestSha256)
                val cached = keyStore.getCachedManifest(it.itemId)
                if (cached != null) {
                    if (cached.manifest.msgId == opened.msgId && cached.manifestSha256 == wantManifestShaHex) {
                        if (filterAppId.isNullOrEmpty() || cached.manifest.appId == filterAppId) {
                            previews.add(
                                InboxPreview(
                                    itemId = it.itemId,
                                    createdAt = it.createdAt,
                                    expiresAt = it.expiresAt,
                                    totalBytes = it.totalBytes,
                                    cached = true,
                                    manifest = cached.manifest,
                                )
                            )
                        }
                        continue
                    } else {
                        // Evict stale/substituted cache entry
                        keyStore.deleteCachedManifest(it.itemId)
                    }
                }

                val p0Layout = it.parts.firstOrNull { p -> p.partId == 0 } ?: continue
                val (manifest, manifestSha) = try {
                    pullAndVerifyManifest(
                        msgIdRaw16 = opened.msgIdRaw,
                        msgIdHex = opened.msgId,
                        p0Key32 = opened.part0Key,
                        p0Np7 = opened.part0NoncePrefix,
                        p0Layout = p0Layout,
                        opened = opened,
                        fetchChunk = { txIdx -> getSpoolChunkBytes(st, it.itemId, 0, txIdx) },
                    )
                } catch (_: SyncError) {
                    continue
                }

                keyStore.putCachedManifest(
                    CachedManifestEntry(
                        itemId = it.itemId,
                        cachedAt = System.currentTimeMillis() / 1000L,
                        expiresAt = it.expiresAt,
                        manifestSha256 = KeysAndAuth.toLowerHex(manifestSha),
                        manifest = manifest,
                    )
                )

                if (filterAppId.isNullOrEmpty() || manifest.appId == filterAppId) {
                    previews.add(
                        InboxPreview(
                            itemId = it.itemId,
                            createdAt = it.createdAt,
                            expiresAt = it.expiresAt,
                            totalBytes = it.totalBytes,
                            cached = false,
                            manifest = manifest,
                        )
                    )
                }
            } finally {
                opened.zero()
            }
        }
        previews
    }

    /**
     * Phase 2 Resumable Parcel Pull (callback style — auto-ACKs after `handler` succeeds unless `options.autoAck == false`).
     */
    suspend fun fetchParcel(
        itemId: String,
        options: ReceiveOptions = ReceiveOptions(),
        handler: suspend (ReceivedParcel) -> Unit,
    ): Manifest = withActiveCall {
        val parcel = fetchParcelInternal(itemId = itemId, options = options, handler = handler)
        parcel.manifest
    }

    /**
     * Phase 2 Resumable Parcel Pull (direct suspend return style — defaults to `autoAck = false` so callers can
     * inspect/import `ReceivedParcel` and then call `ackItem(itemId)` to physically burn the relay copy).
     */
    suspend fun fetchParcel(
        itemId: String,
        appId: String? = null,
        autoAck: Boolean = false,
        onProgress: ((com.yellowdking.synctool.envelope.TransferEvent) -> Unit)? = null,
    ): ReceivedParcel = withActiveCall {
        fetchParcelInternal(
            itemId = itemId,
            options = ReceiveOptions(
                onProgress = onProgress,
                appId = appId,
                autoAck = autoAck,
            ),
            handler = null,
        )
    }

    /**
     * Sends an Ed25519-signed `POST /v1/spool/{itemId}/ack` to physically burn the spooled item on the relay,
     * recording `seen_msg_ids` (if tracked from `fetchParcel`) and evicting local Manifest cache.
     * Treats `404 ERR_NOT_FOUND` idempotently as already burned.
     */
    suspend fun ackItem(itemId: String): Unit = withActiveCall {
        val st = ensureInitialized()
        ackItemInternal(st, itemId)
    }

    /**
     * Subscribes to foreground mailbox events via SSE (`60s` read-idle timeout, `90s` server reconnect rotation)
     * with automatic `20s` Long-Poll fallback, `sinceTs - 1` same-second boundary protection, bounded 4,096-entry
     * FIFO dedup, and exponential backoff (`250ms -> 5s`).
     */
    fun watchInbox(initialSinceTs: Long? = null): Flow<InboxWatchEvent> = flow {
        watchInboxInternal(initialSinceTs) { ev ->
            emit(ev)
        }
    }

    suspend fun watchInbox(
        initialSinceTs: Long? = null,
        onEvent: suspend (InboxWatchEvent) -> Unit,
    ): Unit = withActiveCall {
        watchInboxInternal(initialSinceTs, onEvent)
    }

    /**
     * Two-Phase Precision Single-Device Revocation (`ST-P1-8`):
     * 1. Fails with `ERR_DEVICE_UNTRUSTED` if `deviceId` does not exist.
     * 2. Immediately persists `card.copy(revoked = true)` so local trust and `syncMailbox()` recovery are revoked offline.
     * 3. Calls `DELETE /v1/mailboxes/{mailboxId}/deposit-tokens/{inboundTokenId}` (ignoring `404`/`403 ERR_SPOOL_DISABLED`),
     *    and deletes the tombstone from `KeyStore` only after relay revocation completes (allowing idempotent offline retry).
     */
    suspend fun revokeDevice(deviceId: String): Unit = withActiveCall {
        val st = ensureInitialized()
        val card = keyStore.getDevice(deviceId)
            ?: throw SyncError(ErrorCode.ERR_DEVICE_UNTRUSTED, rawMessage = "device not found in keystore")

        val hasToken = card.inboundTokenId.isNotEmpty()
        if (!card.revoked || (hasToken && !card.pendingTokenDelete)) {
            keyStore.putDevice(card.copy(revoked = true, pendingTokenDelete = hasToken))
        }
        if (hasToken) {
            keyStore.addPendingTokenDelete(card.inboundTokenId)
            deleteRelayDepositTokenStrict(st, card.inboundTokenId)
            keyStore.removePendingTokenDelete(card.inboundTokenId)
        }

        keyStore.deleteDevice(card.deviceId)
    }

    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        transport.close()
        var spins = 0
        while (activeCalls.get() > 0 && spins < 200) {
            try {
                Thread.sleep(5)
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
                break
            }
            spins++
        }
        deviceKeysInternal?.zero()
        mailboxKeysInternal?.zero()
        deviceKeysInternal = null
        mailboxKeysInternal = null
        pendingAckItems.clear()
        val dirsSnapshot = synchronized(createdMsgDirs) {
            val copy = createdMsgDirs.toList()
            createdMsgDirs.clear()
            copy
        }
        for (dir in dirsSnapshot) {
            runCatching { dir.deleteRecursively() }
        }
    }

    internal fun trackMsgDir(dir: File) {
        synchronized(createdMsgDirs) {
            createdMsgDirs.add(dir)
        }
    }
}
