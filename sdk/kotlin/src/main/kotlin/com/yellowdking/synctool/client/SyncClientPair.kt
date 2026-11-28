package com.yellowdking.synctool.client

import com.yellowdking.synctool.crypto.Crockford
import com.yellowdking.synctool.crypto.CryptoException
import com.yellowdking.synctool.crypto.Handshake
import com.yellowdking.synctool.crypto.HandshakeResult
import com.yellowdking.synctool.crypto.KeysAndAuth
import com.yellowdking.synctool.envelope.DeviceCard
import com.yellowdking.synctool.envelope.DeviceCardPayload
import com.yellowdking.synctool.envelope.ErrorCode
import com.yellowdking.synctool.envelope.MailboxBindPayload
import com.yellowdking.synctool.envelope.ManifestCodec
import com.yellowdking.synctool.envelope.PairBindPayload
import com.yellowdking.synctool.envelope.PairOffer
import com.yellowdking.synctool.envelope.SyncError
import com.yellowdking.synctool.envelope.SyncUri
import java.nio.charset.StandardCharsets
import kotlinx.coroutines.CancellationException
import kotlinx.serialization.json.JsonPrimitive

// --- Mode A Flow 1A / 1B Handshake ---

internal suspend fun SyncClient.runInitiatorHandshake(
    st: SyncClient.InitializedState,
    purpose: String,
    options: PairOptions,
): ActiveRoomSession {
    val mode = if (options.mode == 0) Handshake.MODE_QR_OOB else options.mode
    if (mode != Handshake.MODE_QR_OOB && mode != Handshake.MODE_COMMIT_SAS) {
        throw SyncError(ErrorCode.ERR_BAD_REQUEST, rawMessage = "invalid handshake mode (use 1 or 2)")
    }

    val roomId = Crockford.generateRoomId()
    val (ephASk, ephAPub) = KeysAndAuth.generateEphemeralX25519()
    val nA = KeysAndAuth.randomBytes(Handshake.HS_NONCE_SIZE)
    val oob = if (mode == Handshake.MODE_QR_OOB) KeysAndAuth.randomBytes(Handshake.OOB_SECRET_SIZE) else ByteArray(0)
    val commitA = if (mode == Handshake.MODE_COMMIT_SAS) Handshake.computeCommitA(purpose, roomId, ephAPub, nA) else ByteArray(0)

    try {
        val m1 = if (mode == Handshake.MODE_QR_OOB) {
            HsM1Wire(
                mode = mode,
                purpose = purpose,
                eA = KeysAndAuth.b64uEncode(ephAPub),
                nA = KeysAndAuth.b64uEncode(nA),
            )
        } else {
            HsM1Wire(
                mode = mode,
                purpose = purpose,
                commitA = KeysAndAuth.b64uEncode(commitA),
            )
        }
        val m1Bytes = ManifestCodec.json.encodeToString(HsM1Wire.serializer(), m1).toByteArray(StandardCharsets.UTF_8)
        val created = createRoom(roomId, options.ttlSec, m1Bytes)
        var lastSeq = created.seq

        val offer = PairOffer(
            version = 1,
            roomId = roomId,
            mode = mode,
            purpose = purpose,
            endpoint = if (options.includeRelay) transport.profile.endpoint else "",
            spkiPins = if (options.includeRelay) transport.profile.resolvedPins else emptyList(),
            expiresAt = created.expiresAt,
            oobSecret = oob,
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
                    roomId = roomId,
                    displayCode = dispCode,
                    mode = mode,
                    purpose = purpose,
                    pairUri = pairUri,
                    expiresAt = created.expiresAt,
                )
            )
        } catch (t: Throwable) {
            closeRoomBestEffort(roomId, created.senderToken, "cancelled")
            throw t
        }

        val (m2Wire, seqAfterM2) = try {
            waitForPeerRoomMessage(roomId, created.senderToken, "receiver", lastSeq)
        } catch (t: Throwable) {
            if (t is CancellationException) {
                closeRoomBestEffort(roomId, created.senderToken, "cancelled")
            }
            throw t
        }
        lastSeq = seqAfterM2

        val m2 = decodeM2OrBurn(roomId, created.senderToken, mode, m2Wire)
        val pubB = decodeExactBytesOrBurn(roomId, created.senderToken, m2.eB, 32, "invalid M2 e_b")
        val nB = decodeExactBytesOrBurn(roomId, created.senderToken, m2.nB, Handshake.HS_NONCE_SIZE, "invalid M2 n_b")

        val hs: HandshakeResult
        if (mode == Handshake.MODE_QR_OOB) {
            hs = try {
                Handshake.deriveQrOobSession(purpose, roomId, ephASk, pubB, ephAPub, nA, pubB, nB, oob)
            } catch (e: CryptoException) {
                closeRoomBestEffort(roomId, created.senderToken, "verify_failed")
                throw SyncError(ErrorCode.ERR_CRYPTO_HANDSHAKE_FAILED, rawMessage = "derive qr_oob session", rawCause = e)
            }
            val macB = try {
                KeysAndAuth.b64uDecode(m2.macB.orEmpty())
            } catch (_: Exception) {
                hs.zero()
                closeRoomBestEffort(roomId, created.senderToken, "verify_failed")
                throw SyncError(ErrorCode.ERR_SAS_MISMATCH, rawMessage = "invalid M2 mac_b encoding")
            }
            try {
                Handshake.verifyMac(hs.macB, macB)
            } catch (_: CryptoException) {
                hs.zero()
                closeRoomBestEffort(roomId, created.senderToken, "verify_failed")
                throw SyncError(ErrorCode.ERR_SAS_MISMATCH, rawMessage = "M2 mac_b verification failed (wrong oob_secret or MITM)")
            }

            val m3Bytes = ManifestCodec.json.encodeToString(
                HsM3Wire.serializer(),
                HsM3Wire(mode = mode, macA = KeysAndAuth.b64uEncode(hs.macA)),
            ).toByteArray(StandardCharsets.UTF_8)
            try {
                lastSeq = postRoomMessage(roomId, created.senderToken, "handshake", m3Bytes)
            } catch (t: Throwable) {
                hs.zero()
                throw t
            }
        } else {
            hs = try {
                Handshake.deriveSasSession(purpose, roomId, ephASk, pubB, commitA, ephAPub, nA, pubB, nB)
            } catch (e: CryptoException) {
                closeRoomBestEffort(roomId, created.senderToken, "verify_failed")
                throw SyncError(ErrorCode.ERR_CRYPTO_HANDSHAKE_FAILED, rawMessage = "derive sas session", rawCause = e)
            }

            val m3Bytes = ManifestCodec.json.encodeToString(
                HsM3Wire.serializer(),
                HsM3Wire(
                    mode = mode,
                    eA = KeysAndAuth.b64uEncode(ephAPub),
                    nA = KeysAndAuth.b64uEncode(nA),
                    macA = KeysAndAuth.b64uEncode(hs.macA),
                ),
            ).toByteArray(StandardCharsets.UTF_8)
            try {
                lastSeq = postRoomMessage(roomId, created.senderToken, "handshake", m3Bytes)
            } catch (t: Throwable) {
                hs.zero()
                throw t
            }

            val (m4Wire, seqAfterM4) = try {
                waitForPeerRoomMessage(roomId, created.senderToken, "receiver", lastSeq)
            } catch (t: Throwable) {
                hs.zero()
                if (t is CancellationException) {
                    closeRoomBestEffort(roomId, created.senderToken, "cancelled")
                }
                throw t
            }
            lastSeq = seqAfterM4

            val m4 = try {
                val raw = KeysAndAuth.b64uDecode(m4Wire.msgB64)
                ManifestCodec.json.decodeFromString(HsM4Wire.serializer(), String(raw, StandardCharsets.UTF_8))
            } catch (_: Exception) {
                hs.zero()
                closeRoomBestEffort(roomId, created.senderToken, "verify_failed")
                throw SyncError(ErrorCode.ERR_CRYPTO_HANDSHAKE_FAILED, rawMessage = "invalid M4 payload")
            }
            if (m4.protoV != 1 || m4.mode != mode) {
                hs.zero()
                closeRoomBestEffort(roomId, created.senderToken, "verify_failed")
                throw SyncError(ErrorCode.ERR_CRYPTO_HANDSHAKE_FAILED, rawMessage = "invalid M4 version/mode")
            }
            val macB = try {
                KeysAndAuth.b64uDecode(m4.macB)
            } catch (_: Exception) {
                hs.zero()
                closeRoomBestEffort(roomId, created.senderToken, "verify_failed")
                throw SyncError(ErrorCode.ERR_SAS_MISMATCH, rawMessage = "invalid M4 mac_b")
            }
            try {
                Handshake.verifyMac(hs.macB, macB)
            } catch (_: CryptoException) {
                hs.zero()
                closeRoomBestEffort(roomId, created.senderToken, "verify_failed")
                throw SyncError(ErrorCode.ERR_SAS_MISMATCH, rawMessage = "M4 mac_b verification failed")
            }

            val sasInputCb = options.onSASInput
            if (sasInputCb == null) {
                hs.zero()
                closeRoomBestEffort(roomId, created.senderToken, "cancelled")
                throw SyncError(ErrorCode.ERR_SAS_MISMATCH, rawMessage = "mode=2 requires onSASInput callback")
            }
            var matched = false
            for (attempt in 0 until 3) {
                val entered = try {
                    sasInputCb.invoke()
                } catch (ce: CancellationException) {
                    hs.zero()
                    closeRoomBestEffort(roomId, created.senderToken, "cancelled")
                    throw ce
                } catch (e: Throwable) {
                    hs.zero()
                    closeRoomBestEffort(roomId, created.senderToken, "rejected")
                    throw SyncError(ErrorCode.ERR_SAS_MISMATCH, rawMessage = "SAS verification rejected", rawCause = e)
                }
                val ok = try {
                    Handshake.verifySas(hs.sasStr, entered)
                    true
                } catch (_: CryptoException) {
                    false
                }
                if (ok) {
                    matched = true
                    break
                }
            }
            if (!matched) {
                hs.zero()
                closeRoomBestEffort(roomId, created.senderToken, "verify_failed")
                throw SyncError(ErrorCode.ERR_SAS_MISMATCH, rawMessage = "SAS mismatch — room burned")
            }
        }

        return ActiveRoomSession(
            roomId = roomId,
            pipeId = created.pipeId,
            token = created.senderToken,
            lastSeq = lastSeq,
            hs = hs,
        )
    } finally {
        KeysAndAuth.zeroBytes(ephASk, nA, oob)
    }
}

internal suspend fun SyncClient.runResponderHandshake(
    joined: RoomJoinResp,
    m1: HsM1Wire,
    oobSecret: ByteArray,
    onSASDisplay: ((String) -> Unit)?,
    onSASConfirm: (suspend (sas: String) -> Boolean)?,
): ActiveRoomSession {
    val roomId = joined.roomId
    val token = joined.receiverToken
    var lastSeq = joined.seq
    val mode = m1.mode
    val purpose = m1.purpose

    if (mode != Handshake.MODE_QR_OOB && mode != Handshake.MODE_COMMIT_SAS) {
        closeRoomBestEffort(roomId, token, "verify_failed")
        throw SyncError(ErrorCode.ERR_CRYPTO_HANDSHAKE_FAILED, rawMessage = "unsupported handshake mode $mode")
    }
    // ST-P0-1: Mandatory upfront fail-closed onSASConfirm gate on Responder in Flow 1B (mode=2) BEFORE M2.
    if (mode == Handshake.MODE_COMMIT_SAS && onSASConfirm == null) {
        closeRoomBestEffort(roomId, token, "verify_failed")
        throw SyncError(
            code = ErrorCode.ERR_SAS_MISMATCH,
            retryable = false,
            rawMessage = "mode=2 responder requires mandatory onSASConfirm callback — room burned",
        )
    }

    val (ephBSk, ephBPub) = KeysAndAuth.generateEphemeralX25519()
    val nB = KeysAndAuth.randomBytes(Handshake.HS_NONCE_SIZE)
    try {
        val hs: HandshakeResult
        if (mode == Handshake.MODE_QR_OOB) {
            if (oobSecret.size != Handshake.OOB_SECRET_SIZE) {
                closeRoomBestEffort(roomId, token, "verify_failed")
                throw SyncError(ErrorCode.ERR_URI_INVALID, rawMessage = "mode=1 requires 16B oob_secret")
            }
            val pubA = decodeExactBytesOrBurn(roomId, token, m1.eA, 32, "invalid M1 e_a")
            val nA = decodeExactBytesOrBurn(roomId, token, m1.nA, Handshake.HS_NONCE_SIZE, "invalid M1 n_a")

            hs = try {
                Handshake.deriveQrOobSession(purpose, roomId, ephBSk, pubA, pubA, nA, ephBPub, nB, oobSecret)
            } catch (e: CryptoException) {
                closeRoomBestEffort(roomId, token, "verify_failed")
                throw SyncError(ErrorCode.ERR_CRYPTO_HANDSHAKE_FAILED, rawMessage = "derive qr_oob session", rawCause = e)
            }

            val m2Bytes = ManifestCodec.json.encodeToString(
                HsM2Wire.serializer(),
                HsM2Wire(
                    mode = mode,
                    eB = KeysAndAuth.b64uEncode(ephBPub),
                    nB = KeysAndAuth.b64uEncode(nB),
                    macB = KeysAndAuth.b64uEncode(hs.macB),
                ),
            ).toByteArray(StandardCharsets.UTF_8)
            try {
                lastSeq = postRoomMessage(roomId, token, "handshake", m2Bytes)
            } catch (t: Throwable) {
                hs.zero()
                throw t
            }

            val (m3Wire, seqAfterM3) = try {
                waitForPeerRoomMessage(roomId, token, "sender", lastSeq)
            } catch (t: Throwable) {
                hs.zero()
                if (t is CancellationException) closeRoomBestEffort(roomId, token, "cancelled")
                throw t
            }
            lastSeq = seqAfterM3

            val m3 = try {
                val raw = KeysAndAuth.b64uDecode(m3Wire.msgB64)
                ManifestCodec.json.decodeFromString(HsM3Wire.serializer(), String(raw, StandardCharsets.UTF_8))
            } catch (_: Exception) {
                hs.zero()
                closeRoomBestEffort(roomId, token, "verify_failed")
                throw SyncError(ErrorCode.ERR_CRYPTO_HANDSHAKE_FAILED, rawMessage = "invalid M3 payload")
            }
            if (m3.protoV != 1 || m3.mode != mode) {
                hs.zero()
                closeRoomBestEffort(roomId, token, "verify_failed")
                throw SyncError(ErrorCode.ERR_CRYPTO_HANDSHAKE_FAILED, rawMessage = "invalid M3 version/mode")
            }
            val macA = try {
                KeysAndAuth.b64uDecode(m3.macA)
            } catch (_: Exception) {
                hs.zero()
                closeRoomBestEffort(roomId, token, "verify_failed")
                throw SyncError(ErrorCode.ERR_SAS_MISMATCH, rawMessage = "invalid M3 mac_a")
            }
            try {
                Handshake.verifyMac(hs.macA, macA)
            } catch (_: CryptoException) {
                hs.zero()
                closeRoomBestEffort(roomId, token, "verify_failed")
                throw SyncError(ErrorCode.ERR_SAS_MISMATCH, rawMessage = "M3 mac_a verification failed")
            }
        } else {
            val commitA = decodeExactBytesOrBurn(roomId, token, m1.commitA, 32, "invalid M1 commit_a")

            val m2Bytes = ManifestCodec.json.encodeToString(
                HsM2Wire.serializer(),
                HsM2Wire(
                    mode = mode,
                    eB = KeysAndAuth.b64uEncode(ephBPub),
                    nB = KeysAndAuth.b64uEncode(nB),
                ),
            ).toByteArray(StandardCharsets.UTF_8)
            lastSeq = postRoomMessage(roomId, token, "handshake", m2Bytes)

            val (m3Wire, seqAfterM3) = try {
                waitForPeerRoomMessage(roomId, token, "sender", lastSeq)
            } catch (t: Throwable) {
                if (t is CancellationException) closeRoomBestEffort(roomId, token, "cancelled")
                throw t
            }
            lastSeq = seqAfterM3

            val m3 = try {
                val raw = KeysAndAuth.b64uDecode(m3Wire.msgB64)
                ManifestCodec.json.decodeFromString(HsM3Wire.serializer(), String(raw, StandardCharsets.UTF_8))
            } catch (_: Exception) {
                closeRoomBestEffort(roomId, token, "verify_failed")
                throw SyncError(ErrorCode.ERR_CRYPTO_HANDSHAKE_FAILED, rawMessage = "invalid M3 payload")
            }
            if (m3.protoV != 1 || m3.mode != mode) {
                closeRoomBestEffort(roomId, token, "verify_failed")
                throw SyncError(ErrorCode.ERR_CRYPTO_HANDSHAKE_FAILED, rawMessage = "invalid M3 version/mode")
            }
            val pubA = decodeExactBytesOrBurn(roomId, token, m3.eA, 32, "invalid M3 e_a")
            val nA = decodeExactBytesOrBurn(roomId, token, m3.nA, Handshake.HS_NONCE_SIZE, "invalid M3 n_a")
            val macA = decodeExactBytesOrBurn(roomId, token, m3.macA, 32, "invalid M3 mac_a")

            hs = try {
                Handshake.deriveSasSession(purpose, roomId, ephBSk, pubA, commitA, pubA, nA, ephBPub, nB)
            } catch (e: CryptoException.CommitMismatch) {
                closeRoomBestEffort(roomId, token, "verify_failed")
                throw SyncError(ErrorCode.ERR_SAS_MISMATCH, rawMessage = "M3 commit_a mismatch — room burned", rawCause = e)
            } catch (e: CryptoException) {
                closeRoomBestEffort(roomId, token, "verify_failed")
                throw SyncError(ErrorCode.ERR_CRYPTO_HANDSHAKE_FAILED, rawMessage = "derive sas session", rawCause = e)
            }

            try {
                Handshake.verifyMac(hs.macA, macA)
            } catch (_: CryptoException) {
                hs.zero()
                closeRoomBestEffort(roomId, token, "verify_failed")
                throw SyncError(ErrorCode.ERR_SAS_MISMATCH, rawMessage = "M3 mac_a mismatch — room burned")
            }

            val m4Bytes = ManifestCodec.json.encodeToString(
                HsM4Wire.serializer(),
                HsM4Wire(mode = mode, macB = KeysAndAuth.b64uEncode(hs.macB)),
            ).toByteArray(StandardCharsets.UTF_8)
            try {
                lastSeq = postRoomMessage(roomId, token, "handshake", m4Bytes)
            } catch (t: Throwable) {
                hs.zero()
                throw t
            }
            onSASDisplay?.invoke(hs.sasStr)
            try {
                enforceResponderSasConfirm(
                    roomId = roomId,
                    roomToken = token,
                    sas = hs.sasStr,
                    onSASConfirm = onSASConfirm,
                )
            } catch (t: Throwable) {
                hs.zero()
                throw t
            }
        }

        return ActiveRoomSession(
            roomId = roomId,
            pipeId = joined.pipeId,
            token = token,
            lastSeq = lastSeq,
            hs = hs,
        )
    } finally {
        KeysAndAuth.zeroBytes(ephBSk, nB)
    }
}

internal suspend fun SyncClient.enforceResponderSasConfirm(
    roomId: String,
    roomToken: String,
    sas: String,
    onSASConfirm: (suspend (sas: String) -> Boolean)?,
) {
    if (onSASConfirm == null) {
        closeRoomBestEffort(roomId, roomToken, "verify_failed")
        throw SyncError(
            code = ErrorCode.ERR_SAS_MISMATCH,
            retryable = false,
            rawMessage = "mode=2 responder requires mandatory onSASConfirm callback — room burned",
        )
    }
    val approved = try {
        onSASConfirm.invoke(sas)
    } catch (ce: CancellationException) {
        closeRoomBestEffort(roomId, roomToken, "cancelled")
        throw ce
    } catch (_: Throwable) {
        false
    }
    if (!approved) {
        closeRoomBestEffort(roomId, roomToken, "verify_failed")
        throw SyncError(
            code = ErrorCode.ERR_SAS_MISMATCH,
            retryable = false,
            rawMessage = "responder rejected SAS confirmation — room burned",
        )
    }
}

private suspend fun SyncClient.decodeM2OrBurn(
    roomId: String,
    token: String,
    expectedMode: Int,
    m2Wire: RoomMessageWire,
): HsM2Wire {
    val raw = try {
        KeysAndAuth.b64uDecode(m2Wire.msgB64)
    } catch (_: Exception) {
        closeRoomBestEffort(roomId, token, "verify_failed")
        throw SyncError(ErrorCode.ERR_CRYPTO_HANDSHAKE_FAILED, rawMessage = "decode M2 base64url")
    }
    val m2 = try {
        ManifestCodec.json.decodeFromString(HsM2Wire.serializer(), String(raw, StandardCharsets.UTF_8))
    } catch (_: Exception) {
        closeRoomBestEffort(roomId, token, "verify_failed")
        throw SyncError(ErrorCode.ERR_CRYPTO_HANDSHAKE_FAILED, rawMessage = "invalid M2 payload")
    }
    if (m2.protoV > 1) {
        closeRoomBestEffort(roomId, token, "verify_failed")
        throw SyncError(
            code = ErrorCode.ERR_UNSUPPORTED_VERSION,
            rawMessage = "unsupported peer proto_v ${m2.protoV}",
            rawDetails = mapOf("proto_v" to JsonPrimitive(m2.protoV), "supported_proto_v" to JsonPrimitive(1)),
        )
    }
    if (m2.protoV != 1 || m2.mode != expectedMode) {
        closeRoomBestEffort(roomId, token, "verify_failed")
        throw SyncError(ErrorCode.ERR_CRYPTO_HANDSHAKE_FAILED, rawMessage = "invalid M2 proto_v or mode")
    }
    return m2
}

private suspend fun SyncClient.decodeExactBytesOrBurn(
    roomId: String,
    token: String,
    b64u: String?,
    expectedLen: Int,
    errMsg: String,
): ByteArray {
    if (b64u.isNullOrEmpty()) {
        closeRoomBestEffort(roomId, token, "verify_failed")
        throw SyncError(ErrorCode.ERR_CRYPTO_HANDSHAKE_FAILED, rawMessage = errMsg)
    }
    val decoded = try {
        KeysAndAuth.b64uDecode(b64u)
    } catch (_: Exception) {
        closeRoomBestEffort(roomId, token, "verify_failed")
        throw SyncError(ErrorCode.ERR_CRYPTO_HANDSHAKE_FAILED, rawMessage = errMsg)
    }
    if (decoded.size != expectedLen) {
        KeysAndAuth.zeroBytes(decoded)
        closeRoomBestEffort(roomId, token, "verify_failed")
        throw SyncError(ErrorCode.ERR_CRYPTO_HANDSHAKE_FAILED, rawMessage = errMsg)
    }
    return decoded
}

// --- PairBind Helpers ---

internal suspend fun SyncClient.buildLocalPairBind(
    st: SyncClient.InitializedState,
    labelOverride: String,
): LocalPairBindBundle {
    val label = labelOverride.trim().ifEmpty { st.deviceLabel }
    // Pure local wall clock for signed DeviceCard.issuedAt (`ST-P1-6`)
    val issuedAt = System.currentTimeMillis() / 1000L
    val cardSig = KeysAndAuth.signDeviceCard(st.deviceKeys.signSeed, st.deviceKeys.kemPubBytes, issuedAt)
    val deviceCardPayload = DeviceCardPayload(
        deviceId = st.deviceKeys.deviceId,
        signPk = KeysAndAuth.b64uEncode(st.deviceKeys.signPub),
        kemPk = KeysAndAuth.b64uEncode(st.deviceKeys.kemPubBytes),
        issuedAt = issuedAt,
        cardSig = KeysAndAuth.b64uEncode(cardSig),
        label = label,
        platform = platform,
    )

    val caps = capabilities()
    var inboundTokenId = ""
    var inboundTokenHash = ""
    var mailboxPayload: MailboxBindPayload? = null
    if (caps.spool.enabled) {
        if (syncMailboxInternal(st)) {
            val reg = try {
                registerPeerDepositToken(st)
            } catch (se: SyncError) {
                if (se.code == ErrorCode.ERR_SPOOL_DISABLED) null else throw se
            }
            if (reg != null) {
                inboundTokenId = reg.first
                inboundTokenHash = reg.second
                mailboxPayload = MailboxBindPayload(
                    relayOrigin = transport.profile.endpoint,
                    mailboxId = st.mailboxKeys.mailboxId,
                    depositToken = reg.third,
                )
            }
        }
    }

    return LocalPairBindBundle(
        payload = PairBindPayload(deviceCard = deviceCardPayload, mailbox = mailboxPayload),
        inboundTokenId = inboundTokenId,
        inboundTokenHash = inboundTokenHash,
    )
}

internal suspend fun SyncClient.decodeAndOpenPeerPairBind(
    sess: ActiveRoomSession,
    peerMsg: RoomMessageWire,
    fromInitiator: Boolean,
): PairBindPayload {
    val pbWire = try {
        val raw = KeysAndAuth.b64uDecode(peerMsg.msgB64)
        ManifestCodec.json.decodeFromString(PairBindWire.serializer(), String(raw, StandardCharsets.UTF_8))
    } catch (_: Exception) {
        closeRoomBestEffort(sess.roomId, sess.token, "verify_failed")
        throw SyncError(ErrorCode.ERR_CRYPTO_DECRYPT_FAILED, rawMessage = "decode peer pair_bind envelope")
    }
    if (pbWire.protoV != 1 || pbWire.op != "pair_bind") {
        closeRoomBestEffort(sess.roomId, sess.token, "verify_failed")
        throw SyncError(ErrorCode.ERR_CRYPTO_DECRYPT_FAILED, rawMessage = "invalid peer pair_bind op")
    }
    val ct = try {
        KeysAndAuth.b64uDecode(pbWire.ct)
    } catch (_: Exception) {
        closeRoomBestEffort(sess.roomId, sess.token, "verify_failed")
        throw SyncError(ErrorCode.ERR_CRYPTO_DECRYPT_FAILED, rawMessage = "decode peer pair_bind ciphertext")
    }
    val pt = try {
        Handshake.openPairBind(sess.hs.sessionKey, sess.hs.prk, sess.hs.th, fromInitiator = fromInitiator, ciphertext = ct)
    } catch (e: CryptoException) {
        closeRoomBestEffort(sess.roomId, sess.token, "verify_failed")
        throw SyncError(ErrorCode.ERR_CRYPTO_DECRYPT_FAILED, rawMessage = "decrypt peer pair_bind", rawCause = e)
    }
    return try {
        ManifestCodec.json.decodeFromString(PairBindPayload.serializer(), String(pt, StandardCharsets.UTF_8))
    } catch (e: Exception) {
        closeRoomBestEffort(sess.roomId, sess.token, "verify_failed")
        throw SyncError(ErrorCode.ERR_CRYPTO_DECRYPT_FAILED, rawMessage = "parse peer pair_bind JSON", rawCause = e)
    } finally {
        KeysAndAuth.zeroBytes(pt)
    }
}

internal suspend fun SyncClient.verifyPeerBindCardOnly(
    peerBind: PairBindPayload,
    roomId: String,
    token: String,
) {
    val signPk = runCatching { KeysAndAuth.b64uDecode(peerBind.deviceCard.signPk) }.getOrNull()
    val kemPk = runCatching { KeysAndAuth.b64uDecode(peerBind.deviceCard.kemPk) }.getOrNull()
    val cardSig = runCatching { KeysAndAuth.b64uDecode(peerBind.deviceCard.cardSig) }.getOrNull()
    if (signPk == null || kemPk == null || cardSig == null) {
        closeRoomBestEffort(roomId, token, "verify_failed")
        throw SyncError(ErrorCode.ERR_CRYPTO_SIGNATURE_INVALID, rawMessage = "invalid peer device card encoding")
    }
    try {
        KeysAndAuth.verifyDeviceCard(
            deviceId = peerBind.deviceCard.deviceId,
            signPk = signPk,
            kemPk = kemPk,
            issuedAt = peerBind.deviceCard.issuedAt,
            cardSig = cardSig,
        )
    } catch (e: Exception) {
        closeRoomBestEffort(roomId, token, "verify_failed")
        throw SyncError(ErrorCode.ERR_CRYPTO_SIGNATURE_INVALID, rawMessage = "peer device card signature invalid", rawCause = e)
    }
}

internal suspend fun SyncClient.verifyAndSavePeerBind(
    st: SyncClient.InitializedState,
    peerBind: PairBindPayload,
    inboundTokenId: String,
    inboundTokenHash: String,
): DeviceCard {
    val signPk = runCatching { KeysAndAuth.b64uDecode(peerBind.deviceCard.signPk) }.getOrNull()
    val kemPk = runCatching { KeysAndAuth.b64uDecode(peerBind.deviceCard.kemPk) }.getOrNull()
    val cardSig = runCatching { KeysAndAuth.b64uDecode(peerBind.deviceCard.cardSig) }.getOrNull()
    if (signPk == null || kemPk == null || cardSig == null) {
        throw SyncError(ErrorCode.ERR_CRYPTO_SIGNATURE_INVALID, rawMessage = "invalid peer device card encoding")
    }
    try {
        KeysAndAuth.verifyDeviceCard(
            deviceId = peerBind.deviceCard.deviceId,
            signPk = signPk,
            kemPk = kemPk,
            issuedAt = peerBind.deviceCard.issuedAt,
            cardSig = cardSig,
        )
    } catch (e: Exception) {
        throw SyncError(ErrorCode.ERR_CRYPTO_SIGNATURE_INVALID, rawMessage = "peer device card signature invalid", rawCause = e)
    }

    var relayOrigin = transport.profile.endpoint
    var relayId = transport.profile.relayId
    var mailboxId = ""
    var outboundDepositToken = ""
    val mb = peerBind.mailbox
    if (mb != null) {
        relayOrigin = mb.relayOrigin
        runCatching { KeysAndAuth.canonicalRelayOrigin(mb.relayOrigin) }.onSuccess { canon ->
            relayOrigin = canon
            relayId = KeysAndAuth.deriveRelayId(canon)
        }
        mailboxId = mb.mailboxId
        outboundDepositToken = mb.depositToken
    }

    val cleanDeviceId = peerBind.deviceCard.deviceId.lowercase()
    val prevCard = keyStore.getDevice(cleanDeviceId)

    val card = DeviceCard(
        deviceId = cleanDeviceId,
        label = peerBind.deviceCard.label,
        platform = peerBind.deviceCard.platform.orEmpty(),
        signPk = peerBind.deviceCard.signPk,
        kemPk = peerBind.deviceCard.kemPk,
        issuedAt = peerBind.deviceCard.issuedAt,
        cardSig = peerBind.deviceCard.cardSig,
        relayOrigin = relayOrigin,
        relayId = relayId,
        mailboxId = mailboxId,
        outboundDepositToken = outboundDepositToken,
        inboundTokenId = inboundTokenId,
        inboundTokenHash = inboundTokenHash,
        pairedAt = System.currentTimeMillis() / 1000L,
        revoked = false,
    )
    keyStore.putDevice(card)

    // Clean up superseded deposit_token on re-pair (`ST-P1-8`), queuing pending delete on transient failure
    if (prevCard != null && prevCard.inboundTokenId.isNotEmpty() && prevCard.inboundTokenId != inboundTokenId) {
        try {
            deleteRelayDepositTokenStrict(st, prevCard.inboundTokenId)
        } catch (_: Throwable) {
            keyStore.addPendingTokenDelete(prevCard.inboundTokenId)
        }
    }
    return card
}
