import Foundation

internal struct ActiveRoomSession: Sendable {
    let roomId: String, pipeId: String, token: String
    var lastSeq: Int
    let hs: HandshakeResult
}

internal struct LocalPairBindBundle: Sendable {
    let payload: PairBindPayload, inboundTokenId: String, inboundTokenHash: String
}

extension SyncClient {
    private func burnError(_ roomId: String, _ token: String, _ code: ErrorCode, _ msg: String, reason: String = "verify_failed", retryable: Bool? = nil, details: [String: String] = [:]) async -> SyncError {
        await closeRoomBestEffort(roomId: roomId, roomToken: token, reason: reason)
        return SyncError(code: code, message: msg, retryable: retryable, details: details)
    }

    // MARK: - Mode A Entrypoints (Device Bind & One-Shot / Direct Pipe)

    internal func initiateDeviceBindInternal(options: PairOptions) async throws -> DeviceCard {
        let st = try await ensureInitialized()
        var sess = try await runInitiatorHandshake(st: st, purpose: SyncHandshake.purposePair, options: options)
        var registeredTokenId = "", bindSucceeded = false
        defer { if !bindSucceeded && !registeredTokenId.isEmpty { let tokId = registeredTokenId; Task { await self.deleteRelayDepositTokenBestEffort(st: st, tokenId: tokId) } } }
        let localBind = try await buildLocalPairBind(st: st, labelOverride: options.label)
        registeredTokenId = localBind.inboundTokenId
        let ctA = try SyncHandshake.sealPairBind(sessionKey32: sess.hs.sessionKey, prk32: sess.hs.prk, th32: sess.hs.th, isInitiator: true, plaintext: try JSONEncoder().encode(localBind.payload))
        sess.lastSeq = try await postRoomMessage(roomId: sess.roomId, roomToken: sess.token, kind: "handshake", payload: try JSONEncoder().encode(PairBindWire(ct: SyncCrypto.b64uEncode(ctA))))
        let (peerMsg, _) = try await waitForPeerRoomMessage(roomId: sess.roomId, roomToken: sess.token, expectedFrom: "receiver", sinceSeq: sess.lastSeq)
        let peerBind = try await decodeAndOpenPeerPairBind(sess: sess, peerMsg: peerMsg, fromInitiator: false)
        let card = try await verifyAndSavePeerBind(st: st, peerBind: peerBind, inboundTokenId: localBind.inboundTokenId, inboundTokenHash: localBind.inboundTokenHash)
        bindSucceeded = true
        await closeRoomBestEffort(roomId: sess.roomId, roomToken: sess.token, reason: "completed")
        return card
    }

    internal func acceptDeviceBindInternal(pairInput: String, options: PairOptions) async throws -> DeviceCard {
        let st = try await ensureInitialized()
        let (roomId, oob) = try parseRoomInput(pairInput)
        let (joined, m1) = try await joinAndReadM1(roomId: roomId)
        guard m1.purpose == SyncHandshake.purposePair else { throw await burnError(roomId, joined.receiverToken, .errInvalidState, "room purpose is not pair") }
        var sess = try await runResponderHandshake(joined: joined, m1: m1, oobSecret: oob, onSASDisplay: options.onSASDisplay, onSASConfirm: options.onSASConfirm)
        var registeredTokenId = "", bindSucceeded = false
        defer { if !bindSucceeded && !registeredTokenId.isEmpty { let tokId = registeredTokenId; Task { await self.deleteRelayDepositTokenBestEffort(st: st, tokenId: tokId) } } }
        let (peerMsg, nextSeq) = try await waitForPeerRoomMessage(roomId: sess.roomId, roomToken: sess.token, expectedFrom: "sender", sinceSeq: sess.lastSeq)
        sess.lastSeq = nextSeq
        let peerBind = try await decodeAndOpenPeerPairBind(sess: sess, peerMsg: peerMsg, fromInitiator: true)
        try await verifyPeerBindCardOnly(peerBind: peerBind, roomId: sess.roomId, token: sess.token)
        let localBind = try await buildLocalPairBind(st: st, labelOverride: options.label)
        registeredTokenId = localBind.inboundTokenId
        let card = try await verifyAndSavePeerBind(st: st, peerBind: peerBind, inboundTokenId: localBind.inboundTokenId, inboundTokenHash: localBind.inboundTokenHash)
        let ctB = try SyncHandshake.sealPairBind(sessionKey32: sess.hs.sessionKey, prk32: sess.hs.prk, th32: sess.hs.th, isInitiator: false, plaintext: try JSONEncoder().encode(localBind.payload))
        _ = try await postRoomMessage(roomId: sess.roomId, roomToken: sess.token, kind: "handshake", payload: try JSONEncoder().encode(PairBindWire(ct: SyncCrypto.b64uEncode(ctB))))
        bindSucceeded = true
        return card
    }

    internal func startOneShotSendInternal(parcel: ParcelInput, options: PairOptions) async throws -> SendResult {
        let st = try await ensureInitialized(), caps = try await capabilities()
        let bpc = caps.streaming.blocksPerChunk > 0 ? caps.streaming.blocksPerChunk : 16
        let prep = try prepareParcel(st: st, input: parcel, blocksPerChunk: bpc)
        var sess = try await runInitiatorHandshake(st: st, purpose: SyncHandshake.purposeOneshot, options: options)
        let (p0Key, p0Np) = try SyncHandshake.deriveOneshotPart0Keys(sessionKey32: sess.hs.sessionKey, msgId16: prep.msgIdRaw)
        let (ctrlKey, ctrlNp) = try SyncHandshake.derivePipeCtrlKeys(th32: sess.hs.th, sessionKey32: sess.hs.sessionKey)
        let startCt = try SyncHandshake.sealPipeCtrl(ctrlKey32: ctrlKey, ctrlNp7: ctrlNp, th32: sess.hs.th, ctrlSeq: 0, plaintext: try JSONEncoder().encode(PipeStartPayload(msgId: prep.msgId, blocksPerChunk: bpc, parts: prep.parts)))
        sess.lastSeq = try await postRoomMessage(roomId: sess.roomId, roomToken: sess.token, kind: "control", payload: try JSONEncoder().encode(PipeCtrlWire(ctrlSeq: 0, ct: SyncCrypto.b64uEncode(startCt))))
        do { try await uploadAllPipeParts(pipeId: sess.pipeId, senderToken: sess.token, prep: prep, p0Key: p0Key, p0Np: p0Np, blocksPerChunk: bpc, onProgress: options.onProgress) }
        catch { await closeRoomBestEffort(roomId: sess.roomId, roomToken: sess.token, reason: "cancelled"); throw error }
        let (ackWire, _) = try await waitForPeerRoomMessage(roomId: sess.roomId, roomToken: sess.token, expectedFrom: "receiver", sinceSeq: sess.lastSeq)
        try await verifyOneshotPipeAck(sess: sess, ctrlKey32: ctrlKey, ctrlNp7: ctrlNp, ackWire: ackWire, expectedMsgId: prep.msgId)
        await closeRoomBestEffort(roomId: sess.roomId, roomToken: sess.token, reason: "completed")
        return SendResult(mode: DeliveryMode.pipe, msgId: prep.msgId, roomId: sess.roomId, totalBytes: prep.totalEnc)
    }

    internal func receiveFromRoomInternal(pairInput: String, options: ReceiveOptions, handler: (@Sendable (ReceivedParcel) async throws -> Void)?) async throws -> ReceivedParcel {
        let st = try await ensureInitialized()
        let (roomId, oob) = try parseRoomInput(pairInput)
        let (joined, rawM1) = try await joinAndReadRawM1(roomId: roomId)
        let tok = joined.receiverToken
        guard let probe = try? JSONDecoder().decode(RoomM1Probe.self, from: rawM1) else { throw await burnError(roomId, tok, .errCryptoHandshakeFailed, "invalid room M1 frame") }
        if probe.protoV > 1 { throw await burnError(roomId, tok, .errUnsupportedVersion, "unsupported room M1 proto_v \(probe.protoV)", details: ["proto_v": "\(probe.protoV)", "supported_proto_v": "1"]) }
        guard probe.protoV == 1 else { throw await burnError(roomId, tok, .errCryptoHandshakeFailed, "invalid room M1 proto_v") }
        if probe.mode == SyncHandshake.modeDirect && probe.purpose == SyncHandshake.purposeDirect {
            guard let initPayload = try? JSONDecoder().decode(DirectRoomInitPayload.self, from: rawM1) else { throw await burnError(roomId, tok, .errCryptoHandshakeFailed, "invalid direct M1 payload") }
            return try await receiveDirectJoined(st: st, joined: joined, initPayload: initPayload, options: options, handler: handler)
        }
        guard let m1 = try? JSONDecoder().decode(HsM1Wire.self, from: rawM1) else { throw await burnError(roomId, tok, .errCryptoHandshakeFailed, "invalid handshake M1") }
        guard m1.purpose == SyncHandshake.purposeOneshot else { throw await burnError(roomId, tok, .errInvalidState, "unexpected room purpose for receive") }
        return try await receiveOneShotJoined(st: st, joined: joined, m1: m1, oob: oob, options: options, handler: handler)
    }

    // MARK: - Room Signaling, SSE & Long-Poll Fallback

    internal func createRoom(roomId: String, ttlSec: Int, initialMsg: Data?) async throws -> RoomCreateResp {
        let req = RoomCreateReq(roomId: roomId, ttlSec: ttlSec <= 0 ? 300 : ttlSec, initialMsgB64: (initialMsg?.isEmpty == false) ? SyncCrypto.b64uEncode(initialMsg!) : nil)
        let resp = try await transport.doControl(method: "POST", pathAndQuery: "/v1/rooms", jsonBodyBytes: try JSONEncoder().encode(req))
        return try JSONDecoder().decode(RoomCreateResp.self, from: resp.body)
    }

    internal func joinRoom(roomId: String) async throws -> RoomJoinResp {
        let resp = try await transport.doControl(method: "POST", pathAndQuery: "/v1/rooms/\(roomId)/join", jsonBodyBytes: Data("{}".utf8))
        return try JSONDecoder().decode(RoomJoinResp.self, from: resp.body)
    }

    internal func postRoomMessage(roomId: String, roomToken: String, kind: String, payload: Data) async throws -> Int {
        let req = RoomPostMsgReq(kind: kind, msgB64: SyncCrypto.b64uEncode(payload))
        let resp = try await transport.doControl(method: "POST", pathAndQuery: "/v1/rooms/\(roomId)/messages", jsonBodyBytes: try JSONEncoder().encode(req), opts: RequestAuthOptions(roomToken: roomToken))
        return (try? JSONDecoder().decode(RoomPostMsgResp.self, from: resp.body).seq) ?? 0
    }

    internal func closeRoomBestEffort(roomId: String, roomToken: String, reason: String) async {
        guard !roomId.isEmpty && !roomToken.isEmpty else { return }
        let tr = self.transport
        await Task.detached {
            guard let body = try? JSONEncoder().encode(RoomCloseReq(reason: reason)) else { return }
            _ = try? await tr.doControl(method: "POST", pathAndQuery: "/v1/rooms/\(roomId)/close", jsonBodyBytes: body, opts: RequestAuthOptions(roomToken: roomToken))
        }.value
    }

    internal func waitForPeerRoomMessage(roomId: String, roomToken: String, expectedFrom: String, sinceSeq: Int) async throws -> (RoomMessageWire, Int) {
        var curSince = sinceSeq, usePoll = false, backoffMs: UInt64 = 250
        while true {
            try Task.checkCancellation()
            if !usePoll {
                let path = "/v1/rooms/\(roomId)/events?since=\(curSince)&mode=sse", started = DispatchTime.now().uptimeNanoseconds
                var gotReconnect = false
                do {
                    for try await ev in transport.sseEvents(pathAndQuery: path, opts: RequestAuthOptions(roomToken: roomToken)) {
                        switch ev.event {
                        case "message":
                            if let d = ev.data.data(using: .utf8), let m = try? JSONDecoder().decode(RoomMessageWire.self, from: d) {
                                if m.seq > curSince { curSince = m.seq }
                                if m.from == expectedFrom { return (m, curSince) }
                            }
                        case "burned": throw SyncError(code: .errRoomBurned, message: "room burned by peer", httpStatus: 410)
                        case "closed": throw SyncError(code: .errNotFound, message: "room closed by peer", httpStatus: 404)
                        case "reconnect": gotReconnect = true
                        default: break
                        }
                        if gotReconnect { break }
                    }
                } catch is CancellationError { throw SyncError(code: .errCancelled, message: "operation cancelled") }
                catch let se as SyncError {
                    if se.isAuthError || se.isSecurityAlert || se.isVersionMismatch || se.code == .errRoomBurned || se.code == .errNotFound || se.code == .errCancelled { throw se }
                    usePoll = true; try await sleepRetryAfter(se, defaultMs: backoffMs); backoffMs = min(backoffMs * 2, 5_000); continue
                }
                if gotReconnect { backoffMs = 250; continue }
                if (DispatchTime.now().uptimeNanoseconds - started) < 1_000_000_000 {
                    usePoll = true; try await Task.sleep(nanoseconds: backoffMs * 1_000_000); backoffMs = min(backoffMs * 2, 5_000)
                }
                continue
            }
            let resp: RawHttpResponse
            do { resp = try await transport.doControl(method: "GET", pathAndQuery: "/v1/rooms/\(roomId)/events?since=\(curSince)&mode=poll&wait_sec=20", opts: RequestAuthOptions(roomToken: roomToken)) }
            catch let se as SyncError {
                if se.isAuthError || se.isSecurityAlert || se.isVersionMismatch || se.code == .errRoomBurned || se.code == .errNotFound || !se.retryable { throw se }
                try await sleepRetryAfter(se, defaultMs: backoffMs); backoffMs = min(backoffMs * 2, 5_000); continue
            }
            backoffMs = 250
            guard let pr = try? JSONDecoder().decode(RoomPollResp.self, from: resp.body) else { throw SyncError(code: .errBadRequest, message: "decode room poll failed", httpStatus: resp.statusCode) }
            for m in pr.messages {
                if m.seq > curSince { curSince = m.seq }
                if m.from == expectedFrom { return (m, curSince) }
            }
            if pr.state == "burned" { throw SyncError(code: .errRoomBurned, message: "room burned: \(pr.reason)", httpStatus: 410) }
            if pr.state == "closed" { throw SyncError(code: .errNotFound, message: "room closed: \(pr.reason)", httpStatus: 404) }
        }
    }

    internal func sleepRetryAfter(_ se: SyncError, defaultMs: UInt64) async throws {
        let waitMs = (se.retryAfterSec.flatMap { $0 > 0 ? min(UInt64($0) * 1_000, 15_000) : nil }) ?? defaultMs
        try await Task.sleep(nanoseconds: waitMs * 1_000_000)
    }

    internal func parseRoomInput(_ pairInput: String) throws -> (String, Data) {
        let trimmed = pairInput.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.lowercased().hasPrefix("synctool://") { let offer = try SyncUri.parsePairUri(trimmed); return (offer.roomId, offer.oobSecret) }
        return (try Crockford.normalizeRoomId(trimmed), Data())
    }

    internal func joinAndReadRawM1(roomId: String) async throws -> (RoomJoinResp, Data) {
        var joined = try await joinRoom(roomId: roomId)
        if joined.messages.isEmpty {
            let (m1Wire, nextSeq) = try await waitForPeerRoomMessage(roomId: roomId, roomToken: joined.receiverToken, expectedFrom: "sender", sinceSeq: joined.seq)
            joined.seq = nextSeq; joined.messages = [m1Wire]
        }
        guard let rawM1 = try? SyncCrypto.b64uDecode(joined.messages[0].msgB64) else { throw await burnError(roomId, joined.receiverToken, .errCryptoHandshakeFailed, "decode M1 base64url failed") }
        return (joined, rawM1)
    }

    internal func joinAndReadM1(roomId: String) async throws -> (RoomJoinResp, HsM1Wire) {
        let (joined, rawM1) = try await joinAndReadRawM1(roomId: roomId)
        if let probe = try? JSONDecoder().decode(RoomM1Probe.self, from: rawM1), probe.protoV > 1 {
            throw await burnError(roomId, joined.receiverToken, .errUnsupportedVersion, "unsupported M1 proto_v \(probe.protoV)", details: ["proto_v": "\(probe.protoV)", "supported_proto_v": "1"])
        }
        guard let m1 = try? JSONDecoder().decode(HsM1Wire.self, from: rawM1) else { throw await burnError(roomId, joined.receiverToken, .errCryptoHandshakeFailed, "invalid M1 json") }
        guard m1.protoV == 1 else { throw await burnError(roomId, joined.receiverToken, .errCryptoHandshakeFailed, "invalid M1 proto_v") }
        return (joined, m1)
    }

    // MARK: - Flow 1A / 1B Handshakes (`ST-P0-1` Responder Fail-Closed SAS Gate)

    internal func runInitiatorHandshake(st: InitializedState, purpose: String, options: PairOptions) async throws -> ActiveRoomSession {
        let mode = options.mode == 0 ? SyncHandshake.modeQrOob : options.mode
        guard mode == SyncHandshake.modeQrOob || mode == SyncHandshake.modeCommitSas else { throw SyncError(code: .errBadRequest, message: "invalid handshake mode (use 1 or 2)") }
        let roomId = try Crockford.generateRoomId(), (ephASk, ephAPub) = try SyncCrypto.x25519Generate()
        let nA = try SyncCrypto.randomBytes(SyncHandshake.hsNonceSize)
        let oob = mode == SyncHandshake.modeQrOob ? try SyncCrypto.randomBytes(SyncHandshake.oobSecretSize) : Data()
        let commitA = mode == SyncHandshake.modeCommitSas ? try SyncHandshake.computeCommitA(purpose: purpose, roomId: roomId, eAPub: ephAPub, nA: nA) : Data()
        let m1 = mode == SyncHandshake.modeQrOob
            ? HsM1Wire(mode: mode, purpose: purpose, eA: SyncCrypto.b64uEncode(ephAPub), nA: SyncCrypto.b64uEncode(nA), commitA: nil)
            : HsM1Wire(mode: mode, purpose: purpose, eA: nil, nA: nil, commitA: SyncCrypto.b64uEncode(commitA))
        let created = try await createRoom(roomId: roomId, ttlSec: options.ttlSec, initialMsg: try JSONEncoder().encode(m1))
        let sTok = created.senderToken
        var lastSeq = created.seq
        let offer = PairOffer(version: 1, roomId: roomId, mode: mode, purpose: purpose, endpoint: options.includeRelay ? transport.profile.endpoint : "", spkiPins: options.includeRelay ? transport.profile.resolvedPins : [], expiresAt: created.expiresAt, oobSecret: oob, accessKey: options.includeRelay ? transport.profile.accessKey : "")
        do { try await options.onOfferReady?(OfferReadyInfo(roomId: roomId, displayCode: try Crockford.formatRoomId(roomId), mode: mode, purpose: purpose, pairUri: try SyncUri.formatPairUri(offer), expiresAt: created.expiresAt)) }
        catch { await closeRoomBestEffort(roomId: roomId, roomToken: sTok, reason: "cancelled"); throw error }

        let (m2Wire, seqAfterM2) = try await waitOrCancelRoom(roomId: roomId, token: sTok, expectedFrom: "receiver", sinceSeq: lastSeq); lastSeq = seqAfterM2
        let m2 = try await decodeM2OrBurn(roomId: roomId, token: sTok, expectedMode: mode, m2Wire: m2Wire)
        let pubB = try await decodeExactOrBurn(roomId: roomId, token: sTok, b64u: m2.eB, expectedLen: 32, errMsg: "invalid M2 e_b")
        let nB = try await decodeExactOrBurn(roomId: roomId, token: sTok, b64u: m2.nB, expectedLen: SyncHandshake.hsNonceSize, errMsg: "invalid M2 n_b")
        let hs: HandshakeResult
        if mode == SyncHandshake.modeQrOob {
            do { hs = try SyncHandshake.deriveQrOobSession(purpose: purpose, roomId: roomId, localPriv32: ephASk, remotePub32: pubB, eAPub: ephAPub, nA: nA, eBPub: pubB, nB: nB, oobSecret: oob) }
            catch { await closeRoomBestEffort(roomId: roomId, roomToken: sTok, reason: "verify_failed"); throw (error as? SyncError) ?? SyncError(code: .errCryptoHandshakeFailed, message: "derive qr_oob session failed") }
            guard let macB = try? SyncCrypto.b64uDecode(m2.macB ?? ""), (try? SyncHandshake.verifyMac(expected32: hs.macB, got: macB)) != nil else { throw await burnError(roomId, sTok, .errSasMismatch, "M2 mac_b verification failed") }
            lastSeq = try await postRoomMessage(roomId: roomId, roomToken: sTok, kind: "handshake", payload: try JSONEncoder().encode(HsM3Wire(mode: mode, eA: nil, nA: nil, macA: SyncCrypto.b64uEncode(hs.macA))))
        } else {
            do { hs = try SyncHandshake.deriveSasSession(purpose: purpose, roomId: roomId, localPriv32: ephASk, remotePub32: pubB, commitA: commitA, eAPub: ephAPub, nA: nA, eBPub: pubB, nB: nB) }
            catch { await closeRoomBestEffort(roomId: roomId, roomToken: sTok, reason: "verify_failed"); throw (error as? SyncError) ?? SyncError(code: .errCryptoHandshakeFailed, message: "derive sas session failed") }
            lastSeq = try await postRoomMessage(roomId: roomId, roomToken: sTok, kind: "handshake", payload: try JSONEncoder().encode(HsM3Wire(mode: mode, eA: SyncCrypto.b64uEncode(ephAPub), nA: SyncCrypto.b64uEncode(nA), macA: SyncCrypto.b64uEncode(hs.macA))))
            let (m4Wire, seqAfterM4) = try await waitOrCancelRoom(roomId: roomId, token: sTok, expectedFrom: "receiver", sinceSeq: lastSeq); lastSeq = seqAfterM4
            guard let m4Raw = try? SyncCrypto.b64uDecode(m4Wire.msgB64), let m4 = try? JSONDecoder().decode(HsM4Wire.self, from: m4Raw), m4.protoV == 1 && m4.mode == mode else { throw await burnError(roomId, sTok, .errCryptoHandshakeFailed, "invalid M4 payload") }
            guard let macB = try? SyncCrypto.b64uDecode(m4.macB), (try? SyncHandshake.verifyMac(expected32: hs.macB, got: macB)) != nil else { throw await burnError(roomId, sTok, .errSasMismatch, "M4 mac_b verification failed") }
            guard let sasInputCb = options.onSASInput else { throw await burnError(roomId, sTok, .errSasMismatch, "mode=2 requires onSASInput callback", reason: "cancelled") }
            var matched = false
            for _ in 0..<3 {
                let entered: String
                do { entered = try await sasInputCb() }
                catch is CancellationError { throw await burnError(roomId, sTok, .errCancelled, "SAS input cancelled", reason: "cancelled") }
                catch { throw await burnError(roomId, sTok, .errSasMismatch, "SAS verification rejected", reason: "rejected") }
                if (try? SyncHandshake.verifySas(expected6Digits: hs.sasCode, entered: entered)) != nil { matched = true; break }
            }
            guard matched else { throw await burnError(roomId, sTok, .errSasMismatch, "SAS mismatch — room burned") }
        }
        return ActiveRoomSession(roomId: roomId, pipeId: created.pipeId, token: sTok, lastSeq: lastSeq, hs: hs)
    }

    internal func runResponderHandshake(joined: RoomJoinResp, m1: HsM1Wire, oobSecret: Data, onSASDisplay: (@Sendable (String) -> Void)?, onSASConfirm: (@Sendable (String) async throws -> Bool)?) async throws -> ActiveRoomSession {
        let roomId = joined.roomId, token = joined.receiverToken, mode = m1.mode, purpose = m1.purpose
        var lastSeq = joined.seq
        guard mode == SyncHandshake.modeQrOob || mode == SyncHandshake.modeCommitSas else { throw await burnError(roomId, token, .errCryptoHandshakeFailed, "unsupported handshake mode \(mode)") }
        if mode == SyncHandshake.modeCommitSas && onSASConfirm == nil {
            throw await burnError(roomId, token, .errSasMismatch, "mode=2 responder requires mandatory onSASConfirm callback — room burned", retryable: false)
        }
        let (ephBSk, ephBPub) = try SyncCrypto.x25519Generate(), nB = try SyncCrypto.randomBytes(SyncHandshake.hsNonceSize)
        let hs: HandshakeResult
        if mode == SyncHandshake.modeQrOob {
            guard oobSecret.count == SyncHandshake.oobSecretSize else { throw await burnError(roomId, token, .errUriInvalid, "mode=1 requires 16B oob_secret") }
            let pubA = try await decodeExactOrBurn(roomId: roomId, token: token, b64u: m1.eA, expectedLen: 32, errMsg: "invalid M1 e_a")
            let nA = try await decodeExactOrBurn(roomId: roomId, token: token, b64u: m1.nA, expectedLen: SyncHandshake.hsNonceSize, errMsg: "invalid M1 n_a")
            do { hs = try SyncHandshake.deriveQrOobSession(purpose: purpose, roomId: roomId, localPriv32: ephBSk, remotePub32: pubA, eAPub: pubA, nA: nA, eBPub: ephBPub, nB: nB, oobSecret: oobSecret) }
            catch { await closeRoomBestEffort(roomId: roomId, roomToken: token, reason: "verify_failed"); throw (error as? SyncError) ?? SyncError(code: .errCryptoHandshakeFailed, message: "derive qr_oob session failed") }
            lastSeq = try await postRoomMessage(roomId: roomId, roomToken: token, kind: "handshake", payload: try JSONEncoder().encode(HsM2Wire(mode: mode, eB: SyncCrypto.b64uEncode(ephBPub), nB: SyncCrypto.b64uEncode(nB), macB: SyncCrypto.b64uEncode(hs.macB))))
            let (m3Wire, seqAfterM3) = try await waitOrCancelRoom(roomId: roomId, token: token, expectedFrom: "sender", sinceSeq: lastSeq); lastSeq = seqAfterM3
            guard let m3Raw = try? SyncCrypto.b64uDecode(m3Wire.msgB64), let m3 = try? JSONDecoder().decode(HsM3Wire.self, from: m3Raw), m3.protoV == 1 && m3.mode == mode else { throw await burnError(roomId, token, .errCryptoHandshakeFailed, "invalid M3 payload") }
            guard let macA = try? SyncCrypto.b64uDecode(m3.macA), (try? SyncHandshake.verifyMac(expected32: hs.macA, got: macA)) != nil else { throw await burnError(roomId, token, .errSasMismatch, "M3 mac_a verification failed") }
        } else {
            let commitA = try await decodeExactOrBurn(roomId: roomId, token: token, b64u: m1.commitA, expectedLen: 32, errMsg: "invalid M1 commit_a")
            lastSeq = try await postRoomMessage(roomId: roomId, roomToken: token, kind: "handshake", payload: try JSONEncoder().encode(HsM2Wire(mode: mode, eB: SyncCrypto.b64uEncode(ephBPub), nB: SyncCrypto.b64uEncode(nB), macB: nil)))
            let (m3Wire, seqAfterM3) = try await waitOrCancelRoom(roomId: roomId, token: token, expectedFrom: "sender", sinceSeq: lastSeq); lastSeq = seqAfterM3
            guard let m3Raw = try? SyncCrypto.b64uDecode(m3Wire.msgB64), let m3 = try? JSONDecoder().decode(HsM3Wire.self, from: m3Raw), m3.protoV == 1 && m3.mode == mode else { throw await burnError(roomId, token, .errCryptoHandshakeFailed, "invalid M3 payload") }
            let pubA = try await decodeExactOrBurn(roomId: roomId, token: token, b64u: m3.eA, expectedLen: 32, errMsg: "invalid M3 e_a")
            let nA = try await decodeExactOrBurn(roomId: roomId, token: token, b64u: m3.nA, expectedLen: SyncHandshake.hsNonceSize, errMsg: "invalid M3 n_a")
            let macA = try await decodeExactOrBurn(roomId: roomId, token: token, b64u: m3.macA, expectedLen: 32, errMsg: "invalid M3 mac_a")
            do { hs = try SyncHandshake.deriveSasSession(purpose: purpose, roomId: roomId, localPriv32: ephBSk, remotePub32: pubA, commitA: commitA, eAPub: pubA, nA: nA, eBPub: ephBPub, nB: nB) }
            catch { await closeRoomBestEffort(roomId: roomId, roomToken: token, reason: "verify_failed"); throw (error as? SyncError) ?? SyncError(code: .errCryptoHandshakeFailed, message: "derive sas session failed") }
            guard (try? SyncHandshake.verifyMac(expected32: hs.macA, got: macA)) != nil else { throw await burnError(roomId, token, .errSasMismatch, "M3 mac_a mismatch — room burned") }
            lastSeq = try await postRoomMessage(roomId: roomId, roomToken: token, kind: "handshake", payload: try JSONEncoder().encode(HsM4Wire(mode: mode, macB: SyncCrypto.b64uEncode(hs.macB))))
            onSASDisplay?(hs.sasCode)
            guard let cb = onSASConfirm else { throw await burnError(roomId, token, .errSasMismatch, "mode=2 responder requires mandatory onSASConfirm callback — room burned", retryable: false) }
            let approved: Bool
            do { approved = try await cb(hs.sasCode) }
            catch is CancellationError { throw await burnError(roomId, token, .errCancelled, "SAS confirmation cancelled", reason: "cancelled") }
            catch { approved = false }
            guard approved else { throw await burnError(roomId, token, .errSasMismatch, "responder rejected SAS confirmation — room burned", retryable: false) }
        }
        return ActiveRoomSession(roomId: roomId, pipeId: joined.pipeId, token: token, lastSeq: lastSeq, hs: hs)
    }

    private func waitOrCancelRoom(roomId: String, token: String, expectedFrom: String, sinceSeq: Int) async throws -> (RoomMessageWire, Int) {
        do { return try await waitForPeerRoomMessage(roomId: roomId, roomToken: token, expectedFrom: expectedFrom, sinceSeq: sinceSeq) }
        catch let se as SyncError where se.code == .errCancelled { await closeRoomBestEffort(roomId: roomId, roomToken: token, reason: "cancelled"); throw se }
        catch is CancellationError { throw await burnError(roomId, token, .errCancelled, "operation cancelled", reason: "cancelled") }
    }

    private func decodeM2OrBurn(roomId: String, token: String, expectedMode: Int, m2Wire: RoomMessageWire) async throws -> HsM2Wire {
        guard let raw = try? SyncCrypto.b64uDecode(m2Wire.msgB64) else { throw await burnError(roomId, token, .errCryptoHandshakeFailed, "invalid M2 payload") }
        if let probe = try? JSONDecoder().decode(RoomM1Probe.self, from: raw), probe.protoV > 1 {
            throw await burnError(roomId, token, .errUnsupportedVersion, "unsupported peer proto_v \(probe.protoV)", details: ["proto_v": "\(probe.protoV)", "supported_proto_v": "1"])
        }
        guard let m2 = try? JSONDecoder().decode(HsM2Wire.self, from: raw), m2.protoV == 1 && m2.mode == expectedMode else {
            throw await burnError(roomId, token, .errCryptoHandshakeFailed, "invalid M2 proto_v or mode")
        }
        return m2
    }

    private func decodeExactOrBurn(roomId: String, token: String, b64u: String?, expectedLen: Int, errMsg: String) async throws -> Data {
        guard let s = b64u, !s.isEmpty, let decoded = try? SyncCrypto.b64uDecode(s), decoded.count == expectedLen else { throw await burnError(roomId, token, .errCryptoHandshakeFailed, errMsg) }
        return decoded
    }

    // MARK: - PairBind & Mode A Live Pipe Transfer

    private func buildLocalPairBind(st: InitializedState, labelOverride: String) async throws -> LocalPairBindBundle {
        let trimmed = labelOverride.trimmingCharacters(in: .whitespacesAndNewlines), label = trimmed.isEmpty ? st.deviceLabel : trimmed
        let issuedAt = Int64(Date().timeIntervalSince1970)
        let cardSig = try SyncCrypto.signDeviceCard(signSeed32: st.deviceKeys.sigSeed, kemPk32: st.deviceKeys.kemPk, issuedAt: issuedAt)
        let dcPayload = DeviceCardPayload(deviceId: st.deviceKeys.deviceId, signPk: SyncCrypto.b64uEncode(st.deviceKeys.sigPk), kemPk: SyncCrypto.b64uEncode(st.deviceKeys.kemPk), issuedAt: issuedAt, cardSig: SyncCrypto.b64uEncode(cardSig), label: label, platform: platform)
        let caps = try await capabilities()
        var inboundTokenId = "", inboundTokenHash = "", mbPayload: MailboxBindPayload?
        if caps.spool.enabled, try await syncMailboxInternal(st) {
            do {
                let (tokId, tokHash, rawTok) = try await registerPeerDepositToken(st: st)
                inboundTokenId = tokId; inboundTokenHash = tokHash
                mbPayload = MailboxBindPayload(relayOrigin: transport.profile.endpoint, mailboxId: st.mailboxKeys.mailboxId, depositToken: rawTok)
            } catch let se as SyncError where se.code == .errSpoolDisabled {}
        }
        return LocalPairBindBundle(payload: PairBindPayload(deviceCard: dcPayload, mailbox: mbPayload), inboundTokenId: inboundTokenId, inboundTokenHash: inboundTokenHash)
    }

    private func decodeAndOpenPeerPairBind(sess: ActiveRoomSession, peerMsg: RoomMessageWire, fromInitiator: Bool) async throws -> PairBindPayload {
        guard let raw = try? SyncCrypto.b64uDecode(peerMsg.msgB64), let pbWire = try? JSONDecoder().decode(PairBindWire.self, from: raw),
              pbWire.protoV == 1 && pbWire.op == "pair_bind", let ct = try? SyncCrypto.b64uDecode(pbWire.ct),
              let pt = try? SyncHandshake.openPairBind(sessionKey32: sess.hs.sessionKey, prk32: sess.hs.prk, th32: sess.hs.th, fromInitiator: fromInitiator, ciphertext: ct),
              let parsed = try? JSONDecoder().decode(PairBindPayload.self, from: pt) else {
            throw await burnError(sess.roomId, sess.token, .errCryptoDecryptFailed, "decode or decrypt peer pair_bind failed")
        }
        return parsed
    }

    private func verifyPeerBindCardOnly(peerBind: PairBindPayload, roomId: String, token: String) async throws {
        guard let signPk = try? SyncCrypto.b64uDecode(peerBind.deviceCard.signPk), let kemPk = try? SyncCrypto.b64uDecode(peerBind.deviceCard.kemPk),
              let cardSig = try? SyncCrypto.b64uDecode(peerBind.deviceCard.cardSig),
              (try? SyncCrypto.verifyDeviceCard(deviceId: peerBind.deviceCard.deviceId, signPk: signPk, kemPk: kemPk, issuedAt: peerBind.deviceCard.issuedAt, cardSig: cardSig)) != nil else {
            throw await burnError(roomId, token, .errCryptoSignatureInvalid, "peer DeviceCard signature invalid")
        }
    }

    private func verifyAndSavePeerBind(st: InitializedState, peerBind: PairBindPayload, inboundTokenId: String, inboundTokenHash: String) async throws -> DeviceCard {
        guard let signPk = try? SyncCrypto.b64uDecode(peerBind.deviceCard.signPk), let kemPk = try? SyncCrypto.b64uDecode(peerBind.deviceCard.kemPk),
              let cardSig = try? SyncCrypto.b64uDecode(peerBind.deviceCard.cardSig) else { throw SyncError(code: .errCryptoSignatureInvalid, message: "invalid peer DeviceCard encoding") }
        try SyncCrypto.verifyDeviceCard(deviceId: peerBind.deviceCard.deviceId, signPk: signPk, kemPk: kemPk, issuedAt: peerBind.deviceCard.issuedAt, cardSig: cardSig)
        var relayOrigin = transport.profile.endpoint, relayId = transport.profile.relayId, mailboxId = "", outboundDepositToken = ""
        if let mb = peerBind.mailbox {
            relayOrigin = mb.relayOrigin
            if let canon = try? SyncCrypto.canonicalRelayOrigin(mb.relayOrigin) { relayOrigin = canon; relayId = SyncCrypto.deriveRelayId(canon) }
            mailboxId = mb.mailboxId; outboundDepositToken = mb.depositToken
        }
        let cleanId = peerBind.deviceCard.deviceId.lowercased(), prevCard = try await keyStore.getDevice(cleanId)
        let card = DeviceCard(deviceId: cleanId, label: peerBind.deviceCard.label, platform: peerBind.deviceCard.platform ?? "", signPk: peerBind.deviceCard.signPk, kemPk: peerBind.deviceCard.kemPk, issuedAt: peerBind.deviceCard.issuedAt, cardSig: peerBind.deviceCard.cardSig, relayOrigin: relayOrigin, relayId: relayId, mailboxId: mailboxId, outboundDepositToken: outboundDepositToken, inboundTokenId: inboundTokenId, inboundTokenHash: inboundTokenHash, pairedAt: Int64(Date().timeIntervalSince1970), revoked: false)
        try await keyStore.putDevice(card)
        if let prev = prevCard, !prev.inboundTokenId.isEmpty, prev.inboundTokenId != inboundTokenId {
            do { try await deleteRelayDepositTokenStrict(st: st, tokenId: prev.inboundTokenId) } catch { try? await keyStore.addPendingTokenDelete(prev.inboundTokenId) }
        }
        return card
    }

    private func verifyOneshotPipeAck(sess: ActiveRoomSession, ctrlKey32: Data, ctrlNp7: Data, ackWire: RoomMessageWire, expectedMsgId: String) async throws {
        guard let raw = try? SyncCrypto.b64uDecode(ackWire.msgB64), let cw = try? JSONDecoder().decode(PipeCtrlWire.self, from: raw),
              let ct = try? SyncCrypto.b64uDecode(cw.ct),
              let ptAck = try? SyncHandshake.openPipeCtrlVerified(ctrlKey32: ctrlKey32, ctrlNp7: ctrlNp7, th32: sess.hs.th, ctrlSeq: cw.ctrlSeq, fromInitiator: false, lastSeenSeq: -1, ciphertext: ct),
              let ack = try? JSONDecoder().decode(PipeAckPayload.self, from: ptAck), ack.op == "pipe_ack" && ack.msgId == expectedMsgId else {
            throw await burnError(sess.roomId, sess.token, .errCryptoDecryptFailed, "invalid or unauthenticated pipe_ack")
        }
    }

    private func receiveOneShotJoined(st: InitializedState, joined: RoomJoinResp, m1: HsM1Wire, oob: Data, options: ReceiveOptions, handler: (@Sendable (ReceivedParcel) async throws -> Void)?) async throws -> ReceivedParcel {
        var sess = try await runResponderHandshake(joined: joined, m1: m1, oobSecret: oob, onSASDisplay: options.onSASDisplay, onSASConfirm: options.onSASConfirm)
        let (ctrlKey, ctrlNp) = try SyncHandshake.derivePipeCtrlKeys(th32: sess.hs.th, sessionKey32: sess.hs.sessionKey)
        let (startWire, nextSeq) = try await waitForPeerRoomMessage(roomId: sess.roomId, roomToken: sess.token, expectedFrom: "sender", sinceSeq: sess.lastSeq); sess.lastSeq = nextSeq
        guard let raw = try? SyncCrypto.b64uDecode(startWire.msgB64), let cw = try? JSONDecoder().decode(PipeCtrlWire.self, from: raw),
              let ct = try? SyncCrypto.b64uDecode(cw.ct),
              let ptStart = try? SyncHandshake.openPipeCtrlVerified(ctrlKey32: ctrlKey, ctrlNp7: ctrlNp, th32: sess.hs.th, ctrlSeq: cw.ctrlSeq, fromInitiator: true, lastSeenSeq: -1, ciphertext: ct),
              let startCmd = try? JSONDecoder().decode(PipeStartPayload.self, from: ptStart) else {
            throw await burnError(sess.roomId, sess.token, .errCryptoDecryptFailed, "decrypt pipe_start failed")
        }
        guard startCmd.op == "pipe_start" && SyncCrypto.isLowerHex(startCmd.msgId, count: 32), let msgIdRaw = try? SyncCrypto.hexDecode(startCmd.msgId) else {
            throw await burnError(sess.roomId, sess.token, .errManifestInvalid, "invalid pipe_start payload")
        }
        let (p0Key, p0Np) = try SyncHandshake.deriveOneshotPart0Keys(sessionKey32: sess.hs.sessionKey, msgId16: msgIdRaw)
        let parcel: ReceivedParcel
        do { parcel = try await downloadAndDeliverPipeParcel(st: st, pipeId: sess.pipeId, recvToken: sess.token, msgIdRaw16: msgIdRaw, msgIdHex: startCmd.msgId, p0Key32: p0Key, p0Np7: p0Np, opened: nil, parts: startCmd.parts, options: options, handler: handler) }
        catch { await closeRoomBestEffort(roomId: sess.roomId, roomToken: sess.token, reason: "cancelled"); throw error }
        let ackCt = try SyncHandshake.sealPipeCtrl(ctrlKey32: ctrlKey, ctrlNp7: ctrlNp, th32: sess.hs.th, ctrlSeq: 1, plaintext: try JSONEncoder().encode(PipeAckPayload(msgId: startCmd.msgId)))
        _ = try await postRoomMessage(roomId: sess.roomId, roomToken: sess.token, kind: "control", payload: try JSONEncoder().encode(PipeCtrlWire(ctrlSeq: 1, ct: SyncCrypto.b64uEncode(ackCt))))
        return parcel
    }

    private func receiveDirectJoined(st: InitializedState, joined: RoomJoinResp, initPayload: DirectRoomInitPayload, options: ReceiveOptions, handler: (@Sendable (ReceivedParcel) async throws -> Void)?) async throws -> ReceivedParcel {
        let roomId = joined.roomId, token = joined.receiverToken
        guard let hdrBytes = try? SyncCrypto.b64uDecode(initPayload.sealedHeader), hdrBytes.count == SyncSealedHeader.sealedHeaderSize else {
            throw await burnError(roomId, token, .errCryptoSignatureInvalid, "invalid direct sealed_header")
        }
        let opened: OpenedSealedHeader
        do { opened = try await openAndVerifySealedHeader(st: st, hdrBytes: hdrBytes) } catch { await closeRoomBestEffort(roomId: roomId, roomToken: token, reason: "verify_failed"); throw error }
        try claimInFlightMsgId(opened.msgId); defer { releaseInFlightMsgId(opened.msgId) }
        let parcel: ReceivedParcel
        do { parcel = try await downloadAndDeliverPipeParcel(st: st, pipeId: joined.pipeId, recvToken: token, msgIdRaw16: opened.msgIdRaw, msgIdHex: opened.msgId, p0Key32: opened.part0Key, p0Np7: opened.part0NoncePrefix, opened: opened, parts: initPayload.parts, options: options, handler: handler) }
        catch let se as SyncError { await closeRoomBestEffort(roomId: roomId, roomToken: token, reason: (se.isSecurityAlert || se.isAuthError) ? "verify_failed" : "cancelled"); throw se }
        catch { await closeRoomBestEffort(roomId: roomId, roomToken: token, reason: "cancelled"); throw error }
        try await keyStore.markSeenMsgId(opened.msgId, createdAt: opened.createdAt, seenAt: Int64(Date().timeIntervalSince1970))
        let ackMac = try SyncSealedHeader.computeDirectAckMac(part0Key32: opened.part0Key, msgIdRaw16: opened.msgIdRaw)
        _ = try await postRoomMessage(roomId: roomId, roomToken: token, kind: "control", payload: try JSONEncoder().encode(PipeAckPayload(msgId: opened.msgId, ackMac: SyncCrypto.b64uEncode(ackMac))))
        return parcel
    }

    internal func sendDirectViaPipe(prep: PreparedParcel, sealedB64: String, p0Key: Data, p0Np: Data, blocksPerChunk: Int, options: SendOptions) async throws -> SendResult {
        let roomId = try Crockford.generateRoomId()
        let created = try await createRoom(roomId: roomId, ttlSec: options.ttlSec, initialMsg: try JSONEncoder().encode(DirectRoomInitPayload(sealedHeader: sealedB64, blocksPerChunk: blocksPerChunk, parts: prep.parts)))
        let offer = PairOffer(version: 1, roomId: roomId, mode: SyncHandshake.modeDirect, purpose: SyncHandshake.purposeDirect, endpoint: options.includeRelay ? transport.profile.endpoint : "", spkiPins: options.includeRelay ? transport.profile.resolvedPins : [], expiresAt: created.expiresAt, accessKey: options.includeRelay ? transport.profile.accessKey : "")
        do {
            try await options.onOfferReady?(OfferReadyInfo(roomId: roomId, displayCode: try Crockford.formatRoomId(roomId), mode: SyncHandshake.modeDirect, purpose: SyncHandshake.purposeDirect, pairUri: try SyncUri.formatPairUri(offer), expiresAt: created.expiresAt))
            try await uploadAllPipeParts(pipeId: created.pipeId, senderToken: created.senderToken, prep: prep, p0Key: p0Key, p0Np: p0Np, blocksPerChunk: blocksPerChunk, onProgress: options.onProgress)
        } catch { await closeRoomBestEffort(roomId: roomId, roomToken: created.senderToken, reason: "cancelled"); throw error }
        let (ackWire, _) = try await waitForPeerRoomMessage(roomId: roomId, roomToken: created.senderToken, expectedFrom: "receiver", sinceSeq: created.seq)
        guard let raw = try? SyncCrypto.b64uDecode(ackWire.msgB64), let ack = try? JSONDecoder().decode(PipeAckPayload.self, from: raw),
              ack.op == "pipe_ack" && ack.msgId == prep.msgId, let macB64 = ack.ackMac, let macBytes = try? SyncCrypto.b64uDecode(macB64),
              (try? SyncSealedHeader.verifyDirectAckMac(part0Key32: p0Key, msgIdRaw16: prep.msgIdRaw, gotMac: macBytes)) != nil else {
            throw await burnError(roomId, created.senderToken, .errCryptoSignatureInvalid, "direct pipe_ack MAC verification failed")
        }
        await closeRoomBestEffort(roomId: roomId, roomToken: created.senderToken, reason: "completed")
        return SendResult(mode: DeliveryMode.pipe, msgId: prep.msgId, roomId: roomId, totalBytes: prep.totalEnc)
    }

    private func withPipeRetry<T>(partId: Int, txIdx: Int, op: () async throws -> T) async throws -> T {
        let maxRetries = (partId == 0 && txIdx == 0) ? 6 : 2
        var retries = 0
        while true {
            try Task.checkCancellation()
            do { return try await op() }
            catch let se as SyncError where se.code == .errPipePeerTimeout && retries < maxRetries { retries += 1; try await Task.sleep(nanoseconds: 50_000_000) }
        }
    }

    internal func uploadAllPipeParts(pipeId: String, senderToken: String, prep: PreparedParcel, p0Key: Data, p0Np: Data, blocksPerChunk: Int, onProgress: (@Sendable (TransferEvent) -> Void)?) async throws {
        try await uploadAllParcelParts(mode: DeliveryMode.pipe, prep: prep, p0Key: p0Key, p0Np: p0Np, blocksPerChunk: blocksPerChunk, onProgress: onProgress) { partId, txIdx, chunkData in
            _ = try await self.withPipeRetry(partId: partId, txIdx: txIdx) {
                try await self.transport.doStreamUpload(method: "PUT", pathAndQuery: "/v1/pipe/\(pipeId)/parts/\(partId)/chunks/\(txIdx)", chunkData: chunkData, opts: RequestAuthOptions(roomToken: senderToken))
            }
        }
    }

    internal func fetchPipeChunkData(pipeId: String, recvToken: String, partId: Int, txIdx: Int) async throws -> Data {
        try await withPipeRetry(partId: partId, txIdx: txIdx) {
            try await self.transport.fetchChunkData(pathAndQuery: "/v1/pipe/\(pipeId)/parts/\(partId)/chunks/\(txIdx)", opts: RequestAuthOptions(roomToken: recvToken))
        }
    }

    private func downloadAndDeliverPipeParcel(st: InitializedState, pipeId: String, recvToken: String, msgIdRaw16: Data, msgIdHex: String, p0Key32: Data, p0Np7: Data, opened: OpenedSealedHeader?, parts: [PartLayout], options: ReceiveOptions, handler: (@Sendable (ReceivedParcel) async throws -> Void)?) async throws -> ReceivedParcel {
        var partMap: [Int: PartLayout] = [:]; for p in parts { partMap[p.partId] = p }
        guard partMap.count == parts.count, let p0Layout = partMap[0], p0Layout.chunkCount > 0 else { throw SyncError(code: .errManifestInvalid, message: "invalid or duplicate pipe part layouts") }
        let totalBytes = parts.reduce(Int64(0)) { $0 + $1.totalBytes }
        let (manifest, _) = try await pullAndVerifyManifest(msgIdRaw16: msgIdRaw16, msgIdHex: msgIdHex, p0Key32: p0Key32, p0Np7: p0Np7, p0Layout: p0Layout, opened: opened) { txIdx in
            try await self.fetchPipeChunkData(pipeId: pipeId, recvToken: recvToken, partId: 0, txIdx: txIdx)
        }
        guard parts.count == 1 + manifest.blobs.count else { throw SyncError(code: .errManifestInvalid, message: "pipe parts count mismatch") }
        if let wantApp = options.appId, !wantApp.isEmpty, manifest.appId != wantApp { throw SyncError(code: .errManifestInvalid, message: "parcel app_id \(manifest.appId) does not match expected \(wantApp)") }
        let blobs = try await pullAndVerifyBlobs(st: st, itemId: "", expiresAt: 0, msgIdRaw16: msgIdRaw16, manifest: manifest, partMap: partMap, totalBytes: totalBytes, initialDoneBytes: p0Layout.totalBytes, mode: DeliveryMode.pipe, onProgress: options.onProgress) { partId, txIdx in
            try await self.fetchPipeChunkData(pipeId: pipeId, recvToken: recvToken, partId: partId, txIdx: txIdx)
        }
        let parcel = ReceivedParcel(manifest: manifest, blobs: blobs)
        if let h = handler { try await h(parcel) }
        return parcel
    }
}
