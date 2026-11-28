import CryptoKit
import Darwin
import Foundation

internal struct PreparedBlob: Sendable { let partId: Int, blobKey32: Data, desc: BlobDescriptor, input: BlobInput }
internal struct PreparedParcel: Sendable {
    let msgIdRaw: Data, msgId: String, createdAt: Int64, manifest: Manifest
    let manifestUtf8: Data, manifestPad: Data, manifestSha256: Data, blobs: [PreparedBlob], parts: [PartLayout], totalEnc: Int64
}

private let maxFutureCreatedAtSkewSec: Int64 = 600
private let watchDedupFifoCap: Int = 4096

extension SyncClient {
    internal nonisolated func mailboxAuthOpts(_ st: InitializedState, acceptSse: Bool = false) -> RequestAuthOptions {
        RequestAuthOptions(mailboxId: st.mailboxKeys.mailboxId, mailboxAuthSeed32: st.mailboxKeys.authSeed, acceptSse: acceptSse)
    }

    // MARK: - Deposit Tokens, Replay Guard, SealedHeader & Parcel Preparation

    internal func registerPeerDepositToken(st: InitializedState) async throws -> (String, String, String) {
        let rawToken = try SyncCrypto.generateTokenB64u(), tokenId = "dt_\(SyncCrypto.hexEncode(try SyncCrypto.randomBytes(8)))", tokenHashHex = SyncCrypto.hashDepositToken(rawToken)
        _ = try await transport.doControl(method: "POST", pathAndQuery: "/v1/mailboxes/\(st.mailboxKeys.mailboxId)/deposit-tokens", jsonBodyBytes: try JSONEncoder().encode(MailboxDepositTokenSpec(tokenId: tokenId, tokenHashHex: tokenHashHex)), opts: mailboxAuthOpts(st))
        return (tokenId, tokenHashHex, rawToken)
    }

    internal func deleteRelayDepositTokenStrict(st: InitializedState, tokenId: String) async throws {
        guard !tokenId.isEmpty else { return }
        do { _ = try await transport.doControl(method: "DELETE", pathAndQuery: "/v1/mailboxes/\(st.mailboxKeys.mailboxId)/deposit-tokens/\(tokenId)", opts: mailboxAuthOpts(st)) }
        catch let se as SyncError where se.code == .errNotFound || se.code == .errSpoolDisabled {}
    }

    internal func deleteRelayDepositTokenBestEffort(st: InitializedState, tokenId: String) async {
        guard !tokenId.isEmpty else { return }
        let tr = self.transport, opts = mailboxAuthOpts(st), path = "/v1/mailboxes/\(st.mailboxKeys.mailboxId)/deposit-tokens/\(tokenId)"
        await Task.detached { _ = try? await tr.doControl(method: "DELETE", pathAndQuery: path, opts: opts) }.value
    }

    internal func claimInFlightMsgId(_ msgId: String) throws {
        let norm = msgId.lowercased()
        guard inFlightMsgIds.insert(norm).inserted else { throw SyncError(code: .errMsgReplayDetected, message: "msg_id is already being processed concurrently", details: ["msg_id": norm]) }
    }

    internal func releaseInFlightMsgId(_ msgId: String) { inFlightMsgIds.remove(msgId.lowercased()) }

    internal func openAndVerifySealedHeader(st: InitializedState, hdrBytes: Data) async throws -> OpenedSealedHeader {
        let (_, msgIdHex) = try SyncSealedHeader.parseClearHeaderMsgId(hdrBytes)
        if try await keyStore.hasSeenMsgId(msgIdHex) { throw SyncError(code: .errMsgReplayDetected, message: "msg_id already processed (replay rejected)", details: ["msg_id": msgIdHex]) }
        var cardMap: [String: DeviceCard] = [:]
        for c in try await keyStore.listDevices() where !c.revoked { cardMap[c.deviceId.lowercased()] = c }
        let opened = try SyncSealedHeader.open0RttHeader(recipientKeys: st.deviceKeys, sealedHeader: hdrBytes) { senderId in
            guard let card = cardMap[senderId.lowercased()], !card.revoked, let pk = try? SyncCrypto.b64uDecode(card.signPk), pk.count == 32 else { return nil }
            return pk
        }
        let nowSec = Int64(Date().timeIntervalSince1970), watermark = try await keyStore.getReplayWatermark()
        let minAllowed = max(0, max(nowSec - defaultSeenMsgRetentionDays * 86_400, watermark))
        guard opened.createdAt >= minAllowed && opened.createdAt <= nowSec + maxFutureCreatedAtSkewSec else {
            throw SyncError(code: .errMsgReplayDetected, message: "sealed_header created_at outside freshness window", details: ["msg_id": opened.msgId, "created_at": "\(opened.createdAt)"])
        }
        return opened
    }

    internal func prepareParcel(st: InitializedState, input: ParcelInput, blocksPerChunk: Int) throws -> PreparedParcel {
        guard input.blobs.count <= ManifestCodec.maxBlobs else { throw SyncError(code: .errManifestInvalid, message: "blobs count exceeds max \(ManifestCodec.maxBlobs)") }
        let bpc = blocksPerChunk <= 0 ? 16 : blocksPerChunk, createdAt = Int64(Date().timeIntervalSince1970)
        let msgIdRaw = try SyncCrypto.randomBytes(SyncCrypto.msgIdRawSize), msgIdHex = SyncCrypto.hexEncode(msgIdRaw)
        let parcelAppId = input.appId.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? appId : input.appId
        let schema = input.schema.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? "generic.parcel.v1" : input.schema
        var blobs: [PreparedBlob] = [], descs: [BlobDescriptor] = []
        for (idx, bi) in input.blobs.enumerated() {
            try Task.checkCancellation()
            let partId = idx + 1, reader = try bi.openReader(); defer { reader.close() }
            var hasher = SHA256(), counted: Int64 = 0
            while true {
                let chunk = try reader.readChunk(maxBytes: 65_536)
                if chunk.isEmpty { break }
                hasher.update(data: chunk); counted += Int64(chunk.count)
            }
            let blobKey = try SyncCrypto.randomBytes(32)
            let desc = BlobDescriptor(partId: partId, role: bi.role.isEmpty ? "file" : bi.role, name: bi.name.isEmpty ? "part_\(partId).bin" : bi.name, mime: bi.mime.isEmpty ? "application/octet-stream" : bi.mime, size: counted, sha256: SyncCrypto.hexEncode(Data(hasher.finalize())), key: SyncCrypto.b64uEncode(blobKey), encoding: bi.encoding.isEmpty ? "identity" : bi.encoding, meta: bi.meta)
            blobs.append(PreparedBlob(partId: partId, blobKey32: blobKey, desc: desc, input: bi)); descs.append(desc)
        }
        let manifest = Manifest(envelopeVersion: ManifestCodec.envelopeVersion, msgId: msgIdHex, appId: parcelAppId, schema: schema, createdAt: createdAt, sender: SenderInfo(deviceId: st.deviceKeys.deviceId, label: st.deviceLabel, platform: platform), inlinePayload: input.inlinePayload, blobs: descs)
        let manifestUtf8 = try ManifestCodec.marshalManifest(manifest), manifestPad = try StreamCipher.padManifest4K(manifestUtf8)
        let p0Enc = StreamCipher.encryptedPartSize(plaintextLen: Int64(manifestPad.count))
        var parts = [PartLayout(partId: 0, totalBytes: p0Enc, chunkCount: StreamCipher.transportChunkCount(encryptedSize: p0Enc, blocksPerChunk: bpc))], totalEnc = p0Enc
        for b in blobs {
            let encSz = StreamCipher.encryptedPartSize(plaintextLen: b.desc.size)
            parts.append(PartLayout(partId: b.partId, totalBytes: encSz, chunkCount: StreamCipher.transportChunkCount(encryptedSize: encSz, blocksPerChunk: bpc))); totalEnc += encSz
        }
        return PreparedParcel(msgIdRaw: msgIdRaw, msgId: msgIdHex, createdAt: createdAt, manifest: manifest, manifestUtf8: manifestUtf8, manifestPad: manifestPad, manifestSha256: SyncCrypto.sha256(manifestUtf8), blobs: blobs, parts: parts, totalEnc: totalEnc)
    }

    internal func pullAndVerifyManifest(msgIdRaw16: Data, msgIdHex: String, p0Key32: Data, p0Np7: Data, p0Layout: PartLayout, opened: OpenedSealedHeader?, fetchChunk: (Int) async throws -> Data) async throws -> (Manifest, Data) {
        guard p0Layout.totalBytes > 0 && p0Layout.totalBytes <= Int64(ManifestCodec.maxEncryptedManifestBytes) && p0Layout.chunkCount >= 1 && p0Layout.chunkCount <= ManifestCodec.maxManifestChunks else {
            throw SyncError(code: .errManifestInvalid, message: "part_id=0 layout out of bounds")
        }
        let sc = try StreamCipher(encKey32: p0Key32, noncePrefix7: p0Np7, msgIdRaw16: msgIdRaw16, partId: 0)
        var paddedOut = Data(), blkIdx: UInt32 = 0, sawFinal = false, totalEncSeen: Int64 = 0
        for tx in 0..<p0Layout.chunkCount {
            if sawFinal { throw SyncError(code: .errStreamTruncated, message: "extra transport chunks after final manifest block") }
            let chunkBytes = try await fetchChunk(tx); totalEncSeen += Int64(chunkBytes.count)
            guard totalEncSeen <= p0Layout.totalBytes && totalEncSeen <= Int64(ManifestCodec.maxEncryptedManifestBytes) else { throw SyncError(code: .errManifestInvalid, message: "part_id=0 stream exceeded manifest byte budget") }
            let (blocksDone, fin) = try StreamCipher.decryptChunkBuffer(cipher: sc, chunkBytes: chunkBytes, startBlockIdx: blkIdx, totalBlocks: 0, isLastTransportChunk: tx == p0Layout.chunkCount - 1, alreadySawFinal: sawFinal) { paddedOut.append($0) }
            blkIdx &+= blocksDone; if fin { sawFinal = true }
        }
        guard sawFinal && totalEncSeen == p0Layout.totalBytes else { throw SyncError(code: .errStreamTruncated, message: "manifest stream missing final block or byte count mismatch") }
        let rawManifest = try StreamCipher.unpadManifest4K(paddedOut), rawSha = SyncCrypto.sha256(rawManifest)
        if let opened = opened, !SyncCrypto.constantTimeEquals(rawSha, opened.manifestSha256) { throw SyncError(code: .errCryptoSignatureInvalid, message: "manifest SHA-256 does not match signed SealedHeader") }
        let manifest = try ManifestCodec.parseManifest(rawManifest)
        guard manifest.msgId == msgIdHex else { throw SyncError(code: .errManifestInvalid, message: "manifest msg_id mismatch") }
        if let opened = opened, manifest.sender.deviceId != opened.senderDeviceId || manifest.createdAt != opened.createdAt { throw SyncError(code: .errCryptoSignatureInvalid, message: "manifest sender/created_at mismatch with SealedHeader") }
        return (manifest, rawSha)
    }

    internal func uploadAllParcelParts(mode: String, prep: PreparedParcel, p0Key: Data, p0Np: Data, blocksPerChunk: Int, onProgress: (@Sendable (TransferEvent) -> Void)?, putChunk: (Int, Int, Data) async throws -> Void) async throws {
        var totalSent: Int64 = 0; let started = DispatchTime.now().uptimeNanoseconds
        func emit(partId: Int, partDone: Int64, partTotal: Int64) {
            guard let cb = onProgress else { return }
            let elapsed = max(Double(DispatchTime.now().uptimeNanoseconds - started) / 1_000_000_000.0, 0.001)
            cb(TransferEvent(stage: "transferring", direction: "send", mode: mode, msgId: prep.msgId, partId: partId, partsTotal: prep.parts.count, bytesDone: totalSent, bytesTotal: prep.totalEnc, partBytesDone: partDone, partBytesTotal: partTotal, speedBps: Int64(Double(totalSent) / elapsed)))
        }
        var p0Done: Int64 = 0; let p0Total = prep.parts[0].totalBytes
        let p0Reader = try BlobInput.fromData(prep.manifestPad, name: "manifest").openReader(); defer { p0Reader.close() }
        try await streamUploadPart(reader: p0Reader, plaintextSize: Int64(prep.manifestPad.count), encKey32: p0Key, noncePrefix7: p0Np, msgIdRaw16: prep.msgIdRaw, partId: 0, blocksPerChunk: blocksPerChunk) { txIdx, chunk in
            try await putChunk(0, txIdx, chunk); p0Done += Int64(chunk.count); totalSent += Int64(chunk.count); emit(partId: 0, partDone: p0Done, partTotal: p0Total)
        }
        for (i, b) in prep.blobs.enumerated() {
            let (encKey, np) = try StreamCipher.deriveBlobPartKeys(msgIdRaw16: prep.msgIdRaw, partId: b.partId, blobKey32: b.blobKey32)
            let reader = try b.input.openReader(); defer { reader.close() }
            var partDone: Int64 = 0; let partTotal = prep.parts[i + 1].totalBytes
            try await streamUploadPart(reader: reader, plaintextSize: b.desc.size, encKey32: encKey, noncePrefix7: np, msgIdRaw16: prep.msgIdRaw, partId: b.partId, blocksPerChunk: blocksPerChunk) { txIdx, chunk in
                try await putChunk(b.partId, txIdx, chunk); partDone += Int64(chunk.count); totalSent += Int64(chunk.count); emit(partId: b.partId, partDone: partDone, partTotal: partTotal)
            }
        }
    }

    private func streamUploadPart(reader: BlobReader, plaintextSize: Int64, encKey32: Data, noncePrefix7: Data, msgIdRaw16: Data, partId: Int, blocksPerChunk: Int, putChunk: (Int, Data) async throws -> Void) async throws {
        let sc = try StreamCipher(encKey32: encKey32, noncePrefix7: noncePrefix7, msgIdRaw16: msgIdRaw16, partId: partId)
        let totalBlocks = StreamCipher.totalBlocks(plaintextLen: plaintextSize), bpc = max(blocksPerChunk, 1)
        var chunkOut = Data(capacity: bpc * StreamCipher.chunkCiphertextMax), blockIdx: UInt32 = 0, txIdx = 0
        while blockIdx < totalBlocks {
            try Task.checkCancellation()
            let isFinal = (blockIdx == totalBlocks - 1)
            let wantPt = isFinal ? (plaintextSize == 0 ? 0 : Int(((plaintextSize - 1) % Int64(StreamCipher.chunkPlaintextMax)) + 1)) : StreamCipher.chunkPlaintextMax
            var ptSlice = Data(capacity: wantPt)
            while ptSlice.count < wantPt {
                let piece = try reader.readChunk(maxBytes: wantPt - ptSlice.count)
                guard !piece.isEmpty else { throw SyncError(code: .errStorageIo, message: "unexpected EOF reading blob plaintext") }
                ptSlice.append(piece)
            }
            chunkOut.append(try sc.sealBlockAt(blockIdx: blockIdx, isFinal: isFinal, plaintext: ptSlice)); blockIdx &+= 1
            if (Int(blockIdx) % bpc == 0) || (blockIdx == totalBlocks) { try await putChunk(txIdx, chunkOut); chunkOut.removeAll(keepingCapacity: true); txIdx += 1 }
        }
    }

    // MARK: - Mode B Blinded Mailboxes, Spool Upload/Download, Watch & Two-Phase Revoke

    internal func registerMailboxInternal() async throws -> MailboxRegisterResponse {
        let st = try await ensureInitialized()
        let reqBytes = try JSONEncoder().encode(MailboxPutReq(authPkB64: SyncCrypto.b64uEncode(st.mailboxKeys.authPk), depositTokens: nil))
        do {
            let resp = try await transport.doControl(method: "PUT", pathAndQuery: "/v1/mailboxes/\(st.mailboxKeys.mailboxId)", jsonBodyBytes: reqBytes, opts: mailboxAuthOpts(st))
            return try JSONDecoder().decode(MailboxRegisterResponse.self, from: resp.body)
        } catch let se as SyncError where se.code == .errSpoolDisabled {
            return MailboxRegisterResponse(mailboxId: st.mailboxKeys.mailboxId, registered: false, depositTokenCount: 0)
        }
    }

    internal func syncMailboxInternal(_ st: InitializedState) async throws -> Bool {
        var specs: [MailboxDepositTokenSpec] = [], seenTok = Set<String>(), revokedPendingCards: [DeviceCard] = []
        for var card in try await keyStore.listAllDevices() {
            if card.relayId.isEmpty {
                if !card.relayOrigin.isEmpty, let canon = try? SyncCrypto.canonicalRelayOrigin(card.relayOrigin) { card.relayOrigin = canon; card.relayId = SyncCrypto.deriveRelayId(canon) }
                else { card.relayOrigin = transport.profile.endpoint; card.relayId = transport.profile.relayId }
                try? await keyStore.putDevice(card)
            }
            if card.relayId != transport.profile.relayId { continue }
            if card.revoked { if !card.inboundTokenId.isEmpty { revokedPendingCards.append(card) }; continue }
            if card.pendingTokenDelete || card.inboundTokenId.isEmpty || card.inboundTokenHash.count != 64 { continue }
            if seenTok.insert(card.inboundTokenId).inserted && specs.count < 16 { specs.append(MailboxDepositTokenSpec(tokenId: card.inboundTokenId, tokenHashHex: card.inboundTokenHash.lowercased())) }
        }
        let reqBytes = try JSONEncoder().encode(MailboxPutReq(authPkB64: SyncCrypto.b64uEncode(st.mailboxKeys.authPk), depositTokens: specs.isEmpty ? nil : specs))
        let resp: RawHttpResponse
        do { resp = try await transport.doControl(method: "PUT", pathAndQuery: "/v1/mailboxes/\(st.mailboxKeys.mailboxId)", jsonBodyBytes: reqBytes, opts: mailboxAuthOpts(st)) }
        catch let se as SyncError where se.code == .errSpoolDisabled { return false }
        let regOut = try? JSONDecoder().decode(MailboxRegisterResponse.self, from: resp.body)
        if !specs.isEmpty && (regOut?.depositTokenCount ?? 0) < specs.count {
            let tokPath = "/v1/mailboxes/\(st.mailboxKeys.mailboxId)/deposit-tokens"
            for sp in specs {
                do { _ = try await transport.doControl(method: "POST", pathAndQuery: tokPath, jsonBodyBytes: try JSONEncoder().encode(sp), opts: mailboxAuthOpts(st)) }
                catch let se as SyncError where se.code == .errConflict || se.code == .errSpoolDisabled {}
            }
        }
        var pendingDeletes = try await keyStore.listPendingTokenDeletes().filter { !$0.isEmpty }
        for rc in revokedPendingCards where !rc.inboundTokenId.isEmpty && !pendingDeletes.contains(rc.inboundTokenId) { pendingDeletes.append(rc.inboundTokenId) }
        for tokId in pendingDeletes {
            if seenTok.contains(tokId) { try await keyStore.removePendingTokenDelete(tokId); continue }
            if (try? await deleteRelayDepositTokenStrict(st: st, tokenId: tokId)) != nil {
                try await keyStore.removePendingTokenDelete(tokId)
                for rc in revokedPendingCards where rc.inboundTokenId == tokId { try await keyStore.deleteDevice(rc.deviceId) }
            }
        }
        return true
    }

    internal func sendToPeerInternal(targetDeviceId: String, parcel: ParcelInput, options: SendOptions) async throws -> SendResult {
        let st = try await ensureInitialized(), mode = options.deliveryMode.isEmpty ? DeliveryMode.auto : options.deliveryMode
        guard [DeliveryMode.auto, DeliveryMode.spool, DeliveryMode.pipe].contains(mode) else { throw SyncError(code: .errBadRequest, message: "invalid deliveryMode: \(mode)") }
        guard let card = try await keyStore.getDevice(targetDeviceId), !card.revoked else { throw SyncError(code: .errDeviceUntrusted, message: "target device is untrusted or revoked") }
        guard let kemPk = try? SyncCrypto.b64uDecode(card.kemPk), kemPk.count == 32 else { throw SyncError(code: .errCryptoSignatureInvalid, message: "invalid target kem_pk") }
        guard let recipIdRaw = try? SyncCrypto.hexDecode(card.deviceId), recipIdRaw.count == 16 else { throw SyncError(code: .errDeviceUntrusted, message: "invalid target device_id") }
        let caps = try await capabilities(), bpc = caps.streaming.blocksPerChunk > 0 ? caps.streaming.blocksPerChunk : 16
        let prep = try prepareParcel(st: st, input: parcel, blocksPerChunk: bpc), (ephSk, _) = try SyncCrypto.x25519Generate()
        let sealed = try SyncSealedHeader.seal0RttHeaderDeterministic(senderKeys: st.deviceKeys, ephemeralSk32: ephSk, msgIdRaw16: prep.msgIdRaw, recipientIdRaw16: recipIdRaw, recipientKemPub32: kemPk, createdAt: prep.createdAt, manifestSha256: prep.manifestSha256)
        let sealedB64 = SyncCrypto.b64uEncode(sealed.sealedHeader)
        if mode == DeliveryMode.pipe { return try await sendDirectViaPipe(prep: prep, sealedB64: sealedB64, p0Key: sealed.part0Key, p0Np: sealed.part0NoncePrefix, blocksPerChunk: bpc, options: options) }
        guard caps.spool.enabled && !card.mailboxId.isEmpty && !card.outboundDepositToken.isEmpty else {
            throw SyncError(code: .errSpoolDisabled, message: "relay spool is disabled or peer paired without mailbox; use pipe mode", retryable: false, httpStatus: 403, details: ["suggest_mode": "pipe"])
        }
        if caps.spool.maxItemBytes > 0 && prep.totalEnc > caps.spool.maxItemBytes {
            throw SyncError(code: .errOfflineQuotaExceeded, message: "parcel exceeds relay spool max_item_bytes", retryable: false, httpStatus: 413, details: ["scope": "item", "max_item_bytes": "\(caps.spool.maxItemBytes)", "total_bytes": "\(prep.totalEnc)", "suggest_mode": "pipe"])
        }
        let initReq = SpoolInitReq(mailboxId: card.mailboxId, declaredTotalBytes: prep.totalEnc, ttlSec: options.ttlSec, sealedHeader: sealedB64, parts: prep.parts)
        let initResp = try await transport.doControl(method: "POST", pathAndQuery: "/v1/spool/init", jsonBodyBytes: try JSONEncoder().encode(initReq), opts: RequestAuthOptions(depositToken: card.outboundDepositToken))
        let initOut = try JSONDecoder().decode(SpoolInitResp.self, from: initResp.body)
        var committed = false
        defer { if !committed { let itemId = initOut.itemId, upTok = initOut.uploadToken, tr = self.transport; Task.detached { _ = try? await tr.doControl(method: "DELETE", pathAndQuery: "/v1/spool/\(itemId)", opts: RequestAuthOptions(uploadToken: upTok)) } } }
        try await uploadAllParcelParts(mode: DeliveryMode.spool, prep: prep, p0Key: sealed.part0Key, p0Np: sealed.part0NoncePrefix, blocksPerChunk: bpc, onProgress: options.onProgress) { partId, txIdx, chunkData in
            _ = try await self.transport.doStreamUpload(method: "PUT", pathAndQuery: "/v1/spool/\(initOut.itemId)/parts/\(partId)/chunks/\(txIdx)", chunkData: chunkData, opts: RequestAuthOptions(uploadToken: initOut.uploadToken))
        }
        let commitResp = try await transport.doControl(method: "POST", pathAndQuery: "/v1/spool/\(initOut.itemId)/commit", jsonBodyBytes: Data("{}".utf8), opts: RequestAuthOptions(uploadToken: initOut.uploadToken))
        committed = true
        let commitOut = try? JSONDecoder().decode(SpoolCommitResp.self, from: commitResp.body)
        return SendResult(mode: DeliveryMode.spool, msgId: prep.msgId, itemId: initOut.itemId, totalBytes: prep.totalEnc, expiresAt: (commitOut?.expiresAt ?? 0) > 0 ? commitOut!.expiresAt : initOut.expiresAt)
    }

    internal func listRawInboxItems(_ st: InitializedState) async throws -> [InboxItemMeta] {
        let path = "/v1/mailboxes/\(st.mailboxKeys.mailboxId)/items", opts = mailboxAuthOpts(st)
        let resp: RawHttpResponse
        do { resp = try await transport.doControl(method: "GET", pathAndQuery: path, opts: opts) }
        catch let se as SyncError where se.code == .errNotFound {
            if (try? await syncMailboxInternal(st)) == true { resp = try await transport.doControl(method: "GET", pathAndQuery: path, opts: opts) } else { throw se }
        }
        guard let decoded = try? JSONDecoder().decode(MailboxItemsResp.self, from: resp.body) else { throw SyncError(code: .errBadRequest, message: "decode mailbox items failed", httpStatus: resp.statusCode) }
        return decoded.items
    }

    /// Two-Phase Inbox Listing (`ST-P0-3`): always verifies `SealedHeader` BEFORE consulting `CachedManifestEntry`.
    internal func listInboxInternal(filterAppId: String?) async throws -> [InboxPreview] {
        let st = try await ensureInitialized()
        let items: [InboxItemMeta]
        do { items = try await listRawInboxItems(st) } catch let se as SyncError where se.code == .errSpoolDisabled { return [] }
        try await keyStore.pruneCachedManifests(Set(items.map(\.itemId)))
        var previews: [InboxPreview] = []
        for it in items {
            guard let hdrBytes = try? SyncCrypto.b64uDecode(it.sealedHeader), let opened = try? await openAndVerifySealedHeader(st: st, hdrBytes: hdrBytes) else {
                try? await keyStore.deleteCachedManifest(it.itemId); continue
            }
            let wantShaHex = SyncCrypto.hexEncode(opened.manifestSha256)
            if let cached = try await keyStore.getCachedManifest(it.itemId) {
                if cached.manifest.msgId == opened.msgId && cached.manifestSha256 == wantShaHex {
                    if (filterAppId ?? "").isEmpty || cached.manifest.appId == filterAppId { previews.append(InboxPreview(itemId: it.itemId, createdAt: it.createdAt, expiresAt: it.expiresAt, totalBytes: it.totalBytes, cached: true, manifest: cached.manifest)) }
                    continue
                }
                try? await keyStore.deleteCachedManifest(it.itemId)
            }
            guard let p0Layout = it.parts.first(where: { $0.partId == 0 }),
                  let (manifest, manifestSha) = try? await pullAndVerifyManifest(msgIdRaw16: opened.msgIdRaw, msgIdHex: opened.msgId, p0Key32: opened.part0Key, p0Np7: opened.part0NoncePrefix, p0Layout: p0Layout, opened: opened, fetchChunk: { txIdx in try await self.transport.fetchChunkData(pathAndQuery: "/v1/spool/\(it.itemId)/parts/0/chunks/\(txIdx)", opts: self.mailboxAuthOpts(st)) }) else { continue }
            try await keyStore.putCachedManifest(CachedManifestEntry(itemId: it.itemId, cachedAt: Int64(Date().timeIntervalSince1970), expiresAt: it.expiresAt, manifestSha256: SyncCrypto.hexEncode(manifestSha), manifest: manifest))
            if (filterAppId ?? "").isEmpty || manifest.appId == filterAppId { previews.append(InboxPreview(itemId: it.itemId, createdAt: it.createdAt, expiresAt: it.expiresAt, totalBytes: it.totalBytes, cached: false, manifest: manifest)) }
        }
        return previews
    }

    internal func fetchParcelInternal(itemId: String, options: ReceiveOptions, handler: (@Sendable (ReceivedParcel) async throws -> Void)?) async throws -> ReceivedParcel {
        let st = try await ensureInitialized(), items = try await listRawInboxItems(st)
        guard let target = items.first(where: { $0.itemId == itemId }) else { throw SyncError(code: .errNotFound, message: "inbox item not found: \(itemId)", httpStatus: 404) }
        guard let hdrBytes = try? SyncCrypto.b64uDecode(target.sealedHeader) else { try? await keyStore.deleteCachedManifest(itemId); throw SyncError(code: .errCryptoSignatureInvalid, message: "decode sealed_header failed") }
        let opened: OpenedSealedHeader
        do { opened = try await openAndVerifySealedHeader(st: st, hdrBytes: hdrBytes) } catch { try? await keyStore.deleteCachedManifest(itemId); throw error }
        try claimInFlightMsgId(opened.msgId); defer { releaseInFlightMsgId(opened.msgId) }
        var partMap: [Int: PartLayout] = [:]; for p in target.parts { partMap[p.partId] = p }
        guard partMap.count == target.parts.count, let p0Layout = partMap[0] else { throw SyncError(code: .errManifestInvalid, message: "invalid or duplicate spool item part layouts") }
        let wantShaHex = SyncCrypto.hexEncode(opened.manifestSha256)
        let manifest: Manifest
        if let cached = try await keyStore.getCachedManifest(itemId), cached.manifest.msgId == opened.msgId && !cached.manifestSha256.isEmpty && cached.manifestSha256 == wantShaHex {
            manifest = cached.manifest
        } else {
            let (pulled, pulledSha) = try await pullAndVerifyManifest(msgIdRaw16: opened.msgIdRaw, msgIdHex: opened.msgId, p0Key32: opened.part0Key, p0Np7: opened.part0NoncePrefix, p0Layout: p0Layout, opened: opened) { txIdx in
                try await self.transport.fetchChunkData(pathAndQuery: "/v1/spool/\(itemId)/parts/0/chunks/\(txIdx)", opts: self.mailboxAuthOpts(st))
            }
            try await keyStore.putCachedManifest(CachedManifestEntry(itemId: itemId, cachedAt: Int64(Date().timeIntervalSince1970), expiresAt: target.expiresAt, manifestSha256: SyncCrypto.hexEncode(pulledSha), manifest: pulled))
            manifest = pulled
        }
        guard target.parts.count == 1 + manifest.blobs.count else { throw SyncError(code: .errManifestInvalid, message: "spool item parts count mismatch") }
        if let wantApp = options.appId, !wantApp.isEmpty, manifest.appId != wantApp { throw SyncError(code: .errManifestInvalid, message: "parcel app_id \(manifest.appId) does not match expected \(wantApp)") }
        let blobs = try await pullAndVerifyBlobs(st: st, itemId: itemId, expiresAt: target.expiresAt, msgIdRaw16: opened.msgIdRaw, manifest: manifest, partMap: partMap, totalBytes: target.totalBytes, initialDoneBytes: p0Layout.totalBytes, mode: DeliveryMode.spool, onProgress: options.onProgress) { partId, txIdx in
            try await self.transport.fetchChunkData(pathAndQuery: "/v1/spool/\(itemId)/parts/\(partId)/chunks/\(txIdx)", opts: self.mailboxAuthOpts(st))
        }
        let parcel = ReceivedParcel(itemId: itemId, manifest: manifest, blobs: blobs)
        if let h = handler { try await h(parcel) }
        pendingAckItems[itemId] = (opened.msgId, opened.createdAt)
        if options.autoAck { try await ackItemInternal(st: st, itemId: itemId) }
        return parcel
    }

    internal func ackItemInternal(st: InitializedState, itemId: String) async throws {
        if let pending = pendingAckItems.removeValue(forKey: itemId) { try await keyStore.markSeenMsgId(pending.msgId, createdAt: pending.createdAt, seenAt: Int64(Date().timeIntervalSince1970)) }
        try await keyStore.deleteCachedManifest(itemId)
        do { _ = try await transport.doControl(method: "POST", pathAndQuery: "/v1/spool/\(itemId)/ack", jsonBodyBytes: Data("{}".utf8), opts: mailboxAuthOpts(st)) }
        catch let se as SyncError where se.code == .errNotFound {}
    }

    internal func watchInboxInternal(initialSinceTs: Int64?, onEvent: @escaping @Sendable (InboxWatchEvent) async throws -> Void) async throws {
        let st = try await ensureInitialized()
        var sinceTs = max(Int64(0), initialSinceTs ?? (Int64(Date().timeIntervalSince1970) - 1))
        var seenQueue: [String] = [], seenSet = Set<String>(), usePoll = false, pollCycles = 0, healed404 = false, backoffMs: UInt64 = 250
        func recordDup(_ id: String) -> Bool {
            if id.isEmpty { return false }; if seenSet.contains(id) { return true }
            if seenQueue.count >= watchDedupFifoCap { seenSet.remove(seenQueue.removeFirst()) }
            seenQueue.append(id); seenSet.insert(id); return false
        }
        func checkFatalWatchErr(_ se: SyncError) throws {
            if se.isAuthError || se.isSecurityAlert || se.isVersionMismatch || se.code == .errSpoolDisabled || se.code == .errNotFound || se.code == .errCancelled { throw se }
        }
        while true {
            try Task.checkCancellation()
            let querySince = max(Int64(0), sinceTs - 1)
            if !usePoll {
                let path = "/v1/mailboxes/\(st.mailboxKeys.mailboxId)/events?mode=sse&since_ts=\(querySince)", started = DispatchTime.now().uptimeNanoseconds
                var gotReconnect = false
                do {
                    for try await ev in transport.sseEvents(pathAndQuery: path, opts: mailboxAuthOpts(st, acceptSse: true)) {
                        healed404 = false; backoffMs = 250
                        if ev.event == "new_item", let d = ev.data.data(using: .utf8), let item = try? JSONDecoder().decode(InboxWatchEvent.self, from: d) {
                            if item.createdAt > sinceTs { sinceTs = item.createdAt }
                            if !recordDup(item.itemId) { try await onEvent(item) }
                        } else if ev.event == "reconnect" { gotReconnect = true; break }
                    }
                } catch is CancellationError { throw SyncError(code: .errCancelled, message: "watchInbox cancelled") }
                catch let se as SyncError {
                    if se.code == .errNotFound && !healed404 { healed404 = true; if (try? await syncMailboxInternal(st)) == true { continue } }
                    try checkFatalWatchErr(se); usePoll = true; pollCycles = 0; try await sleepRetryAfter(se, defaultMs: backoffMs); backoffMs = min(backoffMs * 2, 5_000); continue
                }
                if !gotReconnect && (DispatchTime.now().uptimeNanoseconds - started) < 1_000_000_000 {
                    usePoll = true; pollCycles = 0; try await Task.sleep(nanoseconds: backoffMs * 1_000_000); backoffMs = min(backoffMs * 2, 5_000)
                }
                continue
            }
            let resp: RawHttpResponse
            do { resp = try await transport.doControl(method: "GET", pathAndQuery: "/v1/mailboxes/\(st.mailboxKeys.mailboxId)/events?mode=poll&wait_sec=20&since_ts=\(querySince)", opts: mailboxAuthOpts(st)) }
            catch let se as SyncError {
                if se.code == .errNotFound && !healed404 { healed404 = true; if (try? await syncMailboxInternal(st)) == true { continue } }
                try checkFatalWatchErr(se); try await sleepRetryAfter(se, defaultMs: backoffMs); backoffMs = min(backoffMs * 2, 5_000); continue
            }
            healed404 = false; backoffMs = 250
            guard let out = try? JSONDecoder().decode(MailboxPollResp.self, from: resp.body) else { throw SyncError(code: .errBadRequest, message: "decode mailbox poll failed", httpStatus: resp.statusCode) }
            for item in out.items {
                if item.createdAt > sinceTs { sinceTs = item.createdAt }
                if !recordDup(item.itemId) { try await onEvent(item) }
            }
            if out.serverTs > sinceTs { sinceTs = out.serverTs }
            pollCycles += 1; if pollCycles >= 6 { usePoll = false; pollCycles = 0 }
        }
    }

    internal func revokeDeviceInternal(deviceId: String) async throws {
        let st = try await ensureInitialized()
        guard var card = try await keyStore.getDevice(deviceId) else { throw SyncError(code: .errDeviceUntrusted, message: "device not found in keystore") }
        let hasToken = !card.inboundTokenId.isEmpty
        if !card.revoked || (hasToken && !card.pendingTokenDelete) { card.revoked = true; card.pendingTokenDelete = hasToken; try await keyStore.putDevice(card) }
        if hasToken {
            try await keyStore.addPendingTokenDelete(card.inboundTokenId)
            try await deleteRelayDepositTokenStrict(st: st, tokenId: card.inboundTokenId)
            try await keyStore.removePendingTokenDelete(card.inboundTokenId)
        }
        try await keyStore.deleteDevice(card.deviceId)
    }

    // MARK: - Hardened Streaming Blob Pull & Checkpoint Resume (`ST-P0-2`)

    internal func pullAndVerifyBlobs(st: InitializedState, itemId: String, expiresAt: Int64, msgIdRaw16: Data, manifest: Manifest, partMap: [Int: PartLayout], totalBytes: Int64, initialDoneBytes: Int64, mode: String, onProgress: (@Sendable (TransferEvent) -> Void)?, fetchChunk: (Int, Int) async throws -> Data) async throws -> [ReceivedBlob] {
        guard partMap.count == 1 + manifest.blobs.count && partMap[0] != nil else { throw SyncError(code: .errManifestInvalid, message: "part layout count mismatch with manifest.blobs") }
        if manifest.blobs.isEmpty { return [] }
        var seenPartIds = Set<Int>()
        for blob in manifest.blobs {
            guard blob.partId > 0 && seenPartIds.insert(blob.partId).inserted, let layout = partMap[blob.partId] else { throw SyncError(code: .errManifestInvalid, message: "invalid, duplicate, or missing layout for part_id=\(blob.partId)") }
            let wantEnc = StreamCipher.encryptedPartSize(plaintextLen: blob.size), totalBlocks = StreamCipher.totalBlocks(plaintextLen: blob.size)
            guard layout.totalBytes == wantEnc && layout.chunkCount >= 1 && Int64(layout.chunkCount) <= Int64(totalBlocks) else { throw SyncError(code: .errManifestInvalid, message: "part_id=\(blob.partId) layout mismatches signed blob.size") }
        }
        try ensureSafeRealDir(st.tempDir)
        let msgDir = st.tempDir.appendingPathComponent(manifest.msgId, isDirectory: true)
        try ensureSafeRealDir(msgDir); createdMsgDirs.insert(msgDir)
        var doneBytes = initialDoneBytes, out: [ReceivedBlob] = []
        let started = DispatchTime.now().uptimeNanoseconds
        for blob in manifest.blobs {
            try Task.checkCancellation()
            let layout = partMap[blob.partId]!, wantEnc = StreamCipher.encryptedPartSize(plaintextLen: blob.size), totalBlocks = StreamCipher.totalBlocks(plaintextLen: blob.size)
            let partFile = msgDir.appendingPathComponent("part_\(blob.partId).part", isDirectory: false)
            let verifiedFile = msgDir.appendingPathComponent("part_\(blob.partId).verified", isDirectory: false)
            if mode == DeliveryMode.spool && verifyExistingFileSha256(verifiedFile, expectedSize: blob.size, expectedShaHex: blob.sha256) {
                doneBytes += wantEnc; out.append(ReceivedBlob(descriptor: blob, safeFileURL: verifiedFile, safeName: ManifestCodec.sanitizeFilename(blob.name))); continue
            }
            guard let rawKey = try? SyncCrypto.b64uDecode(blob.key), rawKey.count == 32 else { try? FileManager.default.removeItem(at: msgDir); throw SyncError(code: .errManifestInvalid, message: "invalid blob key") }
            let (encKey, np) = try StreamCipher.deriveBlobPartKeys(msgIdRaw16: msgIdRaw16, partId: blob.partId, blobKey32: rawKey)
            let sc = try StreamCipher(encKey32: encKey, noncePrefix7: np, msgIdRaw16: msgIdRaw16, partId: blob.partId)
            var startTx = 0, initialBlkIdx: UInt32 = 0, resumed = false
            if mode == DeliveryMode.spool, let cp = try await keyStore.getCheckpoint(direction: "recv", msgId: manifest.msgId, partId: blob.partId),
               cp.nextTxIdx >= 1 && cp.nextTxIdx < layout.chunkCount && cp.nextBlockIdx > 0 {
                var pst = Darwin.stat()
                if partFile.path.withCString({ Darwin.lstat($0, &pst) }) == 0 && (pst.st_mode & S_IFMT) == S_IFREG && pst.st_size == cp.nextBlockIdx * Int64(StreamCipher.chunkPlaintextMax) {
                    startTx = cp.nextTxIdx; initialBlkIdx = UInt32(cp.nextBlockIdx); resumed = true
                }
            }
            var partDone = resumed ? Int64(initialBlkIdx) * Int64(StreamCipher.chunkCiphertextMax) : 0
            if resumed { doneBytes += partDone }
            let fd = partFile.path.withCString { Darwin.open($0, O_CREAT | O_WRONLY | O_NOFOLLOW | (resumed ? O_APPEND : O_TRUNC), mode_t(0o600)) }
            guard fd >= 0 else { try? FileManager.default.removeItem(at: msgDir); throw SyncError(code: .errStorageIo, message: "open temp part file failed") }
            var fdOpen = true; defer { if fdOpen { _ = Darwin.close(fd) } }
            do {
                let dec = RollingBlockDecryptor(cipher: sc, totalBlocks: totalBlocks, initialBlockIdx: initialBlkIdx) { try writeAllFd(fd, data: $0) }
                for tx in startTx..<layout.chunkCount {
                    try dec.ensureNotFinalBeforeChunk()
                    let chunkData: Data
                    do { chunkData = try await fetchChunk(blob.partId, tx) }
                    catch let se as SyncError {
                        if !se.isSecurityAlert && se.code != .errManifestInvalid && mode == DeliveryMode.spool && tx > 0 { throw SyncError(code: .errInterruptedResumable, message: "blob download interrupted with checkpoint saved", retryable: true) }
                        throw se
                    }
                    guard !chunkData.isEmpty else { throw SyncError(code: .errStreamTruncated, message: "empty transport chunk") }
                    guard partDone + Int64(chunkData.count) <= wantEnc else { throw SyncError(code: .errManifestInvalid, message: "part_id=\(blob.partId) ciphertext exceeded EncryptedPartSize") }
                    var off = 0
                    while off < chunkData.count { let end = min(off + 32_768, chunkData.count); try dec.feed(Data(chunkData[off..<end])); off = end }
                    try dec.finishTransportChunk()
                    partDone += Int64(chunkData.count); doneBytes += Int64(chunkData.count)
                    if mode == DeliveryMode.spool && tx + 1 < layout.chunkCount {
                        try await keyStore.putCheckpoint(TransferCheckpoint(direction: "recv", msgId: manifest.msgId, itemId: itemId, partId: blob.partId, nextTxIdx: tx + 1, nextBlockIdx: Int64(dec.blkIdx), expiresAt: expiresAt))
                    }
                    if let cb = onProgress {
                        let elapsed = max(Double(DispatchTime.now().uptimeNanoseconds - started) / 1_000_000_000.0, 0.001)
                        cb(TransferEvent(stage: "transferring", direction: "recv", mode: mode, msgId: manifest.msgId, partId: blob.partId, partsTotal: partMap.count, bytesDone: doneBytes, bytesTotal: totalBytes, partBytesDone: partDone, partBytesTotal: layout.totalBytes, speedBps: Int64(Double(doneBytes) / elapsed), resumed: resumed))
                    }
                }
                guard Darwin.fsync(fd) == 0 else { throw SyncError(code: .errStorageIo, message: "fsync temp part failed") }
                _ = Darwin.close(fd); fdOpen = false
                guard dec.sawFinal && partDone == wantEnc else { throw SyncError(code: .errStreamTruncated, message: "blob stream missing authenticated final block") }
                guard verifyExistingFileSha256(partFile, expectedSize: blob.size, expectedShaHex: blob.sha256) else { throw SyncError(code: .errHashMismatch, message: "part_id=\(blob.partId) size/sha256 mismatch") }
                try await keyStore.deleteCheckpoint(direction: "recv", msgId: manifest.msgId, partId: blob.partId)
                try? FileManager.default.removeItem(at: verifiedFile)
                guard (try? FileManager.default.moveItem(at: partFile, to: verifiedFile)) != nil else { throw SyncError(code: .errStorageIo, message: "atomic finalize verified blob failed") }
                out.append(ReceivedBlob(descriptor: blob, safeFileURL: verifiedFile, safeName: ManifestCodec.sanitizeFilename(blob.name)))
            } catch let se as SyncError {
                if se.code != .errInterruptedResumable && !se.retryable {
                    if fdOpen { _ = Darwin.close(fd); fdOpen = false }
                    try? FileManager.default.removeItem(at: msgDir)
                    try? await keyStore.deleteCheckpoint(direction: "recv", msgId: manifest.msgId, partId: blob.partId)
                }
                throw se
            }
        }
        return out
    }
}

private func ensureSafeRealDir(_ dir: URL) throws {
    var st = Darwin.stat()
    if dir.path.withCString({ Darwin.lstat($0, &st) }) == 0 {
        guard (st.st_mode & S_IFMT) == S_IFDIR else { throw SyncError(code: .errStorageIo, message: "temp directory must be a real directory, not a symlink") }
    } else if (try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)) == nil { throw SyncError(code: .errStorageIo, message: "create temp directory failed") }
}

private func verifyExistingFileSha256(_ url: URL, expectedSize: Int64, expectedShaHex: String) -> Bool {
    var st = Darwin.stat()
    guard url.path.withCString({ Darwin.lstat($0, &st) }) == 0, (st.st_mode & S_IFMT) == S_IFREG, st.st_size == expectedSize, let fh = try? FileHandle(forReadingFrom: url) else { return false }
    defer { try? fh.close() }
    var hasher = SHA256()
    while let chunk = try? fh.read(upToCount: 65_536), !chunk.isEmpty { hasher.update(data: chunk) }
    return SyncCrypto.hexEncode(Data(hasher.finalize())) == expectedShaHex
}

private func writeAllFd(_ fd: Int32, data: Data) throws {
    try data.withUnsafeBytes { rawBuf in
        guard let base = rawBuf.baseAddress else { return }
        var written = 0
        while written < rawBuf.count {
            let w = Darwin.write(fd, base.advanced(by: written), rawBuf.count - written)
            if w < 0 { if errno == EINTR { continue }; throw SyncError(code: .errStorageIo, message: "write part file failed") }
            written += w
        }
    }
}
