import Foundation

/// `64 KiB -> 65,552 B` STREAM AEAD (`12B` deterministic nonce, `46B` `"synctool-chunk-v1"` AAD),
/// strict 4 KiB Manifest bucket padding, `RollingBlockDecryptor`, and `LocalMetaKey` cache sealing (`CRYPTO_AND_AUTH.md` §6).
public struct StreamCipher: Sendable {
    public static let chunkPlaintextMax: Int = 65536
    public static let aeadTagLen: Int = 16
    public static let chunkCiphertextMax: Int = 65552
    public static let chunkAadLen: Int = 46

    public static let manifestPadBucket: Int = 4096
    public static let manifestMaxRawBytes: Int = 131072
    public static let maxManifestPaddedBytes: Int = 135168
    public static let maxManifestCiphertextBytes: Int = 135216
    public static let maxPartId: Int = 63

    private static let prefixChunkAad = Data("synctool-chunk-v1".utf8)
    private static let infoBlobEncKey = Data("synctool-v1/blob-enc-key".utf8)
    private static let infoBlobNoncePfx = Data("synctool-v1/blob-nonce-prefix".utf8)

    public let encKey: Data
    public let noncePrefix: Data
    public let msgIdRaw: Data
    public let partId: Int

    public init(encKey32: Data, noncePrefix7: Data, msgIdRaw16: Data, partId: Int) throws {
        guard partId >= 0 && partId <= Self.maxPartId else {
            throw SyncError(code: .errManifestInvalid, message: "part_id out of range 0..63")
        }
        guard encKey32.count == 32 && noncePrefix7.count == 7 && msgIdRaw16.count == 16 else {
            throw SyncError(code: .errCryptoDecryptFailed, message: "invalid StreamCipher key/noncePrefix/msgId length")
        }
        self.encKey = Data(encKey32)
        self.noncePrefix = Data(noncePrefix7)
        self.msgIdRaw = Data(msgIdRaw16)
        self.partId = partId
    }

    public func sealBlockAt(blockIdx: UInt32, isFinal: Bool, plaintext: Data) throws -> Data {
        guard plaintext.count <= Self.chunkPlaintextMax && (isFinal || plaintext.count == Self.chunkPlaintextMax) else {
            throw SyncError(code: .errBadRequest, message: "invalid STREAM plaintext block size")
        }
        let nonce = try Self.buildChunkNonce(noncePrefix7: noncePrefix, blockIdx: blockIdx, isFinal: isFinal)
        let aad = try Self.buildChunkAad(
            msgIdRaw16: msgIdRaw, partId: partId, blockIdx: blockIdx, isFinal: isFinal, plaintextLen: plaintext.count
        )
        return try SyncCrypto.aesGcmSeal(key: encKey, nonce: nonce, plaintext: plaintext, aad: aad)
    }

    public func openBlockAt(blockIdx: UInt32, isFinal: Bool, ciphertextAndTag: Data) throws -> Data {
        let ct = Data(ciphertextAndTag)
        guard ct.count >= Self.aeadTagLen && ct.count <= Self.chunkCiphertextMax else {
            throw SyncError(code: .errCryptoDecryptFailed, message: "invalid STREAM ciphertext block length")
        }
        let ptLen = ct.count - Self.aeadTagLen
        guard isFinal || ptLen == Self.chunkPlaintextMax else {
            throw SyncError(code: .errCryptoDecryptFailed, message: "non-final STREAM block must be 64 KiB")
        }
        let nonce = try Self.buildChunkNonce(noncePrefix7: noncePrefix, blockIdx: blockIdx, isFinal: isFinal)
        let aad = try Self.buildChunkAad(
            msgIdRaw16: msgIdRaw, partId: partId, blockIdx: blockIdx, isFinal: isFinal, plaintextLen: ptLen
        )
        return try SyncCrypto.aesGcmOpen(key: encKey, nonce: nonce, ciphertextAndTag: ct, aad: aad)
    }

    public static func deriveBlobPartKeys(
        msgIdRaw16: Data, partId: Int, blobKey32: Data
    ) throws -> (encKey: Data, noncePrefix: Data) {
        guard partId >= 1 && partId <= maxPartId else {
            throw SyncError(code: .errManifestInvalid, message: "blob part_id must be in 1..63")
        }
        guard msgIdRaw16.count == 16 && blobKey32.count == 32 else {
            throw SyncError(code: .errManifestInvalid, message: "invalid msg_id or blob_key length")
        }
        var salt = Data(capacity: 20)
        salt.append(Data(msgIdRaw16))
        SyncCrypto.appendUInt32BE(&salt, UInt32(partId))
        let prk = SyncCrypto.hkdfExtract(salt: salt, ikm: blobKey32)
        let encKey = try SyncCrypto.hkdfExpand(prk: prk, info: infoBlobEncKey, length: 32)
        let np = try SyncCrypto.hkdfExpand(prk: prk, info: infoBlobNoncePfx, length: 7)
        return (encKey, np)
    }

    /// 12-byte deterministic STREAM nonce: `nonce_prefix(7B) || uint32_be(block_idx)(4B) || uint8(is_final)(1B)`.
    public static func buildChunkNonce(noncePrefix7: Data, blockIdx: UInt32, isFinal: Bool) throws -> Data {
        guard noncePrefix7.count == 7 else {
            throw SyncError(code: .errCryptoDecryptFailed, message: "nonce_prefix must be 7 bytes")
        }
        var out = Data(capacity: 12)
        out.append(Data(noncePrefix7))
        SyncCrypto.appendUInt32BE(&out, blockIdx)
        out.append(isFinal ? 0x01 : 0x00)
        return out
    }

    /// Exact 46-byte binary STREAM AAD (`CRYPTO_AND_AUTH.md` §6.2).
    public static func buildChunkAad(
        msgIdRaw16: Data, partId: Int, blockIdx: UInt32, isFinal: Bool, plaintextLen: Int
    ) throws -> Data {
        guard msgIdRaw16.count == 16 && partId >= 0 && partId <= maxPartId && plaintextLen >= 0 else {
            throw SyncError(code: .errCryptoDecryptFailed, message: "invalid STREAM AAD parameters")
        }
        var out = Data(capacity: chunkAadLen)
        out.append(prefixChunkAad)
        out.append(Data(msgIdRaw16))
        SyncCrypto.appendUInt32BE(&out, UInt32(partId))
        SyncCrypto.appendUInt32BE(&out, blockIdx)
        out.append(isFinal ? 0x01 : 0x00)
        SyncCrypto.appendUInt32BE(&out, UInt32(plaintextLen))
        return out
    }

    public static func totalBlocks(plaintextLen: Int64) -> UInt32 {
        if plaintextLen <= 0 { return 1 }
        let blocks = ((UInt64(plaintextLen) - 1) / UInt64(chunkPlaintextMax)) + 1
        return blocks > UInt64(UInt32.max) ? UInt32.max : UInt32(blocks)
    }

    public static func encryptedPartSize(plaintextLen: Int64) -> Int64 {
        if plaintextLen <= 0 { return Int64(aeadTagLen) }
        let blocks = ((UInt64(plaintextLen) - 1) / UInt64(chunkPlaintextMax)) + 1
        let overhead = blocks * UInt64(aeadTagLen)
        let maxInt64U = UInt64(Int64.max)
        if overhead > maxInt64U - UInt64(plaintextLen) { return Int64.max }
        return Int64(UInt64(plaintextLen) + overhead)
    }

    public static func transportChunkCount(encryptedSize: Int64, blocksPerChunk: Int) -> Int {
        let bpc = blocksPerChunk <= 0 ? 16 : blocksPerChunk
        if encryptedSize <= 0 { return 1 }
        let chunkCap = UInt64(bpc) * UInt64(chunkCiphertextMax)
        let chunks = ((UInt64(encryptedSize) - 1) / chunkCap) + 1
        return chunks > UInt64(Int.max) ? Int.max : Int(chunks)
    }

    public static func encryptPartData(
        _ plaintext: Data, encKey32: Data, noncePrefix7: Data, msgIdRaw16: Data, partId: Int, startBlockIdx: UInt32 = 0
    ) throws -> Data {
        let sc = try StreamCipher(encKey32: encKey32, noncePrefix7: noncePrefix7, msgIdRaw16: msgIdRaw16, partId: partId)
        let pt = Data(plaintext)
        if pt.isEmpty {
            return try sc.sealBlockAt(blockIdx: startBlockIdx, isFinal: true, plaintext: Data())
        }
        var out = Data(capacity: Int(encryptedPartSize(plaintextLen: Int64(pt.count))))
        var off = 0
        var blk = startBlockIdx
        while off < pt.count {
            let rem = pt.count - off
            let isFinal = rem <= chunkPlaintextMax
            let take = isFinal ? rem : chunkPlaintextMax
            if !isFinal && blk == UInt32.max {
                throw SyncError(code: .errManifestInvalid, message: "STREAM exceeds 2^32 block limit")
            }
            let slice = Data(pt[off..<(off + take)])
            out.append(try sc.sealBlockAt(blockIdx: blk, isFinal: isFinal, plaintext: slice))
            off += take
            if !isFinal { blk &+= 1 }
        }
        return out
    }

    public static func decryptPartData(
        _ ciphertext: Data, encKey32: Data, noncePrefix7: Data, msgIdRaw16: Data, partId: Int, startBlockIdx: UInt32 = 0
    ) throws -> Data {
        let sc = try StreamCipher(encKey32: encKey32, noncePrefix7: noncePrefix7, msgIdRaw16: msgIdRaw16, partId: partId)
        let ct = Data(ciphertext)
        guard !ct.isEmpty else {
            throw SyncError(code: .errStreamTruncated, message: "empty STREAM ciphertext")
        }
        var out = Data()
        var off = 0
        var blk = startBlockIdx
        while off < ct.count {
            let rem = ct.count - off
            let isFinal = rem <= chunkCiphertextMax
            let take = isFinal ? rem : chunkCiphertextMax
            if !isFinal && blk == UInt32.max {
                throw SyncError(code: .errManifestInvalid, message: "STREAM exceeds 2^32 block limit")
            }
            let slice = Data(ct[off..<(off + take)])
            out.append(try sc.openBlockAt(blockIdx: blk, isFinal: isFinal, ciphertextAndTag: slice))
            off += take
            if !isFinal { blk &+= 1 }
        }
        return out
    }

    /// Decrypts a transport chunk buffer with strict `ST-P0-2` `sawFinal` and `UInt32.max` guards.
    public static func decryptChunkBuffer(
        cipher: StreamCipher,
        chunkBytes: Data,
        startBlockIdx: UInt32,
        totalBlocks: UInt32,
        isLastTransportChunk: Bool,
        alreadySawFinal: Bool,
        onPlaintext: (Data) throws -> Void
    ) throws -> (blocksDone: UInt32, sawFinal: Bool) {
        let raw = Data(chunkBytes)
        guard !raw.isEmpty else {
            throw SyncError(code: .errStreamTruncated, message: "empty transport chunk")
        }
        guard !alreadySawFinal else {
            throw SyncError(code: .errStreamTruncated, message: "unexpected ciphertext after final STREAM block")
        }
        var off = 0
        var blk = startBlockIdx
        var blocksDone: UInt32 = 0
        var sawFinal = false

        while off < raw.count {
            if sawFinal {
                throw SyncError(code: .errStreamTruncated, message: "trailing bytes after final STREAM block")
            }
            if totalBlocks > 0 && blk >= totalBlocks {
                throw SyncError(code: .errManifestInvalid, message: "STREAM block count exceeded signed manifest size")
            }
            let rem = raw.count - off
            let take = min(chunkCiphertextMax, rem)
            if blk == UInt32.max && off + take < raw.count {
                throw SyncError(code: .errManifestInvalid, message: "STREAM block index overflow")
            }
            let isFinal: Bool
            if totalBlocks > 0 {
                isFinal = (blk == totalBlocks - 1)
            } else {
                isFinal = isLastTransportChunk && (off + take == raw.count)
            }
            let ctSlice = Data(raw[off..<(off + take)])
            let pt = try cipher.openBlockAt(blockIdx: blk, isFinal: isFinal, ciphertextAndTag: ctSlice)
            if !pt.isEmpty { try onPlaintext(pt) }
            if isFinal { sawFinal = true }
            off += take
            if blk < UInt32.max { blk &+= 1 }
            blocksDone &+= 1
        }
        return (blocksDone, sawFinal)
    }

    /// Minimal 4 KiB bucket Manifest padding: `uint32_be(L) || raw(L) || 0x00 * pad_len`.
    public static func padManifest4K(_ jsonBytes: Data) throws -> Data {
        let l = jsonBytes.count
        guard l > 0 && l <= manifestMaxRawBytes else {
            throw SyncError(code: .errManifestInvalid, message: "manifest length out of bounds")
        }
        let totalLen = ((4 + l + manifestPadBucket - 1) / manifestPadBucket) * manifestPadBucket
        var out = Data(capacity: totalLen)
        SyncCrypto.appendUInt32BE(&out, UInt32(l))
        out.append(Data(jsonBytes))
        if out.count < totalLen {
            out.append(Data(count: totalLen - out.count))
        }
        return out
    }

    public static func padManifest(_ jsonBytes: Data) throws -> Data { try padManifest4K(jsonBytes) }

    /// Validates exact minimal 4 KiB bucket alignment, length prefix, and constant-time all-zero tail padding.
    public static func unpadManifest4K(_ padded: Data) throws -> Data {
        let bytes = [UInt8](padded)
        guard bytes.count >= manifestPadBucket && bytes.count % manifestPadBucket == 0 else {
            throw SyncError(code: .errStreamTruncated, message: "invalid manifest 4 KiB bucket alignment")
        }
        let lU32 = (UInt32(bytes[0]) << 24) | (UInt32(bytes[1]) << 16) | (UInt32(bytes[2]) << 8) | UInt32(bytes[3])
        let l = Int(lU32)
        guard l > 0 && l <= manifestMaxRawBytes && (4 + l) <= bytes.count else {
            throw SyncError(code: .errStreamTruncated, message: "invalid manifest padded length prefix")
        }
        let expectedTotal = ((4 + l + manifestPadBucket - 1) / manifestPadBucket) * manifestPadBucket
        guard bytes.count == expectedTotal else {
            throw SyncError(code: .errStreamTruncated, message: "excess manifest 4 KiB bucket padding")
        }
        var nonZero: UInt8 = 0
        for i in (4 + l)..<bytes.count { nonZero |= bytes[i] }
        guard nonZero == 0 else {
            throw SyncError(code: .errStreamTruncated, message: "non-zero tail byte in manifest padding")
        }
        return Data(bytes[4..<(4 + l)])
    }

    public static func unpadManifest(_ padded: Data) throws -> Data { try unpadManifest4K(padded) }

    public static func sealLocalMeta(localMetaKey32: Data, aad: Data, plaintext: Data) throws -> Data {
        guard localMetaKey32.count == 32 else {
            throw SyncError(code: .errKeystoreError, message: "local_meta_key must be 32 bytes")
        }
        let iv = try SyncCrypto.randomBytes(12)
        let ct = try SyncCrypto.aesGcmSeal(key: localMetaKey32, nonce: iv, plaintext: plaintext, aad: aad)
        return iv + ct
    }

    public static func sealLocalMeta(localMetaKey32: Data, context: String, plaintext: Data) throws -> Data {
        try sealLocalMeta(localMetaKey32: localMetaKey32, aad: Data(context.utf8), plaintext: plaintext)
    }

    public static func openLocalMeta(localMetaKey32: Data, aad: Data, sealedBlob: Data) throws -> Data {
        guard localMetaKey32.count == 32 else {
            throw SyncError(code: .errKeystoreError, message: "local_meta_key must be 32 bytes")
        }
        let wire = Data(sealedBlob)
        guard wire.count >= 12 + aeadTagLen else {
            throw SyncError(code: .errCryptoDecryptFailed, message: "sealed local metadata too short")
        }
        let iv = Data(wire.prefix(12))
        let ct = Data(wire.dropFirst(12))
        return try SyncCrypto.aesGcmOpen(key: localMetaKey32, nonce: iv, ciphertextAndTag: ct, aad: aad)
    }

    public static func openLocalMeta(localMetaKey32: Data, context: String, blob: Data) throws -> Data {
        try openLocalMeta(localMetaKey32: localMetaKey32, aad: Data(context.utf8), sealedBlob: blob)
    }
}

/// O(64 KiB) constant-RAM streaming STREAM AEAD block decryptor enforcing `sawFinal` hard stop (`ST-P0-2`).
public final class RollingBlockDecryptor {
    private let cipher: StreamCipher
    private let totalBlocks: UInt32
    private let onPlaintext: (Data) throws -> Void
    private var blockAccum = Data(capacity: StreamCipher.chunkCiphertextMax)
    public private(set) var blkIdx: UInt32
    public private(set) var sawFinal: Bool = false

    public init(
        cipher: StreamCipher,
        totalBlocks: UInt32,
        initialBlockIdx: UInt32 = 0,
        onPlaintext: @escaping (Data) throws -> Void
    ) {
        self.cipher = cipher
        self.totalBlocks = totalBlocks
        self.blkIdx = initialBlockIdx
        self.onPlaintext = onPlaintext
    }

    public func ensureNotFinalBeforeChunk() throws {
        if sawFinal {
            throw SyncError(code: .errStreamTruncated, message: "extra transport chunks after final STREAM block")
        }
    }

    public func feed(_ slice: Data) throws {
        let bytes = Data(slice)
        var srcOff = 0
        while srcOff < bytes.count {
            if sawFinal {
                throw SyncError(code: .errStreamTruncated, message: "trailing bytes after final STREAM block")
            }
            if totalBlocks > 0 && blkIdx >= totalBlocks {
                throw SyncError(code: .errManifestInvalid, message: "STREAM block count exceeded signed manifest size")
            }
            let copyN = min(StreamCipher.chunkCiphertextMax - blockAccum.count, bytes.count - srcOff)
            if copyN == 0 {
                // blockAccum is full (65,552B) on totalBlocks - 1, yet additional bytes arrived
                throw SyncError(code: .errStreamTruncated, message: "trailing bytes beyond declared final STREAM block")
            }
            blockAccum.append(bytes[srcOff..<(srcOff + copyN)])
            srcOff += copyN

            if blockAccum.count == StreamCipher.chunkCiphertextMax && blkIdx + 1 < totalBlocks {
                if blkIdx == UInt32.max {
                    throw SyncError(code: .errManifestInvalid, message: "STREAM block index overflow")
                }
                let pt = try cipher.openBlockAt(blockIdx: blkIdx, isFinal: false, ciphertextAndTag: blockAccum)
                if !pt.isEmpty { try onPlaintext(pt) }
                blkIdx &+= 1
                blockAccum.removeAll(keepingCapacity: true)
            }
        }
    }

    public func finishTransportChunk() throws {
        if !blockAccum.isEmpty {
            guard totalBlocks > 0 && blkIdx == totalBlocks - 1 else {
                throw SyncError(code: .errStreamTruncated, message: "truncated non-final transport chunk")
            }
            let pt = try cipher.openBlockAt(blockIdx: blkIdx, isFinal: true, ciphertextAndTag: blockAccum)
            if !pt.isEmpty { try onPlaintext(pt) }
            if blkIdx < UInt32.max { blkIdx &+= 1 }
            blockAccum.removeAll(keepingCapacity: true)
            sawFinal = true
        }
    }
}
