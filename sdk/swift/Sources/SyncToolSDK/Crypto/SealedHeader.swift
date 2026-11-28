import Foundation

/// Output of sealing a 208-byte 0-RTT `SealedHeader` (`CRYPTO_AND_AUTH.md` §5.2).
public struct SealedHeaderSealOutput: Sendable, Equatable {
    public let sealedHeader: Data
    public let msgIdRaw: Data
    public let part0Key: Data
    public let part0NoncePrefix: Data
}

/// Verified & decrypted result of opening a 208-byte 0-RTT `SealedHeader` (`CRYPTO_AND_AUTH.md` §5.3).
public struct OpenedSealedHeader: Sendable, Equatable {
    public let msgIdRaw: Data
    public let msgId: String
    public let ephemeralPk: Data
    public let senderDeviceIdRaw: Data
    public let senderDeviceId: String
    public let recipientIdRaw: Data
    public let recipientDeviceId: String
    public let createdAt: Int64
    public let manifestSha256: Data
    public let senderSig: Data
    public let part0Key: Data
    public let part0NoncePrefix: Data
}

public typealias SealedHeaderOpenResult = OpenedSealedHeader

/// Flow 2 208-byte `SealedHeader` (`"ST01"` 56B `clear_header` + 152B `sealed_box`), 149B `0rtt-sig`, and `direct_ack` MAC.
public enum SyncSealedHeader {
    public static let sealedHeaderSize: Int = 208
    public static let clearHeaderSize: Int = 56
    public static let sealedBoxPlaintextSize: Int = 136
    public static let sealedBoxSize: Int = 152
    public static let zeroRttSigInputSize: Int = 149

    private static let sealedHeaderMagic: [UInt8] = [0x53, 0x54, 0x30, 0x31] // "ST01"
    private static let sealedMode0Rtt: UInt8 = 0x02

    private static let info0RttHdrKey = Data("synctool-v1/0rtt-hdr-key".utf8)
    private static let info0RttHdrNonce = Data("synctool-v1/0rtt-hdr-nonce".utf8)
    private static let info0RttPart0Key = Data("synctool-v1/0rtt-part0-key".utf8)
    private static let info0RttPart0Np = Data("synctool-v1/0rtt-part0-np".utf8)
    private static let prefix0RttSig = Data("synctool-v1/0rtt-sig\n".utf8)
    private static let prefixDirectAck = Data("synctool-v1/direct-ack".utf8)

    /// Exact 149-byte Ed25519 signing input (`CRYPTO_AND_AUTH.md` §5.2).
    public static func buildZeroRttSigInput(
        clearHeader56: Data,
        senderIdRaw16: Data,
        recipientIdRaw16: Data,
        createdAt: Int64,
        manifestSha256: Data
    ) throws -> Data {
        guard clearHeader56.count == clearHeaderSize else {
            throw SyncError(code: .errCryptoSignatureInvalid, message: "clear_header must be 56 bytes")
        }
        guard senderIdRaw16.count == 16 && recipientIdRaw16.count == 16 && manifestSha256.count == 32 && createdAt >= 0 else {
            throw SyncError(code: .errCryptoSignatureInvalid, message: "invalid 0rtt-sig input parameters")
        }
        var out = Data(capacity: zeroRttSigInputSize)
        out.append(prefix0RttSig)
        out.append(Data(clearHeader56))
        out.append(Data(senderIdRaw16))
        out.append(Data(recipientIdRaw16))
        SyncCrypto.appendUInt64BE(&out, UInt64(createdAt))
        out.append(Data(manifestSha256))
        return out
    }

    public static func seal0RttHeader(
        senderKeys: DeviceKeys,
        recipientIdRaw16: Data,
        recipientKemPub32: Data,
        createdAt: Int64,
        manifestSha256: Data
    ) throws -> SealedHeaderSealOutput {
        let msgIdRaw = try SyncCrypto.randomBytes(16)
        let (ephSk, _) = try SyncCrypto.x25519Generate()
        return try seal0RttHeaderDeterministic(
            senderKeys: senderKeys,
            ephemeralSk32: ephSk,
            msgIdRaw16: msgIdRaw,
            recipientIdRaw16: recipientIdRaw16,
            recipientKemPub32: recipientKemPub32,
            createdAt: createdAt,
            manifestSha256: manifestSha256
        )
    }

    /// Deterministic 0-RTT header sealer; `testFixedSenderSig` allows byte-exact verification against `05_paired_0rtt_envelope.json`
    /// despite Apple `CryptoKit`'s randomized Ed25519 signing nonce.
    public static func seal0RttHeaderDeterministic(
        senderKeys: DeviceKeys,
        ephemeralSk32: Data,
        msgIdRaw16: Data,
        recipientIdRaw16: Data,
        recipientKemPub32: Data,
        createdAt: Int64,
        manifestSha256: Data,
        testFixedSenderSig: Data? = nil
    ) throws -> SealedHeaderSealOutput {
        guard ephemeralSk32.count == 32 && msgIdRaw16.count == 16 && recipientIdRaw16.count == 16 &&
              recipientKemPub32.count == 32 && manifestSha256.count == 32 && createdAt >= 0 else {
            throw SyncError(code: .errCryptoHandshakeFailed, message: "invalid 0-RTT seal parameters")
        }
        let ephPk = try SyncCrypto.x25519PublicKeyFromPrivate(ephemeralSk32)
        var clearHdr = Data(capacity: clearHeaderSize)
        clearHdr.append(contentsOf: sealedHeaderMagic)
        clearHdr.append(sealedMode0Rtt)
        clearHdr.append(contentsOf: [0x00, 0x00, 0x00])
        clearHdr.append(Data(msgIdRaw16))
        clearHdr.append(ephPk)

        let dh = try SyncCrypto.x25519DiffieHellman(sk32: ephemeralSk32, peerPk32: recipientKemPub32)
        let keys = try derive0RttKeys(clearHdr: clearHdr, dh: dh)

        let sigInput = try buildZeroRttSigInput(
            clearHeader56: clearHdr,
            senderIdRaw16: senderKeys.deviceIdRaw,
            recipientIdRaw16: recipientIdRaw16,
            createdAt: createdAt,
            manifestSha256: manifestSha256
        )
        let senderSig: Data
        if let fixed = testFixedSenderSig {
            guard fixed.count == 64 else {
                throw SyncError(code: .errCryptoSignatureInvalid, message: "testFixedSenderSig must be 64 bytes")
            }
            senderSig = Data(fixed)
        } else {
            senderSig = try senderKeys.sign(sigInput)
        }

        var boxPt = Data(capacity: sealedBoxPlaintextSize)
        boxPt.append(senderKeys.deviceIdRaw)
        boxPt.append(Data(recipientIdRaw16))
        SyncCrypto.appendUInt64BE(&boxPt, UInt64(createdAt))
        boxPt.append(Data(manifestSha256))
        boxPt.append(senderSig)

        let sealedBox = try SyncCrypto.aesGcmSeal(key: keys.hdrKey, nonce: keys.hdrNonce, plaintext: boxPt, aad: clearHdr)
        var sealedHdr = Data(capacity: sealedHeaderSize)
        sealedHdr.append(clearHdr)
        sealedHdr.append(sealedBox)

        return SealedHeaderSealOutput(
            sealedHeader: sealedHdr,
            msgIdRaw: Data(msgIdRaw16),
            part0Key: keys.part0Key,
            part0NoncePrefix: keys.part0Np
        )
    }

    public static func parseClearHeaderMsgId(_ sealedHeader: Data) throws -> (raw: Data, hex: String) {
        let bytes = [UInt8](sealedHeader)
        guard bytes.count == sealedHeaderSize,
              bytes[0] == sealedHeaderMagic[0],
              bytes[1] == sealedHeaderMagic[1],
              bytes[2] == sealedHeaderMagic[2],
              bytes[3] == sealedHeaderMagic[3],
              bytes[4] == sealedMode0Rtt,
              bytes[5] == 0x00,
              bytes[6] == 0x00,
              bytes[7] == 0x00 else {
            throw SyncError(code: .errCryptoSignatureInvalid, message: "invalid 208-byte SealedHeader")
        }
        let raw = Data(bytes[8..<24])
        return (raw, SyncCrypto.hexEncode(raw))
    }

    public static func open0RttHeader(
        recipientKeys: DeviceKeys,
        sealedHeader: Data,
        lookupSenderSignPk: (String) throws -> Data?
    ) throws -> OpenedSealedHeader {
        let (msgIdRaw, msgIdHex) = try parseClearHeaderMsgId(sealedHeader)
        let bytes = [UInt8](sealedHeader)
        let clearHdr = Data(bytes[0..<clearHeaderSize])
        let sealedBox = Data(bytes[clearHeaderSize..<sealedHeaderSize])
        let ephPub = Data(bytes[24..<56])

        let dh = try SyncCrypto.x25519DiffieHellman(sk32: recipientKeys.kemSk, peerPk32: ephPub)
        let keys = try derive0RttKeys(clearHdr: clearHdr, dh: dh)

        let boxPt = try SyncCrypto.aesGcmOpen(
            key: keys.hdrKey, nonce: keys.hdrNonce, ciphertextAndTag: sealedBox, aad: clearHdr
        )
        let ptBytes = [UInt8](boxPt)
        guard ptBytes.count == sealedBoxPlaintextSize else {
            throw SyncError(code: .errCryptoSignatureInvalid, message: "invalid sealed_box plaintext length")
        }

        let senderIdRaw = Data(ptBytes[0..<16])
        let recipIdRaw = Data(ptBytes[16..<32])
        var rawCreatedAt: UInt64 = 0
        for i in 32..<40 {
            rawCreatedAt = (rawCreatedAt << 8) | UInt64(ptBytes[i])
        }
        guard rawCreatedAt <= UInt64(Int64.max) else {
            throw SyncError(code: .errCryptoSignatureInvalid, message: "created_at overflow (> Int64.max)")
        }
        let createdAt = Int64(rawCreatedAt)
        let manifestSha = Data(ptBytes[40..<72])
        let senderSig = Data(ptBytes[72..<136])

        guard SyncCrypto.constantTimeEquals(recipIdRaw, recipientKeys.deviceIdRaw) else {
            throw SyncError(code: .errCryptoSignatureInvalid, message: "sealed header recipient_device_id mismatch")
        }

        let senderIdHex = SyncCrypto.hexEncode(senderIdRaw)
        guard let senderSignPk = try lookupSenderSignPk(senderIdHex), senderSignPk.count == 32 else {
            throw SyncError(code: .errDeviceUntrusted, message: "sealed header sender_device_id not trusted")
        }

        // Defense-in-depth: verify sender_device_id matches senderSignPk derivation
        let (_, derivedSenderId) = try SyncCrypto.deriveDeviceId(senderSignPk)
        guard SyncCrypto.constantTimeEquals(Data(senderIdHex.utf8), Data(derivedSenderId.utf8)) else {
            throw SyncError(code: .errCryptoSignatureInvalid, message: "sender_device_id does not match sender sign_pk")
        }

        let sigInput = try buildZeroRttSigInput(
            clearHeader56: clearHdr,
            senderIdRaw16: senderIdRaw,
            recipientIdRaw16: recipIdRaw,
            createdAt: createdAt,
            manifestSha256: manifestSha
        )
        guard SyncCrypto.ed25519VerifyStrict(publicKey: senderSignPk, message: sigInput, signature: senderSig) else {
            throw SyncError(code: .errCryptoSignatureInvalid, message: "invalid 0-RTT sender Ed25519 signature")
        }

        return OpenedSealedHeader(
            msgIdRaw: msgIdRaw,
            msgId: msgIdHex,
            ephemeralPk: ephPub,
            senderDeviceIdRaw: senderIdRaw,
            senderDeviceId: senderIdHex,
            recipientIdRaw: recipIdRaw,
            recipientDeviceId: SyncCrypto.hexEncode(recipIdRaw),
            createdAt: createdAt,
            manifestSha256: manifestSha,
            senderSig: senderSig,
            part0Key: keys.part0Key,
            part0NoncePrefix: keys.part0Np
        )
    }

    private struct Derived0RttKeys {
        let hdrKey: Data
        let hdrNonce: Data
        let part0Key: Data
        let part0Np: Data
    }

    private static func derive0RttKeys(clearHdr: Data, dh: Data) throws -> Derived0RttKeys {
        let prk = SyncCrypto.hkdfExtract(salt: clearHdr, ikm: dh)
        return Derived0RttKeys(
            hdrKey: try SyncCrypto.hkdfExpand(prk: prk, info: info0RttHdrKey, length: 32),
            hdrNonce: try SyncCrypto.hkdfExpand(prk: prk, info: info0RttHdrNonce, length: 12),
            part0Key: try SyncCrypto.hkdfExpand(prk: prk, info: info0RttPart0Key, length: 32),
            part0Np: try SyncCrypto.hkdfExpand(prk: prk, info: info0RttPart0Np, length: 7)
        )
    }

    public static func computeDirectAckMac(part0Key32: Data, msgIdRaw16: Data) throws -> Data {
        guard part0Key32.count == 32 && msgIdRaw16.count == 16 else {
            throw SyncError(code: .errCryptoSignatureInvalid, message: "invalid direct_ack key or msg_id length")
        }
        return SyncCrypto.hmacSha256(key: part0Key32, prefixDirectAck, Data(msgIdRaw16))
    }

    public static func verifyDirectAckMac(part0Key32: Data, msgIdRaw16: Data, gotMac: Data) throws {
        let expected = try computeDirectAckMac(part0Key32: part0Key32, msgIdRaw16: msgIdRaw16)
        guard SyncCrypto.constantTimeEquals(expected, gotMac) else {
            throw SyncError(code: .errCryptoSignatureInvalid, message: "direct pipe_ack MAC verification failed")
        }
    }
}
