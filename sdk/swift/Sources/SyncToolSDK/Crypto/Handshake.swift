import Foundation

/// Derived session keys, confirmation MACs, and optional 6-digit SAS for Flow 1A/1B (`CRYPTO_AND_AUTH.md` §4).
public struct HandshakeResult: Sendable, Equatable {
    public let th: Data
    public let prk: Data
    public let sessionKey: Data
    public let confirmKeyA: Data
    public let confirmKeyB: Data
    public let macA: Data
    public let macB: Data
    public let sasBytes: Data
    public let sasInt: Int
    public let sasStr: String?

    public var sasCode: String { sasStr ?? "" }
}

public typealias HandshakeKeys = HandshakeResult

/// Flow 1A (`mode=1`), Flow 1B (`mode=2`), `oneshot` `part0` HKDF, `pipe_ctrl` (`57B` AAD), and `PairBind` AEAD.
public enum SyncHandshake {
    public static let protoVersion: Int = 1

    public static let modeDirect: Int = 0
    public static let modeQrOob: Int = 1
    public static let modeCommitSas: Int = 2

    public static let purposeDirect: String = "direct"
    public static let purposeOneshot: String = "oneshot"
    public static let purposePair: String = "pair"

    public static let purposeCodeOneshot: UInt8 = 0x01
    public static let purposeCodePair: UInt8 = 0x02

    public static let oobSecretSize: Int = 16
    public static let hsNonceSize: Int = 32

    private static let prefixHsQr = Data("synctool-v1/hs-qr".utf8)
    private static let prefixCommit = Data("synctool-v1/commit".utf8)
    private static let prefixHsSas = Data("synctool-v1/hs-sas".utf8)
    private static let infoSessionKey = Data("synctool-v1/session-key".utf8)
    private static let infoConfirmA = Data("synctool-v1/confirm-a".utf8)
    private static let infoConfirmB = Data("synctool-v1/confirm-b".utf8)
    private static let infoSas = Data("synctool-v1/sas".utf8)
    private static let infoOneshotPart0Key = Data("synctool-v1/oneshot-part0-key".utf8)
    private static let infoOneshotPart0Np = Data("synctool-v1/oneshot-part0-np".utf8)
    private static let infoPipeCtrlKey = Data("synctool-v1/pipe-ctrl-key".utf8)
    private static let infoPipeCtrlNp = Data("synctool-v1/pipe-ctrl-np".utf8)
    private static let prefixPipeCtrlAad = Data("synctool-v1/pipe-ctrl".utf8)
    private static let infoPairNonceA = Data("synctool-v1/pair-nonce-a".utf8)
    private static let infoPairNonceB = Data("synctool-v1/pair-nonce-b".utf8)
    private static let prefixPairBindA = Data("synctool-v1/pair-bind/a".utf8)
    private static let prefixPairBindB = Data("synctool-v1/pair-bind/b".utf8)

    public static func purposeCode(_ purpose: String) throws -> UInt8 {
        switch purpose {
        case purposeOneshot: return purposeCodeOneshot
        case purposePair: return purposeCodePair
        default:
            throw SyncError(code: .errCryptoHandshakeFailed, message: "invalid handshake purpose")
        }
    }

    /// Exact 154-byte ordered `transcript_1` for Flow 1A (`mode=1`, `qr_oob_x25519`).
    public static func buildQrTranscript(
        purpose: String,
        roomId: String,
        eAPub: Data,
        nA: Data,
        eBPub: Data,
        nB: Data
    ) throws -> Data {
        let pCode = try purposeCode(purpose)
        guard Crockford.isCanonicalRoomId(roomId) else {
            throw SyncError(code: .errUriInvalid, message: "non-canonical room_id in transcript")
        }
        guard eAPub.count == 32 && nA.count == hsNonceSize && eBPub.count == 32 && nB.count == hsNonceSize else {
            throw SyncError(code: .errCryptoHandshakeFailed, message: "invalid Flow 1A transcript input lengths")
        }
        var out = Data(capacity: 154)
        out.append(prefixHsQr)
        out.append(pCode)
        out.append(Data(roomId.utf8))
        out.append(Data(eAPub))
        out.append(Data(nA))
        out.append(Data(eBPub))
        out.append(Data(nB))
        return out
    }

    public static func deriveQrOobSession(
        purpose: String,
        roomId: String,
        localPriv32: Data,
        remotePub32: Data,
        eAPub: Data,
        nA: Data,
        eBPub: Data,
        nB: Data,
        oobSecret: Data
    ) throws -> HandshakeResult {
        guard oobSecret.count == oobSecretSize else {
            throw SyncError(code: .errCryptoHandshakeFailed, message: "oob_secret must be 16 bytes")
        }
        let shared = try SyncCrypto.x25519DiffieHellman(sk32: localPriv32, peerPk32: remotePub32)
        return try deriveMode1SessionKeys(
            shared32: shared,
            oobSecret16: oobSecret,
            purpose: purpose,
            roomId: roomId,
            eAPub: eAPub,
            nA: nA,
            eBPub: eBPub,
            nB: nB
        )
    }

    public static func deriveMode1SessionKeys(
        shared32: Data,
        oobSecret16: Data,
        purpose: String,
        roomId: String,
        eAPub: Data,
        nA: Data,
        eBPub: Data,
        nB: Data
    ) throws -> HandshakeResult {
        guard shared32.count == 32 && oobSecret16.count == oobSecretSize else {
            throw SyncError(code: .errCryptoHandshakeFailed, message: "invalid shared secret or oob_secret length")
        }
        let transcript = try buildQrTranscript(
            purpose: purpose, roomId: roomId, eAPub: eAPub, nA: nA, eBPub: eBPub, nB: nB
        )
        let th = SyncCrypto.sha256(transcript)
        var ikm = Data(capacity: 48)
        ikm.append(Data(shared32))
        ikm.append(Data(oobSecret16))
        let prk = SyncCrypto.hkdfExtract(salt: th, ikm: ikm)
        return try buildSessionAndConfirm(th: th, prk: prk, withSas: false)
    }

    /// Exact 91-byte input -> 32-byte SHA-256 commitment for Flow 1B (`mode=2`).
    public static func computeCommitA(
        purpose: String,
        roomId: String,
        eAPub: Data,
        nA: Data
    ) throws -> Data {
        let pCode = try purposeCode(purpose)
        guard Crockford.isCanonicalRoomId(roomId) else {
            throw SyncError(code: .errUriInvalid, message: "non-canonical room_id in commit_a")
        }
        guard eAPub.count == 32 && nA.count == hsNonceSize else {
            throw SyncError(code: .errCryptoHandshakeFailed, message: "invalid commit_a input lengths")
        }
        var buf = Data(capacity: 91)
        buf.append(prefixCommit)
        buf.append(pCode)
        buf.append(Data(roomId.utf8))
        buf.append(Data(eAPub))
        buf.append(Data(nA))
        return SyncCrypto.sha256(buf)
    }

    public static func verifyCommitA(
        purpose: String,
        roomId: String,
        eAPub: Data,
        nA: Data,
        commitA: Data
    ) throws {
        guard commitA.count == 32 else {
            throw SyncError(code: .errSasMismatch, message: "commit_a must be 32 bytes")
        }
        let expected = try computeCommitA(purpose: purpose, roomId: roomId, eAPub: eAPub, nA: nA)
        guard SyncCrypto.constantTimeEquals(expected, commitA) else {
            throw SyncError(code: .errSasMismatch, message: "handshake commit_a verification failed")
        }
    }

    /// Exact 187-byte ordered `transcript_2` for Flow 1B (`mode=2`, `commit_sas_x25519`).
    public static func buildSasTranscript(
        purpose: String,
        roomId: String,
        commitA: Data,
        eAPub: Data,
        nA: Data,
        eBPub: Data,
        nB: Data
    ) throws -> Data {
        let pCode = try purposeCode(purpose)
        guard Crockford.isCanonicalRoomId(roomId) else {
            throw SyncError(code: .errUriInvalid, message: "non-canonical room_id in transcript_2")
        }
        guard commitA.count == 32 && eAPub.count == 32 && nA.count == hsNonceSize &&
              eBPub.count == 32 && nB.count == hsNonceSize else {
            throw SyncError(code: .errCryptoHandshakeFailed, message: "invalid Flow 1B transcript input lengths")
        }
        var out = Data(capacity: 187)
        out.append(prefixHsSas)
        out.append(pCode)
        out.append(Data(roomId.utf8))
        out.append(Data(commitA))
        out.append(Data(eAPub))
        out.append(Data(nA))
        out.append(Data(eBPub))
        out.append(Data(nB))
        return out
    }

    public static func deriveSasSession(
        purpose: String,
        roomId: String,
        localPriv32: Data,
        remotePub32: Data,
        commitA: Data,
        eAPub: Data,
        nA: Data,
        eBPub: Data,
        nB: Data
    ) throws -> HandshakeResult {
        try verifyCommitA(purpose: purpose, roomId: roomId, eAPub: eAPub, nA: nA, commitA: commitA)
        let shared = try SyncCrypto.x25519DiffieHellman(sk32: localPriv32, peerPk32: remotePub32)
        return try deriveMode2SessionKeys(
            shared32: shared,
            purpose: purpose,
            roomId: roomId,
            commitA: commitA,
            eAPub: eAPub,
            nA: nA,
            eBPub: eBPub,
            nB: nB
        )
    }

    public static func deriveMode2SessionKeys(
        shared32: Data,
        purpose: String,
        roomId: String,
        commitA: Data,
        eAPub: Data,
        nA: Data,
        eBPub: Data,
        nB: Data
    ) throws -> HandshakeResult {
        try verifyCommitA(purpose: purpose, roomId: roomId, eAPub: eAPub, nA: nA, commitA: commitA)
        guard shared32.count == 32 else {
            throw SyncError(code: .errCryptoHandshakeFailed, message: "shared secret must be 32 bytes")
        }
        let transcript = try buildSasTranscript(
            purpose: purpose, roomId: roomId, commitA: commitA, eAPub: eAPub, nA: nA, eBPub: eBPub, nB: nB
        )
        let th = SyncCrypto.sha256(transcript)
        let prk = SyncCrypto.hkdfExtract(salt: th, ikm: shared32)
        return try buildSessionAndConfirm(th: th, prk: prk, withSas: true)
    }

    private static func buildSessionAndConfirm(th: Data, prk: Data, withSas: Bool) throws -> HandshakeResult {
        let sessionKey = try SyncCrypto.hkdfExpand(prk: prk, info: infoSessionKey, length: 32)
        let confirmKeyA = try SyncCrypto.hkdfExpand(prk: prk, info: infoConfirmA, length: 32)
        let confirmKeyB = try SyncCrypto.hkdfExpand(prk: prk, info: infoConfirmB, length: 32)
        let macA = SyncCrypto.hmacSha256(key: confirmKeyA, th)
        let macB = SyncCrypto.hmacSha256(key: confirmKeyB, th)
        guard withSas else {
            return HandshakeResult(
                th: th, prk: prk, sessionKey: sessionKey,
                confirmKeyA: confirmKeyA, confirmKeyB: confirmKeyB,
                macA: macA, macB: macB,
                sasBytes: Data(count: 4), sasInt: 0, sasStr: nil
            )
        }
        let sasBytes = try SyncCrypto.hkdfExpand(prk: prk, info: infoSas, length: 4)
        let b = [UInt8](sasBytes)
        let u32 = (UInt32(b[0]) << 24) | (UInt32(b[1]) << 16) | (UInt32(b[2]) << 8) | UInt32(b[3])
        let sasInt = Int(u32 % 1_000_000)
        return HandshakeResult(
            th: th, prk: prk, sessionKey: sessionKey,
            confirmKeyA: confirmKeyA, confirmKeyB: confirmKeyB,
            macA: macA, macB: macB,
            sasBytes: sasBytes, sasInt: sasInt, sasStr: pad6Digits(sasInt)
        )
    }

    private static func pad6Digits(_ value: Int) -> String {
        var v = value % 1_000_000
        var digits = [UInt8](repeating: 0x30, count: 6)
        for i in stride(from: 5, through: 0, by: -1) {
            digits[i] = UInt8(0x30 + (v % 10))
            v /= 10
        }
        return String(decoding: digits, as: UTF8.self)
    }

    public static func verifyMac(expected32: Data, got: Data) throws {
        guard expected32.count == 32 && SyncCrypto.constantTimeEquals(expected32, got) else {
            throw SyncError(code: .errSasMismatch, message: "handshake key confirmation MAC mismatch")
        }
    }

    public static func verifySas(expected6Digits: String, entered: String) throws {
        var clean = [UInt8]()
        clean.reserveCapacity(6)
        for scalar in entered.unicodeScalars {
            let v = scalar.value
            if v == 0x20 || v == 0x2D || v == 0x09 || v == 0x0D || v == 0x0A { continue }
            guard v >= 0x30 && v <= 0x39 && clean.count < 6 else {
                throw SyncError(code: .errSasMismatch, message: "invalid SAS digits")
            }
            clean.append(UInt8(v))
        }
        guard clean.count == 6 && expected6Digits.utf8.count == 6 &&
              SyncCrypto.constantTimeEquals(Data(expected6Digits.utf8), Data(clean)) else {
            throw SyncError(code: .errSasMismatch, message: "SAS verification mismatch")
        }
    }

    public static func deriveOneshotPart0Keys(sessionKey32: Data, msgId16: Data) throws -> (part0Key: Data, part0NoncePrefix: Data) {
        guard sessionKey32.count == 32 && msgId16.count == SyncCrypto.msgIdRawSize else {
            throw SyncError(code: .errCryptoHandshakeFailed, message: "invalid oneshot part0 HKDF inputs")
        }
        let prk = SyncCrypto.hkdfExtract(salt: msgId16, ikm: sessionKey32)
        let p0Key = try SyncCrypto.hkdfExpand(prk: prk, info: infoOneshotPart0Key, length: 32)
        let p0Np = try SyncCrypto.hkdfExpand(prk: prk, info: infoOneshotPart0Np, length: 7)
        return (p0Key, p0Np)
    }

    public static func derivePipeCtrlKeys(th32: Data, sessionKey32: Data) throws -> (ctrlKey: Data, ctrlNp: Data) {
        guard th32.count == 32 && sessionKey32.count == 32 else {
            throw SyncError(code: .errCryptoHandshakeFailed, message: "invalid pipe_ctrl HKDF inputs")
        }
        let prk = SyncCrypto.hkdfExtract(salt: th32, ikm: sessionKey32)
        let ctrlKey = try SyncCrypto.hkdfExpand(prk: prk, info: infoPipeCtrlKey, length: 32)
        let ctrlNp = try SyncCrypto.hkdfExpand(prk: prk, info: infoPipeCtrlNp, length: 7)
        return (ctrlKey, ctrlNp)
    }

    public static func validatePipeCtrlSeq(ctrlSeq: Int64, fromInitiator: Bool, lastSeenSeq: Int64) throws {
        guard ctrlSeq >= 0 && ctrlSeq <= 0xffff_ffff else {
            throw SyncError(code: .errCryptoHandshakeFailed, message: "pipe_ctrl seq out of uint32 range")
        }
        let wantParity: Int64 = fromInitiator ? 0 : 1
        guard (ctrlSeq & 1) == wantParity && ctrlSeq > lastSeenSeq else {
            throw SyncError(code: .errCryptoHandshakeFailed, message: "invalid pipe_ctrl seq parity or monotonicity")
        }
    }

    /// Exact 57-byte AAD: `"synctool-v1/pipe-ctrl"(21B) || th(32B) || uint32_be(ctrl_seq)(4B)`.
    public static func buildPipeCtrlAad(th32: Data, ctrlSeq: UInt32) throws -> Data {
        guard th32.count == 32 else {
            throw SyncError(code: .errCryptoHandshakeFailed, message: "th must be 32 bytes")
        }
        var aad = Data(capacity: 57)
        aad.append(prefixPipeCtrlAad)
        aad.append(Data(th32))
        SyncCrypto.appendUInt32BE(&aad, ctrlSeq)
        return aad
    }

    public static func sealPipeCtrl(
        ctrlKey32: Data, ctrlNp7: Data, th32: Data, ctrlSeq: UInt32, plaintext: Data
    ) throws -> Data {
        guard ctrlKey32.count == 32 && ctrlNp7.count == 7 else {
            throw SyncError(code: .errCryptoHandshakeFailed, message: "invalid pipe_ctrl key/np length")
        }
        let aad = try buildPipeCtrlAad(th32: th32, ctrlSeq: ctrlSeq)
        var nonce = Data(capacity: 12)
        nonce.append(Data(ctrlNp7))
        SyncCrypto.appendUInt32BE(&nonce, ctrlSeq)
        nonce.append(0x00)
        return try SyncCrypto.aesGcmSeal(key: ctrlKey32, nonce: nonce, plaintext: plaintext, aad: aad)
    }

    public static func openPipeCtrl(
        ctrlKey32: Data, ctrlNp7: Data, th32: Data, ctrlSeq: UInt32, ciphertext: Data
    ) throws -> Data {
        guard ctrlKey32.count == 32 && ctrlNp7.count == 7 else {
            throw SyncError(code: .errCryptoDecryptFailed, message: "invalid pipe_ctrl key/np length")
        }
        let aad = try buildPipeCtrlAad(th32: th32, ctrlSeq: ctrlSeq)
        var nonce = Data(capacity: 12)
        nonce.append(Data(ctrlNp7))
        SyncCrypto.appendUInt32BE(&nonce, ctrlSeq)
        nonce.append(0x00)
        return try SyncCrypto.aesGcmOpen(key: ctrlKey32, nonce: nonce, ciphertextAndTag: ciphertext, aad: aad)
    }

    public static func openPipeCtrlVerified(
        ctrlKey32: Data, ctrlNp7: Data, th32: Data, ctrlSeq: Int64, fromInitiator: Bool, lastSeenSeq: Int64, ciphertext: Data
    ) throws -> Data {
        try validatePipeCtrlSeq(ctrlSeq: ctrlSeq, fromInitiator: fromInitiator, lastSeenSeq: lastSeenSeq)
        return try openPipeCtrl(ctrlKey32: ctrlKey32, ctrlNp7: ctrlNp7, th32: th32, ctrlSeq: UInt32(ctrlSeq), ciphertext: ciphertext)
    }

    public static func derivePairBindNonces(prk32: Data) throws -> (nonceA: Data, nonceB: Data) {
        guard prk32.count == 32 else {
            throw SyncError(code: .errCryptoHandshakeFailed, message: "prk must be 32 bytes")
        }
        let na = try SyncCrypto.hkdfExpand(prk: prk32, info: infoPairNonceA, length: 12)
        let nb = try SyncCrypto.hkdfExpand(prk: prk32, info: infoPairNonceB, length: 12)
        return (na, nb)
    }

    public static func sealPairBind(
        sessionKey32: Data, prk32: Data, th32: Data, isInitiator: Bool, plaintext: Data
    ) throws -> Data {
        guard sessionKey32.count == 32 && th32.count == 32 else {
            throw SyncError(code: .errCryptoHandshakeFailed, message: "invalid PairBind key/th length")
        }
        let (na, nb) = try derivePairBindNonces(prk32: prk32)
        let nonce = isInitiator ? na : nb
        let aad = (isInitiator ? prefixPairBindA : prefixPairBindB) + Data(th32)
        return try SyncCrypto.aesGcmSeal(key: sessionKey32, nonce: nonce, plaintext: plaintext, aad: aad)
    }

    public static func openPairBind(
        sessionKey32: Data, prk32: Data, th32: Data, fromInitiator: Bool, ciphertext: Data
    ) throws -> Data {
        guard sessionKey32.count == 32 && th32.count == 32 else {
            throw SyncError(code: .errCryptoDecryptFailed, message: "invalid PairBind key/th length")
        }
        let (na, nb) = try derivePairBindNonces(prk32: prk32)
        let nonce = fromInitiator ? na : nb
        let aad = (fromInitiator ? prefixPairBindA : prefixPairBindB) + Data(th32)
        return try SyncCrypto.aesGcmOpen(key: sessionKey32, nonce: nonce, ciphertextAndTag: ciphertext, aad: aad)
    }
}
