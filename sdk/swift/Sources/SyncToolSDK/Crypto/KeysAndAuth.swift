import CryptoKit
import Darwin
import Foundation
import Security

/// Per-relay blinded mailbox Ed25519 ownership keys (`CRYPTO_AND_AUTH.md` §3.2–§3.3).
public struct MailboxKeys: Sendable, Equatable {
    public let relayId: String
    public let authSeed: Data
    public let authPk: Data
    public let mailboxId: String

    public init(relayId: String, authSeed: Data, authPk: Data, mailboxId: String) {
        self.relayId = relayId; self.authSeed = Data(authSeed)
        self.authPk = Data(authPk); self.mailboxId = mailboxId
    }

    public func sign(_ message: Data) throws -> Data {
        try SyncCrypto.ed25519Sign(seed32: authSeed, message: message)
    }
}

/// Domain-separated device key hierarchy derived from a single 32B `device_master_seed` (`CRYPTO_AND_AUTH.md` §3).
public struct DeviceKeys: Sendable, Equatable {
    public let masterSeed: Data
    public let masterPrk: Data
    public let sigSeed: Data
    public let sigPk: Data
    /// Raw unclamped 32-byte HKDF output (`kem_sk_hex` in `01_seed_and_keys.json`).
    public let kemSk: Data
    public let kemPk: Data
    public let localMetaKey: Data
    public let deviceIdRaw: Data
    /// 32-char lowercase hex of `SHA256("synctool-v1/device-id:" || sigPk)[0..<16]`.
    public let deviceId: String

    public var signSeed: Data { sigSeed }
    public var signPk: Data { sigPk }

    public static func fromMasterSeed(_ seed32: Data) throws -> DeviceKeys {
        try SyncCrypto.deriveDeviceKeys(seed32)
    }

    public static func generate() throws -> DeviceKeys {
        try fromMasterSeed(SyncCrypto.generateMasterSeed())
    }

    public func sign(_ message: Data) throws -> Data {
        try SyncCrypto.ed25519Sign(seed32: sigSeed, message: message)
    }

    public func deriveMailboxKeys(relayId: String) throws -> MailboxKeys {
        try SyncCrypto.deriveMailboxKeys(masterPrk: masterPrk, relayId: relayId)
    }
}

/// Core `synctool-v1` cryptographic primitives, strict Curve25519 wrappers, and request auth.
public enum SyncCrypto {
    public static let masterSeedSize = 32
    public static let deviceIdRawSize = 16
    public static let msgIdRawSize = 16

    public static let headerRelayTs = "X-Sync-TS"
    public static let headerRelayNonce = "X-Sync-Nonce"
    public static let headerRelaySig = "X-Sync-Sig"
    public static let headerRoomToken = "X-Sync-Room-Token"
    public static let headerMailboxSig = "X-Sync-Mailbox-Sig"
    public static let headerDepositToken = "X-Sync-Deposit-Token"
    public static let headerUploadToken = "X-Sync-Upload-Token"
    public static let headerClientAgent = "X-Sync-Client"

    private static let masterSeedSalt = Data("synctool-v1/master-seed-salt".utf8)
    private static let infoEd25519Sign = Data("synctool-v1/ed25519-sign".utf8)
    private static let infoX25519Kem = Data("synctool-v1/x25519-kem".utf8)
    private static let infoMailboxAuthPfx = "synctool-v1/mailbox-auth/"
    private static let infoLocalMetaKey = Data("synctool-v1/local-storage-key".utf8)

    private static let prefixRelayId = Data("synctool-v1/relay-id:".utf8)
    private static let prefixDeviceId = Data("synctool-v1/device-id:".utf8)
    private static let prefixMailboxId = Data("synctool-v1/mailbox-id:".utf8)
    private static let prefixDeviceCard = Data("synctool-v1/device-card\n".utf8)
    private static let prefixAccessKey = Data("synctool-v1/access-key:".utf8)
    private static let prefixDepositToken = Data("synctool-v1/deposit-token:".utf8)
    private static let prefixUploadToken = Data("synctool-v1/upload-token:".utf8)
    private static let prefixMailboxAuthIn = "synctool-v1/mailbox-auth\n"

    public static let ed25519Pkcs8Prefix = Data([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20])
    public static let x25519Pkcs8Prefix = Data([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20])
    public static let ed25519SpkiPrefix = Data([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00])
    public static let x25519SpkiPrefix = Data([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00])
    public static let p256SpkiPrefix = Data([
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
        0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
    ])

    private static let ed25519OrderLLE: [UInt8] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
    ]
    private static let ed25519FieldPLE: [UInt8] = [0xed] + [UInt8](repeating: 0xff, count: 30) + [0x7f]
    private static let ed25519SmallOrderPks: [[UInt8]] = [
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000080",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000080",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
    ].map { try! [UInt8](SyncCrypto.hexDecode($0)) }

    private static let zero32 = Data(count: 32)
    private static let hexAscii: [UInt8] = Array("0123456789abcdef".utf8)

    public static func randomBytes(_ count: Int) throws -> Data {
        guard count >= 0 else { throw SyncError(code: .errBadRequest, message: "negative byte count") }
        if count == 0 { return Data() }
        var bytes = [UInt8](repeating: 0, count: count)
        guard SecRandomCopyBytes(kSecRandomDefault, count, &bytes) == errSecSuccess else {
            throw SyncError(code: .errKeystoreError, message: "CSPRNG SecRandomCopyBytes failed")
        }
        return Data(bytes)
    }

    public static func generateMasterSeed() throws -> Data { try randomBytes(masterSeedSize) }
    public static func generateNonceHex() throws -> String { hexEncode(try randomBytes(16)) }
    public static func generateTokenB64u() throws -> String { b64uEncode(try randomBytes(32)) }

    public static func constantTimeEquals(_ a: Data, _ b: Data) -> Bool {
        constantTimeEqualsBytes([UInt8](a), [UInt8](b))
    }

    internal static func constantTimeEqualsBytes(_ a: [UInt8], _ b: [UInt8]) -> Bool {
        guard a.count == b.count else { return false }
        var diff: UInt8 = 0
        for i in 0..<a.count { diff |= (a[i] ^ b[i]) }
        return diff == 0
    }

    public static func hexEncode(_ data: Data) -> String {
        var out = [UInt8]()
        out.reserveCapacity(data.count * 2)
        for b in data { out.append(hexAscii[Int(b >> 4)]); out.append(hexAscii[Int(b & 0x0f)]) }
        return String(decoding: out, as: UTF8.self)
    }

    public static func hexDecode(_ hex: String) throws -> Data {
        let utf8 = Array(hex.utf8)
        guard utf8.count % 2 == 0 else { throw SyncError(code: .errBadRequest, message: "odd-length hex") }
        var out = [UInt8](repeating: 0, count: utf8.count / 2)
        for i in 0..<out.count {
            out[i] = (try hexNibble(utf8[i * 2]) << 4) | (try hexNibble(utf8[i * 2 + 1]))
        }
        return Data(out)
    }

    private static func hexNibble(_ b: UInt8) throws -> UInt8 {
        if b >= 0x30 && b <= 0x39 { return b - 0x30 }
        if b >= 0x61 && b <= 0x66 { return b - 0x61 + 10 }
        if b >= 0x41 && b <= 0x46 { return b - 0x41 + 10 }
        throw SyncError(code: .errBadRequest, message: "invalid hex character")
    }

    public static func isLowerHex(_ s: String, count: Int) -> Bool {
        let u = Array(s.utf8)
        return u.count == count && u.allSatisfy { ($0 >= 0x30 && $0 <= 0x39) || ($0 >= 0x61 && $0 <= 0x66) }
    }

    public static func b64uEncode(_ data: Data) -> String {
        Data(data).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    public static func b64uDecode(_ str: String) throws -> Data {
        if str.isEmpty { return Data() }
        let utf8 = Array(str.utf8)
        guard utf8.count % 4 != 1 else { throw SyncError(code: .errBadRequest, message: "invalid base64url length") }
        for b in utf8 {
            let ok = (b >= 0x41 && b <= 0x5A) || (b >= 0x61 && b <= 0x7A) || (b >= 0x30 && b <= 0x39) || b == 0x2D || b == 0x5F
            guard ok else { throw SyncError(code: .errBadRequest, message: "invalid unpadded base64url character") }
        }
        var b64 = str.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        let pad = (4 - (b64.utf8.count % 4)) % 4
        if pad > 0 { b64 += String(repeating: "=", count: pad) }
        guard let decoded = Data(base64Encoded: b64), b64uEncode(decoded) == str else {
            throw SyncError(code: .errBadRequest, message: "non-canonical base64url encoding")
        }
        return decoded
    }

    public static func sha256(_ parts: Data...) -> Data {
        var h = SHA256(); for p in parts { h.update(data: p) }; return Data(h.finalize())
    }

    public static func hmacSha256(key: Data, _ parts: Data...) -> Data {
        var mac = HMAC<SHA256>(key: SymmetricKey(data: key.isEmpty ? zero32 : Data(key)))
        for p in parts { mac.update(data: p) }
        return Data(mac.finalize())
    }

    public static func hkdfExtract(salt: Data, ikm: Data) -> Data {
        hmacSha256(key: salt.isEmpty ? zero32 : salt, ikm)
    }

    public static func hkdfExpand(prk: Data, info: Data, length: Int) throws -> Data {
        guard prk.count == 32 && length >= 0 && length <= 255 * 32 else {
            throw SyncError(code: .errCryptoHandshakeFailed, message: "invalid HKDF parameters")
        }
        if length == 0 { return Data() }
        let symKey = SymmetricKey(data: Data(prk))
        var out = Data(capacity: length), t = Data(), counter: UInt8 = 1
        while out.count < length {
            var mac = HMAC<SHA256>(key: symKey)
            if !t.isEmpty { mac.update(data: t) }
            if !info.isEmpty { mac.update(data: info) }
            mac.update(data: Data([counter]))
            t = Data(mac.finalize())
            out.append(t.prefix(min(32, length - out.count)))
            counter &+= 1
        }
        return out
    }

    public static func hkdfDerive(salt: Data, ikm: Data, info: Data, length: Int) throws -> Data {
        try hkdfExpand(prk: hkdfExtract(salt: salt, ikm: ikm), info: info, length: length)
    }

    /// AES-256-GCM seal emitting wire `ciphertext || tag16` only (nonce is deterministic, never prepended).
    public static func aesGcmSeal(key: Data, nonce: Data, plaintext: Data, aad: Data = Data()) throws -> Data {
        guard key.count == 32 && nonce.count == 12 else {
            throw SyncError(code: .errCryptoDecryptFailed, message: "AES-256-GCM requires 32B key and 12B nonce")
        }
        let gcmNonce = try AES.GCM.Nonce(data: Data(nonce))
        let box = try AES.GCM.seal(Data(plaintext), using: SymmetricKey(data: Data(key)), nonce: gcmNonce, authenticating: Data(aad))
        var out = Data(capacity: plaintext.count + 16)
        out.append(box.ciphertext); out.append(box.tag)
        return out
    }

    /// AES-256-GCM open consuming wire `ciphertext || tag16`.
    public static func aesGcmOpen(key: Data, nonce: Data, ciphertextAndTag: Data, aad: Data = Data()) throws -> Data {
        guard key.count == 32 && nonce.count == 12 else {
            throw SyncError(code: .errCryptoDecryptFailed, message: "AES-256-GCM requires 32B key and 12B nonce")
        }
        let wire = Data(ciphertextAndTag)
        guard wire.count >= 16 else { throw SyncError(code: .errCryptoDecryptFailed, message: "ciphertext shorter than 16B tag") }
        do {
            let box = try AES.GCM.SealedBox(nonce: try AES.GCM.Nonce(data: Data(nonce)), ciphertext: wire.prefix(wire.count - 16), tag: wire.suffix(16))
            return try AES.GCM.open(box, using: SymmetricKey(data: Data(key)), authenticating: Data(aad))
        } catch {
            throw SyncError(code: .errCryptoDecryptFailed, message: "AES-256-GCM authentication failed")
        }
    }

    public static func x25519KeypairFromRawScalar(_ sk32: Data) throws -> (sk: Data, pk: Data) {
        let rawSk = Data(sk32)
        guard rawSk.count == 32, let priv = try? Curve25519.KeyAgreement.PrivateKey(rawRepresentation: rawSk) else {
            throw SyncError(code: .errCryptoHandshakeFailed, message: "X25519 private key must be 32 bytes")
        }
        return (sk: rawSk, pk: Data(priv.publicKey.rawRepresentation))
    }

    public static func x25519PublicKeyFromPrivate(_ sk32: Data) throws -> Data { try x25519KeypairFromRawScalar(sk32).pk }
    public static func x25519Generate() throws -> (sk: Data, pk: Data) { try x25519KeypairFromRawScalar(randomBytes(32)) }

    public static func x25519DiffieHellman(sk32: Data, peerPk32: Data) throws -> Data {
        let rawSk = Data(sk32), rawPk = Data(peerPk32)
        guard rawSk.count == 32 && rawPk.count == 32 else {
            throw SyncError(code: .errCryptoHandshakeFailed, message: "X25519 keys must be 32 bytes")
        }
        let sharedBytes: Data
        do {
            let priv = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: rawSk)
            let pub = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: rawPk)
            sharedBytes = (try priv.sharedSecretFromKeyAgreement(with: pub)).withUnsafeBytes { Data($0) }
        } catch {
            throw SyncError(code: .errCryptoHandshakeFailed, message: "x25519 key agreement rejected low-order point")
        }
        if constantTimeEquals(sharedBytes, zero32) {
            throw SyncError(code: .errCryptoHandshakeFailed, message: "x25519 shared secret is all zeros")
        }
        return sharedBytes
    }

    public static func ed25519PublicKeyFromSeed(_ seed32: Data) throws -> Data {
        let raw = Data(seed32)
        guard raw.count == 32, let priv = try? Curve25519.Signing.PrivateKey(rawRepresentation: raw) else {
            throw SyncError(code: .errCryptoSignatureInvalid, message: "Ed25519 seed must be 32 bytes")
        }
        return Data(priv.publicKey.rawRepresentation)
    }

    public static func ed25519Sign(seed32: Data, message: Data) throws -> Data {
        let raw = Data(seed32)
        guard raw.count == 32, let priv = try? Curve25519.Signing.PrivateKey(rawRepresentation: raw),
              let sig = try? priv.signature(for: Data(message)) else {
            throw SyncError(code: .errCryptoSignatureInvalid, message: "Ed25519 signing failed")
        }
        return Data(sig)
    }

    /// Strict RFC 8032 §5.1.7 verification: rejects all 10 torsion point encodings, `y >= p`, and `S >= L`.
    public static func ed25519VerifyStrict(publicKey: Data, message: Data, signature: Data) -> Bool {
        let pk = [UInt8](publicKey), sig = [UInt8](signature)
        guard pk.count == 32 && sig.count == 64 else { return false }
        for torsion in ed25519SmallOrderPks where constantTimeEqualsBytes(pk, torsion) { return false }
        guard isLessThanLE(pk, mod: ed25519FieldPLE, clearTopBit: true),
              isLessThanLE(Array(sig[0..<32]), mod: ed25519FieldPLE, clearTopBit: true),
              isLessThanLE(Array(sig[32..<64]), mod: ed25519OrderLLE, clearTopBit: false),
              let pub = try? Curve25519.Signing.PublicKey(rawRepresentation: Data(pk)) else { return false }
        return pub.isValidSignature(Data(sig), for: Data(message))
    }

    private static func isLessThanLE(_ a32: [UInt8], mod: [UInt8], clearTopBit: Bool) -> Bool {
        var borrow = 0
        for i in 0..<32 {
            let ai = Int((clearTopBit && i == 31) ? (a32[31] & 0x7f) : a32[i])
            let diff = ai - Int(mod[i]) - borrow
            borrow = diff < 0 ? 1 : 0
        }
        return borrow == 1
    }

    public static func deriveDeviceKeys(_ seed32: Data) throws -> DeviceKeys {
        let rawSeed = Data(seed32)
        guard rawSeed.count == masterSeedSize else {
            throw SyncError(code: .errKeystoreError, message: "device_master_seed must be 32 bytes")
        }
        let masterPrk = hkdfExtract(salt: masterSeedSalt, ikm: rawSeed)
        let sigSeed = try hkdfExpand(prk: masterPrk, info: infoEd25519Sign, length: 32)
        let kemSk = try hkdfExpand(prk: masterPrk, info: infoX25519Kem, length: 32)
        let localMeta = try hkdfExpand(prk: masterPrk, info: infoLocalMetaKey, length: 32)
        let sigPk = try ed25519PublicKeyFromSeed(sigSeed)
        let kemPk = try x25519PublicKeyFromPrivate(kemSk)
        let (devRaw, devHex) = try deriveDeviceId(sigPk)
        return DeviceKeys(
            masterSeed: rawSeed, masterPrk: masterPrk, sigSeed: sigSeed, sigPk: sigPk,
            kemSk: kemSk, kemPk: kemPk, localMetaKey: localMeta, deviceIdRaw: devRaw, deviceId: devHex
        )
    }

    public static func deriveMailboxKeys(masterPrk: Data, relayId: String) throws -> MailboxKeys {
        guard masterPrk.count == 32 && !relayId.isEmpty else {
            throw SyncError(code: .errKeystoreError, message: "invalid masterPrk or empty relayId")
        }
        let authSeed = try hkdfExpand(prk: masterPrk, info: Data((infoMailboxAuthPfx + relayId).utf8), length: 32)
        let authPk = try ed25519PublicKeyFromSeed(authSeed)
        return MailboxKeys(relayId: relayId, authSeed: authSeed, authPk: authPk, mailboxId: try deriveMailboxId(authPk))
    }

    public static func deriveRelayId(_ canonicalOrigin: String) -> String {
        hexEncode(Data(sha256(prefixRelayId, Data(canonicalOrigin.utf8)).prefix(16)))
    }

    public static func deriveDeviceId(_ signPk: Data) throws -> (raw: Data, hex: String) {
        guard signPk.count == 32 else { throw SyncError(code: .errCryptoSignatureInvalid, message: "sign_pk must be 32B") }
        let raw = Data(sha256(prefixDeviceId, Data(signPk)).prefix(16))
        return (raw, hexEncode(raw))
    }

    public static func deriveMailboxId(_ mailboxAuthPk: Data) throws -> String {
        guard mailboxAuthPk.count == 32 else { throw SyncError(code: .errCryptoSignatureInvalid, message: "mailbox_auth_pk must be 32B") }
        return hexEncode(Data(sha256(prefixMailboxId, Data(mailboxAuthPk)).prefix(16)))
    }

    public static func deviceCardSignInput(signPk: Data, kemPk: Data, issuedAt: Int64) throws -> Data {
        guard signPk.count == 32 && kemPk.count == 32 && issuedAt >= 0 else {
            throw SyncError(code: .errCryptoSignatureInvalid, message: "invalid DeviceCard signing parameters")
        }
        var out = Data(capacity: prefixDeviceCard.count + 72)
        out.append(prefixDeviceCard); out.append(Data(signPk)); out.append(Data(kemPk))
        appendUInt64BE(&out, UInt64(issuedAt))
        return out
    }

    public static func signDeviceCard(signSeed32: Data, kemPk32: Data, issuedAt: Int64) throws -> Data {
        let signPk = try ed25519PublicKeyFromSeed(signSeed32)
        return try ed25519Sign(seed32: signSeed32, message: deviceCardSignInput(signPk: signPk, kemPk: kemPk32, issuedAt: issuedAt))
    }

    public static func verifyDeviceCard(deviceId: String, signPk: Data, kemPk: Data, issuedAt: Int64, cardSig: Data) throws {
        guard signPk.count == 32 && kemPk.count == 32 && cardSig.count == 64 && isLowerHex(deviceId, count: 32) else {
            throw SyncError(code: .errCryptoSignatureInvalid, message: "invalid DeviceCard key/signature/id")
        }
        let (_, expectedId) = try deriveDeviceId(signPk)
        guard constantTimeEquals(Data(deviceId.utf8), Data(expectedId.utf8)) else {
            throw SyncError(code: .errCryptoSignatureInvalid, message: "device_id does not match sign_pk")
        }
        let input = try deviceCardSignInput(signPk: signPk, kemPk: kemPk, issuedAt: issuedAt)
        guard ed25519VerifyStrict(publicKey: signPk, message: input, signature: cardSig) else {
            throw SyncError(code: .errCryptoSignatureInvalid, message: "invalid DeviceCard Ed25519 signature")
        }
    }

    public static func encodeEd25519Pkcs8(_ seed32: Data) throws -> Data {
        guard seed32.count == 32 else { throw SyncError(code: .errBadRequest, message: "seed must be 32B") }
        return ed25519Pkcs8Prefix + Data(seed32)
    }
    public static func encodeX25519Pkcs8(_ sk32: Data) throws -> Data {
        guard sk32.count == 32 else { throw SyncError(code: .errBadRequest, message: "sk must be 32B") }
        return x25519Pkcs8Prefix + Data(sk32)
    }
    public static func encodeEd25519Spki(_ pk32: Data) throws -> Data {
        guard pk32.count == 32 else { throw SyncError(code: .errBadRequest, message: "pk must be 32B") }
        return ed25519SpkiPrefix + Data(pk32)
    }
    public static func encodeX25519Spki(_ pk32: Data) throws -> Data {
        guard pk32.count == 32 else { throw SyncError(code: .errBadRequest, message: "pk must be 32B") }
        return x25519SpkiPrefix + Data(pk32)
    }
    public static func encodeP256SpkiFromX963(_ raw65: Data) throws -> Data {
        guard raw65.count == 65 else { throw SyncError(code: .errTlsCertInvalid, message: "P-256 X9.63 key must be 65B") }
        return p256SpkiPrefix + Data(raw65)
    }

    // MARK: - Relay Access HMAC & Mailbox Ownership Request Signing (`CRYPTO_AND_AUTH.md` §7)

    public static func deriveRelayHmacKey(_ accessKey: String) -> Data { sha256(prefixAccessKey, Data(accessKey.utf8)) }
    public static func hashDepositToken(_ rawToken: String) -> String { hexEncode(sha256(prefixDepositToken, Data(rawToken.utf8))) }
    public static func hashUploadToken(_ rawToken: String) -> String { hexEncode(sha256(prefixUploadToken, Data(rawToken.utf8))) }
    public static func bodyBindingControl(_ rawBody: Data? = nil) -> String { "sha256:\(hexEncode(sha256(rawBody ?? Data())))" }
    public static func bodyBindingStream(_ contentLength: Int64) -> String { "stream:\(contentLength)" }

    public static func extraTokenBinding(depositToken: String = "", uploadToken: String = "") -> String {
        if !depositToken.isEmpty { return "deposit:\(hashDepositToken(depositToken))" }
        if !uploadToken.isEmpty { return "upload:\(hashUploadToken(uploadToken))" }
        return ""
    }

    public static func buildCanonicalRequest(
        method: String, pathAndRawQuery: String, ts: String, nonce: String, bodyBinding: String, extraTokenBinding: String = ""
    ) -> String {
        "\(method.uppercased())\n\(pathAndRawQuery)\n\(ts)\n\(nonce)\n\(bodyBinding)\n\(extraTokenBinding)"
    }

    public static func signRelayRequest(
        accessKey: String, method: String, pathAndRawQuery: String, ts: String, nonce: String, bodyBinding: String, extraTokenBinding: String = ""
    ) -> String {
        let canon = buildCanonicalRequest(method: method, pathAndRawQuery: pathAndRawQuery, ts: ts, nonce: nonce, bodyBinding: bodyBinding, extraTokenBinding: extraTokenBinding)
        return hexEncode(hmacSha256(key: deriveRelayHmacKey(accessKey), Data(canon.utf8)))
    }

    public static func verifyRelayRequest(
        accessKey: String, method: String, pathAndRawQuery: String, ts: String, nonce: String, bodyBinding: String, extraTokenBinding: String = "", sigHex: String
    ) -> Bool {
        guard isLowerHex(sigHex, count: 64), let got = try? hexDecode(sigHex) else { return false }
        let canon = buildCanonicalRequest(method: method, pathAndRawQuery: pathAndRawQuery, ts: ts, nonce: nonce, bodyBinding: bodyBinding, extraTokenBinding: extraTokenBinding)
        return constantTimeEquals(hmacSha256(key: deriveRelayHmacKey(accessKey), Data(canon.utf8)), got)
    }

    public static func buildMailboxSigInput(
        method: String, pathAndRawQuery: String, mailboxId: String, ts: String, nonce: String, bodyBinding: String
    ) -> String {
        "\(prefixMailboxAuthIn)\(method.uppercased())\n\(pathAndRawQuery)\n\(mailboxId)\n\(ts)\n\(nonce)\n\(bodyBinding)"
    }

    public static func signMailboxRequest(
        mailboxAuthSeed32: Data, method: String, pathAndRawQuery: String, mailboxId: String, ts: String, nonce: String, bodyBinding: String
    ) throws -> String {
        let input = buildMailboxSigInput(method: method, pathAndRawQuery: pathAndRawQuery, mailboxId: mailboxId, ts: ts, nonce: nonce, bodyBinding: bodyBinding)
        return b64uEncode(try ed25519Sign(seed32: mailboxAuthSeed32, message: Data(input.utf8)))
    }

    public static func verifyMailboxRequest(
        mailboxAuthPk32: Data, method: String, pathAndRawQuery: String, mailboxId: String, ts: String, nonce: String, bodyBinding: String, sigB64u: String
    ) -> Bool {
        guard mailboxAuthPk32.count == 32, let sig = try? b64uDecode(sigB64u), sig.count == 64 else { return false }
        let input = buildMailboxSigInput(method: method, pathAndRawQuery: pathAndRawQuery, mailboxId: mailboxId, ts: ts, nonce: nonce, bodyBinding: bodyBinding)
        return ed25519VerifyStrict(publicKey: mailboxAuthPk32, message: Data(input.utf8), signature: sig)
    }

    internal static func appendUInt32BE(_ data: inout Data, _ v: UInt32) {
        data.append(contentsOf: [UInt8((v >> 24) & 0xff), UInt8((v >> 16) & 0xff), UInt8((v >> 8) & 0xff), UInt8(v & 0xff)])
    }

    internal static func appendUInt64BE(_ data: inout Data, _ v: UInt64) {
        for shift in stride(from: 56, through: 0, by: -8) { data.append(UInt8((v >> shift) & 0xff)) }
    }
}
