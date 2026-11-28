import Foundation

/// Canonical 35 `synctool-v1` cross-language error codes (`ENVELOPE_AND_SDK.md` §4.2 & `PROTOCOL.md` §4).
public enum ErrorCode: String, Sendable, Codable, CaseIterable, Equatable {
    // A. 15 Normative Relay Wire Error Codes
    case errBadRequest = "ERR_BAD_REQUEST"
    case errReplayDetected = "ERR_REPLAY_DETECTED"
    case errUnauthorizedToken = "ERR_UNAUTHORIZED_TOKEN"
    case errSpoolDisabled = "ERR_SPOOL_DISABLED"
    case errDownloadLimitExceeded = "ERR_DOWNLOAD_LIMIT_EXCEEDED"
    case errNotFound = "ERR_NOT_FOUND"
    case errClockSkew = "ERR_CLOCK_SKEW"
    case errRoomBusy = "ERR_ROOM_BUSY"
    case errInvalidState = "ERR_INVALID_STATE"
    case errConflict = "ERR_CONFLICT"
    case errRoomBurned = "ERR_ROOM_BURNED"
    case errChunkTooLarge = "ERR_CHUNK_TOO_LARGE"
    case errOfflineQuotaExceeded = "ERR_OFFLINE_QUOTA_EXCEEDED"
    case errRateLimited = "ERR_RATE_LIMITED"
    case errPipePeerTimeout = "ERR_PIPE_PEER_TIMEOUT"

    // B. 20 Client, Crypto & Host Error Codes
    case errRelayUnreachable = "ERR_RELAY_UNREACHABLE"
    case errTlsPinMismatch = "ERR_TLS_PIN_MISMATCH"
    case errTlsCertInvalid = "ERR_TLS_CERT_INVALID"
    case errAuthFailed = "ERR_AUTH_FAILED"
    case errHandshakeTimeout = "ERR_HANDSHAKE_TIMEOUT"
    case errSasMismatch = "ERR_SAS_MISMATCH"
    case errCryptoHandshakeFailed = "ERR_CRYPTO_HANDSHAKE_FAILED"
    case errCryptoDecryptFailed = "ERR_CRYPTO_DECRYPT_FAILED"
    case errCryptoSignatureInvalid = "ERR_CRYPTO_SIGNATURE_INVALID"
    case errStreamTruncated = "ERR_STREAM_TRUNCATED"
    case errMsgReplayDetected = "ERR_MSG_REPLAY_DETECTED"
    case errHashMismatch = "ERR_HASH_MISMATCH"
    case errManifestInvalid = "ERR_MANIFEST_INVALID"
    case errUnsupportedVersion = "ERR_UNSUPPORTED_VERSION"
    case errDeviceUntrusted = "ERR_DEVICE_UNTRUSTED"
    case errInterruptedResumable = "ERR_INTERRUPTED_RESUMABLE"
    case errUriInvalid = "ERR_URI_INVALID"
    case errKeystoreError = "ERR_KEYSTORE_ERROR"
    case errStorageIo = "ERR_STORAGE_IO"
    case errCancelled = "ERR_CANCELLED"

    public static let errInvalidUri: ErrorCode = .errUriInvalid
    public static let errSignatureInvalid: ErrorCode = .errCryptoSignatureInvalid
    public static let errIntegrityMismatch: ErrorCode = .errHashMismatch
    public static let errSenderRevoked: ErrorCode = .errDeviceUntrusted
    public static let errSenderUnknown: ErrorCode = .errDeviceUntrusted
    public static let errQuotaExceeded: ErrorCode = .errOfflineQuotaExceeded
    public static let errRelayUnavailable: ErrorCode = .errRelayUnreachable
    public static let errUnauthorized: ErrorCode = .errUnauthorizedToken
    public static let errRoomClosed: ErrorCode = .errRoomBurned
    public static let errRoomFull: ErrorCode = .errRoomBusy
    public static let errTimeout: ErrorCode = .errHandshakeTimeout
    public static let errIo: ErrorCode = .errStorageIo

    public var defaultRetryable: Bool {
        switch self {
        case .errReplayDetected, .errClockSkew, .errRateLimited, .errPipePeerTimeout,
             .errRelayUnreachable, .errHandshakeTimeout, .errInterruptedResumable:
            return true
        default:
            return false
        }
    }

    public static func fromWire(_ raw: String) -> ErrorCode { ErrorCode(rawValue: raw) ?? .errBadRequest }
}

/// URI & log secret redaction utilities (`ENVELOPE_AND_SDK.md` §3.3).
public enum Redact {
    private static let syncUriFragRegex = try! NSRegularExpression(pattern: #"(?i)(synctool://[^\s"'<>#]*)#[^\s"'<>)\]]*"#)
    private static let httpUriRegex = try! NSRegularExpression(pattern: #"(?i)(https?://)([^\s"'<>/#@]+@)?([^\s"'<>#]*)(#[^\s"'<>)\]]*)?"#)
    private static let standaloneFragRegex = try! NSRegularExpression(pattern: #"(?i)#(?:(?:k|s)=[^\s"'<>)\]]*|[^\s"'<>)\]]*?(?:&|^)(?:k|s)=[^\s"'<>)\]]*)"#)
    private static let querySecretRegex = try! NSRegularExpression(pattern: #"(?i)([?&](?:k|s)=)[^&#\s"'<>)\]]+"#)

    public static func uri(_ raw: String) -> String {
        guard !raw.isEmpty else { return "" }
        let withoutFrag = raw.firstIndex(of: "#").map { String(raw[..<$0]) + "#[REDACTED]" } ?? raw
        return replaceAll(querySecretRegex, in: withoutFrag, with: "$1[REDACTED]")
    }

    public static func message(_ msg: String) -> String {
        guard !msg.isEmpty else { return "" }
        var out = replaceAll(syncUriFragRegex, in: msg, with: "$1#[REDACTED]")
        out = redactHttpUrls(in: out)
        out = replaceAll(standaloneFragRegex, in: out, with: "#[REDACTED]")
        return replaceAll(querySecretRegex, in: out, with: "$1[REDACTED]")
    }

    public static func details(_ raw: [String: String]) -> [String: String] {
        var out: [String: String] = [:]; out.reserveCapacity(raw.count)
        for (k, v) in raw { out[k] = message(v) }
        return out
    }

    private static func replaceAll(_ regex: NSRegularExpression, in str: String, with template: String) -> String {
        regex.stringByReplacingMatches(in: str, options: [], range: NSRange(str.startIndex..<str.endIndex, in: str), withTemplate: template)
    }

    private static func redactHttpUrls(in text: String) -> String {
        let matches = httpUriRegex.matches(in: text, options: [], range: NSRange(text.startIndex..<text.endIndex, in: text))
        guard !matches.isEmpty else { return text }
        var result = text
        for match in matches.reversed() {
            guard let fullRange = Range(match.range, in: result),
                  let schemeRange = Range(match.range(at: 1), in: result),
                  let hostPathRange = Range(match.range(at: 3), in: result) else { continue }
            let userPrefix = match.range(at: 2).location != NSNotFound ? "[REDACTED]@" : ""
            let fragSuffix = match.range(at: 4).location != NSNotFound ? "#[REDACTED]" : ""
            result.replaceSubrange(fullRange, with: "\(result[schemeRange])\(userPrefix)\(result[hostPathRange])\(fragSuffix)")
        }
        return result
    }
}

/// Structured cross-language `synctool-v1` SDK error (`ENVELOPE_AND_SDK.md` §4.1).
public struct SyncError: Error, LocalizedError, Sendable, CustomStringConvertible, Equatable {
    public let code: ErrorCode
    public let wireCode: String
    public let message: String
    public let retryable: Bool
    public let httpStatus: Int?
    public let retryAfterSec: Int?
    public let details: [String: String]

    public init(
        code: ErrorCode, message: String = "", retryable: Bool? = nil,
        httpStatus: Int? = nil, retryAfterSec: Int? = nil, details: [String: String] = [:]
    ) {
        self.code = code; self.wireCode = code.rawValue; self.message = Redact.message(message)
        self.retryable = retryable ?? code.defaultRetryable; self.httpStatus = httpStatus
        self.retryAfterSec = retryAfterSec; self.details = Redact.details(details)
    }

    public init(
        wireCode: String, message: String = "", retryable: Bool? = nil,
        httpStatus: Int? = nil, retryAfterSec: Int? = nil, details: [String: String] = [:]
    ) {
        let mapped = ErrorCode(rawValue: wireCode) ?? .errBadRequest
        self.code = mapped; self.wireCode = wireCode.isEmpty ? mapped.rawValue : wireCode
        self.message = Redact.message(message); self.retryable = retryable ?? mapped.defaultRetryable
        self.httpStatus = httpStatus; self.retryAfterSec = retryAfterSec; self.details = Redact.details(details)
    }

    public var isRetryable: Bool { retryable }
    public var isAuthError: Bool {
        [.errAuthFailed, .errUnauthorizedToken, .errDeviceUntrusted, .errTlsPinMismatch, .errTlsCertInvalid].contains(code)
    }
    public var isSecurityAlert: Bool {
        [.errTlsPinMismatch, .errSasMismatch, .errRoomBurned, .errCryptoHandshakeFailed,
         .errCryptoDecryptFailed, .errCryptoSignatureInvalid, .errStreamTruncated, .errHashMismatch, .errMsgReplayDetected].contains(code)
    }
    public var isQuotaExceeded: Bool {
        [.errOfflineQuotaExceeded, .errSpoolDisabled, .errChunkTooLarge, .errDownloadLimitExceeded].contains(code)
    }
    public var suggestPipeMode: Bool {
        code == .errSpoolDisabled || code == .errOfflineQuotaExceeded || details["suggest_mode"] == "pipe"
    }
    public var isVersionMismatch: Bool { code == .errUnsupportedVersion }

    public var exitCode: Int {
        switch code {
        case .errUriInvalid, .errBadRequest, .errManifestInvalid, .errUnsupportedVersion: return 2
        case .errRelayUnreachable, .errAuthFailed, .errRateLimited, .errPipePeerTimeout, .errHandshakeTimeout,
             .errReplayDetected, .errClockSkew, .errRoomBusy, .errInvalidState, .errConflict,
             .errChunkTooLarge, .errDownloadLimitExceeded: return 3
        case .errTlsPinMismatch, .errTlsCertInvalid, .errSasMismatch, .errRoomBurned, .errCryptoHandshakeFailed,
             .errCryptoDecryptFailed, .errCryptoSignatureInvalid, .errStreamTruncated, .errHashMismatch,
             .errMsgReplayDetected, .errDeviceUntrusted, .errUnauthorizedToken: return 4
        case .errSpoolDisabled, .errOfflineQuotaExceeded, .errNotFound: return 5
        case .errInterruptedResumable: return 6
        default: return 1
        }
    }

    public var description: String { message.isEmpty ? wireCode : "\(wireCode): \(message)" }
    public var errorDescription: String? { description }
}

// MARK: - Relay Profiles, Pair Offers, Arbitrary JSON Value, Pipe Control Payloads & Events

public enum TlsMode {
    public static let systemCa = "system_ca"
    public static let caAlias = "ca"
    public static let spkiPin = "spki_pin"
}

public struct RelayProfile: Codable, Sendable, Equatable, CustomStringConvertible {
    public var relayId: String, alias: String, endpoint: String, accessKey: String
    public var tlsMode: String, spkiPins: [String], legacySpkiSha256: String, isDefault: Bool

    enum CodingKeys: String, CodingKey {
        case relayId = "relay_id", alias, endpoint, origin, accessKey = "access_key"
        case tlsMode = "tls_mode", spkiPins = "spki_pins", legacySpkiSha256 = "spki_sha256", isDefault = "is_default"
    }

    public init(
        endpoint: String, accessKey: String, tlsMode: String = "", spkiPin: String = "",
        spkiPins: [String] = [], relayId: String = "", alias: String = "", isDefault: Bool = false
    ) {
        let merged = Self.mergePins(spkiPins, spkiPin)
        self.relayId = relayId; self.alias = alias; self.endpoint = endpoint; self.accessKey = accessKey
        self.tlsMode = tlsMode.isEmpty ? (!merged.isEmpty ? TlsMode.spkiPin : TlsMode.systemCa) : tlsMode
        self.spkiPins = merged; self.legacySpkiSha256 = merged.first ?? ""; self.isDefault = isDefault
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let ep = (try c.decodeIfPresent(String.self, forKey: .endpoint)) ?? (try c.decodeIfPresent(String.self, forKey: .origin)) ?? ""
        let merged = Self.mergePins(try c.decodeIfPresent([String].self, forKey: .spkiPins) ?? [], try c.decodeIfPresent(String.self, forKey: .legacySpkiSha256) ?? "")
        self.relayId = try c.decodeIfPresent(String.self, forKey: .relayId) ?? ""
        self.alias = try c.decodeIfPresent(String.self, forKey: .alias) ?? ""
        self.endpoint = ep; self.accessKey = try c.decodeIfPresent(String.self, forKey: .accessKey) ?? ""
        let rawMode = try c.decodeIfPresent(String.self, forKey: .tlsMode) ?? ""
        self.tlsMode = rawMode.isEmpty ? (!merged.isEmpty ? TlsMode.spkiPin : TlsMode.systemCa) : rawMode
        self.spkiPins = merged; self.legacySpkiSha256 = merged.first ?? ""
        self.isDefault = try c.decodeIfPresent(Bool.self, forKey: .isDefault) ?? false
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        let merged = resolvedPins
        try c.encode(relayId, forKey: .relayId); try c.encode(alias, forKey: .alias)
        try c.encode(endpoint, forKey: .endpoint); try c.encode(accessKey, forKey: .accessKey)
        try c.encode(tlsMode, forKey: .tlsMode); try c.encode(merged, forKey: .spkiPins)
        try c.encode(merged.first ?? "", forKey: .legacySpkiSha256); try c.encode(isDefault, forKey: .isDefault)
    }

    public var resolvedPins: [String] { Self.mergePins(spkiPins, legacySpkiSha256) }
    public var spkiPin: String { resolvedPins.first ?? "" }
    public var description: String {
        "RelayProfile(relayId=\(relayId), alias=\(alias), endpoint=\(endpoint), tlsMode=\(tlsMode), spkiPins=\(resolvedPins), accessKey=[REDACTED])"
    }

    internal static func mergePins(_ pins: [String], _ singlePin: String) -> [String] {
        var out: [String] = []
        for raw in pins + [singlePin] {
            for part in raw.split(separator: ",") {
                var clean = part.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
                if clean.hasPrefix("sha256:") { clean = String(clean.dropFirst(7)) }
                if !clean.isEmpty && !out.contains(clean) { out.append(clean) }
            }
        }
        return out
    }
}

public struct PairOffer: Sendable, Equatable, CustomStringConvertible {
    public var version: Int, roomId: String, mode: Int, purpose: String
    public var endpoint: String, spkiPins: [String], expiresAt: Int64, oobSecret: Data, accessKey: String

    public init(
        version: Int = 1, roomId: String, mode: Int, purpose: String, endpoint: String = "",
        spkiPins: [String] = [], expiresAt: Int64 = 0, oobSecret: Data = Data(), accessKey: String = ""
    ) {
        self.version = version; self.roomId = roomId; self.mode = mode; self.purpose = purpose
        self.endpoint = endpoint; self.spkiPins = spkiPins; self.expiresAt = expiresAt
        self.oobSecret = Data(oobSecret); self.accessKey = accessKey
    }

    public var spkiPin: String { spkiPins.first ?? "" }
    public var description: String {
        "PairOffer(v=\(version), r=\(roomId), m=\(mode), p=\(purpose), u=\(endpoint), spkiPins=\(spkiPins), exp=\(expiresAt), secrets=[REDACTED])"
    }
}

public typealias ParsedPairUri = PairOffer

public enum JSONValue: Sendable, Codable, Equatable,
    ExpressibleByNilLiteral, ExpressibleByBooleanLiteral, ExpressibleByIntegerLiteral,
    ExpressibleByFloatLiteral, ExpressibleByStringLiteral, ExpressibleByArrayLiteral, ExpressibleByDictionaryLiteral
{
    case null, bool(Bool), int(Int64), double(Double), string(String), array([JSONValue]), object([String: JSONValue])

    public init(nilLiteral: ()) { self = .null }
    public init(booleanLiteral value: Bool) { self = .bool(value) }
    public init(integerLiteral value: Int64) { self = .int(value) }
    public init(floatLiteral value: Double) { self = .double(value) }
    public init(stringLiteral value: String) { self = .string(value) }
    public init(arrayLiteral elements: JSONValue...) { self = .array(elements) }
    public init(dictionaryLiteral elements: (String, JSONValue)...) {
        var d: [String: JSONValue] = [:]; for (k, v) in elements { d[k] = v }; self = .object(d)
    }

    public var stringValue: String? { if case .string(let s) = self { return s }; return nil }
    public var intValue: Int64? { if case .int(let n) = self { return n }; return nil }
    public var boolValue: Bool? { if case .bool(let b) = self { return b }; return nil }
    public var objectValue: [String: JSONValue]? { if case .object(let o) = self { return o }; return nil }
    public var arrayValue: [JSONValue]? { if case .array(let a) = self { return a }; return nil }

    public init(from decoder: Decoder) throws {
        let c = try decoder.singleValueContainer()
        if c.decodeNil() { self = .null }
        else if let b = try? c.decode(Bool.self) { self = .bool(b) }
        else if let i = try? c.decode(Int64.self) { self = .int(i) }
        else if let d = try? c.decode(Double.self) { self = .double(d) }
        else if let s = try? c.decode(String.self) { self = .string(s) }
        else if let a = try? c.decode([JSONValue].self) { self = .array(a) }
        else if let o = try? c.decode([String: JSONValue].self) { self = .object(o) }
        else { throw DecodingError.dataCorruptedError(in: c, debugDescription: "Unsupported JSONValue") }
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.singleValueContainer()
        switch self {
        case .null: try c.encodeNil()
        case .bool(let b): try c.encode(b)
        case .int(let i): try c.encode(i)
        case .double(let d): try c.encode(d)
        case .string(let s): try c.encode(s)
        case .array(let a): try c.encode(a)
        case .object(let o): try c.encode(o)
        }
    }
}

public struct PartLayout: Codable, Sendable, Equatable {
    public var partId: Int, totalBytes: Int64, chunkCount: Int
    enum CodingKeys: String, CodingKey { case partId = "part_id", totalBytes = "total_bytes", chunkCount = "chunk_count" }
    public init(partId: Int, totalBytes: Int64, chunkCount: Int) {
        self.partId = partId; self.totalBytes = totalBytes; self.chunkCount = chunkCount
    }
}

public struct DeviceCardPayload: Codable, Sendable, Equatable {
    public var deviceId: String, signPk: String, kemPk: String, issuedAt: Int64, cardSig: String, label: String, platform: String?
    enum CodingKeys: String, CodingKey {
        case deviceId = "device_id", signPk = "sign_pk", kemPk = "kem_pk", issuedAt = "issued_at", cardSig = "card_sig", label, platform
    }
    public init(deviceId: String, signPk: String, kemPk: String, issuedAt: Int64, cardSig: String, label: String, platform: String? = nil) {
        self.deviceId = deviceId; self.signPk = signPk; self.kemPk = kemPk; self.issuedAt = issuedAt
        self.cardSig = cardSig; self.label = label; self.platform = platform
    }
}

public struct MailboxBindPayload: Codable, Sendable, Equatable {
    public var relayOrigin: String, mailboxId: String, depositToken: String
    enum CodingKeys: String, CodingKey { case relayOrigin = "relay_origin", mailboxId = "mailbox_id", depositToken = "deposit_token" }
    public init(relayOrigin: String, mailboxId: String, depositToken: String) {
        self.relayOrigin = relayOrigin; self.mailboxId = mailboxId; self.depositToken = depositToken
    }
}

public struct PairBindPayload: Codable, Sendable, Equatable {
    public var deviceCard: DeviceCardPayload, mailbox: MailboxBindPayload?
    enum CodingKeys: String, CodingKey { case deviceCard = "device_card", mailbox }
    public init(deviceCard: DeviceCardPayload, mailbox: MailboxBindPayload? = nil) {
        self.deviceCard = deviceCard; self.mailbox = mailbox
    }
    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(deviceCard, forKey: .deviceCard); try c.encode(mailbox, forKey: .mailbox)
    }
}

public struct PipeStartPayload: Codable, Sendable, Equatable {
    public var op: String = "pipe_start", msgId: String, blocksPerChunk: Int, parts: [PartLayout]
    enum CodingKeys: String, CodingKey { case op, msgId = "msg_id", blocksPerChunk = "blocks_per_chunk", parts }
    public init(op: String = "pipe_start", msgId: String, blocksPerChunk: Int, parts: [PartLayout]) {
        self.op = op; self.msgId = msgId; self.blocksPerChunk = blocksPerChunk; self.parts = parts
    }
}

public struct PipeAckPayload: Codable, Sendable, Equatable {
    public var op: String = "pipe_ack", msgId: String, ackMac: String?
    enum CodingKeys: String, CodingKey { case op, msgId = "msg_id", ackMac = "ack_mac" }
    public init(op: String = "pipe_ack", msgId: String, ackMac: String? = nil) {
        self.op = op; self.msgId = msgId; self.ackMac = ackMac
    }
}

public struct DirectRoomInitPayload: Codable, Sendable, Equatable {
    public var protoV: Int = 1, mode: Int = 0, purpose: String = "direct"
    public var sealedHeader: String, blocksPerChunk: Int, parts: [PartLayout]
    enum CodingKeys: String, CodingKey {
        case protoV = "proto_v", mode, purpose, sealedHeader = "sealed_header", blocksPerChunk = "blocks_per_chunk", parts
    }
    public init(sealedHeader: String, blocksPerChunk: Int, parts: [PartLayout]) {
        self.sealedHeader = sealedHeader; self.blocksPerChunk = blocksPerChunk; self.parts = parts
    }
}

public struct TransferEvent: Codable, Sendable, Equatable {
    public var type: String = "event", event: String = "transfer_progress"
    public var stage: String, direction: String, mode: String, msgId: String
    public var partId: Int, partsTotal: Int
    public var bytesDone: Int64, bytesTotal: Int64, partBytesDone: Int64, partBytesTotal: Int64, speedBps: Int64
    public var resumed: Bool, ts: Int64
    enum CodingKeys: String, CodingKey {
        case type, event, stage, direction, mode, msgId = "msg_id", partId = "part_id", partsTotal = "parts_total"
        case bytesDone = "bytes_done", bytesTotal = "bytes_total", partBytesDone = "part_bytes_done"
        case partBytesTotal = "part_bytes_total", speedBps = "speed_bps", resumed, ts
    }
    public init(
        stage: String, direction: String, mode: String, msgId: String = "", partId: Int = 0, partsTotal: Int = 0,
        bytesDone: Int64 = 0, bytesTotal: Int64 = 0, partBytesDone: Int64 = 0, partBytesTotal: Int64 = 0,
        speedBps: Int64 = 0, resumed: Bool = false, ts: Int64 = Int64(Date().timeIntervalSince1970)
    ) {
        self.stage = stage; self.direction = direction; self.mode = mode; self.msgId = msgId
        self.partId = partId; self.partsTotal = partsTotal; self.bytesDone = bytesDone; self.bytesTotal = bytesTotal
        self.partBytesDone = partBytesDone; self.partBytesTotal = partBytesTotal; self.speedBps = speedBps
        self.resumed = resumed; self.ts = ts
    }
}

public struct RelayCertExpiringEvent: Codable, Sendable, Equatable {
    public var type: String = "event", event: String = "relay_cert_expiring_soon"
    public var relayId: String, expiresAt: Int64, daysRemaining: Int, severity: String
    enum CodingKeys: String, CodingKey {
        case type, event, relayId = "relay_id", expiresAt = "expires_at", daysRemaining = "days_remaining", severity
    }
    public init(relayId: String, expiresAt: Int64, daysRemaining: Int, severity: String) {
        self.relayId = relayId; self.expiresAt = expiresAt; self.daysRemaining = daysRemaining; self.severity = severity
    }
}
