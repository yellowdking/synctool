import Foundation

public typealias Handshake = SyncHandshake

private extension KeyedDecodingContainer {
    func dec<T: Decodable>(_ key: Key, _ fallback: T) throws -> T { (try decodeIfPresent(T.self, forKey: key)) ?? fallback }
}

public struct SyncClientConfig: Sendable {
    public var relay: RelayProfile, keyStore: any SyncKeyStore, appId: String, deviceLabel: String, platform: String
    public var tempDir: URL?
    public var onCertExpiring: (@Sendable (RelayCertExpiringEvent) -> Void)?

    public init(
        relay: RelayProfile, keyStore: any SyncKeyStore = MemoryKeyStore(), appId: String = "synctool.sdk",
        deviceLabel: String = "", platform: String = Self.defaultPlatform(), tempDir: URL? = nil,
        onCertExpiring: (@Sendable (RelayCertExpiringEvent) -> Void)? = nil
    ) {
        self.relay = relay; self.keyStore = keyStore; self.appId = appId
        self.deviceLabel = deviceLabel; self.platform = platform; self.tempDir = tempDir; self.onCertExpiring = onCertExpiring
    }

    public static func defaultPlatform() -> String {
        #if os(iOS)
        return "ios"
        #elseif os(macOS)
        return "macos"
        #else
        return "apple"
        #endif
    }
}

public struct DeviceIdentity: Sendable, Equatable {
    public let deviceId: String, label: String, signPkB64u: String, kemPkB64u: String, mailboxId: String, relayId: String
}

public struct PingResult: Codable, Sendable, Equatable {
    public var protoV: Int = 1, minProtoV: Int = 1, maxProtoV: Int = 1
    public var serverVersion: String = "", serverTs: Int64 = 0, profile: String = "", spoolBackend: String = ""
    public var certExpiresAt: Int64 = 0, certRotateRecommended: Bool = false, rttMs: Int64 = 0, clockOffsetSec: Int64 = 0
    enum CodingKeys: String, CodingKey {
        case protoV = "proto_v", minProtoV = "min_proto_v", maxProtoV = "max_proto_v", serverVersion = "server_version"
        case serverTs = "server_ts", profile, spoolBackend = "spool_backend", certExpiresAt = "cert_expires_at"
        case certRotateRecommended = "cert_rotate_recommended", rttMs = "rtt_ms", clockOffsetSec = "clock_offset_sec"
    }
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        protoV = try c.dec(.protoV, 1); minProtoV = try c.dec(.minProtoV, 1); maxProtoV = try c.dec(.maxProtoV, 1)
        serverVersion = try c.dec(.serverVersion, ""); serverTs = try c.dec(.serverTs, 0)
        profile = try c.dec(.profile, ""); spoolBackend = try c.dec(.spoolBackend, "")
        certExpiresAt = try c.dec(.certExpiresAt, 0); certRotateRecommended = try c.dec(.certRotateRecommended, false)
        rttMs = try c.dec(.rttMs, 0); clockOffsetSec = try c.dec(.clockOffsetSec, 0)
    }
}

public struct StreamingCaps: Codable, Sendable, Equatable {
    public var enabled: Bool = true, blocksPerChunk: Int = 16, maxTransportChunkBytes: Int = 1_048_832
    public var recommendedParallelChunks: Int = 1, maxParallelChunks: Int = 3, rendezvousTimeoutSec: Int = 30, roomTtlMaxSec: Int = 600
    enum CodingKeys: String, CodingKey {
        case enabled, blocksPerChunk = "blocks_per_chunk", maxTransportChunkBytes = "max_transport_chunk_bytes"
        case recommendedParallelChunks = "recommended_parallel_chunks", maxParallelChunks = "max_parallel_chunks"
        case rendezvousTimeoutSec = "rendezvous_timeout_sec", roomTtlMaxSec = "room_ttl_max_sec"
    }
    public init() {}
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        enabled = try c.dec(.enabled, true); blocksPerChunk = try c.dec(.blocksPerChunk, 16)
        maxTransportChunkBytes = try c.dec(.maxTransportChunkBytes, 1_048_832)
        recommendedParallelChunks = try c.dec(.recommendedParallelChunks, 1); maxParallelChunks = try c.dec(.maxParallelChunks, 3)
        rendezvousTimeoutSec = try c.dec(.rendezvousTimeoutSec, 30); roomTtlMaxSec = try c.dec(.roomTtlMaxSec, 600)
    }
}

public struct SpoolCaps: Codable, Sendable, Equatable {
    public var enabled: Bool = false, backend: String = "off"
    public var maxItemBytes: Int64 = 0, maxMailboxBytes: Int64 = 0, maxTotalBytes: Int64 = 0
    public var maxItemsPerMailbox: Int = 0, defaultTtlSec: Int = 0, maxTtlSec: Int = 0, uncommittedTtlSec: Int = 0
    public var maxManifestDownloads: Int = 0, maxDownloadsPerChunk: Int = 0, maxDepositTokensPerMailbox: Int = 0
    enum CodingKeys: String, CodingKey {
        case enabled, backend, maxItemBytes = "max_item_bytes", maxMailboxBytes = "max_mailbox_bytes", maxTotalBytes = "max_total_bytes"
        case maxItemsPerMailbox = "max_items_per_mailbox", defaultTtlSec = "default_ttl_sec", maxTtlSec = "max_ttl_sec"
        case uncommittedTtlSec = "uncommitted_ttl_sec", maxManifestDownloads = "max_manifest_downloads"
        case maxDownloadsPerChunk = "max_downloads_per_chunk", maxDepositTokensPerMailbox = "max_deposit_tokens_per_mailbox"
    }
    public init() {}
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        enabled = try c.dec(.enabled, false); backend = try c.dec(.backend, "off")
        maxItemBytes = try c.dec(.maxItemBytes, 0); maxMailboxBytes = try c.dec(.maxMailboxBytes, 0); maxTotalBytes = try c.dec(.maxTotalBytes, 0)
        maxItemsPerMailbox = try c.dec(.maxItemsPerMailbox, 0); defaultTtlSec = try c.dec(.defaultTtlSec, 0); maxTtlSec = try c.dec(.maxTtlSec, 0)
        uncommittedTtlSec = try c.dec(.uncommittedTtlSec, 0); maxManifestDownloads = try c.dec(.maxManifestDownloads, 0)
        maxDownloadsPerChunk = try c.dec(.maxDownloadsPerChunk, 0); maxDepositTokensPerMailbox = try c.dec(.maxDepositTokensPerMailbox, 0)
    }
}

public struct RelayCaps: Codable, Sendable, Equatable {
    public var protoV: Int = 1, minProtoV: Int = 1, maxProtoV: Int = 1, serverVersion: String = ""
    public var features: [String] = [], profile: String = "standard", serverTs: Int64 = 0
    public var certExpiresAt: Int64 = 0, certRotateRecommended: Bool = false
    public var cryptoPlaintextBlockBytes: Int = 65536, cryptoBlockBytes: Int = 65552
    public var streaming: StreamingCaps = StreamingCaps(), spool: SpoolCaps = SpoolCaps()
    enum CodingKeys: String, CodingKey {
        case protoV = "proto_v", minProtoV = "min_proto_v", maxProtoV = "max_proto_v", serverVersion = "server_version"
        case features, profile, serverTs = "server_ts", certExpiresAt = "cert_expires_at", certRotateRecommended = "cert_rotate_recommended"
        case cryptoPlaintextBlockBytes = "crypto_plaintext_block_bytes", cryptoBlockBytes = "crypto_block_bytes", streaming, spool
    }
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        protoV = try c.dec(.protoV, 1); minProtoV = try c.dec(.minProtoV, 1); maxProtoV = try c.dec(.maxProtoV, 1)
        serverVersion = try c.dec(.serverVersion, ""); features = try c.dec(.features, []); profile = try c.dec(.profile, "standard")
        serverTs = try c.dec(.serverTs, 0); certExpiresAt = try c.dec(.certExpiresAt, 0); certRotateRecommended = try c.dec(.certRotateRecommended, false)
        cryptoPlaintextBlockBytes = try c.dec(.cryptoPlaintextBlockBytes, 65536); cryptoBlockBytes = try c.dec(.cryptoBlockBytes, 65552)
        streaming = try c.dec(.streaming, StreamingCaps()); spool = try c.dec(.spool, SpoolCaps())
    }
}

public struct MailboxRegisterResponse: Codable, Sendable, Equatable {
    public var mailboxId: String, registered: Bool, depositTokenCount: Int
    enum CodingKeys: String, CodingKey { case mailboxId = "mailbox_id", registered, depositTokenCount = "deposit_token_count" }
    public init(mailboxId: String, registered: Bool = true, depositTokenCount: Int = 0) {
        self.mailboxId = mailboxId; self.registered = registered; self.depositTokenCount = depositTokenCount
    }
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        mailboxId = try c.decode(String.self, forKey: .mailboxId); registered = try c.dec(.registered, true); depositTokenCount = try c.dec(.depositTokenCount, 0)
    }
}

public struct InboxItemMeta: Codable, Sendable, Equatable {
    public var itemId: String, createdAt: Int64, expiresAt: Int64, totalBytes: Int64, sealedHeader: String, parts: [PartLayout]
    enum CodingKeys: String, CodingKey { case itemId = "item_id", createdAt = "created_at", expiresAt = "expires_at", totalBytes = "total_bytes", sealedHeader = "sealed_header", parts }
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        itemId = try c.decode(String.self, forKey: .itemId); createdAt = try c.dec(.createdAt, 0); expiresAt = try c.dec(.expiresAt, 0)
        totalBytes = try c.dec(.totalBytes, 0); sealedHeader = try c.decode(String.self, forKey: .sealedHeader); parts = try c.dec(.parts, [])
    }
}

public struct InboxPreview: Sendable, Equatable {
    public let itemId: String, createdAt: Int64, expiresAt: Int64, totalBytes: Int64, cached: Bool, manifest: Manifest
}

public struct InboxWatchEvent: Codable, Sendable, Equatable {
    public var itemId: String, totalBytes: Int64, createdAt: Int64, expiresAt: Int64
    enum CodingKeys: String, CodingKey { case itemId = "item_id", totalBytes = "total_bytes", createdAt = "created_at", expiresAt = "expires_at" }
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        itemId = try c.decode(String.self, forKey: .itemId); totalBytes = try c.dec(.totalBytes, 0); createdAt = try c.dec(.createdAt, 0); expiresAt = try c.dec(.expiresAt, 0)
    }
}

public struct SendResult: Codable, Sendable, Equatable {
    public var mode: String, msgId: String, itemId: String, roomId: String, totalBytes: Int64, expiresAt: Int64
    enum CodingKeys: String, CodingKey { case mode, msgId = "msg_id", itemId = "item_id", roomId = "room_id", totalBytes = "total_bytes", expiresAt = "expires_at" }
    public init(mode: String, msgId: String, itemId: String = "", roomId: String = "", totalBytes: Int64, expiresAt: Int64 = 0) {
        self.mode = mode; self.msgId = msgId; self.itemId = itemId; self.roomId = roomId; self.totalBytes = totalBytes; self.expiresAt = expiresAt
    }
}

public struct OfferReadyInfo: Sendable, Equatable {
    public let roomId: String, displayCode: String, mode: Int, purpose: String, pairUri: String, expiresAt: Int64
}

public enum DeliveryMode {
    public static let auto = "auto", spool = "spool", pipe = "pipe"
}

public struct PairOptions: Sendable {
    public var mode: Int, label: String, includeRelay: Bool, ttlSec: Int
    public var onOfferReady: (@Sendable (OfferReadyInfo) async throws -> Void)?
    public var onSASInput: (@Sendable () async throws -> String)?
    public var onSASDisplay: (@Sendable (String) -> Void)?
    /// Mandatory on Responder when `mode == 2` (`commit_sas_x25519`); fails closed before `M2` if `nil`.
    public var onSASConfirm: (@Sendable (String) async throws -> Bool)?
    public var onProgress: (@Sendable (TransferEvent) -> Void)?

    public init(
        mode: Int = SyncHandshake.modeQrOob, label: String = "", includeRelay: Bool = false, ttlSec: Int = 300,
        onOfferReady: (@Sendable (OfferReadyInfo) async throws -> Void)? = nil,
        onSASInput: (@Sendable () async throws -> String)? = nil,
        onSASDisplay: (@Sendable (String) -> Void)? = nil,
        onSASConfirm: (@Sendable (String) async throws -> Bool)? = nil,
        onProgress: (@Sendable (TransferEvent) -> Void)? = nil
    ) {
        self.mode = mode; self.label = label; self.includeRelay = includeRelay; self.ttlSec = ttlSec
        self.onOfferReady = onOfferReady; self.onSASInput = onSASInput; self.onSASDisplay = onSASDisplay
        self.onSASConfirm = onSASConfirm; self.onProgress = onProgress
    }
}

public struct SendOptions: Sendable {
    public var deliveryMode: String, ttlSec: Int, includeRelay: Bool
    public var onOfferReady: (@Sendable (OfferReadyInfo) async throws -> Void)?
    public var onProgress: (@Sendable (TransferEvent) -> Void)?

    public init(
        deliveryMode: String = DeliveryMode.auto, ttlSec: Int = 0, includeRelay: Bool = false,
        onOfferReady: (@Sendable (OfferReadyInfo) async throws -> Void)? = nil,
        onProgress: (@Sendable (TransferEvent) -> Void)? = nil
    ) {
        self.deliveryMode = deliveryMode; self.ttlSec = ttlSec; self.includeRelay = includeRelay
        self.onOfferReady = onOfferReady; self.onProgress = onProgress
    }
}

public struct ReceiveOptions: Sendable {
    public var onSASDisplay: (@Sendable (String) -> Void)?
    public var onSASConfirm: (@Sendable (String) async throws -> Bool)?
    public var onProgress: (@Sendable (TransferEvent) -> Void)?
    public var appId: String?, autoAck: Bool

    public init(
        onSASDisplay: (@Sendable (String) -> Void)? = nil,
        onSASConfirm: (@Sendable (String) async throws -> Bool)? = nil,
        onProgress: (@Sendable (TransferEvent) -> Void)? = nil,
        appId: String? = nil, autoAck: Bool = true
    ) {
        self.onSASDisplay = onSASDisplay; self.onSASConfirm = onSASConfirm
        self.onProgress = onProgress; self.appId = appId; self.autoAck = autoAck
    }
}

// MARK: - Internal Wire Signaling & Spool DTOs

internal struct HsM1Wire: Codable {
    var protoV: Int; var mode: Int; var purpose: String; var eA: String?; var nA: String?; var commitA: String?
    enum CodingKeys: String, CodingKey { case protoV = "proto_v", mode, purpose, eA = "e_a", nA = "n_a", commitA = "commit_a" }
    init(protoV: Int = 1, mode: Int, purpose: String, eA: String? = nil, nA: String? = nil, commitA: String? = nil) { self.protoV = protoV; self.mode = mode; self.purpose = purpose; self.eA = eA; self.nA = nA; self.commitA = commitA }
    init(from decoder: Decoder) throws { let c = try decoder.container(keyedBy: CodingKeys.self); protoV = try c.dec(.protoV, 1); mode = try c.decode(Int.self, forKey: .mode); purpose = try c.decode(String.self, forKey: .purpose); eA = try c.decodeIfPresent(String.self, forKey: .eA); nA = try c.decodeIfPresent(String.self, forKey: .nA); commitA = try c.decodeIfPresent(String.self, forKey: .commitA) }
}
internal struct HsM2Wire: Codable {
    var protoV: Int; var mode: Int; var eB: String; var nB: String; var macB: String?
    enum CodingKeys: String, CodingKey { case protoV = "proto_v", mode, eB = "e_b", nB = "n_b", macB = "mac_b" }
    init(protoV: Int = 1, mode: Int, eB: String, nB: String, macB: String? = nil) { self.protoV = protoV; self.mode = mode; self.eB = eB; self.nB = nB; self.macB = macB }
    init(from decoder: Decoder) throws { let c = try decoder.container(keyedBy: CodingKeys.self); protoV = try c.dec(.protoV, 1); mode = try c.decode(Int.self, forKey: .mode); eB = try c.decode(String.self, forKey: .eB); nB = try c.decode(String.self, forKey: .nB); macB = try c.decodeIfPresent(String.self, forKey: .macB) }
}
internal struct HsM3Wire: Codable {
    var protoV: Int; var mode: Int; var eA: String?; var nA: String?; var macA: String
    enum CodingKeys: String, CodingKey { case protoV = "proto_v", mode, eA = "e_a", nA = "n_a", macA = "mac_a" }
    init(protoV: Int = 1, mode: Int, eA: String? = nil, nA: String? = nil, macA: String) { self.protoV = protoV; self.mode = mode; self.eA = eA; self.nA = nA; self.macA = macA }
    init(from decoder: Decoder) throws { let c = try decoder.container(keyedBy: CodingKeys.self); protoV = try c.dec(.protoV, 1); mode = try c.decode(Int.self, forKey: .mode); eA = try c.decodeIfPresent(String.self, forKey: .eA); nA = try c.decodeIfPresent(String.self, forKey: .nA); macA = try c.decode(String.self, forKey: .macA) }
}
internal struct HsM4Wire: Codable {
    var protoV: Int; var mode: Int; var macB: String
    enum CodingKeys: String, CodingKey { case protoV = "proto_v", mode, macB = "mac_b" }
    init(protoV: Int = 1, mode: Int, macB: String) { self.protoV = protoV; self.mode = mode; self.macB = macB }
    init(from decoder: Decoder) throws { let c = try decoder.container(keyedBy: CodingKeys.self); protoV = try c.dec(.protoV, 1); mode = try c.decode(Int.self, forKey: .mode); macB = try c.decode(String.self, forKey: .macB) }
}
internal struct PairBindWire: Codable {
    var protoV: Int; var op: String; var ct: String
    enum CodingKeys: String, CodingKey { case protoV = "proto_v", op, ct }
    init(protoV: Int = 1, op: String = "pair_bind", ct: String) { self.protoV = protoV; self.op = op; self.ct = ct }
    init(from decoder: Decoder) throws { let c = try decoder.container(keyedBy: CodingKeys.self); protoV = try c.dec(.protoV, 1); op = try c.dec(.op, "pair_bind"); ct = try c.decode(String.self, forKey: .ct) }
}
internal struct PipeCtrlWire: Codable { var ctrlSeq: Int64, ct: String; enum CodingKeys: String, CodingKey { case ctrlSeq = "ctrl_seq", ct } }
internal struct RoomCreateReq: Codable { var roomId: String, ttlSec: Int, initialMsgB64: String?; enum CodingKeys: String, CodingKey { case roomId = "room_id", ttlSec = "ttl_sec", initialMsgB64 = "initial_msg_b64" } }
internal struct RoomCreateResp: Codable {
    var roomId: String, pipeId: String, senderToken: String, expiresAt: Int64, seq: Int
    enum CodingKeys: String, CodingKey { case roomId = "room_id", pipeId = "pipe_id", senderToken = "sender_token", expiresAt = "expires_at", seq }
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        roomId = try c.decode(String.self, forKey: .roomId); pipeId = try c.decode(String.self, forKey: .pipeId)
        senderToken = try c.decode(String.self, forKey: .senderToken); expiresAt = try c.decode(Int64.self, forKey: .expiresAt); seq = try c.dec(.seq, 0)
    }
}
internal struct RoomMessageWire: Codable, Sendable {
    var seq: Int, from: String, kind: String, msgB64: String
    enum CodingKeys: String, CodingKey { case seq, from, kind, msgB64 = "msg_b64" }
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        seq = try c.dec(.seq, 0); from = try c.dec(.from, ""); kind = try c.dec(.kind, ""); msgB64 = try c.dec(.msgB64, "")
    }
}
internal struct RoomJoinResp: Codable {
    var roomId: String, pipeId: String, receiverToken: String, expiresAt: Int64, seq: Int, messages: [RoomMessageWire]
    enum CodingKeys: String, CodingKey { case roomId = "room_id", pipeId = "pipe_id", receiverToken = "receiver_token", expiresAt = "expires_at", seq, messages }
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        roomId = try c.decode(String.self, forKey: .roomId); pipeId = try c.decode(String.self, forKey: .pipeId)
        receiverToken = try c.decode(String.self, forKey: .receiverToken); expiresAt = try c.decode(Int64.self, forKey: .expiresAt)
        seq = try c.dec(.seq, 0); messages = try c.dec(.messages, [])
    }
}
internal struct RoomPostMsgReq: Codable { var kind: String, msgB64: String; enum CodingKeys: String, CodingKey { case kind, msgB64 = "msg_b64" } }
internal struct RoomPostMsgResp: Codable {
    var seq: Int = 0
    enum CodingKeys: String, CodingKey { case seq }
    init(from decoder: Decoder) throws { let c = try decoder.container(keyedBy: CodingKeys.self); seq = try c.dec(.seq, 0) }
}
internal struct RoomPollResp: Codable {
    var state: String, seq: Int, messages: [RoomMessageWire], reason: String
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        state = try c.dec(.state, ""); seq = try c.dec(.seq, 0); messages = try c.dec(.messages, []); reason = try c.dec(.reason, "")
    }
}
internal struct RoomCloseReq: Codable { var reason: String }
internal struct MailboxDepositTokenSpec: Codable { var tokenId: String, tokenHashHex: String; enum CodingKeys: String, CodingKey { case tokenId = "token_id", tokenHashHex = "token_hash_hex" } }
internal struct MailboxPutReq: Codable { var authPkB64: String, depositTokens: [MailboxDepositTokenSpec]?; enum CodingKeys: String, CodingKey { case authPkB64 = "auth_pk_b64", depositTokens = "deposit_tokens" } }
internal struct SpoolInitReq: Codable { var mailboxId: String, declaredTotalBytes: Int64, ttlSec: Int, sealedHeader: String, parts: [PartLayout]; enum CodingKeys: String, CodingKey { case mailboxId = "mailbox_id", declaredTotalBytes = "declared_total_bytes", ttlSec = "ttl_sec", sealedHeader = "sealed_header", parts } }
internal struct SpoolInitResp: Codable {
    var itemId: String, uploadToken: String, expiresAt: Int64
    enum CodingKeys: String, CodingKey { case itemId = "item_id", uploadToken = "upload_token", expiresAt = "expires_at" }
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        itemId = try c.decode(String.self, forKey: .itemId); uploadToken = try c.decode(String.self, forKey: .uploadToken); expiresAt = try c.dec(.expiresAt, 0)
    }
}
internal struct SpoolCommitResp: Codable {
    var expiresAt: Int64 = 0
    enum CodingKeys: String, CodingKey { case expiresAt = "expires_at" }
    init(from decoder: Decoder) throws { let c = try decoder.container(keyedBy: CodingKeys.self); expiresAt = try c.dec(.expiresAt, 0) }
}
internal struct MailboxItemsResp: Codable {
    var items: [InboxItemMeta] = []
    enum CodingKeys: String, CodingKey { case items }
    init(from decoder: Decoder) throws { let c = try decoder.container(keyedBy: CodingKeys.self); items = try c.dec(.items, []) }
}
internal struct MailboxPollResp: Codable {
    var items: [InboxWatchEvent], serverTs: Int64
    enum CodingKeys: String, CodingKey { case items, serverTs = "server_ts" }
    init(from decoder: Decoder) throws { let c = try decoder.container(keyedBy: CodingKeys.self); items = try c.dec(.items, []); serverTs = try c.dec(.serverTs, 0) }
}
internal struct RoomM1Probe: Codable {
    var protoV: Int = 0, mode: Int = -1, purpose: String = ""
    enum CodingKeys: String, CodingKey { case protoV = "proto_v", mode, purpose }
    init(from decoder: Decoder) throws { let c = try decoder.container(keyedBy: CodingKeys.self); protoV = try c.dec(.protoV, 0); mode = try c.dec(.mode, -1); purpose = try c.dec(.purpose, "") }
}

// MARK: - Canonical `SyncClient` Actor

public actor SyncClient {
    internal struct InitializedState: Sendable {
        let deviceKeys: DeviceKeys, mailboxKeys: MailboxKeys, deviceLabel: String, tempDir: URL
    }

    private let config: SyncClientConfig
    internal nonisolated let transport: SyncTransport
    public nonisolated let keyStore: any SyncKeyStore
    public nonisolated let appId: String
    public nonisolated let platform: String
    public nonisolated var relayProfile: RelayProfile { transport.profile }

    private var initializedState: InitializedState?
    private var initTask: Task<InitializedState, Error>?
    private var isClosed: Bool = false
    internal var createdMsgDirs: Set<URL> = []
    internal var inFlightMsgIds: Set<String> = []
    internal var pendingAckItems: [String: (msgId: String, createdAt: Int64)] = [:]

    public init(config: SyncClientConfig) throws {
        self.config = config
        self.transport = try SyncTransport(rawProfile: config.relay)
        let cleanApp = config.appId.trimmingCharacters(in: .whitespacesAndNewlines)
        self.appId = cleanApp.isEmpty ? "synctool.sdk" : cleanApp
        let cleanPlat = config.platform.trimmingCharacters(in: .whitespacesAndNewlines)
        self.platform = cleanPlat.isEmpty ? SyncClientConfig.defaultPlatform() : cleanPlat
        self.keyStore = config.keyStore
    }

    public init(
        relay: RelayProfile, keyStore: any SyncKeyStore = MemoryKeyStore(), appId: String = "synctool.sdk",
        deviceLabel: String = "", platform: String = SyncClientConfig.defaultPlatform(), tempDir: URL? = nil,
        onCertExpiring: (@Sendable (RelayCertExpiringEvent) -> Void)? = nil
    ) throws {
        try self.init(config: SyncClientConfig(relay: relay, keyStore: keyStore, appId: appId, deviceLabel: deviceLabel, platform: platform, tempDir: tempDir, onCertExpiring: onCertExpiring))
    }

    public init(
        relayUri: String, keyStore: any SyncKeyStore = MemoryKeyStore(), appId: String = "synctool.sdk",
        deviceLabel: String = "", platform: String = SyncClientConfig.defaultPlatform(), tempDir: URL? = nil,
        onCertExpiring: (@Sendable (RelayCertExpiringEvent) -> Void)? = nil
    ) throws {
        try self.init(relay: try SyncUri.parseRelayUri(relayUri), keyStore: keyStore, appId: appId, deviceLabel: deviceLabel, platform: platform, tempDir: tempDir, onCertExpiring: onCertExpiring)
    }

    public nonisolated func getClockOffsetSec() -> Int64 { transport.getClockOffsetSec() }
    public nonisolated func setClockOffsetSec(_ offsetSec: Int64) { transport.setClockOffsetSec(offsetSec) }

    internal func checkOpen() throws {
        if isClosed { throw SyncError(code: .errCancelled, message: "SyncClient is closed") }
    }

    internal func ensureInitialized() async throws -> InitializedState {
        try checkOpen()
        if let st = initializedState { return st }
        if let pending = initTask { return try await pending.value }
        let cfgLabel = config.deviceLabel.trimmingCharacters(in: .whitespacesAndNewlines), cfgTemp = config.tempDir
        let ks = keyStore, relayId = transport.profile.relayId
        let task = Task<InitializedState, Error> {
            let dk = try DeviceKeys.fromMasterSeed(try await ks.loadOrCreateMasterSeed())
            let mk = try dk.deriveMailboxKeys(relayId: relayId)
            var label = cfgLabel
            if label.isEmpty {
                let stored = (try await ks.getLocalLabel())?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
                label = !stored.isEmpty ? stored : (ProcessInfo.processInfo.hostName.isEmpty ? "synctool-device" : ProcessInfo.processInfo.hostName)
            }
            if label.unicodeScalars.count > 64 { label = String(label.unicodeScalars.prefix(64)) }
            let tmp = cfgTemp ?? FileManager.default.temporaryDirectory.appendingPathComponent("synctool-tmp-\(dk.deviceId.prefix(12))", isDirectory: true)
            return InitializedState(deviceKeys: dk, mailboxKeys: mk, deviceLabel: label, tempDir: tmp)
        }
        initTask = task
        do {
            let st = try await task.value; try checkOpen(); initializedState = st; initTask = nil; return st
        } catch { initTask = nil; throw error }
    }

    public func getIdentity() async throws -> DeviceIdentity {
        let st = try await ensureInitialized()
        return DeviceIdentity(
            deviceId: st.deviceKeys.deviceId, label: st.deviceLabel,
            signPkB64u: SyncCrypto.b64uEncode(st.deviceKeys.sigPk), kemPkB64u: SyncCrypto.b64uEncode(st.deviceKeys.kemPk),
            mailboxId: st.mailboxKeys.mailboxId, relayId: transport.profile.relayId
        )
    }

    public func ping() async throws -> PingResult {
        try checkOpen()
        let start = DispatchTime.now().uptimeNanoseconds
        let resp = try await transport.doControl(method: "GET", pathAndQuery: "/v1/ping")
        guard var parsed = try? JSONDecoder().decode(PingResult.self, from: resp.body) else {
            throw SyncError(code: .errBadRequest, message: "decode ping response failed", httpStatus: resp.statusCode)
        }
        parsed.rttMs = Int64((DispatchTime.now().uptimeNanoseconds - start) / 1_000_000)
        parsed.clockOffsetSec = parsed.serverTs - Int64(Date().timeIntervalSince1970)
        checkCertRotation(expiresAt: parsed.certExpiresAt, recommended: parsed.certRotateRecommended)
        return parsed
    }

    public func capabilities() async throws -> RelayCaps {
        try checkOpen()
        let resp = try await transport.doControl(method: "GET", pathAndQuery: "/v1/caps")
        guard let parsed = try? JSONDecoder().decode(RelayCaps.self, from: resp.body) else {
            throw SyncError(code: .errBadRequest, message: "decode caps response failed", httpStatus: resp.statusCode)
        }
        checkCertRotation(expiresAt: parsed.certExpiresAt, recommended: parsed.certRotateRecommended)
        return parsed
    }

    private func checkCertRotation(expiresAt: Int64, recommended: Bool) {
        guard let cb = config.onCertExpiring, expiresAt > 0 else { return }
        let days = Int((expiresAt - Int64(Date().timeIntervalSince1970)) / 86_400)
        if recommended || days < 30 {
            cb(RelayCertExpiringEvent(relayId: transport.profile.relayId, expiresAt: expiresAt, daysRemaining: days, severity: days <= 7 ? "urgent" : "warning"))
        }
    }

    public func initiateDeviceBind(options: PairOptions = PairOptions()) async throws -> DeviceCard { try await initiateDeviceBindInternal(options: options) }
    public func startDeviceBind(options: PairOptions = PairOptions()) async throws -> DeviceCard { try await initiateDeviceBindInternal(options: options) }
    public func acceptDeviceBind(pairInput: String, options: PairOptions = PairOptions()) async throws -> DeviceCard { try await acceptDeviceBindInternal(pairInput: pairInput, options: options) }
    public func startOneShotSend(parcel: ParcelInput, options: PairOptions = PairOptions()) async throws -> SendResult { try await startOneShotSendInternal(parcel: parcel, options: options) }

    public func receiveOneShot(pairInput: String, options: ReceiveOptions = ReceiveOptions(), handler: (@Sendable (ReceivedParcel) async throws -> Void)? = nil) async throws -> ReceivedParcel {
        try await receiveFromRoomInternal(pairInput: pairInput, options: options, handler: handler)
    }
    public func receiveDirect(pairInput: String, options: ReceiveOptions = ReceiveOptions(), handler: (@Sendable (ReceivedParcel) async throws -> Void)? = nil) async throws -> ReceivedParcel {
        try await receiveFromRoomInternal(pairInput: pairInput, options: options, handler: handler)
    }
    public func receiveFromRoom(pairInput: String, options: ReceiveOptions = ReceiveOptions(), handler: (@Sendable (ReceivedParcel) async throws -> Void)? = nil) async throws -> ReceivedParcel {
        try await receiveFromRoomInternal(pairInput: pairInput, options: options, handler: handler)
    }

    public func registerMailbox() async throws -> MailboxRegisterResponse { try await registerMailboxInternal() }
    public func syncMailbox() async throws -> Bool { try await syncMailboxInternal(ensureInitialized()) }
    public func sendToPeer(targetDeviceId: String, parcel: ParcelInput, options: SendOptions = SendOptions()) async throws -> SendResult { try await sendToPeerInternal(targetDeviceId: targetDeviceId, parcel: parcel, options: options) }
    public func sendToDevice(targetDeviceId: String, parcel: ParcelInput, options: SendOptions = SendOptions()) async throws -> SendResult { try await sendToPeerInternal(targetDeviceId: targetDeviceId, parcel: parcel, options: options) }
    public func listInbox(filterAppId: String? = nil) async throws -> [InboxPreview] { try await listInboxInternal(filterAppId: filterAppId) }

    public func fetchParcel(itemId: String, options: ReceiveOptions = ReceiveOptions(), handler: @escaping @Sendable (ReceivedParcel) async throws -> Void) async throws -> Manifest {
        try await fetchParcelInternal(itemId: itemId, options: options, handler: handler).manifest
    }
    public func fetchParcel(itemId: String, appId: String? = nil, autoAck: Bool = false, onProgress: (@Sendable (TransferEvent) -> Void)? = nil) async throws -> ReceivedParcel {
        try await fetchParcelInternal(itemId: itemId, options: ReceiveOptions(onProgress: onProgress, appId: appId, autoAck: autoAck), handler: nil)
    }
    public func ackItem(itemId: String) async throws { try await ackItemInternal(st: ensureInitialized(), itemId: itemId) }
    public func ackItem(_ itemId: String) async throws { try await ackItemInternal(st: ensureInitialized(), itemId: itemId) }

    public func watchInbox(initialSinceTs: Int64? = nil, onEvent: @escaping @Sendable (InboxWatchEvent) async throws -> Void) async throws {
        try await watchInboxInternal(initialSinceTs: initialSinceTs, onEvent: onEvent)
    }
    public nonisolated func watchInbox(initialSinceTs: Int64? = nil) -> AsyncThrowingStream<InboxWatchEvent, Error> {
        AsyncThrowingStream { continuation in
            let task = Task {
                do {
                    try await self.watchInbox(initialSinceTs: initialSinceTs) { continuation.yield($0) }
                    continuation.finish()
                } catch is CancellationError { continuation.finish() }
                catch let se as SyncError where se.code == .errCancelled { continuation.finish() }
                catch { continuation.finish(throwing: error) }
            }
            continuation.onTermination = { @Sendable _ in task.cancel() }
        }
    }

    public func revokeDevice(deviceId: String) async throws { try await revokeDeviceInternal(deviceId: deviceId) }
    public func revokeDevice(_ deviceId: String) async throws { try await revokeDeviceInternal(deviceId: deviceId) }

    public func close() {
        guard !isClosed else { return }
        isClosed = true; initTask?.cancel(); initTask = nil; initializedState = nil; pendingAckItems.removeAll()
        transport.close()
        let dirs = createdMsgDirs; createdMsgDirs.removeAll()
        for dir in dirs { try? FileManager.default.removeItem(at: dir) }
    }
}
