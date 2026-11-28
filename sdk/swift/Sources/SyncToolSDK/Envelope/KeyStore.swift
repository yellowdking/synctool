import Darwin
import Foundation
import Security

public let defaultSeenMsgRetentionDays: Int64 = 30
public let defaultSeenMsgMinEntries: Int = 4096

public struct DeviceCard: Codable, Sendable, Equatable, CustomStringConvertible {
    public var deviceId: String, label: String, platform: String, signPk: String, kemPk: String
    public var issuedAt: Int64, cardSig: String, relayOrigin: String, relayId: String, mailboxId: String
    public var outboundDepositToken: String, inboundTokenId: String, inboundTokenHash: String
    public var pairedAt: Int64, revoked: Bool, pendingTokenDelete: Bool
    enum CodingKeys: String, CodingKey {
        case deviceId = "device_id", label, platform, signPk = "sign_pk", kemPk = "kem_pk"
        case issuedAt = "issued_at", cardSig = "card_sig", relayOrigin = "relay_origin", relayId = "relay_id"
        case mailboxId = "mailbox_id", outboundDepositToken = "outbound_deposit_token"
        case inboundTokenId = "inbound_token_id", inboundTokenHash = "inbound_token_hash"
        case pairedAt = "paired_at", revoked, pendingTokenDelete = "pending_token_delete"
    }

    public init(
        deviceId: String, label: String, platform: String = "", signPk: String, kemPk: String, issuedAt: Int64,
        cardSig: String, relayOrigin: String = "", relayId: String = "", mailboxId: String = "",
        outboundDepositToken: String = "", inboundTokenId: String = "", inboundTokenHash: String = "",
        pairedAt: Int64 = 0, revoked: Bool = false, pendingTokenDelete: Bool = false
    ) {
        self.deviceId = deviceId; self.label = label; self.platform = platform; self.signPk = signPk; self.kemPk = kemPk
        self.issuedAt = issuedAt; self.cardSig = cardSig; self.relayOrigin = relayOrigin; self.relayId = relayId
        self.mailboxId = mailboxId; self.outboundDepositToken = outboundDepositToken; self.inboundTokenId = inboundTokenId
        self.inboundTokenHash = inboundTokenHash; self.pairedAt = pairedAt; self.revoked = revoked; self.pendingTokenDelete = pendingTokenDelete
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        deviceId = try c.decode(String.self, forKey: .deviceId)
        label = try c.decode(String.self, forKey: .label)
        platform = try c.decodeIfPresent(String.self, forKey: .platform) ?? ""
        signPk = try c.decode(String.self, forKey: .signPk)
        kemPk = try c.decode(String.self, forKey: .kemPk)
        issuedAt = try c.decode(Int64.self, forKey: .issuedAt)
        cardSig = try c.decode(String.self, forKey: .cardSig)
        relayOrigin = try c.decodeIfPresent(String.self, forKey: .relayOrigin) ?? ""
        relayId = try c.decodeIfPresent(String.self, forKey: .relayId) ?? ""
        mailboxId = try c.decodeIfPresent(String.self, forKey: .mailboxId) ?? ""
        outboundDepositToken = try c.decodeIfPresent(String.self, forKey: .outboundDepositToken) ?? ""
        inboundTokenId = try c.decodeIfPresent(String.self, forKey: .inboundTokenId) ?? ""
        inboundTokenHash = try c.decodeIfPresent(String.self, forKey: .inboundTokenHash) ?? ""
        pairedAt = try c.decodeIfPresent(Int64.self, forKey: .pairedAt) ?? 0
        revoked = try c.decodeIfPresent(Bool.self, forKey: .revoked) ?? false
        pendingTokenDelete = try c.decodeIfPresent(Bool.self, forKey: .pendingTokenDelete) ?? false
    }

    public var description: String {
        "DeviceCard(deviceId=\(deviceId), label=\(label), platform=\(platform), relayId=\(relayId), mailboxId=\(mailboxId), revoked=\(revoked), pendingTokenDelete=\(pendingTokenDelete), outboundDepositToken=[REDACTED])"
    }
}

public struct SeenMsgEntry: Codable, Sendable, Equatable {
    public var msgId: String, createdAt: Int64, seenAt: Int64
    enum CodingKeys: String, CodingKey { case msgId = "msg_id", createdAt = "created_at", seenAt = "seen_at" }
    public init(msgId: String, createdAt: Int64, seenAt: Int64) {
        self.msgId = msgId; self.createdAt = createdAt; self.seenAt = seenAt
    }
}

public struct CachedManifestEntry: Codable, Sendable, Equatable {
    public var itemId: String, cachedAt: Int64, expiresAt: Int64, manifestSha256: String, manifest: Manifest
    enum CodingKeys: String, CodingKey {
        case itemId = "item_id", cachedAt = "cached_at", expiresAt = "expires_at", manifestSha256 = "manifest_sha256", manifest
    }
    public init(itemId: String, cachedAt: Int64, expiresAt: Int64, manifestSha256: String = "", manifest: Manifest) {
        self.itemId = itemId; self.cachedAt = cachedAt; self.expiresAt = expiresAt; self.manifestSha256 = manifestSha256; self.manifest = manifest
    }
}

public struct TransferCheckpoint: Codable, Sendable, Equatable {
    public var key: String, direction: String, msgId: String, itemId: String
    public var partId: Int, nextTxIdx: Int, nextBlockIdx: Int64, uploadToken: String, expiresAt: Int64
    enum CodingKeys: String, CodingKey {
        case key, direction, msgId = "msg_id", itemId = "item_id", partId = "part_id"
        case nextTxIdx = "next_tx_idx", nextBlockIdx = "next_block_idx", uploadToken = "upload_token", expiresAt = "expires_at"
    }
    public init(
        key: String = "", direction: String, msgId: String, itemId: String = "", partId: Int,
        nextTxIdx: Int, nextBlockIdx: Int64, uploadToken: String = "", expiresAt: Int64 = 0
    ) {
        self.key = key.isEmpty ? Self.buildKey(direction: direction, msgId: msgId, partId: partId) : key
        self.direction = direction; self.msgId = msgId; self.itemId = itemId; self.partId = partId
        self.nextTxIdx = nextTxIdx; self.nextBlockIdx = nextBlockIdx; self.uploadToken = uploadToken; self.expiresAt = expiresAt
    }
    public static func buildKey(direction: String, msgId: String, partId: Int) -> String { "\(direction):\(msgId.lowercased()):\(partId)" }
}

public enum LocalMetaCacheCodec {
    public static func sealCachedManifest(localMetaKey32: Data, entry: CachedManifestEntry) throws -> String {
        let raw = try JSONEncoder().encode(entry)
        return SyncCrypto.b64uEncode(try StreamCipher.sealLocalMeta(localMetaKey32: localMetaKey32, context: "synctool-v1/manifest-cache:\(entry.itemId)", plaintext: raw))
    }

    public static func openCachedManifest(localMetaKey32: Data, itemId: String, sealedB64u: String) -> CachedManifestEntry? {
        guard let blob = try? SyncCrypto.b64uDecode(sealedB64u),
              let raw = try? StreamCipher.openLocalMeta(localMetaKey32: localMetaKey32, context: "synctool-v1/manifest-cache:\(itemId)", blob: blob) else { return nil }
        return try? JSONDecoder().decode(CachedManifestEntry.self, from: raw)
    }

    public static func sealCheckpoint(localMetaKey32: Data, cp: TransferCheckpoint) throws -> String {
        let key = cp.key.isEmpty ? TransferCheckpoint.buildKey(direction: cp.direction, msgId: cp.msgId, partId: cp.partId) : cp.key
        var norm = cp; norm.key = key
        let raw = try JSONEncoder().encode(norm)
        return SyncCrypto.b64uEncode(try StreamCipher.sealLocalMeta(localMetaKey32: localMetaKey32, context: "synctool-v1/checkpoint:\(key)", plaintext: raw))
    }

    public static func openCheckpoint(localMetaKey32: Data, key: String, sealedB64u: String) -> TransferCheckpoint? {
        guard let blob = try? SyncCrypto.b64uDecode(sealedB64u),
              let raw = try? StreamCipher.openLocalMeta(localMetaKey32: localMetaKey32, context: "synctool-v1/checkpoint:\(key)", blob: blob) else { return nil }
        return try? JSONDecoder().decode(TransferCheckpoint.self, from: raw)
    }
}

// MARK: - SyncKeyStore Protocol & Memory / File / Keychain Actors (`ENVELOPE_AND_SDK.md` §5.1)

public protocol SyncKeyStore: Sendable {
    func loadOrCreateMasterSeed() async throws -> Data
    func getLocalLabel() async throws -> String?
    func setLocalLabel(_ label: String) async throws
    func getRelayProfile(_ relayIdOrAlias: String) async throws -> RelayProfile?
    func getDefaultRelayProfile() async throws -> RelayProfile?
    func listRelayProfiles() async throws -> [RelayProfile]
    func saveRelayProfile(_ profile: RelayProfile) async throws
    func listDevices() async throws -> [DeviceCard]
    func listAllDevices() async throws -> [DeviceCard]
    func getDevice(_ deviceId: String) async throws -> DeviceCard?
    func putDevice(_ card: DeviceCard) async throws
    func deleteDevice(_ deviceId: String) async throws
    func addPendingTokenDelete(_ tokenId: String) async throws
    func listPendingTokenDeletes() async throws -> [String]
    func removePendingTokenDelete(_ tokenId: String) async throws
    func hasSeenMsgId(_ msgId: String) async throws -> Bool
    func markSeenMsgId(_ msgId: String, createdAt: Int64, seenAt: Int64) async throws
    func getReplayWatermark() async throws -> Int64
    func getCachedManifest(_ itemId: String) async throws -> CachedManifestEntry?
    func putCachedManifest(_ entry: CachedManifestEntry) async throws
    func deleteCachedManifest(_ itemId: String) async throws
    func pruneCachedManifests(_ activeItemIds: Set<String>) async throws
    func getCheckpoint(direction: String, msgId: String, partId: Int) async throws -> TransferCheckpoint?
    func putCheckpoint(_ cp: TransferCheckpoint) async throws
    func deleteCheckpoint(direction: String, msgId: String, partId: Int) async throws
}

public typealias KeyStore = SyncKeyStore

internal struct PersistedKeyStoreState: Codable {
    var version: Int = 1
    var masterSeedB64u: String?
    var localLabel: String?
    var replayWatermarkTs: Int64 = 0
    var pendingTokenDeletes: [String] = []
    var relays: [String: RelayProfile] = [:]
    var devices: [String: DeviceCard] = [:]
    var seenMsgs: [String: SeenMsgEntry] = [:]
    var sealedManifestCache: [String: String] = [:]
    var sealedCheckpoints: [String: String] = [:]

    func relay(_ idOrAlias: String) -> RelayProfile? {
        relays[idOrAlias] ?? relays.values.first { !$0.alias.isEmpty && $0.alias.caseInsensitiveCompare(idOrAlias) == .orderedSame }
    }
    func defaultRelay() -> RelayProfile? { relays.values.first { $0.isDefault } ?? relays.values.min { $0.relayId < $1.relayId } }
    func sortedRelays() -> [RelayProfile] { relays.values.sorted { $0.relayId < $1.relayId } }
    func activeDevices() -> [DeviceCard] { devices.values.filter { !$0.revoked }.sorted { $0.pairedAt < $1.pairedAt } }
    func allDevices() -> [DeviceCard] { devices.values.sorted { $0.pairedAt < $1.pairedAt } }
    func device(_ id: String) -> DeviceCard? { devices[id.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()] }
    func hasSeen(_ id: String) -> Bool { seenMsgs[id.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()] != nil }

    mutating func saveRelay(_ profile: RelayProfile) {
        var u = profile
        if u.isDefault || relays.isEmpty {
            u.isDefault = true
            for k in relays.keys where k != u.relayId { relays[k]?.isDefault = false }
        }
        relays[u.relayId] = u
    }
    mutating func upsertDevice(_ card: DeviceCard) {
        var c = card; c.deviceId = c.deviceId.trimmingCharacters(in: .whitespacesAndNewlines).lowercased(); devices[c.deviceId] = c
    }
    mutating func addPendingTok(_ tok: String) -> Bool {
        let t = tok.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !t.isEmpty && !pendingTokenDeletes.contains(t) else { return false }
        pendingTokenDeletes.append(t); return true
    }
    mutating func markSeen(_ msgId: String, createdAt: Int64, seenAt: Int64) {
        let id = msgId.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        seenMsgs[id] = SeenMsgEntry(msgId: id, createdAt: createdAt, seenAt: seenAt)
        if seenMsgs.count > defaultSeenMsgMinEntries {
            let cutoff = Int64(Date().timeIntervalSince1970) - defaultSeenMsgRetentionDays * 86_400
            for entry in seenMsgs.values.sorted(by: { $0.seenAt < $1.seenAt }) {
                if seenMsgs.count <= defaultSeenMsgMinEntries { break }
                if entry.seenAt < cutoff {
                    seenMsgs.removeValue(forKey: entry.msgId)
                    if entry.createdAt > replayWatermarkTs { replayWatermarkTs = entry.createdAt }
                }
            }
        }
    }
    mutating func openManifest(_ itemId: String, mk: Data) -> CachedManifestEntry? {
        guard let sealed = sealedManifestCache[itemId] else { return nil }
        let opened = LocalMetaCacheCodec.openCachedManifest(localMetaKey32: mk, itemId: itemId, sealedB64u: sealed)
        if opened == nil { sealedManifestCache.removeValue(forKey: itemId) }
        return opened
    }
    mutating func pruneManifests(_ activeIds: Set<String>) -> Bool {
        var changed = false
        for k in Array(sealedManifestCache.keys) where !activeIds.contains(k) { sealedManifestCache.removeValue(forKey: k); changed = true }
        return changed
    }
    mutating func openCheckpoint(direction: String, msgId: String, partId: Int, mk: Data) -> TransferCheckpoint? {
        let k = TransferCheckpoint.buildKey(direction: direction, msgId: msgId, partId: partId)
        guard let sealed = sealedCheckpoints[k] else { return nil }
        let nowSec = Int64(Date().timeIntervalSince1970)
        guard let cp = LocalMetaCacheCodec.openCheckpoint(localMetaKey32: mk, key: k, sealedB64u: sealed),
              cp.expiresAt <= 0 || cp.expiresAt >= nowSec else {
            sealedCheckpoints.removeValue(forKey: k); return nil
        }
        return cp
    }
}

public actor MemoryKeyStore: SyncKeyStore {
    private var masterSeed: Data?, localMetaKey: Data?
    private var st = PersistedKeyStoreState()

    public init(initialSeed: Data? = nil) {
        if let seed = initialSeed, seed.count == SyncCrypto.masterSeedSize {
            self.masterSeed = Data(seed); self.localMetaKey = (try? DeviceKeys.fromMasterSeed(seed))?.localMetaKey
        }
    }
    private func loadSeed() throws -> Data {
        if let s = masterSeed { return s }
        let gen = try SyncCrypto.generateMasterSeed()
        masterSeed = gen; localMetaKey = try DeviceKeys.fromMasterSeed(gen).localMetaKey
        return gen
    }
    private func mk() throws -> Data { if let k = localMetaKey { return k }; return try DeviceKeys.fromMasterSeed(loadSeed()).localMetaKey }

    public func loadOrCreateMasterSeed() async throws -> Data { try loadSeed() }
    public func getLocalLabel() async throws -> String? { st.localLabel }
    public func setLocalLabel(_ label: String) async throws { st.localLabel = label.trimmingCharacters(in: .whitespacesAndNewlines) }
    public func getRelayProfile(_ idOrAlias: String) async throws -> RelayProfile? { st.relay(idOrAlias) }
    public func getDefaultRelayProfile() async throws -> RelayProfile? { st.defaultRelay() }
    public func listRelayProfiles() async throws -> [RelayProfile] { st.sortedRelays() }
    public func saveRelayProfile(_ profile: RelayProfile) async throws { st.saveRelay(profile) }
    public func listDevices() async throws -> [DeviceCard] { st.activeDevices() }
    public func listAllDevices() async throws -> [DeviceCard] { st.allDevices() }
    public func getDevice(_ deviceId: String) async throws -> DeviceCard? { st.device(deviceId) }
    public func putDevice(_ card: DeviceCard) async throws { st.upsertDevice(card) }
    public func deleteDevice(_ deviceId: String) async throws { st.devices.removeValue(forKey: deviceId.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()) }
    public func addPendingTokenDelete(_ tokenId: String) async throws { _ = st.addPendingTok(tokenId) }
    public func listPendingTokenDeletes() async throws -> [String] { st.pendingTokenDeletes }
    public func removePendingTokenDelete(_ tokenId: String) async throws { st.pendingTokenDeletes.removeAll { $0 == tokenId.trimmingCharacters(in: .whitespacesAndNewlines) } }
    public func hasSeenMsgId(_ msgId: String) async throws -> Bool { st.hasSeen(msgId) }
    public func markSeenMsgId(_ msgId: String, createdAt: Int64, seenAt: Int64) async throws { st.markSeen(msgId, createdAt: createdAt, seenAt: seenAt) }
    public func getReplayWatermark() async throws -> Int64 { st.replayWatermarkTs }
    public func getCachedManifest(_ itemId: String) async throws -> CachedManifestEntry? { try st.openManifest(itemId, mk: mk()) }
    public func putCachedManifest(_ entry: CachedManifestEntry) async throws { st.sealedManifestCache[entry.itemId] = try LocalMetaCacheCodec.sealCachedManifest(localMetaKey32: mk(), entry: entry) }
    public func deleteCachedManifest(_ itemId: String) async throws { st.sealedManifestCache.removeValue(forKey: itemId) }
    public func pruneCachedManifests(_ activeItemIds: Set<String>) async throws { _ = st.pruneManifests(activeItemIds) }
    public func getCheckpoint(direction: String, msgId: String, partId: Int) async throws -> TransferCheckpoint? { try st.openCheckpoint(direction: direction, msgId: msgId, partId: partId, mk: mk()) }
    public func putCheckpoint(_ cp: TransferCheckpoint) async throws {
        let k = TransferCheckpoint.buildKey(direction: cp.direction, msgId: cp.msgId, partId: cp.partId)
        st.sealedCheckpoints[k] = try LocalMetaCacheCodec.sealCheckpoint(localMetaKey32: mk(), cp: cp)
    }
    public func deleteCheckpoint(direction: String, msgId: String, partId: Int) async throws {
        st.sealedCheckpoints.removeValue(forKey: TransferCheckpoint.buildKey(direction: direction, msgId: msgId, partId: partId))
    }
}

public actor FileKeyStore: SyncKeyStore {
    private let fileURL: URL
    private var st: PersistedKeyStoreState

    public init(directoryURL: URL) throws {
        var dirStat = Darwin.stat()
        if directoryURL.path.withCString({ Darwin.lstat($0, &dirStat) }) == 0 {
            guard (dirStat.st_mode & S_IFMT) == S_IFDIR else {
                throw SyncError(code: .errKeystoreError, message: "keystore dir must be a real directory, not a symlink")
            }
        } else if (try? FileManager.default.createDirectory(at: directoryURL, withIntermediateDirectories: true)) == nil {
            throw SyncError(code: .errKeystoreError, message: "create keystore dir failed")
        }
        _ = directoryURL.path.withCString { Darwin.chmod($0, mode_t(0o700)) }
        self.fileURL = directoryURL.appendingPathComponent("keystore.json", isDirectory: false)
        if FileManager.default.fileExists(atPath: fileURL.path) {
            guard let data = try? Data(contentsOf: fileURL), let decoded = try? JSONDecoder().decode(PersistedKeyStoreState.self, from: data) else {
                throw SyncError(code: .errKeystoreError, message: "corrupted keystore.json")
            }
            self.st = decoded
        } else { self.st = PersistedKeyStoreState() }
    }

    private func persist() throws { try writeRestrictedFileAtomically(JSONEncoder().encode(st), to: fileURL) }
    private func ensureSeed() throws -> Data {
        if let b64 = st.masterSeedB64u, !b64.isEmpty {
            guard let raw = try? SyncCrypto.b64uDecode(b64), raw.count == 32 else {
                throw SyncError(code: .errKeystoreError, message: "corrupted master seed in keystore.json")
            }
            return raw
        }
        let gen = try SyncCrypto.generateMasterSeed()
        st.masterSeedB64u = SyncCrypto.b64uEncode(gen); try persist()
        return gen
    }
    private func mk() throws -> Data { try DeviceKeys.fromMasterSeed(ensureSeed()).localMetaKey }

    public func loadOrCreateMasterSeed() async throws -> Data { try ensureSeed() }
    public func getLocalLabel() async throws -> String? { st.localLabel }
    public func setLocalLabel(_ label: String) async throws { st.localLabel = label.trimmingCharacters(in: .whitespacesAndNewlines); try persist() }
    public func getRelayProfile(_ idOrAlias: String) async throws -> RelayProfile? { st.relay(idOrAlias) }
    public func getDefaultRelayProfile() async throws -> RelayProfile? { st.defaultRelay() }
    public func listRelayProfiles() async throws -> [RelayProfile] { st.sortedRelays() }
    public func saveRelayProfile(_ profile: RelayProfile) async throws { st.saveRelay(profile); try persist() }
    public func listDevices() async throws -> [DeviceCard] { st.activeDevices() }
    public func listAllDevices() async throws -> [DeviceCard] { st.allDevices() }
    public func getDevice(_ deviceId: String) async throws -> DeviceCard? { st.device(deviceId) }
    public func putDevice(_ card: DeviceCard) async throws { st.upsertDevice(card); try persist() }
    public func deleteDevice(_ deviceId: String) async throws { st.devices.removeValue(forKey: deviceId.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()); try persist() }
    public func addPendingTokenDelete(_ tokenId: String) async throws { if st.addPendingTok(tokenId) { try persist() } }
    public func listPendingTokenDeletes() async throws -> [String] { st.pendingTokenDeletes }
    public func removePendingTokenDelete(_ tokenId: String) async throws { st.pendingTokenDeletes.removeAll { $0 == tokenId.trimmingCharacters(in: .whitespacesAndNewlines) }; try persist() }
    public func hasSeenMsgId(_ msgId: String) async throws -> Bool { st.hasSeen(msgId) }
    public func markSeenMsgId(_ msgId: String, createdAt: Int64, seenAt: Int64) async throws { st.markSeen(msgId, createdAt: createdAt, seenAt: seenAt); try persist() }
    public func getReplayWatermark() async throws -> Int64 { st.replayWatermarkTs }
    public func getCachedManifest(_ itemId: String) async throws -> CachedManifestEntry? { try st.openManifest(itemId, mk: mk()) }
    public func putCachedManifest(_ entry: CachedManifestEntry) async throws { st.sealedManifestCache[entry.itemId] = try LocalMetaCacheCodec.sealCachedManifest(localMetaKey32: mk(), entry: entry); try persist() }
    public func deleteCachedManifest(_ itemId: String) async throws { st.sealedManifestCache.removeValue(forKey: itemId); try persist() }
    public func pruneCachedManifests(_ activeItemIds: Set<String>) async throws { if st.pruneManifests(activeItemIds) { try persist() } }
    public func getCheckpoint(direction: String, msgId: String, partId: Int) async throws -> TransferCheckpoint? { try st.openCheckpoint(direction: direction, msgId: msgId, partId: partId, mk: mk()) }
    public func putCheckpoint(_ cp: TransferCheckpoint) async throws {
        let k = TransferCheckpoint.buildKey(direction: cp.direction, msgId: cp.msgId, partId: cp.partId)
        st.sealedCheckpoints[k] = try LocalMetaCacheCodec.sealCheckpoint(localMetaKey32: mk(), cp: cp); try persist()
    }
    public func deleteCheckpoint(direction: String, msgId: String, partId: Int) async throws {
        st.sealedCheckpoints.removeValue(forKey: TransferCheckpoint.buildKey(direction: direction, msgId: msgId, partId: partId)); try persist()
    }
}

/// Hardware-backed Keychain `SyncKeyStore` storing ONLY 32B `device_master_seed` in Apple Keychain
/// (`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`) and sealing the local state file with `LocalMetaKey`.
public actor KeychainKeyStore: SyncKeyStore {
    private let service: String, account: String, stateFileURL: URL
    private var cachedSeed: Data?, loaded = false
    private var st = PersistedKeyStoreState()

    public init(service: String = "com.yellowdking.synctool", account: String = "device_master_seed", stateFileURL: URL) {
        self.service = service; self.account = account; self.stateFileURL = stateFileURL
    }

    private func ensureLoaded() throws -> (Data, Data) {
        let seed: Data
        if let s = cachedSeed {
            seed = s
        } else {
            let s = try keychainLoadOrCreateSeed()
            cachedSeed = s
            seed = s
        }
        let mk = try DeviceKeys.fromMasterSeed(seed).localMetaKey
        if !loaded {
            if FileManager.default.fileExists(atPath: stateFileURL.path) {
                let pt = try StreamCipher.openLocalMeta(localMetaKey32: mk, context: "synctool-v1/keychain-state-v1", blob: Data(contentsOf: stateFileURL))
                st = try JSONDecoder().decode(PersistedKeyStoreState.self, from: pt)
            }
            loaded = true
        }
        return (seed, mk)
    }

    private func persist(_ mk: Data) throws {
        st.masterSeedB64u = nil
        let sealed = try StreamCipher.sealLocalMeta(localMetaKey32: mk, context: "synctool-v1/keychain-state-v1", plaintext: JSONEncoder().encode(st))
        try? FileManager.default.createDirectory(at: stateFileURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        try writeRestrictedFileAtomically(sealed, to: stateFileURL)
    }

    private func keychainLoadOrCreateSeed() throws -> Data {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service,
            kSecAttrAccount as String: account, kSecReturnData as String: true, kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecSuccess, let data = item as? Data, data.count == 32 { return data }
        guard status == errSecItemNotFound else { throw SyncError(code: .errKeystoreError, message: "Keychain read failed (\(status))") }
        let gen = try SyncCrypto.generateMasterSeed()
        let addAttrs: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: account,
            kSecValueData as String: gen, kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ]
        let addStatus = SecItemAdd(addAttrs as CFDictionary, nil)
        if addStatus == errSecDuplicateItem {
            var retry: CFTypeRef?
            if SecItemCopyMatching(query as CFDictionary, &retry) == errSecSuccess, let d = retry as? Data, d.count == 32 { return d }
        }
        guard addStatus == errSecSuccess else { throw SyncError(code: .errKeystoreError, message: "Keychain write failed (\(addStatus))") }
        return gen
    }

    public func loadOrCreateMasterSeed() async throws -> Data { try ensureLoaded().0 }
    public func getLocalLabel() async throws -> String? { _ = try ensureLoaded(); return st.localLabel }
    public func setLocalLabel(_ label: String) async throws { let (_, mk) = try ensureLoaded(); st.localLabel = label.trimmingCharacters(in: .whitespacesAndNewlines); try persist(mk) }
    public func getRelayProfile(_ idOrAlias: String) async throws -> RelayProfile? { _ = try ensureLoaded(); return st.relay(idOrAlias) }
    public func getDefaultRelayProfile() async throws -> RelayProfile? { _ = try ensureLoaded(); return st.defaultRelay() }
    public func listRelayProfiles() async throws -> [RelayProfile] { _ = try ensureLoaded(); return st.sortedRelays() }
    public func saveRelayProfile(_ profile: RelayProfile) async throws { let (_, mk) = try ensureLoaded(); st.saveRelay(profile); try persist(mk) }
    public func listDevices() async throws -> [DeviceCard] { _ = try ensureLoaded(); return st.activeDevices() }
    public func listAllDevices() async throws -> [DeviceCard] { _ = try ensureLoaded(); return st.allDevices() }
    public func getDevice(_ deviceId: String) async throws -> DeviceCard? { _ = try ensureLoaded(); return st.device(deviceId) }
    public func putDevice(_ card: DeviceCard) async throws { let (_, mk) = try ensureLoaded(); st.upsertDevice(card); try persist(mk) }
    public func deleteDevice(_ deviceId: String) async throws { let (_, mk) = try ensureLoaded(); st.devices.removeValue(forKey: deviceId.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()); try persist(mk) }
    public func addPendingTokenDelete(_ tokenId: String) async throws { let (_, mk) = try ensureLoaded(); if st.addPendingTok(tokenId) { try persist(mk) } }
    public func listPendingTokenDeletes() async throws -> [String] { _ = try ensureLoaded(); return st.pendingTokenDeletes }
    public func removePendingTokenDelete(_ tokenId: String) async throws { let (_, mk) = try ensureLoaded(); st.pendingTokenDeletes.removeAll { $0 == tokenId.trimmingCharacters(in: .whitespacesAndNewlines) }; try persist(mk) }
    public func hasSeenMsgId(_ msgId: String) async throws -> Bool { _ = try ensureLoaded(); return st.hasSeen(msgId) }
    public func markSeenMsgId(_ msgId: String, createdAt: Int64, seenAt: Int64) async throws { let (_, mk) = try ensureLoaded(); st.markSeen(msgId, createdAt: createdAt, seenAt: seenAt); try persist(mk) }
    public func getReplayWatermark() async throws -> Int64 { _ = try ensureLoaded(); return st.replayWatermarkTs }
    public func getCachedManifest(_ itemId: String) async throws -> CachedManifestEntry? { let (_, mk) = try ensureLoaded(); return st.openManifest(itemId, mk: mk) }
    public func putCachedManifest(_ entry: CachedManifestEntry) async throws { let (_, mk) = try ensureLoaded(); st.sealedManifestCache[entry.itemId] = try LocalMetaCacheCodec.sealCachedManifest(localMetaKey32: mk, entry: entry); try persist(mk) }
    public func deleteCachedManifest(_ itemId: String) async throws { let (_, mk) = try ensureLoaded(); st.sealedManifestCache.removeValue(forKey: itemId); try persist(mk) }
    public func pruneCachedManifests(_ activeItemIds: Set<String>) async throws { let (_, mk) = try ensureLoaded(); if st.pruneManifests(activeItemIds) { try persist(mk) } }
    public func getCheckpoint(direction: String, msgId: String, partId: Int) async throws -> TransferCheckpoint? { let (_, mk) = try ensureLoaded(); return st.openCheckpoint(direction: direction, msgId: msgId, partId: partId, mk: mk) }
    public func putCheckpoint(_ cp: TransferCheckpoint) async throws {
        let (_, mk) = try ensureLoaded(); let k = TransferCheckpoint.buildKey(direction: cp.direction, msgId: cp.msgId, partId: cp.partId)
        st.sealedCheckpoints[k] = try LocalMetaCacheCodec.sealCheckpoint(localMetaKey32: mk, cp: cp); try persist(mk)
    }
    public func deleteCheckpoint(direction: String, msgId: String, partId: Int) async throws {
        let (_, mk) = try ensureLoaded(); st.sealedCheckpoints.removeValue(forKey: TransferCheckpoint.buildKey(direction: direction, msgId: msgId, partId: partId)); try persist(mk)
    }
}

private func writeRestrictedFileAtomically(_ data: Data, to fileURL: URL) throws {
    do {
        #if os(iOS)
        try data.write(to: fileURL, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
        #else
        try data.write(to: fileURL, options: [.atomic])
        _ = fileURL.path.withCString { Darwin.chmod($0, mode_t(0o600)) }
        #endif
    } catch {
        throw SyncError(code: .errKeystoreError, message: "persist keystore state failed")
    }
}
