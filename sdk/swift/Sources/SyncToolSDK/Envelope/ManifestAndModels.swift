import Darwin
import Foundation

// MARK: - Universal Parcel Manifest, Streaming Blobs & Safe File Extraction (`ENVELOPE_AND_SDK.md` §2)

public struct SenderInfo: Codable, Sendable, Equatable {
    public var deviceId: String, label: String, platform: String?
    enum CodingKeys: String, CodingKey { case deviceId = "device_id", label, platform }
    public init(deviceId: String, label: String, platform: String? = nil) {
        self.deviceId = deviceId; self.label = label; self.platform = platform
    }
}

public struct BlobDescriptor: Codable, Sendable, Equatable {
    public var partId: Int, role: String, name: String, mime: String, size: Int64, sha256: String, key: String, encoding: String?, meta: [String: JSONValue]?
    enum CodingKeys: String, CodingKey { case partId = "part_id", role, name, mime, size, sha256, key, encoding, meta }
    public init(partId: Int, role: String, name: String, mime: String, size: Int64, sha256: String, key: String, encoding: String? = "identity", meta: [String: JSONValue]? = nil) {
        self.partId = partId; self.role = role; self.name = name; self.mime = mime; self.size = size
        self.sha256 = sha256; self.key = key; self.encoding = encoding; self.meta = meta
    }
}

public struct Manifest: Codable, Sendable, Equatable {
    public var envelopeVersion: Int, msgId: String, appId: String, schema: String, createdAt: Int64
    public var sender: SenderInfo, inlinePayload: [String: JSONValue]?, blobs: [BlobDescriptor]
    enum CodingKeys: String, CodingKey {
        case envelopeVersion = "envelope_version", msgId = "msg_id", appId = "app_id", schema
        case createdAt = "created_at", sender, inlinePayload = "inline_payload", blobs
    }
    public init(
        envelopeVersion: Int = ManifestCodec.envelopeVersion, msgId: String, appId: String, schema: String,
        createdAt: Int64, sender: SenderInfo, inlinePayload: [String: JSONValue]? = nil, blobs: [BlobDescriptor] = []
    ) {
        self.envelopeVersion = envelopeVersion; self.msgId = msgId; self.appId = appId; self.schema = schema
        self.createdAt = createdAt; self.sender = sender; self.inlinePayload = inlinePayload; self.blobs = blobs
    }
}

public enum ManifestCodec {
    public static let envelopeVersion = 1
    public static let maxInlinePayloadBytes = 65536
    public static let maxManifestBytes = StreamCipher.manifestMaxRawBytes
    public static let maxPaddedManifestBytes = StreamCipher.maxManifestPaddedBytes
    public static let maxEncryptedManifestBytes = StreamCipher.maxManifestCiphertextBytes
    public static let maxManifestChunks = 4
    public static let maxBlobs = StreamCipher.maxPartId
    public static let maxBlobMetaBytes = 2048
    public static let maxSafeIntJs: Int64 = 9_007_199_254_740_991

    private static let appSchemaRegex = try! NSRegularExpression(pattern: #"^[a-z0-9][a-z0-9._-]{1,63}$"#)
    private static let roleRegex = try! NSRegularExpression(pattern: #"^[a-z0-9][a-z0-9._-]{0,31}$"#)

    public static func validate(_ m: Manifest) throws -> Data {
        if m.envelopeVersion > envelopeVersion {
            throw SyncError(code: .errUnsupportedVersion, message: "unsupported envelope_version \(m.envelopeVersion)", details: ["envelope_version": "\(m.envelopeVersion)", "supported_version": "1"])
        }
        guard m.envelopeVersion == envelopeVersion, SyncCrypto.isLowerHex(m.msgId, count: 32),
              matches(appSchemaRegex, m.appId), matches(appSchemaRegex, m.schema), m.createdAt >= 0,
              SyncCrypto.isLowerHex(m.sender.deviceId, count: 32), (1...64).contains(m.sender.label.unicodeScalars.count),
              m.blobs.count <= maxBlobs else {
            throw SyncError(code: .errManifestInvalid, message: "invalid manifest header fields")
        }
        let encoder = JSONEncoder()
        if let inline = m.inlinePayload, (try encoder.encode(inline)).count > maxInlinePayloadBytes {
            throw SyncError(code: .errManifestInvalid, message: "inline_payload exceeds 65536 bytes")
        }
        var seenParts = Set<Int>()
        for blob in m.blobs {
            guard (1...maxBlobs).contains(blob.partId), seenParts.insert(blob.partId).inserted,
                  matches(roleRegex, blob.role), (1...255).contains(blob.name.unicodeScalars.count),
                  (1...128).contains(blob.mime.count), blob.size >= 0 && blob.size <= maxSafeIntJs,
                  SyncCrypto.isLowerHex(blob.sha256, count: 64),
                  let rawKey = try? SyncCrypto.b64uDecode(blob.key), rawKey.count == 32 else {
                throw SyncError(code: .errManifestInvalid, message: "invalid blob descriptor in manifest")
            }
            if let enc = blob.encoding, !enc.isEmpty, enc != "identity" && enc != "gzip" && enc != "zstd" {
                throw SyncError(code: .errManifestInvalid, message: "invalid blob encoding")
            }
            if let meta = blob.meta, (try encoder.encode(meta)).count > maxBlobMetaBytes {
                throw SyncError(code: .errManifestInvalid, message: "blob meta exceeds 2048 bytes")
            }
        }
        let raw = try encoder.encode(m)
        guard !raw.isEmpty && raw.count <= maxManifestBytes else {
            throw SyncError(code: .errManifestInvalid, message: "manifest exceeds 131072 bytes")
        }
        return raw
    }

    public static func marshalManifest(_ m: Manifest) throws -> Data { try validate(m) }

    public static func parseManifest(_ raw: Data) throws -> Manifest {
        guard !raw.isEmpty && raw.count <= maxManifestBytes, String(data: raw, encoding: .utf8) != nil,
              let root = (try? JSONSerialization.jsonObject(with: raw)) as? [String: Any] else {
            throw SyncError(code: .errManifestInvalid, message: "manifest JSON object invalid")
        }
        if let ev = root["envelope_version"] as? Int, ev > envelopeVersion {
            throw SyncError(code: .errUnsupportedVersion, message: "unsupported envelope_version \(ev)", details: ["envelope_version": "\(ev)", "supported_version": "1"])
        }
        guard root["blobs"] is [Any], let m = try? JSONDecoder().decode(Manifest.self, from: raw) else {
            throw SyncError(code: .errManifestInvalid, message: "parse manifest fields failed")
        }
        _ = try validate(m)
        return m
    }

    public static func sanitizeFilename(_ rawName: String) -> String {
        var name = rawName.replacingOccurrences(of: "\\", with: "/")
        if let slash = name.lastIndex(of: "/") { name = String(name[name.index(after: slash)...]) }
        var scalars = String.UnicodeScalarView()
        for sc in name.unicodeScalars {
            let v = sc.value
            if v == 0xFFFD || (0x202A...0x202E).contains(v) || (0x2066...0x2069).contains(v) || v == 0x200E || v == 0x200F || v == 0x061C { continue }
            if v <= 0x1F || (0x7F...0x9F).contains(v) || [0x2F, 0x5C, 0x3A, 0x2A, 0x3F, 0x22, 0x3C, 0x3E, 0x7C].contains(v) {
                scalars.append("_"); continue
            }
            scalars.append(sc)
        }
        let trimSet = CharacterSet.whitespacesAndNewlines.union(CharacterSet(charactersIn: "."))
        var out = String(scalars).trimmingCharacters(in: trimSet)
        if out.isEmpty || out.trimmingCharacters(in: CharacterSet(charactersIn: "._")).isEmpty { return "blob.bin" }
        out = truncateUtf8Safe(out, maxBytes: 199).trimmingCharacters(in: trimSet)
        if out.isEmpty || out == "." || out == ".." { return "blob.bin" }
        let stem = out.firstIndex(of: ".").map { String(out[..<$0]) } ?? out
        return isWindowsReservedStem(stem) ? "_\(out)" : out
    }

    private static func isWindowsReservedStem(_ stem: String) -> Bool {
        let u = stem.trimmingCharacters(in: .whitespacesAndNewlines).uppercased()
        if ["CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$", "COM\u{00B9}", "COM\u{00B2}", "COM\u{00B3}", "LPT\u{00B9}", "LPT\u{00B2}", "LPT\u{00B3}"].contains(u) { return true }
        guard (u.hasPrefix("COM") || u.hasPrefix("LPT")) && u.count == 4, let last = u.last else { return false }
        return last >= "1" && last <= "9"
    }

    private static func truncateUtf8Safe(_ s: String, maxBytes: Int) -> String {
        if s.utf8.count <= maxBytes { return s }
        let ext = s.lastIndex(of: ".").flatMap { dot -> String? in
            guard dot > s.startIndex else { return nil }
            let c = String(s[dot...]); return ((1...16).contains(c.utf8.count) && c.utf8.count < maxBytes) ? c : nil
        } ?? ""
        let stem = ext.isEmpty ? s : String(s.dropLast(ext.count)), budget = maxBytes - ext.utf8.count
        var out = String.UnicodeScalarView(), used = 0
        for sc in stem.unicodeScalars {
            if used + sc.utf8.count > budget { break }
            out.append(sc); used += sc.utf8.count
        }
        let trimmed = String(out).trimmingCharacters(in: CharacterSet.whitespacesAndNewlines.union(CharacterSet(charactersIn: ".")))
        return trimmed.isEmpty ? "blob.bin" : trimmed + ext
    }

    private static func matches(_ regex: NSRegularExpression, _ s: String) -> Bool {
        regex.firstMatch(in: s, options: [], range: NSRange(s.startIndex..<s.endIndex, in: s)) != nil
    }
}

public final class BlobReader {
    public let size: Int64
    private let readFn: (Int) throws -> Data, closeFn: () -> Void
    internal init(size: Int64, readFn: @escaping (Int) throws -> Data, closeFn: @escaping () -> Void) {
        self.size = size; self.readFn = readFn; self.closeFn = closeFn
    }
    deinit { closeFn() }
    public func readChunk(maxBytes: Int) throws -> Data { try readFn(maxBytes) }
    public func close() { closeFn() }
}

public struct BlobInput: Sendable {
    public let role: String, name: String, mime: String, encoding: String, meta: [String: JSONValue]?
    private let opener: @Sendable () throws -> BlobReader

    public init(
        role: String = "file", name: String, mime: String = "application/octet-stream",
        encoding: String = "identity", meta: [String: JSONValue]? = nil, opener: @escaping @Sendable () throws -> BlobReader
    ) {
        self.role = role.isEmpty ? "file" : role; self.name = name
        self.mime = mime.isEmpty ? "application/octet-stream" : mime
        self.encoding = encoding.isEmpty ? "identity" : encoding; self.meta = meta; self.opener = opener
    }

    public func openReader() throws -> BlobReader { try opener() }

    public static func fromData(
        _ data: Data, name: String, role: String = "file",
        mime: String = "application/octet-stream", encoding: String = "identity", meta: [String: JSONValue]? = nil
    ) -> BlobInput {
        let copy = Data(data)
        return BlobInput(role: role, name: name, mime: mime, encoding: encoding, meta: meta) {
            var off = 0
            return BlobReader(size: Int64(copy.count), readFn: { maxBytes in
                guard off < copy.count && maxBytes > 0 else { return Data() }
                let take = min(maxBytes, copy.count - off), slice = Data(copy[off..<(off + take)])
                off += take; return slice
            }, closeFn: {})
        }
    }

    public static func fromBytes(
        _ bytes: Data, name: String, role: String = "file",
        mime: String = "application/octet-stream", encoding: String = "identity", meta: [String: JSONValue]? = nil
    ) -> BlobInput { fromData(bytes, name: name, role: role, mime: mime, encoding: encoding, meta: meta) }

    public static func fromFile(
        _ fileURL: URL, role: String = "file", name: String? = nil,
        mime: String? = nil, encoding: String = "identity", meta: [String: JSONValue]? = nil
    ) -> BlobInput {
        let resolvedName = (name?.isEmpty == false) ? name! : fileURL.lastPathComponent
        let resolvedMime = (mime?.isEmpty == false) ? mime! : inferBasicMime(resolvedName)
        return BlobInput(role: role, name: resolvedName, mime: resolvedMime, encoding: encoding, meta: meta) {
            var st = Darwin.stat()
            guard fileURL.path.withCString({ Darwin.lstat($0, &st) }) == 0 && (st.st_mode & S_IFMT) == S_IFREG,
                  let fh = try? FileHandle(forReadingFrom: fileURL) else {
                throw SyncError(code: .errStorageIo, message: "blob file must be a readable regular non-symlink file")
            }
            var closed = false
            return BlobReader(size: Int64(st.st_size), readFn: { maxBytes in
                guard !closed && maxBytes > 0 else { return Data() }
                do { return try fh.read(upToCount: maxBytes) ?? Data() } catch {
                    throw SyncError(code: .errStorageIo, message: "read blob file failed")
                }
            }, closeFn: { if !closed { closed = true; try? fh.close() } })
        }
    }

    private static func inferBasicMime(_ fileName: String) -> String {
        switch (fileName as NSString).pathExtension.lowercased() {
        case "txt", "md", "log": return "text/plain; charset=utf-8"
        case "json": return "application/json"
        case "gz": return "application/gzip"
        case "png": return "image/png"
        case "jpg", "jpeg": return "image/jpeg"
        case "webp": return "image/webp"
        case "gif": return "image/gif"
        case "mp4": return "video/mp4"
        case "m4a": return "audio/mp4"
        case "mp3": return "audio/mpeg"
        case "pdf": return "application/pdf"
        default: return "application/octet-stream"
        }
    }
}

public struct ParcelInput: Sendable {
    public var appId: String, schema: String, inlinePayload: [String: JSONValue]?, blobs: [BlobInput]
    public init(appId: String = "", schema: String = "generic.parcel.v1", inlinePayload: [String: JSONValue]? = nil, blobs: [BlobInput] = []) {
        self.appId = appId; self.schema = schema; self.inlinePayload = inlinePayload; self.blobs = blobs
    }
    public static func text(appId: String = "", text: String) -> ParcelInput {
        ParcelInput(appId: appId, schema: "clip.text.v1", inlinePayload: ["text": .string(text)])
    }
}

public struct ReceivedBlob: Sendable {
    public let descriptor: BlobDescriptor, safeFileURL: URL, safeName: String
    public init(descriptor: BlobDescriptor, safeFileURL: URL, safeName: String) {
        self.descriptor = descriptor; self.safeFileURL = safeFileURL; self.safeName = safeName
    }
    public var safePath: String { safeFileURL.path }

    public func openFileHandle() throws -> FileHandle {
        guard let fh = try? FileHandle(forReadingFrom: safeFileURL) else {
            throw SyncError(code: .errStorageIo, message: "open received blob failed")
        }
        return fh
    }

    public func readBytesVerified(maxBytes: Int = 64 * 1024 * 1024) throws -> Data {
        var st = Darwin.stat()
        guard safeFileURL.path.withCString({ Darwin.lstat($0, &st) }) == 0,
              (st.st_mode & S_IFMT) == S_IFREG,
              st.st_size <= Int64(maxBytes),
              let data = try? Data(contentsOf: safeFileURL) else {
            throw SyncError(code: .errStorageIo, message: "read verified blob failed or exceeds max limit")
        }
        guard Int64(data.count) == descriptor.size &&
              SyncCrypto.hexEncode(SyncCrypto.sha256(data)) == descriptor.sha256 else {
            throw SyncError(code: .errHashMismatch, message: "received blob size or SHA-256 mismatch")
        }
        return data
    }

    public func saveToDir(_ outDir: URL) throws -> URL {
        var dirStat = Darwin.stat()
        if outDir.path.withCString({ Darwin.lstat($0, &dirStat) }) == 0 {
            guard (dirStat.st_mode & S_IFMT) == S_IFDIR else {
                throw SyncError(code: .errStorageIo, message: "output directory must be a real directory, not a symlink")
            }
        } else if (try? FileManager.default.createDirectory(at: outDir, withIntermediateDirectories: true)) == nil {
            throw SyncError(code: .errStorageIo, message: "create output directory failed")
        }
        let cleanName = ManifestCodec.sanitizeFilename(safeName.isEmpty ? descriptor.name : safeName)
        let ext = cleanName.lastIndex(of: ".").flatMap { $0 > cleanName.startIndex ? String(cleanName[$0...]) : nil } ?? ""
        let stem = ext.isEmpty ? cleanName : String(cleanName.dropLast(ext.count))

        var outFd: Int32 = -1, targetURL: URL?
        for i in 0..<10_000 {
            let candURL = outDir.appendingPathComponent(i == 0 ? cleanName : "\(stem)_\(i)\(ext)", isDirectory: false)
            let fd = candURL.path.withCString { Darwin.open($0, O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW, mode_t(0o600)) }
            if fd >= 0 { outFd = fd; targetURL = candURL; break }
            if errno == EEXIST { continue }
            throw SyncError(code: .errStorageIo, message: "create destination file failed (errno=\(errno))")
        }
        guard outFd >= 0, let destURL = targetURL else {
            throw SyncError(code: .errStorageIo, message: "too many filename collisions in output directory")
        }
        do {
            let inFh = try openFileHandle(); defer { try? inFh.close() }
            while let chunk = try inFh.read(upToCount: 65536), !chunk.isEmpty {
                try chunk.withUnsafeBytes { rawBuf in
                    guard let base = rawBuf.baseAddress else { return }
                    var written = 0
                    while written < rawBuf.count {
                        let w = Darwin.write(outFd, base.advanced(by: written), rawBuf.count - written)
                        if w < 0 { if errno == EINTR { continue }; throw SyncError(code: .errStorageIo, message: "write failed") }
                        written += w
                    }
                }
            }
            guard Darwin.fsync(outFd) == 0 else { throw SyncError(code: .errStorageIo, message: "fsync failed") }
            _ = Darwin.close(outFd); outFd = -1
        } catch {
            if outFd >= 0 { _ = Darwin.close(outFd) }
            try? FileManager.default.removeItem(at: destURL)
            throw (error as? SyncError) ?? SyncError(code: .errStorageIo, message: "save destination file failed")
        }
        try? FileManager.default.removeItem(at: safeFileURL)
        return destURL
    }
}

public struct ReceivedParcel: Sendable {
    public let itemId: String, manifest: Manifest, blobs: [ReceivedBlob]
    public init(itemId: String = "", manifest: Manifest, blobs: [ReceivedBlob] = []) {
        self.itemId = itemId; self.manifest = manifest; self.blobs = blobs
    }
}
