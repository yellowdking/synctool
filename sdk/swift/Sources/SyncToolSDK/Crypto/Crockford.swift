import Darwin
import Foundation

/// Standard Crockford Base32 5-byte <-> 8-char room code codec + Luhn-mod-32 (`CRYPTO_AND_AUTH.md` §2.3).
public enum Crockford {
    public static let alphabet: String = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
    public static let roomIdLength: Int = 8
    public static let roomIdRawBytes: Int = 5

    private static let alphabetBytes: [UInt8] = Array(alphabet.utf8)

    private static let decodeTable: [Int] = {
        var tbl = [Int](repeating: -1, count: 128)
        for (idx, b) in Array("0123456789ABCDEFGHJKMNPQRSTVWXYZ".utf8).enumerated() {
            tbl[Int(b)] = idx
            if b >= 0x41 && b <= 0x5A { tbl[Int(b + 32)] = idx }
        }
        tbl[Int(UInt8(ascii: "O"))] = 0; tbl[Int(UInt8(ascii: "o"))] = 0
        tbl[Int(UInt8(ascii: "I"))] = 1; tbl[Int(UInt8(ascii: "i"))] = 1
        tbl[Int(UInt8(ascii: "L"))] = 1; tbl[Int(UInt8(ascii: "l"))] = 1
        return tbl
    }()

    public static func generateRoomId() throws -> String {
        try encode5Bytes(SyncCrypto.randomBytes(roomIdRawBytes))
    }

    public static func encode5Bytes(_ data5: Data) throws -> String {
        let bytes = [UInt8](data5)
        guard bytes.count == roomIdRawBytes else {
            throw SyncError(code: .errUriInvalid, message: "room_id raw input must be 5 bytes")
        }
        var v: UInt64 = 0
        for b in bytes { v = (v << 8) | UInt64(b) }
        var out = [UInt8](repeating: 0, count: roomIdLength)
        for i in stride(from: roomIdLength - 1, through: 0, by: -1) {
            out[i] = alphabetBytes[Int(v & 0x1F)]; v >>= 5
        }
        return String(decoding: out, as: UTF8.self)
    }

    public static func encodeRoomId(_ data5: Data) throws -> String { try encode5Bytes(data5) }

    public static func normalize(_ raw: String) throws -> String {
        var out = [UInt8]()
        out.reserveCapacity(roomIdLength)
        for scalar in raw.unicodeScalars {
            let code = scalar.value
            if code == 0x2D || code == 0x20 || code == 0x09 || code == 0x0D || code == 0x0A { continue }
            guard code < 128 else { throw SyncError(code: .errUriInvalid, message: "non-ASCII character in room_id") }
            let v = decodeTable[Int(code)]
            guard v >= 0 else { throw SyncError(code: .errUriInvalid, message: "invalid Crockford character in room_id") }
            guard out.count < roomIdLength else { throw SyncError(code: .errUriInvalid, message: "room_id exceeds 8 chars") }
            out.append(alphabetBytes[v])
        }
        guard out.count == roomIdLength else { throw SyncError(code: .errUriInvalid, message: "room_id must be 8 chars") }
        return String(decoding: out, as: UTF8.self)
    }

    public static func normalizeRoomId(_ raw: String) throws -> String { try normalize(raw) }

    public static func decode8Chars(_ code: String) throws -> Data {
        let norm = try normalize(code)
        var v: UInt64 = 0
        for b in norm.utf8 { v = (v << 5) | UInt64(decodeTable[Int(b)]) }
        var raw = [UInt8](repeating: 0, count: roomIdRawBytes)
        for i in stride(from: roomIdRawBytes - 1, through: 0, by: -1) {
            raw[i] = UInt8(v & 0xFF); v >>= 8
        }
        return Data(raw)
    }

    public static func decodeRoomId(_ code: String) throws -> Data { try decode8Chars(code) }

    public static func formatRoomId(_ code: String) throws -> String {
        let bytes = Array(try normalize(code).utf8)
        return "\(String(decoding: bytes[0..<4], as: UTF8.self))-\(String(decoding: bytes[4..<8], as: UTF8.self))"
    }

    public static func isCanonicalRoomId(_ s: String) -> Bool {
        let utf8 = Array(s.utf8)
        return utf8.count == roomIdLength && utf8.allSatisfy { $0 < 128 && alphabetBytes.contains($0) }
    }

    public static func computeLuhnMod32CheckChar(_ input: String) throws -> Character {
        let cleaned = try normalizeArbitraryCrockford(input)
        guard !cleaned.isEmpty else { throw SyncError(code: .errUriInvalid, message: "empty Crockford string") }
        var factor = 2, sum = 0
        for i in stride(from: cleaned.count - 1, through: 0, by: -1) {
            let cp = decodeTable[Int(cleaned[i])]
            var addend = factor * cp
            factor = (factor == 2) ? 1 : 2
            addend = (addend / 32) + (addend % 32)
            sum += addend
        }
        let checkCp = (32 - (sum % 32)) % 32
        return Character(UnicodeScalar(alphabetBytes[checkCp]))
    }

    public static func appendLuhnMod32(_ input: String) throws -> String {
        let cleaned = String(decoding: try normalizeArbitraryCrockford(input), as: UTF8.self)
        return "\(cleaned)\(try computeLuhnMod32CheckChar(cleaned))"
    }

    public static func verifyLuhnMod32(_ inputWithCheck: String) -> Bool {
        guard let cleaned = try? normalizeArbitraryCrockford(inputWithCheck), cleaned.count >= 2 else { return false }
        let body = String(decoding: cleaned[0..<(cleaned.count - 1)], as: UTF8.self)
        guard let expected = try? computeLuhnMod32CheckChar(body), let ascii = expected.asciiValue else { return false }
        return cleaned[cleaned.count - 1] == ascii
    }

    private static func normalizeArbitraryCrockford(_ input: String) throws -> [UInt8] {
        var out = [UInt8]()
        out.reserveCapacity(input.utf8.count)
        for scalar in input.unicodeScalars {
            let code = scalar.value
            if code == 0x2D || code == 0x20 || code == 0x09 || code == 0x0D || code == 0x0A { continue }
            guard code < 128 else { throw SyncError(code: .errUriInvalid, message: "non-ASCII character") }
            let v = decodeTable[Int(code)]
            guard v >= 0 else { throw SyncError(code: .errUriInvalid, message: "invalid Crockford character") }
            out.append(alphabetBytes[v])
        }
        return out
    }
}

// MARK: - Canonical Relay Origin & RFC 5952 IPv6 (POSIX inet_pton, zero DNS, zero input echo)

extension SyncCrypto {
    public static func canonicalRelayOrigin(_ rawUrl: String) throws -> String {
        let trimmed = rawUrl.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, !trimmed.contains("#"), !trimmed.contains("?"),
              trimmed.utf8.allSatisfy({ $0 > 0x20 && $0 < 0x7f }),
              let sep = trimmed.range(of: "://") else {
            throw SyncError(code: .errUriInvalid, message: "malformed relay origin URL")
        }
        let scheme = trimmed[..<sep.lowerBound].lowercased()
        guard scheme == "https" || scheme == "http" else {
            throw SyncError(code: .errUriInvalid, message: "unsupported relay scheme")
        }
        var auth = String(trimmed[sep.upperBound...])
        if auth.hasSuffix("/") { auth.removeLast() }
        guard !auth.isEmpty, !auth.contains("/"), !auth.contains("\\"), !auth.contains("@"), !auth.contains("%") else {
            throw SyncError(code: .errUriInvalid, message: "origin must not contain path, userinfo, or escapes")
        }
        let (rawHost, rawPort) = try splitHostPortAuthority(auth)
        let canonHost = try canonicalizeHost(rawHost)
        let portNum: Int
        if let pStr = rawPort {
            guard !pStr.isEmpty, pStr.utf8.allSatisfy({ $0 >= 0x30 && $0 <= 0x39 }),
                  let parsed = Int(pStr), (1...65535).contains(parsed) else {
                throw SyncError(code: .errUriInvalid, message: "invalid relay port")
            }
            portNum = parsed
        } else { portNum = (scheme == "https") ? 443 : 80 }
        if scheme == "http" && !isLoopbackHost(canonHost) {
            throw SyncError(code: .errUriInvalid, message: "http scheme only permitted for loopback")
        }
        return "\(scheme)://\(canonHost.contains(":") ? "[\(canonHost)]" : canonHost):\(portNum)"
    }

    private static func splitHostPortAuthority(_ authority: String) throws -> (String, String?) {
        if authority.hasPrefix("[") {
            guard let closeIdx = authority.firstIndex(of: "]") else {
                throw SyncError(code: .errUriInvalid, message: "unclosed IPv6 bracket")
            }
            let inside = String(authority[authority.index(after: authority.startIndex)..<closeIdx])
            let rest = String(authority[authority.index(after: closeIdx)...])
            guard !inside.isEmpty && (rest.isEmpty || (rest.hasPrefix(":") && rest.count > 1)) else {
                throw SyncError(code: .errUriInvalid, message: "invalid IPv6 host/port authority")
            }
            return ("[\(inside)]", rest.isEmpty ? nil : String(rest.dropFirst()))
        }
        let parts = authority.split(separator: ":", omittingEmptySubsequences: false)
        if parts.count == 1 { return (authority, nil) }
        guard parts.count == 2 && !parts[0].isEmpty && !parts[1].isEmpty else {
            throw SyncError(code: .errUriInvalid, message: "malformed host:port or unbracketed IPv6")
        }
        return (String(parts[0]), String(parts[1]))
    }

    private static func canonicalizeHost(_ rawHost: String) throws -> String {
        if rawHost.hasPrefix("[") && rawHost.hasSuffix("]") {
            guard let v6 = parseStrictIpv6(String(rawHost.dropFirst().dropLast())) else {
                throw SyncError(code: .errUriInvalid, message: "invalid IPv6 literal")
            }
            return formatRfc5952Ipv6(v6)
        }
        let lower = rawHost.lowercased()
        if let v4 = parseStrictIpv4(lower) { return "\(v4[0]).\(v4[1]).\(v4[2]).\(v4[3])" }
        if lower.utf8.allSatisfy({ ($0 >= 0x30 && $0 <= 0x39) || $0 == 0x2e }) {
            throw SyncError(code: .errUriInvalid, message: "invalid IPv4 literal")
        }
        guard !lower.isEmpty && !lower.hasPrefix(".") && !lower.hasSuffix(".") &&
              lower.utf8.allSatisfy({ ($0 >= 0x61 && $0 <= 0x7a) || ($0 >= 0x30 && $0 <= 0x39) || $0 == 0x2e || $0 == 0x2d }) else {
            throw SyncError(code: .errUriInvalid, message: "invalid hostname")
        }
        return lower
    }

    public static func isLoopbackHost(_ host: String) -> Bool {
        let h = stripBrackets(host).lowercased()
        if h == "localhost" { return true }
        if let v4 = parseStrictIpv4(h) { return v4[0] == 127 }
        guard let v6 = parseStrictIpv6(h) else { return false }
        return (v6[0..<15].allSatisfy({ $0 == 0 }) && v6[15] == 1) || (isIpv4MappedIpv6(v6) && v6[12] == 127)
    }

    public static func isIpHost(_ host: String) -> Bool {
        var h = stripBrackets(host)
        if let pct = h.firstIndex(of: "%") { h = String(h[..<pct]) }
        return !h.isEmpty && (parseStrictIpv4(h) != nil || parseStrictIpv6(h) != nil)
    }

    private static func stripBrackets(_ s: String) -> String {
        let t = s.trimmingCharacters(in: .whitespacesAndNewlines)
        return (t.hasPrefix("[") && t.hasSuffix("]") && t.count >= 2) ? String(t.dropFirst().dropLast()) : t
    }

    private static func parseStrictIpv4(_ s: String) -> [UInt8]? {
        let parts = s.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4, parts.allSatisfy({ !$0.isEmpty && $0.count <= 3 && !($0.count > 1 && $0.hasPrefix("0")) && $0.utf8.allSatisfy({ $0 >= 0x30 && $0 <= 0x39 }) }) else { return nil }
        var addr4 = in_addr()
        guard s.withCString({ inet_pton(AF_INET, $0, &addr4) }) == 1 else { return nil }
        return withUnsafeBytes(of: &addr4) { Array($0) }
    }

    private static func parseStrictIpv6(_ s: String) -> [UInt8]? {
        guard !s.isEmpty && !s.contains("%") && s.contains(":") else { return nil }
        var addr6 = in6_addr()
        guard s.withCString({ inet_pton(AF_INET6, $0, &addr6) }) == 1 else { return nil }
        return withUnsafeBytes(of: &addr6) { Array($0) }
    }

    private static func isIpv4MappedIpv6(_ b16: [UInt8]) -> Bool {
        b16[0..<10].allSatisfy({ $0 == 0 }) && b16[10] == 0xff && b16[11] == 0xff
    }

    private static func formatRfc5952Ipv6(_ b16: [UInt8]) -> String {
        if isIpv4MappedIpv6(b16) { return "::ffff:\(b16[12]).\(b16[13]).\(b16[14]).\(b16[15])" }
        let groups = (0..<8).map { (UInt16(b16[$0 * 2]) << 8) | UInt16(b16[$0 * 2 + 1]) }
        var bestStart = -1, bestLen = 0, curStart = -1, curLen = 0
        for i in 0..<8 {
            if groups[i] == 0 {
                if curStart < 0 { curStart = i; curLen = 1 } else { curLen += 1 }
                if curLen > bestLen && curLen >= 2 { bestStart = curStart; bestLen = curLen }
            } else { curStart = -1; curLen = 0 }
        }
        var out = "", i = 0
        while i < 8 {
            if i == bestStart { out += "::"; i += bestLen; continue }
            if !out.isEmpty && !out.hasSuffix("::") { out += ":" }
            out += String(groups[i], radix: 16, uppercase: false); i += 1
        }
        return out
    }
}

// MARK: - `synctool://relay` & `synctool://pair` Parser/Formatter (`ENVELOPE_AND_SDK.md` §3)

public enum SyncUri {
    public static let maxSpkiPins = 8
    private static let unreservedChars = CharacterSet(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")

    public static func parseAndValidateSpkiPins(_ rawPinParam: String) throws -> [String] {
        let trimmed = rawPinParam.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty { return [] }
        let parts = trimmed.split(separator: ",", omittingEmptySubsequences: false)
        guard !parts.isEmpty && parts.count <= maxSpkiPins else {
            throw SyncError(code: .errUriInvalid, message: "SPKI pin list must contain 1..8 comma-separated 64-hex pins")
        }
        var dedup: [String] = []
        for rawPart in parts {
            var pin = rawPart.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            if pin.hasPrefix("sha256:") { pin = String(pin.dropFirst(7)) }
            guard SyncCrypto.isLowerHex(pin, count: 64) else {
                throw SyncError(code: .errUriInvalid, message: "each SPKI pin must be 64 hex characters")
            }
            if !dedup.contains(pin) { dedup.append(pin) }
        }
        return dedup
    }

    public static func parseRelayUri(_ raw: String) throws -> RelayProfile {
        let (query, frag) = try parseStrictSyncUri(raw, expectedHost: "relay")
        guard (query["k"] ?? "").isEmpty && (query["s"] ?? "").isEmpty else {
            throw SyncError(code: .errUriInvalid, message: "access key k must be placed in #fragment, not query")
        }
        try validateUriVersion(query["v"])
        guard let rawOrigin = query["u"], !rawOrigin.isEmpty else {
            throw SyncError(code: .errUriInvalid, message: "missing required parameter u")
        }
        let origin = try SyncCrypto.canonicalRelayOrigin(rawOrigin)
        let (scheme, host) = extractSchemeAndHost(origin)
        let rawPin = (query["pin"] ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        let pins = rawPin.isEmpty ? [] : try parseAndValidateSpkiPins(rawPin)
        if pins.isEmpty && scheme == "https" && SyncCrypto.isIpHost(host) {
            throw SyncError(code: .errUriInvalid, message: "bare IP relay requires 64-hex SPKI pin")
        }
        let accessKey = frag["k"] ?? ""
        guard accessKey.count >= 32 else {
            throw SyncError(code: .errUriInvalid, message: "missing or short access key k in #fragment")
        }
        return RelayProfile(
            endpoint: origin, accessKey: accessKey, tlsMode: !pins.isEmpty ? TlsMode.spkiPin : TlsMode.systemCa,
            spkiPins: pins, relayId: SyncCrypto.deriveRelayId(origin)
        )
    }

    public static func formatRelayUri(_ profile: RelayProfile) throws -> String {
        let origin = try SyncCrypto.canonicalRelayOrigin(profile.endpoint)
        guard profile.accessKey.count >= 32 else { throw SyncError(code: .errUriInvalid, message: "access key must be >= 32 chars") }
        let (scheme, host) = extractSchemeAndHost(origin)
        let pins = profile.resolvedPins.isEmpty ? [] : try parseAndValidateSpkiPins(profile.resolvedPins.joined(separator: ","))
        if pins.isEmpty && scheme == "https" && SyncCrypto.isIpHost(host) {
            throw SyncError(code: .errUriInvalid, message: "bare IP relay requires SPKI pin")
        }
        let pinPart = pins.isEmpty ? "" : "&pin=\(pins.joined(separator: ","))"
        return "synctool://relay?v=1&u=\(queryEscape(origin))\(pinPart)#k=\(queryEscape(profile.accessKey))"
    }

    public static func parsePairUri(_ raw: String) throws -> PairOffer {
        let (query, frag) = try parseStrictSyncUri(raw, expectedHost: "pair")
        guard (query["s"] ?? "").isEmpty && (query["k"] ?? "").isEmpty else {
            throw SyncError(code: .errUriInvalid, message: "secrets s/k must be in #fragment, not query")
        }
        try validateUriVersion(query["v"])
        let roomId = try Crockford.normalize(query["r"] ?? "")
        guard let mode = Int(query["m"] ?? "") else { throw SyncError(code: .errUriInvalid, message: "invalid mode m") }
        let purpose = query["p"] ?? ""
        try validateModeAndPurpose(mode: mode, purpose: purpose)

        let rawOrigin = query["u"] ?? "", rawPin = (query["pin"] ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        var origin = "", pins: [String] = []
        if !rawOrigin.isEmpty {
            origin = try SyncCrypto.canonicalRelayOrigin(rawOrigin)
            let (scheme, host) = extractSchemeAndHost(origin)
            if !rawPin.isEmpty { pins = try parseAndValidateSpkiPins(rawPin) }
            else if scheme == "https" && SyncCrypto.isIpHost(host) {
                throw SyncError(code: .errUriInvalid, message: "bare IP in pair URI requires SPKI pin")
            }
        } else if !rawPin.isEmpty { throw SyncError(code: .errUriInvalid, message: "pin requires origin u") }

        var exp: Int64 = 0
        if let expStr = query["exp"], !expStr.isEmpty {
            guard let parsed = Int64(expStr), parsed > 0 else { throw SyncError(code: .errUriInvalid, message: "invalid exp") }
            exp = parsed
        }
        let sStr = frag["s"] ?? ""
        let oob: Data
        if mode == SyncHandshake.modeQrOob {
            guard !sStr.isEmpty, let dec = try? SyncCrypto.b64uDecode(sStr), dec.count == SyncHandshake.oobSecretSize else {
                throw SyncError(code: .errUriInvalid, message: "mode=1 requires 16-byte #s= oob_secret")
            }
            oob = dec
        } else {
            guard sStr.isEmpty else { throw SyncError(code: .errUriInvalid, message: "mode=0/2 must omit #s=") }
            oob = Data()
        }
        let accessKey = frag["k"] ?? ""
        if !accessKey.isEmpty && (origin.isEmpty || accessKey.count < 32) {
            throw SyncError(code: .errUriInvalid, message: "access key #k= requires origin u and >= 32 chars")
        }
        return PairOffer(version: 1, roomId: roomId, mode: mode, purpose: purpose, endpoint: origin, spkiPins: pins, expiresAt: exp, oobSecret: oob, accessKey: accessKey)
    }

    public static func formatPairUri(_ offer: PairOffer) throws -> String {
        let roomId = try Crockford.normalize(offer.roomId)
        try validateModeAndPurpose(mode: offer.mode, purpose: offer.purpose)
        if offer.mode == SyncHandshake.modeQrOob {
            guard offer.oobSecret.count == SyncHandshake.oobSecretSize else {
                throw SyncError(code: .errUriInvalid, message: "mode=1 requires 16B oob_secret")
            }
        } else if !offer.oobSecret.isEmpty {
            throw SyncError(code: .errUriInvalid, message: "mode=0/2 must omit oob_secret")
        }
        var origin = "", pins: [String] = []
        if !offer.endpoint.isEmpty {
            origin = try SyncCrypto.canonicalRelayOrigin(offer.endpoint)
            let (scheme, host) = extractSchemeAndHost(origin)
            if !offer.spkiPins.isEmpty { pins = try parseAndValidateSpkiPins(offer.spkiPins.joined(separator: ",")) }
            else if scheme == "https" && SyncCrypto.isIpHost(host) {
                throw SyncError(code: .errUriInvalid, message: "bare IP in pair URI requires SPKI pin")
            }
        } else if !offer.spkiPins.isEmpty || !offer.accessKey.isEmpty {
            throw SyncError(code: .errUriInvalid, message: "spkiPins/accessKey in pair URI requires endpoint u")
        }
        if !offer.accessKey.isEmpty && offer.accessKey.count < 32 {
            throw SyncError(code: .errUriInvalid, message: "access key must be >= 32 chars")
        }
        var out = "synctool://pair?r=\(roomId)&m=\(offer.mode)&p=\(offer.purpose)&v=1"
        if !origin.isEmpty {
            out += "&u=\(queryEscape(origin))"
            if !pins.isEmpty { out += "&pin=\(pins.joined(separator: ","))" }
        }
        if offer.expiresAt > 0 { out += "&exp=\(offer.expiresAt)" }
        var frags: [String] = []
        if offer.mode == SyncHandshake.modeQrOob { frags.append("s=\(SyncCrypto.b64uEncode(offer.oobSecret))") }
        if !offer.accessKey.isEmpty { frags.append("k=\(queryEscape(offer.accessKey))") }
        if !frags.isEmpty { out += "#\(frags.joined(separator: "&"))" }
        return out
    }

    public static func extractRelayFromPairUri(_ raw: String) throws -> RelayProfile? {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.lowercased().hasPrefix("synctool://pair") else { return nil }
        let offer = try parsePairUri(trimmed)
        guard !offer.endpoint.isEmpty && !offer.accessKey.isEmpty else { return nil }
        return RelayProfile(endpoint: offer.endpoint, accessKey: offer.accessKey, spkiPins: offer.spkiPins, relayId: SyncCrypto.deriveRelayId(offer.endpoint))
    }

    private static func validateModeAndPurpose(mode: Int, purpose: String) throws {
        let ok = (mode == SyncHandshake.modeDirect && purpose == SyncHandshake.purposeDirect) ||
            ((mode == SyncHandshake.modeQrOob || mode == SyncHandshake.modeCommitSas) &&
             (purpose == SyncHandshake.purposeOneshot || purpose == SyncHandshake.purposePair))
        guard ok else { throw SyncError(code: .errUriInvalid, message: "invalid pair mode/purpose combination") }
    }

    private static func validateUriVersion(_ v: String?) throws {
        guard let v = v, !v.isEmpty, v != "1" else { return }
        if let vInt = Int(v), vInt > 1 {
            throw SyncError(code: .errUnsupportedVersion, message: "unsupported URI version \(vInt)", details: ["version": "\(vInt)", "supported_version": "1"])
        }
        throw SyncError(code: .errUriInvalid, message: "unsupported URI version")
    }

    private static func parseStrictSyncUri(_ raw: String, expectedHost: String) throws -> ([String: String], [String: String]) {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, trimmed.utf8.allSatisfy({ $0 > 0x20 && $0 < 0x7f }),
              let sep = trimmed.range(of: "://"), trimmed[..<sep.lowerBound].lowercased() == "synctool" else {
            throw SyncError(code: .errUriInvalid, message: "expected synctool://\(expectedHost) URI")
        }
        var rest = String(trimmed[sep.upperBound...]), rawFrag: String?, rawQuery: String?
        if let h = rest.firstIndex(of: "#") { rawFrag = String(rest[rest.index(after: h)...]); rest = String(rest[..<h]) }
        if let q = rest.firstIndex(of: "?") { rawQuery = String(rest[rest.index(after: q)...]); rest = String(rest[..<q]) }
        if rest.hasSuffix("/") { rest.removeLast() }
        guard rest.lowercased() == expectedHost else { throw SyncError(code: .errUriInvalid, message: "expected synctool://\(expectedHost)") }
        return (try parseQueryPairs(rawQuery), try parseQueryPairs(rawFrag))
    }

    private static func parseQueryPairs(_ raw: String?) throws -> [String: String] {
        guard let raw = raw, !raw.isEmpty else { return [:] }
        var out: [String: String] = [:]
        for pair in raw.split(separator: "&", omittingEmptySubsequences: false) where !pair.isEmpty {
            if let eq = pair.firstIndex(of: "=") {
                let k = try percentDecode(String(pair[..<eq])), v = try percentDecode(String(pair[pair.index(after: eq)...]))
                if out[k] == nil { out[k] = v }
            } else {
                let k = try percentDecode(String(pair))
                if out[k] == nil { out[k] = "" }
            }
        }
        return out
    }

    private static func percentDecode(_ s: String) throws -> String {
        let plusDecoded = s.replacingOccurrences(of: "+", with: "%20")
        let utf8 = Array(plusDecoded.utf8)
        var i = 0
        while i < utf8.count {
            if utf8[i] == 0x25 {
                guard i + 2 < utf8.count, isHex(utf8[i + 1]), isHex(utf8[i + 2]) else {
                    throw SyncError(code: .errUriInvalid, message: "malformed percent-encoding in URI")
                }
                i += 3
            } else { i += 1 }
        }
        guard let decoded = plusDecoded.removingPercentEncoding else {
            throw SyncError(code: .errUriInvalid, message: "malformed UTF-8 in URI")
        }
        return decoded
    }

    private static func isHex(_ b: UInt8) -> Bool { (b >= 0x30 && b <= 0x39) || (b >= 0x41 && b <= 0x46) || (b >= 0x61 && b <= 0x66) }
    private static func queryEscape(_ s: String) -> String { s.addingPercentEncoding(withAllowedCharacters: unreservedChars) ?? s }

    internal static func extractSchemeAndHost(_ canonicalOrigin: String) -> (String, String) {
        guard let sep = canonicalOrigin.range(of: "://") else { return ("", "") }
        let scheme = String(canonicalOrigin[..<sep.lowerBound]).lowercased(), auth = String(canonicalOrigin[sep.upperBound...])
        if auth.hasPrefix("["), let close = auth.firstIndex(of: "]") { return (scheme, String(auth[auth.index(after: auth.startIndex)..<close])) }
        if let colon = auth.lastIndex(of: ":") { return (scheme, String(auth[..<colon])) }
        return (scheme, auth)
    }
}
