import CryptoKit
import Foundation
import Security

internal struct RequestAuthOptions: Sendable {
    var contentType: String = "", roomToken: String = "", depositToken: String = ""
    var uploadToken: String = "", mailboxId: String = "", mailboxAuthSeed32: Data?, acceptSse: Bool = false
}

internal struct RawHttpResponse: Sendable { let statusCode: Int, headers: [String: String], body: Data }
internal struct SseEvent: Sendable { let id: String, event: String, data: String }

/// Bounds-checked X.509 DER parser slicing raw `subjectPublicKeyInfo` TLV and `Validity` directly from `TBSCertificate`.
/// Works identically for `CA:FALSE` self-signed ECDSA P-256/P-384, RSA-2048/4096, and Ed25519 leaf certs without `trustd` self-anchor failure.
internal enum X509SpkiExtractor {
    struct TLV { let tag: UInt8; let fullRange: Range<Int>; let valRange: Range<Int>; let nextPos: Int }

    static func extractSpkiAndValidity(certDER: Data) throws -> (spkiDER: Data, notBeforeUnix: Int64, notAfterUnix: Int64) {
        let bytes = [UInt8](certDER)
        let certSeq = try readTLV(bytes, at: 0, limit: bytes.count)
        guard certSeq.tag == 0x30 else { throw SyncError(code: .errTlsCertInvalid, message: "X.509 outer element is not SEQUENCE") }
        let tbs = try readTLV(bytes, at: certSeq.valRange.lowerBound, limit: certSeq.valRange.upperBound)
        guard tbs.tag == 0x30 else { throw SyncError(code: .errTlsCertInvalid, message: "X.509 TBSCertificate is not SEQUENCE") }

        var cur = tbs.valRange.lowerBound; let tbsEnd = tbs.valRange.upperBound
        let first = try readTLV(bytes, at: cur, limit: tbsEnd)
        if first.tag == 0xA0 {
            let serial = try readTLV(bytes, at: first.nextPos, limit: tbsEnd)
            guard serial.tag == 0x02 else { throw SyncError(code: .errTlsCertInvalid, message: "X.509 missing serialNumber") }
            cur = serial.nextPos
        } else if first.tag == 0x02 { cur = first.nextPos }
        else { throw SyncError(code: .errTlsCertInvalid, message: "X.509 invalid version/serial field") }

        let sigAlg = try readTLV(bytes, at: cur, limit: tbsEnd)
        let issuer = try readTLV(bytes, at: sigAlg.nextPos, limit: tbsEnd)
        let validity = try readTLV(bytes, at: issuer.nextPos, limit: tbsEnd)
        guard sigAlg.tag == 0x30 && issuer.tag == 0x30 && validity.tag == 0x30 else {
            throw SyncError(code: .errTlsCertInvalid, message: "X.509 invalid sigAlg/issuer/validity")
        }
        let nbTLV = try readTLV(bytes, at: validity.valRange.lowerBound, limit: validity.valRange.upperBound)
        let naTLV = try readTLV(bytes, at: nbTLV.nextPos, limit: validity.valRange.upperBound)
        let notBefore = try parseAsn1Time(tag: nbTLV.tag, bytes: Array(bytes[nbTLV.valRange]))
        let notAfter = try parseAsn1Time(tag: naTLV.tag, bytes: Array(bytes[naTLV.valRange]))

        let subject = try readTLV(bytes, at: validity.nextPos, limit: tbsEnd)
        let spki = try readTLV(bytes, at: subject.nextPos, limit: tbsEnd)
        guard subject.tag == 0x30 && spki.tag == 0x30 else {
            throw SyncError(code: .errTlsCertInvalid, message: "X.509 invalid subject or subjectPublicKeyInfo")
        }
        return (Data(bytes[spki.fullRange]), notBefore, notAfter)
    }

    static func readTLV(_ bytes: [UInt8], at pos: Int, limit: Int) throws -> TLV {
        guard pos + 2 <= limit else { throw SyncError(code: .errTlsCertInvalid, message: "truncated ASN.1 DER header") }
        let tag = bytes[pos], b1 = bytes[pos + 1]
        var valStart = pos + 2, length = 0
        if (b1 & 0x80) == 0 { length = Int(b1) }
        else {
            let nBytes = Int(b1 & 0x7F)
            guard (1...4).contains(nBytes), valStart + nBytes <= limit, bytes[valStart] != 0 else {
                throw SyncError(code: .errTlsCertInvalid, message: "invalid ASN.1 DER length")
            }
            for i in 0..<nBytes { length = (length << 8) | Int(bytes[valStart + i]) }
            guard length >= 128 else { throw SyncError(code: .errTlsCertInvalid, message: "non-minimal ASN.1 DER length") }
            valStart += nBytes
        }
        guard length >= 0 && valStart + length <= limit else {
            throw SyncError(code: .errTlsCertInvalid, message: "ASN.1 DER value exceeds parent bounds")
        }
        let end = valStart + length
        return TLV(tag: tag, fullRange: pos..<end, valRange: valStart..<end, nextPos: end)
    }

    static func parseAsn1Time(tag: UInt8, bytes: [UInt8]) throws -> Int64 {
        guard (tag == 0x17 || tag == 0x18), bytes.last == 0x5A else {
            throw SyncError(code: .errTlsCertInvalid, message: "unsupported ASN.1 Time encoding")
        }
        var core = Array(bytes.dropLast())
        if tag == 0x18, let dotIdx = core.firstIndex(of: 0x2E) { core = Array(core[..<dotIdx]) }
        func dec(_ off: Int, _ len: Int) throws -> Int {
            guard off + len <= core.count else { throw SyncError(code: .errTlsCertInvalid, message: "short ASN.1 Time") }
            var v = 0
            for i in off..<(off + len) {
                guard core[i] >= 0x30 && core[i] <= 0x39 else { throw SyncError(code: .errTlsCertInvalid, message: "non-digit in ASN.1 Time") }
                v = v * 10 + Int(core[i] - 0x30)
            }
            return v
        }
        let year: Int, off: Int
        if tag == 0x17 {
            guard core.count == 12 else { throw SyncError(code: .errTlsCertInvalid, message: "invalid UTCTime length") }
            let yy = try dec(0, 2); year = (yy >= 50) ? (1900 + yy) : (2000 + yy); off = 2
        } else {
            guard core.count == 14 else { throw SyncError(code: .errTlsCertInvalid, message: "invalid GeneralizedTime length") }
            year = try dec(0, 4); off = 4
        }
        let month = try dec(off, 2), day = try dec(off + 2, 2), hour = try dec(off + 4, 2), minute = try dec(off + 6, 2), second = try dec(off + 8, 2)
        guard (1...12).contains(month), (1...31).contains(day), (0...23).contains(hour), (0...59).contains(minute), (0...60).contains(second) else {
            throw SyncError(code: .errTlsCertInvalid, message: "ASN.1 Time calendar field out of range")
        }
        let y = Int64(year) - (month <= 2 ? 1 : 0), era = (y >= 0 ? y : y - 399) / 400, yoe = y - era * 400
        let m = Int64(month), doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + Int64(day) - 1
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy
        return (era * 146097 + doe - 719468) * 86_400 + Int64(hour) * 3_600 + Int64(minute) * 60 + Int64(second)
    }
}

/// Session-level TLS 1.3 pin/CA evaluator & `3xx` redirect blocker with per-task error map (`Trap A` & `Trap B`).
internal final class SyncSessionDelegate: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    let scheme: String, tlsMode: String, expectedPins: [(hex: String, digest: Data)]
    private let lock = NSLock()
    private var tlsErrors: [Int: SyncError] = [:]

    init(scheme: String, tlsMode: String, expectedPins: [(hex: String, digest: Data)]) {
        self.scheme = scheme; self.tlsMode = tlsMode; self.expectedPins = expectedPins
    }

    func recordTaskError(_ taskId: Int, _ err: SyncError) { lock.lock(); tlsErrors[taskId] = err; lock.unlock() }
    func takeTaskError(_ taskId: Int) -> SyncError? { lock.lock(); defer { lock.unlock() }; return tlsErrors.removeValue(forKey: taskId) }

    func evaluateServerTrust(_ serverTrust: SecTrust) -> Result<URLCredential, SyncError> {
        if tlsMode == TlsMode.spkiPin {
            guard let chain = SecTrustCopyCertificateChain(serverTrust),
                  CFArrayGetCount(chain) > 0,
                  let rawLeaf = CFArrayGetValueAtIndex(chain, 0) else {
                return .failure(SyncError(code: .errTlsCertInvalid, message: "relay presented no TLS leaf certificate"))
            }
            let leaf = Unmanaged<SecCertificate>.fromOpaque(rawLeaf).takeUnretainedValue()
            guard CFGetTypeID(leaf) == SecCertificateGetTypeID() else {
                return .failure(SyncError(code: .errTlsCertInvalid, message: "invalid leaf certificate CFType"))
            }
            let parsed: (spkiDER: Data, notBeforeUnix: Int64, notAfterUnix: Int64)
            do { parsed = try X509SpkiExtractor.extractSpkiAndValidity(certDER: SecCertificateCopyData(leaf) as Data) }
            catch let se as SyncError { return .failure(se) }
            catch { return .failure(SyncError(code: .errTlsCertInvalid, message: "failed to parse relay X.509 DER")) }

            let nowUnix = Int64(Date().timeIntervalSince1970)
            guard nowUnix >= parsed.notBeforeUnix && nowUnix <= parsed.notAfterUnix else {
                return .failure(SyncError(code: .errTlsCertInvalid, message: "relay certificate expired or not yet valid"))
            }
            let gotDigest = SyncCrypto.sha256(parsed.spkiDER)
            var matched = false
            for (_, wantDigest) in expectedPins where SyncCrypto.constantTimeEquals(gotDigest, wantDigest) { matched = true }
            guard matched else {
                return .failure(SyncError(
                    code: .errTlsPinMismatch, message: "relay leaf SPKI SHA-256 pin mismatch", retryable: false,
                    details: ["expected_pin": expectedPins.first?.hex ?? "", "got_pin": SyncCrypto.hexEncode(gotDigest)]
                ))
            }
            return .success(URLCredential(trust: serverTrust))
        }
        var cfErr: CFError?
        guard SecTrustEvaluateWithError(serverTrust, &cfErr) else {
            return .failure(SyncError(code: .errTlsCertInvalid, message: "system CA certificate evaluation failed"))
        }
        return .success(URLCredential(trust: serverTrust))
    }

    func handleChallenge(task: URLSessionTask, challenge: URLAuthenticationChallenge, onError: ((SyncError) -> Void)? = nil, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust, let serverTrust = challenge.protectionSpace.serverTrust else {
            completionHandler(.performDefaultHandling, nil); return
        }
        switch evaluateServerTrust(serverTrust) {
        case .success(let cred): completionHandler(.useCredential, cred)
        case .failure(let err): onError?(err); recordTaskError(task.taskIdentifier, err); completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }

    func redirectBlockedError(_ statusCode: Int) -> SyncError {
        SyncError(code: .errRelayUnreachable, message: "relay HTTP redirect blocked for credential and SPKI pin safety", retryable: false, httpStatus: statusCode)
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        handleChallenge(task: task, challenge: challenge, completionHandler: completionHandler)
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        recordTaskError(task.taskIdentifier, redirectBlockedError(response.statusCode)); completionHandler(nil)
    }
}

internal final class TaskCaptureDelegate: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    private let parent: SyncSessionDelegate
    private let lock = NSLock()
    private var taskId: Int = -1
    private var capturedError: SyncError?

    init(parent: SyncSessionDelegate) { self.parent = parent }

    func urlSession(_ session: URLSession, didCreateTask task: URLSessionTask) { lock.lock(); taskId = task.taskIdentifier; lock.unlock() }

    func urlSession(_ session: URLSession, task: URLSessionTask, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        lock.lock(); taskId = task.taskIdentifier; lock.unlock()
        parent.handleChallenge(task: task, challenge: challenge, onError: { err in
            self.lock.lock(); self.capturedError = err; self.lock.unlock()
        }, completionHandler: completionHandler)
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        let err = parent.redirectBlockedError(response.statusCode)
        lock.lock(); taskId = task.taskIdentifier; capturedError = err; lock.unlock()
        parent.recordTaskError(task.taskIdentifier, err); completionHandler(nil)
    }

    func takeError() -> SyncError? {
        lock.lock(); let local = capturedError; capturedError = nil; let id = taskId; lock.unlock()
        if let local = local { _ = parent.takeTaskError(id); return local }
        return id >= 0 ? parent.takeTaskError(id) : nil
    }
}

/// TLS 1.3 HTTP/SSE transport with SPKI multi-pinning, scoped `409 ERR_CLOCK_SKEW` calibration, and raw-byte SSE parser.
public final class SyncTransport: @unchecked Sendable {
    public static let clientAgentHeader = "synctool-swift/0.4.0"
    private static let maxControlResponseBytes = 4 * 1024 * 1024
    private static let sseReadIdleTimeoutSec: TimeInterval = 60.0
    private static let minValidServerTs: Int64 = 1_700_000_000, maxValidServerTs: Int64 = 4_102_444_800, maxCalibratedOffsetSec: Int64 = 86_400

    public let profile: RelayProfile
    private let sessionDelegate: SyncSessionDelegate, httpSession: URLSession, sseSession: URLSession
    private let offsetLock = NSLock()
    private var clockOffsetSecInternal: Int64 = 0

    public init(rawProfile: RelayProfile) throws {
        let canonicalOrigin = try SyncCrypto.canonicalRelayOrigin(rawProfile.endpoint)
        guard rawProfile.accessKey.count >= 32 else { throw SyncError(code: .errUriInvalid, message: "relay access_key must be >= 32 characters") }
        let (scheme, host) = SyncUri.extractSchemeAndHost(canonicalOrigin)
        let validatedPins = rawProfile.resolvedPins.isEmpty ? [] : try SyncUri.parseAndValidateSpkiPins(rawProfile.resolvedPins.joined(separator: ","))

        let rawMode = rawProfile.tlsMode.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let normalizedMode: String
        switch rawMode {
        case "": normalizedMode = validatedPins.isEmpty ? TlsMode.systemCa : TlsMode.spkiPin
        case TlsMode.systemCa, TlsMode.caAlias: normalizedMode = TlsMode.systemCa
        case TlsMode.spkiPin: normalizedMode = TlsMode.spkiPin
        default: throw SyncError(code: .errUriInvalid, message: "unsupported tls_mode")
        }
        if scheme == "https" {
            if normalizedMode == TlsMode.spkiPin && validatedPins.isEmpty { throw SyncError(code: .errUriInvalid, message: "spki_pin mode requires at least 1 64-hex SPKI pin") }
            if normalizedMode == TlsMode.systemCa && SyncCrypto.isIpHost(host) { throw SyncError(code: .errUriInvalid, message: "bare IP relay requires spki_pin mode and 64-hex SPKI pin") }
        }
        let relayId = rawProfile.relayId.isEmpty ? SyncCrypto.deriveRelayId(canonicalOrigin) : rawProfile.relayId
        self.profile = RelayProfile(endpoint: canonicalOrigin, accessKey: rawProfile.accessKey, tlsMode: normalizedMode, spkiPins: validatedPins, relayId: relayId, alias: rawProfile.alias, isDefault: rawProfile.isDefault)
        let delegate = SyncSessionDelegate(scheme: scheme, tlsMode: normalizedMode, expectedPins: try validatedPins.map { ($0, try SyncCrypto.hexDecode($0)) })
        self.sessionDelegate = delegate

        func makeConfig(_ timeout: TimeInterval) -> URLSessionConfiguration {
            let cfg = URLSessionConfiguration.ephemeral
            cfg.tlsMinimumSupportedProtocolVersion = .TLSv13; cfg.httpCookieAcceptPolicy = .never; cfg.httpShouldSetCookies = false
            cfg.urlCache = nil; cfg.requestCachePolicy = .reloadIgnoringLocalCacheData
            cfg.timeoutIntervalForRequest = timeout; cfg.timeoutIntervalForResource = 0
            return cfg
        }
        self.httpSession = URLSession(configuration: makeConfig(35.0), delegate: delegate, delegateQueue: nil)
        self.sseSession = URLSession(configuration: makeConfig(Self.sseReadIdleTimeoutSec), delegate: delegate, delegateQueue: nil)
    }

    public func getClockOffsetSec() -> Int64 { offsetLock.lock(); defer { offsetLock.unlock() }; return clockOffsetSecInternal }
    public func setClockOffsetSec(_ offsetSec: Int64) {
        let clamped = min(max(offsetSec, -Self.maxCalibratedOffsetSec), Self.maxCalibratedOffsetSec)
        offsetLock.lock(); clockOffsetSecInternal = clamped; offsetLock.unlock()
    }
    public func relayAuthUnixNow() -> Int64 { Int64(Date().timeIntervalSince1970) + getClockOffsetSec() }
    public func close() { httpSession.invalidateAndCancel(); sseSession.invalidateAndCancel() }

    internal func doControl(method: String, pathAndQuery: String, jsonBodyBytes: Data? = nil, opts: RequestAuthOptions = RequestAuthOptions()) async throws -> RawHttpResponse {
        var effective = opts
        if jsonBodyBytes != nil && effective.contentType.isEmpty { effective.contentType = "application/json; charset=utf-8" }
        return try await executeWithSkewRetry {
            let (req, callDel) = try self.buildSignedRequest(method: method, pathAndQuery: pathAndQuery, controlBody: jsonBodyBytes, streamLen: nil, opts: effective)
            let (data, resp) = try await self.runDataCall(req: req, callDelegate: callDel, maxBytes: Self.maxControlResponseBytes)
            return try self.validateResponse(data: data, resp: resp)
        }
    }

    internal func doStreamUpload(method: String, pathAndQuery: String, chunkData: Data, opts: RequestAuthOptions) async throws -> RawHttpResponse {
        var effective = opts
        if effective.contentType.isEmpty { effective.contentType = "application/octet-stream" }
        return try await executeWithSkewRetry {
            var (req, callDel) = try self.buildSignedRequest(method: method, pathAndQuery: pathAndQuery, controlBody: nil, streamLen: Int64(chunkData.count), opts: effective)
            req.setValue("\(chunkData.count)", forHTTPHeaderField: "Content-Length")
            do {
                let (data, rawResp) = try await self.httpSession.upload(for: req, from: chunkData, delegate: callDel)
                if let tlsErr = callDel.takeError() { throw tlsErr }
                return try self.validateResponse(data: data, resp: rawResp)
            } catch { throw self.classifyTransportError(error, callDelegate: callDel) }
        }
    }

    internal func fetchChunkData(pathAndQuery: String, opts: RequestAuthOptions) async throws -> Data {
        try await executeWithSkewRetry {
            let (req, callDel) = try self.buildSignedRequest(method: "GET", pathAndQuery: pathAndQuery, controlBody: nil, streamLen: nil, opts: opts)
            let (data, resp) = try await self.runDataCall(req: req, callDelegate: callDel, maxBytes: 8 * 1024 * 1024)
            return try self.validateResponse(data: data, resp: resp).body
        }
    }

    internal func sseEvents(pathAndQuery: String, opts: RequestAuthOptions) -> AsyncThrowingStream<SseEvent, Error> {
        AsyncThrowingStream { continuation in
            let task = Task {
                do {
                    try await self.consumeSseStream(pathAndQuery: pathAndQuery, opts: opts) { continuation.yield($0) }
                    continuation.finish()
                } catch { continuation.finish(throwing: error) }
            }
            continuation.onTermination = { @Sendable _ in task.cancel() }
        }
    }

    private func consumeSseStream(pathAndQuery: String, opts: RequestAuthOptions, onEvent: (SseEvent) -> Void) async throws {
        var sseOpts = opts; sseOpts.acceptSse = true
        let (asyncBytes, callDel) = try await openSignedSseBytes(pathAndQuery: pathAndQuery, opts: sseOpts)
        var lineBuf = Data(capacity: 512), curId = "", curEvent = "", dataLines: [String] = []
        func flush() {
            guard !curEvent.isEmpty || !dataLines.isEmpty || !curId.isEmpty else { return }
            onEvent(SseEvent(id: curId, event: curEvent, data: dataLines.joined(separator: "\n")))
            curId = ""; curEvent = ""; dataLines.removeAll(keepingCapacity: true)
        }
        do {
            for try await byte in asyncBytes {
                try Task.checkCancellation()
                if byte == 0x0A {
                    if lineBuf.last == 0x0D { lineBuf.removeLast() }
                    if lineBuf.isEmpty { flush() }
                    else if lineBuf[lineBuf.startIndex] != 0x3A {
                        let line = String(decoding: lineBuf, as: UTF8.self)
                        if let colon = line.firstIndex(of: ":") {
                            let field = String(line[..<colon])
                            var valSub = line[line.index(after: colon)...]
                            if valSub.first == " " { valSub = valSub.dropFirst() }
                            switch field {
                            case "event": curEvent = String(valSub)
                            case "data": dataLines.append(String(valSub))
                            case "id": curId = String(valSub)
                            default: break
                            }
                        }
                    }
                    lineBuf.removeAll(keepingCapacity: true)
                } else if lineBuf.count < 262_144 { lineBuf.append(byte) }
            }
            flush()
        } catch { throw classifyTransportError(error, callDelegate: callDel) }
    }

    private func openSignedSseBytes(pathAndQuery: String, opts: RequestAuthOptions) async throws -> (URLSession.AsyncBytes, TaskCaptureDelegate) {
        for attempt in 0..<2 {
            let (req, callDel) = try buildSignedRequest(method: "GET", pathAndQuery: pathAndQuery, controlBody: nil, streamLen: nil, opts: opts)
            let bytes: URLSession.AsyncBytes, rawResp: URLResponse
            do {
                (bytes, rawResp) = try await sseSession.bytes(for: req, delegate: callDel)
                if let tlsErr = callDel.takeError() { throw tlsErr }
            } catch { throw classifyTransportError(error, callDelegate: callDel) }
            guard let http = rawResp as? HTTPURLResponse else { throw SyncError(code: .errRelayUnreachable, message: "non-HTTP SSE response") }
            if (200...299).contains(http.statusCode) { return (bytes, callDel) }
            if (300...399).contains(http.statusCode) {
                throw SyncError(code: .errRelayUnreachable, message: "relay HTTP redirect blocked", retryable: false, httpStatus: http.statusCode)
            }
            var errData = Data()
            do { for try await b in bytes { errData.append(b); if errData.count >= 65_536 { break } } } catch {}
            let wireErr = Self.decodeWireError(statusCode: http.statusCode, headers: extractHeaders(http), body: errData)
            if wireErr.code == .errClockSkew && attempt == 0, let srvTs = Self.extractBoundedServerTs(wireErr.details) {
                calibrateClockOffset(srvTs); continue
            }
            throw wireErr
        }
        throw SyncError(code: .errClockSkew, message: "clock skew persisted after calibration retry", retryable: false, httpStatus: 409)
    }

    private func executeWithSkewRetry<T>(_ op: () async throws -> T) async throws -> T {
        for attempt in 0..<2 {
            do { return try await op() }
            catch let se as SyncError where se.code == .errClockSkew && attempt == 0 {
                if let srvTs = Self.extractBoundedServerTs(se.details) { calibrateClockOffset(srvTs); continue }
                throw se
            }
        }
        throw SyncError(code: .errClockSkew, message: "clock skew persisted after calibration retry", retryable: false, httpStatus: 409)
    }

    private func buildSignedRequest(method: String, pathAndQuery: String, controlBody: Data?, streamLen: Int64?, opts: RequestAuthOptions) throws -> (URLRequest, TaskCaptureDelegate) {
        guard let url = URL(string: profile.endpoint + pathAndQuery) else { throw SyncError(code: .errUriInvalid, message: "invalid request URL path") }
        let ts = "\(relayAuthUnixNow())", nonce = try SyncCrypto.generateNonceHex()
        let bodyBinding = streamLen.map { SyncCrypto.bodyBindingStream($0) } ?? SyncCrypto.bodyBindingControl(controlBody)
        let extraBinding = SyncCrypto.extraTokenBinding(depositToken: opts.depositToken, uploadToken: opts.uploadToken)
        let sig = SyncCrypto.signRelayRequest(accessKey: profile.accessKey, method: method, pathAndRawQuery: pathAndQuery, ts: ts, nonce: nonce, bodyBinding: bodyBinding, extraTokenBinding: extraBinding)

        var req = URLRequest(url: url)
        req.httpMethod = method.uppercased()
        req.setValue(Self.clientAgentHeader, forHTTPHeaderField: SyncCrypto.headerClientAgent)
        req.setValue(ts, forHTTPHeaderField: SyncCrypto.headerRelayTs)
        req.setValue(nonce, forHTTPHeaderField: SyncCrypto.headerRelayNonce)
        req.setValue(sig, forHTTPHeaderField: SyncCrypto.headerRelaySig)
        if !opts.contentType.isEmpty { req.setValue(opts.contentType, forHTTPHeaderField: "Content-Type") }
        if opts.acceptSse { req.setValue("text/event-stream", forHTTPHeaderField: "Accept") }
        if !opts.roomToken.isEmpty { req.setValue(opts.roomToken, forHTTPHeaderField: SyncCrypto.headerRoomToken) }
        if !opts.depositToken.isEmpty { req.setValue(opts.depositToken, forHTTPHeaderField: SyncCrypto.headerDepositToken) }
        if !opts.uploadToken.isEmpty { req.setValue(opts.uploadToken, forHTTPHeaderField: SyncCrypto.headerUploadToken) }
        if !opts.mailboxId.isEmpty, let mbSeed = opts.mailboxAuthSeed32 {
            req.setValue(try SyncCrypto.signMailboxRequest(mailboxAuthSeed32: mbSeed, method: method, pathAndRawQuery: pathAndQuery, mailboxId: opts.mailboxId, ts: ts, nonce: nonce, bodyBinding: bodyBinding), forHTTPHeaderField: SyncCrypto.headerMailboxSig)
        }
        if streamLen == nil, let body = controlBody { req.httpBody = body; req.setValue("\(body.count)", forHTTPHeaderField: "Content-Length") }
        else if streamLen == nil && ["POST", "PUT", "PATCH"].contains(req.httpMethod ?? "") { req.httpBody = Data(); req.setValue("0", forHTTPHeaderField: "Content-Length") }
        return (req, TaskCaptureDelegate(parent: sessionDelegate))
    }

    private func runDataCall(req: URLRequest, callDelegate: TaskCaptureDelegate, maxBytes: Int) async throws -> (Data, URLResponse) {
        do {
            let (data, resp) = try await httpSession.data(for: req, delegate: callDelegate)
            if let tlsErr = callDelegate.takeError() { throw tlsErr }
            if data.count > maxBytes { throw SyncError(code: .errBadRequest, message: "response exceeded \(maxBytes)-byte limit", retryable: false) }
            return (data, resp)
        } catch { throw classifyTransportError(error, callDelegate: callDelegate) }
    }

    private func validateResponse(data: Data, resp: URLResponse) throws -> RawHttpResponse {
        guard let http = resp as? HTTPURLResponse else { throw SyncError(code: .errRelayUnreachable, message: "non-HTTP relay response") }
        let headers = extractHeaders(http)
        if (300...399).contains(http.statusCode) { throw SyncError(code: .errRelayUnreachable, message: "relay HTTP redirect blocked", retryable: false, httpStatus: http.statusCode) }
        if (200...299).contains(http.statusCode) { return RawHttpResponse(statusCode: http.statusCode, headers: headers, body: data) }
        throw Self.decodeWireError(statusCode: http.statusCode, headers: headers, body: data)
    }

    private func extractHeaders(_ http: HTTPURLResponse) -> [String: String] {
        var out: [String: String] = [:]; for (k, v) in http.allHeaderFields { out["\(k)".lowercased()] = "\(v)" }; return out
    }

    internal func classifyTransportError(_ error: Error, callDelegate: TaskCaptureDelegate?) -> SyncError {
        if let tlsErr = callDelegate?.takeError() { return tlsErr }
        if let se = error as? SyncError { return se }
        if error is CancellationError || Task.isCancelled { return SyncError(code: .errCancelled, message: "operation cancelled", retryable: false) }
        if let ue = error as? URLError {
            switch ue.code {
            case .cancelled: return SyncError(code: .errCancelled, message: "request cancelled", retryable: false)
            case .serverCertificateUntrusted, .serverCertificateHasBadDate, .serverCertificateHasUnknownRoot,
                 .serverCertificateNotYetValid, .secureConnectionFailed, .clientCertificateRejected, .clientCertificateRequired:
                return SyncError(code: .errTlsCertInvalid, message: "TLS certificate or handshake verification failed", retryable: false)
            case .timedOut: return SyncError(code: .errRelayUnreachable, message: "relay request timed out", retryable: true)
            default: return SyncError(code: .errRelayUnreachable, message: "relay unreachable", retryable: true)
            }
        }
        return SyncError(code: .errRelayUnreachable, message: "relay unreachable", retryable: true)
    }

    private func calibrateClockOffset(_ serverTs: Int64) { setClockOffsetSec(serverTs - Int64(Date().timeIntervalSince1970)) }

    internal static func decodeWireError(statusCode: Int, headers: [String: String], body: Data) -> SyncError {
        let trimmed = String(decoding: body, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
        if statusCode == 404 && trimmed.isEmpty { return SyncError(code: .errAuthFailed, message: "relay rejected authentication (silent 404)", retryable: false, httpStatus: 404) }
        if !trimmed.isEmpty, let data = trimmed.data(using: .utf8),
           let obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
           let wireCode = obj["error"] as? String, !wireCode.isEmpty {
            let msg = (obj["message"] as? String) ?? "", retryable = obj["retryable"] as? Bool
            var details: [String: String] = [:]
            for (k, v) in obj where k != "error" && k != "message" && k != "retryable" {
                if let s = v as? String { details[k] = s } else if let n = v as? NSNumber { details[k] = n.stringValue }
            }
            var retryAfterSec: Int?
            if let ra = headers["retry-after"]?.trimmingCharacters(in: .whitespacesAndNewlines), !ra.isEmpty {
                details["retry_after"] = ra
                if let sec = Int(ra) { details["retry_after_sec"] = "\(sec)"; retryAfterSec = sec }
            }
            return SyncError(wireCode: wireCode, message: msg, retryable: retryable, httpStatus: statusCode, retryAfterSec: retryAfterSec, details: details)
        }
        if statusCode == 404 { return SyncError(code: .errAuthFailed, message: "relay returned stealth 404", retryable: false, httpStatus: 404) }
        return SyncError(code: .errRelayUnreachable, message: "unexpected relay status \(statusCode)", retryable: statusCode >= 500, httpStatus: statusCode)
    }

    internal static func extractBoundedServerTs(_ details: [String: String]) -> Int64? {
        guard let raw = details["server_ts"] else { return nil }
        if let ts = Int64(raw), (minValidServerTs...maxValidServerTs).contains(ts) {
            return ts
        }
        if let d = Double(raw), d.isFinite, d >= Double(minValidServerTs), d <= Double(maxValidServerTs) {
            return Int64(d)
        }
        return nil
    }
}
