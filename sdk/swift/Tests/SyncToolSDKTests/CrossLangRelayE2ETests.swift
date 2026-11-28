import Darwin
import Foundation
import XCTest
@testable import SyncToolSDK

#if os(macOS)

private actor AsyncSignal<T: Sendable> {
    private var value: T?
    private var waiters: [UUID: CheckedContinuation<T, Error>] = [:]
    private var cancelledIds: Set<UUID> = []

    func complete(_ v: T) {
        guard value == nil else { return }
        value = v
        let pending = Array(waiters.values)
        waiters.removeAll()
        cancelledIds.removeAll()
        for c in pending { c.resume(returning: v) }
    }

    func wait(timeoutSec: Double = 15.0) async throws -> T {
        if let v = value { return v }
        return try await withThrowingTaskGroup(of: T.self) { group in
            group.addTask {
                let id = UUID()
                return try await withTaskCancellationHandler {
                    try await withCheckedThrowingContinuation { cont in
                        Task { await self.enqueue(id: id, cont: cont) }
                    }
                } onCancel: {
                    Task { await self.cancelWaiter(id: id) }
                }
            }
            group.addTask {
                try await Task.sleep(nanoseconds: UInt64(timeoutSec * 1_000_000_000))
                throw SyncError(code: .errHandshakeTimeout, message: "AsyncSignal timed out after \(timeoutSec)s")
            }
            let first = try await group.next()!
            group.cancelAll()
            return first
        }
    }

    private func enqueue(id: UUID, cont: CheckedContinuation<T, Error>) {
        if let v = value {
            cont.resume(returning: v)
        } else if cancelledIds.remove(id) != nil {
            cont.resume(throwing: CancellationError())
        } else {
            waiters[id] = cont
        }
    }

    private func cancelWaiter(id: UUID) {
        cancelledIds.insert(id)
        if let cont = waiters.removeValue(forKey: id) {
            cont.resume(throwing: CancellationError())
        }
    }
}

final class CrossLangRelayE2ETests: XCTestCase {
    private var relayProcess: Process?
    private var relayDataDir: URL?
    private var workDir: URL?
    private var relayUri: String = ""
    private var relayProfile: RelayProfile!

    private func findFreePort() throws -> UInt16 {
        let sock = Darwin.socket(AF_INET, SOCK_STREAM, 0)
        guard sock >= 0 else { throw SyncError(code: .errStorageIo, message: "socket() failed") }
        defer { _ = Darwin.close(sock) }
        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = 0
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        let bindRes = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(sock, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
        }
        guard bindRes == 0 else { throw SyncError(code: .errStorageIo, message: "bind(0) failed") }
        var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        let nameRes = withUnsafeMutablePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.getsockname(sock, $0, &len) }
        }
        guard nameRes == 0 else { throw SyncError(code: .errStorageIo, message: "getsockname() failed") }
        return UInt16(bigEndian: addr.sin_port)
    }

    override func setUp() async throws {
        try await super.setUp()
        let rawBin = (ProcessInfo.processInfo.environment["SYNCTOOL_RELAY_BIN"] ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        guard !rawBin.isEmpty else {
            throw XCTSkip("SYNCTOOL_RELAY_BIN is unset; skipping live Go synctool-relay E2E suite")
        }
        let binURL = URL(fileURLWithPath: rawBin)
        XCTAssertTrue(FileManager.default.fileExists(atPath: binURL.path), "SYNCTOOL_RELAY_BIN missing at \(binURL.path)")

        let baseTmp = FileManager.default.temporaryDirectory
        let dataDir = baseTmp.appendingPathComponent("synctool-swift-relay-\(UUID().uuidString)", isDirectory: true)
        let tempWork = baseTmp.appendingPathComponent("synctool-swift-work-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dataDir, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: tempWork, withIntermediateDirectories: true)
        self.relayDataDir = dataDir
        self.workDir = tempWork

        let listenAddr = "127.0.0.1:\(try findFreePort())"
        let commonArgs = ["--public-host", "127.0.0.1", "--listen", listenAddr, "--profile", "standard", "--spool", "disk", "--tls", "selfsigned", "--data-dir", dataDir.path]

        let initProc = Process()
        initProc.executableURL = binURL
        initProc.arguments = ["init"] + commonArgs
        let initPipe = Pipe()
        initProc.standardOutput = initPipe
        initProc.standardError = initPipe
        try initProc.run()
        let initData = initPipe.fileHandleForReading.readDataToEndOfFile()
        initProc.waitUntilExit()
        let initOut = String(decoding: initData, as: UTF8.self)
        XCTAssertEqual(0, initProc.terminationStatus, "synctool-relay init failed:\n\(Redact.message(initOut))")

        let regex = try NSRegularExpression(pattern: #"synctool://relay\?[^\s]+"#)
        guard let match = regex.firstMatch(in: initOut, range: NSRange(initOut.startIndex..<initOut.endIndex, in: initOut)),
              let range = Range(match.range, in: initOut) else {
            XCTFail("Failed to parse synctool://relay URI from init output"); return
        }
        self.relayUri = String(initOut[range]).trimmingCharacters(in: .whitespacesAndNewlines)
        self.relayProfile = try SyncUri.parseRelayUri(relayUri)

        let serveProc = Process()
        serveProc.executableURL = binURL
        serveProc.arguments = ["serve"] + commonArgs
        // Prevent 64 KiB macOS pipe buffer stall during multi-MiB transfers
        serveProc.standardOutput = FileHandle.nullDevice
        serveProc.standardError = FileHandle.nullDevice
        try serveProc.run()
        self.relayProcess = serveProc

        let probe = try SyncClient(relayUri: relayUri, deviceLabel: "ReadyProbe")
        defer { Task { await probe.close() } }
        var ready = false
        for _ in 0..<100 {
            if !serveProc.isRunning { XCTFail("synctool-relay serve exited prematurely (\(serveProc.terminationStatus))"); return }
            if (try? await probe.ping()) != nil { ready = true; break }
            try await Task.sleep(nanoseconds: 100_000_000)
        }
        XCTAssertTrue(ready, "synctool-relay did not respond to ping within 10s")
    }

    override func tearDown() async throws {
        if let proc = relayProcess {
            if proc.isRunning { proc.terminate() }
            proc.waitUntilExit()
        }
        relayProcess = nil
        if let d = relayDataDir { try? FileManager.default.removeItem(at: d) }
        if let w = workDir { try? FileManager.default.removeItem(at: w) }
        try await super.tearDown()
    }

    func testPingClockSkewCalibrationAndTlsPinEnforcement() async throws {
        // 1. Wrong SPKI pin MUST fail closed with ERR_TLS_PIN_MISMATCH (never URLError.cancelled / ERR_CANCELLED!)
        let wrongPin = relayProfile.spkiPin == String(repeating: "0", count: 64) ? String(repeating: "f", count: 64) : String(repeating: "0", count: 64)
        var badProfile = relayProfile!
        badProfile.spkiPins = [wrongPin]; badProfile.legacySpkiSha256 = wrongPin
        let badClient = try SyncClient(relay: badProfile, deviceLabel: "WrongPin")
        do {
            _ = try await badClient.ping()
            XCTFail("Expected wrong SPKI pin to fail with ERR_TLS_PIN_MISMATCH")
        } catch let se as SyncError {
            XCTAssertEqual(.errTlsPinMismatch, se.code)
        }
        await badClient.close()

        // 2. Multi-pin rotation list [wrongPin, realPin] MUST succeed via constant-time SPKI matching
        var multiProfile = relayProfile!
        multiProfile.spkiPins = [wrongPin, relayProfile.spkiPin]; multiProfile.legacySpkiSha256 = wrongPin
        let okClient = try SyncClient(relay: multiProfile, deviceLabel: "MultiPin")
        let pingRes = try await okClient.ping()
        XCTAssertEqual(1, pingRes.protoV)
        XCTAssertEqual("standard", pingRes.profile)
        XCTAssertEqual("disk", pingRes.spoolBackend)

        // 3. Deliberate +3600s clock skew auto-calibrates on 409 ERR_CLOCK_SKEW
        okClient.setClockOffsetSec(3600)
        let calibrated = try await okClient.ping()
        XCTAssertEqual(1, calibrated.protoV)
        XCTAssertLessThan(abs(okClient.getClockOffsetSec()), 30)
        await okClient.close()
    }

    func testFlow1AQrOneShotMultiChunk3_2MiB() async throws {
        let dir = workDir!
        // 3,355,443 bytes (~3.2 MiB) spans 52 64-KiB STREAM AEAD blocks and 4 1-MiB standard transport chunks
        let payloadSize = 3_355_443
        var payload = [UInt8](repeating: 0, count: payloadSize)
        for idx in 0..<payloadSize { payload[idx] = UInt8((idx * 37 + 13) & 0xff) }
        let payloadData = Data(payload)
        let expectedSha = SyncCrypto.hexEncode(SyncCrypto.sha256(payloadData))
        let srcFile = dir.appendingPathComponent("vault_3_2mb.bin")
        try payloadData.write(to: srcFile)
        let outDir = dir.appendingPathComponent("bob-out", isDirectory: true)

        let alice = try SyncClient(relayUri: relayUri, appId: "com.yellowdking.gravityssh", deviceLabel: "Alice-Mac", tempDir: dir.appendingPathComponent("alice-tmp"))
        let bob = try SyncClient(relayUri: relayUri, appId: "com.yellowdking.gravityssh", deviceLabel: "Bob-iPhone", tempDir: dir.appendingPathComponent("bob-tmp"))

        let offerSig = AsyncSignal<OfferReadyInfo>()
        let sendTask = Task {
            try await alice.startOneShotSend(
                parcel: ParcelInput(
                    schema: "gravityssh.vault.v1",
                    inlinePayload: ["hosts_count": .int(12), "keys_count": .int(3)],
                    blobs: [BlobInput.fromFile(srcFile, role: "vault_bundle", name: "vault_bundle.json.gz", mime: "application/gzip", encoding: "gzip")]
                ),
                options: PairOptions(mode: SyncHandshake.modeQrOob, includeRelay: true, onOfferReady: { await offerSig.complete($0) })
            )
        }

        let offer = try await offerSig.wait()
        XCTAssertTrue(offer.pairUri.contains("#s="))

        let received = try await bob.receiveOneShot(pairInput: offer.pairUri)
        let sendRes = try await sendTask.value
        XCTAssertEqual("pipe", sendRes.mode)
        XCTAssertEqual(sendRes.msgId, received.manifest.msgId)
        XCTAssertEqual(Int64(payloadSize), received.blobs[0].descriptor.size)
        XCTAssertEqual(expectedSha, received.blobs[0].descriptor.sha256)

        let savedURL = try received.blobs[0].saveToDir(outDir)
        XCTAssertEqual(payloadData, try Data(contentsOf: savedURL))
        await alice.close(); await bob.close()
    }

    func testFlow1BSasFailClosedMutualBindSpoolWatchBurnAnd2PhaseRevoke() async throws {
        let dir = workDir!
        let aliceKs = MemoryKeyStore(), bobKs = MemoryKeyStore(), charlieKs = MemoryKeyStore()
        let alice = try SyncClient(relay: relayProfile, keyStore: aliceKs, appId: "com.yellowdking.gravityssh", deviceLabel: "Alice-Desktop", tempDir: dir.appendingPathComponent("a-sas"))
        let bob = try SyncClient(relay: relayProfile, keyStore: bobKs, appId: "com.yellowdking.gravityssh", deviceLabel: "Bob-iPhone", tempDir: dir.appendingPathComponent("b-sas"))

        // PART A0: Responder omitting mandatory `onSASConfirm` in mode=2 MUST fail closed BEFORE M2!
        do {
            let codeSig = AsyncSignal<String>()
            let initTask = Task {
                try await alice.initiateDeviceBind(options: PairOptions(mode: SyncHandshake.modeCommitSas, onOfferReady: { await codeSig.complete($0.displayCode) }, onSASInput: { "000000" }))
            }
            let code = try await codeSig.wait()
            do {
                _ = try await bob.acceptDeviceBind(pairInput: code, options: PairOptions(mode: SyncHandshake.modeCommitSas, onSASConfirm: nil))
                XCTFail("Expected missing onSASConfirm to fail closed")
            } catch let se as SyncError { XCTAssertEqual(.errSasMismatch, se.code) }
            let bobDevsA0 = try await bobKs.listDevices()
            XCTAssertTrue(bobDevsA0.isEmpty)
            do { _ = try await initTask.value; XCTFail("Expected initiator to observe room burn") }
            catch let se as SyncError { XCTAssertTrue(se.code == .errRoomBurned || se.code == .errNotFound) }
        }

        // PART A: Responder rejecting `onSASConfirm` (returning false) MUST fail closed BEFORE saving peer DeviceCard!
        do {
            let codeSig = AsyncSignal<String>(), sasSig = AsyncSignal<String>()
            let initTask = Task {
                try await alice.initiateDeviceBind(options: PairOptions(mode: SyncHandshake.modeCommitSas, onOfferReady: { await codeSig.complete($0.displayCode) }, onSASInput: { try await sasSig.wait() }))
            }
            let code = try await codeSig.wait()
            do {
                _ = try await bob.acceptDeviceBind(pairInput: code, options: PairOptions(mode: SyncHandshake.modeCommitSas, onSASConfirm: { sas in await sasSig.complete(sas); return false }))
                XCTFail("Expected SAS rejection to throw ERR_SAS_MISMATCH")
            } catch let se as SyncError { XCTAssertEqual(.errSasMismatch, se.code) }
            let bobDevsA = try await bobKs.listDevices()
            XCTAssertTrue(bobDevsA.isEmpty)
            do { _ = try await initTask.value; XCTFail("Expected initiator failure on burned room") }
            catch let se as SyncError { XCTAssertTrue([ErrorCode.errRoomBurned, .errNotFound, .errSasMismatch].contains(se.code)) }
        }

        // PART B: Positive Flow 1B mutual SAS Device Bind with ONLY `onSASConfirm` (proves zero deadlock!)
        let posCodeSig = AsyncSignal<String>(), posSasSig = AsyncSignal<String>()
        let posInitTask = Task {
            try await alice.initiateDeviceBind(options: PairOptions(mode: SyncHandshake.modeCommitSas, onOfferReady: { await posCodeSig.complete($0.displayCode) }, onSASInput: { try await posSasSig.wait() }))
        }
        let posCode = try await posCodeSig.wait()
        let aliceOnBob = try await bob.acceptDeviceBind(pairInput: posCode, options: PairOptions(mode: SyncHandshake.modeCommitSas, onSASConfirm: { sas in await posSasSig.complete(sas); return sas.count == 6 }))
        let bobOnAlice = try await posInitTask.value
        let aliceIdentity = try await alice.getIdentity()
        let bobIdentity = try await bob.getIdentity()
        XCTAssertEqual(aliceIdentity.deviceId, aliceOnBob.deviceId)
        XCTAssertEqual(bobIdentity.deviceId, bobOnAlice.deviceId)
        XCTAssertFalse(bobOnAlice.mailboxId.isEmpty)

        // Pair Charlie <-> Bob via QR
        let charlie = try SyncClient(relay: relayProfile, keyStore: charlieKs, appId: "com.yellowdking.gravityssh", deviceLabel: "Charlie-iPad", tempDir: dir.appendingPathComponent("c-tmp"))
        let qrSig = AsyncSignal<String>()
        let charliePairTask = Task { try await charlie.initiateDeviceBind(options: PairOptions(mode: SyncHandshake.modeQrOob, onOfferReady: { await qrSig.complete($0.pairUri) })) }
        _ = try await bob.acceptDeviceBind(pairInput: try await qrSig.wait())
        let bobOnCharlie = try await charliePairTask.value

        // PART C: Flow 2 0-RTT Mode B Spool + Foreground `watchInbox` + Two-Phase `listInbox` + `fetchParcel` + `ackItem` Burn!
        let watchSig = AsyncSignal<InboxWatchEvent>()
        let watchTask = Task {
            for try await ev in bob.watchInbox() {
                await watchSig.complete(ev); break
            }
        }
        try await Task.sleep(nanoseconds: 200_000_000)

        var blobArr = [UInt8](repeating: 0, count: 150_000)
        for idx in 0..<blobArr.count { blobArr[idx] = UInt8((idx * 19 + 5) & 0xff) }
        let blobData = Data(blobArr)
        let sendRes = try await alice.sendToPeer(
            targetDeviceId: bobOnAlice.deviceId,
            parcel: ParcelInput(schema: "gravityssh.vault.v1", inlinePayload: ["summary": .string("2-phase-test")], blobs: [BlobInput.fromData(blobData, name: "vault_bundle.json.gz", role: "vault_bundle", mime: "application/gzip", encoding: "gzip")])
        )
        XCTAssertEqual("spool", sendRes.mode)
        let watched = try await watchSig.wait()
        XCTAssertEqual(sendRes.itemId, watched.itemId)
        watchTask.cancel()

        let inbox1 = try await bob.listInbox()
        XCTAssertEqual(1, inbox1.count); XCTAssertFalse(inbox1[0].cached)
        let inbox2 = try await bob.listInbox(filterAppId: "com.yellowdking.gravityssh")
        XCTAssertEqual(1, inbox2.count); XCTAssertTrue(inbox2[0].cached)

        do {
            _ = try await bob.fetchParcel(itemId: sendRes.itemId, appId: "com.other.app", autoAck: false)
            XCTFail("Expected mismatched appId rejection")
        } catch let se as SyncError { XCTAssertEqual(.errManifestInvalid, se.code) }

        let fetched = try await bob.fetchParcel(itemId: sendRes.itemId, appId: "com.yellowdking.gravityssh", autoAck: false)
        XCTAssertEqual(blobData, try fetched.blobs[0].readBytesVerified())
        let inboxBeforeAck = try await bob.listInbox()
        XCTAssertEqual(1, inboxBeforeAck.count)

        try await bob.ackItem(itemId: sendRes.itemId)
        try await bob.ackItem(itemId: sendRes.itemId) // Idempotent retry on burned item
        let inboxAfterAck = try await bob.listInbox()
        XCTAssertTrue(inboxAfterAck.isEmpty)

        // PART D & E: Online single-device revocation + Offline 2-phase revoke -> `syncMailbox()` retry & cache eviction (`ST-P1-8` & `ST-P0-3`)
        try await bob.revokeDevice(deviceId: aliceOnBob.deviceId)
        do {
            _ = try await alice.sendToPeer(targetDeviceId: bobOnAlice.deviceId, parcel: ParcelInput.text(appId: "com.yellowdking.gravityssh", text: "revoked"))
            XCTFail("Expected revoked Alice token to fail")
        } catch let se as SyncError { XCTAssertEqual(.errUnauthorizedToken, se.code) }

        let charlieSend = try await charlie.sendToPeer(targetDeviceId: bobOnCharlie.deviceId, parcel: ParcelInput.text(appId: "com.yellowdking.gravityssh", text: "charlie-ok"))
        _ = try await bob.listInbox()
        let cachedCharlie = try await bob.listInbox()
        XCTAssertTrue(cachedCharlie[0].cached)

        let charlieId = (try await charlie.getIdentity()).deviceId
        var offlineProfile = relayProfile!
        offlineProfile.endpoint = "https://127.0.0.1:\(try findFreePort())"
        let offlineBob = try SyncClient(relay: offlineProfile, keyStore: bobKs, appId: "com.yellowdking.gravityssh", deviceLabel: "Bob-Offline", tempDir: dir.appendingPathComponent("b-off"))
        do {
            try await offlineBob.revokeDevice(deviceId: charlieId)
            XCTFail("Expected offline revokeDevice to fail on unreachable endpoint after local tombstone")
        } catch let se as SyncError { XCTAssertEqual(.errRelayUnreachable, se.code) }
        await offlineBob.close()

        let tombstone = try await bobKs.getDevice(charlieId)
        XCTAssertEqual(true, tombstone?.revoked)
        XCTAssertEqual(true, tombstone?.pendingTokenDelete)

        let postRevokeInbox = try await bob.listInbox()
        XCTAssertTrue(postRevokeInbox.isEmpty)
        let evictedCache = try await bobKs.getCachedManifest(charlieSend.itemId)
        XCTAssertNil(evictedCache)

        let synced = try await bob.syncMailbox()
        XCTAssertTrue(synced)
        let afterSyncCard = try await bobKs.getDevice(charlieId)
        let afterSyncPending = try await bobKs.listPendingTokenDeletes()
        XCTAssertNil(afterSyncCard)
        XCTAssertTrue(afterSyncPending.isEmpty)

        do {
            _ = try await charlie.sendToPeer(targetDeviceId: bobOnCharlie.deviceId, parcel: ParcelInput.text(appId: "com.yellowdking.gravityssh", text: "blocked"))
            XCTFail("Expected Charlie deposit token deleted after syncMailbox()")
        } catch let se as SyncError { XCTAssertEqual(.errUnauthorizedToken, se.code) }

        await alice.close(); await bob.close(); await charlie.close()
    }

    func testFlow1BSasOneShotAndGoCliCrossLangInterop() async throws {
        let dir = workDir!
        let sender = try SyncClient(relayUri: relayUri, appId: "com.yellowdking.gravityssh", deviceLabel: "Sender-SAS", tempDir: dir.appendingPathComponent("s-1b"))
        let receiver = try SyncClient(relayUri: relayUri, appId: "com.yellowdking.gravityssh", deviceLabel: "Receiver-SAS", tempDir: dir.appendingPathComponent("r-1b"))

        // 1. Positive `mode=2` One-Shot with ONLY `onSASConfirm` (zero deadlock & zero `pipe_ack` wipe race)
        let codeSig = AsyncSignal<String>(), sasSig = AsyncSignal<String>()
        let sendTask = Task {
            try await sender.startOneShotSend(
                parcel: ParcelInput.text(appId: "com.yellowdking.gravityssh", text: "sas-oneshot-payload"),
                options: PairOptions(mode: SyncHandshake.modeCommitSas, onOfferReady: { await codeSig.complete($0.displayCode) }, onSASInput: { try await sasSig.wait() })
            )
        }
        let code = try await codeSig.wait()
        let received = try await receiver.receiveOneShot(
            pairInput: code,
            options: ReceiveOptions(onSASConfirm: { sas in await sasSig.complete(sas); return sas.count == 6 })
        )
        let sendRes = try await sendTask.value
        XCTAssertEqual(sendRes.msgId, received.manifest.msgId)

        // 2. Optional live Go `synctool` CLI -> Go `synctool-relay` -> Swift `SyncClient` E2E when `SYNCTOOL_CLI_BIN` is provided
        let cliBin = (ProcessInfo.processInfo.environment["SYNCTOOL_CLI_BIN"] ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        if !cliBin.isEmpty && FileManager.default.fileExists(atPath: cliBin) {
            let cliFile = dir.appendingPathComponent("cli_note.txt")
            let cliPayload = Data("cross-lang-go-cli-to-swift-sdk".utf8)
            try cliPayload.write(to: cliFile)
            let cliCfg = dir.appendingPathComponent("cli-cfg", isDirectory: true)
            try FileManager.default.createDirectory(at: cliCfg, withIntermediateDirectories: true)

            let cliProc = Process()
            cliProc.executableURL = URL(fileURLWithPath: cliBin)
            cliProc.arguments = ["--json", "--config", cliCfg.path, "--app", "com.yellowdking.gravityssh", "send", "--oneshot", "--mode", "qr", "--file", "\(cliFile.path):note"]
            var env = ProcessInfo.processInfo.environment
            env["SYNCTOOL_RELAY"] = relayUri
            cliProc.environment = env
            let outPipe = Pipe()
            let errPipe = Pipe()
            cliProc.standardOutput = outPipe
            cliProc.standardError = errPipe
            try cliProc.run()
            try? outPipe.fileHandleForWriting.close()
            try? errPipe.fileHandleForWriting.close()
            defer { if cliProc.isRunning { cliProc.terminate() } }

            let uriSig = AsyncSignal<String>()
            let readHandle = outPipe.fileHandleForReading
            Task.detached {
                var buf = Data()
                var scratch = [UInt8](repeating: 0, count: 1024)
                while true {
                    let n = withExtendedLifetime(readHandle) {
                        scratch.withUnsafeMutableBytes { ptr in
                            Darwin.read(readHandle.fileDescriptor, ptr.baseAddress, ptr.count)
                        }
                    }
                    if n < 0 && errno == EINTR { continue }
                    if n <= 0 { break }
                    buf.append(contentsOf: scratch[0..<n])
                    while let nl = buf.firstIndex(of: 0x0A) {
                        let line = Data(buf[..<nl])
                        buf.removeSubrange(...nl)
                        if let obj = (try? JSONSerialization.jsonObject(with: line)) as? [String: Any],
                           (obj["event"] as? String) == "offer_ready",
                           let pairUri = obj["pair_uri"] as? String {
                            await uriSig.complete(pairUri)
                        }
                    }
                }
                await uriSig.complete("")
            }
            let cliPairUri = try await uriSig.wait()
            if cliPairUri.isEmpty {
                cliProc.waitUntilExit()
                let errData = errPipe.fileHandleForReading.readDataToEndOfFile()
                let errText = Redact.message(String(decoding: errData, as: UTF8.self))
                XCTFail("synctool CLI exited without offer_ready (status=\(cliProc.terminationStatus)): \(errText)")
                return
            }
            let fromGoCli = try await receiver.receiveOneShot(pairInput: cliPairUri)
            cliProc.waitUntilExit()
            XCTAssertEqual(0, cliProc.terminationStatus)
            XCTAssertEqual(1, fromGoCli.blobs.count)
            XCTAssertEqual(cliPayload, try fromGoCli.blobs[0].readBytesVerified())
        }

        await sender.close(); await receiver.close()
    }
}

#else

final class CrossLangRelayE2ETests: XCTestCase {
    func testMacOSRelaySuiteSkippedOniOS() throws {
        XCTAssertTrue(true)
    }
}

#endif
