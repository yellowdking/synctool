package com.yellowdking.synctool.client

import com.yellowdking.synctool.crypto.Handshake
import com.yellowdking.synctool.crypto.KeysAndAuth
import com.yellowdking.synctool.envelope.BlobInput
import com.yellowdking.synctool.envelope.ErrorCode
import com.yellowdking.synctool.envelope.MemoryKeyStore
import com.yellowdking.synctool.envelope.ParcelInput
import com.yellowdking.synctool.envelope.RelayProfile
import com.yellowdking.synctool.envelope.SyncError
import com.yellowdking.synctool.envelope.SyncUri
import java.io.File
import java.io.FileOutputStream
import java.net.ServerSocket
import java.nio.file.Files
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.supervisorScope
import kotlinx.coroutines.withTimeout
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Assume
import org.junit.Before
import org.junit.Test

class CrossLangRelayE2ETest {

    private var relayProcess: Process? = null
    private var relayDataDir: File? = null
    private var workDir: File? = null
    private lateinit var relayUri: String
    private lateinit var relayProfile: RelayProfile

    private fun findFreePort(): Int {
        ServerSocket(0).use { sock ->
            return sock.localPort
        }
    }

    @Before
    fun setUpRelay(): Unit = runBlocking {
        val relayBin = System.getenv("SYNCTOOL_RELAY_BIN")?.trim()
        Assume.assumeTrue(
            "SYNCTOOL_RELAY_BIN is unset; skipping live Go synctool-relay E2E test",
            !relayBin.isNullOrEmpty(),
        )
        val binFile = File(relayBin!!)
        assertTrue("SYNCTOOL_RELAY_BIN does not exist at ${binFile.absolutePath}", binFile.isFile)

        val dataDir = Files.createTempDirectory("synctool-kt-relay-e2e-").toFile()
        val tempWork = Files.createTempDirectory("synctool-kt-work-e2e-").toFile()
        relayDataDir = dataDir
        workDir = tempWork

        val port = findFreePort()
        val listenAddr = "127.0.0.1:$port"

        // 1. Run `synctool-relay init`
        val initProc = ProcessBuilder(
            binFile.absolutePath,
            "init",
            "--public-host", "127.0.0.1",
            "--listen", listenAddr,
            "--profile", "standard",
            "--spool", "disk",
            "--tls", "selfsigned",
            "--data-dir", dataDir.absolutePath,
        ).redirectErrorStream(true).start()

        val initOut = initProc.inputStream.bufferedReader().readText()
        assertTrue("synctool-relay init timed out", initProc.waitFor(15, TimeUnit.SECONDS))
        assertEquals("synctool-relay init failed:\n$initOut", 0, initProc.exitValue())

        val uriMatch = Regex("""synctool://relay\?[^\s]+""").find(initOut)
            ?: throw IllegalStateException("Failed to extract synctool://relay URI from init output:\n$initOut")
        relayUri = uriMatch.value.trim()
        relayProfile = SyncUri.parseRelayUri(relayUri)

        // 2. Spawn `synctool-relay serve`
        val serveProc = ProcessBuilder(
            binFile.absolutePath,
            "serve",
            "--public-host", "127.0.0.1",
            "--listen", listenAddr,
            "--profile", "standard",
            "--spool", "disk",
            "--tls", "selfsigned",
            "--data-dir", dataDir.absolutePath,
        ).redirectErrorStream(true).start()
        relayProcess = serveProc

        // Drain relay output asynchronously to prevent pipe buffer stalls
        Thread({
            runCatching {
                serveProc.inputStream.bufferedReader().forEachLine { /* discard runtime logs */ }
            }
        }, "relay-stdout-drain").apply { isDaemon = true }.start()

        // 3. Poll `ping()` until ready
        SyncClient(relayUri = relayUri, deviceLabel = "ReadyProbe").use { probe ->
            val deadline = System.currentTimeMillis() + 10_000L
            var ready = false
            while (System.currentTimeMillis() < deadline) {
                if (!serveProc.isAlive) {
                    fail("synctool-relay serve exited prematurely with code ${serveProc.exitValue()}")
                }
                try {
                    probe.ping()
                    ready = true
                    break
                } catch (_: Throwable) {
                    delay(100L)
                }
            }
            assertTrue("synctool-relay did not respond to ping within 10s", ready)
        }
        Unit
    }

    @After
    fun tearDownRelay(): Unit {
        relayProcess?.let { proc ->
            proc.destroy()
            if (!proc.waitFor(3, TimeUnit.SECONDS)) {
                proc.destroyForcibly()
                proc.waitFor(2, TimeUnit.SECONDS)
            }
        }
        relayProcess = null
        relayDataDir?.deleteRecursively()
        workDir?.deleteRecursively()
    }

    @Test
    fun testPingClockSkewCalibrationAndTlsPinEnforcement(): Unit = runBlocking {
        // 1. Wrong SPKI pin MUST fail closed with ERR_TLS_PIN_MISMATCH
        val wrongPin = "0".repeat(64).let { if (it == relayProfile.spkiPin) "f".repeat(64) else it }
        val badProfile = relayProfile.copy(
            spkiPins = listOf(wrongPin),
            legacySpkiSha256 = wrongPin,
        )
        SyncClient(SyncClientConfig(relay = badProfile, deviceLabel = "WrongPinClient")).use { badClient ->
            try {
                badClient.ping()
                fail("Expected wrong SPKI pin to fail with ERR_TLS_PIN_MISMATCH")
            } catch (se: SyncError) {
                assertEquals(ErrorCode.ERR_TLS_PIN_MISMATCH, se.code)
            }
        }

        // 2. Multi-pin rotation list [wrongPin, realPin] MUST succeed via constant-time pin matching
        val multiPinProfile = relayProfile.copy(
            spkiPins = listOf(wrongPin, relayProfile.spkiPin),
            legacySpkiSha256 = wrongPin,
        )
        SyncClient(SyncClientConfig(relay = multiPinProfile, deviceLabel = "MultiPinClient")).use { okClient ->
            val pingRes = okClient.ping()
            assertEquals(1, pingRes.protoV)
            assertEquals("standard", pingRes.profile)
            assertEquals("disk", pingRes.spoolBackend)

            // 3. Deliberate +3600s clock skew auto-calibrates on 409 ERR_CLOCK_SKEW
            okClient.setClockOffsetSec(3600L)
            val calibratedPing = okClient.ping()
            assertEquals(1, calibratedPing.protoV)
            assertTrue("Expected calibrated offset near 0, got ${okClient.getClockOffsetSec()}", kotlin.math.abs(okClient.getClockOffsetSec()) < 30L)
        }
        Unit
    }

    @Test
    fun testFlow1AQrOneShotMultiChunk3_2MiB(): Unit = runBlocking {
        val dir = workDir!!
        // 3.2 MiB (3,355,443 bytes) spans 52 64-KiB STREAM AEAD blocks and 4 1-MiB standard transport chunks!
        val payloadSize = 3_355_443
        val payloadBytes = ByteArray(payloadSize) { idx -> ((idx * 37 + 13) and 0xff).toByte() }
        val expectedSha = KeysAndAuth.toLowerHex(KeysAndAuth.sha256(payloadBytes))
        val srcFile = File(dir, "vault_3_2mb.bin")
        FileOutputStream(srcFile).use { it.write(payloadBytes) }

        val aliceTmp = File(dir, "alice-tmp")
        val bobTmp = File(dir, "bob-tmp")
        val outDir = File(dir, "bob-out")

        SyncClient(relayUri = relayUri, appId = "com.yellowdking.gravityssh", deviceLabel = "Alice-PC", tempDir = aliceTmp).use { alice ->
            SyncClient(relayUri = relayUri, appId = "com.yellowdking.gravityssh", deviceLabel = "Bob-Android", tempDir = bobTmp).use { bob ->
                val offerDeferred = CompletableDeferred<OfferReadyInfo>()

                val sendJob = async(Dispatchers.Default) {
                    alice.startOneShotSend(
                        parcel = ParcelInput(
                            schema = "gravityssh.vault.v1",
                            inlinePayload = buildJsonObject {
                                put("hosts_count", JsonPrimitive(12))
                                put("keys_count", JsonPrimitive(3))
                            },
                            blobs = listOf(
                                BlobInput.fromFile(
                                    file = srcFile,
                                    role = "vault_bundle",
                                    name = "vault_bundle.json.gz",
                                    mime = "application/gzip",
                                    encoding = "gzip",
                                )
                            ),
                        ),
                        options = PairOptions(
                            mode = Handshake.MODE_QR_OOB,
                            includeRelay = true,
                            onOfferReady = { offer -> offerDeferred.complete(offer) },
                        ),
                    )
                }

                val offer = withTimeout(15_000L) { offerDeferred.await() }
                assertTrue(offer.pairUri.contains("#s="))

                var savedFile: File? = null
                val received = withTimeout(30_000L) {
                    bob.receiveOneShot(offer.pairUri) { parcel ->
                        assertEquals(1, parcel.blobs.size)
                        savedFile = parcel.blobs[0].saveToDir(outDir)
                    }
                }
                val sendRes = withTimeout(15_000L) { sendJob.await() }

                assertEquals("pipe", sendRes.mode)
                assertEquals(sendRes.msgId, received.manifest.msgId)
                assertEquals("gravityssh.vault.v1", received.manifest.schema)
                assertEquals(payloadSize.toLong(), received.blobs[0].descriptor.size)
                assertEquals(expectedSha, received.blobs[0].descriptor.sha256)
                assertNotNull(savedFile)
                assertArrayEquals(payloadBytes, savedFile!!.readBytes())
            }
        }
        Unit
    }

    @Test
    fun testFlow1BSasBindFailClosedAndMutualSuccessPlusFlow2ModeBSpoolBurn(): Unit = runBlocking {
        val dir = workDir!!
        val aliceKs = MemoryKeyStore()
        val bobKs = MemoryKeyStore()
        val charlieKs = MemoryKeyStore()

        SyncClient(
            SyncClientConfig(
                relay = relayProfile,
                keyStore = aliceKs,
                appId = "com.yellowdking.gravityssh",
                deviceLabel = "Alice-Desktop",
                tempDir = File(dir, "alice-sas-tmp"),
            )
        ).use { alice ->
            SyncClient(
                SyncClientConfig(
                    relay = relayProfile,
                    keyStore = bobKs,
                    appId = "com.yellowdking.gravityssh",
                    deviceLabel = "Bob-Phone",
                    tempDir = File(dir, "bob-sas-tmp"),
                )
            ).use { bob ->
                // PART A0: Upfront null gate (`ST-P0-1`) — Responder omitting `onSASConfirm` in mode=2 MUST fail closed immediately before M2!
                supervisorScope {
                    val nullRoomDeferred = CompletableDeferred<String>()
                    val nullInitJob = async(Dispatchers.Default) {
                        alice.initiateDeviceBind(
                            PairOptions(
                                mode = Handshake.MODE_COMMIT_SAS,
                                onOfferReady = { info -> nullRoomDeferred.complete(info.displayCode) },
                                onSASInput = { "000000" },
                            )
                        )
                    }
                    val nullCode = withTimeout(10_000L) { nullRoomDeferred.await() }
                    try {
                        bob.acceptDeviceBind(
                            pairInput = nullCode,
                            options = PairOptions(
                                mode = Handshake.MODE_COMMIT_SAS,
                                onSASDisplay = { _ -> },
                                onSASConfirm = null, // Missing mandatory callback!
                            ),
                        )
                        fail("Expected missing Responder onSASConfirm to fail closed immediately with ERR_SAS_MISMATCH")
                    } catch (se: SyncError) {
                        assertEquals(ErrorCode.ERR_SAS_MISMATCH, se.code)
                    }
                    assertTrue(bobKs.listDevices().isEmpty())
                    try {
                        withTimeout(10_000L) { nullInitJob.await() }
                        fail("Expected Initiator to observe room burn when Responder failed upfront null gate")
                    } catch (se: SyncError) {
                        assertTrue(se.code == ErrorCode.ERR_ROOM_BURNED || se.code == ErrorCode.ERR_NOT_FOUND)
                    }
                }

                // PART A: Negative Flow 1B SAS test — Responder rejecting `onSASConfirm` MUST fail closed BEFORE saving DeviceCard!
                supervisorScope {
                    val negRoomDeferred = CompletableDeferred<String>()
                    val negSasDeferred = CompletableDeferred<String>()

                    val negInitiatorJob = async(Dispatchers.Default) {
                        alice.initiateDeviceBind(
                            PairOptions(
                                mode = Handshake.MODE_COMMIT_SAS,
                                onOfferReady = { info -> negRoomDeferred.complete(info.displayCode) },
                                onSASInput = { withTimeout(10_000L) { negSasDeferred.await() } },
                            )
                        )
                    }

                    val negCode = withTimeout(10_000L) { negRoomDeferred.await() }
                    try {
                        bob.acceptDeviceBind(
                            pairInput = negCode,
                            options = PairOptions(
                                mode = Handshake.MODE_COMMIT_SAS,
                                onSASDisplay = null, // Prove Responder invokes onSASConfirm immediately after M4 without onSASDisplay!
                                onSASConfirm = { sas ->
                                    negSasDeferred.complete(sas)
                                    false // User rejects SAS!
                                },
                            ),
                        )
                        fail("Expected Responder SAS rejection to throw ERR_SAS_MISMATCH")
                    } catch (se: SyncError) {
                        assertEquals(ErrorCode.ERR_SAS_MISMATCH, se.code)
                    }

                    // Responder KeyStore MUST remain completely empty (zero trust hijack!)
                    assertTrue("Responder must NOT save peer DeviceCard when onSASConfirm returns false", bobKs.listDevices().isEmpty())

                    // Initiator must also observe room burn / failure
                    try {
                        withTimeout(10_000L) { negInitiatorJob.await() }
                        fail("Expected Initiator to fail when Responder burned room on SAS rejection")
                    } catch (se: SyncError) {
                        assertTrue(se.code == ErrorCode.ERR_ROOM_BURNED || se.code == ErrorCode.ERR_NOT_FOUND || se.code == ErrorCode.ERR_SAS_MISMATCH)
                    }
                }

                // PART B: Positive Flow 1B SAS Device Bind with `onSASDisplay = null` (ONLY `onSASConfirm` set on Responder)
                // while Initiator blocks in `onSASInput` waiting for Responder's `onSASConfirm` to observe `sas` — proves ZERO deadlock!
                val posRoomDeferred = CompletableDeferred<String>()
                val posSasFromConfirmDeferred = CompletableDeferred<String>()

                val posInitiatorJob = async(Dispatchers.Default) {
                    alice.initiateDeviceBind(
                        PairOptions(
                            mode = Handshake.MODE_COMMIT_SAS,
                            onOfferReady = { info -> posRoomDeferred.complete(info.displayCode) },
                            onSASInput = { withTimeout(10_000L) { posSasFromConfirmDeferred.await() } },
                        )
                    )
                }

                val posCode = withTimeout(10_000L) { posRoomDeferred.await() }
                val aliceCardOnBob = withTimeout(15_000L) {
                    bob.acceptDeviceBind(
                        pairInput = posCode,
                        options = PairOptions(
                            mode = Handshake.MODE_COMMIT_SAS,
                            onSASDisplay = null,
                            onSASConfirm = { sas ->
                                posSasFromConfirmDeferred.complete(sas)
                                sas.length == 6
                            },
                        ),
                    )
                }
                val bobCardOnAlice = withTimeout(15_000L) { posInitiatorJob.await() }

                assertEquals(alice.getIdentity().deviceId, aliceCardOnBob.deviceId)
                assertEquals(bob.getIdentity().deviceId, bobCardOnAlice.deviceId)
                assertTrue(bobCardOnAlice.mailboxId.isNotEmpty())
                assertTrue(bobCardOnAlice.outboundDepositToken.isNotEmpty())

                // Also pair Charlie <-> Bob via QR so we can verify precision single-device revocation
                SyncClient(
                    SyncClientConfig(
                        relay = relayProfile,
                        keyStore = charlieKs,
                        appId = "com.yellowdking.gravityssh",
                        deviceLabel = "Charlie-Tablet",
                        tempDir = File(dir, "charlie-tmp"),
                    )
                ).use { charlie ->
                    val qrOffer = CompletableDeferred<String>()
                    val charliePairJob = async(Dispatchers.Default) {
                        charlie.initiateDeviceBind(
                            PairOptions(
                                mode = Handshake.MODE_QR_OOB,
                                onOfferReady = { qrOffer.complete(it.pairUri) },
                            )
                        )
                    }
                    bob.acceptDeviceBind(withTimeout(10_000L) { qrOffer.await() })
                    val bobOnCharlie = withTimeout(10_000L) { charliePairJob.await() }

                    // PART C: Flow 2 0-RTT Mode B Spool + Foreground `watchInbox` + Two-Phase `listInbox` + `fetchParcel` + `ackItem` Burn!
                    val watchEventDeferred = CompletableDeferred<InboxWatchEvent>()
                    val watchJob = async(Dispatchers.Default) {
                        bob.watchInbox { ev ->
                            watchEventDeferred.complete(ev)
                            throw CancellationException("received expected watch event")
                        }
                    }
                    delay(200L)

                    val blobBytes = ByteArray(150_000) { i -> ((i * 19 + 5) and 0xff).toByte() }
                    val sendRes = alice.sendToPeer(
                        targetDeviceId = bobCardOnAlice.deviceId,
                        parcel = ParcelInput(
                            schema = "gravityssh.vault.v1",
                            inlinePayload = buildJsonObject { put("summary", JsonPrimitive("2-phase-test")) },
                            blobs = listOf(
                                BlobInput.fromBytes(
                                    bytes = blobBytes,
                                    name = "vault_bundle.json.gz",
                                    role = "vault_bundle",
                                    mime = "application/gzip",
                                    encoding = "gzip",
                                )
                            ),
                        ),
                    )
                    assertEquals("spool", sendRes.mode)
                    assertTrue(sendRes.itemId.startsWith("itm_"))

                    val watched = withTimeout(10_000L) { watchEventDeferred.await() }
                    assertEquals(sendRes.itemId, watched.itemId)
                    watchJob.cancelAndJoin()

                    // Phase 1: listInbox (1st call downloads & seals in LocalMetaKey cache; 2nd call hits cache)
                    val inbox1 = bob.listInbox()
                    assertEquals(1, inbox1.size)
                    assertFalse(inbox1[0].cached)
                    assertEquals(sendRes.itemId, inbox1[0].itemId)

                    val inbox2 = bob.listInbox(filterAppId = "com.yellowdking.gravityssh")
                    assertEquals(1, inbox2.size)
                    assertTrue(inbox2[0].cached)

                    // Verify appId pre-filter rejects mismatched appId BEFORE downloading blobs
                    try {
                        bob.fetchParcel(itemId = sendRes.itemId, appId = "com.other.app", autoAck = false)
                        fail("Expected mismatched appId to fail in fetchParcel")
                    } catch (se: SyncError) {
                        assertEquals(ErrorCode.ERR_MANIFEST_INVALID, se.code)
                    }

                    // Phase 2: fetchParcel (autoAck = false) -> inspect/verify -> ackItem physical burn
                    val fetched = bob.fetchParcel(
                        itemId = sendRes.itemId,
                        appId = "com.yellowdking.gravityssh",
                        autoAck = false,
                    )
                    assertEquals(sendRes.msgId, fetched.manifest.msgId)
                    assertEquals(1, fetched.blobs.size)
                    assertArrayEquals(blobBytes, fetched.blobs[0].readBytesVerified())

                    // Item is still on relay until ackItem is called
                    assertEquals(1, bob.listInbox().size)

                    // Explicitly burn via signed `/ack`
                    bob.ackItem(sendRes.itemId)
                    // Idempotent retry against already-burned item must succeed cleanly
                    bob.ackItem(sendRes.itemId)

                    // Confirm physical burn on relay
                    assertTrue(bob.listInbox().isEmpty())
                    try {
                        bob.fetchParcel(itemId = sendRes.itemId, autoAck = false)
                        fail("Expected burned item to return ERR_NOT_FOUND")
                    } catch (se: SyncError) {
                        assertEquals(ErrorCode.ERR_NOT_FOUND, se.code)
                    }

                    // PART D: Two-Phase Precision Single-Device Revocation (`revokeDevice`)
                    bob.revokeDevice(aliceCardOnBob.deviceId)
                    try {
                        alice.sendToPeer(bobCardOnAlice.deviceId, ParcelInput.text("com.yellowdking.gravityssh", "revoked-push"))
                        fail("Expected revoked Alice deposit token to fail with ERR_UNAUTHORIZED_TOKEN")
                    } catch (se: SyncError) {
                        assertEquals(ErrorCode.ERR_UNAUTHORIZED_TOKEN, se.code)
                    }

                    // Charlie's independent deposit token MUST remain 100% functional!
                    val charlieSend = charlie.sendToPeer(
                        bobOnCharlie.deviceId,
                        ParcelInput.text("com.yellowdking.gravityssh", "charlie-still-trusted"),
                    )
                    assertEquals("spool", charlieSend.mode)
                    assertEquals(1, bob.listInbox().size)
                    // Second listInbox populates cached=true for charlieSend.itemId
                    assertTrue(bob.listInbox()[0].cached)

                    // PART E: Offline 2-Phase Revoke -> `syncMailbox()` Retry + Revoked-Sender Cache Eviction (`ST-P1-8` & `ST-P0-3`)
                    val charlieId = charlie.getIdentity().deviceId
                    val deadPort = findFreePort()
                    val offlineProfile = relayProfile.copy(
                        endpoint = "https://127.0.0.1:$deadPort",
                    )
                    SyncClient(
                        SyncClientConfig(
                            relay = offlineProfile,
                            keyStore = bobKs, // Shares KeyStore + masterSeed + relayId override check? Wait: keep same relayId on card!
                            appId = "com.yellowdking.gravityssh",
                            deviceLabel = "Bob-Phone-Offline",
                            tempDir = File(dir, "bob-offline-tmp"),
                        )
                    ).use { offlineBob ->
                        try {
                            offlineBob.revokeDevice(charlieId)
                            fail("Expected offline revokeDevice to fail on unreachable endpoint after saving local tombstone")
                        } catch (se: SyncError) {
                            assertEquals(ErrorCode.ERR_RELAY_UNREACHABLE, se.code)
                        }
                    }

                    // Phase 1 must already have persisted revoked=true & pendingTokenDelete=true locally!
                    assertTrue("Active listDevices() must exclude offline-revoked peer", bobKs.listDevices().none { it.deviceId == charlieId })
                    val tombstone = bobKs.getDevice(charlieId)
                    assertNotNull("Tombstone must remain in KeyStore until online token deletion succeeds", tombstone)
                    assertTrue(tombstone!!.revoked)
                    assertTrue(tombstone.pendingTokenDelete)
                    assertTrue(bobKs.listPendingTokenDeletes().isNotEmpty())

                    // listInbox MUST immediately hide Charlie's previously cached item AND evict its cached manifest (`ST-P0-3`)!
                    assertTrue("listInbox must exclude items from newly revoked sender", bob.listInbox().isEmpty())
                    assertNull("Revoked sender cached manifest must be evicted on listInbox failure", bobKs.getCachedManifest(charlieSend.itemId))

                    // Now bring Bob online via `syncMailbox()` — must retry DELETE /deposit-tokens/{id} and clean up tombstone!
                    assertTrue(bob.syncMailbox())
                    assertNull("Tombstone must be deleted once syncMailbox() completes token deletion", bobKs.getDevice(charlieId))
                    assertTrue("Pending token delete queue must be empty after syncMailbox()", bobKs.listPendingTokenDeletes().isEmpty())

                    // Verify Charlie's deposit token is now physically deleted on the relay (`401 ERR_UNAUTHORIZED_TOKEN`)
                    try {
                        charlie.sendToPeer(bobOnCharlie.deviceId, ParcelInput.text("com.yellowdking.gravityssh", "after-offline-revoke-sync"))
                        fail("Expected Charlie's deposit token to be deleted on relay after Bob's syncMailbox() retry")
                    } catch (se: SyncError) {
                        assertEquals(ErrorCode.ERR_UNAUTHORIZED_TOKEN, se.code)
                    }
                }
            }
        }
        Unit
    }

    @Test
    fun testFlow1BSasOneShotFailClosedAndZeroDeadlockPipeAck(): Unit = runBlocking {
        val dir = workDir!!
        SyncClient(relayUri = relayUri, appId = "com.yellowdking.gravityssh", deviceLabel = "Sender-SAS-OneShot", tempDir = File(dir, "s-tmp")).use { sender ->
            SyncClient(relayUri = relayUri, appId = "com.yellowdking.gravityssh", deviceLabel = "Receiver-SAS-OneShot", tempDir = File(dir, "r-tmp")).use { receiver ->
                // 1. Upfront null gate in `receiveOneShot` (`mode=2`, `onSASConfirm = null`) MUST fail closed before M2!
                supervisorScope {
                    val codeDef = CompletableDeferred<String>()
                    val sendJob = async(Dispatchers.Default) {
                        sender.startOneShotSend(
                            parcel = ParcelInput.text("com.yellowdking.gravityssh", "should-never-send"),
                            options = PairOptions(
                                mode = Handshake.MODE_COMMIT_SAS,
                                onOfferReady = { codeDef.complete(it.displayCode) },
                                onSASInput = { "000000" },
                            ),
                        )
                    }
                    val code = withTimeout(10_000L) { codeDef.await() }
                    try {
                        receiver.receiveOneShot(
                            pairInput = code,
                            options = ReceiveOptions(onSASDisplay = null, onSASConfirm = null),
                        )
                        fail("Expected receiveOneShot in mode=2 with onSASConfirm=null to fail closed")
                    } catch (se: SyncError) {
                        assertEquals(ErrorCode.ERR_SAS_MISMATCH, se.code)
                    }
                    try {
                        withTimeout(10_000L) { sendJob.await() }
                        fail("Expected startOneShotSend to observe room burn")
                    } catch (se: SyncError) {
                        assertTrue(se.code == ErrorCode.ERR_ROOM_BURNED || se.code == ErrorCode.ERR_NOT_FOUND)
                    }
                }

                // 2. Positive `mode=2` One-Shot with ONLY `onSASConfirm` (`onSASDisplay = null`) — zero deadlock & zero `pipe_ack` wipe race!
                val codeDef = CompletableDeferred<String>()
                val sasFromConfirm = CompletableDeferred<String>()
                val sendJob = async(Dispatchers.Default) {
                    sender.startOneShotSend(
                        parcel = ParcelInput.text("com.yellowdking.gravityssh", "sas-oneshot-payload"),
                        options = PairOptions(
                            mode = Handshake.MODE_COMMIT_SAS,
                            onOfferReady = { codeDef.complete(it.displayCode) },
                            onSASInput = { withTimeout(10_000L) { sasFromConfirm.await() } },
                        ),
                    )
                }
                val code = withTimeout(10_000L) { codeDef.await() }
                val received = withTimeout(15_000L) {
                    receiver.receiveOneShot(
                        pairInput = code,
                        options = ReceiveOptions(
                            onSASDisplay = null,
                            onSASConfirm = { sas ->
                                sasFromConfirm.complete(sas)
                                sas.length == 6
                            },
                        ),
                    )
                }
                val sendRes = withTimeout(15_000L) { sendJob.await() }
                assertEquals("pipe", sendRes.mode)
                assertEquals(sendRes.msgId, received.manifest.msgId)
            }
        }
        Unit
    }
}
