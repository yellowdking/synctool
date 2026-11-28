// Cross-language real-process End-to-End Integration Suite:
// Go CLI (`cmd/synctool`) <-> Real `synctool-relay` process <-> Node.js WebCrypto SDK (`sdk/ts`)
//
// Usage:
//   node ./e2e/cross_lang.mjs
// Optional env:
//   SYNCTOOL_GO_BIN=/path/to/go   (defaults to "go" on PATH)

import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

import {
  ErrorCode,
  MemoryKeyStore,
  SyncClient,
  SyncError,
  blobFromBytes,
  bytesToHex,
  randomBytes,
  signRelayRequest,
} from '../sdk/ts/src/index.js';
import {
  buildBinaries,
  log,
  makeTempDir,
  runCLI,
  runProfileSpoolOffAndProxyScenarios,
  sha256Hex,
  spawnCLIInteractive,
  startRelayProcess,
} from './cross_lang_helpers.mjs';
import { runHardeningAndSelfHealingScenarios } from './cross_lang_hardening.mjs';

async function main() {
  const workDir = makeTempDir('synctool-cross-e2e-');
  const activeRelays = [];
  try {
    const { relayBin, cliBin } = buildBinaries(workDir);

    // =========================================================================
    // SCENARIO 1: Real TLS 1.3 + SPKI Pinning Relay (standard + disk: 1,048,832 B chunks)
    // =========================================================================
    log('1. Starting real synctool-relay (tls=selfsigned, profile=standard, spool=disk)...');
    const relayTLS = await startRelayProcess(relayBin, {
      tlsMode: 'selfsigned',
      profile: 'standard',
      spool: 'disk',
    });
    activeRelays.push(relayTLS);

    // Init Go CLI Device A via --stdin (never passing #k= on command line!)
    const goConfigA = path.join(workDir, 'go-alice-cfg');
    const initA = await runCLI(cliBin, goConfigA, ['init', '--stdin', '--label', 'Go-Alice'], `${relayTLS.relayURI}\n`);
    assert.equal(initA.code, 0, `Go CLI init failed: ${JSON.stringify(initA)}`);
    const goAliceDeviceId = initA.result.device_id;
    const goAliceMailboxId = initA.result.mailbox_id;
    log(`   Go-Alice initialized: device_id=${goAliceDeviceId}`);

    // Init TS SDK Device B (pinned TLS 1.3!)
    const tsB = new SyncClient({
      relay: relayTLS.relayURI,
      keyStore: new MemoryKeyStore(),
      appId: 'com.yellowdking.notes',
      label: 'TS-Bob',
    });
    await tsB.registerMailbox();
    const tsBId = await tsB.getIdentity();
    const tsBMb = await tsB.getMailboxIdentity();
    log(`   TS-Bob initialized:   device_id=${tsBId.deviceId}`);

    // Verify negative TLS Pin mismatch & wrong AccessKey silent 404 on TS SDK
    const badPinClient = new SyncClient({
      relay: {
        origin: relayTLS.parsed.origin,
        tlsMode: 'spki_pin',
        spkiPin: '0'.repeat(64),
        accessKey: relayTLS.parsed.accessKey,
      },
    });
    await assert.rejects(() => badPinClient.ping(), (err) => err instanceof SyncError && err.code === ErrorCode.ERR_TLS_PIN_MISMATCH);

    const badKeyClient = new SyncClient({
      relay: {
        origin: relayTLS.parsed.origin,
        tlsMode: 'spki_pin',
        spkiPin: relayTLS.parsed.spkiPin,
        accessKey: 'wrong-key-0123456789abcdefghijklmnopqrstuvwxyz',
      },
    });
    await assert.rejects(() => badKeyClient.ping(), (err) => err instanceof SyncError && err.code === ErrorCode.ERR_AUTH_FAILED);
    log('   Verified SPKI Pin mismatch rejection & wrong AccessKey silent 404.');

    // Verify 409 ERR_CLOCK_SKEW auto-calibration & retry on TS SDK
    const skewedTS = new SyncClient({
      relay: relayTLS.relayURI,
      clockOffsetSec: -300,
    });
    const skewPing = await skewedTS.ping();
    assert.equal(skewPing.proto_v, 1);
    assert.ok(Math.abs(skewPing.clock_offset_sec) <= 5, `expected calibrated clock offset near 0, got ${skewPing.clock_offset_sec}`);
    log('   Verified 409 ERR_CLOCK_SKEW auto-calibration & retry.');

    // Verify duplicate HTTP X-Sync-Nonce -> 401 ERR_REPLAY_DETECTED
    const fixedTs = Math.floor(Date.now() / 1000);
    const fixedNonce = bytesToHex(randomBytes(16));
    const { sigHex } = await signRelayRequest({
      accessKey: relayTLS.parsed.accessKey,
      method: 'GET',
      pathAndRawQuery: '/v1/ping',
      ts: fixedTs,
      nonce: fixedNonce,
    });
    const replayHeaders = {
      'X-Sync-TS': String(fixedTs),
      'X-Sync-Nonce': fixedNonce,
      'X-Sync-Sig': sigHex,
      'X-Sync-Client': 'synctool-e2e/1.0',
    };
    const r1 = await tsB._rawTransport(`${relayTLS.parsed.origin}/v1/ping`, { method: 'GET', headers: replayHeaders });
    assert.equal(r1.status, 200);
    await r1.text();
    const r2 = await tsB._rawTransport(`${relayTLS.parsed.origin}/v1/ping`, { method: 'GET', headers: replayHeaders });
    assert.equal(r2.status, 401);
    const r2Json = await r2.json();
    assert.equal(r2Json.error, ErrorCode.ERR_REPLAY_DETECTED);
    log('   Verified duplicate HTTP nonce -> 401 ERR_REPLAY_DETECTED.');

    // =========================================================================
    // SCENARIO 2: Flow 1A (QR OOB) Cross-Language One-Shot (Both Directions, Multi-Chunk >3 chunks)
    // =========================================================================
    log('2. Testing Flow 1A (QR OOB) One-Shot: Go CLI -> TS SDK & TS SDK -> Go CLI (3.2 MiB = 4 chunks on standard)...');
    const payload900K = crypto.randomBytes(3300 * 1024 + 137);
    const payload900KPath = path.join(workDir, 'multi_chunk_3m.bin');
    fs.writeFileSync(payload900KPath, payload900K);
    const payload900KSha = sha256Hex(payload900K);

    // 2A: Go CLI send --oneshot --mode qr -> TS receiveOneShot
    const goSendQR = spawnCLIInteractive(cliBin, goConfigA, [
      '--app', 'com.yellowdking.gravityssh',
      'send', '--oneshot', '--mode', 'qr',
      '--schema', 'vault.snapshot.v1',
      '--text', 'GravitySSH-Go-To-TS',
      '--file', `${payload900KPath}:vault_dump`,
    ]);
    const offerEvQR = await goSendQR.waitForEvent((e) => e.type === 'event' && e.event === 'offer_ready');
    let tsGotQRBytes = null;
    let tsGotQRManifest = null;
    await tsB.receiveOneShot(offerEvQR.pair_uri, async ({ manifest, blobs }) => {
      tsGotQRManifest = manifest;
      tsGotQRBytes = blobs[0].bytes;
    });
    const goSendQRRes = await goSendQR.done;
    assert.equal(goSendQRRes.code, 0, `Go oneshot QR send failed: ${JSON.stringify(goSendQRRes)}`);
    assert.equal(tsGotQRManifest.inline_payload.text, 'GravitySSH-Go-To-TS');
    assert.equal(sha256Hex(tsGotQRBytes), payload900KSha);

    // 2B: TS startOneShotSend (mode=1) -> Go CLI recv
    let tsOfferQR = null;
    const goOutQR = path.join(workDir, 'out-qr-from-ts');
    let goRecvPromise = null;
    const tsSendQRRes = await tsB.startOneShotSend(
      {
        appId: 'com.yellowdking.notes',
        schema: 'note.oneshot.v1',
        inlinePayload: { text: 'TS-To-Go-QR-OneShot' },
        blobs: [blobFromBytes(payload900K, { role: 'video', name: 'demo.mp4', mime: 'video/mp4' })],
      },
      {
        mode: 1,
        onOfferReady: (offer) => {
          tsOfferQR = offer;
          goRecvPromise = runCLI(cliBin, goConfigA, ['recv', '--stdin', '--out', goOutQR], `${offer.pairUri}\n`);
        },
      },
    );
    const goRecvQRRes = await goRecvPromise;
    assert.equal(goRecvQRRes.code, 0, `Go recv QR failed: ${JSON.stringify(goRecvQRRes)}`);
    assert.equal(goRecvQRRes.result.manifest.msg_id, tsSendQRRes.msgId);
    assert.equal(goRecvQRRes.result.manifest.inline_payload.text, 'TS-To-Go-QR-OneShot');
    assert.equal(sha256Hex(fs.readFileSync(goRecvQRRes.result.files[0])), payload900KSha);
    log('   Flow 1A (QR OOB) Go <-> TS multi-chunk one-shot passed both directions!');

    // =========================================================================
    // SCENARIO 3: Flow 1B (Commit-Reveal X25519 + 6-digit SAS) Cross-Language Bind & One-Shot
    // =========================================================================
    log('3. Testing Flow 1B (Commit-Reveal + 6-digit SAS): Go CLI <-> TS SDK Device Bind & One-Shot...');
    // 3A: Go CLI pair offer --mode sas <-> TS acceptDeviceBind
    log('   3A: Go CLI pair offer --mode sas <-> TS acceptDeviceBind...');
    const goPairSAS = spawnCLIInteractive(cliBin, goConfigA, ['pair', 'offer', '--mode', 'sas', '--label', 'Go-Alice']);
    const pairOfferEv = await goPairSAS.waitForEvent((e) => e.type === 'event' && e.event === 'offer_ready');
    log(`   3A: offer_ready room=${pairOfferEv.room_id} display=${pairOfferEv.display_code}`);
    const tsCardOfGo = await tsB.acceptDeviceBind(pairOfferEv.display_code, {
      label: 'TS-Bob',
      timeoutMs: 15_000,
      onSASDisplay: ({ sas }) => {
        log(`   3A: TS displayed SAS=${sas}, writing to Go CLI stdin...`);
        goPairSAS.writeLine(sas);
        goPairSAS.endInput();
      },
      onSASConfirm: async () => true,
    });
    log('   3A: TS acceptDeviceBind returned! Waiting for Go CLI...');
    const goPairSASRes = await goPairSAS.done;
    assert.equal(goPairSASRes.code, 0, `Go SAS pair offer failed: ${JSON.stringify(goPairSASRes)}`);
    assert.equal(goPairSASRes.result.device_id, tsBId.deviceId);
    assert.equal(tsCardOfGo.device_id, goAliceDeviceId);

    // 3B: TS startOneShotSend (mode=2 SAS) <-> Go CLI recv (read sas_ready event into TS onSASInput + confirm Go Responder SAS!)
    log('   3B: TS startOneShotSend (mode=2 SAS) <-> Go CLI recv...');
    const goOutSAS = path.join(workDir, 'out-sas-from-ts');
    let goRecvSASProc = null;
    await tsB.startOneShotSend(
      {
        schema: 'clip.sas.v1',
        inlinePayload: { msg: 'TS-To-Go-SAS-Verified' },
      },
      {
        mode: 2,
        timeoutMs: 15_000,
        onOfferReady: (offer) => {
          log(`   3B: TS offer ready room=${offer.formattedRoomId}, spawning Go CLI recv...`);
          goRecvSASProc = spawnCLIInteractive(cliBin, goConfigA, ['recv', '--out', goOutSAS, offer.formattedRoomId]);
        },
        onSASInput: async () => {
          log('   3B: TS waiting for Go CLI sas_ready event...');
          const sasEv = await goRecvSASProc.waitForEvent((e) => e.type === 'event' && e.event === 'sas_ready');
          log(`   3B: Go CLI displayed SAS=${sasEv.sas}, confirming Go Responder & feeding to TS...`);
          goRecvSASProc.writeLine('y');
          goRecvSASProc.endInput();
          return sasEv.sas;
        },
      },
    );
    const goRecvSASDone = await goRecvSASProc.done;
    assert.equal(goRecvSASDone.code, 0, `Go SAS recv failed: ${JSON.stringify(goRecvSASDone)}`);
    assert.equal(goRecvSASDone.result.manifest.inline_payload.msg, 'TS-To-Go-SAS-Verified');
    log('   Flow 1B (Commit-Reveal + 6-digit SAS) passed for both Device Bind and One-Shot!');

    // =========================================================================
    // SCENARIO 4: Flow 2 (0-RTT Sealed Sender) Mode B Multi-Chunk Spool, Two-Phase Preview,
    //             Checkpoint Resume, Physical Burn & Bidirectional Go <-> TS
    // =========================================================================
    log('4. Testing Flow 2 (0-RTT) Mode B multi-chunk spool: Go -> TS (with resume + burn) & TS -> Go...');

    // 4A: Go CLI send --to TS-Bob
    const goSendSpool = await runCLI(cliBin, goConfigA, [
      '--app', 'com.yellowdking.notes',
      'send', '--to', tsBId.deviceId,
      '--schema', 'note.item.v1',
      '--text', '手机发给电脑的多媒体笔记',
      '--file', `${payload900KPath}:video`,
    ]);
    assert.equal(goSendSpool.code, 0, `Go Mode B send failed: ${JSON.stringify(goSendSpool)}`);
    const itemIdGoToTs = goSendSpool.result.item_id;
    assert.ok(itemIdGoToTs && itemIdGoToTs.startsWith('itm_'));

    const itemDiskPath1 = path.join(relayTLS.dataDir, 'spool', tsBMb.mailboxId.slice(0, 2), tsBMb.mailboxId, itemIdGoToTs);
    assert.ok(fs.existsSync(path.join(itemDiskPath1, 'item.json')), 'expected spooled item on relay disk');

    // TS Phase 1 two-phase listInbox (run 2x to verify preview cache)
    const list1 = await tsB.listInbox({ appId: 'com.yellowdking.notes' });
    assert.equal(list1.length, 1);
    assert.equal(list1[0].item_id, itemIdGoToTs);
    assert.equal(list1[0].manifest.inline_payload.text, '手机发给电脑的多媒体笔记');
    const list2 = await tsB.listInbox({ appId: 'com.yellowdking.notes' });
    assert.equal(list2.length, 1);

    // TS Phase 2 with simulated disconnect after chunk 1 + resume from checkpoint!
    const prefixPieces = [];
    const checkpoints = new Map();
    const abortCtrl = new AbortController();
    let seenChunks = 0;
    await assert.rejects(
      () => tsB.fetchParcel(
        itemIdGoToTs,
        async () => { throw new Error('must not deliver partial parcel'); },
        {
          signal: abortCtrl.signal,
          createBlobSink: () => ({
            write(pt) { prefixPieces.push(new Uint8Array(pt)); },
            finish() { return null; },
          }),
          onChunkCheckpoint(partId, nextTxIdx) {
            checkpoints.set(partId, nextTxIdx);
            seenChunks++;
            if (seenChunks === 2) abortCtrl.abort();
          },
        },
      ),
      (err) => err instanceof SyncError && err.code === ErrorCode.ERR_CANCELLED,
    );
    assert.equal(checkpoints.get(1), 2, 'expected checkpoint saved at tx_idx=2');

    // Resume TS fetchParcel from checkpoint tx_idx=2!
    const prefixBuf = Buffer.concat(prefixPieces);
    const resumePrefixes = new Map([[1, new Uint8Array(prefixBuf.buffer, prefixBuf.byteOffset, prefixBuf.byteLength)]]);
    let tsFinalBytes = null;
    await tsB.fetchParcel(
      itemIdGoToTs,
      async ({ blobs }) => {
        tsFinalBytes = blobs[0].bytes;
      },
      {
        resumeCheckpoints: checkpoints,
        resumePrefixes,
      },
    );
    assert.equal(sha256Hex(tsFinalBytes), payload900KSha, 'resumed TS blob SHA-256 mismatch');
    assert.ok(!fs.existsSync(itemDiskPath1), 'expected relay disk directory physically deleted after signed ACK');

    // 4B: TS SDK sendToDevice -> Go CLI inbox list -> Go CLI inbox pull + physical burn
    const tsSendSpool = await tsB.sendToDevice(goAliceDeviceId, {
      appId: 'com.yellowdking.notes',
      schema: 'note.item.v1',
      inlinePayload: { title: 'TS发给Go的笔记', count: 42 },
      blobs: [blobFromBytes(payload900K, { role: 'image', name: 'photo.jpg', mime: 'image/jpeg' })],
    });
    assert.equal(tsSendSpool.mode, 'spool');
    const itemDiskPath2 = path.join(relayTLS.dataDir, 'spool', goAliceMailboxId.slice(0, 2), goAliceMailboxId, tsSendSpool.itemId);
    assert.ok(fs.existsSync(path.join(itemDiskPath2, 'item.json')));

    const goList = await runCLI(cliBin, goConfigA, ['inbox', 'list', '--app', 'com.yellowdking.notes']);
    assert.equal(goList.code, 0);
    assert.equal(goList.result.length, 1);
    assert.equal(goList.result[0].item_id, tsSendSpool.itemId);

    const goPullDir = path.join(workDir, 'go-pull-from-ts');
    const goPull = await runCLI(cliBin, goConfigA, ['inbox', 'pull', '--item', tsSendSpool.itemId, '--out', goPullDir]);
    assert.equal(goPull.code, 0, `Go inbox pull failed: ${JSON.stringify(goPull)}`);
    assert.equal(goPull.result[0].manifest.inline_payload.title, 'TS发给Go的笔记');
    assert.equal(sha256Hex(fs.readFileSync(goPull.result[0].files[0])), payload900KSha);
    assert.ok(!fs.existsSync(itemDiskPath2), 'expected relay disk item physically burned after Go signed ACK');
    log('   Flow 2 Mode B multi-chunk spool, two-phase preview, resume & physical burn passed both directions!');

    // =========================================================================
    // SCENARIO 5: Precision Single-Device Revocation (Bind C, Revoke B, Verify C Unaffected)
    // =========================================================================
    log('5. Testing cross-language single-device precision revocation...');
    const tsC = new SyncClient({
      relay: relayTLS.relayURI,
      keyStore: new MemoryKeyStore(),
      appId: 'com.yellowdking.notes',
      label: 'TS-Carol',
    });
    await tsC.registerMailbox();

    // Pair Go-Alice <-> TS-Carol via QR OOB
    const goPairC = spawnCLIInteractive(cliBin, goConfigA, ['pair', 'offer', '--mode', 'qr', '--label', 'Go-Alice']);
    const offerC = await goPairC.waitForEvent((e) => e.type === 'event' && e.event === 'offer_ready');
    await tsC.acceptDeviceBind(offerC.pair_uri, { label: 'TS-Carol' });
    const goPairCRes = await goPairC.done;
    assert.equal(goPairCRes.code, 0);

    // Go-Alice revokes ONLY TS-Bob
    const revRes = await runCLI(cliBin, goConfigA, ['device', 'revoke', tsBId.deviceId]);
    assert.equal(revRes.code, 0, `Go device revoke failed: ${JSON.stringify(revRes)}`);

    // TS-Bob is now rejected with 401 ERR_UNAUTHORIZED_TOKEN
    await assert.rejects(
      () => tsB.sendToDevice(goAliceDeviceId, { schema: 'note.v1', inlinePayload: { text: 'revoked' } }),
      (err) => err instanceof SyncError && err.code === ErrorCode.ERR_UNAUTHORIZED_TOKEN,
    );

    // TS-Carol STILL sends cleanly and Go-Alice pulls it!
    const carolSend = await tsC.sendToDevice(goAliceDeviceId, {
      appId: 'com.yellowdking.notes',
      schema: 'note.v1',
      inlinePayload: { text: 'carol-still-works' },
    });
    const goPullCarol = await runCLI(cliBin, goConfigA, ['inbox', 'pull', '--item', carolSend.itemId, '--out', path.join(workDir, 'carol-out')]);
    assert.equal(goPullCarol.code, 0);
    assert.equal(goPullCarol.result[0].manifest.inline_payload.text, 'carol-still-works');
    log('   Precision single-device revocation passed!');

    // Scenarios 5B, 6, 7: --profile=nano quotas, --spool=off + Mode A direct, and reverse proxy tls=off
    await runProfileSpoolOffAndProxyScenarios({
      relayBin,
      cliBin,
      workDir,
      activeRelays,
      payloadBytes: payload900K,
      payloadPath: payload900KPath,
      payloadSha: payload900KSha,
    });

    // Scenarios 8, 9, 10: nano memory-spool reboot self-healing, security hardening & examples verification
    await runHardeningAndSelfHealingScenarios({
      relayBin,
      cliBin,
      workDir,
    });

    log('ALL CROSS-LANGUAGE E2E SCENARIOS PASSED 100%!');
  } finally {
    for (const r of activeRelays) {
      await r.stop().catch(() => {});
    }
    fs.rmSync(workDir, { recursive: true, force: true });
  }
}

main().catch((err) => {
  console.error('[cross-lang-e2e] FAILED:', err);
  process.exit(1);
});
