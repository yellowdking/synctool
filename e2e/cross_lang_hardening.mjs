// Phase 2 Cross-Language Security Hardening, Self-Healing, Subprocess & Examples E2E Scenarios.

import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  ErrorCode,
  NodeFileKeyStore,
  SyncClient,
  SyncError,
  blobFromBytes,
  isRetryable,
  isVersionMismatch,
  parseRelayURI,
} from '../sdk/ts/src/index.js';
import { invokeSynctoolJSON } from '../examples/cli-subprocess/sync_helper.mjs';
import {
  getFreePort,
  log,
  makeTempDir,
  runCLI,
  spawnCLIInteractive,
} from './cross_lang_helpers.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const REPO_ROOT = path.resolve(__dirname, '..');
const GO_BIN = process.env.SYNCTOOL_GO_BIN || 'go';

async function spawnRelayOnPort(relayBin, { port, dataDir, profile = 'nano', spool = 'memory', tlsMode = 'selfsigned' }) {
  const listenAddr = `127.0.0.1:${port}`;
  const certFile = path.join(dataDir, 'cert.pem');
  let relayURI = null;
  if (!fs.existsSync(certFile)) {
    const initOut = execFileSync(
      relayBin,
      ['init', '--public-host', '127.0.0.1', '--listen', listenAddr, '--profile', profile, '--spool', spool, '--tls', tlsMode, '--data-dir', dataDir],
      { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] },
    );
    const match = initOut.match(/synctool:\/\/relay\?[^\s]+/);
    assert.ok(match, `missing synctool://relay URI in init output: ${initOut}`);
    relayURI = match[0].trim();
  }

  const child = spawn(
    relayBin,
    ['serve', '--public-host', '127.0.0.1', '--listen', listenAddr, '--profile', profile, '--spool', spool, '--tls', tlsMode, '--data-dir', dataDir],
    { stdio: ['ignore', 'pipe', 'pipe'] },
  );
  let stderrBuf = '';
  child.stderr.on('data', (d) => { stderrBuf += d.toString(); });

  return {
    relayURI,
    child,
    async waitReady(uri) {
      const probe = new SyncClient({ relay: uri, label: 'probe' });
      const deadline = Date.now() + 10_000;
      while (Date.now() < deadline) {
        if (child.exitCode !== null) {
          throw new Error(`synctool-relay exited early (${child.exitCode}): ${stderrBuf}`);
        }
        try {
          await probe.ping();
          return;
        } catch {
          await new Promise((r) => setTimeout(r, 80));
        }
      }
      child.kill('SIGTERM');
      throw new Error(`synctool-relay not ready in time: ${stderrBuf}`);
    },
    stopKeepData() {
      return new Promise((resolve) => {
        if (child.exitCode !== null || child.signalCode !== null) {
          resolve();
          return;
        }
        child.once('exit', () => resolve());
        child.kill('SIGTERM');
        setTimeout(() => {
          if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
        }, 2000).unref();
      });
    },
  };
}

export async function runHardeningAndSelfHealingScenarios({ relayBin, cliBin, workDir }) {
  // =========================================================================
  // SCENARIO 8: Real-Process nano (spool=memory) Reboot Self-Healing (Go CLI <-> TS NodeFileKeyStore)
  // =========================================================================
  log('8. Testing real-process nano (spool=memory) reboot self-healing + NodeFileKeyStore + SYNCTOOL_RELAY env...');
  const healPort = await getFreePort();
  const healRelayDir = makeTempDir('synctool-heal-relay-');
  let inst1 = null;
  let inst2 = null;
  let inst3 = null;
  try {
    inst1 = await spawnRelayOnPort(relayBin, { port: healPort, dataDir: healRelayDir, profile: 'nano', spool: 'memory' });
    const healURI = inst1.relayURI;
    await inst1.waitReady(healURI);

    const goHealCfg = path.join(workDir, 'go-heal-cfg');
    const tsHealCfg = path.join(workDir, 'ts-heal-cfg');

    // Init Go CLI using --relay-stdin
    const initGo = await runCLI(cliBin, goHealCfg, ['init', '--relay-stdin', '--label', 'Go-Heal-Alice'], `${healURI}\n`);
    assert.equal(initGo.code, 0, `Go init --relay-stdin failed: ${JSON.stringify(initGo)}`);

    // Init TS Client via SyncClient.fromEnv + NodeFileKeyStore (0600 atomic persistence)
    const prevRelayEnv = process.env.SYNCTOOL_RELAY;
    const prevCfgEnv = process.env.SYNCTOOL_CONFIG;
    process.env.SYNCTOOL_RELAY = healURI;
    process.env.SYNCTOOL_CONFIG = tsHealCfg;
    let tsHealBob;
    try {
      tsHealBob = SyncClient.fromEnv({ appId: 'com.yellowdking.notes', label: 'TS-Heal-Bob' });
    } finally {
      if (prevRelayEnv === undefined) delete process.env.SYNCTOOL_RELAY; else process.env.SYNCTOOL_RELAY = prevRelayEnv;
      if (prevCfgEnv === undefined) delete process.env.SYNCTOOL_CONFIG; else process.env.SYNCTOOL_CONFIG = prevCfgEnv;
    }
    assert.ok(tsHealBob.keyStore instanceof NodeFileKeyStore, 'expected SyncClient.fromEnv to use NodeFileKeyStore');

    // Pair Go-Heal-Alice <-> TS-Heal-Bob
    const pairProc = spawnCLIInteractive(cliBin, goHealCfg, ['pair', 'offer', '--mode', 'qr', '--label', 'Go-Heal-Alice']);
    const pairOffer = await pairProc.waitForEvent((e) => e.type === 'event' && e.event === 'offer_ready');
    const tsCardOfAlice = await tsHealBob.acceptDeviceBind(pairOffer.pair_uri, { label: 'TS-Heal-Bob' });
    const goPairDone = await pairProc.done;
    assert.equal(goPairDone.code, 0);
    assert.equal(typeof tsCardOfAlice.inbound_token_hash, 'string');
    assert.equal(tsCardOfAlice.inbound_token_hash.length, 64);

    // Reboot #1: Kill synctool-relay process (wiping 100% of memory mailboxes) and restart on same port!
    await inst1.stopKeepData();
    inst2 = await spawnRelayOnPort(relayBin, { port: healPort, dataDir: healRelayDir, profile: 'nano', spool: 'memory' });
    await inst2.waitReady(healURI);

    // Re-open fresh SyncClient from disk NodeFileKeyStore -> listInbox() auto-heals TS mailbox + deposit_token!
    const tsHealBobReopened = new SyncClient({
      relay: parseRelayURI(healURI),
      keyStore: new NodeFileKeyStore(tsHealCfg),
      appId: 'com.yellowdking.notes',
      label: 'TS-Heal-Bob',
    });
    const emptyAfterHeal = await tsHealBobReopened.listInbox();
    assert.equal(emptyAfterHeal.length, 0);

    // Go-Heal-Alice can immediately send to TS-Heal-Bob without re-pairing!
    const goSendAfterHeal = await runCLI(cliBin, goHealCfg, [
      '--app', 'com.yellowdking.notes',
      'send', '--to', 'TS-Heal-Bob',
      '--text', 'Go->TS survived nano RAM wipe!',
    ]);
    assert.equal(goSendAfterHeal.code, 0, `Go send after TS self-heal failed: ${JSON.stringify(goSendAfterHeal)}`);

    const healedItems = await tsHealBobReopened.listInbox({ appId: 'com.yellowdking.notes' });
    assert.equal(healedItems.length, 1);
    let pulledText = null;
    await tsHealBobReopened.fetchParcel(healedItems[0].item_id, async ({ manifest }) => {
      pulledText = manifest.inline_payload.text;
    });
    assert.equal(pulledText, 'Go->TS survived nano RAM wipe!');

    // Reboot #2: Wipe relay RAM again -> Go CLI `inbox list` auto-heals Go's mailbox -> TS `sendText` succeeds!
    await inst2.stopKeepData();
    inst3 = await spawnRelayOnPort(relayBin, { port: healPort, dataDir: healRelayDir, profile: 'nano', spool: 'memory' });
    await inst3.waitReady(healURI);

    const goHealList = await runCLI(cliBin, goHealCfg, ['inbox', 'list']);
    assert.equal(goHealList.code, 0, `Go CLI self-healing inbox list failed: ${JSON.stringify(goHealList)}`);

    const tsTextSent = await tsHealBobReopened.sendText('Go-Heal-Alice', 'TS->Go sendText after 2nd reboot!');
    assert.equal(tsTextSent.mode, 'spool');

    const goPulled = await runCLI(cliBin, goHealCfg, ['inbox', 'pull', '--item', tsTextSent.itemId, '--out', path.join(workDir, 'heal-out')]);
    assert.equal(goPulled.code, 0);
    assert.equal(goPulled.result[0].manifest.inline_payload.text, 'TS->Go sendText after 2nd reboot!');
    log('   Real-process nano memory-spool reboot self-healing passed in both directions (Go <-> TS)!');

    // =========================================================================
    // SCENARIO 9: CLI Security Hardening (watch --auto-pull --app isolation, safe filenames,
    //             overwrite/symlink defense, TS 307 redirect block, and error secret redaction)
    // =========================================================================
    log('9. Testing CLI watch --auto-pull --app isolation, filename/overwrite defense, 307 redirect block & secret redaction...');

    // 9A: Verify `inbox watch --auto-pull --app com.target.notes` NEVER burns parcels belonging to `com.other.vault`!
    const otherSent = await tsHealBobReopened.sendToDevice(initGo.result.device_id, {
      appId: 'com.other.vault',
      schema: 'vault.secret.v1',
      inlinePayload: { secret: 'MUST_NEVER_BE_BURNED_BY_NOTES_WATCHER' },
    });
    const watchOutDir = path.join(workDir, 'watch-app-out');
    const watchProc = spawnCLIInteractive(cliBin, goHealCfg, [
      'inbox', 'watch', '--auto-pull', '--app', 'com.target.notes', '--out', watchOutDir,
    ]);
    // Give SSE watcher 200ms to subscribe, then push matching com.target.notes parcel
    await new Promise((r) => setTimeout(r, 200));
    const targetSent = await tsHealBobReopened.sendToDevice(initGo.result.device_id, {
      appId: 'com.target.notes',
      schema: 'note.item.v1',
      inlinePayload: { text: 'pull-only-this-note' },
    });
    const autoPulledEv = await watchProc.waitForEvent((e) => e.type === 'event' && e.event === 'auto_pulled' && e.item_id === targetSent.itemId, 10_000);
    assert.equal(autoPulledEv.msg_id, targetSent.msgId);
    watchProc.endInput();
    watchProc.child.kill();
    await watchProc.done.catch(() => {});
    log('   9A: watch --auto-pull --app triggered for target app; verifying other app unburned...');

    // Confirm `com.other.vault` parcel is STILL intact and unburned on the relay!
    const otherCheck = await runCLI(cliBin, goHealCfg, ['inbox', 'list', '--app', 'com.other.vault']);
    assert.equal(otherCheck.code, 0);
    assert.equal(otherCheck.result.length, 1, 'P0 regression: inbox watch --auto-pull --app burned another app\'s parcel!');
    assert.equal(otherCheck.result[0].item_id, otherSent.itemId);
    // Cleanly pull `com.other.vault` parcel now
    const pullOther = await runCLI(cliBin, goHealCfg, ['inbox', 'pull', '--item', otherSent.itemId, '--out', watchOutDir]);
    assert.equal(pullOther.code, 0);
    assert.equal(pullOther.result[0].manifest.inline_payload.secret, 'MUST_NEVER_BE_BURNED_BY_NOTES_WATCHER');
    log('   9A: passed!');

    // 9B: Filename sanitization (Windows reserved NUL.txt + BiDi RLO + non-clobbering O_EXCL collision)
    const safeOutDir = path.join(workDir, 'safe-out');
    fs.mkdirSync(safeOutDir, { recursive: true });
    const preExisting = path.join(safeOutDir, 'report.txt');
    fs.writeFileSync(preExisting, 'ORIGINAL_PROTECTED_CONTENT');

    const hostileParcel = await tsHealBobReopened.sendToDevice(initGo.result.device_id, {
      appId: 'com.yellowdking.notes',
      schema: 'files.test.v1',
      blobs: [
        blobFromBytes(Buffer.from('NEW_REPORT_PAYLOAD'), { role: 'doc', name: 'report.txt', mime: 'text/plain' }),
        blobFromBytes(Buffer.from('WINDOWS_RESERVED_PAYLOAD'), { role: 'doc', name: '..\\NUL.txt', mime: 'text/plain' }),
        blobFromBytes(Buffer.from('BIDI_RLO_PAYLOAD'), { role: 'doc', name: 'invoice\u202Etxt.exe', mime: 'application/octet-stream' }),
      ],
    });
    const safePull = await runCLI(cliBin, goHealCfg, ['inbox', 'pull', '--item', hostileParcel.itemId, '--out', safeOutDir]);
    assert.equal(safePull.code, 0, `safePull failed: ${JSON.stringify(safePull)}`);
    assert.equal(fs.readFileSync(preExisting, 'utf8'), 'ORIGINAL_PROTECTED_CONTENT', 'existing report.txt must never be overwritten');
    const savedBasenames = safePull.result[0].files.map((f) => path.basename(f));
    assert.deepEqual(savedBasenames, ['report_1.txt', '_NUL.txt', 'invoicetxt.exe']);
    log('   9B: passed!');

    // 9C: TS SDK unify receiveFromRoom (Mode A Flow 2 direct)
    const directSendProc = spawnCLIInteractive(cliBin, goHealCfg, [
      'send', '--to', 'TS-Heal-Bob', '--mode', 'pipe', '--text', 'Unified-receiveFromRoom-OK',
    ]);
    const directOffer = await directSendProc.waitForEvent((e) => e.type === 'event' && e.event === 'offer_ready', 10_000);
    let gotRoomText = null;
    await tsHealBobReopened.receiveFromRoom(directOffer.pair_uri, async ({ manifest }) => {
      gotRoomText = manifest.inline_payload.text;
    }, { timeoutMs: 10_000 });
    const directSendDone = await directSendProc.done;
    assert.equal(directSendDone.code, 0);
    assert.equal(gotRoomText, 'Unified-receiveFromRoom-OK');
    log('   9C: passed!');

    // 9D: TS SDK HTTP 307 Redirect Block (X-Sync-* headers must never leak to redirect target)
    let canaryCount = 0;
    const canarySrv = http.createServer((_req, res) => { canaryCount++; res.writeHead(200); res.end('leaked'); });
    await new Promise((r) => canarySrv.listen(0, '127.0.0.1', r));
    const canaryPort = canarySrv.address().port;
    const redirSrv = http.createServer((_req, res) => {
      res.writeHead(307, { Location: `http://127.0.0.1:${canaryPort}/steal`, Connection: 'close' });
      res.end();
    });
    await new Promise((r) => redirSrv.listen(0, '127.0.0.1', r));
    const redirPort = redirSrv.address().port;
    try {
      const redirClient = new SyncClient({
        relay: { origin: `http://127.0.0.1:${redirPort}`, accessKey: 'R'.repeat(43) },
      });
      await assert.rejects(
        () => redirClient.ping(),
        (err) => err instanceof SyncError && err.code === ErrorCode.ERR_RELAY_UNREACHABLE && !isRetryable(err),
      );
      assert.equal(canaryCount, 0, 'TS SyncClient followed 307 redirect to canary!');
    } finally {
      redirSrv.closeAllConnections?.();
      canarySrv.closeAllConnections?.();
      redirSrv.close();
      canarySrv.close();
    }
    log('   9D: passed!');

    // 9E: Version mismatch (v=2) -> ERR_UNSUPPORTED_VERSION (exit code 2) & zero #k= secret leakage
    const v2Secret = 'ULTRA_SECRET_FRAGMENT_KEY_98765432109876543210';
    const v2URI = `synctool://relay?v=2&u=https%3A%2F%2F127.0.0.1%3A54843&pin=${'a'.repeat(64)}#k=${v2Secret}`;
    assert.throws(
      () => parseRelayURI(v2URI),
      (err) => isVersionMismatch(err) && !err.message.includes(v2Secret),
    );
    const badInit = await runCLI(cliBin, path.join(workDir, 'bad-v2-cfg'), ['init', '--relay-stdin'], `${v2URI}\n`);
    assert.equal(badInit.code, 2, `expected exit code 2 on v=2 URI, got ${JSON.stringify(badInit)}`);
    assert.equal(badInit.error?.code, ErrorCode.ERR_UNSUPPORTED_VERSION);
    assert.equal(JSON.stringify(badInit).includes(v2Secret), false, 'CLI leaked #k= secret in JSON/stderr output!');
    log('   CLI watch isolation, safe filenames, 307 redirect block, version mismatch & secret redaction passed!');

    // 9F: Flow 1B SAS Responder mandatory onSASConfirm negative gate (rejecting burns room before saving DeviceCard!)
    const tsRejectResp = new SyncClient({
      relay: parseRelayURI(healURI),
      label: 'TS-Reject-Responder',
    });
    const sasNegOfferProc = spawnCLIInteractive(cliBin, goHealCfg, ['pair', 'offer', '--mode', 'sas', '--label', 'Go-Heal-Alice']);
    const sasNegOffer = await sasNegOfferProc.waitForEvent((e) => e.type === 'event' && e.event === 'offer_ready', 10_000);
    await assert.rejects(
      () => tsRejectResp.acceptDeviceBind(sasNegOffer.display_code, {
        timeoutMs: 10_000,
        onSASDisplay: ({ sas }) => {
          sasNegOfferProc.writeLine(sas);
          sasNegOfferProc.endInput();
        },
        onSASConfirm: async () => false,
      }),
      (err) => err instanceof SyncError && err.code === ErrorCode.ERR_SAS_MISMATCH,
    );
    assert.equal((await tsRejectResp.keyStore.listDevices()).length, 0, 'rejected SAS responder must never save peer DeviceCard');
    await sasNegOfferProc.done.catch(() => {});
    await tsRejectResp.close();
    log('   9F: mandatory Responder onSASConfirm negative gate passed!');

    // =========================================================================
    // SCENARIO 10: Runnable `examples/` Verification (Go, TS & Subprocess NDJSON)
    // =========================================================================
    log('10. Verifying runnable examples/ (go-minimal, ts-minimal & cli-subprocess against live relay)...');
    const goExOut = execFileSync(GO_BIN, ['run', './examples/go-minimal', '--self-test'], {
      cwd: REPO_ROOT,
      env: { ...process.env, CGO_ENABLED: '0' },
      encoding: 'utf8',
    });
    assert.ok(goExOut.includes('ok: app=com.example.notes'), `unexpected go-minimal output: ${goExOut}`);

    const tsExOut = execFileSync(process.execPath, ['./examples/ts-minimal/quickstart.mjs', '--self-test'], {
      cwd: REPO_ROOT,
      encoding: 'utf8',
    });
    assert.ok(tsExOut.includes('ok: app=com.example.notes'), `unexpected ts-minimal output: ${tsExOut}`);

    const subPing = await invokeSynctoolJSON(cliBin, ['ping'], {
      env: {
        SYNCTOOL_RELAY: healURI,
        SYNCTOOL_CONFIG: goHealCfg,
      },
    });
    assert.equal(subPing.exitCode, 0, `cli-subprocess ping failed: ${JSON.stringify(subPing)}`);
    assert.equal(subPing.result?.profile, 'nano');
    assert.equal(subPing.result?.spool_backend, 'memory');
    log('   All 3 runnable examples verified successfully!');
  } finally {
    if (inst1) await inst1.stopKeepData().catch(() => {});
    if (inst2) await inst2.stopKeepData().catch(() => {});
    if (inst3) await inst3.stopKeepData().catch(() => {});
    fs.rmSync(healRelayDir, { recursive: true, force: true });
  }
}
