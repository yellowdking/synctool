// Helper process managers and secondary scenario runners for e2e/cross_lang.mjs.

import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import readline from 'node:readline';
import { fileURLToPath } from 'node:url';

import {
  ErrorCode,
  MemoryKeyStore,
  SyncClient,
  SyncError,
  blobFromBytes,
  parseRelayURI,
} from '../sdk/ts/src/index.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const REPO_ROOT = path.resolve(__dirname, '..');
const GO_BIN = process.env.SYNCTOOL_GO_BIN || 'go';
const EXE_SUFFIX = process.platform === 'win32' ? '.exe' : '';

export function log(msg) {
  console.log(`[cross-lang-e2e] ${msg}`);
}

export function getFreePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.unref();
    srv.on('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const { port } = srv.address();
      srv.close(() => resolve(port));
    });
  });
}

export function sha256Hex(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

export function makeTempDir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

export function buildBinaries(outDir) {
  const relayBin = path.join(outDir, `synctool-relay${EXE_SUFFIX}`);
  const cliBin = path.join(outDir, `synctool${EXE_SUFFIX}`);
  log(`Building synctool-relay and synctool CLI using ${GO_BIN}...`);
  execFileSync(GO_BIN, ['build', '-o', relayBin, './cmd/synctool-relay'], {
    cwd: REPO_ROOT,
    env: { ...process.env, CGO_ENABLED: '0' },
    stdio: 'pipe',
  });
  execFileSync(GO_BIN, ['build', '-o', cliBin, './cmd/synctool'], {
    cwd: REPO_ROOT,
    env: { ...process.env, CGO_ENABLED: '0' },
    stdio: 'pipe',
  });
  return { relayBin, cliBin };
}

export async function startRelayProcess(relayBin, opts) {
  const port = await getFreePort();
  const dataDir = makeTempDir('synctool-relay-e2e-');
  const listenAddr = `127.0.0.1:${port}`;
  const tlsMode = opts.tlsMode ?? 'selfsigned';
  const profile = opts.profile ?? 'nano';
  const spool = opts.spool ?? 'disk';

  const initArgs = [
    'init',
    '--public-host', '127.0.0.1',
    '--listen', listenAddr,
    '--profile', profile,
    '--spool', spool,
    '--tls', tlsMode,
    '--data-dir', dataDir,
  ];
  if (opts.trustProxies) {
    initArgs.push('--trust-proxies', opts.trustProxies);
  }
  const initOut = execFileSync(relayBin, initArgs, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  const uriMatch = initOut.match(/synctool:\/\/relay\?[^\s]+/);
  assert.ok(uriMatch, `failed to parse onboarding URI from synctool-relay init output:\n${initOut}`);
  const relayURI = uriMatch[0].trim();
  const parsed = parseRelayURI(relayURI);

  const serveArgs = [
    'serve',
    '--public-host', '127.0.0.1',
    '--listen', listenAddr,
    '--profile', profile,
    '--spool', spool,
    '--tls', tlsMode,
    '--data-dir', dataDir,
  ];
  if (opts.trustProxies) {
    serveArgs.push('--trust-proxies', opts.trustProxies);
  }
  const child = spawn(relayBin, serveArgs, { stdio: ['ignore', 'pipe', 'pipe'] });
  let stderrBuf = '';
  child.stderr.on('data', (d) => { stderrBuf += d.toString(); });

  // Wait until relay responds to ping from TS client.
  const probeClient = new SyncClient({ relay: relayURI, label: 'probe' });
  const deadline = Date.now() + 10_000;
  let ready = false;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) {
      throw new Error(`synctool-relay exited early (${child.exitCode}): ${stderrBuf}`);
    }
    try {
      await probeClient.ping();
      ready = true;
      break;
    } catch {
      await new Promise((r) => setTimeout(r, 100));
    }
  }
  if (!ready) {
    child.kill('SIGTERM');
    throw new Error(`synctool-relay did not become ready in time:\n${stderrBuf}`);
  }

  return {
    relayURI,
    parsed,
    dataDir,
    port,
    stop() {
      return new Promise((resolve) => {
        if (child.exitCode !== null || child.signalCode !== null) {
          fs.rmSync(dataDir, { recursive: true, force: true });
          resolve();
          return;
        }
        child.once('exit', () => {
          fs.rmSync(dataDir, { recursive: true, force: true });
          resolve();
        });
        child.kill('SIGTERM');
        setTimeout(() => {
          if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
        }, 2000).unref();
      });
    },
  };
}

export function runCLI(cliBin, configDir, args, stdinText = null) {
  return new Promise((resolve, reject) => {
    const fullArgs = ['--config', configDir, '--json', ...args];
    const child = spawn(cliBin, fullArgs, { stdio: ['pipe', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => { stdout += d.toString(); });
    child.stderr.on('data', (d) => { stderr += d.toString(); });
    child.on('error', reject);
    child.on('close', (code) => {
      const lines = stdout.trim().split(/\r?\n/).filter(Boolean).map((l) => JSON.parse(l));
      const resultLine = [...lines].reverse().find((l) => l.type === 'result');
      const errorLine = [...lines].reverse().find((l) => l.type === 'error');
      resolve({ code, lines, result: resultLine?.data, error: errorLine?.error, stderr });
    });
    if (stdinText !== null) {
      child.stdin.write(stdinText);
    }
    child.stdin.end();
  });
}

export function spawnCLIInteractive(cliBin, configDir, args) {
  const fullArgs = ['--config', configDir, '--json', ...args];
  const child = spawn(cliBin, fullArgs, { stdio: ['pipe', 'pipe', 'pipe'] });
  const events = [];
  const waiters = [];
  let stderr = '';
  child.stderr.on('data', (d) => { stderr += d.toString(); });

  const rl = readline.createInterface({ input: child.stdout });
  rl.on('line', (line) => {
    const trimmed = line.trim();
    if (!trimmed) return;
    const obj = JSON.parse(trimmed);
    events.push(obj);
    for (let i = waiters.length - 1; i >= 0; i--) {
      if (waiters[i].pred(obj)) {
        const w = waiters.splice(i, 1)[0];
        w.resolve(obj);
      }
    }
  });

  const donePromise = new Promise((resolve, reject) => {
    child.on('error', reject);
    child.on('close', (code) => {
      rl.close();
      for (const w of waiters.splice(0)) {
        w.reject(new Error(`CLI exited (${code}) before expected event. stderr=${stderr}`));
      }
      const resultLine = [...events].reverse().find((l) => l.type === 'result');
      const errorLine = [...events].reverse().find((l) => l.type === 'error');
      resolve({ code, events, result: resultLine?.data, error: errorLine?.error, stderr });
    });
  });

  function waitForEvent(pred, timeoutMs = 20_000) {
    const existing = events.find(pred);
    if (existing) return Promise.resolve(existing);
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        const idx = waiters.findIndex((w) => w.resolve === resolve);
        if (idx >= 0) waiters.splice(idx, 1);
        reject(new Error(`Timed out waiting for CLI event. events=${JSON.stringify(events)} stderr=${stderr}`));
      }, timeoutMs);
      waiters.push({
        pred,
        resolve: (v) => { clearTimeout(timer); resolve(v); },
        reject: (e) => { clearTimeout(timer); reject(e); },
      });
    });
  }

  return {
    child,
    waitForEvent,
    writeLine(s) {
      child.stdin.write(`${s}\n`);
    },
    endInput() {
      child.stdin.end();
    },
    done: donePromise,
  };
}

export async function runProfileSpoolOffAndProxyScenarios({
  relayBin,
  cliBin,
  workDir,
  activeRelays,
  payloadBytes,
  payloadPath,
  payloadSha,
}) {
  // =========================================================================
  // SCENARIO 5B: Dedicated --profile=nano 4 MiB Quota Enforcement Check
  // =========================================================================
  log('5B. Starting real synctool-relay (--profile=nano, --spool=memory) & testing 4 MiB quota...');
  const relayNano = await startRelayProcess(relayBin, {
    tlsMode: 'selfsigned',
    profile: 'nano',
    spool: 'memory',
  });
  activeRelays.push(relayNano);

  const tsNanoA = new SyncClient({ relay: relayNano.relayURI, keyStore: new MemoryKeyStore(), label: 'TS-Nano-A' });
  const tsNanoB = new SyncClient({ relay: relayNano.relayURI, keyStore: new MemoryKeyStore(), label: 'TS-Nano-B' });
  const nanoCaps = await tsNanoA.capabilities();
  assert.equal(nanoCaps.profile, 'nano');
  assert.equal(nanoCaps.streaming.max_transport_chunk_bytes, 262208);
  assert.equal(nanoCaps.spool.max_item_bytes, 4 * 1024 * 1024);

  let nanoOfferUri = null;
  let nanoAcceptP = null;
  await tsNanoA.startDeviceBind({
    mode: 1,
    timeoutMs: 15_000,
    onOfferReady: (o) => {
      nanoOfferUri = o.pairUri;
      nanoAcceptP = tsNanoB.acceptDeviceBind(nanoOfferUri, { timeoutMs: 15_000 });
    },
  });
  await nanoAcceptP;
  const nanoBId = (await tsNanoB.getIdentity()).deviceId;

  const big5M = crypto.randomBytes(4 * 1024 * 1024 + 4096);
  await assert.rejects(
    () => tsNanoA.sendToDevice(nanoBId, {
      schema: 'video.v1',
      blobs: [blobFromBytes(big5M, { role: 'video', name: 'huge.mp4' })],
    }),
    (err) => err instanceof SyncError && err.code === ErrorCode.ERR_OFFLINE_QUOTA_EXCEEDED,
  );
  log('   --profile=nano 262,208 B chunk & 4 MiB quota enforcement passed!');

  // =========================================================================
  // SCENARIO 6: Manual --spool=off Kill-Switch + Mode A Flow 2 Direct (Go <-> TS)
  // =========================================================================
  log('6. Starting real synctool-relay (--spool=off, --tls=selfsigned) & testing Flow 2 Mode A direct...');
  const relaySpoolOff = await startRelayProcess(relayBin, {
    tlsMode: 'selfsigned',
    profile: 'nano',
    spool: 'off',
  });
  activeRelays.push(relaySpoolOff);

  const goConfigOff = path.join(workDir, 'go-off-cfg');
  const initOff = await runCLI(cliBin, goConfigOff, ['init', '--stdin', '--label', 'Go-Off'], `${relaySpoolOff.relayURI}\n`);
  assert.equal(initOff.code, 0);
  assert.equal(initOff.result.spool_enabled, false);
  assert.equal(initOff.result.spool_backend, 'off');

  const tsOff = new SyncClient({
    relay: relaySpoolOff.relayURI,
    keyStore: new MemoryKeyStore(),
    label: 'TS-Off',
  });
  const offReg = await tsOff.registerMailbox();
  assert.equal(offReg.registered, false);
  await assert.rejects(
    () => tsOff.registerMailbox({ strict: true }),
    (err) => err instanceof SyncError && err.code === ErrorCode.ERR_SPOOL_DISABLED,
  );

  // Pair Go-Off <-> TS-Off cleanly under --spool=off!
  const goPairOff = spawnCLIInteractive(cliBin, goConfigOff, ['pair', 'offer', '--mode', 'qr', '--label', 'Go-Off']);
  const offerOff = await goPairOff.waitForEvent((e) => e.type === 'event' && e.event === 'offer_ready');
  const tsCardOff = await tsOff.acceptDeviceBind(offerOff.pair_uri, { label: 'TS-Off' });
  const goPairOffRes = await goPairOff.done;
  assert.equal(goPairOffRes.code, 0);
  assert.equal(tsCardOff.mailbox_id, null);

  // 6A: Go CLI send --to TS-Off --mode pipe -> TS receiveDirect (zero-disk!)
  const goDirectSend = spawnCLIInteractive(cliBin, goConfigOff, [
    'send', '--to', goPairOffRes.result.device_id,
    '--mode', 'pipe',
    '--schema', 'note.direct.v1',
    '--text', 'Go-To-TS-Direct-NoSpool',
    '--file', `${payloadPath}:video`,
  ]);
  const directOfferGo = await goDirectSend.waitForEvent((e) => e.type === 'event' && e.event === 'offer_ready');
  let tsDirectBytes = null;
  let tsDirectManifest = null;
  await tsOff.receiveDirect(directOfferGo.pair_uri, async ({ manifest, blobs }) => {
    tsDirectManifest = manifest;
    tsDirectBytes = blobs[0].bytes;
  });
  const goDirectSendRes = await goDirectSend.done;
  assert.equal(goDirectSendRes.code, 0, `Go direct pipe send failed: ${JSON.stringify(goDirectSendRes)}`);
  assert.equal(tsDirectManifest.inline_payload.text, 'Go-To-TS-Direct-NoSpool');
  assert.equal(sha256Hex(tsDirectBytes), payloadSha);

  // 6B: TS sendToDevice(deliveryMode:'pipe') -> Go CLI recv (zero-disk!)
  const goDirectOut = path.join(workDir, 'go-direct-out');
  let goDirectRecvP = null;
  await tsOff.sendToDevice(
    initOff.result.device_id,
    {
      schema: 'note.direct.v1',
      inlinePayload: { text: 'TS-To-Go-Direct-NoSpool' },
      blobs: [blobFromBytes(payloadBytes, { role: 'video', name: 'direct_ts.mp4' })],
    },
    {
      deliveryMode: 'pipe',
      onOfferReady: (offer) => {
        goDirectRecvP = runCLI(cliBin, goConfigOff, ['recv', '--out', goDirectOut, offer.pairUri]);
      },
    },
  );
  const goDirectRecvRes = await goDirectRecvP;
  assert.equal(goDirectRecvRes.code, 0, `Go direct pipe recv failed: ${JSON.stringify(goDirectRecvRes)}`);
  assert.equal(goDirectRecvRes.result.manifest.inline_payload.text, 'TS-To-Go-Direct-NoSpool');
  assert.equal(sha256Hex(fs.readFileSync(goDirectRecvRes.result.files[0])), payloadSha);
  log('   --spool=off kill-switch + cross-language Mode A direct (m=0&p=direct) passed both directions!');

  // =========================================================================
  // SCENARIO 7: Reverse Proxy Mode (--tls=off + --trust-proxies=127.0.0.1/32)
  // =========================================================================
  log('7. Starting real synctool-relay (--tls=off, --trust-proxies=127.0.0.1/32)...');
  const relayProxy = await startRelayProcess(relayBin, {
    tlsMode: 'off',
    profile: 'standard',
    spool: 'memory',
    trustProxies: '127.0.0.1/32',
  });
  activeRelays.push(relayProxy);

  const goConfigProxy = path.join(workDir, 'go-proxy-cfg');
  const initProxy = await runCLI(cliBin, goConfigProxy, ['init', '--stdin', '--label', 'Go-Proxy'], `${relayProxy.relayURI}\n`);
  assert.equal(initProxy.code, 0);
  const tsProxy = new SyncClient({ relay: relayProxy.relayURI, label: 'TS-Proxy' });
  const proxyPing = await tsProxy.ping();
  assert.equal(proxyPing.profile, 'standard');
  assert.equal(proxyPing.spool_backend, 'memory');
  assert.equal(proxyPing.cert_expires_at, 0);
  log('   Reverse-proxy --tls=off + TRUSTED_PROXIES mode passed for Go CLI & TS SDK!');
}
