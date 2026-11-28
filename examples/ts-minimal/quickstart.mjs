// Minimal Node.js / Browser WebCrypto SDK integration example (zero npm dependencies).
//
// Run offline self-check:
//   node ./examples/ts-minimal/quickstart.mjs --self-test
//
// Run against a live relay:
//   SYNCTOOL_RELAY='synctool://relay?v=1&u=https%3A%2F%2Fsync.example.com%3A443#k=...' \
//   SYNCTOOL_CONFIG=./.demo-keystore \
//   node ./examples/ts-minimal/quickstart.mjs

import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import {
  NodeFileKeyStore,
  SyncClient,
  isRetryable,
  isVersionMismatch,
  parcelText,
  redactMessage,
  sanitizeFileName,
  suggestPipeMode,
} from '../../sdk/ts/src/index.js';

async function runSelfTest() {
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'synctool-ts-example-'));
  try {
    const store = new NodeFileKeyStore(tmpDir);
    const seed1 = await store.loadOrCreateMasterSeed();
    const seed2 = await store.loadOrCreateMasterSeed();
    if (seed1.length !== 32 || Buffer.compare(seed1, seed2) !== 0) {
      throw new Error('NodeFileKeyStore seed persistence check failed');
    }
    const p = parcelText('hello cross-platform world', 'com.example.notes');
    const safe = sanitizeFileName('..\\COM1.txt');
    const red = redactMessage('uri=synctool://pair?r=K7M9P2XQ&m=1&p=oneshot#s=ABCDEFGHIJKLMNOPQRSTUV');
    const tmpCli = new SyncClient({
      relay: { origin: 'https://sync.example.com:443', accessKey: 'K'.repeat(43) },
      keyStore: store,
      appId: 'com.example.notes',
    });
    await tmpCli.getIdentity();
    await tmpCli.close();
    console.log(`ok: app=${p.appId} safe=${safe} redacted=${red}`);
  } finally {
    await fs.rm(tmpDir, { recursive: true, force: true });
  }
}

async function main() {
  if (process.argv.includes('--self-test') || (!process.env.SYNCTOOL_RELAY && !process.env.SYNCTOOL_RELAY_URI)) {
    await runSelfTest();
    return;
  }

  // 1. Initialize client from SYNCTOOL_RELAY + SYNCTOOL_CONFIG (NodeFileKeyStore 0600)
  const cli = SyncClient.fromEnv({ appId: 'com.example.notes', label: 'Node Quickstart' });
  try {
    const ping = await cli.ping();
    console.log(`connected: profile=${ping.profile} spool=${ping.spool_backend} rtt=${ping.rtt_ms}ms`);

    // 2. Two-phase inbox preview + verified fetch & signed ACK burn (auto self-heals on nano restart)
    const previews = await cli.listInbox({ appId: 'com.example.notes' });
    for (const item of previews) {
      await cli.fetchParcel(item.item_id, async ({ manifest, blobs }) => {
        console.log('received note:', manifest.inline_payload);
        for (const b of blobs) {
          console.log(`attachment verified: ${b.safeName} (${b.descriptor.size} bytes)`);
        }
      });
    }
  } finally {
    await cli.close();
  }
}

main().catch((err) => {
  if (isVersionMismatch(err)) {
    console.error('Please upgrade @yellowdking/synctool:', err.message);
  } else if (suggestPipeMode(err)) {
    console.error('Offline spool unavailable/full — retry with { deliveryMode: "pipe" }:', err.message);
  } else if (isRetryable(err)) {
    console.error('Transient network error (safe to retry):', err.message);
  } else {
    console.error('Sync error:', err);
  }
  process.exit(1);
});
