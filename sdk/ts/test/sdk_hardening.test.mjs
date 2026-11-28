import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';

import {
  CHUNK_CIPHERTEXT_MAX,
  ErrorCode,
  NodeFileKeyStore,
  SyncClient,
  SyncError,
  blobFromBytes,
  bytesToHex,
  deriveBlobPartKeys,
  isAuthError,
  isQuotaExceeded,
  isRetryable,
  isSecurityAlert,
  isVersionMismatch,
  openStreamBlock,
  parsePairURI,
  parseRelayURI,
  randomBytes,
  redactMessage,
  sanitizeFileName,
  sealStreamBlock,
  suggestPipeMode,
  utf8Encode,
  validateManifest,
} from '../src/index.js';

// ============================================================================
// 1. Security Hardening: Redirect Block, Filename Sanitization, Secret Redaction & Bounds
// ============================================================================

test('Security hardening: 3xx redirect block, Windows reserved names, RLO strip, secret redaction & STREAM bounds', async () => {
  // 1. Filename sanitization (anchors + Windows reserved + RLO + emoji truncation + trailing dots/spaces)
  assert.equal(sanitizeFileName('../../evil/clip.mp4'), 'clip.mp4');
  assert.equal(sanitizeFileName('...'), 'attachment.bin');
  assert.equal(sanitizeFileName('CON'), '_CON');
  assert.equal(sanitizeFileName('nul.txt'), '_nul.txt');
  assert.equal(sanitizeFileName('C:\\foo\\COM1.tar.gz'), '_COM1.tar.gz');
  assert.equal(sanitizeFileName('lpt\u00b9.doc'), '_lpt\u00b9.doc');
  assert.equal(sanitizeFileName('  .report.pdf. . '), 'report.pdf');
  assert.equal(sanitizeFileName('invoice\u202ecod.exe'), 'invoicecod.exe');

  const longEmoji = '🚀跨端安全'.repeat(25) + '.mp4';
  const safeEmoji = sanitizeFileName(longEmoji);
  assert.ok(utf8Encode(safeEmoji).length <= 200);
  assert.ok(safeEmoji.endsWith('.mp4'));
  assert.equal(safeEmoji.includes('\ufffd'), false);

  // 2. SyncError auto-redaction of embedded URI #k= and #s=
  const secretKey = 'SECRET_RELAY_ACCESS_KEY_0123456789ABCDEF0123';
  const secretOob = 'SECRET_OOB_1234567890AB';
  const err = new SyncError(
    ErrorCode.ERR_URI_INVALID,
    `failed on synctool://relay?v=1&u=https%3A%2F%2Fsync.example.com%3A443#k=${secretKey} and #s=${secretOob}`,
  );
  assert.equal(err.message.includes(secretKey), false);
  assert.equal(err.message.includes(secretOob), false);
  assert.equal(JSON.stringify(err).includes(secretKey), false);
  assert.equal(redactMessage(`uri=synctool://pair?r=K7M9P2XQ#s=${secretOob}`).includes(secretOob), false);

  // 3. Error classification helpers & ERR_UNSUPPORTED_VERSION
  assert.equal(isQuotaExceeded(new SyncError(ErrorCode.ERR_OFFLINE_QUOTA_EXCEEDED, 'full')), true);
  assert.equal(suggestPipeMode(new SyncError(ErrorCode.ERR_SPOOL_DISABLED, 'off')), true);
  assert.equal(isRetryable(new SyncError(ErrorCode.ERR_RATE_LIMITED, '429', { retryable: true })), true);
  assert.equal(isAuthError(new SyncError(ErrorCode.ERR_TLS_PIN_MISMATCH, 'pin')), true);
  assert.equal(isSecurityAlert(new SyncError(ErrorCode.ERR_TLS_PIN_MISMATCH, 'pin')), true);
  assert.equal(isVersionMismatch(new SyncError(ErrorCode.ERR_UNSUPPORTED_VERSION, 'v2')), true);

  // v1.1 unknown fields tolerated; envelope_version > 1 -> ERR_UNSUPPORTED_VERSION
  const v11Manifest = {
    envelope_version: 1,
    msg_id: 'a'.repeat(32),
    app_id: 'com.yellowdking.notes',
    schema: 'note.item.v2',
    created_at: 1764246000,
    future_ext: { tags: ['work'] },
    sender: { device_id: 'b'.repeat(32), label: 'Phone', future_os: 'android-17' },
    inline_payload: { text: 'ok' },
    blobs: [],
  };
  assert.ok(validateManifest(v11Manifest).length > 0);
  assert.throws(() => validateManifest({ ...v11Manifest, envelope_version: 2 }), (e) => isVersionMismatch(e));
  assert.throws(() => validateManifest({ ...v11Manifest, envelope_version: 0 }), (e) => e.code === ErrorCode.ERR_MANIFEST_INVALID);
  assert.throws(
    () => parseRelayURI(`  synctool://relay?v=2&u=${encodeURIComponent('https://sync.example.com:443')}#k=${'A'.repeat(43)}  `),
    (e) => isVersionMismatch(e),
  );
  assert.throws(() => parsePairURI('synctool://pair?r=K7M9P2XQ&m=2&p=oneshot&v=2'), (e) => isVersionMismatch(e));

  // Whitespace trimming in URI parsers
  const trimmedRelay = parseRelayURI(` \n synctool://relay?v=1&u=${encodeURIComponent('https://sync.example.com:443')}#k=${'A'.repeat(43)} \n `);
  assert.equal(trimmedRelay.origin, 'https://sync.example.com:443');

  // 4. Non-final STREAM block length check
  const { encKey, noncePrefix } = await deriveBlobPartKeys(randomBytes(32), randomBytes(16), 1);
  await assert.rejects(
    () => sealStreamBlock(encKey, noncePrefix, randomBytes(16), 1, 0, false, new Uint8Array(100)),
    (e) => e instanceof SyncError && e.code === ErrorCode.ERR_CRYPTO_HANDSHAKE_FAILED,
  );
  await assert.rejects(
    () => openStreamBlock(encKey, noncePrefix, randomBytes(16), 1, 0, false, new Uint8Array(116)),
    (e) => e instanceof SyncError && e.code === ErrorCode.ERR_STREAM_TRUNCATED,
  );

  // 5. HTTP redirect: 'error' & 307 status hard-block
  let seenInit = null;
  const redirectClient = new SyncClient({
    relay: { origin: 'https://sync.example.com:443', accessKey: 'K'.repeat(43) },
    fetchImpl: async (_url, init) => {
      seenInit = init;
      return { status: 307, headers: { get: () => 'https://evil.example/steal' }, async text() { return ''; } };
    },
  });
  await assert.rejects(
    () => redirectClient.ping(),
    (e) => e instanceof SyncError && e.code === ErrorCode.ERR_RELAY_UNREACHABLE && e.retryable === false,
  );
  assert.equal(seenInit.redirect, 'error');

  // Real Node globalThis.fetch (undici) 307 redirect wraps 'unexpected redirect' inside err.cause.message
  const redirectSrv = http.createServer((_req, res) => {
    res.writeHead(307, { Location: 'http://127.0.0.1:9/steal' });
    res.end();
  });
  await new Promise((resolve) => redirectSrv.listen(0, '127.0.0.1', resolve));
  try {
    const { port } = redirectSrv.address();
    const realRedirectClient = new SyncClient({
      relay: { origin: `http://127.0.0.1:${port}`, accessKey: 'K'.repeat(43) },
    });
    await assert.rejects(
      () => realRedirectClient.ping(),
      (e) => e instanceof SyncError && e.code === ErrorCode.ERR_RELAY_UNREACHABLE && e.retryable === false,
    );
  } finally {
    await new Promise((resolve) => redirectSrv.close(resolve));
  }

  // 6. registerMailbox() & syncMailbox() gracefully degrade under --spool=off (strict: true throws ERR_SPOOL_DISABLED)
  const spoolOffClient = new SyncClient({
    relay: { origin: 'https://sync.example.com:443', accessKey: 'K'.repeat(43) },
    fetchImpl: async () => jsonResp(403, { error: 'ERR_SPOOL_DISABLED', retryable: false, suggest_mode: 'pipe' }),
  });
  const gracefulReg = await spoolOffClient.registerMailbox();
  assert.equal(gracefulReg.registered, false);
  await assert.rejects(
    () => spoolOffClient.registerMailbox({ strict: true }),
    (e) => e instanceof SyncError && e.code === ErrorCode.ERR_SPOOL_DISABLED,
  );
  const gracefulSync = await spoolOffClient.syncMailbox();
  assert.equal(gracefulSync.registered, false);
});

// ============================================================================
// 2. Self-Healing, NodeFileKeyStore, part_id=0 OOM Guard & Unified receiveFromRoom
// ============================================================================

test('Self-healing after nano memory-spool wipe, NodeFileKeyStore, part_id=0 OOM guard & receiveFromRoom', async () => {
  const tmpA = await fs.mkdtemp(path.join(os.tmpdir(), 'synctool-ks-a-'));
  const tmpB = await fs.mkdtemp(path.join(os.tmpdir(), 'synctool-ks-b-'));
  try {
    const accessKey = 'N'.repeat(43);
    const relayOrigin = 'https://sync.example.com:443';
    const serverNow = Math.floor(Date.now() / 1000) - 3600;

    let mailboxes = new Map();
    const rooms = new Map();
    const pipeWaiters = new Map();
    const items = new Map();
    const chunks = new Map();
    let part0Fetches = 0;

    const mockFetch = async (urlStr, init) => {
      const u = new URL(urlStr);
      const p = u.pathname;
      const m = init.method || 'GET';

      if (m === 'GET' && p === '/v1/caps') {
        return jsonResp(200, {
          proto_v: 1, min_proto_v: 1, max_proto_v: 1, server_version: '0.2.0', features: ['pipe_v1', 'spool_v1'],
          profile: 'nano', server_ts: serverNow, cert_expires_at: 0, cert_rotate_recommended: false,
          crypto_plaintext_block_bytes: 65536, crypto_block_bytes: 65552,
          streaming: { enabled: true, blocks_per_chunk: 2, max_transport_chunk_bytes: 2 * CHUNK_CIPHERTEXT_MAX, rendezvous_timeout_sec: 30, room_ttl_max_sec: 600 },
          spool: { enabled: true, backend: 'memory', max_item_bytes: 4 * 1024 * 1024, max_mailbox_bytes: 8 * 1024 * 1024, max_total_bytes: 16 * 1024 * 1024, max_items_per_mailbox: 16, default_ttl_sec: 1800, max_ttl_sec: 7200, uncommitted_ttl_sec: 1800, max_manifest_downloads: 16, max_downloads_per_chunk: 3, max_deposit_tokens_per_mailbox: 16 },
        });
      }
      if (m === 'PUT' && p.startsWith('/v1/mailboxes/')) {
        const mbId = p.split('/')[3];
        if (!mailboxes.has(mbId)) mailboxes.set(mbId, new Map());
        // Simulate v0.1.0 relay ignoring deposit_tokens in PUT to exercise SDK fallback POST!
        return jsonResp(200, { mailbox_id: mbId, registered: true, deposit_token_count: mailboxes.get(mbId).size });
      }
      if (m === 'POST' && p.endsWith('/deposit-tokens')) {
        const mbId = p.split('/')[3];
        if (!mailboxes.has(mbId)) return jsonResp(404, { error: 'ERR_NOT_FOUND', scope: 'mailbox', retryable: false });
        const body = JSON.parse(new TextDecoder().decode(init.body));
        mailboxes.get(mbId).set(body.token_id, body.token_hash_hex);
        return jsonResp(201, { token_id: body.token_id, active_count: mailboxes.get(mbId).size });
      }
      if (m === 'GET' && p.endsWith('/items')) {
        const mbId = p.split('/')[3];
        if (!mailboxes.has(mbId)) return jsonResp(404, { error: 'ERR_NOT_FOUND', scope: 'mailbox', retryable: false });
        const list = Array.from(items.values()).filter((it) => it.mailbox_id === mbId && it.committed)
          .map((it) => ({ item_id: it.item_id, created_at: it.created_at, expires_at: it.expires_at, total_bytes: it.declared_total_bytes, sealed_header: it.sealed_header, parts: it.parts }));
        return jsonResp(200, { mailbox_id: mbId, items: list });
      }
      if (m === 'POST' && p === '/v1/spool/init') {
        const body = JSON.parse(new TextDecoder().decode(init.body));
        const mb = mailboxes.get(body.mailbox_id);
        if (!mb || mb.size === 0) return jsonResp(404, { error: 'ERR_NOT_FOUND', scope: 'mailbox', retryable: false });
        const itemId = 'itm_' + bytesToHex(randomBytes(16));
        items.set(itemId, { ...body, item_id: itemId, created_at: serverNow, expires_at: serverNow + 1800, committed: false });
        return jsonResp(201, { item_id: itemId, upload_token: 'U'.repeat(43), max_transport_chunk_bytes: 2 * CHUNK_CIPHERTEXT_MAX, upload_expires_at: serverNow + 1800, expires_at: serverNow + 1800 });
      }
      if (m === 'PUT' && p.startsWith('/v1/spool/')) {
        const seg = p.split('/');
        chunks.set(`${seg[3]}:${seg[5]}:${seg[7]}`, new Uint8Array(init.body));
        return jsonResp(200, { received_bytes: init.body.byteLength });
      }
      if (m === 'POST' && p.endsWith('/commit')) {
        const itemId = p.split('/')[3];
        items.get(itemId).committed = true;
        return jsonResp(200, { item_id: itemId, committed: true, expires_at: serverNow + 1800 });
      }
      if (m === 'GET' && p.startsWith('/v1/spool/')) {
        const seg = p.split('/');
        if (Number(seg[5]) === 0) part0Fetches++;
        return binResp(200, chunks.get(`${seg[3]}:${seg[5]}:${seg[7]}`));
      }
      if (m === 'POST' && p.endsWith('/ack')) {
        items.delete(p.split('/')[3]);
        return jsonResp(200, { burned: true });
      }
      if (m === 'POST' && p === '/v1/rooms') {
        const body = JSON.parse(new TextDecoder().decode(init.body));
        const room = { room_id: body.room_id, pipe_id: bytesToHex(randomBytes(16)), sender_token: 'S'.repeat(43), receiver_token: 'R'.repeat(43), state: 'waiting', seq: body.initial_msg_b64 ? 1 : 0, messages: body.initial_msg_b64 ? [{ seq: 1, from: 'sender', kind: 'handshake', msg_b64: body.initial_msg_b64 }] : [], waiters: [] };
        rooms.set(body.room_id, room);
        return jsonResp(201, { room_id: room.room_id, pipe_id: room.pipe_id, sender_token: room.sender_token, expires_at: serverNow + 300, seq: room.seq });
      }
      if (m === 'POST' && p.endsWith('/join')) {
        const room = rooms.get(p.split('/')[3]);
        room.state = 'joined';
        return jsonResp(200, { room_id: room.room_id, pipe_id: room.pipe_id, receiver_token: room.receiver_token, expires_at: serverNow + 300, seq: room.seq, messages: [...room.messages] });
      }
      if (m === 'POST' && p.endsWith('/messages')) {
        const room = rooms.get(p.split('/')[3]);
        const body = JSON.parse(new TextDecoder().decode(init.body));
        const from = init.headers['X-Sync-Room-Token'] === room.sender_token ? 'sender' : 'receiver';
        room.seq += 1;
        room.messages.push({ seq: room.seq, from, kind: body.kind, msg_b64: body.msg_b64 });
        for (const w of room.waiters.splice(0)) w();
        return jsonResp(200, { seq: room.seq });
      }
      if (m === 'GET' && p.endsWith('/events')) {
        const room = rooms.get(p.split('/')[3]);
        const since = Number(u.searchParams.get('since') || '0');
        if (room.messages.filter((x) => x.seq > since).length === 0 && room.state === 'joined') {
          await new Promise((r) => { const t = setTimeout(r, 150); room.waiters.push(() => { clearTimeout(t); r(); }); });
        }
        return jsonResp(200, { state: room.state, seq: room.seq, messages: room.messages.filter((x) => x.seq > since), reason: '' });
      }
      if (m === 'POST' && p.endsWith('/close')) return jsonResp(200, { state: 'closed' });
      if (p.startsWith('/v1/pipe/')) {
        const seg = p.split('/');
        const key = `${seg[3]}:${seg[5]}:${seg[7]}`;
        if (m === 'PUT') {
          const bytes = new Uint8Array(init.body);
          const ex = pipeWaiters.get(key);
          if (ex?.resolveGet) { pipeWaiters.delete(key); ex.resolveGet(bytes); } else { await new Promise((resolvePut) => pipeWaiters.set(key, { bytes, resolvePut })); }
          return jsonResp(200, { bytes_relayed: bytes.length });
        }
        if (m === 'GET') {
          const ex = pipeWaiters.get(key);
          let bytes;
          if (ex?.bytes) { pipeWaiters.delete(key); bytes = ex.bytes; ex.resolvePut(); } else { bytes = await new Promise((resolveGet) => pipeWaiters.set(key, { resolveGet })); }
          return binResp(200, bytes);
        }
      }
      return jsonResp(404, { error: 'ERR_NOT_FOUND', retryable: false });
    };

    const ksA = new NodeFileKeyStore(tmpA);
    const ksB = new NodeFileKeyStore(tmpB);
    const alice = new SyncClient({ relay: { origin: relayOrigin, accessKey }, keyStore: ksA, label: 'Alice', fetchImpl: mockFetch, clockOffsetSec: serverNow - Math.floor(Date.now() / 1000) });
    const bob = new SyncClient({ relay: { origin: relayOrigin, accessKey }, keyStore: ksB, label: 'Bob', fetchImpl: mockFetch, clockOffsetSec: serverNow - Math.floor(Date.now() / 1000) });

    // 1. Pair via SAS with hyphenated input ("123-456") and persist into NodeFileKeyStore
    let offeredCode;
    let resolveOffer;
    const offerP = new Promise((r) => { resolveOffer = r; });
    let resolveSas;
    const sasP = new Promise((r) => { resolveSas = r; });
    const bindA = alice.startDeviceBind({
      mode: 2,
      preferPoll: true,
      onOfferReady: (o) => { offeredCode = o.formattedRoomId; resolveOffer(); },
      onSASInput: async () => {
        const raw = await sasP;
        return `${raw.slice(0, 3)}-${raw.slice(3)}`; // hyphenated SAS!
      },
    });
    await offerP;
    const bindB = bob.acceptDeviceBind(offeredCode, {
      preferPoll: true,
      onSASDisplay: ({ sas }) => resolveSas(sas),
      onSASConfirm: async () => true,
    });
    await Promise.all([bindA, bindB]);

    // Verify NodeFileKeyStore persisted inbound_token_hash on disk
    const reopenedKsB = new NodeFileKeyStore(tmpB);
    const cardsOnB = await reopenedKsB.listDevices();
    assert.equal(cardsOnB.length, 1);
    assert.equal(cardsOnB[0].inbound_token_hash.length, 64);

    // 2. Wipe relay mailboxes (simulating nano memory-spool restart!)
    mailboxes = new Map();

    // 3. Bob calls listInbox -> receives 404 -> auto self-heals mailbox + Alice's deposit_token!
    const healedList = await bob.listInbox();
    assert.equal(healedList.length, 0);

    // 4. Alice sends text via sendText('Bob', ...) WITHOUT re-pairing -> succeeds!
    const sent = await alice.sendText('Bob', 'healed note');
    assert.equal(sent.mode, 'spool');

    // 5. Part 0 OOM DoS check: inject oversized part_id=0 layout -> must reject with 0 part_id=0 chunk GETs!
    const goodItem = items.get(sent.itemId);
    const savedParts = goodItem.parts;
    goodItem.parts = [{ part_id: 0, total_bytes: 999_999, chunk_count: 50 }];
    part0Fetches = 0;
    await assert.rejects(
      () => bob.listInbox({ strict: true }),
      (e) => e instanceof SyncError && e.code === ErrorCode.ERR_MANIFEST_INVALID,
    );
    assert.equal(part0Fetches, 0);
    goodItem.parts = savedParts;

    // 6. Normal pull & burn + safeName verification via unified receiveFromRoom (m=0 direct)
    let dirOffer;
    let resolveDir;
    const dirP = new Promise((r) => { resolveDir = r; });
    const sendDir = alice.sendToDevice(
      (await ksA.listDevices())[0].device_id,
      { schema: 'file.v1', blobs: [blobFromBytes(utf8Encode('hi'), { role: 'file', name: 'NUL.txt' })] },
      { deliveryMode: 'pipe', preferPoll: true, onOfferReady: (o) => { dirOffer = o.pairUri; resolveDir(); } },
    );
    await dirP;
    let gotSafeName = '';
    const recvDir = bob.receiveFromRoom(dirOffer, async ({ blobs }) => {
      gotSafeName = blobs[0].safeName;
    }, { preferPoll: true });
    await Promise.all([sendDir, recvDir]);
    assert.equal(gotSafeName, '_NUL.txt');
  } finally {
    await fs.rm(tmpA, { recursive: true, force: true });
    await fs.rm(tmpB, { recursive: true, force: true });
  }
});

function jsonResp(status, obj) {
  const txt = JSON.stringify(obj);
  return { status, headers: { get: () => null }, async text() { return txt; }, async json() { return obj; }, async arrayBuffer() { return utf8Encode(txt).buffer; } };
}

function binResp(status, bytes) {
  return { status, headers: { get: () => null }, async text() { return ''; }, async arrayBuffer() { return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength); } };
}
