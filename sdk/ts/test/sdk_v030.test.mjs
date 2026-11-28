import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs/promises';
import https from 'node:https';
import os from 'node:os';
import path from 'node:path';

import {
  CHUNK_CIPHERTEXT_MAX,
  CHUNK_PLAINTEXT_MAX,
  ErrorCode,
  MemoryKeyStore,
  NodeFileKeyStore,
  StreamingSha256,
  SyncClient,
  SyncError,
  b64uToBytes,
  blobFromBytes,
  blobFromNodeFile,
  bytesToB64u,
  bytesToHex,
  canonicalizeRelayOrigin,
  computeCommitA,
  computeCommitSasHandshake,
  computeQrOobHandshake,
  concatBytes,
  createNodeFileBlobSink,
  decryptPartBytes,
  deriveBlobPartKeys,
  deriveDeviceIdentity,
  deriveRelayId,
  ed25519KeyPairFromSeed,
  ed25519Sign,
  ed25519Verify,
  encryptPartBytes,
  formatPairURI,
  formatRelayURI,
  hexToBytes,
  isLoopbackHost,
  isSmallOrderEd25519PublicKey,
  normalizeRoomId,
  openPaired0RTTHeader,
  openPipeCtrlFrame,
  parsePairURI,
  parseRelayURI,
  randomBytes,
  readU32be,
  readU64be,
  redactMessage,
  sanitizeFileName,
  sealPaired0RTTHeader,
  sealStreamBlock,
  setCryptoProvider,
  sha256,
  signDeviceCard,
  u64be,
  utf8Encode,
  verifyDeviceCard,
} from '../src/index.js';
import { iterateSSE } from '../src/client_transport.js';

function jsonResp(status, obj, extraHeaders = {}) {
  const txt = JSON.stringify(obj);
  const map = new Map(Object.entries(extraHeaders).map(([k, v]) => [k.toLowerCase(), String(v)]));
  return {
    status,
    headers: { get: (k) => map.get(String(k).toLowerCase()) ?? null },
    body: { cancel: async () => {} },
    async text() { return txt; },
    async json() { return obj; },
    async arrayBuffer() {
      const b = utf8Encode(txt);
      return b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength);
    },
  };
}

function binResp(status, bytes) {
  return {
    status,
    headers: { get: () => null },
    body: { cancel: async () => {} },
    async text() { return new TextDecoder().decode(bytes); },
    async arrayBuffer() { return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength); },
  };
}

function createStatefulMockRelay({ spoolEnabled = true, blocksPerChunk = 2 } = {}) {
  const serverNow = () => Math.floor(Date.now() / 1000);
  const rooms = new Map();
  const pipeWaiters = new Map();
  const mailboxes = new Map();
  const items = new Map();
  const chunks = new Map();
  const stats = {
    part0Gets: 0,
    blobGets: 0,
    depositTokenPosts: 0,
    depositTokenDeletes: [],
    spoolDeletes: [],
    burnedRooms: [],
    closedRooms: [],
  };

  const fetchImpl = async (urlStr, init = {}) => {
    const u = new URL(urlStr);
    const p = u.pathname;
    const m = init.method || 'GET';

    if (m === 'GET' && p === '/v1/ping') {
      return jsonResp(200, {
        proto_v: 1,
        server_ts: serverNow(),
        profile: 'nano',
        spool_backend: spoolEnabled ? 'memory' : 'off',
        cert_expires_at: 0,
        cert_rotate_recommended: false,
      });
    }
    if (m === 'GET' && p === '/v1/caps') {
      return jsonResp(200, {
        proto_v: 1,
        profile: 'nano',
        server_ts: serverNow(),
        cert_expires_at: 0,
        cert_rotate_recommended: false,
        crypto_plaintext_block_bytes: 65536,
        crypto_block_bytes: 65552,
        streaming: {
          enabled: true,
          blocks_per_chunk: blocksPerChunk,
          max_transport_chunk_bytes: blocksPerChunk * CHUNK_CIPHERTEXT_MAX,
          rendezvous_timeout_sec: 30,
          room_ttl_max_sec: 600,
        },
        spool: spoolEnabled
          ? {
              enabled: true,
              backend: 'memory',
              max_item_bytes: 16 * 1024 * 1024,
              max_mailbox_bytes: 32 * 1024 * 1024,
              max_total_bytes: 64 * 1024 * 1024,
              max_items_per_mailbox: 16,
              default_ttl_sec: 1800,
              max_ttl_sec: 7200,
              uncommitted_ttl_sec: 1800,
              max_manifest_downloads: 16,
              max_downloads_per_chunk: 3,
              max_deposit_tokens_per_mailbox: 16,
            }
          : {
              enabled: false,
              backend: 'off',
              max_item_bytes: 0,
              max_mailbox_bytes: 0,
              max_total_bytes: 0,
              max_items_per_mailbox: 0,
              default_ttl_sec: 0,
              max_ttl_sec: 0,
              uncommitted_ttl_sec: 0,
              max_manifest_downloads: 0,
              max_downloads_per_chunk: 0,
              max_deposit_tokens_per_mailbox: 0,
            },
      });
    }
    if (m === 'PUT' && p.startsWith('/v1/mailboxes/')) {
      if (!spoolEnabled) return jsonResp(403, { error: 'ERR_SPOOL_DISABLED', retryable: false });
      const mbId = p.split('/')[3];
      const body = JSON.parse(new TextDecoder().decode(init.body));
      if (!mailboxes.has(mbId)) mailboxes.set(mbId, new Map());
      const tokMap = mailboxes.get(mbId);
      for (const sp of body.deposit_tokens || []) {
        tokMap.set(sp.token_id, sp.token_hash_hex);
      }
      return jsonResp(200, { mailbox_id: mbId, registered: true, deposit_token_count: tokMap.size });
    }
    if (m === 'POST' && p.endsWith('/deposit-tokens')) {
      if (!spoolEnabled) return jsonResp(403, { error: 'ERR_SPOOL_DISABLED', retryable: false });
      const mbId = p.split('/')[3];
      const body = JSON.parse(new TextDecoder().decode(init.body));
      if (!mailboxes.has(mbId)) mailboxes.set(mbId, new Map());
      mailboxes.get(mbId).set(body.token_id, body.token_hash_hex);
      stats.depositTokenPosts++;
      return jsonResp(201, { token_id: body.token_id, active_count: mailboxes.get(mbId).size });
    }
    if (m === 'DELETE' && p.includes('/deposit-tokens/')) {
      if (!spoolEnabled) return jsonResp(403, { error: 'ERR_SPOOL_DISABLED', retryable: false });
      const seg = p.split('/');
      const mbId = seg[3];
      const tokId = seg[5];
      stats.depositTokenDeletes.push(tokId);
      mailboxes.get(mbId)?.delete(tokId);
      return jsonResp(200, { token_id: tokId, revoked: true });
    }
    if (m === 'POST' && p === '/v1/rooms') {
      const body = JSON.parse(new TextDecoder().decode(init.body));
      const room = {
        room_id: body.room_id,
        pipe_id: bytesToHex(randomBytes(16)),
        sender_token: 'S'.repeat(43),
        receiver_token: 'R'.repeat(43),
        state: 'waiting',
        reason: '',
        seq: body.initial_msg_b64 ? 1 : 0,
        messages: body.initial_msg_b64 ? [{ seq: 1, from: 'sender', kind: 'handshake', msg_b64: body.initial_msg_b64 }] : [],
        waiters: [],
      };
      rooms.set(body.room_id, room);
      return jsonResp(201, { room_id: room.room_id, pipe_id: room.pipe_id, sender_token: room.sender_token, expires_at: serverNow() + 300, seq: room.seq });
    }
    if (m === 'POST' && p.endsWith('/join')) {
      const rid = p.split('/')[3];
      const room = rooms.get(rid);
      if (!room) return jsonResp(404, { error: 'ERR_NOT_FOUND', retryable: false });
      if (room.state === 'burned') return jsonResp(410, { error: 'ERR_ROOM_BURNED', retryable: false });
      room.state = 'joined';
      return jsonResp(200, { room_id: rid, pipe_id: room.pipe_id, receiver_token: room.receiver_token, expires_at: serverNow() + 300, seq: room.seq, messages: [...room.messages] });
    }
    if (m === 'POST' && p.endsWith('/messages')) {
      const rid = p.split('/')[3];
      const room = rooms.get(rid);
      if (!room) return jsonResp(404, { error: 'ERR_NOT_FOUND', retryable: false });
      if (room.state === 'burned') return jsonResp(410, { error: 'ERR_ROOM_BURNED', retryable: false });
      const body = JSON.parse(new TextDecoder().decode(init.body));
      const from = init.headers['X-Sync-Room-Token'] === room.sender_token ? 'sender' : 'receiver';
      room.seq++;
      room.messages.push({ seq: room.seq, from, kind: body.kind, msg_b64: body.msg_b64 });
      for (const w of room.waiters.splice(0)) w();
      return jsonResp(200, { seq: room.seq });
    }
    if (m === 'GET' && p.endsWith('/events') && p.startsWith('/v1/rooms/')) {
      const rid = p.split('/')[3];
      const room = rooms.get(rid);
      if (!room) return jsonResp(404, { error: 'ERR_NOT_FOUND', retryable: false });
      const since = Number(u.searchParams.get('since') || '0');
      const getMissed = () => room.messages.filter((x) => x.seq > since);
      if (getMissed().length === 0 && room.state !== 'burned' && room.state !== 'closed') {
        await new Promise((r) => {
          const t = setTimeout(r, 100);
          room.waiters.push(() => { clearTimeout(t); r(); });
        });
      }
      return jsonResp(200, { state: room.state, seq: room.seq, messages: getMissed(), reason: room.reason });
    }
    if (m === 'POST' && p.endsWith('/close')) {
      const rid = p.split('/')[3];
      const room = rooms.get(rid);
      if (room) {
        const body = JSON.parse(new TextDecoder().decode(init.body));
        if (body.reason === 'verify_failed' || body.reason === 'rejected') {
          room.state = 'burned';
          stats.burnedRooms.push(rid);
        } else {
          room.state = 'closed';
          stats.closedRooms.push(rid);
        }
        room.reason = body.reason;
        for (const w of room.waiters.splice(0)) w();
      }
      return jsonResp(200, { room_id: rid, state: room?.state || 'closed' });
    }
    if (p.startsWith('/v1/pipe/')) {
      const seg = p.split('/');
      const key = `${seg[3]}:${seg[5]}:${seg[7]}`;
      if (m === 'PUT') {
        const bytes = new Uint8Array(init.body);
        const ex = pipeWaiters.get(key);
        if (ex?.resolveGet) {
          pipeWaiters.delete(key);
          ex.resolveGet(bytes);
        } else {
          await new Promise((resolvePut) => pipeWaiters.set(key, { bytes, resolvePut }));
        }
        return jsonResp(200, { bytes_relayed: bytes.length });
      }
      if (m === 'GET') {
        const ex = pipeWaiters.get(key);
        let bytes;
        if (ex?.bytes) {
          pipeWaiters.delete(key);
          bytes = ex.bytes;
          ex.resolvePut();
        } else {
          bytes = await new Promise((resolveGet) => pipeWaiters.set(key, { resolveGet }));
        }
        return binResp(200, bytes);
      }
    }
    if (m === 'POST' && p === '/v1/spool/init') {
      const body = JSON.parse(new TextDecoder().decode(init.body));
      const itemId = 'itm_' + bytesToHex(randomBytes(12));
      const now = serverNow();
      items.set(itemId, { ...body, item_id: itemId, created_at: now, expires_at: now + 1800, committed: false });
      return jsonResp(201, { item_id: itemId, upload_token: 'U'.repeat(43), max_transport_chunk_bytes: blocksPerChunk * CHUNK_CIPHERTEXT_MAX, upload_expires_at: now + 1800, expires_at: now + 1800 });
    }
    if (m === 'DELETE' && /^\/v1\/spool\/[^/]+$/.test(p)) {
      const itemId = p.split('/')[3];
      stats.spoolDeletes.push(itemId);
      items.delete(itemId);
      return jsonResp(200, { deleted: true });
    }
    if (m === 'PUT' && p.startsWith('/v1/spool/')) {
      const seg = p.split('/');
      chunks.set(`${seg[3]}:${seg[5]}:${seg[7]}`, new Uint8Array(init.body));
      return jsonResp(200, { received_bytes: init.body.byteLength });
    }
    if (m === 'POST' && p.endsWith('/commit')) {
      const itemId = p.split('/')[3];
      const it = items.get(itemId);
      it.committed = true;
      return jsonResp(200, { item_id: itemId, committed: true, expires_at: it.expires_at });
    }
    if (m === 'GET' && p.endsWith('/items')) {
      const mbId = p.split('/')[3];
      const list = Array.from(items.values())
        .filter((it) => it.mailbox_id === mbId && it.committed)
        .map((it) => ({ item_id: it.item_id, created_at: it.created_at, expires_at: it.expires_at, total_bytes: it.declared_total_bytes, sealed_header: it.sealed_header, parts: it.parts }));
      return jsonResp(200, { mailbox_id: mbId, items: list });
    }
    if (m === 'GET' && p.startsWith('/v1/spool/')) {
      const seg = p.split('/');
      if (Number(seg[5]) === 0) stats.part0Gets++;
      else stats.blobGets++;
      return binResp(200, chunks.get(`${seg[3]}:${seg[5]}:${seg[7]}`));
    }
    if (m === 'POST' && p.endsWith('/ack')) {
      items.delete(p.split('/')[3]);
      return jsonResp(200, { burned: true });
    }
    return jsonResp(404, { error: 'ERR_NOT_FOUND', retryable: false });
  };

  return { fetchImpl, rooms, mailboxes, items, chunks, stats };
}

// ============================================================================
// 1. ST-P0-1: Mandatory Responder onSASConfirm in Flow 1B (mode=2)
// ============================================================================

test('ST-P0-1: Flow 1B mode=2 Responder fails closed (burning room) when onSASConfirm is missing or returns false', async () => {
  const relay = createStatefulMockRelay({ spoolEnabled: true });
  const relayCfg = { origin: 'https://sync.example.com:443', accessKey: 'K'.repeat(43) };
  const alice = new SyncClient({ relay: relayCfg, fetchImpl: relay.fetchImpl, label: 'Alice' });
  const bob = new SyncClient({ relay: relayCfg, fetchImpl: relay.fetchImpl, label: 'Bob' });

  // 1A. Missing onSASConfirm on acceptDeviceBind -> immediately burns room, issues 0 deposit tokens, saves 0 cards
  let room1;
  let offer1Ready;
  const offer1P = new Promise((r) => { offer1Ready = r; });
  const init1 = alice.startDeviceBind({
    mode: 2,
    preferPoll: true,
    onOfferReady: (o) => { room1 = o.roomId; offer1Ready(); },
    onSASInput: async () => '000000',
  });
  await offer1P;
  await assert.rejects(
    () => bob.acceptDeviceBind(room1, { preferPoll: true }),
    (e) => e instanceof SyncError && e.code === ErrorCode.ERR_SAS_MISMATCH,
  );
  await assert.rejects(init1, (e) => e instanceof SyncError && e.code === ErrorCode.ERR_ROOM_BURNED);
  assert.ok(relay.stats.burnedRooms.includes(room1));
  assert.equal(relay.stats.depositTokenPosts, 0);
  assert.equal((await bob.keyStore.listDevices({ includeRevoked: true })).length, 0);

  // 1B. Rejecting onSASConfirm: async () => false on acceptDeviceBind -> onSASDisplay fires first, then room burned!
  let room2;
  let offer2Ready;
  const offer2P = new Promise((r) => { offer2Ready = r; });
  let displayedSas = null;
  let sasDisplayedResolve;
  const sasDisplayedP = new Promise((r) => { sasDisplayedResolve = r; });

  const init2 = alice.startDeviceBind({
    mode: 2,
    preferPoll: true,
    onOfferReady: (o) => { room2 = o.roomId; offer2Ready(); },
    onSASInput: async () => await sasDisplayedP,
  });
  await offer2P;
  await assert.rejects(
    () => bob.acceptDeviceBind(room2, {
      preferPoll: true,
      onSASDisplay: ({ sas, formattedSas }) => {
        displayedSas = sas;
        assert.equal(formattedSas.length, 7);
        sasDisplayedResolve(sas);
      },
      onSASConfirm: async () => false,
    }),
    (e) => e instanceof SyncError && e.code === ErrorCode.ERR_SAS_MISMATCH,
  );
  await init2.catch(() => {});
  assert.equal(typeof displayedSas, 'string');
  assert.equal(displayedSas.length, 6);
  assert.ok(relay.stats.burnedRooms.includes(room2));
  assert.equal((await bob.keyStore.listDevices({ includeRevoked: true })).length, 0);

  // 1C. Rejecting onSASConfirm on receiveOneShot (mode=2) -> handler NEVER invoked, room burned!
  let room3;
  let offer3Ready;
  const offer3P = new Promise((r) => { offer3Ready = r; });
  let sas3Resolve;
  const sas3P = new Promise((r) => { sas3Resolve = r; });
  let handlerCalled = false;

  const send3 = alice.startOneShotSend(
    { schema: 'clip.v1', inlinePayload: { secret: 'mitm' } },
    {
      mode: 2,
      preferPoll: true,
      onOfferReady: (o) => { room3 = o.formattedRoomId; offer3Ready(); },
      onSASInput: async () => await sas3P,
    },
  );
  await offer3P;
  await assert.rejects(
    () => bob.receiveOneShot(
      room3,
      async () => { handlerCalled = true; },
      {
        preferPoll: true,
        onSASDisplay: ({ sas }) => sas3Resolve(sas),
        onSASConfirm: async () => false,
      },
    ),
    (e) => e instanceof SyncError && e.code === ErrorCode.ERR_SAS_MISMATCH,
  );
  await send3.catch(() => {});
  assert.equal(handlerCalled, false);

  // 1D. Positive onSASConfirm: async () => true on receiveOneShot (mode=2) -> succeeds!
  let room4;
  let offer4Ready;
  const offer4P = new Promise((r) => { offer4Ready = r; });
  let sas4Resolve;
  const sas4P = new Promise((r) => { sas4Resolve = r; });
  let deliveredText = null;

  const send4 = alice.startOneShotSend(
    { schema: 'clip.v1', inlinePayload: { text: 'verified-sas-oneshot' } },
    {
      mode: 2,
      preferPoll: true,
      onOfferReady: (o) => { room4 = o.formattedRoomId; offer4Ready(); },
      onSASInput: async () => await sas4P,
    },
  );
  await offer4P;
  const recv4 = bob.receiveOneShot(
    room4,
    async ({ manifest }) => { deliveredText = manifest.inline_payload.text; },
    {
      preferPoll: true,
      onSASDisplay: ({ sas }) => sas4Resolve(sas),
      onSASConfirm: async () => true,
    },
  );
  await Promise.all([send4, recv4]);
  assert.equal(deliveredText, 'verified-sas-oneshot');
});

// ============================================================================
// 2. ST-P0-2 & ST-P0-3: PartLayout Validation, sawFinal Hard-Stop & listInbox Cache Security
// ============================================================================

test('ST-P0-2 & ST-P0-3: PartLayout vs signed manifest.blobs.size, sawFinal post-final rejection & listInbox revocation/substitution', async () => {
  // 2A. Direct STREAM sawFinal hard-stop: block 0 (isFinal=true, 1B) followed by forged valid AEAD block 1 (isFinal=false, 64KiB)
  const msgId = randomBytes(16);
  const { encKey, noncePrefix } = await deriveBlobPartKeys(randomBytes(32), msgId, 1);
  const b0 = await sealStreamBlock(encKey, noncePrefix, msgId, 1, 0, true, new Uint8Array([0x42]));
  const b1 = await sealStreamBlock(encKey, noncePrefix, msgId, 1, 1, false, new Uint8Array(CHUNK_PLAINTEXT_MAX));
  await assert.rejects(
    () => decryptPartBytes(encKey, noncePrefix, msgId, 1, concatBytes(b0, b1), { expectedTotalBlocks: 1 }),
    (e) => e instanceof SyncError && e.code === ErrorCode.ERR_STREAM_TRUNCATED,
  );

  // 2B. Full Mode B flow: pair Alice & Bob, verify PartLayout tampering rejected with 0 blob GETs, and listInbox revocation evicts cache
  const relay = createStatefulMockRelay({ spoolEnabled: true, blocksPerChunk: 2 });
  const relayCfg = { origin: 'https://sync.example.com:443', accessKey: 'K'.repeat(43) };
  const alice = new SyncClient({ relay: relayCfg, fetchImpl: relay.fetchImpl, appId: 'com.notes', label: 'Alice' });
  const bob = new SyncClient({ relay: relayCfg, fetchImpl: relay.fetchImpl, appId: 'com.notes', label: 'Bob' });

  let pairUri;
  let offerReady;
  const offerP = new Promise((r) => { offerReady = r; });
  const bindA = alice.startDeviceBind({ mode: 1, preferPoll: true, onOfferReady: (o) => { pairUri = o.pairUri; offerReady(); } });
  await offerP;
  const [, cardAOnB] = await Promise.all([bindA, bob.acceptDeviceBind(pairUri, { preferPoll: true })]);
  const idB = await bob.getIdentity();

  const sent = await alice.sendToDevice(idB.deviceId, {
    schema: 'note.v1',
    inlinePayload: { secretNote: 'SUPER_SENSITIVE_PREVIEW_TEXT' },
    blobs: [blobFromBytes(new Uint8Array([1, 2, 3, 4, 5]), { role: 'att', name: 'tiny.bin' })],
  });

  // Inflate wire PartLayout total_bytes / chunk_count on relay -> fetchParcel MUST reject with 0 blob GETs!
  const itemRec = relay.items.get(sent.itemId);
  const origParts = structuredClone(itemRec.parts);
  itemRec.parts = [
    origParts[0],
    { part_id: 1, total_bytes: 999_999, chunk_count: 100 },
  ];
  relay.stats.blobGets = 0;
  await assert.rejects(
    () => bob.fetchParcel(sent.itemId, async () => {}),
    (e) => e instanceof SyncError && e.code === ErrorCode.ERR_MANIFEST_INVALID,
  );
  assert.equal(relay.stats.blobGets, 0, 'must reject forged PartLayout BEFORE downloading any blob chunks');
  itemRec.parts = origParts;

  // ST-P2-1: fetchParcel with mismatched appId must NOT download blobs or burn the item!
  await assert.rejects(
    () => bob.fetchParcel(sent.itemId, async () => {}, { appId: 'com.other.app' }),
    (e) => e instanceof SyncError && e.code === ErrorCode.ERR_INVALID_STATE,
  );
  assert.equal(relay.stats.blobGets, 0);
  assert.equal(relay.items.has(sent.itemId), true);

  // ST-P0-3: First listInbox caches manifest; revoking Alice MUST immediately hide cached item & evict cache!
  const inboxBefore = await bob.listInbox();
  assert.equal(inboxBefore.length, 1);
  assert.ok((await bob.keyStore.getCachedManifestPreview(sent.itemId)) !== null);

  await bob.revokeDevice(cardAOnB.device_id);
  const inboxAfterRevoke = await bob.listInbox();
  assert.equal(inboxAfterRevoke.length, 0, 'ST-P0-3: revoked sender preview must never be returned from cache');
  assert.equal(await bob.keyStore.getCachedManifestPreview(sent.itemId), null, 'revoked cache entry must be evicted');
});

// ============================================================================
// 3. ST-P1-1, ST-Opt-2 & ST-P2-2: Multi-Pin SPKI (1..8 pins) + Live TLS 1.3 Keep-Alive Pinning
// ============================================================================

test('ST-P1-1, ST-Opt-2 & ST-P2-2: Multi-pin SPKI URI round-trip & live Node TLS 1.3 rotation pin match', async () => {
  const p1 = 'A'.repeat(64);
  const p2 = 'b'.repeat(64);
  const key = 'K'.repeat(43);

  const relayUri = formatRelayURI({
    origin: 'https://127.0.0.1:54843',
    spkiPin: `  ${p1} , ${p2}  `,
    accessKey: key,
  });
  const parsed = parseRelayURI(relayUri);
  assert.deepEqual(parsed.spkiPins, ['a'.repeat(64), 'b'.repeat(64)]);
  assert.equal(parsed.spkiPin, 'a'.repeat(64));

  const pairUri = formatPairURI({
    roomId: 'K7M9P2XQ',
    mode: 2,
    purpose: 'pair',
    relayOrigin: 'https://127.0.0.1:54843',
    spkiPins: parsed.spkiPins,
  });
  const parsedPair = parsePairURI(pairUri);
  assert.deepEqual(parsedPair.spkiPins, ['a'.repeat(64), 'b'.repeat(64)]);
  assert.equal(parsedPair.spkiPin, 'a'.repeat(64));

  // Reject >8 pins and empty trailing comma
  const ninePins = Array.from({ length: 9 }, (_, i) => i.toString(16).repeat(64)).join(',');
  assert.throws(
    () => parseRelayURI(`synctool://relay?v=1&u=https%3A%2F%2F127.0.0.1%3A54843&pin=${ninePins}#k=${key}`),
    (e) => e instanceof SyncError && e.code === ErrorCode.ERR_URI_INVALID,
  );
  assert.throws(
    () => parseRelayURI(`synctool://relay?v=1&u=https%3A%2F%2F127.0.0.1%3A54843&pin=${'a'.repeat(64)},#k=${key}`),
    (e) => e instanceof SyncError && e.code === ErrorCode.ERR_URI_INVALID,
  );

  // Pure Node.js ASN.1 DER self-signed ECDSA P-256 X.509 v3 certificate generator (zero external openssl needed!)
  function derLen(len) {
    if (len < 0x80) return Buffer.from([len]);
    const hex = len.toString(16);
    const bytes = Buffer.from(hex.length % 2 ? '0' + hex : hex, 'hex');
    return Buffer.concat([Buffer.from([0x80 | bytes.length]), bytes]);
  }
  const derTlv = (tag, body) => Buffer.concat([Buffer.from([tag]), derLen(body.length), body]);
  const derSeq = (...items) => derTlv(0x30, Buffer.concat(items));
  const derSet = (...items) => derTlv(0x31, Buffer.concat(items));
  const fmtUtc = (d) => d.toISOString().replace(/[-:T]/g, '').slice(2, 14) + 'Z';

  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const spkiDer = publicKey.export({ type: 'spki', format: 'der' });
  const keyPem = privateKey.export({ type: 'pkcs8', format: 'pem' });
  // OID 1.2.840.10045.4.3.2 (ecdsa-with-SHA256) & OID 2.5.4.3 (commonName)
  const algId = derSeq(Buffer.from('06082a8648ce3d040302', 'hex'));
  const cnAttr = derSeq(derSet(derSeq(Buffer.from('0603550403', 'hex'), derTlv(0x0c, Buffer.from('127.0.0.1')))));
  const validity = derSeq(
    derTlv(0x17, Buffer.from(fmtUtc(new Date(Date.now() - 3600_000)))),
    derTlv(0x17, Buffer.from(fmtUtc(new Date(Date.now() + 86400_000 * 30)))),
  );
  const serial = derTlv(0x02, Buffer.concat([Buffer.from([0x01]), crypto.randomBytes(8)]));
  const tbs = derSeq(
    derTlv(0xa0, derTlv(0x02, Buffer.from([0x02]))), // v3
    serial,
    algId,
    cnAttr,
    validity,
    cnAttr,
    spkiDer,
  );
  const sigDer = crypto.sign('sha256', tbs, privateKey);
  const certDer = derSeq(tbs, algId, derTlv(0x03, Buffer.concat([Buffer.from([0x00]), sigDer])));
  const certPem = `-----BEGIN CERTIFICATE-----\n${certDer.toString('base64').match(/.{1,64}/g).join('\n')}\n-----END CERTIFICATE-----\n`;

  const actualPin = crypto.createHash('sha256').update(spkiDer).digest('hex');
  let tlsConns = 0;
  const srv = https.createServer({ key: keyPem, cert: certPem, minVersion: 'TLSv1.3' }, (_req, res) => {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ proto_v: 1, server_ts: Math.floor(Date.now() / 1000), profile: 'standard', spool_backend: 'disk', cert_expires_at: 0, cert_rotate_recommended: false }));
  });
  srv.on('secureConnection', () => { tlsConns++; });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const port = srv.address().port;
  const dualClient = new SyncClient({
    relay: {
      origin: `https://127.0.0.1:${port}`,
      spkiPins: ['0'.repeat(64), actualPin], // 2nd staged pin matches!
      accessKey: key,
    },
  });
  const wrongPinClient = new SyncClient({
    relay: {
      origin: `https://127.0.0.1:${port}`,
      spkiPins: ['0'.repeat(64), 'f'.repeat(64)],
      accessKey: key,
    },
  });
  try {
    await dualClient.ping();
    await dualClient.ping();
    assert.equal(tlsConns, 1, 'ST-P2-2: keepAlive pinnedAgent should reuse verified TLS 1.3 socket across requests');
    await assert.rejects(
      () => wrongPinClient.ping(),
      (e) => e instanceof SyncError && e.code === ErrorCode.ERR_TLS_PIN_MISMATCH,
    );
  } finally {
    await dualClient.close();
    await wrongPinClient.close();
    srv.closeAllConnections?.();
    await new Promise((r) => srv.close(r));
  }
});

// ============================================================================
// 4. ST-P1-6, ST-P1-7 & ST-P1-8: Clock Skew Scoping, 0-RTT Freshness/InFlight & 2-Phase Revoke/Re-Pair
// ============================================================================

test('ST-P1-6, ST-P1-7 & ST-P1-8: Clock skew scoping/clamping, 0-RTT freshness + inFlightMsgIds, re-pair cleanup & offline 2-phase revoke', async () => {
  // 4A. ST-P1-6: Malicious relay returning 409 server_ts = year 2200 is clamped to ±365d and NEVER taints manifest.created_at!
  let firstCall = true;
  const localBefore = Math.floor(Date.now() / 1000);
  const relay = createStatefulMockRelay({ spoolEnabled: true });
  const wrappedFetch = async (urlStr, init) => {
    if (firstCall) {
      firstCall = false;
      return jsonResp(409, { error: 'ERR_CLOCK_SKEW', server_ts: localBefore + 500 * 86400 }); // +500d > 365d!
    }
    return relay.fetchImpl(urlStr, init);
  };
  const relayCfg = { origin: 'https://sync.example.com:443', accessKey: 'K'.repeat(43) };
  const alice = new SyncClient({ relay: relayCfg, fetchImpl: wrappedFetch, label: 'Alice' });
  const bob = new SyncClient({ relay: relayCfg, fetchImpl: relay.fetchImpl, label: 'Bob' });

  const pingRes = await alice.ping();
  assert.equal(pingRes.clock_offset_sec, 365 * 86400, 'clock offset must clamp to +365d');

  // Pair Alice & Bob twice -> 2nd re-pair must delete Bob's old deposit_token for Alice!
  for (let round = 0; round < 2; round++) {
    let uri;
    let ready;
    const p = new Promise((r) => { ready = r; });
    const aP = alice.startDeviceBind({ mode: 1, preferPoll: true, onOfferReady: (o) => { uri = o.pairUri; ready(); } });
    await p;
    await Promise.all([aP, bob.acceptDeviceBind(uri, { preferPoll: true })]);
  }
  assert.equal(relay.stats.depositTokenDeletes.length, 2, 're-pairing same peer must delete superseded inbound deposit_tokens on both sides');

  const idB = await bob.getIdentity();
  const idA = await alice.getIdentity();
  // Verify Alice's signed DeviceCard.issued_at on Bob is near real local clock, NOT +365d!
  const cardAOnB = await bob.keyStore.getDevice(idA.deviceId);
  assert.ok(Math.abs(cardAOnB.issued_at - localBefore) < 30, `DeviceCard.issued_at tainted by clockOffsetSec: ${cardAOnB.issued_at}`);

  // Verify Alice's signed manifest.created_at is near real local clock, NOT +365d!
  const sent = await alice.sendToDevice(idB.deviceId, { schema: 'note.v1', inlinePayload: { ok: 1 } });
  let gotCreatedAt = 0;
  // ST-P1-7: Test concurrent fetchParcel TOCTOU protection via inFlightMsgIds!
  const [r1, r2] = await Promise.allSettled([
    bob.fetchParcel(sent.itemId, async ({ manifest }) => {
      await new Promise((r) => setTimeout(r, 40));
      gotCreatedAt = manifest.created_at;
    }),
    bob.fetchParcel(sent.itemId, async () => {}),
  ]);
  const fulfilled = [r1, r2].filter((x) => x.status === 'fulfilled');
  const rejected = [r1, r2].filter((x) => x.status === 'rejected');
  assert.equal(fulfilled.length, 1);
  assert.equal(rejected.length, 1);
  assert.equal(rejected[0].reason.code, ErrorCode.ERR_MSG_REPLAY_DETECTED);
  assert.ok(Math.abs(gotCreatedAt - localBefore) < 30, 'manifest.created_at must never be tainted by clockOffsetSec');

  // 4B. ST-P1-7: Expired (>30d old) and future (>+600s) SealedHeaders rejected
  const manifestSha = await sha256(utf8Encode('{"x":1}'));
  const oldSealed = await sealPaired0RTTHeader({
    msgId: randomBytes(16),
    senderSignSeed: idA.signSeed,
    senderDeviceIdRaw: idA.deviceIdRaw,
    recipientDeviceIdRaw: idB.deviceIdRaw,
    recipientKemPk: idB.kemPk,
    createdAt: localBefore - 31 * 86400,
    manifestSha256: manifestSha,
  });
  await assert.rejects(
    () => openPaired0RTTHeader({
      sealedHeader: oldSealed.sealedHeaderB64u,
      recipientKemSk: idB.kemSk,
      recipientDeviceIdRaw: idB.deviceIdRaw,
      nowSec: localBefore,
      lookupSenderCard: () => cardAOnB,
    }),
    (e) => e instanceof SyncError && e.code === ErrorCode.ERR_MSG_REPLAY_DETECTED,
  );

  // 4C. ST-P1-8: Offline 2-phase revokeDevice blocks local trust immediately and flushes relay DELETE on syncMailbox()
  let relayOffline = true;
  const offlineFlakyBob = new SyncClient({
    relay: relayCfg,
    keyStore: bob.keyStore,
    fetchImpl: async (u, i) => {
      if (relayOffline) throw new Error('network down');
      return relay.fetchImpl(u, i);
    },
  });
  const deletesBefore = relay.stats.depositTokenDeletes.length;
  await assert.rejects(
    () => offlineFlakyBob.revokeDevice(idA.deviceId),
    (e) => e instanceof SyncError && e.code === ErrorCode.ERR_RELAY_UNREACHABLE,
  );
  // Immediately untrusted locally even though relay DELETE failed!
  assert.equal((await bob.keyStore.listDevices()).length, 0);
  const pendingCard = await bob.keyStore.getDevice(idA.deviceId);
  assert.equal(pendingCard.revoked, true);
  assert.equal(pendingCard.pending_token_delete, true);

  // Come back online -> syncMailbox() flushes pending relay token DELETE and removes tombstoned card!
  relayOffline = false;
  await offlineFlakyBob.syncMailbox();
  assert.equal(relay.stats.depositTokenDeletes.length, deletesBefore + 1);
  assert.equal(await bob.keyStore.getDevice(idA.deviceId), null);
});

// ============================================================================
// 5. ST-P1-9, ST-P1-10, ST-P1-11, ST-P1-12 & ST-P1-13
// ============================================================================

test('ST-P1-9..13: watchInbox TLS rethrow + SSE idle timeout, spool abort DELETE, Node file helpers + resumePrefixReaders, localMetaKey cache & client.close()', async () => {
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'synctool-v030-'));
  try {
    // 5A. ST-P1-9: watchInbox immediately rethrows ERR_TLS_PIN_MISMATCH without poll fallback
    const pinFailClient = new SyncClient({
      relay: { origin: 'https://sync.example.com:443', accessKey: 'K'.repeat(43) },
      fetchImpl: async () => { throw new SyncError(ErrorCode.ERR_TLS_PIN_MISMATCH, 'pin mismatch'); },
    });
    await assert.rejects(
      () => pinFailClient.watchInbox({ onItem: () => {} }),
      (e) => e instanceof SyncError && e.code === ErrorCode.ERR_TLS_PIN_MISMATCH,
    );

    // 5B. ST-P1-9: iterateSSE enforces idle read timeout on stalled half-open stream
    const stalledStream = new ReadableStream({ start() { /* never pushes */ } });
    await assert.rejects(
      async () => {
        for await (const _ev of iterateSSE(stalledStream, undefined, { idleTimeoutMs: 40 })) {
          // unreachable
        }
      },
      (e) => e instanceof SyncError && e.code === ErrorCode.ERR_RELAY_UNREACHABLE,
    );

    // 5C. ST-P1-10: Aborted Mode B upload issues best-effort DELETE /v1/spool/{id}
    const relay = createStatefulMockRelay({ spoolEnabled: true, blocksPerChunk: 1 });
    const relayCfg = { origin: 'https://sync.example.com:443', accessKey: 'K'.repeat(43) };
    const ksA = new NodeFileKeyStore(path.join(tmpDir, 'ks-a'));
    const ksB = new NodeFileKeyStore(path.join(tmpDir, 'ks-b'));

    // ST-P1-13: Transient keystore error must NOT permanently poison client.getIdentity()
    let failOnce = true;
    const origLoad = ksA.loadOrCreateMasterSeed.bind(ksA);
    ksA.loadOrCreateMasterSeed = async () => {
      if (failOnce) {
        failOnce = false;
        throw new SyncError(ErrorCode.ERR_KEYSTORE_ERROR, 'transient EBUSY');
      }
      return origLoad();
    };
    const alice = new SyncClient({ relay: relayCfg, keyStore: ksA, fetchImpl: relay.fetchImpl, label: 'Alice' });
    const bob = new SyncClient({ relay: relayCfg, keyStore: ksB, fetchImpl: relay.fetchImpl, label: 'Bob' });
    await assert.rejects(() => alice.getIdentity(), (e) => e.code === ErrorCode.ERR_KEYSTORE_ERROR);
    const idA = await alice.getIdentity(); // Second attempt succeeds cleanly!
    assert.equal(idA.deviceId.length, 32);

    // Pair Alice & Bob
    let uri;
    let ready;
    const p = new Promise((r) => { ready = r; });
    const bindP = alice.initiateDeviceBind({ mode: 1, preferPoll: true, onOfferReady: (o) => { uri = o.pairUri; ready(); } });
    await p;
    await Promise.all([bindP, bob.acceptDeviceBind(uri, { preferPoll: true })]);
    const idB = await bob.getIdentity();

    // Abort mid-upload after chunk 0 -> verify DELETE /v1/spool/{itemId} ran!
    const abortCtrl = new AbortController();
    const twoBlockData = randomBytes(100_000);
    await assert.rejects(
      () => alice.sendToDevice(
        idB.deviceId,
        { schema: 'file.v1', blobs: [blobFromBytes(twoBlockData, { role: 'file', name: 'abort.bin' })] },
        {
          signal: abortCtrl.signal,
          onProgress: (ev) => {
            if (ev.part_id === 0) abortCtrl.abort();
          },
        },
      ),
      (e) => e instanceof SyncError && e.code === ErrorCode.ERR_CANCELLED,
    );
    assert.equal(relay.stats.spoolDeletes.length, 1, 'aborted upload must DELETE uncommitted spool item');

    // 5D. ST-P1-11 & ST-P1-13: blobFromNodeFile + createNodeFileBlobSink + maxInMemoryBlobBytes + resumePrefixReaders + localMetaKey sealing!
    const srcFilePath = path.join(tmpDir, 'source_video.mp4');
    const videoData = randomBytes(150_000); // 3 blocks
    await fs.writeFile(srcFilePath, videoData);
    const outDir = path.join(tmpDir, 'out');
    await fs.mkdir(outDir, { recursive: true });
    await fs.writeFile(path.join(outDir, 'source_video.mp4'), 'DO_NOT_OVERWRITE');

    const sent = await alice.sendToDevice(idB.deviceId, {
      schema: 'vault.v1',
      inlinePayload: { topSecretSshKey: 'PRIVATE_KEY_CANARY_DO_NOT_STORE_PLAINTEXT' },
      blobs: [await blobFromNodeFile(srcFilePath, { role: 'video', mime: 'video/mp4' })],
    });

    // List inbox on Bob -> verify `keystore.json` on disk encrypts manifest_cache with localMetaKey!
    const list = await bob.listInbox();
    assert.equal(list.length, 1);
    const rawKsJson = await fs.readFile(path.join(tmpDir, 'ks-b', 'keystore.json'), 'utf8');
    assert.equal(rawKsJson.includes('PRIVATE_KEY_CANARY_DO_NOT_STORE_PLAINTEXT'), false, 'manifest_cache on disk must be encrypted with localMetaKey!');
    assert.ok(rawKsJson.includes('sealed_preview_v1'));

    // maxInMemoryBlobBytes guard rejects when createBlobSink is omitted
    await assert.rejects(
      () => bob.fetchParcel(sent.itemId, async () => {}, { maxInMemoryBlobBytes: 1024 }),
      (e) => e instanceof SyncError && e.code === ErrorCode.ERR_STORAGE_IO,
    );

    // Resumed fetchParcel with streaming resumePrefixReaders (zero full-prefix RAM buffer) + createNodeFileBlobSink!
    const prefixLen = CHUNK_PLAINTEXT_MAX; // 1 block = chunk 0 under blocksPerChunk=1
    let sinkOut = null;
    const progressEvents = [];
    await bob.fetchParcel(
      sent.itemId,
      async ({ blobs }) => {
        sinkOut = blobs[0].sinkResult;
      },
      {
        blocksPerChunk: 1,
        resumeCheckpoints: new Map([[1, 1]]),
        resumePrefixReaders: new Map([
          [1, async (off, len) => videoData.subarray(off, off + len)],
        ]),
        createBlobSink: async (desc) => {
          const inner = await createNodeFileBlobSink(outDir)(desc);
          // Pre-seed chunk 0 into sink as if resuming a partial file
          await inner.write(videoData.subarray(0, prefixLen));
          return inner;
        },
        onProgress: (ev) => progressEvents.push(ev),
      },
    );
    assert.equal(sinkOut.safeName, 'source_video_1.mp4', 'must not overwrite existing source_video.mp4');
    assert.deepEqual(new Uint8Array(await fs.readFile(sinkOut.path)), videoData);
    assert.equal(await fs.readFile(path.join(outDir, 'source_video.mp4'), 'utf8'), 'DO_NOT_OVERWRITE');
    assert.ok(progressEvents.some((e) => e.speed_bps > 0));

    // Go-compatible keystore.json field aliases (`endpoint` + `spki_sha256`)
    const goRelayDir = path.join(tmpDir, 'ks-go-compat');
    await fs.mkdir(goRelayDir, { recursive: true });
    const goRelayId = await deriveRelayId('https://127.0.0.1:54843');
    await fs.writeFile(
      path.join(goRelayDir, 'keystore.json'),
      JSON.stringify({
        version: 1,
        master_seed_b64u: bytesToB64u(randomBytes(32)),
        local_label: 'Go-CLI',
        relays: {
          [goRelayId]: {
            relay_id: goRelayId,
            alias: 'prod',
            endpoint: 'https://127.0.0.1:54843',
            access_key: 'G'.repeat(43),
            tls_mode: 'spki_pin',
            spki_sha256: `${'a'.repeat(64)},${'b'.repeat(64)}`,
            is_default: true,
          },
        },
      }),
    );
    const goCompatKs = new NodeFileKeyStore(goRelayDir);
    const defProf = await goCompatKs.getDefaultRelayProfile();
    assert.equal(defProf.origin, 'https://127.0.0.1:54843');
    assert.equal(defProf.endpoint, 'https://127.0.0.1:54843');
    assert.deepEqual(defProf.spki_pins, ['a'.repeat(64), 'b'.repeat(64)]);
    assert.equal(defProf.spki_pin, 'a'.repeat(64));

    // client.close() zeroes derived keys and rejects subsequent calls with ERR_CANCELLED
    await alice.close();
    assert.equal(idA.signSeed.every((b) => b === 0), true, 'close() must wipe signSeed in RAM');
    assert.equal(idA.kemSk.every((b) => b === 0), true, 'close() must wipe kemSk in RAM');
    await assert.rejects(() => alice.ping(), (e) => e instanceof SyncError && e.code === ErrorCode.ERR_CANCELLED);
    await bob.close();
  } finally {
    await fs.rm(tmpDir, { recursive: true, force: true });
  }
});

// ============================================================================
// 6. ST-P2-10,11,15 & ST-Opt-1,6: Canonical Origin, Crockford ASCII, Bounds, Ed25519 Torsion/S+L & WebCrypto Wrap
// ============================================================================

test('ST-P2-10,11,15 & ST-Opt-1,6: Canonical origin parity, Crockford ASCII, uint64 bounds, non-destructive SHA-256 & Ed25519 torsion/S+L', async () => {
  // 6A. Go/TS CanonicalRelayOrigin parity & zero secret leak on malformed inputs
  assert.equal(canonicalizeRelayOrigin('https://relay.example.com:0443').origin, 'https://relay.example.com:443');
  assert.equal(canonicalizeRelayOrigin('http://127.0.0.2:0090/').origin, 'http://127.0.0.2:90');
  assert.equal(canonicalizeRelayOrigin('http://[::ffff:127.0.0.1]:8080').origin, 'http://[::ffff:127.0.0.1]:8080');
  assert.equal(canonicalizeRelayOrigin('https://[::ffff:1.2.3.4]:8443').origin, 'https://[::ffff:1.2.3.4]:8443');
  assert.equal(isLoopbackHost('127.0.0.2'), true);
  assert.equal(isLoopbackHost('[::ffff:127.0.0.1]'), true);

  for (const bad of [
    'https://admin:SUPER_SECRET_PASS@relay.example.com:443',
    'https://relay.example.com:',
    'https://relay.example.com?',
    'https://relay\texample.com:443',
    'https://[fe80::1%25eth0]:443',
    'ht!tp://relay.example.com#k=SUPER_SECRET_KEY',
  ]) {
    assert.throws(
      () => canonicalizeRelayOrigin(bad),
      (e) => e instanceof SyncError && e.code === ErrorCode.ERR_URI_INVALID && !e.message.includes('SUPER_SECRET'),
    );
  }

  // Secret redaction on multi-param fragment & accidental query secret
  assert.equal(redactMessage('err #s=SEC_ONE&k=SEC_TWO').includes('SEC_TWO'), false);
  assert.equal(redactMessage('bad https://x.test?k=SEC_QUERY').includes('SEC_QUERY'), false);
  assert.equal(sanitizeFileName('CONIN$.txt'), '_CONIN$.txt');
  assert.equal(sanitizeFileName('CONOUT$'), '_CONOUT$');

  // 6B. Crockford strict ASCII pre-check (rejects Unicode 'ﬁ', 'ſ', 'K')
  for (const unicodeRoom of ['K7M9P2\ufb01', 'K7M9P2X\u017f', 'K7M9P2X\u212a']) {
    assert.throws(() => normalizeRoomId(unicodeRoom));
  }

  // 6C. readU32be / readU64be subarray bounds & MAX_SAFE_INTEGER guard + 32B handshake length checks
  const sub = new Uint8Array(16).subarray(4, 10); // 6 bytes
  assert.throws(() => readU32be(sub, 3), RangeError);
  assert.throws(() => readU64be(sub, 0), RangeError);
  const maxU64 = new Uint8Array(8).fill(0xff);
  assert.throws(() => readU64be(maxU64, 0), RangeError);
  assert.throws(() => u64be(Number.MAX_SAFE_INTEGER + 1), RangeError);

  await assert.rejects(
    () => computeCommitA({ purpose: 'pair', roomId: 'K7M9P2XQ', eA: new Uint8Array(32), nA: new Uint8Array(0) }),
    (e) => e instanceof SyncError && e.code === ErrorCode.ERR_CRYPTO_HANDSHAKE_FAILED,
  );
  await assert.rejects(
    () => computeQrOobHandshake({ purpose: 'pair', roomId: 'K7M9P2XQ', shared: randomBytes(32), oobSecret: randomBytes(16), eA: randomBytes(31), nA: randomBytes(32), eB: randomBytes(32), nB: randomBytes(32) }),
    (e) => e instanceof SyncError && e.code === ErrorCode.ERR_CRYPTO_HANDSHAKE_FAILED,
  );
  await assert.rejects(
    () => computeCommitSasHandshake({ purpose: 'pair', roomId: 'K7M9P2XQ', shared: randomBytes(32), commitA: randomBytes(16), eA: randomBytes(32), nA: randomBytes(32), eB: randomBytes(32), nB: randomBytes(32) }),
    (e) => e instanceof SyncError && e.code === ErrorCode.ERR_CRYPTO_HANDSHAKE_FAILED,
  );
  await assert.rejects(
    () => openPipeCtrlFrame(randomBytes(32), randomBytes(7), randomBytes(32), { ctrl_seq: 0x1_0000_0000, ct: 'AAAA' }),
    (e) => e instanceof SyncError && e.code === ErrorCode.ERR_CRYPTO_DECRYPT_FAILED,
  );

  // 6D. Non-destructive StreamingSha256.digest()
  const sh = new StreamingSha256();
  sh.update(utf8Encode('hello '));
  const mid1 = sh.digestHex();
  const mid2 = sh.digestHex();
  assert.equal(mid1, mid2, 'calling digestHex() twice must return identical digest');
  sh.update(utf8Encode('world'));
  assert.equal(sh.digestHex(), bytesToHex(await sha256(utf8Encode('hello world'))));

  // 6E. MemoryKeyStore lowercase & !revoked parity
  const mks = new MemoryKeyStore();
  await mks.putDevice({ device_id: 'ABCDEF0123456789ABCDEF0123456789', label: 'Dev', paired_at: 1, revoked: true });
  assert.equal((await mks.listDevices()).length, 0);
  assert.equal((await mks.listDevices({ includeRevoked: true })).length, 1);
  assert.ok((await mks.getDevice('abcdef0123456789abcdef0123456789')) !== null);

  // 6F. Ed25519 small-order torsion PK rejection & S + L malleability rejection (even under custom ZIP-215 provider!)
  const torsionHexes = [
    '0000000000000000000000000000000000000000000000000000000000000000',
    '0100000000000000000000000000000000000000000000000000000000000000',
    'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
    '0000000000000000000000000000000000000000000000000000000000000080',
    '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05',
    '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85',
    'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a',
    'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa',
    'edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f', // y == p (non-canonical)
  ];
  for (const th of torsionHexes) {
    const pk = hexToBytes(th);
    assert.equal(isSmallOrderEd25519PublicKey(pk), true, `expected torsion/non-canonical PK ${th} to be flagged`);
    assert.equal(await ed25519Verify(pk, utf8Encode('msg'), new Uint8Array(64)), false);
  }

  const kp = await ed25519KeyPairFromSeed(randomBytes(32));
  const validSig = await ed25519Sign(kp.seed, utf8Encode('canonical'));
  // Construct malleable S + L
  const orderL = 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3edn;
  let sBig = 0n;
  for (let i = 31; i >= 0; i--) sBig = (sBig << 8n) | BigInt(validSig[32 + i]);
  let sPlusL = sBig + orderL;
  const malSig = new Uint8Array(validSig);
  for (let i = 0; i < 32; i++) {
    malSig[32 + i] = Number(sPlusL & 0xffn);
    sPlusL >>= 8n;
  }
  try {
    // Even if custom provider naively returns true (like ZIP-215), ed25519Verify MUST reject S >= L & torsion PKs!
    setCryptoProvider({ ed25519Verify: () => true });
    assert.equal(await ed25519Verify(kp.publicKey, utf8Encode('canonical'), malSig), false);
    assert.equal(await ed25519Verify(hexToBytes(torsionHexes[1]), utf8Encode('canonical'), validSig), false);
  } finally {
    setCryptoProvider(null);
  }

  // ST-P1-12: Custom provider throwing DOMException-like error is wrapped in SyncError(ERR_CRYPTO_HANDSHAKE_FAILED)
  try {
    setCryptoProvider({
      ed25519PublicKeyFromSeed: () => { throw new DOMException('Ed25519 unsupported', 'NotSupportedError'); },
    });
    await assert.rejects(
      () => ed25519KeyPairFromSeed(randomBytes(32)),
      (e) => e instanceof SyncError && e.code === ErrorCode.ERR_CRYPTO_HANDSHAKE_FAILED,
    );
  } finally {
    setCryptoProvider(null);
  }

  // Uppercase device_id rejected in verifyDeviceCard
  const id = await deriveDeviceIdentity(randomBytes(32));
  const cSig = await signDeviceCard(id.signSeed, id.signPk, id.kemPk, 1700000000);
  assert.equal(
    await verifyDeviceCard({
      device_id: id.deviceId.toUpperCase(),
      sign_pk: bytesToB64u(id.signPk),
      kem_pk: bytesToB64u(id.kemPk),
      issued_at: 1700000000,
      card_sig: bytesToB64u(cSig),
    }),
    false,
  );
});
