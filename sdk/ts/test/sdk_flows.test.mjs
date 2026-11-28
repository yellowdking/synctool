import test from 'node:test';
import assert from 'node:assert/strict';

import {
  CHUNK_CIPHERTEXT_MAX,
  CHUNK_PLAINTEXT_MAX,
  ErrorCode,
  MemoryKeyStore,
  SyncClient,
  SyncError,
  blobFromBytes,
  bytesToB64u,
  bytesToHex,
  randomBytes,
  signDeviceCard,
  utf8Encode,
} from '../src/index.js';

// ============================================================================
// 5. SyncClient Logic Tests (Clock Skew Auto-Retry, Mode B Spool, Cache & Revoke)
// ============================================================================

test('SyncClient handles 409 ERR_CLOCK_SKEW auto-retry, cert expiry event, Mode B two-phase pull + cache + ACK burn', async () => {
  const accessKey = 'K'.repeat(43);
  const relayOrigin = 'https://sync.example.com:443';
  const serverNow = Math.floor(Date.now() / 1000) - 3600;
  let skewTriggered = false;
  let part0GetCount = 0;

  // Minimal stateful mock relay implementing ping, caps, mailboxes, spool & 409 clock skew
  const mailboxes = new Map();
  const items = new Map();
  const chunks = new Map();

  const mockFetch = async (urlStr, init) => {
    const u = new URL(urlStr);
    const path = u.pathname;
    const method = init.method || 'GET';
    const ts = Number(init.headers['X-Sync-TS']);

    if (Math.abs(ts - serverNow) > 60) {
      skewTriggered = true;
      return makeResponse(409, { error: 'ERR_CLOCK_SKEW', server_ts: serverNow, max_skew_sec: 60 });
    }

    if (method === 'GET' && path === '/v1/ping') {
      return makeResponse(200, {
        proto_v: 1,
        server_ts: serverNow,
        profile: 'standard',
        spool_backend: 'disk',
        cert_expires_at: serverNow + 10 * 86400, // 10 days -> warning
        cert_rotate_recommended: true,
      });
    }
    if (method === 'GET' && path === '/v1/caps') {
      return makeResponse(200, {
        proto_v: 1,
        profile: 'nano',
        server_ts: serverNow,
        cert_expires_at: 0,
        cert_rotate_recommended: false,
        crypto_plaintext_block_bytes: 65536,
        crypto_block_bytes: 65552,
        streaming: { enabled: true, blocks_per_chunk: 2, max_transport_chunk_bytes: 2 * CHUNK_CIPHERTEXT_MAX, rendezvous_timeout_sec: 30, room_ttl_max_sec: 600 },
        spool: { enabled: true, backend: 'memory', max_item_bytes: 4 * 1024 * 1024, max_mailbox_bytes: 8 * 1024 * 1024, max_total_bytes: 16 * 1024 * 1024, max_items_per_mailbox: 16, default_ttl_sec: 1800, max_ttl_sec: 7200, uncommitted_ttl_sec: 1800, max_manifest_downloads: 16, max_downloads_per_chunk: 3, max_deposit_tokens_per_mailbox: 16 },
      });
    }
    if (method === 'PUT' && path.startsWith('/v1/mailboxes/')) {
      const mbId = path.split('/')[3];
      mailboxes.set(mbId, { tokens: new Map() });
      return makeResponse(200, { mailbox_id: mbId, registered: true, deposit_token_count: 0 });
    }
    if (method === 'POST' && path.endsWith('/deposit-tokens')) {
      const mbId = path.split('/')[3];
      const body = JSON.parse(new TextDecoder().decode(init.body));
      mailboxes.get(mbId).tokens.set(body.token_id, body.token_hash_hex);
      return makeResponse(201, { token_id: body.token_id, active_count: mailboxes.get(mbId).tokens.size });
    }
    if (method === 'DELETE' && path.includes('/deposit-tokens/')) {
      const parts = path.split('/');
      const mbId = parts[3];
      const tokId = parts[5];
      mailboxes.get(mbId).tokens.delete(tokId);
      return makeResponse(200, { token_id: tokId, revoked: true, active_count: mailboxes.get(mbId).tokens.size });
    }
    if (method === 'POST' && path === '/v1/spool/init') {
      const body = JSON.parse(new TextDecoder().decode(init.body));
      const itemId = 'itm_' + bytesToHex(randomBytes(16));
      items.set(itemId, { ...body, item_id: itemId, created_at: serverNow, expires_at: serverNow + 1800, committed: false });
      return makeResponse(201, { item_id: itemId, upload_token: 'U'.repeat(43), max_transport_chunk_bytes: 2 * CHUNK_CIPHERTEXT_MAX, upload_expires_at: serverNow + 1800, expires_at: serverNow + 1800 });
    }
    if (method === 'PUT' && path.startsWith('/v1/spool/')) {
      const seg = path.split('/'); // /v1/spool/{id}/parts/{pid}/chunks/{tx}
      const key = `${seg[3]}:${seg[5]}:${seg[7]}`;
      chunks.set(key, new Uint8Array(init.body));
      return makeResponse(200, { item_id: seg[3], part_id: Number(seg[5]), tx_idx: Number(seg[7]), received_bytes: init.body.byteLength });
    }
    if (method === 'POST' && path.endsWith('/commit')) {
      const itemId = path.split('/')[3];
      const it = items.get(itemId);
      it.committed = true;
      return makeResponse(200, { item_id: itemId, committed: true, expires_at: it.expires_at });
    }
    if (method === 'GET' && path.endsWith('/items')) {
      const mbId = path.split('/')[3];
      const list = Array.from(items.values())
        .filter((it) => it.mailbox_id === mbId && it.committed)
        .map((it) => ({ item_id: it.item_id, created_at: it.created_at, expires_at: it.expires_at, total_bytes: it.declared_total_bytes, sealed_header: it.sealed_header, parts: it.parts }));
      return makeResponse(200, { mailbox_id: mbId, used_bytes: 0, quota_bytes: 8 * 1024 * 1024, items: list });
    }
    if (method === 'GET' && path.startsWith('/v1/spool/')) {
      const seg = path.split('/');
      if (Number(seg[5]) === 0) part0GetCount++;
      const data = chunks.get(`${seg[3]}:${seg[5]}:${seg[7]}`);
      return makeBinaryResponse(200, data);
    }
    if (method === 'POST' && path.endsWith('/ack')) {
      const itemId = path.split('/')[3];
      items.delete(itemId);
      return makeResponse(200, { item_id: itemId, burned: true });
    }
    return makeResponse(404, { error: 'ERR_NOT_FOUND', message: 'not found', retryable: false });
  };

  let certEvent = null;
  const aliceStore = new MemoryKeyStore();
  const bobStore = new MemoryKeyStore();
  const alice = new SyncClient({
    relay: { origin: relayOrigin, accessKey },
    keyStore: aliceStore,
    appId: 'com.yellowdking.notes',
    label: 'Alice Phone',
    fetchImpl: mockFetch,
    onCertExpiring: (ev) => { certEvent = ev; },
    clockOffsetSec: 500, // Deliberately skewed to force 409 ERR_CLOCK_SKEW!
  });
  const bob = new SyncClient({
    relay: { origin: relayOrigin, accessKey },
    keyStore: bobStore,
    appId: 'com.yellowdking.notes',
    label: 'Bob Desktop',
    fetchImpl: mockFetch,
  });

  // 1. Ping triggers 409 ERR_CLOCK_SKEW -> auto-calibrates and succeeds on retry, firing cert expiring warning
  const pingRes = await alice.ping();
  assert.equal(skewTriggered, true);
  assert.equal(pingRes.server_ts, serverNow);
  assert.ok(certEvent && certEvent.days_remaining === 10 && certEvent.severity === 'warning');

  // 2. Pair Alice & Bob cards directly into each keystore
  await bob.ping();
  await bob.registerMailbox();
  const idA = await alice.getIdentity();
  const idB = await bob.getIdentity();
  const mbB = await bob.getMailboxIdentity();
  const depTok = 'D'.repeat(43);

  await aliceStore.putDevice({
    device_id: idB.deviceId,
    label: 'Bob Desktop',
    sign_pk: bytesToB64u(idB.signPk),
    kem_pk: bytesToB64u(idB.kemPk),
    issued_at: serverNow,
    card_sig: bytesToB64u(await signDeviceCard(idB.signSeed, idB.signPk, idB.kemPk, serverNow)),
    relay_origin: relayOrigin,
    relay_id: await alice.getRelayId(),
    mailbox_id: mbB.mailboxId,
    outbound_deposit_token: depTok,
    inbound_token_id: null,
    paired_at: serverNow,
    revoked: false,
  });
  await bobStore.putDevice({
    device_id: idA.deviceId,
    label: 'Alice Phone',
    sign_pk: bytesToB64u(idA.signPk),
    kem_pk: bytesToB64u(idA.kemPk),
    issued_at: serverNow,
    card_sig: bytesToB64u(await signDeviceCard(idA.signSeed, idA.signPk, idA.kemPk, serverNow)),
    relay_origin: relayOrigin,
    relay_id: await bob.getRelayId(),
    mailbox_id: null,
    outbound_deposit_token: null,
    inbound_token_id: 'dt_alice01',
    paired_at: serverNow,
    revoked: false,
  });

  // 3. Alice sends multi-block (150 KiB -> 3 blocks -> 2 transport chunks under blocks_per_chunk=2) note + attachment
  const videoBytes = new Uint8Array(150_000);
  for (let i = 0; i < videoBytes.length; i++) videoBytes[i] = (i * 7 + 3) & 0xff;
  const sent = await alice.sendToDevice(idB.deviceId, {
    schema: 'note.item.v1',
    inlinePayload: { title: 'Test Note', text: 'Encrypted multimedia' },
    blobs: [blobFromBytes(videoBytes, { role: 'video', name: 'clip.mp4', mime: 'video/mp4' })],
  });
  assert.equal(sent.mode, 'spool');

  // 4. Bob lists inbox TWICE -> part_id=0 must only be downloaded ONCE thanks to local preview cache!
  const list1 = await bob.listInbox({ appId: 'com.yellowdking.notes' });
  const list2 = await bob.listInbox({ appId: 'com.yellowdking.notes' });
  assert.equal(list1.length, 1);
  assert.equal(list2.length, 1);
  assert.equal(part0GetCount, 1);
  assert.equal(list1[0].manifest.inline_payload.title, 'Test Note');

  // 5. Bob fetches parcel, verifies full 150 KiB bytes, and ACK burns item on relay
  let deliveredBytes = null;
  await bob.fetchParcel(sent.itemId, async ({ manifest, blobs }) => {
    assert.equal(manifest.blobs.length, 1);
    deliveredBytes = blobs[0].bytes;
  });
  assert.deepEqual(deliveredBytes, videoBytes);
  assert.equal(items.size, 0); // Burned!
  assert.equal(await bobStore.hasSeenMsgID(sent.msgId), true);

  // 6. Revoke Alice -> deletes local card & server token
  await bob.revokeDevice(idA.deviceId);
  assert.equal(await bobStore.getDevice(idA.deviceId), null);
});

// ============================================================================
// 6. Full Room & Mode A Flows + Mode B Chunk Resume
// ============================================================================

test('SyncClient full room & Mode A flows: Flow 1A/1B bind (--spool=off), OneShot pipe, Flow 2 direct pipe & Mode B resume', async () => {
  const accessKey = 'M'.repeat(43);
  const relayOrigin = 'https://sync.example.com:443';
  const serverNow = Math.floor(Date.now() / 1000) - 3600;
  let spoolEnabled = false;

  // Stateful mock relay supporting rooms (long-poll), Mode A pipe rendezvous, mailboxes & spool
  const rooms = new Map();
  const pipeWaiters = new Map(); // key -> { resolvePut?, resolveGet?, bytes? }
  const items = new Map();
  const spoolChunks = new Map();

  const mockFetch = async (urlStr, init) => {
    const u = new URL(urlStr);
    const path = u.pathname;
    const method = init.method || 'GET';

    if (method === 'GET' && path === '/v1/ping') {
      return makeResponse(200, { proto_v: 1, server_ts: serverNow, profile: 'nano', spool_backend: spoolEnabled ? 'memory' : 'off', cert_expires_at: 0, cert_rotate_recommended: false });
    }
    if (method === 'GET' && path === '/v1/caps') {
      return makeResponse(200, {
        proto_v: 1,
        profile: 'nano',
        server_ts: serverNow,
        cert_expires_at: 0,
        cert_rotate_recommended: false,
        crypto_plaintext_block_bytes: 65536,
        crypto_block_bytes: 65552,
        streaming: { enabled: true, blocks_per_chunk: 2, max_transport_chunk_bytes: 2 * CHUNK_CIPHERTEXT_MAX, rendezvous_timeout_sec: 30, room_ttl_max_sec: 600 },
        spool: spoolEnabled
          ? { enabled: true, backend: 'memory', max_item_bytes: 4 * 1024 * 1024, max_mailbox_bytes: 8 * 1024 * 1024, max_total_bytes: 16 * 1024 * 1024, max_items_per_mailbox: 16, default_ttl_sec: 1800, max_ttl_sec: 7200, uncommitted_ttl_sec: 1800, max_manifest_downloads: 16, max_downloads_per_chunk: 3, max_deposit_tokens_per_mailbox: 16 }
          : { enabled: false, backend: 'off', max_item_bytes: 0, max_mailbox_bytes: 0, max_total_bytes: 0, max_items_per_mailbox: 0, default_ttl_sec: 0, max_ttl_sec: 0, uncommitted_ttl_sec: 0, max_manifest_downloads: 0, max_downloads_per_chunk: 0, max_deposit_tokens_per_mailbox: 0 },
      });
    }
    if (method === 'POST' && path === '/v1/rooms') {
      const body = JSON.parse(new TextDecoder().decode(init.body));
      const room = {
        room_id: body.room_id,
        pipe_id: bytesToHex(randomBytes(16)),
        sender_token: 'S'.repeat(43),
        receiver_token: 'R'.repeat(43),
        state: 'waiting',
        reason: '',
        seq: 0,
        messages: [],
        waiters: [],
      };
      if (body.initial_msg_b64) {
        room.seq = 1;
        room.messages.push({ seq: 1, from: 'sender', kind: 'handshake', msg_b64: body.initial_msg_b64 });
      }
      rooms.set(body.room_id, room);
      return makeResponse(201, { room_id: room.room_id, pipe_id: room.pipe_id, sender_token: room.sender_token, expires_at: serverNow + 300, seq: room.seq });
    }
    if (method === 'POST' && path.endsWith('/join')) {
      const rid = path.split('/')[3];
      const room = rooms.get(rid);
      if (!room) return makeResponse(404, { error: 'ERR_NOT_FOUND', message: 'no room', retryable: false });
      if (room.state === 'burned') return makeResponse(410, { error: 'ERR_ROOM_BURNED', message: 'burned', retryable: false });
      if (room.state !== 'waiting') return makeResponse(409, { error: 'ERR_ROOM_BUSY', message: 'busy', retryable: false });
      room.state = 'joined';
      return makeResponse(200, { room_id: rid, pipe_id: room.pipe_id, receiver_token: room.receiver_token, expires_at: serverNow + 300, seq: room.seq, messages: [...room.messages] });
    }
    if (method === 'POST' && path.endsWith('/messages')) {
      const rid = path.split('/')[3];
      const room = rooms.get(rid);
      if (!room) return makeResponse(404, { error: 'ERR_NOT_FOUND', message: 'no room', retryable: false });
      if (room.state === 'burned') return makeResponse(410, { error: 'ERR_ROOM_BURNED', message: 'burned', retryable: false });
      const body = JSON.parse(new TextDecoder().decode(init.body));
      const from = init.headers['X-Sync-Room-Token'] === room.sender_token ? 'sender' : 'receiver';
      room.seq += 1;
      room.messages.push({ seq: room.seq, from, kind: body.kind, msg_b64: body.msg_b64 });
      for (const w of room.waiters.splice(0)) w();
      return makeResponse(200, { seq: room.seq });
    }
    if (method === 'GET' && path.endsWith('/events')) {
      const rid = path.split('/')[3];
      const room = rooms.get(rid);
      if (!room) return makeResponse(404, { error: 'ERR_NOT_FOUND', message: 'no room', retryable: false });
      const since = Number(u.searchParams.get('since') || '0');
      const getMissed = () => room.messages.filter((m) => m.seq > since);
      if (getMissed().length === 0 && room.state !== 'burned' && room.state !== 'closed') {
        await new Promise((r) => {
          const t = setTimeout(r, 200);
          room.waiters.push(() => { clearTimeout(t); r(); });
        });
      }
      return makeResponse(200, { state: room.state, seq: room.seq, messages: getMissed(), reason: room.reason });
    }
    if (method === 'POST' && path.endsWith('/close')) {
      const rid = path.split('/')[3];
      const room = rooms.get(rid);
      if (room) {
        const body = JSON.parse(new TextDecoder().decode(init.body));
        room.state = body.reason === 'verify_failed' || body.reason === 'rejected' ? 'burned' : 'closed';
        room.reason = body.reason;
        for (const w of room.waiters.splice(0)) w();
      }
      return makeResponse(200, { room_id: rid, state: room?.state || 'closed' });
    }
    if (path.startsWith('/v1/pipe/')) {
      const seg = path.split('/'); // /v1/pipe/{pid}/parts/{part}/chunks/{tx}
      const key = `${seg[3]}:${seg[5]}:${seg[7]}`;
      if (method === 'PUT') {
        const bytes = new Uint8Array(init.body);
        const existing = pipeWaiters.get(key);
        if (existing?.resolveGet) {
          pipeWaiters.delete(key);
          existing.resolveGet(bytes);
        } else {
          await new Promise((resolvePut) => {
            pipeWaiters.set(key, { bytes, resolvePut });
          });
        }
        return makeResponse(200, { pipe_id: seg[3], part_id: Number(seg[5]), tx_idx: Number(seg[7]), bytes_relayed: bytes.length });
      }
      if (method === 'GET') {
        const existing = pipeWaiters.get(key);
        let bytes;
        if (existing?.bytes) {
          pipeWaiters.delete(key);
          bytes = existing.bytes;
          existing.resolvePut();
        } else {
          bytes = await new Promise((resolveGet) => {
            pipeWaiters.set(key, { resolveGet });
          });
        }
        return makeBinaryResponse(200, bytes);
      }
    }
    if (method === 'POST' && path === '/v1/spool/init') {
      const body = JSON.parse(new TextDecoder().decode(init.body));
      const itemId = 'itm_' + bytesToHex(randomBytes(16));
      items.set(itemId, { ...body, item_id: itemId, created_at: serverNow, expires_at: serverNow + 1800, committed: false });
      return makeResponse(201, { item_id: itemId, upload_token: 'U'.repeat(43), max_transport_chunk_bytes: 2 * CHUNK_CIPHERTEXT_MAX, upload_expires_at: serverNow + 1800, expires_at: serverNow + 1800 });
    }
    if (method === 'PUT' && path.startsWith('/v1/spool/')) {
      const seg = path.split('/');
      spoolChunks.set(`${seg[3]}:${seg[5]}:${seg[7]}`, new Uint8Array(init.body));
      return makeResponse(200, { item_id: seg[3], part_id: Number(seg[5]), tx_idx: Number(seg[7]), received_bytes: init.body.byteLength });
    }
    if (method === 'POST' && path.endsWith('/commit')) {
      const itemId = path.split('/')[3];
      items.get(itemId).committed = true;
      return makeResponse(200, { item_id: itemId, committed: true, expires_at: serverNow + 1800 });
    }
    if (method === 'GET' && path.endsWith('/items')) {
      const mbId = path.split('/')[3];
      const list = Array.from(items.values()).filter((it) => it.mailbox_id === mbId && it.committed)
        .map((it) => ({ item_id: it.item_id, created_at: it.created_at, expires_at: it.expires_at, total_bytes: it.declared_total_bytes, sealed_header: it.sealed_header, parts: it.parts }));
      return makeResponse(200, { mailbox_id: mbId, used_bytes: 0, quota_bytes: 8 * 1024 * 1024, items: list });
    }
    if (method === 'GET' && path.startsWith('/v1/spool/')) {
      const seg = path.split('/');
      return makeBinaryResponse(200, spoolChunks.get(`${seg[3]}:${seg[5]}:${seg[7]}`));
    }
    if (method === 'POST' && path.endsWith('/ack')) {
      items.delete(path.split('/')[3]);
      return makeResponse(200, { burned: true });
    }
    return makeResponse(404, { error: 'ERR_NOT_FOUND', message: 'not found', retryable: false });
  };

  const alice = new SyncClient({ relay: { origin: relayOrigin, accessKey }, label: 'Alice', fetchImpl: mockFetch, clockOffsetSec: serverNow - Math.floor(Date.now() / 1000) });
  const bob = new SyncClient({ relay: { origin: relayOrigin, accessKey }, label: 'Bob', fetchImpl: mockFetch, clockOffsetSec: serverNow - Math.floor(Date.now() / 1000) });

  // 1. Flow 1B Commit-Reveal SAS DeviceBind under --spool=off (mailbox == null!)
  let offeredRoom = null;
  let resolveOffer;
  const offerReady = new Promise((r) => { resolveOffer = r; });
  let resolveSas;
  const sasReady = new Promise((r) => { resolveSas = r; });

  const bindA = alice.startDeviceBind({
    mode: 2,
    preferPoll: true,
    onOfferReady: (offer) => { offeredRoom = offer.roomId; resolveOffer(); },
    onSASInput: async () => await sasReady,
  });
  await offerReady;
  const bindB = bob.acceptDeviceBind(offeredRoom, {
    preferPoll: true,
    onSASDisplay: ({ sas }) => { resolveSas(sas); },
    onSASConfirm: async () => true,
  });
  const [cardBOnA, cardAOnB] = await Promise.all([bindA, bindB]);
  assert.equal(cardBOnA.mailbox_id, null);
  assert.equal(cardAOnB.mailbox_id, null);

  // 2. Under --spool=off, auto delivery returns ERR_SPOOL_DISABLED; pipe delivery (Flow 2 Mode A direct) succeeds!
  await assert.rejects(
    () => alice.sendToDevice(cardBOnA.device_id, { schema: 'note.item.v1', inlinePayload: { hi: 1 } }),
    (e) => e instanceof SyncError && e.code === ErrorCode.ERR_SPOOL_DISABLED,
  );

  const directPayload = new Uint8Array(140_000);
  for (let i = 0; i < directPayload.length; i++) directPayload[i] = (i * 5) & 0xff;
  let directUri = null;
  let resolveDirect;
  const directReady = new Promise((r) => { resolveDirect = r; });
  const sendDirectP = alice.sendToDevice(
    cardBOnA.device_id,
    { schema: 'note.item.v1', inlinePayload: { direct: true }, blobs: [blobFromBytes(directPayload, { role: 'video', name: 'v.mp4' })] },
    { deliveryMode: 'pipe', preferPoll: true, onOfferReady: (o) => { directUri = o.pairUri; resolveDirect(); } },
  );
  await directReady;
  assert.ok(directUri.includes('m=0&p=direct') && !directUri.includes('#s='));
  let gotDirect = null;
  const recvDirectP = bob.receiveDirect(directUri, async ({ manifest, blobs }) => {
    assert.equal(manifest.inline_payload.direct, true);
    gotDirect = blobs[0].bytes;
  }, { preferPoll: true });
  await Promise.all([sendDirectP, recvDirectP]);
  assert.deepEqual(gotDirect, directPayload);

  // 3. Flow 1A QR OOB OneShot Mode A Pipe
  const oneshotBytes = new Uint8Array(70_000);
  oneshotBytes.fill(0x42);
  let oneshotUri = null;
  let resolveOS;
  const osReady = new Promise((r) => { resolveOS = r; });
  const osSendP = alice.startOneShotSend(
    { schema: 'vault.snapshot.v1', inlinePayload: { count: 3 }, blobs: [blobFromBytes(oneshotBytes, { role: 'vault_dump', name: 'vault.json' })] },
    { mode: 1, preferPoll: true, onOfferReady: (o) => { oneshotUri = o.pairUri; resolveOS(); } },
  );
  await osReady;
  assert.ok(oneshotUri.includes('#s='));
  let gotOS = null;
  const osRecvP = bob.receiveOneShot(oneshotUri, async ({ manifest, blobs }) => {
    assert.equal(manifest.inline_payload.count, 3);
    gotOS = blobs[0].bytes;
  }, { preferPoll: true });
  await Promise.all([osSendP, osRecvP]);
  assert.deepEqual(gotOS, oneshotBytes);

  // 4. Mode B chunk checkpoint resume (startTxIdx=1 with resumePrefixBytes for 200 KiB = 4 blocks = 2 chunks)
  spoolEnabled = true;
  await alice.capabilities({ refresh: true });
  await bob.capabilities({ refresh: true });
  const mbB = await bob.getMailboxIdentity();
  await alice.keyStore.putDevice({ ...cardBOnA, mailbox_id: mbB.mailboxId, outbound_deposit_token: 'T'.repeat(43) });
  const resumeData = new Uint8Array(200_000);
  for (let i = 0; i < resumeData.length; i++) resumeData[i] = (i * 11) & 0xff;
  const spooled = await alice.sendToDevice(cardBOnA.device_id, {
    schema: 'note.item.v1',
    inlinePayload: { resume: true },
    blobs: [blobFromBytes(resumeData, { role: 'video', name: 'resumed.mp4' })],
  });
  let resumedBytes = null;
  // Simulate resuming after chunk 0 (2 blocks * 64 KiB = 131,072 bytes already decrypted to disk!)
  await bob.fetchParcel(spooled.itemId, async ({ blobs }) => { resumedBytes = blobs[0].bytes; }, {
    blocksPerChunk: 2,
    resumeCheckpoints: new Map([[1, 1]]),
    resumePrefixes: new Map([[1, resumeData.subarray(0, 2 * CHUNK_PLAINTEXT_MAX)]]),
  });
  assert.deepEqual(resumedBytes, resumeData);
});

function makeResponse(status, jsonObj) {
  const text = JSON.stringify(jsonObj);
  return {
    status,
    headers: { get: () => null },
    async text() { return text; },
    async json() { return jsonObj; },
    async arrayBuffer() { return utf8Encode(text).buffer; },
  };
}

function makeBinaryResponse(status, bytes) {
  return {
    status,
    headers: { get: () => null },
    async text() { return new TextDecoder().decode(bytes); },
    async arrayBuffer() { return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength); },
  };
}
