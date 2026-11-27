import test from 'node:test';
import assert from 'node:assert/strict';

import {
  ErrorCode,
  SEALED_HEADER_LEN,
  StreamingSha256,
  SyncError,
  bytesToB64u,
  bytesToHex,
  computeCommitA,
  computeCommitSasHandshake,
  computeDirectAckMac,
  computeQrOobHandshake,
  decodeRoomId,
  decryptPartBytes,
  deriveBlobPartKeys,
  deriveDeviceIdentity,
  deriveMailboxIdentity,
  deriveOneshotPart0Keys,
  derivePipeCtrlKeys,
  deriveRelayId,
  encodeRoomId,
  encryptPartBytes,
  formatPairURI,
  formatRelayURI,
  formatRoomId,
  generateRoomId,
  generateX25519KeyPair,
  isValidRoomId,
  normalizeRoomId,
  openPairBindPayload,
  openPaired0RTTHeader,
  openPipeCtrlFrame,
  padManifest,
  parsePairURI,
  parseRelayURI,
  randomBytes,
  redactURI,
  sanitizeFileName,
  sealPairBindPayload,
  sealPaired0RTTHeader,
  sealPipeCtrlFrame,
  sha256,
  signDeviceCard,
  signMailboxRequest,
  signRelayRequest,
  unpadManifest,
  utf8Encode,
  validateManifest,
  verifyDeviceCard,
  verifyDirectAckMac,
  verifyMailboxRequest,
  x25519SharedSecret,
} from '../src/index.js';

// ============================================================================
// 1. Crockford Base32 Room IDs
// ============================================================================

test('Crockford Base32 round-trip, boundaries, normalization & rejection', () => {
  assert.equal(encodeRoomId(new Uint8Array([0, 0, 0, 0, 0])), '00000000');
  assert.deepEqual(decodeRoomId('0000-0000'), new Uint8Array([0, 0, 0, 0, 0]));

  assert.equal(encodeRoomId(new Uint8Array([0xff, 0xff, 0xff, 0xff, 0xff])), 'ZZZZZZZZ');
  assert.deepEqual(decodeRoomId('zzzz-zzzz'), new Uint8Array([0xff, 0xff, 0xff, 0xff, 0xff]));

  assert.equal(normalizeRoomId(' o1iL - 9p2x '), '01119P2X');
  assert.equal(formatRoomId('o1iL9p2x'), '0111-9P2X');
  assert.equal(isValidRoomId('01119P2X', { strict: true }), true);
  assert.equal(isValidRoomId('0111-9P2X', { strict: true }), false);
  assert.equal(isValidRoomId('0111-9P2X'), true);

  assert.throws(() => normalizeRoomId('UUUUUUUU'));
  assert.throws(() => normalizeRoomId('ABC123'));
  assert.throws(() => encodeRoomId(new Uint8Array(4)));

  for (let i = 0; i < 32; i++) {
    const r = generateRoomId();
    assert.equal(r.length, 8);
    assert.equal(encodeRoomId(decodeRoomId(r)), r);
  }
});

// ============================================================================
// 2. StreamingSha256 matches WebCrypto SHA-256 across block boundaries
// ============================================================================

test('StreamingSha256 matches WebCrypto SHA-256 across edge lengths', async () => {
  for (const len of [0, 1, 55, 56, 63, 64, 65, 127, 128, 1000, 150000]) {
    const data = new Uint8Array(len);
    for (let i = 0; i < len; i++) data[i] = (i * 31 + 17) & 0xff;
    const expected = bytesToHex(await sha256(data));
    const h = new StreamingSha256();
    // Feed in irregular slice sizes
    for (let off = 0; off < len; off += 137) {
      h.update(data.subarray(off, Math.min(off + 137, len)));
    }
    assert.equal(h.digestHex(), expected, `mismatch at len=${len}`);
  }
});

// ============================================================================
// 3. Envelope, Manifest Validation & synctool:// URI Rules
// ============================================================================

test('URI parsing, formatting, bare-IP SPKI enforcement & fragment security', () => {
  const pin = 'a'.repeat(64);
  const key = 'B'.repeat(43);
  const s = 'C'.repeat(22);

  // Relay URI: bare IP requires pin
  const relayUri = formatRelayURI({ origin: 'https://1.2.3.4:54843', spkiPin: pin, accessKey: key });
  assert.ok(relayUri.includes(`#k=${key}`));
  assert.equal(redactURI(relayUri).includes(key), false);
  const parsedRelay = parseRelayURI(relayUri);
  assert.equal(parsedRelay.origin, 'https://1.2.3.4:54843');
  assert.equal(parsedRelay.tlsMode, 'spki_pin');
  assert.equal(parsedRelay.spkiPin, pin);
  assert.equal(parsedRelay.accessKey, key);

  assert.throws(
    () => parseRelayURI(`synctool://relay?v=1&u=${encodeURIComponent('https://1.2.3.4:54843')}#k=${key}`),
    (e) => e instanceof SyncError && e.code === ErrorCode.ERR_URI_INVALID,
  );
  // Reject secret in query string
  assert.throws(
    () => parseRelayURI(`synctool://relay?v=1&u=${encodeURIComponent('https://sync.example.com:443')}&k=${key}`),
    (e) => e instanceof SyncError && e.code === ErrorCode.ERR_URI_INVALID,
  );

  // Domain HTTPS without pin -> system_ca
  const domRelay = parseRelayURI(`synctool://relay?v=1&u=${encodeURIComponent('https://sync.example.com')}#k=${key}`);
  assert.equal(domRelay.origin, 'https://sync.example.com:443');
  assert.equal(domRelay.tlsMode, 'system_ca');
  assert.equal(domRelay.spkiPin, null);

  // Pair URI: m=1 requires #s=, m=2 and m=0 forbid #s=
  const pair1 = formatPairURI({ roomId: 'K7M9-P2XQ', mode: 1, purpose: 'pair', oobSecret: s });
  assert.ok(pair1.endsWith(`#s=${s}`));
  const p1 = parsePairURI(pair1);
  assert.equal(p1.roomId, 'K7M9P2XQ');
  assert.equal(p1.mode, 1);
  assert.equal(p1.purpose, 'pair');
  assert.equal(p1.oobSecret, s);

  const pair2 = formatPairURI({ roomId: 'K7M9P2XQ', mode: 2, purpose: 'oneshot' });
  assert.equal(pair2.includes('#'), false);
  assert.equal(parsePairURI(pair2).mode, 2);

  const pair0 = formatPairURI({ roomId: 'K7M9P2XQ', mode: 0, purpose: 'direct' });
  assert.equal(pair0.includes('#'), false);
  const p0 = parsePairURI(pair0);
  assert.equal(p0.mode, 0);
  assert.equal(p0.purpose, 'direct');
  assert.equal(p0.oobSecret, null);

  assert.throws(() => parsePairURI(`synctool://pair?r=K7M9P2XQ&m=0&p=oneshot`), (e) => e.code === ErrorCode.ERR_URI_INVALID);
  assert.throws(() => parsePairURI(`synctool://pair?r=K7M9P2XQ&m=2&p=oneshot#s=${s}`), (e) => e.code === ErrorCode.ERR_URI_INVALID);
  assert.throws(() => parsePairURI(`synctool://pair?r=K7M9P2XQ&m=1&p=oneshot`), (e) => e.code === ErrorCode.ERR_URI_INVALID);
});

test('Manifest validation, path traversal sanitization & 4 KiB padding', () => {
  assert.equal(sanitizeFileName('../../etc/passwd'), 'passwd');
  assert.equal(sanitizeFileName('C:\\Windows\\System32\\evil.exe'), 'evil.exe');
  assert.equal(sanitizeFileName('...'), 'attachment.bin');

  const valid = {
    envelope_version: 1,
    msg_id: '0123456789abcdef0123456789abcdef',
    app_id: 'com.yellowdking.notes',
    schema: 'note.item.v1',
    created_at: 1764246000,
    sender: { device_id: 'fedcba9876543210fedcba9876543210', label: 'Phone', platform: 'android' },
    inline_payload: { title: 'Hello' },
    blobs: [],
  };
  const encoded = validateManifest(valid);
  const padded = padManifest(encoded);
  assert.equal(padded.length, 4096);
  assert.deepEqual(unpadManifest(padded), encoded);

  // Tamper trailing zero pad byte -> must reject
  const badPad = new Uint8Array(padded);
  badPad[badPad.length - 1] = 0x01;
  assert.throws(() => unpadManifest(badPad), (e) => e instanceof SyncError && e.code === ErrorCode.ERR_STREAM_TRUNCATED);

  // Oversized inline_payload (> 64 KiB) -> reject
  assert.throws(
    () => validateManifest({ ...valid, inline_payload: { big: 'x'.repeat(70000) } }),
    (e) => e instanceof SyncError && e.code === ErrorCode.ERR_MANIFEST_INVALID,
  );
});

// ============================================================================
// 4. Crypto Primitives, Flows 1A/1B/2 & STREAM AEAD Negative Assertions
// ============================================================================

test('Crypto end-to-end: identity, Flow 1A/1B, pipe_ctrl, Flow 2 0-RTT & STREAM AEAD', async () => {
  const seedA = randomBytes(32);
  const seedB = randomBytes(32);
  const idA = await deriveDeviceIdentity(seedA);
  const idB = await deriveDeviceIdentity(seedB);
  const relayId = await deriveRelayId('https://sync.example.com:443');
  const mbA = await deriveMailboxIdentity(seedA, relayId);
  assert.equal(idA.deviceId.length, 32);
  assert.equal(mbA.mailboxId.length, 32);

  // Low-order all-zero X25519 public key MUST be rejected
  await assert.rejects(
    () => x25519SharedSecret(idA.kemSk, new Uint8Array(32)),
    (e) => e instanceof SyncError && e.code === ErrorCode.ERR_CRYPTO_HANDSHAKE_FAILED,
  );

  // DeviceCard signing & tamper rejection
  const issuedAt = 1764246000;
  const sigA = await signDeviceCard(idA.signSeed, idA.signPk, idA.kemPk, issuedAt);
  const cardA = {
    device_id: idA.deviceId,
    sign_pk: bytesToB64u(idA.signPk),
    kem_pk: bytesToB64u(idA.kemPk),
    issued_at: issuedAt,
    card_sig: bytesToB64u(sigA),
    label: 'Alice',
  };
  assert.equal(await verifyDeviceCard(cardA), true);
  assert.equal(await verifyDeviceCard({ ...cardA, issued_at: issuedAt + 1 }), false);

  // Flow 1A QR OOB + pipe_ctrl + pair_bind
  const ephA = await generateX25519KeyPair();
  const ephB = await generateX25519KeyPair();
  const nA = randomBytes(32);
  const nB = randomBytes(32);
  const oob = randomBytes(16);
  const shA = await x25519SharedSecret(ephA.privateKey, ephB.publicKey);
  const shB = await x25519SharedSecret(ephB.privateKey, ephA.publicKey);
  assert.deepEqual(shA, shB);

  const qrA = await computeQrOobHandshake({ purpose: 'oneshot', roomId: 'K7M9P2XQ', shared: shA, oobSecret: oob, eA: ephA.publicKey, nA, eB: ephB.publicKey, nB });
  const qrB = await computeQrOobHandshake({ purpose: 'oneshot', roomId: 'K7M9P2XQ', shared: shB, oobSecret: oob, eA: ephA.publicKey, nA, eB: ephB.publicKey, nB });
  assert.deepEqual(qrA.sessionKey, qrB.sessionKey);
  assert.deepEqual(qrA.macA, qrB.macA);
  assert.deepEqual(qrA.macB, qrB.macB);

  const { ctrlKey, ctrlNoncePrefix } = await derivePipeCtrlKeys(qrA.sessionKey, qrA.th);
  const frame0 = await sealPipeCtrlFrame(ctrlKey, ctrlNoncePrefix, qrA.th, 0, { op: 'pipe_start', msg_id: 'a'.repeat(32) });
  const opened0 = await openPipeCtrlFrame(ctrlKey, ctrlNoncePrefix, qrA.th, frame0, { expectedParity: 0, lastSeenSeq: -1 });
  assert.equal(opened0.payload.op, 'pipe_start');
  // Wrong parity rejected
  await assert.rejects(() => openPipeCtrlFrame(ctrlKey, ctrlNoncePrefix, qrA.th, frame0, { expectedParity: 1 }));
  // Non-monotonic rejected
  await assert.rejects(() => openPipeCtrlFrame(ctrlKey, ctrlNoncePrefix, qrA.th, frame0, { expectedParity: 0, lastSeenSeq: 0 }));

  // PairBindPayload encryption
  const bindCt = await sealPairBindPayload(qrA.sessionKey, qrA.prk, qrA.th, 'a', { device_card: cardA, mailbox: null });
  const bindPt = await openPairBindPayload(qrB.sessionKey, qrB.prk, qrB.th, 'a', bindCt);
  assert.equal(bindPt.mailbox, null);
  assert.equal(bindPt.device_card.device_id, idA.deviceId);

  // Flow 1B Commit-Reveal SAS
  const commitA = await computeCommitA({ purpose: 'pair', roomId: 'K7M9P2XQ', eA: ephA.publicKey, nA });
  const sasA = await computeCommitSasHandshake({ purpose: 'pair', roomId: 'K7M9P2XQ', shared: shA, commitA, eA: ephA.publicKey, nA, eB: ephB.publicKey, nB });
  const sasB = await computeCommitSasHandshake({ purpose: 'pair', roomId: 'K7M9P2XQ', shared: shB, commitA, eA: ephA.publicKey, nA, eB: ephB.publicKey, nB });
  assert.equal(sasA.sasStr.length, 6);
  assert.equal(sasA.sasStr, sasB.sasStr);

  // Flow 2 0-RTT SealedHeader + direct_ack + replay & tamper checks
  const msgId = randomBytes(16);
  const manifestSha = await sha256(utf8Encode('{"test":1}'));
  const sealed = await sealPaired0RTTHeader({
    msgId,
    senderSignSeed: idA.signSeed,
    senderDeviceIdRaw: idA.deviceIdRaw,
    recipientDeviceIdRaw: idB.deviceIdRaw,
    recipientKemPk: idB.kemPk,
    createdAt: 1764246000,
    manifestSha256: manifestSha,
  });
  assert.equal(sealed.sealedHeader.length, SEALED_HEADER_LEN);
  assert.equal(sealed.sealedHeaderB64u.length, 278);

  const opened = await openPaired0RTTHeader({
    sealedHeader: sealed.sealedHeaderB64u,
    recipientKemSk: idB.kemSk,
    recipientDeviceIdRaw: idB.deviceIdRaw,
    lookupSenderCard: (id) => (id === idA.deviceId ? cardA : null),
  });
  assert.equal(opened.senderDeviceId, idA.deviceId);
  assert.deepEqual(opened.part0Key, sealed.part0Key);

  // direct_ack MAC
  const ackMac = await computeDirectAckMac(opened.part0Key, msgId);
  assert.equal(await verifyDirectAckMac(sealed.part0Key, msgId, ackMac), true);
  const badMac = new Uint8Array(ackMac);
  badMac[0] ^= 1;
  assert.equal(await verifyDirectAckMac(sealed.part0Key, msgId, badMac), false);

  // Tamper clear_header -> must fail
  const tamperedHdr = new Uint8Array(sealed.sealedHeader);
  tamperedHdr[10] ^= 0x80;
  await assert.rejects(
    () => openPaired0RTTHeader({
      sealedHeader: tamperedHdr,
      recipientKemSk: idB.kemSk,
      recipientDeviceIdRaw: idB.deviceIdRaw,
      lookupSenderCard: () => cardA,
    }),
    (e) => e instanceof SyncError && e.code === ErrorCode.ERR_CRYPTO_DECRYPT_FAILED,
  );

  // STREAM AEAD multi-block (200 KiB = 4 blocks, packed with nano=4 & standard=16) + negative tests
  const bigPt = new Uint8Array(200_000);
  for (let i = 0; i < bigPt.length; i++) bigPt[i] = (i * 13) & 0xff;
  const blobKey = randomBytes(32);
  const { encKey, noncePrefix } = await deriveBlobPartKeys(blobKey, msgId, 1);
  const { blocks, transportChunks } = await encryptPartBytes(encKey, noncePrefix, msgId, 1, bigPt, 2);
  assert.equal(blocks.length, 4);
  assert.equal(transportChunks.length, 2);
  assert.deepEqual(await decryptPartBytes(encKey, noncePrefix, msgId, 1, transportChunks), bigPt);

  // Truncated stream (drop final block) -> MUST reject!
  const truncated = blocks.slice(0, 3);
  await assert.rejects(() => decryptPartBytes(encKey, noncePrefix, msgId, 1, truncated));

  // Reordered blocks -> MUST reject!
  await assert.rejects(() => decryptPartBytes(encKey, noncePrefix, msgId, 1, [blocks[1], blocks[0], blocks[2], blocks[3]]));

  // Cross-part_id splice -> MUST reject!
  await assert.rejects(() => decryptPartBytes(encKey, noncePrefix, msgId, 2, transportChunks));

  // Relay & Mailbox request signing
  const sig = await signRelayRequest({
    accessKey: 'A'.repeat(43),
    method: 'PUT',
    pathAndRawQuery: '/v1/spool/itm_123/parts/1/chunks/0',
    ts: 1764246000,
    nonce: '00112233445566778899aabbccddeeff',
    streamContentLength: 1048832,
    uploadToken: 'U'.repeat(43),
  });
  assert.equal(sig.bodyBinding, 'stream:1048832');
  assert.ok(sig.extraTokenBinding.startsWith('upload:'));
  assert.equal(sig.sigHex.length, 64);

  const mbSig = await signMailboxRequest({
    mailboxAuthSeed: mbA.mailboxAuthSeed,
    method: 'POST',
    pathAndRawQuery: `/v1/spool/itm_123/ack`,
    mailboxId: mbA.mailboxId,
    ts: 1764246000,
    nonce: '00112233445566778899aabbccddeeff',
    bodyBytes: utf8Encode('{}'),
  });
  assert.equal(
    await verifyMailboxRequest({
      mailboxAuthPk: mbA.mailboxAuthPk,
      method: 'POST',
      pathAndRawQuery: `/v1/spool/itm_123/ack`,
      mailboxId: mbA.mailboxId,
      ts: 1764246000,
      nonce: '00112233445566778899aabbccddeeff',
      bodyBytes: utf8Encode('{}'),
      sigB64u: mbSig.sigB64u,
    }),
    true,
  );

  // Oneshot 2-step HKDF check
  const os = await deriveOneshotPart0Keys(qrA.sessionKey, msgId);
  assert.equal(os.part0Key.length, 32);
  assert.equal(os.part0NoncePrefix.length, 7);
});
