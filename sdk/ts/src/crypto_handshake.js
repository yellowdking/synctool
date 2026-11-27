// Flow 1 (QR OOB, Commit-Reveal SAS, pipe_ctrl, PairBindPayload) and Flow 2 (208B SealedHeader & direct_ack)
// (spec/CRYPTO_AND_AUTH.md §4–§5).

import { ErrorCode, SyncError } from './envelope.js';
import { normalizeRoomId } from './crockford.js';
import {
  CLEAR_HEADER_LEN,
  SEALED_HEADER_LEN,
  aesGcmOpen,
  aesGcmSeal,
  b64uToBytes,
  bytesToB64u,
  bytesToHex,
  concatBytes,
  constantTimeEqual,
  ed25519Sign,
  ed25519Verify,
  generateX25519KeyPair,
  hkdfExpand,
  hkdfExtract,
  hmacSha256,
  isAllZero,
  readU32be,
  readU64be,
  sha256,
  u32be,
  u64be,
  utf8Decode,
  utf8Encode,
  x25519KeyPairFromSk,
  x25519SharedSecret,
  zeroBytes,
} from './crypto_primitives.js';

// ============================================================================
// §4 Flow 1: Interactive Pairing & One-Shot Handshake (QR OOB + Commit-SAS)
// ============================================================================

/** @param {'oneshot' | 'pair'} purpose */
export function purposeToCode(purpose) {
  if (purpose === 'oneshot') return 0x01;
  if (purpose === 'pair') return 0x02;
  throw new RangeError(`invalid Flow 1 purpose: ${purpose}`);
}

/**
 * Flow 1A (`mode=1`, qr_oob_x25519) key schedule & confirmation MACs (spec/CRYPTO_AND_AUTH.md §4.1).
 * @param {{
 *   purpose: 'oneshot' | 'pair',
 *   roomId: string,
 *   shared: Uint8Array,
 *   oobSecret: Uint8Array,
 *   eA: Uint8Array,
 *   nA: Uint8Array,
 *   eB: Uint8Array,
 *   nB: Uint8Array,
 * }} params
 */
export async function computeQrOobHandshake(params) {
  const room = normalizeRoomId(params.roomId);
  const pCode = purposeToCode(params.purpose);
  if (params.shared.length !== 32 || isAllZero(params.shared)) {
    throw new SyncError(ErrorCode.ERR_CRYPTO_HANDSHAKE_FAILED, 'invalid shared secret');
  }
  if (params.oobSecret.length !== 16) {
    throw new SyncError(ErrorCode.ERR_CRYPTO_HANDSHAKE_FAILED, 'oob_secret must be 16 bytes');
  }
  const transcript = concatBytes(
    utf8Encode('synctool-v1/hs-qr'), // 17B
    new Uint8Array([pCode]), // 1B
    utf8Encode(room), // 8B
    params.eA, // 32B
    params.nA, // 32B
    params.eB, // 32B
    params.nB, // 32B (total 154B)
  );
  const th = await sha256(transcript);
  const ikm = concatBytes(params.shared, params.oobSecret);
  const prk = await hkdfExtract(th, ikm);
  const [sessionKey, confirmKeyB, confirmKeyA] = await Promise.all([
    hkdfExpand(prk, utf8Encode('synctool-v1/session-key'), 32),
    hkdfExpand(prk, utf8Encode('synctool-v1/confirm-b'), 32),
    hkdfExpand(prk, utf8Encode('synctool-v1/confirm-a'), 32),
  ]);
  const [macB, macA] = await Promise.all([
    hmacSha256(confirmKeyB, th),
    hmacSha256(confirmKeyA, th),
  ]);
  return { transcript, th, prk, sessionKey, confirmKeyA, confirmKeyB, macA, macB };
}

/**
 * Flow 1B (`mode=2`) M1 commitment: SHA256("synctool-v1/commit" || purpose_code || room_id || E_a || n_a) (91B input).
 * @param {{ purpose: 'oneshot' | 'pair', roomId: string, eA: Uint8Array, nA: Uint8Array }} params
 */
export async function computeCommitA(params) {
  const room = normalizeRoomId(params.roomId);
  const pCode = purposeToCode(params.purpose);
  const input = concatBytes(
    utf8Encode('synctool-v1/commit'), // 18B
    new Uint8Array([pCode]), // 1B
    utf8Encode(room), // 8B
    params.eA, // 32B
    params.nA, // 32B (total 91B)
  );
  return sha256(input);
}

/**
 * Flow 1B (`mode=2`, commit_sas_x25519) key schedule, 6-digit SAS & MACs (spec/CRYPTO_AND_AUTH.md §4.2).
 * @param {{
 *   purpose: 'oneshot' | 'pair',
 *   roomId: string,
 *   shared: Uint8Array,
 *   commitA: Uint8Array,
 *   eA: Uint8Array,
 *   nA: Uint8Array,
 *   eB: Uint8Array,
 *   nB: Uint8Array,
 * }} params
 */
export async function computeCommitSasHandshake(params) {
  const room = normalizeRoomId(params.roomId);
  const pCode = purposeToCode(params.purpose);
  if (params.shared.length !== 32 || isAllZero(params.shared)) {
    throw new SyncError(ErrorCode.ERR_CRYPTO_HANDSHAKE_FAILED, 'invalid shared secret');
  }
  const transcript = concatBytes(
    utf8Encode('synctool-v1/hs-sas'), // 18B
    new Uint8Array([pCode]), // 1B
    utf8Encode(room), // 8B
    params.commitA, // 32B
    params.eA, // 32B
    params.nA, // 32B
    params.eB, // 32B
    params.nB, // 32B (total 187B)
  );
  const th = await sha256(transcript);
  const prk = await hkdfExtract(th, params.shared);
  const [sessionKey, sasBytes, confirmKeyA, confirmKeyB] = await Promise.all([
    hkdfExpand(prk, utf8Encode('synctool-v1/session-key'), 32),
    hkdfExpand(prk, utf8Encode('synctool-v1/sas'), 4),
    hkdfExpand(prk, utf8Encode('synctool-v1/confirm-a'), 32),
    hkdfExpand(prk, utf8Encode('synctool-v1/confirm-b'), 32),
  ]);
  const sasInt = readU32be(sasBytes, 0) % 1000000;
  const sasStr = String(sasInt).padStart(6, '0');
  const [macA, macB] = await Promise.all([
    hmacSha256(confirmKeyA, th),
    hmacSha256(confirmKeyB, th),
  ]);
  return { transcript, th, prk, sessionKey, sasBytes, sasInt, sasStr, confirmKeyA, confirmKeyB, macA, macB };
}

/**
 * Derive oneshot part_id=0 (Manifest) keys via strict 2-step HKDF-Extract + HKDF-Expand (spec/CRYPTO_AND_AUTH.md §4.3).
 * @param {Uint8Array} sessionKey32
 * @param {Uint8Array} msgId16
 */
export async function deriveOneshotPart0Keys(sessionKey32, msgId16) {
  if (sessionKey32.length !== 32) throw new RangeError('sessionKey must be 32 bytes');
  if (msgId16.length !== 16) throw new RangeError('msgId must be 16 bytes');
  const oneshotPrk = await hkdfExtract(msgId16, sessionKey32);
  const [part0Key, part0NoncePrefix] = await Promise.all([
    hkdfExpand(oneshotPrk, utf8Encode('synctool-v1/oneshot-part0-key'), 32),
    hkdfExpand(oneshotPrk, utf8Encode('synctool-v1/oneshot-part0-np'), 7),
  ]);
  return { oneshotPrk, part0Key, part0NoncePrefix };
}

/**
 * Derive Flow 1 oneshot room control-frame keys (spec/CRYPTO_AND_AUTH.md §4.3).
 * @param {Uint8Array} sessionKey32
 * @param {Uint8Array} th32
 */
export async function derivePipeCtrlKeys(sessionKey32, th32) {
  const ctrlPrk = await hkdfExtract(th32, sessionKey32);
  const [ctrlKey, ctrlNoncePrefix] = await Promise.all([
    hkdfExpand(ctrlPrk, utf8Encode('synctool-v1/pipe-ctrl-key'), 32),
    hkdfExpand(ctrlPrk, utf8Encode('synctool-v1/pipe-ctrl-np'), 7),
  ]);
  return { ctrlPrk, ctrlKey, ctrlNoncePrefix };
}

/**
 * Seal an encrypted Flow 1 oneshot room control frame (`{"ctrl_seq":n,"ct":"..."}`).
 * Sender uses even ctrl_seq (0,2,4...); Receiver uses odd ctrl_seq (1,3,5...).
 * @param {Uint8Array} ctrlKey32
 * @param {Uint8Array} ctrlNp7
 * @param {Uint8Array} th32
 * @param {number} ctrlSeq
 * @param {any} payloadObj
 */
export async function sealPipeCtrlFrame(ctrlKey32, ctrlNp7, th32, ctrlSeq, payloadObj) {
  const nonce = concatBytes(ctrlNp7, u32be(ctrlSeq), new Uint8Array([0x00])); // 12B
  const aad = concatBytes(utf8Encode('synctool-v1/pipe-ctrl'), th32, u32be(ctrlSeq)); // 21+32+4 = 57B
  const pt = utf8Encode(JSON.stringify(payloadObj));
  const ct = await aesGcmSeal(ctrlKey32, nonce, pt, aad);
  return { ctrl_seq: ctrlSeq, ct: bytesToB64u(ct) };
}

/**
 * Open and verify an encrypted Flow 1 oneshot room control frame.
 * Enforces parity (even=0 for sender, odd=1 for receiver) and strict monotonicity.
 * @param {Uint8Array} ctrlKey32
 * @param {Uint8Array} ctrlNp7
 * @param {Uint8Array} th32
 * @param {{ ctrl_seq: number, ct: string }} frame
 * @param {{ expectedParity?: 0 | 1, lastSeenSeq?: number }} [rules]
 */
export async function openPipeCtrlFrame(ctrlKey32, ctrlNp7, th32, frame, rules = {}) {
  if (!frame || typeof frame !== 'object' || !Number.isInteger(frame.ctrl_seq) || frame.ctrl_seq < 0 || typeof frame.ct !== 'string') {
    throw new SyncError(ErrorCode.ERR_CRYPTO_DECRYPT_FAILED, 'malformed pipe_ctrl frame');
  }
  const seq = frame.ctrl_seq;
  if (rules.expectedParity !== undefined && (seq & 1) !== rules.expectedParity) {
    throw new SyncError(ErrorCode.ERR_CRYPTO_DECRYPT_FAILED, `invalid ctrl_seq parity: got ${seq}`);
  }
  if (rules.lastSeenSeq !== undefined && seq <= rules.lastSeenSeq) {
    throw new SyncError(ErrorCode.ERR_CRYPTO_DECRYPT_FAILED, `non-monotonic ctrl_seq: ${seq} <= ${rules.lastSeenSeq}`);
  }
  const nonce = concatBytes(ctrlNp7, u32be(seq), new Uint8Array([0x00]));
  const aad = concatBytes(utf8Encode('synctool-v1/pipe-ctrl'), th32, u32be(seq));
  const pt = await aesGcmOpen(ctrlKey32, nonce, b64uToBytes(frame.ct), aad);
  try {
    return { ctrl_seq: seq, payload: JSON.parse(utf8Decode(pt)) };
  } catch (err) {
    throw new SyncError(ErrorCode.ERR_CRYPTO_DECRYPT_FAILED, 'invalid JSON in pipe_ctrl payload', { cause: err });
  }
}

/**
 * Seal a PairBindPayload ciphertext for side 'a' (initiator) or 'b' (responder) (spec/CRYPTO_AND_AUTH.md §4.3).
 * @param {Uint8Array} sessionKey32
 * @param {Uint8Array} prk32
 * @param {Uint8Array} th32
 * @param {'a' | 'b'} side
 * @param {any} payloadObj
 */
export async function sealPairBindPayload(sessionKey32, prk32, th32, side, payloadObj) {
  if (side !== 'a' && side !== 'b') throw new RangeError('side must be "a" or "b"');
  const nonce = await hkdfExpand(prk32, utf8Encode(`synctool-v1/pair-nonce-${side}`), 12);
  const aad = concatBytes(utf8Encode(`synctool-v1/pair-bind/${side}`), th32);
  const pt = utf8Encode(JSON.stringify(payloadObj));
  return aesGcmSeal(sessionKey32, nonce, pt, aad);
}

/**
 * Open a PairBindPayload ciphertext from side 'a' or 'b'.
 * @param {Uint8Array} sessionKey32
 * @param {Uint8Array} prk32
 * @param {Uint8Array} th32
 * @param {'a' | 'b'} side
 * @param {Uint8Array} ciphertext
 */
export async function openPairBindPayload(sessionKey32, prk32, th32, side, ciphertext) {
  if (side !== 'a' && side !== 'b') throw new RangeError('side must be "a" or "b"');
  const nonce = await hkdfExpand(prk32, utf8Encode(`synctool-v1/pair-nonce-${side}`), 12);
  const aad = concatBytes(utf8Encode(`synctool-v1/pair-bind/${side}`), th32);
  const pt = await aesGcmOpen(sessionKey32, nonce, ciphertext, aad);
  try {
    return JSON.parse(utf8Decode(pt));
  } catch (err) {
    throw new SyncError(ErrorCode.ERR_CRYPTO_DECRYPT_FAILED, 'invalid JSON in PairBindPayload', { cause: err });
  }
}

// ============================================================================
// §5 Flow 2: Paired 0-RTT SealedHeader (208B) & Mode A Direct ACK
// ============================================================================

const MAGIC_ST01 = utf8Encode('ST01');

/**
 * Build fixed 56B clear_header + 152B sealed_box = 208B SealedHeader (spec/CRYPTO_AND_AUTH.md §5.1–5.2).
 * @param {{
 *   msgId: Uint8Array,
 *   ephemeralSk?: Uint8Array,
 *   senderSignSeed: Uint8Array,
 *   senderDeviceIdRaw: Uint8Array,
 *   recipientDeviceIdRaw: Uint8Array,
 *   recipientKemPk: Uint8Array,
 *   createdAt: number,
 *   manifestSha256: Uint8Array,
 * }} params
 */
export async function sealPaired0RTTHeader(params) {
  if (params.msgId.length !== 16) throw new RangeError('msgId must be 16 bytes');
  if (params.senderDeviceIdRaw.length !== 16) throw new RangeError('senderDeviceIdRaw must be 16 bytes');
  if (params.recipientDeviceIdRaw.length !== 16) throw new RangeError('recipientDeviceIdRaw must be 16 bytes');
  if (params.recipientKemPk.length !== 32) throw new RangeError('recipientKemPk must be 32 bytes');
  if (params.manifestSha256.length !== 32) throw new RangeError('manifestSha256 must be 32 bytes');

  const eph = params.ephemeralSk
    ? await x25519KeyPairFromSk(params.ephemeralSk)
    : await generateX25519KeyPair();

  const clearHeader = concatBytes(
    MAGIC_ST01, // 4B
    new Uint8Array([0x02, 0x00, 0x00, 0x00]), // mode=0x02, flags=0x00, reserved=0x0000
    params.msgId, // 16B
    eph.publicKey, // 32B (total 56B)
  );

  const dh = await x25519SharedSecret(eph.privateKey, params.recipientKemPk);
  const hdrPrk = await hkdfExtract(clearHeader, dh);
  const [hdrKey, hdrNonce, part0Key, part0NoncePrefix] = await Promise.all([
    hkdfExpand(hdrPrk, utf8Encode('synctool-v1/0rtt-hdr-key'), 32),
    hkdfExpand(hdrPrk, utf8Encode('synctool-v1/0rtt-hdr-nonce'), 12),
    hkdfExpand(hdrPrk, utf8Encode('synctool-v1/0rtt-part0-key'), 32),
    hkdfExpand(hdrPrk, utf8Encode('synctool-v1/0rtt-part0-np'), 7),
  ]);

  const sigInput = concatBytes(
    utf8Encode('synctool-v1/0rtt-sig\n'), // 21B
    clearHeader, // 56B
    params.senderDeviceIdRaw, // 16B
    params.recipientDeviceIdRaw, // 16B
    u64be(params.createdAt), // 8B
    params.manifestSha256, // 32B (total 149B)
  );
  const senderSig = await ed25519Sign(params.senderSignSeed, sigInput);

  const sealedBoxPlaintext = concatBytes(
    params.senderDeviceIdRaw, // 16B
    params.recipientDeviceIdRaw, // 16B
    u64be(params.createdAt), // 8B
    params.manifestSha256, // 32B
    senderSig, // 64B (total 136B)
  );
  const sealedBox = await aesGcmSeal(hdrKey, hdrNonce, sealedBoxPlaintext, clearHeader);
  const sealedHeader = concatBytes(clearHeader, sealedBox); // 208B

  if (!params.ephemeralSk) {
    zeroBytes(eph.privateKey);
  }
  zeroBytes(dh);

  return {
    clearHeader,
    sealedBox,
    sealedHeader,
    sealedHeaderB64u: bytesToB64u(sealedHeader),
    sigInput,
    senderSig,
    hdrPrk,
    hdrKey,
    hdrNonce,
    part0Key,
    part0NoncePrefix,
  };
}

/**
 * Open and fully verify a 208B SealedHeader following exact order in spec/CRYPTO_AND_AUTH.md §5.3 (steps 1-6).
 * @param {{
 *   sealedHeader: Uint8Array | string,
 *   recipientKemSk: Uint8Array,
 *   recipientDeviceIdRaw: Uint8Array,
 *   hasSeenMsgId?: (msgIdHex: string) => Promise<boolean> | boolean,
 *   lookupSenderCard: (senderDeviceIdHex: string) => Promise<any> | any,
 * }} params
 */
export async function openPaired0RTTHeader(params) {
  let raw;
  try {
    raw = typeof params.sealedHeader === 'string' ? b64uToBytes(params.sealedHeader) : params.sealedHeader;
  } catch (err) {
    throw new SyncError(ErrorCode.ERR_CRYPTO_DECRYPT_FAILED, 'invalid base64url SealedHeader', { cause: err });
  }
  // Step 1: exact 208B & fixed clear header fields
  if (!(raw instanceof Uint8Array) || raw.length !== SEALED_HEADER_LEN) {
    throw new SyncError(ErrorCode.ERR_CRYPTO_DECRYPT_FAILED, `SealedHeader must be exact ${SEALED_HEADER_LEN} bytes`);
  }
  if (
    raw[0] !== 0x53 || raw[1] !== 0x54 || raw[2] !== 0x30 || raw[3] !== 0x31 ||
    raw[4] !== 0x02 || raw[5] !== 0x00 || raw[6] !== 0x00 || raw[7] !== 0x00
  ) {
    throw new SyncError(ErrorCode.ERR_CRYPTO_DECRYPT_FAILED, 'SealedHeader magic/mode/flags/reserved invalid');
  }
  const clearHeader = raw.subarray(0, CLEAR_HEADER_LEN);
  const sealedBox = raw.subarray(CLEAR_HEADER_LEN);
  const msgIdRaw = raw.slice(8, 24);
  const msgId = bytesToHex(msgIdRaw);
  const ephemeralPk = raw.slice(24, 56);

  // Step 2: check local seen_msg_ids replay cache
  if (params.hasSeenMsgId && (await params.hasSeenMsgId(msgId))) {
    throw new SyncError(ErrorCode.ERR_MSG_REPLAY_DETECTED, `msg_id already seen: ${msgId}`);
  }

  // Step 3: X25519 + HKDF + AES-256-GCM decrypt sealed_box
  const dh = await x25519SharedSecret(params.recipientKemSk, ephemeralPk);
  const hdrPrk = await hkdfExtract(clearHeader, dh);
  zeroBytes(dh);
  const [hdrKey, hdrNonce, part0Key, part0NoncePrefix] = await Promise.all([
    hkdfExpand(hdrPrk, utf8Encode('synctool-v1/0rtt-hdr-key'), 32),
    hkdfExpand(hdrPrk, utf8Encode('synctool-v1/0rtt-hdr-nonce'), 12),
    hkdfExpand(hdrPrk, utf8Encode('synctool-v1/0rtt-part0-key'), 32),
    hkdfExpand(hdrPrk, utf8Encode('synctool-v1/0rtt-part0-np'), 7),
  ]);
  const pt = await aesGcmOpen(hdrKey, hdrNonce, sealedBox, clearHeader);
  if (pt.length !== 136) {
    throw new SyncError(ErrorCode.ERR_CRYPTO_DECRYPT_FAILED, 'invalid sealed_box plaintext length');
  }

  const senderDeviceIdRaw = pt.slice(0, 16);
  const recipientDeviceIdRaw = pt.slice(16, 32);
  const createdAt = readU64be(pt, 32);
  const manifestSha256 = pt.slice(40, 72);
  const senderSig = pt.slice(72, 136);

  // Step 4: verify recipient_device_id matches self
  if (!constantTimeEqual(recipientDeviceIdRaw, params.recipientDeviceIdRaw)) {
    throw new SyncError(ErrorCode.ERR_CRYPTO_SIGNATURE_INVALID, 'recipient_device_id mismatch');
  }

  // Step 5: lookup trusted non-revoked sender card
  const senderDeviceId = bytesToHex(senderDeviceIdRaw);
  const senderCard = await params.lookupSenderCard(senderDeviceId);
  if (!senderCard || senderCard.revoked) {
    throw new SyncError(ErrorCode.ERR_DEVICE_UNTRUSTED, `untrusted or revoked sender device: ${senderDeviceId}`);
  }

  // Step 6: verify Ed25519 signature over exact 149B sig_input
  const sigInput = concatBytes(
    utf8Encode('synctool-v1/0rtt-sig\n'),
    clearHeader,
    senderDeviceIdRaw,
    recipientDeviceIdRaw,
    u64be(createdAt),
    manifestSha256,
  );
  const senderSignPk = b64uToBytes(senderCard.sign_pk);
  const valid = await ed25519Verify(senderSignPk, sigInput, senderSig);
  if (!valid) {
    throw new SyncError(ErrorCode.ERR_CRYPTO_SIGNATURE_INVALID, 'Ed25519 Sealed Sender signature invalid');
  }

  return {
    msgIdRaw,
    msgId,
    ephemeralPk,
    senderDeviceIdRaw,
    senderDeviceId,
    recipientDeviceIdRaw,
    recipientDeviceId: bytesToHex(recipientDeviceIdRaw),
    createdAt,
    manifestSha256,
    senderSig,
    senderCard,
    part0Key,
    part0NoncePrefix,
  };
}

/**
 * Compute Flow 2 Mode A direct completion MAC: HMAC-SHA256(part0_key, "synctool-v1/direct-ack" || msg_id(16B)).
 * @param {Uint8Array} part0Key32
 * @param {Uint8Array} msgId16
 */
export async function computeDirectAckMac(part0Key32, msgId16) {
  return hmacSha256(part0Key32, concatBytes(utf8Encode('synctool-v1/direct-ack'), msgId16));
}

/**
 * Constant-time verify Flow 2 Mode A direct completion MAC.
 * @param {Uint8Array} part0Key32
 * @param {Uint8Array} msgId16
 * @param {Uint8Array} mac32
 */
export async function verifyDirectAckMac(part0Key32, msgId16, mac32) {
  const expected = await computeDirectAckMac(part0Key32, msgId16);
  return constantTimeEqual(expected, mac32);
}
