// Internal room signaling, Flow 1A/1B handshake engine & bidirectional DeviceBind flows.
// Part of synctool v1 zero-dependency cross-platform client.

import { formatRoomId, generateRoomId, normalizeRoomId } from './crockford.js';
import {
  PROTO_VERSION,
  b64uToBytes,
  bytesToB64u,
  bytesToHex,
  computeCommitA,
  computeCommitSasHandshake,
  computeQrOobHandshake,
  constantTimeEqual,
  deriveRelayId,
  generateX25519KeyPair,
  hashDepositToken,
  openPairBindPayload,
  randomBytes,
  sealPairBindPayload,
  signDeviceCard,
  utf8Decode,
  utf8Encode,
  verifyDeviceCard,
  x25519SharedSecret,
  zeroBytes,
} from './crypto.js';
import {
  ErrorCode,
  SyncError,
  canonicalizeRelayOrigin,
  formatPairURI,
  parsePairURI,
} from './envelope.js';
import { DEFAULT_HANDSHAKE_TIMEOUT_MS, iterateSSE } from './client_transport.js';

// ============================================================================
// Room Signaling & SSE / Long-Poll Helpers
// ============================================================================

export async function closeRoom(client, roomId, roomToken, reason) {
  try {
    await client._signedRequest({
      method: 'POST',
      path: `/v1/rooms/${roomId}/close`,
      roomToken,
      jsonBody: { reason },
    });
  } catch {
    // Best-effort cleanup on abort/burn
  }
}

export async function postRoomMessage(client, roomId, roomToken, kind, payloadObjOrBytes, signal) {
  const raw = payloadObjOrBytes instanceof Uint8Array
    ? payloadObjOrBytes
    : utf8Encode(JSON.stringify(payloadObjOrBytes));
  const res = await client._signedRequest({
    method: 'POST',
    path: `/v1/rooms/${roomId}/messages`,
    roomToken,
    jsonBody: { kind, msg_b64: bytesToB64u(raw) },
    signal,
  });
  return res.json();
}

/**
 * Wait for the next room message matching predicate via SSE (with transparent 90s reconnect and poll fallback).
 */
export async function waitRoomMessage(client, roomId, roomToken, sinceSeq, predicate, { timeoutMs = DEFAULT_HANDSHAKE_TIMEOUT_MS, preferPoll = false, signal } = {}) {
  const deadline = Date.now() + timeoutMs;
  let cursor = sinceSeq;
  let usePoll = preferPoll;

  while (Date.now() < deadline) {
    if (signal?.aborted) throw new SyncError(ErrorCode.ERR_CANCELLED, 'operation cancelled');
    const remainingSec = Math.max(1, Math.min(20, Math.ceil((deadline - Date.now()) / 1000)));
    const mode = usePoll ? 'poll' : 'sse';
    const query = usePoll
      ? `/v1/rooms/${roomId}/events?since=${cursor}&mode=poll&wait_sec=${remainingSec}`
      : `/v1/rooms/${roomId}/events?since=${cursor}&mode=sse`;

    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), Math.max(1000, deadline - Date.now()));
    const onOuterAbort = () => ctrl.abort();
    signal?.addEventListener('abort', onOuterAbort, { once: true });

    try {
      const res = await client._signedRequest({ method: 'GET', path: query, roomToken, signal: ctrl.signal });
      if (mode === 'poll') {
        const data = await res.json();
        if (data.state === 'burned') {
          throw new SyncError(ErrorCode.ERR_ROOM_BURNED, `room burned: ${data.reason || 'verify_failed'}`);
        }
        for (const msg of data.messages || []) {
          cursor = Math.max(cursor, msg.seq);
          if (predicate(msg)) return { msg, seq: cursor };
        }
        if (data.state === 'closed') {
          throw new SyncError(ErrorCode.ERR_HANDSHAKE_TIMEOUT, `room closed before expected message: ${data.reason || ''}`);
        }
      } else {
        for await (const ev of iterateSSE(res.body, ctrl.signal)) {
          if (ev.event === 'burned') {
            throw new SyncError(ErrorCode.ERR_ROOM_BURNED, `room burned: ${ev.data}`);
          }
          if (ev.event === 'closed') {
            throw new SyncError(ErrorCode.ERR_HANDSHAKE_TIMEOUT, `room closed: ${ev.data}`);
          }
          if (ev.event === 'reconnect') {
            try {
              const parsed = JSON.parse(ev.data);
              if (typeof parsed.since === 'number') cursor = Math.max(cursor, parsed.since);
            } catch { /* ignore */ }
            break; // cleanly reconnect
          }
          if (ev.event === 'message' && ev.data) {
            const msg = JSON.parse(ev.data);
            if (typeof msg.seq === 'number') cursor = Math.max(cursor, msg.seq);
            if (predicate(msg)) {
              ctrl.abort();
              return { msg, seq: cursor };
            }
          }
        }
      }
    } catch (err) {
      if (signal?.aborted) throw new SyncError(ErrorCode.ERR_CANCELLED, 'operation cancelled', { cause: err });
      if (err instanceof SyncError && (err.code === ErrorCode.ERR_ROOM_BURNED || err.code === ErrorCode.ERR_NOT_FOUND || err.code === ErrorCode.ERR_UNAUTHORIZED_TOKEN || err.code === ErrorCode.ERR_HANDSHAKE_TIMEOUT)) {
        throw err;
      }
      if (!usePoll && Date.now() < deadline) {
        usePoll = true; // fall back to long-poll if SSE proxy drops
        continue;
      }
      if (Date.now() >= deadline) {
        throw new SyncError(ErrorCode.ERR_HANDSHAKE_TIMEOUT, 'timed out waiting for peer handshake message', { retryable: true, cause: err });
      }
    } finally {
      clearTimeout(timer);
      signal?.removeEventListener('abort', onOuterAbort);
    }
  }
  throw new SyncError(ErrorCode.ERR_HANDSHAKE_TIMEOUT, 'handshake wait timed out', { retryable: true });
}

// ============================================================================
// Flow 1 Handshake Engine (Shared by OneShot & DeviceBind)
// ============================================================================

export async function runFlow1Initiator(client, { purpose, mode = 1, includeRelay = false, ttlSec = 300, onOfferReady, onSASInput, timeoutMs = DEFAULT_HANDSHAKE_TIMEOUT_MS, preferPoll = false, signal }) {
  if (mode !== 1 && mode !== 2) {
    throw new SyncError(ErrorCode.ERR_BAD_REQUEST, 'Flow 1 mode must be 1 (qr) or 2 (sas)');
  }
  const roomId = generateRoomId();
  const ephA = await generateX25519KeyPair();
  const nA = randomBytes(32);
  const oobSecret = mode === 1 ? randomBytes(16) : null;
  const commitA = mode === 2 ? await computeCommitA({ purpose, roomId, eA: ephA.publicKey, nA }) : null;

  const m1 = mode === 1
    ? { proto_v: PROTO_VERSION, mode: 1, purpose, e_a: bytesToB64u(ephA.publicKey), n_a: bytesToB64u(nA) }
    : { proto_v: PROTO_VERSION, mode: 2, purpose, commit_a: bytesToB64u(commitA) };

  const createRes = await client._signedRequest({
    method: 'POST',
    path: '/v1/rooms',
    jsonBody: { room_id: roomId, ttl_sec: ttlSec, initial_msg_b64: bytesToB64u(utf8Encode(JSON.stringify(m1))) },
    signal,
  });
  const room = await createRes.json();
  const roomToken = room.sender_token;
  let seq = room.seq ?? 1;

  const pairUri = formatPairURI({
    roomId,
    mode,
    purpose,
    oobSecret: oobSecret ? bytesToB64u(oobSecret) : null,
    relayOrigin: includeRelay ? client.relay.origin : null,
    spkiPin: includeRelay ? client.relay.spkiPin : null,
    accessKey: includeRelay ? client.relay.accessKey : null,
    expiresAt: room.expires_at,
  });

  if (onOfferReady) {
    await onOfferReady({
      roomId,
      formattedRoomId: formatRoomId(roomId),
      pairUri,
      mode,
      purpose,
      expiresAt: room.expires_at,
    });
  }

  try {
    // Wait for M2 from receiver
    const { msg: m2Msg, seq: s2 } = await waitRoomMessage(
      client, roomId, roomToken, seq,
      (m) => m.from === 'receiver' && m.kind === 'handshake',
      { timeoutMs, preferPoll, signal },
    );
    seq = s2;
    const m2 = JSON.parse(utf8Decode(b64uToBytes(m2Msg.msg_b64)));
    if (m2.proto_v !== PROTO_VERSION || m2.mode !== mode) {
      await closeRoom(client, roomId, roomToken, 'verify_failed');
      throw new SyncError(ErrorCode.ERR_CRYPTO_HANDSHAKE_FAILED, 'peer handshake mode/version mismatch');
    }
    const eB = b64uToBytes(m2.e_b);
    const nB = b64uToBytes(m2.n_b);
    const shared = await x25519SharedSecret(ephA.privateKey, eB);

    if (mode === 1) {
      const hs = await computeQrOobHandshake({ purpose, roomId, shared, oobSecret, eA: ephA.publicKey, nA, eB, nB });
      const peerMacB = b64uToBytes(m2.mac_b);
      if (!constantTimeEqual(peerMacB, hs.macB)) {
        await closeRoom(client, roomId, roomToken, 'verify_failed');
        throw new SyncError(ErrorCode.ERR_SAS_MISMATCH, 'QR OOB key confirmation MAC_B mismatch');
      }
      const m3Res = await postRoomMessage(client, roomId, roomToken, 'handshake', {
        proto_v: PROTO_VERSION,
        mode: 1,
        mac_a: bytesToB64u(hs.macA),
      }, signal);
      seq = m3Res.seq;
      zeroBytes(ephA.privateKey);
      zeroBytes(shared);
      return { roomId, pipeId: room.pipe_id, roomToken, seq, hs };
    }

    // mode === 2 (Commit-Reveal X25519 + input-style 6-digit SAS)
    const hs = await computeCommitSasHandshake({ purpose, roomId, shared, commitA, eA: ephA.publicKey, nA, eB, nB });
    const m3Res = await postRoomMessage(client, roomId, roomToken, 'handshake', {
      proto_v: PROTO_VERSION,
      mode: 2,
      e_a: bytesToB64u(ephA.publicKey),
      n_a: bytesToB64u(nA),
      mac_a: bytesToB64u(hs.macA),
    }, signal);
    seq = m3Res.seq;

    // Wait for M4 (mac_b)
    const { msg: m4Msg, seq: s4 } = await waitRoomMessage(
      client, roomId, roomToken, seq,
      (m) => m.from === 'receiver' && m.kind === 'handshake',
      { timeoutMs, preferPoll, signal },
    );
    seq = s4;
    const m4 = JSON.parse(utf8Decode(b64uToBytes(m4Msg.msg_b64)));
    if (!m4.mac_b || !constantTimeEqual(b64uToBytes(m4.mac_b), hs.macB)) {
      await closeRoom(client, roomId, roomToken, 'verify_failed');
      throw new SyncError(ErrorCode.ERR_SAS_MISMATCH, 'Commit-SAS key confirmation MAC_B mismatch');
    }

    // Mandatory user input of Bob's 6-digit SAS (up to 2 typo retries per spec/CRYPTO_AND_AUTH.md §4.2)
    if (!onSASInput) {
      await closeRoom(client, roomId, roomToken, 'verify_failed');
      throw new SyncError(ErrorCode.ERR_SAS_MISMATCH, 'mode=2 requires onSASInput callback to verify 6-digit SAS');
    }
    const expectedSasBytes = utf8Encode(hs.sasStr);
    let verified = false;
    for (let tries = 0; tries < 3; tries++) {
      const entered = await onSASInput({ attempt: tries + 1, maxAttempts: 3 });
      if (entered == null) break; // user rejected
      const cleaned = String(entered).replace(/\s+/g, '');
      if (cleaned.length === 6 && constantTimeEqual(utf8Encode(cleaned), expectedSasBytes)) {
        verified = true;
        break;
      }
    }
    if (!verified) {
      await closeRoom(client, roomId, roomToken, 'verify_failed');
      throw new SyncError(ErrorCode.ERR_SAS_MISMATCH, '6-digit SAS verification failed; room burned');
    }

    zeroBytes(ephA.privateKey);
    zeroBytes(shared);
    return { roomId, pipeId: room.pipe_id, roomToken, seq, hs };
  } catch (err) {
    zeroBytes(ephA.privateKey);
    throw err;
  }
}

export async function runFlow1Responder(client, pairInput, { expectedPurpose, onSASDisplay, timeoutMs = DEFAULT_HANDSHAKE_TIMEOUT_MS, preferPoll = false, signal } = {}) {
  const parsed = typeof pairInput === 'string' && pairInput.startsWith('synctool://pair')
    ? parsePairURI(pairInput)
    : { roomId: normalizeRoomId(pairInput), mode: 2, purpose: expectedPurpose, oobSecret: null };

  if (expectedPurpose && parsed.purpose !== expectedPurpose) {
    throw new SyncError(ErrorCode.ERR_BAD_REQUEST, `expected purpose=${expectedPurpose}, got ${parsed.purpose}`);
  }

  // Join without msg_b64 first to read and lock M1 (PROTOCOL.md §5.2)
  const joinRes = await client._signedRequest({
    method: 'POST',
    path: `/v1/rooms/${parsed.roomId}/join`,
    jsonBody: {},
    signal,
  });
  const joined = await joinRes.json();
  const roomToken = joined.receiver_token;
  let seq = joined.seq ?? 0;

  let m1Msg = (joined.messages || []).find((m) => m.from === 'sender' && m.kind === 'handshake');
  if (!m1Msg) {
    const waited = await waitRoomMessage(
      client, parsed.roomId, roomToken, seq,
      (m) => m.from === 'sender' && m.kind === 'handshake',
      { timeoutMs, preferPoll, signal },
    );
    m1Msg = waited.msg;
    seq = waited.seq;
  }
  const m1 = JSON.parse(utf8Decode(b64uToBytes(m1Msg.msg_b64)));
  const mode = m1.mode;
  const purpose = m1.purpose;
  if (m1.proto_v !== PROTO_VERSION || (mode !== 1 && mode !== 2) || (expectedPurpose && purpose !== expectedPurpose)) {
    await closeRoom(client, parsed.roomId, roomToken, 'verify_failed');
    throw new SyncError(ErrorCode.ERR_CRYPTO_HANDSHAKE_FAILED, 'invalid M1 handshake parameters');
  }

  const ephB = await generateX25519KeyPair();
  const nB = randomBytes(32);

  try {
    if (mode === 1) {
      if (!parsed.oobSecret) {
        await closeRoom(client, parsed.roomId, roomToken, 'verify_failed');
        throw new SyncError(ErrorCode.ERR_URI_INVALID, 'room requires mode=1 QR oob_secret (#s=)');
      }
      const eA = b64uToBytes(m1.e_a);
      const nA = b64uToBytes(m1.n_a);
      const oobSecret = b64uToBytes(parsed.oobSecret);
      const shared = await x25519SharedSecret(ephB.privateKey, eA);
      const hs = await computeQrOobHandshake({ purpose, roomId: parsed.roomId, shared, oobSecret, eA, nA, eB: ephB.publicKey, nB });
      const m2Res = await postRoomMessage(client, parsed.roomId, roomToken, 'handshake', {
        proto_v: PROTO_VERSION,
        mode: 1,
        e_b: bytesToB64u(ephB.publicKey),
        n_b: bytesToB64u(nB),
        mac_b: bytesToB64u(hs.macB),
      }, signal);
      seq = m2Res.seq;

      const { msg: m3Msg, seq: s3 } = await waitRoomMessage(
        client, parsed.roomId, roomToken, seq,
        (m) => m.from === 'sender' && m.kind === 'handshake',
        { timeoutMs, preferPoll, signal },
      );
      seq = s3;
      const m3 = JSON.parse(utf8Decode(b64uToBytes(m3Msg.msg_b64)));
      if (!m3.mac_a || !constantTimeEqual(b64uToBytes(m3.mac_a), hs.macA)) {
        await closeRoom(client, parsed.roomId, roomToken, 'verify_failed');
        throw new SyncError(ErrorCode.ERR_SAS_MISMATCH, 'QR OOB key confirmation MAC_A mismatch');
      }
      zeroBytes(ephB.privateKey);
      zeroBytes(shared);
      return { roomId: parsed.roomId, pipeId: joined.pipe_id, roomToken, seq, hs, mode, purpose };
    }

    // mode === 2 (Commit-Reveal X25519)
    const commitA = b64uToBytes(m1.commit_a);
    const m2Res = await postRoomMessage(client, parsed.roomId, roomToken, 'handshake', {
      proto_v: PROTO_VERSION,
      mode: 2,
      e_b: bytesToB64u(ephB.publicKey),
      n_b: bytesToB64u(nB),
    }, signal);
    seq = m2Res.seq;

    const { msg: m3Msg, seq: s3 } = await waitRoomMessage(
      client, parsed.roomId, roomToken, seq,
      (m) => m.from === 'sender' && m.kind === 'handshake',
      { timeoutMs, preferPoll, signal },
    );
    seq = s3;
    const m3 = JSON.parse(utf8Decode(b64uToBytes(m3Msg.msg_b64)));
    const eA = b64uToBytes(m3.e_a);
    const nA = b64uToBytes(m3.n_a);

    // Step 1: verify commitment BEFORE deriving SAS!
    const recomputedCommit = await computeCommitA({ purpose, roomId: parsed.roomId, eA, nA });
    if (!constantTimeEqual(recomputedCommit, commitA)) {
      await closeRoom(client, parsed.roomId, roomToken, 'verify_failed');
      throw new SyncError(ErrorCode.ERR_SAS_MISMATCH, 'Commit-Reveal commit_a verification failed; room burned');
    }

    const shared = await x25519SharedSecret(ephB.privateKey, eA);
    const hs = await computeCommitSasHandshake({ purpose, roomId: parsed.roomId, shared, commitA, eA, nA, eB: ephB.publicKey, nB });
    if (!m3.mac_a || !constantTimeEqual(b64uToBytes(m3.mac_a), hs.macA)) {
      await closeRoom(client, parsed.roomId, roomToken, 'verify_failed');
      throw new SyncError(ErrorCode.ERR_SAS_MISMATCH, 'Commit-SAS key confirmation MAC_A mismatch');
    }

    const m4Res = await postRoomMessage(client, parsed.roomId, roomToken, 'handshake', {
      proto_v: PROTO_VERSION,
      mode: 2,
      mac_b: bytesToB64u(hs.macB),
    }, signal);
    seq = m4Res.seq;

    if (onSASDisplay) {
      await onSASDisplay({ sas: hs.sasStr, formatted: `${hs.sasStr.slice(0, 3)} ${hs.sasStr.slice(3)}` });
    }
    zeroBytes(ephB.privateKey);
    zeroBytes(shared);
    return { roomId: parsed.roomId, pipeId: joined.pipe_id, roomToken, seq, hs, mode, purpose };
  } catch (err) {
    zeroBytes(ephB.privateKey);
    throw err;
  }
}

// ============================================================================
// Flow 1: Device Binding (Supports Both Spool Enabled & --spool=off)
// ============================================================================

async function buildSelfBindPayload(client, caps, label, platform, signal) {
  const id = await client.getIdentity();
  const issuedAt = Math.floor(Date.now() / 1000);
  const cardSig = await signDeviceCard(id.signSeed, id.signPk, id.kemPk, issuedAt);
  const deviceCard = {
    device_id: id.deviceId,
    sign_pk: bytesToB64u(id.signPk),
    kem_pk: bytesToB64u(id.kemPk),
    issued_at: issuedAt,
    card_sig: bytesToB64u(cardSig),
    label: label || client.label,
    platform: platform || client.platform,
  };

  let mailbox = null;
  let inboundTokenId = null;
  if (caps?.spool?.enabled) {
    const mb = await client.getMailboxIdentity();
    await client.registerMailbox({ signal });
    const rawDepositToken = bytesToB64u(randomBytes(32));
    inboundTokenId = `dt_${bytesToHex(randomBytes(8))}`;
    const tokenHashHex = await hashDepositToken(rawDepositToken);
    await client._signedRequest({
      method: 'POST',
      path: `/v1/mailboxes/${mb.mailboxId}/deposit-tokens`,
      jsonBody: { token_id: inboundTokenId, token_hash_hex: tokenHashHex },
      signMailbox: true,
      mailboxId: mb.mailboxId,
      signal,
    });
    mailbox = {
      relay_origin: client.relay.origin,
      mailbox_id: mb.mailboxId,
      deposit_token: rawDepositToken,
    };
  }

  return {
    payload: mailbox ? { device_card: deviceCard, mailbox } : { device_card: deviceCard, mailbox: null },
    inboundTokenId,
  };
}

async function storePeerBindPayload(client, peerPayload, inboundTokenId) {
  const dc = peerPayload?.device_card;
  if (!dc || !(await verifyDeviceCard(dc))) {
    throw new SyncError(ErrorCode.ERR_CRYPTO_SIGNATURE_INVALID, 'peer DeviceCard signature verification failed');
  }
  const mb = peerPayload.mailbox ?? null;
  const peerRelayOrigin = mb?.relay_origin ? canonicalizeRelayOrigin(mb.relay_origin).origin : client.relay.origin;
  const peerRelayId = await deriveRelayId(peerRelayOrigin);
  const card = {
    device_id: dc.device_id,
    label: dc.label || 'Peer Device',
    platform: dc.platform || 'unknown',
    sign_pk: dc.sign_pk,
    kem_pk: dc.kem_pk,
    issued_at: dc.issued_at,
    card_sig: dc.card_sig,
    relay_origin: peerRelayOrigin,
    relay_id: peerRelayId,
    mailbox_id: mb?.mailbox_id ?? null,
    outbound_deposit_token: mb?.deposit_token ?? null,
    inbound_token_id: inboundTokenId ?? null,
    paired_at: Math.floor(Date.now() / 1000),
    revoked: false,
  };
  await client.keyStore.putDevice(card);
  return card;
}

function encodePairBindMessage(ctBytes) {
  // JSON envelope matching Go SDK (board #41): {"proto_v":1,"op":"pair_bind","ct":"<b64u>"}
  return {
    proto_v: PROTO_VERSION,
    op: 'pair_bind',
    ct: bytesToB64u(ctBytes),
  };
}

function extractPairBindCiphertext(msgB64) {
  const raw = b64uToBytes(msgB64);
  if (raw.length > 0 && raw[0] === 0x7b /* '{' */) {
    try {
      const parsed = JSON.parse(utf8Decode(raw));
      if (parsed && typeof parsed.ct === 'string') return b64uToBytes(parsed.ct);
      if (parsed && typeof parsed.bind_ct === 'string') return b64uToBytes(parsed.bind_ct);
    } catch { /* fall through to raw ciphertext */ }
  }
  return raw;
}

export async function startDeviceBindImpl(client, opts = {}) {
  const caps = await client.capabilities({ signal: opts.signal });
  const { roomId, roomToken, seq: s0, hs } = await runFlow1Initiator(client, {
    purpose: 'pair',
    mode: opts.mode ?? 1,
    includeRelay: opts.includeRelay ?? false,
    onOfferReady: opts.onOfferReady,
    onSASInput: opts.onSASInput,
    timeoutMs: opts.timeoutMs,
    preferPoll: opts.preferPoll,
    signal: opts.signal,
  });
  try {
    const { payload, inboundTokenId } = await buildSelfBindPayload(client, caps, opts.label, opts.platform, opts.signal);
    const ctA = await sealPairBindPayload(hs.sessionKey, hs.prk, hs.th, 'a', payload);
    const sent = await postRoomMessage(client, roomId, roomToken, 'handshake', encodePairBindMessage(ctA), opts.signal);
    const { msg: peerMsg } = await waitRoomMessage(
      client, roomId, roomToken, Math.max(s0, sent.seq),
      (m) => m.from === 'receiver' && m.kind === 'handshake',
      { timeoutMs: opts.timeoutMs, preferPoll: opts.preferPoll, signal: opts.signal },
    );
    const peerCt = extractPairBindCiphertext(peerMsg.msg_b64);
    const peerPayload = await openPairBindPayload(hs.sessionKey, hs.prk, hs.th, 'b', peerCt);
    const card = await storePeerBindPayload(client, peerPayload, inboundTokenId);
    await closeRoom(client, roomId, roomToken, 'completed');
    return card;
  } finally {
    zeroBytes(hs.sessionKey);
    zeroBytes(hs.prk);
  }
}

export async function acceptDeviceBindImpl(client, pairInput, opts = {}) {
  const caps = await client.capabilities({ signal: opts.signal });
  const { roomId, roomToken, seq: s0, hs } = await runFlow1Responder(client, pairInput, {
    expectedPurpose: 'pair',
    onSASDisplay: opts.onSASDisplay,
    timeoutMs: opts.timeoutMs,
    preferPoll: opts.preferPoll,
    signal: opts.signal,
  });
  try {
    const { msg: peerMsg } = await waitRoomMessage(
      client, roomId, roomToken, s0,
      (m) => m.from === 'sender' && m.kind === 'handshake',
      { timeoutMs: opts.timeoutMs, preferPoll: opts.preferPoll, signal: opts.signal },
    );
    const peerCt = extractPairBindCiphertext(peerMsg.msg_b64);
    const peerPayload = await openPairBindPayload(hs.sessionKey, hs.prk, hs.th, 'a', peerCt);
    const { payload, inboundTokenId } = await buildSelfBindPayload(client, caps, opts.label, opts.platform, opts.signal);
    const ctB = await sealPairBindPayload(hs.sessionKey, hs.prk, hs.th, 'b', payload);
    await postRoomMessage(client, roomId, roomToken, 'handshake', encodePairBindMessage(ctB), opts.signal);
    const card = await storePeerBindPayload(client, peerPayload, inboundTokenId);
    // Do NOT close room here: initiator closes room after reading & verifying ctB (prevents wipe race).
    return card;
  } finally {
    zeroBytes(hs.sessionKey);
    zeroBytes(hs.prk);
  }
}
