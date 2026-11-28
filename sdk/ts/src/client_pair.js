// Internal room signaling, Flow 1A/1B handshake engine (with mandatory Responder onSASConfirm) & bidirectional DeviceBind flows.
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
  isAuthError,
  isSecurityAlert,
  isVersionMismatch,
  parsePairURI,
} from './envelope.js';
import {
  DEFAULT_HANDSHAKE_TIMEOUT_MS,
  DEFAULT_SSE_IDLE_TIMEOUT_MS,
  computeRetryBackoffMs,
  iterateSSE,
  sleepWithSignal,
} from './client_transport.js';

// ============================================================================
// Room Signaling & SSE / Long-Poll Helpers
// ============================================================================

export async function closeRoom(client, roomId, roomToken, reason) {
  if (!roomId || !roomToken) return;
  try {
    await client._signedRequest({
      method: 'POST',
      path: `/v1/rooms/${roomId}/close`,
      roomToken,
      jsonBody: { reason },
      signal: AbortSignal.timeout(5_000),
    });
  } catch {
    // Best-effort cleanup on abort/burn
  }
}

export async function burnOrCloseRoomOnError(client, roomId, roomToken, err, signal) {
  if (!roomId || !roomToken) return;
  if (signal?.aborted || (err instanceof SyncError && err.code === ErrorCode.ERR_CANCELLED)) {
    await closeRoom(client, roomId, roomToken, 'cancelled');
    return;
  }
  if (
    err instanceof SyncError &&
    (err.code === ErrorCode.ERR_ROOM_BURNED ||
      err.code === ErrorCode.ERR_HANDSHAKE_TIMEOUT ||
      err.code === ErrorCode.ERR_NOT_FOUND)
  ) {
    return;
  }
  await closeRoom(client, roomId, roomToken, 'verify_failed');
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

function parseHandshakeJsonB64(msgB64, label) {
  try {
    return JSON.parse(utf8Decode(b64uToBytes(msgB64)));
  } catch (err) {
    throw new SyncError(ErrorCode.ERR_CRYPTO_HANDSHAKE_FAILED, `malformed ${label} handshake message`, { cause: err });
  }
}

function decodeHandshakeFieldB64(str, expectedLen, label) {
  if (typeof str !== 'string') {
    throw new SyncError(ErrorCode.ERR_CRYPTO_HANDSHAKE_FAILED, `missing ${label} in handshake message`);
  }
  let raw;
  try {
    raw = b64uToBytes(str);
  } catch (err) {
    throw new SyncError(ErrorCode.ERR_CRYPTO_HANDSHAKE_FAILED, `invalid base64url ${label} in handshake message`, { cause: err });
  }
  if (raw.length !== expectedLen) {
    zeroBytes(raw);
    throw new SyncError(ErrorCode.ERR_CRYPTO_HANDSHAKE_FAILED, `${label} must be ${expectedLen} bytes, got ${raw.length}`);
  }
  return raw;
}

/**
 * Wait for the next room message matching predicate via SSE (with 60s idle read timeout, 90s reconnect,
 * immediate security/auth error rethrow, and jittered 250ms..5s backoff poll fallback).
 */
export async function waitRoomMessage(
  client,
  roomId,
  roomToken,
  sinceSeq,
  predicate,
  { timeoutMs = DEFAULT_HANDSHAKE_TIMEOUT_MS, preferPoll = false, signal } = {},
) {
  const deadline = Date.now() + timeoutMs;
  let cursor = sinceSeq;
  let usePoll = preferPoll;
  let retryAttempt = 0;

  while (Date.now() < deadline) {
    if (signal?.aborted) throw new SyncError(ErrorCode.ERR_CANCELLED, 'operation cancelled');
    const remainingMs = deadline - Date.now();
    if (remainingMs <= 0) break;
    const remainingSec = Math.max(1, Math.min(20, Math.ceil(remainingMs / 1000)));
    const mode = usePoll ? 'poll' : 'sse';
    const query = usePoll
      ? `/v1/rooms/${roomId}/events?since=${cursor}&mode=poll&wait_sec=${remainingSec}`
      : `/v1/rooms/${roomId}/events?since=${cursor}&mode=sse`;

    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), Math.max(250, remainingMs));
    timer.unref?.();
    const onOuterAbort = () => ctrl.abort();
    signal?.addEventListener('abort', onOuterAbort, { once: true });

    const reqStartMs = Date.now();
    try {
      const res = await client._signedRequest({ method: 'GET', path: query, roomToken, signal: ctrl.signal });
      if (mode === 'poll') {
        const data = await res.json();
        retryAttempt = 0;
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
        let cleanlyRotated = false;
        for await (const ev of iterateSSE(res.body, ctrl.signal, { idleTimeoutMs: DEFAULT_SSE_IDLE_TIMEOUT_MS })) {
          retryAttempt = 0;
          if (ev.event === 'burned') {
            throw new SyncError(ErrorCode.ERR_ROOM_BURNED, `room burned: ${ev.data}`);
          }
          if (ev.event === 'closed') {
            throw new SyncError(ErrorCode.ERR_HANDSHAKE_TIMEOUT, `room closed: ${ev.data}`);
          }
          if (ev.event === 'reconnect') {
            cleanlyRotated = true;
            try {
              const parsed = JSON.parse(ev.data);
              if (typeof parsed.since === 'number') cursor = Math.max(cursor, parsed.since);
            } catch { /* ignore */ }
            break;
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
        // Prevent 0ms spin if SSE returned immediate EOF without a `reconnect` event.
        if (!cleanlyRotated && Date.now() - reqStartMs < 500 && Date.now() < deadline) {
          const left = deadline - Date.now();
          if (left > 0) {
            await sleepWithSignal(computeRetryBackoffMs(retryAttempt++, null, left), signal);
          }
        }
      }
    } catch (err) {
      if (signal?.aborted) throw new SyncError(ErrorCode.ERR_CANCELLED, 'operation cancelled', { cause: err });
      if (
        isAuthError(err) ||
        isSecurityAlert(err) ||
        isVersionMismatch(err) ||
        (err instanceof SyncError &&
          (err.code === ErrorCode.ERR_NOT_FOUND ||
            err.code === ErrorCode.ERR_HANDSHAKE_TIMEOUT ||
            err.code === ErrorCode.ERR_ROOM_BUSY ||
            err.code === ErrorCode.ERR_INVALID_STATE))
      ) {
        throw err;
      }
      if (Date.now() >= deadline) {
        throw new SyncError(ErrorCode.ERR_HANDSHAKE_TIMEOUT, 'timed out waiting for peer handshake message', {
          retryable: true,
          cause: err,
        });
      }
      const switchedFromSSE = !usePoll;
      usePoll = true;
      const left = deadline - Date.now();
      if (left <= 0) break;
      // If SSE failed immediately on proxy rejection, switch to poll on first attempt with minimal delay;
      // otherwise apply full 250ms..5s exponential backoff with jitter.
      if (!switchedFromSSE || retryAttempt > 0) {
        await sleepWithSignal(computeRetryBackoffMs(retryAttempt, err, left), signal);
      }
      retryAttempt++;
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

export async function runFlow1Initiator(
  client,
  {
    purpose,
    mode = 1,
    includeRelay = false,
    ttlSec = 300,
    onOfferReady,
    onSASInput,
    timeoutMs = DEFAULT_HANDSHAKE_TIMEOUT_MS,
    preferPoll = false,
    signal,
  },
) {
  if (mode !== 1 && mode !== 2) {
    throw new SyncError(ErrorCode.ERR_BAD_REQUEST, 'Flow 1 mode must be 1 (qr) or 2 (sas)');
  }
  const roomId = generateRoomId();
  const ephA = await generateX25519KeyPair();
  const nA = randomBytes(32);
  const oobSecret = mode === 1 ? randomBytes(16) : null;
  let roomToken = null;
  let shared = null;

  try {
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
    roomToken = room.sender_token;
    let seq = room.seq ?? 1;

    const pairUri = formatPairURI({
      roomId,
      mode,
      purpose,
      oobSecret: oobSecret ? bytesToB64u(oobSecret) : null,
      relayOrigin: includeRelay ? client.relay.origin : null,
      spkiPin: includeRelay ? client.relay.spkiPin : null,
      spkiPins: includeRelay ? client.relay.spkiPins : null,
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

    // Wait for M2 from receiver
    const { msg: m2Msg, seq: s2 } = await waitRoomMessage(
      client,
      roomId,
      roomToken,
      seq,
      (m) => m.from === 'receiver' && m.kind === 'handshake',
      { timeoutMs, preferPoll, signal },
    );
    seq = s2;
    const m2 = parseHandshakeJsonB64(m2Msg.msg_b64, 'M2');
    if (Number.isInteger(m2.proto_v) && m2.proto_v > PROTO_VERSION) {
      await closeRoom(client, roomId, roomToken, 'verify_failed');
      roomToken = null;
      throw new SyncError(ErrorCode.ERR_UNSUPPORTED_VERSION, `unsupported peer handshake proto_v: ${m2.proto_v}`, {
        details: { proto_v: m2.proto_v, supported_proto_v: PROTO_VERSION },
      });
    }
    if (m2.proto_v !== PROTO_VERSION || m2.mode !== mode) {
      await closeRoom(client, roomId, roomToken, 'verify_failed');
      roomToken = null;
      throw new SyncError(ErrorCode.ERR_CRYPTO_HANDSHAKE_FAILED, 'peer handshake mode/version mismatch');
    }
    const eB = decodeHandshakeFieldB64(m2.e_b, 32, 'e_b');
    const nB = decodeHandshakeFieldB64(m2.n_b, 32, 'n_b');
    shared = await x25519SharedSecret(ephA.privateKey, eB);

    if (mode === 1) {
      const hs = await computeQrOobHandshake({ purpose, roomId, shared, oobSecret, eA: ephA.publicKey, nA, eB, nB });
      const peerMacB = decodeHandshakeFieldB64(m2.mac_b, 32, 'mac_b');
      if (!constantTimeEqual(peerMacB, hs.macB)) {
        zeroBytes(hs.sessionKey);
        zeroBytes(hs.prk);
        await closeRoom(client, roomId, roomToken, 'verify_failed');
        roomToken = null;
        throw new SyncError(ErrorCode.ERR_SAS_MISMATCH, 'QR OOB key confirmation MAC_B mismatch');
      }
      const m3Res = await postRoomMessage(
        client,
        roomId,
        roomToken,
        'handshake',
        { proto_v: PROTO_VERSION, mode: 1, mac_a: bytesToB64u(hs.macA) },
        signal,
      );
      seq = m3Res.seq;
      const finalToken = roomToken;
      roomToken = null;
      return { roomId, pipeId: room.pipe_id, roomToken: finalToken, seq, hs, mode };
    }

    // mode === 2 (Commit-Reveal X25519 + input-style 6-digit SAS)
    const hs = await computeCommitSasHandshake({ purpose, roomId, shared, commitA, eA: ephA.publicKey, nA, eB, nB });
    const m3Res = await postRoomMessage(
      client,
      roomId,
      roomToken,
      'handshake',
      {
        proto_v: PROTO_VERSION,
        mode: 2,
        e_a: bytesToB64u(ephA.publicKey),
        n_a: bytesToB64u(nA),
        mac_a: bytesToB64u(hs.macA),
      },
      signal,
    );
    seq = m3Res.seq;

    // Wait for M4 (mac_b)
    const { msg: m4Msg, seq: s4 } = await waitRoomMessage(
      client,
      roomId,
      roomToken,
      seq,
      (m) => m.from === 'receiver' && m.kind === 'handshake',
      { timeoutMs, preferPoll, signal },
    );
    seq = s4;
    const m4 = parseHandshakeJsonB64(m4Msg.msg_b64, 'M4');
    if (m4.proto_v !== PROTO_VERSION || m4.mode !== 2 || typeof m4.mac_b !== 'string') {
      zeroBytes(hs.sessionKey);
      zeroBytes(hs.prk);
      await closeRoom(client, roomId, roomToken, 'verify_failed');
      roomToken = null;
      throw new SyncError(ErrorCode.ERR_CRYPTO_HANDSHAKE_FAILED, 'invalid M4 handshake frame');
    }
    const peerMacB = decodeHandshakeFieldB64(m4.mac_b, 32, 'mac_b');
    if (!constantTimeEqual(peerMacB, hs.macB)) {
      zeroBytes(hs.sessionKey);
      zeroBytes(hs.prk);
      await closeRoom(client, roomId, roomToken, 'verify_failed');
      roomToken = null;
      throw new SyncError(ErrorCode.ERR_SAS_MISMATCH, 'Commit-SAS key confirmation MAC_B mismatch');
    }

    // Mandatory user input of Bob's 6-digit SAS (up to 2 typo retries per spec/CRYPTO_AND_AUTH.md §4.2)
    if (typeof onSASInput !== 'function') {
      zeroBytes(hs.sessionKey);
      zeroBytes(hs.prk);
      await closeRoom(client, roomId, roomToken, 'verify_failed');
      roomToken = null;
      throw new SyncError(ErrorCode.ERR_SAS_MISMATCH, 'mode=2 requires onSASInput callback to verify 6-digit SAS');
    }
    const expectedSasBytes = utf8Encode(hs.sasStr);
    let verified = false;
    for (let tries = 0; tries < 3; tries++) {
      const entered = await onSASInput({ attempt: tries + 1, maxAttempts: 3 });
      if (entered == null) break; // user rejected
      const cleaned = String(entered).replace(/[\s-]+/g, '');
      if (cleaned.length === 6 && constantTimeEqual(utf8Encode(cleaned), expectedSasBytes)) {
        verified = true;
        break;
      }
    }
    if (!verified) {
      zeroBytes(hs.sessionKey);
      zeroBytes(hs.prk);
      await closeRoom(client, roomId, roomToken, 'verify_failed');
      roomToken = null;
      throw new SyncError(ErrorCode.ERR_SAS_MISMATCH, '6-digit SAS verification failed; room burned');
    }

    const finalToken = roomToken;
    roomToken = null;
    return { roomId, pipeId: room.pipe_id, roomToken: finalToken, seq, hs, mode };
  } catch (err) {
    if (roomToken) {
      await burnOrCloseRoomOnError(client, roomId, roomToken, err, signal);
    }
    throw err;
  } finally {
    zeroBytes(ephA.privateKey);
    zeroBytes(nA);
    zeroBytes(oobSecret);
    zeroBytes(shared);
  }
}

export async function runFlow1Responder(
  client,
  pairInput,
  {
    expectedPurpose,
    preJoined = null,
    onSASDisplay,
    onSASConfirm,
    timeoutMs = DEFAULT_HANDSHAKE_TIMEOUT_MS,
    preferPoll = false,
    signal,
  } = {},
) {
  const trimmedInput = typeof pairInput === 'string' ? pairInput.trim() : '';
  const parsed = typeof pairInput === 'object' && pairInput !== null && pairInput.roomId
    ? pairInput
    : trimmedInput.toLowerCase().startsWith('synctool://pair')
      ? parsePairURI(trimmedInput)
      : { roomId: normalizeRoomId(trimmedInput), mode: 2, purpose: expectedPurpose, oobSecret: null };

  if (expectedPurpose && parsed.purpose && parsed.purpose !== expectedPurpose) {
    throw new SyncError(ErrorCode.ERR_BAD_REQUEST, `expected purpose=${expectedPurpose}, got ${parsed.purpose}`);
  }

  // Join without msg_b64 first to read and lock M1 (PROTOCOL.md §5.2)
  let joined = preJoined;
  if (!joined) {
    const joinRes = await client._signedRequest({
      method: 'POST',
      path: `/v1/rooms/${parsed.roomId}/join`,
      jsonBody: {},
      signal,
    });
    joined = await joinRes.json();
  }
  let roomToken = joined.receiver_token;
  let seq = joined.seq ?? 0;

  const ephB = await generateX25519KeyPair();
  const nB = randomBytes(32);
  let shared = null;
  let oobBytes = null;

  try {
    let m1Msg = (joined.messages || []).find((m) => m.from === 'sender' && m.kind === 'handshake');
    if (!m1Msg) {
      const waited = await waitRoomMessage(
        client,
        parsed.roomId,
        roomToken,
        seq,
        (m) => m.from === 'sender' && m.kind === 'handshake',
        { timeoutMs, preferPoll, signal },
      );
      m1Msg = waited.msg;
      seq = waited.seq;
    }
    const m1 = parseHandshakeJsonB64(m1Msg.msg_b64, 'M1');
    const mode = m1.mode;
    const purpose = m1.purpose;
    if (Number.isInteger(m1.proto_v) && m1.proto_v > PROTO_VERSION) {
      await closeRoom(client, parsed.roomId, roomToken, 'verify_failed');
      roomToken = null;
      throw new SyncError(ErrorCode.ERR_UNSUPPORTED_VERSION, `unsupported M1 proto_v: ${m1.proto_v}`, {
        details: { proto_v: m1.proto_v, supported_proto_v: PROTO_VERSION },
      });
    }
    if (m1.proto_v !== PROTO_VERSION || (mode !== 1 && mode !== 2) || (expectedPurpose && purpose !== expectedPurpose)) {
      await closeRoom(client, parsed.roomId, roomToken, 'verify_failed');
      roomToken = null;
      throw new SyncError(ErrorCode.ERR_CRYPTO_HANDSHAKE_FAILED, 'invalid M1 handshake parameters');
    }

    if (mode === 1) {
      if (!parsed.oobSecret) {
        await closeRoom(client, parsed.roomId, roomToken, 'verify_failed');
        roomToken = null;
        throw new SyncError(ErrorCode.ERR_URI_INVALID, 'room requires mode=1 QR oob_secret (#s=)');
      }
      const eA = decodeHandshakeFieldB64(m1.e_a, 32, 'e_a');
      const nA = decodeHandshakeFieldB64(m1.n_a, 32, 'n_a');
      oobBytes = decodeHandshakeFieldB64(parsed.oobSecret, 16, 'oob_secret');
      shared = await x25519SharedSecret(ephB.privateKey, eA);
      const hs = await computeQrOobHandshake({
        purpose,
        roomId: parsed.roomId,
        shared,
        oobSecret: oobBytes,
        eA,
        nA,
        eB: ephB.publicKey,
        nB,
      });
      const m2Res = await postRoomMessage(
        client,
        parsed.roomId,
        roomToken,
        'handshake',
        {
          proto_v: PROTO_VERSION,
          mode: 1,
          e_b: bytesToB64u(ephB.publicKey),
          n_b: bytesToB64u(nB),
          mac_b: bytesToB64u(hs.macB),
        },
        signal,
      );
      seq = m2Res.seq;

      const { msg: m3Msg, seq: s3 } = await waitRoomMessage(
        client,
        parsed.roomId,
        roomToken,
        seq,
        (m) => m.from === 'sender' && m.kind === 'handshake',
        { timeoutMs, preferPoll, signal },
      );
      seq = s3;
      const m3 = parseHandshakeJsonB64(m3Msg.msg_b64, 'M3');
      if (m3.proto_v !== PROTO_VERSION || m3.mode !== 1 || typeof m3.mac_a !== 'string') {
        zeroBytes(hs.sessionKey);
        zeroBytes(hs.prk);
        await closeRoom(client, parsed.roomId, roomToken, 'verify_failed');
        roomToken = null;
        throw new SyncError(ErrorCode.ERR_CRYPTO_HANDSHAKE_FAILED, 'invalid M3 handshake frame');
      }
      const peerMacA = decodeHandshakeFieldB64(m3.mac_a, 32, 'mac_a');
      if (!constantTimeEqual(peerMacA, hs.macA)) {
        zeroBytes(hs.sessionKey);
        zeroBytes(hs.prk);
        await closeRoom(client, parsed.roomId, roomToken, 'verify_failed');
        roomToken = null;
        throw new SyncError(ErrorCode.ERR_SAS_MISMATCH, 'QR OOB key confirmation MAC_A mismatch');
      }
      const finalToken = roomToken;
      roomToken = null;
      return { roomId: parsed.roomId, pipeId: joined.pipe_id, roomToken: finalToken, seq, hs, mode, purpose };
    }

    // mode === 2 (Commit-Reveal X25519 + Mandatory Responder onSASConfirm — ST-P0-1)
    if (typeof onSASConfirm !== 'function') {
      await closeRoom(client, parsed.roomId, roomToken, 'verify_failed');
      roomToken = null;
      throw new SyncError(
        ErrorCode.ERR_SAS_MISMATCH,
        'mode=2 responder requires onSASConfirm({ sas, formattedSas }) => boolean | Promise<boolean>',
      );
    }

    const commitA = decodeHandshakeFieldB64(m1.commit_a, 32, 'commit_a');
    const m2Res = await postRoomMessage(
      client,
      parsed.roomId,
      roomToken,
      'handshake',
      {
        proto_v: PROTO_VERSION,
        mode: 2,
        e_b: bytesToB64u(ephB.publicKey),
        n_b: bytesToB64u(nB),
      },
      signal,
    );
    seq = m2Res.seq;

    const { msg: m3Msg, seq: s3 } = await waitRoomMessage(
      client,
      parsed.roomId,
      roomToken,
      seq,
      (m) => m.from === 'sender' && m.kind === 'handshake',
      { timeoutMs, preferPoll, signal },
    );
    seq = s3;
    const m3 = parseHandshakeJsonB64(m3Msg.msg_b64, 'M3');
    if (m3.proto_v !== PROTO_VERSION || m3.mode !== 2) {
      await closeRoom(client, parsed.roomId, roomToken, 'verify_failed');
      roomToken = null;
      throw new SyncError(ErrorCode.ERR_CRYPTO_HANDSHAKE_FAILED, 'invalid M3 handshake frame');
    }
    const eA = decodeHandshakeFieldB64(m3.e_a, 32, 'e_a');
    const nA = decodeHandshakeFieldB64(m3.n_a, 32, 'n_a');
    const peerMacA = decodeHandshakeFieldB64(m3.mac_a, 32, 'mac_a');

    // Step 1: verify commitment BEFORE deriving SAS!
    const recomputedCommit = await computeCommitA({ purpose, roomId: parsed.roomId, eA, nA });
    if (!constantTimeEqual(recomputedCommit, commitA)) {
      await closeRoom(client, parsed.roomId, roomToken, 'verify_failed');
      roomToken = null;
      throw new SyncError(ErrorCode.ERR_SAS_MISMATCH, 'Commit-Reveal commit_a verification failed; room burned');
    }

    shared = await x25519SharedSecret(ephB.privateKey, eA);
    const hs = await computeCommitSasHandshake({
      purpose,
      roomId: parsed.roomId,
      shared,
      commitA,
      eA,
      nA,
      eB: ephB.publicKey,
      nB,
    });
    if (!constantTimeEqual(peerMacA, hs.macA)) {
      zeroBytes(hs.sessionKey);
      zeroBytes(hs.prk);
      await closeRoom(client, parsed.roomId, roomToken, 'verify_failed');
      roomToken = null;
      throw new SyncError(ErrorCode.ERR_SAS_MISMATCH, 'Commit-SAS key confirmation MAC_A mismatch');
    }

    const m4Res = await postRoomMessage(
      client,
      parsed.roomId,
      roomToken,
      'handshake',
      {
        proto_v: PROTO_VERSION,
        mode: 2,
        mac_b: bytesToB64u(hs.macB),
      },
      signal,
    );
    seq = m4Res.seq;

    const formattedSas = `${hs.sasStr.slice(0, 3)} ${hs.sasStr.slice(3)}`;
    const sasInfo = { sas: hs.sasStr, formatted: formattedSas, formattedSas };
    if (onSASDisplay) {
      await onSASDisplay(sasInfo);
    }

    let confirmed = false;
    try {
      confirmed = (await onSASConfirm(sasInfo)) === true;
    } catch (confirmErr) {
      zeroBytes(hs.sessionKey);
      zeroBytes(hs.prk);
      await closeRoom(client, parsed.roomId, roomToken, 'verify_failed');
      roomToken = null;
      if (confirmErr instanceof SyncError) throw confirmErr;
      throw new SyncError(ErrorCode.ERR_SAS_MISMATCH, 'responder SAS confirmation rejected; room burned', {
        cause: confirmErr,
      });
    }
    if (!confirmed) {
      zeroBytes(hs.sessionKey);
      zeroBytes(hs.prk);
      await closeRoom(client, parsed.roomId, roomToken, 'verify_failed');
      roomToken = null;
      throw new SyncError(ErrorCode.ERR_SAS_MISMATCH, 'responder rejected 6-digit SAS verification; room burned');
    }

    const finalToken = roomToken;
    roomToken = null;
    return { roomId: parsed.roomId, pipeId: joined.pipe_id, roomToken: finalToken, seq, hs, mode, purpose };
  } catch (err) {
    if (roomToken) {
      await burnOrCloseRoomOnError(client, parsed.roomId, roomToken, err, signal);
    }
    throw err;
  } finally {
    zeroBytes(ephB.privateKey);
    zeroBytes(nB);
    zeroBytes(oobBytes);
    zeroBytes(shared);
  }
}

// ============================================================================
// Flow 1: Device Binding (Supports Both Spool Enabled & --spool=off)
// ============================================================================

async function bestEffortDeleteDepositToken(client, tokenId) {
  if (!tokenId) return true;
  try {
    const mb = await client.getMailboxIdentity();
    await client._signedRequest({
      method: 'DELETE',
      path: `/v1/mailboxes/${mb.mailboxId}/deposit-tokens/${tokenId}`,
      signMailbox: true,
      mailboxId: mb.mailboxId,
      signal: AbortSignal.timeout(5_000),
    });
    return true;
  } catch (err) {
    if (err instanceof SyncError && (err.code === ErrorCode.ERR_NOT_FOUND || err.code === ErrorCode.ERR_SPOOL_DISABLED)) {
      return true;
    }
    return false;
  }
}

async function buildSelfBindPayload(client, caps, label, platform, signal) {
  const id = await client.getIdentity();
  const issuedAt = client._localNowSec(); // ST-P1-6: strictly local clock, never tainted by clockOffsetSec!
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
  let inboundTokenHash = null;
  if (caps?.spool?.enabled) {
    try {
      const mb = await client.getMailboxIdentity();
      const regRes = await client.registerMailbox({ signal });
      if (regRes?.registered !== false) {
        const rawDepositToken = bytesToB64u(randomBytes(32));
        const candidateTokenId = `dt_${bytesToHex(randomBytes(8))}`;
        const tokenHashHex = await hashDepositToken(rawDepositToken);
        await client._signedRequest({
          method: 'POST',
          path: `/v1/mailboxes/${mb.mailboxId}/deposit-tokens`,
          jsonBody: { token_id: candidateTokenId, token_hash_hex: tokenHashHex },
          signMailbox: true,
          mailboxId: mb.mailboxId,
          signal,
        });
        inboundTokenId = candidateTokenId;
        inboundTokenHash = tokenHashHex;
        mailbox = {
          relay_origin: client.relay.origin,
          mailbox_id: mb.mailboxId,
          deposit_token: rawDepositToken,
        };
      }
    } catch (err) {
      // ST-P1-8: gracefully treat 403 ERR_SPOOL_DISABLED as non-fatal (--spool=off relay)
      if (!(err instanceof SyncError && err.code === ErrorCode.ERR_SPOOL_DISABLED)) {
        throw err;
      }
      mailbox = null;
      inboundTokenId = null;
      inboundTokenHash = null;
    }
  }

  return {
    payload: mailbox ? { device_card: deviceCard, mailbox } : { device_card: deviceCard, mailbox: null },
    inboundTokenId,
    inboundTokenHash,
  };
}

async function storePeerBindPayload(client, peerPayload, inboundTokenId, inboundTokenHash) {
  const dc = peerPayload?.device_card;
  if (!dc || !(await verifyDeviceCard(dc))) {
    throw new SyncError(ErrorCode.ERR_CRYPTO_SIGNATURE_INVALID, 'peer DeviceCard signature verification failed');
  }
  const peerDeviceId = dc.device_id.toLowerCase();
  const prevCard = await client.keyStore.getDevice(peerDeviceId);
  const oldTokenId = prevCard?.inbound_token_id && prevCard.inbound_token_id !== inboundTokenId
    ? prevCard.inbound_token_id
    : null;

  const mb = peerPayload.mailbox ?? null;
  const peerRelayOrigin = mb?.relay_origin ? canonicalizeRelayOrigin(mb.relay_origin).origin : client.relay.origin;
  const peerRelayId = await deriveRelayId(peerRelayOrigin);

  let staleTokenIds = Array.isArray(prevCard?.stale_inbound_token_ids)
    ? [...prevCard.stale_inbound_token_ids]
    : [];
  if (oldTokenId) {
    const deleted = await bestEffortDeleteDepositToken(client, oldTokenId);
    if (!deleted && !staleTokenIds.includes(oldTokenId)) {
      staleTokenIds.push(oldTokenId);
    }
  }

  const card = {
    device_id: peerDeviceId,
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
    inbound_token_hash: inboundTokenHash ?? null,
    paired_at: client._localNowSec(),
    revoked: false,
    ...(staleTokenIds.length > 0 ? { stale_inbound_token_ids: staleTokenIds } : {}),
  };
  await client.keyStore.putDevice(card);
  return card;
}

function encodePairBindMessage(ctBytes) {
  return {
    proto_v: PROTO_VERSION,
    op: 'pair_bind',
    ct: bytesToB64u(ctBytes),
  };
}

function extractPairBindCiphertext(msgB64) {
  let raw;
  try {
    raw = b64uToBytes(msgB64);
  } catch (err) {
    throw new SyncError(ErrorCode.ERR_CRYPTO_DECRYPT_FAILED, 'invalid base64url in pair_bind frame', { cause: err });
  }
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
    ttlSec: opts.ttlSec ?? 300,
    onOfferReady: opts.onOfferReady,
    onSASInput: opts.onSASInput,
    timeoutMs: opts.timeoutMs,
    preferPoll: opts.preferPoll,
    signal: opts.signal,
  });
  let createdTokenId = null;
  let saved = false;
  try {
    const { payload, inboundTokenId, inboundTokenHash } = await buildSelfBindPayload(
      client,
      caps,
      opts.label,
      opts.platform,
      opts.signal,
    );
    createdTokenId = inboundTokenId;
    const ctA = await sealPairBindPayload(hs.sessionKey, hs.prk, hs.th, 'a', payload);
    const sent = await postRoomMessage(client, roomId, roomToken, 'handshake', encodePairBindMessage(ctA), opts.signal);
    const { msg: peerMsg } = await waitRoomMessage(
      client,
      roomId,
      roomToken,
      Math.max(s0, sent.seq),
      (m) => m.from === 'receiver' && m.kind === 'handshake',
      { timeoutMs: opts.timeoutMs, preferPoll: opts.preferPoll, signal: opts.signal },
    );
    const peerCt = extractPairBindCiphertext(peerMsg.msg_b64);
    const peerPayload = await openPairBindPayload(hs.sessionKey, hs.prk, hs.th, 'b', peerCt);
    const card = await storePeerBindPayload(client, peerPayload, inboundTokenId, inboundTokenHash);
    saved = true;
    await closeRoom(client, roomId, roomToken, 'completed');
    return card;
  } catch (err) {
    if (!saved && createdTokenId) {
      await bestEffortDeleteDepositToken(client, createdTokenId);
    }
    await burnOrCloseRoomOnError(client, roomId, roomToken, err, opts.signal);
    throw err;
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
    onSASConfirm: opts.onSASConfirm,
    timeoutMs: opts.timeoutMs,
    preferPoll: opts.preferPoll,
    signal: opts.signal,
  });
  let createdTokenId = null;
  let saved = false;
  try {
    const { msg: peerMsg } = await waitRoomMessage(
      client,
      roomId,
      roomToken,
      s0,
      (m) => m.from === 'sender' && m.kind === 'handshake',
      { timeoutMs: opts.timeoutMs, preferPoll: opts.preferPoll, signal: opts.signal },
    );
    const peerCt = extractPairBindCiphertext(peerMsg.msg_b64);
    const peerPayload = await openPairBindPayload(hs.sessionKey, hs.prk, hs.th, 'a', peerCt);
    // Verify peer DeviceCard signature BEFORE issuing any relay deposit_token!
    if (!peerPayload?.device_card || !(await verifyDeviceCard(peerPayload.device_card))) {
      throw new SyncError(ErrorCode.ERR_CRYPTO_SIGNATURE_INVALID, 'peer DeviceCard signature verification failed');
    }
    const { payload, inboundTokenId, inboundTokenHash } = await buildSelfBindPayload(
      client,
      caps,
      opts.label,
      opts.platform,
      opts.signal,
    );
    createdTokenId = inboundTokenId;
    const card = await storePeerBindPayload(client, peerPayload, inboundTokenId, inboundTokenHash);
    saved = true;
    const ctB = await sealPairBindPayload(hs.sessionKey, hs.prk, hs.th, 'b', payload);
    await postRoomMessage(client, roomId, roomToken, 'handshake', encodePairBindMessage(ctB), opts.signal);
    // Do NOT close room here: initiator closes room after reading & verifying ctB (prevents wipe race).
    return card;
  } catch (err) {
    if (!saved && createdTokenId) {
      await bestEffortDeleteDepositToken(client, createdTokenId);
    }
    await burnOrCloseRoomOnError(client, roomId, roomToken, err, opts.signal);
    throw err;
  } finally {
    zeroBytes(hs.sessionKey);
    zeroBytes(hs.prk);
  }
}
