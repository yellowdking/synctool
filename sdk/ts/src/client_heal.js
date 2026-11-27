// Self-healing mailbox synchronization, ergonomic helpers & unified Mode A room receive dispatch.

import { normalizeRoomId } from './crockford.js';
import { PROTO_VERSION, b64uToBytes, bytesToB64u, utf8Decode } from './crypto.js';
import { ErrorCode, SyncError, parcelText, parsePairURI, relayProfileFromEnv } from './envelope.js';
import { isNodeRuntime } from './client_transport.js';
import { closeRoom } from './client_pair.js';
import { receiveDirectJoinedImpl, receiveOneShotJoinedImpl } from './client_pipe.js';
import { NodeFileKeyStore } from './keystore_node.js';

/**
 * Resolve a trusted non-revoked peer DeviceCard by exact device_id, prefix, or case-insensitive label.
 */
export async function resolveDeviceCard(keyStore, query) {
  const q = typeof query === 'string' ? query.trim() : '';
  if (!q) {
    throw new SyncError(ErrorCode.ERR_BAD_REQUEST, 'empty target device id or label');
  }
  const exact = await keyStore.getDevice(q.toLowerCase());
  if (exact && !exact.revoked) return exact;

  const cards = (await keyStore.listDevices()).filter((c) => !c.revoked);
  const qLower = q.toLowerCase();
  const matches = cards.filter(
    (c) => String(c.label || '').toLowerCase() === qLower || String(c.device_id || '').toLowerCase().startsWith(qLower),
  );
  if (matches.length === 1) return matches[0];
  if (matches.length > 1) {
    throw new SyncError(ErrorCode.ERR_CONFLICT, `ambiguous device label or prefix: "${q}"`);
  }
  throw new SyncError(ErrorCode.ERR_DEVICE_UNTRUSTED, `target device not found or untrusted: "${q}"`);
}

/**
 * Idempotently register this device's blinded mailbox and restore all active per-peer deposit token hashes
 * from KeyStore (1-RTT atomic restore on v1.1+ relays, with per-token POST fallback for v1.0 relays/mocks).
 */
export async function syncMailboxImpl(client, opts = {}) {
  const [mb, relayId, cards] = await Promise.all([
    client.getMailboxIdentity(),
    client.getRelayId(),
    client.keyStore.listDevices(),
  ]);

  const specs = [];
  const seenIds = new Set();
  for (const card of cards) {
    if (card.revoked || !card.inbound_token_id || typeof card.inbound_token_hash !== 'string' || card.inbound_token_hash.length !== 64) {
      continue;
    }
    if (card.relay_id && card.relay_id !== relayId) continue;
    if (seenIds.has(card.inbound_token_id)) continue;
    seenIds.add(card.inbound_token_id);
    specs.push({
      token_id: card.inbound_token_id,
      token_hash_hex: card.inbound_token_hash.toLowerCase(),
    });
    if (specs.length >= 16) break;
  }

  let regData;
  try {
    const res = await client._signedRequest({
      method: 'PUT',
      path: `/v1/mailboxes/${mb.mailboxId}`,
      jsonBody: {
        auth_pk_b64: bytesToB64u(mb.mailboxAuthPk),
        ...(specs.length > 0 ? { deposit_tokens: specs } : {}),
      },
      signMailbox: true,
      mailboxId: mb.mailboxId,
      signal: opts.signal,
    });
    regData = await res.json();
  } catch (err) {
    if (!opts.throwOnDisabled && err instanceof SyncError && err.code === ErrorCode.ERR_SPOOL_DISABLED) {
      return { mailbox_id: mb.mailboxId, registered: false, deposit_token_count: 0 };
    }
    throw err;
  }

  if (specs.length > 0 && (regData?.deposit_token_count ?? 0) < specs.length) {
    for (const sp of specs) {
      try {
        await client._signedRequest({
          method: 'POST',
          path: `/v1/mailboxes/${mb.mailboxId}/deposit-tokens`,
          jsonBody: sp,
          signMailbox: true,
          mailboxId: mb.mailboxId,
          signal: opts.signal,
        });
      } catch (err) {
        if (!(err instanceof SyncError && (err.code === ErrorCode.ERR_CONFLICT || err.code === ErrorCode.ERR_SPOOL_DISABLED))) {
          throw err;
        }
      }
    }
    regData = { ...regData, deposit_token_count: Math.max(regData?.deposit_token_count ?? 0, specs.length) };
  }
  return regData;
}

/**
 * Send a zero-boilerplate UTF-8 text parcel to a paired device (by device_id or label).
 */
export async function sendTextImpl(client, targetDeviceOrLabel, text, opts = {}) {
  const card = await resolveDeviceCard(client.keyStore, targetDeviceOrLabel);
  return client.sendToDevice(card.device_id, parcelText(text, client.appId), opts);
}

/**
 * Unified Mode A room receiver (auto-dispatches Flow 2 m=0 direct and Flow 1 m=1/2 oneshot).
 */
export async function receiveFromRoomImpl(client, pairInput, handler, opts = {}) {
  const trimmed = typeof pairInput === 'string' ? pairInput.trim() : '';
  const parsed = trimmed.toLowerCase().startsWith('synctool://pair')
    ? parsePairURI(trimmed)
    : { roomId: normalizeRoomId(trimmed), mode: null, purpose: null, oobSecret: null };

  const joinRes = await client._signedRequest({
    method: 'POST',
    path: `/v1/rooms/${parsed.roomId}/join`,
    jsonBody: {},
    signal: opts.signal,
  });
  const joined = await joinRes.json();
  const roomToken = joined.receiver_token;
  const m1Msg = (joined.messages || []).find((m) => m.from === 'sender' && m.kind === 'handshake');
  if (m1Msg) {
    const m1 = JSON.parse(utf8Decode(b64uToBytes(m1Msg.msg_b64)));
    if (Number.isInteger(m1.proto_v) && m1.proto_v > PROTO_VERSION) {
      await closeRoom(client, parsed.roomId, roomToken, 'verify_failed');
      throw new SyncError(ErrorCode.ERR_UNSUPPORTED_VERSION, `unsupported room M1 proto_v: ${m1.proto_v}`, {
        details: { proto_v: m1.proto_v, supported_proto_v: PROTO_VERSION },
      });
    }
    if (m1.proto_v === PROTO_VERSION && m1.mode === 0 && m1.purpose === 'direct') {
      return receiveDirectJoinedImpl(client, parsed.roomId, joined, m1, handler, opts);
    }
  }
  return receiveOneShotJoinedImpl(client, parsed, joined, handler, opts);
}

/**
 * Construct a SyncClient from standard environment variables (`SYNCTOOL_RELAY`, `SYNCTOOL_APP`, `SYNCTOOL_CONFIG`).
 */
export function createClientFromEnv(SyncClientClass, overrides = {}) {
  const env = typeof process !== 'undefined' && process?.env ? process.env : {};
  const relay = overrides.relay ?? relayProfileFromEnv();
  const appId = overrides.appId ?? (env.SYNCTOOL_APP?.trim() || undefined);
  let keyStore = overrides.keyStore;
  if (!keyStore && isNodeRuntime() && env.SYNCTOOL_CONFIG?.trim()) {
    keyStore = new NodeFileKeyStore(env.SYNCTOOL_CONFIG.trim());
  }
  return new SyncClientClass({
    ...overrides,
    relay,
    ...(appId ? { appId } : {}),
    ...(keyStore ? { keyStore } : {}),
  });
}
