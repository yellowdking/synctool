// Universal Envelope (Parcel / Manifest v1), synctool:// URI parsing & serialization,
// and unified cross-language SyncError & TransferEvent types (spec/ENVELOPE_AND_SDK.md).

import { normalizeRoomId } from './crockford.js';

export const ENVELOPE_VERSION = 1;
export const MAX_MANIFEST_BYTES = 131072; // 128 KiB
export const MAX_INLINE_PAYLOAD_BYTES = 65536; // 64 KiB
export const MAX_BLOBS = 63; // part_id 0 (Manifest) + 1..63 (Blobs) = max 64 parts
export const MAX_BLOB_META_BYTES = 2048;

const UTF8_ENCODER = new TextEncoder();

/** Frozen cross-language error code enumeration (15 wire + 19 client/local = 34 codes). */
export const ErrorCode = Object.freeze({
  // Wire protocol codes (1-to-1 with spec/PROTOCOL.md §4)
  ERR_BAD_REQUEST: 'ERR_BAD_REQUEST',
  ERR_REPLAY_DETECTED: 'ERR_REPLAY_DETECTED',
  ERR_UNAUTHORIZED_TOKEN: 'ERR_UNAUTHORIZED_TOKEN',
  ERR_SPOOL_DISABLED: 'ERR_SPOOL_DISABLED',
  ERR_DOWNLOAD_LIMIT_EXCEEDED: 'ERR_DOWNLOAD_LIMIT_EXCEEDED',
  ERR_NOT_FOUND: 'ERR_NOT_FOUND',
  ERR_CLOCK_SKEW: 'ERR_CLOCK_SKEW',
  ERR_ROOM_BUSY: 'ERR_ROOM_BUSY',
  ERR_INVALID_STATE: 'ERR_INVALID_STATE',
  ERR_CONFLICT: 'ERR_CONFLICT',
  ERR_ROOM_BURNED: 'ERR_ROOM_BURNED',
  ERR_CHUNK_TOO_LARGE: 'ERR_CHUNK_TOO_LARGE',
  ERR_OFFLINE_QUOTA_EXCEEDED: 'ERR_OFFLINE_QUOTA_EXCEEDED',
  ERR_RATE_LIMITED: 'ERR_RATE_LIMITED',
  ERR_PIPE_PEER_TIMEOUT: 'ERR_PIPE_PEER_TIMEOUT',

  // Client transport, crypto & host codes
  ERR_RELAY_UNREACHABLE: 'ERR_RELAY_UNREACHABLE',
  ERR_TLS_PIN_MISMATCH: 'ERR_TLS_PIN_MISMATCH',
  ERR_TLS_CERT_INVALID: 'ERR_TLS_CERT_INVALID',
  ERR_AUTH_FAILED: 'ERR_AUTH_FAILED',
  ERR_HANDSHAKE_TIMEOUT: 'ERR_HANDSHAKE_TIMEOUT',
  ERR_SAS_MISMATCH: 'ERR_SAS_MISMATCH',
  ERR_CRYPTO_HANDSHAKE_FAILED: 'ERR_CRYPTO_HANDSHAKE_FAILED',
  ERR_CRYPTO_DECRYPT_FAILED: 'ERR_CRYPTO_DECRYPT_FAILED',
  ERR_CRYPTO_SIGNATURE_INVALID: 'ERR_CRYPTO_SIGNATURE_INVALID',
  ERR_STREAM_TRUNCATED: 'ERR_STREAM_TRUNCATED',
  ERR_MSG_REPLAY_DETECTED: 'ERR_MSG_REPLAY_DETECTED',
  ERR_HASH_MISMATCH: 'ERR_HASH_MISMATCH',
  ERR_MANIFEST_INVALID: 'ERR_MANIFEST_INVALID',
  ERR_DEVICE_UNTRUSTED: 'ERR_DEVICE_UNTRUSTED',
  ERR_INTERRUPTED_RESUMABLE: 'ERR_INTERRUPTED_RESUMABLE',
  ERR_URI_INVALID: 'ERR_URI_INVALID',
  ERR_KEYSTORE_ERROR: 'ERR_KEYSTORE_ERROR',
  ERR_STORAGE_IO: 'ERR_STORAGE_IO',
  ERR_CANCELLED: 'ERR_CANCELLED',
});

/** Structured cross-language error matching spec/ENVELOPE_AND_SDK.md §4.1. */
export class SyncError extends Error {
  /**
   * @param {string} code
   * @param {string} message
   * @param {{ retryable?: boolean, httpStatus?: number, details?: Record<string, unknown>, cause?: unknown }} [options]
   */
  constructor(code, message, options = {}) {
    super(message, options.cause !== undefined ? { cause: options.cause } : undefined);
    this.name = 'SyncError';
    this.code = code;
    this.retryable = Boolean(options.retryable);
    this.httpStatus = options.httpStatus ?? 0;
    this.details = options.details ?? {};
  }

  toJSON() {
    return {
      code: this.code,
      retryable: this.retryable,
      http_status: this.httpStatus,
      message: this.message,
      details: this.details,
    };
  }
}

const HEX32_RE = /^[0-9a-f]{32}$/;
const HEX64_RE = /^[0-9a-f]{64}$/;
const B64U43_RE = /^[A-Za-z0-9_-]{43}$/;
const B64U22_RE = /^[A-Za-z0-9_-]{22}$/;
const NAMESPACE_RE = /^[a-z0-9][a-z0-9._-]{1,63}$/;
const ROLE_RE = /^[a-z0-9][a-z0-9._-]{0,31}$/;
const ALLOWED_ENCODINGS = new Set(['identity', 'gzip', 'zstd']);

/**
 * Validate a decoded Manifest object strictly against spec/ENVELOPE_AND_SDK.md §2.2.
 * Returns normalized serialized UTF-8 bytes length if valid, otherwise throws SyncError(ERR_MANIFEST_INVALID).
 * @param {any} manifest
 * @param {{ expectedMsgId?: string }} [options]
 */
export function validateManifest(manifest, options = {}) {
  if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest)) {
    throw new SyncError(ErrorCode.ERR_MANIFEST_INVALID, 'manifest must be a JSON object');
  }
  if (manifest.envelope_version !== ENVELOPE_VERSION) {
    throw new SyncError(ErrorCode.ERR_MANIFEST_INVALID, `unsupported envelope_version: ${manifest.envelope_version}`);
  }
  if (typeof manifest.msg_id !== 'string' || !HEX32_RE.test(manifest.msg_id)) {
    throw new SyncError(ErrorCode.ERR_MANIFEST_INVALID, 'manifest.msg_id must be 32 lowercase hex chars');
  }
  if (options.expectedMsgId && manifest.msg_id !== options.expectedMsgId) {
    throw new SyncError(ErrorCode.ERR_MANIFEST_INVALID, 'manifest.msg_id does not match envelope msg_id');
  }
  if (typeof manifest.app_id !== 'string' || !NAMESPACE_RE.test(manifest.app_id)) {
    throw new SyncError(ErrorCode.ERR_MANIFEST_INVALID, 'manifest.app_id is invalid');
  }
  if (typeof manifest.schema !== 'string' || !NAMESPACE_RE.test(manifest.schema)) {
    throw new SyncError(ErrorCode.ERR_MANIFEST_INVALID, 'manifest.schema is invalid');
  }
  if (!Number.isSafeInteger(manifest.created_at) || manifest.created_at < 0) {
    throw new SyncError(ErrorCode.ERR_MANIFEST_INVALID, 'manifest.created_at must be a non-negative integer');
  }

  // sender
  const sender = manifest.sender;
  if (!sender || typeof sender !== 'object' || Array.isArray(sender)) {
    throw new SyncError(ErrorCode.ERR_MANIFEST_INVALID, 'manifest.sender must be an object');
  }
  if (typeof sender.device_id !== 'string' || !HEX32_RE.test(sender.device_id)) {
    throw new SyncError(ErrorCode.ERR_MANIFEST_INVALID, 'manifest.sender.device_id must be 32 lowercase hex chars');
  }
  if (typeof sender.label !== 'string' || sender.label.length < 1 || sender.label.length > 64) {
    throw new SyncError(ErrorCode.ERR_MANIFEST_INVALID, 'manifest.sender.label must be 1..64 chars');
  }
  if (sender.platform !== undefined && typeof sender.platform !== 'string') {
    throw new SyncError(ErrorCode.ERR_MANIFEST_INVALID, 'manifest.sender.platform must be a string');
  }

  // inline_payload
  if (manifest.inline_payload !== undefined && manifest.inline_payload !== null) {
    if (typeof manifest.inline_payload !== 'object' || Array.isArray(manifest.inline_payload)) {
      throw new SyncError(ErrorCode.ERR_MANIFEST_INVALID, 'manifest.inline_payload must be an object or null');
    }
    const inlineBytes = UTF8_ENCODER.encode(JSON.stringify(manifest.inline_payload));
    if (inlineBytes.length > MAX_INLINE_PAYLOAD_BYTES) {
      throw new SyncError(
        ErrorCode.ERR_MANIFEST_INVALID,
        `manifest.inline_payload exceeds ${MAX_INLINE_PAYLOAD_BYTES} bytes (${inlineBytes.length})`,
      );
    }
  }

  // blobs
  if (!Array.isArray(manifest.blobs)) {
    throw new SyncError(ErrorCode.ERR_MANIFEST_INVALID, 'manifest.blobs must be an array');
  }
  if (manifest.blobs.length > MAX_BLOBS) {
    throw new SyncError(ErrorCode.ERR_MANIFEST_INVALID, `manifest.blobs exceeds max ${MAX_BLOBS}`);
  }
  const seenParts = new Set();
  for (let i = 0; i < manifest.blobs.length; i++) {
    const b = manifest.blobs[i];
    if (!b || typeof b !== 'object' || Array.isArray(b)) {
      throw new SyncError(ErrorCode.ERR_MANIFEST_INVALID, `blobs[${i}] must be an object`);
    }
    if (!Number.isInteger(b.part_id) || b.part_id < 1 || b.part_id > MAX_BLOBS) {
      throw new SyncError(ErrorCode.ERR_MANIFEST_INVALID, `blobs[${i}].part_id must be 1..${MAX_BLOBS}`);
    }
    if (seenParts.has(b.part_id)) {
      throw new SyncError(ErrorCode.ERR_MANIFEST_INVALID, `duplicate blobs part_id: ${b.part_id}`);
    }
    seenParts.add(b.part_id);

    if (typeof b.role !== 'string' || !ROLE_RE.test(b.role)) {
      throw new SyncError(ErrorCode.ERR_MANIFEST_INVALID, `blobs[${i}].role is invalid`);
    }
    if (typeof b.name !== 'string' || b.name.length < 1 || b.name.length > 255) {
      throw new SyncError(ErrorCode.ERR_MANIFEST_INVALID, `blobs[${i}].name must be 1..255 chars`);
    }
    if (typeof b.mime !== 'string' || b.mime.length < 1 || b.mime.length > 128) {
      throw new SyncError(ErrorCode.ERR_MANIFEST_INVALID, `blobs[${i}].mime must be 1..128 chars`);
    }
    if (!Number.isSafeInteger(b.size) || b.size < 0) {
      throw new SyncError(ErrorCode.ERR_MANIFEST_INVALID, `blobs[${i}].size must be a non-negative safe integer`);
    }
    if (typeof b.sha256 !== 'string' || !HEX64_RE.test(b.sha256)) {
      throw new SyncError(ErrorCode.ERR_MANIFEST_INVALID, `blobs[${i}].sha256 must be 64 lowercase hex chars`);
    }
    if (typeof b.key !== 'string' || !B64U43_RE.test(b.key)) {
      throw new SyncError(ErrorCode.ERR_MANIFEST_INVALID, `blobs[${i}].key must be 43-char b64u (32B)`);
    }
    if (b.encoding !== undefined && !ALLOWED_ENCODINGS.has(b.encoding)) {
      throw new SyncError(ErrorCode.ERR_MANIFEST_INVALID, `blobs[${i}].encoding is invalid`);
    }
    if (b.meta !== undefined && b.meta !== null) {
      if (typeof b.meta !== 'object' || Array.isArray(b.meta)) {
        throw new SyncError(ErrorCode.ERR_MANIFEST_INVALID, `blobs[${i}].meta must be an object`);
      }
      const metaBytes = UTF8_ENCODER.encode(JSON.stringify(b.meta));
      if (metaBytes.length > MAX_BLOB_META_BYTES) {
        throw new SyncError(ErrorCode.ERR_MANIFEST_INVALID, `blobs[${i}].meta exceeds ${MAX_BLOB_META_BYTES} bytes`);
      }
    }
  }

  const encoded = UTF8_ENCODER.encode(JSON.stringify(manifest));
  if (encoded.length === 0 || encoded.length > MAX_MANIFEST_BYTES) {
    throw new SyncError(
      ErrorCode.ERR_MANIFEST_INVALID,
      `serialized manifest exceeds ${MAX_MANIFEST_BYTES} bytes (${encoded.length})`,
    );
  }
  return encoded;
}

/**
 * Sanitize untrusted display filename from Manifest to prevent path traversal when saving locally.
 * @param {string} name
 * @param {string} [fallback='attachment.bin']
 * @returns {string}
 */
export function sanitizeFileName(name, fallback = 'attachment.bin') {
  if (typeof name !== 'string') return fallback;
  // Strip path components, control chars, NUL, Windows-reserved chars
  const base = name.replace(/^.*[\\/]/, '').trim();
  if (!base || /^\.+$/.test(base)) return fallback;
  let cleaned = base
    .replace(/[\x00-\x1f\x7f<>:"/\\|?*]/g, '_')
    .replace(/\.{2,}/g, '_')
    .trim();
  while (cleaned.startsWith('.')) cleaned = cleaned.slice(1);
  if (!cleaned || /^[._]+$/.test(cleaned)) return fallback;
  return cleaned.slice(0, 200);
}

/**
 * Check if hostname is a bare IPv4 or IPv6 literal.
 * @param {string} host
 * @returns {boolean}
 */
export function isBareIP(host) {
  if (!host) return false;
  const h = host.startsWith('[') && host.endsWith(']') ? host.slice(1, -1) : host;
  // IPv6 literal contains ':'
  if (h.includes(':')) return true;
  // IPv4 literal: 4 decimal octets
  const parts = h.split('.');
  if (parts.length !== 4) return false;
  return parts.every((p) => /^\d{1,3}$/.test(p) && Number(p) <= 255);
}

/**
 * Check if hostname is loopback (127.0.0.1, ::1, localhost).
 * @param {string} host
 * @returns {boolean}
 */
export function isLoopbackHost(host) {
  const h = (host || '').toLowerCase().replace(/^\[|\]$/g, '');
  return h === 'localhost' || h === '127.0.0.1' || h === '::1';
}

/**
 * Canonicalize a relay origin strictly per spec/CRYPTO_AND_AUTH.md §3.3:
 * lowercase scheme://host:port with explicit port, no path/query/fragment, no trailing slash.
 * @param {string} rawUrl
 * @returns {{ origin: string, scheme: string, hostname: string, port: number }}
 */
export function canonicalizeRelayOrigin(rawUrl) {
  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch {
    throw new SyncError(ErrorCode.ERR_URI_INVALID, 'invalid relay URL');
  }
  const scheme = parsed.protocol.replace(/:$/, '').toLowerCase();
  if (scheme !== 'https' && !(scheme === 'http' && isLoopbackHost(parsed.hostname))) {
    throw new SyncError(
      ErrorCode.ERR_URI_INVALID,
      `relay URL must use https:// (http:// only allowed for loopback), got ${scheme}://`,
    );
  }
  if ((parsed.pathname && parsed.pathname !== '/') || parsed.search || parsed.hash) {
    throw new SyncError(ErrorCode.ERR_URI_INVALID, 'relay URL must not contain path, query, or fragment');
  }
  const hostname = parsed.hostname.toLowerCase();
  if (!hostname) {
    throw new SyncError(ErrorCode.ERR_URI_INVALID, 'relay URL missing hostname');
  }
  const port = parsed.port ? Number(parsed.port) : scheme === 'https' ? 443 : 80;
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new SyncError(ErrorCode.ERR_URI_INVALID, 'relay URL has invalid port');
  }
  const formattedHost = hostname.includes(':') && !hostname.startsWith('[') ? `[${hostname}]` : hostname;
  return {
    origin: `${scheme}://${formattedHost}:${port}`,
    scheme,
    hostname,
    port,
  };
}

/**
 * Parse a query/fragment "a=1&b=2" string into a Map without logging secrets.
 * @param {string} str
 * @returns {Map<string, string>}
 */
function parseKV(str) {
  const map = new Map();
  if (!str) return map;
  for (const part of str.split('&')) {
    if (!part) continue;
    const idx = part.indexOf('=');
    if (idx < 0) {
      map.set(decodeURIComponent(part), '');
    } else {
      const k = decodeURIComponent(part.slice(0, idx));
      const v = decodeURIComponent(part.slice(idx + 1));
      map.set(k, v);
    }
  }
  return map;
}

/**
 * Parse `synctool://relay?v=1&u=<origin>[&pin=<64hex>]#k=<access_key>` per spec/ENVELOPE_AND_SDK.md §3.1.
 * @param {string} uri
 */
export function parseRelayURI(uri) {
  if (typeof uri !== 'string' || !uri.startsWith('synctool://relay')) {
    throw new SyncError(ErrorCode.ERR_URI_INVALID, 'relay URI must start with synctool://relay');
  }
  const hashIdx = uri.indexOf('#');
  const beforeHash = hashIdx >= 0 ? uri.slice(0, hashIdx) : uri;
  const fragmentStr = hashIdx >= 0 ? uri.slice(hashIdx + 1) : '';
  const qIdx = beforeHash.indexOf('?');
  const pathPart = qIdx >= 0 ? beforeHash.slice('synctool://'.length, qIdx) : beforeHash.slice('synctool://'.length);
  if (pathPart !== 'relay') {
    throw new SyncError(ErrorCode.ERR_URI_INVALID, 'relay URI path must be "relay"');
  }
  const queryStr = qIdx >= 0 ? beforeHash.slice(qIdx + 1) : '';
  const query = parseKV(queryStr);
  const frag = parseKV(fragmentStr);

  const vStr = query.get('v') ?? '1';
  if (vStr !== '1') {
    throw new SyncError(ErrorCode.ERR_URI_INVALID, `unsupported relay URI version: ${vStr}`);
  }
  const rawU = query.get('u');
  if (!rawU) {
    throw new SyncError(ErrorCode.ERR_URI_INVALID, 'relay URI missing required parameter "u"');
  }
  const { origin, scheme, hostname } = canonicalizeRelayOrigin(rawU);

  const pin = query.get('pin') ?? '';
  if (pin) {
    if (!HEX64_RE.test(pin)) {
      throw new SyncError(ErrorCode.ERR_URI_INVALID, 'relay URI "pin" must be 64 lowercase hex chars');
    }
  } else if (scheme === 'https' && isBareIP(hostname)) {
    throw new SyncError(ErrorCode.ERR_URI_INVALID, 'bare IP https relay requires SPKI "pin" (insecure skip-verify is forbidden)');
  }

  const accessKey = frag.get('k') ?? '';
  if (!accessKey || accessKey.length < 32) {
    throw new SyncError(ErrorCode.ERR_URI_INVALID, 'relay URI missing valid fragment "#k=" (min 32 chars)');
  }
  if (query.has('k')) {
    throw new SyncError(ErrorCode.ERR_URI_INVALID, 'access key "k" must be in #fragment, never in query string');
  }

  return {
    version: 1,
    origin,
    tlsMode: pin ? 'spki_pin' : 'system_ca',
    spkiPin: pin || null,
    accessKey,
  };
}

/**
 * Serialize a RelayProfile into canonical `synctool://relay?v=1&u=...[&pin=...]#k=...`.
 * @param {{ origin: string, spkiPin?: string | null, accessKey: string }} profile
 * @returns {string}
 */
export function formatRelayURI(profile) {
  const { origin, scheme, hostname } = canonicalizeRelayOrigin(profile.origin);
  const pin = profile.spkiPin ?? '';
  if (pin && !HEX64_RE.test(pin)) {
    throw new SyncError(ErrorCode.ERR_URI_INVALID, 'spkiPin must be 64 lowercase hex chars');
  }
  if (!pin && scheme === 'https' && isBareIP(hostname)) {
    throw new SyncError(ErrorCode.ERR_URI_INVALID, 'bare IP https relay requires spkiPin');
  }
  if (!profile.accessKey || profile.accessKey.length < 32) {
    throw new SyncError(ErrorCode.ERR_URI_INVALID, 'accessKey must be at least 32 chars');
  }
  let q = `v=1&u=${encodeURIComponent(origin)}`;
  if (pin) q += `&pin=${pin}`;
  return `synctool://relay?${q}#k=${encodeURIComponent(profile.accessKey)}`;
}

/**
 * Parse `synctool://pair?r=<room>&m=<0|1|2>&p=<direct|oneshot|pair>[&v=1][&u=...[&pin=...]][&exp=...][#[s=...][&k=...]]`
 * strictly per spec/ENVELOPE_AND_SDK.md §3.2.
 * @param {string} uri
 */
export function parsePairURI(uri) {
  if (typeof uri !== 'string' || !uri.startsWith('synctool://pair')) {
    throw new SyncError(ErrorCode.ERR_URI_INVALID, 'pair URI must start with synctool://pair');
  }
  const hashIdx = uri.indexOf('#');
  const beforeHash = hashIdx >= 0 ? uri.slice(0, hashIdx) : uri;
  const fragmentStr = hashIdx >= 0 ? uri.slice(hashIdx + 1) : '';
  const qIdx = beforeHash.indexOf('?');
  const pathPart = qIdx >= 0 ? beforeHash.slice('synctool://'.length, qIdx) : beforeHash.slice('synctool://'.length);
  if (pathPart !== 'pair') {
    throw new SyncError(ErrorCode.ERR_URI_INVALID, 'pair URI path must be "pair"');
  }
  const query = parseKV(qIdx >= 0 ? beforeHash.slice(qIdx + 1) : '');
  const frag = parseKV(fragmentStr);

  if (query.has('s') || query.has('k')) {
    throw new SyncError(ErrorCode.ERR_URI_INVALID, 'secrets "s" and "k" must be in #fragment, never in query string');
  }

  const vStr = query.get('v') ?? '1';
  if (vStr !== '1') {
    throw new SyncError(ErrorCode.ERR_URI_INVALID, `unsupported pair URI version: ${vStr}`);
  }

  const rawRoom = query.get('r');
  if (!rawRoom) {
    throw new SyncError(ErrorCode.ERR_URI_INVALID, 'pair URI missing required parameter "r"');
  }
  let roomId;
  try {
    roomId = normalizeRoomId(rawRoom);
  } catch (err) {
    throw new SyncError(ErrorCode.ERR_URI_INVALID, `invalid room_id: ${err.message}`);
  }

  const modeRaw = query.get('m');
  if (modeRaw !== '0' && modeRaw !== '1' && modeRaw !== '2') {
    throw new SyncError(ErrorCode.ERR_URI_INVALID, 'pair URI "m" must be 0, 1, or 2');
  }
  const mode = Number(modeRaw);

  const purpose = query.get('p');
  if (purpose !== 'direct' && purpose !== 'oneshot' && purpose !== 'pair') {
    throw new SyncError(ErrorCode.ERR_URI_INVALID, 'pair URI "p" must be direct, oneshot, or pair');
  }
  if (mode === 0 && purpose !== 'direct') {
    throw new SyncError(ErrorCode.ERR_URI_INVALID, 'mode=0 requires p=direct');
  }
  if (mode !== 0 && purpose === 'direct') {
    throw new SyncError(ErrorCode.ERR_URI_INVALID, 'p=direct requires mode=0');
  }

  const oobSecret = frag.get('s') ?? '';
  if (mode === 1) {
    if (!B64U22_RE.test(oobSecret)) {
      throw new SyncError(ErrorCode.ERR_URI_INVALID, 'mode=1 requires 22-char b64u #s= (16B oob_secret)');
    }
  } else if (oobSecret) {
    throw new SyncError(ErrorCode.ERR_URI_INVALID, `mode=${mode} must NOT contain #s=`);
  }

  let relayOrigin = null;
  let spkiPin = null;
  const rawU = query.get('u');
  const rawPin = query.get('pin') ?? '';
  if (rawU) {
    const parsed = canonicalizeRelayOrigin(rawU);
    relayOrigin = parsed.origin;
    if (rawPin) {
      if (!HEX64_RE.test(rawPin)) {
        throw new SyncError(ErrorCode.ERR_URI_INVALID, 'pair URI "pin" must be 64 lowercase hex chars');
      }
      spkiPin = rawPin;
    } else if (parsed.scheme === 'https' && isBareIP(parsed.hostname)) {
      throw new SyncError(ErrorCode.ERR_URI_INVALID, 'bare IP https relay in pair URI requires SPKI "pin"');
    }
  } else if (rawPin) {
    throw new SyncError(ErrorCode.ERR_URI_INVALID, 'pair URI "pin" requires "u"');
  }

  let expiresAt = null;
  if (query.has('exp')) {
    const expNum = Number(query.get('exp'));
    if (!Number.isSafeInteger(expNum) || expNum <= 0) {
      throw new SyncError(ErrorCode.ERR_URI_INVALID, 'pair URI "exp" must be a positive integer unix timestamp');
    }
    expiresAt = expNum;
  }

  const accessKey = frag.get('k') ?? null;
  if (accessKey !== null && accessKey.length < 32) {
    throw new SyncError(ErrorCode.ERR_URI_INVALID, 'pair URI "#k=" access key must be >= 32 chars');
  }

  return {
    version: 1,
    roomId,
    mode,
    purpose,
    oobSecret: mode === 1 ? oobSecret : null,
    relayOrigin,
    spkiPin,
    accessKey,
    expiresAt,
  };
}

/**
 * Serialize a Pair URI strictly per spec/ENVELOPE_AND_SDK.md §3.2.
 * `#s=` is emitted ONLY for mode=1; entire `#fragment` is omitted if neither `s` nor `k` is present.
 * @param {{
 *   roomId: string,
 *   mode: 0 | 1 | 2,
 *   purpose: 'direct' | 'oneshot' | 'pair',
 *   oobSecret?: string | null,
 *   relayOrigin?: string | null,
 *   spkiPin?: string | null,
 *   accessKey?: string | null,
 *   expiresAt?: number | null,
 * }} opts
 * @returns {string}
 */
export function formatPairURI(opts) {
  const roomId = normalizeRoomId(opts.roomId);
  const mode = opts.mode;
  const purpose = opts.purpose;
  if (mode !== 0 && mode !== 1 && mode !== 2) {
    throw new SyncError(ErrorCode.ERR_URI_INVALID, 'mode must be 0, 1, or 2');
  }
  if (mode === 0 && purpose !== 'direct') {
    throw new SyncError(ErrorCode.ERR_URI_INVALID, 'mode=0 requires purpose=direct');
  }
  if (mode !== 0 && purpose !== 'oneshot' && purpose !== 'pair') {
    throw new SyncError(ErrorCode.ERR_URI_INVALID, 'mode=1/2 requires purpose=oneshot or pair');
  }
  if (mode === 1) {
    if (!opts.oobSecret || !B64U22_RE.test(opts.oobSecret)) {
      throw new SyncError(ErrorCode.ERR_URI_INVALID, 'mode=1 requires 22-char b64u oobSecret');
    }
  } else if (opts.oobSecret) {
    throw new SyncError(ErrorCode.ERR_URI_INVALID, `mode=${mode} must not include oobSecret`);
  }

  const qParts = [`r=${roomId}`, `m=${mode}`, `p=${purpose}`, 'v=1'];
  if (opts.relayOrigin) {
    const parsed = canonicalizeRelayOrigin(opts.relayOrigin);
    qParts.push(`u=${encodeURIComponent(parsed.origin)}`);
    if (opts.spkiPin) {
      if (!HEX64_RE.test(opts.spkiPin)) {
        throw new SyncError(ErrorCode.ERR_URI_INVALID, 'spkiPin must be 64 lowercase hex chars');
      }
      qParts.push(`pin=${opts.spkiPin}`);
    } else if (parsed.scheme === 'https' && isBareIP(parsed.hostname)) {
      throw new SyncError(ErrorCode.ERR_URI_INVALID, 'bare IP https relay requires spkiPin');
    }
  }
  if (opts.expiresAt != null) {
    if (!Number.isSafeInteger(opts.expiresAt) || opts.expiresAt <= 0) {
      throw new SyncError(ErrorCode.ERR_URI_INVALID, 'expiresAt must be a positive integer');
    }
    qParts.push(`exp=${opts.expiresAt}`);
  }

  const fragParts = [];
  if (mode === 1 && opts.oobSecret) {
    fragParts.push(`s=${opts.oobSecret}`);
  }
  if (opts.accessKey) {
    if (opts.accessKey.length < 32) {
      throw new SyncError(ErrorCode.ERR_URI_INVALID, 'accessKey must be >= 32 chars');
    }
    fragParts.push(`k=${encodeURIComponent(opts.accessKey)}`);
  }

  const base = `synctool://pair?${qParts.join('&')}`;
  return fragParts.length > 0 ? `${base}#${fragParts.join('&')}` : base;
}

/**
 * Strip #fragment from a synctool:// URI so it is safe for logging/diagnostics.
 * @param {string} uri
 * @returns {string}
 */
export function redactURI(uri) {
  if (typeof uri !== 'string') return '';
  const idx = uri.indexOf('#');
  return idx >= 0 ? `${uri.slice(0, idx)}#<redacted>` : uri;
}
