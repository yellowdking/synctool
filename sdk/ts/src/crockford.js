// Standard Crockford Base32 encoding/decoding for synctool-v1 8-char room_id (5 random bytes = 40 bits).
// Alphabet: 0123456789ABCDEFGHJKMNPQRSTVWXYZ (exact 32 chars, no I/L/O/U).

export const CROCKFORD_ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
export const ROOM_ID_BYTES = 5;
export const ROOM_ID_LENGTH = 8;

const DECODE_MAP = new Int8Array(128).fill(-1);
for (let i = 0; i < CROCKFORD_ALPHABET.length; i++) {
  DECODE_MAP[CROCKFORD_ALPHABET.charCodeAt(i)] = i;
}

/**
 * Encode exactly 5 bytes (40 bits, big-endian) into an 8-character uppercase Crockford Base32 room_id.
 * @param {Uint8Array} bytes
 * @returns {string}
 */
export function encodeRoomId(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length !== ROOM_ID_BYTES) {
    throw new RangeError(`room_id input must be exactly ${ROOM_ID_BYTES} bytes`);
  }
  const b0 = bytes[0];
  const b1 = bytes[1];
  const b2 = bytes[2];
  const b3 = bytes[3];
  const b4 = bytes[4];

  // 40 bits split big-endian into eight 5-bit groups:
  // [0..4] [5..9] [10..14] [15..19] [20..24] [25..29] [30..34] [35..39]
  const out = new Array(ROOM_ID_LENGTH);
  out[0] = CROCKFORD_ALPHABET[(b0 >>> 3) & 0x1f];
  out[1] = CROCKFORD_ALPHABET[((b0 & 0x07) << 2) | (b1 >>> 6)];
  out[2] = CROCKFORD_ALPHABET[(b1 >>> 1) & 0x1f];
  out[3] = CROCKFORD_ALPHABET[((b1 & 0x01) << 4) | (b2 >>> 4)];
  out[4] = CROCKFORD_ALPHABET[((b2 & 0x0f) << 1) | (b3 >>> 7)];
  out[5] = CROCKFORD_ALPHABET[(b3 >>> 2) & 0x1f];
  out[6] = CROCKFORD_ALPHABET[((b3 & 0x03) << 3) | (b4 >>> 5)];
  out[7] = CROCKFORD_ALPHABET[b4 & 0x1f];
  return out.join('');
}

/**
 * Normalize a user-supplied room code:
 * strip whitespace and '-', uppercase, map O->0, I->1, L->1, and reject any non-alphabet characters or wrong length.
 * @param {string} input
 * @returns {string} Canonical 8-char uppercase room_id (without hyphens)
 */
export function normalizeRoomId(input) {
  if (typeof input !== 'string') {
    throw new Error('room_id must be a string');
  }
  let normalized = '';
  for (let i = 0; i < input.length; i++) {
    const rawCode = input.charCodeAt(i);
    if (rawCode >= 128) {
      throw new Error(`invalid non-ASCII character in room_id: ${JSON.stringify(input[i])}`);
    }
    const ch = input[i];
    if (ch === '-' || ch === ' ' || ch === '\t' || ch === '\r' || ch === '\n') {
      continue;
    }
    let upper = ch.toUpperCase();
    if (upper === 'O') upper = '0';
    else if (upper === 'I' || upper === 'L') upper = '1';

    const code = upper.charCodeAt(0);
    if (upper.length !== 1 || code >= 128 || DECODE_MAP[code] < 0) {
      throw new Error(`invalid Crockford Base32 character in room_id: ${JSON.stringify(ch)}`);
    }
    normalized += upper;
  }
  if (normalized.length !== ROOM_ID_LENGTH) {
    throw new Error(`room_id must be exactly ${ROOM_ID_LENGTH} characters after normalization, got ${normalized.length}`);
  }
  return normalized;
}

/**
 * Decode an 8-character Crockford Base32 room_id (accepts hyphens/whitespace/case/O/I/L per spec) into 5 bytes.
 * @param {string} input
 * @returns {Uint8Array}
 */
export function decodeRoomId(input) {
  const canonical = normalizeRoomId(input);
  const v = new Uint8Array(ROOM_ID_LENGTH);
  for (let i = 0; i < ROOM_ID_LENGTH; i++) {
    v[i] = DECODE_MAP[canonical.charCodeAt(i)];
  }
  const out = new Uint8Array(ROOM_ID_BYTES);
  out[0] = (v[0] << 3) | (v[1] >>> 2);
  out[1] = ((v[1] & 0x03) << 6) | (v[2] << 1) | (v[3] >>> 4);
  out[2] = ((v[3] & 0x0f) << 4) | (v[4] >>> 1);
  out[3] = ((v[4] & 0x01) << 7) | (v[5] << 2) | (v[6] >>> 3);
  out[4] = ((v[6] & 0x07) << 5) | v[7];
  return out;
}

/**
 * Validate whether a string is a valid room_id (strict or after normalization).
 * @param {string} input
 * @param {{ strict?: boolean }} [options]
 * @returns {boolean}
 */
export function isValidRoomId(input, options = {}) {
  if (typeof input !== 'string') return false;
  if (options.strict) {
    if (input.length !== ROOM_ID_LENGTH) return false;
    for (let i = 0; i < ROOM_ID_LENGTH; i++) {
      const code = input.charCodeAt(i);
      if (code >= 128 || DECODE_MAP[code] < 0) return false;
    }
    return true;
  }
  try {
    normalizeRoomId(input);
    return true;
  } catch {
    return false;
  }
}

/**
 * Format canonical 8-char room_id for human display as "XXXX-XXXX".
 * @param {string} roomId
 * @returns {string}
 */
export function formatRoomId(roomId) {
  const canonical = normalizeRoomId(roomId);
  return `${canonical.slice(0, 4)}-${canonical.slice(4)}`;
}

/**
 * Generate a fresh CSPRNG 8-character canonical room_id (40 bits entropy, zero modulo bias).
 * @returns {string}
 */
export function generateRoomId() {
  const raw = new Uint8Array(ROOM_ID_BYTES);
  globalThis.crypto.getRandomValues(raw);
  return encodeRoomId(raw);
}
