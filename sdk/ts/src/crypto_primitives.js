// Zero-dependency WebCrypto primitives, RFC 8410 Curve25519 DER wrapping, and Master Seed HKDF derivation
// (spec/CRYPTO_AND_AUTH.md §2–§3). Works natively in Node 20+, Deno, Bun, Chrome/Edge 137+, Firefox 130+, Safari 17+
// (legacy WebViews supported via setCryptoProvider).

import { ErrorCode, SyncError } from './errors.js';

export const PROTO_VERSION = 1;
export const CHUNK_PLAINTEXT_MAX = 65536; // 64 KiB
export const AEAD_TAG_LEN = 16;
export const CHUNK_CIPHERTEXT_MAX = CHUNK_PLAINTEXT_MAX + AEAD_TAG_LEN; // 65,552 B
export const MANIFEST_PAD_BUCKET = 4096; // 4 KiB
export const CLEAR_HEADER_LEN = 56;
export const SEALED_BOX_LEN = 152;
export const SEALED_HEADER_LEN = CLEAR_HEADER_LEN + SEALED_BOX_LEN; // 208 B

const UTF8_ENC = new TextEncoder();
const UTF8_DEC = new TextDecoder('utf-8', { fatal: true });

// RFC 8410 fixed DER prefixes (spec/CRYPTO_AND_AUTH.md §2.2)
export const ED25519_PKCS8_PREFIX = hexToBytes('302e020100300506032b657004220420');
export const X25519_PKCS8_PREFIX = hexToBytes('302e020100300506032b656e04220420');
export const ED25519_SPKI_PREFIX = hexToBytes('302a300506032b6570032100');
export const X25519_SPKI_PREFIX = hexToBytes('302a300506032b656e032100');

// Ed25519 group constants for strict canonical S < L & small-order torsion PK rejection (RFC 8032 §5.1.3)
const ED25519_P = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffedn;
const ED25519_L = 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3edn;
const ED25519_ORDER8_Y1 = 0x05fc536d880238b13933c6d305acdfd5f098eff289f4c345b027b2c28f95e826n;
const ED25519_ORDER8_Y2 = ED25519_P - ED25519_ORDER8_Y1;

// 1-time cached KAT vectors for WebCrypto PKCS#8 -> JWK.x derivation (RFC 8032 §7.1 Test 1 & RFC 7748 §6.1)
const KAT_ED25519_SEED = hexToBytes('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60');
const KAT_ED25519_PK = hexToBytes('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a');
const KAT_X25519_SK = hexToBytes('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a');
const KAT_X25519_PK = hexToBytes('8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a');

/** @type {Promise<void> | null} */
let ed25519KatPromise = null;
/** @type {Promise<void> | null} */
let x25519KatPromise = null;

/** @type {any} */
let customCryptoProvider = null;

/**
 * Optionally inject a custom Curve25519 provider (for legacy WebViews lacking WebCrypto X25519/Ed25519).
 * Pass null to reset back to 100% native WebCrypto.
 * @param {any} provider
 */
export function setCryptoProvider(provider) {
  customCryptoProvider = provider ?? null;
  ed25519KatPromise = null;
  x25519KatPromise = null;
}

function getSubtle() {
  const s = globalThis.crypto?.subtle;
  if (!s) {
    throw new SyncError(ErrorCode.ERR_CRYPTO_HANDSHAKE_FAILED, 'WebCrypto SubtleCrypto is not available in this runtime');
  }
  return s;
}

function wrapWebCryptoError(opName, err) {
  if (err instanceof SyncError) return err;
  return new SyncError(
    ErrorCode.ERR_CRYPTO_HANDSHAKE_FAILED,
    `WebCrypto ${opName} failed (${err?.name || 'Error'}: ${err?.message || err}); register setCryptoProvider() on legacy WebViews`,
    { cause: err },
  );
}

// ============================================================================
// Binary & Encoding Primitives
// ============================================================================

/** @param {string} s */
export function utf8Encode(s) {
  return UTF8_ENC.encode(s);
}

/** @param {Uint8Array} b */
export function utf8Decode(b) {
  return UTF8_DEC.decode(b);
}

/** @param {number} n */
export function randomBytes(n) {
  if (!Number.isSafeInteger(n) || n < 0) {
    throw new RangeError(`invalid randomBytes length: ${n}`);
  }
  const out = new Uint8Array(n);
  const maxStep = 65536; // W3C WebCrypto getRandomValues 64 KiB quota per call
  for (let off = 0; off < n; off += maxStep) {
    globalThis.crypto.getRandomValues(out.subarray(off, Math.min(off + maxStep, n)));
  }
  return out;
}

/** @param {Uint8Array} bytes */
export function bytesToHex(bytes) {
  let out = '';
  for (let i = 0; i < bytes.length; i++) {
    out += bytes[i].toString(16).padStart(2, '0');
  }
  return out;
}

/** @param {string} hex */
export function hexToBytes(hex) {
  if (typeof hex !== 'string' || hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) {
    throw new Error('invalid hex string');
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/**
 * Unpadded Base64url encode (RFC 4648 §5) without Node Buffer dependency or stack overflow.
 * @param {Uint8Array} bytes
 * @returns {string}
 */
export function bytesToB64u(bytes) {
  let bin = '';
  const step = 0x8000;
  for (let i = 0; i < bytes.length; i += step) {
    const chunk = bytes.subarray(i, Math.min(i + step, bytes.length));
    bin += String.fromCharCode.apply(null, chunk);
  }
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

/**
 * Strict unpadded Base64url decode (RFC 4648 §5). Rejects padding '=' or illegal characters.
 * @param {string} str
 * @returns {Uint8Array}
 */
export function b64uToBytes(str) {
  if (typeof str !== 'string' || !/^[A-Za-z0-9_-]*$/.test(str) || str.length % 4 === 1) {
    throw new Error('invalid unpadded base64url string');
  }
  const b64 = str.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (str.length % 4)) % 4);
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) {
    out[i] = bin.charCodeAt(i);
  }
  return out;
}

/** @param {...Uint8Array} parts */
export function concatBytes(...parts) {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

/** @param {number} n */
export function u32be(n) {
  if (!Number.isInteger(n) || n < 0 || n > 0xffffffff) {
    throw new RangeError(`uint32 out of range: ${n}`);
  }
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n, false);
  return b;
}

/** @param {Uint8Array} buf @param {number} [offset=0] */
export function readU32be(buf, offset = 0) {
  if (!(buf instanceof Uint8Array) || !Number.isInteger(offset) || offset < 0 || offset + 4 > buf.byteLength) {
    throw new RangeError(`readU32be out of bounds (offset=${offset}, byteLength=${buf?.byteLength})`);
  }
  return new DataView(buf.buffer, buf.byteOffset + offset, 4).getUint32(0, false);
}

/** @param {number | bigint} n */
export function u64be(n) {
  if (typeof n === 'number') {
    if (!Number.isSafeInteger(n) || n < 0) {
      throw new RangeError(`uint64 safe integer out of range: ${n}`);
    }
  } else if (typeof n !== 'bigint') {
    throw new RangeError(`uint64 must be a safe integer or bigint: ${n}`);
  }
  const big = typeof n === 'bigint' ? n : BigInt(n);
  if (big < 0n || big > 0xffffffffffffffffn) {
    throw new RangeError(`uint64 out of range: ${n}`);
  }
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, big, false);
  return b;
}

/** @param {Uint8Array} buf @param {number} [offset=0] */
export function readU64be(buf, offset = 0) {
  if (!(buf instanceof Uint8Array) || !Number.isInteger(offset) || offset < 0 || offset + 8 > buf.byteLength) {
    throw new RangeError(`readU64be out of bounds (offset=${offset}, byteLength=${buf?.byteLength})`);
  }
  const big = new DataView(buf.buffer, buf.byteOffset + offset, 8).getBigUint64(0, false);
  if (big > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new RangeError(`uint64 exceeds Number.MAX_SAFE_INTEGER: ${big}`);
  }
  return Number(big);
}

/**
 * Constant-time byte slice comparison.
 * @param {Uint8Array} a
 * @param {Uint8Array} b
 */
export function constantTimeEqual(a, b) {
  if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array)) return false;
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

/** @param {Uint8Array | null | undefined} buf */
export function zeroBytes(buf) {
  if (buf instanceof Uint8Array) {
    buf.fill(0);
  }
}

/** @param {Uint8Array} bytes */
export function isAllZero(bytes) {
  let acc = 0;
  for (let i = 0; i < bytes.length; i++) {
    acc |= bytes[i];
  }
  return acc === 0;
}

function bytes32LeToBigInt(buf32, offset = 0) {
  let v = 0n;
  for (let i = 31; i >= 0; i--) {
    v = (v << 8n) | BigInt(buf32[offset + i]);
  }
  return v;
}

/**
 * Check if a 32-byte Ed25519 public key is non-canonical (y >= p, -0) or one of the 8 small-order torsion points.
 * @param {Uint8Array} pk32
 * @returns {boolean}
 */
export function isSmallOrderEd25519PublicKey(pk32) {
  if (!(pk32 instanceof Uint8Array) || pk32.length !== 32) return true;
  const raw = bytes32LeToBigInt(pk32, 0);
  const y = raw & ((1n << 255n) - 1n);
  if (y >= ED25519_P) return true;
  if (y === 0n || y === 1n || y === ED25519_P - 1n || y === ED25519_ORDER8_Y1 || y === ED25519_ORDER8_Y2) {
    return true;
  }
  return false;
}

function isCanonicalEd25519Scalar(sig64) {
  const s = bytes32LeToBigInt(sig64, 32);
  return s < ED25519_L;
}

// ============================================================================
// Core Cryptographic Primitives (WebCrypto Native)
// ============================================================================

/** @param {Uint8Array} data */
export async function sha256(data) {
  try {
    const digest = await getSubtle().digest('SHA-256', data);
    return new Uint8Array(digest);
  } catch (err) {
    throw wrapWebCryptoError('SHA-256', err);
  }
}

/**
 * @param {Uint8Array} keyBytes
 * @param {Uint8Array} data
 */
export async function hmacSha256(keyBytes, data) {
  try {
    const subtle = getSubtle();
    const key = await subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const sig = await subtle.sign('HMAC', key, data);
    return new Uint8Array(sig);
  } catch (err) {
    throw wrapWebCryptoError('HMAC-SHA256', err);
  }
}

/**
 * RFC 5869 HKDF-Extract(salt, ikm) = HMAC-SHA256(salt || 0^32, ikm).
 * @param {Uint8Array} salt
 * @param {Uint8Array} ikm
 */
export async function hkdfExtract(salt, ikm) {
  const effectiveSalt = salt && salt.length > 0 ? salt : new Uint8Array(32);
  return hmacSha256(effectiveSalt, ikm);
}

/**
 * RFC 5869 HKDF-Expand(prk, info, length).
 * @param {Uint8Array} prk
 * @param {Uint8Array} info
 * @param {number} length
 */
export async function hkdfExpand(prk, info, length) {
  if (length <= 0 || length > 255 * 32) {
    throw new RangeError(`invalid HKDF-Expand length: ${length}`);
  }
  const n = Math.ceil(length / 32);
  const out = new Uint8Array(n * 32);
  let prev = new Uint8Array(0);
  for (let i = 1; i <= n; i++) {
    const input = concatBytes(prev, info, new Uint8Array([i]));
    prev = await hmacSha256(prk, input);
    out.set(prev, (i - 1) * 32);
  }
  return out.slice(0, length);
}

/**
 * Single-call WebCrypto HKDF(salt, ikm, info, length) — mathematically identical to
 * hkdfExpand(hkdfExtract(salt, ikm), info, length).
 * @param {Uint8Array} salt
 * @param {Uint8Array} ikm
 * @param {Uint8Array} info
 * @param {number} length
 */
export async function hkdfDerive(salt, ikm, info, length) {
  try {
    const subtle = getSubtle();
    const key = await subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
    const bits = await subtle.deriveBits(
      { name: 'HKDF', hash: 'SHA-256', salt, info },
      key,
      length * 8,
    );
    return new Uint8Array(bits);
  } catch (err) {
    throw wrapWebCryptoError('HKDF', err);
  }
}

/**
 * AES-256-GCM Seal. Output is ciphertext || 16B tag.
 * @param {Uint8Array} key32
 * @param {Uint8Array} nonce12
 * @param {Uint8Array} plaintext
 * @param {Uint8Array} aad
 */
export async function aesGcmSeal(key32, nonce12, plaintext, aad) {
  if (key32.length !== 32) throw new RangeError('AES-256-GCM key must be 32 bytes');
  if (nonce12.length !== 12) throw new RangeError('AES-256-GCM nonce must be 12 bytes');
  try {
    const subtle = getSubtle();
    const key = await subtle.importKey('raw', key32, { name: 'AES-GCM' }, false, ['encrypt']);
    const ct = await subtle.encrypt(
      { name: 'AES-GCM', iv: nonce12, additionalData: aad, tagLength: 128 },
      key,
      plaintext,
    );
    return new Uint8Array(ct);
  } catch (err) {
    throw wrapWebCryptoError('AES-GCM seal', err);
  }
}

/**
 * AES-256-GCM Open. Throws SyncError(ERR_CRYPTO_DECRYPT_FAILED) on authentication failure.
 * @param {Uint8Array} key32
 * @param {Uint8Array} nonce12
 * @param {Uint8Array} ciphertextWithTag
 * @param {Uint8Array} aad
 */
export async function aesGcmOpen(key32, nonce12, ciphertextWithTag, aad) {
  if (key32.length !== 32) throw new RangeError('AES-256-GCM key must be 32 bytes');
  if (nonce12.length !== 12) throw new RangeError('AES-256-GCM nonce must be 12 bytes');
  if (ciphertextWithTag.length < AEAD_TAG_LEN) {
    throw new SyncError(ErrorCode.ERR_CRYPTO_DECRYPT_FAILED, 'ciphertext shorter than 16B GCM tag');
  }
  try {
    const subtle = getSubtle();
    const key = await subtle.importKey('raw', key32, { name: 'AES-GCM' }, false, ['decrypt']);
    const pt = await subtle.decrypt(
      { name: 'AES-GCM', iv: nonce12, additionalData: aad, tagLength: 128 },
      key,
      ciphertextWithTag,
    );
    return new Uint8Array(pt);
  } catch (err) {
    throw new SyncError(ErrorCode.ERR_CRYPTO_DECRYPT_FAILED, 'AES-256-GCM authentication failed', { cause: err });
  }
}

// ============================================================================
// RFC 8410 DER Wrapping & Curve25519 (Ed25519 / X25519)
// ============================================================================

/** @param {Uint8Array} seed32 */
export function ed25519SeedToPkcs8(seed32) {
  if (seed32.length !== 32) throw new RangeError('Ed25519 seed must be 32 bytes');
  return concatBytes(ED25519_PKCS8_PREFIX, seed32);
}

/** @param {Uint8Array} sk32 */
export function x25519SkToPkcs8(sk32) {
  if (sk32.length !== 32) throw new RangeError('X25519 private key must be 32 bytes');
  return concatBytes(X25519_PKCS8_PREFIX, sk32);
}

/** @param {Uint8Array} pk32 */
export function ed25519PubToSpki(pk32) {
  if (pk32.length !== 32) throw new RangeError('Ed25519 public key must be 32 bytes');
  return concatBytes(ED25519_SPKI_PREFIX, pk32);
}

/** @param {Uint8Array} pk32 */
export function x25519PubToSpki(pk32) {
  if (pk32.length !== 32) throw new RangeError('X25519 public key must be 32 bytes');
  return concatBytes(X25519_SPKI_PREFIX, pk32);
}

async function deriveEd25519PkViaWebCrypto(subtle, seed32) {
  const pkcs8 = ed25519SeedToPkcs8(seed32);
  try {
    const privKey = await subtle.importKey('pkcs8', pkcs8, { name: 'Ed25519' }, true, ['sign']);
    const jwk = await subtle.exportKey('jwk', privKey);
    if (!jwk?.x) {
      throw new SyncError(ErrorCode.ERR_CRYPTO_HANDSHAKE_FAILED, 'WebCrypto Ed25519 JWK export missing public key x');
    }
    const pk = b64uToBytes(jwk.x);
    if (pk.length !== 32) {
      throw new SyncError(ErrorCode.ERR_CRYPTO_HANDSHAKE_FAILED, 'WebCrypto Ed25519 JWK x has invalid length');
    }
    return pk;
  } catch (err) {
    throw wrapWebCryptoError('Ed25519 key derivation', err);
  } finally {
    zeroBytes(pkcs8);
  }
}

async function deriveX25519PkViaWebCrypto(subtle, sk32) {
  const pkcs8 = x25519SkToPkcs8(sk32);
  try {
    const privKey = await subtle.importKey('pkcs8', pkcs8, { name: 'X25519' }, true, ['deriveBits']);
    const jwk = await subtle.exportKey('jwk', privKey);
    if (!jwk?.x) {
      throw new SyncError(ErrorCode.ERR_CRYPTO_HANDSHAKE_FAILED, 'WebCrypto X25519 JWK export missing public key x');
    }
    const pk = b64uToBytes(jwk.x);
    if (pk.length !== 32) {
      throw new SyncError(ErrorCode.ERR_CRYPTO_HANDSHAKE_FAILED, 'WebCrypto X25519 JWK x has invalid length');
    }
    return pk;
  } catch (err) {
    throw wrapWebCryptoError('X25519 key derivation', err);
  } finally {
    zeroBytes(pkcs8);
  }
}

function ensureEd25519Kat(subtle) {
  if (!ed25519KatPromise) {
    ed25519KatPromise = (async () => {
      const derived = await deriveEd25519PkViaWebCrypto(subtle, KAT_ED25519_SEED);
      if (!constantTimeEqual(derived, KAT_ED25519_PK)) {
        throw new SyncError(
          ErrorCode.ERR_CRYPTO_HANDSHAKE_FAILED,
          'WebCrypto Ed25519 JWK x KAT self-check failed; register setCryptoProvider()',
        );
      }
    })().catch((err) => {
      ed25519KatPromise = null;
      throw err;
    });
  }
  return ed25519KatPromise;
}

function ensureX25519Kat(subtle) {
  if (!x25519KatPromise) {
    x25519KatPromise = (async () => {
      const derived = await deriveX25519PkViaWebCrypto(subtle, KAT_X25519_SK);
      if (!constantTimeEqual(derived, KAT_X25519_PK)) {
        throw new SyncError(
          ErrorCode.ERR_CRYPTO_HANDSHAKE_FAILED,
          'WebCrypto X25519 JWK x KAT self-check failed; register setCryptoProvider()',
        );
      }
    })().catch((err) => {
      x25519KatPromise = null;
      throw err;
    });
  }
  return x25519KatPromise;
}

/**
 * Derive 32B Ed25519 public key from 32B seed using standard WebCrypto (or optional CryptoProvider).
 * @param {Uint8Array} seed32
 * @returns {Promise<{ seed: Uint8Array, publicKey: Uint8Array }>}
 */
export async function ed25519KeyPairFromSeed(seed32) {
  if (seed32.length !== 32) throw new RangeError('Ed25519 seed must be 32 bytes');
  if (customCryptoProvider?.ed25519PublicKeyFromSeed) {
    try {
      const publicKey = new Uint8Array(await customCryptoProvider.ed25519PublicKeyFromSeed(seed32));
      if (publicKey.length !== 32) {
        throw new SyncError(ErrorCode.ERR_CRYPTO_HANDSHAKE_FAILED, 'customCryptoProvider Ed25519 public key must be 32 bytes');
      }
      return { seed: new Uint8Array(seed32), publicKey };
    } catch (err) {
      throw wrapWebCryptoError('custom Ed25519 key derivation', err);
    }
  }
  const subtle = getSubtle();
  await ensureEd25519Kat(subtle);
  const publicKey = await deriveEd25519PkViaWebCrypto(subtle, seed32);
  return { seed: new Uint8Array(seed32), publicKey };
}

/**
 * Derive 32B X25519 public key from 32B private key using standard WebCrypto (or optional CryptoProvider).
 * @param {Uint8Array} sk32
 * @returns {Promise<{ privateKey: Uint8Array, publicKey: Uint8Array }>}
 */
export async function x25519KeyPairFromSk(sk32) {
  if (sk32.length !== 32) throw new RangeError('X25519 private key must be 32 bytes');
  if (customCryptoProvider?.x25519PublicKeyFromSk) {
    try {
      const publicKey = new Uint8Array(await customCryptoProvider.x25519PublicKeyFromSk(sk32));
      if (publicKey.length !== 32) {
        throw new SyncError(ErrorCode.ERR_CRYPTO_HANDSHAKE_FAILED, 'customCryptoProvider X25519 public key must be 32 bytes');
      }
      return { privateKey: new Uint8Array(sk32), publicKey };
    } catch (err) {
      throw wrapWebCryptoError('custom X25519 key derivation', err);
    }
  }
  const subtle = getSubtle();
  await ensureX25519Kat(subtle);
  const publicKey = await deriveX25519PkViaWebCrypto(subtle, sk32);
  return { privateKey: new Uint8Array(sk32), publicKey };
}

/** Generate a fresh CSPRNG X25519 key pair. */
export async function generateX25519KeyPair() {
  const sk = randomBytes(32);
  try {
    return await x25519KeyPairFromSk(sk);
  } finally {
    zeroBytes(sk);
  }
}

/**
 * Compute X25519(sk32, peerPk32). Strictly rejects all-zero shared secrets (low-order points).
 * @param {Uint8Array} sk32
 * @param {Uint8Array} peerPk32
 * @returns {Promise<Uint8Array>}
 */
export async function x25519SharedSecret(sk32, peerPk32) {
  if (!(sk32 instanceof Uint8Array) || !(peerPk32 instanceof Uint8Array) || sk32.length !== 32 || peerPk32.length !== 32) {
    throw new SyncError(ErrorCode.ERR_CRYPTO_HANDSHAKE_FAILED, 'X25519 keys must be 32 bytes');
  }
  let shared;
  try {
    if (customCryptoProvider?.x25519SharedSecret) {
      shared = new Uint8Array(await customCryptoProvider.x25519SharedSecret(sk32, peerPk32));
    } else {
      const subtle = getSubtle();
      await ensureX25519Kat(subtle);
      const pkcs8 = x25519SkToPkcs8(sk32);
      try {
        const privKey = await subtle.importKey('pkcs8', pkcs8, { name: 'X25519' }, false, ['deriveBits']);
        const pubKey = await subtle.importKey('spki', x25519PubToSpki(peerPk32), { name: 'X25519' }, false, []);
        const bits = await subtle.deriveBits({ name: 'X25519', public: pubKey }, privKey, 256);
        shared = new Uint8Array(bits);
      } finally {
        zeroBytes(pkcs8);
      }
    }
  } catch (err) {
    throw wrapWebCryptoError('X25519 key agreement', err);
  }
  if (shared.length !== 32 || isAllZero(shared)) {
    zeroBytes(shared);
    throw new SyncError(ErrorCode.ERR_CRYPTO_HANDSHAKE_FAILED, 'rejected all-zero X25519 shared secret (low-order point)');
  }
  return shared;
}

/**
 * PureEdDSA Ed25519 sign.
 * @param {Uint8Array} seed32
 * @param {Uint8Array} message
 * @returns {Promise<Uint8Array>} 64B signature
 */
export async function ed25519Sign(seed32, message) {
  if (seed32.length !== 32) throw new RangeError('Ed25519 seed must be 32 bytes');
  if (customCryptoProvider?.ed25519Sign) {
    try {
      const sig = new Uint8Array(await customCryptoProvider.ed25519Sign(seed32, message));
      if (sig.length !== 64) {
        throw new SyncError(ErrorCode.ERR_CRYPTO_HANDSHAKE_FAILED, 'customCryptoProvider Ed25519 signature must be 64 bytes');
      }
      return sig;
    } catch (err) {
      throw wrapWebCryptoError('custom Ed25519 sign', err);
    }
  }
  const subtle = getSubtle();
  const pkcs8 = ed25519SeedToPkcs8(seed32);
  try {
    const privKey = await subtle.importKey('pkcs8', pkcs8, { name: 'Ed25519' }, false, ['sign']);
    const sig = await subtle.sign('Ed25519', privKey, message);
    return new Uint8Array(sig);
  } catch (err) {
    throw wrapWebCryptoError('Ed25519 sign', err);
  } finally {
    zeroBytes(pkcs8);
  }
}

/**
 * PureEdDSA Ed25519 verify. Strictly rejects small-order public keys and non-canonical S >= L signatures.
 * @param {Uint8Array} publicKey32
 * @param {Uint8Array} message
 * @param {Uint8Array} signature64
 * @returns {Promise<boolean>}
 */
export async function ed25519Verify(publicKey32, message, signature64) {
  if (!(publicKey32 instanceof Uint8Array) || !(signature64 instanceof Uint8Array)) return false;
  if (publicKey32.length !== 32 || signature64.length !== 64) return false;
  if (isSmallOrderEd25519PublicKey(publicKey32)) return false;
  if (!isCanonicalEd25519Scalar(signature64)) return false;
  try {
    if (customCryptoProvider?.ed25519Verify) {
      return Boolean(await customCryptoProvider.ed25519Verify(publicKey32, message, signature64));
    }
    const subtle = getSubtle();
    const pubKey = await subtle.importKey('spki', ed25519PubToSpki(publicKey32), { name: 'Ed25519' }, false, ['verify']);
    return await subtle.verify('Ed25519', pubKey, signature64, message);
  } catch {
    return false;
  }
}

// ============================================================================
// §3 Master Seed Key Derivation & Deterministic IDs
// ============================================================================

const MASTER_SEED_SALT = utf8Encode('synctool-v1/master-seed-salt');

/** @param {Uint8Array} seed32 */
export async function deriveMasterPRK(seed32) {
  if (seed32.length !== 32) throw new RangeError('device_master_seed must be 32 bytes');
  return hkdfExtract(MASTER_SEED_SALT, seed32);
}

/** @param {string} canonicalRelayOrigin */
export async function deriveRelayId(canonicalRelayOrigin) {
  const hash = await sha256(concatBytes(utf8Encode('synctool-v1/relay-id:'), utf8Encode(canonicalRelayOrigin)));
  return bytesToHex(hash.subarray(0, 16));
}

/** @param {Uint8Array} signPk32 */
export async function deriveDeviceIdRaw(signPk32) {
  const hash = await sha256(concatBytes(utf8Encode('synctool-v1/device-id:'), signPk32));
  return hash.subarray(0, 16);
}

/** @param {Uint8Array} signPk32 */
export async function deriveDeviceId(signPk32) {
  return bytesToHex(await deriveDeviceIdRaw(signPk32));
}

/** @param {Uint8Array} mailboxAuthPk32 */
export async function deriveMailboxId(mailboxAuthPk32) {
  const hash = await sha256(concatBytes(utf8Encode('synctool-v1/mailbox-id:'), mailboxAuthPk32));
  return bytesToHex(hash.subarray(0, 16));
}

/**
 * Derive all device identity keys from single 32B device_master_seed (spec/CRYPTO_AND_AUTH.md §3).
 * @param {Uint8Array} seed32
 */
export async function deriveDeviceIdentity(seed32) {
  const masterPrk = await deriveMasterPRK(seed32);
  const [signSeed, kemSk, localMetaKey] = await Promise.all([
    hkdfExpand(masterPrk, utf8Encode('synctool-v1/ed25519-sign'), 32),
    hkdfExpand(masterPrk, utf8Encode('synctool-v1/x25519-kem'), 32),
    hkdfExpand(masterPrk, utf8Encode('synctool-v1/local-storage-key'), 32),
  ]);
  const [{ publicKey: signPk }, { publicKey: kemPk }] = await Promise.all([
    ed25519KeyPairFromSeed(signSeed),
    x25519KeyPairFromSk(kemSk),
  ]);
  const deviceIdRaw = await deriveDeviceIdRaw(signPk);
  const deviceId = bytesToHex(deviceIdRaw);
  return {
    masterPrk,
    signSeed,
    signPk,
    kemSk,
    kemPk,
    localMetaKey,
    deviceIdRaw,
    deviceId,
  };
}

/**
 * Derive per-relay isolated mailbox ownership keypair and mailbox_id (spec/CRYPTO_AND_AUTH.md §3.2–3.3).
 * @param {Uint8Array} seed32
 * @param {string} relayId
 */
export async function deriveMailboxIdentity(seed32, relayId) {
  if (typeof relayId !== 'string' || !/^[0-9a-f]{32}$/.test(relayId)) {
    throw new SyncError(ErrorCode.ERR_BAD_REQUEST, 'relayId must be 32 lowercase hex chars');
  }
  const masterPrk = await deriveMasterPRK(seed32);
  try {
    const mailboxAuthSeed = await hkdfExpand(
      masterPrk,
      concatBytes(utf8Encode('synctool-v1/mailbox-auth/'), utf8Encode(relayId)),
      32,
    );
    const { publicKey: mailboxAuthPk } = await ed25519KeyPairFromSeed(mailboxAuthSeed);
    const mailboxId = await deriveMailboxId(mailboxAuthPk);
    return {
      mailboxAuthSeed,
      mailboxAuthPk,
      mailboxId,
    };
  } finally {
    zeroBytes(masterPrk);
  }
}

/**
 * Build exact DeviceCard binding signature input (spec/CRYPTO_AND_AUTH.md §3.3).
 * @param {Uint8Array} signPk32
 * @param {Uint8Array} kemPk32
 * @param {number} issuedAt
 */
export function buildDeviceCardSigInput(signPk32, kemPk32, issuedAt) {
  return concatBytes(
    utf8Encode('synctool-v1/device-card\n'),
    signPk32,
    kemPk32,
    u64be(issuedAt),
  );
}

/**
 * Sign a DeviceCard binding (kem_pk owned by sign_pk).
 * @param {Uint8Array} signSeed32
 * @param {Uint8Array} signPk32
 * @param {Uint8Array} kemPk32
 * @param {number} issuedAt
 */
export async function signDeviceCard(signSeed32, signPk32, kemPk32, issuedAt) {
  const input = buildDeviceCardSigInput(signPk32, kemPk32, issuedAt);
  return ed25519Sign(signSeed32, input);
}

/**
 * Verify a DeviceCard's deterministic device_id derivation, non-torsion sign_pk, and Ed25519 card_sig.
 * @param {{ device_id: string, sign_pk: string, kem_pk: string, issued_at: number, card_sig: string }} card
 */
export async function verifyDeviceCard(card) {
  if (!card || typeof card !== 'object') return false;
  if (typeof card.device_id !== 'string' || !/^[0-9a-f]{32}$/.test(card.device_id)) return false;
  try {
    const signPk = b64uToBytes(card.sign_pk);
    const kemPk = b64uToBytes(card.kem_pk);
    const sig = b64uToBytes(card.card_sig);
    if (signPk.length !== 32 || kemPk.length !== 32 || sig.length !== 64) return false;
    if (isSmallOrderEd25519PublicKey(signPk)) return false;
    if (!Number.isSafeInteger(card.issued_at) || card.issued_at < 0) return false;
    const expectedDeviceId = await deriveDeviceId(signPk);
    if (!constantTimeEqual(utf8Encode(card.device_id), utf8Encode(expectedDeviceId))) return false;
    const input = buildDeviceCardSigInput(signPk, kemPk, card.issued_at);
    return await ed25519Verify(signPk, input, sig);
  } catch {
    return false;
  }
}
