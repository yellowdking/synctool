// STREAM Chunked AEAD (64 KiB / 65,552 B, 46B AAD), 4 KiB Manifest Bucketing Padding,
// and Relay Access HMAC (X-Sync-Sig) / Mailbox Ed25519 (X-Sync-Mailbox-Sig) (spec/CRYPTO_AND_AUTH.md §6–§7).

import { ErrorCode, MAX_MANIFEST_BYTES, SyncError } from './envelope.js';
import {
  AEAD_TAG_LEN,
  CHUNK_CIPHERTEXT_MAX,
  CHUNK_PLAINTEXT_MAX,
  MANIFEST_PAD_BUCKET,
  aesGcmOpen,
  aesGcmSeal,
  b64uToBytes,
  bytesToB64u,
  bytesToHex,
  concatBytes,
  ed25519Sign,
  ed25519Verify,
  hkdfExpand,
  hkdfExtract,
  hmacSha256,
  readU32be,
  sha256,
  u32be,
  utf8Encode,
  zeroBytes,
} from './crypto_primitives.js';

const EMPTY_SHA256_HEX = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

// ============================================================================
// §6 STREAM Chunked AEAD & 4 KiB Manifest Bucketing Padding
// ============================================================================

/**
 * Derive per-blob STREAM keys for part_id >= 1 (spec/CRYPTO_AND_AUTH.md §6.2).
 * @param {Uint8Array} blobKey32
 * @param {Uint8Array} msgId16
 * @param {number} partId
 */
export async function deriveBlobPartKeys(blobKey32, msgId16, partId) {
  if (blobKey32.length !== 32) throw new RangeError('blobKey must be 32 bytes');
  if (msgId16.length !== 16) throw new RangeError('msgId must be 16 bytes');
  if (!Number.isInteger(partId) || partId < 1 || partId > 63) {
    throw new RangeError(`blob part_id must be 1..63, got ${partId}`);
  }
  const salt = concatBytes(msgId16, u32be(partId));
  const partPrk = await hkdfExtract(salt, blobKey32);
  const [encKey, noncePrefix] = await Promise.all([
    hkdfExpand(partPrk, utf8Encode('synctool-v1/blob-enc-key'), 32),
    hkdfExpand(partPrk, utf8Encode('synctool-v1/blob-nonce-prefix'), 7),
  ]);
  return { partPrk, encKey, noncePrefix };
}

/**
 * Build deterministic 12B STREAM Nonce: nonce_prefix(7B) || uint32_be(block_idx) || uint8(is_final).
 * @param {Uint8Array} noncePrefix7
 * @param {number} blockIdx
 * @param {boolean} isFinal
 */
export function buildChunkNonce(noncePrefix7, blockIdx, isFinal) {
  if (noncePrefix7.length !== 7) throw new RangeError('noncePrefix must be 7 bytes');
  return concatBytes(noncePrefix7, u32be(blockIdx), new Uint8Array([isFinal ? 0x01 : 0x00]));
}

/**
 * Build fixed 46B binary STREAM AAD (spec/CRYPTO_AND_AUTH.md §6.2).
 * @param {Uint8Array} msgId16
 * @param {number} partId
 * @param {number} blockIdx
 * @param {boolean} isFinal
 * @param {number} plaintextLen
 */
export function buildChunkAAD(msgId16, partId, blockIdx, isFinal, plaintextLen) {
  if (msgId16.length !== 16) throw new RangeError('msgId must be 16 bytes');
  return concatBytes(
    utf8Encode('synctool-chunk-v1'), // 17B
    msgId16, // 16B
    u32be(partId), // 4B
    u32be(blockIdx), // 4B
    new Uint8Array([isFinal ? 0x01 : 0x00]), // 1B
    u32be(plaintextLen), // 4B (total 46B)
  );
}

/**
 * Seal one STREAM atomic block (0..65536 B plaintext -> 16..65552 B ciphertext).
 */
export async function sealStreamBlock(encKey32, noncePrefix7, msgId16, partId, blockIdx, isFinal, plaintextBlock) {
  if (!Number.isInteger(blockIdx) || blockIdx < 0 || blockIdx > 0xffffffff) {
    throw new SyncError(ErrorCode.ERR_CRYPTO_HANDSHAKE_FAILED, `STREAM blockIdx out of uint32 range: ${blockIdx}`);
  }
  if (!isFinal && blockIdx === 0xffffffff) {
    throw new SyncError(ErrorCode.ERR_CRYPTO_HANDSHAKE_FAILED, 'STREAM blockIdx overflow past uint32 max');
  }
  if (plaintextBlock.length > CHUNK_PLAINTEXT_MAX) {
    throw new RangeError(`plaintext block exceeds ${CHUNK_PLAINTEXT_MAX} bytes`);
  }
  if (!isFinal && plaintextBlock.length !== CHUNK_PLAINTEXT_MAX) {
    throw new SyncError(ErrorCode.ERR_CRYPTO_HANDSHAKE_FAILED, `non-final STREAM block must be ${CHUNK_PLAINTEXT_MAX} bytes`);
  }
  const nonce = buildChunkNonce(noncePrefix7, blockIdx, isFinal);
  const aad = buildChunkAAD(msgId16, partId, blockIdx, isFinal, plaintextBlock.length);
  return aesGcmSeal(encKey32, nonce, plaintextBlock, aad);
}

/**
 * Open one STREAM atomic block (16..65552 B ciphertext -> 0..65536 B plaintext).
 */
export async function openStreamBlock(encKey32, noncePrefix7, msgId16, partId, blockIdx, isFinal, ciphertextBlock) {
  if (!Number.isInteger(blockIdx) || blockIdx < 0 || blockIdx > 0xffffffff) {
    throw new SyncError(ErrorCode.ERR_STREAM_TRUNCATED, `STREAM blockIdx out of uint32 range: ${blockIdx}`);
  }
  if (!isFinal && blockIdx === 0xffffffff) {
    throw new SyncError(ErrorCode.ERR_STREAM_TRUNCATED, 'STREAM blockIdx overflow past uint32 max');
  }
  if (ciphertextBlock.length < AEAD_TAG_LEN || ciphertextBlock.length > CHUNK_CIPHERTEXT_MAX) {
    throw new SyncError(ErrorCode.ERR_CRYPTO_DECRYPT_FAILED, `invalid ciphertext block length: ${ciphertextBlock.length}`);
  }
  const plaintextLen = ciphertextBlock.length - AEAD_TAG_LEN;
  if (!isFinal && plaintextLen !== CHUNK_PLAINTEXT_MAX) {
    throw new SyncError(ErrorCode.ERR_STREAM_TRUNCATED, `non-final STREAM ciphertext block must be ${CHUNK_PLAINTEXT_MAX} bytes`);
  }
  const nonce = buildChunkNonce(noncePrefix7, blockIdx, isFinal);
  const aad = buildChunkAAD(msgId16, partId, blockIdx, isFinal, plaintextLen);
  return aesGcmOpen(encKey32, nonce, ciphertextBlock, aad);
}

/** @param {number} plaintextLen */
export function calcBlockCount(plaintextLen) {
  if (!Number.isSafeInteger(plaintextLen) || plaintextLen < 0) {
    throw new RangeError(`invalid plaintextLen: ${plaintextLen}`);
  }
  if (plaintextLen === 0) return 1;
  const blocks = Math.ceil(plaintextLen / CHUNK_PLAINTEXT_MAX);
  if (blocks > 0xffffffff) {
    throw new RangeError(`plaintextLen exceeds STREAM uint32 block limit: ${plaintextLen}`);
  }
  return blocks;
}

/** @param {number} plaintextLen */
export function calcEncryptedPartSize(plaintextLen) {
  const blocks = calcBlockCount(plaintextLen);
  if (plaintextLen === 0) return AEAD_TAG_LEN;
  return plaintextLen + blocks * AEAD_TAG_LEN;
}

/** @param {number} plaintextLen @param {number} blocksPerChunk */
export function calcTransportChunkCount(plaintextLen, blocksPerChunk) {
  if (!Number.isInteger(blocksPerChunk) || blocksPerChunk < 1) {
    throw new RangeError(`invalid blocksPerChunk: ${blocksPerChunk}`);
  }
  return Math.ceil(calcBlockCount(plaintextLen) / blocksPerChunk);
}

/**
 * Encrypt a plaintext byte slice into packed HTTP transport chunks (`N * 65552 B` except last chunk).
 * Note: For large blobs, prefer streaming block-by-block via `sealStreamBlock` in client to avoid buffering in RAM.
 */
export async function encryptPartBytes(encKey32, noncePrefix7, msgId16, partId, plaintext, blocksPerChunk = 16) {
  const totalBlocks = calcBlockCount(plaintext.length);
  const ctBlocks = [];
  for (let blockIdx = 0; blockIdx < totalBlocks; blockIdx++) {
    const start = blockIdx * CHUNK_PLAINTEXT_MAX;
    const end = Math.min(start + CHUNK_PLAINTEXT_MAX, plaintext.length);
    const ptBlock = plaintext.subarray(start, end);
    const isFinal = blockIdx === totalBlocks - 1;
    ctBlocks.push(await sealStreamBlock(encKey32, noncePrefix7, msgId16, partId, blockIdx, isFinal, ptBlock));
  }
  const transportChunks = [];
  for (let i = 0; i < ctBlocks.length; i += blocksPerChunk) {
    transportChunks.push(concatBytes(...ctBlocks.slice(i, i + blocksPerChunk)));
  }
  return { blocks: ctBlocks, transportChunks, totalCipherBytes: calcEncryptedPartSize(plaintext.length) };
}

/**
 * Decrypt concatenated ciphertext stream (or array of transport chunks) for one part_id.
 * Enforces complete final-block (is_final=0x01) authentication and hard-stops on trailing ciphertext.
 * @param {Uint8Array} encKey32
 * @param {Uint8Array} noncePrefix7
 * @param {Uint8Array} msgId16
 * @param {number} partId
 * @param {Uint8Array | Uint8Array[]} ciphertextOrChunks
 * @param {{ expectedTotalBlocks?: number }} [options]
 */
export async function decryptPartBytes(encKey32, noncePrefix7, msgId16, partId, ciphertextOrChunks, options = {}) {
  const full = Array.isArray(ciphertextOrChunks) ? concatBytes(...ciphertextOrChunks) : ciphertextOrChunks;
  if (full.length < AEAD_TAG_LEN) {
    throw new SyncError(ErrorCode.ERR_STREAM_TRUNCATED, 'encrypted part shorter than minimum 16B final block');
  }
  const blockCount = Math.ceil(full.length / CHUNK_CIPHERTEXT_MAX);
  if (options.expectedTotalBlocks !== undefined) {
    if (!Number.isInteger(options.expectedTotalBlocks) || options.expectedTotalBlocks < 1) {
      throw new RangeError(`invalid expectedTotalBlocks: ${options.expectedTotalBlocks}`);
    }
    if (blockCount !== options.expectedTotalBlocks) {
      throw new SyncError(
        ErrorCode.ERR_STREAM_TRUNCATED,
        `block count mismatch: got ${blockCount}, expected ${options.expectedTotalBlocks}`,
      );
    }
  }
  const targetTotalBlocks = options.expectedTotalBlocks ?? blockCount;
  const ptParts = [];
  let sawFinal = false;
  let offset = 0;
  let blockIdx = 0;
  while (offset < full.length) {
    if (sawFinal || blockIdx >= targetTotalBlocks) {
      throw new SyncError(ErrorCode.ERR_STREAM_TRUNCATED, 'trailing ciphertext after authenticated final STREAM block');
    }
    const end = Math.min(offset + CHUNK_CIPHERTEXT_MAX, full.length);
    const ctBlock = full.subarray(offset, end);
    const isFinal = blockIdx === targetTotalBlocks - 1;
    if (!isFinal && ctBlock.length !== CHUNK_CIPHERTEXT_MAX) {
      throw new SyncError(ErrorCode.ERR_STREAM_TRUNCATED, 'non-final block has unexpected length');
    }
    try {
      const pt = await openStreamBlock(encKey32, noncePrefix7, msgId16, partId, blockIdx, isFinal, ctBlock);
      ptParts.push(pt);
      if (isFinal) sawFinal = true;
    } catch (err) {
      if (isFinal && options.expectedTotalBlocks === undefined) {
        throw new SyncError(
          ErrorCode.ERR_CRYPTO_DECRYPT_FAILED,
          'final block authentication failed (tampered or truncated stream)',
          { cause: err },
        );
      }
      throw err;
    }
    offset = end;
    blockIdx++;
  }
  if (!sawFinal || blockIdx !== targetTotalBlocks) {
    throw new SyncError(ErrorCode.ERR_STREAM_TRUNCATED, 'stream ended without authenticated is_final=0x01 block');
  }
  return concatBytes(...ptParts);
}

/**
 * Pad manifest UTF-8 bytes up to 4 KiB multiple: uint32_be(L) || manifest(L) || 0x00*pad (spec/CRYPTO_AND_AUTH.md §6.3).
 * @param {Uint8Array} manifestUtf8Bytes
 */
export function padManifest(manifestUtf8Bytes) {
  const L = manifestUtf8Bytes.length;
  if (L <= 0 || L > MAX_MANIFEST_BYTES) {
    throw new SyncError(ErrorCode.ERR_MANIFEST_INVALID, `manifest length must be 1..${MAX_MANIFEST_BYTES}, got ${L}`);
  }
  const totalLen = Math.ceil((4 + L) / MANIFEST_PAD_BUCKET) * MANIFEST_PAD_BUCKET;
  const out = new Uint8Array(totalLen); // zero-initialized
  new DataView(out.buffer).setUint32(0, L, false);
  out.set(manifestUtf8Bytes, 4);
  return out;
}

/**
 * Unpad 4 KiB-bucketed manifest plaintext. Rejects invalid lengths or any non-zero trailing padding byte.
 * @param {Uint8Array} paddedBytes
 */
export function unpadManifest(paddedBytes) {
  if (paddedBytes.length < MANIFEST_PAD_BUCKET || paddedBytes.length % MANIFEST_PAD_BUCKET !== 0) {
    throw new SyncError(ErrorCode.ERR_STREAM_TRUNCATED, 'padded manifest length must be a positive multiple of 4096');
  }
  const L = readU32be(paddedBytes, 0);
  if (L <= 0 || L > MAX_MANIFEST_BYTES || 4 + L > paddedBytes.length) {
    throw new SyncError(ErrorCode.ERR_MANIFEST_INVALID, `invalid manifest length prefix: ${L}`);
  }
  const expectedTotal = Math.ceil((4 + L) / MANIFEST_PAD_BUCKET) * MANIFEST_PAD_BUCKET;
  if (paddedBytes.length !== expectedTotal) {
    throw new SyncError(ErrorCode.ERR_MANIFEST_INVALID, `manifest bucket length mismatch: got ${paddedBytes.length}, expected ${expectedTotal}`);
  }
  let padOr = 0;
  for (let i = 4 + L; i < paddedBytes.length; i++) {
    padOr |= paddedBytes[i];
  }
  if (padOr !== 0) {
    throw new SyncError(ErrorCode.ERR_STREAM_TRUNCATED, 'non-zero trailing padding byte in manifest');
  }
  return paddedBytes.slice(4, 4 + L);
}

// ============================================================================
// §7 Relay Access Auth (X-Sync-Sig) & Mailbox Ed25519 (X-Sync-Mailbox-Sig)
// ============================================================================

/** @param {string} accessKeyString */
export async function deriveRelayHmacKey(accessKeyString) {
  return sha256(concatBytes(utf8Encode('synctool-v1/access-key:'), utf8Encode(accessKeyString)));
}

/** @param {string} depositToken */
export async function hashDepositToken(depositToken) {
  return bytesToHex(await sha256(concatBytes(utf8Encode('synctool-v1/deposit-token:'), utf8Encode(depositToken))));
}

/** @param {string} uploadToken */
export async function hashUploadToken(uploadToken) {
  return bytesToHex(await sha256(concatBytes(utf8Encode('synctool-v1/upload-token:'), utf8Encode(uploadToken))));
}

/**
 * Compute BODY_BINDING for X-Sync-Sig and X-Sync-Mailbox-Sig.
 * Control plane: "sha256:<hex>"; Data plane chunk PUT: "stream:<decimal_content_length>".
 * @param {{ bodyBytes?: Uint8Array | null, streamContentLength?: number | null }} opts
 */
export async function computeBodyBinding(opts = {}) {
  if (opts.streamContentLength !== undefined && opts.streamContentLength !== null) {
    if (!Number.isSafeInteger(opts.streamContentLength) || opts.streamContentLength < 0) {
      throw new RangeError('streamContentLength must be a non-negative integer');
    }
    return `stream:${opts.streamContentLength}`;
  }
  if (!opts.bodyBytes || opts.bodyBytes.length === 0) {
    return `sha256:${EMPTY_SHA256_HEX}`;
  }
  return `sha256:${bytesToHex(await sha256(opts.bodyBytes))}`;
}

/**
 * Build 6-line canonical request string for X-Sync-Sig (spec/CRYPTO_AND_AUTH.md §7.2).
 */
export function buildCanonicalRelayRequest({ method, pathAndRawQuery, ts, nonce, bodyBinding, extraTokenBinding = '' }) {
  return [
    method.toUpperCase(),
    pathAndRawQuery,
    String(ts),
    nonce,
    bodyBinding,
    extraTokenBinding,
  ].join('\n');
}

/**
 * Compute X-Sync-Sig (64-char lowercase hex HMAC-SHA256).
 * @param {{
 *   accessKey: string,
 *   method: string,
 *   pathAndRawQuery: string,
 *   ts: number | string,
 *   nonce: string,
 *   bodyBytes?: Uint8Array | null,
 *   streamContentLength?: number | null,
 *   depositToken?: string | null,
 *   uploadToken?: string | null,
 * }} params
 */
export async function signRelayRequest(params) {
  const bodyBinding = await computeBodyBinding({
    bodyBytes: params.bodyBytes,
    streamContentLength: params.streamContentLength,
  });
  let extraTokenBinding = '';
  if (params.depositToken) {
    extraTokenBinding = `deposit:${await hashDepositToken(params.depositToken)}`;
  } else if (params.uploadToken) {
    extraTokenBinding = `upload:${await hashUploadToken(params.uploadToken)}`;
  }
  const canonical = buildCanonicalRelayRequest({
    method: params.method,
    pathAndRawQuery: params.pathAndRawQuery,
    ts: params.ts,
    nonce: params.nonce,
    bodyBinding,
    extraTokenBinding,
  });
  const hmacKey = await deriveRelayHmacKey(params.accessKey);
  let sigBytes;
  try {
    sigBytes = await hmacSha256(hmacKey, utf8Encode(canonical));
  } finally {
    zeroBytes(hmacKey);
  }
  return {
    canonical,
    bodyBinding,
    extraTokenBinding,
    sigHex: bytesToHex(sigBytes),
  };
}

/**
 * Build 7-line mailbox ownership signature input (spec/CRYPTO_AND_AUTH.md §7.4).
 */
export function buildMailboxSigInput({ method, pathAndRawQuery, mailboxId, ts, nonce, bodyBinding }) {
  return [
    'synctool-v1/mailbox-auth',
    method.toUpperCase(),
    pathAndRawQuery,
    mailboxId,
    String(ts),
    nonce,
    bodyBinding,
  ].join('\n');
}

/**
 * Compute X-Sync-Mailbox-Sig (86-char unpadded b64u Ed25519 signature).
 * @param {{
 *   mailboxAuthSeed: Uint8Array,
 *   method: string,
 *   pathAndRawQuery: string,
 *   mailboxId: string,
 *   ts: number | string,
 *   nonce: string,
 *   bodyBytes?: Uint8Array | null,
 *   streamContentLength?: number | null,
 * }} params
 */
export async function signMailboxRequest(params) {
  const bodyBinding = await computeBodyBinding({
    bodyBytes: params.bodyBytes,
    streamContentLength: params.streamContentLength,
  });
  const input = buildMailboxSigInput({
    method: params.method,
    pathAndRawQuery: params.pathAndRawQuery,
    mailboxId: params.mailboxId,
    ts: params.ts,
    nonce: params.nonce,
    bodyBinding,
  });
  const sig = await ed25519Sign(params.mailboxAuthSeed, utf8Encode(input));
  return { input, bodyBinding, sigB64u: bytesToB64u(sig) };
}

/**
 * Verify X-Sync-Mailbox-Sig Ed25519 signature.
 * @param {{
 *   mailboxAuthPk: Uint8Array,
 *   method: string,
 *   pathAndRawQuery: string,
 *   mailboxId: string,
 *   ts: number | string,
 *   nonce: string,
 *   bodyBytes?: Uint8Array | null,
 *   streamContentLength?: number | null,
 *   sigB64u: string,
 * }} params
 */
export async function verifyMailboxRequest(params) {
  try {
    const bodyBinding = await computeBodyBinding({
      bodyBytes: params.bodyBytes,
      streamContentLength: params.streamContentLength,
    });
    const input = buildMailboxSigInput({
      method: params.method,
      pathAndRawQuery: params.pathAndRawQuery,
      mailboxId: params.mailboxId,
      ts: params.ts,
      nonce: params.nonce,
      bodyBinding,
    });
    return await ed25519Verify(params.mailboxAuthPk, utf8Encode(input), b64uToBytes(params.sigB64u));
  } catch {
    return false;
  }
}
