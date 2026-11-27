// Internal transport, streaming SHA-256, BlobInput helpers, Node TLS 1.3 SPKI Pinning & SSE parser.
// Part of synctool v1 zero-dependency cross-platform client.

import {
  CHUNK_PLAINTEXT_MAX,
  bytesToHex,
  concatBytes,
  constantTimeEqual,
  utf8Encode,
} from './crypto.js';
import {
  ErrorCode,
  SyncError,
  isBareIP,
} from './envelope.js';

export const DEFAULT_HANDSHAKE_TIMEOUT_MS = 180_000;

// ============================================================================
// Zero-Dependency Incremental SHA-256 (FIPS 180-4) for Browser Anti-OOM Streaming
// Uses native node:crypto createHash on Node.js, pure JS incremental fallback elsewhere.
// ============================================================================

const SHA256_K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

/** Pure-JS incremental SHA-256 (zero dependencies, constant ~1 KB RAM). */
export class StreamingSha256 {
  constructor() {
    this._h = new Uint32Array([
      0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
      0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ]);
    this._buf = new Uint8Array(64);
    this._bufLen = 0;
    this._totalBytes = 0n;
    this._w = new Uint32Array(64);
  }

  /** @param {Uint8Array} chunk */
  update(chunk) {
    this._totalBytes += BigInt(chunk.length);
    let offset = 0;
    if (this._bufLen > 0) {
      const need = 64 - this._bufLen;
      const take = Math.min(need, chunk.length);
      this._buf.set(chunk.subarray(0, take), this._bufLen);
      this._bufLen += take;
      offset += take;
      if (this._bufLen === 64) {
        this._compress(this._buf, 0);
        this._bufLen = 0;
      }
    }
    while (offset + 64 <= chunk.length) {
      this._compress(chunk, offset);
      offset += 64;
    }
    if (offset < chunk.length) {
      const rem = chunk.length - offset;
      this._buf.set(chunk.subarray(offset), 0);
      this._bufLen = rem;
    }
    return this;
  }

  /** @returns {Uint8Array} */
  digest() {
    const bitLen = this._totalBytes * 8n;
    const padLen = ((56 - (this._bufLen + 1)) % 64 + 64) % 64;
    const tail = new Uint8Array(1 + padLen + 8);
    tail[0] = 0x80;
    new DataView(tail.buffer).setBigUint64(1 + padLen, bitLen, false);
    this.update(tail);

    const out = new Uint8Array(32);
    const dv = new DataView(out.buffer);
    for (let i = 0; i < 8; i++) {
      dv.setUint32(i * 4, this._h[i], false);
    }
    return out;
  }

  /** @returns {string} */
  digestHex() {
    return bytesToHex(this.digest());
  }

  /** @param {Uint8Array} block @param {number} off */
  _compress(block, off) {
    const w = this._w;
    for (let i = 0; i < 16; i++) {
      const j = off + i * 4;
      w[i] = ((block[j] << 24) | (block[j + 1] << 16) | (block[j + 2] << 8) | block[j + 3]) >>> 0;
    }
    for (let i = 16; i < 64; i++) {
      const s0 = (rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3)) >>> 0;
      const s1 = (rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10)) >>> 0;
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }
    let a = this._h[0], b = this._h[1], c = this._h[2], d = this._h[3];
    let e = this._h[4], f = this._h[5], g = this._h[6], h = this._h[7];
    for (let i = 0; i < 64; i++) {
      const S1 = (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) >>> 0;
      const ch = ((e & f) ^ (~e & g)) >>> 0;
      const temp1 = (h + S1 + ch + SHA256_K[i] + w[i]) >>> 0;
      const S0 = (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) >>> 0;
      const maj = ((a & b) ^ (a & c) ^ (b & c)) >>> 0;
      const temp2 = (S0 + maj) >>> 0;
      h = g; g = f; f = e; e = (d + temp1) >>> 0;
      d = c; c = b; b = a; a = (temp1 + temp2) >>> 0;
    }
    this._h[0] = (this._h[0] + a) >>> 0;
    this._h[1] = (this._h[1] + b) >>> 0;
    this._h[2] = (this._h[2] + c) >>> 0;
    this._h[3] = (this._h[3] + d) >>> 0;
    this._h[4] = (this._h[4] + e) >>> 0;
    this._h[5] = (this._h[5] + f) >>> 0;
    this._h[6] = (this._h[6] + g) >>> 0;
    this._h[7] = (this._h[7] + h) >>> 0;
  }
}

function rotr(x, n) {
  return ((x >>> n) | (x << (32 - n))) >>> 0;
}

// ============================================================================
// Streaming Blob Input Helpers (Anti-OOM: Slice-Based Reading)
// ============================================================================

/**
 * Create a streaming BlobInput backed by a Web File or Blob (reads strictly 64 KiB slices).
 * @param {Blob} webBlob
 * @param {{ role: string, name?: string, mime?: string, sha256?: string, encoding?: 'identity'|'gzip'|'zstd', meta?: Record<string, unknown> }} opts
 */
export function blobFromWebBlob(webBlob, opts) {
  return {
    role: opts.role,
    name: opts.name ?? (typeof /** @type {any} */ (webBlob).name === 'string' ? /** @type {any} */ (webBlob).name : 'attachment.bin'),
    mime: opts.mime ?? (webBlob.type || 'application/octet-stream'),
    size: webBlob.size,
    sha256: opts.sha256,
    encoding: opts.encoding ?? 'identity',
    meta: opts.meta,
    async readSlice(offset, length) {
      const buf = await webBlob.slice(offset, offset + length).arrayBuffer();
      return new Uint8Array(buf);
    },
  };
}

/**
 * Create a streaming BlobInput from a generic random-access slice reader (e.g., Node fs.FileHandle).
 * @param {{
 *   role: string,
 *   name: string,
 *   mime?: string,
 *   size: number,
 *   sha256?: string,
 *   encoding?: 'identity'|'gzip'|'zstd',
 *   meta?: Record<string, unknown>,
 *   readSlice: (offset: number, length: number) => Promise<Uint8Array> | Uint8Array,
 * }} opts
 */
export function blobFromSliceReader(opts) {
  return {
    role: opts.role,
    name: opts.name,
    mime: opts.mime ?? 'application/octet-stream',
    size: opts.size,
    sha256: opts.sha256,
    encoding: opts.encoding ?? 'identity',
    meta: opts.meta,
    readSlice: opts.readSlice,
  };
}

/**
 * Convenience helper for small in-memory payloads/tests. Avoid for large videos on mobile/browser.
 * @param {Uint8Array} bytes
 * @param {{ role: string, name: string, mime?: string, sha256?: string, encoding?: 'identity'|'gzip'|'zstd', meta?: Record<string, unknown> }} opts
 */
export function blobFromBytes(bytes, opts) {
  const buf = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  return {
    role: opts.role,
    name: opts.name,
    mime: opts.mime ?? 'application/octet-stream',
    size: buf.length,
    sha256: opts.sha256,
    encoding: opts.encoding ?? 'identity',
    meta: opts.meta,
    async readSlice(offset, length) {
      return buf.subarray(offset, Math.min(offset + length, buf.length));
    },
  };
}

/** @param {any} blobInput */
export async function computeBlobSha256(blobInput) {
  if (blobInput.sha256) return blobInput.sha256;
  const hasher = new StreamingSha256();
  let offset = 0;
  while (offset < blobInput.size) {
    const len = Math.min(CHUNK_PLAINTEXT_MAX, blobInput.size - offset);
    const slice = await blobInput.readSlice(offset, len);
    if (slice.length !== len) {
      throw new SyncError(ErrorCode.ERR_STORAGE_IO, `short read on blob "${blobInput.name}" at offset ${offset}`);
    }
    hasher.update(slice);
    offset += len;
  }
  return hasher.digestHex();
}

// ============================================================================
// Node.js Strict TLS 1.3 SPKI Pinning Transport (Zero HTTP Bytes Sent Before Pin Check)
// ============================================================================

export function isNodeRuntime() {
  return typeof process !== 'undefined' && Boolean(process.versions?.node);
}

let nodeModulesPromise = null;
function loadNodeModules() {
  if (!nodeModulesPromise) {
    nodeModulesPromise = Promise.all([
      import('node:http'),
      import('node:tls'),
      import('node:crypto'),
      import('node:stream'),
    ]).then(([http, tls, crypto, stream]) => ({ http, tls, crypto, stream }));
  }
  return nodeModulesPromise;
}

/**
 * Execute an HTTPS request in Node.js with strict TLS 1.3 + leaf cert validity + SPKI SHA-256 Pinning.
 * Uses node:http + async createConnection (never returning sock synchronously) so TLS handshake + SPKI pin
 * verification strictly completes in 'secureConnect' BEFORE oncreate(null, sock) hands the socket to http.request,
 * guaranteeing 0 bytes of HTTP headers/tokens are ever transmitted over an unverified peer.
 */
export async function nodePinnedFetch(urlStr, init, expectedSpkiPinHex) {
  const { http, tls, crypto, stream } = await loadNodeModules();
  const u = new URL(urlStr);
  const hostname = u.hostname.replace(/^\[|\]$/g, '');
  const port = u.port ? Number(u.port) : 443;
  const expectedPinBytes = utf8Encode(expectedSpkiPinHex.toLowerCase());

  return new Promise((resolve, reject) => {
    let settled = false;
    let activeSock = null;
    const fail = (err) => {
      if (!settled) {
        settled = true;
        reject(err);
      }
    };

    const headers = {};
    if (init.headers) {
      for (const [k, v] of Object.entries(init.headers)) {
        if (v !== undefined && v !== null) headers[k] = String(v);
      }
    }
    const body = init.body instanceof Uint8Array ? init.body : init.body ? utf8Encode(String(init.body)) : null;
    if (body && !headers['Content-Length'] && !headers['content-length']) {
      headers['Content-Length'] = String(body.byteLength);
    }

    const pinnedAgent = new http.Agent({ keepAlive: false });
    pinnedAgent.createConnection = (_opts, oncreate) => {
      const sock = tls.connect({
        host: hostname,
        port,
        servername: isBareIP(hostname) ? undefined : hostname,
        minVersion: 'TLSv1.3',
        rejectUnauthorized: false,
      });
      activeSock = sock;
      let handedOff = false;

      sock.once('secureConnect', () => {
        if (handedOff) return;
        try {
          const peerCert = sock.getPeerCertificate(true);
          if (!peerCert || !peerCert.raw || peerCert.raw.length === 0) {
            handedOff = true;
            sock.destroy();
            oncreate(new SyncError(ErrorCode.ERR_TLS_CERT_INVALID, 'relay presented empty TLS certificate'));
            return;
          }
          const x509 = new crypto.X509Certificate(peerCert.raw);
          const nowMs = Date.now();
          const validFromMs = Date.parse(x509.validFrom);
          const validToMs = Date.parse(x509.validTo);
          if (Number.isNaN(validFromMs) || Number.isNaN(validToMs) || nowMs < validFromMs || nowMs > validToMs) {
            handedOff = true;
            sock.destroy();
            oncreate(new SyncError(ErrorCode.ERR_TLS_CERT_INVALID, 'relay TLS leaf certificate is expired or not yet valid'));
            return;
          }
          const spkiDer = x509.publicKey.export({ type: 'spki', format: 'der' });
          const actualPinHex = crypto.createHash('sha256').update(spkiDer).digest('hex');
          if (!constantTimeEqual(utf8Encode(actualPinHex), expectedPinBytes)) {
            handedOff = true;
            sock.destroy();
            oncreate(new SyncError(ErrorCode.ERR_TLS_PIN_MISMATCH, 'relay TLS SPKI SHA-256 pin mismatch'));
            return;
          }
          handedOff = true;
          oncreate(null, sock);
        } catch (err) {
          handedOff = true;
          sock.destroy();
          const syncErr = err instanceof SyncError
            ? err
            : new SyncError(ErrorCode.ERR_TLS_CERT_INVALID, `TLS SPKI verification error: ${err.message}`, { cause: err });
          oncreate(syncErr);
        }
      });
      sock.once('error', (err) => {
        if (!handedOff) {
          handedOff = true;
          const mapped = err instanceof SyncError
            ? err
            : new SyncError(ErrorCode.ERR_RELAY_UNREACHABLE, `TLS connect failed: ${err.message}`, {
                retryable: true,
                cause: err,
              });
          oncreate(mapped);
        }
      });
      // Intentionally return undefined so http.Agent waits for async oncreate() after pin check!
      return undefined;
    };

    const req = http.request(
      {
        hostname,
        port,
        path: u.pathname + u.search,
        method: init.method || 'GET',
        headers,
        agent: pinnedAgent,
      },
      (res) => {
        if (settled) return;
        settled = true;
        const headerMap = new Map();
        for (const [k, v] of Object.entries(res.headers)) {
          headerMap.set(k.toLowerCase(), Array.isArray(v) ? v.join(', ') : String(v ?? ''));
        }
        const webBody = stream.Readable.toWeb(res);
        resolve({
          status: res.statusCode ?? 0,
          headers: {
            get(name) {
              return headerMap.get(String(name).toLowerCase()) ?? null;
            },
          },
          body: webBody,
          async arrayBuffer() {
            const reader = webBody.getReader();
            const chunks = [];
            try {
              while (true) {
                const { value, done } = await reader.read();
                if (done) break;
                chunks.push(value instanceof Uint8Array ? value : new Uint8Array(value));
              }
            } finally {
              reader.releaseLock();
            }
            const joined = concatBytes(...chunks);
            return joined.buffer.slice(joined.byteOffset, joined.byteOffset + joined.byteLength);
          },
          async text() {
            const ab = await this.arrayBuffer();
            return new TextDecoder().decode(new Uint8Array(ab));
          },
          async json() {
            return JSON.parse(await this.text());
          },
        });
      },
    );

    const onAbort = () => {
      const err = new SyncError(ErrorCode.ERR_CANCELLED, 'request aborted');
      if (activeSock && !activeSock.destroyed) activeSock.destroy();
      req.destroy(err);
      fail(err);
    };
    if (init.signal) {
      if (init.signal.aborted) {
        onAbort();
        return;
      }
      init.signal.addEventListener('abort', onAbort, { once: true });
      req.once('close', () => init.signal.removeEventListener('abort', onAbort));
    }

    req.on('error', (err) => {
      if (err instanceof SyncError) {
        fail(err);
      } else {
        fail(new SyncError(ErrorCode.ERR_RELAY_UNREACHABLE, `relay request failed: ${err.message}`, { retryable: true, cause: err }));
      }
    });

    if (body) req.write(body);
    req.end();
  });
}

// ============================================================================
// Standard SSE Line Parser (Zero Dependencies)
// ============================================================================

export async function* iterateSSE(readableStream, signal) {
  if (!readableStream) return;
  const reader = readableStream.getReader();
  const decoder = new TextDecoder('utf-8');
  let buffer = '';
  let eventName = 'message';
  let dataLines = [];
  let lastId = '';

  const flush = () => {
    if (dataLines.length === 0) return null;
    const ev = { event: eventName || 'message', data: dataLines.join('\n'), id: lastId };
    eventName = 'message';
    dataLines = [];
    return ev;
  };

  try {
    while (!signal?.aborted) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      let nl;
      while ((nl = buffer.indexOf('\n')) >= 0) {
        const line = buffer.slice(0, nl).replace(/\r$/, '');
        buffer = buffer.slice(nl + 1);
        if (line === '') {
          const ev = flush();
          if (ev) yield ev;
        } else if (line.startsWith(':')) {
          // comment / heartbeat (: ping)
        } else if (line.startsWith('event:')) {
          eventName = line.slice(6).trim();
        } else if (line.startsWith('data:')) {
          dataLines.push(line.slice(5).trimStart());
        } else if (line.startsWith('id:')) {
          lastId = line.slice(3).trim();
        }
      }
    }
    const tail = flush();
    if (tail) yield tail;
  } finally {
    reader.cancel().catch(() => {});
  }
}
