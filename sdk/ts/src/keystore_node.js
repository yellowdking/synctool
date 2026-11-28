// Secure Node.js / Electron / Bun / Deno local-file KeyStore (dir 0700, file 0600, .keystore.lock,
// 5x Windows atomic rename retry, and 100% Go FileKeyStore `keystore.json` field compatibility).

import { loadNodeFs } from '#node-platform';
import { b64uToBytes, bytesToB64u, bytesToHex, randomBytes } from './crypto.js';
import { ErrorCode, SyncError } from './envelope.js';
import {
  DEFAULT_SEEN_MIN_CAPACITY,
  DEFAULT_SEEN_RETENTION_SEC,
  normalizeStoredRelayProfile,
} from './keystore.js';

const RENAME_RETRY_CODES = new Set(['EPERM', 'EACCES', 'EBUSY']);
const STALE_LOCK_AGE_MS = 10_000;

function sleepMs(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export async function renameWithWindowsRetry(fs, tmpPath, destPath, maxAttempts = 5) {
  let lastErr = null;
  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    try {
      await fs.rename(tmpPath, destPath);
      return;
    } catch (err) {
      lastErr = err;
      if (!RENAME_RETRY_CODES.has(err?.code) || attempt === maxAttempts - 1) {
        throw err;
      }
      await sleepMs(15 * (attempt + 1));
    }
  }
  throw lastErr;
}

function normalizeParsedState(parsed) {
  const relays = {};
  if (parsed?.relays && typeof parsed.relays === 'object') {
    for (const [id, prof] of Object.entries(parsed.relays)) {
      const norm = normalizeStoredRelayProfile({ ...prof, relay_id: prof?.relay_id || id });
      if (norm) relays[id] = norm;
    }
  }
  const devices = {};
  if (parsed?.devices && typeof parsed.devices === 'object') {
    for (const [rawId, card] of Object.entries(parsed.devices)) {
      if (card && typeof card === 'object') {
        const id = String(card.device_id || rawId).toLowerCase().trim();
        devices[id] = { ...card, device_id: id };
      }
    }
  }
  const seenMsgs = {};
  if (parsed?.seen_msgs && typeof parsed.seen_msgs === 'object') {
    for (const [rawId, entry] of Object.entries(parsed.seen_msgs)) {
      if (entry && typeof entry === 'object') {
        const id = String(entry.msg_id || rawId).toLowerCase().trim();
        seenMsgs[id] = {
          msg_id: id,
          created_at: entry.created_at ?? entry.createdAt ?? 0,
          seen_at: entry.seen_at ?? entry.seenAt ?? 0,
        };
      }
    }
  }
  return {
    version: 1,
    master_seed_b64u: parsed?.master_seed_b64u || '',
    ...(parsed?.local_label ? { local_label: parsed.local_label } : {}),
    relays,
    devices,
    seen_msgs: seenMsgs,
    manifest_cache: parsed?.manifest_cache && typeof parsed.manifest_cache === 'object' ? parsed.manifest_cache : {},
    checkpoints: parsed?.checkpoints && typeof parsed.checkpoints === 'object' ? parsed.checkpoints : {},
    replay_watermark_ts: Number.isSafeInteger(parsed?.replay_watermark_ts) ? parsed.replay_watermark_ts : 0,
  };
}

export class NodeFileKeyStore {
  /**
   * @param {string} dirPath
   * @param {{ seenRetentionSec?: number, seenMinCapacity?: number }} [options]
   */
  constructor(dirPath, options = {}) {
    if (typeof dirPath !== 'string' || !dirPath.trim()) {
      throw new SyncError(ErrorCode.ERR_KEYSTORE_ERROR, 'NodeFileKeyStore requires a non-empty directory path');
    }
    this._dir = dirPath;
    this._seenRetentionSec = options.seenRetentionSec ?? DEFAULT_SEEN_RETENTION_SEC;
    this._seenMinCapacity = options.seenMinCapacity ?? DEFAULT_SEEN_MIN_CAPACITY;
    this._state = null;
    this._lastMtimeMs = -1;
    this._queue = Promise.resolve();
  }

  /** @template T @param {() => Promise<T>} fn @returns {Promise<T>} */
  _serialized(fn) {
    const next = this._queue.then(fn, fn);
    this._queue = next.then(() => undefined, () => undefined);
    return next;
  }

  async _ensureDir(fs) {
    try {
      const st = await fs.lstat(this._dir);
      if (st.isSymbolicLink() || !st.isDirectory()) {
        throw new SyncError(ErrorCode.ERR_KEYSTORE_ERROR, 'keystore path must be a real directory, not a symlink');
      }
    } catch (err) {
      if (err instanceof SyncError) throw err;
      if (err?.code !== 'ENOENT') {
        throw new SyncError(ErrorCode.ERR_KEYSTORE_ERROR, `lstat keystore dir failed: ${err.message}`, { cause: err });
      }
      await fs.mkdir(this._dir, { recursive: true, mode: 0o700 });
    }
    await fs.chmod(this._dir, 0o700).catch(() => {});
  }

  /**
   * Acquire advisory `.keystore.lock` to serialize cross-process updates (CLI + Electron/Node).
   */
  async _withFileLock(fn) {
    const { fs, path } = await loadNodeFs();
    await this._ensureDir(fs);
    const lockPath = path.join(this._dir, '.keystore.lock');
    let lockFh = null;
    for (let attempt = 0; attempt < 30; attempt++) {
      try {
        lockFh = await fs.open(lockPath, 'wx', 0o600);
        await lockFh.writeFile(`${process.pid}:${Date.now()}\n`, 'utf8').catch(() => {});
        break;
      } catch (err) {
        if (err?.code !== 'EEXIST' && !RENAME_RETRY_CODES.has(err?.code)) {
          throw new SyncError(ErrorCode.ERR_KEYSTORE_ERROR, `acquire keystore lock failed: ${err.message}`, { cause: err });
        }
        try {
          const st = await fs.stat(lockPath);
          if (Date.now() - st.mtimeMs > STALE_LOCK_AGE_MS) {
            await fs.unlink(lockPath).catch(() => {});
            continue;
          }
        } catch { /* lock already released */ }
        if (attempt === 29) {
          throw new SyncError(ErrorCode.ERR_KEYSTORE_ERROR, 'timed out waiting for .keystore.lock', { retryable: true });
        }
        await sleepMs(20);
      }
    }
    try {
      return await fn(fs, path);
    } finally {
      if (lockFh) await lockFh.close().catch(() => {});
      await fs.unlink(lockPath).catch(() => {});
    }
  }

  async _ensureLoaded(forceReloadCheck = false) {
    const { fs, path } = await loadNodeFs();
    await this._ensureDir(fs);
    const filePath = path.join(this._dir, 'keystore.json');

    if (this._state && !forceReloadCheck) {
      try {
        const st = await fs.stat(filePath);
        if (st.mtimeMs === this._lastMtimeMs) {
          return this._state;
        }
      } catch (err) {
        if (err?.code === 'ENOENT' && this._lastMtimeMs < 0) {
          return this._state;
        }
      }
    } else if (this._state && forceReloadCheck) {
      try {
        const st = await fs.stat(filePath);
        if (st.mtimeMs === this._lastMtimeMs) {
          return this._state;
        }
      } catch (err) {
        if (err?.code === 'ENOENT') return this._state;
      }
    }

    try {
      const raw = await fs.readFile(filePath, 'utf8');
      const parsed = JSON.parse(raw);
      const stat = await fs.stat(filePath).catch(() => null);
      this._state = normalizeParsedState(parsed);
      this._lastMtimeMs = stat ? stat.mtimeMs : Date.now();
    } catch (err) {
      if (err?.code === 'ENOENT') {
        if (!this._state) {
          this._state = normalizeParsedState({});
        }
        this._lastMtimeMs = -1;
      } else {
        throw new SyncError(ErrorCode.ERR_KEYSTORE_ERROR, `read keystore.json failed: ${err.message}`, { cause: err });
      }
    }
    return this._state;
  }

  async _persist(fs, path) {
    const filePath = path.join(this._dir, 'keystore.json');
    const tmpName = `.keystore-${process.pid}-${bytesToHex(randomBytes(6))}.tmp`;
    const tmpPath = path.join(this._dir, tmpName);
    const data = JSON.stringify(this._state, null, 2);

    let fh = null;
    try {
      fh = await fs.open(tmpPath, 'wx', 0o600);
      await fh.writeFile(data, 'utf8');
      await fh.sync();
      await fh.close();
      fh = null;
      await renameWithWindowsRetry(fs, tmpPath, filePath, 5);
      await fs.chmod(filePath, 0o600).catch(() => {});
      const stat = await fs.stat(filePath).catch(() => null);
      if (stat) this._lastMtimeMs = stat.mtimeMs;
    } catch (err) {
      if (fh) await fh.close().catch(() => {});
      await fs.unlink(tmpPath).catch(() => {});
      throw new SyncError(ErrorCode.ERR_KEYSTORE_ERROR, `persist keystore.json failed: ${err.message}`, { cause: err });
    }
  }

  loadOrCreateMasterSeed() {
    return this._serialized(async () => {
      const st = await this._ensureLoaded();
      if (st.master_seed_b64u) {
        let raw;
        try {
          raw = b64uToBytes(st.master_seed_b64u);
        } catch (err) {
          throw new SyncError(ErrorCode.ERR_KEYSTORE_ERROR, 'corrupted master_seed_b64u in keystore.json', { cause: err });
        }
        if (raw.length !== 32) {
          throw new SyncError(ErrorCode.ERR_KEYSTORE_ERROR, 'corrupted master_seed_b64u length in keystore.json');
        }
        return raw;
      }
      return this._withFileLock(async (fs, path) => {
        const fresh = await this._ensureLoaded(true);
        if (fresh.master_seed_b64u) {
          const raw = b64uToBytes(fresh.master_seed_b64u);
          if (raw.length !== 32) {
            throw new SyncError(ErrorCode.ERR_KEYSTORE_ERROR, 'corrupted master_seed_b64u in keystore.json');
          }
          return raw;
        }
        const generated = randomBytes(32);
        fresh.master_seed_b64u = bytesToB64u(generated);
        await this._persist(fs, path);
        return new Uint8Array(generated);
      });
    });
  }

  getRelayProfile(relayIdOrAlias) {
    return this._serialized(async () => {
      const st = await this._ensureLoaded();
      const key = String(relayIdOrAlias ?? '').trim();
      if (st.relays[key]) return normalizeStoredRelayProfile(st.relays[key]);
      const lower = key.toLowerCase();
      for (const p of Object.values(st.relays)) {
        if (p.alias && String(p.alias).toLowerCase() === lower) {
          return normalizeStoredRelayProfile(p);
        }
      }
      return null;
    });
  }

  getDefaultRelayProfile() {
    return this._serialized(async () => {
      const st = await this._ensureLoaded();
      let first = null;
      for (const p of Object.values(st.relays)) {
        if (p.is_default) return normalizeStoredRelayProfile(p);
        if (!first || String(p.relay_id) < String(first.relay_id)) {
          first = p;
        }
      }
      return first ? normalizeStoredRelayProfile(first) : null;
    });
  }

  listRelayProfiles() {
    return this._serialized(async () => {
      const st = await this._ensureLoaded();
      return Object.values(st.relays)
        .map((p) => normalizeStoredRelayProfile(p))
        .sort((a, b) => String(a.relay_id).localeCompare(String(b.relay_id)));
    });
  }

  saveRelayProfile(profile) {
    return this._serialized(() =>
      this._withFileLock(async (fs, path) => {
        if (!profile || !profile.relay_id) {
          throw new SyncError(ErrorCode.ERR_KEYSTORE_ERROR, 'relay profile missing relay_id');
        }
        const st = await this._ensureLoaded(true);
        const normalized = normalizeStoredRelayProfile(profile);
        if (normalized.is_default || Object.keys(st.relays).length === 0) {
          normalized.is_default = true;
          for (const id of Object.keys(st.relays)) {
            if (id !== normalized.relay_id && st.relays[id].is_default) {
              st.relays[id] = { ...st.relays[id], is_default: false };
            }
          }
        }
        st.relays[normalized.relay_id] = normalized;
        await this._persist(fs, path);
      }),
    );
  }

  /** @param {{ includeRevoked?: boolean }} [options] */
  listDevices(options = {}) {
    return this._serialized(async () => {
      const includeRevoked = Boolean(options?.includeRevoked);
      const st = await this._ensureLoaded();
      return Object.values(st.devices)
        .filter((c) => (includeRevoked ? true : !c.revoked))
        .sort((a, b) => (a.paired_at ?? 0) - (b.paired_at ?? 0))
        .map((c) => structuredClone(c));
    });
  }

  getDevice(deviceId) {
    return this._serialized(async () => {
      const st = await this._ensureLoaded();
      const c = st.devices[String(deviceId ?? '').toLowerCase().trim()];
      return c ? structuredClone(c) : null;
    });
  }

  putDevice(card) {
    return this._serialized(() =>
      this._withFileLock(async (fs, path) => {
        if (!card || !card.device_id) {
          throw new SyncError(ErrorCode.ERR_KEYSTORE_ERROR, 'device card missing device_id');
        }
        const st = await this._ensureLoaded(true);
        const id = String(card.device_id).toLowerCase().trim();
        st.devices[id] = { ...structuredClone(card), device_id: id };
        await this._persist(fs, path);
      }),
    );
  }

  deleteDevice(deviceId) {
    return this._serialized(() =>
      this._withFileLock(async (fs, path) => {
        const st = await this._ensureLoaded(true);
        delete st.devices[String(deviceId ?? '').toLowerCase().trim()];
        await this._persist(fs, path);
      }),
    );
  }

  hasSeenMsgID(msgId) {
    return this._serialized(async () => {
      const st = await this._ensureLoaded();
      return Boolean(st.seen_msgs[String(msgId ?? '').toLowerCase().trim()]);
    });
  }

  markSeenMsgID(msgId, createdAt, seenAt = Math.floor(Date.now() / 1000)) {
    return this._serialized(() =>
      this._withFileLock(async (fs, path) => {
        const st = await this._ensureLoaded(true);
        const id = String(msgId ?? '').toLowerCase().trim();
        st.seen_msgs[id] = { msg_id: id, created_at: createdAt, seen_at: seenAt };
        const keys = Object.keys(st.seen_msgs);
        if (keys.length > this._seenMinCapacity) {
          const cutoff = seenAt - this._seenRetentionSec;
          const sorted = keys.map((k) => st.seen_msgs[k]).sort((a, b) => (a.seen_at ?? 0) - (b.seen_at ?? 0));
          let count = keys.length;
          for (const entry of sorted) {
            if (count <= this._seenMinCapacity) break;
            if ((entry.seen_at ?? 0) < cutoff) {
              if (typeof entry.created_at === 'number' && entry.created_at > (st.replay_watermark_ts ?? 0)) {
                st.replay_watermark_ts = entry.created_at;
              }
              delete st.seen_msgs[entry.msg_id];
              count--;
            }
          }
        }
        await this._persist(fs, path);
      }),
    );
  }

  getReplayWatermark() {
    return this._serialized(async () => {
      const st = await this._ensureLoaded();
      return st.replay_watermark_ts ?? 0;
    });
  }

  getCachedManifestPreview(itemId) {
    return this._serialized(async () => {
      const st = await this._ensureLoaded();
      const v = st.manifest_cache[itemId];
      return v ? structuredClone(v) : null;
    });
  }

  putCachedManifestPreview(itemId, preview) {
    return this._serialized(() =>
      this._withFileLock(async (fs, path) => {
        const st = await this._ensureLoaded(true);
        st.manifest_cache[itemId] = structuredClone(preview);
        await this._persist(fs, path);
      }),
    );
  }

  deleteCachedManifestPreview(itemId) {
    return this._serialized(() =>
      this._withFileLock(async (fs, path) => {
        const st = await this._ensureLoaded(true);
        if (st.manifest_cache[itemId] !== undefined) {
          delete st.manifest_cache[itemId];
          await this._persist(fs, path);
        }
      }),
    );
  }

  pruneCachedManifestPreviews(activeItemIds) {
    return this._serialized(() =>
      this._withFileLock(async (fs, path) => {
        const st = await this._ensureLoaded(true);
        let changed = false;
        for (const id of Object.keys(st.manifest_cache)) {
          if (!activeItemIds.has(id)) {
            delete st.manifest_cache[id];
            changed = true;
          }
        }
        if (changed) await this._persist(fs, path);
      }),
    );
  }
}
