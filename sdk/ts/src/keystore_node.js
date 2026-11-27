// Secure Node.js / Electron / Bun / Deno local-file KeyStore (dir 0700, file 0600, atomic rename).
// Dynamically imports node:fs/promises and node:path so browser/PWA bundlers stay 100% clean.

import { b64uToBytes, bytesToB64u, bytesToHex, randomBytes } from './crypto.js';
import { ErrorCode, SyncError } from './envelope.js';
import { DEFAULT_SEEN_MIN_CAPACITY, DEFAULT_SEEN_RETENTION_SEC } from './keystore.js';

let nodeFsPromise = null;
function loadNodeFs() {
  if (!nodeFsPromise) {
    nodeFsPromise = Promise.all([import('node:fs/promises'), import('node:path')]).then(([fs, path]) => ({ fs, path }));
  }
  return nodeFsPromise;
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
    this._queue = Promise.resolve();
  }

  /** @template T @param {() => Promise<T>} fn @returns {Promise<T>} */
  _serialized(fn) {
    const next = this._queue.then(fn, fn);
    this._queue = next.then(() => undefined, () => undefined);
    return next;
  }

  async _ensureLoaded() {
    if (this._state) return this._state;
    const { fs, path } = await loadNodeFs();
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

    const filePath = path.join(this._dir, 'keystore.json');
    try {
      const raw = await fs.readFile(filePath, 'utf8');
      const parsed = JSON.parse(raw);
      this._state = {
        version: 1,
        master_seed_b64u: parsed.master_seed_b64u || '',
        relays: parsed.relays && typeof parsed.relays === 'object' ? parsed.relays : {},
        devices: parsed.devices && typeof parsed.devices === 'object' ? parsed.devices : {},
        seen_msgs: parsed.seen_msgs && typeof parsed.seen_msgs === 'object' ? parsed.seen_msgs : {},
        manifest_cache: parsed.manifest_cache && typeof parsed.manifest_cache === 'object' ? parsed.manifest_cache : {},
      };
    } catch (err) {
      if (err?.code === 'ENOENT') {
        this._state = { version: 1, master_seed_b64u: '', relays: {}, devices: {}, seen_msgs: {}, manifest_cache: {} };
      } else {
        throw new SyncError(ErrorCode.ERR_KEYSTORE_ERROR, `read keystore.json failed: ${err.message}`, { cause: err });
      }
    }
    return this._state;
  }

  async _persist() {
    const { fs, path } = await loadNodeFs();
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
      await fs.rename(tmpPath, filePath);
      await fs.chmod(filePath, 0o600).catch(() => {});
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
        const raw = b64uToBytes(st.master_seed_b64u);
        if (raw.length !== 32) {
          throw new SyncError(ErrorCode.ERR_KEYSTORE_ERROR, 'corrupted master_seed_b64u in keystore.json');
        }
        return raw;
      }
      const generated = randomBytes(32);
      st.master_seed_b64u = bytesToB64u(generated);
      await this._persist();
      return new Uint8Array(generated);
    });
  }

  getRelayProfile(relayId) {
    return this._serialized(async () => {
      const st = await this._ensureLoaded();
      const p = st.relays[relayId];
      return p ? structuredClone(p) : null;
    });
  }

  saveRelayProfile(profile) {
    return this._serialized(async () => {
      if (!profile || !profile.relay_id) {
        throw new SyncError(ErrorCode.ERR_KEYSTORE_ERROR, 'relay profile missing relay_id');
      }
      const st = await this._ensureLoaded();
      st.relays[profile.relay_id] = structuredClone(profile);
      await this._persist();
    });
  }

  listDevices() {
    return this._serialized(async () => {
      const st = await this._ensureLoaded();
      return Object.values(st.devices).filter((c) => !c.revoked).map((c) => structuredClone(c));
    });
  }

  getDevice(deviceId) {
    return this._serialized(async () => {
      const st = await this._ensureLoaded();
      const c = st.devices[String(deviceId).toLowerCase().trim()];
      return c ? structuredClone(c) : null;
    });
  }

  putDevice(card) {
    return this._serialized(async () => {
      if (!card || !card.device_id) {
        throw new SyncError(ErrorCode.ERR_KEYSTORE_ERROR, 'device card missing device_id');
      }
      const st = await this._ensureLoaded();
      const id = String(card.device_id).toLowerCase().trim();
      st.devices[id] = { ...structuredClone(card), device_id: id };
      await this._persist();
    });
  }

  deleteDevice(deviceId) {
    return this._serialized(async () => {
      const st = await this._ensureLoaded();
      delete st.devices[String(deviceId).toLowerCase().trim()];
      await this._persist();
    });
  }

  hasSeenMsgID(msgId) {
    return this._serialized(async () => {
      const st = await this._ensureLoaded();
      return Boolean(st.seen_msgs[String(msgId).toLowerCase()]);
    });
  }

  markSeenMsgID(msgId, createdAt, seenAt = Math.floor(Date.now() / 1000)) {
    return this._serialized(async () => {
      const st = await this._ensureLoaded();
      const id = String(msgId).toLowerCase();
      st.seen_msgs[id] = { msg_id: id, created_at: createdAt, seen_at: seenAt };
      const keys = Object.keys(st.seen_msgs);
      if (keys.length > this._seenMinCapacity) {
        const cutoff = seenAt - this._seenRetentionSec;
        const sorted = keys.map((k) => st.seen_msgs[k]).sort((a, b) => (a.seen_at ?? 0) - (b.seen_at ?? 0));
        let count = keys.length;
        for (const entry of sorted) {
          if (count <= this._seenMinCapacity) break;
          if ((entry.seen_at ?? 0) < cutoff) {
            delete st.seen_msgs[entry.msg_id];
            count--;
          }
        }
      }
      await this._persist();
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
    return this._serialized(async () => {
      const st = await this._ensureLoaded();
      st.manifest_cache[itemId] = structuredClone(preview);
      await this._persist();
    });
  }

  deleteCachedManifestPreview(itemId) {
    return this._serialized(async () => {
      const st = await this._ensureLoaded();
      if (st.manifest_cache[itemId] !== undefined) {
        delete st.manifest_cache[itemId];
        await this._persist();
      }
    });
  }

  pruneCachedManifestPreviews(activeItemIds) {
    return this._serialized(async () => {
      const st = await this._ensureLoaded();
      let changed = false;
      for (const id of Object.keys(st.manifest_cache)) {
        if (!activeItemIds.has(id)) {
          delete st.manifest_cache[id];
          changed = true;
        }
      }
      if (changed) await this._persist();
    });
  }
}
