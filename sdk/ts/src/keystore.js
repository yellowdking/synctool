// Minimal KeyStore interface (single 32B device_master_seed + DeviceCard + 30-day seen_msg_ids)
// + reference MemoryKeyStore implementation (spec/ENVELOPE_AND_SDK.md §5.1).
//
// Host adaptation notes:
// - Browser / PWA: store device_master_seed in IndexedDB (ideally wrapped by a non-extractable
//   WebCrypto AES-GCM key or OS passkey/WebAuthn PRF), never localStorage plaintext if avoidable.
// - Electron / Tauri: use OS Keychain / DPAPI / Secret Service (safeStorage / keyring plugin)
//   for the single 32B device_master_seed and encrypt DeviceCard/seen_msg_ids with local_meta_key.
// - Node.js CLI / service: persist in mode-0600 file in mode-0700 directory (encrypted via OS vault).

import { ErrorCode, SyncError, canonicalizeRelayOrigin, normalizeSpkiPins } from './envelope.js';

export const DEFAULT_SEEN_RETENTION_SEC = 30 * 24 * 3600; // 30 days
export const DEFAULT_SEEN_MIN_CAPACITY = 4096;

/**
 * Normalize a RelayProfile record with full Go <-> TS `keystore.json` field compatibility:
 * keeps `origin` <-> `endpoint` and `spki_pins` <-> `spki_pin` <-> `spki_sha256` synchronized.
 * @param {any} raw
 */
export function normalizeStoredRelayProfile(raw) {
  if (!raw || typeof raw !== 'object') return null;
  const clone = structuredClone(raw);
  const rawOrigin = clone.origin || clone.endpoint || '';
  if (rawOrigin) {
    try {
      const canon = canonicalizeRelayOrigin(rawOrigin).origin;
      clone.origin = canon;
      clone.endpoint = canon;
    } catch {
      clone.origin = rawOrigin;
      clone.endpoint = rawOrigin;
    }
  }
  let pins = [];
  if (Array.isArray(clone.spki_pins) && clone.spki_pins.length > 0) {
    pins = normalizeSpkiPins(clone.spki_pins, 'spki_pins');
  } else if (clone.spki_pin) {
    pins = normalizeSpkiPins(clone.spki_pin, 'spki_pin');
  } else if (clone.spki_sha256) {
    pins = normalizeSpkiPins(clone.spki_sha256, 'spki_sha256');
  }
  clone.spki_pins = pins;
  clone.spki_pin = pins[0] ?? null;
  if (pins.length > 0) {
    clone.spki_sha256 = pins.join(',');
    clone.tls_mode = 'spki_pin';
  } else {
    delete clone.spki_sha256;
    clone.tls_mode = clone.tls_mode || 'system_ca';
  }
  return clone;
}

/**
 * Reference in-memory KeyStore implementation suitable for tests, ephemeral sessions,
 * and as a serialization base for custom persistent stores.
 */
export class MemoryKeyStore {
  /**
   * @param {{
   *   masterSeed?: Uint8Array,
   *   seenRetentionSec?: number,
   *   seenMinCapacity?: number,
   * }} [options]
   */
  constructor(options = {}) {
    /** @type {Uint8Array | null} */
    this._masterSeed = options.masterSeed ? new Uint8Array(options.masterSeed) : null;
    if (this._masterSeed && this._masterSeed.length !== 32) {
      throw new SyncError(ErrorCode.ERR_KEYSTORE_ERROR, 'device_master_seed must be exactly 32 bytes');
    }
    /** @type {Map<string, any>} */
    this._relays = new Map();
    /** @type {Map<string, any>} */
    this._devices = new Map();
    /** @type {Map<string, { msgId: string, createdAt: number, seenAt: number }>} */
    this._seenMsgIds = new Map();
    /** @type {Map<string, any>} */
    this._manifestCache = new Map();
    this._seenRetentionSec = options.seenRetentionSec ?? DEFAULT_SEEN_RETENTION_SEC;
    this._seenMinCapacity = options.seenMinCapacity ?? DEFAULT_SEEN_MIN_CAPACITY;
    this._replayWatermarkTs = 0;
  }

  async loadOrCreateMasterSeed() {
    if (!this._masterSeed) {
      this._masterSeed = new Uint8Array(32);
      globalThis.crypto.getRandomValues(this._masterSeed);
    }
    return new Uint8Array(this._masterSeed);
  }

  /** @param {string} relayIdOrAlias */
  async getRelayProfile(relayIdOrAlias) {
    const key = String(relayIdOrAlias || '').trim();
    const direct = this._relays.get(key);
    if (direct) return normalizeStoredRelayProfile(direct);
    const lower = key.toLowerCase();
    for (const p of this._relays.values()) {
      if (p.alias && String(p.alias).toLowerCase() === lower) {
        return normalizeStoredRelayProfile(p);
      }
    }
    return null;
  }

  async getDefaultRelayProfile() {
    let first = null;
    for (const p of this._relays.values()) {
      if (p.is_default) return normalizeStoredRelayProfile(p);
      if (!first || String(p.relay_id) < String(first.relay_id)) {
        first = p;
      }
    }
    return first ? normalizeStoredRelayProfile(first) : null;
  }

  async listRelayProfiles() {
    return Array.from(this._relays.values())
      .map((p) => normalizeStoredRelayProfile(p))
      .sort((a, b) => String(a.relay_id).localeCompare(String(b.relay_id)));
  }

  /** @param {any} profile */
  async saveRelayProfile(profile) {
    if (!profile || !profile.relay_id) {
      throw new SyncError(ErrorCode.ERR_KEYSTORE_ERROR, 'relay profile missing relay_id');
    }
    const normalized = normalizeStoredRelayProfile(profile);
    if (normalized.is_default || this._relays.size === 0) {
      normalized.is_default = true;
      for (const [id, existing] of this._relays) {
        if (id !== normalized.relay_id && existing.is_default) {
          existing.is_default = false;
        }
      }
    }
    this._relays.set(normalized.relay_id, normalized);
  }

  /** @param {{ includeRevoked?: boolean }} [options] */
  async listDevices(options = {}) {
    const includeRevoked = Boolean(options?.includeRevoked);
    return Array.from(this._devices.values())
      .filter((c) => (includeRevoked ? true : !c.revoked))
      .sort((a, b) => (a.paired_at ?? 0) - (b.paired_at ?? 0))
      .map((c) => structuredClone(c));
  }

  /** @param {string} deviceId */
  async getDevice(deviceId) {
    const id = String(deviceId ?? '').toLowerCase().trim();
    const card = this._devices.get(id);
    return card ? structuredClone(card) : null;
  }

  /** @param {any} card */
  async putDevice(card) {
    if (!card || !card.device_id) {
      throw new SyncError(ErrorCode.ERR_KEYSTORE_ERROR, 'device card missing device_id');
    }
    const id = String(card.device_id).toLowerCase().trim();
    this._devices.set(id, { ...structuredClone(card), device_id: id });
  }

  /** @param {string} deviceId */
  async deleteDevice(deviceId) {
    const id = String(deviceId ?? '').toLowerCase().trim();
    this._devices.delete(id);
  }

  /** @param {string} msgId */
  async hasSeenMsgID(msgId) {
    const id = String(msgId ?? '').toLowerCase().trim();
    return this._seenMsgIds.has(id);
  }

  /**
   * @param {string} msgId
   * @param {number} createdAt
   * @param {number} [seenAt]
   */
  async markSeenMsgID(msgId, createdAt, seenAt = Math.floor(Date.now() / 1000)) {
    const id = String(msgId ?? '').toLowerCase().trim();
    this._seenMsgIds.set(id, { msgId: id, createdAt, seenAt });
    this._pruneSeen(seenAt);
  }

  async getReplayWatermark() {
    return this._replayWatermarkTs;
  }

  /** @param {number} nowSec */
  _pruneSeen(nowSec) {
    if (this._seenMsgIds.size <= this._seenMinCapacity) return;
    const cutoff = nowSec - this._seenRetentionSec;
    const sorted = Array.from(this._seenMsgIds.values()).sort((a, b) => a.seenAt - b.seenAt);
    for (const entry of sorted) {
      if (this._seenMsgIds.size <= this._seenMinCapacity) break;
      if (entry.seenAt < cutoff) {
        if (typeof entry.createdAt === 'number' && entry.createdAt > this._replayWatermarkTs) {
          this._replayWatermarkTs = entry.createdAt;
        }
        this._seenMsgIds.delete(entry.msgId);
      }
    }
  }

  /**
   * Optional local manifest preview cache keyed by item_id (prevents hitting part_id=0 16-download cap).
   * @param {string} itemId
   */
  async getCachedManifestPreview(itemId) {
    const val = this._manifestCache.get(itemId);
    return val ? structuredClone(val) : null;
  }

  /**
   * @param {string} itemId
   * @param {any} preview
   */
  async putCachedManifestPreview(itemId, preview) {
    this._manifestCache.set(itemId, structuredClone(preview));
  }

  /** @param {string} itemId */
  async deleteCachedManifestPreview(itemId) {
    this._manifestCache.delete(itemId);
  }

  /** @param {Set<string>} activeItemIds */
  async pruneCachedManifestPreviews(activeItemIds) {
    for (const id of this._manifestCache.keys()) {
      if (!activeItemIds.has(id)) {
        this._manifestCache.delete(id);
      }
    }
  }
}

export { NodeFileKeyStore } from './keystore_node.js';
