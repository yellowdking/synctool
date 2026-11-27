// Minimal KeyStore interface (single 32B device_master_seed + DeviceCard + 30-day seen_msg_ids)
// + reference MemoryKeyStore implementation (spec/ENVELOPE_AND_SDK.md §5.1).
//
// Host adaptation notes:
// - Browser / PWA: store device_master_seed in IndexedDB (ideally wrapped by a non-extractable
//   WebCrypto AES-GCM key or OS passkey/WebAuthn PRF), never localStorage plaintext if avoidable.
// - Electron / Tauri: use OS Keychain / DPAPI / Secret Service (safeStorage / keyring plugin)
//   for the single 32B device_master_seed and encrypt DeviceCard/seen_msg_ids with local_meta_key.
// - Node.js CLI / service: persist in mode-0600 file in mode-0700 directory (encrypted via OS vault).

import { ErrorCode, SyncError } from './envelope.js';

export const DEFAULT_SEEN_RETENTION_SEC = 30 * 24 * 3600; // 30 days
export const DEFAULT_SEEN_MIN_CAPACITY = 4096;

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
    /** @type {Map<string, { createdAt: number, seenAt: number }>} */
    this._seenMsgIds = new Map();
    /** @type {Map<string, any>} */
    this._manifestCache = new Map();
    this._seenRetentionSec = options.seenRetentionSec ?? DEFAULT_SEEN_RETENTION_SEC;
    this._seenMinCapacity = options.seenMinCapacity ?? DEFAULT_SEEN_MIN_CAPACITY;
  }

  async loadOrCreateMasterSeed() {
    if (!this._masterSeed) {
      this._masterSeed = new Uint8Array(32);
      globalThis.crypto.getRandomValues(this._masterSeed);
    }
    return new Uint8Array(this._masterSeed);
  }

  /** @param {string} relayId */
  async getRelayProfile(relayId) {
    const profile = this._relays.get(relayId);
    return profile ? structuredClone(profile) : null;
  }

  /** @param {any} profile */
  async saveRelayProfile(profile) {
    if (!profile || !profile.relay_id) {
      throw new SyncError(ErrorCode.ERR_KEYSTORE_ERROR, 'relay profile missing relay_id');
    }
    this._relays.set(profile.relay_id, structuredClone(profile));
  }

  async listDevices() {
    return Array.from(this._devices.values()).map((c) => structuredClone(c));
  }

  /** @param {string} deviceId */
  async getDevice(deviceId) {
    const card = this._devices.get(deviceId);
    return card ? structuredClone(card) : null;
  }

  /** @param {any} card */
  async putDevice(card) {
    if (!card || !card.device_id) {
      throw new SyncError(ErrorCode.ERR_KEYSTORE_ERROR, 'device card missing device_id');
    }
    this._devices.set(card.device_id, structuredClone(card));
  }

  /** @param {string} deviceId */
  async deleteDevice(deviceId) {
    this._devices.delete(deviceId);
  }

  /** @param {string} msgId */
  async hasSeenMsgID(msgId) {
    return this._seenMsgIds.has(msgId);
  }

  /**
   * @param {string} msgId
   * @param {number} createdAt
   * @param {number} [seenAt]
   */
  async markSeenMsgID(msgId, createdAt, seenAt = Math.floor(Date.now() / 1000)) {
    this._seenMsgIds.set(msgId, { createdAt, seenAt });
    this._pruneSeen(seenAt);
  }

  /** @param {number} nowSec */
  _pruneSeen(nowSec) {
    if (this._seenMsgIds.size <= this._seenMinCapacity) return;
    const cutoff = nowSec - this._seenRetentionSec;
    for (const [id, entry] of this._seenMsgIds) {
      if (this._seenMsgIds.size <= this._seenMinCapacity) break;
      if (entry.seenAt < cutoff) {
        this._seenMsgIds.delete(id);
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
