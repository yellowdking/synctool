// Cross-platform zero-dependency synctool v1 client (Browser / PWA / Node.js 20+ / Deno / Bun / Electron / Tauri).
// Implements spec/PROTOCOL.md, spec/CRYPTO_AND_AUTH.md, and spec/ENVELOPE_AND_SDK.md.

import {
  bytesToHex,
  deriveDeviceIdentity,
  deriveMailboxIdentity,
  deriveRelayId,
  randomBytes,
  signMailboxRequest,
  signRelayRequest,
  utf8Encode,
  zeroBytes,
} from './crypto.js';
import {
  ErrorCode,
  SyncError,
  canonicalizeRelayOrigin,
  isBareIP,
  parseRelayURI,
  resolveConfigSpkiPins,
} from './envelope.js';
import { MemoryKeyStore } from './keystore.js';
import {
  DEFAULT_MAX_IN_MEMORY_BLOB_BYTES,
  StreamingSha256,
  blobFromBytes,
  blobFromNodeFile,
  blobFromSliceReader,
  blobFromWebBlob,
  createNodeFileBlobSink,
  createNodePinnedAgent,
  isNodeRuntime,
  nodePinnedFetch,
} from './client_transport.js';
import { acceptDeviceBindImpl, startDeviceBindImpl } from './client_pair.js';
import { receiveDirectImpl, receiveOneShotImpl, startOneShotSendImpl } from './client_pipe.js';
import {
  fetchParcelImpl,
  listInboxImpl,
  revokeDeviceImpl,
  sendToDeviceImpl,
  watchInboxImpl,
} from './client_spool.js';
import {
  createClientFromEnv,
  receiveFromRoomImpl,
  resolveDeviceCard,
  sendTextImpl,
  syncMailboxImpl,
} from './client_heal.js';

export {
  DEFAULT_MAX_IN_MEMORY_BLOB_BYTES,
  StreamingSha256,
  blobFromWebBlob,
  blobFromSliceReader,
  blobFromBytes,
  blobFromNodeFile,
  createNodeFileBlobSink,
  resolveDeviceCard,
};

const CLIENT_UA = 'synctool-ts/0.3.0';
export const MAX_CLOCK_SKEW_OFFSET_SEC = 365 * 86400; // ±365 days safe bound (ST-P1-6)

function clampClockOffset(offsetSec) {
  if (!Number.isFinite(offsetSec)) return 0;
  return Math.max(-MAX_CLOCK_SKEW_OFFSET_SEC, Math.min(MAX_CLOCK_SKEW_OFFSET_SEC, Math.trunc(offsetSec)));
}

function normalizeClientRelayConfig(relayInput) {
  if (typeof relayInput === 'string') {
    return parseRelayURI(relayInput);
  }
  if (!relayInput || typeof relayInput !== 'object') {
    throw new SyncError(ErrorCode.ERR_URI_INVALID, 'invalid relay configuration');
  }
  const rawOrigin = relayInput.origin ?? relayInput.endpoint ?? '';
  const canon = canonicalizeRelayOrigin(rawOrigin);
  const spkiPins = resolveConfigSpkiPins(
    {
      spkiPins: relayInput.spkiPins ?? relayInput.spki_pins,
      spkiPin: relayInput.spkiPin ?? relayInput.spki_pin ?? relayInput.spki_sha256,
    },
    'spkiPin',
  );
  const accessKey = relayInput.accessKey ?? relayInput.access_key ?? '';
  if (!accessKey || accessKey.length < 32) {
    throw new SyncError(ErrorCode.ERR_URI_INVALID, 'relay accessKey must be >= 32 chars');
  }
  if (spkiPins.length === 0 && canon.scheme === 'https' && isBareIP(canon.hostname)) {
    throw new SyncError(ErrorCode.ERR_URI_INVALID, 'bare IP https relay requires SPKI pin');
  }
  const tlsMode = spkiPins.length > 0 ? 'spki_pin' : (relayInput.tlsMode ?? relayInput.tls_mode ?? 'system_ca');
  if (tlsMode === 'spki_pin' && spkiPins.length === 0) {
    throw new SyncError(ErrorCode.ERR_URI_INVALID, 'tlsMode="spki_pin" requires at least one 64-hex SPKI pin');
  }
  return {
    version: 1,
    origin: canon.origin,
    tlsMode,
    spkiPin: spkiPins[0] ?? null,
    spkiPins,
    accessKey,
  };
}

// ============================================================================
// SyncClient Implementation
// ============================================================================

export class SyncClient {
  /**
   * @param {{
   *   relay: string | { origin: string, tlsMode?: 'system_ca'|'spki_pin', spkiPin?: string|null, spkiPins?: string[]|null, accessKey: string },
   *   keyStore?: any,
   *   appId?: string,
   *   label?: string,
   *   platform?: string,
   *   fetchImpl?: typeof fetch,
   *   onCertExpiring?: (event: any) => void,
   *   clockOffsetSec?: number,
   *   maxInMemoryBlobBytes?: number,
   * }} config
   */
  constructor(config) {
    if (!config || !config.relay) {
      throw new SyncError(ErrorCode.ERR_URI_INVALID, 'SyncClient requires relay configuration or synctool://relay URI');
    }
    this.relay = normalizeClientRelayConfig(config.relay);
    this.keyStore = config.keyStore ?? new MemoryKeyStore();
    this.appId = config.appId ?? 'synctool.ts';
    this.label = config.label ?? 'synctool-ts';
    this.platform = config.platform ?? (isNodeRuntime() ? 'linux' : 'web');
    this._fetchImpl = config.fetchImpl ?? null;
    this._onCertExpiring = config.onCertExpiring ?? null;
    this._clockOffsetSec = clampClockOffset(config.clockOffsetSec ?? 0);
    this._maxInMemoryBlobBytes = config.maxInMemoryBlobBytes ?? DEFAULT_MAX_IN_MEMORY_BLOB_BYTES;

    this._cachedCaps = null;
    this._identityPromise = null;
    this._resolvedIdentity = null;
    this._relayIdPromise = null;
    this._mailboxIdentityPromise = null;
    this._resolvedMailboxIdentity = null;
    this._pinnedAgentPromise = null;
    this._pinnedAgent = null;
    /** @type {Set<AbortController>} */
    this._activeControllers = new Set();
    /** @type {Set<string>} */
    this._inFlightMsgIds = new Set();
    this._closed = false;
  }

  static fromEnv(overrides = {}) {
    return createClientFromEnv(SyncClient, overrides);
  }

  _assertOpen() {
    if (this._closed) {
      throw new SyncError(ErrorCode.ERR_CANCELLED, 'SyncClient is closed');
    }
  }

  /** Local wall-clock Unix seconds — NEVER tainted by relay `clockOffsetSec` (ST-P1-6). */
  _localNowSec() {
    return Math.floor(Date.now() / 1000);
  }

  /** Relay HTTP authentication timestamp (`X-Sync-TS` / `since_ts` ONLY) (ST-P1-6). */
  _authNowSec() {
    return this._localNowSec() + this._clockOffsetSec;
  }

  async _getReplayWatermarkSec() {
    if (typeof this.keyStore?.getReplayWatermark === 'function') {
      return (await this.keyStore.getReplayWatermark()) ?? 0;
    }
    return 0;
  }

  async getRelayId() {
    this._assertOpen();
    if (!this._relayIdPromise) {
      this._relayIdPromise = deriveRelayId(this.relay.origin).catch((err) => {
        this._relayIdPromise = null;
        throw err;
      });
    }
    return this._relayIdPromise;
  }

  async getIdentity() {
    this._assertOpen();
    if (!this._identityPromise) {
      this._identityPromise = (async () => {
        const seed = await this.keyStore.loadOrCreateMasterSeed();
        try {
          const id = await deriveDeviceIdentity(seed);
          if (this._closed) {
            this._zeroIdentity(id);
            throw new SyncError(ErrorCode.ERR_CANCELLED, 'SyncClient is closed');
          }
          this._resolvedIdentity = id;
          return id;
        } finally {
          zeroBytes(seed);
        }
      })().catch((err) => {
        this._identityPromise = null;
        throw err;
      });
    }
    return this._identityPromise;
  }

  async getMailboxIdentity() {
    this._assertOpen();
    if (!this._mailboxIdentityPromise) {
      this._mailboxIdentityPromise = (async () => {
        const [seed, relayId] = await Promise.all([
          this.keyStore.loadOrCreateMasterSeed(),
          this.getRelayId(),
        ]);
        try {
          const mb = await deriveMailboxIdentity(seed, relayId);
          if (this._closed) {
            zeroBytes(mb.mailboxAuthSeed);
            throw new SyncError(ErrorCode.ERR_CANCELLED, 'SyncClient is closed');
          }
          this._resolvedMailboxIdentity = mb;
          return mb;
        } finally {
          zeroBytes(seed);
        }
      })().catch((err) => {
        this._mailboxIdentityPromise = null;
        throw err;
      });
    }
    return this._mailboxIdentityPromise;
  }

  _zeroIdentity(id) {
    if (!id) return;
    zeroBytes(id.masterPrk);
    zeroBytes(id.signSeed);
    zeroBytes(id.kemSk);
    zeroBytes(id.localMetaKey);
  }

  /**
   * Abort all active requests, destroy keep-alive TLS SPKI agent sockets, and wipe derived secret keys in RAM (ST-P1-13).
   */
  async close() {
    if (this._closed) return;
    this._closed = true;

    for (const ctrl of this._activeControllers) {
      ctrl.abort();
    }
    this._activeControllers.clear();

    const pendingId = this._identityPromise;
    const pendingMb = this._mailboxIdentityPromise;
    this._identityPromise = null;
    this._mailboxIdentityPromise = null;

    if (pendingId) {
      const id = await pendingId.catch(() => null);
      this._zeroIdentity(id);
    }
    this._zeroIdentity(this._resolvedIdentity);
    this._resolvedIdentity = null;

    if (pendingMb) {
      const mb = await pendingMb.catch(() => null);
      if (mb) zeroBytes(mb.mailboxAuthSeed);
    }
    if (this._resolvedMailboxIdentity) {
      zeroBytes(this._resolvedMailboxIdentity.mailboxAuthSeed);
      this._resolvedMailboxIdentity = null;
    }

    if (this._pinnedAgentPromise) {
      const agent = await this._pinnedAgentPromise.catch(() => null);
      agent?.destroy();
      this._pinnedAgentPromise = null;
    }
    if (this._pinnedAgent) {
      this._pinnedAgent.destroy();
      this._pinnedAgent = null;
    }
  }

  async _getOrCreatePinnedAgent() {
    if (this._pinnedAgent) return this._pinnedAgent;
    if (!this._pinnedAgentPromise) {
      this._pinnedAgentPromise = createNodePinnedAgent(this.relay.spkiPins)
        .then((agent) => {
          if (this._closed) {
            agent.destroy();
            throw new SyncError(ErrorCode.ERR_CANCELLED, 'SyncClient is closed');
          }
          this._pinnedAgent = agent;
          return agent;
        })
        .catch((err) => {
          this._pinnedAgentPromise = null;
          throw err;
        });
    }
    return this._pinnedAgentPromise;
  }

  // --------------------------------------------------------------------------
  // Low-Level Transport & Authenticated Request Pipeline (with 409 Clock Skew Retry)
  // --------------------------------------------------------------------------

  async _rawTransport(url, init = {}) {
    this._assertOpen();
    const reqCtrl = new AbortController();
    const callerSignal = init.signal;
    const onCallerAbort = () => reqCtrl.abort();
    if (callerSignal) {
      if (callerSignal.aborted) {
        throw new SyncError(ErrorCode.ERR_CANCELLED, 'request aborted');
      }
      callerSignal.addEventListener('abort', onCallerAbort, { once: true });
    }
    this._activeControllers.add(reqCtrl);

    const effectiveInit = { ...init, signal: reqCtrl.signal };
    try {
      if (this._fetchImpl) {
        try {
          return await this._fetchImpl(url, effectiveInit);
        } catch (err) {
          if (err instanceof SyncError) throw err;
          if (reqCtrl.signal.aborted) throw new SyncError(ErrorCode.ERR_CANCELLED, 'request aborted', { cause: err });
          const errDesc = `${err?.message || ''} ${err?.cause?.message || ''}`;
          const isRedirectBlock = effectiveInit.redirect === 'error' && /redirect/i.test(errDesc);
          throw new SyncError(
            ErrorCode.ERR_RELAY_UNREACHABLE,
            isRedirectBlock ? 'relay HTTP redirect blocked for credential safety' : `fetch failed: ${err.message}`,
            { retryable: !isRedirectBlock, cause: err },
          );
        }
      }
      if (this.relay.tlsMode === 'spki_pin' && this.relay.spkiPins.length > 0) {
        if (!isNodeRuntime()) {
          throw new SyncError(
            ErrorCode.ERR_TLS_CERT_INVALID,
            'browser sandbox cannot perform custom TLS SPKI pinning; use HTTPS domain with system_ca or Node/native runtime',
          );
        }
        const agent = await this._getOrCreatePinnedAgent();
        return await nodePinnedFetch(url, effectiveInit, this.relay.spkiPins, agent);
      }
      try {
        return await globalThis.fetch(url, effectiveInit);
      } catch (err) {
        if (reqCtrl.signal.aborted) throw new SyncError(ErrorCode.ERR_CANCELLED, 'request aborted', { cause: err });
        const errDesc = `${err?.message || ''} ${err?.cause?.message || ''}`;
        const isRedirectBlock = effectiveInit.redirect === 'error' && /redirect/i.test(errDesc);
        throw new SyncError(
          ErrorCode.ERR_RELAY_UNREACHABLE,
          isRedirectBlock ? 'relay HTTP redirect blocked for credential safety' : `relay unreachable: ${err.message}`,
          { retryable: !isRedirectBlock, cause: err },
        );
      }
    } finally {
      this._activeControllers.delete(reqCtrl);
      callerSignal?.removeEventListener('abort', onCallerAbort);
    }
  }

  /**
   * Perform an authenticated relay request with automatic 1-time 409 ERR_CLOCK_SKEW adjustment & retry.
   */
  async _signedRequest(opts) {
    return this._signedRequestAttempt(opts, 0);
  }

  async _signedRequestAttempt(opts, attempt) {
    this._assertOpen();
    const method = opts.method.toUpperCase();
    const pathAndRawQuery = opts.path;
    const isDataPlanePut = Boolean(opts.isDataPlanePut);
    const bodyBytes = opts.jsonBody !== undefined
      ? utf8Encode(JSON.stringify(opts.jsonBody))
      : (opts.bodyBytes ?? null);

    const ts = this._authNowSec();
    const nonce = bytesToHex(randomBytes(16));

    const sigParams = {
      accessKey: this.relay.accessKey,
      method,
      pathAndRawQuery,
      ts,
      nonce,
      bodyBytes: isDataPlanePut ? null : bodyBytes,
      streamContentLength: isDataPlanePut ? (bodyBytes ? bodyBytes.byteLength : 0) : null,
      depositToken: opts.depositToken ?? null,
      uploadToken: opts.uploadToken ?? null,
    };
    const { sigHex } = await signRelayRequest(sigParams);

    const headers = {
      'X-Sync-TS': String(ts),
      'X-Sync-Nonce': nonce,
      'X-Sync-Sig': sigHex,
      'X-Sync-Client': CLIENT_UA,
    };
    if (opts.jsonBody !== undefined) {
      headers['Content-Type'] = 'application/json; charset=utf-8';
    } else if (isDataPlanePut) {
      headers['Content-Type'] = 'application/octet-stream';
      headers['Content-Length'] = String(bodyBytes ? bodyBytes.byteLength : 0);
    }
    if (opts.roomToken) headers['X-Sync-Room-Token'] = opts.roomToken;
    if (opts.depositToken) headers['X-Sync-Deposit-Token'] = opts.depositToken;
    if (opts.uploadToken) headers['X-Sync-Upload-Token'] = opts.uploadToken;

    if (opts.signMailbox) {
      const mb = await this.getMailboxIdentity();
      const targetMailboxId = opts.mailboxId ?? mb.mailboxId;
      const { sigB64u } = await signMailboxRequest({
        mailboxAuthSeed: mb.mailboxAuthSeed,
        method,
        pathAndRawQuery,
        mailboxId: targetMailboxId,
        ts,
        nonce,
        bodyBytes: isDataPlanePut ? null : bodyBytes,
        streamContentLength: isDataPlanePut ? (bodyBytes ? bodyBytes.byteLength : 0) : null,
      });
      headers['X-Sync-Mailbox-Sig'] = sigB64u;
    }

    const url = `${this.relay.origin}${pathAndRawQuery}`;
    const res = await this._rawTransport(url, {
      method,
      headers,
      body: bodyBytes && bodyBytes.byteLength > 0 ? bodyBytes : undefined,
      redirect: 'error',
      signal: opts.signal,
    });

    if (res.status >= 200 && res.status < 300) {
      return res;
    }
    if (res.status >= 300 && res.status < 400) {
      // ST-P2-15: cancel any unread 3xx redirect response stream immediately
      res.body?.cancel?.().catch(() => {});
      throw new SyncError(ErrorCode.ERR_RELAY_UNREACHABLE, 'relay HTTP redirect blocked for credential and SPKI pin safety', {
        retryable: false,
        httpStatus: res.status,
      });
    }

    // Parse error response
    const rawText = await res.text().catch(() => '');
    if (res.status === 404 && rawText.trim() === '') {
      throw new SyncError(ErrorCode.ERR_AUTH_FAILED, 'relay returned silent 404 (invalid access key, signature, or IP banned)', {
        httpStatus: 404,
      });
    }

    let errJson = null;
    try {
      errJson = rawText ? JSON.parse(rawText) : null;
    } catch {
      errJson = null;
    }

    // Automatic 1-time 409 ERR_CLOCK_SKEW adjustment & retry with fresh nonce, clamped to ±365d (ST-P1-6)
    const rawServerTs = typeof errJson?.server_ts === 'number' ? errJson.server_ts : errJson?.server_unix;
    if (
      res.status === 409 &&
      errJson?.error === ErrorCode.ERR_CLOCK_SKEW &&
      Number.isFinite(rawServerTs) &&
      rawServerTs > 0 &&
      attempt === 0
    ) {
      const rawOffset = Math.trunc(rawServerTs) - this._localNowSec();
      this._clockOffsetSec = clampClockOffset(rawOffset);
      return this._signedRequestAttempt(opts, 1);
    }

    if (errJson && typeof errJson.error === 'string') {
      const { error: code, message, retryable, ...rest } = errJson;
      const retryAfter = res.headers.get('retry-after');
      if (retryAfter && rest.retry_after_sec === undefined) {
        const parsed = Number(retryAfter);
        if (Number.isFinite(parsed)) rest.retry_after_sec = parsed;
      }
      throw new SyncError(code, message || code, {
        retryable: Boolean(retryable),
        httpStatus: res.status,
        details: rest,
      });
    }

    throw new SyncError(ErrorCode.ERR_RELAY_UNREACHABLE, `unexpected relay HTTP ${res.status}`, {
      retryable: res.status >= 500,
      httpStatus: res.status,
    });
  }

  async _checkCertExpiryEvent(payload) {
    if (!this._onCertExpiring || !payload || !payload.cert_rotate_recommended || !payload.cert_expires_at) return;
    const nowSec = payload.server_ts ?? this._localNowSec();
    const daysRemaining = Math.max(0, Math.floor((payload.cert_expires_at - nowSec) / 86400));
    const relayId = await this.getRelayId();
    this._onCertExpiring({
      type: 'event',
      event: 'relay_cert_expiring_soon',
      relay_id: relayId,
      expires_at: payload.cert_expires_at,
      days_remaining: daysRemaining,
      severity: daysRemaining <= 7 ? 'urgent' : 'warning',
    });
  }

  // --------------------------------------------------------------------------
  // §5.1 System Probe, Capabilities & Mailbox Registration
  // --------------------------------------------------------------------------

  async ping(opts = {}) {
    const start = Date.now();
    const res = await this._signedRequest({ method: 'GET', path: '/v1/ping', signal: opts.signal });
    const data = await res.json();
    const rttMs = Date.now() - start;
    await this._checkCertExpiryEvent(data);
    return { ...data, rtt_ms: rttMs, clock_offset_sec: this._clockOffsetSec };
  }

  async capabilities(opts = {}) {
    if (this._cachedCaps && !opts.refresh) return this._cachedCaps;
    const res = await this._signedRequest({ method: 'GET', path: '/v1/caps', signal: opts.signal });
    const data = await res.json();
    this._cachedCaps = data;
    await this._checkCertExpiryEvent(data);
    return data;
  }

  async registerMailbox(opts = {}) {
    return syncMailboxImpl(this, opts);
  }

  async syncMailbox(opts = {}) {
    return syncMailboxImpl(this, opts);
  }

  // --------------------------------------------------------------------------
  // High-Level Flow Methods (Delegated to Modular Internal Engines)
  // --------------------------------------------------------------------------

  startDeviceBind(opts = {}) {
    return startDeviceBindImpl(this, opts);
  }

  initiateDeviceBind(opts = {}) {
    return startDeviceBindImpl(this, opts);
  }

  acceptDeviceBind(pairInput, opts = {}) {
    return acceptDeviceBindImpl(this, pairInput, opts);
  }

  startOneShotSend(parcel, opts = {}) {
    return startOneShotSendImpl(this, parcel, opts);
  }

  receiveOneShot(pairInput, handler, opts = {}) {
    return receiveOneShotImpl(this, pairInput, handler, opts);
  }

  sendToDevice(targetDeviceId, parcel, opts = {}) {
    return sendToDeviceImpl(this, targetDeviceId, parcel, opts);
  }

  sendText(targetDeviceOrLabel, text, opts = {}) {
    return sendTextImpl(this, targetDeviceOrLabel, text, opts);
  }

  receiveDirect(pairInput, handler, opts = {}) {
    return receiveDirectImpl(this, pairInput, handler, opts);
  }

  receiveFromRoom(pairInput, handler, opts = {}) {
    return receiveFromRoomImpl(this, pairInput, handler, opts);
  }

  listInbox(opts = {}) {
    return listInboxImpl(this, opts);
  }

  fetchParcel(itemId, handler, opts = {}) {
    return fetchParcelImpl(this, itemId, handler, opts);
  }

  watchInbox(opts) {
    return watchInboxImpl(this, opts);
  }

  revokeDevice(deviceId, opts = {}) {
    return revokeDeviceImpl(this, deviceId, opts);
  }
}
