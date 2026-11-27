// Cross-platform zero-dependency synctool v1 client (Browser / PWA / Node.js 20+ / Deno / Bun / Electron / Tauri).
// Implements spec/PROTOCOL.md, spec/CRYPTO_AND_AUTH.md, and spec/ENVELOPE_AND_SDK.md.

import {
  bytesToB64u,
  bytesToHex,
  deriveDeviceIdentity,
  deriveMailboxIdentity,
  deriveRelayId,
  randomBytes,
  signMailboxRequest,
  signRelayRequest,
  utf8Encode,
} from './crypto.js';
import {
  ErrorCode,
  SyncError,
  canonicalizeRelayOrigin,
  isBareIP,
  parseRelayURI,
} from './envelope.js';
import { MemoryKeyStore } from './keystore.js';
import {
  StreamingSha256,
  blobFromBytes,
  blobFromSliceReader,
  blobFromWebBlob,
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

export { StreamingSha256, blobFromWebBlob, blobFromSliceReader, blobFromBytes };

const CLIENT_UA = 'synctool-ts/1.0';

// ============================================================================
// SyncClient Implementation
// ============================================================================

export class SyncClient {
  /**
   * @param {{
   *   relay: string | { origin: string, tlsMode?: 'system_ca'|'spki_pin', spkiPin?: string|null, accessKey: string },
   *   keyStore?: any,
   *   appId?: string,
   *   label?: string,
   *   platform?: string,
   *   fetchImpl?: typeof fetch,
   *   onCertExpiring?: (event: any) => void,
   *   clockOffsetSec?: number,
   * }} config
   */
  constructor(config) {
    if (!config || !config.relay) {
      throw new SyncError(ErrorCode.ERR_URI_INVALID, 'SyncClient requires relay configuration or synctool://relay URI');
    }
    const parsedRelay = typeof config.relay === 'string' ? parseRelayURI(config.relay) : {
      origin: canonicalizeRelayOrigin(config.relay.origin).origin,
      tlsMode: config.relay.spkiPin ? 'spki_pin' : (config.relay.tlsMode ?? 'system_ca'),
      spkiPin: config.relay.spkiPin ?? null,
      accessKey: config.relay.accessKey,
    };
    if (!parsedRelay.accessKey || parsedRelay.accessKey.length < 32) {
      throw new SyncError(ErrorCode.ERR_URI_INVALID, 'relay accessKey must be >= 32 chars');
    }
    const canon = canonicalizeRelayOrigin(parsedRelay.origin);
    if (canon.scheme === 'https' && isBareIP(canon.hostname) && !parsedRelay.spkiPin) {
      throw new SyncError(ErrorCode.ERR_URI_INVALID, 'bare IP https relay requires SPKI pin');
    }

    this.relay = parsedRelay;
    this.keyStore = config.keyStore ?? new MemoryKeyStore();
    this.appId = config.appId ?? 'synctool.ts';
    this.label = config.label ?? 'synctool-ts';
    this.platform = config.platform ?? (isNodeRuntime() ? 'linux' : 'web');
    this._fetchImpl = config.fetchImpl ?? null;
    this._onCertExpiring = config.onCertExpiring ?? null;
    this._clockOffsetSec = config.clockOffsetSec ?? 0;
    this._cachedCaps = null;
    this._identityPromise = null;
    this._relayIdPromise = null;
    this._mailboxIdentityPromise = null;
  }

  async getRelayId() {
    if (!this._relayIdPromise) {
      this._relayIdPromise = deriveRelayId(this.relay.origin);
    }
    return this._relayIdPromise;
  }

  async getIdentity() {
    if (!this._identityPromise) {
      this._identityPromise = (async () => {
        const seed = await this.keyStore.loadOrCreateMasterSeed();
        return deriveDeviceIdentity(seed);
      })();
    }
    return this._identityPromise;
  }

  async getMailboxIdentity() {
    if (!this._mailboxIdentityPromise) {
      this._mailboxIdentityPromise = (async () => {
        const [seed, relayId] = await Promise.all([
          this.keyStore.loadOrCreateMasterSeed(),
          this.getRelayId(),
        ]);
        return deriveMailboxIdentity(seed, relayId);
      })();
    }
    return this._mailboxIdentityPromise;
  }

  // --------------------------------------------------------------------------
  // Low-Level Transport & Authenticated Request Pipeline (with 409 Clock Skew Retry)
  // --------------------------------------------------------------------------

  async _rawTransport(url, init) {
    if (this._fetchImpl) {
      try {
        return await this._fetchImpl(url, init);
      } catch (err) {
        if (err instanceof SyncError) throw err;
        if (init.signal?.aborted) throw new SyncError(ErrorCode.ERR_CANCELLED, 'request aborted', { cause: err });
        throw new SyncError(ErrorCode.ERR_RELAY_UNREACHABLE, `fetch failed: ${err.message}`, { retryable: true, cause: err });
      }
    }
    if (this.relay.tlsMode === 'spki_pin' && this.relay.spkiPin) {
      if (!isNodeRuntime()) {
        throw new SyncError(
          ErrorCode.ERR_TLS_CERT_INVALID,
          'browser sandbox cannot perform custom TLS SPKI pinning; use HTTPS domain with system_ca or Node/native runtime',
        );
      }
      return nodePinnedFetch(url, init, this.relay.spkiPin);
    }
    try {
      return await globalThis.fetch(url, init);
    } catch (err) {
      if (init.signal?.aborted) throw new SyncError(ErrorCode.ERR_CANCELLED, 'request aborted', { cause: err });
      throw new SyncError(ErrorCode.ERR_RELAY_UNREACHABLE, `relay unreachable: ${err.message}`, { retryable: true, cause: err });
    }
  }

  /**
   * Perform an authenticated relay request with automatic 1-time 409 ERR_CLOCK_SKEW adjustment & retry.
   */
  async _signedRequest(opts) {
    return this._signedRequestAttempt(opts, 0);
  }

  async _signedRequestAttempt(opts, attempt) {
    const method = opts.method.toUpperCase();
    const pathAndRawQuery = opts.path; // e.g. "/v1/ping" or "/v1/rooms/ABCD1234/events?since=0&mode=sse"
    const isDataPlanePut = Boolean(opts.isDataPlanePut);
    const bodyBytes = opts.jsonBody !== undefined
      ? utf8Encode(JSON.stringify(opts.jsonBody))
      : (opts.bodyBytes ?? null);

    const ts = Math.floor(Date.now() / 1000) + this._clockOffsetSec;
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
      signal: opts.signal,
    });

    if (res.status >= 200 && res.status < 300) {
      return res;
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

    // Automatic 1-time 409 ERR_CLOCK_SKEW adjustment & retry with fresh nonce (spec/CRYPTO_AND_AUTH.md §7.3)
    if (res.status === 409 && errJson?.error === ErrorCode.ERR_CLOCK_SKEW && typeof errJson.server_ts === 'number' && attempt === 0) {
      this._clockOffsetSec = errJson.server_ts - Math.floor(Date.now() / 1000);
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
    const nowSec = payload.server_ts ?? Math.floor(Date.now() / 1000);
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
    const mb = await this.getMailboxIdentity();
    const res = await this._signedRequest({
      method: 'PUT',
      path: `/v1/mailboxes/${mb.mailboxId}`,
      jsonBody: { auth_pk_b64: bytesToB64u(mb.mailboxAuthPk) },
      signMailbox: true,
      mailboxId: mb.mailboxId,
      signal: opts.signal,
    });
    return res.json();
  }

  // --------------------------------------------------------------------------
  // High-Level Flow Methods (Delegated to Modular Internal Engines)
  // --------------------------------------------------------------------------

  startDeviceBind(opts = {}) {
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

  receiveDirect(pairInput, handler, opts = {}) {
    return receiveDirectImpl(this, pairInput, handler, opts);
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
