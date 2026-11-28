// Cross-language SyncError, frozen error code registry, secret auto-redaction,
// and forward-compatible error classification helpers (spec/ENVELOPE_AND_SDK.md §4).

/** Frozen cross-language error code enumeration (15 wire + 20 client/local codes). */
export const ErrorCode = Object.freeze({
  // Wire protocol codes (1-to-1 with spec/PROTOCOL.md §4)
  ERR_BAD_REQUEST: 'ERR_BAD_REQUEST',
  ERR_REPLAY_DETECTED: 'ERR_REPLAY_DETECTED',
  ERR_UNAUTHORIZED_TOKEN: 'ERR_UNAUTHORIZED_TOKEN',
  ERR_SPOOL_DISABLED: 'ERR_SPOOL_DISABLED',
  ERR_DOWNLOAD_LIMIT_EXCEEDED: 'ERR_DOWNLOAD_LIMIT_EXCEEDED',
  ERR_NOT_FOUND: 'ERR_NOT_FOUND',
  ERR_CLOCK_SKEW: 'ERR_CLOCK_SKEW',
  ERR_ROOM_BUSY: 'ERR_ROOM_BUSY',
  ERR_INVALID_STATE: 'ERR_INVALID_STATE',
  ERR_CONFLICT: 'ERR_CONFLICT',
  ERR_ROOM_BURNED: 'ERR_ROOM_BURNED',
  ERR_CHUNK_TOO_LARGE: 'ERR_CHUNK_TOO_LARGE',
  ERR_OFFLINE_QUOTA_EXCEEDED: 'ERR_OFFLINE_QUOTA_EXCEEDED',
  ERR_RATE_LIMITED: 'ERR_RATE_LIMITED',
  ERR_PIPE_PEER_TIMEOUT: 'ERR_PIPE_PEER_TIMEOUT',

  // Client transport, crypto & host codes
  ERR_RELAY_UNREACHABLE: 'ERR_RELAY_UNREACHABLE',
  ERR_TLS_PIN_MISMATCH: 'ERR_TLS_PIN_MISMATCH',
  ERR_TLS_CERT_INVALID: 'ERR_TLS_CERT_INVALID',
  ERR_AUTH_FAILED: 'ERR_AUTH_FAILED',
  ERR_HANDSHAKE_TIMEOUT: 'ERR_HANDSHAKE_TIMEOUT',
  ERR_SAS_MISMATCH: 'ERR_SAS_MISMATCH',
  ERR_CRYPTO_HANDSHAKE_FAILED: 'ERR_CRYPTO_HANDSHAKE_FAILED',
  ERR_CRYPTO_DECRYPT_FAILED: 'ERR_CRYPTO_DECRYPT_FAILED',
  ERR_CRYPTO_SIGNATURE_INVALID: 'ERR_CRYPTO_SIGNATURE_INVALID',
  ERR_STREAM_TRUNCATED: 'ERR_STREAM_TRUNCATED',
  ERR_MSG_REPLAY_DETECTED: 'ERR_MSG_REPLAY_DETECTED',
  ERR_HASH_MISMATCH: 'ERR_HASH_MISMATCH',
  ERR_MANIFEST_INVALID: 'ERR_MANIFEST_INVALID',
  ERR_UNSUPPORTED_VERSION: 'ERR_UNSUPPORTED_VERSION',
  ERR_DEVICE_UNTRUSTED: 'ERR_DEVICE_UNTRUSTED',
  ERR_INTERRUPTED_RESUMABLE: 'ERR_INTERRUPTED_RESUMABLE',
  ERR_URI_INVALID: 'ERR_URI_INVALID',
  ERR_KEYSTORE_ERROR: 'ERR_KEYSTORE_ERROR',
  ERR_STORAGE_IO: 'ERR_STORAGE_IO',
  ERR_CANCELLED: 'ERR_CANCELLED',
});

const REDACT_SYNC_URI_RE = /(synctool:\/\/[^\s"'<>#]*)#[^\s"'<>]*/gi;
const REDACT_FRAGMENT_RE = /#(?:[^\s"'<>]*?(?:^|&))?(?:k|s)=[^\s"'<>]*/gi;
const REDACT_QUERY_SECRET_RE = /([?&](?:k|s)=)[^\s"'&<>#]+/gi;

/**
 * Scrub any embedded synctool://#fragment or #k=/#s=/query k=/s= secret from diagnostic strings.
 * @param {string} msg
 * @returns {string}
 */
export function redactMessage(msg) {
  if (typeof msg !== 'string' || msg.length === 0) return '';
  return msg
    .replace(REDACT_SYNC_URI_RE, '$1#<redacted>')
    .replace(REDACT_FRAGMENT_RE, '#<redacted>')
    .replace(REDACT_QUERY_SECRET_RE, '$1<redacted>');
}

function redactDetailsValue(val) {
  if (typeof val === 'string') return redactMessage(val);
  if (Array.isArray(val)) return val.map(redactDetailsValue);
  if (val && typeof val === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(val)) {
      out[k] = redactDetailsValue(v);
    }
    return out;
  }
  return val;
}

/** Structured cross-language error matching spec/ENVELOPE_AND_SDK.md §4.1 (auto-redacting URI secrets). */
export class SyncError extends Error {
  /**
   * @param {string} code
   * @param {string} message
   * @param {{ retryable?: boolean, httpStatus?: number, details?: Record<string, unknown>, cause?: unknown }} [options]
   */
  constructor(code, message, options = {}) {
    const safeMessage = redactMessage(String(message ?? code));
    let safeCause = options.cause;
    if (safeCause instanceof Error && typeof safeCause.message === 'string') {
      const scrubbed = redactMessage(safeCause.message);
      if (scrubbed !== safeCause.message) {
        safeCause = new Error(scrubbed);
      }
    }
    super(safeMessage, safeCause !== undefined ? { cause: safeCause } : undefined);
    this.name = 'SyncError';
    this.code = code;
    this.retryable = Boolean(options.retryable);
    this.httpStatus = options.httpStatus ?? 0;
    this.details = options.details ? redactDetailsValue(options.details) : {};
  }

  toJSON() {
    return {
      code: this.code,
      retryable: this.retryable,
      http_status: this.httpStatus,
      message: redactMessage(this.message),
      details: redactDetailsValue(this.details),
    };
  }
}

const QUOTA_CODES = new Set([
  ErrorCode.ERR_OFFLINE_QUOTA_EXCEEDED,
  ErrorCode.ERR_SPOOL_DISABLED,
  ErrorCode.ERR_CHUNK_TOO_LARGE,
  ErrorCode.ERR_DOWNLOAD_LIMIT_EXCEEDED,
]);

const AUTH_CODES = new Set([
  ErrorCode.ERR_AUTH_FAILED,
  ErrorCode.ERR_UNAUTHORIZED_TOKEN,
  ErrorCode.ERR_DEVICE_UNTRUSTED,
  ErrorCode.ERR_TLS_PIN_MISMATCH,
  ErrorCode.ERR_TLS_CERT_INVALID,
]);

const SECURITY_ALERT_CODES = new Set([
  ErrorCode.ERR_TLS_PIN_MISMATCH,
  ErrorCode.ERR_SAS_MISMATCH,
  ErrorCode.ERR_ROOM_BURNED,
  ErrorCode.ERR_CRYPTO_HANDSHAKE_FAILED,
  ErrorCode.ERR_CRYPTO_DECRYPT_FAILED,
  ErrorCode.ERR_CRYPTO_SIGNATURE_INVALID,
  ErrorCode.ERR_STREAM_TRUNCATED,
  ErrorCode.ERR_HASH_MISMATCH,
  ErrorCode.ERR_MSG_REPLAY_DETECTED,
]);

/** @param {unknown} err */
export function isRetryable(err) {
  return err instanceof SyncError && Boolean(err.retryable);
}

/** @param {unknown} err */
export function isQuotaExceeded(err) {
  return err instanceof SyncError && QUOTA_CODES.has(err.code);
}

/** @param {unknown} err */
export function suggestPipeMode(err) {
  if (!(err instanceof SyncError)) return false;
  if (err.code === ErrorCode.ERR_SPOOL_DISABLED || err.code === ErrorCode.ERR_OFFLINE_QUOTA_EXCEEDED) return true;
  return err.details?.suggest_mode === 'pipe';
}

/** @param {unknown} err */
export function isAuthError(err) {
  return err instanceof SyncError && AUTH_CODES.has(err.code);
}

/** @param {unknown} err */
export function isSecurityAlert(err) {
  return err instanceof SyncError && SECURITY_ALERT_CODES.has(err.code);
}

/** @param {unknown} err */
export function isVersionMismatch(err) {
  return err instanceof SyncError && err.code === ErrorCode.ERR_UNSUPPORTED_VERSION;
}
