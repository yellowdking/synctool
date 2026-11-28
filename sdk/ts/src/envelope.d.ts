export declare const ENVELOPE_VERSION: 1;
export declare const MAX_MANIFEST_BYTES: 131072;
export declare const MAX_ENCRYPTED_MANIFEST_BYTES: 135216;
export declare const MAX_MANIFEST_CHUNKS: 4;
export declare const MAX_INLINE_PAYLOAD_BYTES: 65536;
export declare const MAX_BLOBS: 63;
export declare const MAX_BLOB_META_BYTES: 2048;
export declare const MAX_SPKI_PINS: 8;

export declare const ErrorCode: Readonly<{
  ERR_BAD_REQUEST: 'ERR_BAD_REQUEST';
  ERR_REPLAY_DETECTED: 'ERR_REPLAY_DETECTED';
  ERR_UNAUTHORIZED_TOKEN: 'ERR_UNAUTHORIZED_TOKEN';
  ERR_SPOOL_DISABLED: 'ERR_SPOOL_DISABLED';
  ERR_DOWNLOAD_LIMIT_EXCEEDED: 'ERR_DOWNLOAD_LIMIT_EXCEEDED';
  ERR_NOT_FOUND: 'ERR_NOT_FOUND';
  ERR_CLOCK_SKEW: 'ERR_CLOCK_SKEW';
  ERR_ROOM_BUSY: 'ERR_ROOM_BUSY';
  ERR_INVALID_STATE: 'ERR_INVALID_STATE';
  ERR_CONFLICT: 'ERR_CONFLICT';
  ERR_ROOM_BURNED: 'ERR_ROOM_BURNED';
  ERR_CHUNK_TOO_LARGE: 'ERR_CHUNK_TOO_LARGE';
  ERR_OFFLINE_QUOTA_EXCEEDED: 'ERR_OFFLINE_QUOTA_EXCEEDED';
  ERR_RATE_LIMITED: 'ERR_RATE_LIMITED';
  ERR_PIPE_PEER_TIMEOUT: 'ERR_PIPE_PEER_TIMEOUT';
  ERR_RELAY_UNREACHABLE: 'ERR_RELAY_UNREACHABLE';
  ERR_TLS_PIN_MISMATCH: 'ERR_TLS_PIN_MISMATCH';
  ERR_TLS_CERT_INVALID: 'ERR_TLS_CERT_INVALID';
  ERR_AUTH_FAILED: 'ERR_AUTH_FAILED';
  ERR_HANDSHAKE_TIMEOUT: 'ERR_HANDSHAKE_TIMEOUT';
  ERR_SAS_MISMATCH: 'ERR_SAS_MISMATCH';
  ERR_CRYPTO_HANDSHAKE_FAILED: 'ERR_CRYPTO_HANDSHAKE_FAILED';
  ERR_CRYPTO_DECRYPT_FAILED: 'ERR_CRYPTO_DECRYPT_FAILED';
  ERR_CRYPTO_SIGNATURE_INVALID: 'ERR_CRYPTO_SIGNATURE_INVALID';
  ERR_STREAM_TRUNCATED: 'ERR_STREAM_TRUNCATED';
  ERR_MSG_REPLAY_DETECTED: 'ERR_MSG_REPLAY_DETECTED';
  ERR_HASH_MISMATCH: 'ERR_HASH_MISMATCH';
  ERR_MANIFEST_INVALID: 'ERR_MANIFEST_INVALID';
  ERR_UNSUPPORTED_VERSION: 'ERR_UNSUPPORTED_VERSION';
  ERR_DEVICE_UNTRUSTED: 'ERR_DEVICE_UNTRUSTED';
  ERR_INTERRUPTED_RESUMABLE: 'ERR_INTERRUPTED_RESUMABLE';
  ERR_URI_INVALID: 'ERR_URI_INVALID';
  ERR_KEYSTORE_ERROR: 'ERR_KEYSTORE_ERROR';
  ERR_STORAGE_IO: 'ERR_STORAGE_IO';
  ERR_CANCELLED: 'ERR_CANCELLED';
}>;

export type SyncErrorCode = (typeof ErrorCode)[keyof typeof ErrorCode];

export interface SyncErrorJSON {
  code: SyncErrorCode | string;
  retryable: boolean;
  http_status: number;
  message: string;
  details: Record<string, unknown>;
}

export declare class SyncError extends Error {
  readonly code: SyncErrorCode | string;
  readonly retryable: boolean;
  readonly httpStatus: number;
  readonly details: Record<string, unknown>;
  constructor(
    code: SyncErrorCode | string,
    message: string,
    options?: {
      retryable?: boolean;
      httpStatus?: number;
      details?: Record<string, unknown>;
      cause?: unknown;
    },
  );
  toJSON(): SyncErrorJSON;
}

export interface ManifestSender {
  device_id: string;
  label: string;
  platform?: string;
}

export interface BlobDescriptor {
  part_id: number;
  role: string;
  name: string;
  mime: string;
  size: number;
  sha256: string;
  key: string;
  encoding?: 'identity' | 'gzip' | 'zstd';
  meta?: Record<string, unknown>;
}

export interface Manifest {
  envelope_version: 1;
  msg_id: string;
  app_id: string;
  schema: string;
  created_at: number;
  sender: ManifestSender;
  inline_payload?: Record<string, unknown> | null;
  blobs: BlobDescriptor[];
}

export interface ParsedRelayURI {
  version: 1;
  origin: string;
  tlsMode: 'system_ca' | 'spki_pin';
  spkiPin: string | null;
  spkiPins: string[];
  accessKey: string;
}

export interface ParsedPairURI {
  version: 1;
  roomId: string;
  mode: 0 | 1 | 2;
  purpose: 'direct' | 'oneshot' | 'pair';
  oobSecret: string | null;
  relayOrigin: string | null;
  spkiPin: string | null;
  spkiPins: string[];
  accessKey: string | null;
  expiresAt: number | null;
}

export interface TransferEvent {
  type: 'event';
  event: 'transfer_progress';
  stage:
    | 'connecting'
    | 'handshaking'
    | 'awaiting_sas'
    | 'manifest_ready'
    | 'transferring'
    | 'verifying'
    | 'acking'
    | 'completed'
    | 'failed';
  direction: 'send' | 'recv';
  mode: 'pipe' | 'spool';
  msg_id: string;
  part_id: number;
  parts_total: number;
  bytes_done: number;
  bytes_total: number;
  part_bytes_done: number;
  part_bytes_total: number;
  speed_bps: number;
  resumed: boolean;
  ts: number;
}

export interface RelayCertExpiringEvent {
  type: 'event';
  event: 'relay_cert_expiring_soon';
  relay_id: string;
  expires_at: number;
  days_remaining: number;
  severity: 'warning' | 'urgent';
}

export declare function validateManifest(
  manifest: unknown,
  options?: { expectedMsgId?: string },
): Uint8Array;
export declare function sanitizeFileName(name: string, fallback?: string): string;
export declare function isBareIP(host: string): boolean;
export declare function isLoopbackHost(host: string): boolean;
export declare function canonicalizeRelayOrigin(rawUrl: string): {
  origin: string;
  scheme: string;
  hostname: string;
  port: number;
};
export declare function normalizeSpkiPins(input: string | string[] | null | undefined, label?: string): string[];
export declare function resolveConfigSpkiPins(
  obj: { spkiPins?: string[] | null; spkiPin?: string | null },
  label?: string,
): string[];
export declare function parseRelayURI(uri: string): ParsedRelayURI;
export declare function formatRelayURI(profile: {
  origin?: string;
  endpoint?: string;
  spkiPin?: string | null;
  spkiPins?: string[] | null;
  accessKey: string;
}): string;
export declare function parsePairURI(uri: string): ParsedPairURI;
export declare function formatPairURI(opts: {
  roomId: string;
  mode: 0 | 1 | 2;
  purpose: 'direct' | 'oneshot' | 'pair';
  oobSecret?: string | null;
  relayOrigin?: string | null;
  spkiPin?: string | null;
  spkiPins?: string[] | null;
  accessKey?: string | null;
  expiresAt?: number | null;
}): string;
export declare function redactURI(uri: string): string;
export declare function redactMessage(msg: string): string;
export declare function relayProfileFromEnv(): ParsedRelayURI;
export declare function parcelText(text: string, appId?: string): {
  appId?: string;
  schema: string;
  inlinePayload: { text: string };
  blobs: never[];
};
export declare function isRetryable(err: unknown): boolean;
export declare function isQuotaExceeded(err: unknown): boolean;
export declare function suggestPipeMode(err: unknown): boolean;
export declare function isAuthError(err: unknown): boolean;
export declare function isSecurityAlert(err: unknown): boolean;
export declare function isVersionMismatch(err: unknown): boolean;
