import type { BlobDescriptor, Manifest, RelayCertExpiringEvent, TransferEvent } from './envelope.js';
import type { DeviceCard, KeyStore } from './keystore.js';

export declare class StreamingSha256 {
  update(chunk: Uint8Array): this;
  digest(): Uint8Array;
  digestHex(): string;
}

export interface BlobInput {
  role: string;
  name: string;
  mime?: string;
  size: number;
  sha256?: string;
  encoding?: 'identity' | 'gzip' | 'zstd';
  meta?: Record<string, unknown>;
  readSlice(offset: number, length: number): Promise<Uint8Array> | Uint8Array;
}

export interface BlobSink<T = unknown> {
  write(chunk: Uint8Array): Promise<void> | void;
  finish(): Promise<T> | T;
  abort?(err: unknown): Promise<void> | void;
}

export interface ReceivedBlob<T = unknown> {
  descriptor: BlobDescriptor;
  bytes?: Uint8Array;
  sinkResult?: T;
}

export interface ParcelInput {
  appId?: string;
  schema: string;
  senderLabel?: string;
  senderPlatform?: string;
  inlinePayload?: Record<string, unknown> | null;
  blobs?: BlobInput[];
}

export interface RelayConfig {
  origin: string;
  tlsMode?: 'system_ca' | 'spki_pin';
  spkiPin?: string | null;
  accessKey: string;
}

export interface SyncClientConfig {
  relay: string | RelayConfig;
  keyStore?: KeyStore;
  appId?: string;
  label?: string;
  platform?: string;
  fetchImpl?: typeof fetch;
  onCertExpiring?: (event: RelayCertExpiringEvent) => void;
  clockOffsetSec?: number;
}

export interface RoomOffer {
  roomId: string;
  formattedRoomId: string;
  pairUri: string;
  mode: 0 | 1 | 2;
  purpose: 'direct' | 'oneshot' | 'pair';
  expiresAt: number;
}

export interface InboxPreview {
  item_id: string;
  created_at: number;
  expires_at: number;
  total_bytes: number;
  parts: Array<{ part_id: number; total_bytes: number; chunk_count: number }>;
  sealed_header: string;
  manifest: Manifest;
  sender_device_id: string;
  sender_label: string;
}

export declare function blobFromWebBlob(
  webBlob: Blob,
  opts: {
    role: string;
    name?: string;
    mime?: string;
    sha256?: string;
    encoding?: 'identity' | 'gzip' | 'zstd';
    meta?: Record<string, unknown>;
  },
): BlobInput;

export declare function blobFromSliceReader(opts: BlobInput): BlobInput;

export declare function blobFromBytes(
  bytes: Uint8Array,
  opts: {
    role: string;
    name: string;
    mime?: string;
    sha256?: string;
    encoding?: 'identity' | 'gzip' | 'zstd';
    meta?: Record<string, unknown>;
  },
): BlobInput;

export declare class SyncClient {
  readonly relay: { origin: string; tlsMode: 'system_ca' | 'spki_pin'; spkiPin: string | null; accessKey: string };
  readonly keyStore: KeyStore;
  readonly appId: string;
  readonly label: string;
  readonly platform: string;

  constructor(config: SyncClientConfig);

  getRelayId(): Promise<string>;
  getIdentity(): Promise<import('./crypto.js').DeviceIdentity>;
  getMailboxIdentity(): Promise<{ mailboxAuthSeed: Uint8Array; mailboxAuthPk: Uint8Array; mailboxId: string }>;

  ping(opts?: { signal?: AbortSignal }): Promise<{
    proto_v: number;
    server_ts: number;
    profile: string;
    spool_backend: string;
    cert_expires_at: number;
    cert_rotate_recommended: boolean;
    rtt_ms: number;
    clock_offset_sec: number;
  }>;

  capabilities(opts?: { refresh?: boolean; signal?: AbortSignal }): Promise<any>;
  registerMailbox(opts?: { signal?: AbortSignal }): Promise<{ mailbox_id: string; registered: boolean; deposit_token_count: number }>;

  startDeviceBind(opts?: {
    mode?: 1 | 2;
    label?: string;
    platform?: string;
    includeRelay?: boolean;
    onOfferReady?: (offer: RoomOffer) => Promise<void> | void;
    onSASInput?: (info: { attempt: number; maxAttempts: number }) => Promise<string | null> | string | null;
    timeoutMs?: number;
    preferPoll?: boolean;
    signal?: AbortSignal;
  }): Promise<DeviceCard>;

  acceptDeviceBind(
    pairInput: string,
    opts?: {
      label?: string;
      platform?: string;
      onSASDisplay?: (info: { sas: string; formatted: string }) => Promise<void> | void;
      timeoutMs?: number;
      preferPoll?: boolean;
      signal?: AbortSignal;
    },
  ): Promise<DeviceCard>;

  startOneShotSend(
    parcel: ParcelInput,
    opts?: {
      mode?: 1 | 2;
      includeRelay?: boolean;
      onOfferReady?: (offer: RoomOffer) => Promise<void> | void;
      onSASInput?: (info: { attempt: number; maxAttempts: number }) => Promise<string | null> | string | null;
      onProgress?: (ev: TransferEvent) => void;
      timeoutMs?: number;
      preferPoll?: boolean;
      signal?: AbortSignal;
    },
  ): Promise<{ mode: 'pipe'; msgId: string; totalBytes: number }>;

  receiveOneShot<T = unknown>(
    pairInput: string,
    handler: (received: { manifest: Manifest; blobs: ReceivedBlob<T>[] }) => Promise<void> | void,
    opts?: {
      onSASDisplay?: (info: { sas: string; formatted: string }) => Promise<void> | void;
      createBlobSink?: (desc: BlobDescriptor) => Promise<BlobSink<T>> | BlobSink<T>;
      timeoutMs?: number;
      preferPoll?: boolean;
      signal?: AbortSignal;
    },
  ): Promise<Manifest>;

  sendToDevice(
    targetDeviceId: string,
    parcel: ParcelInput,
    opts?: {
      deliveryMode?: 'auto' | 'spool' | 'pipe';
      ttlSec?: number;
      includeRelay?: boolean;
      onOfferReady?: (offer: RoomOffer) => Promise<void> | void;
      onProgress?: (ev: TransferEvent) => void;
      timeoutMs?: number;
      preferPoll?: boolean;
      signal?: AbortSignal;
    },
  ): Promise<{ mode: 'spool' | 'pipe'; itemId?: string; roomId?: string; msgId: string; totalBytes: number; expiresAt?: number }>;

  receiveDirect<T = unknown>(
    pairInput: string,
    handler: (received: { manifest: Manifest; senderCard: DeviceCard; blobs: ReceivedBlob<T>[] }) => Promise<void> | void,
    opts?: {
      createBlobSink?: (desc: BlobDescriptor) => Promise<BlobSink<T>> | BlobSink<T>;
      timeoutMs?: number;
      preferPoll?: boolean;
      signal?: AbortSignal;
    },
  ): Promise<Manifest>;

  listInbox(opts?: { appId?: string; strict?: boolean; signal?: AbortSignal }): Promise<InboxPreview[]>;

  fetchParcel<T = unknown>(
    itemId: string,
    handler: (received: { itemId: string; manifest: Manifest; senderCard: DeviceCard; blobs: ReceivedBlob<T>[] }) => Promise<void> | void,
    opts?: {
      itemMeta?: any;
      createBlobSink?: (desc: BlobDescriptor) => Promise<BlobSink<T>> | BlobSink<T>;
      resumeCheckpoints?: Map<number, number>;
      onChunkCheckpoint?: (partId: number, nextTxIdx: number) => void;
      onProgress?: (ev: TransferEvent) => void;
      signal?: AbortSignal;
    },
  ): Promise<Manifest>;

  watchInbox(opts: {
    onItem: (item: { item_id: string; total_bytes: number; created_at: number; expires_at: number }) => Promise<void> | void;
    preferPoll?: boolean;
    sinceTs?: number;
    signal?: AbortSignal;
  }): Promise<void>;

  revokeDevice(deviceId: string, opts?: { signal?: AbortSignal }): Promise<void>;
}
