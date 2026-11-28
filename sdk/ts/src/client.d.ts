import type { BlobDescriptor, Manifest, RelayCertExpiringEvent, TransferEvent } from './envelope.js';
import type { DeviceCard, KeyStore } from './keystore.js';

export declare const DEFAULT_MAX_IN_MEMORY_BLOB_BYTES: number;
export declare const MAX_CLOCK_SKEW_OFFSET_SEC: number;

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

export interface NodeFileBlobSinkResult {
  path: string;
  safeName: string;
  bytesWritten: number;
}

export interface ReceivedBlob<T = unknown> {
  descriptor: BlobDescriptor;
  safeName: string;
  bytes?: Uint8Array;
  sinkResult?: T;
}

export interface ParcelInput {
  appId?: string;
  schema: string;
  senderLabel?: string;
  senderPlatform?: string;
  inlinePayload?: Record<string, unknown> | null;
  blobs?: Array<BlobInput | Promise<BlobInput>>;
}

export interface RelayConfig {
  origin: string;
  tlsMode?: 'system_ca' | 'spki_pin';
  spkiPin?: string | null;
  spkiPins?: string[] | null;
  accessKey: string;
}

export interface RelayCapabilities {
  proto_v: number;
  min_proto_v?: number;
  max_proto_v?: number;
  server_version?: string;
  features?: string[];
  profile: string;
  server_ts: number;
  cert_expires_at: number;
  cert_rotate_recommended: boolean;
  crypto_plaintext_block_bytes: number;
  crypto_block_bytes: number;
  streaming: {
    enabled: boolean;
    blocks_per_chunk: number;
    max_transport_chunk_bytes: number;
    rendezvous_timeout_sec: number;
    room_ttl_max_sec: number;
  };
  spool: {
    enabled: boolean;
    backend: string;
    max_item_bytes: number;
    max_mailbox_bytes: number;
    max_total_bytes: number;
    max_items_per_mailbox: number;
    default_ttl_sec: number;
    max_ttl_sec: number;
    uncommitted_ttl_sec: number;
    max_manifest_downloads: number;
    max_downloads_per_chunk: number;
    max_deposit_tokens_per_mailbox: number;
  };
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
  maxInMemoryBlobBytes?: number;
}

export interface RoomOffer {
  roomId: string;
  formattedRoomId: string;
  pairUri: string;
  mode: 0 | 1 | 2;
  purpose: 'direct' | 'oneshot' | 'pair';
  expiresAt: number;
}

export interface SASDisplayInfo {
  sas: string;
  formatted: string;
  formattedSas: string;
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

export type ResumePrefixReader = (offset: number, length: number) => Promise<Uint8Array> | Uint8Array;

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

export declare function blobFromNodeFile(
  filePath: string,
  opts?: {
    role?: string;
    name?: string;
    mime?: string;
    sha256?: string;
    encoding?: 'identity' | 'gzip' | 'zstd';
    meta?: Record<string, unknown>;
  },
): Promise<BlobInput>;

export declare function createNodeFileBlobSink(
  dirPath: string,
): (desc: BlobDescriptor) => Promise<BlobSink<NodeFileBlobSinkResult>>;

export declare function resolveDeviceCard(keyStore: KeyStore, query: string): Promise<DeviceCard>;

export declare class SyncClient {
  static fromEnv(overrides?: Partial<SyncClientConfig>): SyncClient;
  readonly relay: {
    version: 1;
    origin: string;
    tlsMode: 'system_ca' | 'spki_pin';
    spkiPin: string | null;
    spkiPins: string[];
    accessKey: string;
  };
  readonly keyStore: KeyStore;
  readonly appId: string;
  readonly label: string;
  readonly platform: string;

  constructor(config: SyncClientConfig);

  getRelayId(): Promise<string>;
  getIdentity(): Promise<import('./crypto.js').DeviceIdentity>;
  getMailboxIdentity(): Promise<{ mailboxAuthSeed: Uint8Array; mailboxAuthPk: Uint8Array; mailboxId: string }>;
  close(): Promise<void>;

  ping(opts?: { signal?: AbortSignal }): Promise<{
    proto_v: number;
    min_proto_v?: number;
    max_proto_v?: number;
    server_version?: string;
    server_ts: number;
    profile: string;
    spool_backend: string;
    cert_expires_at: number;
    cert_rotate_recommended: boolean;
    rtt_ms: number;
    clock_offset_sec: number;
  }>;

  capabilities(opts?: { refresh?: boolean; signal?: AbortSignal }): Promise<RelayCapabilities>;
  registerMailbox(opts?: { strict?: boolean; signal?: AbortSignal }): Promise<{
    mailbox_id: string;
    registered: boolean;
    deposit_token_count: number;
  }>;
  syncMailbox(opts?: { strict?: boolean; signal?: AbortSignal }): Promise<{
    mailbox_id: string;
    registered: boolean;
    deposit_token_count: number;
  }>;

  startDeviceBind(opts?: {
    mode?: 1 | 2;
    label?: string;
    platform?: string;
    includeRelay?: boolean;
    ttlSec?: number;
    onOfferReady?: (offer: RoomOffer) => Promise<void> | void;
    onSASInput?: (info: { attempt: number; maxAttempts: number }) => Promise<string | null> | string | null;
    timeoutMs?: number;
    preferPoll?: boolean;
    signal?: AbortSignal;
  }): Promise<DeviceCard>;

  initiateDeviceBind(opts?: {
    mode?: 1 | 2;
    label?: string;
    platform?: string;
    includeRelay?: boolean;
    ttlSec?: number;
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
      onSASDisplay?: (info: SASDisplayInfo) => Promise<void> | void;
      onSASConfirm?: (info: SASDisplayInfo) => Promise<boolean> | boolean;
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
      ttlSec?: number;
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
      onSASDisplay?: (info: SASDisplayInfo) => Promise<void> | void;
      onSASConfirm?: (info: SASDisplayInfo) => Promise<boolean> | boolean;
      createBlobSink?: (desc: BlobDescriptor) => Promise<BlobSink<T>> | BlobSink<T>;
      maxInMemoryBlobBytes?: number;
      onProgress?: (ev: TransferEvent) => void;
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
  ): Promise<{
    mode: 'spool' | 'pipe';
    itemId?: string;
    roomId?: string;
    msgId: string;
    totalBytes: number;
    expiresAt?: number;
  }>;

  sendText(
    targetDeviceOrLabel: string,
    text: string,
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
  ): Promise<{
    mode: 'spool' | 'pipe';
    itemId?: string;
    roomId?: string;
    msgId: string;
    totalBytes: number;
    expiresAt?: number;
  }>;

  receiveDirect<T = unknown>(
    pairInput: string,
    handler: (received: { manifest: Manifest; senderCard: DeviceCard; blobs: ReceivedBlob<T>[] }) => Promise<void> | void,
    opts?: {
      createBlobSink?: (desc: BlobDescriptor) => Promise<BlobSink<T>> | BlobSink<T>;
      maxInMemoryBlobBytes?: number;
      onProgress?: (ev: TransferEvent) => void;
      timeoutMs?: number;
      preferPoll?: boolean;
      signal?: AbortSignal;
    },
  ): Promise<Manifest>;

  receiveFromRoom<T = unknown>(
    pairInput: string,
    handler: (received: { manifest: Manifest; senderCard?: DeviceCard; blobs: ReceivedBlob<T>[] }) => Promise<void> | void,
    opts?: {
      onSASDisplay?: (info: SASDisplayInfo) => Promise<void> | void;
      onSASConfirm?: (info: SASDisplayInfo) => Promise<boolean> | boolean;
      createBlobSink?: (desc: BlobDescriptor) => Promise<BlobSink<T>> | BlobSink<T>;
      maxInMemoryBlobBytes?: number;
      onProgress?: (ev: TransferEvent) => void;
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
      appId?: string;
      itemMeta?: any;
      blocksPerChunk?: number;
      createBlobSink?: (desc: BlobDescriptor) => Promise<BlobSink<T>> | BlobSink<T>;
      maxInMemoryBlobBytes?: number;
      resumeCheckpoints?: Map<number, number>;
      resumePrefixes?: Map<number, Uint8Array>;
      resumePrefixReaders?: Map<number, ResumePrefixReader>;
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
