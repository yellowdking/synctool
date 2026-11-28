export declare const DEFAULT_SEEN_RETENTION_SEC: number;
export declare const DEFAULT_SEEN_MIN_CAPACITY: number;

export interface RelayProfile {
  relay_id: string;
  alias?: string;
  origin: string;
  endpoint?: string;
  tls_mode: 'system_ca' | 'spki_pin';
  spki_pin?: string | null;
  spki_pins?: string[];
  spki_sha256?: string;
  is_default?: boolean;
  access_key: string;
}

export interface DeviceCard {
  device_id: string;
  label: string;
  platform?: string;
  sign_pk: string;
  kem_pk: string;
  issued_at: number;
  card_sig: string;
  relay_origin?: string | null;
  relay_id?: string | null;
  mailbox_id?: string | null;
  outbound_deposit_token?: string | null;
  inbound_token_id?: string | null;
  inbound_token_hash?: string | null;
  stale_inbound_token_ids?: string[];
  pending_token_delete?: boolean;
  paired_at: number;
  revoked: boolean;
}

export declare function normalizeStoredRelayProfile(raw: Partial<RelayProfile> | null | undefined): RelayProfile | null;

export interface KeyStore {
  loadOrCreateMasterSeed(): Promise<Uint8Array>;
  getRelayProfile(relayIdOrAlias: string): Promise<RelayProfile | null>;
  getDefaultRelayProfile?(): Promise<RelayProfile | null>;
  listRelayProfiles?(): Promise<RelayProfile[]>;
  saveRelayProfile(profile: RelayProfile): Promise<void>;
  listDevices(options?: { includeRevoked?: boolean }): Promise<DeviceCard[]>;
  getDevice(deviceId: string): Promise<DeviceCard | null>;
  putDevice(card: DeviceCard): Promise<void>;
  deleteDevice(deviceId: string): Promise<void>;
  hasSeenMsgID(msgId: string): Promise<boolean>;
  markSeenMsgID(msgId: string, createdAt: number, seenAt?: number): Promise<void>;
  getReplayWatermark?(): Promise<number>;
  getCachedManifestPreview?(itemId: string): Promise<unknown | null>;
  putCachedManifestPreview?(itemId: string, preview: unknown): Promise<void>;
  deleteCachedManifestPreview?(itemId: string): Promise<void>;
  pruneCachedManifestPreviews?(activeItemIds: Set<string>): Promise<void>;
}

export declare class MemoryKeyStore implements KeyStore {
  constructor(options?: {
    masterSeed?: Uint8Array;
    seenRetentionSec?: number;
    seenMinCapacity?: number;
  });
  loadOrCreateMasterSeed(): Promise<Uint8Array>;
  getRelayProfile(relayIdOrAlias: string): Promise<RelayProfile | null>;
  getDefaultRelayProfile(): Promise<RelayProfile | null>;
  listRelayProfiles(): Promise<RelayProfile[]>;
  saveRelayProfile(profile: RelayProfile): Promise<void>;
  listDevices(options?: { includeRevoked?: boolean }): Promise<DeviceCard[]>;
  getDevice(deviceId: string): Promise<DeviceCard | null>;
  putDevice(card: DeviceCard): Promise<void>;
  deleteDevice(deviceId: string): Promise<void>;
  hasSeenMsgID(msgId: string): Promise<boolean>;
  markSeenMsgID(msgId: string, createdAt: number, seenAt?: number): Promise<void>;
  getReplayWatermark(): Promise<number>;
  getCachedManifestPreview(itemId: string): Promise<unknown | null>;
  putCachedManifestPreview(itemId: string, preview: unknown): Promise<void>;
  deleteCachedManifestPreview(itemId: string): Promise<void>;
  pruneCachedManifestPreviews(activeItemIds: Set<string>): Promise<void>;
}

export declare class NodeFileKeyStore implements KeyStore {
  constructor(
    dirPath: string,
    options?: {
      seenRetentionSec?: number;
      seenMinCapacity?: number;
    },
  );
  loadOrCreateMasterSeed(): Promise<Uint8Array>;
  getRelayProfile(relayIdOrAlias: string): Promise<RelayProfile | null>;
  getDefaultRelayProfile(): Promise<RelayProfile | null>;
  listRelayProfiles(): Promise<RelayProfile[]>;
  saveRelayProfile(profile: RelayProfile): Promise<void>;
  listDevices(options?: { includeRevoked?: boolean }): Promise<DeviceCard[]>;
  getDevice(deviceId: string): Promise<DeviceCard | null>;
  putDevice(card: DeviceCard): Promise<void>;
  deleteDevice(deviceId: string): Promise<void>;
  hasSeenMsgID(msgId: string): Promise<boolean>;
  markSeenMsgID(msgId: string, createdAt: number, seenAt?: number): Promise<void>;
  getReplayWatermark(): Promise<number>;
  getCachedManifestPreview(itemId: string): Promise<unknown | null>;
  putCachedManifestPreview(itemId: string, preview: unknown): Promise<void>;
  deleteCachedManifestPreview(itemId: string): Promise<void>;
  pruneCachedManifestPreviews(activeItemIds: Set<string>): Promise<void>;
}
