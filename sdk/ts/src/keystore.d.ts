export declare const DEFAULT_SEEN_RETENTION_SEC: number;
export declare const DEFAULT_SEEN_MIN_CAPACITY: number;

export interface RelayProfile {
  relay_id: string;
  origin: string;
  tls_mode: 'system_ca' | 'spki_pin';
  spki_pin?: string | null;
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
  paired_at: number;
  revoked: boolean;
}

export interface KeyStore {
  loadOrCreateMasterSeed(): Promise<Uint8Array>;
  getRelayProfile(relayId: string): Promise<RelayProfile | null>;
  saveRelayProfile(profile: RelayProfile): Promise<void>;
  listDevices(): Promise<DeviceCard[]>;
  getDevice(deviceId: string): Promise<DeviceCard | null>;
  putDevice(card: DeviceCard): Promise<void>;
  deleteDevice(deviceId: string): Promise<void>;
  hasSeenMsgID(msgId: string): Promise<boolean>;
  markSeenMsgID(msgId: string, createdAt: number, seenAt?: number): Promise<void>;
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
  getRelayProfile(relayId: string): Promise<RelayProfile | null>;
  saveRelayProfile(profile: RelayProfile): Promise<void>;
  listDevices(): Promise<DeviceCard[]>;
  getDevice(deviceId: string): Promise<DeviceCard | null>;
  putDevice(card: DeviceCard): Promise<void>;
  deleteDevice(deviceId: string): Promise<void>;
  hasSeenMsgID(msgId: string): Promise<boolean>;
  markSeenMsgID(msgId: string, createdAt: number, seenAt?: number): Promise<void>;
  getCachedManifestPreview(itemId: string): Promise<unknown | null>;
  putCachedManifestPreview(itemId: string, preview: unknown): Promise<void>;
  deleteCachedManifestPreview(itemId: string): Promise<void>;
  pruneCachedManifestPreviews(activeItemIds: Set<string>): Promise<void>;
}
