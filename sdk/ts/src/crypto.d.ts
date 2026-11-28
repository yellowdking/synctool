export declare const PROTO_VERSION: 1;
export declare const CHUNK_PLAINTEXT_MAX: 65536;
export declare const AEAD_TAG_LEN: 16;
export declare const CHUNK_CIPHERTEXT_MAX: 65552;
export declare const MANIFEST_PAD_BUCKET: 4096;
export declare const CLEAR_HEADER_LEN: 56;
export declare const SEALED_BOX_LEN: 152;
export declare const SEALED_HEADER_LEN: 208;
export declare const DEFAULT_0RTT_MAX_AGE_SEC: number;
export declare const DEFAULT_0RTT_MAX_FUTURE_SKEW_SEC: number;

export declare const ED25519_PKCS8_PREFIX: Uint8Array;
export declare const X25519_PKCS8_PREFIX: Uint8Array;
export declare const ED25519_SPKI_PREFIX: Uint8Array;
export declare const X25519_SPKI_PREFIX: Uint8Array;

export interface CustomCryptoProvider {
  ed25519PublicKeyFromSeed?(seed32: Uint8Array): Promise<Uint8Array> | Uint8Array;
  ed25519Sign?(seed32: Uint8Array, message: Uint8Array): Promise<Uint8Array> | Uint8Array;
  ed25519Verify?(publicKey32: Uint8Array, message: Uint8Array, signature64: Uint8Array): Promise<boolean> | boolean;
  x25519PublicKeyFromSk?(sk32: Uint8Array): Promise<Uint8Array> | Uint8Array;
  x25519SharedSecret?(sk32: Uint8Array, peerPk32: Uint8Array): Promise<Uint8Array> | Uint8Array;
}

export declare function setCryptoProvider(provider: CustomCryptoProvider | null): void;

export declare function utf8Encode(s: string): Uint8Array;
export declare function utf8Decode(b: Uint8Array): string;
export declare function randomBytes(n: number): Uint8Array;
export declare function bytesToHex(bytes: Uint8Array): string;
export declare function hexToBytes(hex: string): Uint8Array;
export declare function bytesToB64u(bytes: Uint8Array): string;
export declare function b64uToBytes(str: string): Uint8Array;
export declare function concatBytes(...parts: Uint8Array[]): Uint8Array;
export declare function u32be(n: number): Uint8Array;
export declare function readU32be(buf: Uint8Array, offset?: number): number;
export declare function u64be(n: number | bigint): Uint8Array;
export declare function readU64be(buf: Uint8Array, offset?: number): number;
export declare function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean;
export declare function zeroBytes(buf: Uint8Array | null | undefined): void;
export declare function isAllZero(bytes: Uint8Array): boolean;
export declare function isSmallOrderEd25519PublicKey(pk32: Uint8Array): boolean;

export declare function sha256(data: Uint8Array): Promise<Uint8Array>;
export declare function hmacSha256(keyBytes: Uint8Array, data: Uint8Array): Promise<Uint8Array>;
export declare function hkdfExtract(salt: Uint8Array, ikm: Uint8Array): Promise<Uint8Array>;
export declare function hkdfExpand(prk: Uint8Array, info: Uint8Array, length: number): Promise<Uint8Array>;
export declare function hkdfDerive(salt: Uint8Array, ikm: Uint8Array, info: Uint8Array, length: number): Promise<Uint8Array>;
export declare function aesGcmSeal(key32: Uint8Array, nonce12: Uint8Array, plaintext: Uint8Array, aad: Uint8Array): Promise<Uint8Array>;
export declare function aesGcmOpen(key32: Uint8Array, nonce12: Uint8Array, ciphertextWithTag: Uint8Array, aad: Uint8Array): Promise<Uint8Array>;

export declare function ed25519SeedToPkcs8(seed32: Uint8Array): Uint8Array;
export declare function x25519SkToPkcs8(sk32: Uint8Array): Uint8Array;
export declare function ed25519PubToSpki(pk32: Uint8Array): Uint8Array;
export declare function x25519PubToSpki(pk32: Uint8Array): Uint8Array;

export declare function ed25519KeyPairFromSeed(seed32: Uint8Array): Promise<{ seed: Uint8Array; publicKey: Uint8Array }>;
export declare function x25519KeyPairFromSk(sk32: Uint8Array): Promise<{ privateKey: Uint8Array; publicKey: Uint8Array }>;
export declare function generateX25519KeyPair(): Promise<{ privateKey: Uint8Array; publicKey: Uint8Array }>;
export declare function x25519SharedSecret(sk32: Uint8Array, peerPk32: Uint8Array): Promise<Uint8Array>;
export declare function ed25519Sign(seed32: Uint8Array, message: Uint8Array): Promise<Uint8Array>;
export declare function ed25519Verify(publicKey32: Uint8Array, message: Uint8Array, signature64: Uint8Array): Promise<boolean>;

export declare function deriveMasterPRK(seed32: Uint8Array): Promise<Uint8Array>;
export declare function deriveRelayId(canonicalRelayOrigin: string): Promise<string>;
export declare function deriveDeviceIdRaw(signPk32: Uint8Array): Promise<Uint8Array>;
export declare function deriveDeviceId(signPk32: Uint8Array): Promise<string>;
export declare function deriveMailboxId(mailboxAuthPk32: Uint8Array): Promise<string>;

export interface DeviceIdentity {
  masterPrk: Uint8Array;
  signSeed: Uint8Array;
  signPk: Uint8Array;
  kemSk: Uint8Array;
  kemPk: Uint8Array;
  localMetaKey: Uint8Array;
  deviceIdRaw: Uint8Array;
  deviceId: string;
}

export declare function deriveDeviceIdentity(seed32: Uint8Array): Promise<DeviceIdentity>;
export declare function deriveMailboxIdentity(seed32: Uint8Array, relayId: string): Promise<{
  mailboxAuthSeed: Uint8Array;
  mailboxAuthPk: Uint8Array;
  mailboxId: string;
}>;
export declare function buildDeviceCardSigInput(signPk32: Uint8Array, kemPk32: Uint8Array, issuedAt: number): Uint8Array;
export declare function signDeviceCard(signSeed32: Uint8Array, signPk32: Uint8Array, kemPk32: Uint8Array, issuedAt: number): Promise<Uint8Array>;
export declare function verifyDeviceCard(card: {
  device_id: string;
  sign_pk: string;
  kem_pk: string;
  issued_at: number;
  card_sig: string;
}): Promise<boolean>;

export declare function purposeToCode(purpose: 'oneshot' | 'pair'): 1 | 2;
export declare function computeQrOobHandshake(params: {
  purpose: 'oneshot' | 'pair';
  roomId: string;
  shared: Uint8Array;
  oobSecret: Uint8Array;
  eA: Uint8Array;
  nA: Uint8Array;
  eB: Uint8Array;
  nB: Uint8Array;
}): Promise<{
  transcript: Uint8Array;
  th: Uint8Array;
  prk: Uint8Array;
  sessionKey: Uint8Array;
  confirmKeyA: Uint8Array;
  confirmKeyB: Uint8Array;
  macA: Uint8Array;
  macB: Uint8Array;
}>;
export declare function computeCommitA(params: {
  purpose: 'oneshot' | 'pair';
  roomId: string;
  eA: Uint8Array;
  nA: Uint8Array;
}): Promise<Uint8Array>;
export declare function computeCommitSasHandshake(params: {
  purpose: 'oneshot' | 'pair';
  roomId: string;
  shared: Uint8Array;
  commitA: Uint8Array;
  eA: Uint8Array;
  nA: Uint8Array;
  eB: Uint8Array;
  nB: Uint8Array;
}): Promise<{
  transcript: Uint8Array;
  th: Uint8Array;
  prk: Uint8Array;
  sessionKey: Uint8Array;
  sasBytes: Uint8Array;
  sasInt: number;
  sasStr: string;
  confirmKeyA: Uint8Array;
  confirmKeyB: Uint8Array;
  macA: Uint8Array;
  macB: Uint8Array;
}>;

export declare function deriveOneshotPart0Keys(sessionKey32: Uint8Array, msgId16: Uint8Array): Promise<{
  oneshotPrk: Uint8Array;
  part0Key: Uint8Array;
  part0NoncePrefix: Uint8Array;
}>;
export declare function derivePipeCtrlKeys(sessionKey32: Uint8Array, th32: Uint8Array): Promise<{
  ctrlPrk: Uint8Array;
  ctrlKey: Uint8Array;
  ctrlNoncePrefix: Uint8Array;
}>;
export declare function sealPipeCtrlFrame(
  ctrlKey32: Uint8Array,
  ctrlNp7: Uint8Array,
  th32: Uint8Array,
  ctrlSeq: number,
  payloadObj: unknown,
): Promise<{ ctrl_seq: number; ct: string }>;
export declare function openPipeCtrlFrame(
  ctrlKey32: Uint8Array,
  ctrlNp7: Uint8Array,
  th32: Uint8Array,
  frame: { ctrl_seq: number; ct: string },
  rules?: { expectedParity?: 0 | 1; lastSeenSeq?: number },
): Promise<{ ctrl_seq: number; payload: any }>;

export declare function sealPairBindPayload(
  sessionKey32: Uint8Array,
  prk32: Uint8Array,
  th32: Uint8Array,
  side: 'a' | 'b',
  payloadObj: unknown,
): Promise<Uint8Array>;
export declare function openPairBindPayload(
  sessionKey32: Uint8Array,
  prk32: Uint8Array,
  th32: Uint8Array,
  side: 'a' | 'b',
  ciphertext: Uint8Array,
): Promise<any>;

export declare function sealPaired0RTTHeader(params: {
  msgId: Uint8Array;
  ephemeralSk?: Uint8Array;
  senderSignSeed: Uint8Array;
  senderDeviceIdRaw: Uint8Array;
  recipientDeviceIdRaw: Uint8Array;
  recipientKemPk: Uint8Array;
  createdAt: number;
  manifestSha256: Uint8Array;
}): Promise<{
  clearHeader: Uint8Array;
  sealedBox: Uint8Array;
  sealedHeader: Uint8Array;
  sealedHeaderB64u: string;
  sigInput: Uint8Array;
  senderSig: Uint8Array;
  hdrPrk: Uint8Array;
  hdrKey: Uint8Array;
  hdrNonce: Uint8Array;
  part0Key: Uint8Array;
  part0NoncePrefix: Uint8Array;
}>;

export declare function openPaired0RTTHeader(params: {
  sealedHeader: Uint8Array | string;
  recipientKemSk: Uint8Array;
  recipientDeviceIdRaw: Uint8Array;
  nowSec?: number | null;
  maxAgeSec?: number;
  maxFutureSkewSec?: number;
  replayWatermarkSec?: number;
  hasSeenMsgId?: (msgIdHex: string) => Promise<boolean> | boolean;
  lookupSenderCard: (senderDeviceIdHex: string) => Promise<any> | any;
}): Promise<{
  msgIdRaw: Uint8Array;
  msgId: string;
  ephemeralPk: Uint8Array;
  senderDeviceIdRaw: Uint8Array;
  senderDeviceId: string;
  recipientDeviceIdRaw: Uint8Array;
  recipientDeviceId: string;
  createdAt: number;
  manifestSha256: Uint8Array;
  senderSig: Uint8Array;
  senderCard: any;
  part0Key: Uint8Array;
  part0NoncePrefix: Uint8Array;
}>;

export declare function computeDirectAckMac(part0Key32: Uint8Array, msgId16: Uint8Array): Promise<Uint8Array>;
export declare function verifyDirectAckMac(part0Key32: Uint8Array, msgId16: Uint8Array, mac32: Uint8Array): Promise<boolean>;

export declare function deriveBlobPartKeys(blobKey32: Uint8Array, msgId16: Uint8Array, partId: number): Promise<{
  partPrk: Uint8Array;
  encKey: Uint8Array;
  noncePrefix: Uint8Array;
}>;
export declare function buildChunkNonce(noncePrefix7: Uint8Array, blockIdx: number, isFinal: boolean): Uint8Array;
export declare function buildChunkAAD(msgId16: Uint8Array, partId: number, blockIdx: number, isFinal: boolean, plaintextLen: number): Uint8Array;
export declare function sealStreamBlock(
  encKey32: Uint8Array,
  noncePrefix7: Uint8Array,
  msgId16: Uint8Array,
  partId: number,
  blockIdx: number,
  isFinal: boolean,
  plaintextBlock: Uint8Array,
): Promise<Uint8Array>;
export declare function openStreamBlock(
  encKey32: Uint8Array,
  noncePrefix7: Uint8Array,
  msgId16: Uint8Array,
  partId: number,
  blockIdx: number,
  isFinal: boolean,
  ciphertextBlock: Uint8Array,
): Promise<Uint8Array>;
export declare function calcBlockCount(plaintextLen: number): number;
export declare function calcEncryptedPartSize(plaintextLen: number): number;
export declare function calcTransportChunkCount(plaintextLen: number, blocksPerChunk: number): number;
export declare function encryptPartBytes(
  encKey32: Uint8Array,
  noncePrefix7: Uint8Array,
  msgId16: Uint8Array,
  partId: number,
  plaintext: Uint8Array,
  blocksPerChunk?: number,
): Promise<{ blocks: Uint8Array[]; transportChunks: Uint8Array[]; totalCipherBytes: number }>;
export declare function decryptPartBytes(
  encKey32: Uint8Array,
  noncePrefix7: Uint8Array,
  msgId16: Uint8Array,
  partId: number,
  ciphertextOrChunks: Uint8Array | Uint8Array[],
  options?: { expectedTotalBlocks?: number },
): Promise<Uint8Array>;
export declare function padManifest(manifestUtf8Bytes: Uint8Array): Uint8Array;
export declare function unpadManifest(paddedBytes: Uint8Array): Uint8Array;

export declare function deriveRelayHmacKey(accessKeyString: string): Promise<Uint8Array>;
export declare function hashDepositToken(depositToken: string): Promise<string>;
export declare function hashUploadToken(uploadToken: string): Promise<string>;
export declare function computeBodyBinding(opts?: {
  bodyBytes?: Uint8Array | null;
  streamContentLength?: number | null;
}): Promise<string>;
export declare function buildCanonicalRelayRequest(params: {
  method: string;
  pathAndRawQuery: string;
  ts: number | string;
  nonce: string;
  bodyBinding: string;
  extraTokenBinding?: string;
}): string;
export declare function signRelayRequest(params: {
  accessKey: string;
  method: string;
  pathAndRawQuery: string;
  ts: number | string;
  nonce: string;
  bodyBytes?: Uint8Array | null;
  streamContentLength?: number | null;
  depositToken?: string | null;
  uploadToken?: string | null;
}): Promise<{ canonical: string; bodyBinding: string; extraTokenBinding: string; sigHex: string }>;
export declare function buildMailboxSigInput(params: {
  method: string;
  pathAndRawQuery: string;
  mailboxId: string;
  ts: number | string;
  nonce: string;
  bodyBinding: string;
}): string;
export declare function signMailboxRequest(params: {
  mailboxAuthSeed: Uint8Array;
  method: string;
  pathAndRawQuery: string;
  mailboxId: string;
  ts: number | string;
  nonce: string;
  bodyBytes?: Uint8Array | null;
  streamContentLength?: number | null;
}): Promise<{ input: string; bodyBinding: string; sigB64u: string }>;
export declare function verifyMailboxRequest(params: {
  mailboxAuthPk: Uint8Array;
  method: string;
  pathAndRawQuery: string;
  mailboxId: string;
  ts: number | string;
  nonce: string;
  bodyBytes?: Uint8Array | null;
  streamContentLength?: number | null;
  sigB64u: string;
}): Promise<boolean>;
