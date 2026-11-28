// Internal Flow 2 Mode B Encrypted Spool delivery, localMetaKey-sealed two-phase inbox preview/fetch,
// 60s-idle-guarded SSE watch with backoff/FIFO dedup, & 2-phase revocation.
// Part of synctool v1 zero-dependency cross-platform client.

import {
  CHUNK_CIPHERTEXT_MAX,
  aesGcmOpen,
  aesGcmSeal,
  b64uToBytes,
  bytesToB64u,
  bytesToHex,
  concatBytes,
  constantTimeEqual,
  decryptPartBytes,
  deriveBlobPartKeys,
  hexToBytes,
  openPaired0RTTHeader,
  randomBytes,
  sealPaired0RTTHeader,
  sha256,
  unpadManifest,
  utf8Decode,
  utf8Encode,
  zeroBytes,
} from './crypto.js';
import {
  ErrorCode,
  MAX_ENCRYPTED_MANIFEST_BYTES,
  SyncError,
  isAuthError,
  isSecurityAlert,
  isVersionMismatch,
  validateManifest,
} from './envelope.js';
import {
  BoundedIdSet,
  DEFAULT_SSE_IDLE_TIMEOUT_MS,
  computeRetryBackoffMs,
  iterateSSE,
  sleepWithSignal,
} from './client_transport.js';
import {
  assertValidBlobPartLayout,
  assertValidBlocksPerChunk,
  assertValidPart0Layout,
  calcSpeedBps,
  downloadBlobStreaming,
  prepareParcel,
  sendDirectModeAImpl,
  uploadPartStreaming,
} from './client_pipe.js';

const ALLOWED_DELIVERY_MODES = new Set(['auto', 'spool', 'pipe']);

// ============================================================================
// localMetaKey AES-256-GCM Manifest Cache Sealing (ST-P1-13 & ST-P2-15)
// ============================================================================

async function sealManifestCacheRecord(localMetaKey, item, manifest, manifestUtf8, manifestShaHex) {
  const innerPt = utf8Encode(
    JSON.stringify({
      manifest,
      raw_manifest_b64u: bytesToB64u(manifestUtf8),
      manifest_sha256: manifestShaHex,
    }),
  );
  const nonce = randomBytes(12);
  const aad = utf8Encode(`synctool-v1/manifest-cache:${item.item_id}`);
  const ct = await aesGcmSeal(localMetaKey, nonce, innerPt, aad);
  return {
    item_id: item.item_id,
    cached_at: Math.floor(Date.now() / 1000),
    expires_at: item.expires_at,
    manifest_sha256: manifestShaHex,
    sealed_preview_v1: bytesToB64u(concatBytes(nonce, ct)),
  };
}

/**
 * Open and cryptographically verify a cached manifest entry against `header.manifestSha256` & `header.msgId`.
 * Returns verified `manifest` object or `null` if stale/tampered/mismatched.
 */
async function verifyCachedManifestRecord(localMetaKey, itemId, rawCached, header) {
  if (!rawCached || typeof rawCached !== 'object') return null;
  try {
    let manifest = null;
    let rawManifestBytes = null;
    let claimedShaHex = typeof rawCached.manifest_sha256 === 'string' ? rawCached.manifest_sha256.toLowerCase() : '';

    if (typeof rawCached.sealed_preview_v1 === 'string') {
      const blob = b64uToBytes(rawCached.sealed_preview_v1);
      if (blob.length < 28) return null;
      const nonce = blob.subarray(0, 12);
      const ct = blob.subarray(12);
      const aad = utf8Encode(`synctool-v1/manifest-cache:${itemId}`);
      const pt = await aesGcmOpen(localMetaKey, nonce, ct, aad);
      const inner = JSON.parse(utf8Decode(pt));
      manifest = inner.manifest;
      if (typeof inner.raw_manifest_b64u === 'string') {
        rawManifestBytes = b64uToBytes(inner.raw_manifest_b64u);
      }
      if (typeof inner.manifest_sha256 === 'string') {
        claimedShaHex = inner.manifest_sha256.toLowerCase();
      }
    } else if (rawCached.manifest && typeof rawCached.manifest === 'object') {
      // Backwards-compatible with Go FileKeyStore CachedManifestEntry or custom KeyStore objects
      manifest = rawCached.manifest;
      if (typeof rawCached.raw_manifest_b64u === 'string') {
        rawManifestBytes = b64uToBytes(rawCached.raw_manifest_b64u);
      }
    } else {
      return null;
    }

    if (!manifest || typeof manifest !== 'object') return null;
    const serialized = validateManifest(manifest, { expectedMsgId: header.msgId });
    if (manifest.sender.device_id !== header.senderDeviceId || manifest.created_at !== header.createdAt) {
      return null;
    }

    // Verify exact manifest SHA-256 matches the Ed25519-signed SealedHeader!
    if (rawManifestBytes) {
      const actualSha = await sha256(rawManifestBytes);
      if (!constantTimeEqual(actualSha, header.manifestSha256)) return null;
    } else if (/^[0-9a-f]{64}$/.test(claimedShaHex)) {
      if (!constantTimeEqual(hexToBytes(claimedShaHex), header.manifestSha256)) return null;
    } else {
      const actualSha = await sha256(serialized);
      if (!constantTimeEqual(actualSha, header.manifestSha256)) return null;
    }

    return manifest;
  } catch {
    return null;
  }
}

// ============================================================================
// Flow 2: Paired Device 0-RTT Send (Mode B Spool + Mode A Direct Pipe Dispatch)
// ============================================================================

export async function sendToDeviceImpl(client, targetDeviceId, parcel, opts = {}) {
  const deliveryMode = opts.deliveryMode ?? 'auto';
  if (!ALLOWED_DELIVERY_MODES.has(deliveryMode)) {
    throw new SyncError(ErrorCode.ERR_BAD_REQUEST, `invalid deliveryMode: ${deliveryMode} (expected auto, spool, or pipe)`);
  }
  const targetCard = await client.keyStore.getDevice(targetDeviceId);
  if (!targetCard || targetCard.revoked) {
    throw new SyncError(ErrorCode.ERR_DEVICE_UNTRUSTED, `target device untrusted or revoked: ${targetDeviceId}`);
  }
  const caps = await client.capabilities({ signal: opts.signal });
  const blocksPerChunk = caps.streaming.blocks_per_chunk;
  const prep = await prepareParcel(client, parcel, blocksPerChunk);

  const sealed = await sealPaired0RTTHeader({
    msgId: prep.msgIdRaw,
    senderSignSeed: prep.identity.signSeed,
    senderDeviceIdRaw: prep.identity.deviceIdRaw,
    recipientDeviceIdRaw: hexToBytes(targetCard.device_id),
    recipientKemPk: b64uToBytes(targetCard.kem_pk),
    createdAt: prep.createdAt,
    manifestSha256: prep.manifestSha256,
  });

  let itemId = null;
  let uploadToken = null;
  let committed = false;

  try {
    if (deliveryMode === 'pipe') {
      return await sendDirectModeAImpl(client, prep, sealed, blocksPerChunk, opts);
    }

    const canUseSpool = Boolean(caps.spool?.enabled && targetCard.mailbox_id && targetCard.outbound_deposit_token);
    if (!caps.spool?.enabled) {
      throw new SyncError(ErrorCode.ERR_SPOOL_DISABLED, 'relay offline spool is disabled (--spool=off)', {
        httpStatus: 403,
        details: { suggest_mode: 'pipe' },
      });
    }
    if (!canUseSpool) {
      throw new SyncError(ErrorCode.ERR_SPOOL_DISABLED, 'peer DeviceCard has no mailbox/deposit_token (paired under --spool=off)', {
        httpStatus: 403,
        details: { suggest_mode: 'pipe' },
      });
    }
    if (caps.spool.max_item_bytes > 0 && prep.declaredTotalBytes > caps.spool.max_item_bytes) {
      throw new SyncError(ErrorCode.ERR_OFFLINE_QUOTA_EXCEEDED, 'parcel exceeds relay spool.max_item_bytes', {
        httpStatus: 413,
        details: {
          scope: 'item',
          max_item_bytes: caps.spool.max_item_bytes,
          actual_bytes: prep.declaredTotalBytes,
          suggest_mode: 'pipe',
        },
      });
    }

    const initRes = await client._signedRequest({
      method: 'POST',
      path: '/v1/spool/init',
      depositToken: targetCard.outbound_deposit_token,
      jsonBody: {
        mailbox_id: targetCard.mailbox_id,
        declared_total_bytes: prep.declaredTotalBytes,
        ttl_sec: opts.ttlSec ?? 0,
        sealed_header: sealed.sealedHeaderB64u,
        parts: prep.partsMeta,
      },
      signal: opts.signal,
    });
    const initData = await initRes.json();
    itemId = initData.item_id;
    uploadToken = initData.upload_token;

    const startMs = Date.now();
    let bytesDone = 0;
    const emit = (stage, partId, partDone, partTotal) => {
      if (!opts.onProgress) return;
      opts.onProgress({
        type: 'event',
        event: 'transfer_progress',
        stage,
        direction: 'send',
        mode: 'spool',
        msg_id: prep.msgId,
        part_id: partId,
        parts_total: prep.partsMeta.length,
        bytes_done: bytesDone,
        bytes_total: prep.declaredTotalBytes,
        part_bytes_done: partDone,
        part_bytes_total: partTotal,
        speed_bps: calcSpeedBps(bytesDone, startMs),
        resumed: false,
        ts: Math.floor(Date.now() / 1000),
      });
    };

    const putSpoolChunk = async (pid, tx, buf) => {
      await client._signedRequest({
        method: 'PUT',
        path: `/v1/spool/${itemId}/parts/${pid}/chunks/${tx}`,
        uploadToken,
        bodyBytes: buf,
        isDataPlanePut: true,
        signal: opts.signal,
      });
    };

    let p0Done = 0;
    await uploadPartStreaming({
      partId: 0,
      plaintextSize: prep.paddedManifest.length,
      readPlaintextSlice: async (off, len) => prep.paddedManifest.subarray(off, off + len),
      encKey: sealed.part0Key,
      noncePrefix: sealed.part0NoncePrefix,
      msgIdRaw: prep.msgIdRaw,
      blocksPerChunk,
      putChunkFn: putSpoolChunk,
      onChunkDone: (_tx, len) => {
        bytesDone += len;
        p0Done += len;
        emit('transferring', 0, p0Done, prep.partsMeta[0].total_bytes);
      },
    });

    for (const { partId, blobKey, input } of prep.blobSecrets) {
      const { encKey, noncePrefix } = await deriveBlobPartKeys(blobKey, prep.msgIdRaw, partId);
      let pDone = 0;
      const pTotal = prep.partsMeta[partId].total_bytes;
      try {
        await uploadPartStreaming({
          partId,
          plaintextSize: input.size,
          readPlaintextSlice: (off, len) => input.readSlice(off, len),
          encKey,
          noncePrefix,
          msgIdRaw: prep.msgIdRaw,
          blocksPerChunk,
          putChunkFn: putSpoolChunk,
          onChunkDone: (_tx, len) => {
            bytesDone += len;
            pDone += len;
            emit('transferring', partId, pDone, pTotal);
          },
        });
      } finally {
        zeroBytes(encKey);
      }
    }

    const commitRes = await client._signedRequest({
      method: 'POST',
      path: `/v1/spool/${itemId}/commit`,
      uploadToken,
      jsonBody: {},
      signal: opts.signal,
    });
    committed = true;
    const commitData = await commitRes.json();
    emit('completed', prep.partsMeta.length - 1, 0, 0);
    return {
      mode: 'spool',
      itemId,
      msgId: prep.msgId,
      totalBytes: prep.declaredTotalBytes,
      expiresAt: commitData.expires_at ?? initData.expires_at,
    };
  } catch (err) {
    // ST-P1-10: immediately release uncommitted spool quota on abort or mid-upload failure
    if (!committed && itemId && uploadToken) {
      await client
        ._signedRequest({
          method: 'DELETE',
          path: `/v1/spool/${itemId}`,
          uploadToken,
          signal: AbortSignal.timeout(5_000),
        })
        .catch(() => {});
    }
    throw err;
  } finally {
    prep.zero();
    zeroBytes(sealed.part0Key);
    zeroBytes(sealed.part0NoncePrefix);
    zeroBytes(sealed.hdrKey);
    zeroBytes(sealed.hdrPrk);
  }
}

// ============================================================================
// Flow 2: Mode B Two-Phase Inbox (List / Fetch / Watch / Revoke)
// ============================================================================

async function fetchAndVerifyManifestPart0(client, itemMeta, header, mailboxId, signal) {
  const part0 = (itemMeta.parts || []).find((p) => p.part_id === 0);
  assertValidPart0Layout(part0);
  const chunks = [];
  let p0Total = 0;
  for (let tx = 0; tx < part0.chunk_count; tx++) {
    const res = await client._signedRequest({
      method: 'GET',
      path: `/v1/spool/${itemMeta.item_id}/parts/0/chunks/${tx}`,
      signMailbox: true,
      mailboxId,
      signal,
    });
    const ch = new Uint8Array(await res.arrayBuffer());
    p0Total += ch.length;
    if (p0Total > MAX_ENCRYPTED_MANIFEST_BYTES || p0Total > part0.total_bytes) {
      throw new SyncError(ErrorCode.ERR_MANIFEST_INVALID, 'part_id=0 stream exceeded maximum manifest byte budget');
    }
    chunks.push(ch);
  }
  if (p0Total !== part0.total_bytes) {
    throw new SyncError(ErrorCode.ERR_STREAM_TRUNCATED, 'part_id=0 stream shorter than declared total_bytes');
  }
  const padded = await decryptPartBytes(header.part0Key, header.part0NoncePrefix, header.msgIdRaw, 0, chunks);
  const manifestUtf8 = unpadManifest(padded);
  const actualSha = await sha256(manifestUtf8);
  if (!constantTimeEqual(actualSha, header.manifestSha256)) {
    throw new SyncError(ErrorCode.ERR_HASH_MISMATCH, 'manifest SHA-256 mismatch with SealedHeader');
  }
  const manifest = JSON.parse(utf8Decode(manifestUtf8));
  validateManifest(manifest, { expectedMsgId: header.msgId });
  if (manifest.sender.device_id !== header.senderDeviceId || manifest.created_at !== header.createdAt) {
    throw new SyncError(ErrorCode.ERR_CRYPTO_SIGNATURE_INVALID, 'manifest sender/created_at mismatch with SealedHeader');
  }
  return { manifest, manifestUtf8, manifestShaHex: bytesToHex(actualSha) };
}

async function fetchRawMailboxItemsWithHeal(client, mb, signal) {
  const doGet = () =>
    client._signedRequest({
      method: 'GET',
      path: `/v1/mailboxes/${mb.mailboxId}/items`,
      signMailbox: true,
      mailboxId: mb.mailboxId,
      signal,
    });
  try {
    const res = await doGet();
    return await res.json();
  } catch (err) {
    // Self-healing: if memory-spool relay restarted and returned 404 ERR_NOT_FOUND for our mailbox,
    // transparently re-register mailbox + peer deposit_tokens once and retry!
    if (err instanceof SyncError && err.code === ErrorCode.ERR_NOT_FOUND) {
      await client.syncMailbox({ signal });
      const retryRes = await doGet();
      return await retryRes.json();
    }
    throw err;
  }
}

/**
 * Two-phase inbox listing (ST-P0-3 & ST-P1-13):
 * ALWAYS verifies inline `SealedHeader` (`!card.revoked`, `!hasSeenMsgID`, Ed25519 signature, freshness window)
 * BEFORE consulting `localMetaKey`-encrypted cached manifests, evicting any stale/revoked/substituted cache entries.
 */
export async function listInboxImpl(client, opts = {}) {
  const [selfId, mb, watermarkSec] = await Promise.all([
    client.getIdentity(),
    client.getMailboxIdentity(),
    client._getReplayWatermarkSec(),
  ]);
  const data = await fetchRawMailboxItemsWithHeal(client, mb, opts.signal);
  const items = data.items || [];
  const activeIds = new Set(items.map((it) => it.item_id));
  if (client.keyStore.pruneCachedManifestPreviews) {
    await client.keyStore.pruneCachedManifestPreviews(activeIds);
  }

  const nowSec = client._localNowSec();
  const previews = [];
  for (const item of items) {
    let header = null;
    try {
      header = await openPaired0RTTHeader({
        sealedHeader: item.sealed_header,
        recipientKemSk: selfId.kemSk,
        recipientDeviceIdRaw: selfId.deviceIdRaw,
        nowSec,
        replayWatermarkSec: watermarkSec,
        hasSeenMsgId: (id) => client.keyStore.hasSeenMsgID(id),
        lookupSenderCard: (id) => client.keyStore.getDevice(id),
      });

      let manifest = null;
      if (client.keyStore.getCachedManifestPreview) {
        const rawCached = await client.keyStore.getCachedManifestPreview(item.item_id);
        if (rawCached) {
          manifest = await verifyCachedManifestRecord(selfId.localMetaKey, item.item_id, rawCached, header);
          if (!manifest && client.keyStore.deleteCachedManifestPreview) {
            await client.keyStore.deleteCachedManifestPreview(item.item_id);
          }
        }
      }

      if (!manifest) {
        const fetched = await fetchAndVerifyManifestPart0(client, item, header, mb.mailboxId, opts.signal);
        manifest = fetched.manifest;
        if (client.keyStore.putCachedManifestPreview) {
          const sealedCache = await sealManifestCacheRecord(
            selfId.localMetaKey,
            item,
            fetched.manifest,
            fetched.manifestUtf8,
            fetched.manifestShaHex,
          );
          await client.keyStore.putCachedManifestPreview(item.item_id, sealedCache);
        }
      }

      if (!opts.appId || manifest.app_id === opts.appId) {
        previews.push({
          item_id: item.item_id,
          created_at: item.created_at,
          expires_at: item.expires_at,
          total_bytes: item.total_bytes,
          parts: item.parts,
          sealed_header: item.sealed_header,
          manifest,
          sender_device_id: header.senderDeviceId,
          sender_label: header.senderCard.label,
        });
      }
    } catch (err) {
      if (client.keyStore.deleteCachedManifestPreview) {
        await client.keyStore.deleteCachedManifestPreview(item.item_id).catch(() => {});
      }
      if (opts.strict) throw err;
      continue;
    } finally {
      if (header) {
        zeroBytes(header.part0Key);
        zeroBytes(header.part0NoncePrefix);
      }
    }
  }
  return previews;
}

/**
 * Fetch, verify, deliver, record seen_msg_ids, and send signed ACK burn for a Mode B spooled parcel.
 * Enforces `inFlightMsgIds`, `SealedHeader.created_at` window, `appId` pre-filter (ST-P2-1), `PartLayout` bounds (ST-P0-2),
 * `maxInMemoryBlobBytes`, and streaming `resumePrefixReaders` (ST-P1-11).
 */
export async function fetchParcelImpl(client, itemId, handler, opts = {}) {
  const [selfId, mb, watermarkSec] = await Promise.all([
    client.getIdentity(),
    client.getMailboxIdentity(),
    client._getReplayWatermarkSec(),
  ]);
  let itemMeta = opts.itemMeta ?? null;
  if (!itemMeta) {
    const data = await fetchRawMailboxItemsWithHeal(client, mb, opts.signal);
    itemMeta = (data.items || []).find((it) => it.item_id === itemId);
    if (!itemMeta) {
      throw new SyncError(ErrorCode.ERR_NOT_FOUND, `spooled item not found: ${itemId}`, { httpStatus: 404 });
    }
  }

  const header = await openPaired0RTTHeader({
    sealedHeader: itemMeta.sealed_header,
    recipientKemSk: selfId.kemSk,
    recipientDeviceIdRaw: selfId.deviceIdRaw,
    nowSec: client._localNowSec(),
    replayWatermarkSec: watermarkSec,
    hasSeenMsgId: async (id) => client._inFlightMsgIds.has(id) || (await client.keyStore.hasSeenMsgID(id)),
    lookupSenderCard: (id) => client.keyStore.getDevice(id),
  });

  if (client._inFlightMsgIds.has(header.msgId)) {
    zeroBytes(header.part0Key);
    zeroBytes(header.part0NoncePrefix);
    throw new SyncError(ErrorCode.ERR_MSG_REPLAY_DETECTED, `parcel msg_id is already in flight: ${header.msgId}`);
  }
  client._inFlightMsgIds.add(header.msgId);

  try {
    let manifest = null;
    if (client.keyStore.getCachedManifestPreview) {
      const rawCached = await client.keyStore.getCachedManifestPreview(itemId);
      if (rawCached) {
        manifest = await verifyCachedManifestRecord(selfId.localMetaKey, itemId, rawCached, header);
        if (!manifest && client.keyStore.deleteCachedManifestPreview) {
          await client.keyStore.deleteCachedManifestPreview(itemId);
        }
      }
    }
    if (!manifest) {
      const fetched = await fetchAndVerifyManifestPart0(client, itemMeta, header, mb.mailboxId, opts.signal);
      manifest = fetched.manifest;
      if (client.keyStore.putCachedManifestPreview) {
        const sealedCache = await sealManifestCacheRecord(
          selfId.localMetaKey,
          itemMeta,
          fetched.manifest,
          fetched.manifestUtf8,
          fetched.manifestShaHex,
        );
        await client.keyStore.putCachedManifestPreview(itemId, sealedCache);
      }
    }

    // ST-P2-1: appId pre-filter — NEVER download blobs or burn another app's parcel on a shared mailbox!
    if (opts.appId && manifest.app_id !== opts.appId) {
      throw new SyncError(
        ErrorCode.ERR_INVALID_STATE,
        `parcel app_id "${manifest.app_id}" does not match requested appId "${opts.appId}"`,
        { details: { app_id: manifest.app_id, expected_app_id: opts.appId, skipped: true } },
      );
    }

    const caps = opts.blocksPerChunk ? null : await client.capabilities({ signal: opts.signal }).catch(() => null);
    const knownBlocksPerChunk = opts.blocksPerChunk ?? caps?.streaming?.blocks_per_chunk ?? null;
    const blocksPerChunk = knownBlocksPerChunk ?? 16;
    assertValidBlocksPerChunk(blocksPerChunk);

    // ST-P0-2: validate ALL wire PartLayouts against signed Manifest BEFORE downloading any blob chunks!
    for (const blobDesc of manifest.blobs) {
      const pm = (itemMeta.parts || []).find((p) => p.part_id === blobDesc.part_id);
      if (!pm) throw new SyncError(ErrorCode.ERR_MANIFEST_INVALID, `item missing part_id=${blobDesc.part_id}`);
      assertValidBlobPartLayout(pm, blobDesc, knownBlocksPerChunk);
    }

    const part0Meta = (itemMeta.parts || []).find((p) => p.part_id === 0);
    const startMs = Date.now();
    let bytesDone = part0Meta?.total_bytes ?? 0;
    let transferredSinceStart = 0;
    const maxInMemoryBlobBytes = opts.maxInMemoryBlobBytes ?? client._maxInMemoryBlobBytes;
    const blobs = [];

    for (const blobDesc of manifest.blobs) {
      const pm = (itemMeta.parts || []).find((p) => p.part_id === blobDesc.part_id);
      const startTxIdx = opts.resumeCheckpoints?.get(blobDesc.part_id) ?? 0;
      const resumePrefixBytes = opts.resumePrefixes?.get(blobDesc.part_id) ?? null;
      const resumePrefixReader = opts.resumePrefixReaders?.get(blobDesc.part_id) ?? null;
      const resumedCipherOffset = startTxIdx > 0
        ? Math.min(pm.total_bytes, startTxIdx * blocksPerChunk * CHUNK_CIPHERTEXT_MAX)
        : 0;
      let partDone = resumedCipherOffset;
      bytesDone += resumedCipherOffset;

      blobs.push(
        await downloadBlobStreaming({
          blobDesc,
          chunkCount: pm.chunk_count,
          blocksPerChunk,
          msgIdRaw: header.msgIdRaw,
          startTxIdx,
          resumePrefixBytes,
          resumePrefixReader,
          createBlobSink: opts.createBlobSink,
          maxInMemoryBlobBytes,
          getChunkFn: async (pid, tx) => {
            const res = await client._signedRequest({
              method: 'GET',
              path: `/v1/spool/${itemId}/parts/${pid}/chunks/${tx}`,
              signMailbox: true,
              mailboxId: mb.mailboxId,
              signal: opts.signal,
            });
            return new Uint8Array(await res.arrayBuffer());
          },
          onChunkDone: (tx, len) => {
            bytesDone += len;
            partDone += len;
            transferredSinceStart += len;
            opts.onChunkCheckpoint?.(blobDesc.part_id, tx + 1);
            opts.onProgress?.({
              type: 'event',
              event: 'transfer_progress',
              stage: 'transferring',
              direction: 'recv',
              mode: 'spool',
              msg_id: header.msgId,
              part_id: blobDesc.part_id,
              parts_total: itemMeta.parts.length,
              bytes_done: bytesDone,
              bytes_total: itemMeta.total_bytes,
              part_bytes_done: partDone,
              part_bytes_total: pm.total_bytes,
              speed_bps: calcSpeedBps(transferredSinceStart, startMs),
              resumed: startTxIdx > 0,
              ts: Math.floor(Date.now() / 1000),
            });
          },
        }),
      );
    }

    // Atomic delivery BEFORE marking seen & ACKing burn
    await handler({ itemId, manifest, senderCard: header.senderCard, blobs });
    await client.keyStore.markSeenMsgID(header.msgId, header.createdAt, client._localNowSec());

    try {
      await client._signedRequest({
        method: 'POST',
        path: `/v1/spool/${itemId}/ack`,
        jsonBody: {},
        signMailbox: true,
        mailboxId: mb.mailboxId,
        signal: opts.signal,
      });
    } catch (err) {
      if (!(err instanceof SyncError && err.code === ErrorCode.ERR_NOT_FOUND)) {
        throw err;
      }
    }
    if (client.keyStore.deleteCachedManifestPreview) {
      await client.keyStore.deleteCachedManifestPreview(itemId);
    }
    opts.onProgress?.({
      type: 'event',
      event: 'transfer_progress',
      stage: 'completed',
      direction: 'recv',
      mode: 'spool',
      msg_id: header.msgId,
      part_id: manifest.blobs.length,
      parts_total: itemMeta.parts.length,
      bytes_done: itemMeta.total_bytes ?? bytesDone,
      bytes_total: itemMeta.total_bytes ?? bytesDone,
      part_bytes_done: 0,
      part_bytes_total: 0,
      speed_bps: calcSpeedBps(transferredSinceStart, startMs),
      resumed: false,
      ts: Math.floor(Date.now() / 1000),
    });
    return manifest;
  } finally {
    client._inFlightMsgIds.delete(header.msgId);
    zeroBytes(header.part0Key);
    zeroBytes(header.part0NoncePrefix);
  }
}

/**
 * Watch mailbox events via SSE (with 60s idle read timeout, `since_ts - 1` same-second safety,
 * 4096-entry FIFO `item_id` dedup, immediate TLS/Auth error rethrow, and 250ms..5s jittered backoff).
 */
export async function watchInboxImpl(client, { onItem, preferPoll = false, sinceTs, signal }) {
  const mb = await client.getMailboxIdentity();
  let highWaterTs = typeof sinceTs === 'number'
    ? Math.max(0, Math.floor(sinceTs))
    : Math.max(0, client._authNowSec());
  let usePoll = preferPoll;
  let pollCyclesSinceFallback = 0;
  let retryAttempt = 0;
  let healed404 = false;
  const seenItemIds = new BoundedIdSet(4096);

  while (!signal?.aborted) {
    // Query `highWaterTs - 1` so items committed later in the same Unix second are never dropped!
    const querySinceTs = Math.max(0, highWaterTs - 1);
    const path = usePoll
      ? `/v1/mailboxes/${mb.mailboxId}/events?mode=poll&wait_sec=20&since_ts=${querySinceTs}`
      : `/v1/mailboxes/${mb.mailboxId}/events?mode=sse&since_ts=${querySinceTs}`;
    const reqStartMs = Date.now();

    try {
      const res = await client._signedRequest({
        method: 'GET',
        path,
        signMailbox: true,
        mailboxId: mb.mailboxId,
        signal,
      });
      healed404 = false;
      if (usePoll) {
        const data = await res.json();
        retryAttempt = 0;
        for (const item of data.items || []) {
          if (typeof item.created_at === 'number') highWaterTs = Math.max(highWaterTs, item.created_at);
          if (item.item_id && seenItemIds.has(item.item_id)) continue;
          if (item.item_id) seenItemIds.add(item.item_id);
          await onItem(item);
        }
        if (typeof data.server_ts === 'number') highWaterTs = Math.max(highWaterTs, data.server_ts);
        if (!preferPoll) {
          pollCyclesSinceFallback++;
          if (pollCyclesSinceFallback >= 3) {
            usePoll = false;
            pollCyclesSinceFallback = 0;
          }
        }
      } else {
        let cleanlyRotated = false;
        for await (const ev of iterateSSE(res.body, signal, { idleTimeoutMs: DEFAULT_SSE_IDLE_TIMEOUT_MS })) {
          retryAttempt = 0;
          if (ev.event === 'reconnect') {
            cleanlyRotated = true;
            break;
          }
          if (ev.event === 'new_item' && ev.data) {
            let item;
            try {
              item = JSON.parse(ev.data);
            } catch {
              continue;
            }
            if (typeof item.created_at === 'number') highWaterTs = Math.max(highWaterTs, item.created_at);
            if (item.item_id && seenItemIds.has(item.item_id)) continue;
            if (item.item_id) seenItemIds.add(item.item_id);
            await onItem(item);
          }
        }
        if (!cleanlyRotated && Date.now() - reqStartMs < 500 && !signal?.aborted) {
          await sleepWithSignal(computeRetryBackoffMs(retryAttempt++), signal);
        }
      }
    } catch (err) {
      if (signal?.aborted || (err instanceof SyncError && err.code === ErrorCode.ERR_CANCELLED)) return;
      if (err instanceof SyncError && err.code === ErrorCode.ERR_NOT_FOUND && !healed404) {
        healed404 = true;
        await client.syncMailbox({ signal });
        continue;
      }
      if (
        isAuthError(err) ||
        isSecurityAlert(err) ||
        isVersionMismatch(err) ||
        (err instanceof SyncError && (err.code === ErrorCode.ERR_SPOOL_DISABLED || err.code === ErrorCode.ERR_NOT_FOUND))
      ) {
        throw err;
      }
      usePoll = true;
      pollCyclesSinceFallback = 0;
      await sleepWithSignal(computeRetryBackoffMs(retryAttempt++, err), signal);
    }
  }
}

/**
 * Two-phase precision single-device revocation (ST-P1-8):
 * 1. Immediately persists `revoked = true` + `pending_token_delete` in KeyStore (blocking local trust even if offline).
 * 2. Deletes only that peer's `deposit_token` on the relay, then deletes the record from KeyStore (retried in `syncMailbox` if offline).
 */
export async function revokeDeviceImpl(client, deviceId, opts = {}) {
  const card = await client.keyStore.getDevice(deviceId);
  if (!card) {
    throw new SyncError(ErrorCode.ERR_DEVICE_UNTRUSTED, `device not found in keystore: ${deviceId}`);
  }

  const hasToken = Boolean(card.inbound_token_id);
  const staleTokens = Array.isArray(card.stale_inbound_token_ids) ? card.stale_inbound_token_ids : [];
  await client.keyStore.putDevice({
    ...card,
    revoked: true,
    pending_token_delete: hasToken || staleTokens.length > 0,
  });

  const tokensToDelete = [
    ...(card.inbound_token_id ? [card.inbound_token_id] : []),
    ...staleTokens,
  ];
  if (tokensToDelete.length > 0) {
    const mb = await client.getMailboxIdentity();
    for (const tokId of tokensToDelete) {
      try {
        await client._signedRequest({
          method: 'DELETE',
          path: `/v1/mailboxes/${mb.mailboxId}/deposit-tokens/${tokId}`,
          signMailbox: true,
          mailboxId: mb.mailboxId,
          signal: opts.signal,
        });
      } catch (err) {
        if (!(err instanceof SyncError && (err.code === ErrorCode.ERR_NOT_FOUND || err.code === ErrorCode.ERR_SPOOL_DISABLED))) {
          throw err;
        }
      }
    }
  }

  await client.keyStore.deleteDevice(card.device_id);
}
