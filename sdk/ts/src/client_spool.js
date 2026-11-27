// Internal Flow 2 Mode B Encrypted Spool delivery, two-phase inbox preview/fetch, SSE watch & revocation.
// Part of synctool v1 zero-dependency cross-platform client.

import {
  b64uToBytes,
  constantTimeEqual,
  decryptPartBytes,
  deriveBlobPartKeys,
  hexToBytes,
  openPaired0RTTHeader,
  sealPaired0RTTHeader,
  sha256,
  unpadManifest,
  utf8Decode,
  zeroBytes,
} from './crypto.js';
import {
  ErrorCode,
  MAX_ENCRYPTED_MANIFEST_BYTES,
  SyncError,
  validateManifest,
} from './envelope.js';
import { iterateSSE } from './client_transport.js';
import {
  assertValidPart0Layout,
  downloadBlobStreaming,
  prepareParcel,
  sendDirectModeAImpl,
  uploadPartStreaming,
} from './client_pipe.js';

// ============================================================================
// Flow 2: Paired Device 0-RTT Send (Mode B Spool + Mode A Direct Pipe Dispatch)
// ============================================================================

export async function sendToDeviceImpl(client, targetDeviceId, parcel, opts = {}) {
  const targetCard = await client.keyStore.getDevice(targetDeviceId);
  if (!targetCard || targetCard.revoked) {
    throw new SyncError(ErrorCode.ERR_DEVICE_UNTRUSTED, `target device untrusted or revoked: ${targetDeviceId}`);
  }
  const caps = await client.capabilities({ signal: opts.signal });
  const blocksPerChunk = caps.streaming.blocks_per_chunk;
  const prep = await prepareParcel(client, parcel, blocksPerChunk);
  const deliveryMode = opts.deliveryMode ?? 'auto';

  const sealed = await sealPaired0RTTHeader({
    msgId: prep.msgIdRaw,
    senderSignSeed: prep.identity.signSeed,
    senderDeviceIdRaw: prep.identity.deviceIdRaw,
    recipientDeviceIdRaw: hexToBytes(targetCard.device_id),
    recipientKemPk: b64uToBytes(targetCard.kem_pk),
    createdAt: prep.createdAt,
    manifestSha256: prep.manifestSha256,
  });

  try {
    const canUseSpool = Boolean(caps.spool?.enabled && targetCard.mailbox_id && targetCard.outbound_deposit_token);
    if (deliveryMode === 'auto') {
      if (!caps.spool?.enabled) {
        throw new SyncError(ErrorCode.ERR_SPOOL_DISABLED, 'relay offline spool is disabled (--spool=off)', {
          httpStatus: 403,
          details: { suggest_mode: 'pipe' },
        });
      }
      if (prep.declaredTotalBytes > caps.spool.max_item_bytes) {
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
      if (!canUseSpool) {
        throw new SyncError(ErrorCode.ERR_SPOOL_DISABLED, 'peer DeviceCard has no mailbox/deposit_token (paired under --spool=off)', {
          details: { suggest_mode: 'pipe' },
        });
      }
    }

    if (deliveryMode === 'pipe') {
      return await sendDirectModeAImpl(client, prep, sealed, blocksPerChunk, opts);
    }

    // Mode B Encrypted Spool
    if (!targetCard.mailbox_id || !targetCard.outbound_deposit_token) {
      throw new SyncError(ErrorCode.ERR_SPOOL_DISABLED, 'target DeviceCard missing mailbox_id or outbound_deposit_token');
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
    const itemId = initData.item_id;
    const uploadToken = initData.upload_token;

    let bytesDone = 0;
    const emit = (partId, partDone, partTotal) => {
      if (!opts.onProgress) return;
      opts.onProgress({
        type: 'event',
        event: 'transfer_progress',
        stage: 'transferring',
        direction: 'send',
        mode: 'spool',
        msg_id: prep.msgId,
        part_id: partId,
        parts_total: prep.partsMeta.length,
        bytes_done: bytesDone,
        bytes_total: prep.declaredTotalBytes,
        part_bytes_done: partDone,
        part_bytes_total: partTotal,
        speed_bps: 0,
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
      onChunkDone: (_tx, len) => { bytesDone += len; p0Done += len; emit(0, p0Done, prep.partsMeta[0].total_bytes); },
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
          onChunkDone: (_tx, len) => { bytesDone += len; pDone += len; emit(partId, pDone, pTotal); },
        });
      } finally {
        zeroBytes(encKey);
        zeroBytes(blobKey);
      }
    }

    const commitRes = await client._signedRequest({
      method: 'POST',
      path: `/v1/spool/${itemId}/commit`,
      uploadToken,
      jsonBody: {},
      signal: opts.signal,
    });
    const commitData = await commitRes.json();
    return {
      mode: 'spool',
      itemId,
      msgId: prep.msgId,
      totalBytes: prep.declaredTotalBytes,
      expiresAt: commitData.expires_at,
    };
  } finally {
    zeroBytes(sealed.part0Key);
    zeroBytes(sealed.hdrKey);
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
    if (p0Total > MAX_ENCRYPTED_MANIFEST_BYTES) {
      throw new SyncError(ErrorCode.ERR_MANIFEST_INVALID, 'part_id=0 stream exceeded maximum manifest byte budget');
    }
    chunks.push(ch);
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
  return manifest;
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
 * Two-phase inbox listing: decrypts and locally caches part_id=0 Manifest previews by item_id
 * so repeated refreshes do not consume the relay's 16-download part_id=0 quota.
 */
export async function listInboxImpl(client, opts = {}) {
  const [selfId, mb] = await Promise.all([client.getIdentity(), client.getMailboxIdentity()]);
  const data = await fetchRawMailboxItemsWithHeal(client, mb, opts.signal);
  const items = data.items || [];
  const activeIds = new Set(items.map((it) => it.item_id));
  if (client.keyStore.pruneCachedManifestPreviews) {
    await client.keyStore.pruneCachedManifestPreviews(activeIds);
  }

  const previews = [];
  for (const item of items) {
    let cached = client.keyStore.getCachedManifestPreview
      ? await client.keyStore.getCachedManifestPreview(item.item_id)
      : null;
    if (!cached) {
      let header;
      try {
        header = await openPaired0RTTHeader({
          sealedHeader: item.sealed_header,
          recipientKemSk: selfId.kemSk,
          recipientDeviceIdRaw: selfId.deviceIdRaw,
          hasSeenMsgId: (id) => client.keyStore.hasSeenMsgID(id),
          lookupSenderCard: (id) => client.keyStore.getDevice(id),
        });
        const manifest = await fetchAndVerifyManifestPart0(client, item, header, mb.mailboxId, opts.signal);
        cached = {
          item_id: item.item_id,
          created_at: item.created_at,
          expires_at: item.expires_at,
          total_bytes: item.total_bytes,
          parts: item.parts,
          sealed_header: item.sealed_header,
          manifest,
          sender_device_id: header.senderDeviceId,
          sender_label: header.senderCard.label,
        };
        if (client.keyStore.putCachedManifestPreview) {
          await client.keyStore.putCachedManifestPreview(item.item_id, cached);
        }
      } catch (err) {
        if (opts.strict) throw err;
        continue; // skip invalid/replayed/untrusted item in listing
      } finally {
        if (header) zeroBytes(header.part0Key);
      }
    }
    if (!opts.appId || cached.manifest.app_id === opts.appId) {
      previews.push(cached);
    }
  }
  return previews;
}

/**
 * Fetch, verify, deliver, record seen_msg_ids, and send signed ACK burn for a Mode B spooled parcel.
 */
export async function fetchParcelImpl(client, itemId, handler, opts = {}) {
  const [selfId, mb] = await Promise.all([client.getIdentity(), client.getMailboxIdentity()]);
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
    hasSeenMsgId: (id) => client.keyStore.hasSeenMsgID(id),
    lookupSenderCard: (id) => client.keyStore.getDevice(id),
  });

  try {
    const cached = client.keyStore.getCachedManifestPreview
      ? await client.keyStore.getCachedManifestPreview(itemId)
      : null;
    const validCache = cached?.manifest && cached.manifest.msg_id === header.msgId && (!cached.sealed_header || cached.sealed_header === itemMeta.sealed_header);
    const manifest = validCache
      ? cached.manifest
      : await fetchAndVerifyManifestPart0(client, itemMeta, header, mb.mailboxId, opts.signal);

    const caps = opts.blocksPerChunk ? null : await client.capabilities({ signal: opts.signal }).catch(() => null);
    const blocksPerChunk = opts.blocksPerChunk ?? caps?.streaming?.blocks_per_chunk ?? 16;

    let bytesDone = 0;
    const blobs = [];
    for (const blobDesc of manifest.blobs) {
      const pm = (itemMeta.parts || []).find((p) => p.part_id === blobDesc.part_id);
      if (!pm) throw new SyncError(ErrorCode.ERR_MANIFEST_INVALID, `item missing part_id=${blobDesc.part_id}`);
      const startTxIdx = opts.resumeCheckpoints?.get(blobDesc.part_id) ?? 0;
      const resumePrefixBytes = opts.resumePrefixes?.get(blobDesc.part_id) ?? null;
      let partDone = 0;
      blobs.push(await downloadBlobStreaming({
        blobDesc,
        chunkCount: pm.chunk_count,
        blocksPerChunk,
        msgIdRaw: header.msgIdRaw,
        startTxIdx,
        resumePrefixBytes,
        createBlobSink: opts.createBlobSink,
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
            speed_bps: 0,
            resumed: startTxIdx > 0,
            ts: Math.floor(Date.now() / 1000),
          });
        },
      }));
    }

    // Atomic delivery BEFORE marking seen & ACKing burn
    await handler({ itemId, manifest, senderCard: header.senderCard, blobs });
    await client.keyStore.markSeenMsgID(header.msgId, header.createdAt);

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
    return manifest;
  } finally {
    zeroBytes(header.part0Key);
  }
}

/**
 * Watch mailbox events on-demand via SSE (auto-reconnects cleanly on 90s rotation, falls back to 20s long-poll).
 */
export async function watchInboxImpl(client, { onItem, preferPoll = false, sinceTs, signal }) {
  const mb = await client.getMailboxIdentity();
  const defaultSince = Math.max(0, Math.floor(Date.now() / 1000) + (client._clockOffsetSec ?? 0) - 1);
  let cursorTs = typeof sinceTs === 'number' ? Math.max(0, sinceTs) : defaultSince;
  let usePoll = preferPoll;
  let healed404 = false;
  const seenItemIds = new Set();

  while (!signal?.aborted) {
    const path = usePoll
      ? `/v1/mailboxes/${mb.mailboxId}/events?mode=poll&wait_sec=20&since_ts=${cursorTs}`
      : `/v1/mailboxes/${mb.mailboxId}/events?mode=sse&since_ts=${cursorTs}`;
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
        for (const item of data.items || []) {
          if (typeof item.created_at === 'number') cursorTs = Math.max(cursorTs, item.created_at);
          if (item.item_id && seenItemIds.has(item.item_id)) continue;
          if (item.item_id) seenItemIds.add(item.item_id);
          await onItem(item);
        }
        if (typeof data.server_ts === 'number') cursorTs = Math.max(cursorTs, data.server_ts);
      } else {
        for await (const ev of iterateSSE(res.body, signal)) {
          if (ev.event === 'reconnect') break;
          if (ev.event === 'new_item' && ev.data) {
            const item = JSON.parse(ev.data);
            if (typeof item.created_at === 'number') cursorTs = Math.max(cursorTs, item.created_at);
            if (item.item_id && seenItemIds.has(item.item_id)) continue;
            if (item.item_id) seenItemIds.add(item.item_id);
            await onItem(item);
          }
        }
      }
    } catch (err) {
      if (signal?.aborted) return;
      if (err instanceof SyncError && err.code === ErrorCode.ERR_NOT_FOUND && !healed404) {
        healed404 = true;
        await client.syncMailbox({ signal });
        continue;
      }
      if (err instanceof SyncError && (err.code === ErrorCode.ERR_SPOOL_DISABLED || err.code === ErrorCode.ERR_UNAUTHORIZED_TOKEN || err.code === ErrorCode.ERR_AUTH_FAILED || err.code === ErrorCode.ERR_NOT_FOUND)) {
        throw err;
      }
      usePoll = true;
    }
  }
}

/**
 * Precision single-device revocation (zero impact on other paired devices; compatible with --spool=off).
 */
export async function revokeDeviceImpl(client, deviceId, opts = {}) {
  const card = await client.keyStore.getDevice(deviceId);
  if (card?.inbound_token_id) {
    const mb = await client.getMailboxIdentity();
    try {
      await client._signedRequest({
        method: 'DELETE',
        path: `/v1/mailboxes/${mb.mailboxId}/deposit-tokens/${card.inbound_token_id}`,
        signMailbox: true,
        mailboxId: mb.mailboxId,
        signal: opts.signal,
      });
    } catch (err) {
      // Already deleted or spool disabled: still remove local card
      if (!(err instanceof SyncError && (err.code === ErrorCode.ERR_NOT_FOUND || err.code === ErrorCode.ERR_SPOOL_DISABLED))) {
        throw err;
      }
    }
  }
  await client.keyStore.deleteDevice(deviceId);
}
