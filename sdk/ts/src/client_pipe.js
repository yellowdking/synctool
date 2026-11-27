// Internal parcel preparation, streaming chunk engine & Mode A zero-disk pipe transfers (OneShot + Direct).
// Part of synctool v1 zero-dependency cross-platform client.

import { formatRoomId, generateRoomId, normalizeRoomId } from './crockford.js';
import {
  AEAD_TAG_LEN,
  CHUNK_CIPHERTEXT_MAX,
  CHUNK_PLAINTEXT_MAX,
  PROTO_VERSION,
  b64uToBytes,
  bytesToB64u,
  bytesToHex,
  calcBlockCount,
  calcEncryptedPartSize,
  calcTransportChunkCount,
  computeDirectAckMac,
  concatBytes,
  constantTimeEqual,
  decryptPartBytes,
  deriveBlobPartKeys,
  deriveOneshotPart0Keys,
  derivePipeCtrlKeys,
  hexToBytes,
  openPaired0RTTHeader,
  openPipeCtrlFrame,
  openStreamBlock,
  padManifest,
  randomBytes,
  sealPipeCtrlFrame,
  sealStreamBlock,
  sha256,
  unpadManifest,
  utf8Decode,
  utf8Encode,
  verifyDirectAckMac,
  zeroBytes,
} from './crypto.js';
import {
  ENVELOPE_VERSION,
  ErrorCode,
  SyncError,
  formatPairURI,
  parsePairURI,
  validateManifest,
} from './envelope.js';
import {
  DEFAULT_HANDSHAKE_TIMEOUT_MS,
  StreamingSha256,
  computeBlobSha256,
} from './client_transport.js';
import {
  closeRoom,
  postRoomMessage,
  runFlow1Initiator,
  runFlow1Responder,
  waitRoomMessage,
} from './client_pair.js';

// ============================================================================
// Parcel Preparation & Streaming Chunk Upload/Download Engine
// ============================================================================

export async function prepareParcel(client, parcel, blocksPerChunk) {
  const id = await client.getIdentity();
  const msgIdRaw = randomBytes(16);
  const msgId = bytesToHex(msgIdRaw);
  const createdAt = Math.floor(Date.now() / 1000);
  const inputBlobs = parcel.blobs ?? [];

  const blobDescriptors = [];
  const blobSecrets = [];
  for (let i = 0; i < inputBlobs.length; i++) {
    const b = inputBlobs[i];
    const partId = i + 1;
    const hashHex = await computeBlobSha256(b);
    const blobKey = randomBytes(32);
    blobDescriptors.push({
      part_id: partId,
      role: b.role,
      name: b.name,
      mime: b.mime || 'application/octet-stream',
      size: b.size,
      sha256: hashHex,
      key: bytesToB64u(blobKey),
      encoding: b.encoding ?? 'identity',
      ...(b.meta ? { meta: b.meta } : {}),
    });
    blobSecrets.push({ partId, blobKey, input: b });
  }

  const manifest = {
    envelope_version: ENVELOPE_VERSION,
    msg_id: msgId,
    app_id: parcel.appId ?? client.appId,
    schema: parcel.schema,
    created_at: createdAt,
    sender: {
      device_id: id.deviceId,
      label: parcel.senderLabel ?? client.label,
      platform: parcel.senderPlatform ?? client.platform,
    },
    inline_payload: parcel.inlinePayload ?? null,
    blobs: blobDescriptors,
  };

  const manifestUtf8 = validateManifest(manifest, { expectedMsgId: msgId });
  const manifestSha256 = await sha256(manifestUtf8);
  const paddedManifest = padManifest(manifestUtf8);

  const partsMeta = [
    {
      part_id: 0,
      total_bytes: calcEncryptedPartSize(paddedManifest.length),
      chunk_count: calcTransportChunkCount(paddedManifest.length, blocksPerChunk),
    },
    ...blobSecrets.map(({ partId, input }) => ({
      part_id: partId,
      total_bytes: calcEncryptedPartSize(input.size),
      chunk_count: calcTransportChunkCount(input.size, blocksPerChunk),
    })),
  ];
  const declaredTotalBytes = partsMeta.reduce((acc, p) => acc + p.total_bytes, 0);

  return {
    identity: id,
    msgIdRaw,
    msgId,
    createdAt,
    manifest,
    manifestUtf8,
    manifestSha256,
    paddedManifest,
    blobSecrets,
    partsMeta,
    declaredTotalBytes,
  };
}

/**
 * Stream-encrypt and upload one part_id chunk-by-chunk (constant memory: at most blocksPerChunk * 65,552 B).
 */
export async function uploadPartStreaming({
  partId,
  plaintextSize,
  readPlaintextSlice,
  encKey,
  noncePrefix,
  msgIdRaw,
  blocksPerChunk,
  putChunkFn,
  startTxIdx = 0,
  onChunkDone,
}) {
  const totalBlocks = calcBlockCount(plaintextSize);
  const totalChunks = Math.ceil(totalBlocks / blocksPerChunk);

  for (let txIdx = startTxIdx; txIdx < totalChunks; txIdx++) {
    const firstBlock = txIdx * blocksPerChunk;
    const lastBlock = Math.min(totalBlocks, firstBlock + blocksPerChunk) - 1;
    const ctBlocks = [];
    for (let blockIdx = firstBlock; blockIdx <= lastBlock; blockIdx++) {
      const ptStart = blockIdx * CHUNK_PLAINTEXT_MAX;
      const ptLen = plaintextSize === 0 ? 0 : Math.min(CHUNK_PLAINTEXT_MAX, plaintextSize - ptStart);
      const ptBlock = ptLen === 0 ? new Uint8Array(0) : await readPlaintextSlice(ptStart, ptLen);
      const isFinal = blockIdx === totalBlocks - 1;
      ctBlocks.push(await sealStreamBlock(encKey, noncePrefix, msgIdRaw, partId, blockIdx, isFinal, ptBlock));
    }
    const transportChunk = ctBlocks.length === 1 ? ctBlocks[0] : concatBytes(...ctBlocks);
    await putChunkFn(partId, txIdx, transportChunk);
    if (onChunkDone) onChunkDone(txIdx, transportChunk.length);
  }
}

/**
 * Stream-download, AEAD-verify, SHA-256-verify, and write one blob part_id chunk-by-chunk.
 */
export async function downloadBlobStreaming({
  blobDesc,
  chunkCount,
  blocksPerChunk = 16,
  msgIdRaw,
  getChunkFn,
  createBlobSink,
  startTxIdx = 0,
  resumePrefixBytes = null,
  onChunkDone,
}) {
  const blobKey = b64uToBytes(blobDesc.key);
  const { encKey, noncePrefix } = await deriveBlobPartKeys(blobKey, msgIdRaw, blobDesc.part_id);
  const totalBlocks = calcBlockCount(blobDesc.size);
  const hasher = new StreamingSha256();
  const sink = createBlobSink ? await createBlobSink(blobDesc) : null;
  const collected = sink ? null : [];

  let blockIdx = startTxIdx * blocksPerChunk;
  let totalDecrypted = 0;
  let sawFinal = false;

  if (startTxIdx > 0 && resumePrefixBytes) {
    hasher.update(resumePrefixBytes);
    totalDecrypted += resumePrefixBytes.length;
    if (collected) collected.push(resumePrefixBytes);
  }

  try {
    for (let txIdx = startTxIdx; txIdx < chunkCount; txIdx++) {
      const chunkBytes = await getChunkFn(blobDesc.part_id, txIdx);
      if (chunkBytes.length < AEAD_TAG_LEN) {
        throw new SyncError(ErrorCode.ERR_STREAM_TRUNCATED, `chunk ${txIdx} of part ${blobDesc.part_id} too short`);
      }
      let offset = 0;
      while (offset < chunkBytes.length) {
        const end = Math.min(offset + CHUNK_CIPHERTEXT_MAX, chunkBytes.length);
        const ctBlock = chunkBytes.subarray(offset, end);
        const isFinal = blockIdx === totalBlocks - 1;
        if (!isFinal && ctBlock.length !== CHUNK_CIPHERTEXT_MAX) {
          throw new SyncError(ErrorCode.ERR_STREAM_TRUNCATED, `unexpected non-final block length at block ${blockIdx}`);
        }
        const ptBlock = await openStreamBlock(encKey, noncePrefix, msgIdRaw, blobDesc.part_id, blockIdx, isFinal, ctBlock);
        hasher.update(ptBlock);
        totalDecrypted += ptBlock.length;
        if (sink) {
          await sink.write(ptBlock);
        } else {
          collected.push(ptBlock);
        }
        if (isFinal) sawFinal = true;
        blockIdx++;
        offset = end;
      }
      if (onChunkDone) onChunkDone(txIdx, chunkBytes.length);
    }

    if (!sawFinal || blockIdx !== totalBlocks) {
      throw new SyncError(ErrorCode.ERR_STREAM_TRUNCATED, `part ${blobDesc.part_id} truncated before final block`);
    }
    if (totalDecrypted !== blobDesc.size) {
      throw new SyncError(ErrorCode.ERR_HASH_MISMATCH, `part ${blobDesc.part_id} size mismatch: ${totalDecrypted} != ${blobDesc.size}`);
    }
    const actualSha = hasher.digestHex();
    if (actualSha !== blobDesc.sha256) {
      throw new SyncError(ErrorCode.ERR_HASH_MISMATCH, `part ${blobDesc.part_id} SHA-256 mismatch`);
    }

    const sinkResult = sink ? await sink.finish() : undefined;
    return {
      descriptor: blobDesc,
      bytes: collected ? concatBytes(...collected) : undefined,
      sinkResult,
    };
  } catch (err) {
    if (sink?.abort) await sink.abort(err).catch(() => {});
    throw err;
  } finally {
    zeroBytes(encKey);
    zeroBytes(blobKey);
  }
}

export async function putPipeChunkWithRetry(client, pipeId, roomToken, partId, txIdx, bytes, deadlineMs, signal) {
  while (true) {
    try {
      await client._signedRequest({
        method: 'PUT',
        path: `/v1/pipe/${pipeId}/parts/${partId}/chunks/${txIdx}`,
        roomToken,
        bodyBytes: bytes,
        isDataPlanePut: true,
        signal,
      });
      return;
    } catch (err) {
      if (err instanceof SyncError && err.code === ErrorCode.ERR_PIPE_PEER_TIMEOUT && Date.now() < deadlineMs) {
        continue;
      }
      throw err;
    }
  }
}

export async function getPipeChunkWithRetry(client, pipeId, roomToken, partId, txIdx, deadlineMs, signal) {
  while (true) {
    try {
      const res = await client._signedRequest({
        method: 'GET',
        path: `/v1/pipe/${pipeId}/parts/${partId}/chunks/${txIdx}`,
        roomToken,
        signal,
      });
      return new Uint8Array(await res.arrayBuffer());
    } catch (err) {
      if (err instanceof SyncError && err.code === ErrorCode.ERR_PIPE_PEER_TIMEOUT && Date.now() < deadlineMs) {
        continue;
      }
      throw err;
    }
  }
}

// ============================================================================
// Flow 1: One-Shot Mode A Streaming Send / Receive
// ============================================================================

export async function startOneShotSendImpl(client, parcel, opts = {}) {
  const caps = await client.capabilities({ signal: opts.signal });
  const blocksPerChunk = caps.streaming.blocks_per_chunk;
  const prep = await prepareParcel(client, parcel, blocksPerChunk);
  const { roomId, pipeId, roomToken, seq: s0, hs } = await runFlow1Initiator(client, {
    purpose: 'oneshot',
    mode: opts.mode ?? 1,
    includeRelay: opts.includeRelay ?? false,
    onOfferReady: opts.onOfferReady,
    onSASInput: opts.onSASInput,
    timeoutMs: opts.timeoutMs,
    preferPoll: opts.preferPoll,
    signal: opts.signal,
  });

  const { part0Key, part0NoncePrefix } = await deriveOneshotPart0Keys(hs.sessionKey, prep.msgIdRaw);
  const { ctrlKey, ctrlNoncePrefix } = await derivePipeCtrlKeys(hs.sessionKey, hs.th);

  try {
    const startFrame = await sealPipeCtrlFrame(ctrlKey, ctrlNoncePrefix, hs.th, 0, {
      op: 'pipe_start',
      msg_id: prep.msgId,
      blocks_per_chunk: blocksPerChunk,
      parts: prep.partsMeta,
    });
    const sent = await postRoomMessage(client, roomId, roomToken, 'control', startFrame, opts.signal);

    const deadlineMs = Date.now() + (opts.timeoutMs ?? DEFAULT_HANDSHAKE_TIMEOUT_MS);
    let bytesDone = 0;
    const emit = (partId, partDone, partTotal) => {
      if (!opts.onProgress) return;
      opts.onProgress({
        type: 'event',
        event: 'transfer_progress',
        stage: 'transferring',
        direction: 'send',
        mode: 'pipe',
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

    // Upload part_id=0 (padded Manifest)
    let p0Done = 0;
    await uploadPartStreaming({
      partId: 0,
      plaintextSize: prep.paddedManifest.length,
      readPlaintextSlice: async (off, len) => prep.paddedManifest.subarray(off, off + len),
      encKey: part0Key,
      noncePrefix: part0NoncePrefix,
      msgIdRaw: prep.msgIdRaw,
      blocksPerChunk,
      putChunkFn: (pid, tx, buf) => putPipeChunkWithRetry(client, pipeId, roomToken, pid, tx, buf, deadlineMs, opts.signal),
      onChunkDone: (_tx, len) => { bytesDone += len; p0Done += len; emit(0, p0Done, prep.partsMeta[0].total_bytes); },
    });

    // Upload blobs part_id=1..N
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
          putChunkFn: (pid, tx, buf) => putPipeChunkWithRetry(client, pipeId, roomToken, pid, tx, buf, deadlineMs, opts.signal),
          onChunkDone: (_tx, len) => { bytesDone += len; pDone += len; emit(partId, pDone, pTotal); },
        });
      } finally {
        zeroBytes(encKey);
        zeroBytes(blobKey);
      }
    }

    // Wait for encrypted pipe_ack (ctrl_seq = 1, odd parity)
    const { msg: ackMsg } = await waitRoomMessage(
      client, roomId, roomToken, Math.max(s0, sent.seq),
      (m) => m.from === 'receiver' && m.kind === 'control',
      { timeoutMs: opts.timeoutMs, preferPoll: opts.preferPoll, signal: opts.signal },
    );
    const ackFrame = JSON.parse(utf8Decode(b64uToBytes(ackMsg.msg_b64)));
    const { payload: ackPayload } = await openPipeCtrlFrame(ctrlKey, ctrlNoncePrefix, hs.th, ackFrame, {
      expectedParity: 1,
      lastSeenSeq: -1,
    });
    if (ackPayload.op !== 'pipe_ack' || ackPayload.msg_id !== prep.msgId) {
      throw new SyncError(ErrorCode.ERR_CRYPTO_DECRYPT_FAILED, 'invalid pipe_ack payload');
    }
    await closeRoom(client, roomId, roomToken, 'completed');
    return { mode: 'pipe', msgId: prep.msgId, totalBytes: prep.declaredTotalBytes };
  } finally {
    zeroBytes(hs.sessionKey);
    zeroBytes(part0Key);
    zeroBytes(ctrlKey);
  }
}

export async function receiveOneShotImpl(client, pairInput, handler, opts = {}) {
  const { roomId, pipeId, roomToken, seq: s0, hs } = await runFlow1Responder(client, pairInput, {
    expectedPurpose: 'oneshot',
    onSASDisplay: opts.onSASDisplay,
    timeoutMs: opts.timeoutMs,
    preferPoll: opts.preferPoll,
    signal: opts.signal,
  });
  const { ctrlKey, ctrlNoncePrefix } = await derivePipeCtrlKeys(hs.sessionKey, hs.th);

  try {
    const { msg: startMsg } = await waitRoomMessage(
      client, roomId, roomToken, s0,
      (m) => m.from === 'sender' && m.kind === 'control',
      { timeoutMs: opts.timeoutMs, preferPoll: opts.preferPoll, signal: opts.signal },
    );
    const startFrame = JSON.parse(utf8Decode(b64uToBytes(startMsg.msg_b64)));
    const { payload: startPayload } = await openPipeCtrlFrame(ctrlKey, ctrlNoncePrefix, hs.th, startFrame, {
      expectedParity: 0,
      lastSeenSeq: -1,
    });
    if (startPayload.op !== 'pipe_start' || !startPayload.msg_id || !Array.isArray(startPayload.parts)) {
      throw new SyncError(ErrorCode.ERR_MANIFEST_INVALID, 'invalid pipe_start control command');
    }

    const msgIdRaw = hexToBytes(startPayload.msg_id);
    const { part0Key, part0NoncePrefix } = await deriveOneshotPart0Keys(hs.sessionKey, msgIdRaw);
    const deadlineMs = Date.now() + (opts.timeoutMs ?? DEFAULT_HANDSHAKE_TIMEOUT_MS);

    const part0Meta = startPayload.parts.find((p) => p.part_id === 0);
    if (!part0Meta) throw new SyncError(ErrorCode.ERR_MANIFEST_INVALID, 'pipe_start missing part_id=0');

    const p0Chunks = [];
    for (let tx = 0; tx < part0Meta.chunk_count; tx++) {
      p0Chunks.push(await getPipeChunkWithRetry(client, pipeId, roomToken, 0, tx, deadlineMs, opts.signal));
    }
    const paddedManifest = await decryptPartBytes(part0Key, part0NoncePrefix, msgIdRaw, 0, p0Chunks);
    const manifestUtf8 = unpadManifest(paddedManifest);
    const manifest = JSON.parse(utf8Decode(manifestUtf8));
    validateManifest(manifest, { expectedMsgId: startPayload.msg_id });

    const blobs = [];
    for (const blobDesc of manifest.blobs) {
      const pm = startPayload.parts.find((p) => p.part_id === blobDesc.part_id);
      if (!pm) throw new SyncError(ErrorCode.ERR_MANIFEST_INVALID, `missing part_id=${blobDesc.part_id} in pipe_start`);
      blobs.push(await downloadBlobStreaming({
        blobDesc,
        chunkCount: pm.chunk_count,
        msgIdRaw,
        getChunkFn: (pid, tx) => getPipeChunkWithRetry(client, pipeId, roomToken, pid, tx, deadlineMs, opts.signal),
        createBlobSink: opts.createBlobSink,
      }));
    }

    await handler({ manifest, blobs });

    const ackFrame = await sealPipeCtrlFrame(ctrlKey, ctrlNoncePrefix, hs.th, 1, {
      op: 'pipe_ack',
      msg_id: startPayload.msg_id,
    });
    await postRoomMessage(client, roomId, roomToken, 'control', ackFrame, opts.signal);
    // Do NOT close room here: sender closes room after reading & verifying pipe_ack (prevents wipe race).
    zeroBytes(part0Key);
    return manifest;
  } finally {
    zeroBytes(hs.sessionKey);
    zeroBytes(ctrlKey);
  }
}

// ============================================================================
// Flow 2: Paired Device 0-RTT Mode A Direct Pipe Send / Receive
// ============================================================================

export async function sendDirectModeAImpl(client, prep, sealed, blocksPerChunk, opts) {
  const roomId = generateRoomId();
  const m1 = {
    proto_v: PROTO_VERSION,
    mode: 0,
    purpose: 'direct',
    sealed_header: sealed.sealedHeaderB64u,
    blocks_per_chunk: blocksPerChunk,
    parts: prep.partsMeta,
  };
  const createRes = await client._signedRequest({
    method: 'POST',
    path: '/v1/rooms',
    jsonBody: { room_id: roomId, ttl_sec: opts.ttlSec ?? 300, initial_msg_b64: bytesToB64u(utf8Encode(JSON.stringify(m1))) },
    signal: opts.signal,
  });
  const room = await createRes.json();
  const roomToken = room.sender_token;
  const pipeId = room.pipe_id;
  const pairUri = formatPairURI({
    roomId,
    mode: 0,
    purpose: 'direct',
    relayOrigin: opts.includeRelay ? client.relay.origin : null,
    spkiPin: opts.includeRelay ? client.relay.spkiPin : null,
    accessKey: opts.includeRelay ? client.relay.accessKey : null,
    expiresAt: room.expires_at,
  });

  if (opts.onOfferReady) {
    await opts.onOfferReady({
      roomId,
      formattedRoomId: formatRoomId(roomId),
      pairUri,
      mode: 0,
      purpose: 'direct',
      expiresAt: room.expires_at,
    });
  }

  const deadlineMs = Date.now() + (opts.timeoutMs ?? DEFAULT_HANDSHAKE_TIMEOUT_MS);
  await uploadPartStreaming({
    partId: 0,
    plaintextSize: prep.paddedManifest.length,
    readPlaintextSlice: async (off, len) => prep.paddedManifest.subarray(off, off + len),
    encKey: sealed.part0Key,
    noncePrefix: sealed.part0NoncePrefix,
    msgIdRaw: prep.msgIdRaw,
    blocksPerChunk,
    putChunkFn: (pid, tx, buf) => putPipeChunkWithRetry(client, pipeId, roomToken, pid, tx, buf, deadlineMs, opts.signal),
  });

  for (const { partId, blobKey, input } of prep.blobSecrets) {
    const { encKey, noncePrefix } = await deriveBlobPartKeys(blobKey, prep.msgIdRaw, partId);
    try {
      await uploadPartStreaming({
        partId,
        plaintextSize: input.size,
        readPlaintextSlice: (off, len) => input.readSlice(off, len),
        encKey,
        noncePrefix,
        msgIdRaw: prep.msgIdRaw,
        blocksPerChunk,
        putChunkFn: (pid, tx, buf) => putPipeChunkWithRetry(client, pipeId, roomToken, pid, tx, buf, deadlineMs, opts.signal),
      });
    } finally {
      zeroBytes(encKey);
      zeroBytes(blobKey);
    }
  }

  const { msg: ackMsg } = await waitRoomMessage(
    client, roomId, roomToken, room.seq ?? 1,
    (m) => m.from === 'receiver' && m.kind === 'control',
    { timeoutMs: opts.timeoutMs, preferPoll: opts.preferPoll, signal: opts.signal },
  );
  const ackPayload = JSON.parse(utf8Decode(b64uToBytes(ackMsg.msg_b64)));
  if (ackPayload.op !== 'pipe_ack' || ackPayload.msg_id !== prep.msgId || typeof ackPayload.ack_mac !== 'string') {
    throw new SyncError(ErrorCode.ERR_CRYPTO_SIGNATURE_INVALID, 'malformed Flow 2 direct pipe_ack');
  }
  const ok = await verifyDirectAckMac(sealed.part0Key, prep.msgIdRaw, b64uToBytes(ackPayload.ack_mac));
  if (!ok) {
    await closeRoom(client, roomId, roomToken, 'verify_failed');
    throw new SyncError(ErrorCode.ERR_CRYPTO_SIGNATURE_INVALID, 'Flow 2 direct ack_mac verification failed');
  }
  await closeRoom(client, roomId, roomToken, 'completed');
  return { mode: 'pipe', roomId, msgId: prep.msgId, totalBytes: prep.declaredTotalBytes };
}

/**
 * Receive Flow 2 Mode A Direct Transfer (m=0&p=direct, spec/CRYPTO_AND_AUTH.md §5.4).
 */
export async function receiveDirectImpl(client, pairInput, handler, opts = {}) {
  const roomId = typeof pairInput === 'string' && pairInput.startsWith('synctool://pair')
    ? parsePairURI(pairInput).roomId
    : normalizeRoomId(pairInput);

  const joinRes = await client._signedRequest({
    method: 'POST',
    path: `/v1/rooms/${roomId}/join`,
    jsonBody: {},
    signal: opts.signal,
  });
  const joined = await joinRes.json();
  const roomToken = joined.receiver_token;
  const pipeId = joined.pipe_id;
  const m1Msg = (joined.messages || []).find((m) => m.from === 'sender' && m.kind === 'handshake');
  if (!m1Msg) {
    await closeRoom(client, roomId, roomToken, 'verify_failed');
    throw new SyncError(ErrorCode.ERR_CRYPTO_HANDSHAKE_FAILED, 'direct room missing initial M1');
  }
  const m1 = JSON.parse(utf8Decode(b64uToBytes(m1Msg.msg_b64)));
  if (m1.proto_v !== PROTO_VERSION || m1.mode !== 0 || m1.purpose !== 'direct' || !m1.sealed_header || !Array.isArray(m1.parts)) {
    await closeRoom(client, roomId, roomToken, 'verify_failed');
    throw new SyncError(ErrorCode.ERR_CRYPTO_HANDSHAKE_FAILED, 'invalid direct M1 payload');
  }

  const selfId = await client.getIdentity();
  let header;
  try {
    header = await openPaired0RTTHeader({
      sealedHeader: m1.sealed_header,
      recipientKemSk: selfId.kemSk,
      recipientDeviceIdRaw: selfId.deviceIdRaw,
      hasSeenMsgId: (id) => client.keyStore.hasSeenMsgID(id),
      lookupSenderCard: (id) => client.keyStore.getDevice(id),
    });
  } catch (err) {
    await closeRoom(client, roomId, roomToken, 'verify_failed');
    throw err;
  }

  try {
    const deadlineMs = Date.now() + (opts.timeoutMs ?? DEFAULT_HANDSHAKE_TIMEOUT_MS);
    const part0Meta = m1.parts.find((p) => p.part_id === 0);
    if (!part0Meta) throw new SyncError(ErrorCode.ERR_MANIFEST_INVALID, 'direct M1 missing part_id=0');

    const p0Chunks = [];
    for (let tx = 0; tx < part0Meta.chunk_count; tx++) {
      p0Chunks.push(await getPipeChunkWithRetry(client, pipeId, roomToken, 0, tx, deadlineMs, opts.signal));
    }
    const paddedManifest = await decryptPartBytes(header.part0Key, header.part0NoncePrefix, header.msgIdRaw, 0, p0Chunks);
    const manifestUtf8 = unpadManifest(paddedManifest);
    const actualManifestSha = await sha256(manifestUtf8);
    if (!constantTimeEqual(actualManifestSha, header.manifestSha256)) {
      throw new SyncError(ErrorCode.ERR_HASH_MISMATCH, 'manifest SHA-256 does not match SealedHeader');
    }
    const manifest = JSON.parse(utf8Decode(manifestUtf8));
    validateManifest(manifest, { expectedMsgId: header.msgId });
    if (manifest.sender.device_id !== header.senderDeviceId || manifest.created_at !== header.createdAt) {
      throw new SyncError(ErrorCode.ERR_CRYPTO_SIGNATURE_INVALID, 'manifest sender/created_at mismatch with SealedHeader');
    }

    const blobs = [];
    for (const blobDesc of manifest.blobs) {
      const pm = m1.parts.find((p) => p.part_id === blobDesc.part_id);
      if (!pm) throw new SyncError(ErrorCode.ERR_MANIFEST_INVALID, `missing part_id=${blobDesc.part_id}`);
      blobs.push(await downloadBlobStreaming({
        blobDesc,
        chunkCount: pm.chunk_count,
        msgIdRaw: header.msgIdRaw,
        getChunkFn: (pid, tx) => getPipeChunkWithRetry(client, pipeId, roomToken, pid, tx, deadlineMs, opts.signal),
        createBlobSink: opts.createBlobSink,
      }));
    }

    await handler({ manifest, senderCard: header.senderCard, blobs });
    await client.keyStore.markSeenMsgID(header.msgId, header.createdAt);

    const ackMac = await computeDirectAckMac(header.part0Key, header.msgIdRaw);
    await postRoomMessage(client, roomId, roomToken, 'control', {
      op: 'pipe_ack',
      msg_id: header.msgId,
      ack_mac: bytesToB64u(ackMac),
    }, opts.signal);
    // Do NOT close room here: sender closes room after verifying ack_mac (prevents wipe race).
    return manifest;
  } finally {
    zeroBytes(header.part0Key);
  }
}
