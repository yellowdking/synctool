@file:OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)

package com.yellowdking.synctool.envelope

import com.yellowdking.synctool.crypto.KeysAndAuth
import com.yellowdking.synctool.crypto.StreamCipher
import java.nio.charset.StandardCharsets
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.EncodeDefault
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

const val DEFAULT_SEEN_MSG_RETENTION_DAYS: Long = 30L
const val DEFAULT_SEEN_MSG_MIN_ENTRIES: Int = 4096

@Serializable
data class DeviceCard(
    @SerialName("device_id") val deviceId: String,
    val label: String,
    val platform: String = "",
    @SerialName("sign_pk") val signPk: String,
    @SerialName("kem_pk") val kemPk: String,
    @SerialName("issued_at") val issuedAt: Long,
    @SerialName("card_sig") val cardSig: String,
    @SerialName("relay_origin") val relayOrigin: String = "",
    @SerialName("relay_id") val relayId: String = "",
    @SerialName("mailbox_id") val mailboxId: String = "",
    @SerialName("outbound_deposit_token") val outboundDepositToken: String = "",
    @SerialName("inbound_token_id") val inboundTokenId: String = "",
    @SerialName("inbound_token_hash") val inboundTokenHash: String = "",
    @SerialName("paired_at") val pairedAt: Long = 0L,
    @EncodeDefault(EncodeDefault.Mode.ALWAYS)
    val revoked: Boolean = false,
    @SerialName("pending_token_delete") val pendingTokenDelete: Boolean = false,
) {
    override fun toString(): String {
        return "DeviceCard(deviceId=$deviceId, label=$label, platform=$platform, relayId=$relayId, mailboxId=$mailboxId, revoked=$revoked, pendingTokenDelete=$pendingTokenDelete, outboundDepositToken=[REDACTED])"
    }
}

@Serializable
data class SeenMsgEntry(
    @SerialName("msg_id") val msgId: String,
    @SerialName("created_at") val createdAt: Long,
    @SerialName("seen_at") val seenAt: Long,
)

@Serializable
data class CachedManifestEntry(
    @SerialName("item_id") val itemId: String,
    @SerialName("cached_at") val cachedAt: Long,
    @SerialName("expires_at") val expiresAt: Long,
    @SerialName("manifest_sha256") val manifestSha256: String = "",
    val manifest: Manifest,
)

@Serializable
data class TransferCheckpoint(
    val key: String = "",
    val direction: String,
    @SerialName("msg_id") val msgId: String,
    @SerialName("item_id") val itemId: String = "",
    @SerialName("part_id") val partId: Int,
    @SerialName("next_tx_idx") val nextTxIdx: Int,
    @SerialName("next_block_idx") val nextBlockIdx: Long,
    @SerialName("upload_token") val uploadToken: String = "",
    @SerialName("expires_at") val expiresAt: Long = 0L,
) {
    companion object {
        fun buildKey(direction: String, msgId: String, partId: Int): String {
            return "$direction:${msgId.lowercase()}:$partId"
        }
    }
}

/**
 * Helper codec sealing/opening local cache entries (`CachedManifestEntry`, `TransferCheckpoint`)
 * with the device's HKDF-derived 32-byte `local_meta_key` via AES-256-GCM.
 */
object LocalMetaCacheCodec {
    fun sealCachedManifest(localMetaKey32: ByteArray, entry: CachedManifestEntry): String {
        val aad = "synctool-v1/manifest-cache:${entry.itemId}".toByteArray(StandardCharsets.UTF_8)
        val raw = ManifestCodec.json.encodeToString(CachedManifestEntry.serializer(), entry)
            .toByteArray(StandardCharsets.UTF_8)
        return try {
            KeysAndAuth.b64uEncode(StreamCipher.sealLocalMeta(localMetaKey32, aad, raw))
        } finally {
            KeysAndAuth.zeroBytes(raw)
        }
    }

    fun openCachedManifest(localMetaKey32: ByteArray, itemId: String, sealedB64u: String): CachedManifestEntry? {
        return try {
            val aad = "synctool-v1/manifest-cache:$itemId".toByteArray(StandardCharsets.UTF_8)
            val blob = KeysAndAuth.b64uDecode(sealedB64u)
            val raw = StreamCipher.openLocalMeta(localMetaKey32, aad, blob)
            try {
                ManifestCodec.json.decodeFromString(
                    CachedManifestEntry.serializer(),
                    String(raw, StandardCharsets.UTF_8),
                )
            } finally {
                KeysAndAuth.zeroBytes(raw)
            }
        } catch (_: Exception) {
            null
        }
    }

    fun sealCheckpoint(localMetaKey32: ByteArray, cp: TransferCheckpoint): String {
        val key = cp.key.ifEmpty { TransferCheckpoint.buildKey(cp.direction, cp.msgId, cp.partId) }
        val normalized = cp.copy(key = key)
        val aad = "synctool-v1/checkpoint:$key".toByteArray(StandardCharsets.UTF_8)
        val raw = ManifestCodec.json.encodeToString(TransferCheckpoint.serializer(), normalized)
            .toByteArray(StandardCharsets.UTF_8)
        return try {
            KeysAndAuth.b64uEncode(StreamCipher.sealLocalMeta(localMetaKey32, aad, raw))
        } finally {
            KeysAndAuth.zeroBytes(raw)
        }
    }

    fun openCheckpoint(localMetaKey32: ByteArray, key: String, sealedB64u: String): TransferCheckpoint? {
        return try {
            val aad = "synctool-v1/checkpoint:$key".toByteArray(StandardCharsets.UTF_8)
            val blob = KeysAndAuth.b64uDecode(sealedB64u)
            val raw = StreamCipher.openLocalMeta(localMetaKey32, aad, blob)
            try {
                ManifestCodec.json.decodeFromString(
                    TransferCheckpoint.serializer(),
                    String(raw, StandardCharsets.UTF_8),
                )
            } finally {
                KeysAndAuth.zeroBytes(raw)
            }
        } catch (_: Exception) {
            null
        }
    }
}

interface KeyStore {
    suspend fun loadOrCreateMasterSeed(): ByteArray
    suspend fun getLocalLabel(): String? = null
    suspend fun setLocalLabel(label: String) {}

    suspend fun getRelayProfile(relayIdOrAlias: String): RelayProfile?
    suspend fun getDefaultRelayProfile(): RelayProfile?
    suspend fun listRelayProfiles(): List<RelayProfile>
    suspend fun saveRelayProfile(profile: RelayProfile)

    suspend fun listDevices(): List<DeviceCard>
    suspend fun listAllDevices(): List<DeviceCard> = listDevices()
    suspend fun getDevice(deviceId: String): DeviceCard?
    suspend fun putDevice(card: DeviceCard)
    suspend fun deleteDevice(deviceId: String)

    suspend fun addPendingTokenDelete(tokenId: String) {}
    suspend fun listPendingTokenDeletes(): List<String> = emptyList()
    suspend fun removePendingTokenDelete(tokenId: String) {}

    suspend fun hasSeenMsgId(msgId: String): Boolean
    suspend fun markSeenMsgId(msgId: String, createdAt: Long, seenAt: Long)
    suspend fun getReplayWatermark(): Long = 0L

    suspend fun getCachedManifest(itemId: String): CachedManifestEntry?
    suspend fun putCachedManifest(entry: CachedManifestEntry)
    suspend fun deleteCachedManifest(itemId: String)
    suspend fun pruneCachedManifests(activeItemIds: Set<String>)

    suspend fun getCheckpoint(direction: String, msgId: String, partId: Int): TransferCheckpoint?
    suspend fun putCheckpoint(cp: TransferCheckpoint)
    suspend fun deleteCheckpoint(direction: String, msgId: String, partId: Int)
}

/**
 * Coroutine-safe in-memory KeyStore implementation that seals cached manifests and checkpoints
 * with the derived 32B `LocalMetaKey` (AES-256-GCM) and tracks `replayWatermark` across rolling evictions.
 */
class MemoryKeyStore(initialSeed: ByteArray? = null) : KeyStore {
    private val mutex = Mutex()
    private var masterSeed: ByteArray? = initialSeed?.also {
        require(it.size == KeysAndAuth.MASTER_SEED_SIZE) { "initialSeed must be 32 bytes" }
    }?.copyOf()
    private var localMetaKey: ByteArray? = masterSeed?.let { seed ->
        val dk = KeysAndAuth.deriveDeviceKeys(seed)
        val meta = dk.localMetaKey.copyOf()
        dk.zero()
        meta
    }
    private var localLabel: String? = null
    private val relays = LinkedHashMap<String, RelayProfile>()
    private val devices = LinkedHashMap<String, DeviceCard>()
    private val pendingTokenDeletes = LinkedHashSet<String>()
    private val seenMsgs = LinkedHashMap<String, SeenMsgEntry>()
    private var replayWatermarkTs: Long = 0L
    private val sealedManifestCache = LinkedHashMap<String, String>()
    private val sealedCheckpoints = LinkedHashMap<String, String>()

    private fun ensureMetaKeyLocked(): ByteArray {
        localMetaKey?.let { return it }
        val seed = masterSeed ?: KeysAndAuth.generateMasterSeed().also { masterSeed = it }
        val dk = KeysAndAuth.deriveDeviceKeys(seed)
        val meta = dk.localMetaKey.copyOf()
        dk.zero()
        localMetaKey = meta
        return meta
    }

    override suspend fun loadOrCreateMasterSeed(): ByteArray = mutex.withLock {
        val existing = masterSeed
        if (existing != null) {
            return@withLock existing.copyOf()
        }
        val generated = KeysAndAuth.generateMasterSeed()
        masterSeed = generated.copyOf()
        ensureMetaKeyLocked()
        generated
    }

    override suspend fun getLocalLabel(): String? = mutex.withLock { localLabel }

    override suspend fun setLocalLabel(label: String) = mutex.withLock {
        localLabel = label.trim()
    }

    override suspend fun getRelayProfile(relayIdOrAlias: String): RelayProfile? = mutex.withLock {
        relays[relayIdOrAlias]?.let { return@withLock it }
        relays.values.firstOrNull { it.alias.isNotEmpty() && it.alias.equals(relayIdOrAlias, ignoreCase = true) }
    }

    override suspend fun getDefaultRelayProfile(): RelayProfile? = mutex.withLock {
        relays.values.firstOrNull { it.isDefault } ?: relays.values.minByOrNull { it.relayId }
    }

    override suspend fun listRelayProfiles(): List<RelayProfile> = mutex.withLock {
        relays.values.sortedBy { it.relayId }
    }

    override suspend fun saveRelayProfile(profile: RelayProfile) = mutex.withLock {
        val makeDefault = profile.isDefault || relays.isEmpty()
        val updated = if (makeDefault) profile.copy(isDefault = true) else profile
        if (makeDefault) {
            for ((id, existing) in relays.entries.toList()) {
                if (id != updated.relayId && existing.isDefault) {
                    relays[id] = existing.copy(isDefault = false)
                }
            }
        }
        relays[updated.relayId] = updated
    }

    override suspend fun listDevices(): List<DeviceCard> = mutex.withLock {
        devices.values.filter { !it.revoked }.sortedBy { it.pairedAt }
    }

    override suspend fun listAllDevices(): List<DeviceCard> = mutex.withLock {
        devices.values.sortedBy { it.pairedAt }
    }

    override suspend fun getDevice(deviceId: String): DeviceCard? = mutex.withLock {
        devices[deviceId.trim().lowercase()]
    }

    override suspend fun putDevice(card: DeviceCard) = mutex.withLock {
        val cleanId = card.deviceId.trim().lowercase()
        devices[cleanId] = card.copy(deviceId = cleanId)
    }

    override suspend fun deleteDevice(deviceId: String): Unit = mutex.withLock {
        devices.remove(deviceId.trim().lowercase())
        Unit
    }

    override suspend fun addPendingTokenDelete(tokenId: String): Unit = mutex.withLock {
        val clean = tokenId.trim()
        if (clean.isNotEmpty()) {
            pendingTokenDeletes.add(clean)
        }
        Unit
    }

    override suspend fun listPendingTokenDeletes(): List<String> = mutex.withLock {
        pendingTokenDeletes.toList()
    }

    override suspend fun removePendingTokenDelete(tokenId: String): Unit = mutex.withLock {
        pendingTokenDeletes.remove(tokenId.trim())
        Unit
    }

    override suspend fun hasSeenMsgId(msgId: String): Boolean = mutex.withLock {
        seenMsgs.containsKey(msgId.trim().lowercase())
    }

    override suspend fun markSeenMsgId(msgId: String, createdAt: Long, seenAt: Long) = mutex.withLock {
        val id = msgId.trim().lowercase()
        seenMsgs[id] = SeenMsgEntry(msgId = id, createdAt = createdAt, seenAt = seenAt)
        if (seenMsgs.size > DEFAULT_SEEN_MSG_MIN_ENTRIES) {
            val nowSec = System.currentTimeMillis() / 1000L
            val cutoff = nowSec - DEFAULT_SEEN_MSG_RETENTION_DAYS * 86_400L
            val sorted = seenMsgs.values.sortedBy { it.seenAt }
            for (entry in sorted) {
                if (seenMsgs.size <= DEFAULT_SEEN_MSG_MIN_ENTRIES) break
                if (entry.seenAt < cutoff) {
                    seenMsgs.remove(entry.msgId)
                    if (entry.createdAt > replayWatermarkTs) {
                        replayWatermarkTs = entry.createdAt
                    }
                }
            }
        }
    }

    override suspend fun getReplayWatermark(): Long = mutex.withLock { replayWatermarkTs }

    override suspend fun getCachedManifest(itemId: String): CachedManifestEntry? = mutex.withLock {
        val sealed = sealedManifestCache[itemId] ?: return@withLock null
        val metaKey = ensureMetaKeyLocked()
        val opened = LocalMetaCacheCodec.openCachedManifest(metaKey, itemId, sealed)
        if (opened == null) {
            sealedManifestCache.remove(itemId)
        }
        opened
    }

    override suspend fun putCachedManifest(entry: CachedManifestEntry) = mutex.withLock {
        val metaKey = ensureMetaKeyLocked()
        sealedManifestCache[entry.itemId] = LocalMetaCacheCodec.sealCachedManifest(metaKey, entry)
    }

    override suspend fun deleteCachedManifest(itemId: String): Unit = mutex.withLock {
        sealedManifestCache.remove(itemId)
        Unit
    }

    override suspend fun pruneCachedManifests(activeItemIds: Set<String>) = mutex.withLock {
        val toRemove = sealedManifestCache.keys.filter { it !in activeItemIds }
        for (id in toRemove) {
            sealedManifestCache.remove(id)
        }
    }

    override suspend fun getCheckpoint(direction: String, msgId: String, partId: Int): TransferCheckpoint? = mutex.withLock {
        val k = TransferCheckpoint.buildKey(direction, msgId, partId)
        val sealed = sealedCheckpoints[k] ?: return@withLock null
        val metaKey = ensureMetaKeyLocked()
        val cp = LocalMetaCacheCodec.openCheckpoint(metaKey, k, sealed)
        val nowSec = System.currentTimeMillis() / 1000L
        if (cp == null || (cp.expiresAt > 0L && cp.expiresAt < nowSec)) {
            sealedCheckpoints.remove(k)
            return@withLock null
        }
        cp
    }

    override suspend fun putCheckpoint(cp: TransferCheckpoint) = mutex.withLock {
        val k = TransferCheckpoint.buildKey(cp.direction, cp.msgId, cp.partId)
        val metaKey = ensureMetaKeyLocked()
        sealedCheckpoints[k] = LocalMetaCacheCodec.sealCheckpoint(metaKey, cp.copy(key = k))
    }

    override suspend fun deleteCheckpoint(direction: String, msgId: String, partId: Int): Unit = mutex.withLock {
        val k = TransferCheckpoint.buildKey(direction, msgId, partId)
        sealedCheckpoints.remove(k)
        Unit
    }
}
