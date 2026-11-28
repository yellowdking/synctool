@file:OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)

package com.yellowdking.synctool.client

import com.yellowdking.synctool.crypto.Handshake
import com.yellowdking.synctool.envelope.Manifest
import com.yellowdking.synctool.envelope.PartLayout
import com.yellowdking.synctool.envelope.RelayCertExpiringEvent
import com.yellowdking.synctool.envelope.RelayProfile
import com.yellowdking.synctool.envelope.TransferEvent
import com.yellowdking.synctool.envelope.KeyStore
import com.yellowdking.synctool.envelope.MemoryKeyStore
import java.io.File
import kotlinx.serialization.EncodeDefault
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

data class SyncClientConfig(
    val relay: RelayProfile,
    val keyStore: KeyStore = MemoryKeyStore(),
    val appId: String = "synctool.sdk",
    val deviceLabel: String = "",
    val platform: String = defaultPlatform(),
    val tempDir: File? = null,
    val onCertExpiring: ((RelayCertExpiringEvent) -> Unit)? = null,
) {
    companion object {
        fun defaultPlatform(): String {
            val vm = System.getProperty("java.vm.name").orEmpty().lowercase()
            if ("dalvik" in vm || "art" in vm) return "android"
            val os = System.getProperty("os.name").orEmpty().lowercase()
            return when {
                "win" in os -> "windows"
                "mac" in os || "darwin" in os -> "macos"
                "linux" in os -> "linux"
                else -> "unknown"
            }
        }
    }
}

data class DeviceIdentity(
    val deviceId: String,
    val label: String,
    val signPkB64u: String,
    val kemPkB64u: String,
    val mailboxId: String,
    val relayId: String,
)

@Serializable
data class PingResult(
    @SerialName("proto_v") val protoV: Int = 1,
    @SerialName("min_proto_v") val minProtoV: Int = 1,
    @SerialName("max_proto_v") val maxProtoV: Int = 1,
    @SerialName("server_version") val serverVersion: String = "",
    @SerialName("server_ts") val serverTs: Long = 0L,
    val profile: String = "",
    @SerialName("spool_backend") val spoolBackend: String = "",
    @SerialName("cert_expires_at") val certExpiresAt: Long = 0L,
    @SerialName("cert_rotate_recommended") val certRotateRecommended: Boolean = false,
    @SerialName("rtt_ms") val rttMs: Long = 0L,
    @SerialName("clock_offset_sec") val clockOffsetSec: Long = 0L,
)

@Serializable
data class StreamingCaps(
    val enabled: Boolean = true,
    @SerialName("blocks_per_chunk") val blocksPerChunk: Int = 16,
    @SerialName("max_transport_chunk_bytes") val maxTransportChunkBytes: Int = 1048832,
    @SerialName("recommended_parallel_chunks") val recommendedParallelChunks: Int = 1,
    @SerialName("max_parallel_chunks") val maxParallelChunks: Int = 3,
    @SerialName("rendezvous_timeout_sec") val rendezvousTimeoutSec: Int = 30,
    @SerialName("room_ttl_max_sec") val roomTtlMaxSec: Int = 600,
)

@Serializable
data class SpoolCaps(
    val enabled: Boolean = false,
    val backend: String = "off",
    @SerialName("max_item_bytes") val maxItemBytes: Long = 0L,
    @SerialName("max_mailbox_bytes") val maxMailboxBytes: Long = 0L,
    @SerialName("max_total_bytes") val maxTotalBytes: Long = 0L,
    @SerialName("max_items_per_mailbox") val maxItemsPerMailbox: Int = 0,
    @SerialName("default_ttl_sec") val defaultTtlSec: Int = 0,
    @SerialName("max_ttl_sec") val maxTtlSec: Int = 0,
    @SerialName("uncommitted_ttl_sec") val uncommittedTtlSec: Int = 0,
    @SerialName("max_manifest_downloads") val maxManifestDownloads: Int = 0,
    @SerialName("max_downloads_per_chunk") val maxDownloadsPerChunk: Int = 0,
    @SerialName("max_deposit_tokens_per_mailbox") val maxDepositTokensPerMailbox: Int = 0,
)

@Serializable
data class RelayCaps(
    @SerialName("proto_v") val protoV: Int = 1,
    @SerialName("min_proto_v") val minProtoV: Int = 1,
    @SerialName("max_proto_v") val maxProtoV: Int = 1,
    @SerialName("server_version") val serverVersion: String = "",
    val features: List<String> = emptyList(),
    val profile: String = "standard",
    @SerialName("server_ts") val serverTs: Long = 0L,
    @SerialName("cert_expires_at") val certExpiresAt: Long = 0L,
    @SerialName("cert_rotate_recommended") val certRotateRecommended: Boolean = false,
    @SerialName("crypto_plaintext_block_bytes") val cryptoPlaintextBlockBytes: Int = 65536,
    @SerialName("crypto_block_bytes") val cryptoBlockBytes: Int = 65552,
    val streaming: StreamingCaps = StreamingCaps(),
    val spool: SpoolCaps = SpoolCaps(),
)

@Serializable
data class MailboxRegisterResponse(
    @SerialName("mailbox_id") val mailboxId: String,
    val registered: Boolean = true,
    @SerialName("deposit_token_count") val depositTokenCount: Int = 0,
)

@Serializable
data class InboxItemMeta(
    @SerialName("item_id") val itemId: String,
    @SerialName("created_at") val createdAt: Long,
    @SerialName("expires_at") val expiresAt: Long,
    @SerialName("total_bytes") val totalBytes: Long,
    @SerialName("sealed_header") val sealedHeader: String,
    val parts: List<PartLayout> = emptyList(),
)

data class InboxPreview(
    val itemId: String,
    val createdAt: Long,
    val expiresAt: Long,
    val totalBytes: Long,
    val cached: Boolean,
    val manifest: Manifest,
)

@Serializable
data class InboxWatchEvent(
    @SerialName("item_id") val itemId: String,
    @SerialName("total_bytes") val totalBytes: Long = 0L,
    @SerialName("created_at") val createdAt: Long = 0L,
    @SerialName("expires_at") val expiresAt: Long = 0L,
)

@Serializable
data class SendResult(
    val mode: String,
    @SerialName("msg_id") val msgId: String,
    @SerialName("item_id") val itemId: String = "",
    @SerialName("room_id") val roomId: String = "",
    @SerialName("total_bytes") val totalBytes: Long,
    @SerialName("expires_at") val expiresAt: Long = 0L,
)

data class OfferReadyInfo(
    val roomId: String,
    val displayCode: String,
    val mode: Int,
    val purpose: String,
    val pairUri: String,
    val expiresAt: Long,
)

object DeliveryMode {
    const val AUTO: String = "auto"
    const val SPOOL: String = "spool"
    const val PIPE: String = "pipe"
}

data class PairOptions(
    val mode: Int = Handshake.MODE_QR_OOB,
    val label: String = "",
    val includeRelay: Boolean = false,
    val ttlSec: Int = 300,
    val onOfferReady: (suspend (OfferReadyInfo) -> Unit)? = null,
    val onSASInput: (suspend () -> String)? = null,
    val onSASDisplay: ((sas: String) -> Unit)? = null,
    /**
     * Mandatory on Responder when mode == 2 (commit_sas_x25519).
     * Fails closed (`closeRoom(..., "verify_failed")` + `ERR_SAS_MISMATCH`) if null or returns false.
     */
    val onSASConfirm: (suspend (sas: String) -> Boolean)? = null,
    val onProgress: ((TransferEvent) -> Unit)? = null,
)

data class SendOptions(
    val deliveryMode: String = DeliveryMode.AUTO,
    val ttlSec: Int = 0,
    val includeRelay: Boolean = false,
    val onOfferReady: (suspend (OfferReadyInfo) -> Unit)? = null,
    val onProgress: ((TransferEvent) -> Unit)? = null,
)

data class ReceiveOptions(
    val onSASDisplay: ((sas: String) -> Unit)? = null,
    /**
     * Mandatory on Responder when mode == 2 (commit_sas_x25519).
     * Fails closed (`closeRoom(..., "verify_failed")` + `ERR_SAS_MISMATCH`) if null or returns false.
     */
    val onSASConfirm: (suspend (sas: String) -> Boolean)? = null,
    val onProgress: ((TransferEvent) -> Unit)? = null,
    val appId: String? = null,
    val autoAck: Boolean = true,
)

// Internal wire DTOs for room signaling and spool APIs

@Serializable
internal data class HsM1Wire(
    @EncodeDefault(EncodeDefault.Mode.ALWAYS)
    @SerialName("proto_v") val protoV: Int = 1,
    @EncodeDefault(EncodeDefault.Mode.ALWAYS)
    val mode: Int,
    @EncodeDefault(EncodeDefault.Mode.ALWAYS)
    val purpose: String,
    @SerialName("e_a") val eA: String? = null,
    @SerialName("n_a") val nA: String? = null,
    @SerialName("commit_a") val commitA: String? = null,
)

@Serializable
internal data class HsM2Wire(
    @EncodeDefault(EncodeDefault.Mode.ALWAYS)
    @SerialName("proto_v") val protoV: Int = 1,
    @EncodeDefault(EncodeDefault.Mode.ALWAYS)
    val mode: Int,
    @SerialName("e_b") val eB: String,
    @SerialName("n_b") val nB: String,
    @SerialName("mac_b") val macB: String? = null,
)

@Serializable
internal data class HsM3Wire(
    @EncodeDefault(EncodeDefault.Mode.ALWAYS)
    @SerialName("proto_v") val protoV: Int = 1,
    @EncodeDefault(EncodeDefault.Mode.ALWAYS)
    val mode: Int,
    @SerialName("e_a") val eA: String? = null,
    @SerialName("n_a") val nA: String? = null,
    @SerialName("mac_a") val macA: String,
)

@Serializable
internal data class HsM4Wire(
    @EncodeDefault(EncodeDefault.Mode.ALWAYS)
    @SerialName("proto_v") val protoV: Int = 1,
    @EncodeDefault(EncodeDefault.Mode.ALWAYS)
    val mode: Int,
    @SerialName("mac_b") val macB: String,
)

@Serializable
internal data class PairBindWire(
    @EncodeDefault(EncodeDefault.Mode.ALWAYS)
    @SerialName("proto_v") val protoV: Int = 1,
    @EncodeDefault(EncodeDefault.Mode.ALWAYS)
    val op: String = "pair_bind",
    val ct: String,
)

@Serializable
internal data class PipeCtrlWire(
    @EncodeDefault(EncodeDefault.Mode.ALWAYS)
    @SerialName("ctrl_seq") val ctrlSeq: Long,
    val ct: String,
)

@Serializable
internal data class RoomCreateReq(
    @SerialName("room_id") val roomId: String,
    @SerialName("ttl_sec") val ttlSec: Int,
    @SerialName("initial_msg_b64") val initialMsgB64: String? = null,
)

@Serializable
internal data class RoomCreateResp(
    @SerialName("room_id") val roomId: String,
    @SerialName("pipe_id") val pipeId: String,
    @SerialName("sender_token") val senderToken: String,
    @SerialName("expires_at") val expiresAt: Long,
    val seq: Int = 0,
)

@Serializable
internal data class RoomMessageWire(
    val seq: Int = 0,
    val from: String = "",
    val kind: String = "",
    @SerialName("msg_b64") val msgB64: String = "",
)

@Serializable
internal data class RoomJoinResp(
    @SerialName("room_id") val roomId: String,
    @SerialName("pipe_id") val pipeId: String,
    @SerialName("receiver_token") val receiverToken: String,
    @SerialName("expires_at") val expiresAt: Long,
    val seq: Int = 0,
    val messages: List<RoomMessageWire> = emptyList(),
)

@Serializable
internal data class RoomPostMsgReq(
    val kind: String,
    @SerialName("msg_b64") val msgB64: String,
)

@Serializable
internal data class RoomPostMsgResp(
    val seq: Int = 0,
)

@Serializable
internal data class RoomPollResp(
    val state: String = "",
    val seq: Int = 0,
    val messages: List<RoomMessageWire> = emptyList(),
    val reason: String = "",
)

@Serializable
internal data class RoomCloseReq(
    val reason: String,
)

@Serializable
internal data class MailboxDepositTokenSpec(
    @SerialName("token_id") val tokenId: String,
    @SerialName("token_hash_hex") val tokenHashHex: String,
)

@Serializable
internal data class MailboxPutReq(
    @SerialName("auth_pk_b64") val authPkB64: String,
    @SerialName("deposit_tokens") val depositTokens: List<MailboxDepositTokenSpec>? = null,
)

@Serializable
internal data class SpoolInitReq(
    @SerialName("mailbox_id") val mailboxId: String,
    @SerialName("declared_total_bytes") val declaredTotalBytes: Long,
    @SerialName("ttl_sec") val ttlSec: Int = 0,
    @SerialName("sealed_header") val sealedHeader: String,
    @EncodeDefault(EncodeDefault.Mode.ALWAYS)
    val parts: List<PartLayout>,
)

@Serializable
internal data class SpoolInitResp(
    @SerialName("item_id") val itemId: String,
    @SerialName("upload_token") val uploadToken: String,
    @SerialName("max_transport_chunk_bytes") val maxTransportChunkBytes: Int = 0,
    @SerialName("upload_expires_at") val uploadExpiresAt: Long = 0L,
    @SerialName("expires_at") val expiresAt: Long = 0L,
)

@Serializable
internal data class SpoolCommitResp(
    @SerialName("item_id") val itemId: String = "",
    val committed: Boolean = true,
    @SerialName("expires_at") val expiresAt: Long = 0L,
)

@Serializable
internal data class MailboxItemsResp(
    val items: List<InboxItemMeta> = emptyList(),
)

@Serializable
internal data class MailboxPollResp(
    val items: List<InboxWatchEvent> = emptyList(),
    @SerialName("server_ts") val serverTs: Long = 0L,
)

@Serializable
internal data class RoomM1Probe(
    @SerialName("proto_v") val protoV: Int = 0,
    val mode: Int = -1,
    val purpose: String = "",
)
