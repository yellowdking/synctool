# `synctool` v1 通用密文信封、URI、错误码与跨端 SDK 冻结规范

- **文档路径**：`spec/ENVELOPE_AND_SDK.md`
- **规范版本**：`v1.0`（Status: **Frozen for Stage 0 / MVP & V1**）
- **配套规范**（三份文档已完成字节级/字段级对齐）：
  - `spec/CRYPTO_AND_AUTH.md`（密码套件、单种子 HKDF、流 1 / 流 2 帧格式、STREAM AEAD、请求签名与 7 份黄金测试向量清单的唯一密码学权威）
  - `spec/PROTOCOL.md`（中继 16 个 HTTP/SSE 端点、三档 VPS 预设与 `--spool=off`、7 步鉴权流水线、配额与部署规范）
- **兼容性声明**：`yellowdking/synctool` 为全新独立仓库，采用全新 `synctool-v1` 协议，**完全不兼容** GravitySSH 旧版 `gssh-sync-v2` 客户端与中继，零历史包袱。

---

## 1. 官方技术栈与跨端 SDK 矩阵

> 设计目标：**适用性最广**（覆盖 SSH 换机、跨端记事本以及各类简易信息传输小工具）× **后续维护升级最容易**（个人开发者长期可持续）× **数据绝对安全**（全链路零信任 E2EE，零冷门自研加密依赖）。

### 1.1 架构铁律：开放规范 + 黄金测试向量 + 纯原生轻量 SDK（拒绝 FFI 地狱）

`synctool` **不采用** Go `gomobile` 或 Rust `UniFFI` 跨语言 FFI 单核心打包方案，原因如下：
1. **避免跨端编译与维护地狱**：`gomobile` 会为移动端引入 10~15 MiB Runtime 膨胀且难以无缝对接系统原生后台传输（Android WorkManager / iOS URLSession）；Rust FFI 需额外引入第二主力语言并长期维护五端交叉编译 CI（NDK / Xcode / MSVC）。
2. **标准库单一密码套件天然易互通**：`v1` 锁定 `X25519 + Ed25519 + HKDF-SHA256 + AES-256-GCM + SHA-256 + HMAC-SHA256`（`CRYPTO_AND_AUTH.md` §2.1），零自研曲线与多端手写 PAKE 风险。
3. **黄金测试向量根治多语言漂移**：`spec/test-vectors/01_seed_and_keys.json` ~ `07_crockford_room_id.json`（见 `CRYPTO_AND_AUTH.md` §8）是全语言唯一真相源；任何语言 SDK 合入前必须 **100% 跑通全部正/负向测试向量**，确保字节级互通零偏差。

### 1.2 官方组件与 SDK 交付矩阵

| 组件 | 阶段 | 语言与依赖约束 | 覆盖场景 | 选型理由（适用性 / 维护 / 安全） |
| :--- | :--- | :--- | :--- | :--- |
| **`synctool-relay`**（中继服务端） | **MVP** | **纯 Go 1.24+ 标准库**，零第三方依赖、零外部 DB | 256MB NAT 小鸡到高配 VPS（Docker `scratch` ~6–10MB 多架构镜像 + 免 Docker 静态二进制裸跑） | 单静态文件零依赖最易部署与安全升级；`--profile=auto` 自动识别内存分档，且强制提供 `--spool=off` / `SYNCTOOL_SPOOL=off` 手动关闭离线暂存 |
| **`spec/` + `spec/test-vectors/`** | **阶段 0 / MVP** | Markdown 规范 + 7 份 JSON 黄金测试向量 | 所有客户端与未来扩展语言的唯一契约 | 一次冻结，长期防漂移，极适合个人开发者配合 AI 快速生成并自动验测新语言 SDK |
| **`sdk/go`**（参考实现 SDK） | **MVP** | **纯 Go 1.24+ 标准库**（`crypto/ecdh`, `crypto/ed25519`, `crypto/hkdf`, `crypto/aes`, `crypto/cipher`, `crypto/sha256`, `crypto/hmac`），零第三方加密依赖 | Windows / macOS / Linux 桌面应用（含 GravitySSH / Wails）、服务端工具、后台任务 | 与服务端同语言栈零切换成本，本身即最高可读性的协议参考实现 |
| **`synctool-cli`**（万能组装 CLI） | **MVP** | 由 `sdk/go` 编译，单文件 ~5MB | 任何简易信息传输小工具、Shell / Python / AutoHotkey / Raycast / 桌面快捷脚本 | 提供结构化 `--json`（stdout 纯 JSON / NDJSON，stderr 诊断与 QR），外部程序无需引入 SDK，**5 分钟子进程调用即可组装安全同步** |
| **`sdk/ts`**（最广覆盖生态 SDK） | **MVP** | **纯 TypeScript，零第三方加密依赖**，基于标准 WebCrypto（`crypto.subtle`）+ 标准 `fetch` / `ReadableStream` | **浏览器 / PWA 轻应用、Node.js 20+、Deno / Bun、Electron、Tauri WebView、React Native、嵌入式 WebView** | **适用面最广**：一套代码通吃网页轻工具与跨端桌面/移动容器；零外部加密依赖使供应链风险最小、长期升级最省心 |
| **`sdk/dart`**（按需扩展） | **V1（若记事本选 Flutter）** | 纯 Dart + 成熟加密库，按 7 份测试向量校验 | Android / iOS / Windows / macOS / Linux 五端统一应用 | 若跨端记事本选 Flutter，一套 Dart SDK 原生覆盖五端，个人维护成本最低 |
| **`sdk/kotlin`**（按需扩展） | **V1（若选原生 Android）** | Kotlin + JVM/Android 加密库 + OkHttp / WorkManager | 原生 Android 记事本 & 升级 GravitySSH Android 端 | 原生贴合 Android Foreground Service / WorkManager 锁屏大视频断点续传 |
| **`sdk/swift`**（按需扩展） | **V2 按需** | Swift + Apple `CryptoKit`（100% 系统原生覆盖全部算法） | 原生 iOS / macOS 应用 | 零外部加密库，原生对接 Keychain 与 `URLSession` |

### 1.3 `sdk/ts` 运行时安全边界与零依赖实现约定

1. **原生 WebCrypto 零三方依赖**：
   - `AES-256-GCM`、`HKDF-SHA256`、`HMAC-SHA256`、`SHA-256`、`X25519`、`Ed25519` 已在 Chrome 133+ / Edge 133+ / Firefox 130+ / Safari 17+ / Node.js 20+ / Deno / Bun 的标准 `SubtleCrypto` 中原生内置。
   - 导入 32B 原始 Ed25519/X25519 私钥与公钥时，严格按 `CRYPTO_AND_AUTH.md` §2.2 的固定 16B PKCS#8 / 12B SPKI RFC 8410 DER 前缀封装，无需 ASN.1 第三方库。
   - 仅当运行于极少数尚未升级 WebCrypto Curve25519 的旧版移动端 WebView / React Native 运行时，`sdk/ts` 提供可选薄接口 `CryptoProvider` 允许应用方单行注入纯 JS 审计库（如 `@noble/curves`），**绝不引入 WASM 或 C/FFI 编译链**。
2. **浏览器沙箱 TLS 边界**：
   - 浏览器 / PWA 沙箱中的 `sdk/ts` 遵循系统 HTTPS CA 证书校验（`tls=system_ca`，中继需配置有效域名 HTTPS，如 Caddy / Nginx + Let's Encrypt / Cloudflare）。
   - Node.js / Electron / Tauri（自定义 TLS 传输层）及原生 `sdk/go` / `sdk/dart` / `sdk/kotlin` / `sdk/swift` 同时支持 `tls=system_ca` 与裸 IP 自签证书 `tls=spki_pin`。

### 1.4 兼顾“最高安全 × 适用最广 × 上手最易”的三路径两套流映射

| 业务场景 | 底层密码流（`CRYPTO_AND_AUTH.md`） | 传输模式（`PROTOCOL.md`） | 用户操作体验 |
| :--- | :--- | :--- | :--- |
| **一次性换机 / 首次绑定（有摄像头，主路径）** | 流 1A（`mode=1`）：**QR OOB 128-bit 暗码 + 临时 X25519** + 双向 Key Confirmation | 房间信令 + Mode A 实时零落盘管道（`oneshot`）或房间密文直换 `PairBindPayload`（`pair`） | 扫 1 次二维码即完成最高安全等级抗 MITM 认证与前向保密协商，零手输、无裸 IP 中间人风险 |
| **一次性换机 / 首次绑定（无摄像头 / 跨城 / CLI 兜底）** | 流 1B（`mode=2`）：**8 字符 Crockford Base32 明码路由 + 3 步 Commit-Reveal X25519 + 强制输入式 6 位 SAS** | 同上 | 仅传 8 位明码（绝不参与加密），发送端**手输接收端屏幕 6 位 SAS** 方可放行（杜绝盲点同意），失败即焚房间（`410 ERR_ROOM_BURNED`） |
| **已绑定设备高频定向推送（记事本 / 剪贴板 / 小工具）** | 流 2（`mode=0x02`）：**DeviceCard 0-RTT Ephemeral-Static X25519 + Ed25519 Sealed Sender**（固定 208B `SealedHeader`） | 优先 **Mode B 加密暂存箱**（`spool.enabled == true` 且 `size ≤ spool.max_item_bytes`，前台挂轻量 SSE 1 秒秒收并签名 ACK 即焚，离线可断点续拉）；超限或 `--spool=off` 时引导双方在场切 **Mode A 零落盘直传** | 点选目标设备（如“书房台式机”）**一键直发**，无需重复核码；仅目标设备私钥可解，单设备丢失可精准吊销且零误伤其他设备 |

> 注：流 1 握手帧保留 `mode=3` 扩展槽供 V2 按需接入可插拔 PAKE（SPAKE2/CPace）；流 2 `SealedHeader.flags` bit 0 预留供 V2 按需扩展一次性预密钥（OTPK）。

---

## 2. Universal Envelope：`Parcel` 与 `Manifest` 冻结规范

`synctool` 永远保持**业务无知（Domain-Agnostic）**。任何应用（GravitySSH 保险库、图文视音混合笔记、剪贴板、TOTP 备份、单文件速传）的数据一律封装为统一逻辑包裹 **`Parcel`**。

### 2.1 包裹结构、`part_id` 编号、分块对齐与 4 KiB 填充

一个 `Parcel` 对应一次完整投递（全局唯一 16B 随机 `msg_id`），按非负整数 `part_id` 拆分为 `1 + K` 个独立加密部件，严格对应中继路由 `.../parts/{part_id}/chunks/{tx_idx}`：

1. **`part_id = 0`（必填，Manifest 槽）**：
   - 承载 UTF-8 编码的 **Manifest JSON**（原始字节记为 `manifest_utf8_bytes`，长度 `L`）。
   - **硬上限**：`0 < L ≤ 131,072 B`（128 KiB），超出直接返回 `ERR_MANIFEST_INVALID`。
   - **4 KiB 分桶填充（严格对齐 `CRYPTO_AND_AUTH.md` §6.3）**：
     - 进入 STREAM AEAD（`part_id = 0`）之前，先按 `uint32_be(L) || manifest_utf8_bytes(L) || (0x00 * pad_len)` 向上对齐至 `4,096 B` 整数倍（防小消息长度侧信道）。
     - 流 2 `SealedHeader` 内签名的 `manifest_sha256` 固定为 `SHA256(manifest_utf8_bytes)`（**不含** 4B 长度前缀与末尾 `0x00` 填充字节）。
   - 使用流 1（`CRYPTO_AND_AUTH.md` §4.3）或流 2（`CRYPTO_AND_AUTH.md` §5.2）产出的 `(part0_key, part0_nonce_prefix)` 加密。
2. **`part_id = 1 .. N`（可选，`0 ≤ N ≤ 63`，Blob 附件槽）**：
   - 承载图片、视频、语音、配置文件包等任意二进制流；与 `PROTOCOL.md` §5.5 单包裹最多 `64` 个 parts（`part_id = 0` + 最多 `63` 个附件）完全一致。
   - 中继**仅见不透明整数 `part_id`**，永不获知业务文件名、MIME、`app_id` 或附件角色。
   - 每个 `part_id = k (1 ≤ k ≤ 63)` 使用发送端 CSPRNG 独立生成的 **32B 随机 `blob_key`**（写入加密 Manifest `blobs[i].key`），按 `CRYPTO_AND_AUTH.md` §6.2 经 HKDF 派生 `(enc_key, nonce_prefix)` 并以 **46B 定长二进制 AAD** 执行 STREAM AEAD 加密。
3. **分块字节对齐（三份规范统一口径）**：
   - 加密原子块恒定：**`65,536 B`（64 KiB）明文 → `65,552 B`（64 KiB + 16 B AES-256-GCM Tag）密文块**（每 `part_id` 末块明文允许 `0 .. 65,536 B` 且置 `is_final = 0x01`；空附件产出 1 块 16B 密文）。
   - HTTP 传输分片 `chunks/{tx_idx}` 按连续 `N` 个密文块无额外帧头顺次拼接，严格匹配 `/v1/caps` 下发的 `streaming.blocks_per_chunk` 与 `streaming.max_transport_chunk_bytes`：
     - `nano`：`4 × 65,552 B = 262,208 B`
     - `standard`：`16 × 65,552 B = 1,048,832 B`
     - `media`：`32 × 65,552 B = 2,097,664 B`
   - 声明总字节 `declared_total_bytes`（用于 `POST /v1/spool/init`）：等于全部 `part_id = 0..N` 的**加密后总密文字节数之和**（对任一 `part`，若明文总长为 `S`（其中 `part_id=0` 取填充后长度 `total_len`），则加密后字节数 = `S == 0 ? 16 : S + ceil(S / 65536) * 16`）。
4. **禁止默认压缩**：
   - `synctool` 协议层与 SDK **严禁对 `part_id >= 1` 自动执行压缩**。若业务 App 在加密前自行压缩纯文本附件，须在 `blobs[i].encoding` 显式标注；`blobs[i].size` 与 `blobs[i].sha256` 始终对应**输入 STREAM AEAD 加密之前的字节**。
5. **两阶段拉取、本地预览缓存与原子交付**：
   - 接收端先校验 `SealedHeader`（流 2）并拉取解密 `part_id = 0`（Manifest）展示预览（来源设备、应用、标题、附件数与总字节数）；中继对 `part_id = 0` 设有独立下载上限 **`16` 次**（附件 `part_id >= 1` 为 `nano=3 / standard=5 / media=5`，见 `PROTOCOL.md` §5.5 & §6.2），且 **SDK 必须在本地按 `item_id` 缓存已解密 Manifest 摘要**（可用 `local_meta_key` 保护，条目被 ACK 或从 `/items` 消失时淘汰），彻底杜绝多次刷新 `inbox list` 误撞 `403 ERR_DOWNLOAD_LIMIT_EXCEEDED`；
   - 按需流式分片拉取 `part_id = 1..N` 到本地临时文件（权限 `0600`），逐块校验 AEAD + 终结块 `is_final=0x01` + 全文件 `size` 与 `sha256`；
   - 仅当全部校验通过且业务 `ParcelHandler` 返回持久化成功后，SDK 才更新本地 `seen_msg_ids` 并调用 `POST /v1/spool/{item_id}/ack`（携带 `X-Sync-Mailbox-Sig`）触发中继立即焚毁。

### 2.2 Manifest JSON Schema（`envelope_version = 1`）

#### 顶层字段定义

| 字段 | 类型 | 必填 | 约束与语义 |
| :--- | :--- | :---: | :--- |
| `envelope_version` | `integer` | 是 | 固定 `1`。遇到未知版本号 SDK 必须拒绝并返回 `ERR_MANIFEST_INVALID`。 |
| `msg_id` | `string` | 是 | **32 位小写十六进制**（16B CSPRNG 随机值）。必须与底层 `SealedHeader.msg_id`（流 2）及 STREAM AEAD 46B AAD 中的 `msg_id(16B)` 逐字节一致，否则返回 `ERR_MANIFEST_INVALID`。 |
| `app_id` | `string` | 是 | 应用命名空间隔离标识，正则 `^[a-z0-9][a-z0-9._-]{1,63}$`（如 `com.yellowdking.notes`、`com.yellowdking.gravityssh`、`synctool.cli`）。系统保留空间：`synctool.system`。 |
| `schema` | `string` | 是 | 业务数据结构与版本标识，正则 `^[a-z0-9][a-z0-9._-]{1,63}$`（如 `note.item.v1`、`vault.snapshot.v1`、`clip.text.v1`）。 |
| `created_at` | `integer` | 是 | 发送端创建包裹的 UTC Unix 秒级时间戳（非负整数）。流 2 中必须与 `SealedHeader.sealed_box` 内签名锁定的 `created_at` 一致。 |
| `sender` | `object` | 是 | 发送方身份信息对象（见下表）。 |
| `inline_payload` | `object \| null` | 否 | 缺省为 `null`。小体积结构化业务 JSON（如笔记正文、标题、剪贴板文字）。**硬上限：UTF-8 序列化字节数 `≤ 65,536 B`（64 KiB）**，超出必须改走 `blobs` 流式附件。 |
| `blobs` | `array<BlobDescriptor>` | 是 | 二进制附件清单，无附件时固定为空数组 `[]`；长度范围 **`0 .. 63`**（与 `PROTOCOL.md` §5.5 单包裹 `max 64 parts` 严格对齐）。 |

#### `sender` 字段定义

| 字段 | 类型 | 必填 | 约束与语义 |
| :--- | :--- | :---: | :--- |
| `device_id` | `string` | 是 | **32 位小写十六进制**，定义同 `CRYPTO_AND_AUTH.md` §3.3：`hex(SHA256("synctool-v1/device-id:" \|\| sign_pk(32B))[0:16])`。**安全校验**：流 2 中必须与已验签 `SealedHeader.sender_device_id_raw` 逐字节一致，不一致立即拒绝并返回 `ERR_CRYPTO_SIGNATURE_INVALID`。 |
| `label` | `string` | 是 | 1~64 UTF-8 字符的人类可读设备昵称（仅解密后供 UI 展示，绝不参与安全信任判定）。 |
| `platform` | `string` | 否 | 建议枚举：`android` \| `ios` \| `windows` \| `macos` \| `linux` \| `web` \| `cli` \| `unknown`。 |

#### `blobs[]` 元素（`BlobDescriptor`）字段定义

| 字段 | 类型 | 必填 | 约束与语义 |
| :--- | :--- | :---: | :--- |
| `part_id` | `integer` | 是 | 范围 **`1 .. 63`**，数组内严格唯一（推荐按 `1, 2, ...` 连续递增），对应数据面路径 `parts/{part_id}/chunks/{tx_idx}`。 |
| `role` | `string` | 是 | 1~32 字符（正则 `^[a-z0-9][a-z0-9._-]{0,31}$`），业务自定义语义角色（如 `image`、`video`、`voice`、`file`、`vault_dump`、`thumbnail`）。 |
| `name` | `string` | 是 | 1~255 UTF-8 字符展示文件名。**路径穿越防线**：接收端落盘严禁将 `name` 直接拼接至本地文件系统路径，必须剥离 `/`、`\`、`..`、NUL 与控制字符，SDK 统一先落盘至安全名 `part_<part_id>.tmp`。 |
| `mime` | `string` | 是 | 1~128 字符标准 MIME 类型（如 `image/jpeg`、`video/mp4`、`audio/mp4`、`application/octet-stream`）。 |
| `size` | `integer` | 是 | 送入 STREAM AEAD 加密前的明文精确字节数（`≥ 0`，`≤ 9,007,199,254,740,991` 兼容 JS `Number.MAX_SAFE_INTEGER`）。 |
| `sha256` | `string` | 是 | **64 位小写十六进制**，加密前明文完整 SHA-256 哈希；落盘后强制校验，不符返回 `ERR_HASH_MISMATCH`。 |
| `key` | `string` | 是 | **43 字符无填充 Base64url**（`b64u`），对应 32B CSPRNG 随机 `blob_key`（按 `CRYPTO_AND_AUTH.md` §6.2 派生该 `part_id` 的 `enc_key` 与 `nonce_prefix`）。 |
| `encoding` | `string` | 否 | 缺省 `"identity"`，允许 `"identity"` \| `"gzip"` \| `"zstd"`，仅标注业务层在加密前是否自行预压缩。 |
| `meta` | `object` | 否 | 可选扩展轻量元数据（如 `{"w":1920,"h":1080}` 或 `{"duration_ms":38500}`），单条序列化后 `≤ 2,048 B`。 |

#### 完整 Manifest 示例（记事本“文字 + 图片 + 语音”定向推送）

```json
{
  "envelope_version": 1,
  "msg_id": "9f86d081884c7d659a2feaa0c55ad015",
  "app_id": "com.yellowdking.notes",
  "schema": "note.item.v1",
  "created_at": 1764246000,
  "sender": {
    "device_id": "a1b2c3d4e5f60718293a4b5c6d7e8f90",
    "label": "我的手机",
    "platform": "android"
  },
  "inline_payload": {
    "note_id": "01JDF3A9W0EXAMPLE000001",
    "title": "项目会议纪要",
    "markdown": "白板拍照与现场录音已附后。"
  },
  "blobs": [
    {
      "part_id": 1,
      "role": "image",
      "name": "whiteboard_01.jpg",
      "mime": "image/jpeg",
      "size": 1843200,
      "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      "encoding": "identity",
      "meta": { "w": 1920, "h": 1080 }
    },
    {
      "part_id": 2,
      "role": "voice",
      "name": "meeting.m4a",
      "mime": "audio/mp4",
      "size": 420100,
      "sha256": "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",
      "key": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
      "encoding": "identity",
      "meta": { "duration_ms": 38500 }
    }
  ]
}
```

### 2.3 系统级载荷与 Mode A 房间控制帧约定

1. **首次设备双向绑定（`purpose == "pair"`，完整兼容 `--spool=off`）**：
   - 不走 Mode A 管道，而是严格按 `CRYPTO_AND_AUTH.md` §4.3，在流 1 房间内使用 `session_key` + `pair_nonce_a/b` 直接双向交换加密后的 **`PairBindPayload`**（携带经 `sign_sk` 签名的 `device_card` + 条件可选 `mailbox` 对象，含 `device_card.platform` 字段）。
   - **当 `spool.enabled == true`**：双方在发包前先向中继调用 `POST /v1/mailboxes/{mailbox_id}/deposit-tokens` 注册不透明 `token_id`（如 `dt_<16_hex>`）与 `token_hash_hex`，并在 `PairBindPayload.mailbox` 中填入 `{relay_origin, mailbox_id, deposit_token}`。
   - **当 `spool.enabled == false`（中继设 `--spool=off`）**：跳过信箱注册与投递令牌签发，`PairBindPayload.mailbox` 置为 `null` 或省略；双方仍校验 `device_id` 派生与 `card_sig` Ed25519 签名后保存本地 `DeviceCard`，从而在无离线暂存中继下照常进行流 2 Mode A 零落盘直传。
2. **Mode A 管道控制帧契约（`POST /v1/rooms/{room_id}/messages`, `kind: "control"`）**：
   - **流 1 `oneshot` 加密控制帧**（加解密公式冻结于 `CRYPTO_AND_AUTH.md` §4.3，线缆 `msg_b64` 解码为 `{"ctrl_seq":<uint32>,"ct":"<b64u>"}`，发送端偶号 `0,2,4...`、接收端奇号 `1,3,5...`）：
     - 发送端启动数据面指令：`{"op":"pipe_start","msg_id":"<32 hex>","blocks_per_chunk":16,"parts":[{"part_id":0,"total_bytes":4112,"chunk_count":1},...]}`
     - 接收端全部校验落盘完成回执：`{"op":"pipe_ack","msg_id":"<32 hex>"}`（双方随后调 `/close{reason:"completed"}`）。
   - **流 2 已绑定设备走 Mode A 零落盘直传（`mode=0, purpose="direct"`，用于 `--spool=off` 或超出暂存上限大视频）**：
     - 发送端建房 `POST /v1/rooms` 的 `initial_msg_b64` 携带：`{"proto_v":1,"mode":0,"purpose":"direct","sealed_header":"<278-char b64u>","blocks_per_chunk":16,"parts":[{"part_id":0,"total_bytes":4112,"chunk_count":1},...]}`；
     - 接收端 `/join` 读取并按 `CRYPTO_AND_AUTH.md` §5.3 完整验签 `SealedHeader`（任何异常立即 `/close{reason:"verify_failed"}` 熔断房间）→ 按 `parts/{part_id}/chunks/{tx_idx}` 流式直通拉取并校验落盘 → 写入 `seen_msg_ids` 后发 `kind: "control"` 完收回执：
       `{"op":"pipe_ack","msg_id":"<32 hex>","ack_mac":"<b64u(HMAC-SHA256(part0_key, utf8(\"synctool-v1/direct-ack\") || msg_id(16B)))>"}`（防恶意中继伪造完收通知），发送端验 `ack_mac` 通过后双方关闭房间。
3. **端到端密文自检包裹（`app_id = "synctool.system", schema = "device.ping.v1"`）**：
   - 纯 Manifest 包裹（`blobs: []`），`inline_payload` 为 `{"echo": "<nonce>"}`，供 CLI 与集成测试端到端验证流 2 全链路。

---

## 3. 统一配置与配对 URI 规范（`synctool://`）

全系统统一单一 Scheme `synctool://`。所有高敏感机密参数（`k` = `relay_access_key`，`s` = `oob_secret`）**强制置于 `#fragment`**（RFC 3986：Fragment 永不随网络请求发送，且隔离于常规代理/路由日志）。

### 3.1 中继配置 URI：`synctool://relay`

由 `synctool-relay init` / `synctool-relay cert-rotate` **仅向交互 TTY** 输出文本与 ASCII 二维码（对齐 `PROTOCOL.md` §7.4 与 `CRYPTO_AND_AUTH.md` §7.5）：

```text
synctool://relay?v=1&u=<percent_encoded_canonical_origin>[&pin=<64_hex_spki>]#k=<43_char_b64u_access_key>
```

| 位置 | 参数 | 必填 | 格式与校验规则 |
| :--- | :--- | :---: | :--- |
| Query | `v` | 推荐（缺省按 `1`） | 协议版本号，固定 `1`。 |
| Query | `u` | **是** | Percent-encoded **`canonical_relay_origin`**（小写 `scheme://host:port`，**显式包含端口**如 `https://relay.example.com:443` 或 `https://1.2.3.4:54843`，无末尾 `/`，不得含 path/query/fragment；仅本地回环 `127.0.0.1` / `localhost` / `[::1]` 允许 `http://`）。客户端按 `CRYPTO_AND_AUTH.md` §3.3 确定性计算 `relay_id = hex(SHA256("synctool-v1/relay-id:" \|\| canonical_relay_origin)[0:16])`。 |
| Query | `pin` | 条件必填 | **64 位小写十六进制**（`hex(SHA256(DER(SubjectPublicKeyInfo)))`，对齐 `CRYPTO_AND_AUTH.md` §7.5 & `PROTOCOL.md` §7.2）。存在时客户端强制启用 `tls=spki_pin` 严格锁定叶证书指纹；缺省时启用 `tls=system_ca`。**安全铁律**：当 `u` 的 Host 为 IPv4/IPv6 裸 IP 时，`pin` **必填**，缺省即报错 `ERR_URI_INVALID`（彻底废除不校验跳过证书）。 |
| Fragment | `k` | **是** | 43 字符无填充 `b64u`（或 ≥32 字符人工自定义 `RELAY_ACCESS_KEY` 字符串），按 `CRYPTO_AND_AUTH.md` §7.1 派生 `relay_hmac_key`。 |

### 3.2 一次性配对 / 换机 / 绑定 / 直传 URI：`synctool://pair`

用于 QR 码或受控复制传递房间路由（`m=1` 时通过 `#s=` 线下传递 128-bit `oob_secret`；`m=2` 与 `m=0` 不带 `#s=`，完全对齐 `CRYPTO_AND_AUTH.md` §4.1 & §5）：

```text
synctool://pair?r=<8char_room_id>&m=<0|1|2>&p=<direct|oneshot|pair>[&v=1][&u=<percent_encoded_canonical_origin>[&pin=<64_hex_spki>]][&exp=<unix_sec>][#[s=<22_char_b64u_16B>][&k=<43_char_b64u_access_key>]]
```

| 位置 | 参数 | 必填 | 格式与校验规则 |
| :--- | :--- | :---: | :--- |
| Query | `r` | **是** | 8 字符标准 Crockford Base32 房间明码（仅作中继路由，绝不参与密钥派生；解析按 `CRYPTO_AND_AUTH.md` §2.3 规范化）。 |
| Query | `m` | **是** | 房间握手/认证模式：<br>• `1`（`qr_oob_x25519`）：流 1A 扫码主路径，**必须**携带 `#s=`，仅配 `p=oneshot` 或 `p=pair`；<br>• `2`（`commit_sas_x25519`）：流 1B 无摄像头兜底，**严禁**携带 `#s=`，须输入对端 6 位 SAS，配 `p=oneshot` 或 `p=pair`；<br>• `0`（`paired_direct`）：流 2 已绑定设备走 Mode A 零落盘直传（`--spool=off` 或超大视频），**严禁**携带 `#s=`，仅配 `p=direct`（直接靠已绑定 `DeviceCard` 与 208B `SealedHeader` 完成端到端双向验签加密，无需再核 SAS）。 |
| Query | `p` | **是** | 房间目的（`purpose`）：`oneshot`（一次性换机/单次速传）、`pair`（首次双向绑定 `DeviceCard`）或 `direct`（已绑定设备 Mode A 零落盘直传，仅与 `m=0` 配对）。 |
| Query | `v` | 否（缺省 `1`） | 协议版本，固定 `1`。 |
| Query | `u` / `pin` | 否 | 可选；若接收端尚未配置该中继（如新机换机），随码附带中继规范地址与证书指纹；双方已配同一中继时省略以降低二维码密度。若 `u` 为裸 IP，强制要求 `pin`。 |
| Query | `exp` | 否 | 房间过期 UTC Unix 秒时间戳（扫码后可本地即判是否过期）。 |
| Fragment | `s` | **仅 `m=1` 必填** | **22 字符无填充 `b64u`**，对应 **16B（128-bit）随机 `oob_secret`**。**永不经中继发送**；`m=2` 与 `m=0` 时**必须省略**（若 `#fragment` 中无 `s` 也无 `k`，则整个 `#...` 省略）。 |
| Fragment | `k` | 否 | 仅当附带 `u` 且需新设备免预先配中继一步直连时携带 `relay_access_key`。 |

> **无摄像头 / 跨城纯手输兜底**：
> - 未绑定设备（`m=2`）：仅传达 8 字符 `room_id`（展示为 `XXXX-XXXX`）→ 双方走 3 步 Commit-Reveal X25519 → **发送端 UI 强制用户输入接收端屏幕显示的 6 位 `sas_str`（如 `042 819`）**，比对通过方放行。UI 必须提醒用户：**明码与 6 位 SAS 严禁发在同一微信/QQ 对话框**。
> - 已绑定设备直传（`m=0&p=direct`）：由 `send --to <dev> --mode pipe` 产出 `synctool://pair?r=<room>&m=0&p=direct`（或直接告知 8 位 `room_id`），接收端自动按 `DeviceCard` 验签 `SealedHeader` 并流式直收，无需重复核对 SAS。

### 3.3 URI 安全红线（所有端强制执行）

1. **严禁注册系统全局 Deep Link**：Android（`intent-filter`）、iOS（`CFBundleURLTypes` / Universal Links）、Windows/macOS（自定义 URL Protocol Handler）**禁止**向操作系统注册 `synctool://` 全局拉起，防止 `#k=` / `#s=` 被系统历史或恶意第三方 App 拦截。所有 App 仅允许通过**应用内摄像头扫码**或**应用内受控粘贴输入框**解析。
2. **严禁明文落日志与崩溃上报**：任何 SDK 日志、网络拦截器、崩溃收集器、CLI stderr 输出中**必须剥离/打码 `#fragment` 全部内容**；原生语言解析完毕后应尽快擦零原始 URI 缓冲。
3. **CLI 防 Shell History 泄露**：`synctool init`、`synctool pair accept`、`synctool recv` 均强制支持 `--stdin` 从管道读入含密 URI 或交互式密文输入。

---

## 4. 统一跨语言错误码枚举与进度事件模型

### 4.1 协议线缆错误与 SDK `SyncError` 的 1-to-1 映射规则

- **中继线缆响应格式（`PROTOCOL.md` §4）**：扁平 JSON `{"error":"<CODE>","message":"...","retryable":false, ...extra_fields}`（未过 HMAC 鉴权则返回静默空 `404`）。
- **SDK 统一错误对象 `SyncError`**：所有语言 SDK（Go / TS / Dart / Kotlin / Swift）与 `synctool-cli --json` 统一包装为：
  ```json
  {
    "code": "ERR_OFFLINE_QUOTA_EXCEEDED",
    "retryable": false,
    "http_status": 413,
    "message": "declared item size exceeds relay max_item_bytes",
    "details": {
      "scope": "item",
      "max_item_bytes": 104857600,
      "suggest_mode": "pipe"
    }
  }
  ```
  - 线缆 `error` 字段直接原样映射为 `SyncError.code`；其余顶层扩展字段（如 `server_ts`、`max_item_bytes`、`scope`、`suggest_mode`、`max_transport_chunk_bytes`）归入 `details`。
  - **禁止硬编码中文 UI 提示作为程序判断依据**，业务 UI 一律根据 `code` 做分支处理与多语言文案展示。

### 4.2 冻结错误码全集（15 项中继线缆码 + 19 项客户端/本地码，共 34 项）

#### A. 中继线缆错误码（与 `PROTOCOL.md` §4 100% 一致）

| 错误码 `code` | HTTP 状态 | `retryable` | 触发语义与 SDK 标准处理 |
| :--- | :---: | :---: | :--- |
| `ERR_BAD_REQUEST` | `400` | `false` | 参数非法、JSON 畸形、`mailbox_id` 派生校验不符、缺显式 `Content-Length` |
| `ERR_REPLAY_DETECTED` | `401` | `true` | HMAC 合法但请求头 `X-Sync-Nonce` 在 120s 窗口内重复；SDK 可换新 nonce 安全重试 |
| `ERR_UNAUTHORIZED_TOKEN` | `401` | `false` | `X-Sync-Room-Token`、`X-Sync-Upload-Token`、`X-Sync-Deposit-Token`（如已被对端吊销）或 `X-Sync-Mailbox-Sig` 无效 |
| `ERR_SPOOL_DISABLED` | `403` | `false` | 中继已设 `--spool=off` 关闭离线暂存（含 `suggest_mode: "pipe"`），UI 引导走 Mode A 双方在场直传 |
| `ERR_DOWNLOAD_LIMIT_EXCEEDED` | `403` | `false` | 单个分片超过 `max_downloads_per_chunk` 下载次数上限 |
| `ERR_NOT_FOUND` | `404`（JSON） | `false` | 已鉴权请求访问的房间、信箱、令牌或暂存条目不存在/已过期/已焚毁（对 `/ack` 幂等视为已焚毁） |
| `ERR_CLOCK_SKEW` | `409` | `true` | HMAC 合法但 `\|X-Sync-TS - server_ts\| > 60s`（附 `server_ts`, `max_skew_sec`）；SDK 验 TLS 后**自动缓存时钟偏移并换新 nonce 无感重试 1 次** |
| `ERR_ROOM_BUSY` | `409` | `false` | 房间已被其他设备抢占（严格 1 发 1 收独占） |
| `ERR_INVALID_STATE` | `409` | `false` | 状态机非法跃迁（如 `commit` 缺片、已提交后继续上传或中止、握手帧超上限 8 帧） |
| `ERR_CONFLICT` | `409` | `false` | 重复活跃 `room_id`、信箱 `auth_pk` 冲突、重复 `token_id` 或单信箱已满 `16` 条 `deposit_token` |
| `ERR_ROOM_BURNED` | `410` | `false` | 房间因 `verify_failed` / `rejected` / `cancelled` 单次熔断已被永久销毁 |
| `ERR_CHUNK_TOO_LARGE` | `413` | `false` | 传输分片 `Content-Length > max_transport_chunk_bytes`（附上限字节数） |
| `ERR_OFFLINE_QUOTA_EXCEEDED` | `413` / `507` | `false` | 超出单条目上限（`413`, `scope="item"`）或全局/信箱/条数上限（`507`, `scope="global"\|"mailbox"\|"item_count"`），附 `suggest_mode: "pipe"`，绝不静默淘汰未读数据 |
| `ERR_RATE_LIMITED` | `429` | `true` | 命中 IP 限流、活跃房间上限或并发流信号量饱和（附 `Retry-After` 秒数） |
| `ERR_PIPE_PEER_TIMEOUT` | `504` | `true` | Mode A 分块在 `rendezvous_timeout_sec`（30s）内未等到对端接入 |

#### B. 客户端接入、密码学与本地宿主错误码

| 错误码 `code` | 触发场景 | `retryable` | 语义说明 |
| :--- | :--- | :---: | :--- |
| `ERR_RELAY_UNREACHABLE` | 网络/TCP/DNS | `true` | 中继不可达、连接断开或超时 |
| `ERR_TLS_PIN_MISMATCH` | TLS 握手 | `false` | 叶证书 SPKI SHA-256 与配置 `pin` 不匹配（疑似 MITM 或中继已轮换证书，须人工核验重新扫码） |
| `ERR_TLS_CERT_INVALID` | TLS 握手 | `false` | 系统 CA 校验失败、证书过期或缺少 SAN/EKU |
| `ERR_AUTH_FAILED` | 静默空 `404` | `false` | `RELAY_ACCESS_KEY` 错误、签名未过或 IP 被临时封禁（中继返回空体隐身 404） |
| `ERR_HANDSHAKE_TIMEOUT` | 流 1 等待 | `true` | 等待对端加入房间或确认超时 |
| `ERR_SAS_MISMATCH` | 流 1 核验 | `false` | 6 位 SAS 核验码输入不符、Commit 承诺不符或 Key Confirmation MAC 失败（疑似 MITM，客户端**必须**调 `/close{reason:"verify_failed"}` 熔断房间） |
| `ERR_CRYPTO_HANDSHAKE_FAILED` | 流 1 / 流 2 | `false` | X25519 共享密钥为全零低阶点或握手帧结构非法（对齐 `CRYPTO_AND_AUTH.md` §2.1） |
| `ERR_CRYPTO_DECRYPT_FAILED` | 流 1 / 流 2 / STREAM | `false` | AES-256-GCM 解密或认证标签校验失败（密文被篡改或密钥不匹配） |
| `ERR_CRYPTO_SIGNATURE_INVALID` | 流 2 / 绑定 | `false` | Ed25519 `DeviceCard` 签名、`SealedHeader` 签名无效，或 `sender.device_id` / `recipient_device_id` 不匹配 |
| `ERR_STREAM_TRUNCATED` | STREAM AEAD | `false` | 流终止但缺失 `is_final=0x01` 认证块，或分块序号不连续，或 Manifest 4 KiB 填充非全零 |
| `ERR_MSG_REPLAY_DETECTED` | 端到端去重 | `false` | 包裹 `msg_id` 已命中本地持久化 `seen_msg_ids` 防重放窗口，拒收恶意中继重放的旧密文（与 HTTP 401 nonce 重复区分，绝不重试） |
| `ERR_HASH_MISMATCH` | 落盘校验 | `false` | 解密落盘后附件全量 `sha256` 或 `size` 与 Manifest 声明不符 |
| `ERR_MANIFEST_INVALID` | 信封解析 | `false` | Manifest 非法 JSON、版本不支持、超 128 KiB、`inline_payload` 超 64 KiB、附件数 > 63、`part_id` 重复或 `msg_id` 不一致 |
| `ERR_DEVICE_UNTRUSTED` | 信任录查询 | `false` | 目标或来源 `device_id` 不在本地受信任 `DeviceCard` 列表或已被吊销 |
| `ERR_INTERRUPTED_RESUMABLE` | 弱网/切后台 | `true` | 分片传输中断但本地已保存断点 checkpoint，重连可断点续传 |
| `ERR_URI_INVALID` | 本地宿主 | `false` | `synctool://` 语法非法、缺必填项或裸 IP 缺少 `pin` |
| `ERR_KEYSTORE_ERROR` | 本地宿主 | `false` | 宿主安全存储（Keychain / Keystore / DPAPI / 加密文件）读写失败 |
| `ERR_STORAGE_IO` | 本地宿主 | `false` | 本地待发文件不可读或临时落盘目录 I/O 失败 / 磁盘满 |
| `ERR_CANCELLED` | 本地宿主 | `false` | 调用方主动取消（`context.Canceled` / `AbortSignal`） |

### 4.3 统一进度与生命周期事件模型

#### 传输进度事件 `TransferEvent`

```json
{
  "type": "event",
  "event": "transfer_progress",
  "stage": "transferring",
  "direction": "send",
  "mode": "spool",
  "msg_id": "9f86d081884c7d659a2feaa0c55ad015",
  "part_id": 1,
  "parts_total": 3,
  "bytes_done": 1048832,
  "bytes_total": 2263860,
  "part_bytes_done": 1048832,
  "part_bytes_total": 1843664,
  "speed_bps": 4194304,
  "resumed": false,
  "ts": 1764246005
}
```

- `stage` 枚举：`"connecting"` → `"handshaking"` → `"awaiting_sas"` → `"manifest_ready"` → `"transferring"` → `"verifying"` → `"acking"` → `"completed"` | `"failed"`。
- `mode` 枚举：`"pipe"`（Mode A） | `"spool"`（Mode B）。

#### 证书到期轮换预警事件 `RelayCertExpiringEvent`

自签证书有效期锁死 **730 天**（`CRYPTO_AND_AUTH.md` §7.5 & `PROTOCOL.md` §7.2）。当 `/v1/ping` 或 `/v1/caps` 返回 `cert_rotate_recommended == true`（即 `cert_expires_at` 剩余 **`< 30 天`**）时，SDK 必须触发以下预警事件提醒用户执行 `synctool-relay cert-rotate` 并重新扫码（剩余 `≤ 7 天` 时 `severity` 升级为 `"urgent"`）：

```json
{
  "type": "event",
  "event": "relay_cert_expiring_soon",
  "relay_id": "7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d",
  "expires_at": 1827318000,
  "days_remaining": 24,
  "severity": "warning"
}
```

---

## 5. 最小宿主接口契约（让任意应用 <100 行胶水嵌入）

任何应用嵌入 `synctool` SDK 只需注入 3 个极简宿主接口，业务层零密码学与分片心智负担。

### 5.1 `KeyStore`（单种子安全存储接口）

宿主安全存储（iOS/macOS Keychain、Android Keystore、Windows DPAPI、Linux Secret Service、CLI 加密文件）只需持久化 **3 项核心状态**：

1. **单一 32 字节主种子 `device_master_seed`（永不离开本机安全存储）**：
   严格按 `CRYPTO_AND_AUTH.md` §3.1–§3.2 经主提取 + 域分离 HKDF 实时派生全部设备密钥：
   - `master_prk = HKDF-Extract(salt = utf8("synctool-v1/master-seed-salt"), ikm = device_master_seed(32B))`
   - `sign_seed` = `HKDF-Expand(master_prk, utf8("synctool-v1/ed25519-sign"), 32)` → Ed25519 `(sign_sk, sign_pk)`
   - `kem_sk` = `HKDF-Expand(master_prk, utf8("synctool-v1/x25519-kem"), 32)` → X25519 `(kem_sk, kem_pk)`
   - `mailbox_auth_seed(relay_id)` = `HKDF-Expand(master_prk, utf8("synctool-v1/mailbox-auth/") \|\| utf8(relay_id), 32)` → 中继隔离 Ed25519 `(mailbox_auth_sk, mailbox_auth_pk)`
   - `local_meta_key` = `HKDF-Expand(master_prk, utf8("synctool-v1/local-storage-key"), 32)` → 仅限本地状态/断点加密保护
   - 确定性标识：`device_id = hex(SHA256("synctool-v1/device-id:" \|\| sign_pk)[0:16])`，`mailbox_id = hex(SHA256("synctool-v1/mailbox-id:" \|\| mailbox_auth_pk)[0:16])`。

2. **受信任 `DeviceCard` 列表（持久化结构，兼容 `--spool=off`）**：
   ```json
   {
     "device_id": "a1b2c3d4e5f60718293a4b5c6d7e8f90",
     "label": "书房台式机",
     "platform": "windows",
     "sign_pk": "<43-char b64u 32B>",
     "kem_pk": "<43-char b64u 32B>",
     "issued_at": 1764246000,
     "card_sig": "<86-char b64u 64B Ed25519 sig>",
     "relay_origin": "https://relay.example.com:443",
     "relay_id": "7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d",
     "mailbox_id": "9f8e7d6c5b4a39281706f5e4d3c2b1a0",
     "outbound_deposit_token": "<43-char b64u 32B, null/omitted when paired under --spool=off>",
     "inbound_token_id": "dt_a1b2c3d4e5f60718",
     "paired_at": 1764246005,
     "revoked": false
   }
   ```
   - **条件可选字段（兼容 `--spool=off`）**：`mailbox_id`、`outbound_deposit_token`、`inbound_token_id` 均为**条件可选**——当首次绑定时中继处于 `--spool=off`（`spool.enabled == false`），三者均为 `null`/省略，不影响本地保存 `DeviceCard` 并以流 2 Mode A 直传（`m=0&p=direct`）安全互发。
   - **单设备精准吊销闭环**：设备 B 丢失时，A 调用 `RevokeDevice(device_id_B)` → 本地立即删除/标记吊销 B 的 `DeviceCard`（即时阻断后续流 2 Mode A 直传与 Mode B 收发）；若 `card.inbound_token_id` 非空且中继已启用暂存，同步以 `X-Sync-Mailbox-Sig` 签名调用 `DELETE /v1/mailboxes/{self_mailbox_id}/deposit-tokens/{card.inbound_token_id}` 精准删除 B 对应的 1 条哈希，**其余所有已绑定设备零受影响**。

3. **`seen_msg_ids` 持久化防重放窗口**：
   - 严格对齐 `CRYPTO_AND_AUTH.md` §5.3：滚动保留期 **`≥ 中继最大 TTL + 7 天`（默认 30 天滚动窗口，且不少于最近 4,096 条）**；仅当整包校验并交付业务成功后写入，再发签名 `ACK`。

4. **跨语言最小接口签名**：
   ```text
   interface KeyStore {
     LoadOrCreateMasterSeed() -> (seed: bytes[32], err)
     GetRelayProfile(relay_id: string) -> (profile: RelayProfile?, err)
     SaveRelayProfile(profile: RelayProfile) -> err
     ListDevices() -> (cards: DeviceCard[], err)
     GetDevice(device_id: string) -> (card: DeviceCard?, err)
     PutDevice(card: DeviceCard) -> err
     DeleteDevice(device_id: string) -> err
     HasSeenMsgID(msg_id: string) -> (seen: bool, err)
     MarkSeenMsgID(msg_id: string, created_at: int64, seen_at: int64) -> err
   }
   ```

### 5.2 `BlobStorage`、`CheckpointStore` 与防 OOM 红线

- **发送侧 API 红线**：所有语言 SDK 的 `BlobInput` **只接受流式句柄 / 文件路径 / Web `File | Blob | ReadableStream`**，**严禁**为大附件提供全量 `[]byte` / `Uint8Array` 入参，从 API 层面杜绝手机端发视频 OOM。
- **接收侧落盘红线**：SDK 流式写入 `TempDir/<msg_id>/part_<part_id>.tmp`（权限 `0600`）并同步计算明文 `sha256`；全部块验签且校验 `size` + `sha256` 通过后才移交安全路径/句柄给业务 `ParcelHandler`，业务返回成功后再写入 `seen_msg_ids` 并发送签名 `ACK`。
- **断点续传 `CheckpointStore`**：按 `(msg_id, direction, part_id)` 记录 `item_id / pipe_id`、`next_tx_idx`、`next_block_idx`、`upload_token`（发送侧）及 `expires_at`（可用 `local_meta_key` 保护），弱网或手机切后台中断后再次调用自动续传。

### 5.3 高层 `Client` 核心 API 契约（Go / TS / Dart / Kotlin 统一语义）

```text
interface Client {
  // 探活与能力发现（内置 409 ERR_CLOCK_SKEW 自动校时重试 1 次 + 证书到期预警）
  Ping(ctx) -> (PingResult, err)
  Capabilities(ctx) -> (RelayCaps, err)

  // 流 1：一次性按需直传 / 换机（Mode A 零落盘管道，传完即擦零 session_key）
  StartOneShotSend(ctx, parcel, opts: { mode: 1|2, onOfferReady, onSASInput, onProgress }) -> (SendResult, err)
  ReceiveOneShot(ctx, pairInput, handler, opts: { onSASDisplay, onProgress }) -> (Manifest, err)

  // 流 1：首次设备双向绑定（房间内加密交换 PairBindPayload 并互注册独立 deposit_token）
  StartDeviceBind(ctx, opts: { mode: 1|2, label, onOfferReady, onSASInput }) -> (DeviceCard, err)
  AcceptDeviceBind(ctx, pairInput, opts: { label, onSASDisplay }) -> (DeviceCard, err)

  // 流 2：已绑定设备定向推送（统一 0-RTT SealedHeader）
  // deliveryMode="auto": 查 /v1/caps，spool 开启且未超限走 Mode B；否则返回 ERR_SPOOL_DISABLED / ERR_OFFLINE_QUOTA_EXCEEDED
  // deliveryMode="pipe": 建 m=0&p=direct 房间通过 onOfferReady 输出房间明码/URI，走 Mode A 零落盘直传并验 direct pipe_ack
  SendToDevice(ctx, targetDeviceID, parcel, opts: { deliveryMode: "auto"|"spool"|"pipe", onOfferReady?, onProgress }) -> (SendResult, err)
  // 接收流 2 Mode A 直传（支持 m=0&p=direct URI 或 8 位房间明码；也可与 ReceiveOneShot 统一入口按房间首帧 mode 自动分派）
  ReceiveDirect(ctx, pairInput, handler, opts: { onProgress }) -> (Manifest, err)

  // 按需收件箱（两阶段拉取：ListInbox 按 item_id 本地缓存已解密 part_id=0 Manifest 摘要避免重复耗尽 16 次下载上限）
  ListInbox(ctx, opts: { appID? }) -> (InboxPreview[], err)
  FetchParcel(ctx, itemID, handler, opts: { onProgress }) -> (Manifest, err)
  WatchInbox(ctx, onEvent) -> err          // 前台按需 SSE，90s 主动 reconnect 无感重连 + 自动降级 20s 长轮询
  RevokeDevice(ctx, deviceID) -> err       // 精准单设备吊销（兼容 --spool=off，零误伤其他设备）
}
```

---

## 6. `synctool-cli` 核心子命令契约

`synctool-cli`（可执行文件名 `synctool`）既是 `sdk/go` 的验证客户端，也是**供一切脚本、快捷工具和轻量桌面程序“5 分钟子进程组装”的通用外壳**。

### 6.1 全局参数、结构化 `--json` 模式与退出码

- **全局参数**：
  - `--config <dir>`：状态与密钥存储目录（强制 `0700`，默认遵循 OS 规范如 `%AppData%\synctool` / `~/.config/synctool`）。
  - `--relay <relay_id|alias>`：指定已配置中继（默认激活中继）。
  - `--app <app_id>`：指定业务命名空间，默认 `"synctool.cli"`（外部工具传入自身 `app_id` 如 `com.yellowdking.clip` 实现隔离）。
  - `--json`：机器可读模式——**`stdout` 严格仅输出单行 JSON 或 NDJSON**（进度行 `"type":"event"`，最终结果行 `"type":"result"`，错误行 `"type":"error"` 附标准 `SyncError`）；二维码 ASCII 与人工交互提示统一输出至 `stderr`。
  - `--quiet` / `-q`：关闭非必要 `stderr` 提示。
- **统一退出码（Exit Code）**：

| 退出码 | 含义 | 典型对应错误码 |
| :---: | :--- | :--- |
| `0` | 成功 | - |
| `1` | 通用或本地存储 / 密钥库错误 | `ERR_KEYSTORE_ERROR`, `ERR_STORAGE_IO` |
| `2` | 参数或 URI 格式错误 | `ERR_URI_INVALID`, `ERR_BAD_REQUEST`, `ERR_MANIFEST_INVALID` |
| `3` | 网络 / 中继不可达 / 鉴权 / 限流错误 | `ERR_RELAY_UNREACHABLE`, `ERR_AUTH_FAILED`, `ERR_RATE_LIMITED`, `ERR_PIPE_PEER_TIMEOUT` |
| `4` | 安全核验、吊销或完整性失败（严禁忽略） | `ERR_TLS_PIN_MISMATCH`, `ERR_SAS_MISMATCH`, `ERR_ROOM_BURNED`, `ERR_CRYPTO_*`, `ERR_HASH_MISMATCH`, `ERR_MSG_REPLAY_DETECTED`, `ERR_DEVICE_UNTRUSTED`, `ERR_UNAUTHORIZED_TOKEN` |
| `5` | 离线暂存关闭或配额超限（可切 Mode A） | `ERR_SPOOL_DISABLED`, `ERR_OFFLINE_QUOTA_EXCEEDED`, `ERR_NOT_FOUND`（已过期） |
| `6` | 弱网中断且已保存断点（可重跑续传） | `ERR_INTERRUPTED_RESUMABLE` |

### 6.2 七大核心子命令契约

1. **`synctool init`** —— 初始化本机身份并接入自建中继
   - 用法：`synctool init [--relay-uri <uri> | --stdin] [--alias <name>] [--label <device_label>]`
   - 行为：生成/加载 32B `device_master_seed` → 解析 `synctool://relay?...#k=...` → 调 `GET /v1/ping` 与 `GET /v1/caps` 验证连通、时钟与证书指纹 → 调 `PUT /v1/mailboxes/{mailbox_id}` 注册本机盲化信箱（当 `spool.enabled == true`）→ 持久化配置。
   - 安全约束：优先 `--stdin` 读入 URI 防泄露至 Shell History；任何输出严禁包含 `relay_access_key` 或 `device_master_seed`。

2. **`synctool ping`** —— 探测中继连通性、VPS 档位、暂存开关与证书寿命
   - 用法：`synctool ping [--relay <id|alias>]`
   - 输出：RTT（ms）、`profile`（`nano|standard|media`）、`spool.enabled` / `spool.backend`（`off|memory|disk`）、`spool.max_item_bytes`、`streaming.blocks_per_chunk` / `max_transport_chunk_bytes`、`clock_offset_sec`、`cert_expires_at` 及 `cert_rotate_recommended`。

3. **`synctool pair`** —— 首次双向绑定受信任设备（流 1 `purpose="pair"`）
   - 发起方：`synctool pair offer [--label <name>] [--mode qr|sas] [--include-relay]`
     - 默认 `--mode qr`（流 1A）：建房并向 `stderr` 打印 ASCII QR 码与 `synctool://pair?...#s=...`；
     - `--mode sas`（流 1B）：建房并输出 8 位房间明码 `XXXX-XXXX`，对端接入后交互提示**手动输入对端屏幕 6 位 SAS**，校验通过后双向完成 `PairBindPayload` 交换与单设备 `deposit_token` 注册。
   - 接受方：`synctool pair accept [<pair_uri_or_room_code>] [--stdin] [--label <name>]`
     - 自动识别 `synctool://pair?...`（走 `m=1` 或 `m=2`）或 8 位房间明码（走 `m=2` 并展示 6 位 SAS 供发起方输入）。

4. **`synctool send`** —— 加密发送包裹（支持已绑定定向推送 & 一次性按需直传）
   - **已绑定定向推送（流 2）**：
     `synctool send --to <device_id|label> [--schema <schema>] [--text <utf8> | --inline-json <file|->] [--file <path>[:<role>] ...] [--mode auto|spool|pipe]`
     - `--mode auto`（默认）：查 `/v1/caps`，若 `spool.enabled == true` 且加密总大小 `≤ spool.max_item_bytes`（且对端名片含 `mailbox_id` / `outbound_deposit_token`）走 Mode B 0-RTT 加密暂存箱；否则返回退出码 `5`（`ERR_SPOOL_DISABLED` 或 `ERR_OFFLINE_QUOTA_EXCEEDED`）并提示加 `--mode pipe` 走双方在线零落盘直传。
     - `--mode pipe`：创建 `mode=0, purpose="direct"` 房间并在 `initial_msg_b64` 写入 208B `SealedHeader` 与分片布局，向 `stderr` 输出 `synctool://pair?r=<room>&m=0&p=direct`（无 `#s=`）与 8 位房间明码 `XXXX-XXXX` 供目标设备接收，待对方完成落盘校验并回传带 `ack_mac` 的 `pipe_ack` 后结束。
   - **一次性按需直传（流 1，如换机/临时速传）**：
     `synctool send --oneshot [--schema <schema>] [--text <utf8> | --inline-json <file|->] [--file <path>[:<role>] ...] [--mode qr|sas] [--include-relay]`
     - 创建 `purpose="oneshot"` 房间，核验通过后通过加密 `pipe_start` 走 Mode A 零落盘分块直通，收到 `pipe_ack` 后关闭房间并擦零 `session_key`。

5. **`synctool recv`** —— 接收 Mode A 直传包裹（含流 1 一次性 & 流 2 已绑定直传），或按 ID 拉取指定收件箱包裹
   - Mode A 房间接收：`synctool recv [<pair_uri_or_room_code>] [--stdin] --out <dir>`
     - 自动识别输入与房间首帧 `mode`：
       - `m=1` / `m=2`（`p=oneshot`）：执行流 1 核验（QR OOB 或 Commit-Reveal SAS）→ 收加密 `pipe_start` → 流式拉取全部分片并校验 `sha256` 落盘 → 发加密 `pipe_ack`。
       - `m=0&p=direct`（或输入纯 8 位房间明码且房间首帧为 `mode=0`）：执行流 2 `SealedHeader` 完整验签（验目标设备 ID、受信任 `DeviceCard` 与 Ed25519 签名，非法立即 `/close{reason:"verify_failed"}` 熔断）→ 流式直通落盘校验 `sha256` → 写入 `seen_msg_ids` → 发带 `ack_mac` 的 `pipe_ack` 完收。
   - 拉取指定暂存包裹：`synctool recv --item <item_id> --out <dir>`
     - 按两阶段流式落盘校验 `sha256` + `size`，验证全部通过后写 `seen_msg_ids` 并发送签名 `ACK` 焚毁中继副本，输出解密 Manifest 与安全落盘文件路径。

6. **`synctool inbox`** —— 按需查看、拉取与前台监听已绑定收件箱
   - `synctool inbox list [--app <app_id>]`：拉取并解密所有待收条目的 `SealedHeader` 与 `part_id=0` Manifest（**本地按 `item_id` 缓存已解密摘要**，不重复消耗中继 16 次 `part_id=0` 下载配额），列出摘要（`item_id`、来源设备、`app_id`、`schema`、时间、附件数与总字节），**不下载大附件、不发 ACK**。
   - `synctool inbox pull [--app <app_id>] [--all | --item <item_id>] --out <dir>`：流式断点下载全部 `part_id=1..N`、校验全量 `sha256` 落盘后签名 `ACK` 即焚。
   - `synctool inbox watch [--app <app_id>] [--out <dir>] [--auto-pull]`：按需前台挂轻量 SSE（`90s` 正常 `reconnect` 重连 / 自动降级 `20s` 长轮询），收到 `new_item` 立即吐 `--json` 事件（或加 `--auto-pull` 自动拉齐落盘并焚毁）。

7. **`synctool device`** —— 本机身份与受信任设备管理（含精准单设备吊销）
   - `synctool device whoami`：打印本机 `device_id`、`label`、`sign_pk`、`kem_pk`、`mailbox_id`（严禁打印私钥与主种子）。
   - `synctool device list`：列出全部受信任 `DeviceCard`（`device_id`、`label`、`platform`、`paired_at`、`relay_origin`）。
   - `synctool device rename <device_id> <new_label>`：更新本地备注名。
   - `synctool device revoke <device_id>`：精准吊销单个丢失/淘汰设备（删除本地名片；若已绑定信箱令牌则同步向中继签名调用 `DELETE /v1/mailboxes/{mailbox_id}/deposit-tokens/{inbound_token_id}`，**不影响其他已绑定设备**）。

---

## 7. 三份规范交叉对齐核验表（Stage 0 冻结锚点）

| 冻结契约项 | 冻结精确值 / 规则 | 对齐权威文档 |
| :--- | :--- | :--- |
| 锁定密码套件 | `X25519 + Ed25519 + HKDF-SHA256 + HMAC-SHA256 + AES-256-GCM + SHA-256`（`proto_v=1`，无运行时降级） | `CRYPTO_AND_AUTH.md` §2.1 |
| 单种子 HKDF 派生 | `master_prk = HKDF-Extract("synctool-v1/master-seed-salt", seed(32B))` → `ed25519-sign` / `x25519-kem` / `mailbox-auth/<relay_id>` / `local-storage-key` | `CRYPTO_AND_AUTH.md` §3.1–3.2 |
| 确定性标识公式 | `relay_id`/`device_id`/`mailbox_id` 均为 `hex(SHA256("synctool-v1/<kind>:" \|\| input)[0:16])`（32 位小写 hex） | `CRYPTO_AND_AUTH.md` §3.3, `PROTOCOL.md` §1 |
| 流 1 房间明码 | 8 字符标准 Crockford Base32（5B = 40-bit CSPRNG，线缆大写无连字符，绝不参与密钥派生） | `CRYPTO_AND_AUTH.md` §2.3, `PROTOCOL.md` §1 |
| Mode A 管道控制帧 | 流 1 `oneshot` 加密 `pipe_start` / `pipe_ack`；流 2 `mode=0&purpose=direct` 首帧携 208B `SealedHeader` + 完收 `pipe_ack` 带 `ack_mac` | `CRYPTO_AND_AUTH.md` §4.3 & §5, `PROTOCOL.md` §5.2 |
| 流 2 封装头 | 固定 **208 B**（`b64u` 278 字符）`SealedHeader = clear_header(56B) \|\| sealed_box(152B)` | `CRYPTO_AND_AUTH.md` §5, `PROTOCOL.md` §5.5 |
| 加密块 & 传输分片 | 加密块 `64 KiB` 明文 / `65,552 B` 密文（46B 定长 AAD）；HTTP 分片 `nano=4(262,208 B)` / `standard=16(1,048,832 B)` / `media=32(2,097,664 B)` | `CRYPTO_AND_AUTH.md` §6, `PROTOCOL.md` §2 |
| 数据面 Part 编号与下载上限 | `part_id=0` 为 4 KiB 填充加密 Manifest（明文 `≤128 KiB`，`inline_payload ≤64 KiB`，下载上限 **`16` 次** + SDK 本地按 `item_id` 缓存）；`part_id=1..63`（总 part `≤64`，下载上限 `nano=3/std=5/media=5`） | `CRYPTO_AND_AUTH.md` §6.3, `PROTOCOL.md` §5.5 & §6.2 |
| 鉴权头与时钟偏 | `X-Sync-TS` / `X-Sync-Nonce` / `X-Sync-Sig`（控制面 `sha256:` vs 数据面 `stream:<Content-Length>`）；先验 HMAC（错返静默空 404）→ 超 `±60s` 返 `409 ERR_CLOCK_SKEW`（不入 nonce 表）→ 8,192 条 / 120s nonce 去重（重复 `401 ERR_REPLAY_DETECTED`） | `CRYPTO_AND_AUTH.md` §7.1–7.3, `PROTOCOL.md` §3 |
| 单设备吊销与防重放 | 单信箱 `≤16` 条 `token_id` + `SHA256("synctool-v1/deposit-token:" \|\| token)`，`X-Sync-Mailbox-Sig` 精准删单条（`--spool=off` 下 `mailbox` 字段条件可选）；端侧 `seen_msg_ids` 默认 30 天滚动窗口（撞库报 `ERR_MSG_REPLAY_DETECTED`） | `CRYPTO_AND_AUTH.md` §4.3, §5.3 & §7.4, `PROTOCOL.md` §5.4 |
| 离线暂存与手动关 | `--profile=auto\|nano\|standard\|media` + 显式手动关 `--spool=off`（返回 `403 ERR_SPOOL_DISABLED`）；超限返 `413`/`507 ERR_OFFLINE_QUOTA_EXCEEDED` | `PROTOCOL.md` §4 & §6 |
| 自签证书与 Pin | 730 天 ECDSA P-256（含 `ServerAuth` EKU + IP/DNS SAN），64 位小写 hex SPKI Pin；剩余 `<30 天` `cert_rotate_recommended=true` 触发预警 | `CRYPTO_AND_AUTH.md` §7.5, `PROTOCOL.md` §5.1 & §7.2 |
| 统一 URI 与红线 | `synctool://relay?v=1&u=...[&pin=<64hex>]#k=...` 与 `synctool://pair?r=...&m=0\|1\|2&p=direct\|oneshot\|pair...[#[s=...][&k=...]]`（`#s=` 仅 `m=1` 必带）；敏感参数强制置 `#fragment`，严禁全局 Deep Link 与日志落盘 | `CRYPTO_AND_AUTH.md` §4.1 & §7.5, `PROTOCOL.md` §7.4 |

---

## 8. 端侧安全加固、无感自愈与版本前向兼容补充约定（v1.x 非破坏性扩展）

1. **HTTP 重定向硬阻断**：所有 SDK 客户端必须禁止自动跟随任何 HTTP `3xx` 重定向（Go `http.ErrUseLastResponse`、Web `redirect: "error"`），收到 `300..399` 立即以不可重试 `ERR_RELAY_UNREACHABLE` 拒绝，防止自定义 `X-Sync-*` 鉴权头泄露或绕过 SPKI Pinning。
2. **`part_id = 0` 内存前置防线**：接收端在拉取 `part_id = 0`（Manifest）进入内存缓冲前，必须前置校验 `0 < total_bytes <= 135,216` 且 `1 <= chunk_count <= 4`，超限立即拒绝并返回 `ERR_MANIFEST_INVALID`。
3. **跨平台文件名清洗与原子落盘**：
   - `SanitizeFilename` / `sanitizeFileName` 除剥离路径分隔符与控制字符外，必须剔除 Unicode 双向覆盖符（`U+202A..202E`, `U+2066..2069`）、循环剥离首尾 `.` 与空白、按完整 UTF-8 码点边界截断，并对 Windows 保留设备主文件名（`CON`、`PRN`、`AUX`、`NUL`、`COM1..9`、`LPT1..9` 含扩展名如 `NUL.txt`）统一加 `_` 前缀（如 `_NUL.txt`）。
   - 本地接收附件先写入 `0600` 临时 `.part` 文件，全量 AEAD 终结块与 `size + sha256` 校验通过后方可原子重命名为 `.verified` 暴露给业务回调，并在 `Client.Close()` 时清理残留临时目录。
4. **内存暂存重启自愈（Self-Healing）**：
   - `DeviceCard` 可选持久化单向哈希 `inbound_token_hash`（64 位小写 hex `SHA256("synctool-v1/deposit-token:" || raw_token)`，向后兼容旧 `keystore.json`）。
   - 当 `nano` 内存暂存重启后，接收端访问 `/v1/mailboxes/{self_id}/*` 遇到 `404 ERR_NOT_FOUND` 时，SDK 自动执行 1 次 `SyncMailbox`（幂等调用 `PUT /v1/mailboxes/{self_id}` 合并恢复全部未吊销同中继名片的 `(inbound_token_id, inbound_token_hash)`，并对旧版中继自动回退逐条 `POST .../deposit-tokens`）后无感重试原请求。
5. **平滑演进与错误分类契约**：
   - 所有控制面/信封 JSON 反序列化必须容忍并忽略未来 `v1.x` 新增的可选未知字段；当遇到合法正整数且高于当前支持的主版本号（`envelope_version > 1`、URI `v > 1`、握手 `proto_v > 1`）时，统一返回客户端错误码 `ERR_UNSUPPORTED_VERSION`（CLI 退出码 `2`）。
   - `SyncError` 在构造与格式化时自动脱敏内嵌 `synctool://...#fragment` 及 `#k=`/`#s=`，并跨语言提供 `IsRetryable`、`IsQuotaExceeded`、`SuggestPipeMode`、`IsAuthError`、`IsSecurityAlert`、`IsVersionMismatch` 稳定分类器。
   - 统一环境变量约定：`SYNCTOOL_RELAY`（主，兼容 `SYNCTOOL_RELAY_URI`）、`SYNCTOOL_PAIR_URI`、`SYNCTOOL_APP`、`SYNCTOOL_CONFIG`。
