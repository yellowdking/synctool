# `synctool` 密码学、身份认证与中继鉴权规范（v1 冻结版）

> **文档状态**：Frozen v1.0（阶段 0 冻结契约）  
> **适用范围**：`synctool-relay`（Go）、`sdk/go`、`synctool-cli`、`sdk/ts`（WebCrypto）及未来一切原生语言 SDK（Dart / Kotlin / Swift）  
> **兼容性声明**：全新独立协议 `synctool-v1`，**完全不兼容**老版 GravitySSH `gssh-sync-v2`。

---

## 1. 安全目标、信任模型与验证体系选型

### 1.1 零信任中继假设（Threat Model）
`synctool` 按**最严格零信任中继模型**设计：假设中继 VPS、反向代理、CDN 或网络链路随时可能被攻破、被动抓包、主动篡改、重放、截断或整盘拖库。系统保证：
1. **端到端机密性与完整性**：中继永不持有任何业务明文或解密密钥；即使中继硬盘被拖库，也无任何明文与业务元数据泄露。
2. **抗主动中间人（MITM）与抗离线暴力破解**：消灭任何依赖短口令直接派生密钥或单轮哈希路由的离线破解面。
3. **元数据最小化**：`app_id`、业务 Schema、文件名、MIME 类型、设备明文名、离线推送发送者身份全部封装进密文。
4. **单设备精准吊销**：已绑定设备丢失时可单点吊销其信任与投递权限，零误伤其余设备。

### 1.2 为何锁定当前“三路径 + 两套密码流”验证体系
结合“**数据绝对安全、适用面最广、最易上手、维护升级简单**”的最高原则，v1 锁定以下组合，并彻底放弃在多门客户端语言中各自手写椭圆曲线 PAKE（如 SPAKE2）：

| 场景 | 验证与加密路径 | 密码学安全强度 | 用户上手体验 | 跨平台实现与维护 |
| :--- | :--- | :--- | :--- | :--- |
| **流 1A：面对面换机 / 首次绑定**（90% 手机↔电脑主路径） | **QR OOB 128-bit 暗码 + 临时 X25519 + 双向 Key Confirmation** | 128-bit 带外暗码 + 128-bit ECDH，抗离线破解、抗主动 MITM、完全双向 PFS | **扫一下二维码即通**，零手输、零易错 | 100% 标准库原生内置，零三方加密依赖 |
| **流 1B：无摄像头 / 跨城 / CLI 一次性配对**（兜底路径） | **明码路由 + 3 步 Commit-Reveal X25519 + 发送端强制输入接收端 6 位 SAS** | 128-bit ECDH 抗离线破解；Commit-Reveal 彻底封死 SAS 离线碰撞；在线猜中率 $\le 10^{-6}$ 且失败即熔断房间；完全双向 PFS | 仅传 8 位明码，核对/输入对方 6 位数字即可 | 100% 标准库原生内置，零三方加密依赖 |
| **流 2：已绑定设备高频定向推送**（记事本 / 剪贴板 / 简易信息工具，兼容在线与离线） | **DeviceCard 0-RTT Ephemeral-Static X25519 + Ed25519 Sealed Sender** | 仅目标设备可解、送信方 Ed25519 防伪造、中继不可知发送者、发送端 PFS（预留 `prekey_id` 供 V2 升级 OTPK） | **点选目标设备一键直发**，无需再输任何码 | 统一通吃 Mode B 暂存箱与 Mode A 超限直传 |

**为何此方案优于 MVP 阶段强上多端 PAKE（SPAKE2）**：
- **零自研曲线风险**：WebCrypto / JDK / CryptoKit 原生均不含 SPAKE2，多语言手写椭圆曲线群运算极易引入无效点/子群攻击漏洞；而本方案全部基于全平台标准库原语，实现最薄、最安全、最易维护。
- **反社工更稳健**：用户使用 PAKE 常将自定义弱口令与房间号发在同一个聊天窗，导致同渠道泄露；本方案面对面强制扫码、跨城强制核对动态 6 位 SAS 并以“输入对端数字”防止盲点同意。
- **平滑扩展**：流 1 握手帧保留 `mode` 枚举（`1 = qr_oob_x25519`、`2 = commit_sas_x25519`，预留 `3 = pake_spake2_v2`），未来如需增加口令 PAKE 无需破坏 v1 架构。

---

## 2. 锁定密码套件、编码约定与跨平台互操作红线

### 2.1 锁定单一密码套件（`proto_v = 1`）
v1 **禁止运行时动态协商加密套件**（彻底消除降级攻击面），所有实现必须严格使用：
- **密钥协商**：`X25519`（RFC 7748）。**硬约束**：执行 `X25519(sk, pk)` 后必须校验 32 字节共享密钥**不得为全零**（`0x00 * 32`），否则立即中止并报 `ERR_CRYPTO_HANDSHAKE_FAILED`。
- **数字签名**：`Ed25519`（RFC 8032，PureEdDSA）。
- **哈希与 MAC**：`SHA-256`（FIPS 180-4）与 `HMAC-SHA256`（RFC 2104）。
- **密钥派生**：`HKDF-SHA256`（RFC 5869，明确区分 `HKDF-Extract(salt, ikm)` 与 `HKDF-Expand(prk, info, L)`）。
- **认证加密（AEAD）**：`AES-256-GCM`（32B 密钥、12B 确定性 Nonce、16B 认证 Tag 紧跟密文尾部）。
- **随机数源**：操作系统密码学安全随机源（CSPRNG：`crypto/rand`、`crypto.getRandomValues`、`SecRandomCopyBytes`、`SecureRandom`）。

### 2.2 WebCrypto（`sdk/ts`）零三方依赖互操作规范
浏览器（Chrome 133+ / Edge 133+ / Firefox 130+ / Safari 17+）、Node.js 20+、Deno、Bun 的标准 `SubtleCrypto` 原生支持 `X25519`、`Ed25519`、`HKDF`、`HMAC`、`SHA-256`、`AES-GCM`。  
**关键坑位规避**：`SubtleCrypto.importKey` 导入 `Ed25519`/`X25519` **私钥**仅支持 `"pkcs8"`（不支持 `"raw"`）。各实现从 32 字节原始私钥种子构造 RFC 8410 PKCS#8 DER 时，直接拼接以下**固定 16 字节常量前缀**即可（总长 48 字节）：

| 密钥类型 | DER 格式 | 固定前缀（Hex） | 拼接载荷 | 总长度 |
| :--- | :--- | :--- | :--- | :--- |
| Ed25519 私钥 | PKCS#8 | `302e020100300506032b657004220420` | `sign_seed` (32B) | 48 B |
| X25519 私钥 | PKCS#8 | `302e020100300506032b656e04220420` | `kem_sk` (32B) | 48 B |
| Ed25519 公钥 | SPKI | `302a300506032b6570032100` | `sign_pk` (32B) | 44 B |
| X25519 公钥 | SPKI | `302a300506032b656e032100` | `kem_pk` (32B) | 44 B |

> 注：RFC 7748 规定 X25519 私钥标量钳位（clamping：`k[0] &= 248; k[31] &= 127; k[31] |= 64`）由各平台 `X25519` 底层自动完成；`HKDF-Expand` 产出的 32B `kem_sk` 直接作为原始私钥输入即可保持全平台字节一致。

### 2.3 基础编码约定
- `||`：原始字节顺序拼接，无隐式分隔符。
- `utf8("...")`：不含末尾 `0x00` 的 UTF-8 原始字节。
- `uint8(x)`、`uint32_be(x)`、`uint64_be(x)`：无符号大端序整数。
- `hex(b)`：**小写十六进制**（`[0-9a-f]`）。
- `b64u(b)`：**无填充 Base64url**（RFC 4648 §5，字母表 `A-Za-z0-9-_`，无 `=` 尾缀）。
- **明码房间号 `room_id`（Standard Crockford Base32）**：
  - 生成：取 **5 字节（40 bit）** CSPRNG 随机字节，按大端序 5 bit 一组映射为 8 字符（零模偏差），字母表严格为 32 字符：`0123456789ABCDEFGHJKMNPQRSTVWXYZ`。
  - 规范化（用户输入解析）：去除空白与 `-`，转大写，映射 `O→0`、`I→1`、`L→1`；任何剩余非法字符直接拒绝。
  - 协议传输/哈希使用无连字符的 **8 字节大写规范串 `XXXXXXXX`**；UI 展示为 **`XXXX-XXXX`**。
  - **安全铁律**：`room_id` 仅为中继匿名路由标识，**绝对不得**作为秘密参与任何密钥派生！

---

## 3. 单种子域分离密钥派生表（`device_master_seed`）

客户端在操作系统安全存储（Keychain / Android Keystore / Windows DPAPI / Linux Secret Service）中**仅持久化 1 个 32 字节 CSPRNG `device_master_seed`**（外加受信任 `DeviceCard` 列表与防重放表）。所有设备密钥均确定性域分离派生：

### 3.1 主提取（Master Extract）
```
master_prk = HKDF-Extract(
    salt = utf8("synctool-v1/master-seed-salt"),
    ikm  = device_master_seed(32B)
)
```

### 3.2 子密钥派生表（全部通过 `HKDF-Expand(master_prk, info, L)`）

| 子密钥名 | `info` 字节串 | 长度 `L` | 用途与安全隔离边界 |
| :--- | :--- | :--- | :--- |
| `sign_seed` | `utf8("synctool-v1/ed25519-sign")` | 32 B | 生成设备长期 Ed25519 密钥对 `(sign_sk, sign_pk)` |
| `kem_sk` | `utf8("synctool-v1/x25519-kem")` | 32 B | 生成设备长期 X25519 密钥对 `(kem_sk, kem_pk)`（与 Ed25519 严格独立，严禁同钥跨算法） |
| `mailbox_auth_seed(relay_id)` | `utf8("synctool-v1/mailbox-auth/") \|\| utf8(relay_id)` | 32 B | 为指定中继生成独立 Ed25519 信箱所有权密钥对 `(mailbox_auth_sk, mailbox_auth_pk)`，不同中继间不可关联 |
| `local_meta_key` | `utf8("synctool-v1/local-storage-key")` | 32 B | 仅限本地状态/断点缓存保护，永不离开设备 |

### 3.3 确定性身份标识与 `DeviceCard` 绑定签名
1. **规范中继源 `canonical_relay_origin`**：小写 `scheme://host:port`，**必须显式包含端口**（如 `https://relay.example.com:443`、`https://1.2.3.4:54843`），无尾部斜杠。
   - `relay_id = hex(SHA256(utf8("synctool-v1/relay-id:") || utf8(canonical_relay_origin))[0:16])`（32 位小写 hex）。
2. **设备唯一标识 `device_id`**：
   - `device_id_raw = SHA256(utf8("synctool-v1/device-id:") || sign_pk(32B))[0:16]`（16 字节原始二进制）。
   - 文本/JSON 形态：`device_id = hex(device_id_raw)`（32 位小写 hex）。
3. **中继盲化信箱标识 `mailbox_id`**：
   - `mailbox_id = hex(SHA256(utf8("synctool-v1/mailbox-id:") || mailbox_auth_pk(32B))[0:16])`（32 位小写 hex）。
   - **防抢注规则**：设备向中继注册信箱时，中继**必须验证** `mailbox_id == DeriveMailboxID(mailbox_auth_pk)` 且请求带有对应 `mailbox_auth_sk` 的合法 `X-Sync-Mailbox-Sig`（Proof-of-Possession）。
4. **`DeviceCard` 密钥绑定签名**（证明 `kem_pk` 归属于 `sign_pk`）：
   ```
   card_sig_input =
       utf8("synctool-v1/device-card\n")
       || sign_pk(32B)
       || kem_pk(32B)
       || uint64_be(issued_at)

   card_sig = Ed25519.Sign(sign_sk, card_sig_input)   // 64B
   ```
   接收端写入信任录前**必须验证** `device_id == hex(SHA256("synctool-v1/device-id:" || sign_pk)[0:16])` 且 `Ed25519.Verify(sign_pk, card_sig_input, card_sig) == true`。

---

## 4. 流 1：一次性传输与首次设备绑定握手规范

流 1 运行于中继不透明信令房间 `/v1/rooms/{room_id}`，双方必须同时在线。  
`purpose` 取值与二进制编码：`"oneshot"` → `purpose_code = 0x01`；`"pair"` → `purpose_code = 0x02`。  
**熔断铁律**：任一端一旦验签、承诺校验或确认 MAC 失败，**必须立即调用房间中止接口销毁该房间**并擦零内存临时私钥，确保主动中间人仅获 1 次尝试机会。

### 4.1 子模式 1A：`mode = 1`（`qr_oob_x25519`，扫码主路径）

1. **初始化（发起方 Alice）**：
   - 生成 16B（128-bit）随机 `oob_secret`、临时 X25519 `(e_a, E_a)`、32B 随机 `n_a`。
   - 向中继建房获取 8 字符规范 `room_id`，通过二维码线下展示 `synctool://pair?r=<room_id>&m=1&p=<purpose>#s=<b64u(oob_secret)>`（`oob_secret` **绝不经中继传输**）。
   - 上报 **M1**：
     ```json
     {"proto_v":1,"mode":1,"purpose":"oneshot","e_a":"<b64u(32B)>","n_a":"<b64u(32B)>"}
     ```
2. **响应（接收方 Bob）**：
   - 扫码解析 `room_id` 与 `oob_secret`，拉取 M1，生成临时 X25519 `(e_b, E_b)` 与 32B 随机 `n_b`。
   - 计算共享密钥与握手摘要：
     ```
     shared = X25519(e_b, E_a)                           // 拒全零
     transcript_1 =
         utf8("synctool-v1/hs-qr")                       // 17B
         || uint8(purpose_code)                          //  1B (0x01 or 0x02)
         || utf8(room_id)                                //  8B (大写无连字符)
         || E_a(32B) || n_a(32B) || E_b(32B) || n_b(32B) // 128B (总计 154B)
     th = SHA256(transcript_1)                           // 32B
     prk = HKDF-Extract(salt = th, ikm = shared(32B) || oob_secret(16B))

     session_key   = HKDF-Expand(prk, utf8("synctool-v1/session-key"), 32)
     confirm_key_b = HKDF-Expand(prk, utf8("synctool-v1/confirm-b"),   32)
     confirm_key_a = HKDF-Expand(prk, utf8("synctool-v1/confirm-a"),   32)
     mac_b         = HMAC-SHA256(confirm_key_b, th)      // 32B
     ```
   - 上报 **M2**：
     ```json
     {"proto_v":1,"mode":1,"e_b":"<b64u(32B)>","n_b":"<b64u(32B)>","mac_b":"<b64u(32B)>"}
     ```
3. **确认（Alice → Bob）**：
   - Alice 拉取 M2，按相同公式推导 `th, prk, session_key, confirm_key_b, confirm_key_a`，**常量时间校验 `mac_b`**。失败立即中止并销毁房间。
   - 校验通过后计算 `mac_a = HMAC-SHA256(confirm_key_a, th)`，上报 **M3**：
     ```json
     {"proto_v":1,"mode":1,"mac_a":"<b64u(32B)>"}
     ```
   - Bob 拉取 M3 并**常量时间校验 `mac_a`**。至此双方建立防 MITM、前向保密的 `session_key`。

### 4.2 子模式 1B：`mode = 2`（`commit_sas_x25519`，无摄像头/跨城兜底）

采用 **3 步 Commit-Reveal（承诺-揭示）**，从密码学上彻底阻断主动中间人看到双方公钥后本地暴力碰撞 6 位 SAS 的攻击：

1. **M1 承诺（Alice → 中继）**：
   - Alice 生成临时 X25519 `(e_a, E_a)` 与 32B 随机 `n_a`，**暂不发送 `E_a` 与 `n_a`**，仅计算承诺：
     ```
     commit_a = SHA256(
         utf8("synctool-v1/commit")    // 18B
         || uint8(purpose_code)        //  1B
         || utf8(room_id)              //  8B
         || E_a(32B)                   // 32B
         || n_a(32B)                   // 32B (输入总计 91B)
     )                                 // 32B
     ```
   - 上报 **M1**：
     ```json
     {"proto_v":1,"mode":2,"purpose":"oneshot","commit_a":"<b64u(32B)>"}
     ```
2. **M2 响应（Bob → 中继）**：
   - Bob 输入明码 `room_id`，拉取并锁定 `commit_a`，生成临时 X25519 `(e_b, E_b)` 与 32B 随机 `n_b`，上报 **M2**：
     ```json
     {"proto_v":1,"mode":2,"e_b":"<b64u(32B)>","n_b":"<b64u(32B)>"}
     ```
3. **M3 揭示（Alice → 中继）**：
   - Alice 拉取 M2，计算：
     ```
     shared = X25519(e_a, E_b)                           // 拒全零
     transcript_2 =
         utf8("synctool-v1/hs-sas")                      // 18B
         || uint8(purpose_code)                          //  1B
         || utf8(room_id)                                //  8B
         || commit_a(32B)                                // 32B
         || E_a(32B) || n_a(32B) || E_b(32B) || n_b(32B) // 128B (总计 187B)
     th = SHA256(transcript_2)                           // 32B
     prk = HKDF-Extract(salt = th, ikm = shared(32B))

     session_key   = HKDF-Expand(prk, utf8("synctool-v1/session-key"), 32)
     sas_bytes     = HKDF-Expand(prk, utf8("synctool-v1/sas"),          4)
     confirm_key_a = HKDF-Expand(prk, utf8("synctool-v1/confirm-a"),   32)
     confirm_key_b = HKDF-Expand(prk, utf8("synctool-v1/confirm-b"),   32)

     sas_int = uint32_be(sas_bytes) % 1000000            // 0..999999
     sas_str = zero_pad_6_digits(sas_int)                // 例如 "042819"，展示为 "042 819"
     mac_a   = HMAC-SHA256(confirm_key_a, th)            // 32B
     ```
   - 上报 **M3**：
     ```json
     {"proto_v":1,"mode":2,"e_a":"<b64u(32B)>","n_a":"<b64u(32B)>","mac_a":"<b64u(32B)>"}
     ```
   - **硬约束**：此时 Alice **严禁**上传任何业务密文，进入等待人工核验状态。
4. **M4 校验与防盲点人工核验（Bob & Alice）**：
   - Bob 拉取 M3，**第一步先验承诺**：重算 `SHA256("synctool-v1/commit" || purpose_code || room_id || E_a || n_a)` 并常量时间比对 `commit_a`；不符立即中止并销毁房间。
   - Bob 派生 `th, prk, session_key, sas_str, confirm_key_a, confirm_key_b`，**常量时间校验 `mac_a`**；不符立即销毁房间。
   - 校验通过后：Bob 上报 **M4** `{"proto_v":1,"mode":2,"mac_b":"<b64u(HMAC-SHA256(confirm_key_b, th))>"}` 并在屏幕展示 6 位 `sas_str`（`sas_str` **绝不经中继发送**）。
   - Alice 收到 M4 校验 `mac_b` 通过后，UI **强制要求用户输入 Bob 屏幕上的 6 位 `sas_str`**（本地常量时间比对，允许最多 2 次防手误输入重试；超限或用户点拒绝立即销毁房间）。比对一致后方才放行后续数据传输或设备绑定。

### 4.3 握手成功后的分叉产出

- **若 `purpose == "oneshot"`（一次性按需传输，走 Mode A 实时管道）**：
  - **数据面 `part_id = 0`（Manifest）密钥派生**（严格两步 `HKDF-Extract + HKDF-Expand`，确保 Go `crypto/hkdf.Key` 与 WebCrypto `SubtleCrypto.deriveBits` 单调用 100% 互通；随机 `msg_id` 为 16B，经下方加密 `pipe_start` 控制帧传递）：
    ```
    oneshot_prk        = HKDF-Extract(salt = msg_id(16B), ikm = session_key(32B))
    part0_key          = HKDF-Expand(oneshot_prk, utf8("synctool-v1/oneshot-part0-key"), 32)
    part0_nonce_prefix = HKDF-Expand(oneshot_prk, utf8("synctool-v1/oneshot-part0-np"),   7)
    ```
  - **房间加密控制帧契约（`POST /v1/rooms/{room_id}/messages`, `kind: "control"`）**：
    - 密钥派生：
      ```
      ctrl_prk = HKDF-Extract(salt = th(32B), ikm = session_key(32B))
      ctrl_key = HKDF-Expand(ctrl_prk, utf8("synctool-v1/pipe-ctrl-key"), 32)
      ctrl_np  = HKDF-Expand(ctrl_prk, utf8("synctool-v1/pipe-ctrl-np"),   7)
      ```
    - 序号与防重放：`ctrl_seq` 为 `uint32` 单调递增序号，**发起/发送方使用偶数 `0, 2, 4, ...`**，**接收方使用奇数 `1, 3, 5, ...`**（接收端必须校验对端 `ctrl_seq` 奇偶性正确且严格大于已收序号）。
    - Nonce 与 AAD（57 字节定长）：
      ```
      nonce(12B) = ctrl_np(7B) || uint32_be(ctrl_seq) || uint8(0x00)
      aad(57B)   = utf8("synctool-v1/pipe-ctrl") || th(32B) || uint32_be(ctrl_seq)
      ```
    - 线缆格式（`msg_b64` 解码后的 UTF-8 JSON）：`{"ctrl_seq":0,"ct":"<b64u(AES-256-GCM 密文+16B Tag)>"}`。
    - 冻结的两条明文 JSON 控制指令：
      1. 发送方启动管道：`{"op":"pipe_start","msg_id":"<32 hex>","blocks_per_chunk":16,"parts":[{"part_id":0,"total_bytes":4112,"chunk_count":1}]}`（`part_id` 范围 `0..63`）；
      2. 接收方全部落盘验签通过后回报：`{"op":"pipe_ack","msg_id":"<32 hex>"}`（随后双方调用 `POST /v1/rooms/{room_id}/close`，`reason: "completed"`）。
  - 传输结束立即擦零 `session_key`、`ctrl_key` 与 `part0_key`，不留长期信任状态。

- **若 `purpose == "pair"`（首次绑定设备名片）**：
  - 若中继能力 `/v1/caps` 显示 `spool.enabled == true`：双方先分别在本端为对方生成全新 32B 随机 `deposit_token`，并将其哈希注册到己方中继信箱；若中继关闭暂存（`--spool=off`，即 `spool.enabled == false`）：**跳过信箱注册**，下方 `PairBindPayload.mailbox` 置为 `null` 或省略（仍可完成设备绑定并走流 2 Mode A 直传）。
  - 双方在房间内交换加密 `PairBindPayload`：
    ```
    pair_nonce_a = HKDF-Expand(prk, utf8("synctool-v1/pair-nonce-a"), 12)
    pair_nonce_b = HKDF-Expand(prk, utf8("synctool-v1/pair-nonce-b"), 12)
    ct_a = AES-256-GCM.Seal(session_key, pair_nonce_a, utf8(json_a), aad = utf8("synctool-v1/pair-bind/a") || th(32B))
    ct_b = AES-256-GCM.Seal(session_key, pair_nonce_b, utf8(json_b), aad = utf8("synctool-v1/pair-bind/b") || th(32B))
    ```
  - `PairBindPayload` 明文 JSON（`device_card.platform` 为可选字段；`mailbox` 为条件可选，`spool.enabled == false` 时为 `null` 或省略）：
    ```json
    {
      "device_card": {
        "device_id": "<32 hex>",
        "sign_pk": "<b64u 32B>",
        "kem_pk": "<b64u 32B>",
        "issued_at": 1764246000,
        "card_sig": "<b64u 64B>",
        "label": "书房台式机",
        "platform": "windows"
      },
      "mailbox": {
        "relay_origin": "https://relay.example.com:443",
        "mailbox_id": "<32 hex>",
        "deposit_token": "<b64u 32B>"
      }
    }
    ```
  - 双方解密并校验 `DeviceCard` 签名无误后，各自持久化对端名片并立即销毁房间与 `session_key`。

---

## 5. 流 2：已绑定设备 0-RTT 认证封装与 Sealed Sender

适用于一切已绑定设备间的定向推送，**统一覆盖 Mode B 暂存箱与 Mode A 超限/无暂存直传**。协议头 `SealedHeader` 固定为 **208 字节**（`b64u` 编码固定 **278 字符**），作为不透明字段 `sealed_header` 在 `init` 时提交给中继，使 `part_id = 0` 及 `1..N` 保持 100% 纯粹的 STREAM AEAD 分块结构。

### 5.1 固定 56 字节明文头 `clear_header`

| 偏移 | 长度 | 字段名 | 说明 |
| :--- | :--- | :--- | :--- |
| `0` | 4 B | `magic` | 固定 ASCII `"ST01"`（`0x53 0x54 0x30 0x31`） |
| `4` | 1 B | `mode` | 固定 `0x02`（`paired_0rtt`） |
| `5` | 1 B | `flags` | v1 固定 `0x00`（bit 0 预留 V2 `has_prekey_id` OTPK 扩展） |
| `6` | 2 B | `reserved` | 固定 `0x0000` |
| `8` | 16 B | `msg_id` | 16B CSPRNG 随机消息唯一标识（与防重放表、STREAM AAD 绑定） |
| `24` | 32 B | `ephemeral_pk` | 发送方为本条消息全新生成的临时 X25519 公钥 $E_A$ |

> 合计 `56 B`；中继仅可见 `magic/mode`、随机 `msg_id` 和随机 $E_A$，**完全不可见发送方、接收方、应用类型与时间**。

### 5.2 密钥派生与 152 字节 `sealed_box` 构造
1. 发送方 A 生成随机 `msg_id(16B)`、临时 X25519 `(e_A, E_A)`，先构造并哈希明文 Manifest（见 §6.3）：
   `manifest_sha256 = SHA256(manifest_utf8_bytes)`（32B，不含 Padding 字节与 4B 长度前缀）。
2. 查本地受信任名片取出目标设备 B 的 `kem_pk_B`，计算：
   ```
   dh = X25519(e_A, kem_pk_B)                                  // 拒全零
   hdr_prk            = HKDF-Extract(salt = clear_header(56B), ikm = dh(32B))
   hdr_key            = HKDF-Expand(hdr_prk, utf8("synctool-v1/0rtt-hdr-key"),   32)
   hdr_nonce          = HKDF-Expand(hdr_prk, utf8("synctool-v1/0rtt-hdr-nonce"), 12)
   part0_key          = HKDF-Expand(hdr_prk, utf8("synctool-v1/0rtt-part0-key"), 32)
   part0_nonce_prefix = HKDF-Expand(hdr_prk, utf8("synctool-v1/0rtt-part0-np"),   7)
   ```
3. 计算发送方 Ed25519 签名（**精确 149 字节签名原文**）：
   ```
   sig_input(149B) =
       utf8("synctool-v1/0rtt-sig\n")  // 21B
       || clear_header(56B)            // 56B (锁定 magic/mode/msg_id/E_A)
       || sender_device_id_raw(16B)    // 16B
       || recipient_device_id_raw(16B) // 16B (防定向误投/UKS 攻击)
       || uint64_be(created_at)        //  8B (Unix 秒)
       || manifest_sha256(32B)         // 32B (间接锁定 Manifest 与其内所有 Blob 密钥和 SHA-256)
   ```
   ```
   sender_sig = Ed25519.Sign(sign_sk_A, sig_input)             // 64B
   ```
4. 组装 **136 字节** `sealed_box_plaintext` 并加密：
   ```
   sealed_box_plaintext(136B) =
       sender_device_id_raw(16B)
       || recipient_device_id_raw(16B)
       || uint64_be(created_at)(8B)
       || manifest_sha256(32B)
       || sender_sig(64B)

   sealed_box(152B) = AES-256-GCM.Seal(
       key       = hdr_key(32B),
       nonce     = hdr_nonce(12B),
       plaintext = sealed_box_plaintext(136B),
       aad       = clear_header(56B)
   )

   SealedHeader(208B) = clear_header(56B) || sealed_box(152B)
   ```
5. 发送方立即在内存中擦零临时私钥 `e_A`。

### 5.3 接收方校验顺序（零漏洞防重放/防伪造）
接收方 B 收到 `SealedHeader(208B)`（甚至早在拉取收件箱列表阶段）即按以下顺序校验，**任意一步失败立即拒收**：
1. 长度必须精确 `208 B`，`magic == "ST01"`，`mode == 0x02`，`flags == 0x00`，`reserved == 0x0000`。
2. 查询本地防重放缓存 `seen_msg_ids`：若 `msg_id` 已存在，直接丢弃（防恶意中继回放历史已领密文）。
3. 计算 `dh = X25519(kem_sk_B, E_A)`（拒全零），派生 `hdr_key, hdr_nonce, part0_key, part0_nonce_prefix`，以 `aad = clear_header(56B)` 解密 `sealed_box(152B)`。
4. 校验 `recipient_device_id_raw == self.device_id_raw`。
5. 以 `sender_device_id_raw` 查询本地受信任 `DeviceCard` 列表：若不存在或已被吊销，立即拒绝（防已吊销设备继续投递）。
6. 重构 `sig_input(149B)` 并验证 `Ed25519.Verify(sender_card.sign_pk, sig_input, sender_sig) == true`。
7. 下载并 STREAM 解密 `part_id = 0`，去填充得到 `manifest_utf8_bytes`，校验 `SHA256(manifest_utf8_bytes) == manifest_sha256`。
8. 按 Manifest 中每个附件的 `(part_id, blob_key, sha256)` 逐块 STREAM 解密并校验整文件明文 `sha256`。
9. 全部落盘成功后，将 `(msg_id, created_at)` 写入本地持久化 `seen_msg_ids`（保留期须 ≥ 中继最大 TTL + 7 天，默认 30 天滚动窗口），再向中继发送签名 `ACK` 触发焚毁。

### 5.4 流 2 走 Mode A 零落盘直传契约（`--spool=off` 或超出暂存上限）
当已绑定设备因中继关闭暂存（`--spool=off`）或包裹体积超出暂存上限而使用 Mode A 实时管道直传时，完全复用 §5.1–§5.3 的 `SealedHeader(208B)` 与 STREAM 分块格式，不引入额外握手算法：
1. **建房与初始载荷**：发送端向中继调用 `POST /v1/rooms` 获取明码 `room_id`（通过 `synctool://pair?r=<room_id>&m=0&p=direct...` 不带 `#s=` 传递给接收端），`initial_msg_b64` 解码为以下 JSON（`part_id` 范围 `0..63`）：
   ```json
   {
     "proto_v": 1,
     "mode": 0,
     "purpose": "direct",
     "sealed_header": "<278-char b64u>",
     "blocks_per_chunk": 16,
     "parts": [{"part_id": 0, "total_bytes": 4112, "chunk_count": 1}]
   }
   ```
2. **接收端验签与熔断**：接收端调用 `POST /v1/rooms/{room_id}/join` 读取 M1，严格按 §5.3 步骤 1–6 校验 `sealed_header`（含 `seen_msg_ids` 防重放、受信任未吊销 `DeviceCard` 与 Ed25519 验签）。**任一步失败必须立即调用 `POST /v1/rooms/{room_id}/close`（`reason: "verify_failed"`）熔断销毁房间。**
3. **流式传输与防伪造 `direct_ack`**：接收端按 `parts/{part_id}/chunks/{tx_idx}` 经 Mode A 管道拉取全部密文块，校验 `part_id=0` 的 `manifest_sha256` 及所有附件 STREAM AEAD 与 `sha256` 并写入 `seen_msg_ids` 后，经 `POST /v1/rooms/{room_id}/messages`（`kind: "control"`）发送防中继伪造的确认帧（`msg_b64` 解码为明文 JSON）：
   ```json
   {
     "op": "pipe_ack",
     "msg_id": "<32 hex>",
     "ack_mac": "<b64u(32B)>"
   }
   ```
   其中：
   ```
   ack_mac = HMAC-SHA256(part0_key(32B), utf8("synctool-v1/direct-ack") || msg_id(16B))
   ```
   发送端常量时间校验 `ack_mac` 通过后，双方调用 `/close`（`reason: "completed"`）结束管道。

---

## 6. STREAM 分块流式 AEAD 与填充规范

适用于所有 `part_id`（范围 `0..63`：`0` 为加密 Manifest，`1..63` 为不透明附件槽），同时兼容 Mode A 实时流式管道与 Mode B 分片断点续传。

### 6.1 加密原子块与传输分片解耦规则
- **加密原子块常量（全档位恒定不变）**：
  - `CHUNK_PLAINTEXT_MAX = 65536`（`64 KiB`）
  - `AEAD_TAG_LEN = 16`
  - `CHUNK_CIPHERTEXT_MAX = 65552`（`64 KiB + 16 B`）
- **切块规则（给定某 `part_id` 明文总长 `S` 字节）**：
  - 若 `S == 0`：产出 **1 块**（`block_idx = 0, is_final = 0x01, plaintext_len = 0`，密文 `16 B`）。
  - 若 `S > 0`：产出 `total_blocks = ceil(S / 65536)` 块：
    - `block_idx = 0 .. total_blocks - 2`：`plaintext_len = 65536`、`is_final = 0x00`、密文严格 `65,552 B`。
    - `block_idx = total_blocks - 1`：`plaintext_len = ((S - 1) % 65536) + 1`（`1..65536`）、`is_final = 0x01`、密文 `plaintext_len + 16 B`。
- **HTTP 传输分片对齐（`.../parts/{part_id}/chunks/{tx_idx}`）**：
  - 传输分片 `tx_idx` 仅是将连续 `N` 个加密原子块（`block_idx = tx_idx * N .. min(total_blocks, (tx_idx+1)*N) - 1`）**直接顺次无额外帧头拼接**。
  - `N` 由中继 `/v1/caps` 下发：`nano = 4`（`262,208 B`）、`standard = 16`（`1,048,832 B`）、`media = 32`（`2,097,664 B`）；每个 `part_id` 的最后一片允许 `≤ N × 65,552 B`。
  - **解码边界**：收端对每片按 `65,552 B` 步长切分；最后一块（由 Manifest 已知 `total_blocks` 或 `part_id = 0` 的 EOF 确定）置 `is_final = 0x01` 验签。任何截断导致缺失 `is_final = 0x01` 认证块均视为传输未完成/被篡改，绝不交付业务层。

### 6.2 每附件独立密钥、12B 确定性 Nonce 与 46B 定长 AAD
1. **密钥与 Nonce 前缀**：
   - `part_id = 0`：直接使用流 1（§4.3）或流 2（§5.2）产出的 `(part0_key, part0_nonce_prefix)`。
   - `part_id = 1..N`：发送方为每个附件生成全新 32B CSPRNG `blob_key`（写入加密 Manifest 中对应附件的 `key` 字段），按下式派生：
     ```
     part_prk     = HKDF-Extract(salt = msg_id(16B) || uint32_be(part_id), ikm = blob_key(32B))
     enc_key      = HKDF-Expand(part_prk, utf8("synctool-v1/blob-enc-key"),      32)
     nonce_prefix = HKDF-Expand(part_prk, utf8("synctool-v1/blob-nonce-prefix"),  7)
     ```
2. **12 字节确定性 Nonce**：
   ```
   nonce(12B) = nonce_prefix(7B) || uint32_be(block_idx) || uint8(is_final)
   ```
   （单附件支持最高 $2^{32} \times 64\text{ KiB} = 256\text{ TiB}$，杜绝任何 Nonce 重用与断点续传重放 Nonce 风险。）
3. **46 字节定长二进制 AAD**：
   ```
   AAD(46B) =
       utf8("synctool-chunk-v1")   // 17B
       || msg_id(16B)              // 16B
       || uint32_be(part_id)       //  4B
       || uint32_be(block_idx)     //  4B
       || uint8(is_final)          //  1B (0x00 or 0x01)
       || uint32_be(plaintext_len) //  4B (0..65536)
   ```
   > 校核长度：`17 + 16 + 4 + 4 + 1 + 4 = 46 B`。
4. **单块加解密**：
   `ct_block = AES-256-GCM.Seal(enc_key, nonce, pt_block, AAD)`

### 6.3 Manifest 4 KiB 分桶填充与压缩禁令
- **Manifest 填充（仅 `part_id = 0`，防小消息体积侧信道）**：
  - 设 `manifest_utf8_bytes` 长度为 `L`（`0 < L <= 131072`，其中业务 `inline_payload <= 65536`）。
  - 向上对齐至 `4096 B`（4 KiB）整数倍：`total_len = ceil((4 + L) / 4096) * 4096`，`pad_len = total_len - 4 - L`。
  - 构造明文输入：`padded_manifest = uint32_be(L) || manifest_utf8_bytes(L) || (0x00 * pad_len)`，再进入 STREAM AEAD（`part_id = 0`）。
  - 解密后必须校验：`len >= 4`、`len % 4096 == 0`、`4 + L <= len`、且尾部全部 `pad_len` 字节严格为 `0x00`（否则拒绝）。
- **压缩禁令**：`synctool` 协议层与 SDK **严禁对 `part_id >= 1`（图/视频/语音等）自动执行压缩**（杜绝无收益耗电、手机 OOM 与压缩侧信道）。纯文本压缩仅允许业务层自行决定并在加密前处理。

---

## 7. 中继接入鉴权、时钟防死锁、信箱验签与 TLS 规范

### 7.1 `RELAY_ACCESS_KEY` 派生与必选请求头
- **零公开默认密钥**：中继绝不内置公开硬编码默认密钥；首次 `init`/启动若未通过环境变量提供，自动生成 32B CSPRNG 随机密钥并编码为 43 字符无填充 `b64u` 仅向 TTY 打印（严禁写入运行日志）。手动配置时长度**必须 ≥ 32 字符**。
- **HMAC 密钥统一派生**（兼容自动生成与人工环境变量字符串，消除 Base64 格式坑）：
  ```
  relay_hmac_key = SHA256(utf8("synctool-v1/access-key:") || utf8(access_key_string))  // 32B
  ```
- **所有已鉴权接口必带请求头**：
  - `X-Sync-TS`：ASCII 十进制 Unix 秒时间戳（如 `1764246000`）。
  - `X-Sync-Nonce`：32 位小写 hex（16 字节 CSPRNG 随机数）。
  - `X-Sync-Sig`：64 位小写 hex = `hex(HMAC-SHA256(relay_hmac_key, canonical_req))`。
- **按接口可选附带的凭证头**：
  - `X-Sync-Deposit-Token`：43 字符 `b64u`（32B 随机投递令牌，用于 `POST /v1/spool/init`）。
  - `X-Sync-Upload-Token`：43 字符 `b64u`（32B 中继签发的单次上传会话令牌，用于 `PUT /v1/spool/{item_id}/parts/{part_id}/chunks/{tx_idx}`、`POST /v1/spool/{item_id}/commit` 与 `DELETE /v1/spool/{item_id}`）。
  - `X-Sync-Mailbox-Sig`：86 字符 `b64u`（64B Ed25519 签名，用于一切信箱所有者管理/拉取/订阅/ACK 即焚操作）。

### 7.2 `X-Sync-Sig` 精确签名原文（控制面 vs 数据面分离）
```
canonical_req =
    METHOD               + "\n" +   // 大写：GET / POST / PUT / DELETE
    PATH_AND_RAW_QUERY   + "\n" +   // 如 "/v1/spool/init" 或 "/v1/mailboxes/<id>/events?since_ts=0"
    X-Sync-TS            + "\n" +
    X-Sync-Nonce         + "\n" +
    BODY_BINDING         + "\n" +
    EXTRA_TOKEN_BINDING
```
> **`PATH_AND_RAW_QUERY` 规范化说明**：无查询参数时**不带尾部 `?`**，有查询参数时原样拼接 `"?" + raw_query`（等价于 Go `r.URL.RequestURI()` 及 JS `url.pathname + url.search`）。
1. **`BODY_BINDING`（两类域分离，彻底杜绝大文件缓冲验签）**：
   - **控制面接口**（除数据面分片 `PUT` 外的全部端点，包括 `GET`/`POST`/`DELETE`/SSE）：
     `"sha256:" + hex(SHA256(raw_request_body))`  
     （空请求体固定为 `"sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"`。）
   - **数据面分片上传接口**（`PUT /v1/pipe/{pipe_id}/parts/{part_id}/chunks/{tx_idx}` 与 `PUT /v1/spool/{item_id}/parts/{part_id}/chunks/{tx_idx}`）：
     `"stream:" + decimal_content_length`  
     （**强制要求显式非负整数 `Content-Length`**，拒绝 `Transfer-Encoding: chunked`；服务端绝不整包缓冲验签，密文完整性由端到端 STREAM AEAD 保证。）
2. **`EXTRA_TOKEN_BINDING`**：
   - 若请求含 `X-Sync-Deposit-Token`：`"deposit:" + hex(SHA256(utf8("synctool-v1/deposit-token:") || utf8(X-Sync-Deposit-Token)))`
   - 否则若请求含 `X-Sync-Upload-Token`：`"upload:" + hex(SHA256(utf8("synctool-v1/upload-token:") || utf8(X-Sync-Upload-Token)))`
   - 否则：`""`（空字符串，其前面的 `"\n"` 仍保留）。

### 7.3 服务端鉴权执行顺序与 `409 ERR_CLOCK_SKEW` 防死锁规则
服务端中间件**必须严格按以下 5 步顺序执行**：
1. **格式与大小预检**：缺头、非法字符或控制面请求体超限（`> 16 KiB`）→ `strike++`，返回静默空 `404`（移除 `Server` 头 + `Connection: close`）。
2. **第一步先验 `X-Sync-Sig`（常量时间比对）**：未通过 → `strike++`，返回静默空 `404`。**严禁向未通过 HMAC 校验的外部扫描器泄露时间戳或端点存在性。**
3. **第二步校验时钟窗口（±60s）**：若 `|ts - server_unix_now| > 60`：
   - **严禁写入 nonce 缓存**、**严禁执行任何业务副作用**、**照常计入单 IP 限流**；
   - 返回 HTTP `409 Conflict`：
     ```json
     {"error":"ERR_CLOCK_SKEW","server_ts":1764246000,"max_skew_sec":60}
     ```
   - 客户端仅在验过 TLS（含 SPKI Pin）后信任 `server_ts`，缓存进程内时钟偏移并换用**新 `X-Sync-Nonce`** 自动重试 1 次。
4. **第三步校验并写入 `X-Sync-Nonce` 去重表**：
   - 仅当步骤 2 与 3 均通过后才写入（防未授权流量打爆内存）；
   - 有界滑动缓存：上限 **`8,192` 条**，单条 TTL **`120 秒`**（超上限按最旧淘汰）。命中重复 nonce 返回 HTTP `401` `{"error":"ERR_REPLAY_DETECTED"}`。
5. **第四步执行端点专属鉴权**：信箱所有权签名（§7.4）、投递令牌匹配（§7.4）或房间/上传会话令牌校验。

### 7.4 信箱所有权签名（`X-Sync-Mailbox-Sig`）与单设备 `deposit_token` 吊销
1. **信箱所有者签名原文（Ed25519，由 `mailbox_auth_sk` 签发）**：
   ```
   mailbox_sig_input =
       "synctool-v1/mailbox-auth\n" +
       METHOD             + "\n" +
       PATH_AND_RAW_QUERY + "\n" +
       mailbox_id         + "\n" +
       X-Sync-TS          + "\n" +
       X-Sync-Nonce       + "\n" +
       BODY_BINDING
   ```
   - 所有信箱注册/更新、增删 `deposit_token_hash`、列举待领条目、SSE 事件订阅、拉取暂存分片、发送 `ACK` 焚毁请求均强制校验 `X-Sync-Mailbox-Sig`。
2. **多对端独立 `deposit_token` 与精准吊销**：
   - 每个信箱在服务端最多绑定 **`16` 条** `deposit_token_hash`（每条 32B = `hex(SHA256("synctool-v1/deposit-token:" || utf8(deposit_token)))`），中继**绝不存明文 `deposit_token`**。
   - 发送端调用 `POST /v1/spool/init` 向某 `mailbox_id` 投递时，须在 `X-Sync-Deposit-Token` 携带配对时获颁的令牌；服务端常量时间遍历匹配该信箱的 `≤ 16` 条哈希。
   - **单设备丢失吊销**：机主在另一台设备上删除丢失设备的 `DeviceCard`，并凭 `X-Sync-Mailbox-Sig` 请求中继删除该丢失设备对应的单条 `deposit_token_hash`，**其余所有已绑定设备零影响**。

### 7.5 传输层 TLS、裸 IP 强制 SPKI Pinning 与证书寿命
- **禁止无校验跳过证书**：彻底废除类似 GravitySSH `RelayTLSModeSelfSignedIP` 的跳过校验行为。
- **裸 IP 自建模式（`tls=selfsigned`）**：
  - 自动生成并持久化 ECDSA P-256 自签证书，必须包含 `ExtKeyUsageServerAuth` EKU 及明确的 IP/DNS SAN；
  - 证书有效期锁定 **730 天（2 年）**，严格低于 Apple 平台 `≤ 825` 天叶证书兼容红线；
  - 服务端计算证书公钥指纹 `pin = hex(SHA256(DER(SubjectPublicKeyInfo)))`（64 位小写 hex），写入配置 URI `synctool://relay?...#k=<access_key>`；客户端必须严格校验叶证书 SPKI SHA-256 精确匹配，并在 `/v1/ping` 返回的 `cert_expires_at` 剩余 **< 30 天** 时向用户触发轮换提醒。
- **反代模式（`tls=off`）**：服务端仅允许在监听地址为 loopback（`127.0.0.1` / `::1`）或显式配置 `TRUSTED_PROXIES` 时启用 `tls=off`；客户端对外部反代域名强制走系统根 CA 的 TLS 1.3。
- **URI 安全红线**：`synctool://relay?...` 与 `synctool://pair?...` 中的敏感密钥（`k`、`s`）置于 `#fragment`（防止出现在 HTTP 请求或反代日志中）；所有客户端严禁将含密钥 URI 写入日志/崩溃上报，移动端严禁注册系统全局 Deep Link 拦截该 scheme。

---

## 8. 阶段 1 必须交付的黄金测试向量清单（`spec/test-vectors/`）

为保证 Go、TypeScript（WebCrypto）及未来 Dart / Kotlin / Swift 实现 **100% 字节级互通零偏差**，阶段 1 编码伊始必须先以 Go 参考实现生成并由 `sdk/ts` 交叉跑通以下 **7 份黄金测试向量 JSON**：

| 文件名 | 必须覆盖的正向与负向（破坏性）用例 |
| :--- | :--- |
| `01_seed_and_keys.json` | 固定 `device_master_seed` → `master_prk`、`sign_seed/sign_pk`、`kem_sk/kem_pk`、`device_id`、`relay_id`、`mailbox_auth_pk`、`mailbox_id`、`DeviceCard` 绑定签名、以及 48B Ed25519/X25519 PKCS#8 DER 字节（供 WebCrypto 验测）。 |
| `02_relay_auth_sig.json` | 控制面 JSON 体 `X-Sync-Sig`、空体 GET `X-Sync-Sig`、数据面 `stream:<len>` `X-Sync-Sig`、`deposit:` 与 `upload:` 令牌绑定、`X-Sync-Mailbox-Sig` Ed25519 验签，以及 `±60s` 通过 / `±61s` 触发 `409 ERR_CLOCK_SKEW` 边界用例。 |
| `03_handshake_qr_oob.json` | `mode=1` 完整 `M1/M2/M3`、`transcript_1`、`th`、`session_key`、`mac_a`/`mac_b`、`oneshot_prk`/`part0_key`/`part0_nonce_prefix`、`pipe_ctrl` 加密控制帧（`ctrl_key`/`ctrl_np`/57B AAD/`pipe_start` & `pipe_ack`）及 `PairBindPayload`（含 `mailbox: null` 场景）加解密；负向：`oob_secret` 差 1 bit 拒收、低阶全零 X25519 公钥拒收、`ctrl_seq` 奇偶或单调性违规拒收。 |
| `04_handshake_commit_sas.json` | `mode=2` 完整 3 步 `commit_a`、`transcript_2`、`th`、`session_key`、6 位 `sas_str`（含前导零如 `"004219"` 用例）、`mac_a`/`mac_b` 与 `pipe_ctrl` 控制帧；负向：揭示阶段篡改 `E_a` 触发承诺不符拒收。 |
| `05_paired_0rtt_envelope.json` | 完整 208B `SealedHeader`（56B `clear_header` + 152B `sealed_box`）、149B `sig_input`、`part0_key`/`part0_nonce_prefix`、以及流 2 Mode A 直传的 `direct_ack`（`HMAC-SHA256(part0_key, "synctool-v1/direct-ack" \|\| msg_id)`）；负向：篡改 `clear_header`、错误 `recipient_device_id`、无效 Ed25519 签名、重复 `msg_id` 拒收、伪造 `ack_mac` 拒收。 |
| `06_stream_aead_and_padding.json` | Manifest 4 KiB 分桶填充（边界：`L=0` 拒收、`L=1`、`L=4092`、`L=4093`、`L=65532`，及非零尾填充拒收）；STREAM AEAD 多块加解密（`0 B` 空文件、`100 B`、`65,536 B` 整块、`65,537 B` 两块、`300,000 B` 按 `nano=4` 与 `standard=16` 打包）；负向：块乱序、截断缺失 `is_final=0x01`、跨 `part_id` 拼接、篡改 1 字节 Tag 全部必须拒收。 |
| `07_crockford_room_id.json` | 5B 随机输入 ↔ 8 字符 Crockford Base32 双向映射（含全 `0x00` 与全 `0xFF` 边界）、大小写/连字符/`O→0`/`I,L→1` 规范化、非法字符拒绝。 |
