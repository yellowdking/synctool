# `synctool` Relay Server Protocol & Deployment Specification (`v1`)

> **Status**: Frozen Draft — Stage 0 (`synctool-v1`, **zero backward compatibility** with legacy GravitySSH `gssh-sync-v2`)  
> **Scope**: Normative HTTP/1.1 + HTTP/2 wire protocol, control/data plane separation, Mode A (Real-Time Zero-Disk Chunked Pipe), Mode B (Ephemeral Encrypted Spool), multi-tier VPS resource profiles, TLS/reverse-proxy rules, and anti-DoS gates for `synctool-relay`.  
> **Companion Specs**:
> - Cryptographic primitives, canonical signing strings, AEAD block layout, and handshake payloads: `spec/CRYPTO_AND_AUTH.md` (normative authority for all cryptographic byte layouts).
> - Envelope/Manifest JSON Schema, URI scheme, SDK matrix, and CLI contract: `spec/ENVELOPE_AND_SDK.md`.

---

## 1. Design Principles & Wire Conventions

1. **Zero-Trust Ciphertext Relay**: `synctool-relay` never holds decryption keys and never sees plaintext `app_id`, schemas, filenames, MIME types, device display names, or offline sender identities.
2. **Control Plane vs. Data Plane Separation**:
   - **Control Plane**: Small UTF-8 JSON (`application/json; charset=utf-8`), hard body limit **`16,384 B` (16 KiB)**.
   - **Data Plane**: Raw opaque encrypted binary chunks (`application/octet-stream`). **No JSON wrapping, no Base64 encoding, no relay-side `gzip` compression.**
   - **Event Plane**: On-demand Server-Sent Events (`text/event-stream; charset=utf-8`) with automatic Long-Poll JSON fallback (`mode=poll`).
3. **Zero Unbounded Buffering**:
   - Server **MUST NEVER** buffer full data-plane request bodies via `io.ReadAll`.
   - Data-plane requests stream strictly through `sync.Pool` fixed `32 KiB` (`nano`) or `64 KiB` (`standard`/`media`) buffers with `io.LimitReader` and mandatory `Content-Length` bounds.
4. **Canonical Encoding & Identifier Conventions** (aligned byte-for-byte with `spec/CRYPTO_AND_AUTH.md` §2.3 & §3.3):
   - Timestamps: Unix epoch seconds (`int64`, UTC).
   - Binary tokens/signatures/opaque payloads: **unpadded Base64url** (`b64u`, RFC 4648 §5, `A-Za-z0-9-_`), unless explicitly specified as lowercase hex (`[0-9a-f]`).
   - Identifiers:
     - `room_id`: **Exact 8 uppercase Standard Crockford Base32 chars** (`0123456789ABCDEFGHJKMNPQRSTVWXYZ`, 5 CSPRNG bytes = 40 bits, no hyphens on the wire; pure routing label, **never** used in key derivation).
     - `relay_id`: Deterministic 32-char lowercase hex derived by clients from `canonical_relay_origin` (`scheme://host:port`, explicit port, lowercase, no trailing slash): `hex(SHA256("synctool-v1/relay-id:" || canonical_relay_origin)[0:16])`.
     - `pipe_id`: 32-char lowercase hex (128-bit CSPRNG, server-issued, bound to a single room).
     - `mailbox_id`: 32-char lowercase hex = `hex(SHA256("synctool-v1/mailbox-id:" || mailbox_auth_pk(32B))[0:16])`.
     - `item_id`: `itm_` + 32-char lowercase hex (128-bit CSPRNG, server-issued).
     - `part_id`: unsigned integer `0..63` (`0` = encrypted Manifest, `1..63` = opaque binary attachment slots, max `64` parts per parcel).
     - `tx_idx`: unsigned integer `0..4294967295` (0-based HTTP transport chunk index within a `part_id`).

---

## 2. Transport Alignment with STREAM AEAD (`N × 65,552 B`)

Per `spec/CRYPTO_AND_AUTH.md` §6, the encryption layer slices each `part_id` into fixed `64 KiB` (`65,536 B`) plaintext blocks, producing **`65,552 B`** (`65,536 B + 16 B AES-256-GCM Tag`) ciphertext blocks (except the final block of a `part_id`, which may be `16..65,552 B`).

An HTTP transport chunk (`.../parts/{part_id}/chunks/{tx_idx}`) concatenates **`N` consecutive ciphertext blocks** verbatim without extra framing:

| VPS Profile | `blocks_per_chunk` (`N`) | `max_transport_chunk_bytes` (`N × 65,552 B`) | Approx. Size |
| :--- | :---: | :---: | :---: |
| `nano` | `4` | **`262,208 B`** | ~256 KiB |
| `standard` (default) | `16` | **`1,048,832 B`** | ~1 MiB |
| `media` | `32` | **`2,097,664 B`** | ~2 MiB |

- **Final Transport Chunk Rule**: For any `part_id`, the last transport chunk (`tx_idx = chunk_count - 1`) MAY be smaller than `max_transport_chunk_bytes` (down to `16 B` for a 0-byte empty part). The relay enforces `1 <= Content-Length <= max_transport_chunk_bytes` and does **not** require divisibility by `65,552 B`, preventing false rejection of final partial plaintext blocks.
- **Non-Final Chunk Convention**: Clients SHOULD pack full `N × 65,552 B` for all non-final chunks (`tx_idx < chunk_count - 1`).

---

## 3. Edge Access Control, Request Authentication & Stealth Rules

### 3.1 Required Relay Access Headers (All `/v1/*` Endpoints)

Per `spec/CRYPTO_AND_AUTH.md` §7.1–§7.2, every `/v1/*` HTTP request MUST carry:

| Header | Required | Format | Description |
| :--- | :---: | :--- | :--- |
| `X-Sync-TS` | **Yes** | Decimal Unix seconds (UTC) | Client wall-clock timestamp (e.g. `1764246000`). |
| `X-Sync-Nonce` | **Yes** | 32-char lowercase hex (16B CSPRNG) | Per-request replay nonce within 120s sliding window. |
| `X-Sync-Sig` | **Yes** | 64-char lowercase hex | `hex(HMAC-SHA256(relay_hmac_key, canonical_req))`, where `relay_hmac_key = SHA256("synctool-v1/access-key:" || access_key_string)`. |
| `X-Sync-Client` | No | `<agent>/<ver>` (1–64 ASCII, no spaces) | Optional diagnostic user-agent (e.g. `synctool-go/1.0`, `synctool-ts/1.0`). Must NOT contain personal device names or `app_id`. |

**Exact `canonical_req` Layout** (normative definition in `spec/CRYPTO_AND_AUTH.md` §7.2):
```text
METHOD               + "\n" +
PATH_AND_RAW_QUERY   + "\n" +   // No trailing "?" when query is empty (Go r.URL.RequestURI() / JS url.pathname + url.search)
X-Sync-TS            + "\n" +
X-Sync-Nonce         + "\n" +
BODY_BINDING         + "\n" +
EXTRA_TOKEN_BINDING
```
- **`BODY_BINDING`**:
  - **Control-Plane endpoints** (all endpoints except data-plane chunk `PUT`, body `<= 16 KiB`): `"sha256:" + hex(SHA256(raw_request_body))` (empty body = `"sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"`).
  - **Data-Plane chunk uploads** (`PUT /v1/pipe/.../chunks/{tx_idx}` and `PUT /v1/spool/.../chunks/{tx_idx}`): `"stream:" + decimal_content_length` (mandatory explicit non-negative `Content-Length`, `Transfer-Encoding: chunked` rejected). **Relay MUST NOT buffer chunk bodies for HMAC verification.**
- **`EXTRA_TOKEN_BINDING`**:
  - If `X-Sync-Deposit-Token` header present: `"deposit:" + hex(SHA256("synctool-v1/deposit-token:" || utf8(X-Sync-Deposit-Token)))`
  - Else if `X-Sync-Upload-Token` header present: `"upload:" + hex(SHA256("synctool-v1/upload-token:" || utf8(X-Sync-Upload-Token)))`
  - Else: `""` (empty string; preceding `"\n"` is retained).

### 3.2 Additional Route-Specific Auth Headers

| Header | Format | Used On |
| :--- | :--- | :--- |
| `X-Sync-Room-Token` | 43-char `b64u` (32B) | `/v1/rooms/{room_id}/messages`, `/events`, `/close`, and `/v1/pipe/{pipe_id}/...` (`sender_token` for `PUT`, `receiver_token` for `GET`). |
| `X-Sync-Mailbox-Sig` | 86-char `b64u` (64B Ed25519 sig) | All `/v1/mailboxes/{mailbox_id}*`, `GET /v1/spool/{item_id}/parts/...`, `POST /v1/spool/{item_id}/ack`. Signed over `"synctool-v1/mailbox-auth\n" + METHOD + "\n" + PATH_AND_RAW_QUERY + "\n" + mailbox_id + "\n" + X-Sync-TS + "\n" + X-Sync-Nonce + "\n" + BODY_BINDING` (`CRYPTO_AND_AUTH.md` §7.4). |
| `X-Sync-Deposit-Token` | 43-char `b64u` (32B) | `POST /v1/spool/init`. Verified in constant time against target mailbox's stored `SHA256("synctool-v1/deposit-token:" || utf8(token))` allowlist (max 16 entries). |
| `X-Sync-Upload-Token` | 43-char `b64u` (32B) | `PUT /v1/spool/{item_id}/parts/...`, `POST /v1/spool/{item_id}/commit`, `DELETE /v1/spool/{item_id}`. |

### 3.3 Mandatory 7-Step Validation Pipeline (Clock-Skew Deadlock Prevention + Stealth)

Requests MUST execute in this **strict order**:

1. **L4 TCP Gate (`limitListener`)**: Drop banned IPs immediately at `Accept()` (zero TLS/HTTP work); enforce global and per-IP active TCP connection limits.
2. **Real IP Extraction & Rate Limit**: Extract client IP via `TRUSTED_PROXIES` (§7.3); aggregate IPv6 to `/64`; enforce dual token buckets (`control` vs `stream/event`).
3. **Route, Header & Control-Body Size Check**: Unknown path, disallowed HTTP method, missing/malformed `X-Sync-TS`/`X-Sync-Nonce`/`X-Sync-Sig`, or control-plane body `> 16 KiB` → increment IP strike (+1) and return **Silent Stealth `404`** (HTTP `404 Not Found`, empty body `Content-Length: 0`, no `Server` header, `Connection: close` on HTTP/1.1).
4. **Constant-Time `X-Sync-Sig` HMAC Check (FIRST — Before Clock & Nonce)**:
   - Compare expected HMAC with `hmac.Equal`.
   - **If invalid**: increment IP strike (+1), return **Silent Stealth `404`**. **NEVER** leak `server_ts` and **NEVER** write to nonce cache.
5. **Clock Skew Check (`±60s`)**:
   - Check `|client_ts - server_unix_now| > 60`.
   - **If skewed**: **DO NOT write nonce cache, DO NOT run any business side-effect** (still counted against Step 2 IP rate limit). Return **`409 Conflict`**:
     ```json
     {"error":"ERR_CLOCK_SKEW","message":"client clock skew exceeds 60s window","retryable":true,"server_ts":1764246000,"max_skew_sec":60}
     ```
   - Legitimate clients holding `RELAY_ACCESS_KEY` (over verified TLS/SPKI Pin) cache the clock offset and retry once with a fresh `X-Sync-Nonce`.
6. **Bounded Replay Nonce Cache Check**:
   - Only reached after Steps 4 & 5 pass (prevents unauthenticated memory exhaustion).
   - Bounded cache: **`max_entries = 8,192`**, TTL **`120s`**, oldest-evict when full.
   - If nonce already present → strike (+1), return **`401 Unauthorized`** `{"error":"ERR_REPLAY_DETECTED","message":"nonce already consumed","retryable":true}`.
   - Otherwise insert `(X-Sync-Nonce, now)`.
7. **Endpoint-Specific Auth & Handler**: Verify `X-Sync-Room-Token`, `X-Sync-Mailbox-Sig`, `X-Sync-Deposit-Token`, or `X-Sync-Upload-Token`.

---

## 4. Standard Error Format & HTTP Status Code Matrix

All **authenticated** error responses return `Content-Type: application/json; charset=utf-8` using a flat, unambiguous JSON envelope aligned with `spec/CRYPTO_AND_AUTH.md` §7.3:

```json
{
  "error": "ERR_OFFLINE_QUOTA_EXCEEDED",
  "message": "declared item size exceeds relay max_item_bytes",
  "retryable": false,
  "scope": "item",
  "max_item_bytes": 104857600,
  "suggest_mode": "pipe"
}
```

> **Rule**: `error` is the normative machine-readable enum; `message` is a concise English diagnostic string only (never localized UI prose).

| HTTP Status | `error` Code | `retryable` | Trigger & Extra Top-Level Fields |
| :---: | :--- | :---: | :--- |
| `404` *(empty)* | *(none — silent stealth)* | `false` | Unauthenticated request, bad `X-Sync-Sig`, unknown route, bad method, malformed headers. |
| `400` | `ERR_BAD_REQUEST` | `false` | Malformed JSON, invalid field/range, `mailbox_id` derivation mismatch, missing `Content-Length`. |
| `401` | `ERR_REPLAY_DETECTED` | `true` | Valid HMAC but `X-Sync-Nonce` already consumed within 120s (retry with fresh nonce). |
| `401` | `ERR_UNAUTHORIZED_TOKEN` | `false` | Invalid `X-Sync-Room-Token`, `X-Sync-Upload-Token`, `X-Sync-Deposit-Token`, or `X-Sync-Mailbox-Sig`. |
| `403` | `ERR_SPOOL_DISABLED` | `false` | Mode B endpoint called when relay runs `--spool=off`. Includes `suggest_mode: "pipe"`. |
| `403` | `ERR_DOWNLOAD_LIMIT_EXCEEDED` | `false` | Chunk exceeded `max_downloads_per_chunk` cap. |
| `404` | `ERR_NOT_FOUND` | `false` | Authenticated request for nonexistent, expired, or already-burned resource. |
| `409` | `ERR_CLOCK_SKEW` | `true` | Valid HMAC with `\|X-Sync-TS - server_ts\| > 60`. Includes `server_ts`, `max_skew_sec: 60`. |
| `409` | `ERR_ROOM_BUSY` | `false` | Room already claimed by another receiver (strict 1-to-1 exclusivity). |
| `409` | `ERR_INVALID_STATE` | `false` | Out-of-order state transition (e.g., `commit` missing chunks, upload after `commit`, handshake turn cap exceeded). |
| `409` | `ERR_CONFLICT` | `false` | Duplicate `room_id`, mailbox `auth_pk` mismatch, or mailbox already at max 16 `deposit_token`s. |
| `410` | `ERR_ROOM_BURNED` | `false` | Room permanently destroyed by `verify_failed` / `rejected` / `cancelled` circuit breaker. |
| `413` | `ERR_CHUNK_TOO_LARGE` | `false` | Chunk `Content-Length > max_transport_chunk_bytes`. Includes `max_transport_chunk_bytes`. |
| `413` | `ERR_OFFLINE_QUOTA_EXCEEDED` | `false` | `declared_total_bytes > spool.max_item_bytes`. Includes `scope: "item"`, `max_item_bytes`, `suggest_mode: "pipe"`. |
| `429` | `ERR_RATE_LIMITED` | `true` | IP rate limit, `max_active_rooms`, or `transferSem` saturated. Includes `Retry-After: <seconds>` header. |
| `504` | `ERR_PIPE_PEER_TIMEOUT` | `true` | Mode A chunk partner did not join within `rendezvous_timeout_sec` (`30s`). |
| `507` | `ERR_OFFLINE_QUOTA_EXCEEDED` | `false` | Global spool cap, mailbox byte cap, or mailbox item count cap full (**never** silently evicts unread items). Includes `scope: "global"\|"mailbox"\|"item_count"`, `suggest_mode: "pipe"`. |

---

## 5. Complete HTTP API Specification

### 5.1 System Probe & Capability Discovery

#### `GET /v1/ping`
RTT check, wall-clock probe, and certificate expiry monitor.
- **Auth**: Relay Access HMAC.
- **Response `200 OK`**:
```json
{
  "proto_v": 1,
  "server_ts": 1764246000,
  "profile": "standard",
  "spool_backend": "disk",
  "cert_expires_at": 1827318000,
  "cert_rotate_recommended": false
}
```
- `cert_expires_at` is `0` when `--tls=off`. `cert_rotate_recommended` is `true` when remaining cert validity `< 30 days` (`2,592,000 s`, aligned with `CRYPTO_AND_AUTH.md` §7.5).

#### `GET /v1/caps`
Negotiates exact server profile capabilities, `N × 65,552 B` chunk sizing, and Mode B spool switch/quotas before any data transfer.
- **Auth**: Relay Access HMAC.
- **Response `200 OK`**:
```json
{
  "proto_v": 1,
  "profile": "standard",
  "server_ts": 1764246000,
  "cert_expires_at": 1827318000,
  "cert_rotate_recommended": false,
  "crypto_plaintext_block_bytes": 65536,
  "crypto_block_bytes": 65552,
  "streaming": {
    "enabled": true,
    "blocks_per_chunk": 16,
    "max_transport_chunk_bytes": 1048832,
    "recommended_parallel_chunks": 1,
    "max_parallel_chunks": 3,
    "rendezvous_timeout_sec": 30,
    "room_ttl_max_sec": 600
  },
  "spool": {
    "enabled": true,
    "backend": "disk",
    "max_item_bytes": 104857600,
    "max_mailbox_bytes": 268435456,
    "max_total_bytes": 536870912,
    "max_items_per_mailbox": 64,
    "default_ttl_sec": 86400,
    "max_ttl_sec": 259200,
    "uncommitted_ttl_sec": 1800,
    "max_manifest_downloads": 16,
    "max_downloads_per_chunk": 5,
    "max_deposit_tokens_per_mailbox": 16
  }
}
```
- When `--spool=off`: `spool.enabled = false`, `spool.backend = "off"`, all spool capacity/count fields = `0`.

---

### 5.2 Interactive Pairing & Signaling Rooms (`/v1/rooms/...`)

Hosts opaque signaling for **Flow 1** (one-shot transfers such as GravitySSH migration & first-time device binding via `mode=1 qr_oob_x25519` or `mode=2 commit_sas_x25519`) and **Mode A Direct Setup** (for `spool=off` or oversized videos exceeding `spool.max_item_bytes`, carrying Flow 2 `sealed_header` in the initial opaque message).

**Security & Memory Invariants**:
- Rooms live strictly in RAM (never written to disk) and wipe all message slices with `clear()` upon closure, burn, or TTL expiry.
- Strict 1-sender + 1-receiver exclusivity (`waiting` → `joined` → `closed` / `burned`).
- Max `8` `handshake` frames per room, max `4,096 B` raw payload per message (`msg_b64`).
- **Single-Failure Circuit Breaker**: Calling `/close` with `reason = "verify_failed"` or `"rejected"` immediately transitions the room to `burned`, clears buffered messages, tears down `pipe_id`, and returns `410 ERR_ROOM_BURNED` to any further call (strictly 1 online attempt against 6-digit SAS).

#### `POST /v1/rooms`
Sender creates an ephemeral room.
- **Auth**: Relay Access HMAC.
- **Request JSON**:
```json
{
  "room_id": "K7M9P2XQ",
  "ttl_sec": 300,
  "initial_msg_b64": "<optional opaque M1 <= 4096 B raw>"
}
```
  - `room_id`: exact 8 uppercase Crockford Base32 chars (`[0-9A-HJKMNP-TV-Z]{8}`).
  - `ttl_sec`: `60..600` (default `300`).
- **Response `201 Created`**:
```json
{
  "room_id": "K7M9P2XQ",
  "pipe_id": "a1b2c3d4e5f60718293a4b5c6d7e8f90",
  "sender_token": "<43-char b64u>",
  "expires_at": 1764246300,
  "seq": 1
}
```
  (`seq` is `1` if `initial_msg_b64` was provided, else `0`.)
- **Errors**: `400 ERR_BAD_REQUEST`, `409 ERR_CONFLICT` (duplicate active `room_id`), `429 ERR_RATE_LIMITED` (`max_active_rooms` cap reached).

#### `POST /v1/rooms/{room_id}/join`
Receiver exclusively claims the room (at most once).
- **Auth**: Relay Access HMAC.
- **Request JSON**:
```json
{
  "msg_b64": "<optional opaque message <= 4096 B raw>"
}
```
  - **Sequence Rule**: When `msg_b64` is omitted or empty, no message is appended and `seq` **does NOT increment** (e.g., if Sender sent `M1` at `seq: 1`, `/join` without `msg_b64` returns `seq: 1` and `messages: [M1]`).
  - **Handshake Order Rule**: For `mode=2` (`commit_sas_x25519`), Receiver **MUST** call `/join` without `msg_b64` first to fetch and lock `M1 (commit_a)` before computing and sending `M2` via `POST /v1/rooms/{room_id}/messages`. Likewise, `mode=1` (`qr_oob_x25519`) and `mode=0` (`direct`) Receivers call `/join` without `msg_b64` to fetch `M1` before responding or pulling chunks.
- **Response `200 OK`**:
```json
{
  "room_id": "K7M9P2XQ",
  "pipe_id": "a1b2c3d4e5f60718293a4b5c6d7e8f90",
  "receiver_token": "<43-char b64u>",
  "expires_at": 1764246300,
  "seq": 1,
  "messages": [
    {"seq": 1, "from": "sender", "kind": "handshake", "msg_b64": "..."}
  ]
}
```
- **Errors**: `404 ERR_NOT_FOUND`, `409 ERR_ROOM_BUSY`, `410 ERR_ROOM_BURNED`.

#### `POST /v1/rooms/{room_id}/messages`
Posts next opaque handshake message (`M2`/`M3`/`M4`/`PairBindPayload` ciphertext) or Mode A control message (`pipe_start` / `pipe_ack`).
- **Auth**: Relay Access HMAC + `X-Sync-Room-Token`.
- **Request JSON**:
```json
{
  "kind": "handshake",
  "msg_b64": "<opaque <= 4096 B raw>"
}
```
  - `kind`: `"handshake"` (max `8` per room) | `"control"` (ring-buffered last `16` messages in RAM, keeping per-room RAM strictly `< 80 KiB`).
- **Response `200 OK`**: `{"seq": 3}`.
- **Errors**: `401 ERR_UNAUTHORIZED_TOKEN`, `404 ERR_NOT_FOUND`, `409 ERR_INVALID_STATE`, `410 ERR_ROOM_BURNED`.

#### Mode A Control Frame & Flow 2 Direct Setup Contract *(Opaque to Relay)*
The relay never parses `msg_b64`; clients MUST conform to these exact room payload formats when using Mode A `/v1/pipe/...`:
1. **Flow 1 `oneshot` Control Frames** (`POST /v1/rooms/{room_id}/messages`, `kind: "control"`):
   - Wire `msg_b64` decodes to `{"ctrl_seq":0,"ct":"<b64u>"}`, encrypted/authenticated per `CRYPTO_AND_AUTH.md` §4.3 (`ctrl_seq` even for sender `0,2,4...`, odd for receiver `1,3,5...`).
   - Decrypted plaintext JSON commands:
     - Sender starts pipe: `{"op":"pipe_start","msg_id":"<32 hex>","blocks_per_chunk":16,"parts":[{"part_id":0,"total_bytes":4112,"chunk_count":1}]}`
     - Receiver confirms full AEAD verification & disk persistence: `{"op":"pipe_ack","msg_id":"<32 hex>"}` (both peers then call `POST /v1/rooms/{room_id}/close` with `{"reason":"completed"}`).
2. **Flow 2 Paired Direct Mode A (`--spool=off` or oversized payload > `spool.max_item_bytes`)**:
   - Sender opens room (`POST /v1/rooms`) with `initial_msg_b64` decoding to:
     ```json
     {
       "proto_v": 1,
       "mode": 0,
       "purpose": "direct",
       "sealed_header": "<278-char b64u fixed 208B SealedHeader>",
       "blocks_per_chunk": 16,
       "parts": [
         {"part_id": 0, "total_bytes": 4112, "chunk_count": 1},
         {"part_id": 1, "total_bytes": 5244160, "chunk_count": 5}
       ]
     }
     ```
   - Receiver calls `/join` (omitting `msg_b64`), extracts `M1`, and runs full Flow 2 `SealedHeader` verification (`CRYPTO_AND_AUTH.md` §5.3). On any failure, Receiver **MUST** immediately call `/close` with `{"reason":"verify_failed"}` to burn the room.
   - Both sides stream encrypted chunks via `PUT`/`GET /v1/pipe/{pipe_id}/parts/{part_id}/chunks/{tx_idx}` (`part_id` in `0..63`).
   - After Receiver verifies all STREAM AEAD blocks + manifest SHA-256 and persists locally, Receiver posts `kind: "control"` with `msg_b64` decoding to:
     ```json
     {
       "op": "pipe_ack",
       "msg_id": "<32 hex>",
       "ack_mac": "<b64u(HMAC-SHA256(part0_key, utf8(\"synctool-v1/direct-ack\") || msg_id(16B)))>"
     }
     ```
     (prevents a malicious relay from forging completion), followed by `/close` with `{"reason":"completed"}`.

#### `GET /v1/rooms/{room_id}/events?since=<seq>&mode=<sse|poll>&wait_sec=<1..25>`
Event-driven peer signaling reception (replaces legacy short-polling).
- **Auth**: Relay Access HMAC + `X-Sync-Room-Token`.
- **Query Params**: `since` (default `0`), `mode` (`"sse"` default | `"poll"`), `wait_sec` (`1..25`, default `20`, for `mode=poll`).
- **Response (`mode=sse`, `200 OK`)**:
  - Mandatory Headers:
    - `Content-Type: text/event-stream; charset=utf-8`
    - `Cache-Control: no-cache, no-transform`
    - `X-Accel-Buffering: no`
  - Event stream format:
    ```text
    id: 2
    event: message
    data: {"seq":2,"from":"receiver","kind":"handshake","msg_b64":"..."}

    : ping

    event: reconnect
    data: {"since":2}
    ```
    Terminal events: `event: burned` or `event: closed` with `data: {"reason":"verify_failed"}`.
  - **Proxy-Safe Keepalive & Rotation**: Server writes `: ping\n\n` every **`20s`** and cleanly ends the SSE stream with `event: reconnect` at **`90s`** (staying under Cloudflare 100s / Nginx default timeouts). Clients treat clean EOF / `reconnect` as normal and reopen with `since=<last_seq>` (or transparently fall back to `mode=poll`).
- **Response (`mode=poll`, `200 OK`)**:
```json
{
  "state": "joined",
  "seq": 2,
  "messages": [
    {"seq": 2, "from": "receiver", "kind": "handshake", "msg_b64": "..."}
  ],
  "reason": ""
}
```

#### `POST /v1/rooms/{room_id}/close`
Gracefully closes room or triggers immediate single-failure security burn.
- **Auth**: Relay Access HMAC + `X-Sync-Room-Token`.
- **Request JSON**: `{"reason": "completed" | "rejected" | "verify_failed" | "cancelled"}`.
- **Behavior**: Immediately clears all buffered `msg_b64` bytes with `clear()`, cancels active Mode A pipe streams on `pipe_id`, pushes terminal `closed`/`burned` event to peer, keeps only the 1-field `reason` tombstoned for `15s` so peer observes the terminal state, then deletes the room.
- **Response `200 OK`**: `{"room_id": "K7M9P2XQ", "state": "burned"}` (or `"closed"` for `"completed"`/`"cancelled"`).

---

### 5.3 Mode A — Real-Time Zero-Disk Chunked Pipe (`/v1/pipe/...`)

Bound to an active room's `pipe_id`. Enables **GB-scale streaming on 256 MiB RAM / zero-disk VPS** with chunk-level weak-network resumability.

#### `PUT /v1/pipe/{pipe_id}/parts/{part_id}/chunks/{tx_idx}` *(Sender)*
- **Auth**: Relay Access HMAC (`BODY_BINDING = "stream:" + Content-Length`) + `X-Sync-Room-Token: <sender_token>`.
- **Required Headers**:
  - `Content-Type: application/octet-stream`
  - `Content-Length: <1..max_transport_chunk_bytes>` (`Transfer-Encoding: chunked` rejected with `400 ERR_BAD_REQUEST`).
- **Behavior**:
  1. Validates `0 <= part_id <= 63` (else `400 ERR_BAD_REQUEST`) and enforces `1 <= Content-Length <= max_transport_chunk_bytes` (else `413 ERR_CHUNK_TOO_LARGE`).
  2. Registers in-memory rendezvous key `(pipe_id, part_id, tx_idx)` (duplicate concurrent PUT returns `409 ERR_CONFLICT`).
  3. Waits up to **`30s`** (`rendezvous_timeout_sec`) for matching Receiver `GET` (else `504 ERR_PIPE_PEER_TIMEOUT`).
  4. Acquires `transferSem` (waits up to `5s`, else `429 ERR_RATE_LIMITED` + `Retry-After`).
  5. Bridges `req.Body` directly to Receiver `http.ResponseWriter` via pooled `32 KiB`/`64 KiB` buffer (`io.CopyBuffer`) + `Flusher` + optional bandwidth limiter.
  6. Refreshes **`30s` Stall Timeout** via `http.ResponseController` on every copy step (kills Slowloris without capping total transfer duration).
  7. **Zero disk writes; zero chunk retention after transfer.**
- **Response `200 OK`**:
```json
{
  "pipe_id": "a1b2c3d4e5f60718293a4b5c6d7e8f90",
  "part_id": 1,
  "tx_idx": 0,
  "bytes_relayed": 1048832
}
```

#### `GET /v1/pipe/{pipe_id}/parts/{part_id}/chunks/{tx_idx}` *(Receiver)*
- **Auth**: Relay Access HMAC + `X-Sync-Room-Token: <receiver_token>`.
- **Behavior**: Parks on `(pipe_id, part_id, tx_idx)` for up to `30s` (either peer may arrive first). Streams raw ciphertext with `Content-Type: application/octet-stream`, `Content-Length: <sender_content_length>`, `Cache-Control: no-store`, `X-Accel-Buffering: no`.
- **Resumability**: On mid-chunk drop, Receiver's STREAM AEAD tag fails and does not advance checkpoint; upon reconnect both peers re-issue the exact same `(part_id, tx_idx)`.
- **Errors**: `401 ERR_UNAUTHORIZED_TOKEN`, `404 ERR_NOT_FOUND`, `410 ERR_ROOM_BURNED`, `429 ERR_RATE_LIMITED`, `504 ERR_PIPE_PEER_TIMEOUT`.

---

### 5.4 Mode B — Blinded Mailboxes & Per-Device Deposit Tokens (`/v1/mailboxes/...`)

> **Manual Off Switch Guard**: When running with `--spool=off` (`SYNCTOOL_SPOOL=off`), **all `/v1/mailboxes/*` and `/v1/spool/*` endpoints immediately return `403 ERR_SPOOL_DISABLED`** (after Step 4 HMAC verification).

#### `PUT /v1/mailboxes/{mailbox_id}`
Registers a device's blinded mailbox and binds its Ed25519 `mailbox_auth_pk` (idempotent for same `auth_pk`).
- **Auth**: Relay Access HMAC + `X-Sync-Mailbox-Sig` (verified with `auth_pk_b64` in body; server **MUST** verify `mailbox_id == hex(SHA256("synctool-v1/mailbox-id:" || auth_pk)[0:16])` per `CRYPTO_AND_AUTH.md` §3.3).
- **Request JSON**:
```json
{
  "auth_pk_b64": "<43-char b64u 32B Ed25519 public key>"
}
```
- **Response `200 OK`**:
```json
{
  "mailbox_id": "9f8e7d6c5b4a39281706f5e4d3c2b1a0",
  "registered": true,
  "deposit_token_count": 0
}
```
- **Errors**: `400 ERR_BAD_REQUEST`, `401 ERR_UNAUTHORIZED_TOKEN`, `403 ERR_SPOOL_DISABLED`, `409 ERR_CONFLICT`.

#### `POST /v1/mailboxes/{mailbox_id}/deposit-tokens`
Adds a per-peer deposit token hash (`max 16` active per mailbox, enabling single-device revocation without disturbing other paired devices).
- **Auth**: Relay Access HMAC + `X-Sync-Mailbox-Sig`.
- **Request JSON**:
```json
{
  "token_id": "dt_a1b2c3d4",
  "token_hash_hex": "<64-char lowercase hex SHA256(\"synctool-v1/deposit-token:\" || utf8(raw_deposit_token))>"
}
```
  - `token_id`: opaque 8–32 char `[A-Za-z0-9_-]` label (must NOT contain device display names). Relay never stores plaintext `deposit_token`.
- **Response `201 Created`**: `{"token_id": "dt_a1b2c3d4", "active_count": 3}`.
- **Errors**: `401 ERR_UNAUTHORIZED_TOKEN`, `403 ERR_SPOOL_DISABLED`, `404 ERR_NOT_FOUND`, `409 ERR_CONFLICT` (cap 16 reached or duplicate `token_id`).

#### `DELETE /v1/mailboxes/{mailbox_id}/deposit-tokens/{token_id}`
Immediately revokes a single lost/compromised peer's deposit right.
- **Auth**: Relay Access HMAC + `X-Sync-Mailbox-Sig`.
- **Response `200 OK`**: `{"token_id": "dt_a1b2c3d4", "revoked": true, "active_count": 2}`.
- **Errors**: `401 ERR_UNAUTHORIZED_TOKEN`, `403 ERR_SPOOL_DISABLED`, `404 ERR_NOT_FOUND`.

#### `GET /v1/mailboxes/{mailbox_id}/items`
Lists all **committed**, unexpired items awaiting pull.
- **Auth**: Relay Access HMAC + `X-Sync-Mailbox-Sig`.
- **Response `200 OK`**:
```json
{
  "mailbox_id": "9f8e7d6c5b4a39281706f5e4d3c2b1a0",
  "used_bytes": 1052944,
  "quota_bytes": 268435456,
  "items": [
    {
      "item_id": "itm_11223344556677889900aabbccddeeff",
      "created_at": 1764246000,
      "expires_at": 1764332400,
      "total_bytes": 1052944,
      "sealed_header": "<278-char b64u fixed 208B SealedHeader>",
      "parts": [
        {"part_id": 0, "total_bytes": 4112, "chunk_count": 1},
        {"part_id": 1, "total_bytes": 1048832, "chunk_count": 1}
      ]
    }
  ]
}
```

#### `GET /v1/mailboxes/{mailbox_id}/events?mode=<sse|poll>&wait_sec=<1..25>&since_ts=<unix_sec>`
On-demand foreground notification stream so open apps pull newly committed Mode B items within ~1s and burn them immediately (eliminating separate online presence probing).
- **Auth**: Relay Access HMAC + `X-Sync-Mailbox-Sig`.
- **SSE Headers & Lifecycle**: Identical to §5.2 (`Content-Type: text/event-stream; charset=utf-8`, `Cache-Control: no-cache, no-transform`, `X-Accel-Buffering: no`, `: ping` every `20s`, graceful `event: reconnect` at `90s`).
- **SSE Event**:
  ```text
  event: new_item
  data: {"item_id":"itm_11223344556677889900aabbccddeeff","total_bytes":1052944,"created_at":1764246000,"expires_at":1764332400}
  ```
- **Long-Poll (`mode=poll`) Response `200 OK`**:
```json
{
  "items": [
    {"item_id": "itm_11223344556677889900aabbccddeeff", "total_bytes": 1052944, "created_at": 1764246000, "expires_at": 1764332400}
  ],
  "server_ts": 1764246020
}
```

---

### 5.5 Mode B — Ephemeral Spool Upload, Two-Phase Pull & Signed ACK Burn (`/v1/spool/...`)

#### `POST /v1/spool/init` *(Sender)*
Atomically enforces all 4 quota tiers and opens an uncommitted spool upload.
- **Auth**: Relay Access HMAC (with `EXTRA_TOKEN_BINDING = "deposit:..."`) + `X-Sync-Deposit-Token: <43-char b64u>`.
- **Request JSON**:
```json
{
  "mailbox_id": "9f8e7d6c5b4a39281706f5e4d3c2b1a0",
  "declared_total_bytes": 5248272,
  "ttl_sec": 86400,
  "sealed_header": "<278-char b64u fixed 208B SealedHeader>",
  "parts": [
    {"part_id": 0, "total_bytes": 4112, "chunk_count": 1},
    {"part_id": 1, "total_bytes": 5244160, "chunk_count": 5}
  ]
}
```
  - **Validation Rules**:
    - `sealed_header` MUST decode to exact `208 B` (`proto_v = 1`, per `CRYPTO_AND_AUTH.md` §5).
    - `parts` MUST contain `part_id: 0` (Manifest); valid `part_id` range is strictly `0..63` (max `64` parts per item, unique `part_id`s).
    - `sum(parts[i].total_bytes) == declared_total_bytes`.
    - For each part: `chunk_count >= 1`, `total_bytes <= chunk_count * max_transport_chunk_bytes`.
    - `ttl_sec` clamped to `[60, spool.max_ttl_sec]` (default `spool.default_ttl_sec` when `0` or omitted).
    - Four-tier atomic quota enforcement (`item` → `413`; `item_count`/`mailbox`/`global` → `507`), **never evicting unread items**; uncommitted uploads count toward reserved quota and expire after `uncommitted_ttl_sec` (`1800s`).
- **Response `201 Created`**:
```json
{
  "item_id": "itm_11223344556677889900aabbccddeeff",
  "upload_token": "<43-char b64u>",
  "max_transport_chunk_bytes": 1048832,
  "upload_expires_at": 1764247800,
  "expires_at": 1764332400
}
```

#### `PUT /v1/spool/{item_id}/parts/{part_id}/chunks/{tx_idx}` *(Sender)*
Idempotent streaming chunk upload.
- **Auth**: Relay Access HMAC (`BODY_BINDING = "stream:" + Content-Length`, `EXTRA_TOKEN_BINDING = "upload:..."`) + `X-Sync-Upload-Token`.
- **Required Headers**: `Content-Type: application/octet-stream`, `Content-Length: <1..max_transport_chunk_bytes>`.
- **Behavior**:
  - Validates `(part_id, tx_idx)` in range and item uncommitted (else `409 ERR_INVALID_STATE`).
  - Enforces `Content-Length <= max_transport_chunk_bytes` (`413 ERR_CHUNK_TOO_LARGE`) and per-part cumulative bytes `<= parts[part_id].total_bytes` (`400 ERR_BAD_REQUEST`).
  - Acquires `transferSem`, streams with pooled `32 KiB`/`64 KiB` buffer and `30s` Stall Timeout to:
    - `memory`: exact-sized byte slice (`clear()` on overwrite/delete).
    - `disk`: temp file `p{part_id}_c{tx_idx}.enc.tmp` (mode `0600`) then atomic `os.Rename` to `p{part_id}_c{tx_idx}.enc`.
  - Safe idempotent retry on weak networks.
- **Response `200 OK`**:
```json
{
  "item_id": "itm_11223344556677889900aabbccddeeff",
  "part_id": 1,
  "tx_idx": 0,
  "received_bytes": 1048832
}
```

#### `POST /v1/spool/{item_id}/commit` *(Sender)*
Atomically publishes item to target mailbox and fires foreground SSE `new_item` event.
- **Auth**: Relay Access HMAC (`EXTRA_TOKEN_BINDING = "upload:..."`) + `X-Sync-Upload-Token`.
- **Request JSON**: `{}`
- **Behavior**: Verifies every declared `(part_id, tx_idx)` chunk exists and exact total bytes match `declared_total_bytes` (else `409 ERR_INVALID_STATE` with `missing_chunks` list capped at 16). Marks `committed = true`, invalidates `upload_token`, emits SSE `new_item`.
- **Response `200 OK`**: `{"item_id": "...", "committed": true, "expires_at": 1764332400}`.

#### `DELETE /v1/spool/{item_id}` *(Sender Abort — Uncommitted Only)*
Aborts an uncommitted upload and reclaims quota immediately.
- **Auth**: Relay Access HMAC (`EXTRA_TOKEN_BINDING = "upload:..."`) + `X-Sync-Upload-Token`.
- **Response `200 OK`**: `{"item_id": "...", "aborted": true}`.
- **Errors**: `409 ERR_INVALID_STATE` if already committed.

#### `GET /v1/spool/{item_id}/parts/{part_id}/chunks/{tx_idx}` *(Recipient Two-Phase / Resumable Pull)*
- **Auth**: Relay Access HMAC + `X-Sync-Mailbox-Sig` (server resolves `item.mailbox_id` from `item_id` and verifies signature against that mailbox's `auth_pk` using `item.mailbox_id`).
- **Behavior**:
  - Requires `committed == true` and unexpired (else `404 ERR_NOT_FOUND`).
  - Enforces per-chunk download limits (else `403 ERR_DOWNLOAD_LIMIT_EXCEEDED`):
    - **`part_id == 0` (Manifest)**: independent limit of **`16`** downloads across all profiles (`spool.max_manifest_downloads`), preventing repeated `inbox list` refreshes from locking out unread parcels on `nano`.
    - **`part_id >= 1` (Attachment blobs)**: `spool.max_downloads_per_chunk` (`3` on `nano`, `5` on `standard`/`media`).
  - Acquires `transferSem`.
  - **`disk` backend**: serves `p{part_id}_c{tx_idx}.enc` directly via `http.ServeContent` (**Linux `sendfile` zero-copy**, no secondary server-side encryption wrapper).
  - **`memory` backend**: writes directly from RAM slice.
  - **NEVER deletes item on `GET`.** Recipient pulls `part_id=0` (Manifest) first to preview, then pulls `part_id=1..N` chunks with checkpoint resume, verifies STREAM AEAD tags + manifest SHA-256 on disk, updates `seen_msg_ids`, and then calls `/ack`.
- **Response `200 OK`**: `Content-Type: application/octet-stream`, `Content-Length: <chunk_bytes>`, `Cache-Control: no-store`.

#### `POST /v1/spool/{item_id}/ack` *(Recipient Signed Burn-After-Read)*
Permanently destroys the spooled item after end-to-end verification and local persistence.
- **Auth**: Relay Access HMAC + `X-Sync-Mailbox-Sig` (signed with `item.mailbox_id` per `CRYPTO_AND_AUTH.md` §7.4).
- **Request JSON**: `{}`
- **Behavior**: Removes item from index, immediately runs `os.RemoveAll` (`disk`) or `clear()` every slice (`memory`), reclaims global & mailbox quotas.
- **Response `200 OK`**: `{"item_id": "...", "burned": true}`. (Retry against already-burned item returns `404 ERR_NOT_FOUND`, which SDK treats as burned.)

---

## 6. Multi-Tier VPS Presets (`auto|nano|standard|media`) & Manual Spool Switch

### 6.1 Profile Auto-Detection & Explicit Manual Off-Switch

- **`--profile` / `SYNCTOOL_PROFILE`**: `auto` *(default)* | `nano` | `standard` | `media`.
  - When `auto`:
    1. Determine effective memory `M`: read Linux cgroup v2 `/sys/fs/cgroup/memory.max` → fallback cgroup v1 `/sys/fs/cgroup/memory/memory.limit_in_bytes` → fallback OS physical RAM.
    2. `M < 768 MiB` → `nano`; `768 MiB <= M < 2048 MiB` → `standard`; `M >= 2048 MiB` → `media`.
    3. If resolved profile selects `spool=disk`, verify `--data-dir` is writable with `>= 256 MiB` free space; otherwise downgrade `spool` to `memory` and log a warning.
- **`--spool` / `SYNCTOOL_SPOOL`**: `auto` *(default, inherits profile)* | **`off`** *(explicit manual kill-switch disabling all Mode B offline storage)* | `memory` | `disk`.
  - Any explicit `--spool` setting **strictly overrides** `--profile`'s default backend (e.g., `--profile=auto --spool=off` keeps optimal streaming limits while guaranteeing zero offline persistence).

### 6.2 Frozen Three-Tier Resource Matrix

| Parameter (CLI / `SYNCTOOL_*`) | `nano` (<768MB VPS / NAT) | `standard` (768MB–2GB, Default) | `media` (2GB+ High-Cap VPS) |
| :--- | :---: | :---: | :---: |
| Target Container RAM / `GOMEMLIMIT` | `64 MiB` / `48 MiB` | `192 MiB` / `144 MiB` | `512 MiB` / `384 MiB` |
| `GOGC` default | `50` | `50` | `100` |
| Stream Copy Buffer (`sync.Pool`) | `32 KiB` | `64 KiB` | `64 KiB` |
| `blocks_per_chunk` (`N × 65,552 B`) | `4` (`262,208 B`) | `16` (`1,048,832 B`) | `32` (`2,097,664 B`) |
| Mode A Streaming Pipe | Enabled (0 disk) | Enabled (0 disk) | Enabled (0 disk) |
| Max Active Rooms (`max_active_rooms`) | `32` | `128` | `512` |
| L4 Max Active TCP Conns (`max_conns`) | `32` | `128` | `512` |
| L4 Max TCP Conns / IP (`max_conns_per_ip`) | `6` | `16` | `32` |
| L7 Concurrent Data Streams (`transfer_sem`) | `2` (per IP: `1`) | `8` (per IP: `3`) | `32` (per IP: `8`) |
| Default Spool Backend (`spool`) | `memory` | `disk` | `disk` |
| Spool Global Cap (`spool_max_total_bytes`) | `16 MiB` | `512 MiB` | `10 GiB` |
| Spool Per-Mailbox Cap (`spool_max_mailbox_bytes`) | `8 MiB` | `256 MiB` | `4 GiB` |
| Spool Single-Item Cap (`spool_max_item_bytes`) | `4 MiB` | `100 MiB` | `2 GiB` |
| Max Items / Mailbox (`spool_max_items`) | `16` | `64` | `256` |
| Spool Default / Max TTL | `30m` / `2h` | `24h` / `72h` | `72h` / `168h` (7d) |
| Max Downloads / Manifest (`part_id == 0`) | `16` | `16` | `16` |
| Max Downloads / Blob Chunk (`part_id >= 1`) | `3` | `5` | `5` |
| Control Rate Limit / IP (per min / burst) | `120` / `40` | `240` / `80` | `480` / `160` |
| Chunk/Event Rate Limit / IP (per min / burst) | `1800` / `240` | `3600` / `480` | `6000` / `800` |
| Max Tracked IPs (`max_tracked_ips`) | `2,048` | `4,096` | `16,384` |
| Strike Ban Threshold / Duration / Decay | `10` / `15m` / `-1 per min` | `10` / `15m` / `-1 per min` | `10` / `15m` / `-1 per min` |
| Global Bandwidth Limit (`max_bandwidth_mbps`) | `0` (optional e.g. `40` Mbps) | `0` (unlimited) | `0` (unlimited) |

> **HTTP Timeout Discipline (All Tiers)**:
> - `ReadHeaderTimeout`: `10s`; `IdleTimeout`: `60s`.
> - **NO global `ReadTimeout`/`WriteTimeout`** (prevents cutting off slow mobile media streams).
> - Control-plane handler deadline: `15s` via `http.ResponseController`.
> - Data-plane chunk stall timeout: `30s` rolling deadline reset per buffer iteration.

---

## 7. Deployment, TLS, Reverse Proxy & Disk Layout

### 7.1 Dual Deployment Forms (Including Docker-Free 256MB VPS)

1. **Docker One-Click (Primary for 512MB+ VPS)**:
   - Multi-arch `FROM scratch` static Go binary (`linux/amd64`, `linux/arm64`, ~6–10 MiB), `USER 65532:65532`, `cap_drop: ALL`, `no-new-privileges:true`, `read_only: true` rootfs (mount `/data` only for persisted certs/key and `spool=disk`).
   - Docker `HEALTHCHECK` invokes `synctool-relay healthcheck` (no `curl`/`wget` needed in `scratch`).
   - CI publishes to **GHCR (`ghcr.io/yellowdking/synctool`)** + **Docker Hub**, plus standalone static binaries on **GitHub Releases**.
2. **Standalone Static Binary + `systemd` Unit (For 256MB Low-RAM VPS)**:
   - Avoids `dockerd`/`containerd`'s 80–120 MiB RAM tax.
   - Reference `systemd` unit sets `MemoryMax=64M`, `DynamicUser=yes`, `ProtectSystem=strict`, `NoNewPrivileges=yes`, keeping idle RSS **`< 15 MiB`**.

### 7.2 TLS Modes & 730-Day Self-Signed Certificate Policy

`--tls` / `SYNCTOOL_TLS`:

| Mode | Behavior & Security Guardrails |
| :--- | :--- |
| `selfsigned` *(default)* | On `init`/first start, generates & persists ECDSA P-256 leaf cert (`cert.pem`/`key.pem`, mode `0600`) in `--data-dir` with **`ExtKeyUsageServerAuth`**, explicit **IP SAN and/or DNS SAN** (from `--public-host`), **730-day validity** (strictly under Apple's ≤825-day leaf cert limit), and TLS `MinVersion = TLS 1.3`. Prints `pin = hex(SHA256(DER(SPKI)))` (64-char lowercase hex) in `synctool://relay?...#...`. Clients **MUST** strictly pin SPKI (no insecure skip-verify mode). |
| `cert` | Loads `--tls-cert` & `--tls-key` (TLS `MinVersion = TLS 1.3`), reloads on `SIGHUP`. |
| `off` | Plaintext HTTP (HTTP/1.1 + optional H2C) behind Nginx / Caddy / Cloudflare Tunnel. **Hard Safety Guard**: startup **MUST FAIL** if `--tls=off` AND `--listen` is non-loopback AND `--trust-proxies` is empty. |

- **Rotation Lifecycle**: `/v1/ping` and `/v1/caps` return `cert_expires_at` and `cert_rotate_recommended` (`true` when `< 30 days` remain). Operators run `synctool-relay cert-rotate` to mint a fresh 730-day cert and obtain the updated onboarding URI/QR.

### 7.3 Reverse Proxy Compatibility & `TRUSTED_PROXIES`

- **`--trust-proxies` / `SYNCTOOL_TRUSTED_PROXIES`**: Comma-separated CIDR list (default **empty**).
  - When empty: real client IP is strictly `r.RemoteAddr` (ignores `X-Forwarded-For` / `X-Real-IP` / `CF-Connecting-IP` to defeat header spoofing).
  - When set: if `r.RemoteAddr` matches a trusted CIDR, walk `X-Forwarded-For` right-to-left and pick the **first IP NOT in `TRUSTED_PROXIES`** (falling back to `CF-Connecting-IP` / `X-Real-IP` when configured).
- **Recommended Nginx Reverse Proxy Snippet**:
  ```nginx
  client_max_body_size 4m;
  proxy_request_buffering off;
  proxy_buffering off;
  proxy_http_version 1.1;
  proxy_set_header Connection "";
  proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
  proxy_read_timeout 120s;
  ```
- **Cloudflare Tunnel / CDN Compatibility**: Because `max_transport_chunk_bytes <= 2 MiB` and SSE streams cleanly rotate at `90s` with `20s` keepalives + `X-Accel-Buffering: no`, `synctool-relay` operates cleanly behind Cloudflare Free's 100 MB body limit and 100s timeout without sacrificing E2EE.

### 7.4 CLI Subcommands & Onboarding URI Output

- `synctool-relay init [--public-host <ip-or-domain>] [--port 54843] [--data-dir /data]`:
  - Generates 256-bit random `RELAY_ACCESS_KEY` (`43-char b64u`, persisted in `access.key` mode `0600`; **zero hardcoded default key exists in source code**) and 730-day self-signed cert (unless `--tls=off`/`cert`).
  - Prints unified URI `synctool://relay?v=1&u=<percent_encoded_canonical_origin>[&pin=<64-hex-spki>]#k=<access_key>` and ASCII QR **strictly to interactive TTY / explicit `init` stdout** (exact URI parameter grammar frozen in `spec/ENVELOPE_AND_SDK.md`).
- `synctool-relay serve` *(default)*: Starts relay server. **NEVER** prints `access_key`, tokens, signatures, or full IDs to runtime logs.
- `synctool-relay cert-rotate`: Rotates 730-day self-signed cert and prints updated SPKI pin URI.
- `synctool-relay healthcheck`: Probes local listener and exits `0`/`1`.

### 7.5 On-Disk Spool Layout (`spool=disk`) & Lazy GC

- Directory layout under `<data-dir>/` (dirs `0700`, files `0600`, **zero plaintext business metadata in paths or JSON**):
  ```text
  <data-dir>/
    access.key          # 43-char b64u (0600)
    cert.pem / key.pem  # 730-day ECDSA P-256 (0600)
    spool/
      <mb_2hex>/<mailbox_id>/
        mailbox.json    # {"auth_pk_b64":"...","deposit_tokens":[{"token_id":"...","token_hash_hex":"..."}]}
        <item_id>/
          item.json     # {"sealed_header":"...","declared_total_bytes":...,"committed":true,"created_at":...,"expires_at":...,"parts":[...]}
          p0_c0.enc     # raw encrypted Manifest chunk
          p1_c0.enc     # raw encrypted Blob chunk (served via sendfile)
  ```
- **Startup Recovery**: Scans `<data-dir>/spool/` to rebuild the lightweight RAM index, immediately purges expired items, abandoned uncommitted uploads past `uncommitted_ttl_sec`, and orphaned `.tmp` files.
- **Lazy GC (Near-Zero Idle Footprint)**: When `active_rooms == 0` AND `spooled_items == 0`, the background GC ticker pauses completely (woken automatically on next room creation or spool init), keeping idle CPU ≈ `0.0%`, disk I/O = `0`, and RSS `< 15 MiB`.
- **Log Redaction**: Runtime logs emit only sanitized 8-char ID prefixes, error codes, quota/ban events, and HTTP status codes; Docker compose templates cap `json-file` logs at `max-size: 5m`, `max-file: 2`.
