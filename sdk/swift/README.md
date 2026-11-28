# SyncToolSDK (Swift)

Zero-dependency native Swift SDK (`synctool-v1`) for **iOS 16+** and **macOS 13+**, built exclusively on Apple system frameworks (`CryptoKit`, `Security`, `Foundation`).

## Features

- **Zero External Dependencies**: Pure Swift 5.10 using `CryptoKit` (HKDF-SHA256, X25519, Ed25519 with strict `S < L` & torsion-point rejection, AES-256-GCM) and `URLSession` (TLS 1.3).
- **Multi-Pin SPKI Certificate Pinning**: Direct X.509 `TBSCertificate` `subjectPublicKeyInfo` DER verification supporting `1..8` SHA-256 SPKI pins for zero-downtime relay certificate rotation (`CA:FALSE` self-signed ECDSA/RSA/Ed25519 or `system_ca`).
- **Three Pairing & Transfer Flows**:
  - **Flow 1A (`mode=1`)**: QR 128-bit out-of-band secret + ephemeral X25519 (`initiateDeviceBind`, `acceptDeviceBind`, `startOneShotSend`, `receiveOneShot`).
  - **Flow 1B (`mode=2`)**: 8-character Crockford Base32 room code + 3-step Commit-Reveal X25519 + mandatory fail-closed 6-digit SAS verification (`onSASInput` on initiator, mandatory `onSASConfirm` on responder).
  - **Flow 2 (`mode=0` / 0-RTT Sealed Sender)**: Paired device push via Mode B encrypted spool (`sendToPeer`, two-phase `listInbox` -> `fetchParcel` -> `ackItem`, foreground SSE/poll `watchInbox`) or live Mode A zero-disk pipe (`DeliveryMode.pipe` / `receiveDirect`), plus two-phase single-device revocation (`revokeDevice`).
- **Constant-Memory Streaming & Resume**: `64 KiB -> 65,552 B` STREAM AEAD chunking backed by file URLs (`BlobInput.fromFile`) and `LocalMetaKey`-sealed resumable checkpoints.

## Swift Package Manager Integration

Add `synctool` from GitHub (root `Package.swift` exposes `SyncToolSDK` directly):

```swift
dependencies: [
    .package(url: "https://github.com/yellowdking/synctool.git", from: "0.4.0")
],
targets: [
    .target(
        name: "YourApp",
        dependencies: [
            .product(name: "SyncToolSDK", package: "synctool")
        ]
    )
]
```

Or reference the local package directory `.package(path: "path/to/synctool/sdk/swift")`.

## Quick Start

```swift
import Foundation
import SyncToolSDK

// 1. Parse relay configuration URI (keep #k= out of logs; SyncError & Redact scrub fragments automatically)
let relay = try SyncUri.parseRelayUri(relayUriString)

// 2. Choose KeyStore: KeychainKeyStore (iOS/macOS production), FileKeyStore (CLI/macOS), or MemoryKeyStore (tests)
let keyStore = KeychainKeyStore(
    service: "com.example.app.synctool",
    stateFileURL: appSupportDirectory.appendingPathComponent("synctool-state.bin")
)

let client = try SyncClient(
    relay: relay,
    keyStore: keyStore,
    appId: "com.example.notes",
    deviceLabel: "My iPhone"
)
defer { Task { await client.close() } }

// 3. Probe connectivity & relay capabilities
let ping = try await client.ping()

// 4. Pair two devices (Flow 1B 8-char room code + mandatory 6-digit SAS verification on both ends)
let peerCard = try await client.acceptDeviceBind(
    pairInput: roomCode,
    options: PairOptions(
        mode: SyncHandshake.modeCommitSas,
        onSASConfirm: { sas in
            await promptUserToConfirmSixDigitSAS(sas)
        }
    )
)

// 5. Push encrypted parcel with file-backed attachment
let sendResult = try await client.sendToPeer(
    targetDeviceId: peerCard.deviceId,
    parcel: ParcelInput(
        appId: "com.example.notes",
        schema: "note.item.v1",
        inlinePayload: ["title": .string("Field Note")],
        blobs: [BlobInput.fromFile(photoFileURL, role: "image")]
    )
)

// 6. Two-phase inbox preview, resumable attachment pull & signed physical burn ACK
let previews = try await client.listInbox(filterAppId: "com.example.notes")
for item in previews {
    let parcel = try await client.fetchParcel(itemId: item.itemId, autoAck: false)
    for blob in parcel.blobs {
        _ = try blob.saveToDir(downloadsDirectory)
    }
    try await client.ackItem(item.itemId)
}
```

## Running Tests & Verification

```bash
# Run golden test vectors (spec/test-vectors/01..07.json) + crypto/envelope hardening tests
swift test --package-path sdk/swift

# Run full cross-language live Go synctool-relay & synctool CLI E2E suite on macOS
go build -o /tmp/synctool-relay-e2e ./cmd/synctool-relay
go build -o /tmp/synctool-cli-e2e ./cmd/synctool
SYNCTOOL_RELAY_BIN=/tmp/synctool-relay-e2e \
SYNCTOOL_CLI_BIN=/tmp/synctool-cli-e2e \
swift test --package-path sdk/swift

# Verify clean iOS Simulator compilation (ensures zero macOS-only API leaks in SyncToolSDK)
(cd sdk/swift && xcodebuild build -scheme SyncToolSDK -destination "generic/platform=iOS Simulator" CODE_SIGN_ALLOWED=NO -quiet)
```
