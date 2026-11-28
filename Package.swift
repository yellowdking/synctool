// swift-tools-version: 5.10
import PackageDescription

let package = Package(
    name: "SyncToolSDK",
    platforms: [
        .iOS(.v16),
        .macOS(.v13),
    ],
    products: [
        .library(
            name: "SyncToolSDK",
            targets: ["SyncToolSDK"]
        ),
    ],
    targets: [
        .target(
            name: "SyncToolSDK",
            path: "sdk/swift/Sources/SyncToolSDK"
        ),
    ]
)
