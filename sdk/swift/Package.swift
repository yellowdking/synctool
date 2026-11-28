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
            path: "Sources/SyncToolSDK"
        ),
        .testTarget(
            name: "SyncToolSDKTests",
            dependencies: ["SyncToolSDK"],
            path: "Tests/SyncToolSDKTests"
        ),
    ]
)
