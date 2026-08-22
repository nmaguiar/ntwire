// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "NTWire",
    platforms: [.iOS(.v17), .macOS(.v14)],
    products: [
        .library(name: "NTWireCore", targets: ["NTWireCore"])
    ],
    targets: [
        .target(name: "NTWireCore"),
        .testTarget(name: "NTWireCoreTests", dependencies: ["NTWireCore"])
    ]
)
