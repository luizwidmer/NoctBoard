// swift-tools-version: 6.0
// SPDX-FileCopyrightText: 2026 Luiz Widmer
// SPDX-License-Identifier: AGPL-3.0-or-later

import Foundation
import PackageDescription

let noctweaveDependency: Package.Dependency
let noctweavePackageIdentity: String

if let localPath = ProcessInfo.processInfo.environment["NOCTWEAVE_PACKAGE_PATH"],
   !localPath.isEmpty {
    noctweaveDependency = .package(path: localPath)
    noctweavePackageIdentity = URL(fileURLWithPath: localPath).lastPathComponent
} else {
    noctweaveDependency = .package(
        url: "https://github.com/luizwidmer/Noctweave.git",
        revision: "ab417cc8f043825ad9ddf4aa92f64dc5c4b31d4f"
    )
    noctweavePackageIdentity = "Noctweave"
}

let package = Package(
    name: "NoctBoard",
    platforms: [
        .macOS(.v14),
    ],
    products: [
        .library(name: "NoctBoardCore", targets: ["NoctBoardCore"]),
        .library(name: "NoctBoardTransport", targets: ["NoctBoardTransport"]),
        .library(name: "NoctBoardUI", targets: ["NoctBoardUI"]),
        .executable(name: "noctboard", targets: ["NoctBoardCLI"]),
        .executable(name: "NoctBoardApp", targets: ["NoctBoardApp"]),
        .executable(name: "NoctBoardDemo", targets: ["NoctBoardDemo"]),
    ],
    dependencies: [noctweaveDependency],
    targets: [
        .target(
            name: "NoctBoardCore",
            dependencies: [
                .product(name: "NoctweaveCore", package: noctweavePackageIdentity),
            ]
        ),
        .target(
            name: "NoctBoardTransport",
            dependencies: [
                "NoctBoardCore",
                .product(name: "NoctweaveCore", package: noctweavePackageIdentity),
            ]
        ),
        .target(
            name: "NoctBoardUI",
            dependencies: [
                "NoctBoardCore",
                "NoctBoardTransport",
                .product(name: "NoctweaveCore", package: noctweavePackageIdentity),
            ]
        ),
        .executableTarget(
            name: "NoctBoardCLI",
            dependencies: [
                "NoctBoardCore",
                "NoctBoardTransport",
                .product(name: "NoctweaveCore", package: noctweavePackageIdentity),
            ]
        ),
        .executableTarget(
            name: "NoctBoardApp",
            dependencies: ["NoctBoardUI"]
        ),
        .executableTarget(
            name: "NoctBoardDemo",
            dependencies: [
                "NoctBoardCore",
                .product(name: "NoctweaveCore", package: noctweavePackageIdentity),
            ]
        ),
        .testTarget(
            name: "NoctBoardCoreTests",
            dependencies: [
                "NoctBoardCore",
                .product(name: "NoctweaveCore", package: noctweavePackageIdentity),
            ]
        ),
        .testTarget(
            name: "NoctBoardTransportTests",
            dependencies: [
                "NoctBoardCore",
                "NoctBoardTransport",
                .product(name: "NoctweaveCore", package: noctweavePackageIdentity),
            ]
        ),
        .testTarget(
            name: "NoctBoardAuditSurfaceTests",
            dependencies: [
                "NoctBoardCore",
                "NoctBoardTransport",
                "NoctBoardUI",
                .product(name: "NoctweaveCore", package: noctweavePackageIdentity),
            ]
        ),
    ]
)
