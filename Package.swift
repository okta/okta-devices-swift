// swift-tools-version: 5.7
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "DeviceAuthenticator",
    platforms: [
        .iOS(.v13),
        .macOS(.v10_15)
    ],
    products: [
        .library(
            name: "DeviceAuthenticator",
            targets: ["DeviceAuthenticator"]),
    ],
    dependencies: [
        .package(url: "https://github.com/groue/GRDB.swift.git", .upToNextMajor(from: "5.0.0")),
        .package(url: "https://github.com/okta/okta-ios-jwt.git", .upToNextMajor(from: "2.3.0")),
        .package(url: "https://github.com/okta/okta-logger-swift.git", .upToNextMajor(from: "1.0.0"))
    ],
    targets: [
        .target(
            name: "DeviceAuthenticator",
            dependencies: [
                .product(name: "GRDB", package: "GRDB.swift"),
                .product(name: "OktaJWT", package: "okta-ios-jwt"),
                .product(name: "OktaFileLogger", package: "okta-logger-swift")
            ]),
        .testTarget(
            name: "DeviceAuthenticatorUnitTests",
            dependencies: ["DeviceAuthenticator"]),
    ]
)
