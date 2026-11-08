// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "FenrirAgent",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .executable(name: "fenrir-agent", targets: ["FenrirAgent"]),
    ],
    dependencies: [
        // No external dependencies needed for Endpoint Security
        // TODO: Add YARA Swift wrapper dependency here
    ],
    targets: [
        .target(name: "FenrirAuditToken", linkerSettings: [.linkedLibrary("bsm")]),
        .executableTarget(
            name: "FenrirAgent",
            dependencies: ["FenrirAuditToken"],
            linkerSettings: [
                .linkedLibrary("EndpointSecurity"),
                .linkedFramework("Foundation"),
                .linkedFramework("CoreServices"),
                .linkedFramework("CryptoKit")
            ]
        ),
    ]
)
