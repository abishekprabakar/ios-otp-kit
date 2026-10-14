// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "OTPKit",
    platforms: [
        .iOS(.v16),
        .macOS(.v13),
        .tvOS(.v16),
        .watchOS(.v9),
    ],
    products: [
        .library(name: "OTPCore", targets: ["OTPCore"]),
        .library(name: "OTPUI", targets: ["OTPUI"]),
        .executable(name: "otp-demo", targets: ["otp-demo"]),
    ],
    targets: [
        // Foundation-only: SHA-1/256/512, HMAC, Base32, HOTP/TOTP, otpauth:// URIs,
        // the vault actor. Builds and tests on Linux.
        .target(name: "OTPCore"),
        // SwiftUI authenticator list. Every line is behind `#if canImport(SwiftUI)`,
        // so on Linux this compiles to an empty module; the view only builds in Xcode.
        .target(name: "OTPUI", dependencies: ["OTPCore"]),
        .executableTarget(name: "otp-demo", dependencies: ["OTPCore"]),
        .testTarget(name: "OTPCoreTests", dependencies: ["OTPCore"]),
    ]
)
