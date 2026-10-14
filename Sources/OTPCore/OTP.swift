// HOTP (RFC 4226) and TOTP (RFC 6238): generation, and server-side verification with a
// drift window, look-ahead resynchronisation and replay protection.

import Foundation

public enum OTPError: Error, Equatable, Sendable {
    case unsupportedDigits(Int)
    case invalidPeriod(Int)
    case timeBeforeEpoch
    case emptySecret
}

/// The RFC 4226 one-time-password function. `digits` is 6...8 (RFC 4226 §5.3 requires at
/// least 6; the 31-bit truncated value only supports 9 full digits, and no deployed
/// authenticator uses more than 8).
public struct HOTP: Sendable, Equatable {
    public let secret: [UInt8]
    public let algorithm: OTPAlgorithm
    public let digits: Int

    public init(secret: [UInt8], algorithm: OTPAlgorithm = .sha1, digits: Int = 6) throws {
        guard !secret.isEmpty else { throw OTPError.emptySecret }
        guard (6...8).contains(digits) else { throw OTPError.unsupportedDigits(digits) }
        self.secret = secret
        self.algorithm = algorithm
        self.digits = digits
    }

    /// HMAC over the counter as an 8-byte big-endian integer (RFC 4226 §5.2).
    public func hmac(counter: UInt64) -> [UInt8] {
        let message = (0..<8).reversed().map { UInt8(truncatingIfNeeded: counter >> (UInt64($0) * 8)) }
        return algorithm.hmac(key: secret, message: message)
    }

    /// Dynamic truncation (RFC 4226 §5.3): the low nibble of the LAST byte picks an offset;
    /// four bytes from there, with the top bit masked off, form a 31-bit integer. Using the
    /// last byte also for SHA-256/512 is what RFC 6238's reference code does.
    public static func truncate(_ mac: [UInt8]) -> UInt32 {
        let offset = Int(mac[mac.count - 1] & 0x0f)
        return UInt32(mac[offset] & 0x7f) << 24
            | UInt32(mac[offset + 1]) << 16
            | UInt32(mac[offset + 2]) << 8
            | UInt32(mac[offset + 3])
    }

    public func code(counter: UInt64) -> String {
        var modulus: UInt32 = 1
        for _ in 0..<digits { modulus *= 10 }
        let value = HOTP.truncate(hmac(counter: counter)) % modulus
        let s = String(value)
        return String(repeating: "0", count: digits - s.count) + s
    }

    /// RFC 4226 §7.4 resynchronisation: accept a code from `counter` up to
    /// `counter + lookAhead`. Returns the counter that matched; the server must store
    /// `matched + 1` as the next expected counter.
    public func verify(_ candidate: String, expectedCounter counter: UInt64, lookAhead: Int = 10) -> UInt64? {
        for i in 0...UInt64(max(0, lookAhead)) {
            let c = counter &+ i
            if constantTimeEquals(code(counter: c), candidate) { return c }
        }
        return nil
    }
}

/// RFC 6238: HOTP with counter T = floor((now - T0) / X).
public struct TOTP: Sendable, Equatable {
    public let hotp: HOTP
    public let period: Int
    public let t0: Int64

    public init(secret: [UInt8], algorithm: OTPAlgorithm = .sha1, digits: Int = 6,
                period: Int = 30, t0: Int64 = 0) throws {
        guard period > 0 else { throw OTPError.invalidPeriod(period) }
        self.hotp = try HOTP(secret: secret, algorithm: algorithm, digits: digits)
        self.period = period
        self.t0 = t0
    }

    /// Time step for a Unix time in whole seconds. Floor division, so a time inside a
    /// step always maps to that step; times before T0 are rejected rather than wrapped.
    public func counter(at unixTime: Int64) throws -> UInt64 {
        guard unixTime >= t0 else { throw OTPError.timeBeforeEpoch }
        return UInt64((unixTime - t0) / Int64(period))
    }

    public func code(at unixTime: Int64) throws -> String {
        hotp.code(counter: try counter(at: unixTime))
    }

    public func code(at date: Date) throws -> String {
        try code(at: Int64(date.timeIntervalSince1970.rounded(.down)))
    }

    /// Seconds until the current code rolls over (1...period).
    public func secondsRemaining(at unixTime: Int64) -> Int {
        let into = Int((unixTime - t0) % Int64(period))
        return period - (into < 0 ? into + period : into)
    }

    public enum Verification: Equatable, Sendable {
        /// Matched at `counter`, which is `drift` steps from the verifier's current step.
        case accepted(counter: UInt64, drift: Int)
        /// Matched, but at or before the last counter this account already accepted.
        case replayed(counter: UInt64)
        case rejected
    }

    /// Server-side check (RFC 6238 §5.2): try the current step, then ±1, ±2 … up to
    /// `window`, nearest first. RFC 6238 §5.2 says a verifier MUST NOT accept the same
    /// OTP twice, so any match at or below `lastAcceptedCounter` is a replay.
    public func verify(_ candidate: String, at unixTime: Int64, window: Int = 1,
                       lastAcceptedCounter: UInt64? = nil) throws -> Verification {
        let now = try counter(at: unixTime)
        var order = [0]
        if window > 0 { for d in 1...window { order += [-d, d] } }
        for drift in order {
            if drift < 0 && UInt64(-drift) > now { continue }
            let c = drift < 0 ? now - UInt64(-drift) : now + UInt64(drift)
            guard constantTimeEquals(hotp.code(counter: c), candidate) else { continue }
            if let last = lastAcceptedCounter, c <= last { return .replayed(counter: c) }
            return .accepted(counter: c, drift: drift)
        }
        return .rejected
    }
}

/// Compares two codes without an early exit, so response timing does not reveal how many
/// leading digits of a guess were right.
public func constantTimeEquals(_ a: String, _ b: String) -> Bool {
    let x = Array(a.utf8), y = Array(b.utf8)
    var diff = UInt8(x.count == y.count ? 0 : 1)
    for i in 0..<max(x.count, y.count) {
        diff |= (i < x.count ? x[i] : 0) ^ (i < y.count ? y[i] : 0)
    }
    return diff == 0
}
