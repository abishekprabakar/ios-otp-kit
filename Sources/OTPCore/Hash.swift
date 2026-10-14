// SHA-1, SHA-256 and SHA-512 (FIPS 180-4) and HMAC (RFC 2104), written out in full.
//
// On Apple platforms production code should use CryptoKit; it is not available on Linux,
// and swift-crypto is an external dependency. Implementing the three digests here keeps
// the package dependency-free and makes the OTP pipeline testable end to end against the
// published FIPS / RFC vectors.

import Foundation

/// Hash algorithms an OTP account may use (the `algorithm=` parameter of a key URI).
public enum OTPAlgorithm: String, Codable, Sendable, CaseIterable {
    case sha1 = "SHA1"
    case sha256 = "SHA256"
    case sha512 = "SHA512"

    /// Compression-function block size in bytes (64 for SHA-1/256, 128 for SHA-512).
    public var blockSize: Int { self == .sha512 ? 128 : 64 }

    public var digestSize: Int {
        switch self {
        case .sha1: return 20
        case .sha256: return 32
        case .sha512: return 64
        }
    }

    public func hash<D: Sequence>(_ data: D) -> [UInt8] where D.Element == UInt8 {
        let bytes = Array(data)
        switch self {
        case .sha1: return SHA1.hash(bytes)
        case .sha256: return SHA256.hash(bytes)
        case .sha512: return SHA512.hash(bytes)
        }
    }

    /// HMAC per RFC 2104: H((K' ^ opad) || H((K' ^ ipad) || m)), where K' is the key
    /// hashed if longer than one block, then zero-padded to the block size.
    public func hmac(key: [UInt8], message: [UInt8]) -> [UInt8] {
        var k = key.count > blockSize ? hash(key) : key
        k += [UInt8](repeating: 0, count: blockSize - k.count)
        let inner = hash(k.map { $0 ^ 0x36 } + message)
        return hash(k.map { $0 ^ 0x5c } + inner)
    }
}

@inline(__always) private func rotl32(_ x: UInt32, _ n: UInt32) -> UInt32 { (x << n) | (x >> (32 - n)) }
@inline(__always) private func rotr32(_ x: UInt32, _ n: UInt32) -> UInt32 { (x >> n) | (x << (32 - n)) }
@inline(__always) private func rotr64(_ x: UInt64, _ n: UInt64) -> UInt64 { (x >> n) | (x << (64 - n)) }

/// Merkle–Damgård padding: 0x80, zeros, then the bit length big-endian in the last
/// `lengthBytes` bytes (8 for 64-byte blocks, 16 for SHA-512's 128-byte blocks).
func mdPad(_ message: [UInt8], blockSize: Int, lengthBytes: Int) -> [UInt8] {
    var m = message
    let bitLength = UInt64(message.count) &* 8
    m.append(0x80)
    while (m.count + lengthBytes) % blockSize != 0 { m.append(0) }
    // Messages are < 2^61 bytes, so the high bytes of a 128-bit length are zero.
    m += [UInt8](repeating: 0, count: lengthBytes - 8)
    for i in (0..<8).reversed() { m.append(UInt8(truncatingIfNeeded: bitLength >> (UInt64(i) * 8))) }
    return m
}

enum SHA1 {
    static func hash(_ message: [UInt8]) -> [UInt8] {
        var h: [UInt32] = [0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476, 0xC3D2_E1F0]
        let m = mdPad(message, blockSize: 64, lengthBytes: 8)
        var w = [UInt32](repeating: 0, count: 80)
        for chunk in stride(from: 0, to: m.count, by: 64) {
            for t in 0..<16 {
                let i = chunk + 4 * t
                w[t] = UInt32(m[i]) << 24 | UInt32(m[i + 1]) << 16 | UInt32(m[i + 2]) << 8 | UInt32(m[i + 3])
            }
            for t in 16..<80 { w[t] = rotl32(w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16], 1) }
            var (a, b, c, d, e) = (h[0], h[1], h[2], h[3], h[4])
            for t in 0..<80 {
                let f: UInt32, k: UInt32
                switch t {
                case 0..<20: f = (b & c) | (~b & d); k = 0x5A82_7999
                case 20..<40: f = b ^ c ^ d; k = 0x6ED9_EBA1
                case 40..<60: f = (b & c) | (b & d) | (c & d); k = 0x8F1B_BCDC
                default: f = b ^ c ^ d; k = 0xCA62_C1D6
                }
                let temp = rotl32(a, 5) &+ f &+ e &+ k &+ w[t]
                (e, d, c, b, a) = (d, c, rotl32(b, 30), a, temp)
            }
            h[0] = h[0] &+ a; h[1] = h[1] &+ b; h[2] = h[2] &+ c; h[3] = h[3] &+ d; h[4] = h[4] &+ e
        }
        return h.flatMap { v in (0..<4).reversed().map { UInt8(truncatingIfNeeded: v >> (UInt32($0) * 8)) } }
    }
}

enum SHA256 {
    static let k: [UInt32] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ]

    static func hash(_ message: [UInt8]) -> [UInt8] {
        var h: [UInt32] = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                           0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]
        let m = mdPad(message, blockSize: 64, lengthBytes: 8)
        var w = [UInt32](repeating: 0, count: 64)
        for chunk in stride(from: 0, to: m.count, by: 64) {
            for t in 0..<16 {
                let i = chunk + 4 * t
                w[t] = UInt32(m[i]) << 24 | UInt32(m[i + 1]) << 16 | UInt32(m[i + 2]) << 8 | UInt32(m[i + 3])
            }
            for t in 16..<64 {
                let s0 = rotr32(w[t - 15], 7) ^ rotr32(w[t - 15], 18) ^ (w[t - 15] >> 3)
                let s1 = rotr32(w[t - 2], 17) ^ rotr32(w[t - 2], 19) ^ (w[t - 2] >> 10)
                w[t] = w[t - 16] &+ s0 &+ w[t - 7] &+ s1
            }
            var (a, b, c, d, e, f, g, hh) = (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7])
            for t in 0..<64 {
                let S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25)
                let ch = (e & f) ^ (~e & g)
                let t1 = hh &+ S1 &+ ch &+ k[t] &+ w[t]
                let S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22)
                let maj = (a & b) ^ (a & c) ^ (b & c)
                let t2 = S0 &+ maj
                (hh, g, f, e, d, c, b, a) = (g, f, e, d &+ t1, c, b, a, t1 &+ t2)
            }
            for (i, v) in [a, b, c, d, e, f, g, hh].enumerated() { h[i] = h[i] &+ v }
        }
        return h.flatMap { v in (0..<4).reversed().map { UInt8(truncatingIfNeeded: v >> (UInt32($0) * 8)) } }
    }
}

enum SHA512 {
    static let k: [UInt64] = [
        0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538,
        0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe,
        0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
        0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
        0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab,
        0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
        0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed,
        0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
        0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
        0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53,
        0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373,
        0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
        0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c,
        0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6,
        0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
        0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
    ]

    static func hash(_ message: [UInt8]) -> [UInt8] {
        var h: [UInt64] = [0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
                           0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179]
        let m = mdPad(message, blockSize: 128, lengthBytes: 16)
        var w = [UInt64](repeating: 0, count: 80)
        for chunk in stride(from: 0, to: m.count, by: 128) {
            for t in 0..<16 {
                var v: UInt64 = 0
                for j in 0..<8 { v = v << 8 | UInt64(m[chunk + 8 * t + j]) }
                w[t] = v
            }
            for t in 16..<80 {
                let s0 = rotr64(w[t - 15], 1) ^ rotr64(w[t - 15], 8) ^ (w[t - 15] >> 7)
                let s1 = rotr64(w[t - 2], 19) ^ rotr64(w[t - 2], 61) ^ (w[t - 2] >> 6)
                w[t] = w[t - 16] &+ s0 &+ w[t - 7] &+ s1
            }
            var (a, b, c, d, e, f, g, hh) = (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7])
            for t in 0..<80 {
                let S1 = rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41)
                let ch = (e & f) ^ (~e & g)
                let t1 = hh &+ S1 &+ ch &+ k[t] &+ w[t]
                let S0 = rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39)
                let maj = (a & b) ^ (a & c) ^ (b & c)
                let t2 = S0 &+ maj
                (hh, g, f, e, d, c, b, a) = (g, f, e, d &+ t1, c, b, a, t1 &+ t2)
            }
            for (i, v) in [a, b, c, d, e, f, g, hh].enumerated() { h[i] = h[i] &+ v }
        }
        return h.flatMap { v in (0..<8).reversed().map { UInt8(truncatingIfNeeded: v >> (UInt64($0) * 8)) } }
    }
}

extension Array where Element == UInt8 {
    /// Lower-case hex, for tests and diagnostics.
    public var hex: String { map { String(format: "%02x", $0) }.joined() }
}
