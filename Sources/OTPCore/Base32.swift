// RFC 4648 §6 Base32 — the encoding every authenticator uses for shared secrets.

import Foundation

public enum Base32Error: Error, Equatable, Sendable {
    case invalidCharacter(Character)
    /// The number of significant characters cannot come from whole bytes
    /// (valid remainders mod 8 are 0, 2, 4, 5, 7).
    case invalidLength(Int)
    /// Leftover bits in the final character are non-zero — not a canonical encoding.
    case nonZeroTrailingBits
}

public enum Base32 {
    static let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")

    static let lookup: [Character: UInt8] = {
        var t: [Character: UInt8] = [:]
        for (i, c) in alphabet.enumerated() {
            t[c] = UInt8(i)
            t[Character(c.lowercased())] = UInt8(i)
        }
        return t
    }()

    public static func encode(_ bytes: [UInt8], padding: Bool = true) -> String {
        var out = ""
        var buffer: UInt32 = 0
        var bits = 0
        for b in bytes {
            buffer = buffer << 8 | UInt32(b)
            bits += 8
            while bits >= 5 {
                out.append(alphabet[Int((buffer >> UInt32(bits - 5)) & 31)])
                bits -= 5
            }
        }
        if bits > 0 { out.append(alphabet[Int((buffer << UInt32(5 - bits)) & 31)]) }
        if padding { while out.count % 8 != 0 { out.append("=") } }
        return out
    }

    /// Decodes leniently the way users type secrets: case-insensitive, ignores spaces,
    /// hyphens and trailing `=` padding. Rejects anything that is not a canonical
    /// encoding of a whole number of bytes.
    public static func decode(_ string: String) throws -> [UInt8] {
        let cleaned = string.filter { $0 != " " && $0 != "-" && $0 != "\t" }
        var significant = Substring(cleaned)
        while significant.last == "=" { significant.removeLast() }

        switch significant.count % 8 {
        case 1, 3, 6: throw Base32Error.invalidLength(significant.count)
        default: break
        }

        var out: [UInt8] = []
        out.reserveCapacity(significant.count * 5 / 8)
        var buffer: UInt32 = 0
        var bits = 0
        for c in significant {
            guard let v = lookup[c] else { throw Base32Error.invalidCharacter(c) }
            buffer = (buffer << 5 | UInt32(v)) & 0xFFFF
            bits += 5
            if bits >= 8 {
                out.append(UInt8(truncatingIfNeeded: buffer >> UInt32(bits - 8)))
                bits -= 8
            }
        }
        if bits > 0 && (buffer & ((1 << UInt32(bits)) - 1)) != 0 { throw Base32Error.nonZeroTrailingBits }
        return out
    }
}
