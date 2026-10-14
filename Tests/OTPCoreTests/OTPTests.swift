// HOTP/TOTP against RFC 4226 Appendix D and RFC 6238 Appendix B; verifier semantics
// (drift window, replay, look-ahead resync) against hand-worked scenarios; Key URI
// parsing against the format's documented example and its rules; vault concurrency.

import XCTest
@testable import OTPCore

final class HOTPTests: XCTestCase {
    let secret = Array("12345678901234567890".utf8)

    func testRFC4226IntermediateHMACAndTruncation() throws {
        // RFC 4226 Appendix D, "Calculation of HMAC-SHA-1(Secret, Count)" and
        // "Truncated" tables, counts 0...9.
        let hmacs = [
            "cc93cf18508d94934c64b65d8ba7667fb7cde4b0", "75a48a19d4cbe100644e8ac1397eea747a2d33ab",
            "0bacb7fa082fef30782211938bc1c5e70416ff44", "66c28227d03a2d5529262ff016a1e6ef76557ece",
            "a904c900a64b35909874b33e61c5938a8e15ed1c", "a37e783d7b7233c083d4f62926c7a25f238d0316",
            "bc9cd28561042c83f219324d3c607256c03272ae", "a4fb960c0bc06e1eabb804e5b397cdc4b45596fa",
            "1b3c89f65e6c9e883012052823443f048b4332db", "1637409809a679dc698207310c8c7fc07290d9e5",
        ]
        let truncated: [UInt32] = [1284755224, 1094287082, 137359152, 1726969429, 1640338314,
                                   868254676, 1918287922, 82162583, 673399871, 645520489]
        let hotp = try HOTP(secret: secret)
        for c in 0..<10 {
            let mac = hotp.hmac(counter: UInt64(c))
            XCTAssertEqual(mac.hex, hmacs[c], "count \(c)")
            XCTAssertEqual(HOTP.truncate(mac), truncated[c], "count \(c)")
        }
    }

    func testRFC4226Codes() throws {
        let expected = ["755224", "287082", "359152", "969429", "338314",
                        "254676", "287922", "162583", "399871", "520489"]
        let hotp = try HOTP(secret: secret)
        XCTAssertEqual((0..<10).map { hotp.code(counter: UInt64($0)) }, expected)
    }

    func testDynamicTruncationWorkedExample() {
        // RFC 4226 §5.4: last byte 0x5a -> offset 10 -> 0x50ef7f19 -> 872921 (6 digits).
        let mac: [UInt8] = [0x1f, 0x86, 0x98, 0x69, 0x0e, 0x02, 0xca, 0x16, 0x61, 0x85,
                            0x50, 0xef, 0x7f, 0x19, 0xda, 0x8e, 0x94, 0x5b, 0x55, 0x5a]
        XCTAssertEqual(HOTP.truncate(mac), 0x50ef7f19)
        XCTAssertEqual(HOTP.truncate(mac) % 1_000_000, 872921)
    }

    func testLeadingZerosArePreserved() throws {
        // Counter 2 truncates to 137359152, so 8 digits keep only the low 8: "37359152".
        // Among 2000 six-digit codes roughly 10% start with "0"; none may be shortened.
        let hotp = try HOTP(secret: secret, digits: 8)
        XCTAssertEqual(hotp.code(counter: 2), "37359152")
        let zeros = try (0..<2000).map { try HOTP(secret: secret).code(counter: UInt64($0)) }
        XCTAssertTrue(zeros.allSatisfy { $0.count == 6 })
        XCTAssertTrue(zeros.contains { $0.hasPrefix("0") }, "2000 codes should include a leading zero")
    }

    func testLookAheadResync() throws {
        let hotp = try HOTP(secret: secret)
        XCTAssertEqual(hotp.verify("399871", expectedCounter: 3, lookAhead: 10), 8)
        XCTAssertNil(hotp.verify("399871", expectedCounter: 3, lookAhead: 4))  // 3...7 only
        XCTAssertNil(hotp.verify("755224", expectedCounter: 1))                // never goes backwards
    }

    func testRejectsBadParameters() {
        XCTAssertThrowsError(try HOTP(secret: secret, digits: 5)) { XCTAssertEqual($0 as? OTPError, .unsupportedDigits(5)) }
        XCTAssertThrowsError(try HOTP(secret: [])) { XCTAssertEqual($0 as? OTPError, .emptySecret) }
        XCTAssertThrowsError(try TOTP(secret: secret, period: 0)) { XCTAssertEqual($0 as? OTPError, .invalidPeriod(0)) }
    }
}

final class TOTPTests: XCTestCase {
    static let seeds: [OTPAlgorithm: [UInt8]] = [
        .sha1: Array("12345678901234567890".utf8),
        .sha256: Array("12345678901234567890123456789012".utf8),
        .sha512: Array("1234567890123456789012345678901234567890123456789012345678901234".utf8),
    ]

    /// RFC 6238 Appendix B, all 18 rows.
    func testRFC6238AppendixB() throws {
        let table: [(Int64, UInt64, String, String, String)] = [
            (59, 0x1, "94287082", "46119246", "90693936"),
            (1_111_111_109, 0x23523EC, "07081804", "68084774", "25091201"),
            (1_111_111_111, 0x23523ED, "14050471", "67062674", "99943326"),
            (1_234_567_890, 0x273EF07, "89005924", "91819424", "93441116"),
            (2_000_000_000, 0x3F940AA, "69279037", "90698825", "38618901"),
            (20_000_000_000, 0x27BC86AA, "65353130", "77737706", "47863826"),
        ]
        for (t, step, s1, s256, s512) in table {
            for (alg, want) in [(OTPAlgorithm.sha1, s1), (.sha256, s256), (.sha512, s512)] {
                let totp = try TOTP(secret: Self.seeds[alg]!, algorithm: alg, digits: 8)
                XCTAssertEqual(try totp.counter(at: t), step, "T at \(t)")
                XCTAssertEqual(try totp.code(at: t), want, "\(alg) at \(t)")
            }
        }
    }

    func testStepBoundariesAndCountdown() throws {
        let totp = try TOTP(secret: Self.seeds[.sha1]!)
        XCTAssertEqual(try totp.counter(at: 29), 0)
        XCTAssertEqual(try totp.counter(at: 30), 1)
        XCTAssertEqual(totp.secondsRemaining(at: 30), 30)
        XCTAssertEqual(totp.secondsRemaining(at: 59), 1)
        // With T0 = 100 the step edges move with it.
        let shifted = try TOTP(secret: Self.seeds[.sha1]!, period: 30, t0: 100)
        XCTAssertEqual(try shifted.counter(at: 129), 0)
        XCTAssertEqual(try shifted.counter(at: 130), 1)
        XCTAssertThrowsError(try shifted.counter(at: 99)) { XCTAssertEqual($0 as? OTPError, .timeBeforeEpoch) }
        // Date overload floors fractional seconds (59.999 is still step 1).
        XCTAssertEqual(try totp.code(at: Date(timeIntervalSince1970: 59.999)), try totp.code(at: 59))
    }

    func testVerifyWindowNearestFirst() throws {
        let totp = try TOTP(secret: Self.seeds[.sha1]!, digits: 8)
        // At t = 89 (step 2): the step-1 code (t=59 -> 94287082) is one step late.
        XCTAssertEqual(try totp.verify("94287082", at: 89, window: 1), .accepted(counter: 1, drift: -1))
        XCTAssertEqual(try totp.verify("94287082", at: 89, window: 0), .rejected)
        XCTAssertEqual(try totp.verify("94287082", at: 119, window: 1), .rejected)       // step 3: two late
        XCTAssertEqual(try totp.verify("94287082", at: 119, window: 2), .accepted(counter: 1, drift: -2))
        // Near T0 the window must not underflow below step 0.
        XCTAssertEqual(try totp.verify(try totp.code(at: 0), at: 10, window: 3), .accepted(counter: 0, drift: 0))
    }

    func testReplayRejected() throws {
        let totp = try TOTP(secret: Self.seeds[.sha1]!, digits: 8)
        XCTAssertEqual(try totp.verify("94287082", at: 59, lastAcceptedCounter: 1), .replayed(counter: 1))
        // A later counter was already accepted: an older (still in-window) code is a replay too.
        XCTAssertEqual(try totp.verify("94287082", at: 89, lastAcceptedCounter: 2), .replayed(counter: 1))
        XCTAssertEqual(try totp.verify("94287082", at: 89, lastAcceptedCounter: 0), .accepted(counter: 1, drift: -1))
    }

    func testConstantTimeEquals() {
        XCTAssertTrue(constantTimeEquals("123456", "123456"))
        XCTAssertFalse(constantTimeEquals("123456", "123457"))
        XCTAssertFalse(constantTimeEquals("123456", "1234567"))
        XCTAssertFalse(constantTimeEquals("", "0"))
    }
}

final class KeyURITests: XCTestCase {
    /// The example from the Key URI Format documentation.
    let example = "otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA1&digits=6&period=30"

    func testParsesDocumentedExample() throws {
        let a = try OTPAccount(uri: example)
        XCTAssertEqual(a.issuer, "ACME Co")
        XCTAssertEqual(a.name, "john.doe@email.com")
        XCTAssertEqual(a.kind, .totp(period: 30))
        XCTAssertEqual(a.algorithm, .sha1)
        XCTAssertEqual(a.digits, 6)
        XCTAssertEqual(a.secret, try Base32.decode("HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ"))
        XCTAssertEqual(a.secret.count, 20)
    }

    func testDefaultsAndEncodedColon() throws {
        let a = try OTPAccount(uri: "otpauth://totp/Example%3Aalice%40google.com?secret=JBSWY3DPEHPK3PXP")
        XCTAssertEqual(a.issuer, "Example")
        XCTAssertEqual(a.name, "alice@google.com")
        XCTAssertEqual(a.kind, .totp(period: 30))
        XCTAssertEqual(a.algorithm, .sha1)
        XCTAssertEqual(a.digits, 6)
        // JBSWY3DPEHPK3PXP is "Hello!" followed by 0xDEADBEEF.
        XCTAssertEqual(a.secret, [0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x21, 0xde, 0xad, 0xbe, 0xef])
    }

    func testRoundTrip() throws {
        let a = try OTPAccount(uri: "otpauth://hotp/My%20VPN:bob?secret=GEZDGNBVGY3TQOJQ&counter=42&algorithm=sha512&digits=8")
        XCTAssertEqual(a.kind, .hotp(counter: 42))
        XCTAssertEqual(a.algorithm, .sha512)
        let b = try OTPAccount(uri: a.uri, id: a.id)
        XCTAssertEqual(a, b)
    }

    func testRejections() {
        func err(_ s: String) -> KeyURIError? {
            do { _ = try OTPAccount(uri: s); return nil } catch { return error as? KeyURIError }
        }
        XCTAssertEqual(err("https://example.com"), .notOTPAuth)
        XCTAssertEqual(err("otpauth://motp/x?secret=MZXW6YQ"), .unknownType("motp"))
        XCTAssertEqual(err("otpauth://totp/x?issuer=a"), .missingSecret)
        XCTAssertEqual(err("otpauth://hotp/x?secret=MZXW6YQ"), .missingCounter)
        XCTAssertEqual(err("otpauth://totp/x?secret=MZXW6YQ&digits=10"), .invalidParameter("digits"))
        XCTAssertEqual(err("otpauth://totp/x?secret=MZXW6YQ&algorithm=MD5"), .invalidParameter("algorithm"))
        XCTAssertEqual(err("otpauth://totp/x?secret=MZXW1"), .badSecret(.invalidCharacter("1")))
        XCTAssertEqual(err("otpauth://totp/Evil:bob?secret=MZXW6YQ&issuer=Bank"), .issuerMismatch(label: "Evil", parameter: "Bank"))
        XCTAssertEqual(err("otpauth://totp/Bank:?secret=MZXW6YQ"), .emptyAccountName)
    }
}

final class VaultTests: XCTestCase {
    let rfcSecretURI = "otpauth://totp/RFC:sha1?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8"

    func testSnapshotsMatchRFC() async throws {
        let vault = TokenVault()
        try await vault.add(uri: rfcSecretURI)
        let rows = try await vault.snapshots(at: 1_111_111_109)
        XCTAssertEqual(rows.map(\.code), ["07081804"])
        // 1111111109 = 30 * 37037036 + 29: one second left in step 0x23523EC, which is why
        // RFC 6238's next row (1111111111) lands in step 0x23523ED.
        XCTAssertEqual(rows[0].secondsRemaining, 1)
        XCTAssertEqual(rows[0].progress!, 1.0 / 30.0, accuracy: 1e-12)
    }

    func testDuplicateRejected() async throws {
        let vault = TokenVault()
        try await vault.add(uri: rfcSecretURI)
        do { try await vault.add(uri: rfcSecretURI); XCTFail("expected duplicate") }
        catch { XCTAssertEqual(error as? VaultError, .duplicate("RFC (sha1)")) }
    }

    func testVaultReplayHighWaterMark() async throws {
        let vault = TokenVault()
        let a = try await vault.add(uri: rfcSecretURI)
        let r1 = try await vault.verify(id: a.id, code: "94287082", at: 59)
        let r2 = try await vault.verify(id: a.id, code: "94287082", at: 59)
        XCTAssertEqual(r1, .accepted(counter: 1, drift: 0))
        XCTAssertEqual(r2, .replayed(counter: 1))
    }

    func testHOTPClientAndServerResync() async throws {
        let client = TokenVault()
        let acct = try await client.add(uri: "otpauth://hotp/VPN:t?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&counter=0")
        var codes: [String] = []
        for _ in 0..<6 { codes.append(try await client.nextHOTPCode(id: acct.id)) }
        XCTAssertEqual(codes, ["755224", "287082", "359152", "969429", "338314", "254676"])

        let server = TokenVault(accounts: [OTPAccount(id: acct.id, kind: .hotp(counter: 0), issuer: "VPN",
                                                      name: "t", secret: acct.secret)])
        let r = try await server.verify(id: acct.id, code: codes[5], at: 0)
        XCTAssertEqual(r, .accepted(counter: 5, drift: 5))
        let kind = await server.accounts[0].kind
        XCTAssertEqual(kind, .hotp(counter: 6))
        // The consumed code cannot be reused: the server now starts at 6.
        let again = try await server.verify(id: acct.id, code: codes[5], at: 0)
        XCTAssertEqual(again, .rejected)
    }

    /// 200 concurrent presses must hand out 200 distinct consecutive counters; actor
    /// isolation is what guarantees no counter is issued twice.
    func testConcurrentHOTPPressesNeverReuseACounter() async throws {
        let vault = TokenVault()
        let acct = try await vault.add(uri: "otpauth://hotp/VPN:t?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&counter=0")
        let codes = try await withThrowingTaskGroup(of: String.self) { group in
            for _ in 0..<200 { group.addTask { try await vault.nextHOTPCode(id: acct.id) } }
            return try await group.reduce(into: [String]()) { $0.append($1) }
        }
        let hotp = try HOTP(secret: acct.secret)
        XCTAssertEqual(codes.sorted(), (0..<200).map { hotp.code(counter: UInt64($0)) }.sorted())
        let kind = await vault.accounts[0].kind
        XCTAssertEqual(kind, .hotp(counter: 200))
    }

    func testJSONBackupRoundTrip() async throws {
        let vault = TokenVault()
        try await vault.add(uri: rfcSecretURI)
        try await vault.add(uri: "otpauth://hotp/VPN:t?secret=GEZDGNBVGY3TQOJQ&counter=9")
        let restored = try TokenVault.importJSON(try await vault.exportJSON())
        let a = await vault.accounts, b = await restored.accounts
        XCTAssertEqual(a, b)
    }
}
