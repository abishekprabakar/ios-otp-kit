// Walks through the package: RFC 6238 Appendix B regenerated from scratch, Key URI
// round-trip, a vault at a fixed instant, and a verifier handling drift and replay.

import Foundation
import OTPCore

func line(_ s: String = "") { print(s) }

line("== RFC 6238 Appendix B, regenerated (8 digits, X = 30 s, T0 = 0) ==")
let seeds: [(OTPAlgorithm, String)] = [
    (.sha1, "12345678901234567890"),
    (.sha256, "12345678901234567890123456789012"),
    (.sha512, "1234567890123456789012345678901234567890123456789012345678901234"),
]
line("      Unix time        T (hex)          SHA1      SHA256    SHA512")
for t: Int64 in [59, 1_111_111_109, 1_111_111_111, 1_234_567_890, 2_000_000_000, 20_000_000_000] {
    let totps = seeds.map { try! TOTP(secret: Array($0.1.utf8), algorithm: $0.0, digits: 8) }
    let counter = try! totps[0].counter(at: t)
    let codes = totps.map { try! $0.code(at: t) }
    line(String(format: "%15lld  %016llX  ", t, counter) + codes.joined(separator: "  "))
}

line()
line("== RFC 4226 Appendix D, HOTP counter 0...9 ==")
let hotp = try! HOTP(secret: Array("12345678901234567890".utf8))
line((0..<10).map { hotp.code(counter: UInt64($0)) }.joined(separator: " "))

line()
line("== Key URI round trip ==")
let uri = "otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA1&digits=6&period=30"
let acct = try! OTPAccount(uri: uri)
line("parsed : issuer=\(acct.issuer ?? "-") name=\(acct.name) secret=\(acct.secret.count) bytes \(acct.algorithm.rawValue)/\(acct.digits)/\(acct.kind)")
line("emitted: \(acct.uri)")
line("reparse equal: \(try! OTPAccount(uri: acct.uri, id: acct.id) == acct)")

let now: Int64 = 1_760_279_163  // fixed instant so the output is reproducible
let vault = TokenVault()
let sem = DispatchSemaphore(value: 0)
Task {
    let a = try! await vault.add(uri: uri)
    try! await vault.add(uri: "otpauth://totp/GitHub:abishek?secret=JBSWY3DPEHPK3PXP&issuer=GitHub")
    try! await vault.add(uri: "otpauth://totp/Bank:card-1234?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA&algorithm=SHA256&digits=8&period=60")
    let h = try! await vault.add(uri: "otpauth://hotp/VPN:token?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&counter=0")

    line()
    line("== Vault at Unix time \(now) ==")
    for s in try! await vault.snapshots(at: now) {
        let tail = s.secondsRemaining.map { "\($0)s left of \(s.period!)" } ?? "event-based"
        line("  " + s.label.padding(toLength: 30, withPad: " ", startingAt: 0) + s.code.padding(toLength: 10, withPad: " ", startingAt: 0) + tail)
    }

    line()
    line("== Verifier: ACME account, window = 1 step ==")
    let totp = try! TOTP(secret: a.secret)
    let late = try! totp.code(at: now - 30)       // user typed the previous step's code
    line("previous-step code \(late): \(try! await vault.verify(id: a.id, code: late, at: now))")
    line("same code again   \(late): \(try! await vault.verify(id: a.id, code: late, at: now))")
    let older = try! totp.code(at: now - 90)
    line("3 steps old       \(older): \(try! await vault.verify(id: a.id, code: older, at: now))")
    let cur = try! totp.code(at: now)
    line("current code      \(cur): \(try! await vault.verify(id: a.id, code: cur, at: now))")

    line()
    line("== HOTP resync: token pressed 4 times without logging in ==")
    for _ in 0..<4 { _ = try! await vault.nextHOTPCode(id: h.id) }
    let fifth = try! await vault.nextHOTPCode(id: h.id)       // client is now at counter 5
    let restored = try! TokenVault.importJSON(try! await vault.exportJSON())
    line("JSON backup restored \(await restored.accounts.count) accounts; client HOTP counter now \(await restored.accounts.first { $0.id == h.id }!.kind)")
    let verifier = TokenVault(accounts: [OTPAccount(id: h.id, kind: .hotp(counter: 0), issuer: "VPN", name: "token", secret: h.secret)])
    line("server expects 0, user sends \(fifth): \(try! await verifier.verify(id: h.id, code: fifth, at: now))")
    line("server state after resync: \(await verifier.accounts[0].kind)")
    sem.signal()
}
sem.wait()
