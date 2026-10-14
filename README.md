# ios-otp-kit — OTPKit

A SwiftPM package for building an authenticator app (or the verifying server side of one):
**HOTP (RFC 4226)** and **TOTP (RFC 6238)** generation and verification, `otpauth://` Key
URI parsing for enrolment QR codes, and an actor-isolated vault — with **SHA-1, SHA-256,
SHA-512 and HMAC implemented from FIPS 180-4 / RFC 2104**, so the core has zero
dependencies and runs identically on iOS, macOS and Linux.

Every expected value in the test suite is a published vector, not a snapshot of this
code's own output.

## What's in it

| Target | Contents |
|---|---|
| `OTPCore` (Foundation only) | `Hash.swift` — SHA-1/256/512, Merkle–Damgård padding, HMAC. `Base32.swift` — RFC 4648 encode/decode, lenient to spaces/case/padding, rejects non-canonical trailing bits. `OTP.swift` — `HOTP` (dynamic truncation, look-ahead resync), `TOTP` (floor time-step, T0, countdown, ±window verification nearest-first, replay detection), constant-time comparison. `Account.swift` — `OTPAccount` (`Codable`, `Sendable`), Key URI parse/serialise with the format's rules, `TokenVault` actor. |
| `OTPUI` | `AuthenticatorView` — SwiftUI list driven by `TimelineView`, countdown ring, red code in the last 5 s, "Next" button for HOTP. Wrapped in `#if canImport(SwiftUI)`. |
| `otp-demo` | Executable that regenerates the RFC tables and walks through a verifier scenario. |

### The parts that are easy to get wrong

- **Dynamic truncation** reads the offset from the low nibble of the *last* MAC byte, for
  SHA-256/512 too (that is what RFC 6238's reference implementation does), and masks the
  top bit so the result is a positive 31-bit integer. Codes are zero-padded.
- **Time step** is `floor((t − T0) / X)`; times before T0 are an error, not a wrapped counter.
  The 2603-era row of RFC 6238 (`t = 20000000000`) needs a 64-bit counter.
- **Verification** tries the current step, then −1, +1, −2, +2 … so the nearest match wins.
  RFC 6238 §5.2 forbids accepting the same OTP twice; the verifier keeps a high-water mark
  and reports any match at or below it as `.replayed`, including an *older* in-window code
  after a newer one was accepted.
- **HOTP resync** (RFC 4226 §7.4) looks ahead from the expected counter and, on a match,
  stores `matched + 1` — so the consumed code can never be accepted again.
- **Key URIs**: the label is `issuer:account` with the colon possibly percent-encoded; if the
  label prefix and the `issuer=` parameter disagree the URI is rejected (a phishing QR could
  otherwise display one issuer and file the secret under another). `counter` is mandatory
  for HOTP; defaults are SHA1 / 6 digits / 30 s.
- **Actor isolation**: `TokenVault` owns HOTP counters and replay marks, so 200 concurrent
  "Next" presses hand out 200 distinct consecutive counters (tested).

## Usage

```swift
import OTPCore

let vault = TokenVault()
let acct = try await vault.add(uri: "otpauth://totp/GitHub:me?secret=JBSWY3DPEHPK3PXP&issuer=GitHub")
let rows = try await vault.snapshots(at: Int64(Date().timeIntervalSince1970))
// rows[0].code, rows[0].secondsRemaining, rows[0].progress

// Server side
let result = try await vault.verify(id: acct.id, code: "123456", at: now, window: 1)
// .accepted(counter:drift:) / .replayed(counter:) / .rejected
```

In an iOS app target: `import OTPUI` and show `AuthenticatorView(vault: vault)`.

## Run it

```bash
swift test          # 31 XCTest cases
swift run otp-demo
```

## What was actually compiled and tested

- **Toolchain:** Swift 6.0.3 (`swift-6.0.3-RELEASE`, the Ubuntu `swiftlang 6.0.3-2build1`
  packages), x86_64 Ubuntu 24.04, swift-corelibs-foundation.
- **`OTPCore`:** compiled in debug and release. **All 31 XCTest cases pass** on that Linux toolchain.
- **`otp-demo`:** compiled and run on Linux; the output below is pasted from that run. The
  vault codes at the fixed instant were cross-checked against an independent Python
  `hmac`/`hashlib` computation (250771, 788191, 51486079, and 027974 for the previous step).
- **`OTPUI`:** every line is inside `#if canImport(SwiftUI)`, so on Linux the target compiles
  to an empty module. **The SwiftUI view itself has not been compiled.** It only builds in
  Xcode on Apple platforms.
- **Mutation check:** 10 hand-written mutants (truncation offset from first byte, `<` vs `<=`
  in replay, 64-bit SHA-512 length field, HMAC truncating rather than hashing long keys,
  no Base32 trailing-bit check, ceil time-step, ignoring issuer mismatch, forward-only
  window, resync storing `matched` instead of `matched + 1`, SHA-512 σ0 shift→rotate).
  **All 10 were caught** by the suite.

### Test vectors used

| Area | Source |
|---|---|
| SHA-1 / SHA-256 / SHA-512 | FIPS 180 examples: "abc", empty string, 448-bit and 896-bit messages, one million "a" |
| Padding boundaries (55/56/64 bytes) | independent implementation (Python `hashlib`) |
| HMAC-SHA1 | RFC 2202 cases 1, 2, 6 |
| HMAC-SHA256/512 | RFC 4231 cases 1, 2, 6 (6 = key longer than the block) |
| Base32 | RFC 4648 §10 |
| HOTP | RFC 4226 §5.4 worked example and Appendix D (HMACs, truncated values, codes) |
| TOTP | RFC 6238 Appendix B — all 18 rows, SHA1/256/512 |

## Sample output (`swift run otp-demo`)

```
== RFC 6238 Appendix B, regenerated (8 digits, X = 30 s, T0 = 0) ==
      Unix time        T (hex)          SHA1      SHA256    SHA512
             59  0000000000000001  94287082  46119246  90693936
     1111111109  00000000023523EC  07081804  68084774  25091201
     1111111111  00000000023523ED  14050471  67062674  99943326
     1234567890  000000000273EF07  89005924  91819424  93441116
     2000000000  0000000003F940AA  69279037  90698825  38618901
    20000000000  0000000027BC86AA  65353130  77737706  47863826

== RFC 4226 Appendix D, HOTP counter 0...9 ==
755224 287082 359152 969429 338314 254676 287922 162583 399871 520489

== Key URI round trip ==
parsed : issuer=ACME Co name=john.doe@email.com secret=20 bytes SHA1/6/totp(period: 30)
emitted: otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA1&digits=6&period=30
reparse equal: true

== Vault at Unix time 1760279163 ==
  ACME Co (john.doe@email.com)  250771    27s left of 30
  Bank (card-1234)              51486079  57s left of 60
  GitHub (abishek)              788191    27s left of 30
  VPN (token)                   755224    event-based

== Verifier: ACME account, window = 1 step ==
previous-step code 027974: accepted(counter: 58675971, drift: -1)
same code again   027974: replayed(counter: 58675971)
3 steps old       167471: rejected
current code      250771: accepted(counter: 58675972, drift: 0)

== HOTP resync: token pressed 4 times without logging in ==
JSON backup restored 4 accounts; client HOTP counter now hotp(counter: 5)
server expects 0, user sends 338314: accepted(counter: 4, drift: 4)
server state after resync: hotp(counter: 5)
```

## Security notes

The hash implementations are correct against the standard vectors but are written for
clarity, not side-channel resistance. In a shipping Apple-platform app, back `OTPAlgorithm`
with CryptoKit's `HMAC<Insecure.SHA1>` / `HMAC<SHA256>` / `HMAC<SHA512>` and keep secrets
in the Keychain (`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`); `exportJSON()` writes
secrets in the clear and is meant to be encrypted before it touches disk.

## License

MIT
