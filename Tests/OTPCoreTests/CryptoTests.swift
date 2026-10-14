// Every expected value here is a published test vector: FIPS 180-2 Appendix A–C /
// NIST CSRC examples for the digests, RFC 2202 (HMAC-SHA1), RFC 4231 (HMAC-SHA-2),
// RFC 4648 §10 (Base32).

import XCTest
@testable import OTPCore

final class DigestTests: XCTestCase {
    let abc = Array("abc".utf8)
    let two448 = Array("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".utf8)
    let two896 = Array("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu".utf8)
    let millionA = [UInt8](repeating: 0x61, count: 1_000_000)

    func testSHA1() {
        XCTAssertEqual(SHA1.hash(abc).hex, "a9993e364706816aba3e25717850c26c9cd0d89d")
        XCTAssertEqual(SHA1.hash([]).hex, "da39a3ee5e6b4b0d3255bfef95601890afd80709")
        XCTAssertEqual(SHA1.hash(two448).hex, "84983e441c3bd26ebaae4aa1f95129e5e54670f1")
        XCTAssertEqual(SHA1.hash(millionA).hex, "34aa973cd4c4daa4f61eeb2bdbad27316534016f")
    }

    func testSHA256() {
        XCTAssertEqual(SHA256.hash(abc).hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        XCTAssertEqual(SHA256.hash([]).hex, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        XCTAssertEqual(SHA256.hash(two448).hex, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1")
        XCTAssertEqual(SHA256.hash(millionA).hex, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0")
    }

    func testSHA512() {
        XCTAssertEqual(SHA512.hash(abc).hex,
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f")
        XCTAssertEqual(SHA512.hash([]).hex,
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e")
        XCTAssertEqual(SHA512.hash(two896).hex,
            "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909")
        XCTAssertEqual(SHA512.hash(millionA).hex,
            "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b")
    }

    /// Lengths straddling the padding boundary (55/56/63/64 bytes for 64-byte blocks;
    /// 111/112 for SHA-512) are where off-by-one padding bugs live. Expected digests of
    /// "a" * n were taken from an independent implementation (Python hashlib).
    func testPaddingBoundaries() {
        let expected256: [Int: String] = [
            55: "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318",
            56: "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a",
            64: "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb",
        ]
        for (n, h) in expected256 {
            XCTAssertEqual(SHA256.hash([UInt8](repeating: 0x61, count: n)).hex, h, "n=\(n)")
        }
        XCTAssertEqual(mdPad([UInt8](repeating: 0, count: 55), blockSize: 64, lengthBytes: 8).count, 64)
        XCTAssertEqual(mdPad([UInt8](repeating: 0, count: 56), blockSize: 64, lengthBytes: 8).count, 128)
        XCTAssertEqual(mdPad([UInt8](repeating: 0, count: 111), blockSize: 128, lengthBytes: 16).count, 128)
        XCTAssertEqual(mdPad([UInt8](repeating: 0, count: 112), blockSize: 128, lengthBytes: 16).count, 256)
    }
}

final class HMACTests: XCTestCase {
    let largeKeyMsg = Array("Test Using Larger Than Block-Size Key - Hash Key First".utf8)

    func testRFC2202SHA1() {
        XCTAssertEqual(OTPAlgorithm.sha1.hmac(key: [UInt8](repeating: 0x0b, count: 20), message: Array("Hi There".utf8)).hex,
                       "b617318655057264e28bc0b6fb378c8ef146be00")
        XCTAssertEqual(OTPAlgorithm.sha1.hmac(key: Array("Jefe".utf8), message: Array("what do ya want for nothing?".utf8)).hex,
                       "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79")
        XCTAssertEqual(OTPAlgorithm.sha1.hmac(key: [UInt8](repeating: 0xaa, count: 80), message: largeKeyMsg).hex,
                       "aa4ae5e15272d00e95705637ce8a3b55ed402112")
    }

    func testRFC4231SHA256() {
        XCTAssertEqual(OTPAlgorithm.sha256.hmac(key: [UInt8](repeating: 0x0b, count: 20), message: Array("Hi There".utf8)).hex,
                       "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
        XCTAssertEqual(OTPAlgorithm.sha256.hmac(key: Array("Jefe".utf8), message: Array("what do ya want for nothing?".utf8)).hex,
                       "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
        XCTAssertEqual(OTPAlgorithm.sha256.hmac(key: [UInt8](repeating: 0xaa, count: 131), message: largeKeyMsg).hex,
                       "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54")
    }

    func testRFC4231SHA512() {
        XCTAssertEqual(OTPAlgorithm.sha512.hmac(key: [UInt8](repeating: 0x0b, count: 20), message: Array("Hi There".utf8)).hex,
            "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854")
        XCTAssertEqual(OTPAlgorithm.sha512.hmac(key: Array("Jefe".utf8), message: Array("what do ya want for nothing?".utf8)).hex,
            "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737")
        XCTAssertEqual(OTPAlgorithm.sha512.hmac(key: [UInt8](repeating: 0xaa, count: 131), message: largeKeyMsg).hex,
            "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598")
    }
}

final class Base32Tests: XCTestCase {
    let vectors: [(String, String)] = [
        ("", ""), ("f", "MY======"), ("fo", "MZXQ===="), ("foo", "MZXW6==="),
        ("foob", "MZXW6YQ="), ("fooba", "MZXW6YTB"), ("foobar", "MZXW6YTBOI======"),
    ]

    func testRFC4648Vectors() throws {
        for (plain, enc) in vectors {
            XCTAssertEqual(Base32.encode(Array(plain.utf8)), enc)
            XCTAssertEqual(try Base32.decode(enc), Array(plain.utf8))
        }
    }

    func testLenientInput() throws {
        XCTAssertEqual(try Base32.decode("mzxw 6ytb-oi"), Array("foobar".utf8))
        XCTAssertEqual(Base32.encode(Array("12345678901234567890".utf8), padding: false), "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
    }

    func testRejectsMalformed() {
        XCTAssertThrowsError(try Base32.decode("MZXW1")) { XCTAssertEqual($0 as? Base32Error, .invalidCharacter("1")) }
        XCTAssertThrowsError(try Base32.decode("MZX")) { XCTAssertEqual($0 as? Base32Error, .invalidLength(3)) }
        // "MZ" decodes to "f" only if the last 2 bits are zero; "M3" has them set.
        XCTAssertThrowsError(try Base32.decode("M3")) { XCTAssertEqual($0 as? Base32Error, .nonZeroTrailingBits) }
    }
}
