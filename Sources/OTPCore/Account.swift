// The `otpauth://` Key URI format (what an enrolment QR code contains), the account
// model it decodes to, and an actor-isolated vault of accounts.

import Foundation

public enum KeyURIError: Error, Equatable, Sendable {
    case notOTPAuth
    case unknownType(String)
    case missingSecret
    case badSecret(Base32Error)
    case missingCounter
    case invalidParameter(String)
    case issuerMismatch(label: String, parameter: String)
    case emptyAccountName
}

public struct OTPAccount: Codable, Sendable, Identifiable, Equatable {
    public enum Kind: Codable, Sendable, Equatable {
        case totp(period: Int)
        case hotp(counter: UInt64)
    }

    public var id: UUID
    public var kind: Kind
    public var issuer: String?
    public var name: String
    public var secret: [UInt8]
    public var algorithm: OTPAlgorithm
    public var digits: Int

    public init(id: UUID = UUID(), kind: Kind, issuer: String?, name: String, secret: [UInt8],
                algorithm: OTPAlgorithm = .sha1, digits: Int = 6) {
        self.id = id; self.kind = kind; self.issuer = issuer; self.name = name
        self.secret = secret; self.algorithm = algorithm; self.digits = digits
    }

    public var displayLabel: String { issuer.map { "\($0) (\(name))" } ?? name }

    // MARK: Key URI parsing

    /// Parses `otpauth://TYPE/[ISSUER:]ACCOUNT?secret=…&issuer=…&algorithm=…&digits=…&period=…&counter=…`.
    /// Defaults: SHA1, 6 digits, 30 s. `counter` is mandatory for HOTP. If the label
    /// prefix and the `issuer` parameter are both present they must agree.
    public init(uri: String, id: UUID = UUID()) throws {
        guard let comps = URLComponents(string: uri), comps.scheme?.lowercased() == "otpauth",
              let type = comps.host?.lowercased() else { throw KeyURIError.notOTPAuth }
        var params: [String: String] = [:]
        for item in comps.queryItems ?? [] { params[item.name.lowercased()] = item.value ?? "" }

        var label = comps.path
        if label.hasPrefix("/") { label.removeFirst() }
        var labelIssuer: String?
        var name = label
        if let colon = label.firstIndex(of: ":") {
            labelIssuer = String(label[..<colon]).trimmingCharacters(in: .whitespaces)
            name = String(label[label.index(after: colon)...]).trimmingCharacters(in: .whitespaces)
        }
        guard !name.isEmpty else { throw KeyURIError.emptyAccountName }

        let paramIssuer = params["issuer"].flatMap { $0.isEmpty ? nil : $0 }
        if let l = labelIssuer, let p = paramIssuer, l != p {
            throw KeyURIError.issuerMismatch(label: l, parameter: p)
        }

        guard let secretText = params["secret"], !secretText.isEmpty else { throw KeyURIError.missingSecret }
        let secret: [UInt8]
        do { secret = try Base32.decode(secretText) } catch let e as Base32Error { throw KeyURIError.badSecret(e) }
        guard !secret.isEmpty else { throw KeyURIError.missingSecret }

        var algorithm = OTPAlgorithm.sha1
        if let a = params["algorithm"] {
            guard let parsed = OTPAlgorithm(rawValue: a.uppercased()) else { throw KeyURIError.invalidParameter("algorithm") }
            algorithm = parsed
        }
        var digits = 6
        if let d = params["digits"] {
            guard let n = Int(d), (6...8).contains(n) else { throw KeyURIError.invalidParameter("digits") }
            digits = n
        }

        let kind: Kind
        switch type {
        case "totp":
            var period = 30
            if let p = params["period"] {
                guard let n = Int(p), n > 0 else { throw KeyURIError.invalidParameter("period") }
                period = n
            }
            kind = .totp(period: period)
        case "hotp":
            guard let c = params["counter"] else { throw KeyURIError.missingCounter }
            guard let n = UInt64(c) else { throw KeyURIError.invalidParameter("counter") }
            kind = .hotp(counter: n)
        default:
            throw KeyURIError.unknownType(type)
        }

        self.init(id: id, kind: kind, issuer: paramIssuer ?? labelIssuer, name: name,
                  secret: secret, algorithm: algorithm, digits: digits)
    }

    /// Serialises back to a Key URI (issuer in both label and parameter, as recommended).
    public var uri: String {
        let typeAndExtra: (String, String)
        switch kind {
        case .totp(let p): typeAndExtra = ("totp", "&period=\(p)")
        case .hotp(let c): typeAndExtra = ("hotp", "&counter=\(c)")
        }
        let label = (issuer.map { pct($0) + ":" } ?? "") + pct(name)
        var s = "otpauth://\(typeAndExtra.0)/\(label)?secret=\(Base32.encode(secret, padding: false))"
        if let issuer { s += "&issuer=\(pct(issuer))" }
        s += "&algorithm=\(algorithm.rawValue)&digits=\(digits)" + typeAndExtra.1
        return s
    }

    private func pct(_ s: String) -> String {
        var allowed = CharacterSet.alphanumerics
        allowed.insert(charactersIn: "-._~@")
        return s.addingPercentEncoding(withAllowedCharacters: allowed) ?? s
    }

    func makeTOTP(period: Int) throws -> TOTP {
        try TOTP(secret: secret, algorithm: algorithm, digits: digits, period: period)
    }

    func makeHOTP() throws -> HOTP { try HOTP(secret: secret, algorithm: algorithm, digits: digits) }
}

/// What a list row shows.
public struct CodeSnapshot: Sendable, Equatable, Identifiable {
    public let id: UUID
    public let label: String
    public let code: String
    /// Seconds left in the current step for TOTP; nil for HOTP (event-based).
    public let secondsRemaining: Int?
    public let period: Int?

    public var progress: Double? {
        guard let s = secondsRemaining, let p = period else { return nil }
        return Double(s) / Double(p)
    }
}

public enum VaultError: Error, Equatable, Sendable {
    case duplicate(String)
    case notFound
    case wrongKind
}

/// Actor-isolated store. Mutating state (HOTP counters, replay high-water marks) is only
/// touched inside the actor, so concurrent views and verifiers cannot race on a counter.
public actor TokenVault {
    public private(set) var accounts: [OTPAccount] = []
    private var lastAccepted: [UUID: UInt64] = [:]

    public init(accounts: [OTPAccount] = []) { self.accounts = accounts }

    @discardableResult
    public func add(uri: String) throws -> OTPAccount {
        try add(OTPAccount(uri: uri))
    }

    @discardableResult
    public func add(_ account: OTPAccount) throws -> OTPAccount {
        if accounts.contains(where: { $0.issuer == account.issuer && $0.name == account.name }) {
            throw VaultError.duplicate(account.displayLabel)
        }
        _ = try account.makeHOTP()  // validates digits / secret up front
        accounts.append(account)
        return account
    }

    public func remove(id: UUID) {
        accounts.removeAll { $0.id == id }
        lastAccepted[id] = nil
    }

    /// Codes for every account at `unixTime`, sorted by label. HOTP rows show the code for
    /// the current counter without consuming it.
    public func snapshots(at unixTime: Int64) throws -> [CodeSnapshot] {
        try accounts.map { a -> CodeSnapshot in
            switch a.kind {
            case .totp(let period):
                let t = try a.makeTOTP(period: period)
                return CodeSnapshot(id: a.id, label: a.displayLabel, code: try t.code(at: unixTime),
                                    secondsRemaining: t.secondsRemaining(at: unixTime), period: period)
            case .hotp(let counter):
                return CodeSnapshot(id: a.id, label: a.displayLabel, code: try a.makeHOTP().code(counter: counter),
                                    secondsRemaining: nil, period: nil)
            }
        }
        .sorted { $0.label.localizedCaseInsensitiveCompare($1.label) == .orderedAscending }
    }

    /// Client side of HOTP: return the code for the current counter and advance it.
    public func nextHOTPCode(id: UUID) throws -> String {
        guard let i = accounts.firstIndex(where: { $0.id == id }) else { throw VaultError.notFound }
        guard case .hotp(let counter) = accounts[i].kind else { throw VaultError.wrongKind }
        let code = try accounts[i].makeHOTP().code(counter: counter)
        accounts[i].kind = .hotp(counter: counter + 1)
        return code
    }

    /// Verifier side. TOTP: ±`window` steps with replay protection. HOTP: look-ahead
    /// resync; on success the stored counter jumps to matched + 1.
    public func verify(id: UUID, code: String, at unixTime: Int64, window: Int = 1,
                       lookAhead: Int = 10) throws -> TOTP.Verification {
        guard let i = accounts.firstIndex(where: { $0.id == id }) else { throw VaultError.notFound }
        switch accounts[i].kind {
        case .totp(let period):
            let result = try accounts[i].makeTOTP(period: period)
                .verify(code, at: unixTime, window: window, lastAcceptedCounter: lastAccepted[id])
            if case .accepted(let c, _) = result { lastAccepted[id] = c }
            return result
        case .hotp(let counter):
            guard let matched = try accounts[i].makeHOTP().verify(code, expectedCounter: counter, lookAhead: lookAhead)
            else { return .rejected }
            accounts[i].kind = .hotp(counter: matched + 1)
            return .accepted(counter: matched, drift: Int(matched - counter))
        }
    }

    public func exportJSON() throws -> Data {
        let enc = JSONEncoder()
        enc.outputFormatting = [.sortedKeys]
        return try enc.encode(accounts)
    }

    public static func importJSON(_ data: Data) throws -> TokenVault {
        TokenVault(accounts: try JSONDecoder().decode([OTPAccount].self, from: data))
    }
}
