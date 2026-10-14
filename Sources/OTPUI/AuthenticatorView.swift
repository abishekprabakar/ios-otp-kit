// SwiftUI authenticator list. Everything is behind `#if canImport(SwiftUI)`: on Linux
// this file compiles to nothing, and the view itself only builds in Xcode.

#if canImport(SwiftUI)
import SwiftUI
import OTPCore

@available(iOS 16, macOS 13, tvOS 16, watchOS 9, *)
public struct AuthenticatorView: View {
    let vault: TokenVault
    @State private var rows: [CodeSnapshot] = []
    @State private var error: String?

    public init(vault: TokenVault) { self.vault = vault }

    public var body: some View {
        TimelineView(.periodic(from: .now, by: 1)) { context in
            List(rows) { row in
                CodeRow(row: row) {
                    if row.secondsRemaining == nil {
                        Task {
                            _ = try? await vault.nextHOTPCode(id: row.id)
                            await refresh(at: .now)
                        }
                    }
                }
            }
            .overlay { if let error { Text(error).foregroundStyle(.red) } }
            .task(id: Int(context.date.timeIntervalSince1970)) { await refresh(at: context.date) }
        }
        .navigationTitle("Codes")
    }

    private func refresh(at date: Date) async {
        do {
            rows = try await vault.snapshots(at: Int64(date.timeIntervalSince1970))
            error = nil
        } catch {
            self.error = String(describing: error)
        }
    }
}

@available(iOS 16, macOS 13, tvOS 16, watchOS 9, *)
struct CodeRow: View {
    let row: CodeSnapshot
    let onTapHOTP: () -> Void

    var body: some View {
        HStack {
            VStack(alignment: .leading, spacing: 4) {
                Text(row.label).font(.subheadline).foregroundStyle(.secondary)
                Text(grouped(row.code))
                    .font(.system(.title, design: .monospaced).weight(.semibold))
                    .foregroundStyle((row.secondsRemaining ?? 99) <= 5 ? .red : .primary)
                    .contentTransition(.numericText())
            }
            Spacer()
            if let progress = row.progress, let s = row.secondsRemaining {
                ZStack {
                    Circle().stroke(.quaternary, lineWidth: 4)
                    Circle().trim(from: 0, to: progress)
                        .stroke(.tint, style: StrokeStyle(lineWidth: 4, lineCap: .round))
                        .rotationEffect(.degrees(-90))
                    Text("\(s)").font(.caption.monospacedDigit())
                }
                .frame(width: 32, height: 32)
                .accessibilityLabel("\(s) seconds remaining")
            } else {
                Button("Next", action: onTapHOTP).buttonStyle(.bordered)
            }
        }
        .padding(.vertical, 4)
    }

    /// "123456" -> "123 456", "12345678" -> "1234 5678".
    private func grouped(_ code: String) -> String {
        let mid = code.index(code.startIndex, offsetBy: code.count / 2)
        return code[..<mid] + " " + code[mid...]
    }
}
#endif
