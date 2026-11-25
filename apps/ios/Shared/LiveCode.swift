import SwiftUI

/// Items known to have no one-time code (klav-core said `NotFound`), so
/// their rows stop asking. Cleared when the vault changes.
@MainActor
enum CodeMemo {
    static var none: Set<String> = []
}

/// A live one-time code: the digits in Departure Mono and the period as
/// blocks, one per second (docs/diseno-visual §4.1). It is asked for only
/// while on screen (the task ends when the view goes away) and again each
/// time the code changes. Tapping it copies the code.
struct LiveCode: View {
    enum Style {
        /// In a list row: small digits, short bar, aligned to the end.
        case row
        /// In an item's fields: large digits and a long bar.
        case detail
    }

    let id: String
    let title: String
    var style: Style = .row
    /// Asks klav-core for the code.
    let fetch: @Sendable (String) async throws -> TotpInfo
    /// The item has no code after all.
    var onNone: () -> Void = {}
    /// Any other failure (a locked vault, mostly).
    var onError: (Error) -> Void = { _ in }
    /// Tapping the code (copy). Nil: not tappable.
    var onCopy: ((String) -> Void)?
    /// Asked for only when tapped, and shown until it changes (the Mac app
    /// with the presence gate on, ADR 0041: each fetch may ask for Touch ID,
    /// so nothing fetches on its own).
    var onDemand = false

    @State private var info: TotpInfo?
    @State private var validUntil = Date.distantPast
    /// On demand: taps so far; each one fetches once.
    @State private var asked = 0
    @Environment(\.dynamicTypeSize) private var typeSize

    var body: some View {
        TimelineView(.periodic(from: .now, by: 1)) { context in
            let left = max(0, Int(validUntil.timeIntervalSince(context.date).rounded(.up)))
            let trailing = style == .row && !typeSize.isAccessibilitySize
            let content = VStack(alignment: trailing ? .trailing : .leading, spacing: style == .row ? 5 : 8) {
                Text(info.map { spacedCode($0.code) } ?? "··· ···")
                    .font(.pixel(style == .row ? 19 : 34, relativeTo: style == .row ? .body : .largeTitle))
                    .foregroundStyle(Palette.tinta)
                    .lineLimit(1)
                    .fixedSize()
                    // Read in the label below, with the seconds left.
                    .accessibilityHidden(true)
                TimeBlocks(remaining: info == nil ? 0 : left, period: Int(info?.period ?? 30),
                           height: style == .row ? 3 : 4)
                    .frame(width: style == .row ? 66 : 220)
            }
            // One element for VoiceOver, the button included: the digits
            // and the blocks are read once, in the label, never again as
            // the text inside.
            Group {
                if onDemand && info == nil {
                    Button { asked += 1 } label: { content.contentShape(Rectangle()) }
                        .buttonStyle(.plain)
                        .accessibilityHint("Shows the code")
                } else if let onCopy, let code = info?.code {
                    Button { onCopy(code) } label: { content.contentShape(Rectangle()) }
                        .buttonStyle(.plain)
                        .accessibilityHint("Copies the code")
                } else {
                    content
                }
            }
            .accessibilityElement(children: .combine)
            .accessibilityLabel(label(left: left))
        }
        .task(id: "\(id)#\(asked)") {
            if onDemand {
                if asked > 0 { await showOnce() }
            } else {
                await refresh()
            }
        }
    }

    /// On demand: fetches the code once and shows it until it changes.
    private func showOnce() async {
        do {
            let fresh = try await fetch(id)
            info = fresh
            validUntil = Date().addingTimeInterval(TimeInterval(fresh.remaining))
            try await Task.sleep(for: .seconds(Double(max(fresh.remaining, 1))))
            info = nil
        } catch is CancellationError {
            return
        } catch KlavError.NotFound, KlavError.Invalid {
            CodeMemo.none.insert(id)
            onNone()
        } catch {
            onError(error)
        }
    }

    private func label(left: Int) -> String {
        guard let info else {
            if onDemand { return String(localized: "One-time code for \(title), hidden") }
            return String(localized: "One-time code for \(title), loading")
        }
        let digits = info.code.map(String.init).joined(separator: " ")
        let changes = String(localized: "Changes in \(left) seconds", comment: "VoiceOver, after the code; plural")
        return String(localized: "One-time code for \(title): \(digits). \(changes)")
    }

    /// Fetches the code, then again each time it changes.
    private func refresh() async {
        while !Task.isCancelled {
            do {
                let fresh = try await fetch(id)
                info = fresh
                validUntil = Date().addingTimeInterval(TimeInterval(fresh.remaining))
                try await Task.sleep(for: .seconds(Double(max(fresh.remaining, 1)) + 0.15))
            } catch is CancellationError {
                return
            } catch KlavError.NotFound, KlavError.Invalid {
                CodeMemo.none.insert(id)
                onNone()
                return
            } catch {
                onError(error)
                return
            }
        }
    }
}

/// A secret that is not on screen: two greys of noise instead of dots.
/// Once shown it dissolves into the text in ~200 ms, pixel by pixel along
/// the same thresholds (instant with Reduce Motion).
struct MaskedValue: View {
    /// The value, once the person asked to see it.
    let value: String?
    var font: Font = .mono(15, relativeTo: .body)
    var hiddenWidth: CGFloat = 140

    @State private var reveal: Double = 1
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        Group {
            if let value {
                Text(value)
                    .font(font)
                    .foregroundStyle(Palette.tinta)
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .overlay {
                        if reveal < 1 {
                            DitherView(kind: .mask, palette: .mask, pixel: 2, reveal: reveal, keep: false)
                        }
                    }
            } else {
                DitherView(kind: .mask, palette: .mask, pixel: 2)
                    .frame(width: hiddenWidth, height: 16)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .accessibilityElement(children: .ignore)
                    .accessibilityLabel("Hidden")
            }
        }
        .onChange(of: value != nil) { _, shown in
            guard shown else { return }
            dissolve()
        }
    }

    private func dissolve() {
        guard !reduceMotion else {
            reveal = 1
            return
        }
        reveal = 0
        Task {
            let steps = 8
            for step in 1...steps {
                try? await Task.sleep(for: .milliseconds(200 / steps))
                reveal = Double(step) / Double(steps)
            }
        }
    }
}
