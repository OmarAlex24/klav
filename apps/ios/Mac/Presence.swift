import SwiftUI

// The presence gate in the Mac app (ADR 0041, layer 5): the words of the
// master-password sheet, from what `klavd` said the password grants, and
// Settings › Presence, how long one confirmation lasts.

/// What a master password grants, in the app's language (ADR 0041 §2.4).
/// The words follow `lasts`, what `klavd` binds the password to, never the
/// setting alone; with no window, the one value it hands out.
enum PresenceWords {
    static func reason(_ ask: PresenceAskInfo) -> String {
        switch ask.lasts {
        case .fiveMinutes:
            if let who = someoneElse(ask) {
                return String(localized: "Confirming lets \(who) use your vault for 5 minutes.")
            }
            return String(localized: "Confirming lets this app use your vault for 5 minutes.")
        case .untilLock:
            if let who = someoneElse(ask) {
                return String(localized: "Confirming lets \(who) use your vault until Klav locks.")
            }
            return String(localized: "Confirming lets this app use your vault until Klav locks.")
        case nil:
            return once(ask.value)
        }
    }

    /// Who the window is for, when it isn't this app's own connection: the
    /// app's held connection has no terminal, so these are what `klavd`
    /// would have to say about a key the app doesn't expect.
    private static func someoneElse(_ ask: PresenceAskInfo) -> String? {
        guard !ask.declared else { return nil }
        switch ask.key {
        case .connection, .noWindow: return nil
        case .session:
            if let terminal = ask.terminal { return String(localized: "the terminal \(terminal)") }
            return String(localized: "a terminal")
        case .parent: return String(localized: "a program with no terminal")
        }
    }

    /// One value, this once. The title is the item's in the vault: a hint,
    /// already cleaned by `klav-ffi`.
    private static func once(_ value: PresenceValueInfo?) -> String {
        guard let value else { return String(localized: "Confirming hands out this value, this once.") }
        let title = value.title
        switch value.kind {
        case .show:
            if let title { return String(localized: "Confirming shows “\(title)”, this once.") }
            return String(localized: "Confirming shows this item, this once.")
        case .previous:
            if let title { return String(localized: "Confirming shows a previous password of “\(title)”, this once.") }
            return String(localized: "Confirming shows a previous password, this once.")
        case .code:
            if let title { return String(localized: "Confirming shows the one-time code of “\(title)”, this once.") }
            return String(localized: "Confirming shows a one-time code, this once.")
        case .generated:
            return String(localized: "Confirming shows a generated password, this once.")
        case .fill:
            if let title { return String(localized: "Confirming fills “\(title)”, this once.") }
            return String(localized: "Confirming fills a sign-in, this once.")
        case .resolve:
            return String(localized: "Confirming hands out the values of a command, this once.")
        }
    }

    /// What Touch ID or the password authorizes when the setting loosens:
    /// the change only; it opens no window (ADR 0041 §2.4).
    static func loosening(_ setting: PresenceSetting) -> String {
        switch setting {
        case .always: return String(localized: "Ask every time")
        case .fiveMinutes: return String(localized: "Let one confirmation last 5 minutes")
        case .whileUnlocked: return String(localized: "Let one confirmation last until Klav locks")
        }
    }
}

extension PresenceLasts {
    /// The window an unlock's question said it opens, sent back as `shown`.
    var window: PresenceSetting {
        switch self {
        case .fiveMinutes: .fiveMinutes
        case .untilLock: .whileUnlocked
        }
    }
}

extension UnlockQuestionInfo {
    /// What the lock screen says a typed master password opens.
    var words: String? {
        guard gate else { return nil }
        switch lasts {
        case .fiveMinutes:
            return String(localized: "Unlocking with the master password also lets this app use your vault for 5 minutes.")
        case .untilLock:
            return String(localized: "Unlocking with the master password also lets this app use your vault until Klav locks.")
        case nil:
            return String(localized: "After you unlock, each value still asks you to confirm.")
        }
    }
}

/// Settings › Presence: how long one confirmation (Touch ID or the master
/// password) lets a program read values from Klav. Shown only from a
/// `klavd` with the gate on, and only while it is unlocked (Q-N2): locked,
/// `klavd` can't read the setting.
struct PresenceSettingsView: View {
    @EnvironmentObject private var model: MacModel
    @State private var setting: PresenceSetting?
    @State private var changing: PresenceSetting?
    @State private var problem: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            VStack(alignment: .leading, spacing: 6) {
                Text("How long one confirmation lasts")
                    .font(.ui(15, .semibold)).foregroundStyle(Palette.tinta)
                    .accessibilityAddTraits(.isHeader)
                Text("Before Klav hands out a password, a code or a note, it asks for Touch ID or your master password. This applies to every program that reads from Klav on this Mac: this app, the CLI and the browser extension.")
                    .font(.ui(12.5)).foregroundStyle(Palette.gris)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Rule()
            if model.phase != .unlocked {
                Text("Unlock Klav to see and change this setting.")
                    .font(.ui(14)).foregroundStyle(Palette.gris)
                    .accessibilityIdentifier("presence-locked")
            } else if let setting {
                VStack(spacing: 0) {
                    ForEach(Self.options, id: \.self) { option in
                        if option != Self.options.first { Rule() }
                        row(option, selected: option == setting)
                    }
                }
                .overlay(Rectangle().strokeBorder(Palette.linea, lineWidth: 1))
                Text("Choosing a longer time asks for Touch ID or your master password, and counts from your next confirmation. A shorter one applies at once.")
                    .font(.ui(12)).foregroundStyle(Palette.gris)
                    .fixedSize(horizontal: false, vertical: true)
            } else if problem == nil {
                Text("Reading…").font(.ui(14)).foregroundStyle(Palette.gris)
            }
            if let problem { Notice(text: problem) }
            Spacer(minLength: 0)
        }
        .padding(24)
        .frame(width: 520, alignment: .topLeading)
        .frame(minHeight: 400, alignment: .top)
        .background(Palette.papel)
        .task(id: model.phase) { await read() }
        .onDisappear { model.withdrawPrompt(over: .settings) }
        .sheet(item: model.passwordPromptHere(.settings)) { prompt in
            PasswordSheet(prompt: prompt).environmentObject(model)
        }
    }

    private static let options: [PresenceSetting] = [.always, .fiveMinutes, .whileUnlocked]

    private func row(_ option: PresenceSetting, selected: Bool) -> some View {
        Button {
            choose(option)
        } label: {
            HStack(alignment: .top, spacing: 14) {
                ZStack {
                    Rectangle().fill(selected ? Palette.tinta : Palette.papel)
                    Rectangle().strokeBorder(selected ? Palette.tinta : Palette.linea, lineWidth: 1)
                    if selected { Rectangle().fill(Palette.papel).frame(width: 6, height: 6) }
                }
                .frame(width: 18, height: 18)
                .padding(.top, 1)
                VStack(alignment: .leading, spacing: 4) {
                    HStack(spacing: 8) {
                        Text(Self.title(option)).font(.ui(14, .medium)).foregroundStyle(Palette.tinta)
                        if changing == option {
                            Text(model.waitingForPresence).font(.ui(12)).foregroundStyle(Palette.gris)
                        }
                    }
                    Text(Self.detail(option)).font(.ui(12.5)).foregroundStyle(Palette.gris)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: 12)
                Span(option: option, selected: selected)
                    .padding(.top, 5)
                    .accessibilityHidden(true)
            }
            .padding(14)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .disabled(changing != nil)
        .accessibilityAddTraits(selected ? .isSelected : [])
        .accessibilityIdentifier("presence-\(Self.id(option))")
    }

    static func title(_ option: PresenceSetting) -> LocalizedStringKey {
        switch option {
        case .always: "Every time"
        case .fiveMinutes: "For 5 minutes"
        case .whileUnlocked: "While Klav is unlocked"
        }
    }

    static func detail(_ option: PresenceSetting) -> LocalizedStringKey {
        switch option {
        case .always: "Each value asks again, even right after you unlock."
        case .fiveMinutes: "One confirmation covers what that terminal, the browser or this app reads for the next 5 minutes."
        case .whileUnlocked: "One confirmation covers what it reads until Klav locks."
        }
    }

    private static func id(_ option: PresenceSetting) -> String {
        switch option {
        case .always: "always"
        case .fiveMinutes: "5m"
        case .whileUnlocked: "unlocked"
        }
    }

    private func read() async {
        guard model.phase == .unlocked else {
            setting = nil
            problem = nil
            return
        }
        do {
            setting = try await model.presenceSetting()
            problem = nil
        } catch KlavError.Locked {
            setting = nil
            model.refresh()
        } catch {
            problem = describe(error)
        }
    }

    private func choose(_ option: PresenceSetting) {
        guard option != setting, changing == nil else { return }
        problem = nil
        changing = option
        Task {
            do {
                // With the password sheet, this returns once it is up, and
                // the new setting arrives through `done`.
                try await model.setPresenceSetting(option) { setting = $0 }
                changing = nil
            } catch {
                changing = nil
                problem = describe(error)
            }
        }
    }
}

/// How long each choice lasts, drawn in the code's time blocks: one block,
/// five, or a bar to the end.
private struct Span: View {
    let option: PresenceSetting
    let selected: Bool

    var body: some View {
        let color = selected ? Palette.tinta : Palette.cruz
        HStack(spacing: 3) {
            switch option {
            case .always:
                Rectangle().fill(color).frame(width: 6, height: 6)
            case .fiveMinutes:
                ForEach(0..<5, id: \.self) { _ in Rectangle().fill(color).frame(width: 6, height: 6) }
            case .whileUnlocked:
                Rectangle().fill(color).frame(width: 62, height: 6)
            }
        }
        .frame(width: 62, alignment: .leading)
    }
}
