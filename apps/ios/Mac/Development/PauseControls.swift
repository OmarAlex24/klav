import SwiftUI

/// «Pause agents» above Development › Agents (ADR 0033 §7.5): pausing
/// asks nothing (P2), resuming asks for Touch ID. A pause decided while
/// klavd could not reach the server says it holds on this Mac only.
struct PauseBar: View {
    @EnvironmentObject private var model: MacModel
    @State private var length: PauseLength = .hour
    @State private var busy = false
    @State private var problem: String?

    var body: some View {
        Group {
            if let pause = model.everyonePaused { paused(pause) } else { running }
        }
        .overlay(Rectangle().strokeBorder(model.everyonePaused == nil ? Palette.linea : Palette.cobalto, lineWidth: 1))
        .crossCorners()
    }

    private var running: some View {
        HStack(alignment: .top, spacing: 14) {
            IconView(icon: .pause, size: 16)
                .foregroundStyle(Palette.tinta)
                .frame(width: 28, height: 28)
                .overlay(Rectangle().strokeBorder(Palette.linea, lineWidth: 1))
            VStack(alignment: .leading, spacing: 6) {
                Text("Pause agents").font(.ui(15, .semibold)).foregroundStyle(Palette.tinta)
                // Resuming goes through presence: Touch ID, or the master
                // password on a Mac without it (`withPresence`).
                Text(model.touchIDReady
                     ? String(localized: "Stops every agent of your account at once, on this Mac and everywhere else, until the time is up or you resume. Pausing asks nothing; resuming asks for Touch ID.")
                     : String(localized: "Stops every agent of your account at once, on this Mac and everywhere else, until the time is up or you resume. Pausing asks nothing; resuming asks for your master password."))
                    .font(.ui(12.5)).foregroundStyle(Palette.gris)
                    .fixedSize(horizontal: false, vertical: true)
                // What a pause does not stop (ADR 0033 §7.7).
                Text("It doesn’t take back what an agent already has: a process it started, a file it was given, what it read. For a stolen key, revoke and rotate.")
                    .font(.ui(12)).foregroundStyle(Palette.gris)
                    .fixedSize(horizontal: false, vertical: true)
                HStack(spacing: 8) {
                    ForEach(PauseLength.allCases) { option in
                        Chip(text: option.label, on: length == option) { length = option }
                    }
                    Spacer(minLength: 8)
                    Button(busy ? String(localized: "Pausing…") : String(localized: "Pause")) {
                        Task { await pause() }
                    }
                    .buttonStyle(PrimaryButtonStyle(compact: true))
                    .fixedSize()
                    .disabled(busy)
                }
                .padding(.top, 4)
                if let problem { Notice(text: problem) }
            }
        }
        .padding(16)
    }

    private func paused(_ pause: PauseInfo) -> some View {
        HStack(alignment: .top, spacing: 0) {
            CompactMark().frame(width: 10)
            VStack(alignment: .leading, spacing: 6) {
                Text(verbatim: PauseWords.title(pause)).font(.ui(15, .semibold)).foregroundStyle(Palette.cobalto)
                Text(verbatim: PauseWords.span(pause))
                    .font(.ui(12.5)).foregroundStyle(Palette.gris)
                if let note = PauseWords.whereItHolds(pause) {
                    Notice(text: note, tone: .info).padding(.top, 2)
                }
                HStack(spacing: 10) {
                    Button(busy ? model.waitingForPresence : String(localized: "Resume")) {
                        Task { await resume() }
                    }
                    .buttonStyle(PrimaryButtonStyle(compact: true))
                    .fixedSize()
                    .disabled(busy)
                    Text(model.touchIDReady ? String(localized: "Agents can use Klav again after Touch ID.")
                                            : String(localized: "Agents can use Klav again once you enter your master password."))
                        .font(.ui(12)).foregroundStyle(Palette.gris)
                }
                .padding(.top, 4)
                if let problem { Notice(text: problem) }
            }
            .padding(16)
            Spacer(minLength: 0)
        }
        .fixedSize(horizontal: false, vertical: true)
    }

    private func pause() async {
        busy = true
        problem = nil
        do { try await model.pauseAgents(minutes: length.minutes) } catch { problem = describe(error) }
        busy = false
    }

    private func resume() async {
        busy = true
        problem = nil
        do { try await model.resumeAgents() } catch { problem = describe(error) }
        busy = false
    }
}

/// The menu bar's line for the pause: pause in one click, or the pause in
/// effect with «Resume», which opens the window (Touch ID).
struct PauseLine: View {
    @EnvironmentObject private var model: MacModel
    var open: () -> Void
    @State private var problem: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            if let pause = model.everyonePaused {
                let locked = model.phase != .unlocked
                HStack(spacing: 10) {
                    CompactMark().frame(width: 6, height: 28)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(verbatim: PauseWords.title(pause)).font(.ui(13, .medium)).foregroundStyle(Palette.cobalto)
                            .lineLimit(1)
                        Text(verbatim: PauseWords.span(pause)).font(.ui(12)).foregroundStyle(Palette.gris).lineLimit(1)
                    }
                    Spacer()
                    if PauseWords.offersUnlock(pause, locked: locked) {
                        // Unlocking signs the pause and sends it (§7.3).
                        SmallAction(title: "Unlock to pause everywhere") { open() }
                    } else {
                        SmallAction(title: "Resume") {
                            model.section = .agents
                            open()
                        }
                    }
                }
                // Said, not hidden: where the pause holds (§7.2).
                if let note = PauseWords.whereItHolds(pause, locked: locked) {
                    Text(verbatim: note).font(.ui(12)).foregroundStyle(Palette.gris)
                        .fixedSize(horizontal: false, vertical: true)
                }
            } else {
                HStack(spacing: 10) {
                    IconView(icon: .pause, size: 14).foregroundStyle(Palette.tinta)
                        .frame(width: 6)
                    Text("Pause agents").font(.ui(13, .medium)).foregroundStyle(Palette.tinta)
                    Spacer()
                    SmallAction(title: "1 hour") { Task { await pause(60) } }
                    SmallAction(title: "Until I resume") { Task { await pause(nil) } }
                }
            }
            if let problem { Notice(text: problem) }
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
    }

    private func pause(_ minutes: Int?) async {
        problem = nil
        do { try await model.pauseAgents(minutes: minutes) } catch { problem = describe(error) }
    }
}

/// What changed outside Klav in a client's entry or a copy of the skill
/// (ADR 0033 §4, §6), in red, with «See» (or «See the changes») and
/// «Leave it». In the menu bar and at the top of Clients.
struct ClientWarningsView: View {
    @EnvironmentObject private var model: MacModel
    /// Opens the window (from the menu bar).
    var open: (() -> Void)?

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            ForEach(model.shownWarnings) { warning in
                HStack(alignment: .firstTextBaseline, spacing: 10) {
                    Text(verbatim: warning.text)
                        .font(.ui(12.5, .medium)).foregroundStyle(Palette.rojo)
                        .fixedSize(horizontal: false, vertical: true)
                    Spacer(minLength: 6)
                    SmallAction(title: warning.kind == .skillEdited ? "See the changes" : "See") {
                        model.see(warning)
                        open?()
                    }
                    SmallAction(title: "Leave it") { model.leave(warning) }
                }
            }
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
    }
}
