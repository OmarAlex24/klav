import AppKit
import SwiftUI

/// The menu bar icon: the pixel key, solid when unlocked and faint when
/// not, and the number of requests waiting next to it.
struct MenuBarLabel: View {
    @EnvironmentObject private var model: MacModel
    @EnvironmentObject private var installer: Installer
    @Environment(\.openWindow) private var openWindow
    @Environment(\.openSettings) private var openSettings

    var body: some View {
        HStack(spacing: 3) {
            Image(nsImage: KeyIcon.image(unlocked: model.phase == .unlocked, paused: model.everyonePaused != nil))
            if model.pendingCount > 0 {
                Text(verbatim: "\(model.pendingCount)")
            }
        }
        .accessibilityLabel(label)
        .task {
            model.start()
            #if DEBUG
            Snapshot.apply(to: model)
            Snapshot.openWindows({ openWindow(id: $0) }, settings: { openSettings() })
            #endif
        }
        .onReceive(NotificationCenter.default.publisher(for: .klavOpenMain)) { _ in
            openWindow(id: WindowID.main)
        }
        // Another klav on the PATH older than this app's, whether klavd
        // runs or not (docs/macos.md §3).
        .task { await installer.checkCLIs() }
        // After an update, klavd may still be the old app's (ADR 0027 §4).
        .onChange(of: model.info?.running == true, initial: true) { _, running in
            guard running, let info = model.info else { return }
            Task {
                if await installer.checkVersion(engine: model.engine, info: info) { model.refresh() }
                // The skill follows this app's klav (ADR 0033 §6), once,
                // and then what changed outside Klav is said (§4, §6).
                await model.updateSkillAtLaunch(installer)
                await model.checkClientsAtLaunch(installer)
            }
        }
    }

    private var label: Text {
        var state = model.phase == .unlocked ? Text("Klav, unlocked") : Text("Klav, locked")
        if model.everyonePaused != nil { state = Text("\(state), agents paused") }
        guard model.pendingCount > 0 else { return state }
        return Text("\(state), \(model.pendingCount) requests waiting")
    }
}

/// The pixel key as a template image for the menu bar; with every agent
/// paused, two bars under its teeth (ADR 0033 §7.5).
enum KeyIcon {
    private static var cache: [Int: NSImage] = [:]

    static func image(unlocked: Bool, paused: Bool = false) -> NSImage {
        let key = (unlocked ? 1 : 0) + (paused ? 2 : 0)
        if let image = cache[key] { return image }
        let size = NSSize(width: 18, height: 18)
        let image = NSImage(size: size, flipped: true) { rect in
            let cell = rect.width / 9
            let inset = (rect.width - cell * 8) / 2
            NSColor.black.withAlphaComponent(unlocked ? 1 : 0.45).setFill()
            for (x, y) in KeyGlyph.cells {
                NSRect(x: inset + CGFloat(x) * cell, y: inset + CGFloat(y) * cell, width: cell, height: cell).fill()
            }
            if paused {
                NSColor.black.setFill()
                for x in [5, 7] {
                    NSRect(x: inset + CGFloat(x) * cell, y: inset + 6 * cell, width: cell, height: 2 * cell).fill()
                }
            }
            return true
        }
        image.isTemplate = true
        cache[key] = image
        return image
    }
}

/// The panel under the menu bar icon: the state, a quick search that
/// copies a user name, password or code, the requests waiting, and the
/// way to the window.
struct MenuBarView: View {
    @EnvironmentObject private var model: MacModel
    @EnvironmentObject private var installer: Installer
    @Environment(\.openWindow) private var openWindow
    @Environment(\.openSettings) private var openSettings
    @Environment(\.dismiss) private var dismiss

    @State private var query = ""
    @State private var results: [ItemInfo] = []
    @State private var password = ""
    @State private var problem: String?
    @FocusState private var searching: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            Rule()
            // What changed outside Klav, never hidden (ADR 0033 §4, §6, E1).
            if !model.shownWarnings.isEmpty {
                ClientWarningsView(open: { open() })
                Rule()
            }
            // A theft signal of a sandbox, never hidden (ADR 0036 E4).
            if !model.shownThefts.isEmpty || model.sandboxIntegrity != nil {
                SandboxTheftsView(open: { open() })
                Rule()
            }
            switch model.phase {
            case .unlocked: unlockedBody
            case .locked:
                lockedBody
                // Pausing works while locked: klavd keeps it on this Mac and
                // tells the server once it can (ADR 0033 §7). Not after the
                // deletion: there are no agents left (D-C).
                if !model.accountDeleted {
                    Rule()
                    PauseLine(open: open)
                }
            case .starting: Color.clear.frame(height: 80)
            case .signedOut, .noDaemon: setUpBody
            }
            // An older klav the terminal may run instead of this app's
            // (docs/macos.md §3): at the bottom, with the agent rows, said
            // where the person looks, not only in Settings.
            if !installer.shownOlderCLIs.isEmpty {
                Rule()
                OlderCLIsLine(show: {
                    openSettings()
                    NSApp.activate()
                })
            }
            Rule()
            footer
        }
        .frame(width: 360)
        .background(Palette.papel)
        .overlay(alignment: .bottom) {
            if let toast = model.toast { ToastView(toast: toast) }
        }
        .task(id: "\(query)|\(model.generation)|\(model.phase == .unlocked)") { await search() }
    }

    // MARK: Parts

    private var header: some View {
        HStack(spacing: 10) {
            Wordmark(size: 16)
            Spacer()
            Text(stateLine)
                .font(.ui(12, relativeTo: .caption))
                .foregroundStyle(Palette.gris)
            Button {
                openSettings()
                NSApp.activate()
                dismiss()
            } label: {
                ZStack(alignment: .topTrailing) {
                    IconView(icon: .gear, size: 14)
                        .foregroundStyle(Palette.gris)
                    if installer.needsSetupAttention {
                        CompactMark().frame(width: 5, height: 5).offset(x: 2, y: -2)
                    }
                }
                .frame(width: 24, height: 24)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .help("This Mac & Settings (⌘,)")
            .accessibilityLabel("Settings")
        }
        .padding(.horizontal, 14)
        .frame(height: 44)
    }

    private var stateLine: String {
        guard let info = model.info else { return "" }
        if model.unlocking { return String(localized: "Unlocking…") }
        switch model.phase {
        case .unlocked:
            if let left = info.locksInSecs {
                return String(localized: "Locks in \(max(1, Int((Double(left) / 60).rounded(.up)))) min")
            }
            return String(localized: "Unlocked")
        case .locked: return String(localized: "Locked")
        case .signedOut: return String(localized: "No account yet")
        case .noDaemon: return String(localized: "Not running")
        case .starting: return ""
        }
    }

    private var unlockedBody: some View {
        VStack(alignment: .leading, spacing: 0) {
            if model.accountDeleted {
                // §7.6, D-C: search and copy still work.
                DeletedLine()
                Rule()
            }
            HStack(spacing: 8) {
                IconView(icon: .search, size: 14).foregroundStyle(Palette.gris)
                TextField("Search your vault", text: $query)
                    .textFieldStyle(.plain)
                    .font(.ui(14))
                    .focused($searching)
                    .onSubmit { copyFirst() }
            }
            .padding(.horizontal, 14)
            .frame(height: 40)
            Rule()
            if results.isEmpty {
                Text(query.isEmpty ? "Your vault is empty." : "Nothing matches “\(query)”.")
                    .font(.ui(13))
                    .foregroundStyle(Palette.gris)
                    .padding(14)
            } else {
                ForEach(results.prefix(6)) { item in
                    QuickRow(item: item)
                    if item.id != results.prefix(6).last?.id { Rule().padding(.leading, 52) }
                }
            }
            if model.pendingCount > 0 {
                Rule()
                requests
            }
            if let use = model.lastAgentUse {
                Rule()
                lastUse(use)
            }
            if !model.accountDeleted {
                Rule()
                PauseLine(open: open)
            }
        }
        .onAppear { searching = true }
        .task(id: model.generation) {
            await model.loadLastAgentUse()
            // Each read syncs and verifies the log: at most every 5 min.
            await model.loadSandboxes(maxAge: 300)
        }
    }

    /// «cursor filled it in on github.com · GitHub · 2 min ago», which
    /// opens Activity (ADR 0033 §8.1).
    private func lastUse(_ use: LogEntryInfo) -> some View {
        Button {
            model.openActivity(item: nil, agent: nil)
            open()
        } label: {
            HStack(spacing: 10) {
                IconView(icon: .list, size: 14).foregroundStyle(Palette.gris)
                    .frame(width: 6)
                VStack(alignment: .leading, spacing: 2) {
                    (Text(verbatim: ActivityWords.shown(use.actor, max: 30)).font(.ui(13, .medium))
                        .foregroundColor(Palette.cobalto)
                        + Text(verbatim: use.agentId.map { " " + AgentText.idPrefix($0) } ?? "")
                        .font(.mono(11)).foregroundColor(Palette.gris)
                        + Text(verbatim: " " + ActivityWords.did(use)).font(.ui(13)).foregroundColor(Palette.tinta))
                        .lineLimit(1)
                    Text(verbatim: [ActivityWords.title(use), ActivityWords.when(use.atMs)].compactMap { $0 }
                        .joined(separator: " · "))
                        .font(.ui(12)).foregroundStyle(Palette.gris).lineLimit(1)
                }
                Spacer()
                Text("Activity").font(.ui(13, .medium)).foregroundStyle(Palette.tinta)
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 10)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }

    private var requests: some View {
        Button {
            model.section = .requests
            open()
        } label: {
            HStack(spacing: 10) {
                CompactMark().frame(width: 6, height: 28)
                VStack(alignment: .leading, spacing: 2) {
                    Text(model.pendingCount == 1 ? "1 agent request is waiting" : "\(model.pendingCount) agent requests are waiting")
                        .font(.ui(13, .medium))
                        .foregroundStyle(Palette.cobalto)
                    if let first = model.approvals.first {
                        Text(verbatim: McpWords.summary(first).map { "\($0.who) · \($0.what)" }
                             ?? "\(first.agent) · \(RequestWords.wants(first.permission, RequestWords.target(first.target).title))")
                            .font(.ui(12))
                            .foregroundStyle(Palette.gris)
                            .lineLimit(1)
                    }
                }
                Spacer()
                Text("Review").font(.ui(13, .medium)).foregroundStyle(Palette.tinta)
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 10)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }

    private var lockedBody: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 14) {
                DitherView(kind: .keyhole(open: model.unlocking ? 0.5 : 0), palette: .blue, pixel: 2)
                    .frame(width: 56, height: 56)
                VStack(alignment: .leading, spacing: 3) {
                    Text(model.unlocking ? "Waiting for Touch ID…" : "Klav is locked")
                        .font(.ui(15, .semibold))
                        .foregroundStyle(Palette.tinta)
                    if let email = model.info?.email {
                        Text(verbatim: email).font(.ui(12)).foregroundStyle(Palette.gris)
                    }
                }
            }
            if model.touchIDReady {
                Button(model.unlocking ? "Waiting for Touch ID…" : "Unlock with Touch ID") {
                    Task { await touchID() }
                }
                .buttonStyle(PrimaryButtonStyle(compact: true))
                .keyboardShortcut(.defaultAction)
                .disabled(model.unlocking)
                if model.unlocking {
                    Text("macOS asks on behalf of Klav’s background service.")
                        .font(.ui(12))
                        .foregroundStyle(Palette.gris)
                        .fixedSize(horizontal: false, vertical: true)
                }
            } else {
                SecureField("Master password", text: $password)
                    .textFieldStyle(.plain)
                    .font(.ui(14))
                    .padding(.horizontal, 10)
                    .frame(height: 32)
                    .overlay(Rectangle().strokeBorder(Palette.linea, lineWidth: 1))
                    .onSubmit { Task { await withPassword() } }
                Button(model.unlocking ? "Unlocking…" : "Unlock") { Task { await withPassword() } }
                    .buttonStyle(PrimaryButtonStyle(compact: true))
                    .disabled(password.isEmpty || model.unlocking)
            }
            if let problem { Notice(text: problem) }
        }
        .padding(14)
    }

    private var setUpBody: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(model.phase == .signedOut ? "Sign in or create an account to use Klav on this Mac." : "Klav isn’t set up on this Mac yet.")
                .font(.ui(13))
                .foregroundStyle(Palette.tinta)
                .fixedSize(horizontal: false, vertical: true)
            Button("Set up this Mac") { open() }
                .buttonStyle(PrimaryButtonStyle(compact: true))
        }
        .padding(14)
    }

    private var footer: some View {
        HStack(spacing: 4) {
            FooterButton(title: "Open Klav", shortcut: "O") { open() }
            if model.phase == .unlocked {
                FooterButton(title: "Lock", shortcut: "L") { model.lock() }
            }
            Spacer()
            FooterButton(title: "Quit", shortcut: "Q") { NSApp.terminate(nil) }
        }
        .padding(.horizontal, 6)
        .frame(height: 38)
    }

    // MARK: Actions

    private func open() {
        openWindow(id: WindowID.main)
        NSApp.activate()
        dismiss()
    }

    /// The master password's sheet shows over the window (ADR 0041).
    private func showWindow() { open() }

    private func search() async {
        guard model.phase == .unlocked else { results = []; return }
        let text = query.trimmingCharacters(in: .whitespaces)
        if !text.isEmpty { try? await Task.sleep(for: .milliseconds(120)) }
        guard !Task.isCancelled else { return }
        let found = try? await model.run { engine in
            try engine.items(query: ItemQuery(vaultId: nil, projectId: nil, text: text.isEmpty ? nil : text,
                                              kind: nil, trash: false))
        }
        results = Array((found ?? []).prefix(6))
    }

    /// Return copies the first result's password.
    private func copyFirst() {
        guard let first = results.first else { return }
        Task {
            let id = first.id
            if let value = try? await model.value(onAsk: showWindow, { try $0.fieldValue(id: id, field: "password") },
                                                  withPassword: { try $0.fieldValueWithPassword(id: id, field: "password", password: $1) }) {
                model.copy(value)
            }
        }
    }

    private func touchID() async {
        problem = nil
        do { try await model.unlockWithTouchID() } catch { problem = describe(error) }
    }

    private func withPassword() async {
        problem = nil
        let typed = password
        do {
            try await model.unlock(password: typed)
            password = ""
        } catch {
            problem = describe(error)
        }
    }
}

/// One search result: copy the user name, the password or the code.
/// The menu bar's line after the deletion (§7.6): the vault is read-only.
private struct DeletedLine: View {
    var body: some View {
        HStack(spacing: 10) {
            Rectangle().fill(Palette.rojo).frame(width: 2, height: 28)
            VStack(alignment: .leading, spacing: 2) {
                Text("Klav deleted your account").font(.ui(13, .medium)).foregroundStyle(Palette.tinta)
                Text("Read-only: you can search and copy, but not edit or sync.")
                    .font(.ui(12)).foregroundStyle(Palette.gris)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
        .accessibilityElement(children: .combine)
    }
}

private struct QuickRow: View {
    @EnvironmentObject private var model: MacModel
    @Environment(\.openWindow) private var openWindow
    @Environment(\.dismiss) private var dismiss
    let item: ItemInfo
    @State private var hovering = false
    /// A login shows «Code» once klavd says it has one.
    @State private var hasCode = false

    var body: some View {
        HStack(spacing: 12) {
            Tile(title: item.title, site: item.urls.first, size: 26)
            VStack(alignment: .leading, spacing: 1) {
                Text(verbatim: item.title).font(.ui(13, .medium)).foregroundStyle(Palette.tinta).lineLimit(1)
                if let user = item.username {
                    Text(verbatim: user).font(.ui(12)).foregroundStyle(Palette.gris).lineLimit(1)
                }
            }
            Spacer(minLength: 8)
            HStack(spacing: 4) {
                if item.username != nil {
                    SmallAction(title: "User") { copy("username") }
                }
                if item.kind == .login {
                    SmallAction(title: "Password") { copy("password") }
                }
                if item.kind == .totp || hasCode {
                    SmallAction(title: "Code") { code() }
                }
            }
            .fixedSize()
            .opacity(hovering ? 1 : 0.55)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 8)
        .background(hovering ? Palette.niebla : Color.clear)
        .onHover { hovering = $0 }
        .task(id: item.id) {
            guard item.kind == .login else { return }
            let id = item.id
            // From the item, not by fetching a code: with the presence gate
            // on a fetch may ask for Touch ID (ADR 0041).
            hasCode = (try? await model.run { try $0.item(id: id) })?.hasTotp ?? false
        }
    }

    /// The master password's sheet shows over the window (ADR 0041).
    private func showWindow() {
        openWindow(id: WindowID.main)
        NSApp.activate()
        dismiss()
    }

    private func copy(_ field: String) {
        let id = item.id
        Task {
            do {
                let value = try await model.value(onAsk: showWindow, { try $0.fieldValue(id: id, field: field) },
                                                  withPassword: { try $0.fieldValueWithPassword(id: id, field: field, password: $1) })
                model.copy(value)
            } catch is CancellationError {
            } catch {
                model.show(Toast(text: describe(error)))
            }
        }
    }

    private func code() {
        let id = item.id
        Task {
            do {
                let info = try await model.value(onAsk: showWindow, { try $0.totp(id: id) },
                                                 withPassword: { try $0.totpWithPassword(id: id, password: $1) })
                model.copy(info.code)
            } catch is CancellationError {
            } catch {
                model.show(Toast(text: describe(error)))
            }
        }
    }
}

/// The older `klav` programs on the PATH, in the menu bar's panel: «Show»
/// opens Settings › This Mac, where its build and how to update it are;
/// «Not now» keeps it quiet until either build changes. The sentence takes
/// the whole width, so a long path wraps between words, not beside the
/// buttons.
struct OlderCLIsLine: View {
    @EnvironmentObject private var installer: Installer
    let show: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            ForEach(installer.shownOlderCLIs) { cli in
                let path = shortPath(cli.path)
                VStack(alignment: .leading, spacing: 6) {
                    Text(verbatim: String(localized: "An older klav is at \(path). Your terminal may run it instead of this app’s."))
                        .font(.ui(12.5, .medium)).foregroundStyle(Palette.tinta)
                        .fixedSize(horizontal: false, vertical: true)
                        .frame(maxWidth: .infinity, alignment: .leading)
                    HStack(spacing: 8) {
                        SmallAction(title: "Show", label: String(localized: "Show the klav at \(path)"), action: show)
                        SmallAction(title: "Not now", label: String(localized: "Not now for the klav at \(path)")) {
                            installer.leave(cli)
                        }
                    }
                }
            }
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
    }
}

/// The mark of agent requests and notices where the dither band would be
/// too narrow to read as one (under 12 pt): a plain cobalt bar, sized by
/// its frame (docs/diseno-visual §3, decision of 2026-11-17). Decoration:
/// the row's text says what it is.
struct CompactMark: View {
    var body: some View {
        Rectangle().fill(Palette.cobalto).accessibilityHidden(true)
    }
}

/// A small square text button in a row. `label`, when given, is what
/// VoiceOver says instead of the title (the title alone may not say what
/// it acts on).
struct SmallAction: View {
    let title: LocalizedStringKey
    var label: String?
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Text(title)
                .font(.ui(11, .medium))
                .foregroundStyle(Palette.tinta)
                .padding(.horizontal, 7)
                .frame(height: 22)
                .overlay(Rectangle().strokeBorder(Palette.linea, lineWidth: 1))
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityLabel(label.map { Text(verbatim: $0) } ?? Text(title))
    }
}

/// A footer action with its shortcut in Geist Mono.
private struct FooterButton: View {
    let title: LocalizedStringKey
    let shortcut: Character
    let action: () -> Void
    @State private var hovering = false

    var body: some View {
        Button(action: action) {
            HStack(spacing: 6) {
                Text(title).font(.ui(13)).foregroundStyle(Palette.tinta)
                Text(verbatim: "⌘\(shortcut)").font(.ui(11)).foregroundStyle(Palette.gris)
            }
            .padding(.horizontal, 8)
            .frame(height: 28)
            .background(hovering ? Palette.niebla : Color.clear)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .keyboardShortcut(KeyEquivalent(shortcut.lowercased().first ?? shortcut), modifiers: [.command])
        .onHover { hovering = $0 }
    }
}
