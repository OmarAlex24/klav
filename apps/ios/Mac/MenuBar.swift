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
/// copies a user name, password, code or key, or opens the item in the
/// window, the requests waiting, and the way to the window.
struct MenuBarView: View {
    @EnvironmentObject private var model: MacModel
    @EnvironmentObject private var installer: Installer
    @Environment(\.openWindow) private var openWindow
    @Environment(\.openSettings) private var openSettings
    @Environment(\.dismiss) private var dismiss

    @State private var query = ""
    /// The result Return acts on, moved with ↑ and ↓ or the pointer.
    @State private var selection = 0
    /// The panel's other lines, read a moment after each showing.
    @State private var panelLoad: Task<Void, Never>?
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
                    // The proxy on this Mac answers without klavd: its
                    // sandboxes can be revoked while locked (ADR 0036 E2.3).
                    LocalSandboxesLine()
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
        // The panel is a window macOS shows and hides, and SwiftUI may keep
        // this view between showings: each showing focuses the search and
        // reads what may have changed, and hiding it starts the next one
        // empty (KeyWindowWatcher).
        .background(KeyWindowWatcher { key in key ? shown() : hidden() })
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
            searchField
            Rule()
            resultsList
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
        .task(id: model.generation) { await loadPanel(after: .seconds(1)) }
    }

    /// The search: typed in memory over the model's copy of the list, so
    /// nothing waits on `klavd` (QuickSearch.swift).
    private var searchField: some View {
        HStack(spacing: 8) {
            IconView(icon: .search, size: 14).foregroundStyle(Palette.gris)
            TextField("Search your vault", text: $query)
                .textFieldStyle(.plain)
                .font(.ui(14))
                .focused($searching)
                .onSubmit { primary() }
                .onKeyPress(.downArrow) { move(1) }
                .onKeyPress(.upArrow) { move(-1) }
                // ⌘↩ opens the selected result in the window.
                .onKeyPress(.return, phases: .down) { press in
                    guard press.modifiers.contains(.command), let item = selected else { return .ignored }
                    openInWindow(item)
                    return .handled
                }
                // Esc clears the search first; with nothing typed it closes the panel.
                .onKeyPress(.escape) {
                    guard !query.isEmpty else { return .ignored }
                    query = ""
                    return .handled
                }
            if !query.isEmpty {
                Button {
                    query = ""
                    searching = true
                } label: {
                    IconView(icon: .close, size: 10)
                        .foregroundStyle(Palette.gris)
                        .frame(width: 22, height: 22)
                        .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .help("Clear the search")
                .accessibilityLabel("Clear the search")
            }
        }
        .padding(.horizontal, 14)
        .frame(height: 40)
        .onChange(of: query) { _, _ in selection = 0 }
    }

    /// The first results, or why there are none.
    @ViewBuilder private var resultsList: some View {
        let shown = results
        if shown.isEmpty {
            Group {
                if model.quickItems == nil {
                    if let problem = model.quickProblem {
                        Text(verbatim: problem)
                    } else {
                        Text("Loading your vault…")
                    }
                } else if query.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                    Text("Your vault is empty.")
                } else {
                    Text("Nothing matches “\(query)”.")
                }
            }
            .font(.ui(13))
            .foregroundStyle(Palette.gris)
            .fixedSize(horizontal: false, vertical: true)
            .padding(14)
        } else {
            ForEach(Array(shown.enumerated()), id: \.element.id) { index, item in
                QuickRow(item: item, hasCode: model.quickCodes.contains(item.id), selected: index == selection,
                         hover: { if $0 { selection = index } },
                         open: { openInWindow(item) },
                         copy: { copy($0, of: item) })
                if index < shown.count - 1 { Rule().padding(.leading, 52) }
            }
        }
    }

    private var results: [ItemInfo] {
        Array(QuickSearch.filter(model.quickItems ?? [], query: query).prefix(QuickSearch.limit))
    }

    private var selected: ItemInfo? {
        let shown = results
        return shown.indices.contains(selection) ? shown[selection] : shown.first
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

    private func move(_ step: Int) -> KeyPress.Result {
        let count = results.count
        guard count > 0 else { return .ignored }
        selection = min(max(selection + step, 0), count - 1)
        return .handled
    }

    /// Return: the selected result's password, code or key (its user name
    /// for other kinds); an item with nothing to copy opens in the window.
    private func primary() {
        guard let item = selected else { return }
        if let action = QuickSearch.primary(item, hasCode: model.quickCodes.contains(item.id)) {
            copy(action, of: item)
        } else {
            openInWindow(item)
        }
    }

    /// The window, on this item.
    private func openInWindow(_ item: ItemInfo) {
        model.openItem(item.id)
        open()
    }

    private func copy(_ action: QuickSearch.Action, of item: ItemInfo) {
        Task {
            do {
                let value = try await model.quickValue(action, of: item, onAsk: showWindow)
                model.copy(value)
            } catch is CancellationError {
            } catch let error as QuickSearchError {
                model.show(Toast(text: error.errorDescription ?? ""))
            } catch {
                model.show(Toast(text: describe(error)))
            }
        }
    }

    /// The panel showed: the search takes the keyboard, and what it shows
    /// is read again if it may have changed.
    private func shown() {
        searching = true
        model.loadQuickItems()
        panelLoad?.cancel()
        panelLoad = Task { await loadPanel(after: .seconds(1)) }
    }

    /// The panel hid: the next showing starts with an empty search.
    private func hidden() {
        query = ""
        selection = 0
        panelLoad?.cancel()
        panelLoad = nil
    }

    /// The panel's other lines. `klavd` holds the session for the whole of
    /// each unlocked request, and both of these sync with the server, so a
    /// copy asked while they run waits for them: they start a moment after
    /// the panel shows (a copy right away goes first), not again while a
    /// recent read stands, and not at all once the panel hid.
    private func loadPanel(after delay: Duration) async {
        try? await Task.sleep(for: delay)
        guard !Task.isCancelled, model.phase == .unlocked else { return }
        await model.loadLastAgentUse(maxAge: 30)
        guard !Task.isCancelled else { return }
        // Each read syncs and verifies the log: at most every 5 min.
        await model.loadSandboxes(maxAge: 300)
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

/// One search result. Clicking it opens the item in the window; its
/// buttons copy the user name, the password, the code or the key, and
/// only that.
private struct QuickRow: View {
    let item: ItemInfo
    let hasCode: Bool
    /// Return acts on it.
    let selected: Bool
    let hover: (Bool) -> Void
    let open: () -> Void
    let copy: (QuickSearch.Action) -> Void

    var body: some View {
        HStack(spacing: 12) {
            Button(action: open) {
                HStack(spacing: 12) {
                    Tile(title: item.title, site: item.urls.first, size: 26)
                    VStack(alignment: .leading, spacing: 1) {
                        Text(verbatim: item.title).font(.ui(13, .medium)).foregroundStyle(Palette.tinta).lineLimit(1)
                        if let user = item.username {
                            Text(verbatim: user).font(.ui(12)).foregroundStyle(Palette.gris).lineLimit(1)
                        }
                    }
                    Spacer(minLength: 8)
                }
                // The whole row up to the buttons opens it, padding included.
                .padding(.leading, 14)
                .padding(.vertical, 8)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .help("Open in Klav")
            .accessibilityLabel(Text("Open \(item.title) in Klav"))
            HStack(spacing: 4) {
                ForEach(QuickSearch.actions(item, hasCode: hasCode), id: \.self) { action in
                    switch action {
                    case .username: SmallAction(title: "User") { copy(.username) }
                    case .password: SmallAction(title: "Password") { copy(.password) }
                    case .code: SmallAction(title: "Code") { copy(.code) }
                    case .key: SmallAction(title: "Key", label: String(localized: "Copy the API key")) { copy(.key) }
                    }
                }
            }
            .fixedSize()
            .opacity(selected ? 1 : 0.55)
        }
        .padding(.trailing, 14)
        // One highlight: the pointer moves the selection, like ↑ and ↓.
        .background(selected ? Palette.niebla : Color.clear)
        .onHover(perform: hover)
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

/// Tells the panel when its window becomes key (macOS showed it) and
/// stops being key (it hid). `onAppear` can't: SwiftUI may keep the
/// panel's view between showings, and it may run before the window can
/// take the keyboard. A window that is not key never asks for it, so a
/// screenshot run's preview window takes no focus from anyone.
private struct KeyWindowWatcher: NSViewRepresentable {
    let changed: (Bool) -> Void

    func makeNSView(context: Context) -> WatcherView {
        let view = WatcherView()
        view.changed = changed
        return view
    }

    func updateNSView(_ view: WatcherView, context: Context) {
        view.changed = changed
    }

    final class WatcherView: NSView {
        var changed: ((Bool) -> Void)?
        private var observers: [NSObjectProtocol] = []

        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            observers.forEach { NotificationCenter.default.removeObserver($0) }
            observers = []
            guard let window else { return }
            let center = NotificationCenter.default
            observers.append(center.addObserver(forName: NSWindow.didBecomeKeyNotification, object: window,
                                                queue: .main) { [weak self] _ in self?.changed?(true) })
            observers.append(center.addObserver(forName: NSWindow.didResignKeyNotification, object: window,
                                                queue: .main) { [weak self] _ in self?.changed?(false) })
            if window.isKeyWindow {
                DispatchQueue.main.async { [weak self] in self?.changed?(true) }
            }
        }

        deinit {
            observers.forEach { NotificationCenter.default.removeObserver($0) }
        }
    }
}
