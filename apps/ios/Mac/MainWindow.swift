import AppKit
import SwiftUI

/// The window: the lock screen, or the sidebar with the vault, the
/// requests, the agents and the vault's health.
struct MainWindow: View {
    @EnvironmentObject private var model: MacModel
    @EnvironmentObject private var installer: Installer
    @Environment(\.openSettings) private var openSettings

    var body: some View {
        Group {
            // One branch for the setup, whatever the phase under it: a new
            // SetupView would drop the account sheet (and the new account's
            // kit) when klavd goes locked, then unlocked, while it is open.
            if model.showsSetup {
                SetupView()
            } else {
                switch model.phase {
                case .unlocked:
                    HStack(spacing: 0) {
                        Sidebar()
                            .frame(width: 220)
                        Rectangle().fill(Palette.linea).frame(width: 1)
                        VStack(spacing: 0) {
                            // ADR 0037 §7.4: while the deletion is pending.
                            DeletionBand()
                            // §7.6, D-C: after it, the vault read-only.
                            DeletedBand()
                            // An older klav on the PATH (docs/macos.md §3):
                            // shown in the window too, not only the menu bar.
                            OlderCLIsBand(show: {
                                openSettings()
                                NSApp.activate()
                            })
                            content
                                .frame(maxWidth: .infinity, maxHeight: .infinity)
                        }
                    }
                    .task(id: model.info?.running) { await installer.refresh(info: model.info) }
                case .locked:
                    LockScreen()
                case .starting, .signedOut, .noDaemon:
                    Palette.papel
                }
            }
        }
        .frame(minWidth: 820, minHeight: 540)
        .background(Palette.papel)
        // One paper from the title bar down, whatever scrolls under it.
        .containerBackground(Palette.papel, for: .window)
        .toolbarBackgroundVisibility(.hidden, for: .windowToolbar)
        .overlay(alignment: .bottom) {
            if let toast = model.toast {
                ToastView(toast: toast).frame(maxWidth: 420)
            }
        }
        // While «Change permissions…» is open, it shows the prompt itself:
        // macOS shows no second sheet from the window under a sheet, so
        // signing would wait on a prompt nobody sees.
        .sheet(item: model.passwordPromptHere(inSheet: false)) { prompt in
            PasswordSheet(prompt: prompt)
        }
        .sheet(isPresented: $model.uninstalling) {
            UninstallSheet()
        }
        .sheet(item: $model.editor) { request in
            ItemEditorSheet(request: request)
        }
        .sheet(item: $model.trashing) { item in
            TrashSheet(item: item)
        }
        .modifier(DockWhileOpen())
        // Signed in from «Set up this Mac»: its «Agents» step comes next,
        // once (ADR 0033 E2.3). The account sheet sets it when it succeeds
        // (`makeAccount`); this covers an account made elsewhere, the CLI.
        .onChange(of: model.phase) { old, new in
            if old == .signedOut, new == .unlocked, !AgentsStep.decided { model.agentsStepPending = true }
        }
    }

    @ViewBuilder private var content: some View {
        switch model.section {
        case .vault(let filter): VaultPane(filter: filter)
        // Read-only after the deletion (D-C): nothing for the agents.
        case _ where model.accountDeleted: VaultPane(filter: .all)
        case .requests: RequestsPane()
        case .agents: AgentsPane()
        case .sandboxes: SandboxesPane()
        case .mcpServers: McpServersPane()
        case .activity: ActivityPane()
        case .clients: ClientsPane()
        case .health: HealthPane()
        }
    }
}

// MARK: - Older CLI band

/// Above the window's content when an older `klav` is on the PATH
/// (docs/macos.md §3): the same warning as the menu bar panel, so opening
/// the window directly never misses it.
private struct OlderCLIsBand: View {
    @EnvironmentObject private var installer: Installer
    let show: () -> Void

    var body: some View {
        if !installer.shownOlderCLIs.isEmpty {
            VStack(spacing: 0) {
                ForEach(installer.shownOlderCLIs) { cli in
                    let path = shortPath(cli.path)
                    HStack(spacing: 0) {
                        Rectangle().fill(Palette.rojo).frame(width: 2)
                        HStack(spacing: 12) {
                            Text(verbatim: String(localized: "An older klav is at \(path). Your terminal may run it instead of this app’s."))
                                .font(.ui(13, .medium)).foregroundStyle(Palette.tinta)
                                .fixedSize(horizontal: false, vertical: true)
                            Spacer(minLength: 8)
                            Button("Show") { show() }
                                .buttonStyle(SecondaryButtonStyle(compact: true, block: false))
                                .accessibilityLabel(Text(verbatim: String(localized: "Show the klav at \(path)")))
                            Button("Not now") { installer.leave(cli) }
                                .buttonStyle(SecondaryButtonStyle(compact: true, block: false))
                                .accessibilityLabel(Text(verbatim: String(localized: "Not now for the klav at \(path)")))
                        }
                        .padding(.horizontal, 14)
                        .padding(.vertical, 8)
                    }
                    .fixedSize(horizontal: false, vertical: true)
                    .background(Palette.niebla)
                    Rule()
                }
            }
            .accessibilityElement(children: .contain)
        }
    }
}

// MARK: - Sidebar

private struct Sidebar: View {
    @EnvironmentObject private var model: MacModel
    @EnvironmentObject private var installer: Installer
    @Environment(\.openSettings) private var openSettings
    @State private var vaults: [VaultInfo] = []
    @State private var projects: [ProjectInfo] = []
    /// How many items of each kind; nil until klavd answered, or if it
    /// could not (then every kind shows, without a count).
    @State private var counts: [Kind: Int]?
    @State private var projectCounts: [String: Int] = [:]
    @State private var total = 0
    @State private var counted = false

    private var repoProjects: [ProjectInfo] {
        projects.filter { !$0.repos.isEmpty }
    }

    private static let kinds: [Kind] = [.login, .totp, .card, .note, .apiKey, .sshKey, .identity, .file]

    /// The kinds with something in them, as the iPhone's and the
    /// extension's type tabs, plus the chosen one even if it emptied.
    private var shownKinds: [Kind] {
        guard counted else { return [] }
        guard let counts else { return Self.kinds }
        return Self.kinds.filter { (counts[$0] ?? 0) > 0 || model.section == .vault(.kind($0)) }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Wordmark(size: 17)
                Spacer()
            }
            .padding(.horizontal, 16)
            .frame(height: 52)
            ScrollView {
                VStack(alignment: .leading, spacing: 2) {
                    Row(icon: .grid, title: "All items", shortcut: "⌘1", count: total, section: .vault(.all))
                    ForEach(shownKinds, id: \.self) { kind in
                        Row(icon: kind.icon, title: LocalizedStringKey(kind.plural), count: counts?[kind] ?? 0,
                            section: .vault(.kind(kind)))
                    }
                    if vaults.count > 1 {
                        Group(title: "Vaults")
                        ForEach(vaults, id: \.id) { vault in
                            Row(icon: .safe, title: LocalizedStringKey(vault.name), count: Int(vault.items),
                                section: .vault(.vault(vault.id)))
                        }
                    }
                    if !repoProjects.isEmpty {
                        Group(title: "Repositories")
                        ForEach(repoProjects, id: \.id) { project in
                            Row(icon: .cube,
                                title: LocalizedStringKey(project.primaryRepoShort ?? project.name),
                                count: projectCounts[project.id] ?? 0,
                                section: .vault(.project(project.id)))
                        }
                    }
                    // After the deletion only the vault is left (D-C): the
                    // agents have no account, and health would change items.
                    if !model.accountDeleted {
                        // What asks for a decision stays on its own, above any
                        // group: it is never hidden (ADR 0033, E1).
                        Rule().padding(.horizontal, 8).padding(.vertical, 10)
                        Row(icon: .inbox, title: "Requests", shortcut: "⌘2", count: model.pendingCount, blue: true,
                            section: .requests)
                        Group(title: "Development")
                        Row(icon: .robot, title: "Agents", shortcut: "⌘3", paused: model.everyonePaused != nil,
                            section: .agents)
                        Row(icon: .cube, title: "Sandboxes", shortcut: "⌘7", section: .sandboxes)
                        Row(icon: .braces, title: "MCP servers", shortcut: "⌘8", section: .mcpServers)
                        Row(icon: .list, title: "Activity", shortcut: "⌘5", section: .activity)
                        Row(icon: .plug, title: "Clients", shortcut: "⌘6", section: .clients)
                        Group(title: "Passwords")
                        Row(icon: .pulse, title: "Vault health", shortcut: "⌘4", section: .health)
                    }
                }
                .padding(.horizontal, 8)
                .padding(.bottom, 12)
            }
            Rule()
            ActionRow(icon: .gear, title: "This Mac", shortcut: "⌘,", attention: installer.needsSetupAttention) {
                openSettings()
                NSApp.activate()
            }
            .padding(.horizontal, 8)
            .padding(.vertical, 6)
            .help("Set up this Mac, browsers and Settings (⌘,)")
            Rule()
            account
        }
        .background(Palette.papel)
        .task(id: model.generation) {
            vaults = (try? await model.run { try $0.vaults() }) ?? []
            projects = (try? await model.run { try $0.projects(vaultId: nil) }) ?? []
            let items = try? await model.run { try $0.items(query: ItemQuery()) }
            counts = items.map { Dictionary(grouping: $0, by: \.kind).mapValues(\.count) }
            projectCounts = items.map { Dictionary(grouping: $0, by: \.projectId).mapValues(\.count) } ?? [:]
            total = items?.count ?? 0
            counted = true
        }
    }

    private var account: some View {
        HStack(spacing: 8) {
            VStack(alignment: .leading, spacing: 1) {
                Text(verbatim: model.info?.email ?? "")
                    .font(.ui(12, .medium)).foregroundStyle(Palette.tinta).lineLimit(1)
                    .truncationMode(.middle)
                    .help(model.info?.email ?? "")
                Text(model.accountDeleted ? "Read-only" : model.info?.syncing == true ? "Syncing…" : "Unlocked")
                    .font(.ui(11)).foregroundStyle(Palette.gris)
            }
            Spacer()
            Button("Lock") { model.lock() }
                .buttonStyle(SecondaryButtonStyle(compact: true, block: false))
                .help("Lock Klav (⌘L): the extension and the CLI lock too")
        }
        .padding(12)
    }

    private struct Group: View {
        let title: LocalizedStringKey
        var body: some View {
            Text(title)
                .font(.ui(11, .medium))
                .foregroundStyle(Palette.gris)
                .padding(.horizontal, 8)
                .padding(.top, 16)
                .padding(.bottom, 4)
        }
    }

    /// A row: its line icon (grey, ink when chosen or under the cursor),
    /// the name and, at the end, how many there are. Under the cursor the
    /// shortcut takes the count's place, except for the requests waiting.
    private struct Row: View {
        @EnvironmentObject private var model: MacModel
        let icon: Icon
        let title: LocalizedStringKey
        var shortcut: String?
        var count: Int = 0
        var blue = false
        /// Every agent is paused: a cobalt «Paused» tag in place of the count.
        var paused = false
        let section: Section
        @State private var hovering = false

        var body: some View {
            let selected = model.section == section
            Button {
                model.section = section
            } label: {
                HStack(spacing: 8) {
                    IconView(icon: icon, size: 16)
                        .foregroundStyle(selected || hovering ? Palette.tinta : Palette.gris)
                    Text(title)
                        .font(.ui(13, selected ? .medium : .regular))
                        .foregroundStyle(Palette.tinta)
                        .lineLimit(1)
                    Spacer(minLength: 4)
                    if paused {
                        Text("Paused")
                            .font(.ui(11, .medium))
                            .foregroundStyle(Palette.cobalto)
                            .padding(.horizontal, 5)
                            .frame(minHeight: 18)
                            .overlay(Rectangle().strokeBorder(Palette.cobalto, lineWidth: 1))
                    } else if let shortcut, hovering, !(blue && count > 0) {
                        Text(verbatim: shortcut).font(.ui(11)).foregroundStyle(Palette.gris)
                    } else if count > 0 {
                        Text(count, format: .number)
                            .font(.ui(11, .medium))
                            .monospacedDigit()
                            .foregroundStyle(blue ? Palette.botonTexto : Palette.gris)
                            .padding(.horizontal, 5)
                            .frame(minWidth: 18, minHeight: 18)
                            .background(blue ? Palette.cobalto : Color.clear)
                    }
                }
                .padding(.horizontal, 8)
                .frame(height: 28)
                .background(selected ? Palette.niebla : hovering ? Palette.niebla.opacity(0.5) : Color.clear)
                .overlay(alignment: .leading) {
                    if selected { Rectangle().fill(Palette.tinta).frame(width: 2) }
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .onHover { hovering = $0 }
            .accessibilityAddTraits(selected ? .isSelected : [])
        }
    }

    /// A button row in the sidebar that opens an action (such as Settings ›
    /// This Mac) instead of switching panes, with an optional cobalt mark
    /// when setup items want attention.
    private struct ActionRow: View {
        let icon: Icon
        let title: LocalizedStringKey
        var shortcut: String?
        var attention = false
        let action: () -> Void
        @State private var hovering = false

        var body: some View {
            Button(action: action) {
                HStack(spacing: 8) {
                    IconView(icon: icon, size: 16)
                        .foregroundStyle(hovering ? Palette.tinta : Palette.gris)
                    Text(title)
                        .font(.ui(13))
                        .foregroundStyle(Palette.tinta)
                        .lineLimit(1)
                    Spacer(minLength: 4)
                    if let shortcut, hovering {
                        Text(verbatim: shortcut).font(.ui(11)).foregroundStyle(Palette.gris)
                    } else if attention {
                        CompactMark().frame(width: 6, height: 6)
                    }
                }
                .padding(.horizontal, 8)
                .frame(height: 28)
                .background(hovering ? Palette.niebla.opacity(0.5) : Color.clear)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .onHover { hovering = $0 }
        }
    }
}

extension Kind {
    /// The sidebar's name of a kind.
    var plural: String {
        switch self {
        case .login: return String(localized: "Logins")
        case .totp: return String(localized: "One-time codes")
        case .card: return String(localized: "Cards")
        case .note: return String(localized: "Secure notes")
        case .apiKey: return String(localized: "API keys")
        case .sshKey: return String(localized: "SSH keys")
        case .identity: return String(localized: "Addresses")
        case .file: return String(localized: "Files")
        }
    }
}

// MARK: - Lock screen

/// The keyhole of light (docs/diseno-visual §3), Touch ID through
/// `klavd`, and the master password.
struct LockScreen: View {
    @EnvironmentObject private var model: MacModel
    @State private var password = ""
    @State private var problem: String?
    @State private var showPassword = false
    @FocusState private var focused: Bool

    var body: some View {
        HStack(spacing: 0) {
            DitherView(kind: .keyhole(open: model.unlocking ? 0.6 : 0), palette: .blue, pixel: 3)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 14) {
                Spacer()
                Wordmark(size: 19)
                Title("Klav is locked", size: 28)
                if let email = model.info?.email {
                    Text(verbatim: email).font(.ui(14)).foregroundStyle(Palette.gris)
                }
                if model.revokeAfterUnlock != nil {
                    // ADR 0033, amendment of 2026-11-10, P12: revoking
                    // waits for the unlock; pausing works now.
                    VStack(alignment: .leading, spacing: 8) {
                        Text("You were revoking an agent: unlock to go on. Meanwhile, pausing every agent stops them at once.")
                            .font(.ui(13)).foregroundStyle(Palette.tinta)
                            .fixedSize(horizontal: false, vertical: true)
                        Button("Pause every agent now") { Task { problem = await model.pauseEveryAgentNow() } }
                            .buttonStyle(SecondaryButtonStyle(compact: true))
                            .disabled(model.everyonePaused != nil)
                            .fixedSize()
                    }
                }
                if model.accountDeleted {
                    // §7.6, D-C: the copy still opens.
                    Text("Klav deleted your account. This Mac’s copy opens read-only.")
                        .font(.ui(13)).foregroundStyle(Palette.gris)
                        .fixedSize(horizontal: false, vertical: true)
                }
                if model.touchIDReady && !showPassword {
                    Button(model.unlocking ? "Waiting for Touch ID…" : "Unlock with Touch ID") {
                        Task { await touchID() }
                    }
                    .buttonStyle(PrimaryButtonStyle())
                    .keyboardShortcut(.defaultAction)
                    .disabled(model.unlocking)
                    .padding(.top, 8)
                    if model.unlocking {
                        Text("macOS asks on behalf of Klav’s background service, the same one the extension and the CLI use.")
                            .font(.ui(12)).foregroundStyle(Palette.gris)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    Button("Use the master password") { showPassword = true; focused = true }
                        .buttonStyle(LinkButtonStyle())
                } else {
                    if let reason = model.info?.passwordRequired {
                        Text(reason.contains("restart")
                             ? "Touch ID asks for the master password after the Mac restarts."
                             : "Touch ID asks for the master password every 14 days.")
                            .font(.ui(13)).foregroundStyle(Palette.gris)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    FieldLabel("Master password").padding(.top, 8)
                    SecureField("", text: $password)
                        .textFieldStyle(.plain)
                        .focused($focused)
                        .inputBox(focused: focused)
                        .onSubmit { Task { await unlock() } }
                    Button(model.unlocking ? "Unlocking…" : "Unlock") { Task { await unlock() } }
                        .buttonStyle(PrimaryButtonStyle())
                        .keyboardShortcut(.defaultAction)
                        .disabled(password.isEmpty || model.unlocking)
                    // ADR 0041 §2.4: what the typed password opens, said
                    // before it is typed; klavd opens only that.
                    if let words = model.unlockQuestion?.words {
                        Text(words)
                            .font(.ui(12)).foregroundStyle(Palette.gris)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
                if let problem { Notice(text: problem) }
                Spacer()
                Text("Unlocking here unlocks the browser extension and the CLI too.")
                    .font(.ui(12)).foregroundStyle(Palette.gris)
                    .padding(.bottom, 24)
            }
            .frame(width: 340)
            .padding(.horizontal, 44)
            .background(Palette.papel)
        }
        .onAppear { focused = !model.touchIDReady }
        .task(id: model.info?.presenceGate == true && (showPassword || !model.touchIDReady)) {
            await model.readUnlockQuestion()
        }
    }

    private func touchID() async {
        problem = nil
        do { try await model.unlockWithTouchID() } catch {
            problem = describe(error)
            if let e = error as? KlavError, e.wantsPassword { showPassword = true; focused = true }
        }
    }

    private func unlock() async {
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

/// The master password when Touch ID cannot confirm an approval.
struct PasswordSheet: View {
    @EnvironmentObject private var model: MacModel
    @Environment(\.dismiss) private var dismiss
    let prompt: PasswordPrompt
    @State private var password = ""
    @State private var busy = false
    @State private var problem: String?
    @FocusState private var focused: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Title("Confirm it’s you", size: 22)
            Text(verbatim: prompt.reason).font(.ui(14)).foregroundStyle(Palette.tinta)
            Text("Touch ID isn’t available, so Klav asks for the master password.")
                .font(.ui(13)).foregroundStyle(Palette.gris)
                .fixedSize(horizontal: false, vertical: true)
            SecureField("", text: $password)
                .textFieldStyle(.plain)
                .focused($focused)
                .inputBox(focused: focused)
                .onSubmit { Task { await confirm() } }
            if let problem { Notice(text: problem) }
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                    .buttonStyle(SecondaryButtonStyle(compact: true, block: false))
                    .keyboardShortcut(.cancelAction)
                Button(busy ? "Checking…" : "Confirm") { Task { await confirm() } }
                    .buttonStyle(PrimaryButtonStyle(compact: true))
                    .fixedSize()
                    .keyboardShortcut(.defaultAction)
                    .disabled(password.isEmpty || busy)
            }
        }
        .padding(24)
        .frame(width: 380)
        .background(Palette.papel)
        .onAppear { focused = true }
    }

    private func confirm() async {
        busy = true
        defer { busy = false }
        let typed = password
        do {
            try await prompt.retry(typed)
            dismiss()
        } catch {
            problem = describe(error)
        }
    }
}
