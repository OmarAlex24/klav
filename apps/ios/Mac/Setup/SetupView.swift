import AppKit
import SwiftUI

/// «Set up this Mac» (ADR 0027 §4): six steps, each saying what it will
/// touch before doing it. The window shows it until there is an account
/// and `klavd` answers, then until the «Agents» step is done or skipped
/// (ADR 0033 E2.3); Settings › This Mac shows it again.
struct SetupView: View {
    @EnvironmentObject private var model: MacModel
    @EnvironmentObject private var installer: Installer
    var inSettings = false

    @State private var account: AccountSheet.Mode?
    @State private var confirmLink = false
    @State private var confirmHosts = false
    @State private var confirmDaemon = false
    @State private var uninstalling = false
    @State private var advanced = false
    /// «Connect the browsers» while the command line let the development
    /// extension in: keep it or remove it (T122).
    @State private var confirmDev = false

    var body: some View {
        ScrollView {
            Group {
                if inSettings {
                    VStack(alignment: .leading, spacing: 0) {
                        notices
                        steps
                        openAtLogin.padding(.top, 24)
                        Button("Uninstall Klav from this Mac…") { uninstalling = true }
                            .buttonStyle(SecondaryButtonStyle(compact: true, danger: true, block: false))
                            .padding(.top, 24)
                    }
                    .padding(24)
                } else {
                    // The window: what Klav is on the left, the steps on the right.
                    HStack(alignment: .top, spacing: 48) {
                        VStack(alignment: .leading, spacing: 0) {
                            Wordmark(size: 19)
                            Title("Set up this Mac", size: 28).padding(.top, 14)
                            Text("Klav keeps your vault in klavd, a small background service that the browser extension, the CLI and this app share. Each step says what it changes before it does.")
                                .font(.ui(14)).foregroundStyle(Palette.gris)
                                .fixedSize(horizontal: false, vertical: true)
                                .padding(.top, 8)
                            notices
                        }
                        .fixedSize(horizontal: false, vertical: true)
                        .frame(width: 260, alignment: .leading)
                        steps.frame(maxWidth: 600)
                    }
                    .padding(.horizontal, 48)
                    .padding(.vertical, 40)
                    .frame(maxWidth: .infinity, alignment: .top)
                }
            }
        }
        // Right after signing in, the window stays here for the «Agents»
        // step, the last one: it opens at the bottom (ADR 0033 E2.3).
        .defaultScrollAnchor(model.agentsStepPending && !inSettings || inSettings && settingsAtEnd ? .bottom : .top)
        .background(Palette.papel)
        .task(id: model.info?.running) { await installer.refresh(info: model.info) }
        // The person may change Login Items in System Settings and come back.
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
            installer.refreshOpenAtLogin()
        }
        #if DEBUG
        .onAppear {
            if !inSettings, account == nil { account = Snapshot.accountSheet }
            if UserDefaults.standard.bool(forKey: "KlavAdvanced") { advanced = true }
        }
        #endif
        .sheet(item: $account) { mode in
            AccountSheet(mode: mode).environmentObject(model).environmentObject(installer)
        }
        .sheet(isPresented: $uninstalling) {
            UninstallSheet().environmentObject(model).environmentObject(installer)
        }
        .confirmationDialog(linkQuestion, isPresented: $confirmLink) {
            Button("Replace it") { Task { await installer.linkCLI(replace: true) } }
            Button("Cancel", role: .cancel) {}
        }
        .confirmationDialog("Use this app’s host in every browser?", isPresented: $confirmHosts) {
            // The next question, if any, comes once this one is gone.
            Button("Use this app’s") { DispatchQueue.main.async { connectHosts(replacingForeign: true) } }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text(verbatim: installer.foreignHostsMessage)
        }
        .confirmationDialog("Keep the development extension?", isPresented: $confirmDev) {
            Button("Keep it") { Task { await installer.connectHosts(keepingDevelopment: true) } }
            Button("Remove it") { Task { await installer.connectHosts(keepingDevelopment: false) } }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text(verbatim: String(localized: "klav extension install-host --dev let the development extension into \(installer.cliDevBrowsers.map(BrowserNames.name).formatted(.list(type: .and))). Any unpacked extension with the public key in Klav’s repository could talk to klavd too. Keeping it turns on “Development extension” and lets it into every Chromium browser on this Mac."))
        }
        .confirmationDialog("Stop the other klavd and use this app’s?", isPresented: $confirmDaemon) {
            Button("Use this app’s") { Task { await installer.useThisDaemon(engine: model.engine); model.refresh() } }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text(verbatim: installer.otherDaemon ?? "")
        }
    }

    @ViewBuilder private var notices: some View {
        if !installer.placement.canInstall {
            Notice(text: String(localized: "Move Klav to the Applications folder and open it from there. From the disk image or Downloads, macOS runs it from a temporary place, and a link or a background service pointing there would break."))
                .padding(.top, 20)
        } else if case .notTeamSigned = installer.helperTrust {
            Notice(text: String(localized: "This copy of Klav isn’t signed by Klav, so it sets nothing up. Download Klav from klav.dev."))
                .padding(.top, 20)
        } else if let why = installer.helpersUntrusted {
            Notice(text: String(localized: "Part of this copy of Klav isn’t signed by Klav (\(why)), so it sets nothing up. Download Klav again from klav.dev."))
                .padding(.top, 20)
        } else if installer.helpersMissing {
            Notice(text: String(localized: "This copy of Klav has no klav, klavd or klav-native-host inside: it was built without them. Install from the disk image."))
                .padding(.top, 20)
        } else if installer.unsignedDevelopmentBuild {
            Notice(text: String(localized: "Development build: Klav doesn’t check that its helpers are signed by Klav’s team. Copies from klav.dev do."),
                   tone: .info)
                .padding(.top, 20)
        }
    }

    private var steps: some View {
        VStack(spacing: 0) {
            daemonStep
            Rule()
            cliStep
            Rule()
            hostsStep
            Rule()
            extensionStep
            Rule()
            accountStep
            Rule()
            AgentsStep(inSettings: inSettings)
        }
        .overlay(Rectangle().strokeBorder(Palette.linea, lineWidth: 1))
        .crossCorners()
        .padding(.top, inSettings ? 0 : 6)
        .disabled(!installer.placement.canInstall || installer.helpersMissing || installer.helpersUntrusted != nil)
    }

    /// Screenshots of Settings' end (`-KlavSettingsBottom`, debug only).
    private var settingsAtEnd: Bool {
        #if DEBUG
        return Snapshot.settingsBottom
        #else
        return false
        #endif
    }

    private var linkQuestion: String {
        if case .other(let what) = installer.link {
            return String(localized: "\(installer.paths.link.path) already exists (\(what)). Replace it with a link to this app’s klav?")
        }
        return ""
    }

    // MARK: Steps

    private var daemonStep: some View {
        StepRow(title: "Background service",
                touches: "Adds Klav to System Settings › General › Login Items & Extensions: klavd starts when you log in, from inside this app.",
                done: installer.daemonReady,
                problem: installer.problems[.daemon]) {
            if let other = installer.otherDaemon {
                Status(text: String(localized: "Another klavd is running: \(other)"), tone: .warning)
                Button("Use this app’s") { confirmDaemon = true }
                    .buttonStyle(SecondaryButtonStyle(compact: true, block: false))
            } else {
                switch installer.agent {
                case .enabled:
                    Status(text: model.info?.running == true
                           ? String(localized: "Running, version \(model.info?.version ?? "?")")
                           : String(localized: "Set up, but not running: it starts at your next login"), tone: .done)
                case .requiresApproval:
                    Status(text: String(localized: "Allow Klav in System Settings › General › Login Items & Extensions"), tone: .warning)
                    Button("Open Login Items") { installer.system.openLoginItems() }
                        .buttonStyle(SecondaryButtonStyle(compact: true, block: false))
                case .notFound, .notRegistered:
                    action(installer.busy == .daemon ? "Setting up…" : "Set up") {
                        Task { await installer.setUpDaemon(engine: model.engine, info: model.info); model.refresh() }
                    }
                }
            }
        }
    }

    private var cliStep: some View {
        StepRow(title: "Command line",
                touches: "Creates \(installer.paths.link.path), a link to the klav inside this app, so updates update it too. macOS asks for an administrator’s password once.",
                done: installer.link == .ours,
                problem: installer.problems[.cli]) {
            switch installer.link {
            case .ours:
                Status(text: String(localized: "klav works in a new terminal"), tone: .done)
            case .other(let what):
                Status(text: String(localized: "Something else is there: \(what)"), tone: .warning)
                Button("Replace…") { confirmLink = true }
                    .buttonStyle(SecondaryButtonStyle(compact: true, block: false))
            case .missing:
                HStack(spacing: 8) {
                    action(installer.busy == .cli ? "Waiting for the password…" : "Add klav") {
                        Task { await installer.linkCLI(replace: false) }
                    }
                    Button("Copy the command instead") { model.copy(installer.linkCommand, what: String(localized: "Command copied")) }
                        .buttonStyle(LinkButtonStyle())
                }
            }
            ForEach(installer.otherCLIs, id: \.self) { path in
                otherCLI(path, installer.checkedCLIs.first { $0.path == path })
            }
        }
    }

    /// Another `klav` on the PATH, by what its file says (`BuildMarker`):
    /// older, the same build, newer, or a neutral line when it doesn't say
    /// its build. Only an older one shows a command, and only for cargo or
    /// Homebrew; the app runs none of it.
    @ViewBuilder private func otherCLI(_ path: String, _ cli: OtherCLI?) -> some View {
        switch cli?.age {
        case .older?:
            if let cli {
                Status(text: String(localized: "An older klav is at \(path). Your terminal may run it instead of this app’s."),
                       tone: .warning)
                Text(verbatim: builds(cli))
                    .font(.ui(12.5)).foregroundStyle(Palette.gris)
                    .fixedSize(horizontal: false, vertical: true)
                update(cli)
            }
        case .newer?:
            Status(text: String(localized: "A newer klav is at \(path). Your terminal may run it instead of this app’s."),
                   tone: .warning)
        case .same?:
            Status(text: String(localized: "The same klav as this app’s is at \(path)."), tone: .plain)
        case .unknown?:
            Status(text: String(localized: "Another klav is at \(path) and doesn’t say its build. Your terminal may run it instead of this app’s."),
                   tone: .warning)
        case nil:
            // Not read: the helpers aren't signed by Klav's team, the
            // sample's safety, or the read didn't end within its limit (a
            // hung volume; then whether a klav is there isn't known either).
            Status(text: String(localized: "Another klav is at \(path). Your terminal may run it instead of this app’s."),
                   tone: .warning)
        }
    }

    /// Its build and this app's, from what each file says.
    private func builds(_ cli: OtherCLI) -> String {
        let app = installer.appBuild?.described ?? "?"
        let build = cli.build?.described ?? "?"
        return String(localized: "Its build: \(build). This app’s: \(app).")
    }

    /// How to update an older one: the command for cargo or Homebrew, which
    /// the app shows and never runs.
    @ViewBuilder private func update(_ cli: OtherCLI) -> some View {
        switch cli.origin {
        case .cargo:
            if let command = cli.command {
                commandBlock(String(localized: "It came from cargo install. To update it, run this in Terminal, after you update that source:"), command)
            } else {
                Text("It came from cargo install. Install it again from the source you used, or remove it so this app’s klav runs.")
                    .font(.ui(12.5)).foregroundStyle(Palette.gris)
                    .fixedSize(horizontal: false, vertical: true)
            }
        case .homebrew:
            if let command = cli.command {
                commandBlock(String(localized: "It came from Homebrew. To update it, run this in Terminal:"), command)
            }
        case .other:
            EmptyView()
        }
    }

    private func commandBlock(_ intro: String, _ command: String) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(verbatim: intro)
                .font(.ui(12.5)).foregroundStyle(Palette.gris)
                .fixedSize(horizontal: false, vertical: true)
            Text(verbatim: command)
                .font(.mono(12)).foregroundStyle(Palette.tinta)
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(10)
                .background(Palette.niebla)
            Button("Copy the command") { model.copy(command, what: String(localized: "Command copied")) }
                .buttonStyle(LinkButtonStyle())
        }
    }

    private var hostsStep: some View {
        StepRow(title: "Browsers",
                touches: hostsTouches,
                done: installer.hostsReady,
                problem: installer.problems[.hosts]) {
            ForEach(installer.browsers, id: \.self) { id in
                let mine = installer.neededManifests.filter { $0.browser == id }
                let foreign = mine.filter(\.foreign)
                if installer.foreignDevKept.contains(id) {
                    // Another install lets the development build in here,
                    // and this app can't change that: said, not hidden.
                    ForEach(installer.foreignDevManifests.filter { $0.browser == id }) { m in
                        Status(text: String(localized: "\(BrowserNames.name(id)): another install, \(m.runs ?? m.pointsTo ?? "?")"), tone: .warning)
                    }
                } else if installer.cliDevBrowsers.contains(id) {
                    Status(text: String(localized: "\(BrowserNames.name(id)): lets in the development extension, connected from the command line"), tone: .warning)
                } else if installer.waits(id) {
                    Status(text: String(localized: "\(BrowserNames.name(id)): connects with “Development extension”, under “Advanced options”, until Klav is in the Chrome Web Store"), tone: .plain)
                } else if !mine.isEmpty, mine.allSatisfy(\.current) {
                    Status(text: "\(BrowserNames.name(id)): \(String(localized: "ready"))", tone: .done)
                } else if foreign.isEmpty, mine.contains(where: \.outdated) {
                    // This app's, but its host turns away an extension the
                    // manifest lists: connecting rewrites it without asking.
                    Status(text: String(localized: "\(BrowserNames.name(id)): needs connecting again"), tone: .plain)
                } else if foreign.isEmpty {
                    Status(text: "\(BrowserNames.name(id)): \(String(localized: "not connected yet"))", tone: .plain)
                } else {
                    ForEach(foreign) { m in
                        Status(text: String(localized: "\(BrowserNames.name(id)): another install, \(m.runs ?? m.pointsTo ?? "?")"), tone: .warning)
                    }
                }
            }
            if let kept = installer.foreignDevKeptLine {
                Status(text: kept, tone: .warning)
            }
            if installer.manifests.isEmpty {
                Status(text: String(localized: "No supported browser found on this Mac."), tone: .plain)
            } else if installer.hostsToConnect {
                action(installer.busy == .hosts ? "Connecting…" : installer.foreignManifests.isEmpty ? "Connect the browsers" : "Use this app’s…") {
                    connectHosts(replacingForeign: false)
                }
            }
            if !installer.manifests.isEmpty || installer.devExtension { advancedHosts }
        }
    }

    /// «Connect the browsers»: the installer reads the browsers again, then
    /// connects or says what to ask first (another install's manifests, or
    /// the development extension the command line let in), so connecting
    /// never drops the development extension on an old reading.
    private func connectHosts(replacingForeign: Bool) {
        Task {
            switch await installer.connectBrowsers(info: model.info, replacingForeign: replacingForeign) {
            case .none: break
            case .foreign: confirmHosts = true
            case .development: confirmDev = true
            }
        }
    }

    private var hostsTouches: LocalizedStringKey {
        installer.devExtension
            ? "Writes one small file in each browser’s folder so the extension can reach klavd: \(browserList). Development extension is on: Chromium browsers also let in the extension you load unpacked."
            : "Writes one small file in each browser’s folder so the extension can reach klavd: \(browserList). Firefox can connect now. Until Klav is in the Chrome Web Store, Chrome, Dia and the other Chromium browsers connect with “Development extension”, under “Advanced options”."
    }

    /// «Open Klav at login» (Settings only): off by default, and it shows
    /// what macOS says, not what was last chosen (`Installer.openAtLoginIsOn`).
    /// `klavd` starts at login either way, as the background service.
    private var openAtLogin: some View {
        let isOn = installer.openAtLoginIsOn
        return VStack(alignment: .leading, spacing: 8) {
            Toggle(isOn: Binding(get: { isOn },
                                 set: { on in Task { await installer.flipOpenAtLogin(on) } })) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Open Klav at login").font(.ui(13.5)).foregroundStyle(Palette.tinta)
                    Text("Klav opens in the menu bar when you log in, without a window. klavd starts at login either way: it’s the background service.")
                        .font(.ui(12)).foregroundStyle(Palette.gris)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            .toggleStyle(SquareToggleStyle())
            .disabled(installer.busy != nil || (!isOn && !installer.canOpenAtLogin))
            if installer.openAtLogin == .requiresApproval {
                Status(text: String(localized: "Allow Klav in System Settings › General › Login Items & Extensions"), tone: .warning)
                Button("Open Login Items") { installer.system.openLoginItems() }
                    .buttonStyle(SecondaryButtonStyle(compact: true, block: false))
            }
            if let problem = installer.problems[.login] { Notice(text: problem) }
        }
    }

    /// «Development extension» (T122): off by default, its risk in view
    /// before it is turned on.
    @ViewBuilder private var advancedHosts: some View {
        if advanced || installer.devExtension {
            Toggle(isOn: Binding(get: { installer.devExtension },
                                 set: { on in Task { await installer.setDevExtension(on) } })) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Development extension").font(.ui(13.5)).foregroundStyle(Palette.tinta)
                    Text("Lets in the Klav extension you load unpacked in Chrome, Dia and other Chromium browsers. Any unpacked extension with the public key in Klav’s repository could talk to klavd too.")
                        .font(.ui(12)).foregroundStyle(Palette.gris)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            .toggleStyle(SquareToggleStyle())
            .disabled(installer.busy != nil)
            .padding(.top, 4)
        } else {
            Button("Advanced options") { advanced = true }
                .buttonStyle(LinkButtonStyle())
        }
    }

    private var browserList: String {
        let names = installer.browsers.map(BrowserNames.name)
        return names.isEmpty ? String(localized: "none found") : names.formatted(.list(type: .and))
    }

    private var extensionStep: some View {
        StepRow(title: "Extension",
                touches: "Install Klav’s extension in each browser. Until it is in the stores, load it by hand: the page says how.",
                done: !connected.isEmpty,
                problem: nil) {
            ForEach(installer.browsers, id: \.self) { id in
                HStack(spacing: 10) {
                    if connected.contains(id) {
                        Status(text: String(localized: "Connected in \(BrowserNames.name(id))"), tone: .done)
                    } else {
                        Text(verbatim: BrowserNames.name(id)).font(.ui(13)).foregroundStyle(Palette.tinta)
                        Spacer()
                        Button("How to install it") { NSWorkspace.shared.open(BrowserNames.extensionPage) }
                            .buttonStyle(SecondaryButtonStyle(compact: true, block: false))
                    }
                }
            }
        }
    }

    /// Browsers (CLI names) whose extension attached to `klavd`.
    private var connected: Set<String> {
        let seen = model.info?.browsers.map(\.browser) ?? []
        return Set(installer.browsers.filter { id in seen.contains { BrowserNames.matches($0, id) } })
    }

    private var accountStep: some View {
        StepRow(title: "Account",
                touches: "Sign in with your emergency kit, or create an account. The master password and the Secret Key stay on this Mac.",
                done: model.info?.loggedIn == true,
                problem: nil) {
            if model.info?.loggedIn == true {
                Status(text: String(localized: "Signed in as \(model.info?.email ?? "")"), tone: .done)
            } else if model.info?.running != true {
                Status(text: String(localized: "Set up the background service first."), tone: .plain)
            } else {
                HStack(spacing: 8) {
                    action("Sign in") { account = .signIn }
                    Button("Create an account") { account = .signUp }
                        .buttonStyle(SecondaryButtonStyle(compact: true, block: false))
                }
            }
        }
    }

    private func action(_ title: LocalizedStringKey, _ run: @escaping () -> Void) -> some View {
        Button(title, action: run)
            .buttonStyle(PrimaryButtonStyle(compact: true))
            .fixedSize()
            .disabled(installer.busy != nil)
    }
}

/// Settings › This Mac.
struct MacSettingsView: View {
    #if DEBUG
    @State private var tab = Snapshot.settingsTab ?? "mac"
    #else
    @State private var tab = "mac"
    #endif

    var body: some View {
        TabView(selection: $tab) {
            SetupView(inSettings: true)
                .frame(width: 640, height: 720)
                .tabItem { Label("This Mac", systemImage: "laptopcomputer") }
                .tag("mac")
            // ADR 0037 §4: «Delete my account».
            AccountSettingsView()
                .tabItem { Label("Account", systemImage: "person.crop.circle") }
                .tag("account")
        }
    }
}

/// One step: its name, what it changes, then its state and action.
struct StepRow<Content: View>: View {
    let title: LocalizedStringKey
    let touches: LocalizedStringKey
    let done: Bool
    let problem: String?
    @ViewBuilder var content: Content

    var body: some View {
        HStack(alignment: .top, spacing: 14) {
            ZStack {
                Rectangle().fill(done ? Palette.tinta : Palette.papel)
                Rectangle().strokeBorder(done ? Palette.tinta : Palette.linea, lineWidth: 1)
                if done { IconView(icon: .check, size: 14).foregroundStyle(Palette.papel) }
            }
            .frame(width: 20, height: 20)
            .padding(.top, 1)
            .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 8) {
                Text(title).font(.ui(15, .semibold)).foregroundStyle(Palette.tinta)
                Text(touches).font(.ui(12.5)).foregroundStyle(Palette.gris)
                    .fixedSize(horizontal: false, vertical: true)
                VStack(alignment: .leading, spacing: 8) { content }.padding(.top, 2)
                if let problem { Notice(text: problem) }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .padding(16)
        .accessibilityElement(children: .contain)
        .accessibilityValue(done ? Text("Done") : Text("To do"))
    }
}

struct Status: View {
    enum Tone { case done, warning, plain }
    let text: String
    let tone: Tone

    var body: some View {
        Text(verbatim: text)
            .font(.ui(13, tone == .done ? .medium : .regular))
            .foregroundStyle(tone == .warning ? Palette.rojo : tone == .done ? Palette.tinta : Palette.gris)
            .textSelection(.enabled)
            .fixedSize(horizontal: false, vertical: true)
    }
}

/// The CLI's browser names, as people know them, and how the extension
/// names itself to `klavd` (`navigator.userAgentData` brands).
enum BrowserNames {
    /// The public install guide's «Browser extension» section
    /// (`apps/docs/src/content/docs/get-started/install.mdx`).
    static let extensionPage = URL(string: "https://docs.klav.dev/get-started/install/#browser-extension")!

    static func name(_ id: String) -> String {
        switch id {
        case "chrome": return "Chrome"
        case "chromium": return "Chromium"
        case "brave": return "Brave"
        case "arc": return "Arc"
        case "edge": return "Edge"
        case "dia": return "Dia"
        case "firefox": return "Firefox"
        default: return id
        }
    }

    /// `Google Chrome` is `chrome`, `Microsoft Edge` is `edge`…
    static func matches(_ extensionName: String, _ id: String) -> Bool {
        let name = extensionName.lowercased()
        switch id {
        case "chrome": return name.contains("chrome") && !name.contains("chromium")
        case "chromium": return name == "chromium"
        default: return name.contains(id)
        }
    }
}
