import AppKit
import Foundation

/// «Set up this Mac» (ADR 0027 §4): `klavd` as a LaunchAgent, the CLI on
/// the PATH, the browsers' native messaging hosts, the extension and the
/// account. Each step says what it touches before doing it, never replaces
/// another install without asking, and can be done again from Settings.
@MainActor
final class Installer: ObservableObject {
    enum Step: Hashable { case daemon, cli, hosts, account, uninstall, login }

    /// A browser's manifest, from `klav extension host-status`.
    struct Manifest: Decodable, Equatable, Identifiable {
        let browser: String
        let path: String
        let exists: Bool
        let pointsTo: String?
        let runs: String?
        /// Points to this app's wrapper, which runs this app's host and
        /// lets in every extension the manifest lists.
        let current: Bool
        /// Extensions the manifest lists that its host would turn away
        /// (`chrome-extension://<id>/` or a Firefox add-on ID).
        let refused: [String]?
        /// This app's: `current`, or it points to this app's wrapper, which
        /// runs this app's host, and only `refused` keeps it from being
        /// current. Set by `hostStatus`, which has the wrapper and the host.
        fileprivate(set) var ours = false
        /// A Chromium manifest whose `allowed_origins` lists the development
        /// build (`Installer.developmentOrigin`). Set by `hostStatus`.
        fileprivate(set) var listsDevelopmentBuild = false
        /// Points to this `KLAV_HOME`'s wrapper, which `install-host` rewrites,
        /// whatever host that wrapper runs now. Set by `hostStatus`.
        fileprivate(set) var viaThisHomesWrapper = false
        var id: String { path }
        /// Chromium's format (`allowed_origins`). Firefox's, in Mozilla's
        /// directory, is also the one Dia reads.
        var chromium: Bool { browser != "firefox" && !path.contains("/Mozilla/") }
        /// This app's, written before its wrapper changed: «Connect the
        /// browsers» writes it again without asking, and uninstalling takes it.
        var outdated: Bool { ours && !current }
        /// Another install's: the app shows it and asks before replacing it.
        var foreign: Bool { exists && !ours }

        enum CodingKeys: String, CodingKey {
            case browser, path, exists, current, runs, refused
            case pointsTo = "points_to"
        }
    }

    private struct HostReport: Decodable {
        /// This `KLAV_HOME`'s wrapper.
        let wrapper: String
        /// The host this app's `klav` would install (`--host`, resolved).
        let host: String?
        let manifests: [Manifest]
    }

    /// `klav extension install-host --json`: the Chromium browsers it left
    /// out for want of an extension to allow.
    private struct InstallReport: Decodable {
        let skipped: [String]?
    }

    enum LinkState: Equatable {
        case missing
        case ours
        /// Something else is there: its path or where it points.
        case other(String)
    }

    @Published private(set) var placement: Placement
    @Published private(set) var agent: AgentState = .notRegistered
    /// «Open Klav at login»: what macOS says of the app as a login item,
    /// read again on each refresh and when the app comes to the front (the
    /// person may change it in System Settings). Off by default.
    @Published private(set) var openAtLogin: AgentState = .notRegistered
    /// `klavd` runs, but from another path (a `cargo install`, an old app).
    @Published private(set) var otherDaemon: String?
    @Published private(set) var link: LinkState = .missing
    /// Other `klav` programs on the PATH: they may run instead of this one.
    @Published private(set) var otherCLIs: [String] = []
    /// This app's `klav` (`Helpers/klav --version`): what the others are
    /// compared with. Nil without trusted helpers.
    @Published private(set) var appBuild: BuildIdentity?
    /// The other `klav` programs, each with its build and how it compares
    /// with this app's (only with trusted helpers).
    @Published private(set) var checkedCLIs: [OtherCLI] = []
    /// The other `klav` programs older than this app's.
    var olderCLIs: [OtherCLI] { checkedCLIs.filter { $0.age == .older } }
    /// Those the person hasn't left, for the menu bar's panel.
    var shownOlderCLIs: [OtherCLI] { olderCLIs.filter { leftCLIs[leaveKey($0)] == nil } }
    /// «Not now» in the menu bar: by path and both builds, kept in the
    /// preferences, so it comes back only when either build changes.
    @Published private var leftCLIs: [String: Any] = [:]
    private static let leftCLIsKey = "olderCLIsLeft"

    func leave(_ cli: OtherCLI) {
        var left = leftCLIs
        left[leaveKey(cli)] = true
        leftCLIs = left
        defaults.set(left, forKey: Self.leftCLIsKey)
    }

    private func leaveKey(_ cli: OtherCLI) -> String {
        [cli.path, cli.build?.commit ?? cli.build?.version ?? "?", appBuild?.commit ?? "?"].joined(separator: "|")
    }
    @Published private(set) var manifests: [Manifest] = []
    @Published private(set) var helpersMissing = false
    /// What the signature check said (T120); nil without helpers to check.
    @Published private(set) var helperTrust: HelperSignature.Verdict?
    /// Why the helpers can't be trusted (T120): nothing is set up.
    var helpersUntrusted: String? { helperTrust?.refusal }
    /// A Debug build not signed by Klav's team: it sets up, but its helpers
    /// are not checked, and the setup says so.
    var unsignedDevelopmentBuild: Bool { helperTrust == .development }
    @Published private(set) var busy: Step?
    @Published var problems: [Step: String] = [:]
    /// «Development extension» (Settings, advanced): Chromium browsers let
    /// in the build loaded unpacked. Off by default (T122).
    @Published private(set) var devExtension: Bool
    /// Chromium browsers the last «Connect the browsers» left out: no
    /// store build to allow yet, and no development extension.
    @Published private(set) var waitingForStore: [String]

    let paths: InstallPaths
    let system: MacSystem
    private let defaults: SetupPreferences
    let signatures: CodeSignatures
    let development: Bool

    static let devExtensionKey = "devExtension"
    /// The Chromium development build's origin: its ID is fixed by the
    /// public `key` in its manifest (`DEV_CHROMIUM_ID` in
    /// `crates/klav-daemon/src/native.rs`). The build a release publishes
    /// to load unpacked, `klav-extension-chromium.zip`, carries that key.
    nonisolated static let developmentOrigin = "chrome-extension://niiplppgdljgimbnmokojdkofdcjkgao/"
    private static let waitingKey = "browsersWaitingForStore"
    /// What was left out depends on the bundle's `klav`: an update with a
    /// store ID connects them.
    private static var build: String { Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "" }

    init(paths: InstallPaths, system: MacSystem, placement: Placement,
         defaults: SetupPreferences = UserDefaults.standard,
         signatures: CodeSignatures = LiveSignatures(),
         development: Bool = HelperSignature.developmentBuild) {
        self.paths = paths
        self.system = system
        self.placement = placement
        self.defaults = defaults
        self.signatures = signatures
        self.development = development
        devExtension = defaults.bool(forKey: Self.devExtensionKey)
        let saved = defaults.dictionary(forKey: Self.waitingKey)
        waitingForStore = saved?[Self.build] as? [String] ?? []
        leftCLIs = defaults.dictionary(forKey: Self.leftCLIsKey) ?? [:]
    }

    static func live() -> Installer {
        Installer(paths: .live(), system: LiveSystem(), placement: .of(Bundle.main.bundleURL))
    }

    // MARK: State

    /// Manifests «Connect the browsers» writes: not the Chromium ones of a
    /// browser that waits for the store.
    var neededManifests: [Manifest] {
        let kept = foreignDevKept
        return manifests.filter { !($0.chromium && waits($0.browser)) && !($0.foreign && kept.contains($0.browser) && $0.chromium) }
    }
    /// Manifests that point to another install: the app shows them and asks.
    /// This app's own with an outdated wrapper are not among them.
    var foreignManifests: [Manifest] { neededManifests.filter(\.foreign) }
    /// Done when a browser can reach `klavd`: not while every one waits for
    /// the store (Dia's manifest in Mozilla's folder alone lets nothing in).
    var hostsReady: Bool {
        !neededManifests.isEmpty && neededManifests.allSatisfy(\.current) && browsers.contains { !waits($0) }
    }
    /// Something «Connect the browsers» would still write.
    var hostsToConnect: Bool { neededManifests.contains { !$0.current } }

    /// A Chromium browser that cannot reach `klavd` until Klav is in its
    /// store (or the development extension is on). Not one the command line
    /// connected to the development build: that one reaches it.
    func waits(_ browser: String) -> Bool {
        !devExtension && waitingForStore.contains(browser) && !cliDevBrowsers.contains(browser)
            && !foreignDevManifests.contains { $0.browser == browser }
    }
    /// Chromium browsers whose manifest lets in the development build
    /// through this app's host while «Development extension» is off:
    /// `klav extension install-host --dev` connected it from the command
    /// line. The app never turns the switch on by itself, nor takes that
    /// way in without asking: the Browsers step says so, and connecting the
    /// browsers asks first (`connectHosts(keepingDevelopment:)`, T122).
    /// Read from `manifests` and `devExtension`, so it changes with them.
    var cliDevBrowsers: [String] {
        guard !devExtension else { return [] }
        var seen = Set<String>()
        return manifests.filter { $0.chromium && $0.current && $0.listsDevelopmentBuild }
            .map(\.browser).filter { seen.insert($0).inserted }
    }
    /// The browsers whose manifest, of another install, has a host that lets
    /// the development build in (`klav extension install-host --dev` from
    /// another `klav`, even with this `KLAV_HOME`). With «Development
    /// extension» off, «Use this app’s» shuts that build out there, and its
    /// question says so.
    ///
    /// Only where that is true: the manifest points to this `KLAV_HOME`'s
    /// wrapper (which «Use this app’s» rewrites without the development
    /// build), and `install-host` will write that wrapper, which it does only
    /// with a Firefox-format manifest to write (Firefox, or Dia's copy in
    /// Mozilla's folder). Without one, while Klav has no Chromium extension
    /// to allow, it stops before writing anything (`foreignDevKept`).
    var foreignDevBrowsers: [String] {
        guard writesWrapper else { return [] }
        return Self.names(foreignDevManifests.filter(\.viaThisHomesWrapper))
    }
    /// Another install's Chromium manifests whose host lets the development
    /// build in, while «Development extension» is off.
    var foreignDevManifests: [Manifest] {
        guard !devExtension else { return [] }
        return manifests.filter {
            $0.chromium && $0.foreign && $0.listsDevelopmentBuild
                && !($0.refused ?? []).contains(Self.developmentOrigin)
        }
    }
    /// The browsers where another install's host lets the development build
    /// in and this app can change nothing: its manifest points to another
    /// `KLAV_HOME`'s wrapper, or there is no Firefox-format manifest to write,
    /// so `install-host` stops before the wrapper. «Use this app’s» can't
    /// replace them until Klav is in the Chrome Web Store, so they aren't
    /// offered for replacing; the Browsers step says the door stays open,
    /// whatever `waitingForStore` says.
    var foreignDevKept: [String] {
        Self.names(foreignDevManifests.filter { !($0.viaThisHomesWrapper && writesWrapper) })
    }
    /// `install-host` without `--dev` writes this home's wrapper: there is a
    /// Firefox-format manifest to write.
    private var writesWrapper: Bool { manifests.contains { !$0.chromium } }

    private static func names(_ manifests: [Manifest]) -> [String] {
        var seen = Set<String>()
        return manifests.map(\.browser).filter { seen.insert($0).inserted }
    }

    /// The question before replacing another install's manifests: each
    /// browser and the host it runs now, then what it does to the
    /// development extension another install let in (T122): shut out where
    /// it is (`foreignDevBrowsers`), still connecting where this app can't
    /// change it (`foreignDevKept`).
    var foreignHostsMessage: String {
        var lines = foreignManifests.map { "\($0.browser): \($0.runs ?? $0.pointsTo ?? "?")" }
        let out = foreignDevBrowsers, kept = foreignDevKept
        if !out.isEmpty || !kept.isEmpty { lines.append("") }
        if !out.isEmpty {
            let names = out.map(BrowserNames.name).formatted(.list(type: .and))
            lines.append(String(localized: "The host there now lets the development extension into \(names). This app’s won’t while “Development extension” is off, so it stops connecting there."))
        }
        if let line = foreignDevKeptLine { lines.append(line) }
        return lines.joined(separator: "\n")
    }

    /// What the Browsers step and the question say of `foreignDevKept`.
    var foreignDevKeptLine: String? {
        guard !foreignDevKept.isEmpty else { return nil }
        let names = foreignDevKept.map(BrowserNames.name).formatted(.list(type: .and))
        return String(localized: "Another install’s host lets the development extension into \(names). Klav can’t replace it there until Klav is in the Chrome Web Store, so the development extension still connects.")
    }
    var daemonReady: Bool { agent == .enabled && otherDaemon == nil }
    /// The browsers with Klav's host, by the name the CLI gives them.
    var browsers: [String] {
        var seen = Set<String>()
        return manifests.map(\.browser).filter { seen.insert($0).inserted }
    }

    /// Reads of the browsers started, and the newest one applied: a read
    /// that ends after a newer one (a slow `refresh` after a connect) never
    /// puts its older list back.
    private var hostReadsStarted = 0
    private var hostReadApplied = 0

    private func startHostRead() -> Int {
        hostReadsStarted += 1
        return hostReadsStarted
    }

    private func setManifests(_ found: [Manifest], read: Int) {
        guard read > hostReadApplied else { return }
        hostReadApplied = read
        manifests = found
    }

    func refresh(info: DaemonInfo?) async {
        let hostRead = startHostRead()
        let paths = paths, system = system, signatures = signatures, development = development
        let helpersMissing = !FileManager.default.isExecutableFile(atPath: paths.cli.path)
        let state = await Task.detached {
            () -> (AgentState, String?, LinkState, CLIState, [Manifest], HelperSignature.Verdict?, AgentState) in
            let trust = helpersMissing ? nil
                : HelperSignature.check(helpers: paths.helpers, signatures: signatures, development: development)
            let untrusted = trust?.refusal
            let agent = system.agentState()
            var other: String?
            if let info, info.running, let pid = info.pid, let exe = system.executable(of: Int32(pid)),
               !Self.same(exe, paths.daemon.path) {
                other = exe
            }
            let link = Self.linkState(paths)
            let clis = Self.cliState(paths, system, trusted: !helpersMissing && untrusted == nil)
            let manifests = helpersMissing || untrusted != nil ? [] : ((try? Self.hostStatus(paths, system)) ?? [])
            return (agent, other, link, clis, manifests, trust, system.appLoginState())
        }.value
        self.helpersMissing = helpersMissing
        (agent, otherDaemon, link, _, _, helperTrust, openAtLogin) = state
        setManifests(state.4, read: hostRead)
        (otherCLIs, appBuild, checkedCLIs) = (state.3.others, state.3.app, state.3.checked)
        if let why = helpersUntrusted {
            macLog.error("not signed by Klav's team, nothing is set up: \(why, privacy: .public)")
        }
    }

    nonisolated static func same(_ a: String, _ b: String) -> Bool {
        URL(fileURLWithPath: a).resolvingSymlinksInPath().standardizedFileURL.path
            == URL(fileURLWithPath: b).resolvingSymlinksInPath().standardizedFileURL.path
    }

    nonisolated static func linkState(_ paths: InstallPaths) -> LinkState {
        let fm = FileManager.default
        let path = paths.link.path
        if let target = try? fm.destinationOfSymbolicLink(atPath: path) {
            let absolute = target.hasPrefix("/") ? target : paths.linkDirectory.appendingPathComponent(target).path
            return same(absolute, paths.cli.path) ? .ours : .other(absolute)
        }
        return fm.fileExists(atPath: path) ? .other(path) : .missing
    }

    /// What `refresh` and `checkCLIs` read of the other `klav` programs.
    struct CLIState {
        let others: [String]
        let app: BuildIdentity?
        let checked: [OtherCLI]
    }

    /// The other `klav` programs, and with trusted helpers how each
    /// compares with this app's. This app's build comes from its own
    /// signed `klav --version`; each other's from the line its file
    /// carries (`MacSystem.probeCLIs`, `BuildMarker`): the app never runs a
    /// `klav` it didn't install. Everything that touches another `klav`'s
    /// folder runs in `BuildMarker.Reader`'s bounded jobs, so a PATH folder
    /// on a volume that stops answering holds nothing up: its `klav` is
    /// listed as not read.
    nonisolated static func cliState(_ paths: InstallPaths, _ system: MacSystem, trusted: Bool) -> CLIState {
        var seen = Set<String>()
        let candidates = paths.pathDirectories.map { $0.appendingPathComponent("klav").path }
            .filter { $0 != paths.link.path && seen.insert($0).inserted }
        let contents = trusted && system.refusal(for: paths) == nil
        let probes = system.probeCLIs(candidates, appCLI: paths.cli.path, contents: contents)
        // A path whose job didn't end in time: whether a `klav` is there
        // isn't known, so it is listed, not read.
        let others = candidates.filter { probes[$0]?.present ?? true }
        guard contents else { return CLIState(others: others, app: nil, checked: []) }
        let app = (try? system.run(paths.cli, ["--version"], environment: environment(paths)))
            .flatMap { $0.status == 0 ? BuildIdentity(versionOutput: $0.output, program: "klav") : nil }
        let checked = others.map { path -> OtherCLI in
            let probe = probes[path]
            let age: BuildIdentity.Age? = probe?.reading.map { reading in
                guard let build = reading.build, let app else { return .unknown }
                return build.age(comparedWith: app)
            }
            return OtherCLI(path: path, reading: probe?.reading, age: age, origin: probe?.origin ?? .other)
        }
        return CLIState(others: others, app: app, checked: checked)
    }

    /// Once per launch, from the menu bar, whether `klavd` runs or not:
    /// the other `klav` programs and how they compare with this app's.
    /// Only what `refresh` also reads, so the two never disagree.
    func checkCLIs() async {
        guard !clisChecked else { return }
        clisChecked = true
        let paths = paths, system = system, signatures = signatures, development = development
        let helpersMissing = !FileManager.default.isExecutableFile(atPath: paths.cli.path)
        let state = await Task.detached(priority: .utility) { () -> CLIState in
            let trusted = !helpersMissing
                && HelperSignature.check(helpers: paths.helpers, signatures: signatures, development: development).refusal == nil
            return Self.cliState(paths, system, trusted: trusted)
        }.value
        (otherCLIs, appBuild, checkedCLIs) = (state.others, state.app, state.checked)
    }

    private var clisChecked = false

    private nonisolated static func hostStatus(_ paths: InstallPaths, _ system: MacSystem) throws -> [Manifest] {
        let result = try system.run(paths.cli, ["extension", "host-status", "--host", paths.nativeHost.path, "--json"],
                                    environment: environment(paths))
        guard result.status == 0 else { throw SetupError.failed(result.errors) }
        let report = try JSONDecoder().decode(HostReport.self, from: result.output)
        return report.manifests.map { manifest in
            var manifest = manifest
            // The CLI's own test: this home's wrapper, running this host.
            // A host that would refuse an extension the manifest lists is
            // the only thing that keeps such a manifest from being current.
            manifest.ours = manifest.current
                || (!(manifest.refused ?? []).isEmpty && manifest.pointsTo == report.wrapper
                    && report.host != nil && manifest.runs == report.host)
            manifest.viaThisHomesWrapper = manifest.pointsTo == report.wrapper
            if manifest.chromium, let data = FileManager.default.contents(atPath: manifest.path),
               let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
               let origins = json["allowed_origins"] as? [String] {
                manifest.listsDevelopmentBuild = origins.contains(developmentOrigin)
            }
            return manifest
        }
    }

    private nonisolated static func environment(_ paths: InstallPaths) -> [String: String] {
        ["HOME": paths.userHome.path, "KLAV_HOME": paths.klavHome.path]
    }

    /// `klavd --version` of the bundle: `klavd 0.6.0 (ce4fa5099092
    /// 2026-11-13T18:17:02Z)`. With this Mac's home and `KLAV_HOME`, like
    /// every other run.
    nonisolated func helperBuild() -> BuildIdentity? {
        guard let result = try? system.run(paths.daemon, ["--version"], environment: Self.environment(paths)),
              result.status == 0 else {
            return nil
        }
        return BuildIdentity(versionOutput: result.output, program: "klavd")
    }

    // MARK: Steps

    private func step(_ step: Step, undoes: Bool = false, _ body: () async throws -> Void) async {
        // The sample vault never touches the person's real home or PATH,
        // uninstalling included (it could delete the real KLAV_HOME).
        if let why = system.refusal(for: paths) {
            problems[step] = why
            return
        }
        // T120: never set up helpers that are not Klav's (uninstalling, or
        // undoing a step, is fine).
        if step != .uninstall, !undoes, helpersUntrusted != nil { return }
        busy = step
        problems[step] = nil
        do {
            try await body()
        } catch SetupError.cancelled {
            // The person said no: nothing to report.
        } catch {
            problems[step] = describe(error)
        }
        busy = nil
    }

    /// 1. `klavd` as a LaunchAgent: it starts at login, and macOS lists it
    /// in Login Items as «Klav».
    func setUpDaemon(engine: MacEngine, info: DaemonInfo?) async {
        await step(.daemon) {
            let system = system
            try await Task.detached {
                if system.agentState() != .enabled { try system.registerAgent() }
            }.value
            if system.agentState() == .requiresApproval { system.openLoginItems() }
            await refresh(info: info)
        }
    }

    /// Stops a `klavd` from another path and starts this app's.
    func useThisDaemon(engine: MacEngine) async {
        await step(.daemon) {
            let system = system
            try await Task.detached {
                try? engine.shutdown()
                for _ in 0..<50 where engine.status().running {
                    try await Task.sleep(for: .milliseconds(100))
                }
                if system.agentState() == .enabled { try system.restartAgent() } else { try system.registerAgent() }
            }.value
            try await Task.sleep(for: .milliseconds(500))
            await refresh(info: engine.status())
        }
    }

    /// After «Delete this Mac’s copy» stopped `klavd` (ADR 0037): the
    /// LaunchAgent does not start it again after a clean exit, so it is
    /// restarted here, signed out. Nothing is registered that was not.
    func restartDaemonIfRegistered() async {
        let system = system
        try? await Task.detached {
            if system.agentState() == .enabled { try system.restartAgent() }
        }.value
    }

    private var versionChecked = false

    /// Once per launch: reads the state, then `restartIfOutdated`.
    func checkVersion(engine: MacEngine, info: DaemonInfo) async -> Bool {
        guard !versionChecked else { return false }
        versionChecked = true
        await refresh(info: info)
        return await restartIfOutdated(engine: engine, info: info)
    }

    /// A `klavd` from this app's bundle that is not the build there now
    /// (the app was updated, and the old binary still runs): `shutdown`,
    /// and the LaunchAgent starts the new one. The person unlocks again.
    ///
    /// The builds differ when their commits differ, when only one of them
    /// says its commit (a `klavd` from before builds said theirs reports
    /// only `0.0.0`), or, when neither does, when their numbers differ
    /// (`BuildIdentity.sameBuild`). It converges: after the restart the
    /// running `klavd` is the bundle's binary, which says what its
    /// `--version` says.
    func restartIfOutdated(engine: MacEngine, info: DaemonInfo) async -> Bool {
        guard info.running, info.version != nil, otherDaemon == nil, agent == .enabled,
              helpersUntrusted == nil else { return false }
        let system = system
        let running = BuildIdentity(status: info)
        let helper = await Task.detached { [self] in helperBuild() }.value
        guard let helper, !running.sameBuild(as: helper) else { return false }
        macLog.info("klavd \(running.described, privacy: .public) is not the app's \(helper.described, privacy: .public): restarting it")
        _ = try? await Task.detached {
            try? engine.shutdown()
            try await Task.sleep(for: .milliseconds(300))
            try system.restartAgent()
        }.value
        return true
    }

    /// 2. `klav` on the PATH: a symlink in `/usr/local/bin` to the bundle's,
    /// so every update of the app updates the CLI. macOS asks for an
    /// administrator's password once (that directory is root's). Something
    /// else already there is replaced only with `replace`.
    func linkCLI(replace: Bool) async {
        await step(.cli) {
            let paths = paths, system = system
            if case .other = Self.linkState(paths), !replace { return }
            try await Task.detached {
                let fm = FileManager.default
                let dir = paths.linkDirectory.path
                if fm.fileExists(atPath: dir), fm.isWritableFile(atPath: dir) {
                    try? fm.removeItem(atPath: paths.link.path)
                    try fm.createSymbolicLink(atPath: paths.link.path, withDestinationPath: paths.cli.path)
                } else {
                    try system.runAsAdministrator(
                        "/bin/mkdir -p \(shellQuote(dir)) && /bin/ln -sfn \(shellQuote(paths.cli.path)) \(shellQuote(paths.link.path))")
                }
            }.value
            link = Self.linkState(paths)
        }
    }

    /// The command to make the link by hand, for a person who would rather
    /// not give the app the password.
    var linkCommand: String {
        "sudo mkdir -p \(shellQuote(paths.linkDirectory.path)) && sudo ln -sfn \(shellQuote(paths.cli.path)) \(shellQuote(paths.link.path))"
    }

    /// 3. The browsers' native messaging hosts, through the bundle's `klav`
    /// (`klav extension install-host`). Manifests of another install are
    /// replaced only after the person chose «Use this app's».
    ///
    /// Firefox's add-on has a fixed ID. Chromium browsers need the store
    /// build's, which `klav` allows once the Chrome Web Store assigns it;
    /// until then they are left out (`skipped`). `--dev` allows the
    /// development build loaded unpacked, only with «Development
    /// extension» on: its key is public (T122, ADR 0030 layer 09).
    func installHosts() async {
        await step(.hosts) { try await connect() }
    }

    /// What connecting the browsers needs from the person first.
    enum HostsQuestion: Equatable {
        /// Nothing: they were connected.
        case none
        /// Another install's manifests would be replaced (`foreignManifests`).
        case foreign
        /// The command line let the development build in (`cliDevBrowsers`).
        case development
    }

    /// «Connect the browsers», and «Use this app’s» once the person said yes
    /// to replacing another install's manifests (`replacingForeign`). It reads
    /// the browsers again first: the person may have run `klav extension
    /// install-host --dev` in Terminal since the window last read them, and
    /// connecting on that old reading would drop the development build
    /// without asking (T122). Then it connects, or writes nothing and says
    /// what to ask.
    ///
    /// The browsers are read here, not taken from `refresh`, which shows an
    /// empty list when `host-status` fails: deciding on that would connect
    /// without `--dev` and without asking. A failed read stops the step with
    /// its error and writes nothing.
    func connectBrowsers(info: DaemonInfo?, replacingForeign: Bool) async -> HostsQuestion {
        await refresh(info: info)
        var question = HostsQuestion.none
        let paths = paths, system = system
        await step(.hosts) {
            let read = startHostRead()
            let found = try await Task.detached { try Self.hostStatus(paths, system) }.value
            setManifests(found, read: read)
            if !replacingForeign, !foreignManifests.isEmpty {
                question = .foreign
            } else if !cliDevBrowsers.isEmpty {
                question = .development
            } else {
                try await connect()
            }
        }
        return question
    }

    /// `klav extension install-host` through the bundle's `klav`, and the
    /// browsers read again. Runs inside `step(.hosts)`.
    private func connect() async throws {
        let paths = paths, system = system
        let arguments = ["extension", "install-host", "--host", paths.nativeHost.path]
            + (devExtension ? ["--dev"] : []) + ["--json"]
        let result = try await Task.detached {
            try system.run(paths.cli, arguments, environment: Self.environment(paths))
        }.value
        let nothingToAllow = result.errors.contains("no Chromium extension to allow")
        guard result.status == 0 || nothingToAllow else {
            throw SetupError.failed(result.errors.contains("no supported browser")
                ? String(localized: "No supported browser found on this Mac.")
                : result.errors)
        }
        let read = startHostRead()
        let found = try await Task.detached { try Self.hostStatus(paths, system) }.value
        if nothingToAllow {
            // Only Chromium browsers here, and nothing to allow in them.
            var seen = Set<String>()
            setWaiting(found.filter(\.chromium).map(\.browser).filter { seen.insert($0).inserted })
        } else {
            let report = try? JSONDecoder().decode(InstallReport.self, from: result.output)
            setWaiting(report?.skipped ?? [])
        }
        setManifests(found, read: read)
    }

    /// «Connect the browsers» while `cliDevBrowsers` isn't empty, after the
    /// person chose (T122). Keeping it turns «Development extension» on and
    /// connects with `--dev`, which lets the development build into every
    /// Chromium browser here. Removing it takes this app's Chromium
    /// manifests that list it and this home's wrapper, then connects without
    /// `--dev`, all in one step (`busy`). With a Firefox-format manifest to
    /// write, `install-host` writes the wrapper again without the development
    /// build; with only Chromium browsers it stops before (nothing to allow),
    /// and the wrapper stays gone. Either way no wrapper lists that build.
    func connectHosts(keepingDevelopment keep: Bool) async {
        if keep {
            await setDevExtension(true)
            await installHosts()
            return
        }
        let paths = paths, system = system
        await step(.hosts) {
            // What to delete is read in this step, not taken from the list
            // the window showed when the person clicked.
            let found = try await Task.detached { try Self.hostStatus(paths, system) }.value
            let listing = found.filter { $0.chromium && $0.ours && $0.listsDevelopmentBuild }.map(\.path)
            await Task.detached {
                let fm = FileManager.default
                for path in listing { try? fm.removeItem(atPath: path) }
                // The wrapper lists the development build too, and a manifest
                // `host-status` doesn't see (`install-host --dev
                // --user-data-dir`) can still point at it: it goes, as when
                // the switch is turned off. `install-host` writes it again
                // without the development build when it has a browser to
                // connect; otherwise it stays gone.
                try? fm.removeItem(at: paths.klavHome.appendingPathComponent("native-host/klav-native-host"))
            }.value
            try await connect()
        }
    }

    /// Turns «Development extension» on or off, for this app. Off takes the
    /// development build's way in at once: this app's Chromium manifests
    /// and the host's wrapper (which lists the extensions it lets in) go,
    /// and the browsers are connected again without it.
    func setDevExtension(_ on: Bool) async {
        guard on != devExtension else { return }
        devExtension = on
        defaults.set(on, forKey: Self.devExtensionKey)
        setWaiting([])
        guard !on else { return }
        let paths = paths, system = system
        let ours = manifests.filter(\.ours)
        guard !ours.isEmpty else { return }
        await step(.hosts) {
            await Task.detached {
                let fm = FileManager.default
                for manifest in ours where manifest.chromium {
                    try? fm.removeItem(atPath: manifest.path)
                }
                try? fm.removeItem(at: paths.klavHome.appendingPathComponent("native-host/klav-native-host"))
            }.value
            let read = startHostRead()
            setManifests(try await Task.detached { try Self.hostStatus(paths, system) }.value, read: read)
        }
        await installHosts()
        // Said, not hidden: a manifest that stays still lets it in. Its
        // host now turns it away, so it is outdated, not current.
        let left = manifests.filter { $0.chromium && $0.ours }.map(\.path)
        if !left.isEmpty, problems[.hosts] == nil {
            problems[.hosts] = String(localized: "Klav couldn’t remove these files; delete them to stop the development extension: \(left.joined(separator: ", "))")
        }
    }

    private func setWaiting(_ browsers: [String]) {
        waitingForStore = browsers
        defaults.set(browsers.isEmpty ? [:] : [Self.build: browsers], forKey: Self.waitingKey)
    }

    // MARK: Open Klav at login

    /// What macOS says now of the app as a login item.
    func refreshOpenAtLogin() {
        openAtLogin = system.appLoginState()
    }

    /// Whether «Open Klav at login» may be turned on: not from a
    /// translocated copy and not from the disk image (`Placement.canInstall`:
    /// a login item there would point to a temporary place), and with
    /// helpers signed by Klav's team (T120). Off always works.
    var canOpenAtLogin: Bool { placement.canInstall && helpersUntrusted == nil }

    /// The switch is on only when macOS says `.enabled`: while it waits for
    /// the person's approval, Klav doesn't open at login yet.
    var openAtLoginIsOn: Bool { openAtLogin == .enabled }

    /// The person flips the switch. On while macOS waits for their
    /// approval opens Login Items, where they allow it; registering again
    /// would change nothing.
    func flipOpenAtLogin(_ on: Bool) async {
        if on, openAtLogin == .requiresApproval {
            system.openLoginItems()
            return
        }
        await setOpenAtLogin(on)
    }

    /// «Open Klav at login» (Settings › This Mac): registers the app itself
    /// with `SMAppService.mainApp`, apart from `klavd`'s LaunchAgent, which
    /// starts at login either way. macOS may want the person to allow it in
    /// Login Items: then `openAtLogin` says `.requiresApproval`.
    func setOpenAtLogin(_ on: Bool) async {
        if on, !placement.canInstall { return }
        var failure: String?
        await step(.login, undoes: !on) {
            let system = system
            failure = await Task.detached { () -> String? in
                do {
                    if on { try system.registerApp() } else { try system.unregisterApp() }
                    return nil
                } catch {
                    // Already as asked (registered twice, or already off):
                    // not a failure.
                    let now = system.appLoginState()
                    if on ? (now == .enabled || now == .requiresApproval) : now == .notRegistered { return nil }
                    let why = error.localizedDescription
                    return on
                        ? String(localized: "macOS didn’t add Klav to Login Items: \(why)")
                        : String(localized: "macOS didn’t take Klav off Login Items: \(why)")
                }
            }.value
        }
        if let failure { problems[.login] = failure }
        refreshOpenAtLogin()
    }

    // MARK: Uninstalling (ADR 0027 §4.1)

    /// Takes off the LaunchAgent, `klavd`, the browsers' manifests and the
    /// link; `KLAV_HOME` (the Secret Key, the cache) only with `deleteHome`.
    func uninstall(engine: MacEngine, deleteHome: Bool) async -> Bool {
        var done = false
        await step(.uninstall) {
            let paths = paths, system = system
            let linkIsOurs = Self.linkState(paths) == .ours
            let left = try await Task.detached { () -> [String] in
                // What macOS kept in Login Items: said instead of success.
                var left: [String] = []
                if system.agentState() != .notRegistered {
                    do { try system.unregisterAgent() } catch where system.agentState() != .notRegistered {
                        left.append(String(localized: "macOS didn’t take the background service off Login Items: \(error.localizedDescription)"))
                    }
                }
                if system.appLoginState() != .notRegistered {
                    do { try system.unregisterApp() } catch where system.appLoginState() != .notRegistered {
                        left.append(String(localized: "macOS didn’t take Klav off Login Items: \(error.localizedDescription)"))
                    }
                }
                try? engine.shutdown()
                // Only the manifests that run this app's host, outdated
                // ones too: another install's stay where they are.
                if FileManager.default.isExecutableFile(atPath: paths.cli.path) {
                    for manifest in try Self.hostStatus(paths, system) where manifest.ours {
                        try? FileManager.default.removeItem(atPath: manifest.path)
                    }
                    try? FileManager.default.removeItem(
                        at: paths.klavHome.appendingPathComponent("native-host/klav-native-host"))
                }
                if linkIsOurs {
                    let fm = FileManager.default
                    if fm.isWritableFile(atPath: paths.linkDirectory.path) {
                        try fm.removeItem(atPath: paths.link.path)
                    } else {
                        try system.runAsAdministrator("/bin/rm -f \(shellQuote(paths.link.path))")
                    }
                }
                if deleteHome, FileManager.default.fileExists(atPath: paths.klavHome.path) {
                    try FileManager.default.removeItem(at: paths.klavHome)
                }
                return left
            }.value
            if left.isEmpty { done = true } else { problems[.uninstall] = left.joined(separator: "\n") }
        }
        await refresh(info: nil)
        return done
    }
}

/// Where the app keeps its setup choices: `UserDefaults` (`dev.klav.mac`),
/// or memory in the tests, which write nothing outside their directory.
protocol SetupPreferences: AnyObject {
    func bool(forKey defaultName: String) -> Bool
    func dictionary(forKey defaultName: String) -> [String: Any]?
    func set(_ value: Any?, forKey defaultName: String)
}

extension UserDefaults: SetupPreferences {}

/// Single-quotes `text` for `/bin/sh`.
func shellQuote(_ text: String) -> String {
    "'" + text.replacingOccurrences(of: "'", with: "'\\''") + "'"
}
