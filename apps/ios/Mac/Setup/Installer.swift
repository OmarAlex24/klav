import AppKit
import Foundation

/// «Set up this Mac» (ADR 0027 §4): `klavd` as a LaunchAgent, the CLI on
/// the PATH, the browsers' native messaging hosts, the extension and the
/// account. Each step says what it touches before doing it, never replaces
/// another install without asking, and can be done again from Settings.
@MainActor
final class Installer: ObservableObject {
    enum Step: Hashable { case daemon, cli, hosts, account, uninstall, login, extensionDownload }

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
    /// Supported browsers installed as apps on this Mac (`LiveSystem`), or
    /// nil when not filtering by installed apps (tests).
    @Published private(set) var installedBrowsers: Set<String>?
    /// Browsers the person unchecked in Settings › This Mac › Browsers.
    @Published private(set) var deselectedBrowsers: Set<String> = []
    /// True once `refresh(info:)` has run at least once (avoids a flash of
    /// incomplete-setup badges before state is read).
    @Published private(set) var refreshed = false
    /// Where this app unpacked the Chromium extension, if already downloaded.
    @Published private(set) var unpackedExtensionURL: URL?
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
    private static let deselectedBrowsersKey = "deselectedBrowsers"
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
        let savedDeselected = defaults.dictionary(forKey: Self.deselectedBrowsersKey) ?? [:]
        deselectedBrowsers = Set(savedDeselected.compactMap { $0.value as? Bool == true ? $0.key : nil })
        unpackedExtensionURL = Self.existingExtensionDirectory(klavHome: paths.klavHome)
        leftCLIs = defaults.dictionary(forKey: Self.leftCLIsKey) ?? [:]
    }

    static func live() -> Installer {
        Installer(paths: .live(), system: LiveSystem(), placement: .of(Bundle.main.bundleURL))
    }

    // MARK: State

    /// Whether a browser is checked in «Browsers». Checked by default.
    func isBrowserSelected(_ id: String) -> Bool { !deselectedBrowsers.contains(id) }

    /// Checks or unchecks a browser in «Browsers», saved in preferences.
    func setBrowserSelected(_ id: String, _ selected: Bool) {
        var next = deselectedBrowsers
        if selected { next.remove(id) } else { next.insert(id) }
        guard next != deselectedBrowsers else { return }
        deselectedBrowsers = next
        let stored = Dictionary(uniqueKeysWithValues: next.map { ($0, true) })
        defaults.set(stored, forKey: Self.deselectedBrowsersKey)
    }

    /// Supported browsers shown in «Browsers»: installed apps when the system
    /// reports them (`LiveSystem`), otherwise every browser whose data folder
    /// exists (tests).
    var browsers: [String] {
        var seen = Set<String>()
        if let installed = installedBrowsers {
            let ordered = BrowserNames.order.filter { installed.contains($0) }
            let extra = manifests.map(\.browser).filter { installed.contains($0) && !ordered.contains($0) }
            return (ordered + extra).filter { seen.insert($0).inserted }
        }
        return manifests.map(\.browser).filter { seen.insert($0).inserted }
    }

    /// Browsers with leftover data folders on disk whose app is not installed
    /// on this Mac.
    var uninstalledBrowsers: [String] {
        guard let installed = installedBrowsers else { return [] }
        var seen = Set<String>()
        return manifests.map(\.browser).filter { !installed.contains($0) && seen.insert($0).inserted }
    }

    /// Installed (or visible) browsers the person chose to connect.
    var chosenBrowsers: [String] {
        browsers.filter { !deselectedBrowsers.contains($0) }
    }

    /// Manifests of the browsers the person chose: uninstalled folders and
    /// unchecked browsers are left alone.
    var activeManifests: [Manifest] {
        let chosen = Set(chosenBrowsers)
        return manifests.filter { chosen.contains($0.browser) }
    }

    /// Something in Settings › This Mac wants attention: an older `klav` on
    /// the PATH, `klavd` not set up, `klav` not linked, or chosen browsers
    /// not connected yet.
    var needsSetupAttention: Bool {
        if !shownOlderCLIs.isEmpty { return true }
        guard refreshed else { return false }
        return !daemonReady || link != .ours || (!chosenBrowsers.isEmpty && !hostsReady)
    }

    /// Deduplicates foreign manifests for one browser that run the same host
    /// (Dia reads both `Dia/User Data` and `Mozilla`, which often point to
    /// the same other install).
    static func uniqueForeignHosts(_ manifests: [Manifest]) -> [Manifest] {
        var seen = Set<String>()
        return manifests.filter { m in
            seen.insert("\(m.browser)|\(m.runs ?? m.pointsTo ?? "?")").inserted
        }
    }

    /// Manifests «Connect the browsers» writes: only for chosen browsers, and
    /// not the Chromium ones of a browser that waits for the store.
    var neededManifests: [Manifest] {
        let kept = foreignDevKept
        return activeManifests.filter { !($0.chromium && waits($0.browser)) && !($0.foreign && kept.contains($0.browser) && $0.chromium) }
    }
    /// Manifests that point to another install: the app shows them and asks.
    /// This app's own with an outdated wrapper are not among them.
    var foreignManifests: [Manifest] { neededManifests.filter(\.foreign) }
    /// Done when a chosen browser can reach `klavd`: not while every one waits
    /// for the store (Dia's manifest in Mozilla's folder alone lets nothing in).
    var hostsReady: Bool {
        !neededManifests.isEmpty && neededManifests.allSatisfy(\.current) && chosenBrowsers.contains { !waits($0) }
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
    /// Read from `activeManifests` and `devExtension`, so it changes with them.
    var cliDevBrowsers: [String] {
        guard !devExtension else { return [] }
        var seen = Set<String>()
        return activeManifests.filter { $0.chromium && $0.current && $0.listsDevelopmentBuild }
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
        return activeManifests.filter {
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
    /// Firefox-format manifest to write among the chosen browsers.
    private var writesWrapper: Bool { activeManifests.contains { !$0.chromium } }

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
        var lines = Self.uniqueForeignHosts(foreignManifests).map { "\($0.browser): \($0.runs ?? $0.pointsTo ?? "?")" }
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
        let installed = system.installedBrowsers()
        let helpersMissing = !FileManager.default.isExecutableFile(atPath: paths.cli.path)
        let state = await Task.detached {
            () -> (AgentState, String?, LinkState, CLIState, [Manifest], HelperSignature.Verdict?, AgentState, URL?) in
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
            let manifests = helpersMissing || untrusted != nil ? [] : ((try? Self.hostStatus(paths, system, installed: installed)) ?? [])
            let extensionDir = Self.existingExtensionDirectory(klavHome: paths.klavHome)
            return (agent, other, link, clis, manifests, trust, system.appLoginState(), extensionDir)
        }.value
        self.helpersMissing = helpersMissing
        installedBrowsers = installed
        (agent, otherDaemon, link, _, _, helperTrust, openAtLogin, unpackedExtensionURL) = state
        setManifests(state.4, read: hostRead)
        (otherCLIs, appBuild, checkedCLIs) = (state.3.others, state.3.app, state.3.checked)
        refreshed = true
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

    private nonisolated static func hostStatus(_ paths: InstallPaths, _ system: MacSystem,
                                               installed: Set<String>? = nil) throws -> [Manifest] {
        var list = try runHostStatus(paths, system, browsers: [])
        if let installed {
            let seen = Set(list.map(\.browser))
            let missing = installed.subtracting(seen).sorted()
            if !missing.isEmpty, let extra = try? runHostStatus(paths, system, browsers: missing) {
                let pathsSeen = Set(list.map(\.path))
                list += extra.filter { !pathsSeen.contains($0.path) }
            }
        }
        return list
    }

    private nonisolated static func runHostStatus(_ paths: InstallPaths, _ system: MacSystem,
                                                  browsers: [String]) throws -> [Manifest] {
        let arguments = ["extension", "host-status", "--host", paths.nativeHost.path]
            + browsers.flatMap { ["--browser", $0] } + ["--json"]
        let result = try system.run(paths.cli, arguments, environment: environment(paths))
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
        let paths = paths, system = system, installed = installedBrowsers
        await step(.hosts) {
            let read = startHostRead()
            let found = try await Task.detached { try Self.hostStatus(paths, system, installed: installed) }.value
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

    private var usesExplicitBrowserFilter: Bool {
        installedBrowsers != nil || !deselectedBrowsers.isEmpty
    }

    /// `klav extension install-host` through the bundle's `klav`, and the
    /// browsers read again. Runs inside `step(.hosts)`.
    private func connect() async throws {
        let paths = paths, system = system, installed = installedBrowsers
        let explicit = usesExplicitBrowserFilter
        let chosen = chosenBrowsers
        if explicit, chosen.isEmpty {
            let read = startHostRead()
            let found = try await Task.detached { try Self.hostStatus(paths, system, installed: installed) }.value
            setWaiting([])
            setManifests(found, read: read)
            return
        }
        let browserArgs = explicit ? chosen.flatMap { ["--browser", $0] } : []
        let arguments = ["extension", "install-host", "--host", paths.nativeHost.path]
            + browserArgs + (devExtension ? ["--dev"] : []) + ["--json"]
        let result = try await Task.detached {
            try system.run(paths.cli, arguments, environment: Self.environment(paths))
        }.value
        let nothingToAllow = result.errors.contains("no Chromium extension to allow")
        guard result.status == 0 || nothingToAllow else {
            throw SetupError.failed(result.errors.contains("no supported browser")
                ? String(localized: "No supported browser found on this Mac.")
                : result.errors)
        }
        // When connecting specific browsers without `--dev` and Chromium has no
        // store build yet, still write Mozilla's manifest if Firefox or Dia was
        // chosen, without touching uninstalled or unchecked browsers.
        if nothingToAllow, explicit, !devExtension,
           chosen.contains("firefox") || chosen.contains("dia") {
            let ffArgs = ["extension", "install-host", "--host", paths.nativeHost.path,
                          "--browser", "firefox", "--json"]
            let ffResult = try await Task.detached {
                try system.run(paths.cli, ffArgs, environment: Self.environment(paths))
            }.value
            guard ffResult.status == 0 else {
                throw SetupError.failed(ffResult.errors)
            }
        }
        let read = startHostRead()
        let found = try await Task.detached { try Self.hostStatus(paths, system, installed: installed) }.value
        if nothingToAllow {
            // Chosen Chromium browsers have nothing to allow yet.
            var seen = Set<String>()
            let chosenSet = Set(chosen)
            setWaiting(found.filter { $0.chromium && (!explicit || chosenSet.contains($0.browser)) }
                .map(\.browser).filter { seen.insert($0).inserted })
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
        let paths = paths, system = system, installed = installedBrowsers
        await step(.hosts) {
            // What to delete is read in this step, not taken from the list
            // the window showed when the person clicked.
            let found = try await Task.detached { try Self.hostStatus(paths, system, installed: installed) }.value
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
        let paths = paths, system = system, installed = installedBrowsers
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
            setManifests(try await Task.detached { try Self.hostStatus(paths, system, installed: installed) }.value, read: read)
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

    // MARK: Chromium extension download & unpack

    /// Stable folder where this app unpacks the Chromium extension so the
    /// browser keeps loading it from one place and updates replace it in place.
    var extensionDirectory: URL { paths.klavHome.appendingPathComponent("extension/chromium") }

    nonisolated static func existingExtensionDirectory(klavHome: URL) -> URL? {
        let dir = klavHome.appendingPathComponent("extension/chromium")
        let manifest = dir.appendingPathComponent("manifest.json")
        return FileManager.default.isReadableFile(atPath: manifest.path) ? dir : nil
    }

    /// Maximum size accepted for the Chromium extension zip (25 MiB).
    nonisolated static let maxExtensionArchiveBytes: Int64 = 25 * 1024 * 1024

    /// Downloads the latest Chromium extension zip from `url`, unpacks it
    /// safely into `extensionDirectory`, and optionally reveals it in Finder.
    func downloadChromiumExtension(from url: URL = BrowserNames.chromiumExtensionDownload, reveal: Bool = true) async {
        await step(.extensionDownload) {
            let destination = extensionDirectory
            let (tempZip, response) = try await URLSession.shared.download(from: url)
            defer { try? FileManager.default.removeItem(at: tempZip) }
            if !url.isFileURL, let scheme = response.url?.scheme?.lowercased(), scheme != "https" {
                throw SetupError.failed(String(localized: "Couldn’t download the extension over an insecure connection."))
            }
            if let http = response as? HTTPURLResponse, !(200..<300).contains(http.statusCode) {
                throw SetupError.failed(String(localized: "Couldn’t download the extension (HTTP \(http.statusCode))."))
            }
            let values = try tempZip.resourceValues(forKeys: [.fileSizeKey])
            if let size = values.fileSize, Int64(size) > Self.maxExtensionArchiveBytes {
                throw SetupError.failed(String(localized: "The downloaded extension archive is larger than expected."))
            }
            try await Task.detached {
                try Self.unpackExtensionZip(tempZip, into: destination)
            }.value
            unpackedExtensionURL = Self.existingExtensionDirectory(klavHome: paths.klavHome)
            if reveal, let folder = unpackedExtensionURL {
                NSWorkspace.shared.activateFileViewerSelecting([folder])
            }
        }
    }

    /// Unpacks a Chromium extension zip into `destination` atomically, after
    /// verifying it contains `manifest.json` and no symbolic links.
    nonisolated static func unpackExtensionZip(_ zip: URL, into destination: URL) throws {
        let fm = FileManager.default
        let parent = destination.deletingLastPathComponent()
        try fm.createDirectory(at: parent, withIntermediateDirectories: true)
        let staging = parent.appendingPathComponent(".chromium-staging-\(UUID().uuidString)")
        try fm.createDirectory(at: staging, withIntermediateDirectories: true)
        defer { try? fm.removeItem(at: staging) }

        let ditto = try runTool(URL(fileURLWithPath: "/usr/bin/ditto"), ["-xk", zip.path, staging.path], environment: [:])
        guard ditto.status == 0 else {
            throw SetupError.failed(ditto.errors.isEmpty ? String(localized: "Couldn’t unpack the extension archive.") : ditto.errors)
        }

        let source: URL
        if fm.fileExists(atPath: staging.appendingPathComponent("manifest.json").path) {
            source = staging
        } else {
            let entries = try fm.contentsOfDirectory(at: staging, includingPropertiesForKeys: [.isDirectoryKey],
                                                     options: [.skipsHiddenFiles])
                .filter { $0.lastPathComponent != "__MACOSX" }
            if entries.count == 1,
               fm.fileExists(atPath: entries[0].appendingPathComponent("manifest.json").path) {
                source = entries[0]
            } else {
                throw SetupError.failed(String(localized: "The downloaded archive didn’t contain a Klav extension."))
            }
        }

        // Reject symbolic links inside the archive before moving it in place.
        if let enumerator = fm.enumerator(at: source, includingPropertiesForKeys: [.isSymbolicLinkKey]) {
            for case let fileURL as URL in enumerator {
                let isLink = (try? fileURL.resourceValues(forKeys: [.isSymbolicLinkKey]).isSymbolicLink) ?? false
                if isLink {
                    throw SetupError.failed(String(localized: "The downloaded extension archive contained an unexpected link."))
                }
            }
        }

        if fm.fileExists(atPath: destination.path) {
            _ = try fm.replaceItemAt(destination, withItemAt: source)
        } else {
            try fm.moveItem(at: source, to: destination)
        }
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
