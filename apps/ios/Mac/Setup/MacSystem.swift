import AppKit
import Darwin
import Foundation
import ServiceManagement

/// Where setting up this Mac reads and writes (ADR 0027 §4). The app uses
/// the real places; the tests point every one of them at a temporary
/// directory, so nothing touches the Mac they run on.
struct InstallPaths {
    /// `Klav.app/Contents/Helpers`: `klav`, `klav-native-host`, and `klavd`,
    /// a link to `klavd.app/Contents/MacOS/klavd` (`HelperSignature`).
    var helpers: URL
    /// Where the CLI's symlink goes (`/usr/local/bin`).
    var linkDirectory: URL
    /// The person's home, where the browsers keep their manifests.
    var userHome: URL
    /// `KLAV_HOME`.
    var klavHome: URL
    /// Directories searched for another `klav` (the login shell's PATH is
    /// not the app's).
    var pathDirectories: [URL]

    var cli: URL { helpers.appendingPathComponent("klav") }
    var daemon: URL { helpers.appendingPathComponent("klavd") }
    var nativeHost: URL { helpers.appendingPathComponent("klav-native-host") }
    var link: URL { linkDirectory.appendingPathComponent("klav") }

    /// This app's places. In debug builds, `KLAV_HELPERS_DIR`,
    /// `KLAV_CLI_LINK_DIR` and `KLAV_BROWSER_HOME` move them for a test run.
    static func live() -> InstallPaths {
        let env = ProcessInfo.processInfo.environment
        var helpers = Bundle.main.bundleURL.appendingPathComponent("Contents/Helpers")
        var linkDirectory = URL(fileURLWithPath: "/usr/local/bin")
        var userHome = FileManager.default.homeDirectoryForCurrentUser
        #if DEBUG
        if let dir = env["KLAV_HELPERS_DIR"], !dir.isEmpty { helpers = URL(fileURLWithPath: dir) }
        if let dir = env["KLAV_CLI_LINK_DIR"], !dir.isEmpty { linkDirectory = URL(fileURLWithPath: dir) }
        if let dir = env["KLAV_BROWSER_HOME"], !dir.isEmpty { userHome = URL(fileURLWithPath: dir) }
        #endif
        let klavHome = (try? KlavHome.directory()) ?? userHome.appendingPathComponent("Library/Application Support/klav")
        return InstallPaths(helpers: helpers, linkDirectory: linkDirectory, userHome: userHome,
                            klavHome: klavHome, pathDirectories: searchPath(home: userHome))
    }

    /// `/etc/paths`, `/etc/paths.d/*` and where `cargo`, `pipx`, Homebrew
    /// and people put programs, in that order.
    static func searchPath(home: URL) -> [URL] {
        var dirs: [String] = []
        let fm = FileManager.default
        if let text = try? String(contentsOfFile: "/etc/paths", encoding: .utf8) {
            dirs += text.split(separator: "\n").map(String.init)
        }
        if let names = try? fm.contentsOfDirectory(atPath: "/etc/paths.d") {
            for name in names.sorted() {
                if let text = try? String(contentsOfFile: "/etc/paths.d/\(name)", encoding: .utf8) {
                    dirs += text.split(separator: "\n").map(String.init)
                }
            }
        }
        dirs += ["/opt/homebrew/bin", "/usr/local/bin"]
        dirs += [".cargo/bin", ".local/bin", "bin"].map { home.appendingPathComponent($0).path }
        var seen = Set<String>()
        return dirs.map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty && seen.insert($0).inserted }
            .map { URL(fileURLWithPath: $0) }
    }
}

/// `klavd`'s LaunchAgent, as `SMAppService` reports it.
enum AgentState: Equatable {
    case notRegistered
    case enabled
    /// Registered, but the person has to allow it in System Settings ›
    /// General › Login Items & Extensions.
    case requiresApproval
    /// The *plist* is not in the bundle (a build without helpers).
    case notFound
}

/// What a program printed and how it ended.
struct ToolResult {
    let status: Int32
    let output: Data
    let errors: String
}

/// Everything setting up the Mac does to the system. The app uses
/// `LiveSystem`; the tests, a fake that never registers a LaunchAgent nor
/// asks for an administrator's password.
protocol MacSystem: Sendable {
    func agentState() -> AgentState
    func registerAgent() throws
    func unregisterAgent() throws
    /// «Open Klav at login»: the app itself as a login item
    /// (`SMAppService.mainApp`), apart from `klavd`'s LaunchAgent. Same
    /// states as the agent's.
    func appLoginState() -> AgentState
    func registerApp() throws
    func unregisterApp() throws
    /// Starts the LaunchAgent's `klavd` again (`launchctl kickstart -k`).
    func restartAgent() throws
    func openLoginItems()
    /// Runs `command` with `/bin/sh` as root, after macOS asks for an
    /// administrator's password. Throws `SetupError.cancelled` when the
    /// person cancels.
    func runAsAdministrator(_ command: String) throws
    func run(_ tool: URL, _ arguments: [String], environment: [String: String]) throws -> ToolResult
    /// The `klav` at each of `candidates` (one per PATH folder): whether it
    /// is there and isn't `appCLI`, and with `contents` which build its file
    /// says it is and where it came from, without running it
    /// (`BuildMarker.Reader`: bounded, one job per path, an unchanged file
    /// isn't read again). A path is missing from the answer when its job
    /// didn't end within the limit (a hung volume). The sample never reads
    /// the contents of the person's own `klav`.
    func probeCLIs(_ candidates: [String], appCLI: String, contents: Bool) -> [String: BuildMarker.Probe]
    /// The executable of a process.
    func executable(of pid: Int32) -> String?
    /// Supported browsers installed as apps on this Mac (CLI names: `ardia`,
    /// `dia`, `chrome`, …), or nil when the system doesn't filter by
    /// installed apps (tests without an explicit list).
    func installedBrowsers() -> Set<String>?
    /// Why nothing may be set up or written on these places, or nil. The
    /// real Mac never refuses; the sample (`SampleSystem`) refuses the
    /// person's real home, `KLAV_HOME` and PATH.
    func refusal(for paths: InstallPaths) -> String?
}

enum SetupError: LocalizedError, Equatable {
    case cancelled
    case failed(String)

    var errorDescription: String? {
        switch self {
        case .cancelled: return String(localized: "Cancelled.")
        case .failed(let message): return message
        }
    }
}

/// The real Mac.
struct LiveSystem: MacSystem {
    static let agentPlist = "dev.klav.klavd.plist"
    static let agentLabel = "dev.klav.klavd"

    private var service: SMAppService { SMAppService.agent(plistName: Self.agentPlist) }

    func agentState() -> AgentState { Self.state(of: service) }

    func registerAgent() throws { try service.register() }
    func unregisterAgent() throws { try service.unregister() }

    func appLoginState() -> AgentState { Self.state(of: .mainApp) }
    func registerApp() throws { try SMAppService.mainApp.register() }
    func unregisterApp() throws { try SMAppService.mainApp.unregister() }

    private static func state(of service: SMAppService) -> AgentState {
        switch service.status {
        case .enabled: return .enabled
        case .requiresApproval: return .requiresApproval
        case .notFound: return .notFound
        case .notRegistered: return .notRegistered
        @unknown default: return .notRegistered
        }
    }

    func restartAgent() throws {
        let target = "gui/\(getuid())/\(Self.agentLabel)"
        let result = try run(URL(fileURLWithPath: "/bin/launchctl"), ["kickstart", "-k", target], environment: [:])
        guard result.status == 0 else { throw SetupError.failed(result.errors) }
    }

    func openLoginItems() { SMAppService.openSystemSettingsLoginItems() }

    func runAsAdministrator(_ command: String) throws {
        let escaped = command.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"")
        let source = "do shell script \"\(escaped)\" with administrator privileges"
        var error: NSDictionary?
        guard let script = NSAppleScript(source: source) else { throw SetupError.failed("AppleScript") }
        script.executeAndReturnError(&error)
        if let error {
            // -128: the person cancelled the password dialog.
            if (error[NSAppleScript.errorNumber] as? Int) == -128 { throw SetupError.cancelled }
            throw SetupError.failed(error[NSAppleScript.errorMessage] as? String ?? "AppleScript")
        }
    }

    func run(_ tool: URL, _ arguments: [String], environment: [String: String]) throws -> ToolResult {
        try runTool(tool, arguments, environment: environment)
    }

    /// One reader for the app's life, so its cache outlives each refresh.
    private static let reader = BuildMarker.Reader()

    func probeCLIs(_ candidates: [String], appCLI: String, contents: Bool) -> [String: BuildMarker.Probe] {
        Self.reader.probe(candidates.map { ($0, contents) }, appCLI: appCLI)
    }

    func executable(of pid: Int32) -> String? { executablePath(of: pid) }

    func installedBrowsers() -> Set<String>? {
        var found = Set<String>()
        for (id, bundleIDs) in BrowserNames.bundleIDs {
            if bundleIDs.contains(where: { NSWorkspace.shared.urlForApplication(withBundleIdentifier: $0) != nil }) {
                found.insert(id)
            }
        }
        return found
    }

    func refusal(for paths: InstallPaths) -> String? { nil }
}

/// Runs a program and waits for it; its output stays in memory (the tools
/// run here never print a secret).
func runTool(_ tool: URL, _ arguments: [String], environment: [String: String]) throws -> ToolResult {
    let process = Process()
    process.executableURL = tool
    process.arguments = arguments
    var env = ProcessInfo.processInfo.environment
    for (key, value) in environment { env[key] = value }
    process.environment = env
    let out = Pipe(), err = Pipe()
    process.standardOutput = out
    process.standardError = err
    process.standardInput = FileHandle.nullDevice
    try process.run()
    let output = out.fileHandleForReading.readDataToEndOfFile()
    let errors = err.fileHandleForReading.readDataToEndOfFile()
    process.waitUntilExit()
    return ToolResult(status: process.terminationStatus, output: output,
                      errors: String(decoding: errors, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines))
}

/// `proc_pidpath`: the executable of a process of this user.
func executablePath(of pid: Int32) -> String? {
    var buffer = [CChar](repeating: 0, count: Int(4 * MAXPATHLEN))
    let length = proc_pidpath(pid, &buffer, UInt32(buffer.count))
    guard length > 0 else { return nil }
    return String(cString: buffer)
}

/// Where this copy of the app runs from (ADR 0027 §4): nothing is set up
/// from a translocated copy or from the disk image, because a link or a
/// LaunchAgent pointing there breaks.
enum Placement: Equatable {
    case applications
    /// Fine, but not in an Applications folder.
    case elsewhere
    /// Gatekeeper runs it from a random read-only path (still in Downloads
    /// or the disk image).
    case translocated
    /// Straight from the mounted DMG.
    case diskImage

    var canInstall: Bool { self == .applications || self == .elsewhere }

    static func of(_ bundle: URL) -> Placement {
        let path = bundle.standardizedFileURL.path
        if path.contains("/AppTranslocation/") { return .translocated }
        if path.hasPrefix("/Volumes/"),
           let values = try? bundle.resourceValues(forKeys: [.volumeIsReadOnlyKey]),
           values.volumeIsReadOnly == true {
            return .diskImage
        }
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        if path.hasPrefix("/Applications/") || path.hasPrefix(home + "/Applications/") { return .applications }
        return .elsewhere
    }
}
