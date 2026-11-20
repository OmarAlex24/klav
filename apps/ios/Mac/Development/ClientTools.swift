import Foundation

/// The agent clients and the Klav skill, through the bundle's `klav`
/// (ADR 0033 §1: the logic lives in the CLI, the app only shows it).
/// Every call runs `klav client …` or `klav skill …` with `--json` on this
/// Mac's home and `KLAV_HOME`, as «Set up this Mac» runs `klav extension`.
///
/// The app starts from the Finder with a short `PATH`, so `klav` gets the
/// directories a login shell would have (`InstallPaths.searchPath`): there
/// it finds `claude` and `codex`, whose own CLIs write their entries.
struct ClientTools: Sendable {
    let paths: InstallPaths
    let system: MacSystem
    let signatures: CodeSignatures
    let development: Bool

    @MainActor
    init(_ installer: Installer) {
        paths = installer.paths
        system = installer.system
        signatures = installer.signatures
        development = installer.development
    }

    init(paths: InstallPaths, system: MacSystem,
         signatures: CodeSignatures = LiveSignatures(),
         development: Bool = HelperSignature.developmentBuild) {
        self.paths = paths
        self.system = system
        self.signatures = signatures
        self.development = development
    }

    /// The bundle's `klav` is there and can run.
    var available: Bool { FileManager.default.isExecutableFile(atPath: paths.cli.path) }

    /// T120, checked again right before the app writes a client's settings
    /// or trusts what its `klav` prints (ADR 0033 §3.1, condition 1). A
    /// release build not signed by Klav's team refuses, as «Set up this
    /// Mac» does.
    func checkSignature() throws -> HelperSignature.Verdict {
        let verdict = HelperSignature.check(helpers: paths.helpers, signatures: signatures, development: development)
        if let why = verdict.refusal {
            throw SetupError.failed(String(localized: "Part of this copy of Klav isn’t signed by Klav (\(why)), so it sets nothing up. Download Klav again from klav.dev."))
        }
        return verdict
    }

    var environment: [String: String] {
        let dirs = paths.pathDirectories.map(\.path) + ["/usr/bin", "/bin", "/usr/sbin", "/sbin"]
        var seen = Set<String>()
        return ["HOME": paths.userHome.path,
                "KLAV_HOME": paths.klavHome.path,
                "PATH": dirs.filter { seen.insert($0).inserted }.joined(separator: ":")]
    }

    /// `klav <arguments> --json`, decoded. A failure says what `klav` said.
    func run<T: Decodable>(_ arguments: [String], as type: T.Type = T.self) throws -> T {
        let result = try system.run(paths.cli, arguments + ["--json"], environment: environment)
        guard result.status == 0 else {
            throw SetupError.failed(Self.message(result.errors, status: result.status))
        }
        do {
            return try JSONDecoder().decode(T.self, from: result.output)
        } catch {
            throw SetupError.failed(String(localized: "Klav’s command line answered something this app doesn’t understand. Update Klav."))
        }
    }

    /// `klav`'s last line, without its `klav: ` prefix.
    static func message(_ errors: String, status: Int32) -> String {
        var text = errors.split(separator: "\n").last.map(String.init) ?? ""
        for prefix in ["klav: ", "error: "] where text.hasPrefix(prefix) { text = String(text.dropFirst(prefix.count)) }
        return text.isEmpty ? String(localized: "klav ended with code \(status).") : text
    }

    func clients() throws -> [ClientRow] { try run(["client", "list"], as: ClientList.self).clients }

    func skillStatus() throws -> SkillStatus { try run(["skill", "status"]) }

    /// The skill this `klav` carries, as text (`klav skill show`), for
    /// «See the changes» (§6).
    func bundledSkill() throws -> String {
        let result = try system.run(paths.cli, ["skill", "show"], environment: environment)
        guard result.status == 0 else { throw SetupError.failed(Self.message(result.errors, status: result.status)) }
        return String(decoding: result.output, as: UTF8.self)
    }

    /// The summary before writing (`--dry-run`), or the write itself, bound
    /// to the summary the person saw (`expect`).
    func connect(_ client: String, dryRun: Bool, replace: Bool = false, adopt: Bool = false,
                 noSkill: Bool = false, expect: String? = nil) throws -> ConnectPlan {
        var args = ["client", "connect", client]
        args.append(dryRun ? "--dry-run" : "--yes")
        if replace { args.append("--replace") }
        if adopt { args.append("--adopt") }
        if noSkill { args.append("--no-skill") }
        if let expect, !dryRun { args += ["--expect-sha256", expect] }
        return try run(args)
    }

    func disconnect(_ client: String, dryRun: Bool) throws -> ConnectPlan {
        try run(["client", "disconnect", client, dryRun ? "--dry-run" : "--yes"])
    }

    /// The skill in these clients' folders (the «Agents» step of «Set up
    /// this Mac», E2.3).
    func installSkill(clients: [String], dryRun: Bool) throws -> SkillReport {
        var args = ["skill", "install"]
        for c in clients { args += ["--client", c] }
        if dryRun { args.append("--dry-run") }
        return try run(args)
    }

    /// The copies that are Klav's and unchanged, brought to this `klav`'s
    /// version; edited ones are left as they are (ADR 0033 §6).
    func updateSkill() throws -> SkillReport { try run(["skill", "update"]) }

    /// What the person chose for one copy (§6): bring it up to date, keep
    /// their edits, put Klav's back (theirs is kept next to it), adopt an
    /// identical one, or install it again.
    func skill(_ action: SkillAction, in folder: String) throws -> SkillReport {
        switch action {
        case .update: return try run(["skill", "update", "--dir", folder])
        case .keepMine: return try run(["skill", "update", "--keep-mine", "--dir", folder])
        case .replace: return try run(["skill", "install", "--dir", folder, "--replace"])
        case .adopt: return try run(["skill", "install", "--dir", folder, "--adopt"])
        case .install: return try run(["skill", "install", "--dir", folder])
        }
    }
}

enum SkillAction {
    case update, keepMine, replace, adopt, install
}

// MARK: - What `klav` answers

/// `klav client list --json`.
struct ClientList: Decodable, Sendable {
    let clients: [ClientRow]
}

/// A row of `klav client list --json`.
struct ClientRow: Decodable, Identifiable, Equatable, Sendable {
    let id: String
    let name: String
    /// `unavailable`, `not_installed`, `managed`, `malformed`,
    /// `not_connected`, `connected`, `changed` or `person`.
    let state: String
    let installed: String?
    let config: ClientConfig?
    let method: String?
    let unknownCommand: Bool?
    let agent: ClientAgent?
    let restartRequired: Bool
    let skillsDir: String?
    let note: String?
    /// The client's own command (`claude`, `codex`) as `klav` finds it on
    /// the PATH the app gives it: the one that writes the entry.
    let cli: String?

    enum CodingKeys: String, CodingKey {
        case id, name, state, installed, config, method, agent, note, cli
        case unknownCommand = "unknown_command"
        case restartRequired = "restart_required"
        case skillsDir = "skills_dir"
    }

    /// Klav can write its entry here (installed, not managed, readable).
    var canConnect: Bool { ["not_connected", "person", "changed", "connected"].contains(state) && method != nil }
}

struct ClientConfig: Decodable, Equatable, Sendable {
    let path: String
    let exists: Bool
    let linkTo: String?
    let key: String

    enum CodingKeys: String, CodingKey {
        case path, exists, key
        case linkTo = "link_to"
    }
}

struct ClientAgent: Decodable, Equatable, Sendable {
    let name: String
    let registeredHere: Bool

    enum CodingKeys: String, CodingKey {
        case name
        case registeredHere = "registered_here"
    }
}

/// `klav client connect|disconnect --json`.
struct ConnectPlan: Decodable, Sendable {
    let client: String
    let dryRun: Bool
    let agent: PlanAgent?
    let mcp: PlanMcp?
    let skill: [PlanSkill]
    let warnings: [String]?
    let notes: [String]?
    let next: String?

    enum CodingKeys: String, CodingKey {
        case client, agent, mcp, skill, warnings, notes, next
        case dryRun = "dry_run"
    }
}

struct PlanAgent: Decodable, Sendable {
    let name: String
    let id: String?
    /// `pending`, `active`, or `new` (registered by this command).
    let status: String
    let words: String?
    let registers: Bool
}

struct PlanMcp: Decodable, Sendable {
    /// `add`, `replace`, `keep`, `remove`, `conflict`…
    let action: String
    let owner: String
    let method: String
    let file: String
    let linkTo: String?
    let key: String
    /// Klav's entry alone, before and after: never the rest of the file.
    let before: JSONValue?
    let after: JSONValue?
    let commands: [[String]]?
    let expectSha256: String
    let backup: String?
    let restartRequired: Bool

    enum CodingKeys: String, CodingKey {
        case action, owner, method, file, key, before, after, commands, backup
        case linkTo = "link_to"
        case expectSha256 = "expect_sha256"
        case restartRequired = "restart_required"
    }
}

struct PlanSkill: Decodable, Sendable {
    let path: String
    let action: String
    let state: String?
    let note: String?
}

/// `klav skill status --json`.
struct SkillStatus: Decodable, Sendable {
    struct Bundled: Decodable, Sendable { let version: String }
    let bundled: Bundled
    let copies: [SkillCopy]
}

struct SkillCopy: Decodable, Identifiable, Sendable {
    let path: String
    /// `current`, `older`, `newer`, `edited`, `removed` or `unmanaged`.
    let state: String
    let version: String?
    /// Not Klav's, but identical to a skill Klav published.
    let adoptable: Bool?
    let clients: [String]?
    /// The version over which the person kept their edited copy («Keep
    /// mine», ADR 0033 §6).
    let keptMine: String?
    var id: String { path }

    enum CodingKeys: String, CodingKey {
        case path, state, version, adoptable, clients
        case keptMine = "kept_mine"
    }

    /// Edited, and kept as it is over this `klav`'s skill: no warning and
    /// nothing to choose until the next version.
    func kept(over bundled: String?) -> Bool { state == "edited" && bundled != nil && keptMine == bundled }

    /// The skills folder (`<folder>/klav/SKILL.md`), what `--dir` takes.
    var folder: String {
        URL(fileURLWithPath: path).deletingLastPathComponent().deletingLastPathComponent().path
    }
}

/// `klav skill install|update --json`.
struct SkillReport: Decodable, Sendable {
    struct Step: Decodable, Sendable {
        let path: String
        let action: String
        let state: String?
        let note: String?
    }
    let version: String
    let dryRun: Bool
    let copies: [Step]

    enum CodingKeys: String, CodingKey {
        case version, copies
        case dryRun = "dry_run"
    }
}

/// Any JSON, to show Klav's entry as `klav` printed it.
indirect enum JSONValue: Decodable, Sendable, Equatable {
    case string(String), number(Double), bool(Bool), null
    case array([JSONValue]), object([(String, JSONValue)])

    init(from decoder: Decoder) throws {
        let c = try decoder.singleValueContainer()
        if c.decodeNil() { self = .null; return }
        if let b = try? c.decode(Bool.self) { self = .bool(b); return }
        if let n = try? c.decode(Double.self) { self = .number(n); return }
        if let s = try? c.decode(String.self) { self = .string(s); return }
        if let a = try? c.decode([JSONValue].self) { self = .array(a); return }
        let o = try decoder.container(keyedBy: AnyKey.self)
        self = .object(try o.allKeys.sorted { $0.stringValue < $1.stringValue }.map {
            ($0.stringValue, try o.decode(JSONValue.self, forKey: $0))
        })
    }

    static func == (a: JSONValue, b: JSONValue) -> Bool { a.pretty() == b.pretty() }

    private struct AnyKey: CodingKey {
        let stringValue: String
        init?(stringValue: String) { self.stringValue = stringValue }
        var intValue: Int? { nil }
        init?(intValue: Int) { nil }
    }

    /// Indented, keys in order.
    func pretty(_ indent: String = "") -> String {
        let inner = indent + "  "
        switch self {
        case .string(let s): return "\"\(s.replacingOccurrences(of: "\"", with: "\\\""))\""
        case .number(let n): return n == n.rounded() ? String(Int64(n)) : String(n)
        case .bool(let b): return b ? "true" : "false"
        case .null: return "null"
        case .array(let a):
            if a.allSatisfy({ if case .string = $0 { return true }; return false }) {
                return "[" + a.map { $0.pretty() }.joined(separator: ", ") + "]"
            }
            return "[\n" + a.map { inner + $0.pretty(inner) }.joined(separator: ",\n") + "\n\(indent)]"
        case .object(let o):
            if o.isEmpty { return "{}" }
            return "{\n" + o.map { "\(inner)\"\($0.0)\": \($0.1.pretty(inner))" }.joined(separator: ",\n") + "\n\(indent)}"
        }
    }
}

extension ClientRow {
    /// The state in words, and whether it is a warning (red, §4).
    var stateText: (String, Bool) {
        switch state {
        case "connected": return (String(localized: "Connected"), unknownCommand == true)
        case "not_connected": return (String(localized: "Not connected"), false)
        case "not_installed": return (String(localized: "Not installed"), false)
        case "unavailable": return (String(localized: "Not on this Mac"), false)
        case "managed": return (String(localized: "Your organization manages this client’s MCP servers"), false)
        case "malformed": return (String(localized: "Its settings file can’t be read"), true)
        case "changed": return (String(localized: "Klav’s entry was changed outside Klav"), true)
        case "person": return (String(localized: "Has a klav entry Klav didn’t write"), false)
        default: return (state, false)
        }
    }
}

extension SkillCopy {
    var stateText: (String, Bool) { stateText(bundled: nil) }

    /// The state in words, and whether it is a warning (red, §6). A copy
    /// kept over `bundled` is not.
    func stateText(bundled: String?) -> (String, Bool) {
        if kept(over: bundled) { return (String(localized: "Kept as you edited it"), false) }
        switch state {
        case "current": return (String(localized: "Up to date"), false)
        case "older": return (String(localized: "Older"), false)
        case "newer": return (String(localized: "Newer than this Klav"), false)
        case "edited": return (String(localized: "Edited by you"), true)
        case "removed": return (String(localized: "Removed"), false)
        case "unmanaged": return (String(localized: "Not installed by Klav"), false)
        default: return (state, false)
        }
    }
}

/// The client an agent is for, when its name is a client's (§3.1).
enum AgentClients {
    static let names = ["claude-code": "Claude Code", "claude-desktop": "Claude Desktop", "codex": "Codex",
                        "cursor": "Cursor", "vscode": "VS Code"]

    static func client(of agentName: String) -> String? { names[agentName] }
}
