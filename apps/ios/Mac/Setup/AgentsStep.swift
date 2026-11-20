import SwiftUI

/// The sixth step of «Set up this Mac» (ADR 0033 E2.3): Klav's skill in
/// the folders of the agent clients here, so Claude Code, Codex or Cursor
/// know how to use Klav and how to connect when they first need it. It
/// writes no MCP entry and registers no agent: that is decided when an
/// agent asks, with its reason. The summary comes first
/// (`klav skill install --dry-run`), and it can be skipped.
struct AgentsStep: View {
    @EnvironmentObject private var model: MacModel
    @EnvironmentObject private var installer: Installer
    var inSettings = false

    @State private var rows: [ClientRow] = []
    @State private var copies: [SkillCopy] = []
    /// The chosen skills folders.
    @State private var chosen: Set<String> = []
    @State private var loaded = false
    @State private var summary: SkillReport?
    @State private var installed: SkillReport?
    @State private var busy = false
    @State private var problem: String?

    /// The person installed the skill here or said «Not now».
    static var decided: Bool {
        get { UserDefaults.standard.bool(forKey: "KlavAgentsStepDone") }
        set { UserDefaults.standard.set(newValue, forKey: "KlavAgentsStepDone") }
    }

    var body: some View {
        StepRow(title: "Agents",
                touches: "Installs Klav’s skill in your agent clients’ folders, so their agents know how to use Klav. It writes no MCP settings and registers no agent.",
                done: done,
                problem: problem) {
            if model.info?.loggedIn != true {
                Status(text: String(localized: "Sign in first."), tone: .plain)
            } else if !loaded {
                Status(text: String(localized: "Looking for agent clients…"), tone: .plain)
            } else if candidates.isEmpty {
                Status(text: String(localized: "No agent client with a skills folder on this Mac: Claude Code, Codex or Cursor."), tone: .plain)
                notNow(String(localized: "Continue"))
            } else if let installed {
                ForEach(installed.copies, id: \.path) { step in
                    Status(text: "\(shortPath(step.path)): \(stepWords(step.action))",
                           tone: step.action == "leave" ? .warning : .done)
                }
                Text("Claude will connect by itself the first time it needs to, and you approve it here with Touch ID.")
                    .font(.ui(12.5)).foregroundStyle(Palette.gris)
                    .fixedSize(horizontal: false, vertical: true)
                if !inSettings && model.agentsStepPending {
                    Button("Open Klav") { model.agentsStepPending = false }
                        .buttonStyle(PrimaryButtonStyle(compact: true))
                        .fixedSize()
                }
            } else if let summary {
                review(summary)
            } else {
                choose
            }
        }
        .task(id: model.info?.loggedIn) { await load() }
    }

    private var done: Bool {
        installed != nil || (!candidates.isEmpty && candidates.allSatisfy { copy(in: $0.folder)?.state == "current" })
    }

    /// One skills folder and the clients that read it: Codex, Cursor and
    /// VS Code share `~/.agents/skills` (§2), so it is one box, not three.
    struct Folder: Identifiable {
        let folder: String
        let clients: [ClientRow]
        var id: String { folder }
        var names: String { clients.map(\.name).formatted(.list(type: .and)) }
        var installed: Bool { clients.contains { $0.installed != nil } }
    }

    /// The folders of the clients that have one. Claude Desktop has none (§2).
    private var candidates: [Folder] { Self.folders(rows) }

    /// The skills folders of the clients installed on this Mac, each with
    /// the installed clients that read it: a client that isn't installed
    /// neither adds a folder nor counts in one.
    static func folders(_ rows: [ClientRow]) -> [Folder] {
        var out: [Folder] = []
        for row in rows where row.installed != nil {
            guard let dir = row.skillsDir else { continue }
            if let i = out.firstIndex(where: { $0.folder == dir }) {
                out[i] = Folder(folder: dir, clients: out[i].clients + [row])
            } else {
                out.append(Folder(folder: dir, clients: [row]))
            }
        }
        return out
    }

    private func copy(in folder: String) -> SkillCopy? { copies.first { $0.folder == folder } }

    /// The clients to pass to `klav skill install`: one installed client
    /// per chosen folder.
    private var chosenClients: [String] {
        candidates.filter { chosen.contains($0.folder) }.compactMap { $0.clients.first?.id }
    }

    private var choose: some View {
        VStack(alignment: .leading, spacing: 8) {
            ForEach(candidates) { group in
                if copy(in: group.folder)?.state == "current" {
                    Status(text: String(localized: "\(group.names): the skill is installed"), tone: .done)
                } else {
                    Toggle(isOn: Binding(get: { chosen.contains(group.folder) },
                                         set: { on in if on { chosen.insert(group.folder) } else { chosen.remove(group.folder) } })) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Install Klav’s skill in \(group.names)").font(.ui(13.5)).foregroundStyle(Palette.tinta)
                                .fixedSize(horizontal: false, vertical: true)
                            Text(verbatim: shortPath(group.folder) + "/klav/")
                                .font(.mono(11.5)).foregroundStyle(Palette.gris)
                        }
                    }
                    .toggleStyle(SquareToggleStyle())
                }
            }
            Text("Claude will connect by itself the first time it needs to, and you approve it here with Touch ID.")
                .font(.ui(12.5)).foregroundStyle(Palette.gris)
                .fixedSize(horizontal: false, vertical: true)
                .padding(.top, 2)
            HStack(spacing: 12) {
                Button(busy ? String(localized: "Looking…") : String(localized: "Review and install")) {
                    Task { await look() }
                }
                .buttonStyle(PrimaryButtonStyle(compact: true))
                .fixedSize()
                .disabled(busy || chosen.isEmpty)
                notNow(String(localized: "Not now"))
            }
        }
    }

    /// The summary before writing: each folder and what happens to it.
    private func review(_ report: SkillReport) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("This is what Klav will change:").font(.ui(13, .medium)).foregroundStyle(Palette.tinta)
            VStack(alignment: .leading, spacing: 0) {
                ForEach(Array(report.copies.enumerated()), id: \.offset) { index, step in
                    if index > 0 { Rule() }
                    VStack(alignment: .leading, spacing: 2) {
                        Text(verbatim: shortPath(step.path)).font(.mono(11.5)).foregroundStyle(Palette.tinta)
                            .lineLimit(1).truncationMode(.middle)
                        Text(verbatim: stepWords(step.action) + (step.note.map { " · " + ActivityWords.shown($0, max: 200) } ?? ""))
                            .font(.ui(12)).foregroundStyle(step.action == "leave" ? Palette.rojo : Palette.gris)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    .padding(.horizontal, 10).padding(.vertical, 8)
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
            .overlay(Rectangle().strokeBorder(Palette.linea, lineWidth: 1))
            if report.copies.contains(where: { $0.action == "leave" }) {
                Text("A copy that isn’t Klav’s, or that you edited, is left as it is. Choose what to do with it in Development › Clients.")
                    .font(.ui(12)).foregroundStyle(Palette.gris)
                    .fixedSize(horizontal: false, vertical: true)
            }
            HStack(spacing: 10) {
                Button(busy ? String(localized: "Installing…") : String(localized: "Install")) {
                    Task { await install() }
                }
                .buttonStyle(PrimaryButtonStyle(compact: true))
                .fixedSize()
                .disabled(busy)
                Button("Back") { summary = nil }
                    .buttonStyle(SecondaryButtonStyle(compact: true, block: false))
                    .disabled(busy)
            }
        }
    }

    private func notNow(_ title: String) -> some View {
        Button(title) {
            Self.decided = true
            model.agentsStepPending = false
        }
        .buttonStyle(LinkButtonStyle())
    }

    private func stepWords(_ action: String) -> String {
        switch action {
        case "install": return String(localized: "installs the skill")
        case "replace": return String(localized: "brings the skill up to date")
        case "adopt": return String(localized: "keeps that copy as Klav’s")
        case "keep": return String(localized: "already up to date")
        case "leave": return String(localized: "left as it is")
        default: return action
        }
    }

    // MARK: Running `klav`

    private func load() async {
        guard model.info?.loggedIn == true else { return }
        let tools = ClientTools(installer)
        guard tools.available else { loaded = true; return }
        do {
            let (found, status) = try await Task.detached(priority: .userInitiated) {
                (try tools.clients(), try? tools.skillStatus())
            }.value
            rows = found
            copies = status?.copies ?? []
            // Chosen unless the skill there is already up to date.
            chosen = Set(candidates.filter { copy(in: $0.folder)?.state != "current" }.map(\.folder))
            problem = nil
        } catch {
            problem = describe(error)
        }
        loaded = true
    }

    private func look() async {
        busy = true
        problem = nil
        let tools = ClientTools(installer), clients = chosenClients
        do {
            summary = try await Task.detached(priority: .userInitiated) {
                try tools.installSkill(clients: clients, dryRun: true)
            }.value
        } catch {
            problem = describe(error)
        }
        busy = false
    }

    private func install() async {
        busy = true
        problem = nil
        let tools = ClientTools(installer), clients = chosenClients
        do {
            installed = try await Task.detached(priority: .userInitiated) {
                _ = try tools.checkSignature()
                return try tools.installSkill(clients: clients, dryRun: false)
            }.value
            Self.decided = true
            summary = nil
        } catch {
            problem = describe(error)
        }
        busy = false
    }
}
