import SwiftUI

/// Development › Clients (ADR 0033 E1, ⌘6): one row per agent client with
/// Klav's MCP entry and its skill, and below, the Klav skill with every
/// copy. Everything comes from the bundle's `klav client` and `klav skill`
/// (§1); writing always shows the summary first (§3.5).
struct ClientsPane: View {
    @EnvironmentObject private var model: MacModel
    @EnvironmentObject private var installer: Installer
    @State private var rows: [ClientRow] = []
    @State private var skill: SkillStatus?
    @State private var loaded = false
    @State private var problem: String?
    @State private var sheet: ClientSheet?
    @State private var skillBusy: String?
    /// The copy of the skill whose changes are shown (§6).
    @State private var diffing: SkillCopy?
    #if DEBUG
    @State private var snapped = false
    #endif

    var body: some View {
        VStack(spacing: 0) {
            PaneHeader(title: "Clients", detail: loaded ? detail : nil)
            ScrollView {
                VStack(alignment: .leading, spacing: 0) {
                    intro
                    // What changed outside Klav (§4, §6): first, in red.
                    if !model.shownWarnings.isEmpty {
                        ClientWarningsView()
                            .padding(.horizontal, -14)
                            .padding(.top, 14)
                    }
                    if let problem { Notice(text: problem).padding(.top, 16) }
                    if !rows.isEmpty {
                        SectionLabel("Agent clients on this Mac").padding(.top, 26).padding(.bottom, 10)
                        FieldBlock {
                            ForEach(Array(rows.enumerated()), id: \.element.id) { index, row in
                                if index > 0 { Rule() }
                                ClientRowView(row: row, copy: copy(for: row), bundled: skill?.bundled.version) { connecting in
                                    sheet = ClientSheet(row: row, connecting: connecting)
                                }
                            }
                        }
                    }
                    if let skill { skillBlock(skill) }
                }
                .frame(maxWidth: 700, alignment: .leading)
                .padding(.horizontal, 28)
                .padding(.vertical, 24)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        .sheet(item: $sheet) { which in
            ConnectSheet(row: which.row, connecting: which.connecting, tools: ClientTools(installer)) {
                Task { await load() }
            }
            .environmentObject(model)
            .frame(width: 540, height: 640)
        }
        .sheet(item: $diffing) { copy in
            SkillDiffSheet(copy: copy, tools: ClientTools(installer)) { action in
                await run(action, copy)
            }
            .frame(width: 620, height: 640)
        }
        .task(id: model.generation) { await load() }
        // «See» from a warning while Clients is already open.
        .onChange(of: "\(model.clientToShow ?? "")|\(model.skillToShow ?? "")") { _, now in
            if now != "|" { Task { await load() } }
        }
    }

    private var detail: String {
        let connected = rows.filter { $0.state == "connected" }.count
        return String(localized: "\(Int64(connected)) connected")
    }

    private var intro: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Klav’s MCP entry tells a client how to start klav mcp, and the skill tells its agent how to use Klav. Neither gives access: an agent can use an item only after you approve it, with the projects you choose.")
                .font(.ui(13)).foregroundStyle(Palette.gris)
                .fixedSize(horizontal: false, vertical: true)
            HStack(spacing: 6) {
                Text("To stop every agent at once:").font(.ui(13)).foregroundStyle(Palette.gris)
                Button("Pause agents") { model.section = .agents }
                    .buttonStyle(.plain)
                    .font(.ui(13, .medium))
                    .foregroundStyle(Palette.cobalto)
            }
        }
    }

    /// The copy of the skill in a client's folder.
    private func copy(for row: ClientRow) -> SkillCopy? {
        guard let dir = row.skillsDir else { return nil }
        let wanted = URL(fileURLWithPath: dir).standardizedFileURL.path
        return skill?.copies.first { URL(fileURLWithPath: $0.folder).standardizedFileURL.path == wanted }
    }

    // MARK: The skill (§6)

    private func skillBlock(_ status: SkillStatus) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            SectionLabel("Klav skill").padding(.top, 30).padding(.bottom, 10)
            Text("This Klav carries version \(status.bundled.version). Klav keeps its own copies up to date when the app starts; a copy you edited is left as it is until you choose.")
                .font(.ui(13)).foregroundStyle(Palette.gris)
                .fixedSize(horizontal: false, vertical: true)
                .padding(.bottom, 12)
            if status.copies.isEmpty {
                Text("No copy yet: connecting a client installs it in its folder.")
                    .font(.ui(13)).foregroundStyle(Palette.gris)
            } else {
                FieldBlock {
                    ForEach(Array(status.copies.enumerated()), id: \.element.id) { index, copy in
                        if index > 0 { Rule() }
                        skillRow(copy, bundled: status.bundled.version)
                    }
                }
            }
        }
    }

    private func skillRow(_ copy: SkillCopy, bundled: String) -> some View {
        let (state, warning) = copy.stateText(bundled: bundled)
        return HStack(alignment: .firstTextBaseline, spacing: 12) {
            VStack(alignment: .leading, spacing: 3) {
                Text(verbatim: shortPath(copy.path))
                    .font(.mono(12)).foregroundStyle(Palette.tinta)
                    .lineLimit(1).truncationMode(.middle)
                    .textSelection(.enabled)
                Text(verbatim: copyDetail(copy))
                    .font(.ui(12)).foregroundStyle(Palette.gris)
            }
            Spacer(minLength: 12)
            VStack(alignment: .trailing, spacing: 6) {
                Text(verbatim: state).font(.ui(12, .medium))
                    .foregroundStyle(warning ? Palette.rojo : copy.state == "current" ? Palette.cobalto : Palette.gris)
                HStack(spacing: 6) {
                    if skillBusy == copy.path {
                        Text("Working…").font(.ui(11)).foregroundStyle(Palette.gris)
                    } else {
                        if copy.state == "edited" && !copy.kept(over: bundled) {
                            SmallAction(title: "See the changes") { diffing = copy }
                        }
                        ForEach(Array(actions(for: copy, bundled: bundled).enumerated()), id: \.offset) { _, pair in
                            SmallAction(title: pair.1) { Task { await run(pair.0, copy) } }
                        }
                    }
                }
            }
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 11)
    }

    private func copyDetail(_ copy: SkillCopy) -> String {
        let names = (copy.clients ?? []).compactMap { id in rows.first { $0.id == id }?.name }
        let version = copy.version.map { String(localized: "Version \($0)") }
        return ([version] + [names.isEmpty ? nil : names.joined(separator: ", ")]).compactMap { $0 }.joined(separator: " · ")
    }

    private func actions(for copy: SkillCopy, bundled: String) -> [(SkillAction, LocalizedStringKey)] {
        // Kept as the person edited it: nothing to choose until the next
        // version (§6, «Keep mine»).
        if copy.kept(over: bundled) { return [] }
        switch copy.state {
        case "older": return [(.update, "Update")]
        case "edited": return [(.keepMine, "Keep mine"), (.replace, "Use Klav’s (keep a copy)")]
        case "unmanaged":
            return copy.adoptable == true ? [(.adopt, "Adopt it"), (.replace, "Use Klav’s (keep a copy)")]
                                          : [(.replace, "Use Klav’s (keep a copy)")]
        case "removed": return [(.install, "Install again")]
        default: return []
        }
    }

    private func run(_ action: SkillAction, _ copy: SkillCopy) async {
        skillBusy = copy.path
        let tools = ClientTools(installer)
        let folder = copy.folder
        do {
            _ = try await Task.detached(priority: .userInitiated) {
                _ = try tools.checkSignature()
                return try tools.skill(action, in: folder)
            }.value
            await load()
        } catch {
            problem = describe(error)
        }
        skillBusy = nil
    }

    private func load() async {
        let tools = ClientTools(installer)
        guard tools.available else {
            problem = String(localized: "This app’s klav isn’t there. Open «Set up this Mac» to put it back.")
            loaded = true
            return
        }
        do {
            let (clients, status) = try await Task.detached(priority: .userInitiated) {
                (try tools.clients(), try? tools.skillStatus())
            }.value
            rows = clients
            skill = status
            problem = nil
            model.setClientWarnings(clients: clients, skill: status)
            // «See» from a warning: the client's summary, or the changes.
            if let id = model.clientToShow {
                model.clientToShow = nil
                if let row = clients.first(where: { $0.id == id }) { sheet = ClientSheet(row: row, connecting: true) }
            }
            if let path = model.skillToShow {
                model.skillToShow = nil
                diffing = status?.copies.first { $0.path == path }
            }
            #if DEBUG
            if !snapped, let id = Snapshot.connectSheet, let row = clients.first(where: { $0.id == id }) {
                snapped = true
                sheet = ClientSheet(row: row, connecting: true)
            }
            #endif
        } catch {
            problem = describe(error)
        }
        loaded = true
    }
}

/// `klav`'s notes start in lower case, as its messages: a capital here.
func sentenceCase(_ text: String) -> String { text.prefix(1).uppercased() + text.dropFirst() }

/// `~/…` for a path in the home.
func shortPath(_ path: String) -> String {
    let home = ProcessInfo.processInfo.environment["KLAV_BROWSER_HOME"] ?? NSHomeDirectory()
    return path.hasPrefix(home + "/") ? "~" + path.dropFirst(home.count) : path
}

private struct ClientSheet: Identifiable {
    let row: ClientRow
    let connecting: Bool
    var id: String { row.id + (connecting ? "+" : "-") }
}

private struct ClientRowView: View {
    @EnvironmentObject private var model: MacModel
    let row: ClientRow
    let copy: SkillCopy?
    /// The version of the skill this `klav` carries.
    let bundled: String?
    let open: (_ connecting: Bool) -> Void

    var body: some View {
        let (state, warning) = row.stateText
        HStack(alignment: .top, spacing: 14) {
            VStack(alignment: .leading, spacing: 4) {
                Text(verbatim: row.name).font(.ui(14, .medium)).foregroundStyle(Palette.tinta)
                Text(verbatim: state).font(.ui(12.5, warning ? .medium : .regular))
                    .foregroundStyle(warning ? Palette.rojo : row.state == "connected" ? Palette.cobalto : Palette.gris)
                    .fixedSize(horizontal: false, vertical: true)
                if let config = row.config, row.state != "unavailable", row.state != "not_installed" {
                    Text(verbatim: shortPath(config.path) + (config.linkTo.map { " → " + shortPath($0) } ?? ""))
                        .font(.mono(11.5)).foregroundStyle(Palette.gris)
                        .lineLimit(1).truncationMode(.middle)
                        .textSelection(.enabled)
                }
                if let agent = row.agent, agent.registeredHere {
                    HStack(spacing: 4) {
                        Text("Agent:").font(.ui(12)).foregroundStyle(Palette.gris)
                        Button(agent.name) { model.section = .agents }
                            .buttonStyle(.plain)
                            .font(.ui(12, .medium)).foregroundStyle(Palette.cobalto)
                    }
                }
                if let dir = row.skillsDir {
                    Text(verbatim: skillLine(dir))
                        .font(.ui(12)).foregroundStyle(copy?.stateText(bundled: bundled).1 == true ? Palette.rojo : Palette.gris)
                        .fixedSize(horizontal: false, vertical: true)
                }
                if row.restartRequired && row.state == "connected" {
                    Text("Restart \(row.name) to load it.").font(.ui(12)).foregroundStyle(Palette.gris)
                }
                if let note = row.note, row.state != "unavailable" {
                    Text(verbatim: sentenceCase(ActivityWords.shown(note, max: 220)))
                        .font(.ui(12)).foregroundStyle(Palette.gris)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            Spacer(minLength: 12)
            if row.canConnect {
                Toggle(isOn: Binding(get: { row.state == "connected" }, set: { open($0) })) {
                    Text("Klav’s MCP").font(.ui(12.5)).foregroundStyle(Palette.tinta)
                }
                .toggleStyle(SquareToggleStyle())
                .fixedSize()
                .help(Text("Connects or disconnects the client. It isn’t a safety switch: to stop agents, pause them."))
            }
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 12)
        .opacity(row.state == "unavailable" || row.state == "not_installed" ? 0.6 : 1)
    }

    private func skillLine(_ dir: String) -> String {
        let place = shortPath(dir) + "/klav"
        guard let copy else { return String(localized: "Skill: not in \(place)") }
        return String(localized: "Skill in \(place): \(copy.stateText(bundled: bundled).0)")
    }
}

/// «This is what Klav will change» (ADR 0033 §3.5): `klav client connect
/// --dry-run` first, then the same command with `--yes`, bound to the file
/// the person saw (`--expect-sha256`). It shows Klav's entry alone, never
/// the rest of the client's settings.
private struct ConnectSheet: View {
    @EnvironmentObject private var model: MacModel
    @Environment(\.dismiss) private var dismiss
    let row: ClientRow
    let connecting: Bool
    let tools: ClientTools
    let done: () -> Void

    @State private var plan: ConnectPlan?
    @State private var problem: String?
    @State private var busy = false
    @State private var replace = false
    /// The helpers' signature (T120) when the summary was made: only
    /// Klav's team's lets this Mac compare the words by itself (§3.1).
    @State private var verdict: HelperSignature.Verdict?

    var body: some View {
        VStack(spacing: 0) {
            ScrollView {
                VStack(alignment: .leading, spacing: 0) {
                    HStack {
                        Text(connecting ? "Connect \(row.name)" : "Disconnect \(row.name)")
                            .font(.ui(22, .semibold)).foregroundStyle(Palette.tinta)
                        Spacer()
                        Button("Cancel") { dismiss() }
                            .buttonStyle(SecondaryButtonStyle(compact: true))
                            .fixedSize()
                    }
                    Text("This is what Klav will change. Nothing is written until you confirm.")
                        .font(.ui(13.5)).foregroundStyle(Palette.gris)
                        .padding(.top, 6)
                    if let plan { summary(plan) } else if problem == nil {
                        Text("Looking…").font(.ui(13)).foregroundStyle(Palette.gris).padding(.top, 24)
                    }
                    if let problem { Notice(text: problem).padding(.top, 18) }
                }
                .padding(22)
            }
            footer
        }
        .background(Palette.papel)
        .task(id: replace) { await look() }
    }

    private var footer: some View {
        HStack(spacing: 10) {
            Spacer()
            Button(busy ? String(localized: "Writing…") : connecting ? String(localized: "Connect") : String(localized: "Disconnect")) {
                Task { await write() }
            }
            .buttonStyle(PrimaryButtonStyle(compact: true))
            .fixedSize()
            .disabled(busy || plan == nil || conflict)
        }
        .padding(.horizontal, 22)
        .padding(.vertical, 14)
        .overlay(alignment: .top) { Rule() }
        .background(Palette.papel)
    }

    private var conflict: Bool { plan?.mcp?.action == "conflict" }

    @ViewBuilder
    private func summary(_ plan: ConnectPlan) -> some View {
        if let mcp = plan.mcp { mcpBlock(mcp) }
        if connecting, let agent = plan.agent { agentBlock(agent) }
        if !plan.skill.isEmpty {
            FieldLabel("The skill").padding(.top, 22).padding(.bottom, 8)
            FieldBlock {
                ForEach(Array(plan.skill.enumerated()), id: \.offset) { index, step in
                    if index > 0 { Rule() }
                    VStack(alignment: .leading, spacing: 3) {
                        Text(verbatim: shortPath(step.path)).font(.mono(11.5)).foregroundStyle(Palette.tinta)
                            .lineLimit(1).truncationMode(.middle)
                        Text(verbatim: skillStep(step)).font(.ui(12.5)).foregroundStyle(Palette.gris)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.horizontal, 12).padding(.vertical, 10)
                }
            }
        }
        ForEach(plan.warnings ?? [], id: \.self) { Notice(text: sentenceCase(ActivityWords.shown($0, max: 300))).padding(.top, 12) }
        ForEach(plan.notes ?? [], id: \.self) { Notice(text: sentenceCase(ActivityWords.shown($0, max: 300)), tone: .info).padding(.top, 12) }
        if !connecting {
            Text("The agent keeps its access: pause or revoke it for that.")
                .font(.ui(12.5)).foregroundStyle(Palette.gris).padding(.top, 14)
        }
    }

    private func mcpBlock(_ mcp: PlanMcp) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            FieldLabel("Its MCP settings").padding(.top, 22).padding(.bottom, 8)
            VStack(alignment: .leading, spacing: 10) {
                Text(verbatim: actionWords(mcp)).font(.ui(14, .medium)).foregroundStyle(Palette.tinta)
                    .fixedSize(horizontal: false, vertical: true)
                Text(verbatim: shortPath(mcp.file) + (mcp.linkTo.map { " → " + shortPath($0) } ?? ""))
                    .font(.mono(11.5)).foregroundStyle(Palette.gris)
                    .textSelection(.enabled)
                if let commands = mcp.commands, !commands.isEmpty {
                    Text("Through \(row.name)’s own command:").font(.ui(12.5)).foregroundStyle(Palette.gris)
                    code(commands.map(shellLine).joined(separator: "\n"))
                    // Which one: the app's PATH is not the terminal's.
                    if let cli = row.cli {
                        Text("It runs \(shortPath(cli)), the first one on the PATH this app gives klav. If your terminal finds another one first, connect from there.")
                            .font(.ui(12)).foregroundStyle(Palette.gris)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
                if ["claude-code", "codex"].contains(row.id) {
                    Text("This app doesn’t see CODEX_HOME or CLAUDE_CONFIG_DIR from your shell: it uses the settings in this file.")
                        .font(.ui(12)).foregroundStyle(Palette.gris)
                        .fixedSize(horizontal: false, vertical: true)
                }
                if let before = mcp.before, mcp.action != "add" {
                    FieldLabel(mcp.action == "keep" || mcp.action == "adopt" ? "Klav’s entry" : "Now")
                    code("\"\(mcp.key)\": " + before.pretty())
                }
                if let after = mcp.after, mcp.action == "add" || mcp.action == "replace" {
                    FieldLabel(mcp.before == nil ? "Klav’s entry" : "After")
                    code("\"\(mcp.key)\": " + after.pretty())
                }
                Text("Only Klav’s entry is shown; the rest of the file stays as it is.")
                    .font(.ui(12)).foregroundStyle(Palette.gris)
                if let backup = mcp.backup {
                    Text("A copy of the file goes to \(shortPath(backup)) first.")
                        .font(.ui(12)).foregroundStyle(Palette.gris)
                }
                if mcp.restartRequired {
                    Text("Restart \(row.name) afterwards to load it.").font(.ui(12)).foregroundStyle(Palette.gris)
                }
                if mcp.action == "conflict" { conflictBlock(mcp) }
            }
            .padding(14)
            .overlay(Rectangle().strokeBorder(Palette.linea, lineWidth: 1))
            .crossCorners()
        }
    }

    /// Klav's entry changed since Klav wrote it: the person can put it
    /// back here. An entry Klav did not write is theirs: only a terminal
    /// replaces or adopts it, where `klav` asks them (§3.4).
    @ViewBuilder
    private func conflictBlock(_ mcp: PlanMcp) -> some View {
        if mcp.owner == "changed" {
            Notice(text: String(localized: "Klav’s entry was changed outside Klav. Put Klav’s back? A copy of the file is kept."))
            Button("Put Klav’s back") { replace = true }
                .buttonStyle(SecondaryButtonStyle(compact: true))
                .fixedSize()
        } else {
            Notice(text: String(localized: "There’s already a klav entry that Klav didn’t write. Only you can replace it or keep it, in Terminal, where klav asks you:"))
            code("klav client connect \(row.id) --replace\nklav client connect \(row.id) --adopt")
        }
    }

    private func agentBlock(_ agent: PlanAgent) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            FieldLabel("The agent").padding(.top, 22)
            Text(verbatim: agentWords(agent))
                .font(.ui(13.5)).foregroundStyle(Palette.tinta)
                .fixedSize(horizontal: false, vertical: true)
            if agent.registers {
                Text("No project comes chosen: you pick what it gets on the card, and approve with Touch ID.")
                    .font(.ui(12.5)).foregroundStyle(Palette.gris)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    private func code(_ text: String) -> some View {
        Text(verbatim: text)
            .font(.mono(12)).foregroundStyle(Palette.tinta)
            .textSelection(.enabled)
            .fixedSize(horizontal: false, vertical: true)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(10)
            .background(Palette.niebla)
    }

    private func shellLine(_ words: [String]) -> String {
        words.map { w in
            w.allSatisfy { $0.isLetter || $0.isNumber || "-_./=:@".contains($0) } ? w : "'" + w.replacingOccurrences(of: "'", with: "'\\''") + "'"
        }.joined(separator: " ")
    }

    private func actionWords(_ mcp: PlanMcp) -> String {
        switch mcp.action {
        case "add": return String(localized: "Adds Klav’s entry “\(mcp.key)”")
        case "replace": return String(localized: "Replaces the entry “\(mcp.key)” with Klav’s")
        case "remove": return String(localized: "Removes Klav’s entry “\(mcp.key)”")
        case "adopt": return String(localized: "Keeps the entry “\(mcp.key)” as Klav’s, as it is")
        case "keep": return String(localized: "Klav’s entry is already there: nothing to change")
        case "conflict": return String(localized: "There’s an entry “\(mcp.key)” Klav didn’t write")
        default: return mcp.action
        }
    }

    private func agentWords(_ agent: PlanAgent) -> String {
        ConnectWords.agent(agent, verdict: verdict)
    }

    private func skillStep(_ step: PlanSkill) -> String {
        let text: String
        switch step.action {
        case "install": text = String(localized: "Installs the skill")
        case "replace": text = String(localized: "Brings the skill up to date")
        case "remove": text = String(localized: "Removes Klav’s skill")
        case "keep": text = String(localized: "The skill is already there")
        case "leave": text = String(localized: "Leaves this copy as it is: it isn’t Klav’s, or you edited it")
        default: text = step.action
        }
        return step.note.map { text + " · " + ActivityWords.shown($0, max: 200) } ?? text
    }

    // MARK: Running `klav`

    private func look() async {
        problem = nil
        let tools = tools, id = row.id, connecting = connecting, replace = replace
        do {
            let (checked, looked) = try await Task.detached(priority: .userInitiated) {
                let verdict = HelperSignature.check(helpers: tools.paths.helpers, signatures: tools.signatures,
                                                    development: tools.development)
                let plan = connecting ? try tools.connect(id, dryRun: true, replace: replace)
                                      : try tools.disconnect(id, dryRun: true)
                return (verdict, plan)
            }.value
            verdict = checked
            plan = looked
        } catch {
            plan = nil
            problem = describe(error)
        }
    }

    private func write() async {
        guard let plan else { return }
        busy = true
        problem = nil
        let tools = tools, id = row.id, connecting = connecting, replace = replace
        let expect = plan.mcp?.expectSha256
        do {
            let (verdict, result) = try await Task.detached(priority: .userInitiated) {
                // T120 right before `klav` runs (§3.1, condition 1).
                let verdict = try tools.checkSignature()
                return (verdict, connecting ? try tools.connect(id, dryRun: false, replace: replace, expect: expect)
                                            : try tools.disconnect(id, dryRun: false))
            }.value
            finish(result, verdict: verdict)
        } catch {
            problem = describe(error)
            busy = false
        }
    }

    private func finish(_ result: ConnectPlan, verdict: HelperSignature.Verdict) {
        done()
        dismiss()
        guard connecting else {
            model.show(Toast(text: String(localized: "\(row.name) is disconnected.")))
            return
        }
        // P5: the words this app's own `klav` printed for the agent it just
        // registered, kept only with Klav's signature (§3.1).
        model.connected(result, client: row.name, verdict: verdict)
    }
}

/// What the summary of «Connect» says about the agent (§3.1, E2.2). The
/// words compare by themselves only for an agent this command registers
/// (`registers`) with helpers signed by Klav's team; an agent that already
/// exists here, maybe waiting since an agent connected by itself, is
/// compared by eye.
enum ConnectWords {
    static func agent(_ agent: PlanAgent, verdict: HelperSignature.Verdict?) -> String {
        switch agent.status {
        case "active": return String(localized: "Uses the agent “\(agent.name)”, which already has access.")
        case "pending": return String(localized: "The agent “\(agent.name)” is already waiting for your approval, in Requests. Compare its words by eye with the ones klav printed where it was registered.")
        case "registered" where !agent.registers:
            return String(localized: "Uses the agent “\(agent.name)” that this Mac already has. If it’s still waiting for your approval, compare its words by eye in Requests with the ones klav printed where it was registered: this Mac didn’t register it now.")
        default:
            return agent.registers && verdict == .trusted
                ? String(localized: "Registers the agent “\(agent.name)”. It gets nothing until you approve it in Requests: this Mac compares the words for you.")
                : String(localized: "Registers the agent “\(agent.name)”. It gets nothing until you approve it in Requests, where you compare its words by eye: this copy of Klav isn’t signed by Klav’s team, so it doesn’t compare them for you.")
        }
    }
}

/// «See the changes» (ADR 0033 §6): the person's copy of the skill line by
/// line against the one this `klav` carries. The skill has no secrets, so
/// it is shown whole. «Use Klav’s» keeps theirs next to it; «Keep mine»
/// does not ask again until the next version.
private struct SkillDiffSheet: View {
    @Environment(\.dismiss) private var dismiss
    let copy: SkillCopy
    let tools: ClientTools
    let act: (SkillAction) async -> Void

    @State private var lines: [(LineDiff.Kind, String)]?
    @State private var problem: String?

    var body: some View {
        VStack(spacing: 0) {
            VStack(alignment: .leading, spacing: 6) {
                HStack {
                    Text("Changes in your skill").font(.ui(20, .semibold)).foregroundStyle(Palette.tinta)
                    Spacer()
                    Button("Close") { dismiss() }
                        .buttonStyle(SecondaryButtonStyle(compact: true))
                        .fixedSize()
                }
                Text(verbatim: shortPath(copy.path)).font(.mono(11.5)).foregroundStyle(Palette.gris)
                Text("− only in yours · + in the one this Klav carries")
                    .font(.ui(12)).foregroundStyle(Palette.gris)
            }
            .padding(20)
            Rule()
            ScrollView {
                if let lines {
                    VStack(alignment: .leading, spacing: 0) {
                        ForEach(Array(lines.enumerated()), id: \.offset) { _, line in
                            Text(verbatim: (line.0 == .removed ? "− " : line.0 == .added ? "+ " : "  ") + line.1)
                                .font(.mono(11.5))
                                .foregroundStyle(line.0 == .removed ? Palette.rojo : line.0 == .added ? Palette.cobalto : Palette.gris)
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .textSelection(.enabled)
                        }
                    }
                    .padding(16)
                } else if let problem {
                    Notice(text: problem).padding(16)
                } else {
                    Text("Looking…").font(.ui(13)).foregroundStyle(Palette.gris).padding(16)
                }
            }
            Rule()
            HStack(spacing: 10) {
                Spacer()
                Button("Keep mine") { Task { await act(.keepMine); dismiss() } }
                    .buttonStyle(SecondaryButtonStyle(compact: true))
                    .fixedSize()
                Button("Use Klav’s (keep a copy)") { Task { await act(.replace); dismiss() } }
                    .buttonStyle(PrimaryButtonStyle(compact: true))
                    .fixedSize()
            }
            .padding(.horizontal, 20)
            .padding(.vertical, 14)
        }
        .background(Palette.papel)
        .task { await load() }
    }

    private func load() async {
        let tools = tools, path = copy.path
        do {
            let (mine, klavs) = try await Task.detached(priority: .userInitiated) {
                (try String(contentsOfFile: path, encoding: .utf8), try tools.bundledSkill())
            }.value
            lines = LineDiff.lines(from: mine, to: klavs)
        } catch {
            problem = describe(error)
        }
    }
}
