import LocalAuthentication
import SwiftUI

/// Face ID before resuming agents (ADR 0033 P2): biometrics only. Without
/// Face ID, or when the person picks the fallback, the master password,
/// never the iPhone's code, which Klav does not know.
enum ResumePresence {
    enum Outcome: Equatable { case confirmed, cancelled, needsPassword }

    /// What «Resume» asks for now, as `check` decides it: the words say
    /// this, never «Face ID» when it will be the master password.
    enum Ask: Equatable { case faceID, touchID, password }

    static func ask(_ context: LAContext = LAContext()) -> Ask {
        var error: NSError?
        return ask(biometrics: context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error),
                   type: context.biometryType)
    }

    /// No biometrics now (none, not enrolled, locked out): the password.
    static func ask(biometrics: Bool, type: LABiometryType) -> Ask {
        guard biometrics else { return .password }
        return type == .touchID ? .touchID : .faceID
    }

    static func check(_ reason: String) async -> Outcome {
        await withCheckedContinuation { continuation in
            let context = LAContext()
            context.localizedFallbackTitle = String(localized: "Use the master password")
            guard ask(context) != .password else {
                continuation.resume(returning: .needsPassword)
                return
            }
            context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason) { ok, error in
                continuation.resume(returning: ok ? .confirmed : outcome((error as? LAError)?.code))
            }
        }
    }

    /// What the person does to resume, in words.
    static func howTo(_ ask: Ask) -> String {
        switch ask {
        case .faceID: return String(localized: "To resume, use Face ID.")
        case .touchID: return String(localized: "To resume, use Touch ID.")
        case .password: return String(localized: "To resume, enter your master password.")
        }
    }

    /// A failed prompt: the person chose the password, or Face ID can't be
    /// used now; anything else (cancel) resumes nothing.
    static func outcome(_ code: LAError.Code?) -> Outcome {
        switch code {
        case .userFallback?, .biometryNotAvailable?, .biometryNotEnrolled?, .biometryLockout?, .passcodeNotSet?:
            return .needsPassword
        default:
            return .cancelled
        }
    }
}

/// Where Agents leads.
enum AgentsRoute: Hashable {
    case agent(String)
    case activity
}

/// Agents (ADR 0033 §9): «Pause agents» on top, then every agent of the
/// account with its state and its pause, as in the Mac's Development ›
/// Agents. A row opens the agent's timeline; Activity is the whole log.
/// No clients or skill here: no agent client runs on an iPhone.
struct AgentsView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var reviewing: AgentItem?

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                HStack {
                    Title("Agents", size: 22)
                    Spacer()
                    Button("Done") { dismiss() }.buttonStyle(SecondaryButtonStyle(compact: true))
                }
                .padding(.horizontal, 20)
                .frame(minHeight: 64)
                .overlay(alignment: .bottom) { Rule() }
                ScrollView {
                    VStack(alignment: .leading, spacing: 0) {
                        PauseCard()
                        activityLink.padding(.top, 18)
                        Rule()
                        if model.agentList.isEmpty { empty.padding(.top, 28) }
                        group("Waiting for you", waiting)
                        group("With access", active)
                        group("Denied or revoked", others)
                        if !model.agentList.isEmpty {
                            Text("To change what an agent can do, or to revoke it: klav agent approve and klav agent revoke in the terminal.")
                                .font(.ui(13, relativeTo: .footnote)).foregroundStyle(Palette.gris)
                                .fixedSize(horizontal: false, vertical: true)
                                .textSelection(.enabled)
                                .padding(.top, 16)
                        }
                    }
                    .padding(.horizontal, 20)
                    .padding(.top, 20)
                    .padding(.bottom, 40)
                }
                .refreshable {
                    await model.sync(force: true)
                    await model.loadRequests()
                }
            }
            .background(Palette.papel)
            .toolbar(.hidden, for: .navigationBar)
            .navigationDestination(for: AgentsRoute.self) { route in
                switch route {
                case .agent(let id): AgentDetailView(agentId: id)
                case .activity: ActivityView()
                }
            }
        }
        .task { await model.loadRequests() }
        .sheet(item: $reviewing) { agent in
            AgentReviewView<AppModel>(agent: agent).environmentObject(model)
        }
    }

    private var activityLink: some View {
        NavigationLink(value: AgentsRoute.activity) {
            HStack(spacing: 12) {
                IconView(icon: .list).foregroundStyle(Palette.tinta)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Activity").font(.ui(16, .medium)).foregroundStyle(Palette.tinta)
                    Text("Every use by an agent and every decision of yours")
                        .font(.ui(13, relativeTo: .footnote)).foregroundStyle(Palette.gris)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: 8)
                IconView(icon: .back).rotationEffect(.degrees(180)).foregroundStyle(Palette.gris)
                    .accessibilityHidden(true)
            }
            .frame(minHeight: 60)
            .contentShape(Rectangle())
        }
        .buttonStyle(RowButtonStyle())
        .accessibilityIdentifier("agents-activity")
    }

    private var waiting: [DevAgentInfo] { model.agentList.filter { $0.agent.status == "pending" } }
    private var active: [DevAgentInfo] { model.agentList.filter { $0.agent.status == "active" } }
    private var others: [DevAgentInfo] {
        model.agentList.filter { $0.agent.status == "denied" || $0.agent.status == "revoked" }
    }

    @ViewBuilder
    private func group(_ title: LocalizedStringKey, _ list: [DevAgentInfo]) -> some View {
        if !list.isEmpty {
            SectionLabel(title).padding(.top, 28).padding(.bottom, 10)
            FieldBlock {
                ForEach(Array(list.enumerated()), id: \.element.agent.id) { index, item in
                    if index > 0 { Rule() }
                    AgentRow(item: item) { reviewing = item.agent }
                }
            }
        }
    }

    private var empty: some View {
        HStack(alignment: .top, spacing: 16) {
            DitherView(kind: .band, palette: .blue, pixel: 3)
                .frame(width: 32, height: 80)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 6) {
                Text("No agent yet").font(.ui(16, .medium)).foregroundStyle(Palette.tinta)
                Text("When an agent asks to join your account, you compare its words and approve it here with Face ID. In the agent’s terminal: klav agent register --name <name>")
                    .font(.ui(14, relativeTo: .subheadline)).foregroundStyle(Palette.gris)
                    .fixedSize(horizontal: false, vertical: true)
                    .textSelection(.enabled)
            }
        }
    }
}

/// «Pause agents» on top of Agents (ADR 0033 §7.5): the length, then
/// «Pause», which asks nothing; or the pause in effect with «Resume».
struct PauseCard: View {
    @EnvironmentObject private var model: AppModel
    @State private var length: PauseLength = .hour
    @State private var busy = false
    @State private var problem: String?

    var body: some View {
        if let pause = model.everyonePaused {
            PausedCard(pause: pause)
        } else {
            VStack(alignment: .leading, spacing: 8) {
                HStack(spacing: 10) {
                    IconView(icon: .pause).foregroundStyle(Palette.tinta)
                    Text("Pause agents").font(.ui(17, .semibold)).foregroundStyle(Palette.tinta)
                        .accessibilityAddTraits(.isHeader)
                }
                Text(verbatim: String(localized: "Stops every agent of your account at once, everywhere, until the time is up or you resume. Pausing asks nothing.")
                     + " " + ResumePresence.howTo(ResumePresence.ask()))
                    .font(.ui(14, relativeTo: .subheadline)).foregroundStyle(Palette.gris)
                    .fixedSize(horizontal: false, vertical: true)
                // What a pause does not stop (ADR 0033 §7.7).
                Text("It doesn’t take back what an agent already has: a process it started, a file it was given, what it read. For a stolen key, revoke and rotate.")
                    .font(.ui(13, relativeTo: .footnote)).foregroundStyle(Palette.gris)
                    .fixedSize(horizontal: false, vertical: true)
                Flow(spacing: 8) {
                    ForEach(PauseLength.allCases) { option in
                        Chip(text: option.label, on: length == option) { length = option }
                    }
                }
                .padding(.top, 6)
                Button(busy ? String(localized: "Pausing…") : String(localized: "Pause")) {
                    Task { await pause() }
                }
                .buttonStyle(PrimaryButtonStyle())
                .disabled(busy)
                .accessibilityIdentifier("agents-pause")
                .padding(.top, 4)
                if let problem { Notice(text: problem) }
            }
            .padding(16)
            .overlay(Rectangle().strokeBorder(Palette.linea, lineWidth: 1))
            .crossCorners()
        }
    }

    private func pause() async {
        busy = true
        problem = nil
        do { try await model.pauseAgents(minutes: length.minutes) } catch { problem = describe(error) }
        busy = false
    }
}

/// Every agent is paused: the blue band, since when and until when, and
/// «Resume» (Face ID, or the master password). On top of Agents, and over
/// the vault, where it is never hidden.
struct PausedCard: View {
    let pause: PauseInfo
    /// Over the vault: a way to Agents instead of the line on resuming.
    var openAgents: (() -> Void)?
    @State private var problem: String?

    var body: some View {
        HStack(alignment: .top, spacing: 0) {
            DitherView(kind: .band, palette: .blue, pixel: 3)
                .frame(width: 10)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 6) {
                Text(verbatim: PauseWords.title(pause))
                    .font(.ui(17, .semibold)).foregroundStyle(Palette.cobalto)
                    .accessibilityAddTraits(.isHeader)
                // «47 min left» counts down on its own; the model drops the
                // pause once it ends.
                TimelineView(.everyMinute) { _ in
                    Text(verbatim: PauseWords.span(pause))
                        .font(.ui(14, relativeTo: .subheadline)).foregroundStyle(Palette.gris)
                        .fixedSize(horizontal: false, vertical: true)
                }
                if openAgents == nil {
                    Text(verbatim: ResumePresence.howTo(ResumePresence.ask()))
                        .font(.ui(13, relativeTo: .footnote)).foregroundStyle(Palette.gris)
                        .fixedSize(horizontal: false, vertical: true)
                }
                HStack(spacing: 10) {
                    ResumeButton(agentId: nil, problem: $problem)
                    if let openAgents {
                        Button("Agents", action: openAgents)
                            .buttonStyle(SecondaryButtonStyle(compact: true))
                            .fixedSize()
                    }
                }
                .padding(.top, 4)
                if let problem { Notice(text: problem) }
            }
            .padding(16)
            Spacer(minLength: 0)
        }
        .fixedSize(horizontal: false, vertical: true)
        .background(Palette.papel)
        .overlay(Rectangle().strokeBorder(Palette.cobalto, lineWidth: 1))
        .crossCorners()
        .accessibilityElement(children: .contain)
    }
}

/// «Resume»: Face ID, or the master password on an iPhone without it.
struct ResumeButton: View {
    @EnvironmentObject private var model: AppModel
    let agentId: String?
    @Binding var problem: String?
    @State private var busy = false
    @State private var askPassword = false

    var body: some View {
        Button(busy ? model.waitingForPresence : String(localized: "Resume")) {
            Task { await resume() }
        }
        .buttonStyle(PrimaryButtonStyle(compact: true))
        .fixedSize()
        .disabled(busy)
        .accessibilityIdentifier(agentId == nil ? "agents-resume" : "agent-resume")
        .sheet(isPresented: $askPassword) {
            // Also after «Use the master password» or a Face ID lockout:
            // never «this iPhone has no Face ID» when it has.
            ConfirmPasswordSheet(title: agentId == nil ? "Resume every agent" : "Resume the agent",
                                 message: "Enter your master password to let agents use Klav again.",
                                 action: "Resume") { password in
                try await model.resumeAgents(agentId: agentId, password: password)
            }
            .presentationDetents([.height(340)])
        }
    }

    private func resume() async {
        busy = true
        problem = nil
        do {
            if try await model.resumeAgents(agentId: agentId) == .needsPassword { askPassword = true }
        } catch {
            problem = describe(error)
        }
        busy = false
    }
}

/// One agent: its name with the start of its ID, its projects, its last
/// use, its state and its pause.
private struct AgentRow: View {
    @EnvironmentObject private var model: AppModel
    let item: DevAgentInfo
    let review: () -> Void
    @State private var problem: String?

    private var agent: AgentItem { item.agent }
    private var pause: AgentPauseInfo? { Pauses(model.pauses).stopping(item) }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            NavigationLink(value: AgentsRoute.agent(agent.id)) {
                HStack(alignment: .top, spacing: 12) {
                    AgentSummary(item: item)
                    Spacer(minLength: 8)
                    AgentState(item: item, pause: pause)
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(RowButtonStyle())
            if agent.status == "revoked", let text = model.keyChangeText(agent.id) {
                Text(verbatim: text)
                    .font(.ui(13, relativeTo: .footnote)).foregroundStyle(Palette.gris)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if agent.status == "pending" {
                Button("Compare words", action: review)
                    .buttonStyle(PrimaryButtonStyle(compact: true))
            } else if agent.status == "active" {
                AgentPauseActions(agentId: agent.id, name: agent.name, pause: pause, problem: $problem)
            }
            if let problem { Notice(text: problem) }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 12)
    }
}

/// The name, verified role, host/proxy link, the projects and when it was used.
private struct AgentSummary: View {
    let item: DevAgentInfo

    var body: some View {
        VStack(alignment: .leading, spacing: 3) {
            (Text(verbatim: AgentText.line(item.agent.name, max: 40)).font(.ui(16, .medium)).foregroundStyle(Palette.tinta)
                + Text(verbatim: "  " + AgentText.idPrefix(item.agent.id)).font(.mono(12)).foregroundStyle(Palette.gris))
                .fixedSize(horizontal: false, vertical: true)
            Tag(text: ActivityWords.roleBadge(item),
                color: item.role == .proxy ? Palette.cobalto : item.role == .sandboxIssuer ? Palette.tinta : Palette.gris)
            if let origin = ActivityWords.originSummary(item) {
                Text(verbatim: origin)
                    .font(.ui(13, relativeTo: .footnote)).foregroundStyle(Palette.tinta)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if let note = item.agent.note, !note.isEmpty {
                Text("\("“\(AgentText.line(note, max: 120))”") (according to the agent)")
                    .font(.ui(12, relativeTo: .caption)).foregroundStyle(Palette.gris)
                    .lineLimit(1)
            }
            if !item.agent.projects.isEmpty {
                Text(verbatim: item.agent.projects.joined(separator: ", "))
                    .font(.ui(13, relativeTo: .footnote)).foregroundStyle(Palette.gris)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Text(verbatim: ActivityWords.seen(item))
                .font(.ui(13, relativeTo: .footnote)).foregroundStyle(Palette.gris)
        }
    }
}

/// «Paused · Until 11:31», «Has access», «Waiting»…
private struct AgentState: View {
    let item: DevAgentInfo
    let pause: AgentPauseInfo?
    /// Trailing at the end of a row; leading under the agent's name.
    var leading = false

    var body: some View {
        if let pause {
            VStack(alignment: leading ? .leading : .trailing, spacing: 4) {
                Tag(text: String(localized: "Paused"), color: Palette.cobalto)
                Text(verbatim: PauseWords.agentState(pause))
                    .font(.ui(12, relativeTo: .caption)).foregroundStyle(Palette.gris)
                    .multilineTextAlignment(leading ? .leading : .trailing)
            }
        } else {
            Text(verbatim: AgentWords.status(item.agent.status))
                .font(.ui(13, .medium, relativeTo: .footnote))
                .foregroundStyle(item.agent.status == "active" ? Palette.cobalto : Palette.gris)
        }
    }
}

/// «Pause» with its length, or «Resume» for the agent's own pause. While
/// every agent is paused, the agent has nothing to resume alone.
private struct AgentPauseActions: View {
    @EnvironmentObject private var model: AppModel
    let agentId: String
    /// The agent's name, for VoiceOver: every row has its «Pause».
    let name: String
    let pause: AgentPauseInfo?
    @Binding var problem: String?
    @State private var busy = false

    var body: some View {
        if let pause {
            if !pause.everyone { ResumeButton(agentId: agentId, problem: $problem) }
        } else {
            Menu {
                ForEach(PauseLength.allCases) { length in
                    Button(length.label) { Task { await self.pause(length.minutes) } }
                }
            } label: {
                Text(busy ? String(localized: "Pausing…") : String(localized: "Pause"))
                    .font(.ui(14, .medium))
                    .foregroundStyle(Palette.tinta)
                    .padding(.horizontal, 12)
                    .frame(minHeight: 36)
                    .overlay(Rectangle().strokeBorder(Palette.linea, lineWidth: 1))
                    .contentShape(Rectangle())
            }
            .disabled(busy)
            .accessibilityLabel(Text("Pause \(AgentText.line(name, max: 40))"))
            .accessibilityIdentifier("agent-pause")
        }
    }

    private func pause(_ minutes: Int?) async {
        busy = true
        problem = nil
        do { try await model.pauseAgents(agentId: agentId, minutes: minutes) } catch { problem = describe(error) }
        busy = false
    }
}

/// An agent's state in words (its last use: `ActivityWords.seen`).
enum AgentWords {
    static func status(_ status: String) -> String {
        switch status {
        case "active": return String(localized: "Has access")
        case "denied": return String(localized: "Denied")
        case "revoked": return String(localized: "Revoked")
        default: return String(localized: "Waiting")
        }
    }

}

/// One agent (ADR 0033 §8.1, §9): its state and pause, then its timeline,
/// by day: what it did and what you decided about it.
struct AgentDetailView: View {
    @EnvironmentObject private var model: AppModel
    let agentId: String
    @State private var lines: [LogEntryInfo] = []
    @State private var loaded = false
    @State private var problem: String?
    @State private var actionProblem: String?
    @State private var revoking = false

    static let limit: UInt32 = 200

    private var item: DevAgentInfo? { model.agentList.first { $0.agent.id == agentId } }

    var body: some View {
        VStack(spacing: 0) {
            BackBar(title: "Agents")
            ScrollView {
                VStack(alignment: .leading, spacing: 0) {
                    if let item { header(item) }
                    if let problem { Notice(text: problem).padding(.top, 16) }
                    SectionLabel("Activity").padding(.top, 28)
                    if loaded && lines.isEmpty {
                        Text("Nothing in the log yet")
                            .font(.ui(14, relativeTo: .subheadline)).foregroundStyle(Palette.gris)
                            .padding(.top, 12)
                    }
                    ActivityDays(lines: lines)
                    if lines.count >= Int(Self.limit) {
                        // No filters here: the rest are in the terminal.
                        Text("Showing the newest \(Int64(Self.limit)). For the rest: klav log --agent in the terminal.")
                            .font(.ui(13, relativeTo: .footnote)).foregroundStyle(Palette.gris)
                            .fixedSize(horizontal: false, vertical: true)
                            .textSelection(.enabled)
                            .padding(.top, 16)
                    }
                }
                .padding(.horizontal, 20)
                .padding(.top, 20)
                .padding(.bottom, 40)
            }
            .refreshable { await load() }
        }
        .background(Palette.papel)
        .toolbar(.hidden, for: .navigationBar)
        .task(id: "\(agentId)|\(model.generation)|\(model.pauses.count)") { await load() }
        .sheet(isPresented: $revoking) {
            AgentRevokeSheet(agentId: agentId, name: item?.agent.name ?? "")
        }
    }

    private func header(_ item: DevAgentInfo) -> some View {
        let pause = Pauses(model.pauses).stopping(item)
        return VStack(alignment: .leading, spacing: 6) {
            Text(verbatim: AgentText.line(item.agent.name, max: 64))
                .font(.ui(26, .semibold, relativeTo: .title))
                .foregroundStyle(Palette.tinta)
                .fixedSize(horizontal: false, vertical: true)
                .accessibilityAddTraits(.isHeader)
            Text(verbatim: "ID " + AgentText.idPrefix(item.agent.id))
                .font(.mono(12)).foregroundStyle(Palette.gris)
            Tag(text: ActivityWords.roleBadge(item),
                color: item.role == .proxy ? Palette.cobalto : item.role == .sandboxIssuer ? Palette.tinta : Palette.gris)
            if let origin = ActivityWords.originSummary(item) {
                Text(verbatim: origin)
                    .font(.ui(14, relativeTo: .subheadline)).foregroundStyle(Palette.tinta)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if let note = item.agent.note, !note.isEmpty {
                Text("\("“\(AgentText.line(note, max: 200))”") (according to the agent)")
                    .font(.ui(14, relativeTo: .subheadline)).foregroundStyle(Palette.gris)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if !item.agent.projects.isEmpty {
                Text(verbatim: item.agent.projects.joined(separator: ", "))
                    .font(.ui(14, relativeTo: .subheadline)).foregroundStyle(Palette.tinta)
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(.top, 4)
            }
            Text(verbatim: ActivityWords.seen(item))
                .font(.ui(13, relativeTo: .footnote)).foregroundStyle(Palette.gris)
            HStack(alignment: .center, spacing: 10) {
                // A revoked agent's key change says «Revoked» itself.
                if item.agent.status != "revoked" || model.keyChangeText(item.agent.id) == nil {
                    AgentState(item: item, pause: pause, leading: true)
                }
                Spacer(minLength: 8)
                if item.agent.status == "active" {
                    AgentPauseActions(agentId: item.agent.id, name: item.agent.name, pause: pause, problem: $actionProblem)
                }
            }
            .padding(.top, 12)
            if let actionProblem { Notice(text: actionProblem) }
            if item.agent.status == "active" {
                // Paused or not: a pause ends, a revocation doesn't.
                Button("Revoke…") { revoking = true }
                    .buttonStyle(SecondaryButtonStyle(compact: true, danger: true))
                    .fixedSize()
                    .padding(.top, 6)
                    .accessibilityIdentifier("agent-revoke")
            }
            if item.agent.status == "revoked" { KeyChangeBand(agentId: item.agent.id) }
        }
    }

    private func load() async {
        guard let service = model.service else { return }
        var filter = LogFilterInput.all(limit: Self.limit)
        filter.agent = agentId
        let wanted = filter
        do {
            let found = try await service.run { core, _ in try core.auditLog(filter: wanted) }
            if Task.isCancelled { return }
            lines = found
            problem = nil
        } catch KlavError.Locked {
            model.lock()
        } catch {
            problem = describe(error)
        }
        loaded = true
    }
}

/// The bar of a pushed screen: back to where it came from.
struct BackBar: View {
    let title: LocalizedStringKey
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        HStack {
            Button {
                dismiss()
            } label: {
                HStack(spacing: 4) {
                    IconView(icon: .back)
                    Text(title).font(.ui(15))
                }
                .foregroundStyle(Palette.gris)
                .frame(minHeight: 44)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            Spacer()
        }
        .padding(.horizontal, 20)
        .frame(minHeight: 56)
        .overlay(alignment: .bottom) { Rule() }
    }
}
