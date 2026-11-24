import SwiftUI

/// What the request cards need from the app: the iPhone's `AppModel` and
/// the Mac's `MacModel`. Each confirms with its own Face ID or Touch ID.
@MainActor
protocol RequestsModel: ObservableObject {
    /// What the person changed on each pending task card, by task ID.
    var taskEdits: [String: TaskEdits] { get }
    /// "Waiting for Face ID…" or "Waiting for Touch ID…".
    var waitingForPresence: String { get }
    func decide(_ approval: ApprovalItem, approve: Bool, leaseMinutes: UInt32) async throws
    func addToTask(_ approval: ApprovalItem) async throws
    func editTask(_ card: TaskItem, _ change: (inout TaskEdits) -> Void)
    func decideTask(_ card: TaskItem, approve: Bool) async throws
    func endTask(_ card: TaskItem) async throws
    func fulfillSecretRequest(_ card: SecretRequestItem, input: SecretRequestFulfillInput) async throws -> SecretRequestFulfillOutput
    func denySecretRequest(_ card: SecretRequestItem) async throws
    func approve(_ agent: AgentItem, projects: [String], expiresInDays: UInt32?) async throws
    func deny(_ agent: AgentItem) async throws
    /// The projects an agent can be given.
    func agentProjects() async throws -> [ProjectInfo]
    /// The pairing words of an agent this account approved: the grant it
    /// signed ties them to the agent's key, unlike the name, which the
    /// agent chose. Nil for any other agent.
    func pairingWords(ofAgent id: String) -> String?
}

// Task requests (ADR 0021) as the extension's popup tells them: one card
// for a whole job, completed by this device from the vault, and the
// running task with what is left of it and «End task».

/// An agent asks to do something its policy says to ask about.
struct ApprovalCard<Model: RequestsModel>: View {
    @EnvironmentObject private var model: Model
    let approval: ApprovalItem
    var highlighted = false

    @State private var busy = false
    @State private var problem: String?

    var body: some View {
        let target = RequestWords.target(approval.target)
        AgentCard(highlighted: highlighted) {
            AgentMark(text: "\(approval.agent) is waiting for your permission")
                .accessibilityAddTraits(.isHeader)
            AgentKey<Model>(agentId: approval.agentId)
            if let task = approval.task {
                Text("Outside the task “\(task.task)”")
                    .font(.ui(13, .medium, relativeTo: .footnote))
                    .foregroundStyle(Palette.tinta)
                    .fixedSize(horizontal: false, vertical: true)
            }
            sentence(wants(target.title), bold: [target.title])
                .foregroundStyle(Palette.tinta)
                .fixedSize(horizontal: false, vertical: true)
            if let place = target.where {
                Text(place)
                    .font(.ui(13, relativeTo: .footnote))
                    .foregroundStyle(Palette.gris)
            }
            if let domain = approval.domain {
                // The agent names the site; nothing checked it.
                Text("Site: \(domain) (according to the agent)")
                    .font(.ui(13, relativeTo: .footnote))
                    .foregroundStyle(Palette.tinta)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Text("“\(approval.reason)”")
                .font(.ui(13, relativeTo: .footnote))
                .foregroundStyle(Palette.gris)
                .fixedSize(horizontal: false, vertical: true)
            Expires(at: approval.expiresAt)
            if let problem { Notice(text: problem).padding(.top, 4) }
            if let task = approval.task {
                // Outside the task (ADR 0021 §6), in the ADR's order.
                Flow(spacing: 8) {
                    Button("Deny") { decide(approve: false, lease: 0) }
                        .buttonStyle(SecondaryButtonStyle(compact: true))
                    Button(busy ? model.waitingForPresence : String(localized: "Approve once")) { decide(approve: true, lease: 0) }
                        .buttonStyle(PrimaryButtonStyle(compact: true))
                    if task.canAdd {
                        Button("Add to the task", action: add)
                            .buttonStyle(SecondaryButtonStyle(compact: true))
                            .accessibilityHint("Adds it to the task until the task ends, without making it longer")
                    }
                }
                .padding(.top, 6)
            } else {
                Flow(spacing: 8) {
                    Button(busy ? model.waitingForPresence : String(localized: "Approve once")) { decide(approve: true, lease: 0) }
                        .buttonStyle(PrimaryButtonStyle(compact: true))
                    Button("Approve 15 min") { decide(approve: true, lease: 15) }
                        .buttonStyle(SecondaryButtonStyle(compact: true))
                        .accessibilityHint("Lets it repeat this same request without asking you for 15 minutes")
                    Button("Deny") { decide(approve: false, lease: 0) }
                        .buttonStyle(SecondaryButtonStyle(compact: true))
                }
                .padding(.top, 6)
            }
        }
        .disabled(busy)
    }

    /// "Wants to fill GitHub (password)", with the target's name where
    /// `Bold.mark(0)` is. The site the agent names goes on its own line.
    private func wants(_ title: String) -> String {
        RequestWords.wants(approval.permission, Bold.mark(0))
    }

    private func add() {
        busy = true
        problem = nil
        Task {
            do {
                try await model.addToTask(approval)
            } catch {
                problem = describeRequest(error)
            }
            busy = false
        }
    }

    private func decide(approve: Bool, lease: UInt32) {
        busy = true
        problem = nil
        Task {
            do {
                try await model.decide(approval, approve: approve, leaseMinutes: lease)
            } catch {
                problem = describeRequest(error)
            }
            busy = false
        }
    }
}

/// An agent asks to join the account.
struct RegistrationCard<Model: RequestsModel>: View {
    @EnvironmentObject private var model: Model
    let agent: AgentItem
    var highlighted = false
    /// Another agent of the account has this name (ADR 0033 E2.2): said
    /// on the card, so a second registration does not pass as the first.
    var warning: String? = nil
    var review: () -> Void

    @State private var busy = false
    @State private var problem: String?

    var body: some View {
        AgentCard(highlighted: highlighted) {
            AgentMark(text: "New agent")
                .accessibilityAddTraits(.isHeader)
            sentence(String(localized: "\(Bold.mark(0)) wants to join your account"), bold: [agent.name])
                .foregroundStyle(Palette.tinta)
                .fixedSize(horizontal: false, vertical: true)
            // The start of its ID: two agents with one name are told apart (T136).
            Text(verbatim: "ID " + AgentText.idPrefix(agent.id))
                .font(.mono(12))
                .foregroundStyle(Palette.gris)
            if let note = agent.note, !note.isEmpty {
                // The agent wrote it (T136): one line, without controls.
                Text("\("“\(AgentText.line(note, max: 200))”") (according to the agent)")
                    .font(.ui(13, relativeTo: .footnote))
                    .foregroundStyle(Palette.gris)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if let warning { Notice(text: warning).padding(.top, 2) }
            Expires(at: agent.expiresAt)
            if let problem { Notice(text: problem).padding(.top, 4) }
            HStack(spacing: 8) {
                Button("Compare words", action: review)
                    .buttonStyle(PrimaryButtonStyle(compact: true))
                Button {
                    busy = true
                    Task {
                        do { try await model.deny(agent) } catch { problem = describeRequest(error) }
                        busy = false
                    }
                } label: {
                    Text("Deny")
                }
                .buttonStyle(SecondaryButtonStyle(compact: true))
            }
            .padding(.top, 6)
        }
        .disabled(busy)
    }
}

/// When «They match: approve» can be pressed: not while it works, with a
/// project chosen, and never when this Mac launched the registration and
/// the words are not the ones its `klav` printed (ADR 0033 §3.1, P5).
enum AgentApproval {
    static func allowed(busy: Bool, chosen: Int, matched: Bool?) -> Bool {
        !busy && chosen > 0 && matched != false
    }
}

/// Approving an agent, as in the mockup: the six words numbered in a 2 × 3
/// grid (the order matters when comparing them), the projects it gets and
/// for how long (ADR 0018 §6). The policy is the CLI's default.
struct AgentReviewView<Model: RequestsModel>: View {
    @EnvironmentObject private var model: Model
    @Environment(\.dismiss) private var dismiss
    let agent: AgentItem
    /// Another agent of the account has this name (ADR 0033 E2.2).
    var warning: String? = nil
    /// This Mac launched the registration and holds the words its own
    /// `klav` printed (ADR 0033 §3.1, P5): true, they match; false, they
    /// do not, and approving is off. Nil: the person compares by eye.
    var matched: Bool? = nil

    enum Expiry: UInt32, CaseIterable, Identifiable {
        case day = 1, week = 7, month = 30, never = 0
        var id: UInt32 { rawValue }
        var label: String {
            switch self {
            case .day: return String(localized: "1 day")
            case .week: return String(localized: "7 days")
            case .month: return String(localized: "30 days")
            case .never: return String(localized: "No end")
            }
        }
        var days: UInt32? { self == .never ? nil : rawValue }
    }

    @State private var projects: [ProjectInfo] = []
    @State private var loaded = false
    @State private var chosen: Set<String> = []
    @State private var expiry: Expiry = .never
    @State private var busy = false
    @State private var problem: String?

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                HStack(alignment: .center) {
                    AgentMark(text: "New agent")
                    Spacer()
                    Button("Cancel") { dismiss() }
                        .buttonStyle(SecondaryButtonStyle(compact: true))
                }
                Title("\(agent.name) wants to join", size: 24)
                    .padding(.top, 14)
                Text(verbatim: "ID " + AgentText.idPrefix(agent.id))
                    .font(.mono(12))
                    .foregroundStyle(Palette.gris)
                    .padding(.top, 4)
                Text(matched == nil ? String(localized: "Compare these words with the ones in your terminal.")
                                    : String(localized: "This Mac registered the agent and compared the words for you."))
                    .font(.ui(14, relativeTo: .subheadline))
                    .foregroundStyle(Palette.gris)
                    .padding(.top, 6)
                if let note = agent.note, !note.isEmpty {
                    Text("\("“\(AgentText.line(note, max: 200))”") (according to the agent)")
                        .font(.ui(14, relativeTo: .subheadline))
                        .foregroundStyle(Palette.gris)
                        .fixedSize(horizontal: false, vertical: true)
                        .padding(.top, 4)
                }
                if let warning { Notice(text: warning).padding(.top, 14) }

                words.padding(.top, 22)
                if matched == true {
                    HStack(spacing: 8) {
                        IconView(icon: .check, size: 14)
                        Text("They match (this Mac launched the registration)")
                            .font(.ui(13, .medium, relativeTo: .footnote))
                    }
                    .foregroundStyle(Palette.cobalto)
                    .padding(.top, 10)
                } else if matched == false {
                    Notice(text: String(localized: "These aren’t the words this Mac’s klav printed when it registered the agent. Don’t approve it: deny it and connect again."))
                        .padding(.top, 10)
                }

                FieldLabel("You give it access to").padding(.top, 24).padding(.bottom, 10)
                projectChips

                FieldLabel("For how long").padding(.top, 20).padding(.bottom, 10)
                Flow(spacing: 8) {
                    ForEach(Expiry.allCases) { option in
                        Chip(text: option.label, on: expiry == option) { expiry = option }
                    }
                }
                Text("Whatever its policy asks to confirm will come to you here. To fine-tune permissions, domains or hours, use “klav agent approve” in the terminal.")
                    .font(.ui(12, relativeTo: .caption))
                    .foregroundStyle(Palette.gris)
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(.top, 12)

                if let problem { Notice(text: problem).padding(.top, 16) }
            }
            .padding(.horizontal, 20)
            .padding(.top, 22)
            .padding(.bottom, 20)
        }
        .safeAreaInset(edge: .bottom, spacing: 0) {
            VStack(spacing: 10) {
                Button(action: approve) {
                    Text(busy ? model.waitingForPresence : String(localized: "They match: approve"))
                }
                .buttonStyle(PrimaryButtonStyle())
                .disabled(!AgentApproval.allowed(busy: busy, chosen: chosen.count, matched: matched))
                Button("They don’t match", action: deny)
                    .buttonStyle(SecondaryButtonStyle(danger: true))
                    .disabled(busy)
                    .accessibilityHint("Denies the agent")
            }
            .padding(.horizontal, 20)
            .padding(.top, 12)
            .padding(.bottom, 8)
            .background(Palette.papel)
        }
        .background(Palette.papel)
        .task { await loadProjects() }
    }

    /// The six words, numbered: two columns, three rows, a line between
    /// them and the cross corners.
    private var words: some View {
        let list = agent.pairingWords.split(separator: " ").map(String.init)
        let rows = stride(from: 0, to: list.count, by: 2).map { Array(list.enumerated())[$0..<min($0 + 2, list.count)] }
        return VStack(spacing: 0) {
            ForEach(Array(rows.enumerated()), id: \.offset) { r, row in
                if r > 0 { Rule() }
                HStack(spacing: 0) {
                    ForEach(Array(row), id: \.offset) { index, word in
                        if index % 2 == 1 { Rectangle().fill(Palette.linea).frame(width: 1) }
                        VStack(alignment: .leading, spacing: 6) {
                            Text(verbatim: "\(index + 1)")
                                .font(.ui(11, relativeTo: .caption2))
                                .foregroundStyle(Palette.gris)
                            Text(word)
                                .font(.pixel(21, relativeTo: .title2))
                                .foregroundStyle(Palette.tinta)
                                .lineLimit(1)
                                .minimumScaleFactor(0.6)
                        }
                        .padding(.horizontal, 12)
                        .padding(.vertical, 12)
                        .frame(maxWidth: .infinity, alignment: .leading)
                    }
                }
                .fixedSize(horizontal: false, vertical: true)
            }
        }
        .overlay(Rectangle().strokeBorder(Palette.linea, lineWidth: 1))
        .crossCorners()
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(String(localized: "Words: \(spoken(list))"))
    }

    /// "1, alfa; 2, bravo; …" for VoiceOver.
    private func spoken(_ list: [String]) -> String {
        list.enumerated().map { "\($0.offset + 1), \($0.element)" }.joined(separator: "; ")
    }

    @ViewBuilder
    private var projectChips: some View {
        if !loaded {
            Text("Loading projects…")
                .font(.ui(14, relativeTo: .subheadline))
                .foregroundStyle(Palette.gris)
        } else {
            Flow(spacing: 8) {
                ForEach(projects, id: \.id) { project in
                    Chip(text: project.vault + " / " + project.name, on: chosen.contains(project.id)) {
                        if chosen.contains(project.id) { chosen.remove(project.id) } else { chosen.insert(project.id) }
                    }
                }
            }
        }
    }

    private func loadProjects() async {
        do {
            let list = try await model.agentProjects()
            projects = list.sorted { ($0.vault, $0.name) < ($1.vault, $1.name) }
        } catch {
            problem = describeRequest(error)
        }
        loaded = true
    }

    private func approve() {
        busy = true
        problem = nil
        let ids = projects.filter { chosen.contains($0.id) }.map(\.id)
        Task {
            do {
                try await model.approve(agent, projects: ids, expiresInDays: expiry.days)
                dismiss()
            } catch {
                problem = describeRequest(error)
            }
            busy = false
        }
    }

    private func deny() {
        busy = true
        Task {
            do {
                try await model.deny(agent)
                dismiss()
            } catch {
                problem = describeRequest(error)
            }
            busy = false
        }
    }
}

/// An agent asks for a task: who and what in its words, then one row per
/// item from the vault, the duration and Approve / Deny.
struct PendingTaskCard<Model: RequestsModel>: View {
    @EnvironmentObject private var model: Model
    let card: TaskItem
    var highlighted = false

    @State private var busy = false
    @State private var problem: String?

    var body: some View {
        let edits = model.taskEdits[card.id] ?? TaskEdits()
        AgentCard(highlighted: highlighted) {
            AgentMark(text: "\(card.agent) asks for a task")
                .accessibilityAddTraits(.isHeader)
            AgentKey<Model>(agentId: card.agentId)
            Text(card.task)
                .font(.ui(16, .semibold, relativeTo: .headline))
                .foregroundStyle(Palette.tinta)
                .fixedSize(horizontal: false, vertical: true)
            Text("“\(card.reason)”")
                .font(.ui(13, relativeTo: .footnote))
                .foregroundStyle(Palette.gris)
                .fixedSize(horizontal: false, vertical: true)
            Text("According to the agent")
                .font(.ui(12, relativeTo: .caption))
                .foregroundStyle(Palette.gris)

            VStack(alignment: .leading, spacing: 0) {
                Rule()
                ForEach(card.rows, id: \.itemId) { row in
                    TaskRowView<Model>(card: card, row: row, edits: edits)
                    Rule()
                }
            }
            .padding(.top, 6)

            FieldLabel("Duration").padding(.top, 8)
            Flow(spacing: 8) {
                ForEach(TaskWords.durations(requested: card.durationSecs), id: \.self) { secs in
                    Chip(text: TaskWords.duration(secs), on: edits.duration(for: card) == secs) {
                        model.editTask(card) { $0.forSecs = secs }
                    }
                }
            }
            TimelineView(.periodic(from: .now, by: 30)) { context in
                Text(TaskWords.lasts(edits.duration(for: card), now: context.date))
                    .font(.ui(12, relativeTo: .caption))
                    .foregroundStyle(Palette.gris)
                    .fixedSize(horizontal: false, vertical: true)
            }

            if let problem { Notice(text: problem).padding(.top, 4) }
            Flow(spacing: 8) {
                Button(busy ? model.waitingForPresence : String(localized: "Approve")) { decide(approve: true) }
                    .buttonStyle(PrimaryButtonStyle(compact: true))
                Button("Deny") { decide(approve: false) }
                    .buttonStyle(SecondaryButtonStyle(compact: true))
            }
            .padding(.top, 6)
        }
        .disabled(busy)
        // A box ticked again answers "check at least one permission".
        .onChange(of: model.taskEdits[card.id]) { _, _ in problem = nil }
    }

    private func decide(approve: Bool) {
        problem = nil
        if approve, !(model.taskEdits[card.id] ?? TaskEdits()).anyChecked(card) {
            problem = RequestError.nothingChecked.userMessage
            return
        }
        busy = true
        Task {
            do {
                try await model.decideTask(card, approve: approve)
            } catch {
                problem = describeRequest(error)
            }
            busy = false
        }
    }
}

/// One item of a pending task: its box, title, user and sites from the
/// vault, what is wrong with it, and a box per permission.
struct TaskRowView<Model: RequestsModel>: View {
    @EnvironmentObject private var model: Model
    let card: TaskItem
    let row: TaskRowItem
    let edits: TaskEdits

    var body: some View {
        let title = row.title ?? row.reference
        let usable = row.permissions.contains { !TaskEdits.blocked(row, $0) }
        let state = edits.state(of: row)
        VStack(alignment: .leading, spacing: 4) {
            CheckRow(state: state, enabled: usable, label: [title, row.username].compactMap { $0 }.joined(separator: ", "),
                     action: { model.editTask(card) { $0.set(row, state != .on) } }) {
                VStack(alignment: .leading, spacing: 2) {
                    Text(title)
                        .font(.ui(15, .medium))
                        .foregroundStyle(Palette.tinta)
                        .fixedSize(horizontal: false, vertical: true)
                    if let user = row.username, !user.isEmpty {
                        Text(user)
                            .font(.ui(13, relativeTo: .footnote))
                            .foregroundStyle(Palette.gris)
                    }
                    if !row.domains.isEmpty {
                        Text(row.domainClaimed
                             ? String(localized: "\(row.domains.joined(separator: ", ")) (according to the agent)")
                             : row.domains.joined(separator: ", "))
                            .font(.ui(13, relativeTo: .footnote))
                            .foregroundStyle(Palette.gris)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
            }
            if row.missing {
                flag(String(localized: "Not in your vault or outside the agent’s projects"))
            }
            if row.domainMismatch {
                flag(String(localized: "The site does not match the item (\(row.askedDomain ?? "?"))"))
            }
            if row.noSite {
                flag(String(localized: "No site: the item has no URL, so it cannot be filled in a task"))
            }
            VStack(alignment: .leading, spacing: 6) {
                ForEach(row.permissions, id: \.permission) { permission in
                    line(permission, title: title)
                }
            }
            .padding(.leading, 14)
            .padding(.top, 2)
        }
        .padding(.vertical, 10)
    }

    /// "one-time code for Invoices, Added by Klav": the item's name makes
    /// two `fill` boxes sound different.
    static func spoken(_ permission: TaskPermissionItem, name: String, title: String) -> String {
        var parts = [String(localized: "\(name) for \(title)")]
        if permission.addedByKlav { parts.append(String(localized: "Added by Klav")) }
        if permission.deniedByPolicy { parts.append(String(localized: "Your policy denies it")) }
        if permission.noSite { parts.append(String(localized: "No site")) }
        return parts.joined(separator: ", ")
    }

        private func flag(_ text: String) -> some View {
        Text(text)
            .font(.ui(12, relativeTo: .caption))
            .foregroundStyle(Palette.rojo)
            .fixedSize(horizontal: false, vertical: true)
    }

    @ViewBuilder
    private func line(_ permission: TaskPermissionItem, title: String) -> some View {
        let blocked = TaskEdits.blocked(row, permission)
        let name = TaskWords.permission(permission.permission)
        let on = edits.isChecked(row, permission)
        let label = Self.spoken(permission, name: name, title: title)
        VStack(alignment: .leading, spacing: 2) {
            CheckRow(state: on ? .on : .off, enabled: !blocked, label: label,
                     action: { model.editTask(card) { $0.set(row, permission, !on) } }) {
                Flow(spacing: 8) {
                    Text(name)
                        .font(.ui(14, relativeTo: .subheadline))
                        .foregroundStyle(blocked ? Palette.cruz : Palette.tinta)
                        .strikethrough(blocked, color: Palette.cruz)
                    if permission.addedByKlav {
                        Text("Added by Klav")
                            .font(.ui(12, relativeTo: .caption))
                            .foregroundStyle(Palette.cobalto)
                    }
                    if permission.deniedByPolicy {
                        Text("Your policy denies it")
                            .font(.ui(12, relativeTo: .caption))
                            .foregroundStyle(Palette.gris)
                    } else if permission.noSite {
                        Text("No site")
                            .font(.ui(12, relativeTo: .caption))
                            .foregroundStyle(Palette.gris)
                    }
                }
            }
            if !blocked, let warning = TaskWords.warning(permission.permission) {
                Text(warning)
                    .font(.ui(12, relativeTo: .caption))
                    .foregroundStyle(Palette.gris)
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(.trailing, 34)
            }
        }
    }
}

/// A running task: what it covers, what is left of it and «End task».
/// The blue band is the time: it empties from the top as the task runs.
struct LiveTaskCard<Model: RequestsModel>: View {
    @EnvironmentObject private var model: Model
    let card: TaskItem
    var highlighted = false

    @State private var busy = false
    @State private var problem: String?

    var body: some View {
        TimelineView(.periodic(from: .now, by: 5)) { context in
            AgentCard(highlighted: highlighted, spent: TaskWords.spent(card, now: context.date)) {
                AgentMark(text: "\(card.agent) is working on a task")
                    .accessibilityAddTraits(.isHeader)
                AgentKey<Model>(agentId: card.agentId)
                Text(card.task)
                    .font(.ui(16, .semibold, relativeTo: .headline))
                    .foregroundStyle(Palette.tinta)
                    .fixedSize(horizontal: false, vertical: true)
                Text(TaskWords.left(until: card.expiresAt ?? 0, now: context.date))
                    .font(.ui(13, relativeTo: .footnote))
                    .foregroundStyle(Palette.gris)
                    .fixedSize(horizontal: false, vertical: true)
                VStack(alignment: .leading, spacing: 6) {
                    ForEach(covered, id: \.itemId) { row in
                        VStack(alignment: .leading, spacing: 1) {
                            Text(row.title ?? row.reference)
                                .font(.ui(14, .medium, relativeTo: .subheadline))
                                .foregroundStyle(Palette.tinta)
                            Text(row.permissions.filter(\.checked).map { TaskWords.permission($0.permission) }
                                .joined(separator: ", "))
                                .font(.ui(13, relativeTo: .footnote))
                                .foregroundStyle(Palette.gris)
                        }
                        .fixedSize(horizontal: false, vertical: true)
                        .accessibilityElement(children: .combine)
                    }
                }
                .padding(.top, 4)
                if let problem { Notice(text: problem).padding(.top, 4) }
                Button("End task", action: end)
                    .buttonStyle(SecondaryButtonStyle(compact: true))
                    .accessibilityHint("The agent can no longer use it")
                    .padding(.top, 6)
            }
        }
        .disabled(busy)
    }

    private var covered: [TaskRowItem] {
        card.rows.filter { $0.permissions.contains(where: \.checked) }
    }

    private func end() {
        busy = true
        problem = nil
        Task {
            do { try await model.endTask(card) } catch { problem = describeRequest(error) }
            busy = false
        }
    }
}

/// What ties a card to the agent's key, under the name the agent chose:
/// the start of its ID (as `klav approval` prints it) and, for an agent
/// this account approved, the pairing words compared back then.
struct AgentKey<Model: RequestsModel>: View {
    @EnvironmentObject private var model: Model
    let agentId: String

    var body: some View {
        Text(Self.line(id: agentId, words: model.pairingWords(ofAgent: agentId)))
            .font(.ui(12, relativeTo: .caption))
            .foregroundStyle(Palette.gris)
            .fixedSize(horizontal: false, vertical: true)
    }

    static func line(id: String, words: String?) -> String {
        let short = String(id.prefix(8))
        guard let words else { return String(localized: "Agent \(short)…") }
        return String(localized: "Agent \(short)… · words: \(words)")
    }
}

/// A card's identity in a list: its ID and the digest of the request it
/// shows (ADR 0030 §5). A request that changes on the server gets a new
/// card instead of keeping the old text under the same ID.
extension ApprovalItem {
    var decisionKey: String { "\(id):\(requestDigest)" }
}

extension TaskItem {
    var decisionKey: String { "\(id):\(requestDigest)" }
}

extension SecretRequestItem {
    var decisionKey: String { "\(id):\(proposalDigest)" }
}

/// An agent asks the person to save a missing secret (or update a secret field
/// of an existing item) via a hidden input on their device (ADR 0046).
///
/// Security invariants enforced here:
/// - The entered secret stays only in `@State` and is cleared on save, deny,
///   or view disappear (never logged).
/// - T234: agent-suggested `login` URLs stay unchecked by default.
/// - T235: `setupUrl` is never auto-opened; displays full host + warning and
///   a punycode/IDN alert when applicable.
/// - T239: `proxyProposal` toggle is unchecked by default and requires
///   presence (Touch ID / Face ID / master password) when enabled.
struct SecretRequestCard<Model: RequestsModel>: View {
    @EnvironmentObject private var model: Model
    let card: SecretRequestItem
    var highlighted = false

    @State private var secret = ""
    @State private var revealSecret = false
    @State private var title = ""
    @State private var selectedProjectId = ""
    @State private var projects: [ProjectInfo] = []
    @State private var confirmedUrls: Set<String> = []
    @State private var grantProxy = false
    @State private var busy = false
    @State private var problem: String?
    @State private var initialized = false

    private var isUpdate: Bool { card.mode == "update" }
    private var canSave: Bool {
        card.proposalError == nil && (!isUpdate || card.targetReference != nil)
    }
    private var fieldName: String { card.field ?? "api_key" }
    private var selectedProject: ProjectInfo? {
        projects.first(where: { $0.id == selectedProjectId })
    }

    var body: some View {
        AgentCard(highlighted: highlighted) {
            AgentMark(text: String(localized: "\(card.agent) asks for a secret"))
                .accessibilityAddTraits(.isHeader)
            AgentKey<Model>(agentId: card.agentId)

            if isUpdate {
                let target = card.targetTitle ?? card.targetReference ?? "?"
                Text(String(localized: "Replace \(fieldName) on \(target)"))
                    .font(.ui(14, .semibold, relativeTo: .subheadline))
                    .foregroundStyle(Palette.tinta)
                    .fixedSize(horizontal: false, vertical: true)
                if let ref = card.targetReference {
                    Text(ref)
                        .font(.ui(12, relativeTo: .caption))
                        .foregroundStyle(Palette.gris)
                } else {
                    Notice(text: String(localized: "This item is not in your vault or is in the trash."))
                }
                Text("The previous value stays in password history.")
                    .font(.ui(12, relativeTo: .caption))
                    .foregroundStyle(Palette.gris)
            } else {
                Text(String(localized: "Save a new item (\(card.kind ?? "api_key"))"))
                    .font(.ui(14, .semibold, relativeTo: .subheadline))
                    .foregroundStyle(Palette.tinta)
            }

            Text("“\(card.reason)”")
                .font(.ui(13, relativeTo: .footnote))
                .foregroundStyle(Palette.gris)
                .fixedSize(horizontal: false, vertical: true)
            Expires(at: card.expiresAt)

            if let err = card.proposalError {
                Notice(text: err)
            }

            if !isUpdate && card.proposalError == nil {
                VStack(alignment: .leading, spacing: 6) {
                    Text("Title")
                        .font(.ui(12, .medium, relativeTo: .caption))
                        .foregroundStyle(Palette.gris)
                    TextField(String(localized: "Title"), text: $title)
                        .textFieldStyle(.roundedBorder)
                }

                if !projects.isEmpty {
                    VStack(alignment: .leading, spacing: 6) {
                        Text("Project")
                            .font(.ui(12, .medium, relativeTo: .caption))
                            .foregroundStyle(Palette.gris)
                        Picker(String(localized: "Project"), selection: $selectedProjectId) {
                            ForEach(projects, id: \.id) { project in
                                Text(projectLabel(project)).tag(project.id)
                            }
                        }
                        .labelsHidden()
                    }
                }

                // T234: agent-suggested `login` URLs stay unchecked by default.
                if card.kind == "login", !card.urls.isEmpty {
                    VStack(alignment: .leading, spacing: 4) {
                        Text(String(localized: "Sites suggested by \(card.agent) (unchecked by default):"))
                            .font(.ui(12, relativeTo: .caption))
                            .foregroundStyle(Palette.gris)
                        ForEach(card.urls, id: \.self) { url in
                            Toggle(isOn: Binding(
                                get: { confirmedUrls.contains(url) },
                                set: { checked in
                                    if checked { confirmedUrls.insert(url) } else { confirmedUrls.remove(url) }
                                }
                            )) {
                                Text(url)
                                    .font(.ui(12, relativeTo: .caption))
                                    .foregroundStyle(Palette.tinta)
                            }
                        }
                    }
                }
            }

            // T235: never auto-open setupUrl; show full domain + punycode warning.
            if let setup = card.setupUrl, let url = URL(string: setup.url) {
                VStack(alignment: .leading, spacing: 4) {
                    Text(String(localized: "Link suggested by \(card.agent) — check the domain before opening: \(setup.host)"))
                        .font(.ui(12, relativeTo: .caption))
                        .foregroundStyle(Palette.gris)
                        .fixedSize(horizontal: false, vertical: true)
                    if setup.hasPunycode {
                        Notice(text: String(localized: "This domain uses internationalized labels (punycode). Check every character carefully."))
                    }
                    Link(String(localized: "Open \(setup.host)"), destination: url)
                        .font(.ui(13, .medium, relativeTo: .footnote))
                }
            }

            if canSave {
                VStack(alignment: .leading, spacing: 6) {
                    HStack {
                        Text(String(localized: "Secret (\(fieldName))"))
                            .font(.ui(12, .medium, relativeTo: .caption))
                            .foregroundStyle(Palette.gris)
                        Spacer()
                        Button(revealSecret ? String(localized: "Hide") : String(localized: "Show")) {
                            revealSecret.toggle()
                        }
                        .font(.ui(12, relativeTo: .caption))
                        .buttonStyle(.plain)
                    }
                    Group {
                        if revealSecret {
                            TextField(card.placeholder ?? "", text: $secret)
                        } else {
                            SecureField(card.placeholder ?? "", text: $secret)
                        }
                    }
                    .textFieldStyle(.roundedBorder)
                }
            }

            // T239: optional proxy grant, unchecked by default, requires presence.
            if let proxy = card.proxyProposal, canSave {
                VStack(alignment: .leading, spacing: 4) {
                    Toggle(isOn: $grantProxy) {
                        Text(String(localized: "Also grant to credential proxy (“\(proxy.profile)”)"))
                            .font(.ui(13, .medium, relativeTo: .footnote))
                            .foregroundStyle(Palette.tinta)
                    }
                    Text("\(proxy.upstream) · \(proxy.methods.joined(separator: ", ")) · \(proxy.pathPrefixes.joined(separator: ", "))")
                        .font(.ui(12, relativeTo: .caption))
                        .foregroundStyle(Palette.gris)
                        .fixedSize(horizontal: false, vertical: true)
                }
                .padding(.top, 2)
            }

            if let problem { Notice(text: problem).padding(.top, 4) }

            Flow(spacing: 8) {
                Button(busy && grantProxy ? model.waitingForPresence : String(localized: "Save to Klav")) {
                    save()
                }
                .buttonStyle(PrimaryButtonStyle(compact: true))
                .disabled(!canSave || secret.isEmpty)

                Button("Deny") { deny() }
                    .buttonStyle(SecondaryButtonStyle(compact: true))
            }
            .padding(.top, 6)
        }
        .disabled(busy)
        .task(id: card.decisionKey) {
            if !initialized {
                initialized = true
                title = card.title ?? ""
                if let list = try? await model.agentProjects() {
                    projects = list
                    if let wantedProject = card.projectId, list.contains(where: { $0.id == wantedProject }) {
                        selectedProjectId = wantedProject
                    } else if let first = list.first {
                        selectedProjectId = first.id
                    }
                }
            }
        }
        .onDisappear {
            secret = ""
            revealSecret = false
        }
    }

    private func projectLabel(_ project: ProjectInfo) -> String {
        let shared = card.agentProjects.contains { $0.vaultId == project.vaultId && $0.projectId == project.id }
        let name = "\(project.vault) / \(project.name)"
        return shared
            ? String(localized: "\(name) (shared with \(card.agent))")
            : String(localized: "\(name) (not shared with \(card.agent))")
    }

    private func save() {
        guard !secret.isEmpty else { return }
        let value = secret
        let input = SecretRequestFulfillInput(
            digest: card.proposalDigest,
            secret: value,
            vault: isUpdate ? nil : selectedProject?.vaultId,
            project: isUpdate ? nil : selectedProject?.id,
            title: isUpdate ? nil : (title.trimmingCharacters(in: .whitespaces).isEmpty ? nil : title.trimmingCharacters(in: .whitespaces)),
            field: card.field,
            urls: (!isUpdate && !confirmedUrls.isEmpty) ? Array(confirmedUrls).sorted() : nil,
            notes: nil,
            allowDuplicate: false,
            grantProxy: grantProxy,
            proxyBaseVersion: nil,
            everyDeviceUpdated: false,
            shownWords: nil
        )
        busy = true
        problem = nil
        Task {
            do {
                _ = try await model.fulfillSecretRequest(card, input: input)
                secret = ""
                revealSecret = false
            } catch {
                problem = describeRequest(error)
            }
            busy = false
        }
    }

    private func deny() {
        busy = true
        problem = nil
        Task {
            do {
                try await model.denySecretRequest(card)
                secret = ""
                revealSecret = false
            } catch {
                problem = describeRequest(error)
            }
            busy = false
        }
    }
}
