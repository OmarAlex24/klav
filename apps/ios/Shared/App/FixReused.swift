import SwiftUI

/// What «Fix my reused passwords» needs from each app's model (ADR 0022
/// §6): the iPhone checks Face ID itself; the Mac lets `klavd` ask for
/// Touch ID, or asks for the master password in a sheet first, so the
/// task arrives in `offered` once the offer is signed.
@MainActor
protocol FixOffering: ObservableObject {
    /// "Waiting for Face ID…" or "Waiting for Touch ID…".
    var waitingForPresence: String { get }
    /// Offers the task; `offered` gets it once it is signed. Throws when
    /// the offer failed or the person didn't confirm.
    func offerFix(_ input: OfferInput, agent: String, offered: @escaping @MainActor (TaskItem) -> Void) async throws
}

/// «Fix my reused passwords»: the agent, the logins (each with its change
/// page and what the task holds), the duration and one approval. Blue,
/// like everything agents do.
struct OfferCard<Model: FixOffering>: View {
    @EnvironmentObject private var model: Model
    let offer: ReusedOfferInfo
    let pick: (String) -> Void
    let done: (TaskItem) -> Void
    let cancel: () -> Void

    @State private var unchecked: Set<String> = []
    @State private var secs = HealthWords.defaultSecs
    @State private var busy = false
    @State private var problem: String?

    var body: some View {
        AgentCard {
            AgentMark(text: "Fix my reused passwords")
                .accessibilityAddTraits(.isHeader)
            Text("The agent changes each password on its site through your computer’s browser, without seeing the current one or the new one. It gets the sites, never which ones share a password.")
                .font(.ui(14, relativeTo: .subheadline))
                .foregroundStyle(Palette.tinta)
                .fixedSize(horizontal: false, vertical: true)

            agents.padding(.top, 6)

            VStack(alignment: .leading, spacing: 0) {
                Rule()
                ForEach(offer.rows, id: \.itemId) { row in
                    OfferRowView(row: row, enabled: offer.agent != nil && row.blocked == nil,
                                 on: offer.agent != nil && row.blocked == nil && !unchecked.contains(row.itemId)) {
                        if unchecked.contains(row.itemId) { unchecked.remove(row.itemId) } else { unchecked.insert(row.itemId) }
                        problem = nil
                    }
                    Rule()
                }
            }
            .padding(.top, 6)
            Text("The agent will change the passwords you leave checked")
                .font(.ui(12, relativeTo: .caption))
                .foregroundStyle(Palette.gris)
                .fixedSize(horizontal: false, vertical: true)

            FieldLabel("Duration").padding(.top, 8)
            Flow(spacing: 8) {
                ForEach(HealthWords.offerSteps, id: \.self) { step in
                    Chip(text: TaskWords.duration(step), on: secs == step) { secs = step }
                }
            }
            TimelineView(.periodic(from: .now, by: 30)) { context in
                Text(TaskWords.lasts(secs, now: context.date))
                    .font(.ui(12, relativeTo: .caption))
                    .foregroundStyle(Palette.gris)
                    .fixedSize(horizontal: false, vertical: true)
            }

            if let problem { Notice(text: problem).padding(.top, 4) }
            Flow(spacing: 8) {
                Button(busy ? model.waitingForPresence : String(localized: "Approve"), action: approve)
                    .buttonStyle(PrimaryButtonStyle(compact: true))
                    .disabled(offer.agent == nil)
                    .accessibilityIdentifier("offer-approve")
                Button("Cancel", action: cancel)
                    .buttonStyle(SecondaryButtonStyle(compact: true))
            }
            .padding(.top, 6)
        }
        .disabled(busy)
    }

    @ViewBuilder
    private var agents: some View {
        if offer.agents.isEmpty {
            Notice(text: String(localized: "No agent can take it yet. Register one and approve it first:"), tone: .info)
            Text(verbatim: "klav agent register")
                .font(.mono(13))
                .foregroundStyle(Palette.tinta)
                .textSelection(.enabled)
        } else {
            FieldLabel("Agent")
            Flow(spacing: 8) {
                ForEach(offer.agents, id: \.id) { agent in
                    Chip(text: agent.name, on: offer.agent?.id == agent.id) {
                        if offer.agent?.id != agent.id { pick(agent.id) }
                    }
                }
            }
            if offer.agent == nil {
                Text("Choose an agent")
                    .font(.ui(12, relativeTo: .caption))
                    .foregroundStyle(Palette.gris)
            }
        }
    }

    private func approve() {
        guard let agent = offer.agent else { return }
        let input = HealthWords.input(agent: agent.id, rows: offer.rows, unchecked: unchecked, secs: secs)
        guard !input.items.isEmpty else {
            problem = String(localized: "Check at least one login")
            return
        }
        problem = nil
        busy = true
        Task {
            do {
                try await model.offerFix(input, agent: agent.name) { task in done(task) }
            } catch {
                problem = describeRequest(error)
            }
            busy = false
        }
    }
}

/// One login of the offer: its box, title and sites, its user and group,
/// why it cannot go, where it changes and the code Klav adds.
struct OfferRowView: View {
    let row: OfferRowInfo
    let enabled: Bool
    let on: Bool
    let toggle: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 3) {
            CheckRow(state: on ? .on : .off, enabled: enabled,
                     label: [row.title, row.username].compactMap { $0 }.joined(separator: ", "), action: toggle) {
                VStack(alignment: .leading, spacing: 2) {
                    Text(row.title)
                        .font(.ui(15, .medium))
                        .foregroundStyle(Palette.tinta)
                        .fixedSize(horizontal: false, vertical: true)
                    if !row.hosts.isEmpty {
                        line(row.hosts.joined(separator: ", "))
                    }
                    let user = [row.username, row.group.map { String(localized: "group \(Int64($0))") }]
                        .compactMap { $0 }.filter { !$0.isEmpty }.joined(separator: " · ")
                    if !user.isEmpty { line(user) }
                }
            }
            if let blocked = row.blocked {
                Text(HealthWords.block(blocked))
                    .font(.ui(12, relativeTo: .caption))
                    .foregroundStyle(Palette.rojo)
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                if let url = row.changeUrl {
                    line(String(localized: "Changes it at \(url.replacingOccurrences(of: "https://", with: ""))"))
                }
                if row.permissions.contains("totp") {
                    VStack(alignment: .leading, spacing: 2) {
                        HStack(spacing: 8) {
                            Text(TaskWords.permission("totp"))
                                .font(.ui(14, relativeTo: .subheadline))
                                .foregroundStyle(Palette.tinta)
                            Text("Added by Klav")
                                .font(.ui(12, relativeTo: .caption))
                                .foregroundStyle(Palette.cobalto)
                        }
                        if let warning = TaskWords.warning("totp") {
                            Text(warning)
                                .font(.ui(12, relativeTo: .caption))
                                .foregroundStyle(Palette.gris)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    }
                    .padding(.leading, 14)
                    .padding(.top, 2)
                    .accessibilityElement(children: .combine)
                }
            }
        }
        .padding(.vertical, 10)
    }

    private func line(_ text: String) -> some View {
        Text(text)
            .font(.ui(13, relativeTo: .footnote))
            .foregroundStyle(Palette.gris)
            .fixedSize(horizontal: false, vertical: true)
    }
}

/// A running «Fix my reused passwords» task: each site as changed, in
/// progress, pending or failed, from the task's log. The band is the time.
struct FixProgressCard: View {
    let progress: TaskProgressInfo

    var body: some View {
        let n = HealthWords.counts(progress.sites)
        TimelineView(.periodic(from: .now, by: 5)) { context in
            AgentCard(spent: progress.card.map { TaskWords.spent($0, now: context.date) }) {
                AgentMark(text: "\(progress.card?.agent ?? "") is changing your passwords")
                    .accessibilityAddTraits(.isHeader)
                if let card = progress.card {
                    Text(card.task)
                        .font(.ui(16, .semibold, relativeTo: .headline))
                        .foregroundStyle(Palette.tinta)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Text(summary(n))
                    .font(.ui(13, relativeTo: .footnote))
                    .foregroundStyle(Palette.gris)
                    .fixedSize(horizontal: false, vertical: true)
                VStack(alignment: .leading, spacing: 6) {
                    ForEach(progress.sites, id: \.itemId) { site in
                        VStack(alignment: .leading, spacing: 1) {
                            Text(site.title ?? site.reference ?? site.itemId)
                                .font(.ui(14, .medium, relativeTo: .subheadline))
                                .foregroundStyle(Palette.tinta)
                            Text("\(site.hosts.first ?? "") · \(HealthWords.site(site))")
                                .font(.ui(13, relativeTo: .footnote))
                                .foregroundStyle(site.state == "failed" ? Palette.rojo
                                    : site.state == "changed" ? Palette.tinta : Palette.gris)
                        }
                        .fixedSize(horizontal: false, vertical: true)
                        .accessibilityElement(children: .combine)
                    }
                }
                .padding(.top, 4)
            }
        }
    }

    private func summary(_ n: (changed: Int, pending: Int, failed: Int)) -> String {
        let counts = String(localized: "Changed \(Int64(n.changed)) · pending \(Int64(n.pending)) · failed \(Int64(n.failed))")
        guard let end = progress.card?.expiresAt else { return counts }
        return "\(counts) · " + TaskWords.until(end)
    }
}
