import SwiftUI

/// Development › Agents (ADR 0033 E1, §7.5): «Pause agents» above the
/// list, then every agent of the account with its state (waiting, with
/// access, paused), the client it is for and when it was last used. An
/// agent opens its page, with «Permissions» and «Revoke…» (amendment of
/// 2026-11-10, F5).
struct AgentsPane: View {
    @EnvironmentObject private var model: MacModel
    @EnvironmentObject private var installer: Installer
    @State private var agents: [DevAgentInfo] = []
    @State private var revocations: [RevocationInfo] = []
    @State private var localIds: Set<String> = []
    @State private var problem: String?
    @State private var loaded = false

    var body: some View {
        Group {
            if let id = model.openAgent {
                AgentPage(agentId: id).id(id)
            } else {
                list
            }
        }
        .sheet(item: $model.revoking) { request in
            RevokeSheet(agentId: request.agentId)
                .environmentObject(model)
                .frame(width: 540, height: 660)
        }
        .sheet(item: $model.changingGrant) { request in
            GrantSheet(agentId: request.agentId)
                .environmentObject(model)
                .frame(width: 580, height: 640)
        }
    }

    private var list: some View {
        VStack(spacing: 0) {
            PaneHeader(title: "Agents", detail: loaded ? detail : nil)
            ScrollView {
                VStack(alignment: .leading, spacing: 0) {
                    PauseBar()
                    if let problem { Notice(text: problem).padding(.top, 16) }
                    if loaded && agents.isEmpty { empty.padding(.top, 28) }
                    group("Waiting for you", waiting)
                    group("With access", active)
                    group("Denied or revoked", others)
                }
                .frame(maxWidth: 660, alignment: .leading)
                .padding(.horizontal, 28)
                .padding(.vertical, 24)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        .task(id: model.generation) { await load() }
    }

    private var detail: String {
        waiting.isEmpty ? String(localized: "\(Int64(active.count)) with access")
                        : String(localized: "\(Int64(active.count)) with access · \(Int64(waiting.count)) waiting")
    }

    private var waiting: [DevAgentInfo] { agents.filter { $0.agent.status == "pending" } }
    private var active: [DevAgentInfo] { agents.filter { $0.agent.status == "active" } }
    private var others: [DevAgentInfo] { agents.filter { $0.agent.status == "denied" || $0.agent.status == "revoked" } }

    @ViewBuilder
    private func group(_ title: LocalizedStringKey, _ list: [DevAgentInfo]) -> some View {
        if !list.isEmpty {
            SectionLabel(title).padding(.top, 28).padding(.bottom, 10)
            FieldBlock {
                ForEach(Array(list.enumerated()), id: \.element.agent.id) { index, item in
                    if index > 0 { Rule() }
                    DevAgentRow(item: item, pause: pause(of: item),
                                isLocal: localIds.contains(item.agent.id),
                                revocation: RevokeWords.state(model.revocationFlows[item.agent.id],
                                                              left: model.keysLeft(of: item.agent.id, listed: revocations)))
                }
            }
        }
    }

    /// What stops the agent now: `klavd`'s status first (a pause made a
    /// moment ago, or one only on this Mac), then the server's list.
    private func pause(of item: DevAgentInfo) -> AgentPauseInfo? { Pauses(model.pauses).stopping(item) }

    private var empty: some View {
        HStack(alignment: .top, spacing: 18) {
            DitherView(kind: .band, palette: .blue, pixel: 3)
                .frame(width: 40, height: 88)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 6) {
                Text("No agent yet").font(.ui(16, .medium)).foregroundStyle(Palette.tinta)
                Text("Connect Claude Code, Codex or Cursor in Clients, and approve it here with Touch ID. For anything else, in the agent’s terminal: klav agent register --name <name>")
                    .font(.ui(13)).foregroundStyle(Palette.gris)
                    .fixedSize(horizontal: false, vertical: true)
                    .textSelection(.enabled)
                Button("Open Clients") { model.section = .clients }
                    .buttonStyle(SecondaryButtonStyle(compact: true))
                    .fixedSize()
                    .padding(.top, 6)
            }
        }
    }

    private func load() async {
        if installer.system.refusal(for: installer.paths) == nil {
            localIds = LocalAgents.ids(in: installer.paths.klavHome)
        }
        do {
            (agents, revocations) = try await model.agentsAndRevocations()
            problem = nil
        } catch KlavError.Locked {
            model.refresh()
        } catch {
            problem = describe(error)
        }
        loaded = true
    }
}

private struct DevAgentRow: View {
    @EnvironmentObject private var model: MacModel
    let item: DevAgentInfo
    let pause: AgentPauseInfo?
    /// This agent's local config (`agents/<name>.json`) lives on this Mac.
    let isLocal: Bool
    /// «Revoked. Keys left to change (3 of 5)», while a revocation's key
    /// change is not finished.
    let revocation: String?
    @State private var problem: String?
    @State private var busy = false

    private var agent: AgentItem { item.agent }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .top, spacing: 12) {
                Button { model.openAgent = agent.id } label: { summary.contentShape(Rectangle()) }
                    .buttonStyle(.plain)
                    .accessibilityHint(Text("Opens the agent’s page"))
                Spacer(minLength: 12)
                VStack(alignment: .trailing, spacing: 8) {
                    state
                    HStack(spacing: 6) { actions }
                }
                .fixedSize()
            }
            if let revocation {
                HStack(spacing: 8) {
                    Rectangle().fill(Palette.rojo).frame(width: 7, height: 7)
                    Text(verbatim: revocation).font(.ui(12, .medium)).foregroundStyle(Palette.tinta)
                }
            }
            if let problem { Notice(text: problem) }
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 12)
        .disabled(busy)
    }

    private var roleColor: Color {
        switch item.role {
        case .proxy: return Palette.cobalto
        case .sandboxIssuer: return Palette.tinta
        case .standard: return Palette.gris
        }
    }

    private var summary: some View {
                VStack(alignment: .leading, spacing: 4) {
                    HStack(alignment: .center, spacing: 8) {
                        Text(verbatim: AgentText.line(agent.name, max: 64))
                            .font(.ui(14, .medium)).foregroundStyle(Palette.tinta)
                        Text(verbatim: ActivityWords.roleBadge(item))
                            .font(.ui(11, .medium)).foregroundStyle(roleColor)
                            .padding(.horizontal, 6).frame(height: 19)
                            .overlay(Rectangle().strokeBorder(roleColor.opacity(item.role == .standard ? 0.5 : 1), lineWidth: 1))
                        if isLocal {
                            Text("On this Mac")
                                .font(.ui(11, .medium)).foregroundStyle(Palette.tinta)
                                .padding(.horizontal, 6).frame(height: 19)
                                .background(Palette.niebla)
                        }
                        Text(verbatim: String(agent.id.prefix(8)))
                            .font(.mono(11)).foregroundStyle(Palette.gris)
                    }
                    if let origin = ActivityWords.originSummary(item) {
                        Text(verbatim: origin)
                            .font(.ui(12.5, .medium)).foregroundStyle(Palette.tinta)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    if let note = agent.note, !note.isEmpty {
                        Text("\("“\(AgentText.line(note, max: 120))”") (according to the agent)")
                            .font(.ui(12)).foregroundStyle(Palette.gris)
                            .lineLimit(1)
                    }
                    if !agent.projects.isEmpty {
                        Text(verbatim: agent.projects.joined(separator: ", "))
                            .font(.ui(12.5)).foregroundStyle(Palette.gris)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    Text(verbatim: ActivityWords.seen(item))
                        .font(.ui(12)).foregroundStyle(Palette.gris)
                }
    }

    @ViewBuilder
    private var state: some View {
        if let pause {
            VStack(alignment: .trailing, spacing: 3) {
                Text("Paused")
                    .font(.ui(11, .medium)).foregroundStyle(Palette.cobalto)
                    .padding(.horizontal, 6).frame(height: 20)
                    .overlay(Rectangle().strokeBorder(Palette.cobalto, lineWidth: 1))
                Text(verbatim: PauseWords.agentState(pause))
                    .font(.ui(12)).foregroundStyle(Palette.gris)
            }
        } else {
            Text(verbatim: status)
                .font(.ui(12, .medium))
                .foregroundStyle(agent.status == "active" ? Palette.cobalto : Palette.gris)
        }
    }

    private var status: String {
        switch agent.status {
        case "active": return String(localized: "Has access")
        case "denied": return String(localized: "Denied")
        case "revoked": return String(localized: "Revoked")
        default: return String(localized: "Waiting")
        }
    }

    @ViewBuilder
    private var actions: some View {
        switch agent.status {
        case "pending":
            SmallAction(title: "Review in Requests") { model.section = .requests }
        case "active":
            if let pause, !pause.everyone {
                SmallAction(title: busy ? "Waiting…" : "Resume") { Task { await resume() } }
            } else if pause == nil {
                Menu {
                    ForEach(PauseLength.allCases) { length in
                        Button(length.label) { Task { await self.pause(length.minutes) } }
                    }
                } label: {
                    Text("Pause")
                        .font(.ui(11, .medium)).foregroundStyle(Palette.tinta)
                }
                .menuStyle(.button)
                .buttonStyle(.plain)
                .menuIndicator(.hidden)
                .padding(.horizontal, 7)
                .frame(height: 22)
                .overlay(Rectangle().strokeBorder(Palette.linea, lineWidth: 1))
                .fixedSize()
            }
            SmallAction(title: "Activity") { model.openActivity(agent: agent.id) }
        default:
            SmallAction(title: "Activity") { model.openActivity(agent: agent.id) }
        }
    }

    private func pause(_ minutes: Int?) async {
        busy = true
        problem = nil
        do { try await model.pauseAgents(agentId: agent.id, minutes: minutes) } catch { problem = describe(error) }
        busy = false
    }

    private func resume() async {
        busy = true
        problem = nil
        do { try await model.resumeAgents(agentId: agent.id) } catch { problem = describe(error) }
        busy = false
    }
}
