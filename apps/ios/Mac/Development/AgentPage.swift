import SwiftUI

/// An agent's page in Development › Agents (ADR 0033, amendment of
/// 2026-11-10, F5): its state, what is left of a revocation, «Permissions»
/// with the grant in words, «Change permissions…» and «Revoke…».
struct AgentPage: View {
    @EnvironmentObject private var model: MacModel
    @EnvironmentObject private var installer: Installer
    let agentId: String
    @State private var agent: DevAgentInfo?
    @State private var isLocal = false
    @State private var grant: GrantEditorInfo?
    @State private var listed: [RevocationInfo] = []
    @State private var problem: String?
    /// The grant could not be read: «Permissions» says so, «Revoke…» stays.
    @State private var grantProblem: String?
    /// «Finish» was already pressed by itself once for a key change
    /// `klavd` finished in the background (so «Done» comes from a report).
    @State private var confirmed = false

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 10) {
                Button { model.openAgent = nil } label: {
                    HStack(spacing: 6) {
                        IconView(icon: .back, size: 14)
                        Text("Agents").font(.ui(15, .semibold))
                    }
                    .foregroundStyle(Palette.tinta)
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .keyboardShortcut("[", modifiers: .command)
                Spacer()
            }
            .padding(.horizontal, 28)
            .frame(height: 52)
            .overlay(alignment: .bottom) { Rule() }
            ScrollView {
                VStack(alignment: .leading, spacing: 0) {
                    if let agent {
                        header(agent)
                        revocation(agent.agent)
                        if let problem { Notice(text: problem).padding(.top, 16) }
                        if agent.agent.status == "active" {
                            // Revoking never waits on reading the grant
                            // (F1 gap 4): «Revoke…» shows whatever it says.
                            if let grant {
                                PermissionsSection(grant: grant)
                                    .padding(.top, 28)
                            } else if let grantProblem {
                                Notice(text: grantProblem).padding(.top, 28)
                            }
                            actions(agent.agent, grant: grant)
                                .padding(.top, 20)
                        }
                    } else if let problem {
                        Notice(text: problem)
                    }
                }
                .frame(maxWidth: 660, alignment: .leading)
                .padding(.horizontal, 28)
                .padding(.vertical, 24)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        .task(id: model.generation) { await load() }
        .onChange(of: model.info?.revocations) { _, _ in confirmIfFinished() }
    }

    // MARK: Parts

    private func header(_ item: DevAgentInfo) -> some View {
        let agent = item.agent
        let roleColor: Color = item.role == .proxy ? Palette.cobalto : item.role == .sandboxIssuer ? Palette.tinta : Palette.gris
        return VStack(alignment: .leading, spacing: 6) {
            // The agent chose its name: one line, quoted, and said to be
            // its own (T136).
            HStack(alignment: .firstTextBaseline, spacing: 10) {
                Title("“\(AgentText.line(agent.name, max: 64))”", size: 24)
                    .lineLimit(1)
                Text("named by the agent").font(.ui(12)).foregroundStyle(Palette.gris)
            }
            HStack(alignment: .center, spacing: 10) {
                Text(verbatim: status(agent)).font(.ui(13, .medium))
                    .foregroundStyle(agent.status == "active" ? Palette.cobalto : Palette.gris)
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
                Text(verbatim: "ID \(AgentText.idPrefix(agent.id))").font(.mono(11)).foregroundStyle(Palette.gris)
                    .textSelection(.enabled)
            }
            if let origin = ActivityWords.originSummary(item) {
                Text(verbatim: origin)
                    .font(.ui(13, .medium)).foregroundStyle(Palette.tinta)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if let note = agent.note {
                Text("“\(AgentText.line(note))”, according to the agent")
                    .font(.ui(12.5)).foregroundStyle(Palette.gris)
                    .lineLimit(1)
            }
        }
    }

    private func status(_ agent: AgentItem) -> String {
        switch agent.status {
        case "active": return String(localized: "Has access")
        case "denied": return String(localized: "Denied")
        case "revoked": return String(localized: "Revoked")
        default: return String(localized: "Waiting")
        }
    }

    /// «Revoked», what is left of the key change, and «Finish».
    @ViewBuilder
    private func revocation(_ agent: AgentItem) -> some View {
        let flow = model.revocationFlows[agent.id]
        let left = model.keysLeft(of: agent.id, listed: listed)
        if model.info?.revocationsUnreadable == true, agent.status == "revoked", flow == nil {
            // What is left can't be told: never nothing, never «Done».
            RevocationBand(text: model.info?.revocationsNewer == true ? RevokeWords.newerRecord : RevokeWords.unreadableRecord(agent.id),
                           flow: nil, left: nil, finish: nil)
                .padding(.top, 20)
        } else if let text = RevokeWords.state(flow, left: left) {
            RevocationBand(text: text, flow: flow, left: left,
                           finish: RevokeWords.canFinish(flow, left: left) ? { Task { await model.finishKeys(of: agent.id, left: left) } } : nil)
                .padding(.top, 20)
        }
    }

    @ViewBuilder
    private func actions(_ agent: AgentItem, grant: GrantEditorInfo?) -> some View {
        HStack(spacing: 10) {
            if grant?.editable == true {
                Button("Change permissions…") { model.changingGrant = GrantChangeRequest(agentId: agent.id) }
                    .buttonStyle(PrimaryButtonStyle(compact: true))
                    .fixedSize()
            }
            Button("Revoke…") { model.revoking = RevokeRequest(agentId: agent.id) }
                .buttonStyle(SecondaryButtonStyle(compact: true, danger: true))
                .fixedSize()
        }
    }

    // MARK: Loading

    /// The agent, then what is left of its revocation and its grant, each
    /// on its own: neither failing hides the agent or «Revoke…».
    private func load() async {
        let id = agentId
        if installer.system.refusal(for: installer.paths) == nil {
            isLocal = LocalAgents.ids(in: installer.paths.klavHome).contains(id)
        }
        do {
            let (agents, listed) = try await model.agentsAndRevocations()
            agent = agents.first { $0.agent.id == id }
            self.listed = listed
            problem = agent == nil ? String(localized: "This agent isn’t in your account any more.") : nil
        } catch KlavError.Locked {
            model.refresh()
            return
        } catch {
            problem = describe(error)
            return
        }
        if agent?.agent.status == "active" {
            do {
                grant = try await model.run { try $0.grantEditor(id: id) }
                grantProblem = nil
            } catch {
                grant = nil
                grantProblem = String(localized: "Klav couldn’t read this agent’s permissions: \(describe(error))")
            }
        } else {
            grant = nil
            grantProblem = nil
        }
        confirmIfFinished()
    }

    /// A key change the person asked for, which `klavd` finished by itself
    /// after an unlock (P11), on an older `klavd`: one more call, which
    /// changes nothing, gives the report that says «Done». Never when the
    /// box was unchecked: that call would change keys (P7).
    private func confirmIfFinished() {
        guard !confirmed, model.confirmsByItself(agentId, listed: listed) else { return }
        confirmed = true
        Task { await model.finishKeys(of: agentId) }
    }
}

/// What a revocation is at: red on the left, the state, one block per
/// project (changed in ink), and «Finish» when something is left.
struct RevocationBand: View {
    let text: String
    let flow: RevocationFlow?
    let left: RevocationInfo?
    let finish: (() -> Void)?

    var body: some View {
        HStack(spacing: 0) {
            Rectangle().fill(flow?.stage == .done ? Palette.tinta : Palette.rojo).frame(width: 2)
            VStack(alignment: .leading, spacing: 8) {
                HStack(alignment: .firstTextBaseline, spacing: 12) {
                    Text(verbatim: text).font(.ui(14, .medium)).foregroundStyle(Palette.tinta)
                        .fixedSize(horizontal: false, vertical: true)
                    Spacer(minLength: 8)
                    if let finish {
                        SmallAction(title: "Finish", action: finish)
                    }
                }
                if let left, left.projects > 0 {
                    ProjectBlocks(done: Int(left.rotated), total: Int(left.projects))
                }
                if let why = left?.lastError ?? flow?.failed {
                    Text(verbatim: why).font(.ui(12)).foregroundStyle(Palette.gris)
                        .fixedSize(horizontal: false, vertical: true)
                        .textSelection(.enabled)
                }
            }
            .padding(.vertical, 10)
            .padding(.horizontal, 12)
        }
        .background(Palette.niebla)
        .accessibilityElement(children: .combine)
    }
}

/// One square per project of a key change: changed ones in ink. No
/// smooth transitions, like the code's time.
struct ProjectBlocks: View {
    let done: Int
    let total: Int

    var body: some View {
        HStack(spacing: 3) {
            ForEach(0..<max(1, total), id: \.self) { i in
                Rectangle()
                    .fill(i < done ? Palette.tinta : Palette.papel)
                    .overlay(Rectangle().strokeBorder(Palette.tinta.opacity(i < done ? 0 : 0.5), lineWidth: 1))
                    .frame(width: 12, height: 12)
            }
        }
        .transaction { $0.animation = nil }
        .accessibilityHidden(true)
    }
}

// MARK: - Permissions

/// «Permissions»: the grant in words. The editor's model when it fits;
/// else the rules as signed, and what changes them.
struct PermissionsSection: View {
    let grant: GrantEditorInfo

    /// This Mac can't tell what the grant says (an older `klavd`, or a grant
    /// it can't read): «unknown», never «none».
    private var unknown: Bool { GrantWords.grantUnknown(grant) }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            SectionLabel("Permissions").padding(.bottom, 10)
            FieldBlock {
                row(String(localized: "Projects")) {
                    if unknown {
                        Text("Unknown").font(.ui(13)).foregroundStyle(Palette.gris)
                    } else if grant.projects.isEmpty {
                        Text("None").font(.ui(13)).foregroundStyle(Palette.gris)
                    } else {
                        VStack(alignment: .trailing, spacing: 2) {
                            ForEach(grant.projects, id: \.projectId) { p in
                                Text(verbatim: place(p)).font(.ui(13)).foregroundStyle(Palette.tinta)
                            }
                        }
                    }
                }
                if let policy = grant.editor {
                    ForEach(policy.permissions, id: \.permission) { setting in
                        Rule()
                        row(GrantWords.permissionTitle(setting.permission)) {
                            if setting.permission == "fill" && !policy.fillSites.isEmpty {
                                Text("Only on \(policy.fillSites.joined(separator: ", "))")
                                    .font(.ui(13)).foregroundStyle(Palette.tinta)
                                    .multilineTextAlignment(.trailing)
                            } else {
                                EffectLadder(effect: setting.effect ?? setting.defaultEffect, isDefault: setting.effect == nil)
                            }
                        }
                    }
                    Rule()
                    row(String(localized: "Hours")) { value(GrantWords.hours(policy.hours)) }
                    Rule()
                    row(String(localized: "Expires")) { value(GrantWords.expiry(policy.expiresAtSecs)) }
                } else {
                    ForEach(Array(grant.rules.enumerated()), id: \.offset) { _, rule in
                        Rule()
                        row(GrantWords.permissionTitle(rule.permission)) {
                            VStack(alignment: .trailing, spacing: 3) {
                                EffectLadder(effect: rule.effect, isDefault: false)
                                if let only = conditions(rule) {
                                    Text(verbatim: only).font(.ui(12)).foregroundStyle(Palette.gris)
                                        .multilineTextAlignment(.trailing)
                                }
                            }
                        }
                    }
                    if grant.rules.isEmpty {
                        Rule()
                        row(String(localized: "Rules")) {
                            value(unknown ? String(localized: "Unknown") : String(localized: "Klav’s defaults"))
                        }
                    }
                    if grant.expiresAtSecs != nil {
                        Rule()
                        row(String(localized: "Expires")) { value(GrantWords.expiry(grant.expiresAtSecs)) }
                    }
                }
            }
            if let kind = grant.readOnly {
                let (text, command) = GrantWords.readOnly(kind, agent: GrantWords.commandAgent(grant.agentId))
                VStack(alignment: .leading, spacing: 6) {
                    Text(verbatim: text).font(.ui(13)).foregroundStyle(Palette.tinta)
                        .fixedSize(horizontal: false, vertical: true)
                    if let command {
                        Text(verbatim: command).font(.mono(12)).foregroundStyle(Palette.gris)
                            .textSelection(.enabled)
                    }
                }
                .padding(.top, 12)
            }
        }
    }

    private func place(_ p: GrantedProjectInfo) -> String {
        p.project.isEmpty ? AgentText.idPrefix(p.projectId) : "\(p.vault)/\(p.project)"
    }

    private func conditions(_ rule: RuleInfo) -> String? {
        var parts: [String] = []
        if !rule.sites.isEmpty { parts.append(String(localized: "on \(rule.sites.joined(separator: ", "))")) }
        if !rule.tags.isEmpty { parts.append(String(localized: "items tagged \(rule.tags.joined(separator: ", "))")) }
        if rule.places > 0 { parts.append(String(localized: "in some vaults or projects")) }
        if !rule.hours.isEmpty { parts.append(GrantWords.hours(rule.hours)) }
        if let end = rule.expiresAtSecs { parts.append(String(localized: "until \(GrantWords.expiry(end))")) }
        if rule.more { parts.append(String(localized: "and more conditions")) }
        return parts.isEmpty ? nil : parts.joined(separator: " · ")
    }

    private func value(_ text: String) -> some View {
        Text(verbatim: text).font(.ui(13)).foregroundStyle(Palette.tinta).multilineTextAlignment(.trailing)
    }

    private func row<V: View>(_ title: String, @ViewBuilder _ value: () -> V) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 12) {
            Text(verbatim: title).font(.ui(13)).foregroundStyle(Palette.gris)
            Spacer(minLength: 12)
            value()
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
    }
}

/// Allow · ask · deny, as three squares: the effect in force filled. A
/// default (no rule) is filled in mist, so a rule and a default read
/// apart. With `pick`, the cells are the control.
struct EffectLadder: View {
    let effect: String
    let isDefault: Bool
    var pick: ((String) -> Void)?

    static let effects = ["allow", "ask", "deny"]

    var body: some View {
        HStack(spacing: 0) {
            ForEach(Self.effects, id: \.self) { e in
                cell(e)
                if e != Self.effects.last { Rectangle().fill(Palette.tinta.opacity(0.35)).frame(width: 1, height: 22) }
            }
        }
        .overlay(Rectangle().strokeBorder(Palette.tinta.opacity(0.35), lineWidth: 1))
        .fixedSize()
        .accessibilityElement(children: pick == nil ? .ignore : .contain)
        .accessibilityLabel(pick == nil ? Text(verbatim: GrantWords.effect(effect, isDefault: isDefault)) : Text(verbatim: ""))
    }

    @ViewBuilder
    private func cell(_ e: String) -> some View {
        let on = e == effect
        let label = Text(verbatim: GrantWords.effect(e))
            .font(.ui(11.5, on ? .medium : .regular))
            .foregroundStyle(on ? (isDefault ? Palette.tinta : Palette.botonTexto) : Palette.gris)
            .frame(width: 62, height: 22)
            .background(on ? (isDefault ? Palette.niebla : (e == "allow" ? Palette.cobalto : Palette.tinta)) : Palette.papel)
        if let pick {
            Button { pick(e) } label: { label.contentShape(Rectangle()) }
                .buttonStyle(.plain)
                .accessibilityAddTraits(on ? .isSelected : [])
        } else {
            label
        }
    }
}
