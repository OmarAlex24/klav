import Foundation
import SwiftUI

/// What Development shows of the model: the pauses, the last use of an
/// agent and the checks on a registration (ADR 0033 §7, §8, E2.2).
extension MacModel {
    // MARK: Pauses (§7)

    /// The pauses in effect, as `klavd` says in `status`, also while locked.
    var pauses: [PauseInfo] {
        let now = Int64(Date().timeIntervalSince1970 * 1000)
        return (info?.agentsPaused ?? []).filter { $0.untilMs.map { $0 > now } ?? true }
    }

    /// The pause of every agent, if there is one.
    var everyonePaused: PauseInfo? { pauses.first { $0.agentId == nil } }

    /// The pause of this agent alone, if there is one.
    func pause(ofAgent id: String) -> PauseInfo? { pauses.first { $0.agentId == id } }

    /// «Pause agents»: at once, nothing asked (P2). `minutes` nil: until
    /// the person resumes.
    func pauseAgents(agentId: String? = nil, minutes: Int?) async throws {
        let until = minutes.map { Int64(Date().timeIntervalSince1970 * 1000) + Int64($0) * 60_000 }
        let left = try await run { try $0.pauseAgents(agentId: agentId, untilMs: until) }
        let mine = left.first { $0.agentId == agentId }
        show(Toast(text: mine?.serverUnsupported == true
            ? String(localized: "Paused on this Mac only: the server doesn’t support pausing agents. Update it.")
            : mine?.local == true
            ? String(localized: "Paused on this Mac for now: Klav tells the server as soon as it can.")
            : agentId == nil ? String(localized: "Every agent is paused.") : String(localized: "Paused.")))
        refresh()
        changed()
    }

    /// «Resume»: Touch ID, or the master password where there is none.
    func resumeAgents(agentId: String? = nil) async throws {
        try await withPresence(agentId == nil ? String(localized: "Resume every agent")
                                             : String(localized: "Resume the agent")) { engine, password in
            _ = try engine.resumeAgentsWithPassword(agentId: agentId, password: password)
        } done: { [weak self] in
            self?.show(Toast(text: String(localized: "Agents can use Klav again.")))
            self?.refresh()
        }
    }

    // MARK: Activity (§8)

    /// The newest thing an agent did with an item, for the menu bar.
    func loadLastAgentUse() async {
        guard phase == .unlocked, !accountDeleted else { lastAgentUse = nil; return }
        let recent = try? await run { try $0.auditLog(filter: .all(limit: 40)) }
        lastAgentUse = recent?.first { $0.agentId != nil && $0.action == "agent.access" && $0.itemId != nil }
    }

    /// Activity, filtered by an item or an agent («Open in the log»).
    func openActivity(item: String? = nil, agent: String? = nil) {
        activityItem = item
        activityAgent = agent
        section = .activity
    }

    // MARK: Registrations (E2.2, §3.1)

    /// Another agent of the account with the same name: said on the card,
    /// so a second registration does not pass as the first. This Mac
    /// registering another one with that name comes first (this one is not
    /// it), then one with access, another one waiting, and one denied or
    /// revoked before.
    func sameName(as agent: AgentItem) -> String? {
        let name = agent.name, mine = AgentText.idPrefix(agent.id)
        if launchedRegistrations[agent.id] == nil,
           let launched = launchedRegistrations.first(where: { $0.key != agent.id && $0.value.name == name }) {
            return String(localized: "This Mac registered another agent “\(name)” (ID \(AgentText.idPrefix(launched.key))). This one (ID \(mine)) isn’t it: deny it unless you started it yourself.")
        }
        let others = knownAgents.values.filter { $0.id != agent.id && $0.name == name }
        if others.contains(where: { $0.status == "active" }) {
            return String(localized: "You already have an agent “\(name)” with access. Approve this one only if you started it.")
        }
        if let other = others.first(where: { $0.status == "pending" }) {
            return String(localized: "Another agent “\(name)” is waiting too (ID \(AgentText.idPrefix(other.id))). Approve only the one whose words you saw where you started it.")
        }
        if let other = others.first(where: { ["denied", "revoked"].contains($0.status) }) {
            return other.status == "denied"
                ? String(localized: "You denied an agent “\(name)” before. Approve this one only if you started it.")
                : String(localized: "You revoked an agent “\(name)” before. Approve this one only if you started it.")
        }
        return nil
    }

    /// Whether this Mac launched the registration and the words match
    /// what its own `klav` printed (P5). Nil when the app did not launch
    /// it: the person compares by eye.
    func launchedMatch(_ agent: AgentItem) -> Bool? {
        guard let launched = launchedRegistrations[agent.id] else { return nil }
        return launched.words == agent.pairingWords
    }

    /// After «Connect» wrote (§3.1, P5). A registration this command made
    /// (`registers`) opens Requests; its words are kept in memory to
    /// compare with the request only when the helpers are signed by Klav's
    /// team (`.trusted`, condition 1), checked right before `klav` ran. In
    /// any other case, a Debug build included, the person compares them by
    /// eye. Returns whether the words were kept.
    @discardableResult
    func connected(_ result: ConnectPlan, client: String, verdict: HelperSignature.Verdict?) -> Bool {
        guard let agent = result.agent, agent.registers, let id = agent.id, let words = agent.words else {
            show(Toast(text: String(localized: "\(client) is connected.")))
            return false
        }
        let kept = verdict == .trusted
        if kept { launchedRegistrations[id] = LaunchedRegistration(name: agent.name, words: words) }
        show(Toast(text: String(localized: "Connected. Approve \(agent.name) in Requests.")))
        loadRequests()
        section = .requests
        return kept
    }

    // MARK: The skill (§6)

    /// Once per launch: the copies of the skill that are Klav's and
    /// unchanged follow this app's `klav`. Edited ones are left alone and
    /// shown in Development › Clients. Only from Applications with signed
    /// helpers (`docs/macos.md` §2), and never on the sample vault's real
    /// home (`SampleSafety`).
    func updateSkillAtLaunch(_ installer: Installer) async {
        guard !skillChecked, installer.helpersUntrusted == nil, !installer.helpersMissing,
              installer.placement == .applications,
              installer.system.refusal(for: installer.paths) == nil else { return }
        skillChecked = true
        let tools = ClientTools(installer)
        let report = try? await Task.detached(priority: .utility) {
            _ = try tools.checkSignature()
            return try tools.updateSkill()
        }.value
        let updated = report?.copies.filter { $0.action == "replace" || $0.action == "install" }.count ?? 0
        if updated > 0 { macLog.info("skill updated in \(updated) folders") }
    }

    // MARK: What changed outside Klav (§4, §6, T131, T132)

    /// Once per launch, after the skill: `klav client list` and `klav
    /// skill status`, read only, say what changed outside Klav. Not on the
    /// sample vault's real home (`SampleSafety`), nor with helpers that
    /// aren't Klav's (T120).
    func checkClientsAtLaunch(_ installer: Installer) async {
        guard !clientsChecked, installer.helpersUntrusted == nil, !installer.helpersMissing,
              installer.system.refusal(for: installer.paths) == nil else { return }
        clientsChecked = true
        let tools = ClientTools(installer)
        guard tools.available else { return }
        let found = try? await Task.detached(priority: .utility) {
            (try tools.clients(), try? tools.skillStatus())
        }.value
        if let found { setClientWarnings(clients: found.0, skill: found.1) }
    }

    /// What Clients or the launch just read.
    func setClientWarnings(clients: [ClientRow], skill: SkillStatus?) {
        clientWarnings = ClientWarning.from(clients: clients, skill: skill)
    }

    /// The warnings the person has not left for this launch.
    var shownWarnings: [ClientWarning] { clientWarnings.filter { !dismissedWarnings.contains($0.id) } }

    /// «Leave it» (§4): until the app starts again.
    func leave(_ warning: ClientWarning) { dismissedWarnings.insert(warning.id) }

    /// «See» (§4) or «See the changes» (§6): Clients, with the client's
    /// summary (Klav's entry alone) or the copy's changes.
    func see(_ warning: ClientWarning) {
        switch warning.kind {
        case .entryChanged, .unknownCommand: clientToShow = warning.target
        case .skillEdited: skillToShow = warning.target
        }
        section = .clients
    }
}

/// Something changed outside Klav that the person should know of (ADR 0033
/// §4, §6): never hidden, in red.
struct ClientWarning: Identifiable, Equatable {
    enum Kind: String, Equatable {
        /// Klav's entry in a client was changed since Klav wrote it.
        case entryChanged
        /// Klav's entry runs a program that is not the app's link, its
        /// bundle's `klav` nor the `klav` that answered (T131).
        case unknownCommand
        /// A copy of the skill Klav wrote was edited (T132).
        case skillEdited
    }

    let kind: Kind
    /// The client's ID, or the copy's path.
    let target: String
    let text: String
    var id: String { kind.rawValue + "|" + target }

    static func from(clients: [ClientRow], skill: SkillStatus?) -> [ClientWarning] {
        var out: [ClientWarning] = []
        for row in clients where row.state == "changed" || row.state == "connected" {
            if row.unknownCommand == true {
                out.append(ClientWarning(kind: .unknownCommand, target: row.id,
                                         text: String(localized: "Klav’s entry in \(row.name) runs a program that isn’t this Klav’s.")))
            } else if row.state == "changed" {
                out.append(ClientWarning(kind: .entryChanged, target: row.id,
                                         text: String(localized: "Klav’s entry in \(row.name) changed.")))
            }
        }
        for copy in skill?.copies ?? [] {
            let bundled = skill?.bundledVersion(for: copy)
            guard copy.state == "edited" && !copy.kept(over: bundled) else { continue }
            let place = shortPath(copy.path)
            out.append(ClientWarning(kind: .skillEdited, target: copy.path,
                                     text: copy.version != bundled
                                         ? String(localized: "There’s a new Klav skill; yours in \(place) has changes.")
                                         : String(localized: "Your Klav skill in \(place) has changes.")))
        }
        return out
    }
}

/// Two texts line by line, for «See the changes» (§6): the skill has no
/// secrets, so it is shown whole.
enum LineDiff {
    enum Kind: Equatable { case same, removed, added }

    /// `old` (the person's copy) to `new` (this `klav`'s skill).
    static func lines(from old: String, to new: String) -> [(Kind, String)] {
        let a = old.components(separatedBy: "\n"), b = new.components(separatedBy: "\n")
        var removed = Set<Int>(), added = Set<Int>()
        for change in b.difference(from: a) {
            switch change {
            case .remove(let offset, _, _): removed.insert(offset)
            case .insert(let offset, _, _): added.insert(offset)
            }
        }
        var out: [(Kind, String)] = []
        var i = 0, j = 0
        while i < a.count || j < b.count {
            if i < a.count, removed.contains(i) {
                out.append((.removed, a[i])); i += 1
            } else if j < b.count, added.contains(j) {
                out.append((.added, b[j])); j += 1
            } else if i < a.count, j < b.count {
                out.append((.same, a[i])); i += 1; j += 1
            } else {
                break
            }
        }
        return out
    }
}

/// A registration this app launched in this session (§3.1, P5): the
/// agent's name and the pairing words its own `klav` child printed.
struct LaunchedRegistration: Equatable {
    let name: String
    let words: String
}
