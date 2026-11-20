import Foundation
import SwiftUI

// Revoking an agent and changing its permissions from the Mac (ADR 0033,
// amendment of 2026-11-10, F2, F3, F5). The logic is in Rust: `klavd`
// computes the differences, whether they widen, and asks for presence. The
// app shows what it is given and sends back what the person chose.

/// «Revoke…» on an agent.
struct RevokeRequest: Identifiable, Equatable {
    let agentId: String
    var id: String { agentId }
}

/// «Change permissions…» on an agent.
struct GrantChangeRequest: Identifiable, Equatable {
    let agentId: String
    var id: String { agentId }
}

/// A revocation started from this app (F2): the revocation alone first,
/// then the key change. «Done» comes only from a complete report.
struct RevocationFlow: Equatable {
    enum Stage: Equatable {
        /// The first call, without the key change.
        case revoking
        /// Revoked; no key change was asked.
        case revoked
        /// Revoked; its projects' keys are changing.
        case changingKeys
        /// Revoked, and every key asked for changed.
        case done
        /// Revoked, with keys left to change (`failed` says why).
        case keysLeft
    }

    let agentId: String
    var stage: Stage
    /// The person asked to change its projects' keys (P7: checked). Without
    /// it, «Finish» only changes the keys of items granted one by one.
    let changeKeys: Bool
    /// What stopped the key change.
    var failed: String?
    /// `vault/project` still to change, when the last report said.
    var pending: [String] = []
    /// `klavd` changes the keys by itself (`revoke_agent` with
    /// `background`): `status` says how it goes, and the agent leaving it,
    /// while unlocked, is the end.
    var background = false
    /// When the revocation answered: a `status` asked before says nothing
    /// about it.
    var startedAt = Date()
    /// The key change went ahead without the audit log, which may list
    /// another project: never «Done» (T189).
    var logUnchecked = false
    /// Unlocked `status` answers in a row that no longer list the agent.
    /// «Done» takes two: one read alone may race with `klavd` reading its
    /// record at an unlock.
    var absentReads = 0
    /// What the key change skipped because Klav can't reach it (a deleted
    /// project, a vault gone, an item this Mac no longer sees): «Done» then
    /// never says every key changed.
    /// From the report, or from `klavd`'s `status` while it lists the end.
    var skipped = 0

    /// The agent is revoked: everything after the first call.
    var revoked: Bool { stage != .revoking }
}

extension MacModel {
    // MARK: Revoking (F2)

    /// Revokes the agent at once (nothing asked, ADR 0014 §7.1) and, with
    /// `changeKeys`, has `klavd` change its projects' keys in the
    /// background: it answers once the agent is revoked and the key change
    /// is written down, so the change outlives the app, and a lock only
    /// pauses it (P11). The page says «Revoked» as soon as it answers, and
    /// follows the rest in `status` ([`followKeyChanges`]).
    ///
    /// A `klavd` older than that answers nothing for it: then the revocation
    /// alone first, and the key change in a second call, as before.
    ///
    /// Throws only when nothing was revoked (Klav locked, for one: then
    /// «Revoke…» opens again after unlocking, P12).
    func revoke(_ agent: AgentItem, changeKeys: Bool) async throws {
        let id = agent.id
        revocationFlows[id] = RevocationFlow(agentId: id, stage: .revoking, changeKeys: changeKeys)
        let first: RevokeReportInfo
        var background = false
        do {
            if changeKeys, let report = try await run({ try $0.revokeAgentInBackground(id: id) }) {
                first = report
                background = true
            } else {
                first = try await run { try $0.revokeAgent(id: id, rotate: false) }
            }
        } catch {
            revocationFlows[id] = nil
            if case KlavError.Locked = error {
                revokeAfterUnlock = id
                refresh()
            }
            throw error
        }
        let name = AgentText.line(first.agent.name, max: 64)
        show(Toast(text: String(localized: "Revoked. “\(name)” can’t use Klav any more.")))
        changed()
        var flow = RevocationFlow(agentId: id, stage: .revoked, changeKeys: changeKeys)
        flow.background = background
        flow.startedAt = Date()
        flow.logUnchecked = first.logUnchecked
        flow.pending = first.pending
        // What the first call couldn't reach: kept until `klavd` says more.
        flow.skipped = first.skipped.count
        if background {
            // Its projects change in `klavd` now; `failed` here means it
            // never started (it does not know them, or an item's key).
            if let failed = first.failed {
                // Nothing runs in `klavd`: «Finish» asks again.
                flow.stage = .keysLeft
                flow.failed = failed
                flow.background = false
            } else {
                // Items or grants left from the first call are in `klavd`'s
                // record too: `status` lists them until they are done.
                flow.stage = .changingKeys
            }
            revocationFlows[id] = flow
            refresh()
            return
        }
        // Items granted one by one change their keys in the first call
        // (ADR 0036 §18): one left is left whether or not projects change.
        guard first.complete else {
            flow.stage = .keysLeft
            flow.failed = first.failed
            revocationFlows[id] = flow
            return
        }
        revocationFlows[id] = flow
        if changeKeys { await finishKeys(of: id) }
    }

    /// The key change of a revoked agent, or «Finish» after one that
    /// stopped. `klavd` changes one project at a time, without holding the
    /// vault, and never changes a key twice. Without the box checked, only
    /// the keys of items granted one by one: the projects' keys never
    /// change unless the person asked (P7). Without a flow (the app
    /// restarted), what the person chose comes from what `klavd` says is
    /// left (`left`), and when that can't tell, no project's key changes.
    func finishKeys(of id: String, left: RevocationInfo? = nil) async {
        let changeKeys = revocationFlows[id]?.changeKeys ?? RevokeWords.keyChangeAsked(left)
        var flow = revocationFlows[id] ?? RevocationFlow(agentId: id, stage: .revoked, changeKeys: changeKeys)
        flow.stage = .changingKeys
        flow.failed = nil
        // Asked here, the answer is the report: not followed in `status`.
        flow.background = false
        revocationFlows[id] = flow
        do {
            let report = try await run { try $0.revokeAgent(id: id, rotate: changeKeys) }
            // Without the box, only items' keys changed: «Revoked», never
            // a word about every key (P7).
            flow.stage = report.complete ? (changeKeys ? .done : .revoked) : .keysLeft
            flow.failed = report.failed
            flow.pending = report.pending
            flow.logUnchecked = report.logUnchecked
            flow.skipped = max(flow.skipped, report.skipped.count)
        } catch {
            // A lock cuts it: klavd goes on by itself at the next unlock
            // (P11), and the page says what is left meanwhile.
            flow.stage = .keysLeft
            flow.failed = describe(error)
        }
        revocationFlows[id] = flow
        refresh()
        changed()
    }

    /// A key change `klavd` runs by itself, from `status` (asked at
    /// `askedAt`): running, stopped with what stopped it, over as far as
    /// Klav can reach (`needsWork` off: only skipped ones left), or gone.
    /// `klavd`'s record keeps everything left, items and an unread audit log
    /// included, so gone while unlocked, twice in a row, means every key
    /// changed. Locked, `status` keeps the counts of the last unlocked
    /// moment and nothing runs; after a restart it lists nothing until the
    /// unlock, so absence then says nothing. A record `klavd` can't read
    /// says nothing either: never «Done» then.
    func followKeyChanges(_ info: DaemonInfo, askedAt: Date) {
        for (id, flow) in revocationFlows where flow.background && askedAt > flow.startedAt {
            guard flow.stage == .changingKeys || flow.stage == .keysLeft || flow.stage == .done else { continue }
            var next = flow
            if info.revocationsUnreadable {
                next.stage = .keysLeft
                next.absentReads = 0
                next.failed = info.revocationsNewer ? RevokeWords.newerRecord : RevokeWords.unreadableRecord(id)
            } else if let left = info.revocations.first(where: { $0.agentId == id }) {
                next.absentReads = 0
                if left.running {
                    next.stage = .changingKeys
                    next.failed = nil
                } else if !info.unlocked || left.lastError != nil || left.unknownProjects {
                    next.stage = .keysLeft
                    next.failed = left.lastError ?? next.failed
                } else if !left.needsWork {
                    // Only what Klav can't reach is left: the words say which.
                    next.stage = .done
                    next.failed = nil
                    next.pending = []
                    next.skipped = max(flow.skipped, Int(left.skipped))
                } else if flow.stage == .done {
                    // Something came back (a vault restored): not done.
                    next.stage = .keysLeft
                }
            } else if info.unlocked, flow.stage != .done {
                next.absentReads += 1
                if next.absentReads >= 2 {
                    next.stage = .done
                    next.failed = nil
                    next.pending = []
                }
            }
            if next != flow {
                revocationFlows[id] = next
                if next.stage == .done { changed() }
            }
        }
    }

    /// Where the master-password prompt shows: over «Change permissions…»
    /// while it is open, otherwise over the window. Never both, never neither.
    func passwordPromptHere(inSheet: Bool) -> Binding<PasswordPrompt?> {
        Binding(
            get: { [weak self] in
                guard let self, (self.changingGrant != nil) == inSheet else { return nil }
                return self.passwordPrompt
            },
            set: { [weak self] value in
                guard let self else { return }
                // Closing always clears: a correct password closes
                // «Change permissions…» first (`done`), and the prompt's own
                // close comes after, from a place no longer shown.
                if value == nil {
                    self.passwordPrompt = nil
                } else if (self.changingGrant != nil) == inSheet {
                    self.passwordPrompt = value
                }
            })
    }

    /// «Pause every agent now» from the lock screen: what went wrong, or
    /// nil. Never silent (the person may be stopping an agent in a hurry).
    func pauseEveryAgentNow() async -> String? {
        do {
            try await pauseAgents(minutes: nil)
            return nil
        } catch {
            return String(localized: "Klav couldn’t pause the agents: \(describe(error))")
        }
    }

    /// What «Revoke…» shows when Klav couldn't say what the agent saw: the
    /// agent from the list, its projects unknown, and why. Revoking (and
    /// the key change, P7) never waits on that read.
    func exposureUnknown(of id: String, because error: Error) async throws -> ExposureInfo {
        let agent = try await run { try $0.agents() }.first { $0.id == id }
        guard let agent else { throw error }
        return ExposureInfo(agent: agent, projects: [], items: [], denied: 0,
                            logWarning: describe(error),
                            cost: KeyChangeCostInfo(items: 0, otherAgents: [], itemsAtLeast: true, othersAtLeast: true),
                            projectsUnknown: true)
    }

    /// The agents, and what is left of their revocations. The second never
    /// fails the first: without it, the pages only say less (a `klavd` that
    /// could not answer, or an older one).
    func agentsAndRevocations() async throws -> ([DevAgentInfo], [RevocationInfo]) {
        let agents = try await run { try $0.devAgents() }
        let listed = (try? await run { try $0.agentRevocations() }) ?? []
        return (agents, listed)
    }

    /// Whether the page finishes by itself a key change `klavd` ended in
    /// the background: only one the person asked for (P7), followed with
    /// the second call (an older `klavd`), and with nothing left listed.
    func confirmsByItself(_ id: String, listed: [RevocationInfo]) -> Bool {
        guard let flow = revocationFlows[id] else { return false }
        return flow.changeKeys && !flow.background && flow.stage == .keysLeft
            && keysLeft(of: id, listed: listed) == nil
    }

    /// After unlocking: «Revoke…» opens again where it was (P12).
    func resumeRevoking() {
        guard let id = revokeAfterUnlock else { return }
        revokeAfterUnlock = nil
        section = .agents
        openAgent = id
        revoking = RevokeRequest(agentId: id)
    }

    /// What `klavd` says is left of a revocation's key change: its
    /// progress in `status` (also while it runs), else what `agent_revocations`
    /// listed.
    func keysLeft(of id: String, listed: [RevocationInfo]) -> RevocationInfo? {
        info?.revocations.first { $0.agentId == id } ?? listed.first { $0.agentId == id }
    }

    // MARK: Changing the grant (F3)

    /// The sheet of a change: only the differences. Signs nothing.
    func prepareGrantChange(agent: String, change: GrantChangeInput) async throws -> GrantChangePreviewInfo {
        try await run { try $0.grantChangePrepare(id: agent, change: change) }
    }

    /// Signs the change the sheet showed. `klavd` prepares it again, and
    /// refuses if the grant changed meanwhile; when the change widens it
    /// asks for Touch ID, or for the master password where there is none.
    /// `done` gets the report once it is signed.
    func applyGrantChange(_ preview: GrantChangePreviewInfo, change: GrantChangeInput,
                          done: @escaping @MainActor (GrantChangeReportInfo) -> Void) async throws {
        let id = preview.agentId, digest = preview.digest
        let name = AgentText.line(preview.name, max: 64)
        try await withPresenceResult(String(localized: "Let “\(name)” do more"), { engine, password in
            try engine.grantChangeApplyWithPassword(id: id, change: change, digest: digest, password: password)
        }, done: { [weak self] report in
            self?.show(Toast(text: GrantWords.changed(report)))
            done(report)
        })
    }
}

// MARK: - Words

/// How the grant's parts read, in the words `klavd`'s Touch ID dialog uses
/// for the same permissions (F4).
enum GrantWords {
    /// The toast after a grant change: the grant is in force; a key change
    /// that stopped says why, never an empty list (fourth re-check, F6).
    static func changed(_ report: GrantChangeReportInfo) -> String {
        if report.complete { return String(localized: "Permissions changed.") }
        if let failed = report.failed {
            return String(localized: "Permissions changed, but the key change of the projects taken away stopped: \(failed)")
        }
        return String(localized: "Permissions changed, but some keys didn’t: \(report.pending.joined(separator: ", "))")
    }

    /// The editor's permissions, in its order.
    static let permissions = ["list", "fill", "inject", "totp", "reveal", "create", "update", "delete"]

    /// A permission inside a sentence or a line of the sheet.
    static func permission(_ p: String) -> String {
        switch p {
        case "list": return String(localized: "list", comment: "A permission in an agent's grant")
        case "fill": return String(localized: "fill", comment: "A permission on a task card")
        case "inject": return String(localized: "inject", comment: "A permission on a task card")
        case "totp": return String(localized: "code", comment: "A permission in an agent's grant: one-time codes")
        case "reveal": return String(localized: "reveal", comment: "A permission in an agent's grant")
        case "create": return String(localized: "create", comment: "A permission in an agent's grant")
        case "update": return String(localized: "edit", comment: "A permission in an agent's grant: change items")
        case "delete": return String(localized: "delete", comment: "A permission in an agent's grant")
        default: return p
        }
    }

    /// A permission as a row's title in «Permissions».
    static func permissionTitle(_ p: String) -> String {
        switch p {
        case "list": return String(localized: "See the list")
        case "fill": return String(localized: "Fill in the browser")
        case "inject": return String(localized: "Inject into commands")
        case "totp": return String(localized: "One-time codes")
        case "reveal": return String(localized: "See values")
        case "create": return String(localized: "Create items")
        case "update": return String(localized: "Edit items")
        case "delete": return String(localized: "Delete items")
        default: return p
        }
    }

    static func effect(_ e: String) -> String {
        switch e {
        case "allow": return String(localized: "allow", comment: "What a permission does in a grant")
        case "ask": return String(localized: "ask", comment: "What a permission does in a grant: ask you first")
        case "deny": return String(localized: "deny", comment: "What a permission does in a grant")
        default: return e
        }
    }

    /// «ask (default)»: without a rule, the permission's default.
    static func effect(_ e: String, isDefault: Bool) -> String {
        isDefault ? String(localized: "\(effect(e)) (default)") : effect(e)
    }

    static func sites(_ list: [String]) -> String {
        list.isEmpty ? String(localized: "any site") : list.joined(separator: ", ")
    }

    static func hours(_ list: [TimeWindowInfo]) -> String {
        list.isEmpty ? String(localized: "always") : list.map(window).joined(separator: "; ")
    }

    static func expiry(_ secs: UInt64?) -> String {
        guard let secs else { return String(localized: "never") }
        return Date(timeIntervalSince1970: TimeInterval(secs)).formatted(date: .abbreviated, time: .omitted)
    }

    /// «Mon–Fri 09:00–18:00», with its UTC offset only when it is not this
    /// Mac's.
    static func window(_ w: TimeWindowInfo) -> String {
        let span = "\(clock(w.startMinutes))–\(clock(w.endMinutes))"
        var text = "\(days(w.days)) \(span)"
        if Int(w.utcOffsetMinutes) * 60 != TimeZone.current.secondsFromGMT() {
            let sign = w.utcOffsetMinutes < 0 ? "−" : "+"
            let abs = Int(w.utcOffsetMinutes.magnitude)
            text += String(format: " UTC%@%02d:%02d", sign, abs / 60, abs % 60)
        }
        return text
    }

    static let weekdays = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]

    /// The short name of `mon` … `sun`, in the interface's language.
    static func dayName(_ day: String) -> String {
        guard let index = weekdays.firstIndex(of: day) else { return day }
        // `shortWeekdaySymbols` starts on Sunday.
        return Calendar.current.shortWeekdaySymbols[(index + 1) % 7]
    }

    /// «every day», «Mon–Fri», or «Mon, Wed, Fri».
    static func days(_ list: [String]) -> String {
        guard !list.isEmpty, Set(list).count < 7 else { return String(localized: "every day") }
        let indexes = list.compactMap { weekdays.firstIndex(of: $0) }
        if indexes.count >= 3, indexes == Array(indexes[0]...indexes[0] + indexes.count - 1) {
            return "\(dayName(list.first!))–\(dayName(list.last!))"
        }
        return list.map(dayName).joined(separator: ", ")
    }

    static func clock(_ minutes: UInt16) -> String {
        String(format: "%02d:%02d", minutes / 60, minutes % 60)
    }

    /// One line of the sheet: before → after.
    static func line(_ kind: ChangeKind) -> String {
        switch kind {
        case .projectAdded(let project): return "+ \(project)"
        case .projectRemoved(let project): return "− \(project)"
        case let .permission(p, before, beforeDefault, after, afterDefault):
            return "\(permission(p)): \(effect(before, isDefault: beforeDefault)) → \(effect(after, isDefault: afterDefault))"
        case let .fillSites(before, after):
            return String(localized: "Where it fills: \(sites(before)) → \(sites(after))")
        case let .hours(before, after):
            return String(localized: "Hours: \(hours(before)) → \(hours(after))")
        case let .expires(before, after):
            return String(localized: "Expires: \(expiry(before)) → \(expiry(after))")
        case .rules:
            return String(localized: "Rules the app doesn’t edit changed")
        }
    }

    /// This Mac can't tell what the grant says: from a `klavd` older than
    /// the editor, or a grant it can't read.
    static func grantUnknown(_ grant: GrantEditorInfo) -> Bool {
        grant.readOnly == .olderKlavd || grant.readOnly == .unreadable
    }

    /// The agent in a terminal command: its ID, which the CLI takes like a
    /// name. The name is the agent's own words (T136): it may hold spaces,
    /// quotes or another agent's name.
    static func commandAgent(_ id: String) -> String { id }

    /// Why a grant cannot be changed here, and what changes it.
    static func readOnly(_ kind: ReadOnlyKind, agent: String) -> (String, String?) {
        switch kind {
        case .rules:
            return (String(localized: "This grant has rules the app can’t edit (tags, vaults or projects in a rule, an expiry per rule). The app shows them and never signs a simpler copy."),
                    "klav agent approve \(agent) --policy-file <file>")
        case .proxy:
            return (String(localized: "This is the credential proxy’s grant. The terminal changes it."), "klav proxy")
        case .issuer:
            return (String(localized: "This agent starts sandboxes, and its grant carries the proxy’s address. The terminal changes it."),
                    "klav proxy issuer add \(agent)")
        case .unreadable:
            return (String(localized: "This Mac can’t read this grant whole, so it doesn’t change it. Update Klav."), nil)
        case .olderKlavd:
            return (String(localized: "Klav’s background service is older than changing permissions from the app. Update Klav, or use the terminal."),
                    "klav agent approve \(agent)")
        case .notActive, .noGrant:
            return (String(localized: "This agent has no grant to change."), nil)
        }
    }
}

/// The review sheet as the person reads it: the lines `klavd` sent, in its
/// order, and the sentence on what signing asks.
struct GrantReview: Equatable {
    struct Row: Equatable {
        let text: String
        let widens: Bool
    }

    let rows: [Row]
    let headline: String

    init(_ preview: GrantChangePreviewInfo, touchID: Bool) {
        rows = preview.lines.map { Row(text: GrantWords.line($0.kind), widens: $0.widens) }
        let name = AgentText.line(preview.name, max: 64)
        if preview.widens {
            headline = touchID
                ? String(localized: "This lets “\(name)” do more: Klav will ask for Touch ID.")
                : String(localized: "This lets “\(name)” do more: Klav will ask for your master password.")
        } else {
            headline = touchID
                ? String(localized: "This only narrows what “\(name)” can do: no Touch ID needed.")
                : String(localized: "This only narrows what “\(name)” can do: nothing to confirm.")
        }
    }
}

/// What a revocation's state reads as on the agent's page and in the list.
enum RevokeWords {
    /// The state, with what `klavd` says is left (`left`).
    static func state(_ flow: RevocationFlow?, left: RevocationInfo?) -> String? {
        if let left, left.narrowed {
            // The agent is active: the projects taken away from it.
            return narrowing(left)
        }
        if let left, left.running {
            return String(localized: "Revoked. Changing keys: \(Int64(left.rotated)) of \(Int64(left.projects)) projects")
        }
        switch flow?.stage {
        case .revoking: return String(localized: "Revoking…")
        case .changingKeys: return String(localized: "Revoked. Changing keys…")
        case .done:
            if let left, left.skipped > 0 { return outOfReach(left, flow) }
            if let flow, flow.skipped > 0 { return unreachable(flow.skipped) }
            return String(localized: "Revoked. Done: every key changed.")
        case .keysLeft, .revoked, nil:
            if let left { return revocation(left, flow) }
            if flow?.stage == .keysLeft { return String(localized: "Revoked. Keys left to change") }
            return flow == nil ? nil : String(localized: "Revoked")
        }
    }

    /// What `klavd` says is left of a revocation, most pressing first.
    private static func revocation(_ left: RevocationInfo, _ flow: RevocationFlow?) -> String {
        if left.unknownProjects {
            return String(localized: "Revoked. Klav doesn’t know which projects it had.")
        }
        if left.toChange > 0 {
            return String(localized: "Revoked. Keys left to change (\(Int64(left.toChange)) of \(Int64(left.projects)))")
        }
        if left.items > 0 {
            return String(localized: "Revoked. Some items shared with it one by one still need a new key.")
        }
        if left.regrants > 0 {
            return String(localized: "Revoked. Other agents still need their new grant.")
        }
        if left.logUnchecked {
            return String(localized: "Revoked. Klav hasn’t read the audit log yet, which lists every project it had.")
        }
        if left.skipped > 0 { return outOfReach(left, flow) }
        return String(localized: "Revoked. Keys left to change")
    }

    /// `klavd` can't read its record of owed key changes: what is left
    /// can't be told, and the terminal says why.
    static func unreadableRecord(_ id: String) -> String {
        String(localized: "Klav can’t read its record of the key changes it owes, so it can’t tell what is left. In the terminal, klav agent show \(id) says why.")
    }

    /// What `klavd` says is out of reach. Without the key change, only
    /// items shared one by one changed keys: never a word about every key
    /// (P7, fifth re-check, 1). An older `klavd` never sends
    /// `withoutKeyChange`: then this Mac's flow tells, and without one, a
    /// revocation with no project to change gets the words that claim no
    /// key changed. A project means the key change was asked: `klavd`
    /// counts projects only for one (review of #308, N2).
    private static func outOfReach(_ left: RevocationInfo, _ flow: RevocationFlow?) -> String {
        if left.withoutKeyChange || flow?.changeKeys == false || (flow == nil && left.projects == 0) {
            return String(localized: "Revoked. \(Int64(left.skipped)) items shared with it one by one are out of Klav’s reach, so their keys didn’t change (their vault is gone, or this Mac no longer sees them). If one comes back, Klav changes its key then; an item deleted for good never comes back.")
        }
        return unreachable(Int(left.skipped))
    }

    /// Over as far as Klav can reach: never «every key changed».
    private static func unreachable(_ skipped: Int) -> String {
        String(localized: "Revoked. Klav changed every key it can reach; \(Int64(skipped)) are out of its reach (their vault or project is gone, or this Mac no longer sees them).")
    }

    /// A newer Klav wrote `klavd`'s record of owed key changes: updating
    /// Klav reads it again. Never "move it aside", which would lose it.
    static var newerRecord: String {
        String(localized: "A newer version of Klav wrote its record of the key changes it owes, and this one can’t read it. Update Klav to see what is left.")
    }

    /// A key change of projects taken away from an active agent.
    private static func narrowing(_ left: RevocationInfo) -> String {
        if left.running {
            return String(localized: "Changing the keys of the projects taken away: \(Int64(left.rotated)) of \(Int64(left.projects))")
        }
        if !left.needsWork, left.skipped > 0 {
            return String(localized: "Klav changed the keys of the projects taken away that it can reach; \(Int64(left.skipped)) are out of its reach.")
        }
        return String(localized: "Keys of the projects taken away left to change (\(Int64(left.toChange)) of \(Int64(left.projects))). Klav tries again each time you unlock.")
    }

    /// Whether the person asked for the projects' keys to change, for a
    /// revocation this Mac has no flow for. `withoutKeyChange` says it was
    /// declined. An older `klavd` doesn't send it, but it counts projects,
    /// and writes unknown projects, an unread log or grants to issue again,
    /// only for a revocation with the key change. Nothing to tell it from:
    /// no key change, never one nobody asked for (P7).
    static func keyChangeAsked(_ left: RevocationInfo?) -> Bool {
        guard let left, !left.withoutKeyChange, !left.narrowed else { return false }
        return left.projects > 0 || left.unknownProjects || left.logUnchecked || left.regrants > 0
    }

    /// Whether «Finish» shows: something is left that it can do, and
    /// nothing runs. What it finishes is what the person chose
    /// (`finishKeys`). Never for a narrowing: «Finish» revokes, and the
    /// agent is active (`klavd` goes on with it at each unlock).
    static func canFinish(_ flow: RevocationFlow?, left: RevocationInfo?) -> Bool {
        if left?.running == true || flow?.stage == .changingKeys || flow?.stage == .revoking { return false }
        if let left {
            if left.narrowed { return false }
            return left.needsWork || left.unknownProjects || left.lastError != nil
        }
        return flow?.stage == .keysLeft
    }

    /// «Also change its projects’ keys» shows when there are projects, or
    /// when this Mac can’t tell which (`KeyChangeWords`, shared with the
    /// iPhone).
    static func offersKeyChange(_ seen: ExposureInfo) -> Bool { KeyChangeWords.offersKeyChange(seen) }

    /// What «Also change its projects’ keys» costs (`KeyChangeWords`).
    static func cost(_ cost: KeyChangeCostInfo, unknownProjects: Bool) -> String {
        KeyChangeWords.cost(cost, unknownProjects: unknownProjects)
    }
}
