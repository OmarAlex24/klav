import Foundation

/// The audit log in words (ADR 0033 §8.1), on the iPhone and the Mac: what
/// happened, how it went and the alerts. The reason and the site are the
/// agent's words: the views show them in quotes, in one line, marked
/// «according to the agent» (T136).
enum ActivityWords {
    /// An agent wrote the event (its use of an item, its registration), not
    /// the person: told by `byAgent`, never by the name, which the agent
    /// chose. A `klavd` older than `byAgent` sends it false; there, as in
    /// klav-client's filter, an actor other than `you` is an agent.
    static func isAgent(_ e: LogEntryInfo) -> Bool {
        e.byAgent || (e.agentId != nil && e.actor != "you" && !e.actor.isEmpty)
    }

    /// «You», or the agent's name in one line. The person's pause of an
    /// agent names the agent (`agentId`) but is the person's.
    static func actor(_ e: LogEntryInfo) -> String {
        isAgent(e) ? shown(e.actor, max: 40) : String(localized: "You")
    }

    /// What the person did, as one sentence: «You paused an agent»,
    /// «Pausaste un agente». Not «You» and `did`, which Spanish says in the
    /// third person («pausó»), as an agent's.
    static func yours(_ e: LogEntryInfo) -> String {
        switch e.action {
        case "approval.decided":
            return e.outcome == "approve" ? String(localized: "You approved a request") : String(localized: "You denied a request")
        case "task.decided":
            return e.outcome == "approve" ? String(localized: "You approved a task") : String(localized: "You denied a task")
        case "agent.granted": return String(localized: "You gave an agent access")
        case "agent.denied": return String(localized: "You denied an agent")
        case "agent.revoked": return String(localized: "You revoked an agent")
        case "agents.paused":
            return e.agentId == nil ? String(localized: "You paused every agent") : String(localized: "You paused an agent")
        case "agents.resumed":
            return e.agentId == nil ? String(localized: "You resumed every agent") : String(localized: "You resumed an agent")
        case "item.created": return String(localized: "You created it")
        case "item.updated": return String(localized: "You changed it")
        case "item.trashed": return String(localized: "You moved it to the trash")
        case "project.rotated": return String(localized: "You rotated a project key")
        case "passkey.used": return String(localized: "You signed in with a passkey")
        default: return String(localized: "You") + " " + did(e)
        }
    }

    /// The events by day, newest first, as the log lists them.
    static func days(_ lines: [LogEntryInfo]) -> [(String, [LogEntryInfo])] {
        var out: [(String, [LogEntryInfo])] = []
        for entry in lines {
            let day = day(entry.atMs)
            if out.last?.0 == day { out[out.count - 1].1.append(entry) } else { out.append((day, [entry])) }
        }
        return out
    }

    /// «filled it in on github.com», «injected it into a process»… for an
    /// agent; «approved a request», «paused every agent»… for the person.
    static func did(_ e: LogEntryInfo) -> String {
        let site = e.domain.map { self.site($0) }
        switch (e.action, e.permission) {
        case ("agent.access", "fill"):
            return site.map { String(localized: "filled it in on \($0)") } ?? String(localized: "filled it in")
        case ("agent.access", "inject"): return String(localized: "injected it into a process")
        case ("agent.access", "totp"): return String(localized: "generated a one-time code")
        case ("agent.access", "reveal"): return String(localized: "revealed its value")
        case ("agent.access", "list"): return String(localized: "listed items")
        case ("agent.access", "passkey"):
            return site.map { String(localized: "signed in to \($0) with the passkey") } ?? String(localized: "used the passkey")
        case ("agent.access", let p?): return String(localized: "used it (\(p))")
        case ("agent.create", _): return String(localized: "created it")
        case ("agent.update", _): return String(localized: "changed it")
        case ("agent.trash", _): return String(localized: "moved it to the trash")
        case ("agent.ask", _): return String(localized: "asked to change it")
        case ("rotate.started", _): return String(localized: "started changing its password")
        case ("rotate.confirmed", _): return String(localized: "changed its password")
        case ("rotate.cancelled", _): return String(localized: "cancelled a password change")
        case ("agent.registered", _): return String(localized: "asked to join your account")
        case ("task.requested", _): return String(localized: "asked to start a task")
        case ("task.ended", _): return String(localized: "ended a task")
        case ("approval.decided", _):
            return e.outcome == "approve" ? String(localized: "approved a request") : String(localized: "denied a request")
        case ("task.decided", _):
            return e.outcome == "approve" ? String(localized: "approved a task") : String(localized: "denied a task")
        case ("agent.granted", _): return String(localized: "gave an agent access")
        case ("agent.denied", _): return String(localized: "denied an agent")
        case ("agent.revoked", _): return String(localized: "revoked an agent")
        case ("agents.paused", _):
            return e.agentId == nil ? String(localized: "paused every agent") : String(localized: "paused an agent")
        case ("agents.resumed", _):
            return e.agentId == nil ? String(localized: "resumed every agent") : String(localized: "resumed an agent")
        case ("item.created", _): return String(localized: "created it")
        case ("item.updated", _): return String(localized: "changed it")
        case ("item.trashed", _): return String(localized: "moved it to the trash")
        case ("project.rotated", _): return String(localized: "rotated a project key")
        case ("passkey.used", _): return String(localized: "signed in with a passkey")
        default: return e.action
        }
    }

    /// The policy's outcome or the person's decision, when it says
    /// something more than «done»: nil for an allowed use and the person's
    /// own changes.
    static func outcome(_ e: LogEntryInfo) -> (String, Tone)? {
        switch e.outcome {
        case "ask": return (String(localized: "Asked you"), .agent)
        case "deny": return (String(localized: "Denied"), .denied)
        case "approve" where e.action == "approval.decided" || e.action == "task.decided":
            return nil
        default: return nil
        }
    }

    enum Tone { case agent, denied, plain }

    static func alert(_ name: String) -> String {
        switch name {
        case "first_use": return String(localized: "First use")
        case "burst": return String(localized: "Burst")
        case "denied": return String(localized: "Denied")
        default: return name
        }
    }

    /// How a use got through, for «Who used it».
    static func how(_ use: ItemUseInfo) -> String {
        switch use.how {
        case .policy: return String(localized: "Allowed by your policy")
        case .approvedOnce: return String(localized: "Approved once")
        case .approvedFor:
            if let until = use.leaseUntilMs, let at = use.approvedAtMs, until > at {
                return String(localized: "Approved for \(TaskWords.duration(UInt64((until - at) / 1000)))")
            }
            return String(localized: "Approved for a while")
        case .task:
            return use.task.map { String(localized: "Inside the task “\(shown($0))”") } ?? String(localized: "Inside a task")
        case .asked: return String(localized: "Asked you")
        case .denied: return String(localized: "Denied")
        case .other: return ""
        }
    }

    static let permissions = ["fill", "inject", "totp", "reveal", "list", "create", "update", "delete", "passkey", "rotate"]

    static func permissionName(_ p: String) -> String {
        switch p {
        case "fill": return String(localized: "Fill")
        case "inject": return String(localized: "Inject")
        case "totp": return String(localized: "One-time code")
        case "reveal": return String(localized: "Reveal")
        case "list": return String(localized: "List")
        case "create": return String(localized: "Create")
        case "update": return String(localized: "Update")
        case "delete": return String(localized: "Delete")
        case "passkey": return String(localized: "Passkey")
        case "rotate": return String(localized: "Change password")
        default: return p
        }
    }

    static let outcomes = ["allow", "ask", "deny", "approve"]

    static func outcomeName(_ o: String) -> String {
        switch o {
        case "allow": return String(localized: "Allowed")
        case "ask": return String(localized: "Asked you")
        case "deny": return String(localized: "Denied")
        case "approve": return String(localized: "Approved by you")
        default: return o
        }
    }

    /// An agent's words in one line, cut short (T136).
    static func shown(_ text: String, max: Int = 120) -> String { AgentText.line(text, max: max) }

    /// The site the agent named, in quotes and marked as its word (§8.2).
    static func site(_ domain: String) -> String {
        String(localized: "\("“\(shown(domain, max: 60))”") (according to the agent)")
    }

    /// An agent's line under its name, on the iPhone and the Mac: «Last
    /// used 2 min ago · added Nov 3», or «Asked on Nov 1» for one without
    /// access, with the day it asked, never the day it was approved.
    static func seen(_ item: DevAgentInfo, now: Date = Date()) -> String {
        guard item.agent.status == "active" else {
            return String(localized: "Asked on \(date(item.agent.createdAt))")
        }
        let added = date(item.approvedMs ?? item.agent.createdAt)
        guard let last = item.lastSeenMs else { return String(localized: "Not used yet · added \(added)") }
        return String(localized: "Last used \(when(last, now: now)) · added \(added)")
    }

    /// «Nov 3, 2026».
    static func date(_ ms: Int64) -> String {
        Date(timeIntervalSince1970: Double(ms) / 1000).formatted(date: .abbreviated, time: .omitted)
    }

    /// «2 min ago», «Yesterday at 10:40», «Nov 3 at 9:12».
    static func when(_ ms: Int64, now: Date = Date()) -> String {
        let date = Date(timeIntervalSince1970: Double(ms) / 1000)
        let seconds = now.timeIntervalSince(date)
        if seconds < 60 { return String(localized: "just now") }
        if seconds < 3600 { return String(localized: "\(Int(seconds / 60)) min ago") }
        return date.formatted(.relative(presentation: .named))
    }

    static func clock(_ ms: Int64) -> String {
        Date(timeIntervalSince1970: Double(ms) / 1000).formatted(date: .omitted, time: .shortened)
    }

    /// «Today», «Yesterday», «Monday, November 3».
    static func day(_ ms: Int64) -> String {
        let date = Date(timeIntervalSince1970: Double(ms) / 1000)
        let calendar = Calendar.current
        if calendar.isDateInToday(date) { return String(localized: "Today") }
        if calendar.isDateInYesterday(date) { return String(localized: "Yesterday") }
        return date.formatted(.dateTime.weekday(.wide).month(.wide).day())
    }

    /// What «Verify now» checked, and what it warns about.
    static func checked(_ report: VerifyInfo) -> String {
        let note = String(localized: "Checked \(Int64(report.events)) events, \(Int64(report.agentSignatures + report.accountSignatures)) signatures and \(Int64(report.heads)) heads of your devices.")
        return ([note] + warnings(report)).joined(separator: " ")
    }

    /// The warnings of «Verify now», each in one line. Why there was no
    /// head to hold the chain against comes as a code, said in the
    /// interface's language; the rest come in `klav-client`'s words.
    static func warnings(_ report: VerifyInfo) -> [String] {
        (report.unpinned.map { [unpinned($0)] } ?? []) + report.warnings.map { shown($0, max: 200) }
    }

    static func unpinned(_ kind: UnpinnedHead) -> String {
        switch kind {
        case .missing:
            return String(localized: "This device hadn’t verified the log before: the events until now are trusted as the server sent them, checked only against heads your other devices signed.")
        case .unreadable:
            return String(localized: "The head this device pinned can’t be read: the events until now are trusted as the server sent them, checked only against heads your other devices signed.")
        case .otherAccount:
            return String(localized: "The head this device pinned belongs to another account: the events until now are trusted as the server sent them, checked only against heads your other devices signed.")
        }
    }

    /// The item's title from its reference (`klav://Vault/Project/Title`).
    static func title(_ e: LogEntryInfo) -> String? {
        if let reference = e.item { return RequestWords.target(reference).title }
        return e.itemId.map { String(localized: "(deleted) \($0.prefix(8))") }
    }
}

/// The Period filter of Activity (ADR 0033 §8.1), on the iPhone and the Mac.
enum ActivityPeriod: String, CaseIterable, Identifiable {
    case all, today, week, month
    var id: String { rawValue }
    var label: String {
        switch self {
        case .all: return String(localized: "Any time")
        case .today: return String(localized: "Today")
        case .week: return String(localized: "Last 7 days")
        case .month: return String(localized: "Last 30 days")
        }
    }

    /// Where the period starts (Unix ms); nil: any time.
    func since(now: Date = Date()) -> Int64? {
        switch self {
        case .all: return nil
        case .today: return Int64(Calendar.current.startOfDay(for: now).timeIntervalSince1970 * 1000)
        case .week: return Int64(now.addingTimeInterval(-7 * 86_400).timeIntervalSince1970 * 1000)
        case .month: return Int64(now.addingTimeInterval(-30 * 86_400).timeIntervalSince1970 * 1000)
        }
    }
}

extension LogFilterInput {
    /// Every event, newest first, at most `limit`.
    static func all(limit: UInt32? = nil) -> LogFilterInput {
        LogFilterInput(item: nil, agent: nil, vault: nil, sinceMs: nil, untilMs: nil, alerts: false,
                       permissions: [], outcomes: [], text: nil, limit: limit)
    }
}
