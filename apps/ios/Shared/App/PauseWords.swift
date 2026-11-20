import Foundation

/// How long «Pause agents» lasts, on the iPhone and the Mac.
enum PauseLength: Int, CaseIterable, Identifiable {
    case quarter = 15, hour = 60, untilResumed = 0
    var id: Int { rawValue }
    var minutes: Int? { self == .untilResumed ? nil : rawValue }
    var label: String {
        switch self {
        case .quarter: return String(localized: "15 min")
        case .hour: return String(localized: "1 hour")
        case .untilResumed: return String(localized: "Until I resume")
        }
    }
}

/// The pauses in effect (ADR 0033 §7) and what stops each agent: the
/// pauses this device keeps, each signed by the account, and what the
/// server says of each agent in `devAgents`.
struct Pauses: Equatable {
    /// Only the ones still in effect at `now`.
    let list: [PauseInfo]
    let now: Int64

    init(_ list: [PauseInfo], now: Int64 = Pauses.now()) {
        self.now = now
        self.list = list.filter { $0.untilMs.map { $0 > now } ?? true }
    }

    static func now() -> Int64 { Int64(Date().timeIntervalSince1970 * 1000) }

    /// The pause of every agent, if there is one.
    var everyone: PauseInfo? { list.first { $0.agentId == nil } }

    /// The pause of this agent alone, if there is one.
    func own(_ agentId: String) -> PauseInfo? { list.first { $0.agentId == agentId } }

    /// What stops `item` now: its own pause first, then every agent's
    /// (a pause made a moment ago, or one only on this Mac), then what the
    /// server listed. Only an agent with access can be paused.
    func stopping(_ item: DevAgentInfo) -> AgentPauseInfo? {
        guard item.agent.status == "active" else { return nil }
        return signed(item) ?? listed(item)
    }

    /// What the server listed for the agent, if it hasn't ended by `now`:
    /// offline, that list can be older than the pause's end.
    func listed(_ item: DevAgentInfo) -> AgentPauseInfo? {
        item.paused.flatMap { pause in pause.untilMs.map { $0 > now } ?? true ? pause : nil }
    }

    /// Whether the server says of an agent with access that it is paused
    /// when the signed pauses say it isn't, or the other way round: another
    /// device paused or resumed since this one last synced.
    func disagrees(with agents: [DevAgentInfo]) -> Bool {
        agents.contains { $0.agent.status == "active" && (listed($0) != nil) != (signed($0) != nil) }
    }

    private func signed(_ item: DevAgentInfo) -> AgentPauseInfo? {
        if let own = own(item.agent.id) {
            return AgentPauseInfo(everyone: false, sinceMs: own.sinceMs, untilMs: own.untilMs)
        }
        if let all = everyone {
            return AgentPauseInfo(everyone: true, sinceMs: all.sinceMs, untilMs: all.untilMs)
        }
        return nil
    }
}

enum PauseWords {
    /// «Since 10:31 · until 11:31, 47 min left» or «… until you resume».
    static func span(_ pause: PauseInfo) -> String {
        let since = ActivityWords.clock(pause.sinceMs)
        guard let until = pause.untilMs else {
            return String(localized: "Since \(since) · until you resume")
        }
        return String(localized: "Since \(since) · until \(ActivityWords.clock(until)), \(minutesUntil(until)) min left")
    }

    /// «Every agent is paused», or «… on this Mac» while the pause has not
    /// reached the server (§7.2, §7.3): never «everywhere» when it isn't.
    /// The iPhone signs and sends a pause at once, so it is never local.
    static func title(_ pause: PauseInfo) -> String {
        pause.local || pause.serverUnsupported ? String(localized: "Every agent is paused on this Mac")
                                               : String(localized: "Every agent is paused")
    }

    /// Said when the pause has not reached the server. Locked, klavd has
    /// nothing to sign it with: unlocking sends it (§7.3).
    static func whereItHolds(_ pause: PauseInfo, locked: Bool = false) -> String? {
        if pause.serverUnsupported {
            return String(localized: "Paused on this Mac only: the server doesn’t support pausing agents. Klav refuses what goes through this Mac; an agent elsewhere isn’t stopped. Update the server.")
        }
        if pause.local && locked {
            return String(localized: "Paused on this Mac; unlock to pause everywhere. Until then, only what goes through this Mac is refused.")
        }
        if pause.local {
            return String(localized: "Paused on this Mac for now: Klav tells the server as soon as it’s unlocked and online. Until then, only what goes through this Mac is refused.")
        }
        return nil
    }

    /// Offer «Unlock to pause everywhere»: the pause waits for klavd to be
    /// unlocked to be signed and sent.
    static func offersUnlock(_ pause: PauseInfo, locked: Bool) -> Bool { pause.local && !pause.serverUnsupported && locked }

    /// An agent's own state: «Ends at 11:31», «Until you resume», or «With
    /// every agent» when the pause of every agent stops it.
    static func agentState(_ pause: AgentPauseInfo) -> String {
        if pause.everyone { return String(localized: "With every agent") }
        return pause.untilMs.map { String(localized: "Ends at \(ActivityWords.clock($0))") }
            ?? String(localized: "Until you resume")
    }
}

/// The rounded minutes until `ms`, for «until 10:40» and «47 min left».
func minutesUntil(_ ms: Int64) -> Int {
    max(1, Int((Double(ms) / 1000 - Date().timeIntervalSince1970) / 60 + 0.5))
}
