import Foundation

/// «Also change its projects’ keys» when revoking an agent (ADR 0033,
/// amendment of 2026-11-10, F2, P7), on the Mac and the iPhone alike.
enum KeyChangeWords {
    /// «Also change its projects’ keys» shows when there are projects, or
    /// when this device can’t tell which (an unreadable grant): Klav looks
    /// for them in what the account signed (P7).
    static func offersKeyChange(_ seen: ExposureInfo) -> Bool {
        !seen.projects.isEmpty || seen.projectsUnknown
    }

    /// What «Also change its projects’ keys» costs, never more certain than
    /// what Klav could read.
    static func cost(_ cost: KeyChangeCostInfo, unknownProjects: Bool) -> String {
        if unknownProjects {
            return String(localized: "Klav looks for its projects in what your account signed, then wraps their items’ keys again.")
        }
        let items = Int64(cost.items)
        let others = cost.otherAgents.map { String(localized: "“\(AgentText.line($0, max: 64))”") }
        var parts: [String] = []
        if cost.itemsAtLeast && items == 0 {
            parts.append(String(localized: "Klav couldn’t count the items in those projects; it wraps all of their keys again, with their stored versions."))
        } else if cost.itemsAtLeast {
            parts.append(String(localized: "Klav wraps the keys of at least \(items) items again, with their stored versions."))
        } else {
            parts.append(String(localized: "Klav wraps the keys of \(items) items again, with their stored versions."))
        }
        if others.count == 1 {
            parts.append(String(localized: "\(others[0]) gets a new grant with the new keys by itself, without comparing words again."))
        } else if !others.isEmpty {
            parts.append(String(localized: "\(others.joined(separator: ", ")) get a new grant with the new keys by themselves, without comparing words again."))
        }
        if cost.othersAtLeast {
            parts.append(String(localized: "Klav couldn’t read every agent’s grant: any other agent that holds these projects also gets one."))
        } else if others.isEmpty {
            parts.append(String(localized: "Without it, the agent keeps those projects’ keys: a dishonest server could let it open what you add there later."))
        }
        return parts.joined(separator: " ")
    }
}
