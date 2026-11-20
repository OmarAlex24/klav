import Foundation

/// The pure parts, twins of the extension's `health.ts`.
enum HealthWords {
    /// An offered task lasts 2 hours unless the person picks otherwise.
    static let defaultSecs: UInt64 = 2 * 3600
    /// How often a running fix task's progress is read while «Vault health»
    /// is on screen.
    static let progressEvery: Duration = .seconds(5)

    /// Durations the person can pick: 2 h first, then 15 min to 24 h.
    static let offerSteps: [UInt64] = [7200, 900, 1800, 3600, 14_400, 28_800, 86_400]

    /// The logins the person left checked, in the card's order; blocked
    /// ones never.
    static func picked(_ rows: [OfferRowInfo], unchecked: Set<String>) -> [String] {
        rows.filter { $0.blocked == nil && !unchecked.contains($0.itemId) }.map(\.itemId)
    }

    /// What goes to `offer_task`: the person's own (neutral) title and
    /// reason, in the interface's language. The agent reads them.
    static func input(agent: String, rows: [OfferRowInfo], unchecked: Set<String>, secs: UInt64) -> OfferInput {
        OfferInput(agent: agent, items: picked(rows, unchecked: unchecked),
                   task: String(localized: "Change passwords", comment: "Title of the task offered to an agent"),
                   reason: String(localized: "Give each of these sites a new password that Klav generates and keeps",
                                  comment: "Reason of the task offered to an agent"),
                   durationSecs: secs)
    }

    /// How a site of a running task reads.
    static func site(_ site: SiteProgressInfo) -> String {
        switch site.state {
        case "changed": return String(localized: "changed", comment: "A site of a password change task")
        case "failed": return String(localized: "failed", comment: "A site of a password change task")
        default:
            return site.started ? String(localized: "in progress", comment: "A site of a password change task")
                : String(localized: "pending", comment: "A site of a password change task")
        }
    }

    /// How many sites are changed, pending and failed.
    static func counts(_ sites: [SiteProgressInfo]) -> (changed: Int, pending: Int, failed: Int) {
        let changed = sites.filter { $0.state == "changed" }.count
        let failed = sites.filter { $0.state == "failed" }.count
        return (changed, sites.count - changed - failed, failed)
    }

    /// A task worth following here: offered by the person, running, with
    /// `rotate`.
    static func isFixTask(_ card: TaskItem, now: Int64) -> Bool {
        card.offered && card.status == "approved" && (card.expiresAt ?? 0) > now
            && card.rows.contains { $0.permissions.contains { $0.permission == "rotate" && $0.checked } }
    }

    /// Why a login cannot go in the task.
    static func block(_ name: String) -> String {
        switch name {
        case "not_granted": return String(localized: "Its project is not among the agent’s projects")
        case "no_site": return String(localized: "It has no website: the change happens on the item’s site")
        case "not_login": return String(localized: "It is not a login with a password")
        case "other_field": return String(localized: "The shared password is not the login’s main one")
        default: return name
        }
    }

    /// The item's title, with the field when it is not the password.
    static func title(_ item: HealthItemInfo) -> String {
        item.field == "password" ? item.title : "\(item.title) (\(item.fieldLabel))"
    }

    static func day(_ ms: Int64) -> String {
        Date(timeIntervalSince1970: Double(ms) / 1000).formatted(date: .abbreviated, time: .omitted)
    }
}
