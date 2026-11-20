import Foundation

// Task cards (ADR 0021): what the person changed and the words, shared by
// the iOS and Mac apps. Not part of the AutoFill extension.

/// What the person changed on a pending task card: the boxes they ticked
/// or cleared and a shorter duration. Kept in `AppModel` by task, so a
/// poll that brings the same card back does not undo them.
struct TaskEdits: Equatable {
    /// `item:permission` → checked, only where the person touched it.
    var checked: [String: Bool] = [:]
    /// The duration picked (seconds), if not the one asked for.
    var forSecs: UInt64?

    enum State: Equatable { case on, off, mixed }

    static func key(_ item: String, _ permission: String) -> String { "\(item):\(permission)" }

    /// What the policy denies, an item the vault lacks, a row whose site
    /// does not match (T92) and a permission without a site (ADR 0030 §6)
    /// are never checked.
    static func blocked(_ row: TaskRowItem, _ permission: TaskPermissionItem) -> Bool {
        permission.deniedByPolicy || permission.noSite || row.missing || row.domainMismatch
    }

    func isChecked(_ row: TaskRowItem, _ permission: TaskPermissionItem) -> Bool {
        if Self.blocked(row, permission) { return false }
        return checked[Self.key(row.itemId, permission.permission)] ?? permission.checked
    }

    /// The item's box: on when all it can hold is checked, mixed when some.
    func state(of row: TaskRowItem) -> State {
        let usable = row.permissions.filter { !Self.blocked(row, $0) }
        let on = usable.filter { isChecked(row, $0) }.count
        if usable.isEmpty || on == 0 { return .off }
        return on == usable.count ? .on : .mixed
    }

    mutating func set(_ row: TaskRowItem, _ permission: TaskPermissionItem, _ on: Bool) {
        guard !Self.blocked(row, permission) else { return }
        checked[Self.key(row.itemId, permission.permission)] = on
    }

    /// The item's box checks or clears every permission it can hold.
    mutating func set(_ row: TaskRowItem, _ on: Bool) {
        for permission in row.permissions { set(row, permission, on) }
    }

    /// Something is left to approve.
    func anyChecked(_ card: TaskItem) -> Bool {
        card.rows.contains { row in row.permissions.contains { isChecked(row, $0) } }
    }

    /// The duration on screen: the one picked, never longer than asked.
    func duration(for card: TaskItem) -> UInt64 {
        guard let forSecs, forSecs < card.durationSecs else { return card.durationSecs }
        return forSecs
    }

    /// What goes to `decide_task`, as the popup's `choiceOf`: cleared boxes
    /// in `without`, boxes Klav offered unchecked and the person ticked in
    /// `with`, and the duration only when shorter than asked. Never what
    /// the policy denies or an item the vault lacks.
    func choice(for card: TaskItem) -> TaskChoiceInput {
        var choice = TaskChoiceInput(without: [], with: [], forSecs: nil)
        for row in card.rows {
            for permission in row.permissions where !Self.blocked(row, permission) {
                let now = isChecked(row, permission)
                let entry = TaskChoiceEntry(itemId: row.itemId, permission: permission.permission)
                if permission.checked && !now { choice.without.append(entry) }
                if !permission.checked && now { choice.with.append(entry) }
            }
        }
        let secs = duration(for: card)
        if secs < card.durationSecs { choice.forSecs = secs }
        return choice
    }
}

/// The words of a task card.
enum TaskWords {
    /// Shorter durations the person can pick (never longer than asked, and
    /// at least 5 minutes, like `--for`).
    static let steps: [UInt64] = [15 * 60, 30 * 60, 3600, 2 * 3600, 4 * 3600, 8 * 3600]

    /// The duration asked for, then the shorter steps, longest first.
    static func durations(requested: UInt64) -> [UInt64] {
        [requested] + steps.filter { $0 < requested && $0 >= 5 * 60 }.reversed()
    }

    /// "15 min", "1 h", "1 h 30 min" (the same in English and Spanish).
    static func duration(_ secs: UInt64) -> String {
        let minutes = Int((Double(secs) / 60).rounded())
        if minutes < 60 { return "\(minutes) min" }
        let rest = minutes % 60
        return rest > 0 ? "\(minutes / 60) h \(rest) min" : "\(minutes / 60) h"
    }

    /// The time of day of `ms` (Unix ms), as the iPhone writes it.
    static func clock(_ ms: Int64) -> String {
        Date(timeIntervalSince1970: Double(ms) / 1000).formatted(date: .omitted, time: .shortened)
    }

    static func permission(_ name: String) -> String {
        switch name {
        case "fill": return String(localized: "fill", comment: "A permission on a task card")
        case "totp": return String(localized: "one-time code", comment: "A permission on a task card")
        case "inject": return String(localized: "inject", comment: "A permission on a task card")
        case "update": return String(localized: "update", comment: "A permission on a task card")
        case "passkey": return String(localized: "passkey", comment: "A permission on a task card")
        case "rotate": return String(localized: "change password", comment: "A permission on a task card")
        default: return name
        }
    }

    static func warning(_ name: String) -> String? {
        switch name {
        case "totp": return String(localized: "2FA stops being a second factor for this agent")
        case "passkey": return String(localized: "The agent will sign in with your passkey; your approval counts as verification")
        case "rotate": return String(localized: "The agent will change this password")
        default: return nil
        }
    }

    /// "2 h from approval, until 6:15 PM".
    static func lasts(_ secs: UInt64, now: Date) -> String {
        let end = Int64((now.timeIntervalSince1970 + Double(secs)) * 1000)
        let at = clock(end), span = duration(secs)
        if atOne(at) {
            return String(localized: "task.lasts.atOne", defaultValue: "\(span) from approval, until \(at)",
                          comment: "The task's end at one o'clock: Spanish says «la 1:15», not «las»")
        }
        return String(localized: "\(span) from approval, until \(at)")
    }

    /// "1 h 20 min left · ends at 6:15 PM".
    static func left(until end: Int64, now: Date) -> String {
        let remaining = max(0, Double(end) / 1000 - now.timeIntervalSince1970)
        let at = clock(end), span = duration(UInt64(remaining))
        if atOne(at) {
            return String(localized: "task.left.atOne", defaultValue: "\(span) left · ends at \(at)",
                          comment: "The task's end at one o'clock: Spanish says «a la 1:15», not «a las»")
        }
        return String(localized: "\(span) left · ends at \(at)")
    }

    /// "until 6:15 PM", after a running fix task's counts.
    static func until(_ end: Int64) -> String {
        let at = clock(end)
        if atOne(at) {
            return String(localized: "task.until.atOne", defaultValue: "until \(at)",
                          comment: "A task's end at one o'clock: Spanish says «hasta la 1:15», not «hasta las»")
        }
        return String(localized: "until \(at)")
    }

    /// Whether a time from `clock` is at one o'clock ("1:15 PM", "01:15"),
    /// where Spanish takes «la» and every other hour «las».
    static func atOne(_ clock: String) -> Bool {
        Int(clock.prefix { $0.isASCII && $0.isNumber }) == 1
    }

    /// How much of a running task is spent, 0…1. From the request, not
    /// `decided_at`: each «Add to the task» signs a new `decided_at` with
    /// the same end, and the band must not refill.
    static func spent(_ card: TaskItem, now: Date) -> Double {
        let end = Double(card.expiresAt ?? 0)
        let total = max(1, end - Double(card.createdAt))
        let remaining = max(0, end - now.timeIntervalSince1970 * 1000)
        return min(1, max(0, 1 - remaining / total))
    }
}
