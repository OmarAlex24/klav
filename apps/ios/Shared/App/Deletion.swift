import Foundation

// Deleting the account (ADR 0037 §7): what the iPhone and the Mac share.

/// A date as the screens say it: «14 de noviembre» / "November 14".
func deletionDay(_ ms: Int64) -> String {
    Date(timeIntervalSince1970: TimeInterval(ms) / 1000)
        .formatted(.dateTime.month(.wide).day())
}

/// The deletion's date has passed but the server hasn't said it deleted
/// the account (no sync since, or offline): never «will be deleted» on a
/// past day.
func deletionDue(_ deletion: AccountDeletionInfo, now: Date = Date()) -> Bool {
    deletion.deleteAt <= Int64(now.timeIntervalSince1970 * 1000)
}

/// The line that says when, as the date stands now.
func deletionHeadline(_ deletion: AccountDeletionInfo, now: Date = Date()) -> String {
    deletionDue(deletion, now: now)
        ? String(localized: "Your account was to be deleted on \(deletionDay(deletion.deleteAt))")
        : String(localized: "Your account will be deleted on \(deletionDay(deletion.deleteAt))")
}

/// What deleting this device's copy, or signing out, would lose, as the
/// check counted it (ADR 0037, Q3 of the re-review; T138 for passkeys):
/// what never went up is only here. The dialog says it, and confirming it
/// accepts exactly that loss: if more is waiting by then, Klav refuses.
enum UnsentLoss: Equatable {
    /// Nothing waits: the copy can go.
    case nothing
    /// These never went up, and go with the copy.
    case counted(generated: UInt32, passkeys: UInt32)
    /// Klav couldn't count (locked with a queue, or the check failed):
    /// something may be waiting.
    case unknown

    init(_ check: SignOutCheck?) {
        guard let check, !check.lockedWithQueue else {
            self = .unknown
            return
        }
        if check.unsentGenerated == 0 && check.unsentPasskeys == 0 {
            self = .nothing
        } else {
            self = .counted(generated: check.unsentGenerated, passkeys: check.unsentPasskeys)
        }
    }

    /// What confirming a dialog that said this agrees to lose.
    var accepted: AcceptedLoss {
        switch self {
        case .nothing: return .nothing
        case .counted(let generated, let passkeys): return .unsent(passkeys: passkeys, generated: generated)
        case .unknown: return .unknown
        }
    }

    /// Generated passwords may be among what waits: the history lists
    /// them, to copy.
    var mayHoldGenerated: Bool {
        switch self {
        case .nothing: return false
        case .counted(let generated, _): return generated > 0
        case .unknown: return true
        }
    }
}
