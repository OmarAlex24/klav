import Foundation

/// The vault engine (`KlavCore` from `klav-ffi`) and the device keystore.
/// Every call blocks in Rust, so it runs off the main thread.
final class CoreService: @unchecked Sendable {
    let core: KlavCore
    let keystore: PlatformKeystore

    init() throws {
        core = try KlavCore(homeDir: try KlavHome.directory().path)
        keystore = Keystores.platform()
    }

    /// Runs `body` on a background thread and re-protects the files it may
    /// have written.
    @discardableResult
    func run<T: Sendable>(_ body: @escaping @Sendable (KlavCore, PlatformKeystore) throws -> T) async throws -> T {
        let core = core
        let keystore = keystore
        return try await Task.detached(priority: .userInitiated) {
            defer { KlavHome.protect() }
            return try body(core, keystore)
        }.value
    }
}

extension KlavError {
    /// What to tell the person, in the interface's language.
    var userMessage: String {
        switch self {
        case .WrongCredentials: return String(localized: "The master password or the Secret Key isn’t right.")
        case .NotLoggedIn: return String(localized: "This iPhone doesn’t have an account yet.")
        case .Locked: return String(localized: "Klav is locked.")
        case .SessionExpired: return String(localized: "The session expired or was revoked. Sign in again.")
        case .Network: return String(localized: "Couldn’t reach the server. Check its address and your connection.")
        case .Rollback: return String(localized: "The server sent older data than this iPhone has already seen. Nothing was synced: it may be an attack or an old backup.")
        case .Security(let message): return String(localized: "Security problem: \(message)")
        case .BiometryFailed: return String(localized: "Face ID didn’t finish.")
        case .BiometryUnavailable(let message):
            return message.contains("changed")
                ? String(localized: "Face ID changed on this iPhone. Enter the master password to turn it back on.")
                : String(localized: "Face ID isn’t available right now: use your master password.")
        case .PasswordRequired(let message): return String(localized: "Enter the master password: Face ID asks for it \(passwordReason(message)).")
        case .NotFound(let message): return String(localized: "Not found: \(message)")
        case .Conflict: return String(localized: "The item changed on another device. Sync and try again.")
        case .SiteMismatch: return String(localized: "This item isn’t saved for this site.")
        case .Denied(let message): return String(localized: "Not allowed: \(message)")
        // ADR 0037 §7.6, §7.7. A person's session never gets
        // `AccountDeleting`: only agents do, and the message says when.
        case .AccountDeleted: return String(localized: "Klav deleted your account")
        case .AccountDeleting(let message): return message
        case .DeletionUnsupported: return String(localized: "This server can’t delete accounts from the app. Ask whoever runs it.")
        // 409, 429 and a lost answer, in the person's language: never the
        // server's English (review finding 3).
        case .DeletionAlreadyScheduled: return String(localized: "The deletion of your account is already scheduled. Klav shows when as soon as it syncs.")
        case .DeletionRateLimited: return String(localized: "Klav limits how often the deletion can be asked for. Try again later.")
        case .DeletionNotRecorded(let deleteAt, _):
            guard let deleteAt else {
                return String(localized: "The server canceled the deletion, but this iPhone couldn’t save it. It shows after the next sync.")
            }
            // Formatted here: the AutoFill extension has no Shared/App.
            let day = Date(timeIntervalSince1970: TimeInterval(deleteAt) / 1000).formatted(.dateTime.month(.wide).day())
            return String(localized: "The server scheduled the deletion for \(day), but this iPhone couldn’t save it. It shows after the next sync.")
        // ADR 0048 §2, §3.2: the invite, in the person's language; a
        // quota, in the server's words (which limit, used, maximum).
        case .InviteInvalid: return String(localized: "This invite code isn’t valid for this email.")
        case .QuotaExceeded(let message): return message
        case .Invalid(let message): return message
        }
    }
}

/// Why Face ID wants the password, from `klav-ffi`'s reason.
func passwordReason(_ reason: String) -> String {
    reason.contains("restart") ? String(localized: "after the iPhone restarts") : String(localized: "every 14 days")
}

/// A user-facing message for any error.
func describe(_ error: Error) -> String {
    if let e = error as? KlavError { return e.userMessage }
    return String(localized: "Something went wrong: \(error.localizedDescription)")
}
