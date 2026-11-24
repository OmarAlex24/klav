import AuthenticationServices
import Foundation
import os
import SwiftUI
import UIKit

/// Lifecycle messages (never values or names from the vault).
let appLog = Logger(subsystem: "dev.klav.ios", category: "app")

/// How long Klav stays open in the background before it locks.
enum AutoLock: Int, CaseIterable, Identifiable {
    case immediately = 0
    case oneMinute = 60
    case fiveMinutes = 300
    case fifteenMinutes = 900
    case oneHour = 3600

    var id: Int { rawValue }

    var label: String {
        switch self {
        case .immediately: return String(localized: "When you leave the app")
        case .oneMinute: return String(localized: "After 1 minute")
        case .fiveMinutes: return String(localized: "After 5 minutes")
        case .fifteenMinutes: return String(localized: "After 15 minutes")
        case .oneHour: return String(localized: "After 1 hour")
        }
    }

    /// What the lock screen says after locking by itself.
    var lockNote: String {
        switch self {
        case .immediately: return String(localized: "Locked when the app went to the background")
        case .oneMinute: return String(localized: "Locked after 1 minute in the background")
        case .fiveMinutes: return String(localized: "Locked after 5 minutes in the background")
        case .fifteenMinutes: return String(localized: "Locked after 15 minutes in the background")
        case .oneHour: return String(localized: "Locked after 1 hour in the background")
        }
    }
}

/// When the app left the screen, on a clock the person cannot move: the
/// wall clock changes with Settings (or a time zone), and `systemUptime`
/// stops while the iPhone sleeps. `ContinuousClock` keeps counting in both
/// cases (layer 11 of the 2026-11 round).
struct AutoLockTimer {
    private(set) var leftAt: ContinuousClock.Instant?

    /// The app went to the background (the first time counts).
    mutating func left(at now: ContinuousClock.Instant = .now) {
        if leftAt == nil { leftAt = now }
    }

    /// The app is back: whether it stayed away `limit` or longer. Starts
    /// over either way.
    mutating func cameBack(after limit: Duration, at now: ContinuousClock.Instant = .now) -> Bool {
        defer { leftAt = nil }
        guard let leftAt else { return false }
        return leftAt.duration(to: now) >= limit
    }
}

/// Preferences of this iPhone (no secrets), shared with the extension.
final class Preferences: ObservableObject {
    private let defaults = KlavHome.defaults

    @Published var autoLock: AutoLock {
        didSet { defaults.set(autoLock.rawValue, forKey: "autoLock") }
    }
    /// Set up Face ID when the password unlocks.
    @Published var faceID: Bool {
        didSet { defaults.set(faceID, forKey: "faceID") }
    }
    /// Offer logins in the keyboard's QuickType bar (titles, user names and
    /// sites only; never secrets).
    @Published var quickType: Bool {
        didSet { defaults.set(quickType, forKey: "quickType") }
    }
    /// The last server signed in to (pre-filled after signing out).
    @Published var lastServer: String {
        didSet { defaults.set(lastServer, forKey: "lastServer") }
    }
    /// The welcome to AutoFill was closed («Not now», or Klav was turned
    /// on): it is not offered again until the next sign-in.
    @Published var autofillWelcomeDismissed: Bool {
        didSet { defaults.set(autofillWelcomeDismissed, forKey: "autofillWelcomeDismissed") }
    }

    init() {
        autoLock = AutoLock(rawValue: defaults.object(forKey: "autoLock") as? Int ?? 60) ?? .oneMinute
        faceID = defaults.object(forKey: "faceID") as? Bool ?? true
        quickType = defaults.object(forKey: "quickType") as? Bool ?? true
        lastServer = defaults.string(forKey: "lastServer") ?? ""
        autofillWelcomeDismissed = defaults.bool(forKey: "autofillWelcomeDismissed")
    }
}

/// The app's state: which screen, the account, and locking.
@MainActor
final class AppModel: ObservableObject {
    enum Phase: Equatable {
        case starting
        case broken(String)
        case signedOut
        case locked
        case unlocked
    }

    @Published private(set) var phase: Phase = .starting
    @Published private(set) var status: CoreStatus?
    @Published private(set) var biometrics: BiometricState?
    /// Hides the vault while the app is not in front (app switcher). The
    /// root view covers itself and `PrivacyShield` covers the rest.
    @Published private(set) var covered = false {
        didSet {
            guard covered != oldValue else { return }
            if covered { PrivacyShield.shared.show() } else { PrivacyShield.shared.hide() }
        }
    }
    /// Changes every time the vault is unlocked or synced (views reload).
    @Published private(set) var generation = 0
    /// The last sync failed: what is shown is this iPhone's copy.
    @Published private(set) var offline: String?
    /// Passkeys AutoFill saved without a connection that are not on the
    /// server yet, or a queue of them that could not be read (T138).
    @Published private(set) var passkeyNotice: String?
    /// The set-aside outboxes `passkeyNotice` counted: acknowledged when it
    /// is on screen, only those (T138).
    private var setAsideToAcknowledge: [String] = []
    /// Moves with every sync that sets `passkeyNotice`, so a notice already
    /// on screen still acknowledges what the new sync counted.
    @Published private(set) var passkeyNoticeID = 0
    /// The app is on screen (active, or inactive under a system prompt).
    @Published private(set) var inForeground = true
    /// The person locked it themselves: do not pop up Face ID right away.
    @Published private(set) var lockedByHand = false
    /// Why the vault locked by itself, for the lock screen (nil: at launch
    /// or by hand).
    @Published private(set) var lockNote: String?
    /// The lock screen's keyhole is flooding with light: the vault opened
    /// and appears once the light fills the field (docs/diseno-visual §3).
    @Published private(set) var opening = false

    /// The message at the bottom (after a copy, with the clipboard's time).
    @Published private(set) var toast: Toast?

    /// Agents' requests waiting for this person (ADR 0018 §5 and §6).
    @Published private(set) var approvals: [ApprovalItem] = []
    @Published private(set) var registrations: [AgentItem] = []
    /// Task requests to decide and running tasks (ADR 0021 §8).
    @Published private(set) var tasks: [TaskItem] = []
    /// Secret requests from agents waiting for a value (ADR 0046).
    @Published private(set) var secretRequests: [SecretRequestItem] = []
    /// What the person changed on each pending task card, by task ID.
    @Published private(set) var taskEdits: [String: TaskEdits] = [:]
    /// The account's agents by ID (names for the sites they added, pairing
    /// words for the cards).
    @Published private(set) var knownAgents: [String: AgentItem] = [:]
    /// The account's agents with their pause and last use, for Agents
    /// (ADR 0033 §9): read with the requests.
    @Published private(set) var agentList: [DevAgentInfo] = []
    /// The pauses in effect, each signed by the account: what the last
    /// sync left, or this iPhone's own decision (ADR 0033 §7, §9). One that
    /// ended is dropped at the next read, offline too.
    @Published private(set) var pauses: [PauseInfo] = []
    /// The key changes this iPhone owes after revoking an agent, from its
    /// sealed record (ADR 0033, amendment of 2026-11-10, P10): read with
    /// the requests. The iPhone has no `klavd`: its own steps change the
    /// keys, one project per call, while Klav is unlocked (`Revoke.swift`).
    @Published var revocations: [RevocationInfo] = []
    /// The record doesn't open: what is left can't be told.
    @Published var revocationsProblem: String?
    /// Agents whose key change runs now on this iPhone.
    @Published var changingKeys: Set<String> = []
    /// How this iPhone's last run of an agent's key change ended.
    @Published var keyChangeEnds: [String: KeyChangeEnd] = [:]
    /// The key changes left were picked up again after this unlock.
    var resumedKeyChanges = false
    /// The disagreement between the agents and the pauses that a sync
    /// already caught up with: one sync for each, not one every 8 s. Kept
    /// only once that sync went through, so a failed one is tried again.
    private(set) var pauseDisagreement: String?
    /// A catch-up sync is running: the 8-s poll doesn't start another.
    private var catchingUp = false
    /// The catch-up sync; true when it went through. Tests replace it
    /// (the model has no core there).
    var catchUpSync: (@MainActor () async -> Bool)?
    /// A notification was opened: the request to show once it is loaded.
    @Published var route: PushRoute?
    /// Klav is turned on as an AutoFill provider in iOS Settings (nil:
    /// not read yet). Read on unlock and on every return to the app.
    @Published private(set) var autofillEnabled: Bool?
    /// The welcome to AutoFill over the vault.
    @Published private(set) var autofillWelcome: AutofillWelcome = .hidden
    /// A notification was opened over the welcome: not again this launch.
    private var autofillWelcomeDeferred = false
    /// «Add <host> to this item», left by the AutoFill extension after the
    /// person filled a login saved for a subdomain (ADR 0025 §2).
    @Published private(set) var siteOffer: SiteOffer?
    /// A one-time code link iOS opened Klav with (ADR 0035 §4), already
    /// read by klav-core. Only in memory, never on disk or in the log;
    /// its sheet comes up once the vault is open.
    @Published private(set) var pendingCode: PendingCode?
    /// Google Authenticator's `otpauth-migration://` links opened from iOS,
    /// for the import wizard (ADR 0035 §5). Only in memory.
    @Published private(set) var migrationLinks: [String] = []
    /// The deletion of the account the person asked for, while it is
    /// pending (ADR 0037 §7.4).
    @Published private(set) var accountDeletion: AccountDeletionInfo?
    /// Klav deleted the account (ADR 0037 §7.6): when. The copy stays,
    /// read-only, until the person deletes it (D-C).
    @Published private(set) var deletedAt: Int64?

    /// The account is gone: the vault reads, nothing edits or syncs
    /// (ADR 0037 §3, D-C).
    var readOnly: Bool { deletedAt != nil }

    let preferences = Preferences()
    private var lastSync: Date?
    private(set) var service: CoreService?
    private var away = AutoLockTimer()
    /// Our own Face ID prompt is up: it makes the app inactive, but that
    /// must not cover the screen or count as leaving.
    private var authenticating = false
    /// This iPhone's APNs token, registered with the server once unlocked.
    private var pushTokenValue: String?
    private var registeredToken: String?

    func start() {
        guard service == nil else { return }
        do {
            service = try CoreService()
            refresh()
        } catch {
            phase = .broken(describe(error))
        }
    }

    /// Re-reads the device state and picks the screen.
    func refresh() {
        guard let service else { return }
        let status = service.core.status()
        self.status = status
        biometrics = service.core.biometricState(keystore: service.keystore)
        if !status.hasAccount {
            phase = .signedOut
        } else {
            phase = status.unlocked ? .unlocked : .locked
        }
    }

    /// Re-reads only the Face ID state (it changes in the iPhone's settings).
    func refreshBiometrics() {
        guard let service else { return }
        biometrics = service.core.biometricState(keystore: service.keystore)
    }

    /// Face ID can open the vault now (enrolled and not due for the password).
    var faceIDReady: Bool {
        guard let b = biometrics else { return false }
        return b.available && b.enrolled && b.passwordRequired == nil
    }

    // MARK: Signing in and unlocking

    func signIn(server: String, email: String, password: String, secretKey: String, deviceName: String) async throws {
        guard let service else { return }
        let keystore = preferences.faceID ? service.keystore : nil
        authenticating = true
        defer { authenticating = false }
        _ = try await service.run { core, _ in
            try core.signIn(server: server, email: email, password: password,
                            secretKey: secretKey, deviceName: deviceName, keystore: keystore)
        }
        preferences.lastServer = server
        unlocked()
    }

    func unlock(password: String) async throws {
        guard let service else { return }
        let keystore = preferences.faceID ? service.keystore : nil
        _ = try await service.run { core, _ in
            try core.unlockWithPassword(password: password, keystore: keystore)
        }
        await open()
    }

    func unlockWithFaceID() async throws {
        guard let service else { return }
        authenticating = true
        defer { authenticating = false }
        try await service.run { core, keystore in
            try core.unlockWithBiometrics(keystore: keystore, reason: String(localized: "Open your Klav vault"))
        }
        await open()
    }

    /// From the lock screen: lets the keyhole flood (~400 ms) before the
    /// vault replaces it. Instant with Reduce Motion, or when the lock
    /// screen is not showing (turning Face ID on in Settings).
    private func open() async {
        if phase == .locked && !UIAccessibility.isReduceMotionEnabled {
            opening = true
            try? await Task.sleep(for: .milliseconds(430))
            withAnimation(.easeOut(duration: 0.16)) { unlocked() }
            opening = false
        } else {
            unlocked()
        }
    }

    private func unlocked() {
        appLog.info("unlocked")
        lockedByHand = false
        lockNote = nil
        refresh()
        generation += 1
        showIncoming()
        Task {
            await refreshAutofill()
            await sync()
            await readSiteOffer()
            await Push.prepare()
            await registerPush()
            await loadRequests()
        }
    }

    /// Pulls changes; without a connection the local copy stays in use.
    /// True when the copy is up to date: synced now, or a moment ago.
    @discardableResult
    func sync(force: Bool = false) async -> Bool {
        guard let service, phase == .unlocked else { return false }
        // A deleted account has nothing to sync (ADR 0037 §3).
        if readOnly { return false }
        // Coming back from Face ID makes the app active right after the
        // unlock already synced.
        if !force, let last = lastSync, Date().timeIntervalSince(last) < 10 { return true }
        lastSync = Date()
        do {
            let info = try await service.run { core, _ in try core.sync() }
            offline = nil
            passkeyNotice = Self.passkeyNotice(info)
            setAsideToAcknowledge = info.passkeyQueuesSetAside > 0 ? info.passkeyQueueSetAsideIds : []
            passkeyNoticeID += 1
            generation += 1
            // The sync brings the pauses other devices decided.
            await readPauses()
            await updateQuickType()
            await readAccountDeletion()
            return true
        } catch KlavError.Locked {
            lock()
            return false
        } catch KlavError.AccountDeleted(let deleteAt, _) {
            // This iPhone knew the date and it passed (ADR 0037 §3). The
            // copy stays: only the person deletes it (T165).
            offline = nil
            deletedAt = deleteAt ?? accountDeletion?.deleteAt ?? Int64(Date().timeIntervalSince1970 * 1000)
        } catch KlavError.SessionExpired {
            offline = KlavError.SessionExpired.userMessage
        } catch {
            offline = describe(error)
        }
        await readAccountDeletion()
        return false
    }

    // MARK: Deleting the account (ADR 0037)

    /// Reads the deletion the last sync left in the local copy, and
    /// whether the server already deleted the account: kept on this
    /// iPhone, so the vault opens read-only after a restart without
    /// network (D-C).
    func readAccountDeletion() async {
        guard let service, phase == .unlocked else { return }
        let deletion = try? await service.run { core, _ in try core.accountDeletion() }
        if deletion != accountDeletion { accountDeletion = deletion }
        if let deletion, deletion.deleted, deletedAt == nil { deletedAt = deletion.deleteAt }
    }

    /// Whether this server can delete the account from the app, asked
    /// before Face ID or the password (§4).
    func deletionSupported() async throws -> Bool {
        guard let service else { return false }
        return try await service.run { core, _ in try core.deletionSupported() }
    }

    /// Asks the server to delete the account in 7 days: Face ID first
    /// where Klav uses it (`klav-ffi` decides, from the enrolment), then
    /// the master password.
    func requestAccountDeletion(password: String) async throws {
        guard let service else { return }
        let reason = String(localized: "Confirm it’s you to delete your account")
        authenticating = true
        defer { authenticating = false }
        do {
            let asked = try await service.run { core, keystore in
                try core.requestAccountDeletion(password: password, keystore: keystore, reason: reason)
            }
            accountDeletion = asked
        } catch KlavError.DeletionAlreadyScheduled(let message) {
            // Asked from another device, or an answer lost: the sync
            // brings the date, and the banner shows it.
            await sync(force: true)
            throw KlavError.DeletionAlreadyScheduled(message: message)
        }
    }

    /// What «Cancel the deletion» got from the person.
    enum CancelDeletionOutcome: Equatable {
        case done
        /// No Face ID (or the person chose the password): ask for it.
        case needsPassword
        case cancelled
    }

    /// «Cancel the deletion»: it brings the agents back, so it asks what
    /// resuming them asks (ADR 0037 A2): Face ID first, without it the
    /// master password, never the iPhone's code.
    func cancelAccountDeletion() async throws -> CancelDeletionOutcome {
        guard service != nil else { return .cancelled }
        authenticating = true
        let presence = await ResumePresence.check(String(localized: "Cancel the deletion of your account"))
        authenticating = false
        switch presence {
        case .needsPassword: return .needsPassword
        case .cancelled: return .cancelled
        case .confirmed: break
        }
        try await canceled { core in try core.cancelAccountDeletion() }
        return .done
    }

    /// «Cancel the deletion» with the master password; a wrong one cancels
    /// nothing.
    func cancelAccountDeletion(password: String) async throws {
        try await canceled { core in try core.cancelAccountDeletionWithPassword(password: password) }
    }

    private func canceled(_ call: @escaping @Sendable (KlavCore) throws -> Bool) async throws {
        guard let service else { return }
        let canceled: Bool
        do {
            canceled = try await service.run { core, _ in try call(core) }
        } catch KlavError.AccountDeleted(let deleteAt, _) {
            // Too late: the server already deleted it.
            deletedAt = deleteAt ?? accountDeletion?.deleteAt ?? Int64(Date().timeIntervalSince1970 * 1000)
            return
        }
        accountDeletion = nil
        if canceled {
            show(Toast(text: String(localized: "The deletion was canceled. Your agents work again.")))
            return
        }
        // Nothing to cancel here: another device did, or asked again. The
        // server says which.
        await sync(force: true)
        if accountDeletion == nil, deletedAt == nil {
            show(Toast(text: String(localized: "The deletion was already canceled.")))
        }
    }

    /// A notification about the account (asked, canceled, deleted): the
    /// app learns which by syncing.
    func accountChanged() {
        Task { await sync(force: true) }
    }

    /// Something changed locally (an item saved): reload the lists.
    func changed() {
        generation += 1
        Task { await updateQuickType() }
    }

    /// Re-publishes the QuickType suggestions from the open vault (or
    /// removes them when turned off).
    func updateQuickType() async {
        guard preferences.quickType else {
            await IdentityStore.clear()
            return
        }
        guard let service, phase == .unlocked,
              let identities = try? await service.run({ core, _ in try core.credentialIdentities() })
        else { return }
        let passkeys = (try? await service.run { core, _ in try core.passkeyIdentities() }) ?? []
        await IdentityStore.replace(with: identities, passkeys: passkeys)
    }

    /// Copies a value and says for how long it stays on the clipboard.
    func copy(_ value: String) {
        Clipboard.copy(value)
        show(Toast(text: String(localized: "Copied. Klav will clear it from the clipboard in \(Int(Clipboard.clearAfter)) s."),
                   clears: Clipboard.clearAfter))
    }

    func show(_ toast: Toast) {
        self.toast = toast
        let id = toast.id
        Task {
            try? await Task.sleep(for: .seconds(toast.clears ?? 4))
            if self.toast?.id == id { self.toast = nil }
        }
    }

    func lock(byHand: Bool = false, note: String? = nil) {
        appLog.info("lock (by hand: \(byHand, privacy: .public))")
        lockedByHand = byHand
        lockNote = note
        service?.core.lock()
        offline = nil
        lastSync = nil
        // What agents asked stays on the server; locked, the app keeps
        // none of it. The opened notification (`route`) stays: it is shown
        // once the vault opens again. So does the site AutoFill left to add
        // (ADR 0025): it names an item, so it waits on disk and is read
        // again after unlocking.
        forgetRequests()
        siteOffer = nil
        // The sheet of a link from iOS goes away; the link waits in memory
        // and its sheet comes back after unlocking (ADR 0035 §4).
        IncomingPresenter.shared.dismiss(animated: false)
        refresh()
    }

    /// Drops the agents' requests, the tasks and what the person changed
    /// on them.
    private func forgetRequests() {
        approvals = []
        registrations = []
        tasks = []
        secretRequests = []
        taskEdits = [:]
        knownAgents = [:]
        agentList = []
        pauses = []
        pauseDisagreement = nil
        catchingUp = false
        revocations = []
        revocationsProblem = nil
        keyChangeEnds = [:]
        resumedKeyChanges = false
    }

    // MARK: Links from iOS (ADR 0035)

    /// A link iOS opened Klav with: a one-time code (`otpauth://`, «Set Up
    /// Codes In», the camera) or a Google Authenticator export
    /// (`otpauth-migration://`). klav-core reads a code link right away and
    /// Swift keeps only its opaque object; the last link wins. The log says
    /// what kind of link came, never what it says.
    func openLink(_ url: URL) {
        // A deleted account's copy saves nothing new (D-C): say so rather
        // than open a sheet that can't finish.
        if readOnly, IncomingLink(url) != .other {
            show(Toast(text: String(localized: "Klav deleted your account, so this copy can’t save anything new.")))
            return
        }
        switch IncomingLink(url) {
        case .code(let text):
            do {
                let link = try CodeLink(link: text)
                pendingCode = PendingCode(link: link, info: link.info())
                appLog.info("link: a one-time code")
            } catch {
                appLog.info("link: a one-time code Klav can't save")
                show(Toast(text: String(localized: "Klav can’t read this link. It saves time-based codes (TOTP).")))
                return
            }
        case .migration(let text):
            if !migrationLinks.contains(text) { migrationLinks.append(text) }
            appLog.info("link: a Google Authenticator export")
        case .other:
            appLog.info("link: not one Klav opens")
            return
        }
        showIncoming()
    }

    /// Puts what iOS opened over the vault once it is open: the code's
    /// sheet first, then the import of Google Authenticator's links.
    func showIncoming() {
        guard phase == .unlocked else { return }
        let presenter = IncomingPresenter.shared
        presenter.onSwipedAway = { [weak self] kind in
            switch kind {
            case .code(let id): self?.closeCode(id)
            case .migration: self?.closeMigration()
            }
        }
        // UIKit took it away for an alert or a sheet of SwiftUI: it comes
        // back once that is closed (the presenter waits for it).
        presenter.onLost = { [weak self] _ in self?.showIncoming() }
        if let pending = pendingCode {
            presenter.present(.code(pending.id), SaveCodeView(pending: pending) { [weak self] in self?.closeCode(pending.id) }
                .environmentObject(self)
                .environmentObject(preferences))
        } else if !migrationLinks.isEmpty {
            presenter.present(.migration, ImportView(incoming: true) { [weak self] in self?.closeMigration() }
                .environmentObject(self)
                .environmentObject(preferences))
        }
    }

    /// The code's sheet closed (done or cancelled): its link is forgotten.
    func closeCode(_ id: UUID) {
        if pendingCode?.id == id { pendingCode = nil }
        if IncomingPresenter.shared.shown == .code(id) { IncomingPresenter.shared.dismiss() }
        showIncoming()
    }

    /// The code is in the vault: its link is forgotten while the sheet
    /// still shows the code, so locking now doesn't bring the sheet back.
    func codeSaved(_ id: UUID) {
        if pendingCode?.id == id { pendingCode = nil }
    }

    /// The import of Google Authenticator's links closed.
    func closeMigration() {
        migrationLinks = []
        if IncomingPresenter.shared.shown == .migration { IncomingPresenter.shared.dismiss() }
        showIncoming()
    }

    /// Those links were imported: a new export starts from nothing.
    func migrationImported() {
        migrationLinks = []
    }

    /// Signing out forgets every link that was waiting. Internal for the
    /// tests: `signOut` needs a server.
    func forgetLinks() {
        pendingCode = nil
        migrationLinks = []
        IncomingPresenter.shared.dismiss(animated: false)
    }

    /// The pairing words of an agent this account approved: the grant it
    /// signed ties them to the agent's key (`klav-ffi` checked it), unlike
    /// the name, which the agent chose. Nil for any other agent.
    func pairingWords(ofAgent id: String) -> String? {
        guard let agent = knownAgents[id], agent.status == "active", !agent.projects.isEmpty else { return nil }
        return agent.pairingWords
    }

    /// What AutoFill saved offline says after a sync: a queue set aside
    /// (said once), or passkeys still waiting.
    private static func passkeyNotice(_ info: SyncInfo) -> String? {
        if info.passkeyQueuesSetAside > 0 {
            return String(localized: "Some passkeys saved without a connection could not be read and were set aside. Save them again on their sites.")
        }
        if info.passkeysWaiting > 0 {
            return String(localized: "\(Int(info.passkeysWaiting)) passkeys are not uploaded yet. They go up when this iPhone is online and Klav is open.")
        }
        return nil
    }

    /// The passkey notice is on screen: the set-aside outboxes it counted
    /// need not be said again (later syncs still say any set aside since).
    func passkeyNoticeShown() async {
        guard let service, !setAsideToAcknowledge.isEmpty else { return }
        let ids = setAsideToAcknowledge
        setAsideToAcknowledge = []
        do {
            _ = try await service.run { core, _ in try core.acknowledgePasskeyQueuesSetAside(ids: ids) }
        } catch {
            // Not acknowledged: the next sync says it again.
        }
    }

    /// What signing out would lose: passkeys AutoFill saved offline whose
    /// keys are only on this iPhone. Uploads them first if it can. `nil`:
    /// Klav could not tell (the dialog says passkeys may be lost).
    func signOutCheck() async -> SignOutCheck? {
        guard let service else { return nil }
        return try? await service.run { core, _ in try core.signOutCheck() }
    }

    /// What `signOut` did.
    enum SignOutOutcome {
        case signedOut
        /// Klav refused: passkeys are waiting now (one may have been saved
        /// while the dialog was open). Ask again with this check.
        case refused(SignOutCheck?)
        case failed(String)
    }

    /// Signs out, losing at most what the dialog the person confirmed said
    /// (`accepted`): if more passkeys are waiting by now (one saved while
    /// it was open), Klav refuses and nothing is deleted.
    func signOut(accepted: AcceptedLoss) async -> SignOutOutcome {
        guard let service else { return .failed(KlavError.Locked.userMessage) }
        // While still signed in: stop the server from notifying this iPhone.
        let hadPush = registeredToken != nil || pushTokenValue != nil
        if hadPush {
            _ = try? await service.run { core, _ in try core.unregisterPushToken() }
        }
        do {
            try await service.run { core, _ in try core.signOut(accepted: accepted) }
        } catch {
            if hadPush {
                // Still signed in: notifications come back.
                registeredToken = nil
                await registerPush()
            }
            if let e = error as? KlavError, case .Denied = e {
                return .refused(await signOutCheck())
            }
            return .failed(describe(error))
        }
        passkeyNotice = nil
        setAsideToAcknowledge = []
        UIApplication.shared.unregisterForRemoteNotifications()
        registeredToken = nil
        pushTokenValue = nil
        forgetRequests()
        route = nil
        forgetLinks()
        await IdentityStore.clear()
        offline = nil
        accountDeletion = nil
        deletedAt = nil
        // The next account sees the welcome to AutoFill again.
        preferences.autofillWelcomeDismissed = false
        autofillWelcome = .hidden
        autofillEnabled = nil
        autofillWelcomeDeferred = false
        refresh()
        return .signedOut
    }

    // MARK: AutoFill

    /// Asks iOS whether Klav is on as an AutoFill provider. Turned on just
    /// now (in Settings): the suggestions go up right away, and the welcome
    /// confirms and closes, or a toast says so if the welcome was closed.
    func refreshAutofill() async {
        guard phase == .unlocked else { return }
        let enabled = await ASCredentialIdentityStore.shared.state().isEnabled
        let was = autofillEnabled
        autofillEnabled = enabled
        if enabled, was == false {
            appLog.info("autofill: turned on")
            // QuickType suggestions are only published while enabled.
            Task { await updateQuickType() }
            if autofillWelcome == .asking {
                confirmAutofill()
            } else {
                show(Toast(text: String(localized: "Klav can fill in Safari and other apps now.")))
            }
        } else if !enabled, autofillWelcome == .hidden, !autofillWelcomeDeferred,
                  AutofillWelcome.offered(enabled: enabled, dismissed: preferences.autofillWelcomeDismissed) {
            autofillWelcome = .asking
        }
    }

    /// The site the AutoFill extension left to add, unless the item is
    /// gone or already matches that site (added by hand, or on another
    /// device): then it is dropped without asking.
    func readSiteOffer() async {
        guard phase == .unlocked, let service, let offer = SiteOffer.pending() else {
            siteOffer = nil
            return
        }
        let stillParent = (try? await service.run { core, _ -> Bool in
            let info = try core.item(id: offer.itemId).info
            // The sites the person confirmed, as AutoFill used (ADR 0030 §7).
            return !info.trashed && siteRelation(host: offer.host, urls: info.confirmedUrls) == .parent
        }) ?? false
        guard stillParent else {
            SiteOffer.clear()
            siteOffer = nil
            return
        }
        showSiteOffer(offer)
    }

    /// Asks «Add this site?» about `offer` (read while the vault is open).
    func showSiteOffer(_ offer: SiteOffer) {
        siteOffer = offer
    }

    /// «Add this site»: a normal edit of the item, so it matches exactly.
    func addSite(_ offer: SiteOffer) async {
        SiteOffer.clear()
        siteOffer = nil
        guard let service else { return }
        do {
            let edit = ItemEdit(addUrls: ["https://\(offer.host)"])
            let id = offer.itemId
            _ = try await service.run { core, _ in try core.editItem(id: id, edit: edit) }
            generation += 1
            show(Toast(text: String(localized: "Added \(offer.host) to \(offer.title).")))
        } catch {
            show(Toast(text: describe(error)))
        }
    }

    /// «Not now»: the offer is not asked again.
    func dismissSiteOffer() {
        SiteOffer.clear()
        siteOffer = nil
    }

    /// From Klav's Settings, while Klav is still off.
    func offerAutofillWelcome() {
        guard autofillEnabled != true else { return }
        autofillWelcomeDeferred = false
        autofillWelcome = .asking
    }

    /// «Not now»: the row in Klav's Settings stays.
    func dismissAutofillWelcome() {
        preferences.autofillWelcomeDismissed = true
        autofillWelcome = .hidden
    }

    /// The box fills and the keyhole lights up; then the welcome closes.
    private func confirmAutofill() {
        preferences.autofillWelcomeDismissed = true
        autofillWelcome = .done
        Task {
            try? await Task.sleep(for: .milliseconds(1800))
            if autofillWelcome == .done {
                withAnimation(.easeOut(duration: 0.2)) { autofillWelcome = .hidden }
            }
        }
    }

    // MARK: Agents' requests

    /// Re-reads the pending requests and the tasks. A failed read keeps
    /// the last list.
    func loadRequests() async {
        guard let service, phase == .unlocked, !readOnly else { return }
        var loaded = true
        var listed: [DevAgentInfo]?
        do {
            let (pending, agents) = try await service.run { core, _ in
                (try core.approvals(), try core.devAgents())
            }
            // Locked while the server answered: show nothing of it.
            guard phase == .unlocked else { return }
            received(approvals: pending, agents: agents.map(\.agent))
            listed = agents
        } catch KlavError.Locked {
            lock()
            return
        } catch {
            loaded = false
            appLog.error("requests: \(describe(error), privacy: .private)")
        }
        // The pauses are this iPhone's, not the server's: re-read them also
        // when the server didn't answer, so an ended pause leaves the screen.
        do {
            let paused = try await service.run { core, _ in try core.agentsPaused() }
            guard phase == .unlocked else { return }
            if let listed { received(agents: listed, pauses: paused) } else { keep(paused) }
        } catch KlavError.Locked {
            lock()
            return
        } catch {
            appLog.error("pauses: \(describe(error), privacy: .private)")
        }
        // This iPhone's own record: also offline, and it may resume a key
        // change after the unlock.
        await loadRevocations()
        // Apart: a server without tasks must not hide the approvals.
        do {
            let list = try await service.run { core, _ in try core.tasks() }
            guard phase == .unlocked else { return }
            showTasks(list)
        } catch KlavError.Locked {
            lock()
            return
        } catch {
            loaded = false
            appLog.error("tasks: \(describe(error), privacy: .private)")
        }
        // Secret requests (ADR 0046): separate so older servers do not hide approvals/tasks.
        do {
            let list = try await service.run { core, _ in try core.secretRequests() }
            guard phase == .unlocked else { return }
            let now = Int64(Date().timeIntervalSince1970 * 1000)
            let pending = list.filter { $0.status == "pending" && $0.expiresAt > now }
            if pending != secretRequests { secretRequests = pending }
        } catch KlavError.Locked {
            lock()
            return
        } catch {
            appLog.error("secret requests: \(describe(error), privacy: .private)")
        }
        if loaded { settleRoute() }
    }

    /// Pending requests still to decide, agents still waiting to join, and
    /// all the account's agents.
    func received(approvals pending: [ApprovalItem], agents: [AgentItem],
                  now: Int64 = Int64(Date().timeIntervalSince1970 * 1000)) {
        let live = pending.filter { $0.status == "pending" && $0.expiresAt > now }
        let waiting = agents.filter { $0.status == "pending" && $0.expiresAt > now }
        if live != approvals { approvals = live }
        if waiting != registrations { registrations = waiting }
        let known = Dictionary(agents.map { ($0.id, $0) }, uniquingKeysWith: { first, _ in first })
        if known != knownAgents { knownAgents = known }
    }

    /// The agents with their pause, and the pauses this iPhone holds. When
    /// the server says an agent is paused and the signed pauses don't, or
    /// the other way round, another device decided since the last sync:
    /// sync once, and the banner follows (ADR 0033 §9). Answers the
    /// catch-up it started, if any.
    @discardableResult
    func received(agents list: [DevAgentInfo], pauses paused: [PauseInfo]) -> Task<Void, Never>? {
        if list != agentList { agentList = list }
        keep(paused)
        let pauses = Pauses(paused)
        guard pauses.disagrees(with: list) else {
            pauseDisagreement = nil
            return nil
        }
        let key = list.map { "\($0.agent.id)\(pauses.listed($0) != nil)" }.joined(separator: ",")
            + "|" + pauses.list.map { "\($0.agentId ?? "*")\($0.sinceMs)" }.joined(separator: ",")
        guard key != pauseDisagreement, !catchingUp else { return nil }
        catchingUp = true
        return Task { await catchUp(key) }
    }

    /// One sync for a disagreement, remembered only once it went through:
    /// offline, the next poll tries again.
    private func catchUp(_ key: String) async {
        let synced: Bool
        if let catchUpSync { synced = await catchUpSync() } else { synced = await sync(force: true) }
        catchingUp = false
        if synced { pauseDisagreement = key }
    }

    /// Keeps the pauses still in effect: one that ended leaves the screen.
    private func keep(_ paused: [PauseInfo]) {
        let live = Pauses(paused).list
        if live != pauses { pauses = live }
    }

    /// Pending tasks still to decide and running ones still running. A
    /// card that stays keeps what the person changed on it.
    func showTasks(_ list: [TaskItem], now: Int64 = Int64(Date().timeIntervalSince1970 * 1000)) {
        let shown = list.filter {
            ($0.status == "pending" && $0.decideBy > now) || ($0.status == "approved" && ($0.expiresAt ?? 0) > now)
        }
        if shown != tasks { tasks = shown }
        let pending = Set(shown.filter { $0.status == "pending" }.map(\.id))
        let kept = taskEdits.filter { pending.contains($0.key) }
        if kept != taskEdits { taskEdits = kept }
    }

    /// A notification was opened (maybe before unlocking).
    func open(_ route: PushRoute) {
        self.route = route
        // The request must not open under the welcome.
        if autofillWelcome == .asking {
            autofillWelcome = .hidden
            autofillWelcomeDeferred = true
        }
        Task { await loadRequests() }
    }

    /// The opened request is no longer pending: say so instead of showing
    /// nothing.
    private func settleRoute() {
        guard let route else { return }
        let found: Bool
        switch route {
        case .approval(let id): found = approvals.contains { $0.id == id }
        case .agent(let id): found = registrations.contains { $0.id == id }
        case .task(let id): found = tasks.contains { $0.id == id }
        case .secretRequest(let id): found = secretRequests.contains { $0.id == id }
        }
        if !found {
            self.route = nil
            show(Toast(text: String(localized: "That request is no longer pending.")))
        }
    }

    /// Face ID (or the iPhone's code) before approving. Our own prompt must
    /// not cover the screen.
    func confirmPresence(_ reason: String) async -> Bool {
        authenticating = true
        defer { authenticating = false }
        return await Presence.confirm(reason)
    }

    /// Deny, approve once (`leaseMinutes` 0) or approve for a while.
    func decide(_ approval: ApprovalItem, approve: Bool, leaseMinutes: UInt32 = 0) async throws {
        guard let service else { return }
        if approve, !(await confirmPresence(String(localized: "Approve \(approval.agent)’s request"))) {
            throw RequestError.notConfirmed
        }
        let id = approval.id
        // The request on screen is the one signed (ADR 0030 §5).
        let digest = approval.requestDigest
        try await service.run { core, _ in
            try core.decideApproval(id: id, approve: approve, leaseMinutes: leaseMinutes, requestDigest: digest)
        }
        approvals.removeAll { $0.id == id }
        show(Toast(text: approve ? String(localized: "Approved. \(approval.agent) can go on.") : String(localized: "Denied.")))
        await loadRequests()
    }

    /// Changes a pending task card (a box, an item, the duration).
    func editTask(_ card: TaskItem, _ change: (inout TaskEdits) -> Void) {
        var edits = taskEdits[card.id] ?? TaskEdits()
        change(&edits)
        taskEdits[card.id] = edits
    }

    /// Approves a task with what the person left checked (after Face ID),
    /// or denies it (nothing asked).
    func decideTask(_ card: TaskItem, approve: Bool) async throws {
        guard let service else { return }
        let edits = taskEdits[card.id] ?? TaskEdits()
        var choice: TaskChoiceInput?
        if approve {
            guard edits.anyChecked(card) else { throw RequestError.nothingChecked }
            guard await confirmPresence(String(localized: "Approve \(card.agent)’s task")) else {
                throw RequestError.notConfirmed
            }
            choice = edits.choice(for: card)
        }
        let id = card.id
        let digest = card.requestDigest
        let decided = try await service.run { core, _ in
            try core.decideTask(id: id, approve: approve, choice: choice, requestDigest: digest)
        }
        taskEdits[id] = nil
        tasks.removeAll { $0.id == id }
        if decided.status == "approved" { tasks.append(decided) }
        show(Toast(text: approve ? String(localized: "Task approved. \(card.agent) can start.") : String(localized: "Task denied.")))
        await loadRequests()
    }

    /// «Add to the task» (after Face ID): the next revision of the running
    /// task, same end, and this request approved once.
    func addToTask(_ approval: ApprovalItem) async throws {
        guard let service, let task = approval.task else { return }
        guard await confirmPresence(String(localized: "Add to \(approval.agent)’s task")) else {
            throw RequestError.notConfirmed
        }
        let id = approval.id
        let digest = approval.requestDigest
        _ = try await service.run { core, _ in try core.addToTask(approvalId: id, requestDigest: digest) }
        approvals.removeAll { $0.id == id }
        show(Toast(text: String(localized: "Added to the task “\(task.task)”.")))
        await loadRequests()
    }

    /// Fulfills a pending secret request (ADR 0046). Granting `klav-proxy`
    /// access asks for Face ID first (T239).
    func fulfillSecretRequest(_ card: SecretRequestItem, input: SecretRequestFulfillInput) async throws -> SecretRequestFulfillOutput {
        guard let service else { throw KlavError.Locked }
        if input.grantProxy {
            guard await confirmPresence(String(localized: "Save and grant credential proxy for \(card.agent)")) else {
                throw RequestError.notConfirmed
            }
        }
        let id = card.id
        let output = try await service.run { core, _ in
            try core.fulfillSecretRequest(id: id, input: input)
        }
        secretRequests.removeAll { $0.id == id }
        generation += 1
        show(Toast(text: String(localized: "Saved to Klav.")))
        await loadRequests()
        return output
    }

    /// Denies a pending secret request with a signed decision.
    func denySecretRequest(_ card: SecretRequestItem) async throws {
        guard let service else { throw KlavError.Locked }
        let id = card.id
        let digest = card.proposalDigest
        _ = try await service.run { core, _ in
            try core.denySecretRequest(id: id, proposalDigest: digest)
        }
        secretRequests.removeAll { $0.id == id }
        show(Toast(text: String(localized: "Secret request denied.")))
        await loadRequests()
    }

    /// «Fix my reused passwords» (ADR 0022 §6): everything that can fail is
    /// checked before Face ID, then the offer is signed and sent once.
    func offerFix(_ input: OfferInput, agent: String) async throws -> TaskItem {
        guard let service else { throw KlavError.Locked }
        _ = try await service.run { core, _ in try core.checkOffer(offer: input) }
        guard await confirmPresence(String(localized: "Offer \(agent) a task to change passwords")) else {
            throw RequestError.notConfirmed
        }
        let task = try await service.run { core, _ in try core.offerTask(offer: input) }
        await loadRequests()
        return task
    }

    /// «End task»: nothing asked, like denying.
    func endTask(_ card: TaskItem) async throws {
        guard let service else { return }
        let id = card.id
        _ = try await service.run { core, _ in try core.endTask(id: id) }
        tasks.removeAll { $0.id == id }
        show(Toast(text: String(localized: "Task ended. \(card.agent) can no longer use it.")))
        await loadRequests()
    }

    /// Signs the agent's grant for these projects (default policy).
    func approve(_ agent: AgentItem, projects: [String], expiresInDays: UInt32?) async throws {
        guard let service else { return }
        guard await confirmPresence(String(localized: "Approve the agent \(agent.name)")) else {
            throw RequestError.notConfirmed
        }
        let id = agent.id
        let words = agent.pairingWords
        _ = try await service.run { core, _ in
            try core.approveAgent(id: id, pairingWords: words, projectIds: projects, expiresInDays: expiresInDays)
        }
        registrations.removeAll { $0.id == id }
        show(Toast(text: String(localized: "\(agent.name) can use Klav now.")))
        await loadRequests()
    }

    func deny(_ agent: AgentItem) async throws {
        guard let service else { return }
        let id = agent.id
        try await service.run { core, _ in try core.denyAgent(id: id) }
        registrations.removeAll { $0.id == id }
        show(Toast(text: String(localized: "Denied. \(agent.name) won’t be able to use your account.")))
        await loadRequests()
    }

    // MARK: Pausing agents (ADR 0033 §7, §9)

    /// The pause of every agent in effect, if there is one: never hidden.
    var everyonePaused: PauseInfo? { Pauses(pauses).everyone }

    /// Re-reads the pauses this iPhone holds (after a sync).
    func readPauses() async {
        guard let service, phase == .unlocked,
              let paused = try? await service.run({ core, _ in try core.agentsPaused() }) else { return }
        guard phase == .unlocked else { return }
        keep(paused)
    }

    /// «Pause agents»: at once, nothing asked (P2). `minutes` nil: until
    /// the person resumes. Signed and sent now; a failure says why.
    func pauseAgents(agentId: String? = nil, minutes: Int?) async throws {
        guard let service else { return }
        let until = minutes.map { Pauses.now() + Int64($0) * 60_000 }
        let left = try await service.run { core, _ in try core.pauseAgents(agentId: agentId, untilMs: until) }
        keep(left)
        show(Toast(text: agentId == nil ? String(localized: "Every agent is paused.") : String(localized: "Paused.")))
        await loadRequests()
    }

    /// What «Resume» got from the person.
    enum ResumeOutcome: Equatable {
        case resumed
        /// No Face ID (or the person chose the password): ask for it.
        case needsPassword
        case cancelled
    }

    /// «Resume»: Face ID first, as approving; without Face ID the master
    /// password, never the iPhone's code (ADR 0033 P2).
    func resumeAgents(agentId: String? = nil) async throws -> ResumeOutcome {
        guard let service else { return .cancelled }
        authenticating = true
        let presence = await ResumePresence.check(agentId == nil ? String(localized: "Resume every agent")
                                                                 : String(localized: "Resume the agent"))
        authenticating = false
        switch presence {
        case .needsPassword: return .needsPassword
        case .cancelled: return .cancelled
        case .confirmed: break
        }
        let left = try await service.run { core, _ in try core.resumeAgents(agentId: agentId) }
        await resumed(left)
        return .resumed
    }

    /// «Resume» with the master password; a wrong one resumes nothing.
    func resumeAgents(agentId: String?, password: String) async throws {
        guard let service else { return }
        let left = try await service.run { core, _ in
            try core.resumeAgentsWithPassword(agentId: agentId, password: password)
        }
        await resumed(left)
    }

    private func resumed(_ left: [PauseInfo]) async {
        keep(left)
        show(Toast(text: String(localized: "Agents can use Klav again.")))
        await loadRequests()
    }

    // MARK: Notifications

    /// iOS gave this iPhone a token (at every launch, maybe while locked).
    func pushToken(_ token: String) {
        pushTokenValue = token
        Task { await registerPush() }
    }

    /// Tells the server where to notify; needs the vault open.
    private func registerPush() async {
        guard let service, phase == .unlocked, let token = pushTokenValue, token != registeredToken else { return }
        let sandbox = Push.sandbox
        do {
            try await service.run { core, _ in try core.registerPushToken(token: token, sandbox: sandbox) }
            registeredToken = token
            appLog.info("push: token registered (sandbox: \(sandbox, privacy: .public))")
        } catch {
            appLog.error("push: \(describe(error), privacy: .private)")
        }
    }

    // MARK: Face ID setting

    /// Turns Face ID on: the master password re-wraps the local key.
    // MARK: The account's server and emergency kit (ADR 0028)

    /// The emergency kit as text, rebuilt with today's server after the
    /// master password. It holds the Secret Key: show it, never log it.
    func emergencyKit(password: String) async throws -> String {
        guard let service else { throw KlavError.NotLoggedIn }
        return try await service.run { core, _ in
            try core.emergencyKit(password: password)
        }
    }

    /// Moves the account to another server URL: a full sign-in there with
    /// the master password, kept only if that server has this account.
    func moveServer(to text: String, password: String) async throws {
        guard let service else { return }
        let server = try serverFromInput(text: text)
        let saved = try await service.run { core, _ in
            try core.setServer(password: password, server: server)
        }
        preferences.lastServer = saved
        refresh()
    }

    func enableFaceID(password: String) async throws {
        preferences.faceID = true
        try await unlock(password: password)
        if biometrics?.enrolled != true {
            throw KlavError.BiometryUnavailable(message: "this iPhone has no Face ID set up")
        }
    }

    /// Turns Face ID off in Klav once the iPhone confirms its owner (Face
    /// ID, or its passcode), never with nothing or the master password
    /// alone (ADR 0037 A4). Refused, nothing changes and the switch goes
    /// back on.
    func disableFaceID() async throws {
        guard let service else { return }
        defer { refreshBiometrics() }
        let reason = String(localized: "Turn off Face ID for Klav")
        authenticating = true
        defer { authenticating = false }
        try await service.run { core, keystore in try core.forgetBiometrics(keystore: keystore, reason: reason) }
        preferences.faceID = false
        refresh()
    }

    // MARK: Leaving and coming back

    func scene(_ scene: ScenePhase) {
        appLog.debug("scene \(String(describing: scene), privacy: .public), phase \(String(describing: self.phase), privacy: .private)")
        switch scene {
        case .active:
            covered = false
            inForeground = true
            if away.cameBack(after: .seconds(preferences.autoLock.rawValue)), phase == .unlocked {
                lock(note: preferences.autoLock.lockNote)
            }
            refreshBiometrics()
            if phase == .unlocked {
                Task {
                    // Back from iOS Settings: maybe Klav was turned on.
                    await refreshAutofill()
                    await sync()
                    // Back from Safari: maybe AutoFill left a site to add.
                    await readSiteOffer()
                    await loadRequests()
                }
            }
        case .inactive:
            if !authenticating { covered = true }
        case .background:
            covered = true
            inForeground = false
            lockedByHand = false
            away.left()
            if preferences.autoLock == .immediately, phase == .unlocked { lock(note: AutoLock.immediately.lockNote) }
        @unknown default:
            break
        }
    }
}
