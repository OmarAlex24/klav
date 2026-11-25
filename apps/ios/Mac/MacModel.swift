import AppKit
import Foundation
import os
import SwiftUI
import UserNotifications

/// Lifecycle messages (never values or names from the vault).
let macLog = Logger(subsystem: "dev.klav.mac", category: "app")

/// Where the window is.
enum Section: Hashable {
    case vault(VaultFilter)
    case requests
    /// Development (ADR 0033, E1): the agents, their activity and the
    /// clients with their MCP entry and the skill.
    case agents
    /// Development › Sandboxes (ADR 0036 E4): the proxy on top, then the
    /// sandboxes it serves.
    case sandboxes
    case activity
    case clients
    case health
}

extension Section {
    /// The vault, whatever its filter.
    var isVault: Bool { if case .vault = self { return true }; return false }
}

/// What the vault list shows.
enum VaultFilter: Hashable {
    case all
    case kind(Kind)
    case vault(String)
    case project(String)

    /// Whether the list shows `item`.
    func includes(_ item: ItemInfo) -> Bool {
        switch self {
        case .all: return true
        case .kind(let kind): return item.kind == kind
        case .vault(let id): return item.vaultId == id
        case .project(let id): return item.projectId == id
        }
    }
}

/// The item editor (⌘N, ⌘E): a new item of a kind, or an item's changes.
enum EditorRequest: Identifiable, Equatable {
    case create(Kind)
    case edit(String)

    var id: String {
        switch self {
        case .create(let kind): return "new-\(kind)"
        case .edit(let item): return "edit-\(item)"
        }
    }
}

/// Asks for the master password when Touch ID cannot confirm, then runs
/// the action again with it.
struct PasswordPrompt: Identifiable {
    let id: UUID
    /// What it is for ("Approve the request of deploy-bot").
    let reason: String
    let retry: (String) async throws -> Void

    init(id: UUID = UUID(), reason: String, retry: @escaping (String) async throws -> Void) {
        self.id = id
        self.reason = reason
        self.retry = retry
    }
}

/// The app's state: `klavd`'s state, the requests of agents and the
/// window's place. Every engine call runs off the main thread.
@MainActor
final class MacModel: ObservableObject, RequestsModel {
    enum Phase: Equatable {
        case starting
        /// `klavd` does not answer on this home's socket.
        case noDaemon
        case signedOut
        case locked
        case unlocked
    }

    @Published private(set) var phase: Phase = .starting
    @Published private(set) var info: DaemonInfo?
    /// Touch ID is up: klavd asked the system (the prompt names «klavd»,
    /// riesgo residual 43), so the app says what it is waiting for.
    @Published private(set) var unlocking = false
    /// Moves when what the reads answer may have changed: views reload.
    @Published private(set) var generation = 0
    @Published private(set) var approvals: [ApprovalItem] = []
    @Published private(set) var registrations: [AgentItem] = []
    /// The account's agents by ID: the pairing words on the cards.
    @Published private(set) var knownAgents: [String: AgentItem] = [:]
    @Published private(set) var tasks: [TaskItem] = []
    @Published private(set) var secretRequests: [SecretRequestItem] = []
    /// What the person changed on each pending task card, by task ID.
    @Published private(set) var taskEdits: [String: TaskEdits] = [:]
    @Published private(set) var toast: Toast?
    @Published var section: Section = .vault(.all)
    @Published var selectedItem: String?
    /// The item editor, while it is open. Locking closes it, and with it
    /// whatever the person typed.
    @Published var editor: EditorRequest?
    /// The item waiting for «Move to the trash» to be confirmed.
    @Published var trashing: ItemInfo?
    @Published var passwordPrompt: PasswordPrompt?
    /// The app menu's «Uninstall Klav from this Mac…» opens its sheet.
    @Published var uninstalling = false
    /// What Activity shows when «Open in the log» opened it.
    @Published var activityItem: String?
    @Published var activityAgent: String?
    /// The newest thing an agent did, for the menu bar's line.
    @Published var lastAgentUse: LogEntryInfo?
    /// Development › Sandboxes (ADR 0036 E2, E4): the last list `klavd`
    /// gave, and why the last read failed. The menu bar's theft signals
    /// come from it, also while locked; signing out forgets it.
    @Published var sandboxList: SandboxListInfo?
    @Published var sandboxProblem: String?
    /// When `sandboxList` was read, by this Mac's clock (Unix ms): the
    /// heartbeat's age grows from it, and the footer says it.
    @Published var sandboxListReadMs: Int64 = 0
    /// The last read failed its checks (a log that doesn't verify, a
    /// server rolling back): no list is shown, the problem is, in red.
    @Published var sandboxIntegrity: SandboxIntegrity?
    /// Reads started and finished, in order: a read numbered after a
    /// revocation's answer is the one that can tell whether the server
    /// logged it.
    @Published var sandboxReadsDone = 0
    var sandboxReadsStarted = 0
    var sandboxRead: Task<Void, Never>?
    var sandboxesReadAt = Date.distantPast
    var readingSandboxes: Bool { sandboxRead != nil }
    /// The person's revocations waiting for the next read to show them in
    /// the verified log (ADR 0036 E3.3); `missed` once a read didn't.
    @Published var revocationChecks: [RevocationCheck] = []
    /// What the last action in Sandboxes answered, until the list it speaks
    /// of changes or the next action.
    @Published var sandboxNotice: SandboxNotice?
    /// Moves when the sandboxes are forgotten (signing out, the account
    /// deleted): a read that started before never lands after.
    var sandboxEpoch = 0
    #if DEBUG
    /// Tests: awaited once by the next read after `klavd` answered and
    /// before the list lands (an async suspension, no blocked thread).
    var sandboxReadHold: (@MainActor () async -> Void)?
    #endif
    /// «Revoke all» open in Development › Sandboxes.
    @Published var revokingAllSandboxes = false
    /// The proxy a «Revoke again» on a «Revoke all» names; nil: the list's.
    @Published var revokeAllFor: String?
    /// «Got it» on a theft signal, by sandbox ID, in memory only (Omar,
    /// 2026-11-17): after a restart it shows again, and nothing outside the
    /// app (its preferences, a launch argument) can mark one as seen.
    @Published var seenThefts: Set<String> = []
    /// Registrations this app launched in this session (ADR 0033 §3.1, P5):
    /// agent ID → its name and the pairing words its own `klav` child
    /// printed. Only in memory, so a restart forgets them and the person
    /// compares by eye.
    @Published var launchedRegistrations: [String: LaunchedRegistration] = [:]

    let engine: MacEngine
    /// Signs in or creates the account in this process (ADR 0027 §3).
    let accounts: AccountMaker
    private var timer: Timer?
    private var lastRevision: UInt64?
    private var lastRequests = Date.distantPast
    private var seenRequests: Set<String> = []
    private var notificationsAsked = false
    private var requestsLoaded = false
    /// `klav skill update` ran this launch.
    var skillChecked = false
    /// The clients and the skill were checked this launch (ADR 0033 §4, §6).
    var clientsChecked = false
    /// What changed outside Klav in a client's entry or a copy of the
    /// skill (T131, T132): shown in the menu bar and in Clients, also with
    /// Development hidden (E1).
    @Published var clientWarnings: [ClientWarning] = []
    /// «Leave it»: not said again until the app starts again.
    @Published var dismissedWarnings: Set<String> = []
    /// «See»: the client whose summary Clients opens, or the copy of the
    /// skill whose changes it shows.
    @Published var clientToShow: String?
    @Published var skillToShow: String?
    /// The window stays on «Set up this Mac» after signing in, for its
    /// «Agents» step, until the skill is installed or «Not now»
    /// (ADR 0033 E2.3). Only right after setting up: never after an update.
    @Published var agentsStepPending = false
    /// The sheet to sign in or create the account is open: the window
    /// stays on «Set up this Mac» until it closes.
    @Published var accountSheetOpen = false
    /// The deletion this app just asked for, until `klavd` can say: a
    /// locked `klavd` learns it at its next sync (ADR 0037). An unlocked
    /// one synced right after the request, so its word counts from then
    /// on, a cancel from another device included.
    @Published private(set) var askedHere: AccountDeletionInfo?
    private var askedHereAt = Date.distantPast
    /// Touch ID is up for the deletion: `klavd` asked the system.
    @Published private(set) var confirmingDeletion = false
    /// Development › Agents: the agent whose page is open.
    @Published var openAgent: String?
    /// «Revoke…» open on this agent (ADR 0033, amendment of 2026-11-10,
    /// F2). Locking closes it.
    @Published var revoking: RevokeRequest?
    /// «Change permissions…» open on this agent (F3). Locking closes it,
    /// with what was changed in it.
    @Published var changingGrant: GrantChangeRequest?
    /// Revocations started from this app, by agent: «Revoked» at once,
    /// «Done» only once the key change says it is complete.
    @Published var revocationFlows: [String: RevocationFlow] = [:]
    /// «Revoke…» was open, or refused, while Klav locked: it opens again
    /// after unlocking (P12). Never a revocation kept to send later.
    @Published var revokeAfterUnlock: String?

    /// The window shows «Set up this Mac»: without `klavd` or an account,
    /// while the account sheet is open (the phase can pass through
    /// `.locked` and `.unlocked` under it), and then for the «Agents» step.
    var showsSetup: Bool {
        switch phase {
        case .signedOut, .noDaemon: return true
        case .starting: return false
        case .locked: return accountSheetOpen
        case .unlocked: return accountSheetOpen || agentsStepPending
        }
    }

    /// Signs in or creates the account in this process, then has `klavd`
    /// open the vault (ADR 0027 §3): only `klavd` keeps it open. Returns
    /// the new account's emergency kit. Done, the «Agents» step comes next
    /// unless the person already decided it (E2.3): set here, not from the
    /// phase, which may go `.signedOut` → `.locked` → `.unlocked` when the
    /// poll lands between signing in and `klavd`'s unlock.
    func makeAccount(signUp: Bool, server: String, email: String, password: String, secretKey: String,
                     deviceName: String, stepDecided: Bool? = nil) async throws -> String? {
        let stepDecided = stepDecided ?? AgentsStep.decided
        let accounts = accounts, engine = engine
        let kit = try await Task.detached(priority: .userInitiated) { () -> String? in
            var kit: String?
            if signUp {
                kit = try accounts.signUp(server: server, email: email, password: password, deviceName: deviceName)
            } else {
                try accounts.signIn(server: server, email: email, password: password, secretKey: secretKey,
                                    deviceName: deviceName)
            }
            // klavd opens the vault (and offers Touch ID from now on).
            try engine.unlock(password: password)
            return kit
        }.value
        if !stepDecided { agentsStepPending = true }
        refresh()
        return kit
    }

    init(engine: MacEngine, accounts: AccountMaker) {
        self.engine = engine
        self.accounts = accounts
    }

    /// Waiting for the person: registrations, secret requests, tasks to decide, approvals.
    var pendingCount: Int {
        approvals.count
            + registrations.count
            + tasks.filter { $0.status == "pending" }.count
            + secretRequests.filter { $0.status == "pending" }.count
    }

    // MARK: Engine calls

    /// Runs `body` on a background thread.
    func run<T: Sendable>(_ body: @escaping @Sendable (MacEngine) throws -> T) async throws -> T {
        let engine = engine
        return try await Task.detached(priority: .userInitiated) { try body(engine) }.value
    }

    // MARK: State

    /// Polls `klavd`: its state every 2 s (a Unix socket, cheap), the
    /// requests every 10 s while unlocked.
    func start() {
        guard timer == nil else { return }
        refresh()
        timer = Timer.scheduledTimer(withTimeInterval: 2, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.refresh() }
        }
    }

    func refresh() {
        Task {
            let asked = Date()
            let info = await Task.detached(priority: .utility) { [engine] in engine.status() }.value
            apply(info, askedAt: asked)
        }
    }

    private func apply(_ info: DaemonInfo, askedAt: Date) {
        self.info = info
        followKeyChanges(info, askedAt: askedAt)
        if info.accountDeletion != nil || !info.loggedIn || info.accountDeleted
            || (info.unlocked && askedAt > askedHereAt) {
            askedHere = nil
        }
        if info.accountDeleted {
            if sandboxList != nil { forgetSandboxes() }
            // Read-only (D-C): only the vault, and nothing for the agents.
            if case .vault = section {} else { section = .vault(.all) }
            if !approvals.isEmpty || !registrations.isEmpty || !tasks.isEmpty { clearRequests() }
            // Nothing can be saved or approved any more: the editor goes,
            // with what was typed, and so does the master password's sheet.
            closeSheets()
        }
        let next: Phase
        if !info.running {
            next = .noDaemon
        } else if !info.loggedIn {
            next = .signedOut
        } else {
            next = info.unlocked ? .unlocked : .locked
        }
        if next != phase {
            phase = next
            // «Unlock Klav to revoke…» and the like stop being true.
            sandboxNotice = nil
            if next != .unlocked { clearRequests() }
            if next == .signedOut { forgetSandboxes() }
            if next == .unlocked { resumeRevoking() }
        }
        if lastRevision != info.revision {
            lastRevision = info.revision
            generation += 1
        }
        if phase == .unlocked, !info.accountDeleted, Date().timeIntervalSince(lastRequests) >= 10 {
            loadRequests()
        }
    }

    private func forgetSandboxes() {
        sandboxList = nil
        sandboxProblem = nil
        sandboxIntegrity = nil
        sandboxListReadMs = 0
        revocationChecks = []
        revokeAllFor = nil
        sandboxNotice = nil
        sandboxEpoch += 1
        sandboxesReadAt = .distantPast
    }

    private func clearRequests() {
        approvals = []
        registrations = []
        knownAgents = [:]
        tasks = []
        secretRequests = []
        selectedItem = nil
        lastAgentUse = nil
        closeSheets()
    }

    /// Closes the window's sheets that need Klav unlocked and an account:
    /// the editor (with what was typed), the trash's confirmation and the
    /// master password. Runs when Klav locks and once the account is
    /// deleted, so none of them stays over the lock screen. A withdrawn
    /// master password prompt can no longer run its action
    /// (`withPresence`).
    private func closeSheets() {
        if editor != nil { editor = nil }
        if trashing != nil { trashing = nil }
        if passwordPrompt != nil { passwordPrompt = nil }
        if changingGrant != nil { changingGrant = nil }
        if revokingAllSandboxes { revokingAllSandboxes = false }
        revokeAllFor = nil
        if let request = revoking {
            // Not revoked yet: «Revoke…» opens again after unlocking (P12).
            // Once revoked, the agent's page says what is left instead.
            if revocationFlows[request.agentId] == nil { revokeAfterUnlock = request.agentId }
            revoking = nil
        }
    }

    /// Something changed here (an edit, a decision): read again now.
    func changed() {
        generation += 1
        loadRequests()
    }

    func loadRequests() {
        lastRequests = Date()
        Task {
            do {
                let (approvals, agents, tasks, secretReqs) = try await run { engine in
                    let sr = (try? engine.secretRequests()) ?? []
                    return (try engine.approvals(), try engine.agents(), try engine.tasks(), sr)
                }
                self.approvals = approvals
                registrations = agents.filter { $0.status == "pending" }
                knownAgents = Dictionary(agents.map { ($0.id, $0) }, uniquingKeysWith: { first, _ in first })
                self.tasks = tasks
                self.secretRequests = secretReqs.filter { $0.status == "pending" }
                let live = Set(tasks.map(\.id))
                taskEdits = taskEdits.filter { live.contains($0.key) }
                notifyNew()
            } catch KlavError.Locked {
                refresh()
            } catch {
                macLog.info("requests failed")
            }
        }
    }

    // MARK: Unlocking

    func unlockWithTouchID() async throws {
        unlocking = true
        defer { unlocking = false }
        try await run { try $0.unlock(password: nil) }
        opened()
    }

    func unlock(password: String) async throws {
        unlocking = true
        defer { unlocking = false }
        try await run { try $0.unlock(password: password) }
        opened()
    }

    private func opened() {
        refresh()
        loadRequests()
        askForNotifications()
    }

    func lock() {
        Task {
            _ = try? await run { try $0.lock() }
            clearRequests()
            refresh()
        }
    }

    /// Touch ID can open klavd now.
    var touchIDReady: Bool {
        guard let info else { return false }
        return info.touchIdAvailable && info.touchIdEnrolled && info.passwordRequired == nil
    }

    // MARK: Deleting the account (ADR 0037)

    /// The deletion the person asked for, while it is pending: Settings ›
    /// Account and the band above the window's content (§7.4).
    var accountDeletion: AccountDeletionInfo? {
        accountDeleted ? nil : info?.accountDeletion ?? askedHere
    }

    /// Klav deleted the account (§7.6): the vault stays, read-only, until
    /// the person deletes this Mac's copy (D-C).
    var accountDeleted: Bool { info?.accountDeleted == true }

    /// When it was deleted, as `klavd` knew it.
    var deletedAt: Int64? { accountDeleted ? info?.accountDeletion?.deleteAt : nil }

    /// Whether the server can, asked before Touch ID or the password (§4).
    func deletionSupported() async throws -> Bool {
        try await run { try $0.deletionSupported() }
    }

    /// Asks the server to delete the account in 7 days: Touch ID through
    /// `klavd` where it is set up, then the master password, here.
    func requestAccountDeletion(password: String) async throws {
        confirmingDeletion = true
        defer { confirmingDeletion = false }
        do {
            let asked = try await run { try $0.requestAccountDeletion(password: password) }
            askedHere = asked
            askedHereAt = Date()
        } catch KlavError.DeletionAlreadyScheduled(let message) {
            // Asked from another device, or an answer lost: klavd syncs,
            // and the band shows the date.
            _ = try? await run { try $0.sync() }
            refresh()
            throw KlavError.DeletionAlreadyScheduled(message: message)
        }
        refresh()
    }

    /// «Cancel the deletion»: it brings the agents back, so it asks what
    /// resuming them asks (ADR 0037 A2): Touch ID through `klavd`, or the
    /// master password where Touch ID can't. `done` gets whether there was
    /// one to cancel, once it is over.
    func cancelAccountDeletion(done: @escaping @MainActor (Bool) -> Void = { _ in }) async throws {
        let canceled = Box(false)
        do {
            try await withPresence(String(localized: "Cancel the deletion of your account")) { engine, password in
                canceled.value = try engine.cancelAccountDeletionWithPassword(password: password)
            } done: { [weak self] in
                self?.deletionCanceled(canceled.value)
                done(canceled.value)
            }
        } catch KlavError.AccountDeleted(let deleteAt, let message) {
            // Too late: the server already deleted it. klavd says so next.
            refresh()
            throw KlavError.AccountDeleted(deleteAt: deleteAt, message: message)
        }
    }

    private func deletionCanceled(_ canceled: Bool) {
        askedHere = nil
        // Nothing to cancel: another device did first.
        show(Toast(text: canceled
                   ? String(localized: "The deletion was canceled. Your agents work again.")
                   : String(localized: "The deletion was already canceled.")))
        refresh()
    }

    /// What «Delete this Mac’s copy» would lose: generated passwords that
    /// never went up (ADR 0037 Q3). `.unknown` when Klav couldn't tell.
    func deleteCopyCheck() async -> UnsentLoss {
        UnsentLoss(try? await run { try $0.deleteCopyCheck() })
    }

    /// The generated passwords that never went up, to copy them before the
    /// copy goes. Needs `klavd` unlocked.
    func unsentGenerated() async throws -> [GeneratedEntryInfo] {
        try await run { try $0.generatorHistory() }.filter(\.pending)
    }

    /// «Delete this Mac’s copy»: stops `klavd` and deletes the account's
    /// files here. Then `restart` brings `klavd` back, signed out.
    /// Refused (`Denied`) while generated passwords wait, unless
    /// `discardUnsent`. A refusal after `klavd` stopped brings it back too,
    /// still with the account, so the person can copy them.
    func deleteThisCopy(discardUnsent: Bool, restart: @escaping @Sendable () async -> Void) async throws {
        do {
            try await run { try $0.deleteThisCopy(discardUnsent: discardUnsent) }
        } catch {
            let running = await Task.detached(priority: .userInitiated) { [engine] in engine.status().running }.value
            if !running { await restart() }
            refresh()
            throw error
        }
        await restart()
        refresh()
    }

    // MARK: Presence

    /// Runs an action that klavd confirms with Touch ID; when Touch ID
    /// cannot (a Mac without it, or turned off), asks for the master
    /// password and runs it again with it. `done` runs after either.
    /// Nothing waits on the prompt: this returns once it is up, and the
    /// action runs from the sheet. Once the prompt is withdrawn (Klav
    /// locked, the account was deleted, another prompt took its place),
    /// its action throws `CancellationError` instead of running.
    func withPresence(_ reason: String,
                      _ action: @escaping @Sendable (MacEngine, String?) throws -> Void,
                      done: @escaping @MainActor () -> Void) async throws {
        do {
            try await run { try action($0, nil) }
        } catch let error as KlavError where error.wantsPassword {
            let id = UUID()
            passwordPrompt = PasswordPrompt(id: id, reason: reason) { [weak self] password in
                guard let self else { return }
                guard self.passwordPrompt?.id == id else { throw CancellationError() }
                try await self.run { try action($0, password) }
                // Closed here, before `done` closes the sheet it sits on:
                // nothing is left for the window to show again.
                if self.passwordPrompt?.id == id { self.passwordPrompt = nil }
                done()
                self.changed()
            }
            return
        }
        done()
        changed()
    }

    /// `withPresence` for an action whose answer the caller needs (the
    /// report of a signed grant change): `done` gets it.
    func withPresenceResult<T: Sendable>(_ reason: String,
                                         _ action: @escaping @Sendable (MacEngine, String?) throws -> T,
                                         done: @escaping @MainActor (T) -> Void) async throws {
        let value: T
        do {
            value = try await run { try action($0, nil) }
        } catch let error as KlavError where error.wantsPassword {
            let id = UUID()
            passwordPrompt = PasswordPrompt(id: id, reason: reason) { [weak self] password in
                guard let self else { return }
                guard self.passwordPrompt?.id == id else { throw CancellationError() }
                let value = try await self.run { try action($0, password) }
                // Closed here, before `done` closes the sheet it sits on:
                // nothing is left for the window to show again.
                if self.passwordPrompt?.id == id { self.passwordPrompt = nil }
                done(value)
                self.changed()
            }
            return
        }
        done(value)
        changed()
    }

    var waitingForPresence: String {
        touchIDReady ? String(localized: "Waiting for Touch ID…") : String(localized: "Checking…")
    }

    /// Deny, approve once (`leaseMinutes` 0) or approve for a while.
    func decide(_ approval: ApprovalItem, approve: Bool, leaseMinutes: UInt32) async throws {
        let id = approval.id, agent = approval.agent, digest = approval.requestDigest
        let gone: @MainActor () -> Void = { [weak self] in
            self?.approvals.removeAll { $0.id == id }
            self?.show(Toast(text: approve ? String(localized: "Approved. \(agent) can go on.") : String(localized: "Denied.")))
        }
        if !approve {
            try await run { try $0.decideApproval(id: id, approve: false, leaseMinutes: 0, requestDigest: digest) }
            gone()
            changed()
            return
        }
        try await withPresence(String(localized: "Approve \(agent)’s request")) { engine, password in
            try engine.decideApprovalWithPassword(id: id, approve: true, leaseMinutes: leaseMinutes,
                                                  requestDigest: digest, password: password)
        } done: { gone() }
    }

    /// «Add to the task»: the next revision of the running task, same
    /// end, and this request approved once.
    func addToTask(_ approval: ApprovalItem) async throws {
        guard let task = approval.task else { return }
        let id = approval.id, title = task.task, digest = approval.requestDigest
        try await withPresence(String(localized: "Add to \(approval.agent)’s task")) { engine, password in
            _ = try engine.addToTaskWithPassword(approvalId: id, requestDigest: digest, password: password)
        } done: { [weak self] in
            self?.approvals.removeAll { $0.id == id }
            self?.show(Toast(text: String(localized: "Added to the task “\(title)”.")))
        }
    }

    /// Approves a task with what the person left checked, or denies it.
    func decideTask(_ card: TaskItem, approve: Bool) async throws {
        let id = card.id, agent = card.agent, digest = card.requestDigest
        let edits = taskEdits[id] ?? TaskEdits()
        let gone: @MainActor () -> Void = { [weak self] in
            self?.taskEdits[id] = nil
            self?.tasks.removeAll { $0.id == id }
            self?.show(Toast(text: approve ? String(localized: "Task approved. \(agent) can start.") : String(localized: "Task denied.")))
        }
        if !approve {
            _ = try await run { try $0.decideTask(id: id, approve: false, choice: nil, requestDigest: digest) }
            gone()
            changed()
            return
        }
        guard edits.anyChecked(card) else { throw RequestError.nothingChecked }
        let choice = edits.choice(for: card)
        try await withPresence(String(localized: "Approve \(agent)’s task")) { engine, password in
            _ = try engine.decideTaskWithPassword(id: id, approve: true, choice: choice, requestDigest: digest,
                                                  password: password)
        } done: { gone() }
    }

    /// «End task»: nothing asked, like denying.
    func endTask(_ card: TaskItem) async throws {
        let id = card.id
        _ = try await run { try $0.endTask(id: id) }
        tasks.removeAll { $0.id == id }
        show(Toast(text: String(localized: "Task ended. \(card.agent) can no longer use it.")))
        changed()
    }

    func editTask(_ card: TaskItem, _ change: (inout TaskEdits) -> Void) {
        var edits = taskEdits[card.id] ?? TaskEdits()
        change(&edits)
        taskEdits[card.id] = edits
    }

    /// Fulfills a pending secret request (ADR 0046). Granting `klav-proxy`
    /// access asks for Touch ID (or master password) through `klavd` (T239).
    func fulfillSecretRequest(_ card: SecretRequestItem, input: SecretRequestFulfillInput) async throws -> SecretRequestFulfillOutput {
        let id = card.id
        let saved = Box<SecretRequestFulfillOutput?>(nil)
        if input.grantProxy {
            try await withPresence(String(localized: "Save and grant credential proxy for \(card.agent)")) { engine, password in
                saved.value = try engine.fulfillSecretRequestWithPassword(id: id, input: input, password: password)
            } done: { [weak self] in
                self?.secretRequests.removeAll { $0.id == id }
                self?.show(Toast(text: String(localized: "Saved to Klav.")))
            }
            guard let output = saved.value else { throw RequestError.notConfirmed }
            return output
        }
        let output = try await run { try $0.fulfillSecretRequest(id: id, input: input) }
        secretRequests.removeAll { $0.id == id }
        show(Toast(text: String(localized: "Saved to Klav.")))
        changed()
        return output
    }

    /// Denies a pending secret request with a signed decision.
    func denySecretRequest(_ card: SecretRequestItem) async throws {
        let id = card.id
        let digest = card.proposalDigest
        _ = try await run { try $0.denySecretRequest(id: id, proposalDigest: digest) }
        secretRequests.removeAll { $0.id == id }
        show(Toast(text: String(localized: "Secret request denied.")))
        changed()
    }

    /// Signs the agent's grant for these projects (the CLI's default policy).
    func approve(_ agent: AgentItem, projects: [String], expiresInDays: UInt32?) async throws {
        let id = agent.id, words = agent.pairingWords, name = agent.name
        try await withPresence(String(localized: "Approve the agent \(name)")) { engine, password in
            _ = try engine.approveAgentWithPassword(id: id, pairingWords: words, projectIds: projects,
                                                   expiresInDays: expiresInDays, password: password)
        } done: { [weak self] in
            self?.registrations.removeAll { $0.id == id }
            self?.show(Toast(text: String(localized: "\(name) can use Klav now.")))
        }
    }

    func deny(_ agent: AgentItem) async throws {
        let id = agent.id
        try await run { try $0.denyAgent(id: id) }
        registrations.removeAll { $0.id == id }
        show(Toast(text: String(localized: "Denied. \(agent.name) won’t be able to use your account.")))
        changed()
    }

    func agentProjects() async throws -> [ProjectInfo] {
        try await run { try $0.projects(vaultId: nil) }
    }

    /// Saves or clears a person-owned label and/or machine host for an agent
    /// (ADR 0047). Stored E2E-encrypted in the personal vault's system project.
    func setAgentLabel(id: String, label: String?, host: String?) async throws {
        try await run { try $0.setAgentLabel(id: id, label: label, host: host) }
        changed()
    }

    /// Replaces the linked Git repositories of a project (ADR 0032 §2).
    @discardableResult
    func setProjectRepos(vaultId: String, projectId: String, repos: [String]) async throws -> ProjectInfo {
        let updated = try await run { try $0.setProjectRepos(vaultId: vaultId, projectId: projectId, repos: repos) }
        changed()
        return updated
    }

    /// The pairing words of an agent this account approved: its signed
    /// grant ties them to the agent's key, unlike the name. Nil for any
    /// other agent.
    func pairingWords(ofAgent id: String) -> String? {
        guard let agent = knownAgents[id], agent.status == "active", !agent.projects.isEmpty else { return nil }
        return agent.pairingWords
    }

    // MARK: Items

    /// Items can be created, edited and trashed: unlocked, with an account
    /// that still exists (read-only after the deletion, ADR 0037 D-C), and
    /// not in the middle of «Set up this Mac».
    var canChangeItems: Bool { phase == .unlocked && !accountDeleted && !showsSetup }

    /// A sheet of the window's is open: the editor (and the generator in
    /// it), the trash's confirmation, the master password or «Uninstall».
    /// ⌘N and ⌘E wait for it to close: a new editor would replace the
    /// sheet and throw away what the person typed in it.
    var sheetOpen: Bool { editor != nil || trashing != nil || passwordPrompt != nil || uninstalling }

    /// «New item» (⌘N): of the kind the list shows, if the editor makes
    /// that kind, else a login. Nothing while a sheet is open.
    func newItem() {
        guard canChangeItems, !sheetOpen else { return }
        var kind: Kind = .login
        if case .vault(.kind(let shown)) = section, ItemDraft.creatable.contains(shown) { kind = shown }
        if case .vault = section {} else { section = .vault(.all) }
        editor = .create(kind)
    }

    /// «Edit» (⌘E): the item open in the vault. Nothing while a sheet is
    /// open.
    func editSelected() {
        guard canChangeItems, !sheetOpen, case .vault = section, let id = selectedItem else { return }
        editor = .edit(id)
    }

    /// The editor saved: the item opens in the list (all items if the list
    /// would hide a new one).
    func saved(_ info: ItemInfo, created: Bool) {
        editor = nil
        if created, case .vault(let filter) = section, !filter.includes(info) { section = .vault(.all) }
        selectedItem = info.id
        show(Toast(text: created ? String(localized: "Saved to the vault.") : String(localized: "Changes saved.")))
        changed()
    }

    /// «Move to the trash», once the person confirmed it.
    func trash(_ item: ItemInfo) async throws {
        let id = item.id
        try await run { try $0.trashItem(id: id) }
        trashing = nil
        if selectedItem == id { selectedItem = nil }
        show(Toast(text: String(localized: "Moved to the trash.")))
        changed()
    }

    /// The sites an agent added (ADR 0030 §7). Confirm: an edit of the
    /// person's with no changes, so the new version is theirs and all its
    /// sites count. Remove: that same edit without them.
    func settleSites(_ info: ItemInfo, remove: Bool) async throws {
        let id = info.id
        let edit = ItemEdit(removeUrls: remove ? info.pendingUrls : [])
        _ = try await run { try $0.editItem(id: id, edit: edit) }
        show(Toast(text: remove ? String(localized: "Removed the sites the agent added.")
                                : String(localized: "Confirmed. Klav fills on those sites now.")))
        changed()
    }

    // MARK: Fix my reused passwords (ADR 0022 §6)

    /// The card: the logins that share a password, checked against
    /// `agent`'s grant, and the agents that can take the task.
    func reusedOffer(agent: String?) async throws -> ReusedOfferInfo {
        try await run { try $0.reusedOffer(agent: agent) }
    }

    /// The running fix tasks this person offered, with each site's state.
    /// A failed read leaves a task out: progress is a courtesy here.
    func fixProgress() async -> [TaskProgressInfo] {
        guard let tasks = try? await run({ try $0.tasks() }) else { return [] }
        let now = Int64(Date().timeIntervalSince1970 * 1000)
        var list: [TaskProgressInfo] = []
        for task in tasks where HealthWords.isFixTask(task, now: now) {
            let id = task.id
            if let progress = try? await run({ try $0.taskProgress(taskId: id) }) { list.append(progress) }
        }
        return list
    }

    // MARK: Copying

    func copy(_ value: String, what: String? = nil) {
        Clipboard.copy(value)
        show(Toast(text: what ?? "", clears: Clipboard.clearAfter))
    }

    func show(_ toast: Toast) {
        self.toast = toast
        let id = toast.id
        Task {
            try? await Task.sleep(for: .seconds(3))
            if self.toast?.id == id { self.toast = nil }
        }
    }

    // MARK: Notifications (local: no APNs on the Mac, ADR 0027 §1)

    private func askForNotifications() {
        guard !notificationsAsked, Bundle.main.bundleIdentifier != nil else { return }
        // Not in the tests or on the sample vault: nothing is left behind in
        // the Mac's notification settings.
        guard ProcessInfo.processInfo.environment["XCTestConfigurationFilePath"] == nil,
              !UserDefaults.standard.bool(forKey: "KlavSample") else { return }
        notificationsAsked = true
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound, .badge]) { _, _ in }
    }

    /// One system notification per request seen for the first time. The
    /// first load after unlocking only remembers what is there.
    private func notifyNew() {
        let first = !requestsLoaded
        requestsLoaded = true
        var fresh: [(String, String, String)] = []
        for a in approvals where !seenRequests.contains(a.id) {
            let target = RequestWords.target(a.target).title
            fresh.append((a.id, a.agent, RequestWords.wants(a.permission, target)))
        }
        for r in registrations where !seenRequests.contains(r.id) {
            fresh.append((r.id, r.name, String(localized: "Wants to join your Klav as an agent")))
        }
        for t in tasks where t.status == "pending" && !seenRequests.contains(t.id) {
            fresh.append((t.id, t.agent, String(localized: "Asks to start the task “\(t.task)”")))
        }
        for sr in secretRequests where sr.status == "pending" && !seenRequests.contains(sr.id) {
            fresh.append((sr.id, sr.agent, String(localized: "Asks you to save a secret in Klav")))
        }
        for (id, _, _) in fresh { seenRequests.insert(id) }
        guard !first, !fresh.isEmpty, notificationsAsked else { return }
        let center = UNUserNotificationCenter.current()
        for (id, agent, body) in fresh {
            let content = UNMutableNotificationContent()
            content.title = agent
            content.body = body
            content.userInfo = ["request": id]
            center.add(UNNotificationRequest(identifier: id, content: content, trigger: nil))
        }
    }
}

/// A value set on a background thread and read after it is done.
final class Box<T>: @unchecked Sendable {
    var value: T
    init(_ value: T) { self.value = value }
}

extension MacModel: FixOffering {
    /// Offers the task: `klavd` checks the offer, then asks for Touch ID;
    /// where Touch ID can't, the master password sheet asks and the offer
    /// goes again with it. `offered` gets the task once it is signed.
    func offerFix(_ input: OfferInput, agent: String, offered: @escaping @MainActor (TaskItem) -> Void) async throws {
        let signed = Box<TaskItem?>(nil)
        try await withPresence(String(localized: "Offer \(agent) a task to change passwords")) { engine, password in
            signed.value = try engine.offerTaskWithPassword(offer: input, password: password)
        } done: {
            if let task = signed.value { offered(task) }
        }
    }
}

