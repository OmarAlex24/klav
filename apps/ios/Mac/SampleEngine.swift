#if DEBUG
import Foundation

/// A made-up vault for screenshots and previews (`-KlavSample YES`, debug
/// builds only): no `klavd`, no server, no real secret. Decisions change
/// the lists so the screens can be clicked through.
///
/// `-KlavSampleLocked YES` starts it locked; `-KlavSampleNoTouchID YES`
/// is a Mac without Touch ID; `-KlavSampleSignedOut YES` has no account
/// yet (the setup screen); `-KlavSampleDeletion pending|deleted|unsupported`
/// is the account's deletion (ADR 0037) asked, done, or a server that
/// cannot; `deleted-unsent` is done with two generated passwords that never
/// went up; `-KlavSampleFix YES` has «Fix my reused passwords» running;
/// `-KlavSampleKeysLeft YES` has old-scraper revoked with keys left to
/// change (ADR 0033, amendment of 2026-11-10).
final class SampleEngine: MacEngine, @unchecked Sendable {
    private let mutex = NSLock()
    private var unlocked: Bool
    private var loggedIn: Bool
    private var approvalList: [ApprovalItem]
    private var taskList: [TaskItem]
    private var secretRequestList: [SecretRequestItem] = []
    private var agentList: [AgentItem]
    private var breachCheck = false
    private let touchID: Bool
    /// «Pause agents»: `-KlavSamplePaused YES` starts with every agent paused.
    private var pauses: [PauseInfo]
    /// The last event this Mac verified (`klav log verify`).
    private var verifiedSeq: UInt64 = 209
    /// The account's deletion (ADR 0037), and whether it happened.
    private var deletion: AccountDeletionInfo?
    private var deleted = false
    private let deletionSupport: Bool
    /// Generated passwords only in this Mac's outbox (ADR 0037 Q3).
    private var unsent: [GeneratedEntryInfo] = []

    /// An agent's grant in the sample: what the editor shows.
    private struct SampleGrant {
        var projects: [GrantedProjectInfo]
        var editor: EditorPolicyInfo?
        var readOnly: ReadOnlyKind?
        var rules: [RuleInfo] = []
        var version: UInt64
    }

    private var grants: [String: SampleGrant] = [:]
    /// Revocations whose key change is not finished, by agent.
    private var keysLeft: [String: RevocationInfo] = [:]
    /// Tests: the key change waits on it, so «Revoked» shows before «Done».
    var rotationGate: DispatchSemaphore?
    /// Tests: the key change stops after the first project.
    var rotationFails = false
    /// Tests: a `klavd` older than the background key change, the editor
    /// and the revocations list.
    var olderKlavd = false
    /// Tests: `agent_revocations` fails.
    var revocationsFail = false
    /// Tests: `klavd` can't read its record of key changes (`status` says
    /// so, `agent_revocations` fails).
    var recordUnreadable = false
    /// With `recordUnreadable`: a newer Klav wrote the record.
    var recordNewer = false
    /// Tests: what a revocation report says Klav can't reach.
    var reportSkips: [String] = []
    /// Tests: pausing fails.
    var pauseFails = false
    /// `agent_exposure` fails (the server did not answer).
    var exposureFails = false
    /// Tests: agents whose grant this Mac can't read (no projects known).
    var unreadableGrants: Set<String> = []
    /// Tests: agents with an item granted one by one whose key does not
    /// change the first time.
    var itemsPendingOnce: Set<String> = []
    /// Tests: every revocation asked, as `id rotate background`.
    private(set) var revokeCalls: [String] = []

    private struct Sample {
        var info: ItemInfo
        var fields: [FieldInfo]
        var notes: String?
        var totp: Bool
    }

    /// The items; creating, editing and trashing change them.
    private var samples: [Sample]

    /// Without arguments, from the launch arguments.
    init(locked: Bool? = nil, touchID: Bool? = nil, signedOut: Bool? = nil, deletion: String? = nil,
         keysLeft: Bool? = nil) {
        let defaults = UserDefaults.standard
        loggedIn = !(signedOut ?? defaults.bool(forKey: "KlavSampleSignedOut"))
        unlocked = loggedIn && !(locked ?? defaults.bool(forKey: "KlavSampleLocked"))
        self.touchID = touchID ?? !defaults.bool(forKey: "KlavSampleNoTouchID")
        let now = Self.now
        let deletionState = deletion ?? defaults.string(forKey: "KlavSampleDeletion")
        deletionSupport = deletionState != "unsupported"
        switch deletionState {
        case "pending":
            // Asked from the iPhone two days ago.
            self.deletion = AccountDeletionInfo(requestedAt: now - 2 * 86_400_000, deleteAt: now + 5 * 86_400_000,
                                                deviceName: "iPhone de Ana", thisDevice: false, deleted: false)
        case "deleted", "deleted-unsent":
            self.deletion = AccountDeletionInfo(requestedAt: now - 7 * 86_400_000 - 3_600_000,
                                                deleteAt: now - 3_600_000, deviceName: "MacBook de Ana",
                                                thisDevice: true, deleted: true)
            deleted = true
            if deletionState == "deleted-unsent" {
                unsent = [
                    GeneratedEntryInfo(createdAt: now - 26 * 3_600_000, host: "app.linear.app",
                                       savedInTitle: nil, pending: true),
                    GeneratedEntryInfo(createdAt: now - 9 * 86_400_000, host: "github.com",
                                       savedInTitle: nil, pending: true),
                ]
            }
        default:
            break
        }
        samples = Self.makeSamples(now: now)
        pauses = defaults.bool(forKey: "KlavSamplePaused")
            ? [PauseInfo(agentId: nil, sinceMs: now - 6 * 60_000, untilMs: now + 54 * 60_000, local: false,
                         serverUnsupported: false)]
            : []
        approvalList = [
            ApprovalItem(id: "ap1", status: "pending", agentId: "ag1", agent: "deploy-bot", permission: "fill",
                         target: "klav://Trabajo/Infra/AWS console/password", reason: "Deploy the staging stack",
                         domain: "signin.aws.amazon.com", createdAt: now - 40_000, expiresAt: now + 260_000, task: nil,
                         requestDigest: "sample-ap1"),
            ApprovalItem(id: "ap2", status: "pending", agentId: "ag2", agent: "release-agent", permission: "reveal",
                         target: "klav://Trabajo/Backend/Stripe/secret", reason: "Rotate the webhook signing key",
                         domain: nil, createdAt: now - 10_000, expiresAt: now + 170_000,
                         task: OutsideTaskItem(id: "t2", task: "Ship version 0.9", expiresAt: now + 3_000_000, canAdd: true),
                         requestDigest: "sample-ap2"),
        ]
        let fill = TaskPermissionItem(permission: "fill", checked: true, asked: true, addedByKlav: false, deniedByPolicy: false, noSite: false)
        let code = TaskPermissionItem(permission: "totp", checked: true, asked: false, addedByKlav: true, deniedByPolicy: false, noSite: false)
        let inject = TaskPermissionItem(permission: "inject", checked: true, asked: true, addedByKlav: false, deniedByPolicy: false, noSite: false)
        let update = TaskPermissionItem(permission: "update", checked: false, asked: true, addedByKlav: false, deniedByPolicy: true, noSite: false)
        func row(_ id: String, _ title: String, _ user: String?, _ ref: String, _ domains: [String],
                 _ permissions: [TaskPermissionItem]) -> TaskRowItem {
            TaskRowItem(vaultId: "v2", projectId: "p2", itemId: id, reference: ref, title: title, username: user,
                        missing: false, askedDomain: domains.first, domainMismatch: false, domains: domains,
                        permissions: permissions, noSite: false, domainClaimed: false)
        }
        taskList = [
            TaskItem(id: "t1", status: "pending", agentId: "ag2", agent: "release-agent", task: "Publish the docs site",
                     reason: "Upload the new build to the CDN and purge the cache", offered: false, durationSecs: 3600,
                     createdAt: now - 20_000, decideBy: now + 280_000, decidedAt: nil, revision: 0, expiresAt: nil,
                     endedAt: nil, endedBy: nil,
                     rows: [row("i-gh", "GitHub", "ana-dev", "klav://Trabajo/Backend/GitHub", ["github.com"], [fill, code]),
                            row("i-cf", "Cloudflare", "ana@example.com", "klav://Trabajo/Infra/Cloudflare",
                                ["dash.cloudflare.com"], [inject, update])],
                     requestDigest: "sample-t1"),
            TaskItem(id: "t2", status: "approved", agentId: "ag2", agent: "release-agent", task: "Ship version 0.9",
                     reason: "Tag, build and publish the release", offered: false, durationSecs: 7200,
                     createdAt: now - 4_300_000, decideBy: now - 4_000_000, decidedAt: now - 4_200_000, revision: 1,
                     expiresAt: now + 3_000_000, endedAt: nil, endedBy: nil,
                     rows: [row("i-gh", "GitHub", "ana-dev", "klav://Trabajo/Backend/GitHub", ["github.com"], [fill, code])],
                     requestDigest: "sample-t2"),
        ]
        agentList = [
            AgentItem(id: "ag3", name: "claude-code", note: "On ana’s MacBook, repo klav", status: "pending",
                      pairingWords: "anchor breeze copper dune echo falcon", createdAt: now - 30_000,
                      expiresAt: now + 570_000, projects: []),
            AgentItem(id: "ag1", name: "deploy-bot", note: nil, status: "active", pairingWords: "", createdAt: now - 86_400_000 * 40,
                      expiresAt: 0, projects: ["Trabajo/Infra"]),
            AgentItem(id: "ag2", name: "release-agent", note: nil, status: "active", pairingWords: "",
                      createdAt: now - 86_400_000 * 12, expiresAt: 0, projects: ["Trabajo/Backend", "Trabajo/Infra"]),
            AgentItem(id: "ag4", name: "old-scraper", note: nil, status: "revoked", pairingWords: "",
                      createdAt: now - 86_400_000 * 200, expiresAt: 0, projects: []),
            // A claude-code the person denied: the pending one's card says so
            // (ADR 0033 E2.2).
            AgentItem(id: "ag5", name: "claude-code", note: nil, status: "denied", pairingWords: "",
                      createdAt: now - 86_400_000 * 3, expiresAt: 0, projects: []),
        ]
        grants = Self.makeGrants(now: now)
        if keysLeft ?? defaults.bool(forKey: "KlavSampleKeysLeft") {
            self.keysLeft["ag4"] = Self.progress("ag4", name: "old-scraper",
                                                 projects: ["Trabajo/Web", "Trabajo/Backend", "Trabajo/Infra"], rotated: 1,
                                                 lastError: "rotating the key of Trabajo/Backend: the server did not answer")
        }
        // «Fix my reused passwords» running for 20 minutes (`-KlavSampleFix YES`).
        if defaults.bool(forKey: "KlavSampleFix"), let agent = agentList.first(where: { $0.id == "ag2" }) {
            let words = HealthWords.input(agent: agent.id, rows: [], unchecked: [], secs: 7200)
            taskList.append(fixTask(id: "t3", agent: agent, items: ["i-cf", "i-aws"], title: words.task ?? "",
                                    reason: words.reason ?? "", secs: 7200, startedAgo: 20 * 60_000))
        }
    }

    /// The sample account was made (`SampleAccounts`).
    func signedIn() { mutex.lock(); loggedIn = true; mutex.unlock() }

    private static var now: Int64 { Int64(Date().timeIntervalSince1970 * 1000) }

    /// What `klavd` says is left of a key change, as it counts it: the
    /// first `rotated` of `projects` changed, `skipped` out of reach.
    static func progress(_ id: String, name: String?, projects: [String], rotated: Int, running: Bool = false,
                         lastError: String? = nil, items: UInt32 = 0, narrowed: Bool = false,
                         skipped: [String] = [], logUnchecked: Bool = false,
                         withoutKeyChange: Bool = false) -> RevocationInfo {
        let toChange = max(projects.count - rotated - skipped.count, 0)
        return RevocationInfo(agentId: id, name: name, projects: UInt32(projects.count), rotated: UInt32(rotated),
                              regrants: 0, unknownProjects: false, narrowed: narrowed, items: items,
                              logUnchecked: logUnchecked, withoutKeyChange: withoutKeyChange,
                              skipped: UInt32(skipped.count), skippedProjects: skipped,
                              toChange: UInt32(toChange), needsWork: toChange > 0 || items > 0 || logUnchecked,
                              running: running, lastError: lastError,
                              pending: Array(projects.dropFirst(rotated).prefix(toChange)))
    }

    private func locked<T>(_ body: () throws -> T) throws -> T {
        mutex.lock()
        defer { mutex.unlock() }
        guard unlocked else { throw KlavError.Locked }
        return try body()
    }

    // MARK: klavd

    func status() -> DaemonInfo {
        mutex.lock()
        defer { mutex.unlock() }
        let seen = UInt64(Self.now - 120_000)
        return DaemonInfo(running: true, version: "0.9.0", pid: 4242, loggedIn: loggedIn,
                          email: loggedIn ? "ana@example.com" : nil,
                          unlocked: unlocked, unlockedWith: unlocked ? "touch_id" : nil, idleLockSecs: 900,
                          locksInSecs: unlocked ? 840 : nil, touchIdAvailable: touchID, touchIdEnrolled: touchID,
                          passwordRequired: nil, revision: 7, syncing: false,
                          browsers: [BrowserLink(browser: "Google Chrome", connected: true, atMs: seen)],
                          agentsPaused: pauses.filter { $0.untilMs.map { $0 > Self.now } ?? true },
                          accountDeletion: loggedIn ? deletion : nil, accountDeleted: loggedIn && deleted,
                          revocations: keysLeft.values.sorted { $0.agentId < $1.agentId }.map { left in
                              // Only counts, as klavd says them; locked, no
                              // names either.
                              var shown = left
                              shown.pending = []
                              shown.skippedProjects = []
                              if !unlocked { shown.name = nil; shown.lastError = nil; shown.running = false }
                              return shown
                          },
                          revocationsUnreadable: unlocked && recordUnreadable,
                          revocationsNewer: unlocked && recordUnreadable && recordNewer)
    }

    func unlock(password: String?) throws {
        Thread.sleep(forTimeInterval: 0.6)
        guard loggedIn else { throw KlavError.NotLoggedIn }
        if password == nil && !touchID { throw KlavError.BiometryUnavailable(message: "no Touch ID") }
        if let password, password != "sample" { throw KlavError.WrongCredentials }
        mutex.lock(); unlocked = true; mutex.unlock()
    }

    func lock() throws { mutex.lock(); unlocked = false; mutex.unlock() }
    func shutdown() throws {}

    // MARK: Deleting the account (ADR 0037)

    func deletionSupported() throws -> Bool { deletionSupport }

    /// Touch ID first (the sample's always answers), then the sample's
    /// password, `sample`.
    func requestAccountDeletion(password: String) throws -> AccountDeletionInfo {
        Thread.sleep(forTimeInterval: 0.6)
        guard deletionSupport else { throw KlavError.DeletionUnsupported(message: "this server cannot") }
        guard password == "sample" else { throw KlavError.WrongCredentials }
        mutex.lock()
        defer { mutex.unlock() }
        // The server's 409: asked already, here or on another device.
        if deletion != nil { throw KlavError.DeletionAlreadyScheduled(message: "already scheduled") }
        let now = Self.now
        let asked = AccountDeletionInfo(requestedAt: now, deleteAt: now + 7 * 86_400_000,
                                        deviceName: "MacBook de Ana", thisDevice: true, deleted: false)
        deletion = asked
        return asked
    }

    /// As klavd: Touch ID, or the sample's password where there is none.
    func cancelAccountDeletion() throws -> Bool {
        try cancelAccountDeletionWithPassword(password: nil)
    }

    func cancelAccountDeletionWithPassword(password: String?) throws -> Bool {
        // A locked klavd says so before it asks for anything.
        try locked {}
        try presence(true, password)
        return try locked {
            if deleted { throw KlavError.AccountDeleted(deleteAt: deletion?.deleteAt, message: "deleted") }
            defer { deletion = nil }
            return deletion != nil
        }
    }

    /// As `delete_copy_check`: locked, the outbox can't be listed.
    func deleteCopyCheck() throws -> SignOutCheck {
        mutex.lock()
        defer { mutex.unlock() }
        guard !unsent.isEmpty else {
            return SignOutCheck(unsentPasskeys: 0, unsentGenerated: 0, lockedWithQueue: false)
        }
        return unlocked
            ? SignOutCheck(unsentPasskeys: 0, unsentGenerated: UInt32(unsent.count), lockedWithQueue: false)
            : SignOutCheck(unsentPasskeys: 0, unsentGenerated: 0, lockedWithQueue: true)
    }

    /// «Delete this Mac’s copy»: signed out, as klavd after
    /// `delete_this_copy`. Refused while generated passwords wait, unless
    /// `discardUnsent` («Delete anyway»).
    func deleteThisCopy(discardUnsent: Bool) throws {
        mutex.lock()
        defer { mutex.unlock() }
        if !discardUnsent && !unsent.isEmpty {
            throw KlavError.Denied(message: "generated passwords never went up")
        }
        unsent = []
        loggedIn = false
        unlocked = false
        deletion = nil
        deleted = false
    }

    // MARK: Vault

    func sync() throws -> SyncInfo {
        SyncInfo(vaultsUpdated: 0, itemsReceived: 0, passkeysWaiting: 0, passkeyQueuesSetAside: 0, passkeyQueueSetAsideIds: [])
    }

    func vaults() throws -> [VaultInfo] {
        try locked {
            [VaultInfo(id: "v1", name: "Personal", items: UInt32(samples.filter { $0.info.vaultId == "v1" }.count)),
             VaultInfo(id: "v2", name: "Trabajo", items: UInt32(samples.filter { $0.info.vaultId == "v2" }.count))]
        }
    }

    func projects(vaultId: String?) throws -> [ProjectInfo] {
        try locked {
            [ProjectInfo(id: "p1", vaultId: "v1", vault: "Personal", name: "General"),
             ProjectInfo(id: "p2", vaultId: "v2", vault: "Trabajo", name: "Backend"),
             ProjectInfo(id: "p3", vaultId: "v2", vault: "Trabajo", name: "Infra")]
                .filter { vaultId == nil || $0.vaultId == vaultId }
        }
    }

    func items(query: ItemQuery) throws -> [ItemInfo] {
        try locked {
            samples.map(\.info).filter { info in
                (query.kind == nil || info.kind == query.kind)
                    && (query.vaultId == nil || info.vaultId == query.vaultId)
                    && (query.text.map { t in
                        info.title.localizedCaseInsensitiveContains(t)
                            || (info.username ?? "").localizedCaseInsensitiveContains(t)
                            || info.urls.contains { $0.localizedCaseInsensitiveContains(t) }
                    } ?? true)
            }
            .sorted { $0.title.localizedCaseInsensitiveCompare($1.title) == .orderedAscending }
        }
    }

    private func sample(_ id: String) throws -> Sample {
        guard let s = samples.first(where: { $0.info.id == id }) else { throw KlavError.NotFound(message: id) }
        return s
    }

    func item(id: String) throws -> ItemDetail {
        try locked {
            let s = try sample(id)
            return ItemDetail(info: s.info, fields: s.fields, hasNotes: s.notes != nil, hasTotp: s.totp, attachments: [])
        }
    }

    func fieldValue(id: String, field: String) throws -> String {
        try locked {
            let s = try sample(id)
            if let plain = s.fields.first(where: { $0.name == field })?.value { return plain }
            switch field {
            case "password": return "sample-\(s.info.title.lowercased().filter(\.isLetter))-Vx7q-29Lm"
            case "number": return "4111 1111 1111 1111"
            case "cvv": return "123"
            default: return "sample-secret-\(field)"
            }
        }
    }

    func notes(id: String) throws -> String? { try locked { try sample(id).notes } }

    func totp(id: String) throws -> TotpInfo {
        try locked {
            guard try sample(id).totp else { throw KlavError.NotFound(message: "no code") }
            let seconds = UInt64(Date().timeIntervalSince1970)
            let step = seconds / 30
            let code = String(format: "%06d", (step &* 7919 &+ UInt64(abs(id.hashValue % 1000))) % 1_000_000)
            return TotpInfo(code: code, remaining: 30 - seconds % 30, period: 30)
        }
    }

    /// As klav-client: a title the project already has is refused.
    func createItem(input: NewItemInput) throws -> ItemInfo {
        try locked {
            if deleted { throw KlavError.AccountDeleted(deleteAt: deletion?.deleteAt, message: "deleted") }
            let projects: [(id: String, vaultId: String, vault: String, name: String)] = [
                ("p1", "v1", "Personal", "General"), ("p2", "v2", "Trabajo", "Backend"), ("p3", "v2", "Trabajo", "Infra")]
            let project = projects.first { $0.id == input.projectId } ?? projects[0]
            let title = input.title.trimmingCharacters(in: .whitespaces)
            if titleTaken(title, in: project.id, items: samples.map(\.info)) {
                throw KlavError.Invalid(message: "klav://\(project.vault)/\(project.name)/\(title) already exists")
            }
            let id = "i-new-\(samples.count)"
            let user = input.fields.first { $0.name == "username" || $0.name == "cardholder" }?.value
            let info = ItemInfo(id: id, reference: "klav://\(project.vault)/\(project.name)/\(title)",
                                vaultId: project.vaultId, vault: project.vault, projectId: project.id,
                                project: project.name, kind: input.kind, title: title, username: user,
                                urls: input.urls, tags: [], version: 1, updatedAt: Self.now, trashed: false,
                                confirmedUrls: input.urls)
            let fields = input.fields.map { Self.field(for: $0) }
            samples.append(Sample(info: info, fields: fields, notes: input.notes,
                                  totp: input.fields.contains { $0.name == "totp" }))
            return info
        }
    }

    /// The person's edit: their version, so every site counts (ADR 0030 §7).
    func editItem(id: String, edit: ItemEdit) throws -> ItemInfo {
        try locked {
            if deleted { throw KlavError.AccountDeleted(deleteAt: deletion?.deleteAt, message: "deleted") }
            guard let index = samples.firstIndex(where: { $0.info.id == id }) else { throw KlavError.NotFound(message: id) }
            var s = samples[index]
            if let title = edit.title {
                let others = samples.filter { $0.info.id != id }.map(\.info)
                if titleTaken(title, in: s.info.projectId, items: others) {
                    throw KlavError.Invalid(message: "\(title) already exists")
                }
                s.info.title = title
            }
            for change in edit.set {
                if let at = s.fields.firstIndex(where: { $0.name == change.name }) {
                    if !s.fields[at].secret { s.fields[at].value = change.value }
                    s.fields[at].filled = true
                } else {
                    s.fields.append(Self.field(for: change))
                }
                if change.name == "username" { s.info.username = change.value }
                if change.name == "totp" { s.totp = true }
            }
            let urls = (s.info.urls + edit.addUrls).filter { !edit.removeUrls.contains($0) }
            s.info.urls = urls
            s.info.confirmedUrls = urls
            s.info.pendingUrls = []
            s.info.authorAgentId = nil
            if let notes = edit.notes { s.notes = notes.isEmpty ? nil : notes }
            s.info.version += 1
            s.info.updatedAt = Self.now
            samples[index] = s
            return s.info
        }
    }

    func trashItem(id: String) throws {
        try locked {
            if deleted { throw KlavError.AccountDeleted(deleteAt: deletion?.deleteAt, message: "deleted") }
            guard samples.contains(where: { $0.info.id == id }) else { throw KlavError.NotFound(message: id) }
            samples.removeAll { $0.info.id == id }
        }
    }

    /// A field the sample keeps: plain values as typed, secrets only as
    /// filled (revealing one gives a made-up value).
    private static func field(for edit: FieldEdit) -> FieldInfo {
        let secret = ["password", "totp", "api_key", "number", "cvv"].contains(edit.name)
        let kind: FieldType = switch edit.name {
        case "username": .username
        case "password": .password
        case "totp": .totp
        case "expiry": .monthYear
        default: secret ? .concealed : .text
        }
        return FieldInfo(name: edit.name, label: fieldName(name: edit.name, label: ""), kind: kind, secret: secret,
                         filled: true, value: secret ? nil : edit.value)
    }

    func passwordHistory(id: String) throws -> PasswordHistoryInfo {
        try locked {
            id == "i-gh"
                ? PasswordHistoryInfo(entries: [PreviousPasswordInfo(index: 0, field: "password", label: "Password",
                                                                     fromMs: Self.now - 86_400_000 * 400,
                                                                     toMs: Self.now - 86_400_000 * 30, unconfirmed: false)],
                                      pending: false, pendingSince: nil)
                : PasswordHistoryInfo(entries: [], pending: false, pendingSince: nil)
        }
    }

    func previousPassword(id: String, index: UInt32) throws -> String { try locked { "sample-old-Pq83-zz1" } }
    func resolvePending(id: String, accept: Bool) throws -> PasswordHistoryInfo { try passwordHistory(id: id) }
    func recordGenerated(value: String, host: String?) throws -> Int64 { Self.now }
    func generatorHistory() throws -> [GeneratedEntryInfo] { try locked { unsent } }
    func generatedValue(createdAt: Int64) throws -> String {
        try locked {
            guard unsent.contains(where: { $0.createdAt == createdAt }) else {
                throw KlavError.NotFound(message: "none")
            }
            return "sample-generated-Tq7v-82kd"
        }
    }
    func clearGeneratorHistory() throws -> UInt32 { 0 }

    // MARK: Agents

    func approvals() throws -> [ApprovalItem] { try locked { approvalList } }

    func decideApproval(id: String, approve: Bool, leaseMinutes: UInt32, requestDigest: String) throws {
        try decideApprovalWithPassword(id: id, approve: approve, leaseMinutes: leaseMinutes,
                                       requestDigest: requestDigest, password: nil)
    }

    func decideApprovalWithPassword(id: String, approve: Bool, leaseMinutes: UInt32, requestDigest: String,
                                    password: String?) throws {
        try presence(approve, password)
        try locked { approvalList.removeAll { $0.id == id } }
    }

    func tasks() throws -> [TaskItem] { try locked { taskList } }

    func decideTask(id: String, approve: Bool, choice: TaskChoiceInput?, requestDigest: String) throws -> TaskItem {
        try decideTaskWithPassword(id: id, approve: approve, choice: choice, requestDigest: requestDigest, password: nil)
    }

    func decideTaskWithPassword(id: String, approve: Bool, choice: TaskChoiceInput?, requestDigest: String,
                                password: String?) throws -> TaskItem {
        try presence(approve, password)
        return try locked {
            guard let index = taskList.firstIndex(where: { $0.id == id }) else { throw KlavError.NotFound(message: id) }
            var task = taskList.remove(at: index)
            if approve {
                task.status = "approved"
                task.expiresAt = Self.now + Int64(task.durationSecs) * 1000
                taskList.append(task)
            }
            return task
        }
    }

    func addToTask(approvalId: String, requestDigest: String) throws -> TaskItem {
        try addToTaskWithPassword(approvalId: approvalId, requestDigest: requestDigest, password: nil)
    }

    func addToTaskWithPassword(approvalId: String, requestDigest: String, password: String?) throws -> TaskItem {
        try presence(true, password)
        return try locked {
            approvalList.removeAll { $0.id == approvalId }
            guard let task = taskList.first(where: { $0.status == "approved" }) else { throw KlavError.NotFound(message: "task") }
            return task
        }
    }

    func endTask(id: String) throws -> TaskItem {
        try locked {
            guard let index = taskList.firstIndex(where: { $0.id == id }) else { throw KlavError.NotFound(message: id) }
            var task = taskList.remove(at: index)
            task.status = "ended"
            return task
        }
    }

    func secretRequests() throws -> [SecretRequestItem] { try locked { secretRequestList } }

    func fulfillSecretRequest(id: String, input: SecretRequestFulfillInput) throws -> SecretRequestFulfillOutput {
        try fulfillSecretRequestWithPassword(id: id, input: input, password: nil)
    }

    func fulfillSecretRequestWithPassword(id: String, input: SecretRequestFulfillInput,
                                          password: String?) throws -> SecretRequestFulfillOutput {
        try presence(input.grantProxy, password)
        return try locked {
            guard let index = secretRequestList.firstIndex(where: { $0.id == id }) else {
                throw KlavError.NotFound(message: id)
            }
            var card = secretRequestList.remove(at: index)
            card.status = "fulfilled"
            card.decidedAt = Self.now
            let title = input.title ?? card.title ?? card.targetTitle ?? "Secret"
            let item = ItemInfo(
                id: card.targetItemId ?? UUID().uuidString,
                vaultId: input.vault ?? card.vaultId ?? "v-personal",
                vault: "Personal",
                projectId: input.project ?? card.projectId ?? "p-general",
                project: "General",
                kind: card.kind ?? card.targetKind ?? "api_key",
                title: title,
                username: nil,
                urls: input.urls ?? [],
                pendingUrls: [],
                tags: [],
                version: 1,
                updatedAt: Self.now,
                trashed: false,
                reference: "klav://Personal/General/\(title)",
                hasPasskey: false,
                passkeyRpId: nil,
                passkeyUser: nil
            )
            return SecretRequestFulfillOutput(
                card: card,
                item: item,
                inGrant: true,
                proxyProfile: input.grantProxy ? card.proxyProposal?.profile : nil,
                proxyWarnings: []
            )
        }
    }

    func denySecretRequest(id: String, proposalDigest: String) throws -> SecretRequestItem {
        try locked {
            guard let index = secretRequestList.firstIndex(where: { $0.id == id }) else {
                throw KlavError.NotFound(message: id)
            }
            var card = secretRequestList.remove(at: index)
            card.status = "denied"
            card.decidedAt = Self.now
            return card
        }
    }

    // MARK: Fix my reused passwords (ADR 0022 §6)

    /// The logins of the health report's reused groups, checked against
    /// the agent's projects, as `klav-client` builds the card.
    func reusedOffer(agent: String?) throws -> ReusedOfferInfo {
        let groups = try vaultHealth().reused
        return try locked {
            let agents = agentList.filter { $0.status == "active" && !$0.projects.isEmpty }
            let chosen: AgentItem?
            if let agent {
                guard let found = agents.first(where: { $0.id == agent || $0.name == agent }) else {
                    throw KlavError.NotFound(message: agent)
                }
                chosen = found
            } else {
                chosen = agents.count == 1 ? agents.first : nil
            }
            var rows: [OfferRowInfo] = []
            for (index, group) in groups.enumerated() {
                for item in group.items where !rows.contains(where: { $0.itemId == item.id }) {
                    guard let sample = samples.first(where: { $0.info.id == item.id }) else { continue }
                    let info = sample.info
                    let granted = chosen.map { $0.projects.contains("\(info.vault)/\(info.project)") } ?? true
                    rows.append(OfferRowInfo(itemId: info.id, vaultId: info.vaultId, projectId: info.projectId,
                                             reference: info.reference, title: info.title, username: info.username,
                                             hosts: Self.hosts(info), changeUrl: Self.changePages[info.id],
                                             group: UInt32(index + 1),
                                             permissions: sample.totp ? ["rotate", "totp"] : ["rotate"],
                                             blocked: granted ? nil : "not_granted"))
                }
            }
            rows.sort { ($0.blocked != nil ? 1 : 0, $0.hosts.joined(), $0.title) < ($1.blocked != nil ? 1 : 0, $1.hosts.joined(), $1.title) }
            func offerAgent(_ a: AgentItem) -> OfferAgentInfo { OfferAgentInfo(id: a.id, name: a.name) }
            return ReusedOfferInfo(agents: agents.map(offerAgent), agent: chosen.map(offerAgent), rows: rows,
                                   task: "Change passwords",
                                   reason: "Give each of these sites a new password that Klav generates and keeps",
                                   durationSecs: 7200)
        }
    }

    func offerTaskWithPassword(offer: OfferInput, password: String?) throws -> TaskItem {
        guard !offer.items.isEmpty else { throw KlavError.Invalid(message: "no logins") }
        try presence(true, password)
        return try locked {
            guard let agent = agentList.first(where: { $0.status == "active" && ($0.id == offer.agent || $0.name == offer.agent) })
            else { throw KlavError.NotFound(message: offer.agent) }
            let task = fixTask(id: "t\(taskList.count + 10)", agent: agent, items: offer.items,
                               title: offer.task ?? "Change passwords",
                               reason: offer.reason ?? "Give each of these sites a new password that Klav generates and keeps",
                               secs: offer.durationSecs ?? 7200, startedAgo: 0)
            taskList.append(task)
            return task
        }
    }

    /// The first site changed, the second in progress, the rest pending.
    func taskProgress(taskId: String) throws -> TaskProgressInfo {
        try locked {
            guard let task = taskList.first(where: { $0.id == taskId }) else { throw KlavError.NotFound(message: taskId) }
            let sites = task.rows.enumerated().map { index, row in
                SiteProgressInfo(itemId: row.itemId, reference: row.reference, title: row.title, hosts: row.domains,
                                 state: index == 0 ? "changed" : "pending", started: index == 1,
                                 at: index == 0 ? Self.now - 4 * 60_000 : nil)
            }
            return TaskProgressInfo(taskId: task.id, card: task, sites: sites)
        }
    }

    /// An approved task the person offered, with `rotate` on each login.
    private func fixTask(id: String, agent: AgentItem, items: [String], title: String, reason: String, secs: UInt64,
                         startedAgo: Int64) -> TaskItem {
        let now = Self.now - startedAgo
        let rotate = TaskPermissionItem(permission: "rotate", checked: true, asked: true, addedByKlav: false,
                                        deniedByPolicy: false, noSite: false)
        let rows = items.compactMap { id in samples.first { $0.info.id == id }?.info }.map { info in
            TaskRowItem(vaultId: info.vaultId, projectId: info.projectId, itemId: info.id, reference: info.reference,
                        title: info.title, username: info.username, missing: false, askedDomain: Self.hosts(info).first,
                        domainMismatch: false, domains: Self.hosts(info), permissions: [rotate], noSite: false,
                        domainClaimed: false)
        }
        return TaskItem(id: id, status: "approved", agentId: agent.id, agent: agent.name, task: title, reason: reason,
                        offered: true, durationSecs: secs, createdAt: now, decideBy: now, decidedAt: now, revision: 1,
                        expiresAt: now + Int64(secs) * 1000, endedAt: nil, endedBy: nil, rows: rows,
                        requestDigest: "sample-\(id)")
    }

    private static func hosts(_ info: ItemInfo) -> [String] {
        info.confirmedUrls.compactMap { URL(string: $0)?.host }
    }

    private static let changePages = [
        "i-cf": "https://dash.cloudflare.com/profile/authentication",
        "i-aws": "https://console.aws.amazon.com/iam/home#/security_credentials",
        "i-cfe": "https://www.cfe.mx/mi-cuenta/contrasena",
    ]

    func agents() throws -> [AgentItem] { try locked { agentList } }

    func approveAgent(id: String, pairingWords: String, projectIds: [String], expiresInDays: UInt32?) throws -> AgentItem {
        try approveAgentWithPassword(id: id, pairingWords: pairingWords, projectIds: projectIds,
                                     expiresInDays: expiresInDays, password: nil)
    }

    func approveAgentWithPassword(id: String, pairingWords: String, projectIds: [String],
                                  expiresInDays: UInt32?, password: String?) throws -> AgentItem {
        try presence(true, password)
        return try locked {
            guard let index = agentList.firstIndex(where: { $0.id == id }) else { throw KlavError.NotFound(message: id) }
            agentList[index].status = "active"
            agentList[index].projects = projectIds.map { $0 == "p1" ? "Personal/General" : $0 == "p2" ? "Trabajo/Backend" : "Trabajo/Infra" }
            return agentList[index]
        }
    }

    func denyAgent(id: String) throws {
        try locked {
            if let index = agentList.firstIndex(where: { $0.id == id }) { agentList[index].status = "denied" }
        }
    }

    // MARK: Revoking and changing grants

    private static let places = ["p1": ("v1", "Personal", "General"), "p2": ("v2", "Trabajo", "Backend"),
                                 "p3": ("v2", "Trabajo", "Infra")]

    private static func place(_ id: String) -> GrantedProjectInfo {
        let (vault, vaultName, name) = places[id] ?? ("v?", "", "")
        return GrantedProjectInfo(vaultId: vault, vault: vaultName, projectId: id, project: name)
    }

    private static func editorPolicy(_ effects: [String: String], sites: [String] = [], hours: [TimeWindowInfo] = [],
                                     expires: UInt64? = nil) -> EditorPolicyInfo {
        let defaults = ["list": "allow", "fill": "allow", "inject": "allow", "totp": "ask", "reveal": "deny",
                        "create": "allow", "update": "ask", "delete": "deny"]
        return EditorPolicyInfo(
            permissions: GrantWords.permissions.map {
                PermissionSettingInfo(permission: $0, effect: effects[$0], defaultEffect: defaults[$0] ?? "deny")
            },
            fillSites: sites, hours: hours, expiresAtSecs: expires)
    }

    private static func makeGrants(now: Int64) -> [String: SampleGrant] {
        let offset = Int16(TimeZone.current.secondsFromGMT() / 60)
        let weekdays = TimeWindowInfo(days: ["mon", "tue", "wed", "thu", "fri"], startMinutes: 8 * 60, endMinutes: 20 * 60,
                                      utcOffsetMinutes: offset)
        let month = UInt64(now / 1000) + 30 * 86_400
        return [
            "ag1": SampleGrant(projects: [place("p3")],
                               editor: editorPolicy(["reveal": "ask", "delete": "deny"], sites: ["signin.aws.amazon.com"],
                                                    hours: [weekdays], expires: month),
                               version: 3),
            "ag2": SampleGrant(projects: [place("p2"), place("p3")], editor: nil, readOnly: .rules,
                               rules: [RuleInfo(permission: "reveal", effect: "ask", sites: [], tags: ["release"], places: 0,
                                                hours: [], expiresAtSecs: nil, more: false),
                                       RuleInfo(permission: "fill", effect: "allow", sites: [], tags: [], places: 1,
                                                hours: [], expiresAtSecs: nil, more: false)],
                               version: 5),
        ]
    }

    private func agentItem(_ id: String) throws -> AgentItem {
        guard let agent = agentList.first(where: { $0.id == id }) else { throw KlavError.NotFound(message: id) }
        return agent
    }

    func agentExposure(id: String) throws -> ExposureInfo {
        if exposureFails { throw KlavError.Network(message: "the server did not answer") }
        return try locked {
            let agent = try agentItem(id)
            let projects = grants[id]?.projects ?? []
            let ids = Set(projects.map(\.projectId))
            let seen: [SeenItemInfo] = id == "ag1"
                ? [SeenItemInfo(itemId: "i-aws", reference: "klav://Trabajo/Infra/AWS console", permissions: ["fill"],
                                secret: true, attachments: 0, uses: 14, firstMs: Self.now - 30 * 86_400_000,
                                lastMs: Self.now - 2 * 60_000, trashed: false, deleted: false),
                   SeenItemInfo(itemId: "i-cf", reference: "klav://Trabajo/Infra/Cloudflare", permissions: ["list"],
                                secret: false, attachments: 0, uses: 3, firstMs: Self.now - 9 * 86_400_000,
                                lastMs: Self.now - 86_400_000, trashed: false, deleted: false)]
                : []
            let others = agentList.filter { other in
                other.id != id && other.status == "active"
                    && (grants[other.id]?.projects ?? []).contains { ids.contains($0.projectId) }
            }.map(\.name)
            let items = samples.filter { ids.contains($0.info.projectId) }.count
            let unreadable = unreadableGrants.contains(id)
            return ExposureInfo(agent: agent, projects: unreadable ? [] : projects, items: seen,
                                denied: id == "ag1" ? 2 : 0, logWarning: nil,
                                cost: KeyChangeCostInfo(items: unreadable ? 0 : UInt32(items), otherAgents: unreadable ? [] : others,
                                                        itemsAtLeast: false, othersAtLeast: false),
                                projectsUnknown: unreadable)
        }
    }

    /// What a revocation reports it saw: `agent_exposure`, or, when that
    /// can't be read, the agent alone (revoking never waits on it).
    private func seenForRevoke(_ id: String) throws -> ExposureInfo {
        if let seen = try? agentExposure(id: id) { return seen }
        return try locked {
            ExposureInfo(agent: try agentItem(id), projects: grants[id]?.projects ?? [], items: [], denied: 0,
                         logWarning: "the server did not answer",
                         cost: KeyChangeCostInfo(items: 0, otherAgents: [], itemsAtLeast: true, othersAtLeast: true),
                         projectsUnknown: false)
        }
    }

    func revokeAgent(id: String, rotate: Bool) throws -> RevokeReportInfo {
        try locked { revokeCalls.append("\(id) \(rotate) false") }
        let exposure = try seenForRevoke(id)
        let projects = exposure.projects.map { "\($0.vault)/\($0.project)" }
        if !rotate {
            return try locked {
                guard let index = agentList.firstIndex(where: { $0.id == id }) else { throw KlavError.NotFound(message: id) }
                agentList[index].status = "revoked"
                let itemLeft = itemsPendingOnce.remove(id) != nil
                return RevokeReportInfo(agent: agentList[index], exposure: exposure, rotated: [], alreadyRotated: [],
                                        rekeyedItems: itemLeft ? 0 : 1, itemsPending: itemLeft ? 1 : 0, regranted: [],
                                        notRegranted: [], failed: itemLeft ? "changing the key of 1 item: the server did not answer" : nil,
                                        pending: [], warnings: [], logUnchecked: false, skipped: reportSkips, complete: !itemLeft)
            }
        }
        let name = exposure.agent.name
        try locked {
            keysLeft[id] = Self.progress(id, name: name, projects: projects, rotated: 0, running: true)
        }
        rotationGate?.wait()
        return try locked {
            let agent = try agentItem(id)
            if rotationFails, projects.count > 1 {
                let why = "rotating the key of \(projects[1]): the server did not answer"
                keysLeft[id] = Self.progress(id, name: name, projects: projects, rotated: 1, lastError: why)
                return RevokeReportInfo(agent: agent, exposure: exposure, rotated: [projects[0]], alreadyRotated: [],
                                        rekeyedItems: 0, itemsPending: 0, regranted: exposure.cost.otherAgents,
                                        notRegranted: [], failed: why, pending: Array(projects.dropFirst()), warnings: [],
                                        logUnchecked: false, skipped: reportSkips, complete: false)
            }
            keysLeft[id] = nil
            return RevokeReportInfo(agent: agent, exposure: exposure, rotated: projects, alreadyRotated: [],
                                    rekeyedItems: 0, itemsPending: 0, regranted: exposure.cost.otherAgents, notRegranted: [],
                                    failed: nil, pending: [], warnings: [], logUnchecked: false, skipped: reportSkips, complete: true)
        }
    }

    /// `klavd`'s background key change: revoked and written down at once,
    /// the keys change after (behind `rotationGate`), and `status` says how
    /// it goes. An item granted one by one whose key did not change
    /// (`itemsPendingOnce`) stays in the record, so `status` keeps listing
    /// it once the projects are done.
    func revokeAgentInBackground(id: String) throws -> RevokeReportInfo? {
        try locked { revokeCalls.append("\(id) true true") }
        if olderKlavd { return nil }
        let exposure = try seenForRevoke(id)
        let projects = exposure.projects.map { "\($0.vault)/\($0.project)" }
        let name = exposure.agent.name
        let (agent, itemLeft): (AgentItem, Bool) = try locked {
            guard let index = agentList.firstIndex(where: { $0.id == id }) else { throw KlavError.NotFound(message: id) }
            agentList[index].status = "revoked"
            let itemLeft = itemsPendingOnce.remove(id) != nil
            keysLeft[id] = Self.progress(id, name: name, projects: projects, rotated: 0, running: true,
                                         items: itemLeft ? 1 : 0)
            return (agentList[index], itemLeft)
        }
        let gate = rotationGate
        let fails = rotationFails
        DispatchQueue.global(qos: .utility).async { [self] in
            gate?.wait()
            mutex.lock()
            defer { mutex.unlock() }
            if fails, projects.count > 1 {
                keysLeft[id] = Self.progress(id, name: name, projects: projects, rotated: 1,
                                             lastError: "rotating the key of \(projects[1]): the server did not answer",
                                             items: itemLeft ? 1 : 0)
            } else if itemLeft {
                keysLeft[id] = Self.progress(id, name: name, projects: projects, rotated: projects.count,
                                             lastError: "changing the key of 1 item: the server did not answer", items: 1)
            } else {
                keysLeft[id] = nil
            }
        }
        return RevokeReportInfo(agent: agent, exposure: exposure, rotated: [], alreadyRotated: [], rekeyedItems: 0,
                                itemsPending: itemLeft ? 1 : 0, regranted: [], notRegranted: [],
                                failed: nil, pending: projects, warnings: [], logUnchecked: false, skipped: reportSkips,
                                complete: projects.isEmpty && !itemLeft)
    }

    func agentRevocations() throws -> [RevocationInfo] {
        if revocationsFail { throw KlavError.Network(message: "the server did not answer") }
        if recordUnreadable { throw KlavError.Invalid(message: "revocations.bin, which holds the key changes this device owes, cannot be read") }
        if olderKlavd { return [] }
        return try locked { keysLeft.values.sorted { $0.agentId < $1.agentId } }
    }

    func grantEditor(id: String) throws -> GrantEditorInfo {
        if olderKlavd {
            // What `klav-ffi` gives for a `klavd` without the editor: no name.
            return GrantEditorInfo(agentId: id, name: "", version: 0, projects: [], editable: false,
                                   readOnly: .olderKlavd, editor: nil, rules: [], expiresAtSecs: nil)
        }
        return try locked {
            if unreadableGrants.contains(id) {
                return GrantEditorInfo(agentId: id, name: try agentItem(id).name, version: 0, projects: [], editable: false,
                                       readOnly: .unreadable, editor: nil, rules: [], expiresAtSecs: nil)
            }
            let agent = try agentItem(id)
            guard agent.status == "active", let grant = grants[id] else {
                return GrantEditorInfo(agentId: id, name: agent.name, version: 0, projects: [], editable: false,
                                       readOnly: .notActive, editor: nil, rules: [], expiresAtSecs: nil)
            }
            return GrantEditorInfo(agentId: id, name: agent.name, version: grant.version, projects: grant.projects,
                                   editable: grant.editor != nil, readOnly: grant.readOnly, editor: grant.editor,
                                   rules: grant.rules, expiresAtSecs: grant.editor?.expiresAtSecs)
        }
    }

    private static func strictness(_ effect: String) -> Int { ["allow": 0, "ask": 1, "deny": 2][effect] ?? 2 }

    /// The sheet `klavd` would give, worked out here only for the sample.
    private func sheet(_ id: String, _ change: GrantChangeInput) throws -> GrantChangePreviewInfo {
        let agent = try agentItem(id)
        guard let grant = grants[id], let old = grant.editor else {
            throw KlavError.Invalid(message: "this grant can't be changed from the app")
        }
        var lines: [ChangeLineInfo] = []
        let before = grant.projects.map(\.projectId), after = change.projectIds
        for p in after where !before.contains(p) {
            let place = Self.place(p)
            lines.append(ChangeLineInfo(kind: .projectAdded(project: "\(place.vault)/\(place.project)"), widens: true))
        }
        let removed = before.filter { !after.contains($0) }.map { Self.place($0) }.map { "\($0.vault)/\($0.project)" }
        for place in removed { lines.append(ChangeLineInfo(kind: .projectRemoved(project: place), widens: false)) }
        for setting in old.permissions {
            let next = change.permissions.first { $0.permission == setting.permission }?.effect
            let was = setting.effect ?? setting.defaultEffect, now = next ?? setting.defaultEffect
            guard was != now || (setting.effect == nil) != (next == nil) else { continue }
            lines.append(ChangeLineInfo(kind: .permission(permission: setting.permission, before: was,
                                                          beforeDefault: setting.effect == nil, after: now,
                                                          afterDefault: next == nil),
                                        widens: Self.strictness(now) < Self.strictness(was)))
        }
        func wider<T: Equatable>(_ old: [T], _ new: [T]) -> Bool {
            (!old.isEmpty && new.isEmpty) || new.contains { !old.contains($0) }
        }
        if old.fillSites != change.fillSites {
            lines.append(ChangeLineInfo(kind: .fillSites(before: old.fillSites, after: change.fillSites),
                                        widens: wider(old.fillSites, change.fillSites)))
        }
        if old.hours != change.hours {
            lines.append(ChangeLineInfo(kind: .hours(before: old.hours, after: change.hours), widens: wider(old.hours, change.hours)))
        }
        if old.expiresAtSecs != change.expiresAtSecs {
            let later = change.expiresAtSecs.map { end in old.expiresAtSecs.map { end > $0 } ?? false } ?? true
            lines.append(ChangeLineInfo(kind: .expires(beforeSecs: old.expiresAtSecs, afterSecs: change.expiresAtSecs),
                                        widens: later))
        }
        guard !lines.isEmpty else { throw KlavError.Invalid(message: "nothing changes") }
        return GrantChangePreviewInfo(agentId: id, name: agent.name, version: grant.version + 1, lines: lines,
                                      widens: lines.contains { $0.widens }, digest: "sample-\(grant.version)-\(change)",
                                      removedProjects: removed, rotateRemoved: change.rotateRemoved,
                                      warnings: [])
    }

    func grantChangePrepare(id: String, change: GrantChangeInput) throws -> GrantChangePreviewInfo {
        try locked { try sheet(id, change) }
    }

    func grantChangeApplyWithPassword(id: String, change: GrantChangeInput, digest: String,
                                      password: String?) throws -> GrantChangeReportInfo {
        let preview = try locked { try sheet(id, change) }
        guard preview.digest == digest else {
            throw KlavError.Security(message: "the grant changed while you were looking at it: nothing was signed; open it again")
        }
        try presence(preview.widens, password)
        return try locked {
            guard var grant = grants[id] else { throw KlavError.NotFound(message: id) }
            grant.projects = change.projectIds.map { Self.place($0) }
            grant.editor = Self.editorPolicy(
                Dictionary(change.permissions.compactMap { p in p.effect.map { (p.permission, $0) } },
                           uniquingKeysWith: { _, last in last }),
                sites: change.fillSites, hours: change.hours, expires: change.expiresAtSecs)
            grant.version += 1
            grants[id] = grant
            guard let index = agentList.firstIndex(where: { $0.id == id }) else { throw KlavError.NotFound(message: id) }
            agentList[index].projects = grant.projects.map { "\($0.vault)/\($0.project)" }
            return GrantChangeReportInfo(agent: agentList[index], rotated: change.rotateRemoved ? preview.removedProjects : [],
                                         regranted: [], notRegranted: [], failed: nil, pending: [], skipped: [], complete: true)
        }
    }

    // MARK: Development

    func devAgents() throws -> [DevAgentInfo] {
        try locked {
            let everyone = pauses.first { $0.agentId == nil }
            return agentList.map { agent in
                let own = pauses.first { $0.agentId == agent.id }
                let pause = (own ?? everyone).map {
                    AgentPauseInfo(everyone: $0.agentId == nil, sinceMs: $0.sinceMs, untilMs: $0.untilMs)
                }
                let seen: Int64? = switch agent.id {
                case "ag1": Self.now - 2 * 60_000
                case "ag2": Self.now - 47 * 60_000
                default: nil
                }
                return DevAgentInfo(agent: agent, lastSeenMs: seen,
                                    approvedMs: agent.status == "active" ? agent.createdAt + 60_000 : nil,
                                    paused: agent.status == "active" ? pause : nil)
            }
        }
    }

    func pauseAgents(agentId: String?, untilMs: Int64?) throws -> [PauseInfo] {
        if pauseFails { throw KlavError.DaemonUnavailable(message: "klavd is not running") }
        mutex.lock()
        defer { mutex.unlock() }
        pauses.removeAll { $0.agentId == agentId }
        pauses.append(PauseInfo(agentId: agentId, sinceMs: Self.now, untilMs: untilMs, local: !unlocked,
                                serverUnsupported: false))
        return pauses
    }

    func resumeAgentsWithPassword(agentId: String?, password: String?) throws -> [PauseInfo] {
        try presence(true, password)
        return try locked {
            pauses.removeAll { $0.agentId == agentId }
            return pauses
        }
    }

    func auditLog(filter: LogFilterInput) throws -> [LogEntryInfo] {
        try locked {
            let text = filter.text?.trimmingCharacters(in: .whitespaces).lowercased() ?? ""
            let kept = sampleLog().filter { e in
                (filter.agent.map { a in e.actor == a || e.agentId == a } ?? true)
                    && (filter.item.map { i in e.itemId == i || (e.item ?? "").contains(i) } ?? true)
                    && (filter.permissions.isEmpty || filter.permissions.contains(e.permission ?? ""))
                    && (filter.outcomes.isEmpty || filter.outcomes.contains(e.outcome ?? ""))
                    && (!filter.alerts || !e.alerts.isEmpty)
                    && (filter.sinceMs.map { e.atMs >= $0 } ?? true)
                    && (text.isEmpty || [e.actor, e.item ?? "", e.reason ?? "", e.domain ?? ""]
                        .contains { $0.lowercased().contains(text) })
            }
            return filter.limit.map { Array(kept.prefix(Int($0))) } ?? kept
        }
    }

    func itemActivity(item: String) throws -> ItemActivityInfo {
        try locked {
            let info = try sample(item).info
            let uses = sampleLog().filter { $0.itemId == item && $0.agentId != nil && $0.action.hasPrefix("agent.") }
                .map { e -> ItemUseInfo in
                    let how: UseHow = e.outcome == "deny" ? .denied : e.outcome == "ask" ? .asked
                        : e.taskId != nil ? .task : e.approvalId == "ap-15" ? .approvedFor
                        : e.approvalId != nil ? .approvedOnce : .policy
                    return ItemUseInfo(entry: e, how: how,
                                       leaseUntilMs: how == .approvedFor ? e.atMs + 15 * 60_000 - 30_000 : nil,
                                       approvedAtMs: e.approvalId != nil ? e.atMs - 30_000 : nil,
                                       task: e.taskId != nil ? "Ship version 0.9" : nil)
                }
            return ItemActivityInfo(itemId: item, reference: info.reference, trashed: false, deleted: false, uses: uses)
        }
    }

    func auditStatus() throws -> AuditStatusInfo {
        try locked {
            let events = UInt64(sampleLog().first?.seq ?? 0)
            return AuditStatusInfo(events: events, verified: verifiedSeq,
                                   unverified: events > verifiedSeq ? events - verifiedSeq : 0)
        }
    }

    func verifyAudit() throws -> VerifyInfo {
        Thread.sleep(forTimeInterval: 0.7)
        return try locked {
            let events = UInt64(sampleLog().first?.seq ?? 0)
            verifiedSeq = events
            return VerifyInfo(events: events, agentSignatures: 141, accountSignatures: 38, heads: 3,
                              signedHead: events, warnings: [], unpinned: nil)
        }
    }

    /// The sample log, newest first: what the agents of the sample did
    /// with its items, and the person's decisions.
    private func sampleLog() -> [LogEntryInfo] {
        let now = Self.now, minute: Int64 = 60_000
        var seq: UInt64 = 214
        var out: [LogEntryInfo] = []
        func add(_ ago: Int64, _ actor: String, _ agentId: String?, _ action: String, _ permission: String? = nil,
                 _ outcome: String? = nil, item: String? = nil, reason: String? = nil, domain: String? = nil,
                 task: String? = nil, approval: String? = nil, alerts: [String] = []) {
            let info = item.flatMap { id in samples.first { $0.info.id == id }?.info }
            out.append(LogEntryInfo(seq: seq, atMs: now - ago * minute, actor: actor, byAgent: actor != "you",
                                    agentId: agentId,
                                    action: action, permission: permission, outcome: outcome,
                                    item: info?.reference, itemId: item, vault: info?.vault, reason: reason,
                                    domain: domain, taskId: task, approvalId: approval, untilMs: nil,
                                    attachments: 0, alerts: alerts, verified: seq <= verifiedSeq))
            seq -= 1
        }
        add(2, "deploy-bot", "ag1", "agent.access", "fill", "allow", item: "i-aws",
            reason: "Deploy the staging stack", domain: "signin.aws.amazon.com")
        add(3, "deploy-bot", "ag1", "agent.access", "totp", "allow", item: "i-aws",
            reason: "Deploy the staging stack", domain: "signin.aws.amazon.com")
        add(9, "release-agent", "ag2", "agent.access", "inject", "allow", item: "i-stripe",
            reason: "Run the payment integration tests", task: "t2")
        add(14, "release-agent", "ag2", "agent.access", "fill", "allow", item: "i-gh",
            reason: "Open the release pull request", domain: "github.com", task: "t2")
        add(31, "release-agent", "ag2", "agent.access", "reveal", "deny", item: "i-cf",
            reason: "Read the API token", alerts: ["denied"])
        add(40, "release-agent", "ag2", "agent.access", "totp", "allow", item: "i-gh",
            reason: "Sign in to push the tag", domain: "github.com", approval: "ap-15")
        add(41, "you", nil, "approval.decided", "totp", "approve", item: "i-gh",
            reason: "Sign in to push the tag", domain: "github.com", approval: "ap-15")
        add(42, "release-agent", "ag2", "agent.access", "totp", "ask", item: "i-gh",
            reason: "Sign in to push the tag", domain: "github.com", approval: "ap-15")
        add(70, "you", nil, "task.decided", nil, "approve", task: "t2")
        add(118, "you", nil, "item.updated", item: "i-gh")
        add(180, "deploy-bot", "ag1", "agent.access", "fill", "allow", item: "i-cf",
            reason: "Purge the CDN cache", domain: "dash.cloudflare.com", approval: "ap-1",
            alerts: ["first_use"])
        add(182, "you", nil, "approval.decided", "fill", "approve", item: "i-cf",
            reason: "Purge the CDN cache", domain: "dash.cloudflare.com", approval: "ap-1")
        add(60 * 26, "you", nil, "agents.resumed")
        add(60 * 27, "you", nil, "agents.paused")
        add(60 * 30, "you", nil, "agent.granted")
        return out
    }

    /// Touch ID takes a moment; without it, the master password ("sample").
    private func presence(_ needed: Bool, _ password: String?) throws {
        guard needed else { return }
        if let password {
            if password != "sample" { throw KlavError.WrongCredentials }
        } else if touchID {
            Thread.sleep(forTimeInterval: 0.8)
        } else {
            throw KlavError.BiometryUnavailable(message: "no Touch ID")
        }
    }

    // MARK: Health

    func vaultHealth() throws -> VaultHealthInfo {
        try locked {
            func h(_ id: String) -> HealthItemInfo {
                let s = samples.first { $0.info.id == id }!.info
                return HealthItemInfo(id: s.id, vaultId: s.vaultId, projectId: s.projectId, reference: s.reference,
                                      kind: s.kind, title: s.title, username: s.username,
                                      hosts: Self.hosts(s), field: "password",
                                      fieldLabel: "Password")
            }
            let breaches = breachCheck
                ? BreachInfo(status: "checked", found: [BreachedPasswordInfo(item: h("i-forum"), count: 3_861)],
                             queries: 9, message: nil)
                : BreachInfo(status: "off", found: [], queries: 0, message: nil)
            return VaultHealthInfo(checkedAt: Self.now, items: UInt32(samples.count), passwords: 9, skipped: 0,
                                   reused: [ReusedGroupInfo(items: [h("i-aws"), h("i-cf")]),
                                            ReusedGroupInfo(items: [h("i-cfe"), h("i-forum")])],
                                   weak: [WeakPasswordInfo(item: h("i-forum"), score: 1, generatedBits: nil)],
                                   old: [OldPasswordInfo(item: h("i-aws"), sinceMs: Self.now - 86_400_000 * 540,
                                                         days: 540, source: "record")],
                                   breaches: breaches)
        }
    }

    func healthSettings() throws -> HealthSettingsInfo { try locked { HealthSettingsInfo(breachCheck: breachCheck) } }

    func setBreachCheck(on: Bool) throws -> HealthSettingsInfo {
        try locked {
            breachCheck = on
            return HealthSettingsInfo(breachCheck: on)
        }
    }

    // MARK: Data

    private static func makeSamples(now: Int64) -> [Sample] {
        let day: Int64 = 86_400_000
        func info(_ id: String, _ vault: (String, String), _ project: (String, String), _ kind: Kind, _ title: String,
                  _ user: String?, _ urls: [String], _ age: Int64) -> ItemInfo {
            ItemInfo(id: id, reference: "klav://\(vault.1)/\(project.1)/\(title)", vaultId: vault.0, vault: vault.1,
                     projectId: project.0, project: project.1, kind: kind, title: title, username: user, urls: urls,
                     tags: [], version: 3, updatedAt: now - age * day, trashed: false, confirmedUrls: urls)
        }
        func field(_ name: String, _ label: String, _ kind: FieldType, secret: Bool = false, _ value: String? = nil) -> FieldInfo {
            FieldInfo(name: name, label: label, kind: kind, secret: secret, filled: true, value: secret ? nil : value)
        }
        let personal = ("v1", "Personal"), work = ("v2", "Trabajo")
        let general = ("p1", "General"), backend = ("p2", "Backend"), infra = ("p3", "Infra")
        func login(_ id: String, _ v: (String, String), _ p: (String, String), _ title: String, _ user: String,
                   _ url: String, age: Int64, totp: Bool = false, notes: String? = nil) -> Sample {
            var fields = [field("username", "Username", .username, user), field("password", "Password", .password, secret: true)]
            if totp { fields.append(field("totp", "One-time password", .totp, secret: true)) }
            return Sample(info: info(id, v, p, .login, title, user, [url], age), fields: fields, notes: notes, totp: totp)
        }
        return [
            login("i-gh", work, backend, "GitHub", "ana-dev", "https://github.com", age: 30, totp: true,
                  notes: "Recovery codes are in the safe."),
            login("i-aws", work, infra, "AWS console", "ana@example.com", "https://signin.aws.amazon.com", age: 540, totp: true),
            {
                // deploy-bot added a site nobody confirmed yet (ADR 0030 §7).
                var cf = login("i-cf", work, infra, "Cloudflare", "ana@example.com", "https://dash.cloudflare.com",
                               age: 90, totp: true)
                cf.info.urls.append("https://cloudflare-access.example.net/login")
                cf.info.pendingUrls = ["https://cloudflare-access.example.net/login"]
                cf.info.authorAgentId = "ag1"
                return cf
            }(),
            login("i-cfe", personal, general, "CFE", "ana.lopez", "https://www.cfe.mx", age: 200),
            login("i-forum", personal, general, "Photography forum", "analopez", "https://forum.example.org", age: 700),
            login("i-mail", personal, general, "Fastmail", "ana@example.com", "https://app.fastmail.com", age: 12, totp: true),
            Sample(info: info("i-stripe", work, backend, .apiKey, "Stripe", nil, ["https://dashboard.stripe.com"], 4),
                   fields: [field("secret", "Secret key", .concealed, secret: true)],
                   notes: nil, totp: false),
            Sample(info: info("i-visa", personal, general, .card, "Visa", "Ana López", [], 60),
                   fields: [field("cardholder", "Cardholder name", .text, "Ana López"),
                            field("number", "Number", .concealed, secret: true),
                            field("expiry", "Expiry date", .monthYear, "2029-08"),
                            field("cvv", "Verification code", .concealed, secret: true)],
                   notes: nil, totp: false),
            Sample(info: info("i-ssh", work, infra, .sshKey, "deploy@staging", nil, [], 33),
                   fields: [field("public_key", "Public key", .text, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKs…q8 deploy"),
                            field("private_key", "Private key", .concealed, secret: true)],
                   notes: nil, totp: false),
            Sample(info: info("i-note", personal, general, .note, "Router", nil, [], 300),
                   fields: [], notes: "Admin page at 192.168.1.1. Guest network: Casa-Invitados.", totp: false),
            Sample(info: info("i-home", personal, general, .identity, "Casa", nil, [], 400),
                   fields: [field("first_name", "First name", .text, "Ana"),
                            field("last_name", "Last name", .text, "López"),
                            field("address", "Address", .text, "Av. Reforma 1"),
                            field("city", "City", .text, "Ciudad de México")],
                   notes: nil, totp: false),
            Sample(info: info("i-discord", personal, general, .totp, "Discord", "analopez", [], 150),
                   fields: [field("totp", "One-time password", .totp, secret: true)],
                   notes: nil, totp: true),
        ]
    }

    // MARK: Sandboxes (ADR 0036 E2)

    /// The list `sandbox_list_checked` gives; nil builds `sandboxScenario`.
    private var sandboxState: SandboxListInfo?
    /// `-KlavSampleSandboxes none|empty|quiet|rollback|flagged|paused`;
    /// without it, a proxy with a sandbox in each state and a theft signal.
    /// `integrity`: every read fails its security checks. `unregistered`:
    /// every state, and a revocation the log didn't show (`Snapshot`).
    var sandboxScenario = UserDefaults.standard.string(forKey: "KlavSampleSandboxes") ?? "all"
    /// Tests: reading the list fails with this.
    var sandboxListFails: KlavError?
    /// Tests: the next reads fail this check (`sandbox_list_checked`).
    var sandboxListRefused: SandboxCheckInfo?
    /// Tests: the server answers that a later revocation exists.
    var revokeNotApplied = false
    /// Tests: every revocation asked, as `proxy scope`.
    private(set) var sandboxRevokeCalls: [String] = []
    /// Tests: the server answers «revoked» but doesn't log it, so the next
    /// lists don't show it (ADR 0036 E3.3).
    var revokeUnlogged = false
    /// Tests: the account's deletion runs out now (ADR 0037).
    func finishDeletion() {
        mutex.lock(); deleted = true; mutex.unlock()
    }

    /// Tests: lists read so far.
    private(set) var sandboxListCalls = 0

    /// Tests: the next lists are this one.
    func setSandboxes(_ list: SandboxListInfo) {
        mutex.lock(); sandboxState = list; mutex.unlock()
    }

    func sandboxListChecked(allProxies: Bool) throws -> SandboxListCheckedInfo {
        try locked {
            if let error = sandboxListFails { throw error }
            if let check = sandboxListRefused { return .refused(check: check, message: "the check's words") }
            if sandboxScenario == "integrity" { return SandboxSamples.integrityRefusal }
            sandboxListCalls += 1
            return .listed(list: currentSandboxes())
        }
    }

    func revokeSandbox(proxyId: String, sandboxId: String) throws -> SandboxRevokeInfo {
        try locked {
            sandboxRevokeCalls.append("\(proxyId) \(sandboxId)")
            let at = Self.now
            if revokeNotApplied { return .notApplied(scope: sandboxId, laterMs: at + 4 * 60_000) }
            let ids = markRevoking(at: at) { $0.proxyId == proxyId && $0.sandboxId == sandboxId }
            guard !ids.isEmpty else { throw KlavError.NotFound(message: "sandbox") }
            return .revoked(scope: sandboxId, atMs: at, sandboxIds: ids)
        }
    }

    func revokeAllSandboxes(proxyId: String) throws -> SandboxRevokeInfo {
        try locked {
            sandboxRevokeCalls.append("\(proxyId) all")
            let at = Self.now
            if revokeNotApplied { return .notApplied(scope: "all", laterMs: at + 4 * 60_000) }
            let ids = markRevoking(at: at) { $0.proxyId == proxyId && SandboxBoard.revocable($0) }
            return .revoked(scope: "all", atMs: at, sandboxIds: ids)
        }
    }

    /// Under the mutex.
    private func currentSandboxes() -> SandboxListInfo {
        if let sandboxState { return sandboxState }
        let list = SandboxSamples.list(sandboxScenario, now: Self.now)
        sandboxState = list
        return list
    }

    /// Under the mutex: the server took the revocation, so the rows say
    /// «Revoking…» until the proxy logs their end, with its signed time.
    /// With `revokeUnlogged` the log doesn't get it: the rows don't change.
    private func markRevoking(at: Int64, _ covers: (SandboxInfo) -> Bool) -> [String] {
        var list = currentSandboxes()
        var ids: [String] = []
        for i in list.sandboxes.indices where covers(list.sandboxes[i]) && SandboxBoard.revocable(list.sandboxes[i]) {
            if !revokeUnlogged {
                list.sandboxes[i].status = .revoking
                list.sandboxes[i].revokedByPersonMs = at
            }
            ids.append(list.sandboxes[i].sandboxId)
        }
        sandboxState = list
        return ids
    }
}

/// The sample's sandboxes, also the tests' fixtures: made-up IDs, labels
/// and issuers, no proxy anywhere.
enum SandboxSamples {
    /// What `klav-client` says when the proxy setting names an agent the
    /// server doesn't list: how a `klavd` older than `sandbox_list_checked`
    /// reports it.
    static let integrityFailure = KlavError.Security(message: integrityMessage)
    static let integrityMessage = "the account's proxy setting names agent \(proxy), which the server does not list among the account's agents, so its sandboxes cannot be shown: the server may be hiding it, or a device of the account named an agent the server does not have. Check `klav proxy status`, or set the proxy again with `klav proxy use`"

    /// The same check, named (`-KlavSampleSandboxes integrity`).
    static let integrityRefusal = SandboxListCheckedInfo.refused(check: .unlistedProxy(agentId: proxy), message: integrityMessage)

    /// `-KlavSampleSandboxes unregistered`: «Revoke» on chat-123 three
    /// minutes ago, which the log still doesn't show.
    static func unregistered(now: Int64) -> RevocationCheck {
        var check = RevocationCheck(proxyId: proxy, scope: "ad1e2f3a-4b5c-4d6e-7f8a-9b0c1d2e3f4a", label: "chat-123",
                                    atMs: now - 3 * 60_000, sandboxIds: ["ad1e2f3a-4b5c-4d6e-7f8a-9b0c1d2e3f4a"],
                                    afterRead: 0)
        check.missed = true
        return check
    }

    static let proxy = "7c1e2f90-4b3d-4a8e-9f21-3d5e6a7b8c9d"
    static let oldProxy = "2d9b6c14-0e5f-4c7a-8b31-6f4e2a1d9c07"
    static let t3code = "a41c9e07-58b2-4d36-9e1f-0c7b3a5d2e84"
    static let runner = "5be2d1f4-9a07-4c8e-b3d6-1e2f4a6c8b90"
    static let writer = "e0f3a2b1-7c64-4d59-a8e2-9b1c3d5f7a06"

    static func row(_ id: String, _ label: String, proxy: String = proxy, issuer: String = t3code,
                    issuerName: String? = "t3code", profiles: [String] = ["northflank"],
                    issued: Int64, expires: Int64, claimed: Int64? = nil,
                    status: SandboxStatusInfo, end: SandboxEndInfo? = nil, ended: Int64? = nil,
                    revoked: Int64? = nil, connected: Bool? = nil, seen: Int64? = nil) -> SandboxInfo {
        SandboxInfo(sandboxId: id, proxyId: proxy, issuerId: issuer, issuerName: issuerName, label: label,
                    profiles: profiles, issuedMs: issued, expiresMs: expires, claimedMs: claimed, status: status,
                    endReason: end, endedMs: ended, revokedByPersonMs: revoked, connected: connected,
                    lastSeenMs: seen)
    }

    static func proxyInfo(now: Int64, paused: Bool = false, sentAgo: Int64? = 2 * 60_000, quiet: Bool = false,
                          noSigns: ProxyNoSigns? = nil) -> SandboxProxyInfo {
        SandboxProxyInfo(agentId: proxy, name: "proxy-fly", paused: paused,
                         heartbeatSentMs: sentAgo.map { now - $0 }, heartbeatAgeMs: sentAgo,
                         quiet: quiet, noSigns: noSigns)
    }

    /// One sandbox in each state, a theft signal and those that ended,
    /// oldest first, as the log has them.
    static func rows(now: Int64) -> [SandboxInfo] {
        let m: Int64 = 60_000, h: Int64 = 3_600_000
        let runner = (issuer: Self.runner, name: "boat-runner")
        return [
            row("0f4b5c6d-7e8f-4a1b-9c2d-3e4f5a6b7c8d", "chat-101", issued: now - 36 * h, expires: now - 30 * h,
                claimed: now - 36 * h + m, status: .ended, end: .ttl, ended: now - 30 * h),
            row("1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d", "old-runner", issuer: runner.issuer, issuerName: runner.name,
                profiles: ["railway"], issued: now - 23 * h, expires: now - 17 * h, claimed: now - 23 * h + m,
                status: .ended, end: .issuerRemoved, ended: now - 20 * h),
            row("2b3c4d5e-6f7a-4b8c-9d0e-1f2a3b4c5d6e", "chat-110", issued: now - 13 * h, expires: now - 7 * h,
                claimed: now - 13 * h + m, status: .ended, end: .released, ended: now - 11 * h),
            row("3c4d5e6f-7a8b-4c9d-0e1f-2a3b4c5d6e7f", "lint-bot", issuer: runner.issuer, issuerName: runner.name,
                profiles: ["railway"], issued: now - 12 * h, expires: now - 6 * h, claimed: now - 12 * h + m,
                status: .ended, end: .inactivity, ended: now - 9 * h),
            row("4d5e6f7a-8b9c-4d0e-1f2a-3b4c5d6e7f8a", "chat-105", profiles: ["maple"], issued: now - 6 * h - 30 * m,
                expires: now - 30 * m, claimed: now - 6 * h, status: .expired),
            row("5e6f7a8b-9c0d-4e1f-2a3b-4c5d6e7f8a9b", "chat-109", profiles: ["northflank", "maple"],
                issued: now - 6 * h, expires: now, claimed: now - 6 * h + m, status: .ended, end: .person,
                ended: now - 5 * h),
            row("6f7a8b9c-0d1e-4f2a-3b4c-5d6e7f8a9b0c", "chat-118", issued: now - 3 * h, expires: now + 3 * h,
                claimed: now - 3 * h + m, status: .ended, end: .theft, ended: now - 22 * m),
            row("7a8b9c0d-1e2f-4a3b-4c5d-6e7f8a9b0c1d", "chat-112", issued: now - 2 * h - 30 * m, expires: now + 3 * h,
                claimed: now - 2 * h - 29 * m, status: .ended, end: .stop, ended: now - 2 * h),
            row("8b9c0d1e-2f3a-4b4c-5d6e-7f8a9b0c1d2e", "fix-flaky-tests", issuer: runner.issuer,
                issuerName: runner.name, profiles: ["railway"], issued: now - 2 * h, expires: now + 4 * h,
                claimed: now - 2 * h + m, status: .active, connected: false, seen: now - 20 * m),
            row("9c0d1e2f-3a4b-4c5d-6e7f-8a9b0c1d2e3f", "chat-117", profiles: ["maple"], issued: now - 90 * m,
                expires: now + 4 * h, claimed: now - 89 * m, status: .revoking, revoked: now - 4 * m),
            row("ad1e2f3a-4b5c-4d6e-7f8a-9b0c1d2e3f4a", "chat-123", profiles: ["northflank", "maple"],
                issued: now - 48 * m, expires: now + 5 * h + 12 * m, claimed: now - 47 * m, status: .active,
                connected: true, seen: now - m),
            row("be2f3a4b-5c6d-4e7f-8a9b-0c1d2e3f4a5b", "nightly-deps", issuer: runner.issuer,
                issuerName: runner.name, profiles: ["railway"], issued: now - 40 * m, expires: now + 2 * h,
                status: .waiting),
            row("cf3a4b5c-6d7e-4f8a-9b0c-1d2e3f4a5b6c", "chat-125", issued: now - 6 * m, expires: now + 6 * h,
                claimed: now - 5 * m, status: .unknown),
            row("d04b5c6d-7e8f-4a9b-0c1d-2e3f4a5b6c7d", "chat-124", issued: now - 3 * m, expires: now + 6 * h,
                status: .waiting),
        ]
    }

    static func list(_ scenario: String, now: Int64) -> SandboxListInfo {
        let all = rows(now: now)
        let live = all.filter(SandboxBoard.isLive)
        func make(_ proxy: SandboxProxyInfo?, _ rows: [SandboxInfo], warnings: [String] = [],
                  security: SandboxSecurityInfo? = nil) -> SandboxListInfo {
            SandboxListInfo(proxy: proxy, sandboxes: rows, verifiedEvents: 412, warnings: warnings,
                            marksUnreadable: false, security: security)
        }
        switch scenario {
        case "none":
            return make(nil, [])
        case "empty":
            return make(proxyInfo(now: now, sentAgo: 12 * 60_000), [])
        case "quiet":
            return make(proxyInfo(now: now, sentAgo: 3 * 3_600_000, quiet: true), live)
        case "rollback":
            return make(proxyInfo(now: now, sentAgo: nil, quiet: true, noSigns: .rollback),
                        all.filter { !SandboxBoard.isTheft($0) },
                        warnings: [SandboxBoard.rollbackWarning])
        case "flagged":
            // No proxy is trusted, so no heartbeat speaks for any row.
            var rows = live
            for i in rows.indices {
                rows[i].connected = nil
                rows[i].lastSeenMs = nil
            }
            var other = rows.prefix(2).map { $0 }
            for i in other.indices {
                other[i].proxyId = oldProxy
                other[i].sandboxId = "e" + other[i].sandboxId.dropFirst()
            }
            return make(nil, rows + other,
                        security: .preferencesByAgent(agentId: writer,
                                                      message: "agent \(writer) wrote the account's preferences"))
        case "paused":
            return make(proxyInfo(now: now, paused: true, sentAgo: 25 * 60_000, quiet: true),
                        live.filter { $0.status != .unknown })
        default:
            return make(proxyInfo(now: now), all)
        }
    }
}

/// Signing in or up on the sample: no server, a made-up kit.
struct SampleAccounts: AccountMaker {
    let engine: SampleEngine

    func signIn(server: String, email: String, password: String, secretKey: String, deviceName: String) throws {
        guard password == "sample" else { throw KlavError.WrongCredentials }
        engine.signedIn()
    }

    func signUp(server: String, email: String, password: String, deviceName: String) throws -> String {
        engine.signedIn()
        return """
        KLAV EMERGENCY KIT (SAMPLE, NOT A REAL ACCOUNT)
        ===============================================

        Server:     \(server)
        E-mail:     \(email)
        Account ID: 00000000-0000-0000-0000-000000000000
        Secret Key: SAMPLE-ONLY-NOT-A-KEY
        """
    }
}

/// The system as the screenshots and the tests see it: a LaunchAgent that
/// is only a flag, no administrator's password, the real `klav` (pointed at
/// temporary homes by `KLAV_BROWSER_HOME` and `KLAV_HOME`).
///
/// It never runs a program, nor sets anything up, on the person's real
/// home, `KLAV_HOME` or PATH (`SampleSafety`): a test run once wrote
/// `clients.json` in the real `KLAV_HOME` through `klav skill update`.
final class SampleSystem: MacSystem, @unchecked Sendable {
    private let mutex = NSLock()
    private var state: AgentState
    private(set) var administratorCommands: [String] = []
    private(set) var restarts = 0
    var other: String?

    init(agent: AgentState = .notRegistered, reader: BuildMarker.Reader = BuildMarker.Reader()) {
        state = agent
        self.reader = reader
    }

    func agentState() -> AgentState { mutex.lock(); defer { mutex.unlock() }; return state }
    func registerAgent() throws { mutex.lock(); state = .enabled; mutex.unlock() }
    /// What `unregisterAgent` throws instead (macOS keeping it).
    var agentError: Error?
    func unregisterAgent() throws {
        mutex.lock(); defer { mutex.unlock() }
        if let agentError { throw agentError }
        state = .notRegistered
    }
    func restartAgent() throws { mutex.lock(); restarts += 1; mutex.unlock() }
    /// Times System Settings › Login Items was opened.
    private(set) var loginItemsOpened = 0
    func openLoginItems() { mutex.lock(); loginItemsOpened += 1; mutex.unlock() }

    /// The app as a login item: never registered with macOS. `appRegistersAs`
    /// is what `register` leaves (`.requiresApproval` when macOS wants the
    /// person to allow it); `appError`, what it throws instead.
    private var appState: AgentState = .notRegistered
    var appRegistersAs: AgentState = .enabled
    var appError: Error?
    private(set) var appRegistrations = 0

    func appLoginState() -> AgentState { mutex.lock(); defer { mutex.unlock() }; return appState }
    func registerApp() throws {
        mutex.lock(); defer { mutex.unlock() }
        if let appError { throw appError }
        appRegistrations += 1
        appState = appRegistersAs
    }
    func unregisterApp() throws {
        mutex.lock(); defer { mutex.unlock() }
        if let appError { throw appError }
        appState = .notRegistered
    }
    /// The person turns it off (or on) in System Settings.
    func setAppLoginState(_ state: AgentState) { mutex.lock(); appState = state; mutex.unlock() }

    func runAsAdministrator(_ command: String) throws {
        mutex.lock(); administratorCommands.append(command); mutex.unlock()
        throw SetupError.cancelled
    }

    /// Runs `tool` only when what it gets, the app's environment with this
    /// call's on top, points at test folders (`SampleSafety`).
    func run(_ tool: URL, _ arguments: [String], environment: [String: String]) throws -> ToolResult {
        var effective = ProcessInfo.processInfo.environment
        for (key, value) in environment { effective[key] = value }
        if let why = SampleSafety.problem(environment: effective) { throw SetupError.failed(why) }
        guard arguments.contains("host-status") else { return try runTool(tool, arguments, environment: environment) }
        mutex.lock()
        let failure = hostStatusFailure, after = afterHostStatus
        mutex.unlock()
        if let failure { return ToolResult(status: 1, output: Data(), errors: failure) }
        let result = try runTool(tool, arguments, environment: environment)
        after?()
        return result
    }

    private var hostStatusFailure: String?
    private var afterHostStatus: (@Sendable () -> Void)?

    /// Tests: `klav extension host-status` fails with this message (nil: runs).
    func failHostStatus(_ message: String?) { mutex.lock(); hostStatusFailure = message; mutex.unlock() }
    /// Tests: runs after each `host-status` has read the browsers and
    /// before its answer goes back (a slow read).
    func afterEachHostStatus(_ body: (@Sendable () -> Void)?) { mutex.lock(); afterHostStatus = body; mutex.unlock() }

    /// Files whose contents `probeCLIs` refused to read (`SampleSafety`).
    private(set) var refusedReads: [String] = []

    /// Reads another `klav`'s file, and cargo's record beside it, only in a
    /// test folder: one on the person's real PATH or in their home is only
    /// looked for, never read (`SampleSafety`).
    func probeCLIs(_ candidates: [String], appCLI: String, contents: Bool) -> [String: BuildMarker.Probe] {
        let jobs = candidates.map { path -> (path: String, contents: Bool) in
            guard contents, SampleSafety.problem(tool: URL(fileURLWithPath: path)) != nil else { return (path, contents) }
            mutex.lock(); refusedReads.append(path); mutex.unlock()
            return (path, false)
        }
        return reader.probe(jobs, appCLI: appCLI)
    }

    /// Its own reader, so one test's cache never answers for another's.
    let reader: BuildMarker.Reader

    /// Tests: browsers reported as installed apps on this Mac (nil: show
    /// every browser whose data folder exists under the test home).
    private var installedSet: Set<String>?
    func setInstalledBrowsers(_ browsers: Set<String>?) { mutex.lock(); installedSet = browsers; mutex.unlock() }
    func installedBrowsers() -> Set<String>? { mutex.lock(); defer { mutex.unlock() }; return installedSet }

    func executable(of pid: Int32) -> String? { mutex.lock(); defer { mutex.unlock() }; return other }

    func refusal(for paths: InstallPaths) -> String? { SampleSafety.problem(paths: paths) }
}

/// What keeps the sample vault off the person's real home (review of PR
/// #230): `klav` and the setup run there only on test folders, outside the
/// home folder. `scripts/macos/test.sh` gives the test host fresh ones
/// (`KLAV_HOME`, `KLAV_BROWSER_HOME`, `KLAV_CLI_LINK_DIR`); a run from
/// Xcode without them is refused, not let through.
enum SampleSafety {
    /// The home folder from the user database: `$HOME` can be moved.
    static var realHome: String {
        if let entry = getpwuid(getuid()), let dir = entry.pointee.pw_dir {
            return URL(fileURLWithPath: String(cString: dir)).standardizedFileURL.path
        }
        return FileManager.default.homeDirectoryForCurrentUser.standardizedFileURL.path
    }

    /// `path` is the real home or inside it, as written or once its links
    /// are followed.
    static func inRealHome(_ path: String) -> Bool {
        let home = realHome
        let url = URL(fileURLWithPath: path)
        return [url.standardizedFileURL.path, url.resolvingSymlinksInPath().standardizedFileURL.path]
            .contains { $0 == home || $0.hasPrefix(home + "/") }
    }

    /// Why `klav` may not run with this environment, or nil. `HOME` and
    /// `KLAV_HOME` must be test folders; `CODEX_HOME` and
    /// `CLAUDE_CONFIG_DIR`, which `klav client` follows, too when set.
    static func problem(environment: [String: String]) -> String? {
        for key in ["HOME", "KLAV_HOME"] {
            guard let value = environment[key], value.hasPrefix("/") else {
                return "The sample vault runs klav only on a test folder, and \(key) isn’t one: set KLAV_HOME and KLAV_BROWSER_HOME outside your home folder."
            }
        }
        for key in ["HOME", "KLAV_HOME", "CODEX_HOME", "CLAUDE_CONFIG_DIR"] {
            guard let value = environment[key], !value.isEmpty else { continue }
            if !value.hasPrefix("/") || inRealHome(value) {
                return "The sample vault doesn’t run klav on your real home (\(key) is \(value)): set KLAV_HOME and KLAV_BROWSER_HOME outside your home folder."
            }
        }
        return nil
    }

    /// Why the sample may not run or read this program, or nil: only one
    /// in a test folder, never in the real home, in a directory of the
    /// real PATH (the person's own `klav`, `/usr/local/bin/klav`) or in an
    /// Applications folder, as written or once its links are followed.
    static func problem(tool: URL) -> String? {
        let real = Set(InstallPaths.searchPath(home: URL(fileURLWithPath: realHome)).map { $0.standardizedFileURL.path })
        for url in [tool.standardizedFileURL, tool.resolvingSymlinksInPath().standardizedFileURL] {
            let dir = url.deletingLastPathComponent().path
            if inRealHome(url.path) || real.contains(dir) || url.path.hasPrefix("/Applications/") {
                return "The sample vault doesn’t run or read \(url.path): only programs in a test folder."
            }
        }
        return nil
    }

    /// Why the setup may not touch these places, or nil: the home, the
    /// `KLAV_HOME` and the link's folder must be test folders, not the
    /// person's nor a directory of the real PATH (`/usr/local/bin`).
    static func problem(paths: InstallPaths) -> String? {
        if inRealHome(paths.userHome.path) || inRealHome(paths.klavHome.path) {
            return "The sample vault sets nothing up on your real home: set KLAV_HOME and KLAV_BROWSER_HOME outside your home folder."
        }
        let link = paths.linkDirectory.standardizedFileURL.path
        let real = Set(InstallPaths.searchPath(home: URL(fileURLWithPath: realHome)).map { $0.standardizedFileURL.path })
        if inRealHome(link) || real.contains(link) {
            return "The sample vault doesn’t link klav in \(link): set KLAV_CLI_LINK_DIR to a test folder."
        }
        return nil
    }
}

extension MacModel {
    static func sample(_ engine: SampleEngine) -> MacModel {
        MacModel(engine: engine, accounts: SampleAccounts(engine: engine))
    }
}
#endif
