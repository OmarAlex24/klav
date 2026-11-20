import Foundation
import SwiftUI

/// Development › Sandboxes (ADR 0036 E2, E4) as the person reads it: the
/// proxy on top, a security problem apart from the warnings, the theft
/// signals, the live sandboxes and those that ended in the last 24 hours.
/// Built from `klavd`'s `sandbox_list_checked`, never `sandbox_list`, so a
/// list with a security problem is shown with it instead of failing.
struct SandboxBoard {
    let list: SandboxListInfo
    /// This Mac's clock (Unix ms).
    let now: Int64
    /// When the list was read (Unix ms): the heartbeat's age is from then.
    let readMs: Int64
    /// Every agent paused, as `klavd`'s status says: no sandbox can use
    /// the proxy, whatever the proxy's own heartbeat said.
    let everyonePaused: Bool
    /// The last read failed (the network, `klavd`): this list is an old
    /// reading, so nothing the proxy said reads as current.
    let stale: Bool
    /// Theft signals the person answered «Got it»: they move to «Ended».
    let seenThefts: Set<String>

    static let day: Int64 = 86_400_000

    init(list: SandboxListInfo, now: Int64, readMs: Int64? = nil, everyonePaused: Bool, seenThefts: Set<String>,
         stale: Bool = false) {
        self.stale = stale
        self.list = list
        self.now = now
        self.readMs = readMs ?? now
        self.everyonePaused = everyonePaused
        self.seenThefts = seenThefts
    }

    var proxy: SandboxProxyInfo? { list.proxy }
    var security: SandboxSecurityInfo? { list.security }

    /// No proxy set and nothing wrong with the setting: the pane says what
    /// is lost without one and how to set one.
    var noProxy: Bool { list.proxy == nil && list.security == nil }

    /// With the security flag there is no proxy, and the rows are every
    /// proxy's. Without a proxy the chain's rows are every proxy's too.
    var everyProxysRows: Bool { list.proxy == nil }

    /// «Agents are paused: no sandbox can use the proxy.»
    var paused: Bool { everyonePaused || (list.proxy?.paused ?? false) }

    /// Theft signals not answered yet, newest first: on top of everything.
    var thefts: [SandboxInfo] {
        list.sandboxes.filter { Self.isTheft($0) && !seenThefts.contains($0.sandboxId) }.reversed()
    }

    /// Waiting, active, revoking and a state this version does not know
    /// (never left out, never taken as ended), newest first.
    var live: [SandboxInfo] { list.sandboxes.filter(Self.isLive).reversed() }

    /// Ended, or past their expiry with the end not logged yet, in the last
    /// 24 hours, newest first by when they ended (or expired). An answered
    /// theft signal is here too.
    var ended: [SandboxInfo] {
        list.sandboxes.filter { s in
            switch s.status {
            case .ended:
                if Self.isTheft(s) && !seenThefts.contains(s.sandboxId) { return false }
                return (s.endedMs ?? s.expiresMs) >= now - Self.day
            case .expired:
                return s.expiresMs >= now - Self.day
            default:
                return false
            }
        }.sorted { ($0.endedMs ?? $0.expiresMs) > ($1.endedMs ?? $1.expiresMs) }
    }

    /// The rows «Revoke all» covers: the account's proxy's that can still
    /// be revoked. None without a proxy (the flag lists every proxy's rows,
    /// and «all» is one proxy's).
    var revokeAll: [SandboxInfo] {
        guard let proxy = list.proxy else { return [] }
        return live.filter { $0.proxyId == proxy.agentId && Self.revocable($0) }
    }

    /// The warnings to show as ordinary warnings. A heartbeat rollback is
    /// also in `warnings`, in `klav-client`'s exact words; the proxy's
    /// header already says it as a security warning, so that one line is
    /// not said twice. Nothing else is hidden.
    var warnings: [String] {
        guard list.proxy?.noSigns == .rollback else { return list.warnings }
        return list.warnings.filter { $0 != Self.rollbackWarning }
    }

    /// `klav-client`'s warning for a heartbeat rollback (`sandboxes.rs`).
    static let rollbackWarning = "the server sent an older heartbeat of the proxy than this device has seen: it is not shown"

    /// How long ago the proxy's last heartbeat was signed, now: the age the
    /// list gave, plus the time since it was read.
    func heartbeatAge(_ p: SandboxProxyInfo) -> Int64? { Self.age(p, now: now, readMs: readMs) }

    static func age(_ p: SandboxProxyInfo, now: Int64, readMs: Int64) -> Int64? {
        if let age = p.heartbeatAgeMs { return age + max(0, now - readMs) }
        return p.heartbeatSentMs.map { now - $0 }
    }

    /// Something below the header: without a proxy, only what the log
    /// still has alive or a theft signal, never an empty list.
    var showsList: Bool { !noProxy || !thefts.isEmpty || !live.isEmpty }

    static func isTheft(_ s: SandboxInfo) -> Bool { s.status == .ended && s.endReason == .theft }

    static func isLive(_ s: SandboxInfo) -> Bool {
        switch s.status {
        case .waiting, .active, .revoking, .unknown: return true
        case .expired, .ended: return false
        }
    }

    /// «Revoke» on a row: waiting or active, and a state this version does
    /// not know (taken as live). Not one already revoking.
    static func revocable(_ s: SandboxInfo) -> Bool {
        switch s.status {
        case .waiting, .active, .unknown: return true
        case .revoking, .expired, .ended: return false
        }
    }
}

/// How a line is colored: cobalt for what agents do, grey for the rest,
/// red for a security warning or a theft signal.
enum SandboxTone: Equatable { case agent, quiet, alert }

/// The words of Development › Sandboxes, in the interface's language. The
/// label is the issuer's words and is said as such (T136, T157).
enum SandboxWords {
    static func idPrefix(_ id: String) -> String { String(id.prefix(8)) }

    /// “chat-123”, one clean line.
    static func quoted(_ text: String) -> String { String(localized: "“\(AgentText.line(text, max: 64))”") }

    static func profiles(_ s: SandboxInfo) -> String {
        s.profiles.isEmpty ? String(localized: "No profile")
                           : s.profiles.map { AgentText.line($0, max: 64) }.joined(separator: ", ")
    }

    /// «Issuer: t3code · 3f2a9c01», the name the server lists and the
    /// start of its ID.
    static func issuer(_ s: SandboxInfo) -> String {
        let id = idPrefix(s.issuerId)
        guard let name = s.issuerName.map({ AgentText.line($0, max: 64) }), !name.isEmpty else {
            return String(localized: "Issuer \(id)")
        }
        return String(localized: "Issuer: \(name) · \(id)")
    }

    /// «6 h 12 min», «45 min».
    static func span(_ ms: Int64) -> String {
        let minutes = max(1, Int((ms + 59_999) / 60_000))
        if minutes < 60 { return String(localized: "\(minutes) min") }
        let hours = minutes / 60, rest = minutes % 60
        return rest == 0 ? String(localized: "\(hours) h") : String(localized: "\(hours) h \(rest) min")
    }

    /// «just now», «4 min ago», «2 h 5 min ago».
    static func ago(_ ms: Int64) -> String {
        if ms < 60_000 { return String(localized: "just now") }
        if ms < 3_600_000 { return String(localized: "\(Int(ms / 60_000)) min ago") }
        return String(localized: "\(span(ms)) ago")
    }

    static func expiry(_ s: SandboxInfo, now: Int64) -> String {
        let left = s.expiresMs - now
        return left > 0 ? String(localized: "Expires in \(span(left))")
                        : String(localized: "Expired \(ago(-left))")
    }

    // MARK: The proxy

    /// Its name in quotes, as the server lists it, or «Your proxy».
    static func proxyName(_ p: SandboxProxyInfo) -> String {
        guard let name = p.name.map({ AgentText.line($0, max: 64) }), !name.isEmpty else {
            return String(localized: "Your proxy")
        }
        return quoted(name)
    }

    /// The proxy's heartbeat: its age, why there are no signs, or a
    /// rollback, which is a security warning and never a quiet proxy
    /// (decision of 2026-11-16, «Un latido que retrocede»).
    /// `readMs`: when the list was read; the age grows from it. Whether the
    /// proxy is quiet is `klav-client`'s judgment at that read: its
    /// thresholds don't reach Swift, so it isn't judged again here.
    /// `stale`: the list is an old reading (the last read failed), so the
    /// heartbeat it carried isn't the proxy's word now.
    static func heartbeat(_ p: SandboxProxyInfo, paused: Bool, now: Int64, readMs: Int64? = nil,
                          stale: Bool = false) -> (String, SandboxTone) {
        let readMs = readMs ?? now
        if p.noSigns == .rollback {
            return (String(localized: "Security warning: the server sent an older heartbeat of the proxy than this Mac already accepted, so it may be holding the latest one back. The list comes from the verified log and is right; the proxy’s state isn’t known."), .alert)
        }
        if stale { return (String(localized: "No signs from the proxy."), .quiet) }
        if paused && (p.quiet || p.noSigns != nil) {
            return (String(localized: "Paused: the proxy keeps what it can’t log and sends it when agents resume."), .agent)
        }
        if let reason = p.noSigns {
            return (String(localized: "No signs from the proxy: \(noSigns(reason))"), .quiet)
        }
        if p.quiet {
            guard let age = quietFor(p, now: now, readMs: readMs) else { return (String(localized: "No signs from the proxy."), .quiet) }
            return (String(localized: "No signs from the proxy for \(span(age))"), .quiet)
        }
        guard let age = quietFor(p, now: now, readMs: readMs) else { return (String(localized: "No heartbeat yet."), .quiet) }
        return (String(localized: "Last heartbeat \(ago(age)), according to the proxy."), .quiet)
    }

    /// How long the proxy has been quiet, by this Mac's clock, measured
    /// from its last heartbeat's signed time (E3.3).
    static func quietFor(_ p: SandboxProxyInfo, now: Int64, readMs: Int64? = nil) -> Int64? {
        SandboxBoard.age(p, now: now, readMs: readMs ?? now)
    }

    static func noSigns(_ reason: ProxyNoSigns) -> String {
        switch reason {
        case .noHeartbeat: return String(localized: "the server has no heartbeat from it.")
        case .noEpoch: return String(localized: "the verified log doesn’t have its store yet.")
        case .otherEpoch: return String(localized: "its heartbeat is from another store than the one in the verified log.")
        case .ahead: return String(localized: "its heartbeat is signed more than 5 minutes ahead of this Mac’s clock.")
        case .version: return String(localized: "its heartbeat is from a newer proxy. Update Klav.")
        case .rollback: return String(localized: "the server held its latest heartbeat back.")
        case .unknown: return String(localized: "for a reason this version of Klav doesn’t know. Update Klav.")
        }
    }

    // MARK: The security problem

    /// What the person reads, and the command that fixes it: the app can't
    /// set the proxy (no operation for it), the terminal does.
    static func security(_ s: SandboxSecurityInfo, everyProxy: Bool) -> String {
        let rows = everyProxy ? " " + String(localized: "Until then the list shows every proxy’s sandboxes.") : ""
        switch s {
        case .preferencesByAgent(let agentId, _):
            return String(localized: "The agent \(idPrefix(agentId)) wrote your account’s preferences, which no agent may write. Klav trusts no proxy until you choose yours again, which replaces those preferences whole without using anything in them.") + rows
        case .unknown(let message):
            return String(localized: "A security problem this version of Klav doesn’t know: \(AgentText.line(message, max: 300)) Update Klav.") + rows
        }
    }

    static let chooseProxy = "klav proxy use own <proxy>"

    // MARK: A sandbox's state

    /// The state on the right of a row, and the line under it.
    static func state(_ s: SandboxInfo, paused: Bool, now: Int64) -> (String, String?, SandboxTone) {
        switch s.status {
        case .waiting:
            let late = now - s.issuedMs > 15 * 60_000
            return (String(localized: "Waiting to be claimed"),
                    late ? String(localized: "Nobody has claimed it yet: the sandbox may not have started.") : nil, .quiet)
        case .active:
            return (String(localized: "Active"), nil, .agent)
        case .revoking:
            if paused { return (String(localized: "Revoking…"), String(localized: "Paused: the proxy confirms it when agents resume."), .quiet) }
            let late = s.revokedByPersonMs.map { now - $0 > 2 * 60_000 } ?? false
            return (String(localized: "Revoking…"),
                    late ? String(localized: "Revoked on the server; the proxy hasn’t confirmed it yet.") : nil, .quiet)
        case .expired:
            return (String(localized: "Expired"),
                    String(localized: "The server already denies it access; the proxy hasn’t logged its end yet."), .quiet)
        case .ended:
            return (ended(s.endReason), s.endedMs.map { String(localized: "Ended \(ago(now - $0))") },
                    s.endReason == .theft ? .alert : .quiet)
        case .unknown:
            return (String(localized: "Unknown state"),
                    String(localized: "A state this version of Klav doesn’t know: it counts as live. Update Klav."), .quiet)
        }
    }

    /// Why it ended, in the person's words (E2.1).
    static func ended(_ reason: SandboxEndInfo?) -> String {
        switch reason {
        case .stop: return String(localized: "The issuer stopped it")
        case .ttl: return String(localized: "It expired")
        case .inactivity: return String(localized: "An hour without a connection")
        case .theft: return String(localized: "Theft signal")
        case .released: return String(localized: "The sandbox let it go when it shut down")
        case .issuerRemoved: return String(localized: "You removed or revoked its issuer")
        case .person: return String(localized: "You revoked it")
        case .personLocal: return String(localized: "You revoked it on this Mac")
        case .unknown, nil: return String(localized: "Ended, for a reason this version of Klav doesn’t know")
        }
    }

    /// Its last connection, per the proxy's heartbeat (E2.1). Nil where
    /// there is nothing to say.
    /// Nil without a proxy: no heartbeat speaks for any row then.
    /// Nil too on an old reading (`stale`): what the proxy said then isn't
    /// current.
    static func connection(_ s: SandboxInfo, proxy: SandboxProxyInfo?, paused: Bool, now: Int64,
                           readMs: Int64? = nil, stale: Bool = false) -> String? {
        guard s.status == .active || s.status == .unknown else { return nil }
        guard let proxy, !paused, !stale else { return nil }
        if proxy.quiet || proxy.noSigns != nil {
            if proxy.noSigns == nil, let age = quietFor(proxy, now: now, readMs: readMs) {
                return String(localized: "No signs from the proxy for \(span(age))")
            }
            return String(localized: "No signs from the proxy.")
        }
        if s.connected == true { return String(localized: "Connected, according to the proxy") }
        if let seen = s.lastSeenMs {
            return s.connected == false
                ? String(localized: "No connection for \(span(now - seen)), according to the proxy")
                : String(localized: "Last connection \(ago(now - seen)), according to the proxy")
        }
        return nil
    }

    static let theft = String(localized: "Someone claimed this sandbox a second time and Klav revoked it. If it wasn’t you or the issuer, someone copied its environment: the sandbox’s provider still has its variables.")

    // MARK: Revoking

    /// What the server's answer means, in plain words.
    static func revoked(_ outcome: SandboxRevokeInfo) -> String {
        switch outcome {
        case .revoked(let scope, _, let ids):
            guard scope == "all" else {
                return String(localized: "Revoked on the server: it gets no access from now on. It says “Revoking…” until the proxy confirms it stopped.")
            }
            return ids.count == 1
                ? String(localized: "Revoked 1 sandbox on the server: it gets no access from now on. It says “Revoking…” until the proxy confirms it stopped.")
                : String(localized: "Revoked \(ids.count) sandboxes on the server: they get no access from now on. Each says “Revoking…” until the proxy confirms it stopped.")
        case .notApplied(let scope, _):
            return scope == "all"
                ? String(localized: "Not applied: the server already has a later revocation of all of them, signed ahead of this Mac’s clock. The sandboxes it covers say “Revoking…”; those issued after it aren’t covered.")
                : String(localized: "Not applied: the server already has a later revocation of this sandbox, signed ahead of this Mac’s clock. If it covers it, the row says “Revoking…”.")
        }
    }

    /// Why revoking didn't go through.
    static func failure(_ error: Error) -> String {
        if case KlavError.Locked = error {
            return String(localized: "Unlock Klav to revoke: revoking signs with your account. Nothing was revoked.")
        }
        return describe(error)
    }

    // MARK: A read that fails its checks

    /// The check `klav-client` named (`sandbox_list_checked`), in the app's
    /// words. A check this build doesn't know gets the generic sentence,
    /// with `klav-client`'s English words apart, under their own label.
    static func integrity(_ check: SandboxCheckInfo, message: String, bundle: Bundle? = nil) -> SandboxIntegrity {
        switch check {
        case .unlistedProxy(let agentId):
            return SandboxIntegrity(
                text: String(localized: "The account’s proxy setting names agent \(agentId), which the server doesn’t list among the account’s agents: the server may be hiding it, or a device of the account named an agent the server doesn’t have. Klav doesn’t show the last list it read, which may no longer be true.", bundle: bundle),
                command: true)
        case .proxyHeartbeat(let agentId):
            return SandboxIntegrity(text: String(localized: "The proxy’s heartbeat (agent \(agentId)) doesn’t verify: it isn’t what the proxy signed, or it isn’t a heartbeat. Klav doesn’t show the last list it read, which may no longer be true.", bundle: bundle))
        case .log:
            return SandboxIntegrity(text: String(localized: "The account’s audit log, as the server sent it, doesn’t verify: the server may have altered it. Klav doesn’t show the last list it read, which may no longer be true.", bundle: bundle))
        case .unknown:
            return unverified(message, bundle: bundle)
        }
    }

    /// A read `klav-client` refused that arrived as an error: a `klavd`
    /// older than `sandbox_list_checked`, the session's own checks, or the
    /// server rolled back. Nil for any other failure (the network, a
    /// `klavd` that is down), which keeps the last list.
    static func integrity(_ error: Error, bundle: Bundle? = nil) -> SandboxIntegrity? {
        guard let error = error as? KlavError else { return nil }
        switch error {
        case .Security(let message):
            return unverified(message, bundle: bundle)
        case .Rollback:
            return SandboxIntegrity(text: String(localized: "The server sent older data than this Mac has already seen, so Klav doesn’t show the sandbox list: it may be an attack or an old backup.", bundle: bundle))
        default:
            return nil
        }
    }

    /// What the app can say for sure, and `klav-client`'s words apart.
    private static func unverified(_ message: String, bundle: Bundle?) -> SandboxIntegrity {
        // `klavd` puts `SECURITY: ` before `klav-client`'s words; the
        // block is already titled as a security problem.
        let words = message.hasPrefix(securityPrefix) ? String(message.dropFirst(securityPrefix.count)) : message
        let detail = AgentText.line(words, max: integrityMax).trimmingCharacters(in: .whitespaces)
        return SandboxIntegrity(
            text: String(localized: "Klav couldn’t verify the sandbox list, so it doesn’t show the last list it read, which may no longer be true.", bundle: bundle),
            detail: detail.isEmpty ? nil : detail)
    }

    /// The cap on `klav-client`'s words in that block, with margin. One
    /// measured: the proxy setting naming an agent the server doesn't list
    /// reaches the app at 349 characters (339 from `klav-client` plus
    /// `klavd`'s `SECURITY: `); `klavd` sends at most 1000.
    static let integrityMax = 600
    static let securityPrefix = "SECURITY: "

    /// «Read 3 min ago».
    static func read(_ readMs: Int64, now: Int64) -> String {
        String(localized: "Read \(ago(max(0, now - readMs)))")
    }

    // MARK: A revocation the server didn't log (E3.3)

    static func unregistered(_ c: RevocationCheck) -> String {
        c.scope == RevocationCheck.all
            ? String(localized: "Klav revoked every sandbox of your proxy and the server answered, but the verified log doesn’t have that revocation: they may still have access. Klav checks again on every read. To cut them now, pause agents or revoke the proxy.")
            : String(localized: "Klav revoked \(quoted(c.label)) and the server answered, but the verified log doesn’t have that revocation: it may still have access. Klav checks again on every read. To cut it now, pause agents or revoke the proxy.")
    }
}

/// A read that failed its checks, as the Sandboxes pane says it.
struct SandboxIntegrity: Equatable {
    /// What happened, in the app's words.
    let text: String
    /// `klav-client`'s own words, in English, shown apart under their label:
    /// only for a check this build has no words for.
    var detail: String?
    /// The terminal's command that sets the proxy again.
    var command = false
}

/// The proxy «Revoke all» signs for, and the sandboxes it covers if the
/// list on screen can say (nil: it can't).
struct RevokeAllScope {
    let proxyId: String
    let covered: [SandboxInfo]?
}

/// What an action in Sandboxes answered (a revocation, or why it failed).
struct SandboxNotice {
    let text: String
    let error: Bool
    /// The revocation it speaks of, if the server took one.
    let check: UUID?
    /// The list as it stood: a read that changes it takes the notice away.
    let fingerprint: [String]

    static func fingerprint(_ list: SandboxListInfo) -> [String] {
        [list.proxy?.agentId ?? ""] + list.sandboxes.map {
            "\($0.proxyId) \($0.sandboxId) \($0.status) \($0.revokedByPersonMs ?? 0) \($0.endedMs ?? 0)"
        }
    }
}

/// A revocation the server answered, waiting for a read that started after
/// the answer to show it in the verified log (ADR 0036 E3.3): each covered
/// sandbox's `revokedByPersonMs` at least its signed time.
struct RevocationCheck: Identifiable {
    static let all = "all"
    let id = UUID()
    let proxyId: String
    /// A sandbox's ID, or `all`.
    let scope: String
    /// The issuer's label of that sandbox (empty with `all`).
    let label: String
    let atMs: Int64
    let sandboxIds: [String]
    /// The number of the last read started before the answer.
    let afterRead: Int
    /// A read after the answer didn't show it.
    var missed = false

    enum Seen { case logged, notLogged, cannotTell }

    /// What `list` says of it. A sandbox the list doesn't have (another
    /// proxy's, once the list is the account's proxy's only) says nothing.
    func seen(in list: SandboxListInfo) -> Seen {
        var told = false
        for id in sandboxIds {
            guard let row = list.sandboxes.first(where: { $0.sandboxId == id }) else { continue }
            told = true
            if (row.revokedByPersonMs ?? .min) < atMs { return .notLogged }
        }
        return told ? .logged : .cannotTell
    }
}

// MARK: - The model

extension MacModel {
    var nowMs: Int64 { Int64(Date().timeIntervalSince1970 * 1000) }

    /// The pane's list, as the board reads it; nil until `klavd` answered,
    /// and after a read that failed its checks.
    var sandboxBoard: SandboxBoard? { sandboxBoard(now: nowMs) }

    func sandboxBoard(now: Int64) -> SandboxBoard? {
        sandboxList.map {
            SandboxBoard(list: $0, now: now, readMs: sandboxListReadMs, everyonePaused: everyonePaused != nil,
                         seenThefts: seenThefts, stale: sandboxProblem != nil)
        }
    }

    /// Theft signals not answered yet: in the menu bar, in red, whatever
    /// else is shown (ADR 0036 E4).
    var shownThefts: [SandboxInfo] { sandboxBoard?.thefts ?? [] }

    /// Revocations a read after the answer didn't find in the log.
    var unregisteredRevocations: [RevocationCheck] { revocationChecks.filter(\.missed) }

    /// Reads the list from `klavd`, unless it was read less than `maxAge`
    /// seconds ago. Each read syncs and verifies the log, so the menu bar
    /// reads it at most every 5 minutes.
    ///
    /// With `maxAge` 0 the caller needs a read that starts now: if one is
    /// already running (it may have the list from before a revocation), it
    /// waits for it and reads again. Otherwise a running read is enough.
    func loadSandboxes(maxAge: TimeInterval) async {
        let wanted = sandboxReadsStarted + 1
        while true {
            guard phase == .unlocked, !accountDeleted else { return }
            if sandboxReadsDone >= wanted { return }
            if let running = sandboxRead {
                guard maxAge == 0 else { return }
                await running.value
                continue
            }
            guard maxAge == 0 || Date().timeIntervalSince(sandboxesReadAt) >= maxAge else { return }
            sandboxReadsStarted += 1
            let number = sandboxReadsStarted
            let read = Task { @MainActor in
                await self.readSandboxes(number: number)
                self.sandboxReadsDone = number
                self.sandboxRead = nil
            }
            sandboxRead = read
            await read.value
            return
        }
    }

    /// One read. A plain failure keeps the last list and says why; one that
    /// failed its checks drops it, so nothing old reads as current.
    private func readSandboxes(number: Int) async {
        let started = nowMs
        let epoch = sandboxEpoch
        // Signed out or the account deleted while it read: nothing lands.
        var current: Bool { epoch == sandboxEpoch && phase == .unlocked && !accountDeleted }
        do {
            let answer = try await run { try $0.sandboxListChecked(allProxies: false) }
            #if DEBUG
            if let hold = sandboxReadHold {
                sandboxReadHold = nil
                await hold()
            }
            #endif
            guard current else { return }
            let list: SandboxListInfo
            switch answer {
            case .listed(let listed):
                list = listed
            case .refused(let check, let message):
                dropSandboxes(SandboxWords.integrity(check, message: message))
                sandboxesReadAt = Date()
                return
            }
            if let notice = sandboxNotice, notice.fingerprint != SandboxNotice.fingerprint(list) {
                sandboxNotice = nil
            }
            sandboxList = list
            sandboxListReadMs = started
            sandboxProblem = nil
            sandboxIntegrity = nil
            judgeRevocations(list, read: number)
            pruneSeenThefts(list)
        } catch KlavError.Locked {
            refresh()
        } catch {
            guard current else { return }
            if let integrity = SandboxWords.integrity(error) {
                dropSandboxes(integrity)
            } else {
                sandboxProblem = describe(error)
            }
        }
        sandboxesReadAt = Date()
    }

    /// A read that failed its checks drops the list, so nothing old reads
    /// as current, and says why.
    private func dropSandboxes(_ integrity: SandboxIntegrity) {
        sandboxList = nil
        sandboxProblem = nil
        sandboxNotice = nil
        sandboxIntegrity = integrity
    }

    /// Each revocation waiting: a read started after its answer either
    /// shows it (done), can't tell (dropped, unless it is already red: then
    /// it stays until a read shows it), or doesn't (missed, kept and
    /// checked again on every read).
    private func judgeRevocations(_ list: SandboxListInfo, read: Int) {
        revocationChecks = revocationChecks.compactMap { check in
            guard read > check.afterRead else { return check }
            switch check.seen(in: list) {
            case .logged: return nil
            case .cannotTell: return check.missed ? check : nil
            case .notLogged:
                var missed = check
                missed.missed = true
                return missed
            }
        }
    }

    /// «Revoke»: signed by `klavd` with the account, without Touch ID
    /// (E2.3). Says what the server answered, then reads the list again.
    func revokeSandbox(_ s: SandboxInfo) async throws -> String {
        try await revokeSandbox(proxyId: s.proxyId, sandboxId: s.sandboxId, label: s.label)
    }

    func revokeSandbox(proxyId: String, sandboxId: String, label: String) async throws -> String {
        sandboxNotice = nil
        let outcome = try await run { try $0.revokeSandbox(proxyId: proxyId, sandboxId: sandboxId) }
        let check = expectInLog(outcome, proxyId: proxyId, label: label)
        await loadSandboxes(maxAge: 0)
        return say(SandboxWords.revoked(outcome), about: check)
    }

    /// «Revoke all»: every sandbox of the account's proxy issued so far.
    func revokeAllSandboxes(proxyId: String) async throws -> String {
        sandboxNotice = nil
        let outcome = try await run { try $0.revokeAllSandboxes(proxyId: proxyId) }
        let check = expectInLog(outcome, proxyId: proxyId, label: "")
        await loadSandboxes(maxAge: 0)
        return say(SandboxWords.revoked(outcome), about: check)
    }

    /// What «Revoke all» signs for: the proxy a «Revoke again» names, or
    /// the list's. The sandboxes it covers only when the list on screen is
    /// that proxy's and has some; otherwise the sheet says it can't tell
    /// how many, and still revokes (E3.3: revoking only takes access away).
    var revokeAllScope: RevokeAllScope? {
        let board = sandboxBoard
        guard let proxyId = revokeAllFor ?? board?.proxy?.agentId else { return nil }
        guard let board, board.proxy?.agentId == proxyId, !board.revokeAll.isEmpty else {
            return RevokeAllScope(proxyId: proxyId, covered: nil)
        }
        return RevokeAllScope(proxyId: proxyId, covered: board.revokeAll)
    }

    /// «Revoke all» in its sheet.
    func confirmRevokeAll() async throws -> String {
        guard let scope = revokeAllScope else { throw KlavError.NotFound(message: "proxy") }
        return try await revokeAllSandboxes(proxyId: scope.proxyId)
    }

    /// «Revoke again» on a revocation the log didn't show. The check stays
    /// until a new answer replaces it (`expectInLog`, same proxy and
    /// scope), and the new one stays red until a read shows it: a failure,
    /// «not applied» or an answer that covers nothing leaves the red block
    /// where it was. With `all` it opens «Revoke all» for the check's
    /// proxy (sandboxes issued since are covered too); nil then.
    func revokeAgain(_ check: RevocationCheck) async throws -> String? {
        if check.scope == RevocationCheck.all {
            revokeAllFor = check.proxyId
            revokingAllSandboxes = true
            return nil
        }
        return try await revokeSandbox(proxyId: check.proxyId, sandboxId: check.scope, label: check.label)
    }

    @discardableResult
    private func expectInLog(_ outcome: SandboxRevokeInfo, proxyId: String, label: String) -> RevocationCheck? {
        guard case .revoked(let scope, let at, let ids) = outcome, !ids.isEmpty else { return nil }
        // A red one stays red until a read shows the new revocation, also
        // when the reads after it fail.
        let wasMissed = revocationChecks.contains { $0.proxyId == proxyId && $0.scope == scope && $0.missed }
        revocationChecks.removeAll { $0.proxyId == proxyId && $0.scope == scope }
        var check = RevocationCheck(proxyId: proxyId, scope: scope, label: label, atMs: at,
                                    sandboxIds: ids, afterRead: sandboxReadsStarted)
        check.missed = wasMissed
        revocationChecks.append(check)
        return check
    }

    /// The answer, kept until the list it speaks of changes or the next
    /// action; about a revocation, it goes once that one turns red.
    @discardableResult
    func say(_ text: String, error: Bool = false, about check: RevocationCheck? = nil) -> String {
        sandboxNotice = SandboxNotice(text: text, error: error, check: check?.id,
                                      fingerprint: sandboxList.map(SandboxNotice.fingerprint) ?? [])
        return text
    }

    /// The notice to show: none once the revocation it speaks of is red.
    var shownSandboxNotice: SandboxNotice? {
        guard let notice = sandboxNotice else { return nil }
        if let id = notice.check, unregisteredRevocations.contains(where: { $0.id == id }) { return nil }
        return notice
    }

    /// «Got it» on a theft signal, kept in memory until the app quits; the
    /// row moves to «Ended in the last 24 h».
    func gotIt(theft id: String) {
        seenThefts.insert(id)
    }

    /// Answers for theft signals the list no longer has are forgotten.
    private func pruneSeenThefts(_ list: SandboxListInfo) {
        let thefts = Set(list.sandboxes.filter(SandboxBoard.isTheft).map(\.sandboxId))
        let kept = seenThefts.intersection(thefts)
        guard kept != seenThefts else { return }
        seenThefts = kept
    }

    /// The sandboxes' page, from the menu bar or a theft signal.
    func openSandboxes() { section = .sandboxes }
}
