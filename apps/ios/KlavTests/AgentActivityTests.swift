import LocalAuthentication
import XCTest
@testable import Klav

/// Agents' pause and activity on the iPhone (ADR 0033 §9): which pause
/// stops an agent, when the iPhone has to sync to learn one, what Face ID
/// leaves to the master password, the log's filters and words, and their
/// Spanish.
final class AgentActivityTests: XCTestCase {
    private let bot = "0192f3a4-5b6c-7d8e-9f00-112233445566"
    private let other = "0192f3a4-0000-7d8e-9f00-aabbccddeeff"

    private func agent(_ id: String, status: String = "active", paused: AgentPauseInfo? = nil,
                       lastSeen: Int64? = nil, createdAt: Int64 = 1_000, approvedMs: Int64? = 2_000) -> DevAgentInfo {
        DevAgentInfo(agent: AgentItem(id: id, name: "bot", note: nil, status: status, pairingWords: "uno dos tres",
                                      createdAt: createdAt, expiresAt: 0, projects: ["Personal/General"]),
                     lastSeenMs: lastSeen, approvedMs: approvedMs, paused: paused)
    }

    private func pause(_ agent: String?, since: Int64 = 1_000, until: Int64? = nil) -> PauseInfo {
        PauseInfo(agentId: agent, sinceMs: since, untilMs: until, local: false, serverUnsupported: false)
    }

    private func entry(actor: String, byAgent: Bool, agentId: String?, action: String = "agent.access",
                       permission: String? = "totp", at: Int64 = 0, seq: UInt64 = 1) -> LogEntryInfo {
        LogEntryInfo(seq: seq, atMs: at, actor: actor, byAgent: byAgent, agentId: agentId, action: action,
                     permission: permission, outcome: nil, item: nil, itemId: nil, vault: nil, reason: nil,
                     domain: nil, taskId: nil, approvalId: nil, untilMs: nil, attachments: 0, alerts: [],
                     verified: false)
    }

    // MARK: Pauses

    func testAnEndedPauseNoLongerCounts() {
        let pauses = Pauses([pause(nil, until: 5_000), pause(bot, until: 20_000)], now: 10_000)
        XCTAssertNil(pauses.everyone)
        XCTAssertEqual(pauses.own(bot)?.untilMs, 20_000)
        XCTAssertNotNil(Pauses([pause(nil)], now: Int64.max - 1).everyone, "a pause without an end holds")
    }

    /// The agent's own pause first, then every agent's, then what the
    /// server listed; only an agent with access is paused.
    func testWhatStopsAnAgent() {
        let fromServer = AgentPauseInfo(everyone: true, sinceMs: 5, untilMs: nil)
        let both = Pauses([pause(nil, since: 1), pause(bot, since: 2, until: 9_000)], now: 0)
        XCTAssertEqual(both.stopping(agent(bot)), AgentPauseInfo(everyone: false, sinceMs: 2, untilMs: 9_000))
        XCTAssertEqual(both.stopping(agent(other)), AgentPauseInfo(everyone: true, sinceMs: 1, untilMs: nil))
        XCTAssertEqual(Pauses([], now: 0).stopping(agent(bot, paused: fromServer)), fromServer)
        XCTAssertNil(Pauses([], now: 0).stopping(agent(bot)))
        XCTAssertNil(both.stopping(agent(bot, status: "pending")))
        XCTAssertNil(both.stopping(agent(bot, status: "revoked", paused: fromServer)))
    }

    /// Another device paused or resumed since this iPhone last synced.
    func testTheServerAndTheSignedPausesDisagree() {
        let server = AgentPauseInfo(everyone: false, sinceMs: 1, untilMs: nil)
        XCTAssertFalse(Pauses([], now: 0).disagrees(with: [agent(bot)]))
        XCTAssertTrue(Pauses([], now: 0).disagrees(with: [agent(bot, paused: server)]), "paused elsewhere")
        XCTAssertTrue(Pauses([pause(bot)], now: 0).disagrees(with: [agent(bot)]), "resumed elsewhere")
        XCTAssertFalse(Pauses([pause(bot)], now: 0).disagrees(with: [agent(bot, paused: server)]))
        XCTAssertFalse(Pauses([], now: 0).disagrees(with: [agent(bot, status: "revoked", paused: server)]))
    }

    func testAPauseInWords() {
        XCTAssertEqual(PauseWords.agentState(AgentPauseInfo(everyone: true, sinceMs: 0, untilMs: 1)),
                       "With every agent")
        XCTAssertEqual(PauseWords.agentState(AgentPauseInfo(everyone: false, sinceMs: 0, untilMs: nil)),
                       "Until you resume")
        XCTAssertTrue(PauseWords.agentState(AgentPauseInfo(everyone: false, sinceMs: 0, untilMs: 1)).hasPrefix("Ends at "))
        // The iPhone signs and sends a pause at once: never «on this Mac».
        XCTAssertEqual(PauseWords.title(pause(nil)), "Every agent is paused")
        XCTAssertNil(PauseWords.whereItHolds(pause(nil)))
        XCTAssertTrue(PauseWords.span(pause(nil)).hasSuffix("until you resume"))
        XCTAssertEqual(PauseLength.allCases.map(\.minutes), [15, 60, nil])
    }

    // MARK: The model

    /// The agents and pauses come with the requests, and locking forgets
    /// them with the rest.
    @MainActor
    func testTheModelKeepsTheAgentsAndPausesUntilItLocks() {
        let model = AppModel()
        model.received(agents: [agent(bot)], pauses: [pause(nil)])
        XCTAssertEqual(model.agentList.count, 1)
        XCTAssertNotNil(model.everyonePaused)
        model.lock()
        XCTAssertTrue(model.agentList.isEmpty)
        XCTAssertTrue(model.pauses.isEmpty)
        XCTAssertNil(model.everyonePaused)
    }

    /// An ended pause leaves the screen: the model drops it when it reads
    /// the pauses (offline too), and what the server listed before it ended
    /// no longer stops the agent nor asks for a sync.
    @MainActor
    func testAnEndedPauseLeavesTheScreen() {
        let past = Pauses.now() - 60_000
        let model = AppModel()
        model.received(agents: [agent(bot)], pauses: [pause(nil, until: past), pause(other)])
        XCTAssertNil(model.everyonePaused)
        XCTAssertEqual(model.pauses.map(\.agentId), [other])
        let ended = AgentPauseInfo(everyone: false, sinceMs: 1, untilMs: 5_000)
        XCTAssertNil(Pauses([], now: 10_000).stopping(agent(bot, paused: ended)))
        XCTAssertFalse(Pauses([], now: 10_000).disagrees(with: [agent(bot, paused: ended)]))
        XCTAssertEqual(Pauses([], now: 1_000).stopping(agent(bot, paused: ended)), ended)
    }

    /// The catch-up sync for a disagreement is remembered only once it went
    /// through: a failed one (offline) is tried again at the next poll, one
    /// that worked isn't repeated, and none starts while one runs.
    @MainActor
    func testTheCatchUpSyncIsRetriedUntilItWorks() async {
        let model = AppModel()
        var calls = 0
        var works = false
        model.catchUpSync = {
            calls += 1
            return works
        }
        let elsewhere = [agent(bot, paused: AgentPauseInfo(everyone: false, sinceMs: 1, untilMs: nil))]

        let first = model.received(agents: elsewhere, pauses: [])
        XCTAssertNil(model.received(agents: elsewhere, pauses: []), "one at a time")
        await first?.value
        XCTAssertEqual(calls, 1)
        XCTAssertNil(model.pauseDisagreement, "a failed sync is not remembered")

        await model.received(agents: elsewhere, pauses: [])?.value
        XCTAssertEqual(calls, 2, "tried again at the next poll")

        works = true
        await model.received(agents: elsewhere, pauses: [])?.value
        XCTAssertEqual(calls, 3)
        XCTAssertNotNil(model.pauseDisagreement)
        XCTAssertNil(model.received(agents: elsewhere, pauses: []), "once for each disagreement")
        XCTAssertEqual(calls, 3)

        // Another disagreement syncs again; agreeing forgets it.
        await model.received(agents: elsewhere + [agent(other)], pauses: [pause(other)])?.value
        XCTAssertEqual(calls, 4)
        XCTAssertNil(model.received(agents: [agent(bot)], pauses: []))
        XCTAssertNil(model.pauseDisagreement)
    }

    // MARK: Face ID or the master password

    /// The person chose the password, or Face ID can't be used: the master
    /// password. Cancelling resumes nothing and asks for nothing more.
    func testWhatFaceIDLeavesToTheMasterPassword() {
        for code: LAError.Code in [.userFallback, .biometryNotAvailable, .biometryNotEnrolled, .biometryLockout,
                                   .passcodeNotSet] {
            XCTAssertEqual(ResumePresence.outcome(code), .needsPassword, "\(code)")
        }
        for code: LAError.Code? in [.userCancel, .systemCancel, .appCancel, .authenticationFailed, nil] {
            XCTAssertEqual(ResumePresence.outcome(code), .cancelled, "\(String(describing: code))")
        }
    }

    /// The words say what «Resume» will ask for: the master password
    /// whenever Face ID can't be used now, never «Face ID» then.
    func testTheResumeWordsFollowWhatItAsks() {
        XCTAssertEqual(ResumePresence.ask(biometrics: true, type: .faceID), .faceID)
        XCTAssertEqual(ResumePresence.ask(biometrics: true, type: .touchID), .touchID)
        // No biometry, not set up or locked out: canEvaluatePolicy is false.
        for type: LABiometryType in [.faceID, .touchID, .none] {
            XCTAssertEqual(ResumePresence.ask(biometrics: false, type: type), .password, "\(type.rawValue)")
        }
        XCTAssertEqual(ResumePresence.howTo(.faceID), "To resume, use Face ID.")
        XCTAssertEqual(ResumePresence.howTo(.touchID), "To resume, use Touch ID.")
        XCTAssertEqual(ResumePresence.howTo(.password), "To resume, enter your master password.")
    }

    // MARK: The log

    func testTheFiltersBecomeTheLogsQuery() {
        var filter = ActivityFilter(item: "i1")
        XCTAssertTrue(filter.filtering)
        filter.text = "  github "
        filter.permissions = ["totp", "fill"]
        filter.outcomes = ["deny"]
        filter.agent = bot
        filter.alertsOnly = true
        let input = filter.input()
        XCTAssertEqual(input.text, "github")
        XCTAssertEqual(input.permissions, ["fill", "totp"])
        XCTAssertEqual(input.outcomes, ["deny"])
        XCTAssertEqual(input.item, "i1")
        XCTAssertEqual(input.agent, bot)
        XCTAssertTrue(input.alerts)
        XCTAssertNil(input.sinceMs, "any time")
        XCTAssertEqual(input.limit, ActivityFilter.limit)
        filter.text = "   "
        XCTAssertNil(filter.input().text)
        // The period starts the log that many days back, or at midnight.
        let now = Date(timeIntervalSince1970: 1_000_000)
        filter.period = .week
        XCTAssertEqual(filter.input(now: now).sinceMs, (1_000_000 - 7 * 86_400) * 1000)
        filter.period = .today
        XCTAssertEqual(filter.input(now: now).sinceMs,
                       Int64(Calendar.current.startOfDay(for: now).timeIntervalSince1970 * 1000))
        XCTAssertEqual(ActivityPeriod.allCases.map(\.label), ["Any time", "Today", "Last 7 days", "Last 30 days"])
        filter.text = ""
        filter.alertsOnly = false
        filter.permissions = []
        filter.outcomes = []
        filter.item = nil
        filter.agent = nil
        XCTAssertTrue(filter.filtering, "a period alone is a filter")
        filter.clear()
        XCTAssertFalse(filter.filtering)
        XCTAssertEqual(filter, ActivityFilter())
    }

    /// `byAgent` tells who wrote an event: the person's pause of an agent
    /// names the agent but is the person's, whatever the agent is called.
    func testWhoDidItComesFromByAgentNotTheName() {
        let use = entry(actor: "you", byAgent: true, agentId: bot)
        XCTAssertTrue(ActivityWords.isAgent(use))
        XCTAssertEqual(ActivityWords.actor(use), "you", "an agent may call itself you")
        let paused = entry(actor: "you", byAgent: false, agentId: bot, action: "agents.paused", permission: nil)
        XCTAssertFalse(ActivityWords.isAgent(paused))
        XCTAssertEqual(ActivityWords.actor(paused), "You")
        XCTAssertEqual(ActivityWords.yours(paused), "You paused an agent")
        XCTAssertEqual(ActivityWords.yours(entry(actor: "you", byAgent: false, agentId: nil, action: "agents.resumed",
                                                 permission: nil)), "You resumed every agent")
        // A klavd older than byAgent: an actor other than you is an agent.
        XCTAssertTrue(ActivityWords.isAgent(entry(actor: "bot", byAgent: false, agentId: bot)))
        XCTAssertFalse(ActivityWords.isAgent(entry(actor: "you", byAgent: false, agentId: nil, action: "item.updated")))
    }

    func testTheLogGoesByDay() {
        // Noon today: a minute earlier is still today.
        let noon = Calendar.current.startOfDay(for: Date()).addingTimeInterval(12 * 3600)
        let now = Int64(noon.timeIntervalSince1970 * 1000)
        let day: Int64 = 86_400_000
        let days = ActivityWords.days([entry(actor: "bot", byAgent: true, agentId: bot, at: now, seq: 3),
                                       entry(actor: "bot", byAgent: true, agentId: bot, at: now - 1, seq: 2),
                                       entry(actor: "bot", byAgent: true, agentId: bot, at: now - 3 * day, seq: 1)])
        XCTAssertEqual(days.map(\.0.isEmpty), [false, false])
        XCTAssertEqual(days.first?.0, "Today")
        XCTAssertEqual(days.map { $0.1.map(\.seq) }, [[3, 2], [1]])
    }

    func testTheChainLine() {
        XCTAssertEqual(ChainWords.title(nil), "The log")
        XCTAssertEqual(ChainWords.title(AuditStatusInfo(events: 9, verified: nil, unverified: 9)),
                       "This iPhone hasn’t verified the log yet")
        XCTAssertEqual(ChainWords.title(AuditStatusInfo(events: 9, verified: 9, unverified: 0)),
                       "Verified up to event #9")
        XCTAssertEqual(ChainWords.title(AuditStatusInfo(events: 12, verified: 9, unverified: 3)),
                       "Verified up to event #9 · 3 not verified yet")
        XCTAssertTrue(ChainWords.verified(AuditStatusInfo(events: 9, verified: 9, unverified: 0)))
        XCTAssertFalse(ChainWords.verified(AuditStatusInfo(events: 12, verified: 9, unverified: 3)))
        let report = VerifyInfo(events: 12, agentSignatures: 4, accountSignatures: 6, heads: 2, signedHead: 12,
                                warnings: ["The head of laptop is behind."], unpinned: nil)
        XCTAssertEqual(ActivityWords.checked(report),
                       "Checked 12 events, 10 signatures and 2 heads of your devices. The head of laptop is behind.")
        let one = VerifyInfo(events: 1, agentSignatures: 0, accountSignatures: 1, heads: 1, signedHead: 1,
                             warnings: [], unpinned: nil)
        XCTAssertEqual(ActivityWords.checked(one), "Checked 1 event, 1 signature and 1 head of your devices.")
        // Why there was no head to hold the chain against comes as a code
        // (klav-ffi drops klav-client's English), said first and in the
        // interface's language.
        let first = VerifyInfo(events: 12, agentSignatures: 4, accountSignatures: 6, heads: 0, signedHead: 12,
                               warnings: ["agent 0192 is no longer listed"], unpinned: .missing)
        XCTAssertEqual(ActivityWords.warnings(first).count, 2)
        XCTAssertTrue(ActivityWords.warnings(first)[0].hasPrefix("This device hadn’t verified the log before"))
        XCTAssertEqual(ActivityWords.warnings(first)[1], "agent 0192 is no longer listed")
        XCTAssertTrue(ActivityWords.unpinned(.unreadable).hasPrefix("The head this device pinned can’t be read"))
        XCTAssertTrue(ActivityWords.unpinned(.otherAccount).hasPrefix("The head this device pinned belongs to another account"))
    }

    func testAnAgentInWords() {
        XCTAssertEqual(AgentWords.status("active"), "Has access")
        XCTAssertEqual(AgentWords.status("pending"), "Waiting")
        XCTAssertEqual(AgentWords.status("revoked"), "Revoked")
        let now = Date(timeIntervalSince1970: 100)
        XCTAssertTrue(ActivityWords.seen(agent(bot), now: now).hasPrefix("Not used yet · added "))
        XCTAssertTrue(ActivityWords.seen(agent(bot, lastSeen: 99_000), now: now).hasPrefix("Last used just now · added "))
        XCTAssertTrue(ActivityWords.seen(agent(bot, status: "pending"), now: now).hasPrefix("Asked on "))
        // Asked on March 1, approved ten days later: one with access was
        // added when approved; a revoked or denied one says when it asked.
        let asked: Int64 = 1_772_366_400_000
        let approved = asked + 10 * 86_400_000
        XCTAssertNotEqual(ActivityWords.date(asked), ActivityWords.date(approved))
        XCTAssertEqual(ActivityWords.seen(agent(bot, createdAt: asked, approvedMs: approved), now: now),
                       "Not used yet · added \(ActivityWords.date(approved))")
        for status in ["revoked", "denied"] {
            XCTAssertEqual(ActivityWords.seen(agent(bot, status: status, createdAt: asked, approvedMs: approved), now: now),
                           "Asked on \(ActivityWords.date(asked))", status)
        }
    }

    // MARK: Spanish

    private func spanish(_ key: String) -> String {
        guard let path = Bundle.main.path(forResource: "es", ofType: "lproj"), let bundle = Bundle(path: path) else {
            return "no es.lproj"
        }
        return bundle.localizedString(forKey: key, value: "MISSING", table: nil)
    }

    func testAgentsAndActivitySpeakSpanish() {
        XCTAssertEqual(spanish("Agents"), "Agentes")
        XCTAssertEqual(spanish("Pause agents"), "Pausar agentes")
        XCTAssertEqual(spanish("Resume"), "Reanudar")
        XCTAssertEqual(spanish("Use the master password"), "Usar la contraseña maestra")
        XCTAssertEqual(spanish("Every use by an agent and every decision of yours"),
                       "Cada uso de un agente y cada decisión tuya")
        // What resuming asks for, as what the person does.
        XCTAssertEqual(spanish("To resume, use Face ID."), "Para reanudar, usa Face ID.")
        XCTAssertEqual(spanish("To resume, use Touch ID."), "Para reanudar, usa Touch ID.")
        XCTAssertEqual(spanish("To resume, enter your master password."),
                       "Para reanudar, escribe tu contraseña maestra.")
        // Times without an article, right for every hour: never «a las 1:31».
        XCTAssertEqual(String.localizedStringWithFormat(spanish("Ends at %@"), "1:31"), "Termina: 1:31")
        XCTAssertEqual(String.localizedStringWithFormat(spanish("Since %@ · until you resume"), "1:05"),
                       "Desde 1:05 · hasta que reanudes")
        XCTAssertEqual(String.localizedStringWithFormat(spanish("Since %@ · until %@, %lld min left"), "0:31", "1:31", 1),
                       "De 0:31 a 1:31 · falta 1 min")
        XCTAssertEqual(String.localizedStringWithFormat(spanish("Since %@ · until %@, %lld min left"), "10:31", "11:31", 47),
                       "De 10:31 a 11:31 · faltan 47 min")
        // «Verify now» counts, each with its plural.
        let checked = "Checked %lld events, %lld signatures and %lld heads of your devices."
        XCTAssertEqual(String.localizedStringWithFormat(spanish(checked), 1, 3, 1),
                       "Revisé 1 evento, 3 firmas y 1 cabeza de tus dispositivos.")
        XCTAssertEqual(String.localizedStringWithFormat(spanish(checked), 12, 1, 2),
                       "Revisé 12 eventos, 1 firma y 2 cabezas de tus dispositivos.")
        XCTAssertEqual(spanish("This iPhone hasn’t verified the log yet"), "Este iPhone aún no ha verificado la bitácora")
        XCTAssertEqual(spanish("Who used it"), "Quién lo usó")
        // The person's sentence in the second person, never «Tú pausó».
        XCTAssertEqual(spanish("You paused an agent"), "Pausaste un agente")
        XCTAssertEqual(spanish("You gave an agent access"), "Diste acceso a un agente")
        XCTAssertEqual(spanish("%@ (according to the agent)"), "%@ (según el agente)")
        // The Mac's marker, apart from the reason so that it is never cut.
        XCTAssertEqual(spanish("(according to the agent)"), "(según el agente)")
        for key in ["Stops every agent of your account at once, everywhere, until the time is up or you resume. Pausing asks nothing.",
                    "Enter your master password to let agents use Klav again.",
                    "Showing the newest %lld. For the rest: klav log --agent in the terminal.",
                    "Who used it shows when this iPhone can reach the server.",
                    "When an agent asks to join your account, you compare its words and approve it here with Face ID. In the agent’s terminal: klav agent register --name <name>",
                    "Verifying checks every signature in the chain and signs where this iPhone got to, so the server can’t rewrite what it already saw.",
                    "Every use of an item by an agent, and every decision of yours, is written in the account’s audit log. The server can’t change an event without this iPhone noticing."] {
            XCTAssertNotEqual(spanish(key), "MISSING", key)
            XCTAssertNotEqual(spanish(key), key, key)
        }
    }
}
