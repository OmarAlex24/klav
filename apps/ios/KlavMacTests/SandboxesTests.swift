import XCTest
@testable import Klav

/// Development › Sandboxes (ADR 0036 E2, E4): what the pane reads from
/// `sandbox_list_flagged` and what revoking says. Over the sample's
/// fixtures (`SandboxSamples`) and the sample engine: no klavd, no proxy.
@MainActor
final class SandboxesTests: XCTestCase {
    private let now = Int64(Date().timeIntervalSince1970 * 1000)
    private let m: Int64 = 60_000, h: Int64 = 3_600_000

    private func board(_ scenario: String, everyonePaused: Bool = false, seen: Set<String> = []) -> SandboxBoard {
        SandboxBoard(list: SandboxSamples.list(scenario, now: now), now: now, everyonePaused: everyonePaused,
                     seenThefts: seen)
    }

    private func row(_ board: SandboxBoard, _ label: String) throws -> SandboxInfo {
        try XCTUnwrap(board.list.sandboxes.first { $0.label == label }, label)
    }

    private func replacing(_ list: SandboxListInfo, rows: [SandboxInfo]) -> SandboxListInfo {
        SandboxListInfo(proxy: list.proxy, sandboxes: rows, verifiedEvents: list.verifiedEvents + 1,
                        warnings: list.warnings, marksUnreadable: list.marksUnreadable, security: list.security)
    }

    private func settle(until done: @escaping @MainActor () -> Bool) async throws {
        for _ in 0..<100 where !done() {
            try await Task.sleep(for: .milliseconds(30))
        }
        XCTAssertTrue(done(), "timed out")
    }

    private func unlockedModel(_ engine: SampleEngine = SampleEngine(locked: false, touchID: true)) async throws -> MacModel {
        let model = MacModel.sample(engine)
        model.refresh()
        try await settle { model.phase == .unlocked }
        await model.loadSandboxes(maxAge: 0)
        XCTAssertNotNil(model.sandboxList)
        return model
    }

    // MARK: The proxy

    /// No proxy set: only the header, with what is lost and how to set one,
    /// never an empty list.
    func testWithoutAProxyOnlyTheHeaderShows() {
        let b = board("none")
        XCTAssertTrue(b.noProxy)
        XCTAssertFalse(b.showsList, "no empty list")
        XCTAssertTrue(b.revokeAll.isEmpty)
        XCTAssertFalse(b.paused)
    }

    func testAQuietProxySaysForHowLong() throws {
        let b = board("quiet")
        let proxy = try XCTUnwrap(b.proxy)
        let (line, tone) = SandboxWords.heartbeat(proxy, paused: false, now: now)
        XCTAssertEqual(tone, .quiet, "quiet is not a security warning")
        XCTAssertEqual(line, String(localized: "No signs from the proxy for \(SandboxWords.span(3 * h))"))
        XCTAssertTrue(line.contains("3 h"), line)
        let active = try row(b, "chat-123")
        XCTAssertEqual(SandboxWords.connection(active, proxy: proxy, paused: false, now: now), line,
                       "a quiet proxy's «Connected» isn't trusted")
        XCTAssertEqual(SandboxWords.proxyName(proxy), String(localized: "“\("proxy-fly")”"))
        XCTAssertTrue(b.showsList)
        XCTAssertFalse(b.everyProxysRows)
    }

    func testALiveProxySaysItsHeartbeatsAge() throws {
        let proxy = try XCTUnwrap(board("all").proxy)
        let (line, tone) = SandboxWords.heartbeat(proxy, paused: false, now: now)
        XCTAssertEqual(tone, .quiet)
        XCTAssertEqual(line, String(localized: "Last heartbeat \(SandboxWords.ago(2 * m)), according to the proxy."))
        let active = try row(board("all"), "chat-123")
        XCTAssertEqual(SandboxWords.connection(active, proxy: proxy, paused: false, now: now),
                       String(localized: "Connected, according to the proxy"))
    }

    /// A heartbeat that went back is a security warning, never a quiet
    /// proxy, and it isn't said twice (decision of 2026-11-16).
    func testARolledBackHeartbeatIsASecurityWarning() throws {
        let b = board("rollback")
        let proxy = try XCTUnwrap(b.proxy)
        XCTAssertEqual(proxy.noSigns, .rollback)
        let (line, tone) = SandboxWords.heartbeat(proxy, paused: false, now: now)
        XCTAssertEqual(tone, .alert)
        XCTAssertEqual(line, String(localized: "Security warning: the server sent an older heartbeat of the proxy than this Mac already accepted, so it may be holding the latest one back. The list comes from the verified log and is right; the proxy’s state isn’t known."))
        XCTAssertEqual(b.list.warnings.count, 1)
        XCTAssertTrue(b.warnings.isEmpty, "the header already says it")
        // Even paused, it stays a warning.
        XCTAssertEqual(SandboxWords.heartbeat(proxy, paused: true, now: now).1, .alert)
        // Only that exact line goes: another warning, even one that talks
        // of an older heartbeat, still shows.
        var list = b.list
        list.warnings += ["something else", "an older heartbeat of another proxy"]
        XCTAssertEqual(SandboxBoard(list: list, now: now, everyonePaused: false, seenThefts: []).warnings,
                       ["something else", "an older heartbeat of another proxy"])
        // Without a rollback the line isn't taken away.
        var quiet = SandboxSamples.list("quiet", now: now)
        quiet.warnings = [SandboxBoard.rollbackWarning]
        XCTAssertEqual(SandboxBoard(list: quiet, now: now, everyonePaused: false, seenThefts: []).warnings,
                       [SandboxBoard.rollbackWarning])
        XCTAssertTrue(b.showsList)
        XCTAssertFalse(b.live.isEmpty)
    }

    // MARK: The security flag

    /// An agent wrote the preferences: a security problem apart from the
    /// warnings, every proxy's rows, and no «Revoke all» (it is one
    /// proxy's).
    func testTheSecurityFlagListsEveryProxysRows() throws {
        let b = board("flagged")
        let security = try XCTUnwrap(b.security)
        XCTAssertNil(b.proxy)
        XCTAssertFalse(b.noProxy, "not the plain «No proxy»")
        XCTAssertTrue(b.everyProxysRows)
        XCTAssertTrue(b.showsList)
        XCTAssertTrue(b.warnings.isEmpty, "the flag is not a warning")
        XCTAssertTrue(b.revokeAll.isEmpty)
        XCTAssertEqual(Set(b.live.map(\.proxyId)), [SandboxSamples.proxy, SandboxSamples.oldProxy])
        let words = SandboxWords.security(security, everyProxy: b.everyProxysRows)
        XCTAssertTrue(words.contains(SandboxWords.idPrefix(SandboxSamples.writer)), words)
        XCTAssertTrue(words.hasSuffix(String(localized: "Until then the list shows every proxy’s sandboxes.")), words)
        XCTAssertFalse(words.contains("wrote the account's preferences"), "the core's message isn't shown raw")

        // Without a proxy no heartbeat speaks for a row.
        for row in b.live {
            XCTAssertNil(SandboxWords.connection(row, proxy: nil, paused: false, now: now), row.label)
        }

        let unknown = SandboxWords.security(.unknown(message: "a new\nproblem"), everyProxy: false)
        XCTAssertTrue(unknown.contains("a new problem"), unknown)
        XCTAssertFalse(unknown.contains("every proxy"), unknown)
    }

    // MARK: Theft signals

    func testATheftSignalIsOnTopUntilAnswered() throws {
        let b = board("all")
        let theft = try row(b, "chat-118")
        XCTAssertEqual(b.thefts.map(\.sandboxId), [theft.sandboxId])
        XCTAssertFalse(b.ended.contains { $0.sandboxId == theft.sandboxId }, "not folded away")
        XCTAssertFalse(b.live.contains { $0.sandboxId == theft.sandboxId })
        XCTAssertEqual(SandboxWords.state(theft, paused: false, now: now).2, .alert)

        let answered = board("all", seen: [theft.sandboxId])
        XCTAssertTrue(answered.thefts.isEmpty)
        XCTAssertTrue(answered.ended.contains { $0.sandboxId == theft.sandboxId }, "moves to «Ended»")
        // Even with no proxy left, a theft signal shows.
        var list = SandboxSamples.list("none", now: now)
        list.sandboxes = [theft]
        XCTAssertTrue(SandboxBoard(list: list, now: now, everyonePaused: false, seenThefts: []).showsList)
    }

    func testTheMenuBarShowsTheftsUntilGotIt() async throws {
        let model = try await unlockedModel()
        XCTAssertEqual(model.shownThefts.map(\.label), ["chat-118"])
        let id = try XCTUnwrap(model.shownThefts.first?.sandboxId)
        model.gotIt(theft: id)
        XCTAssertTrue(model.shownThefts.isEmpty)
        model.openSandboxes()
        XCTAssertEqual(model.section, .sandboxes)
    }

    // MARK: States

    func testEachStateHasItsWords() throws {
        let b = board("all")
        XCTAssertEqual(b.live.map(\.label),
                       ["chat-124", "chat-125", "nightly-deps", "chat-123", "chat-117", "fix-flaky-tests"])

        let fresh = SandboxWords.state(try row(b, "chat-124"), paused: false, now: now)
        XCTAssertEqual(fresh.0, String(localized: "Waiting to be claimed"))
        XCTAssertNil(fresh.1)
        let late = SandboxWords.state(try row(b, "nightly-deps"), paused: false, now: now)
        XCTAssertEqual(late.0, String(localized: "Waiting to be claimed"))
        XCTAssertEqual(late.1, String(localized: "Nobody has claimed it yet: the sandbox may not have started."))

        let active = SandboxWords.state(try row(b, "chat-123"), paused: false, now: now)
        XCTAssertEqual(active.0, String(localized: "Active"))
        XCTAssertEqual(active.2, .agent)

        let revoking = try row(b, "chat-117")
        let r = SandboxWords.state(revoking, paused: false, now: now)
        XCTAssertEqual(r.0, String(localized: "Revoking…"))
        XCTAssertEqual(r.1, String(localized: "Revoked on the server; the proxy hasn’t confirmed it yet."), "4 min unconfirmed")
        XCTAssertFalse(SandboxBoard.revocable(revoking), "no second «Revoke»")

        let expired = SandboxWords.state(try row(b, "chat-105"), paused: false, now: now)
        XCTAssertEqual(expired.0, String(localized: "Expired"))
        XCTAssertNotNil(expired.1)

        let disconnected = try row(b, "fix-flaky-tests")
        XCTAssertEqual(SandboxWords.connection(disconnected, proxy: b.proxy, paused: false, now: now),
                       String(localized: "No connection for \(SandboxWords.span(20 * m)), according to the proxy"))
        XCTAssertNil(SandboxWords.connection(try row(b, "chat-124"), proxy: b.proxy, paused: false, now: now),
                     "waiting: no connection to speak of")

        XCTAssertEqual(Set(b.revokeAll.map(\.label)), ["chat-124", "chat-125", "nightly-deps", "chat-123", "fix-flaky-tests"])
    }

    /// A state this version doesn't know is live and revocable, never
    /// left out nor taken as ended.
    func testAnUnknownStateIsLive() throws {
        let b = board("all")
        let unknown = try row(b, "chat-125")
        XCTAssertEqual(unknown.status, .unknown)
        XCTAssertTrue(b.live.contains { $0.sandboxId == unknown.sandboxId })
        XCTAssertFalse(b.ended.contains { $0.sandboxId == unknown.sandboxId })
        XCTAssertTrue(SandboxBoard.revocable(unknown))
        let (state, note, _) = SandboxWords.state(unknown, paused: false, now: now)
        XCTAssertEqual(state, String(localized: "Unknown state"))
        XCTAssertEqual(note, String(localized: "A state this version of Klav doesn’t know: it counts as live. Update Klav."))
        XCTAssertEqual(SandboxWords.ended(.unknown), SandboxWords.ended(nil))
    }

    /// The last 24 hours, newest first, each with why it ended.
    func testEndedInTheLastDaySaysWhy() throws {
        let b = board("all")
        // By when each ended (or expired: chat-105, 30 min ago), newest first.
        XCTAssertEqual(b.ended.map(\.label), ["chat-105", "chat-112", "chat-109", "lint-bot", "chat-110", "old-runner"])
        XCTAssertFalse(b.ended.contains { $0.label == "chat-101" }, "30 h ago: gone")
        XCTAssertEqual(b.ended.map(\.endReason), [nil, .stop, .person, .inactivity, .released, .issuerRemoved])
        XCTAssertEqual(SandboxWords.ended(.stop), String(localized: "The issuer stopped it"))
        XCTAssertEqual(SandboxWords.ended(.person), String(localized: "You revoked it"))
        XCTAssertEqual(SandboxWords.ended(.released), String(localized: "The sandbox let it go when it shut down"))
        XCTAssertEqual(SandboxWords.ended(.inactivity), String(localized: "An hour without a connection"))
        XCTAssertEqual(SandboxWords.ended(.issuerRemoved), String(localized: "You removed or revoked its issuer"))
        XCTAssertEqual(SandboxWords.ended(.personLocal), String(localized: "You revoked it on this Mac"))
        XCTAssertEqual(SandboxWords.ended(.ttl), String(localized: "It expired"))
    }

    // MARK: Pause

    func testInPauseNoSandboxCanUseTheProxy() throws {
        let b = board("paused")
        XCTAssertTrue(b.paused)
        let proxy = try XCTUnwrap(b.proxy)
        let (line, tone) = SandboxWords.heartbeat(proxy, paused: b.paused, now: now)
        XCTAssertEqual(line, String(localized: "Paused: the proxy keeps what it can’t log and sends it when agents resume."))
        XCTAssertEqual(tone, .agent, "a paused proxy is quiet on purpose")
        let revoking = try row(b, "chat-117")
        XCTAssertEqual(SandboxWords.state(revoking, paused: true, now: now).1,
                       String(localized: "Paused: the proxy confirms it when agents resume."))
        XCTAssertNil(SandboxWords.connection(try row(b, "chat-123"), proxy: proxy, paused: true, now: now))

        // Every agent paused on this Mac pauses the pane too, whatever the
        // proxy's own heartbeat says.
        XCTAssertFalse(board("all").paused)
        XCTAssertTrue(board("all", everyonePaused: true).paused)
    }

    // MARK: Revoking

    func testRevokingARowTurnsItToRevoking() async throws {
        let engine = SampleEngine(locked: false, touchID: true)
        let model = try await unlockedModel(engine)
        let target = try XCTUnwrap(model.sandboxBoard?.live.first { $0.label == "chat-123" })
        let words = try await model.revokeSandbox(target)
        XCTAssertEqual(words, String(localized: "Revoked on the server: it gets no access from now on. It says “Revoking…” until the proxy confirms it stopped."))
        XCTAssertEqual(engine.sandboxRevokeCalls, ["\(SandboxSamples.proxy) \(target.sandboxId)"])
        let after = try XCTUnwrap(model.sandboxBoard?.live.first { $0.sandboxId == target.sandboxId })
        XCTAssertEqual(after.status, .revoking, "read again after revoking")
        XCTAssertNil(model.passwordPrompt, "revoking asks nothing")
    }

    func testRevokingAllCoversTheProxysLiveRows() async throws {
        let engine = SampleEngine(locked: false, touchID: true)
        let model = try await unlockedModel(engine)
        let board = try XCTUnwrap(model.sandboxBoard)
        let covered = board.revokeAll.count
        XCTAssertEqual(covered, 5)
        let words = try await model.revokeAllSandboxes(proxyId: try XCTUnwrap(board.proxy).agentId)
        XCTAssertEqual(words, String(localized: "Revoked \(covered) sandboxes on the server: they get no access from now on. Each says “Revoking…” until the proxy confirms it stopped."))
        XCTAssertEqual(engine.sandboxRevokeCalls, ["\(SandboxSamples.proxy) all"])
        XCTAssertTrue(try XCTUnwrap(model.sandboxBoard).revokeAll.isEmpty)
        XCTAssertEqual(try XCTUnwrap(model.sandboxBoard).live.filter { $0.status == .revoking }.count, covered + 1)
    }

    func testNotAppliedSaysSo() async throws {
        let engine = SampleEngine(locked: false, touchID: true)
        let model = try await unlockedModel(engine)
        engine.revokeNotApplied = true
        let target = try XCTUnwrap(model.sandboxBoard?.live.first { $0.label == "chat-123" })
        let one = try await model.revokeSandbox(target)
        XCTAssertEqual(one, String(localized: "Not applied: the server already has a later revocation of this sandbox, signed ahead of this Mac’s clock. If it covers it, the row says “Revoking…”."))
        XCTAssertEqual(model.sandboxBoard?.live.first { $0.sandboxId == target.sandboxId }?.status, .active,
                       "nothing changed here")
        let all = try await model.revokeAllSandboxes(proxyId: SandboxSamples.proxy)
        XCTAssertEqual(all, String(localized: "Not applied: the server already has a later revocation of all of them, signed ahead of this Mac’s clock. The sandboxes it covers say “Revoking…”; those issued after it aren’t covered."))
        XCTAssertEqual(SandboxWords.revoked(.revoked(scope: "all", atMs: now, sandboxIds: ["a"])),
                       String(localized: "Revoked 1 sandbox on the server: it gets no access from now on. It says “Revoking…” until the proxy confirms it stopped."))
    }

    func testRevokingWhileLockedSaysToUnlock() async throws {
        let engine = SampleEngine(locked: false, touchID: true)
        let model = try await unlockedModel(engine)
        let target = try XCTUnwrap(model.sandboxBoard?.live.first)
        try engine.lock()
        do {
            _ = try await model.revokeSandbox(target)
            XCTFail("revoked while locked")
        } catch {
            XCTAssertEqual(SandboxWords.failure(error),
                           String(localized: "Unlock Klav to revoke: revoking signs with your account. Nothing was revoked."))
        }
        XCTAssertTrue(engine.sandboxRevokeCalls.isEmpty)
        XCTAssertEqual(SandboxWords.failure(KlavError.Network(message: "offline")), describe(KlavError.Network(message: "offline")))
    }

    /// A read that fails its checks drops the last list, so nothing old
    /// reads as current, and says it as a security problem.
    func testAReadThatFailsItsChecksDropsTheList() async throws {
        let engine = SampleEngine(locked: false, touchID: true)
        let model = try await unlockedModel(engine)
        XCTAssertFalse(model.shownThefts.isEmpty)
        engine.sandboxListFails = KlavError.Security(message: "the log doesn’t verify.")
        await model.loadSandboxes(maxAge: 0)
        XCTAssertNil(model.sandboxList)
        XCTAssertNil(model.sandboxBoard)
        XCTAssertNil(model.sandboxProblem, "not an ordinary notice")
        XCTAssertTrue(model.shownThefts.isEmpty)
        XCTAssertEqual(model.sandboxIntegrity,
                       SandboxIntegrity(text: String(localized: "Klav couldn’t verify the sandbox list, so it doesn’t show the last list it read, which may no longer be true."),
                                        detail: "the log doesn’t verify."))

        engine.sandboxListFails = KlavError.Rollback(message: "older")
        await model.loadSandboxes(maxAge: 0)
        XCTAssertNil(model.sandboxList)
        XCTAssertEqual(model.sandboxIntegrity, SandboxIntegrity(text: String(localized: "The server sent older data than this Mac has already seen, so Klav doesn’t show the sandbox list: it may be an attack or an old backup.")))

        engine.sandboxListFails = nil
        await model.loadSandboxes(maxAge: 0)
        XCTAssertNil(model.sandboxIntegrity)
        XCTAssertNotNil(model.sandboxList)
    }

    /// A check `klav-client` names drops the list the same way, and the
    /// block says which, in the app's words.
    func testANamedCheckDropsTheListAndSaysWhich() async throws {
        let engine = SampleEngine(locked: false, touchID: true)
        let model = try await unlockedModel(engine)
        XCTAssertFalse(model.shownThefts.isEmpty)
        model.say("Revoked.")
        engine.sandboxListRefused = .proxyHeartbeat(agentId: SandboxSamples.proxy)
        await model.loadSandboxes(maxAge: 0)
        XCTAssertNil(model.sandboxList)
        XCTAssertNil(model.sandboxBoard)
        XCTAssertNil(model.sandboxProblem, "not an ordinary notice")
        XCTAssertNil(model.sandboxNotice)
        XCTAssertTrue(model.shownThefts.isEmpty)
        let integrity = try XCTUnwrap(model.sandboxIntegrity)
        XCTAssertEqual(integrity, SandboxWords.integrity(.proxyHeartbeat(agentId: SandboxSamples.proxy), message: "the check's words"))
        XCTAssertTrue(integrity.text.contains(SandboxSamples.proxy))
        XCTAssertNil(integrity.detail, "the app has words for it")

        engine.sandboxListRefused = nil
        await model.loadSandboxes(maxAge: 0)
        XCTAssertNil(model.sandboxIntegrity)
        XCTAssertNotNil(model.sandboxList)
    }

    /// Each check `klav-client` can name today, in English and in Spanish:
    /// a whole sentence, with its period, and the agent where there is one.
    /// One this build doesn't know says only what is sure, and shows
    /// `klav-client`'s words apart.
    func testEachCheckSpeaksBothLanguages() throws {
        let path = { (language: String) in
            try XCTUnwrap(Bundle(for: MacModel.self).path(forResource: language, ofType: "lproj").flatMap(Bundle.init(path:)))
        }
        let en = try path("en"), es = try path("es")
        let agent = SandboxSamples.proxy
        let checks: [(SandboxCheckInfo, String, String)] = [
            (.unlistedProxy(agentId: agent),
             "The account’s proxy setting names agent \(agent), which the server doesn’t list",
             "El ajuste del proxy de la cuenta nombra al agente \(agent), que el servidor no incluye"),
            (.proxyHeartbeat(agentId: agent),
             "The proxy’s heartbeat (agent \(agent)) doesn’t verify",
             "El latido del proxy (agente \(agent)) no se pudo verificar"),
            (.log, "The account’s audit log, as the server sent it, doesn’t verify",
             "La bitácora de la cuenta, tal como la mandó el servidor, no se pudo verificar"),
            (.unknown, "Klav couldn’t verify the sandbox list, so it doesn’t show",
             "Klav no pudo verificar la lista de sandboxes, así que no muestra"),
        ]
        for (check, english, spanish) in checks {
            let inEnglish = SandboxWords.integrity(check, message: "audit log: a newer check", bundle: en)
            let inSpanish = SandboxWords.integrity(check, message: "audit log: a newer check", bundle: es)
            XCTAssertTrue(inEnglish.text.hasPrefix(english), inEnglish.text)
            XCTAssertTrue(inSpanish.text.hasPrefix(spanish), inSpanish.text)
            for words in [inEnglish.text, inSpanish.text] {
                XCTAssertTrue(words.hasSuffix("."), words)
                XCTAssertFalse(words.contains("audit log:"), "klav-client's words stay apart: \(words)")
            }
            XCTAssertTrue(inEnglish.text.hasSuffix("Klav doesn’t show the last list it read, which may no longer be true.")
                          || check == .unknown, inEnglish.text)
            XCTAssertTrue(inSpanish.text.hasSuffix("que puede ya no ser cierta."), inSpanish.text)
            XCTAssertEqual(inEnglish.command, check == .unlistedProxy(agentId: agent), "the terminal sets the proxy again")
            XCTAssertEqual(inSpanish.command, inEnglish.command)
            XCTAssertEqual(inEnglish.detail, check == .unknown ? "audit log: a newer check" : nil)
            XCTAssertEqual(inSpanish.detail, inEnglish.detail)
        }

        // A `klavd` older than `sandbox_list_checked`: the error, its
        // prefix gone, apart from the sentence.
        let older = try XCTUnwrap(SandboxWords.integrity(KlavError.Security(message: "SECURITY: proxy heartbeat: bad nonce"), bundle: es))
        XCTAssertEqual(older.text, "Klav no pudo verificar la lista de sandboxes, así que no muestra la última lista que leyó, que puede ya no ser cierta.")
        XCTAssertEqual(older.detail, "proxy heartbeat: bad nonce")
        XCTAssertFalse(older.command)
        XCTAssertNil(SandboxWords.integrity(KlavError.Security(message: "SECURITY: "))?.detail, "nothing to show apart")
        XCTAssertEqual(es.localizedString(forKey: "What the check said (in English):", value: "∅", table: nil),
                       "Lo que dijo la comprobación (en inglés):")
        let rollback = try XCTUnwrap(SandboxWords.integrity(KlavError.Rollback(message: "older"), bundle: es))
        XCTAssertTrue(rollback.text.hasPrefix("El servidor mandó datos más viejos"), rollback.text)
        XCTAssertNil(rollback.detail)
    }

    /// A plain failure (the network) keeps the last list and says why.
    func testAFailedReadKeepsTheLastList() async throws {
        let engine = SampleEngine(locked: false, touchID: true)
        let model = try await unlockedModel(engine)
        let before = try XCTUnwrap(model.sandboxList)
        engine.sandboxListFails = KlavError.Network(message: "offline")
        await model.loadSandboxes(maxAge: 0)
        XCTAssertEqual(model.sandboxList?.sandboxes.count, before.sandboxes.count)
        XCTAssertNotNil(model.sandboxProblem)
        XCTAssertNil(model.sandboxIntegrity)
        engine.sandboxListFails = nil
        await model.loadSandboxes(maxAge: 30)
        XCTAssertNotNil(model.sandboxProblem, "read less than 30 s ago: not read again")
        await model.loadSandboxes(maxAge: 0)
        XCTAssertNil(model.sandboxProblem)
    }

    // MARK: Ages and reads

    /// The heartbeat's age grows from the read; the footer says when.
    func testAgesGrowFromTheRead() throws {
        let readMs = now - 5 * m
        let live = SandboxBoard(list: SandboxSamples.list("all", now: readMs), now: now, readMs: readMs,
                                everyonePaused: false, seenThefts: [])
        let proxy = try XCTUnwrap(live.proxy)
        XCTAssertEqual(live.heartbeatAge(proxy), 7 * m)
        XCTAssertEqual(SandboxWords.heartbeat(proxy, paused: false, now: now, readMs: readMs).0,
                       String(localized: "Last heartbeat \(SandboxWords.ago(7 * m)), according to the proxy."))
        XCTAssertEqual(SandboxWords.read(readMs, now: now), String(localized: "Read \(SandboxWords.ago(5 * m))"))
        XCTAssertEqual(SandboxWords.read(now, now: now), String(localized: "Read \(String(localized: "just now"))"))

        let quiet = SandboxBoard(list: SandboxSamples.list("quiet", now: readMs), now: now, readMs: readMs,
                                 everyonePaused: false, seenThefts: [])
        let q = try XCTUnwrap(quiet.proxy)
        XCTAssertEqual(SandboxWords.heartbeat(q, paused: false, now: now, readMs: readMs).0,
                       String(localized: "No signs from the proxy for \(SandboxWords.span(3 * h + 5 * m))"))
    }

    /// The read after «Revoke» starts after the answer: a read already
    /// running, with the list from before, doesn't count for it.
    func testTheReadAfterRevokingIsNotTheOneAlreadyRunning() async throws {
        let engine = SampleEngine(locked: false, touchID: true)
        let model = try await unlockedModel(engine)
        let target = try XCTUnwrap(model.sandboxBoard?.live.first { $0.label == "chat-123" })
        XCTAssertEqual(engine.sandboxListCalls, 1)

        let gate = Gate()
        model.sandboxReadHold = { await gate.wait() }
        let early = Task { await model.loadSandboxes(maxAge: 0) }
        try await settle { gate.waiting }                   // it has the list from before
        XCTAssertEqual(engine.sandboxListCalls, 2)

        let revoking = Task { try await model.revokeSandbox(target) }
        try await settle { engine.sandboxRevokeCalls.count == 1 }
        try await Task.sleep(for: .milliseconds(100))
        gate.open()                                         // the early read lands now
        let words = try await revoking.value
        await early.value

        XCTAssertEqual(engine.sandboxListCalls, 3, "one more read after the answer")
        XCTAssertEqual(model.sandboxList?.sandboxes.first { $0.sandboxId == target.sandboxId }?.status, .revoking)
        XCTAssertTrue(words.hasPrefix(String(localized: "Revoked on the server: it gets no access from now on. It says “Revoking…” until the proxy confirms it stopped.").prefix(20)))
        XCTAssertTrue(model.revocationChecks.isEmpty, "the log shows it")
        XCTAssertTrue(model.unregisteredRevocations.isEmpty)
    }

    // MARK: A revocation the server didn't log (E3.3)

    func testARevocationTheLogDoesntShowIsSaidInRed() async throws {
        let engine = SampleEngine(locked: false, touchID: true)
        let model = try await unlockedModel(engine)
        let target = try XCTUnwrap(model.sandboxBoard?.live.first { $0.label == "chat-123" })
        engine.revokeUnlogged = true
        _ = try await model.revokeSandbox(target)
        let missed = try XCTUnwrap(model.unregisteredRevocations.first)
        XCTAssertEqual(model.unregisteredRevocations.count, 1)
        XCTAssertEqual(missed.scope, target.sandboxId)
        XCTAssertEqual(SandboxWords.unregistered(missed),
                       String(localized: "Klav revoked \(SandboxWords.quoted("chat-123")) and the server answered, but the verified log doesn’t have that revocation: it may still have access. Klav checks again on every read. To cut it now, pause agents or revoke the proxy."))
        // Checked again on every read: still missing.
        await model.loadSandboxes(maxAge: 0)
        XCTAssertEqual(model.unregisteredRevocations.count, 1)

        // «Revoke again», and this time the log has it.
        engine.revokeUnlogged = false
        _ = try await model.revokeAgain(missed)
        XCTAssertTrue(model.revocationChecks.isEmpty)
        XCTAssertEqual(engine.sandboxRevokeCalls.count, 2)

        // «Revoke all» the log doesn't show: the same, in its own words.
        engine.revokeUnlogged = true
        _ = try await model.revokeAllSandboxes(proxyId: SandboxSamples.proxy)
        let all = try XCTUnwrap(model.unregisteredRevocations.first)
        XCTAssertEqual(all.scope, RevocationCheck.all)
        XCTAssertTrue(SandboxWords.unregistered(all).hasPrefix(String(localized: "Klav revoked every sandbox of your proxy and the server answered, but the verified log doesn’t have that revocation: they may still have access. Klav checks again on every read. To cut them now, pause agents or revoke the proxy.").prefix(30)))
    }

    /// A «Revoke again» that fails keeps the red block: the old check goes
    /// only when a new answer replaces it.
    func testARevokeAgainThatFailsKeepsTheRedBlock() async throws {
        let engine = SampleEngine(locked: false, touchID: true)
        let model = try await unlockedModel(engine)
        let target = try XCTUnwrap(model.sandboxBoard?.live.first { $0.label == "chat-123" })
        engine.revokeUnlogged = true
        _ = try await model.revokeSandbox(target)
        let missed = try XCTUnwrap(model.unregisteredRevocations.first)

        try engine.lock()
        do {
            _ = try await model.revokeAgain(missed)
            XCTFail("revoked while locked")
        } catch {}
        XCTAssertEqual(model.unregisteredRevocations.map(\.id), [missed.id])

        // «Not applied» covers nothing new either: still red.
        _ = try engine.unlock(password: "sample", shown: nil)
        engine.revokeNotApplied = true
        _ = try await model.revokeAgain(missed)
        XCTAssertEqual(model.unregisteredRevocations.map(\.id), [missed.id])
    }

    /// «Revoke again» on a «Revoke all» opens the «Revoke all» sheet, which
    /// says how many it covers now; nothing is signed yet.
    func testRevokeAgainOnRevokeAllOpensTheSheet() async throws {
        let engine = SampleEngine(locked: false, touchID: true)
        let model = try await unlockedModel(engine)
        engine.revokeUnlogged = true
        _ = try await model.revokeAllSandboxes(proxyId: SandboxSamples.proxy)
        let all = try XCTUnwrap(model.unregisteredRevocations.first)
        XCTAssertEqual(all.scope, RevocationCheck.all)
        XCTAssertFalse(model.revokingAllSandboxes)

        let words = try await model.revokeAgain(all)
        XCTAssertNil(words)
        XCTAssertTrue(model.revokingAllSandboxes)
        XCTAssertEqual(engine.sandboxRevokeCalls.count, 1, "only the first one")
        XCTAssertEqual(model.unregisteredRevocations.map(\.id), [all.id])
        // The list on screen is that proxy's: the sheet says how many.
        XCTAssertEqual(model.revokeAllScope?.proxyId, SandboxSamples.proxy)
        XCTAssertNotNil(model.revokeAllScope?.covered)
    }

    /// «Revoke all» from the toolbar is the list's proxy, with its count.
    func testRevokeAllFromTheListIsTheListsProxy() async throws {
        let model = try await unlockedModel()
        let board = try XCTUnwrap(model.sandboxBoard)
        let scope = try XCTUnwrap(model.revokeAllScope)
        XCTAssertEqual(scope.proxyId, SandboxSamples.proxy)
        XCTAssertEqual(scope.covered?.map(\.sandboxId), board.revokeAll.map(\.sandboxId))
    }

    /// Without a list, «Revoke again» on a «Revoke all» opens a sheet that
    /// can't say how many and still signs, for the check's proxy.
    func testRevokeAllWithoutAListSignsForTheChecksProxy() async throws {
        let engine = SampleEngine(locked: false, touchID: true)
        let model = try await unlockedModel(engine)
        engine.revokeUnlogged = true
        _ = try await model.revokeAllSandboxes(proxyId: SandboxSamples.proxy)
        let all = try XCTUnwrap(model.unregisteredRevocations.first)
        engine.sandboxListFails = KlavError.Security(message: "the log doesn’t verify.")
        await model.loadSandboxes(maxAge: 0)
        XCTAssertNil(model.sandboxBoard)

        _ = try await model.revokeAgain(all)
        let scope = try XCTUnwrap(model.revokeAllScope, "the button has a proxy")
        XCTAssertEqual(scope.proxyId, SandboxSamples.proxy)
        XCTAssertNil(scope.covered, "it can't say how many")
        _ = try await model.confirmRevokeAll()
        XCTAssertEqual(engine.sandboxRevokeCalls.last, "\(SandboxSamples.proxy) all")
        XCTAssertEqual(model.unregisteredRevocations.count, 1, "still red: no read has shown it")
    }

    /// The account's proxy changed while a «Revoke all» was red: «Revoke
    /// again» signs for the old one, never the list's.
    func testRevokeAgainOnRevokeAllUsesTheChecksProxy() async throws {
        let engine = SampleEngine(locked: false, touchID: true)
        let model = try await unlockedModel(engine)
        var old = RevocationCheck(proxyId: SandboxSamples.oldProxy, scope: RevocationCheck.all, label: "",
                                  atMs: model.nowMs - 60_000, sandboxIds: ["x"], afterRead: 0)
        old.missed = true
        model.revocationChecks = [old]

        _ = try await model.revokeAgain(old)
        let scope = try XCTUnwrap(model.revokeAllScope)
        XCTAssertEqual(scope.proxyId, SandboxSamples.oldProxy)
        XCTAssertNil(scope.covered, "the list is another proxy's")
        _ = try await model.confirmRevokeAll()
        XCTAssertEqual(engine.sandboxRevokeCalls, ["\(SandboxSamples.oldProxy) all"])
    }

    /// A «Revoke again» the server takes stays red while the reads after
    /// it fail, and goes once a read shows it.
    func testARevokeAgainStaysRedUntilARead() async throws {
        let engine = SampleEngine(locked: false, touchID: true)
        let model = try await unlockedModel(engine)
        let target = try XCTUnwrap(model.sandboxBoard?.live.first { $0.label == "chat-123" })
        engine.revokeUnlogged = true
        _ = try await model.revokeSandbox(target)
        let missed = try XCTUnwrap(model.unregisteredRevocations.first)

        engine.sandboxListFails = KlavError.Security(message: "the log doesn’t verify.")
        await model.loadSandboxes(maxAge: 0)
        engine.revokeUnlogged = false
        _ = try await model.revokeAgain(missed)
        XCTAssertEqual(engine.sandboxRevokeCalls.count, 2)
        XCTAssertNil(model.sandboxList, "the read after it failed")
        XCTAssertEqual(model.unregisteredRevocations.map(\.scope), [target.sandboxId])
        XCTAssertNil(model.shownSandboxNotice, "the red block speaks for it")

        engine.sandboxListFails = nil
        await model.loadSandboxes(maxAge: 0)
        XCTAssertTrue(model.revocationChecks.isEmpty, "the log shows it")
    }

    /// A notice goes when the list fails its checks, and when Klav locks.
    func testNoticesGoWhenTheyStopBeingTrue() async throws {
        let engine = SampleEngine(locked: false, touchID: true)
        let model = try await unlockedModel(engine)
        model.say("Revoked.")
        engine.sandboxListFails = KlavError.Security(message: "the log doesn’t verify.")
        await model.loadSandboxes(maxAge: 0)
        XCTAssertNil(model.sandboxNotice)

        model.say("Unlock Klav to revoke.", error: true)
        try engine.lock()
        model.refresh()
        try await settle { model.phase == .locked }
        XCTAssertNil(model.sandboxNotice)
    }

    /// A read that can't tell (the rows left the list) keeps a check
    /// already red.
    func testAReadThatCantTellKeepsARedCheck() async throws {
        let engine = SampleEngine(locked: false, touchID: true)
        let model = try await unlockedModel(engine)
        let target = try XCTUnwrap(model.sandboxBoard?.live.first { $0.label == "chat-123" })
        engine.revokeUnlogged = true
        _ = try await model.revokeSandbox(target)
        XCTAssertEqual(model.unregisteredRevocations.count, 1)

        let list = try XCTUnwrap(model.sandboxList)
        engine.setSandboxes(replacing(list, rows: list.sandboxes.filter { $0.sandboxId != target.sandboxId }))
        await model.loadSandboxes(maxAge: 0)
        XCTAssertEqual(model.unregisteredRevocations.count, 1)
    }

    /// The answer stays while the list it speaks of doesn't change, goes
    /// when it changes or on the next action, and gives way to the red
    /// block for its revocation.
    func testTheAnswerStaysUntilTheListChanges() async throws {
        let engine = SampleEngine(locked: false, touchID: true)
        let model = try await unlockedModel(engine)
        let target = try XCTUnwrap(model.sandboxBoard?.live.first { $0.label == "chat-123" })
        let words = try await model.revokeSandbox(target)
        XCTAssertEqual(model.shownSandboxNotice?.text, words)
        XCTAssertEqual(model.shownSandboxNotice?.error, false)

        await model.loadSandboxes(maxAge: 0)
        XCTAssertEqual(model.shownSandboxNotice?.text, words, "the same list")

        let list = try XCTUnwrap(model.sandboxList)
        engine.setSandboxes(replacing(list, rows: list.sandboxes.filter { $0.sandboxId != target.sandboxId }))
        await model.loadSandboxes(maxAge: 0)
        XCTAssertNil(model.shownSandboxNotice, "the list changed")

        model.say("Nothing was revoked.", error: true)
        let other = try XCTUnwrap(model.sandboxBoard?.live.first { SandboxBoard.revocable($0) })
        engine.revokeUnlogged = true
        _ = try await model.revokeSandbox(other)
        XCTAssertNotNil(model.sandboxNotice, "this revocation's answer")
        XCTAssertNotEqual(model.sandboxNotice?.text, "Nothing was revoked.")
        XCTAssertEqual(model.unregisteredRevocations.count, 1)
        XCTAssertNil(model.shownSandboxNotice, "its red block says it instead")
    }

    /// An old reading (the last read failed): the proxy's heartbeat and the
    /// rows' connections don't read as current.
    func testAnOldReadingSaysNoSigns() async throws {
        let engine = SampleEngine(locked: false, touchID: true)
        let model = try await unlockedModel(engine)
        let fresh = try XCTUnwrap(model.sandboxBoard)
        let proxy = try XCTUnwrap(fresh.proxy)
        let live = try row(fresh, "chat-123")
        XCTAssertNotNil(SandboxWords.connection(live, proxy: proxy, paused: false, now: fresh.now, readMs: fresh.readMs))
        XCTAssertNotEqual(SandboxWords.heartbeat(proxy, paused: false, now: fresh.now, readMs: fresh.readMs).0,
                          String(localized: "No signs from the proxy."))

        engine.sandboxListFails = KlavError.Network(message: "offline")
        await model.loadSandboxes(maxAge: 0)
        let old = try XCTUnwrap(model.sandboxBoard)
        XCTAssertTrue(old.stale)
        XCTAssertFalse(fresh.stale)
        let (text, tone) = SandboxWords.heartbeat(proxy, paused: false, now: old.now, readMs: old.readMs, stale: old.stale)
        XCTAssertEqual(text, String(localized: "No signs from the proxy."))
        XCTAssertEqual(tone, .quiet)
        XCTAssertNil(SandboxWords.connection(try row(old, "chat-123"), proxy: old.proxy, paused: false,
                                             now: old.now, readMs: old.readMs, stale: old.stale))

        // A heartbeat that went back stays a security warning.
        let rolled = try XCTUnwrap(SandboxSamples.list("rollback", now: old.now).proxy)
        XCTAssertEqual(SandboxWords.heartbeat(rolled, paused: false, now: old.now, stale: true).1, .alert)

        engine.sandboxListFails = nil
        await model.loadSandboxes(maxAge: 0)
        XCTAssertEqual(model.sandboxBoard?.stale, false)
    }

    /// `klav-client`'s longest integrity message fits whole.
    func testALongIntegrityMessageIsNotCut() throws {
        guard case .Security(let message) = SandboxSamples.integrityFailure else { return XCTFail("not Security") }
        XCTAssertGreaterThan(message.count, 330)
        let integrity = try XCTUnwrap(SandboxWords.integrity(SandboxSamples.integrityFailure))
        XCTAssertEqual(integrity.detail, message, "whole, apart from the sentence")
        XCTAssertFalse(integrity.text.contains(message))
        // What reaches the app has `klavd`'s prefix: the block drops it.
        XCTAssertEqual(SandboxWords.integrity(KlavError.Security(message: "SECURITY: " + message)), integrity)
        let huge = String(repeating: "x", count: 2000)
        XCTAssertLessThan(try XCTUnwrap(SandboxWords.integrity(KlavError.Security(message: huge))?.detail).count, 1000)
    }

    /// Signed out while a read ran: what it read doesn't land.
    func testAReadThatEndsAfterSigningOutIsDropped() async throws {
        let engine = SampleEngine(locked: false, touchID: true)
        let model = try await unlockedModel(engine)
        let gate = Gate()
        model.sandboxReadHold = { await gate.wait() }
        let read = Task { await model.loadSandboxes(maxAge: 0) }
        try await settle { gate.waiting }

        try engine.deleteThisCopy(discardUnsent: true)
        model.refresh()
        try await settle { model.phase == .signedOut }
        XCTAssertNil(model.sandboxList)
        gate.open()
        await read.value
        XCTAssertNil(model.sandboxList)
        XCTAssertNil(model.sandboxBoard)
    }

    /// The account deleted while a read ran: what it read doesn't land.
    func testAReadThatEndsAfterTheAccountIsDeletedIsDropped() async throws {
        let engine = SampleEngine(locked: false, touchID: true)
        let model = try await unlockedModel(engine)
        let gate = Gate()
        model.sandboxReadHold = { await gate.wait() }
        let read = Task { await model.loadSandboxes(maxAge: 0) }
        try await settle { gate.waiting }

        engine.finishDeletion()
        model.refresh()
        try await settle { model.accountDeleted }
        XCTAssertNil(model.sandboxList)
        gate.open()
        await read.value
        XCTAssertNil(model.sandboxList)
    }

    /// The sample switches the captures use.
    func testTheSampleSwitchesForTheCaptures() async throws {
        let engine = SampleEngine(locked: false, touchID: true)
        engine.sandboxScenario = "integrity"
        let model = MacModel.sample(engine)
        model.refresh()
        try await settle { model.phase == .unlocked }
        await model.loadSandboxes(maxAge: 0)
        XCTAssertNil(model.sandboxList)
        XCTAssertEqual(model.sandboxIntegrity,
                       SandboxWords.integrity(.unlistedProxy(agentId: SandboxSamples.proxy), message: SandboxSamples.integrityMessage))
        XCTAssertEqual(model.sandboxIntegrity?.command, true)

        let other = try await unlockedModel()
        other.revocationChecks = [SandboxSamples.unregistered(now: other.nowMs)]
        await other.loadSandboxes(maxAge: 0)
        XCTAssertEqual(other.unregisteredRevocations.map(\.label), ["chat-123"])
    }

    /// Under the flag the rows are every proxy's: «Revoke» names the row's
    /// own proxy.
    func testRevokingUnderTheFlagUsesTheRowsProxy() async throws {
        let engine = SampleEngine(locked: false, touchID: true)
        engine.sandboxScenario = "flagged"
        let model = try await unlockedModel(engine)
        let other = try XCTUnwrap(model.sandboxBoard?.live.first { $0.proxyId == SandboxSamples.oldProxy && SandboxBoard.revocable($0) })
        _ = try await model.revokeSandbox(other)
        XCTAssertEqual(engine.sandboxRevokeCalls, ["\(SandboxSamples.oldProxy) \(other.sandboxId)"])
        XCTAssertEqual(model.sandboxBoard?.live.first { $0.sandboxId == other.sandboxId }?.status, .revoking)
        XCTAssertTrue(model.revocationChecks.isEmpty)
    }

    // MARK: «Got it», in memory

    /// «Got it» lives in memory: another run of the app shows the signal
    /// again, and an answer for a theft that left the list is forgotten.
    func testGotItIsInMemoryAndForgottenWhenTheTheftLeavesTheList() async throws {
        var list = SandboxSamples.list("all", now: now)
        let first = try XCTUnwrap(list.sandboxes.first { SandboxBoard.isTheft($0) })
        var second = first
        second.sandboxId = "f1" + first.sandboxId.dropFirst(2)
        second.label = "chat-119"
        list.sandboxes.append(second)

        let engine = SampleEngine(locked: false, touchID: true)
        engine.setSandboxes(list)
        let model = MacModel.sample(engine)
        model.refresh()
        try await settle { model.phase == .unlocked }
        await model.loadSandboxes(maxAge: 0)
        XCTAssertEqual(Set(model.shownThefts.map(\.label)), ["chat-118", "chat-119"])

        model.gotIt(theft: first.sandboxId)
        XCTAssertEqual(model.shownThefts.map(\.label), ["chat-119"], "one answered, the other still shown")

        // Another run of the app shows both again: nothing is kept.
        let again = MacModel.sample(engine)
        again.refresh()
        try await settle { again.phase == .unlocked }
        await again.loadSandboxes(maxAge: 0)
        XCTAssertEqual(Set(again.shownThefts.map(\.label)), ["chat-118", "chat-119"])

        // The answered theft is no longer in the list: forgotten.
        list.sandboxes.removeAll { $0.sandboxId == first.sandboxId }
        engine.setSandboxes(list)
        await model.loadSandboxes(maxAge: 0)
        XCTAssertTrue(model.seenThefts.isEmpty)
    }

    // MARK: Words

    func testTheSpanishWordsAreTheGlossarys() throws {
        let es = try XCTUnwrap(Bundle(for: MacModel.self).path(forResource: "es", ofType: "lproj").flatMap(Bundle.init(path:)))
        let words = ["Waiting to be claimed": "Esperando el reclamo", "Revoking…": "Revocando…",
                     "Active sandboxes": "Sandboxes activos", "Revoke all": "Revocar todos",
                     "Theft signal": "Señal de robo", "according to the issuer": "según el emisor",
                     "Credential proxy": "Proxy de credenciales", "“%@”": "«%@»", "It expired": "Venció",
                     "Active sandboxes (all proxies)": "Sandboxes activos (todos los proxies)",
                     "The server didn’t register your revocation": "El servidor no registró tu revocación",
                     "Unlock Klav to revoke: revoking signs with your account. Nothing was revoked.":
                        "Desbloquea Klav para revocar: para revocar, Klav firma con tu cuenta. No se revocó nada.",
                     "%lld h %lld min": "%1$lld h %2$lld min"]
        for (en, spanish) in words {
            XCTAssertEqual(es.localizedString(forKey: en, value: "∅", table: nil), spanish, en)
        }
    }
}

/// Holds a read until the test opens it, on the main actor, without
/// blocking a thread.
@MainActor
private final class Gate {
    private var continuation: CheckedContinuation<Void, Never>?
    private var opened = false
    private(set) var waiting = false

    func wait() async {
        guard !opened else { return }
        waiting = true
        await withCheckedContinuation { continuation = $0 }
    }

    func open() {
        opened = true
        continuation?.resume()
        continuation = nil
    }
}
