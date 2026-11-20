import XCTest
@testable import Klav

/// Development (ADR 0033): the pause, the activity, the checks on a
/// registration and what the app reads from `klav client` and `klav skill`.
/// Over the sample engine and canned JSON: no klavd, no real home.
@MainActor
final class DevelopmentTests: XCTestCase {
    private func settle(until done: @escaping @MainActor () -> Bool) async throws {
        for _ in 0..<100 where !done() {
            try await Task.sleep(for: .milliseconds(30))
        }
        XCTAssertTrue(done(), "timed out")
    }

    // MARK: Pause (§7)

    /// Pausing asks nothing; resuming goes through presence, and without
    /// Touch ID asks for the master password first.
    func testPausingAsksNothingAndResumingAsksForPresence() async throws {
        let model = MacModel.sample(SampleEngine(locked: false, touchID: false))
        model.refresh()
        try await settle { model.phase == .unlocked }
        XCTAssertNil(model.everyonePaused)

        try await model.pauseAgents(minutes: 60)
        try await settle { model.everyonePaused != nil }
        let pause = try XCTUnwrap(model.everyonePaused)
        XCTAssertNil(model.passwordPrompt, "pausing asks nothing")
        XCTAssertEqual(minutesUntil(try XCTUnwrap(pause.untilMs)), 60)

        try await model.resumeAgents()
        let prompt = try XCTUnwrap(model.passwordPrompt, "no Touch ID: the password")
        XCTAssertNotNil(model.everyonePaused, "nothing resumed before the password")
        try await prompt.retry("sample")
        model.refresh()
        try await settle { model.everyonePaused == nil }
    }

    func testAnAgentsOwnPauseIsNotEveryones() async throws {
        let model = MacModel.sample(SampleEngine(locked: false, touchID: true))
        model.refresh()
        try await settle { model.phase == .unlocked }
        try await model.pauseAgents(agentId: "ag1", minutes: nil)
        try await settle { model.pause(ofAgent: "ag1") != nil }
        XCTAssertNil(model.everyonePaused)
        XCTAssertNil(model.pause(ofAgent: "ag1")?.untilMs, "until the person resumes")
        let agents = try await model.run { try $0.devAgents() }
        let paused = try XCTUnwrap(agents.first { $0.agent.id == "ag1" }?.paused)
        XCTAssertFalse(paused.everyone)
        XCTAssertNil(agents.first { $0.agent.id == "ag2" }?.paused)
    }

    // MARK: Registrations (E2.2, §3.1)

    func testTheCardSaysWhenTheNameWasDeniedBefore() async throws {
        let model = MacModel.sample(SampleEngine(locked: false, touchID: true))
        model.loadRequests()
        try await settle { !model.registrations.isEmpty }
        let pending = try XCTUnwrap(model.registrations.first { $0.name == "claude-code" })
        let warning = try XCTUnwrap(model.sameName(as: pending))
        XCTAssertTrue(warning.contains("denied"), warning)
        let other = try XCTUnwrap(model.knownAgents["ag1"])
        XCTAssertNil(model.sameName(as: other), "no other deploy-bot")
    }

    /// The words compare by themselves only for a registration this app
    /// launched, with the words its own `klav` printed (P5).
    func testOnlyARegistrationThisAppLaunchedComparesItself() async throws {
        let model = MacModel.sample(SampleEngine(locked: false, touchID: true))
        model.loadRequests()
        try await settle { !model.registrations.isEmpty }
        let pending = try XCTUnwrap(model.registrations.first)
        XCTAssertNil(model.launchedMatch(pending), "not launched here: compared by eye")
        model.launchedRegistrations[pending.id] = LaunchedRegistration(name: pending.name, words: pending.pairingWords)
        XCTAssertEqual(model.launchedMatch(pending), true)
        model.launchedRegistrations[pending.id] = LaunchedRegistration(name: pending.name,
                                                                       words: "other words entirely here now six")
        XCTAssertEqual(model.launchedMatch(pending), false)
    }

    // MARK: Activity (§8)

    func testActivityFiltersAndWhoUsedIt() async throws {
        let model = MacModel.sample(SampleEngine(locked: false, touchID: true))
        var filter = LogFilterInput.all()
        filter.outcomes = ["deny"]
        let denied = try await model.run { [filter] in try $0.auditLog(filter: filter) }
        XCTAssertFalse(denied.isEmpty)
        XCTAssertTrue(denied.allSatisfy { $0.outcome == "deny" })

        let github = try await model.run { try $0.itemActivity(item: "i-gh") }
        XCTAssertTrue(github.uses.allSatisfy { $0.entry.agentId != nil }, "only the agents' events")
        let lease = try XCTUnwrap(github.uses.first { $0.how == .approvedFor })
        XCTAssertEqual(ActivityWords.how(lease), "Approved for 15 min")

        let status = try await model.run { try $0.auditStatus() }
        XCTAssertGreaterThan(status.unverified, 0)
        _ = try await model.run { try $0.verifyAudit() }
        let after = try await model.run { try $0.auditStatus() }
        XCTAssertEqual(after.unverified, 0)
    }

    /// The agent's words go in one line, without controls or bidi marks
    /// (T136).
    func testAgentWordsAreShownInOneLine() {
        XCTAssertEqual(ActivityWords.shown("Deploy\nthe \u{202E}stack\u{0007}"), "Deploy the stack")
        XCTAssertEqual(ActivityWords.shown(String(repeating: "a", count: 200), max: 10).count, 10)
    }

    // MARK: What `klav` answers

    func testClientListDecodes() throws {
        let json = """
        {"checked":"2026-11-05","clients":[
          {"id":"claude-code","name":"Claude Code","state":"not_connected","installed":"/h/.claude",
           "config":{"path":"/h/.claude.json","exists":true,"key":"mcpServers.klav"},"method":null,
           "agent":{"name":"claude-code","registered_here":false},"managed":{},"restart_required":false,
           "skills_dir":"/h/.claude/skills","note":"Klav writes Claude Code only with its `claude` command"},
          {"id":"cursor","name":"Cursor","state":"person","config":{"path":"/h/.cursor/mcp.json","exists":true,
           "key":"mcpServers.klav"},"method":"file","entry":{"command":"/usr/local/bin/klav","args":["mcp"]},
           "managed":{"notes":["a team list"]},"restart_required":false,"skills_dir":"/h/.agents/skills",
           "unknown_command":true}
        ]}
        """
        let rows = try JSONDecoder().decode(ClientList.self, from: Data(json.utf8)).clients
        XCTAssertEqual(rows.map(\.id), ["claude-code", "cursor"])
        XCTAssertFalse(rows[0].canConnect, "no method: its CLI is not on PATH")
        XCTAssertTrue(rows[1].canConnect)
        XCTAssertEqual(rows[1].stateText.0, "Has a klav entry Klav didn’t write")
    }

    func testTheSummaryShowsKlavsEntryAlone() throws {
        let json = """
        {"client":"codex","dry_run":true,"agent":{"name":"codex","status":"new","registers":true},
         "mcp":{"action":"add","owner":"none","method":"file","file":"/h/.codex/config.toml","key":"mcp_servers.klav",
          "before":null,"after":{"command":"/Applications/Klav.app/Contents/Helpers/klav","args":["mcp","--agent","codex"]},
          "file_sha256":"e3b0","expect_sha256":"e3b0","backup":"/k/client-backups/codex","restart_required":false},
         "skill":[{"path":"/h/.agents/skills/klav/SKILL.md","action":"install","version":"0.2.0"}]}
        """
        let plan = try JSONDecoder().decode(ConnectPlan.self, from: Data(json.utf8))
        let mcp = try XCTUnwrap(plan.mcp)
        XCTAssertEqual(mcp.expectSha256, "e3b0")
        XCTAssertNil(mcp.before)
        XCTAssertEqual(mcp.after?.pretty(), """
        {
          "args": ["mcp", "--agent", "codex"],
          "command": "/Applications/Klav.app/Contents/Helpers/klav"
        }
        """)
        XCTAssertEqual(plan.agent?.registers, true)
        XCTAssertNil(plan.agent?.words, "a dry run registers nothing")
    }

    func testSkillStatusFindsEachCopysFolder() throws {
        let json = """
        {"bundled":{"version":"0.2.0","sha256":"3a0a"},"copies":[
          {"path":"/h/.agents/skills/klav/SKILL.md","state":"edited","version":"0.2.0","clients":["codex","cursor"]}
        ]}
        """
        let status = try JSONDecoder().decode(SkillStatus.self, from: Data(json.utf8))
        XCTAssertEqual(status.copies.first?.folder, "/h/.agents/skills")
        XCTAssertEqual(status.copies.first?.stateText.1, true, "an edited copy is a warning")
    }

    func testKlavsErrorLosesItsPrefix() {
        XCTAssertEqual(ClientTools.message("klav: no Klav account on this device\n", status: 2),
                       "no Klav account on this device")
        XCTAssertEqual(ClientTools.message("", status: 5), "klav ended with code 5.")
    }

    // MARK: Review of PR #230

    private func plan(agent: String) throws -> ConnectPlan {
        try JSONDecoder().decode(ConnectPlan.self,
                                 from: Data(#"{"client":"codex","dry_run":false,"agent":\#(agent),"skill":[]}"#.utf8))
    }

    /// P5 by the path «Connect» takes after writing (`ConnectSheet.finish`
    /// calls `connected`): the words are kept only for an agent this
    /// command registered, with helpers signed by Klav's team.
    func testOnlyARegistrationThisCommandMadeWithKlavsSignatureIsKept() async throws {
        let model = MacModel.sample(SampleEngine(locked: false, touchID: true))
        let new = try plan(agent: #"{"name":"codex","id":"ag-new","status":"pending","words":"a b c d e f","registers":true}"#)
        XCTAssertFalse(model.connected(new, client: "Codex", verdict: .development), "a Debug build compares by eye")
        XCTAssertNil(model.launchedRegistrations["ag-new"])
        XCTAssertEqual(model.section, .requests, "Requests opens anyway")

        model.section = .clients
        let existing = try plan(agent: #"{"name":"codex","id":"ag-old","status":"pending","words":"a b c d e f","registers":false}"#)
        XCTAssertFalse(model.connected(existing, client: "Codex", verdict: .trusted))
        XCTAssertNil(model.launchedRegistrations["ag-old"], "an agent that was already here: by eye")
        XCTAssertEqual(model.section, .clients)

        XCTAssertTrue(model.connected(new, client: "Codex", verdict: .trusted))
        XCTAssertEqual(model.launchedRegistrations["ag-new"], LaunchedRegistration(name: "codex", words: "a b c d e f"))
        XCTAssertEqual(model.section, .requests)
    }

    /// «They match: approve» follows the words this Mac's klav printed
    /// (the function the button uses).
    func testApprovingIsOffWhenTheWordsDontMatch() async throws {
        let model = MacModel.sample(SampleEngine(locked: false, touchID: true))
        model.loadRequests()
        try await settle { !model.registrations.isEmpty }
        let pending = try XCTUnwrap(model.registrations.first)
        model.launchedRegistrations[pending.id] = LaunchedRegistration(name: pending.name, words: "not the same six words at all")
        XCTAssertFalse(AgentApproval.allowed(busy: false, chosen: 1, matched: model.launchedMatch(pending)))
        model.launchedRegistrations[pending.id] = LaunchedRegistration(name: pending.name, words: pending.pairingWords)
        XCTAssertTrue(AgentApproval.allowed(busy: false, chosen: 1, matched: model.launchedMatch(pending)))
        XCTAssertTrue(AgentApproval.allowed(busy: false, chosen: 1, matched: nil), "compared by eye")
        XCTAssertFalse(AgentApproval.allowed(busy: false, chosen: 0, matched: true), "no project comes chosen (P4)")
        XCTAssertFalse(AgentApproval.allowed(busy: true, chosen: 1, matched: true))
    }

    /// The summary of «Connect» promises the comparison only when it
    /// will happen (E2.2: an agent that connected by itself is compared
    /// by eye).
    func testTheSummaryPromisesTheComparisonOnlyWhenItHappens() throws {
        let decode = { (json: String) in try JSONDecoder().decode(PlanAgent.self, from: Data(json.utf8)) }
        let registered = try decode(#"{"name":"claude-code","id":"ag3","status":"registered","words":"a b c d e f","registers":false}"#)
        let here = ConnectWords.agent(registered, verdict: .trusted)
        XCTAssertTrue(here.contains("by eye"), here)
        XCTAssertFalse(here.contains("compares the words for you"), here)
        let new = try decode(#"{"name":"codex","status":"new","registers":true}"#)
        XCTAssertTrue(ConnectWords.agent(new, verdict: .trusted).contains("compares the words for you"))
        let debug = ConnectWords.agent(new, verdict: .development)
        XCTAssertFalse(debug.contains("compares the words for you"), debug)
        XCTAssertTrue(debug.contains("by eye"), debug)
    }

    func testTheCardSaysWhenAnotherOneWithTheNameWaitsOrThisMacRegisteredAnother() async throws {
        let model = MacModel.sample(SampleEngine(locked: false, touchID: true))
        model.loadRequests()
        try await settle { model.knownAgents["ag3"] != nil }
        let second = AgentItem(id: "ag9-second", name: "claude-code", note: nil, status: "pending", pairingWords: "x",
                               createdAt: 0, expiresAt: 0, projects: [])
        let waiting = try XCTUnwrap(model.sameName(as: second))
        XCTAssertTrue(waiting.contains("waiting too") && waiting.contains("ag3"), waiting)

        let pending = try XCTUnwrap(model.knownAgents["ag3"])
        model.launchedRegistrations["ag7-mine"] = LaunchedRegistration(name: "claude-code", words: "y")
        let other = try XCTUnwrap(model.sameName(as: pending))
        XCTAssertTrue(other.contains("This Mac registered another") && other.contains("ag7-mine") && other.contains("ag3"),
                      other)
        XCTAssertEqual(AgentText.idPrefix("3f2a9c01-aaaa-bbbb"), "3f2a9c01")
    }

    /// A pause that holds on this Mac only says so, and locked it offers
    /// to unlock to pause everywhere (§7.2, §7.3). The menu bar's
    /// `PauseLine` and `PauseBar` show these words.
    func testALocalPauseSaysItHoldsOnThisMac() {
        let local = PauseInfo(agentId: nil, sinceMs: 0, untilMs: nil, local: true, serverUnsupported: false)
        let everywhere = PauseInfo(agentId: nil, sinceMs: 0, untilMs: nil, local: false, serverUnsupported: false)
        let old = PauseInfo(agentId: nil, sinceMs: 0, untilMs: nil, local: false, serverUnsupported: true)
        XCTAssertEqual(PauseWords.title(everywhere), "Every agent is paused")
        XCTAssertEqual(PauseWords.title(local), "Every agent is paused on this Mac")
        XCTAssertEqual(PauseWords.title(old), "Every agent is paused on this Mac")
        XCTAssertTrue(PauseWords.whereItHolds(local, locked: true)?.contains("unlock to pause everywhere") == true)
        XCTAssertFalse(PauseWords.whereItHolds(local, locked: false)?.contains("unlock to pause everywhere") == true)
        XCTAssertTrue(PauseWords.offersUnlock(local, locked: true))
        XCTAssertFalse(PauseWords.offersUnlock(local, locked: false))
        XCTAssertFalse(PauseWords.offersUnlock(old, locked: true), "unlocking won't reach a server without pauses")
        XCTAssertNil(PauseWords.whereItHolds(everywhere, locked: true))
    }

    /// Signing in shows the «Agents» step even when the poll lands between
    /// signing in and klavd's unlock (the sample waits 0.6 s to unlock), and
    /// the window stays on the setup under the sheet meanwhile.
    func testTheAgentsStepComesAfterSigningInEvenThroughLocked() async throws {
        let model = MacModel.sample(SampleEngine(locked: false, touchID: true, signedOut: true))
        model.refresh()
        try await settle { model.phase == .signedOut }
        XCTAssertTrue(model.showsSetup)
        model.accountSheetOpen = true
        let made = Task {
            try await model.makeAccount(signUp: false, server: "https://klav.test", email: "ana@example.com",
                                        password: "sample", secretKey: "K1-SAMPLE", deviceName: "Mac",
                                        stepDecided: false)
        }
        try await settle { model.refresh(); return model.phase == .locked }
        XCTAssertTrue(model.showsSetup, "locked under the sheet: still «Set up this Mac»")
        _ = try await made.value
        XCTAssertTrue(model.agentsStepPending)
        model.accountSheetOpen = false
        model.refresh()
        try await settle { model.phase == .unlocked }
        XCTAssertTrue(model.showsSetup, "the «Agents» step comes next")

        let decided = MacModel.sample(SampleEngine(locked: false, touchID: true, signedOut: true))
        _ = try await decided.makeAccount(signUp: false, server: "https://klav.test", email: "ana@example.com",
                                          password: "sample", secretKey: "K1-SAMPLE", deviceName: "Mac",
                                          stepDecided: true)
        XCTAssertFalse(decided.agentsStepPending, "once decided, it doesn't come back")
    }

    private let clientsJSON = """
    {"checked":"2026-11-05","clients":[
      {"id":"claude-code","name":"Claude Code","state":"changed","installed":"/h/.claude",
       "config":{"path":"/h/.claude.json","exists":true,"key":"mcpServers.klav"},"method":"cli",
       "cli":"/opt/homebrew/bin/claude","managed":{},"restart_required":false,"skills_dir":"/h/.claude/skills"},
      {"id":"codex","name":"Codex","state":"not_installed","method":null,"managed":{},"restart_required":false,
       "skills_dir":"/h/.agents/skills"},
      {"id":"cursor","name":"Cursor","state":"connected","installed":"/h/.cursor",
       "config":{"path":"/h/.cursor/mcp.json","exists":true,"key":"mcpServers.klav"},"method":"file",
       "managed":{},"restart_required":false,"skills_dir":"/h/.agents/skills","unknown_command":true}
    ]}
    """

    /// The «Agents» step counts only the clients installed here.
    func testTheAgentsStepCountsOnlyInstalledClients() throws {
        let rows = try JSONDecoder().decode(ClientList.self, from: Data(clientsJSON.utf8)).clients
        XCTAssertEqual(rows[0].cli, "/opt/homebrew/bin/claude", "the claude the summary names")
        let folders = AgentsStep.folders(rows)
        XCTAssertEqual(folders.map(\.folder), ["/h/.claude/skills", "/h/.agents/skills"])
        XCTAssertEqual(folders[1].clients.map(\.id), ["cursor"], "Codex isn't installed")

        let none = try JSONDecoder().decode(ClientList.self, from: Data("""
        {"clients":[{"id":"codex","name":"Codex","state":"not_installed","method":null,"restart_required":false,
         "skills_dir":"/h/.agents/skills"}]}
        """.utf8)).clients
        XCTAssertTrue(AgentsStep.folders(none).isEmpty)
    }

    /// What changed outside Klav is said in red (§4, §6); a copy kept as
    /// the person edited it is not, and «Leave it» lasts until the app
    /// starts again.
    func testWhatChangedOutsideKlavIsSaid() throws {
        let rows = try JSONDecoder().decode(ClientList.self, from: Data(clientsJSON.utf8)).clients
        let skill = try JSONDecoder().decode(SkillStatus.self, from: Data("""
        {"bundled":{"version":"0.3.0","sha256":"aa"},"copies":[
          {"path":"/h/.claude/skills/klav/SKILL.md","state":"edited","version":"0.2.0"},
          {"path":"/h/.agents/skills/klav/SKILL.md","state":"edited","version":"0.2.0","kept_mine":"0.3.0"}
        ]}
        """.utf8))
        let kept = skill.copies[1]
        XCTAssertEqual(kept.keptMine, "0.3.0")
        XCTAssertEqual(kept.stateText(bundled: "0.3.0").0, "Kept as you edited it")
        XCTAssertFalse(kept.stateText(bundled: "0.3.0").1, "not red")
        XCTAssertTrue(skill.copies[0].stateText(bundled: "0.3.0").1)

        let warnings = ClientWarning.from(clients: rows, skill: skill)
        XCTAssertEqual(warnings.map(\.kind), [.entryChanged, .unknownCommand, .skillEdited])
        XCTAssertEqual(warnings.map(\.target), ["claude-code", "cursor", "/h/.claude/skills/klav/SKILL.md"])

        let model = MacModel.sample(SampleEngine(locked: false, touchID: true))
        model.setClientWarnings(clients: rows, skill: skill)
        model.leave(warnings[0])
        XCTAssertEqual(model.shownWarnings.map(\.kind), [.unknownCommand, .skillEdited])
        model.see(warnings[2])
        XCTAssertEqual(model.section, .clients)
        XCTAssertEqual(model.skillToShow, "/h/.claude/skills/klav/SKILL.md")
    }

    func testTheSkillsChangesLineByLine() {
        let lines = LineDiff.lines(from: "a\nmine\nc", to: "a\nb\nc\nd")
        XCTAssertEqual(lines.map { $0.0 }, [.same, .removed, .added, .same, .added])
        XCTAssertEqual(lines.map { $0.1 }, ["a", "mine", "b", "c", "d"])
    }

    /// The site is the agent's word (§8.2).
    func testTheSiteIsMarkedAsTheAgents() {
        let entry = LogEntryInfo(seq: 1, atMs: 0, actor: "cursor", byAgent: true, agentId: "ag1", action: "agent.access",
                                 permission: "fill", outcome: "allow", item: nil, itemId: nil, vault: nil,
                                 reason: nil, domain: "github.com", taskId: nil, approvalId: nil, untilMs: nil,
                                 attachments: 0, alerts: [], verified: true)
        XCTAssertEqual(ActivityWords.did(entry), "filled it in on “github.com” (according to the agent)")
    }
}
