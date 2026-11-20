import XCTest
@testable import Klav

/// Revoking an agent and changing its permissions from the Mac (ADR 0033,
/// amendment of 2026-11-10, F8 layer 4), over the sample engine: the review
/// sheet is the lines `klavd` sent, widening asks for presence, a read-only
/// grant offers no editor, and «Done» comes only from a complete key change.
@MainActor
final class AgentGrantsTests: XCTestCase {
    private func settle(until done: @escaping @MainActor () -> Bool) async throws {
        for _ in 0..<150 where !done() {
            try await Task.sleep(for: .milliseconds(30))
        }
        XCTAssertTrue(done(), "timed out")
    }

    private func agentItem(_ model: MacModel, _ id: String) async throws -> AgentItem {
        let agents = try await model.run { try $0.agents() }
        return try XCTUnwrap(agents.first { $0.id == id })
    }

    private func unlocked(_ engine: SampleEngine) async throws -> MacModel {
        let model = MacModel.sample(engine)
        model.refresh()
        try await settle { model.phase == .unlocked }
        return model
    }

    /// deploy-bot with one more project, `delete` on «ask» and `list` on
    /// «deny»: two lines widen, one narrows.
    private func mixedChange(_ model: MacModel) async throws -> (GrantChangeInput, GrantChangePreviewInfo) {
        let grant = try await model.run { try $0.grantEditor(id: "ag1") }
        var draft = GrantDraft(grant)
        draft.projects.insert("p1")
        draft.effects["delete"] = "ask"
        draft.effects["list"] = "deny"
        let change = draft.input(order: grant.projects.map(\.projectId))
        return (change, try await model.prepareGrantChange(agent: "ag1", change: change))
    }

    // MARK: The review sheet (F3)

    func testTheReviewSheetShowsExactlyThePreviewsLines() async throws {
        let model = try await unlocked(SampleEngine(locked: false, touchID: true))
        let (_, preview) = try await mixedChange(model)
        XCTAssertEqual(preview.lines.count, 3)

        let sheet = GrantReview(preview, touchID: true)
        XCTAssertEqual(sheet.rows.count, preview.lines.count)
        for (row, line) in zip(sheet.rows, preview.lines) {
            XCTAssertEqual(row.text, GrantWords.line(line.kind))
            XCTAssertEqual(row.widens, line.widens)
        }
        XCTAssertEqual(sheet.rows.filter(\.widens).count, 2)
        XCTAssertTrue(sheet.rows.contains { $0.text == "+ Personal/General" && $0.widens }, "\(sheet.rows)")
        XCTAssertTrue(sheet.rows.contains { !$0.widens && $0.text.contains("→") }, "\(sheet.rows)")
    }

    /// With `widens`, the sheet says Klav will ask for Touch ID (the master
    /// password on a Mac without it); a change that only narrows says
    /// nothing will be asked.
    func testTheSheetSaysWhenTouchIDWillBeAsked() async throws {
        let model = try await unlocked(SampleEngine(locked: false, touchID: true))
        let (_, wide) = try await mixedChange(model)
        XCTAssertTrue(wide.widens)
        XCTAssertTrue(GrantReview(wide, touchID: true).headline.contains("Touch ID"))
        XCTAssertTrue(GrantReview(wide, touchID: false).headline.contains("master password"))

        let grant = try await model.run { try $0.grantEditor(id: "ag1") }
        var draft = GrantDraft(grant)
        draft.effects["inject"] = "deny"
        let narrow = try await model.prepareGrantChange(agent: "ag1", change: draft.input(order: []))
        XCTAssertFalse(narrow.widens)
        let headline = GrantReview(narrow, touchID: true).headline
        XCTAssertTrue(headline.contains("only narrows"), headline)
        XCTAssertFalse(headline.contains("will ask"), headline)
    }

    /// Widening goes through presence (the master password here); narrowing
    /// signs at once.
    func testOnlyWideningAsksForPresence() async throws {
        let model = try await unlocked(SampleEngine(locked: false, touchID: false))
        let (change, wide) = try await mixedChange(model)
        var signed: GrantChangeReportInfo?
        try await model.applyGrantChange(wide, change: change) { signed = $0 }
        let prompt = try XCTUnwrap(model.passwordPrompt, "widening asks for the master password")
        XCTAssertNil(signed, "nothing signed before the password")
        try await prompt.retry("sample")
        XCTAssertEqual(signed?.complete, true)
        XCTAssertNil(model.passwordPrompt, "a right password closes the prompt by itself")

        let grant = try await model.run { try $0.grantEditor(id: "ag1") }
        XCTAssertEqual(grant.version, 4)
        var draft = GrantDraft(grant)
        draft.projects.remove("p1")
        let narrowChange = draft.input(order: grant.projects.map(\.projectId))
        let narrow = try await model.prepareGrantChange(agent: "ag1", change: narrowChange)
        XCTAssertFalse(narrow.widens)
        XCTAssertEqual(narrow.removedProjects, ["Personal/General"])
        signed = nil
        try await model.applyGrantChange(narrow, change: narrowChange) { signed = $0 }
        XCTAssertNil(model.passwordPrompt, "narrowing asks nothing")
        XCTAssertEqual(signed?.complete, true)
    }

    /// A sheet prepared on an older grant is not signed (T188).
    func testAStaleSheetIsNotSigned() async throws {
        let model = try await unlocked(SampleEngine(locked: false, touchID: true))
        let (change, preview) = try await mixedChange(model)
        // Another change lands first (the terminal, another Mac).
        let grant = try await model.run { try $0.grantEditor(id: "ag1") }
        var other = GrantDraft(grant)
        other.effects["inject"] = "deny"
        let otherChange = other.input(order: [])
        let otherSheet = try await model.prepareGrantChange(agent: "ag1", change: otherChange)
        try await model.applyGrantChange(otherSheet, change: otherChange) { _ in }
        do {
            try await model.applyGrantChange(preview, change: change) { _ in XCTFail("signed a stale sheet") }
            XCTFail("a stale sheet went through")
        } catch KlavError.Security {}
    }

    // MARK: Read-only grants (F3)

    func testAReadOnlyGrantHasNoChangePermissions() async throws {
        let model = try await unlocked(SampleEngine(locked: false, touchID: true))
        let grant = try await model.run { try $0.grantEditor(id: "ag2") }
        XCTAssertFalse(grant.editable, "«Change permissions…» shows only when editable")
        XCTAssertNil(grant.editor)
        XCTAssertEqual(grant.readOnly, .rules)
        XCTAssertFalse(grant.rules.isEmpty, "shown in words all the same")
        let (_, command) = GrantWords.readOnly(.rules, agent: GrantWords.commandAgent(grant.agentId))
        XCTAssertEqual(command, "klav agent approve ag2 --policy-file <file>", "the ID, never the agent's own words")
        XCTAssertEqual(GrantWords.readOnly(.olderKlavd, agent: "x").1, "klav agent approve x")

        let editable = try await model.run { try $0.grantEditor(id: "ag1") }
        XCTAssertTrue(editable.editable)
        XCTAssertEqual(editable.editor?.permissions.map(\.permission), GrantWords.permissions)
    }

    // MARK: Revoking (F2)

    /// Asks `status` until `done`, the way the window does every two seconds.
    private func follow(_ model: MacModel, until done: @escaping @MainActor () -> Bool) async throws {
        for _ in 0..<150 where !done() {
            model.refresh()
            try await Task.sleep(for: .milliseconds(30))
        }
        XCTAssertTrue(done(), "timed out")
    }

    /// «Revoked» comes with the first call, before the key change ends;
    /// «Done» only once `klavd` says nothing is left (P11, T189).
    func testRevokedShowsBeforeTheKeyChangeEndsAndDoneOnlyWhenComplete() async throws {
        let engine = SampleEngine(locked: false, touchID: true)
        let gate = DispatchSemaphore(value: 0)
        engine.rotationGate = gate
        let model = try await unlocked(engine)
        let agent = try await agentItem(model, "ag1")

        try await model.revoke(agent, changeKeys: true)
        let flow = try XCTUnwrap(model.revocationFlows["ag1"])
        XCTAssertEqual(flow.stage, .changingKeys)
        XCTAssertTrue(flow.revoked)
        XCTAssertTrue(flow.background, "klavd changes the keys by itself")
        XCTAssertEqual(engine.revokeCalls, ["ag1 true true"], "one call, written down in klavd before it answers")
        try await follow(model) { model.info?.revocations.first?.running == true }
        let left = model.keysLeft(of: "ag1", listed: [])
        let text = try XCTUnwrap(RevokeWords.state(model.revocationFlows["ag1"], left: left))
        XCTAssertTrue(text.hasPrefix("Revoked"), text)
        XCTAssertFalse(text.contains("Done"), text)
        XCTAssertFalse(RevokeWords.canFinish(model.revocationFlows["ag1"], left: left), "nothing to finish while it runs")
        let status = try await agentItem(model, "ag1").status
        XCTAssertEqual(status, "revoked", "revoked before the keys changed")

        gate.signal()
        try await follow(model) { model.revocationFlows["ag1"]?.stage == .done }
        let done = try XCTUnwrap(RevokeWords.state(model.revocationFlows["ag1"], left: model.keysLeft(of: "ag1", listed: [])))
        XCTAssertTrue(done.contains("Done"), done)
    }

    /// A key change that stops is «keys left» with «Finish», never «Done».
    func testAKeyChangeThatStopsNeverSaysDone() async throws {
        let engine = SampleEngine(locked: false, touchID: true)
        engine.rotationFails = true
        let model = try await unlocked(engine)
        let agent = try await agentItem(model, "ag2")
        try await model.revoke(agent, changeKeys: true)
        try await follow(model) { model.revocationFlows["ag2"]?.stage == .keysLeft }
        let flow = try XCTUnwrap(model.revocationFlows["ag2"])
        XCTAssertNotNil(flow.failed)
        let listed = try await model.run { try $0.agentRevocations() }
        let left = model.keysLeft(of: "ag2", listed: listed)
        XCTAssertEqual(left.map { ($0.rotated, $0.projects) }?.0, 1)
        let text = try XCTUnwrap(RevokeWords.state(flow, left: left))
        XCTAssertEqual(text, "Revoked. Keys left to change (1 of 2)")
        XCTAssertTrue(RevokeWords.canFinish(flow, left: left))

        // «Finish» once the server answers again.
        engine.rotationFails = false
        await model.finishKeys(of: "ag2")
        XCTAssertEqual(model.revocationFlows["ag2"]?.stage, .done)
    }

    /// A `klavd` older than the background key change: the revocation
    /// alone, then the key change in a second call, as before.
    func testAnOlderKlavdRevokesFirstThenChangesTheKeys() async throws {
        let engine = SampleEngine(locked: false, touchID: true)
        engine.olderKlavd = true
        let model = try await unlocked(engine)
        try await model.revoke(try await agentItem(model, "ag1"), changeKeys: true)
        XCTAssertEqual(engine.revokeCalls, ["ag1 true true", "ag1 false false", "ag1 true false"])
        XCTAssertEqual(model.revocationFlows["ag1"]?.stage, .done)
        XCTAssertEqual(model.revocationFlows["ag1"]?.background, false)
    }

    /// After the app restarts there is no flow: «Finish» keeps what the
    /// person chose. Declined (or, from an older `klavd`, no project
    /// counted), no project's key changes; asked, they change (P7, review
    /// of #308, follow-up 1).
    func testFinishWithoutAFlowKeepsThePersonsChoice() async throws {
        let engine = SampleEngine(locked: false, touchID: true)
        let model = try await unlocked(engine)
        let declined = SampleEngine.progress("ag1", name: "deploy-bot", projects: [], rotated: 0, items: 1,
                                             withoutKeyChange: true)
        XCTAssertTrue(RevokeWords.canFinish(nil, left: declined), "«Finish» shows")
        await model.finishKeys(of: "ag1", left: declined)
        XCTAssertFalse(engine.revokeCalls.contains { $0.contains(" true ") }, "\(engine.revokeCalls)")

        model.revocationFlows["ag1"] = nil
        let older = SampleEngine.progress("ag1", name: "deploy-bot", projects: [], rotated: 0, items: 1)
        await model.finishKeys(of: "ag1", left: older)
        XCTAssertFalse(engine.revokeCalls.contains { $0.contains(" true ") }, "\(engine.revokeCalls)")

        let asked = SampleEngine.progress("ag2", name: "ci", projects: ["Personal/General"], rotated: 0)
        await model.finishKeys(of: "ag2", left: asked)
        XCTAssertTrue(engine.revokeCalls.contains("ag2 true false"), "\(engine.revokeCalls)")
    }

    /// With the box unchecked, no call ever changes a project's key: not
    /// the revocation, not «Finish», not the page opening again (P7).
    func testAnUncheckedBoxNeverChangesAProjectsKeys() async throws {
        let engine = SampleEngine(locked: false, touchID: true)
        engine.itemsPendingOnce = ["ag1"]
        let model = try await unlocked(engine)
        try await model.revoke(try await agentItem(model, "ag1"), changeKeys: false)
        XCTAssertEqual(model.revocationFlows["ag1"]?.stage, .keysLeft, "an item granted one by one is left")
        XCTAssertFalse(model.confirmsByItself("ag1", listed: []), "the page does not finish it by itself")
        await model.finishKeys(of: "ag1")
        // Only an item's key changed: «Revoked», never «every key changed».
        XCTAssertEqual(model.revocationFlows["ag1"]?.stage, .revoked)
        let text = RevokeWords.state(model.revocationFlows["ag1"], left: model.keysLeft(of: "ag1", listed: []))
        XCTAssertEqual(text, "Revoked")
        XCTAssertFalse(engine.revokeCalls.contains { $0.contains(" true ") }, "\(engine.revokeCalls)")

        // Checked, on an older `klavd`, with nothing left listed (it finished
        // in the background after an unlock): the page confirms it with one
        // more call.
        let older = SampleEngine(locked: false, touchID: true)
        older.olderKlavd = true
        older.itemsPendingOnce = ["ag2"]
        let other = try await unlocked(older)
        try await other.revoke(try await agentItem(other, "ag2"), changeKeys: true)
        XCTAssertEqual(other.revocationFlows["ag2"]?.stage, .keysLeft)
        XCTAssertTrue(other.confirmsByItself("ag2", listed: []))
    }

    /// A key change that went ahead without the audit log is never «Done»
    /// (T189): `klavd`'s record keeps it, and `status` lists it until a
    /// later step reads the log.
    func testAKeyChangeWithoutTheAuditLogIsNeverDone() async throws {
        let model = try await unlocked(SampleEngine(locked: false, touchID: true))
        var flow = RevocationFlow(agentId: "ag1", stage: .changingKeys, changeKeys: true)
        flow.background = true
        flow.startedAt = Date().addingTimeInterval(-10)
        model.revocationFlows["ag1"] = flow
        var info = try XCTUnwrap(model.info)
        let projects = ["Trabajo/Infra", "Trabajo/Web"]
        info.revocations = [SampleEngine.progress("ag1", name: "deploy-bot", projects: projects, rotated: 2,
                                                  lastError: "reading the audit log: the server did not answer",
                                                  logUnchecked: true)]
        model.followKeyChanges(info, askedAt: Date())
        let stopped = try XCTUnwrap(model.revocationFlows["ag1"])
        XCTAssertEqual(stopped.stage, .keysLeft)
        XCTAssertTrue(stopped.failed?.contains("audit log") == true)
        let left = info.revocations[0]
        let text = try XCTUnwrap(RevokeWords.state(stopped, left: left))
        XCTAssertTrue(text.contains("audit log"), text)
        XCTAssertTrue(RevokeWords.canFinish(stopped, left: left))

        // A `status` asked before the revocation says nothing about it.
        flow.startedAt = Date()
        model.revocationFlows["ag1"] = flow
        model.followKeyChanges(info, askedAt: flow.startedAt.addingTimeInterval(-1))
        XCTAssertEqual(model.revocationFlows["ag1"]?.stage, .changingKeys)
    }

    /// «Done» takes two unlocked reads in a row without the agent: one read
    /// alone may come before `klavd` read its record at an unlock.
    func testOneReadWithoutTheAgentIsNotDone() async throws {
        let model = try await unlocked(SampleEngine(locked: false, touchID: true))
        var flow = RevocationFlow(agentId: "ag1", stage: .changingKeys, changeKeys: true)
        flow.background = true
        flow.startedAt = Date().addingTimeInterval(-10)
        model.revocationFlows["ag1"] = flow
        var info = try XCTUnwrap(model.info)
        info.revocations = []
        model.followKeyChanges(info, askedAt: Date())
        XCTAssertEqual(model.revocationFlows["ag1"]?.stage, .changingKeys, "one read is not enough")
        // Listed again in between: the count starts over.
        var listed = info
        listed.revocations = [SampleEngine.progress("ag1", name: "deploy-bot", projects: ["Trabajo/Infra"], rotated: 0)]
        model.followKeyChanges(listed, askedAt: Date())
        model.followKeyChanges(info, askedAt: Date())
        XCTAssertEqual(model.revocationFlows["ag1"]?.stage, .changingKeys)
        model.followKeyChanges(info, askedAt: Date())
        XCTAssertEqual(model.revocationFlows["ag1"]?.stage, .done)
    }

    /// A record `klavd` can't read says nothing about what is left: never
    /// «Done», whatever `status` lists, and the page says why.
    func testARecordKlavdCantReadIsNeverDone() async throws {
        let engine = SampleEngine(locked: false, touchID: true)
        let model = try await unlocked(engine)
        var flow = RevocationFlow(agentId: "ag1", stage: .changingKeys, changeKeys: true)
        flow.background = true
        flow.startedAt = Date().addingTimeInterval(-10)
        model.revocationFlows["ag1"] = flow
        engine.recordUnreadable = true
        for _ in 0..<3 {
            model.refresh()
            try await Task.sleep(for: .milliseconds(60))
        }
        XCTAssertEqual(model.info?.revocationsUnreadable, true)
        let stopped = try XCTUnwrap(model.revocationFlows["ag1"])
        XCTAssertEqual(stopped.stage, .keysLeft)
        XCTAssertTrue(stopped.failed?.contains("klav agent show ag1") == true, stopped.failed ?? "nil")
        let (_, listed) = try await model.agentsAndRevocations()
        XCTAssertTrue(listed.isEmpty)
    }

    /// Over as far as Klav can reach (a vault or project gone): the words
    /// say so, never «every key changed», and «Finish» has nothing to do.
    func testSkippedProjectsNeverReadAsEveryKeyChanged() async throws {
        let model = try await unlocked(SampleEngine(locked: false, touchID: true))
        var flow = RevocationFlow(agentId: "ag1", stage: .changingKeys, changeKeys: true)
        flow.background = true
        flow.startedAt = Date().addingTimeInterval(-10)
        model.revocationFlows["ag1"] = flow
        var info = try XCTUnwrap(model.info)
        let left = SampleEngine.progress("ag1", name: "deploy-bot", projects: ["Trabajo/Infra", "Old/Infra"], rotated: 1,
                                         skipped: ["Old/Infra: its vault is deleted"])
        XCTAssertFalse(left.needsWork)
        info.revocations = [left]
        model.followKeyChanges(info, askedAt: Date())
        let over = try XCTUnwrap(model.revocationFlows["ag1"])
        XCTAssertEqual(over.stage, .done)
        let text = try XCTUnwrap(RevokeWords.state(over, left: left))
        XCTAssertFalse(text.contains("every key changed"), text)
        XCTAssertTrue(text.contains("out of its reach"), text)
        XCTAssertFalse(RevokeWords.canFinish(over, left: left))
        // After a restart (no flow), the same.
        XCTAssertEqual(RevokeWords.state(nil, left: left), text)

        // The vault comes back: not done any more.
        info.revocations = [SampleEngine.progress("ag1", name: "deploy-bot", projects: ["Trabajo/Infra", "Old/Infra"],
                                                  rotated: 1)]
        model.followKeyChanges(info, askedAt: Date())
        XCTAssertEqual(model.revocationFlows["ag1"]?.stage, .keysLeft)
    }

    /// A narrowed grant in force whose key change stopped: the toast says
    /// why, never "some keys didn’t:" followed by nothing (F6).
    func testAStoppedKeyChangeSaysWhyInTheToast() {
        let agent = AgentItem(id: "ag1", name: "deploy-bot", note: nil, status: "active", pairingWords: "",
                              createdAt: 0, expiresAt: 0, projects: [])
        let stopped = GrantChangeReportInfo(agent: agent, rotated: [], regranted: [], notRegranted: [],
                                            failed: "revocations.bin cannot be read", pending: [], skipped: [],
                                            complete: false)
        let text = GrantWords.changed(stopped)
        XCTAssertTrue(text.contains("revocations.bin cannot be read"), text)
        XCTAssertFalse(text.hasSuffix(": "), text)
        let left = GrantChangeReportInfo(agent: agent, rotated: [], regranted: [], notRegranted: [], failed: nil,
                                         pending: ["Trabajo/Infra"], skipped: [], complete: false)
        XCTAssertTrue(GrantWords.changed(left).contains("Trabajo/Infra"))
        let done = GrantChangeReportInfo(agent: agent, rotated: [], regranted: [], notRegranted: [], failed: nil,
                                         pending: [], skipped: [], complete: true)
        XCTAssertEqual(GrantWords.changed(done), String(localized: "Permissions changed."))
    }

    /// A key change that skipped a deleted project leaves no entry once it
    /// ends: the skips it saw stay with the flow, so «Done» never says every
    /// key changed, also after the agent leaves `status` (N5).
    func testADoneThatSkippedNeverSaysEveryKeyChanged() async throws {
        let model = try await unlocked(SampleEngine(locked: false, touchID: true))
        var flow = RevocationFlow(agentId: "ag1", stage: .changingKeys, changeKeys: true)
        flow.background = true
        flow.startedAt = Date().addingTimeInterval(-10)
        model.revocationFlows["ag1"] = flow
        var info = try XCTUnwrap(model.info)
        let left = SampleEngine.progress("ag1", name: "deploy-bot", projects: ["Trabajo/Infra", "Trabajo/Old"], rotated: 1,
                                         skipped: ["Trabajo/Old: the project was deleted"])
        info.revocations = [left]
        model.followKeyChanges(info, askedAt: Date())
        info.revocations = []
        model.followKeyChanges(info, askedAt: Date())
        model.followKeyChanges(info, askedAt: Date())
        let over = try XCTUnwrap(model.revocationFlows["ag1"])
        XCTAssertEqual(over.stage, .done)
        XCTAssertEqual(over.skipped, 1)
        let text = try XCTUnwrap(RevokeWords.state(over, left: nil))
        XCTAssertFalse(text.contains("every key changed"), text)
        XCTAssertTrue(text.contains("out of its reach"), text)

        // From a report («Finish», or an older klavd): the same words.
        var reported = RevocationFlow(agentId: "ag2", stage: .done, changeKeys: true)
        reported.skipped = 2
        let words = try XCTUnwrap(RevokeWords.state(reported, left: nil))
        XCTAssertFalse(words.contains("every key changed"), words)
    }

    /// What the first call couldn't reach (an item this Mac no longer sees)
    /// is kept while `klavd` goes on, and «Done» never says every key
    /// changed (fifth re-check, 6: `revoke`).
    func testTheFirstCallsSkipsOutliveKlavdsSteps() async throws {
        let engine = SampleEngine(locked: false, touchID: true)
        let gate = DispatchSemaphore(value: 0)
        engine.rotationGate = gate
        engine.reportSkips = ["item it1: this device no longer sees it (purged, or the server stopped sending it)"]
        let model = try await unlocked(engine)
        let agent = try await agentItem(model, "ag1")
        try await model.revoke(agent, changeKeys: true)
        XCTAssertEqual(model.revocationFlows["ag1"]?.skipped, 1, "said by the first call")
        gate.signal()
        try await follow(model) { model.revocationFlows["ag1"]?.stage == .done }
        let done = try XCTUnwrap(model.revocationFlows["ag1"])
        XCTAssertEqual(done.skipped, 1)
        let text = try XCTUnwrap(RevokeWords.state(done, left: model.keysLeft(of: "ag1", listed: [])))
        XCTAssertFalse(text.contains("every key changed"), text)
        XCTAssertTrue(text.contains("out of its reach"), text)
    }

    /// «Finish» keeps the larger count: what an earlier call skipped, or
    /// what this report skips (fifth re-check, 6: `finishKeys`).
    func testFinishKeepsTheLargerSkipCount() async throws {
        let engine = SampleEngine(locked: false, touchID: true)
        engine.reportSkips = ["Trabajo/Old: the project was deleted"]
        let model = try await unlocked(engine)
        for (earlier, expected) in [(2, 2), (0, 1)] {
            var flow = RevocationFlow(agentId: "ag1", stage: .keysLeft, changeKeys: true)
            flow.skipped = earlier
            model.revocationFlows["ag1"] = flow
            await model.finishKeys(of: "ag1")
            let over = try XCTUnwrap(model.revocationFlows["ag1"])
            XCTAssertEqual(over.stage, .done)
            XCTAssertEqual(over.skipped, expected, "earlier \(earlier)")
            let text = try XCTUnwrap(RevokeWords.state(over, left: nil))
            XCTAssertFalse(text.contains("every key changed"), text)
        }
    }

    /// `status` ending the key change keeps the larger count too: what the
    /// first call said, or what `klavd` counts (fifth re-check, 6:
    /// `followKeyChanges`).
    func testTheEndInStatusKeepsTheLargerSkipCount() async throws {
        let model = try await unlocked(SampleEngine(locked: false, touchID: true))
        for (earlier, counted, expected) in [(2, 1, 2), (1, 3, 3)] {
            var flow = RevocationFlow(agentId: "ag1", stage: .changingKeys, changeKeys: true)
            flow.background = true
            flow.startedAt = Date().addingTimeInterval(-10)
            flow.skipped = earlier
            model.revocationFlows["ag1"] = flow
            var info = try XCTUnwrap(model.info)
            let skipped = (0..<counted).map { "Trabajo/Old\($0): the project was deleted" }
            let left = SampleEngine.progress("ag1", name: "deploy-bot", projects: ["Trabajo/Infra"] + skipped.map { String($0.prefix(while: { $0 != ":" })) },
                                             rotated: 1, skipped: skipped)
            XCTAssertFalse(left.needsWork)
            info.revocations = [left]
            model.followKeyChanges(info, askedAt: Date())
            let over = try XCTUnwrap(model.revocationFlows["ag1"])
            XCTAssertEqual(over.stage, .done)
            XCTAssertEqual(over.skipped, expected, "earlier \(earlier), counted \(counted)")
        }
    }

    /// Without the key change, only items shared one by one change keys:
    /// one out of reach never reads as «every key», nor as a project gone
    /// (fifth re-check, 1).
    func testARevocationWithoutTheKeyChangeNeverSaysEveryKey() throws {
        let left = SampleEngine.progress("ag1", name: "deploy-bot", projects: [], rotated: 0,
                                         skipped: ["item it1: this device no longer sees it (purged, or the server stopped sending it)"],
                                         withoutKeyChange: true)
        XCTAssertFalse(left.needsWork)
        let flow = RevocationFlow(agentId: "ag1", stage: .revoked, changeKeys: false)
        for state in [RevokeWords.state(flow, left: left), RevokeWords.state(nil, left: left)] {
            let text = try XCTUnwrap(state)
            XCTAssertFalse(text.contains("every key"), text)
            XCTAssertFalse(text.contains("project"), text)
            XCTAssertTrue(text.contains("shared with it one by one"), text)
        }
        XCTAssertFalse(RevokeWords.canFinish(flow, left: left))
    }

    /// An older `klavd` sends no `withoutKeyChange`: a revocation this Mac
    /// asked without the key change, or one with no project to change, never
    /// reads as «every key it can reach» (review of #308, N2).
    func testAnOlderKlavdNeverMakesARevocationClaimEveryKey() throws {
        let left = SampleEngine.progress("ag1", name: "deploy-bot", projects: [], rotated: 0,
                                         skipped: ["item it1: this device no longer sees it (purged, or the server stopped sending it)"])
        XCTAssertFalse(left.withoutKeyChange)
        let without = RevocationFlow(agentId: "ag1", stage: .revoked, changeKeys: false)
        for state in [RevokeWords.state(without, left: left), RevokeWords.state(nil, left: left)] {
            let text = try XCTUnwrap(state)
            XCTAssertFalse(text.contains("every key"), text)
            XCTAssertTrue(text.contains("shared with it one by one"), text)
            XCTAssertFalse(text.contains("tries again"), text)
        }
        // A project to change: the key change was asked, and these words fit.
        let rotating = SampleEngine.progress("ag1", name: "deploy-bot", projects: ["Personal/General"], rotated: 1,
                                             skipped: ["Personal/Old: the project was deleted"])
        let text = try XCTUnwrap(RevokeWords.state(nil, left: rotating))
        XCTAssertTrue(text.contains("every key it can reach"), text)
    }

    /// A record a newer Klav wrote: the page says to update Klav, never to
    /// move the file aside or to look in the terminal, and never «Done» (N2).
    func testARecordFromANewerKlavSaysToUpdate() async throws {
        let engine = SampleEngine(locked: false, touchID: true)
        let model = try await unlocked(engine)
        var flow = RevocationFlow(agentId: "ag1", stage: .changingKeys, changeKeys: true)
        flow.background = true
        flow.startedAt = Date().addingTimeInterval(-10)
        model.revocationFlows["ag1"] = flow
        engine.recordUnreadable = true
        engine.recordNewer = true
        for _ in 0..<3 {
            model.refresh()
            try await Task.sleep(for: .milliseconds(60))
        }
        XCTAssertEqual(model.info?.revocationsNewer, true)
        let stopped = try XCTUnwrap(model.revocationFlows["ag1"])
        XCTAssertEqual(stopped.stage, .keysLeft)
        XCTAssertEqual(stopped.failed, RevokeWords.newerRecord)
        XCTAssertFalse(RevokeWords.newerRecord.contains("aside"))
    }

    /// A key change of projects taken away from an active agent: shown,
    /// never as a revocation, and never with «Finish» (it would revoke).
    func testANarrowingKeyChangeNeverOffersFinish() {
        let left = SampleEngine.progress("ag1", name: "deploy-bot", projects: ["Personal/General"], rotated: 0,
                                         lastError: "changing the key of Personal/General: the server did not answer",
                                         narrowed: true)
        let text = RevokeWords.state(nil, left: left) ?? ""
        XCTAssertFalse(text.hasPrefix("Revoked"), text)
        XCTAssertTrue(text.contains("taken away"), text)
        XCTAssertFalse(RevokeWords.canFinish(nil, left: left))
    }

    /// Unchecking the box revokes without a key change: nothing is left and
    /// nothing says «Done» about keys.
    func testRevokingWithoutTheKeyChangeLeavesNothingPending() async throws {
        let model = try await unlocked(SampleEngine(locked: false, touchID: true))
        let agent = try await agentItem(model, "ag1")
        try await model.revoke(agent, changeKeys: false)
        XCTAssertEqual(model.revocationFlows["ag1"]?.stage, .revoked)
        XCTAssertEqual(RevokeWords.state(model.revocationFlows["ag1"], left: nil), "Revoked")
        let pending = try await model.run { try $0.agentRevocations() }
        XCTAssertTrue(pending.isEmpty)
    }

    /// The list and the agent's page say what `klavd` has left; locked, it
    /// keeps counting without names (status).
    func testKeysLeftShowInTheListAlsoWhileLocked() async throws {
        let engine = SampleEngine(locked: false, touchID: true, keysLeft: true)
        let model = try await unlocked(engine)
        let left = try XCTUnwrap(model.keysLeft(of: "ag4", listed: []))
        XCTAssertEqual(RevokeWords.state(nil, left: left), "Revoked. Keys left to change (2 of 3)")
        XCTAssertEqual(left.name, "old-scraper")

        try engine.lock()
        model.refresh()
        try await settle { model.phase == .locked }
        let counted = try XCTUnwrap(model.info?.revocations.first)
        XCTAssertNil(counted.name, "no names while locked")
        XCTAssertNil(counted.lastError)
        XCTAssertEqual(counted.projects, 3)
    }

    /// P12: revoking with Klav locked revokes nothing, and «Revoke…»
    /// opens again after unlocking.
    func testRevokeWhileLockedOpensAgainAfterUnlocking() async throws {
        let engine = SampleEngine(locked: false, touchID: true)
        let model = try await unlocked(engine)
        let agent = try await agentItem(model, "ag1")
        try engine.lock()
        do {
            try await model.revoke(agent, changeKeys: true)
            XCTFail("revoked while locked")
        } catch KlavError.Locked {}
        XCTAssertNil(model.revocationFlows["ag1"], "nothing revoked")
        XCTAssertEqual(model.revokeAfterUnlock, "ag1")
        try await settle { model.phase == .locked }

        try engine.unlock(password: nil)
        model.refresh()
        try await settle { model.phase == .unlocked }
        XCTAssertEqual(model.revoking?.agentId, "ag1")
        XCTAssertEqual(model.openAgent, "ag1")
        XCTAssertEqual(model.section, .agents)
        XCTAssertNil(model.revokeAfterUnlock)
    }

    /// Locking closes «Revoke…» before it revoked, and it opens again after
    /// unlocking; the editor closes with what was changed in it.
    func testLockingClosesTheSheetsAndRevokeComesBack() async throws {
        let engine = SampleEngine(locked: false, touchID: true)
        let model = try await unlocked(engine)
        model.revoking = RevokeRequest(agentId: "ag2")
        model.changingGrant = GrantChangeRequest(agentId: "ag1")
        try engine.lock()
        model.refresh()
        try await settle { model.phase == .locked }
        XCTAssertNil(model.revoking)
        XCTAssertNil(model.changingGrant)
        XCTAssertEqual(model.revokeAfterUnlock, "ag2")
    }

    // MARK: What the sheets say when Klav can't read something

    /// «Revoke…» when Klav can't say what the agent saw: the agent from
    /// the list, its projects unknown, the key change offered, and revoking
    /// still goes ahead with it.
    func testRevokeStaysWhenWhatItSawCantBeRead() async throws {
        let engine = SampleEngine(locked: false, touchID: true)
        engine.exposureFails = true
        let model = try await unlocked(engine)
        let seen = try await model.exposureUnknown(of: "ag1", because: KlavError.Network(message: "the server did not answer"))
        XCTAssertEqual(seen.agent.name, "deploy-bot")
        XCTAssertTrue(seen.projectsUnknown)
        XCTAssertTrue(RevokeWords.offersKeyChange(seen))
        XCTAssertNotNil(seen.logWarning)
        do {
            _ = try await model.exposureUnknown(of: "nobody", because: KlavError.NotFound(message: "nobody"))
            XCTFail("an agent not in the list")
        } catch KlavError.NotFound {}

        // Revoking goes ahead, with the key change, all the same.
        try await model.revoke(seen.agent, changeKeys: true)
        XCTAssertEqual(model.revocationFlows["ag1"]?.revoked, true)
        let status = try await agentItem(model, "ag1").status
        XCTAssertEqual(status, "revoked")
        XCTAssertEqual(engine.revokeCalls, ["ag1 true true"])
    }

    /// An item granted one by one whose key did not change stays in
    /// `klavd`'s record: once the projects are done, `status` still lists
    /// it, and the page says so instead of «Done» (T189).
    func testItemsLeftKeepABackgroundKeyChangeFromDone() async throws {
        let engine = SampleEngine(locked: false, touchID: true)
        engine.itemsPendingOnce = ["ag1"]
        let model = try await unlocked(engine)
        try await model.revoke(try await agentItem(model, "ag1"), changeKeys: true)
        XCTAssertEqual(model.revocationFlows["ag1"]?.background, true)
        try await follow(model) { model.revocationFlows["ag1"]?.stage == .keysLeft }
        for _ in 0..<5 {
            model.refresh()
            try await Task.sleep(for: .milliseconds(30))
        }
        let flow = try XCTUnwrap(model.revocationFlows["ag1"])
        XCTAssertEqual(flow.stage, .keysLeft, "never «Done» with an item left")
        let left = try XCTUnwrap(model.keysLeft(of: "ag1", listed: []))
        XCTAssertEqual(left.items, 1)
        let text = try XCTUnwrap(RevokeWords.state(flow, left: left))
        XCTAssertTrue(text.contains("one by one"), text)
        XCTAssertTrue(RevokeWords.canFinish(flow, left: left))
    }

    /// Quitting the app mid-change: a new window on the same `klavd`
    /// shows what runs and what is left, and never says «Done» on its own.
    func testAWindowOpenedMidChangeShowsWhatIsLeft() async throws {
        let engine = SampleEngine(locked: false, touchID: true)
        let gate = DispatchSemaphore(value: 0)
        engine.rotationGate = gate
        engine.rotationFails = true
        let first = try await unlocked(engine)
        try await first.revoke(try await agentItem(first, "ag2"), changeKeys: true)

        let reopened = try await unlocked(engine)
        XCTAssertNil(reopened.revocationFlows["ag2"], "a new window has no flow of its own")
        try await follow(reopened) { reopened.info?.revocations.first?.running == true }
        let running = reopened.keysLeft(of: "ag2", listed: [])
        XCTAssertEqual(RevokeWords.state(nil, left: running), "Revoked. Changing keys: 0 of 2 projects")
        XCTAssertFalse(RevokeWords.canFinish(nil, left: running))

        gate.signal()
        try await follow(reopened) { reopened.info?.revocations.first?.running == false }
        let listed = try await reopened.run { try $0.agentRevocations() }
        let left = reopened.keysLeft(of: "ag2", listed: listed)
        XCTAssertEqual(RevokeWords.state(nil, left: left), "Revoked. Keys left to change (1 of 2)")
        XCTAssertTrue(RevokeWords.canFinish(nil, left: left))
    }

    /// Locking in the middle: the change stops saying it runs and is never
    /// «Done» while locked; after unlocking it ends as `klavd` says.
    func testLockingInTheMiddleNeverSaysDone() async throws {
        let engine = SampleEngine(locked: false, touchID: true)
        let gate = DispatchSemaphore(value: 0)
        engine.rotationGate = gate
        let model = try await unlocked(engine)
        try await model.revoke(try await agentItem(model, "ag1"), changeKeys: true)
        try await follow(model) { model.info?.revocations.first?.running == true }

        try engine.lock()
        model.refresh()
        try await settle { model.phase == .locked }
        gate.signal()
        for _ in 0..<5 {
            model.refresh()
            try await Task.sleep(for: .milliseconds(30))
            XCTAssertNotEqual(model.revocationFlows["ag1"]?.stage, .done, "never «Done» while locked")
        }

        try engine.unlock(password: nil)
        try await follow(model) { model.revocationFlows["ag1"]?.stage == .done }
    }

    /// An unreadable grant keeps the key change on, and says the projects
    /// are unknown: never «no access».
    func testAnUnreadableGrantStillOffersTheKeyChange() async throws {
        let engine = SampleEngine(locked: false, touchID: true)
        engine.unreadableGrants = ["ag1"]
        let model = try await unlocked(engine)
        let seen = try await model.run { try $0.agentExposure(id: "ag1") }
        XCTAssertTrue(seen.projects.isEmpty)
        XCTAssertTrue(seen.projectsUnknown)
        XCTAssertTrue(RevokeWords.offersKeyChange(seen))
        let cost = RevokeWords.cost(seen.cost, unknownProjects: true)
        XCTAssertTrue(cost.contains("looks for its projects"), cost)
        XCTAssertFalse(cost.contains(" 0 "), cost)
    }

    /// The cost never reads more certain than what Klav could count.
    func testTheCostSaysAtLeastWhenKlavCouldntCount() {
        func cost(_ items: UInt32, _ others: [String], items atLeast: Bool, others othersAtLeast: Bool) -> String {
            RevokeWords.cost(KeyChangeCostInfo(items: items, otherAgents: others, itemsAtLeast: atLeast,
                                               othersAtLeast: othersAtLeast), unknownProjects: false)
        }
        let exact = cost(5, [], items: false, others: false)
        XCTAssertTrue(exact.contains("keys of 5 items"), exact)
        XCTAssertTrue(exact.contains("Without it"), exact)
        XCTAssertTrue(cost(5, [], items: true, others: false).contains("at least 5 items"))
        let none = cost(0, [], items: true, others: false)
        XCTAssertTrue(none.contains("couldn’t count"), none)
        XCTAssertFalse(none.contains("0 items"), none)
        let others = cost(2, ["a\u{202E}b"], items: false, others: true)
        XCTAssertTrue(others.contains("“ab” gets a new grant"), others)
        XCTAssertTrue(others.contains("couldn’t read every agent’s grant"), others)
        XCTAssertFalse(others.contains("Without it"), others)
    }

    /// An older `klavd` or an unreadable grant: «unknown», and the command
    /// carries the agent's ID.
    func testAGrantThisMacCantReadSaysUnknown() async throws {
        let engine = SampleEngine(locked: false, touchID: true)
        engine.olderKlavd = true
        let model = try await unlocked(engine)
        let grant = try await model.run { try $0.grantEditor(id: "ag1") }
        XCTAssertTrue(GrantWords.grantUnknown(grant))
        XCTAssertEqual(GrantWords.readOnly(.olderKlavd, agent: GrantWords.commandAgent(grant.agentId)).1,
                       "klav agent approve ag1")

        engine.olderKlavd = false
        engine.unreadableGrants = ["ag1"]
        let unreadable = try await model.run { try $0.grantEditor(id: "ag1") }
        XCTAssertTrue(GrantWords.grantUnknown(unreadable))
        let rules = try await model.run { try $0.grantEditor(id: "ag2") }
        XCTAssertFalse(GrantWords.grantUnknown(rules), "hand-written rules are known, only not editable")
    }

    /// Revoking never waits on the list of revocations (or an older
    /// `klavd` without it): the agents still load.
    func testAgentsLoadWhenTheRevocationsDont() async throws {
        let engine = SampleEngine(locked: false, touchID: true)
        engine.revocationsFail = true
        let model = try await unlocked(engine)
        let (agents, listed) = try await model.agentsAndRevocations()
        XCTAssertFalse(agents.isEmpty)
        XCTAssertTrue(listed.isEmpty)
    }

    /// «Pause every agent now» on the lock screen says when it fails.
    func testPausingFromTheLockScreenSaysWhyItFailed() async throws {
        let engine = SampleEngine(locked: false, touchID: true)
        let model = try await unlocked(engine)
        engine.pauseFails = true
        let problem = await model.pauseEveryAgentNow()
        XCTAssertTrue(problem?.contains("couldn’t pause") == true, problem ?? "nil")
        engine.pauseFails = false
        let none = await model.pauseEveryAgentNow()
        XCTAssertNil(none)
    }

    /// Without Touch ID, the master password shows over «Change
    /// permissions…» while it is open, else over the window: one place.
    func testThePasswordPromptShowsOverTheGrantSheet() async throws {
        let model = try await unlocked(SampleEngine(locked: false, touchID: false))
        let (change, wide) = try await mixedChange(model)
        model.changingGrant = GrantChangeRequest(agentId: "ag1")
        try await model.applyGrantChange(wide, change: change) { _ in }
        XCTAssertNotNil(model.passwordPromptHere(inSheet: true).wrappedValue)
        XCTAssertNil(model.passwordPromptHere(inSheet: false).wrappedValue)
        model.changingGrant = nil
        XCTAssertNil(model.passwordPromptHere(inSheet: true).wrappedValue)
        XCTAssertNotNil(model.passwordPromptHere(inSheet: false).wrappedValue)

        // The right password: signing closes the grant sheet first, then the
        // prompt closes from inside it. Nothing shows again on the window.
        model.changingGrant = GrantChangeRequest(agentId: "ag1")
        let prompt = try XCTUnwrap(model.passwordPromptHere(inSheet: true).wrappedValue)
        var signed = false
        let grant = try await model.run { try $0.grantEditor(id: "ag1") }
        XCTAssertEqual(grant.version, 3, "nothing signed before the password")
        try await prompt.retry("sample")
        signed = try await model.run { try $0.grantEditor(id: "ag1") }.version == 4
        XCTAssertTrue(signed)
        // Nothing else closes it here: the retry did.
        XCTAssertNil(model.passwordPrompt)
        model.changingGrant = nil
        XCTAssertNil(model.passwordPromptHere(inSheet: false).wrappedValue, "never shown again over the window")
    }

    // MARK: Words

    /// The sheet names permissions and effects with the words of `klavd`'s
    /// Touch ID dialog (`prompt.rs`), in both languages (F4).
    func testTheSheetsWordsAreTheDialogs() throws {
        let es = try XCTUnwrap(Bundle(for: MacModel.self).path(forResource: "es", ofType: "lproj").flatMap(Bundle.init(path:)))
        let keys = ["list": "list", "fill": "fill", "inject": "inject", "totp": "code", "reveal": "reveal",
                    "create": "create", "update": "edit", "delete": "delete"]
        let dialog = ["list": "listar", "fill": "rellenar", "inject": "inyectar", "totp": "código", "reveal": "revelar",
                      "create": "crear", "update": "editar", "delete": "borrar"]
        for p in GrantWords.permissions {
            XCTAssertEqual(GrantWords.permission(p), keys[p], p)
            XCTAssertEqual(es.localizedString(forKey: keys[p]!, value: "∅", table: nil), dialog[p], p)
        }
        for (en, spanish) in [("allow", "permitir"), ("ask", "preguntar"), ("deny", "denegar")] {
            XCTAssertEqual(GrantWords.effect(en), en)
            XCTAssertEqual(es.localizedString(forKey: en, value: "∅", table: nil), spanish)
        }
    }

    func testWindowsAndDaysReadAsTheEditorWroteThem() {
        let here = Int16(TimeZone.current.secondsFromGMT() / 60)
        let weekdays = TimeWindowInfo(days: ["mon", "tue", "wed", "thu", "fri"], startMinutes: 540, endMinutes: 1080,
                                      utcOffsetMinutes: here)
        let text = GrantWords.window(weekdays)
        XCTAssertTrue(text.hasSuffix(" 09:00–18:00"), text)
        XCTAssertFalse(text.contains("UTC"), "this Mac's own offset is not said")
        let away = TimeWindowInfo(days: [], startMinutes: 1320, endMinutes: 120,
                                  utcOffsetMinutes: here == -360 ? 60 : -360)
        XCTAssertTrue(GrantWords.window(away).contains("UTC"), GrantWords.window(away))
        XCTAssertEqual(NewWindow(days: ["mon"], start: "9:00", end: "18:30").window?.startMinutes, 540)
        XCTAssertNil(NewWindow(days: ["mon"], start: "25:00", end: "18:30").window)
        XCTAssertEqual(NewWindow(days: Set(GrantWords.weekdays), start: "08:00", end: "09:00").window?.days, [],
                       "every day is no days")
    }

    /// Opened and closed without changes, the editor sends the grant in
    /// force; the button to review stays off (klavd refuses a no-op).
    func testAnUntouchedEditorChangesNothing() async throws {
        let model = try await unlocked(SampleEngine(locked: false, touchID: true))
        let grant = try await model.run { try $0.grantEditor(id: "ag1") }
        let draft = GrantDraft(grant)
        XCTAssertEqual(draft, GrantDraft(grant))
        do {
            _ = try await model.prepareGrantChange(agent: "ag1", change: draft.input(order: grant.projects.map(\.projectId)))
            XCTFail("a change with nothing in it")
        } catch KlavError.Invalid {}
    }
}
