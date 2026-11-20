import XCTest
@testable import Klav

/// «Fix my reused passwords» on the Mac (ADR 0022 §6), the iPhone's card
/// over the sample engine: no klavd, no real home. What klavd signs is
/// tested in Rust (`crates/klav-ffi/tests/daemon.rs`).
@MainActor
final class FixReusedTests: XCTestCase {
    private func unlocked(touchID: Bool) async throws -> MacModel {
        let model = MacModel.sample(SampleEngine(locked: false, touchID: touchID, signedOut: false, deletion: ""))
        model.refresh()
        try await settle { model.phase == .unlocked }
        return model
    }

    private func settle(until done: @escaping @MainActor () -> Bool) async throws {
        for _ in 0..<100 where !done() { try await Task.sleep(for: .milliseconds(30)) }
        XCTAssertTrue(done(), "timed out")
    }

    /// With two agents nobody is picked; picking one checks its projects,
    /// and the logins it can't take go last.
    func testTheCardChecksTheLoginsAgainstTheAgent() async throws {
        let model = try await unlocked(touchID: true)
        let open = try await model.reusedOffer(agent: nil)
        XCTAssertEqual(open.agents.map(\.name), ["deploy-bot", "release-agent"])
        XCTAssertNil(open.agent, "two agents: the person picks")

        let offer = try await model.reusedOffer(agent: "ag1")
        XCTAssertEqual(offer.agent?.name, "deploy-bot")
        XCTAssertEqual(offer.rows.map(\.itemId), ["i-cf", "i-aws", "i-forum", "i-cfe"])
        XCTAssertEqual(offer.rows.map(\.blocked), [nil, nil, "not_granted", "not_granted"])
        XCTAssertEqual(offer.rows.map(\.group), [1, 1, 2, 2])
        XCTAssertEqual(offer.rows[0].hosts, ["dash.cloudflare.com"], "never a site an agent added")
    }

    /// One approval with Touch ID: the task arrives signed and its sites
    /// show in the progress.
    func testApprovingWithTouchIDOffersTheCheckedLogins() async throws {
        let model = try await unlocked(touchID: true)
        let offer = try await model.reusedOffer(agent: "ag2")
        let input = HealthWords.input(agent: "ag2", rows: offer.rows, unchecked: ["i-aws"], secs: 3600)
        XCTAssertEqual(input.items, ["i-cf"], "unchecked and blocked logins stay out")
        var offered: TaskItem?
        try await model.offerFix(input, agent: "release-agent") { offered = $0 }
        XCTAssertNil(model.passwordPrompt)
        let task = try XCTUnwrap(offered)
        XCTAssertTrue(task.offered)
        XCTAssertEqual(task.durationSecs, 3600)

        let progress = await model.fixProgress()
        XCTAssertEqual(progress.map(\.taskId), [task.id])
        XCTAssertEqual(progress.first?.sites.map(\.itemId), ["i-cf"])
        XCTAssertEqual(progress.first?.sites.first?.state, "changed")
    }

    /// Without Touch ID the master password comes first, and nothing is
    /// offered before it.
    func testWithoutTouchIDTheMasterPasswordComesFirst() async throws {
        let model = try await unlocked(touchID: false)
        let offer = try await model.reusedOffer(agent: "ag2")
        let input = HealthWords.input(agent: "ag2", rows: offer.rows, unchecked: [], secs: 7200)
        var offered: TaskItem?
        try await model.offerFix(input, agent: "release-agent") { offered = $0 }
        let prompt = try XCTUnwrap(model.passwordPrompt, "no Touch ID: the password")
        XCTAssertNil(offered)
        let none = await model.fixProgress()
        XCTAssertEqual(none, [], "nothing offered before the password")
        do {
            try await prompt.retry("wrong")
            XCTFail("a wrong password")
        } catch KlavError.WrongCredentials {}
        XCTAssertNil(offered)
        try await prompt.retry("sample")
        XCTAssertEqual(try XCTUnwrap(offered).rows.map(\.itemId), ["i-cf", "i-aws"])
    }

    /// Klav locks while the master password's sheet is up (a Mac without
    /// Touch ID, after Approve): the sheet goes instead of staying over the
    /// lock screen, and the offer doesn't go through from it, not even
    /// with the right password after unlocking again.
    func testLockingWithdrawsTheMasterPasswordSheet() async throws {
        let model = try await unlocked(touchID: false)
        let offer = try await model.reusedOffer(agent: "ag2")
        let input = HealthWords.input(agent: "ag2", rows: offer.rows, unchecked: [], secs: 7200)
        var offered: TaskItem?
        try await model.offerFix(input, agent: "release-agent") { offered = $0 }
        let prompt = try XCTUnwrap(model.passwordPrompt, "no Touch ID: the password")

        model.lock()
        try await settle { model.phase == .locked }
        XCTAssertNil(model.passwordPrompt, "no master password sheet over the lock screen")
        XCTAssertFalse(model.sheetOpen)

        try await model.unlock(password: "sample")
        try await settle { model.phase == .unlocked }
        XCTAssertNil(model.passwordPrompt, "unlocking doesn't bring it back")
        do {
            try await prompt.retry("sample")
            XCTFail("a withdrawn prompt ran its offer")
        } catch is CancellationError {}
        XCTAssertNil(offered)
        let running = await model.fixProgress()
        XCTAssertEqual(running, [], "the offer did not go through")
    }

    /// The account's deletion withdraws the master password's sheet too
    /// (read-only, ADR 0037 D-C: nothing left to approve).
    func testTheDeletionWithdrawsTheMasterPasswordSheet() async throws {
        let model = MacModel.sample(SampleEngine(locked: false, touchID: false, signedOut: false, deletion: "deleted"))
        var ran = false
        model.passwordPrompt = PasswordPrompt(reason: "Approve deploy-bot’s request") { _ in ran = true }
        model.refresh()
        try await settle { model.accountDeleted }
        XCTAssertEqual(model.phase, .unlocked, "not the lock: the deletion closed it")
        XCTAssertNil(model.passwordPrompt)
        XCTAssertFalse(ran)
    }

    /// Locked: no card and no progress.
    func testLockedThereIsNoOfferNorProgress() async throws {
        let engine = SampleEngine(locked: false, touchID: true, signedOut: false, deletion: "")
        let model = MacModel.sample(engine)
        model.refresh()
        try await settle { model.phase == .unlocked }
        let offer = try await model.reusedOffer(agent: "ag2")
        try await model.offerFix(HealthWords.input(agent: "ag2", rows: offer.rows, unchecked: [], secs: 3600),
                                 agent: "release-agent") { _ in }
        let running = await model.fixProgress()
        XCTAssertEqual(running.count, 1)
        model.lock()
        try await settle { model.phase == .locked }
        let after = await model.fixProgress()
        XCTAssertEqual(after, [])
        do {
            _ = try await model.reusedOffer(agent: nil)
            XCTFail("locked")
        } catch KlavError.Locked {}
    }

    func testTheFixSpeaksSpanish() throws {
        let es = try XCTUnwrap(Bundle(for: MacModel.self).path(forResource: "es", ofType: "lproj").flatMap(Bundle.init(path:)))
        for key in ["Fix my reused passwords", "Offer %@ a task to change passwords", "Offered to %@",
                    "The agent will change the passwords you leave checked", "Waiting for Touch ID…"] {
            XCTAssertNotEqual(es.localizedString(forKey: key, value: "∅", table: nil), "∅", key)
        }
    }
}
