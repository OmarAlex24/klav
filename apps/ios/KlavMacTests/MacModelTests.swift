import XCTest
@testable import Klav

/// The Mac app's model over the sample engine: no klavd, no real home.
@MainActor
final class MacModelTests: XCTestCase {
    private func settle(_ model: MacModel, until done: @escaping @MainActor () -> Bool) async throws {
        for _ in 0..<100 where !done() {
            try await Task.sleep(for: .milliseconds(30))
        }
        XCTAssertTrue(done(), "timed out")
    }

    func testThePhaseFollowsKlavd() async throws {
        let model = MacModel.sample(SampleEngine(locked: true, touchID: true))
        model.refresh()
        try await settle(model) { model.phase == .locked }
        XCTAssertTrue(model.touchIDReady)
        try await model.unlockWithTouchID()
        try await settle(model) { model.phase == .unlocked }
        model.lock()
        try await settle(model) { model.phase == .locked }
        XCTAssertTrue(model.approvals.isEmpty, "locking forgets the requests")
    }

    func testAWrongPasswordLeavesItLocked() async throws {
        let model = MacModel.sample(SampleEngine(locked: true, touchID: false))
        model.refresh()
        try await settle(model) { model.phase == .locked }
        XCTAssertFalse(model.touchIDReady)
        do {
            try await model.unlock(password: "nope")
            XCTFail("unlocked with a wrong password")
        } catch KlavError.WrongCredentials {}
        try await model.unlock(password: "sample")
        try await settle(model) { model.phase == .unlocked }
    }

    /// Without Touch ID, approving asks for the master password and then
    /// goes through with it.
    func testWithoutTouchIDApprovingAsksForThePassword() async throws {
        let model = MacModel.sample(SampleEngine(locked: false, touchID: false))
        model.loadRequests()
        try await settle(model) { model.approvals.count == 2 }
        let first = model.approvals[0]
        try await model.decide(first, approve: true, leaseMinutes: 0)
        let prompt = try XCTUnwrap(model.passwordPrompt)
        XCTAssertEqual(model.approvals.count, 2, "nothing approved before the password")
        try await prompt.retry("sample")
        XCTAssertFalse(model.approvals.contains { $0.id == first.id })
    }

    func testATaskWithEveryBoxClearedIsNotApproved() async throws {
        let model = MacModel.sample(SampleEngine(locked: false, touchID: true))
        model.loadRequests()
        try await settle(model) { model.tasks.contains { $0.status == "pending" } }
        let card = try XCTUnwrap(model.tasks.first { $0.status == "pending" })
        for row in card.rows { model.editTask(card) { $0.set(row, false) } }
        do {
            try await model.decideTask(card, approve: true)
            XCTFail("approved a task with nothing checked")
        } catch RequestError.nothingChecked {}
        model.editTask(card) { $0.set(card.rows[0], true) }
        try await model.decideTask(card, approve: true)
        XCTAssertFalse(model.tasks.contains { $0.id == card.id && $0.status == "pending" })
    }

    func testPendingCountsWhatWaitsForThePerson() async throws {
        let model = MacModel.sample(SampleEngine(locked: false, touchID: true))
        model.loadRequests()
        // Two approvals, one agent to approve, one task to decide; the
        // running task does not wait for anyone.
        try await settle(model) { model.pendingCount == 4 }
    }

    func testDaemonErrorsSayWhatToDo() {
        XCTAssertEqual(KlavError.DaemonUnavailable(message: "klavd connect").macMessage,
                       "Klav’s background service isn’t running.")
        XCTAssertTrue(KlavError.BiometryUnavailable(message: "touch id is off").wantsPassword)
        XCTAssertFalse(KlavError.WrongCredentials.wantsPassword)
    }

    /// The app, the CLI and klavd agree on the home (klav-client's home.rs).
    func testTheHomeIsTheCLIsOne() throws {
        let home = try KlavHome.directory().path
        if let custom = ProcessInfo.processInfo.environment["KLAV_HOME"], !custom.isEmpty {
            XCTAssertEqual(home, (custom as NSString).expandingTildeInPath)
        } else {
            XCTAssertTrue(home.hasSuffix("/Library/Application Support/klav"), home)
        }
    }

    func testRequestWordsMatchTheIPhone() {
        XCTAssertEqual(RequestWords.target("klav://Trabajo/Infra/AWS%20console/password").title, "AWS console (password)")
        XCTAssertEqual(RequestWords.target("klav://Trabajo/Infra/AWS console/password").title, "AWS console (password)")
        XCTAssertEqual(RequestWords.wants("fill", "GitHub"), "Wants to fill GitHub")
    }
}
