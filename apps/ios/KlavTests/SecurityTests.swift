import UIKit
import XCTest
@testable import Klav

/// Layer 11 of the 2026-11 security round: the privacy cover, auto-lock,
/// what locking forgets, the agent's key on the cards and AutoFill's
/// service.
extension KlavTests {
    // MARK: Auto-lock

    /// The wall clock can be moved back in Settings to stay unlocked; the
    /// timer counts on `ContinuousClock`, which only goes forward and keeps
    /// counting while the iPhone sleeps.
    func testAutoLockCountsOnAMonotonicClock() {
        let start = ContinuousClock.now
        var timer = AutoLockTimer()
        XCTAssertFalse(timer.cameBack(after: .zero, at: start), "never left")

        timer.left(at: start)
        timer.left(at: start + .seconds(30)) // the first time counts
        XCTAssertFalse(timer.cameBack(after: .seconds(60), at: start + .seconds(59)))
        XCTAssertNil(timer.leftAt, "coming back starts over")

        timer.left(at: start)
        XCTAssertTrue(timer.cameBack(after: .seconds(60), at: start + .seconds(60)))
        timer.left(at: start)
        XCTAssertTrue(timer.cameBack(after: .zero, at: start))
    }

    // MARK: Locking

    private func approval(_ id: String, agent: String = "a1") -> ApprovalItem {
        ApprovalItem(id: id, status: "pending", agentId: agent, agent: "bot", permission: "fill",
                     target: "klav://Personal/General/GitHub", reason: "log in", domain: "github.com",
                     createdAt: 0, expiresAt: 600_000, task: nil, requestDigest: "00")
    }

    private func agent(_ id: String, status: String, projects: [String] = []) -> AgentItem {
        AgentItem(id: id, name: "bot", note: nil, status: status, pairingWords: "uno dos tres cuatro cinco seis",
                  createdAt: 0, expiresAt: 600_000, projects: projects)
    }

    private func task(_ id: String) -> TaskItem {
        TaskItem(id: id, status: "pending", agentId: "a1", agent: "bot", task: "Facturas", reason: "lo pidió",
                 offered: false, durationSecs: 600, createdAt: 0, decideBy: 600_000, decidedAt: nil, revision: 0, expiresAt: nil,
                 endedAt: nil, endedBy: nil, rows: [], requestDigest: "00")
    }

    /// Locked, the app keeps nothing an agent asked or what the person
    /// changed on a card, nor the site AutoFill left to add; the opened
    /// notification waits for the unlock.
    @MainActor
    func testLockingForgetsTheAgentsRequests() {
        let model = AppModel()
        model.received(approvals: [approval("r1")],
                       agents: [agent("a1", status: "active", projects: ["Personal/General"]),
                                agent("a2", status: "pending")],
                       now: 1)
        model.showTasks([task("t1")], now: 1)
        model.editTask(model.tasks[0]) { $0.forSecs = 300 }
        model.route = .approval("r1")
        // The site AutoFill left to add (ADR 0025) names an item.
        model.showSiteOffer(SiteOffer(itemId: "i1", title: "1Password", host: "1password.com",
                                      savedFor: "my.1password.com", at: Date()))
        XCTAssertNotNil(model.siteOffer)
        XCTAssertEqual(model.approvals.count, 1)
        XCTAssertEqual(model.registrations.count, 1)
        XCTAssertEqual(model.tasks.count, 1)
        XCTAssertEqual(model.taskEdits.count, 1)
        XCTAssertNotNil(model.pairingWords(ofAgent: "a1"))

        model.lock()
        XCTAssertNil(model.siteOffer)
        XCTAssertTrue(model.approvals.isEmpty)
        XCTAssertTrue(model.registrations.isEmpty)
        XCTAssertTrue(model.tasks.isEmpty)
        XCTAssertTrue(model.taskEdits.isEmpty)
        XCTAssertTrue(model.knownAgents.isEmpty)
        XCTAssertEqual(model.route, .approval("r1"))
    }

    // MARK: The agent on the cards

    /// The name is the agent's choice; the pairing words come from its key
    /// and only count for an agent with a grant (`klav-ffi` checked it).
    @MainActor
    func testCardsShowWhatTiesTheAgentToItsKey() {
        let model = AppModel()
        model.received(approvals: [],
                       agents: [agent("granted", status: "active", projects: ["Personal/General"]),
                                agent("nogrant", status: "active"),
                                agent("revoked", status: "revoked", projects: ["Personal/General"]),
                                agent("waiting", status: "pending")],
                       now: 1)
        XCTAssertEqual(model.pairingWords(ofAgent: "granted"), "uno dos tres cuatro cinco seis")
        for id in ["nogrant", "revoked", "waiting", "unknown"] {
            XCTAssertNil(model.pairingWords(ofAgent: id), id)
        }
        let id = "0192f3a4-5b6c-7d8e-9f00-112233445566"
        XCTAssertEqual(AgentKey<AppModel>.line(id: id, words: nil), "Agent 0192f3a4…")
        XCTAssertEqual(AgentKey<AppModel>.line(id: id, words: "uno dos"), "Agent 0192f3a4… · words: uno dos")
        XCTAssertEqual(spanish("Agent %@… · words: %@"), "Agente %@… · palabras: %@")
        XCTAssertEqual(spanish("Sites added by an agent"), "Sitios añadidos por un agente")
        XCTAssertEqual(spanish("Sites added by %@"), "Sitios añadidos por %@")
    }

    // MARK: Privacy cover

    /// The cover is a window above the app's sheets and alerts (a cover in
    /// the root view stays under a sheet), up as soon as the app is not in
    /// front and down when it is.
    @MainActor
    func testThePrivacyCoverIsAWindowAboveSheetsAndAlerts() throws {
        let model = AppModel()
        let shield = PrivacyShield.shared
        defer { model.scene(.active) }

        model.scene(.inactive)
        XCTAssertTrue(model.covered)
        XCTAssertTrue(shield.isShowing)
        let window = try XCTUnwrap(shield.window)
        XCTAssertGreaterThan(window.windowLevel, .alert)
        XCTAssertFalse(window.isKeyWindow)

        model.scene(.active)
        XCTAssertFalse(shield.isShowing)

        model.scene(.background)
        XCTAssertTrue(shield.isShowing)
        model.scene(.active)
        XCTAssertFalse(shield.isShowing)
    }

    // MARK: AutoFill

    private func login(_ id: String) -> ItemInfo {
        ItemInfo(id: id, reference: "", vaultId: "v", vault: "Personal", projectId: "p", project: "General",
                 kind: .login, title: id, username: "ana", urls: [], tags: [], version: 1, updatedAt: 0,
                 trashed: false)
    }

    /// iOS can ask about several services: each login fills for the one it
    /// matched, not for the first service with a host.
    func testAutoFillFillsForTheServiceTheItemMatched() {
        var matches = SiteMatches()
        matches.add([login("a")], for: "https://accounts.example.com")
        matches.add([login("a"), login("b")], for: "https://login.example.org")
        XCTAssertEqual(matches.items.map(\.id), ["a", "b"])
        XCTAssertEqual(matches.services["a"], "https://accounts.example.com")
        XCTAssertEqual(matches.services["b"], "https://login.example.org")

        matches.keep { $0.id == "b" }
        XCTAssertEqual(matches.items.map(\.id), ["b"])
        XCTAssertEqual(matches.services, ["b": "https://login.example.org"])
    }
}
