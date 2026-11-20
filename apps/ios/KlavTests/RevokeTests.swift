import XCTest
@testable import Klav

/// Revoking an agent from the iPhone (ADR 0033, amendment of 2026-11-10,
/// P10): what its key change reads as, when «Finish» shows, what an unlock
/// picks up again, and the Spanish.
final class RevokeTests: XCTestCase {
    private let bot = "0192f3a4-5b6c-7d8e-9f00-112233445566"

    private func left(projects: UInt32 = 0, rotated: UInt32 = 0, items: UInt32 = 0, skipped: [String] = [],
                      unknown: Bool = false, narrowed: Bool = false, lastError: String? = nil,
                      without: Bool = false) -> RevocationInfo {
        let toChange = projects > rotated + UInt32(skipped.count) ? projects - rotated - UInt32(skipped.count) : 0
        return RevocationInfo(agentId: bot, name: "bot", projects: projects, rotated: rotated, regrants: 0,
                              unknownProjects: unknown, narrowed: narrowed, items: items, logUnchecked: false,
                              withoutKeyChange: without,
                              skipped: UInt32(skipped.count), skippedProjects: skipped, toChange: toChange,
                              needsWork: !unknown && (toChange > 0 || items > 0), running: false,
                              lastError: lastError, pending: [])
    }

    /// From what the record holds, the iPhone never says «every key it can
    /// reach», and a revocation without projects never talks of them.
    func testWhatIsLeftNeverClaimsEveryKey() throws {
        let itemsOnly = left(skipped: ["item it1: this device no longer sees it (purged, or the server stopped sending it)"])
        let text = try XCTUnwrap(KeyChangeState.text(itemsOnly, running: false, end: nil))
        XCTAssertTrue(text.contains("shared with it one by one"), text)
        XCTAssertFalse(text.contains("project"), text)
        XCTAssertFalse(text.contains("every key"), text)
        XCTAssertFalse(text.contains("tries again"), text)
        XCTAssertFalse(text.contains("changes its key then"), text)

        // `status` says it was a revocation without the key change: never
        // a word about projects, even with projects counted.
        let without = left(projects: 2, rotated: 1, skipped: ["item it1: its vault is gone"], without: true)
        let none = try XCTUnwrap(KeyChangeState.text(without, running: false, end: nil))
        XCTAssertTrue(none.contains("shared with it one by one"), none)
        XCTAssertFalse(KeyChangeState.asksProjects(without))

        let projects = left(projects: 2, rotated: 1, skipped: ["Personal/Old: the project was deleted"])
        let said = try XCTUnwrap(KeyChangeState.text(projects, running: false, end: nil))
        XCTAssertTrue(said.contains("1 key is out of Klav’s reach"), said)
        XCTAssertFalse(said.contains("every key"), said)
        XCTAssertFalse(KeyChangeState.canFinish(projects, running: false))
    }

    /// «Done: every key changed» only for the projects' key change this
    /// iPhone ran to the end with nothing out of reach.
    func testDoneSaysEveryKeyOnlyForProjectsWithNothingSkipped() {
        XCTAssertEqual(KeyChangeState.text(nil, running: false, end: .done(projects: true, skipped: 0)),
                       "Revoked. Done: every key changed.")
        let items = KeyChangeState.text(nil, running: false, end: .done(projects: false, skipped: 0)) ?? ""
        XCTAssertFalse(items.contains("every key"), items)
        let skipped = KeyChangeState.text(nil, running: false, end: .done(projects: true, skipped: 2)) ?? ""
        XCTAssertFalse(skipped.contains("every key"), skipped)
        XCTAssertNil(KeyChangeState.text(nil, running: false, end: nil))
    }

    /// Keys left: «Finish» shows, an unlock picks it up again, and while
    /// it runs neither does. Unknown projects wait for the person (T189);
    /// a narrowing is not the iPhone's (P10).
    func testFinishAndPickUpFollowWhatCanMove() throws {
        let owed = left(projects: 3, rotated: 1)
        XCTAssertEqual(KeyChangeState.text(owed, running: false, end: nil), "Revoked. Keys left to change (2 of 3)")
        XCTAssertTrue(KeyChangeState.canFinish(owed, running: false))
        XCTAssertFalse(KeyChangeState.canFinish(owed, running: true))
        XCTAssertTrue(KeyChangeState.resumes(owed))
        let running = try XCTUnwrap(KeyChangeState.text(owed, running: true, end: nil))
        XCTAssertTrue(running.contains("1 of 3"), running)

        let unknown = left(unknown: true)
        XCTAssertFalse(KeyChangeState.canFinish(unknown, running: false))
        XCTAssertFalse(KeyChangeState.resumes(unknown))

        let narrowing = left(projects: 1, narrowed: true)
        XCTAssertNil(KeyChangeState.text(narrowing, running: false, end: nil))
        XCTAssertFalse(KeyChangeState.canFinish(narrowing, running: false))
        XCTAssertFalse(KeyChangeState.resumes(narrowing))
    }

    /// Why it stopped: a step's error, the record's, or no progress.
    func testAStoppedKeyChangeSaysWhy() {
        XCTAssertEqual(KeyChangeState.problem(nil, end: .stopped("offline")), "The key change stopped: offline")
        XCTAssertEqual(KeyChangeState.problem(left(projects: 1, lastError: "offline"), end: nil),
                       "The key change stopped: offline")
        let stalled = KeyChangeState.problem(nil, end: .stalled) ?? ""
        XCTAssertTrue(stalled.contains("next time you unlock"), stalled)
        XCTAssertNil(KeyChangeState.problem(left(projects: 1), end: nil))
    }

    private func spanish(_ key: String) -> String {
        guard let path = Bundle.main.path(forResource: "es", ofType: "lproj"), let bundle = Bundle(path: path) else {
            return "no es.lproj"
        }
        return bundle.localizedString(forKey: key, value: "MISSING", table: nil)
    }

    func testRevokingSpeaksSpanish() {
        XCTAssertEqual(spanish("Revoked."), "Revocado.")
        XCTAssertEqual(spanish("The key change stopped: %@"), "El cambio de llaves se detuvo: %@")
        XCTAssertNotEqual(spanish("This iPhone can’t read its grant, so it can’t tell which projects’ keys it held. It may have held some."), "MISSING")
        XCTAssertNotEqual(spanish("Keep Klav open until it’s done. If it closes or locks, Klav picks up where it left off the next time you unlock."), "MISSING")
    }
}
