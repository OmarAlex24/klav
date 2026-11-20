import SwiftUI
import XCTest
@testable import Klav

/// «Vault health» and assisted changes (ADR 0022 §4–6): what the offer
/// sends, how a running task's sites read, and the words in Spanish. The
/// twin of the extension's `test/health.test.ts`.
extension KlavTests {
    private func offerRow(_ id: String, host: String?, blocked: String? = nil,
                          permissions: [String] = ["rotate"]) -> OfferRowInfo {
        OfferRowInfo(itemId: id, vaultId: "v", projectId: "p", reference: "klav://Personal/General/\(id)",
                     title: id, username: "ana", hosts: host.map { [$0] } ?? [], changeUrl: nil, group: 1,
                     permissions: permissions, blocked: blocked)
    }

    private func site(_ state: String, started: Bool = false) -> SiteProgressInfo {
        SiteProgressInfo(itemId: "i", reference: nil, title: "Bank", hosts: ["bank.example"], state: state,
                         started: started, at: nil)
    }

    func testTheOfferSendsTheLoginsLeftCheckedNeverABlockedOne() {
        let rows = [offerRow("Bank", host: "bank.example"),
                    offerRow("Notes", host: nil, blocked: "no_site"),
                    offerRow("Shop", host: "shop.example", permissions: ["rotate", "totp"])]
        XCTAssertEqual(HealthWords.picked(rows, unchecked: ["Shop"]), ["Bank"])
        let input = HealthWords.input(agent: "agent-1", rows: rows, unchecked: [], secs: 3600)
        XCTAssertEqual(input, OfferInput(agent: "agent-1", items: ["Bank", "Shop"], task: "Change passwords",
                                         reason: "Give each of these sites a new password that Klav generates and keeps",
                                         durationSecs: 3600))
        XCTAssertEqual(HealthWords.block("no_site"), "It has no website: the change happens on the item’s site")
    }

    /// The agent reads the title and the reason: they say nothing about
    /// which sites share a password, in either language.
    func testTheOfferTellsTheAgentNothingAboutReuse() {
        let words = ["Change passwords", "Give each of these sites a new password that Klav generates and keeps"]
        for text in words + words.map({ spanish($0) }) {
            XCTAssertNil(text.lowercased().range(of: "reuse|repet|share|compart|same|misma", options: .regularExpression),
                         text)
        }
        XCTAssertEqual(spanish("Change passwords"), "Cambiar contraseñas")
    }

    func testAnOfferedTaskLastsTwoHoursUnlessThePersonPicksAtMostADay() {
        let steps = HealthWords.offerSteps
        XCTAssertEqual(steps.first, 7200)
        XCTAssertEqual(steps.max(), 86_400)
        XCTAssertEqual(Set(steps).count, steps.count)
    }

    func testARunningTasksSitesReadChangedInProgressPendingOrFailed() {
        XCTAssertEqual(HealthWords.site(site("changed")), "changed")
        XCTAssertEqual(HealthWords.site(site("failed")), "failed")
        XCTAssertEqual(HealthWords.site(site("pending")), "pending")
        XCTAssertEqual(HealthWords.site(site("pending", started: true)), "in progress")
        let n = HealthWords.counts([site("changed"), site("pending", started: true), site("pending"), site("failed")])
        XCTAssertEqual(n.changed, 1)
        XCTAssertEqual(n.pending, 2)
        XCTAssertEqual(n.failed, 1)
    }

    /// Only a task the person offered, still running, with `rotate`.
    func testOnlyOfferedRunningRotateTasksAreFollowed() {
        func card(offered: Bool, status: String = "approved", expiresAt: Int64 = 2_000, permission: String = "rotate")
            -> TaskItem {
            TaskItem(id: "t", status: status, agentId: "a", agent: "bot", task: "Change passwords", reason: "r",
                     offered: offered, durationSecs: 7200, createdAt: 0, decideBy: 0, decidedAt: 0, revision: 1,
                     expiresAt: expiresAt, endedAt: nil, endedBy: nil,
                     rows: [TaskRowItem(vaultId: "v", projectId: "p", itemId: "i", reference: "r", title: "Bank",
                                        username: nil, missing: false, askedDomain: nil, domainMismatch: false,
                                        domains: ["bank.example"],
                                        permissions: [TaskPermissionItem(permission: permission, checked: true,
                                                                         asked: false, addedByKlav: false,
                                                                         deniedByPolicy: false, noSite: false)],
                                        noSite: false, domainClaimed: false)],
                     requestDigest: "")
        }
        XCTAssertTrue(HealthWords.isFixTask(card(offered: true), now: 1_000))
        XCTAssertFalse(HealthWords.isFixTask(card(offered: false), now: 1_000), "asked by the agent")
        XCTAssertFalse(HealthWords.isFixTask(card(offered: true), now: 3_000), "over")
        XCTAssertFalse(HealthWords.isFixTask(card(offered: true, status: "ended"), now: 1_000))
        XCTAssertFalse(HealthWords.isFixTask(card(offered: true, permission: "fill"), now: 1_000))
    }

    /// The words of «Vault health», the offer and the pending change, as
    /// the extension says them in Spanish.
    func testHealthAndPendingChangesInSpanish() {
        XCTAssertEqual(spanish("Vault health"), "Salud de la bóveda")
        XCTAssertEqual(spanish("Fix my reused passwords"), "Arreglar mis contraseñas repetidas")
        XCTAssertEqual(spanish("Pending change: did the new password work?"),
                       "Cambio pendiente: ¿funcionó la contraseña nueva?")
        XCTAssertEqual(spanish("Use the new one"), "Usar la nueva")
        XCTAssertEqual(spanish("Keep the current one"), "Mantener la actual")
        XCTAssertEqual(spanish("Look for breached passwords"), "Buscar contraseñas filtradas")
        XCTAssertTrue(spanish("Klav asks Have I Been Pwned (api.pwnedpasswords.com) about each password. It sends only the first 5 characters of the password’s SHA-1 hash, never the password or the whole hash, and the answer is padded so its size gives nothing away. Have I Been Pwned sees your IP address and the time. This iPhone only.")
            .hasPrefix("Klav pregunta a Have I Been Pwned"))
        XCTAssertEqual(String.localizedStringWithFormat(spanish("Reused · %lld"), 2), "Repetidas · 2")
        XCTAssertEqual(String.localizedStringWithFormat(spanish("Changed %lld · pending %lld · failed %lld"), 1, 2, 0),
                       "Cambiadas: 1 · pendientes: 2 · fallidas: 0")
        XCTAssertEqual(String.localizedStringWithFormat(spanish("%@ · generated, not confirmed"), "ayer"),
                       "ayer · generada, no confirmada")
        XCTAssertEqual(String.localizedStringWithFormat(spanish("%@ is changing your passwords"), "bot"),
                       "bot está cambiando tus contraseñas")
        XCTAssertEqual(String(localized: "Reused · \(Int64(3))"), "Reused · 3")
    }

    /// The pending card's two buttons and the offer's boxes are told apart.
    @MainActor
    func testVoiceOverReadsThePendingCardAndTheOffer() async throws {
        let pending = try await hosted(PendingChangeCard(id: "i1", since: nil, decided: {})
            .environmentObject(AppModel())).map(\.label)
        for wanted in ["Use the new one", "Keep the current one"] {
            XCTAssertTrue(pending.contains(wanted), "\(wanted) in \(pending)")
        }
        let offer = ReusedOfferInfo(agents: [OfferAgentInfo(id: "a1", name: "bot")],
                                    agent: OfferAgentInfo(id: "a1", name: "bot"),
                                    rows: [offerRow("Bank", host: "bank.example"),
                                           offerRow("Shop", host: "shop.example", permissions: ["rotate", "totp"]),
                                           offerRow("Notes", host: nil, blocked: "no_site")],
                                    task: "Change passwords", reason: "r", durationSecs: 7200)
        let labels = try await hosted(OfferCard<AppModel>(offer: offer, pick: { _ in }, done: { _ in }, cancel: {})
            .environmentObject(AppModel())).map(\.label).filter { !$0.isEmpty }
        for wanted in ["Bank, ana", "Shop, ana", "Notes, ana"] {
            XCTAssertTrue(labels.contains(wanted), "\(wanted) in \(labels)")
        }
    }
}
