import SwiftUI
import XCTest
@testable import Klav

/// Task cards (ADR 0021): what the card sends when the person approves,
/// the twin of the extension's `test/tasks.test.ts`, and how it reads.
extension KlavTests {
    private func perm(_ name: String, checked: Bool = true, asked: Bool = true, addedByKlav: Bool = false,
                      deniedByPolicy: Bool = false, noSite: Bool = false) -> TaskPermissionItem {
        TaskPermissionItem(permission: name, checked: checked, asked: asked, addedByKlav: addedByKlav,
                           deniedByPolicy: deniedByPolicy, noSite: noSite)
    }

    private func row(_ item: String, _ title: String?, missing: Bool = false, mismatch: Bool = false,
                     noSite: Bool = false, domains: [String] = [],
                     _ permissions: [TaskPermissionItem]) -> TaskRowItem {
        TaskRowItem(vaultId: "v", projectId: "p", itemId: item, reference: "klav://v/p/\(item)", title: title,
                    username: title == nil ? nil : "ana", missing: missing, askedDomain: nil, domainMismatch: mismatch,
                    domains: domains, permissions: permissions, noSite: noSite, domainClaimed: false)
    }

    /// T92 and ADR 0030 §6: a row whose site does not match, or a `fill`
    /// without a site, cannot be ticked again.
    func testRowsWithoutAMatchingSiteCannotBeTicked() {
        let mismatch = row("m", "Banco", mismatch: true, domains: ["banco.mx"], [perm("fill", checked: false)])
        let noSite = row("n", "Login", noSite: true,
                         [perm("fill", checked: false, noSite: true), perm("inject")])
        var edits = TaskEdits()
        edits.set(mismatch, true)
        edits.set(noSite, true)
        XCTAssertFalse(edits.isChecked(mismatch, mismatch.permissions[0]))
        XCTAssertFalse(edits.isChecked(noSite, noSite.permissions[0]))
        XCTAssertTrue(edits.isChecked(noSite, noSite.permissions[1]))
    }

    /// The extension test's card: CFE with a code Klav added, Banco with a
    /// passkey offered unchecked and an `update` the policy denies, and an
    /// item the vault lacks.
    private var card: TaskItem {
        TaskItem(id: "t1", status: "pending", agentId: "a1", agent: "facturas",
                 task: "Descargar las facturas de octubre", reason: "lo pidió la persona", offered: false, durationSecs: 3600,
                 createdAt: 0, decideBy: 600_000, decidedAt: nil, revision: 0, expiresAt: nil, endedAt: nil,
                 endedBy: nil, rows: [
                    row("i1", "CFE", domains: ["cfe.mx"], [perm("fill"), perm("totp", asked: false, addedByKlav: true)]),
                    row("i2", "Banco", domains: ["banco.mx"],
                        [perm("fill"), perm("passkey", checked: false),
                         perm("update", checked: false, deniedByPolicy: true)]),
                    row("i3", nil, missing: true, [perm("fill", checked: false)]),
                 ], requestDigest: "00")
    }

    private func entry(_ item: String, _ permission: String) -> TaskChoiceEntry {
        TaskChoiceEntry(itemId: item, permission: permission)
    }

    func testATaskCardSendsNothingWhenThePersonChangesNothing() {
        let choice = TaskEdits().choice(for: card)
        XCTAssertEqual(choice, TaskChoiceInput(without: [], with: [], forSecs: nil))
        XCTAssertTrue(TaskEdits().anyChecked(card))
    }

    func testATaskCardSendsWhatWasClearedAndWhatWasTickedByHand() {
        let card = card
        var edits = TaskEdits()
        edits.set(card.rows[0], card.rows[0].permissions[1], false)
        edits.set(card.rows[1], card.rows[1].permissions[1], true)
        edits.forSecs = 1800
        XCTAssertEqual(edits.choice(for: card),
                       TaskChoiceInput(without: [entry("i1", "totp")], with: [entry("i2", "passkey")], forSecs: 1800))
        // The item's box: mixed, then all it can hold.
        XCTAssertEqual(edits.state(of: card.rows[0]), .mixed)
        XCTAssertEqual(edits.state(of: card.rows[1]), .on)
        edits.set(card.rows[0], true)
        XCTAssertEqual(edits.state(of: card.rows[0]), .on)
        XCTAssertEqual(edits.choice(for: card).without, [])
    }

    func testATaskCardNeverSendsWhatThePolicyDeniesOrAMissingItem() {
        let card = card
        var edits = TaskEdits()
        for row in card.rows { edits.set(row, true) }
        let choice = edits.choice(for: card)
        XCTAssertEqual(choice.with, [entry("i2", "passkey")])
        XCTAssertEqual(choice.without, [])
        XCTAssertFalse(edits.isChecked(card.rows[1], card.rows[1].permissions[2]), "the policy denies it")
        XCTAssertEqual(edits.state(of: card.rows[2]), .off, "not in the vault")
        // Clearing every item leaves nothing to approve: deny instead.
        for row in card.rows { edits.set(row, false) }
        XCTAssertFalse(edits.anyChecked(card))
        XCTAssertEqual(RequestError.nothingChecked.userMessage, "Check at least one permission, or deny the task")
    }

    func testATaskIsShortenedNeverLengthened() {
        XCTAssertEqual(TaskWords.durations(requested: 3600), [3600, 1800, 900])
        XCTAssertEqual(TaskWords.durations(requested: 7200), [7200, 3600, 1800, 900])
        XCTAssertEqual(TaskWords.durations(requested: 86_400), [86_400, 28_800, 14_400, 7200, 3600, 1800, 900])
        XCTAssertEqual(TaskWords.durations(requested: 600), [600])
        var edits = TaskEdits()
        edits.forSecs = 7200
        XCTAssertEqual(edits.duration(for: card), 3600, "never longer than asked")
        XCTAssertNil(edits.choice(for: card).forSecs)
        edits.forSecs = 3600
        XCTAssertNil(edits.choice(for: card).forSecs, "what was asked is not sent")
        XCTAssertEqual(TaskWords.duration(15 * 60), "15 min")
        XCTAssertEqual(TaskWords.duration(3600), "1 h")
        XCTAssertEqual(TaskWords.duration(5400), "1 h 30 min")
    }

    func testARunningTaskEmptiesFromWhenItWasAsked() {
        var live = card
        live.status = "approved"
        live.createdAt = 1_000_000
        live.decidedAt = 1_500_000
        live.expiresAt = 2_000_000
        XCTAssertEqual(TaskWords.spent(live, now: Date(timeIntervalSince1970: 1_000)), 0, accuracy: 0.001)
        XCTAssertEqual(TaskWords.spent(live, now: Date(timeIntervalSince1970: 1_500)), 0.5, accuracy: 0.001)
        XCTAssertEqual(TaskWords.spent(live, now: Date(timeIntervalSince1970: 3_000)), 1, accuracy: 0.001)
        XCTAssertTrue(TaskWords.left(until: 2_000_000, now: Date(timeIntervalSince1970: 1_400)).hasPrefix("10 min left · ends at "))
    }

    func testTaskNotificationsAndWordsInSpanish() {
        XCTAssertEqual(PushRoute(userInfo: ["klav": ["type": "task", "id": "t1"]]), .task("t1"))
        XCTAssertEqual(PushRoute(userInfo: ["klav": ["type": "secret_request", "id": "sr1"]]), .secretRequest("sr1"))
        XCTAssertEqual(String(localized: "PUSH_SECRET_REQUEST_TITLE"), "An agent is asking for a secret")
        XCTAssertEqual(spanish("PUSH_SECRET_REQUEST_TITLE"), "Un agente pide un secreto")
        XCTAssertFalse(spanish("PUSH_SECRET_REQUEST_BODY").contains("PUSH"))
        XCTAssertEqual(String(localized: "PUSH_TASK_TITLE"), "An agent is asking for a task")
        XCTAssertEqual(spanish("PUSH_TASK_TITLE"), "Un agente pide una tarea")
        XCTAssertFalse(spanish("PUSH_TASK_BODY").contains("PUSH"))
        XCTAssertEqual(spanish("%@ asks for a task"), "%@ pide una tarea")
        XCTAssertEqual(spanish("Outside the task “%@”"), "Fuera de la tarea «%@»")
        XCTAssertEqual(spanish("Add to the task"), "Añadir a la tarea")
        XCTAssertEqual(spanish("End task"), "Terminar tarea")
        XCTAssertEqual(spanish("Duration"), "Duración")
        XCTAssertEqual(spanish("one-time code"), "código de un solo uso")
        XCTAssertEqual(String.localizedStringWithFormat(spanish("%@ left · ends at %@"), "1 h", "18:15"),
                       "Quedan 1 h · termina a las 18:15")
        XCTAssertEqual(TaskWords.permission("totp"), "one-time code")
        XCTAssertEqual(RequestWords.wants("passkey", "AWS"), "Wants to sign in to AWS with your passkey")
    }

    /// Two items with `fill` must not sound the same: each box says its
    /// permission and its item, and what Klav added or the policy denies.
    @MainActor
    func testVoiceOverTellsEveryBoxOnATaskCardApart() async throws {
        for size: DynamicTypeSize in [.large, .accessibility3] {
            let view = PendingTaskCard<AppModel>(card: card)
                .environmentObject(AppModel())
                .environment(\.dynamicTypeSize, size)
            let labels = try await hosted(view).map(\.label).filter { !$0.isEmpty }
            XCTAssertEqual(Set(labels).count, labels.count, "\(size): \(labels)")
            for wanted in ["CFE, ana", "fill for CFE", "one-time code for CFE, Added by Klav", "fill for Banco",
                           "update for Banco, Your policy denies it", "passkey for Banco"] {
                XCTAssertTrue(labels.contains(wanted), "\(size): \(wanted) in \(labels)")
            }
        }
    }
}
