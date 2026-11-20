import XCTest
@testable import Klav

/// Deleting the account from the Mac app (ADR 0037, layer 5), over the
/// sample engine: the model's states and the words that say «this Mac».
/// The request through a real `klavd` is tested in Rust
/// (`klav-ffi/tests/daemon.rs`).
@MainActor
final class DeleteAccountMacTests: XCTestCase {
    private func settle(_ model: MacModel, until done: @escaping @MainActor () -> Bool) async throws {
        for _ in 0..<100 where !done() {
            try await Task.sleep(for: .milliseconds(30))
        }
        XCTAssertTrue(done(), "timed out")
    }

    private func spanish(_ key: String) -> String {
        guard let path = Bundle.main.path(forResource: "es", ofType: "lproj"), let bundle = Bundle(path: path) else {
            return "no es.lproj"
        }
        return bundle.localizedString(forKey: key, value: "MISSING", table: nil)
    }

    /// Set once from a background task.
    private final class Flag: @unchecked Sendable {
        private let lock = NSLock()
        private var value = false
        var on: Bool { lock.lock(); defer { lock.unlock() }; return value }
        func set() { lock.lock(); value = true; lock.unlock() }
    }

    func testAskingNeedsThePasswordAndShowsTheDate() async throws {
        let model = MacModel.sample(SampleEngine(locked: false, touchID: true, deletion: "none"))
        model.refresh()
        try await settle(model) { model.phase == .unlocked }
        XCTAssertNil(model.accountDeletion)
        let supported = try await model.deletionSupported()
        XCTAssertTrue(supported)
        do {
            try await model.requestAccountDeletion(password: "nope")
            XCTFail("asked with a wrong password")
        } catch KlavError.WrongCredentials {}
        XCTAssertNil(model.accountDeletion, "nothing asked")
        try await model.requestAccountDeletion(password: "sample")
        let asked = try XCTUnwrap(model.accountDeletion)
        XCTAssertTrue(asked.thisDevice)
        XCTAssertEqual(asked.deleteAt - asked.requestedAt, 7 * 86_400_000)
        XCTAssertFalse(model.confirmingDeletion)
        XCTAssertFalse(model.accountDeleted)
    }

    func testCancelingAsksForTouchIDOrThePassword() async throws {
        // Touch ID: klavd asks it, nothing more here.
        let model = MacModel.sample(SampleEngine(locked: false, touchID: true, deletion: "pending"))
        model.refresh()
        try await settle(model) { model.accountDeletion != nil }
        XCTAssertEqual(model.accountDeletion?.thisDevice, false, "asked from the iPhone")
        try await model.cancelAccountDeletion()
        try await settle(model) { model.accountDeletion == nil }
        XCTAssertNil(model.passwordPrompt)
        XCTAssertEqual(model.toast?.text, "The deletion was canceled. Your agents work again.")
    }

    func testWithoutTouchIDCancelingAsksForThePassword() async throws {
        // ADR 0037 A2: what resuming the agents asks, never nothing.
        let model = MacModel.sample(SampleEngine(locked: false, touchID: false, deletion: "pending"))
        model.refresh()
        try await settle(model) { model.accountDeletion != nil }
        var outcome: Bool?
        try await model.cancelAccountDeletion { outcome = $0 }
        let prompt = try XCTUnwrap(model.passwordPrompt, "the master password")
        XCTAssertEqual(prompt.reason, "Cancel the deletion of your account")
        XCTAssertNotNil(model.accountDeletion, "nothing canceled yet")
        do {
            try await prompt.retry("nope")
            XCTFail("canceled with a wrong password")
        } catch KlavError.WrongCredentials {}
        XCTAssertNil(outcome)
        try await prompt.retry("sample")
        XCTAssertEqual(outcome, true)
        try await settle(model) { model.accountDeletion == nil }
        XCTAssertEqual(model.toast?.text, "The deletion was canceled. Your agents work again.")

        // Another device canceled first: nothing left, and it says so.
        try await model.cancelAccountDeletion { outcome = $0 }
        try await XCTUnwrap(model.passwordPrompt).retry("sample")
        XCTAssertEqual(outcome, false)
        XCTAssertEqual(model.toast?.text, "The deletion was already canceled.")
    }

    func testALockedMacSaysToUnlockToCancel() async throws {
        let model = MacModel.sample(SampleEngine(locked: true, touchID: true, deletion: "pending"))
        model.refresh()
        try await settle(model) { model.phase == .locked && model.accountDeletion != nil }
        do {
            try await model.cancelAccountDeletion()
            XCTFail("canceled while locked")
        } catch {
            XCTAssertEqual(cancelDeletionProblem(error), "Unlock Klav to cancel.")
        }
        XCTAssertNil(model.passwordPrompt, "a locked klavd asks for nothing")
        XCTAssertEqual(spanish("Unlock Klav to cancel."), "Desbloquea Klav para cancelar.")
    }

    func testAskedAlreadyShowsTheDateItHas() async throws {
        // The server's 409: the band keeps the date klavd knows.
        let model = MacModel.sample(SampleEngine(locked: false, touchID: true, deletion: "pending"))
        model.refresh()
        try await settle(model) { model.accountDeletion != nil }
        do {
            try await model.requestAccountDeletion(password: "sample")
            XCTFail("asked twice")
        } catch let error as KlavError {
            guard case .DeletionAlreadyScheduled = error else { return XCTFail("\(error)") }
            XCTAssertEqual(error.macMessage,
                           "The deletion of your account is already scheduled. Klav shows when as soon as it syncs.")
        }
        XCTAssertNotNil(model.accountDeletion)
        XCTAssertEqual(spanish("Klav limits how often the deletion can be asked for. Try again later."),
                       "Klav limita cuántas veces se puede pedir el borrado. Vuelve a intentarlo más tarde.")
    }

    func testAServerThatCannotSaysSoFirst() async throws {
        let model = MacModel.sample(SampleEngine(locked: false, touchID: true, deletion: "unsupported"))
        let supported = try await model.deletionSupported()
        XCTAssertFalse(supported)
    }

    func testAfterTheDeletionTheVaultStaysReadOnly() async throws {
        let model = MacModel.sample(SampleEngine(locked: false, touchID: true, deletion: "deleted"))
        model.section = .requests
        model.refresh()
        try await settle(model) { model.accountDeleted }
        XCTAssertNil(model.accountDeletion, "no longer pending")
        XCTAssertNotNil(model.deletedAt)
        XCTAssertEqual(model.phase, .unlocked, "the copy still opens (T165)")
        // D-C: only the vault, search and copy; nothing for the agents.
        XCTAssertEqual(model.section, .vault(.all))
        let items = try await model.run { try $0.items(query: ItemQuery()) }
        XCTAssertFalse(items.isEmpty, "the vault reads")
        XCTAssertEqual(model.pendingCount, 0)
        await model.loadLastAgentUse()
        XCTAssertNil(model.lastAgentUse)
        // Too late to cancel.
        do {
            try await model.cancelAccountDeletion()
            XCTFail("canceled a deleted account")
        } catch KlavError.AccountDeleted {}
        let loss = await model.deleteCopyCheck()
        XCTAssertEqual(loss, .nothing, "nothing waits to go up")
        let restarted = Flag()
        try await model.deleteThisCopy(discardUnsent: false) { restarted.set() }
        try await settle(model) { model.phase == .signedOut }
        XCTAssertFalse(model.accountDeleted)
        XCTAssertTrue(restarted.on, "klavd comes back, signed out")
    }

    /// Q3 of the re-review: generated passwords that never went up are
    /// only on this Mac. «Delete this Mac’s copy» counts them, lists them
    /// to copy, refuses, and «Delete anyway» deletes.
    func testDeletingTheCopyRefusesWhileGeneratedPasswordsWait() async throws {
        let model = MacModel.sample(SampleEngine(locked: false, touchID: true, deletion: "deleted-unsent"))
        model.refresh()
        try await settle(model) { model.accountDeleted }
        let loss = await model.deleteCopyCheck()
        XCTAssertEqual(loss, .counted(generated: 2, passkeys: 0))
        let unsent = try await model.unsentGenerated()
        XCTAssertEqual(unsent.map(\.host), ["app.linear.app", "github.com"])
        let at = unsent[0].createdAt
        let value = try await model.run { try $0.generatedValue(createdAt: at) }
        XCTAssertFalse(value.isEmpty, "it copies")
        let restarted = Flag()
        do {
            try await model.deleteThisCopy(discardUnsent: false) { restarted.set() }
            XCTFail("deleted the copy with generated passwords waiting")
        } catch KlavError.Denied {}
        XCTAssertFalse(restarted.on, "klavd kept running, with the account")
        XCTAssertEqual(model.phase, .unlocked)
        // Locked, klavd can't list them: something may be waiting.
        try await model.run { try $0.lock() }
        let lockedLoss = await model.deleteCopyCheck()
        XCTAssertEqual(lockedLoss, .unknown)
        try await model.deleteThisCopy(discardUnsent: true) { restarted.set() }
        try await settle(model) { model.phase == .signedOut }
        XCTAssertTrue(restarted.on, "klavd comes back, signed out")
    }

    func testTheRefusalSpeaksSpanish() {
        XCTAssertEqual(spanish("Delete anyway"), "Borrar de todos modos")
        XCTAssertEqual(String.localizedStringWithFormat(spanish("%lld generated passwords never reached your account: they’re only on this Mac. Copy them somewhere else before you delete this copy."), 2),
                       "Hay 2 contraseñas generadas que nunca llegaron a tu cuenta: solo están en este Mac. Cópialas en otro sitio antes de borrar esta copia.")
        XCTAssertEqual(spanish("Generated passwords that never reached your account may be waiting on this Mac. Unlock Klav to see and copy them; if you delete this copy, any are lost."),
                       "Puede que en este Mac haya contraseñas generadas que nunca llegaron a tu cuenta. Desbloquea Klav para verlas y copiarlas; si borras esta copia, las que haya se pierden.")
    }

    func testTheMacSaysThisMac() {
        // ADR 0037 §7: the iPhone's words with «este Mac».
        XCTAssertEqual(spanish("Delete this Mac’s copy"), "Borrar la copia de este Mac")
        XCTAssertEqual(
            String(format: spanish("On %@, everything in %@ was deleted from the server. This Mac still keeps an encrypted copy."),
                   "14 de noviembre", "ana@example.com"),
            "El 14 de noviembre se borró del servidor todo lo de ana@example.com. Este Mac todavía guarda una copia cifrada.")
        XCTAssertEqual(spanish("This Mac"), "Este Mac")
        XCTAssertEqual(spanish("Touch ID isn’t available right now, and Klav uses it on this Mac to delete the account. Open the lid (or unlock the Mac with its password if Touch ID is locked) and try again, or delete it from another of your devices."),
                       "Touch ID no está disponible ahora, y Klav lo usa en este Mac para borrar la cuenta. Abre la tapa (o, si Touch ID se bloqueó, desbloquea el Mac con su contraseña) y vuelve a intentarlo, o bórrala desde otro de tus dispositivos.")
        XCTAssertEqual(spanish("Touch ID changed on this Mac, so Klav stopped using it here. Enter the master password again to delete the account."),
                       "Touch ID cambió en este Mac, así que Klav dejó de usarlo aquí. Vuelve a escribir la contraseña maestra para borrar la cuenta.")
        XCTAssertEqual(spanish("Delete this Mac’s copy?"), "¿Borrar la copia de este Mac?")
        XCTAssertEqual(spanish("Deleting…"), "Borrando…")
        XCTAssertEqual(spanish("Klav deleted your account. This Mac’s copy opens read-only."),
                       "Klav borró tu cuenta. La copia de este Mac se abre en solo lectura.")
        XCTAssertEqual(KlavError.AccountDeleted(deleteAt: nil, message: "x").macMessage, "Klav deleted your account")
        XCTAssertEqual(KlavError.DeletionUnsupported(message: "x").macMessage,
                       "This server can’t delete accounts from the app. Ask whoever runs it.")
    }
}
