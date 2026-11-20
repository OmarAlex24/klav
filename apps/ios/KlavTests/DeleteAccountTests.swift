import XCTest
@testable import Klav

/// Deleting the account (ADR 0037 §7): the words of each screen in both
/// languages, the account notices and the dates.
final class DeleteAccountTests: XCTestCase {
    private func spanish(_ key: String) -> String {
        guard let path = Bundle.main.path(forResource: "es", ofType: "lproj"), let bundle = Bundle(path: path) else {
            return "no es.lproj"
        }
        return bundle.localizedString(forKey: key, value: "MISSING", table: nil)
    }

    func testAccountNoticesCarryNoIDAndAreNotARequest() {
        let account: [AnyHashable: Any] = ["klav": ["type": "account"]]
        XCTAssertTrue(Push.isAccount(account))
        XCTAssertNil(PushRoute(userInfo: account), "not a request to show")
        XCTAssertFalse(Push.isAccount(["klav": ["type": "approval", "id": "a1"]]))
        XCTAssertFalse(Push.isAccount(["aps": ["alert": "hola"]]))
    }

    func testTheNoticesSpeakEnglishAndSpanish() {
        // §7.5: the server sends only the keys.
        XCTAssertEqual(String(localized: "PUSH_ACCOUNT_DELETION_TITLE"), "Someone asked to delete your Klav account")
        XCTAssertEqual(spanish("PUSH_ACCOUNT_DELETION_TITLE"), "Se pidió borrar tu cuenta de Klav")
        XCTAssertEqual(spanish("PUSH_ACCOUNT_DELETION_BODY"),
                       "Abre Klav para ver cuándo y desde qué dispositivo. Si no fuiste tú, cancélalo.")
        XCTAssertEqual(String(localized: "PUSH_ACCOUNT_CANCELED_BODY"), "Your account stays in Klav.")
        XCTAssertEqual(spanish("PUSH_ACCOUNT_CANCELED_TITLE"), "Se canceló el borrado de tu cuenta")
        XCTAssertEqual(String(localized: "PUSH_ACCOUNT_DELETED_BODY"), "Open Klav to delete this iPhone’s copy.")
        XCTAssertEqual(spanish("PUSH_ACCOUNT_DELETED_TITLE"), "Klav borró tu cuenta")
    }

    func testTheScreensSpeakSpanish() {
        // §7.1–§7.4, §7.6, §7.7.
        XCTAssertEqual(spanish("Delete my account"), "Borrar mi cuenta")
        XCTAssertEqual(spanish("Delete your account?"), "¿Borrar tu cuenta?")
        XCTAssertEqual(spanish("Confirm it’s you to delete your account"), "Confirma que eres tú para borrar tu cuenta")
        XCTAssertEqual(spanish("Cancel the deletion"), "Cancelar el borrado")
        XCTAssertEqual(spanish("Delete this iPhone’s copy"), "Borrar la copia de este iPhone")
        XCTAssertEqual(spanish("This server can’t delete accounts from the app. Ask whoever runs it."),
                       "Este servidor no permite borrar la cuenta desde la app. Pídeselo a quien lo opera.")
        // Arguments that change places in Spanish.
        XCTAssertEqual(String(format: spanish("You asked from %@ on %@. Until then Klav keeps working, except for your agents."),
                              "iPhone", "7 de noviembre"),
                       "Lo pediste desde iPhone el 7 de noviembre. Hasta entonces Klav sigue funcionando, salvo tus agentes.")
        XCTAssertEqual(String(format: spanish("On %@, everything in %@ was deleted from the server. This iPhone still keeps an encrypted copy."),
                              "14 de noviembre", "ana@example.com"),
                       "El 14 de noviembre se borró del servidor todo lo de ana@example.com. Este iPhone todavía guarda una copia cifrada.")
        // The error of a wrong password already existed.
        XCTAssertEqual(spanish("The master password isn’t right."), "La contraseña maestra no es correcta.")
    }

    func testTheDateIsTheMonthAndTheDay() {
        // 2026-11-14 18:03 UTC, in the test's time zone it may be the 14th
        // or the 15th: the month is what matters, and no year.
        let day = deletionDay(1_794_679_380_000)
        XCTAssertTrue(day.contains("November"), day)
        XCTAssertFalse(day.contains("2026"), day)
    }

    func testANewErrorSaysWhatHappened() {
        XCTAssertEqual(KlavError.AccountDeleted(deleteAt: 1, message: "x").userMessage, "Klav deleted your account")
        XCTAssertEqual(KlavError.DeletionUnsupported(message: "x").userMessage,
                       "This server can’t delete accounts from the app. Ask whoever runs it.")
        // 409, 429 and a lost answer: never the server's English (review
        // finding 3).
        XCTAssertEqual(KlavError.DeletionAlreadyScheduled(message: "account deletion already scheduled").userMessage,
                       "The deletion of your account is already scheduled. Klav shows when as soon as it syncs.")
        XCTAssertEqual(KlavError.DeletionRateLimited(message: "too many requests").userMessage,
                       "Klav limits how often the deletion can be asked for. Try again later.")
        XCTAssertEqual(KlavError.DeletionNotRecorded(deleteAt: nil, message: "x").userMessage,
                       "The server canceled the deletion, but this iPhone couldn’t save it. It shows after the next sync.")
        let scheduled = KlavError.DeletionNotRecorded(deleteAt: 1_794_679_380_000, message: "x").userMessage
        XCTAssertTrue(scheduled.hasPrefix("The server scheduled the deletion for November"), scheduled)
        XCTAssertTrue(scheduled.hasSuffix("but this iPhone couldn’t save it. It shows after the next sync."), scheduled)
    }

    func testTheNewErrorsSpeakSpanish() {
        XCTAssertEqual(spanish("The deletion of your account is already scheduled. Klav shows when as soon as it syncs."),
                       "El borrado de tu cuenta ya está programado. Klav te muestra la fecha en cuanto sincronice.")
        XCTAssertEqual(spanish("Klav limits how often the deletion can be asked for. Try again later."),
                       "Klav limita cuántas veces se puede pedir el borrado. Vuelve a intentarlo más tarde.")
        XCTAssertEqual(String(format: spanish("The server scheduled the deletion for %@, but this iPhone couldn’t save it. It shows after the next sync."),
                              "14 de noviembre"),
                       "El servidor programó el borrado para el 14 de noviembre, pero este iPhone no pudo guardarlo. Lo verás tras la próxima sincronización.")
        XCTAssertEqual(spanish("Face ID stays on in Klav: turning it off needs Face ID or the iPhone’s passcode."),
                       "Face ID sigue activo en Klav: para desactivarlo hace falta Face ID o el código del iPhone.")
        XCTAssertEqual(spanish("Read-only: you can search and copy, but not edit or sync."),
                       "Solo lectura: puedes buscar y copiar, pero no editar ni sincronizar.")
        XCTAssertEqual(spanish("Delete this iPhone’s copy?"), "¿Borrar la copia de este iPhone?")
        XCTAssertEqual(spanish("Klav deleted your account, so this copy can’t save anything new."),
                       "Klav borró tu cuenta, así que esta copia ya no guarda nada nuevo.")
        XCTAssertEqual(String(format: spanish("Your account was to be deleted on %@"), "14 de noviembre"),
                       "Tu cuenta debía borrarse el 14 de noviembre")
    }

    /// Past the date and without network the line no longer says «will
    /// be» (review nit).
    func testAPastDateNoLongerSaysWillBe() {
        let deletion = AccountDeletionInfo(requestedAt: 1_794_074_580_000, deleteAt: 1_794_679_380_000,
                                           deviceName: "iPhone", thisDevice: true, deleted: false)
        let before = Date(timeIntervalSince1970: 1_794_679_379)
        let after = Date(timeIntervalSince1970: 1_794_679_381)
        XCTAssertFalse(deletionDue(deletion, now: before))
        XCTAssertTrue(deletionDue(deletion, now: after))
        XCTAssertTrue(deletionHeadline(deletion, now: before).hasPrefix("Your account will be deleted on November"))
        XCTAssertTrue(deletionHeadline(deletion, now: after).hasPrefix("Your account was to be deleted on November"))
    }

    /// Turning Face ID off asks for the device owner. Only an iPhone with
    /// no passcode is `Unavailable`, the one case where `klav-ffi` lets
    /// the enrolment go without a prompt; a lockout must refuse, or
    /// failing Face ID on purpose would turn it off (review finding 1).
    /// «Delete this iPhone’s copy» and signing out (Q3 of the re-review):
    /// what never went up is counted, and confirming a dialog accepts
    /// exactly what it said. Klav couldn't tell: whatever waits.
    func testDeletingTheCopyCountsWhatNeverWentUp() {
        let check = { (passkeys: UInt32, generated: UInt32, locked: Bool) in
            SignOutCheck(unsentPasskeys: passkeys, unsentGenerated: generated, lockedWithQueue: locked)
        }
        XCTAssertEqual(UnsentLoss(check(0, 0, false)), .nothing)
        XCTAssertEqual(UnsentLoss(check(0, 2, false)), .counted(generated: 2, passkeys: 0))
        XCTAssertEqual(UnsentLoss(check(1, 3, false)), .counted(generated: 3, passkeys: 1))
        XCTAssertEqual(UnsentLoss(check(0, 0, true)), .unknown, "locked with a queue")
        XCTAssertEqual(UnsentLoss(nil), .unknown, "the check failed")
        XCTAssertTrue(UnsentLoss(check(0, 2, false)).mayHoldGenerated)
        XCTAssertFalse(UnsentLoss(check(1, 0, false)).mayHoldGenerated)
        XCTAssertTrue(UnsentLoss.unknown.mayHoldGenerated, "the history may list some")
        guard case .nothing = UnsentLoss.nothing.accepted else { return XCTFail("nothing") }
        guard case .unsent(let passkeys, let generated) = UnsentLoss(check(1, 3, false)).accepted,
              passkeys == 1, generated == 3 else { return XCTFail("what the dialog said") }
        // «Delete anyway», and a dialog that couldn't count: whatever waits.
        guard case .unknown = UnsentLoss(nil).accepted else { return XCTFail("unknown") }
    }

    func testTheRefusalSpeaksSpanish() {
        XCTAssertEqual(spanish("Delete anyway"), "Borrar de todos modos")
        XCTAssertEqual(spanish("Delete this iPhone’s copy anyway?"), "¿Borrar de todos modos la copia de este iPhone?")
        XCTAssertEqual(spanish("Generator history"), "Historial del generador")
        XCTAssertEqual(String.localizedStringWithFormat(spanish("%lld generated passwords never reached your account: they’re only on this iPhone. Copy them somewhere else before you delete this copy."), 2),
                       "Hay 2 contraseñas generadas que nunca llegaron a tu cuenta: solo están en este iPhone. Cópialas en otro sitio antes de borrar esta copia.")
        XCTAssertEqual(String.localizedStringWithFormat(spanish("%lld generated passwords never reached your account: they’re only on this iPhone. Copy them somewhere else before you delete this copy."), 1),
                       "Hay 1 contraseña generada que nunca llegó a tu cuenta: solo está en este iPhone. Cópiala en otro sitio antes de borrar esta copia.")
        XCTAssertEqual(String.localizedStringWithFormat(spanish("%lld generated passwords are not uploaded yet: if you sign out, they’re lost. Copy them from the generator history, or connect to the internet and open Klav to upload them first."), 3),
                       "Hay 3 contraseñas generadas sin subir: si sales, se pierden. Cópialas desde el historial del generador, o conéctate a internet y abre Klav para subirlas antes.")
        XCTAssertEqual(String.localizedStringWithFormat(Bundle.main.localizedString(forKey: "%lld passkeys saved without a connection never reached your account: they’re lost with this copy.", value: "MISSING", table: nil), 1),
                       "1 passkey saved without a connection never reached your account: it’s lost with this copy.")
        // N2: the list of what is not deleted agrees.
        XCTAssertEqual(spanish("Not deleted: the copy on your devices until you delete it, your emergency kit, and anything you copied out of Klav."),
                       "No se borran: la copia de tus dispositivos (hasta que tú la borres), tu kit de emergencia y lo que hayas copiado fuera de Klav.")
    }

    func testOnlyNoPasscodeLetsFaceIDGoWithoutTheOwner() {
        XCTAssertEqual(DeviceOwner.failure(.passcodeNotSet), .Unavailable)
        XCTAssertEqual(DeviceOwner.failure(.biometryLockout), .Other)
        XCTAssertEqual(DeviceOwner.failure(.biometryNotAvailable), .Other)
        XCTAssertEqual(DeviceOwner.failure(.biometryNotEnrolled), .Other)
        XCTAssertEqual(DeviceOwner.failure(.userCancel), .Cancelled)
        XCTAssertEqual(DeviceOwner.failure(.systemCancel), .Cancelled)
        XCTAssertEqual(DeviceOwner.failure(.authenticationFailed), .AuthFailed)
        XCTAssertEqual(DeviceOwner.failure(nil), .Other)
    }
}
