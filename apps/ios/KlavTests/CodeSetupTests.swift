import SwiftUI
import XCTest
@testable import Klav

/// «Set Up Codes In» (ADR 0035): which links Klav takes, what klav-core
/// reads from a code link, the link waiting in memory, and the sheet's
/// Spanish. Saving against a server is in `crates/klav-ffi/tests/codigos.rs`.
/// Test vectors only (RFC 4648's `JBSWY3DPEHPK3PXP`).
final class CodeSetupTests: XCTestCase {
    private let link = "otpauth://totp/Example:ana%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example"
    private let migration = "otpauth-migration://offline?data=Ci8KE3NhbXBsZS1ob3RwLWNvdW50ZXISBmxlZ2FjeRoKTGVnYWN5IFZQTiABKAEwARABGAIgASiy8hk%3D"

    private func url(_ text: String) -> URL {
        URL(string: text)!
    }

    // MARK: Links

    /// Compared with `==`, never `XCTAssertEqual`: a failure would print
    /// the link, secret included, in the test log.
    func testKlavTakesCodeLinksAndGoogleExportsOnly() {
        XCTAssertTrue(IncomingLink(url(link)) == .code(link))
        let upper = "OTPAUTH://totp/X?secret=JBSWY3DPEHPK3PXP"
        XCTAssertTrue(IncomingLink(url(upper)) == .code(upper))
        XCTAssertTrue(IncomingLink(url(migration)) == .migration(migration))
        XCTAssertTrue(IncomingLink(url("https://example.com/otpauth")) == .other)
        XCTAssertTrue(IncomingLink(url("klav://Personal/General/GitHub")) == .other)
    }

    /// klav-core reads the link; what crosses to Swift has no secret, and
    /// `image=` (a picture on someone's server) is dropped, never fetched.
    func testKlavCoreReadsTheLinkAndKeepsItsSecret() throws {
        let code = try CodeLink(link: link + "&image=https%3A%2F%2Fevil.example%2Flogo.png")
        let info = code.info()
        XCTAssertEqual(info.issuer, "Example")
        XCTAssertEqual(info.account, "ana@example.com")
        XCTAssertEqual(info.digits, 6)
        XCTAssertEqual(info.period, 30)
        XCTAssertEqual(info.algorithm, "SHA1")
        XCTAssertNil(info.unusual)
        for text in [String(describing: info), String(reflecting: info), String(describing: code)] {
            XCTAssertFalse(text.contains("JBSWY3DP"), text)
            XCTAssertFalse(text.contains("evil.example"), text)
        }
        XCTAssertEqual(PendingCode(link: code, info: info).name, "Example")
    }

    func testAnUnusualCodeSaysHowItIs() throws {
        let code = try CodeLink(link: "otpauth://totp/ana?secret=JBSWY3DPEHPK3PXP&digits=8&period=60&algorithm=SHA256")
        let info = code.info()
        XCTAssertEqual(info.unusual, "8 digits · every 60 s · SHA256")
        // No issuer: the account names it.
        XCTAssertNil(info.issuer)
        XCTAssertEqual(PendingCode(link: code, info: info).name, "ana")
    }

    /// The link's text is cleaned before it is shown: no control or bidi
    /// characters, one line, cut short.
    func testTheLinksTextIsCleanedBeforeItIsShown() throws {
        let issuer = "Git%E2%80%AEHub%0Aand%20more" + String(repeating: "x", count: 200)
        let code = try CodeLink(link: "otpauth://totp/ana?secret=JBSWY3DPEHPK3PXP&issuer=\(issuer)")
        let shown = try XCTUnwrap(code.info().issuer)
        XCTAssertFalse(shown.unicodeScalars.contains { $0.value == 0x202E || $0 == "\n" }, shown)
        XCTAssertLessThanOrEqual(shown.count, 96)
    }

    /// Counter codes (HOTP), broken links and links without a secret are
    /// refused, and the error doesn't repeat the link.
    func testLinksKlavCantSaveAreRefusedWithoutRepeatingThem() {
        for bad in ["otpauth://hotp/Example:ana?secret=JBSWY3DPEHPK3PXP&counter=1",
                    "otpauth://totp/Example:ana?issuer=Example",
                    "otpauth://totp/Example:ana?secret=JBSWY3DPEHPK3PXP!!"] {
            XCTAssertThrowsError(try CodeLink(link: bad), bad) { error in
                XCTAssertFalse(describe(error).contains("JBSWY3DP"), describe(error))
            }
        }
    }

    // MARK: The link waits in memory

    /// Not open (here: not even started), the link waits in memory; the
    /// last one wins; one Klav can't save leaves the waiting one alone;
    /// saving or closing forgets it.
    @MainActor
    func testACodeLinkWaitsForTheVaultAndIsForgottenOnceDone() throws {
        let model = AppModel()
        XCTAssertNil(model.pendingCode)

        model.openLink(url(link))
        let first = try XCTUnwrap(model.pendingCode)
        XCTAssertEqual(first.name, "Example")
        XCTAssertNil(IncomingPresenter.shared.shown)

        model.openLink(url("otpauth://totp/Other:bob?secret=KRSXG5CTMVRXEZLU&issuer=Other"))
        let second = try XCTUnwrap(model.pendingCode)
        XCTAssertNotEqual(second.id, first.id)
        XCTAssertEqual(second.name, "Other")

        model.openLink(url("otpauth://hotp/Example:ana?secret=JBSWY3DPEHPK3PXP&counter=1"))
        XCTAssertEqual(model.pendingCode?.id, second.id)
        model.openLink(url("https://example.com"))
        XCTAssertEqual(model.pendingCode?.id, second.id)

        // An old sheet closing doesn't forget the new link.
        model.closeCode(first.id)
        XCTAssertEqual(model.pendingCode?.id, second.id)
        model.lock()
        XCTAssertEqual(model.pendingCode?.id, second.id)
        model.codeSaved(second.id)
        XCTAssertNil(model.pendingCode)

        model.openLink(url(link))
        let third = try XCTUnwrap(model.pendingCode)
        model.closeCode(third.id)
        XCTAssertNil(model.pendingCode)
    }

    @MainActor
    func testGoogleExportsWaitForTheImport() {
        let model = AppModel()
        model.openLink(url(migration))
        model.openLink(url(migration))
        XCTAssertEqual(model.migrationLinks, [migration])
        model.lock()
        XCTAssertEqual(model.migrationLinks, [migration])
        model.migrationImported()
        XCTAssertTrue(model.migrationLinks.isEmpty)
        model.openLink(url(migration))
        model.closeMigration()
        XCTAssertTrue(model.migrationLinks.isEmpty)
        // Signing out forgets them too.
        model.openLink(url(migration))
        model.forgetLinks()
        XCTAssertTrue(model.migrationLinks.isEmpty)
    }

    /// Opens `link` and hands back its id and a weak look at its `CodeLink`,
    /// without keeping a copy of `PendingCode` (a copy would keep it alive).
    @MainActor
    private func openWatched(_ model: AppModel) throws -> (id: UUID, link: () -> CodeLink?) {
        model.openLink(url(link))
        let id = try XCTUnwrap(model.pendingCode?.id)
        weak let watched = model.pendingCode?.link
        XCTAssertNotNil(watched)
        return (id, { watched })
    }

    /// Once the link is done with, Swift lets go of its `CodeLink`, and
    /// klav-core zeroes the secret (T145): after closing the sheet, after
    /// saving, after another link and after signing out. Locking keeps it.
    @MainActor
    func testTheCodeLinkIsLetGoOnceItIsDone() throws {
        let model = AppModel()

        let closed = try openWatched(model)
        model.lock()
        XCTAssertNotNil(closed.link(), "the link waits while locked")
        model.closeCode(closed.id)
        XCTAssertNil(closed.link())

        let saved = try openWatched(model)
        model.codeSaved(saved.id)
        XCTAssertNil(saved.link())

        let replaced = try openWatched(model)
        let latest = try openWatched(model)
        XCTAssertNil(replaced.link(), "the last link wins")
        XCTAssertNotNil(latest.link())

        model.forgetLinks()
        XCTAssertNil(model.pendingCode)
        XCTAssertNil(latest.link())
    }

    // MARK: Choosing the login

    private func login(_ title: String, user: String? = nil, sites: [String] = [], project: String = "p") -> ItemInfo {
        ItemInfo(id: "id-" + title, reference: "", vaultId: "v", vault: "Personal", projectId: project, project: "General",
                 kind: .login, title: title, username: user, urls: sites, tags: [], version: 1, updatedAt: 0,
                 trashed: false, confirmedUrls: sites)
    }

    func testTheSearchLooksAtTitlesUsersAndSites() {
        let target = CodeTarget(item: login("Bank", user: "ana@example.com", sites: ["https://www.bank.test/login"]),
                                issuerMatch: false, accountMatch: true, code: .none)
        XCTAssertEqual(target.site, "bank.test")
        XCTAssertTrue(target.matches("ban"))
        XCTAssertTrue(target.matches("ANA@"))
        XCTAssertTrue(target.matches("bank.test"))
        XCTAssertFalse(target.matches("github"))
        XCTAssertFalse(target.matches("  "))
        XCTAssertNil(CodeTarget(item: login("Note"), issuerMatch: false, accountMatch: false, code: .none).site)
    }

    /// A new login can't take a title its project already has (klav-client
    /// refuses it): spaces around and ASCII case aside.
    func testANewLoginNeedsATitleItsProjectDoesntHave() {
        let items = [login("GitHub"), login("Bank", project: "other")]
        XCTAssertTrue(titleTaken("github ", in: "p", items: items))
        XCTAssertFalse(titleTaken("GitHub 2", in: "p", items: items))
        XCTAssertFalse(titleTaken("Bank", in: "p", items: items))
        XCTAssertTrue(titleTaken("bank", in: "other", items: items))
        XCTAssertFalse(titleTaken("", in: "p", items: items))
        XCTAssertFalse(titleTaken("GitHub", in: nil, items: items))
    }

    // MARK: Spanish

    private func spanish(_ key: String) -> String {
        guard let path = Bundle.main.path(forResource: "es", ofType: "lproj"), let bundle = Bundle(path: path) else {
            return "no es.lproj"
        }
        return bundle.localizedString(forKey: key, value: "MISSING", table: nil)
    }

    func testTheSheetSpeaksSpanish() {
        // Our own views' keys are in the catalog by hand.
        XCTAssertEqual(Title("Save code").text, Text("Save code"))
        XCTAssertEqual(spanish("Save code"), "Guardar código")
        XCTAssertEqual(spanish("Logins for this code"), "Logins de este código")
        XCTAssertEqual(spanish("Another login"), "Otro login")
        XCTAssertEqual(spanish("New login"), "Login nuevo")
        XCTAssertEqual(spanish("Search your logins"), "Buscar en tus logins")
        XCTAssertEqual(spanish("Replace"), "Reemplazar")
        XCTAssertEqual(spanish("Set up codes in Klav"), "Configurar códigos en Klav")
        XCTAssertEqual(String.localizedStringWithFormat(spanish("Unlock Klav to save the code for %@."), "GitHub"),
                       "Desbloquea Klav para guardar el código de GitHub.")
        XCTAssertEqual(String.localizedStringWithFormat(spanish("Code saved in %@"), "GitHub"),
                       "Código guardado en GitHub")
        XCTAssertEqual(spanish("Klav can’t read this link. It saves time-based codes (TOTP)."),
                       "Klav no puede leer este enlace. Guarda códigos por tiempo (TOTP).")
        // Arguments that change places.
        XCTAssertEqual(String.localizedStringWithFormat(
            spanish("This link says it’s for “%@”, but %@ is for %@. Check that it’s the right login."),
            "GitHub", "Banco", "bank.test"),
                       "Este enlace dice que es de «GitHub», pero Banco es de bank.test. Comprueba que es el login correcto.")
        XCTAssertEqual(String(localized: "every \(60) s"), "every 60 s")
    }

    /// Every key of the app's catalog has its Spanish: one added without it
    /// would show in English in a Spanish iPhone. Read from the catalog
    /// itself (`Shared/Localizable.xcstrings`), not from the built app,
    /// which only has the keys that do have it.
    func testEveryKeyOfTheCatalogHasItsSpanish() throws {
        let catalog = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Shared/Localizable.xcstrings")
        let json = try JSONSerialization.jsonObject(with: Data(contentsOf: catalog)) as? [String: Any]
        let strings = try XCTUnwrap(json?["strings"] as? [String: [String: Any]])
        XCTAssertGreaterThan(strings.count, 500)
        // Not words: the same in every language.
        let notWords: Set<String> = ["—", "%@ / %@"]
        let missing = strings.filter { key, entry in
            guard !notWords.contains(key), entry["shouldTranslate"] as? Bool != false else { return false }
            let spanish = (entry["localizations"] as? [String: Any])?["es"] as? [String: Any]
            let unit = spanish?["stringUnit"] as? [String: Any]
            let value = unit?["value"] as? String ?? ""
            // A plural or device variation has no single value.
            return value.isEmpty && spanish?["variations"] == nil
        }.keys.sorted()
        XCTAssertEqual(missing, [], "keys without Spanish")
    }
}
