import AuthenticationServices
import XCTest
@testable import Klav

/// ADR 0020 §11: the passkeys the AutoFill extension offers and what iOS
/// learns about them.
final class PasskeyTests: XCTestCase {
    private func passkey(_ rp: String, id: UInt8, user: String = "ana") -> PasskeyIdentityInfo {
        PasskeyIdentityInfo(itemId: "item-\(id)", title: "Example", rpId: rp, userName: user,
                            credentialId: Data([id, id]), userHandle: Data([9, id]))
    }

    func testOnlyTheSitesOwnPasskeysAreOffered() {
        let all = [passkey("example.com", id: 1), passkey("login.example.com", id: 2),
                   passkey("EXAMPLE.com", id: 3), passkey("evilexample.com", id: 4), passkey("com", id: 5)]
        // The rpId exactly (case aside): never a parent or a subdomain.
        XCTAssertEqual(PasskeyIdentities.matching(all, rpId: "example.com", allowed: []).map(\.itemId),
                       ["item-1", "item-3"])
        XCTAssertEqual(PasskeyIdentities.matching(all, rpId: "login.example.com", allowed: []).map(\.itemId),
                       ["item-2"])
        // A page that lists its credentials gets only those.
        XCTAssertEqual(PasskeyIdentities.matching(all, rpId: "example.com", allowed: [Data([3, 3])]).map(\.itemId),
                       ["item-3"])
        XCTAssertTrue(PasskeyIdentities.matching(all, rpId: "example.com", allowed: [Data([2, 2])]).isEmpty)
    }

    /// The identity iOS keeps names the site, the account and the
    /// credential; the key never leaves the vault.
    func testAPasskeyIdentityCarriesNoKey() {
        let p = passkey("example.com", id: 7)
        let identity = PasskeyIdentities.identity(p)
        XCTAssertEqual(identity.relyingPartyIdentifier, "example.com")
        XCTAssertEqual(identity.userName, "ana")
        XCTAssertEqual(identity.credentialID, Data([7, 7]))
        XCTAssertEqual(identity.userHandle, Data([9, 7]))
        XCTAssertEqual(identity.recordIdentifier, "item-7")
        // Without a user name, the login's title.
        XCTAssertEqual(PasskeyIdentities.identity(passkey("example.com", id: 8, user: "")).userName, "Example")
    }

    func testSuggestionsFollowTheAppsSetting() {
        let suite = "klav-passkeys-\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suite)!
        defer { defaults.removePersistentDomain(forName: suite) }
        XCTAssertTrue(PasskeyIdentities.suggestionsOn(defaults))
        defaults.set(false, forKey: "quickType")
        XCTAssertFalse(PasskeyIdentities.suggestionsOn(defaults))
        defaults.set(true, forKey: "quickType")
        XCTAssertTrue(PasskeyIdentities.suggestionsOn(defaults))
    }

    func testTheSheetSpeaksSpanish() {
        func spanish(_ key: String) -> String {
            guard let path = Bundle.main.path(forResource: "es", ofType: "lproj"), let bundle = Bundle(path: path) else {
                return "no es.lproj"
            }
            return bundle.localizedString(forKey: key, value: "MISSING", table: nil)
        }
        XCTAssertEqual(spanish("Save a passkey"), "Guardar una passkey")
        XCTAssertEqual(spanish("Unlock to sign in"), "Desbloquea para iniciar sesión")
        XCTAssertEqual(spanish("Replace the passkey?"), "¿Reemplazar la passkey?")
        XCTAssertEqual(spanish("Keep it"), "Conservarla")
        XCTAssertEqual(spanish("Klav keeps it on this iPhone. Open Klav to sync this passkey to your other devices."),
                       "Klav la guarda en este iPhone. Abre Klav para sincronizar esta passkey con tus otros dispositivos.")
        XCTAssertEqual(String.localizedStringWithFormat(spanish("Sign in with the passkey for %@, %@"), "ana", "Example"),
                       "Iniciar sesión con la passkey de ana, Example")
        XCTAssertEqual(String.localizedStringWithFormat(
            spanish("%@ already has a passkey for this account. The new one replaces it, and the old one stops working."),
            "Example"), "Example ya tiene una passkey para esta cuenta. La nueva la reemplaza y la anterior deja de funcionar.")
        XCTAssertEqual(spanish("Save a passkey with Klav"), "Guardar una passkey con Klav")
    }
}
