import AuthenticationServices
import CryptoKit
import SwiftUI
import XCTest
@testable import Klav

final class KlavTests: XCTestCase {
    private var home: URL!

    override func setUpWithError() throws {
        home = FileManager.default.temporaryDirectory
            .appendingPathComponent("klav-tests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: home)
    }

    func testAFreshHomeHasNoAccount() throws {
        let core = try KlavCore(homeDir: home.path)
        let status = core.status()
        XCTAssertFalse(status.hasAccount)
        XCTAssertFalse(status.unlocked)
        XCTAssertThrowsError(try core.items(query: ItemQuery())) { error in
            // Nothing is readable before an unlock.
            guard case KlavError.Locked = error else {
                return XCTFail("expected Locked, got \(error)")
            }
        }
        XCTAssertFalse(coreVersion().isEmpty)
    }

    /// ADR 0028: no default server under test, and the «Use my own server»
    /// field's aliases for klav.dev.
    func testTestsHaveNoDefaultServerAndKlavDevIsAnAlias() throws {
        XCTAssertNil(defaultServer(), "KLAV_NO_DEFAULT_SERVER must reach the tests")
        for alias in ["klav.dev", "api.klav.dev", "https://klav-server-production.up.railway.app/"] {
            XCTAssertEqual(try serverFromInput(text: alias), "https://api.klav.dev", alias)
        }
        XCTAssertEqual(try serverFromInput(text: "vault.example.com"), "https://vault.example.com")
        XCTAssertThrowsError(try serverFromInput(text: "http://vault.example.com"))
        XCTAssertEqual(serverName(server: "https://api.klav.dev"), "klav.dev")
        XCTAssertEqual(serverName(server: "https://vault.example.com"), "vault.example.com")
    }

    func testGeneratedPasswordsHaveTheRequestedLength() throws {
        let password = try generatePassword(length: 24, symbols: false)
        XCTAssertEqual(password.count, 24)
        XCTAssertTrue(password.allSatisfy { $0.isLetter || $0.isNumber })
    }

    func testTheGeneratorFollowsTypesAndSiteRules() throws {
        func input(_ kind: GeneratorType) -> GeneratorInput {
            GeneratorInput(kind: kind, length: 20, digits: true, symbols: true, words: 5, pinLength: 6)
        }
        let smart = try generate(input: input(.smart), host: nil)
        XCTAssertEqual(smart.value.count, 20)
        XCTAssertEqual(smart.strength, "very_strong")
        XCTAssertNil(smart.rulesDomain)
        let pin = try generate(input: input(.pin), host: nil)
        XCTAssertTrue(pin.value.count == 6 && pin.value.allSatisfy(\.isNumber))
        XCTAssertEqual(try generate(input: input(.memorable), host: nil).value.split(separator: "-").count, 5)
        let accor = try generate(input: input(.smart), host: "https://all.accor.com/login")
        XCTAssertEqual(accor.rulesDomain, "accor.com")
        // Letters, digits and symbols each keep their look (G10).
        let shown = colored("aB3$")
        XCTAssertEqual(String(shown.characters), "aB3$")
    }

    func testTheKeystoreWrapAgreesWithTheKeyHolder() throws {
        // The wrap side of the Secure Enclave keystore is plain CryptoKit:
        // the holder of the private key must reach the same secret.
        let holder = P256.KeyAgreement.PrivateKey()
        let wrap = try SecureEnclaveKeystore().wrap(publicKey: holder.publicKey.x963Representation)
        XCTAssertEqual(wrap.ephemeralPublic.count, 65)
        XCTAssertEqual(wrap.secret.count, 32)
        let peer = try P256.KeyAgreement.PublicKey(x963Representation: wrap.ephemeralPublic)
        let again = try holder.sharedSecretFromKeyAgreement(with: peer).withUnsafeBytes { Data($0) }
        XCTAssertEqual(again, wrap.secret)
        XCTAssertGreaterThan(deviceBootTime(), 0)
    }

    func testItemsAreGroupedByVaultAndProject() {
        func item(_ title: String, _ vault: String, _ project: String) -> ItemInfo {
            ItemInfo(id: title, reference: "", vaultId: vault, vault: vault, projectId: vault + "/" + project,
                     project: project, kind: .login, title: title, username: nil,
                     urls: ["https://\(title.lowercased()).com/login"], tags: [], version: 1,
                     updatedAt: 0, trashed: false)
        }
        let groups = ItemGroup.grouping([
            item("Zeta", "Personal", "Web"), item("GitHub", "Trabajo", "Infra"),
            item("alfa", "Personal", "Web"), item("AWS", "Trabajo", "Infra"),
        ])
        XCTAssertEqual(groups.map(\.vault), ["Personal", "Trabajo"])
        XCTAssertEqual(groups[0].items.map(\.title), ["alfa", "Zeta"])
        XCTAssertEqual(groups[1].items.map(\.title), ["AWS", "GitHub"])
        XCTAssertEqual(groups[0].items[0].subtitle, "alfa.com")
    }

    func testErrorsAreToldInTheInterfacesLanguage() {
        XCTAssertTrue(KlavError.WrongCredentials.userMessage.contains("master password"))
        XCTAssertEqual(passwordReason("The master password is required after a restart."),
                       "after the iPhone restarts")
        XCTAssertEqual(passwordReason("The master password is required every 14 days."), "every 14 days")
        XCTAssertTrue(KlavError.BiometryUnavailable(message: "Face ID changed on this device")
            .userMessage.contains("changed"))
        XCTAssertEqual(spanish("The master password or the Secret Key isn’t right."),
                       "La contraseña maestra o el Secret Key no son correctos.")
        XCTAssertEqual(spanish("after the iPhone restarts"), "después de reiniciar el iPhone")
    }

    func testTheAutofillWelcomeOnlyAsksWhileKlavIsOff() {
        XCTAssertTrue(AutofillWelcome.offered(enabled: false, dismissed: false))
        // «Not now» (or turning it on once) is not asked again.
        XCTAssertFalse(AutofillWelcome.offered(enabled: false, dismissed: true))
        XCTAssertFalse(AutofillWelcome.offered(enabled: true, dismissed: false))
        // Before iOS answers, nothing pops up.
        XCTAssertFalse(AutofillWelcome.offered(enabled: nil, dismissed: false))
    }

    func testTheAutofillWelcomeNamesWhatSettingsShows() {
        // iOS calls the page «Autorrelleno y contraseñas» in Spanish.
        XCTAssertEqual(spanish("AutoFill & Passwords"), "Autorrelleno y contraseñas")
        XCTAssertEqual(spanish("Open AutoFill & Passwords"), "Abrir Autorrelleno y contraseñas")
        XCTAssertEqual(spanish("Fill passwords with Klav"), "Rellena contraseñas con Klav")
        XCTAssertEqual(spanish("Not now"), "Ahora no")
        XCTAssertEqual(Title("Klav fills in now").text, Text("Klav fills in now"))
    }

    func testAutoLockDefaultsToOneMinute() {
        XCTAssertEqual(AutoLock.oneMinute.rawValue, 60)
        XCTAssertEqual(AutoLock.allCases.first, .immediately)
    }

    func testFieldsAreNamedInTheInterfacesLanguageUnlessRenamed() {
        XCTAssertEqual(fieldName(name: "password", label: "Password"), "Password")
        XCTAssertEqual(fieldName(name: "api_key", label: ""), "API key")
        XCTAssertEqual(fieldName(name: "password", label: "PIN del banco"), "PIN del banco")
        XCTAssertEqual(fieldName(name: "custom", label: ""), "custom")
        XCTAssertEqual(displayHost("https://github.com/login"), "github.com")
        XCTAssertEqual(Kind.apiKey.label, "API key")
        XCTAssertEqual(Kind.login.label, "Login")
        XCTAssertEqual(spanish("Password"), "Contraseña")
        XCTAssertEqual(spanish("kind.login"), "Inicio de sesión")
        XCTAssertEqual(spanish("Login"), "Login")
    }

    func testCopiedValuesExpireAndStayOnThisDevice() throws {
        Clipboard.copy("valor-de-prueba")
        XCTAssertEqual(UIPasteboard.general.string, "valor-de-prueba")
        XCTAssertEqual(Clipboard.clearAfter, 30)
        UIPasteboard.general.items = []
    }

    func testQuickTypeSuggestionsCarryNoSecrets() {
        let github = CredentialIdentity(
            itemId: "i1", title: "GitHub", username: "ana",
            hosts: ["github.com", "gist.github.com"], hasPassword: true, hasTotp: true)
        let note = CredentialIdentity(
            itemId: "i2", title: "Wiki", username: "", hosts: ["wiki.test"],
            hasPassword: true, hasTotp: false)
        let out = IdentityStore.suggestions(for: [github, note])
        let passwords = out.compactMap { $0 as? ASPasswordCredentialIdentity }
        let codes = out.compactMap { $0 as? ASOneTimeCodeCredentialIdentity }
        XCTAssertEqual(passwords.map(\.serviceIdentifier.identifier), ["github.com", "gist.github.com", "wiki.test"])
        XCTAssertEqual(passwords.map(\.user), ["ana", "ana", "Wiki"])
        XCTAssertEqual(codes.map(\.serviceIdentifier.identifier), ["github.com", "gist.github.com"])
        XCTAssertEqual(Set(out.compactMap(\.recordIdentifier)), ["i1", "i2"])
    }

    func testNotificationsOnlyCarryAKindAndAnID() {
        XCTAssertEqual(PushRoute(userInfo: ["klav": ["type": "approval", "id": "a1"]]), .approval("a1"))
        XCTAssertEqual(PushRoute(userInfo: ["klav": ["type": "agent", "id": "g1"]]), .agent("g1"))
        XCTAssertNil(PushRoute(userInfo: ["klav": ["type": "other", "id": "x"]]))
        XCTAssertNil(PushRoute(userInfo: ["aps": ["alert": "hola"]]))
        XCTAssertEqual(Push.hex(Data([0x0a, 0xff, 0x00])), "0aff00")
        XCTAssertTrue(Push.sandbox, "debug builds use the APNs sandbox")
    }

    func testRequestsAreToldLikeTheExtension() {
        XCTAssertEqual(RequestWords.wants("totp", "GitHub"), "Wants the one-time code for GitHub")
        let target = RequestWords.target("klav://Personal/General/Banco%20Azul/password")
        XCTAssertEqual(target.title, "Banco Azul (password)")
        XCTAssertEqual(target.where, "Personal / General")
        // References show names as written; both forms read the same.
        let written = RequestWords.target("klav://Personal/Café con leche/Banco Azul/password")
        XCTAssertEqual(written.title, "Banco Azul (password)")
        XCTAssertEqual(written.where, "Personal / Café con leche")
        XCTAssertEqual(RequestWords.target("klav://Personal/General/50%25 off").title, "50% off")
        XCTAssertEqual(RequestWords.target("Personal/General").title, "Personal/General")
        let now = Date(timeIntervalSince1970: 1_000)
        XCTAssertEqual(RequestWords.remaining(until: 1_010_000, now: now), "expires in 1 min")
        XCTAssertEqual(RequestWords.remaining(until: 1_000_000 + 7_200_000, now: now), "expires in 2 hours")
        XCTAssertEqual(RequestWords.remaining(until: 999_000, now: now), "already expired")
        XCTAssertEqual(spanish("Wants the one-time code for %@"), "Quiere el código de un solo uso de %@")
        XCTAssertEqual(spanish("expires in %lld hours"), "caduca en %lld horas")
    }

    // MARK: Languages

    /// `key` from the string catalog in Spanish (the tests run in English).
    func spanish(_ key: String, table: String? = nil) -> String {
        guard let path = Bundle.main.path(forResource: "es", ofType: "lproj"), let bundle = Bundle(path: path) else {
            return "no es.lproj"
        }
        return bundle.localizedString(forKey: key, value: "MISSING", table: table)
    }

    func testTheAppSpeaksEnglishAndSpanish() {
        XCTAssertEqual(Bundle.main.developmentLocalization, "en")
        XCTAssertTrue(Bundle.main.localizations.contains("es"))
        XCTAssertEqual(String(localized: "Unlock with Face ID"), "Unlock with Face ID")
        XCTAssertEqual(spanish("Unlock with Face ID"), "Desbloquear con Face ID")
        // Our own views (Title, SectionLabel…) take keys the compiler does
        // not extract: they are in the catalog by hand.
        XCTAssertEqual(spanish("Open Klav first"), "Abre Klav primero")
        XCTAssertEqual(spanish("%@ wants to join"), "%@ quiere unirse")
        XCTAssertEqual(spanish("They match: approve"), "Coinciden: aprobar")
        // Approval pushes carry only these keys.
        XCTAssertEqual(String(localized: "PUSH_APPROVAL_TITLE"), "An agent is asking for permission")
        XCTAssertEqual(spanish("PUSH_APPROVAL_TITLE"), "Un agente pide permiso")
        XCTAssertEqual(spanish("NSFaceIDUsageDescription", table: "InfoPlist"),
                       "Klav usa Face ID para abrir tu bóveda y confirmar las aprobaciones de tus agentes.")
        // Plurals and arguments that change places.
        XCTAssertEqual(String(localized: "Changes in \(1) seconds"), "Changes in 1 second")
        XCTAssertEqual(String.localizedStringWithFormat(spanish("Version %llu · updated %@"), UInt64(3), "ayer"),
                       "Versión 3 · actualizado ayer")
    }

    /// A literal given to our own views is a catalog key, as with `Text`;
    /// a `String` (an item's title) is shown as is.
    func testOurViewsTakeLiteralsAsKeys() {
        XCTAssertEqual(Title("Open Klav first").text, Text("Open Klav first"))
        XCTAssertNotEqual(Title("Open Klav first").text, Text(verbatim: "Open Klav first"))
        XCTAssertEqual(Title(String("GitHub")).text, Text(verbatim: "GitHub"))
        XCTAssertEqual(SectionLabel("Notes").text, Text("Notes"))
        XCTAssertEqual(SectionLabel(String("Personal / General")).text, Text(verbatim: "Personal / General"))
        XCTAssertEqual(FieldLabel("Where").text, Text("Where"))
        XCTAssertEqual(placeholder("Search your vault"), placeholder(LocalizedStringKey("Search your vault")))
        XCTAssertNotEqual(placeholder("Search your vault"), placeholder(String("Search your vault")))
    }

    func testEveryCatalogEntryHasItsSpanish() throws {
        let url = try XCTUnwrap(Bundle.main.url(forResource: "Localizable", withExtension: "strings",
                                                subdirectory: nil, localization: "es"))
        let table = try XCTUnwrap(NSDictionary(contentsOf: url) as? [String: String])
        XCTAssertGreaterThan(table.count, 240)
        for (key, value) in table {
            XCTAssertFalse(value.isEmpty, key)
        }
    }

    // MARK: Site icons

    func testSiteLogosComeFromTheShippedMapOnly() {
        XCTAssertGreaterThan(SiteIcons.logos.count, 300)
        let github = SiteIcons.logo(for: "github.com")
        XCTAssertNotNil(github)
        XCTAssertEqual(SiteIcons.logo(for: "gist.github.com"), github)
        XCTAssertNotNil(SiteIcons.logo(for: "mail.google.com"))
        XCTAssertNotEqual(SiteIcons.logo(for: "mail.google.com"), SiteIcons.logo(for: "google.com"))
        XCTAssertNil(SiteIcons.logo(for: "evilgithub.com"))
        XCTAssertNil(SiteIcons.logo(for: "github.com.evil.example"))
        XCTAssertNil(SiteIcons.logo(for: "localhost"))
        XCTAssertEqual(SiteIcons.host("https://www.GitHub.com/login?x=1"), "github.com")
        XCTAssertEqual(SiteIcons.host("github.com"), "github.com")
        XCTAssertNil(SiteIcons.logo(forSite: nil))
        XCTAssertNil(SiteIcons.logo(forSite: "not a url"))
    }

    func testEveryShippedLogoParses() {
        for (domain, d) in SiteIcons.logos {
            guard let path = LogoPath.parse(d) else { return XCTFail("\(domain) does not parse") }
            let box = path.boundingRect
            XCTAssertFalse(box.isEmpty, domain)
            XCTAssertTrue(CGRect(x: -0.5, y: -0.5, width: 25, height: 25).contains(box), "\(domain): \(box)")
        }
    }

    func testLogoPathsReadTheMapsShortNumbers() {
        XCTAssertEqual(LogoPath.tokens("M.5-.25L12 4Z"),
                       [.command("M"), .number(0.5), .number(-0.25), .command("L"), .number(12), .number(4), .command("Z")])
        XCTAssertEqual(LogoPath.tokens("M1.5.5"), [.command("M"), .number(1.5), .number(0.5)])
        XCTAssertEqual(LogoPath.tokens("C1-1 2-1 3 0"),
                       [.command("C"), .number(1), .number(-1), .number(2), .number(-1), .number(3), .number(0)])
        XCTAssertNil(LogoPath.tokens("M0 0A1 1 0 0 1 2 2"), "arcs never reach the map")
        XCTAssertNil(LogoPath.parse("L1 1"), "a path starts with M")
        XCTAssertNil(LogoPath.parse("M0 0C1 1"), "a curve needs six numbers")
        let square = LogoPath.parse("M0 0L24 0L24 24L0 24Z")
        XCTAssertEqual(square?.boundingRect, CGRect(x: 0, y: 0, width: 24, height: 24))
    }

    // MARK: VoiceOver

    /// What VoiceOver can land on: the hosting view's accessibility
    /// elements, opened down to the leaves.
    @MainActor
    private func spokenLabels(_ root: NSObject) -> [String] {
        var out: [String] = []
        func walk(_ node: NSObject, depth: Int) {
            guard depth < 40 else { return }
            if node.isAccessibilityElement {
                out.append(node.accessibilityLabel ?? "")
                return
            }
            let children = (node.accessibilityElements as? [NSObject])
                ?? (node as? UIView)?.subviews ?? []
            for child in children { walk(child, depth: depth + 1) }
        }
        walk(root, depth: 0)
        return out
    }

    @MainActor
    func testVoiceOverReadsTheLiveCodeOnce() async throws {
        for copyable in [true, false] {
            let code = LiveCode(id: "i1", title: "GitHub", style: .row,
                                fetch: { _ in TotpInfo(code: "123456", remaining: 20, period: 30) },
                                onCopy: copyable ? { _ in } : nil)
            let host = UIHostingController(rootView: code.frame(width: 200, height: 80))
            let window = UIWindow(frame: CGRect(x: 0, y: 0, width: 200, height: 80))
            window.rootViewController = host
            window.makeKeyAndVisible()
            var labels: [String] = []
            for _ in 0..<40 {
                try await Task.sleep(for: .milliseconds(50))
                host.view.layoutIfNeeded()
                labels = spokenLabels(host.view)
                if labels.contains(where: { $0.contains("1 2 3 4 5 6") }) { break }
            }
            let withCode = labels.filter { $0.contains("1 2 3 4 5 6") || $0.contains("123 456") || $0.contains("123456") }
            XCTAssertEqual(withCode.count, 1, "copyable \(copyable): \(labels)")
            XCTAssertTrue(withCode.first?.hasPrefix("One-time code for GitHub: 1 2 3 4 5 6.") == true, "\(labels)")
            window.isHidden = true
        }
    }

    // MARK: Large text

    /// The elements VoiceOver can land on, with where they are on screen.
    @MainActor
    func spokenElements(_ root: NSObject) -> [(label: String, frame: CGRect)] {
        var out: [(String, CGRect)] = []
        func walk(_ node: NSObject, depth: Int) {
            guard depth < 40 else { return }
            if node.isAccessibilityElement {
                out.append((node.accessibilityLabel ?? "", node.accessibilityFrame))
                return
            }
            let children = (node.accessibilityElements as? [NSObject])
                ?? (node as? UIView)?.subviews ?? []
            for child in children { walk(child, depth: depth + 1) }
        }
        walk(root, depth: 0)
        return out
    }

    /// Lays a view out at the width of an iPhone 17's item block and
    /// returns what VoiceOver finds in it.
    @MainActor
    func hosted<V: View>(_ view: V, width: CGFloat = 353) async throws -> [(label: String, frame: CGRect)] {
        let host = UIHostingController(rootView: view.frame(width: width).fixedSize(horizontal: false, vertical: true))
        let size = host.sizeThatFits(in: CGSize(width: width, height: 4000))
        let window = UIWindow(frame: CGRect(origin: .zero, size: CGSize(width: width, height: max(size.height, 1))))
        window.rootViewController = host
        window.makeKeyAndVisible()
        defer { window.isHidden = true }
        var elements: [(label: String, frame: CGRect)] = []
        for _ in 0..<20 {
            try await Task.sleep(for: .milliseconds(50))
            host.view.layoutIfNeeded()
            elements = spokenElements(host.view)
            if !elements.isEmpty { break }
        }
        return elements
    }

    /// With accessibility text the field's name keeps the whole width (one
    /// line, never "Passwor" / "d") and «Show» and copy go under the value;
    /// at the usual sizes they stay beside it.
    @MainActor
    func testItemRowsStackWithAccessibilityText() async throws {
        let sizes: [DynamicTypeSize] = [.large, .xxxLarge, .accessibility1, .accessibility3, .accessibility5]
        for name in ["Password", "Contraseña"] {
            let field = FieldInfo(name: "password", label: name, kind: .password, secret: true, filled: true, value: nil)
            for size in sizes {
                let row = FieldRow(field: field, revealed: nil, onToggle: {}, onCopy: {})
                    .environment(\.dynamicTypeSize, size)
                let elements = try await hosted(row)
                let label = try XCTUnwrap(elements.first { $0.label == name }, "\(size): \(elements.map(\.label))")
                let show = try XCTUnwrap(elements.first { $0.label == "Show \(name)" }, "\(size): \(elements.map(\.label))")
                let copy = try XCTUnwrap(elements.first { $0.label == "Copy \(name)" }, "\(size): \(elements.map(\.label))")

                let line = UIHostingController(rootView: RowLabel(Text(verbatim: name)).environment(\.dynamicTypeSize, size))
                    .sizeThatFits(in: CGSize(width: 10_000, height: 10_000))
                XCTAssertLessThanOrEqual(label.frame.height, line.height + 1, "\(name) at \(size) takes more than one line")
                XCTAssertGreaterThanOrEqual(label.frame.width, line.width - 1, "\(name) at \(size) is cut")

                if size.isAccessibilitySize {
                    XCTAssertGreaterThanOrEqual(show.frame.minY, label.frame.maxY, "\(size): «Show» goes under the value")
                    XCTAssertGreaterThanOrEqual(copy.frame.minY, label.frame.maxY, "\(size): copy goes under the value")
                } else {
                    XCTAssertGreaterThan(show.frame.minX, label.frame.maxX, "\(size): «Show» stays beside the value")
                    XCTAssertLessThan(show.frame.minY, label.frame.maxY, "\(size): «Show» stays beside the value")
                }
            }
        }
    }

    /// Two passwords changed in the same minute show the same text; VoiceOver
    /// hears their place in the list as well, so no two rows read the same.
    @MainActor
    func testVoiceOverTellsPreviousPasswordsOfTheSameMinuteApart() async throws {
        let minute: Int64 = 1_793_000_000_000
        let entries = (0..<3).map { i in
            PreviousPasswordInfo(index: UInt32(i), field: "password", label: "", fromMs: minute + Int64(i) * 1_000,
                                 toMs: minute + Int64(i) * 1_000 + 2_000, unconfirmed: false)
        }
        let list = VStack(spacing: 0) {
            ForEach(Array(entries.enumerated()), id: \.element.index) { position, entry in
                PreviousPasswordRow(entry: entry, position: position + 1, count: entries.count, shown: nil,
                                    onToggle: {}, onCopy: {})
            }
        }
        let labels = try await hosted(list).map(\.label).filter { $0 != "Hidden" }
        XCTAssertEqual(labels.count, 9, "\(labels)")
        XCTAssertEqual(Set(labels).count, labels.count, "\(labels)")
        for position in 1...3 {
            XCTAssertEqual(labels.filter { $0.hasSuffix(", \(position) of 3") }.count, 3, "\(labels)")
        }
        XCTAssertTrue(labels.contains { $0.hasPrefix("Show the previous Password of ") && $0.hasSuffix(", 2 of 3") }, "\(labels)")
        XCTAssertEqual(String.localizedStringWithFormat(spanish("%@, %lld of %lld"), "Contraseña, 4 nov 2026", Int64(2), Int64(3)),
                       "Contraseña, 4 nov 2026, 2 de 3")
        XCTAssertEqual(String.localizedStringWithFormat(spanish("Show the previous %@ of %@, %lld of %lld"),
                                                        "contraseña", "4 nov", Int64(1), Int64(3)),
                       "Mostrar contraseña anterior del 4 nov, 1 de 3")
    }
}

