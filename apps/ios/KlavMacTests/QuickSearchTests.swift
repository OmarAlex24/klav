import XCTest
@testable import Klav

/// The menu bar's quick search over the sample engine: the list it keeps,
/// how it matches, what a row opens and what its buttons copy.
@MainActor
final class QuickSearchTests: XCTestCase {
    private func settle(until done: @escaping @MainActor () -> Bool) async throws {
        for _ in 0..<100 where !done() {
            try await Task.sleep(for: .milliseconds(30))
        }
        XCTAssertTrue(done(), "timed out")
    }

    private func unlockedModel(touchID: Bool = true) async throws -> MacModel {
        let model = MacModel.sample(SampleEngine(locked: false, touchID: touchID))
        model.refresh()
        try await settle { model.phase == .unlocked && model.quickItems != nil }
        return model
    }

    private func item(_ id: String, _ title: String, kind: Kind = .login, user: String? = nil,
                      urls: [String] = [], tags: [String] = []) -> ItemInfo {
        ItemInfo(id: id, reference: "klav://V/P/\(title)", vaultId: "v", vault: "V", projectId: "p", project: "P",
                 kind: kind, title: title, username: user, urls: urls, tags: tags, version: 1, updatedAt: 0,
                 trashed: false)
    }

    // MARK: Matching

    /// Typed text matches like klavd's list (title, user name, sites and
    /// tags, any case), titles that start with it first.
    func testItMatchesLikeKlavdWithTitlesThatStartWithItFirst() {
        let items = [
            item("1", "Old northflank login"),
            item("2", "Cloudflare", user: "ops@northflank.dev"),
            item("3", "Northflank", user: "ana"),
            item("4", "Deploy key", kind: .apiKey, urls: ["https://app.NORTHFLANK.com"]),
            item("5", "Registry", tags: ["northflank"]),
            item("6", "GitHub", user: "ana-dev", urls: ["https://github.com"]),
        ]
        XCTAssertEqual(QuickSearch.filter(items, query: "  NorthF ").map(\.id), ["3", "1", "2", "4", "5"])
        XCTAssertEqual(QuickSearch.filter(items, query: "").map(\.id), items.map(\.id), "nothing typed: every item")
        XCTAssertEqual(QuickSearch.filter(items, query: "zzz"), [])
    }

    /// The search runs in memory over the model's list: what it finds is
    /// what the engine's own search finds.
    func testTheLocalSearchFindsWhatTheEngineFinds() async throws {
        let model = try await unlockedModel()
        let all = try XCTUnwrap(model.quickItems)
        XCTAssertFalse(all.isEmpty)
        for text in ["git", "ana", "AWS", "stripe.com", "x"] {
            let engine = try await model.run {
                try $0.items(query: ItemQuery(vaultId: nil, projectId: nil, text: text, kind: nil, trash: false))
            }
            XCTAssertEqual(Set(QuickSearch.filter(all, query: text).map(\.id)), Set(engine.map(\.id)), text)
        }
    }

    // MARK: The model's list

    /// Unlocking reads the list and which items have a code; locking
    /// forgets both, and a read that started before never lands after.
    func testTheListIsReadOnUnlockAndForgottenOnLock() async throws {
        let model = try await unlockedModel()
        try await settle { !model.quickCodes.isEmpty }
        XCTAssertTrue(model.quickCodes.contains("i-gh"), "GitHub has a code")
        XCTAssertFalse(model.quickCodes.contains("i-cfe"), "CFE has none")
        model.lock()
        try await settle { model.phase == .locked }
        XCTAssertNil(model.quickItems)
        XCTAssertTrue(model.quickCodes.isEmpty)
        model.loadQuickItems()
        try await Task.sleep(for: .milliseconds(150))
        XCTAssertNil(model.quickItems, "nothing is read while locked")
    }

    /// Reading again (something changed) keeps the last list on screen
    /// until the new one lands: the results never go empty in between.
    func testReadingAgainKeepsTheLastListUntilTheNewOneLands() async throws {
        let model = try await unlockedModel()
        let before = try XCTUnwrap(model.quickItems)
        let found = QuickSearch.filter(before, query: "git")
        XCTAssertFalse(found.isEmpty)
        let landed = model.quickReadsLanded
        model.changed()
        XCTAssertEqual(model.quickItems, before, "the old list stays while the new one is read")
        XCTAssertEqual(QuickSearch.filter(model.quickItems ?? [], query: "git"), found)
        try await settle { model.quickReadsLanded > landed }
        XCTAssertEqual(QuickSearch.filter(model.quickItems ?? [], query: "git").map(\.id), found.map(\.id))
    }

    /// One read per generation: the 2 s refresh asks again for nothing.
    func testTheListIsReadOncePerGeneration() async throws {
        let model = try await unlockedModel()
        let started = model.quickReadsStarted
        model.loadQuickItems()
        model.refresh()
        try await Task.sleep(for: .milliseconds(150))
        XCTAssertEqual(model.quickReadsStarted, started)
    }

    // MARK: Opening an item

    /// Clicking a result opens the window on it, in All items, whatever
    /// section the window showed.
    func testOpeningAResultSelectsItInAllItems() async throws {
        let model = try await unlockedModel()
        model.section = .sandboxes
        model.selectedItem = "i-cfe"
        let requests = model.itemOpenRequests
        model.openItem("i-gh")
        XCTAssertEqual(model.section, .vault(.all))
        XCTAssertEqual(model.selectedItem, "i-gh")
        XCTAssertEqual(model.itemOpenRequests, requests + 1, "the vault list drops its own search")

        model.section = .vault(.kind(.apiKey))
        model.openItem("i-mail")
        XCTAssertEqual(model.section, .vault(.all))
        XCTAssertEqual(model.selectedItem, "i-mail")
    }

    // MARK: Buttons

    func testEachKindGetsItsButtons() {
        XCTAssertEqual(QuickSearch.actions(item("1", "GitHub", user: "ana"), hasCode: true), [.username, .password, .code])
        XCTAssertEqual(QuickSearch.actions(item("1", "Forum"), hasCode: false), [.password])
        XCTAssertEqual(QuickSearch.actions(item("1", "Discord", kind: .totp, user: "ana"), hasCode: false), [.username, .code])
        XCTAssertEqual(QuickSearch.actions(item("1", "Stripe", kind: .apiKey), hasCode: false), [.key])
        XCTAssertEqual(QuickSearch.actions(item("1", "Note", kind: .note), hasCode: false), [])
        XCTAssertEqual(QuickSearch.primary(item("1", "GitHub", user: "ana"), hasCode: true), .password)
        XCTAssertEqual(QuickSearch.primary(item("1", "Discord", kind: .totp), hasCode: false), .code)
        XCTAssertEqual(QuickSearch.primary(item("1", "Stripe", kind: .apiKey), hasCode: false), .key)
        XCTAssertNil(QuickSearch.primary(item("1", "Note", kind: .note), hasCode: false), "Return opens it")
    }

    /// «Key» copies `api_key`, the main secret, else the first secret.
    func testTheKeyIsTheMainSecretElseTheFirstSecret() {
        func detail(_ fields: [FieldInfo]) -> ItemDetail {
            ItemDetail(info: item("1", "K", kind: .apiKey), fields: fields, hasNotes: false, hasTotp: false, attachments: [])
        }
        func field(_ name: String, _ kind: FieldType, secret: Bool = true, filled: Bool = true) -> FieldInfo {
            FieldInfo(name: name, label: name, kind: kind, secret: secret, filled: filled, value: nil)
        }
        XCTAssertEqual(QuickSearch.keyField(of: detail([field("token", .concealed), field("api_key", .concealed)])), "api_key")
        XCTAssertEqual(QuickSearch.keyField(of: detail([field("host", .text, secret: false), field("totp", .totp),
                                                        field("secret", .concealed)])), "secret")
        XCTAssertNil(QuickSearch.keyField(of: detail([field("secret", .concealed, filled: false)])))
    }

    /// The API key's button copies its key, through the presence gate
    /// like the window's copy.
    func testTheApiKeyButtonCopiesItsKey() async throws {
        let model = try await unlockedModel()
        // Its key is in `secret`, not `api_key`, like an imported one.
        let stripe = try XCTUnwrap(model.quickItems?.first { $0.id == "i-stripe" })
        let value = try await model.quickValue(.key, of: stripe)
        let expected = try await model.run { try $0.fieldValue(id: stripe.id, field: "secret") }
        XCTAssertEqual(value, expected)
    }

    /// The other buttons copy what they say.
    func testTheLoginButtonsCopyWhatTheySay() async throws {
        let model = try await unlockedModel()
        let github = try XCTUnwrap(model.quickItems?.first { $0.id == "i-gh" })
        let user = try await model.quickValue(.username, of: github)
        XCTAssertEqual(user, "ana-dev")
        let password = try await model.quickValue(.password, of: github)
        let expected = try await model.run { try $0.fieldValue(id: "i-gh", field: "password") }
        XCTAssertEqual(password, expected)
        let code = try await model.quickValue(.code, of: github)
        XCTAssertFalse(code.isEmpty)
    }
}
