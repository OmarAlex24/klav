import XCTest
@testable import Klav

/// Creating and editing items on the Mac (the iPhone's editor, `ItemDraft`)
/// over the sample engine: no klavd, no real home. What klavd itself does
/// with them is tested in Rust (`crates/klav-ffi/tests/daemon.rs`).
@MainActor
final class ItemEditorTests: XCTestCase {
    private func unlocked() async throws -> (MacModel, SampleEngine) {
        let engine = SampleEngine(locked: false, touchID: true, signedOut: false, deletion: "")
        let model = MacModel.sample(engine)
        model.refresh()
        for _ in 0..<100 where model.phase != .unlocked { try await Task.sleep(for: .milliseconds(30)) }
        XCTAssertEqual(model.phase, .unlocked)
        return (model, engine)
    }

    // MARK: ItemDraft

    func testANewLoginSendsOnlyWhatWasTyped() {
        let specs = ItemDraft.templateFields(.login)
        XCTAssertEqual(specs.map(\.name), ["username", "password", "totp"])
        XCTAssertEqual(specs.filter(\.secret).map(\.name), ["password", "totp"])
        XCTAssertEqual(specs.filter(\.generate).map(\.name), ["password"])
        let project = ProjectInfo(id: "p2", vaultId: "v2", vault: "Trabajo", name: "Backend",
                                  repos: ["github.com/acme/backend"])
        XCTAssertEqual(project.primaryRepoShort, "acme/backend")
        XCTAssertEqual(project.displayWithRepo, "Trabajo / Backend · acme/backend")
        let input = ItemDraft.newItem(kind: .login, title: "  Linear ", project: project, specs: specs,
                                      typed: ["username": "ana", "password": "pw", "totp": ""],
                                      site: "linear.app", notes: "")
        XCTAssertEqual(input.title, "Linear")
        XCTAssertEqual(input.projectId, "p2")
        XCTAssertEqual(input.vaultId, "v2")
        XCTAssertEqual(input.fields.map(\.name), ["username", "password"], "an empty field isn't sent")
        XCTAssertEqual(input.urls, ["https://linear.app"])
        XCTAssertNil(input.notes)
    }

    func testACodeComesFromAKeyOrALink() {
        // klav-core reads either; the editor passes the field as typed.
        let specs = ItemDraft.templateFields(.login)
        for code in ["JBSWY3DPEHPK3PXP", "otpauth://totp/Acme:ana?secret=JBSWY3DPEHPK3PXP&issuer=Acme"] {
            let input = ItemDraft.newItem(kind: .login, title: "Acme", project: nil, specs: specs,
                                          typed: ["totp": code], site: "", notes: "")
            XCTAssertEqual(input.fields, [FieldEdit(name: "totp", value: code)])
        }
    }

    func testOnlyALoginKeepsItsSite() {
        let input = ItemDraft.newItem(kind: .apiKey, title: "Stripe", project: nil,
                                      specs: ItemDraft.templateFields(.apiKey), typed: ["api_key": "sk"],
                                      site: "stripe.com", notes: "rotate yearly")
        XCTAssertEqual(input.urls, [])
        XCTAssertEqual(input.notes, "rotate yearly")
        XCTAssertNil(ItemDraft.normalizedSite("  "))
        XCTAssertEqual(ItemDraft.normalizedSite("http://x.test"), "http://x.test")
    }

    func testAnEditSendsOnlyWhatChanged() throws {
        let engine = SampleEngine(locked: false, touchID: true, signedOut: false, deletion: "")
        let detail = try engine.item(id: "i-gh")
        let specs = ItemDraft.editFields(detail)
        XCTAssertEqual(specs.first { $0.name == "password" }?.placeholder, String(localized: "Unchanged"),
                       "a filled secret is never pre-filled")
        var typed = ItemDraft.plainValues(detail)
        XCTAssertNil(typed["password"])
        // Nothing changed: an empty edit.
        let same = ItemDraft.edit(of: detail, title: detail.info.title, specs: specs, typed: typed,
                                  site: "", notes: "", notesBefore: nil)
        XCTAssertNil(same.title)
        XCTAssertEqual(same.set, [])
        XCTAssertEqual(same.addUrls, [])
        XCTAssertNil(same.notes)
        // A new user name and a new password, a site, and the notes opened
        // but left as they were.
        typed["username"] = "ana-new"
        typed["password"] = "fresh"
        let changed = ItemDraft.edit(of: detail, title: "GitHub ", specs: specs, typed: typed,
                                     site: "gist.github.com", notes: "Recovery codes are in the safe.",
                                     notesBefore: "Recovery codes are in the safe.")
        XCTAssertNil(changed.title, "spaces around the same title aren't a change")
        XCTAssertEqual(Set(changed.set.map(\.name)), ["username", "password"])
        XCTAssertEqual(changed.addUrls, ["https://gist.github.com"])
        XCTAssertNil(changed.notes)
    }

    func testATakenTitleIsSeenAsKlavClientSeesIt() {
        let items = [ItemInfo(id: "a", reference: "klav://Personal/General/GitHub", vaultId: "v1", vault: "Personal",
                              projectId: "p1", project: "General", kind: .login, title: "GitHub", username: nil,
                              urls: [], tags: [], version: 1, updatedAt: 0, trashed: false)]
        XCTAssertTrue(titleTaken(" github ", in: "p1", items: items))
        XCTAssertFalse(titleTaken("GitHub", in: "p2", items: items), "another project may have it")
        XCTAssertFalse(titleTaken("GitLab", in: "p1", items: items))
        XCTAssertFalse(titleTaken("GitHub", in: nil, items: items))
    }

    // MARK: The Mac's model

    func testNewItemFollowsTheListAndOpensTheItemSaved() async throws {
        let (model, _) = try await unlocked()
        model.section = .vault(.kind(.card))
        model.newItem()
        XCTAssertEqual(model.editor, .create(.card), "the kind the list shows")
        model.editor = nil
        model.section = .vault(.kind(.sshKey))
        model.newItem()
        XCTAssertEqual(model.editor, .create(.login), "a kind the editor can't make: a login")
        model.editor = nil
        model.section = .agents
        model.newItem()
        XCTAssertEqual(model.section, .vault(.all))
        model.editor = nil

        let input = ItemDraft.newItem(kind: .login, title: "Linear", project: nil,
                                      specs: ItemDraft.templateFields(.login), typed: ["password": "pw"],
                                      site: "linear.app", notes: "")
        let info = try await model.run { try $0.createItem(input: input) }
        model.section = .vault(.kind(.card))
        model.saved(info, created: true)
        XCTAssertNil(model.editor)
        XCTAssertEqual(model.section, .vault(.all), "the list would hide the new login")
        XCTAssertEqual(model.selectedItem, info.id)
        XCTAssertEqual(model.toast?.text, String(localized: "Saved to the vault."))
    }

    func testASecondItemWithTheSameTitleIsRefused() async throws {
        let (model, _) = try await unlocked()
        let input = NewItemInput(kind: .login, title: "github", vaultId: "v2", projectId: "p2")
        do {
            _ = try await model.run { try $0.createItem(input: input) }
            XCTFail("a repeated title")
        } catch KlavError.Invalid {}
    }

    func testEditingNeedsAnOpenItemInTheVault() async throws {
        let (model, _) = try await unlocked()
        model.selectedItem = nil
        model.editSelected()
        XCTAssertNil(model.editor)
        model.selectedItem = "i-gh"
        model.section = .health
        model.editSelected()
        XCTAssertNil(model.editor, "⌘E only edits what the vault shows")
        model.section = .vault(.all)
        model.editSelected()
        XCTAssertEqual(model.editor, .edit("i-gh"))
    }

    /// ⌘N and ⌘E never replace an open sheet. What the person typed lives
    /// in the editor sheet's own state, which SwiftUI keeps while
    /// `model.editor` stays the same request; so the request staying put is
    /// what keeps the draft.
    func testNothingOpensOverAnOpenSheet() async throws {
        let (model, _) = try await unlocked()
        model.selectedItem = "i-gh"
        model.editSelected()
        let editing = try XCTUnwrap(model.editor)
        XCTAssertEqual(editing, .edit("i-gh"))
        XCTAssertTrue(model.sheetOpen)

        // ⌘N halfway through an edit: the edit stays, and so does the list.
        model.section = .vault(.kind(.card))
        model.newItem()
        XCTAssertEqual(model.editor, editing, "⌘N doesn't replace the edit")
        XCTAssertEqual(model.editor?.id, editing.id)
        model.section = .health
        model.newItem()
        XCTAssertEqual(model.section, .health, "nor moves the window to the vault")
        model.section = .vault(.all)
        model.selectedItem = "i-cf"
        model.editSelected()
        XCTAssertEqual(model.editor, editing, "⌘E doesn't swap the item being edited")

        // ⌘N on a new item's editor keeps it too.
        model.editor = .create(.note)
        model.newItem()
        XCTAssertEqual(model.editor, .create(.note))
        model.editor = nil

        // The trash's confirmation: no editor over it.
        model.trashing = try await model.run { try $0.item(id: "i-gh") }.info
        model.editSelected()
        XCTAssertNil(model.editor, "⌘E with the trash's confirmation open")
        model.newItem()
        XCTAssertNil(model.editor, "⌘N with the trash's confirmation open")
        XCTAssertEqual(model.trashing?.id, "i-gh")
        model.trashing = nil

        // The master password's sheet and «Uninstall» too.
        model.passwordPrompt = PasswordPrompt(reason: "Approve deploy-bot’s request") { _ in }
        model.newItem()
        model.editSelected()
        XCTAssertNil(model.editor, "the master password's sheet")
        model.passwordPrompt = nil
        model.uninstalling = true
        model.newItem()
        model.editSelected()
        XCTAssertNil(model.editor, "the uninstall sheet")
        model.uninstalling = false

        // Every sheet closed: ⌘E works again.
        XCTAssertFalse(model.sheetOpen)
        model.editSelected()
        XCTAssertEqual(model.editor, .edit("i-cf"))
    }

    func testLockingClosesTheEditorAndWhatWasTyped() async throws {
        let (model, _) = try await unlocked()
        model.editor = .edit("i-gh")
        model.trashing = try await model.run { try $0.item(id: "i-gh") }.info
        model.lock()
        for _ in 0..<100 where model.phase != .locked { try await Task.sleep(for: .milliseconds(30)) }
        XCTAssertNil(model.editor)
        XCTAssertNil(model.trashing)
        XCTAssertFalse(model.canChangeItems)
        model.newItem()
        XCTAssertNil(model.editor, "nothing opens while locked")
    }

    func testAfterTheDeletionNothingChanges() async throws {
        let engine = SampleEngine(locked: false, touchID: true, signedOut: false, deletion: "deleted")
        let model = MacModel.sample(engine)
        model.editor = .create(.login)
        model.refresh()
        for _ in 0..<100 where !model.accountDeleted { try await Task.sleep(for: .milliseconds(30)) }
        XCTAssertNil(model.editor, "read-only (ADR 0037 D-C)")
        XCTAssertFalse(model.canChangeItems)
        model.newItem()
        XCTAssertNil(model.editor)
    }

    func testTrashAndTheAgentsSites() async throws {
        let (model, _) = try await unlocked()
        var cf = try await model.run { try $0.item(id: "i-cf") }.info
        XCTAssertEqual(cf.pendingUrls, ["https://cloudflare-access.example.net/login"])
        XCTAssertFalse(cf.confirmedUrls.contains(cf.pendingUrls[0]), "an agent's site isn't the person's")
        try await model.settleSites(cf, remove: true)
        cf = try await model.run { try $0.item(id: "i-cf") }.info
        XCTAssertEqual(cf.pendingUrls, [])
        XCTAssertEqual(cf.urls, ["https://dash.cloudflare.com"])

        model.selectedItem = "i-cf"
        model.trashing = cf
        try await model.trash(cf)
        XCTAssertNil(model.trashing)
        XCTAssertNil(model.selectedItem)
        let left = try await model.run { try $0.items(query: ItemQuery()) }
        XCTAssertFalse(left.contains { $0.id == "i-cf" })
    }

    func testTheEditorSpeaksSpanish() throws {
        let es = try XCTUnwrap(Bundle(for: MacModel.self).path(forResource: "es", ofType: "lproj").flatMap(Bundle.init(path:)))
        for key in ["New item", "Edit", "Move to the trash…", "Save to the vault", "Save the changes", "Generate",
                    "Use this password", "Sites added by an agent", "It stops showing on all your devices.",
                    "New Item", "Edit Item", "Password generator"] {
            XCTAssertNotEqual(es.localizedString(forKey: key, value: "∅", table: nil), "∅", key)
        }
    }
}
