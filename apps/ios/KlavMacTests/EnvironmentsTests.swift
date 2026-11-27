import XCTest
@testable import Klav

/// Environments in the Mac app (ADR 0032 §6, layer 4b): the names a
/// variable and an environment may take, the draft of a variable and the
/// edit it becomes, the words of an origin, which values are on screen,
/// and, over the sample engine, the list, a value asked for every time in
/// a protected environment (the master password without Touch ID), saving,
/// lowering the protection and «New item» in Environments. The real
/// `klavd` side is `crates/klav-ffi/tests/entornos.rs` and the daemon's
/// gate tests.
@MainActor
final class EnvironmentsTests: XCTestCase {
    private func settle(until done: @escaping @MainActor () -> Bool) async throws {
        for _ in 0..<100 where !done() {
            try await Task.sleep(for: .milliseconds(30))
        }
        XCTAssertTrue(done(), "timed out")
    }

    private func unlocked(touchID: Bool) async throws -> (MacModel, SampleEngine) {
        let engine = SampleEngine(locked: false, touchID: touchID, signedOut: false, deletion: "")
        let model = MacModel.sample(engine)
        model.refresh()
        try await settle { model.phase == .unlocked }
        return (model, engine)
    }

    // MARK: Rules and drafts

    func testNamesFollowTheADR() {
        XCTAssertTrue(EnvironmentRules.isVariableName("STRIPE_KEY"))
        XCTAssertTrue(EnvironmentRules.isVariableName("_private2"))
        XCTAssertFalse(EnvironmentRules.isVariableName("2FA"))
        XCTAssertFalse(EnvironmentRules.isVariableName("API-KEY"))
        XCTAssertFalse(EnvironmentRules.isVariableName(String(repeating: "A", count: 129)))
        XCTAssertTrue(EnvironmentRules.isEnvironmentName("development"))
        XCTAssertTrue(EnvironmentRules.isEnvironmentName("pr-42_preview"))
        XCTAssertFalse(EnvironmentRules.isEnvironmentName("Production"))
        XCTAssertFalse(EnvironmentRules.isEnvironmentName("-dev"))
        XCTAssertTrue(EnvironmentRules.protectedByDefault("production"))
        XCTAssertTrue(EnvironmentRules.protectedByDefault("PROD"))
        XCTAssertFalse(EnvironmentRules.protectedByDefault("preprod"))
    }

    func testADraftBecomesAValueOrAReferenceAndNeverBoth() throws {
        var draft = VariableDraft(name: "1BAD", source: .value, text: "x")
        XCTAssertNotNil(draft.problem)
        XCTAssertNil(draft.edit)

        draft = VariableDraft(name: " API_TOKEN ", source: .value, text: "")
        XCTAssertEqual(draft.problem, String(localized: "Type a value."))

        draft.text = "tok-123"
        let value = try XCTUnwrap(draft.edit)
        XCTAssertEqual(value.set.map(\.name), ["API_TOKEN"])
        XCTAssertEqual(value.set.first?.value, "tok-123")
        XCTAssertNil(value.set.first?.reference)
        XCTAssertFalse(value.create)
        XCTAssertNil(value.protected)

        draft = VariableDraft(name: "STRIPE_KEY", source: .reference, text: "https://stripe.com")
        XCTAssertEqual(draft.problem, String(localized: "A reference starts with klav://"))
        draft.text = "  klav://Trabajo/Backend/Stripe/secret "
        let reference = try XCTUnwrap(draft.edit)
        XCTAssertEqual(reference.set.first?.reference, "klav://Trabajo/Backend/Stripe/secret")
        XCTAssertNil(reference.set.first?.value)

        XCTAssertEqual(EnvironmentRules.remove("A").remove, ["A"])
        XCTAssertEqual(EnvironmentRules.protect(false).protected, false)
        let create = EnvironmentRules.create(protected: true)
        XCTAssertTrue(create.create && create.mustBeNew)
        XCTAssertEqual(create.protected, true)
    }

    func testOriginsAndRowsSayWhereValuesComeFrom() {
        let own = VariableInfo(name: "A", reference: nil, target: nil, targetProtected: false, resolve: "klav://v/p/e/A")
        XCTAssertEqual(EnvironmentWords.origin(own), String(localized: "Its own value"))
        let ref = VariableInfo(name: "B", reference: "klav://x", target: "Stripe › secret", targetProtected: true,
                               resolve: "klav://v/p/e/B")
        XCTAssertTrue(EnvironmentWords.origin(ref).contains("Stripe › secret"))
        XCTAssertTrue(EnvironmentWords.origin(ref).contains(String(localized: "protected")))
        let unseen = VariableInfo(name: "C", reference: "klav://x", target: nil, targetProtected: false,
                                  resolve: "klav://v/p/e/C")
        XCTAssertEqual(EnvironmentWords.origin(unseen), String(localized: "From an item this device can’t see"))
        XCTAssertEqual(EnvironmentWords.row(vault: "Trabajo", project: "Backend", variables: nil), "Trabajo / Backend")
        XCTAssertTrue(EnvironmentWords.row(vault: "Trabajo", project: "Backend", variables: 2).hasSuffix("2 variables"))
        XCTAssertTrue(EnvironmentWords.protectedBy(["production"]).contains("“production”"))
    }

    func testValuesShowOnlyUntilHidden() {
        var reveal = EnvironmentReveal()
        XCTAssertNil(reveal.value("A"))
        reveal.show("A", "one")
        reveal.show("B", "two")
        XCTAssertTrue(reveal.isShown("A"))
        reveal.hide("A")
        XCTAssertNil(reveal.value("A"))
        XCTAssertEqual(reveal.value("B"), "two")
        reveal.hideAll()
        XCTAssertEqual(reveal, EnvironmentReveal())
    }

    // MARK: Over the sample engine

    func testEnvironmentsAreListedByKindWithTheirProtection() async throws {
        let (_, engine) = try await unlocked(touchID: true)
        let items = try engine.items(query: ItemQuery())
        let envs = items.filter { $0.kind == .environment }
        XCTAssertEqual(Set(envs.map(\.title)), ["development", "production"])
        XCTAssertEqual(items.first { $0.title == "Stripe" }?.protectedBy, ["production"])
        XCTAssertEqual(Kind.environment.icon, .layers)

        let list = try engine.environments(projectId: "p2")
        XCTAssertEqual(list.map(\.name), ["development", "production"])
        XCTAssertEqual(list.map(\.protected), [false, true])
        let prod = try XCTUnwrap(try engine.environment(projectId: "p2", name: "production"))
        XCTAssertEqual(prod.variables.map(\.name), ["DATABASE_URL", "STRIPE_KEY"])
        XCTAssertEqual(prod.variables.last?.target, "Stripe › secret")
        XCTAssertNil(try engine.environment(projectId: "p2", name: "staging"))
    }

    /// Without Touch ID, every value of a protected environment asks for
    /// the master password; a development value asks nothing.
    func testAProtectedValueAsksEveryTime() async throws {
        let (model, engine) = try await unlocked(touchID: false)
        let dev = try XCTUnwrap(try engine.environment(projectId: "p2", name: "development"))
        let free = try await model.value({ try $0.variableValue(reference: dev.variables[0].resolve) },
                                         withPassword: { try $0.variableValueWithPassword(reference: dev.variables[0].resolve, password: $1) })
        XCTAssertFalse(free.isEmpty)
        XCTAssertNil(model.passwordPrompt, "development asks nothing")

        let prod = try XCTUnwrap(try engine.environment(projectId: "p2", name: "production"))
        let reference = prod.variables[0].resolve
        for _ in 0..<2 {
            let value = Task { @MainActor in
                try await model.value({ try $0.variableValue(reference: reference) },
                                      withPassword: { try $0.variableValueWithPassword(reference: reference, password: $1) })
            }
            try await settle { model.passwordPrompt != nil }
            let prompt = try XCTUnwrap(model.passwordPrompt)
            try await prompt.retry("sample")
            let got = try await value.value
            XCTAssertFalse(got.isEmpty)
            XCTAssertNil(model.passwordPrompt)
        }
        XCTAssertEqual(engine.variableReads.filter { $0 == reference }.count, 2, "asked and read every time")

        // Only an environment's variable: a login's field is refused.
        XCTAssertThrowsError(try engine.variableValue(reference: "klav://Trabajo/Backend/GitHub/password"))
    }

    /// Adding a variable asks nothing; turning the protection off asks for
    /// the master password first, and nothing changes until it is given.
    func testSavingAndLoweringTheProtection() async throws {
        let (model, engine) = try await unlocked(touchID: false)
        var saved: EnvironmentSavedInfo?
        let add = try XCTUnwrap(VariableDraft(name: "REDIS_URL", source: .value, text: "redis://cache").edit)
        try await model.withPresenceResult("lower") { engine, password in
            try engine.saveEnvironmentWithPassword(projectId: "p2", name: "production", edit: add, password: password)
        } done: { saved = $0 }
        XCTAssertNil(model.passwordPrompt, "adding asks nothing")
        XCTAssertEqual(saved.map(EnvironmentWords.saved), String(localized: "Saved"))
        XCTAssertEqual(try engine.environment(projectId: "p2", name: "production")?.variables.map(\.name),
                       ["DATABASE_URL", "STRIPE_KEY", "REDIS_URL"])

        saved = nil
        try await model.withPresenceResult("lower") { engine, password in
            try engine.saveEnvironmentWithPassword(projectId: "p2", name: "production",
                                                   edit: EnvironmentRules.protect(false), password: password)
        } done: { saved = $0 }
        let prompt = try XCTUnwrap(model.passwordPrompt, "no Touch ID: the password")
        XCTAssertNil(saved)
        XCTAssertEqual(try engine.environments(projectId: "p2").first { $0.name == "production" }?.protected, true)
        try await prompt.retry("sample")
        XCTAssertEqual(saved?.protected, false)
        XCTAssertEqual(try engine.environments(projectId: "p2").first { $0.name == "production" }?.protected, false)
    }

    func testNewItemInEnvironmentsMakesAnEnvironment() async throws {
        let (model, engine) = try await unlocked(touchID: true)
        model.section = .vault(.kind(.environment))
        model.newItem()
        XCTAssertTrue(model.creatingEnvironment)
        XCTAssertNil(model.editor, "not the item editor")
        XCTAssertTrue(model.sheetOpen)
        model.creatingEnvironment = false

        let created = try engine.saveEnvironment(projectId: "p1", name: "prod", edit: EnvironmentRules.create(protected: true))
        XCTAssertTrue(created.created && created.protected)
        XCTAssertThrowsError(try engine.saveEnvironment(projectId: "p1", name: "prod",
                                                        edit: EnvironmentRules.create(protected: true)))
        _ = try engine.trashEnvironment(projectId: "p1", name: "prod")
        XCTAssertTrue(try engine.environments(projectId: "p1").isEmpty)
    }
}
