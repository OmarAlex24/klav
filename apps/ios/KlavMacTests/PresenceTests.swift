import Darwin
import XCTest
@testable import Klav

/// The presence gate in the Mac app (ADR 0041, layer 5), over the sample
/// engine; the real `klavd` side is `crates/klav-ffi/tests/presence.rs`.
@MainActor
final class PresenceTests: XCTestCase {
    private func settle(until done: @escaping @MainActor () -> Bool) async throws {
        for _ in 0..<100 where !done() {
            try await Task.sleep(for: .milliseconds(30))
        }
        XCTAssertTrue(done(), "timed out")
    }

    /// A Mac without Touch ID, the gate on, the setting on 5 minutes.
    private func gated(locked: Bool = false) -> (MacModel, SampleEngine) {
        let engine = SampleEngine(locked: locked, touchID: false, signedOut: false, deletion: "")
        engine.presenceGate = true
        return (MacModel.sample(engine), engine)
    }

    // MARK: The home (ADR 0041 §1.2, N1)

    /// The signed app's home comes from the account record, not from the
    /// environment: `HOME` and `CFFIXED_USER_HOME` change nothing.
    func testTheHomeComesFromTheAccountRecord() throws {
        let fromRecord = try KlavHome.accountHome()
        let record = try XCTUnwrap(getpwuid(getuid()))
        let expected = String(cString: record.pointee.pw_dir)
        XCTAssertEqual(fromRecord.path, expected)
        let saved = ["HOME", "CFFIXED_USER_HOME"].map { ($0, ProcessInfo.processInfo.environment[$0]) }
        defer {
            for (name, value) in saved {
                if let value { setenv(name, value, 1) } else { unsetenv(name) }
            }
        }
        setenv("HOME", "/tmp/klav-hostile-home", 1)
        setenv("CFFIXED_USER_HOME", "/tmp/klav-hostile-home", 1)
        XCTAssertEqual(try KlavHome.accountHome().path, expected)
        XCTAssertEqual(try KlavHome.defaultDirectory().path, expected + "/Library/Application Support/klav")
    }

    // MARK: Values behind the gate

    /// Without Touch ID a value asks for the master password in the app's
    /// sheet; a wrong one keeps the sheet, the right one hands the value to
    /// the caller that asked.
    func testAValueWaitsForTheMasterPassword() async throws {
        let (model, engine) = gated()
        model.refresh()
        try await settle { model.phase == .unlocked }
        let id = try XCTUnwrap(engine.items(query: ItemQuery()).first { $0.kind == .login }).id
        let value = Task { @MainActor in
            try await model.value({ try $0.fieldValue(id: id, field: "password") },
                                  withPassword: { try $0.fieldValueWithPassword(id: id, field: "password", password: $1) })
        }
        try await settle { model.passwordPrompt != nil }
        let prompt = try XCTUnwrap(model.passwordPrompt)
        XCTAssertEqual(prompt.host, .window)
        XCTAssertEqual(prompt.ask?.lasts, .untilLock)
        XCTAssertEqual(prompt.reason, String(localized: "Confirming lets this app use your vault until Klav locks."))
        do {
            try await prompt.retry("nope")
            XCTFail("a wrong password went through")
        } catch KlavError.WrongCredentials {}
        XCTAssertEqual(model.passwordPrompt?.id, prompt.id, "the sheet stays for another try")
        try await prompt.retry("sample")
        let got = try await value.value
        XCTAssertTrue(got.hasPrefix("sample-"))
        XCTAssertNil(model.passwordPrompt)
        // The window is open now: the next value asks nothing.
        let again = try await model.value({ try $0.notes(id: id) },
                                          withPassword: { try $0.notesWithPassword(id: id, password: $1) })
        _ = again
        XCTAssertNil(model.passwordPrompt)
    }

    /// Closing the sheet, or Klav locking, stops the caller's wait.
    func testAWithdrawnPromptCancelsTheValue() async throws {
        let (model, engine) = gated()
        model.refresh()
        try await settle { model.phase == .unlocked }
        let id = try XCTUnwrap(engine.items(query: ItemQuery()).first { $0.kind == .login }).id
        let value = Task { @MainActor in
            try await model.value(host: .editor, { try $0.notes(id: id) },
                                  withPassword: { try $0.notesWithPassword(id: id, password: $1) })
        }
        try await settle { model.passwordPrompt != nil }
        XCTAssertEqual(model.passwordPrompt?.host, .editor)
        XCTAssertNil(model.passwordPromptHere(.window).wrappedValue, "only over the editor")
        XCTAssertNotNil(model.passwordPromptHere(.editor).wrappedValue)
        model.withdrawPrompt(over: .editor)
        do {
            _ = try await value.value
            XCTFail("the value arrived without a password")
        } catch is CancellationError {}
    }

    /// Under Always, a value asks for itself, worded by what it hands out.
    func testUnderAlwaysEachValueSaysWhatItHandsOut() async throws {
        let (model, engine) = gated()
        model.refresh()
        try await settle { model.phase == .unlocked }
        _ = try engine.setPresenceWindow(window: .always, password: nil)
        let item = try XCTUnwrap(engine.items(query: ItemQuery()).first { $0.kind == .login })
        let value = Task { @MainActor in
            try await model.value({ try $0.fieldValue(id: item.id, field: "password") },
                                  withPassword: { try $0.fieldValueWithPassword(id: item.id, field: "password", password: $1) })
        }
        try await settle { model.passwordPrompt != nil }
        XCTAssertNil(model.passwordPrompt?.ask?.lasts)
        XCTAssertEqual(model.passwordPrompt?.reason,
                       String(localized: "Confirming shows “\(item.title)”, this once."))
        try await model.passwordPrompt?.retry("sample")
        _ = try await value.value
    }

    // MARK: The setting

    /// Tightening asks nothing; loosening without Touch ID asks for the
    /// master password over Settings.
    func testLooseningTheSettingAsksForThePassword() async throws {
        let (model, engine) = gated()
        model.refresh()
        try await settle { model.phase == .unlocked }
        let before = try await model.presenceSetting()
        XCTAssertEqual(before, .fiveMinutes)
        var now: PresenceSetting?
        try await model.setPresenceSetting(.always) { now = $0 }
        XCTAssertEqual(now, .always)
        XCTAssertNil(model.passwordPrompt, "tightening asks nothing")
        try await model.setPresenceSetting(.whileUnlocked) { now = $0 }
        let prompt = try XCTUnwrap(model.passwordPrompt)
        XCTAssertEqual(prompt.host, .settings)
        XCTAssertEqual(now, .always, "nothing changed before the password")
        try await prompt.retry("sample")
        XCTAssertEqual(now, .whileUnlocked)
        XCTAssertEqual(try engine.presenceWindow(), .whileUnlocked)
    }

    /// Locked, the setting can't be read (Q-N2).
    func testTheSettingIsNotReadWhileLocked() async throws {
        let (model, _) = gated(locked: true)
        model.refresh()
        try await settle { model.phase == .locked }
        do {
            _ = try await model.presenceSetting()
            XCTFail("read while locked")
        } catch KlavError.Locked {}
    }

    // MARK: Unlocking

    /// The lock screen says what the password opens, and the unlock sends
    /// it back as `shown`.
    func testTheUnlockQuestionSaysWhatThePasswordOpens() async throws {
        let (model, _) = gated(locked: true)
        model.refresh()
        try await settle { model.phase == .locked }
        await model.readUnlockQuestion()
        let question = try XCTUnwrap(model.unlockQuestion)
        XCTAssertEqual(question.lasts, .untilLock)
        XCTAssertEqual(question.lasts?.window, .whileUnlocked)
        XCTAssertEqual(question.words,
                       String(localized: "Unlocking with the master password also lets this app use your vault until Klav locks."))
        try await model.unlock(password: "sample")
        try await settle { model.phase == .unlocked }
        XCTAssertNil(model.unlockQuestion)
    }

    func testWithTheGateOffTheLockScreenSaysNothingNew() async throws {
        let model = MacModel.sample(SampleEngine(locked: true, touchID: false, signedOut: false, deletion: ""))
        model.refresh()
        try await settle { model.phase == .locked }
        await model.readUnlockQuestion()
        XCTAssertNil(model.unlockQuestion)
        XCTAssertNil(UnlockQuestionInfo(gate: false, elsewhere: false, key: .connection, declared: false,
                                        lasts: nil).words)
    }

    // MARK: Words

    func testTheBusyAnswersAreToldApart() {
        let check = KlavError.PresenceBusy(passwordCheck: true, inThisApp: false, message: "x").macMessage
        let app = KlavError.PresenceBusy(passwordCheck: false, inThisApp: true, message: "x").macMessage
        let other = KlavError.PresenceBusy(passwordCheck: false, inThisApp: false, message: "x").macMessage
        XCTAssertEqual(Set([check, app, other]).count, 3)
        XCTAssertNotEqual(KlavError.Conflict(version: 0).macMessage,
                          KlavError.ChangedWhileConfirming(message: "x").macMessage)
    }

    func testEveryAskIsWorded() {
        for lasts in [nil, PresenceLasts.fiveMinutes, .untilLock] {
            for key in [PresenceKeyKind.connection, .session, .parent, .noWindow] {
                for kind in [PresenceValueKind.show, .previous, .code, .fill, .generated, .resolve] {
                    for title in [nil, "GitHub"] as [String?] {
                        let ask = PresenceAskInfo(key: key, window: .fiveMinutes, terminal: "ttys003", declared: false,
                                                  lasts: lasts, value: PresenceValueInfo(kind: kind, title: title, count: 3))
                        let words = PresenceWords.reason(ask)
                        XCTAssertFalse(words.isEmpty)
                        if lasts == .untilLock { XCTAssertTrue(words.contains("until Klav locks"), words) }
                        if lasts == nil, let title { XCTAssertTrue(words.contains(title) || kind == .generated || kind == .resolve, words) }
                    }
                }
            }
        }
    }

    /// Every new sentence has its Spanish.
    func testThePresenceWordsHaveSpanish() throws {
        let es = try XCTUnwrap(Bundle(for: MacModel.self).path(forResource: "es", ofType: "lproj").flatMap(Bundle.init(path:)))
        for key in [
            "Confirming lets this app use your vault until Klav locks.",
            "Confirming lets this app use your vault for 5 minutes.",
            "Confirming shows “%@”, this once.",
            "How long one confirmation lasts",
            "Unlock Klav to see and change this setting.",
            "Klav was already unlocked elsewhere; this unlock gave this app nothing. If you didn’t unlock it, lock Klav.",
            "Klav is checking another master password. Try again in a moment.",
        ] {
            XCTAssertNotEqual(es.localizedString(forKey: key, value: "∅", table: nil), "∅", key)
        }
    }
}
