import SwiftUI
import XCTest
@testable import Klav

/// Klav Cloud's proxy on the Mac (ADR 0051, layer 5): the row for each
/// state the check in `klav-client` leaves (attested, the red rows, can't
/// be checked, not used), «Use», «Stop using it» and «Set it up again»
/// through presence, and the proxy on this Mac beside it (Q5 (a)), in
/// English and in Spanish.
final class CloudProxyTests: XCTestCase {
    private func es() throws -> Bundle {
        try XCTUnwrap(Bundle(for: MacModel.self).path(forResource: "es", ofType: "lproj").flatMap(Bundle.init(path:)))
    }

    private func say(_ bundle: Bundle, _ key: String, _ args: CVarArg...) -> String {
        String(format: bundle.localizedString(forKey: key, value: "∅", table: nil), arguments: args)
    }

    // MARK: The row

    func testTheRowFollowsTheCheck() {
        let verified = SampleCloud.verified(agent: "6f1c")
        XCTAssertEqual(CloudProxyWords.headline(verified),
                       "Attested: version 0.12.0, commit 3b8f0c2, checked just now.")
        XCTAssertFalse(verified.needsAttention)
        XCTAssertNil(CloudProxyWords.reason(verified))

        // Each red row says what happened and keeps what it holds.
        for state in [HostedProxyState.unverified, .notEntitled, .lostKeys, .revoked] {
            let info = SampleCloud.failing(state, reason: nil)
            XCTAssertTrue(info.needsAttention, "\(state)")
            XCTAssertNotNil(CloudProxyWords.headline(info), "\(state)")
        }
        // Can't be checked: not red, nothing shared meanwhile.
        let unreachable = SampleCloud.failing(.unreachable, reason: "unreachable")
        XCTAssertFalse(unreachable.needsAttention)
        XCTAssertEqual(CloudProxyWords.headline(unreachable),
                       "Klav Cloud’s proxy can’t be checked right now. Nothing new is shared with it until it can.")

        // Offered only to an entitled account.
        XCTAssertNotNil(CloudProxyWords.headline(SampleCloud.notUsed(entitled: true)))
        XCTAssertNil(CloudProxyWords.headline(SampleCloud.notUsed(entitled: false)))
        XCTAssertNil(CloudProxyWords.headline(SampleCloud.notUsed(entitled: nil)))
    }

    /// §6.3: the red row says whether a stale release is likelier than an attack.
    func testTheRedRowSaysWhy() {
        let expired = SampleCloud.failing(.unverified, reason: "manifest_expired")
        XCTAssertEqual(CloudProxyWords.reason(expired),
                       "Its list of approved images expired. That’s most likely a late release, not an attack.")
        let revoked = SampleCloud.failing(.unverified, reason: "image_revoked")
        XCTAssertEqual(CloudProxyWords.reason(revoked),
                       "It runs an image Klav revoked. Stop using it, then rotate the provider tokens it held.")
        let other = SampleCloud.failing(.unverified, reason: "signature")
        XCTAssertEqual(CloudProxyWords.reason(other),
                       "Its attestation or its list of approved images doesn’t check out.")
        XCTAssertNil(CloudProxyWords.reason(SampleCloud.failing(.lostKeys, reason: "lost_keys")))
    }

    // MARK: The actions

    func testUseStopAndResetNeedPresence() throws {
        let engine = SampleEngine(locked: false, touchID: false)
        engine.cloudProxyInfo = SampleCloud.notUsed()
        XCTAssertThrowsError(try engine.hostedProxyActWithPassword(action: .use, password: nil))
        XCTAssertEqual(try engine.hostedProxy().state, .notUsed)

        let used = try engine.hostedProxyActWithPassword(action: .use, password: "sample")
        XCTAssertEqual(used.info.state, .verified)
        XCTAssertEqual(try engine.hostedProxy().version, "0.12.0")
        // Used already: «Use» again is refused.
        XCTAssertThrowsError(try engine.hostedProxyActWithPassword(action: .use, password: "sample"))

        let reset = try engine.hostedProxyActWithPassword(action: .reset, password: "sample")
        XCTAssertEqual(reset.info.state, .verified)
        XCTAssertNotEqual(reset.info.agentId, used.info.agentId)

        let stopped = try engine.hostedProxyActWithPassword(action: .stop, password: "sample")
        XCTAssertEqual(stopped.info.state, .notUsed)
        XCTAssertFalse(stopped.notes.isEmpty, "it says which tokens to rotate")
        XCTAssertThrowsError(try engine.hostedProxyActWithPassword(action: .stop, password: "sample"))
    }

    /// Without Touch ID, «Stop using it» asks for the master password, and
    /// nothing changes before it.
    @MainActor
    func testStoppingAsksForThePasswordFirst() async throws {
        let engine = SampleEngine(locked: false, touchID: false)
        engine.cloudProxyInfo = SampleCloud.failing(.unverified, reason: "image_revoked")
        let model = MacModel.sample(engine)
        model.refresh()
        for _ in 0..<100 where model.phase != .unlocked {
            try await Task.sleep(for: .milliseconds(30))
        }
        XCTAssertEqual(model.phase, .unlocked)
        await model.loadCloudProxy()
        XCTAssertEqual(model.cloudProxy?.state, .unverified)
        await model.actOnCloudProxy(.stop)
        let prompt = try XCTUnwrap(model.passwordPrompt)
        XCTAssertEqual(prompt.reason, CloudProxyWords.reasonFor(.stop))
        XCTAssertEqual(try engine.hostedProxy().state, .unverified, "nothing before the password")
        try await prompt.retry("sample")
        XCTAssertEqual(model.cloudProxy?.state, .notUsed)
        XCTAssertFalse(model.cloudProxyNotes.isEmpty)
    }

    /// The row loads itself when it appears, also while it shows nothing
    /// yet (an empty `Group` never ran its `.task`).
    @MainActor
    func testTheRowLoadsWhenItAppears() async throws {
        let engine = SampleEngine(locked: false, touchID: true)
        engine.cloudProxyInfo = SampleCloud.verified(agent: "6f1c")
        let model = MacModel.sample(engine)
        model.refresh()
        for _ in 0..<100 where model.phase != .unlocked {
            try await Task.sleep(for: .milliseconds(30))
        }
        XCTAssertNil(model.cloudProxy)
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 600, height: 300),
                              styleMask: [.titled], backing: .buffered, defer: false)
        window.isReleasedWhenClosed = false
        window.contentView = NSHostingView(rootView: CloudProxyRow().environmentObject(model))
        defer { window.close() }
        for _ in 0..<100 where model.cloudProxy == nil {
            try await Task.sleep(for: .milliseconds(30))
        }
        XCTAssertEqual(model.cloudProxy?.state, .verified)
    }

    // MARK: Q5: the proxy on this Mac stays

    func testTheProxyOnThisMacServesLocalAgentsBesideKlavCloud() {
        let info = SandboxSamples.localProxy
        let board = LocalProxyBoard(state: .running(info: info), accountProxy: "a-hosted-agent", cloud: true)
        XCTAssertFalse(board.otherProxy, "it is this Mac's own proxy, not another account's")
        XCTAssertFalse(board.onThisMac)
        XCTAssertEqual(LocalProxyWords.status(board, agent: .enabled),
                       "Running on this Mac for its local agents, at 127.0.0.1:\(info.port). Sandboxes use Klav Cloud’s proxy.")
        let without = LocalProxyBoard(state: .running(info: info), accountProxy: "a-hosted-agent")
        XCTAssertTrue(without.otherProxy)
    }

    // MARK: Spanish

    func testSpanishIsWrittenNatively() throws {
        let es = try es()
        XCTAssertEqual(say(es, "Klav Cloud’s proxy couldn’t be verified. Klav won’t share new credentials with it."),
                       "No se pudo verificar el proxy de Klav Cloud. Klav no le compartirá credenciales nuevas.")
        XCTAssertEqual(say(es, "Stop using it"), "Dejar de usarlo")
        XCTAssertEqual(say(es, "Use Klav Cloud Proxy"), "Usar el proxy de Klav Cloud")
        XCTAssertEqual(say(es, "Attested: version %@, commit %@, checked just now.", "0.12.0", "3b8f0c2"),
                       "Atestado: versión 0.12.0, commit 3b8f0c2, comprobado hace un momento.")
    }
}
