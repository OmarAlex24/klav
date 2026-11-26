import XCTest
@testable import Klav

/// The credential proxy on this Mac (ADR 0036 E3.5, E4; layer 11): «On
/// this Mac», the live connection from its local socket, revoking through
/// it while Klav is locked, the MCP URL with its real port, and its
/// LaunchAgent started, stopped and taken off when Klav is uninstalled.
/// Over the sample engine and `SampleSystem`: no proxy, no LaunchAgent.
@MainActor
final class LocalProxyTests: XCTestCase {
    private func settle(until done: @escaping @MainActor () -> Bool) async throws {
        for _ in 0..<100 where !done() {
            try await Task.sleep(for: .milliseconds(30))
        }
        XCTAssertTrue(done(), "timed out")
    }

    private func info(port: UInt16 = 8790, proxy: String = SandboxSamples.proxy) -> LocalProxyInfo {
        let sample = SandboxSamples.localProxy
        return LocalProxyInfo(proxyId: proxy, port: port, localCalls: true, channel: false, mcpGateway: true,
                              mcpProfiles: ["maple"], sandboxes: sample.sandboxes, unsentEnds: 0)
    }

    func testOnThisMacOnlyForTheAccountsProxy() {
        let mine = LocalProxyBoard(state: .running(info: info()), accountProxy: SandboxSamples.proxy)
        XCTAssertTrue(mine.onThisMac)
        XCTAssertFalse(mine.otherProxy)
        XCTAssertEqual(mine.connected("ad1e2f3a-4b5c-4d6e-7f8a-9b0c1d2e3f4a"), true)
        XCTAssertEqual(mine.connected("b7c8d9e0-1f2a-4b3c-8d4e-5f6a7b8c9d0e"), false)
        XCTAssertNil(mine.connected("not-there"))
        XCTAssertEqual(LocalProxyWords.status(mine, agent: .enabled),
                       "Running on this Mac, at 127.0.0.1:8790.")

        // Another proxy runs here: never the account's rows, never «On this Mac».
        let other = LocalProxyBoard(state: .running(info: info(proxy: SandboxSamples.oldProxy)),
                                    accountProxy: SandboxSamples.proxy)
        XCTAssertFalse(other.onThisMac)
        XCTAssertTrue(other.otherProxy)
        XCTAssertNil(other.connected("ad1e2f3a-4b5c-4d6e-7f8a-9b0c1d2e3f4a"))
        XCTAssertTrue(LocalProxyWords.status(other, agent: .enabled).contains(SandboxWords.idPrefix(SandboxSamples.oldProxy)))

        // Not running: set up or not.
        let none = LocalProxyBoard(state: .notRunning(registered: false), accountProxy: nil)
        XCTAssertFalse(none.registered)
        XCTAssertEqual(LocalProxyWords.status(none, agent: .notRegistered),
                       String(localized: "No credential proxy is set up on this Mac."))
        let stopped = LocalProxyBoard(state: .notRunning(registered: true), accountProxy: nil)
        XCTAssertTrue(stopped.registered)
        XCTAssertEqual(LocalProxyWords.status(stopped, agent: .notRegistered),
                       String(localized: "Set up on this Mac, and stopped."))
        XCTAssertTrue(LocalProxyWords.status(stopped, agent: .requiresApproval).contains("Login Items")
                      || Locale.current.language.languageCode != .english)
    }

    func testTheMcpUrlHasThePortTheProxyListensOn() {
        let url = "http://127.0.0.1:8790/maple/mcp"
        let board = LocalProxyBoard(state: .running(info: info(port: 8791)), accountProxy: SandboxSamples.proxy)
        XCTAssertEqual(board.localUrl(url, profile: "maple"), "http://127.0.0.1:8791/maple/mcp")
        // A profile this proxy doesn't serve keeps what the list said.
        XCTAssertEqual(board.localUrl("http://127.0.0.1:8790/github/mcp", profile: "github"),
                       "http://127.0.0.1:8790/github/mcp")
        let none = LocalProxyBoard(state: .notRunning(registered: true), accountProxy: SandboxSamples.proxy)
        XCTAssertEqual(none.localUrl(url, profile: "maple"), url)
    }

    func testRevokingOnThisMacWorksWhileLocked() async throws {
        let engine = SampleEngine(locked: true, touchID: true)
        engine.localProxyState = .running(info: info())
        let model = MacModel.sample(engine)
        model.refresh()
        try await settle { model.phase == .locked }
        await model.loadLocalProxy()
        XCTAssertEqual(model.localProxyBoard.info?.sandboxes.count, 2)

        let one = try await model.revokeLocally("ad1e2f3a-4b5c-4d6e-7f8a-9b0c1d2e3f4a")
        XCTAssertEqual(one, String(localized: "Revoked on this Mac: it gets nothing from the proxy from now on."))
        XCTAssertEqual(model.localProxyBoard.info?.sandboxes.map(\.label), ["chat-124"])
        let all = try await model.revokeLocally(nil)
        XCTAssertEqual(all, String(localized: "Revoked on this Mac: it gets nothing from the proxy from now on."))
        XCTAssertEqual(model.localProxyBoard.info?.sandboxes.count, 0)
        XCTAssertEqual(engine.localRevokeCalls, ["ad1e2f3a-4b5c-4d6e-7f8a-9b0c1d2e3f4a", "all"])
        XCTAssertEqual(model.phase, .locked, "nothing unlocked")

        engine.localProxyState = .notRunning(registered: true)
        do {
            _ = try await model.revokeLocally(nil)
            XCTFail("no proxy runs")
        } catch KlavError.NotFound {
        }
    }

    func testRevokedWords() {
        XCTAssertEqual(LocalProxyWords.revoked(LocalRevokeInfo(revoked: [], logged: true)),
                       String(localized: "No live sandbox on this Mac to revoke."))
        XCTAssertEqual(LocalProxyWords.revoked(LocalRevokeInfo(revoked: ["a", "b"], logged: true)),
                       String(localized: "Revoked \(Int64(2)) sandboxes on this Mac: they get nothing from the proxy from now on."))
        XCTAssertNotEqual(LocalProxyWords.revoked(LocalRevokeInfo(revoked: ["a"], logged: false)),
                          LocalProxyWords.revoked(LocalRevokeInfo(revoked: ["a"], logged: true)),
                          "says when the server doesn't have it yet")
        XCTAssertEqual(LocalProxyWords.count(1), String(localized: "1 sandbox on this Mac"))
    }

    func testTheProxysLaunchAgentStartsStopsAndGoesWithKlav() async throws {
        let base = ProcessInfo.processInfo.environment["KLAV_TEST_TMPDIR"].map(URL.init(fileURLWithPath:))
            ?? FileManager.default.temporaryDirectory
        var root = base.appendingPathComponent("klp-\(UUID().uuidString.prefix(8))")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        root = root.resolvingSymlinksInPath()
        defer { try? FileManager.default.removeItem(at: root) }
        let system = SampleSystem()
        let paths = InstallPaths(helpers: Bundle.main.bundleURL.appendingPathComponent("Contents/Helpers"),
                                 linkDirectory: root.appendingPathComponent("bin"),
                                 userHome: root.appendingPathComponent("user"),
                                 klavHome: root.appendingPathComponent("home"),
                                 pathDirectories: [])
        let installer = Installer(paths: paths, system: system, placement: .applications,
                                  defaults: MemoryPreferences(),
                                  development: true)
        await installer.startLocalProxy()
        XCTAssertEqual(installer.proxyAgent, .enabled)
        XCTAssertNil(installer.problems[.proxy])
        // Started again while registered: a restart, not a second agent.
        await installer.startLocalProxy()
        XCTAssertEqual(system.proxyRestarts, 1)
        await installer.stopLocalProxy()
        XCTAssertEqual(installer.proxyAgent, .notRegistered)

        await installer.startLocalProxy()
        XCTAssertEqual(system.proxyAgentState(), .enabled)
        _ = await installer.uninstall(engine: SampleEngine(locked: false, touchID: true), deleteHome: false)
        XCTAssertEqual(system.proxyAgentState(), .notRegistered, "uninstalling takes the proxy off too")

        // A build without its plist: said, not hidden.
        let without = SampleSystem()
        without.proxyRegistersAs = .notFound
        let other = Installer(paths: paths, system: without, placement: .applications,
                              defaults: MemoryPreferences(),
                              development: true)
        await other.startLocalProxy()
        XCTAssertNotNil(other.problems[.proxy])
    }

    /// The bundle carries the proxy's LaunchAgent, run by the bundle's
    /// `klav` as `klav-proxy serve --if-registered`.
    func testTheBundleCarriesTheProxysLaunchAgent() throws {
        let plist = Bundle.main.bundleURL.appendingPathComponent("Contents/Library/LaunchAgents/dev.klav.proxy.plist")
        guard FileManager.default.fileExists(atPath: plist.path) else {
            throw XCTSkip("this Klav.app was built without its helpers")
        }
        let dict = try XCTUnwrap(NSDictionary(contentsOf: plist) as? [String: Any])
        XCTAssertEqual(dict["Label"] as? String, "dev.klav.proxy")
        XCTAssertEqual(dict["BundleProgram"] as? String, "Contents/Helpers/klav")
        XCTAssertEqual(dict["ProgramArguments"] as? [String], ["klav-proxy", "serve", "--if-registered"])
    }
}
