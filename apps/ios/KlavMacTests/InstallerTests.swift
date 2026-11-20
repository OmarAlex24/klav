import Combine
import XCTest
@testable import Klav

/// «Set up this Mac» against temporary homes: the real `klav` of the
/// bundle's Helpers, browsers that are only directories, a link directory
/// of the test, and `SampleSystem` instead of SMAppService and the
/// administrator's password. Nothing outside the test's directory changes.
@MainActor
final class InstallerTests: XCTestCase {
    private var root: URL!
    /// The app's preferences for this test only, in memory.
    private var defaults: MemoryPreferences!

    override func setUpWithError() throws {
        let base = ProcessInfo.processInfo.environment["KLAV_TEST_TMPDIR"].map(URL.init(fileURLWithPath:))
            ?? FileManager.default.temporaryDirectory
        // Short: the CLI may open klavd's socket under KLAV_HOME.
        root = base.appendingPathComponent("kmi-\(UUID().uuidString.prefix(8))")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        root = root.resolvingSymlinksInPath()
        defaults = MemoryPreferences()
    }

    override func tearDownWithError() throws {
        if let root { try? FileManager.default.removeItem(at: root) }
    }

    private var helpers: URL { Bundle.main.bundleURL.appendingPathComponent("Contents/Helpers") }

    private func installer(system: SampleSystem = SampleSystem(), linkDir: String = "bin",
                           placement: Placement = .applications,
                           signatures: CodeSignatures = LiveSignatures(),
                           development: Bool = HelperSignature.developmentBuild) throws -> Installer {
        guard FileManager.default.isExecutableFile(atPath: helpers.appendingPathComponent("klav").path) else {
            throw XCTSkip("this Klav.app was built without its helpers")
        }
        let paths = InstallPaths(helpers: helpers,
                                 linkDirectory: root.appendingPathComponent(linkDir),
                                 userHome: root.appendingPathComponent("user"),
                                 klavHome: root.appendingPathComponent("home"),
                                 pathDirectories: [root.appendingPathComponent("bin"),
                                                   root.appendingPathComponent("cargo-bin")])
        return Installer(paths: paths, system: system, placement: placement, defaults: defaults,
                         signatures: signatures, development: development)
    }

    private func mkdir(_ path: String) throws -> URL {
        let url = root.appendingPathComponent(path)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    private func write(_ text: String, to path: String, executable: Bool = false) throws -> URL {
        let url = root.appendingPathComponent(path)
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try text.write(to: url, atomically: true, encoding: .utf8)
        if executable { try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: url.path) }
        return url
    }

    /// Another install's manifest, as an older `klav extension install-host`
    /// leaves it: a wrapper that runs another host.
    private func foreignManifest(at path: String) throws -> URL {
        let wrapper = try write("#!/bin/sh\nexec '/opt/old/klav-native-host' --home '/x' \"$@\"\n",
                                to: "old/wrapper", executable: true)
        return try write(#"{"name":"dev.klav.host","path":"\#(wrapper.path)","type":"stdio"}"#, to: path)
    }

    private let support = "user/Library/Application Support"

    func testDiaTakesItsHostFromMozillaAndAnOldOneIsShownBeforeReplacing() async throws {
        let installer = try installer()
        _ = try mkdir("\(support)/Dia/User Data")
        let mozilla = try foreignManifest(at: "\(support)/Mozilla/NativeMessagingHosts/dev.klav.host.json")
        let before = try String(contentsOf: mozilla, encoding: .utf8)

        await installer.refresh(info: nil)
        XCTAssertEqual(installer.browsers, ["dia"])
        XCTAssertEqual(installer.manifests.count, 2, "Dia/User Data and Mozilla")
        XCTAssertEqual(installer.foreignManifests.map(\.path), [mozilla.path])
        XCTAssertEqual(installer.foreignManifests.first?.runs, "/opt/old/klav-native-host")
        XCTAssertFalse(installer.hostsReady)
        XCTAssertEqual(try String(contentsOf: mozilla, encoding: .utf8), before, "reading changes nothing")

        // The person chose «Use this app's».
        await installer.installHosts()
        XCTAssertNil(installer.problems[.hosts])
        XCTAssertTrue(installer.foreignManifests.isEmpty, "\(installer.manifests)")
        XCTAssertFalse(installer.hostsToConnect)
        XCTAssertEqual(installer.waitingForStore, ["dia"], "no store build to allow in Dia's own folder yet")
        XCTAssertFalse(installer.hostsReady, "not done while Dia waits for the store")
        let wrapper = try String(contentsOf: root.appendingPathComponent("home/native-host/klav-native-host"),
                                 encoding: .utf8)
        XCTAssertTrue(wrapper.contains(helpers.appendingPathComponent("klav-native-host").resolvingSymlinksInPath().path),
                      wrapper)
    }

    func testUninstallTakesOnlyThisAppsFiles() async throws {
        let installer = try installer(system: SampleSystem(agent: .enabled))
        _ = try mkdir("\(support)/Dia/User Data")
        _ = try mkdir("\(support)/Google/Chrome")
        await installer.setDevExtension(true)
        await installer.installHosts()
        XCTAssertTrue(installer.hostsReady)
        _ = try mkdir("bin")
        await installer.linkCLI(replace: false)
        XCTAssertEqual(installer.link, .ours)
        // Later, another install takes Chrome's manifest.
        let chrome = try foreignManifest(at: "\(support)/Google/Chrome/NativeMessagingHosts/dev.klav.host.json")
        try "cache".write(to: root.appendingPathComponent("home/kept"), atomically: true, encoding: .utf8)
        // And this app's wrapper no longer lets in what Dia's own manifest
        // lists: still this app's, so it goes too.
        try dropDevExtensionFromWrapper()
        await installer.refresh(info: nil)
        let dia = try XCTUnwrap(installer.manifests.first { $0.path.contains("/Dia/User Data/") })
        XCTAssertTrue(dia.outdated, "\(dia)")
        XCTAssertEqual(installer.foreignManifests.map(\.path), [chrome.path])

        let done = await installer.uninstall(engine: SampleEngine(locked: false, touchID: true), deleteHome: false)
        XCTAssertTrue(done, "\(installer.problems)")
        XCTAssertEqual(installer.system.agentState(), .notRegistered)
        let fm = FileManager.default
        XCTAssertTrue(fm.fileExists(atPath: chrome.path), "another install's manifest stays")
        XCTAssertFalse(fm.fileExists(atPath: root.appendingPathComponent(
            "\(support)/Dia/User Data/NativeMessagingHosts/dev.klav.host.json").path))
        XCTAssertFalse(fm.fileExists(atPath: root.appendingPathComponent(
            "\(support)/Mozilla/NativeMessagingHosts/dev.klav.host.json").path))
        XCTAssertFalse(fm.fileExists(atPath: root.appendingPathComponent("home/native-host/klav-native-host").path))
        XCTAssertEqual(installer.link, .missing)
        XCTAssertTrue(fm.fileExists(atPath: root.appendingPathComponent("home/kept").path), "KLAV_HOME stays")

        let again = await installer.uninstall(engine: SampleEngine(locked: false, touchID: true), deleteHome: true)
        XCTAssertTrue(again)
        XCTAssertFalse(fm.fileExists(atPath: root.appendingPathComponent("home").path), "asked: KLAV_HOME goes")
    }

    private var chromeManifest: URL {
        root.appendingPathComponent("\(support)/Google/Chrome/NativeMessagingHosts/dev.klav.host.json")
    }
    private var firefoxManifest: URL {
        root.appendingPathComponent("\(support)/Mozilla/NativeMessagingHosts/dev.klav.host.json")
    }
    private var wrapper: URL { root.appendingPathComponent("home/native-host/klav-native-host") }
    /// The development build's ID, whose key is public (`klav_daemon::native::DEV_CHROMIUM_ID`).
    private let devID = "niiplppgdljgimbnmokojdkofdcjkgao"

    func testByDefaultOnlyFirefoxConnectsAndChromiumWaitsForTheStore() async throws {
        let installer = try installer()
        XCTAssertFalse(installer.devExtension, "off unless the person turns it on")
        _ = try mkdir("\(support)/Google/Chrome")
        _ = try mkdir("\(support)/Mozilla")

        await installer.refresh(info: nil)
        XCTAssertTrue(installer.hostsToConnect)
        await installer.installHosts()
        XCTAssertNil(installer.problems[.hosts])
        let fm = FileManager.default
        XCTAssertTrue(fm.fileExists(atPath: firefoxManifest.path))
        XCTAssertFalse(fm.fileExists(atPath: chromeManifest.path), "no Chromium extension to allow")
        XCTAssertFalse(try String(contentsOf: wrapper, encoding: .utf8).contains(devID))
        XCTAssertEqual(installer.waitingForStore, ["chrome"])
        XCTAssertTrue(installer.waits("chrome"))
        XCTAssertTrue(installer.hostsReady, "\(installer.manifests)")
        XCTAssertFalse(installer.hostsToConnect, "nothing left to connect: no button")

        // The app opens again: Chrome still waits, with no button.
        let again = try self.installer()
        await again.refresh(info: nil)
        XCTAssertEqual(again.waitingForStore, ["chrome"])
        XCTAssertFalse(again.hostsToConnect)
    }

    func testOnlyChromiumBrowsersIsNotAProblem() async throws {
        let installer = try installer()
        _ = try mkdir("\(support)/Google/Chrome")
        await installer.installHosts()
        XCTAssertNil(installer.problems[.hosts], "the step says Chrome waits for the store")
        XCTAssertEqual(installer.waitingForStore, ["chrome"])
        XCTAssertFalse(installer.hostsReady)
        XCTAssertFalse(installer.hostsToConnect)
        XCTAssertFalse(FileManager.default.fileExists(atPath: chromeManifest.path))
    }

    func testTheDevelopmentExtensionIsKeptAndTurningItOffTakesItsWayIn() async throws {
        let installer = try installer()
        _ = try mkdir("\(support)/Google/Chrome")
        _ = try mkdir("\(support)/Mozilla")
        await installer.installHosts()
        XCTAssertTrue(installer.waits("chrome"))

        await installer.setDevExtension(true)
        XCTAssertTrue(defaults.bool(forKey: Installer.devExtensionKey), "in the app's preferences")
        XCTAssertFalse(installer.waits("chrome"))
        XCTAssertTrue(installer.hostsToConnect, "Chrome can be connected now")
        await installer.installHosts()
        XCTAssertNil(installer.problems[.hosts])
        XCTAssertTrue(try String(contentsOf: chromeManifest, encoding: .utf8).contains(devID))
        XCTAssertTrue(try String(contentsOf: wrapper, encoding: .utf8).contains(devID))
        XCTAssertTrue(installer.hostsReady)
        XCTAssertTrue(try self.installer().devExtension, "kept for the next launch")

        await installer.setDevExtension(false)
        XCTAssertNil(installer.problems[.hosts])
        XCTAssertFalse(defaults.bool(forKey: Installer.devExtensionKey))
        let fm = FileManager.default
        XCTAssertFalse(fm.fileExists(atPath: chromeManifest.path), "Chrome's manifest goes at once")
        XCTAssertFalse(try String(contentsOf: wrapper, encoding: .utf8).contains(devID), "the host no longer lets it in")
        XCTAssertTrue(fm.fileExists(atPath: firefoxManifest.path), "Firefox stays connected")
        XCTAssertEqual(installer.waitingForStore, ["chrome"])
        XCTAssertTrue(installer.hostsReady)
    }

    /// The person, in Terminal, with this app's klav (the link of step 2),
    /// runs what the install guide tells a CLI user to run.
    private func installHostFromTheCommandLine() throws {
        let cli = try runTool(helpers.appendingPathComponent("klav"),
                              ["extension", "install-host", "--dev",
                               "--host", helpers.appendingPathComponent("klav-native-host").path],
                              environment: ["HOME": root.appendingPathComponent("user").path,
                                            "KLAV_HOME": root.appendingPathComponent("home").path])
        XCTAssertEqual(cli.status, 0, cli.errors)
        XCTAssertTrue(try String(contentsOf: chromeManifest, encoding: .utf8).contains(devID))
    }

    /// `klav extension install-host --dev` let the development build in. The
    /// app says so, never turns «Development extension» on by itself, and
    /// launching changes nothing; connecting the browsers asks first.
    func testADevelopmentBuildTheCLIConnectedIsSaidAndLaunchChangesNothing() async throws {
        _ = try mkdir("\(support)/Google/Chrome")
        _ = try mkdir("\(support)/Mozilla")
        try installHostFromTheCommandLine()
        let manifest = try String(contentsOf: chromeManifest, encoding: .utf8)
        let script = try String(contentsOf: wrapper, encoding: .utf8)

        for _ in 0..<2 {
            let installer = try installer()
            await installer.refresh(info: nil)
            XCTAssertFalse(installer.devExtension, "never turned on by the app")
            XCTAssertFalse(defaults.bool(forKey: Installer.devExtensionKey))
            XCTAssertEqual(installer.cliDevBrowsers, ["chrome"], "the Browsers step says so, and connecting asks")
            XCTAssertFalse(installer.waits("chrome"), "it does reach klavd")
            XCTAssertTrue(installer.hostsReady, "\(installer.manifests)")
        }
        XCTAssertEqual(try String(contentsOf: chromeManifest, encoding: .utf8), manifest, "launching changed nothing")
        XCTAssertEqual(try String(contentsOf: wrapper, encoding: .utf8), script)
    }

    func testKeepingTheCLIsDevelopmentExtensionTurnsTheSwitchOn() async throws {
        _ = try mkdir("\(support)/Google/Chrome")
        _ = try mkdir("\(support)/Mozilla")
        try installHostFromTheCommandLine()
        let installer = try installer()
        await installer.refresh(info: nil)
        XCTAssertEqual(installer.cliDevBrowsers, ["chrome"])

        await installer.connectHosts(keepingDevelopment: true)
        XCTAssertNil(installer.problems[.hosts])
        XCTAssertTrue(installer.devExtension)
        XCTAssertTrue(defaults.bool(forKey: Installer.devExtensionKey))
        XCTAssertTrue(try String(contentsOf: chromeManifest, encoding: .utf8).contains(devID))
        XCTAssertTrue(try String(contentsOf: wrapper, encoding: .utf8).contains(devID), "the host still lets it in")
        XCTAssertEqual(installer.cliDevBrowsers, [], "now the switch says it")
        XCTAssertTrue(installer.hostsReady)
    }

    func testRemovingTheCLIsDevelopmentExtensionTakesItsWayIn() async throws {
        _ = try mkdir("\(support)/Google/Chrome")
        _ = try mkdir("\(support)/Mozilla")
        try installHostFromTheCommandLine()
        let installer = try installer()
        await installer.refresh(info: nil)

        await installer.connectHosts(keepingDevelopment: false)
        XCTAssertNil(installer.problems[.hosts])
        XCTAssertFalse(installer.devExtension)
        XCTAssertFalse(FileManager.default.fileExists(atPath: chromeManifest.path), "Chrome's manifest goes")
        XCTAssertFalse(try String(contentsOf: wrapper, encoding: .utf8).contains(devID), "the host no longer lets it in")
        XCTAssertTrue(FileManager.default.fileExists(atPath: firefoxManifest.path), "Firefox stays connected")
        XCTAssertEqual(installer.cliDevBrowsers, [])
        XCTAssertTrue(installer.waits("chrome"))
    }

    /// «Remove it» is one step: `busy` is set before anything is deleted, so
    /// the buttons are disabled for all of it.
    func testRemovingTheCLIsDevelopmentExtensionIsOneStep() async throws {
        _ = try mkdir("\(support)/Google/Chrome")
        _ = try mkdir("\(support)/Mozilla")
        try installHostFromTheCommandLine()
        let installer = try installer()
        await installer.refresh(info: nil)
        var manifestWhenBusy: Bool?
        let watch = installer.$busy.sink { [chromeManifest] busy in
            if busy == .hosts, manifestWhenBusy == nil {
                manifestWhenBusy = FileManager.default.fileExists(atPath: chromeManifest.path)
            }
        }
        await installer.connectHosts(keepingDevelopment: false)
        watch.cancel()
        XCTAssertEqual(manifestWhenBusy, true, "busy before Chrome's manifest goes")
        XCTAssertNil(installer.busy)
        XCTAssertFalse(FileManager.default.fileExists(atPath: chromeManifest.path))
    }

    /// A Mac with only Chromium browsers: `install-host` has nothing to
    /// allow and stops before writing a wrapper. «Remove it» takes this
    /// home's wrapper too, so nothing lists the development build, also for
    /// a manifest `host-status` doesn't see (`--user-data-dir`), which now
    /// points at nothing (`docs/macos.md` §3, step 3).
    func testRemovingItWithOnlyChromeLeavesNoBrowserAWayIn() async throws {
        _ = try mkdir("\(support)/Google/Chrome")
        try installHostFromTheCommandLine()
        let custom = root.appendingPathComponent("custom-profile")
        let cli = try runTool(helpers.appendingPathComponent("klav"),
                              ["extension", "install-host", "--dev", "--user-data-dir", custom.path,
                               "--host", helpers.appendingPathComponent("klav-native-host").path],
                              environment: ["HOME": root.appendingPathComponent("user").path,
                                            "KLAV_HOME": root.appendingPathComponent("home").path])
        XCTAssertEqual(cli.status, 0, cli.errors)
        let customManifest = custom.appendingPathComponent("NativeMessagingHosts/dev.klav.host.json")
        XCTAssertTrue(try String(contentsOf: customManifest, encoding: .utf8).contains(wrapper.path))
        let installer = try installer()
        await installer.refresh(info: nil)
        XCTAssertEqual(installer.cliDevBrowsers, ["chrome"])
        XCTAssertFalse(installer.manifests.contains { $0.path == customManifest.path }, "host-status doesn't list it")

        await installer.connectHosts(keepingDevelopment: false)
        XCTAssertNil(installer.problems[.hosts], "nothing to allow is not a failure")
        XCTAssertFalse(installer.devExtension)
        XCTAssertFalse(FileManager.default.fileExists(atPath: chromeManifest.path), "Chrome's manifest goes")
        XCTAssertFalse(FileManager.default.fileExists(atPath: wrapper.path),
                       "the wrapper goes, and install-host had nothing to write it again for")
        XCTAssertFalse(installer.manifests.contains { $0.exists && $0.listsDevelopmentBuild })
        XCTAssertEqual(installer.cliDevBrowsers, [])
        XCTAssertEqual(installer.waitingForStore, ["chrome"])
    }

    /// `host-status` fails while «Connect the browsers» reads the browsers
    /// again: nothing is connected (which would drop the development build
    /// without asking), and the step says why.
    func testAFailedReadOfTheBrowsersConnectsNothing() async throws {
        _ = try mkdir("\(support)/Google/Chrome")
        _ = try mkdir("\(support)/Mozilla")
        try installHostFromTheCommandLine()
        let system = SampleSystem()
        let installer = try installer(system: system)
        await installer.refresh(info: nil)
        XCTAssertEqual(installer.cliDevBrowsers, ["chrome"])
        let script = try String(contentsOf: wrapper, encoding: .utf8)
        let firefox = try String(contentsOf: firefoxManifest, encoding: .utf8)

        system.failHostStatus("host-status could not read the browsers")
        let answer = await installer.connectBrowsers(info: nil, replacingForeign: false)
        XCTAssertEqual(answer, .none)
        XCTAssertTrue(installer.problems[.hosts]?.contains("host-status could not read the browsers") == true,
                      "\(String(describing: installer.problems[.hosts]))")
        XCTAssertEqual(try String(contentsOf: wrapper, encoding: .utf8), script, "nothing written")
        XCTAssertEqual(try String(contentsOf: firefoxManifest, encoding: .utf8), firefox)
        XCTAssertNil(installer.busy)
    }

    /// A slow `refresh` that read the browsers before a newer read ends
    /// after it: its older list never comes back.
    func testAnOlderReadOfTheBrowsersNeverWins() async throws {
        _ = try mkdir("\(support)/Google/Chrome")
        _ = try mkdir("\(support)/Mozilla")
        let system = SampleSystem()
        let installer = try installer(system: system)
        let read = DispatchSemaphore(value: 0), gate = DispatchSemaphore(value: 0)
        system.afterEachHostStatus {
            read.signal()
            _ = gate.wait(timeout: .now() + 10)
        }
        let old = Task { await installer.refresh(info: nil) }
        let started = await Task.detached { read.wait(timeout: .now() + 10) == .success }.value
        XCTAssertTrue(started, "the old refresh read the browsers")
        system.afterEachHostStatus(nil)

        try installHostFromTheCommandLine()
        await installer.refresh(info: nil)
        XCTAssertEqual(installer.cliDevBrowsers, ["chrome"], "the newer read")
        gate.signal()
        await old.value
        XCTAssertEqual(installer.cliDevBrowsers, ["chrome"], "the older one, ending last, didn't put its list back")
    }

    /// The window read the browsers before the person ran `install-host
    /// --dev` in Terminal. «Connect the browsers» reads them again, and asks
    /// instead of connecting on the old reading (which dropped the
    /// development build without a question).
    func testConnectingReadsTheBrowsersAgainBeforeDeciding() async throws {
        _ = try mkdir("\(support)/Google/Chrome")
        _ = try mkdir("\(support)/Mozilla")
        let installer = try installer()
        await installer.refresh(info: nil)
        XCTAssertEqual(installer.cliDevBrowsers, [])
        XCTAssertTrue(installer.hostsToConnect, "the button shows «Connect the browsers»")

        try installHostFromTheCommandLine()
        let script = try String(contentsOf: wrapper, encoding: .utf8)
        let question = await installer.connectBrowsers(info: nil, replacingForeign: false)
        XCTAssertEqual(question, .development, "asks: «Keep the development extension?»")
        XCTAssertEqual(try String(contentsOf: wrapper, encoding: .utf8), script, "nothing written before the answer")
        XCTAssertTrue(try String(contentsOf: chromeManifest, encoding: .utf8).contains(devID))

        // Nothing new: it connects at once.
        await installer.connectHosts(keepingDevelopment: true)
        let answer1 = await installer.connectBrowsers(info: nil, replacingForeign: false)
        XCTAssertEqual(answer1, .none)
    }

    /// Another `klav`, with its own host (a copy of this one), runs
    /// `install-host --dev` with `klavHome`: another install's manifests.
    @discardableResult
    private func installHostFromAnotherKlav(klavHome: String) throws -> URL {
        let otherHost = root.appendingPathComponent("other-klav/klav-native-host")
        if !FileManager.default.fileExists(atPath: otherHost.path) {
            try FileManager.default.createDirectory(at: otherHost.deletingLastPathComponent(), withIntermediateDirectories: true)
            try FileManager.default.copyItem(at: helpers.appendingPathComponent("klav-native-host"), to: otherHost)
        }
        let cli = try runTool(helpers.appendingPathComponent("klav"),
                              ["extension", "install-host", "--dev", "--host", otherHost.path],
                              environment: ["HOME": root.appendingPathComponent("user").path,
                                            "KLAV_HOME": root.appendingPathComponent(klavHome).path])
        XCTAssertEqual(cli.status, 0, cli.errors)
        return otherHost
    }

    private let shutOut = "The host there now lets the development extension into Chrome. This app’s won’t while “Development extension” is off, so it stops connecting there."
    private let stillConnects = "Another install’s host lets the development extension into Chrome. Klav can’t replace it there until Klav is in the Chrome Web Store, so the development extension still connects."

    /// Case 1 of 3: another `klav` (its own host, this `KLAV_HOME`) connected
    /// the development build, and Firefox is here. «Use this app’s» rewrites
    /// this home's wrapper without that build, so it is shut out of Chrome,
    /// and the question says so, in both languages.
    func testReplacingAnotherInstallsDevelopmentConnectionSaysItShutsItOut() async throws {
        _ = try mkdir("\(support)/Google/Chrome")
        _ = try mkdir("\(support)/Mozilla")
        try installHostFromAnotherKlav(klavHome: "home")

        let installer = try installer()
        await installer.refresh(info: nil)
        XCTAssertTrue(installer.foreignManifests.contains { $0.path == chromeManifest.path }, "\(installer.manifests)")
        XCTAssertEqual(installer.foreignDevBrowsers, ["chrome"])
        XCTAssertEqual(installer.foreignDevKept, [])
        XCTAssertEqual(installer.cliDevBrowsers, [], "not this app's: the other question")
        XCTAssertEqual(installer.foreignHostsMessage.components(separatedBy: "\n").last, shutOut)
        let answer2 = await installer.connectBrowsers(info: nil, replacingForeign: false)
        XCTAssertEqual(answer2, .foreign)

        let es = try XCTUnwrap(Bundle(for: MacModel.self).path(forResource: "es", ofType: "lproj").flatMap(Bundle.init(path:)))
        let key = "The host there now lets the development extension into %@. This app’s won’t while “Development extension” is off, so it stops connecting there."
        XCTAssertEqual(es.localizedString(forKey: key, value: nil, table: nil),
                       "El host que hay ahora deja entrar la extensión de desarrollo en %@. El de esta app no lo hará mientras «Extensión de desarrollo» esté apagada, así que ahí deja de conectarse.")

        // «Use this app’s»: replaced, and the development build is out.
        let answer3 = await installer.connectBrowsers(info: nil, replacingForeign: true)
        XCTAssertEqual(answer3, .none)
        XCTAssertNil(installer.problems[.hosts])
        XCTAssertTrue(installer.foreignManifests.isEmpty)
        XCTAssertFalse(try String(contentsOf: wrapper, encoding: .utf8).contains(devID), "the door is shut")
        XCTAssertEqual(installer.foreignDevKept, [])
        XCTAssertNil(installer.foreignDevKeptLine)
    }

    /// Case 2 of 3: the same, with only Chromium browsers. `install-host`
    /// would stop before writing the wrapper, so nothing changes: no
    /// promise to shut it out, no replacing offered, and the step keeps
    /// saying the development build gets in, also after connecting.
    func testWithOnlyChromeAnotherInstallsDevelopmentConnectionIsSaidToStay() async throws {
        _ = try mkdir("\(support)/Google/Chrome")
        try installHostFromAnotherKlav(klavHome: "home")
        let installer = try installer()
        await installer.refresh(info: nil)
        XCTAssertEqual(installer.foreignDevBrowsers, [], "nothing would shut it out")
        XCTAssertEqual(installer.foreignDevKept, ["chrome"])
        XCTAssertEqual(installer.foreignDevKeptLine, stillConnects)
        XCTAssertTrue(installer.foreignManifests.isEmpty, "no replacing offered that can't happen")

        let answer = await installer.connectBrowsers(info: nil, replacingForeign: false)
        XCTAssertEqual(answer, .none)
        XCTAssertTrue(try String(contentsOf: wrapper, encoding: .utf8).contains(devID), "the door is still open…")
        XCTAssertEqual(installer.waitingForStore, ["chrome"])
        XCTAssertFalse(installer.waits("chrome"), "…and not hidden as waiting for the store")
        XCTAssertEqual(installer.foreignDevKept, ["chrome"])
        XCTAssertEqual(installer.foreignDevKeptLine, stillConnects)

        let es = try XCTUnwrap(Bundle(for: MacModel.self).path(forResource: "es", ofType: "lproj").flatMap(Bundle.init(path:)))
        XCTAssertEqual(es.localizedString(forKey: "Another install’s host lets the development extension into %@. Klav can’t replace it there until Klav is in the Chrome Web Store, so the development extension still connects.", value: nil, table: nil),
                       "El host de otra instalación deja entrar la extensión de desarrollo en %@. Klav no puede reemplazarlo ahí mientras no esté en Chrome Web Store, así que la extensión de desarrollo se sigue conectando.")
    }

    /// Case 3 of 3: another `klav` with another `KLAV_HOME` (its own
    /// wrapper), Firefox here too. «Use this app’s» replaces Firefox's
    /// manifest, but nothing of the other install's Chrome changes: the
    /// question says the development build still connects there, and the
    /// step keeps saying it afterwards.
    func testAnotherHomesDevelopmentConnectionIsSaidToStay() async throws {
        _ = try mkdir("\(support)/Google/Chrome")
        _ = try mkdir("\(support)/Mozilla")
        try installHostFromAnotherKlav(klavHome: "other-home")
        let chrome = try String(contentsOf: chromeManifest, encoding: .utf8)
        let installer = try installer()
        await installer.refresh(info: nil)
        XCTAssertEqual(installer.foreignDevBrowsers, [])
        XCTAssertEqual(installer.foreignDevKept, ["chrome"])
        XCTAssertEqual(installer.foreignManifests.map(\.browser), ["firefox"], "only what can be replaced")
        let lines = installer.foreignHostsMessage.components(separatedBy: "\n")
        XCTAssertEqual(lines.last, stillConnects)
        XCTAssertFalse(installer.foreignHostsMessage.contains("stops connecting"))

        let answer = await installer.connectBrowsers(info: nil, replacingForeign: true)
        XCTAssertEqual(answer, .none)
        XCTAssertNil(installer.problems[.hosts])
        XCTAssertTrue(installer.foreignManifests.isEmpty)
        XCTAssertEqual(try String(contentsOf: chromeManifest, encoding: .utf8), chrome, "the other install's Chrome is as it was")
        XCTAssertTrue(try String(contentsOf: root.appendingPathComponent("other-home/native-host/klav-native-host"),
                                 encoding: .utf8).contains(devID), "its door is open…")
        XCTAssertEqual(installer.foreignDevKept, ["chrome"], "…and still said")
        XCTAssertEqual(installer.foreignDevKeptLine, stillConnects)
    }

    /// Turning the switch off while the app refreshes can't end with it on:
    /// nothing turns it on but the person, even when the command line lets
    /// the development build in again afterwards.
    func testTurningTheDevelopmentExtensionOffCannotEndWithItOn() async throws {
        _ = try mkdir("\(support)/Google/Chrome")
        _ = try mkdir("\(support)/Mozilla")
        let installer = try installer()
        await installer.setDevExtension(true)
        await installer.installHosts()
        XCTAssertTrue(installer.hostsReady)

        async let off: Void = installer.setDevExtension(false)
        async let refreshed: Void = installer.refresh(info: nil)
        _ = await (off, refreshed)
        await installer.refresh(info: nil)
        XCTAssertFalse(installer.devExtension)
        XCTAssertFalse(defaults.bool(forKey: Installer.devExtensionKey))

        try installHostFromTheCommandLine()
        await installer.refresh(info: nil)
        XCTAssertFalse(installer.devExtension, "said, not turned on")
        XCTAssertEqual(installer.cliDevBrowsers, ["chrome"])
    }

    func testOnlyAWorkingDevelopmentConnectionIsSaid() async throws {
        _ = try mkdir("\(support)/Google/Chrome")
        _ = try mkdir("\(support)/Mozilla")
        let installer = try installer()
        await installer.installHosts()
        await installer.refresh(info: nil)
        XCTAssertEqual(installer.cliDevBrowsers, [], "Firefox alone says nothing about the development build")

        // Chrome's manifest lists the development build, but the host
        // turns it away (an older wrapper): not a working way in.
        await installer.setDevExtension(true)
        await installer.installHosts()
        try dropDevExtensionFromWrapper()
        defaults.set(false, forKey: Installer.devExtensionKey)
        let fresh = try self.installer()
        await fresh.refresh(info: nil)
        XCTAssertFalse(fresh.devExtension)
        XCTAssertEqual(fresh.cliDevBrowsers, [])
    }

    /// This app's wrapper as `install-host` wrote it before the development
    /// build needed `--dev`: the manifests still list that build, and the
    /// host turns it away.
    private func dropDevExtensionFromWrapper() throws {
        let script = try String(contentsOf: wrapper, encoding: .utf8)
        let old = script.replacingOccurrences(of: " --allow 'chrome-extension://\(devID)/'", with: "")
        XCTAssertNotEqual(old, script, script)
        // In place: the wrapper keeps its permissions.
        try old.write(to: wrapper, atomically: false, encoding: .utf8)
    }

    func testThisAppsManifestWithAnOutdatedWrapperIsConnectedAgainWithoutAsking() async throws {
        let installer = try installer()
        _ = try mkdir("\(support)/Google/Chrome")
        _ = try mkdir("\(support)/Mozilla")
        await installer.setDevExtension(true)
        await installer.installHosts()
        XCTAssertTrue(installer.hostsReady, "\(installer.manifests)")

        try dropDevExtensionFromWrapper()
        await installer.refresh(info: nil)
        let chrome = try XCTUnwrap(installer.manifests.first { $0.path == chromeManifest.path })
        XCTAssertFalse(chrome.current)
        XCTAssertEqual(chrome.refused, ["chrome-extension://\(devID)/"])
        XCTAssertEqual(chrome.pointsTo, wrapper.path)
        XCTAssertTrue(chrome.ours)
        XCTAssertTrue(chrome.outdated)
        XCTAssertFalse(chrome.foreign)
        let firefox = try XCTUnwrap(installer.manifests.first { $0.path == firefoxManifest.path })
        XCTAssertTrue(firefox.current, "Firefox's add-on still gets in")
        XCTAssertNil(firefox.refused)
        XCTAssertFalse(firefox.outdated)
        XCTAssertTrue(installer.foreignManifests.isEmpty, "this app's own: nothing to ask")
        XCTAssertTrue(installer.hostsToConnect)
        XCTAssertFalse(installer.hostsReady)

        // «Connect the browsers», with no question in between.
        await installer.installHosts()
        XCTAssertNil(installer.problems[.hosts])
        XCTAssertTrue(installer.hostsReady, "\(installer.manifests)")
        XCTAssertTrue(installer.manifests.allSatisfy { $0.refused == nil }, "\(installer.manifests)")
        XCTAssertTrue(try String(contentsOf: wrapper, encoding: .utf8).contains(devID))
    }

    func testTurningTheDevelopmentExtensionOffTakesAnOutdatedManifestToo() async throws {
        let installer = try installer()
        _ = try mkdir("\(support)/Google/Chrome")
        _ = try mkdir("\(support)/Mozilla")
        await installer.setDevExtension(true)
        await installer.installHosts()
        try dropDevExtensionFromWrapper()
        await installer.refresh(info: nil)
        XCTAssertEqual(installer.manifests.first { $0.path == chromeManifest.path }?.outdated, true)

        await installer.setDevExtension(false)
        XCTAssertNil(installer.problems[.hosts])
        let fm = FileManager.default
        XCTAssertFalse(fm.fileExists(atPath: chromeManifest.path),
                       "it still lists the development build: it goes at once")
        XCTAssertTrue(fm.fileExists(atPath: firefoxManifest.path))
        XCTAssertTrue(installer.hostsReady)
    }

    /// The same host, but through another `KLAV_HOME`'s wrapper that turns
    /// away what the manifest lists: another install's, so the app asks
    /// before replacing it and uninstalling leaves it.
    func testAnotherHomesWrapperIsForeignEvenWhenItRunsThisAppsHost() async throws {
        let installer = try installer()
        _ = try mkdir("\(support)/Google/Chrome")
        await installer.setDevExtension(true)
        await installer.installHosts()
        let host = try XCTUnwrap(installer.manifests.first { $0.path == chromeManifest.path }?.runs)

        let other = try write("#!/bin/sh\nexec \(shellQuote(host)) --home \(shellQuote(root.appendingPathComponent("other").path)) \"$@\"\n",
                              to: "other/native-host/klav-native-host", executable: true)
        let manifest = #"{"name":"dev.klav.host","path":"\#(other.path)","type":"stdio","allowed_origins":["chrome-extension://\#(devID)/"]}"#
        try manifest.write(to: chromeManifest, atomically: true, encoding: .utf8)

        await installer.refresh(info: nil)
        let chrome = try XCTUnwrap(installer.manifests.first { $0.path == chromeManifest.path })
        XCTAssertEqual(chrome.refused, ["chrome-extension://\(devID)/"])
        XCTAssertEqual(chrome.runs, host, "only the wrapper is another home's")
        XCTAssertEqual(chrome.pointsTo, other.path)
        XCTAssertFalse(chrome.ours)
        XCTAssertFalse(chrome.outdated)
        XCTAssertTrue(chrome.foreign)
        XCTAssertEqual(installer.foreignManifests.map(\.path), [chromeManifest.path])
        XCTAssertEqual(try String(contentsOf: chromeManifest, encoding: .utf8), manifest, "reading changes nothing")

        let done = await installer.uninstall(engine: SampleEngine(locked: false, touchID: true), deleteHome: false)
        XCTAssertTrue(done, "\(installer.problems)")
        XCTAssertEqual(try String(contentsOf: chromeManifest, encoding: .utf8), manifest, "another install's stays")
    }

    func testTheLinkNeverReplacesAnotherKlavWithoutAsking() async throws {
        let installer = try installer()
        let other = try write("#!/bin/sh\n", to: "bin/klav", executable: true)
        _ = try write("#!/bin/sh\n", to: "cargo-bin/klav", executable: true)

        await installer.refresh(info: nil)
        XCTAssertEqual(installer.link, .other(other.path))
        XCTAssertEqual(installer.otherCLIs, [root.appendingPathComponent("cargo-bin/klav").path])

        await installer.linkCLI(replace: false)
        XCTAssertEqual(try String(contentsOf: other, encoding: .utf8), "#!/bin/sh\n", "not replaced")

        await installer.linkCLI(replace: true)
        XCTAssertEqual(installer.link, .ours)
        XCTAssertEqual(try FileManager.default.destinationOfSymbolicLink(atPath: other.path),
                       helpers.appendingPathComponent("klav").path)
    }

    func testARootOwnedDirectoryAsksForTheAdministratorsPassword() async throws {
        let system = SampleSystem()
        let installer = try installer(system: system, linkDir: "missing/bin")
        await installer.linkCLI(replace: false)
        // SampleSystem says the person cancelled: nothing to report.
        XCTAssertNil(installer.problems[.cli])
        XCTAssertEqual(system.administratorCommands.count, 1)
        let command = try XCTUnwrap(system.administratorCommands.first)
        XCTAssertTrue(command.contains("/bin/ln -sfn '\(helpers.appendingPathComponent("klav").path)'"), command)
        XCTAssertTrue(installer.linkCommand.hasPrefix("sudo mkdir -p "), installer.linkCommand)
    }

    func testTheBackgroundServiceAndAnotherKlavd() async throws {
        let system = SampleSystem()
        let installer = try installer(system: system)
        await installer.setUpDaemon(engine: SampleEngine(locked: false, touchID: true), info: nil)
        XCTAssertEqual(installer.agent, .enabled)

        let engine = SampleEngine(locked: false, touchID: true)
        system.other = "/Users/ana/.cargo/bin/klavd"
        await installer.refresh(info: engine.status())
        XCTAssertEqual(installer.otherDaemon, "/Users/ana/.cargo/bin/klavd")
        XCTAssertFalse(installer.daemonReady)
        let restarted = await installer.restartIfOutdated(engine: engine, info: engine.status())
        XCTAssertFalse(restarted, "another klavd is not restarted behind the person's back")

        // The kernel names the binary inside klavd.app (where the link
        // leads); the link itself is the same klavd too.
        for path in ["klavd.app/Contents/MacOS/klavd", "klavd"] {
            system.other = helpers.appendingPathComponent(path).path
            await installer.refresh(info: engine.status())
            XCTAssertNil(installer.otherDaemon, path)
            XCTAssertTrue(installer.daemonReady, path)
        }
    }

    func testAnUpdatedAppRestartsTheOldKlavd() async throws {
        let system = SampleSystem(agent: .enabled)
        let installer = try installer(system: system)
        let engine = SampleEngine(locked: false, touchID: true)
        await installer.refresh(info: nil)
        let helper = try XCTUnwrap(installer.helperBuild())
        guard let commit = helper.commit, let time = helper.time else {
            throw XCTSkip("these helpers were built without Git history: \(helper.described)")
        }
        var restarts = 0
        func check(_ info: DaemonInfo, restarts expected: Bool, _ what: String) async {
            let restarted = await installer.restartIfOutdated(engine: engine, info: info)
            XCTAssertEqual(restarted, expected, what)
            if restarted { restarts += 1 }
            XCTAssertEqual(system.restarts, restarts, what)
        }

        // The same build: `status` gives the whole hash, `--version` 12 digits.
        var info = engine.status()
        info.version = helper.version
        info.commit = commit + String(repeating: "0", count: 40 - commit.count)
        info.commitTime = UInt64(time.timeIntervalSince1970)
        await check(info, restarts: false, "the same commit")

        // The bug this fixes: an old klavd and the new one both said 0.0.0.
        info.commit = nil
        info.commitTime = nil
        await check(info, restarts: true, "a klavd from before builds said their commit")

        info.commit = "0123456789ab"
        info.commitTime = UInt64(time.timeIntervalSince1970) - 3600
        await check(info, restarts: true, "another commit, older")
        info.commitTime = UInt64(time.timeIntervalSince1970) + 3600
        await check(info, restarts: true, "another commit, newer: still not the bundle's")

        info.commit = commit
        info.commitTime = UInt64(time.timeIntervalSince1970)
        info.version = "9.9.9"
        await check(info, restarts: false, "the commit decides, not the number")
    }

    /// `--version` is read strictly: anything but `klav <number>`, with an
    /// optional `(commit unknown)` or `(<hash> <time>)`, is not a Klav
    /// answer, and nothing else of it reaches the screen.
    func testVersionOutputIsReadStrictly() {
        func parse(_ text: String, _ program: String = "klav") -> BuildIdentity? {
            BuildIdentity(versionOutput: Data(text.utf8), program: program)
        }
        let full = parse("klav 0.0.0 (ce4fa5099092 2026-11-13T18:17:02Z)\n")
        XCTAssertEqual(full?.commit, "ce4fa5099092")
        XCTAssertEqual(full?.time, Date(timeIntervalSince1970: 1_794_593_822))
        XCTAssertEqual(parse("klavd 0.0.0 (ce4fa5099092 2026-11-13T18:17:02Z)", "klavd")?.version, "0.0.0")
        XCTAssertEqual(parse("klav 0.0.0")?.known, false)
        XCTAssertEqual(parse("klav 0.0.0 (commit unknown)")?.unknownCommit, true)
        for bad in ["klavd 0.0.0", "klav", "klav 0.0.0 (CE4FA5099092 2026-11-13T18:17:02Z)",
                    "klav 0.0.0 (ce4fa50 2026-11-13T18:17:02+01:00)", "klav 0.0.0 extra",
                    "klav 0.0.0\nklav 0.0.0", "klav \u{202E}0.0.0", "klav 0.0.0\u{1b}[2J",
                    "klav " + String(repeating: "1", count: 600)] {
            XCTAssertNil(parse(bad), bad)
        }

        var info = SampleEngine(locked: false, touchID: true).status()
        info.commit = "ce4fa50990924bf17d349b752ad8020ff6b3a9ff"
        info.commitTime = 1_794_593_822
        let running = BuildIdentity(status: info)
        XCTAssertTrue(running.sameBuild(as: full!))
        XCTAssertEqual(full!.age(comparedWith: running), .same)
        info.commit = "not hex"
        XCTAssertFalse(BuildIdentity(status: info).known, "a malformed commit is no commit")
        // This app's build doesn't say its commit: nothing is called older.
        let ours = BuildIdentity(version: "0.0.0", commit: nil, time: nil, unknownCommit: true)
        XCTAssertEqual(parse("klav 0.0.0")!.age(comparedWith: ours), .unknown)
        // One that prints only its number is neutral too, never older.
        XCTAssertEqual(parse("klav 0.0.0")!.age(comparedWith: full!), .unknown)
    }

    /// Neither says its commit (a build from a source without Git): the
    /// numbers decide, as before build identities.
    func testWithoutCommitsTheNumbersDecideTheRestart() {
        let a = BuildIdentity(version: "0.0.0", commit: nil, time: nil)
        XCTAssertTrue(a.sameBuild(as: BuildIdentity(version: "0.0.0", commit: nil, time: nil, unknownCommit: true)))
        XCTAssertFalse(a.sameBuild(as: BuildIdentity(version: "0.1.0", commit: nil, time: nil)))
        XCTAssertFalse(a.sameBuild(as: BuildIdentity(version: "0.0.0", commit: "ce4fa5099092", time: Date())))
    }

    // MARK: Another klav on the PATH (docs/macos.md §3)

    /// A `klav` that is never run: a shell script that would leave
    /// `ran-<name>` in the test's folder if it ran, followed by `marker`
    /// lines the way a build carries them.
    @discardableResult
    private func fakeCLI(at path: String, markers: [String]) throws -> URL {
        let name = path.replacingOccurrences(of: "/", with: "-")
        let body = "#!/bin/sh\ntouch '\(root.path)/ran-\(name)'\nexit 0\n"
            + markers.map { "\u{0}\u{0}klav-build-identity: \($0)\n" }.joined()
        return try write(body, to: path, executable: true)
    }

    /// Nothing the tests made was run.
    private func assertNothingRan(file: StaticString = #filePath, line: UInt = #line) throws {
        let ran = try FileManager.default.contentsOfDirectory(atPath: root.path).filter { $0.hasPrefix("ran-") }
        XCTAssertEqual(ran, [], "the app ran another klav", file: file, line: line)
    }

    /// This app's build, as its own `klav --version` says it; skips when
    /// the helpers were built without Git history (nothing to compare with).
    private func appBuild(_ installer: Installer) async throws -> BuildIdentity {
        await installer.refresh(info: nil)
        let app = try XCTUnwrap(installer.appBuild, "this app's klav --version")
        guard app.known else { throw XCTSkip("these helpers were built without Git history: \(app.described)") }
        return app
    }

    private func stamp(_ date: Date) -> String {
        ISO8601DateFormatter().string(from: date)
    }

    func testAnOlderKlavIsNamedFromItsFileAndNeverRun() async throws {
        let installer = try installer()
        let app = try await appBuild(installer)
        let time = try XCTUnwrap(app.time)
        let old = try fakeCLI(at: "cargo-bin/klav", markers: ["0.0.0 (0123456789ab \(stamp(time - 3600)))"])
        let before = try Data(contentsOf: old)
        await installer.refresh(info: nil)
        let cli = try XCTUnwrap(installer.checkedCLIs.first)
        XCTAssertEqual(cli.path, old.path)
        XCTAssertEqual(cli.age, .older)
        XCTAssertEqual(cli.build?.commit, "0123456789ab")
        XCTAssertEqual(cli.origin, .other)
        XCTAssertNil(cli.command, "neither cargo nor Homebrew: no command")
        XCTAssertEqual(installer.olderCLIs.map(\.path), [old.path])
        XCTAssertEqual(installer.appBuild, app)
        XCTAssertEqual(try Data(contentsOf: old), before, "reading changes nothing")
        try assertNothingRan()

        // «Not now» in the menu bar holds across launches, for these builds.
        XCTAssertEqual(installer.shownOlderCLIs.count, 1)
        installer.leave(cli)
        XCTAssertTrue(installer.shownOlderCLIs.isEmpty)
        let again = try self.installer()
        await again.checkCLIs()
        XCTAssertEqual(again.olderCLIs.count, 1)
        XCTAssertTrue(again.shownOlderCLIs.isEmpty, "left, until a build changes")
        try fakeCLI(at: "cargo-bin/klav", markers: ["0.0.0 (fedcba987654 2020-01-01T00:00:00Z)"])
        let changed = try self.installer()
        await changed.checkCLIs()
        XCTAssertEqual(changed.shownOlderCLIs.count, 1, "another build of it is said again")
        try assertNothingRan()
    }

    /// The four states, by what the file says: older, the same build, newer,
    /// or neutral when it doesn't say its build. Only older is older.
    func testOnlyAMarkerWithAnOlderCommitTimeIsOlder() async throws {
        let installer = try installer()
        let app = try await appBuild(installer)
        let time = try XCTUnwrap(app.time), commit = try XCTUnwrap(app.commit)
        let cases: [([String], BuildIdentity.Age, BuildMarker.Reading?)] = [
            (["0.0.0 (0123456789ab \(stamp(time - 60)))"], .older, nil),
            (["9.9.9 (0123456789ab \(stamp(time - 60)))"], .older, nil),
            (["0.0.0 (0123456789ab \(stamp(time + 60)))"], .newer, nil),
            (["0.0.0 (0123456789ab \(stamp(time)))"], .unknown, nil),
            (["0.0.0 (\(commit) \(stamp(time)))"], .same, nil),
            // A shorter hash of the same commit is the same build, whatever
            // the time or the number says.
            (["9.9.9 (\(commit.prefix(8)) \(stamp(time + 60)))"], .same, nil),
            // Doesn't say its build: neutral, never older.
            ([], .unknown, .silent(.noMarker)),
            (["0.0.0"], .unknown, .silent(.noCommit)),
            (["0.0.0 (commit unknown)"], .unknown, .silent(.noCommit)),
            (["0.0.0 (0123456789ab \(stamp(time - 60)))", "0.0.0 (0123456789ab \(stamp(time - 61)))"],
             .unknown, .silent(.disagree)),
            (["0.0.0 (0123456789ab 2026-11-13)"], .unknown, .silent(.malformed)),
            (["0.0.0 (CE4FA5099092 \(stamp(time - 60)))"], .unknown, .silent(.malformed)),
            (["0.0.0\u{1b}]8;;https://example.com\u{07}"], .unknown, .silent(.malformed)),
            (["0.0.0 \u{202E}(0123456789ab \(stamp(time - 60)))"], .unknown, .silent(.malformed)),
        ]
        for (markers, age, reading) in cases {
            try fakeCLI(at: "cargo-bin/klav", markers: markers)
            await installer.refresh(info: nil)
            let cli = try XCTUnwrap(installer.checkedCLIs.first, "\(markers)")
            XCTAssertEqual(cli.age, age, "\(markers)")
            if let reading { XCTAssertEqual(cli.reading, reading, "\(markers)") }
            if age != .older {
                XCTAssertNil(cli.command, "\(markers)")
                XCTAssertTrue(installer.olderCLIs.isEmpty, "\(markers)")
            }
        }
        try assertNothingRan()
    }

    func testCargoAndHomebrewShowTheirCommandOnlyForAnOlderBuild() async throws {
        let paths = InstallPaths(helpers: helpers, linkDirectory: root.appendingPathComponent("bin"),
                                 userHome: root.appendingPathComponent("user"),
                                 klavHome: root.appendingPathComponent("home"),
                                 pathDirectories: [root.appendingPathComponent("elsewhere/cargo/bin"),
                                                   root.appendingPathComponent("brew/bin"),
                                                   root.appendingPathComponent("brew/opt/bin")])
        guard FileManager.default.isExecutableFile(atPath: paths.cli.path) else {
            throw XCTSkip("this Klav.app was built without its helpers")
        }
        let installer = Installer(paths: paths, system: SampleSystem(), placement: .applications, defaults: defaults)
        let app = try await appBuild(installer)
        let older = "0.0.0 (0123456789ab \(stamp(try XCTUnwrap(app.time) - 3600)))"
        // cargo with CARGO_HOME (or --root) elsewhere: its record is beside bin/.
        let cargo = try fakeCLI(at: "elsewhere/cargo/bin/klav", markers: [older])
        let source = root.appendingPathComponent("src/my klav").path
        let record: [String: Any] = ["installs": [
            "klav-cli 0.0.0 (path+\(URL(fileURLWithPath: source + "/crates/klav-cli").absoluteString))": ["bins": ["klav"]],
            "klav-daemon 0.0.0 (git+https://ana:ghp_s3cret@example.com/klav.git?branch=main#ce4fa50990924bf17d349b752ad8020ff6b3a9ff)":
                ["bins": ["klavd", "klav-native-host"]],
            "ripgrep 14.1.1 (registry+https://github.com/rust-lang/crates.io-index)": ["bins": ["rg"]],
        ]]
        let recordFile = root.appendingPathComponent("elsewhere/cargo/.crates2.json")
        try JSONSerialization.data(withJSONObject: record).write(to: recordFile)
        // Homebrew: a link into a Cellar, and the libexec layout.
        let cellar = try fakeCLI(at: "brew/Cellar/klav/1.2.0/bin/klav", markers: [older])
        _ = try mkdir("brew/bin")
        try FileManager.default.createSymbolicLink(atPath: root.appendingPathComponent("brew/bin/klav").path,
                                                   withDestinationPath: cellar.path)
        let libexec = try fakeCLI(at: "brew/Cellar/klav-tools/2.0/libexec/bin/klav", markers: [older])
        _ = try mkdir("brew/opt/bin")
        try FileManager.default.createSymbolicLink(atPath: root.appendingPathComponent("brew/opt/bin/klav").path,
                                                   withDestinationPath: libexec.path)

        await installer.refresh(info: nil)
        XCTAssertEqual(installer.olderCLIs.count, 3, "\(installer.checkedCLIs)")
        let fromCargo = try XCTUnwrap(installer.checkedCLIs.first { $0.path == cargo.path })
        XCTAssertEqual(fromCargo.command,
                       "cargo install --locked --path '\(source)/crates/klav-cli'"
                       + " && cargo install --locked --git 'https://example.com/klav.git' --branch 'main' klav-daemon",
                       "the token in the https source is left out")
        let fromBrew = try XCTUnwrap(installer.checkedCLIs.first { $0.path.hasSuffix("brew/bin/klav") })
        XCTAssertEqual(fromBrew.origin, .homebrew(formula: "klav"))
        XCTAssertEqual(fromBrew.command, "brew upgrade klav")
        let fromLibexec = try XCTUnwrap(installer.checkedCLIs.first { $0.path.hasSuffix("brew/opt/bin/klav") })
        XCTAssertEqual(fromLibexec.command, "brew upgrade klav-tools")

        // The same files without a marker: neutral, and no command at all.
        try fakeCLI(at: "elsewhere/cargo/bin/klav", markers: [])
        try fakeCLI(at: "brew/Cellar/klav/1.2.0/bin/klav", markers: [])
        await installer.refresh(info: nil)
        for cli in installer.checkedCLIs where !cli.path.hasSuffix("brew/opt/bin/klav") {
            XCTAssertEqual(cli.age, .unknown, cli.path)
            XCTAssertNil(cli.command, cli.path)
        }

        // Without cargo's record, no command is made up.
        try fakeCLI(at: "elsewhere/cargo/bin/klav", markers: [older])
        try FileManager.default.removeItem(at: recordFile)
        await installer.refresh(info: nil)
        XCTAssertEqual(installer.checkedCLIs.first { $0.path == cargo.path }?.origin, .other)
        try assertNothingRan()
    }

    /// An `ssh` source keeps the user it needs; only `https` loses one.
    func testOnlyAnHttpsSourceLosesItsUser() {
        XCTAssertEqual(OtherCLI.installCommand(package: "klav-cli", key: "klav-cli 0.0.0 (git+ssh://git@example.com/klav.git#ce4f)"),
                       "cargo install --locked --git 'ssh://git@example.com/klav.git' klav-cli")
        XCTAssertEqual(OtherCLI.installCommand(package: "klav-cli", key: "klav-cli 0.0.0 (git+https://tok@example.com/klav.git?tag=v1#ce4f)"),
                       "cargo install --locked --git 'https://example.com/klav.git' --tag 'v1' klav-cli")
    }

    /// The reader: only regular files, bounded, every marker, and the
    /// pieces it reads in overlap so a marker split between two is found.
    func testTheReaderReadsOnlyARegularFileAndEveryMarker() throws {
        let line = "0.0.0 (0123456789ab 2026-11-13T18:17:02Z)"
        // A FIFO with no writer: a blocking open would wait forever.
        let fifo = root.appendingPathComponent("fifo-klav").path
        XCTAssertEqual(mkfifo(fifo, 0o755), 0)
        let start = Date()
        XCTAssertEqual(BuildMarker.read(fifo), .silent(.notAFile))
        XCTAssertLessThan(Date().timeIntervalSince(start), 1)
        XCTAssertEqual(BuildMarker.read(try mkdir("dir/klav").path), .silent(.notAFile))
        // A link loop, and nothing there.
        let loop = root.appendingPathComponent("loop-a").path
        try FileManager.default.createSymbolicLink(atPath: loop, withDestinationPath: root.appendingPathComponent("loop-b").path)
        try FileManager.default.createSymbolicLink(atPath: root.appendingPathComponent("loop-b").path, withDestinationPath: loop)
        XCTAssertEqual(BuildMarker.read(loop), .silent(.unreadable))
        XCTAssertEqual(BuildMarker.read(root.appendingPathComponent("missing").path), .silent(.unreadable))

        // Larger than the cap: not read at all, even with a marker first.
        let large = try fakeCLI(at: "large/klav", markers: [line])
        let handle = try FileHandle(forWritingTo: large)
        try handle.truncate(atOffset: UInt64(BuildMarker.cap) + 1)
        try handle.close()
        XCTAssertEqual(BuildMarker.read(large.path), .silent(.tooLarge))

        // A marker split between two pieces, at every byte of the prefix and
        // the line; the same marker twice (two slices that agree) says it once.
        let full = Array("klav-build-identity: \(line)\n".utf8)
        for split in stride(from: 1, to: full.count, by: 3) {
            var bytes = [UInt8](repeating: 0x2E, count: BuildMarker.chunk - split)
            bytes += full
            bytes += [UInt8](repeating: 0x2E, count: 100) + full
            let url = root.appendingPathComponent("split/klav-\(split)")
            try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
            try Data(bytes).write(to: url)
            XCTAssertEqual(BuildMarker.read(url.path).build?.commit, "0123456789ab", "split at \(split)")
        }
        // A prefix whose line never ends is a marker that disagrees.
        var cut = Array("klav-build-identity: \(line)\n".utf8)
        cut += Array("klav-build-identity: ".utf8) + [UInt8](repeating: 0x41, count: 300)
        let broken = root.appendingPathComponent("broken-klav")
        try Data(cut).write(to: broken)
        XCTAssertEqual(BuildMarker.read(broken.path), .silent(.disagree))
        try assertNothingRan()
    }

    /// Memory and time stay small whatever the file: the read ends at the
    /// second marker that differs (or one whose line never ends), and keeps
    /// one marker line, not one per marker.
    func testTheReaderStopsAtTheSecondMarkerThatDiffers() throws {
        // The reviewer's file, made sparse: distinct markers first, then
        // 64 MiB the old reader read to the end, keeping every line.
        let lines = (0..<4096).map { String(format: "klav-build-identity: %08x\n", $0) }.joined()
        let many = root.appendingPathComponent("many-klav")
        try Data(lines.utf8).write(to: many)
        let handle = try FileHandle(forWritingTo: many)
        try handle.truncate(atOffset: 64 * 1024 * 1024)
        try handle.close()
        let outcome = BuildMarker.read(many.path, cached: { _ in nil })
        XCTAssertEqual(outcome.reading, .silent(.disagree))
        XCTAssertLessThanOrEqual(outcome.bytesRead, BuildMarker.chunk, "stops in the first piece")

        // A marker whose line never ends, then more file: the same.
        var cut = Array("klav-build-identity: ".utf8) + [UInt8](repeating: 0x41, count: 300)
        cut += [UInt8](repeating: 0, count: 8 * BuildMarker.chunk)
        let broken = root.appendingPathComponent("cut-klav")
        try Data(cut).write(to: broken)
        let brokenOutcome = BuildMarker.read(broken.path, cached: { _ in nil })
        XCTAssertEqual(brokenOutcome.reading, .silent(.disagree))
        XCTAssertLessThanOrEqual(brokenOutcome.bytesRead, BuildMarker.chunk)

        // The same marker many times (agreeing slices) still reads it all.
        let same = try fakeCLI(at: "same/klav", markers: Array(repeating: "0.0.0 (0123456789ab 2026-11-13T18:17:02Z)", count: 50))
        XCTAssertEqual(BuildMarker.read(same.path).build?.commit, "0123456789ab")
        try assertNothingRan()
    }

    /// A file that hasn't changed isn't read again; one that changed is.
    func testAnUnchangedKlavIsNotReadAgain() throws {
        let reader = BuildMarker.Reader()
        let file = try fakeCLI(at: "cached/klav", markers: ["0.0.0 (0123456789ab 2026-11-13T18:17:02Z)"])
        XCTAssertEqual(reader.read(file.path)?.build?.commit, "0123456789ab")
        let once = reader.bytesRead
        XCTAssertGreaterThan(once, 0)
        XCTAssertEqual(reader.read(file.path)?.build?.commit, "0123456789ab")
        XCTAssertEqual(reader.bytesRead, once, "unchanged: not read again")
        try fakeCLI(at: "cached/klav", markers: ["0.0.0 (fedcba987654 2026-11-13T18:17:02Z)"])
        XCTAssertEqual(reader.read(file.path)?.build?.commit, "fedcba987654", "changed: read again")
        XCTAssertGreaterThan(reader.bytesRead, once)
        try assertNothingRan()
    }

    /// A read that hangs (a `klav` on a hung network volume) gives "not
    /// read" after the limit, and doesn't pile up: the same path gives nil at
    /// once until that read ends, and its result serves the next refresh.
    func testAHungReadIsNotReadAndHoldsNothing() throws {
        let gate = DispatchSemaphore(value: 0)
        let calls = Counter()
        let reader = BuildMarker.Reader(limit: .milliseconds(200)) { _, _, _, _ in
            calls.add()
            if calls.value == 1 { _ = gate.wait(timeout: .now() + 5) }
            let build = BuildIdentity(version: "0.0.0", commit: "0123456789ab", time: Date(timeIntervalSince1970: 0))
            return BuildMarker.JobOutcome(probe: BuildMarker.Probe(present: true, reading: .said(build), origin: .other))
        }
        let start = Date()
        XCTAssertNil(reader.read("/Volumes/hung/klav"), "past the limit: not read")
        XCTAssertNil(reader.read("/Volumes/hung/klav"), "still running: no second read")
        XCTAssertLessThan(Date().timeIntervalSince(start), 2)
        XCTAssertEqual(calls.value, 1)
        gate.signal()
        let deadline = Date().addingTimeInterval(5)
        var later: BuildMarker.Reading?
        while later == nil, Date() < deadline {
            later = reader.read("/Volumes/hung/klav")
            if later == nil { Thread.sleep(forTimeInterval: 0.05) }
        }
        XCTAssertEqual(later?.build?.commit, "0123456789ab", "once it ends, the path is read again")
    }

    /// A cargo record whose decoded text isn't printable ASCII gets no
    /// command: no newline, no right-to-left override, on screen or in the
    /// clipboard.
    func testACommandThatIsntPrintableASCIIIsNotOffered() {
        for key in [
            "klav-cli 0.0.0 (path+file:///tmp/a%0Arm%20-rf%20~%0A/crates/klav-cli)",
            "klav-cli 0.0.0 (git+https://example.com/klav.git?branch=%0Acurl%20evil%7Csh#ce4f)",
            "klav-cli 0.0.0 (path+file:///tmp/kl%E2%80%AEav/crates/klav-cli)",
            "klav-cli 0.0.0 (git+https://example.com/klav.git?tag=v1%E2%80%AE#ce4f)",
        ] {
            XCTAssertNil(OtherCLI.installCommand(package: "klav-cli", key: key), key)
        }
        // A space is printable, and quoted.
        XCTAssertEqual(OtherCLI.installCommand(package: "klav-cli", key: "klav-cli 0.0.0 (path+file:///tmp/my%20klav/crates/klav-cli)"),
                       "cargo install --locked --path '/tmp/my klav/crates/klav-cli'")
        let older = OtherCLI(path: "/x/bin/klav", reading: nil, age: .older,
                             origin: .cargo(command: "cargo install --locked --path '/tmp/a\nb'"))
        XCTAssertNil(older.command, "checked again where it is shown")
    }

    /// The quoting is POSIX, and fish ends a single-quoted string at `\'`:
    /// a backslash (which quoting an apostrophe writes) or a `!` gets no
    /// command, and a record where either install is refused gets none at
    /// all (review of round 3: these two keys ran `echo INJECTED` in fish).
    func testACommandWithABackslashOrBangIsNotOffered() throws {
        let cli = "klav-cli 0.0.0 (path+file:///tmp/a%5C)"
        let daemon = "klav-daemon 0.0.0 (path+file:///;%20echo%20INJECTED;%20echo%20%5C)"
        XCTAssertNil(OtherCLI.installCommand(package: "klav-cli", key: cli))
        XCTAssertNil(OtherCLI.installCommand(package: "klav-daemon", key: daemon))
        let record = try JSONSerialization.data(withJSONObject: ["installs": [cli: [:], daemon: [:]]])
        XCTAssertNil(OtherCLI.cargoCommand(data: record))
        for key in ["klav-cli 0.0.0 (path+file:///tmp/a%21b/crates/klav-cli)",
                    "klav-cli 0.0.0 (path+file:///tmp/klav%20it's/crates/klav-cli)",
                    "klav-cli 0.0.0 (git+https://example.com/klav.git?branch=a%5Cb#ce4f)"] {
            XCTAssertNil(OtherCLI.installCommand(package: "klav-cli", key: key), key)
        }
        // One install it can quote and one it can't: no half command.
        let half = try JSONSerialization.data(withJSONObject: ["installs": [
            "klav-cli 0.0.0 (path+file:///tmp/klav/crates/klav-cli)": [:], daemon: [:]]])
        XCTAssertNil(OtherCLI.cargoCommand(data: half))
        XCTAssertFalse(OtherCLI.printable("a\\b"))
        XCTAssertFalse(OtherCLI.printable("a!b"))
        XCTAssertTrue(OtherCLI.printable("cargo install --locked --path '/tmp/my klav'"))
    }

    /// cargo's record is read from its open descriptor: only a regular file
    /// of at most 1 MB, also through a link, and never more than the cap +
    /// 1 bytes. Nothing here blocks, and nothing refused is parsed.
    func testCargosRecordIsReadFromItsDescriptorWithACap() throws {
        let start = Date()
        let fifo = root.appendingPathComponent("fifo/.crates2.json").path
        _ = try mkdir("fifo")
        XCTAssertEqual(mkfifo(fifo, 0o644), 0)
        XCTAssertEqual(OtherCLI.readRecord(at: fifo).0, .refused(.notAFile))
        XCTAssertEqual(OtherCLI.readRecord(at: try mkdir("dir/.crates2.json").path).0, .refused(.notAFile))
        let device = root.appendingPathComponent("zero/.crates2.json").path
        _ = try mkdir("zero")
        try FileManager.default.createSymbolicLink(atPath: device, withDestinationPath: "/dev/zero")
        let (zero, zeroBytes) = OtherCLI.readRecord(at: device)
        XCTAssertEqual(zero, .refused(.notAFile))
        XCTAssertEqual(zeroBytes, 0)
        // One byte over the cap, as the file and through a link, whose own
        // size (what the path's attributes say) is tiny: refused before a
        // byte is read.
        let large = try write(String(repeating: " ", count: OtherCLI.recordCap + 1), to: "large/.crates2.json")
        XCTAssertEqual(OtherCLI.readRecord(at: large.path).0, .refused(.tooLarge))
        let linked = root.appendingPathComponent("linked/.crates2.json").path
        _ = try mkdir("linked")
        try FileManager.default.createSymbolicLink(atPath: linked, withDestinationPath: large.path)
        let (viaLink, linkBytes) = OtherCLI.readRecord(at: linked)
        XCTAssertEqual(viaLink, .refused(.tooLarge))
        XCTAssertEqual(linkBytes, 0)
        XCTAssertEqual(OtherCLI.readRecord(at: root.appendingPathComponent("none/.crates2.json").path).0, .missing)
        let fine = try write("{\"installs\":{}}", to: "fine/.crates2.json")
        if case .read(let data, _) = OtherCLI.readRecord(at: fine.path).0 {
            XCTAssertEqual(data, Data("{\"installs\":{}}".utf8))
        } else {
            XCTFail("a small regular record is read")
        }
        // Through a probe: a FIFO beside a klav is cargo without a command.
        let cli = try fakeCLI(at: "fifo-cargo/bin/klav", markers: [])
        XCTAssertEqual(mkfifo(root.appendingPathComponent("fifo-cargo/.crates2.json").path, 0o644), 0)
        let none = BuildMarker.Known(marker: { _ in nil }, record: { _, _ in nil })
        XCTAssertEqual(BuildMarker.probe(cli.path, appCLI: "", contents: true, known: none).probe.origin,
                       .cargo(command: nil))
        XCTAssertLessThan(Date().timeIntervalSince(start), 2, "nothing blocked")
        try assertNothingRan()
    }

    /// Two callers of one slow read (the menu bar's `checkCLIs` and
    /// `refresh` at launch) both get its answer from one job; with a read
    /// that hangs, both get "not read" within the limit, still one job.
    func testTwoCallersOfOneReadBothGetItsAnswer() {
        let build = BuildIdentity(version: "0.0.0", commit: "0123456789ab", time: Date(timeIntervalSince1970: 0))
        let slow = BuildMarker.Reader(limit: .seconds(3)) { _, _, _, _ in
            Thread.sleep(forTimeInterval: 0.5)
            return BuildMarker.JobOutcome(probe: BuildMarker.Probe(present: true, reading: .said(build), origin: .other))
        }
        XCTAssertEqual(both { slow.read("/x/klav") }, [build.commit, build.commit])
        XCTAssertEqual(slow.jobsStarted, 1)

        let gate = DispatchSemaphore(value: 0)
        defer { gate.signal() }
        let hung = BuildMarker.Reader(limit: .milliseconds(300)) { _, _, _, _ in
            _ = gate.wait(timeout: .now() + 5)
            return BuildMarker.JobOutcome(probe: BuildMarker.Probe(present: true, reading: .said(build), origin: .other))
        }
        let start = Date()
        XCTAssertEqual(both { hung.read("/x/klav") }, [nil, nil])
        XCTAssertLessThan(Date().timeIntervalSince(start), 2)
        XCTAssertEqual(hung.jobsStarted, 1)
    }

    /// Runs `read` twice at once, the second a little after the first, and
    /// gives each answer's commit.
    private func both(_ read: @escaping () -> BuildMarker.Reading?) -> [String?] {
        let group = DispatchGroup()
        let lock = NSLock()
        var answers: [Int: String?] = [:]
        for index in 0..<2 {
            group.enter()
            DispatchQueue.global().asyncAfter(deadline: .now() + .milliseconds(index * 50)) {
                let commit = read()?.build?.commit
                lock.lock(); answers[index] = .some(commit); lock.unlock()
                group.leave()
            }
        }
        _ = group.wait(timeout: .now() + 10)
        return [answers[0] ?? nil, answers[1] ?? nil]
    }

    /// A read that failed (a read error, a file that grew while it was
    /// read) isn't kept: the next refresh reads the file again.
    func testAFailedReadIsReadAgain() {
        let file = BuildMarker.FileID(stat())
        let build = BuildIdentity(version: "0.0.0", commit: "0123456789ab", time: Date(timeIntervalSince1970: 0))
        let calls = Counter()
        let reader = BuildMarker.Reader { _, _, _, known in
            calls.add()
            if calls.value == 1 {
                return BuildMarker.JobOutcome(probe: BuildMarker.Probe(present: true, reading: .silent(.unreadable), origin: .other),
                                              marker: (file, .silent(.unreadable), false))
            }
            let reading = known.marker(file) ?? .said(build)
            return BuildMarker.JobOutcome(probe: BuildMarker.Probe(present: true, reading: reading, origin: .other),
                                          marker: (file, reading, true))
        }
        XCTAssertEqual(reader.read("/x/klav"), .silent(.unreadable))
        XCTAssertEqual(reader.read("/x/klav"), .said(build), "the failure wasn't kept")
        XCTAssertEqual(reader.read("/x/klav"), .said(build), "the whole read is")
    }

    /// A PATH folder on a volume that stops answering: its job hangs in its
    /// first `stat`, `refresh` still ends within the limit with that `klav`
    /// listed as not read, and the next `refresh` starts no second job.
    func testAHungFolderHoldsNoRefreshUp() async throws {
        let hungFolder = root.appendingPathComponent("hung-mount/bin")
        let hung = hungFolder.appendingPathComponent("klav").path
        let gate = DispatchSemaphore(value: 0)
        defer { gate.signal() }
        let calls = Counter()
        let reader = BuildMarker.Reader(limit: .milliseconds(300)) { path, appCLI, contents, known in
            if path == hung {
                calls.add()
                _ = gate.wait(timeout: .now() + 5)
                return BuildMarker.JobOutcome(probe: BuildMarker.Probe(present: false, reading: nil, origin: nil))
            }
            return BuildMarker.probe(path, appCLI: appCLI, contents: contents, known: known)
        }
        let paths = InstallPaths(helpers: helpers, linkDirectory: root.appendingPathComponent("bin"),
                                 userHome: root.appendingPathComponent("user"),
                                 klavHome: root.appendingPathComponent("home"),
                                 pathDirectories: [root.appendingPathComponent("cargo-bin"), hungFolder])
        guard FileManager.default.isExecutableFile(atPath: paths.cli.path) else {
            throw XCTSkip("this Klav.app was built without its helpers")
        }
        let other = try fakeCLI(at: "cargo-bin/klav", markers: ["0.0.0 (0123456789ab 2026-11-13T18:17:02Z)"])
        let installer = Installer(paths: paths, system: SampleSystem(reader: reader), placement: .applications,
                                  defaults: defaults)
        for round in 1...2 {
            let start = Date()
            await installer.refresh(info: nil)
            XCTAssertLessThan(Date().timeIntervalSince(start), 2.5, "round \(round): not held up")
            XCTAssertEqual(installer.otherCLIs, [other.path, hung], "round \(round)")
            let row = try XCTUnwrap(installer.checkedCLIs.first { $0.path == hung }, "round \(round)")
            XCTAssertNil(row.reading, "round \(round): not read")
            XCTAssertNil(row.age)
            XCTAssertEqual(installer.checkedCLIs.first { $0.path == other.path }?.build?.commit, "0123456789ab")
            XCTAssertEqual(calls.value, 1, "round \(round): one job for the hung path")
        }
        try assertNothingRan()
    }

    /// The real files: this app's own helpers say their build, and say the
    /// same as their `--version`. With `KLAV_READER_FIXTURES` (a folder,
    /// through `TEST_RUNNER_KLAV_READER_FIXTURES`), also builds kept there:
    /// a `klav` from before the build identity and one from before the
    /// marker say nothing; release `klav` and `klavd` say their build.
    func testRealBuildsSayTheirBuildOnlyWithTheMarker() throws {
        for name in ["klav", "klavd"] {
            let file = helpers.appendingPathComponent(name)
            guard FileManager.default.isExecutableFile(atPath: file.path) else {
                throw XCTSkip("this Klav.app was built without its helpers")
            }
            let result = try runTool(file, ["--version"], environment: [:])
            let said = try XCTUnwrap(BuildIdentity(versionOutput: result.output, program: name))
            switch BuildMarker.read(file.path) {
            case .said(let build): XCTAssertEqual(build, said, name)
            case .silent(.noCommit): XCTAssertFalse(said.known, "\(name): built without Git history")
            case let other: XCTFail("\(name): \(other)")
            }
        }
        guard let dir = ProcessInfo.processInfo.environment["KLAV_READER_FIXTURES"], !dir.isEmpty else { return }
        let expected: [(String, BuildMarker.Reading?)] = [
            ("klav-pre385", .silent(.noMarker)), ("klav-no-marker", .silent(.noMarker)),
            ("klav-release", nil), ("klavd-release", nil),
        ]
        for (name, reading) in expected {
            let file = URL(fileURLWithPath: dir).appendingPathComponent(name).path
            XCTAssertTrue(FileManager.default.fileExists(atPath: file), "\(name) is missing in \(dir)")
            let read = BuildMarker.read(file)
            if let reading { XCTAssertEqual(read, reading, name) } else { XCTAssertNotNil(read.build, name) }
        }
    }

    /// The sample never reads a `klav` of the person's PATH or home.
    func testTheSampleReadsNoKlavOfTheRealPath() throws {
        let system = SampleSystem()
        let home = URL(fileURLWithPath: SampleSafety.realHome)
        let real = ["/usr/local/bin/klav", "/opt/homebrew/bin/klav", home.appendingPathComponent(".cargo/bin/klav").path,
                    "/Applications/Klav.app/Contents/Helpers/klav"]
        let found = system.probeCLIs(real, appCLI: "", contents: true)
        for path in real {
            XCTAssertNil(found[path]?.reading, path)
            XCTAssertNil(found[path]?.origin, "not even cargo's record: \(path)")
        }
        XCTAssertEqual(system.refusedReads.count, 4)
        let fake = try fakeCLI(at: "probe/klav", markers: ["0.0.0 (0123456789ab 2026-11-13T18:17:02Z)"])
        XCTAssertNotNil(system.probeCLIs([fake.path], appCLI: "", contents: true)[fake.path]?.reading?.build)
        XCTAssertEqual(system.refusedReads.count, 4)
        try assertNothingRan()
    }

    func testNothingIsSetUpFromATemporaryPlace() {
        XCTAssertEqual(Placement.of(URL(fileURLWithPath:
            "/private/var/folders/ab/T/AppTranslocation/0F1E/d/Klav.app")), .translocated)
        XCTAssertEqual(Placement.of(URL(fileURLWithPath: "/Applications/Klav.app")), .applications)
        XCTAssertEqual(Placement.of(FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Applications/Klav.app")), .applications)
        XCTAssertEqual(Placement.of(URL(fileURLWithPath: "/Users/ana/Desktop/Klav.app")), .elsewhere)
        XCTAssertFalse(Placement.translocated.canInstall)
        XCTAssertFalse(Placement.diskImage.canInstall)
        XCTAssertTrue(Placement.elsewhere.canInstall)
    }

    func testTheExtensionsNameMatchesTheCLIsBrowser() {
        XCTAssertTrue(BrowserNames.matches("Google Chrome", "chrome"))
        XCTAssertFalse(BrowserNames.matches("Chromium", "chrome"))
        XCTAssertTrue(BrowserNames.matches("Chromium", "chromium"))
        XCTAssertTrue(BrowserNames.matches("Microsoft Edge", "edge"))
        XCTAssertTrue(BrowserNames.matches("Dia", "dia"))
        XCTAssertEqual(BrowserNames.name("dia"), "Dia")
    }

    func testOnlyTheTeamsHelpersAreTrusted() throws {
        // This test build is signed ad hoc: no team, so the Debug path.
        XCTAssertNil(LiveSignatures().claimedTeam(of: Bundle.main.bundleURL))
        XCTAssertEqual(HelperSignature.check(helpers: helpers), .development)
        XCTAssertEqual(HelperSignature.check(helpers: helpers, development: false), .notTeamSigned(nil))
        // Signed by Apple, not by Klav's team, and not dev.klav.klav.
        let ls = URL(fileURLWithPath: "/bin/ls")
        XCTAssertNil(HelperSignature.verify(ls, requirement: "anchor apple"))
        XCTAssertNotNil(HelperSignature.verify(ls, requirement: HelperSignature.requirement()))
        XCTAssertNotNil(HelperSignature.verify(ls, requirement: HelperSignature.requirement(identifier: "dev.klav.klav")))
        XCTAssertNotNil(HelperSignature.verify(root.appendingPathComponent("nothing"), requirement: "anchor apple"))
    }

    /// The Touch ID dialog names the bundle that holds the asking process's
    /// binary: klavd lives in Helpers/klavd.app, named Klav, with the app's
    /// icon (ADR 0027, note of 2026-11-05). The LaunchAgent runs it there,
    /// and Helpers/klavd leads to it for whatever runs klavd by that path.
    func testKlavdLivesInABundleNamedKlav() throws {
        guard FileManager.default.isExecutableFile(atPath: helpers.appendingPathComponent("klav").path) else {
            throw XCTSkip("this Klav.app was built without its helpers")
        }
        let bundleURL = helpers.appendingPathComponent(HelperSignature.daemonBundle)
        let bundle = try XCTUnwrap(Bundle(url: bundleURL))
        XCTAssertEqual(bundle.bundleIdentifier, "dev.klav.klavd")
        XCTAssertEqual(bundle.object(forInfoDictionaryKey: "CFBundleDisplayName") as? String, "Klav")
        XCTAssertEqual(bundle.object(forInfoDictionaryKey: "CFBundleName") as? String, "Klav")
        XCTAssertEqual(bundle.object(forInfoDictionaryKey: "LSUIElement") as? Bool, true)
        XCTAssertEqual(bundle.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String,
                       Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String)
        XCTAssertNotNil(bundle.url(forResource: "AppIcon", withExtension: "icns"), "the app's icon")
        let binary = try XCTUnwrap(bundle.executableURL).resolvingSymlinksInPath()
        XCTAssertTrue(FileManager.default.isExecutableFile(atPath: binary.path))

        XCTAssertNil(HelperSignature.daemonLinkProblem(helpers: helpers))
        XCTAssertEqual(helpers.appendingPathComponent("klavd").resolvingSymlinksInPath(), binary)
        XCTAssertNil(HelperSignature.verify(bundleURL, requirement: "identifier \"dev.klav.klavd\""))

        let plist = Bundle.main.bundleURL.appendingPathComponent("Contents/Library/LaunchAgents/dev.klav.klavd.plist")
        let agent = try XCTUnwrap(NSDictionary(contentsOf: plist))
        let program = try XCTUnwrap(agent["BundleProgram"] as? String)
        XCTAssertEqual(Bundle.main.bundleURL.appendingPathComponent(program).standardizedFileURL.path,
                       bundleURL.appendingPathComponent("Contents/MacOS/klavd").standardizedFileURL.path,
                       "the LaunchAgent runs the binary inside klavd.app, not the link")
    }

    func testHelpersKlavdMustBeTheLinkIntoItsBundle() throws {
        let dir = try mkdir("Helpers")
        let link = dir.appendingPathComponent("klavd")
        XCTAssertNotNil(HelperSignature.daemonLinkProblem(helpers: dir), "nothing there")

        _ = try write("#!/bin/sh\n", to: "Helpers/klavd", executable: true)
        XCTAssertNotNil(HelperSignature.daemonLinkProblem(helpers: dir), "a file, not a link")

        try FileManager.default.removeItem(at: link)
        try FileManager.default.createSymbolicLink(atPath: link.path, withDestinationPath: "/usr/local/bin/klavd")
        XCTAssertEqual(HelperSignature.daemonLinkProblem(helpers: dir), "→ /usr/local/bin/klavd")

        try FileManager.default.removeItem(at: link)
        try FileManager.default.createSymbolicLink(atPath: link.path, withDestinationPath: HelperSignature.daemonLinkTarget)
        XCTAssertNil(HelperSignature.daemonLinkProblem(helpers: dir))
    }

    /// Made-up signatures, by file name: the team each one names, its
    /// identifier, and whether its seal holds. A requirement is met only by
    /// a sealed file of Klav's team with the identifier asked for.
    private struct FakeSignatures: CodeSignatures {
        struct Signed {
            var team: String? = HelperSignature.teamID
            var identifier: String
            var sealed = true
        }
        var files: [String: Signed]

        /// Klav's build, untouched.
        static var team: FakeSignatures {
            FakeSignatures(files: [
                "Klav.app": Signed(identifier: "dev.klav.mac"),
                "klav": Signed(identifier: "dev.klav.klav"),
                "klav-native-host": Signed(identifier: "dev.klav.klav-native-host"),
                "klavd.app": Signed(identifier: "dev.klav.klavd"),
            ])
        }

        func claimedTeam(of url: URL) -> String? { files[url.lastPathComponent]?.team }

        func problem(_ url: URL, requirement: String) -> String? {
            guard let file = files[url.lastPathComponent] else { return "missing" }
            guard file.sealed else { return "a sealed resource is missing or invalid" }
            guard file.team == HelperSignature.teamID else { return "team \(file.team ?? "none")" }
            let met = [HelperSignature.requirement(), HelperSignature.requirement(identifier: file.identifier)]
            return met.contains(requirement) ? nil : "identifier \(file.identifier)"
        }
    }

    /// A `Klav.app` of the test's own, with `Helpers/klavd` linked as the
    /// build leaves it: the fake answers for the files.
    private func fakeApp() throws -> (app: URL, helpers: URL) {
        let helpers = try mkdir("Klav.app/Contents/Helpers")
        try FileManager.default.createSymbolicLink(atPath: helpers.appendingPathComponent("klavd").path,
                                                   withDestinationPath: HelperSignature.daemonLinkTarget)
        return (root.appendingPathComponent("Klav.app"), helpers)
    }

    /// T120: the team the app names only picks the path. Klav's build is
    /// checked even when its own seal is broken, and a build that is not
    /// the team's sets nothing up unless it is a Debug build, which says so.
    func testTheTeamIsCheckedEvenWhenTheAppsSealIsBroken() throws {
        let (app, helpers) = try fakeApp()
        func check(_ signatures: FakeSignatures, development: Bool = false) -> HelperSignature.Verdict {
            HelperSignature.check(helpers: helpers, app: app, signatures: signatures, development: development)
        }

        // The team's build, untouched.
        XCTAssertEqual(check(.team), .trusted)
        XCTAssertNil(HelperSignature.Verdict.trusted.refusal)

        // A helper signed by another team, or as another helper.
        var other = FakeSignatures.team
        other.files["klav-native-host"]?.team = "ABCDE12345"
        XCTAssertEqual(check(other), .untrusted("klav-native-host: team ABCDE12345"))
        var swapped = FakeSignatures.team
        swapped.files["klavd.app"]?.identifier = "dev.klav.klav"
        XCTAssertEqual(check(swapped), .untrusted("klavd: identifier dev.klav.klav"))

        // A tampered helper breaks the app's seal too: still checked, and
        // the helper is named. Before T120's fix this set up anyway.
        var tampered = FakeSignatures.team
        tampered.files["klav"]?.sealed = false
        tampered.files["Klav.app"]?.sealed = false
        XCTAssertEqual(check(tampered), .untrusted("klav: a sealed resource is missing or invalid"))
        XCTAssertEqual(check(tampered, development: true), check(tampered), "Debug changes nothing for the team's build")
        // The app's seal alone (its plist, the klavd link): refused too.
        var resealed = FakeSignatures.team
        resealed.files["Klav.app"]?.sealed = false
        XCTAssertEqual(check(resealed), .untrusted("Klav.app: a sealed resource is missing or invalid"))

        // Helpers/klavd replaced by a file.
        try FileManager.default.removeItem(at: helpers.appendingPathComponent("klavd"))
        _ = try write("#!/bin/sh\n", to: "Klav.app/Contents/Helpers/klavd", executable: true)
        if case .untrusted(let why) = check(.team) {
            XCTAssertTrue(why.hasPrefix("klavd: "), why)
        } else {
            XCTFail("a klavd that is not the link is trusted")
        }

        // Not the team's build: ad hoc, or another team's.
        var adHoc = FakeSignatures.team
        adHoc.files["Klav.app"]?.team = nil
        XCTAssertEqual(check(adHoc), .notTeamSigned(nil))
        XCTAssertEqual(check(adHoc).refusal, "ad hoc")
        var foreign = FakeSignatures.team
        foreign.files["Klav.app"]?.team = "ABCDE12345"
        XCTAssertEqual(check(foreign), .notTeamSigned("ABCDE12345"))
        // A Debug build sets up, and says so.
        XCTAssertEqual(check(adHoc, development: true), .development)
        XCTAssertNil(HelperSignature.Verdict.development.refusal)
    }

    // MARK: Open Klav at login

    func testOpenAtLoginIsOffByDefaultAndShowsWhatMacOSSays() async throws {
        let system = SampleSystem(agent: .enabled)
        let installer = try installer(system: system)
        await installer.refresh(info: nil)
        XCTAssertEqual(installer.openAtLogin, .notRegistered, "off by default")
        XCTAssertTrue(installer.canOpenAtLogin)

        await installer.setOpenAtLogin(true)
        XCTAssertEqual(installer.openAtLogin, .enabled)
        XCTAssertEqual(system.appRegistrations, 1)
        XCTAssertNil(installer.problems[.login])
        XCTAssertEqual(system.agentState(), .enabled, "klavd's LaunchAgent is another login item")

        // The person turns it off in System Settings and comes back.
        system.setAppLoginState(.notRegistered)
        installer.refreshOpenAtLogin()
        XCTAssertEqual(installer.openAtLogin, .notRegistered)

        await installer.setOpenAtLogin(true)
        await installer.setOpenAtLogin(false)
        XCTAssertEqual(installer.openAtLogin, .notRegistered)
        XCTAssertEqual(system.agentState(), .enabled, "turning it off leaves klavd's LaunchAgent")
    }

    func testOpenAtLoginSaysWhenMacOSWantsApprovalOrRefuses() async throws {
        let system = SampleSystem()
        system.appRegistersAs = .requiresApproval
        let installer = try installer(system: system)
        await installer.flipOpenAtLogin(true)
        XCTAssertEqual(installer.openAtLogin, .requiresApproval)
        XCTAssertFalse(installer.openAtLoginIsOn, "waiting for approval: Klav doesn't open at login yet")
        XCTAssertNil(installer.problems[.login], "approval is a state, not a failure")
        XCTAssertEqual(system.appRegistrations, 1)
        // The switch is off; turning it on opens Login Items, it doesn't
        // register again.
        await installer.flipOpenAtLogin(true)
        XCTAssertEqual(system.loginItemsOpened, 1)
        XCTAssertEqual(system.appRegistrations, 1)
        // The person allows it there: the switch is on.
        system.setAppLoginState(.enabled)
        installer.refreshOpenAtLogin()
        XCTAssertTrue(installer.openAtLoginIsOn)
        // Turning it off unregisters it, from either state.
        system.setAppLoginState(.requiresApproval)
        installer.refreshOpenAtLogin()
        await installer.flipOpenAtLogin(false)
        XCTAssertEqual(installer.openAtLogin, .notRegistered)
        XCTAssertEqual(system.loginItemsOpened, 1)

        system.appError = SetupError.failed("Operation not permitted.")
        await installer.setOpenAtLogin(true)
        XCTAssertEqual(installer.openAtLogin, .notRegistered)
        XCTAssertEqual(installer.problems[.login], "macOS didn’t add Klav to Login Items: Operation not permitted.")
        XCTAssertNil(installer.busy)

        // Already registered: macOS throws, but it is on, so no failure.
        system.appError = nil
        system.appRegistersAs = .enabled
        await installer.setOpenAtLogin(true)
        XCTAssertNil(installer.problems[.login])
        system.appError = SetupError.failed("Already registered.")
        await installer.setOpenAtLogin(true)
        XCTAssertEqual(installer.openAtLogin, .enabled)
        XCTAssertNil(installer.problems[.login])

        // Turning it off when macOS refuses: it stays on, and says why.
        system.appError = SetupError.failed("Operation not permitted.")
        await installer.flipOpenAtLogin(false)
        XCTAssertEqual(installer.openAtLogin, .enabled)
        XCTAssertTrue(installer.openAtLoginIsOn, "macOS kept it, so the switch shows it on")
        XCTAssertEqual(installer.problems[.login], "macOS didn’t take Klav off Login Items: Operation not permitted.")
        XCTAssertNil(installer.busy)
        system.appError = nil

        // In Spanish.
        let es = try XCTUnwrap(Bundle(for: MacModel.self).path(forResource: "es", ofType: "lproj").flatMap(Bundle.init(path:)))
        XCTAssertEqual(es.localizedString(forKey: "macOS didn’t add Klav to Login Items: %@", value: nil, table: nil),
                       "macOS no añadió Klav a Ítems de inicio: %@")
        XCTAssertEqual(es.localizedString(forKey: "Open Klav at login", value: nil, table: nil),
                       "Abrir Klav al iniciar sesión")
    }

    func testOpenAtLoginIsOnlyTurnedOnFromApplicationsAndBySignedHelpers() async throws {
        let system = SampleSystem()
        let translocated = try installer(system: system, placement: .translocated)
        XCTAssertFalse(translocated.canOpenAtLogin)
        await translocated.setOpenAtLogin(true)
        XCTAssertEqual(system.appRegistrations, 0, "never a login item for a temporary copy")

        var adHoc = FakeSignatures.team
        adHoc.files["Klav.app"]?.team = nil
        let release = try installer(system: system, signatures: adHoc, development: false)
        await release.refresh(info: nil)
        XCTAssertFalse(release.canOpenAtLogin)
        await release.setOpenAtLogin(true)
        XCTAssertEqual(system.appRegistrations, 0, "not signed by Klav's team (T120)")
        // Off always works, so an earlier build's login item can go.
        system.setAppLoginState(.enabled)
        await release.setOpenAtLogin(false)
        XCTAssertEqual(system.appLoginState(), .notRegistered)
    }

    func testUninstallTakesOffOpenAtLogin() async throws {
        let system = SampleSystem(agent: .enabled)
        let installer = try installer(system: system)
        await installer.setOpenAtLogin(true)
        XCTAssertEqual(installer.openAtLogin, .enabled)
        let done = await installer.uninstall(engine: SampleEngine(locked: false, touchID: true), deleteHome: false)
        XCTAssertTrue(done, "\(installer.problems)")
        XCTAssertEqual(system.appLoginState(), .notRegistered)
        XCTAssertEqual(installer.openAtLogin, .notRegistered)
        XCTAssertEqual(system.agentState(), .notRegistered)
    }

    /// macOS keeps Klav or `klavd` in Login Items: the sheet says so, not
    /// «Klav is off this Mac».
    func testUninstallSaysWhatMacOSKeptInLoginItems() async throws {
        let system = SampleSystem(agent: .enabled)
        let installer = try installer(system: system)
        await installer.setOpenAtLogin(true)
        system.appError = SetupError.failed("Operation not permitted.")
        system.agentError = SetupError.failed("Busy.")
        var done = await installer.uninstall(engine: SampleEngine(locked: false, touchID: true), deleteHome: false)
        XCTAssertFalse(done)
        XCTAssertEqual(installer.problems[.uninstall],
                       "macOS didn’t take the background service off Login Items: Busy.\n"
                       + "macOS didn’t take Klav off Login Items: Operation not permitted.")
        // Once macOS lets them go, uninstalling again finishes.
        system.appError = nil
        system.agentError = nil
        done = await installer.uninstall(engine: SampleEngine(locked: false, touchID: true), deleteHome: false)
        XCTAssertTrue(done, "\(installer.problems)")
        XCTAssertNil(installer.problems[.uninstall])
    }

    /// A release build not signed by the team: every step but uninstalling
    /// does nothing, and the setup says why.
    func testABuildNotSignedByTheTeamSetsNothingUp() async throws {
        var adHoc = FakeSignatures.team
        adHoc.files["Klav.app"]?.team = nil
        let system = SampleSystem()
        let release = try installer(system: system, signatures: adHoc, development: false)
        await release.refresh(info: nil)
        XCTAssertEqual(release.helperTrust, .notTeamSigned(nil))
        XCTAssertEqual(release.helpersUntrusted, "ad hoc")
        XCTAssertFalse(release.unsignedDevelopmentBuild)
        XCTAssertTrue(release.manifests.isEmpty, "not even klav host-status runs")

        await release.setUpDaemon(engine: SampleEngine(locked: false, touchID: true), info: nil)
        XCTAssertEqual(release.agent, .notRegistered)
        _ = try mkdir("bin")
        await release.linkCLI(replace: true)
        XCTAssertTrue(system.administratorCommands.isEmpty)
        XCTAssertNil(try? FileManager.default.destinationOfSymbolicLink(atPath: root.appendingPathComponent("bin/klav").path),
                     "no link to an untrusted klav")

        // The same build in Debug: it sets up, and says its helpers are not checked.
        let debug = try installer(system: SampleSystem(), signatures: adHoc, development: true)
        await debug.refresh(info: nil)
        XCTAssertTrue(debug.unsignedDevelopmentBuild)
        XCTAssertNil(debug.helpersUntrusted)
        await debug.setUpDaemon(engine: SampleEngine(locked: false, touchID: true), info: nil)
        XCTAssertEqual(debug.agent, .enabled)
    }

    func testAnUpdateNotSignedByTheTeamIsNotExtracted() throws {
        let downloads = root.appendingPathComponent("PersistentDownloads")
        XCTAssertNotNil(UpdateGuard.vet(downloads), "nothing downloaded: rejected")
        let token = try mkdir("PersistentDownloads/tok")
        XCTAssertNotNil(UpdateGuard.vet(downloads), "an empty download: rejected")

        // A file Apple signed: it passes "anchor apple", not Klav's team.
        try FileManager.default.copyItem(at: URL(fileURLWithPath: "/bin/ls"), to: token.appendingPathComponent("Klav-9.dmg"))
        XCTAssertNil(UpdateGuard.vet(downloads, requirement: "anchor apple"))
        let why = try XCTUnwrap(UpdateGuard.vet(downloads))
        XCTAssertTrue(why.hasPrefix("Klav-9.dmg: "), why)

        // One bad file among good ones is enough.
        _ = try write("not signed", to: "PersistentDownloads/tok/extra")
        XCTAssertNotNil(UpdateGuard.vet(downloads, requirement: "anchor apple"))
    }
}

/// `SetupPreferences` that live as long as the test.
final class MemoryPreferences: SetupPreferences {
    private var values: [String: Any] = [:]
    func bool(forKey defaultName: String) -> Bool { values[defaultName] as? Bool ?? false }
    func dictionary(forKey defaultName: String) -> [String: Any]? { values[defaultName] as? [String: Any] }
    func set(_ value: Any?, forKey defaultName: String) { values[defaultName] = value }
}

/// A count shared with a closure that runs on another thread.
private final class Counter: @unchecked Sendable {
    private let lock = NSLock()
    private var count = 0
    var value: Int { lock.lock(); defer { lock.unlock() }; return count }
    func add() { lock.lock(); count += 1; lock.unlock() }
}
