import XCTest
@testable import Klav

/// The sample vault never runs `klav` nor sets anything up on the person's
/// real home (review of PR #230: a test run once wrote `clients.json` in
/// the real `KLAV_HOME`). The `klav` and `klavd` here are scripts that only
/// leave a mark in the test's folder, so even a broken guard writes nothing
/// anywhere else; and no test here deletes or replaces anything.
@MainActor
final class SampleSafetyTests: XCTestCase {
    private var root: URL!

    override func setUpWithError() throws {
        let base = ProcessInfo.processInfo.environment["KLAV_TEST_TMPDIR"].map(URL.init(fileURLWithPath:))
            ?? FileManager.default.temporaryDirectory
        root = base.appendingPathComponent("kms-\(UUID().uuidString.prefix(8))")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        root = root.resolvingSymlinksInPath()
    }

    override func tearDownWithError() throws {
        if let root { try? FileManager.default.removeItem(at: root) }
    }

    /// Where the fake programs write when they run.
    private var mark: URL { root.appendingPathComponent("ran") }
    private var ran: Bool { FileManager.default.fileExists(atPath: mark.path) }

    private var realHome: URL { URL(fileURLWithPath: SampleSafety.realHome) }
    private var realKlavHome: URL { realHome.appendingPathComponent("Library/Application Support/klav") }

    /// Helpers whose `klav` and `klavd` only append their arguments to
    /// `mark` and print an empty `klav skill update --json`.
    private func fakeHelpers() throws -> URL {
        let helpers = root.appendingPathComponent("Helpers")
        try FileManager.default.createDirectory(at: helpers, withIntermediateDirectories: true)
        for name in ["klav", "klavd"] {
            let url = helpers.appendingPathComponent(name)
            let script = """
            #!/bin/sh
            echo "$@" >> '\(mark.path)'
            echo '{"version":"0.0.0","dry_run":false,"copies":[]}'

            """
            try script.write(to: url, atomically: true, encoding: .utf8)
            try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: url.path)
        }
        return helpers
    }

    /// Test folders, with what `klav client` follows pointed there too.
    private var testEnvironment: [String: String] {
        ["HOME": root.appendingPathComponent("user").path,
         "KLAV_HOME": root.appendingPathComponent("home").path,
         "CODEX_HOME": root.appendingPathComponent("user/.codex").path,
         "CLAUDE_CONFIG_DIR": root.appendingPathComponent("user/.claude").path]
    }

    func testTheSampleNeverRunsKlavOnTheRealHome() throws {
        let klav = try fakeHelpers().appendingPathComponent("klav")
        let system = SampleSystem()
        let refused: [[String: String]] = [
            testEnvironment.merging(["HOME": realHome.path]) { $1 },
            testEnvironment.merging(["KLAV_HOME": realKlavHome.path]) { $1 },
            testEnvironment.merging(["KLAV_HOME": ""]) { $1 },
            testEnvironment.merging(["HOME": "relative/home"]) { $1 },
            testEnvironment.merging(["CODEX_HOME": realHome.appendingPathComponent(".codex").path]) { $1 },
            testEnvironment.merging(["CLAUDE_CONFIG_DIR": realHome.appendingPathComponent(".claude").path]) { $1 },
        ]
        for environment in refused {
            XCTAssertThrowsError(try system.run(klav, ["skill", "update", "--json"], environment: environment),
                                 "\(environment)")
        }
        XCTAssertFalse(ran, "klav ran on the real home")

        // On test folders it runs: the fake is a real program.
        let result = try system.run(klav, ["skill", "status", "--json"], environment: testEnvironment)
        XCTAssertEqual(result.status, 0)
        XCTAssertTrue(ran)
    }

    /// `updateSkillAtLaunch`, which the menu bar's label starts, runs
    /// nothing on the real home; nor does a setup step.
    func testNothingRunsAtLaunchOnTheRealHome() async throws {
        let helpers = try fakeHelpers()
        let link = root.appendingPathComponent("bin")
        try FileManager.default.createDirectory(at: link, withIntermediateDirectories: true)
        let paths = InstallPaths(helpers: helpers, linkDirectory: link, userHome: realHome, klavHome: realKlavHome,
                                 pathDirectories: [])
        let installer = Installer(paths: paths, system: SampleSystem(), placement: .applications,
                                  defaults: MemoryPreferences(), development: true)
        XCTAssertNotNil(installer.system.refusal(for: paths))

        let model = MacModel.sample(SampleEngine(locked: false, touchID: true))
        await model.updateSkillAtLaunch(installer)
        XCTAssertFalse(ran, "klav skill update ran on the real home")
        XCTAssertFalse(model.skillChecked)

        // A setup step refuses before doing anything (the link would only
        // land in the test's folder).
        await installer.linkCLI(replace: false)
        XCTAssertNotNil(installer.problems[.cli])
        XCTAssertFalse(FileManager.default.fileExists(atPath: link.appendingPathComponent("klav").path))
        XCTAssertNil(installer.helperBuild(), "klavd --version ran on the real home")
        XCTAssertFalse(ran)

        // The same on test folders runs once, from Applications.
        let test = InstallPaths(helpers: helpers, linkDirectory: link, userHome: root.appendingPathComponent("user"),
                                klavHome: root.appendingPathComponent("home"), pathDirectories: [])
        let elsewhere = Installer(paths: test, system: SampleSystem(), placement: .elsewhere,
                                  defaults: MemoryPreferences(), development: true)
        await model.updateSkillAtLaunch(elsewhere)
        XCTAssertFalse(ran, "the skill follows the app only from Applications (docs/macos.md §2)")
        let fine = Installer(paths: test, system: SampleSystem(), placement: .applications,
                             defaults: MemoryPreferences(), development: true)
        if SampleSafety.problem(environment: ProcessInfo.processInfo.environment
            .merging(ClientTools(fine).environment) { $1 }) == nil {
            await model.updateSkillAtLaunch(fine)
            XCTAssertTrue(ran, "on test folders it runs")
        }
    }

    /// The link's folder of the sample is never a real PATH directory.
    func testTheLinkNeverGoesToTheRealPath() {
        let user = root.appendingPathComponent("user"), home = root.appendingPathComponent("home")
        func paths(link: URL) -> InstallPaths {
            InstallPaths(helpers: root, linkDirectory: link, userHome: user, klavHome: home, pathDirectories: [])
        }
        XCTAssertNotNil(SampleSafety.problem(paths: paths(link: URL(fileURLWithPath: "/usr/local/bin"))))
        XCTAssertNotNil(SampleSafety.problem(paths: paths(link: realHome.appendingPathComponent(".local/bin"))))
        XCTAssertNil(SampleSafety.problem(paths: paths(link: root.appendingPathComponent("bin"))))
    }

    /// The app this test runs in: on the sample vault, its installer has
    /// test folders (`scripts/macos/test.sh`), or refuses the real ones (a
    /// run from Xcode).
    func testTheHostAppsInstallerKeepsOffTheRealHome() throws {
        guard Engines.sample else { throw XCTSkip("the host app isn't on the sample vault") }
        let installer = Engines.installer()
        let paths = installer.paths
        let onTestFolders = !SampleSafety.inRealHome(paths.userHome.path) && !SampleSafety.inRealHome(paths.klavHome.path)
        XCTAssertTrue(onTestFolders || installer.system.refusal(for: paths) != nil, "\(paths)")
    }
}
