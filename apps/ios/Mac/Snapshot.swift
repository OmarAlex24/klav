#if DEBUG
import AppKit

/// Launch arguments for screenshots (debug builds only), with the sample
/// vault (`-KlavSample YES`):
///
///   -KlavAppearance light|dark    the app's appearance
///   -KlavOpen main,menu           windows to open at launch
///   -KlavSection requests|agents|sandboxes|activity|clients|health|vault
///   -KlavItem <id>                the item open in the vault
///   -KlavSheet uninstall|signIn|signUp   a sheet open in the window
///   -KlavSheet connect-<client>   the summary of «Connect» in Clients
///   -KlavAdvanced YES             «Advanced options» open in «Set up this Mac»
///   -KlavSetupAgents YES          the window stays on «Set up this Mac» for
///                                 its «Agents» step
///   -KlavSamplePaused YES         every agent paused (the sample engine)
///   -KlavSampleDeletion pending|deleted|unsupported   the account's
///                                 deletion (ADR 0037)
///   -KlavOpen settings            Settings, on `-KlavSettingsTab account`
///   -KlavSettingsBottom YES       Settings › This Mac scrolled to the end
///                                 («Open Klav at login», «Uninstall…»)
///   -KlavSheet deleteAccount      the deletion's sheet, in Settings › Account
///   -KlavSheet newItem            the editor on a new login
///   -KlavSheet editItem           the editor on `-KlavItem`
///   -KlavSheet trash              «Move to the trash» for `-KlavItem`
///   -KlavGenerator YES            the generator open over the editor
///   -KlavSheet fixReused          «Fix my reused passwords» for release-agent,
///                                 in Vault health
///   -KlavSampleFix YES            that task running (the sample engine)
///   -KlavAgent <id>               that agent's page in Development › Agents
///   -KlavSheet revoke             «Revoke…» on `-KlavAgent`
///   -KlavSheet changeGrant        «Change permissions…» on `-KlavAgent`
///   -KlavSheet reviewGrant        its review sheet, with a sample change
///   -KlavSign YES                 with reviewGrant, presses «Sign» (the password
///                                 prompt shows over the sheet without Touch ID)
///   -KlavSampleKeysLeft YES       old-scraper revoked with keys left
///   -KlavSampleSandboxes none|empty|quiet|rollback|flagged|paused   the
///                                 sandboxes' list (without it, every state and
///                                 a theft signal); integrity: every read fails
///                                 its security checks; unregistered: every
///                                 state and a revocation the log didn't show
///   -KlavSheet revokeAllSandboxes «Revoke all» in Development › Sandboxes
enum Snapshot {
    static func configure() {
        switch UserDefaults.standard.string(forKey: "KlavAppearance") {
        case "dark": NSApp.appearance = NSAppearance(named: .darkAqua)
        case "light": NSApp.appearance = NSAppearance(named: .aqua)
        default: break
        }
    }

    /// Opens what `-KlavOpen` names, once.
    @MainActor
    static func openWindows(_ open: (String) -> Void, settings: () -> Void = {}) {
        guard !opened else { return }
        opened = true
        let names = (UserDefaults.standard.string(forKey: "KlavOpen") ?? "").split(separator: ",")
        if names.contains("main") { open(WindowID.main) }
        if names.contains("menu") { open(WindowID.menuPreview) }
        if names.contains("settings") { settings() }
    }

    /// `-KlavSheet reviewGrant`: the editor goes straight to its review
    /// sheet with a sample change (one project more, `inject` on «deny»).
    static var reviewGrant: Bool { UserDefaults.standard.string(forKey: "KlavSheet") == "reviewGrant" }

    /// The Settings tab `-KlavSettingsTab` names (`mac` or `account`).
    static var settingsTab: String? { UserDefaults.standard.string(forKey: "KlavSettingsTab") }

    /// `-KlavSettingsBottom YES`: Settings › This Mac opens at its end.
    static var settingsBottom: Bool { UserDefaults.standard.bool(forKey: "KlavSettingsBottom") }

    @MainActor
    static func apply(to model: MacModel) {
        let defaults = UserDefaults.standard
        switch defaults.string(forKey: "KlavSection") {
        case "requests": model.section = .requests
        case "agents": model.section = .agents
        case "sandboxes": model.section = .sandboxes
        case "activity": model.section = .activity
        case "clients": model.section = .clients
        case "health": model.section = .health
        default: break
        }
        if let item = defaults.string(forKey: "KlavItem") { model.selectedItem = item }
        let agent = defaults.string(forKey: "KlavAgent")
        if let agent { model.openAgent = agent }
        switch defaults.string(forKey: "KlavSheet") {
        case "revoke": if let agent { model.revoking = RevokeRequest(agentId: agent) }
        case "changeGrant", "reviewGrant": if let agent { model.changingGrant = GrantChangeRequest(agentId: agent) }
        case "uninstall": model.uninstalling = true
        case "revokeAllSandboxes": model.revokingAllSandboxes = true
        case "newItem": model.editor = .create(.login)
        case "editItem": if let item = defaults.string(forKey: "KlavItem") { model.editor = .edit(item) }
        default: break
        }
        if defaults.bool(forKey: "KlavSetupAgents") { model.agentsStepPending = true }
        if defaults.string(forKey: "KlavSampleSandboxes") == "unregistered" {
            let now = Int64(Date().timeIntervalSince1970 * 1000)
            model.revocationChecks = [SandboxSamples.unregistered(now: now)]
        }
    }

    /// The client whose «Connect» summary `-KlavSheet connect-<client>` opens.
    static var connectSheet: String? {
        guard let sheet = UserDefaults.standard.string(forKey: "KlavSheet"), sheet.hasPrefix("connect-") else { return nil }
        return String(sheet.dropFirst("connect-".count))
    }

    /// The account sheet `-KlavSheet` names, in «Set up this Mac».
    static var accountSheet: AccountSheet.Mode? {
        UserDefaults.standard.string(forKey: "KlavSheet").flatMap(AccountSheet.Mode.init(rawValue:))
    }

    /// `-KlavSheet trash`: the item view asks once it has the item.
    @MainActor static func takeTrashSheet() -> Bool {
        guard !trashTaken, UserDefaults.standard.string(forKey: "KlavSheet") == "trash" else { return false }
        trashTaken = true
        return true
    }

    /// `-KlavGenerator YES`: the editor opens the generator once.
    @MainActor static func takeGenerator() -> Bool {
        guard !generatorTaken, UserDefaults.standard.bool(forKey: "KlavGenerator") else { return false }
        generatorTaken = true
        return true
    }

    /// `-KlavSheet fixReused`: the health pane opens the offer once.
    @MainActor static func takeFixOffer() -> Bool {
        guard !fixTaken, UserDefaults.standard.string(forKey: "KlavSheet") == "fixReused" else { return false }
        fixTaken = true
        return true
    }

    @MainActor private static var opened = false
    @MainActor private static var fixTaken = false
    @MainActor private static var trashTaken = false
    @MainActor private static var generatorTaken = false
}
#endif
