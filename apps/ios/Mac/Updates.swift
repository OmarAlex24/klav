import AppKit
import Combine
import Sparkle

/// Updates with Sparkle 2 (ADR 0027 §7, docs/macos.md §6). The appcast and
/// every update are signed with Klav's EdDSA key, and Sparkle checks the
/// update before extracting it (`SUVerifyUpdateBeforeExtraction`).
/// `UpdateGuard` adds the Team ID: what Sparkle downloaded must be signed
/// by SZ3F58F8LX before it is extracted (T123).
///
/// Without `SUPublicEDKey` (a build that empties it), the app does not
/// look for updates.
@MainActor
final class Updates: ObservableObject {
    @Published private(set) var canCheck = false
    private let guardian = UpdateGuard()
    private let presenter = UpdatePresenter()
    private var controller: SPUStandardUpdaterController?

    var enabled: Bool { controller != nil }

    init() {
        guard Self.publicKey != nil else {
            macLog.info("no Sparkle key in this build: updates are off")
            return
        }
        let controller = SPUStandardUpdaterController(startingUpdater: true, updaterDelegate: guardian,
                                                      userDriverDelegate: presenter)
        self.controller = controller
        controller.updater.publisher(for: \.canCheckForUpdates).assign(to: &$canCheck)
        #if DEBUG
        // For the update test (docs/macos.md §6): look now, in the background.
        if UserDefaults.standard.bool(forKey: "KlavCheckUpdatesNow") {
            controller.updater.checkForUpdatesInBackground()
        }
        #endif
    }

    static var publicKey: String? {
        guard let key = Bundle.main.object(forInfoDictionaryKey: "SUPublicEDKey") as? String,
              !key.trimmingCharacters(in: .whitespaces).isEmpty else { return nil }
        return key
    }

    func check() {
        controller?.checkForUpdates(nil)
    }
}

/// Klav lives in the menu bar: Sparkle's window for a scheduled update
/// would open behind other apps. The Dock icon shows while it is up, as
/// with the main window, so it is seen (Sparkle's gentle reminders).
final class UpdatePresenter: NSObject, SPUStandardUserDriverDelegate {
    var supportsGentleScheduledUpdateReminders: Bool { true }

    func standardUserDriverWillHandleShowingUpdate(_ handleShowingUpdate: Bool, forUpdate update: SUAppcastItem,
                                                   state: SPUUserUpdateState) {
        guard handleShowingUpdate, !state.userInitiated else { return }
        NSApp.setActivationPolicy(.regular)
        NSApp.activate()
    }

    func standardUserDriverWillFinishUpdateSession() {
        // Back to the menu bar only, unless the main window is open.
        let windowOpen = NSApp.windows.contains { $0.isVisible && $0.identifier?.rawValue.contains("main") == true }
        if !windowOpen { NSApp.setActivationPolicy(.accessory) }
    }
}

/// T123: Sparkle accepts an update whose EdDSA signature is valid even if
/// another team signed the app inside, and it exposes no hook with the
/// extracted app before its installer takes over. The only moment the app
/// can stop it is `didDownloadUpdate`, which Sparkle calls synchronously
/// right before extracting: here every file it downloaded must be signed
/// by Klav's team (the DMG is, by `scripts/macos/build-app.sh`, and its
/// signature seals the whole image). If one is not, the download goes and
/// Sparkle has nothing to extract.
final class UpdateGuard: NSObject, SPUUpdaterDelegate {
    let downloads: URL
    private var rejectedVersion: String?

    init(downloads: URL = UpdateGuard.sparkleDownloads) {
        self.downloads = downloads
    }

    /// Where Sparkle 2.10 keeps downloads for this app (its
    /// `SPULocalCacheDirectory` and `SPUDownloader`; its installer refuses
    /// any other place). Sparkle is pinned exactly: a new version means
    /// checking this again.
    static var sparkleDownloads: URL {
        let caches = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask)[0]
        return caches
            .appendingPathComponent(Bundle.main.bundleIdentifier ?? "dev.klav.mac")
            .appendingPathComponent("org.sparkle-project.Sparkle/PersistentDownloads")
    }

    /// nil when there is a download and every file in it satisfies
    /// `requirement`; otherwise, why not. Fails closed: nothing found is a
    /// rejection too.
    static func vet(_ downloads: URL, requirement: String = HelperSignature.requirement()) -> String? {
        let fm = FileManager.default
        guard let walker = fm.enumerator(at: downloads, includingPropertiesForKeys: [.isRegularFileKey],
                                         options: [.skipsHiddenFiles]) else {
            return "no download"
        }
        var found = 0
        for case let url as URL in walker {
            guard (try? url.resourceValues(forKeys: [.isRegularFileKey]).isRegularFile) == true else { continue }
            found += 1
            if let problem = HelperSignature.verify(url, requirement: requirement) {
                return "\(url.lastPathComponent): \(problem)"
            }
        }
        return found == 0 ? "no download" : nil
    }

    func updater(_ updater: SPUUpdater, didDownloadUpdate item: SUAppcastItem) {
        guard let why = Self.vet(downloads) else {
            macLog.info("update \(item.displayVersionString, privacy: .public): signed by Klav's team")
            return
        }
        rejectedVersion = item.displayVersionString
        try? FileManager.default.removeItem(at: downloads)
        macLog.error("update \(item.displayVersionString, privacy: .public) rejected: \(why, privacy: .public)")
    }

    /// Sparkle stops once it finds nothing to extract. The notice waits for
    /// that: shown earlier, Sparkle's teardown closes it.
    func updater(_ updater: SPUUpdater, didAbortWithError error: Error) {
        guard let version = rejectedVersion else { return }
        rejectedVersion = nil
        macLog.info("Sparkle stopped after the rejected update")
        DispatchQueue.main.async {
            let alert = NSAlert()
            alert.alertStyle = .critical
            alert.messageText = String(localized: "Klav \(version) wasn’t installed")
            alert.informativeText = String(localized: "The update isn’t signed by Klav, so Klav deleted it and kept this version. If it happens again, download Klav from klav.dev.")
            // A menu bar app is not active: without this the alert opens
            // behind other apps.
            NSApp.activate()
            alert.runModal()
        }
    }

    #if DEBUG
    /// The update test serves its own appcast (`KLAV_SPARKLE_FEED_URL`).
    func feedURLString(for updater: SPUUpdater) -> String? {
        ProcessInfo.processInfo.environment["KLAV_SPARKLE_FEED_URL"].flatMap { $0.isEmpty ? nil : $0 }
    }
    #endif
}
