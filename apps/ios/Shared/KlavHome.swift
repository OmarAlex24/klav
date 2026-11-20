import Foundation

#if os(iOS)
/// Where Klav keeps this device's state (ADR 0018 §2): `<App Group>/klav`,
/// shared by the app and the AutoFill extension, with complete data
/// protection (readable only while the iPhone is unlocked).
enum KlavHome {
    /// The App Group ID from Info.plist (`KlavAppGroup`).
    static var appGroup: String {
        Bundle.main.object(forInfoDictionaryKey: "KlavAppGroup") as? String ?? "group.dev.klav.ios"
    }

    /// Shared preferences (no secrets).
    static var defaults: UserDefaults {
        UserDefaults(suiteName: appGroup) ?? .standard
    }

    /// `<App Group container>/klav`, created with complete protection.
    static func directory() throws -> URL {
        let fm = FileManager.default
        let base: URL
        if let group = fm.containerURL(forSecurityApplicationGroupIdentifier: appGroup) {
            base = group
        } else {
            // Without the App Group (a build signed without it) the app
            // still works; the AutoFill extension will not see the vault.
            base = try fm.url(for: .applicationSupportDirectory, in: .userDomainMask,
                              appropriateFor: nil, create: true)
        }
        let dir = base.appendingPathComponent("klav", isDirectory: true)
        if !fm.fileExists(atPath: dir.path) {
            try fm.createDirectory(at: dir, withIntermediateDirectories: true,
                                   attributes: [.protectionKey: FileProtectionType.complete])
        }
        protect(dir)
        return dir
    }

    /// Re-applies complete protection to the directory and its files (new
    /// files inherit it; this covers files renamed into place).
    static func protect(_ dir: URL? = nil) {
        guard let dir = dir ?? (try? directory()) else { return }
        let fm = FileManager.default
        try? fm.setAttributes([.protectionKey: FileProtectionType.complete], ofItemAtPath: dir.path)
        for name in (try? fm.contentsOfDirectory(atPath: dir.path)) ?? [] {
            try? fm.setAttributes([.protectionKey: FileProtectionType.complete],
                                  ofItemAtPath: dir.appendingPathComponent(name).path)
        }
    }
}
#else
/// Where Klav keeps this Mac's state (ADR 0027 §3): the same home as `klav`
/// and `klavd`, `~/Library/Application Support/klav` (ADR 0011 §5), or
/// `KLAV_HOME` when it is set. The app is not sandboxed, so this is the
/// real path, shared with the CLI and the extension.
enum KlavHome {
    /// Preferences of the Mac app (no secrets).
    static var defaults: UserDefaults { .standard }

    static func directory() throws -> URL {
        if let custom = ProcessInfo.processInfo.environment["KLAV_HOME"], !custom.isEmpty {
            return URL(fileURLWithPath: (custom as NSString).expandingTildeInPath, isDirectory: true)
        }
        let base = try FileManager.default.url(for: .applicationSupportDirectory, in: .userDomainMask,
                                               appropriateFor: nil, create: true)
        return base.appendingPathComponent("klav", isDirectory: true)
    }

    /// `klav-client` creates the home 0700 and its files 0600 itself.
    static func protect(_ dir: URL? = nil) {}
}
#endif
