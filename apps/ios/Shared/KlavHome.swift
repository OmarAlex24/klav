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
/// and `klavd`, `~/Library/Application Support/klav` (ADR 0011 §5). The app
/// is not sandboxed, so this is the real path, shared with the CLI and the
/// extension.
///
/// The signed (Release) app takes the person's home from the account record
/// and ignores every environment variable (ADR 0041 §1.2, N1): `KLAV_HOME`,
/// `HOME` and `CFFIXED_USER_HOME` would otherwise let a program that starts
/// the app point it at a `klavd.sock` of its own and read the held
/// connection. Debug builds (the tests, the sample app) keep honoring
/// `KLAV_HOME`.
enum KlavHome {
    /// Preferences of the Mac app (no secrets).
    static var defaults: UserDefaults { .standard }

    static func directory() throws -> URL {
        #if DEBUG
        if let custom = ProcessInfo.processInfo.environment["KLAV_HOME"], !custom.isEmpty {
            return URL(fileURLWithPath: (custom as NSString).expandingTildeInPath, isDirectory: true)
        }
        #endif
        return try defaultDirectory()
    }

    /// `<account home>/Library/Application Support/klav`, whatever the
    /// environment says.
    static func defaultDirectory() throws -> URL {
        try accountHome()
            .appendingPathComponent("Library/Application Support", isDirectory: true)
            .appendingPathComponent("klav", isDirectory: true)
    }

    /// The home directory in the user's account record
    /// (`getpwuid_r(getuid())->pw_dir`), not `HOME`: `FileManager`'s
    /// `homeDirectoryForCurrentUser` and `.applicationSupportDirectory`
    /// can follow `HOME` and `CFFIXED_USER_HOME`.
    static func accountHome(uid: uid_t = getuid()) throws -> URL {
        var size = sysconf(Int32(_SC_GETPW_R_SIZE_MAX))
        if size <= 0 { size = 4096 }
        while true {
            var buffer = [CChar](repeating: 0, count: size)
            // `pw_dir` points into `buffer`: read it before the buffer goes.
            let (status, path) = buffer.withUnsafeMutableBufferPointer { bytes -> (Int32, String?) in
                var record = passwd()
                var found: UnsafeMutablePointer<passwd>?
                let status = getpwuid_r(uid, &record, bytes.baseAddress, bytes.count, &found)
                guard status == 0, found != nil, let dir = record.pw_dir else { return (status, nil) }
                return (status, String(cString: dir))
            }
            if status == ERANGE, size < 1 << 20 {
                size *= 2
                continue
            }
            guard let path, path.hasPrefix("/"), path.count > 1 else {
                throw HomeError.noAccountRecord(uid: uid, status: status)
            }
            return URL(fileURLWithPath: path, isDirectory: true)
        }
    }

    enum HomeError: LocalizedError {
        case noAccountRecord(uid: uid_t, status: Int32)

        var errorDescription: String? {
            switch self {
            case let .noAccountRecord(uid, status):
                return "no home directory in the account record of user \(uid) (\(status))"
            }
        }
    }

    /// `klav-client` creates the home 0700 and its files 0600 itself.
    static func protect(_ dir: URL? = nil) {}
}
#endif
