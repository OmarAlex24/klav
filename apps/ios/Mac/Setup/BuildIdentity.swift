import Foundation

/// Which build a `klav` or `klavd` is: its version number, and the commit it
/// was built from with that commit's time (`crates/klav-daemon/build.rs`).
/// Every build of one version says the same number (and those from before
/// 0.9.0 all say `0.0.0`), so the commit and its time are what tell two
/// builds apart (ADR 0027 §4.1, `docs/macos.md` §3).
struct BuildIdentity: Equatable {
    /// `0.9.0`.
    let version: String
    /// 7 to 40 lowercase hex digits; nil when the build doesn't say.
    let commit: String?
    /// The commit's committer time; nil with `commit`.
    let time: Date?
    /// It printed `(commit unknown)`: built from a source without Git
    /// history. A build older than build identities prints only the number.
    var unknownCommit = false

    /// Says which commit it was built from.
    var known: Bool { commit != nil && time != nil }

    /// `klavd`'s `status`.
    init(status info: DaemonInfo) {
        version = info.version ?? ""
        if let commit = info.commit, Self.validCommit(commit), let seconds = info.commitTime {
            self.commit = commit
            time = Date(timeIntervalSince1970: TimeInterval(seconds))
        } else {
            commit = nil
            time = nil
        }
    }

    init(version: String, commit: String?, time: Date?, unknownCommit: Bool = false) {
        self.version = version
        self.commit = commit
        self.time = time
        self.unknownCommit = unknownCommit
    }

    /// What `<program> --version` printed, or nil when it isn't a Klav
    /// program's answer. It also reads the marker line of another `klav`'s
    /// file (`BuildMarker`), which comes from a file the app didn't ship,
    /// so it is read strictly: at most 512 bytes, one line of printable
    /// ASCII, and exactly
    ///
    ///     klav 0.0.0
    ///     klav 0.0.0 (commit unknown)
    ///     klav 0.0.0 (ce4fa5099092 2026-11-13T18:17:02Z)
    ///
    /// Nothing else of it is ever shown: the app shows what it parsed.
    init?(versionOutput data: Data, program: String) {
        guard data.count <= 512,
              data.allSatisfy({ $0 == 0x0A || $0 == 0x0D || (0x20...0x7E).contains($0) }) else { return nil }
        let text = String(decoding: data, as: UTF8.self)
        let lines = text.split(whereSeparator: \.isNewline)
        guard lines.count == 1, let line = lines.first else { return nil }
        let words = line.split(separator: " ", omittingEmptySubsequences: false).map(String.init)
        guard words.count >= 2, words[0] == program, Self.validVersion(words[1]) else { return nil }
        let rest = words.dropFirst(2).joined(separator: " ")
        version = words[1]
        switch rest {
        case "":
            commit = nil
            time = nil
        case "(commit unknown)":
            commit = nil
            time = nil
            unknownCommit = true
        default:
            let inner = rest.dropFirst().dropLast().split(separator: " ").map(String.init)
            guard rest.hasPrefix("("), rest.hasSuffix(")"), inner.count == 2, Self.validCommit(inner[0]),
                  let date = Self.parseTime(inner[1]) else { return nil }
            commit = inner[0]
            time = date
        }
    }

    static func validCommit(_ text: String) -> Bool {
        (7...40).contains(text.count) && text.allSatisfy { ("0"..."9").contains($0) || ("a"..."f").contains($0) }
    }

    private static func validVersion(_ text: String) -> Bool {
        (1...32).contains(text.count)
            && text.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber || ".+-".contains($0)) }
    }

    /// Exactly `2026-11-13T18:17:02Z`.
    private static func parseTime(_ text: String) -> Date? {
        guard text.count == 20, text.hasSuffix("Z") else { return nil }
        return try? Date(text, strategy: .iso8601)
    }

    /// The two commits are the same one: one hash may be shorter
    /// (`--version` prints 12 digits, `status` all 40).
    static func sameCommit(_ a: String, _ b: String) -> Bool {
        a.count <= b.count ? b.hasPrefix(a) : a.hasPrefix(b)
    }

    /// The same build: the same commit when both say one, or neither says
    /// one and the numbers match. Restarting `klavd` follows this.
    func sameBuild(as other: BuildIdentity) -> Bool {
        switch (commit, other.commit) {
        case let (a?, b?): return Self.sameCommit(a, b)
        case (nil, nil): return version == other.version
        default: return false
        }
    }

    enum Age: Equatable {
        case same
        /// Built from an earlier commit.
        case older
        case newer
        /// Can't tell: either build doesn't say its commit, or two
        /// different commits share the same second.
        case unknown
    }

    /// How `self` compares with `ours` (this app's), by commit time:
    ///
    /// - the same commit: `same`, whatever the version number says;
    /// - either doesn't say its commit and time: `unknown`, never `older`;
    /// - an earlier commit time: `older`; a later one: `newer`;
    /// - the same time and another commit: `unknown`.
    ///
    /// The version number never orders two builds: commit times do.
    func age(comparedWith ours: BuildIdentity) -> Age {
        guard let mine = time, let theirs = ours.time, let a = commit, let b = ours.commit,
              known, ours.known else { return .unknown }
        if Self.sameCommit(a, b) { return .same }
        if mine < theirs { return .older }
        if mine > theirs { return .newer }
        return .unknown
    }

    /// `0.0.0 (ce4fa5099092, 13 Nov 2026)`, for the setup's lines: only
    /// what was parsed.
    var described: String {
        guard let commit, let time else { return version }
        let short = String(commit.prefix(12))
        return "\(version) (\(short), \(time.formatted(date: .abbreviated, time: .omitted)))"
    }
}
