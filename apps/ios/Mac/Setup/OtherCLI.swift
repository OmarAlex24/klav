import Darwin
import Foundation

/// Another `klav` on the PATH (`Installer.otherCLIs`): which build its file
/// says it is (`BuildMarker`), how that compares with this app's, and, for
/// an older one, the command that would update it. The app never runs it,
/// never replaces it and never runs that command.
struct OtherCLI: Equatable, Identifiable {
    /// How it got there, which decides the command shown for an older one.
    enum Origin: Equatable {
        /// `cargo install`: the command from cargo's own record, when it has
        /// one the app can quote.
        case cargo(command: String?)
        /// A Homebrew formula (its file is inside a `Cellar`).
        case homebrew(formula: String)
        /// Anything else: no command.
        case other
    }

    let path: String
    /// What its file says, or nil when the app didn't read it: helpers not
    /// signed by Klav's team, the sample's safety, or a read that didn't end
    /// within its limit (`BuildMarker.Reader`).
    let reading: BuildMarker.Reading?
    /// Compared with this app's `klav`: `unknown` when either doesn't say
    /// its build; nil when it wasn't read.
    let age: BuildIdentity.Age?
    let origin: Origin
    var id: String { path }

    /// The build its file names, when it names one.
    var build: BuildIdentity? { reading?.build }

    /// The command that updates it: only for one whose file says it is
    /// older than this app's, only from cargo's record or Homebrew, and only
    /// when every character is printable ASCII (`printable`).
    var command: String? {
        guard age == .older else { return nil }
        let command: String?
        switch origin {
        case .cargo(let fromRecord): command = fromRecord
        case .homebrew(let formula): command = "brew upgrade \(formula)"
        case .other: command = nil
        }
        return command.flatMap { Self.printable($0) ? $0 : nil }
    }

    /// Every scalar in 0x20–0x7E, except `\` and `!`. The command is built
    /// from a file the app didn't write (`.crates2.json`, T193), and
    /// `URL.path` and `queryItems` decode `%0A` or `%E2%80%AE` into a newline
    /// or a right-to-left override: quoting keeps them from running, but
    /// they would still reach the screen and the clipboard. The quoting is
    /// POSIX (`shellQuote`), and fish ends a single-quoted string at `\'`, so
    /// a backslash, which `shellQuote` itself writes for an apostrophe, could
    /// turn the rest of the line into commands there; `!` is history
    /// expansion in some shells. Such a record gets no command.
    static func printable(_ text: String) -> Bool {
        text.unicodeScalars.allSatisfy { (0x20...0x7E).contains($0.value) && $0 != "\\" && $0 != "!" }
    }

    /// Where it came from, once its links are followed: Homebrew when a
    /// folder on the way is a `Cellar` (`…/Cellar/<formula>/<version>/bin/klav`,
    /// also `…/libexec/bin/klav`), `cargo` when its folder has cargo's
    /// record beside it (`<root>/bin/klav` and `<root>/.crates2.json`,
    /// whatever `CARGO_HOME` or `--root` was), anything else otherwise.
    ///
    /// `cargo` gets the path of a record that may be there and gives the
    /// origin it makes (nil when there is none): `BuildMarker.probe` reads it
    /// with `readRecord`, inside its bounded job, and keeps what it read.
    static func origin(of path: String, cargo: (String) -> Origin?) -> Origin {
        let resolved = URL(fileURLWithPath: path).resolvingSymlinksInPath()
        let parts = resolved.pathComponents
        if let cellar = parts.lastIndex(of: "Cellar"), parts.count > cellar + 2, validFormula(parts[cellar + 1]) {
            return .homebrew(formula: parts[cellar + 1])
        }
        for file in [URL(fileURLWithPath: path), resolved] {
            let record = file.deletingLastPathComponent().deletingLastPathComponent()
                .appendingPathComponent(".crates2.json")
            if let origin = cargo(record.path) { return origin }
        }
        return .other
    }

    /// cargo's record, as `readRecord` found it.
    enum Record: Equatable {
        /// Nothing there: not a cargo install.
        case missing
        /// Something there the app doesn't read.
        case refused(Refusal)
        case read(Data, BuildMarker.FileID)
    }

    enum Refusal: Equatable {
        /// A FIFO, a directory, a device (also through a link).
        case notAFile
        /// Larger than `recordCap`, or grew past it while it was read.
        case tooLarge
        /// It can't be opened or read.
        case unreadable
    }

    /// The most bytes of cargo's record the app reads (T193).
    static let recordCap = 1_000_000

    /// Reads cargo's record the way `BuildMarker.read` reads a `klav`:
    /// opened without blocking, checked with `fstat` on the open descriptor
    /// (a regular file of at most `recordCap`; a link is followed, so a link
    /// to `/dev/zero` is a device), and at most `recordCap` + 1 bytes read
    /// from that descriptor. A file swapped after the check is never read:
    /// the descriptor is the file that was checked. Also gives how many
    /// bytes were read.
    static func readRecord(at path: String) -> (Record, Int) {
        let fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOCTTY)
        guard fd >= 0 else { return (errno == ENOENT || errno == ENOTDIR ? .missing : .refused(.unreadable), 0) }
        defer { close(fd) }
        var info = stat()
        guard fstat(fd, &info) == 0 else { return (.refused(.unreadable), 0) }
        guard info.st_mode & S_IFMT == S_IFREG else { return (.refused(.notAFile), 0) }
        guard info.st_size <= recordCap else { return (.refused(.tooLarge), 0) }
        var data = Data()
        var piece = [UInt8](repeating: 0, count: 64 * 1024)
        while data.count <= recordCap {
            let want = min(piece.count, recordCap + 1 - data.count)
            let count = piece.withUnsafeMutableBytes { Darwin.read(fd, $0.baseAddress, want) }
            if count < 0 {
                if errno == EINTR { continue }
                return (.refused(.unreadable), data.count)
            }
            if count == 0 { break }
            data.append(contentsOf: piece[0..<count])
        }
        guard data.count <= recordCap else { return (.refused(.tooLarge), data.count) }
        return (.read(data, BuildMarker.FileID(info)), data.count)
    }

    private static func validFormula(_ name: String) -> Bool {
        (1...64).contains(name.count)
            && name.allSatisfy { $0.isASCII && ($0.isLowercase || $0.isNumber || "@._+-".contains($0)) }
    }

    /// The command that installs `klav` (and `klavd`, if cargo installed it
    /// too) again the way it was, from cargo's record (`.crates2.json`, read
    /// by `readRecord`): `--path` for a local source, `--git` for a
    /// repository. Nil without a record the app can parse, or when either
    /// install is one it won't quote (`installCommand`): half a command
    /// would leave the other half old.
    static func cargoCommand(data: Data) -> String? {
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let installs = json["installs"] as? [String: Any] else { return nil }
        var commands: [String] = []
        for package in ["klav-cli", "klav-daemon"] {
            guard let key = installs.keys.first(where: { $0.hasPrefix(package + " ") }) else { continue }
            guard let command = installCommand(package: package, key: key) else { return nil }
            commands.append(command)
        }
        return commands.isEmpty ? nil : commands.joined(separator: " && ")
    }

    /// `klav-cli 0.0.0 (path+file:///Users/ana/klav/crates/klav-cli)` →
    /// `cargo install --locked --path '/Users/ana/klav/crates/klav-cli'`;
    /// `klav-cli 0.0.0 (git+https://example.com/klav.git?branch=main#ce4f…)` →
    /// `cargo install --locked --git 'https://example.com/klav.git' --branch 'main' klav-cli`.
    /// A `user:password@` in an `https` source is left out: it would put a
    /// token on the screen and in the clipboard. An `ssh` source keeps its
    /// user (`git@`), which it needs. Nil when the decoded command isn't all
    /// printable ASCII (`printable`).
    static func installCommand(package: String, key: String) -> String? {
        guard key.count <= 1024, !key.contains(where: { $0.isNewline || ($0.asciiValue.map { $0 < 0x20 || $0 == 0x7F } ?? false) }),
              let open = key.firstIndex(of: "("), key.hasSuffix(")") else { return nil }
        let source = String(key[key.index(after: open)..<key.index(before: key.endIndex)])
        if source.hasPrefix("path+"), let url = URL(string: String(source.dropFirst(5))), url.isFileURL {
            let command = "cargo install --locked --path \(shellQuote(url.path))"
            return printable(command) ? command : nil
        }
        if source.hasPrefix("git+") {
            let rest = String(source.dropFirst(4)).split(separator: "#", maxSplits: 1).first.map(String.init) ?? ""
            guard var parts = URLComponents(string: rest), parts.scheme == "https" || parts.scheme == "ssh" else {
                return nil
            }
            if parts.scheme == "https" {
                parts.user = nil
                parts.password = nil
            }
            let pick = parts.queryItems?.first { ["branch", "tag", "rev"].contains($0.name) && $0.value != nil }
            parts.query = nil
            guard let repo = parts.string else { return nil }
            let selector = pick.map { " --\($0.name) \(shellQuote($0.value ?? ""))" } ?? ""
            let command = "cargo install --locked --git \(shellQuote(repo))\(selector) \(package)"
            return printable(command) ? command : nil
        }
        return nil
    }
}
