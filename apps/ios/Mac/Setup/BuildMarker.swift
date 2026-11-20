import Darwin
import Foundation

/// Which build another `klav` is, read from its file without running it
/// (`docs/macos.md` §3, T193). Since the build identity, every `klav` and
/// `klavd` carries one line of plain text, written by
/// `crates/klav-daemon/build.rs`:
///
///     klav-build-identity: 0.9.0 (ce4fa5099092 2026-11-13T18:17:02Z)\n
///
/// after the prefix, exactly what `--version` prints after the program's
/// name. The app reads the file as this user, never as an administrator,
/// and runs nothing: the file may be any program, and running it would run
/// whatever it is.
enum BuildMarker {
    /// What starts the line (`MARKER_PREFIX` in `build.rs`).
    static let prefix = Array("klav-build-identity: ".utf8)
    /// The most bytes after the prefix before its `\n`: today's line takes
    /// under 60, and `BuildIdentity` reads at most 512 bytes.
    static let maxLine = 256
    /// The most bytes read of a file: 128 MiB, well above today's `klav`
    /// on arm64 (16 MB as the app builds it, 26 MB with cargo's default
    /// release settings, 76 MB in debug). A
    /// larger file doesn't say its build: none of it is read, because a
    /// marker in the part not read could disagree with the rest.
    static let cap = 128 * 1024 * 1024
    /// Read in pieces this size. With at most one marker line kept (a second
    /// one that differs ends the read), memory stays near one piece whatever
    /// the file.
    static let chunk = 1024 * 1024

    /// Why a file doesn't say its build.
    enum Silence: Equatable {
        /// It doesn't exist, or can't be opened (a link loop, no permission).
        case unreadable
        /// A directory, a FIFO, a device: only regular files are read.
        case notAFile
        /// Larger than `cap`.
        case tooLarge
        /// No marker: built before the marker (`klav` before 0.9.0's build
        /// identity), or not Klav at all.
        case noMarker
        /// Two markers that differ (a universal binary's slices disagree, or
        /// one line was cut short). The read stops at the second one.
        case disagree
        /// One marker, but not a line `BuildIdentity` reads strictly.
        case malformed
        /// A well-formed marker that names no commit (`(commit unknown)`):
        /// nothing to compare.
        case noCommit
    }

    enum Reading: Equatable {
        /// The build it names, with its commit and time.
        case said(BuildIdentity)
        case silent(Silence)

        var build: BuildIdentity? {
            if case .said(let build) = self { return build }
            return nil
        }
    }

    /// A file as `fstat` names it. The same values mean the same contents:
    /// writing a file changes its modification and status-change times, and
    /// the status-change time can't be set by hand.
    struct FileID: Hashable {
        let device: Int32
        let inode: UInt64
        let size: Int64
        let modified: [Int]
        let changed: [Int]

        init(_ info: stat) {
            device = info.st_dev
            inode = info.st_ino
            size = info.st_size
            modified = [info.st_mtimespec.tv_sec, info.st_mtimespec.tv_nsec]
            changed = [info.st_ctimespec.tv_sec, info.st_ctimespec.tv_nsec]
        }
    }

    /// What one read gave: the result, which file it was (nil when it didn't
    /// open as a regular file), how many bytes were read, and whether the
    /// read ended on its own terms. A read error, or a file that grew past
    /// the cap while it was read, isn't complete: `Reader` doesn't keep it,
    /// so the next refresh reads the file again.
    struct Outcome {
        let reading: Reading
        let file: FileID?
        let bytesRead: Int
        var complete = true
    }

    /// Reads the file at `path`, following links. Blocking: call it off the
    /// main thread.
    static func read(_ path: String) -> Reading {
        read(path, cached: { _ in nil }).reading
    }

    /// `read(_:)`, but a file `cached` already knows isn't read again.
    static func read(_ path: String, cached: (FileID) -> Reading?) -> Outcome {
        // O_NONBLOCK: a FIFO named `klav` must not wait for a writer. A
        // directory opens too; `fstat` below turns both away. For a regular
        // file it does nothing: a hung volume blocks here (`Reader`).
        let fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOCTTY)
        guard fd >= 0 else { return Outcome(reading: .silent(.unreadable), file: nil, bytesRead: 0) }
        defer { close(fd) }
        var info = stat()
        guard fstat(fd, &info) == 0 else { return Outcome(reading: .silent(.unreadable), file: nil, bytesRead: 0) }
        guard info.st_mode & S_IFMT == S_IFREG else {
            return Outcome(reading: .silent(.notAFile), file: nil, bytesRead: 0)
        }
        let file = FileID(info)
        if let known = cached(file) { return Outcome(reading: known, file: file, bytesRead: 0) }
        guard info.st_size <= cap else { return Outcome(reading: .silent(.tooLarge), file: file, bytesRead: 0) }
        let (reading, bytes, complete) = scan(fd: fd)
        return Outcome(reading: reading, file: file, bytesRead: bytes, complete: complete)
    }

    /// Scans an open regular file for its marker. It keeps one marker line:
    /// a second that differs, or one with no `\n` within `maxLine`, ends the
    /// scan at once as `disagree`, whatever the rest of the file holds.
    private static func scan(fd: Int32) -> (Reading, Int, Bool) {
        var line: [UInt8]?
        var total = 0
        // Bytes read but not scanned yet: the tail of the previous piece is
        // kept, so a marker split between two pieces is still found whole.
        var pending: [UInt8] = []
        var piece = [UInt8](repeating: 0, count: chunk)
        let keep = prefix.count + maxLine
        while true {
            let count = piece.withUnsafeMutableBytes { Darwin.read(fd, $0.baseAddress, chunk) }
            if count < 0 {
                if errno == EINTR { continue }
                return (.silent(.unreadable), total, false)
            }
            total += count
            // The file grew past the cap while it was read.
            if total > cap { return (.silent(.tooLarge), total, false) }
            pending.append(contentsOf: piece[0..<count])
            let end = count == 0
            // Markers that start before `limit` have their whole line in
            // `pending`; the rest waits for the next piece.
            let limit = end ? pending.count : max(0, pending.count - keep)
            var from = 0
            while let at = find(prefix, in: pending, from: from), at < limit {
                let start = at + prefix.count
                let stop = min(pending.count, start + maxLine)
                guard let newline = pending[start..<stop].firstIndex(of: 0x0A) else {
                    return (.silent(.disagree), total, true)
                }
                let found = Array(pending[start..<newline])
                if let line, line != found { return (.silent(.disagree), total, true) }
                line = found
                from = at + 1
            }
            pending.removeFirst(limit)
            if end { break }
        }
        guard let line else { return (.silent(.noMarker), total, true) }
        // The line is what `--version` prints after the program's name.
        guard let build = BuildIdentity(versionOutput: Data("klav ".utf8) + Data(line), program: "klav") else {
            return (.silent(.malformed), total, true)
        }
        return (build.known ? .said(build) : .silent(.noCommit), total, true)
    }

    /// What one job learned of a `klav` in a PATH folder.
    struct Probe: Equatable {
        /// An executable `klav` there that isn't this app's own.
        let present: Bool
        /// What its file says; nil when its contents weren't read (helpers
        /// not signed by Klav's team, or the sample's safety).
        let reading: Reading?
        /// How it got there (`OtherCLI.origin`); nil when not read.
        let origin: OtherCLI.Origin?
    }

    /// What a job may look up instead of reading again.
    struct Known {
        /// A marker reading kept for this file identity.
        let marker: (FileID) -> Reading?
        /// The command kept for cargo's record at this path with this
        /// identity: `.some(nil)` when the record gave none.
        let record: (String, FileID) -> String??
    }

    /// One job's result, and what of it may be kept.
    struct JobOutcome {
        let probe: Probe
        /// The marker read, kept only when `complete`.
        var marker: (file: FileID, reading: Reading, complete: Bool)?
        /// cargo's record, kept only when read whole.
        var record: (path: String, file: FileID, command: String?)?
        var bytesRead = 0
    }

    /// One `klav` in a PATH folder: whether it is there and isn't this
    /// app's, and with `contents` what its file says and where it came from
    /// (cargo's record read with `OtherCLI.readRecord`). Blocking, every
    /// call of it: `Reader` runs it with a limit.
    static func probe(_ path: String, appCLI: String, contents: Bool, known: Known) -> JobOutcome {
        guard FileManager.default.isExecutableFile(atPath: path), !Installer.same(path, appCLI) else {
            return JobOutcome(probe: Probe(present: false, reading: nil, origin: nil))
        }
        guard contents else { return JobOutcome(probe: Probe(present: true, reading: nil, origin: nil)) }
        let read = read(path, cached: known.marker)
        var outcome = JobOutcome(probe: Probe(present: true, reading: read.reading, origin: nil),
                                 marker: read.file.map { ($0, read.reading, read.complete) },
                                 bytesRead: read.bytesRead)
        let origin = OtherCLI.origin(of: path) { record in
            let (found, bytes) = OtherCLI.readRecord(at: record)
            outcome.bytesRead += bytes
            switch found {
            case .missing: return nil
            case .refused: return .cargo(command: nil)
            case .read(let data, let file):
                if let kept = known.record(record, file) { return .cargo(command: kept) }
                let command = OtherCLI.cargoCommand(data: data)
                outcome.record = (record, file, command)
                return .cargo(command: command)
            }
        }
        return JobOutcome(probe: Probe(present: true, reading: read.reading, origin: origin),
                          marker: outcome.marker, record: outcome.record, bytesRead: outcome.bytesRead)
    }

    /// Reads the other `klav` programs for `refresh` and `checkCLIs`
    /// (`LiveSystem`, `SampleSystem`): one job per path does everything that
    /// touches that path's file system (`probe`).
    ///
    /// - Every job runs off the caller's thread, and the caller waits at
    ///   most `limit` for all of them together: a `klav` on a hard mount
    ///   that stops answering blocks a `stat` or an `open`, which no flag
    ///   prevents. A path whose job hasn't ended is missing from the answer,
    ///   "not read", and `refresh` goes on.
    /// - One job per path at a time: a caller that finds one running waits
    ///   for it until that job's own deadline, not a new one, and gets its
    ///   answer; after the deadline it gets "not read" at once. No second
    ///   job piles up behind a hung one, and two callers at launch both get
    ///   the real answer.
    /// - What a job read whole is kept, by file identity (`FileID`): an
    ///   unchanged `klav` isn't read again, and an unchanged `.crates2.json`
    ///   is read (1 MB at most) but not parsed again. A read that failed or
    ///   didn't finish isn't kept.
    final class Reader {
        typealias Work = (_ path: String, _ appCLI: String, _ contents: Bool, _ known: Known) -> JobOutcome

        let limit: DispatchTimeInterval
        private let lock = NSLock()
        private var markers: [String: (file: FileID, reading: Reading)] = [:]
        private var records: [String: (file: FileID, command: String?)] = [:]
        private final class Flight {
            let deadline: DispatchTime
            let group = DispatchGroup()
            var probe: Probe?
            init(deadline: DispatchTime) { self.deadline = deadline }
        }
        private var flights: [String: Flight] = [:]
        private var total = 0
        private var started = 0
        private let work: Work

        init(limit: DispatchTimeInterval = .seconds(3), work: @escaping Work = BuildMarker.probe) {
            self.limit = limit
            self.work = work
        }

        /// Bytes read from files so far (tests).
        var bytesRead: Int { lock.lock(); defer { lock.unlock() }; return total }
        /// Jobs started so far (tests).
        var jobsStarted: Int { lock.lock(); defer { lock.unlock() }; return started }

        /// Each path's answer, missing for a path whose job didn't end in
        /// time. `contents` false only checks that a `klav` is there.
        func probe(_ jobs: [(path: String, contents: Bool)], appCLI: String) -> [String: Probe] {
            var waiting: [(String, Flight)] = []
            lock.lock()
            for (path, contents) in jobs where !waiting.contains(where: { $0.0 == path }) {
                if let running = flights[path] {
                    waiting.append((path, running))
                    continue
                }
                let flight = Flight(deadline: .now() + limit)
                flight.group.enter()
                flights[path] = flight
                started += 1
                waiting.append((path, flight))
                DispatchQueue.global(qos: .utility).async { [self] in
                    let known = Known(marker: { [self] file in
                        lock.lock(); defer { lock.unlock() }
                        return markers[path].flatMap { $0.file == file ? $0.reading : nil }
                    }, record: { [self] record, file in
                        lock.lock(); defer { lock.unlock() }
                        return records[record].flatMap { $0.file == file ? .some($0.command) : nil }
                    })
                    let outcome = work(path, appCLI, contents, known)
                    lock.lock()
                    if let marker = outcome.marker, marker.complete {
                        markers[path] = (marker.file, marker.reading)
                    } else if outcome.marker != nil {
                        markers[path] = nil
                    }
                    if let record = outcome.record { records[record.path] = (record.file, record.command) }
                    total += outcome.bytesRead
                    flight.probe = outcome.probe
                    if flights[path] === flight { flights[path] = nil }
                    lock.unlock()
                    flight.group.leave()
                }
            }
            lock.unlock()
            var found: [String: Probe] = [:]
            for (path, flight) in waiting where flight.group.wait(timeout: flight.deadline) == .success {
                lock.lock()
                found[path] = flight.probe
                lock.unlock()
            }
            return found
        }

        /// What the file at `path` says, or nil when it isn't an executable
        /// `klav` or wasn't read in time (tests).
        func read(_ path: String) -> Reading? {
            probe([(path, true)], appCLI: "")[path]?.reading
        }
    }

    /// The first `needle` in `haystack` at or after `from`.
    private static func find(_ needle: [UInt8], in haystack: [UInt8], from: Int) -> Int? {
        guard from < haystack.count else { return nil }
        return haystack.withUnsafeBytes { hay in
            needle.withUnsafeBytes { pin in
                guard let base = hay.baseAddress,
                      let hit = memmem(base + from, hay.count - from, pin.baseAddress, pin.count) else { return nil }
                return base.distance(to: UnsafeRawPointer(hit))
            }
        }
    }
}
