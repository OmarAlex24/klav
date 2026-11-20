//! Layer 1 of ADR 0041: what the peer's identity is in the sequences the
//! ADR names (finding B1, descriptor passing, orphans, sessions, a peer
//! that exits or whose pid is reused between two reads).
//!
//! The test process is the daemon side: it listens on a socket in its own
//! temporary directory and reads the identity of each connection. The
//! peers are this test binary run again as a helper (`helper`, below),
//! `/bin/sh` and `script` (a session with a terminal). `unsafe` isn't
//! allowed here, so there is no `fork`, and a descriptor reaches another
//! process by inheritance, never with `SCM_RIGHTS`: `nix` sends it only
//! with its `uio` feature, which isn't approved, and the standard library's
//! ancillary-data API is unstable. The kernel state is the same either way:
//! two processes hold one connection.
//!
//! The re-checks the stop rule rests on (the last pidfd read on Linux, the
//! last unique-ID read on macOS) are guarded by tests that make only that
//! read differ, through the seams `procfs::ProcReads` and `macos::Kernel`.

use std::cell::Cell;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::process::{Child, ChildStdout, Command, Stdio};
use std::time::{Duration, Instant};

use super::procfs::{ProcReads, Stat, parse_fdinfo_pid, parse_stat, parse_status_uids, read_peer};
use super::*;

/// The helper's mode; unset in a normal test run.
const HELPER: &str = "KLAV_PEER_HELPER";
/// The socket the helper connects to.
const SOCK: &str = "KLAV_PEER_SOCK";
/// When set, the helper starts a new session first (`setsid`).
const SETSID: &str = "KLAV_PEER_SETSID";
/// When set, to the pid of the helper's parent (a shell's `$$`), the
/// helper waits until that is no longer its parent first.
const ORPHAN: &str = "KLAV_PEER_ORPHAN";
/// This test binary, for shell commands that start a helper.
const EXE: &str = "KLAV_PEER_EXE";
/// When set, the receiver waits until its parent has left its session
/// before it writes.
const AFTER_PARENT_LEAVES: &str = "KLAV_PEER_AFTER_PARENT_LEAVES";
/// The helper's test name, which runs it.
const NAME: &str = "peer::tests::helper";
/// How a shell command starts a helper (with the variables above).
const SH_HELPER: &str =
    r#""$KLAV_PEER_EXE" --exact peer::tests::helper --nocapture --test-threads=1 -q"#;
const WAIT: Duration = Duration::from_secs(30);

// ---------------------------------------------------------------- helper

/// Not a test: the peer processes the other tests start, which are this
/// binary run again with `KLAV_PEER_HELPER` set. Without it, it returns.
#[test]
fn helper() {
    let Ok(mode) = std::env::var(HELPER) else {
        return;
    };
    if std::env::var_os(SETSID).is_some() {
        nix::unistd::setsid().expect("setsid");
    }
    if let Ok(first) = std::env::var(ORPHAN) {
        let first: u32 = first.parse().expect("parent pid");
        let deadline = Instant::now() + WAIT;
        while std::os::unix::process::parent_id() == first {
            assert!(Instant::now() < deadline, "never reparented");
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    match mode.as_str() {
        "connect" => {
            let mut socket = connect();
            say(&mut socket, &format!("pid {}\nend\n", std::process::id()));
            hold(socket);
        }
        // The server's start-up test: connects, says so on its standard
        // output, and holds the connection.
        "connect-mark" => {
            let socket = connect();
            mark("connected");
            hold(socket);
        }
        // The server's start-up test of a full backlog: connects until the
        // socket refuses, says how many went through, and keeps them.
        "fill" => {
            let path = std::env::var_os(SOCK).expect("socket");
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime");
            // Non-blocking connects: a blocking one waits for room on Linux.
            let held = runtime.block_on(async {
                let mut held = Vec::new();
                while held.len() < 4096 {
                    match tokio::net::UnixStream::connect(&path).await {
                        Ok(stream) => held.push(stream),
                        Err(_) => break,
                    }
                }
                held
            });
            mark(&format!("filled {}", held.len()));
            std::thread::sleep(WAIT);
            drop(held);
        }
        "b1-exec" | "b1-exit" | "b1-close" => b1(&mode),
        "pass" => pass(),
        "pass-and-leave" => pass_and_leave(),
        "receive" => {
            if std::env::var_os(AFTER_PARENT_LEAVES).is_some() {
                wait_until_parent_leaves();
            }
            // The socket is this process's standard input.
            let fd = std::io::stdin().as_fd().try_clone_to_owned().expect("dup");
            let mut socket = UnixStream::from(fd);
            say(&mut socket, &format!("pid {}\nend\n", std::process::id()));
            mark("sent");
            hold(socket);
        }
        #[cfg(target_os = "linux")]
        "dumpable" => {
            crate::forbid_same_user_debuggers().expect("forbid");
            let dumpable = nix::sys::prctl::get_dumpable().expect("get_dumpable");
            mark(&format!("dumpable {dumpable}"));
            // `klavd`'s side, non-dumpable: the kernel now owns this
            // process's `/proc/self` files as root, and `identify` reads
            // `/proc/self/fdinfo/<pidfd>`.
            let daemon = Daemon::new();
            mark(&format!("listening {}", daemon.path.display()));
            let (socket, _) = daemon.accept();
            let identity = identify(&socket);
            let pid = match &identity {
                Identity::Known(peer) => peer.process.pid.to_string(),
                _ => "none".to_owned(),
            };
            mark(&format!("identity {pid} {identity:?}"));
        }
        other => panic!("unknown helper mode {other}"),
    }
    std::process::exit(0);
}

fn connect() -> UnixStream {
    UnixStream::connect(std::env::var_os(SOCK).expect("socket")).expect("connect")
}

fn say(socket: &mut UnixStream, text: &str) {
    socket.write_all(text.as_bytes()).expect("write");
}

/// A line for the test on the helper's standard output.
fn mark(line: &str) {
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "KLAV-PEER {line}");
    let _ = out.flush();
}

/// Keeps the connection open until the daemon side closes it.
fn hold(mut socket: UnixStream) {
    let _ = socket.set_read_timeout(Some(Duration::from_secs(60)));
    let mut buf = [0u8; 64];
    while matches!(socket.read(&mut buf), Ok(n) if n > 0) {}
}

/// Finding B1: the helper connects and writes; a child that inherits the
/// socket writes the end of the request (so it is the socket's last user)
/// and then execs holding it, exits, or closes it and execs.
fn b1(mode: &str) {
    let mut socket = connect();
    say(&mut socket, &format!("pid {}\n", std::process::id()));
    let script = match mode {
        "b1-exec" => "read x; printf 'end\\n'; exec sleep 30",
        "b1-exit" => "read x; printf 'end\\n'",
        _ => "read x; printf 'end\\n'; exec 1>&-; echo closed >&2; exec sleep 30",
    };
    let fd = OwnedFd::from(socket.try_clone().expect("dup"));
    let mut child = Command::new("/bin/sh")
        .args(["-c", script])
        .stdin(Stdio::piped())
        .stdout(Stdio::from(fd))
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn sh");
    say(&mut socket, &format!("child {}\n", child.id()));
    drop(child.stdin.take());
    match mode {
        "b1-exit" => {
            let _ = child.wait();
        }
        "b1-close" => {
            let mut line = String::new();
            let stderr = child.stderr.take().expect("stderr");
            BufReader::new(stderr).read_line(&mut line).expect("read");
            assert_eq!(line.trim(), "closed");
        }
        _ => {}
    }
    mark("settled");
    // Not `hold`: on macOS a process blocked reading the socket is its
    // last user again. Standard input stays open until the test ends.
    let _ = std::io::stdin().read(&mut [0u8; 1]);
    drop(socket);
    let _ = child.kill();
    let _ = child.wait();
}

/// Descriptor passing: the helper connects, hands the socket to a process
/// in a new session, which writes the request, and exits. The receiver
/// outlives it on purpose (it ends when the daemon side closes), so it is
/// never waited for here.
#[allow(clippy::zombie_processes)]
fn pass() {
    let mut socket = connect();
    say(&mut socket, &format!("pid {}\n", std::process::id()));
    let fd = OwnedFd::from(socket.try_clone().expect("dup"));
    let mut receiver = helper_command("receive", None)
        .env(SETSID, "1")
        .stdin(Stdio::from(fd))
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn receiver");
    let mut out = BufReader::new(receiver.stdout.take().expect("stdout"));
    wait_mark(&mut out, "sent");
    mark(&format!("passed {}", receiver.id()));
}

/// Descriptor passing into a terminal session: this helper, the
/// connector, runs in one; it connects, starts a receiver that inherits the
/// socket and stays in that session, and then leaves the session itself
/// (`setsid`). The receiver writes last. The connector stays alive, holding
/// the socket without using it, until the receiver ends.
fn pass_and_leave() {
    let mut socket = connect();
    say(&mut socket, &format!("connector {}\n", std::process::id()));
    let fd = OwnedFd::from(socket.try_clone().expect("dup"));
    let mut receiver = helper_command("receive", None)
        .env(AFTER_PARENT_LEAVES, "1")
        .stdin(Stdio::from(fd))
        .spawn()
        .expect("spawn receiver");
    nix::unistd::setsid().expect("setsid");
    let _ = receiver.wait();
    drop(socket);
}

/// Waits until this process's parent is in another session than its own.
fn wait_until_parent_leaves() {
    use nix::unistd::{Pid, getsid};
    let parent = Pid::from_raw(pid(std::os::unix::process::parent_id()));
    let mine = getsid(None).expect("getsid");
    let deadline = Instant::now() + WAIT;
    while getsid(Some(parent)).expect("parent's session") == mine {
        assert!(Instant::now() < deadline, "the parent never left");
        std::thread::sleep(Duration::from_millis(5));
    }
}

// ----------------------------------------------------------- daemon side

/// The daemon side: a listening socket in a temporary directory, removed
/// when the test ends, also when it fails.
struct Daemon {
    listener: UnixListener,
    path: PathBuf,
    _dir: tempfile::TempDir,
}

impl Daemon {
    fn new() -> Daemon {
        // A short path: `sun_path` holds ~104 bytes.
        let dir = tempfile::Builder::new().prefix("kp").tempdir().unwrap();
        let path = dir.path().join("s");
        let listener = UnixListener::bind(&path).unwrap();
        listener.set_nonblocking(true).unwrap();
        Daemon {
            listener,
            path,
            _dir: dir,
        }
    }

    /// The next connection, and the pids its peer wrote before `end`.
    fn accept(&self) -> (UnixStream, Request) {
        let deadline = Instant::now() + WAIT;
        let stream = loop {
            match self.listener.accept() {
                Ok((stream, _)) => break stream,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "no connection");
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(e) => panic!("accept: {e}"),
            }
        };
        stream.set_nonblocking(false).unwrap();
        stream.set_read_timeout(Some(WAIT)).unwrap();
        let mut text = String::new();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        while !text.ends_with("end\n") {
            let n = reader.read_line(&mut text).unwrap();
            assert!(n > 0, "peer closed before end: {text:?}");
        }
        let request = Request::parse(&text);
        (stream, request)
    }
}

/// What a helper wrote on its connection.
#[derive(Debug, Default)]
struct Request {
    pid: Option<i32>,
    child: Option<i32>,
    connector: Option<i32>,
    setsid: bool,
}

impl Request {
    fn parse(text: &str) -> Request {
        let mut request = Request::default();
        for line in text.lines() {
            let mut words = line.split_whitespace();
            match words.next() {
                Some("pid") => request.pid = words.next().and_then(|w| w.parse().ok()),
                Some("child") => request.child = words.next().and_then(|w| w.parse().ok()),
                Some("connector") => {
                    request.connector = words.next().and_then(|w| w.parse().ok());
                }
                _ => {}
            }
            if line.contains("setsid") {
                request.setsid = true;
            }
        }
        request
    }
}

fn helper_command(mode: &str, daemon: Option<&Daemon>) -> Command {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", NAME, "--nocapture", "--test-threads=1", "-q"])
        .env(HELPER, mode)
        .env_remove(SETSID)
        .env_remove(ORPHAN)
        .env_remove(AFTER_PARENT_LEAVES)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if let Some(daemon) = daemon {
        command.env(SOCK, &daemon.path);
    } else if let Some(sock) = std::env::var_os(SOCK) {
        command.env(SOCK, sock);
    }
    command
}

/// Children the test started; killed and reaped when it ends.
#[derive(Default)]
struct Reap(Vec<Child>);

impl Reap {
    fn spawn(&mut self, mut command: Command) -> (u32, Option<BufReader<ChildStdout>>) {
        let mut child = command.spawn().expect("spawn");
        let out = child.stdout.take().map(BufReader::new);
        let pid = child.id();
        self.0.push(child);
        (pid, out)
    }

    fn wait(&mut self, pid: u32) {
        if let Some(child) = self.0.iter_mut().find(|c| c.id() == pid) {
            child.wait().unwrap();
        }
    }

    /// Closes the child's input, which ends it, and reaps it.
    fn wait_after_closing_input(&mut self, pid: u32) {
        if let Some(child) = self.0.iter_mut().find(|c| c.id() == pid) {
            drop(child.stdin.take());
            child.wait().unwrap();
        }
    }

    fn kill(&mut self, pid: u32) {
        if let Some(child) = self.0.iter_mut().find(|c| c.id() == pid) {
            let _ = child.kill();
            child.wait().unwrap();
        }
    }
}

impl Drop for Reap {
    fn drop(&mut self) {
        // Closing a helper's input lets it end its own children first.
        for child in &mut self.0 {
            drop(child.stdin.take());
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        for child in &mut self.0 {
            while matches!(child.try_wait(), Ok(None)) && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(5));
            }
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Reads the helper's output until its line `KLAV-PEER <prefix>…`, and
/// returns the rest of that line.
fn wait_mark(out: &mut impl BufRead, prefix: &str) -> String {
    let mut line = String::new();
    loop {
        line.clear();
        let n = out.read_line(&mut line).expect("read helper output");
        assert!(n > 0, "the helper ended before {prefix}");
        if let Some(rest) = line.trim().strip_prefix("KLAV-PEER ")
            && let Some(rest) = rest.strip_prefix(prefix)
        {
            return rest.trim().to_owned();
        }
    }
}

fn pid(n: u32) -> i32 {
    i32::try_from(n).unwrap()
}

/// On macOS without the Swift shim (`KLAV_NO_SWIFT`) every peer is unknown.
fn no_shim() -> bool {
    cfg!(target_os = "macos") && !klav_touchid::compiled_in()
}

fn known(identity: &Identity) -> &Peer {
    match identity {
        Identity::Known(peer) => peer,
        other => panic!("expected a known peer, got {other:?}"),
    }
}

/// The process a shell command runs in a new session whose controlling
/// terminal is a new pty (`script`).
fn in_new_terminal(command: &str) -> Command {
    let mut script = Command::new("script");
    if cfg!(target_os = "macos") {
        script.args(["-q", "/dev/null", "/bin/sh", "-c", command]);
    } else {
        script.args(["-q", "-e", "-c", command, "/dev/null"]);
    }
    // Kept open until the test ends: some `script`s stop at end of input.
    script
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    script
}

// ----------------------------------------------------------------- tests

#[test]
fn a_connector_in_its_own_session_is_known_and_keyed_by_its_parent_on_macos() {
    let daemon = Daemon::new();
    let mut reap = Reap::default();
    let mut command = helper_command("connect", Some(&daemon));
    command.env(SETSID, "1");
    let (helper, _) = reap.spawn(command);
    let (socket, request) = daemon.accept();
    assert_eq!(request.pid, Some(pid(helper)));
    let identity = identify(&socket);
    if no_shim() {
        assert_eq!(identity, Identity::Unknown);
        return;
    }
    let peer = known(&identity);
    assert_eq!(peer.process.pid, pid(helper));
    assert_eq!(peer.terminal, None);
    assert_eq!(peer.session.map(|s| s.id), Some(pid(helper)), "{peer:?}");
    let parent = peer.parent.expect("the test process is its parent");
    assert_eq!(parent.pid, pid(std::process::id()));
    if cfg!(target_os = "macos") {
        assert_eq!(identity.window_key(), WindowKey::Parent(parent));
    } else {
        assert_eq!(identity.window_key(), WindowKey::Connection);
    }
    // The same answer when asked again: the key is stable.
    assert_eq!(identify(&socket), identity);
}

#[test]
fn children_in_one_terminal_share_its_session_and_a_new_session_does_not() {
    let daemon = Daemon::new();
    let mut reap = Reap::default();
    let command = format!("{SH_HELPER} & {SH_HELPER} & {SETSID}=1 {SH_HELPER} & wait",);
    let mut script = in_new_terminal(&command);
    script
        .env(HELPER, "connect")
        .env(SOCK, &daemon.path)
        .env(EXE, std::env::current_exe().unwrap())
        .env_remove(SETSID)
        .env_remove(ORPHAN);
    reap.spawn(script);
    let mut keys = Vec::new();
    let mut sockets = Vec::new();
    for _ in 0..3 {
        let (socket, request) = daemon.accept();
        let identity = identify(&socket);
        keys.push((request.pid, identity));
        sockets.push(socket);
    }
    if no_shim() {
        assert!(keys.iter().all(|(_, id)| *id == Identity::Unknown));
        return;
    }
    // Which one called `setsid`: the one with no terminal.
    let (in_terminal, alone): (Vec<_>, Vec<_>) = keys
        .iter()
        .partition(|(_, identity)| known(identity).terminal.is_some());
    assert_eq!(in_terminal.len(), 2, "{keys:?}");
    assert_eq!(alone.len(), 1, "{keys:?}");
    let first = in_terminal[0].1.window_key();
    let WindowKey::Session(session) = first else {
        panic!("a peer in a terminal is keyed by its session: {keys:?}");
    };
    assert_eq!(in_terminal[1].1.window_key(), first);
    assert_eq!(
        known(&in_terminal[0].1).terminal,
        known(&in_terminal[1].1).terminal
    );
    // Not the test's own session.
    assert_ne!(session.id, nix::unistd::getsid(None).unwrap().as_raw());
    let other = alone[0].1.window_key();
    assert_ne!(other, first);
    assert!(!matches!(other, WindowKey::Session(_)), "{other:?}");
    drop(sockets);
}

/// The B1 sequence with a child that execs holding the socket: on macOS
/// the peer is that child (the socket's last user, which holds it); on
/// Linux the process that connected. Either way a process of the attacker,
/// keyed as the attacker's own, never anyone else's.
#[test]
fn b1_a_child_that_execs_holding_the_socket_is_the_attackers_own() {
    let daemon = Daemon::new();
    let mut reap = Reap::default();
    let mut command = helper_command("b1-exec", Some(&daemon));
    command
        .env(SETSID, "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped());
    let (helper, out) = reap.spawn(command);
    let (socket, request) = daemon.accept();
    wait_mark(&mut out.unwrap(), "settled");
    let child = request.child.expect("child pid");
    let identity = identify(&socket);
    if no_shim() {
        assert_eq!(identity, Identity::Unknown);
        return;
    }
    let peer = known(&identity);
    if cfg!(target_os = "macos") {
        assert_eq!(
            klav_touchid::peer_token(socket.as_fd()).map(|t| t.0),
            Some(child)
        );
        assert_eq!(peer.process.pid, child);
        let parent = peer.parent.expect("the helper is its parent");
        assert_eq!(parent.pid, pid(helper));
        assert_eq!(identity.window_key(), WindowKey::Parent(parent));
    } else {
        assert_eq!(peer.process.pid, pid(helper));
        assert_eq!(identity.window_key(), WindowKey::Connection);
    }
}

/// B1 with a child that wrote last and exited: on macOS the token names a
/// process that is gone, so the peer is unknown.
#[test]
fn b1_a_child_that_wrote_last_and_exited_leaves_an_unknown_peer_on_macos() {
    b1_without_the_child("b1-exit");
}

/// B1 with a child that wrote last and then closed the socket: on macOS it
/// no longer holds the connection, so the peer is unknown.
#[test]
fn b1_a_child_that_wrote_last_and_closed_the_socket_leaves_an_unknown_peer_on_macos() {
    b1_without_the_child("b1-close");
}

fn b1_without_the_child(mode: &str) {
    let daemon = Daemon::new();
    let mut reap = Reap::default();
    let mut command = helper_command(mode, Some(&daemon));
    command
        .env(SETSID, "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped());
    let (helper, out) = reap.spawn(command);
    let (socket, _) = daemon.accept();
    wait_mark(&mut out.unwrap(), "settled");
    let identity = identify(&socket);
    if cfg!(target_os = "macos") {
        assert_eq!(identity, Identity::Unknown, "{mode}");
        assert_eq!(identity.window_key(), WindowKey::Connection);
    } else {
        // Linux names the connector, which still holds the socket.
        assert_eq!(known(&identity).process.pid, pid(helper));
    }
}

/// The socket handed to a process in another session, and the connector
/// gone: on macOS the receiver holds it, but its creator left, so it is
/// known with no parent and keyed by its connection; on Linux the
/// connector was reaped, so the peer is unknown.
#[test]
fn a_descriptor_passed_to_another_process_is_keyed_by_its_connection() {
    let daemon = Daemon::new();
    let mut reap = Reap::default();
    let mut command = helper_command("pass", Some(&daemon));
    command.stdout(Stdio::piped());
    let (connector, out) = reap.spawn(command);
    let (socket, request) = daemon.accept();
    let receiver: i32 = wait_mark(&mut out.unwrap(), "passed").parse().unwrap();
    assert_eq!(request.pid, Some(receiver));
    reap.wait(connector);
    let identity = identify(&socket);
    assert_eq!(identity.window_key(), WindowKey::Connection, "{identity:?}");
    if cfg!(target_os = "macos") && !no_shim() {
        let peer = known(&identity);
        assert_eq!(peer.process.pid, receiver);
        assert_eq!(peer.parent, None);
        assert_eq!(peer.terminal, None);
    } else {
        assert_eq!(identity, Identity::Unknown);
    }
    drop(socket);
}

/// The socket handed to a process in a terminal session, with the
/// connector alive in another session and no terminal: on macOS the peer is
/// the receiver (the socket's last user, which holds it), keyed by the
/// terminal's session; on Linux it is the connector, keyed by its
/// connection. Either way, a session key only for a process that is in
/// that session.
#[test]
fn a_descriptor_passed_into_a_terminal_session_is_keyed_by_who_kernel_names() {
    let daemon = Daemon::new();
    let mut reap = Reap::default();
    let mut script = in_new_terminal(&format!("{SH_HELPER} & wait"));
    script
        .env(HELPER, "pass-and-leave")
        .env(SOCK, &daemon.path)
        .env(EXE, std::env::current_exe().unwrap())
        .env_remove(SETSID)
        .env_remove(ORPHAN)
        .env_remove(AFTER_PARENT_LEAVES);
    reap.spawn(script);
    let (socket, request) = daemon.accept();
    let connector = request.connector.expect("connector pid");
    let receiver = request.pid.expect("receiver pid");
    assert_ne!(connector, receiver);
    let session_of = |pid: i32| {
        nix::unistd::getsid(Some(nix::unistd::Pid::from_raw(pid)))
            .unwrap()
            .as_raw()
    };
    let terminal_session = session_of(receiver);
    // The connector left the receiver's session, which isn't the test's.
    assert_eq!(session_of(connector), connector);
    assert_ne!(terminal_session, connector);
    assert_ne!(terminal_session, session_of(pid(std::process::id())));
    let identity = identify(&socket);
    if no_shim() {
        assert_eq!(identity, Identity::Unknown);
        return;
    }
    let peer = known(&identity);
    if cfg!(target_os = "macos") {
        assert_eq!(peer.process.pid, receiver, "{identity:?}");
        assert!(peer.terminal.is_some(), "{identity:?}");
        let WindowKey::Session(session) = identity.window_key() else {
            panic!("the receiver is in a terminal: {identity:?}");
        };
        assert_eq!(session.id, terminal_session);
    } else {
        assert_eq!(peer.process.pid, connector, "{identity:?}");
        assert_eq!(peer.terminal, None, "{identity:?}");
        assert_eq!(identity.window_key(), WindowKey::Connection);
    }
    drop(socket);
}

/// After a double fork the peer's parent is `launchd`, `init` or a
/// subreaper: never a key. On macOS the kernel rewrites the orphan's
/// `p_puniqueid` to `launchd`'s unique ID when it reparents it: the
/// creator's ID doesn't survive, so it is `ppid` 1 that makes it no key.
#[test]
fn an_orphan_after_a_double_fork_is_keyed_by_its_connection() {
    let daemon = Daemon::new();
    let mut reap = Reap::default();
    let mut sh = Command::new("/bin/sh");
    sh.args([
        "-c",
        &format!("{ORPHAN}=$$ {SH_HELPER} >/dev/null 2>&1 </dev/null & read x"),
    ])
    .env(HELPER, "connect")
    .env(SOCK, &daemon.path)
    .env(EXE, std::env::current_exe().unwrap())
    .env(SETSID, "1")
    .env_remove(ORPHAN)
    .stdin(Stdio::piped())
    .stdout(Stdio::null());
    let (creator, _) = reap.spawn(sh);
    // The creator is still alive (it waits on its input).
    let creator_id = klav_touchid::unique_id(pid(creator)).map(|c| c.unique);
    reap.wait_after_closing_input(creator);
    let (socket, _) = daemon.accept();
    let identity = identify(&socket);
    assert_eq!(identity.window_key(), WindowKey::Connection, "{identity:?}");
    if !no_shim() {
        let peer = known(&identity);
        assert_eq!(peer.terminal, None);
        if cfg!(target_os = "macos") {
            assert_eq!(peer.parent, None);
            let info = klav_touchid::process_info(peer.process.pid).unwrap();
            assert_eq!(info.ppid, 1, "reparented to launchd");
            let orphan = klav_touchid::unique_id(peer.process.pid).unwrap();
            let launchd = klav_touchid::unique_id(1).unwrap().unique;
            assert_eq!(orphan.parent, launchd);
            assert_ne!(Some(orphan.parent), creator_id);
        }
    }
}

/// A member of a terminal session whose leader has exited: no session key
/// (the leader is gone, and with it the terminal), and an orphan. On macOS
/// the kernel then reports no controlling terminal for the member, flag and
/// device alike (so `process_info` describes it, rather than `None`).
#[test]
fn a_session_whose_leader_left_gives_no_session_key() {
    let daemon = Daemon::new();
    let mut reap = Reap::default();
    let command =
        format!("trap '' HUP; {ORPHAN}=$$ {SH_HELPER} >/dev/null 2>&1 </dev/null & exit 0");
    let mut script = in_new_terminal(&command);
    script
        .env(HELPER, "connect")
        .env(SOCK, &daemon.path)
        .env(EXE, std::env::current_exe().unwrap())
        .env_remove(SETSID)
        .env_remove(ORPHAN);
    reap.spawn(script);
    let (socket, _) = daemon.accept();
    let identity = identify(&socket);
    assert_eq!(identity.window_key(), WindowKey::Connection, "{identity:?}");
    if cfg!(target_os = "macos") && !no_shim() {
        let peer = known(&identity);
        assert_eq!(peer.terminal, None);
        assert_eq!(peer.session, None);
        assert_eq!(peer.parent, None);
    }
}

/// The peer exits (and is reaped) between the first read and the last:
/// unknown.
#[test]
fn a_peer_that_exits_between_the_reads_is_unknown() {
    let daemon = Daemon::new();
    let mut reap = Reap::default();
    let mut command = helper_command("connect", Some(&daemon));
    command.env(SETSID, "1");
    let (helper, _) = reap.spawn(command);
    let (socket, _) = daemon.accept();
    let mut paused = false;
    let identity = identify_with(socket.as_fd(), &mut |step| {
        if step == Step::Middle {
            paused = true;
            reap.kill(helper);
        }
    });
    assert_eq!(identity, Identity::Unknown);
    assert!(paused || no_shim());
}

/// The `SO_PEERPIDFD` errors: only a kernel that doesn't know the option
/// means no window at all.
#[test]
fn only_a_kernel_without_so_peerpidfd_means_no_window() {
    use nix::errno::Errno;
    assert_eq!(without_pidfd(Errno::ENOPROTOOPT), Identity::NoPeerPidfd);
    assert_eq!(Identity::NoPeerPidfd.window_key(), WindowKey::NoWindow);
    for errno in [Errno::ESRCH, Errno::EINVAL, Errno::EBADF] {
        assert_eq!(without_pidfd(errno), Identity::Unknown);
    }
    assert_eq!(Identity::Unknown.window_key(), WindowKey::Connection);
}

#[test]
fn window_keys_follow_section_2_1() {
    let process = |pid| Process {
        pid,
        start: StartTime(7),
    };
    let session = Session {
        id: 40,
        leader_start: StartTime(3),
    };
    let peer = Peer {
        process: process(42),
        parent: Some(process(41)),
        session: Some(session),
        terminal: Some(0x1000_0001),
    };
    let key = |peer: &Peer| Identity::Known(peer.clone()).window_key();
    assert_eq!(key(&peer), WindowKey::Session(session));
    // In a terminal whose leader can't be read: its connection only.
    let leaderless = Peer {
        session: None,
        ..peer.clone()
    };
    assert_eq!(key(&leaderless), WindowKey::Connection);
    let no_terminal = Peer {
        terminal: None,
        ..peer.clone()
    };
    if cfg!(target_os = "macos") {
        assert_eq!(key(&no_terminal), WindowKey::Parent(process(41)));
    } else {
        assert_eq!(key(&no_terminal), WindowKey::Connection);
    }
    for parent in [None, Some(process(1))] {
        let orphan = Peer {
            parent,
            ..no_terminal.clone()
        };
        assert_eq!(key(&orphan), WindowKey::Connection);
    }
}

#[test]
fn proc_stat_is_parsed_after_the_last_parenthesis() {
    // A command name with spaces and parentheses (field 2).
    let text = "4242 (a) (b c) S 4241 4240 4239 34817 4240 4194560 120 0 0 0 1 2 0 0 \
                20 0 1 0 987654 1234567 89 18446744073709551615 1 1 0 0 0 0 0 0 0 0 0 0 \
                17 3 0 0 0 0 0\n";
    assert_eq!(
        parse_stat(text),
        Some(Stat {
            pid: 4242,
            ppid: 4241,
            sid: 4239,
            tty_nr: 34817,
            start: 987654,
        })
    );
    let no_tty = text.replace(" 34817 ", " 0 ");
    assert_eq!(parse_stat(&no_tty).map(|s| s.tty_nr), Some(0));
    assert_eq!(parse_stat("4242 (cut short) S 1 2"), None);
    assert_eq!(parse_stat("garbage"), None);
    assert_eq!(parse_stat(") 1 2 3 ("), None);
}

#[test]
fn pidfd_fdinfo_and_status_uids_are_parsed() {
    let fdinfo = "pos:\t0\nflags:\t02000002\nmnt_id:\t15\nino:\t1057\nPid:\t4242\nNSpid:\t4242\n";
    assert_eq!(parse_fdinfo_pid(fdinfo), Some(4242));
    assert_eq!(parse_fdinfo_pid("Pid:\t-1\nNSpid:\t-1\n"), Some(-1));
    assert_eq!(parse_fdinfo_pid("pos:\t0\n"), None);
    let status = "Name:\tklav\nUmask:\t0022\nState:\tS (sleeping)\nUid:\t1000\t1001\t1000\t1000\n";
    assert_eq!(parse_status_uids(status), Some((1000, 1001)));
    assert_eq!(parse_status_uids("Name:\tklav\n"), None);
}

/// The reads of a Linux peer, with the last pidfd read or the last `stat`
/// able to differ (the stop rule's re-check, finding S3). Every other read
/// succeeds and names the same process.
struct FakeProc<'a> {
    stats: Vec<Stat>,
    peer: i32,
    uid: u32,
    /// Set by the pause at [`Step::Last`]: the reads after it are the last.
    at_last: &'a Cell<bool>,
    last_pidfd: Option<i32>,
    last_stat: Option<Stat>,
}

impl ProcReads for FakeProc<'_> {
    fn pidfd_pid(&mut self) -> Option<i32> {
        match self.last_pidfd {
            Some(pid) if self.at_last.get() => Some(pid),
            _ => Some(self.peer),
        }
    }

    fn stat(&mut self, pid: i32) -> Option<Stat> {
        match self.last_stat {
            Some(stat) if self.at_last.get() && pid == self.peer => Some(stat),
            _ => self.stats.iter().find(|s| s.pid == pid).copied(),
        }
    }

    fn uids(&mut self, _pid: i32) -> Option<(u32, u32)> {
        Some((self.uid, self.uid))
    }
}

/// On Linux, the pid behind the pidfd is read again last, after every
/// other read succeeded: a process reaped in between (-1), or a pidfd that
/// names another pid, makes the peer unknown. So does a `stat` that changed.
#[test]
fn a_pidfd_or_stat_that_changes_by_the_last_read_is_unknown() {
    let stat = |pid, ppid, sid, tty_nr, start| Stat {
        pid,
        ppid,
        sid,
        tty_nr,
        start,
    };
    let peer = stat(4242, 4241, 4240, 34817, 900);
    let at_last = Cell::new(false);
    let read = |last_pidfd: Option<i32>, last_stat: Option<Stat>| {
        at_last.set(false);
        let mut proc = FakeProc {
            stats: vec![
                peer,
                stat(4241, 4240, 4240, 34817, 800),
                stat(4240, 4239, 4240, 34817, 700),
            ],
            peer: 4242,
            uid: 1000,
            at_last: &at_last,
            last_pidfd,
            last_stat,
        };
        read_peer(&mut proc, 1000, &mut |step| {
            if step == Step::Last {
                at_last.set(true);
            }
        })
    };
    // Every read the same: known, in its session.
    let known = read(None, None).expect("every read names the peer");
    assert_eq!(known.process.pid, 4242);
    assert_eq!(known.parent.map(|p| p.pid), Some(4241));
    assert_eq!(known.session.map(|s| s.id), Some(4240));
    assert_eq!(known.terminal, Some(34817));
    // Only the last pidfd read differs.
    assert_eq!(read(Some(-1), None), None, "reaped");
    assert_eq!(read(Some(4243), None), None, "another pid");
    // Only the last `stat` differs: reparented in between.
    let reparented = Stat { ppid: 1, ..peer };
    assert_eq!(read(None, Some(reparented)), None);
}

// --------------------------------------------------------- macOS only

/// The shim's reads, with the last unique-ID read, or the last
/// `process_info` of the peer, able to differ.
#[cfg(target_os = "macos")]
struct LastReads<'a> {
    /// Set by the pause at [`Step::Last`].
    at_last: &'a Cell<bool>,
    unique: bool,
    info: bool,
}

#[cfg(target_os = "macos")]
impl macos::Kernel for LastReads<'_> {
    fn peer_token(&mut self, socket: std::os::fd::BorrowedFd<'_>) -> Option<(i32, i32)> {
        macos::Shim.peer_token(socket)
    }

    fn unique_id(&mut self, pid: i32) -> Option<klav_touchid::UniqueId> {
        let mut id = macos::Shim.unique_id(pid)?;
        if self.unique && self.at_last.get() {
            id.unique ^= 1 << 62;
        }
        Some(id)
    }

    fn holds_peer_end(&mut self, pid: i32, socket: std::os::fd::BorrowedFd<'_>) -> Option<bool> {
        macos::Shim.holds_peer_end(pid, socket)
    }

    fn process_info(&mut self, pid: i32) -> Option<klav_touchid::ProcessInfo> {
        let mut info = macos::Shim.process_info(pid)?;
        if self.info && self.at_last.get() {
            info.start_micros += 1;
        }
        Some(info)
    }
}

/// The unique-ID re-check (ADR 0041 §1.1, R3, the stop rule) with every
/// read succeeding on the real peer and only the last unique ID different:
/// unknown. The same for the last `process_info`.
#[cfg(target_os = "macos")]
#[test]
fn macos_a_unique_id_that_changes_by_the_last_read_is_unknown() {
    if no_shim() {
        return;
    }
    let daemon = Daemon::new();
    let mut reap = Reap::default();
    let mut command = helper_command("connect", Some(&daemon));
    command.env(SETSID, "1");
    let (helper, _) = reap.spawn(command);
    let (socket, _) = daemon.accept();
    let at_last = Cell::new(false);
    let read = |unique: bool, info: bool| {
        at_last.set(false);
        let mut kernel = LastReads {
            at_last: &at_last,
            unique,
            info,
        };
        let identity = macos::identify_reading(&mut kernel, socket.as_fd(), &mut |step| {
            if step == Step::Last {
                at_last.set(true);
            }
        });
        assert!(at_last.get(), "a read before the last failed: {identity:?}");
        identity
    };
    // The same reads, unchanged: the helper.
    assert_eq!(known(&read(false, false)).process.pid, pid(helper));
    assert_eq!(read(true, false), Identity::Unknown);
    assert_eq!(read(false, true), Identity::Unknown);
}

/// The fd-ownership check (ADR 0041 §1.1, stop rule): a process that holds
/// the other end of this connection matches; one that holds another
/// connection to the same socket, or none, doesn't.
#[cfg(target_os = "macos")]
#[test]
fn macos_the_fd_ownership_check_tells_holders_from_others() {
    if no_shim() {
        return;
    }
    let daemon = Daemon::new();
    let mut reap = Reap::default();
    let (a, _) = reap.spawn(helper_command("connect", Some(&daemon)));
    let (socket_a, _) = daemon.accept();
    let (b, _) = reap.spawn(helper_command("connect", Some(&daemon)));
    let (socket_b, _) = daemon.accept();
    let holds =
        |pid: u32, socket: &UnixStream| klav_touchid::holds_peer_end(pid as i32, socket.as_fd());
    assert_eq!(holds(a, &socket_a), Some(true));
    assert_eq!(holds(b, &socket_b), Some(true));
    assert_eq!(holds(a, &socket_b), Some(false));
    assert_eq!(holds(b, &socket_a), Some(false));
    // The daemon side holds its own end, not the other one.
    assert_eq!(holds(std::process::id(), &socket_a), Some(false));
    reap.kill(a);
    assert_eq!(holds(a, &socket_a), None);
}

/// The unique ID (ADR 0041 §1.1, R3): kept across `exec`, which changes
/// the pid version (as the audit token's does); different for each new
/// process; and it records the creator.
#[cfg(target_os = "macos")]
#[test]
fn macos_the_unique_id_survives_exec_and_names_one_process() {
    if no_shim() {
        return;
    }
    let mut reap = Reap::default();
    let mut sh = Command::new("/bin/sh");
    sh.args(["-c", "read x; exec sleep 30"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null());
    let mut child = sh.spawn().unwrap();
    let pid = child.id() as i32;
    let before = klav_touchid::unique_id(pid).unwrap();
    let me = klav_touchid::unique_id(std::process::id() as i32).unwrap();
    assert_eq!(before.parent, me.unique);
    drop(child.stdin.take());
    let deadline = Instant::now() + WAIT;
    let after = loop {
        let now = klav_touchid::unique_id(pid).unwrap();
        if now.version != before.version {
            break now;
        }
        assert!(Instant::now() < deadline, "sh never exec'd");
        std::thread::sleep(Duration::from_millis(5));
    };
    assert_eq!(after.unique, before.unique);
    let (other, _) = reap.spawn({
        let mut c = Command::new("/bin/sleep");
        c.arg("30").stdout(Stdio::null());
        c
    });
    let other = klav_touchid::unique_id(other as i32).unwrap();
    assert!(other.unique > before.unique);
    let _ = child.kill();
    let _ = child.wait();
    assert_eq!(klav_touchid::unique_id(pid), None);
}

/// The stop rule's pid-reuse case (ADR 0041 §1.1, R3): between the
/// fd-ownership check and the last read, the peer exits and an unrelated
/// process of the same user takes its pid. Every read in between succeeds
/// on that process; only the unique ID read last tells them apart.
///
/// Ignored by default: it spawns processes until the pid comes round
/// again (about 80 000 on macOS, a minute or two).
#[cfg(target_os = "macos")]
#[test]
#[ignore = "spawns ~80 000 processes to reuse a pid; run by hand"]
fn macos_a_pid_reused_between_the_first_read_and_the_last_is_unknown() {
    assert!(!no_shim(), "needs the Swift shim");
    let daemon = Daemon::new();
    let mut reap = Reap::default();
    let mut command = helper_command("connect", Some(&daemon));
    command.env(SETSID, "1");
    let (helper, _) = reap.spawn(command);
    let (socket, _) = daemon.accept();
    let mut reused: Option<Child> = None;
    let mut first_start = None;
    let mut reached_last = false;
    let identity = identify_with(socket.as_fd(), &mut |step| match step {
        Step::Middle => {
            first_start = klav_touchid::process_info(pid(helper)).map(|i| i.start_micros);
            reap.kill(helper);
            for _ in 0..400_000 {
                let mut cat = Command::new("/bin/cat")
                    .stdin(Stdio::piped())
                    .stdout(Stdio::null())
                    .spawn()
                    .unwrap();
                if cat.id() == helper {
                    reused = Some(cat);
                    return;
                }
                drop(cat.stdin.take());
                cat.wait().unwrap();
            }
            panic!("pid {helper} was never reused");
        }
        Step::Last => {
            // The reads in between were of the new process, and passed.
            reached_last = true;
            let info = klav_touchid::process_info(pid(helper)).expect("the new process");
            assert_ne!(Some(info.start_micros), first_start);
            assert_eq!(info.euid, nix::unistd::getuid().as_raw());
        }
        Step::First => {}
    });
    let mut cat = reused.expect("the pid was reused");
    // Every read before the last succeeded: only the unique ID caught it.
    assert!(reached_last, "a read before the last failed");
    assert_eq!(identity, Identity::Unknown);
    let _ = cat.kill();
    let _ = cat.wait();
}

/// Run by hand, from a Terminal or iTerm2 window (ADR 0041 §2.1): their
/// sessions are led by root's `login`, and `klavd` has to read that leader
/// to key a terminal peer by its session. The test process connects to a
/// socket it listens on and asserts that `identify` names it, in a
/// terminal, keyed by the session `login` leads. Anywhere else (no
/// terminal, or a leader that isn't root's `login`) it fails and says so.
#[cfg(target_os = "macos")]
#[test]
#[ignore = "by hand, from a Terminal or iTerm2 window whose session root's login leads"]
#[allow(clippy::print_stdout)]
fn by_hand_from_a_terminal_window_a_peer_is_keyed_by_the_session_login_leads() {
    assert!(!no_shim(), "needs the Swift shim (KLAV_NO_SWIFT unset)");
    let ps = |pid: i32| {
        let out = Command::new("ps")
            .args(["-o", "user=,tty=,comm=", "-p", &pid.to_string()])
            .output()
            .expect("ps");
        String::from_utf8_lossy(&out.stdout).trim().to_owned()
    };
    let me = pid(std::process::id());
    let sid = nix::unistd::getsid(None).unwrap().as_raw();
    let mine = ps(me);
    let leader = ps(sid);
    let tty = mine.split_whitespace().nth(1).unwrap_or("??");
    assert!(
        tty != "??",
        "not run from a terminal window: this test process has no controlling terminal \
         ({mine}); run it from a Terminal or iTerm2 window"
    );
    let mut words = leader.split_whitespace();
    let (user, comm) = (words.next(), words.last());
    assert!(
        user == Some("root") && comm.is_some_and(|c| c.ends_with("login")),
        "not run from a session root's login leads: the leader is pid {sid} ({leader}); \
         run it from a Terminal or iTerm2 window, not inside tmux, screen, an IDE or a \
         terminal that starts the shell itself (Warp does)"
    );
    // The reads the session path makes on the leader.
    let unique = klav_touchid::unique_id(sid);
    let info = klav_touchid::process_info(sid);
    let daemon = Daemon::new();
    let mut client = UnixStream::connect(&daemon.path).unwrap();
    say(&mut client, &format!("pid {me}\nend\n"));
    let (socket, _) = daemon.accept();
    let identity = identify(&socket);
    let reads = format!(
        "leader {sid} ({leader}): unique_id = {unique:?}, process_info = {info:?}; \
         identity = {identity:?}"
    );
    println!("{reads}");
    assert!(
        unique.is_some() && info.is_some(),
        "a read on the leader failed: {reads}"
    );
    let peer = known(&identity);
    assert_eq!(peer.process.pid, me, "{reads}");
    assert!(peer.terminal.is_some(), "{reads}");
    let leader_start = StartTime(info.unwrap().start_micros);
    assert_eq!(
        identity.window_key(),
        WindowKey::Session(Session {
            id: sid,
            leader_start
        }),
        "{reads}"
    );
    drop(client);
}

// --------------------------------------------------------- Linux only

/// A kernel without `SO_PEERPIDFD` (before 6.5), through the seam: no
/// window at all.
#[cfg(target_os = "linux")]
#[test]
fn linux_a_kernel_without_so_peerpidfd_has_no_window() {
    use nix::errno::Errno;
    let daemon = Daemon::new();
    let mut reap = Reap::default();
    reap.spawn(helper_command("connect", Some(&daemon)));
    let (socket, _) = daemon.accept();
    let identity = linux::identify_from(socket.as_fd(), |_| Err(Errno::ENOPROTOOPT), &mut |_| {});
    assert_eq!(identity, Identity::NoPeerPidfd);
    assert_eq!(identity.window_key(), WindowKey::NoWindow);
    // And this kernel has it: the same connection is known.
    assert!(
        matches!(identify(&socket), Identity::Known(_)),
        "SO_PEERPIDFD missing on this kernel"
    );
}

/// The pidfd re-check on a real peer: every read of `/proc` succeeds on
/// the live process, and only the last pidfd read says it was reaped (-1):
/// unknown.
#[cfg(target_os = "linux")]
#[test]
fn linux_a_pidfd_reaped_by_the_last_read_is_unknown() {
    use nix::sys::socket::{getsockopt, sockopt::PeerPidfd};

    /// `/proc` as it is, but the last pidfd read is -1.
    struct ReapedAtLast<'a> {
        live: linux::Live<'a>,
        at_last: &'a Cell<bool>,
    }

    impl ProcReads for ReapedAtLast<'_> {
        fn pidfd_pid(&mut self) -> Option<i32> {
            if self.at_last.get() {
                return Some(-1);
            }
            self.live.pidfd_pid()
        }

        fn stat(&mut self, pid: i32) -> Option<Stat> {
            self.live.stat(pid)
        }

        fn uids(&mut self, pid: i32) -> Option<(u32, u32)> {
            self.live.uids(pid)
        }
    }

    let daemon = Daemon::new();
    let mut reap = Reap::default();
    let mut command = helper_command("connect", Some(&daemon));
    command.env(SETSID, "1");
    let (helper, _) = reap.spawn(command);
    let (socket, _) = daemon.accept();
    let pidfd = getsockopt(&socket, PeerPidfd).expect("SO_PEERPIDFD");
    let identity = linux::identify_reading(&mut linux::Live { pidfd: &pidfd }, &mut |_| {});
    assert_eq!(known(&identity).process.pid, pid(helper));
    let at_last = Cell::new(false);
    let mut proc = ReapedAtLast {
        live: linux::Live { pidfd: &pidfd },
        at_last: &at_last,
    };
    let identity = linux::identify_reading(&mut proc, &mut |step| {
        if step == Step::Last {
            at_last.set(true);
        }
    });
    assert!(at_last.get(), "a read before the last failed");
    assert_eq!(identity, Identity::Unknown);
}

/// `klavd` makes itself non-dumpable (ADR 0041 §8), and still identifies
/// its peers: after `PR_SET_DUMPABLE(0)` the kernel owns its `/proc/self`
/// files as root, and `identify` reads `/proc/self/fdinfo/<pidfd>`. The
/// helper is `klavd`'s side; this test process connects.
#[cfg(target_os = "linux")]
#[test]
fn linux_klavd_is_not_dumpable_and_still_identifies_its_peer() {
    let mut reap = Reap::default();
    let mut command = helper_command("dumpable", None);
    command.stdout(Stdio::piped());
    let (_, out) = reap.spawn(command);
    let mut out = out.unwrap();
    assert_eq!(wait_mark(&mut out, "dumpable"), "false");
    let path = wait_mark(&mut out, "listening");
    let me = std::process::id();
    let mut socket = UnixStream::connect(path).expect("connect");
    say(&mut socket, &format!("pid {me}\nend\n"));
    let line = wait_mark(&mut out, "identity");
    let (pid, identity) = line.split_once(' ').unwrap_or((&line, ""));
    assert_eq!(pid, me.to_string(), "{identity}");
    drop(socket);
}

/// The terminal's name in the prompt (ADR 0041 §2.4, layer 2): a real
/// pseudo-terminal, opened by `script`, named from its device number the
/// way `klavd` names a peer's controlling terminal. On macOS through
/// `devname` in the shim, on Linux by decoding the major and minor numbers
/// (here encoded as `/proc/<pid>/stat` gives them).
#[test]
fn a_real_terminal_is_named_from_its_device_number() {
    // The terminal stays open until the name is read: a closed
    // pseudo-terminal has no node under `/dev` any more, and `devname`
    // no longer names it (seen on macOS).
    let probe = if cfg!(target_os = "macos") {
        r#"t=$(tty); echo "KLAV-TTY $t $(stat -f %r "$t")"; read x"#
    } else {
        r#"t=$(tty); echo "KLAV-TTY $t $(stat -c '%t %T' "$t")"; read x"#
    };
    let mut script = Command::new("script");
    if cfg!(target_os = "macos") {
        script.args(["-q", "/dev/null", "/bin/sh", "-c", probe]);
    } else {
        script.args(["-q", "-e", "-c", probe, "/dev/null"]);
    }
    let spawned = script
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn();
    let mut child = match spawned {
        // A Linux image without util-linux's `script`: the decoding has
        // its own test below.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && cfg!(target_os = "linux") => return,
        spawned => spawned.expect("run script"),
    };
    let mut stdout = BufReader::new(child.stdout.take().expect("stdout"));
    let deadline = Instant::now() + Duration::from_secs(20);
    let line = loop {
        let mut line = String::new();
        assert!(
            stdout.read_line(&mut line).expect("read") > 0 && Instant::now() < deadline,
            "no terminal from script"
        );
        // `script` may echo control characters before the line.
        if let Some((_, rest)) = line.split_once("KLAV-TTY ") {
            break rest.trim().to_owned();
        }
    };
    let parts: Vec<&str> = line.split_whitespace().collect();
    let tty = parts[0].strip_prefix("/dev/").expect("a /dev path");
    let device: u64 = if cfg!(target_os = "macos") {
        parts[1].parse().expect("st_rdev")
    } else {
        let major = u64::from_str_radix(parts[1], 16).expect("major");
        let minor = u64::from_str_radix(parts[2], 16).expect("minor");
        // The kernel's `new_encode_dev`, as in `tty_nr`.
        (minor & 0xff) | (major << 8) | ((minor & !0xff) << 12)
    };
    let named = terminal_name(device);
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(b"\n");
    }
    let _ = child.kill();
    let _ = child.wait();
    if cfg!(target_os = "macos") && !klav_touchid::compiled_in() {
        // Without the shim there is no `devname`: "a terminal".
        assert_eq!(named, None);
        return;
    }
    assert_eq!(named.as_deref(), Some(tty), "device {device:#x}");
}

#[test]
fn linux_terminal_numbers_decode_to_their_names_and_odd_ones_to_none() {
    let enc = |major: u64, minor: u64| (minor & 0xff) | (major << 8) | ((minor & !0xff) << 12);
    assert_eq!(linux_terminal_name(enc(136, 3)).as_deref(), Some("pts/3"));
    assert_eq!(
        linux_terminal_name(enc(136, 300)).as_deref(),
        Some("pts/300")
    );
    assert_eq!(linux_terminal_name(enc(4, 2)).as_deref(), Some("tty2"));
    assert_eq!(linux_terminal_name(enc(4, 65)).as_deref(), Some("ttyS1"));
    // `/dev/tty`, the console, and a device of no terminal driver.
    assert_eq!(linux_terminal_name(enc(5, 0)), None);
    assert_eq!(linux_terminal_name(enc(5, 1)), None);
    assert_eq!(linux_terminal_name(enc(8, 0)), None);
    assert_eq!(linux_terminal_name(u64::MAX), None);
    // Only plain names reach a dialog.
    assert!(plain_name("ttys003") && plain_name("pts/12"));
    assert!(!plain_name("") && !plain_name("tty\u{202e}1") && !plain_name("a b"));
    assert!(!plain_name(&"t".repeat(33)));
}
