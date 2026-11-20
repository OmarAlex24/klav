//! How `klavd` proves its socket at start-up, and what the watchdog takes
//! for its own socket (ADR 0041 §8; findings 2 and 4 of the second layer-2
//! review). The start-up race with a client is in `tests/socket.rs`, with
//! the real binary.

use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use tokio::net::UnixListener;

use super::{Probe, bound_socket, bound_socket_with, socket_file, still_ours};

/// This test binary run as the peer helper of `peer::tests`, connecting to
/// `sock` from another process; returns once it connected.
fn connect_from_another_process(sock: &Path) -> Child {
    helper(sock, "connect-mark", "KLAV-PEER connected")
}

/// The peer helper in `mode`, once it printed `ready`.
fn helper(sock: &Path, mode: &str, ready: &str) -> Child {
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "peer::tests::helper",
            "--nocapture",
            "--test-threads=1",
            "-q",
        ])
        .env("KLAV_PEER_HELPER", mode)
        .env("KLAV_PEER_SOCK", sock)
        .env_remove("KLAV_PEER_SETSID")
        .env_remove("KLAV_PEER_ORPHAN")
        .env_remove("KLAV_PEER_AFTER_PARENT_LEAVES")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn the helper");
    let mut out = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    while out.read_line(&mut line).expect("helper output") > 0 {
        if line.contains(ready) {
            return child;
        }
        line.clear();
    }
    stop(child);
    panic!("the helper did not print {ready:?}");
}

fn stop(mut child: Child) {
    // This test's own child, by its handle.
    let _ = child.kill();
    let _ = child.wait();
}

/// The proven socket ends up at the path, and the staging name is gone.
#[tokio::test(flavor = "multi_thread")]
async fn the_socket_is_proven_under_another_name_then_renamed_into_place() {
    let dir = tempfile::tempdir().unwrap();
    let staging = dir.path().join("klavd.new");
    let path = dir.path().join("klavd.sock");
    // A stale socket at the path is replaced.
    drop(std::os::unix::net::UnixListener::bind(&path).unwrap());
    let listener = UnixListener::bind(&staging).unwrap();
    let id = bound_socket(&listener, &staging, &path)
        .await
        .expect("proven");
    assert!(still_ours(&path, id));
    assert!(std::fs::symlink_metadata(&staging).is_err());
}

/// The pid check: a relay that takes the staging name, catches `klavd`'s
/// own connection, forwards one from another process to `klavd`'s socket,
/// and puts the name back before the inode is read again, is caught only
/// by the pid. Without it, `klavd` would take the forwarded connection for
/// its own, and rename a socket it never proved.
#[tokio::test(flavor = "multi_thread")]
async fn a_connection_from_another_process_is_never_taken_for_klavds_own() {
    let dir = tempfile::tempdir().unwrap();
    let staging = dir.path().join("klavd.new");
    let moved = dir.path().join("moved");
    let path = dir.path().join("klavd.sock");
    let listener = UnixListener::bind(&staging).unwrap();
    let mut relay = None;
    let mut helper = None;
    let mut pause = |step: Probe| match step {
        Probe::Bound => {
            std::fs::rename(&staging, &moved).unwrap();
            relay = Some(std::os::unix::net::UnixListener::bind(&staging).unwrap());
        }
        Probe::Connected => {
            // `klavd`'s connection went to the relay. Another process
            // connects to `klavd`'s socket, and the name goes back.
            helper = Some(connect_from_another_process(&moved));
            std::fs::remove_file(&staging).unwrap();
            std::fs::rename(&moved, &staging).unwrap();
        }
    };
    let proven = bound_socket_with(
        &listener,
        &staging,
        &path,
        Duration::from_secs(3),
        &mut pause,
    )
    .await;
    let error = proven.expect_err("a connection from another process was taken for klavd's");
    assert!(error.contains("replaced"), "{error}");
    // Nothing was renamed into place, and the staging name is cleaned up.
    assert!(std::fs::symlink_metadata(&path).is_err());
    assert!(std::fs::symlink_metadata(&staging).is_err());
    drop(relay);
    stop(helper.expect("the helper ran"));
}

/// Another process connecting to the staging name while `klavd` proves it
/// doesn't fail the start: its connection is closed unanswered.
#[tokio::test(flavor = "multi_thread")]
async fn a_stray_connection_at_the_staging_name_does_not_fail_the_start() {
    let dir = tempfile::tempdir().unwrap();
    let staging = dir.path().join("klavd.new");
    let path = dir.path().join("klavd.sock");
    let listener = UnixListener::bind(&staging).unwrap();
    let mut helper = None;
    let mut pause = |step: Probe| {
        if step == Probe::Bound {
            // Queued before `klavd`'s own.
            helper = Some(connect_from_another_process(&staging));
        }
    };
    let id = bound_socket_with(
        &listener,
        &staging,
        &path,
        Duration::from_secs(10),
        &mut pause,
    )
    .await
    .expect("started");
    assert!(still_ours(&path, id));
    stop(helper.expect("the helper ran"));
}

/// A listener at `path` whose backlog holds about `backlog` connections.
fn listener_with_backlog(path: &Path, backlog: i32) -> UnixListener {
    use nix::sys::socket::{AddressFamily, Backlog, SockFlag, SockType, UnixAddr};
    use std::os::fd::AsRawFd;
    let fd = nix::sys::socket::socket(
        AddressFamily::Unix,
        SockType::Stream,
        SockFlag::empty(),
        None,
    )
    .unwrap();
    nix::sys::socket::bind(fd.as_raw_fd(), &UnixAddr::new(path).unwrap()).unwrap();
    nix::sys::socket::listen(&fd, Backlog::new(backlog).unwrap()).unwrap();
    let listener = std::os::unix::net::UnixListener::from(fd);
    listener.set_nonblocking(true).unwrap();
    UnixListener::from_std(listener).unwrap()
}

/// A program that fills the staging name's backlog before `klavd`
/// connects (the third layer-2 review, C) doesn't fail the start:
/// `klavd`'s connect is refused, so it drops what is queued and tries
/// again.
#[tokio::test(flavor = "multi_thread")]
async fn a_full_backlog_at_the_staging_name_does_not_fail_the_start() {
    let dir = tempfile::tempdir().unwrap();
    let staging = dir.path().join("klavd.new");
    let path = dir.path().join("klavd.sock");
    let listener = listener_with_backlog(&staging, 1);
    let mut filler = None;
    let mut pause = |step: Probe| {
        if step == Probe::Bound {
            // From another process: `klavd` would take a connection from
            // its own pid for its own.
            // It stops at its first refused connect: the backlog is full.
            filler = Some(helper(&staging, "fill", "KLAV-PEER filled"));
        }
    };
    let id = bound_socket_with(
        &listener,
        &staging,
        &path,
        Duration::from_secs(10),
        &mut pause,
    )
    .await
    .expect("started");
    assert!(still_ours(&path, id));
    stop(filler.expect("the helper ran"));
}

/// A symbolic link to `klavd`'s socket is not its socket (finding 4).
#[test]
fn a_symbolic_link_is_never_taken_for_the_socket() {
    let dir = tempfile::tempdir().unwrap();
    let real = dir.path().join("real.sock");
    let link = dir.path().join("klavd.sock");
    let _listener = std::os::unix::net::UnixListener::bind(&real).unwrap();
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let id = socket_file(&real).expect("a socket");
    assert!(still_ours(&real, id));
    assert!(!still_ours(&link, id));
    assert!(socket_file(&link).unwrap_err().contains("not a socket"));
    // Nor is a plain file.
    let plain = dir.path().join("plain");
    std::fs::write(&plain, b"").unwrap();
    assert!(socket_file(&plain).is_err());
}
