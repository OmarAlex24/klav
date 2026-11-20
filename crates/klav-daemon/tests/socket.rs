//! `klavd` over its socket, without a server: status, errors, access
//! permissions, one instance per home, shutdown.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use klav_client::Home;
use klav_client::ops::SecretText;
use klav_daemon::client::DaemonClient;
use klav_daemon::protocol::{DaemonStatus, ErrorCode, Request};

fn start(home: &Path) -> Child {
    Command::new(env!("CARGO_BIN_EXE_klavd"))
        .env("KLAV_HOME", home)
        .args(["--idle-lock", "5m"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn klavd")
}

fn wait_for(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if UnixStream::connect(path).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    panic!("klavd did not start");
}

fn wait_exit(child: &mut Child) -> std::process::ExitStatus {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().expect("try_wait") {
            return status;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    let _ = child.kill();
    child.wait().expect("wait")
}

#[tokio::test(flavor = "multi_thread")]
async fn the_socket_speaks_version_1_and_only_to_its_user() {
    let dir = tempfile::tempdir().unwrap();
    let home_dir = dir.path().join("h");
    let home = Home::at(home_dir.clone());
    home.ensure().unwrap();
    // A stale socket file from a crashed daemon is replaced.
    std::fs::write(home.socket_path(), b"").unwrap();
    let mut daemon = start(&home_dir);
    wait_for(&home.socket_path());

    let mode = std::fs::metadata(home.socket_path())
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
    let dir_mode = std::fs::metadata(&home_dir).unwrap().permissions().mode();
    assert_eq!(dir_mode & 0o777, 0o700);

    // A second daemon for the same home refuses to start.
    let second = start(&home_dir).wait_with_output().unwrap();
    assert!(!second.status.success());
    assert!(String::from_utf8_lossy(&second.stderr).contains("already running"));

    let mut client = DaemonClient::connect(&home).await.expect("connect");
    let (status, _): (DaemonStatus, _) = client.call(Request::Status).await.unwrap();
    assert!(!status.logged_in);
    assert!(!status.unlocked);
    assert_eq!(status.protocol, 1);
    assert_eq!(status.idle_lock_secs, 300);
    assert_eq!(status.pid, daemon.id());

    let err = client
        .call::<serde_json::Value>(Request::List {
            filter: Default::default(),
        })
        .await
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::Locked);
    let err = client
        .call::<serde_json::Value>(Request::Unlock {
            password: Some(SecretText::new("whatever-password")),
            passkey_flow: false,
        })
        .await
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::NotLoggedIn);

    // Raw lines: another version, garbage (not echoed back).
    let mut raw = UnixStream::connect(home.socket_path()).unwrap();
    let mut reader = BufReader::new(raw.try_clone().unwrap());
    raw.write_all(b"{\"v\":2,\"id\":5,\"request\":{\"op\":\"status\"}}\n")
        .unwrap();
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    assert!(
        line.contains("\"id\":5") && line.contains("bad_request"),
        "{line}"
    );
    raw.write_all(b"{\"password\":\"MARKER-not-json\n").unwrap();
    line.clear();
    reader.read_line(&mut line).unwrap();
    assert!(
        line.contains("bad_request") && !line.contains("MARKER"),
        "{line}"
    );

    let _: (serde_json::Value, _) = client.call(Request::Shutdown).await.unwrap();
    assert!(wait_exit(&mut daemon).success());
    assert!(!home.socket_path().exists());
}

#[test]
fn the_daemon_stops_when_its_home_disappears() {
    let dir = tempfile::tempdir().unwrap();
    let home_dir = dir.path().join("h");
    let mut daemon = start(&home_dir);
    wait_for(&home_dir.join("klavd.sock"));
    std::fs::remove_dir_all(&home_dir).unwrap();
    assert!(wait_exit(&mut daemon).success());
}

/// A client that connects while `klavd` starts, as the CLI does every 50 ms
/// while it starts one, neither stops it nor is answered before it is
/// ready (finding 2 of the second layer-2 review): `klavd` proves its
/// socket under another name, so the probe never takes a client's
/// connection for its own. Five starts, with clients connecting as fast as
/// they can from this process, which is not `klavd`'s.
#[test]
fn clients_connecting_while_klavd_starts_do_not_stop_it() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    for _ in 0..5 {
        let dir = tempfile::tempdir().unwrap();
        let home_dir = dir.path().join("h");
        std::fs::create_dir_all(&home_dir).unwrap();
        let socket = home_dir.join("klavd.sock");
        let stop = Arc::new(AtomicBool::new(false));
        let clients: Vec<_> = (0..4)
            .map(|_| {
                let (stop, socket) = (Arc::clone(&stop), socket.clone());
                std::thread::spawn(move || {
                    while !stop.load(Ordering::Relaxed) {
                        drop(UnixStream::connect(&socket));
                    }
                })
            })
            .collect();
        let mut daemon = start(&home_dir);
        wait_for(&socket);
        // Still up a moment later, and answering.
        std::thread::sleep(Duration::from_millis(300));
        stop.store(true, Ordering::Relaxed);
        for client in clients {
            client.join().unwrap();
        }
        if let Some(status) = daemon.try_wait().unwrap() {
            let mut err = String::new();
            let _ = std::io::Read::read_to_string(daemon.stderr.as_mut().unwrap(), &mut err);
            panic!("klavd stopped while starting ({status}): {err}");
        }
        let mut raw = UnixStream::connect(&socket).unwrap();
        let mut reader = BufReader::new(raw.try_clone().unwrap());
        raw.write_all(b"{\"v\":1,\"id\":1,\"request\":{\"op\":\"status\"}}\n")
            .unwrap();
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        assert!(line.contains("\"ok\""), "{line}");
        raw.write_all(b"{\"v\":1,\"id\":2,\"request\":{\"op\":\"shutdown\"}}\n")
            .unwrap();
        line.clear();
        reader.read_line(&mut line).unwrap();
        assert!(wait_exit(&mut daemon).success());
        // The staging name is gone with it.
        assert!(std::fs::symlink_metadata(home_dir.join("klavd.new")).is_err());
    }
}

/// A `klavd` older than the client cannot read a request with a field it
/// does not know, and answers with `id` 0: that error comes back as it is,
/// so the caller can tell it apart (the SDK then fills without
/// `agent_id`). Any other `id` that is not the request's is still refused.
#[tokio::test(flavor = "multi_thread")]
async fn an_unreadable_request_comes_back_as_the_daemons_error() {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("old.sock");
    let listener = tokio::net::UnixListener::bind(&path).expect("bind");
    let old = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept");
        let (read, mut write) = stream.into_split();
        let mut lines = tokio::io::BufReader::new(read).lines();
        for reply in [
            r#"{"v":1,"id":0,"error":{"code":"bad_request","message":"malformed request"}}"#,
            r#"{"v":1,"id":7,"ok":{}}"#,
        ] {
            lines.next_line().await.expect("read").expect("a request");
            write
                .write_all(format!("{reply}\n").as_bytes())
                .await
                .expect("write");
        }
    });
    let mut client = DaemonClient::connect_path(&path).await.expect("connect");
    let err = client
        .call::<serde_json::Value>(Request::Status)
        .await
        .expect_err("unreadable");
    assert_eq!(
        (err.code, err.message.as_str()),
        (ErrorCode::BadRequest, "malformed request")
    );
    let err = client
        .call::<serde_json::Value>(Request::Status)
        .await
        .expect_err("another id");
    assert!(err.message.contains("another request"), "{}", err.message);
    old.await.expect("join");
}

/// `2026-11-13T18:17:02Z` to Unix seconds (dates from 1970 on).
fn unix_seconds(text: &str) -> u64 {
    let n = |range: std::ops::Range<usize>| -> u64 { text[range].parse().expect("digits") };
    let (y, m, d) = (n(0..4), n(5..7), n(8..10));
    assert_eq!(text.len(), 20, "{text}");
    assert!(text.ends_with('Z') && &text[10..11] == "T", "{text}");
    // Days from civil (Howard Hinnant), the inverse of build.rs's.
    let y = if m <= 2 { y - 1 } else { y };
    let era = y / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    days * 86_400 + n(11..13) * 3600 + n(14..16) * 60 + n(17..19)
}

/// `klavd --version` names the commit and its time (the Mac app compares
/// them, ADR 0027 §4.1), and `status` reports the same build. Built from a
/// source without Git history, both say it is unknown.
#[tokio::test(flavor = "multi_thread")]
async fn status_reports_the_build_that_version_prints() {
    let out = Command::new(env!("CARGO_BIN_EXE_klavd"))
        .arg("--version")
        .output()
        .expect("klavd --version");
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).expect("utf-8");
    let rest = text
        .trim_end()
        .strip_prefix(&format!("klavd {} (", env!("CARGO_PKG_VERSION")))
        .and_then(|r| r.strip_suffix(')'))
        .unwrap_or_else(|| panic!("unexpected --version: {text:?}"));

    let dir = tempfile::tempdir().unwrap();
    let home_dir = dir.path().join("h");
    let home = Home::at(home_dir.clone());
    home.ensure().unwrap();
    let mut daemon = start(&home_dir);
    wait_for(&home.socket_path());
    let mut client = DaemonClient::connect(&home).await.expect("connect");
    let (status, _): (DaemonStatus, _) = client.call(Request::Status).await.unwrap();
    // The number means what it always meant.
    assert_eq!(status.version, env!("CARGO_PKG_VERSION"));
    if rest == "commit unknown" {
        assert_eq!((status.commit, status.commit_time), (None, None));
    } else {
        let (short, time) = rest.split_once(' ').expect("hash and time");
        assert_eq!(short.len(), 12, "{rest}");
        let commit = status.commit.expect("commit in status");
        assert!(commit.starts_with(short), "{commit} vs {short}");
        assert_eq!(status.commit_time, Some(unix_seconds(time)));
    }
    let _: (serde_json::Value, _) = client.call(Request::Shutdown).await.unwrap();
    assert!(wait_exit(&mut daemon).success());
}

/// `klavd` makes itself non-dumpable at start-up (ADR 0041 §8): the kernel
/// then owns its `/proc/<pid>` files as root, and another process of the
/// same user can't open its `environ`, while it can open a plain child's.
/// Fails if `main` stops calling `forbid_same_user_debuggers`. As root the
/// open succeeds anyway, so then only the owner is checked.
#[cfg(target_os = "linux")]
#[test]
fn klavd_is_not_dumpable_from_start_up() {
    use std::os::unix::fs::MetadataExt;

    let dir = tempfile::tempdir().unwrap();
    let home_dir = dir.path().join("h");
    let home = Home::at(home_dir.clone());
    home.ensure().unwrap();
    let mut daemon = start(&home_dir);
    wait_for(&home.socket_path());
    let mut control = Command::new("sleep")
        .arg("30")
        .stdin(Stdio::null())
        .spawn()
        .expect("spawn sleep");
    let environ = |pid: u32| format!("/proc/{pid}/environ");
    let owner = |path: &str| std::fs::metadata(path).map(|m| m.uid());
    let me = owner("/proc/self").unwrap();
    let klavd_owner = owner(&environ(daemon.id()));
    let klavd_open = std::fs::File::open(environ(daemon.id())).map(drop);
    let control_owner = owner(&environ(control.id()));
    let control_open = std::fs::File::open(environ(control.id())).map(drop);
    let _ = control.kill();
    let _ = control.wait();
    let _ = daemon.kill();
    let _ = daemon.wait();
    assert_eq!(klavd_owner.unwrap(), 0, "klavd's /proc files are root's");
    if me != 0 {
        assert_eq!(control_owner.unwrap(), me);
        control_open.expect("a dumpable child's environ opens");
        let err = klavd_open.expect_err("klavd's environ must not open");
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied, "{err}");
    }
}
