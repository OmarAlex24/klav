//! The forwarder's control socket, `<state>/down.sock`: how `klav-forward
//! down` asks the running forwarder of its state directory to release its
//! sandbox and stop (ADR 0036 §5, note of 2026-11-12).
//!
//! A unix socket in the state directory, not a signal to the pid in
//! `state.json`:
//! - **stopping the process needs the same uid, as a signal does:** the
//!   state directory is private to the forwarder's user
//!   (`setup::check_private`, checked again before the bind), and the
//!   forwarder also checks its peer's uid (root's too). A loopback TCP port
//!   would let any local user stop it. Releasing the sandbox is not what
//!   this guards: any local program can already ask for that through the
//!   forwarder's plaintext port (`POST /_klav/release`, api.md §8.10), and
//!   `down` changes nothing there;
//! - **no pid to trust:** a stale `state.json` after a reboot can name an
//!   unrelated process. Only the forwarder that bound the socket answers
//!   on it, so `down` never signals anything;
//! - **nothing new:** no `unsafe` for `kill(2)`, no new dependency, and no
//!   `kill` program to find in the sandbox's `PATH`.
//!
//! Three lines and an answer, one JSON line each, with a version:
//! 1. `down` sends `{"v":1,"op":"down"}`;
//! 2. the forwarder answers `{"v":1,"op":"ready"}`;
//! 3. `down` sends `{"v":1,"op":"commit"}`, and only then does the
//!    forwarder release and stop, answering [`Stopped`].
//!
//! The commit makes the outcome certain on both ends: a `down` that gave up
//! before `ready` never sends it, and a request left behind by a client
//! that has gone (its bytes can still sit in the socket after it closed,
//! on Linux as on macOS) is never acted on. Once `down` commits, the
//! forwarder's work is bounded by [`RELEASE_TIMEOUT`], well inside
//! [`ANSWER_WAIT`].
//!
//! A plain `SIGTERM` still stops the forwarder without releasing its
//! sandbox.
//!
//! [`RELEASE_TIMEOUT`]: klav_forward::forward::RELEASE_TIMEOUT

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use klav_forward::forward::{Bound, Refusal};
use klav_forward::setup;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Semaphore, mpsc};
use tokio::task::JoinSet;

/// The socket's name, in the state directory. Short: a unix socket's
/// path has at most 103 bytes on macOS and 107 on Linux.
pub(crate) const SOCKET: &str = "down.sock";
/// The only format of the lines and the answer.
pub(crate) const VERSION: u32 = 1;
/// The longest line read.
const MAX_LINE: usize = 1024;
/// How long a connection may take to send its request, and then its
/// commit after `ready`.
const REQUEST_WAIT: Duration = Duration::from_secs(5);
/// How many connections the forwarder reads at once. Each holds a place
/// for twice [`REQUEST_WAIT`] at most (the request, then the commit after
/// `ready`), so a few idle connections never hold `down` behind them. One
/// more is closed at once; `down` connects again every [`AGAIN`] for
/// [`READY_WAIT`], and with no place by then refuses with
/// `klav_forward_cannot_stop`. A program of this user that keeps all of
/// them busy can block `down` for as long as it likes, as it could stop the
/// forwarder with a signal: the socket is no guard against the same user.
///
/// `tests/up.rs::down_says_busy_when_the_socket_stays_full` fills exactly
/// this many readers: change it there too.
const READERS: usize = 16;
/// How long `down` waits for `ready`. Without it, `down` never commits, so
/// the forwarder does nothing.
///
/// `tests/up.rs::down_says_busy_when_the_socket_stays_full` times its steps
/// against this wait (5 s, and 4 s within it): change it there too.
const READY_WAIT: Duration = Duration::from_secs(5);
/// How long `down` pauses before connecting again when the forwarder closed
/// the connection before `ready` (every reader busy), within [`READY_WAIT`].
const AGAIN: Duration = Duration::from_millis(100);
/// How long `down` waits for the answer once it committed: the release
/// and a margin.
pub(crate) const ANSWER_WAIT: Duration =
    Duration::from_secs(klav_forward::forward::RELEASE_TIMEOUT.as_secs() + 10);

/// One of `down`'s lines, or the forwarder's `ready`.
#[derive(Serialize, Deserialize)]
struct Line {
    v: u32,
    op: String,
}

/// What became of the release.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Release {
    /// The proxy ended the sandbox (`released`): its `--max-live` slot is
    /// free.
    Released,
    /// The proxy said it had already ended (stopped, expired or revoked).
    AlreadyEnded,
    /// The proxy got no request (it could not be reached) or refused it:
    /// the sandbox stays live at the proxy until `klav sandbox stop`, its
    /// TTL or 1 hour without calls.
    NotReleased,
    /// The request left but no answer came in time: the proxy most likely
    /// ended it, and `down` cannot tell.
    Unknown,
}

/// The forwarder's answer, sent once its port is closed and its
/// `state.json` is gone.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Stopped {
    pub(crate) v: u32,
    /// Its sandbox, as the proxy said at the claim.
    pub(crate) sandbox: Bound,
    /// The local port it listened on, free now.
    pub(crate) port: u16,
    pub(crate) release: Release,
    /// Whether Klav's server already has the end (only when released).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) logged: Option<bool>,
    /// The proxy's refusal, or the forwarder's own, when not released.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) refusal: Option<Refusal>,
}

/// The running forwarder's end of the socket.
pub(crate) struct Control {
    listener: UnixListener,
    path: PathBuf,
    /// The socket file's inode, so the end removes only its own.
    ino: u64,
    uid: u32,
    readers: Arc<Semaphore>,
    /// Connections that committed, from the readers.
    committed: (mpsc::Sender<UnixStream>, mpsc::Receiver<UnixStream>),
    reading: JoinSet<()>,
}

impl Control {
    /// Binds `<state_dir>/down.sock`, 0600, in a state directory private to
    /// this user. One already there is replaced: `state.json` names the
    /// newest forwarder of the directory, and so does the socket.
    pub(crate) fn bind(state_dir: &Path) -> Result<Self, String> {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let uid = setup::own_uid(state_dir).map_err(|e| e.to_string())?;
        setup::check_private(state_dir, uid)?;
        let path = state_dir.join(SOCKET);
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("{}: {e}", path.display())),
        }
        let listener = UnixListener::bind(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        let done = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .and_then(|()| std::fs::symlink_metadata(&path));
        let meta = match done {
            Ok(meta) => meta,
            Err(e) => {
                let _ = std::fs::remove_file(&path);
                return Err(format!("{}: {e}", path.display()));
            }
        };
        Ok(Self {
            listener,
            path,
            ino: meta.ino(),
            uid,
            readers: Arc::new(Semaphore::new(READERS)),
            committed: mpsc::channel(READERS),
            reading: JoinSet::new(),
        })
    }

    /// Waits for a `down` from this user that committed, and returns its
    /// connection. Each connection is read on its own, so one that sends
    /// nothing holds up no other; anything else is closed without acting.
    pub(crate) async fn wait_for_down(&mut self) -> UnixStream {
        loop {
            tokio::select! {
                Some(stream) = self.committed.1.recv() => return stream,
                accepted = self.listener.accept() => {
                    let Ok((stream, _)) = accepted else {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    };
                    let Ok(place) = Arc::clone(&self.readers).try_acquire_owned() else {
                        continue;
                    };
                    let (uid, committed) = (self.uid, self.committed.0.clone());
                    self.reading.spawn(async move {
                        let taken = take(stream, uid).await;
                        drop(place);
                        if let Some(stream) = taken {
                            let _ = committed.send(stream).await;
                        }
                    });
                    // Finished readers, so the set does not grow.
                    while self.reading.try_join_next().is_some() {}
                }
            }
        }
    }

    /// Removes the socket file, if it is still this one's, and closes every
    /// connection still open on it.
    pub(crate) fn close(self) {
        use std::os::unix::fs::MetadataExt;
        let Self {
            listener,
            path,
            ino,
            mut reading,
            ..
        } = self;
        drop(listener);
        reading.abort_all();
        if std::fs::symlink_metadata(&path).is_ok_and(|m| m.ino() == ino) {
            let _ = std::fs::remove_file(&path);
        }
    }
}

/// One connection, on the forwarder's side: this user's `down`, then
/// `ready`, then its commit, all within [`REQUEST_WAIT`] each. `None` for
/// anything else, the client going away included: it is never acted on.
async fn take(mut stream: UnixStream, uid: u32) -> Option<UnixStream> {
    if !stream.peer_cred().is_ok_and(|c| c.uid() == uid) {
        return None;
    }
    let asked = tokio::time::timeout(REQUEST_WAIT, read_line(&mut stream))
        .await
        .ok()??;
    if !is(&asked, "down") {
        return None;
    }
    tokio::time::timeout(REQUEST_WAIT, write_line(&mut stream, "ready"))
        .await
        .ok()?
        .ok()?;
    let commit = tokio::time::timeout(REQUEST_WAIT, read_line(&mut stream))
        .await
        .ok()??;
    is(&commit, "commit").then_some(stream)
}

/// Whether `line` is `op` in this version.
fn is(line: &str, op: &str) -> bool {
    serde_json::from_str::<Line>(line).is_ok_and(|l| l.v == VERSION && l.op == op)
}

/// One line, at most [`MAX_LINE`] bytes, read a byte at a time so that
/// nothing after it is taken; `None` when there is none, or the
/// connection ends first.
async fn read_line(stream: &mut UnixStream) -> Option<String> {
    let mut line = Vec::new();
    while line.len() < MAX_LINE {
        let byte = stream.read_u8().await.ok()?;
        if byte == b'\n' {
            return String::from_utf8(line).ok();
        }
        line.push(byte);
    }
    None
}

async fn write_line(stream: &mut UnixStream, op: &str) -> std::io::Result<()> {
    let mut line = serde_json::to_vec(&Line {
        v: VERSION,
        op: op.into(),
    })
    .expect("json");
    line.push(b'\n');
    stream.write_all(&line).await
}

/// Sends the answer and closes the connection.
pub(crate) async fn answer(mut stream: UnixStream, stopped: &Stopped) {
    let mut line = serde_json::to_vec(stopped).expect("json");
    line.push(b'\n');
    let _ = tokio::time::timeout(REQUEST_WAIT, async {
        stream.write_all(&line).await?;
        stream.shutdown().await
    })
    .await;
}

/// What `down` got at the socket.
pub(crate) enum Asked {
    /// Nothing that can be trusted listens there (no file, a stale one, or
    /// a socket another user holds): no forwarder of this version runs for
    /// this state directory, or it could not bind.
    Nobody(String),
    /// The connection closed without an answer. Before `ready` (or with no
    /// `ready` in time), `down` did not commit and nothing was asked of the
    /// forwarder. After the commit, the forwarder closes it only once its
    /// port and `state.json` are gone: another `down` stopped it at the
    /// same moment, or it ended. Either way the state and the port tell.
    Closed(String),
    /// The forwarder stopped.
    Stopped(Stopped),
    /// `down` committed, and no answer came in time: the forwarder may be
    /// stopping, or may have stopped.
    NoAnswer(String),
}

/// Asks the forwarder of `state_dir` to release its sandbox and stop.
/// Creates nothing: a missing directory is [`Asked::Nobody`].
pub(crate) async fn ask_down(state_dir: &Path) -> Asked {
    let path = state_dir.join(SOCKET);
    // A forwarder with every reader busy closes a new connection at once:
    // `down` connects again, every [`AGAIN`], until [`READY_WAIT`].
    let deadline = tokio::time::Instant::now() + READY_WAIT;
    let mut stream = loop {
        let mut stream = match UnixStream::connect(&path).await {
            Ok(s) => s,
            Err(e) => return Asked::Nobody(format!("{}: {e}", path.display())),
        };
        // No peer: the forwarder already closed this connection (as
        // below, it may take the next one).
        let ready = match stream.peer_cred() {
            Ok(peer) => {
                if let Err(why) = trusted(state_dir, &path, peer.uid()) {
                    return Asked::Nobody(why);
                }
                tokio::time::timeout_at(deadline, async {
                    write_line(&mut stream, "down").await.ok()?;
                    read_line(&mut stream).await
                })
                .await
            }
            Err(_) => Ok(None),
        };
        match ready {
            Ok(Some(line)) if is(&line, "ready") => break stream,
            Ok(_) if tokio::time::Instant::now() + AGAIN < deadline => {
                tokio::time::sleep(AGAIN).await;
            }
            Ok(_) => {
                return Asked::Closed(format!(
                    "it closed every connection before taking the request for {} s",
                    READY_WAIT.as_secs()
                ));
            }
            Err(_) => {
                return Asked::Closed(format!(
                    "it did not take the request within {} s",
                    READY_WAIT.as_secs()
                ));
            }
        }
    };
    let asked = async {
        write_line(&mut stream, "commit").await.ok()?;
        let line = read_line_long(&mut stream).await?;
        serde_json::from_str::<Stopped>(&line).ok()
    };
    match tokio::time::timeout(ANSWER_WAIT, asked).await {
        Ok(Some(stopped)) if stopped.v == VERSION => Asked::Stopped(stopped),
        Ok(_) => Asked::Closed("it closed the connection without an answer".into()),
        Err(_) => Asked::NoAnswer(format!("no answer came within {} s", ANSWER_WAIT.as_secs())),
    }
}

/// The answer's line: longer than a request, still bounded.
async fn read_line_long(stream: &mut UnixStream) -> Option<String> {
    use tokio::io::AsyncBufReadExt;
    let mut line = String::new();
    let mut reader = tokio::io::BufReader::new(stream.take(64 * 1024));
    match reader.read_line(&mut line).await {
        Ok(n) if n > 0 && line.ends_with('\n') => Some(line),
        _ => None,
    }
}

/// Whether the process on the socket can speak for this state directory:
/// the directory is private to its owner, and the socket file and the
/// process at its other end are that owner's. Root's process is not.
fn trusted(state_dir: &Path, path: &Path, peer: u32) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    let owner = std::fs::metadata(state_dir)
        .map_err(|e| format!("{}: {e}", state_dir.display()))?
        .uid();
    setup::check_private(state_dir, owner)?;
    let file = std::fs::symlink_metadata(path)
        .map_err(|e| format!("{}: {e}", path.display()))?
        .uid();
    same_owner(path, owner, file, peer)
}

/// The socket file and its peer belong to the state directory's owner.
fn same_owner(path: &Path, owner: u32, file: u32, peer: u32) -> Result<(), String> {
    if file != owner || peer != owner {
        return Err(format!(
            "{} is held by uid {peer} (file of uid {file}), not by the state directory's owner (uid {owner})",
            path.display()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(op: &str) -> Vec<u8> {
        let mut l = serde_json::to_vec(&Line {
            v: VERSION,
            op: op.into(),
        })
        .unwrap();
        l.push(b'\n');
        l
    }

    /// This process's uid, as the kernel tells a socket's peer.
    fn me(stream: &UnixStream) -> u32 {
        stream.peer_cred().unwrap().uid()
    }

    /// A private directory of its own, short enough for a socket's path,
    /// removed when dropped (also when the test fails).
    struct Dir(PathBuf);

    impl Dir {
        fn new() -> Self {
            use std::os::unix::fs::PermissionsExt;
            use std::sync::atomic::{AtomicU32, Ordering};
            static N: AtomicU32 = AtomicU32::new(0);
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos();
            let dir = std::env::temp_dir().join(format!(
                "kfc-{}-{}-{nanos}",
                std::process::id(),
                N.fetch_add(1, Ordering::SeqCst)
            ));
            std::fs::create_dir(&dir).unwrap();
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
            Self(dir)
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// The kernel's uid of the peer decides: a `down` and its commit from
    /// another uid get no `ready` and are never taken.
    #[tokio::test]
    async fn a_peer_of_another_uid_is_never_taken() {
        let (server, mut client) = UnixStream::pair().unwrap();
        let other = me(&server).wrapping_add(1);
        client.write_all(&line("down")).await.unwrap();
        client.write_all(&line("commit")).await.unwrap();
        assert!(take(server, other).await.is_none());
        // Closed without a word: an end of file on macOS; on Linux, a reset,
        // since the lines it sent were never read.
        let mut back = Vec::new();
        match client.read_to_end(&mut back).await {
            Ok(_) => {}
            Err(e) => assert_eq!(e.kind(), std::io::ErrorKind::ConnectionReset, "{e}"),
        }
        assert!(back.is_empty(), "{back:?}");
    }

    /// This user's `down` gets `ready`, and is taken only once it commits.
    #[tokio::test]
    async fn this_users_down_is_taken_after_its_commit() {
        let (server, mut client) = UnixStream::pair().unwrap();
        let uid = me(&server);
        let taken = tokio::spawn(take(server, uid));
        client.write_all(&line("down")).await.unwrap();
        let ready = read_line(&mut client).await.unwrap();
        assert!(is(&ready, "ready"), "{ready}");
        client.write_all(&line("commit")).await.unwrap();
        assert!(taken.await.unwrap().is_some());
    }

    /// A request left in the socket by a client that has gone, before or
    /// after `ready`, is never acted on: its bytes can still be read after
    /// the close, and only a commit counts.
    #[tokio::test]
    async fn a_request_whose_client_has_gone_is_never_acted_on() {
        let (server, mut client) = UnixStream::pair().unwrap();
        let uid = me(&server);
        client.write_all(&line("down")).await.unwrap();
        drop(client);
        assert!(take(server, uid).await.is_none());

        let (server, mut client) = UnixStream::pair().unwrap();
        let taken = tokio::spawn(take(server, uid));
        client.write_all(&line("down")).await.unwrap();
        assert!(is(&read_line(&mut client).await.unwrap(), "ready"));
        drop(client);
        assert!(taken.await.unwrap().is_none());

        // Anything but the commit after `ready`.
        let (server, mut client) = UnixStream::pair().unwrap();
        let taken = tokio::spawn(take(server, uid));
        client.write_all(&line("down")).await.unwrap();
        assert!(is(&read_line(&mut client).await.unwrap(), "ready"));
        client.write_all(&line("down")).await.unwrap();
        assert!(taken.await.unwrap().is_none());
    }

    #[test]
    fn the_socket_and_its_peer_must_be_the_directory_owners() {
        let path = Path::new("down.sock");
        assert!(same_owner(path, 501, 501, 501).is_ok());
        assert!(same_owner(path, 501, 501, 0).is_err());
        assert!(same_owner(path, 501, 0, 501).is_err());
        assert!(same_owner(path, 501, 502, 502).is_err());
    }

    /// Idle connections from this user's other programs hold up no `down`:
    /// each is read on its own. Past [`READERS`] at once, one more is
    /// closed at once.
    #[tokio::test]
    async fn idle_connections_never_hold_up_a_down() {
        let dir = Dir::new();
        let mut control = Control::bind(&dir.0).unwrap();
        let path = dir.0.join(SOCKET);
        let mut idle = Vec::new();
        for _ in 0..READERS - 1 {
            idle.push(UnixStream::connect(&path).await.unwrap());
        }
        let asked = tokio::spawn({
            let dir = dir.0.clone();
            async move { ask_down(&dir).await }
        });
        let taken = tokio::time::timeout(Duration::from_secs(2), control.wait_for_down())
            .await
            .expect("down was held up");
        answer(
            taken,
            &Stopped {
                v: VERSION,
                sandbox: serde_json::from_value(serde_json::json!({
                    "sandbox_id": "sbx_test",
                    "label": "t",
                    "profiles": [],
                    "expires_at": 0,
                }))
                .unwrap(),
                port: 1,
                release: Release::Released,
                logged: Some(true),
                refusal: None,
            },
        )
        .await;
        assert!(matches!(asked.await.unwrap(), Asked::Stopped(_)));

        // Every place taken: one more is closed without a word.
        idle.push(UnixStream::connect(&path).await.unwrap());
        let wait = tokio::spawn(async move {
            let _ = tokio::time::timeout(Duration::from_secs(3), control.wait_for_down()).await;
            control
        });
        tokio::time::sleep(Duration::from_millis(200)).await;
        let mut extra = UnixStream::connect(&path).await.unwrap();
        let _ = extra.write_all(&line("down")).await;
        let back = tokio::time::timeout(Duration::from_secs(2), read_line(&mut extra))
            .await
            .expect("closed at once");
        assert!(back.is_none());
        wait.await.unwrap().close();
        assert!(!path.exists());
    }

    /// `down` speaks only to a socket in a directory private to its owner.
    #[tokio::test]
    async fn down_trusts_no_socket_in_a_directory_others_can_write() {
        use std::os::unix::fs::PermissionsExt;
        let dir = Dir::new();
        let _listener = UnixListener::bind(dir.0.join(SOCKET)).unwrap();
        std::fs::set_permissions(&dir.0, std::fs::Permissions::from_mode(0o777)).unwrap();
        match ask_down(&dir.0).await {
            Asked::Nobody(why) => assert!(why.contains("can be written"), "{why}"),
            _ => panic!("a socket in a directory others can write was trusted"),
        }
    }
}
