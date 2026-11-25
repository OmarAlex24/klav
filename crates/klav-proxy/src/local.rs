//! The proxy's local socket (ADR 0036 E3.5, layer 11): the live sandbox
//! list with the real connection of each, and the person's revocation
//! without a signature, for the Klav app and `klav proxy local` on the
//! machine the proxy runs on. The protocol is `klav_client::local_proxy`.
//!
//! - **Where:** `<home>/agents/<name>.sock`, mode 0600, in the agents
//!   directory (0700), or the path `--control-socket` names.
//! - **Who:** only a peer of this process's uid (as `klavd`'s socket, T32;
//!   root's too is refused). Any program of that user may ask: it sees
//!   metadata and can only take access away (risk 64).
//! - **How much:** one request line of at most 1 KiB within 5 s, one
//!   answer, then the connection closes; at most [`READERS`] at once, and
//!   one more is closed at once.
//! - **Revoking** ends the sandboxes here at once (calls in flight cut,
//!   the channel closed on its next call) and logs `sandbox.revoked` with
//!   `person_local`, waiting up to `REVOKE_SEND_WAIT` for the Klav server
//!   before it answers. Ends the server has not taken go out on the next
//!   sweeps; a server older than layer 11 refuses `person_local` (`400`),
//!   and those ends wait in the outbox until it is updated, while the proxy
//!   serves none of those sandboxes.

use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use klav_client::local_proxy::{
    self as wire, LocalError, LocalOp, LocalRequest, LocalRevoked, LocalSandbox, LocalSandboxes,
    codes,
};
use klav_core::ids::SandboxId;
use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Semaphore;

use crate::proxy::ProxyState;

/// How many connections it reads at once.
pub const READERS: usize = 16;
/// How long a connection may take to send its request line.
const REQUEST_WAIT: Duration = Duration::from_secs(5);
/// How long the answer may take to write.
const ANSWER_WRITE: Duration = Duration::from_secs(5);

/// The bound socket, not serving yet.
pub struct LocalSocket {
    listener: UnixListener,
    path: PathBuf,
    /// The socket file's inode, so the end removes only its own.
    ino: u64,
    uid: u32,
}

/// Why the socket was not bound.
#[derive(Debug)]
pub enum BindError {
    /// Another proxy answers on it: this one must not take it over.
    Taken(PathBuf),
    /// Anything else.
    Other(String),
}

impl std::fmt::Display for BindError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Taken(path) => write!(
                f,
                "another klav-proxy already answers on {}: stop it first",
                path.display()
            ),
            Self::Other(why) => f.write_str(why),
        }
    }
}

impl LocalSocket {
    /// Binds `path`, mode 0600. A stale socket file there (nobody answers)
    /// is replaced; one another process answers on is left alone
    /// ([`BindError::Taken`]); anything else there that is not a socket
    /// is an error.
    pub fn bind(path: &Path) -> Result<Self, BindError> {
        let other = |e: std::io::Error| BindError::Other(format!("{}: {e}", path.display()));
        match std::fs::symlink_metadata(path) {
            Ok(meta) if meta.file_type().is_socket() => {
                if std::os::unix::net::UnixStream::connect(path).is_ok() {
                    return Err(BindError::Taken(path.to_owned()));
                }
                std::fs::remove_file(path).map_err(other)?;
            }
            Ok(_) => {
                return Err(BindError::Other(format!(
                    "{} is there and is not a socket: move it away",
                    path.display()
                )));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(other(e)),
        }
        let listener = UnixListener::bind(path).map_err(other)?;
        let meta = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .and_then(|()| std::fs::symlink_metadata(path));
        let meta = match meta {
            Ok(meta) => meta,
            Err(e) => {
                let _ = std::fs::remove_file(path);
                return Err(other(e));
            }
        };
        Ok(Self {
            listener,
            path: path.to_owned(),
            ino: meta.ino(),
            uid: nix::unistd::getuid().as_raw(),
        })
    }

    /// Where it listens.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// What the answer to `sandboxes` says about how the proxy serves.
#[derive(Clone, Copy)]
pub(crate) struct Serving {
    pub(crate) channel: bool,
}

/// Serves the socket until `stop` completes, then removes the socket file
/// if it is still this one's.
pub(crate) async fn serve(
    socket: LocalSocket,
    state: Arc<ProxyState>,
    serving: Serving,
    stop: impl std::future::Future<Output = ()> + Send,
) {
    let LocalSocket {
        listener,
        path,
        ino,
        uid,
    } = socket;
    let readers = Arc::new(Semaphore::new(READERS));
    let mut tasks = tokio::task::JoinSet::new();
    tokio::pin!(stop);
    loop {
        tokio::select! {
            () = &mut stop => break,
            accepted = listener.accept() => {
                let Ok((stream, _)) = accepted else {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                };
                // Every reader busy: closed at once.
                let Ok(place) = Arc::clone(&readers).try_acquire_owned() else {
                    continue;
                };
                let state = Arc::clone(&state);
                tasks.spawn(async move {
                    one(stream, uid, state, serving).await;
                    drop(place);
                });
                while tasks.try_join_next().is_some() {}
            }
        }
    }
    drop(listener);
    tasks.abort_all();
    if std::fs::symlink_metadata(&path).is_ok_and(|m| m.ino() == ino) {
        let _ = std::fs::remove_file(&path);
    }
}

/// One connection: this uid's request, its answer, closed.
async fn one(mut stream: UnixStream, uid: u32, state: Arc<ProxyState>, serving: Serving) {
    if !stream.peer_cred().is_ok_and(|c| c.uid() == uid) {
        return;
    }
    let Ok(Some(line)) = tokio::time::timeout(REQUEST_WAIT, read_line(&mut stream)).await else {
        return;
    };
    let answer = match serde_json::from_str::<LocalRequest>(&line) {
        Ok(req) => match req.op() {
            Some(op) => handle(op, &state, serving).await,
            None => error(codes::BAD_REQUEST, "the line is not a request of version 1"),
        },
        Err(_) => error(codes::BAD_REQUEST, "the line is not a request of version 1"),
    };
    let _ = tokio::time::timeout(ANSWER_WRITE, async {
        stream.write_all(&answer).await?;
        stream.shutdown().await
    })
    .await;
}

/// The answer line to `op`.
async fn handle(op: LocalOp, state: &Arc<ProxyState>, serving: Serving) -> Vec<u8> {
    match op {
        LocalOp::Sandboxes => line(&list(state, serving).await),
        LocalOp::Revoke { scope } => {
            let target = if scope == wire::SCOPE_ALL {
                None
            } else {
                match scope.parse::<SandboxId>() {
                    Ok(id) => Some(id),
                    Err(_) => {
                        return error(codes::BAD_REQUEST, "scope is a sandbox ID or all");
                    }
                }
            };
            match crate::sandboxes::end_locally(state, target).await {
                Ok(ids) => {
                    let logged = send_ends(state, &ids).await;
                    tracing::info!(
                        count = ids.len(),
                        logged,
                        "the person revoked sandboxes through the local socket"
                    );
                    line(&LocalRevoked {
                        v: wire::VERSION,
                        revoked: ids,
                        logged,
                    })
                }
                Err(crate::sandboxes::LocalEndError::NotFound) => error(
                    codes::NOT_FOUND,
                    "this proxy has no live sandbox with that ID",
                ),
                Err(crate::sandboxes::LocalEndError::Store) => error(
                    codes::STORE,
                    "the proxy could not save its sandbox store: nothing was revoked",
                ),
            }
        }
    }
}

/// Sends the waiting ends, for at most `REVOKE_SEND_WAIT`; the send goes
/// on after that in its own task. Whether the server has every one of
/// `ids`.
async fn send_ends(state: &Arc<ProxyState>, ids: &[SandboxId]) -> bool {
    if ids.is_empty() {
        return true;
    }
    let flushed = {
        let state = Arc::clone(state);
        tokio::spawn(async move { crate::sandboxes::flush(&state).await })
    };
    let _ = tokio::time::timeout(wire::REVOKE_SEND_WAIT, flushed).await;
    crate::sandboxes::all_logged(state, ids).await
}

/// The live sandboxes, newest first, with the real connection of each.
async fn list(state: &ProxyState, serving: Serving) -> LocalSandboxes {
    let keys = state.connected_channel_keys();
    let profiles = state.profiles();
    let mcp_profiles = profiles
        .all()
        .into_iter()
        .filter(|p| p.mcp.is_some())
        .map(|p| p.name.clone())
        .collect();
    let proxy_id = state.proxy_id().await;
    let sandboxes = state.sandboxes();
    let store = sandboxes.store.lock().await;
    let now = sandboxes.now();
    let mut live: Vec<LocalSandbox> = store
        .sandboxes
        .iter()
        .filter(|s| s.expires_at > now)
        .map(|s| {
            let connected = store
                .channels
                .iter()
                .filter(|c| c.sandbox_id == s.sandbox_id)
                .filter_map(|c| <[u8; 32]>::try_from(c.channel_key_sha256.as_bytes()).ok())
                .any(|k| keys.contains(&k));
            LocalSandbox {
                sandbox_id: s.sandbox_id,
                issuer_id: s.issuer_id,
                label: s.label.clone(),
                profiles: s.profiles.clone(),
                issued_at: s.issued_at,
                expires_at: s.expires_at,
                claimed: s.claimed_at.is_some(),
                connected,
                last_seen_at: store
                    .last_seen
                    .get(&s.sandbox_id)
                    .copied()
                    .or(s.claimed_at)
                    .filter(|&t| t > 0)
                    .map(|t| t.min(now)),
            }
        })
        .collect();
    live.sort_by_key(|s| std::cmp::Reverse(s.issued_at));
    LocalSandboxes {
        v: wire::VERSION,
        proxy_id,
        port: state.local_port(),
        local_calls: state.serves_local_calls(),
        channel: serving.channel,
        mcp_gateway: state.mcp_gateway(),
        mcp_profiles,
        sandboxes: live,
        unsent_ends: u32::try_from(store.outbox.len()).unwrap_or(u32::MAX),
    }
}

fn line<T: Serialize>(answer: &T) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(answer).unwrap_or_default();
    bytes.push(b'\n');
    bytes
}

fn error(code: &str, message: &str) -> Vec<u8> {
    line(&LocalError {
        v: wire::VERSION,
        error: code.to_owned(),
        message: message.to_owned(),
    })
}

/// One line, at most `MAX_REQUEST` bytes, read a byte at a time; `None`
/// when the connection ends first or the line is longer.
async fn read_line(stream: &mut UnixStream) -> Option<String> {
    let mut bytes = Vec::new();
    while bytes.len() < wire::MAX_REQUEST {
        let byte = stream.read_u8().await.ok()?;
        if byte == b'\n' {
            return String::from_utf8(bytes).ok();
        }
        bytes.push(byte);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stale_socket_is_replaced_and_a_live_one_left_alone() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("p.sock");
        // A file that is not a socket: never removed.
        std::fs::write(&path, b"mine").expect("file");
        assert!(matches!(LocalSocket::bind(&path), Err(BindError::Other(_))));
        assert_eq!(std::fs::read(&path).expect("read"), b"mine");
        std::fs::remove_file(&path).expect("rm");
        // A live one: left to its owner.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        rt.block_on(async {
            let first = LocalSocket::bind(&path).expect("bind");
            let mode = std::fs::metadata(&path).expect("meta").permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
            assert!(matches!(LocalSocket::bind(&path), Err(BindError::Taken(_))));
            drop(first);
        });
        // One whose process ended without removing it: replaced.
        let stale = dir.path().join("q.sock");
        drop(std::os::unix::net::UnixListener::bind(&stale).expect("bind"));
        rt.block_on(async {
            let again = LocalSocket::bind(&stale).expect("a stale socket is replaced");
            assert_eq!(again.path(), stale);
        });
    }
}
