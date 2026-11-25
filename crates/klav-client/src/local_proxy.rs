//! The credential proxy's local socket (ADR 0036 E3.5, layer 11): how the
//! Mac app and `klav proxy local` talk to a `klav-proxy` that runs on this
//! machine, as the same user.
//!
//! A unix socket, `<KLAV_HOME>/agents/<name>.sock` (mode 0600, in the
//! 0700 agents directory), that only answers a peer of the proxy's own uid.
//! One JSON line in, one JSON line out, then the proxy closes:
//!
//! - `{"v":1,"op":"sandboxes"}`: the live sandboxes as the proxy holds
//!   them, with the real connection of each ([`LocalSandboxes`]);
//! - `{"v":1,"op":"revoke","scope":"<sandbox id>"}` or `"scope":"all"`:
//!   ends that sandbox, or every live one, at once and without a signature,
//!   and the proxy logs `sandbox.revoked` with `person_local`
//!   ([`LocalRevoked`]). It works with `klavd` locked (E2.3).
//!
//! What crosses is metadata: IDs, the label the issuer wrote, profile
//! names, times. Never a secret, a digest of one or a key. Any program of
//! the same user can ask both (risk 64): the list shows only metadata, and
//! revoking only takes access away.
//!
//! An error is `{"v":1,"error":"<code>","message":"…"}`.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use klav_core::ids::{AgentId, SandboxId};
use serde::{Deserialize, Serialize};

use crate::Home;

/// The only version of the lines.
pub const VERSION: u32 = 1;
/// The proxy's default agent name (`klav-proxy --name`).
pub const DEFAULT_NAME: &str = "klav-proxy";
/// The longest request line the proxy reads.
pub const MAX_REQUEST: usize = 1024;
/// The longest answer a client reads (the list of a busy proxy).
pub const MAX_ANSWER: u64 = 4 * 1024 * 1024;
/// How long a client waits for the answer: a revoke waits up to
/// [`REVOKE_SEND_WAIT`] for the Klav server, and a margin.
pub const ANSWER_WAIT: Duration = Duration::from_secs(15);
/// How long the proxy waits for the Klav server to take the ends of a
/// revoke before it answers (the ends are sent anyway, later if need be).
pub const REVOKE_SEND_WAIT: Duration = Duration::from_secs(5);
/// The `scope` of every live sandbox.
pub const SCOPE_ALL: &str = "all";

/// The socket of the proxy named `name` whose data directory is `home`.
pub fn socket_path(home: &Home, name: &str) -> PathBuf {
    home.dir().join("agents").join(format!("{name}.sock"))
}

/// A request line: `{"v":1,"op":"sandboxes"}` or
/// `{"v":1,"op":"revoke","scope":"…"}`, nothing else.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalRequest {
    /// [`VERSION`].
    pub v: u32,
    /// `sandboxes` or `revoke`.
    pub op: String,
    /// With `revoke`, and only then: a sandbox ID, or [`SCOPE_ALL`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

impl LocalRequest {
    /// The line for `op`.
    pub fn new(op: &LocalOp) -> Self {
        match op {
            LocalOp::Sandboxes => Self {
                v: VERSION,
                op: "sandboxes".into(),
                scope: None,
            },
            LocalOp::Revoke { scope } => Self {
                v: VERSION,
                op: "revoke".into(),
                scope: Some(scope.clone()),
            },
        }
    }

    /// What it asks, if it is a request of this version.
    pub fn op(&self) -> Option<LocalOp> {
        if self.v != VERSION {
            return None;
        }
        match (self.op.as_str(), &self.scope) {
            ("sandboxes", None) => Some(LocalOp::Sandboxes),
            ("revoke", Some(scope)) => Some(LocalOp::Revoke {
                scope: scope.clone(),
            }),
            _ => None,
        }
    }
}

/// What a request asks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalOp {
    /// The live sandboxes.
    Sandboxes,
    /// End one sandbox (its ID) or every live one ([`SCOPE_ALL`]).
    Revoke {
        /// A sandbox ID, or `all`.
        scope: String,
    },
}

/// The answer to `sandboxes`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalSandboxes {
    /// [`VERSION`].
    pub v: u32,
    /// The proxy's agent ID: the app compares it with the account's proxy.
    pub proxy_id: AgentId,
    /// The port of its loopback listener (`127.0.0.1:PORT`).
    pub port: u16,
    /// Whether it serves profile calls on that listener (not with
    /// `--no-local-calls`): local MCP clients need it.
    pub local_calls: bool,
    /// Whether it also listens for sandboxes' forwarders (`--channel`).
    pub channel: bool,
    /// Whether the account's MCP gateway is on, as the proxy last heard.
    pub mcp_gateway: bool,
    /// Its MCP profiles, by name: `http://127.0.0.1:PORT/<name>/…`.
    pub mcp_profiles: Vec<String>,
    /// Its live sandboxes, newest first.
    pub sandboxes: Vec<LocalSandbox>,
    /// Ends waiting for the Klav server.
    pub unsent_ends: u32,
}

/// One live sandbox, as the proxy holds it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalSandbox {
    /// Its ID.
    pub sandbox_id: SandboxId,
    /// The agent that started it.
    pub issuer_id: AgentId,
    /// The label its issuer wrote: the issuer's words, shown as such.
    pub label: String,
    /// Its profiles.
    pub profiles: Vec<String>,
    /// When it started (Unix ms).
    pub issued_at: i64,
    /// When it ends (Unix ms).
    pub expires_at: i64,
    /// Whether its forwarder claimed it.
    pub claimed: bool,
    /// Whether its forwarder is connected now.
    pub connected: bool,
    /// The last call over its channel, or its claim (Unix ms, proxy clock).
    pub last_seen_at: Option<i64>,
}

/// The answer to `revoke`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalRevoked {
    /// [`VERSION`].
    pub v: u32,
    /// The sandboxes it ended (none for `all` with none live).
    pub revoked: Vec<SandboxId>,
    /// Whether the Klav server already has every end (`person_local`).
    /// When not, the proxy sends them on its next sweeps; it serves none of
    /// them from now on either way.
    pub logged: bool,
}

/// An error line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalError {
    /// [`VERSION`].
    pub v: u32,
    /// A code: [`codes`].
    pub error: String,
    /// What happened, in English.
    pub message: String,
}

/// The error codes of the socket.
pub mod codes {
    /// The line is not a request of this version.
    pub const BAD_REQUEST: &str = "bad_request";
    /// No live sandbox of the proxy has that ID.
    pub const NOT_FOUND: &str = "sandbox_not_found";
    /// The proxy could not save its store: nothing was ended.
    pub const STORE: &str = "store";
}

/// Why asking the local proxy failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalProxyError {
    /// No proxy answers on the socket (no file, a stale one, refused).
    NotRunning(String),
    /// The socket is not this user's: nothing was asked.
    Untrusted(String),
    /// The proxy refused: its code and message.
    Refused {
        /// One of [`codes`], or a newer one.
        code: String,
        /// Its message.
        message: String,
    },
    /// The connection broke, timed out, or the answer did not read.
    Failed(String),
}

impl std::fmt::Display for LocalProxyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotRunning(why) => write!(f, "no klav-proxy answers on this Mac: {why}"),
            Self::Untrusted(why) => write!(f, "the proxy's socket is not to be trusted: {why}"),
            Self::Refused { message, .. } => write!(f, "the local proxy refused: {message}"),
            Self::Failed(why) => write!(f, "the local proxy did not answer: {why}"),
        }
    }
}

impl std::error::Error for LocalProxyError {}

/// Lists the live sandboxes of the proxy at `path`.
pub fn sandboxes(path: &Path) -> Result<LocalSandboxes, LocalProxyError> {
    ask(path, &LocalOp::Sandboxes)
}

/// Ends one sandbox (`Some`) or every live one (`None`) of the proxy at
/// `path`, without a signature (`person_local`).
pub fn revoke(path: &Path, sandbox: Option<SandboxId>) -> Result<LocalRevoked, LocalProxyError> {
    let scope = sandbox.map_or_else(|| SCOPE_ALL.to_owned(), |id| id.to_string());
    ask(path, &LocalOp::Revoke { scope })
}

/// Sends `op` and reads the answer as `T`, or the proxy's error.
fn ask<T: serde::de::DeserializeOwned>(path: &Path, op: &LocalOp) -> Result<T, LocalProxyError> {
    check_socket(path)?;
    let mut stream = UnixStream::connect(path)
        .map_err(|e| LocalProxyError::NotRunning(format!("{}: {e}", path.display())))?;
    let failed = |e: std::io::Error| LocalProxyError::Failed(e.to_string());
    stream.set_read_timeout(Some(ANSWER_WAIT)).map_err(failed)?;
    stream
        .set_write_timeout(Some(ANSWER_WAIT))
        .map_err(failed)?;
    let mut line = serde_json::to_vec(&LocalRequest::new(op))
        .map_err(|e| LocalProxyError::Failed(e.to_string()))?;
    line.push(b'\n');
    stream.write_all(&line).map_err(failed)?;
    let mut answer = String::new();
    BufReader::new(stream.take(MAX_ANSWER))
        .read_line(&mut answer)
        .map_err(failed)?;
    if !answer.ends_with('\n') {
        return Err(LocalProxyError::Failed(
            "the connection closed before a whole answer".into(),
        ));
    }
    read_answer(&answer)
}

/// The answer line as `T`, or the proxy's error.
pub fn read_answer<T: serde::de::DeserializeOwned>(line: &str) -> Result<T, LocalProxyError> {
    let value: serde_json::Value = serde_json::from_str(line)
        .map_err(|_| LocalProxyError::Failed("the answer is not JSON".into()))?;
    if value.get("v").and_then(serde_json::Value::as_u64) != Some(u64::from(VERSION)) {
        return Err(LocalProxyError::Failed(
            "the answer is of another version".into(),
        ));
    }
    if value.get("error").is_some() {
        let e: LocalError = serde_json::from_value(value)
            .map_err(|_| LocalProxyError::Failed("the error does not read".into()))?;
        return Err(LocalProxyError::Refused {
            code: e.error,
            message: e.message,
        });
    }
    serde_json::from_value(value)
        .map_err(|_| LocalProxyError::Failed("the answer does not read".into()))
}

/// The socket is a socket, owned by whoever owns its directory, in a
/// directory no one else may write to: a socket left there by another
/// user is never asked.
fn check_socket(path: &Path) -> Result<(), LocalProxyError> {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) => {
            return Err(LocalProxyError::NotRunning(format!(
                "{}: {e}",
                path.display()
            )));
        }
    };
    if !meta.file_type().is_socket() {
        return Err(LocalProxyError::Untrusted(format!(
            "{} is not a socket",
            path.display()
        )));
    }
    let dir = path.parent().unwrap_or(Path::new("."));
    let dir_meta = std::fs::metadata(dir)
        .map_err(|e| LocalProxyError::NotRunning(format!("{}: {e}", dir.display())))?;
    if meta.uid() != dir_meta.uid() {
        return Err(LocalProxyError::Untrusted(format!(
            "{} belongs to another user",
            path.display()
        )));
    }
    if dir_meta.mode() & 0o022 != 0 {
        return Err(LocalProxyError::Untrusted(format!(
            "others may write in {}",
            dir.display()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_lines_have_their_documented_shape() {
        let line = |op: LocalOp| serde_json::to_string(&LocalRequest::new(&op)).expect("json");
        let sandboxes = line(LocalOp::Sandboxes);
        assert_eq!(sandboxes, r#"{"v":1,"op":"sandboxes"}"#);
        let revoke = line(LocalOp::Revoke {
            scope: "all".into(),
        });
        assert_eq!(revoke, r#"{"v":1,"op":"revoke","scope":"all"}"#);
        // Both read back as what they ask.
        let read = |l: &str| {
            serde_json::from_str::<LocalRequest>(l)
                .ok()
                .and_then(|r| r.op())
        };
        assert_eq!(read(&sandboxes), Some(LocalOp::Sandboxes));
        assert_eq!(
            read(&revoke),
            Some(LocalOp::Revoke {
                scope: "all".into()
            })
        );
        // Anything else is not a request.
        for bad in [
            r#"{"v":1,"op":"stop"}"#,
            r#"{"v":1,"op":"revoke"}"#,
            r#"{"v":1,"op":"sandboxes","scope":"all"}"#,
            r#"{"v":1,"op":"sandboxes","extra":1}"#,
            r#"{"v":2,"op":"sandboxes"}"#,
            r#"{"op":"sandboxes"}"#,
        ] {
            assert_eq!(read(bad), None, "{bad}");
        }
    }

    #[test]
    fn an_error_line_is_the_proxys_refusal() {
        let refused = read_answer::<LocalRevoked>(
            r#"{"v":1,"error":"sandbox_not_found","message":"no such sandbox"}"#,
        );
        assert_eq!(
            refused,
            Err(LocalProxyError::Refused {
                code: codes::NOT_FOUND.into(),
                message: "no such sandbox".into()
            })
        );
        assert!(matches!(
            read_answer::<LocalRevoked>(r#"{"v":2,"revoked":[],"logged":true}"#),
            Err(LocalProxyError::Failed(_))
        ));
        assert_eq!(
            read_answer::<LocalRevoked>(r#"{"v":1,"revoked":[],"logged":true}"#),
            Ok(LocalRevoked {
                v: 1,
                revoked: Vec::new(),
                logged: true
            })
        );
    }

    #[test]
    fn nothing_but_this_users_socket_is_asked() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("p.sock");
        assert!(matches!(
            sandboxes(&path),
            Err(LocalProxyError::NotRunning(_))
        ));
        std::fs::write(&path, b"").expect("file");
        assert!(matches!(
            sandboxes(&path),
            Err(LocalProxyError::Untrusted(_))
        ));
        std::fs::remove_file(&path).expect("rm");
        let _listener = std::os::unix::net::UnixListener::bind(&path).expect("bind");
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o777))
            .expect("chmod");
        assert!(matches!(
            sandboxes(&path),
            Err(LocalProxyError::Untrusted(_))
        ));
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
            .expect("chmod");
    }
}
