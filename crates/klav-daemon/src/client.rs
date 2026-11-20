//! Client side of the socket, used by `klav` and `klav-native-host`.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use klav_client::Home;
use serde::de::DeserializeOwned;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use zeroize::Zeroizing;

use crate::protocol::{
    ErrorBody, ErrorCode, MAX_LINE, Notice, PROTOCOL_VERSION, Request, RequestEnvelope,
    ResponseEnvelope,
};

/// The most notice lines one request may get before its answer: more is a
/// protocol error, not a loop.
const MAX_NOTICES: usize = 4;

/// The presence gate's fields of a request envelope (ADR 0041 §2.4). Send
/// them only to a `klavd` whose `status` has `presence`: an older one
/// refuses unknown fields.
#[derive(Debug, Clone, Copy, Default)]
pub struct Presence {
    /// Ask for notice lines ([`Notice::TouchId`]) before this request's
    /// answer.
    pub notify: bool,
    /// For `unlock` with the password: the window the client's question
    /// said it opens (`always`: none).
    pub shown: Option<crate::uv::Window>,
    /// For `unlock` with the password: the client didn't read it on its
    /// terminal, so the unlock opens no window and isn't a passkey
    /// verification.
    pub untyped: bool,
}

/// `$KLAV_HOME/touchid.json`: `klavd`'s Touch ID enrolment (ADR 0013).
pub const TOUCH_ID_FILE: &str = "touchid.json";
/// `$KLAV_HOME/local-pauses.json`: pauses of agents decided on this Mac
/// that the server does not know yet (ADR 0033 §7.2).
pub const LOCAL_PAUSES_FILE: &str = "local-pauses.json";
/// `$KLAV_HOME/account-deletion.json`: what `klavd` knows of the
/// account's deletion (ADR 0037 §3, A3), so `status` says it while locked,
/// also after a restart.
pub const ACCOUNT_DELETION_FILE: &str = "account-deletion.json";
/// What `klavd` keeps in `$KLAV_HOME` for the account, deleted with this
/// device's copy (`klav logout`, ADR 0037 §3). The rest of the account's
/// files are `klav_client`'s.
pub const ACCOUNT_FILES: &[&str] = &[TOUCH_ID_FILE, LOCAL_PAUSES_FILE, ACCOUNT_DELETION_FILE];

/// Whether `klavd` has Touch ID set up in `home` (its enrolment exists),
/// running or not.
pub fn touch_id_enrolled(home: &Home) -> bool {
    home.file(TOUCH_ID_FILE).exists()
}

/// A connection to `klavd`.
pub struct DaemonClient {
    reader: BufReader<OwnedReadHalf>,
    writer: OwnedWriteHalf,
    next_id: u64,
    /// What the client last read in `status` about the presence gate.
    presence_gate: bool,
}

impl DaemonClient {
    /// Connects to the daemon of `home`; `None` when it is not running.
    pub async fn connect(home: &Home) -> Option<Self> {
        Self::connect_path(&home.socket_path()).await
    }

    /// Connects to a socket path; `None` when nobody listens there.
    pub async fn connect_path(path: &Path) -> Option<Self> {
        let stream = UnixStream::connect(path).await.ok()?;
        let (read, writer) = stream.into_split();
        Some(Self {
            reader: BufReader::new(read),
            writer,
            next_id: 1,
            presence_gate: false,
        })
    }

    /// Whether the last `status` this client read said the presence gate
    /// is on (`presence`, ADR 0041 §2.4). The client records it with
    /// [`DaemonClient::set_presence_gate`]; nothing else reads it.
    pub fn presence_gate(&self) -> bool {
        self.presence_gate
    }

    /// Records what `status` said about the presence gate.
    pub fn set_presence_gate(&mut self, on: bool) {
        self.presence_gate = on;
    }

    /// Sends `request` and decodes the result; also returns the warnings.
    pub async fn call<R: DeserializeOwned>(
        &mut self,
        request: Request,
    ) -> Result<(R, Vec<String>), ErrorBody> {
        self.call_presence(request, Presence::default(), &mut |_| {})
            .await
    }

    /// [`DaemonClient::call`] with the presence gate's envelope fields:
    /// each notice `klavd` writes before the answer goes to `on_notice` as
    /// it arrives.
    pub async fn call_presence<R: DeserializeOwned>(
        &mut self,
        request: Request,
        presence: Presence,
        on_notice: &mut (dyn FnMut(Notice) + Send),
    ) -> Result<(R, Vec<String>), ErrorBody> {
        let id = self.next_id;
        self.next_id += 1;
        let envelope = RequestEnvelope {
            v: PROTOCOL_VERSION,
            id,
            request,
            notify: presence.notify,
            shown: presence.shown,
            untyped: presence.untyped,
        };
        let mut line = Zeroizing::new(serde_json::to_vec(&envelope).map_err(internal)?);
        drop(envelope);
        line.push(b'\n');
        self.writer.write_all(&line).await.map_err(gone)?;
        drop(line);

        let mut notices = 0;
        let response = loop {
            let mut reply = Zeroizing::new(Vec::new());
            let read = (&mut self.reader)
                .take(MAX_LINE as u64 + 1)
                .read_until(b'\n', &mut reply)
                .await
                .map_err(gone)?;
            if read == 0 || reply.last() != Some(&b'\n') {
                return Err(ErrorBody {
                    code: ErrorCode::Internal,
                    message: "klavd closed the connection".into(),
                    paused: None,
                    presence: None,
                });
            }
            let response: ResponseEnvelope = serde_json::from_slice(&reply).map_err(internal)?;
            drop(reply);
            let Some(notice) = response.notice else {
                break response;
            };
            // A notice only for this request, only if it asked, and never
            // instead of the answer.
            notices += 1;
            if !presence.notify
                || response.id != id
                || response.ok.is_some()
                || response.error.is_some()
                || notices > MAX_NOTICES
            {
                return Err(ErrorBody {
                    code: ErrorCode::Internal,
                    message: "klavd sent a notice this request didn't ask for".into(),
                    paused: None,
                    presence: None,
                });
            }
            on_notice(notice);
        };
        // `id` 0 with an error: `klavd` could not read the request, so it
        // could not tell its `id` either (an older `klavd` that does not
        // know a field, say). That error is the answer.
        if response.id == 0
            && let Some(error) = response.error
        {
            return Err(error);
        }
        if response.id != id {
            return Err(ErrorBody {
                code: ErrorCode::Internal,
                message: "klavd answered another request".into(),
                paused: None,
                presence: None,
            });
        }
        if let Some(error) = response.error {
            return Err(error);
        }
        let value = response.ok.unwrap_or(serde_json::Value::Null);
        let result = serde_json::from_value(value).map_err(internal)?;
        Ok((result, response.warnings))
    }
}

/// Starts `klavd` in the background for `home` and connects to it.
///
/// Looks for `klavd` next to the running executable (after resolving
/// symlinks), then in `PATH`. It
/// runs in its own process group (Ctrl-C in a terminal, or the browser
/// closing the native messaging host, does not stop it) and writes its
/// startup errors to `$KLAV_HOME/klavd.log`.
pub async fn spawn_daemon(home: &Home, idle_lock: Duration) -> Result<DaemonClient, String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    // Through a symlink (`/usr/local/bin/klav` → `Klav.app/Contents/
    // Helpers/klav`, ADR 0027 §4), the sibling is the one in the bundle.
    // There `Helpers/klavd` is itself a link to `klavd.app/Contents/MacOS/
    // klavd`, the bundle that makes the Touch ID dialog say Klav (ADR 0027,
    // note of 2026-11-05); started through the link, it still does.
    let exe = std::fs::canonicalize(&exe).unwrap_or(exe);
    let sibling = exe.with_file_name(format!("klavd{}", std::env::consts::EXE_SUFFIX));
    let program = if sibling.exists() {
        sibling
    } else {
        PathBuf::from("klavd")
    };
    home.ensure().map_err(|e| e.to_string())?;
    let log_path = home.file("klavd.log");
    let log = klav_client::home::create_private(&log_path).map_err(|e| e.to_string())?;
    let mut command = std::process::Command::new(&program);
    command
        .arg("--idle-lock")
        .arg(format!("{}s", idle_lock.as_secs()))
        .env("KLAV_HOME", home.dir())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(log));
    {
        use std::os::unix::process::CommandExt;
        // Its own process group: signals to the caller's group miss it.
        command.process_group(0);
    }
    let mut child = command.spawn().map_err(|e| {
        format!(
            "cannot start {}: {e} (install klavd next to klav or in PATH)",
            program.display()
        )
    })?;
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while std::time::Instant::now() < deadline {
        if let Some(client) = DaemonClient::connect(home).await {
            return Ok(client);
        }
        if let Ok(Some(status)) = child.try_wait() {
            let log = std::fs::read_to_string(&log_path).unwrap_or_default();
            return Err(format!("klavd exited ({status}): {}", log.trim()));
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Err("klavd did not start in time".into())
}

fn internal(e: impl std::fmt::Display) -> ErrorBody {
    ErrorBody {
        code: ErrorCode::Internal,
        message: format!("klavd protocol: {e}"),
        paused: None,
        presence: None,
    }
}

fn gone(e: std::io::Error) -> ErrorBody {
    ErrorBody {
        code: ErrorCode::Internal,
        message: format!("klavd connection: {e}"),
        paused: None,
        presence: None,
    }
}
