//! `klav-native-host`: the bridge between the browser extension and
//! `klavd` (ADR 0017 §4, `docs/extension.md`).
//!
//! The browser starts one host process per native messaging port and talks
//! to it over stdin/stdout with 4-byte length-prefixed JSON messages (native
//! byte order). Each message from the extension is a `klavd` request
//! envelope (`{"v":1,"id":…,"request":{…}}`); the host checks it against
//! the list of operations the extension may use and passes it on as a line
//! on the `klavd` socket. Lines from `klavd` go back as messages.
//!
//! The host refuses to bridge a caller that is not an allowed extension:
//! Chromium passes the caller's origin (`chrome-extension://<id>/`) as the
//! first argument, Firefox the manifest path and then the extension ID. A
//! refused caller gets one answer, `extension_not_allowed` with the command
//! that allows it ([`refuse`]); it never reaches `klavd`.

use std::path::PathBuf;
use std::time::Duration;

use klav_client::Home;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::sync::mpsc;
use zeroize::Zeroizing;

use crate::protocol::{
    ErrorBody, ErrorCode, MAX_LINE, PROTOCOL_VERSION, Request, RequestEnvelope, ResponseEnvelope,
};

/// Name of the host in the browsers' manifests.
pub const HOST_NAME: &str = "dev.klav.host";
/// Chromium ID of the development build (fixed by the `key` in its
/// manifest; the private key was discarded).
pub const DEV_CHROMIUM_ID: &str = "niiplppgdljgimbnmokojdkofdcjkgao";
/// Chromium IDs of the published builds, one per store (Chrome Web Store,
/// Edge Add-ons), as each store assigns them. Allowed by default, like the
/// Firefox add-on: the store keeps the key, unlike the development build's.
/// Each is 32 letters a–p (a test checks it). Where they come from:
/// `docs/publicar-extension.md` §6.
pub const STORE_CHROMIUM_IDS: &[&str] = &["aoabckikmlcaffgipfcaoeccgclbpbph"];
/// Firefox ID (`browser_specific_settings.gecko.id`), the same in
/// development and on addons.mozilla.org.
pub const FIREFOX_ID: &str = "klav@klav.dev";
/// Largest message accepted from the extension.
pub const MAX_IN: usize = 1024 * 1024;
/// Largest message the browser accepts from a host (Chromium's limit).
pub const MAX_OUT: usize = 1024 * 1024;

/// The extensions allowed by default: the store builds in Chromium
/// browsers ([`STORE_CHROMIUM_IDS`], as origins) and the Firefox add-on.
/// The Chromium development build ([`DEV_CHROMIUM_ID`]) is not: the public
/// key that fixes its ID is in the repository, so any unpacked extension
/// can take that ID. `klav extension install-host --dev` adds it with
/// `--allow`, like any other ID (`--extension-id`).
pub fn default_allowed() -> Vec<String> {
    STORE_CHROMIUM_IDS
        .iter()
        .map(|id| format!("chrome-extension://{id}/"))
        .chain(std::iter::once(FIREFOX_ID.to_owned()))
        .collect()
}

/// Who started the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Caller {
    /// A Chromium browser: the extension's origin.
    Chromium(String),
    /// Firefox: the add-on ID.
    Firefox(String),
}

impl Caller {
    /// The identifier compared with the allow list.
    pub fn id(&self) -> &str {
        match self {
            Caller::Chromium(origin) => origin,
            Caller::Firefox(id) => id,
        }
    }
}

/// The host's arguments: its own (written by `klav extension install-host`
/// into a wrapper) and the browser's.
#[derive(Debug, Clone)]
pub struct HostArgs {
    /// `KLAV_HOME` (`--home`); the default home otherwise.
    pub home: Option<PathBuf>,
    /// Extra allowed extensions (`--allow`): origins or Firefox IDs.
    pub allowed: Vec<String>,
    /// The caller, from the browser's arguments.
    pub caller: Caller,
}

/// Parses `argv[1..]`.
pub fn parse_args(args: &[String]) -> Result<HostArgs, String> {
    let mut home = None;
    let mut allowed = Vec::new();
    let mut rest = Vec::new();
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--home" => home = Some(PathBuf::from(it.next().ok_or("--home needs a value")?)),
            "--allow" => allowed.push(it.next().ok_or("--allow needs a value")?.clone()),
            other => rest.push(other.to_owned()),
        }
    }
    // Chromium: `chrome-extension://<id>/` (and `--parent-window=…` on
    // Windows). Firefox: the manifest path and the add-on ID.
    let caller = if let Some(origin) = rest.iter().find(|a| a.starts_with("chrome-extension://")) {
        Caller::Chromium(origin.clone())
    } else if rest.len() >= 2 && !rest[rest.len() - 1].starts_with('-') {
        Caller::Firefox(rest[rest.len() - 1].clone())
    } else {
        return Err("not started by a browser (no extension origin or ID)".into());
    };
    Ok(HostArgs {
        home,
        allowed,
        caller,
    })
}

/// Whether `caller` is one of the allowed extensions (the defaults plus
/// `extra`). Origins are compared exactly, with their trailing slash.
pub fn caller_allowed(caller: &Caller, extra: &[String]) -> bool {
    let id = caller.id();
    if let Caller::Chromium(origin) = caller {
        // `chrome-extension://` + 32 letters a–p + `/`.
        let Some(ext) = origin
            .strip_prefix("chrome-extension://")
            .and_then(|r| r.strip_suffix('/'))
        else {
            return false;
        };
        if !is_chromium_id(ext) {
            return false;
        }
    }
    default_allowed()
        .iter()
        .chain(extra)
        .any(|allowed| allowed == id || normalise_origin(allowed).as_deref() == Some(id))
}

/// A Chromium extension ID: 32 letters a–p.
fn is_chromium_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| (b'a'..=b'p').contains(&b))
}

/// A bare Chromium ID as an origin.
fn normalise_origin(id: &str) -> Option<String> {
    is_chromium_id(id).then(|| format!("chrome-extension://{id}/"))
}

/// The command that adds `caller` to the allow list: `--dev` for the
/// development build, `--extension-id` with its ID otherwise. An ID that
/// is not plainly one (it would need shell quoting) becomes `ID`.
pub fn install_hint(caller: &Caller) -> String {
    const INSTALL: &str = "klav extension install-host";
    let id = match caller {
        Caller::Chromium(origin) => {
            let id = origin
                .strip_prefix("chrome-extension://")
                .and_then(|r| r.strip_suffix('/'));
            if id == Some(DEV_CHROMIUM_ID) {
                return format!("{INSTALL} --dev");
            }
            id.filter(|id| is_chromium_id(id))
        }
        // `name@domain` or `{uuid}` (addons.mozilla.org).
        Caller::Firefox(id) => Some(id.as_str()).filter(|id| {
            (id.contains('@') || (id.starts_with('{') && id.ends_with('}')))
                && id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-._@{}".contains(&b))
        }),
    };
    format!("{INSTALL} --extension-id {}", id.unwrap_or("ID"))
}

/// Whether the extension may send `request` (ADR 0017 §4). Never: values
/// for `run`/`inject` (only one environment variable's, ADR 0032 §6),
/// attachments, agents, revocation, the audit log or `shutdown`; and never
/// a duplicate title.
pub fn check_request(request: &Request) -> Result<(), String> {
    match request {
        Request::Status
        | Request::Unlock { .. }
        | Request::Lock
        | Request::Sync
        | Request::Vaults
        | Request::Projects { .. }
        | Request::List { .. }
        | Request::View { .. }
        | Request::Suggest { .. }
        | Request::Autofill { .. }
        | Request::Totp { .. }
        // Passkeys (ADR 0020): candidates are metadata; `get` and `create`
        // ask for Touch ID in klavd and never return a private key.
        | Request::PasskeyCandidates { .. }
        | Request::PasskeyGet { .. }
        | Request::PasskeyCreate { .. }
        // An agent's armed use (ADR 0020 §9): only with the token klavd
        // gave this connection, for that tab, once.
        | Request::AgentPasskeyUse { .. }
        // The verification window: loosening it asks for Touch ID (or the
        // password) in klavd (ADR 0020 §8).
        | Request::PasskeyUv { .. }
        | Request::Approvals { .. }
        | Request::DecideApproval { .. }
        | Request::Tasks { .. }
        | Request::DecideTask { .. }
        | Request::AddToTask { .. }
        | Request::EndTask { .. }
        // Agent secret requests (ADR 0046): extension may list, deny, or
        // fulfill without proxy grants (`proxy_grant` stays off the extension).
        | Request::SecretRequests { .. }
        | Request::DenySecretRequest { .. }
        | Request::GeneratorRecord { .. }
        | Request::GeneratorHistory
        | Request::GeneratedValue { .. }
        | Request::GeneratorDelete { .. }
        | Request::PasswordHistory { .. }
        | Request::PreviousPassword { .. }
        // «Use the new one» / «Keep the current one» on a pending password
        // (ADR 0022 §5): the person's own decision. The agent's
        // `agent_rotate_*` stay off the extension's list.
        | Request::ResolvePending { .. }
        // The health report (ADR 0022 §4) for the popup: items, hosts and
        // reasons, never values.
        | Request::VaultHealth
        | Request::HealthSettings { .. }
        // «Fix my reused passwords» (ADR 0022 §6): the person's card, the
        // offer (with presence, like `decide_task`) and its progress. The
        // card names only the active agents ({id, name}); `agents` stays
        // off the list.
        | Request::ReusedOffer { .. }
        | Request::OfferTask { .. }
        | Request::TaskProgress { .. }
        // Importing (ADR 0024, which lifts ADR 0017 §4's ban): the
        // extension's import wizard. No value comes back; it amounts to
        // creating and editing items, which the extension may do.
        | Request::ImportAdd { .. }
        | Request::ImportPreview { .. }
        | Request::ImportApply { .. }
        | Request::ImportCancel { .. }
        | Request::ExtensionAttach { .. }
        | Request::ExtensionReply { .. }
        // The master password the person typed in Klav's frame for an
        // agent's event (ADR 0041 §3.1): `klavd` checks it.
        | Request::ExtensionPresence { .. }
        // Environments in the popup (ADR 0032 §6): names and origins, never
        // a value; saving one goes through `prepare_environment` (the
        // grants first, presence to lower the protection) and trashing a
        // protected one asks for presence. The import review stays the
        // CLI's: importing a `.env` belongs to it (§6).
        | Request::Environments { .. }
        | Request::Environment { .. }
        | Request::EnvironmentSave { .. }
        | Request::EnvironmentTrash { .. } => Ok(()),
        // «Show» and «Copy» of one variable (ADR 0032 §6): `klavd` refuses
        // a reference that is not an environment's variable, and asks for
        // Touch ID when it is protected. Never the `resolve` of `run`.
        Request::Resolve {
            references,
            variables_only: true,
            ..
        } if references.len() == 1 => Ok(()),
        Request::Create { item } if !item.allow_duplicate => Ok(()),
        Request::Edit { patch, .. } if !patch.allow_duplicate => Ok(()),
        Request::FulfillSecretRequest { input, .. }
            if !input.grant_proxy && !input.allow_duplicate =>
        {
            Ok(())
        }
        Request::FulfillSecretRequest { input, .. } if input.grant_proxy => {
            Err("the extension cannot grant credential proxy access".into())
        }
        Request::Create { .. } | Request::Edit { .. } | Request::FulfillSecretRequest { .. } => {
            Err("the extension cannot create duplicate titles".into())
        }
        _ => Err("this operation is not available to the browser extension".into()),
    }
}

/// Reads one message. `None` at the end of the input.
pub async fn read_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> std::io::Result<Option<Zeroizing<Vec<u8>>>> {
    let mut len = [0u8; 4];
    match reader.read_exact(&mut len).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_ne_bytes(len) as usize;
    if len > MAX_IN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "message too large",
        ));
    }
    let mut body = Zeroizing::new(vec![0u8; len]);
    reader.read_exact(&mut body).await?;
    Ok(Some(body))
}

/// Writes one message.
pub async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    body: &[u8],
) -> std::io::Result<()> {
    let len = u32::try_from(body.len())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "message too large"))?;
    let mut frame = Zeroizing::new(Vec::with_capacity(body.len() + 4));
    frame.extend_from_slice(&len.to_ne_bytes());
    frame.extend_from_slice(body);
    writer.write_all(&frame).await?;
    writer.flush().await
}

fn error_message(id: u64, code: ErrorCode, message: &str) -> Zeroizing<Vec<u8>> {
    let response = ResponseEnvelope {
        v: PROTOCOL_VERSION,
        id,
        ok: None,
        error: Some(ErrorBody {
            code,
            message: message.to_owned(),
            paused: None,
            presence: None,
        }),
        warnings: Vec::new(),
        notice: None,
    };
    Zeroizing::new(serde_json::to_vec(&response).unwrap_or_default())
}

/// The `id` of a message from the extension, `0` if it has none. The rest
/// is skipped, not copied.
fn request_id(message: &[u8]) -> u64 {
    #[derive(serde::Deserialize)]
    struct Id {
        #[serde(default)]
        id: u64,
    }
    serde_json::from_slice::<Id>(message).map_or(0, |m| m.id)
}

/// Answers a caller that is not allowed: its first request gets
/// `extension_not_allowed` with [`install_hint`], and nothing else. The
/// host neither connects to `klavd` nor starts it for this caller, and
/// reads only the request's `id`. Returns at the end of the input, or after
/// that one answer.
pub async fn refuse<R, W>(caller: &Caller, stdin: &mut R, stdout: &mut W) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let Some(frame) = read_frame(stdin).await? else {
        return Ok(());
    };
    let message = format!(
        "this extension is not allowed to use Klav here: run `{}`",
        install_hint(caller)
    );
    let answer = error_message(request_id(&frame), ErrorCode::ExtensionNotAllowed, &message);
    write_frame(stdout, &answer).await
}

/// Turns a message from the extension into a `klavd` line, or the error
/// message to answer with.
pub fn to_daemon_line(message: &[u8]) -> Result<Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>> {
    let mut envelope: RequestEnvelope = match serde_json::from_slice(message) {
        Ok(e) => e,
        Err(_) => {
            // serde's message may quote the input: keep it out.
            return Err(error_message(
                request_id(message),
                ErrorCode::BadRequest,
                "malformed request",
            ));
        }
    };
    if let Err(why) = check_request(&envelope.request) {
        return Err(error_message(envelope.id, ErrorCode::Denied, &why));
    }
    // The envelope's presence fields (ADR 0041, `docs/klavd.md` §3): the
    // extension's `shown` goes through, for its password unlock. A notice
    // line (`notify`) is for a terminal to print its name: the extension
    // has none to print, and a line with no `ok` or `error` would settle
    // its pending request, so it never asks for one.
    envelope.notify = false;
    let mut line = Zeroizing::new(serde_json::to_vec(&envelope).map_err(|_| {
        error_message(
            envelope.id,
            ErrorCode::Internal,
            "cannot encode the request",
        )
    })?);
    line.push(b'\n');
    Ok(line)
}

/// Turns a `klavd` line into a message for the extension; a response too
/// large for the browser becomes an error with the same `id`.
pub fn to_extension_message(line: &[u8]) -> Zeroizing<Vec<u8>> {
    let body = line.strip_suffix(b"\n").unwrap_or(line);
    if body.len() <= MAX_OUT {
        return Zeroizing::new(body.to_vec());
    }
    let id = serde_json::from_slice::<ResponseEnvelope>(body)
        .map(|r| r.id)
        .unwrap_or(0);
    error_message(
        id,
        ErrorCode::Invalid,
        "the answer is too large for the browser: narrow the search",
    )
}

/// Runs the bridge until the browser closes the port or `klavd` goes
/// away. `klavd` is started if it is not running.
pub async fn run<R, W>(home: Home, stdin: R, stdout: W) -> Result<(), String>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let (tx, mut rx) = mpsc::channel::<Zeroizing<Vec<u8>>>(16);
    let writer = tokio::spawn(async move {
        let mut stdout = stdout;
        while let Some(message) = rx.recv().await {
            if write_frame(&mut stdout, &message).await.is_err() {
                return;
            }
        }
    });
    let stream = match UnixStream::connect(home.socket_path()).await {
        Ok(s) => Ok(s),
        Err(_) => match crate::client::spawn_daemon(&home, Duration::from_secs(15 * 60)).await {
            Ok(client) => {
                drop(client);
                UnixStream::connect(home.socket_path())
                    .await
                    .map_err(|e| format!("klavd: {e}"))
            }
            Err(e) => Err(e),
        },
    };
    let mut stdin = stdin;
    let result = match stream {
        Ok(stream) => relay(stream, &mut stdin, tx.clone()).await,
        Err(why) => {
            // Answer every request with the reason, so the extension can
            // show it, until the browser closes the port.
            let message = format!("cannot reach klavd: {why}");
            while let Ok(Some(frame)) = read_frame(&mut stdin).await {
                if tx
                    .send(error_message(
                        request_id(&frame),
                        ErrorCode::Internal,
                        &message,
                    ))
                    .await
                    .is_err()
                {
                    break;
                }
            }
            Err(why)
        }
    };
    drop(tx);
    let _ = writer.await;
    result
}

async fn relay<R: AsyncRead + Unpin>(
    stream: UnixStream,
    stdin: &mut R,
    tx: mpsc::Sender<Zeroizing<Vec<u8>>>,
) -> Result<(), String> {
    let (read, mut write) = stream.into_split();
    let to_browser = tx.clone();
    let mut from_daemon = tokio::spawn(async move {
        let mut reader = BufReader::new(read);
        loop {
            let mut line = Zeroizing::new(Vec::new());
            match (&mut reader)
                .take(MAX_LINE as u64 + 1)
                .read_until(b'\n', &mut line)
                .await
            {
                Ok(0) | Err(_) => return,
                Ok(_) => {}
            }
            if to_browser.send(to_extension_message(&line)).await.is_err() {
                return;
            }
        }
    });
    let result = loop {
        tokio::select! {
            frame = read_frame(stdin) => match frame {
                Ok(Some(frame)) => match to_daemon_line(&frame) {
                    Ok(line) => {
                        if let Err(e) = write.write_all(&line).await {
                            break Err(format!("klavd: {e}"));
                        }
                    }
                    Err(answer) => {
                        if tx.send(answer).await.is_err() {
                            break Ok(());
                        }
                    }
                },
                Ok(None) => break Ok(()),
                Err(e) => break Err(format!("browser: {e}")),
            },
            // klavd went away (stopped, or its home was removed).
            _ = &mut from_daemon => break Err("klavd closed the connection".into()),
        }
    };
    from_daemon.abort();
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn callers_are_read_from_the_browser_arguments() {
        let chrome = parse_args(&args(&[
            "--home",
            "/tmp/h",
            "--allow",
            "abcdefghijklmnopabcdefghijklmnop",
            "chrome-extension://niiplppgdljgimbnmokojdkofdcjkgao/",
        ]))
        .unwrap();
        assert_eq!(chrome.home.as_deref(), Some(std::path::Path::new("/tmp/h")));
        assert_eq!(
            chrome.caller,
            Caller::Chromium("chrome-extension://niiplppgdljgimbnmokojdkofdcjkgao/".into())
        );
        let firefox = parse_args(&args(&[
            "/Users/a/Library/Application Support/Mozilla/NativeMessagingHosts/dev.klav.host.json",
            "klav@klav.dev",
        ]))
        .unwrap();
        assert_eq!(firefox.caller, Caller::Firefox("klav@klav.dev".into()));
        assert!(parse_args(&args(&[])).is_err());
        assert!(parse_args(&args(&["--home"])).is_err());
    }

    #[test]
    fn store_ids_are_chromium_ids() {
        // A mistyped ID would never match a caller: fail here instead.
        for id in STORE_CHROMIUM_IDS {
            assert!(
                id.len() == 32 && id.bytes().all(|b| (b'a'..=b'p').contains(&b)),
                "{id:?} is not a Chromium extension ID (32 letters a-p)"
            );
            assert_ne!(*id, DEV_CHROMIUM_ID);
            let store = Caller::Chromium(format!("chrome-extension://{id}/"));
            assert!(caller_allowed(&store, &[]));
        }
        // The store builds and Firefox's add-on; never the development build.
        let defaults = default_allowed();
        assert_eq!(defaults.len(), STORE_CHROMIUM_IDS.len() + 1);
        assert_eq!(defaults.last().map(String::as_str), Some(FIREFOX_ID));
        assert!(!defaults.iter().any(|id| id.contains(DEV_CHROMIUM_ID)));
    }

    #[test]
    fn only_allowed_extensions_may_call() {
        // The development build only when installed with `--dev` (its key is public).
        let dev = Caller::Chromium(format!("chrome-extension://{DEV_CHROMIUM_ID}/"));
        assert!(!caller_allowed(&dev, &[]));
        assert!(caller_allowed(
            &dev,
            &[format!("chrome-extension://{DEV_CHROMIUM_ID}/")]
        ));
        assert!(caller_allowed(&Caller::Firefox(FIREFOX_ID.into()), &[]));
        let store = Caller::Chromium("chrome-extension://abcdefghijklmnopabcdefghijklmnop/".into());
        assert!(!caller_allowed(&store, &[]));
        assert!(caller_allowed(
            &store,
            &["abcdefghijklmnopabcdefghijklmnop".to_owned()]
        ));
        assert!(caller_allowed(
            &store,
            &["chrome-extension://abcdefghijklmnopabcdefghijklmnop/".to_owned()]
        ));
        // Not an extension origin, even if listed.
        let odd = Caller::Chromium("chrome-extension://evil.example/".into());
        assert!(!caller_allowed(
            &odd,
            &["chrome-extension://evil.example/".to_owned()]
        ));
        assert!(!caller_allowed(
            &Caller::Firefox("other@example.com".into()),
            &[]
        ));
    }

    #[test]
    fn the_extension_only_reaches_its_operations() {
        let ok = |json: &str| to_daemon_line(json.as_bytes()).is_ok();
        let denied = |json: &str| {
            let err = to_daemon_line(json.as_bytes()).expect_err("refused");
            let response: ResponseEnvelope = serde_json::from_slice(&err).expect("response");
            (response.id, response.error.expect("error").code)
        };
        assert!(ok(r#"{"v":1,"id":1,"request":{"op":"status"}}"#));
        assert!(ok(
            r#"{"v":1,"id":2,"request":{"op":"suggest","url":"https://github.com/login"}}"#
        ));
        assert!(ok(
            r#"{"v":1,"id":3,"request":{"op":"autofill","item":"x","url":"https://a.example/","part":"totp"}}"#
        ));
        assert!(ok(
            r#"{"v":1,"id":4,"request":{"op":"create","item":{"kind":"login","title":"A"}}}"#
        ));
        assert!(ok(
            r#"{"v":1,"id":5,"request":{"op":"extension_attach","browser":"Chrome"}}"#
        ));
        assert!(ok(
            r#"{"v":1,"id":6,"request":{"op":"extension_reply","event":3,"ok":{"tab_id":1,"url":"https://a.example/"}}}"#
        ));
        // The master password for an agent's event (ADR 0041 §3.1).
        assert!(ok(
            r#"{"v":1,"id":6,"request":{"op":"extension_presence","event":3,"password":"pw"}}"#
        ));
        // The generator and the password histories (ADR 0022).
        for op in [
            r#"{"op":"generator_record","value":"x","host":"a.example"}"#,
            r#"{"op":"generator_history"}"#,
            r#"{"op":"generated_value","created_at":1}"#,
            r#"{"op":"generator_delete","which":"all"}"#,
            r#"{"op":"generator_delete","which":{"some":[1,2]}}"#,
            r#"{"op":"password_history","query":"GitHub"}"#,
            r#"{"op":"previous_password","query":"GitHub","index":0}"#,
            r#"{"op":"vault_health"}"#,
            // Passkeys (ADR 0020).
            r#"{"op":"passkey_candidates","origin":"https://a.example"}"#,
            r#"{"op":"passkey_get","origin":"https://a.example","challenge":"AAAA","item":"x"}"#,
            r#"{"op":"passkey_create","request":{"origin":"https://a.example","user_id":"AQ","user_name":"a","challenge":"AAAA"}}"#,
            // Task requests from the popup (ADR 0021).
            r#"{"op":"tasks","all":false}"#,
            r#"{"op":"decide_task","task":"abcdef","approve":true,"digest":"00","choice":{"without":[],"with":[]}}"#,
            r#"{"op":"add_to_task","approval":"abcdef","digest":"00"}"#,
            r#"{"op":"end_task","task":"abcdef"}"#,
            // The import wizard (ADR 0024).
            r#"{"op":"import_add","name":"a.csv","data":"YSxi","more":true}"#,
            r#"{"op":"import_add","session":"import-1","name":"a.csv","from":"chrome","data":"YSxi"}"#,
            r#"{"op":"import_preview","session":"import-1"}"#,
            r#"{"op":"import_apply","session":"import-1","vault":"Personal","project":"General"}"#,
            r#"{"op":"import_cancel","session":"import-1"}"#,
        ] {
            assert!(ok(&format!(r#"{{"v":1,"id":7,"request":{op}}}"#)), "{op}");
        }
        // Environments in the popup (ADR 0032 §6).
        for op in [
            r#"{"op":"environments"}"#,
            r#"{"op":"environment","project":"p","name":"production"}"#,
            r#"{"op":"environment_save","project":"p","name":"development","edit":{"set":[{"name":"A","value":"x"}]}}"#,
            r#"{"op":"environment_trash","project":"p","name":"development"}"#,
            r#"{"op":"resolve","references":["klav://a/b/c/D"],"variables_only":true}"#,
        ] {
            assert!(ok(&format!(r#"{{"v":1,"id":8,"request":{op}}}"#)), "{op}");
        }
        for op in [
            r#"{"op":"resolve","references":["klav://a/b/c/d"]}"#,
            r#"{"op":"resolve","references":["klav://a/b/c/d"],"variables_only":false}"#,
            r#"{"op":"resolve","references":["klav://a/b/c/D","klav://a/b/c/E"],"variables_only":true}"#,
            r#"{"op":"resolve","references":[],"variables_only":true}"#,
            r#"{"op":"environment_import_review","name":"development","variables":[["A","x"]]}"#,
            r#"{"op":"shutdown"}"#,
            r#"{"op":"agents"}"#,
            // The presence gate (ADR 0041): never `hold` (decision on Q3),
            // nor the presence setting, which is the CLI's and the app's.
            r#"{"op":"hold"}"#,
            r#"{"op":"presence_window"}"#,
            r#"{"op":"presence_window","window":"unlocked"}"#,
            // Only agents ask for tabs and fills, never the extension.
            r#"{"op":"browser_tab"}"#,
            r#"{"op":"browser_fill","tab":"1.2","host":"a.example","agent":"x","reason":"y","kind":"login","fields":[]}"#,
            r#"{"op":"revoke_agent","agent":"00000000-0000-0000-0000-000000000000"}"#,
            // Revoking and changing an agent's grant from the apps (ADR
            // 0033, amendment of 2026-11-10, F4): the popup has no grant
            // editor, and a compromised extension must neither widen nor
            // revoke.
            r#"{"op":"agent_revocations"}"#,
            r#"{"op":"grant_editor","agent":"00000000-0000-0000-0000-000000000000"}"#,
            r#"{"op":"grant_change_prepare","agent":"00000000-0000-0000-0000-000000000000","change":{"projects":["Personal/web"],"policy":{"rules":{"rules":[]}}}}"#,
            r#"{"op":"grant_change_apply","agent":"00000000-0000-0000-0000-000000000000","change":{"projects":["Personal/web"],"policy":{"rules":{"rules":[]}}},"digest":"00"}"#,
            // Pausing and resuming agents (ADR 0033 §7) are the CLI's and
            // the app's, like revocation.
            r#"{"op":"pause_agents"}"#,
            r#"{"op":"resume_agents"}"#,
            // The credential proxy (ADR 0036 §14) is the person's, at the
            // CLI or in the apps: not even its status reaches the page side.
            r#"{"op":"proxy_status"}"#,
            r#"{"op":"proxy_use","agent":"klav-proxy"}"#,
            r#"{"op":"proxy_grant_preview","item":"A","credential":{"profile":"p","upstream":"https://a.example","header":"authorization","methods":["GET"],"path_prefixes":["/"]}}"#,
            r#"{"op":"proxy_grant","item":"A","credential":{"profile":"p","upstream":"https://a.example","header":"authorization","methods":["GET"],"path_prefixes":["/"]},"base_version":0}"#,
            r#"{"op":"proxy_issuer_preview","agent":"t3","issuer":{"profiles":["p"],"url":"tls://a.example:443"}}"#,
            r#"{"op":"proxy_issuer_add","agent":"t3","issuer":{"profiles":["p"],"url":"tls://a.example:443"},"proxy_base_version":1,"issuer_base_version":0,"shown_issuer":"00000000-0000-0000-0000-000000000000","shown_proxy":"00000000-0000-0000-0000-000000000000"}"#,
            r#"{"op":"proxy_issuer_remove","agent":"t3"}"#,
            r#"{"op":"proxy_revoke","item":"A"}"#,
            // The person's sandboxes (ADR 0036 E2.1, E2.3): the list and
            // the revocation are the apps' and the CLI's, never the page's.
            r#"{"op":"sandbox_list"}"#,
            r#"{"op":"sandbox_list_flagged"}"#,
            r#"{"op":"sandbox_list_checked"}"#,
            r#"{"op":"sandbox_revoke","proxy":"6f1c2b8e-4d3a-4f5b-9c7d-1e2f3a4b5c6d","scope":"all"}"#,
            // Deleting the account is never the extension's (ADR 0037 §4):
            // not its Touch ID step, not cancelling it.
            r#"{"op":"confirm_presence","purpose":"delete_account"}"#,
            r#"{"op":"cancel_account_deletion"}"#,
            r#"{"op":"audit_log"}"#,
            r#"{"op":"audit_status"}"#,
            r#"{"op":"item_activity","item":"GitHub"}"#,
            // Forgetting the log's copy is a decision of trust: the
            // person's, at the terminal (ADR 0033 §8.4).
            r#"{"op":"audit_reset"}"#,
            r#"{"op":"task_log","task":"abcdef"}"#,
            r#"{"op":"create","item":{"kind":"login","title":"A","allow_duplicate":true}}"#,
            r#"{"op":"edit","query":"A","patch":{"title":"B","allow_duplicate":true}}"#,
        ] {
            let line = format!(r#"{{"v":1,"id":9,"request":{op}}}"#);
            assert_eq!(denied(&line), (9, ErrorCode::Denied), "{op}");
        }
        // Malformed input never echoes itself.
        let err = to_daemon_line(br#"{"v":1,"id":5,"request":{"op":"view","query":"MARKER"}}"#)
            .expect_err("missing reveal is malformed");
        assert!(!String::from_utf8_lossy(&err).contains("MARKER"));
        assert_eq!(
            denied(r#"{"v":1,"id":5,"request":{"op":"nope"}}"#).1,
            ErrorCode::BadRequest
        );
        assert_eq!(denied("not json").0, 0);
    }

    /// The extension's password unlock says what its question said
    /// (`shown`, ADR 0041 own choice 34) through the host; a notice it
    /// can't read is never asked for, whatever the extension sends.
    #[test]
    fn the_host_passes_shown_and_drops_notify() {
        let line = to_daemon_line(
            br#"{"v":1,"id":4,"request":{"op":"unlock","password":"pw"},"shown":"unlocked","notify":true}"#,
        )
        .expect("allowed");
        let envelope: RequestEnvelope = serde_json::from_slice(&line).expect("envelope");
        assert_eq!(envelope.shown, Some(crate::uv::Window::Unlocked));
        assert!(!envelope.notify);
        assert!(!envelope.untyped);
    }

    #[test]
    fn large_answers_become_errors_with_their_id() {
        let small = br#"{"v":1,"id":3,"ok":{}}
"#;
        assert_eq!(&*to_extension_message(small), &small[..small.len() - 1]);
        let big = format!(
            "{{\"v\":1,\"id\":4,\"ok\":\"{}\"}}\n",
            "x".repeat(MAX_OUT + 10)
        );
        let message = to_extension_message(big.as_bytes());
        let response: ResponseEnvelope = serde_json::from_slice(&message).unwrap();
        assert_eq!(response.id, 4);
        assert_eq!(response.error.unwrap().code, ErrorCode::Invalid);
    }

    #[test]
    fn the_hint_names_the_command_for_each_caller() {
        let dev = Caller::Chromium(format!("chrome-extension://{DEV_CHROMIUM_ID}/"));
        assert_eq!(install_hint(&dev), "klav extension install-host --dev");
        let store = Caller::Chromium("chrome-extension://abcdefghijklmnopabcdefghijklmnop/".into());
        assert_eq!(
            install_hint(&store),
            "klav extension install-host --extension-id abcdefghijklmnopabcdefghijklmnop"
        );
        assert_eq!(
            install_hint(&Caller::Firefox("other@example.com".into())),
            "klav extension install-host --extension-id other@example.com"
        );
        assert_eq!(
            install_hint(&Caller::Firefox(
                "{12345678-90ab-cdef-1234-567890abcdef}".into()
            )),
            "klav extension install-host --extension-id {12345678-90ab-cdef-1234-567890abcdef}"
        );
        // Nothing that would need quoting goes into the command.
        for odd in [
            Caller::Chromium("chrome-extension://evil.example/".into()),
            Caller::Chromium("chrome-extension://abc;rm -rf ~/".into()),
            Caller::Firefox("a@b;touch x".into()),
            Caller::Firefox("x'@y".into()),
            Caller::Firefox("no-at-sign".into()),
        ] {
            assert_eq!(
                install_hint(&odd),
                "klav extension install-host --extension-id ID",
                "{odd:?}"
            );
        }
    }

    /// The answers `refuse` wrote, one per frame.
    async fn answers(out: &[u8]) -> Vec<ResponseEnvelope> {
        let mut input = out;
        let mut list = Vec::new();
        while let Some(frame) = read_frame(&mut input).await.expect("frame") {
            list.push(serde_json::from_slice(&frame).expect("response"));
        }
        list
    }

    fn frame(body: &[u8]) -> Vec<u8> {
        let mut out = u32::try_from(body.len())
            .expect("len")
            .to_ne_bytes()
            .to_vec();
        out.extend_from_slice(body);
        out
    }

    #[tokio::test]
    async fn a_refused_caller_gets_the_command_and_nothing_else() {
        let dev = Caller::Chromium(format!("chrome-extension://{DEV_CHROMIUM_ID}/"));
        // Two requests: only the first is answered, and none of it comes back.
        let mut input =
            frame(br#"{"v":1,"id":42,"request":{"op":"unlock","password":"MARKER-secret"}}"#);
        input.extend(frame(br#"{"v":1,"id":43,"request":{"op":"status"}}"#));
        let mut out = Vec::new();
        refuse(&dev, &mut &input[..], &mut out).await.expect("io");
        assert!(!String::from_utf8_lossy(&out).contains("MARKER"));
        let list = answers(&out).await;
        assert_eq!(list.len(), 1);
        let answer = &list[0];
        assert_eq!((answer.v, answer.id), (PROTOCOL_VERSION, 42));
        assert!(answer.ok.is_none() && answer.warnings.is_empty());
        let error = answer.error.as_ref().expect("error");
        assert_eq!(error.code, ErrorCode::ExtensionNotAllowed);
        assert!(
            error
                .message
                .contains("`klav extension install-host --dev`"),
            "{}",
            error.message
        );
        // The code as the extension reads it.
        assert!(String::from_utf8_lossy(&out).contains(r#""code":"extension_not_allowed""#));

        // Another extension: its own ID. Not JSON: id 0.
        let store = Caller::Chromium("chrome-extension://abcdefghijklmnopabcdefghijklmnop/".into());
        let mut out = Vec::new();
        refuse(&store, &mut &frame(b"not json")[..], &mut out)
            .await
            .expect("io");
        let list = answers(&out).await;
        assert_eq!(list[0].id, 0);
        assert!(list[0].error.as_ref().expect("error").message.contains(
            "`klav extension install-host --extension-id abcdefghijklmnopabcdefghijklmnop`"
        ));
    }

    #[tokio::test]
    async fn a_refused_caller_without_a_request_gets_nothing() {
        let dev = Caller::Chromium(format!("chrome-extension://{DEV_CHROMIUM_ID}/"));
        // The port closed before any request.
        let mut out = Vec::new();
        refuse(&dev, &mut &b""[..], &mut out).await.expect("io");
        assert!(out.is_empty());
        // Too large: refused unread, no answer.
        let mut huge = (u32::try_from(MAX_IN).expect("len") + 1)
            .to_ne_bytes()
            .to_vec();
        huge.extend_from_slice(br#"{"v":1,"id":1}"#);
        let mut out = Vec::new();
        assert!(refuse(&dev, &mut &huge[..], &mut out).await.is_err());
        assert!(out.is_empty());
        // Cut short.
        let mut cut = frame(br#"{"v":1,"id":1,"request":{"op":"status"}}"#);
        cut.truncate(10);
        let mut out = Vec::new();
        assert!(refuse(&dev, &mut &cut[..], &mut out).await.is_err());
        assert!(out.is_empty());
    }

    #[tokio::test]
    async fn frames_are_length_prefixed_in_native_order() {
        let mut out = Vec::new();
        write_frame(&mut out, br#"{"a":1}"#).await.unwrap();
        assert_eq!(&out[..4], &7u32.to_ne_bytes());
        let mut input = &out[..];
        let frame = read_frame(&mut input).await.unwrap().unwrap();
        assert_eq!(&*frame, br#"{"a":1}"#);
        assert!(read_frame(&mut input).await.unwrap().is_none());
        let mut huge = (u32::try_from(MAX_IN).unwrap() + 1).to_ne_bytes().to_vec();
        huge.extend_from_slice(b"{}");
        assert!(read_frame(&mut &huge[..]).await.is_err());
    }
}
