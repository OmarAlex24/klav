//! The default server and the moves of its URL (ADR 0028).
//!
//! The default server is fixed in the binary: nothing is discovered (no
//! `/.well-known/`, no DNS record, no remote list), so no network answer
//! can point every client somewhere else (threat T110). Changing it takes
//! a new release. The same goes for [`MOVES`], the table of old URLs that
//! accounts are moved off when the new host proves it holds the same
//! account ([`crate::Unlocked::migrate_server`]).

use std::time::Duration;

use klav_core::crypto::invite::InviteCode;
use klav_proto::auth::{AccountKeyset, InviteCheckRequest};
use reqwest::{Method, StatusCode};

use crate::api::{self, Api};
use crate::error::{ClientError, ClientResult};
use crate::home::{Home, write_private};
use crate::session::Unlocked;
use crate::state::AccountFile;
use crate::url::ServerUrl;

/// The server every client uses unless told otherwise.
pub const DEFAULT_SERVER: &str = "https://api.klav.dev";

/// How the interface names the default server.
pub const DEFAULT_SERVER_NAME: &str = "klav.dev";

/// When set (to anything but empty or `0`), there is no default server:
/// a command without one fails as before ADR 0028. Test harnesses set it
/// so no test can reach production by forgetting `--server` (T110).
pub const NO_DEFAULT_SERVER_ENV: &str = "KLAV_NO_DEFAULT_SERVER";

/// Where self-hosting is explained (shown when registration is closed):
/// the public docs' guide (`apps/docs/src/content/docs/self-hosting/`).
pub const SELF_HOSTING_URL: &str = "https://docs.klav.dev/self-hosting/";

/// Old server URL → new one. Exact canonical URLs only: no wildcards and
/// no other `*.up.railway.app` (ADR 0028 §4).
pub const MOVES: &[(&str, &str)] = &[(
    "https://klav-server-production.up.railway.app",
    DEFAULT_SERVER,
)];

/// File in the home directory that remembers a move until `klav status`
/// reports it once. It is not a field of `account.json`: older clients
/// reject unknown fields there and would stop reading the account.
pub(crate) const MOVED_FILE: &str = "server-moved";

/// The default server, or `None` when [`NO_DEFAULT_SERVER_ENV`] is set.
pub fn default_server() -> Option<&'static str> {
    let off = std::env::var_os(NO_DEFAULT_SERVER_ENV)
        .is_some_and(|v| !v.is_empty() && v != "0" && v != "false");
    (!off).then_some(DEFAULT_SERVER)
}

/// Where `server` (a canonical URL) moved to in `moves`, if anywhere.
pub(crate) fn moved_in(moves: &[(&str, &str)], server: &str) -> Option<String> {
    moves
        .iter()
        .find(|(old, _)| *old == server)
        .map(|(_, new)| (*new).to_owned())
}

/// The URL to use for a server the person typed: validated, in canonical
/// form, and through [`MOVES`], so an old emergency kit still works.
pub fn resolve(text: &str) -> ClientResult<String> {
    let url = ServerUrl::parse(text)?;
    Ok(moved_in(MOVES, url.as_str()).unwrap_or_else(|| url.as_str().to_owned()))
}

/// The server a person typed in an app's «Use my own server» field:
/// `https://` added when missing, and `klav.dev`, `api.klav.dev` or a
/// URL of [`MOVES`] all mean [`DEFAULT_SERVER`].
pub fn from_input(text: &str) -> ClientResult<String> {
    let text = text.trim();
    let with_scheme = if text.contains("://") {
        text.to_owned()
    } else {
        format!("https://{text}")
    };
    let url = ServerUrl::parse(&with_scheme)?;
    let default_aliases = [
        format!("https://{DEFAULT_SERVER_NAME}"),
        DEFAULT_SERVER.to_owned(),
    ];
    if default_aliases.iter().any(|a| a == url.as_str()) {
        return Ok(DEFAULT_SERVER.to_owned());
    }
    resolve(url.as_str())
}

/// How the interface names `server`: «klav.dev» for the default, else
/// its host.
pub fn display_name(server: &str) -> String {
    if server == DEFAULT_SERVER {
        return DEFAULT_SERVER_NAME.to_owned();
    }
    reqwest::Url::parse(server)
        .ok()
        .and_then(|u| u.host_str().map(str::to_owned))
        .unwrap_or_else(|| server.to_owned())
}

/// Whether `server` accepts new accounts (`registration_open` in
/// `GET /v1/health`). `None` when the server does not say (older
/// servers): sign-up is tried and the server decides.
pub async fn registration_open(server: &str) -> ClientResult<Option<bool>> {
    let api = Api::new(ServerUrl::parse(server)?)?;
    let res = api
        .send::<()>(Method::GET, "/v1/health", None, None)
        .await?;
    let health: klav_proto::HealthResponse = api::json(res).await?;
    Ok(health.registration_open)
}

/// How a server takes new accounts, as a client reads it (ADR 0048 §1.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Registration {
    /// Anyone can sign up.
    Open,
    /// Signing up needs an invite code: check it with [`check_invite`]
    /// before the password, and send it with the sign-up.
    Invite,
    /// Nobody can sign up. Also a mode this client does not know (a newer
    /// server).
    Closed,
    /// The server says neither `registration_mode` nor `registration_open`
    /// (a server older than ADR 0028): sign-up is tried and the server
    /// decides.
    Unknown,
}

impl Registration {
    /// From a `GET /v1/health` answer: `registration_mode` first, then
    /// `registration_open` (an older server).
    pub fn from_health(health: &klav_proto::HealthResponse) -> Self {
        use klav_proto::RegistrationMode as Mode;
        match (health.registration_mode, health.registration_open) {
            (Some(Mode::Open), _) => Self::Open,
            (Some(Mode::Invite), _) => Self::Invite,
            // A mode from a newer server reads as closed (layer 1's choice).
            (Some(Mode::Closed | Mode::Unknown), _) => Self::Closed,
            (None, Some(true)) => Self::Open,
            (None, Some(false)) => Self::Closed,
            (None, None) => Self::Unknown,
        }
    }
}

/// How `server` takes new accounts (`GET /v1/health`, ADR 0048 §1.2). Asked
/// before any password or emergency kit.
pub async fn registration_mode(server: &str) -> ClientResult<Registration> {
    let api = Api::new(ServerUrl::parse(&resolve(server)?)?)?;
    let res = api
        .send::<()>(Method::GET, "/v1/health", None, None)
        .await?;
    let health: klav_proto::HealthResponse = api::json(res).await?;
    Ok(Registration::from_health(&health))
}

/// Whether `invite` can be used by `email` on `server` now
/// (`POST /v1/auth/invite/check`, ADR 0048 §1.3): `Ok` or
/// [`ClientError::InviteInvalid`]. Not a reservation: the sign-up checks it
/// again. A code that does not even decode is refused here, without
/// spending one of the server's invite attempts.
pub async fn check_invite(server: &str, email: &str, invite: &InviteCode) -> ClientResult<()> {
    if invite.canonical().is_err() {
        return Err(ClientError::InviteInvalid);
    }
    let api = Api::new(ServerUrl::parse(&resolve(server)?)?)?;
    let res = api
        .send(
            Method::POST,
            "/v1/auth/invite/check",
            None,
            Some(&InviteCheckRequest {
                email: email.trim().to_lowercase(),
                invite: invite.clone(),
            }),
        )
        .await?;
    api::empty(res).await
}

/// What a person told to bring an invite hears (ADR 0048 §2): `server`
/// takes new accounts only with one.
pub fn invite_required_message(server: &str) -> String {
    format!(
        "{} takes new accounts by invite only. Give your invite code, or request one at {INVITE_REQUEST_URL}.",
        display_name(server)
    )
}

/// Where a person asks for an invite (ADR 0048 §4).
pub const INVITE_REQUEST_URL: &str = "https://klav.dev";

/// The message shown when registration on `server` is closed, before any
/// password is asked (ADR 0028 §3).
pub fn registration_closed_message(server: &str) -> String {
    format!(
        "Registration on {} is not open yet. You can host your own server: {SELF_HOSTING_URL}",
        display_name(server)
    )
}

/// Remembers that the account moved off `old` (for `klav status`).
pub(crate) fn remember_move(home: &Home, old: &str) -> ClientResult<()> {
    write_private(&home.file(MOVED_FILE), format!("{old}\n").as_bytes())
}

/// The server the account moved off since the last call, if any. The note
/// is removed: `klav status` reports a move once.
pub fn take_move(home: &Home) -> Option<String> {
    let path = home.file(MOVED_FILE);
    let text = std::fs::read_to_string(&path).ok()?;
    let _ = std::fs::remove_file(&path);
    let old = text.trim();
    (!old.is_empty()).then(|| display_name(old))
}

/// How long the check on the new host may take: it runs while unlocking
/// or before a sync, and a host that does not answer must not hold them up.
const MOVE_CHECK_TIMEOUT: Duration = Duration::from_secs(5);

impl Unlocked {
    /// Moves the account off an old server URL of [`MOVES`] (ADR 0028 §4).
    ///
    /// Only when the new host, asked with the access token (never the
    /// refresh token) for `GET /v1/account`, answers with this same
    /// account ID and public identity, `account.json` is rewritten
    /// atomically with the new URL. Anything else (no network, `401`,
    /// another account) changes nothing, and the next load tries again.
    /// The cache, the high-water marks and the log head stay: they belong
    /// to the account, not to the host. Returns the new URL when it moved.
    pub async fn migrate_server(&mut self) -> Option<String> {
        self.migrate_server_with(MOVES).await
    }

    /// [`Unlocked::migrate_server`] with another table (tests only: the
    /// real table is fixed).
    #[doc(hidden)]
    pub async fn migrate_server_with(&mut self, moves: &[(&str, &str)]) -> Option<String> {
        let old = self.account.server.clone();
        let new = moved_in(moves, &old)?;
        let target = ServerUrl::parse(&new).ok()?;
        let check = async {
            // A fresh access token comes from the old host, which this
            // account already trusts.
            self.refresh_session().await.ok()?;
            let api = Api::new(target).ok()?;
            let res = api
                .send::<()>(Method::GET, "/v1/account", Some(&self.tokens.access), None)
                .await
                .ok()?;
            if res.status() != StatusCode::OK {
                return None;
            }
            let keyset: AccountKeyset = api::json(res).await.ok()?;
            (keyset.account_id == self.account.account_id
                && keyset.public_identity == self.account.public_identity)
                .then_some(api)
        };
        let api = tokio::time::timeout(MOVE_CHECK_TIMEOUT, check)
            .await
            .ok()
            .flatten()?;
        let _lock = self.home.lock().ok()?;
        // Another process may have moved (or changed) it meanwhile.
        let mut on_disk = AccountFile::load(&self.home).ok()?;
        if on_disk.account_id != self.account.account_id {
            return None;
        }
        if on_disk.server == old {
            on_disk.server = new.clone();
            on_disk.save(&self.home).ok()?;
            let _ = remember_move(&self.home, &old);
        } else if on_disk.server != new {
            return None;
        }
        self.account.server = new.clone();
        self.api = api;
        Some(new)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_table_is_one_exact_row() {
        assert_eq!(MOVES.len(), 1);
        assert_eq!(
            moved_in(MOVES, "https://klav-server-production.up.railway.app").as_deref(),
            Some(DEFAULT_SERVER)
        );
        for other in [
            "https://other.up.railway.app",
            "https://klav-server-production.up.railway.app/v1",
            "http://klav-server-production.up.railway.app",
            DEFAULT_SERVER,
        ] {
            assert_eq!(moved_in(MOVES, other), None, "{other}");
        }
    }

    #[test]
    fn typed_servers_go_through_the_table() {
        assert_eq!(
            resolve("https://klav-server-production.up.railway.app/").unwrap(),
            DEFAULT_SERVER
        );
        assert_eq!(
            resolve("https://vault.example.com/").unwrap(),
            "https://vault.example.com"
        );
        assert!(resolve("http://vault.example.com").is_err());
    }

    #[test]
    fn app_field_aliases_mean_the_default() {
        for alias in [
            "klav.dev",
            "api.klav.dev",
            "https://api.klav.dev/",
            " https://klav.dev ",
            "klav-server-production.up.railway.app",
        ] {
            assert_eq!(from_input(alias).unwrap(), DEFAULT_SERVER, "{alias}");
        }
        assert_eq!(
            from_input("vault.example.com").unwrap(),
            "https://vault.example.com"
        );
        assert_eq!(
            from_input("http://127.0.0.1:9000").unwrap(),
            "http://127.0.0.1:9000"
        );
    }

    #[test]
    fn names() {
        assert_eq!(display_name(DEFAULT_SERVER), "klav.dev");
        assert_eq!(
            display_name("https://klav-server-production.up.railway.app"),
            "klav-server-production.up.railway.app"
        );
        assert!(
            registration_closed_message(DEFAULT_SERVER).starts_with("Registration on klav.dev")
        );
    }

    #[test]
    fn the_mode_comes_first_and_registration_open_is_the_fallback() {
        let health = |json: &str| -> Registration {
            Registration::from_health(&serde_json::from_str(json).unwrap())
        };
        assert_eq!(
            health(
                r#"{"status":"ok","version":"0.10.0","registration_open":false,"registration_mode":"invite"}"#
            ),
            Registration::Invite
        );
        assert_eq!(
            health(
                r#"{"status":"ok","version":"0.10.0","registration_open":true,"registration_mode":"open"}"#
            ),
            Registration::Open
        );
        assert_eq!(
            health(
                r#"{"status":"ok","version":"0.10.0","registration_open":false,"registration_mode":"closed"}"#
            ),
            Registration::Closed
        );
        // A newer server's mode is closed to this client.
        assert_eq!(
            health(
                r#"{"status":"ok","version":"9.0.0","registration_open":false,"registration_mode":"waitlist"}"#
            ),
            Registration::Closed
        );
        // An older server: only `registration_open`, or nothing at all.
        assert_eq!(
            health(r#"{"status":"ok","version":"0.9.2","registration_open":true}"#),
            Registration::Open
        );
        assert_eq!(
            health(r#"{"status":"ok","version":"0.9.2","registration_open":false}"#),
            Registration::Closed
        );
        assert_eq!(
            health(r#"{"status":"ok","version":"0.1.0"}"#),
            Registration::Unknown
        );
        assert!(
            invite_required_message(DEFAULT_SERVER)
                .starts_with("klav.dev takes new accounts by invite only")
        );
    }

    #[test]
    fn signing_out_forgets_a_move() {
        // A later account on this device must not be told it moved.
        assert!(crate::auth::ACCOUNT_FILES.contains(&MOVED_FILE));
    }

    #[test]
    fn a_move_is_reported_once() {
        let dir = tempfile::tempdir().unwrap();
        let home = Home::at(dir.path().join("h"));
        home.ensure().unwrap();
        assert_eq!(take_move(&home), None);
        remember_move(&home, "https://klav-server-production.up.railway.app").unwrap();
        assert_eq!(
            take_move(&home).as_deref(),
            Some("klav-server-production.up.railway.app")
        );
        assert_eq!(take_move(&home), None);
    }
}
