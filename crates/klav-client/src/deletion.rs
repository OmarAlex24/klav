//! Deleting the account, from the person's side (ADR 0037).
//!
//! The person asks with the master password: the client runs the OPAQUE
//! exchange of a login again inside its session
//! (`POST /v1/account/delete/start` and `…/finish`), and the server
//! schedules the deletion 7 days later. Until then any device with a
//! session cancels it, and every agent is stopped. Face ID or Touch ID,
//! where Klav uses it, comes first and is the caller's (the apps, the CLI
//! through `klavd`): this module only checks the password.
//!
//! **Nothing here deletes a local copy.** Not a `401`, not the `deletion`
//! field, not the final notice: a malicious server could fake a deletion
//! to make every device drop its copy at once (T165). Each device offers
//! the person to delete its own copy, and only the person does.
//!
//! What this device knows of the deletion lives in its own sealed file,
//! [`DELETION_FILE`] (spec §12.2, purpose `deletion`), not in `cache.bin`:
//! an older klav, `klavd` or app reads `cache.bin` with a closed schema
//! and would refuse it with a field it does not know (review finding 5,
//! ADR 0037 A3). It survives restarts, also once the server no longer
//! answers.

use klav_core::crypto::CryptoError;
use klav_core::crypto::identity::{IdentityKeyPair, PublicIdentity, open_identity};
use klav_core::crypto::kdf::{KdfParams, MasterPassword, derive_account_keys};
use klav_core::crypto::keys::LocalKey;
use klav_core::crypto::local::derive_local_key;
use klav_core::crypto::local::{LocalContext, open_local_data, seal_local_data};
use klav_core::crypto::opaque::{self, OpaqueInput};
use klav_proto::Blob;
pub use klav_proto::auth::AccountDeletion;
use klav_proto::auth::{
    AccountDeleteFinishRequest, AccountDeleteStartRequest, AccountDeleteStartResponse,
};
use reqwest::{Method, StatusCode};
use serde::{Deserialize, Serialize};

use crate::api::{self, Api, Body};
use crate::auth::{open_rest, read_secret_key};
use crate::error::{ClientError, ClientResult};
use crate::home::{Home, write_private};
use crate::session::{Unlocked, now_ms};
use crate::state::AccountFile;
use crate::url::ServerUrl;

/// `$KLAV_HOME/deletion.bin`: what this device knows of the account's
/// deletion (ADR 0037 §3, A3). Sealed with the local key (spec §12.2,
/// purpose `deletion`); removed with the account. Absent: none asked.
pub const DELETION_FILE: &str = "deletion.bin";
/// The purpose of [`DELETION_FILE`]'s sealing (spec §12.2).
const PURPOSE_DELETION: &str = "deletion";
/// Format of [`DELETION_FILE`]'s contents.
const DELETION_VERSION: u32 = 1;

/// What this device knows of the account's deletion: asked for (with
/// when), and whether the server already deleted it (a `401` at or after
/// the date). Kept apart from the cache, in [`DELETION_FILE`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct DeletionMarker {
    /// The deletion the person asked for; kept after the deletion too.
    pub(crate) asked: Option<AccountDeletion>,
    /// The server no longer knows the session, and the date passed: the
    /// account is gone. Only with `asked`.
    pub(crate) deleted: bool,
}

/// [`DELETION_FILE`]'s contents.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeletionFile {
    v: u32,
    deletion: AccountDeletion,
    #[serde(default)]
    deleted: bool,
}

impl DeletionMarker {
    /// Reads [`DELETION_FILE`]. One that does not open (left by an earlier
    /// account on this device, damaged, a later format) reads as none: the
    /// next sync says again whether a deletion is asked for.
    pub(crate) fn load(home: &Home, key: &LocalKey, ctx: &LocalContext) -> Self {
        let Ok(blob) = std::fs::read(home.file(DELETION_FILE)) else {
            return Self::default();
        };
        open_local_data(key, ctx, PURPOSE_DELETION, &blob)
            .ok()
            .and_then(|json| serde_json::from_slice::<DeletionFile>(&json).ok())
            .filter(|f| f.v == DELETION_VERSION)
            .map_or_else(Self::default, |f| Self {
                asked: Some(f.deletion),
                deleted: f.deleted,
            })
    }

    /// Writes it to [`DELETION_FILE`]; none asked removes the file.
    pub(crate) fn save(&self, home: &Home, key: &LocalKey, ctx: &LocalContext) -> ClientResult<()> {
        let path = home.file(DELETION_FILE);
        let Some(deletion) = &self.asked else {
            return match std::fs::remove_file(&path) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.into()),
                _ => Ok(()),
            };
        };
        let json = serde_json::to_vec(&DeletionFile {
            v: DELETION_VERSION,
            deletion: deletion.clone(),
            deleted: self.deleted,
        })
        .expect("serializes");
        let blob = seal_local_data(key, ctx, PURPOSE_DELETION, &json)?;
        write_private(&path, &blob)
    }
}

/// Whether `server` lets the person delete the account from the apps and
/// the CLI (`account_deletion` in `GET /v1/health`, ADR 0037 §4). Asked
/// **before** Face ID, Touch ID or the password: an older server does not
/// say, and gets [`ClientError::DeletionUnsupported`] from the caller.
pub async fn supported(server: &str) -> ClientResult<bool> {
    let api = Api::new(ServerUrl::parse(server)?)?;
    let res = api
        .send::<()>(Method::GET, "/v1/health", None, None)
        .await?;
    let health: klav_proto::HealthResponse = api::json(res).await?;
    Ok(health.account_deletion == Some(true))
}

/// Checks `password` against this device's account, offline, and derives
/// the OPAQUE input with the same Argon2id run: a typo is caught here and
/// does not spend one of the server's attempts. The server still checks
/// it with OPAQUE (ADR 0037 §1).
fn opaque_input(
    home: &Home,
    account: &AccountFile,
    password: &MasterPassword,
) -> ClientResult<(LocalKey, OpaqueInput, IdentityKeyPair)> {
    let secret_key = read_secret_key(home)?;
    let params = KdfParams::decode(account.kdf_params.as_bytes())?;
    let (kek, input) = derive_account_keys(password, &secret_key, &params)?.into_parts();
    let public = PublicIdentity::decode(account.public_identity.as_bytes())?;
    let identity = open_identity(
        &kek,
        account.account_id,
        &public,
        account.sealed_identity.as_bytes(),
    )
    .map_err(|e| match e {
        CryptoError::Decryption => ClientError::WrongCredentials,
        other => other.into(),
    })?;
    let local_key = derive_local_key(&kek, &account.local_context());
    Ok((local_key, input, identity))
}

/// Asks to delete the account of `home` with the master password, from a
/// locked device (the CLI): one Argon2id run unlocks this device and
/// proves the password to the server. Returns the unlocked account, with
/// the deletion remembered in its cache, and the deletion.
pub async fn request_account_deletion(
    home: &Home,
    password: &MasterPassword,
) -> ClientResult<(Unlocked, AccountDeletion)> {
    let account = AccountFile::load(home)?;
    let (local_key, input, identity) = opaque_input(home, &account, password)?;
    let mut unlocked = open_rest(home, account, local_key, identity)?;
    let deletion = unlocked.delete_with(&input).await?;
    Ok((unlocked, deletion))
}

impl Unlocked {
    /// The deletion of the account the person asked for, as the last sync
    /// (or this device's own request) left it (ADR 0037 §3). Kept after
    /// the deletion, for its date.
    pub fn account_deletion(&self) -> Option<&AccountDeletion> {
        self.deletion.asked.as_ref()
    }

    /// When the account was deleted, if this device knew the date and it
    /// passed. Local only: the server is not asked, and a `401` from it is
    /// what turns this into [`ClientError::AccountDeleted`].
    pub fn deletion_due(&self) -> Option<i64> {
        self.deletion
            .asked
            .as_ref()
            .map(|d| d.delete_at)
            .filter(|at| *at <= now_ms())
    }

    /// The server deleted the account: this device knew the date, it
    /// passed, and the server no longer knew the session (ADR 0037 §3).
    /// Kept across restarts, so a device offline since still knows. The
    /// copy stays, read-only, until the person deletes it (T165).
    pub fn account_deleted(&self) -> bool {
        self.deletion.deleted
    }

    /// Asks to delete the account (ADR 0037 §1): checks the master password
    /// here, then proves it to the server with OPAQUE, which schedules the
    /// deletion for 7 days later. Face ID or Touch ID, where Klav uses it,
    /// is the caller's, before this.
    ///
    /// A wrong password is [`ClientError::WrongCredentials`] and keeps the
    /// session. One already scheduled is a `409`.
    pub async fn request_account_deletion(
        &mut self,
        password: &MasterPassword,
    ) -> ClientResult<AccountDeletion> {
        let (_, input, _) = opaque_input(&self.home, &self.account, password)?;
        self.delete_with(&input).await
    }

    /// The two OPAQUE round trips, in this session.
    async fn delete_with(&mut self, input: &OpaqueInput) -> ClientResult<AccountDeletion> {
        let (client, ke1) = opaque::client_start_login(input)?;
        let res = self
            .authed(
                Method::POST,
                "/v1/account/delete/start",
                &Body::json(&AccountDeleteStartRequest {
                    credential_request: Blob::new(ke1),
                })?,
            )
            .await?;
        refused(&res)?;
        let start: AccountDeleteStartResponse = api::json(res).await?;
        // The server's half does not verify with our password: it is not
        // the server this account signed up with (or not this account).
        let ke3 = client
            .finish(input, start.credential_response.as_bytes())
            .map_err(|_| ClientError::WrongCredentials)?;
        let res = self
            .authed(
                Method::POST,
                "/v1/account/delete/finish",
                &Body::json(&AccountDeleteFinishRequest {
                    handle: start.handle,
                    credential_finalization: Blob::new(ke3),
                })?,
            )
            .await?;
        refused(&res)?;
        let deletion: AccountDeletion = api::json(res).await?;
        // Scheduled on the server whatever happens next: a failure to
        // record it here must say so, or a retry gets «already scheduled»
        // and reads as a second failure (review finding 7).
        self.remember_deletion(Some(deletion.clone()))
            .map_err(|e| ClientError::DeletionNotRecorded {
                scheduled: Some(deletion.delete_at),
                why: e.to_string(),
            })?;
        Ok(deletion)
    }

    /// Cancels the deletion of the account, from any device with a
    /// session (ADR 0037 P8): no password. `false` when there was none to
    /// cancel (canceled meanwhile from another device, or never asked).
    pub async fn cancel_account_deletion(&mut self) -> ClientResult<bool> {
        let res = self
            .authed(Method::POST, "/v1/account/delete/cancel", &Body::Empty)
            .await?;
        let canceled = match res.status() {
            StatusCode::NO_CONTENT => true,
            StatusCode::NOT_FOUND => false,
            _ => return Err(api::error(res).await),
        };
        self.remember_deletion(None)
            .map_err(|e| ClientError::DeletionNotRecorded {
                scheduled: None,
                why: e.to_string(),
            })?;
        Ok(canceled)
    }
}

/// The answers of `start` and `finish` that are not the server's error:
/// no such route on an older server, a deletion already scheduled
/// (`409`), and the deletion's limits (`429`, ADR 0037 §5.6). The apps
/// say each in their own words.
fn refused(res: &reqwest::Response) -> ClientResult<()> {
    match res.status() {
        StatusCode::NOT_FOUND => Err(ClientError::DeletionUnsupported),
        StatusCode::CONFLICT => Err(ClientError::DeletionAlreadyScheduled),
        StatusCode::TOO_MANY_REQUESTS => Err(ClientError::DeletionRateLimited),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use klav_core::ids::{AccountId, DeviceId};

    use super::*;

    fn deletion() -> AccountDeletion {
        AccountDeletion {
            requested_at: 1_000,
            delete_at: 2_000,
            device_id: DeviceId::generate(),
            device_name: "laptop".into(),
        }
    }

    fn ctx() -> LocalContext {
        LocalContext {
            account: AccountId::generate(),
            device: DeviceId::generate(),
        }
    }

    #[test]
    fn the_marker_survives_a_restart_and_none_removes_it() {
        let dir = tempfile::tempdir().unwrap();
        let home = Home::at(dir.path());
        let (key, ctx) = (LocalKey::generate(), ctx());
        assert_eq!(
            DeletionMarker::load(&home, &key, &ctx),
            DeletionMarker::default()
        );
        let marker = DeletionMarker {
            asked: Some(deletion()),
            deleted: true,
        };
        marker.save(&home, &key, &ctx).unwrap();
        assert_eq!(DeletionMarker::load(&home, &key, &ctx), marker);
        DeletionMarker::default().save(&home, &key, &ctx).unwrap();
        assert!(!home.file(DELETION_FILE).exists());
        // Removing a file that is not there is fine.
        DeletionMarker::default().save(&home, &key, &ctx).unwrap();
    }

    #[test]
    fn a_marker_that_does_not_open_reads_as_none() {
        let dir = tempfile::tempdir().unwrap();
        let home = Home::at(dir.path());
        let (key, ctx) = (LocalKey::generate(), ctx());
        let marker = DeletionMarker {
            asked: Some(deletion()),
            deleted: false,
        };
        marker.save(&home, &key, &ctx).unwrap();
        // Another account (or device) on this home, or another key.
        assert_eq!(
            DeletionMarker::load(&home, &key, &super::tests::ctx()),
            DeletionMarker::default()
        );
        assert_eq!(
            DeletionMarker::load(&home, &LocalKey::generate(), &ctx),
            DeletionMarker::default()
        );
        // Sealed with the cache's purpose: not a marker.
        let cache = seal_local_data(&key, &ctx, "cache", b"{}").unwrap();
        std::fs::write(home.file(DELETION_FILE), cache).unwrap();
        assert_eq!(
            DeletionMarker::load(&home, &key, &ctx),
            DeletionMarker::default()
        );
        std::fs::write(home.file(DELETION_FILE), b"garbage").unwrap();
        assert_eq!(
            DeletionMarker::load(&home, &key, &ctx),
            DeletionMarker::default()
        );
    }
}
