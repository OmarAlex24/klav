//! Claims (ADR 0036 §5, E3.3; layer 6): a forwarder proves it holds a
//! sandbox's one-time secret over the pinned channel, and from then on the
//! sandbox answers only to the channel key that claimed it.
//!
//! - **The order.** The proxy writes the channel key down (the channels
//!   file, before anything else), asks the server to log `sandbox.claimed`
//!   with the key's SHA-256, and only then counts the secret as spent. If
//!   the server refuses the first attempt (a pause, an ended sandbox),
//!   nothing was logged: the record goes and the secret is not spent. If
//!   the answer is lost, the record stays, and only the same key may try
//!   again: the server may have logged it. From then on the record stays
//!   until the sandbox ends, even when a retry is refused: a refusal of
//!   the retry says nothing about the attempt whose answer was lost.
//! - **`409 sandbox_claimed`** means the server holds a claim. For a key
//!   already on record it is that key's own lost claim. For a key recorded
//!   by this very attempt, the server holds a claim from a key the proxy
//!   has no record of (a lost channels file): theft, as below.
//! - **The theft signal.** The right secret from another key, once a key is
//!   on record, means two holders of the secret: the proxy ends the sandbox
//!   with `theft`. A claim the server may not have logged yet is sent
//!   first, with the key that made it (the server takes `theft` only after
//!   a claim). Neither claimer is told which one lost. The push to the
//!   person comes with migration 0019 (layer 5a).
//! - **The channels file** (`<name>.sandbox-channels`, 0600, replaced
//!   atomically) is apart from the store, so the store keeps the format a
//!   proxy from before layer 6 reads. It holds the SHA-256 of each channel
//!   key, never a key or a secret, and the thefts the proxy could not
//!   confirm the server logged ([`UnconfirmedTheft`]).
//!
//! A wrong secret, an unknown sandbox and an ended one get the same
//! answer, so the channel tells nobody which sandboxes exist.

use std::path::{Path, PathBuf};

use klav_client::ClientError;
use klav_core::crypto::sandbox::{SECRET_LEN, SandboxSecret, secret_matches};
use klav_core::ids::SandboxId;
use klav_proto::Blob;
use klav_proto::ErrorCode;
use klav_proto::sandbox::{SUFFIX_CLAIMED, SandboxClaimed, SandboxEnd, sandbox_path};
use serde::{Deserialize, Serialize};

use crate::proxy::ProxyState;
use crate::sandboxes::{Outgoing, Sandboxes, StoreFile, flush, outcome_unknown};

/// The channels file's extension, next to the store.
pub const CHANNELS_EXTENSION: &str = "sandbox-channels";
/// Version of the channels file.
pub const CHANNELS_VERSION: u8 = 1;
/// How many unconfirmed thefts the file keeps (the oldest go).
pub const MAX_UNCONFIRMED_THEFTS: usize = 32;

/// The channel key of a sandbox.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Channel {
    /// The sandbox.
    pub sandbox_id: SandboxId,
    /// SHA-256 of the channel key's SPKI.
    pub channel_key_sha256: Blob,
    /// Whether the server logged the claim (`sandbox.claimed`). Until it
    /// does, only this key may claim again.
    pub logged: bool,
}

/// A `theft` end the proxy could not confirm the server logged: when it
/// was sent, the server refused it, or the claim it needs, as already over
/// (expired, its issuer removed, ended), or did not know the sandbox. That
/// answer is the same whether the server never got the theft or got it
/// and the proxy lost the answer, so the person's log may or may not show
/// it. The proxy keeps it here and `klav-proxy status` shows it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnconfirmedTheft {
    /// The sandbox.
    pub sandbox_id: SandboxId,
    /// When the proxy gave up sending it (Unix ms, the proxy's clock).
    pub dropped_at: i64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChannelsFile {
    v: u8,
    channels: Vec<Channel>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    unconfirmed_thefts: Vec<UnconfirmedTheft>,
}

/// What the channels file holds.
#[derive(Default)]
pub struct ChannelsOnDisk {
    /// The channel keys.
    pub channels: Vec<Channel>,
    /// The thefts the proxy could not confirm the server logged.
    pub unconfirmed_thefts: Vec<UnconfirmedTheft>,
}

/// The channels file next to the store at `store`.
pub fn path_of(store: &Path) -> PathBuf {
    store.with_extension(CHANNELS_EXTENSION)
}

/// Reads the channels file, or none when it is missing. Refuses one it
/// cannot read, as the store does: a forgotten key could let another one
/// claim.
pub fn load(path: &Path) -> Result<ChannelsOnDisk, String> {
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(ChannelsOnDisk::default());
        }
        Err(e) => return Err(format!("sandbox channels {}: {e}", path.display())),
        Ok(_) => {}
    }
    crate::app::check_key_file(path).map_err(|e| {
        e.to_string()
            .replace("key file", "sandbox channels file")
            .replace("the key", "the file")
    })?;
    let bytes =
        std::fs::read(path).map_err(|e| format!("sandbox channels {}: {e}", path.display()))?;
    let file: ChannelsFile = serde_json::from_slice(&bytes).map_err(|_| {
        format!(
            "sandbox channels {} cannot be read; klav-proxy does not start over on its own. Move it away together with the sandbox store to start with no sandboxes",
            path.display()
        )
    })?;
    if file.v != CHANNELS_VERSION {
        return Err(format!(
            "sandbox channels {} is version {}, and this klav-proxy reads version {CHANNELS_VERSION}",
            path.display(),
            file.v
        ));
    }
    Ok(ChannelsOnDisk {
        channels: file.channels,
        unconfirmed_thefts: file.unconfirmed_thefts,
    })
}

/// Writes the channels file (0600, replaced atomically).
pub fn save(
    path: &Path,
    channels: &[Channel],
    unconfirmed_thefts: &[UnconfirmedTheft],
) -> Result<(), String> {
    let bytes = serde_json::to_vec(&ChannelsFile {
        v: CHANNELS_VERSION,
        channels: channels.to_vec(),
        unconfirmed_thefts: unconfirmed_thefts.to_vec(),
    })
    .map_err(|e| e.to_string())?;
    klav_client::home::write_private(path, &bytes).map_err(|e| e.to_string())
}

/// What a claim or a call over the channel gets instead of an answer: the
/// sandbox's part of ADR 0036 §10.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelError {
    /// Unknown, ended, wrong secret, or a key it is not bound to.
    Revoked,
    /// The sandbox this key was bound to ended, and why (said to that key
    /// only: [`crate::sandboxes::StoreFile::end_of`]). A theft is said
    /// alike to both claimers: neither learns which one lost.
    Ended(SandboxEnd),
    /// Past its `expires_at`.
    Expired,
    /// The person paused the agents.
    AgentsPaused,
    /// The proxy cannot reach the server, or does not know whether the
    /// server logged the claim: try again with the same key.
    ServerUnreachable,
    /// Another claim of this sandbox waits for the server.
    Busy,
    /// The server refused the proxy.
    ServerDenied,
    /// The server has no route for sandboxes' claims (a plain `404`): it is
    /// older than this proxy.
    ServerTooOld,
    /// The proxy could not save the claim or the end.
    Store,
    /// Not a claim request.
    BadRequest,
    /// A claim's body over [`crate::channel::MAX_CLAIM_BODY`].
    TooLarge,
}

/// A sandbox bound to a channel key, as a call over the channel sees it.
#[derive(Debug, Clone, Serialize)]
pub struct Bound {
    /// Its ID.
    pub sandbox_id: SandboxId,
    /// The label its issuer gave it.
    pub label: String,
    /// Its profiles: the only ones its calls may use.
    pub profiles: Vec<String>,
    /// When it ends (Unix ms).
    pub expires_at: i64,
}

impl Bound {
    fn of(s: &crate::sandboxes::Stored) -> Self {
        Self {
            sandbox_id: s.sandbox_id,
            label: s.label.clone(),
            profiles: s.profiles.clone(),
            expires_at: s.expires_at,
        }
    }
}

/// The live sandbox bound to `key` (a logged claim), counting the call
/// toward its activity.
pub async fn bound(state: &ProxyState, key: &[u8; 32]) -> Result<Bound, ChannelError> {
    let sandboxes = state.sandboxes();
    let mut store = sandboxes.store.lock().await;
    let now = sandboxes.now();
    // Only the key the handshake proved, never a sandbox ID it names: a key
    // that was never bound gets the same answer as before.
    let gone = |store: &crate::sandboxes::StoreFile| {
        store
            .end_of(key)
            .map_or(ChannelError::Revoked, ChannelError::Ended)
    };
    let Some(id) = store
        .channels
        .iter()
        .find(|c| c.logged && c.channel_key_sha256.as_bytes() == key.as_slice())
        .map(|c| c.sandbox_id)
    else {
        return Err(gone(&store));
    };
    let Some(s) = store
        .sandboxes
        .iter()
        .find(|s| s.sandbox_id == id && s.claimed_at.is_some())
    else {
        return Err(gone(&store));
    };
    if s.expires_at <= now {
        return Err(ChannelError::Expired);
    }
    let found = Bound::of(s);
    store.last_seen.insert(id, now);
    store.ever_bound.insert(*key);
    Ok(found)
}

/// Where a channel key stands, for the channel's connection limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyState {
    /// Bound to a live sandbox.
    Live,
    /// Bound to a sandbox since the proxy started, and that sandbox is no
    /// longer live (stopped, revoked, expired, ended).
    Ended,
    /// Never bound since the proxy started.
    Never,
}

/// Where `key` stands, without counting it as activity.
pub async fn key_state(state: &ProxyState, key: &[u8; 32]) -> KeyState {
    if is_bound(state, key).await {
        return KeyState::Live;
    }
    if state
        .sandboxes()
        .store
        .lock()
        .await
        .ever_bound
        .contains(key)
    {
        KeyState::Ended
    } else {
        KeyState::Never
    }
}

/// Whether `key` is bound to a live sandbox, without counting it as
/// activity (the channel's connection limits).
pub async fn is_bound(state: &ProxyState, key: &[u8; 32]) -> bool {
    let sandboxes = state.sandboxes();
    let mut store = sandboxes.store.lock().await;
    let now = sandboxes.now();
    let live = store
        .channels
        .iter()
        .find(|c| c.logged && c.channel_key_sha256.as_bytes() == key.as_slice())
        .and_then(|c| {
            store
                .sandboxes
                .iter()
                .find(|s| s.sandbox_id == c.sandbox_id && s.claimed_at.is_some())
        })
        .is_some_and(|s| s.expires_at > now);
    if live {
        store.ever_bound.insert(*key);
    }
    live
}

/// What to do with a claim, decided under the store lock.
enum Step {
    /// Already bound to this key.
    Done(Bound),
    /// Ask the server to log the claim of this key; `fresh` when this
    /// attempt put the key on record.
    Log { fresh: bool },
    /// Two keys hold the secret.
    Theft,
}

/// Claims `sandbox` with `secret` for the channel key `key` (the SHA-256
/// of its SPKI, as the TLS handshake proved it).
pub async fn claim(
    state: &ProxyState,
    sandbox: SandboxId,
    secret: &SandboxSecret,
    key: [u8; 32],
) -> Result<Bound, ChannelError> {
    let sandboxes = state.sandboxes();
    let step = {
        let mut store = sandboxes.store.lock().await;
        let now = sandboxes.now();
        let s = store
            .sandboxes
            .iter()
            .find(|s| s.sandbox_id == sandbox)
            .ok_or(ChannelError::Revoked)?;
        let digest: [u8; 32] = s
            .secret_sha256
            .as_bytes()
            .try_into()
            .map_err(|_| ChannelError::Revoked)?;
        if !secret_matches(&digest, sandbox, secret) {
            return Err(ChannelError::Revoked);
        }
        if s.expires_at <= now {
            return Err(ChannelError::Expired);
        }
        let view = Bound::of(s);
        let claimed = s.claimed_at.is_some();
        if store.claiming.contains(&sandbox) {
            return Err(ChannelError::Busy);
        }
        let record = store.channels.iter().find(|c| c.sandbox_id == sandbox);
        // One channel key, one sandbox (ADR 0036 §5: `klav-forward up`
        // makes a key for the one package it holds). A key on record for
        // another sandbox may not claim this one: `bound` would find either
        // record, and a call authorised for one would run as the other
        // (review of #304/#306, follow-up 1). Only for a sandbox with no key
        // on record: the right secret when one is (or after the file was
        // lost) is still theft, decided below.
        let elsewhere = store
            .channels
            .iter()
            .any(|c| c.sandbox_id != sandbox && c.channel_key_sha256.as_bytes() == key.as_slice());
        let step = match record {
            Some(c) if c.channel_key_sha256.as_bytes() != key.as_slice() => Step::Theft,
            Some(c) if c.logged && claimed => Step::Done(view),
            Some(_) => Step::Log { fresh: false },
            // Claimed with no key on record: the channels file was lost.
            // Which key the server logged is unknown, so no key can be
            // trusted to be it.
            None if claimed => Step::Theft,
            // The secret is not spent. It is said aloud, with the sandbox
            // alone: the right secret came from a key that serves another
            // sandbox, which a forwarder never does (review of #313).
            None if elsewhere => {
                tracing::warn!(sandbox = %sandbox, "the right secret from a key bound to another sandbox: claim refused, the secret is not spent");
                return Err(ChannelError::Revoked);
            }
            None => {
                store.channels.push(Channel {
                    sandbox_id: sandbox,
                    channel_key_sha256: Blob::new(key.to_vec()),
                    logged: false,
                });
                if let Err(e) = sandboxes.save_channels(&store) {
                    tracing::error!(error = %e, "could not save the sandbox channels");
                    store.channels.retain(|c| c.sandbox_id != sandbox);
                    return Err(ChannelError::Store);
                }
                Step::Log { fresh: true }
            }
        };
        if matches!(step, Step::Log { .. }) {
            store.claiming.push(sandbox);
        }
        step
    };
    match step {
        Step::Done(view) => {
            sandboxes
                .store
                .lock()
                .await
                .last_seen
                .insert(sandbox, sandboxes.now());
            Ok(view)
        }
        Step::Theft => theft(state, sandbox).await,
        Step::Log { fresh } => log_claim(state, sandbox, key, fresh).await,
    }
}

/// Two holders of the secret: ends the sandbox with `theft`.
async fn theft(state: &ProxyState, sandbox: SandboxId) -> Result<Bound, ChannelError> {
    tracing::warn!(sandbox = %sandbox, "a second claim with the right secret: the sandbox ends with theft");
    end(state, sandbox, SandboxEnd::Theft).await;
    // Only a holder of the secret gets here, and it gets the words the key
    // on record gets: neither learns which claim came first.
    Err(ChannelError::Ended(SandboxEnd::Theft))
}

/// Asks the server to log the claim, then binds it or forgets it. `fresh`
/// when this attempt put the key on record.
async fn log_claim(
    state: &ProxyState,
    sandbox: SandboxId,
    key: [u8; 32],
    fresh: bool,
) -> Result<Bound, ChannelError> {
    let sandboxes = state.sandboxes();
    #[cfg(test)]
    state.before_claim_log().await;
    let logged = post_claim(state, sandbox, key).await;
    let mut store = sandboxes.store.lock().await;
    store.claiming.retain(|id| *id != sandbox);
    let now = sandboxes.now();
    match logged {
        // The server holds a claim, and no key but this one was ever
        // recorded for this sandbox before this attempt: the claim it holds
        // is from a key the proxy has no record of.
        Err(ClientError::Api {
            code: Some(ErrorCode::SandboxClaimed),
            ..
        }) if fresh => {
            store.channels.retain(|c| c.sandbox_id != sandbox);
            if let Some(s) = store.sandboxes.iter_mut().find(|s| s.sandbox_id == sandbox) {
                // Claimed on the server: `theft` goes straight to the end.
                s.claimed_at = Some(now);
            }
            save_both(sandboxes, &store);
            drop(store);
            theft(state, sandbox).await
        }
        Ok(())
        | Err(ClientError::Api {
            code: Some(ErrorCode::SandboxClaimed),
            ..
        }) => {
            for c in store
                .channels
                .iter_mut()
                .filter(|c| c.sandbox_id == sandbox)
            {
                c.logged = true;
            }
            let Some(s) = store.sandboxes.iter_mut().find(|s| s.sandbox_id == sandbox) else {
                // Ended while the server logged it: its end is on its way.
                save_both(sandboxes, &store);
                return Err(ChannelError::Revoked);
            };
            s.claimed_at = Some(now);
            let view = Bound::of(s);
            store.last_seen.insert(sandbox, now);
            store.ever_bound.insert(key);
            if !save_both(sandboxes, &store) {
                // The server has the claim, and only this key is on record:
                // the forwarder's retry with it finds the claim done.
                return Err(ChannelError::Store);
            }
            tracing::info!(sandbox = %sandbox, "sandbox claimed");
            Ok(view)
        }
        Err(e) if outcome_unknown(&e) => {
            tracing::warn!(sandbox = %sandbox, kind = crate::proxy::redacted_kind(&e), "the server did not answer a claim; only the same key may claim again");
            Err(ChannelError::ServerUnreachable)
        }
        Err(e) => {
            if fresh {
                // The server answered the first attempt and logged nothing:
                // the secret is not spent, and the key is forgotten.
                store.channels.retain(|c| c.sandbox_id != sandbox);
                if let Err(e) = sandboxes.save_channels(&store) {
                    tracing::error!(error = %e, "could not save the sandbox channels");
                }
            }
            // A retry: an earlier attempt of this key may be logged, so the
            // key stays on record and no other key may claim.
            tracing::info!(sandbox = %sandbox, kind = crate::proxy::redacted_kind(&e), retry = !fresh, "the server refused a claim");
            Err(refused(&e))
        }
    }
}

/// The server's `claimed`. A `409 sandbox_claimed` comes back as it is:
/// whether it is this key's claim depends on whether the key was already
/// on record ([`log_claim`]).
pub(crate) async fn post_claim(
    state: &ProxyState,
    sandbox: SandboxId,
    key: [u8; 32],
) -> Result<(), ClientError> {
    let path = sandbox_path(sandbox, SUFFIX_CLAIMED);
    state
        .post_signed(
            &path,
            &SandboxClaimed {
                channel_key_sha256: Blob::new(key.to_vec()),
            },
        )
        .await
}

/// Before an end is sent: logs a claim on record the server may not have,
/// with its own key (`theft` and `released` need a claim logged). Nothing
/// to do without one.
pub(crate) async fn log_pending_claim(
    state: &ProxyState,
    sandbox: SandboxId,
) -> Result<(), ClientError> {
    let sandboxes = state.sandboxes();
    let key = {
        let store = sandboxes.store.lock().await;
        let pending = store
            .channels
            .iter()
            .find(|c| c.sandbox_id == sandbox && !c.logged)
            .and_then(|c| <[u8; 32]>::try_from(c.channel_key_sha256.as_bytes()).ok());
        match pending {
            // Its claim is with the server right now: the end waits.
            Some(_) if store.claiming.contains(&sandbox) => {
                return Err(ClientError::Network(
                    "a claim of this sandbox waits for the server".into(),
                ));
            }
            Some(key) => key,
            None => return Ok(()),
        }
    };
    match post_claim(state, sandbox, key).await {
        // The key was on record before any claim was sent, and only it is
        // ever sent for this sandbox: the claim the server has is this one.
        Ok(())
        | Err(ClientError::Api {
            code: Some(ErrorCode::SandboxClaimed),
            ..
        }) => {}
        Err(e) => return Err(e),
    }
    let mut store = sandboxes.store.lock().await;
    for c in store
        .channels
        .iter_mut()
        .filter(|c| c.sandbox_id == sandbox)
    {
        c.logged = true;
    }
    if let Err(e) = sandboxes.save_channels(&store) {
        tracing::error!(error = %e, "could not save the sandbox channels");
    }
    Ok(())
}

/// Ends the sandbox bound to `key` with `released` (its forwarder let it
/// go). Returns whether the server already has the end.
pub async fn release(state: &ProxyState, key: &[u8; 32]) -> Result<bool, ChannelError> {
    let found = bound(state, key).await?;
    if !end(state, found.sandbox_id, SandboxEnd::Released).await {
        return Err(ChannelError::Store);
    }
    let logged = !state
        .sandboxes()
        .store
        .lock()
        .await
        .outbox
        .iter()
        .any(|o| o.sandbox_id == found.sandbox_id);
    tracing::info!(sandbox = %found.sandbox_id, logged, "sandbox released");
    Ok(logged)
}

/// Ends a live sandbox here at once and sends the end. `false` if the end
/// could not be saved (it stays live, as the store on disk says).
async fn end(state: &ProxyState, sandbox: SandboxId, reason: SandboxEnd) -> bool {
    let sandboxes = state.sandboxes();
    {
        let mut store = sandboxes.store.lock().await;
        let Some(at) = store.sandboxes.iter().position(|s| s.sandbox_id == sandbox) else {
            return true;
        };
        let ended = store.sandboxes.remove(at);
        store.outbox.push(Outgoing {
            sandbox_id: sandbox,
            reason,
            at: None,
        });
        if let Err(e) = sandboxes.save(&store) {
            tracing::error!(error = %e, "could not save the sandbox store");
            store.outbox.pop();
            store.sandboxes.insert(at, ended);
            return false;
        }
        store.note_end(sandbox, reason);
        store.last_seen.remove(&sandbox);
        tracing::info!(sandbox = %sandbox, reason = reason.as_str(), "sandbox ended");
    }
    flush(state).await;
    true
}

fn save_both(sandboxes: &Sandboxes, store: &StoreFile) -> bool {
    let mut ok = true;
    if let Err(e) = sandboxes.save_channels(store) {
        tracing::error!(error = %e, "could not save the sandbox channels");
        ok = false;
    }
    if let Err(e) = sandboxes.save(store) {
        tracing::error!(error = %e, "could not save the sandbox store");
        ok = false;
    }
    ok
}

/// The secret of a claim: exactly [`SECRET_LEN`] bytes.
pub fn secret_from(bytes: &[u8]) -> Option<SandboxSecret> {
    let fixed: &[u8; SECRET_LEN] = bytes.try_into().ok()?;
    Some(SandboxSecret::from_bytes(fixed))
}

/// What a forwarder gets when the server refused its claim.
fn refused(e: &ClientError) -> ChannelError {
    match e {
        ClientError::Paused(_) => ChannelError::AgentsPaused,
        ClientError::Api {
            code: Some(ErrorCode::SandboxRevoked | ErrorCode::SandboxNotFound),
            ..
        } => ChannelError::Revoked,
        // No route at all: a server from before layer 5.
        ClientError::Api {
            status: 404,
            code: None,
            ..
        } => ChannelError::ServerTooOld,
        _ => ChannelError::ServerDenied,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn api(status: u16, code: Option<ErrorCode>) -> ClientError {
        ClientError::Api {
            status,
            code,
            message: String::new(),
            current_version: None,
        }
    }

    /// Review of #304: a plain `404` on `claimed` is a server older than
    /// the proxy, never "the person may have revoked it".
    #[test]
    fn a_server_without_the_claim_route_is_called_older() {
        assert_eq!(refused(&api(404, None)), ChannelError::ServerTooOld);
        assert_eq!(
            refused(&api(404, Some(ErrorCode::SandboxNotFound))),
            ChannelError::Revoked
        );
        assert_eq!(
            refused(&api(403, Some(ErrorCode::Forbidden))),
            ChannelError::ServerDenied
        );
        let answer = crate::channel::refusal_of(ChannelError::ServerTooOld);
        assert_eq!(answer.0, 403);
        assert_eq!(answer.1, "klav_not_allowed");
        assert!(
            answer.2.contains("older than this credential proxy"),
            "{}",
            answer.2
        );
    }
}
