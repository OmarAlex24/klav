//! The proxy's heartbeat and its store epoch (ADR 0036 E3.3, spec §13.12).
//!
//! Every store of the proxy, the first one too, has an epoch: 16 random
//! bytes, logged as `sandbox.store_reset` before the first heartbeat sent
//! under it. The heartbeat (`PUT /v1/agent/sandboxes/state`) says which live
//! sandboxes have a forwarder connected and when each was last heard from,
//! signed, with a `seq` that grows within the epoch and the proxy's clock
//! as `sent_at_ms`.
//!
//! The epoch, whether its reset is logged, the last `seq` and the heartbeat
//! a pause held back live in their own file next to the sandbox store
//! (`<name>.sandbox-heartbeat`, 0600), so the store's format does not
//! change and an older proxy still opens it. The file is versioned. One
//! that is missing, unreadable or of another version starts a new epoch:
//! that is always safe, it only logs another reset.
//!
//! Each `seq` is saved before its heartbeat is sent, so a crash never sends
//! one twice. A `409` (a used epoch, or a `seq` that does not grow: a store
//! restored from an old copy) starts a new epoch rather than reuse a `seq`.
//! One attempt sends at most two resets and one heartbeat, so it never
//! loops.
//!
//! In a pause the server refuses it (`403 agents_paused`): the proxy keeps
//! that heartbeat and sends it as it is, same `seq` and `sent_at_ms`, at
//! the first attempt after the resume (ADR 0036 E3.3). A fresh one follows
//! within a minute.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use klav_client::ClientError;
use klav_core::crypto::random;
use klav_core::ids::SandboxId;
use klav_proto::Blob;
use klav_proto::sandbox::{
    HEARTBEAT_VERSION, MAX_HEARTBEAT_SANDBOXES, PATH_SANDBOX_STATE, PATH_STORE_RESET,
    STORE_EPOCH_LEN, SandboxHeartbeat, SandboxLink, SandboxStoreReset,
};
use serde::{Deserialize, Serialize};

use crate::proxy::ProxyState;

/// Format version of the heartbeat file.
pub const HEARTBEAT_FILE_VERSION: u8 = 1;
/// Extension of the heartbeat file, next to the sandbox store.
pub const HEARTBEAT_EXTENSION: &str = "sandbox-heartbeat";
/// With live sandboxes: a heartbeat every 5 minutes.
pub const EVERY_LIVE_MS: i64 = 5 * 60 * 1000;
/// Without: every 30 minutes.
pub const EVERY_IDLE_MS: i64 = 30 * 60 * 1000;
/// A connection or disconnection sends one sooner, at most once a minute;
/// so does a retry after the server could not be reached or the proxy was
/// paused.
pub const SOONEST_MS: i64 = 60 * 1000;
/// How often the heartbeat task looks.
pub const LOOK_EVERY: std::time::Duration = std::time::Duration::from_secs(15);

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HeartbeatFile {
    v: u8,
    store_epoch: Blob,
    /// Whether the server took this epoch's `sandbox.store_reset`.
    logged: bool,
    /// The last `seq` used (saved before it is sent).
    seq: u64,
    /// The heartbeat a pause held back, sent as it is after the resume.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    kept: Option<SandboxHeartbeat>,
}

impl HeartbeatFile {
    fn fresh() -> Self {
        Self {
            v: HEARTBEAT_FILE_VERSION,
            store_epoch: Blob::new(random::array::<STORE_EPOCH_LEN>().to_vec()),
            logged: false,
            seq: 0,
            kept: None,
        }
    }
}

/// What the last attempt did, in this process only.
#[derive(Default)]
struct Last {
    /// When it was (the proxy's clock).
    at: Option<i64>,
    /// Whether it got through.
    sent: bool,
    /// The connected sandboxes it reported.
    connected: HashSet<SandboxId>,
}

/// The proxy's heartbeat state.
pub struct Heartbeats {
    path: Option<PathBuf>,
    file: tokio::sync::Mutex<HeartbeatFile>,
    last: Mutex<Last>,
}

/// The heartbeat file next to the sandbox store `store`.
pub fn path_of(store: &Path) -> PathBuf {
    store.with_extension(HEARTBEAT_EXTENSION)
}

impl Heartbeats {
    /// Reads the heartbeat file at `path`, or starts a new epoch.
    pub fn open(path: PathBuf) -> Self {
        let file = std::fs::read(&path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<HeartbeatFile>(&bytes).ok())
            .filter(|f| {
                f.v == HEARTBEAT_FILE_VERSION && f.store_epoch.as_bytes().len() == STORE_EPOCH_LEN
            });
        let file = file.unwrap_or_else(|| {
            if path.exists() {
                tracing::warn!("the heartbeat file cannot be read: starting a new store epoch");
            }
            HeartbeatFile::fresh()
        });
        Self {
            path: Some(path),
            file: tokio::sync::Mutex::new(file),
            last: Mutex::new(Last::default()),
        }
    }

    /// State in memory only (tests of other parts).
    pub fn in_memory() -> Self {
        Self {
            path: None,
            file: tokio::sync::Mutex::new(HeartbeatFile::fresh()),
            last: Mutex::new(Last::default()),
        }
    }

    fn save(&self, file: &HeartbeatFile) -> Result<(), String> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let bytes = serde_json::to_vec(file).map_err(|e| e.to_string())?;
        klav_client::home::write_private(path, &bytes).map_err(|e| e.to_string())
    }

    fn last(&self) -> std::sync::MutexGuard<'_, Last> {
        self.last.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The current epoch, whether its reset is logged, and the last `seq`.
    pub async fn epoch(&self) -> (Blob, bool, u64) {
        let f = self.file.lock().await;
        (f.store_epoch.clone(), f.logged, f.seq)
    }

    /// The heartbeat a pause held back, if any (tests).
    #[cfg(test)]
    pub(crate) async fn kept(&self) -> Option<SandboxHeartbeat> {
        self.file.lock().await.kept.clone()
    }
}

/// Whether a heartbeat is due at `now`: none sent yet; the period passed
/// (5 min with live sandboxes, 30 without); or, at most once a minute, a
/// sandbox connected or disconnected, or the last attempt failed. A clock
/// that went back past the last attempt makes it due: waiting for it to
/// catch up could silence the proxy for as long as it went back.
fn due(last: &Last, now: i64, live: bool, connected: &HashSet<SandboxId>) -> bool {
    let Some(at) = last.at else {
        return true;
    };
    let since = now.saturating_sub(at);
    if since < 0 {
        return true;
    }
    let every = if live { EVERY_LIVE_MS } else { EVERY_IDLE_MS };
    since >= every || (since >= SOONEST_MS && (!last.sent || *connected != last.connected))
}

/// What the heartbeat says now: the live sandboxes (not yet expired),
/// connected ones first,
/// then the most recently heard from, at most [`MAX_HEARTBEAT_SANDBOXES`].
pub(crate) async fn links(
    state: &ProxyState,
    now: i64,
) -> (bool, HashSet<SandboxId>, Vec<SandboxLink>) {
    let keys = state.connected_channel_keys();
    let store = state.sandboxes().store.lock().await;
    let key_of = |id: SandboxId| {
        store
            .channels
            .iter()
            .find(|c| c.sandbox_id == id)
            .and_then(|c| <[u8; 32]>::try_from(c.channel_key_sha256.as_bytes()).ok())
    };
    let mut links: Vec<SandboxLink> = store
        .sandboxes
        .iter()
        .filter(|s| s.expires_at > now)
        .map(|s| {
            let connected = key_of(s.sandbox_id).is_some_and(|k| keys.contains(&k));
            let seen = store
                .last_seen
                .get(&s.sandbox_id)
                .copied()
                .or(s.claimed_at)
                .filter(|&t| t > 0)
                .map(|t| t.min(now));
            SandboxLink {
                id: s.sandbox_id,
                connected,
                last_seen_at: seen,
            }
        })
        .collect();
    let live = !links.is_empty();
    links.sort_by(|a, b| {
        b.connected
            .cmp(&a.connected)
            .then(b.last_seen_at.cmp(&a.last_seen_at))
    });
    links.truncate(MAX_HEARTBEAT_SANDBOXES);
    let connected = links.iter().filter(|l| l.connected).map(|l| l.id).collect();
    (live, connected, links)
}

/// What one attempt did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sent {
    /// Not due.
    NotDue,
    /// The server took it.
    Sent,
    /// The server took the heartbeat a pause held back: a fresh one goes
    /// within a minute.
    Resent,
    /// It did not get through: the next attempt tries again.
    Failed,
}

fn is_paused(e: &ClientError) -> bool {
    matches!(e, ClientError::Paused(_))
}

fn is_conflict(e: &ClientError) -> bool {
    matches!(e, ClientError::Api { status: 409, .. })
}

fn is_bad_request(e: &ClientError) -> bool {
    matches!(e, ClientError::Api { status: 400, .. })
}

/// The cause of a failure, for the log: never a body.
fn kind(e: &ClientError) -> &'static str {
    crate::proxy::redacted_kind(e)
}

/// Sends the heartbeat if due ([`due`]), or always with `force`.
pub async fn beat(state: &ProxyState, force: bool) -> Sent {
    let heartbeats = state.heartbeats();
    let now = state.sandboxes().now();
    let (live, connected, links) = links(state, now).await;
    if !force && !due(&heartbeats.last(), now, live, &connected) {
        return Sent::NotDue;
    }
    let sent = send(state, now, links).await;
    let mut last = heartbeats.last();
    last.at = Some(now);
    last.sent = sent == Sent::Sent;
    if last.sent {
        last.connected = connected;
    }
    sent
}

/// Logs the epoch's reset if it is not yet, then sends one heartbeat. At
/// most two resets and one heartbeat.
async fn send(state: &ProxyState, now: i64, links: Vec<SandboxLink>) -> Sent {
    let heartbeats = state.heartbeats();
    let mut file = heartbeats.file.lock().await;
    let mut fresh_tries = 0;
    while !file.logged {
        let reset = SandboxStoreReset {
            store_epoch: file.store_epoch.clone(),
        };
        // Saved before it is sent: an epoch the server may have taken is
        // never sent again as new.
        if let Err(e) = heartbeats.save(&file) {
            tracing::error!(error = %e, "could not save the heartbeat file");
            return Sent::Failed;
        }
        match state.post_signed(PATH_STORE_RESET, &reset).await {
            Ok(()) => {
                file.logged = true;
                file.seq = 0;
            }
            Err(e) if is_conflict(&e) && fresh_tries == 0 => {
                tracing::info!("the server already has this store epoch: starting a new one");
                *file = HeartbeatFile::fresh();
                fresh_tries += 1;
            }
            Err(e) => {
                tracing::warn!(
                    kind = kind(&e),
                    "could not log the store reset; the next heartbeat tries again"
                );
                return Sent::Failed;
            }
        }
    }
    // The one a pause held back goes first, as it is.
    let (body, resend) = match file.kept.clone() {
        Some(kept) => (kept, true),
        None => {
            file.seq += 1;
            if let Err(e) = heartbeats.save(&file) {
                tracing::error!(error = %e, "could not save the heartbeat file");
                return Sent::Failed;
            }
            let body = SandboxHeartbeat {
                v: HEARTBEAT_VERSION,
                store_epoch: file.store_epoch.clone(),
                seq: file.seq,
                sent_at_ms: now,
                sandboxes: links,
            };
            (body, false)
        }
    };
    match state.put_signed(PATH_SANDBOX_STATE, &body).await {
        Ok(()) if resend => {
            file.kept = None;
            if let Err(e) = heartbeats.save(&file) {
                tracing::error!(error = %e, "could not save the heartbeat file");
            }
            Sent::Resent
        }
        Ok(()) => Sent::Sent,
        Err(e) if is_paused(&e) => {
            if !resend {
                tracing::info!("paused: the heartbeat waits for the resume");
                file.kept = Some(body);
                if let Err(e) = heartbeats.save(&file) {
                    tracing::error!(error = %e, "could not save the heartbeat file");
                }
            }
            Sent::Failed
        }
        Err(e) if is_conflict(&e) => {
            // A store restored from an old copy, or an epoch that is not
            // the proxy's last: a new epoch, logged at the next attempt.
            tracing::info!(
                "the server refused the heartbeat's epoch or seq: starting a new store epoch"
            );
            *file = HeartbeatFile::fresh();
            if let Err(e) = heartbeats.save(&file) {
                tracing::error!(error = %e, "could not save the heartbeat file");
            }
            Sent::Failed
        }
        Err(e) if resend && is_bad_request(&e) => {
            // The server will never take it (its `sent_at_ms` too far
            // ahead, say): dropped, so a fresh one goes next.
            tracing::warn!("the server refused the heartbeat a pause held back: dropping it");
            file.kept = None;
            if let Err(e) = heartbeats.save(&file) {
                tracing::error!(error = %e, "could not save the heartbeat file");
            }
            Sent::Failed
        }
        Err(e) => {
            tracing::warn!(
                kind = kind(&e),
                "could not send the heartbeat; the next one tries again"
            );
            Sent::Failed
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn last(at: i64, sent: bool, connected: &[SandboxId]) -> Last {
        Last {
            at: Some(at),
            sent,
            connected: connected.iter().copied().collect(),
        }
    }

    /// When a heartbeat is due: the first at once; then every 5 min with
    /// live sandboxes and every 30 without; sooner, but not within a
    /// minute, on a change of connections or after a failure.
    #[test]
    fn a_heartbeat_is_due_by_the_period_or_a_minute_after_a_change() {
        let none = HashSet::new();
        let one = SandboxId::generate();
        let with = HashSet::from([one]);
        assert!(due(&Last::default(), 0, false, &none), "the first");
        let t = 1_000_000;
        for (since, live, due_now) in [
            (EVERY_LIVE_MS - 1, true, false),
            (EVERY_LIVE_MS, true, true),
            (EVERY_LIVE_MS, false, false),
            (EVERY_IDLE_MS - 1, false, false),
            (EVERY_IDLE_MS, false, true),
        ] {
            assert_eq!(
                due(&last(t, true, &[]), t + since, live, &none),
                due_now,
                "{since} ms, live {live}"
            );
        }
        // A connection, a disconnection, a failure: after a minute.
        for (before, sent, now) in [
            (&[][..], true, &with),
            (&[one][..], true, &none),
            (&[][..], false, &none),
        ] {
            assert!(!due(&last(t, sent, before), t + SOONEST_MS - 1, true, now));
            assert!(due(&last(t, sent, before), t + SOONEST_MS, true, now));
        }
        // Nothing changed and it went through: the period.
        assert!(!due(&last(t, true, &[one]), t + SOONEST_MS, true, &with));
        // The clock went back past the last attempt: due at once.
        assert!(due(&last(t, true, &[one]), t - 1, true, &with));
        assert!(due(&last(t, true, &[]), t - EVERY_IDLE_MS, false, &none));
    }

    /// A heartbeat file of another version, or with an epoch of the wrong
    /// length, is not read: the proxy starts a new epoch, not logged.
    #[tokio::test]
    async fn a_heartbeat_file_of_another_version_starts_a_new_epoch() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("proxy.sandbox-heartbeat");
        let epoch = Blob::new(vec![7; STORE_EPOCH_LEN]);
        let ok = serde_json::json!({"v": HEARTBEAT_FILE_VERSION, "store_epoch": epoch,
            "logged": true, "seq": 9});
        std::fs::write(&path, serde_json::to_vec(&ok).expect("json")).expect("write");
        assert_eq!(
            Heartbeats::open(path.clone()).epoch().await,
            (epoch.clone(), true, 9)
        );
        for bad in [
            serde_json::json!({"v": HEARTBEAT_FILE_VERSION + 1, "store_epoch": epoch,
                "logged": true, "seq": 9}),
            serde_json::json!({"v": HEARTBEAT_FILE_VERSION,
                "store_epoch": Blob::new(vec![7; STORE_EPOCH_LEN - 1]), "logged": true, "seq": 9}),
        ] {
            std::fs::write(&path, serde_json::to_vec(&bad).expect("json")).expect("write");
            let (fresh, logged, seq) = Heartbeats::open(path.clone()).epoch().await;
            assert_ne!(fresh, epoch);
            assert_eq!((logged, seq), (false, 0));
        }
    }
}
