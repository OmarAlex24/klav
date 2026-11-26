//! The daemon: socket, access control, idle lock and request dispatch.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, PoisonError, Weak};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use klav_client::health::{BREACH_API, HealthSettings};
use klav_client::proxy_admin::PairingCheck;
use klav_client::{ClientError, Home, Unlocked, unlock_with_password};
use klav_core::crypto::kdf::MasterPassword;
use klav_core::crypto::token;
use klav_core::ids::{AgentId, ItemId, TaskId};
use secrecy::ExposeSecret;
use serde::Serialize;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Mutex, Notify, mpsc, watch};
use tokio::task::JoinHandle;
use zeroize::Zeroizing;

use crate::browser::{Hub, Line};
use crate::imports::Imports;
use crate::presence::{self, Caller, Gate, OnePassword, Presence, PromptKind, Purpose, Untitled};
use crate::prompt::{ItemShown, Lang, Prompt, Source, Widening};
use crate::protocol::{
    AskLasts, AskValue, AskValueKind, BrowserAsk, BrowserCause, DaemonStatus, ErrorBody, ErrorCode,
    MAX_LINE, PROTOCOL_VERSION, PasskeyArmed, PauseInEffect, PresenceAsk, PresenceKey,
    PresencePurpose, Request, RequestEnvelope, ResponseEnvelope, RevocationProgress,
};
use crate::touchid::{self, Biometric};
use crate::uv;

/// How often the idle and sleep checks run.
const TICK: Duration = Duration::from_secs(2);
/// How long to wait before uploading the generator outbox again after a
/// failure (offline).
const FLUSH_RETRY: Duration = Duration::from_secs(30);
/// A clock that runs during sleep moving this much more than one that
/// stops means the machine slept (`Instant` stops during sleep on macOS
/// and Linux).
const SLEEP_GAP: Duration = Duration::from_secs(20);
/// Without a clock that runs during sleep, the wall clock going back more
/// than this locks too: it could hide a sleep from the wall-clock check.
const CLOCK_BACK: Duration = Duration::from_secs(1);
/// A local copy older than this is synced: in the background for reads
/// (ADR 0026), first for everything else.
pub const SYNC_AFTER: Duration = Duration::from_secs(30);
/// Rows in an import preview: enough to look through, small enough for a
/// native message (1 MiB).
const PREVIEW_ROWS: usize = 500;

/// Daemon settings.
#[derive(Debug, Clone)]
pub struct Config {
    /// Account directory (the socket lives there).
    pub home: Home,
    /// Lock after this long without requests.
    pub idle_lock: Duration,
    /// Offer Touch ID (macOS, when available).
    pub touch_id: bool,
    /// Sync a local copy older than this ([`SYNC_AFTER`]).
    pub sync_after: Duration,
    /// The build this `klavd` runs, for `status` (`build.rs`); `None` when
    /// unknown (a source without Git, and the tests).
    pub build: Option<Build>,
}

/// The commit a `klavd` was built from and its committer time, which tell
/// two builds apart while the version number stays the same.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Build {
    /// The commit's hash (7 to 40 lowercase hex digits).
    pub commit: String,
    /// The commit's committer time, in Unix seconds.
    pub commit_time: u64,
}

/// What only one request at a time may touch: the unlocked account (its
/// calls need `&mut` for the network).
struct Session {
    unlocked: Box<Unlocked>,
    /// The last sync that reached a verdict: it succeeded, or the server's
    /// state was refused (a rollback). Network failures leave it alone.
    last_sync: Option<Instant>,
    /// The last sync failed for a reason other than the network or a
    /// refused state (an expired session, a corrupt cache): every read
    /// fails with it until a sync succeeds (ADR 0026 §3).
    sync_error: Option<ErrorBody>,
    /// The last sync refused the server's state (a rollback, T7, or an
    /// impossible counter): a warning on every request until a sync
    /// succeeds, while this device keeps the copy it already verified
    /// (ADR 0030, layer 10, which amends ADR 0026 §3).
    rollback: Option<String>,
    /// The last sync could not reach the server.
    offline: Option<String>,
    /// The server deleted the account (ADR 0037 §3): a warning on every
    /// request, no more syncs, and the copy stays as it is, read-only
    /// (every write needs the server, which refuses it).
    deleted: Option<String>,
    /// `unlocked.generation()` (the cache's) when `State::revision` last
    /// moved.
    seen_cache_generation: u64,
    /// When to try the generator outbox again after a failed upload.
    flush_retry: Option<Instant>,
    /// Imports in progress (ADR 0024).
    imports: Imports,
}

/// An unlocked session. `status`, `lock` and the idle and sleep checks
/// never wait for [`Slot::session`]: a request waiting on the network
/// (a server that does not answer) cannot keep the vault open. Locking
/// cancels the requests in flight, which drop their hold on the session,
/// so its keys are wiped right away.
struct Slot {
    session: Mutex<Session>,
    method: &'static str,
    /// The lock generation this session was opened in.
    generation: u64,
    /// The idle lock's clock: the unlock, then the last request that
    /// worked and counts as use ([`counts_as_use`]), or a step of a key
    /// change the person asked for ([`rotate_in_steps`]). Nothing else
    /// moves it.
    last_use: std::sync::Mutex<Instant>,
    /// Passkey uses agents armed in tabs (ADR 0020 §9). Gone with the
    /// slot: locking drops them.
    arms: std::sync::Mutex<Vec<Arm>>,
    /// The background sync in flight (one at a time, ADR 0026). Here and
    /// not in [`Session`] so `status` can tell without waiting for the
    /// session.
    syncing: std::sync::Mutex<Option<JoinHandle<()>>>,
    /// What checks a master password against this session in memory (ADR
    /// 0041 §2.3), apart from [`Self::session`] so a check waits for no
    /// request. `None` when the session's own KDF parameters don't decode:
    /// then no password counts as presence. Gone with the slot.
    password: Option<klav_client::PasswordCheck>,
}

/// How long an agent's passkey use stays armed in its tab (ADR 0020 §9).
const ARM_TTL: Duration = Duration::from_secs(60);

/// One passkey use an agent armed in a tab (ADR 0020 §9): the next
/// sign-in of `rp_id` on `host` in that tab, once, before `deadline`.
struct Arm {
    /// Digest of the token the extension hands back (the token itself is
    /// not kept).
    digest: [u8; token::DIGEST_LEN],
    /// The extension's connection and its tab.
    conn: u64,
    tab_id: u64,
    host: String,
    rp_id: String,
    item: ItemId,
    agent: AgentId,
    task: TaskId,
    deadline: Instant,
}

impl Drop for Slot {
    /// Locking drops the slot: a background sync still running stops too.
    fn drop(&mut self) {
        if let Some(task) = self
            .syncing
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        {
            task.abort();
        }
    }
}

impl Slot {
    fn is_syncing(&self) -> bool {
        self.syncing
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .is_some_and(|task| !task.is_finished())
    }

    fn last_use(&self) -> Instant {
        *self.last_use.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn used(&self) {
        *self.last_use.lock().unwrap_or_else(PoisonError::into_inner) = Instant::now();
    }

    fn arms(&self) -> std::sync::MutexGuard<'_, Vec<Arm>> {
        self.arms.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Arms `arm`: one per tab, the newest wins.
    fn arm(&self, arm: Arm) {
        let now = Instant::now();
        let mut arms = self.arms();
        arms.retain(|a| a.deadline > now && (a.conn, a.tab_id) != (arm.conn, arm.tab_id));
        arms.push(arm);
    }

    /// Takes the use armed with `digest` for tab `tab_id` of connection
    /// `conn`, if it has not expired: once.
    fn take_arm(&self, digest: &[u8; token::DIGEST_LEN], conn: u64, tab_id: u64) -> Option<Arm> {
        let now = Instant::now();
        let mut arms = self.arms();
        arms.retain(|a| a.deadline > now);
        let at = arms
            .iter()
            .position(|a| a.digest == *digest && a.conn == conn && a.tab_id == tab_id)?;
        Some(arms.swap_remove(at))
    }

    fn is_armed(&self, digest: &[u8; token::DIGEST_LEN]) -> bool {
        self.arms().iter().any(|a| a.digest == *digest)
    }

    fn disarm(&self, digest: &[u8; token::DIGEST_LEN]) {
        self.arms().retain(|a| a.digest != *digest);
    }
}

struct State {
    config: Config,
    slot: std::sync::Mutex<Option<Arc<Slot>>>,
    /// Bumped by every lock: work started before it is cancelled, and an
    /// unlock that started before it is not published.
    generation: watch::Sender<u64>,
    /// One unlock at a time.
    unlocking: Mutex<()>,
    shutdown: Notify,
    browsers: Hub,
    /// Moves whenever what the reads answer may have changed: a sync that
    /// brought changes, or a new session (`DaemonStatus::revision`).
    revision: AtomicU64,
    /// The directory of this executable, symbolic links resolved: the
    /// `klav-native-host` there is the browser's ([`Source`]).
    exe_dir: Option<std::path::PathBuf>,
    /// Agents' signed requests already used here (agent and nonce, with
    /// when: one agent's nonce never blocks another's request),
    /// across locks and unlocks: a request armed or acted on once does not
    /// work again in a later session (T139). Kept for twice the requests'
    /// 5 minutes; a restart of `klavd` forgets them, and starts locked.
    spent_proofs: std::sync::Mutex<Vec<(klav_core::ids::AgentId, Vec<u8>, i64)>>,
    /// The pauses of the account's agents (ADR 0033 §7.2), kept across
    /// locks: `status` reports them and what `klavd` mediates stays
    /// refused while it is locked.
    pauses: std::sync::Mutex<PauseBook>,
    /// The deletion of the account the person asked for, and whether the
    /// server already deleted it, as the last sync said (ADR 0037 §3).
    /// Kept across locks and restarts ([`DELETION_SEEN`]), like the
    /// pauses; no secret.
    deletion: std::sync::Mutex<DeletionSeen>,
    /// The revocations whose key change was asked for and is not finished
    /// (ADR 0033, amendment of 2026-11-10, F2), as the last unlocked
    /// moment left them, and which ones `klavd` is working on: `status`
    /// reports them without the session, also while locked. No secret.
    revocations: std::sync::Mutex<RevocationBook>,
    /// The presence gate's windows, settings and held connections (ADR
    /// 0041). Unused while the gate is off.
    presence: Presence,
    /// The device and inode of the socket file `klavd` bound, read right
    /// after binding (ADR 0041 §8): the watchdog stops `klavd` when the
    /// path names anything else.
    socket_id: (u64, u64),
    /// Every Touch ID call goes through here: the shim in `klavd`, a fake
    /// in the tests.
    touch: Box<dyn Biometric>,
    /// One master-password check at a time (ADR 0041 §2.3).
    passwords: OnePassword,
    /// One change of the presence or passkey setting at a time, from the
    /// read of the current value to the save and the change in memory
    /// (finding 3 of the second layer-2 review).
    setting_change: Mutex<()>,
    /// What only the tests replace.
    #[cfg(test)]
    seams: TestSeams,
}

/// What the server's own tests replace (ADR 0041, layer 2): who each new
/// connection's peer is, and whether `hold` is on.
#[cfg(test)]
#[derive(Default)]
pub(crate) struct TestSeams {
    /// The window key of each next connection, in order; a `Connection`
    /// key becomes the connection's own. Empty: what the kernel says.
    pub(crate) keys: std::sync::Mutex<std::collections::VecDeque<presence::Key>>,
    /// `hold` answers as it will once layer 6 turns it on.
    pub(crate) hold: bool,
    /// Run once, off the async workers, right before `klavd` next marks a
    /// Touch ID prompt open: a test holds it there to send another request
    /// while the lock is held and no dialog is open yet.
    pub(crate) before_prompt: BeforePrompt,
    /// Run once, off the async workers, between the window gate's two
    /// passes (`first` and `require`): a test changes the setting there.
    pub(crate) between_passes: BeforePrompt,
}

/// [`TestSeams::before_prompt`], shared with the test that sets it.
#[cfg(test)]
pub(crate) type BeforePrompt = Arc<std::sync::Mutex<Option<Box<dyn FnOnce() + Send>>>>;

#[cfg(test)]
impl TestSeams {
    fn before_prompt(&self) {
        Self::pause(&self.before_prompt);
    }

    fn between_passes(&self) {
        Self::pause(&self.between_passes);
    }

    fn pause(seam: &BeforePrompt) {
        let pause = seam.lock().unwrap_or_else(PoisonError::into_inner).take();
        if let Some(pause) = pause {
            tokio::task::block_in_place(pause);
        }
    }
}

/// [`State::revocations`].
#[derive(Default)]
struct RevocationBook {
    /// From this device's sealed record (`revocations.bin`), as counts:
    /// no vault or project name outlives the session here.
    pending: Vec<RevocationProgress>,
    /// Key changes in flight, per agent: a request and the resume at
    /// unlock can overlap (their steps take turns on the session, and
    /// neither rotates a project twice).
    running: std::collections::BTreeMap<AgentId, usize>,
    /// The record did not open at the last read: `pending` may be stale.
    unreadable: bool,
    /// It did not open because a newer Klav wrote it.
    newer: bool,
    /// Key changes that finished here while skipping what Klav can't reach
    /// (a deleted project leaves no entry in the record): `status` keeps
    /// saying so until `klavd` restarts or the agent owes a key change
    /// again, so no app reads the end as "every key changed".
    finished: std::collections::BTreeMap<AgentId, RevocationProgress>,
}

impl RevocationBook {
    /// `agent`'s entries in `pending` (a revocation, a narrowing, or both).
    fn of(&self, agent: AgentId) -> Vec<RevocationProgress> {
        self.pending
            .iter()
            .filter(|p| p.agent_id == agent)
            .cloned()
            .collect()
    }

    /// Keeps a key change of `agent` that finished skipping `skipped`
    /// things Klav can't reach (`before`: its entry before the last step,
    /// which rotated `rotated_now` projects). A narrowing stays a
    /// narrowing: the agent is still active (fourth re-check, F3), and a
    /// revocation without the key change stays one. `rotated` counts
    /// projects only: `skipped` also counts items (fifth re-check, 5).
    /// True when `status` changed.
    fn finish(
        &mut self,
        agent: AgentId,
        before: Option<RevocationProgress>,
        skipped: usize,
        rotated_now: usize,
    ) -> bool {
        if skipped == 0 || self.pending.iter().any(|p| p.agent_id == agent) {
            return false;
        }
        let projects = before.as_ref().map_or(0, |b| b.projects);
        let rotated = before
            .as_ref()
            .map_or(0, |b| b.rotated)
            .saturating_add(rotated_now)
            .min(projects);
        let narrowed = before.as_ref().is_some_and(|b| b.narrowed);
        let without_key_change = before.as_ref().is_some_and(|b| b.without_key_change);
        self.finished.insert(
            agent,
            RevocationProgress {
                agent_id: agent,
                name: before.and_then(|b| b.name),
                projects,
                rotated,
                regrants: 0,
                unknown_projects: false,
                narrowed,
                items: 0,
                log_unchecked: false,
                without_key_change,
                skipped,
                to_change: 0,
                needs_work: false,
                running: false,
                last_error: None,
            },
        );
        true
    }

    /// `agent` was revoked again: what an earlier key change of it left in
    /// `finished` no longer holds (a finished narrowing would still call
    /// it active, fifth re-check, 3). True when `status` changed.
    fn revoked(&mut self, agent: AgentId) -> bool {
        self.finished.remove(&agent).is_some()
    }

    /// Takes in a read of the record. One that failed keeps the last list
    /// rather than an empty one that would read as done, and says whether
    /// a newer Klav wrote the record. True when `status` changed.
    fn note(
        &mut self,
        pending: &klav_client::ClientResult<Vec<klav_client::revoke::PendingRevocation>>,
    ) -> bool {
        match pending {
            Err(e) => {
                let newer = matches!(e, klav_client::ClientError::NewerFormat(_));
                let changed = !self.unreadable || self.newer != newer;
                self.unreadable = true;
                self.newer = newer;
                changed
            }
            Ok(pending) => {
                let pending: Vec<RevocationProgress> = pending
                    .iter()
                    .map(|p| RevocationProgress::of(p, false))
                    .collect();
                let before = self.finished.len();
                self.finished
                    .retain(|agent, _| !pending.iter().any(|p| p.agent_id == *agent));
                let changed =
                    self.pending != pending || self.unreadable || self.finished.len() != before;
                self.pending = pending;
                self.unreadable = false;
                self.newer = false;
                changed
            }
        }
    }
}

/// Marks a revocation's key change as running in `status` while it lives.
struct Rotating<'a> {
    state: &'a State,
    agent: AgentId,
}

impl Drop for Rotating<'_> {
    fn drop(&mut self) {
        let mut book = self.state.revocation_book();
        if let Some(n) = book.running.get_mut(&self.agent) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                book.running.remove(&self.agent);
            }
        }
        drop(book);
        self.state.revision.fetch_add(1, Ordering::Relaxed);
    }
}

/// What this `klavd` knows of the account's deletion (ADR 0037 §3).
#[derive(Default, PartialEq)]
struct DeletionSeen {
    /// Asked for, with its date; kept after the deletion too.
    asked: Option<klav_proto::auth::AccountDeletion>,
    /// A sync got `401` at or after the date: the account is gone.
    deleted: bool,
}

/// `$KLAV_HOME/account-deletion.json`: [`DeletionSeen`] across restarts of
/// `klavd` (ADR 0037 A3, review finding 4 of the apps), so `status` says
/// it while locked, like the pauses. Mode 0600, written atomically; no
/// secret (the account, the device that asked, the dates). A forged file
/// can only make `klavd` refuse more for agents and show a notice until
/// the next unlock, which takes what the account's own sealed copy
/// (`deletion.bin`) and the next sync say.
const DELETION_SEEN: &str = crate::client::ACCOUNT_DELETION_FILE;
/// Format of [`DELETION_SEEN`].
const DELETION_SEEN_VERSION: u32 = 1;

#[derive(Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct DeletionSeenFile {
    v: u32,
    account: klav_core::ids::AccountId,
    deletion: klav_proto::auth::AccountDeletion,
    #[serde(default)]
    deleted: bool,
}

/// What an earlier run of `klavd` knew of this home's account's deletion.
/// An unreadable file, or one of another account, is logged and read as
/// none: the next unlock learns it again.
#[allow(clippy::print_stderr)]
fn load_deletion_seen(home: &Home) -> DeletionSeen {
    let path = home.file(DELETION_SEEN);
    let file = match std::fs::read(&path) {
        Ok(bytes) => serde_json::from_slice::<DeletionSeenFile>(&bytes)
            .map_err(|e| e.to_string())
            .and_then(|f| {
                if f.v == DELETION_SEEN_VERSION {
                    Ok(f)
                } else {
                    Err(format!("unsupported version {}", f.v))
                }
            }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return DeletionSeen::default(),
        Err(e) => Err(e.to_string()),
    };
    match file {
        Ok(f) if klav_client::account(home).is_ok_and(|a| a.account_id == f.account) => {
            DeletionSeen {
                asked: Some(f.deletion),
                deleted: f.deleted,
            }
        }
        Ok(_) => DeletionSeen::default(),
        Err(e) => {
            eprintln!(
                "klavd: {}: {e}; the account's deletion shows again after the next unlock",
                path.display()
            );
            DeletionSeen::default()
        }
    }
}

/// What a `klavd` whose account the server deleted says on every request.
fn deleted_warning(at: i64) -> String {
    format!(
        "{}. klavd no longer syncs; `klav logout` deletes this device's copy",
        ClientError::AccountDeleted(at)
    )
}

/// The pauses of agents as this `klavd` knows them. None holds a secret.
#[derive(Default)]
struct PauseBook {
    /// Signed by the account: what the last sync, or this device's own
    /// decision, left in effect. Kept in [`SIGNED_PAUSES`] too, so a
    /// restart of `klavd` (which starts locked) still reports them.
    signed: Vec<klav_proto::agent::AgentPause>,
    /// Decided here, not taken by the server yet: `klavd` was locked (no
    /// account key to sign with) or offline. Signed and sent as soon as
    /// it can (ADR 0033 §7.2, P2).
    local: Vec<LocalPause>,
}

/// A pause decided on this Mac that the server does not know yet. Kept in
/// [`LOCAL_PAUSES`] too, so a restart of `klavd` does not lift it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalPause {
    /// The account of this home when it was decided: only that account
    /// signs it, even if the home changes account meanwhile.
    account: klav_core::ids::AccountId,
    /// The agent; none: every agent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    agent: Option<AgentId>,
    /// When the person decided it (Unix ms). The signed pause is dated
    /// when it is sent: the server takes only recent ones.
    at: i64,
    /// When it ends by itself (Unix ms); `0`: until the person resumes.
    until: i64,
    /// Decided while `klavd` was locked, with no presence (ADR 0033 P2):
    /// the person hears so when the unlock signs it.
    #[serde(default)]
    locked: bool,
    /// The program it came through, as the kernel reports the peer: a
    /// hint for the person, not a check.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source: Option<Source>,
    /// The server answered that it does not support pausing agents (a
    /// server older than the pauses: `405` on the path of every agent).
    /// It holds here only, and the watchdog stops sending it; each unlock
    /// tries once more, in case the server was updated.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    unsupported: bool,
}

/// `$KLAV_HOME/signed-pauses.json`: the pauses signed by the account that
/// the last sync left in effect, so `status` reports them after a restart
/// of `klavd`, before the next unlock and sync. Mode 0600, written
/// atomically; no secret (the account, agents, times and signatures).
/// Loaded without checking the signatures, which needs the account
/// unlocked: a forged file can only make `klavd` refuse more, and the next
/// sync replaces it with what checks out.
const SIGNED_PAUSES: &str = klav_client::pause::SIGNED_PAUSES_FILE;
/// Format of [`SIGNED_PAUSES`].
const SIGNED_PAUSES_VERSION: u32 = 1;

#[derive(Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedPausesFile {
    v: u32,
    account: klav_core::ids::AccountId,
    pauses: Vec<klav_proto::agent::AgentPause>,
}

/// The signed pauses an earlier run of `klavd` saved: of this home's
/// account, and still in effect. An unreadable file is logged and read as
/// none: the server still enforces them, and the next sync brings them.
#[allow(clippy::print_stderr)]
fn load_signed_pauses(home: &Home) -> Vec<klav_proto::agent::AgentPause> {
    let path = home.file(SIGNED_PAUSES);
    let file = match std::fs::read(&path) {
        Ok(bytes) => serde_json::from_slice::<SignedPausesFile>(&bytes)
            .map_err(|e| e.to_string())
            .and_then(|f| {
                if f.v == SIGNED_PAUSES_VERSION {
                    Ok(f)
                } else {
                    Err(format!("unsupported version {}", f.v))
                }
            }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Vec::new(),
        Err(e) => Err(e.to_string()),
    };
    let file = match file {
        Ok(f) => f,
        Err(e) => {
            eprintln!(
                "klavd: {}: {e}; starting without the signed pauses until the next sync",
                path.display()
            );
            return Vec::new();
        }
    };
    let Ok(account) = klav_client::account(home).map(|a| a.account_id) else {
        return Vec::new();
    };
    if file.account != account {
        return Vec::new();
    }
    let now = now_ms();
    file.pauses
        .into_iter()
        .filter(|p| klav_client::pause::in_effect(p, now))
        .collect()
}

/// `$KLAV_HOME/local-pauses.json`: the pauses decided here that the server
/// does not know yet (ADR 0033 §7.2), across restarts of `klavd`. Mode
/// 0600, written atomically; no secret (accounts, agents and times).
const LOCAL_PAUSES: &str = crate::client::LOCAL_PAUSES_FILE;
/// Format of [`LOCAL_PAUSES`].
const LOCAL_PAUSES_VERSION: u32 = 1;

#[derive(Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalPausesFile {
    v: u32,
    pauses: Vec<LocalPause>,
}

/// The pauses decided here that an earlier run of `klavd` left waiting:
/// of this home's account, and not over. An unreadable file is logged and
/// read as none: the pauses the server took still hold.
#[allow(clippy::print_stderr)]
fn load_local_pauses(home: &Home) -> Vec<LocalPause> {
    let path = home.file(LOCAL_PAUSES);
    let read = match std::fs::read(&path) {
        Ok(bytes) => serde_json::from_slice::<LocalPausesFile>(&bytes)
            .map_err(|e| e.to_string())
            .and_then(|f| {
                if f.v == LOCAL_PAUSES_VERSION {
                    Ok(f.pauses)
                } else {
                    Err(format!("unsupported version {}", f.v))
                }
            }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Vec::new(),
        Err(e) => Err(e.to_string()),
    };
    let pauses = match read {
        Ok(p) => p,
        Err(e) => {
            eprintln!(
                "klavd: {}: {e}; starting without the pauses decided on this computer",
                path.display()
            );
            return Vec::new();
        }
    };
    let Ok(account) = klav_client::account(home).map(|a| a.account_id) else {
        return Vec::new();
    };
    let now = now_ms();
    pauses
        .into_iter()
        .filter(|p| p.account == account && (p.until == 0 || p.until > now))
        .collect()
}

/// Whether a pause decided here stays here after the server's error, to
/// be sent again later: everything but a 4xx that the same pause would
/// get again (401, 408 and 429 pass with time). The network, a server
/// error, an expired session, and a later decision on the server that
/// this pause cannot be dated after yet all keep it.
fn kept(e: &ClientError) -> bool {
    !matches!(e, ClientError::Api { status, .. }
        if (400..500).contains(status) && !matches!(status, 401 | 408 | 429))
}

/// Whether the server answered a pause of every agent (`agent`: none) as
/// a server older than the pauses does: `405`, its route for one agent
/// read with the ID `pause` (`klav_client::pause`). The pause then holds
/// here only ([`LocalPause::unsupported`]). One agent's path answers
/// `404`, as for an agent the server does not know, so that one cannot be
/// told apart and is dropped.
fn unsupported(e: &ClientError, agent: Option<AgentId>) -> bool {
    agent.is_none() && matches!(e, ClientError::Api { status: 405, .. })
}

/// What the person hears when the server does not support pausing.
const UNSUPPORTED: &str = "this server does not support pausing agents (update it): every agent is paused on this computer only, where klavd refuses what it mediates, and klavd stops telling the server until the next unlock";

/// A resume whose pause was already lifted here ([`State::forget_local_pause`])
/// and that the server did not take: the warning to give when nothing is
/// left to lift there, or `None` for an error. Offline, the server held no
/// signed pause of the scope (`held`: it does); a server older than the
/// pauses ([`unsupported`]) has none to lift. One agent's `404` cannot be
/// told apart from an unknown agent, so it stays an error.
fn resume_not_sent(err: &ClientError, agent: Option<AgentId>, held: bool) -> Option<String> {
    match err {
        ClientError::Network(why) if !held => {
            Some(format!("offline ({why}): resumed on this computer"))
        }
        _ if unsupported(err, agent) => Some(
            "this server does not support pausing agents (update it): resumed on this computer, where klavd no longer refuses what it mediates"
                .to_owned(),
        ),
        _ => None,
    }
}

/// «from the terminal», for a pause decided while locked.
fn decided_from(source: Option<Source>) -> &'static str {
    source.map_or("from a program Klav does not recognize", |s| {
        s.decided_from(Lang::En)
    })
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

impl State {
    fn pause_book(&self) -> std::sync::MutexGuard<'_, PauseBook> {
        self.pauses.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Writes `book.local` to [`LOCAL_PAUSES`] (none: removes it). Called
    /// with the book's lock held, so one write at a time. A failure is
    /// logged: the pauses still hold until `klavd` stops.
    #[allow(clippy::print_stderr)]
    fn save_local(&self, book: &PauseBook) {
        let path = self.config.home.file(LOCAL_PAUSES);
        let saved = if book.local.is_empty() {
            match std::fs::remove_file(&path) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.to_string()),
                _ => Ok(()),
            }
        } else {
            serde_json::to_vec(&LocalPausesFile {
                v: LOCAL_PAUSES_VERSION,
                pauses: book.local.clone(),
            })
            .map_err(|e| e.to_string())
            .and_then(|json| {
                klav_client::home::write_private(&path, &json).map_err(|e| e.to_string())
            })
        };
        if let Err(e) = saved {
            eprintln!(
                "klavd: cannot save {}: {e}; the pauses decided on this computer hold until klavd stops",
                path.display()
            );
        }
    }

    /// Writes `signed` to [`SIGNED_PAUSES`] for `account` (none: removes
    /// it). Called with the book's lock held. A failure is logged: the
    /// pauses hold all the same, and the next sync after a restart brings
    /// them back.
    #[allow(clippy::print_stderr)]
    fn save_signed(
        &self,
        account: klav_core::ids::AccountId,
        signed: &[klav_proto::agent::AgentPause],
    ) {
        let path = self.config.home.file(SIGNED_PAUSES);
        let saved = if signed.is_empty() {
            match std::fs::remove_file(&path) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.to_string()),
                _ => Ok(()),
            }
        } else {
            serde_json::to_vec(&SignedPausesFile {
                v: SIGNED_PAUSES_VERSION,
                account,
                pauses: signed.to_vec(),
            })
            .map_err(|e| e.to_string())
            .and_then(|json| {
                klav_client::home::write_private(&path, &json).map_err(|e| e.to_string())
            })
        };
        if let Err(e) = saved {
            eprintln!(
                "klavd: cannot save {}: {e}; after a restart, the signed pauses show again with the next sync",
                path.display()
            );
        }
    }

    /// Keeps the signed pauses `u` holds (it checked their signatures)
    /// and forgets the ones decided here that ended. Moves `revision`
    /// when they changed.
    fn learn_pauses(&self, u: &Unlocked) {
        self.learn_deletion(u);
        let signed = u.agent_pauses();
        let account = u.account().account_id;
        let now = now_ms();
        let mut book = self.pause_book();
        let before = book.local.len();
        book.local
            .retain(|p| p.account == account && (p.until == 0 || p.until > now));
        if book.local.len() != before {
            self.save_local(&book);
        }
        if book.signed != signed {
            self.save_signed(account, &signed);
        }
        if book.signed != signed || book.local.len() != before {
            book.signed = signed;
            self.revision.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// What the last sync said of the account's deletion (ADR 0037 §3),
    /// learned with the pauses after every sync.
    fn learn_deletion(&self, u: &Unlocked) {
        let asked = u.account_deletion().cloned();
        let learned = DeletionSeen {
            deleted: asked.is_some() && u.account_deleted(),
            asked,
        };
        let mut seen = self.deletion_seen();
        if *seen != learned {
            *seen = learned;
            self.save_deletion(&seen);
            self.revision.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Writes `seen` to [`DELETION_SEEN`] (none asked: removes it). Called
    /// with its lock held, so one write at a time. A failure is logged:
    /// after a restart, the next unlock learns it again.
    #[allow(clippy::print_stderr)]
    fn save_deletion(&self, seen: &DeletionSeen) {
        let home = &self.config.home;
        let path = home.file(DELETION_SEEN);
        let saved = match (&seen.asked, klav_client::account(home)) {
            (Some(deletion), Ok(account)) => serde_json::to_vec(&DeletionSeenFile {
                v: DELETION_SEEN_VERSION,
                account: account.account_id,
                deletion: deletion.clone(),
                deleted: seen.deleted,
            })
            .map_err(|e| e.to_string())
            .and_then(|json| {
                klav_client::home::write_private(&path, &json).map_err(|e| e.to_string())
            }),
            _ => match std::fs::remove_file(&path) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.to_string()),
                _ => Ok(()),
            },
        };
        if let Err(e) = saved {
            eprintln!(
                "klavd: cannot save {}: {e}; after a restart, the account's deletion shows again after the next unlock",
                path.display()
            );
        }
    }

    fn revocation_book(&self) -> std::sync::MutexGuard<'_, RevocationBook> {
        self.revocations
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// What the sealed record says now: `status` shows it, and the apps
    /// read again when it changes. A record that cannot be read leaves
    /// `status` as it was: `agent_revocations` answers the error, which the
    /// apps show; `klavd.log` gets no more than that it happened.
    #[allow(clippy::print_stderr)]
    fn note_revocations(
        &self,
        pending: &klav_client::ClientResult<Vec<klav_client::revoke::PendingRevocation>>,
    ) {
        if pending.is_err() {
            eprintln!(
                "klavd: revocations.bin cannot be read; the app and `klav agent show` say why"
            );
        }
        if self.revocation_book().note(pending) {
            self.revision.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// `status`'s `revocations`: while locked, the agents and the counts
    /// only, and none running. A step cut off by the lock may not have
    /// dropped its mark yet, but its result is thrown away
    /// (`unless_locked`): nothing moves until the next unlock.
    fn revocations_in_progress(&self, unlocked: bool) -> Vec<RevocationProgress> {
        let book = self.revocation_book();
        book.pending
            .iter()
            .map(|p| {
                let p = RevocationProgress {
                    running: unlocked && book.running.contains_key(&p.agent_id),
                    ..p.clone()
                };
                if unlocked { p } else { p.counts() }
            })
            .chain(book.finished.values().map(|p| {
                if unlocked {
                    p.clone()
                } else {
                    p.clone().counts()
                }
            }))
            .collect()
    }

    /// A key change of `agent` finished here, skipping `skipped` things
    /// Klav can't reach (`before`: its entry before the last step, which
    /// rotated `rotated_now` projects).
    fn note_finished(
        &self,
        agent: AgentId,
        before: Option<RevocationProgress>,
        skipped: usize,
        rotated_now: usize,
    ) {
        if self
            .revocation_book()
            .finish(agent, before, skipped, rotated_now)
        {
            self.revision.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// `agent` was revoked again ([`RevocationBook::revoked`]).
    fn note_revoked(&self, agent: AgentId) {
        if self.revocation_book().revoked(agent) {
            self.revision.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn rotating(&self, agent: AgentId) -> Rotating<'_> {
        *self.revocation_book().running.entry(agent).or_insert(0) += 1;
        self.revision.fetch_add(1, Ordering::Relaxed);
        Rotating { state: self, agent }
    }

    fn deletion_seen(&self) -> std::sync::MutexGuard<'_, DeletionSeen> {
        self.deletion.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// A sync found the account deleted: `klavd` stops syncing and keeps
    /// the copy, read-only (ADR 0037 §3).
    fn mark_deleted(&self) {
        let mut seen = self.deletion_seen();
        if !seen.deleted {
            seen.deleted = true;
            self.save_deletion(&seen);
            self.revision.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Refuses what `klavd` mediates for agents while the person asked to
    /// delete the account, and after (ADR 0037 §3): a second barrier, the
    /// server already refuses every agent. Checked before a pause, like
    /// the server does.
    fn refuse_deleting(&self) -> Result<(), ErrorBody> {
        let seen = self.deletion_seen();
        let Some(asked) = &seen.asked else {
            return Ok(());
        };
        let error = if seen.deleted {
            ClientError::AccountDeleted(asked.delete_at)
        } else {
            ClientError::AccountDeleting(Some(asked.delete_at))
        };
        Err(error_body(&error))
    }

    /// Whether a pause decided here waits to be sent to the server: one
    /// the server answered as unsupported waits only for an unlock.
    fn pauses_waiting(&self) -> bool {
        self.pause_book().local.iter().any(|p| !p.unsupported)
    }

    /// Keeps the pause decided here for `agent` here only: the server does
    /// not support pausing ([`unsupported`]).
    #[allow(clippy::print_stderr)]
    fn hold_unsupported(&self, agent: Option<AgentId>) {
        let mut book = self.pause_book();
        let mut changed = false;
        for p in book.local.iter_mut().filter(|p| p.agent == agent) {
            changed |= !p.unsupported;
            p.unsupported = true;
        }
        if changed {
            self.save_local(&book);
            self.revision.fetch_add(1, Ordering::Relaxed);
            // Once, when it changes: the watchdog does not send it again.
            eprintln!("klavd: {UNSUPPORTED}");
        }
    }

    /// Applies a pause here at once, before (or without) the server.
    fn pause_here(&self, pause: LocalPause) {
        let mut book = self.pause_book();
        book.local.retain(|p| p.agent != pause.agent);
        book.local.push(pause);
        self.save_local(&book);
        self.revision.fetch_add(1, Ordering::Relaxed);
    }

    /// Forgets the pause decided here for `agent` (none: every agent).
    fn forget_local_pause(&self, agent: Option<AgentId>) {
        let mut book = self.pause_book();
        let before = book.local.len();
        book.local.retain(|p| p.agent != agent);
        if book.local.len() != before {
            self.save_local(&book);
            self.revision.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// The pauses in effect now: signed, and decided here.
    fn pauses_in_effect(&self) -> Vec<PauseInEffect> {
        let now = now_ms();
        let book = self.pause_book();
        let signed = book
            .signed
            .iter()
            .filter(|p| klav_client::pause::in_effect(p, now))
            .map(PauseInEffect::signed);
        let local = book
            .local
            .iter()
            .filter(|p| p.until == 0 || p.until > now)
            .map(|p| PauseInEffect {
                agent_id: p.agent,
                since: p.at,
                until: (p.until != 0).then_some(p.until),
                local: true,
                server_unsupported: p.unsupported,
            });
        signed.chain(local).collect()
    }

    /// Refuses what `klavd` mediates for `agent` while a pause holds it
    /// (ADR 0033 §7.2): its own, or the one of every agent. Without the
    /// agent's ID, only the pause of every agent counts.
    fn refuse_paused(&self, agent: Option<AgentId>) -> Result<(), ErrorBody> {
        let holding = self
            .pauses_in_effect()
            .into_iter()
            .filter(|p| p.agent_id.is_none() || (agent.is_some() && p.agent_id == agent))
            .max_by_key(|p| (p.until.unwrap_or(i64::MAX), p.agent_id.is_some()));
        let Some(p) = holding else {
            return Ok(());
        };
        let paused = klav_proto::agent::AgentPaused {
            scope: if p.agent_id.is_some() {
                klav_proto::agent::PauseScope::Agent
            } else {
                klav_proto::agent::PauseScope::All
            },
            since: p.since,
            until: p.until,
        };
        Err(ErrorBody {
            code: ErrorCode::AgentsPaused,
            message: ClientError::Paused(Some(paused)).to_string(),
            paused: Some(paused),
            presence: None,
        })
    }

    /// Takes an agent's signed request for this one use: refused if this
    /// `klavd` already took it, even in an earlier session. Called only
    /// after the request's signature checked out, under the session lock,
    /// so a forged request with the agent's nonce cannot use it up.
    fn spend_proof(
        &self,
        agent: klav_core::ids::AgentId,
        proof: &klav_proto::rotate::AgentRequestProof,
    ) -> Result<(), ErrorBody> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX));
        let mut spent = self
            .spent_proofs
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        spent.retain(|(_, _, at)| now - at <= 2 * klav_client::rotate::PROOF_WINDOW_MS);
        if spent
            .iter()
            .any(|(a, nonce, _)| *a == agent && nonce.as_slice() == proof.nonce.as_bytes())
        {
            return Err(ErrorBody {
                code: ErrorCode::Denied,
                message: "this signed request was already used".into(),
                paused: None,
                presence: None,
            });
        }
        spent.push((agent, proof.nonce.as_bytes().to_vec(), now));
        Ok(())
    }

    fn current(&self) -> Option<Arc<Slot>> {
        self.slot
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Forgets the unlocked state now and cancels what was using it.
    fn lock_now(&self) {
        let slot = self
            .slot
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        self.generation.send_modify(|g| *g += 1);
        // Every window, passkey window and held connection goes with the
        // session (ADR 0041 §2.3, P5).
        self.presence.close(self.generation());
        drop(slot);
    }

    fn generation(&self) -> u64 {
        *self.generation.borrow()
    }

    /// Runs `work` unless (or until) the daemon locks after generation
    /// `since`: then it is dropped, half-way if need be, and the request
    /// fails as locked.
    async fn unless_locked<T>(
        &self,
        since: u64,
        work: impl std::future::Future<Output = Result<T, ErrorBody>>,
    ) -> Result<T, ErrorBody> {
        let mut generation = self.generation.subscribe();
        if *generation.borrow_and_update() != since {
            return Err(locked());
        }
        let result = tokio::select! {
            result = work => result,
            _ = generation.wait_for(|g| *g != since) => return Err(locked()),
        };
        // Finished just as it locked: the result is not handed out.
        if self.generation() != since {
            return Err(locked());
        }
        result
    }
}

type Reply = Result<(serde_json::Value, Vec<String>), ErrorBody>;

/// Runs the daemon until `stop` completes or a client sends `shutdown`.
pub async fn serve(
    config: Config,
    stop: impl std::future::Future<Output = ()>,
) -> Result<(), String> {
    serve_with(
        config,
        stop,
        Box::new(touchid::Shim),
        #[cfg(test)]
        TestSeams::default(),
    )
    .await
}

/// [`serve`] with its Touch ID, which the tests replace.
pub(crate) async fn serve_with(
    config: Config,
    stop: impl std::future::Future<Output = ()>,
    touch: Box<dyn Biometric>,
    #[cfg(test)] seams: TestSeams,
) -> Result<(), String> {
    let home = config.home.clone();
    home.ensure().map_err(|e| e.to_string())?;
    // One daemon per home: hold an exclusive lock for the whole run.
    let lock_path = home.file("klavd.lock");
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&lock_path)
        .map_err(|e| format!("{}: {e}", lock_path.display()))?;
    klav_client::home::set_mode(&lock_path, 0o600).map_err(|e| e.to_string())?;
    if lock.try_lock().is_err() {
        return Err(format!(
            "another klavd is already running for {}",
            home.dir().display()
        ));
    }
    let socket = home.socket_path();
    // Bound under a name no client uses, proven to be this socket, and
    // only then renamed to the socket's path (finding 2 of the second
    // layer-2 review): a client that connects while `klavd` starts finds
    // nothing at the path, or a stale socket nobody answers, and tries
    // again; it never lands in the probe. A program that connects to the
    // staging name itself is closed unanswered if it queued before
    // `klavd`'s own connection, and served like any client once `klavd` is
    // ready if it queued after it: nothing is answered before then. The
    // rename also replaces a stale socket of a `klavd` that died (we hold
    // the lock).
    let staging = home.file(STAGING_SOCKET);
    if std::fs::symlink_metadata(&staging).is_ok() {
        std::fs::remove_file(&staging).map_err(|e| format!("{}: {e}", staging.display()))?;
    }
    let listener = UnixListener::bind(&staging).map_err(|e| {
        format!(
            "cannot listen on {}: {e} (paths over ~100 bytes do not fit in a Unix socket)",
            staging.display()
        )
    })?;
    klav_client::home::set_mode(&staging, 0o600).map_err(|e| e.to_string())?;
    let socket_id = bound_socket(&listener, &staging, &socket).await?;

    let state = Arc::new(State {
        config,
        slot: std::sync::Mutex::new(None),
        generation: watch::Sender::new(0),
        unlocking: Mutex::new(()),
        shutdown: Notify::new(),
        browsers: {
            let hub = Hub::default();
            // P25's rule, with the presence gate (ADR 0041 §3.1).
            hub.set_focus_rule(true);
            hub
        },
        revision: AtomicU64::new(0),
        spent_proofs: std::sync::Mutex::default(),
        // A restart does not lift what the person paused here, nor forget
        // what the last sync said (until the next one).
        pauses: std::sync::Mutex::new(PauseBook {
            signed: load_signed_pauses(&home),
            local: load_local_pauses(&home),
        }),
        deletion: std::sync::Mutex::new(load_deletion_seen(&home)),
        revocations: std::sync::Mutex::new(RevocationBook::default()),
        presence: Presence::default(),
        socket_id,
        touch,
        passwords: OnePassword::default(),
        setting_change: Mutex::new(()),
        #[cfg(test)]
        seams,
        exe_dir: std::env::current_exe()
            .and_then(std::fs::canonicalize)
            .ok()
            .and_then(|exe| exe.parent().map(std::path::Path::to_path_buf)),
    });
    let watchdog = tokio::spawn(watch(Arc::clone(&state)));
    tokio::pin!(stop);
    let result = loop {
        tokio::select! {
            () = &mut stop => break Ok(()),
            () = state.shutdown.notified() => break Ok(()),
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => {
                    if !same_user(&stream) {
                        continue;
                    }
                    // The tests' key for this connection, taken in the
                    // order they connected.
                    #[cfg(test)]
                    let key = state
                        .seams
                        .keys
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .pop_front();
                    #[cfg(not(test))]
                    let key = None;
                    tokio::spawn(connection(Arc::clone(&state), stream, key));
                }
                Err(e) => break Err(format!("accept: {e}")),
            },
        }
    };
    watchdog.abort();
    state.lock_now();
    // Only its own: a path that names another socket now is left alone.
    if still_ours(&socket, socket_id) {
        let _ = std::fs::remove_file(&socket);
    }
    drop(lock);
    result
}

/// The name `klavd` binds its socket under before it is proven: in the
/// same directory, and no longer than `klavd.sock`, so it fits wherever
/// the socket's path does.
const STAGING_SOCKET: &str = "klavd.new";

/// How long `klavd` waits for its own connection at start-up.
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

/// How long `klavd` waits for a queued connection before it tries its own
/// connect again, while the staging socket's backlog is full.
const PROBE_RETRY: Duration = Duration::from_millis(10);

/// A connect refused because the socket's backlog is full: `ECONNREFUSED`
/// on macOS, `EAGAIN` on Linux. A name with no listener is refused the
/// same way on macOS and retried until the timeout says the socket was
/// replaced.
fn backlog_full(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::WouldBlock
    )
}

/// Where [`bound_socket_with`] lets a test act.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
enum Probe {
    /// The socket is bound at the staging name.
    Bound,
    /// `klavd`'s own connection to the staging name went through.
    Connected,
}

/// The device and inode of the socket file `klavd` bound at `staging`,
/// proven and then renamed to `path` (ADR 0041 §8; findings 2 and 4 of the
/// second layer-2 review).
///
/// A socket's own descriptor doesn't give them: `fstat` on it describes the
/// socket, not the file (checked on macOS: device -1 and another inode).
/// So `klavd` reads the staging name, and proves it named its own socket:
/// it connects to it, and accepts until a connection arrives from this very
/// process (a relay bound there would forward from its own pid); any other
/// connection accepted before its own is closed unanswered, also while its
/// own connect is refused because they filled the backlog. The name must
/// still have the same inode, and still be a socket. Only then is it
/// renamed to `path`, which therefore never names a socket that isn't
/// proven, and `path` must then have that inode. A connection queued after
/// `klavd`'s own is left in the backlog: once the name is `path`, the main
/// loop accepts it like any other client's.
async fn bound_socket(
    listener: &UnixListener,
    staging: &std::path::Path,
    path: &std::path::Path,
) -> Result<(u64, u64), String> {
    bound_socket_with(listener, staging, path, PROBE_TIMEOUT, &mut |_| {}).await
}

async fn bound_socket_with(
    listener: &UnixListener,
    staging: &std::path::Path,
    path: &std::path::Path,
    timeout: Duration,
    pause: &mut (dyn FnMut(Probe) + Send),
) -> Result<(u64, u64), String> {
    let before = socket_file(staging)?;
    let proven = prove(listener, staging, path, before, timeout, pause).await;
    if proven.is_err() && still_ours(staging, before) {
        let _ = std::fs::remove_file(staging);
    }
    proven.map(|()| before)
}

async fn prove(
    listener: &UnixListener,
    staging: &std::path::Path,
    path: &std::path::Path,
    before: (u64, u64),
    timeout: Duration,
    pause: &mut (dyn FnMut(Probe) + Send),
) -> Result<(), String> {
    let changed = || {
        format!(
            "{}: the socket was replaced while klavd started; stop whatever else uses this KLAV_HOME and start klavd again",
            path.display()
        )
    };
    let own = i32::try_from(std::process::id()).ok();
    pause(Probe::Bound);
    let probe = async {
        // `klavd`'s own connection. A program connecting to the staging
        // name in a loop can fill its backlog first (the third layer-2
        // review, C): then the connect is refused, so `klavd` accepts and
        // drops what is queued and tries again, within the timeout.
        let mut ours: Option<UnixStream> = None;
        loop {
            if ours.is_none() {
                match UnixStream::connect(staging).await {
                    Ok(stream) => {
                        ours = Some(stream);
                        pause(Probe::Connected);
                    }
                    Err(e) if backlog_full(&e) => {}
                    Err(e) => return Err(format!("{}: {e}", staging.display())),
                }
            }
            let accepted = if ours.is_some() {
                Some(listener.accept().await)
            } else {
                // Room for the next try: one queued connection, or a
                // short wait.
                tokio::time::timeout(PROBE_RETRY, listener.accept())
                    .await
                    .ok()
            };
            let Some(accepted) = accepted else {
                continue;
            };
            let (stream, _) = accepted.map_err(|e| format!("accept: {e}"))?;
            let pid = stream.peer_cred().ok().and_then(|c| c.pid());
            if ours.is_some() && own.is_some() && pid == own {
                return Ok::<(), String>(());
            }
            // Another process at a name no client uses: not ours, and
            // never answered.
            drop(stream);
        }
    };
    tokio::time::timeout(timeout, probe)
        .await
        .map_err(|_| changed())??;
    if socket_file(staging).map_err(|_| changed())? != before {
        return Err(changed());
    }
    std::fs::rename(staging, path).map_err(|e| format!("{}: {e}", path.display()))?;
    if socket_file(path).map_err(|_| changed())? != before {
        return Err(changed());
    }
    Ok(())
}

/// The device and inode of the socket file at `path`, read without
/// following a symbolic link: anything but a socket is an error.
fn socket_file(path: &std::path::Path) -> Result<(u64, u64), String> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let meta = std::fs::symlink_metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if !meta.file_type().is_socket() {
        return Err(format!("{}: not a socket", path.display()));
    }
    Ok((meta.dev(), meta.ino()))
}

/// Whether `path` still names the socket file `klavd` bound (ADR 0041
/// §8): a relay that renamed it away and bound its own there doesn't, and
/// neither does a symbolic link to it (finding 4 of the second layer-2
/// review).
fn still_ours(path: &std::path::Path, id: (u64, u64)) -> bool {
    socket_file(path).is_ok_and(|found| found == id)
}

/// Keeps other processes of the same user from reading `klavd`'s memory
/// (ADR 0041 §8): on Linux, `prctl(PR_SET_DUMPABLE, 0)` stops `ptrace` and
/// `/proc/<pid>/mem` for them, whatever Yama's setting is. Elsewhere it
/// does nothing (on macOS the hardened runtime of a signed build does it).
pub fn forbid_same_user_debuggers() -> Result<(), String> {
    #[cfg(target_os = "linux")]
    nix::sys::prctl::set_dumpable(false).map_err(|e| format!("PR_SET_DUMPABLE: {e}"))?;
    Ok(())
}

/// Only processes of the user running the daemon may talk to it (T32).
fn same_user(stream: &UnixStream) -> bool {
    match stream.peer_cred() {
        Ok(cred) => cred.uid() == nix::unistd::getuid().as_raw(),
        Err(_) => false,
    }
}

/// The program at the other end of the socket, for the Touch ID prompt
/// (T140): the kernel's pid of the peer and its executable. A hint, not
/// access control; `None` when unknown.
fn peer_source(state: &State, stream: &UnixStream) -> Option<Source> {
    let pid = stream.peer_cred().ok()?.pid()?;
    let path = klav_touchid::process_path(pid)?;
    Source::of_executable(&path, state.exe_dir.as_deref())
}

/// A clock that keeps running while the machine sleeps (macOS
/// `CLOCK_MONOTONIC`, Linux `CLOCK_BOOTTIME`), unlike `Instant`. `None`
/// where there is none that differs from `Instant`'s.
fn sleep_clock() -> Option<Duration> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let id = Some(nix::time::ClockId::CLOCK_BOOTTIME);
    #[cfg(target_vendor = "apple")]
    let id = Some(nix::time::ClockId::CLOCK_MONOTONIC);
    #[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple")))]
    let id: Option<nix::time::ClockId> = None;
    nix::time::clock_gettime(id?).ok().map(Duration::from)
}

/// Why `klavd` locked on its own. It goes to the log (stderr) and says
/// nothing about the account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LockReason {
    /// No request used the account for this long (`--idle-lock`).
    Idle(Duration),
    /// The clock that runs during sleep moved `asleep` while `Instant`
    /// moved `awake`.
    Slept { asleep: Duration, awake: Duration },
    /// No clock that runs during sleep: the wall clock jumped `wall`
    /// forward while `Instant` moved `awake`.
    WallForward { wall: Duration, awake: Duration },
    /// No clock that runs during sleep: the wall clock went back.
    WallBack(Duration),
    /// The screen locked (macOS).
    ScreenLocked,
}

impl std::fmt::Display for LockReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Idle(after) => write!(f, "idle for {after:?}"),
            Self::Slept { asleep, awake } => write!(
                f,
                "the machine slept (the clock that runs during sleep moved {asleep:?}, the awake one {awake:?})"
            ),
            Self::WallForward { wall, awake } => write!(
                f,
                "the wall clock jumped {wall:?} while the awake clock moved {awake:?} (no clock that runs during sleep)"
            ),
            Self::WallBack(by) => write!(
                f,
                "the wall clock went back {by:?} (no clock that runs during sleep)"
            ),
            Self::ScreenLocked => write!(f, "the screen locked"),
        }
    }
}

/// Whether the machine slept between two ticks.
///
/// With a clock that runs during sleep (`asleep`), only it and `Instant`
/// (`awake`) decide: NTP, a hypervisor or the person can step the wall
/// clock without the machine sleeping, and a sleep cannot hide from that
/// clock. Without one, the wall clock decides: forward past the awake
/// time, or back by more than [`CLOCK_BACK`] (a step back could hide a
/// sleep from the forward check).
fn slept(
    wall: Result<Duration, std::time::SystemTimeError>,
    awake: Duration,
    asleep: Option<Duration>,
) -> Option<LockReason> {
    if let Some(asleep) = asleep {
        return (asleep > awake + SLEEP_GAP).then_some(LockReason::Slept { asleep, awake });
    }
    match wall {
        Ok(wall) => (wall > awake + SLEEP_GAP).then_some(LockReason::WallForward { wall, awake }),
        Err(back) => {
            let by = back.duration();
            (by > CLOCK_BACK).then_some(LockReason::WallBack(by))
        }
    }
}

/// The daemon's only log line besides start-up errors (`docs/klavd.md`
/// §2). Started by `klav` or the native host, its stderr is
/// `$KLAV_HOME/klavd.log`.
#[allow(clippy::print_stderr)]
fn log_lock(reason: LockReason) {
    let at = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    eprintln!("klavd: locked on its own at {}: {reason}", rfc3339(at));
}

/// Unix seconds as `2026-11-13T18:22:05Z` (UTC): the same as `build.rs`'s,
/// which `--version` uses.
fn rfc3339(secs: u64) -> String {
    let days = secs / 86_400;
    let rest = secs % 86_400;
    // Howard Hinnant's `civil_from_days`, for days on or after the epoch.
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + u64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    )
}

/// Idle lock and lock on sleep. Never waits for a request in flight.
async fn watch(state: Arc<State>) {
    let mut wall = SystemTime::now();
    let mut mono = Instant::now();
    let mut boot = sleep_clock();
    loop {
        tokio::time::sleep(TICK).await;
        let (now_wall, now_mono, now_boot) = (SystemTime::now(), Instant::now(), sleep_clock());
        let slept = slept(
            now_wall.duration_since(wall),
            now_mono.duration_since(mono),
            now_boot.zip(boot).map(|(n, b)| n.saturating_sub(b)),
        );
        (wall, mono, boot) = (now_wall, now_mono, now_boot);
        // The home directory (and our socket) was removed, or the path
        // names another socket (a relay, ADR 0041 §8): nobody can reach
        // us there any more, or not safely, so stop. A swap that is put
        // back between two ticks isn't seen (P26 is not built).
        if !still_ours(&state.config.home.socket_path(), state.socket_id) {
            state.lock_now();
            state.shutdown.notify_one();
            return;
        }
        let Some(slot) = state.current() else {
            continue;
        };
        let idle = slot.last_use().elapsed() >= state.config.idle_lock;
        let reason = slept
            .or_else(|| idle.then_some(LockReason::Idle(state.config.idle_lock)))
            .or_else(|| klav_touchid::screen_locked().then_some(LockReason::ScreenLocked));
        if let Some(reason) = reason {
            log_lock(reason);
            state.lock_now();
            continue;
        }
        tokio::spawn(flush_outbox(Arc::clone(&state), slot, now_mono));
    }
}

/// Generated passwords waiting in the outbox go to the generator history
/// (ADR 0022 §2); offline, they wait and we retry later. Skipped while a
/// request holds the session, and once the server deleted the account:
/// every upload would get `401`, and what waits stays for the person to
/// copy before deleting this copy (ADR 0037 §3).
async fn flush_outbox(state: Arc<State>, slot: Arc<Slot>, now: Instant) {
    let Ok(mut session) = slot.session.try_lock() else {
        return;
    };
    if session.deleted_at().is_some() {
        return;
    }
    let pauses = state.pauses_waiting();
    if session.flush_retry.is_some_and(|t| now < t)
        || (!pauses && session.unlocked.pending_generated() == 0)
    {
        return;
    }
    let flushed = state
        .unless_locked(slot.generation, async {
            // The pauses decided here first: they stop agents everywhere.
            let mut flushed = !pauses || send_local_pauses(&state, &mut session, false).await.0;
            if session.unlocked.pending_generated() > 0 {
                flushed &= session.unlocked.flush_generated().await.is_ok();
            }
            Ok(flushed)
        })
        .await;
    if let Ok(flushed) = flushed {
        session.flush_retry = (!flushed).then_some(now + FLUSH_RETRY);
    }
}

/// «every agent» or «agent <id>», for messages.
fn whom(agent: Option<AgentId>) -> String {
    agent.map_or_else(|| "every agent".to_owned(), |a| format!("agent {a}"))
}

/// Signs and sends the pauses decided here (ADR 0033 §7.2), dated now: the
/// server takes only recent ones. A pause that ended meanwhile is dropped.
/// One the server answered as unsupported is sent again only on an unlock
/// (`unlocking`). Returns whether none is left waiting, and what to tell
/// the person: a pause decided while locked that is now signed (also
/// written to `$KLAV_HOME/klavd.log`: the watchdog may be the one that
/// sends it, with nobody waiting for the answer), one the server did not
/// take yet (kept, see [`kept`]), one it does not support (kept here only,
/// see [`unsupported`]), and one it refused for good (dropped, and also
/// logged).
#[allow(clippy::print_stderr)]
async fn send_local_pauses(
    state: &State,
    session: &mut Session,
    unlocking: bool,
) -> (bool, Vec<String>) {
    let now = now_ms();
    let account = session.unlocked.account().account_id;
    let pending: Vec<LocalPause> = {
        let mut book = state.pause_book();
        let before = book.local.len();
        book.local
            .retain(|p| p.account == account && (p.until == 0 || p.until > now));
        if book.local.len() != before {
            state.save_local(&book);
        }
        book.local
            .iter()
            .filter(|p| unlocking || !p.unsupported)
            .copied()
            .collect()
    };
    let mut warnings = Vec::new();
    let mut all_sent = true;
    for pause in pending {
        match session
            .unlocked
            .pause_agents(pause.agent, pause.until)
            .await
        {
            Ok(_) if pause.locked => {
                let note = format!(
                    "a pause of {} was decided while Klav was locked ({}), with no password or Touch ID; it is now signed and stops the agents everywhere",
                    whom(pause.agent),
                    decided_from(pause.source)
                );
                eprintln!("klavd: {note}");
                warnings.push(note);
            }
            Ok(_) => {}
            Err(ClientError::Network(_)) => {
                all_sent = false;
                break;
            }
            // Kept here only: an older server would refuse it again.
            Err(e) if unsupported(&e, pause.agent) => {
                state.hold_unsupported(pause.agent);
                warnings.push(UNSUPPORTED.to_owned());
                continue;
            }
            // Kept: the watchdog tries again. Not logged, or it would be
            // every 30 seconds for as long as it lasts.
            Err(e) if kept(&e) => {
                all_sent = false;
                warnings.push(format!(
                    "the server did not take the pause of {} decided on this computer yet ({e}): it holds here, and klavd keeps trying",
                    whom(pause.agent)
                ));
                continue;
            }
            Err(e) => {
                let note = format!(
                    "the pause of {} decided on this computer was not taken by the server: {e}",
                    whom(pause.agent)
                );
                eprintln!("klavd: {note}");
                warnings.push(note);
            }
        }
        // Sent, or refused for good: no longer only here.
        {
            let mut book = state.pause_book();
            book.local.retain(|p| *p != pause);
            state.save_local(&book);
        }
        state.revision.fetch_add(1, Ordering::Relaxed);
    }
    state.learn_pauses(&session.unlocked);
    (all_sent, warnings)
}

/// `pause_agents` (ADR 0033 §7.2, P2): applied here at once, then signed
/// and sent; offline it stays here and the watchdog keeps trying. Locked,
/// only every agent can be paused (one agent is resolved and checked
/// with the account), and it is signed after the next unlock.
async fn pause_agents(
    state: &State,
    agent: Option<AgentId>,
    until: Option<i64>,
    source: Option<Source>,
) -> Reply {
    let at = now_ms();
    let until = until.unwrap_or(0);
    if until != 0 && until <= at {
        return Err(ErrorBody {
            code: ErrorCode::Invalid,
            message: "the pause would already be over".into(),
            paused: None,
            presence: None,
        });
    }
    let account = klav_client::account(&state.config.home)
        .map_err(|e| error_body(&e))?
        .account_id;
    let pause = LocalPause {
        account,
        agent,
        at,
        until,
        locked: false,
        source,
        unsupported: false,
    };
    let Some(slot) = state.current() else {
        if agent.is_some() {
            return Err(ErrorBody {
                code: ErrorCode::Locked,
                message: "klavd is locked: unlock it to pause one agent (pausing every agent works locked)".into(),
                paused: None,
                presence: None,
            });
        }
        state.pause_here(LocalPause {
            locked: true,
            ..pause
        });
        return ok(
            state.pauses_in_effect(),
            vec![
                "paused on this computer only: unlock Klav to sign the pause and stop the agents everywhere"
                    .into(),
            ],
        );
    };
    // Before the network: what `klavd` mediates stops now.
    state.pause_here(pause);
    state
        .unless_locked(slot.generation, async {
            let mut session = slot.session.lock().await;
            let mut warnings = session.warnings();
            match session.unlocked.pause_agents(agent, until).await {
                Ok(_) => state.forget_local_pause(agent),
                Err(ClientError::Network(why)) => warnings.push(format!(
                    "offline ({why}): paused on this computer only; klavd keeps trying to tell the server"
                )),
                // A server error, say: it holds here, and the watchdog
                // sends it again (see `kept`).
                Err(e) if kept(&e) => warnings.push(format!(
                    "the server did not take the pause yet ({e}): paused on this computer only; klavd keeps trying to tell the server"
                )),
                // An older server: it holds here, and is not sent again
                // until an unlock.
                Err(e) if unsupported(&e, agent) => {
                    state.hold_unsupported(agent);
                    warnings.push(UNSUPPORTED.to_owned());
                }
                Err(e) => {
                    state.forget_local_pause(agent);
                    return Err(error_body(&e));
                }
            }
            state.learn_pauses(&session.unlocked);
            ok(state.pauses_in_effect(), warnings)
        })
        .await
}

/// One connection. `key`, only in the tests, replaces what the kernel says
/// about the peer.
async fn connection(state: Arc<State>, stream: UnixStream, key: Option<presence::Key>) {
    // Right away, before the peer's pid could be reused.
    let source = peer_source(&state, &stream);
    let (read, mut write) = stream.into_split();
    let mut reader = BufReader::new(read);
    // Responses and, for an attached extension, events share the socket.
    let (lines, mut outgoing) = mpsc::channel::<Line>(16);
    let writer = tokio::spawn(async move {
        while let Some(line) = outgoing.recv().await {
            if write.write_all(&line).await.is_err() {
                return;
            }
        }
    });
    let conn = state.browsers.connection();
    let shutdown = serve_connection(&state, conn, source, key, &mut reader, &lines).await;
    state.browsers.detach(conn);
    state.presence.forget_connection(conn);
    drop(lines);
    let _ = writer.await;
    // Only now: stopping earlier could exit before the reply reaches the
    // client, which then sees the connection closed.
    if shutdown {
        state.shutdown.notify_one();
    }
}

/// Serves requests until the client hangs up. Returns whether the last one
/// was `shutdown`, answered and queued on `lines`.
async fn serve_connection(
    state: &Arc<State>,
    conn: u64,
    source: Option<Source>,
    key: Option<presence::Key>,
    reader: &mut BufReader<tokio::net::unix::OwnedReadHalf>,
    lines: &mpsc::Sender<Line>,
) -> bool {
    loop {
        let mut shutdown = false;
        let mut line = Zeroizing::new(Vec::new());
        let read = match (&mut *reader)
            .take(MAX_LINE as u64 + 1)
            .read_until(b'\n', &mut line)
            .await
        {
            Ok(n) => n,
            Err(_) => return false,
        };
        if read == 0 {
            return false;
        }
        let (id, reply) = if line.last() != Some(&b'\n') {
            (0, Err(bad_request("line too long or truncated")))
        } else {
            match serde_json::from_slice::<RequestEnvelope>(&line) {
                Ok(envelope) if envelope.v != PROTOCOL_VERSION => (
                    envelope.id,
                    Err(bad_request(&format!(
                        "protocol version {} not supported (this klavd speaks {PROTOCOL_VERSION})",
                        envelope.v
                    ))),
                ),
                Ok(envelope) => (envelope.id, {
                    shutdown = matches!(envelope.request, Request::Shutdown);
                    // The idle lock's clock moves here and nowhere else for
                    // a request: one that counts as use and worked puts off
                    // the lock of the session open when it came. Held
                    // weakly, so a lock meanwhile still wipes its keys.
                    let session = counts_as_use(&envelope.request)
                        .then(|| state.current().as_ref().map(Arc::downgrade))
                        .flatten();
                    // Who asks, read per request (ADR 0041 §1.1: on macOS
                    // the socket's last user).
                    let caller = Some({
                        let mut caller = match key {
                            Some(key) => Caller::fixed(conn, key, source),
                            None => {
                                let identity = crate::peer::identify(reader.get_ref().as_ref());
                                Caller::of(conn, &identity, source)
                            }
                        };
                        // Only a request that asked gets a notice line.
                        caller.notify = envelope.notify.then(|| presence::Notifier {
                            lines: lines.clone(),
                            id: envelope.id,
                        });
                        caller.untyped = envelope.untyped;
                        caller
                    });
                    let reply = route(
                        state,
                        conn,
                        lines,
                        source,
                        caller.as_ref(),
                        envelope.shown,
                        envelope.request,
                    )
                    .await;
                    if reply.is_ok()
                        && let Some(slot) = session.and_then(|s| s.upgrade())
                    {
                        slot.used();
                    }
                    reply
                }),
                // serde's message may quote the input: keep it out.
                Err(_) => (0, Err(bad_request("malformed request"))),
            }
        };
        drop(line);
        let response = match reply {
            Ok((ok, warnings)) => ResponseEnvelope {
                v: PROTOCOL_VERSION,
                id,
                ok: Some(ok),
                error: None,
                warnings,
                notice: None,
            },
            Err(error) => ResponseEnvelope {
                v: PROTOCOL_VERSION,
                id,
                ok: None,
                error: Some(error),
                warnings: Vec::new(),
                notice: None,
            },
        };
        let Ok(bytes) = serde_json::to_vec(&response) else {
            return false;
        };
        drop(response);
        let mut bytes = Zeroizing::new(bytes);
        bytes.push(b'\n');
        if lines.send(bytes).await.is_err() {
            return false;
        }
        if shutdown {
            return true;
        }
    }
}

/// The requests that connect agents and the browser extension; none needs
/// the account unlocked (the agent brings values decrypted under its grant).
async fn handle_browser(
    state: &State,
    conn: u64,
    lines: &mpsc::Sender<Line>,
    caller: Option<&Caller>,
    request: Request,
) -> Reply {
    let hub = &state.browsers;
    match request {
        Request::ExtensionAttach { browser } => {
            let browser: String = browser
                .chars()
                .filter(|c| !c.is_control())
                .take(40)
                .collect();
            // How its presence prompt names it (ADR 0041 §3.1, own choice
            // 3): "a browser" when its peer shares the browser's key
            // (macOS), "this browser connection" otherwise.
            let connection_keyed = caller.is_none_or(|c| {
                matches!(
                    c.key,
                    presence::Key::Connection(_) | presence::Key::NoWindow(_)
                )
            });
            hub.attach(conn, browser, lines.clone(), connection_keyed);
            ok(serde_json::json!({}), Vec::new())
        }
        Request::ExtensionPresence { event, password } => {
            // Checked only as the answer to a presence event this
            // connection got and still waits on (own choice 32).
            if !hub.presence_waits(conn, event) {
                return Err(ErrorBody {
                    code: ErrorCode::NotFound,
                    message: "no such event".into(),
                    paused: None,
                    presence: None,
                });
            }
            let Some(slot) = state.current() else {
                return Err(locked());
            };
            // The session's own password (§2.3), one check at a time. A
            // wrong one leaves the event waiting: the frame asks again.
            state.passwords.check(slot.password.as_ref(), password)?;
            hub.presence_verified(conn, event)?;
            ok(serde_json::json!({}), Vec::new())
        }
        Request::ExtensionReply {
            event,
            ok: value,
            error,
        } => {
            let result = match error {
                Some(e) => Err(e),
                None => Ok(value.unwrap_or(serde_json::Value::Null)),
            };
            hub.reply(conn, event, result)?;
            ok(serde_json::json!({}), Vec::new())
        }
        Request::BrowserTab => ok(hub.tab().await?, Vec::new()),
        Request::BrowserFill {
            tab,
            host,
            agent,
            agent_id,
            reason,
            item,
            kind,
            fields,
            selectors,
            submit,
        } => {
            // A second barrier: the server already refuses a paused
            // agent's access (ADR 0033 §7.2).
            state.refuse_deleting()?;
            state.refuse_paused(agent_id)?;
            // The connection's presence first (ADR 0041 §3.1). It needs
            // the unlocked session (the setting, the password's check), so
            // a locked `klavd` says `locked`.
            let Some(slot) = state.current() else {
                return Err(locked());
            };
            browser_presence(
                state,
                &slot,
                &tab,
                BrowserCause::Fill,
                &agent,
                Title::Item(item),
                None,
            )
            .await?;
            let report = hub
                .fill(&tab, host, agent, reason, kind, fields, selectors, submit)
                .await?;
            ok(report, Vec::new())
        }
        _ => Err(bad_request("not a browser request")),
    }
}

/// Where an extension connection's presence prompt takes the item's title
/// from.
enum Title {
    /// Already read from the vault (an assisted change, a passkey's login).
    Known(String),
    /// The item a fill names, looked up in the vault only if a prompt
    /// shows: `None` from an older SDK, and a missing item, name none.
    Item(Option<ItemId>),
}

/// ADR 0041 §3.1: before an agent's event carries values to the extension
/// connection behind `tab`, that connection's presence. Under 5 minutes or
/// While unlocked, one verification lets agents fill through it until
/// Klav locks or it closes; under Always, every event asks. Touch ID where
/// `klavd` can show it, else the master password in Klav's own frame of
/// that browser ([`Event::Presence`]). Canceled, failed or unanswered:
/// `denied`, with what the agent tells the person. With more than one
/// connection attached, P25's rule first, so nobody is asked for a target
/// that would be refused. Only with the gate on.
///
/// [`Event::Presence`]: crate::protocol::Event::Presence
async fn browser_presence(
    state: &State,
    slot: &Slot,
    tab: &str,
    event: BrowserCause,
    agent: &str,
    title: Title,
    site: Option<&str>,
) -> Result<(), ErrorBody> {
    let hub = &state.browsers;
    let (conn, _) = hub.tab_ids(tab)?;
    let Some(setting) = state.presence.extension_needs(slot.generation, conn)? else {
        return Ok(());
    };
    hub.focus(conn).await?;
    let device = presence::Device {
        touch: state.touch.as_ref(),
        touch_id: state.config.touch_id,
        check: slot.password.as_ref(),
        passwords: &state.passwords,
    };
    let touch = presence::Verify::touch_id_available(&device);
    let clean = |text: &str| crate::prompt::clean(text, crate::prompt::MAX_NAME);
    let title = match title {
        Title::Known(title) => Some(clean(&title)),
        Title::Item(None) => None,
        Title::Item(Some(item)) => {
            // Never behind an open dialog when Touch ID follows (the third
            // layer-2 review, finding A).
            let session = if touch {
                state.presence.lock(&slot.session, true, None).await?.0
            } else {
                slot.session.lock().await
            };
            let u = &session.unlocked;
            u.find_item(&item.to_string())
                .and_then(|loc| u.item_summary(loc))
                .ok()
                .map(|summary| clean(&summary.title))
        }
    };
    let attached = u32::try_from(hub.attached()).unwrap_or(u32::MAX);
    let until_lock = setting != uv::Window::Always;
    let ask = BrowserAsk {
        event,
        agent: clean(agent),
        title,
        site: site.map(clean),
        attached: (attached > 1).then_some(attached),
        connection: hub.connection_keyed(conn),
    };
    if touch {
        let reason = Prompt::Browser {
            ask: &ask,
            until_lock,
        }
        .reason(Lang::current(), None);
        let verified = {
            let _open = state.presence.open_prompt(PromptKind::Presence)?;
            tokio::task::block_in_place(|| presence::Verify::touch_id(&device, &reason))
        };
        match verified {
            Ok(()) => {
                return state
                    .presence
                    .extension_verified(slot.generation, conn, setting);
            }
            Err(presence::Refused::Failed(_)) => return Err(crate::browser::declined()),
            // Locked out meanwhile: the master password, as without it.
            Err(presence::Refused::Unavailable) => {}
        }
    }
    let ask = PresenceAsk {
        key: PresenceKey::Connection,
        window: setting,
        terminal: None,
        declared: false,
        lasts: until_lock.then_some(AskLasts::UntilLock),
        value: None,
        browser: Some(ask),
        protected: None,
    };
    hub.ask_presence(tab, ask).await?;
    state
        .presence
        .extension_verified(slot.generation, conn, setting)
}

fn bad_request(message: &str) -> ErrorBody {
    ErrorBody {
        code: ErrorCode::BadRequest,
        message: message.to_owned(),
        paused: None,
        presence: None,
    }
}

fn locked() -> ErrorBody {
    ErrorBody {
        code: ErrorCode::Locked,
        message: "klavd is locked: run `klav unlock`".into(),
        paused: None,
        presence: None,
    }
}

/// Maps a client error to a wire error.
pub(crate) fn error_body(e: &ClientError) -> ErrorBody {
    let code = match e {
        ClientError::NotLoggedIn => ErrorCode::NotLoggedIn,
        ClientError::WrongCredentials => ErrorCode::WrongCredentials,
        ClientError::Rollback(_) => ErrorCode::Rollback,
        ClientError::Security(_) => ErrorCode::Security,
        ClientError::NotFound(_) => ErrorCode::NotFound,
        // A quota or an invite: the message is what the person reads, as
        // the server said it (ADR 0048 §2, §3.2), without a wire code of
        // its own.
        ClientError::Ambiguous(_)
        | ClientError::Invalid(_)
        | ClientError::Reference(_)
        | ClientError::Model(_)
        | ClientError::QuotaExceeded(_)
        | ClientError::InviteInvalid => ErrorCode::Invalid,
        ClientError::Conflict(_) | ClientError::LaterPause(_) | ClientError::LaterRevocation(_) => {
            ErrorCode::Conflict
        }
        ClientError::Network(_) => ErrorCode::Network,
        ClientError::SessionExpired => ErrorCode::SessionExpired,
        ClientError::Denied(_) => ErrorCode::Denied,
        ClientError::Paused(_) => ErrorCode::AgentsPaused,
        ClientError::AccountDeleting(_) => ErrorCode::AccountDeleting,
        ClientError::AccountDeleted(_) => ErrorCode::AccountDeleted,
        ClientError::DeletionUnsupported => ErrorCode::Invalid,
        _ => ErrorCode::Internal,
    };
    ErrorBody {
        code,
        message: e.to_string(),
        paused: None,
        presence: None,
    }
}

fn ok(value: impl Serialize, warnings: Vec<String>) -> Reply {
    serde_json::to_value(value)
        .map(|v| (v, warnings))
        .map_err(|e| ErrorBody {
            code: ErrorCode::Internal,
            message: e.to_string(),
            paused: None,
            presence: None,
        })
}

fn status(state: &State, session: Option<&Slot>, caller: Option<&Caller>) -> DaemonStatus {
    let account = klav_client::account(&state.config.home).ok();
    // Sealed, read at unlock: nothing to report while locked (ADR 0041
    // §2.4, Omar's decision on Q-N2). The passkey window is the caller's
    // key's (§2.5).
    let (passkey_uv, passkey_verified) =
        match session.and_then(|s| state.presence.settings(s.generation).ok()) {
            Some(settings) => (
                Some(settings.passkey),
                caller.is_some_and(|c| !state.presence.passkey_needs(c, Instant::now())),
            ),
            None => (None, false),
        };
    // One lock, released before the rest: two guards in the literal below
    // would both live to its end and deadlock.
    let deletion = {
        let seen = state.deletion_seen();
        (seen.asked.clone(), seen.deleted)
    };
    // One lock, released before `revocations_in_progress` takes it again.
    let record = {
        let book = state.revocation_book();
        (book.unreadable, book.newer)
    };
    DaemonStatus {
        version: env!("CARGO_PKG_VERSION").to_owned(),
        commit: state.config.build.as_ref().map(|b| b.commit.clone()),
        commit_time: state.config.build.as_ref().map(|b| b.commit_time),
        protocol: PROTOCOL_VERSION,
        pid: std::process::id(),
        logged_in: account.is_some(),
        unlocked: session.is_some(),
        email: account.map(|a| a.email),
        unlocked_with: session.map(|s| s.method.to_owned()),
        idle_lock_secs: state.config.idle_lock.as_secs(),
        locks_in_secs: session.map(|s| {
            state
                .config
                .idle_lock
                .saturating_sub(s.last_use().elapsed())
                .as_secs()
        }),
        touch_id: state
            .touch
            .status(&state.config.home, state.config.touch_id),
        revision: state.revision.load(Ordering::Relaxed),
        syncing: session.is_some_and(Slot::is_syncing),
        passkey_uv,
        passkey_verified,
        browsers: state.browsers.seen(),
        agents_paused: state.pauses_in_effect(),
        account_deletion: deletion.0,
        account_deleted: deletion.1,
        revocations: state.revocations_in_progress(session.is_some()),
        // What the caller's own unlock would open (ADR 0041 §2.4).
        presence: caller.map(|c| presence::status_presence(&state.presence, c)),
        revocations_unreadable: record.0,
        revocations_newer: record.1,
        already_unlocked: false,
    }
}

/// `status` as the program that asked may see it: the browser extension,
/// which never gets the list of agents, does not get the revocations of
/// agents either (ADR 0033, amendment of 2026-11-10, F4).
fn for_source(mut status: DaemonStatus, source: Option<Source>) -> DaemonStatus {
    if source == Some(Source::Browser) {
        status.revocations.clear();
        status.revocations_unreadable = false;
        status.revocations_newer = false;
    }
    status
}

/// Reads that answer without syncing first and sync in the background
/// (ADR 0026): the ones that only look at the local copy, and `approvals`
/// and `tasks`, which read the server themselves and take only titles
/// and sites from the copy.
fn reads_without_syncing(request: &Request) -> bool {
    matches!(
        request,
        Request::Approvals { .. }
            | Request::Tasks { .. }
            | Request::SecretRequests { .. }
            | Request::Vaults
            | Request::Projects { .. }
            | Request::List { .. }
            | Request::View { .. }
            | Request::Suggest { .. }
            | Request::Autofill { .. }
            | Request::Totp { .. }
            | Request::PasskeyCandidates { .. }
            | Request::PasskeyGet { .. }
            | Request::GeneratorHistory
            | Request::GeneratedValue { .. }
            | Request::PasswordHistory { .. }
            | Request::PreviousPassword { .. }
            // Only this device's copy of the audit log: no network.
            | Request::AuditStatus
    )
}

/// The person's writes (ADR 0037 §3, D-C): refused once the server deleted
/// the account, before anything runs, as `writing()` in `klav-ffi`. Most
/// would reach the server first and get its `401`, but some write this
/// device's files before the network or without it: the generator outbox
/// (`generator_record`, `generator_delete`), the cache that
/// `reset_cache` empties before it syncs (and could never fill again), the
/// pause `resume_agents` lifts here first. What only reads is not here,
/// nor what is not the vault (the breach check setting, the passkey
/// window, this device's copy of the audit log), nor pausing agents:
/// stopping them is never what to refuse, and they are refused anyway.
fn person_write(request: &Request) -> bool {
    matches!(
        request,
        Request::CreateVault { .. }
            | Request::CreateProject { .. }
            | Request::SetProjectRepos { .. }
            | Request::SetAgentLabel { .. }
            | Request::Create { .. }
            | Request::Edit { .. }
            | Request::Trash { .. }
            | Request::Attach { .. }
            | Request::PasskeyCreate { .. }
            | Request::ResolvePending { .. }
            | Request::GeneratorRecord { .. }
            | Request::GeneratorDelete { .. }
            | Request::ImportApply { .. }
            | Request::ResetCache
            | Request::ApproveAgent { .. }
            | Request::GrantChangeApply { .. }
            | Request::DecideApproval { .. }
            | Request::DecideTask { .. }
            | Request::AddToTask { .. }
            | Request::EndTask { .. }
            | Request::FulfillSecretRequest { .. }
            | Request::DenySecretRequest { .. }
            | Request::RevokeAgent { .. }
            | Request::ProxyUse { .. }
            | Request::ProxyGrant { .. }
            | Request::ProxyRevoke { .. }
            | Request::ProxyIssuerAdd { .. }
            | Request::ProxyIssuerRemove { .. }
            | Request::LocalClientChange { .. }
            | Request::McpGatewayOn { .. }
            | Request::ResumeAgents { .. }
            | Request::DenyAgent { .. }
            | Request::AgentRotateConfirm { .. }
            | Request::AgentRotateCancel { .. }
            | Request::OfferTask { .. }
    )
}

/// Whether a request that works counts as use for the idle lock
/// (`--idle-lock`, T31): only what hands out or changes something keeps
/// an unlocked `klavd` open. Reading lists and state does not, so a client
/// that polls (the Mac app asks for approvals, agents and tasks every
/// 10 s) never keeps it unlocked. The only place that decides it: every
/// operation is named, with no arm that picks for a new one, and
/// `docs/klavd.md` lists the same three groups (a test holds them equal).
fn counts_as_use(request: &Request) -> bool {
    match request {
        // Not use: they only list or report state, hand out no secret value
        // and change nothing in the vault, on the server or in a setting.
        // The three `sandbox_list` reads verify the audit log as
        // `verify_audit` does, and may post this device's signed head of
        // it as it always did: bookkeeping of the read, not a change the
        // person asked for.
        Request::Status
        | Request::Vaults
        | Request::Projects { .. }
        | Request::Environments { .. }
        | Request::Environment { .. }
        | Request::List { .. }
        | Request::Suggest { .. }
        | Request::PasskeyCandidates { .. }
        | Request::Agents
        | Request::AgentLabels
        | Request::Approvals { .. }
        | Request::Tasks { .. }
        | Request::TaskLog { .. }
        | Request::TaskProgress { .. }
        | Request::SecretRequests { .. }
        | Request::AgentExposure { .. }
        | Request::AgentRevocations
        | Request::GrantEditor { .. }
        | Request::GrantChangePrepare { .. }
        | Request::ProxyStatus
        | Request::ProxyGrantPreview { .. }
        | Request::ProxyIssuerPreview { .. }
        | Request::LocalClientPreview { .. }
        | Request::McpGateway
        | Request::AuditLog { .. }
        | Request::AuditStatus
        | Request::ItemActivity { .. }
        | Request::SandboxList
        | Request::SandboxListFlagged
        | Request::SandboxListChecked
        | Request::GeneratorHistory
        | Request::PasswordHistory { .. }
        | Request::ImportPreview { .. }
        | Request::ExtensionAttach { .. }
        | Request::ExtensionReply { .. }
        | Request::ExtensionPresence { .. }
        | Request::BrowserTab
        | Request::Hold => false,
        // Use only when it changes the setting; reading it is not.
        Request::HealthSettings { breach_check } => breach_check.is_some(),
        Request::PasskeyUv { window, .. } => window.is_some(),
        Request::PresenceWindow { window, .. } => window.is_some(),
        // Use: it returns a secret value or a decrypted field, signs,
        // approves or denies, writes to the vault, to the server or to this
        // device, unlocks or locks, or fills. Also the ones that are hard
        // to place: `sync` (it writes this device's copy), `verify_audit`
        // (it signs the log's head), `vault_health` and `reused_offer`
        // (they decrypt every password to compare them), `confirm_presence`
        // (Touch ID), the imports kept in memory, and
        // `agent_rotate_pending` (it uses up the agent's signed request).
        Request::Unlock { .. }
        | Request::Lock
        | Request::Shutdown
        | Request::Sync
        | Request::ResetCache
        | Request::CreateVault { .. }
        | Request::CreateProject { .. }
        | Request::View { .. }
        | Request::Create { .. }
        | Request::Edit { .. }
        | Request::Trash { .. }
        | Request::Totp { .. }
        | Request::Resolve { .. }
        | Request::Autofill { .. }
        | Request::PasskeyGet { .. }
        | Request::PasskeyCreate { .. }
        | Request::Attach { .. }
        | Request::ApproveAgent { .. }
        | Request::DenyAgent { .. }
        | Request::DecideApproval { .. }
        | Request::DecideTask { .. }
        | Request::AddToTask { .. }
        | Request::EndTask { .. }
        | Request::FulfillSecretRequest { .. }
        | Request::DenySecretRequest { .. }
        | Request::RevokeAgent { .. }
        | Request::GrantChangeApply { .. }
        | Request::ProxyUse { .. }
        | Request::ProxyGrant { .. }
        | Request::ProxyRevoke { .. }
        | Request::ProxyIssuerAdd { .. }
        | Request::ProxyIssuerRemove { .. }
        | Request::LocalClientChange { .. }
        | Request::McpGatewayOn { .. }
        | Request::PauseAgents { .. }
        | Request::ResumeAgents { .. }
        | Request::ConfirmPresence { .. }
        | Request::CancelAccountDeletion { .. }
        | Request::VerifyAudit
        | Request::SandboxRevoke { .. }
        | Request::AuditReset
        | Request::GeneratorRecord { .. }
        | Request::GeneratedValue { .. }
        | Request::GeneratorDelete { .. }
        | Request::PreviousPassword { .. }
        | Request::VaultHealth
        | Request::ImportAdd { .. }
        | Request::ImportApply { .. }
        | Request::ImportCancel { .. }
        | Request::BrowserFill { .. }
        | Request::AgentPasskeyArm { .. }
        | Request::AgentPasskeyUse { .. }
        | Request::AgentRotateBegin { .. }
        | Request::AgentRotateConfirm { .. }
        | Request::AgentRotateCancel { .. }
        | Request::AgentRotatePending { .. }
        | Request::ResolvePending { .. }
        | Request::ReusedOffer { .. }
        | Request::OfferTask { .. }
        | Request::SetAgentLabel { .. }
        | Request::SetProjectRepos { .. }
        | Request::EnvironmentImportReview { .. }
        | Request::EnvironmentSave { .. }
        | Request::EnvironmentTrash { .. } => true,
    }
}

impl Session {
    /// The date of the deletion when the server already deleted the
    /// account: as the last sync said, or as this device's own copy
    /// (`deletion.bin`) says from the unlock on.
    fn deleted_at(&self) -> Option<i64> {
        let deleted = self.deleted.is_some() || self.unlocked.account_deleted();
        deleted.then(|| self.unlocked.account_deletion().map_or(0, |d| d.delete_at))
    }
}

/// `vault_health` (ADR 0022 §4): the local part under the session lock,
/// and the breach check, a network call made only if the person turned it
/// on, after releasing it, so it never holds up other requests.
async fn vault_health(state: &State) -> Reply {
    let Some(slot) = state.current() else {
        return Err(locked());
    };
    let (scan, warnings) = state
        .unless_locked(slot.generation, async {
            let mut session = slot.session.lock().await;
            let refreshed = refresh(state, &mut session, false).await;
            track(state, &mut session);
            let warnings = refreshed?;
            let unlocked = &session.unlocked;
            let now = SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX));
            // zxcvbn over every password is CPU work: keep it off the async
            // workers.
            let scan = tokio::task::block_in_place(|| unlocked.health_scan(now));
            Ok((scan, warnings))
        })
        .await?;
    let settings = HealthSettings::load(&state.config.home).map_err(|e| error_body(&e))?;
    // Locking while the breach check waits on the network drops it and the
    // report is not handed out.
    let report = state
        .unless_locked(slot.generation, async {
            Ok(scan
                .finish(settings.breach_check.then_some(BREACH_API))
                .await)
        })
        .await?;
    ok(report, warnings)
}

/// Touch ID (or `password`) before a passkey use, unless the window still
/// covers it (ADR 0020 §8). A password that comes along is always checked.
/// Either way the use consumes the verification it relied on. `behind`:
/// see [`dispatch`].
fn passkey_presence(
    state: &State,
    slot: &Slot,
    password: Option<klav_client::ops::SecretText>,
    reason: &str,
    caller: Option<&Caller>,
    behind: bool,
) -> Result<(), ErrorBody> {
    // The passkey window per key, from the sealed setting (ADR 0041 §2.5).
    // Every request has a caller; fail closed if not.
    let Some(caller) = caller else {
        return Err(locked());
    };
    if password.is_none() && !state.presence.passkey_needs(caller, Instant::now()) {
        state.presence.passkey_spend(caller);
        return Ok(());
    }
    if behind && password.is_none() {
        return Err(presence::busy());
    }
    state.confirm(slot, password, reason)?;
    state
        .presence
        .passkey_checked(slot.generation, caller, Instant::now());
    Ok(())
}

impl State {
    /// A real verification before an operation that already asks (ADR
    /// 0014; ADR 0041 §2.3): `password`, which counts only as the master
    /// password of `slot`'s session in memory, or else Touch ID with
    /// `reason`.
    fn confirm(
        &self,
        slot: &Slot,
        password: Option<klav_client::ops::SecretText>,
        reason: &str,
    ) -> Result<(), ErrorBody> {
        match password {
            Some(password) => self.passwords.check(slot.password.as_ref(), password),
            None => self.touch_id(reason),
        }
    }

    /// Touch ID with `reason`, blocking on the prompt, only while no other
    /// prompt of `klavd`'s is open (ADR 0041 §2.4, finding 5 of the second
    /// layer-2 review), else `presence_busy`.
    fn touch_id(&self, reason: &str) -> Result<(), ErrorBody> {
        if !self.config.touch_id {
            return Err(touchid::turned_off());
        }
        #[cfg(test)]
        self.seams.before_prompt();
        let _open = self.presence.open_prompt(PromptKind::Presence)?;
        tokio::task::block_in_place(|| self.touch.authenticate(reason))
            .map_err(|e| touchid::refused(&e))
    }
}

/// `confirm_presence` (ADR 0037 §1): Touch ID with this Mac's Secure
/// Enclave key, which the Mac's password does not open. Deletes nothing,
/// needs no unlock, takes no password: the caller asks for the master
/// password next and talks to the server itself.
fn confirm_presence(state: &State, purpose: PresencePurpose, source: Option<Source>) -> Reply {
    let home = &state.config.home;
    let ctx = klav_client::account(home)
        .map_err(|e| error_body(&e))?
        .local_context();
    let reason = match purpose {
        PresencePurpose::DeleteAccount => Prompt::DeleteAccount.reason(Lang::current(), source),
    };
    if !state.config.touch_id {
        return Err(touchid::turned_off());
    }
    // Its prompt is one of `klavd`'s: one at a time (ADR 0041 §2.4).
    let _open = state.presence.open_prompt(PromptKind::Presence)?;
    tokio::task::block_in_place(|| state.touch.confirm_with_key(home, ctx, &reason))?;
    ok(serde_json::json!({ "ok": true }), Vec::new())
}

/// `health_settings`: the breach check's setting of this home, and what
/// turning it on sends (ADR 0022 §4).
fn health_settings(state: &State, breach_check: Option<bool>) -> Reply {
    let mut settings = HealthSettings::load(&state.config.home).map_err(|e| error_body(&e))?;
    if let Some(on) = breach_check {
        settings.breach_check = on;
        settings
            .save(&state.config.home)
            .map_err(|e| error_body(&e))?;
    }
    ok(
        serde_json::json!({
            "breach_check": settings.breach_check,
            "notice": klav_client::health::BREACH_CHECK_NOTICE,
        }),
        Vec::new(),
    )
}

/// `agent_rotate_begin` (ADR 0022 §5, steps 2–5). The session lock is
/// taken for the checks and for storing the pending password, and released
/// while the browser answers, so other requests are not held up.
async fn rotate_begin(
    state: &State,
    tab: String,
    step: klav_client::rotate::RotationStep,
    submit: bool,
) -> Reply {
    let Some(slot) = state.current() else {
        return Err(locked());
    };
    // Locking at any step drops the change where it is: nothing more
    // reaches the page and the answer is not handed out.
    state
        .unless_locked(
            slot.generation,
            rotate_steps(state, &slot, tab, step, submit),
        )
        .await
}

/// The steps of [`rotate_begin`], under one lock generation.
async fn rotate_steps(
    state: &State,
    slot: &Slot,
    tab: String,
    step: klav_client::rotate::RotationStep,
    submit: bool,
) -> Reply {
    let e = |e: ClientError| error_body(&e);
    // 1. The agent's signed request, its task and the item.
    let (plan, mut warnings) = {
        let mut session = slot.session.lock().await;
        let refreshed = refresh(state, &mut session, false).await;
        track(state, &mut session);
        let warnings = refreshed?;
        state.refuse_deleting()?;
        state.refuse_paused(Some(step.agent_id))?;
        let plan = session.unlocked.rotation_begin(&step).await.map_err(e)?;
        // Spent only once its signature checks out: a forged request with
        // the agent's nonce must not use up the real one.
        state.spend_proof(step.agent_id, &step.request)?;
        (plan, warnings)
    };
    // 2. Where the tab would fill, and that frame's rules. The frame's
    //    address comes from the browser.
    let target = state
        .browsers
        .rotate_probe(&tab, plan.host.clone(), plan.urls.clone())
        .await?;
    plan.check_page(&target.url).map_err(e)?;
    // The extension connection's presence before the fill step carries
    // values to it, and before anything is stored (ADR 0041 §3.1).
    browser_presence(
        state,
        slot,
        &tab,
        BrowserCause::PasswordChange,
        &plan.agent_name,
        Title::Known(plan.title.clone()),
        None,
    )
    .await?;
    // 3. The new password, stored as pending in a new version of the item
    //    before anything touches the page. If this fails, nothing is filled.
    let new = {
        let mut session = slot.session.lock().await;
        session
            .unlocked
            .rotation_store_pending(&plan, &target.rules)
            .await
            .map_err(e)?
    };
    // 4. Fill. A failure here leaves the pending password in the item: the
    //    person (or the agent's cancel) decides.
    let report = state
        .browsers
        .rotate_fill(
            &tab,
            &target,
            plan.host.clone(),
            plan.agent_name.clone(),
            plan.reason.clone(),
            plan.current().clone(),
            new,
            submit,
        )
        .await
        .map_err(|mut error| {
            error.message = format!(
                "{}{}{}: cancel the change (rotate_cancel) or ask the person",
                error.message,
                crate::protocol::ROTATE_KEPT_PENDING,
                plan.title
            );
            error
        })?;
    let filled = report
        .get("filled")
        .cloned()
        .unwrap_or_else(|| serde_json::json!([]));
    let mut answer = serde_json::json!({
        "filled": filled,
        "pending_id": plan.rotation_id,
    });
    if submit {
        for key in ["submitted", "navigated", "url_after"] {
            if let Some(v) = report.get(key) {
                answer[key] = v.clone();
            }
        }
    }
    if !target.focused {
        warnings
            .push("no password box had the focus: Klav filled the page's change form".to_owned());
    }
    ok(answer, warnings)
}

/// `agent_passkey_arm` (ADR 0020 §9, steps 3–4): `klavd` checks the
/// agent's signed request and its task on its own, then arms one use in the
/// tab and tells the extension. A locked `klavd` refuses: Klav never
/// unlocks for an agent.
async fn agent_passkey_arm(
    state: &State,
    tab: String,
    step: klav_client::agent_passkeys::PasskeyArmStep,
) -> Reply {
    let Some(slot) = state.current() else {
        return Err(locked());
    };
    state
        .unless_locked(slot.generation, arm_steps(state, &slot, tab, step))
        .await
}

/// The steps of [`agent_passkey_arm`], under one lock generation.
async fn arm_steps(
    state: &State,
    slot: &Slot,
    tab: String,
    step: klav_client::agent_passkeys::PasskeyArmStep,
) -> Reply {
    let (conn, tab_id) = state.browsers.tab_ids(&tab)?;
    let (plan, warnings) = {
        let mut session = slot.session.lock().await;
        let refreshed = refresh(state, &mut session, false).await;
        track(state, &mut session);
        let warnings = refreshed?;
        state.refuse_deleting()?;
        state.refuse_paused(Some(step.agent_id))?;
        let plan = session
            .unlocked
            .passkey_arm(&step)
            .await
            .map_err(|e| error_body(&e))?;
        // Spent only once its signature checks out (see `rotate_steps`).
        state.spend_proof(step.agent_id, &step.request)?;
        (plan, warnings)
    };
    // The extension connection's presence before the use is armed there,
    // naming the rpId `klavd` armed from the vault, never the site the
    // agent claims (ADR 0041 §3.1, T140).
    browser_presence(
        state,
        slot,
        &tab,
        BrowserCause::PasskeySignIn,
        &plan.agent_name,
        Title::Known(plan.title.clone()),
        Some(&plan.rp_id),
    )
    .await?;
    let secret = token::generate_token("kpa_");
    let digest = token::token_digest(&secret);
    slot.arm(Arm {
        digest,
        conn,
        tab_id,
        host: plan.host.clone(),
        rp_id: plan.rp_id.clone(),
        item: plan.item,
        agent: plan.agent_id,
        task: plan.task_id,
        deadline: Instant::now() + ARM_TTL,
    });
    // The session lock is free here: if the page already waits, the
    // extension signs through `agent_passkey_use` before it answers.
    let answer = state
        .browsers
        .passkey_arm(
            &tab,
            plan.host,
            plan.rp_id.clone(),
            plan.item.to_string(),
            plan.title,
            plan.agent_name,
            plan.reason,
            klav_client::ops::SecretText::new(secret.expose_secret()),
            u64::try_from(ARM_TTL.as_millis()).unwrap_or(u64::MAX),
        )
        .await;
    let said_used = match answer {
        Ok(value) => value
            .get("used")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false),
        Err(error) => {
            slot.disarm(&digest);
            return Err(error);
        }
    };
    // Used only if `klavd` signed it: the extension's word is not enough.
    let used = said_used && !slot.is_armed(&digest);
    ok(
        PasskeyArmed {
            used,
            rp_id: plan.rp_id,
            expires_in_s: (!used).then_some(ARM_TTL.as_secs()),
        },
        warnings,
    )
}

/// `agent_passkey_use` (ADR 0020 §9, step 4): the extension answers a
/// page's sign-in with the use an agent armed in that tab. Only from the
/// connection and tab it was armed for, once, before it expires, on the
/// armed host and for the armed rpId and login. UV comes from the task's
/// approval (§8): no Touch ID, and the person's window is not spent.
async fn agent_passkey_use(
    state: &Arc<State>,
    conn: u64,
    tab_id: u64,
    origin: &str,
    rp_id: Option<&str>,
    challenge: &str,
    secret: &klav_client::ops::SecretText,
) -> Reply {
    let Some(slot) = state.current() else {
        return Err(locked());
    };
    let denied = |message: String| ErrorBody {
        code: ErrorCode::Denied,
        message,
        paused: None,
        presence: None,
    };
    let Some(arm) = slot.take_arm(&token::digest_str(secret.expose()), conn, tab_id) else {
        return Err(denied(
            "no agent's passkey use is armed in this tab (it was used, it expired, or Klav locked)"
                .into(),
        ));
    };
    // Armed before a pause: not used after it (ADR 0033 §7.2).
    state.refuse_deleting()?;
    state.refuse_paused(Some(arm.agent))?;
    if klav_core::site::fillable_host(origin).ok().as_deref() != Some(arm.host.as_str()) {
        return Err(denied(format!(
            "the use was armed for {}, not for this page: Klav did not sign",
            arm.host
        )));
    }
    state
        .unless_locked(slot.generation, async {
            let e = |e: ClientError| error_body(&e);
            let session = slot.session.lock().await;
            let u = &session.unlocked;
            let site = u.passkey_candidates(origin, rp_id, &[]).map_err(e)?.rp_id;
            if site.as_deref() != Some(arm.rp_id.as_str()) {
                return Err(denied(format!(
                    "the use was armed for the passkey of {}: Klav did not sign",
                    arm.rp_id
                )));
            }
            let assertion = u
                .passkey_get(origin, rp_id, challenge, &arm.item.to_string(), true)
                .map_err(e)?;
            log_passkey_use(state, u, assertion.item, Some((arm.agent, arm.task)));
            ok(assertion, Vec::new())
        })
        .await
}

/// `audit_reset` (`klav log reset`, ADR 0033 §8.4): forgets the audit
/// log's copy and pinned head, without network and also while locked.
/// Unlocked, under the session's lock, so no view puts the copy in memory
/// back on disk meanwhile; an unlock in between is caught by looking again.
async fn audit_reset(state: &State) -> Reply {
    let mut removed: Vec<&'static str> = Vec::new();
    let forget = |removed: &mut Vec<&'static str>, found: Vec<&'static str>| {
        for name in found {
            if !removed.contains(&name) {
                removed.push(name);
            }
        }
    };
    match state.current() {
        Some(slot) => {
            let mut session = slot.session.lock().await;
            let found = session
                .unlocked
                .forget_audit_copy()
                .map_err(|e| error_body(&e))?;
            forget(&mut removed, found);
        }
        None => {
            let found = klav_client::audit::forget_audit_copy(&state.config.home)
                .map_err(|e| error_body(&e))?;
            forget(&mut removed, found);
            if let Some(slot) = state.current() {
                let mut session = slot.session.lock().await;
                let found = session
                    .unlocked
                    .forget_audit_copy()
                    .map_err(|e| error_body(&e))?;
                forget(&mut removed, found);
            }
        }
    }
    ok(removed, Vec::new())
}

/// `revoke_agent` (ADR 0033, amendment of 2026-11-10, F2, F4): the
/// revocation first, alone, under the session; then, with `rotate`, the
/// key change one project at a time ([`rotate_in_steps`]). The fields and
/// the answer are the ones it always had. A key change cut off by a lock
/// still answers with the revocation done, saying what is left: the next
/// unlock resumes it (P11).
async fn revoke_agent(state: &Arc<State>, agent: AgentId, rotate: bool, background: bool) -> Reply {
    let Some(slot) = state.current() else {
        return Err(locked());
    };
    let e = |e: ClientError| error_body(&e);
    let (mut report, warnings) = state
        .unless_locked(slot.generation, async {
            let mut session = slot.session.lock().await;
            let refreshed = refresh(state, &mut session, false).await;
            track(state, &mut session);
            let warnings = refreshed?;
            if let Some(at) = session.deleted_at() {
                return Err(e(ClientError::AccountDeleted(at)));
            }
            let report = session.unlocked.revoke_first(agent, rotate).await;
            if report.is_ok() {
                state.note_revoked(agent);
            }
            state.note_revocations(&session.unlocked.pending_revocations());
            track(state, &mut session);
            let mut report = report.map_err(e)?;
            if rotate && background && report.failed.is_none() {
                report.pending = session.unlocked.rotation_left(agent);
            }
            Ok((report, warnings))
        })
        .await?;
    if rotate && background && report.failed.is_none() {
        // Written down by `revoke_first`: the agent is revoked and the key
        // change asked for, so it outlives this reply, the app and a lock
        // (P11). `status` says how it goes; nothing is answered later.
        tokio::spawn(rotate_in_background(
            Arc::clone(state),
            Arc::downgrade(&slot),
            slot.generation,
            vec![agent],
            true,
        ));
    } else if rotate && report.failed.is_none() {
        let (weak, since) = (Arc::downgrade(&slot), slot.generation);
        drop(slot);
        // Like every reply, nothing is handed out after a lock: the agent
        // is revoked, and `status` says what is left meanwhile.
        let (steps, left) = rotate_in_steps(state, &weak, since, agent, true)
            .await
            .map_err(|mut error| {
                error.message = format!(
                    "{}. The agent is revoked; the key change goes on by itself at the next unlock",
                    error.message
                );
                error
            })?;
        for step in steps {
            report.absorb(step);
        }
        report.pending = left;
    }
    ok(report, warnings)
}

/// One revocation's key change, one project per step (F2): each step takes
/// the session, rotates one project, issues the other agents' grants for
/// it, writes it down and lets the session go before the next, so the
/// vault and the extension wait for one project at most. Holds the slot
/// only during a step: locking stops it, with what is done written down.
/// Answers the steps and the projects left. Only the person's request
/// (`asked`) keeps the vault open longer; the resume at unlock does not
/// put off the idle lock. Two steps in a row that move nothing
/// ([`moved`]) end it until the next unlock: they would only repeat each
/// other, and nothing would ever stop the loop (review of #308, N1).
#[allow(clippy::print_stderr)]
async fn rotate_in_steps(
    state: &State,
    slot: &Weak<Slot>,
    since: u64,
    agent: AgentId,
    asked: bool,
) -> Result<(Vec<klav_client::revoke::RotationStep>, Vec<String>), ErrorBody> {
    let _running = state.rotating(agent);
    state
        .unless_locked(since, async {
            let mut steps = Vec::new();
            let mut skipped = std::collections::BTreeSet::new();
            let mut idle = 0_u8;
            loop {
                let Some(slot) = slot.upgrade() else {
                    return Err(locked());
                };
                let (step, left, end) = {
                    let mut session = slot.session.lock().await;
                    if let Some(at) = session.deleted_at() {
                        return Err(error_body(&ClientError::AccountDeleted(at)));
                    }
                    let before = state.revocation_book().of(agent);
                    let step = session.unlocked.rotation_step(agent).await;
                    state.note_revocations(&session.unlocked.pending_revocations());
                    let mut end = StepEnd::Go;
                    if let Ok(step) = &step {
                        let after = state.revocation_book().of(agent);
                        end = after_step(step, moved(step, &before, &after), &mut idle);
                        if end == StepEnd::Stalled {
                            // Written down as its `last_error`, so `status`,
                            // the apps and `klav agent show` stop saying it
                            // runs (review of #308, follow-up 2).
                            if session.unlocked.note_no_progress(agent).is_err() {
                                eprintln!(
                                    "klavd: the key change for agent {agent} stalled, and revocations.bin could not say so"
                                );
                            }
                            state.note_revocations(&session.unlocked.pending_revocations());
                        }
                        skipped.extend(step.skipped.iter().cloned());
                        if step.done && step.failed.is_none() {
                            // Its entry may be gone with what it skipped.
                            let rotated_now = usize::from(step.rotated.is_some());
                            let before = before.into_iter().next();
                            state.note_finished(agent, before, skipped.len(), rotated_now);
                        }
                    }
                    track(state, &mut session);
                    let step = step.map_err(|e| error_body(&e))?;
                    (step, session.unlocked.rotation_left(agent), end)
                };
                // The rest of a `revoke_agent` the person sent, which counts
                // as use: the reply came before the key change ends.
                if asked {
                    slot.used();
                }
                drop(slot);
                steps.push(step);
                match end {
                    StepEnd::Go => {}
                    StepEnd::Over => return Ok((steps, left)),
                    StepEnd::Stalled => {
                        // Only the agent's ID: the record can name a vault
                        // or a project, which the log keeps after the lock.
                        eprintln!(
                            "klavd: the key change for agent {agent} made no progress twice in a row; it waits for the next unlock"
                        );
                        return Ok((steps, left));
                    }
                }
            }
        })
        .await
}

/// What [`rotate_in_steps`] does after a step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StepEnd {
    /// The next step.
    Go,
    /// Nothing left, or a step failed.
    Over,
    /// Two steps in a row moved nothing: they would only repeat each other.
    Stalled,
}

/// After a step that `moved` (or not), with `idle` the steps in a row that
/// moved nothing before it.
fn after_step(step: &klav_client::revoke::RotationStep, moved: bool, idle: &mut u8) -> StepEnd {
    if step.done || step.failed.is_some() {
        return StepEnd::Over;
    }
    *idle = if moved { 0 } else { idle.saturating_add(1) };
    if *idle >= 2 {
        StepEnd::Stalled
    } else {
        StepEnd::Go
    }
}

/// Whether a step moved a key change: it changed a key, issued a grant
/// again, or changed what `status` says is left of it (`before` and
/// `after`, this agent's entries). A step that did none of these leaves
/// the next one where it was.
fn moved(
    step: &klav_client::revoke::RotationStep,
    before: &[RevocationProgress],
    after: &[RevocationProgress],
) -> bool {
    step.rotated.is_some()
        || !step.rekeyed.is_empty()
        || !step.regranted.is_empty()
        || before != after
}

/// Key changes of revoked agents in the background, one agent after
/// another and one project at a time: the one the person asked for with
/// `background` (F2, `asked`), or those resumed after an unlock (P11, not
/// `asked`: they do not put off the idle lock). A revocation whose projects
/// this device does not know is never passed here: it waits for the
/// person (T189). A lock stops them; what stops one otherwise stays in the
/// record and in `status` (`last_error`, only while unlocked), and
/// `klavd.log` gets only the agent's ID: the reason can name a vault or a
/// project, which the log keeps after the lock.
#[allow(clippy::print_stderr)]
async fn rotate_in_background(
    state: Arc<State>,
    slot: Weak<Slot>,
    since: u64,
    agents: Vec<AgentId>,
    asked: bool,
) {
    for agent in agents {
        let stopped = match rotate_in_steps(&state, &slot, since, agent, asked).await {
            Ok((steps, _)) => steps.iter().any(|s| s.failed.is_some()),
            Err(error) if error.code == ErrorCode::Locked => return,
            Err(_) => true,
        };
        if stopped {
            eprintln!(
                "klavd: the key change for agent {agent} stopped; the app or `klav agent show {agent}` says why"
            );
        }
    }
}

/// A request, from a program of this user (`source`, when known: it only
/// goes into the Touch ID prompt).
/// Every request, in one place: §3's table is consulted first, before any
/// path can answer (ADR 0041 §4; finding 8 of the second layer-2 review).
/// An operation placed in the window row is gated here whichever path
/// handles it, so a new path can't skip the gate.
async fn route(
    state: &Arc<State>,
    conn: u64,
    lines: &mpsc::Sender<Line>,
    source: Option<Source>,
    caller: Option<&Caller>,
    shown: Option<uv::Window>,
    mut request: Request,
) -> Reply {
    // The master password for the gate never reaches the operation.
    let password = presence::take_password(&mut request);
    let checked = match presence::gate(&request) {
        Gate::Window => window_gate(state, caller, &request, password).await?,
        // Each of these asks where it is handled, with its own rule:
        // layer 4 builds the extension connection's presence (the ADR's
        // own choice 16); `passkey_presence` the passkey window;
        // `State::confirm` the operations that already ask;
        // `setting_change` a loosening. The rest hand out no value.
        Gate::ExtensionConnection
        | Gate::PasskeyWindow
        | Gate::AlreadyAsks
        | Gate::Setting
        | Gate::Declares
        | Gate::AgentProof
        | Gate::BrowserChannel
        | Gate::NoValue => None,
    };
    match request {
        request @ (Request::ExtensionAttach { .. }
        | Request::ExtensionReply { .. }
        | Request::ExtensionPresence { .. }
        | Request::BrowserTab
        | Request::BrowserFill { .. }) => handle_browser(state, conn, lines, caller, request).await,
        Request::AgentPasskeyUse {
            tab_id,
            origin,
            rp_id,
            challenge,
            token,
        } => {
            agent_passkey_use(
                state,
                conn,
                tab_id,
                &origin,
                rp_id.as_deref(),
                &challenge,
                &token,
            )
            .await
        }
        request => handle(state, request, source, caller, shown, checked).await,
    }
}

/// What the window gate passed a request for: the session, and what the
/// request named when it was asked for, in the state it was asked about
/// (set for every request of the window row unless a window covered it
/// before anything was read). The request must still name that, in that
/// state, under the session's lock, in the same hold that hands it out: a
/// rename (findings 2 of layer 3's two reviews), an edit (Omar's decision
/// F of 2026-11-19), or, for `resolve` and `generated_value`, any change
/// to a referenced item or to the history entry (his decision K) in
/// between hands out nothing.
struct Checked {
    slot: Arc<Slot>,
    item: Option<Asked>,
    /// The window the answer opens, opened only once the hand-out found
    /// what was asked about (Omar's decision G of 2026-11-19).
    opens: Option<presence::Opening>,
    /// The ADR 0032 «every time» ask ran: what it named is bound by `item`.
    /// When it didn't, the hand-out checks again, under the session's lock,
    /// that the request still names nothing protected (a rename needs no
    /// presence and could point the query at a protected item meanwhile).
    every_time: bool,
}

/// What an ask named, and its state then ([`asked_now`]): two digests
/// through `klav-core`, so what is kept has a fixed size whatever the
/// request's (the second review of layer 3, finding 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Asked {
    /// Which item, which items in order (`resolve`), or which generator
    /// history entry (`generated_value`): what a password sent again must
    /// still match.
    names: [u8; 32],
    /// Their versions, or the entry's instant and value: what the hand-out
    /// must still find.
    version: presence::Version,
}

/// The window row (ADR 0041 §4): with the gate on, the session the value
/// comes from once `caller` passed the gate; with it off, nothing (the
/// password is dropped). Outside the session's lock, so a prompt holds up
/// no other request and a second key's request gets `presence_busy`
/// instead of waiting behind it. A window that covers the caller needs
/// nothing more; otherwise the item the request names is resolved, under
/// that lock but never behind an open dialog, before anything is asked
/// (the third layer-2 review, finding A; the second review of layer 3,
/// finding 2).
async fn window_gate(
    state: &State,
    caller: Option<&Caller>,
    request: &Request,
    password: Option<klav_client::ops::SecretText>,
) -> Result<Option<Checked>, ErrorBody> {
    let Some(slot) = state.current() else {
        return Err(locked());
    };
    // Every request has a caller; fail closed if not.
    let Some(caller) = caller else {
        return Err(locked());
    };
    let device = presence::Device {
        touch: state.touch.as_ref(),
        touch_id: state.config.touch_id,
        check: slot.password.as_ref(),
        passwords: &state.passwords,
    };
    // The first look keeps and compares no ask: only `require` does, so a
    // setting changed between the two can't leave an ask that no resend
    // matches (the second review of layer 3, finding 7).
    let first = tokio::task::block_in_place(|| {
        state.presence.first(
            slot.generation,
            caller,
            password.is_some(),
            &device,
            &Instant::now,
        )
    })?;
    // A value of a protected environment, or of an item it protects, asks
    // every time, whatever window or held connection covers the caller
    // (ADR 0032 §3 and §3.1).
    let touch = password.is_none() && presence::Verify::touch_id_available(&device);
    let asks = matches!(first, Untitled::NeedsText { touch: true });
    if let Some(reason) = protected_reason(state, &slot, request, asks, touch).await? {
        let (value, asked) = value_text(state, &slot, request, touch).await?;
        let bound = presence::Bound {
            request: presence::request_digest(request)?,
            names: asked.map(|a| a.names),
        };
        let passed = tokio::task::block_in_place(|| {
            state.presence.require(
                slot.generation,
                caller,
                Purpose::EveryTime {
                    reason: &reason,
                    value: Some(&value),
                },
                password,
                &bound,
                asked.map(|a| a.version),
                &device,
                Lang::current(),
                &Instant::now,
            )
        })?;
        let item = match (asked, passed.version) {
            (Some(a), Some(version)) => Some(Asked {
                names: a.names,
                version,
            }),
            (Some(_), None) => return Err(changed()),
            (None, _) => None,
        };
        return Ok(Some(Checked {
            slot,
            item,
            opens: None,
            every_time: true,
        }));
    }
    let Untitled::NeedsText { touch } = first else {
        return Ok(Some(Checked {
            slot,
            item: None,
            opens: None,
            every_time: false,
        }));
    };
    #[cfg(test)]
    state.seams.between_passes();
    // The value the ask names, and the item it is, at the version asked
    // about, without waiting behind an open dialog when Touch ID follows.
    let (value, asked) = value_text(state, &slot, request, touch).await?;
    // A password is checked only for the request it was asked for (the
    // request as sent, without the password: no secret in it), kept as a
    // digest (finding 5), and the item it named.
    let bound = presence::Bound {
        request: presence::request_digest(request)?,
        names: asked.map(|a| a.names),
    };
    let passed = tokio::task::block_in_place(|| {
        state.presence.require(
            slot.generation,
            caller,
            Purpose::Window { value: &value },
            password,
            &bound,
            asked.map(|a| a.version),
            &device,
            Lang::current(),
            &Instant::now,
        )
    })?;
    // For a password sent again, the version `klavd` asked about, not the
    // one read now: an edit between the ask and the resend is a `conflict`
    // below (Omar's decision F of 2026-11-19).
    let item = match (asked, passed.version) {
        (Some(a), Some(version)) => Some(Asked {
            names: a.names,
            version,
        }),
        // The ask named something: its state must be known (fails closed).
        (Some(_), None) => return Err(changed()),
        (None, _) => None,
    };
    Ok(Some(Checked {
        slot,
        item,
        opens: passed.opens,
        every_time: false,
    }))
}

/// Why a value request asks every time (ADR 0032 §3.1): it reads a protected
/// environment, an item in the protected set, or any item of a vault whose
/// protection this device cannot tell. Autofill is not a copy or a show
/// and stays under the window (§3.1, "what doesn't change for the person").
/// A request that names nothing is left to the window row, which refuses
/// it.
///
/// The session's lock is taken as [`value_text`] takes it: never behind an
/// open dialog when this request shows one anyway (`asks`), and when it
/// waited while one was open and turns out to need its own Touch ID prompt
/// (`touch`), it answers `presence_busy` instead of showing it right after.
async fn protected_reason(
    state: &State,
    slot: &Slot,
    request: &Request,
    asks: bool,
    touch: bool,
) -> Result<Option<String>, ErrorBody> {
    if !matches!(
        request,
        Request::View { reveal: true, .. }
            | Request::PreviousPassword { .. }
            | Request::Totp { .. }
            | Request::Resolve { .. }
    ) {
        return Ok(None);
    }
    let (session, prompted) = state.presence.lock(&slot.session, asks, None).await?;
    let u = &session.unlocked;
    let items = match request {
        Request::View { query, .. }
        | Request::PreviousPassword { query, .. }
        | Request::Totp { query, .. } => match u.find_item(query) {
            Ok(loc) => vec![loc],
            Err(_) => return Ok(None),
        },
        Request::Resolve { references, .. } => match u.reference_targets(references) {
            Ok(items) => items,
            Err(_) => return Ok(None),
        },
        _ => return Ok(None),
    };
    let reason = u.protection_reason(&items);
    if reason.is_some() && prompted && touch {
        return Err(presence::busy());
    }
    Ok(reason)
}

/// Whether a value request names something protected now, read under the
/// session's lock (see [`protected_reason`]). A query that names nothing
/// is left to the request's own error.
fn protected_now(u: &klav_client::Unlocked, request: &Request) -> bool {
    let items = match request {
        Request::View {
            query,
            reveal: true,
            ..
        }
        | Request::PreviousPassword { query, .. }
        | Request::Totp { query, .. } => match u.find_item(query) {
            Ok(loc) => vec![loc],
            Err(_) => return false,
        },
        Request::Resolve { references, .. } => match u.reference_targets(references) {
            Ok(items) => items,
            Err(_) => return false,
        },
        _ => return false,
    };
    u.protection_reason(&items).is_some()
}

/// The answer when what a value was asked for was renamed away, replaced or
/// edited before the hand-out: nothing goes (ADR 0041; Omar's decisions F
/// and K of 2026-11-19). The wording is matched by the clients
/// (`klav-ffi`'s `CHANGED_WHILE_CONFIRMING`), so it stays one sentence for
/// every request.
fn changed() -> ErrorBody {
    ErrorBody {
        code: ErrorCode::Conflict,
        message: "the item changed while you confirmed: nothing was handed out; \
                  run the command again"
            .into(),
        paused: None,
        presence: None,
    }
}

/// What needs no browser channel. `checked` is the session the window gate
/// passed the request for, if it did.
async fn handle(
    state: &Arc<State>,
    request: Request,
    source: Option<Source>,
    caller: Option<&Caller>,
    shown: Option<uv::Window>,
    checked: Option<Checked>,
) -> Reply {
    match request {
        Request::VaultHealth => return vault_health(state).await,
        Request::HealthSettings { breach_check } => {
            return health_settings(state, breach_check);
        }
        Request::PasskeyUv { window, password } => {
            return setting_change(state, presence::Which::Passkey, window, password, source).await;
        }
        Request::PresenceWindow { window, password } => {
            return setting_change(state, presence::Which::Presence, window, password, source)
                .await;
        }
        Request::Hold => return hold(state, caller),
        Request::AgentRotateBegin { tab, step, submit } => {
            return rotate_begin(state, tab, step, submit).await;
        }
        Request::AgentPasskeyArm { tab, step } => return agent_passkey_arm(state, tab, step).await,
        Request::PauseAgents { agent, until } => {
            return pause_agents(state, agent, until, source).await;
        }
        Request::Status => {
            let status = status(state, state.current().as_deref(), caller);
            return ok(for_source(status, source), Vec::new());
        }
        Request::ConfirmPresence { purpose } => return confirm_presence(state, purpose, source),
        Request::AuditReset => return audit_reset(state).await,
        Request::RevokeAgent {
            agent,
            rotate,
            background,
        } => return revoke_agent(state, agent, rotate, background).await,
        Request::Lock => {
            state.lock_now();
            return ok(status(state, None, caller), Vec::new());
        }
        Request::Shutdown => {
            // The connection stops the daemon once this reply is written.
            state.lock_now();
            return ok(serde_json::json!({}), Vec::new());
        }
        Request::Unlock {
            password,
            passkey_flow,
        } => return unlock(state, password, passkey_flow, source, caller, shown).await,
        _ => {}
    }
    // The session the gate passed the request for: a lock since then
    // cancels it below (`unless_locked`).
    let named = checked.as_ref().and_then(|c| c.item);
    let opens = checked.as_ref().and_then(|c| c.opens);
    let window_only = checked.as_ref().is_some_and(|c| !c.every_time);
    let Some(slot) = checked.map(|c| c.slot).or_else(|| state.current()) else {
        return Err(locked());
    };
    // No prompt waits behind an open dialog (ADR 0041 §2.4; the third
    // layer-2 review, finding A): `dispatch` shows its prompts with the
    // session's lock held, so a request that will show one is answered
    // `presence_busy` instead of waiting for that lock while a dialog is
    // open; any other waits as before, and if it then needs a prompt after
    // all (`behind`), it is busy too.
    let asks = state.config.touch_id && will_ask(state, &request, caller);
    state
        .unless_locked(slot.generation, async {
            let (mut session, behind) = state.presence.lock(&slot.session, asks, None).await?;
            let behind = behind && state.config.touch_id;
            let warnings = if reads_without_syncing(&request) {
                revalidate(state, &slot, &session)
            } else {
                let refreshed = refresh(state, &mut session, false).await;
                track(state, &mut session);
                refreshed
            }?;
            if person_write(&request)
                && let Some(at) = session.deleted_at()
            {
                return Err(error_body(&ClientError::AccountDeleted(at)));
            }
            // What the verification named, still what the request names
            // now (finding 2 of layer 3's review), and in the state it was
            // asked about (Omar's decisions F and K of 2026-11-19): under
            // the session's lock, in the hold that hands it out. A sync that
            // brought a newer version meanwhile is an edit too; a reference
            // or an entry that names nothing now is a change as well.
            if let Some(named) = named
                && asked_now(&session.unlocked, &request).ok().flatten() != Some(named)
            {
                return Err(changed());
            }
            // Passed under a window as unprotected: still unprotected now,
            // in the hold that hands it out (ADR 0032 §3). Otherwise the
            // value would go without its «every time» ask.
            if window_only && protected_now(&session.unlocked, &request) {
                return Err(changed());
            }
            // Only now the window the answer stated: a `conflict` above, or
            // any refusal before it, opens none, and the next value asks
            // again (Omar's decision G of 2026-11-19).
            if let (Some(opening), Some(caller)) = (opens, caller) {
                state.presence.open_window(caller, opening);
            }
            let reply = dispatch(
                state,
                &slot,
                &mut session,
                request,
                warnings,
                source,
                caller,
                behind,
            )
            .await;
            track(state, &mut session);
            reply
        })
        .await
}

/// Whether `request`, sent with no password, shows a Touch ID prompt in
/// [`dispatch`] whatever the vault holds (ADR 0041 §2.4; the third layer-2
/// review, finding A): the operations that already ask, and a passkey use
/// the caller's passkey window doesn't cover now. A widening
/// `grant_change_apply` asks too, but whether it widens is known only under
/// the session's lock, and a passkey window can lapse while the request
/// waits: those are `behind` in [`dispatch`] instead.
fn will_ask(state: &State, request: &Request, caller: Option<&Caller>) -> bool {
    match request {
        Request::ApproveAgent { password, .. }
        | Request::DecideApproval {
            approve: true,
            password,
            ..
        }
        | Request::DecideTask {
            approve: true,
            password,
            ..
        }
        | Request::AddToTask { password, .. }
        | Request::OfferTask { password, .. }
        | Request::FulfillSecretRequest {
            input:
                klav_client::secret_requests::FulfillSecretRequest {
                    grant_proxy: true, ..
                },
            password,
            ..
        }
        | Request::ProxyUse { password, .. }
        | Request::ProxyGrant { password, .. }
        | Request::ProxyRevoke { password, .. }
        | Request::ProxyIssuerAdd { password, .. }
        | Request::ProxyIssuerRemove { password, .. }
        | Request::LocalClientChange { password, .. }
        | Request::McpGatewayOn { password, .. }
        | Request::ResumeAgents { password, .. }
        | Request::CancelAccountDeletion { password } => password.is_none(),
        // Only a change that lowers the protection asks, and only the
        // handler knows (ADR 0032 §3): counted as one that may.
        Request::EnvironmentSave { password, .. } | Request::EnvironmentTrash { password, .. } => {
            password.is_none()
        }
        Request::PasskeyGet { password, .. } | Request::PasskeyCreate { password, .. } => {
            password.is_none()
                && caller.is_some_and(|c| state.presence.passkey_needs(c, Instant::now()))
        }
        _ => false,
    }
}

/// `unlock`. Derives the keys and syncs before publishing the session, so
/// a failure leaves klavd locked, as the client is told. With klavd
/// already unlocked, a password that comes along must be the right one.
async fn unlock(
    state: &Arc<State>,
    password: Option<klav_client::ops::SecretText>,
    passkey_flow: bool,
    source: Option<Source>,
    caller: Option<&Caller>,
    shown: Option<uv::Window>,
) -> Reply {
    // No queue behind an open unlock prompt (ADR 0041 §2.4, N2): the
    // person's own `unlock` must not succeed silently on a dialog another
    // program started, nor show its own right after it. `presence_busy`
    // while one is open, and as soon as one opens while this waits for the
    // unlock running now (the third layer-2 review, finding A).
    let _one = state
        .presence
        .lock(&state.unlocking, true, Some(PromptKind::Unlock))
        .await?
        .0;
    let home = state.config.home.clone();
    let since = state.generation();
    if let Some(slot) = state.current() {
        // Unlocked by another key (ADR 0041 §2.4, Omar's decision on
        // Q-N1): say so; without the password this grants nothing.
        let elsewhere = caller.is_some_and(|c| state.presence.unlocked_by_other(c));
        if let Some(password) = password {
            // The master password of the session in memory, never of the
            // files in the home (ADR 0041 §2.3; finding 1 of the second
            // layer-2 review).
            state.passwords.check(slot.password.as_ref(), password)?;
            // The checked password is the caller's own verification: it
            // opens what the client's question said, if that is what
            // `klavd` would open, and otherwise none (finding 1 of layer
            // 3's review). Every request has a caller.
            if let Some(caller) = caller {
                let stated = presence::unlock_stated(&state.presence, caller, shown);
                // A password the client didn't read on its terminal is no
                // passkey verification (Omar's decision B).
                state.presence.password_at_unlock(
                    slot.generation,
                    caller,
                    stated,
                    !caller.untyped,
                    passkey_flow,
                    Instant::now(),
                );
            }
        }
        let warnings = state
            .unless_locked(slot.generation, async {
                let mut session = slot.session.lock().await;
                let refreshed = refresh(state, &mut session, true).await;
                track(state, &mut session);
                refreshed
            })
            .await?;
        let mut answer = for_source(status(state, Some(&slot), caller), source);
        answer.already_unlocked = elsewhere;
        return ok(answer, warnings);
    }
    // The window the unlock opens for its caller, which is what its prompt
    // said (ADR 0041 §2.4). A password unlock shows no
    // prompt in `klavd`: it opens what the client's own question said, if
    // that is what the Touch ID prompt would have said, and otherwise none
    // (finding 1 of layer 3's review; Omar's decision 4 of 2026-11-19).
    let mut stated = caller.and_then(|c| presence::unlock_stated(&state.presence, c, shown));
    let (unlocked, method) = match password {
        Some(password) => {
            let unlocked = tokio::task::block_in_place(|| {
                unlock_with_password(&home, &MasterPassword::new(password.expose()))
            })
            .map_err(|e| error_body(&e))?;
            drop(password);
            (unlocked, "password")
        }
        None => {
            if !state.config.touch_id {
                return Err(ErrorBody {
                    code: ErrorCode::BiometryUnavailable,
                    message: "Touch ID is turned off for this klavd".into(),
                    paused: None,
                    presence: None,
                });
            }
            let account = klav_client::account(&home).map_err(|e| error_body(&e))?;
            let reason = match caller {
                Some(caller) => {
                    let declared = state.presence.is_declared(caller.conn);
                    let (window, who, lasts) =
                        presence::unlock_window(&state.presence, caller, declared);
                    stated = window;
                    Prompt::UnlockPresence {
                        email: &account.email,
                        who,
                        lasts,
                    }
                    .reason(Lang::current(), source)
                }
                None => Prompt::Unlock {
                    email: &account.email,
                }
                .reason(Lang::current(), source),
            };
            let ctx = account.local_context();
            let local_key = tokio::task::block_in_place(|| {
                // The unlock prompt is open while Touch ID runs, and only
                // when no other prompt is (§2.4).
                #[cfg(test)]
                state.seams.before_prompt();
                let _open = state.presence.open_prompt(PromptKind::Unlock)?;
                state.touch.unlock(&home, ctx, &reason)
            })?;
            let unlocked =
                klav_client::unlock_with_local_key(&home, local_key).map_err(|e| error_body(&e))?;
            (unlocked, "touch_id")
        }
    };
    // The unlock is a real verification (ADR 0020 §8): its instant is the
    // windows' start, as the sync below can take seconds and a window
    // counts from the verification (ADR 0041, plan item 6).
    let verified_at = Instant::now();
    let mut unlocked = unlocked;
    // Before the first sync: it plans with the account's URL (ADR 0028
    // §4). At most a few seconds, and no session is published yet.
    unlocked.migrate_server().await;
    // What `klavd` knew before (an earlier session, or `signed-pauses.json`
    // after a restart), now checked with the account: an unlock that
    // cannot sync does not forget them.
    let known = state.pause_book().signed.clone();
    unlocked.remember_pauses(&known);
    let mut warnings = Vec::new();
    // The settings, sealed in the local data, read now with the local key
    // (ADR 0041 §2.4); the old `passkeys.json` only checked for and gone.
    let settings = {
        let ctx = unlocked.account().local_context();
        presence::load_settings(&home, unlocked.local_key(), &ctx)
    };
    if let Some(warning) = presence::forget_old_passkey_file(&home) {
        warnings.push(warning.to_owned());
    }
    // What checks a password against this session from now on (ADR 0041
    // §2.3): its own parameters and local key, read now.
    let password_check = unlocked.password_check().ok();
    if method == "password" && state.config.touch_id {
        let ctx = unlocked.account().local_context();
        if let Err(e) = state.touch.enrol(&home, ctx, unlocked.local_key()) {
            warnings.push(format!("Touch ID was not set up: {e}"));
        }
    }
    // An account this device already saw deleted (`deletion.bin`): read
    // only from the start, without a sync that can only fail.
    let deleted = unlocked
        .account_deletion()
        .filter(|_| unlocked.account_deleted())
        .map(|d| deleted_warning(d.delete_at));
    let mut session = Session {
        seen_cache_generation: unlocked.generation(),
        unlocked: Box::new(unlocked),
        last_sync: None,
        sync_error: None,
        rollback: None,
        offline: None,
        deleted,
        flush_retry: None,
        imports: Imports::default(),
    };
    let synced = state
        .unless_locked(since, refresh(state, &mut session, true))
        .await?;
    warnings.extend(synced);
    // The new session moves `revision` once, below.
    session.seen_cache_generation = session.unlocked.generation();
    let revocations = session.unlocked.pending_revocations();
    // Before the session shows as unlocked: a `status` read in between
    // would list nothing, and an app could take that for every key
    // changed (after a restart, nothing was listed while locked).
    state.note_revocations(&revocations);
    let slot = Arc::new(Slot {
        session: Mutex::new(session),
        method,
        generation: since,
        last_use: std::sync::Mutex::new(Instant::now()),
        arms: std::sync::Mutex::new(Vec::new()),
        syncing: std::sync::Mutex::new(None),
        password: password_check,
    });
    {
        let mut current = state.slot.lock().unwrap_or_else(PoisonError::into_inner);
        // A lock that arrived since the unlock started wins.
        if state.generation() != since {
            return Err(locked());
        }
        *current = Some(Arc::clone(&slot));
        if let Some(caller) = caller {
            // Touch ID, or a password the client typed, is the passkey
            // verification; one it didn't read on its terminal isn't
            // (Omar's decision B of 2026-11-19).
            let passkey = method == "touch_id" || !caller.untyped;
            state.presence.open(
                since,
                settings,
                caller,
                stated,
                passkey,
                passkey_flow,
                verified_at,
            );
        }
    }
    // Key changes asked for and cut off: resumed by themselves (P11).
    let resume: Vec<AgentId> = revocations
        .iter()
        .flatten()
        .filter(|r| r.needs_work())
        .map(|r| r.agent_id)
        .collect();
    if !resume.is_empty() {
        tokio::spawn(rotate_in_background(
            Arc::clone(state),
            Arc::downgrade(&slot),
            since,
            resume,
            false,
        ));
    }
    state.revision.fetch_add(1, Ordering::Relaxed);
    ok(
        for_source(status(state, Some(&slot), caller), source),
        warnings,
    )
}

/// `hold` (ADR 0041 §1.2): answered `not_supported` until
/// [`HOLD_SUPPORTED`] turns it on, and always on Linux.
fn hold(state: &State, caller: Option<&Caller>) -> Reply {
    #[cfg(test)]
    let supported = hold_supported() || state.seams.hold;
    #[cfg(not(test))]
    let supported = hold_supported();
    let caller = caller.filter(|_| supported);
    let Some(caller) = caller else {
        return Err(not_supported(if cfg!(target_os = "macos") {
            "this klavd does not hold connections yet"
        } else {
            "a held connection is macOS-only"
        }));
    };
    let (declared, held) = state.presence.declare(caller.conn);
    ok(
        serde_json::json!({ "declared": declared, "held": held }),
        Vec::new(),
    )
}

/// Whether `hold` is on (ADR 0041 §1.2). **Off, by the stop rule of layer
/// 5:** `klavd` answers `hold` with `not_supported` until Omar has run layer
/// 5's by-hand checks on a signed Developer ID build (a same-user debugger
/// can't attach; started with `HOME`, `CFFIXED_USER_HOME` and `KLAV_HOME`
/// pointing elsewhere, the app connects to the default socket) and they
/// passed. Turning it on is this one constant, and only on macOS: Linux
/// never holds a connection (§1.2, R9). Without it, the app's long
/// connection is an ordinary one, keyed by its connection (§2.1).
const HOLD_SUPPORTED: bool = false;

/// [`HOLD_SUPPORTED`], on macOS only.
const fn hold_supported() -> bool {
    cfg!(target_os = "macos") && HOLD_SUPPORTED
}

fn not_supported(message: &str) -> ErrorBody {
    ErrorBody {
        code: ErrorCode::NotSupported,
        message: message.to_owned(),
        paused: None,
        presence: None,
    }
}

/// `presence_window`, and `passkey_uv` with the gate on (ADR 0041 §2.4):
/// the setting sealed in the local data, `locked` while locked. Loosening
/// asks for a real verification and opens no window: the next value, or
/// passkey use, asks once more. Tightening asks for nothing and applies at
/// once. The change goes to the store and to memory together.
async fn setting_change(
    state: &State,
    which: presence::Which,
    window: Option<uv::Window>,
    password: Option<klav_client::ops::SecretText>,
    source: Option<Source>,
) -> Reply {
    let Some(slot) = state.current() else {
        return Err(locked());
    };
    let generation = slot.generation;
    let of = |settings: presence::Settings| match which {
        presence::Which::Presence => settings.presence,
        presence::Which::Passkey => settings.passkey,
    };
    // One change at a time, from reading the current value to the save
    // and the change in memory (finding 3 of the second layer-2 review):
    // otherwise a tightening decided against a stale value could land
    // after a move to a tighter one, and leave a looser setting nobody
    // verified, or disk and memory could differ. A change while another
    // runs is answered `presence_busy` at once; waiting would line its
    // prompt up behind the open one (§2.4). Reading only takes no turn.
    let _one = match window {
        Some(_) => Some(
            state
                .setting_change
                .try_lock()
                .map_err(|_| presence::busy())?,
        ),
        None => None,
    };
    let current = of(state.presence.settings(generation)?);
    if let Some(window) = window {
        if window > current {
            let prompt = match which {
                presence::Which::Presence => Prompt::PresenceWindow {
                    from: current,
                    to: window,
                },
                presence::Which::Passkey => Prompt::PasskeyWindow,
            };
            let reason = prompt.reason(Lang::current(), source);
            state.confirm(&slot, password, &reason)?;
        }
        if window != current {
            state
                .unless_locked(generation, async {
                    let session = slot.session.lock().await;
                    let u = &session.unlocked;
                    presence::save(
                        &state.config.home,
                        u.local_key(),
                        &u.account().local_context(),
                        which,
                        window,
                    )
                })
                .await?;
            match which {
                presence::Which::Presence => state.presence.set_presence(generation, window)?,
                presence::Which::Passkey => state.presence.set_passkey(generation, window)?,
            }
        }
    }
    let now = of(state.presence.settings(generation)?);
    ok(serde_json::json!({ "window": now }), Vec::new())
}

/// The value an ask names (ADR 0041 §2.4), and the item it is: the item's
/// title from the vault, never the query the caller wrote. A request that
/// names an item (`view`, `previous_password`, `totp`, `autofill`) must
/// resolve to exactly one, under the session's lock, before any ask (the
/// second review of layer 3, finding 2): otherwise the answer is the one
/// `dispatch` gives, `not_found` or `invalid` (ambiguous), which `view`
/// without `reveal` already gives that caller. So its ask always names the
/// item and its title, and the hand-out is checked against that item under
/// the session's lock (`handle`). `resolve` and `generated_value` name no
/// item in the ask, but are resolved here all the same, every reference to
/// its item and the instant to its history entry, so a reference or an
/// instant that names nothing is refused before any ask, and the hand-out
/// is checked against what they named (Omar's decision K of 2026-11-19;
/// [`asked_now`]). `touch`: a Touch ID prompt follows, so the
/// session's lock is never awaited behind an open dialog: `presence_busy`
/// instead (§2.4; the third layer-2 review, finding A).
async fn value_text(
    state: &State,
    slot: &Slot,
    request: &Request,
    touch: bool,
) -> Result<(AskValue, Option<Asked>), ErrorBody> {
    let (kind, query) = match request {
        Request::View { query, .. } => (AskValueKind::Show, Some(query)),
        Request::PreviousPassword { query, .. } => (AskValueKind::Previous, Some(query)),
        Request::Totp { query, .. } => (AskValueKind::Code, Some(query)),
        Request::Autofill { item, .. } => (AskValueKind::Fill, Some(item)),
        Request::GeneratedValue { .. } => (AskValueKind::Generated, None),
        Request::Resolve { .. } | Request::EnvironmentImportReview { .. } => {
            (AskValueKind::Resolve, None)
        }
        // Only the window row reaches here (`presence::gate`).
        _ => {
            return Err(ErrorBody {
                code: ErrorCode::Internal,
                message: "not a value request".into(),
                paused: None,
                presence: None,
            });
        }
    };
    let session = if touch {
        state.presence.lock(&slot.session, true, None).await?.0
    } else {
        slot.session.lock().await
    };
    let u = &session.unlocked;
    // What the request names, resolved before anything is asked: a query,
    // a reference or an instant that names nothing is refused here (Omar's
    // decision K of 2026-11-19 for `resolve` and `generated_value`).
    let asked = asked_now(u, request).map_err(|e| error_body(&e))?;
    let title = match query {
        Some(query) => {
            let loc = u.find_item(query).map_err(|e| error_body(&e))?;
            let summary = u.item_summary(loc).map_err(|e| error_body(&e))?;
            Some(crate::prompt::clean(
                &summary.title,
                crate::prompt::MAX_NAME,
            ))
        }
        None => None,
    };
    let count = match request {
        Request::Resolve { references, .. } => {
            Some(u32::try_from(references.len()).unwrap_or(u32::MAX))
        }
        _ => None,
    };
    Ok((AskValue { kind, title, count }, asked))
}

/// What a value request names now, and its state, as [`Asked`]'s digests:
///
/// - `view`, `previous_password`, `totp` and `autofill`: the item the query
///   finds, at its `version`, which every write to its content raises (a
///   sync refuses a version lower than one already seen; the trash and a
///   restore raise the server's `revision` instead, and change no content);
/// - `resolve`: every referenced item, in order, at its version, each
///   reference checked as the hand-out resolves it
///   (`klav_client::Unlocked::reference_items`);
/// - `generated_value`: the generator history entry at that instant, by
///   its instant and its value (`klav_client::Unlocked::generated_digest`).
///
/// `Ok(None)` for any other request. An error when the request names
/// nothing now.
fn asked_now(u: &Unlocked, request: &Request) -> Result<Option<Asked>, ClientError> {
    let item = |loc: klav_client::ItemLocation| -> Result<(String, u64), ClientError> {
        Ok((loc.item.to_string(), u.item_summary(loc)?.version))
    };
    let (label, names, versions): (&str, Vec<Vec<u8>>, Vec<Vec<u8>>) = match request {
        Request::View { query, .. }
        | Request::PreviousPassword { query, .. }
        | Request::Totp { query, .. }
        | Request::Autofill { item: query, .. } => {
            let (id, version) = item(u.find_item(query)?)?;
            (
                "item",
                vec![id.clone().into_bytes()],
                vec![id.into_bytes(), version.to_be_bytes().to_vec()],
            )
        }
        Request::Resolve { references, .. } => {
            let mut names = Vec::new();
            let mut versions = Vec::new();
            // Through an environment's reference too: the item behind a
            // variable is part of what was asked about (ADR 0032 §1).
            u.reference_items(references)?;
            for loc in u.reference_targets(references)? {
                let (id, version) = item(loc)?;
                names.push(id.clone().into_bytes());
                versions.push(id.into_bytes());
                versions.push(version.to_be_bytes().to_vec());
            }
            ("resolve", names, versions)
        }
        Request::GeneratedValue { created_at, .. } => {
            let entry = u.generated_digest(*created_at)?;
            (
                "generated",
                vec![created_at.to_be_bytes().to_vec()],
                vec![entry.to_vec()],
            )
        }
        _ => return Ok(None),
    };
    Ok(Some(Asked {
        names: bind_digest(label, "names", &names),
        version: presence::Version(bind_digest(label, "version", &versions)),
    }))
}

/// SHA-256, through `klav-core`, of `label`, `part` and `fields`, each
/// prefixed with its length, so no two lists give the same bytes.
fn bind_digest(label: &str, part: &str, fields: &[Vec<u8>]) -> [u8; 32] {
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    for field in [label.as_bytes(), part.as_bytes()]
        .into_iter()
        .chain(fields.iter().map(Vec::as_slice))
    {
        bytes.extend_from_slice(&(field.len() as u64).to_be_bytes());
        bytes.extend_from_slice(field);
    }
    klav_core::crypto::agent::body_digest(&bytes)
}

/// The MCP profile an approval's tool call goes through, from the proxy's
/// verified grant (ADR 0049 §5.4): best effort, `None` when this device
/// can't name it. Only the proxy's own requests have one.
async fn mcp_profile(u: &mut Unlocked, view: &klav_client::agents::ApprovalView) -> Option<String> {
    let item = view.item_id?;
    let status = u.proxy_status().await.ok()?;
    klav_client::proxy_admin::mcp_profile_names(&status, Some(view.agent_id)).remove(&item)
}

/// Every request that needs the account unlocked. `behind`: with the gate
/// on, a prompt opened while this request waited for the session's lock,
/// so a Touch ID prompt of its own would follow that one: `presence_busy`
/// instead (ADR 0041 §2.4; the third layer-2 review, finding A).
#[allow(clippy::too_many_arguments)]
async fn dispatch(
    state: &Arc<State>,
    slot: &Slot,
    session: &mut Session,
    request: Request,
    warnings: Vec<String>,
    source: Option<Source>,
    caller: Option<&Caller>,
    behind: bool,
) -> Reply {
    let u = &mut session.unlocked;
    // The Touch ID prompt before an approval (ADR 0014), in the Mac's
    // language.
    let confirm = |prompt: Prompt<'_>, password: Option<klav_client::ops::SecretText>| {
        if behind && password.is_none() {
            return Err(presence::busy());
        }
        let reason = prompt.reason(Lang::current(), source);
        state.confirm(slot, password, &reason)
    };
    let e = |e: ClientError| error_body(&e);
    match request {
        // `klav sync` reports every failure, a rollback included (exit 3).
        Request::Sync => match u.sync().await {
            Ok(report) => {
                session.synced();
                ok(report, session.unlocked.warnings().to_vec())
            }
            Err(err) => {
                session.sync_failed(&err);
                Err(error_body(&err))
            }
        },
        Request::ResetCache => match u.reset_cache().await {
            Ok(report) => {
                session.synced();
                ok(report, session.unlocked.warnings().to_vec())
            }
            Err(err) => {
                session.sync_failed(&err);
                Err(error_body(&err))
            }
        },
        Request::Vaults => ok(u.vaults(), warnings),
        Request::Projects { vault } => {
            let vault = vault.map(|v| u.find_vault(&v)).transpose().map_err(e)?;
            ok(u.projects(vault), warnings)
        }
        Request::CreateVault { name } => {
            u.create_vault(&name).await.map_err(e)?;
            ok(serde_json::json!({}), warnings)
        }
        Request::CreateProject { vault, name } => {
            let (vault, _) = u.destination(vault.as_deref(), None).map_err(e)?;
            u.create_project(vault, &name).await.map_err(e)?;
            ok(serde_json::json!({}), warnings)
        }
        Request::SetProjectRepos {
            vault,
            project,
            repos,
        } => {
            let (vault, project) = u.destination(vault.as_deref(), Some(&project)).map_err(e)?;
            ok(
                u.set_project_repos(vault, project, repos)
                    .await
                    .map_err(e)?,
                warnings,
            )
        }
        Request::List { filter } => ok(u.list_items(&filter).map_err(e)?, warnings),
        Request::Environments { project } => {
            ok(u.environments(project.as_deref()).map_err(e)?, warnings)
        }
        Request::Environment { project, name } => ok(
            u.environment_detail(project.as_deref(), &name)
                .await
                .map_err(e)?,
            warnings,
        ),
        Request::EnvironmentImportReview {
            project,
            name,
            variables,
            ..
        } => ok(
            u.import_review(project.as_deref(), &name, &variables)
                .map_err(e)?,
            warnings,
        ),
        Request::EnvironmentSave {
            project,
            name,
            edit,
            password,
        } => {
            let prepared = u
                .prepare_environment(project.as_deref(), &name, &edit)
                .await
                .map_err(e)?;
            // Lowering the protection asks first (ADR 0032 §3).
            if prepared.plan.shrinks {
                confirm(Prompt::LowerProtection { environment: &name }, password)?;
            }
            let saved = u.commit_environment(prepared).await.map_err(e)?;
            let mut warnings = warnings;
            warnings.extend(saved.warnings.iter().cloned());
            ok(saved, warnings)
        }
        Request::EnvironmentTrash {
            project,
            name,
            password,
        } => {
            let protected = u
                .environments(project.as_deref())
                .map_err(e)?
                .into_iter()
                .any(|l| l.name == name && l.protected);
            if protected {
                confirm(Prompt::LowerProtection { environment: &name }, password)?;
            }
            let saved = u
                .trash_environment(project.as_deref(), &name)
                .await
                .map_err(e)?;
            ok(saved, warnings)
        }
        Request::View { query, reveal, .. } => {
            ok(u.view_item(&query, reveal).map_err(e)?, warnings)
        }
        Request::Create { item } => ok(u.create(&item).await.map_err(e)?, warnings),
        Request::Edit { query, patch } => ok(u.edit(&query, &patch).await.map_err(e)?, warnings),
        Request::Trash { query } => ok(u.trash(&query).await.map_err(e)?, warnings),
        Request::Suggest { url } => ok(u.suggest(&url).map_err(e)?, warnings),
        Request::Autofill {
            item,
            url,
            part,
            chosen,
            ..
        } => ok(u.autofill(&item, &url, part, chosen).map_err(e)?, warnings),
        Request::Totp { query, field, .. } => {
            ok(u.totp_code(&query, field.as_deref()).map_err(e)?, warnings)
        }
        Request::PasskeyCandidates {
            origin,
            rp_id,
            allow_credentials,
        } => ok(
            u.passkey_candidates(&origin, rp_id.as_deref(), &allow_credentials)
                .map_err(e)?,
            warnings,
        ),
        Request::PasskeyGet {
            origin,
            rp_id,
            challenge,
            item,
            password,
        } => {
            // Only a login Klav would sign with gets to ask for Touch ID.
            let candidates = u
                .passkey_candidates(&origin, rp_id.as_deref(), &[])
                .map_err(e)?;
            let Some(site) = candidates.rp_id else {
                return Err(ErrorBody {
                    code: ErrorCode::Denied,
                    message: "not a passkey page".into(),
                    paused: None,
                    presence: None,
                });
            };
            if !candidates
                .candidates
                .iter()
                .any(|c| c.item.to_string() == item)
            {
                return Err(ErrorBody {
                    code: ErrorCode::NotFound,
                    message: "no passkey for this site in that login".into(),
                    paused: None,
                    presence: None,
                });
            }
            let reason = Prompt::PasskeySignIn { site: &site }.reason(Lang::current(), source);
            passkey_presence(state, slot, password, &reason, caller, behind)?;
            let assertion = u
                .passkey_get(&origin, rp_id.as_deref(), &challenge, &item, true)
                .map_err(e)?;
            log_passkey_use(state, u, assertion.item, None);
            ok(assertion, warnings)
        }
        Request::PasskeyCreate { request, password } => {
            let site = klav_core::passkey::rp::validate(&request.origin, request.rp_id.as_deref());
            let Ok(site) = site else {
                return ok(
                    klav_client::passkeys::PasskeyCreateOutcome::Browser,
                    warnings,
                );
            };
            let reason = Prompt::PasskeySave { site: &site.rp_id }.reason(Lang::current(), source);
            passkey_presence(state, slot, password, &reason, caller, behind)?;
            ok(u.passkey_create(&request, true).await.map_err(e)?, warnings)
        }
        Request::Resolve { references, .. } => {
            ok(u.resolve_all(&references).await.map_err(e)?, warnings)
        }
        Request::Attach {
            query,
            field,
            file_name,
            content,
        } => ok(
            u.attach(&query, &field, &file_name, None, content.expose())
                .await
                .map_err(e)?,
            warnings,
        ),
        Request::GeneratorRecord { value, host } => {
            let created_at = u
                .record_generated(value.expose(), host.as_deref())
                .map_err(e)?;
            ok(serde_json::json!({ "created_at": created_at }), warnings)
        }
        Request::GeneratorHistory => ok(u.generator_history().map_err(e)?, warnings),
        Request::GeneratedValue { created_at, .. } => {
            ok(u.generated_value(created_at).map_err(e)?, warnings)
        }
        Request::GeneratorDelete { which } => {
            let removed = u.delete_generated(&which).await.map_err(e)?;
            ok(serde_json::json!({ "removed": removed }), warnings)
        }
        Request::PasswordHistory { query } => {
            let loc = u.find_item(&query).map_err(e)?;
            ok(u.password_history(loc).map_err(e)?, warnings)
        }
        Request::PreviousPassword { query, index, .. } => {
            let loc = u.find_item(&query).map_err(e)?;
            ok(u.previous_password(loc, index).map_err(e)?, warnings)
        }
        Request::ImportAdd {
            session: id,
            name,
            from,
            data,
            more,
        } => ok(
            session
                .imports
                .add(id.as_deref(), &name, from.as_deref(), data.expose(), more)?,
            warnings,
        ),
        Request::ImportPreview {
            session: id,
            vault,
            project,
        } => {
            let set = session.imports.get(&id)?;
            ok(
                u.import_preview(set, vault.as_deref(), project.as_deref(), PREVIEW_ROWS)
                    .map_err(e)?,
                warnings,
            )
        }
        Request::ImportApply {
            session: id,
            vault,
            project,
        } => {
            let set = session.imports.get(&id)?;
            let done = u
                .import_apply(set, vault.as_deref(), project.as_deref())
                .await
                .map_err(e)?;
            session.imports.remove(&id);
            ok(done, warnings)
        }
        Request::ImportCancel { session: id } => {
            session.imports.remove(&id);
            ok(serde_json::json!({}), warnings)
        }
        Request::Agents => ok(u.agents().await.map_err(e)?, warnings),
        Request::AgentLabels => ok(u.agent_labels().map_err(e)?, warnings),
        Request::SetAgentLabel { agent, label, host } => {
            let entry = klav_core::model::agent_labels::AgentLabel {
                label,
                host,
                role_hint: None,
            };
            let entry = (!entry.is_empty()).then_some(entry);
            ok(u.set_agent_label(agent, entry).await.map_err(e)?, warnings)
        }
        Request::ApproveAgent {
            agent,
            grant,
            pairing_code,
            password,
        } => {
            // Everything that can fail is checked before asking for
            // presence: the projects, the agent's state, its words.
            let prepared = u
                .prepare_grant(agent, grant, &pairing_code)
                .await
                .map_err(e)?;
            // Only a pending registration: an active agent's grant changes
            // through the sheet of differences, whose dialog names what
            // widens (ADR 0033, amendment of 2026-11-10, F4, T187).
            if !prepared.first() {
                return Err(ErrorBody {
                    code: ErrorCode::Invalid,
                    message: format!(
                        "agent {} is already active: change its grant with grant_change_prepare and grant_change_apply (`klav agent approve` does it, showing the differences)",
                        prepared.agent_name()
                    ),
                    paused: None,
                    presence: None,
                });
            }
            confirm(
                Prompt::Grant {
                    agent: prepared.agent_name(),
                    places: prepared.places(),
                },
                password,
            )?;
            let mut warnings = warnings;
            warnings.extend(prepared.warnings().iter().cloned());
            ok(u.grant_prepared(prepared).await.map_err(e)?, warnings)
        }
        Request::Approvals { all } => ok(u.approvals(all).await.map_err(e)?, warnings),
        Request::DecideApproval {
            approval,
            approve,
            digest,
            lease_secs,
            password,
        } => {
            let view = u.find_approval(&approval).await.map_err(e)?;
            let id = view.id;
            // A security card (ADR 0049 §5.4, T260) is never decided, and
            // never reaches Touch ID: refused before any prompt.
            klav_client::agents::refuse_security_card(&view).map_err(e)?;
            if approve {
                // An MCP tool call's prompt is fixed text, the profile the
                // person signed and the tool: never the agent's words.
                let profile = match view.mcp_tool {
                    Some(_) => mcp_profile(u, &view).await,
                    None => None,
                };
                let prompt = match &view.mcp_tool {
                    Some(tool) => Prompt::McpTool {
                        profile: profile.as_deref(),
                        tool,
                        lease: lease_secs.is_some(),
                    },
                    None => Prompt::Request {
                        agent: &view.agent,
                        permission: view.permission,
                        target: view.target_name.as_deref(),
                    },
                };
                confirm(prompt, password)?;
            }
            ok(
                u.decide_approval(
                    id,
                    approve,
                    lease_secs.map(std::time::Duration::from_secs),
                    &digest,
                )
                .await
                .map_err(e)?,
                warnings,
            )
        }
        Request::Tasks { all } => ok(u.tasks(all).await.map_err(e)?, warnings),
        Request::DecideTask {
            task,
            approve,
            digest,
            choice,
            password,
        } => {
            let pending = u.tasks(false).await.map_err(e)?;
            let card = klav_client::tasks::find_task(&pending, &task).map_err(e)?;
            let id = card.id;
            if approve {
                confirm(
                    Prompt::Task {
                        agent: &card.agent,
                        items: card.approved_items(&choice),
                    },
                    password,
                )?;
            }
            ok(
                u.decide_task(id, approve, &choice, &digest)
                    .await
                    .map_err(e)?,
                warnings,
            )
        }
        Request::AddToTask {
            approval,
            digest,
            password,
        } => {
            let view = u.find_approval(&approval).await.map_err(e)?;
            klav_client::agents::refuse_security_card(&view).map_err(e)?;
            confirm(
                Prompt::AddToTask {
                    agent: &view.agent,
                    item: view.target_name.as_deref(),
                },
                password,
            )?;
            ok(u.add_to_task(view.id, &digest).await.map_err(e)?, warnings)
        }
        Request::EndTask { task } => {
            let live = u.tasks(false).await.map_err(e)?;
            let id = klav_client::tasks::find_task(&live, &task).map_err(e)?.id;
            ok(u.end_task(id).await.map_err(e)?, warnings)
        }
        Request::TaskLog { task } => ok(u.task_log(&task).await.map_err(e)?, warnings),
        Request::SecretRequests { all } => ok(u.secret_requests(all).await.map_err(e)?, warnings),
        Request::FulfillSecretRequest {
            request,
            input,
            password,
        } => {
            let pending = u.secret_requests(false).await.map_err(e)?;
            let card = klav_client::secret_requests::find_secret_request(&pending, &request)
                .map_err(e)?
                .clone();
            if input.grant_proxy {
                if card.proposal_digest != input.digest.trim().to_ascii_lowercase() {
                    return Err(e(ClientError::Security(format!(
                        "secret request {} changed since it was shown; reload and review it again",
                        card.id
                    ))));
                }
                let host = input
                    .proxy_credential
                    .as_ref()
                    .map(|spec| spec.upstream.as_str())
                    .or_else(|| {
                        card.proposal
                            .as_ref()
                            .and_then(|p| p.proxy_proposal.as_ref())
                            .map(|pp| pp.upstream.as_str())
                    })
                    .ok_or_else(|| {
                        e(ClientError::Invalid(
                            "grant_proxy requested, but neither the proposal nor the caller supplied a proxy profile".into(),
                        ))
                    })?;
                let title = input
                    .title
                    .as_deref()
                    .or_else(|| card.proposal.as_ref().and_then(|p| p.title.as_deref()))
                    .or(card.target_title.as_deref());
                confirm(
                    Prompt::SecretRequestProxy {
                        agent: &card.agent,
                        title,
                        host,
                    },
                    password,
                )?;
            }
            let result = u.fulfill_secret_request(card.id, &input).await.map_err(e)?;
            let mut warnings = warnings;
            warnings.extend(result.proxy_warnings.iter().cloned());
            ok(result, warnings)
        }
        Request::DenySecretRequest { request, digest } => {
            let pending = u.secret_requests(false).await.map_err(e)?;
            let card =
                klav_client::secret_requests::find_secret_request(&pending, &request).map_err(e)?;
            ok(
                u.deny_secret_request(card.id, &digest).await.map_err(e)?,
                warnings,
            )
        }
        Request::AgentExposure { agent } => ok(u.agent_exposure(agent).await.map_err(e)?, warnings),
        Request::AgentRevocations => {
            let pending = u.pending_revocations();
            state.note_revocations(&pending);
            ok(pending.map_err(e)?, warnings)
        }
        Request::GrantEditor { agent } => ok(u.grant_editor(agent).await.map_err(e)?, warnings),
        Request::GrantChangePrepare { agent, change } => {
            let prepared = u.prepare_grant_change(agent, &change).await.map_err(e)?;
            ok(prepared.preview(), warnings)
        }
        Request::GrantChangeApply {
            agent,
            change,
            digest,
            password,
        } => {
            // Built again from the grant in force, verified here: the
            // caller's sheet only counts if it is still this one (T188),
            // and whether it widens is never the caller's word (T187).
            let prepared = u.prepare_grant_change(agent, &change).await.map_err(e)?;
            prepared.check_shown(&digest).map_err(e)?;
            if prepared.widens() {
                let lines = prepared.widening_lines();
                let more: Vec<Widening<'_>> =
                    lines.iter().filter_map(|l| Widening::of(l)).collect();
                confirm(
                    Prompt::GrantChange {
                        agent: &prepared.preview().name,
                        more: &more,
                    },
                    password,
                )?;
            }
            let mut warnings = warnings;
            warnings.extend(prepared.preview().warnings.iter().cloned());
            let report = u.commit_grant_change(prepared).await;
            // A narrowing's key change left over shows in `status`, and
            // resumes at the next unlock (P11).
            state.note_revocations(&u.pending_revocations());
            ok(report.map_err(e)?, warnings)
        }
        Request::ProxyStatus => ok(u.proxy_status().await.map_err(e)?, warnings),
        Request::ProxyUse { agent, password } => {
            // Checked before presence: the agent, and the old proxy.
            let prepared = u.prepare_proxy_use(agent.as_deref()).await.map_err(e)?;
            confirm(
                Prompt::ProxyUse {
                    agent: prepared.agent.as_deref(),
                    replaces: prepared.replaces_agent.is_some(),
                },
                password,
            )?;
            // Checked again after presence: the old proxy may have got a
            // credential, the agent changed, or an agent wrote another
            // preferences item, while the dialog was open.
            let again = u.prepare_proxy_use(agent.as_deref()).await.map_err(e)?;
            if !again.same_setting(&prepared) {
                return Err(e(ClientError::Invalid(
                    "the proxy setting changed while you confirmed; run it again".into(),
                )));
            }
            let resigned = u.commit_proxy_use(again).await.map_err(e)?;
            // Like the direct path: an issuer still naming the old proxy
            // fails the command (it exits non-zero), with all that was
            // done in the message.
            let more = resign_result(&resigned).map_err(e)?;
            let mut warnings = warnings;
            // What `use` replaced, and what it could not check (the
            // caller printed the older clients' warning itself).
            warnings.extend(
                prepared
                    .warnings
                    .iter()
                    .filter(|w| w.as_str() != klav_client::proxy_admin::OLDER_CLIENTS_PREFERENCES)
                    .cloned(),
            );
            warnings.extend(more);
            ok(u.proxy_status().await.map_err(e)?, warnings)
        }
        Request::ProxyGrantPreview { item, credential } => ok(
            u.preview_proxy_grant(&item, &credential).await.map_err(e)?,
            warnings,
        ),
        Request::ProxyGrant {
            item,
            credential,
            base_version,
            every_device_updated,
            shown_words,
            shown_item,
            password,
        } => {
            // The words are checked by the person in the prompt below,
            // derived here from the key the commit signs for: none the
            // caller sends authorise anything.
            let prepared = u
                .prepare_proxy_grant(&item, &credential, PairingCheck::InPrompt)
                .await
                .map_err(e)?;
            let view = prepared.view();
            if view.base_version != base_version {
                return Err(e(ClientError::Invalid(format!(
                    "the grant of the proxy {:?} changed since it was shown (version {}); run it again",
                    view.agent, view.base_version
                ))));
            }
            // The item is found again by what the caller sent, and its
            // title can change meanwhile: it must still be the one shown.
            if shown_item.is_some_and(|shown| shown != view.item_id) {
                return Err(e(ClientError::Invalid(format!(
                    "{:?} names another item than the one shown; nothing granted. Run it again",
                    item
                ))));
            }
            // Pending: the words shown before presence must still be the
            // key's. Touch ID shows them again; the master password does
            // not, so this is what catches a key swapped meanwhile.
            if view.first && shown_words.as_deref() != Some(view.pairing_code.as_str()) {
                return Err(e(ClientError::Security(format!(
                    "the key of the proxy {:?} is not the one whose words were shown; nothing granted. Run it again and compare the words",
                    view.agent
                ))));
            }
            prepared
                .require_updated_devices(every_device_updated)
                .map_err(e)?;
            let shown = GrantShown::of(view);
            confirm(
                grant_prompt(view, &shown, prepared.issuers_keeping()),
                password,
            )?;
            ok(u.commit_proxy_change(prepared).await.map_err(e)?, warnings)
        }
        Request::ProxyIssuerPreview { agent, issuer } => ok(
            u.preview_issuer_add(&agent, &issuer).await.map_err(e)?,
            warnings,
        ),
        Request::ProxyIssuerAdd {
            agent,
            issuer,
            proxy_base_version,
            issuer_base_version,
            shown_issuer,
            shown_proxy,
            every_device_updated,
            shown_words,
            password,
        } => {
            // As `ProxyGrant`: the words and both versions shown before
            // presence must still be what this signs, and the dialog says
            // all of it.
            let prepared = u
                .prepare_issuer_add(&agent, &issuer, PairingCheck::InPrompt)
                .await
                .map_err(e)?;
            let view = prepared.view();
            if view.proxy_base_version != proxy_base_version
                || view.issuer_base_version != issuer_base_version
            {
                return Err(e(ClientError::Invalid(format!(
                    "the grant of {:?} or of the proxy {:?} changed since it was shown; run it again",
                    view.issuer, view.proxy
                ))));
            }
            if view.issuer_id != shown_issuer || view.proxy_id != shown_proxy {
                return Err(e(ClientError::Invalid(format!(
                    "{agent:?} or the account's proxy is another agent than the one shown; nothing signed. Run it again"
                ))));
            }
            if view.pending && shown_words.as_deref() != Some(view.pairing_code.as_str()) {
                return Err(e(ClientError::Security(format!(
                    "the key of agent {:?} is not the one whose words were shown; nothing signed. Run it again and compare the words",
                    view.issuer
                ))));
            }
            prepared
                .require_updated_devices(every_device_updated)
                .map_err(e)?;
            confirm(
                Prompt::ProxyIssuerAdd {
                    issuer: &view.issuer,
                    proxy: &view.proxy,
                    address: &view.url,
                    profiles: &view.profiles,
                    max_ttl_secs: view.max_ttl_secs,
                    max_live: view.max_live,
                    words: view.pending.then_some(view.pairing_code.as_str()),
                    inject_ask: view.inject_ask,
                    first_on_account: view.first_on_account,
                },
                password,
            )?;
            let mut warnings = warnings;
            warnings.extend(view.warnings.iter().cloned());
            ok(u.commit_issuer_change(prepared).await.map_err(e)?, warnings)
        }
        Request::ProxyIssuerRemove { agent, password } => {
            let prepared = u.prepare_issuer_remove(&agent).await.map_err(e)?;
            let view = prepared.view();
            confirm(
                Prompt::ProxyIssuerRemove {
                    issuer: &view.issuer,
                    proxy: &view.proxy,
                },
                password,
            )?;
            ok(u.commit_issuer_change(prepared).await.map_err(e)?, warnings)
        }
        Request::LocalClientPreview { name, change } => {
            let prepared = u.prepare_local_client(&name, &change).await.map_err(e)?;
            ok(prepared.view(), warnings)
        }
        Request::LocalClientChange {
            name,
            change,
            base_version,
            shown_proxy,
            password,
        } => {
            let prepared = u.prepare_local_client(&name, &change).await.map_err(e)?;
            let view = prepared.view();
            if view.base_version != base_version || view.agent_id != shown_proxy {
                return Err(e(ClientError::Invalid(format!(
                    "the grant of the proxy {:?} changed since it was shown; run it again",
                    view.agent
                ))));
            }
            let mut warnings = warnings;
            warnings.extend(view.warnings.iter().cloned());
            confirm(
                Prompt::LocalClient {
                    client: &view.name,
                    proxy: &view.agent,
                    profiles: &view.profiles,
                },
                password,
            )?;
            ok(u.commit_local_client(prepared).await.map_err(e)?, warnings)
        }
        Request::McpGateway => ok(u.mcp_gateway_state().await.map_err(e)?, warnings),
        Request::McpGatewayOn {
            every_device_updated,
            password,
        } => {
            // A server older than the gateway, or an acknowledgement
            // missing, is refused before presence; an account already on
            // asks for nothing.
            match u.mcp_gateway_state().await.map_err(e)? {
                None => {
                    return Err(e(ClientError::Invalid(
                        "this Klav server is older than the MCP gateway (ADR 0049): update the server first".into(),
                    )));
                }
                Some(true) => return ok(true, warnings),
                Some(false) => {}
            }
            if !every_device_updated {
                return Err(e(ClientError::Invalid(format!(
                    "{}. Then confirm that every device is updated",
                    klav_client::proxy_admin::OLDER_CLIENTS_MCP
                ))));
            }
            confirm(Prompt::McpGatewayOn, password)?;
            u.turn_mcp_gateway_on().await.map_err(e)?;
            ok(true, warnings)
        }
        Request::ProxyRevoke { item, password } => {
            let prepared = u.prepare_proxy_revoke(&item).await.map_err(e)?;
            let view = prepared.view();
            let mut warnings = warnings;
            warnings.extend(view.warnings.iter().cloned());
            let title = if view.title.is_empty() {
                view.item_id.to_string()
            } else {
                view.title.clone()
            };
            let item = ItemShown {
                title: &title,
                place: &view.place,
                site: view.site.as_deref(),
            };
            // A retry that only finishes re-issuing the other holders takes
            // nothing away: say what it does.
            let prompt = if view.reissue_only {
                Prompt::ProxyReissue {
                    item,
                    agents: &view.holders,
                }
            } else {
                Prompt::ProxyRevoke {
                    agent: &view.agent,
                    item,
                    issuers_losing: view.issuers_losing.len(),
                }
            };
            confirm(prompt, password)?;
            ok(u.commit_proxy_change(prepared).await.map_err(e)?, warnings)
        }
        Request::ResumeAgents { agent, password } => {
            // The name for the prompt; an unknown agent fails before it.
            let name = match agent {
                Some(id) => Some(
                    u.agents()
                        .await
                        .map_err(e)?
                        .into_iter()
                        .find(|a| a.id == id)
                        .ok_or_else(|| e(ClientError::NotFound(format!("agent {id}"))))?
                        .name,
                ),
                None => None,
            };
            confirm(
                Prompt::Resume {
                    agent: name.as_deref(),
                },
                password,
            )?;
            // Never sent: lifted here and now.
            state.forget_local_pause(agent);
            let mut warnings = warnings;
            if let Err(err) = u.resume_agents(agent).await {
                let held = u.agent_pauses().iter().any(|p| p.agent_id == agent);
                match resume_not_sent(&err, agent, held) {
                    Some(warning) => warnings.push(warning),
                    None => return Err(error_body(&err)),
                }
            }
            state.learn_pauses(u);
            ok(state.pauses_in_effect(), warnings)
        }
        Request::CancelAccountDeletion { password } => {
            // Canceling brings the agents back: presence, as resuming them
            // asks for (ADR 0037 A2).
            confirm(Prompt::CancelDeletion, password)?;
            let canceled = u.cancel_account_deletion().await.map_err(e)?;
            state.learn_pauses(u);
            ok(serde_json::json!({ "canceled": canceled }), warnings)
        }
        Request::AuditLog { filter } => ok(u.audit_log(&filter).await.map_err(e)?, warnings),
        Request::VerifyAudit => ok(u.verify_audit().await.map_err(e)?, warnings),
        Request::SandboxList => ok(u.sandbox_list().await.map_err(e)?, warnings),
        Request::SandboxListFlagged => ok(u.sandbox_list_flagged().await.map_err(e)?, warnings),
        Request::SandboxListChecked => ok(
            klav_client::sandboxes::CheckedList::from(u.sandbox_list_checked().await.map_err(e)?),
            warnings,
        ),
        Request::SandboxRevoke { proxy, scope } => {
            let target = klav_proto::sandbox::parse_scope(&scope).map_err(|m| bad_request(&m))?;
            ok(
                u.revoke_sandboxes_outcome(proxy, target).await.map_err(e)?,
                warnings,
            )
        }
        Request::ItemActivity { item } => ok(u.item_activity(&item).await.map_err(e)?, warnings),
        Request::AuditStatus => ok(u.audit_status(), warnings),
        Request::DenyAgent { agent } => {
            u.deny_agent(agent).await.map_err(e)?;
            ok(serde_json::json!({}), warnings)
        }
        Request::AgentRotateConfirm { step } => {
            // Paused, the new password does not become current: it stays
            // pending, for the person to decide from the item's card.
            // Cancelling, which keeps the current one, still works.
            state.refuse_deleting()?;
            state.refuse_paused(Some(step.agent_id))?;
            u.rotation_finish(&step, true).await.map_err(e)?;
            ok(serde_json::json!({ "ok": true }), warnings)
        }
        Request::AgentRotateCancel { step } => {
            u.rotation_finish(&step, false).await.map_err(e)?;
            ok(serde_json::json!({ "ok": true }), warnings)
        }
        // Read only: no pause or deletion refuses it, as it changes
        // nothing; the step the agent sends next is refused by both.
        Request::AgentRotatePending { step } => ok(
            serde_json::json!({ "pending": u.rotation_pending(&step).await.map_err(e)? }),
            warnings,
        ),
        Request::ResolvePending { query, accept } => {
            let loc = u.find_item(&query).map_err(e)?;
            let mut warnings = warnings;
            warnings.extend(u.resolve_pending(loc, accept).await.map_err(e)?);
            ok(u.password_history(loc).map_err(e)?, warnings)
        }
        Request::ReusedOffer { agent } => {
            let now = SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX));
            // zxcvbn over every password is CPU work: keep it off the async
            // workers. No breach check here: only the reused groups count.
            let scan = tokio::task::block_in_place(|| u.health_scan(now));
            let report = scan.finish(None).await;
            ok(
                u.reused_offer_from(&report, agent.as_deref())
                    .await
                    .map_err(e)?,
                warnings,
            )
        }
        Request::OfferTask { offer, password } => {
            // Everything that can fail is checked before asking for
            // presence.
            let prepared = u.prepare_offer(&offer).await.map_err(e)?;
            confirm(
                Prompt::Offer {
                    agent: prepared.agent_name(),
                    passwords: prepared.len(),
                },
                password,
            )?;
            ok(u.send_offer(prepared).await.map_err(e)?, warnings)
        }
        Request::TaskProgress { task } => ok(u.task_progress(&task).await.map_err(e)?, warnings),
        Request::ExtensionAttach { .. }
        | Request::ExtensionReply { .. }
        | Request::ExtensionPresence { .. }
        | Request::BrowserTab
        | Request::BrowserFill { .. } => Err(bad_request("not handled here")),
        Request::Status
        | Request::Lock
        | Request::Shutdown
        | Request::Unlock { .. }
        | Request::VaultHealth
        | Request::HealthSettings { .. }
        | Request::PasskeyUv { .. }
        | Request::Hold
        | Request::PresenceWindow { .. }
        | Request::AgentRotateBegin { .. }
        | Request::AgentPasskeyArm { .. }
        | Request::AgentPasskeyUse { .. }
        | Request::PauseAgents { .. }
        | Request::ConfirmPresence { .. }
        | Request::AuditReset
        | Request::RevokeAgent { .. } => {
            unreachable!("handled above")
        }
    }
}

impl Session {
    fn synced(&mut self) {
        self.last_sync = Some(Instant::now());
        self.sync_error = None;
        self.rollback = None;
        self.offline = None;
    }

    /// Records a failed sync. Offline is a warning, and so is a refused
    /// state (a rollback or another security check, T7): that sync changed
    /// nothing, and this device keeps working with the copy it already
    /// verified, saying so on every request until a sync succeeds.
    /// Otherwise a hostile server (one that announced an impossible
    /// revision once) would lock the person out of their own vault for
    /// good. Anything else (an expired session, a corrupt cache) is an
    /// error for the requests that follow (ADR 0026 §3), returned here.
    fn sync_failed(&mut self, e: &ClientError) -> Option<ErrorBody> {
        match e {
            ClientError::Network(why) => {
                self.offline = Some(format!("offline ({why}); using the local copy"));
                None
            }
            // Not an error for the reads: the copy stays, read-only, and
            // nothing deletes it but the person (ADR 0037 §3, T165).
            ClientError::AccountDeleted(at) => {
                self.last_sync = Some(Instant::now());
                self.sync_error = None;
                self.offline = None;
                self.deleted = Some(deleted_warning(*at));
                None
            }
            ClientError::Rollback(_) | ClientError::Security(_) => {
                // Tried again after `sync_after`, not on every request.
                self.last_sync = Some(Instant::now());
                self.sync_error = None;
                self.offline = None;
                self.rollback = Some(format!(
                    "{e}. klavd keeps using this device's copy, unchanged, and keeps checking. \
                     If the server was restored from a backup you trust, \
                     `klav sync --reset-cache` starts over"
                ));
                None
            }
            e => {
                let body = error_body(e);
                self.sync_error = Some(body.clone());
                Some(body)
            }
        }
    }

    /// The warnings every request carries: offline, a refused state, and
    /// the account's own.
    fn warnings(&self) -> Vec<String> {
        let mut warnings: Vec<String> = self.deleted.iter().cloned().collect();
        warnings.extend(self.rollback.iter().cloned());
        warnings.extend(self.offline.iter().cloned());
        warnings.extend(self.unlocked.warnings().iter().cloned());
        warnings
    }
}

/// Moves `State::revision` if a sync changed the cache, or the pauses of
/// agents, since last time.
fn track(state: &State, session: &mut Session) {
    state.learn_pauses(&session.unlocked);
    if session.deleted.is_some() {
        state.mark_deleted();
    }
    let generation = session.unlocked.generation();
    if generation != session.seen_cache_generation {
        session.seen_cache_generation = generation;
        state.revision.fetch_add(1, Ordering::Relaxed);
    }
}

fn is_stale(state: &State, session: &Session) -> bool {
    // A deleted account has nothing left to sync (ADR 0037 §3).
    if session.deleted.is_some() {
        return false;
    }
    session.sync_error.is_some()
        || session
            .last_sync
            .is_none_or(|t| t.elapsed() >= state.config.sync_after)
}

/// Syncs first when the local copy is older than `sync_after`, or the last
/// sync failed (or always with `force`). See [`Session::sync_failed`] for
/// what is a warning and what an error.
async fn refresh(
    state: &State,
    session: &mut Session,
    force: bool,
) -> Result<Vec<String>, ErrorBody> {
    if force || is_stale(state, session) {
        match session.unlocked.sync().await {
            Ok(_) => session.synced(),
            Err(e) => {
                if let Some(error) = session.sync_failed(&e) {
                    return Err(error);
                }
            }
        }
    }
    let mut warnings = session.warnings();
    // An unlock signs and sends the pauses decided while locked, and tries
    // once more the ones an older server did not support.
    if force && session.offline.is_none() && !state.pause_book().local.is_empty() {
        warnings.extend(send_local_pauses(state, session, true).await.1);
    }
    state.learn_pauses(&session.unlocked);
    Ok(warnings)
}

/// Stale-while-revalidate for the reads of [`reads_without_syncing`]
/// (ADR 0026): they answer from the local copy at once, and a copy that is
/// too old is synced in the background, one sync at a time. A refused
/// state stays a warning (see [`Session::sync_failed`]); any other
/// failure that is not the network fails every read until a sync
/// succeeds, and each of those reads tries again in the background.
fn revalidate(
    state: &Arc<State>,
    slot: &Arc<Slot>,
    session: &Session,
) -> Result<Vec<String>, ErrorBody> {
    if is_stale(state, session) {
        let mut syncing = slot.syncing.lock().unwrap_or_else(PoisonError::into_inner);
        if syncing.as_ref().is_none_or(JoinHandle::is_finished) {
            *syncing = Some(tokio::spawn(background_sync(
                Arc::clone(state),
                Arc::downgrade(slot),
                slot.generation,
            )));
        }
    }
    if let Some(error) = &session.sync_error {
        return Err(error.clone());
    }
    Ok(session.warnings())
}

/// How long `passkey.used` may take to reach the server.
const PASSKEY_USED_TIMEOUT: Duration = Duration::from_secs(10);

/// Sends `passkey.used` for `item` to the audit log after the page got its
/// assertion (ADR 0020 §10): best effort, in the background and with a time
/// limit, so the sign-in never waits on the network and a failure only
/// loses the event. The round trip goes without the session; only an
/// expired token makes it retry with the session, which refreshes it. Like
/// [`background_sync`], it holds the slot only through a [`Weak`] and stops
/// if klavd locks, so locking still wipes the keys at once.
fn log_passkey_use(
    state: &Arc<State>,
    u: &Unlocked,
    item: ItemId,
    agent: Option<(AgentId, TaskId)>,
) {
    // An account the server deleted keeps no audit log to send it to
    // (ADR 0037 §3): the sign-in works from the copy, without the event.
    if u.account_deleted() {
        return;
    }
    let post = u.passkey_used_post(item, agent);
    // `dispatch` runs in the current slot: locking cancels it first.
    let Some(slot) = state.current() else {
        return;
    };
    let since = slot.generation;
    let slot = Arc::downgrade(&slot);
    let state = Arc::clone(state);
    tokio::spawn(async move {
        if let Some(post) = post {
            match tokio::time::timeout(PASSKEY_USED_TIMEOUT, post.send()).await {
                // Sent, or the network failed: nothing more to do.
                Ok(Ok(true) | Err(_)) | Err(_) => return,
                // The token was refused: with the session.
                Ok(Ok(false)) => {}
            }
        }
        let _ = state
            .unless_locked(since, async {
                let Some(slot) = slot.upgrade() else {
                    return Ok(());
                };
                let mut session = slot.session.lock().await;
                let _ = tokio::time::timeout(
                    PASSKEY_USED_TIMEOUT,
                    session.unlocked.log_passkey_used(item, agent),
                )
                .await;
                Ok(())
            })
            .await;
    });
}

/// One background sync, cancelled if klavd locks (the slot's lock
/// generation moves). It holds the session only to plan and to apply, and
/// the slot only through a [`Weak`] in between, so locking wipes the keys
/// at once.
async fn background_sync(state: Arc<State>, slot: Weak<Slot>, since: u64) {
    let _ = state
        .unless_locked(since, background_steps(&state, &slot))
        .await;
}

/// [`background_sync`]: plan with the account, fetch without it, apply with
/// it. Applying runs the same rollback checks as any sync (T7) and is
/// skipped if another sync changed the cache in between.
async fn background_steps(state: &State, slot: &Weak<Slot>) -> Result<(), ErrorBody> {
    let plan = {
        let Some(slot) = slot.upgrade() else {
            return Ok(());
        };
        let mut session = slot.session.lock().await;
        if session.unlocked.sync_plan().is_none()
            && let Err(e) = session.unlocked.refresh_session().await
        {
            finish(state, &mut session, Err(e));
            return Ok(());
        }
        match session.unlocked.sync_plan() {
            Some(plan) => plan,
            None => {
                // Still no usable token: sync holding the account.
                let result = session.unlocked.sync().await.map(|_| ());
                finish(state, &mut session, result);
                return Ok(());
            }
        }
    };
    let fetched = plan.fetch().await;
    let Some(slot) = slot.upgrade() else {
        return Ok(());
    };
    let mut session = slot.session.lock().await;
    let result = match fetched {
        Ok(Some(fetched)) => match session.unlocked.finish_sync(fetched).await {
            Ok(Some(_)) => Ok(()),
            // Another sync changed the cache meanwhile: it stands.
            Ok(None) => return Ok(()),
            Err(e) => Err(e),
        },
        // The token was refused (rotated meanwhile): sync holding the account.
        Ok(None) => session.unlocked.sync().await.map(|_| ()),
        Err(e) => Err(e),
    };
    finish(state, &mut session, result);
    Ok(())
}

fn finish(state: &State, session: &mut Session, result: Result<(), ClientError>) {
    match result {
        Ok(()) => session.synced(),
        Err(e) => {
            session.sync_failed(&e);
        }
    }
    track(state, session);
}

#[cfg(test)]
mod tests {

    /// The `op` of a `Request` variant: `AgentPasskeyUse` → `agent_passkey_use`.
    fn op_name(variant: &str) -> String {
        let mut op = String::new();
        for (i, c) in variant.chars().enumerate() {
            if c.is_ascii_uppercase() && i > 0 {
                op.push('_');
            }
            op.push(c.to_ascii_lowercase());
        }
        op
    }

    /// The `op`s named `Request::…` in `text`.
    fn ops_in(text: &str) -> Vec<String> {
        text.split("Request::")
            .skip(1)
            .map(|rest| {
                op_name(
                    &rest
                        .chars()
                        .take_while(char::is_ascii_alphanumeric)
                        .collect::<String>(),
                )
            })
            .collect()
    }

    /// The idle lock's classification names every operation once, and
    /// `docs/klavd.md` (§2, «What counts as use») lists the same groups.
    /// A missing operation already stops `counts_as_use` from building (no
    /// arm picks for it); this catches an operation moved between groups
    /// without the docs, and a docs list that lost or gained one.
    #[test]
    fn every_operation_is_classified_for_the_idle_lock_as_the_docs_say() {
        use std::collections::BTreeSet;
        // Every variant of `Request`, from its source: four spaces and a
        // capital letter (fields have eight, docs and attributes start
        // otherwise).
        let protocol = include_str!("protocol.rs");
        let enum_body = protocol
            .split("pub enum Request {")
            .nth(1)
            .and_then(|rest| rest.split("\n}\n").next())
            .expect("enum Request");
        let ops: BTreeSet<String> = enum_body
            .lines()
            .filter_map(|line| line.strip_prefix("    "))
            .filter(|line| line.starts_with(|c: char| c.is_ascii_uppercase()))
            .map(|line| {
                op_name(
                    &line
                        .chars()
                        .take_while(char::is_ascii_alphanumeric)
                        .collect::<String>(),
                )
            })
            .collect();
        assert!(
            ops.len() > 80,
            "{} operations read from protocol.rs",
            ops.len()
        );

        // The arms of `counts_as_use`: what each one answers follows its
        // `=>`, and its patterns come before it.
        let source = include_str!("server.rs");
        let body = source
            .split("fn counts_as_use(")
            .nth(1)
            .and_then(|rest| rest.split("\n}\n").next())
            .expect("fn counts_as_use");
        let arms: Vec<&str> = body.split("=>").collect();
        let (mut not_use, mut setting, mut used) = (Vec::new(), Vec::new(), Vec::new());
        for pair in arms.windows(2) {
            let answer = pair[1].trim_start();
            let group = if answer.starts_with("false") {
                &mut not_use
            } else if answer.starts_with("true") {
                &mut used
            } else {
                &mut setting
            };
            // The answers and the comments name no `Request::`.
            group.extend(ops_in(pair[0]));
        }
        let all: Vec<&String> = not_use.iter().chain(&setting).chain(&used).collect();
        let named: BTreeSet<&String> = all.iter().copied().collect();
        assert_eq!(all.len(), named.len(), "an operation is in two arms");
        assert_eq!(
            named,
            ops.iter().collect::<BTreeSet<_>>(),
            "counts_as_use and Request differ"
        );

        // The docs' three lists.
        let docs = include_str!("../../../docs/klavd.md");
        let list = |label: &str| -> BTreeSet<String> {
            let line = docs
                .lines()
                .find(|l| l.starts_with(&format!("- **{label}**")))
                .unwrap_or_else(|| panic!("no list {label:?} in docs/klavd.md"));
            line.split('`')
                .skip(1)
                .step_by(2)
                .map(str::to_owned)
                .collect()
        };
        let set = |v: &[String]| v.iter().cloned().collect::<BTreeSet<_>>();
        assert_eq!(list("Not use"), set(&not_use), "docs/klavd.md: Not use");
        assert_eq!(
            list("Use only when it changes the setting"),
            set(&setting),
            "docs/klavd.md: Use only when it changes the setting"
        );
        assert_eq!(list("Use"), set(&used), "docs/klavd.md: Use");
    }

    #[test]
    fn reading_a_setting_is_not_use_and_changing_it_is() {
        use super::{Request, counts_as_use};
        let request =
            |json: serde_json::Value| -> Request { serde_json::from_value(json).expect("request") };
        assert!(!counts_as_use(&request(
            serde_json::json!({ "op": "health_settings" })
        )));
        assert!(counts_as_use(&request(
            serde_json::json!({ "op": "health_settings", "breach_check": false })
        )));
        assert!(!counts_as_use(&request(
            serde_json::json!({ "op": "passkey_uv" })
        )));
        assert!(counts_as_use(&request(
            serde_json::json!({ "op": "passkey_uv", "window": "always" })
        )));
        assert!(!counts_as_use(&request(
            serde_json::json!({ "op": "presence_window" })
        )));
        assert!(counts_as_use(&request(
            serde_json::json!({ "op": "presence_window", "window": "always" })
        )));
        assert!(!counts_as_use(&request(
            serde_json::json!({ "op": "hold" })
        )));
        // A list is not use; one item's fields are, also without values.
        assert!(!counts_as_use(&request(
            serde_json::json!({ "op": "list", "filter": {} })
        )));
        assert!(counts_as_use(&request(
            serde_json::json!({ "op": "view", "query": "x", "reveal": false })
        )));
    }

    #[test]
    fn the_lock_line_gives_the_time_in_utc() {
        assert_eq!(super::rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(super::rfc3339(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(super::rfc3339(1_794_594_125), "2026-11-13T18:22:05Z");
        assert_eq!(super::rfc3339(253_402_300_799), "9999-12-31T23:59:59Z");
    }

    #[test]
    fn changing_or_revoking_an_agent_is_refused_once_the_account_is_deleted() {
        use super::{Request, person_write};
        use klav_client::grant_change::{ChangePolicy, EditorPolicy, GrantChange};
        let agent = klav_core::ids::AgentId::from_bytes([7; 16]);
        let apply = Request::GrantChangeApply {
            agent,
            change: GrantChange {
                projects: Vec::new(),
                vaults: Vec::new(),
                policy: ChangePolicy::Editor(EditorPolicy::default()),
                rotate_removed: false,
            },
            digest: String::new(),
            password: None,
        };
        assert!(person_write(&apply));
        assert!(person_write(&Request::RevokeAgent {
            agent,
            rotate: true,
            background: true,
        }));
        // Reading what changes, or what it saw, is not a write.
        assert!(!person_write(&Request::GrantEditor { agent }));
        assert!(!person_write(&Request::AgentExposure { agent }));
    }

    #[test]
    fn a_finished_narrowing_stays_a_narrowing() {
        use super::{RevocationBook, RevocationProgress};
        let agent: klav_core::ids::AgentId =
            serde_json::from_str("\"6f1c1b2e-0c1d-4a7b-9e55-1f2a3b4c5d6e\"").expect("id");
        let before: RevocationProgress = serde_json::from_value(serde_json::json!({
            "agent_id": agent, "name": "bot", "projects": 2, "rotated": 1,
            "narrowed": true, "needs_work": true, "to_change": 1,
        }))
        .expect("entry");
        let mut book = RevocationBook::default();
        assert!(
            !book.finish(agent, Some(before.clone()), 0, 0),
            "nothing skipped"
        );
        assert!(book.finish(agent, Some(before), 1, 0));
        let left = &book.finished[&agent];
        assert!(left.narrowed, "{left:?}");
        assert!(!left.needs_work && left.skipped == 1, "{left:?}");
    }

    /// A revocation without the key change that finishes skipping an item
    /// stays one in `status`, and an item skipped is never counted as a
    /// project (fifth re-check, 1 and 5).
    #[test]
    fn a_finished_key_change_says_what_it_was_and_counts_projects_only() {
        use super::{RevocationBook, RevocationProgress};
        let agent: klav_core::ids::AgentId =
            serde_json::from_str("\"6f1c1b2e-0c1d-4a7b-9e55-1f2a3b4c5d6e\"").expect("id");
        let items_only: RevocationProgress = serde_json::from_value(serde_json::json!({
            "agent_id": agent, "name": "bot", "projects": 0, "rotated": 0,
            "items": 1, "without_key_change": true, "needs_work": true,
        }))
        .expect("entry");
        let mut book = RevocationBook::default();
        assert!(book.finish(agent, Some(items_only), 1, 0));
        let left = &book.finished[&agent];
        assert!(left.without_key_change, "{left:?}");
        assert_eq!((left.projects, left.rotated), (0, 0), "{left:?}");

        // Three projects, one rotated before the last step and one in it,
        // one deleted, and an item out of reach: two rotated, not one.
        let rotating: RevocationProgress = serde_json::from_value(serde_json::json!({
            "agent_id": agent, "name": "bot", "projects": 3, "rotated": 1,
            "to_change": 1, "skipped": 1, "needs_work": true,
        }))
        .expect("entry");
        let mut book = RevocationBook::default();
        assert!(book.finish(agent, Some(rotating), 2, 1));
        let left = &book.finished[&agent];
        assert!(!left.without_key_change, "{left:?}");
        assert_eq!((left.projects, left.rotated), (3, 2), "{left:?}");
    }

    /// Revoking an agent again drops what an earlier key change left in
    /// `finished`: a finished narrowing must not call a revoked agent
    /// active (fifth re-check, 3).
    #[test]
    fn revoking_again_forgets_a_finished_narrowing() {
        use super::{RevocationBook, RevocationProgress};
        let agent: klav_core::ids::AgentId =
            serde_json::from_str("\"6f1c1b2e-0c1d-4a7b-9e55-1f2a3b4c5d6e\"").expect("id");
        let before: RevocationProgress = serde_json::from_value(serde_json::json!({
            "agent_id": agent, "name": "bot", "projects": 2, "rotated": 1,
            "narrowed": true, "needs_work": true, "to_change": 1,
        }))
        .expect("entry");
        let mut book = RevocationBook::default();
        assert!(book.finish(agent, Some(before), 1, 0));
        assert!(book.revoked(agent), "status changed");
        assert!(book.finished.is_empty());
        assert!(!book.revoked(agent), "nothing left to drop");
    }

    /// A step that changes no key, issues no grant and leaves `status` as
    /// it was is no progress; any one of those is (review of #308, N1).
    #[test]
    fn a_step_that_moves_nothing_is_no_progress() {
        use super::{RevocationProgress, moved};
        let agent: klav_core::ids::AgentId =
            serde_json::from_str("\"6f1c1b2e-0c1d-4a7b-9e55-1f2a3b4c5d6e\"").expect("id");
        let item: klav_core::ids::ItemId =
            serde_json::from_str("\"7a2d2c3f-1d2e-4b8c-8f66-2a3b4c5d6e7f\"").expect("item");
        let idle: klav_client::revoke::RotationStep = serde_json::from_value(serde_json::json!({
            "agent_id": agent, "skipped": ["item x: this device no longer sees it"],
            "done": false,
        }))
        .expect("step");
        let entry = |items: usize| -> RevocationProgress {
            serde_json::from_value(serde_json::json!({
                "agent_id": agent, "name": "bot", "projects": 0, "rotated": 0,
                "items": items, "without_key_change": true, "needs_work": false,
            }))
            .expect("entry")
        };
        let same = [entry(1)];
        assert!(!moved(&idle, &same, &same));
        assert!(moved(&idle, &same, &[entry(0)]), "status changed");
        assert!(moved(&idle, &same, &[]), "the entry is gone");
        let rekeyed = klav_client::revoke::RotationStep {
            rekeyed: vec![item],
            ..idle.clone()
        };
        assert!(moved(&rekeyed, &same, &same));
        let regranted = klav_client::revoke::RotationStep {
            regranted: vec!["ci".into()],
            ..idle
        };
        assert!(moved(&regranted, &same, &same));
    }

    /// The loop stops after two steps in a row that move nothing, and a
    /// step that moves starts the count again; the end or a failure stops
    /// it at once (review of #308, follow-up 2).
    #[test]
    fn two_idle_steps_in_a_row_stop_the_key_change() {
        use super::{StepEnd, after_step};
        let agent: klav_core::ids::AgentId =
            serde_json::from_str("\"6f1c1b2e-0c1d-4a7b-9e55-1f2a3b4c5d6e\"").expect("id");
        let step = |done: bool, failed: Option<&str>| -> klav_client::revoke::RotationStep {
            serde_json::from_value(serde_json::json!({
                "agent_id": agent, "done": done, "failed": failed,
            }))
            .expect("step")
        };
        let idle = step(false, None);
        let mut count = 0;
        assert_eq!(after_step(&idle, false, &mut count), StepEnd::Go);
        assert_eq!(after_step(&idle, true, &mut count), StepEnd::Go, "it moved");
        assert_eq!(after_step(&idle, false, &mut count), StepEnd::Go);
        assert_eq!(after_step(&idle, false, &mut count), StepEnd::Stalled);
        let mut count = 0;
        assert_eq!(
            after_step(&step(true, None), false, &mut count),
            StepEnd::Over
        );
        assert_eq!(
            after_step(&step(false, Some("offline")), false, &mut count),
            StepEnd::Over
        );
    }

    /// `status` says a revocation without the key change is one; an older
    /// `klavd`'s entry, without the field, reads as before.
    #[test]
    fn status_says_a_revocation_without_the_key_change() {
        use super::RevocationProgress;
        let agent: klav_core::ids::AgentId =
            serde_json::from_str("\"6f1c1b2e-0c1d-4a7b-9e55-1f2a3b4c5d6e\"").expect("id");
        let pending = klav_client::revoke::PendingRevocation {
            agent_id: agent,
            name: "bot".into(),
            projects: Vec::new(),
            rotated: Vec::new(),
            pending: Vec::new(),
            regrants: Vec::new(),
            unknown_projects: false,
            narrowed: false,
            items: 0,
            log_unchecked: false,
            without_key_change: true,
            skipped: vec!["item x: this device no longer sees it".into()],
            last_error: None,
        };
        let progress = RevocationProgress::of(&pending, false);
        assert!(
            progress.without_key_change && !progress.needs_work,
            "{progress:?}"
        );
        let wire = serde_json::to_value(&progress).expect("json");
        assert_eq!(wire["without_key_change"], true, "{wire}");
        let older: RevocationProgress = serde_json::from_value(serde_json::json!({
            "agent_id": agent, "projects": 1, "rotated": 1,
        }))
        .expect("older klavd");
        assert!(!older.without_key_change);
        let wire = serde_json::to_value(&older).expect("json");
        assert!(wire.get("without_key_change").is_none(), "{wire}");
    }

    #[test]
    fn a_record_from_a_newer_klav_is_told_apart_and_keeps_the_last_list() {
        use super::RevocationBook;
        use klav_client::ClientError;
        let mut book = RevocationBook::default();
        assert!(!book.note(&Ok(Vec::new())));
        assert!(book.note(&Err(ClientError::NewerFormat("revocations.bin".into()))));
        assert!(book.unreadable && book.newer);
        // The same read again changes nothing; another failure is told
        // apart from a newer format.
        assert!(!book.note(&Err(ClientError::NewerFormat("revocations.bin".into()))));
        assert!(book.note(&Err(ClientError::Corrupt("x".into()))));
        assert!(book.unreadable && !book.newer);
        assert!(book.note(&Ok(Vec::new())));
        assert!(!book.unreadable && !book.newer);
    }

    #[test]
    fn the_extension_never_sees_the_revocations_of_agents() {
        use super::{DaemonStatus, Source, for_source};
        let status: DaemonStatus = serde_json::from_value(serde_json::json!({
            "version": "0", "protocol": 1, "pid": 1, "logged_in": true,
            "unlocked": true, "idle_lock_secs": 900,
            "revocations": [{
                "agent_id": "00000000-0000-0000-0000-000000000000",
                "name": "bot", "projects": 2, "rotated": 1,
            }],
        }))
        .expect("status");
        assert!(
            for_source(status.clone(), Some(Source::Browser))
                .revocations
                .is_empty()
        );
        for source in [Some(Source::App), Some(Source::Terminal), None] {
            assert_eq!(for_source(status.clone(), source).revocations.len(), 1);
        }
    }

    #[test]
    fn a_proxy_use_that_leaves_an_issuer_on_the_old_proxy_fails() {
        use klav_client::issuers::IssuerResign;
        let done = IssuerResign {
            done: vec!["t3-code".into()],
            failed: Vec::new(),
        };
        let warnings = resign_result(&done).expect("finished");
        assert!(warnings[0].contains("t3-code"));
        let half = IssuerResign {
            done: vec!["t3-code".into()],
            failed: vec!["ci: the server did not answer".into()],
        };
        let err = resign_result(&half).expect_err("not finished");
        let text = err.to_string();
        assert!(text.contains("not finished"), "{text}");
        assert!(
            text.contains("t3-code") && text.contains("ci: the server"),
            "{text}"
        );
        assert!(text.contains("klav proxy use"), "{text}");
    }
    #[test]
    fn the_grant_prompt_lists_every_method_path_and_host_it_signs() {
        use klav_client::proxy_admin::{ProxyChangeView, ProxyCredentialView, ProxyRuleView};
        use klav_core::policy::Effect;
        let rule = |effect, methods: &[&str], paths: &[&str]| ProxyRuleView {
            effect,
            methods: methods.iter().map(|m| (*m).to_owned()).collect(),
            hosts: vec!["api.example.com".into()],
            path_prefixes: paths.iter().map(|p| (*p).to_owned()).collect(),
            mcp_tools: Vec::new(),
        };
        let mut view = ProxyChangeView {
            agent_id: AgentId::from_bytes([1; 16]),
            agent: "klav-proxy".into(),
            first: false,
            pairing_code: String::new(),
            base_version: 1,
            item_id: ItemId::from_bytes([2; 16]),
            title: "API".into(),
            place: "Personal/Infra".into(),
            site: None,
            holders: Vec::new(),
            credential: Some(ProxyCredentialView {
                item_id: ItemId::from_bytes([2; 16]),
                title: "API".into(),
                profile: None,
                rules: vec![
                    rule(Effect::Allow, &["GET", "POST", "DELETE"], &["/v1", "/v2"]),
                    rule(Effect::Ask, &["DELETE", "PATCH"], &["/v1", "/v2"]),
                    rule(Effect::Deny, &["PUT"], &["/admin"]),
                ],
            }),
            replaces: false,
            dropped: Vec::new(),
            warnings: Vec::new(),
            first_on_account: false,
            reissue_only: false,
            issuers_losing: Vec::new(),
            issuers_keeping: Vec::new(),
            local_clients_losing: Vec::new(),
            turns_mcp_gateway_on: false,
            mcp_first: false,
        };
        let shown = GrantShown::of(&view);
        assert_eq!(
            shown,
            GrantShown {
                host: "api.example.com".into(),
                // A method that asks is shown once, as asking: it does.
                allowed: vec!["GET".into(), "POST".into()],
                asked: vec!["DELETE".into(), "PATCH".into()],
                paths: vec!["/v1".into(), "/v2".into()],
                ..GrantShown::default()
            }
        );
        // The usual port, header and field are not shown; others are.
        let profile =
            |upstream: &str, header: &str, field: Option<&str>| klav_proto::agent::ProxyProfile {
                name: "api".into(),
                item_id: ItemId::from_bytes([2; 16]),
                field: field.map(str::to_owned),
                header: header.into(),
                prefix: "Bearer ".into(),
                upstream: upstream.into(),
                rate_per_minute: None,
                mcp: None,
            };
        let credential = view.credential.as_mut().expect("credential");
        credential.profile = Some(profile("https://api.example.com", "authorization", None));
        let usual = GrantShown::of(&view);
        assert_eq!((usual.port, usual.header, usual.field), (None, None, None));
        let credential = view.credential.as_mut().expect("credential");
        credential.profile = Some(profile(
            "https://api.example.com:8443",
            "x-api-key",
            Some("token"),
        ));
        let other = GrantShown::of(&view);
        assert_eq!(
            (other.port, other.header, other.field),
            (Some(8443), Some("x-api-key".into()), Some("token".into()))
        );
    }

    use super::*;

    fn back(by: Duration) -> Result<Duration, std::time::SystemTimeError> {
        let now = SystemTime::now();
        now.duration_since(now + by)
    }

    const TICK_GAP: Duration = Duration::from_secs(2);
    const LONG: Duration = Duration::from_secs(600);

    #[test]
    fn with_a_sleep_clock_only_a_real_sleep_locks() {
        let tick = TICK_GAP;
        // A normal tick.
        assert_eq!(slept(Ok(tick), tick, Some(tick)), None);
        // NTP, a hypervisor or the person steps the wall clock, forward or
        // back, while the machine stays awake: no lock.
        assert_eq!(slept(Ok(LONG), tick, Some(tick)), None);
        assert_eq!(slept(back(Duration::from_secs(60)), tick, Some(tick)), None);
        assert_eq!(slept(back(Duration::from_secs(2)), tick, Some(tick)), None);
        // A real sleep: the clock that runs during sleep moved on, and the
        // wall clock with it.
        let asleep = LONG + tick;
        let reason = Some(LockReason::Slept {
            asleep,
            awake: tick,
        });
        assert_eq!(slept(Ok(asleep), tick, Some(asleep)), reason);
        // A sleep with the wall clock set back meanwhile still locks.
        assert_eq!(
            slept(back(Duration::from_secs(60)), tick, Some(asleep)),
            reason
        );
        assert_eq!(slept(Ok(tick), tick, Some(asleep)), reason);
        // The edge: exactly the gap does not lock, a millisecond more does.
        let edge = tick + SLEEP_GAP;
        assert_eq!(slept(Ok(tick), tick, Some(edge)), None);
        let over = edge + Duration::from_millis(1);
        assert_eq!(
            slept(Ok(tick), tick, Some(over)),
            Some(LockReason::Slept {
                asleep: over,
                awake: tick
            })
        );
    }

    #[test]
    fn without_a_sleep_clock_the_wall_clock_decides() {
        let tick = TICK_GAP;
        assert_eq!(slept(Ok(tick), tick, None), None);
        // A real sleep shows only as the wall clock jumping forward.
        assert_eq!(
            slept(Ok(LONG), tick, None),
            Some(LockReason::WallForward {
                wall: LONG,
                awake: tick
            })
        );
        let edge = tick + SLEEP_GAP;
        assert_eq!(slept(Ok(edge), tick, None), None);
        // A step back could hide a sleep, so more than a second locks.
        let by = Duration::from_secs(60);
        assert_eq!(slept(back(by), tick, None), Some(LockReason::WallBack(by)));
        // A small correction backwards does not.
        assert_eq!(slept(back(Duration::from_millis(200)), tick, None), None);
    }

    #[test]
    fn the_sleep_clock_runs_and_the_reasons_say_what_happened() {
        let start = sleep_clock().expect("a clock that runs during sleep");
        let then = sleep_clock().expect("a clock that runs during sleep");
        assert!(then >= start);
        let text = LockReason::WallBack(Duration::from_secs(3)).to_string();
        assert_eq!(
            text,
            "the wall clock went back 3s (no clock that runs during sleep)"
        );
        assert_eq!(
            LockReason::Idle(Duration::from_secs(900)).to_string(),
            "idle for 900s"
        );
    }

    #[test]
    fn a_pause_decided_here_is_dropped_only_on_a_refusal_for_good() {
        let api = |status| ClientError::Api {
            status,
            code: None,
            message: "x".into(),
            current_version: None,
        };
        // Kept, and sent again later.
        for e in [
            api(500),
            api(502),
            api(503),
            api(401),
            api(408),
            api(429),
            ClientError::Network("offline".into()),
            ClientError::SessionExpired,
            ClientError::LaterPause(1),
        ] {
            assert!(kept(&e), "{e:?}");
        }
        // The same pause would be refused again.
        for status in [400, 403, 404, 405, 409, 422] {
            assert!(!kept(&api(status)), "{status}");
        }
    }

    #[test]
    fn a_local_pause_is_stored_with_no_more_than_it_needs() {
        let pause = LocalPause {
            account: klav_core::ids::AccountId::generate(),
            agent: None,
            at: 1,
            until: 0,
            locked: true,
            source: Some(Source::App),
            unsupported: false,
        };
        let json = serde_json::to_value(LocalPausesFile {
            v: LOCAL_PAUSES_VERSION,
            pauses: vec![pause],
        })
        .expect("json");
        assert_eq!(json["pauses"][0]["source"], "app", "{json}");
        // Written only when set, so the file of a pause the server took
        // stays readable by an earlier `klavd`.
        assert!(json["pauses"][0].get("unsupported").is_none(), "{json}");
        let back: LocalPausesFile = serde_json::from_value(json).expect("back");
        assert_eq!(back.pauses, [pause]);
        // Without `locked`, `source` or `unsupported`: not locked, no
        // source, and sent to the server.
        let old: LocalPause = serde_json::from_value(serde_json::json!({
            "account": pause.account, "at": 1, "until": 0,
        }))
        .expect("old");
        assert!(!old.locked && old.source.is_none() && !old.unsupported);
        let held = LocalPause {
            unsupported: true,
            ..pause
        };
        let json = serde_json::to_value(held).expect("json");
        assert_eq!(json["unsupported"], true, "{json}");
        assert_eq!(decided_from(None), "from a program Klav does not recognize");
        assert_eq!(decided_from(Some(Source::Terminal)), "from the terminal");
    }

    #[test]
    fn only_an_older_server_answering_every_agents_pause_holds_it_here() {
        let api = |status| ClientError::Api {
            status,
            code: None,
            message: "this server does not support pausing agents: update it".into(),
            current_version: None,
        };
        assert!(unsupported(&api(405), None));
        // One agent's 404 could be an agent the server does not know.
        assert!(!unsupported(&api(404), Some(AgentId::generate())));
        assert!(!unsupported(&api(405), Some(AgentId::generate())));
        assert!(!unsupported(&api(404), None));
        assert!(!unsupported(&ClientError::Network("x".into()), None));
    }

    #[test]
    fn a_resume_an_older_server_cannot_take_is_a_warning_like_offline() {
        let api = |status| ClientError::Api {
            status,
            code: None,
            message: "this server does not support pausing agents: update it".into(),
            current_version: None,
        };
        let one = Some(AgentId::generate());
        let offline = ClientError::Network("connection refused".into());
        // Offline, with no signed pause of the scope on the server.
        let said = resume_not_sent(&offline, None, false).expect("offline");
        assert!(said.contains("resumed on this computer"), "{said}");
        assert!(resume_not_sent(&offline, one, false).is_some());
        // Offline while the server holds a signed pause: still paused
        // there, so it is an error.
        assert!(resume_not_sent(&offline, None, true).is_none());
        // A server older than the pauses: every agent's 405 (it has no
        // pause to lift), even if this device held one.
        for held in [false, true] {
            let said = resume_not_sent(&api(405), None, held).expect("older server");
            assert!(said.contains("does not support pausing"), "{said}");
        }
        // One agent's 404 may be an agent it does not know; any other
        // refusal is an error too.
        assert!(resume_not_sent(&api(404), one, false).is_none());
        assert!(resume_not_sent(&api(405), one, false).is_none());
        assert!(resume_not_sent(&api(409), None, false).is_none());
    }

    /// An `account.json` for `account` in `home`: only the account ID
    /// matters to [`load_signed_pauses`].
    fn write_account(home: &Home, account: klav_core::ids::AccountId) {
        let file = klav_client::AccountFile {
            v: 1,
            server: "http://127.0.0.1:1".into(),
            email: "ana@example.com".into(),
            account_id: account,
            device_id: klav_core::ids::DeviceId::generate(),
            device_name: "laptop".into(),
            kdf_params: klav_proto::Blob::new(Vec::new()),
            public_identity: klav_proto::Blob::new(Vec::new()),
            sealed_identity: klav_proto::Blob::new(Vec::new()),
            local_identity: klav_proto::Blob::new(Vec::new()),
        };
        std::fs::write(
            home.account_path(),
            serde_json::to_vec(&file).expect("json"),
        )
        .expect("write account");
    }

    #[test]
    fn the_signed_pauses_are_kept_for_this_homes_account_only() {
        let dir = tempfile::tempdir().expect("tempdir");
        let home = Home::at(dir.path());
        let account = klav_core::ids::AccountId::generate();
        let pause = |until| klav_proto::agent::AgentPause {
            agent_id: None,
            at: 1,
            until,
            signature: klav_proto::Blob::new(vec![0; 64]),
        };
        let write = |file: &SignedPausesFile| {
            std::fs::write(
                home.file(SIGNED_PAUSES),
                serde_json::to_vec(file).expect("json"),
            )
            .expect("write");
        };
        write(&SignedPausesFile {
            v: SIGNED_PAUSES_VERSION,
            account,
            pauses: vec![pause(0)],
        });
        // No account here: nothing is read, whatever the file says.
        assert!(load_signed_pauses(&home).is_empty());
        write_account(&home, account);
        // The same account, the pause in effect: loaded.
        let loaded = load_signed_pauses(&home);
        assert_eq!(loaded.len(), 1, "{loaded:?}");
        assert_eq!(loaded[0].until, 0);
        // A pause with an end still ahead holds; one that ended is dropped.
        let ahead = now_ms() + 60_000;
        write(&SignedPausesFile {
            v: SIGNED_PAUSES_VERSION,
            account,
            pauses: vec![pause(ahead), pause(now_ms() - 1)],
        });
        let loaded = load_signed_pauses(&home);
        assert_eq!(loaded.len(), 1, "{loaded:?}");
        assert_eq!(loaded[0].until, ahead);
        // Saved for another account: dropped, though in effect.
        write(&SignedPausesFile {
            v: SIGNED_PAUSES_VERSION,
            account: klav_core::ids::AccountId::generate(),
            pauses: vec![pause(0)],
        });
        assert!(load_signed_pauses(&home).is_empty());
        // A file that is not one, or of another version: none, logged.
        std::fs::write(home.file(SIGNED_PAUSES), b"{").expect("write");
        assert!(load_signed_pauses(&home).is_empty());
        write(&SignedPausesFile {
            v: SIGNED_PAUSES_VERSION + 1,
            account,
            pauses: vec![pause(0)],
        });
        assert!(load_signed_pauses(&home).is_empty());
        // What it holds: no more than the account, agents, times and the
        // account's signatures.
        let json = serde_json::to_value(SignedPausesFile {
            v: SIGNED_PAUSES_VERSION,
            account,
            pauses: vec![pause(5)],
        })
        .expect("json");
        let mut keys: Vec<&str> = json
            .as_object()
            .expect("object")
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(keys, ["account", "pauses", "v"]);
        let mut keys: Vec<&str> = json["pauses"][0]
            .as_object()
            .expect("object")
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(keys, ["at", "signature", "until"]);
    }
}

/// What a proxy grant signs for its credential, for the presence prompt:
/// the host, the methods it allows and those it asks for, and its path
/// prefixes.
#[derive(Debug, Default, PartialEq)]
struct GrantShown {
    host: String,
    port: Option<u16>,
    header: Option<String>,
    field: Option<String>,
    allowed: Vec<String>,
    asked: Vec<String>,
    paths: Vec<String>,
    /// An MCP profile's endpoint and tool rules (ADR 0049 §5.3).
    mcp: Option<crate::prompt::McpShown>,
}

impl GrantShown {
    fn of(view: &klav_client::proxy_admin::ProxyChangeView) -> Self {
        use klav_core::policy::Effect;
        let mut shown = Self::default();
        let Some(credential) = &view.credential else {
            return shown;
        };
        let mut hosts = Vec::new();
        let mut mcp = crate::prompt::McpShown {
            first: view.mcp_first,
            ..Default::default()
        };
        for rule in &credential.rules {
            // A tool rule says which tools, not which methods: an `ask` on
            // tools does not make every `POST` ask (ADR 0049 §5.3).
            if !rule.mcp_tools.is_empty() {
                let into = match rule.effect {
                    Effect::Allow => &mut mcp.allow,
                    Effect::Ask => &mut mcp.ask,
                    Effect::Deny => &mut mcp.deny,
                };
                into.extend(rule.mcp_tools.iter().cloned());
                continue;
            }
            let into = match rule.effect {
                Effect::Allow => &mut shown.allowed,
                Effect::Ask => &mut shown.asked,
                Effect::Deny => continue,
            };
            into.extend(rule.methods.iter().cloned());
            shown.paths.extend(rule.path_prefixes.iter().cloned());
            hosts.extend(rule.hosts.iter().cloned());
        }
        for list in [
            &mut shown.allowed,
            &mut shown.asked,
            &mut shown.paths,
            &mut hosts,
        ] {
            list.sort();
            list.dedup();
        }
        shown.allowed.retain(|m| !shown.asked.contains(m));
        shown.host = hosts.join(", ");
        // Where the value goes, when not the usual: the port, the header
        // and the field it comes from.
        if let Some(profile) = &credential.profile {
            shown.port = profile
                .upstream_host()
                .map(|(_, port)| port)
                .filter(|port| *port != 443);
            shown.header = Some(profile.header.clone()).filter(|h| h != "authorization");
            shown.field = profile.field.clone();
            if let Some(m) = &profile.mcp {
                mcp.endpoint = m.endpoint.clone();
                for list in [&mut mcp.allow, &mut mcp.ask, &mut mcp.deny] {
                    list.dedup();
                }
                shown.mcp = Some(mcp);
            }
        }
        shown
    }
}

/// The presence dialog of a proxy grant: what `view` shows, with the
/// issuers that keep the profile counted in the request that is signed
/// ([`klav_client::proxy_admin::PreparedProxyChange::issuers_keeping`]).
fn grant_prompt<'a>(
    view: &'a klav_client::proxy_admin::ProxyChangeView,
    shown: &'a GrantShown,
    keeping: usize,
) -> Prompt<'a> {
    Prompt::ProxyGrant {
        agent: &view.agent,
        item: ItemShown {
            title: &view.title,
            place: &view.place,
            site: view.site.as_deref(),
        },
        host: &shown.host,
        port: shown.port,
        header: shown.header.as_deref(),
        field: shown.field.as_deref(),
        allowed: &shown.allowed,
        asked: &shown.asked,
        paths: &shown.paths,
        words: view.first.then_some(view.pairing_code.as_str()),
        first_on_account: view.first_on_account,
        issuers_losing: view.issuers_losing.len(),
        issuers_keeping: keeping,
        mcp: shown.mcp.as_ref(),
    }
}

/// The warnings of a `proxy use` whose issuers were all re-signed, or the
/// error of one that left some naming the old proxy: the setting is
/// written either way, and the same `use` again finishes the rest.
fn resign_result(
    resigned: &klav_client::issuers::IssuerResign,
) -> klav_client::ClientResult<Vec<String>> {
    let warnings = resign_warnings(resigned);
    if resigned.failed.is_empty() {
        Ok(warnings)
    } else {
        Err(ClientError::Invalid(format!(
            "the proxy setting changed, but the change is not finished: {}",
            warnings.join(". ")
        )))
    }
}

/// What a `use` left undone in the issuers' grants, for its warnings.
fn resign_warnings(resigned: &klav_client::issuers::IssuerResign) -> Vec<String> {
    let mut out = Vec::new();
    if !resigned.done.is_empty() {
        out.push(format!(
            "these issuers now name no proxy; make them issuers of the new one with `klav proxy issuer add`: {}",
            resigned
                .done
                .iter()
                .map(|n| format!("{n:?}"))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if !resigned.failed.is_empty() {
        out.push(format!(
            "the grants of these issuers still name the old proxy; run the same `klav proxy use` again to finish: {}",
            resigned
                .failed
                .iter()
                .map(|n| format!("{n:?}"))
                .collect::<Vec<_>>()
                .join("; ")
        ));
    }
    out
}

#[cfg(test)]
mod gate_tests;

#[cfg(test)]
mod socket_tests;
