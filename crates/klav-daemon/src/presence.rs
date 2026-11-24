//! The presence gate (ADR 0041 §2–§4, layer 2), shipped turned off.
//!
//! Before `klavd` hands out a value, the person proves they are there:
//! Touch ID, or the master password where `klavd` can't show Touch ID.
//! A verification opens a window keyed to who the peer is (§2.1): its
//! terminal session, its parent process (macOS, a peer with no terminal),
//! or its connection. The window lasts what the prompt said: 5 minutes, or
//! until Klav locks (§2.4). With the setting on Always there is no window
//! and every value asks.
//!
//! [`Presence`] holds all of it in memory: the settings read at unlock
//! from `klavd`'s sealed local data, the windows and passkey windows per
//! key (§2.5), the held connections and their declarations (§1.2), the
//! open prompt (the busy rule, §2.4) and the key that unlocked `klavd`.
//! Locking drops everything but the declarations, which go when their
//! connection closes or the setting moves to Always.
//!
//! The gate is off unless `klavd` starts with `--presence-gate` (§7): then
//! every operation behaves exactly as before this layer.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Instant;

use klav_client::ops::SecretText;
use klav_client::{Home, PasswordCheck};
use klav_core::crypto::keys::LocalKey;
use klav_core::crypto::local::{LocalContext, open_local_data, seal_local_data};
use serde::{Deserialize, Serialize};

use crate::browser::Line;
use crate::peer::{self, Identity, WindowKey};
use crate::prompt::{Lang, Lasts, Prompt, Source, ValueAsk, Who};
use crate::protocol::{
    AskLasts, AskValue, AskValueKind, ErrorBody, ErrorCode, Notice, PROTOCOL_VERSION, PresenceAsk,
    PresenceKey, Request, ResponseEnvelope, StatusPresence,
};
use crate::touchid::Biometric;
use crate::uv::{self, FIVE_MINUTES, Window};

/// The presence setting, sealed in `klavd`'s local data (spec §12.2, kind
/// `0x41`, purpose `presence`).
const PRESENCE_FILE: &str = "presence.bin";
const PRESENCE_PURPOSE: &str = "presence";
/// The passkey setting, sealed the same way under its own purpose (the
/// ADR names none: the ADR's own choice, Still open).
const PASSKEY_FILE: &str = "passkey-window.bin";
const PASSKEY_PURPOSE: &str = "passkey-window";
/// The passkey setting's old plain file, never read again (§2.4).
pub(crate) const OLD_PASSKEY_FILE: &str = "passkeys.json";
/// The one-time warning when it was there (§2.4, Omar's decision on Q-N3).
pub(crate) const OLD_PASSKEY_WARNING: &str = "Klav no longer reads your old passkey setting: passkeys now ask every time. Choose again in the extension's settings";

/// Which row of ADR 0041 §3's table a request sits in, taken with its
/// argument where the table splits on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Gate {
    /// It returns a value: the window (decisions 1–4).
    Window,
    /// Its events carry agents' values: one presence per extension
    /// connection, every fill on Always (§3.1, layer 4).
    ExtensionConnection,
    /// Passkey uses, with the passkey window per key (§2.5).
    PasskeyWindow,
    /// It already asks for presence itself, unchanged. `grant_change_apply`
    /// asks only when it widens: narrowing is the no-value row.
    AlreadyAsks,
    /// A setting: asks when it loosens, and opens no window then; reading
    /// and tightening are the no-value row (§2.4).
    Setting,
    /// `hold` (§1.2): no verification and no value of its own.
    Declares,
    /// An agent's own proof: its signed request and task, or values the
    /// agent brought.
    AgentProof,
    /// The browser's channel: the active tab, an extension's report.
    BrowserChannel,
    /// Metadata, or a write the caller brings.
    NoValue,
}

/// The row of `request` in §3's table. One `match` with no `_`: a new
/// operation does not compile until someone places it here (P6).
pub(crate) fn gate(request: &Request) -> Gate {
    match request {
        Request::View { reveal: true, .. }
        | Request::PreviousPassword { .. }
        | Request::Totp { .. }
        | Request::GeneratedValue { .. }
        | Request::Resolve { .. }
        | Request::Autofill { .. } => Gate::Window,
        Request::ExtensionAttach { .. } => Gate::ExtensionConnection,
        Request::PasskeyGet { .. } | Request::PasskeyCreate { .. } => Gate::PasskeyWindow,
        Request::ApproveAgent { .. }
        | Request::DecideApproval { approve: true, .. }
        | Request::DecideTask { approve: true, .. }
        | Request::AddToTask { .. }
        | Request::OfferTask { .. }
        | Request::FulfillSecretRequest {
            input: klav_client::secret_requests::FulfillSecretRequest {
                grant_proxy: true,
                ..
            },
            ..
        }
        | Request::GrantChangeApply { .. }
        | Request::ProxyUse { .. }
        | Request::ProxyGrant { .. }
        | Request::ProxyRevoke { .. }
        | Request::ProxyIssuerAdd { .. }
        | Request::ProxyIssuerRemove { .. }
        | Request::ResumeAgents { .. }
        | Request::CancelAccountDeletion { .. }
        | Request::ConfirmPresence { .. } => Gate::AlreadyAsks,
        Request::PasskeyUv {
            window: Some(_), ..
        }
        | Request::PresenceWindow {
            window: Some(_), ..
        } => Gate::Setting,
        Request::Hold => Gate::Declares,
        Request::AgentPasskeyArm { .. }
        | Request::AgentPasskeyUse { .. }
        | Request::AgentRotateBegin { .. }
        | Request::AgentRotateConfirm { .. }
        | Request::AgentRotateCancel { .. }
        | Request::AgentRotatePending { .. }
        | Request::BrowserFill { .. } => Gate::AgentProof,
        Request::BrowserTab | Request::ExtensionReply { .. } => Gate::BrowserChannel,
        Request::Status
        | Request::Unlock { .. }
        | Request::Lock
        | Request::Sync
        | Request::ResetCache
        | Request::Vaults
        | Request::Projects { .. }
        | Request::CreateVault { .. }
        | Request::CreateProject { .. }
        | Request::List { .. }
        | Request::View { reveal: false, .. }
        | Request::Create { .. }
        | Request::Edit { .. }
        | Request::Trash { .. }
        | Request::Suggest { .. }
        | Request::PasskeyCandidates { .. }
        | Request::Attach { .. }
        | Request::Agents
        | Request::DenyAgent { .. }
        | Request::Approvals { .. }
        | Request::DecideApproval { approve: false, .. }
        | Request::DecideTask { approve: false, .. }
        | Request::Tasks { .. }
        | Request::EndTask { .. }
        | Request::TaskLog { .. }
        | Request::SecretRequests { .. }
        | Request::FulfillSecretRequest {
            input: klav_client::secret_requests::FulfillSecretRequest {
                grant_proxy: false,
                ..
            },
            ..
        }
        | Request::DenySecretRequest { .. }
        | Request::AgentExposure { .. }
        | Request::RevokeAgent { .. }
        | Request::AgentRevocations
        | Request::GrantEditor { .. }
        | Request::GrantChangePrepare { .. }
        | Request::PasskeyUv { window: None, .. }
        | Request::PresenceWindow { window: None, .. }
        | Request::ProxyStatus
        | Request::ProxyGrantPreview { .. }
        | Request::ProxyIssuerPreview { .. }
        | Request::PauseAgents { .. }
        | Request::AuditLog { .. }
        | Request::VerifyAudit
        | Request::SandboxList
        | Request::SandboxListFlagged
        // Not in §3's table, which predates it: the same list as
        // `sandbox_list_flagged` (this layer adds it to the table).
        | Request::SandboxListChecked
        | Request::SandboxRevoke { .. }
        | Request::ItemActivity { .. }
        | Request::AuditStatus
        | Request::AuditReset
        | Request::GeneratorRecord { .. }
        | Request::GeneratorHistory
        | Request::GeneratorDelete { .. }
        | Request::PasswordHistory { .. }
        | Request::VaultHealth
        | Request::ImportAdd { .. }
        | Request::ImportPreview { .. }
        | Request::ImportApply { .. }
        | Request::ImportCancel { .. }
        | Request::ResolvePending { .. }
        | Request::ReusedOffer { .. }
        | Request::TaskProgress { .. }
        | Request::HealthSettings { .. }
        | Request::Shutdown => Gate::NoValue,
    }
}

/// Takes the master password out of a request the window gates (§3.2):
/// `klavd` checks it, and the operation never sees it.
pub(crate) fn take_password(request: &mut Request) -> Option<SecretText> {
    match request {
        Request::View { password, .. }
        | Request::PreviousPassword { password, .. }
        | Request::Totp { password, .. }
        | Request::GeneratedValue { password, .. }
        | Request::Resolve { password, .. }
        | Request::Autofill { password, .. } => password.take(),
        _ => None,
    }
}

/// What a window is keyed on, for one connection (§2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Key {
    /// A peer in a terminal: its session.
    Session(peer::Session),
    /// A peer with no terminal (macOS): its parent.
    Parent(peer::Process),
    /// An unknown peer, an orphan, and on Linux every peer with no
    /// terminal: this connection only.
    Connection(u64),
    /// No window at all (Linux without `SO_PEERPIDFD`). The connection
    /// only tells two such callers apart for the `unlock` rule.
    NoWindow(u64),
}

/// Who sent a request, as the gate sees it.
#[derive(Debug, Clone)]
pub(crate) struct Caller {
    /// The connection.
    pub(crate) conn: u64,
    /// Its window key.
    pub(crate) key: Key,
    /// Its controlling terminal's name, when it has one with a name.
    pub(crate) terminal: Option<String>,
    /// The program, from its executable: a hint for the prompt.
    pub(crate) source: Option<Source>,
    /// Where to write a notice before a Touch ID dialog for this request's
    /// value, when its envelope asked for one (`notify`, ADR 0041 §2.4).
    pub(crate) notify: Option<Notifier>,
    /// The envelope's `untyped`: the client didn't read this `unlock`'s
    /// master password on its terminal (stdin, a pipe). Such an unlock opens
    /// no window and isn't the passkey verification of ADR 0020 §8 (Omar's
    /// decisions 4 and B of 2026-11-19).
    pub(crate) untyped: bool,
}

/// Writes [`Notice`] lines on one connection, for one request.
#[derive(Debug, Clone)]
pub(crate) struct Notifier {
    pub(crate) lines: tokio::sync::mpsc::Sender<Line>,
    pub(crate) id: u64,
}

impl Notifier {
    /// Queues `notice` ahead of the request's answer. Never waits: the
    /// connection's writer has room, since a client sends one request at a
    /// time and reads its answer before the next.
    fn send(&self, notice: Notice) {
        let line = ResponseEnvelope {
            v: PROTOCOL_VERSION,
            id: self.id,
            ok: None,
            error: None,
            warnings: Vec::new(),
            notice: Some(notice),
        };
        if let Ok(mut bytes) = serde_json::to_vec(&line) {
            bytes.push(b'\n');
            let _ = self.lines.try_send(zeroize::Zeroizing::new(bytes));
        }
    }
}

impl Caller {
    /// The caller on connection `conn`, from what the kernel says about
    /// the peer.
    pub(crate) fn of(conn: u64, identity: &Identity, source: Option<Source>) -> Caller {
        let key = match identity.window_key() {
            WindowKey::Session(session) => Key::Session(session),
            WindowKey::Parent(parent) => Key::Parent(parent),
            WindowKey::Connection => Key::Connection(conn),
            WindowKey::NoWindow => Key::NoWindow(conn),
        };
        let device = match identity {
            Identity::Known(peer) => peer.terminal,
            Identity::Unknown | Identity::NoPeerPidfd => None,
        };
        Caller {
            conn,
            key,
            terminal: device.and_then(peer::terminal_name),
            source,
            notify: None,
            untyped: false,
        }
    }

    /// A caller whose key is given instead of read from the kernel (only
    /// the server's tests give one): a connection key becomes `conn`'s own,
    /// and a session key's terminal is named after the session.
    pub(crate) fn fixed(conn: u64, key: Key, source: Option<Source>) -> Caller {
        let key = match key {
            Key::Connection(_) => Key::Connection(conn),
            Key::NoWindow(_) => Key::NoWindow(conn),
            key => key,
        };
        let terminal = match key {
            Key::Session(session) => Some(format!("ttys{:03}", session.id)),
            _ => None,
        };
        Caller {
            conn,
            key,
            terminal,
            source,
            notify: None,
            untyped: false,
        }
    }

    /// Who the prompt names (§2.4, §3.2). A hint, never proof (§1.3).
    fn who(&self) -> Who<'_> {
        match self.key {
            Key::Session(_) => self
                .terminal
                .as_deref()
                .map_or(Who::ATerminal, Who::Terminal),
            Key::Parent(_) if self.source == Some(Source::Browser) => Who::Browser,
            Key::Parent(_) => Who::NoTerminal,
            Key::Connection(_) | Key::NoWindow(_) if self.source == Some(Source::Browser) => {
                Who::BrowserConnection
            }
            Key::Connection(_) | Key::NoWindow(_) => Who::Connection,
        }
    }

    fn kind(&self) -> PresenceKey {
        match self.key {
            Key::Session(_) => PresenceKey::Session,
            Key::Parent(_) => PresenceKey::Parent,
            Key::Connection(_) => PresenceKey::Connection,
            Key::NoWindow(_) => PresenceKey::None,
        }
    }
}

/// The two settings, read at unlock (§2.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Settings {
    /// The presence window: missing means 5 minutes.
    pub(crate) presence: Window,
    /// The passkey window: missing means Always.
    pub(crate) passkey: Window,
}

/// What the gate asks for (§4).
#[derive(Debug, Clone, Copy)]
pub(crate) enum Purpose<'a> {
    /// A value under the window. `value` names it, for the prompt with no
    /// window (Always, or no key).
    Window { value: &'a AskValue },
    /// A value that asks every time (ADR 0032's protected set), from any
    /// peer, a held connection included. `reason` is the prompt.
    #[cfg_attr(not(test), allow(dead_code))]
    EveryTime { reason: &'a str },
}

/// What a master password sent again after `presence_required` must be
/// for (finding 2 of layer 3's review): the same request, and, for a
/// request that names an item, the same item. `klavd` checks the password
/// only if it would ask exactly what it asked, for this. Its size is fixed,
/// whatever the request's (the second review of layer 3, finding 5).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Bound {
    /// The request as sent, without its password: its SHA-256
    /// ([`request_digest`]), never the request itself.
    pub(crate) request: [u8; 32],
    /// The item the request names, as `klavd` resolved it under the
    /// session's lock: always set for `view`, `previous_password`, `totp`
    /// and `autofill`, never for `generated_value` and `resolve`.
    pub(crate) item: Option<klav_core::ids::ItemId>,
}

/// The digest [`Bound::request`] keeps of `request` (taken out of its
/// password already), through `klav-core`'s SHA-256. A request that can't be
/// serialized is refused: two such requests must never compare equal.
pub(crate) fn request_digest(request: &Request) -> Result<[u8; 32], ErrorBody> {
    let bytes = zeroize::Zeroizing::new(serde_json::to_vec(request).map_err(|_| ErrorBody {
        code: ErrorCode::Internal,
        message: "klavd could not read back this request".into(),
        paused: None,
        presence: None,
    })?);
    Ok(klav_core::crypto::agent::body_digest(&bytes))
}

/// An ask `klavd` sent on a connection and waits for a password for.
#[derive(Debug, Clone)]
struct Pending {
    generation: u64,
    ask: PresenceAsk,
    bound: Bound,
    /// The version of `bound.item` that was asked about (Omar's decision F
    /// of 2026-11-19): not part of what a resend must match, but what the
    /// hand-out must still find (`Passed::version`).
    version: Option<u64>,
}

impl Pending {
    /// Whether a password sent with `now` answers this ask: the same
    /// session, the same words, the same request and item. The item's
    /// version is not compared here: an edit since the ask is a `conflict`
    /// at the hand-out, not another ask.
    fn answered_by(&self, now: &Pending) -> bool {
        self.generation == now.generation && self.ask == now.ask && self.bound == now.bound
    }
}

/// What [`Presence::require`] passed a value for.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub(crate) struct Passed {
    /// The version of the item the ask was about, which the hand-out must
    /// still find under the session's lock, in the same hold that hands it
    /// out (Omar's decision F of 2026-11-19): for a password sent again,
    /// the version when `klavd` asked, not now. `None` for a request bound
    /// to no item.
    pub(crate) version: Option<u64>,
    /// The window the answer opens, not open yet: [`Presence::open_window`] opens
    /// it once the hand-out finds what was asked about. A `conflict`, or any
    /// refusal before that check, drops it, and the next value asks again
    /// (Omar's decision G of 2026-11-19).
    pub(crate) opens: Option<Opening>,
}

/// A window an answer was going to open (Omar's decision G of 2026-11-19):
/// what the prompt stated, for the session it was stated in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub(crate) struct Opening {
    generation: u64,
    lasts: Lasts,
    declared: bool,
    setting: Window,
}

/// What [`Presence::first`] found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Untitled {
    /// The value may go: a window covers it.
    Passed,
    /// Nothing covers it: read the value's text and the item it is, and
    /// call [`Presence::require`], with the password, if one came. `touch`:
    /// a Touch ID prompt would show, so the value must be read without
    /// waiting behind one (ADR 0041 §2.4; the third layer-2 review,
    /// finding A).
    NeedsText { touch: bool },
}

/// Why a Touch ID check didn't pass.
#[derive(Debug)]
pub(crate) enum Refused {
    /// Touch ID can't be used now (none, locked out): the client asks for
    /// the master password.
    Unavailable,
    /// The person canceled or failed it.
    Failed(ErrorBody),
}

/// A real verification (§2.3). `klavd`'s is [`Device`]; the tests use a
/// fake.
pub(crate) trait Verify {
    /// Whether `klavd` can show Touch ID now.
    fn touch_id_available(&self) -> bool;
    /// Touch ID with `reason` (blocks on the prompt).
    fn touch_id(&self, reason: &str) -> Result<(), Refused>;
    /// Checks the master password (Argon2id: about a second).
    fn password(&self, password: SecretText) -> Result<(), ErrorBody>;
}

/// The device's real verification: Touch ID through the [`Biometric`]
/// seam, the master password checked against the session unlocked in
/// memory ([`PasswordCheck`], §2.3), one check at a time ([`OnePassword`]).
pub(crate) struct Device<'a> {
    pub(crate) touch: &'a dyn Biometric,
    pub(crate) touch_id: bool,
    pub(crate) check: Option<&'a PasswordCheck>,
    pub(crate) passwords: &'a OnePassword,
    pub(crate) gate: bool,
}

impl Verify for Device<'_> {
    fn touch_id_available(&self) -> bool {
        self.touch_id && self.touch.available()
    }

    fn touch_id(&self, reason: &str) -> Result<(), Refused> {
        match self.touch.authenticate(reason) {
            Ok(()) => Ok(()),
            Err(e @ (klav_touchid::Error::Cancelled | klav_touchid::Error::AuthFailed)) => {
                Err(Refused::Failed(crate::touchid::refused(&e)))
            }
            Err(_) => Err(Refused::Unavailable),
        }
    }

    fn password(&self, password: SecretText) -> Result<(), ErrorBody> {
        self.passwords.check(self.gate, self.check, password)
    }
}

/// One master-password check at a time in `klavd` (finding 1 of the second
/// layer-2 review): each wrong password costs an Argon2id run with a large
/// memory setting on its own thread, so a second check while one runs is
/// answered at once instead of starting another. The answer is
/// `presence_busy` with the gate on, and `conflict`, which older clients
/// know, with it off (the ADR's own choice; Still open).
#[derive(Debug, Default)]
pub(crate) struct OnePassword(std::sync::atomic::AtomicBool);

impl OnePassword {
    /// Checks `password` against `check`, the session in memory (§2.3):
    /// `wrong_credentials` when it isn't that session's master password, or
    /// when there is no session to check it against.
    pub(crate) fn check(
        &self,
        gate: bool,
        check: Option<&PasswordCheck>,
        password: SecretText,
    ) -> Result<(), ErrorBody> {
        self.one(gate, || {
            let Some(check) = check else {
                return Err(crate::server::error_body(
                    &klav_client::ClientError::WrongCredentials,
                ));
            };
            let password = klav_core::crypto::kdf::MasterPassword::new(password.expose());
            tokio::task::block_in_place(|| check.check(&password))
                .map_err(|e| crate::server::error_body(&e))
        })
    }

    /// Runs `check` unless another check runs: then the busy answer, at
    /// once (nobody waits, so nothing piles up behind a slow one).
    pub(crate) fn one<T>(
        &self,
        gate: bool,
        check: impl FnOnce() -> Result<T, ErrorBody>,
    ) -> Result<T, ErrorBody> {
        use std::sync::atomic::{AtomicBool, Ordering};
        /// Clears the flag on drop, a panic included.
        struct Running<'a>(&'a AtomicBool);
        impl Drop for Running<'_> {
            fn drop(&mut self) {
                self.0.store(false, Ordering::Release);
            }
        }
        if self
            .0
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(if gate {
                busy()
            } else {
                ErrorBody {
                    code: ErrorCode::Conflict,
                    message: "klavd is checking another master password: try again in a moment"
                        .into(),
                    paused: None,
                    presence: None,
                }
            });
        }
        let _running = Running(&self.0);
        check()
    }

    /// Whether a check is running.
    #[cfg(test)]
    pub(crate) fn running(&self) -> bool {
        self.0.load(std::sync::atomic::Ordering::Acquire)
    }
}

/// A window opened by a verification: it lasts what the prompt said, and
/// tightening the setting shortens it at once (§2.4).
#[derive(Debug, Clone, Copy)]
struct Grant {
    at: Instant,
    /// The setting the prompt stated, lowered by every tightening since.
    window: Window,
}

impl Grant {
    fn covers(&self, setting: Window, now: Instant) -> bool {
        match self.window.min(setting) {
            Window::Always => false,
            Window::FiveMinutes => now.saturating_duration_since(self.at) <= FIVE_MINUTES,
            Window::Unlocked => true,
        }
    }
}

/// A passkey verification, with the passkey setting it was made under
/// (§2.5): loosening the setting later doesn't lengthen it.
#[derive(Debug, Clone, Copy)]
struct PasskeyGrant {
    verified: uv::Verified,
    window: Window,
}

#[derive(Debug, Default)]
struct Inner {
    /// The lock generation the session-bound state below belongs to.
    generation: u64,
    /// Read at unlock; `None` while locked.
    settings: Option<Settings>,
    /// The presence setting this `klavd` last read or set, kept across
    /// locks only to word the next `unlock` prompt (the ADR's own choice;
    /// Still open). `None` until the first unlock since `klavd` started.
    last_presence: Option<Window>,
    windows: HashMap<Key, Grant>,
    passkeys: HashMap<Key, PasskeyGrant>,
    /// The last `presence_required` sent on each connection, which a
    /// password sent again must match (finding 2 of layer 3's review).
    asks: HashMap<u64, Pending>,
    /// Connections held until Klav locks (§1.2).
    held: HashSet<u64>,
    /// Connections that declared `hold`; kept across locks.
    declared: HashSet<u64>,
    /// The prompt `klavd` shows now, if any: one at a time (§2.4).
    prompt: Option<PromptKind>,
    /// The key that unlocked `klavd`, until it locks.
    unlocked_by: Option<Key>,
}

/// Which prompt `klavd` shows (§2.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PromptKind {
    /// A presence prompt: a value, an operation that already asks, a
    /// setting's loosening, a passkey use.
    Presence,
    /// `unlock`'s Touch ID.
    Unlock,
}

/// An open prompt (§2.4): cleared when dropped, also when the Touch ID call
/// panics and unwinds (finding 7 of the second layer-2 review), so `klavd`
/// never answers `presence_busy` for good.
#[must_use]
pub(crate) struct OpenPrompt<'a>(&'a Presence);

impl Drop for OpenPrompt<'_> {
    fn drop(&mut self) {
        let mut inner = self.0.inner();
        inner.prompt = None;
        self.0.shown.send_modify(|shown| shown.open = None);
    }
}

/// The open prompt as the requests waiting for a lock see it: which one is
/// open, and how many have opened since `klavd` started. Changed only with
/// [`Inner::prompt`], under the same lock.
#[derive(Debug, Default, Clone, Copy)]
struct Shown {
    open: Option<PromptKind>,
    opened: u64,
}

/// What a verification at unlock grants, and what the answer says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Unlocked {
    /// The connection is now held until Klav locks.
    pub(crate) held: bool,
}

/// The gate's state. See the module docs.
#[derive(Debug, Default)]
pub(crate) struct Presence {
    inner: Mutex<Inner>,
    /// [`Inner::prompt`], for [`Presence::lock`]'s waiters.
    shown: tokio::sync::watch::Sender<Shown>,
}

fn locked() -> ErrorBody {
    ErrorBody {
        code: ErrorCode::Locked,
        message: "klavd is locked: run `klav unlock`".into(),
        paused: None,
        presence: None,
    }
}

pub(crate) fn busy() -> ErrorBody {
    ErrorBody {
        code: ErrorCode::PresenceBusy,
        message:
            "another program is asking for presence in Klav: try again once that prompt closes"
                .into(),
        paused: None,
        presence: None,
    }
}

impl Presence {
    fn inner(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The settings of the session opened in `generation`; `locked` while
    /// locked.
    pub(crate) fn settings(&self, generation: u64) -> Result<Settings, ErrorBody> {
        let inner = self.inner();
        inner
            .settings
            .filter(|_| inner.generation == generation)
            .ok_or_else(locked)
    }

    /// The presence setting to word an `unlock` prompt with: `None` before
    /// the first unlock since `klavd` started.
    pub(crate) fn last_presence(&self) -> Option<Window> {
        self.inner().last_presence
    }

    /// Klav unlocked in `generation`, by `caller`: its verification opens
    /// the caller's window and passkey window, and on a declared
    /// connection holds it (§2.3, §1.2). `stated` is the window the unlock
    /// prompt, or the client's question, stated (`None`: it stated none,
    /// and opens none). `passkey`: the unlock counts as the passkey
    /// verification (ADR 0020 §8), which a password the client didn't read
    /// on its terminal doesn't (Omar's decision B of 2026-11-19).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn open(
        &self,
        generation: u64,
        settings: Settings,
        caller: &Caller,
        stated: Option<Window>,
        passkey: bool,
        passkey_flow: bool,
        now: Instant,
    ) -> Unlocked {
        let mut inner = self.inner();
        if generation < inner.generation {
            // A lock came first: this session is already gone.
            return Unlocked { held: false };
        }
        inner.generation = generation;
        inner.settings = Some(settings);
        inner.last_presence = Some(settings.presence);
        inner.windows.clear();
        inner.passkeys.clear();
        inner.asks.clear();
        inner.held.clear();
        inner.unlocked_by = Some(caller.key);
        if settings.presence == Window::Always {
            inner.declared.clear();
        }
        let window = stated.map_or(Window::Always, |s| s.min(settings.presence));
        let held = inner.grant(caller, window, now);
        if passkey {
            inner.passkeys.insert(
                caller.key,
                PasskeyGrant {
                    verified: uv::Verified::unlock(now, passkey_flow),
                    window: passkey_window(caller, settings.passkey),
                },
            );
        }
        Unlocked { held }
    }

    /// Klav locked; `generation` is the new one. Everything of the session
    /// goes, and so do the held connections. Declarations stay.
    pub(crate) fn close(&self, generation: u64) {
        let mut inner = self.inner();
        inner.generation = inner.generation.max(generation);
        inner.settings = None;
        inner.windows.clear();
        inner.passkeys.clear();
        inner.asks.clear();
        inner.held.clear();
        inner.unlocked_by = None;
    }

    /// Connection `conn` closed.
    pub(crate) fn forget_connection(&self, conn: u64) {
        let mut inner = self.inner();
        inner.declared.remove(&conn);
        inner.held.remove(&conn);
        inner.windows.remove(&Key::Connection(conn));
        inner.asks.remove(&conn);
        inner.passkeys.remove(&Key::Connection(conn));
        inner.passkeys.remove(&Key::NoWindow(conn));
    }

    /// Whether another key than `caller`'s unlocked `klavd` (§2.4, Q-N1).
    pub(crate) fn unlocked_by_other(&self, caller: &Caller) -> bool {
        self.inner()
            .unlocked_by
            .is_some_and(|key| key != caller.key)
    }

    /// The caller brought the master password to an `unlock` while `klavd`
    /// was already unlocked: its own real verification (§2.4). `stated` is
    /// the window the client said it opens, when that is what `klavd` would
    /// open ([`unlock_stated`]); `None` opens none. `passkey`: as for
    /// [`Presence::open`].
    pub(crate) fn password_at_unlock(
        &self,
        generation: u64,
        caller: &Caller,
        stated: Option<Window>,
        passkey: bool,
        passkey_flow: bool,
        now: Instant,
    ) -> Unlocked {
        let mut inner = self.inner();
        let Some(settings) = inner.settings.filter(|_| inner.generation == generation) else {
            return Unlocked { held: false };
        };
        let window = stated.map_or(Window::Always, |s| s.min(settings.presence));
        let held = inner.grant(caller, window, now);
        if passkey {
            inner.passkeys.insert(
                caller.key,
                PasskeyGrant {
                    verified: uv::Verified::unlock(now, passkey_flow),
                    window: passkey_window(caller, settings.passkey),
                },
            );
        }
        Unlocked { held }
    }

    /// Marks a prompt of `kind` open while the guard lives, or answers
    /// `presence_busy` when one already is (§2.4, finding 5 of the second
    /// layer-2 review: with the gate on, every prompt `klavd` shows takes
    /// part, whichever key or operation asks). Nobody waits for it: a
    /// request that waited would show its dialog right after the open one.
    pub(crate) fn open_prompt(&self, kind: PromptKind) -> Result<OpenPrompt<'_>, ErrorBody> {
        let mut inner = self.inner();
        self.claim(&mut inner, kind)
    }

    /// The one place a prompt is marked open, with `inner` held: what the
    /// waiters of [`Presence::lock`] watch changes with it.
    fn claim(&self, inner: &mut Inner, kind: PromptKind) -> Result<OpenPrompt<'_>, ErrorBody> {
        if inner.prompt.is_some() {
            return Err(busy());
        }
        inner.prompt = Some(kind);
        self.shown.send_modify(|shown| {
            shown.open = Some(kind);
            shown.opened = shown.opened.wrapping_add(1);
        });
        Ok(OpenPrompt(self))
    }

    /// Waits for `lock`, with the gate on, without lining a prompt up behind
    /// an open one (§2.4; the third layer-2 review, finding A). A request
    /// whose dialog's holder keeps `lock` would otherwise wait for that
    /// dialog to close and show its own right after it.
    ///
    /// - `asks`: the caller shows a prompt once it has the lock. It gets
    ///   `presence_busy` at once while a prompt `only` matches (`None`: any)
    ///   is open, and as soon as one opens before the lock is free.
    /// - Otherwise it waits as before. The answer says whether a prompt was
    ///   open when it started waiting, or opened while it waited: a prompt
    ///   the caller turns out to need after all would come right after that
    ///   one, so it answers `presence_busy` instead of showing it.
    ///
    /// A lock that is free at once is taken without either.
    pub(crate) async fn lock<'a, T>(
        &self,
        lock: &'a tokio::sync::Mutex<T>,
        asks: bool,
        only: Option<PromptKind>,
    ) -> Result<(tokio::sync::MutexGuard<'a, T>, bool), ErrorBody> {
        let blocks = |shown: &Shown| shown.open.is_some_and(|k| only.is_none_or(|o| o == k));
        // Subscribed before the lock is tried: no prompt that opens from
        // here on is missed.
        let mut shown = self.shown.subscribe();
        let start = *shown.borrow_and_update();
        if asks && blocks(&start) {
            return Err(busy());
        }
        if let Ok(guard) = lock.try_lock() {
            return Ok((guard, false));
        }
        if asks {
            return tokio::select! {
                biased;
                _ = shown.wait_for(blocks) => Err(busy()),
                guard = lock.lock() => Ok((guard, false)),
            };
        }
        let guard = lock.lock().await;
        let end = *shown.borrow();
        Ok((guard, blocks(&start) || end.opened != start.opened))
    }

    /// Whether an unlock prompt is open.
    #[cfg(test)]
    pub(crate) fn unlock_prompt_open(&self) -> bool {
        self.inner().prompt == Some(PromptKind::Unlock)
    }

    /// Whether any prompt is open.
    #[cfg(test)]
    pub(crate) fn prompt_open(&self) -> bool {
        self.inner().prompt.is_some()
    }

    /// `hold` on `conn` (§1.2). Under Always it has no effect. Answers
    /// whether the connection is declared, and whether it is held.
    pub(crate) fn declare(&self, conn: u64) -> (bool, bool) {
        let mut inner = self.inner();
        if inner.settings.map(|s| s.presence) == Some(Window::Always) {
            return (false, false);
        }
        inner.declared.insert(conn);
        (true, inner.held.contains(&conn))
    }

    /// Changes the presence setting of the session opened in `generation`
    /// (already stored). Tightening applies at once, to every window and
    /// held connection; to Always it drops every held connection and
    /// declaration. Loosening opens nothing: the next value asks (§2.4).
    pub(crate) fn set_presence(&self, generation: u64, window: Window) -> Result<(), ErrorBody> {
        let mut guard = self.inner();
        let inner = &mut *guard;
        if inner.generation != generation {
            return Err(locked());
        }
        let Some(settings) = inner.settings.as_mut() else {
            return Err(locked());
        };
        settings.presence = window;
        inner.last_presence = Some(window);
        for grant in inner.windows.values_mut() {
            grant.window = grant.window.min(window);
        }
        inner.windows.retain(|_, g| g.window != Window::Always);
        if window == Window::Always {
            inner.held.clear();
            inner.declared.clear();
        }
        Ok(())
    }

    /// Changes the passkey setting, with the same rules (§2.4, §2.5).
    pub(crate) fn set_passkey(&self, generation: u64, window: Window) -> Result<(), ErrorBody> {
        let mut guard = self.inner();
        let inner = &mut *guard;
        if inner.generation != generation {
            return Err(locked());
        }
        let Some(settings) = inner.settings.as_mut() else {
            return Err(locked());
        };
        settings.passkey = window;
        for grant in inner.passkeys.values_mut() {
            grant.window = grant.window.min(window);
        }
        Ok(())
    }

    /// Whether a passkey use by `caller` needs a new verification (§2.5).
    pub(crate) fn passkey_needs(&self, caller: &Caller, now: Instant) -> bool {
        let inner = self.inner();
        let Some(settings) = inner.settings else {
            return true;
        };
        inner.passkeys.get(&caller.key).is_none_or(|grant| {
            uv::needs_verification(
                grant.window.min(settings.passkey),
                Some(grant.verified),
                now,
            )
        })
    }

    /// A passkey use relied on `caller`'s last verification.
    pub(crate) fn passkey_spend(&self, caller: &Caller) {
        if let Some(grant) = self.inner().passkeys.get_mut(&caller.key) {
            grant.verified.spent = true;
        }
    }

    /// Touch ID or the password for a passkey use by `caller`, in the
    /// session of `generation`.
    pub(crate) fn passkey_checked(&self, generation: u64, caller: &Caller, now: Instant) {
        let mut inner = self.inner();
        let Some(settings) = inner.settings.filter(|_| inner.generation == generation) else {
            return;
        };
        inner.passkeys.insert(
            caller.key,
            PasskeyGrant {
                verified: uv::Verified::checked(now),
                window: passkey_window(caller, settings.passkey),
            },
        );
    }

    /// The gate (§4): `Ok` when `caller` may have the value `purpose`
    /// names, after a real verification if its window doesn't cover it.
    ///
    /// - A held connection, or an open window of the caller's key, covers
    ///   a `Window` value. Nothing covers an `EveryTime` one.
    /// - `password`, when it comes along, is the verification, but only as
    ///   the answer to the ask `klavd` sent last on this connection: if
    ///   `klavd` would now ask something else (another window, another
    ///   item, another request), it isn't checked, and the answer is the new
    ///   ask (finding 2 of layer 3's review). Only this pass keeps and
    ///   compares asks, so the one kept and the one compared always have the
    ///   same shape (the second review of layer 3, finding 7).
    /// - Otherwise Touch ID, where `klavd` can show it. While another
    ///   presence prompt is open, the answer is `presence_busy` at once
    ///   (§2.4: no queue behind an open prompt, whichever key asks).
    /// - Where it can't, `presence_required`, with what the client's
    ///   prompt must say, kept for the password that answers it.
    ///
    /// A verification that ends after Klav locked grants nothing.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn require(
        &self,
        generation: u64,
        caller: &Caller,
        purpose: Purpose<'_>,
        password: Option<SecretText>,
        bound: &Bound,
        version: Option<u64>,
        verify: &dyn Verify,
        lang: Lang,
        now: &dyn Fn() -> Instant,
    ) -> Result<Passed, ErrorBody> {
        let (setting, declared, lasts, pending, open, checking, version) = {
            let mut inner = self.inner();
            let Some(settings) = inner.settings.filter(|_| inner.generation == generation) else {
                return Err(locked());
            };
            let setting = settings.presence;
            let window = matches!(purpose, Purpose::Window { .. });
            if window && inner.covers(caller, setting, now()) {
                inner.asks.remove(&caller.conn);
                return Ok(Passed {
                    version,
                    opens: None,
                });
            }
            let declared =
                window && setting != Window::Always && inner.declared.contains(&caller.conn);
            let lasts = match (purpose, caller.key, setting) {
                (Purpose::EveryTime { .. }, _, _)
                | (_, Key::NoWindow(_), _)
                | (_, _, Window::Always) => None,
                _ if declared => Some(Lasts::UntilLock),
                (_, _, Window::Unlocked) => Some(Lasts::UntilLock),
                (_, _, Window::FiveMinutes) => Some(Lasts::FiveMinutes),
            };
            let touch = password.is_none() && verify.touch_id_available();
            if touch && inner.prompt.is_some() {
                return Err(busy());
            }
            let value = match (lasts, purpose) {
                (None, Purpose::Window { value }) => Some(value.clone()),
                _ => None,
            };
            let pending = Pending {
                generation,
                ask: PresenceAsk {
                    key: caller.kind(),
                    window: setting,
                    terminal: caller.terminal.clone(),
                    declared,
                    lasts: lasts.map(wire_lasts),
                    value,
                },
                bound: bound.clone(),
                version,
            };
            let mut open = None;
            let mut checking = None;
            // The version the hand-out must find: the one read for this ask,
            // or, for a password sent again, the one `klavd` asked about.
            let mut version = version;
            if let Some(password) = password {
                // Checked only as the answer to what the client was asked.
                if let Some(asked) = inner
                    .asks
                    .remove(&caller.conn)
                    .filter(|asked| asked.answered_by(&pending))
                {
                    version = asked.version;
                    checking = Some(password);
                } else {
                    let ask = pending.ask.clone();
                    inner.asks.insert(caller.conn, pending);
                    return Err(required(ask));
                }
            } else if !touch {
                let ask = pending.ask.clone();
                inner.asks.insert(caller.conn, pending);
                return Err(required(ask));
            } else {
                inner.asks.remove(&caller.conn);
                // Dropped only after `inner` is released (below).
                open = Some(self.claim(&mut inner, PromptKind::Presence)?);
            }
            (setting, declared, lasts, pending, open, checking, version)
        };
        let checked = match checking {
            Some(password) => verify.password(password),
            None => {
                // Just before the dialog: the client prints its terminal's
                // name, to compare with the dialog's (§2.4, N9).
                if let Some(notify) = &caller.notify {
                    notify.send(Notice::TouchId);
                }
                let reason = reason(caller, declared, lasts, purpose, lang);
                let result = verify.touch_id(&reason);
                drop(open);
                match result {
                    Ok(()) => Ok(()),
                    Err(Refused::Failed(e)) => Err(e),
                    Err(Refused::Unavailable) => {
                        let ask = pending.ask.clone();
                        self.inner().asks.insert(caller.conn, pending);
                        return Err(required(ask));
                    }
                }
            }
        };
        checked?;
        let inner = self.inner();
        if inner.settings.is_none() || inner.generation != generation {
            return Err(locked());
        }
        // Not opened here: only once the hand-out finds what was asked
        // about (Omar's decision G of 2026-11-19).
        let opens = lasts.map(|lasts| Opening {
            generation,
            lasts,
            declared,
            setting,
        });
        Ok(Passed { version, opens })
    }

    /// Opens the window a passed verification stated (`Passed::opens`),
    /// called under the session's lock once the hand-out found the item and
    /// the version that were asked about. What the prompt said, shortened by
    /// any tightening since; nothing once Klav locked since.
    pub(crate) fn open_window(&self, caller: &Caller, opening: Opening, now: Instant) {
        let mut inner = self.inner();
        let Some(settings) = inner
            .settings
            .filter(|_| inner.generation == opening.generation)
        else {
            return;
        };
        let stated = match opening.lasts {
            Lasts::FiveMinutes => Window::FiveMinutes,
            Lasts::UntilLock if opening.declared => Window::Unlocked,
            Lasts::UntilLock => opening.setting,
        };
        let window = stated.min(settings.presence);
        if opening.declared {
            if window != Window::Always && inner.declared.contains(&caller.conn) {
                inner.held.insert(caller.conn);
            }
        } else {
            inner.grant(caller, window, now);
        }
    }

    /// The gate's first look at a `Window` value, before `klavd` reads it
    /// (the third layer-2 review, finding A): naming the value means
    /// resolving the item under the session's lock, and an open dialog's
    /// holder can keep that lock. A window that covers it passes here,
    /// without the lock. Otherwise, with Touch ID to show and another
    /// prompt open, `presence_busy`; else [`Untitled::NeedsText`]. It never
    /// asks, never checks a password, and keeps or compares no ask: only
    /// [`Presence::require`] does (the second review of layer 3, finding 7).
    pub(crate) fn first(
        &self,
        generation: u64,
        caller: &Caller,
        password: bool,
        verify: &dyn Verify,
        now: &dyn Fn() -> Instant,
    ) -> Result<Untitled, ErrorBody> {
        let mut inner = self.inner();
        let Some(settings) = inner.settings.filter(|_| inner.generation == generation) else {
            return Err(locked());
        };
        if inner.covers(caller, settings.presence, now()) {
            inner.asks.remove(&caller.conn);
            return Ok(Untitled::Passed);
        }
        let touch = !password && verify.touch_id_available();
        if touch && inner.prompt.is_some() {
            return Err(busy());
        }
        Ok(Untitled::NeedsText { touch })
    }

    #[cfg(test)]
    fn is_held(&self, conn: u64) -> bool {
        self.inner().held.contains(&conn)
    }
}

impl Inner {
    /// Whether a `Window` value for `caller` needs no new verification.
    fn covers(&mut self, caller: &Caller, setting: Window, now: Instant) -> bool {
        if setting == Window::Always {
            return false;
        }
        if self.held.contains(&caller.conn) {
            return true;
        }
        self.windows.retain(|_, g| g.covers(setting, now));
        self.windows.contains_key(&caller.key)
    }

    /// Opens `caller`'s window for `window` from `now`; on a declared
    /// connection, holds it instead. Returns whether it is held.
    fn grant(&mut self, caller: &Caller, window: Window, now: Instant) -> bool {
        if window == Window::Always || matches!(caller.key, Key::NoWindow(_)) {
            return false;
        }
        if self.declared.contains(&caller.conn) {
            self.held.insert(caller.conn);
            return true;
        }
        self.windows.insert(caller.key, Grant { at: now, window });
        false
    }
}

/// The passkey setting a verification of `caller` gets: none past Always
/// for a peer with no window.
fn passkey_window(caller: &Caller, setting: Window) -> Window {
    if matches!(caller.key, Key::NoWindow(_)) {
        Window::Always
    } else {
        setting
    }
}

/// `presence_required`, with what the client's prompt must say (§2.4).
fn required(ask: PresenceAsk) -> ErrorBody {
    ErrorBody {
        code: ErrorCode::PresenceRequired,
        message: "Klav needs the master password before it hands out this value".into(),
        paused: None,
        presence: Some(Box::new(ask)),
    }
}

/// [`Lasts`] as [`PresenceAsk::lasts`] says it.
fn wire_lasts(lasts: Lasts) -> AskLasts {
    match lasts {
        Lasts::FiveMinutes => AskLasts::FiveMinutes,
        Lasts::UntilLock => AskLasts::UntilLock,
    }
}

/// A value as `klavd`'s own Touch ID prompt names it.
pub(crate) fn value_ask(value: &AskValue) -> ValueAsk<'_> {
    let title = value.title.as_deref();
    match value.kind {
        AskValueKind::Show => ValueAsk::Show(title),
        AskValueKind::Previous => ValueAsk::Previous(title),
        AskValueKind::Code => ValueAsk::Code(title),
        AskValueKind::Fill => ValueAsk::Fill(title),
        AskValueKind::Generated => ValueAsk::Generated,
        AskValueKind::Resolve => {
            ValueAsk::Resolve(value.count.map_or(0, |n| usize::try_from(n).unwrap_or(0)))
        }
    }
}

/// The Touch ID prompt for a verification (§2.4, §1.2).
fn reason(
    caller: &Caller,
    declared: bool,
    lasts: Option<Lasts>,
    purpose: Purpose<'_>,
    lang: Lang,
) -> String {
    match (purpose, lasts) {
        (Purpose::EveryTime { reason }, _) => reason.to_owned(),
        // No window: the value, and who it is for (Omar's decision C).
        (Purpose::Window { value }, None) => Prompt::Value {
            ask: value_ask(value),
            who: caller.who(),
        }
        .reason(lang, None),
        (Purpose::Window { .. }, Some(lasts)) => {
            let who = if declared {
                Who::Declared
            } else {
                caller.who()
            };
            Prompt::Presence { who, lasts }.reason(lang, None)
        }
    }
}

/// What the `unlock` prompt says for `caller` (§2.4, §1.2): the window it
/// opens when `klavd` knows the setting, and `None` when it says none.
pub(crate) fn unlock_window<'a>(
    presence: &Presence,
    caller: &'a Caller,
    declared: bool,
) -> (Option<Window>, Who<'a>, Option<Lasts>) {
    let last = presence.last_presence();
    let lasts = match (last, caller.key) {
        (None | Some(Window::Always), _) | (_, Key::NoWindow(_)) => None,
        (Some(_), _) if declared => Some(Lasts::UntilLock),
        (Some(Window::Unlocked), _) => Some(Lasts::UntilLock),
        (Some(Window::FiveMinutes), _) => Some(Lasts::FiveMinutes),
    };
    let stated = match lasts {
        None => None,
        Some(Lasts::FiveMinutes) => Some(Window::FiveMinutes),
        Some(Lasts::UntilLock) => Some(Window::Unlocked),
    };
    let who = if declared {
        Who::Declared
    } else {
        caller.who()
    };
    (stated, who, lasts)
}

/// What `status` tells `caller` with the gate on (§2.4): whether another
/// key unlocked `klavd` (Q-N1), and what the caller's own master password
/// at `unlock` would open, as the unlock's Touch ID prompt would say it.
/// Before the first unlock since `klavd` started it says none: the setting
/// is sealed, and a question never promises a window `klavd` can't name
/// (Omar's decision A of 2026-11-19).
pub(crate) fn status_presence(presence: &Presence, caller: &Caller) -> StatusPresence {
    let declared = presence.is_declared(caller.conn);
    let lasts = unlock_window(presence, caller, declared).2.map(wire_lasts);
    StatusPresence {
        elsewhere: presence.unlocked_by_other(caller),
        key: caller.kind(),
        terminal: caller.terminal.clone(),
        declared,
        lasts,
    }
}

/// The window an `unlock` with the master password opens for `caller`:
/// the one the client said its question showed (`shown`, `always` for
/// none), when that is what `klavd` would open now; otherwise none. Before
/// the first unlock since `klavd` started that is none, like its Touch ID
/// dialog's (Omar's decision A of 2026-11-19, which replaced the ADR's own
/// choice 35). A client that sent nothing (an older one) opens none, and
/// so does a password the client didn't read on its terminal (`untyped`:
/// Omar's decisions 4 and B of 2026-11-19).
pub(crate) fn unlock_stated(
    presence: &Presence,
    caller: &Caller,
    shown: Option<Window>,
) -> Option<Window> {
    if caller.untyped {
        return None;
    }
    let declared = presence.is_declared(caller.conn);
    let would = unlock_window(presence, caller, declared).0;
    if shown == Some(would.unwrap_or(Window::Always)) {
        would
    } else {
        None
    }
}

impl Presence {
    /// Whether `conn` declared `hold`.
    pub(crate) fn is_declared(&self, conn: u64) -> bool {
        self.inner().declared.contains(&conn)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    v: u32,
    window: Window,
}

/// Reads one setting: `missing` when there is no blob; Always when it
/// doesn't open, isn't version 1, or isn't this layout (§2.4).
fn load_one(
    path: &Path,
    key: &LocalKey,
    ctx: &LocalContext,
    purpose: &str,
    missing: Window,
) -> Window {
    let Ok(blob) = std::fs::read(path) else {
        return if std::fs::symlink_metadata(path).is_ok() {
            Window::Always
        } else {
            missing
        };
    };
    open_local_data(key, ctx, purpose, &blob)
        .ok()
        .and_then(|json| serde_json::from_slice::<Stored>(&json).ok())
        .filter(|s| s.v == 1)
        .map_or(Window::Always, |s| s.window)
}

/// Reads both settings with the local key at unlock (§2.4).
pub(crate) fn load_settings(home: &Home, key: &LocalKey, ctx: &LocalContext) -> Settings {
    Settings {
        presence: load_one(
            &home.file(PRESENCE_FILE),
            key,
            ctx,
            PRESENCE_PURPOSE,
            Window::FiveMinutes,
        ),
        passkey: load_one(
            &home.file(PASSKEY_FILE),
            key,
            ctx,
            PASSKEY_PURPOSE,
            Window::Always,
        ),
    }
}

/// Which setting to store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Which {
    Presence,
    Passkey,
}

/// Seals and stores one setting.
pub(crate) fn save(
    home: &Home,
    key: &LocalKey,
    ctx: &LocalContext,
    which: Which,
    window: Window,
) -> Result<(), ErrorBody> {
    let (file, purpose) = match which {
        Which::Presence => (PRESENCE_FILE, PRESENCE_PURPOSE),
        Which::Passkey => (PASSKEY_FILE, PASSKEY_PURPOSE),
    };
    let json = serde_json::to_vec(&Stored { v: 1, window }).map_err(|e| ErrorBody {
        code: ErrorCode::Internal,
        message: e.to_string(),
        paused: None,
        presence: None,
    })?;
    let blob = seal_local_data(key, ctx, purpose, &json).map_err(|e| ErrorBody {
        code: ErrorCode::Internal,
        message: e.to_string(),
        paused: None,
        presence: None,
    })?;
    home.ensure()
        .and_then(|()| klav_client::home::write_private(&home.file(file), &blob))
        .map_err(|e| crate::server::error_body(&e))
}

/// At an unlock with the gate on: whether the old `passkeys.json` exists,
/// never what it says; if it does, it goes and the unlock warns once
/// (§2.4, Omar's decision on Q-N3).
pub(crate) fn forget_old_passkey_file(home: &Home) -> Option<&'static str> {
    let path = home.file(OLD_PASSKEY_FILE);
    std::fs::symlink_metadata(&path).ok()?;
    let _ = std::fs::remove_file(&path);
    Some(OLD_PASSKEY_WARNING)
}

#[cfg(test)]
mod tests;
