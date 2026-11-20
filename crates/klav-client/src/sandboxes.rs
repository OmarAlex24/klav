//! The person's list of sandboxes (ADR 0036 E2.1, E3.3).
//!
//! The list comes from the verified chain alone: whether a sandbox is
//! waiting, active, revoked or ended, and why, is what its signed events
//! say ([`crate::audit::SandboxRecord`]). The proxy's last heartbeat, from
//! `sandbox_state` in `GET /v1/sync`, only adds whether each live sandbox is
//! connected and when it was last seen, and how old the heartbeat is,
//! measured from the `sent_at_ms` the proxy signed. The heartbeat is
//! checked by [`crate::sandbox_state::check_heartbeat`] with the proxy's
//! key as the verification vouched for it, and only that of the proxy the
//! account's encrypted setting names counts. A sandbox the heartbeat names
//! that the chain does not show live is ignored.
//!
//! Each heartbeat that counts moves this device's watermark for that proxy
//! and epoch, kept in [`SANDBOX_MARKS_FILE`]. One older than the watermark
//! as it stood before the sync request is a rollback (T7, T168): that
//! heartbeat does not count ([`NoSigns::Rollback`]), and the list, which
//! comes from the chain, is still shown.
//!
//! The account's preferences name the proxy. When this device cannot read
//! them, or two preferences items disagree, the list is the chain's rows of
//! every proxy, without a proxy and with a warning. When an agent wrote
//! them, [`Unlocked::sandbox_list_flagged`] gives the same rows with a
//! [`SecurityFlag`] instead (no proxy is trusted until the person sets it
//! again), and [`Unlocked::sandbox_list`] fails, as tampering in the chain
//! does.

use std::collections::HashMap;

use klav_core::crypto::identity::PublicIdentity;
use klav_core::crypto::keys::LocalKey;
use klav_core::crypto::local::{LocalContext, open_local_data, seal_local_data};
use klav_core::ids::{AgentId, SandboxId};
use klav_core::model::preferences::{ProxyMode, ProxySetting};
use klav_proto::Blob;
use klav_proto::agent::AgentPause;
use klav_proto::sandbox::{SandboxEnd, SandboxLink, SandboxState};
use klav_proto::sync::SyncState;
use reqwest::Method;
use serde::{Deserialize, Serialize};

use crate::api::Body;
use crate::audit::{AuditError, SandboxRecord, StoreEpoch, VerifyReport};
use crate::error::{ClientError, ClientResult};
use crate::home::Home;
use crate::preferences::PreferencesRead;
use crate::sandbox_state::{Discarded, check_heartbeat};
use crate::session::{Unlocked, now_ms};

/// `$KLAV_HOME/sandbox-marks.bin`: the highest heartbeat `seq` this device
/// accepted for each proxy, under its current store epoch (spec §12.2,
/// §13.12). Sealed with the local key (purpose `sandbox-marks`); kept
/// apart from `cache.bin`, whose closed schema an older client would
/// refuse with a new field. Removed with the account.
pub const SANDBOX_MARKS_FILE: &str = "sandbox-marks.bin";
/// The purpose of [`SANDBOX_MARKS_FILE`]'s sealing.
const PURPOSE_SANDBOX_MARKS: &str = "sandbox-marks";
/// Format of [`SANDBOX_MARKS_FILE`]'s contents.
const SANDBOX_MARKS_VERSION: u32 = 1;

/// With live sandboxes, a heartbeat older than this means the proxy gives
/// no signs (ADR 0036 E2.1).
pub const NO_SIGNS_LIVE_MS: i64 = 10 * 60 * 1000;
/// Without live sandboxes the proxy beats every 30 minutes: no signs only
/// past 40 (ADR 0036 E3.3).
pub const NO_SIGNS_IDLE_MS: i64 = 40 * 60 * 1000;

/// One watermark: the highest `seq` accepted under `store_epoch`, and
/// where that epoch's `sandbox.store_reset` sits in the verified chain
/// (`epoch_seq`), so the mark never goes back to an earlier epoch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Mark {
    proxy: AgentId,
    store_epoch: Blob,
    epoch_seq: u64,
    seq: u64,
}

/// [`SANDBOX_MARKS_FILE`]'s contents: `{v: 1, marks: [{proxy, store_epoch,
/// epoch_seq, seq}]}`, one mark per proxy.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MarksFile {
    v: u32,
    marks: Vec<Mark>,
}

/// What [`SANDBOX_MARKS_FILE`] holds, as read.
#[derive(Debug, Clone, PartialEq, Eq)]
enum MarksRead {
    /// Its marks (none when there is no file yet).
    Marks(Vec<Mark>),
    /// It does not open or parse at this format: read as none, and the
    /// next heartbeat that counts writes it again.
    Damaged,
    /// Written by a later version (`v` above this one's): read as none,
    /// and never written by this one.
    Newer(u32),
}

impl MarksRead {
    fn marks(&self) -> &[Mark] {
        match self {
            Self::Marks(m) => m,
            Self::Damaged | Self::Newer(_) => &[],
        }
    }

    /// The warning for the list, if the file could not be used.
    fn warning(&self) -> Option<String> {
        match self {
            Self::Marks(_) => None,
            Self::Damaged => Some(format!(
                "{SANDBOX_MARKS_FILE} cannot be read: the proxy's heartbeat was checked without \
                 this device's earlier watermark, which is written again"
            )),
            Self::Newer(v) => Some(format!(
                "{SANDBOX_MARKS_FILE} is of a newer version of Klav (format {v}): the proxy's \
                 heartbeat was checked without this device's earlier watermark, and the file is \
                 left as it is. Update Klav"
            )),
        }
    }
}

/// Reads [`SANDBOX_MARKS_FILE`] in `home`: its `v` first, as
/// `revocations.bin` does, so a later layout is never misread.
fn read_marks(home: &Home, key: &LocalKey, ctx: &LocalContext) -> MarksRead {
    #[derive(Deserialize)]
    struct Format {
        v: u32,
    }
    let blob = match std::fs::read(home.file(SANDBOX_MARKS_FILE)) {
        Ok(blob) => blob,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return MarksRead::Marks(Vec::new()),
        Err(_) => return MarksRead::Damaged,
    };
    let Ok(json) = open_local_data(key, ctx, PURPOSE_SANDBOX_MARKS, &blob) else {
        return MarksRead::Damaged;
    };
    match serde_json::from_slice::<Format>(&json) {
        Ok(f) if f.v > SANDBOX_MARKS_VERSION => return MarksRead::Newer(f.v),
        Ok(f) if f.v == SANDBOX_MARKS_VERSION => {}
        _ => return MarksRead::Damaged,
    }
    serde_json::from_slice::<MarksFile>(&json)
        .map_or(MarksRead::Damaged, |f| MarksRead::Marks(f.marks))
}

/// Writes `mark` into [`SANDBOX_MARKS_FILE`] under the home's lock, read
/// again there: for the same proxy and epoch the higher `seq` stays (another
/// process of this device may have stored a later one meanwhile). Another
/// epoch replaces it only if its reset sits later in the chain than the
/// stored epoch's: a process that listed under an older epoch never takes
/// the mark back to it, and on a tie in `epoch_seq` the stored mark stays.
/// A file of a newer version is never written.
fn store_mark(home: &Home, key: &LocalKey, ctx: &LocalContext, mark: Mark) -> ClientResult<()> {
    let _lock = home.lock()?;
    let mut marks = match read_marks(home, key, ctx) {
        MarksRead::Newer(_) => return Ok(()),
        MarksRead::Damaged => Vec::new(),
        MarksRead::Marks(m) => m,
    };
    match marks.iter_mut().find(|m| m.proxy == mark.proxy) {
        Some(m) if m.store_epoch == mark.store_epoch && m.seq >= mark.seq => return Ok(()),
        Some(m) if m.store_epoch != mark.store_epoch && m.epoch_seq >= mark.epoch_seq => {
            return Ok(());
        }
        Some(m) => *m = mark,
        None => marks.push(mark),
    }
    let json = serde_json::to_vec(&MarksFile {
        v: SANDBOX_MARKS_VERSION,
        marks,
    })
    .map_err(|e| ClientError::Invalid(format!("sandbox marks: {e}")))?;
    let blob = seal_local_data(key, ctx, PURPOSE_SANDBOX_MARKS, &json)?;
    crate::home::write_private(&home.file(SANDBOX_MARKS_FILE), &blob)
}

/// Where a sandbox stands, from the verified chain and this device's clock
/// alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxStatus {
    /// Issued, not claimed yet.
    Waiting,
    /// Claimed, not revoked and not expired.
    Active,
    /// The person revoked it and the server says it keeps that and denies
    /// it access, but the proxy has not logged its end yet: that end, signed
    /// in the verified log, is what proves it stopped.
    Revoking,
    /// Past its `expires_at` by this device's clock, and the proxy has not
    /// logged its end yet. The server already denies it access. A device
    /// clock up to 5 minutes ahead shows a sandbox as expired that the
    /// server still serves until its own clock gets there.
    Expired,
    /// The proxy logged its end ([`SandboxRow::end_reason`]).
    Ended,
    /// The account revoked its proxy (`agent.revoked`, signed by the
    /// account, in the verified chain after its issue) and that proxy had
    /// not logged its end: a revoked proxy can never log it, so the row
    /// stays here, for good, whether the person revoked the sandbox or not.
    /// Nothing proves it stopped: the server refuses that proxy's requests,
    /// but a proxy that ignores its revocation keeps what it already
    /// decrypted (ADR 0036 risk 62). Not live. An older `klav` or app
    /// reads it as [`Self::Unknown`]; `klav-ffi` gives the apps the status
    /// the row had before, as an older `klavd` does.
    ProxyRevoked,
    /// A status this build does not know, read from a newer `klavd`. It
    /// fails closed: live, never ended, and counted as one the proxy still
    /// serves. This build never produces it.
    #[serde(other)]
    Unknown,
}

impl SandboxStatus {
    /// Waiting, active, revoking, or a status this build does not know:
    /// the rows the heartbeat may speak of.
    #[must_use]
    pub fn is_live(self) -> bool {
        matches!(
            self,
            Self::Waiting | Self::Active | Self::Revoking | Self::Unknown
        )
    }

    /// Waiting or active, or unknown: the rows the proxy surely still counts
    /// as live, so it beats every 5 minutes. A revoking one it may already
    /// have dropped, and then it beats every 30.
    fn proxy_counts_live(self) -> bool {
        matches!(self, Self::Waiting | Self::Active | Self::Unknown)
    }
}

/// Why a sandbox ended, as its proxy logged it ([`SandboxEnd`]), with a
/// catch-all for a reason this build does not know (from a newer `klavd`):
/// such a row is still ended, since its status says so, and only the
/// reason is unknown. The names are [`SandboxEnd`]'s.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndReason {
    /// Its issuer stopped it.
    Stop,
    /// It reached its `expires_at`.
    Ttl,
    /// An hour without a connection.
    Inactivity,
    /// A second claim with the same secret: the theft signal.
    Theft,
    /// Its forwarder released it when shutting down.
    Released,
    /// The person removed or revoked its issuer.
    IssuerRemoved,
    /// The person revoked it with a signed revocation.
    Person,
    /// The person revoked it through the proxy's local socket.
    PersonLocal,
    /// A reason this build does not know.
    #[serde(other)]
    Unknown,
}

impl From<SandboxEnd> for EndReason {
    fn from(e: SandboxEnd) -> Self {
        match e {
            SandboxEnd::Stop => Self::Stop,
            SandboxEnd::Ttl => Self::Ttl,
            SandboxEnd::Inactivity => Self::Inactivity,
            SandboxEnd::Theft => Self::Theft,
            SandboxEnd::Released => Self::Released,
            SandboxEnd::IssuerRemoved => Self::IssuerRemoved,
            SandboxEnd::Person => Self::Person,
            SandboxEnd::PersonLocal => Self::PersonLocal,
        }
    }
}

/// One sandbox of the account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxRow {
    /// The sandbox.
    pub sandbox_id: SandboxId,
    /// The proxy that issued it.
    pub proxy_id: AgentId,
    /// The issuer, as the proxy signed it.
    pub issuer_id: AgentId,
    /// The issuer's name, as the server lists it (absent when it no longer
    /// does).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer_name: Option<String>,
    /// The issuer's label: shown "per the issuer" (T136).
    pub label: String,
    /// The profiles it may use.
    pub profiles: Vec<String>,
    /// When it was issued (the log's clock, Unix ms).
    pub issued_at: i64,
    /// When it expires, as the proxy signed it (Unix ms).
    pub expires_at: i64,
    /// When it was claimed (the log's clock), if it was.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claimed_at: Option<i64>,
    /// Where it stands.
    pub status: SandboxStatus,
    /// With [`SandboxStatus::Ended`]: why.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_reason: Option<EndReason>,
    /// With [`SandboxStatus::Ended`]: when the end was logged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ended_at: Option<i64>,
    /// The signed time of the person's last revocation that covered it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_by_person_at: Option<i64>,
    /// With [`SandboxStatus::ProxyRevoked`]: when the server logged the
    /// account's signed revocation of its proxy (the log's clock).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_revoked_at: Option<i64>,
    /// Per the proxy's heartbeat, only for a live sandbox of the account's
    /// proxy that the heartbeat names: whether a forwarder is connected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connected: Option<bool>,
    /// Per the same heartbeat: the proxy's last word from it (proxy clock).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen_at: Option<i64>,
}

/// Why there is no heartbeat that counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NoSigns {
    /// The server has none from this proxy.
    NoHeartbeat,
    /// The verified chain has no store epoch of this proxy.
    NoEpoch,
    /// Under another epoch than the chain's last.
    OtherEpoch,
    /// Signed more than 5 minutes ahead of this device's clock.
    Ahead,
    /// A version of the heartbeat this device does not know.
    Version,
    /// Older than one this device already accepted under the same epoch
    /// (a rollback, T7, T168): the server held back the latest. The
    /// watermark does not move.
    Rollback,
    /// A reason this build does not know, read from a newer `klavd`: no
    /// heartbeat counts, so the proxy gives no signs.
    #[serde(other)]
    Unknown,
}

impl From<Discarded> for NoSigns {
    fn from(d: Discarded) -> Self {
        match d {
            Discarded::NoEpoch => Self::NoEpoch,
            Discarded::OtherEpoch => Self::OtherEpoch,
            Discarded::Ahead => Self::Ahead,
            Discarded::Version => Self::Version,
        }
    }
}

/// The account's proxy, as this device sees it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyView {
    /// The proxy the account's setting names.
    pub agent_id: AgentId,
    /// Its name, as the server lists it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// A pause the account signed holds it (its own or every agent's).
    pub paused: bool,
    /// When it signed its last heartbeat that counts (proxy clock), if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub heartbeat_sent_at: Option<i64>,
    /// How old that heartbeat is by this device's clock (ms).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub heartbeat_age_ms: Option<i64>,
    /// Older than [`NO_SIGNS_LIVE_MS`] with live sandboxes, or than
    /// [`NO_SIGNS_IDLE_MS`] without, or none that counts: the proxy gives
    /// no signs (unless it is paused, which says so instead).
    pub quiet: bool,
    /// Why no heartbeat counts, when none does.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub no_signs: Option<NoSigns>,
}

/// How the error for preferences an agent wrote starts, in every reader
/// and in [`SecurityFlag::message`] (also in every `klavd` before the
/// flag): `klav proxy use` knows by it, before presence, that it is the
/// problem `use` repairs.
pub const PREFERENCES_BY_AGENT: &str = "the account's preferences were written by agent ";

/// A security problem the list carries instead of failing: the rows still
/// come from the verified chain, and no proxy is trusted. A caller shows it
/// as a security warning (the CLI exits 3), never as an ordinary one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SecurityFlag {
    /// An agent wrote the account's preferences, which no agent may write.
    /// Nothing in them is used: the list has no proxy, and every proxy's
    /// rows. `klav proxy use`, with presence, replaces them.
    PreferencesByAgent {
        /// The agent the server says wrote them.
        agent_id: AgentId,
    },
    /// A flag this build does not know (a newer `klavd`): still a security
    /// problem, never «all good».
    #[serde(other)]
    Unknown,
}

impl SecurityFlag {
    /// What to tell the person, and what to do.
    #[must_use]
    pub fn message(&self) -> String {
        match self {
            Self::PreferencesByAgent { agent_id } => format!(
                "{PREFERENCES_BY_AGENT}{agent_id}, and no agent may write them: no credential \
                 proxy is trusted until you set it again with `klav proxy use own <agent>` or \
                 `klav proxy use none`, which replaces them"
            ),
            Self::Unknown => {
                "the list carries a security problem this klav does not know: update klav".into()
            }
        }
    }
}

/// Which check refused the list, for a caller that says it in its own
/// words (the Mac app, through `klavd`'s `sandbox_list_checked`). The CLI
/// keeps printing [`ListRefusal::message`]. Read leniently: a check that
/// does not decode (a kind this build does not know, or a known kind
/// without its agent) is [`ListCheck::Unknown`], still a refusal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ListCheck {
    /// The account's proxy setting names an agent the server does not list
    /// among the account's agents: it would hide every sandbox of it.
    UnlistedProxy {
        /// The agent the setting names.
        agent_id: AgentId,
    },
    /// The server sent a heartbeat of the account's proxy that the proxy did
    /// not sign, or that is not a heartbeat.
    ProxyHeartbeat {
        /// The account's proxy.
        agent_id: AgentId,
    },
    /// The account's log did not verify: an event or a head that does not
    /// check, or a chain the server truncated or rewrote.
    Log,
    /// A check this build does not know (a newer `klavd`), or one that does
    /// not decode: still a refusal, said in general words.
    Unknown,
}

/// The checks this build reads by name; anything else is
/// [`ListCheck::Unknown`].
#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum KnownCheck {
    UnlistedProxy { agent_id: AgentId },
    ProxyHeartbeat { agent_id: AgentId },
    Log,
}

impl ListCheck {
    fn read(value: serde_json::Value) -> Self {
        match serde_json::from_value(value) {
            Ok(KnownCheck::UnlistedProxy { agent_id }) => Self::UnlistedProxy { agent_id },
            Ok(KnownCheck::ProxyHeartbeat { agent_id }) => Self::ProxyHeartbeat { agent_id },
            Ok(KnownCheck::Log) => Self::Log,
            Err(_) => Self::Unknown,
        }
    }
}

impl<'de> Deserialize<'de> for ListCheck {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        serde_json::Value::deserialize(d).map(Self::read)
    }
}

/// A list refused by one of its checks: which one, and the words the CLI
/// prints for it, the same [`Unlocked::sandbox_list_flagged`] fails with.
/// Read leniently, so that a refusal never fails to decode and leaves the
/// last list standing: without its check, or not even an object, it is
/// [`ListCheck::Unknown`]; without its words, they are empty.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ListRefusal {
    /// The check.
    pub check: ListCheck,
    /// `klav-client`'s words, in English.
    pub message: String,
}

impl<'de> Deserialize<'de> for ListRefusal {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let serde_json::Value::Object(mut fields) = serde_json::Value::deserialize(d)? else {
            return Ok(Self {
                check: ListCheck::Unknown,
                message: String::new(),
            });
        };
        Ok(Self {
            check: fields
                .remove("check")
                .map_or(ListCheck::Unknown, ListCheck::read),
            message: match fields.remove("message") {
                Some(serde_json::Value::String(message)) => message,
                _ => String::new(),
            },
        })
    }
}

impl ListRefusal {
    /// The error [`Unlocked::sandbox_list_flagged`] gives for it.
    #[must_use]
    pub fn into_error(self) -> ClientError {
        ClientError::Security(self.message)
    }
}

/// `klavd`'s answer to `sandbox_list_checked`: the list, or the check that
/// refused it. Both optional, so that an answer with neither (a newer
/// `klavd` that says it otherwise) is read as a refusal, never as a list.
/// A refusal is read first and wins: a `list` next to it that does not
/// decode is dropped, never an error that would leave the last list
/// standing. Without a refusal, `list` is read as strictly as ever.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct CheckedList {
    /// The list, when every check passed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub list: Option<SandboxList>,
    /// The check that refused it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refused: Option<ListRefusal>,
}

/// [`CheckedList`] without a refusal: the derived, strict reading.
#[derive(Deserialize)]
struct ListedAnswer {
    #[serde(default)]
    list: Option<SandboxList>,
}

impl<'de> Deserialize<'de> for CheckedList {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use serde::de::Error;
        let mut value = serde_json::Value::deserialize(d)?;
        let refused = value
            .as_object_mut()
            .and_then(|fields| fields.remove("refused"))
            .filter(|refused| !refused.is_null());
        if let Some(refused) = refused {
            let list = value
                .as_object_mut()
                .and_then(|fields| fields.remove("list"))
                .and_then(|list| serde_json::from_value(list).ok());
            return Ok(Self {
                list,
                refused: Some(ListRefusal::deserialize(refused).map_err(D::Error::custom)?),
            });
        }
        let ListedAnswer { list } = serde_json::from_value(value).map_err(D::Error::custom)?;
        Ok(Self {
            list,
            refused: None,
        })
    }
}

impl From<Result<SandboxList, ListRefusal>> for CheckedList {
    fn from(checked: Result<SandboxList, ListRefusal>) -> Self {
        match checked {
            Ok(list) => Self {
                list: Some(list),
                refused: None,
            },
            Err(refused) => Self {
                list: None,
                refused: Some(refused),
            },
        }
    }
}

/// Why [`assemble`] gave no list: a check that refused it, or any other
/// error.
#[derive(Debug)]
enum Refused {
    Check(ListRefusal),
    Error(ClientError),
}

impl From<ClientError> for Refused {
    fn from(e: ClientError) -> Self {
        Self::Error(e)
    }
}

/// A failure of the log's verification as the list's check, told by its
/// type ([`AuditError::Tampered`]), with the words the CLI prints for it.
/// Any other error (the network, the session) stays what it is.
fn log_refusal(e: AuditError) -> Result<ListRefusal, ClientError> {
    match e {
        AuditError::Tampered(_) => match ClientError::from(e) {
            ClientError::Security(message) => Ok(ListRefusal {
                check: ListCheck::Log,
                message,
            }),
            other => Err(other),
        },
        AuditError::Client(e) => Err(e),
    }
}

/// The person's list (ADR 0036 E2.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxList {
    /// The account's own proxy; absent without one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy: Option<ProxyView>,
    /// Every sandbox in the verified chain, of every proxy, oldest first.
    pub sandboxes: Vec<SandboxRow>,
    /// Events verified: the list holds every sandbox up to this one.
    pub verified_events: u64,
    /// What the verification could not check, without being tampering;
    /// a rollback of the heartbeat; and a marks file that could not be used.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    /// This device's heartbeat watermarks ([`SANDBOX_MARKS_FILE`]) could
    /// not be used (damaged, or of a newer version): the heartbeat was
    /// checked without them. Also in `warnings`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub marks_unreadable: bool,
    /// A security problem shown with the rows instead of failing; never in
    /// `warnings`. Only [`Unlocked::sandbox_list_flagged`] gives one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security: Option<SecurityFlag>,
}

impl SandboxList {
    /// The view the apps and the CLI show unless asked for every proxy
    /// (ADR 0036 E6.2, «los sandboxes del proxy de la cuenta»): only the
    /// rows of the account's proxy. Without one, every row stays, so a
    /// sandbox of a former proxy is not hidden from a list that has nothing
    /// else to show.
    #[must_use]
    pub fn of_account_proxy(mut self) -> Self {
        if let Some(proxy) = &self.proxy {
            let id = proxy.agent_id;
            self.sandboxes.retain(|r| r.proxy_id == id);
        }
        self
    }

    /// The rows the theft signal ended (a second claim with the right
    /// secret from another key), in the list's order: the order the
    /// sandboxes were issued, not the order they ended. A caller shows
    /// each as a security warning, also where it hides ended rows: the
    /// CLI's plain list and `klav proxy status` (ADR 0036 E2.1, E6.2).
    #[must_use]
    pub fn thefts(&self) -> Vec<&SandboxRow> {
        self.sandboxes.iter().filter(|r| r.is_theft()).collect()
    }
}

impl SandboxRow {
    /// Ended by the theft signal.
    #[must_use]
    pub fn is_theft(&self) -> bool {
        self.status == SandboxStatus::Ended && self.end_reason == Some(EndReason::Theft)
    }
}

/// Where a sandbox stands at `now`, by the chain alone. An end the proxy
/// logged wins over its revocation, which only says no end can follow.
fn status(r: &SandboxRecord, now: i64) -> SandboxStatus {
    if r.end.is_some() {
        SandboxStatus::Ended
    } else if r.proxy_revoked_at.is_some() {
        SandboxStatus::ProxyRevoked
    } else if r.revoked_by_person_at.is_some() {
        SandboxStatus::Revoking
    } else if r.expires_at <= now {
        SandboxStatus::Expired
    } else if r.claimed_at.is_some() {
        SandboxStatus::Active
    } else {
        SandboxStatus::Waiting
    }
}

impl Unlocked {
    /// The account's sandboxes as the verified chain shows them, with the
    /// last heartbeat of the account's proxy (ADR 0036 E2.1, E3.3).
    ///
    /// It takes this device's watermark first, then reads `GET /v1/sync`,
    /// then verifies the whole log, so the chain has every store reset
    /// logged before that heartbeat. The verification signs a new head, as
    /// `klav log verify` does.
    ///
    /// Fails like the verification on tampering, and with
    /// [`ClientError::Security`] on a heartbeat the proxy did not sign,
    /// when the server does not list the account's proxy among its agents
    /// (it would hide every sandbox of that proxy), or when an agent wrote
    /// the preferences. Preferences this device cannot read, or two items
    /// that disagree, are a warning: the rows of every proxy, without a
    /// proxy. A rollback of the heartbeat is not an error:
    /// [`NoSigns::Rollback`].
    ///
    /// What an older caller gets: [`Self::sandbox_list_flagged`] gives the
    /// rows with the flag instead, for a caller that shows it.
    pub async fn sandbox_list(&mut self) -> ClientResult<SandboxList> {
        let list = self.sandbox_list_flagged().await?;
        match &list.security {
            Some(flag) => Err(ClientError::Security(flag.message())),
            None => Ok(list),
        }
    }

    /// [`Self::sandbox_list`], except that preferences an agent wrote give
    /// the chain's rows of every proxy, no proxy, and
    /// [`SecurityFlag::PreferencesByAgent`] in `security`, which the caller
    /// must show as a security problem. Every other failure is the same.
    pub async fn sandbox_list_flagged(&mut self) -> ClientResult<SandboxList> {
        self.sandbox_list_checked()
            .await?
            .map_err(ListRefusal::into_error)
    }

    /// [`Self::sandbox_list_flagged`], with the check that refused the list
    /// apart ([`ListCheck`]): the log, the proxy's heartbeat, or a proxy
    /// the server does not list. Any other failure, a `Security` one
    /// included, is the outer error, as before.
    pub async fn sandbox_list_checked(&mut self) -> ClientResult<Result<SandboxList, ListRefusal>> {
        // The watermark as it stood before the request: a later one that
        // another process of this device stored meanwhile is no rollback.
        let before = {
            let _lock = self.home.lock()?;
            read_marks(&self.home, &self.local_key, &self.ctx)
        };
        let res = self.authed(Method::GET, "/v1/sync", &Body::Empty).await?;
        let state: SyncState = crate::api::json(res).await?;
        let (setting, security) = match self.read_preferences() {
            Ok(PreferencesRead::Read(p)) => (Ok(p.proxy()), None),
            // Nothing in them used: no proxy, and the flag instead of a warning.
            Ok(PreferencesRead::ByAgent(items)) => (
                Ok(ProxySetting::NONE),
                Some(match items.first() {
                    Some((_, agent_id)) => SecurityFlag::PreferencesByAgent {
                        agent_id: *agent_id,
                    },
                    None => SecurityFlag::Unknown,
                }),
            ),
            Err(e @ ClientError::Security(_)) => return Err(e),
            Err(e) => (Err(e.to_string()), None),
        };
        let (report, agents) = match self.verify_audit_with_agents().await {
            Ok(verified) => verified,
            Err(e) => return log_refusal(e).map(Err),
        };
        let mut notices = Vec::new();
        let pauses = self.checked_pauses(&state.agent_pauses, &mut notices);
        let assembled = assemble(&Fetched {
            setting,
            report: &report,
            agents: &agents,
            beats: &state.sandbox_state,
            pauses: &pauses,
            before: &before,
            now: now_ms(),
        });
        let (list, mark) = match assembled {
            Ok(assembled) => assembled,
            Err(Refused::Check(refusal)) => return Ok(Err(refusal)),
            Err(Refused::Error(e)) => return Err(e),
        };
        if let Some(mark) = mark {
            store_mark(&self.home, &self.local_key, &self.ctx, mark)?;
        }
        Ok(Ok(SandboxList { security, ..list }))
    }
}

/// What [`Unlocked::sandbox_list`] fetched, for [`assemble`].
struct Fetched<'a> {
    /// The account's proxy setting, or why it could not be read.
    setting: Result<ProxySetting, String>,
    /// The verified chain.
    report: &'a VerifyReport,
    /// The agents the chain was checked against: name and identity.
    agents: &'a HashMap<AgentId, (String, PublicIdentity)>,
    /// `sandbox_state` of `GET /v1/sync`.
    beats: &'a [SandboxState],
    /// The pauses this account signed.
    pauses: &'a [AgentPause],
    /// This device's watermarks as they stood before the request.
    before: &'a MarksRead,
    /// This device's clock.
    now: i64,
}

/// The list from what was fetched, and the watermark to store. Pure: no
/// I/O. Fails only with a check ([`ListCheck::UnlistedProxy`], or
/// [`ListCheck::ProxyHeartbeat`] for a heartbeat the proxy did not sign); a
/// rollback of the heartbeat is [`NoSigns::Rollback`] with a warning, never
/// an error.
fn assemble(f: &Fetched<'_>) -> Result<(SandboxList, Option<Mark>), Refused> {
    let now = f.now;
    let agents = f.agents;
    let name = |id: &AgentId| agents.get(id).map(|(n, _)| n.clone());
    let mut rows: Vec<SandboxRow> = f
        .report
        .sandboxes
        .iter()
        .map(|r| {
            let status = status(r, now);
            SandboxRow {
                sandbox_id: r.sandbox_id,
                proxy_id: r.proxy,
                issuer_id: r.issuer,
                issuer_name: name(&r.issuer),
                label: r.label.clone(),
                profiles: r.profiles.clone(),
                issued_at: r.issued_at,
                expires_at: r.expires_at,
                claimed_at: r.claimed_at,
                status,
                end_reason: r.end.map(|(reason, _)| reason.into()),
                ended_at: r.end.map(|(_, at)| at),
                revoked_by_person_at: r.revoked_by_person_at,
                proxy_revoked_at: r.proxy_revoked_at,
                connected: None,
                last_seen_at: None,
            }
        })
        .collect();
    let mut warnings = f.report.warnings.clone();
    let marks_unreadable = f.before.warning().is_some();
    warnings.extend(f.before.warning());
    let setting = match &f.setting {
        Ok(setting) => *setting,
        Err(why) => {
            warnings.push(format!(
                "the account's proxy setting cannot be read on this device ({why}): the list \
                 shows the sandboxes of every proxy, without the proxy's heartbeat"
            ));
            ProxySetting::NONE
        }
    };
    let (proxy, mark) = match (setting.mode, setting.agent_id) {
        (ProxyMode::Own, Some(proxy)) => {
            let Some((proxy_name, identity)) = agents.get(&proxy) else {
                return Err(Refused::Check(ListRefusal {
                    check: ListCheck::UnlistedProxy { agent_id: proxy },
                    message: format!(
                        "the account's proxy setting names agent {proxy}, which the server does \
                         not list among the account's agents, so its sandboxes cannot be shown: \
                         the server may be hiding it, or a device of the account named an agent \
                         the server does not have. Check `klav proxy status`, or set the proxy \
                         again with `klav proxy use`"
                    ),
                }));
            };
            let paused = crate::pause::holding(f.pauses, proxy, now).is_some();
            let (judged, mark) = beat_of(
                proxy,
                identity,
                f.beats,
                &f.report.store_epochs,
                f.before.marks(),
                now,
            )
            .map_err(|e| match e {
                // `check_heartbeat`'s only `Security`: not the proxy's, or
                // not a heartbeat.
                ClientError::Security(message) => Refused::Check(ListRefusal {
                    check: ListCheck::ProxyHeartbeat { agent_id: proxy },
                    message,
                }),
                e => Refused::Error(e),
            })?;
            if judged == Err(NoSigns::Rollback) {
                warnings.push(
                    "the server sent an older heartbeat of the proxy than this device has \
                     seen: it is not shown"
                        .to_owned(),
                );
            }
            let view = proxy_view(proxy, Some(proxy_name.clone()), paused, judged, &mut rows);
            (Some(view), mark)
        }
        _ => (None, None),
    };
    Ok((
        SandboxList {
            proxy,
            sandboxes: rows,
            verified_events: f.report.events,
            warnings,
            marks_unreadable,
            security: None,
        },
        mark,
    ))
}

/// A heartbeat that counts (`sent_at_ms`, its age, what it says of each
/// sandbox), or why none does.
type Judged = Result<(i64, i64, Vec<SandboxLink>), NoSigns>;

/// The heartbeat of `proxy` among `entries`, checked against the watermark
/// in `marks` for its current epoch: what it says, and the mark to store
/// when it counts and moves the watermark. A `seq` below the watermark is
/// [`NoSigns::Rollback`], and nothing to store.
fn beat_of(
    proxy: AgentId,
    identity: &PublicIdentity,
    entries: &[SandboxState],
    epochs: &[StoreEpoch],
    marks: &[Mark],
    now: i64,
) -> ClientResult<(Judged, Option<Mark>)> {
    let Some(found) = entries.iter().find(|s| s.proxy_id == proxy) else {
        return Ok((Err(NoSigns::NoHeartbeat), None));
    };
    let current = epochs.iter().find(|e| e.proxy == proxy);
    let watermark = marks
        .iter()
        .find(|m| current.is_some_and(|c| m.proxy == proxy && m.store_epoch == c.store_epoch))
        .map(|m| m.seq);
    let beat = match check_heartbeat(proxy, identity, epochs, &found.proof, watermark, now) {
        Ok(Ok(beat)) => beat,
        Ok(Err(why)) => return Ok((Err(why.into()), None)),
        Err(ClientError::Rollback(_)) => return Ok((Err(NoSigns::Rollback), None)),
        Err(e) => return Err(e),
    };
    let mark = (watermark != Some(beat.seq)).then(|| Mark {
        proxy,
        store_epoch: beat.store_epoch.clone(),
        epoch_seq: current.expect("checked").seq,
        seq: beat.seq,
    });
    Ok((Ok((beat.sent_at_ms, beat.age_ms, beat.sandboxes)), mark))
}

/// The proxy as the list shows it, and what its heartbeat says put on its
/// live rows. Quiet past [`NO_SIGNS_LIVE_MS`] when the proxy surely still
/// counts one of its sandboxes as live (so it beats every 5 minutes), past
/// [`NO_SIGNS_IDLE_MS`] otherwise, strictly; always without a heartbeat
/// that counts.
fn proxy_view(
    proxy: AgentId,
    name: Option<String>,
    paused: bool,
    judged: Judged,
    rows: &mut [SandboxRow],
) -> ProxyView {
    let live = rows
        .iter()
        .any(|r| r.proxy_id == proxy && r.status.proxy_counts_live());
    let limit = if live {
        NO_SIGNS_LIVE_MS
    } else {
        NO_SIGNS_IDLE_MS
    };
    match judged {
        Ok((sent_at, age, links)) => {
            attach(rows, proxy, &links);
            ProxyView {
                agent_id: proxy,
                name,
                paused,
                heartbeat_sent_at: Some(sent_at),
                heartbeat_age_ms: Some(age),
                quiet: age > limit,
                no_signs: None,
            }
        }
        Err(why) => ProxyView {
            agent_id: proxy,
            name,
            paused,
            heartbeat_sent_at: None,
            heartbeat_age_ms: None,
            quiet: true,
            no_signs: Some(why),
        },
    }
}

/// Puts what the heartbeat says on the live rows of `proxy` it names. A
/// sandbox it names that the chain does not show live is ignored.
fn attach(rows: &mut [SandboxRow], proxy: AgentId, links: &[SandboxLink]) {
    let by_id: HashMap<SandboxId, &SandboxLink> = links.iter().map(|l| (l.id, l)).collect();
    for row in rows
        .iter_mut()
        .filter(|r| r.proxy_id == proxy && r.status.is_live())
    {
        if let Some(link) = by_id.get(&row.sandbox_id) {
            row.connected = Some(link.connected);
            row.last_seen_at = link.last_seen_at;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(
        end: Option<SandboxEnd>,
        revoked: bool,
        claimed: bool,
        expires_at: i64,
    ) -> SandboxRecord {
        SandboxRecord {
            sandbox_id: SandboxId::generate(),
            proxy: AgentId::generate(),
            issuer: AgentId::generate(),
            label: "chat".into(),
            profiles: vec!["railway".into()],
            issued_at: 1,
            expires_at,
            claimed_at: claimed.then_some(2),
            end: end.map(|r| (r, 3)),
            revoked_by_person_at: revoked.then_some(2),
            proxy_revoked_at: None,
        }
    }

    /// The chain alone decides: an end first, then the person's
    /// revocation, then the expiry, then the claim.
    #[test]
    fn a_sandboxs_status_comes_from_the_chain() {
        let now = 100;
        for (r, want) in [
            (
                record(Some(SandboxEnd::Theft), true, true, 200),
                SandboxStatus::Ended,
            ),
            (record(None, true, true, 50), SandboxStatus::Revoking),
            (record(None, false, true, 100), SandboxStatus::Expired),
            (record(None, false, true, 200), SandboxStatus::Active),
            (record(None, false, false, 200), SandboxStatus::Waiting),
        ] {
            assert_eq!(status(&r, now), want);
        }
    }

    /// A revoked proxy's row, without an end, is `ProxyRevoked` whatever
    /// else stands (revoked by the person, expired, claimed, waiting); an
    /// end its proxy logged still wins.
    #[test]
    fn a_revoked_proxy_leaves_no_row_waiting_for_its_end() {
        let now = 100;
        let revoked = |mut r: SandboxRecord| {
            r.proxy_revoked_at = Some(4);
            r
        };
        for r in [
            record(None, true, true, 200),
            record(None, true, false, 50),
            record(None, false, true, 100),
            record(None, false, true, 200),
            record(None, false, false, 200),
        ] {
            assert_eq!(status(&revoked(r), now), SandboxStatus::ProxyRevoked);
        }
        assert_eq!(
            status(
                &revoked(record(Some(SandboxEnd::Person), true, true, 200)),
                now
            ),
            SandboxStatus::Ended
        );
        assert!(!SandboxStatus::ProxyRevoked.is_live());
        assert!(!SandboxStatus::ProxyRevoked.proxy_counts_live());
        // Its words on the socket and in `--json`, and what an older reader
        // that does not know them takes them for.
        assert_eq!(
            serde_json::to_value(SandboxStatus::ProxyRevoked).unwrap(),
            "proxy_revoked"
        );
    }

    fn row(status: SandboxStatus, proxy_id: AgentId) -> SandboxRow {
        SandboxRow {
            sandbox_id: SandboxId::generate(),
            proxy_id,
            issuer_id: AgentId::generate(),
            issuer_name: None,
            label: "chat".into(),
            profiles: vec![],
            issued_at: 1,
            expires_at: 2,
            claimed_at: None,
            status,
            end_reason: None,
            ended_at: None,
            revoked_by_person_at: None,
            proxy_revoked_at: None,
            connected: None,
            last_seen_at: None,
        }
    }

    /// Only the rows the theft signal ended, whatever else ended them or
    /// is still live.
    #[test]
    fn thefts_are_the_rows_the_theft_signal_ended() {
        let proxy = AgentId::generate();
        let mut theft = row(SandboxStatus::Ended, proxy);
        theft.end_reason = Some(EndReason::Theft);
        let mut stopped = row(SandboxStatus::Ended, proxy);
        stopped.end_reason = Some(EndReason::Stop);
        let mut unknown = row(SandboxStatus::Ended, proxy);
        unknown.end_reason = Some(EndReason::Unknown);
        // Never a live row, even with a reason it should not have.
        let mut live = row(SandboxStatus::Active, proxy);
        live.end_reason = Some(EndReason::Theft);
        let list = SandboxList {
            proxy: None,
            sandboxes: vec![stopped, theft.clone(), live, unknown],
            verified_events: 4,
            warnings: vec![],
            marks_unreadable: false,
            security: None,
        };
        let found: Vec<SandboxId> = list.thefts().iter().map(|r| r.sandbox_id).collect();
        assert_eq!(found, [theft.sandbox_id]);
    }

    /// A heartbeat signed by `keys` for `proxy` under `epoch`.
    fn signed_beat(
        keys: &klav_core::crypto::identity::IdentityKeyPair,
        proxy: AgentId,
        epoch: &Blob,
        seq: u64,
        sent_at_ms: i64,
    ) -> SandboxState {
        use klav_core::crypto::agent::{self, SignedRequest};
        let body = serde_json::to_vec(&klav_proto::sandbox::SandboxHeartbeat {
            v: klav_proto::sandbox::HEARTBEAT_VERSION,
            store_epoch: epoch.clone(),
            seq,
            sent_at_ms,
            sandboxes: vec![],
        })
        .unwrap();
        let nonce = [seq as u8; 16];
        let digest = agent::body_digest(&body);
        let path = klav_proto::sandbox::PATH_SANDBOX_STATE;
        let signature = agent::sign_request(
            keys,
            &SignedRequest {
                agent: proxy,
                method: "PUT",
                path,
                timestamp_ms: u64::try_from(sent_at_ms).unwrap(),
                nonce: &nonce,
                body_digest: &digest,
            },
        );
        SandboxState {
            proxy_id: proxy,
            proof: klav_proto::audit::AgentProof {
                method: "PUT".into(),
                path: path.into(),
                timestamp: sent_at_ms,
                nonce: Blob::new(nonce.to_vec()),
                body_digest: Blob::new(digest.to_vec()),
                body: Some(Blob::new(body)),
                signature: Blob::new(signature.to_bytes().to_vec()),
            },
            received_at: sent_at_ms,
        }
    }

    fn marks_home() -> (tempfile::TempDir, Home, LocalKey, LocalContext) {
        let dir = tempfile::tempdir().expect("tempdir");
        let home = Home::at(dir.path());
        let ctx = LocalContext {
            account: klav_core::ids::AccountId::generate(),
            device: klav_core::ids::DeviceId::generate(),
        };
        (dir, home, LocalKey::generate(), ctx)
    }

    fn epochs(proxy: AgentId, epoch: &Blob) -> Vec<StoreEpoch> {
        epochs_at(proxy, epoch, 1)
    }

    /// The chain's last store reset of `proxy`: `epoch`, at position `at`.
    fn epochs_at(proxy: AgentId, epoch: &Blob, at: u64) -> Vec<StoreEpoch> {
        vec![StoreEpoch {
            proxy,
            store_epoch: epoch.clone(),
            seq: at,
        }]
    }

    /// The watermark is stored, read back and moved by each heartbeat that
    /// counts; a store from another process with a lower `seq` for the same
    /// epoch leaves the higher one; a lower `seq` from the server is a
    /// rollback that does not move it; a new epoch replaces it.
    #[test]
    fn the_stored_watermark_is_read_back_kept_higher_and_holds_against_an_older_heartbeat() {
        let (_dir, home, key, ctx) = marks_home();
        let keys = klav_core::crypto::identity::IdentityKeyPair::generate();
        let proxy = AgentId::generate();
        let (one, two) = (Blob::new(vec![1; 16]), Blob::new(vec![2; 16]));
        let now = 1_800_000_000_000;
        let beat = |epoch: &Blob, seq: u64| {
            let marks = read_marks(&home, &key, &ctx);
            beat_of(
                proxy,
                keys.public(),
                &[signed_beat(&keys, proxy, epoch, seq, now)],
                // The second store's reset comes later in the chain.
                &epochs_at(proxy, epoch, if *epoch == two { 2 } else { 1 }),
                marks.marks(),
                now,
            )
            .unwrap()
        };
        assert_eq!(read_marks(&home, &key, &ctx), MarksRead::Marks(vec![]));
        for seq in [3, 5] {
            let (judged, mark) = beat(&one, seq);
            assert!(judged.is_ok());
            store_mark(&home, &key, &ctx, mark.expect("moves")).unwrap();
            assert_eq!(read_marks(&home, &key, &ctx).marks()[0].seq, seq);
        }
        // The same one again counts and stores nothing.
        let (judged, mark) = beat(&one, 5);
        assert!(judged.is_ok() && mark.is_none());
        // Another process stored a lower one meanwhile: the higher stays.
        let lower = Mark {
            proxy,
            store_epoch: one.clone(),
            epoch_seq: 1,
            seq: 4,
        };
        store_mark(&home, &key, &ctx, lower).unwrap();
        assert_eq!(read_marks(&home, &key, &ctx).marks()[0].seq, 5);
        // An older one from the server: no signs, nothing to store.
        assert_eq!(beat(&one, 4), (Err(NoSigns::Rollback), None));
        assert_eq!(read_marks(&home, &key, &ctx).marks()[0].seq, 5);
        // A new store: its seq starts over and replaces the mark.
        let (judged, mark) = beat(&two, 1);
        assert!(judged.is_ok());
        store_mark(&home, &key, &ctx, mark.expect("moves")).unwrap();
        let MarksRead::Marks(marks) = read_marks(&home, &key, &ctx) else {
            panic!("read");
        };
        assert_eq!(marks.len(), 1);
        assert_eq!((marks[0].store_epoch.clone(), marks[0].seq), (two, 1));
    }

    /// Two processes of one device (the CLI and `klavd`): one stores `seq`
    /// 7 while the other, which took the watermark (5) before its request,
    /// got 6. The 6 is judged against 5, so it is no false rollback, and
    /// storing it leaves the 7.
    #[test]
    fn two_processes_neither_raise_a_false_rollback_nor_lower_the_watermark() {
        let (_dir, home, key, ctx) = marks_home();
        let keys = klav_core::crypto::identity::IdentityKeyPair::generate();
        let proxy = AgentId::generate();
        let epoch = Blob::new(vec![1; 16]);
        let now = 1_800_000_000_000;
        let mark = |seq| Mark {
            proxy,
            store_epoch: epoch.clone(),
            epoch_seq: 1,
            seq,
        };
        store_mark(&home, &key, &ctx, mark(5)).unwrap();
        let before = read_marks(&home, &key, &ctx);
        store_mark(&home, &key, &ctx, mark(7)).unwrap();
        let (judged, stored) = beat_of(
            proxy,
            keys.public(),
            &[signed_beat(&keys, proxy, &epoch, 6, now)],
            &epochs(proxy, &epoch),
            before.marks(),
            now,
        )
        .unwrap();
        assert!(judged.is_ok(), "{judged:?}");
        store_mark(&home, &key, &ctx, stored.expect("moves past 5")).unwrap();
        assert_eq!(read_marks(&home, &key, &ctx).marks()[0].seq, 7);
    }

    /// A damaged marks file reads as none and is written again; one of a
    /// newer version reads as none and is never written.
    #[test]
    fn a_damaged_marks_file_is_rewritten_and_a_newer_one_is_left_alone() {
        let (_dir, home, key, ctx) = marks_home();
        let path = home.file(SANDBOX_MARKS_FILE);
        let mark = Mark {
            proxy: AgentId::generate(),
            store_epoch: Blob::new(vec![1; 16]),
            epoch_seq: 1,
            seq: 2,
        };
        crate::home::write_private(&path, b"not sealed").unwrap();
        assert_eq!(read_marks(&home, &key, &ctx), MarksRead::Damaged);
        assert!(MarksRead::Damaged.warning().is_some());
        store_mark(&home, &key, &ctx, mark.clone()).unwrap();
        assert_eq!(
            read_marks(&home, &key, &ctx),
            MarksRead::Marks(vec![mark.clone()])
        );
        let newer = seal_local_data(
            &key,
            &ctx,
            PURPOSE_SANDBOX_MARKS,
            br#"{"v":2,"marks":[],"later":1}"#,
        )
        .unwrap();
        crate::home::write_private(&path, &newer).unwrap();
        assert_eq!(read_marks(&home, &key, &ctx), MarksRead::Newer(2));
        assert!(
            MarksRead::Newer(2)
                .warning()
                .is_some_and(|w| w.contains("Update Klav"))
        );
        store_mark(&home, &key, &ctx, mark).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), newer, "never written");
        // A `v` of 1 with a field this version does not know is damaged.
        let odd = seal_local_data(
            &key,
            &ctx,
            PURPOSE_SANDBOX_MARKS,
            br#"{"v":1,"marks":[],"later":1}"#,
        )
        .unwrap();
        crate::home::write_private(&path, &odd).unwrap();
        assert_eq!(read_marks(&home, &key, &ctx), MarksRead::Damaged);
    }

    /// Only the heartbeat of the account's proxy counts, wherever it is in
    /// `sandbox_state`: another approved agent's, first in the list, is
    /// never read.
    #[test]
    fn only_the_proxys_own_heartbeat_counts() {
        let keys = klav_core::crypto::identity::IdentityKeyPair::generate();
        let other_keys = klav_core::crypto::identity::IdentityKeyPair::generate();
        let (proxy, other) = (AgentId::generate(), AgentId::generate());
        let epoch = Blob::new(vec![1; 16]);
        let now = 1_800_000_000_000;
        let entries = [
            signed_beat(&other_keys, other, &epoch, 9, now),
            signed_beat(&keys, proxy, &epoch, 2, now),
        ];
        let (judged, mark) = beat_of(
            proxy,
            keys.public(),
            &entries,
            &epochs(proxy, &epoch),
            &[],
            now,
        )
        .unwrap();
        assert!(judged.is_ok());
        assert_eq!(mark.expect("mark").seq, 2);
        let (judged, _) = beat_of(
            proxy,
            keys.public(),
            &entries[..1],
            &epochs(proxy, &epoch),
            &[],
            now,
        )
        .unwrap();
        assert_eq!(judged, Err(NoSigns::NoHeartbeat));
    }

    /// Quiet strictly past the threshold: 10 minutes when the proxy still
    /// counts one of its own sandboxes as live, 40 otherwise (another
    /// proxy's live sandbox, or only a revoking one, does not count).
    #[test]
    fn quiet_strictly_past_the_threshold_of_the_proxys_own_live_rows() {
        let proxy = AgentId::generate();
        let view = |status: SandboxStatus, of: AgentId, age: i64| {
            let mut rows = vec![row(status, of)];
            proxy_view(proxy, None, false, Ok((1, age, vec![])), &mut rows).quiet
        };
        assert!(!view(SandboxStatus::Active, proxy, NO_SIGNS_LIVE_MS));
        assert!(view(SandboxStatus::Active, proxy, NO_SIGNS_LIVE_MS + 1));
        assert!(view(SandboxStatus::Waiting, proxy, NO_SIGNS_LIVE_MS + 1));
        let elsewhere = AgentId::generate();
        assert!(!view(
            SandboxStatus::Active,
            elsewhere,
            NO_SIGNS_LIVE_MS + 1
        ));
        assert!(!view(SandboxStatus::Revoking, proxy, NO_SIGNS_LIVE_MS + 1));
        assert!(!view(SandboxStatus::Revoking, proxy, NO_SIGNS_IDLE_MS));
        assert!(view(SandboxStatus::Revoking, proxy, NO_SIGNS_IDLE_MS + 1));
        let mut rows = vec![];
        let none = proxy_view(proxy, None, true, Err(NoSigns::Rollback), &mut rows);
        assert!(none.quiet && none.paused);
        assert_eq!(none.no_signs, Some(NoSigns::Rollback));
    }

    /// The heartbeat speaks only of live sandboxes of its own proxy; one it
    /// names that the chain shows ended, or another proxy's, gets nothing.
    #[test]
    fn the_heartbeat_marks_only_live_rows_of_its_proxy() {
        let proxy = AgentId::generate();
        let mut rows = vec![
            row(SandboxStatus::Active, proxy),
            row(SandboxStatus::Ended, proxy),
            row(SandboxStatus::Active, AgentId::generate()),
            row(SandboxStatus::Expired, proxy),
        ];
        let links: Vec<SandboxLink> = rows
            .iter()
            .map(|r| SandboxLink {
                id: r.sandbox_id,
                connected: true,
                last_seen_at: Some(9),
            })
            .collect();
        attach(&mut rows, proxy, &links);
        let got: Vec<Option<bool>> = rows.iter().map(|r| r.connected).collect();
        assert_eq!(got, [Some(true), None, None, None]);
        assert_eq!(rows[0].last_seen_at, Some(9));
    }

    /// The default view keeps only the account's proxy's rows, in order;
    /// without a proxy it keeps every row.
    #[test]
    fn the_default_view_is_the_account_proxys_and_all_without_one() {
        let proxy = AgentId::generate();
        let other = AgentId::generate();
        let rows = vec![
            row(SandboxStatus::Active, other),
            row(SandboxStatus::Ended, proxy),
            row(SandboxStatus::Waiting, other),
            row(SandboxStatus::Active, proxy),
        ];
        let ids: Vec<SandboxId> = rows.iter().map(|r| r.sandbox_id).collect();
        let list = |with_proxy: bool| SandboxList {
            proxy: with_proxy
                .then(|| proxy_view(proxy, None, false, Err(NoSigns::NoHeartbeat), &mut [])),
            sandboxes: rows.clone(),
            verified_events: 7,
            warnings: vec![],
            marks_unreadable: false,
            security: None,
        };
        let mine = list(true).of_account_proxy();
        let got: Vec<SandboxId> = mine.sandboxes.iter().map(|r| r.sandbox_id).collect();
        assert_eq!(got, [ids[1], ids[3]]);
        assert_eq!(mine.verified_events, 7);
        let all = list(false).of_account_proxy();
        assert_eq!(all.sandboxes, rows);
    }

    /// The flag crosses as `{kind, …}`. A kind this build does not know is
    /// `Unknown` also with fields beside it, still a security problem; a
    /// flag without `kind` is no list at all, never a list without a flag.
    #[test]
    fn a_security_flag_crosses_typed_and_an_unknown_one_stays_a_problem() {
        let agent = AgentId::generate();
        let flag = SecurityFlag::PreferencesByAgent { agent_id: agent };
        let json = serde_json::to_value(&flag).expect("json");
        assert_eq!(
            json,
            serde_json::json!({"kind": "preferences_by_agent", "agent_id": agent})
        );
        assert_eq!(
            serde_json::from_value::<SecurityFlag>(json).expect("back"),
            flag
        );
        assert!(flag.message().contains(&agent.to_string()));
        assert!(flag.message().contains("klav proxy use"));
        let newer: SecurityFlag = serde_json::from_value(
            serde_json::json!({"kind": "keys_by_server", "agent_id": agent, "n": 2}),
        )
        .expect("a newer klavd's flag");
        assert_eq!(newer, SecurityFlag::Unknown);
        assert!(newer.message().contains("security problem"));
        let list = |security: serde_json::Value| {
            serde_json::from_value::<SandboxList>(serde_json::json!({
                "sandboxes": [], "verified_events": 1, "security": security,
            }))
        };
        assert!(list(serde_json::json!({"agent_id": agent})).is_err());
        assert_eq!(
            list(serde_json::json!({"kind": "new"}))
                .expect("list")
                .security,
            Some(SecurityFlag::Unknown)
        );
        // An older klavd's list has none: no problem to show.
        let older: SandboxList =
            serde_json::from_value(serde_json::json!({"sandboxes": [], "verified_events": 1}))
                .expect("older");
        assert_eq!(older.security, None);
    }

    /// The mark never goes back across epochs. Process A lists under E1
    /// (its reset at chain position 3) and gets `seq` 10; the proxy resets
    /// to E2 (position 20); process B lists and stores {E2, 1}; then A,
    /// late, stores {E1, 10}. The file keeps E2, so a heartbeat of E2 below
    /// B's is still a rollback. A later epoch still replaces it.
    #[test]
    fn a_mark_never_goes_back_to_an_earlier_epoch() {
        let (_dir, home, key, ctx) = marks_home();
        let keys = klav_core::crypto::identity::IdentityKeyPair::generate();
        let proxy = AgentId::generate();
        let (e1, e2, e3, e4) = (
            Blob::new(vec![1; 16]),
            Blob::new(vec![2; 16]),
            Blob::new(vec![3; 16]),
            Blob::new(vec![4; 16]),
        );
        let now = 1_800_000_000_000;
        let beat = |epoch: &Blob, at: u64, seq: u64, marks: &[Mark]| {
            beat_of(
                proxy,
                keys.public(),
                &[signed_beat(&keys, proxy, epoch, seq, now)],
                &epochs_at(proxy, epoch, at),
                marks,
                now,
            )
            .unwrap()
        };
        let (judged, a) = beat(&e1, 3, 10, &[]);
        assert!(judged.is_ok());
        let a = a.expect("A's mark");
        assert_eq!((a.epoch_seq, a.seq), (3, 10));
        let (_, b) = beat(&e2, 20, 2, &[]);
        store_mark(&home, &key, &ctx, b.expect("B's mark")).unwrap();
        store_mark(&home, &key, &ctx, a).unwrap();
        let stored = read_marks(&home, &key, &ctx);
        assert_eq!(
            stored
                .marks()
                .iter()
                .map(|m| (m.store_epoch.clone(), m.epoch_seq, m.seq))
                .collect::<Vec<_>>(),
            [(e2.clone(), 20, 2)]
        );
        assert_eq!(
            beat(&e2, 20, 1, stored.marks()),
            (Err(NoSigns::Rollback), None)
        );
        let (_, c) = beat(&e3, 31, 1, stored.marks());
        store_mark(&home, &key, &ctx, c.expect("a later epoch")).unwrap();
        let stored = read_marks(&home, &key, &ctx);
        assert_eq!(stored.marks()[0].store_epoch, e3);
        // A tie in `epoch_seq` between two epochs: the stored mark stays.
        let (_, d) = beat(&e4, 31, 9, stored.marks());
        store_mark(&home, &key, &ctx, d.expect("a tied epoch's mark")).unwrap();
        assert_eq!(
            read_marks(&home, &key, &ctx)
                .marks()
                .iter()
                .map(|m| (m.store_epoch.clone(), m.epoch_seq, m.seq))
                .collect::<Vec<_>>(),
            [(e3, 31, 1)]
        );
    }

    /// What the list makes of a fetch: the chain's rows, the account's
    /// proxy with its heartbeat, and the mark to store.
    struct Fetch {
        keys: klav_core::crypto::identity::IdentityKeyPair,
        proxy: AgentId,
        report: VerifyReport,
        agents: HashMap<AgentId, (String, PublicIdentity)>,
        epoch: Blob,
    }

    impl Fetch {
        fn new() -> Self {
            let keys = klav_core::crypto::identity::IdentityKeyPair::generate();
            let proxy = AgentId::generate();
            let epoch = Blob::new(vec![1; 16]);
            let mut mine = record(None, false, true, i64::MAX);
            mine.proxy = proxy;
            let report = VerifyReport {
                events: 9,
                sandboxes: vec![mine, record(None, false, false, i64::MAX)],
                store_epochs: epochs(proxy, &epoch),
                ..VerifyReport::default()
            };
            let agents = HashMap::from([(proxy, ("klav-proxy".to_owned(), keys.public().clone()))]);
            Self {
                keys,
                proxy,
                report,
                agents,
                epoch,
            }
        }

        fn assemble(
            &self,
            setting: Result<ProxySetting, String>,
            seq: u64,
            before: &MarksRead,
        ) -> Result<(SandboxList, Option<Mark>), Refused> {
            self.assemble_signed_by(&self.keys, setting, seq, before)
        }

        fn assemble_signed_by(
            &self,
            keys: &klav_core::crypto::identity::IdentityKeyPair,
            setting: Result<ProxySetting, String>,
            seq: u64,
            before: &MarksRead,
        ) -> Result<(SandboxList, Option<Mark>), Refused> {
            let now = 1_800_000_000_000;
            assemble(&Fetched {
                setting,
                report: &self.report,
                agents: &self.agents,
                beats: &[signed_beat(keys, self.proxy, &self.epoch, seq, now)],
                pauses: &[],
                before,
                now,
            })
        }
    }

    /// A heartbeat older than this device's mark is a rollback the list
    /// shows, never its error: the chain's rows stay, the proxy has no
    /// signs with a warning, and the mark does not move.
    #[test]
    fn a_rolled_back_heartbeat_is_shown_as_no_signs_not_an_error() {
        let f = Fetch::new();
        let own = Ok(ProxySetting::own(f.proxy));
        let before = MarksRead::Marks(vec![Mark {
            proxy: f.proxy,
            store_epoch: f.epoch.clone(),
            epoch_seq: 1,
            seq: 5,
        }]);
        let (list, mark) = f.assemble(own.clone(), 4, &before).expect("a list");
        assert_eq!(list.sandboxes.len(), 2);
        assert_eq!(list.verified_events, 9);
        let proxy = list.proxy.expect("the proxy");
        assert_eq!(proxy.no_signs, Some(NoSigns::Rollback));
        assert!(proxy.quiet);
        assert!(
            list.warnings.iter().any(|w| w.contains("older heartbeat")),
            "{:?}",
            list.warnings
        );
        assert_eq!(mark, None);
        // The next one counts and moves the mark.
        let (list, mark) = f.assemble(own, 6, &before).expect("a list");
        assert_eq!(list.proxy.expect("the proxy").no_signs, None);
        assert_eq!(mark.expect("moves").seq, 6);
    }

    /// Preferences that cannot be read do not fail the list: the rows of
    /// every proxy, no proxy, a warning. A setting that names an agent the
    /// server does not list is still a security error.
    #[test]
    fn unreadable_preferences_list_every_proxy_without_one() {
        let f = Fetch::new();
        let empty = MarksRead::Marks(vec![]);
        let (list, mark) = f
            .assemble(Err("two items disagree".into()), 1, &empty)
            .expect("a list");
        assert_eq!(list.proxy, None);
        assert_eq!(mark, None);
        assert_eq!(list.sandboxes.len(), 2);
        assert!(
            list.warnings
                .iter()
                .any(|w| w.contains("cannot be read") && w.contains("two items disagree")),
            "{:?}",
            list.warnings
        );
        let named = AgentId::generate();
        let unlisted = f.assemble(Ok(ProxySetting::own(named)), 1, &empty);
        let Err(Refused::Check(refusal)) = unlisted else {
            panic!("{unlisted:?}");
        };
        assert_eq!(refusal.check, ListCheck::UnlistedProxy { agent_id: named });
        // The CLI's words stay exactly what they were.
        assert_eq!(
            refusal.message,
            format!(
                "the account's proxy setting names agent {named}, which the server does not list \
                 among the account's agents, so its sandboxes cannot be shown: the server may be \
                 hiding it, or a device of the account named an agent the server does not have. \
                 Check `klav proxy status`, or set the proxy again with `klav proxy use`"
            )
        );
        assert!(matches!(
            refusal.into_error(),
            ClientError::Security(m) if m.contains("a device of the account")
        ));
    }

    /// A heartbeat of the account's proxy that another key signed refuses
    /// the list with its own check, and `klav-client`'s words.
    #[test]
    fn a_heartbeat_the_proxy_did_not_sign_is_its_own_check() {
        let f = Fetch::new();
        let other = klav_core::crypto::identity::IdentityKeyPair::generate();
        let empty = MarksRead::Marks(vec![]);
        let refused = f.assemble_signed_by(&other, Ok(ProxySetting::own(f.proxy)), 1, &empty);
        let Err(Refused::Check(refusal)) = refused else {
            panic!("{refused:?}");
        };
        assert_eq!(
            refusal.check,
            ListCheck::ProxyHeartbeat { agent_id: f.proxy }
        );
        assert!(
            refusal.message.starts_with("proxy heartbeat: "),
            "{}",
            refusal.message
        );
    }

    /// Every error of a log that does not verify is the log's check, told by
    /// its type; any other error, a `Security` one included, stays what it
    /// is, even with the log's words.
    #[test]
    fn a_log_that_does_not_verify_is_its_own_check() {
        let tampered = crate::audit::tampered("event 3 was rewritten".into());
        let refusal = log_refusal(tampered).expect("the log's check");
        assert_eq!(refusal.check, ListCheck::Log);
        assert_eq!(refusal.message, "audit log: event 3 was rewritten");
        assert!(matches!(
            log_refusal(ClientError::Security("an identity changed".into()).into()),
            Err(ClientError::Security(_))
        ));
        assert!(matches!(
            log_refusal(ClientError::Security("audit log: not from the verifier".into()).into()),
            Err(ClientError::Security(_))
        ));
        assert!(matches!(
            log_refusal(ClientError::Network("offline".into()).into()),
            Err(ClientError::Network(_))
        ));
    }

    /// The checks cross typed; one this build does not know, with fields
    /// it does not know either, reads as `unknown`; and an answer with
    /// neither a list nor a refusal has no list.
    #[test]
    fn a_check_crosses_typed_and_an_unknown_one_is_still_a_refusal() {
        let agent = AgentId::generate();
        let refusal = ListRefusal {
            check: ListCheck::UnlistedProxy { agent_id: agent },
            message: "m".into(),
        };
        let json = serde_json::to_value(CheckedList::from(Err(refusal.clone()))).expect("json");
        assert_eq!(
            json,
            serde_json::json!({"refused": {"check": {"kind": "unlisted_proxy", "agent_id": agent}, "message": "m"}})
        );
        assert_eq!(
            serde_json::from_value::<CheckedList>(json)
                .expect("back")
                .refused,
            Some(refusal)
        );
        for (kind, check) in [
            (
                "proxy_heartbeat",
                ListCheck::ProxyHeartbeat { agent_id: agent },
            ),
            ("log", ListCheck::Log),
        ] {
            let json = serde_json::json!({"kind": kind, "agent_id": agent});
            assert_eq!(
                serde_json::from_value::<ListCheck>(json).expect(kind),
                check
            );
        }
        let newer: CheckedList = serde_json::from_value(serde_json::json!({
            "refused": {"check": {"kind": "keys_by_server", "n": 2}, "message": "m", "more": 1},
            "also": true,
        }))
        .expect("a newer klavd's refusal");
        assert_eq!(newer.refused.expect("refused").check, ListCheck::Unknown);
        let neither: CheckedList = serde_json::from_value(serde_json::json!({})).expect("empty");
        assert_eq!(neither, CheckedList::default());

        // A refusal that does not decode is still a refusal, never an error
        // that would leave the last list standing.
        let unknown = |message: &str| ListRefusal {
            check: ListCheck::Unknown,
            message: message.into(),
        };
        for (refused, expected) in [
            (
                serde_json::json!({"check": {"kind": "log"}}),
                ListRefusal {
                    check: ListCheck::Log,
                    message: String::new(),
                },
            ),
            (
                serde_json::json!({"check": {"kind": "unlisted_proxy"}, "message": "m"}),
                unknown("m"),
            ),
            (
                serde_json::json!({"check": {"kind": "proxy_heartbeat", "agent_id": "not-a-uuid"}, "message": "m"}),
                unknown("m"),
            ),
            (
                serde_json::json!({"check": "log", "message": 7}),
                unknown(""),
            ),
            (serde_json::json!({"message": "m"}), unknown("m")),
            (serde_json::json!("refused"), unknown("")),
            (serde_json::json!([1, 2]), unknown("")),
        ] {
            let answer: CheckedList =
                serde_json::from_value(serde_json::json!({ "refused": refused }))
                    .unwrap_or_else(|e| panic!("{refused}: {e}"));
            assert_eq!(answer.refused, Some(expected), "{refused}");
        }

        // A refusal wins over a list next to it that does not decode: the
        // list is dropped, never an error that keeps the last one.
        let log = ListRefusal {
            check: ListCheck::Log,
            message: "audit log: x".into(),
        };
        for list in [serde_json::json!({"sandboxes": 7}), serde_json::json!("x")] {
            let answer: CheckedList = serde_json::from_value(serde_json::json!({
                "list": list,
                "refused": {"check": {"kind": "log"}, "message": "audit log: x"},
            }))
            .unwrap_or_else(|e| panic!("{list}: {e}"));
            assert_eq!(answer.refused, Some(log.clone()), "{list}");
            assert_eq!(answer.list, None, "{list}");
        }
        // Without a refusal the list is as strict as ever: a malformed one
        // is an error, never an empty list; `"refused": null` is no refusal.
        for list in [serde_json::json!({"sandboxes": 7}), serde_json::json!("x")] {
            assert!(
                serde_json::from_value::<CheckedList>(serde_json::json!({"list": list})).is_err()
            );
            assert!(
                serde_json::from_value::<CheckedList>(
                    serde_json::json!({"list": list, "refused": null})
                )
                .is_err()
            );
        }
        assert!(serde_json::from_value::<CheckedList>(serde_json::json!("x")).is_err());
        let healthy: CheckedList = serde_json::from_value(serde_json::json!({
            "list": {"sandboxes": [], "verified_events": 2},
            "refused": null,
        }))
        .expect("a healthy answer");
        assert_eq!(healthy.refused, None);
        assert_eq!(healthy.list.expect("list").verified_events, 2);
    }

    /// A status, an end reason and a «no signs» reason this build does not
    /// know (from a newer `klavd`) read as `unknown`, and an unknown
    /// status fails closed: live, never ended, and the proxy's 10-minute
    /// threshold applies.
    #[test]
    fn what_this_build_does_not_know_reads_as_unknown_and_fails_closed() {
        let proxy = AgentId::generate();
        let mut known = serde_json::to_value(row(SandboxStatus::Active, proxy)).unwrap();
        known["status"] = "parked".into();
        known["end_reason"] = "recycled".into();
        let row: SandboxRow = serde_json::from_value(known).expect("a newer klavd's row");
        assert_eq!(row.status, SandboxStatus::Unknown);
        assert_eq!(row.end_reason, Some(EndReason::Unknown));
        assert!(row.status.is_live() && row.status != SandboxStatus::Ended);
        let why: NoSigns = serde_json::from_value("asleep".into()).expect("no signs");
        assert_eq!(why, NoSigns::Unknown);
        let mut rows = vec![row];
        let view = proxy_view(
            proxy,
            None,
            false,
            Ok((1, NO_SIGNS_LIVE_MS + 1, vec![])),
            &mut rows,
        );
        assert!(view.quiet);
        // Every reason the proxy logs keeps its name.
        for e in [
            SandboxEnd::Theft,
            SandboxEnd::PersonLocal,
            SandboxEnd::IssuerRemoved,
        ] {
            assert_eq!(
                serde_json::to_value(EndReason::from(e)).unwrap(),
                serde_json::to_value(e).unwrap()
            );
        }
    }
}
