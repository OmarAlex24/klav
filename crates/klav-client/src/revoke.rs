//! Revoking an agent, the "what it saw" report and project key rotation
//! (design §5, ADR 0014 §7).

use std::collections::{BTreeMap, BTreeSet};

use klav_core::crypto::agent::{self, GrantToSign};
use klav_core::crypto::context::{ItemContext, ProjectContext};
use klav_core::crypto::identity::PublicIdentity;
use klav_core::crypto::keys::{LocalKey, ProjectKey};
use klav_core::crypto::local::{LocalContext, open_local_data, seal_local_data};
use klav_core::crypto::sign::{SIGNATURE_LEN, Signature};
use klav_core::crypto::wrap::{unwrap_item_key, wrap_item_key, wrap_project_key};
use klav_core::ids::{AccountId, AgentId, ItemId, ProjectId, VaultId};
use klav_core::model::seal_project_meta;
use klav_proto::Blob;
use klav_proto::agent::{AgentInfo, AgentStatus, RevokeAgent};
use klav_proto::vault::{Project, ProjectKeys, RotateProject, WrappedItemKey};
use reqwest::Method;
use serde::{Deserialize, Serialize};

use crate::agents::{AgentView, GrantedProjectView};
use crate::api::Body;
use crate::audit::{LogFilter, log_unreadable};
use crate::error::{ClientError, ClientResult};
use crate::home::{Home, write_private};
use crate::session::{Unlocked, now_ms};

/// `$KLAV_HOME/revocations.bin`: the key changes this device still owes,
/// and what it signed for each agent (ADR 0033, amendment of 2026-11-10,
/// F4 and the reviews of #292, #293 and #297). Sealed with the local key
/// (spec §12.2, purpose `revocations`). Kept apart from `cache.bin`, which
/// still holds each revocation's projects and the ones already rotated:
/// `cache.bin` keeps its version, so a klav, `klavd` or app from before
/// this file still reads it. An older klav that finishes a rotation writes
/// only `cache.bin`, and this file then shows nothing left.
///
/// A file that is here and does not open is an error, never "nothing
/// pending": it may hold a key change the person asked for.
///
/// How the layout evolves (spec §12.2): every change to it bumps `v`, and
/// within one `v` the schema stays closed (`deny_unknown_fields`), so a
/// reader never drops what it does not understand on a rewrite. A reader
/// reads `v` alone first: a newer one is [`ClientError::NewerFormat`],
/// which says to update Klav and leaves the file untouched; "move it
/// aside" is only for a file that does not open, or does not parse at a
/// `v` it knows.
pub const REVOCATIONS_FILE: &str = "revocations.bin";
/// Why a project's key change is skipped: it can never come back (a sync
/// never brings a deleted project back).
const PROJECT_DELETED: &str = "the project was deleted";
/// Why a key change is skipped while its vault is not listed.
const VAULT_UNLISTED: &str = "the server no longer lists its vault (deleted, purged, or access lost); if it comes back, its key change shows as pending again";
/// Why a key change is skipped while its vault is deleted.
const VAULT_DELETED: &str =
    "its vault is deleted; if it is restored, its key change shows as pending again";
/// The `last_error` `klavd` writes when its steps stop making progress
/// (`Unlocked::note_no_progress`): fixed words, no name in them.
const NO_PROGRESS: &str =
    "it made no progress in two steps in a row; it tries again at the next unlock";
/// The purpose of [`REVOCATIONS_FILE`]'s sealing (spec §12.2).
const PURPOSE_REVOCATIONS: &str = "revocations";
/// Format of [`REVOCATIONS_FILE`]'s contents.
const REVOCATIONS_VERSION: u32 = 1;

/// [`REVOCATIONS_FILE`]'s contents. Every field after `agents` is optional,
/// so a file written before them still opens.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RevocationsFile {
    v: u32,
    /// Revocations with something left: the key change the person asked
    /// for, or items granted one by one still without a new key.
    #[serde(default)]
    agents: BTreeMap<AgentId, RotationProgress>,
    /// Key changes of projects taken away from an active agent
    /// (`rotate_removed`): not a revocation, so never in `cache.bin`'s
    /// revocations, which mean "never grant again".
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    narrowed: BTreeMap<AgentId, Narrowing>,
    /// What this device signed for each agent: a server that serves an
    /// older grant, or cuts the log short, cannot take a project out of a
    /// later key change.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    signed: BTreeMap<AgentId, SignedGrants>,
}

impl RevocationsFile {
    fn is_empty(&self) -> bool {
        self.agents.is_empty() && self.narrowed.is_empty() && self.signed.is_empty()
    }
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_true(b: &bool) -> bool {
    *b
}

fn yes() -> bool {
    true
}

/// A revocation with something left (its presence in the file is the mark).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RotationProgress {
    /// The agent's name when it was revoked (the agent's own words).
    name: String,
    /// The person asked to change its projects' keys. Without it, only
    /// `items` are left, and no project's key ever changes for it (P7).
    #[serde(default = "yes", skip_serializing_if = "is_true")]
    rotate: bool,
    /// Projects already rotated whose other agents still need a grant
    /// with the new key.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    regrants: BTreeSet<ProjectId>,
    /// This device could not tell which projects the agent had.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    unknown: bool,
    /// The audit log, which lists every project the agent was granted,
    /// could not be read or does not hold the last grant this device
    /// signed: never done until a later step reads it (T189).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    log_unchecked: bool,
    /// Items granted one by one whose key still has to change, or whose
    /// holders still need a grant with the new key (ADR 0036 §18).
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    items: BTreeSet<ItemId>,
    /// What stopped the last step.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_error: Option<String>,
}

/// What a revocation still has to rotate, from this device's record of it
/// ([`Unlocked::projects_left`]).
struct ProjectsLeft {
    /// The next project to rotate.
    next: Option<ProjectId>,
    /// Those whose key cannot change because they are gone
    /// (`vault/project: why`).
    skipped: Vec<String>,
    /// One of the gone ones can come back (a vault no longer listed).
    may_return: bool,
}

impl RotationProgress {
    /// The key change is over once its items' keys changed: it was declined
    /// (P7), or it was asked and owes nothing else. That is no project left
    /// to rotate or that may come back, no grant to issue again, and
    /// nothing unknown or unread. Both a step ([`Unlocked::rotation_step`])
    /// and the revocation run again ([`Unlocked::revoke_first`]) finish an
    /// entry on this alone.
    fn over(&self, left: &ProjectsLeft) -> bool {
        !self.rotate
            || (left.next.is_none()
                && !left.may_return
                && self.regrants.is_empty()
                && !self.unknown
                && !self.log_unchecked)
    }
}

/// The key change of projects taken away from an active agent
/// (`rotate_removed`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Narrowing {
    /// The agent's name when its grant changed (the agent's own words).
    name: String,
    /// The projects taken away whose key changes.
    projects: BTreeSet<ProjectId>,
    /// Those whose key already changed.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    rotated: BTreeSet<ProjectId>,
    /// Rotated projects whose other agents still need a grant with the
    /// new key.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    regrants: BTreeSet<ProjectId>,
    /// What stopped the last step.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_error: Option<String>,
}

/// What this device signed for one agent.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedGrants {
    /// Every project of every grant this device signed for it, written
    /// before the grant goes to the server.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    projects: BTreeSet<ProjectId>,
    /// Every item of every grant this device signed for it (a proxy's
    /// per-item grant, ADR 0036 §18), written before the grant goes to the
    /// server: a later revocation changes their keys whatever grant the
    /// server serves.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    items: BTreeSet<ItemId>,
    /// The version of the last grant from this device that the server
    /// took, written after it took it: the log must hold it.
    #[serde(default)]
    version: u64,
}

/// A key change this device still owes (F4 `agent_revocations`): a
/// revocation's, or a narrowing's.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingRevocation {
    /// The agent.
    pub agent_id: AgentId,
    /// Its name when it was revoked (the agent's own words, T136).
    pub name: String,
    /// Every project whose key changes (`vault/project`): for a
    /// revocation, every project whose key it held; none when only items
    /// are left.
    pub projects: Vec<String>,
    /// Those already rotated.
    #[serde(default)]
    pub rotated: Vec<String>,
    /// Those still to rotate, in order.
    #[serde(default)]
    pub pending: Vec<String>,
    /// Rotated projects whose other agents still need a new grant.
    #[serde(default)]
    pub regrants: Vec<String>,
    /// This device does not know which projects the agent had: it never
    /// says "done" (T189).
    #[serde(default)]
    pub unknown_projects: bool,
    /// The agent is active, and this is the key change of projects taken
    /// away from it (`rotate_removed`), not a revocation.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub narrowed: bool,
    /// Items granted one by one still without a new key.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub items: usize,
    /// The audit log has not been read for this key change yet (T189).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub log_unchecked: bool,
    /// A revocation without the key change: only the keys of items granted
    /// one by one change, never a project's, so nothing here may read as
    /// "every key changed" (fifth re-check, 1).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub without_key_change: bool,
    /// Projects and items whose key cannot change from this device, and
    /// why (`vault/project: why`, `item <id>: why`): a deleted vault or
    /// project, one this account no longer holds, or an item this device
    /// no longer sees. They do not keep it from being done; one that comes
    /// back shows in `pending` (or `items`) again.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub skipped: Vec<String>,
    /// What stopped the last step.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_zero(n: &usize) -> bool {
    *n == 0
}

impl PendingRevocation {
    /// Something here is worth showing: work left, projects nobody knows,
    /// or projects skipped (so nothing says every key changed).
    fn shows(&self) -> bool {
        self.unknown_projects
            || !self.pending.is_empty()
            || !self.regrants.is_empty()
            || self.items > 0
            || self.log_unchecked
            || !self.skipped.is_empty()
    }

    /// Something here can still move without the person: `klavd` resumes it
    /// at unlock (P11). Unknown projects wait for the person (T189); skipped
    /// ones alone are done.
    #[must_use]
    pub fn needs_work(&self) -> bool {
        !self.unknown_projects
            && (!self.pending.is_empty()
                || !self.regrants.is_empty()
                || self.items > 0
                || self.log_unchecked)
    }
}

/// What one [`Unlocked::rotation_step`] did.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationStep {
    /// The agent.
    pub agent_id: AgentId,
    /// The project whose key rotated in this step.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotated: Option<RotationReport>,
    /// Items granted one by one whose key changed in this step.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rekeyed: Vec<ItemId>,
    /// Other agents that got a new grant in this step.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub regranted: Vec<String>,
    /// Other agents whose grant could not be issued again (`name: why`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub not_regranted: Vec<String>,
    /// Projects and items whose key cannot change from this device
    /// (`vault/project: why`, `item <id>: why`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub skipped: Vec<String>,
    /// What stopped this step.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failed: Option<String>,
    /// Nothing is left of the key change.
    pub done: bool,
}

impl RotationStep {
    fn new(agent_id: AgentId) -> Self {
        Self {
            agent_id,
            rotated: None,
            rekeyed: Vec::new(),
            regranted: Vec::new(),
            not_regranted: Vec::new(),
            skipped: Vec::new(),
            failed: None,
            done: false,
        }
    }
}

/// What an agent obtained from one item, according to the audit log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeenItem {
    /// Item ID.
    pub item_id: ItemId,
    /// Reference, if this device still sees the item.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
    /// Permissions it used and were allowed (`fill`, `reveal`, `update`…).
    pub permissions: Vec<String>,
    /// Whether it obtained a secret value: an allowed `fill`, `inject`,
    /// `totp` or `reveal` of an item that has text secrets (or that this
    /// device cannot open), or an attachment delivered (ADR 0016).
    pub secret: bool,
    /// Attachments delivered to it (deliveries, not distinct files).
    #[serde(default)]
    pub attachments: u64,
    /// Allowed uses.
    pub uses: u64,
    /// First and last use (Unix ms).
    pub first_at: i64,
    /// Last use (Unix ms).
    pub last_at: i64,
    /// The item is in the trash now.
    #[serde(default)]
    pub trashed: bool,
    /// The item no longer exists on this device (purged, or this device
    /// cannot see it).
    #[serde(default)]
    pub deleted: bool,
}

/// "What it saw": the projects whose keys it held and what the audit log
/// says it used.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Exposure {
    /// The agent.
    pub agent: AgentView,
    /// Projects whose keys it received (it could read the titles,
    /// usernames and URLs of their items).
    pub projects: Vec<GrantedProjectView>,
    /// Items it used, most recent first.
    pub items: Vec<SeenItem>,
    /// Denied attempts.
    pub denied: u64,
    /// Why `items` and `denied` are empty: the audit log could not be
    /// read as this device holds it (a server whose chain no longer
    /// matches this device's copy, ADR 0033 §8.4). The projects still come
    /// from the grant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_warning: Option<String>,
    /// `projects` is empty because this device cannot tell which projects
    /// the agent held (a grant it cannot verify and a log it cannot read),
    /// not because it held none. Revoking with the key change still asks
    /// `klavd` to look for them.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub projects_unknown: bool,
}

impl Exposure {
    /// What the grant alone says: its projects, and no item.
    fn of_grant(agent: AgentView, log_warning: Option<String>) -> Self {
        Self {
            projects: agent
                .grant
                .as_ref()
                .map(|g| g.projects.clone())
                .unwrap_or_default(),
            agent,
            items: Vec::new(),
            denied: 0,
            log_warning,
            projects_unknown: false,
        }
    }
}

/// The projects whose keys an agent held, as [`Unlocked::projects_held`]
/// finds them.
struct Held {
    projects: BTreeSet<ProjectId>,
    /// The items granted to it one by one: the grant the server sends,
    /// every grant this device signed and, with the log, every logged one;
    /// then those an earlier run left owed ([`Unlocked::revoke_first`]).
    items: BTreeSet<ItemId>,
    /// Some data could tell: a verified grant, an agent never approved, or
    /// a granted event in the log.
    known: bool,
    /// The log was asked and could not be read: a project may be missing.
    log_failed: bool,
}

/// Which key change a step works on.
#[derive(Debug, Clone, Copy)]
enum Owed {
    /// A revocation's ([`RevocationsFile::agents`]).
    Revoked,
    /// A narrowing's ([`RevocationsFile::narrowed`]).
    Narrowed,
}

/// What a grant this account signed names, read loosely.
struct SignedFound {
    projects: BTreeSet<ProjectId>,
    items: BTreeSet<ItemId>,
    version: u64,
}

/// What the log chain the server presents says the account granted an
/// agent, from events whose account signature checks out.
#[derive(Debug, Default)]
struct LogGrants {
    projects: BTreeSet<ProjectId>,
    items: BTreeSet<ItemId>,
    versions: BTreeSet<u64>,
}

/// Why the log cannot be taken as complete for an agent: it does not hold
/// the last grant this device signed for it (the server may have ended
/// the chain before it).
fn log_misses_signed(signed: Option<&SignedGrants>, found: &LogGrants) -> Option<String> {
    let version = signed.map_or(0, |s| s.version);
    (version > 0 && !found.versions.contains(&version)).then(|| {
        format!(
            "the audit log the server sent does not hold grant version {version}, which this device signed for the agent: the server may have cut it short, and a project granted later could be missing"
        )
    })
}

/// Why item `item`'s key cannot change: this device does not see it any
/// more. It is said, never taken for changed (third re-check, F2), and it
/// stays written down, so it changes if it comes back (fifth re-check, 2).
fn item_unseen(item: ItemId) -> String {
    format!("item {item}: this device no longer sees it (purged, or the server stopped sending it)")
}

/// [`REVOCATIONS_FILE`] is here and cannot be read.
fn unreadable_record(why: &str) -> ClientError {
    ClientError::Corrupt(format!(
        "revocations.bin, which holds the key changes still owed and the grants this device signed, cannot be read ({why}). Klav does not overwrite it. Moving it aside starts a new record; then revoke again, with the key change, every agent whose key change had not finished"
    ))
}

/// [`REVOCATIONS_FILE`] in `home`, or an empty record when there is none.
/// One that is here and does not read, open or parse is an error the
/// person sees: it may hold a key change they asked for, and is never
/// overwritten. One of a newer format is [`ClientError::NewerFormat`].
fn load_record(home: &Home, key: &LocalKey, ctx: &LocalContext) -> ClientResult<RevocationsFile> {
    /// Only the format, read before the rest: a newer layout may not parse
    /// as this one.
    #[derive(Deserialize)]
    struct Format {
        v: u32,
    }
    let blob = match std::fs::read(home.file(REVOCATIONS_FILE)) {
        Ok(blob) => blob,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(RevocationsFile {
                v: REVOCATIONS_VERSION,
                ..RevocationsFile::default()
            });
        }
        Err(e) => return Err(unreadable_record(&e.to_string())),
    };
    let json = open_local_data(key, ctx, PURPOSE_REVOCATIONS, &blob)
        .map_err(|_| unreadable_record("it does not open with this device's key"))?;
    let format: Format =
        serde_json::from_slice(&json).map_err(|e| unreadable_record(&e.to_string()))?;
    if format.v > REVOCATIONS_VERSION {
        return Err(ClientError::NewerFormat(format!(
            "revocations.bin (format {}), which holds the key changes still owed and the grants this device signed,",
            format.v
        )));
    }
    if format.v != REVOCATIONS_VERSION {
        return Err(unreadable_record(&format!(
            "format {} is not one this klav reads",
            format.v
        )));
    }
    serde_json::from_slice(&json).map_err(|e| unreadable_record(&e.to_string()))
}

/// Reads [`REVOCATIONS_FILE`], changes it and writes it back. A file that
/// does not load is never written.
fn update_record<R>(
    home: &Home,
    key: &LocalKey,
    ctx: &LocalContext,
    change: impl FnOnce(&mut RevocationsFile) -> R,
) -> ClientResult<R> {
    let mut file = load_record(home, key, ctx)?;
    let out = change(&mut file);
    save_record(home, key, ctx, &file)?;
    Ok(out)
}

/// Writes `progress` as [`REVOCATIONS_FILE`], or removes the file when
/// nothing is left in it.
fn save_record(
    home: &Home,
    key: &LocalKey,
    ctx: &LocalContext,
    progress: &RevocationsFile,
) -> ClientResult<()> {
    let path = home.file(REVOCATIONS_FILE);
    if progress.is_empty() {
        return match std::fs::remove_file(&path) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.into()),
            _ => Ok(()),
        };
    }
    let json = serde_json::to_vec(&RevocationsFile {
        v: REVOCATIONS_VERSION,
        ..progress.clone()
    })
    .expect("serializes");
    let blob = seal_local_data(key, ctx, PURPOSE_REVOCATIONS, &json)?;
    write_private(&path, &blob)
}

/// A rotated project key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationReport {
    /// Project ID.
    pub project_id: ProjectId,
    /// `vault/project`.
    pub project: String,
    /// Items whose key was re-wrapped.
    pub items: usize,
    /// Stored versions re-wrapped.
    pub versions: usize,
}

/// Result of [`Unlocked::revoke_agent`]. With `rotate`, check
/// [`RevokeReport::complete`]: a rotation that stopped half way says what
/// failed and what is left, and running it again finishes it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokeReport {
    /// The agent, now revoked.
    pub agent: AgentView,
    /// What it saw.
    pub exposure: Exposure,
    /// Project keys rotated by this run (with `rotate`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rotated: Vec<RotationReport>,
    /// `vault/project` already rotated by an earlier run for this
    /// revocation: not rotated again.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub already_rotated: Vec<String>,
    /// Items granted one by one whose key changed (ADR 0036 §18): always
    /// on revoking, since the agent may have kept their keys.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rekeyed: Vec<ItemId>,
    /// Items whose key still has to change (the failed one first): run
    /// the revocation again.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub items_pending: Vec<ItemId>,
    /// Other active agents that got a new grant with the new keys.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub regranted: Vec<String>,
    /// Other active agents whose grant could not be re-issued (`name:
    /// why`): one failure does not stop the others. Run it again.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub not_regranted: Vec<String>,
    /// What stopped the rotation, if it stopped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failed: Option<String>,
    /// `vault/project` still to rotate (the failed one first): run the
    /// revocation with `rotate` again.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pending: Vec<String>,
    /// Projects and items whose key cannot change from this device, and
    /// why (`vault/project: why`, `item <id>: why`): a deleted vault or
    /// project, one this account no longer holds, or an item this device
    /// no longer sees. They do not keep the report from being complete;
    /// the items stay written down and change if they come back.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub skipped: Vec<String>,
    /// What could not be checked (a grant this device cannot read, an
    /// audit log it could not read for the agent's last grant).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    /// The key change was asked for and the audit log could not be read:
    /// the projects this device knows changed key, but one the log would
    /// add may be missing, so it is not done (T189). Asking again reads
    /// the log again.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub log_unchecked: bool,
}

impl RevokeReport {
    /// Nothing is left that Klav can do: the rotation, when asked,
    /// finished. Not "every key changed": what Klav could not reach (a
    /// deleted project, a vault gone) is in `skipped`, and a report that
    /// is complete with skips must say them.
    pub fn complete(&self) -> bool {
        self.failed.is_none()
            && self.pending.is_empty()
            && self.items_pending.is_empty()
            && !self.log_unchecked
    }

    /// Adds what a rotation step did.
    pub fn absorb(&mut self, step: RotationStep) {
        self.rotated.extend(step.rotated);
        self.items_pending.retain(|i| !step.rekeyed.contains(i));
        self.rekeyed.extend(step.rekeyed);
        for why in step.skipped {
            if !self.skipped.contains(&why) {
                self.skipped.push(why);
            }
        }
        for name in step.regranted {
            if !self.regranted.contains(&name) {
                self.regranted.push(name);
            }
        }
        for name in step.not_regranted {
            if !self.not_regranted.contains(&name) {
                self.not_regranted.push(name);
            }
        }
        if step.failed.is_some() {
            self.failed = step.failed;
        }
    }
}

const SECRET_PERMISSIONS: [&str; 4] = ["fill", "inject", "totp", "reveal"];

impl Unlocked {
    /// "What it saw" for an agent, from its verified grant and the audit
    /// log. A log that does not check out ([`ClientError::Security`]) does
    /// not fail it: the projects still come from the grant, and
    /// [`Exposure::log_warning`] says why no item is listed.
    ///
    /// Its projects are those a revocation with the key change rotates
    /// ([`Self::projects_held`]): the grant's and every project the log
    /// says the account granted it, so the sheet shows what the key change
    /// covers.
    pub async fn agent_exposure(&mut self, id: AgentId) -> ClientResult<Exposure> {
        let info = self.agent_info(id).await?;
        let view = self.view_lenient(info.clone());
        let mut warnings = Vec::new();
        // The grants this device signed for it count too; a record that
        // does not open only says so here (revoking says it louder).
        let signed = match self.load_progress() {
            Ok(file) => file.signed.get(&id).cloned(),
            Err(e) => {
                warnings.push(e.to_string());
                None
            }
        };
        let held = self
            .projects_held(&info, &view, true, signed.as_ref(), &mut warnings)
            .await;
        let mut exposure = match self.exposure_of(view.clone()).await {
            Err(e @ ClientError::Security(_)) => {
                Exposure::of_grant(view, Some(log_unreadable("What it saw is shown", &e)))
            }
            other => other?,
        };
        exposure.projects = held
            .projects
            .iter()
            .map(|p| self.project_view(*p))
            .collect();
        exposure.projects_unknown = held.projects.is_empty() && (held.log_failed || !held.known);
        Ok(exposure)
    }

    /// [`Self::agent_exposure`] of `view`, with the log.
    async fn exposure_of(&mut self, view: AgentView) -> ClientResult<Exposure> {
        let id = view.id;
        let lines = self
            .audit_log(&LogFilter {
                agent: Some(id.to_string()),
                ..LogFilter::default()
            })
            .await?;
        let mut items: BTreeMap<ItemId, SeenItem> = BTreeMap::new();
        let mut denied = 0;
        for line in &lines {
            // The agent's own events, told apart by who wrote them, never
            // by the name (an agent may be called `you`).
            if !line.action.starts_with("agent.") || !line.by_agent {
                continue;
            }
            match line.outcome.as_deref() {
                Some("allow") => {}
                Some("deny") => {
                    denied += 1;
                    continue;
                }
                _ => continue,
            }
            let Some(item_id) = line.item_id else {
                continue;
            };
            let permission = line.permission.clone().unwrap_or_default();
            let seen = items.entry(item_id).or_insert_with(|| SeenItem {
                item_id,
                reference: line.item.clone(),
                permissions: Vec::new(),
                secret: false,
                attachments: 0,
                uses: 0,
                first_at: line.at,
                last_at: line.at,
                trashed: false,
                deleted: false,
            });
            seen.uses += 1;
            seen.first_at = seen.first_at.min(line.at);
            seen.last_at = seen.last_at.max(line.at);
            // Provisional: the item's contents decide below.
            seen.secret |= SECRET_PERMISSIONS.contains(&permission.as_str());
            seen.attachments += line.attachments.len() as u64;
            if !seen.permissions.contains(&permission) {
                seen.permissions.push(permission);
            }
        }
        let mut items: Vec<SeenItem> = items.into_values().collect();
        for seen in &mut items {
            match self.item_trashed(seen.item_id) {
                Some(trashed) => seen.trashed = trashed,
                None => seen.deleted = true,
            }
            // The details of an item whose only secrets are attachments
            // hold no value: it obtained a secret only if an attachment
            // was delivered. An item this device cannot open counts.
            if seen.secret && seen.attachments == 0 {
                seen.secret = self.item_has_text_secrets(seen.item_id).unwrap_or(true);
            }
            seen.secret |= seen.attachments > 0;
        }
        items.sort_by_key(|i| std::cmp::Reverse(i.last_at));
        Ok(Exposure {
            items,
            denied,
            ..Exposure::of_grant(view, None)
        })
    }

    /// Revokes an agent (signed by the account, effective on its next
    /// request). With `rotate`, rotates the key of every project it had
    /// and re-issues the grants of the other active agents with them, one
    /// project at a time ([`Self::rotation_step`]). Items it got one by
    /// one change key whatever `rotate` says (ADR 0036 §18), and agents
    /// that still hold them get a new grant.
    ///
    /// This device remembers the revocation in its sealed cache: the agent
    /// is never re-granted, whatever the server says of it. With `rotate`
    /// it also remembers that the person asked for the rotation
    /// ([`REVOCATIONS_FILE`]), so what is left shows in
    /// [`Self::pending_revocations`] until it is done; calling this again
    /// with `rotate` finishes it (the projects already rotated are not
    /// rotated again). A failure while rotating does not return an error:
    /// the report says what was done, what failed and what is left.
    ///
    /// Revoking never depends on reading the grant (ADR 0033, amendment of
    /// 2026-11-10, F1 gap 4): the revocation is signed with the agent's ID
    /// alone, and a grant this device cannot read only becomes a warning.
    /// Nor does it wait on the audit log: a log that cannot be read leaves
    /// "what it saw" without items, with [`Exposure::log_warning`] saying
    /// why. That is when a revocation is needed most (ADR 0033 §7.7).
    pub async fn revoke_agent(&mut self, id: AgentId, rotate: bool) -> ClientResult<RevokeReport> {
        let mut report = self.revoke_first(id, rotate).await?;
        if !rotate || report.failed.is_some() {
            return Ok(report);
        }
        loop {
            let step = self.rotation_step(id).await?;
            let stop = step.done || step.failed.is_some();
            report.absorb(step);
            if stop {
                break;
            }
        }
        report.pending = self.rotation_left(id);
        report.log_unchecked = self
            .load_progress()?
            .agents
            .get(&id)
            .is_some_and(|p| p.log_unchecked);
        Ok(report)
    }

    /// The first half of [`Self::revoke_agent`]: the revocation, the
    /// record of it, "what it saw" and the per-item keys. With `rotate`,
    /// records that the person asked for the rotation, without rotating.
    /// Then [`Self::rotation_step`] does the projects one at a time:
    /// `klavd` releases its session between steps, so the vault never
    /// waits on a whole rotation (F2).
    ///
    /// A [`REVOCATIONS_FILE`] that does not open never stops the
    /// revocation: the agent is revoked, and the report says the key change
    /// could not be written down (`failed`).
    pub async fn revoke_first(&mut self, id: AgentId, rotate: bool) -> ClientResult<RevokeReport> {
        let info = self.agent_info(id).await?;
        let was_revoked = info.status == AgentStatus::Revoked;
        let view = self.view_lenient(info.clone());
        let mut warnings = Vec::new();
        if let Some(why) = &view.grant_error {
            warnings.push(format!(
                "{why}; the agent is revoked all the same, and its projects come from what this device can verify"
            ));
        }
        // Items it was granted, by the server's word or this device's: a
        // server that hides the grant must not hide them. Also those this
        // device still owes a new key, which may have come only from the
        // log or another device's grant: posting the revocation again would
        // fail (`409`) and leave them owed (review of #315, 2). It only
        // keeps the revocation from being posted twice: whether projects'
        // keys change is still `rotate` alone (P7).
        // A record that does not open may hold some: never "none".
        let has_items = view.grant.as_ref().is_some_and(|g| !g.items.is_empty())
            || self.load_progress().map_or(true, |f| {
                f.signed.get(&id).is_some_and(|s| !s.items.is_empty())
                    || f.agents.get(&id).is_some_and(|e| !e.items.is_empty())
            });
        let agent = if was_revoked && (rotate || has_items) {
            // Already revoked: only the key changes are left to do.
            view.clone()
        } else {
            self.post_revocation(id).await?
        };
        // Read after revoking: a record that does not open stops only what
        // it would hold.
        let file = self.load_progress();
        let unreadable = file.as_ref().err().map(ToString::to_string);
        let file = file.ok();
        let signed = file.as_ref().and_then(|f| f.signed.get(&id)).cloned();
        // Its projects, as far as this device can verify them; with the key
        // change, also every project the log says it was granted, and every
        // project of a grant this device signed for it.
        let mut held = self
            .projects_held(&info, &view, rotate, signed.as_ref(), &mut warnings)
            .await;
        if unreadable.is_some() && rotate {
            // Without the record, this device cannot tell whether the log
            // holds its last grant.
            held.log_failed = true;
        }
        // Item keys an earlier run left owed: with or without the key
        // change, an item granted one by one gets a new key, so running the
        // revoke again finishes them (review of #315, 2).
        if let Some(entry) = file.as_ref().and_then(|f| f.agents.get(&id)) {
            held.items.extend(entry.items.iter().copied());
        }
        // A key change of projects taken away earlier, still owed: the
        // revocation's key change takes it over.
        if rotate && let Some(narrowing) = file.as_ref().and_then(|f| f.narrowed.get(&id)) {
            held.projects
                .extend(narrowing.projects.difference(&narrowing.rotated).copied());
            held.known |= !narrowing.projects.is_empty();
        }
        let record = self.cache.revocations.entry(id).or_default();
        record.projects.extend(held.projects.iter().copied());
        let record = record.clone();
        // Nothing known at all: the key change waits for the person (T189).
        // A log that could not be read with projects known does not stop
        // it (a server that rewrites the chain must not stop a key change,
        // ADR 0033 §8.4): they change, and it is not done (`log_unchecked`)
        // until a later step reads the log.
        let unknown = !held.known && record.projects.is_empty();
        self.save_cache()?;
        if rotate && file.is_some() {
            let name = info.name.clone();
            let log_unchecked = held.log_failed;
            self.update_progress(|f| {
                let entry = f.agents.entry(id).or_insert_with(|| RotationProgress {
                    name,
                    rotate: true,
                    ..RotationProgress::default()
                });
                // Asked again: what this run found replaces what an earlier
                // one could not tell.
                entry.rotate = true;
                entry.unknown = unknown;
                entry.log_unchecked = log_unchecked;
                entry.last_error = None;
                f.narrowed.remove(&id);
            })?;
        }
        // Revoked and remembered: now what it saw, from the log. Any
        // failure here (also offline) only leaves the items out.
        let mut exposure = match self.exposure_of(view.clone()).await {
            Ok(exposure) => exposure,
            Err(e) => Exposure::of_grant(
                view,
                Some(log_unreadable(
                    "The agent is revoked, and what it saw is shown",
                    &e,
                )),
            ),
        };
        // The projects the key change covers, not only the grant's.
        exposure.projects = record
            .projects
            .iter()
            .map(|p| self.project_view(*p))
            .collect();
        exposure.projects_unknown = unknown;
        let mut report = RevokeReport {
            agent,
            exposure,
            rotated: Vec::new(),
            already_rotated: Vec::new(),
            rekeyed: Vec::new(),
            items_pending: Vec::new(),
            regranted: Vec::new(),
            not_regranted: Vec::new(),
            failed: None,
            pending: Vec::new(),
            skipped: Vec::new(),
            warnings,
            log_unchecked: rotate && held.log_failed,
        };
        // Its items first: a per-item grant has no projects to rotate. A
        // retry changes their keys again (nothing is lost but a version).
        // They are the grant's, every one this device signed for it, and
        // with the key change every logged one: a server that serves an
        // older grant, or none, leaves none out.
        let items: Vec<ItemId> = held.items.iter().copied().collect();
        let mut items_left: BTreeSet<ItemId> = BTreeSet::new();
        if !items.is_empty() {
            // Those out of reach (unseen, or their vault gone) are written
            // down, not tried: they do not keep the revocation from being
            // complete, and change if they come back.
            let (live, parked) = self.rekeyable_items(&items.iter().copied().collect());
            let parked_ids: Vec<ItemId> = items
                .iter()
                .filter(|i| !live.contains(i))
                .copied()
                .collect();
            report.skipped.extend(parked);
            let rekeys = self.rekey_items(&live).await;
            report
                .skipped
                .extend(rekeys.gone.iter().map(|i| item_unseen(*i)));
            // A key the server took but this device did not sync is not
            // pending, yet its holders were not re-issued: a retry changes
            // it again and re-issues them (`failed` says which).
            items_left.extend(rekeys.unconfirmed.iter().copied());
            items_left.extend(rekeys.pending.iter().copied());
            report.items_pending = items_left.iter().copied().collect();
            // Out of reach, not pending: written down below all the same.
            items_left.extend(rekeys.gone.iter().copied());
            report.failed = rekeys.failed;
            report.rekeyed.clone_from(&rekeys.done);
            if !rekeys.done.is_empty() {
                let failed = self
                    .regrant_items(
                        &mut report.regranted,
                        &mut report.not_regranted,
                        &rekeys.done,
                    )
                    .await;
                if let Some(why) = failed {
                    // Their key changed, but a holder is still on the old
                    // one: written down, so a retry changes it again and
                    // issues the grants then (`failed` says which).
                    items_left.extend(rekeys.done.iter().copied());
                    report.failed.get_or_insert(why);
                }
            }
            items_left.extend(parked_ids);
            // Written down so `klavd` and the apps show them and the next
            // unlock tries again, whether or not the projects' keys change.
            if file.is_some() {
                let (name, failed) = (info.name.clone(), report.failed.clone());
                let left = items_left.clone();
                // On the plain path, an entry asked with the key change that
                // owes nothing else goes too, as a step would finish it:
                // nothing would show it and `klavd` resumes only what needs
                // work (review of #318, 2). One that still owes a project
                // stays (P7). With the key change, the steps that follow
                // finish it and say what they skipped, which `klavd` keeps
                // in `status` (review of #322).
                let projects = self.projects_left(id);
                let closed = self.update_progress(|f| {
                    let mut closed = None;
                    if left.is_empty() {
                        if let Some(entry) = f.agents.get_mut(&id) {
                            entry.items.clear();
                            if !rotate && entry.over(&projects) {
                                closed = Some(entry.rotate);
                                f.agents.remove(&id);
                            }
                        }
                    } else {
                        let entry = f.agents.entry(id).or_insert_with(|| RotationProgress {
                            name,
                            rotate,
                            ..RotationProgress::default()
                        });
                        entry.items = left;
                        entry.last_error = failed;
                    }
                    closed
                })?;
                // A key change the person asked for, closed here: the
                // projects it could not change because they are gone are
                // said once, as the step that finished it would have said
                // them. Never for a declined one: none of its keys was
                // ever going to change.
                if closed == Some(true) {
                    report.skipped.extend(projects.skipped);
                }
            }
        }
        // A record that does not open may name items this device signed
        // for the agent that the server no longer serves: never complete
        // then, with or without the key change (third re-check, F1).
        if let Some(why) = unreadable {
            report.failed.get_or_insert(why);
        }
        if rotate {
            if unknown {
                report.failed.get_or_insert_with(|| {
                    "this device does not know which projects the agent had: the server sent no grant this device can verify, and the audit log has none; check it with `klav log verify`".into()
                });
            }
            report.already_rotated = record
                .projects
                .iter()
                .filter(|p| record.rotated.contains(p))
                .map(|p| self.place(*p))
                .collect();
            if report.failed.is_some() {
                report.pending = self.rotation_left(id);
            }
        }
        Ok(report)
    }

    /// One step of a key change this device owes for agent `id`: a
    /// revocation's (its items first, then the grants still to issue again
    /// from an earlier step, then the next project), then a narrowing's.
    /// Writes down what it did before returning, so a lock or a crash
    /// between steps loses nothing, and a later step neither rotates twice
    /// nor forgets a grant to issue again. A revocation without a rotation
    /// asked for never rotates a project.
    ///
    /// Every step either moves, says what stopped it (`failed`), or is
    /// `done`: `klavd`'s loop stops on either of the last two.
    pub async fn rotation_step(&mut self, id: AgentId) -> ClientResult<RotationStep> {
        let mut step = RotationStep::new(id);
        let file = self.load_progress()?;
        if let Some(entry) = file.agents.get(&id).cloned() {
            self.revoked_step(&mut step, entry).await?;
            if step.done
                && step.failed.is_none()
                && let Some(narrowing) = self.load_progress()?.narrowed.get(&id).cloned()
            {
                // A narrowing asked before a revocation without the key
                // change: it goes on in this same call. The revocation's
                // entry may stay (items out of reach), and then every call
                // would take it first and never reach the narrowing (fifth
                // re-check of #308, N1).
                step.done = false;
                self.narrowed_step(&mut step, narrowing).await?;
            }
        } else if let Some(entry) = file.narrowed.get(&id).cloned() {
            self.narrowed_step(&mut step, entry).await?;
        } else {
            step.done = true;
        }
        Ok(step)
    }

    async fn revoked_step(
        &mut self,
        step: &mut RotationStep,
        entry: RotationProgress,
    ) -> ClientResult<()> {
        let id = step.agent_id;
        let mut parked = Vec::new();
        if !entry.items.is_empty() {
            // Which items are gone is told only after a sync that worked.
            if let Err(e) = self.sync().await {
                let why = format!("syncing before the next key change: {e}");
                self.note_error(Owed::Revoked, id, &why)?;
                step.failed = Some(why);
                return Ok(());
            }
            let (live, skipped) = self.rekeyable_items(&entry.items);
            if !live.is_empty() {
                // Those it can't reach are said in this step too.
                step.skipped = skipped;
                return self.items_step(step, &entry, &live).await;
            }
            // Only items whose vault is gone: they never block the rest.
            parked = skipped;
        }
        if !entry.rotate {
            // No project's key changes without the person asking (P7).
            // Items whose vault is gone keep the entry, said.
            let over = entry.over(&self.projects_left(id));
            step.skipped = parked.clone();
            self.finish(Owed::Revoked, id, !over || !parked.is_empty())?;
            step.done = true;
            return Ok(());
        }
        if !self.cache.revocations.contains_key(&id) {
            return Err(ClientError::NotFound(format!(
                "a revocation of agent {id} on this device"
            )));
        }
        if entry.unknown {
            step.failed = Some(
                "this device does not know which projects the agent had; check the log with `klav log verify`".into(),
            );
            return Ok(());
        }
        if !entry.regrants.is_empty() {
            let projects: Vec<ProjectId> = entry.regrants.iter().copied().collect();
            self.regrant_step(step, &projects, Owed::Revoked).await?;
            if step.failed.is_some() {
                return Ok(());
            }
        }
        // What is gone is told only after a sync that worked, never from a
        // read that failed.
        if let Err(e) = self.sync().await {
            let why = format!("syncing before the next key change: {e}");
            self.note_error(Owed::Revoked, id, &why)?;
            step.failed = Some(why);
            return Ok(());
        }
        let next = self.projects_left(id).next;
        if let Some(project) = next {
            match self.rotate_project_key(project).await {
                Ok(rotated) => {
                    // The grants to issue again first, then the mark: a
                    // crash or a failed save between the two leaves the
                    // project to rotate again (one more version), never
                    // rotated with the other agents left on the old key
                    // and the change reported done (T189).
                    self.update_progress(|f| {
                        if let Some(p) = f.agents.get_mut(&id) {
                            p.regrants.insert(project);
                            p.last_error = None;
                        }
                    })?;
                    self.mark_rotated(id, project)?;
                    step.rotated = Some(rotated);
                    self.regrant_step(step, &[project], Owed::Revoked).await?;
                }
                Err(e) => {
                    let why = format!("rotating the key of {}: {e}", self.place(project));
                    self.note_error(Owed::Revoked, id, &why)?;
                    step.failed = Some(why);
                }
            }
            if step.failed.is_some() {
                return Ok(());
            }
        }
        let projects = self.projects_left(id);
        let entry = self.load_progress()?.agents.get(&id).cloned();
        let Some(mut entry) = entry else {
            step.done = true;
            return Ok(());
        };
        if projects.next.is_some() || !entry.regrants.is_empty() {
            return Ok(());
        }
        if entry.log_unchecked {
            // The log may add a project: read it before anything says done.
            let added = self.recheck_log(step).await?;
            if step.failed.is_some() || added {
                return Ok(());
            }
            // Read: `recheck_log` cleared the mark.
            let Some(read) = self.load_progress()?.agents.get(&id).cloned() else {
                step.done = true;
                return Ok(());
            };
            entry = read;
        }
        // Over only on what `revoke_first` closes an entry on too. Items
        // whose vault is gone stay written down, and so does the entry,
        // until their vault comes back; a project that may come back keeps
        // it as well.
        let over = entry.over(&projects);
        let mut skipped = projects.skipped;
        skipped.extend(parked.iter().cloned());
        step.skipped = skipped;
        self.finish(Owed::Revoked, id, !over || !parked.is_empty())?;
        step.done = true;
        Ok(())
    }

    /// Items granted one by one still without a new key (or whose holders
    /// still need a grant): changed again, and their holders issued again.
    async fn items_step(
        &mut self,
        step: &mut RotationStep,
        entry: &RotationProgress,
        live: &[ItemId],
    ) -> ClientResult<()> {
        let id = step.agent_id;
        let rekeys = self.rekey_items(live).await;
        for why in rekeys.gone.iter().map(|i| item_unseen(*i)) {
            if !step.skipped.contains(&why) {
                step.skipped.push(why);
            }
        }
        // Those not tried this time (out of reach) stay, and so do those
        // that went out of reach meanwhile: if they come back, they change.
        let mut left: BTreeSet<ItemId> = entry
            .items
            .iter()
            .filter(|i| !live.contains(i))
            .copied()
            .collect();
        left.extend(
            rekeys
                .gone
                .iter()
                .chain(&rekeys.unconfirmed)
                .chain(&rekeys.pending)
                .copied(),
        );
        let mut failed = rekeys.failed;
        if !rekeys.done.is_empty() {
            let why = self
                .regrant_items(&mut step.regranted, &mut step.not_regranted, &rekeys.done)
                .await;
            if let Some(why) = why {
                left.extend(rekeys.done.iter().copied());
                failed.get_or_insert(why);
            }
        }
        step.rekeyed = rekeys.done;
        let error = failed.clone();
        self.update_progress(|f| {
            if let Some(p) = f.agents.get_mut(&id) {
                p.items = left;
                p.last_error = error;
            }
        })?;
        step.failed = failed;
        Ok(())
    }

    /// Issues again the grants that hold `items` (their keys just changed).
    /// Returns what stopped it, if anything.
    async fn regrant_items(
        &mut self,
        regranted: &mut Vec<String>,
        not_regranted: &mut Vec<String>,
        items: &[ItemId],
    ) -> Option<String> {
        match self.regrant_agents(&[], items, None).await {
            Ok(r) => {
                let failure = r.failure();
                regranted.extend(r.done);
                not_regranted.extend(r.failed);
                failure
            }
            Err(e) => Some(format!("re-issuing the grants of the other agents: {e}")),
        }
    }

    /// One step of the key change of projects taken away from active agent
    /// `id` (`rotate_removed`).
    async fn narrowed_step(
        &mut self,
        step: &mut RotationStep,
        entry: Narrowing,
    ) -> ClientResult<()> {
        let id = step.agent_id;
        if !entry.regrants.is_empty() {
            let projects: Vec<ProjectId> = entry.regrants.iter().copied().collect();
            self.regrant_step(step, &projects, Owed::Narrowed).await?;
            if step.failed.is_some() {
                return Ok(());
            }
        }
        if let Err(e) = self.sync().await {
            let why = format!("syncing before the next key change: {e}");
            self.note_error(Owed::Narrowed, id, &why)?;
            step.failed = Some(why);
            return Ok(());
        }
        let (next, _, _) = self.next_project(&entry.projects, &entry.rotated);
        if let Some(project) = next {
            match self.rotate_project_key(project).await {
                Ok(rotated) => {
                    // The mark and the grants to issue again in one write.
                    self.update_progress(|f| {
                        if let Some(n) = f.narrowed.get_mut(&id) {
                            n.rotated.insert(project);
                            n.regrants.insert(project);
                            n.last_error = None;
                        }
                    })?;
                    step.rotated = Some(rotated);
                    self.regrant_step(step, &[project], Owed::Narrowed).await?;
                }
                Err(e) => {
                    let why = format!("changing the key of {}: {e}", self.place(project));
                    self.note_error(Owed::Narrowed, id, &why)?;
                    step.failed = Some(why);
                }
            }
            if step.failed.is_some() {
                return Ok(());
            }
        }
        let Some(now) = self.load_progress()?.narrowed.get(&id).cloned() else {
            step.done = true;
            return Ok(());
        };
        let (next, skipped, may_return) = self.next_project(&now.projects, &now.rotated);
        if next.is_some() || !now.regrants.is_empty() {
            return Ok(());
        }
        // After a revocation's step in the same call, its skips stay.
        step.skipped.extend(skipped);
        self.finish(Owed::Narrowed, id, may_return)?;
        step.done = true;
        Ok(())
    }

    /// Reads the audit log again for a key change that went ahead without
    /// it: `true` when it adds a project (rotated by the next steps).
    /// What stops it goes into `step.failed`, and the key change stays not
    /// done.
    async fn recheck_log(&mut self, step: &mut RotationStep) -> ClientResult<bool> {
        let id = step.agent_id;
        let found = match self.agent_info(id).await {
            Err(e) => Err(e.to_string()),
            Ok(info) => match PublicIdentity::decode(info.public_identity.as_bytes()) {
                Err(_) => Err("the agent's public key does not decode, so its grants in the log cannot be checked".to_owned()),
                Ok(public) => self.log_grants(id, &public).await.map_err(|e| e.to_string()),
            },
        };
        let signed = self.load_progress()?.signed.get(&id).cloned();
        let why = match &found {
            Err(e) => Some(format!(
                "reading the audit log, which lists every project the agent was granted: {e}"
            )),
            Ok(found) => log_misses_signed(signed.as_ref(), found),
        };
        if let Some(why) = why {
            self.note_error(Owed::Revoked, id, &why)?;
            step.failed = Some(why);
            return Ok(false);
        }
        let found = found.unwrap_or_default();
        let record = self.cache.revocations.entry(id).or_default();
        let before = record.projects.len();
        record.projects.extend(found.projects);
        let added = record.projects.len() != before;
        if added {
            self.save_cache()?;
        }
        self.update_progress(|f| {
            if let Some(p) = f.agents.get_mut(&id) {
                p.log_unchecked = false;
                p.last_error = None;
            }
        })?;
        Ok(added)
    }

    /// Issues again the grants of the other agents that hold `projects`,
    /// and writes down which are still to issue.
    async fn regrant_step(
        &mut self,
        step: &mut RotationStep,
        projects: &[ProjectId],
        owed: Owed,
    ) -> ClientResult<()> {
        let id = step.agent_id;
        let failed = match self.regrant_agents(projects, &[], None).await {
            Ok(r) => {
                step.regranted.extend(r.done.iter().cloned());
                step.not_regranted.extend(r.failed.iter().cloned());
                r.failure()
            }
            Err(e) => Some(format!("re-issuing the grants of the other agents: {e}")),
        };
        let error = failed.clone();
        self.update_progress(|f| {
            let slot = match owed {
                Owed::Revoked => f
                    .agents
                    .get_mut(&id)
                    .map(|p| (&mut p.regrants, &mut p.last_error)),
                Owed::Narrowed => f
                    .narrowed
                    .get_mut(&id)
                    .map(|n| (&mut n.regrants, &mut n.last_error)),
            };
            if let Some((regrants, last_error)) = slot {
                if error.is_none() {
                    for project in projects {
                        regrants.remove(project);
                    }
                }
                *last_error = error;
            }
        })?;
        step.failed = failed;
        Ok(())
    }

    /// `klavd`'s steps for agent `id` stopped making progress (two in a row
    /// moved nothing): written as the entry's `last_error`, which `status`,
    /// the apps and `klav agent show` say, so nothing reads it as still
    /// running. A step that changes a key clears it. Names nothing, and
    /// it is the format 1 field, not a new one.
    pub fn note_no_progress(&self, id: AgentId) -> ClientResult<()> {
        self.update_progress(|f| {
            if let Some(p) = f.agents.get_mut(&id) {
                p.last_error = Some(NO_PROGRESS.to_owned());
            }
            if let Some(n) = f.narrowed.get_mut(&id) {
                n.last_error = Some(NO_PROGRESS.to_owned());
            }
        })
    }

    /// Writes down what stopped the last step.
    fn note_error(&self, owed: Owed, id: AgentId, why: &str) -> ClientResult<()> {
        self.update_progress(|f| match owed {
            Owed::Revoked => {
                if let Some(p) = f.agents.get_mut(&id) {
                    p.last_error = Some(why.to_owned());
                }
            }
            Owed::Narrowed => {
                if let Some(n) = f.narrowed.get_mut(&id) {
                    n.last_error = Some(why.to_owned());
                }
            }
        })
    }

    /// The end of a key change: gone. One that skipped projects stays, so it
    /// still says so, and a project that comes back (a vault restored)
    /// shows as pending again.
    fn finish(&self, owed: Owed, id: AgentId, keep: bool) -> ClientResult<()> {
        self.update_progress(|f| match (owed, keep) {
            (Owed::Revoked, false) => {
                f.agents.remove(&id);
            }
            (Owed::Narrowed, false) => {
                f.narrowed.remove(&id);
            }
            (Owed::Revoked, true) => {
                if let Some(p) = f.agents.get_mut(&id) {
                    p.last_error = None;
                }
            }
            (Owed::Narrowed, true) => {
                if let Some(n) = f.narrowed.get_mut(&id) {
                    n.last_error = None;
                }
            }
        })
    }

    /// What a revocation of `id` still has to rotate, from this device's
    /// record of it ([`Self::next_project`]): what a step rotates next, and
    /// what it checks before [`Self::finish`].
    fn projects_left(&self, id: AgentId) -> ProjectsLeft {
        let record = self.cache.revocations.get(&id).cloned().unwrap_or_default();
        let (next, skipped, may_return) = self.next_project(&record.projects, &record.rotated);
        ProjectsLeft {
            next,
            skipped,
            may_return,
        }
    }

    /// The next of `projects` to rotate (not in `rotated`, and not gone),
    /// those skipped because they are gone (`vault/project: why`), and
    /// whether one of them can come back (a deleted project never does).
    fn next_project(
        &self,
        projects: &BTreeSet<ProjectId>,
        rotated: &BTreeSet<ProjectId>,
    ) -> (Option<ProjectId>, Vec<String>, bool) {
        let mut next = None;
        let mut skipped = Vec::new();
        let mut may_return = false;
        for project in projects.iter().filter(|p| !rotated.contains(p)) {
            match self.gone(*project) {
                Some(why) => {
                    may_return |= why != PROJECT_DELETED;
                    skipped.push(format!("{}: {why}", self.place(*project)));
                }
                None => {
                    next.get_or_insert(*project);
                }
            }
        }
        (next, skipped, may_return)
    }

    /// Splits `items` into those whose key can change from here and those
    /// skipped (`item <id>: why`) because this device no longer sees them,
    /// or the server no longer lists their vault or deleted it, as the last
    /// sync left it. A skipped item stays written down: if it or its vault
    /// comes back, it is pending again (fifth re-check, 2).
    fn rekeyable_items(&self, items: &BTreeSet<ItemId>) -> (Vec<ItemId>, Vec<String>) {
        let mut live = Vec::new();
        let mut skipped = Vec::new();
        for item in items {
            if self.locate_item(*item).is_none() {
                skipped.push(item_unseen(*item));
                continue;
            }
            match self.item_gone(*item) {
                Some(why) => skipped.push(format!("item {item}: {why}")),
                None => live.push(*item),
            }
        }
        (live, skipped)
    }

    /// Why `item`'s key cannot change from this device: its vault is no
    /// longer listed, or deleted. An item this device no longer sees at all
    /// is not here ([`item_unseen`]).
    fn item_gone(&self, item: ItemId) -> Option<&'static str> {
        let loc = self.locate_item(item)?;
        let vault = self.cache.vaults.get(&loc.vault)?;
        if vault.unlisted {
            return Some(VAULT_UNLISTED);
        }
        vault
            .vault
            .as_ref()
            .is_some_and(|v| v.deleted_at.is_some())
            .then_some(VAULT_DELETED)
    }

    /// Why `project`'s key cannot change from this device, from what the
    /// last sync left here (a step syncs first, and stops if it cannot):
    /// deleted, its vault deleted or no longer listed, or no vault of this
    /// account holds it. A vault this device holds but cannot open is not
    /// gone: that stops the step instead.
    fn gone(&self, project: ProjectId) -> Option<&'static str> {
        if self.cache.marks.deleted_projects.contains(&project) {
            return Some(PROJECT_DELETED);
        }
        match self
            .cache
            .vaults
            .values()
            .find(|v| v.projects.contains_key(&project))
        {
            None => Some("no vault of this account holds it any more"),
            Some(v) if v.unlisted => Some(VAULT_UNLISTED),
            Some(v)
                if v.vault
                    .as_ref()
                    .is_some_and(|vault| vault.deleted_at.is_some()) =>
            {
                Some(VAULT_DELETED)
            }
            Some(_) => None,
        }
    }

    /// The key changes this device still owes, from its records (F4
    /// `agent_revocations`): revocations with something left, and
    /// narrowings. A revocation without a rotation asked for shows only
    /// while items granted one by one wait for a new key.
    pub fn pending_revocations(&self) -> ClientResult<Vec<PendingRevocation>> {
        let file = self.load_progress()?;
        let mut out = Vec::new();
        for (id, entry) in &file.agents {
            let (projects, rotated) = match self.cache.revocations.get(id) {
                Some(record) if entry.rotate => (record.projects.clone(), record.rotated.clone()),
                _ => (BTreeSet::new(), BTreeSet::new()),
            };
            let mut pending =
                self.key_change_left(*id, &entry.name, &projects, &rotated, &entry.regrants);
            pending.unknown_projects = entry.rotate && entry.unknown;
            let (live, parked) = self.rekeyable_items(&entry.items);
            pending.items = live.len();
            pending.skipped.extend(parked);
            pending.log_unchecked = entry.rotate && entry.log_unchecked;
            pending.without_key_change = !entry.rotate;
            pending.last_error.clone_from(&entry.last_error);
            if pending.shows() {
                out.push(pending);
            }
        }
        for (id, narrowing) in &file.narrowed {
            let mut pending = self.key_change_left(
                *id,
                &narrowing.name,
                &narrowing.projects,
                &narrowing.rotated,
                &narrowing.regrants,
            );
            pending.narrowed = true;
            pending.last_error.clone_from(&narrowing.last_error);
            if pending.shows() {
                out.push(pending);
            }
        }
        Ok(out)
    }

    fn key_change_left(
        &self,
        agent_id: AgentId,
        name: &str,
        projects: &BTreeSet<ProjectId>,
        rotated: &BTreeSet<ProjectId>,
        regrants: &BTreeSet<ProjectId>,
    ) -> PendingRevocation {
        let mut pending = Vec::new();
        let mut skipped = Vec::new();
        for project in projects.iter().filter(|p| !rotated.contains(p)) {
            match self.gone(*project) {
                Some(why) => skipped.push(format!("{}: {why}", self.place(*project))),
                None => pending.push(self.place(*project)),
            }
        }
        PendingRevocation {
            agent_id,
            name: name.to_owned(),
            projects: projects.iter().map(|p| self.place(*p)).collect(),
            rotated: projects
                .iter()
                .filter(|p| rotated.contains(p))
                .map(|p| self.place(*p))
                .collect(),
            pending,
            regrants: regrants.iter().map(|p| self.place(*p)).collect(),
            unknown_projects: false,
            narrowed: false,
            items: 0,
            log_unchecked: false,
            without_key_change: false,
            skipped,
            last_error: None,
        }
    }

    /// `vault/project` of the projects of `id`'s revocation still to
    /// rotate, in the order they rotate (gone ones left out).
    #[must_use]
    pub fn rotation_left(&self, id: AgentId) -> Vec<String> {
        self.cache.revocations.get(&id).map_or_else(Vec::new, |r| {
            r.projects
                .iter()
                .filter(|p| !r.rotated.contains(p) && self.gone(**p).is_none())
                .map(|p| self.place(*p))
                .collect()
        })
    }

    /// `vault/project` of the projects of `id`'s narrowing still to rotate.
    pub(crate) fn narrowing_left(&self, id: AgentId) -> ClientResult<Vec<String>> {
        Ok(self
            .load_progress()?
            .narrowed
            .get(&id)
            .map(|n| {
                n.projects
                    .iter()
                    .filter(|p| !n.rotated.contains(p) && self.gone(**p).is_none())
                    .map(|p| self.place(*p))
                    .collect()
            })
            .unwrap_or_default())
    }

    /// Writes down, before a grant goes to the server, the projects and
    /// items it gives agent `id`: a later revocation changes their keys
    /// whatever the server serves or logs.
    pub(crate) fn note_signing(
        &self,
        id: AgentId,
        projects: &BTreeSet<ProjectId>,
        items: &BTreeSet<ItemId>,
    ) -> ClientResult<()> {
        self.update_progress(|f| {
            let signed = f.signed.entry(id).or_default();
            signed.projects.extend(projects.iter().copied());
            signed.items.extend(items.iter().copied());
        })
    }

    /// Writes down that the server took grant `version` for agent `id`
    /// from this device: the log must hold it.
    pub(crate) fn note_signed(&self, id: AgentId, version: u64) -> ClientResult<()> {
        self.update_progress(|f| {
            let signed = f.signed.entry(id).or_default();
            signed.version = signed.version.max(version);
        })
    }

    /// Writes down, before the grant that takes them away is signed, the
    /// projects of active agent `id` whose key changes (`rotate_removed`).
    /// Returns what was there, to put back if the grant does not go through.
    pub(crate) fn note_narrowing(
        &self,
        id: AgentId,
        name: &str,
        removed: &[ProjectId],
    ) -> ClientResult<Option<Narrowing>> {
        self.update_progress(|f| {
            let before = f.narrowed.get(&id).cloned();
            let entry = f.narrowed.entry(id).or_insert_with(|| Narrowing {
                name: name.to_owned(),
                ..Narrowing::default()
            });
            entry.projects.extend(removed.iter().copied());
            // Taken away again after coming back: its key changes again.
            entry.rotated.retain(|p| !removed.contains(p));
            entry.last_error = None;
            before
        })
    }

    /// Puts back the narrowing of `id` as it was before a grant that did
    /// not go through.
    pub(crate) fn restore_narrowing(
        &self,
        id: AgentId,
        before: Option<Narrowing>,
    ) -> ClientResult<()> {
        self.update_progress(|f| match before {
            Some(entry) => {
                f.narrowed.insert(id, entry);
            }
            None => {
                f.narrowed.remove(&id);
            }
        })
    }

    /// The projects, items and version of a grant signed by this account
    /// for `id`, read without knowing every field (a later format still
    /// names its projects and items). `None` unless the account's signature checks out and
    /// the payload names this account and agent.
    fn signed_grant(
        &self,
        id: AgentId,
        public: &PublicIdentity,
        payload: &[u8],
        signature: &[u8],
    ) -> Option<SignedFound> {
        #[derive(Deserialize)]
        struct Loose {
            account_id: AccountId,
            agent_id: AgentId,
            #[serde(default)]
            version: u64,
            #[serde(default)]
            projects: Vec<LooseProject>,
            #[serde(default)]
            items: Vec<LooseItem>,
        }
        #[derive(Deserialize)]
        struct LooseProject {
            project_id: ProjectId,
        }
        #[derive(Deserialize)]
        struct LooseItem {
            item_id: ItemId,
        }
        let signature: [u8; SIGNATURE_LEN] = signature.try_into().ok()?;
        agent::verify_grant(
            self.identity.public(),
            &GrantToSign {
                account: self.account.account_id,
                agent: id,
                agent_public: public,
                payload,
            },
            &Signature::from_bytes(signature),
        )
        .ok()?;
        let loose: Loose = serde_json::from_slice(payload).ok()?;
        (loose.agent_id == id && loose.account_id == self.account.account_id).then(|| SignedFound {
            projects: loose.projects.iter().map(|p| p.project_id).collect(),
            items: loose.items.iter().map(|i| i.item_id).collect(),
            version: loose.version,
        })
    }

    /// Every `agent.granted` of `id` in the account's log whose account
    /// signature checks out here (the log views do not check signatures,
    /// ADR 0033 §8.4): their projects and versions.
    async fn log_grants(
        &mut self,
        id: AgentId,
        public: &PublicIdentity,
    ) -> ClientResult<LogGrants> {
        let entries = self.audit_entries().await?;
        let mut out = LogGrants::default();
        for entry in entries
            .iter()
            .filter(|e| e.event.action == "agent.granted" && e.event.agent_id == Some(id))
        {
            let (Some(payload), Some(signature)) =
                (&entry.event.signed, &entry.event.account_signature)
            else {
                continue;
            };
            if let Some(found) =
                self.signed_grant(id, public, payload.as_bytes(), signature.as_bytes())
            {
                out.projects.extend(found.projects);
                out.items.extend(found.items);
                out.versions.insert(found.version);
            }
        }
        Ok(out)
    }

    /// The projects whose keys agent `id` held, as far as this device can
    /// tell: the grant the server sends (verified, or read loosely when
    /// only its signature checks out), every project of every grant this
    /// device signed for it (`signed`), and, with `with_log`, every project
    /// of every `agent.granted` in the log chain the server presents.
    ///
    /// The server decides which grant it sends and where the chain ends:
    /// it cannot forge the account's signature, nor drop an event from a
    /// chain this device downloaded before or verified (`klav log verify`
    /// pins it), but it can end a chain this device never saw before a
    /// grant. A chain that does not hold the last grant this device signed
    /// for the agent counts as not read (`log_failed`). What is left is a
    /// grant signed on another device and cut off before this device saw
    /// the log: its projects can be missed (docs/modelo-de-amenazas.md,
    /// T189). No project is left out because its key may have changed
    /// since: in doubt, it changes again.
    async fn projects_held(
        &mut self,
        info: &AgentInfo,
        view: &AgentView,
        with_log: bool,
        signed: Option<&SignedGrants>,
        warnings: &mut Vec<String>,
    ) -> Held {
        let id = info.id;
        let public = PublicIdentity::decode(info.public_identity.as_bytes()).ok();
        let mut held = Held {
            projects: view
                .grant
                .iter()
                .flat_map(|g| g.projects.iter().map(|p| p.project_id))
                .collect(),
            items: view
                .grant
                .iter()
                .flat_map(|g| g.items.iter().map(|i| i.item_id))
                .collect(),
            // A grant this device verified, or an agent never approved. A
            // server that sends no grant for an approved agent is not taken
            // at its word (T189).
            known: view.grant.is_some() || info.approved_at.is_none(),
            log_failed: false,
        };
        if view.grant.is_none()
            && let (Some(grant), Some(public)) = (&info.grant, &public)
            && let Some(found) = self.signed_grant(
                id,
                public,
                grant.payload.as_bytes(),
                grant.signature.as_bytes(),
            )
        {
            held.projects.extend(found.projects);
            held.items.extend(found.items);
            held.known = true;
        }
        if let Some(signed) = signed {
            // Items do not make the projects known: a proxy's grant has
            // none (ADR 0036 §2).
            held.items.extend(signed.items.iter().copied());
            if !signed.projects.is_empty() {
                held.projects.extend(signed.projects.iter().copied());
                held.known = true;
            }
        }
        if !with_log {
            return held;
        }
        match public.as_ref() {
            Some(public) => match self.log_grants(id, public).await {
                Ok(found) => {
                    if let Some(why) = log_misses_signed(signed, &found) {
                        held.log_failed = true;
                        warnings.push(why);
                    }
                    held.known |= !found.projects.is_empty();
                    held.projects.extend(found.projects);
                    held.items.extend(found.items);
                }
                Err(e) => {
                    held.log_failed = true;
                    warnings.push(format!(
                        "could not read the audit log for the projects the agent was granted: {e}"
                    ));
                }
            },
            None => {
                held.log_failed = true;
                warnings.push("the agent's public key does not decode".into());
            }
        }
        held
    }

    /// A project as "what it saw" lists it.
    fn project_view(&self, project: ProjectId) -> GrantedProjectView {
        let entry = self.projects.get(&project);
        let vault_id = entry.map(|e| e.vault);
        GrantedProjectView {
            vault_id: vault_id.unwrap_or_else(|| VaultId::from_bytes([0; 16])),
            vault: vault_id
                .and_then(|v| self.vaults.get(&v))
                .map(|v| v.meta.name().to_owned())
                .unwrap_or_default(),
            project_id: project,
            project: entry.map(|e| e.meta.name().to_owned()).unwrap_or_default(),
        }
    }

    /// Records in the sealed cache that the rotation for revoking `agent`
    /// rotated `project`.
    fn mark_rotated(&mut self, agent: AgentId, project: ProjectId) -> ClientResult<()> {
        self.cache
            .revocations
            .entry(agent)
            .or_default()
            .rotated
            .insert(project);
        self.save_cache()
    }

    fn save_cache(&self) -> ClientResult<()> {
        self.cache.save(&self.home, &self.local_key, &self.ctx)
    }

    /// This account's [`REVOCATIONS_FILE`] ([`load_record`]).
    fn load_progress(&self) -> ClientResult<RevocationsFile> {
        load_record(&self.home, &self.local_key, &self.ctx)
    }

    /// Reads [`REVOCATIONS_FILE`], changes it and writes it back, all at
    /// once: never a copy kept across a call that signs a grant (which
    /// writes it too).
    fn update_progress<R>(
        &self,
        change: impl FnOnce(&mut RevocationsFile) -> R,
    ) -> ClientResult<R> {
        update_record(&self.home, &self.local_key, &self.ctx, change)
    }

    async fn post_revocation(&mut self, id: AgentId) -> ClientResult<AgentView> {
        let revoked_at = now_ms();
        let signature = agent::sign_revocation(
            &self.identity,
            self.account.account_id,
            id,
            u64::try_from(revoked_at).unwrap_or(0),
        );
        let info: AgentInfo = self
            .send_json(
                Method::POST,
                &format!("/v1/agents/{id}/revoke"),
                &RevokeAgent {
                    revoked_at,
                    signature: Blob::new(signature.to_bytes().to_vec()),
                },
            )
            .await?;
        Ok(self.view_lenient(info))
    }

    /// Rotates a project key: a new key wrapped with the vault key, every
    /// item key (current and stored versions) re-wrapped with it, in one
    /// transaction on the server. Item keys and contents do not change.
    ///
    /// The server lists the keys to re-wrap. An item it leaves out would
    /// stay wrapped with the old key (the one a revoked agent holds), so the
    /// list must cover every live item of the project this device has, with
    /// the same wrapped key it has; if not, the rotation is refused
    /// ([`ClientError::Security`]).
    pub async fn rotate_project_key(&mut self, project: ProjectId) -> ClientResult<RotationReport> {
        self.sync().await?;
        let mut current = self.project_keys(project).await?;
        if self.check_rotation_keys(project, &current).is_err() {
            // An item created or purged in between: look again once.
            self.sync().await?;
            current = self.project_keys(project).await?;
            self.check_rotation_keys(project, &current)
                .map_err(ClientError::Security)?;
        }
        let entry = self
            .projects
            .get(&project)
            .ok_or_else(|| ClientError::NotFound(format!("project {project}")))?;
        let vault_id = entry.vault;
        let vault = self
            .vaults
            .get(&vault_id)
            .ok_or_else(|| ClientError::NotFound(format!("vault {vault_id}")))?;
        let owner = vault.owner;
        let name = format!("{}/{}", vault.meta.name(), entry.meta.name());
        let pctx = ProjectContext {
            account: owner,
            vault: vault_id,
            project,
        };
        let new_key = ProjectKey::generate();
        let version = current.version + 1;
        let mut keys = Vec::with_capacity(current.keys.len());
        let (mut items, mut versions) = (0, 0);
        for k in &current.keys {
            let ictx = ItemContext {
                account: owner,
                vault: vault_id,
                project,
                item: k.item_id,
            };
            let item_key = unwrap_item_key(&entry.key, &ictx, k.wrapped_key.as_bytes())?;
            keys.push(WrappedItemKey {
                item_id: k.item_id,
                version: k.version,
                wrapped_key: Blob::new(wrap_item_key(&new_key, &ictx, &item_key)),
            });
            if k.version.is_some() {
                versions += 1;
            } else {
                items += 1;
            }
        }
        let body = RotateProject {
            version,
            wrapped_key: Blob::new(wrap_project_key(&vault.key, &pctx, &new_key)),
            meta: Blob::new(seal_project_meta(&new_key, &pctx, version, &entry.meta)),
            keys,
        };
        let _: Project = self
            .send_json(
                Method::POST,
                &format!("/v1/vaults/{vault_id}/projects/{project}/rotate"),
                &body,
            )
            .await?;
        // The rotation is done on the server: a failed sync here must not
        // make a retry rotate again, so it only becomes a warning.
        if let Err(e) = self.sync().await {
            self.warnings.push(format!(
                "the key of {name} rotated, but syncing afterwards failed ({e}): sync again"
            ));
        }
        Ok(RotationReport {
            project_id: project,
            project: name,
            items,
            versions,
        })
    }

    /// `GET …/keys` of `project`.
    async fn project_keys(&mut self, project: ProjectId) -> ClientResult<ProjectKeys> {
        let vault_id = self
            .projects
            .get(&project)
            .ok_or_else(|| ClientError::NotFound(format!("project {project}")))?
            .vault;
        let res = self
            .authed(
                Method::GET,
                &format!("/v1/vaults/{vault_id}/projects/{project}/keys"),
                &Body::Empty,
            )
            .await?;
        crate::api::json(res).await
    }

    /// Whether the keys the server listed for a rotation cover every live
    /// item of `project` in this device's cache, with the wrapped key this
    /// device has. Stored versions cannot be checked: the cache does not
    /// keep the history.
    fn check_rotation_keys(&self, project: ProjectId, listed: &ProjectKeys) -> Result<(), String> {
        let vault = self
            .projects
            .get(&project)
            .map(|p| p.vault)
            .ok_or_else(|| format!("project {project} is not on this device"))?;
        let current: BTreeMap<ItemId, &[u8]> = listed
            .keys
            .iter()
            .filter(|k| k.version.is_none())
            .map(|k| (k.item_id, k.wrapped_key.as_bytes()))
            .collect();
        let Some(cached) = self.cache.vaults.get(&vault) else {
            return Err(format!("vault {vault} is not in this device's cache"));
        };
        let mut missing = 0;
        let mut changed = 0;
        for item in cached.items.values() {
            if item.project_id != project || item.purged_at.is_some() {
                continue;
            }
            let Some(wrapped) = &item.wrapped_key else {
                continue;
            };
            match current.get(&item.id) {
                None => missing += 1,
                Some(listed) if *listed != wrapped.as_bytes() => changed += 1,
                Some(_) => {}
            }
        }
        if missing == 0 && changed == 0 {
            return Ok(());
        }
        Err(format!(
            "the server left out {missing} and changed {changed} of the item keys of this \
             project; nothing was rotated (they would stay with the old key)"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const AGENT: &str = "6f1c1b2e-0c1d-4a7b-9e55-1f2a3b4c5d6e";
    const PROJECT: &str = "0b9a8c7d-6e5f-4a3b-8c2d-1e0f9a8b7c6d";

    #[test]
    fn a_record_from_before_its_later_fields_reads_as_the_key_change_asked_for() {
        // Layer 2's layout: a revocation's entry was always a rotation.
        let old = format!(
            r#"{{"v":1,"agents":{{"{AGENT}":{{"name":"bot","regrants":["{PROJECT}"]}}}}}}"#
        );
        let file: RevocationsFile = serde_json::from_str(&old).expect("old layout");
        let entry = file.agents.values().next().expect("entry");
        assert!(entry.rotate);
        assert_eq!(entry.regrants.len(), 1);
        assert!(!entry.log_unchecked && !entry.unknown && entry.items.is_empty());
        assert!(file.narrowed.is_empty() && file.signed.is_empty());
    }

    #[test]
    fn a_revocation_without_the_key_change_keeps_saying_so() {
        let agent: AgentId = serde_json::from_str(&format!("\"{AGENT}\"")).expect("id");
        let item: ItemId = serde_json::from_str(&format!("\"{PROJECT}\"")).expect("id");
        let mut file = RevocationsFile {
            v: REVOCATIONS_VERSION,
            ..RevocationsFile::default()
        };
        file.agents.insert(
            agent,
            RotationProgress {
                name: "bot".into(),
                rotate: false,
                items: [item].into(),
                ..RotationProgress::default()
            },
        );
        let json = serde_json::to_string(&file).expect("json");
        assert!(json.contains(r#""rotate":false"#), "{json}");
        assert!(
            !json.contains("narrowed") && !json.contains("signed"),
            "{json}"
        );
        let back: RevocationsFile = serde_json::from_str(&json).expect("back");
        assert!(!back.agents[&agent].rotate);
    }

    const ITEM: &str = "3c4d5e6f-7a8b-4c9d-8e0f-1a2b3c4d5e6f";

    /// Every field of format 1, set, as it is written. Changing the layout
    /// changes this and must bump `v` (spec §12.2).
    const V1_FULL: &str = concat!(
        r#"{"v":1,"#,
        r#""agents":{"6f1c1b2e-0c1d-4a7b-9e55-1f2a3b4c5d6e":{"name":"bot","rotate":false,"#,
        r#""regrants":["0b9a8c7d-6e5f-4a3b-8c2d-1e0f9a8b7c6d"],"unknown":true,"log_unchecked":true,"#,
        r#""items":["3c4d5e6f-7a8b-4c9d-8e0f-1a2b3c4d5e6f"],"last_error":"the server did not answer"}},"#,
        r#""narrowed":{"6f1c1b2e-0c1d-4a7b-9e55-1f2a3b4c5d6e":{"name":"bot","#,
        r#""projects":["0b9a8c7d-6e5f-4a3b-8c2d-1e0f9a8b7c6d"],"rotated":["0b9a8c7d-6e5f-4a3b-8c2d-1e0f9a8b7c6d"],"#,
        r#""regrants":["0b9a8c7d-6e5f-4a3b-8c2d-1e0f9a8b7c6d"],"last_error":"stopped"}},"#,
        r#""signed":{"6f1c1b2e-0c1d-4a7b-9e55-1f2a3b4c5d6e":{"#,
        r#""projects":["0b9a8c7d-6e5f-4a3b-8c2d-1e0f9a8b7c6d"],"#,
        r#""items":["3c4d5e6f-7a8b-4c9d-8e0f-1a2b3c4d5e6f"],"version":3}}}"#,
    );

    fn id<T: serde::de::DeserializeOwned>(s: &str) -> T {
        serde_json::from_str(&format!("\"{s}\"")).expect("id")
    }

    #[test]
    fn format_1_is_exactly_this_layout_and_closed() {
        let (agent, project, item) = (
            id::<AgentId>(AGENT),
            id::<ProjectId>(PROJECT),
            id::<ItemId>(ITEM),
        );
        let mut file = RevocationsFile {
            v: 1,
            ..RevocationsFile::default()
        };
        file.agents.insert(
            agent,
            RotationProgress {
                name: "bot".into(),
                rotate: false,
                regrants: [project].into(),
                unknown: true,
                log_unchecked: true,
                items: [item].into(),
                last_error: Some("the server did not answer".into()),
            },
        );
        file.narrowed.insert(
            agent,
            Narrowing {
                name: "bot".into(),
                projects: [project].into(),
                rotated: [project].into(),
                regrants: [project].into(),
                last_error: Some("stopped".into()),
            },
        );
        file.signed.insert(
            agent,
            SignedGrants {
                projects: [project].into(),
                items: [item].into(),
                version: 3,
            },
        );
        assert_eq!(serde_json::to_string(&file).expect("json"), V1_FULL);
        let back: RevocationsFile = serde_json::from_str(V1_FULL).expect("parses");
        assert_eq!(serde_json::to_string(&back).expect("json"), V1_FULL);
        // `klavd`'s no-progress stop (`note_no_progress`) is only a value
        // of the `last_error` both entries already have: the same layout,
        // still `v: 1`, and it names no vault, project or item.
        let stalled = V1_FULL
            .replace("the server did not answer", NO_PROGRESS)
            .replace(
                r#""last_error":"stopped""#,
                &format!(r#""last_error":"{NO_PROGRESS}""#),
            );
        let back: RevocationsFile = serde_json::from_str(&stalled).expect("parses");
        assert_eq!(back.agents[&agent].last_error.as_deref(), Some(NO_PROGRESS));
        assert_eq!(
            back.narrowed[&agent].last_error.as_deref(),
            Some(NO_PROGRESS)
        );
        assert_eq!(serde_json::to_string(&back).expect("json"), stalled);
        // Closed at every level: a field this klav does not know is an
        // error at `v: 1`, never dropped on a rewrite.
        for (from, to) in [
            (r#"{"v":1,"#, r#"{"v":1,"later":1,"#),
            (
                r#"{"name":"bot","rotate""#,
                r#"{"name":"bot","later":1,"rotate""#,
            ),
            (
                r#"{"name":"bot","projects""#,
                r#"{"name":"bot","later":1,"projects""#,
            ),
            (r#""version":3"#, r#""version":3,"later":1"#),
        ] {
            assert_eq!(V1_FULL.matches(from).count(), 1, "{from}");
            let open = V1_FULL.replacen(from, to, 1);
            assert!(
                serde_json::from_str::<RevocationsFile>(&open).is_err(),
                "{open}"
            );
        }
    }

    /// The shortest encodings of format 1, which also become permanent:
    /// an empty record, an entry whose `rotate` is `true` (not written),
    /// a narrowing with nothing rotated, and `signed` with only `version`
    /// (0 is written).
    #[test]
    fn format_1_minimal_encodings_are_exactly_these() {
        let agent = id::<AgentId>(AGENT);
        let empty = RevocationsFile {
            v: 1,
            ..RevocationsFile::default()
        };
        assert_eq!(
            serde_json::to_string(&empty).expect("json"),
            r#"{"v":1,"agents":{}}"#
        );
        let mut file = empty.clone();
        file.agents.insert(
            agent,
            RotationProgress {
                name: "bot".into(),
                rotate: true,
                ..RotationProgress::default()
            },
        );
        file.narrowed.insert(
            agent,
            Narrowing {
                name: "bot".into(),
                ..Narrowing::default()
            },
        );
        file.signed.insert(agent, SignedGrants::default());
        let minimal = format!(
            r#"{{"v":1,"agents":{{"{AGENT}":{{"name":"bot"}}}},"narrowed":{{"{AGENT}":{{"name":"bot","projects":[]}}}},"signed":{{"{AGENT}":{{"version":0}}}}}}"#
        );
        assert_eq!(serde_json::to_string(&file).expect("json"), minimal);
        // Read back, an absent `rotate` is the key change asked for.
        let back: RevocationsFile = serde_json::from_str(&minimal).expect("parses");
        assert!(back.agents[&agent].rotate);
        assert_eq!(back.signed[&agent], SignedGrants::default());
        assert_eq!(serde_json::to_string(&back).expect("json"), minimal);
        let empty_back: RevocationsFile =
            serde_json::from_str(r#"{"v":1,"agents":{}}"#).expect("parses");
        assert!(empty_back.is_empty());
    }

    fn sealed_record(json: &str) -> (tempfile::TempDir, Home, LocalKey, LocalContext) {
        let dir = tempfile::tempdir().expect("tempdir");
        let home = Home::at(dir.path());
        let key = LocalKey::generate();
        let ctx = LocalContext {
            account: AccountId::generate(),
            device: klav_core::ids::DeviceId::generate(),
        };
        let blob = seal_local_data(&key, &ctx, PURPOSE_REVOCATIONS, json.as_bytes()).expect("seal");
        write_private(&home.file(REVOCATIONS_FILE), &blob).expect("write");
        (dir, home, key, ctx)
    }

    #[test]
    fn a_record_from_a_newer_klav_says_to_update_and_is_left_as_it_is() {
        let (_dir, home, key, ctx) = sealed_record(r#"{"v":2,"agents":{},"later":{"x":1}}"#);
        let path = home.file(REVOCATIONS_FILE);
        let before = std::fs::read(&path).expect("read");
        let err = load_record(&home, &key, &ctx).expect_err("newer");
        assert!(matches!(err, ClientError::NewerFormat(_)), "{err:?}");
        let text = err.to_string();
        assert!(
            text.contains("newer version of Klav") && text.contains("Update Klav"),
            "{text}"
        );
        assert!(!text.contains("aside"), "{text}");
        let err = update_record(&home, &key, &ctx, |f| {
            f.signed.entry(id(AGENT)).or_default().version = 1;
        })
        .expect_err("never written");
        assert!(matches!(err, ClientError::NewerFormat(_)), "{err:?}");
        assert_eq!(std::fs::read(&path).expect("read"), before);
    }

    #[test]
    fn a_record_that_does_not_parse_at_a_known_format_says_to_move_it_aside() {
        let (_dir, home, key, ctx) = sealed_record(r#"{"v":1,"later":1}"#);
        let path = home.file(REVOCATIONS_FILE);
        let before = std::fs::read(&path).expect("read");
        let err = load_record(&home, &key, &ctx).expect_err("closed");
        assert!(matches!(err, ClientError::Corrupt(_)), "{err:?}");
        assert!(err.to_string().contains("aside"), "{err}");
        assert!(update_record(&home, &key, &ctx, |_| ()).is_err());
        assert_eq!(std::fs::read(&path).expect("read"), before);
    }
}
