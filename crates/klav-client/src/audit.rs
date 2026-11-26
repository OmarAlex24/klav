//! The audit log as the person reads and checks it (design §6, spec §13.7).
//!
//! `verify` recomputes the hash chain from the stored event bytes, checks
//! every signature an event carries (the agent's signed request, the
//! account's grants and decisions) and every head signed by a device, and
//! compares the chain with the last head this device signed. Then it signs
//! the new head, so later rewrites of anything before it are detected.
//!
//! Nothing the server writes about an event is taken on trust when a
//! signature can back it (ADR 0030 §4): a closed table says, per action,
//! who acts and what proves it; the fields of an event must come from the
//! bytes that were signed; and an agent's key counts only once a grant in
//! the chain, signed by the account, vouches for it.

use std::collections::{HashMap, HashSet};

use klav_core::crypto::agent::{
    self, ApprovalToSign, GrantToSign, PauseScope, PauseToSign, SecretRequestDecisionToSign,
    SignedRequest, TaskDecisionToSign,
};
use klav_core::crypto::audit::{GENESIS, chain_hash, sign_head, verify_head};
use klav_core::crypto::identity::PublicIdentity;
use klav_core::crypto::local::{open_local_data, seal_local_data};
use klav_core::crypto::sandbox::{RevokeScope, RevokeToSign, verify_revoke};
use klav_core::crypto::sign::{SIGNATURE_LEN, Signature};
use klav_core::ids::{AccountId, AgentId, ApprovalId, ItemId, SandboxId, TaskId};
use klav_core::policy::{Permission, normalize_host};
use klav_core::secret_request::SecretRequestDecision;
use klav_core::task::TaskRequest;
use klav_proto::Blob;
use klav_proto::agent::{
    AccessRequest, AgentAsk, AgentCreateItem, AgentTrashItem, AgentUpdateItem, ApprovalRequest,
    GrantPayload,
};
use klav_proto::audit::{
    ActorKind, AgentProof, AgentRoute, AuditEntry, AuditEvent, AuditHeads, AuditPage, SignHead,
    path_id, signed_near,
};
use klav_proto::rotate::{AgentRotateFinish, AgentRotateStart};
// The route rule is in the shared table (`AgentRoute::matches`); the
// tests sign events on it.
#[cfg(test)]
use klav_proto::sandbox::PATH_STORE_RESET;
use klav_proto::sandbox::{
    CHANNEL_KEY_DIGEST_LEN, SandboxClaimed, SandboxEnd, SandboxIssue, SandboxRevoked,
    SandboxStoreReset, all_covers, is_json_object,
};
use klav_proto::secret_request::CreateSecretRequest;
use klav_proto::task::AgentEndTask;
use reqwest::Method;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::api::Body;
use crate::error::{ClientError, ClientResult};
use crate::session::Unlocked;

/// Local file with the last head this device verified and signed.
const PIN_FILE: &str = "audit-head.json";

/// How far the time an agent signed may be from the time the server logged
/// its request (T25: the server refuses requests outside this window).
pub const CLOCK_SKEW_MS: i64 = klav_proto::audit::CLOCK_SKEW_MS;

/// One stored event, parsed.
#[derive(Debug, Clone)]
pub struct Entry {
    /// Position.
    pub seq: u64,
    /// The exact bytes the hash covers.
    pub bytes: Vec<u8>,
    /// The hash the server stored.
    pub hash: [u8; 32],
    /// Parsed event.
    pub event: AuditEvent,
}

/// A head to check the chain against.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pin {
    /// Position.
    pub seq: u64,
    /// Hash at that position.
    #[serde(with = "hex32")]
    pub hash: [u8; 32],
}

/// `audit-head.json`: the last head this device verified, and whose chain
/// it is (ADR 0030 §4.8). Files written before the account was recorded
/// have no `account_id`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct PinFile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    account_id: Option<AccountId>,
    seq: u64,
    #[serde(with = "hex32")]
    hash: [u8; 32],
}

mod hex32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(v: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&v.iter().map(|b| format!("{b:02x}")).collect::<String>())
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let text = String::deserialize(d)?;
        let bytes: Vec<u8> = (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(text.get(i..i + 2).unwrap_or("zz"), 16))
            .collect::<Result<_, _>>()
            .map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 32 bytes"))
    }
}

/// What `verify` checked.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VerifyReport {
    /// Events in the chain.
    pub events: u64,
    /// Agent signatures checked.
    pub agent_signatures: u64,
    /// Account signatures checked (grants, decisions).
    pub account_signatures: u64,
    /// Heads signed by devices that matched.
    pub heads: u64,
    /// The head this device has signed: now, or in an earlier verification
    /// if the log has not grown since (a device does not sign the same head
    /// twice).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_head: Option<u64>,
    /// What could not be checked, without being a sign of tampering: an
    /// agent the server no longer lists, no head pinned on this device, or
    /// an agent action allowed while the agent was paused (ADR 0033 §7.6).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    /// Why this device had no head of its own to hold the chain against,
    /// if it had none. Also in `warnings`, as [`Unpinned::warning`]: this
    /// is the same warning as a code, for the apps to say it in their own
    /// language (ADR 0033 §9).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unpinned: Option<Unpinned>,
    /// The store epoch of each credential proxy's last `sandbox.store_reset`
    /// in the chain (ADR 0036 E3.3, spec §13.12), for proxies whose
    /// signature was checked: a heartbeat counts only under this epoch.
    /// A proxy with no reset in the chain is not here, and none of its
    /// heartbeats count.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub store_epochs: Vec<StoreEpoch>,
    /// Every sandbox issued in the chain by a proxy whose signature was
    /// checked, and where its life stands, in the order they were issued
    /// (ADR 0036 E3.3). For the person's list
    /// ([`crate::sandboxes`]); never serialized, so the report `klavd`
    /// sends and `klav log verify --json` prints do not change.
    #[serde(skip)]
    pub sandboxes: Vec<SandboxRecord>,
}

/// A sandbox as the verified chain shows it (ADR 0036 E3.3). Only the
/// chain decides whether a sandbox is live, ended or revoked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxRecord {
    /// The sandbox.
    pub sandbox_id: SandboxId,
    /// The proxy that issued it.
    pub proxy: AgentId,
    /// The issuer it was issued for, as the proxy signed it.
    pub issuer: AgentId,
    /// The issuer's label, as the proxy signed it (shown "per the issuer").
    pub label: String,
    /// The profiles it may use.
    pub profiles: Vec<String>,
    /// When the server logged its `sandbox.issued` (server clock, ms).
    pub issued_at: i64,
    /// When it expires, as the proxy signed it (ms).
    pub expires_at: i64,
    /// When the server logged its `sandbox.claimed`, if it was claimed.
    pub claimed_at: Option<i64>,
    /// Its `sandbox.revoked`: why, and when the server logged it.
    pub end: Option<(SandboxEnd, i64)>,
    /// The signed `at` of the person's last revocation that covered it.
    pub revoked_by_person_at: Option<i64>,
    /// When the server logged the `agent.revoked` of its proxy, signed by
    /// the account, if the chain has one before the sandbox's issue: that
    /// proxy can never log its end. One issued after it (an older server
    /// logging a request in flight, with the verifier's warning) is not
    /// marked: it stays as it would be without the revocation.
    pub proxy_revoked_at: Option<i64>,
}

/// A proxy's current store epoch, as the chain shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoreEpoch {
    /// The credential proxy.
    pub proxy: AgentId,
    /// The epoch of its last `sandbox.store_reset` (16 bytes).
    pub store_epoch: Blob,
    /// The position of that reset in the chain.
    pub seq: u64,
}

/// Why this device had no pinned head to hold the chain against
/// (ADR 0030 §4.8): the events up to now are trusted as the server sent
/// them, checked only against heads signed by other devices.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Unpinned {
    /// None yet: the first verification on this device.
    Missing,
    /// The pinned head could not be read.
    Unreadable,
    /// The pinned head belongs to another account.
    OtherAccount,
}

impl Unpinned {
    /// The warning in `VerifyReport::warnings`, in English, as `klav log
    /// verify` prints it. `klav-ffi` drops exactly this text from the
    /// warnings it hands the apps, which say it from `unpinned` instead.
    pub fn warning(self) -> String {
        let first = "this device had not verified the log before: the events up to now are \
                     trusted as the server sent them, checked only against heads signed by \
                     other devices";
        match self {
            Self::Missing => first.to_owned(),
            Self::Unreadable => format!("the head pinned on this device is unreadable; {first}"),
            Self::OtherAccount => {
                format!("the head pinned on this device belongs to another account; {first}")
            }
        }
    }
}

/// How every error of a log that does not verify starts, in the words the
/// CLI prints.
const TAMPERED: &str = "audit log: ";

/// A failure of the log's verification, told apart by its type: the
/// sandbox list names it as its own check ([`crate::sandboxes::ListCheck::Log`])
/// without reading the words. Outside this module it is the
/// [`ClientError::Security`] it always was.
#[derive(Debug)]
pub(crate) enum AuditError {
    /// The chain, a head or the copy on this device does not verify.
    Tampered(String),
    /// Anything else (the network, the session).
    Client(ClientError),
}

pub(crate) type AuditResult<T> = Result<T, AuditError>;

impl From<ClientError> for AuditError {
    fn from(e: ClientError) -> Self {
        Self::Client(e)
    }
}

impl From<AuditError> for ClientError {
    fn from(e: AuditError) -> Self {
        match e {
            AuditError::Tampered(message) => Self::Security(format!("{TAMPERED}{message}")),
            AuditError::Client(e) => e,
        }
    }
}

/// The words of the [`ClientError`] it becomes.
impl std::fmt::Display for AuditError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tampered(message) => ClientError::Security(format!("{TAMPERED}{message}")).fmt(f),
            Self::Client(e) => e.fmt(f),
        }
    }
}

pub(crate) fn tampered(message: String) -> AuditError {
    AuditError::Tampered(message)
}

fn sig(blob: &Blob) -> Option<Signature> {
    let bytes: [u8; SIGNATURE_LEN] = blob.as_bytes().try_into().ok()?;
    Some(Signature::from_bytes(bytes))
}

// ------------------------------------------------------------- the table --

/// What backs an event (ADR 0030 §4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Backing {
    /// Attested by the server only (residual risk 10).
    Server,
    /// Signed by the account (spec §13.4–§13.6, §13.8).
    Account,
    /// The agent's signed request (spec §13.3).
    Agent(AgentRoute),
    /// The person settled an agent's password change from the item's card
    /// (ADR 0022 §5): attested by the server, like the person's other
    /// changes, but its agent, task, item and host must be those of a
    /// `rotate.started` the agent signed earlier in the chain.
    PersonRotation,
}

/// Who acts and what backs each action the server writes. An action not in
/// the table is an error.
fn rule(e: &AuditEvent) -> Option<(ActorKind, Backing)> {
    use ActorKind::{Agent, Person};
    // An agent's signed request backs it (the table is shared with the
    // server, which checks it before logging).
    if let Some(route) = AgentRoute::of(e) {
        return Some((Agent, Backing::Agent(route)));
    }
    Some(match e.action.as_str() {
        "agent.registered" => (Agent, Backing::Server),
        "agent.granted"
        | "agent.revoked"
        | "approval.decided"
        | "task.decided"
        | "secret_request.decided" => (Person, Backing::Account),
        // Pauses of agents (ADR 0033 §7, spec §13.9).
        "agents.paused" | "agents.resumed" => (Person, Backing::Account),
        "agent.denied" | "item.created" | "item.updated" | "item.trashed" | "item.restored"
        | "item.purged" | "project.rotated" => (Person, Backing::Server),
        // A device of the person logs a sign-in with a passkey (ADR 0020
        // §10, `POST /v1/audit/person`): only the server attests it, and it
        // never carries a host.
        "passkey.used" => (Person, Backing::Server),
        // A sandbox's life and the proxy's new stores, as the credential
        // proxy signed them (ADR 0036 §9, E3.3, spec §13.12), are in the
        // shared table above; the person's revocation is signed by the
        // account (spec §13.11).
        "sandbox.revoke_requested" => (Person, Backing::Account),
        // The agent's own step is in the shared table above.
        "rotate.confirmed" | "rotate.cancelled" if e.actor == Person => {
            (Person, Backing::PersonRotation)
        }
        "task.ended" => match e.outcome.as_deref()? {
            "person" => (Person, Backing::Account),
            // "agent": in the shared table above.
            // Nobody acted: the server attests the expiry (ADR 0021 §9)
            // and the end a revocation caused (the revocation is signed).
            "expiry" => (Agent, Backing::Server),
            "revocation" => (Person, Backing::Server),
            _ => return None,
        },
        _ => return None,
    })
}

// ---------------------------------------------------------- the verifier --

/// A sandbox issued earlier in the chain (ADR 0036 E3.3).
struct SandboxSeen {
    proxy: AgentId,
    issuer: AgentId,
    /// When it expires, as the proxy signed it (Unix ms).
    expires_at: i64,
    claimed: bool,
    ended: bool,
    /// The `at` of every revocation by the person that covered it so far.
    revoked_at: Vec<i64>,
    /// Whether the proxy's signature on its issue was checked: only those
    /// reach the report.
    checked: bool,
    /// Its position in the chain, for the report's order.
    issued_seq: u64,
    label: String,
    profiles: Vec<String>,
    issued_at: i64,
    claimed_at: Option<i64>,
    end: Option<(SandboxEnd, i64)>,
}

/// The state of one pass over the chain.
struct Verifier<'a> {
    account_id: AccountId,
    account: &'a PublicIdentity,
    /// Agent identities as the server lists them (`GET /v1/agents`).
    listed: &'a HashMap<AgentId, PublicIdentity>,
    /// Agents whose listed identity a verified `agent.granted` vouches for.
    vouched: HashSet<AgentId>,
    /// `(agent, nonce)` pairs seen so far.
    nonces: HashSet<(AgentId, [u8; 16])>,
    /// Agents already warned about.
    warned: HashSet<AgentId>,
    /// `(agent, task, item, host)` of every allowed `rotate.started` so
    /// far: a later step of a change must name one of them.
    rotations: HashSet<(AgentId, TaskId, ItemId, String)>,
    /// The last pause or resume of each scope (`None`: every agent), as
    /// signed: each new one must be later (spec §13.9).
    pause_clock: HashMap<Option<AgentId>, i64>,
    /// Every sandbox issued so far, and where its life stands.
    sandboxes: HashMap<SandboxId, SandboxSeen>,
    /// The last revocation by the person of each proxy and scope (`None`:
    /// `all`), as signed: each new one must be later (spec §13.11).
    revoke_clock: HashMap<(AgentId, Option<SandboxId>), i64>,
    /// Every `(proxy, store epoch)` a `sandbox.store_reset` named so far:
    /// a proxy never starts the same epoch twice.
    store_epochs: HashSet<(AgentId, Vec<u8>)>,
    /// Pauses signed so far and not resumed, by scope: when each one ends
    /// (`0`: until a resume).
    paused: HashMap<Option<AgentId>, i64>,
    /// Agents whose `agent.revoked`, signed by the account, came earlier in
    /// the chain, with the position and the time the server logged the
    /// first one.
    revoked: HashMap<AgentId, (u64, i64)>,
    /// Approvals the account signed for an environment and its protected
    /// items (ADR 0032 §3.1), earlier in the chain: the agent, the
    /// permission, the environment and the other items it lists.
    bundles: HashMap<ApprovalId, (AgentId, Permission, Option<ItemId>, Vec<ItemId>)>,
    report: VerifyReport,
}

impl Verifier<'_> {
    fn unlisted(&mut self, agent: AgentId) {
        if self.warned.insert(agent) {
            self.report.warnings.push(format!(
                "agent {agent} is not in the server's list of agents: its signatures \
                 could not be checked"
            ));
        }
    }

    fn event(&mut self, entry: &Entry) -> AuditResult<()> {
        let e = &entry.event;
        let seq = entry.seq;
        let (actor, backing) = rule(e).ok_or_else(|| {
            tampered(format!(
                "event {seq} has an unknown action ({}{})",
                e.action,
                e.outcome
                    .as_deref()
                    .map(|o| format!(", {o}"))
                    .unwrap_or_default()
            ))
        })?;
        if e.actor != actor {
            return Err(tampered(format!(
                "event {seq} ({}) names the wrong actor",
                e.action
            )));
        }
        // Only a pause has an end, and its signature covers it.
        if e.until.is_some() && e.action != "agents.paused" {
            return Err(tampered(format!(
                "event {seq} ({}) claims an end nobody signed",
                e.action
            )));
        }
        // Only the person's revocation names sandboxes this way: the
        // account signs the one, and the chain backs the list.
        if e.action != "sandbox.revoke_requested"
            && (e.sandbox_id.is_some() || !e.sandbox_ids.is_empty())
        {
            return Err(tampered(format!(
                "event {seq} ({}) names a sandbox nobody signed",
                e.action
            )));
        }
        // Only secret request events carry a secret request ID or proposal digest.
        if !matches!(
            e.action.as_str(),
            "secret_request.created" | "secret_request.decided"
        ) && (e.secret_request_id.is_some() || e.proposal_digest.is_some())
        {
            return Err(tampered(format!(
                "event {seq} ({}) names a secret request nobody signed",
                e.action
            )));
        }
        if e.agent_proof.is_some() && !matches!(backing, Backing::Agent(_)) {
            return Err(tampered(format!(
                "event {seq} ({}) carries an agent request it does not take",
                e.action
            )));
        }
        if backing != Backing::Account
            && (e.account_signature.is_some() || e.signed.is_some() || e.task_request.is_some())
        {
            return Err(tampered(format!(
                "event {seq} ({}) carries a signature it does not take",
                e.action
            )));
        }
        let checked = match backing {
            Backing::Server => {
                // Nothing signed backs a permission, a reason or a host.
                if e.permission.is_some()
                    || e.reason.is_some()
                    || e.domain.is_some()
                    || e.method.is_some()
                    || e.path.is_some()
                {
                    return Err(tampered(format!(
                        "event {seq} ({}) claims what nobody signed",
                        e.action
                    )));
                }
                Ok(())
            }
            Backing::PersonRotation => {
                if e.permission.is_some() || e.reason.is_some() {
                    return Err(tampered(format!(
                        "event {seq} ({}) claims what nobody signed",
                        e.action
                    )));
                }
                self.started_change(entry)
            }
            Backing::Account => self.account_signature(entry),
            Backing::Agent(route) => {
                self.agent_proof(entry, route)?;
                match route {
                    AgentRoute::RotateStart => self.change_started(entry),
                    AgentRoute::RotateFinish => self.started_change(entry),
                    r if r.is_sandbox() => self.sandbox_step(entry, r),
                    _ => Ok(()),
                }
            }
        };
        checked?;
        // The agent's own steps of a password change count too, a cancel
        // included: the server refuses every signed request of a paused
        // agent (ADR 0033 §7.4). The person's step is not the agent's.
        if let Backing::Agent(
            AgentRoute::Access
            | AgentRoute::Create
            | AgentRoute::Update
            | AgentRoute::Trash
            | AgentRoute::RotateStart
            | AgentRoute::RotateFinish,
        ) = backing
        {
            self.used_while_paused(entry);
        }
        if backing == Backing::Agent(AgentRoute::Access) {
            self.used_after_revocation(entry);
            self.bundle_use(entry)?;
        }
        if let Backing::Agent(_) = backing {
            self.after_agent_revoked(entry);
        }
        Ok(())
    }

    /// An allowed access under an environment's approval (ADR 0032 §3.1)
    /// must be by that agent, with that permission, on the environment or
    /// one of the items the account signed in its request: an item it does
    /// not list never rides on it.
    fn bundle_use(&self, entry: &Entry) -> AuditResult<()> {
        let e = &entry.event;
        if e.outcome.as_deref() != Some("allow") {
            return Ok(());
        }
        let Some(approval) = e.approval_id else {
            return Ok(());
        };
        let Some((agent, permission, item, items)) = self.bundles.get(&approval) else {
            return Ok(());
        };
        let listed = e
            .item_id
            .is_some_and(|i| Some(i) == *item || items.contains(&i));
        if e.agent_id != Some(*agent) || e.permission != Some(*permission) || !listed {
            return Err(tampered(format!(
                "event {} ({}): it used approval {approval}, which the account signed for other items",
                entry.seq, e.action
            )));
        }
        Ok(())
    }

    /// Warns of an event the agent signed after the account revoked that
    /// agent, whatever its outcome: after it in the chain, whatever the
    /// times the server wrote. A server that checks, under the account's
    /// lock (the one the revocation takes), that the agent is still active
    /// as it logs the event never logs one; an older server, or an older
    /// instance during a deploy, could log a request in flight when the
    /// revocation came. That is honest, so it is a warning, never a
    /// failure.
    fn after_agent_revoked(&mut self, entry: &Entry) {
        let e = &entry.event;
        let Some(agent) = e.agent_id else {
            return;
        };
        if self.revoked.contains_key(&agent) {
            self.report.warnings.push(format!(
                "event {} ({}): agent {agent} acted after its revocation (an older server \
                 could log a request already in flight, so this is a warning, not a failure)",
                entry.seq, e.action
            ));
        }
    }

    /// Warns of an allowed call for a sandbox after the person's revocation
    /// of it (ADR 0036 E3.3), as of an access during a pause: the server
    /// checks the revocation in the transaction that logs the call, so an
    /// honest chain never has one.
    fn used_after_revocation(&mut self, entry: &Entry) {
        let e = &entry.event;
        if e.outcome.as_deref() != Some("allow") {
            return;
        }
        let Some(sandbox) = e
            .agent_proof
            .as_ref()
            .and_then(|p| p.body.as_ref())
            .and_then(|b| serde_json::from_slice::<AccessRequest>(b.as_bytes()).ok())
            .and_then(|req| req.sandbox)
        else {
            return;
        };
        if self
            .sandboxes
            .get(&sandbox)
            .is_some_and(|s| !s.revoked_at.is_empty())
        {
            self.report.warnings.push(format!(
                "event {} ({}): a call for sandbox {sandbox} was allowed after the person \
                 revoked it",
                entry.seq, e.action
            ));
        }
    }

    /// The person's revocation of sandboxes (spec §13.11): the account's
    /// signature over the proxy, the scope and the time, a time later than
    /// the last revocation of the same proxy and scope, a sandbox that proxy
    /// issued earlier in the chain or, with `all`, exactly the list of its
    /// sandboxes the chain issued before, not ended and not expired.
    fn revoke_signature(&mut self, entry: &Entry, signature: &Signature) -> AuditResult<()> {
        let e = &entry.event;
        let seq = entry.seq;
        let differs = |what: &str| {
            tampered(format!(
                "event {seq} ({}): the {what} differs from what the account signed",
                e.action
            ))
        };
        let fail = |what: &str| tampered(format!("event {seq} ({}) {what}", e.action));
        if e.item_id.is_some()
            || e.permission.is_some()
            || e.domain.is_some()
            || e.method.is_some()
            || e.path.is_some()
            || e.vault_id.is_some()
            || e.project_id.is_some()
            || !e.attachments.is_empty()
        {
            return Err(differs("target"));
        }
        if e.reason.is_some()
            || e.signed.is_some()
            || e.task_request.is_some()
            || e.outcome.is_some()
            || e.task_id.is_some()
            || e.approval_id.is_some()
            || e.lease_until.is_some()
        {
            return Err(differs("data"));
        }
        let proxy = e.agent_id.ok_or_else(|| fail("names no proxy"))?;
        let at = e.decided_at.ok_or_else(|| fail("has no time"))?;
        // The signed time decides which sandboxes an `all` covers
        // ([`all_covers`]); the event's own time, which nobody signs, must
        // still be within the clock window of it, as the server checks it
        // against the same clock reading it logs the event with (spec
        // §13.11).
        if e.at.abs_diff(at) > CLOCK_SKEW_MS.unsigned_abs() {
            return Err(fail("was logged too far from when the person signed it"));
        }
        if e.sandbox_id.is_some() && !e.sandbox_ids.is_empty() {
            return Err(differs("sandboxes"));
        }
        let ok = verify_revoke(
            self.account,
            &RevokeToSign {
                account: self.account_id,
                proxy,
                scope: e.sandbox_id.map_or(RevokeScope::All, RevokeScope::Sandbox),
                at_ms: u64::try_from(at).map_err(|_| differs("time"))?,
            },
            signature,
        )
        .is_ok();
        if !ok {
            return Err(tampered(format!(
                "event {seq} ({}): the account's signature does not verify",
                e.action
            )));
        }
        let scope = (proxy, e.sandbox_id);
        if self
            .revoke_clock
            .get(&scope)
            .is_some_and(|&last| at <= last)
        {
            return Err(fail(
                "is not later than the last revocation of the same sandboxes: a revocation \
                 was replayed",
            ));
        }
        let covered = match e.sandbox_id {
            Some(id) => {
                if !self.sandboxes.get(&id).is_some_and(|s| s.proxy == proxy) {
                    return Err(fail(
                        "names no sandbox that proxy issued earlier in the log",
                    ));
                }
                vec![id]
            }
            None => {
                let mut live: Vec<SandboxId> = self
                    .sandboxes
                    .iter()
                    .filter(|(_, s)| s.proxy == proxy && !s.ended && all_covers(s.expires_at, at))
                    .map(|(id, _)| *id)
                    .collect();
                live.sort();
                if e.sandbox_ids != live {
                    return Err(fail(
                        "lists other sandboxes than that proxy's live ones earlier in the log",
                    ));
                }
                live
            }
        };
        self.revoke_clock.insert(scope, at);
        for id in covered {
            if let Some(seen) = self.sandboxes.get_mut(&id) {
                seen.revoked_at.push(at);
            }
        }
        self.report.account_signatures += 1;
        Ok(())
    }

    /// Warns of an agent action allowed while the agent was paused: after
    /// a signed pause of its scope (or of every agent) and before the
    /// signed resume of that scope or the pause's end (ADR 0033 §7.6). A
    /// warning and not an error: the server orders the chain, and a request
    /// it evaluated before the pause may land right after it.
    fn used_while_paused(&mut self, entry: &Entry) {
        let e = &entry.event;
        let Some(agent) = e.agent_id else {
            return;
        };
        if e.outcome.as_deref() != Some("allow") {
            return;
        }
        let held = [None, Some(agent)].into_iter().any(|scope| {
            self.paused
                .get(&scope)
                .is_some_and(|&until| until == 0 || e.at < until)
        });
        if held {
            self.report.warnings.push(format!(
                "event {} ({}): agent {agent} was allowed while it was paused",
                entry.seq, e.action
            ));
        }
    }

    /// A pause or a resume (spec §13.9): the account's signature over the
    /// scope, the state, the time and the end the event says, a time later
    /// than the last decision on the same scope, and nothing else claimed.
    fn pause_signature(&mut self, entry: &Entry, signature: &Signature) -> AuditResult<()> {
        let e = &entry.event;
        let seq = entry.seq;
        let differs = |what: &str| {
            tampered(format!(
                "event {seq} ({}): the {what} differs from what the account signed",
                e.action
            ))
        };
        if e.item_id.is_some()
            || e.permission.is_some()
            || e.domain.is_some()
            || e.method.is_some()
            || e.path.is_some()
            || e.vault_id.is_some()
            || e.project_id.is_some()
        {
            return Err(differs("target"));
        }
        if e.reason.is_some() || e.signed.is_some() || e.task_request.is_some() {
            return Err(differs("data"));
        }
        let pause = e.action == "agents.paused";
        // A pause without an end has no `until` at all: `Some(0)` would
        // sign the same bytes as `None`, so only one of them is canonical.
        if (!pause && e.until.is_some()) || e.until == Some(0) {
            return Err(differs("end"));
        }
        let at = e
            .decided_at
            .ok_or_else(|| tampered(format!("event {seq} ({}): no time", e.action)))?;
        let until = e.until.unwrap_or(0);
        let ok = agent::verify_pause(
            self.account,
            &PauseToSign {
                account: self.account_id,
                scope: e.agent_id.map_or(PauseScope::All, PauseScope::Agent),
                pause,
                at_ms: u64::try_from(at).map_err(|_| differs("time"))?,
                until_ms: u64::try_from(until).map_err(|_| differs("end"))?,
            },
            signature,
        )
        .is_ok();
        if !ok {
            return Err(tampered(format!(
                "event {seq} ({}): the account's signature does not verify",
                e.action
            )));
        }
        if self
            .pause_clock
            .get(&e.agent_id)
            .is_some_and(|&last| at <= last)
        {
            return Err(tampered(format!(
                "event {seq} ({}) is not later than the last pause or resume of the same agents: \
                 a decision was replayed",
                e.action
            )));
        }
        self.pause_clock.insert(e.agent_id, at);
        if pause {
            self.paused.insert(e.agent_id, until);
        } else {
            self.paused.remove(&e.agent_id);
        }
        self.report.account_signatures += 1;
        Ok(())
    }

    /// A step of a sandbox's life (ADR 0036 E3.3), its body already
    /// checked: an issue of a new sandbox; a claim or an end only of a
    /// sandbox the same proxy issued earlier in the chain, each once, and
    /// `theft` or `released` only after its claim. An issue or a claim
    /// while the proxy or the issuer was paused is a warning, like an
    /// allowed access.
    fn sandbox_step(&mut self, entry: &Entry, route: AgentRoute) -> AuditResult<()> {
        let e = &entry.event;
        let seq = entry.seq;
        let fail = |what: &str| tampered(format!("event {seq} ({}) {what}", e.action));
        let proof = e
            .agent_proof
            .as_ref()
            .ok_or_else(|| fail("lacks the proxy's signed request"))?;
        let proxy = e.agent_id.ok_or_else(|| fail("names no proxy"))?;
        let body = proof
            .body
            .as_ref()
            .ok_or_else(|| fail("lacks the body the proxy signed"))?;
        let issuer = match route {
            AgentRoute::SandboxStoreReset => {
                return self.store_reset(entry, proxy, body.as_bytes());
            }
            AgentRoute::SandboxIssue => {
                let req: SandboxIssue = parse_body(entry, body.as_bytes())?;
                if self.sandboxes.contains_key(&req.sandbox_id) {
                    return Err(fail("issues a sandbox already issued"));
                }
                self.sandboxes.insert(
                    req.sandbox_id,
                    SandboxSeen {
                        proxy,
                        issuer: req.issuer_id,
                        expires_at: req.expires_at,
                        claimed: false,
                        ended: false,
                        revoked_at: Vec::new(),
                        checked: self.vouched.contains(&proxy),
                        issued_seq: seq,
                        label: req.label,
                        profiles: req.profiles,
                        issued_at: e.at,
                        claimed_at: None,
                        end: None,
                    },
                );
                req.issuer_id
            }
            _ => {
                let suffix = if route == AgentRoute::SandboxClaim {
                    "/claimed"
                } else {
                    "/revoked"
                };
                let id: SandboxId = path_id(&proof.path, "/v1/agent/sandboxes/", suffix)
                    .ok_or_else(|| fail("names no sandbox"))?;
                let seen = self
                    .sandboxes
                    .get_mut(&id)
                    .filter(|s| s.proxy == proxy)
                    .ok_or_else(|| fail("names no sandbox that proxy issued earlier in the log"))?;
                if seen.ended {
                    return Err(fail("comes after the sandbox's end"));
                }
                if route == AgentRoute::SandboxClaim {
                    if seen.claimed {
                        return Err(fail("claims a sandbox claimed before"));
                    }
                    seen.claimed = true;
                    seen.claimed_at = Some(e.at);
                    if !seen.revoked_at.is_empty() {
                        let issuer = seen.issuer;
                        self.report.warnings.push(format!(
                            "event {seq} ({}): sandbox {id} was claimed after the person \
                             revoked it",
                            e.action
                        ));
                        return self.held_step(entry, proxy, issuer);
                    }
                } else {
                    let req = parse_end(entry, body.as_bytes())?;
                    if req.reason.needs_claim() && !seen.claimed {
                        return Err(fail("ends with a reason only a claimed sandbox has"));
                    }
                    // `person` answers a revocation of this sandbox by the
                    // person, earlier in the chain, with its `at`.
                    if let (SandboxEnd::Person, Some(at)) = (req.reason, req.at)
                        && !seen.revoked_at.contains(&at)
                    {
                        return Err(fail(
                            "answers no revocation by the person of that sandbox earlier in \
                             the log",
                        ));
                    }
                    seen.ended = true;
                    seen.end = Some((req.reason, e.at));
                    return Ok(());
                }
                seen.issuer
            }
        };
        self.held_step(entry, proxy, issuer)
    }

    /// A proxy's new store (spec §13.12): an epoch that proxy never named
    /// before in the chain, which becomes its current one. Only a proxy
    /// whose signature was checked gets a current epoch in the report:
    /// the device checks heartbeats with the key a grant vouched for.
    fn store_reset(&mut self, entry: &Entry, proxy: AgentId, body: &[u8]) -> AuditResult<()> {
        let req: SandboxStoreReset = parse_body(entry, body)?;
        let epoch = req.store_epoch.as_bytes().to_vec();
        if !self.store_epochs.insert((proxy, epoch)) {
            return Err(tampered(format!(
                "event {} ({}) starts a store epoch that proxy started before",
                entry.seq, entry.event.action
            )));
        }
        // The server refuses every signed request of a paused proxy but
        // `me` (ADR 0033 §7.4), so an honest chain has no reset then.
        let at = entry.event.at;
        let held = [None, Some(proxy)].into_iter().any(|scope| {
            self.paused
                .get(&scope)
                .is_some_and(|&until| until == 0 || at < until)
        });
        if held {
            self.report.warnings.push(format!(
                "event {} ({}): proxy {proxy} was paused",
                entry.seq, entry.event.action
            ));
        }
        let current = &mut self.report.store_epochs;
        current.retain(|s| s.proxy != proxy);
        if self.vouched.contains(&proxy) {
            current.push(StoreEpoch {
                proxy,
                store_epoch: req.store_epoch,
                seq: entry.seq,
            });
        }
        Ok(())
    }

    /// Warns of a sandbox's issue or claim while the proxy or the issuer
    /// was paused.
    fn held_step(&mut self, entry: &Entry, proxy: AgentId, issuer: AgentId) -> AuditResult<()> {
        let e = &entry.event;
        let held = [None, Some(proxy), Some(issuer)].into_iter().any(|scope| {
            self.paused
                .get(&scope)
                .is_some_and(|&until| until == 0 || e.at < until)
        });
        if held {
            self.report.warnings.push(format!(
                "event {} ({}): the proxy or the issuer {issuer} was paused",
                entry.seq, e.action
            ));
        }
        Ok(())
    }

    /// Remembers an allowed `rotate.started` (its body already checked).
    fn change_started(&mut self, entry: &Entry) -> AuditResult<()> {
        let e = &entry.event;
        if e.outcome.as_deref() != Some("allow") {
            return Ok(());
        }
        // `rotate` only passes inside a task (ADR 0021 §5).
        match (e.agent_id, e.task_id, e.item_id, e.domain.clone()) {
            (Some(agent), Some(task), Some(item), Some(host)) => {
                self.rotations.insert((agent, task, item, host));
                Ok(())
            }
            _ => Err(tampered(format!(
                "event {} ({}) lets a change start without its task, item or host",
                entry.seq, e.action
            ))),
        }
    }

    /// A step of a change (the agent's confirm or cancel, or the person's
    /// decision): its agent, item and host, and its task when it names
    /// one, must be those of an allowed `rotate.started` before it. The
    /// host is not in what the agent signs for these steps; this is what
    /// backs it.
    fn started_change(&self, entry: &Entry) -> AuditResult<()> {
        let e = &entry.event;
        let found = match (e.agent_id, e.item_id, e.domain.as_deref()) {
            (Some(agent), Some(item), Some(host)) => match e.task_id {
                Some(task) => self
                    .rotations
                    .contains(&(agent, task, item, host.to_owned())),
                // An agent's step the gate refused may name no task.
                None => {
                    e.actor == ActorKind::Agent
                        && e.outcome.as_deref() != Some("allow")
                        && self
                            .rotations
                            .iter()
                            .any(|(a, _, i, h)| *a == agent && *i == item && h == host)
                }
            },
            _ => false,
        };
        if found {
            Ok(())
        } else {
            Err(tampered(format!(
                "event {} ({}) names no change started earlier in the log by that agent, task, item and host",
                entry.seq, e.action
            )))
        }
    }

    /// Checks that an agent's signed request backs the event.
    fn agent_proof(&mut self, entry: &Entry, route: AgentRoute) -> AuditResult<()> {
        let e = &entry.event;
        let seq = entry.seq;
        let proof = e.agent_proof.as_ref().ok_or_else(|| {
            tampered(format!(
                "event {seq} ({}) lacks the agent's signed request",
                e.action
            ))
        })?;
        let agent = e
            .agent_id
            .ok_or_else(|| tampered(format!("event {seq} has a proof but no agent")))?;
        check_route(entry, proof, route)?;
        let digest: [u8; 32] = proof
            .body_digest
            .as_bytes()
            .try_into()
            .map_err(|_| tampered(format!("event {seq}: bad body digest")))?;
        let nonce: [u8; 16] = proof
            .nonce
            .as_bytes()
            .try_into()
            .map_err(|_| tampered(format!("event {seq}: bad nonce")))?;
        let signature =
            sig(&proof.signature).ok_or_else(|| tampered(format!("event {seq}: bad signature")))?;
        match &proof.body {
            Some(body) => {
                if agent::body_digest(body.as_bytes()) != digest {
                    return Err(tampered(format!("event {seq}: body and digest differ")));
                }
                check_body(entry, route, body.as_bytes())?;
            }
            None if route.needs_body() => {
                return Err(tampered(format!(
                    "event {seq} ({}) lacks the body the agent signed",
                    e.action
                )));
            }
            None => check_fields_without_body(entry, route)?,
        }
        // T25: one request, one event; signed close to when it was logged.
        if !self.nonces.insert((agent, nonce)) {
            return Err(tampered(format!(
                "event {seq}: the agent's request was already used by an earlier event"
            )));
        }
        if !signed_near(proof.timestamp, e.at) {
            return Err(tampered(format!(
                "event {seq}: the agent signed its request too far from when it was logged"
            )));
        }
        if !self.vouched.contains(&agent) {
            if self.listed.contains_key(&agent) {
                return Err(tampered(format!(
                    "event {seq}: no grant in the chain vouches for agent {agent}'s key"
                )));
            }
            self.unlisted(agent);
            return Ok(());
        }
        let public = self
            .listed
            .get(&agent)
            .ok_or_else(|| tampered(format!("event {seq}: unknown agent {agent}")))?;
        agent::verify_request(
            public,
            &SignedRequest {
                agent,
                method: &proof.method,
                path: &proof.path,
                timestamp_ms: u64::try_from(proof.timestamp).unwrap_or(0),
                nonce: &nonce,
                body_digest: &digest,
            },
            &signature,
        )
        .map_err(|_| {
            tampered(format!(
                "event {seq}: the agent's signature does not verify"
            ))
        })?;
        self.report.agent_signatures += 1;
        Ok(())
    }

    /// Checks the account signature an event must carry, and that what the
    /// event says comes from the signed bytes.
    fn account_signature(&mut self, entry: &Entry) -> AuditResult<()> {
        let e = &entry.event;
        let seq = entry.seq;
        let signature = e.account_signature.as_ref().ok_or_else(|| {
            tampered(format!(
                "event {seq} ({}) lacks the account's signature",
                e.action
            ))
        })?;
        let signature =
            sig(signature).ok_or_else(|| tampered(format!("event {seq}: bad signature")))?;
        if matches!(e.action.as_str(), "agents.paused" | "agents.resumed") {
            return self.pause_signature(entry, &signature);
        }
        if e.action == "sandbox.revoke_requested" {
            return self.revoke_signature(entry, &signature);
        }
        if e.action == "secret_request.decided" {
            return self.secret_request_decision_signature(entry, &signature);
        }
        let agent_id = e
            .agent_id
            .ok_or_else(|| tampered(format!("event {seq}: no agent")))?;
        let differs = |what: &str| {
            tampered(format!(
                "event {seq} ({}): the {what} differs from what the account signed",
                e.action
            ))
        };
        let signed = || {
            e.signed
                .as_ref()
                .ok_or_else(|| tampered(format!("event {seq}: signature without data")))
        };
        let decided_at = || u64::try_from(e.decided_at.unwrap_or(0)).unwrap_or(0);
        if e.action != "approval.decided"
            && (e.item_id.is_some()
                || e.permission.is_some()
                || e.domain.is_some()
                || e.method.is_some()
                || e.path.is_some())
        {
            return Err(differs("target"));
        }
        if e.reason.is_some() && e.action != "approval.decided" {
            return Err(differs("reason"));
        }
        if e.action != "task.decided" && e.task_request.is_some() {
            return Err(differs("task request"));
        }
        if matches!(e.action.as_str(), "agent.revoked" | "task.ended") && e.signed.is_some() {
            return Err(differs("data"));
        }
        let ok = match e.action.as_str() {
            "agent.granted" => {
                let signed = signed()?;
                let payload: GrantPayload = serde_json::from_slice(signed.as_bytes())
                    .map_err(|_| tampered(format!("event {seq}: the grant is not readable")))?;
                if payload.account_id != self.account_id || payload.agent_id != agent_id {
                    return Err(differs("agent"));
                }
                let Some(public) = self.listed.get(&agent_id) else {
                    // The grant's signature covers the agent's key; without
                    // it nothing can be checked, and nothing is vouched.
                    self.unlisted(agent_id);
                    return Ok(());
                };
                let ok = agent::verify_grant(
                    self.account,
                    &GrantToSign {
                        account: self.account_id,
                        agent: agent_id,
                        agent_public: public,
                        payload: signed.as_bytes(),
                    },
                    &signature,
                )
                .is_ok();
                if ok {
                    self.vouched.insert(agent_id);
                }
                ok
            }
            "approval.decided" => {
                let approval = e
                    .approval_id
                    .ok_or_else(|| tampered(format!("event {seq}: no approval")))?;
                let signed = signed()?;
                let request: ApprovalRequest =
                    serde_json::from_slice(signed.as_bytes()).map_err(|_| {
                        tampered(format!("event {seq}: the approval request is not readable"))
                    })?;
                if request.approval_id != approval || request.agent_id != agent_id {
                    return Err(differs("approval"));
                }
                if e.vault_id != Some(request.vault_id)
                    || e.project_id != Some(request.project_id)
                    || e.item_id != request.item_id
                {
                    return Err(differs("item"));
                }
                if e.permission != Some(request.permission) {
                    return Err(differs("permission"));
                }
                if e.reason.as_ref().is_some_and(|r| *r != request.reason) {
                    return Err(differs("reason"));
                }
                if e.domain.is_some() && e.domain != request.claims.domain {
                    return Err(differs("host"));
                }
                if e.method.is_some() && e.method != request.claims.method {
                    return Err(differs("method"));
                }
                if e.path.is_some() && e.path != request.claims.path {
                    return Err(differs("path"));
                }
                // ADR 0049 §5.4 (T260): the server refuses a tool or a
                // caller outside its grammar before it stores the request.
                if !crate::agents::approval_mcp_ok(&request) {
                    return Err(tampered(format!(
                        "event {seq}: the approval request names an MCP tool or caller the server never accepts"
                    )));
                }
                let approve = e.outcome.as_deref() == Some("approve");
                let ok = agent::verify_approval(
                    self.account,
                    &ApprovalToSign {
                        approval,
                        agent: agent_id,
                        request: signed.as_bytes(),
                        approve,
                        lease_until_ms: u64::try_from(e.lease_until.unwrap_or(0)).unwrap_or(0),
                        decided_at_ms: decided_at(),
                    },
                    &signature,
                )
                .is_ok();
                if ok && approve && !request.items.is_empty() {
                    self.bundles.insert(
                        approval,
                        (agent_id, request.permission, request.item_id, request.items),
                    );
                }
                ok
            }
            "task.decided" => {
                let task = e
                    .task_id
                    .ok_or_else(|| tampered(format!("event {seq}: no task")))?;
                let request = e
                    .task_request
                    .as_ref()
                    .ok_or_else(|| tampered(format!("event {seq}: no task request")))?;
                agent::verify_task_decision(
                    self.account,
                    &TaskDecisionToSign {
                        task,
                        agent: agent_id,
                        request: request.as_bytes(),
                        decision: signed()?.as_bytes(),
                        approve: e.outcome.as_deref() == Some("approve"),
                        decided_at_ms: decided_at(),
                    },
                    &signature,
                )
                .is_ok()
            }
            "task.ended" => {
                let task = e
                    .task_id
                    .ok_or_else(|| tampered(format!("event {seq}: no task")))?;
                agent::verify_task_end(
                    self.account,
                    self.account_id,
                    task,
                    agent_id,
                    decided_at(),
                    &signature,
                )
                .is_ok()
            }
            "agent.revoked" => agent::verify_revocation(
                self.account,
                self.account_id,
                agent_id,
                decided_at(),
                &signature,
            )
            .is_ok(),
            other => {
                return Err(tampered(format!(
                    "event {seq}: no rule for the account's signature on {other}"
                )));
            }
        };
        if !ok {
            return Err(tampered(format!(
                "event {seq} ({}): the account's signature does not verify",
                e.action
            )));
        }
        if e.action == "agent.revoked" {
            self.revoked.entry(agent_id).or_insert((seq, e.at));
        }
        self.report.account_signatures += 1;
        Ok(())
    }

    /// A person's decision on a secret request (ADR 0046, spec §13.14): the
    /// account's signature over `(account_id, request_id, agent_id,
    /// proposal_digest, decision, decided_at_ms)` and event fields matching the
    /// signed [`SecretRequestDecision`].
    fn secret_request_decision_signature(
        &mut self,
        entry: &Entry,
        signature: &Signature,
    ) -> AuditResult<()> {
        let e = &entry.event;
        let seq = entry.seq;
        let differs = |what: &str| {
            tampered(format!(
                "event {seq} ({}): the {what} differs from what the account signed",
                e.action
            ))
        };
        if e.permission.is_some()
            || e.domain.is_some()
            || e.method.is_some()
            || e.path.is_some()
            || e.reason.is_some()
            || e.task_id.is_some()
            || e.approval_id.is_some()
            || e.lease_until.is_some()
            || e.task_request.is_some()
            || !e.attachments.is_empty()
        {
            return Err(differs("data"));
        }
        let request = e
            .secret_request_id
            .ok_or_else(|| tampered(format!("event {seq}: no secret request")))?;
        let agent = e
            .agent_id
            .ok_or_else(|| tampered(format!("event {seq}: no agent")))?;
        let digest: [u8; 32] = e
            .proposal_digest
            .as_ref()
            .and_then(|d| d.as_bytes().try_into().ok())
            .ok_or_else(|| tampered(format!("event {seq}: bad proposal digest")))?;
        let signed = e
            .signed
            .as_ref()
            .ok_or_else(|| tampered(format!("event {seq}: signature without data")))?;
        let decided_at = e
            .decided_at
            .and_then(|t| u64::try_from(t).ok())
            .ok_or_else(|| tampered(format!("event {seq}: no decided_at")))?;
        let decision: SecretRequestDecision =
            serde_json::from_slice(signed.as_bytes()).map_err(|_| {
                tampered(format!(
                    "event {seq}: the secret request decision is not readable"
                ))
            })?;
        decision.validate().map_err(|_| differs("decision"))?;
        if decision.request_id != request || decision.agent_id != agent {
            return Err(differs("secret request"));
        }
        if e.outcome.as_deref() != Some(decision.status.as_str()) {
            return Err(differs("outcome"));
        }
        if e.vault_id != decision.vault_id
            || e.project_id != decision.project_id
            || e.item_id != decision.item_id
        {
            return Err(differs("target"));
        }
        let ok = agent::verify_secret_request_decision(
            self.account,
            &SecretRequestDecisionToSign {
                request,
                agent,
                proposal_digest: &digest,
                decision: signed.as_bytes(),
                decided_at_ms: decided_at,
            },
            signature,
        )
        .is_ok();
        if !ok {
            return Err(tampered(format!(
                "event {seq} ({}): the account's signature does not verify",
                e.action
            )));
        }
        self.report.account_signatures += 1;
        Ok(())
    }
}

/// The signed method and route must be the action's (ADR 0030 §4.3); the
/// item or task in the route must be the event's.
fn check_route(entry: &Entry, proof: &AgentProof, route: AgentRoute) -> AuditResult<()> {
    let e = &entry.event;
    let ok = route.matches(e, proof);
    if ok {
        Ok(())
    } else {
        Err(tampered(format!(
            "event {} ({}): the agent signed `{} {}`, not this action",
            entry.seq, e.action, proof.method, proof.path
        )))
    }
}

fn parse_body<T: DeserializeOwned>(entry: &Entry, body: &[u8]) -> AuditResult<T> {
    serde_json::from_slice(body).map_err(|_| {
        tampered(format!(
            "event {} ({}): the signed body is not the action's request",
            entry.seq, entry.event.action
        ))
    })
}

/// The body of a `sandbox.revoked`: `at` with `person`, and only with it
/// (anything else is not a request of this action).
fn parse_end(entry: &Entry, body: &[u8]) -> AuditResult<SandboxRevoked> {
    let req: SandboxRevoked = parse_body(entry, body)?;
    // The person's reasons only as an object: the server refuses the array
    // form serde also reads (older reasons keep what earlier verifiers took).
    let person = matches!(req.reason, SandboxEnd::Person | SandboxEnd::PersonLocal);
    if req.check_format().is_err() || (person && !is_json_object(body)) {
        return parse_body::<SandboxRevoked>(entry, b"");
    }
    Ok(req)
}

/// The permission each item-writing action implies.
fn route_permission(route: AgentRoute) -> Option<Permission> {
    match route {
        AgentRoute::Create => Some(Permission::Create),
        AgentRoute::Update => Some(Permission::Update),
        AgentRoute::Trash => Some(Permission::Delete),
        AgentRoute::RotateStart | AgentRoute::RotateFinish => Some(Permission::Rotate),
        AgentRoute::Access
        | AgentRoute::TaskRequest
        | AgentRoute::TaskEnd
        | AgentRoute::Ask
        | AgentRoute::SandboxIssue
        | AgentRoute::SandboxClaim
        | AgentRoute::SandboxRevoke
        | AgentRoute::SandboxStoreReset
        | AgentRoute::SecretRequestCreate => None,
    }
}

/// A sandbox event says nothing but its proxy and, in an end, the reason
/// it signed; the rest of what the proxy signed stays in the body.
fn check_sandbox_body(entry: &Entry, route: AgentRoute, body: &[u8]) -> AuditResult<()> {
    let e = &entry.event;
    let differs = |what: &str| {
        tampered(format!(
            "event {} ({}): the {what} differs from what the proxy signed",
            entry.seq, e.action
        ))
    };
    if e.item_id.is_some()
        || e.vault_id.is_some()
        || e.project_id.is_some()
        || e.permission.is_some()
        || e.domain.is_some()
        || e.method.is_some()
        || e.path.is_some()
        || !e.attachments.is_empty()
    {
        return Err(differs("target"));
    }
    if e.reason.is_some()
        || e.task_id.is_some()
        || e.approval_id.is_some()
        || e.lease_until.is_some()
        || e.decided_at.is_some()
    {
        return Err(differs("data"));
    }
    let outcome = match route {
        AgentRoute::SandboxIssue => {
            let req: SandboxIssue = parse_body(entry, body)?;
            let proxy = e.agent_id.ok_or_else(|| differs("proxy"))?;
            req.check_format(proxy).map_err(|_| differs("sandbox"))?;
            None
        }
        AgentRoute::SandboxClaim => {
            let req: SandboxClaimed = parse_body(entry, body)?;
            if req.channel_key_sha256.as_bytes().len() != CHANNEL_KEY_DIGEST_LEN {
                return Err(differs("channel key"));
            }
            None
        }
        AgentRoute::SandboxStoreReset => {
            // Only as an object (spec §13.12): serde also reads the struct
            // from an array, which is not the body `{store_epoch}`.
            let body = if is_json_object(body) { body } else { b"" };
            let req: SandboxStoreReset = parse_body(entry, body)?;
            req.check_format().map_err(|_| differs("store epoch"))?;
            None
        }
        _ => Some(parse_end(entry, body)?.reason.as_str()),
    };
    if e.outcome.as_deref() != outcome {
        return Err(differs("reason"));
    }
    Ok(())
}

/// An event whose signed body carries MCP fields the server refuses before
/// it logs anything (ADR 0049 §5.4).
fn mcp_refused(entry: &Entry) -> AuditError {
    tampered(format!(
        "event {} ({}): the signed body names an MCP tool or caller the server never accepts",
        entry.seq, entry.event.action
    ))
}

/// Claims on a route that is not `access`: the server refuses MCP claims
/// on every one of them (`check_claims`).
fn no_mcp_claims(entry: &Entry, claims: &klav_proto::agent::Claims) -> AuditResult<()> {
    if claims.mcp_tool.is_some() || claims.mcp_args.is_some() {
        return Err(mcp_refused(entry));
    }
    Ok(())
}

/// What the event says must be what the agent signed (ADR 0030 §4.4).
fn check_body(entry: &Entry, route: AgentRoute, body: &[u8]) -> AuditResult<()> {
    if route.is_sandbox() {
        return check_sandbox_body(entry, route, body);
    }
    let e = &entry.event;
    let differs = |what: &str| {
        tampered(format!(
            "event {} ({}): the {what} differs from what the agent signed",
            entry.seq, e.action
        ))
    };
    // The HTTP target of a `proxy` access (ADR 0036 §2), as signed; no
    // other route carries one.
    let mut http: (Option<String>, Option<String>) = (None, None);
    // (item, permission, reason, host) as signed.
    let (item, permission, reason, domain): (Option<ItemId>, _, String, Option<String>) =
        match route {
            AgentRoute::Access => {
                let req: AccessRequest = parse_body(entry, body)?;
                // The MCP gateway's fields (ADR 0049 §5.4, T260): the
                // server refuses them out of their grammars before it logs.
                if !crate::agents::mcp_fields_ok(
                    req.permission,
                    &req.claims,
                    req.local_client.as_deref(),
                    req.sandbox,
                ) {
                    return Err(mcp_refused(entry));
                }
                // The server refuses a sandbox on anything but `proxy`
                // before it logs (ADR 0036 E3.3).
                if req.sandbox.is_some() && req.permission != Permission::Proxy {
                    return Err(tampered(format!(
                        "event {} ({}): a sandbox on an access that is not proxy",
                        entry.seq, e.action
                    )));
                }
                http = (req.claims.method, req.claims.path);
                (
                    Some(req.item_id),
                    Some(req.permission),
                    req.reason,
                    req.claims.domain,
                )
            }
            AgentRoute::Create => {
                let req: AgentCreateItem = parse_body(entry, body)?;
                no_mcp_claims(entry, &req.claims)?;
                if e.vault_id != Some(req.vault_id) || e.project_id != Some(req.item.project_id) {
                    return Err(differs("project"));
                }
                // The new item's ID is the agent's; the event may name it.
                let item = e.item_id.and(Some(req.item.id));
                (item, route_permission(route), req.reason, req.claims.domain)
            }
            AgentRoute::Update => {
                let req: AgentUpdateItem = parse_body(entry, body)?;
                no_mcp_claims(entry, &req.claims)?;
                (
                    e.item_id,
                    route_permission(route),
                    req.reason,
                    req.claims.domain,
                )
            }
            AgentRoute::Trash => {
                let req: AgentTrashItem = parse_body(entry, body)?;
                no_mcp_claims(entry, &req.claims)?;
                (
                    e.item_id,
                    route_permission(route),
                    req.reason,
                    req.claims.domain,
                )
            }
            AgentRoute::TaskRequest => {
                let req: TaskRequest = parse_body(entry, body)?;
                (None, None, req.reason, None)
            }
            AgentRoute::TaskEnd => {
                let req: AgentEndTask = parse_body(entry, body)?;
                (None, None, req.reason, None)
            }
            AgentRoute::RotateStart => {
                let req: AgentRotateStart = parse_body(entry, body)?;
                no_mcp_claims(entry, &req.claims)?;
                if req.task_id.is_some() && e.task_id.is_some() && req.task_id != e.task_id {
                    return Err(differs("task"));
                }
                (
                    Some(req.item_id),
                    route_permission(route),
                    req.reason,
                    // The server logs the host normalized.
                    req.claims.domain.as_deref().and_then(normalize_host),
                )
            }
            AgentRoute::RotateFinish => {
                let req: AgentRotateFinish = parse_body(entry, body)?;
                // The host is not signed here: `started_change` backs it.
                (
                    Some(req.item_id),
                    route_permission(route),
                    req.reason,
                    e.domain.clone(),
                )
            }
            AgentRoute::Ask => {
                let req: AgentAsk = parse_body(entry, body)?;
                no_mcp_claims(entry, &req.claims)?;
                if !matches!(
                    req.permission,
                    Permission::Create | Permission::Update | Permission::Delete
                ) {
                    return Err(differs("permission"));
                }
                if e.vault_id != Some(req.vault_id) || e.project_id != Some(req.project_id) {
                    return Err(differs("project"));
                }
                (
                    req.item_id,
                    Some(req.permission),
                    req.reason,
                    req.claims.domain,
                )
            }
            AgentRoute::SandboxIssue
            | AgentRoute::SandboxClaim
            | AgentRoute::SandboxRevoke
            | AgentRoute::SandboxStoreReset => {
                return check_sandbox_body(entry, route, body);
            }
            AgentRoute::SecretRequestCreate => {
                let req: CreateSecretRequest = parse_body(entry, body)?;
                if e.secret_request_id != Some(req.id)
                    || e.proposal_digest.as_ref() != Some(&req.proposal_digest)
                {
                    return Err(differs("secret request"));
                }
                (req.target_item_id, None, req.reason, None)
            }
        };
    if e.item_id != item {
        return Err(differs("item"));
    }
    if e.permission != permission {
        return Err(differs("permission"));
    }
    if e.reason.as_deref() != Some(reason.trim()) {
        return Err(differs("reason"));
    }
    if e.domain != domain {
        return Err(differs("host"));
    }
    if e.method != http.0 {
        return Err(differs("method"));
    }
    if e.path != http.1 {
        return Err(differs("path"));
    }
    Ok(())
}

/// An item write whose body was too large to keep: the route still fixes
/// the item and the permission; the reason and host stay unchecked.
fn check_fields_without_body(entry: &Entry, route: AgentRoute) -> AuditResult<()> {
    let e = &entry.event;
    if route == AgentRoute::SecretRequestCreate {
        let digest_ok = e
            .proposal_digest
            .as_ref()
            .is_some_and(|d| d.as_bytes().len() == 32);
        if e.secret_request_id.is_none()
            || !digest_ok
            || e.permission.is_some()
            || e.method.is_some()
            || e.path.is_some()
        {
            return Err(tampered(format!(
                "event {} ({}): invalid secret request metadata",
                entry.seq, e.action
            )));
        }
        return Ok(());
    }
    let item_ok = match route {
        AgentRoute::Create => true,
        // `check_route` tied the item to the signed route.
        _ => e.item_id.is_some(),
    };
    if !item_ok || e.permission != route_permission(route) || e.method.is_some() || e.path.is_some()
    {
        return Err(tampered(format!(
            "event {} ({}): the permission differs from what the agent signed",
            entry.seq, e.action
        )));
    }
    Ok(())
}

/// Verifies the chain, its signatures and the heads. Pure: no I/O.
///
/// `agents` are the identities the server lists; one is used only after a
/// grant in the chain vouches for it. A chain event of an agent the server
/// does not list is a warning in the report, not an error.
pub fn verify(
    account_id: AccountId,
    account: &PublicIdentity,
    agents: &HashMap<AgentId, PublicIdentity>,
    entries: &[Entry],
    heads: &[(Pin, Signature)],
    pin: Option<Pin>,
) -> ClientResult<VerifyReport> {
    verify_chain(account_id, account, agents, entries, heads, pin).map_err(ClientError::from)
}

/// [`verify`], telling a chain that does not verify by its type.
fn verify_chain(
    account_id: AccountId,
    account: &PublicIdentity,
    agents: &HashMap<AgentId, PublicIdentity>,
    entries: &[Entry],
    heads: &[(Pin, Signature)],
    pin: Option<Pin>,
) -> AuditResult<VerifyReport> {
    let mut v = Verifier {
        account_id,
        account,
        listed: agents,
        vouched: HashSet::new(),
        nonces: HashSet::new(),
        warned: HashSet::new(),
        rotations: HashSet::new(),
        pause_clock: HashMap::new(),
        sandboxes: HashMap::new(),
        revoke_clock: HashMap::new(),
        store_epochs: HashSet::new(),
        paused: HashMap::new(),
        revoked: HashMap::new(),
        bundles: HashMap::new(),
        report: VerifyReport::default(),
    };
    let mut previous = GENESIS;
    let mut hashes = Vec::with_capacity(entries.len());
    for (i, entry) in entries.iter().enumerate() {
        let expected = u64::try_from(i + 1).unwrap_or(u64::MAX);
        if entry.seq != expected || entry.event.seq != expected {
            return Err(tampered(format!(
                "events are missing or out of order at {expected}"
            )));
        }
        let hash = chain_hash(entry.seq, &previous, &entry.bytes);
        if hash != entry.hash {
            return Err(tampered(format!(
                "event {} does not match its hash: it was altered",
                entry.seq
            )));
        }
        v.event(entry)?;
        previous = hash;
        hashes.push(hash);
    }
    let mut report = v.report;
    report.events = u64::try_from(entries.len()).unwrap_or(0);
    let mut seen: Vec<(SandboxId, SandboxSeen)> =
        v.sandboxes.into_iter().filter(|(_, s)| s.checked).collect();
    seen.sort_by_key(|(_, s)| s.issued_seq);
    let revoked = v.revoked;
    report.sandboxes = seen
        .into_iter()
        .map(|(sandbox_id, s)| SandboxRecord {
            proxy_revoked_at: revoked
                .get(&s.proxy)
                .filter(|(seq, _)| *seq > s.issued_seq)
                .map(|(_, at)| *at),
            sandbox_id,
            proxy: s.proxy,
            issuer: s.issuer,
            label: s.label,
            profiles: s.profiles,
            issued_at: s.issued_at,
            expires_at: s.expires_at,
            claimed_at: s.claimed_at,
            end: s.end,
            revoked_by_person_at: s.revoked_at.iter().copied().max(),
        })
        .collect();
    let at = |seq: u64| -> Option<[u8; 32]> {
        usize::try_from(seq)
            .ok()
            .and_then(|s| s.checked_sub(1))
            .and_then(|i| hashes.get(i).copied())
    };
    for (head, signature) in heads {
        verify_head(account, account_id, head.seq, &head.hash, signature).map_err(|_| {
            tampered(format!(
                "the head at {} is not signed by the account",
                head.seq
            ))
        })?;
        match at(head.seq) {
            Some(h) if h == head.hash => report.heads += 1,
            Some(_) => {
                return Err(tampered(format!(
                    "the chain was rewritten before position {} (a signed head no longer matches)",
                    head.seq
                )));
            }
            None => {
                return Err(tampered(format!(
                    "the chain was truncated: a signed head is at {} but it ends at {}",
                    head.seq, report.events
                )));
            }
        }
    }
    if let Some(pin) = pin {
        match at(pin.seq) {
            Some(h) if h == pin.hash => {}
            Some(_) => {
                return Err(tampered(format!(
                    "the chain changed before position {}, which this device verified",
                    pin.seq
                )));
            }
            None => {
                return Err(tampered(format!(
                    "the chain is shorter ({}) than when this device verified it ({})",
                    report.events, pin.seq
                )));
            }
        }
    }
    Ok(report)
}

/// Takes one page of `GET /v1/audit?after=`: it must start at `after + 1`
/// and have no gaps (ADR 0030 §4.7). Returns the entries and whether the
/// chain is complete; a page that stops short of `head_seq` without any
/// entry is an error, never a reason to ask again.
fn accept_page(after: u64, page: AuditPage) -> AuditResult<(Vec<Entry>, bool)> {
    if page.entries.is_empty() {
        if page.head_seq > after {
            return Err(tampered(format!(
                "the server stopped at {after} but says the chain goes to {}",
                page.head_seq
            )));
        }
        return Ok((Vec::new(), true));
    }
    let mut last = after;
    let mut entries = Vec::with_capacity(page.entries.len());
    for entry in page.entries {
        let expected = last
            .checked_add(1)
            .ok_or_else(|| tampered("bad position".into()))?;
        if entry.seq != expected {
            return Err(tampered(format!(
                "the server sent event {} where {expected} was due",
                entry.seq
            )));
        }
        last = entry.seq;
        entries.push(parse_entry(entry)?);
    }
    Ok((entries, last >= page.head_seq))
}

/// One stored event as the server (or this device's copy) holds it.
fn parse_entry(entry: AuditEntry) -> AuditResult<Entry> {
    let hash: [u8; 32] = entry
        .hash
        .as_bytes()
        .try_into()
        .map_err(|_| tampered(format!("event {}: bad hash", entry.seq)))?;
    let event: AuditEvent = serde_json::from_slice(entry.event.as_bytes())
        .map_err(|e| tampered(format!("event {}: {e}", entry.seq)))?;
    Ok(Entry {
        seq: entry.seq,
        bytes: entry.event.into_bytes(),
        hash,
        event,
    })
}

/// Adds one page of `GET /v1/audit?after=` to `chain`, this device's copy
/// (ADR 0033 §8.4). Returns whether the chain is complete.
///
/// The copy holds the server to what it already sent, as a pinned head
/// does: an event this device has must come back as it was (the first
/// request overlaps the copy by one event, and each hash covers every event
/// before it, so a rewrite of anything earlier shows there), a new one must
/// follow the copy's last hash, and the server's chain cannot end before
/// the copy does.
fn extend_chain(chain: &mut Vec<Entry>, after: u64, page: AuditPage) -> AuditResult<bool> {
    let head = page.head_seq;
    let (entries, done) = accept_page(after, page)?;
    let have = chain.last().map_or(0, |e| e.seq);
    if head < have {
        return Err(tampered(format!(
            "the server's chain ends at {head}, but this device already downloaded {have} events: it was truncated"
        )));
    }
    for entry in entries {
        if entry.seq <= have {
            let mine = usize::try_from(entry.seq)
                .ok()
                .and_then(|s| s.checked_sub(1))
                .and_then(|i| chain.get(i));
            if mine.is_none_or(|m| m.hash != entry.hash || m.bytes != entry.bytes) {
                return Err(tampered(format!(
                    "event {} is not what the server sent this device before: the chain was rewritten",
                    entry.seq
                )));
            }
            continue;
        }
        let previous = chain.last().map_or(GENESIS, |e| e.hash);
        if chain_hash(entry.seq, &previous, &entry.bytes) != entry.hash {
            return Err(tampered(format!(
                "event {} does not follow the chain this device downloaded: it was rewritten or altered",
                entry.seq
            )));
        }
        chain.push(entry);
    }
    Ok(done)
}

/// Whether `chain` still reaches the head this device verified: a chain
/// rebuilt from the server (no copy here, or one that did not open) must
/// be as long and have the same hash there, or the views would mark the
/// server's new events as verified (ADR 0033 §8.4).
fn reaches_pin(chain: &[Entry], pin: Option<Pin>) -> AuditResult<()> {
    let Some(pin) = pin.filter(|p| p.seq > 0) else {
        return Ok(());
    };
    let at = usize::try_from(pin.seq - 1).ok().and_then(|i| chain.get(i));
    match at {
        None => Err(tampered(format!(
            "the server's chain ends at {}, but this device verified it up to {}: it was truncated",
            chain.last().map_or(0, |e| e.seq),
            pin.seq
        ))),
        Some(e) if e.seq != pin.seq || e.hash != pin.hash => Err(tampered(format!(
            "event {} is not the one this device verified: the chain was rewritten",
            pin.seq
        ))),
        Some(_) => Ok(()),
    }
}

/// `$KLAV_HOME/audit-chain.bin`: the chain this device downloaded (ADR
/// 0033 §8.4), so the views ask only for what is new. Sealed with the
/// local key (spec §12.2, purpose `audit`); removed with the account.
pub(crate) const CHAIN_FILE: &str = "audit-chain.bin";
/// The purpose of [`CHAIN_FILE`]'s sealing (spec §12.2).
const PURPOSE_CHAIN: &str = "audit";
/// Format of [`CHAIN_FILE`]'s contents.
const CHAIN_VERSION: u32 = 1;

#[derive(Serialize, Deserialize)]
struct ChainFile {
    v: u32,
    account_id: AccountId,
    entries: Vec<AuditEntry>,
}

/// Where this device stands on the audit log (ADR 0033 §8.1: «Verified
/// up to event #1234»).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainStatus {
    /// The last event this device downloaded (0: none yet).
    pub events: u64,
    /// The last event this device verified (`klav log verify`), if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified: Option<u64>,
}

impl ChainStatus {
    /// Downloaded events after the last verified one.
    #[must_use]
    pub fn unverified(&self) -> u64 {
        self.events.saturating_sub(self.verified.unwrap_or(0))
    }
}

/// Whether `server`, a whole chain just downloaded, still has every event
/// of this device's copy `mine` as it was: none rewritten, and not shorter.
fn holds_copy(mine: &[Entry], server: &[Entry]) -> AuditResult<()> {
    if let Some(last) = mine.last()
        && server.len() < mine.len()
    {
        return Err(tampered(format!(
            "the server's chain ends at {}, but this device already downloaded {} events: it was truncated",
            server.len(),
            last.seq
        )));
    }
    match mine
        .iter()
        .zip(server)
        .find(|(m, s)| m.seq != s.seq || m.hash != s.hash)
    {
        Some((m, _)) => Err(tampered(format!(
            "event {} is not what the server sent this device before: the chain was rewritten",
            m.seq
        ))),
        None => Ok(()),
    }
}

/// What a report says when the audit log could not be read (`why`): a
/// server whose chain no longer matches this device's copy, say. `what`
/// is what the report still shows, which does not depend on the log
/// (the revocation, the grant's projects, a task's card).
pub(crate) fn log_unreadable(what: &str, why: &ClientError) -> String {
    let fix = match why {
        ClientError::Security(_) => {
            " It may be tampering: check the server. If it was restored from a backup you trust, \
             `klav log reset` makes this device accept the chain it has now."
        }
        _ => "",
    };
    format!("{what} without the audit log: {why}.{fix}")
}

/// `klav log reset` (ADR 0033 §8.4): removes this device's copy of the
/// audit log ([`CHAIN_FILE`]) and the head it verified ([`PIN_FILE`]) from
/// `home`, and says which were there. Needs no network and no unlocked
/// account. It is a decision of trust, for a server restored from a backup
/// the person trusts: from then on this device takes the chain the server
/// has as the good one, the views download it again, and the next `klav
/// log verify` starts over from it, saying so. An unlocked session also
/// keeps the copy in memory: forget it there with
/// [`Unlocked::forget_audit_copy`] (`klavd` does).
pub fn forget_audit_copy(home: &crate::Home) -> ClientResult<Vec<&'static str>> {
    let mut removed = Vec::new();
    for name in [CHAIN_FILE, PIN_FILE] {
        match std::fs::remove_file(home.file(name)) {
            Ok(()) => removed.push(name),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(removed)
}

/// What `audit-head.json` holds on this device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StoredPin {
    Missing,
    Unreadable,
    File(PinFile),
}

/// The head this device pinned for `account`, and why there is none to
/// hold the chain against when there are events (ADR 0030 §4.8). A file
/// without an account comes from before the account was recorded and is
/// taken as this account's (it is rewritten with it); one of another
/// account is ignored.
fn choose_pin(
    account: AccountId,
    stored: StoredPin,
    events: bool,
) -> (Option<Pin>, Option<Unpinned>) {
    match stored {
        StoredPin::File(p) if p.account_id.is_none_or(|a| a == account) => (
            Some(Pin {
                seq: p.seq,
                hash: p.hash,
            }),
            None,
        ),
        StoredPin::File(_) => (None, events.then_some(Unpinned::OtherAccount)),
        StoredPin::Unreadable => (None, events.then_some(Unpinned::Unreadable)),
        StoredPin::Missing => (None, events.then_some(Unpinned::Missing)),
    }
}

/// An event ready to show.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogLine {
    /// Position.
    pub seq: u64,
    /// Time (Unix ms).
    pub at: i64,
    /// `you`, or the agent's name. Tell them apart by [`Self::by_agent`],
    /// never by this text: an agent may be called `you`.
    pub actor: String,
    /// An agent wrote the event (its actor kind is `agent`), not the
    /// person. Absent from an older `klavd`'s answers: `false`.
    #[serde(default)]
    pub by_agent: bool,
    /// The agent involved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<AgentId>,
    /// The name of the agent in `agent_id`, as the server lists it: who an
    /// action of the person, such as an `agent.granted`, was for. Absent
    /// when the server no longer lists it, and from an older `klavd`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_name: Option<String>,
    /// What happened.
    pub action: String,
    /// Permission used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permission: Option<String>,
    /// Policy outcome or decision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<String>,
    /// Item reference (`klav://…`), if known on this device.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub item: Option<String>,
    /// Item ID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub item_id: Option<ItemId>,
    /// Vault name, if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault: Option<String>,
    /// The agent's reason.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Claimed host.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    /// Attachments delivered to the agent with this event (ADR 0016).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attachments: Vec<klav_core::ids::AttachmentId>,
    /// The task this event belongs to (ADR 0021 §9).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_id: Option<TaskId>,
    /// The approval used or decided.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_id: Option<klav_core::ids::ApprovalId>,
    /// In `agents.paused`: when the pause ends by itself (Unix ms).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<i64>,
    /// Alerts.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub alerts: Vec<String>,
    /// At or before the last event this device verified (`klav log
    /// verify`); a later one shows «not verified yet» (ADR 0033 §8.1).
    #[serde(default)]
    pub verified: bool,
    /// The MCP tool a proxied call named, according to the MCP server, as
    /// the proxy signed it (ADR 0049 §6). Only in its grammar.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp_tool: Option<String>,
    /// The local client a proxied call was for, according to the proxy,
    /// as it signed it (ADR 0049 §6). Only in its grammar.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_client: Option<String>,
    /// The sandbox a proxied call was for, according to the proxy, as it
    /// signed it (ADR 0049 §6): who called, where a local client is not.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sandbox: Option<klav_core::ids::SandboxId>,
}

/// The sandbox an `agent.access` event's signed body names, when its MCP
/// fields keep their grammars (as [`mcp_of`]).
fn sandbox_of(e: &AuditEvent) -> Option<klav_core::ids::SandboxId> {
    let body = e
        .agent_proof
        .as_ref()
        .filter(|_| e.action == "agent.access")
        .and_then(|p| p.body.as_ref())?;
    serde_json::from_slice::<AccessRequest>(body.as_bytes())
        .ok()
        .filter(|req| {
            crate::agents::mcp_fields_ok(
                req.permission,
                &req.claims,
                req.local_client.as_deref(),
                req.sandbox,
            )
        })
        .and_then(|req| req.sandbox)
}

/// The MCP tool and local client an `agent.access` event's signed body
/// names (ADR 0049 §6), when both keep their grammars; nothing otherwise.
fn mcp_of(e: &AuditEvent) -> (Option<String>, Option<String>) {
    let Some(body) = e
        .agent_proof
        .as_ref()
        .filter(|_| e.action == "agent.access")
        .and_then(|p| p.body.as_ref())
    else {
        return (None, None);
    };
    match serde_json::from_slice::<AccessRequest>(body.as_bytes()) {
        Ok(req)
            if crate::agents::mcp_fields_ok(
                req.permission,
                &req.claims,
                req.local_client.as_deref(),
                req.sandbox,
            ) =>
        {
            (req.claims.mcp_tool, req.local_client)
        }
        _ => (None, None),
    }
}

/// Filters for [`Unlocked::audit_log`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LogFilter {
    /// An item (reference or query, resolved on this device).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub item: Option<String>,
    /// An agent (name or ID).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
    /// A vault (name or ID).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault: Option<String>,
    /// From this time (Unix ms).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<i64>,
    /// Until this time (Unix ms).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<i64>,
    /// Only events with alerts.
    #[serde(default)]
    pub alerts: bool,
    /// A task (ID, or a unique prefix of 6+ characters).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task: Option<String>,
    /// Only events with one of these permissions (ADR 0033 §8.1).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub permissions: Vec<Permission>,
    /// Only events with one of these outcomes: `allow`, `ask` and `deny`
    /// from the policy, `approve` and `deny` from a decision.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub outcomes: Vec<String>,
    /// Only events whose item (its reference, with the title, resolved on
    /// this device), agent, reason or site contain this text, ignoring
    /// case.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// At most this many events, the newest that pass the other filters.
    /// An older `klavd` ignores it: the caller cuts what it answers again.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

impl LogFilter {
    /// Whether `line` passes the filters a [`LogLine`] carries
    /// (permission, outcome and text; not `limit`). The CLI applies them
    /// again to what an older `klavd`, which ignores them, answers.
    ///
    /// The text looks in the agent's name, not in the person's `you`: an
    /// event the person wrote does not match `you`. A line of an older
    /// `klavd` has no [`LogLine::by_agent`]; there, an actor other than
    /// `you` is an agent's name.
    #[must_use]
    pub fn keeps(&self, line: &LogLine) -> bool {
        let agent_name = (line.by_agent || line.actor != "you").then_some(line.actor.as_str());
        let permission_ok = self.permissions.is_empty()
            || line
                .permission
                .as_deref()
                .is_some_and(|p| self.permissions.iter().any(|w| permission_name(*w) == p));
        let outcome_ok = self.outcomes.is_empty()
            || line
                .outcome
                .as_deref()
                .is_some_and(|o| self.outcomes.iter().any(|w| w.eq_ignore_ascii_case(o)));
        let text_ok = self.text.as_deref().map(str::trim).is_none_or(|t| {
            let t = t.to_lowercase();
            t.is_empty()
                || [
                    agent_name,
                    line.item.as_deref(),
                    line.reason.as_deref(),
                    line.domain.as_deref(),
                ]
                .into_iter()
                .flatten()
                .any(|s| s.to_lowercase().contains(&t))
        });
        permission_ok && outcome_ok && text_ok
    }
}

/// `fill`, as the log writes a permission.
pub(crate) fn permission_name(p: Permission) -> String {
    serde_json::to_value(p)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default()
}

/// The task IDs in `entries` that `wanted` names: the ID itself or a
/// unique prefix of 6+ characters.
pub(crate) fn find_task_in(entries: &[Entry], wanted: &str) -> ClientResult<TaskId> {
    let wanted = wanted.trim();
    if let Ok(id) = wanted.parse::<TaskId>() {
        return Ok(id);
    }
    let mut found: Vec<TaskId> = entries
        .iter()
        .filter_map(|e| e.event.task_id)
        .filter(|id| wanted.len() >= 6 && id.to_string().starts_with(wanted))
        .collect();
    found.sort_unstable_by_key(|id| id.to_string());
    found.dedup();
    match found.as_slice() {
        [one] => Ok(*one),
        [] => Err(ClientError::NotFound(format!(
            "task {wanted:?} in the audit log"
        ))),
        _ => Err(ClientError::Ambiguous(format!(
            "several tasks start with {wanted:?}; use more of the ID"
        ))),
    }
}

impl Unlocked {
    /// Every event of the account's log, in order: this device's copy
    /// ([`CHAIN_FILE`]) and what the server added since (ADR 0033 §8.4).
    /// Each page must go on from the previous one without gaps (ADR 0030
    /// §4.7), the server must still hold the copy as it was
    /// ([`extend_chain`]), and the chain must reach the head this device
    /// verified ([`reaches_pin`]), also when there was no copy. Signatures
    /// are checked by [`Self::verify_audit`], not here.
    pub async fn audit_entries(&mut self) -> ClientResult<Vec<Entry>> {
        let mut chain = self.cached_chain();
        let known = chain.len();
        // One event of overlap on the first request, to see that the
        // server still has this device's last event as it was.
        let mut after = chain.last().map_or(0, |e| e.seq.saturating_sub(1));
        loop {
            let page = self.chain_page(after).await?;
            let done = extend_chain(&mut chain, after, page)?;
            after = chain.last().map_or(0, |e| e.seq);
            if done {
                break;
            }
        }
        let pin = choose_pin(self.account.account_id, self.load_pin(), false).0;
        reaches_pin(&chain, pin)?;
        if chain.len() != known {
            self.keep_chain(&chain);
        }
        Ok(chain)
    }

    async fn chain_page(&mut self, after: u64) -> ClientResult<AuditPage> {
        let res = self
            .authed(
                Method::GET,
                &format!("/v1/audit?after={after}"),
                &Body::Empty,
            )
            .await?;
        crate::api::json(res).await
    }

    /// The whole chain as the server serves it now, from the first event:
    /// what [`Self::verify_audit`] checks.
    async fn download_chain(&mut self) -> AuditResult<Vec<Entry>> {
        let mut entries: Vec<Entry> = Vec::new();
        loop {
            let after = entries.last().map_or(0, |e| e.seq);
            let page = self.chain_page(after).await?;
            let (mut page, done) = accept_page(after, page)?;
            entries.append(&mut page);
            if done {
                break;
            }
        }
        Ok(entries)
    }

    fn chain_path(&self) -> std::path::PathBuf {
        self.home.file(CHAIN_FILE)
    }

    /// This device's copy of the chain: in memory, or else from
    /// [`CHAIN_FILE`]. A copy of another account is none; one that does
    /// not open is none too, with a warning, and the chain is downloaded
    /// again (the pinned head still holds it to what was verified).
    fn cached_chain(&mut self) -> Vec<Entry> {
        self.load_chain();
        self.audit_chain.clone().unwrap_or_default()
    }

    /// Reads [`CHAIN_FILE`] into memory, unless the copy is there already.
    /// A file that is missing or does not open leaves none in memory (see
    /// [`Self::cached_chain`]), so the next view reads it again.
    fn load_chain(&mut self) {
        if self.audit_chain.is_some() {
            return;
        }
        let blob = match std::fs::read(self.chain_path()) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
            Err(e) => {
                self.warnings.push(format!(
                    "{CHAIN_FILE} cannot be read ({e}); downloading the audit log again"
                ));
                return;
            }
        };
        let read = open_local_data(&self.local_key, &self.ctx, PURPOSE_CHAIN, &blob)
            .map_err(|_| "it does not open".to_owned())
            .and_then(|json| serde_json::from_slice::<ChainFile>(&json).map_err(|e| e.to_string()))
            .and_then(|f| {
                if f.v != CHAIN_VERSION {
                    return Err(format!("version {}", f.v));
                }
                if f.account_id != self.account.account_id {
                    return Ok(Vec::new());
                }
                f.entries
                    .into_iter()
                    .map(|e| parse_entry(e).map_err(|e| ClientError::from(e).to_string()))
                    .collect()
            });
        match read {
            Ok(chain) => self.audit_chain = Some(chain),
            Err(why) => self.warnings.push(format!(
                "{CHAIN_FILE}: {why}; downloading the audit log again"
            )),
        }
    }

    /// Keeps `chain` as this device's copy, in memory and sealed on disk.
    /// A failed write is a warning: the views still work, downloading more.
    fn keep_chain(&mut self, chain: &[Entry]) {
        self.audit_chain = Some(chain.to_vec());
        let file = ChainFile {
            v: CHAIN_VERSION,
            account_id: self.account.account_id,
            entries: chain
                .iter()
                .map(|e| AuditEntry {
                    seq: e.seq,
                    event: Blob::new(e.bytes.clone()),
                    hash: Blob::new(e.hash.to_vec()),
                })
                .collect(),
        };
        let saved = serde_json::to_vec(&file)
            .map_err(|e| ClientError::Invalid(format!("audit chain: {e}")))
            .and_then(|json| {
                Ok(seal_local_data(
                    &self.local_key,
                    &self.ctx,
                    PURPOSE_CHAIN,
                    &json,
                )?)
            })
            .and_then(|blob| crate::home::write_private(&self.chain_path(), &blob));
        if let Err(e) = saved {
            self.warnings.push(format!("cannot save {CHAIN_FILE}: {e}"));
        }
    }

    /// The last event this device verified, if it pinned one for this
    /// account.
    fn verified_seq(&self) -> Option<u64> {
        choose_pin(self.account.account_id, self.load_pin(), false)
            .0
            .map(|p| p.seq)
    }

    /// [`forget_audit_copy`] for this session: also the copy in memory, so
    /// the next view downloads the chain again instead of holding the
    /// server to it.
    pub fn forget_audit_copy(&mut self) -> ClientResult<Vec<&'static str>> {
        self.audit_chain = None;
        forget_audit_copy(&self.home)
    }

    /// How far this device downloaded and verified the log, without asking
    /// the server (ADR 0033 §8.1).
    pub fn audit_status(&mut self) -> ChainStatus {
        self.load_chain();
        let events = self
            .audit_chain
            .as_ref()
            .and_then(|c| c.last())
            .map_or(0, |e| e.seq);
        ChainStatus {
            events,
            verified: self.verified_seq(),
        }
    }

    async fn agent_identities(
        &mut self,
    ) -> ClientResult<HashMap<AgentId, (String, PublicIdentity)>> {
        let res = self.authed(Method::GET, "/v1/agents", &Body::Empty).await?;
        let list: klav_proto::agent::AgentList = crate::api::json(res).await?;
        list.agents
            .into_iter()
            .map(|a| {
                Ok((
                    a.id,
                    (
                        a.name,
                        PublicIdentity::decode(a.public_identity.as_bytes())?,
                    ),
                ))
            })
            .collect()
    }

    fn pin_path(&self) -> std::path::PathBuf {
        self.home.file(PIN_FILE)
    }

    fn load_pin(&self) -> StoredPin {
        match std::fs::read(self.pin_path()) {
            Ok(text) => {
                serde_json::from_slice(&text).map_or(StoredPin::Unreadable, StoredPin::File)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => StoredPin::Missing,
            Err(_) => StoredPin::Unreadable,
        }
    }

    /// Whether this device already posted the head at `seq` with `hash`:
    /// its pinned head, which is written only once the server took the
    /// post. Posting an unchanged head on every verification (each sandbox
    /// list does one) matters to an older server: it stores every post and
    /// lists only the latest 100 heads of all the account's devices
    /// together (`GET /v1/audit/heads`), so the repeats would push the
    /// other devices' heads out of that window. A current server stores a
    /// head the device already posted only once, and lists each device's
    /// latest head besides the latest 100.
    fn posted_head(&self, seq: u64, hash: &[u8; 32]) -> bool {
        matches!(
            self.load_pin(),
            StoredPin::File(p)
                if p.account_id == Some(self.account.account_id) && p.seq == seq && p.hash == *hash
        )
    }

    /// Verifies the whole log (`klav log verify`) and signs its head.
    ///
    /// It downloads the whole chain again, as the server serves it now,
    /// and checks it from the first event with the rules of ADR 0030 §4.
    /// Then it holds it to this device's copy too ([`CHAIN_FILE`], which
    /// may go past the last verified head) and keeps it as the new copy.
    pub async fn verify_audit(&mut self) -> ClientResult<VerifyReport> {
        Ok(self.verify_audit_with_agents().await?.0)
    }

    /// [`Self::verify_audit`], with the agents (name and identity) it
    /// checked the chain against: a later check of an agent's signature
    /// must use these, never a second answer of the server.
    pub(crate) async fn verify_audit_with_agents(
        &mut self,
    ) -> AuditResult<(VerifyReport, HashMap<AgentId, (String, PublicIdentity)>)> {
        let entries = self.download_chain().await?;
        let listed = self.agent_identities().await?;
        let agents: HashMap<AgentId, PublicIdentity> =
            listed.iter().map(|(id, (_, p))| (*id, p.clone())).collect();
        let res = self
            .authed(Method::GET, "/v1/audit/heads", &Body::Empty)
            .await?;
        let heads: AuditHeads = crate::api::json(res).await?;
        let heads: Vec<(Pin, Signature)> = heads
            .heads
            .iter()
            .map(|h| {
                Ok((
                    Pin {
                        seq: h.seq,
                        hash: h
                            .hash
                            .as_bytes()
                            .try_into()
                            .map_err(|_| tampered("bad head hash".into()))?,
                    },
                    sig(&h.signature).ok_or_else(|| tampered("bad head signature".into()))?,
                ))
            })
            .collect::<AuditResult<_>>()?;
        let (pin, unpinned) = choose_pin(
            self.account.account_id,
            self.load_pin(),
            !entries.is_empty(),
        );
        let mut report = verify_chain(
            self.account.account_id,
            self.identity.public(),
            &agents,
            &entries,
            &heads,
            pin,
        )?;
        report.warnings.extend(unpinned.map(Unpinned::warning));
        report.unpinned = unpinned;
        let mine = self.cached_chain();
        holds_copy(&mine, &entries)?;
        self.keep_chain(&entries);
        if let Some(last) = entries
            .last()
            .filter(|last| !self.posted_head(last.seq, &last.hash))
        {
            let signature = sign_head(
                &self.identity,
                self.account.account_id,
                last.seq,
                &last.hash,
            );
            let res = self
                .authed(
                    Method::POST,
                    "/v1/audit/heads",
                    &Body::json(&SignHead {
                        seq: last.seq,
                        hash: Blob::new(last.hash.to_vec()),
                        signature: Blob::new(signature.to_bytes().to_vec()),
                    })?,
                )
                .await?;
            crate::api::empty(res).await?;
            let pin = PinFile {
                account_id: Some(self.account.account_id),
                seq: last.seq,
                hash: last.hash,
            };
            let json = serde_json::to_vec(&pin)
                .map_err(|e| ClientError::Invalid(format!("audit pin: {e}")))?;
            crate::home::write_private(&self.pin_path(), &json)?;
        }
        report.signed_head = entries.last().map(|last| last.seq);
        Ok((report, listed))
    }

    /// The log, filtered and with names resolved on this device, newest
    /// first.
    pub async fn audit_log(&mut self, filter: &LogFilter) -> ClientResult<Vec<LogLine>> {
        let entries = self.audit_entries().await?;
        let agents = self.agent_names().await?;
        self.log_lines(&entries, &agents, filter)
    }

    /// The agents the server lists, by ID, with their names.
    pub(crate) async fn agent_names(&mut self) -> ClientResult<HashMap<AgentId, String>> {
        Ok(self
            .agent_identities()
            .await?
            .into_iter()
            .map(|(id, (name, _))| (id, name))
            .collect())
    }

    /// [`Self::audit_log`] over `entries`, already downloaded.
    pub(crate) fn log_lines(
        &self,
        entries: &[Entry],
        agents: &HashMap<AgentId, String>,
        filter: &LogFilter,
    ) -> ClientResult<Vec<LogLine>> {
        let verified = self.verified_seq().unwrap_or(0);
        let agent = match &filter.agent {
            Some(wanted) => {
                let found: Vec<AgentId> = agents
                    .iter()
                    .filter(|(id, name)| {
                        id.to_string() == *wanted || name.eq_ignore_ascii_case(wanted)
                    })
                    .map(|(id, _)| *id)
                    .collect();
                if found.is_empty() {
                    return Err(ClientError::NotFound(format!("agent {wanted:?}")));
                }
                Some(found)
            }
            None => None,
        };
        let item = filter
            .item
            .as_deref()
            .map(|i| {
                if let Ok(id) = i.parse::<ItemId>() {
                    Ok(id)
                } else {
                    self.find_item(i).map(|l| l.item)
                }
            })
            .transpose()?;
        let vault = filter
            .vault
            .as_deref()
            .map(|v| self.find_vault(v))
            .transpose()?;
        let task = filter
            .task
            .as_deref()
            .map(|t| find_task_in(entries, t))
            .transpose()?;
        let mut out = Vec::new();
        for entry in entries.iter().rev() {
            if filter.limit.is_some_and(|n| out.len() >= n) {
                break;
            }
            let e = &entry.event;
            // A pause of every agent is part of each agent's story.
            let every_agent = e.agent_id.is_none() && e.action.starts_with("agents.");
            if agent
                .as_ref()
                .is_some_and(|a| !every_agent && !e.agent_id.is_some_and(|id| a.contains(&id)))
                || item.is_some_and(|i| e.item_id != Some(i))
                || vault.is_some_and(|v| e.vault_id != Some(v))
                || task.is_some_and(|t| e.task_id != Some(t))
                || filter.since.is_some_and(|t| e.at < t)
                || filter.until.is_some_and(|t| e.at > t)
                || (filter.alerts && e.alerts.is_empty())
                || (!filter.permissions.is_empty()
                    && !e
                        .permission
                        .is_some_and(|p| filter.permissions.contains(&p)))
            {
                continue;
            }
            let actor = match (e.actor, e.agent_id) {
                (klav_proto::audit::ActorKind::Agent, Some(id)) => agents
                    .get(&id)
                    .cloned()
                    .unwrap_or_else(|| format!("agent {id}")),
                _ => "you".to_owned(),
            };
            let item_ref = match (e.vault_id, e.project_id, e.item_id) {
                (Some(vault), Some(project), Some(item)) => self
                    .item_summary(crate::ItemLocation {
                        vault,
                        project,
                        item,
                    })
                    .ok()
                    .map(|s| s.reference),
                _ => None,
            };
            let (mcp_tool, local_client) = mcp_of(e);
            let line = LogLine {
                seq: entry.seq,
                at: e.at,
                actor,
                by_agent: e.actor == klav_proto::audit::ActorKind::Agent,
                agent_id: e.agent_id,
                agent_name: e.agent_id.and_then(|id| agents.get(&id).cloned()),
                action: e.action.clone(),
                permission: e.permission.map(permission_name),
                outcome: e.outcome.clone(),
                item: item_ref,
                item_id: e.item_id,
                vault: e.vault_id.and_then(|v| {
                    self.vaults()
                        .into_iter()
                        .find(|s| s.id == v)
                        .map(|s| s.name)
                }),
                reason: e.reason.clone(),
                domain: e.domain.clone(),
                attachments: e.attachments.clone(),
                task_id: e.task_id,
                approval_id: e.approval_id,
                until: e.until,
                alerts: e.alerts.clone(),
                verified: entry.seq <= verified,
                mcp_tool,
                local_client,
                sandbox: sandbox_of(e),
            };
            if filter.keeps(&line) {
                out.push(line);
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use klav_core::crypto::identity::IdentityKeyPair;
    use klav_proto::audit::ActorKind;

    use klav_core::ids::RotationId;

    use super::*;

    fn chain(n: u64) -> Vec<Entry> {
        let mut previous = GENESIS;
        (1..=n)
            .map(|seq| {
                let mut event = AuditEvent::new(ActorKind::Person, "item.created");
                event.seq = seq;
                event.at = i64::try_from(seq).unwrap_or(0);
                let bytes = serde_json::to_vec(&event).unwrap();
                let hash = chain_hash(seq, &previous, &bytes);
                previous = hash;
                Entry {
                    seq,
                    bytes,
                    hash,
                    event,
                }
            })
            .collect()
    }

    /// A page of `GET /v1/audit` with `entries`, the chain ending at `head`.
    fn chain_of(entries: &[Entry], head: u64) -> AuditPage {
        AuditPage {
            entries: entries
                .iter()
                .map(|e| AuditEntry {
                    seq: e.seq,
                    event: Blob::new(e.bytes.clone()),
                    hash: Blob::new(e.hash.to_vec()),
                })
                .collect(),
            head_seq: head,
        }
    }

    #[test]
    fn a_chain_rebuilt_without_the_copy_must_reach_the_pinned_head() {
        let full = chain(6);
        let pin = |seq: u64, hash: [u8; 32]| Some(Pin { seq, hash });
        assert!(reaches_pin(&full, None).is_ok());
        assert!(reaches_pin(&full, pin(4, full[3].hash)).is_ok());
        assert!(reaches_pin(&full, pin(6, full[5].hash)).is_ok());
        // Shorter than what this device verified.
        let why = match reaches_pin(&full[..3], pin(4, full[3].hash)) {
            Err(AuditError::Tampered(m)) => m,
            other => panic!("expected truncated, got {other:?}"),
        };
        assert!(why.contains("truncated"), "{why}");
        // Rewritten from the start, hashes recomputed: another hash there.
        let mut forked = chain(6);
        forked[0].event.action = "item.updated".into();
        forked[0].bytes = serde_json::to_vec(&forked[0].event).unwrap();
        let mut previous = GENESIS;
        for e in &mut forked {
            e.hash = chain_hash(e.seq, &previous, &e.bytes);
            previous = e.hash;
        }
        let why = match reaches_pin(&forked, pin(4, full[3].hash)) {
            Err(AuditError::Tampered(m)) => m,
            other => panic!("expected rewritten, got {other:?}"),
        };
        assert!(why.contains("rewritten"), "{why}");
    }

    fn security(r: AuditResult<bool>) -> String {
        match r {
            Err(AuditError::Tampered(m)) => m,
            other => panic!("expected a security error, got {other:?}"),
        }
    }

    #[test]
    fn the_copy_on_this_device_holds_the_server_to_what_it_sent() {
        let full = chain(6);
        // Nothing on this device: the whole chain comes in.
        let mut mine = Vec::new();
        assert!(extend_chain(&mut mine, 0, chain_of(&full[..4], 4)).expect("first"));
        assert_eq!(mine.len(), 4);
        // Later, one event of overlap and the new ones.
        assert!(extend_chain(&mut mine, 3, chain_of(&full[3..], 6)).expect("more"));
        assert_eq!(mine.len(), 6);
        // Nothing new: the overlap alone.
        assert!(extend_chain(&mut mine, 5, chain_of(&full[5..], 6)).expect("same"));
        assert_eq!(mine.len(), 6);

        // Truncated: the server's chain ends before this device's copy.
        let mut copy = full.clone();
        let why = security(extend_chain(&mut copy, 5, chain_of(&[], 5)));
        assert!(why.contains("truncated"), "{why}");
        let why = security(extend_chain(&mut copy, 5, chain_of(&[], 2)));
        assert!(why.contains("truncated"), "{why}");

        // Rewritten before the copy's end, hashes recomputed: the last
        // event the device has comes back with another hash.
        let mut forked = chain(6);
        forked[1].event.action = "item.updated".into();
        forked[1].bytes = serde_json::to_vec(&forked[1].event).unwrap();
        let mut previous = forked[0].hash;
        for e in forked.iter_mut().skip(1) {
            e.hash = chain_hash(e.seq, &previous, &e.bytes);
            previous = e.hash;
        }
        let mut copy = full[..4].to_vec();
        let why = security(extend_chain(&mut copy, 3, chain_of(&forked[3..], 6)));
        assert!(why.contains("event 4 is not what the server sent"), "{why}");

        // A new event that does not follow the copy's last hash.
        let mut copy = full[..4].to_vec();
        let why = security(extend_chain(&mut copy, 4, chain_of(&forked[4..], 6)));
        assert!(why.contains("event 5 does not follow"), "{why}");
        assert_eq!(copy.len(), 4, "nothing taken from a refused page");
        // An altered event (its hash left as it was).
        let mut altered = full.clone();
        altered[4].bytes = b"{}".to_vec();
        let mut copy = full[..4].to_vec();
        security(extend_chain(&mut copy, 4, chain_of(&altered[4..], 6)));
    }

    #[test]
    fn verify_holds_the_whole_download_to_the_copy_too() {
        let full = chain(6);
        assert!(holds_copy(&[], &full).is_ok());
        assert!(holds_copy(&full[..4], &full).is_ok());
        assert!(holds_copy(&full, &full).is_ok());
        let err = holds_copy(&full, &full[..5]).expect_err("shorter");
        assert!(err.to_string().contains("truncated"), "{err}");
        let mut other = chain(6);
        other[2].hash = [9; 32];
        let err = holds_copy(&full, &other).expect_err("rewritten");
        assert!(err.to_string().contains("event 3"), "{err}");
    }

    #[test]
    fn the_filters_of_a_line_and_the_status() {
        let mut line = LogLine {
            seq: 3,
            at: 1,
            actor: "cursor".into(),
            by_agent: true,
            agent_id: None,
            agent_name: None,
            action: "agent.access".into(),
            permission: Some("fill".into()),
            outcome: Some("allow".into()),
            item: Some("klav://Personal/General/GitHub".into()),
            item_id: None,
            vault: None,
            reason: Some("Log in to deploy".into()),
            domain: Some("github.com".into()),
            attachments: Vec::new(),
            task_id: None,
            approval_id: None,
            until: None,
            alerts: Vec::new(),
            verified: false,
            mcp_tool: None,
            local_client: None,
            sandbox: None,
        };
        let filter =
            |permissions: Vec<Permission>, outcomes: &[&str], text: Option<&str>| LogFilter {
                permissions,
                outcomes: outcomes.iter().map(|o| (*o).to_owned()).collect(),
                text: text.map(str::to_owned),
                ..LogFilter::default()
            };
        assert!(filter(vec![], &[], None).keeps(&line));
        assert!(filter(vec![Permission::Fill, Permission::Totp], &[], None).keeps(&line));
        assert!(!filter(vec![Permission::Reveal], &[], None).keeps(&line));
        assert!(filter(vec![], &["deny", "ALLOW"], None).keeps(&line));
        assert!(!filter(vec![], &["deny"], None).keeps(&line));
        for found in ["github", "DEPLOY", "Cursor", "github.com"] {
            assert!(filter(vec![], &[], Some(found)).keeps(&line), "{found}");
        }
        assert!(!filter(vec![], &[], Some("gitlab")).keeps(&line));
        assert!(filter(vec![], &[], Some("  ")).keeps(&line));
        line.permission = None;
        assert!(!filter(vec![Permission::Fill], &[], None).keeps(&line));
        // `you` finds an agent called so, never the person's events.
        line.actor = "you".into();
        assert!(filter(vec![], &[], Some("YOU")).keeps(&line));
        line.by_agent = false;
        assert!(!filter(vec![], &[], Some("you")).keeps(&line));
        // A line of an older klavd (no `by_agent`): an actor other than
        // `you` is an agent's name.
        line.actor = "cursor".into();
        assert!(filter(vec![], &[], Some("cursor")).keeps(&line));

        let status = ChainStatus {
            events: 10,
            verified: Some(7),
        };
        assert_eq!(status.unverified(), 3);
        assert_eq!(ChainStatus::default().unverified(), 0);
    }

    #[test]
    fn detects_tampering() {
        let keys = IdentityKeyPair::generate();
        let account = AccountId::generate();
        let agents = HashMap::new();
        let entries = chain(5);
        let check = |entries: &[Entry], heads: &[(Pin, Signature)], pin| {
            verify(account, keys.public(), &agents, entries, heads, pin)
        };
        assert_eq!(check(&entries, &[], None).unwrap().events, 5);

        // An edited event (even with its hash recomputed by the server).
        let mut edited = entries.clone();
        edited[1].bytes = b"{}".to_vec();
        assert!(check(&edited, &[], None).is_err());
        let mut rehashed = entries.clone();
        rehashed[1].event.action = "item.updated".into();
        rehashed[1].bytes = serde_json::to_vec(&rehashed[1].event).unwrap();
        let mut previous = rehashed[0].hash;
        for e in rehashed.iter_mut().skip(1) {
            e.hash = chain_hash(e.seq, &previous, &e.bytes);
            previous = e.hash;
        }
        // Internally consistent, but not with what the device saw.
        assert!(check(&rehashed, &[], None).is_ok());
        let pin = Pin {
            seq: 3,
            hash: entries[2].hash,
        };
        assert!(check(&rehashed, &[], Some(pin)).is_err());
        let head = (pin, sign_head(&keys, account, pin.seq, &pin.hash));
        assert!(check(&rehashed, &[head], None).is_err());
        assert_eq!(check(&entries, &[head], Some(pin)).unwrap().heads, 1);

        // Dropped events: gaps and truncation.
        let mut gap = entries.clone();
        gap.remove(2);
        assert!(check(&gap, &[], None).is_err());
        assert!(check(&entries[..2], &[head], None).is_err());
        assert!(check(&entries[..2], &[], Some(pin)).is_err());

        // A head signed by someone else.
        let other = IdentityKeyPair::generate();
        let forged = (pin, sign_head(&other, account, pin.seq, &pin.hash));
        assert!(check(&entries, &[forged], None).is_err());
    }

    fn entries_of(events: Vec<AuditEvent>) -> Vec<Entry> {
        let mut previous = GENESIS;
        events
            .into_iter()
            .zip(1u64..)
            .map(|(mut event, seq)| {
                event.seq = seq;
                let bytes = serde_json::to_vec(&event).unwrap();
                let hash = chain_hash(seq, &previous, &bytes);
                previous = hash;
                Entry {
                    seq,
                    bytes,
                    hash,
                    event,
                }
            })
            .collect()
    }

    #[test]
    fn task_events_carry_the_account_signature() {
        use klav_core::ids::TaskId;

        let keys = IdentityKeyPair::generate();
        let account = AccountId::generate();
        let agents = HashMap::new();
        let agent_id = AgentId::generate();
        let task = TaskId::generate();
        let request = b"{\"v\":1}".to_vec();
        let decision = b"{\"revision\":1}".to_vec();
        let decided = agent::sign_task_decision(
            &keys,
            &TaskDecisionToSign {
                task,
                agent: agent_id,
                request: &request,
                decision: &decision,
                approve: true,
                decided_at_ms: 10,
            },
        );
        let mut decided_event = AuditEvent::new(ActorKind::Person, "task.decided");
        decided_event.agent_id = Some(agent_id);
        decided_event.task_id = Some(task);
        decided_event.outcome = Some("approve".into());
        decided_event.decided_at = Some(10);
        decided_event.signed = Some(Blob::new(decision.clone()));
        decided_event.task_request = Some(Blob::new(request.clone()));
        decided_event.account_signature = Some(Blob::new(decided.to_bytes().to_vec()));
        let mut ended = AuditEvent::new(ActorKind::Person, "task.ended");
        ended.agent_id = Some(agent_id);
        ended.task_id = Some(task);
        ended.outcome = Some("person".into());
        ended.decided_at = Some(20);
        ended.account_signature = Some(Blob::new(
            agent::sign_task_end(&keys, account, task, agent_id, 20)
                .to_bytes()
                .to_vec(),
        ));
        let mut expired = AuditEvent::new(ActorKind::Agent, "task.ended");
        expired.agent_id = Some(agent_id);
        expired.task_id = Some(task);
        expired.outcome = Some("expiry".into());
        let check = |events: Vec<AuditEvent>| {
            verify(
                account,
                keys.public(),
                &agents,
                &entries_of(events),
                &[],
                None,
            )
        };
        let report = check(vec![decided_event.clone(), ended.clone(), expired.clone()]).unwrap();
        assert_eq!(report.account_signatures, 2);

        // A decision the server changed, or without its signature.
        let mut forged = decided_event.clone();
        forged.signed = Some(Blob::new(b"{\"revision\":2}".to_vec()));
        assert!(check(vec![forged]).is_err());
        let mut unsigned = decided_event.clone();
        unsigned.account_signature = None;
        assert!(check(vec![unsigned]).is_err());
        let mut moved = ended.clone();
        moved.decided_at = Some(21);
        assert!(check(vec![moved]).is_err());
        let mut unsigned_end = ended;
        unsigned_end.account_signature = None;
        assert!(check(vec![unsigned_end]).is_err());
        // An agent event other than the expiry still needs a proof.
        let mut by_agent = expired;
        by_agent.outcome = Some("agent".into());
        assert!(check(vec![by_agent]).is_err());
    }

    // ------------------------------------------- the strict rules (G5) --

    use std::cell::Cell;

    use klav_core::ids::{ApprovalId, ProjectId, VaultId};
    use klav_proto::agent::{ApprovalRequest, Claims, GrantPayload};

    const AT: i64 = 1_800_000_000_000;

    /// An account and an agent it granted, with honest events.
    struct World {
        account: AccountId,
        keys: IdentityKeyPair,
        agent: AgentId,
        agent_keys: IdentityKeyPair,
        item: ItemId,
        nonce: Cell<u8>,
    }

    impl World {
        fn new() -> Self {
            Self {
                account: AccountId::generate(),
                keys: IdentityKeyPair::generate(),
                agent: AgentId::generate(),
                agent_keys: IdentityKeyPair::generate(),
                item: ItemId::generate(),
                nonce: Cell::new(0),
            }
        }

        fn listed(&self) -> HashMap<AgentId, PublicIdentity> {
            HashMap::from([(self.agent, self.agent_keys.public().clone())])
        }

        fn check(
            &self,
            events: Vec<AuditEvent>,
            listed: &HashMap<AgentId, PublicIdentity>,
        ) -> ClientResult<VerifyReport> {
            verify(
                self.account,
                self.keys.public(),
                listed,
                &entries_of(events),
                &[],
                None,
            )
        }

        fn granted_for(&self, agent: AgentId, payload_agent: AgentId) -> AuditEvent {
            let payload = serde_json::to_vec(&GrantPayload {
                v: 1,
                account_id: self.account,
                agent_id: payload_agent,
                version: 1,
                issued_at: AT,
                policy: klav_core::policy::Policy::default(),
                projects: Vec::new(),
                items: Vec::new(),
                profiles: Vec::new(),
                issuers: Vec::new(),
                sandbox: None,
                local_clients: Vec::new(),
                released: Vec::new(),
            })
            .unwrap();
            let signature = agent::sign_grant(
                &self.keys,
                &GrantToSign {
                    account: self.account,
                    agent,
                    agent_public: self.agent_keys.public(),
                    payload: &payload,
                },
            );
            let mut e = AuditEvent::new(ActorKind::Person, "agent.granted");
            e.at = AT;
            e.agent_id = Some(agent);
            e.signed = Some(Blob::new(payload));
            e.account_signature = Some(Blob::new(signature.to_bytes().to_vec()));
            e
        }

        fn granted(&self) -> AuditEvent {
            self.granted_for(self.agent, self.agent)
        }

        /// An agent event backed by a request the agent really signed.
        fn signed(
            &self,
            action: &str,
            method: &str,
            path: &str,
            body: Option<&[u8]>,
            timestamp: i64,
        ) -> AuditEvent {
            let n = self.nonce.get() + 1;
            self.nonce.set(n);
            let nonce = [n; 16];
            let digest = agent::body_digest(body.unwrap_or_default());
            let signature = agent::sign_request(
                &self.agent_keys,
                &SignedRequest {
                    agent: self.agent,
                    method,
                    path,
                    timestamp_ms: u64::try_from(timestamp).unwrap(),
                    nonce: &nonce,
                    body_digest: &digest,
                },
            );
            let mut e = AuditEvent::new(ActorKind::Agent, action);
            e.at = AT;
            e.agent_id = Some(self.agent);
            e.agent_proof = Some(AgentProof {
                method: method.into(),
                path: path.into(),
                timestamp,
                nonce: Blob::new(nonce.to_vec()),
                body_digest: Blob::new(digest.to_vec()),
                body: body.map(|b| Blob::new(b.to_vec())),
                signature: Blob::new(signature.to_bytes().to_vec()),
            });
            e
        }

        fn access_body(&self) -> Vec<u8> {
            serde_json::to_vec(&serde_json::json!({
                "item_id": self.item,
                "permission": "fill",
                "reason": " log in ",
                "claims": {"domain": "example.com"},
            }))
            .unwrap()
        }

        /// `agent.access` as the server writes it.
        fn access(&self) -> AuditEvent {
            let body = self.access_body();
            let mut e = self.signed("agent.access", "POST", "/v1/agent/access", Some(&body), AT);
            e.item_id = Some(self.item);
            e.permission = Some(Permission::Fill);
            e.reason = Some("log in".into());
            e.domain = Some("example.com".into());
            e.outcome = Some("allow".into());
            e
        }

        fn approval(&self) -> AuditEvent {
            self.approval_for(Permission::Totp, Vec::new())
        }

        /// An `inject` access by the agent on `item`, allowed under
        /// `approval`.
        fn inject_access(&self, item: ItemId, approval: ApprovalId) -> AuditEvent {
            let body = serde_json::to_vec(&serde_json::json!({
                "item_id": item,
                "permission": "inject",
                "reason": "run",
                "approval_id": approval,
            }))
            .unwrap();
            let mut e = self.signed("agent.access", "POST", "/v1/agent/access", Some(&body), AT);
            e.item_id = Some(item);
            e.permission = Some(Permission::Inject);
            e.reason = Some("run".into());
            e.outcome = Some("allow".into());
            e.approval_id = Some(approval);
            e
        }

        fn approval_for(&self, permission: Permission, items: Vec<ItemId>) -> AuditEvent {
            let approval = ApprovalId::generate();
            let request = serde_json::to_vec(&ApprovalRequest {
                v: 1,
                approval_id: approval,
                agent_id: self.agent,
                agent_name: "bot".into(),
                permission,
                vault_id: VaultId::generate(),
                project_id: ProjectId::generate(),
                item_id: Some(self.item),
                reason: "code".into(),
                claims: Claims::default(),
                grant_version: 1,
                requested_at: AT,
                caller: None,
                items,
            })
            .unwrap();
            let parsed: ApprovalRequest = serde_json::from_slice(&request).unwrap();
            let signature = agent::sign_approval(
                &self.keys,
                &ApprovalToSign {
                    approval,
                    agent: self.agent,
                    request: &request,
                    approve: true,
                    lease_until_ms: 0,
                    decided_at_ms: 5,
                },
            );
            let mut e = AuditEvent::new(ActorKind::Person, "approval.decided");
            e.at = AT;
            e.agent_id = Some(self.agent);
            e.approval_id = Some(approval);
            e.vault_id = Some(parsed.vault_id);
            e.project_id = Some(parsed.project_id);
            e.item_id = parsed.item_id;
            e.permission = Some(parsed.permission);
            e.outcome = Some("approve".into());
            e.lease_until = Some(0);
            e.decided_at = Some(5);
            e.signed = Some(Blob::new(request));
            e.account_signature = Some(Blob::new(signature.to_bytes().to_vec()));
            e
        }
    }

    impl World {
        /// `agents.paused` (`pause`) or `agents.resumed` as the server
        /// writes it, signed by `keys`.
        fn pause_by(
            &self,
            keys: &IdentityKeyPair,
            agent: Option<AgentId>,
            pause: bool,
            at: i64,
            until: i64,
        ) -> AuditEvent {
            let signature = agent::sign_pause(
                keys,
                &PauseToSign {
                    account: self.account,
                    scope: agent.map_or(PauseScope::All, PauseScope::Agent),
                    pause,
                    at_ms: u64::try_from(at).unwrap(),
                    until_ms: u64::try_from(until).unwrap(),
                },
            );
            let mut e = AuditEvent::new(
                ActorKind::Person,
                if pause {
                    "agents.paused"
                } else {
                    "agents.resumed"
                },
            );
            e.at = at;
            e.agent_id = agent;
            e.decided_at = Some(at);
            e.until = (until != 0).then_some(until);
            e.account_signature = Some(Blob::new(signature.to_bytes().to_vec()));
            e
        }

        fn pause(&self, agent: Option<AgentId>, pause: bool, at: i64, until: i64) -> AuditEvent {
            self.pause_by(&self.keys, agent, pause, at, until)
        }

        /// An allowed `agent.access` logged at `at`.
        fn access_at(&self, at: i64) -> AuditEvent {
            let mut e = self.access();
            e.at = at;
            e
        }
    }

    impl World {
        /// `agent.revoked` of `agent` as the server writes it, signed by
        /// `keys` at `at`.
        fn revoked_by(&self, keys: &IdentityKeyPair, agent: AgentId, at: i64) -> AuditEvent {
            let signature =
                agent::sign_revocation(keys, self.account, agent, u64::try_from(at).unwrap());
            let mut e = AuditEvent::new(ActorKind::Person, "agent.revoked");
            e.at = at;
            e.agent_id = Some(agent);
            e.decided_at = Some(at);
            e.account_signature = Some(Blob::new(signature.to_bytes().to_vec()));
            e
        }

        fn revoked(&self, at: i64) -> AuditEvent {
            self.revoked_by(&self.keys, self.agent, at)
        }
    }

    /// An event the agent signed after the account revoked it is a
    /// warning, whatever its route and outcome, and never a failure: an
    /// older server could log a request already in flight when the
    /// revocation came. What the agent did before its revocation is quiet,
    /// and so is an event after it that names the agent but that the agent
    /// did not sign. "After" is the place in the chain, not the time: the
    /// server picks `at`, so an event logged after the revocation with
    /// earlier times still warns.
    #[test]
    fn an_agent_event_after_its_revocation_is_a_warning() {
        let w = World::new();
        // Logged after the revocation, with every time before it: its `at`,
        // and the time the agent signed (`AT`), both below the
        // revocation's `at` and `decided_at` (`AT + 1_000`), within the
        // clock window.
        let mut early = w.access();
        early.at = AT + 500;
        // The end of the agent's task the revocation caused: it names the
        // agent, but the server attests it, and the agent signed nothing.
        let mut ended = AuditEvent::new(ActorKind::Person, "task.ended");
        ended.at = AT + 1_000;
        ended.agent_id = Some(w.agent);
        ended.task_id = Some(TaskId::generate());
        ended.outcome = Some("revocation".into());
        let mut denied = w.access_at(AT + 2_000);
        denied.outcome = Some("deny".into());
        // Another route: a write asked for (`agent.ask`).
        let (vault, project) = (VaultId::generate(), ProjectId::generate());
        let body = serde_json::to_vec(&serde_json::json!({
            "permission": "update",
            "vault_id": vault,
            "project_id": project,
            "item_id": w.item,
            "reason": "rename it",
        }))
        .unwrap();
        let mut ask = w.signed(
            "agent.ask",
            "POST",
            "/v1/agent/approvals",
            Some(&body),
            AT + 2_500,
        );
        ask.at = AT + 2_500;
        ask.vault_id = Some(vault);
        ask.project_id = Some(project);
        ask.item_id = Some(w.item);
        ask.permission = Some(Permission::Update);
        ask.reason = Some("rename it".into());
        ask.outcome = Some("ask".into());
        let report = w
            .check(
                vec![
                    w.granted(),
                    w.access_at(AT),
                    w.revoked(AT + 1_000),
                    early,
                    ended,
                    w.access_at(AT + 1_500),
                    denied,
                    ask,
                ],
                &w.listed(),
            )
            .unwrap();
        assert_eq!(report.warnings.len(), 4, "{:?}", report.warnings);
        let expected = [
            (4, "agent.access"),
            (6, "agent.access"),
            (7, "agent.access"),
            (8, "agent.ask"),
        ];
        for (warning, (seq, action)) in report.warnings.iter().zip(expected) {
            assert!(
                warning.starts_with(&format!("event {seq} ({action}): agent {}", w.agent)),
                "{warning}"
            );
            assert!(warning.contains("acted after its revocation"), "{warning}");
            assert!(warning.contains("a warning, not a failure"), "{warning}");
            // The apps show a warning cut at 200 characters.
            assert!(warning.chars().count() <= 200, "{warning}");
        }
        assert_eq!(report.account_signatures, 2);
    }

    /// Only a revocation the account signed counts, and only for the agent
    /// it names: one by someone else fails the check as before, and another
    /// agent's revocation says nothing about this one.
    #[test]
    fn only_this_agents_signed_revocation_counts() {
        let w = World::new();
        let report = w
            .check(
                vec![
                    w.granted(),
                    w.revoked_by(&w.keys, AgentId::generate(), AT + 1_000),
                    w.access_at(AT + 1_500),
                ],
                &w.listed(),
            )
            .unwrap();
        assert!(report.warnings.is_empty(), "{:?}", report.warnings);

        let mallory = IdentityKeyPair::generate();
        assert!(
            w.check(
                vec![
                    w.granted(),
                    w.revoked_by(&mallory, w.agent, AT + 1_000),
                    w.access_at(AT + 1_500),
                ],
                &w.listed(),
            )
            .is_err()
        );
    }

    #[test]
    fn pauses_are_signed_and_accesses_outside_them_are_quiet() {
        let w = World::new();
        let report = w
            .check(
                vec![
                    w.granted(),
                    w.access_at(AT),
                    w.pause(None, true, AT + 1_000, 0),
                    w.pause(None, false, AT + 2_000, 0),
                    w.access_at(AT + 3_000),
                    // A pause with an end: an access after it is fine.
                    w.pause(Some(w.agent), true, AT + 4_000, AT + 5_000),
                    w.access_at(AT + 6_000),
                ],
                &w.listed(),
            )
            .unwrap();
        assert!(report.warnings.is_empty(), "{:?}", report.warnings);
        assert_eq!(report.account_signatures, 4);
    }

    #[test]
    fn an_access_allowed_during_a_pause_is_a_warning() {
        let w = World::new();
        let mut denied = w.access_at(AT + 1_500);
        denied.outcome = Some("deny".into());
        let report = w
            .check(
                vec![
                    w.granted(),
                    w.pause(None, true, AT + 1_000, 0),
                    w.access_at(AT + 1_500),
                    // A denied one is what a pause should produce: quiet.
                    denied,
                ],
                &w.listed(),
            )
            .unwrap();
        assert_eq!(report.warnings.len(), 1, "{:?}", report.warnings);
        assert!(report.warnings[0].contains("while it was paused"));

        // Resuming every agent does not lift the pause of one agent.
        let report = w
            .check(
                vec![
                    w.granted(),
                    w.pause(Some(w.agent), true, AT + 1_000, 0),
                    w.pause(None, false, AT + 1_100, 0),
                    w.access_at(AT + 1_500),
                ],
                &w.listed(),
            )
            .unwrap();
        assert_eq!(report.warnings.len(), 1, "{:?}", report.warnings);
        // Before the pause's end it still holds.
        let report = w
            .check(
                vec![
                    w.granted(),
                    w.pause(None, true, AT + 1_000, AT + 2_000),
                    w.access_at(AT + 1_999),
                ],
                &w.listed(),
            )
            .unwrap();
        assert_eq!(report.warnings.len(), 1, "{:?}", report.warnings);
    }

    #[test]
    fn a_replayed_or_forged_pause_is_rejected() {
        let w = World::new();
        let resume = w.pause(None, false, AT + 2_000, 0);
        assert_rejected(
            w.check(
                vec![
                    w.pause(None, true, AT + 1_000, 0),
                    resume.clone(),
                    w.pause(None, true, AT + 3_000, 0),
                    resume,
                ],
                &w.listed(),
            ),
            "replayed",
        );
        let mallory = IdentityKeyPair::generate();
        assert_rejected(
            w.check(vec![w.pause_by(&mallory, None, true, AT, 0)], &w.listed()),
            "does not verify",
        );
        // The server changes what was signed: the scope, the end.
        let mut moved = w.pause(None, true, AT, AT + 60_000);
        moved.agent_id = Some(w.agent);
        assert_rejected(w.check(vec![moved], &w.listed()), "does not verify");
        let mut longer = w.pause(None, true, AT, AT + 60_000);
        longer.until = None;
        assert_rejected(w.check(vec![longer], &w.listed()), "does not verify");
        let mut ending = w.pause(None, false, AT, 0);
        ending.until = Some(AT + 60_000);
        assert_rejected(w.check(vec![ending], &w.listed()), "end");
        // No end is no `until`: `Some(0)` signs the same bytes, and is not
        // the canonical form.
        let mut zero = w.pause(None, true, AT, 0);
        zero.until = Some(0);
        assert_rejected(w.check(vec![zero], &w.listed()), "end");
        let mut with_item = w.pause(None, true, AT, 0);
        with_item.item_id = Some(w.item);
        assert_rejected(w.check(vec![with_item], &w.listed()), "target");
        let mut unsigned = w.pause(None, true, AT, 0);
        unsigned.account_signature = None;
        assert_rejected(w.check(vec![unsigned], &w.listed()), "signature");
        // Only a pause has an end.
        let mut access = w.access();
        access.until = Some(AT);
        assert_rejected(
            w.check(vec![w.granted(), access], &w.listed()),
            "claims an end",
        );
        // An action that is not in the table.
        let mut frozen = w.pause(None, true, AT, 0);
        frozen.action = "agents.frozen".into();
        assert_rejected(w.check(vec![frozen], &w.listed()), "unknown action");
    }

    fn assert_rejected(result: ClientResult<VerifyReport>, why: &str) {
        match result {
            Err(ClientError::Security(message)) => {
                assert!(message.contains(why), "expected {why:?}, got {message:?}")
            }
            other => panic!("expected {why:?}, got {other:?}"),
        }
    }

    impl World {
        /// A step of a sandbox's life as the server logs it, signed by the
        /// proxy (`self.agent`).
        fn sandbox(&self, id: SandboxId, step: &str, body: serde_json::Value) -> AuditEvent {
            let body = serde_json::to_vec(&body).unwrap();
            let (action, path) = match step {
                "issued" => ("sandbox.issued", "/v1/agent/sandboxes".to_owned()),
                other => (
                    if other == "claimed" {
                        "sandbox.claimed"
                    } else {
                        "sandbox.revoked"
                    },
                    format!("/v1/agent/sandboxes/{id}/{other}"),
                ),
            };
            let mut e = self.signed(action, "POST", &path, Some(&body), AT);
            if step == "revoked" {
                let reason: serde_json::Value = serde_json::from_slice(&body).unwrap();
                e.outcome = reason["reason"].as_str().map(str::to_owned);
            }
            e
        }

        fn issued(&self, id: SandboxId, issuer: AgentId) -> AuditEvent {
            self.sandbox(
                id,
                "issued",
                serde_json::json!({"sandbox_id": id, "issuer_id": issuer, "label": "chat-123",
                    "profiles": ["railway"], "expires_at": AT + 3_600_000}),
            )
        }

        fn claimed(&self, id: SandboxId) -> AuditEvent {
            self.sandbox(
                id,
                "claimed",
                serde_json::json!({"channel_key_sha256": Blob::new(vec![7; 32])}),
            )
        }

        fn ended(&self, id: SandboxId, reason: &str) -> AuditEvent {
            self.sandbox(id, "revoked", serde_json::json!({ "reason": reason }))
        }
    }

    #[test]
    fn a_sandbox_life_verifies_in_order() {
        let w = World::new();
        let issuer = AgentId::generate();
        let (a, b) = (SandboxId::generate(), SandboxId::generate());
        let report = w
            .check(
                vec![
                    w.granted(),
                    w.issued(a, issuer),
                    w.claimed(a),
                    w.ended(a, "theft"),
                    w.issued(b, issuer),
                    w.ended(b, "ttl"),
                ],
                &w.listed(),
            )
            .unwrap();
        assert!(report.warnings.is_empty(), "{:?}", report.warnings);
        assert_eq!(report.agent_signatures, 5);
        // The report holds each sandbox's life, in the order issued, for
        // the person's list; an unchecked proxy's would not be there.
        let lives: Vec<_> = report
            .sandboxes
            .iter()
            .map(|s| {
                (
                    s.sandbox_id,
                    s.issuer,
                    s.claimed_at.is_some(),
                    s.end.map(|(reason, _)| reason),
                )
            })
            .collect();
        assert_eq!(
            lives,
            [
                (a, issuer, true, Some(SandboxEnd::Theft)),
                (b, issuer, false, Some(SandboxEnd::Ttl)),
            ]
        );
        assert!(report.sandboxes.iter().all(|s| s.proxy == w.agent));
        // Not in the report's JSON (`klavd`, `klav log verify --json`).
        let json = serde_json::to_value(&report).unwrap();
        assert!(json.get("sandboxes").is_none());
        // An unlisted proxy's signatures are not checked: no record.
        let unchecked = w
            .check(vec![w.granted(), w.issued(a, issuer)], &HashMap::new())
            .unwrap();
        assert!(unchecked.sandboxes.is_empty());
    }

    impl World {
        /// `sandbox.revoke_requested` as the server writes it, signed by
        /// `keys`: one sandbox (`scope`), or `all` with the list `ids`.
        fn revoke_by(
            &self,
            keys: &IdentityKeyPair,
            scope: Option<SandboxId>,
            ids: Vec<SandboxId>,
            at: i64,
        ) -> AuditEvent {
            let signature = klav_core::crypto::sandbox::sign_revoke(
                keys,
                &klav_core::crypto::sandbox::RevokeToSign {
                    account: self.account,
                    proxy: self.agent,
                    scope: scope.map_or(
                        klav_core::crypto::sandbox::RevokeScope::All,
                        klav_core::crypto::sandbox::RevokeScope::Sandbox,
                    ),
                    at_ms: u64::try_from(at).unwrap(),
                },
            );
            let mut e = AuditEvent::new(ActorKind::Person, "sandbox.revoke_requested");
            e.at = at;
            e.agent_id = Some(self.agent);
            e.decided_at = Some(at);
            e.sandbox_id = scope;
            e.sandbox_ids = ids;
            e.account_signature = Some(Blob::new(signature.to_bytes().to_vec()));
            e
        }

        fn revoke(&self, scope: Option<SandboxId>, ids: Vec<SandboxId>, at: i64) -> AuditEvent {
            self.revoke_by(&self.keys, scope, ids, at)
        }

        /// The proxy's `sandbox.revoked` with `person`, answering `at`.
        fn person_end(&self, id: SandboxId, at: i64) -> AuditEvent {
            self.sandbox(
                id,
                "revoked",
                serde_json::json!({"reason": "person", "at": at}),
            )
        }

        /// The proxy's allowed call for `sandbox`.
        fn proxied_for(&self, sandbox: SandboxId) -> AuditEvent {
            let body = serde_json::to_vec(&serde_json::json!({
                "item_id": self.item,
                "permission": "proxy",
                "reason": "deploy",
                "claims": {"domain": "api.example.com", "method": "POST", "path": "/graphql"},
                "sandbox": sandbox,
            }))
            .unwrap();
            let mut e = self.signed("agent.access", "POST", "/v1/agent/access", Some(&body), AT);
            e.item_id = Some(self.item);
            e.permission = Some(Permission::Proxy);
            e.reason = Some("deploy".into());
            e.domain = Some("api.example.com".into());
            e.method = Some("POST".into());
            e.path = Some("/graphql".into());
            e.outcome = Some("allow".into());
            e
        }

        /// A sandbox issued with its own end of life.
        fn issued_until(&self, id: SandboxId, issuer: AgentId, expires_at: i64) -> AuditEvent {
            self.sandbox(
                id,
                "issued",
                serde_json::json!({"sandbox_id": id, "issuer_id": issuer, "label": "chat-123",
                    "profiles": ["railway"], "expires_at": expires_at}),
            )
        }
    }

    fn sorted(mut ids: Vec<SandboxId>) -> Vec<SandboxId> {
        ids.sort();
        ids
    }

    /// The account's signed revocation of a sandbox's proxy, later in the
    /// chain than its issue, is what marks its record, with when the server
    /// logged it, for the person's revoked sandbox and for one never
    /// revoked alike. A sandbox issued after the revocation (a request in
    /// flight an older server logged, under the verifier's warning) is not
    /// marked: nothing hides it from the moment it exists.
    #[test]
    fn a_proxys_signed_revocation_marks_its_sandboxes() {
        let w = World::new();
        let issuer = AgentId::generate();
        let (a, b) = (SandboxId::generate(), SandboxId::generate());
        let report = w
            .check(
                vec![
                    w.granted(),
                    w.issued(a, issuer),
                    w.issued(b, issuer),
                    w.revoke(Some(a), Vec::new(), AT + 10),
                    w.revoked(AT + 1_000),
                ],
                &w.listed(),
            )
            .unwrap();
        let marks: Vec<_> = report
            .sandboxes
            .iter()
            .map(|r| (r.sandbox_id, r.proxy_revoked_at))
            .collect();
        assert_eq!(marks, vec![(a, Some(AT + 1_000)), (b, Some(AT + 1_000))]);

        let later = SandboxId::generate();
        let report = w
            .check(
                vec![
                    w.granted(),
                    w.issued(a, issuer),
                    w.revoked(AT + 1_000),
                    w.issued(later, issuer),
                ],
                &w.listed(),
            )
            .unwrap();
        let marks: Vec<_> = report
            .sandboxes
            .iter()
            .map(|r| (r.sandbox_id, r.proxy_revoked_at))
            .collect();
        assert_eq!(marks, vec![(a, Some(AT + 1_000)), (later, None)]);
        assert_eq!(report.warnings.len(), 1, "{:?}", report.warnings);
        assert!(
            report.warnings[0].starts_with("event 4 (sandbox.issued): agent"),
            "{:?}",
            report.warnings
        );
        assert!(report.warnings[0].contains("acted after its revocation"));
    }

    /// Hostile: nothing but the account's signed `agent.revoked` of that
    /// row's proxy marks a sandbox. The revocation of another agent (its
    /// issuer here) leaves it alone; one signed by any other key fails the
    /// whole verification, so no list comes out of it.
    #[test]
    fn only_the_accounts_revocation_of_its_proxy_marks_a_sandbox() {
        let w = World::new();
        let issuer = AgentId::generate();
        let a = SandboxId::generate();
        let report = w
            .check(
                vec![
                    w.granted(),
                    w.issued(a, issuer),
                    w.revoke(Some(a), Vec::new(), AT + 10),
                    w.revoked_by(&w.keys, issuer, AT + 1_000),
                ],
                &w.listed(),
            )
            .unwrap();
        assert_eq!(report.sandboxes.len(), 1);
        assert_eq!(report.sandboxes[0].proxy_revoked_at, None);

        let mallory = IdentityKeyPair::generate();
        assert!(
            w.check(
                vec![
                    w.granted(),
                    w.issued(a, issuer),
                    w.revoked_by(&mallory, w.agent, AT + 1_000),
                ],
                &w.listed(),
            )
            .is_err()
        );
    }

    /// The person revokes one sandbox, then all of them; the proxy answers
    /// each with `person` and the revocation's `at`, and ends another
    /// through its local socket (`person_local`, no revocation needed).
    #[test]
    fn a_persons_revocation_verifies_and_the_proxy_answers_it() {
        let w = World::new();
        let issuer = AgentId::generate();
        let (a, b, c, d) = (
            SandboxId::generate(),
            SandboxId::generate(),
            SandboxId::generate(),
            SandboxId::generate(),
        );
        let report = w
            .check(
                vec![
                    w.granted(),
                    w.issued(a, issuer),
                    w.issued(b, issuer),
                    w.issued(c, issuer),
                    w.claimed(a),
                    w.revoke(Some(a), Vec::new(), AT + 10),
                    w.person_end(a, AT + 10),
                    // `all` lists the live ones issued before it, sorted.
                    w.revoke(None, sorted(vec![b, c]), AT + 20),
                    w.person_end(b, AT + 20),
                    w.person_end(c, AT + 20),
                    // Issued after it: not covered; its own end is local.
                    w.issued(d, issuer),
                    w.ended(d, "person_local"),
                    // `all` again, with nothing live: an empty list.
                    w.revoke(None, Vec::new(), AT + 30),
                    // One sandbox again, already ended: still the person's.
                    w.revoke(Some(a), Vec::new(), AT + 40),
                ],
                &w.listed(),
            )
            .unwrap();
        assert!(report.warnings.is_empty(), "{:?}", report.warnings);
        assert_eq!(report.account_signatures, 1 + 4);
        assert_eq!(report.agent_signatures, 9);
    }

    /// `all` lists exactly the proxy's sandboxes the chain issued before
    /// it, not ended and not expired by the signed time, over-inclusive by
    /// the clock window (ADR 0036 E3.3, spec §13.11): the account does not
    /// sign the list, the chain and the signed time back it.
    #[test]
    fn an_all_lists_exactly_the_live_sandboxes_before_it() {
        let w = World::new();
        let issuer = AgentId::generate();
        let signed = AT + 100;
        let (a, b, ended, expired, recent) = (
            SandboxId::generate(),
            SandboxId::generate(),
            SandboxId::generate(),
            SandboxId::generate(),
            SandboxId::generate(),
        );
        let before = || {
            vec![
                w.granted(),
                w.issued(a, issuer),
                w.issued(b, issuer),
                w.issued(ended, issuer),
                w.ended(ended, "stop"),
                // Expired more than the window before the signed time: out.
                w.issued_until(expired, issuer, signed - CLOCK_SKEW_MS),
                // Expired within the window: listed (and barred either way).
                w.issued_until(recent, issuer, signed - CLOCK_SKEW_MS + 1),
            ]
        };
        let with = |ids: Vec<SandboxId>| {
            let mut events = before();
            events.push(w.revoke(None, ids, signed));
            w.check(events, &w.listed())
        };
        assert!(with(sorted(vec![a, b, recent])).is_ok());
        for wrong in [
            vec![a],
            // The list as the event's own time used to decide it.
            sorted(vec![a, b]),
            sorted(vec![a, b, recent, ended]),
            sorted(vec![a, b, recent, expired]),
            sorted(vec![a, b, recent, SandboxId::generate()]),
            {
                let mut v = sorted(vec![a, b, recent]);
                v.reverse();
                v
            },
            vec![a, a, b, recent],
        ] {
            assert_rejected(with(wrong), "lists other sandboxes");
        }
        // Another proxy's sandbox is not this proxy's to list.
        let other = World::new();
        let mut events = before();
        events.push(other.issued(SandboxId::generate(), issuer));
        events.push(w.revoke(None, sorted(vec![a, b, recent]), signed));
        assert!(w.check(events, &w.listed()).is_ok());
    }

    /// The same list, whatever the event's own time within the window: a
    /// device whose clock ran 5 min ahead of the server's or 5 min behind
    /// it signs an `at` that far from the event, and the list the server
    /// built from that `at` verifies.
    #[test]
    fn an_all_does_not_depend_on_the_events_own_time() {
        let w = World::new();
        let issuer = AgentId::generate();
        let signed = AT + 1_000;
        let (soon, later) = (SandboxId::generate(), SandboxId::generate());
        for logged_at in [signed - CLOCK_SKEW_MS, signed, signed + CLOCK_SKEW_MS] {
            let mut r = w.revoke(None, sorted(vec![soon, later]), signed);
            r.at = logged_at;
            let events = vec![
                w.granted(),
                // Expires just after the signed time: before the event when
                // the device ran behind, and still covered.
                w.issued_until(soon, issuer, signed + 1),
                w.issued(later, issuer),
                r,
            ];
            assert!(w.check(events, &w.listed()).is_ok(), "{logged_at}");
        }
    }

    /// The event's own time, which nobody signs, must be within the clock
    /// window of the time the person signed (review of #341, 2). It no
    /// longer decides which sandboxes an `all` covers (the signed time
    /// does), so this is a sanity check: a chain logged a day late fails.
    #[test]
    fn a_revocation_logged_far_from_when_the_person_signed_it_fails() {
        const HOUR: i64 = 3_600_000;
        let w = World::new();
        let issuer = AgentId::generate();
        let a = SandboxId::generate();
        let run = |logged_at: i64, one: Option<SandboxId>, ids: Vec<SandboxId>| {
            let mut r = w.revoke(one, ids, AT + 10);
            r.at = logged_at;
            w.check(
                vec![w.granted(), w.issued_until(a, issuer, AT + HOUR), r],
                &w.listed(),
            )
        };
        // The reviewer's chain: an `all` logged a day later, leaving out
        // `a`, which lives for an hour.
        assert_rejected(run(AT + 24 * HOUR, None, Vec::new()), "too far from");
        // Honest ones, at the edges of the window.
        for logged_at in [AT + 10, AT + 10 + CLOCK_SKEW_MS, AT + 10 - CLOCK_SKEW_MS] {
            assert!(run(logged_at, None, vec![a]).is_ok(), "{logged_at}");
        }
        for logged_at in [AT + 10 + CLOCK_SKEW_MS + 1, AT + 10 - CLOCK_SKEW_MS - 1] {
            assert_rejected(run(logged_at, None, vec![a]), "too far from");
            assert_rejected(run(logged_at, Some(a), Vec::new()), "too far from");
        }
    }

    #[test]
    fn a_forged_replayed_or_reshaped_revocation_fails() {
        let w = World::new();
        let issuer = AgentId::generate();
        let a = SandboxId::generate();
        let run = |events: Vec<AuditEvent>| {
            let mut all = vec![w.granted(), w.issued(a, issuer)];
            all.extend(events);
            w.check(all, &w.listed())
        };
        let mallory = IdentityKeyPair::generate();
        assert_rejected(
            run(vec![w.revoke_by(&mallory, Some(a), Vec::new(), AT)]),
            "does not verify",
        );
        // The same scope again, or earlier: a replay.
        let once = w.revoke(Some(a), Vec::new(), AT + 10);
        assert_rejected(run(vec![once.clone(), once]), "replayed");
        assert_rejected(
            run(vec![
                w.revoke(None, vec![a], AT + 10),
                w.revoke(None, vec![a], AT + 5),
            ]),
            "replayed",
        );
        // What the account signed, moved: another scope, time or proxy.
        let mut moved = w.revoke(Some(a), Vec::new(), AT);
        moved.sandbox_id = None;
        moved.sandbox_ids = vec![a];
        assert_rejected(run(vec![moved]), "does not verify");
        let mut later = w.revoke(Some(a), Vec::new(), AT);
        later.decided_at = Some(AT + 1);
        assert_rejected(run(vec![later]), "does not verify");
        let mut untimed = w.revoke(Some(a), Vec::new(), AT);
        untimed.decided_at = None;
        assert_rejected(run(vec![untimed]), "no time");
        let mut nobody = w.revoke(Some(a), Vec::new(), AT);
        nobody.agent_id = None;
        assert_rejected(run(vec![nobody]), "no proxy");
        // A sandbox that proxy never issued.
        let stranger = SandboxId::generate();
        assert_rejected(
            run(vec![w.revoke(Some(stranger), Vec::new(), AT)]),
            "no sandbox that proxy issued",
        );
        // One sandbox with a list, or anything else on the event.
        let mut listed = w.revoke(Some(a), Vec::new(), AT);
        listed.sandbox_ids = vec![a];
        assert_rejected(run(vec![listed]), "sandboxes differs");
        let mut with_item = w.revoke(Some(a), Vec::new(), AT);
        with_item.item_id = Some(w.item);
        assert_rejected(run(vec![with_item]), "target");
        let mut with_outcome = w.revoke(Some(a), Vec::new(), AT);
        with_outcome.outcome = Some("allow".into());
        assert_rejected(run(vec![with_outcome]), "data");
        let mut unsigned = w.revoke(Some(a), Vec::new(), AT);
        unsigned.account_signature = None;
        assert_rejected(run(vec![unsigned]), "signature");
        let mut agent = w.revoke(Some(a), Vec::new(), AT);
        agent.actor = ActorKind::Agent;
        assert_rejected(run(vec![agent]), "wrong actor");
        // No other event names sandboxes this way.
        let mut access = w.access();
        access.sandbox_id = Some(a);
        assert_rejected(run(vec![access]), "sandbox nobody signed");
        let mut issued = w.issued(SandboxId::generate(), issuer);
        issued.sandbox_ids = vec![a];
        assert_rejected(run(vec![issued]), "sandbox nobody signed");
    }

    /// `person` answers a revocation of that sandbox by the person, earlier
    /// in the chain, with its `at`; `at` goes with `person` only.
    #[test]
    fn a_person_end_answers_a_revocation_before_it() {
        let w = World::new();
        let issuer = AgentId::generate();
        let (a, b) = (SandboxId::generate(), SandboxId::generate());
        let run = |events: Vec<AuditEvent>| {
            let mut all = vec![w.granted(), w.issued(a, issuer), w.issued(b, issuer)];
            all.extend(events);
            w.check(all, &w.listed())
        };
        assert_rejected(
            run(vec![w.person_end(a, AT)]),
            "answers no revocation by the person",
        );
        assert_rejected(
            run(vec![
                w.revoke(Some(a), Vec::new(), AT + 10),
                w.person_end(a, AT + 11),
            ]),
            "answers no revocation by the person",
        );
        // A revocation of another sandbox is not this one's.
        assert_rejected(
            run(vec![
                w.revoke(Some(b), Vec::new(), AT + 10),
                w.person_end(a, AT + 10),
            ]),
            "answers no revocation by the person",
        );
        // The answer comes after the revocation, not before.
        assert_rejected(
            run(vec![
                w.person_end(a, AT + 10),
                w.revoke(Some(a), Vec::new(), AT + 10),
            ]),
            "answers no revocation by the person",
        );
        // An `all` that covers it is enough.
        assert!(
            run(vec![
                w.revoke(None, sorted(vec![a, b]), AT + 10),
                w.person_end(a, AT + 10),
            ])
            .is_ok()
        );
        for body in [
            serde_json::json!({"reason": "person"}),
            serde_json::json!({"reason": "person", "at": 0}),
            serde_json::json!({"reason": "person_local", "at": AT}),
            serde_json::json!({"reason": "stop", "at": AT}),
            serde_json::json!(["person", AT]),
            serde_json::json!(["person_local"]),
        ] {
            assert_rejected(
                run(vec![
                    w.revoke(Some(a), Vec::new(), AT),
                    w.sandbox(a, "revoked", body),
                ]),
                "not the action's request",
            );
        }
    }

    /// After the person's revocation, an allowed call for that sandbox or
    /// its claim is a warning, as an access during a pause is (ADR 0036
    /// E3.3, ADR 0033 §7.6). Before it, and for another sandbox, quiet.
    #[test]
    fn a_call_or_claim_after_the_persons_revocation_is_a_warning() {
        let w = World::new();
        let issuer = AgentId::generate();
        let (a, b) = (SandboxId::generate(), SandboxId::generate());
        let report = w
            .check(
                vec![
                    w.granted(),
                    w.issued(a, issuer),
                    w.issued(b, issuer),
                    w.proxied_for(a),
                    w.revoke(Some(a), Vec::new(), AT + 10),
                    w.proxied_for(b),
                    w.proxied_for(a),
                    w.claimed(a),
                ],
                &w.listed(),
            )
            .unwrap();
        assert_eq!(report.warnings.len(), 2, "{:?}", report.warnings);
        assert!(report.warnings[0].contains("after the person revoked"));
        assert!(report.warnings[1].contains("after the person revoked"));
        // A refused call is what a revocation should produce: quiet.
        let mut refused = w.proxied_for(a);
        refused.outcome = Some("deny".into());
        let report = w
            .check(
                vec![
                    w.granted(),
                    w.issued(a, issuer),
                    w.revoke(Some(a), Vec::new(), AT + 10),
                    refused,
                ],
                &w.listed(),
            )
            .unwrap();
        assert!(report.warnings.is_empty(), "{:?}", report.warnings);
    }

    #[test]
    fn a_sandbox_step_out_of_order_or_unsigned_fails() {
        let w = World::new();
        let issuer = AgentId::generate();
        let id = SandboxId::generate();
        let run = |events: Vec<AuditEvent>| {
            let mut all = vec![w.granted()];
            all.extend(events);
            w.check(all, &w.listed())
        };
        assert_rejected(run(vec![w.claimed(id)]), "no sandbox that proxy issued");
        assert_rejected(
            run(vec![w.ended(id, "stop")]),
            "no sandbox that proxy issued",
        );
        assert_rejected(
            run(vec![w.issued(id, issuer), w.issued(id, issuer)]),
            "already issued",
        );
        assert_rejected(
            run(vec![w.issued(id, issuer), w.claimed(id), w.claimed(id)]),
            "claimed before",
        );
        assert_rejected(
            run(vec![
                w.issued(id, issuer),
                w.ended(id, "stop"),
                w.ended(id, "ttl"),
            ]),
            "after the sandbox's end",
        );
        assert_rejected(
            run(vec![
                w.issued(id, issuer),
                w.ended(id, "stop"),
                w.claimed(id),
            ]),
            "after the sandbox's end",
        );
        for reason in ["theft", "released"] {
            assert_rejected(
                run(vec![w.issued(id, issuer), w.ended(id, reason)]),
                "only a claimed sandbox",
            );
        }
        // A reason outside the closed set is not a request of that route.
        assert_rejected(
            run(vec![w.issued(id, issuer), w.ended(id, "person")]),
            "not the action's request",
        );
        // The reason logged must be the one signed.
        let mut lied = w.ended(id, "stop");
        lied.outcome = Some("ttl".into());
        assert_rejected(run(vec![w.issued(id, issuer), lied]), "reason differs");
        let mut silent = w.ended(id, "stop");
        silent.outcome = None;
        assert_rejected(run(vec![w.issued(id, issuer), silent]), "reason differs");
        // Nothing but the proxy and the reason on the event.
        let mut extra = w.issued(id, issuer);
        extra.item_id = Some(w.item);
        assert_rejected(run(vec![extra]), "target differs");
        let mut extra = w.claimed(id);
        extra.reason = Some("why".into());
        assert_rejected(run(vec![w.issued(id, issuer), extra]), "data differs");
        // Without the body the proxy signed.
        let mut bare = w.issued(id, issuer);
        bare.agent_proof.as_mut().unwrap().body = None;
        assert_rejected(run(vec![bare]), "lacks the body");
        // Signed for another route.
        let mut moved = w.claimed(id);
        moved.action = "sandbox.revoked".into();
        assert_rejected(run(vec![w.issued(id, issuer), moved]), "not this action");
        // Another proxy (one the server does not list, so only a warning
        // for its key) cannot claim this proxy's sandbox.
        let other = World::new();
        assert_rejected(
            run(vec![w.issued(id, issuer), other.claimed(id)]),
            "no sandbox that proxy issued",
        );
        // A label nobody may show.
        let bad = w.sandbox(
            id,
            "issued",
            serde_json::json!({"sandbox_id": id, "issuer_id": issuer, "label": "a\u{202e}b",
                "profiles": ["railway"], "expires_at": AT}),
        );
        assert_rejected(run(vec![bad]), "sandbox differs");
    }

    #[test]
    fn a_sandbox_issued_or_claimed_in_a_pause_is_a_warning() {
        let w = World::new();
        let issuer = AgentId::generate();
        let (a, b) = (SandboxId::generate(), SandboxId::generate());
        let mut events = vec![w.granted(), w.pause(Some(issuer), true, AT - 1_000, 0)];
        events.push(w.issued(a, issuer));
        events.push(w.pause(Some(issuer), false, AT - 500, 0));
        events.push(w.issued(b, issuer));
        // An end is never one: it only takes access away.
        events.push(w.pause(None, true, AT - 100, 0));
        events.push(w.ended(b, "stop"));
        let report = w.check(events, &w.listed()).unwrap();
        assert_eq!(report.warnings.len(), 1, "{:?}", report.warnings);
        assert!(report.warnings[0].contains("was paused"));
    }

    impl World {
        /// The proxy's `sandbox.store_reset` with `epoch`.
        fn store_reset(&self, epoch: &[u8]) -> AuditEvent {
            let body = serde_json::to_vec(
                &serde_json::json!({ "store_epoch": Blob::new(epoch.to_vec()) }),
            )
            .unwrap();
            self.signed(
                "sandbox.store_reset",
                "POST",
                PATH_STORE_RESET,
                Some(&body),
                AT,
            )
        }
    }

    /// Each reset names a new epoch, and the last one is the proxy's
    /// current epoch in the report (spec §13.12).
    #[test]
    fn a_store_reset_sets_the_proxys_epoch_once() {
        let w = World::new();
        let (one, two) = ([1u8; 16], [2u8; 16]);
        let report = w
            .check(
                vec![w.granted(), w.store_reset(&one), w.store_reset(&two)],
                &w.listed(),
            )
            .unwrap();
        assert!(report.warnings.is_empty(), "{:?}", report.warnings);
        assert_eq!(report.agent_signatures, 2);
        assert_eq!(
            report.store_epochs,
            vec![StoreEpoch {
                proxy: w.agent,
                store_epoch: Blob::new(two.to_vec()),
                seq: 3,
            }]
        );
        // The report keeps it across the apps' boundary.
        let back: VerifyReport =
            serde_json::from_str(&serde_json::to_string(&report).unwrap()).unwrap();
        assert_eq!(back.store_epochs, report.store_epochs);
        // A proxy never starts an epoch twice, not even an old one.
        assert_rejected(
            w.check(
                vec![
                    w.granted(),
                    w.store_reset(&one),
                    w.store_reset(&two),
                    w.store_reset(&one),
                ],
                &w.listed(),
            ),
            "started before",
        );
        // Another proxy may happen to name the same bytes: epochs are
        // per proxy.
        let other = World::new();
        let report = w
            .check(
                vec![w.granted(), w.store_reset(&one), other.store_reset(&one)],
                &w.listed(),
            )
            .unwrap();
        // Its key was not checked (the server does not list it), so it
        // has no current epoch: none of its heartbeats would count.
        assert_eq!(report.warnings.len(), 1, "{:?}", report.warnings);
        assert_eq!(report.store_epochs.len(), 1);
        assert_eq!(report.store_epochs[0].proxy, w.agent);
    }

    #[test]
    fn a_store_reset_out_of_shape_fails() {
        let w = World::new();
        let run = |events: Vec<AuditEvent>| {
            let mut all = vec![w.granted()];
            all.extend(events);
            w.check(all, &w.listed())
        };
        assert_rejected(run(vec![w.store_reset(&[1; 15])]), "store epoch differs");
        let extra = w.signed(
            "sandbox.store_reset",
            "POST",
            PATH_STORE_RESET,
            Some(br#"{"store_epoch":"AQEBAQEBAQEBAQEBAQEBAQ","seq":1}"#),
            AT,
        );
        assert_rejected(run(vec![extra]), "not the action's request");
        // Only as an object: serde also reads the struct from an array.
        let listed = w.signed(
            "sandbox.store_reset",
            "POST",
            PATH_STORE_RESET,
            Some(br#"["AQEBAQEBAQEBAQEBAQEBAQ"]"#),
            AT,
        );
        assert_rejected(run(vec![listed]), "not the action's request");
        let mut bare = w.store_reset(&[1; 16]);
        bare.agent_proof.as_mut().unwrap().body = None;
        assert_rejected(run(vec![bare]), "lacks the body");
        // A heartbeat is not a reset, even signed by the same proxy.
        let moved = w.signed(
            "sandbox.store_reset",
            "PUT",
            klav_proto::sandbox::PATH_SANDBOX_STATE,
            Some(br#"{"store_epoch":"AQEBAQEBAQEBAQEBAQEBAQ"}"#),
            AT,
        );
        assert_rejected(run(vec![moved]), "not this action");
        let mut said = w.store_reset(&[1; 16]);
        said.outcome = Some("allow".into());
        assert_rejected(run(vec![said]), "reason differs");
        let mut named = w.store_reset(&[1; 16]);
        named.sandbox_id = Some(SandboxId::generate());
        assert_rejected(run(vec![named]), "names a sandbox nobody signed");
        let mut extra = w.store_reset(&[1; 16]);
        extra.item_id = Some(w.item);
        assert_rejected(run(vec![extra]), "target differs");
        // While the proxy was paused: the server would have refused it.
        let report = run(vec![
            w.pause(Some(w.agent), true, AT - 1_000, 0),
            w.store_reset(&[1; 16]),
        ])
        .unwrap();
        assert_eq!(report.warnings.len(), 1, "{:?}", report.warnings);
        assert!(report.warnings[0].contains("was paused"));
    }

    #[test]
    fn an_honest_agent_chain_verifies() {
        let w = World::new();
        let task = TaskId::generate();
        let request = serde_json::to_vec(&serde_json::json!({
            "v": 1, "task": "facturas", "reason": "descargar", "duration_secs": 600,
            "access": [{"vault_id": VaultId::generate(), "project_id": ProjectId::generate(),
                        "item_id": w.item, "permissions": ["fill"]}],
        }))
        .unwrap();
        let mut requested = w.signed(
            "task.requested",
            "POST",
            "/v1/agent/tasks",
            Some(&request),
            AT,
        );
        requested.task_id = Some(task);
        requested.reason = Some("descargar".into());
        let end = br#"{"reason":"listo"}"#;
        let mut ended = w.signed(
            "task.ended",
            "POST",
            &format!("/v1/agent/tasks/{task}/end"),
            Some(end),
            AT + CLOCK_SKEW_MS,
        );
        ended.task_id = Some(task);
        ended.outcome = Some("agent".into());
        ended.reason = Some("listo".into());
        // An item write too large to keep its body.
        let mut update = w.signed(
            "agent.update",
            "PUT",
            &format!("/v1/agent/items/{}", w.item),
            None,
            AT - CLOCK_SKEW_MS,
        );
        update.item_id = Some(w.item);
        update.permission = Some(Permission::Update);
        update.reason = Some("rotate".into());
        let mut registered = AuditEvent::new(ActorKind::Agent, "agent.registered");
        registered.agent_id = Some(w.agent);
        let report = w
            .check(
                vec![
                    registered,
                    w.granted(),
                    w.access(),
                    w.approval(),
                    requested,
                    ended,
                    update,
                ],
                &w.listed(),
            )
            .unwrap();
        assert_eq!(report.agent_signatures, 4);
        assert_eq!(report.account_signatures, 2);
        assert!(report.warnings.is_empty());
    }

    #[test]
    fn an_access_needs_the_body_the_agent_signed() {
        let w = World::new();
        let mut access = w.access();
        access.agent_proof.as_mut().unwrap().body = None;
        assert_rejected(
            w.check(vec![w.granted(), access], &w.listed()),
            "lacks the body",
        );
        let mut task = w.signed("task.requested", "POST", "/v1/agent/tasks", None, AT);
        task.task_id = Some(TaskId::generate());
        task.reason = Some("x".into());
        assert_rejected(
            w.check(vec![w.granted(), task], &w.listed()),
            "lacks the body",
        );
    }

    /// A `fill` that names a sandbox is something the server refuses
    /// before it logs (ADR 0036 E3.3): in the chain it is tampering.
    #[test]
    fn only_a_proxied_access_names_a_sandbox() {
        let w = World::new();
        let body = serde_json::to_vec(&serde_json::json!({
            "item_id": w.item,
            "permission": "fill",
            "reason": " log in ",
            "claims": {"domain": "example.com"},
            "sandbox": klav_core::ids::SandboxId::generate(),
        }))
        .unwrap();
        let mut e = w.signed("agent.access", "POST", "/v1/agent/access", Some(&body), AT);
        e.item_id = Some(w.item);
        e.permission = Some(Permission::Fill);
        e.reason = Some("log in".into());
        e.domain = Some("example.com".into());
        e.outcome = Some("allow".into());
        assert_rejected(
            w.check(vec![w.granted(), e], &w.listed()),
            "a sandbox on an access that is not proxy",
        );
    }

    #[test]
    fn the_action_not_the_actor_decides_what_is_required() {
        let w = World::new();
        // An agent's item change, written as if the person made it.
        let mut person = AuditEvent::new(ActorKind::Person, "agent.access");
        person.item_id = Some(w.item);
        assert_rejected(w.check(vec![person], &w.listed()), "wrong actor");
        let mut agent_wrote = AuditEvent::new(ActorKind::Agent, "item.updated");
        agent_wrote.item_id = Some(w.item);
        assert_rejected(w.check(vec![agent_wrote], &w.listed()), "wrong actor");
        assert_rejected(
            w.check(
                vec![AuditEvent::new(ActorKind::Person, "agent.export")],
                &w.listed(),
            ),
            "unknown action",
        );
        let mut odd_end = AuditEvent::new(ActorKind::Agent, "task.ended");
        odd_end.outcome = Some("magic".into());
        assert_rejected(w.check(vec![odd_end], &w.listed()), "unknown action");
        // Nothing signed backs a permission on a server-attested event.
        let mut claimed = AuditEvent::new(ActorKind::Person, "item.updated");
        claimed.permission = Some(Permission::Reveal);
        assert_rejected(w.check(vec![claimed], &w.listed()), "nobody signed");
    }

    #[test]
    fn a_passkey_use_is_the_persons_and_names_no_site() {
        // ADR 0020 §10: only the server attests it; with the agent and task
        // when an agent used it in a task, never with a host.
        let w = World::new();
        let mut used = AuditEvent::new(ActorKind::Person, "passkey.used");
        used.item_id = Some(w.item);
        w.check(vec![used.clone()], &w.listed()).expect("verifies");
        let mut as_agent = used.clone();
        as_agent.actor = ActorKind::Agent;
        assert_rejected(w.check(vec![as_agent], &w.listed()), "wrong actor");
        used.domain = Some("shop.example".into());
        assert_rejected(w.check(vec![used], &w.listed()), "nobody signed");
    }

    #[test]
    fn the_signed_route_must_be_the_actions() {
        let w = World::new();
        // A real signature of `GET /v1/agent/me`, passed off as an access.
        let mut me = w.signed("agent.access", "GET", "/v1/agent/me", Some(b""), AT);
        me.item_id = Some(w.item);
        me.permission = Some(Permission::Fill);
        assert_rejected(
            w.check(vec![w.granted(), me], &w.listed()),
            "not this action",
        );
        // An update signed for another item.
        let mut other = w.signed(
            "agent.update",
            "PUT",
            &format!("/v1/agent/items/{}", ItemId::generate()),
            None,
            AT,
        );
        other.item_id = Some(w.item);
        other.permission = Some(Permission::Update);
        assert_rejected(
            w.check(vec![w.granted(), other], &w.listed()),
            "not this action",
        );
    }

    #[test]
    fn the_event_says_what_the_agent_signed() {
        let w = World::new();
        let mut item = w.access();
        item.item_id = Some(ItemId::generate());
        assert_rejected(w.check(vec![w.granted(), item], &w.listed()), "the item");
        let mut permission = w.access();
        permission.permission = Some(Permission::Reveal);
        assert_rejected(
            w.check(vec![w.granted(), permission], &w.listed()),
            "the permission",
        );
        let mut host = w.access();
        host.domain = Some("bank.example".into());
        assert_rejected(w.check(vec![w.granted(), host], &w.listed()), "the host");
        let mut dropped = w.access();
        dropped.domain = None;
        assert_rejected(w.check(vec![w.granted(), dropped], &w.listed()), "the host");
    }

    #[test]
    fn a_proxied_call_says_the_method_and_path_the_agent_signed() {
        let w = World::new();
        let proxied = || {
            let body = serde_json::to_vec(&serde_json::json!({
                "item_id": w.item,
                "permission": "proxy",
                "reason": "deploy",
                "claims": {"domain": "api.example.com", "method": "POST", "path": "/graphql"},
            }))
            .unwrap();
            let mut e = w.signed("agent.access", "POST", "/v1/agent/access", Some(&body), AT);
            e.item_id = Some(w.item);
            e.permission = Some(Permission::Proxy);
            e.reason = Some("deploy".into());
            e.domain = Some("api.example.com".into());
            e.method = Some("POST".into());
            e.path = Some("/graphql".into());
            e.outcome = Some("allow".into());
            e
        };
        let report = w.check(vec![w.granted(), proxied()], &w.listed()).unwrap();
        assert_eq!(report.agent_signatures, 1);

        let mut method = proxied();
        method.method = Some("DELETE".into());
        assert_rejected(
            w.check(vec![w.granted(), method], &w.listed()),
            "the method",
        );
        let mut path = proxied();
        path.path = Some("/admin".into());
        assert_rejected(w.check(vec![w.granted(), path], &w.listed()), "the path");
        let mut dropped = proxied();
        dropped.path = None;
        assert_rejected(w.check(vec![w.granted(), dropped], &w.listed()), "the path");
        // A method or path the agent never signed, on another access…
        let mut fill = w.access();
        fill.method = Some("GET".into());
        assert_rejected(w.check(vec![w.granted(), fill], &w.listed()), "the method");
        // …or on an event nothing signed.
        let mut grant = w.granted();
        grant.path = Some("/".into());
        assert!(w.check(vec![grant], &w.listed()).is_err());
    }

    /// ADR 0049 §5.4 and §6: a proxied MCP call's signed tool, argument
    /// digest and local client verify, show in the log, and anything
    /// outside their grammars (which the server refuses before it logs)
    /// is tampering.
    #[test]
    fn an_mcp_call_verifies_and_out_of_grammar_fields_are_tampering() {
        let w = World::new();
        let args = klav_core::crypto::mcp::digest_text(&[4; 32]);
        let mcp =
            |permission: &str, tool: &str, local: Option<&str>, sandbox: Option<SandboxId>| {
                let mut body = serde_json::json!({
                    "item_id": w.item,
                    "permission": permission,
                    "reason": "look at the logs",
                    "claims": {
                        "domain": "api.maple.dev", "method": "POST", "path": "/mcp",
                        "mcp_tool": tool, "mcp_args": args,
                    },
                });
                if let Some(local) = local {
                    body["local_client"] = local.into();
                }
                if let Some(sandbox) = sandbox {
                    body["sandbox"] = sandbox.to_string().into();
                }
                let body = serde_json::to_vec(&body).unwrap();
                let mut e = w.signed("agent.access", "POST", "/v1/agent/access", Some(&body), AT);
                e.item_id = Some(w.item);
                e.permission = serde_json::from_value(permission.into()).ok();
                e.reason = Some("look at the logs".into());
                e.domain = Some("api.maple.dev".into());
                e.method = Some("POST".into());
                e.path = Some("/mcp".into());
                e.outcome = Some("allow".into());
                e
            };
        let good = mcp("proxy", "query_logs", Some("claude-code"), None);
        let report = w
            .check(vec![w.granted(), good.clone()], &w.listed())
            .unwrap();
        assert_eq!(report.agent_signatures, 1);
        assert_eq!(
            mcp_of(&good),
            (Some("query_logs".into()), Some("claude-code".into()))
        );
        for (bad, why) in [
            (mcp("proxy", "query logs", None, None), "tool"),
            (mcp("proxy", "q\u{202e}l", None, None), "bidi tool"),
            (
                mcp("proxy", "query_logs", Some("Claude Code"), None),
                "client",
            ),
            (
                mcp(
                    "proxy",
                    "query_logs",
                    Some("cursor"),
                    Some(SandboxId::generate()),
                ),
                "two callers",
            ),
        ] {
            assert_eq!(mcp_of(&bad), (None, None), "{why}");
            assert_rejected(
                w.check(vec![w.granted(), bad], &w.listed()),
                "MCP tool or caller",
            );
        }
        // A tool on anything but `proxy`.
        let mut fill = mcp("fill", "query_logs", None, None);
        fill.method = None;
        fill.path = None;
        assert!(w.check(vec![w.granted(), fill], &w.listed()).is_err());
    }

    #[test]
    fn an_approval_with_an_mcp_tool_and_caller_verifies_only_in_grammar() {
        let w = World::new();
        let approval_for = |tool: &str, caller: Option<klav_proto::agent::ApprovalCaller>| {
            let approval = ApprovalId::generate();
            let request = serde_json::to_vec(&ApprovalRequest {
                v: 1,
                approval_id: approval,
                agent_id: w.agent,
                agent_name: "proxy".into(),
                permission: Permission::Proxy,
                vault_id: VaultId::generate(),
                project_id: ProjectId::generate(),
                item_id: Some(w.item),
                reason: "deploy".into(),
                claims: Claims {
                    domain: Some("api.maple.dev".into()),
                    method: Some("POST".into()),
                    path: Some("/mcp".into()),
                    mcp_tool: Some(tool.into()),
                    mcp_args: Some(klav_core::crypto::mcp::digest_text(&[1; 32])),
                    ..Claims::default()
                },
                grant_version: 1,
                requested_at: AT,
                caller,
                items: Vec::new(),
            })
            .unwrap();
            let parsed: ApprovalRequest = serde_json::from_slice(&request).unwrap();
            assert_eq!(
                crate::agents::approval_mcp_ok(&parsed),
                tool_name_ok_for_test(tool)
                    && parsed.caller.as_ref().is_none_or(|c| c.is_well_formed())
            );
            let signature = agent::sign_approval(
                &w.keys,
                &ApprovalToSign {
                    approval,
                    agent: w.agent,
                    request: &request,
                    approve: true,
                    lease_until_ms: 0,
                    decided_at_ms: 5,
                },
            );
            let mut e = AuditEvent::new(ActorKind::Person, "approval.decided");
            e.at = AT;
            e.agent_id = Some(w.agent);
            e.approval_id = Some(approval);
            e.vault_id = Some(parsed.vault_id);
            e.project_id = Some(parsed.project_id);
            e.item_id = parsed.item_id;
            e.permission = Some(parsed.permission);
            e.outcome = Some("approve".into());
            e.lease_until = Some(0);
            e.decided_at = Some(5);
            e.signed = Some(Blob::new(request));
            e.account_signature = Some(Blob::new(signature.to_bytes().to_vec()));
            e
        };
        let client = |name: &str| klav_proto::agent::ApprovalCaller {
            sandbox_id: None,
            local_client: Some(name.into()),
        };
        w.check(
            vec![
                w.granted(),
                approval_for("deploy_worker", Some(client("cursor"))),
            ],
            &w.listed(),
        )
        .unwrap();
        w.check(
            vec![
                w.granted(),
                approval_for(
                    "deploy_worker",
                    Some(klav_proto::agent::ApprovalCaller {
                        sandbox_id: Some(SandboxId::generate()),
                        local_client: None,
                    }),
                ),
            ],
            &w.listed(),
        )
        .unwrap();
        for bad in [
            approval_for("deploy worker", None),
            approval_for("deploy_worker", Some(client("Cursor\u{202e}"))),
            approval_for(
                "deploy_worker",
                Some(klav_proto::agent::ApprovalCaller {
                    sandbox_id: None,
                    local_client: None,
                }),
            ),
        ] {
            assert_rejected(
                w.check(vec![w.granted(), bad], &w.listed()),
                "MCP tool or caller",
            );
        }
    }

    fn tool_name_ok_for_test(tool: &str) -> bool {
        klav_core::policy::tool_name_ok(tool)
    }

    #[test]
    fn a_security_card_is_never_decided() {
        let view = |security: Option<String>| crate::agents::ApprovalView {
            id: ApprovalId::generate(),
            status: klav_proto::agent::ApprovalStatus::Pending,
            agent_id: AgentId::generate(),
            agent: "proxy".into(),
            permission: Permission::Proxy,
            target: "x".into(),
            target_name: None,
            reason: "r".into(),
            domain: None,
            created_at: 0,
            expires_at: 0,
            lease_until: None,
            task: None,
            request_digest: String::new(),
            mcp_tool: None,
            sandbox: None,
            local_client: None,
            security,
            item_id: None,
            items: Vec::new(),
            items_warning: None,
            always_asks: false,
        };
        assert!(crate::agents::refuse_security_card(&view(None)).is_ok());
        let err = crate::agents::refuse_security_card(&view(Some(
            crate::agents::MCP_SECURITY_CARD.into(),
        )))
        .unwrap_err();
        assert!(matches!(err, ClientError::Security(_)));
        // The fixed text, never what the server sent.
        assert!(err.to_string().contains(crate::agents::MCP_SECURITY_CARD));
    }

    #[test]
    fn an_environment_approval_covers_only_the_items_it_lists() {
        // ADR 0032 §3.1: one approval for an environment and its protected
        // items; each access names it, and an item it does not list never
        // rides on it.
        let w = World::new();
        let stripe = ItemId::generate();
        let decided = w.approval_for(Permission::Inject, vec![stripe]);
        let id = decided.approval_id.unwrap();
        let report = w
            .check(
                vec![
                    w.granted(),
                    decided.clone(),
                    w.inject_access(w.item, id),
                    w.inject_access(stripe, id),
                ],
                &w.listed(),
            )
            .unwrap();
        assert!(report.warnings.is_empty(), "{:?}", report.warnings);
        assert_rejected(
            w.check(
                vec![
                    w.granted(),
                    decided.clone(),
                    w.inject_access(ItemId::generate(), id),
                ],
                &w.listed(),
            ),
            "signed for other items",
        );
        // Another permission under it is refused too.
        let mut reveal = w.inject_access(stripe, id);
        reveal.permission = Some(Permission::Reveal);
        assert!(
            w.check(vec![w.granted(), decided, reveal], &w.listed())
                .is_err()
        );
    }

    #[test]
    fn decisions_and_grants_say_what_the_account_signed() {
        let w = World::new();
        let mut approval = w.approval();
        approval.item_id = Some(ItemId::generate());
        assert_rejected(
            w.check(vec![w.granted(), approval], &w.listed()),
            "the item",
        );
        let mut permission = w.approval();
        permission.permission = Some(Permission::Reveal);
        assert_rejected(
            w.check(vec![w.granted(), permission], &w.listed()),
            "the permission",
        );
        let mut extra = w.approval();
        extra.reason = Some("something else".into());
        assert_rejected(w.check(vec![w.granted(), extra], &w.listed()), "the reason");
        // A grant whose payload names another agent than the one signed.
        let other = w.granted_for(w.agent, AgentId::generate());
        assert_rejected(w.check(vec![other], &w.listed()), "the agent");
    }

    #[test]
    fn only_a_grant_in_the_chain_vouches_for_an_agent_key() {
        let w = World::new();
        // Listed by the server, but no grant in the chain vouches for it.
        assert_rejected(w.check(vec![w.access()], &w.listed()), "vouches");
        // A key the server swapped no longer verifies the grant.
        let mut swapped = HashMap::new();
        swapped.insert(w.agent, IdentityKeyPair::generate().public().clone());
        assert_rejected(
            w.check(vec![w.granted(), w.access()], &swapped),
            "does not verify",
        );
        // An agent the server no longer lists: a warning, not tampering.
        let second = w.access();
        let report = w
            .check(vec![w.granted(), w.access(), second], &HashMap::new())
            .unwrap();
        assert_eq!(report.agent_signatures, 0);
        assert_eq!(report.account_signatures, 0);
        assert_eq!(report.warnings.len(), 1, "{:?}", report.warnings);
        // …but what the event says is still checked.
        let mut moved = w.access();
        moved.item_id = Some(ItemId::generate());
        assert_rejected(
            w.check(vec![w.granted(), moved], &HashMap::new()),
            "the item",
        );
    }

    #[test]
    fn a_request_backs_one_event_close_to_when_it_was_logged() {
        let w = World::new();
        let access = w.access();
        let mut replayed = access.clone();
        replayed.outcome = Some("deny".into());
        assert_rejected(
            w.check(vec![w.granted(), access, replayed], &w.listed()),
            "already used",
        );
        let body = w.access_body();
        let late = |offset: i64| {
            let mut e = w.signed(
                "agent.access",
                "POST",
                "/v1/agent/access",
                Some(&body),
                AT + offset,
            );
            e.item_id = Some(w.item);
            e.permission = Some(Permission::Fill);
            e.reason = Some("log in".into());
            e.domain = Some("example.com".into());
            e
        };
        assert_rejected(
            w.check(vec![w.granted(), late(CLOCK_SKEW_MS + 1)], &w.listed()),
            "too far",
        );
        assert_rejected(
            w.check(vec![w.granted(), late(-CLOCK_SKEW_MS - 1)], &w.listed()),
            "too far",
        );
        assert!(
            w.check(vec![w.granted(), late(CLOCK_SKEW_MS)], &w.listed())
                .is_ok()
        );
    }

    fn page(seqs: &[u64], head_seq: u64) -> AuditPage {
        AuditPage {
            entries: seqs
                .iter()
                .map(|&seq| {
                    let mut event = AuditEvent::new(ActorKind::Person, "item.created");
                    event.seq = seq;
                    klav_proto::audit::AuditEntry {
                        seq,
                        event: Blob::new(serde_json::to_vec(&event).unwrap()),
                        hash: Blob::new(vec![0; 32]),
                    }
                })
                .collect(),
            head_seq,
        }
    }

    #[test]
    fn pages_go_on_without_gaps() {
        let (entries, done) = accept_page(0, page(&[1, 2], 4)).unwrap();
        assert_eq!((entries.len(), done), (2, false));
        assert!(accept_page(2, page(&[3, 4], 4)).unwrap().1);
        assert!(accept_page(4, page(&[], 4)).unwrap().1);
        // A page that skips, repeats or goes back.
        assert!(accept_page(2, page(&[4], 4)).is_err());
        assert!(accept_page(2, page(&[2, 3], 4)).is_err());
        assert!(accept_page(2, page(&[3, 3], 4)).is_err());
        // A server that stops short and asks to be asked again.
        assert!(accept_page(2, page(&[], 4)).is_err());
    }

    #[test]
    fn the_pin_belongs_to_an_account() {
        let me = AccountId::generate();
        let file = |account_id| {
            StoredPin::File(PinFile {
                account_id,
                seq: 3,
                hash: [7; 32],
            })
        };
        let pin = Some(Pin {
            seq: 3,
            hash: [7; 32],
        });
        assert_eq!(choose_pin(me, file(Some(me)), true), (pin, None));
        // Written before the account was recorded: still this device's.
        assert_eq!(choose_pin(me, file(None), true), (pin, None));
        assert_eq!(
            choose_pin(me, file(Some(AccountId::generate())), true),
            (None, Some(Unpinned::OtherAccount))
        );
        // No pin while there are events: first use is said, not silent.
        assert_eq!(
            choose_pin(me, StoredPin::Missing, true),
            (None, Some(Unpinned::Missing))
        );
        assert_eq!(choose_pin(me, StoredPin::Missing, false), (None, None));
        assert_eq!(
            choose_pin(me, StoredPin::Unreadable, true),
            (None, Some(Unpinned::Unreadable))
        );
        // The file round-trips, and an old one without the account reads.
        let json = serde_json::to_string(&PinFile {
            account_id: Some(me),
            seq: 3,
            hash: [7; 32],
        })
        .unwrap();
        assert!(json.contains(&me.to_string()));
        let old: PinFile =
            serde_json::from_str(&format!("{{\"seq\":3,\"hash\":\"{}\"}}", "07".repeat(32)))
                .unwrap();
        assert_eq!(old.account_id, None);
    }

    /// `rotate.*` as the server writes it: the agent's steps with their
    /// signed request, the person's with no signature.
    fn rotation_events(w: &World, task: TaskId) -> Vec<AuditEvent> {
        let rotation = RotationId::generate();
        let start = serde_json::to_vec(&serde_json::json!({
            "item_id": w.item, "reason": "repetida",
            "claims": {"domain": "Banco.Example"}, "task_id": task,
        }))
        .unwrap();
        let mut started = w.signed(
            "rotate.started",
            "POST",
            "/v1/agent/rotations",
            Some(&start),
            AT,
        );
        started.task_id = Some(task);
        started.item_id = Some(w.item);
        started.permission = Some(Permission::Rotate);
        started.reason = Some("repetida".into());
        started.domain = Some("banco.example".into());
        started.outcome = Some("allow".into());
        let finish =
            serde_json::to_vec(&serde_json::json!({"item_id": w.item, "reason": "listo"})).unwrap();
        let mut confirmed = w.signed(
            "rotate.confirmed",
            "POST",
            &format!("/v1/agent/rotations/{rotation}/confirm"),
            Some(&finish),
            AT,
        );
        confirmed.task_id = Some(task);
        confirmed.item_id = Some(w.item);
        confirmed.permission = Some(Permission::Rotate);
        confirmed.reason = Some("listo".into());
        confirmed.domain = Some("banco.example".into());
        confirmed.outcome = Some("allow".into());
        let mut person = AuditEvent::new(ActorKind::Person, "rotate.cancelled");
        person.at = AT;
        person.agent_id = Some(w.agent);
        person.task_id = Some(task);
        person.item_id = Some(w.item);
        person.domain = Some("banco.example".into());
        let mut registered = AuditEvent::new(ActorKind::Agent, "agent.registered");
        registered.agent_id = Some(w.agent);
        vec![registered, w.granted(), started, confirmed, person]
    }

    #[test]
    fn a_password_change_allowed_during_a_pause_is_a_warning() {
        let w = World::new();
        let mut events = rotation_events(&w, TaskId::generate());
        // Paused before the agent's two steps; the person's is quiet.
        events.insert(2, w.pause(None, true, AT - 1_000, 0));
        let report = w.check(events, &w.listed()).unwrap();
        assert_eq!(report.warnings.len(), 2, "{:?}", report.warnings);
        assert!(report.warnings[0].contains("rotate.started"));
        assert!(report.warnings[1].contains("rotate.confirmed"));
        assert!(
            report
                .warnings
                .iter()
                .all(|w| w.contains("while it was paused"))
        );
    }

    #[test]
    fn a_password_change_is_tied_to_the_start_the_agent_signed() {
        let w = World::new();
        let task = TaskId::generate();
        let report = w.check(rotation_events(&w, task), &w.listed()).unwrap();
        assert_eq!(report.agent_signatures, 2);
        assert!(report.warnings.is_empty());

        // The person's decision on a host no change started on.
        let mut events = rotation_events(&w, task);
        events[4].domain = Some("evil.example".into());
        assert_rejected(w.check(events, &w.listed()), "names no change started");
        // …or under another task.
        let mut events = rotation_events(&w, task);
        events[4].task_id = Some(TaskId::generate());
        assert_rejected(w.check(events, &w.listed()), "names no change started");
        // A step with no start before it.
        let mut events = rotation_events(&w, task);
        events.remove(2);
        assert_rejected(w.check(events, &w.listed()), "names no change started");
        // The person's step claims a reason nobody signed.
        let mut events = rotation_events(&w, task);
        events[4].reason = Some("la persona dijo".into());
        assert_rejected(w.check(events, &w.listed()), "claims what nobody signed");
        // A confirm logged from a signed cancel.
        let mut events = rotation_events(&w, task);
        events[3].action = "rotate.cancelled".into();
        assert_rejected(w.check(events, &w.listed()), "not this action");
        // The start's host differs from what the agent signed.
        let mut events = rotation_events(&w, task);
        events[2].domain = Some("otro.example".into());
        assert_rejected(w.check(events, &w.listed()), "host differs");
        // A start let through without its task.
        let mut events = rotation_events(&w, task);
        events[2].task_id = None;
        assert_rejected(w.check(events, &w.listed()), "without its task");
        // The step loses the body the agent signed.
        let mut events = rotation_events(&w, task);
        events[3].agent_proof.as_mut().unwrap().body = None;
        assert_rejected(w.check(events, &w.listed()), "lacks the body");
    }

    #[test]
    fn secret_request_events_verify_and_reject_tampering() {
        use klav_core::crypto::agent::sign_secret_request_decision;
        use klav_core::ids::SecretRequestId;
        use klav_core::secret_request::{SECRET_REQUEST_FORMAT_VERSION, SecretRequestStatus};

        let w = World::new();
        let req_id = SecretRequestId::generate();
        let digest = [0xab_u8; 32];
        let created_body = b"{\"opaque\":true}";

        let mut created = w.signed(
            "secret_request.created",
            "POST",
            "/v1/agent/secret-requests",
            Some(created_body),
            AT,
        );
        // Server omits proof body so proposal_blob is never retained in audit_events.
        created.agent_proof.as_mut().unwrap().body = None;
        created.secret_request_id = Some(req_id);
        created.proposal_digest = Some(Blob::new(digest.to_vec()));
        created.reason = Some("Need Stripe API key".into());

        let vault = VaultId::generate();
        let project = ProjectId::generate();
        let decision = SecretRequestDecision {
            v: SECRET_REQUEST_FORMAT_VERSION,
            request_id: req_id,
            agent_id: w.agent,
            status: SecretRequestStatus::Fulfilled,
            in_grant: true,
            vault_id: Some(vault),
            project_id: Some(project),
            item_id: Some(w.item),
            field: Some("api_key".into()),
            proxy_profile: Some("stripe".into()),
        };
        let decision_bytes = serde_json::to_vec(&decision).unwrap();
        let sig = sign_secret_request_decision(
            &w.keys,
            &SecretRequestDecisionToSign {
                request: req_id,
                agent: w.agent,
                proposal_digest: &digest,
                decision: &decision_bytes,
                decided_at_ms: u64::try_from(AT).unwrap(),
            },
        );
        let mut decided = AuditEvent::new(ActorKind::Person, "secret_request.decided");
        decided.agent_id = Some(w.agent);
        decided.secret_request_id = Some(req_id);
        decided.proposal_digest = Some(Blob::new(digest.to_vec()));
        decided.vault_id = Some(vault);
        decided.project_id = Some(project);
        decided.item_id = Some(w.item);
        decided.outcome = Some("fulfilled".into());
        decided.decided_at = Some(AT);
        decided.signed = Some(Blob::new(decision_bytes));
        decided.account_signature = Some(Blob::new(sig.to_bytes().to_vec()));

        let report = w
            .check(
                vec![w.granted(), created.clone(), decided.clone()],
                &w.listed(),
            )
            .unwrap();
        assert_eq!(report.agent_signatures, 1);
        assert_eq!(report.account_signatures, 2);

        // Tampered item_id on secret_request.decided is rejected.
        let mut bad_item = decided.clone();
        bad_item.item_id = Some(ItemId::generate());
        assert_rejected(
            w.check(vec![w.granted(), created.clone(), bad_item], &w.listed()),
            "target differs",
        );

        // Tampered proposal_digest breaks the account signature.
        let mut bad_digest = decided.clone();
        bad_digest.proposal_digest = Some(Blob::new(vec![0xcd; 32]));
        assert_rejected(
            w.check(vec![w.granted(), created.clone(), bad_digest], &w.listed()),
            "signature does not verify",
        );

        // Tampered outcome is rejected.
        let mut bad_outcome = decided;
        bad_outcome.outcome = Some("denied".into());
        assert_rejected(
            w.check(vec![w.granted(), created, bad_outcome], &w.listed()),
            "outcome differs",
        );
    }
}
