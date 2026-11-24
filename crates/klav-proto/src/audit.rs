//! The audit log (design §6, `docs/api.md` §9, spec §13.7).
//!
//! One hash chain per account. Every event is stored as the exact JSON
//! bytes of an [`AuditEvent`]; `hash_n` covers them and `hash_{n-1}`. Agent
//! events carry the agent's signed request ([`AgentProof`]); decisions of
//! the person carry the account's signature. Events about the person's own
//! item changes are attested by the server only (ADR 0014 §6).

use klav_core::ids::{
    AgentId, ApprovalId, AttachmentId, DeviceId, ItemId, ProjectId, RotationId, SandboxId,
    SecretRequestId, TaskId, VaultId,
};
use klav_core::policy::Permission;
use serde::{Deserialize, Serialize};

use crate::Blob;

/// Version of [`AuditEvent`].
pub const AUDIT_EVENT_VERSION: u32 = 1;
/// Bodies of agent requests up to this size are kept in the proof (so the
/// reason and target can be checked against the signature); larger ones
/// (item writes) keep only their digest. Access, task requests, an agent's
/// end of its task and the steps of an assisted password change refuse
/// larger bodies, so their events always keep it (ADR 0030 §4).
pub const MAX_PROOF_BODY: usize = 16 * 1024;

/// Who acted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorKind {
    /// The person, from one of their devices.
    Person,
    /// An agent.
    Agent,
}

/// The agent's signed request behind an event (spec §13.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentProof {
    /// HTTP method.
    pub method: String,
    /// Path and query as signed.
    pub path: String,
    /// Agent time (Unix ms).
    pub timestamp: i64,
    /// Request nonce.
    pub nonce: Blob,
    /// SHA-256 of the body.
    pub body_digest: Blob,
    /// The body itself, when at most [`MAX_PROOF_BODY`] bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<Blob>,
    /// The agent's signature.
    pub signature: Blob,
}

/// One event of the log. Readers ignore unknown fields: the hash covers
/// the stored bytes, so a newer server can add fields without breaking it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Format version.
    pub v: u32,
    /// Position in the account's chain (from 1).
    pub seq: u64,
    /// Server time (Unix ms).
    pub at: i64,
    /// Person or agent.
    pub actor: ActorKind,
    /// Device of the person.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<DeviceId>,
    /// The agent (actor, or subject of a person's decision).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<AgentId>,
    /// What happened: `agent.registered`, `agent.granted`, `agent.denied`,
    /// `agent.revoked`, `agent.access`, `agent.create`, `agent.update`,
    /// `agent.trash`, `agent.ask`, `approval.decided`, `task.requested`, `task.decided`,
    /// `task.ended`, `item.created`, `item.updated`, `item.trashed`,
    /// `item.restored`, `item.purged`, `project.rotated`, `passkey.used`,
    /// `agents.paused`, `agents.resumed`, `sandbox.issued`,
    /// `sandbox.claimed`, `sandbox.revoked`, `sandbox.revoke_requested`.
    pub action: String,
    /// Vault.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault_id: Option<VaultId>,
    /// Project.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_id: Option<ProjectId>,
    /// Item.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub item_id: Option<ItemId>,
    /// Permission used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permission: Option<Permission>,
    /// `allow`, `ask` or `deny` (policy), `approve` or `deny` (decision);
    /// in `task.ended`, who ended it (`person`, `agent`, `expiry`,
    /// `revocation`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<String>,
    /// The agent's reason.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Claimed host (`fill`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    /// HTTP method of a proxied request (`proxy`, ADR 0036 §9), as the
    /// proxy signed it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    /// HTTP path of a proxied request, without query, as the proxy signed
    /// it (`proxy`). Never a body or a header.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Attachments delivered with an allowed `inject` (ADR 0016).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attachments: Vec<AttachmentId>,
    /// Approval request involved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_id: Option<ApprovalId>,
    /// Task involved: the task of a `task.*` event, or the task that let an
    /// agent action through (ADR 0021 §9).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_id: Option<TaskId>,
    /// Lease of an approval (Unix ms; `0`: once).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_until: Option<i64>,
    /// When the person decided (Unix ms), as signed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decided_at: Option<i64>,
    /// In `agents.paused`: when the pause ends by itself (Unix ms), as
    /// signed; absent when it lasts until the person resumes (spec §13.9).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<i64>,
    /// Alerts raised: `first_use` (first time this agent uses this item's
    /// secrets), `burst` (more than 20 uses in a minute), `denied`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub alerts: Vec<String>,
    /// The agent's signed request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_proof: Option<AgentProof>,
    /// What the account signed: grant payload, approval request bytes or
    /// task decision bytes. (A `task.requested` keeps the agent's request
    /// in its proof's body, not here.)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed: Option<Blob>,
    /// In `task.decided`: the agent's task request the decision answers,
    /// exactly as stored, so the account's signature (spec §13.8) can be
    /// checked from this event alone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_request: Option<Blob>,
    /// The account's signature over it (spec §13.4–13.6, §13.8, §13.9,
    /// §13.11).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_signature: Option<Blob>,
    /// In `sandbox.revoke_requested`: the sandbox the person revoked;
    /// absent when the revocation is `all` (spec §13.11).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sandbox_id: Option<SandboxId>,
    /// In a `sandbox.revoke_requested` with `all`: the proxy's sandboxes it
    /// covers, sorted, as the server read them from the log under the
    /// account's lock (not signed by the account).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sandbox_ids: Vec<SandboxId>,
    /// Secret request involved (`secret_request.created`,
    /// `secret_request.decided`; ADR 0046).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_request_id: Option<SecretRequestId>,
    /// SHA-256 of the canonical proposal JSON of a secret request (32 bytes,
    /// spec §13.14): kept in the audit log while `proposal_blob` is discarded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proposal_digest: Option<Blob>,
}

impl AuditEvent {
    /// An event with only the mandatory fields.
    pub fn new(actor: ActorKind, action: &str) -> Self {
        Self {
            v: AUDIT_EVENT_VERSION,
            seq: 0,
            at: 0,
            actor,
            device_id: None,
            agent_id: None,
            action: action.to_owned(),
            vault_id: None,
            project_id: None,
            item_id: None,
            permission: None,
            outcome: None,
            reason: None,
            domain: None,
            method: None,
            path: None,
            attachments: Vec::new(),
            approval_id: None,
            task_id: None,
            lease_until: None,
            decided_at: None,
            until: None,
            alerts: Vec::new(),
            agent_proof: None,
            signed: None,
            task_request: None,
            account_signature: None,
            sandbox_id: None,
            sandbox_ids: Vec::new(),
            secret_request_id: None,
            proposal_digest: None,
        }
    }
}

/// A stored event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Position.
    pub seq: u64,
    /// The [`AuditEvent`] JSON bytes, as hashed.
    pub event: Blob,
    /// `hash_seq`.
    pub hash: Blob,
}

/// `GET /v1/audit?after=&limit=`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditPage {
    /// Events after `after`, in order.
    pub entries: Vec<AuditEntry>,
    /// Last position of the chain.
    pub head_seq: u64,
}

/// `GET /v1/audit` query.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditQuery {
    /// Return events with `seq > after`.
    #[serde(default)]
    pub after: u64,
    /// At most this many (default and maximum 1000).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

/// A chain head signed by a device of the person.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditHead {
    /// Position.
    pub seq: u64,
    /// `hash_seq`.
    pub hash: Blob,
    /// Account signature (spec §13.7).
    pub signature: Blob,
    /// Device that signed it.
    pub device_id: DeviceId,
    /// When (Unix ms).
    pub signed_at: i64,
}

/// `GET /v1/audit/heads`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditHeads {
    /// Newest first (at most 100).
    pub heads: Vec<AuditHead>,
}

/// `POST /v1/audit/heads`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignHead {
    /// Position.
    pub seq: u64,
    /// `hash_seq`.
    pub hash: Blob,
    /// Account signature.
    pub signature: Blob,
}

/// Actions a device of the person may log itself with
/// `POST /v1/audit/person` (ADR 0020 §10).
pub const PERSON_ACTIONS: &[&str] = &["passkey.used"];

/// `POST /v1/audit/person`: an event that happened only on a device of the
/// person (the server never sees it otherwise), such as signing in with a
/// passkey. The server checks the item, the task and the agent, adds the
/// vault, the project and the device, and appends it to the chain. It
/// carries no site: `passkey.used` names only the item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersonEvent {
    /// One of [`PERSON_ACTIONS`].
    pub action: String,
    /// The item used.
    pub item_id: ItemId,
    /// The agent that used it, inside `task_id` (ADR 0020 §9).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<AgentId>,
    /// The task that let the agent use it. With `agent_id`, or neither.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_id: Option<TaskId>,
}

// ------------------------------------------------ an agent's signed route --

/// How far an agent's signed time and the time its event is logged may be
/// apart (spec §13.3): the server's window for a signed request, and the
/// log verifier's for the event it backs.
pub const CLOCK_SKEW_MS: i64 = 5 * 60 * 1000;

/// The agent request behind an agent action: method and route (ADR 0030
/// §4.3). The log verifier (`klav-client`) checks every agent event with
/// it, and the server with the same code before it logs one, so it never
/// logs an agent's proof its own verifier refuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentRoute {
    /// `POST /v1/agent/access`.
    Access,
    /// `POST /v1/agent/items`.
    Create,
    /// `PUT /v1/agent/items/{item_id}`.
    Update,
    /// `POST /v1/agent/items/{item_id}/trash`.
    Trash,
    /// `POST /v1/agent/tasks`.
    TaskRequest,
    /// `POST /v1/agent/tasks/{task_id}/end`.
    TaskEnd,
    /// `POST /v1/agent/rotations` (ADR 0022 §5).
    RotateStart,
    /// `POST /v1/agent/rotations/{rotation_id}/confirm` or `/cancel`.
    RotateFinish,
    /// `POST /v1/agent/approvals`: a write asked about before its body is
    /// sent (ADR 0030 §3, residual risk 35).
    Ask,
    /// `POST /v1/agent/sandboxes`: the credential proxy started a sandbox
    /// (ADR 0036 §9).
    SandboxIssue,
    /// `POST /v1/agent/sandboxes/{sandbox_id}/claimed`.
    SandboxClaim,
    /// `POST /v1/agent/sandboxes/{sandbox_id}/revoked`.
    SandboxRevoke,
    /// `POST /v1/agent/sandboxes/epochs`: the proxy starts a new store
    /// (ADR 0036 E3.3, spec §13.12).
    SandboxStoreReset,
    /// `POST /v1/agent/secret-requests`: an agent asks the person to create or
    /// update a secret item (ADR 0046). The request body holds `proposal_blob`
    /// which is discarded after decision or expiry, so the audit event omits
    /// `agent_proof.body` and retains `proposal_digest` and `reason`.
    SecretRequestCreate,
}

impl AgentRoute {
    /// The route an agent's event must have been signed for: `None` for an
    /// action no agent signs (the person's, or the server's).
    pub fn of(e: &AuditEvent) -> Option<Self> {
        Some(match e.action.as_str() {
            "agent.access" => Self::Access,
            "agent.create" => Self::Create,
            "agent.update" => Self::Update,
            "agent.trash" => Self::Trash,
            "agent.ask" => Self::Ask,
            "task.requested" => Self::TaskRequest,
            "rotate.started" => Self::RotateStart,
            "sandbox.issued" => Self::SandboxIssue,
            "sandbox.claimed" => Self::SandboxClaim,
            "sandbox.revoked" => Self::SandboxRevoke,
            "sandbox.store_reset" => Self::SandboxStoreReset,
            "secret_request.created" => Self::SecretRequestCreate,
            "rotate.confirmed" | "rotate.cancelled" if e.actor == ActorKind::Agent => {
                Self::RotateFinish
            }
            "task.ended" if e.outcome.as_deref() == Some("agent") => Self::TaskEnd,
            _ => return None,
        })
    }

    /// Whether the event must keep the body (ADR 0030 §4.2). The server
    /// refuses larger bodies on these routes, so an honest event always
    /// has it; item writes carry the encrypted item and may not.
    pub fn needs_body(self) -> bool {
        matches!(
            self,
            Self::Access
                | Self::TaskRequest
                | Self::TaskEnd
                | Self::RotateStart
                | Self::RotateFinish
                | Self::Ask
                | Self::SandboxIssue
                | Self::SandboxClaim
                | Self::SandboxRevoke
                | Self::SandboxStoreReset
        )
    }

    /// A step of a sandbox's life, or a new store of its proxy.
    pub fn is_sandbox(self) -> bool {
        matches!(
            self,
            Self::SandboxIssue | Self::SandboxClaim | Self::SandboxRevoke | Self::SandboxStoreReset
        )
    }

    /// Whether `proof`'s method and route are this route's, with the
    /// event's item or task in it (ADR 0030 §4.3). The path is compared as
    /// signed: a query string or an escaped ID never matches.
    pub fn matches(self, e: &AuditEvent, proof: &AgentProof) -> bool {
        let path = proof.path.as_str();
        match self {
            Self::Access => proof.method == "POST" && path == "/v1/agent/access",
            Self::Create => proof.method == "POST" && path == "/v1/agent/items",
            Self::Update => {
                proof.method == "PUT"
                    && e.item_id.is_some()
                    && path_id::<ItemId>(path, "/v1/agent/items/", "") == e.item_id
            }
            Self::Trash => {
                proof.method == "POST"
                    && e.item_id.is_some()
                    && path_id::<ItemId>(path, "/v1/agent/items/", "/trash") == e.item_id
            }
            Self::TaskRequest => proof.method == "POST" && path == "/v1/agent/tasks",
            Self::Ask => proof.method == "POST" && path == "/v1/agent/approvals",
            Self::TaskEnd => {
                proof.method == "POST"
                    && e.task_id.is_some()
                    && path_id::<TaskId>(path, "/v1/agent/tasks/", "/end") == e.task_id
            }
            Self::RotateStart => proof.method == "POST" && path == "/v1/agent/rotations",
            Self::SandboxIssue => proof.method == "POST" && path == "/v1/agent/sandboxes",
            Self::SandboxClaim => {
                proof.method == "POST"
                    && path_id::<SandboxId>(path, "/v1/agent/sandboxes/", "/claimed").is_some()
            }
            Self::SandboxRevoke => {
                proof.method == "POST"
                    && path_id::<SandboxId>(path, "/v1/agent/sandboxes/", "/revoked").is_some()
            }
            Self::SandboxStoreReset => {
                proof.method == "POST" && path == crate::sandbox::PATH_STORE_RESET
            }
            Self::SecretRequestCreate => {
                proof.method == "POST" && path == "/v1/agent/secret-requests"
            }
            Self::RotateFinish => {
                let step = if e.action == "rotate.confirmed" {
                    "/confirm"
                } else {
                    "/cancel"
                };
                proof.method == "POST"
                    && path_id::<RotationId>(path, "/v1/agent/rotations/", step).is_some()
            }
        }
    }
}

/// `{prefix}{id}{suffix}` → the ID, only when the ID is the whole segment
/// between them.
pub fn path_id<T: std::str::FromStr>(path: &str, prefix: &str, suffix: &str) -> Option<T> {
    let id = path.strip_prefix(prefix)?.strip_suffix(suffix)?;
    if id.is_empty() || id.contains(['/', '?', '#']) {
        return None;
    }
    id.parse().ok()
}

/// Whether an agent's request signed at `timestamp` may back an event
/// logged at `at` (both Unix ms): at most [`CLOCK_SKEW_MS`] apart.
pub fn signed_near(timestamp: i64, at: i64) -> bool {
    !timestamp
        .checked_sub(at)
        .is_none_or(|d| d.abs() > CLOCK_SKEW_MS)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signed(action: &str, method: &str, path: &str) -> (AuditEvent, AgentProof) {
        let e = AuditEvent::new(ActorKind::Agent, action);
        let proof = AgentProof {
            method: method.into(),
            path: path.into(),
            timestamp: 0,
            nonce: Blob::new(vec![0; 16]),
            body_digest: Blob::new(vec![0; 32]),
            body: None,
            signature: Blob::new(vec![0; 64]),
        };
        (e, proof)
    }

    /// The ID in a route is one path segment: no `/`, `?` or `#` in it, and
    /// never empty, whatever the ID type would parse.
    #[test]
    fn path_id_takes_one_bare_segment() {
        let id = |path: &str| path_id::<String>(path, "/v1/agent/items/", "/trash");
        assert_eq!(id("/v1/agent/items/abc/trash"), Some("abc".into()));
        for path in [
            "/v1/agent/items//trash",
            "/v1/agent/items/a/b/trash",
            "/v1/agent/items/a?b/trash",
            "/v1/agent/items/a#b/trash",
            "/v1/agent/items/abc/trash?x=1",
            "/v1/agent/items/abc",
        ] {
            assert_eq!(id(path), None, "{path}");
        }
        let item = ItemId::generate();
        assert_eq!(
            path_id::<ItemId>(&format!("/v1/agent/items/{item}"), "/v1/agent/items/", ""),
            Some(item)
        );
        assert_eq!(
            path_id::<ItemId>(
                &format!("/v1/agent/items/{item}?x=1"),
                "/v1/agent/items/",
                ""
            ),
            None
        );
    }

    /// A route matches only as signed: a query string, even a bare `?`, or
    /// another method is not the action's route.
    #[test]
    fn a_route_never_ignores_a_query() {
        let (e, proof) = signed("agent.access", "POST", "/v1/agent/access");
        let route = AgentRoute::of(&e).unwrap();
        assert_eq!(route, AgentRoute::Access);
        assert!(route.matches(&e, &proof));
        for (method, path) in [
            ("POST", "/v1/agent/access?x=1"),
            ("POST", "/v1/agent/access?"),
            ("POST", "/v1/agent/access/"),
            ("PUT", "/v1/agent/access"),
        ] {
            let (_, proof) = signed("agent.access", method, path);
            assert!(!route.matches(&e, &proof), "{method} {path}");
        }
        let item = ItemId::generate();
        let (mut e, proof) = signed("agent.update", "PUT", &format!("/v1/agent/items/{item}"));
        e.item_id = Some(item);
        assert!(AgentRoute::Update.matches(&e, &proof));
        let (_, proof) = signed(
            "agent.update",
            "PUT",
            &format!("/v1/agent/items/{item}?x=1"),
        );
        assert!(!AgentRoute::Update.matches(&e, &proof));

        let (sr, sr_proof) = signed(
            "secret_request.created",
            "POST",
            "/v1/agent/secret-requests",
        );
        let sr_route = AgentRoute::of(&sr).unwrap();
        assert_eq!(sr_route, AgentRoute::SecretRequestCreate);
        assert!(!sr_route.needs_body());
        assert!(sr_route.matches(&sr, &sr_proof));
    }
}
