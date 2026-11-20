//! Task requests, agent side (ADR 0021 §1, §7): the runtime turns each
//! `ref` into IDs with its decrypted copy, sends the request signed like
//! any other, follows it with long-polls, and verifies the person's
//! decision against the pinned account identity (TOFU, ADR 0014 §1.4)
//! before reporting it.

use std::time::{Duration, Instant};

use klav_client::{ClientError, ClientResult};
use klav_core::crypto::agent::{self as agent_crypto, TaskDecisionToSign};
use klav_core::crypto::identity::PublicIdentity;
use klav_core::crypto::sign::{SIGNATURE_LEN, Signature};
use klav_core::ids::{AgentId, TaskId};
use klav_core::policy::Permission;
use klav_core::task::{
    TASK_FORMAT_VERSION, TaskAccessRequest, TaskDecision, TaskRequest, TaskSpec,
};
use klav_proto::task::{
    AgentEndTask, MAX_TASK_WAIT_SECS, PendingTask, TaskEndedBy, TaskInfo, TaskList, TaskStatus,
};
use reqwest::Method;
use serde::{Deserialize, Serialize};

use crate::agent::Agent;
use crate::session::Session;

/// One approved access, as the agent reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskAccessView {
    /// `klav://vault/project/item` (by name), or the item ID if this
    /// runtime cannot see it.
    #[serde(rename = "ref")]
    pub reference: String,
    /// Approved permissions.
    pub permissions: Vec<Permission>,
    /// Approved hosts (empty: any, for items without a site).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub domains: Vec<String>,
    /// The permissions Klav added (not asked for).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub added_by_klav: Vec<Permission>,
}

/// What the agent asked for and did not get.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskRemovedView {
    /// The item.
    #[serde(rename = "ref")]
    pub reference: String,
    /// The permissions left out.
    pub permissions: Vec<Permission>,
}

/// A task as the agent reports it (`klav agent task show`, MCP `get_task`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskView {
    /// ID.
    pub task_id: TaskId,
    /// State.
    pub status: TaskStatus,
    /// The title the agent gave, or the person's for an offered task.
    pub task: String,
    /// Offered by the person, without a request from this agent (ADR 0022
    /// §6): [`Self::task`] and [`Self::reason`] are theirs.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub offered: bool,
    /// Why, in the person's words; only for an offered task (the agent
    /// knows its own reason).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Until when the person can decide (pending), or when the task ends
    /// (approved) (Unix ms).
    pub expires_at: i64,
    /// Revision of the decision in force.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub revision: u64,
    /// Who ended it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ended_by: Option<TaskEndedBy>,
    /// What the person approved (verified signature).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub access: Vec<TaskAccessView>,
    /// What the agent asked for and the person left out.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub removed: Vec<TaskRemovedView>,
}

fn is_zero(n: &u64) -> bool {
    *n == 0
}

impl Agent {
    /// The state of one of this agent's tasks, waiting up to `wait` (at most
    /// [`MAX_TASK_WAIT_SECS`]) while it is pending.
    pub async fn task(&self, id: TaskId, wait: Duration) -> ClientResult<TaskInfo> {
        let secs = wait.as_secs().min(MAX_TASK_WAIT_SECS);
        let path = if secs == 0 {
            format!("/v1/agent/tasks/{id}")
        } else {
            format!("/v1/agent/tasks/{id}?wait={secs}")
        };
        let info: TaskInfo = self.call::<(), _>(Method::GET, &path, None).await?;
        if info.id != id || info.agent_id != self.id() {
            return Err(ClientError::Security(
                "the server answered for another task or agent".into(),
            ));
        }
        Ok(info)
    }

    /// Waits until the person decides on task `id`, it expires, or
    /// `timeout` passes, with long-polls. Returns the last state.
    pub async fn wait_task(&self, id: TaskId, timeout: Duration) -> ClientResult<TaskInfo> {
        let deadline = Instant::now() + timeout;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            let asked = Instant::now();
            let info = self.task(id, left).await?;
            if info.status != TaskStatus::Pending || left.as_secs() == 0 {
                return Ok(info);
            }
            // A server without long-polls answers at once.
            let pause = Duration::from_secs(1).saturating_sub(asked.elapsed());
            tokio::time::sleep(pause.min(left)).await;
        }
    }

    /// This agent's recent tasks, newest first.
    pub async fn tasks(&self) -> ClientResult<Vec<TaskInfo>> {
        let list: TaskList = self
            .call::<(), _>(Method::GET, "/v1/agent/tasks", None)
            .await?;
        if list.tasks.iter().any(|t| t.agent_id != self.id()) {
            return Err(ClientError::Security(
                "the server listed another agent's task".into(),
            ));
        }
        Ok(list.tasks)
    }

    /// Ends a pending or running task of this agent (`end_task`).
    pub async fn end_task(&self, id: TaskId, reason: &str) -> ClientResult<TaskInfo> {
        if reason.trim().is_empty() {
            return Err(ClientError::Invalid("a reason is mandatory".into()));
        }
        self.call(
            Method::POST,
            &format!("/v1/agent/tasks/{id}/end"),
            Some(&AgentEndTask {
                reason: reason.to_owned(),
            }),
        )
        .await
    }

    /// Parses the request of `info` and, once decided, verifies the
    /// account's signature on the decision in force. A first decision is
    /// also checked against the request (only what was asked, or `totp`
    /// and `passkey` added by Klav; no longer than asked).
    ///
    /// A task the person offered (ADR 0022 §6) has an empty request: its
    /// signed decision carries the person's title and reason, and the
    /// request returned is the one it stands for, with no accesses.
    pub fn verify_task(
        &self,
        info: &TaskInfo,
    ) -> ClientResult<(TaskRequest, Option<TaskDecision>)> {
        verify_task_info(&self.account_identity()?, self.id(), info)
    }
}

/// Parses the request of `info` and, once decided, verifies the
/// account's signature on the decision in force. A first decision is
/// also checked against the request (only what was asked, or `totp`
/// and `passkey` added by Klav; no longer than asked).
///
/// A task the person offered (ADR 0022 §6) has an empty request: its
/// signed decision carries the person's title and reason, and the
/// request returned is the one it stands for, with no accesses.
/// [`Agent::verify_task`] for `agent`, against the pinned `account`
/// identity.
pub(crate) fn verify_task_info(
    account: &PublicIdentity,
    agent: AgentId,
    info: &TaskInfo,
) -> ClientResult<(TaskRequest, Option<TaskDecision>)> {
    let offered = info.request.as_bytes().is_empty();
    let request: Option<TaskRequest> = if offered {
        None
    } else {
        Some(
            serde_json::from_slice(info.request.as_bytes())
                .map_err(|e| ClientError::Corrupt(format!("task {}: request: {e}", info.id)))?,
        )
    };
    let (Some(bytes), Some(sig), Some(decided_at)) =
        (&info.decision, &info.signature, info.decided_at)
    else {
        if matches!(info.status, TaskStatus::Approved | TaskStatus::Denied) {
            return Err(ClientError::Security(format!(
                "task {} is {} without a signed decision",
                info.id,
                info.status.as_str()
            )));
        }
        return request.map(|r| (r, None)).ok_or_else(|| {
            ClientError::Security(format!(
                "task {} has no request and no signed decision",
                info.id
            ))
        });
    };
    let decision: TaskDecision = serde_json::from_slice(bytes.as_bytes())
        .map_err(|e| ClientError::Corrupt(format!("task {}: decision: {e}", info.id)))?;
    let approve = !decision.access.is_empty();
    let signature: [u8; SIGNATURE_LEN] = sig
        .as_bytes()
        .try_into()
        .map_err(|_| ClientError::Security("task signature has a wrong length".into()))?;
    let decided_at_ms = u64::try_from(decided_at).unwrap_or(0);
    agent_crypto::verify_task_decision(
        account,
        &TaskDecisionToSign {
            task: info.id,
            agent,
            request: info.request.as_bytes(),
            decision: bytes.as_bytes(),
            approve,
            decided_at_ms,
        },
        &Signature::from_bytes(signature),
    )
    .map_err(|_| {
        ClientError::Security(format!(
            "the decision of task {} is not signed by the account",
            info.id
        ))
    })?;
    let first_ok = |request: Option<&TaskRequest>| match request {
        Some(r) => decision.check_first(r, decided_at_ms).is_ok(),
        None => decision.check_offered(decided_at_ms).is_ok(),
    };
    let consistent = decision.task_id == info.id
        && decision.agent_id == agent
        && decision.revision == info.revision
        && decision.validate(approve).is_ok()
        && (approve == (info.status != TaskStatus::Denied))
        && (!offered || (approve && decision.offer.is_some()))
        && (!approve
            || (info.expires_at == i64::try_from(decision.expires_at_ms).ok()
                && (decision.revision > 1 || first_ok(request.as_ref()))));
    let request = match request {
        Some(r) => Some(r),
        None => decision.offered_request(decided_at_ms),
    };
    match request {
        Some(request) if consistent => Ok((request, Some(decision))),
        _ => Err(ClientError::Security(format!(
            "the decision of task {} does not match the task",
            info.id
        ))),
    }
}

/// A running task this runtime verified (signature, task, agent, expiry).
#[derive(Debug, Clone)]
pub(crate) struct LiveTask {
    pub(crate) id: TaskId,
    pub(crate) expires_at: i64,
    pub(crate) decision: TaskDecision,
}

impl Session {
    /// Reloads this agent's running tasks. A task whose decision does not
    /// verify is left out: it never covers anything here.
    pub(crate) async fn load_tasks(&mut self) -> ClientResult<()> {
        let now = crate::agent::now_ms();
        let mut live = Vec::new();
        for info in self.agent.tasks().await? {
            let Some(expires_at) = info.expires_at.filter(|e| *e > now) else {
                continue;
            };
            if info.status != TaskStatus::Approved {
                continue;
            }
            if let Ok((_, Some(decision))) = self.agent.verify_task(&info) {
                live.push(LiveTask {
                    id: info.id,
                    expires_at,
                    decision,
                });
            }
        }
        self.tasks = live;
        Ok(())
    }

    /// Names task `id` for the next action (`task_id`): only that task
    /// counts for it, here and on the server. Fails if it is not running.
    pub fn use_task(&mut self, id: TaskId) -> ClientResult<()> {
        if !self.tasks.iter().any(|t| t.id == id) {
            return Err(ClientError::Invalid(format!(
                "task {id} is not running (ended, expired, denied or not approved yet): check it with get_task"
            )));
        }
        self.task = Some(id);
        Ok(())
    }

    /// Forgets the named task (after the action).
    pub fn release_task(&mut self) -> Option<TaskId> {
        self.task.take()
    }

    /// The task a request for `permission` on `item` carries (ADR 0021
    /// §5.5): the one the caller named, else the only running task that
    /// covers the action. Several or none: no task, the normal path.
    pub fn task_for(
        &self,
        item: klav_core::ids::ItemId,
        permission: Permission,
        domain: Option<&str>,
    ) -> Option<TaskId> {
        if self.task.is_some() {
            return self.task;
        }
        let entry = self.items.get(&item)?;
        let now = crate::agent::now_ms();
        let covering: Vec<TaskId> = self
            .tasks
            .iter()
            .filter(|t| {
                t.expires_at > now
                    && t.decision
                        .covers(entry.vault, entry.project, item, permission, domain)
            })
            .map(|t| t.id)
            .collect();
        match covering.as_slice() {
            [one] => Some(*one),
            _ => None,
        }
    }

    /// Turns the refs of `spec` into IDs (ADR 0021 §1) with this runtime's
    /// decrypted copy. `scope` is `klav.toml`'s project, for short refs.
    pub fn task_request(
        &self,
        spec: &TaskSpec,
        scope: Option<(&str, &str)>,
    ) -> ClientResult<TaskRequest> {
        let duration_secs = spec
            .validate()
            .map_err(|e| ClientError::Invalid(e.to_string()))?;
        crate::text::check_declared("task", &spec.task)?;
        crate::text::check_declared("reason", &spec.reason)?;
        let mut access = Vec::with_capacity(spec.access.len());
        for asked in &spec.access {
            let (item, field) = self.locate(&asked.reference, scope)?;
            if field.is_some() {
                return Err(ClientError::Invalid(format!(
                    "{}: a task asks for items, not fields",
                    asked.reference
                )));
            }
            let entry = self
                .items
                .get(&item)
                .ok_or_else(|| ClientError::NotFound(asked.reference.clone()))?;
            access.push(TaskAccessRequest {
                vault_id: entry.vault,
                project_id: entry.project,
                item_id: item,
                permissions: asked.permissions.clone(),
                domain: asked.domain.clone(),
            });
        }
        let request = TaskRequest {
            v: TASK_FORMAT_VERSION,
            task: spec.task.clone(),
            reason: spec.reason.clone(),
            duration_secs,
            access,
        };
        request
            .validate()
            .map_err(|e| ClientError::Invalid(e.to_string()))?;
        Ok(request)
    }

    /// Sends a task request (`POST /v1/agent/tasks`). The person decides on
    /// it; follow it with [`Agent::wait_task`].
    pub async fn submit_task(&self, request: &TaskRequest) -> ClientResult<PendingTask> {
        self.agent
            .call(Method::POST, "/v1/agent/tasks", Some(request))
            .await
    }

    /// Asks for a task and waits up to `wait` for the person (ADR 0021
    /// §7): the task as it stands then (still pending if nobody decided).
    pub async fn request_task(
        &self,
        spec: &TaskSpec,
        scope: Option<(&str, &str)>,
        wait: Duration,
    ) -> ClientResult<TaskView> {
        let request = self.task_request(spec, scope)?;
        let pending = self.submit_task(&request).await?;
        let info = if wait.is_zero() {
            self.agent
                .task(pending.pending_task_id, Duration::ZERO)
                .await?
        } else {
            self.agent.wait_task(pending.pending_task_id, wait).await?
        };
        self.task_view(&info)
    }

    fn reference_of(&self, item: klav_core::ids::ItemId) -> String {
        self.items
            .get(&item)
            .map_or_else(|| item.to_string(), |e| self.info(item, e).reference)
    }

    /// The task as the agent reports it, with the decision verified.
    pub fn task_view(&self, info: &TaskInfo) -> ClientResult<TaskView> {
        let (request, decision) = self.agent.verify_task(info)?;
        let expires_at = match info.status {
            TaskStatus::Pending => info.decide_by,
            _ => info.expires_at.unwrap_or(info.decide_by),
        };
        let (access, removed) = match &decision {
            Some(d) if !d.access.is_empty() => (
                d.access
                    .iter()
                    .map(|a| TaskAccessView {
                        reference: self.reference_of(a.item_id),
                        permissions: a.permissions.clone(),
                        domains: a.domains.clone(),
                        added_by_klav: a.added_by_klav.clone(),
                    })
                    .collect(),
                d.removed_from(&request)
                    .into_iter()
                    .map(|r| TaskRemovedView {
                        reference: self.reference_of(r.item_id),
                        permissions: r.permissions,
                    })
                    .collect(),
            ),
            _ => (Vec::new(), Vec::new()),
        };
        let offered = info.request.as_bytes().is_empty();
        Ok(TaskView {
            task_id: info.id,
            status: info.status,
            task: request.task,
            offered,
            reason: offered.then_some(request.reason),
            expires_at,
            revision: info.revision,
            ended_by: info.ended_by,
            access,
            removed,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_crypto::sign_task_decision as agent_sign;
    use klav_core::crypto::identity::IdentityKeyPair;
    use klav_core::ids::{ItemId, ProjectId, VaultId};
    use klav_core::task::{TASK_FORMAT_VERSION as V, TaskAccessDecision, TaskOffer};
    use klav_proto::Blob;

    const NOW: i64 = 1_800_000_000_000;

    fn offered(agent: AgentId) -> TaskDecision {
        TaskDecision {
            v: V,
            task_id: TaskId::generate(),
            agent_id: agent,
            revision: 1,
            expires_at_ms: u64::try_from(NOW + 3_600_000).unwrap(),
            access: vec![TaskAccessDecision {
                vault_id: VaultId::generate(),
                project_id: ProjectId::generate(),
                item_id: ItemId::generate(),
                permissions: vec![Permission::Rotate],
                domains: vec!["bank.example".into()],
                added_by_klav: Vec::new(),
            }],
            offer: Some(TaskOffer {
                task: "Fix my reused passwords".into(),
                reason: "One password per site".into(),
            }),
        }
    }

    /// `decision`, signed by `account` over `request`, as the server
    /// returns it.
    fn info(account: &IdentityKeyPair, decision: &TaskDecision, request: &[u8]) -> TaskInfo {
        let bytes = serde_json::to_vec(decision).unwrap();
        let signature = agent_sign(
            account,
            &TaskDecisionToSign {
                task: decision.task_id,
                agent: decision.agent_id,
                request,
                decision: &bytes,
                approve: true,
                decided_at_ms: u64::try_from(NOW).unwrap(),
            },
        );
        TaskInfo {
            id: decision.task_id,
            agent_id: decision.agent_id,
            agent_name: "bot".into(),
            status: TaskStatus::Approved,
            request: Blob::new(request.to_vec()),
            created_at: NOW,
            decide_by: NOW,
            decided_at: Some(NOW),
            decision: Some(Blob::new(bytes)),
            signature: Some(Blob::new(signature.to_bytes().to_vec())),
            revision: decision.revision,
            expires_at: Some(i64::try_from(decision.expires_at_ms).unwrap()),
            ended_at: None,
            ended_by: None,
        }
    }

    #[test]
    fn the_agent_verifies_an_offered_task() {
        let account = IdentityKeyPair::generate();
        let agent = AgentId::generate();
        let decision = offered(agent);
        let (request, verified) =
            verify_task_info(account.public(), agent, &info(&account, &decision, &[])).unwrap();
        assert_eq!(verified, Some(decision.clone()));
        assert_eq!(request.task, "Fix my reused passwords");
        assert_eq!(request.reason, "One password per site");

        // Not for another agent, not without an offer, not signed by
        // another account.
        assert!(
            verify_task_info(
                account.public(),
                AgentId::generate(),
                &info(&account, &decision, &[])
            )
            .is_err()
        );
        let mut bare = decision.clone();
        bare.offer = None;
        assert!(verify_task_info(account.public(), agent, &info(&account, &bare, &[])).is_err());
        let other = IdentityKeyPair::generate();
        assert!(verify_task_info(account.public(), agent, &info(&other, &decision, &[])).is_err());
        // An empty request still pending is nothing the server can show.
        let mut pending = info(&account, &decision, &[]);
        pending.status = TaskStatus::Pending;
        pending.decision = None;
        pending.signature = None;
        assert!(verify_task_info(account.public(), agent, &pending).is_err());
    }
}
