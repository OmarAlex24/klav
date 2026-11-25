//! What an approved agent can do (design §5.2–§5.3, ADR 0014 §4–§5): list
//! the items of its granted projects, use one (details come only through
//! `access`), create, update and trash items, and follow its approvals.
//!
//! Every action is checked here against the signed grant, in addition to
//! the agent's own runtime: the agent can only decrypt what was shared with
//! it, and the server only hands out what the policy allows. The server
//! cannot read tags or URLs, so it evaluates the policy with the tags and
//! domain the agent claims (ADR 0014 §4).

use std::collections::HashMap;
use std::time::Duration;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use klav_core::ids::{AgentId, ApprovalId, AttachmentId, ItemId, ProjectId, TaskId, VaultId};
use klav_core::policy::{self, Effect, Permission, Policy, Target};
use klav_proto::Blob;
use klav_proto::agent::{
    AccessGranted, AccessRequest, AgentAsk, AgentAsked, AgentAttachment, AgentCreateItem,
    AgentItems, AgentProjectItems, AgentTrashItem, AgentTrashed, AgentUpdateItem, AgentWritten,
    ApprovalCaller, ApprovalInfo, ApprovalRequest, ApprovalStatus, Claims, GrantPayload,
    LocalClient, MAX_AGENT_ATTACHMENTS_BYTES, MAX_APPROVAL_WAIT_SECS, MAX_REASON, PasskeyAccess,
    PendingApproval, PersonVersion, ProxyProfile,
};
use klav_proto::audit::{ActorKind, AuditEvent};
use klav_proto::task::TaskStatus;
use serde::Deserialize;
use sqlx::Row;
use tokio::sync::broadcast;

use crate::agentauth::AgentAuth;
use crate::audit;
use crate::db::now_ms;
use crate::error::{ApiError, ApiResult};
use crate::push::PushKind;
use crate::routes::approvals::{approval_from_row, effective_approval_status};
use crate::routes::attachments::{ATTACHMENT_COLUMNS, attachment_from_row};
use crate::routes::items::{
    ITEM_COLUMNS, Writer, insert_item, item_from_row, move_to_trash, write_version,
};
use crate::routes::tasks::{covering_task, lock_agent};
use crate::state::AppState;
use crate::vaultdb::{path_id, to_i64, to_u64};

/// How long a person has to answer an approval request.
pub(crate) const APPROVAL_TTL_MS: i64 = 10 * 60 * 1000;
/// Pending approval requests per agent.
const MAX_PENDING_APPROVALS: i64 = 10;
/// How long after the decision an approve-once approval can be spent
/// (ADR 0015 §2).
pub(crate) const ONCE_WINDOW_MS: i64 = 10 * 60 * 1000;
/// How often a long-poll on an approval re-reads the database (decisions
/// made on another server instance, revocations, new grants).
const WAIT_RECHECK: std::time::Duration = std::time::Duration::from_secs(2);

pub(super) fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/agent/items", get(list_items).post(create_item))
        .route("/v1/agent/items/{item_id}", put(update_item))
        .route("/v1/agent/items/{item_id}/trash", post(trash_item))
        .route("/v1/agent/access", post(access))
        .route("/v1/agent/approvals", post(ask_first))
        .route("/v1/agent/approvals/{approval_id}", get(approval_status))
}

/// The agent's current grant, as signed.
pub(crate) struct Grant {
    pub(crate) version: u64,
    pub(crate) policy: Policy,
    /// Granted projects and their vaults.
    pub(crate) projects: HashMap<ProjectId, VaultId>,
    /// Items granted one by one (ADR 0036 §2), with the vault and project
    /// they were in when the grant was signed. Only `proxy` reaches them.
    pub(crate) items: HashMap<ItemId, (VaultId, ProjectId)>,
    /// The credential proxy's profiles (ADR 0036 §2), MCP ones included.
    pub(crate) profiles: Vec<ProxyProfile>,
    /// The credential proxy's local clients (ADR 0049 §3.2).
    pub(crate) local_clients: Vec<LocalClient>,
}

impl Grant {
    /// Whether the grant covers `action` where it is: a `proxy` action only
    /// through an item granted one by one, still in the vault and project
    /// the grant names; any other only through a granted project.
    fn covers(&self, action: &Action<'_>) -> bool {
        if action.permission == Permission::Proxy {
            action.item.and_then(|item| self.items.get(&item))
                == Some(&(action.vault, action.project))
        } else {
            self.projects.get(&action.project) == Some(&action.vault)
        }
    }
}

pub(crate) async fn load_grant(state: &AppState, auth: &AgentAuth) -> ApiResult<Grant> {
    grant_of(state, auth.agent_id).await
}

/// The current grant of `agent`, as signed (`Forbidden` if it has none).
pub(crate) async fn grant_of(state: &AppState, agent: AgentId) -> ApiResult<Grant> {
    let payload: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT grant_payload FROM agents WHERE id = $1")
            .bind(agent.to_string())
            .fetch_one(&state.db().pool)
            .await?;
    let payload = payload.ok_or(ApiError::Forbidden)?;
    let payload: GrantPayload = serde_json::from_slice(&payload)
        .map_err(|_| ApiError::Internal("corrupt grant payload".into()))?;
    Ok(Grant {
        version: payload.version,
        policy: payload.policy,
        projects: payload
            .projects
            .iter()
            .map(|p| (p.project_id, p.vault_id))
            .collect(),
        items: payload
            .items
            .iter()
            .map(|i| (i.item_id, (i.vault_id, i.project_id)))
            .collect(),
        profiles: payload.profiles,
        local_clients: payload.local_clients,
    })
}

impl Grant {
    /// Whether the proxy's grant lets local client `name` use the MCP
    /// profile of `item` (ADR 0049 §3.2): what the server checks
    /// `AccessRequest::local_client` against.
    fn local_client_may_use(&self, name: &str, item: ItemId) -> bool {
        self.profiles
            .iter()
            .filter(|p| p.item_id == item && p.mcp.is_some())
            .any(|p| {
                self.local_clients
                    .iter()
                    .any(|c| c.name == name && c.profiles.contains(&p.name))
            })
    }
}

/// `reason` is mandatory for agents: non-empty, at most [`MAX_REASON`]
/// characters, and none of the characters that change how a text looks
/// (control, format/bidi, line and paragraph separators:
/// [`klav_core::text::is_hidden`]). The person reads it before deciding.
pub(crate) fn check_reason(reason: &str) -> ApiResult<String> {
    let reason = reason.trim();
    if reason.is_empty() {
        return Err(ApiError::bad_request(
            "reason is mandatory: say why the agent needs this",
        ));
    }
    if reason.chars().count() > MAX_REASON || reason.chars().any(klav_core::text::is_hidden) {
        return Err(ApiError::bad_request(
            "reason must have at most 500 characters and no control, format (bidi, zero-width) or separator characters",
        ));
    }
    Ok(reason.to_owned())
}

/// Tags an agent may claim for one action.
pub(crate) const MAX_CLAIMED_TAGS: usize = 64;
/// Longest claimed tag, in characters.
pub(crate) const MAX_CLAIMED_TAG: usize = 128;

/// `method` and `path` only for `proxy`, which needs both and a domain
/// (ADR 0036 §2): `400` otherwise. Part of [`check_claims`]; two routes
/// run this part first, before they look at the domain: a rotation's
/// start, which normalizes it and runs the rest after, and `passkey`,
/// which refuses one not in normal form.
pub(crate) fn check_http_claims(permission: Permission, claims: &Claims) -> ApiResult<()> {
    let http = claims.method.is_some() || claims.path.is_some();
    if permission == Permission::Proxy {
        if claims.domain.is_none() || claims.method.is_none() || claims.path.is_none() {
            return Err(ApiError::bad_request(
                "proxy needs claims.domain, claims.method and claims.path: the request the proxy builds",
            ));
        }
    } else if http {
        return Err(ApiError::bad_request(
            "claims.method and claims.path are only for proxy",
        ));
    }
    Ok(())
}

/// What an agent claims about an item (ADR 0014 §4) goes into the policy
/// evaluation, the approval the person signs and the audit log, so it is
/// bounded and plain:
///
/// * `domain` must be a host name already in the form the policy matches
///   ([`klav_core::policy::normalize_host`]: lowercase, no trailing dot).
///   Rewriting it would make the approval differ from what the runtime
///   asked for; accepting `BANK.COM.` would let it slip past a rule for
///   `bank.com`.
/// * at most [`MAX_CLAIMED_TAGS`] tags of at most [`MAX_CLAIMED_TAG`]
///   characters, non-empty and without hidden characters.
/// * `method` and `path` only for `proxy` (ADR 0036 §2), which needs both
///   and a domain: on any other action they are refused (`400`) before
///   anything is evaluated, stored or logged. An older `klav log verify`
///   or approvals list cannot read them, and they would have no meaning
///   there.
/// * `path` is canonical ([`policy::is_canonical_path`]) and has no `"`.
///   The approval's [`target_key`] is JSON, where each `"` takes two
///   bytes, and Postgres refuses an index entry over 2704 bytes: a long
///   path full of `"` would overflow `approvals_pending_target` and
///   `approvals_agent_target` and answer `500`. The longest canonical path
///   without one fits. Only this route refuses it: `PathPrefix` and every
///   signed format still accept `"`, so nothing already signed changes.
pub(crate) fn check_claims(permission: Permission, claims: &Claims) -> ApiResult<()> {
    check_http_claims(permission, claims)?;
    check_mcp_claims(permission, claims, None, None)?;
    if let Some(domain) = &claims.domain
        && klav_core::policy::normalize_host(domain).as_deref() != Some(domain.as_str())
    {
        return Err(ApiError::bad_request(
            "claims.domain must be a host name in lowercase, without scheme, port or trailing dot",
        ));
    }
    if let Some(method) = &claims.method
        && !policy::is_http_method(method)
    {
        return Err(ApiError::bad_request(
            "claims.method must be an HTTP method in upper case (GET, POST…)",
        ));
    }
    if let Some(path) = &claims.path
        && !policy::is_canonical_path(path)
    {
        return Err(ApiError::bad_request(
            "claims.path must be a canonical path: it starts with /, visible ASCII written as itself, only %20, %3F and %23 escaped (upper-case hex), no ;, \\, query, fragment, empty, . or .. segments",
        ));
    }
    if claims
        .path
        .as_deref()
        .is_some_and(|path| path.contains('"'))
    {
        return Err(ApiError::bad_request(
            "claims.path must not contain `\"`: Klav does not accept it in a proxied path",
        ));
    }
    if claims.tags.len() > MAX_CLAIMED_TAGS {
        return Err(ApiError::bad_request(format!(
            "claims.tags: at most {MAX_CLAIMED_TAGS} tags"
        )));
    }
    for tag in &claims.tags {
        if tag.trim().is_empty()
            || tag.chars().count() > MAX_CLAIMED_TAG
            || tag.chars().any(klav_core::text::is_hidden)
        {
            return Err(ApiError::bad_request(format!(
                "claims.tags: each tag non-empty, at most {MAX_CLAIMED_TAG} characters and without control, format or separator characters"
            )));
        }
    }
    Ok(())
}

/// Whether a request carries anything of the MCP gateway (ADR 0049 §9):
/// the two tool claims or a local client.
pub(crate) fn uses_mcp_gateway(claims: &Claims, local_client: Option<&str>) -> bool {
    claims.mcp_tool.is_some() || claims.mcp_args.is_some() || local_client.is_some()
}

/// The MCP gateway's fields (ADR 0049 §5.4, T260) are refused (`400`)
/// before anything is evaluated, stored or logged, unless:
///
/// * they come with `proxy` only, and `mcp_tool` and `mcp_args` together;
/// * `mcp_tool` is in the tool grammar ([`policy::tool_name_ok`]) and
///   `local_client` in the client grammar ([`policy::local_client_name_ok`]),
///   so no approval card or audit line ever holds anything else;
/// * `mcp_args` is the text form of a 32-byte digest, with one spelling;
/// * the path is at most [`klav_proto::agent::MAX_MCP_ENDPOINT`] bytes (an
///   MCP endpoint), which keeps the approval's keys within the index;
/// * a call is for a sandbox or a local client, never both.
///
/// The account's switch is checked before this, by the route.
pub(crate) fn check_mcp_claims(
    permission: Permission,
    claims: &Claims,
    local_client: Option<&str>,
    sandbox: Option<klav_core::ids::SandboxId>,
) -> ApiResult<()> {
    if !uses_mcp_gateway(claims, local_client) {
        return Ok(());
    }
    if permission != Permission::Proxy {
        return Err(ApiError::bad_request(
            "claims.mcp_tool, claims.mcp_args and local_client are only for proxy",
        ));
    }
    if claims.mcp_tool.is_some() != claims.mcp_args.is_some() {
        return Err(ApiError::bad_request(
            "claims.mcp_tool and claims.mcp_args go together",
        ));
    }
    if claims
        .mcp_tool
        .as_deref()
        .is_some_and(|tool| !policy::tool_name_ok(tool))
    {
        return Err(ApiError::bad_request(
            "claims.mcp_tool must be 1–128 of A-Z, a-z, 0-9, _, - and .",
        ));
    }
    if claims
        .mcp_args
        .as_deref()
        .is_some_and(|args| !klav_core::crypto::mcp::digest_text_ok(args))
    {
        return Err(ApiError::bad_request(
            "claims.mcp_args must be a 32-byte digest in base64url without padding",
        ));
    }
    if local_client.is_some_and(|name| !policy::local_client_name_ok(name)) {
        return Err(ApiError::bad_request(
            "local_client must be 1–32 of a-z, 0-9 and -",
        ));
    }
    if local_client.is_some() && sandbox.is_some() {
        return Err(ApiError::bad_request(
            "a proxied call is for a sandbox or a local client, not both",
        ));
    }
    if claims
        .path
        .as_deref()
        .is_some_and(|path| path.len() > klav_proto::agent::MAX_MCP_ENDPOINT)
    {
        return Err(ApiError::bad_request(
            "an MCP call's path is its profile's endpoint: at most 64 bytes",
        ));
    }
    Ok(())
}

fn now_secs(now_ms: i64) -> u64 {
    u64::try_from(now_ms / 1000).unwrap_or(0)
}

/// An action to check.
pub(crate) struct Action<'a> {
    pub(crate) permission: Permission,
    pub(crate) vault: VaultId,
    pub(crate) project: ProjectId,
    pub(crate) item: Option<ItemId>,
    pub(crate) claims: &'a Claims,
    pub(crate) reason: &'a str,
    /// Attachments the action delivers if allowed (logged with it).
    pub(crate) attachments: &'a [AttachmentId],
    /// The sandbox a proxied call is for (ADR 0036 E3.3), if any.
    pub(crate) sandbox: Option<klav_core::ids::SandboxId>,
    /// The local client a proxied call is for (ADR 0049 §3.2), if any,
    /// already checked against the proxy's grant.
    pub(crate) local_client: Option<&'a str>,
}

/// Outcome of [`gate`].
pub(crate) enum Gate {
    /// Go ahead, with the approval or the task that let it through (if any).
    Allow {
        approval: Option<ApprovalId>,
        task: Option<TaskId>,
    },
    /// The person must decide first.
    Pending(PendingApproval),
}

impl Gate {
    fn pending_response(p: PendingApproval) -> Response {
        (StatusCode::ACCEPTED, Json(p)).into_response()
    }
}

fn policy_request(action: &Action<'_>, now: i64) -> policy::Request {
    policy::Request {
        permission: action.permission,
        // Grants name vaults and projects by ID only: names are not needed.
        vault: Target {
            id: action.vault,
            name: String::new(),
        },
        project: Target {
            id: action.project,
            name: String::new(),
        },
        tags: action.claims.tags.clone(),
        domain: action.claims.domain.clone(),
        item: action.item,
        method: action.claims.method.clone(),
        path: action.claims.path.clone(),
        mcp_tool: action.claims.mcp_tool.clone(),
        now: now_secs(now),
    }
}

/// What an approval is for (ADR 0015 §1): grant version, permission,
/// vault, project, item and claimed domain, and for `proxy` also the method
/// and path (ADR 0036 §9: an approval for `DELETE /a` is not one for
/// `DELETE /b`). The one function every lookup, insert and `approval_id`
/// check goes through. JSON keeps it unambiguous (the domain is text the
/// agent chose). Keys without a method or path are what they always were.
/// A proxied call for a sandbox also names the sandbox, so one sandbox's
/// approval, pending or given, never serves another sandbox or the proxy's
/// own machine; keys without a sandbox are what they always were.
pub(crate) fn target_key(grant_version: u64, action: &Action<'_>) -> String {
    let mut key = serde_json::json!([
        grant_version,
        permission_name(action.permission),
        action.vault.to_string(),
        action.project.to_string(),
        action.item.map(|i| i.to_string()).unwrap_or_default(),
        action
            .claims
            .domain
            .as_deref()
            .map(str::to_ascii_lowercase)
            .unwrap_or_default(),
    ]);
    if (action.claims.method.is_some() || action.claims.path.is_some())
        && let Some(parts) = key.as_array_mut()
    {
        parts.push(action.claims.method.clone().unwrap_or_default().into());
        parts.push(action.claims.path.clone().unwrap_or_default().into());
    }
    if let Some(sandbox) = action.sandbox
        && let Some(parts) = key.as_array_mut()
    {
        parts.push(sandbox.to_string().into());
    }
    if let Some(mcp) = mcp_key_part(action, true)
        && let Some(parts) = key.as_array_mut()
    {
        parts.push(mcp);
    }
    key.to_string()
}

/// The MCP gateway's part of an approval's keys (ADR 0049 §5.4), after
/// method, path and sandbox: one nested array with fixed slots, `["mcp",
/// tool, args, local client]` (`""` for an absent one), so it never reads
/// as a sandbox or another position. `None` for a request without the
/// gateway's fields, whose keys stay what they always were. Without
/// `with_args`, the lease key's part: the same tool with any arguments.
fn mcp_key_part(action: &Action<'_>, with_args: bool) -> Option<serde_json::Value> {
    if !uses_mcp_gateway(action.claims, action.local_client) {
        return None;
    }
    let args = if with_args {
        action.claims.mcp_args.as_deref().unwrap_or_default()
    } else {
        ""
    };
    Some(serde_json::json!([
        "mcp",
        action.claims.mcp_tool.as_deref().unwrap_or_default(),
        args,
        action.local_client.unwrap_or_default(),
    ]))
}

/// The key a lease («for a while») on an MCP tool call also serves (ADR
/// 0049 §5.4, T261): the target key without the argument digest, so the
/// same tool with any arguments, for the same caller. `None` for every
/// request without a tool: its approvals serve their target key only.
pub(crate) fn lease_key(grant_version: u64, action: &Action<'_>) -> Option<String> {
    action.claims.mcp_tool.as_ref()?;
    let full = target_key(grant_version, action);
    let mut key: serde_json::Value = serde_json::from_str(&full).ok()?;
    let parts = key.as_array_mut()?;
    parts.pop();
    parts.push(mcp_key_part(action, false)?);
    Some(key.to_string())
}

/// The live task that covers `action` (ADR 0021 §4), if any. With `only`,
/// just that task. Actions without an item (`create`) are never covered.
async fn task_for(
    state: &AppState,
    auth: &AgentAuth,
    action: &Action<'_>,
    only: Option<TaskId>,
) -> ApiResult<Option<TaskId>> {
    let Some(item) = action.item else {
        return Ok(None);
    };
    covering_task(
        state,
        auth.agent_id,
        action.permission,
        action.vault,
        action.project,
        item,
        action.claims.domain.as_deref(),
        only,
    )
    .await
}

/// Checks an action against the grant and the agent's tasks (ADR 0021 §5,
/// the server half of the double barrier): denies it, lets it through, or
/// turns it into an approval request.
///
/// * `passkey` and `rotate` pass only if a live task covers them; otherwise
///   they are `deny` ("ask for a task").
/// * Otherwise the current grant decides: `deny` stays `deny` (a task never
///   widens it), `allow` passes, and `ask` uses, in order: the
///   `approval_id` given; a live task that covers the action; a running
///   lease or an unspent approve-once decision for the same target; the
///   pending request for the same target; or a new request (ADR 0015 §2).
///
/// With `task_id`, only that task is considered. An action let through
/// while a task covers it logs that task.
///
/// With `probe` (`POST /v1/agent/approvals`, before a write's body is
/// sent), nothing is spent: an approve-once decision found for the target
/// is returned unspent, for the write to spend.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn gate(
    state: &AppState,
    auth: &AgentAuth,
    grant: &Grant,
    action: &Action<'_>,
    kind: &str,
    approval_id: Option<ApprovalId>,
    task_id: Option<TaskId>,
    probe: bool,
) -> ApiResult<Gate> {
    if !grant.covers(action) {
        return Err(ApiError::NotFound);
    }
    let now = now_ms();
    // An expired grant denies everything, tasks included (spec §13.5): the
    // task branch below never reaches `policy::evaluate`, which checks it.
    if grant.policy.expires_at.is_some_and(|t| now_secs(now) >= t) {
        return Err(ApiError::Denied(
            "the agent's policy has expired: the person must grant it again".into(),
        ));
    }
    if action.permission.requires_task() {
        return match task_for(state, auth, action, task_id).await? {
            Some(task) => Ok(Gate::Allow {
                approval: None,
                task: Some(task),
            }),
            None => Err(ApiError::Denied(format!(
                "`{}` only works inside an approved task that covers this item and site: ask for one with request_task",
                permission_name(action.permission)
            ))),
        };
    }
    let decision = policy::evaluate(&grant.policy, &policy_request(action, now));
    match decision.effect {
        Effect::Allow => Ok(Gate::Allow {
            approval: None,
            task: task_for(state, auth, action, task_id).await?,
        }),
        Effect::Deny => Err(ApiError::Denied(format!(
            "the policy denies `{}` here",
            permission_name(action.permission)
        ))),
        Effect::Ask => {
            let key = target_key(grant.version, action);
            let lease = lease_key(grant.version, action);
            if let Some(id) = approval_id {
                use_approval(state, auth, grant, &key, lease.as_deref(), id, now).await?;
                return Ok(Gate::Allow {
                    approval: Some(id),
                    task: None,
                });
            }
            if let Some(task) = task_for(state, auth, action, task_id).await? {
                if !probe {
                    spend_once_for_target(state, auth, &key, task, now).await?;
                }
                return Ok(Gate::Allow {
                    approval: None,
                    task: Some(task),
                });
            }
            if let Some(id) =
                reuse_approved(state, auth, &key, lease.as_deref(), now, probe).await?
            {
                return Ok(Gate::Allow {
                    approval: Some(id),
                    task: None,
                });
            }
            Ok(Gate::Pending(
                ask(
                    state,
                    auth,
                    grant,
                    action,
                    &key,
                    lease.as_deref(),
                    kind,
                    task_id,
                    now,
                )
                .await?,
            ))
        }
    }
}

/// Logs an agent action and its outcome (design §6): the agent's signed
/// request goes with it.
async fn record(
    state: &AppState,
    auth: &AgentAuth,
    action: &Action<'_>,
    kind: &str,
    outcome: &str,
    approval_id: Option<ApprovalId>,
    task_id: Option<TaskId>,
) -> ApiResult<()> {
    let event = agent_event(auth, action, kind, outcome, approval_id, task_id);
    append_agent_event(state, auth, action, outcome, event).await
}

/// The event of an agent action and its outcome, with the agent's signed
/// request.
fn agent_event(
    auth: &AgentAuth,
    action: &Action<'_>,
    kind: &str,
    outcome: &str,
    approval_id: Option<ApprovalId>,
    task_id: Option<TaskId>,
) -> AuditEvent {
    let mut event = AuditEvent::new(ActorKind::Agent, kind);
    event.task_id = task_id;
    event.agent_id = Some(auth.agent_id);
    event.vault_id = Some(action.vault);
    event.project_id = Some(action.project);
    event.item_id = action.item;
    event.permission = Some(action.permission);
    event.outcome = Some(outcome.to_owned());
    event.reason = Some(action.reason.to_owned());
    event.domain.clone_from(&action.claims.domain);
    event.method.clone_from(&action.claims.method);
    event.path.clone_from(&action.claims.path);
    if outcome == "allow" {
        event.attachments = action.attachments.to_vec();
    }
    event.approval_id = approval_id;
    event.agent_proof = Some(auth.proof.clone());
    event
}

/// Appends `event`, the agent's `outcome` on `action` (see [`record`]).
async fn append_agent_event(
    state: &AppState,
    auth: &AgentAuth,
    action: &Action<'_>,
    outcome: &str,
    mut event: AuditEvent,
) -> ApiResult<()> {
    let Some(sandbox) = action.sandbox.filter(|_| outcome == "allow") else {
        return audit::append(state, auth.account_id, event).await.map(drop);
    };
    // A sandbox's allowed call: the barrier again, in the transaction that
    // logs it, under the account's lock (ADR 0036 E3.3). An end or a
    // person's revocation committed before this lock is seen here, so the
    // chain never shows an allowed call for a sandbox after its revocation;
    // the check before the policy only spares the work.
    let now = crate::db::now_ms();
    let mut extra = audit::alerts(state, &event, now).await?;
    event.alerts.append(&mut extra);
    let mut tx = state.db().pool.begin().await?;
    crate::routes::sandboxes::lock_account(&mut tx, auth.account_id).await?;
    // The proxy itself first, as the proxy's own writes check it: a proxy
    // revoked meanwhile gets the extractor's answer (`403 forbidden`), not
    // its sandbox's (`append_in` would refuse it after the barrier too).
    crate::agentauth::still_active(&mut *tx, auth.agent_id, auth.account_id, now).await?;
    crate::routes::sandboxes::barrier(&mut tx, auth, sandbox, now).await?;
    audit::append_in(&mut tx, auth.account_id, &mut event, now).await?;
    tx.commit().await?;
    Ok(())
}

/// [`gate`], with the outcome logged before anything is returned: an
/// agent never gets details (or writes) without an audit event. An action
/// let through by an approval logs that approval's ID (its use).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn checked(
    state: &AppState,
    auth: &AgentAuth,
    grant: &Grant,
    action: &Action<'_>,
    kind: &str,
    approval_id: Option<ApprovalId>,
    task_id: Option<TaskId>,
    probe: bool,
) -> ApiResult<Gate> {
    check_claims(action.permission, action.claims)?;
    let result = gate(
        state,
        auth,
        grant,
        action,
        kind,
        approval_id,
        task_id,
        probe,
    )
    .await;
    match &result {
        Ok(Gate::Allow { approval, task }) => {
            let logged = record(state, auth, action, kind, "allow", *approval, *task).await;
            if let (
                Err(
                    ApiError::Paused(_)
                    | ApiError::Unauthorized
                    | ApiError::BadRequest(_)
                    | ApiError::Forbidden
                    | ApiError::AccountDeleting(_),
                ),
                Some(id),
            ) = (&logged, approval)
                && !probe
            {
                // Paused while in flight (ADR 0033 §7.6), revoked or with
                // the account's deletion asked for meanwhile (both seen
                // under the account's lock as the action is logged), or
                // refused as it was logged (its signed time out of the
                // window by then): the action did not happen, so an
                // approve-once decision it spent is given back. A revoked
                // agent can never use it again; the record stays honest.
                // A probe only read the decision (`reuse_approved`), so it
                // has nothing to give back: another request may have spent
                // it meanwhile.
                unspend(state, *id).await?;
            }
            logged?;
        }
        // Logged by `ask`, a new request in the transaction that stores
        // it.
        Ok(Gate::Pending(_)) => {}
        Err(ApiError::Denied(_)) => {
            record(state, auth, action, kind, "deny", approval_id, task_id).await?;
        }
        Err(_) => {}
    }
    result
}

pub(crate) fn permission_name(permission: Permission) -> String {
    serde_json::to_value(permission)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default()
}

/// Spends an approve-once decision, unless it was already spent (only one
/// concurrent request wins).
async fn spend(state: &AppState, id: &str, now: i64) -> ApiResult<bool> {
    let spent = sqlx::query("UPDATE approvals SET used_at = $1 WHERE id = $2 AND used_at IS NULL")
        .bind(now)
        .bind(id)
        .execute(&state.db().pool)
        .await?;
    Ok(spent.rows_affected() == 1)
}

/// Gives back an approve-once decision spent by an action the log refused
/// (see [`checked`]). Leases are never spent, so they are left alone.
async fn unspend(state: &AppState, id: ApprovalId) -> ApiResult<()> {
    sqlx::query(
        "UPDATE approvals SET used_at = NULL \
         WHERE id = $1 AND (lease_until IS NULL OR lease_until = 0)",
    )
    .bind(id.to_string())
    .execute(&state.db().pool)
    .await?;
    Ok(())
}

/// Spends the approve-once decision «Add to the task» left for `key` in
/// `task` when a use goes through that task instead (ADR 0021 §6): it
/// approved the pending request once so the agent's waiter exits, and must
/// not stay behind. Only approvals bound to that task: an approve-once the
/// person gave on its own keeps serving its window. Leases are left alone.
async fn spend_once_for_target(
    state: &AppState,
    auth: &AgentAuth,
    key: &str,
    task: TaskId,
    now: i64,
) -> ApiResult<()> {
    sqlx::query(
        "UPDATE approvals SET used_at = $1 \
         WHERE agent_id = $2 AND target_key = $3 AND status = $4 \
         AND (lease_until IS NULL OR lease_until = 0) AND used_at IS NULL AND task_id = $5",
    )
    .bind(now)
    .bind(auth.agent_id.to_string())
    .bind(key)
    .bind(ApprovalStatus::Approved.as_str())
    .bind(task.to_string())
    .execute(&state.db().pool)
    .await?;
    Ok(())
}

/// An approval for the same target that lets this request through without
/// asking (ADR 0015 §2): a running lease, or else an approve-once decision
/// taken less than [`ONCE_WINDOW_MS`] ago and not spent yet, which this
/// request spends (with `probe`, it is only returned). Never one bound to a
/// task by «Add to the task»: that one serves only by name, while its task
/// runs ([`use_approval`]).
async fn reuse_approved(
    state: &AppState,
    auth: &AgentAuth,
    key: &str,
    lease: Option<&str>,
    now: i64,
    probe: bool,
) -> ApiResult<Option<ApprovalId>> {
    // An MCP tool call: a running lease on the same tool, whatever its
    // arguments (ADR 0049 §5.4). Never an approve-once decision, which
    // binds its arguments through the target key below.
    if let Some(lease) = lease {
        let id: Option<String> = sqlx::query_scalar(
            "SELECT id FROM approvals \
             WHERE agent_id = $1 AND lease_key = $2 AND status = $3 AND task_id IS NULL \
             AND lease_until > $4 ORDER BY decided_at LIMIT 1",
        )
        .bind(auth.agent_id.to_string())
        .bind(lease)
        .bind(ApprovalStatus::Approved.as_str())
        .bind(now)
        .fetch_optional(&state.db().pool)
        .await?;
        if let Some(id) = id {
            return Ok(Some(path_id(&id)?));
        }
    }
    let rows = sqlx::query(
        "SELECT id, lease_until FROM approvals \
         WHERE agent_id = $1 AND target_key = $2 AND status = $3 AND task_id IS NULL \
         AND (lease_until > $4 \
              OR ((lease_until IS NULL OR lease_until = 0) AND used_at IS NULL AND decided_at > $5)) \
         ORDER BY decided_at",
    )
    .bind(auth.agent_id.to_string())
    .bind(key)
    .bind(ApprovalStatus::Approved.as_str())
    .bind(now)
    .bind(now - ONCE_WINDOW_MS)
    .fetch_all(&state.db().pool)
    .await?;
    // A lease first: it does not need spending a one-time decision.
    for row in &rows {
        if row.try_get::<Option<i64>, _>("lease_until")?.unwrap_or(0) > now {
            return Ok(Some(path_id(&row.try_get::<String, _>("id")?)?));
        }
    }
    for row in &rows {
        let id: String = row.try_get("id")?;
        if probe {
            return Ok(Some(path_id(&id)?));
        }
        if spend(state, &id, now).await? {
            return Ok(Some(path_id(&id)?));
        }
    }
    Ok(None)
}

/// Uses an approval the agent named: it must be this agent's, for the same
/// target under the current grant, approved, and either leased until later
/// or approved once, less than [`ONCE_WINDOW_MS`] ago and not used yet.
#[allow(clippy::too_many_arguments)]
async fn use_approval(
    state: &AppState,
    auth: &AgentAuth,
    grant: &Grant,
    key: &str,
    lease: Option<&str>,
    id: ApprovalId,
    now: i64,
) -> ApiResult<()> {
    let row = sqlx::query(
        "SELECT status, expires_at, target_key, grant_version, decided_at, lease_until, used_at, \
         task_id, lease_key FROM approvals WHERE id = $1 AND agent_id = $2",
    )
    .bind(id.to_string())
    .bind(auth.agent_id.to_string())
    .fetch_optional(&state.db().pool)
    .await?
    .ok_or(ApiError::NotFound)?;
    if row.try_get::<i64, _>("grant_version")? != to_i64(grant.version)? {
        return Err(ApiError::conflict(
            "the grant changed since the approval: ask again",
        ));
    }
    // The same tool with other arguments: only a lease on the tool serves
    // it (ADR 0049 §5.4), checked below once the status is known.
    let other_args = row.try_get::<Option<String>, _>("target_key")?.as_deref() != Some(key);
    if other_args
        && (lease.is_none() || row.try_get::<Option<String>, _>("lease_key")?.as_deref() != lease)
    {
        return Err(ApiError::bad_request(
            "approval_id is for another action, item or site",
        ));
    }
    let status = effective_approval_status(
        &row.try_get::<String, _>("status")?,
        row.try_get("expires_at")?,
        now,
    )?;
    match status {
        ApprovalStatus::Pending => {
            return Err(ApiError::conflict(
                "the approval is still pending: wait for the person",
            ));
        }
        ApprovalStatus::Denied => return Err(ApiError::Denied("the person denied it".into())),
        ApprovalStatus::Expired => {
            return Err(ApiError::conflict("the approval expired: ask again"));
        }
        ApprovalStatus::Approved => {}
    }
    // Bound to a task by «Add to the task»: only while that task runs.
    if let Some(task) = row.try_get::<Option<String>, _>("task_id")? {
        let running: Option<i64> = sqlx::query_scalar(
            "SELECT expires_at FROM tasks WHERE id = $1 AND agent_id = $2 AND status = $3 \
             AND expires_at > $4",
        )
        .bind(&task)
        .bind(auth.agent_id.to_string())
        .bind(TaskStatus::Approved.as_str())
        .bind(now)
        .fetch_optional(&state.db().pool)
        .await?;
        if running.is_none() {
            return Err(ApiError::conflict(
                "the approval was added to a task that is no longer running: ask again",
            ));
        }
    }
    let lease: i64 = row.try_get::<Option<i64>, _>("lease_until")?.unwrap_or(0);
    if lease > now {
        return Ok(());
    }
    if lease != 0 {
        return Err(ApiError::conflict("the approval's lease ended: ask again"));
    }
    if other_args {
        return Err(ApiError::conflict(
            "the approval was once, for other arguments of this tool: ask again",
        ));
    }
    if row.try_get::<Option<i64>, _>("used_at")?.is_some() {
        return Err(ApiError::conflict(
            "the approval was already used: ask again",
        ));
    }
    let decided: i64 = row.try_get::<Option<i64>, _>("decided_at")?.unwrap_or(0);
    if decided <= now - ONCE_WINDOW_MS {
        return Err(ApiError::conflict(
            "the approval was not used within 10 minutes: ask again",
        ));
    }
    if spend(state, &id.to_string(), now).await? {
        Ok(())
    } else {
        Err(ApiError::conflict(
            "the approval was already used: ask again",
        ))
    }
}

/// The live pending request of this agent for `key`, if any.
async fn find_pending(
    state: &AppState,
    auth: &AgentAuth,
    key: &str,
    now: i64,
) -> ApiResult<Option<PendingApproval>> {
    let row = sqlx::query(
        "SELECT id, expires_at FROM approvals \
         WHERE agent_id = $1 AND target_key = $2 AND status = $3 AND expires_at > $4",
    )
    .bind(auth.agent_id.to_string())
    .bind(key)
    .bind(ApprovalStatus::Pending.as_str())
    .bind(now)
    .fetch_optional(&state.db().pool)
    .await?;
    row.map(|row| {
        Ok(PendingApproval {
            pending_approval_id: path_id(&row.try_get::<String, _>("id")?)?,
            expires_at: row.try_get("expires_at")?,
        })
    })
    .transpose()
}

/// The approval request for the person: the pending one for the same
/// target if there is one (a retry gets the same ID), or a new one.
#[allow(clippy::too_many_arguments)]
async fn ask(
    state: &AppState,
    auth: &AgentAuth,
    grant: &Grant,
    action: &Action<'_>,
    key: &str,
    lease: Option<&str>,
    kind: &str,
    task_id: Option<TaskId>,
    now: i64,
) -> ApiResult<PendingApproval> {
    // A request already pending for the target: nothing new is stored,
    // only this ask is logged.
    let reused = |pending: PendingApproval| async move {
        record(
            state,
            auth,
            action,
            kind,
            "ask",
            Some(pending.pending_approval_id),
            task_id,
        )
        .await
        .map(|()| pending)
    };
    if let Some(pending) = find_pending(state, auth, key, now).await? {
        return reused(pending).await;
    }
    let id = ApprovalId::generate();
    let mut event = agent_event(auth, action, kind, "ask", Some(id), task_id);
    let mut extra = audit::alerts(state, &event, now).await?;
    event.alerts.append(&mut extra);
    // Count and insert as one step, under the agent's lock (layer 06 of
    // the 2026-11 round): concurrent requests cannot all pass the cap. The
    // account's lock first, as every transaction that logs in itself
    // takes it: the ask is logged in this transaction, so a request the log
    // refuses (its signed time out of the window by now) stores nothing.
    let mut tx = state.db().pool.begin().await?;
    crate::deletion::lock_account(&mut tx, auth.account_id).await?;
    lock_agent(&mut tx, auth.agent_id).await?;
    // Pending requests expire lazily: mark this agent's old ones, so the
    // unique index on pending targets only holds live requests.
    sqlx::query(
        "UPDATE approvals SET status = $1 WHERE agent_id = $2 AND status = $3 AND expires_at <= $4",
    )
    .bind(ApprovalStatus::Expired.as_str())
    .bind(auth.agent_id.to_string())
    .bind(ApprovalStatus::Pending.as_str())
    .bind(now)
    .execute(&mut *tx)
    .await?;
    let pending: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM approvals WHERE agent_id = $1 AND status = $2 AND expires_at > $3",
    )
    .bind(auth.agent_id.to_string())
    .bind(ApprovalStatus::Pending.as_str())
    .bind(now)
    .fetch_one(&mut *tx)
    .await?;
    if pending >= MAX_PENDING_APPROVALS {
        return Err(ApiError::TooManyRequests {
            retry_after_secs: 60,
        });
    }
    // Who the call is for, under the person's signature (ADR 0049 §5.4),
    // only while the account's switch is on: otherwise the request's bytes
    // stay what older devices read.
    let caller = match (action.sandbox, action.local_client) {
        (None, None) => None,
        (sandbox, local) => crate::routes::account::mcp_gateway_since(&mut *tx, auth.account_id)
            .await?
            .map(|_| ApprovalCaller {
                sandbox_id: sandbox,
                local_client: local.map(str::to_owned),
            }),
    };
    let request = ApprovalRequest {
        v: 1,
        approval_id: id,
        agent_id: auth.agent_id,
        agent_name: auth.name.clone(),
        permission: action.permission,
        vault_id: action.vault,
        project_id: action.project,
        item_id: action.item,
        reason: action.reason.to_owned(),
        claims: action.claims.clone(),
        grant_version: grant.version,
        requested_at: now,
        caller,
    };
    let bytes = serde_json::to_vec(&request)
        .map_err(|e| ApiError::Internal(format!("approval request: {e}")))?;
    let expires_at = now + APPROVAL_TTL_MS;
    let inserted = sqlx::query(
        "INSERT INTO approvals (id, account_id, agent_id, status, permission, vault_id, \
         project_id, item_id, request, grant_version, created_at, expires_at, target_key, \
         lease_key) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)",
    )
    .bind(id.to_string())
    .bind(auth.account_id.to_string())
    .bind(auth.agent_id.to_string())
    .bind(ApprovalStatus::Pending.as_str())
    .bind(permission_name(action.permission))
    .bind(action.vault.to_string())
    .bind(action.project.to_string())
    .bind(action.item.map(|i| i.to_string()))
    .bind(bytes)
    .bind(to_i64(grant.version)?)
    .bind(now)
    .bind(expires_at)
    .bind(key)
    .bind(lease)
    .execute(&mut *tx)
    .await;
    match inserted {
        Ok(_) => {
            audit::append_in(&mut tx, auth.account_id, &mut event, now_ms()).await?;
            tx.commit().await?;
            state.push(auth.account_id, PushKind::Approval, id.to_string());
            Ok(PendingApproval {
                pending_approval_id: id,
                expires_at,
            })
        }
        // A concurrent request for the same target won: use its request.
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
            drop(tx);
            let pending = find_pending(state, auth, key, now).await?.ok_or_else(|| {
                ApiError::conflict("a request for the same action was just decided: retry")
            })?;
            reused(pending).await
        }
        Err(e) => Err(e.into()),
    }
}

/// `GET /v1/agent/items`: overviews and wrapped keys of the granted
/// projects whose `list` the policy allows (upper bound over tags: the
/// runtime applies the exact policy, ADR 0014 §4).
async fn list_items(State(state): State<AppState>, auth: AgentAuth) -> ApiResult<Json<AgentItems>> {
    let grant = load_grant(&state, &auth).await?;
    let now = now_ms();
    let mut projects = Vec::new();
    let mut granted: Vec<(&ProjectId, &VaultId)> = grant.projects.iter().collect();
    granted.sort_by_key(|(p, _)| **p);
    for (project, vault) in granted {
        let claims = Claims::default();
        let action = Action {
            permission: Permission::List,
            vault: *vault,
            project: *project,
            item: None,
            claims: &claims,
            reason: "",
            attachments: &[],
            sandbox: None,
            local_client: None,
        };
        let decision = policy::evaluate_upper_bound(&grant.policy, &policy_request(&action, now));
        if decision.effect != Effect::Allow {
            continue;
        }
        // Read first: if the key rotates before the items are read, the
        // runtime writes with a stale `project_version` and gets a 409.
        // A deleted vault is out of reach (until restored), like for the
        // person: its items wait for the purge.
        let Some(row) = sqlx::query(
            "SELECT p.version, p.meta FROM projects p JOIN vaults v ON v.id = p.vault_id \
             WHERE p.id = $1 AND p.vault_id = $2 AND p.deleted_at IS NULL \
             AND v.deleted_at IS NULL",
        )
        .bind(project.to_string())
        .bind(vault.to_string())
        .fetch_optional(&state.db().pool)
        .await?
        else {
            continue;
        };
        let project_version = to_u64(row.try_get("version")?);
        let project_meta: Option<Vec<u8>> = row.try_get("meta")?;
        let rows = sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT {ITEM_COLUMNS} FROM items WHERE vault_id = $1 AND project_id = $2 \
             AND purged_at IS NULL AND trashed_at IS NULL ORDER BY created_at, id"
        )))
        .bind(vault.to_string())
        .bind(project.to_string())
        .fetch_all(&state.db().pool)
        .await?;
        let attachments = sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT {} FROM attachments a WHERE a.vault_id = $1 \
             AND a.completed_at IS NOT NULL AND a.deleted_at IS NULL \
             AND a.item_id IN (SELECT id FROM items WHERE vault_id = $1 AND project_id = $2 \
             AND purged_at IS NULL AND trashed_at IS NULL) ORDER BY a.created_at, a.id",
            prefixed_attachment_columns()
        )))
        .bind(vault.to_string())
        .bind(project.to_string())
        .fetch_all(&state.db().pool)
        .await?
        .iter()
        .map(attachment_from_row)
        .collect::<ApiResult<_>>()?;
        projects.push(AgentProjectItems {
            vault_id: *vault,
            project_id: *project,
            project_version,
            project_meta: klav_proto::Blob::new(project_meta.unwrap_or_default()),
            items: rows
                .iter()
                .map(|row| item_from_row(row, false))
                .collect::<ApiResult<_>>()?,
            attachments,
        });
    }
    Ok(Json(AgentItems {
        grant_version: grant.version,
        projects,
    }))
}

/// `a.id, a.vault_id, …`: the attachment columns, for a query that names
/// the table `a`.
fn prefixed_attachment_columns() -> String {
    ATTACHMENT_COLUMNS
        .split(',')
        .map(|c| format!("a.{}", c.trim()))
        .collect::<Vec<_>>()
        .join(", ")
}

/// The completed, live attachments of `item`, for an `inject` that asked
/// for them (ADR 0016). Only their metadata: read before the decision is
/// logged, so an allowed access is logged with what it delivers. Their
/// contents are read by [`attachment_contents`], once the decision allows.
async fn attachment_metas(
    state: &AppState,
    item: &klav_proto::vault::Item,
) -> ApiResult<Vec<klav_proto::sync::Attachment>> {
    let metas: Vec<klav_proto::sync::Attachment> = sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT {ATTACHMENT_COLUMNS} FROM attachments WHERE vault_id = $1 AND item_id = $2 \
         AND completed_at IS NOT NULL AND deleted_at IS NULL ORDER BY created_at, id"
    )))
    .bind(item.vault_id.to_string())
    .bind(item.id.to_string())
    .fetch_all(&state.db().pool)
    .await?
    .iter()
    .map(attachment_from_row)
    .collect::<ApiResult<_>>()?;
    let total: u64 = metas.iter().map(|a| a.size).sum();
    if total > MAX_AGENT_ATTACHMENTS_BYTES {
        return Err(ApiError::bad_request(
            "the item's attachments are larger than 16 MiB: agents cannot receive them",
        ));
    }
    Ok(metas)
}

/// The ciphertext of `metas` (from [`attachment_metas`]). Called only for
/// an access the gate allowed: a denied or pending one never touches the
/// files.
async fn attachment_contents(
    state: &AppState,
    vault_id: VaultId,
    metas: Vec<klav_proto::sync::Attachment>,
) -> ApiResult<Vec<AgentAttachment>> {
    let mut out = Vec::with_capacity(metas.len());
    for attachment in metas {
        let path = state.attachments().path(vault_id, attachment.id);
        let content = tokio::fs::read(&path)
            .await
            .map_err(|e| ApiError::Internal(format!("attachment {}: {e}", attachment.id)))?;
        if content.len() as u64 != attachment.size {
            return Err(ApiError::Internal(format!(
                "attachment {} has {} bytes on disk, {} expected",
                attachment.id,
                content.len(),
                attachment.size
            )));
        }
        out.push(AgentAttachment {
            attachment,
            content: klav_proto::Blob::new(content),
        });
    }
    Ok(out)
}

/// The live item `item_id` (any vault), if the agent's grant covers it.
pub(crate) async fn granted_item(
    state: &AppState,
    grant: &Grant,
    item_id: ItemId,
) -> ApiResult<klav_proto::vault::Item> {
    let row = sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT {ITEM_COLUMNS} FROM items WHERE id = $1 AND purged_at IS NULL \
         AND trashed_at IS NULL \
         AND vault_id IN (SELECT id FROM vaults WHERE deleted_at IS NULL)"
    )))
    .bind(item_id.to_string())
    .fetch_optional(&state.db().pool)
    .await?
    .ok_or(ApiError::NotFound)?;
    let item = item_from_row(&row, true)?;
    if grant.projects.get(&item.project_id) != Some(&item.vault_id) {
        return Err(ApiError::NotFound);
    }
    Ok(item)
}

/// The live item `item_id` for a `proxy` access (ADR 0036 §2): it must be
/// one of the items granted one by one, still in the vault and project the
/// grant names (an item moved since then is out of reach until a new grant).
async fn granted_proxy_item(
    state: &AppState,
    grant: &Grant,
    item_id: ItemId,
) -> ApiResult<klav_proto::vault::Item> {
    let Some(&(vault, project)) = grant.items.get(&item_id) else {
        return Err(ApiError::NotFound);
    };
    let row = sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT {ITEM_COLUMNS} FROM items WHERE id = $1 AND vault_id = $2 AND project_id = $3 \
         AND purged_at IS NULL AND trashed_at IS NULL \
         AND vault_id IN (SELECT id FROM vaults WHERE deleted_at IS NULL)"
    )))
    .bind(item_id.to_string())
    .bind(vault.to_string())
    .bind(project.to_string())
    .fetch_optional(&state.db().pool)
    .await?
    .ok_or(ApiError::NotFound)?;
    item_from_row(&row, true)
}

/// `access` with `passkey` (ADR 0020 §9, step 1): only inside a task, for
/// the host of the person's tab (`claims.domain`, mandatory). The server
/// checks the task and logs the use **before** answering, and hands out
/// nothing of the item: the person's `klavd` checks the agent's signed
/// request and the task again, and signs in the browser.
async fn passkey_access(
    state: &AppState,
    auth: &AgentAuth,
    grant: &Grant,
    item: &klav_proto::vault::Item,
    req: &AccessRequest,
    reason: &str,
) -> ApiResult<Response> {
    let host = req.claims.domain.clone().ok_or_else(|| {
        ApiError::bad_request("claims.domain is mandatory: the host of the person's tab")
    })?;
    // As signed, the form `check_claims` asks of every other permission:
    // the event logs this host, and the person's log verifier compares it
    // with the signed one. Rewriting it would log a host the agent never
    // signed, and break the person's log for good.
    if policy::normalize_host(&host).as_deref() != Some(host.as_str()) {
        return Err(ApiError::bad_request(
            "claims.domain must be a host name in lowercase, without scheme, port or trailing dot",
        ));
    }
    let claims = Claims {
        tags: req.claims.tags.clone(),
        domain: Some(host.clone()),
        ..Claims::default()
    };
    let action = Action {
        permission: Permission::Passkey,
        vault: item.vault_id,
        project: item.project_id,
        item: Some(item.id),
        claims: &claims,
        reason,
        attachments: &[],
        sandbox: None,
        local_client: None,
    };
    match checked(
        state,
        auth,
        grant,
        &action,
        "agent.access",
        None,
        req.task_id,
        false,
    )
    .await?
    {
        Gate::Allow {
            task: Some(task), ..
        } => Ok(Json(PasskeyAccess {
            task_id: task,
            item_id: item.id,
            domain: host,
        })
        .into_response()),
        // `passkey` is never asked for one by one: only a task lets it pass.
        _ => Err(ApiError::Internal("passkey passed without a task".into())),
    }
}

/// `POST /v1/agent/access`.
async fn access(State(state): State<AppState>, auth: AgentAuth) -> ApiResult<Response> {
    let req: AccessRequest = auth.logged_json()?;
    if !matches!(
        req.permission,
        Permission::List
            | Permission::Fill
            | Permission::Inject
            | Permission::Totp
            | Permission::Reveal
            | Permission::Update
            | Permission::Passkey
            | Permission::Rotate
            | Permission::Proxy
    ) {
        return Err(ApiError::bad_request(
            "access takes list, fill, inject, totp, reveal, proxy or update (to read before writing); use the item endpoints to write",
        ));
    }
    // A proxied call says where it goes; nothing else names a method or a
    // path (ADR 0036 §2). `checked` runs the same check for every route.
    check_http_claims(req.permission, &req.claims)?;
    // The MCP gateway's fields only while the account's switch is on (ADR
    // 0049 §9), and only in their grammars: refused before anything is
    // evaluated or logged. Without them, nothing here reads the switch.
    if uses_mcp_gateway(&req.claims, req.local_client.as_deref()) {
        if crate::routes::account::mcp_gateway_since(&state.db().pool, auth.account_id)
            .await?
            .is_none()
        {
            return Err(ApiError::mcp_gateway_off());
        }
        check_mcp_claims(
            req.permission,
            &req.claims,
            req.local_client.as_deref(),
            req.sandbox,
        )?;
    }
    // A header value, never a file (ADR 0036 §2).
    if req.permission == Permission::Proxy && req.include_attachments {
        return Err(ApiError::bad_request("proxy never takes attachments"));
    }
    if req.include_attachments && req.permission != Permission::Inject {
        return Err(ApiError::bad_request(
            "attachments are only delivered for inject",
        ));
    }
    let reason = check_reason(&req.reason)?;
    // The second barrier for sandboxes (ADR 0036 E3.3): a proxied call for
    // a sandbox that ended, expired, was never logged, was revoked by the
    // person, or whose issuer is gone or paused is refused before anything
    // is evaluated or logged. An allowed call checks it again when it is
    // logged (`record`).
    if let Some(sandbox) = req.sandbox {
        if req.permission != Permission::Proxy {
            return Err(ApiError::bad_request("sandbox is only for proxy"));
        }
        let now = crate::db::now_ms();
        let mut tx = state.db().pool.begin().await?;
        crate::routes::sandboxes::lock_account(&mut tx, auth.account_id).await?;
        // The proxy itself first, as the proxy's own writes check it: a
        // proxy revoked since the extractor's read gets its answer
        // (`403 forbidden`), not its sandbox's.
        crate::agentauth::still_active(&mut *tx, auth.agent_id, auth.account_id, now).await?;
        crate::routes::sandboxes::barrier(&mut tx, &auth, sandbox, now).await?;
        tx.commit().await?;
    }
    let grant = load_grant(&state, &auth).await?;
    // A local client the proxy's grant does not have for this item's MCP
    // profile is refused (`400`), never evaluated or logged (ADR 0049 §3.2).
    if let Some(name) = req.local_client.as_deref()
        && !grant.local_client_may_use(name, req.item_id)
    {
        return Err(ApiError::bad_request(
            "local_client is not a local client of this proxy's grant for this item's MCP profile",
        ));
    }
    let item = if req.permission == Permission::Proxy {
        granted_proxy_item(&state, &grant, req.item_id).await?
    } else {
        granted_item(&state, &grant, req.item_id).await?
    };
    if req.permission == Permission::Passkey {
        return passkey_access(&state, &auth, &grant, &item, &req, &reason).await;
    }
    let metas = if req.include_attachments {
        attachment_metas(&state, &item).await?
    } else {
        Vec::new()
    };
    let delivered: Vec<AttachmentId> = metas.iter().map(|a| a.id).collect();
    let action = Action {
        permission: req.permission,
        vault: item.vault_id,
        project: item.project_id,
        item: Some(item.id),
        claims: &req.claims,
        reason: &reason,
        attachments: &delivered,
        sandbox: req.sandbox,
        local_client: req.local_client.as_deref(),
    };
    // `rotate` is used through `klavd` and its own route (ADR 0022), never
    // by handing the item to the agent: outside a task it is denied (and
    // logged) like any denial; inside one, `access` does not serve it.
    if req.permission.requires_task()
        && task_for(&state, &auth, &action, req.task_id)
            .await?
            .is_some()
    {
        return Err(ApiError::bad_request(format!(
            "`{}` is used through klavd and the browser, not through access",
            permission_name(req.permission)
        )));
    }
    match checked(
        &state,
        &auth,
        &grant,
        &action,
        "agent.access",
        req.approval_id,
        req.task_id,
        false,
    )
    .await?
    {
        Gate::Pending(p) => Ok(Gate::pending_response(p)),
        Gate::Allow { approval, .. } => {
            let attachments = attachment_contents(&state, item.vault_id, metas).await?;
            let mut item = item;
            // `list` is metadata: the secrets stay out.
            if req.permission == Permission::List {
                item.details = None;
            }
            // The confirmed sites matter to `fill` (ADR 0030 §7), not to a
            // proxy, whose hosts the account signed.
            let person_version = match item.author_agent_id {
                Some(_) if req.permission != Permission::Proxy => {
                    person_version(&state, item.id).await?
                }
                _ => None,
            };
            let sole_author = item.author_agent_id == Some(auth.agent_id)
                && person_version.is_none()
                && sole_author(&state, item.id, auth.agent_id, item.version).await?;
            Ok(Json(AccessGranted {
                item,
                attachments,
                approval_id: approval,
                person_version,
                sole_author,
            })
            .into_response())
        }
    }
}

/// The last stored version of `item` the person wrote (ADR 0030 §7): its
/// overview carries the confirmed sites.
async fn person_version(state: &AppState, item: ItemId) -> ApiResult<Option<PersonVersion>> {
    let row = sqlx::query(
        "SELECT version, wrapped_key, overview FROM item_versions \
         WHERE item_id = $1 AND author_agent_id IS NULL ORDER BY version DESC LIMIT 1",
    )
    .bind(item.to_string())
    .fetch_optional(&state.db().pool)
    .await?;
    row.map(|row| {
        Ok(PersonVersion {
            version: to_u64(row.try_get("version")?),
            wrapped_key: Blob::new(row.try_get("wrapped_key")?),
            overview: Blob::new(row.try_get("overview")?),
        })
    })
    .transpose()
}

/// Whether `agent` wrote every stored previous version of `item` (the
/// current one is checked by the caller) and none is missing from the
/// history, so no version of the person or of another agent can hide in a
/// pruned one (ADR 0030 §7).
async fn sole_author(
    state: &AppState,
    item: ItemId,
    agent: AgentId,
    current: u64,
) -> ApiResult<bool> {
    let (stored, others): (i64, i64) = sqlx::query_as(
        "SELECT COUNT(*), COUNT(*) - COUNT(CASE WHEN author_agent_id = $2 THEN 1 END) \
         FROM item_versions WHERE item_id = $1",
    )
    .bind(item.to_string())
    .bind(agent.to_string())
    .fetch_one(&state.db().pool)
    .await?;
    Ok(others == 0 && to_u64(stored) == current.saturating_sub(1))
}

/// `POST /v1/agent/items`.
async fn create_item(State(state): State<AppState>, auth: AgentAuth) -> ApiResult<Response> {
    let req: AgentCreateItem = auth.json()?;
    let reason = check_reason(&req.reason)?;
    let grant = load_grant(&state, &auth).await?;
    let action = Action {
        permission: Permission::Create,
        vault: req.vault_id,
        project: req.item.project_id,
        item: None,
        claims: &req.claims,
        reason: &reason,
        attachments: &[],
        sandbox: None,
        local_client: None,
    };
    match checked(
        &state,
        &auth,
        &grant,
        &action,
        "agent.create",
        req.approval_id,
        req.task_id,
        false,
    )
    .await?
    {
        Gate::Pending(p) => Ok(Gate::pending_response(p)),
        Gate::Allow { approval, .. } => {
            let item = insert_item(
                &state,
                req.vault_id,
                req.item,
                Writer::Agent {
                    agent: auth.agent_id,
                    account: auth.account_id,
                },
            )
            .await?;
            Ok((
                StatusCode::CREATED,
                Json(AgentWritten {
                    item,
                    approval_id: approval,
                }),
            )
                .into_response())
        }
    }
}

/// `PUT /v1/agent/items/{item_id}`.
async fn update_item(
    State(state): State<AppState>,
    Path(item_id): Path<String>,
    auth: AgentAuth,
) -> ApiResult<Response> {
    let item_id: ItemId = path_id(&item_id)?;
    let req: AgentUpdateItem = auth.json()?;
    if req.item.attachment_keys.is_some() {
        return Err(ApiError::bad_request(
            "agents do not change an item's key: only the person does",
        ));
    }
    let reason = check_reason(&req.reason)?;
    let grant = load_grant(&state, &auth).await?;
    let item = granted_item(&state, &grant, item_id).await?;
    let action = Action {
        permission: Permission::Update,
        vault: item.vault_id,
        project: item.project_id,
        item: Some(item.id),
        claims: &req.claims,
        reason: &reason,
        attachments: &[],
        sandbox: None,
        local_client: None,
    };
    match checked(
        &state,
        &auth,
        &grant,
        &action,
        "agent.update",
        req.approval_id,
        req.task_id,
        false,
    )
    .await?
    {
        Gate::Pending(p) => Ok(Gate::pending_response(p)),
        Gate::Allow { approval, .. } => {
            let item = write_version(
                &state,
                item.vault_id,
                item.id,
                req.item,
                Writer::Agent {
                    agent: auth.agent_id,
                    account: auth.account_id,
                },
            )
            .await?;
            Ok(Json(AgentWritten {
                item,
                approval_id: approval,
            })
            .into_response())
        }
    }
}

/// `POST /v1/agent/items/{item_id}/trash`.
async fn trash_item(
    State(state): State<AppState>,
    Path(item_id): Path<String>,
    auth: AgentAuth,
) -> ApiResult<Response> {
    let item_id: ItemId = path_id(&item_id)?;
    let req: AgentTrashItem = auth.json()?;
    let reason = check_reason(&req.reason)?;
    let grant = load_grant(&state, &auth).await?;
    let item = granted_item(&state, &grant, item_id).await?;
    let action = Action {
        permission: Permission::Delete,
        vault: item.vault_id,
        project: item.project_id,
        item: Some(item.id),
        claims: &req.claims,
        reason: &reason,
        attachments: &[],
        sandbox: None,
        local_client: None,
    };
    match checked(
        &state,
        &auth,
        &grant,
        &action,
        "agent.trash",
        req.approval_id,
        req.task_id,
        false,
    )
    .await?
    {
        Gate::Pending(p) => Ok(Gate::pending_response(p)),
        Gate::Allow { approval, .. } => {
            move_to_trash(
                &state,
                item.vault_id,
                item.id,
                Writer::Agent {
                    agent: auth.agent_id,
                    account: auth.account_id,
                },
            )
            .await?;
            Ok(Json(AgentTrashed {
                approval_id: approval,
            })
            .into_response())
        }
    }
}

/// `POST /v1/agent/approvals`: the person is asked about a write before
/// its body is sent (ADR 0030 §3, residual risk 35). Same checks as the
/// write itself, without spending anything: `202` with the request, `200`
/// with what already lets it through ([`AgentAsked`]), or `403`. Logged
/// as `agent.ask`, with its body.
async fn ask_first(State(state): State<AppState>, auth: AgentAuth) -> ApiResult<Response> {
    let req: AgentAsk = auth.logged_json()?;
    match (req.permission, req.item_id) {
        (Permission::Create, None) | (Permission::Update | Permission::Delete, Some(_)) => {}
        (Permission::Create, Some(_)) => {
            return Err(ApiError::bad_request("create names no item"));
        }
        (Permission::Update | Permission::Delete, None) => {
            return Err(ApiError::bad_request("update and delete name the item"));
        }
        _ => {
            return Err(ApiError::bad_request(
                "only writes (create, update, delete) are asked for here: other actions ask through access",
            ));
        }
    }
    let reason = check_reason(&req.reason)?;
    let grant = load_grant(&state, &auth).await?;
    if let Some(item) = req.item_id {
        let item = granted_item(&state, &grant, item).await?;
        if item.vault_id != req.vault_id || item.project_id != req.project_id {
            return Err(ApiError::bad_request("the item is in another project"));
        }
    }
    let action = Action {
        permission: req.permission,
        vault: req.vault_id,
        project: req.project_id,
        item: req.item_id,
        claims: &req.claims,
        reason: &reason,
        attachments: &[],
        sandbox: None,
        local_client: None,
    };
    match checked(
        &state,
        &auth,
        &grant,
        &action,
        "agent.ask",
        None,
        req.task_id,
        true,
    )
    .await?
    {
        Gate::Pending(p) => Ok(Gate::pending_response(p)),
        Gate::Allow { approval, task } => Ok(Json(AgentAsked {
            approval_id: approval,
            task_id: task,
        })
        .into_response()),
    }
}

/// `?wait=` on [`approval_status`].
#[derive(Debug, Default, Deserialize)]
struct WaitQuery {
    /// Seconds to wait while the request is pending (at most
    /// [`MAX_APPROVAL_WAIT_SECS`]).
    #[serde(default)]
    wait: Option<u64>,
}

/// `GET /v1/agent/approvals/{approval_id}[?wait=N]`: the agent follows its
/// request. With `wait`, a long-poll (ADR 0015 §4): it answers as soon as
/// the request is decided or expires, or after `N` seconds.
async fn approval_status(
    State(state): State<AppState>,
    Path(approval_id): Path<String>,
    Query(query): Query<WaitQuery>,
    auth: AgentAuth,
) -> ApiResult<Json<ApprovalInfo>> {
    let id: ApprovalId = path_id(&approval_id)?;
    let wait = Duration::from_secs(query.wait.unwrap_or(0).min(MAX_APPROVAL_WAIT_SECS));
    let deadline = tokio::time::Instant::now() + wait;
    // Subscribe before reading, so a decision in between is not missed.
    let mut decided = state.subscribe_approvals();
    loop {
        let row = sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT {} FROM approvals WHERE id = $1 AND agent_id = $2",
            crate::routes::approvals::APPROVAL_COLUMNS
        )))
        .bind(id.to_string())
        .bind(auth.agent_id.to_string())
        .fetch_optional(&state.db().pool)
        .await?
        .ok_or(ApiError::NotFound)?;
        let now = now_ms();
        let info = approval_from_row(&row, now)?;
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        if info.status != ApprovalStatus::Pending || left.is_zero() {
            return Ok(Json(info));
        }
        // Wake up when it is decided here, when it expires, or to re-read.
        let until_expiry =
            Duration::from_millis(u64::try_from(info.expires_at - now).unwrap_or(0) + 1);
        let nap = WAIT_RECHECK.min(left).min(until_expiry);
        tokio::select! {
            () = decision_on(&mut decided, id) => {}
            () = tokio::time::sleep(nap) => {}
        }
    }
}

/// Returns when `id` is announced as decided (or announcements were lost).
async fn decision_on(rx: &mut broadcast::Receiver<ApprovalId>, id: ApprovalId) {
    loop {
        match rx.recv().await {
            Ok(decided) if decided == id => return,
            Ok(_) => {}
            Err(broadcast::error::RecvError::Lagged(_)) => return,
            Err(broadcast::error::RecvError::Closed) => std::future::pending::<()>().await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Keys without a sandbox are byte for byte what they were, so the
    /// pending and approved requests stored before this change still match
    /// the same calls; a sandbox makes its own key.
    #[test]
    fn a_sandbox_extends_the_key_and_nothing_else_changes() {
        let (vault, project, item) = (
            VaultId::generate(),
            ProjectId::generate(),
            ItemId::generate(),
        );
        let claims = Claims {
            tags: Vec::new(),
            domain: Some("Backboard.Railway.app".into()),
            method: Some("POST".into()),
            path: Some("/graphql".into()),
            ..Claims::default()
        };
        let action = |sandbox| Action {
            permission: Permission::Proxy,
            vault,
            project,
            item: Some(item),
            claims: &claims,
            reason: "",
            attachments: &[],
            sandbox,
            local_client: None,
        };
        let before = format!(
            r#"[3,"proxy","{vault}","{project}","{item}","backboard.railway.app","POST","/graphql"]"#
        );
        assert_eq!(target_key(3, &action(None)), before);
        let (a, b) = (
            klav_core::ids::SandboxId::generate(),
            klav_core::ids::SandboxId::generate(),
        );
        assert_eq!(
            target_key(3, &action(Some(a))),
            format!(r#"{},"{a}"]"#, before.trim_end_matches(']'))
        );
        assert_ne!(
            target_key(3, &action(Some(a))),
            target_key(3, &action(Some(b)))
        );
        // Without a method or path (every other permission), unchanged too.
        let plain = Claims::default();
        let list = Action {
            permission: Permission::List,
            claims: &plain,
            ..action(None)
        };
        assert_eq!(
            target_key(3, &list),
            format!(r#"[3,"list","{vault}","{project}","{item}",""]"#)
        );
    }

    /// ADR 0049 §5.4: keys without the gateway's fields are what they
    /// were; with them, one fixed-slot part after the sandbox. «Once» binds
    /// the arguments, a lease only the tool, and no caller's key serves
    /// another caller.
    #[test]
    fn mcp_keys_bind_the_tool_the_arguments_and_the_caller() {
        let (vault, project, item) = (
            VaultId::generate(),
            ProjectId::generate(),
            ItemId::generate(),
        );
        let digest = |b: u8| klav_core::crypto::mcp::digest_text(&[b; 32]);
        let claims = |tool: Option<&str>, args: Option<String>| Claims {
            domain: Some("api.maple.dev".into()),
            method: Some("POST".into()),
            path: Some("/mcp".into()),
            mcp_tool: tool.map(str::to_owned),
            mcp_args: args,
            ..Claims::default()
        };
        let key = |c: &Claims, sandbox, local_client| {
            let action = Action {
                permission: Permission::Proxy,
                vault,
                project,
                item: Some(item),
                claims: c,
                reason: "",
                attachments: &[],
                sandbox,
                local_client,
            };
            (target_key(7, &action), lease_key(7, &action))
        };
        let base =
            format!(r#"[7,"proxy","{vault}","{project}","{item}","api.maple.dev","POST","/mcp""#);
        // No tool, no client: as before, and no lease key.
        let session = claims(None, None);
        assert_eq!(key(&session, None, None), (format!("{base}]"), None));
        // A tool call.
        let a1 = claims(Some("deploy"), Some(digest(1)));
        let a2 = claims(Some("deploy"), Some(digest(2)));
        let (t1, l1) = key(&a1, None, None);
        let (t2, l2) = key(&a2, None, None);
        assert_eq!(
            t1,
            format!(r#"{base},["mcp","deploy","{}",""]]"#, digest(1))
        );
        assert_eq!(
            l1.as_deref(),
            Some(&*format!(r#"{base},["mcp","deploy","",""]]"#))
        );
        assert_ne!(t1, t2, "once binds the arguments");
        assert_eq!(l1, l2, "a lease covers any arguments of the tool");
        assert_ne!(
            key(&claims(Some("deploy2"), Some(digest(1))), None, None).1,
            l1
        );
        // Callers never share a key.
        let sandbox = klav_core::ids::SandboxId::generate();
        let by_sandbox = key(&a1, Some(sandbox), None);
        let by_client = key(&a1, None, Some("cursor"));
        let by_other = key(&a1, None, Some("claude-code"));
        let keys = [&t1, &by_sandbox.0, &by_client.0, &by_other.0];
        let leases = [&l1, &by_sandbox.1, &by_client.1, &by_other.1];
        for i in 0..4 {
            for j in 0..4 {
                if i != j {
                    assert_ne!(keys[i], keys[j]);
                    assert_ne!(leases[i], leases[j]);
                }
            }
            assert_ne!(Some(keys[i]), leases[i].as_ref());
        }
        assert!(by_sandbox.0.contains(&format!(r#""{sandbox}",["mcp""#)));
        // A local client without a tool (initialize, tools/list): its own
        // target key, no lease key.
        let (t, l) = key(&session, None, Some("cursor"));
        assert_eq!(t, format!(r#"{base},["mcp","","","cursor"]]"#));
        assert_eq!(l, None);
        // A sandbox ID spelled as a tool cannot collide: the gateway's part
        // is an array, never a string slot.
        let tool_like = claims(Some(&sandbox.to_string()), Some(digest(1)));
        assert_ne!(key(&tool_like, None, None).0, by_sandbox.0);
    }

    #[test]
    fn the_gateways_fields_are_checked_before_anything() {
        let ok = Claims {
            domain: Some("api.maple.dev".into()),
            method: Some("POST".into()),
            path: Some("/mcp".into()),
            mcp_tool: Some("query_logs".into()),
            mcp_args: Some(klav_core::crypto::mcp::digest_text(&[3; 32])),
            ..Claims::default()
        };
        let check = |c: &Claims, p, local: Option<&str>, sandbox| {
            check_mcp_claims(p, c, local, sandbox).is_ok()
        };
        assert!(check(&ok, Permission::Proxy, None, None));
        assert!(check(&ok, Permission::Proxy, Some("claude-code"), None));
        assert!(check(&Claims::default(), Permission::Inject, None, None));
        // Only proxy.
        assert!(!check(&ok, Permission::Inject, None, None));
        assert!(!check(
            &Claims::default(),
            Permission::Fill,
            Some("cursor"),
            None
        ));
        // Tool and arguments together.
        let alone = Claims {
            mcp_args: None,
            ..ok.clone()
        };
        assert!(!check(&alone, Permission::Proxy, None, None));
        let alone = Claims {
            mcp_tool: None,
            ..ok.clone()
        };
        assert!(!check(&alone, Permission::Proxy, None, None));
        // T260: the grammars.
        for tool in [
            "",
            "query logs",
            "q\u{202e}l",
            "quéry",
            "a\nb",
            &"a".repeat(129),
        ] {
            let bad = Claims {
                mcp_tool: Some(tool.into()),
                ..ok.clone()
            };
            assert!(!check(&bad, Permission::Proxy, None, None), "{tool:?}");
        }
        for name in ["", "Claude", "claude code", "a\u{202e}", &"a".repeat(33)] {
            assert!(!check(&ok, Permission::Proxy, Some(name), None), "{name:?}");
        }
        for args in ["", "abc", &"A".repeat(44), &format!("{}9", "_".repeat(42))] {
            let bad = Claims {
                mcp_args: Some(args.into()),
                ..ok.clone()
            };
            assert!(!check(&bad, Permission::Proxy, None, None), "{args:?}");
        }
        // One caller, and an endpoint-sized path.
        let sandbox = Some(klav_core::ids::SandboxId::generate());
        assert!(check(&ok, Permission::Proxy, None, sandbox));
        assert!(!check(&ok, Permission::Proxy, Some("cursor"), sandbox));
        let long = Claims {
            path: Some(format!("/{}", "a".repeat(64))),
            ..ok.clone()
        };
        assert!(!check(&long, Permission::Proxy, None, None));
        // `checked` runs the same check: a write never carries a tool.
        assert!(
            check_claims(
                Permission::Update,
                &Claims {
                    mcp_tool: Some("x".into()),
                    ..Claims::default()
                }
            )
            .is_err()
        );
    }
}
