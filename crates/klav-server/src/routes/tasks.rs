//! Task requests (ADR 0021): an agent asks for a set of items and
//! permissions at once (`POST /v1/agent/tasks`), the person approves one
//! signed card (`POST /v1/tasks/{id}/decide`) and the agent uses that set
//! of targets until the task expires or someone ends it.
//!
//! The server stores the agent's request body and the person's decision
//! verbatim (spec §13.8), checks the account's signature, and keeps one
//! `task_targets` row per approved `(item, permission)` with its hosts.
//! Every agent action re-checks the task on use ([`covering_task`]): it
//! must be approved, before `expires_at`, not ended, and the agent not
//! revoked (the agent extractor refuses revoked agents).

use std::time::Duration;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use klav_core::crypto::agent::{self as agent_crypto, TaskDecisionToSign};
use klav_core::crypto::sign::{SIGNATURE_LEN, Signature};
use klav_core::ids::{AccountId, AgentId, ItemId, ProjectId, TaskId, VaultId};
use klav_core::policy::Permission;
use klav_core::task::{TaskDecision, TaskRequest};
use klav_proto::Blob;
use klav_proto::agent::AgentStatus;
use klav_proto::audit::{ActorKind, AuditEvent};
use klav_proto::task::{
    AgentEndTask, DecideTask, EndTask, MAX_LIVE_TASKS, MAX_PENDING_TASKS, MAX_TASK_WAIT_SECS,
    OfferTask, PendingTask, TASK_DECIDE_TTL_MS, TaskEndedBy, TaskInfo, TaskList, TaskStatus,
};
use serde::Deserialize;
use sqlx::Row;
use sqlx::any::AnyRow;
use tokio::sync::broadcast;

use crate::agentauth::{AgentAuth, CLOCK_SKEW_MS, effective_status};
use crate::audit;
use crate::db::now_ms;
use crate::error::{ApiError, ApiJson, ApiResult};
use crate::push::PushKind;
use crate::routes::agent_access::{check_reason, grant_of, load_grant, permission_name};
use crate::routes::agents::account_identity;
use crate::session::{Auth, parse_id};
use crate::state::AppState;
use crate::vaultdb::{path_id, to_i64};

/// Tasks kept in a list.
const LIST_LIMIT: i64 = 100;
/// How often a long-poll on a task re-reads the database.
const WAIT_RECHECK: Duration = Duration::from_secs(2);

const TASK_COLUMNS: &str = "t.id, t.agent_id, a.name AS agent_name, t.status, t.request, \
     t.created_at, t.decide_by, t.decided_at, t.decision, t.signature, t.revision, t.expires_at, \
     t.ended_at, t.ended_by";

pub(super) fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/agent/tasks", get(agent_list).post(request))
        .route("/v1/agent/tasks/{task_id}", get(agent_get))
        .route("/v1/agent/tasks/{task_id}/end", post(agent_end))
        .route("/v1/tasks", get(list).post(offer))
        .route("/v1/tasks/{task_id}", get(get_one))
        .route("/v1/tasks/{task_id}/decide", post(decide))
        .route("/v1/tasks/{task_id}/end", post(end))
}

/// What a task row covers (ADR 0021 §4): the approvals' target (ADR 0015
/// §1) without the domain (a task approves a list of hosts) and without
/// the grant version (a task re-evaluates the current grant on every use).
pub(crate) fn task_target_key(
    permission: Permission,
    vault: VaultId,
    project: ProjectId,
    item: ItemId,
) -> String {
    serde_json::json!([
        permission_name(permission),
        vault.to_string(),
        project.to_string(),
        item.to_string(),
    ])
    .to_string()
}

fn parse_status(text: &str) -> ApiResult<TaskStatus> {
    TaskStatus::parse(text).ok_or_else(|| ApiError::Internal("corrupt task status".into()))
}

/// A task as the API shows it: a pending request past `decide_by` reads as
/// expired, an approved task past `expires_at` as ended by expiry.
fn task_from_row(row: &AnyRow, now: i64) -> ApiResult<TaskInfo> {
    let decide_by: i64 = row.try_get("decide_by")?;
    let expires_at: Option<i64> = row.try_get("expires_at")?;
    let mut status = parse_status(&row.try_get::<String, _>("status")?)?;
    let mut ended_at: Option<i64> = row.try_get("ended_at")?;
    let mut ended_by = row
        .try_get::<Option<String>, _>("ended_by")?
        .map(|t| {
            TaskEndedBy::parse(&t).ok_or_else(|| ApiError::Internal("corrupt task end".into()))
        })
        .transpose()?;
    match status {
        TaskStatus::Pending if decide_by <= now => status = TaskStatus::Expired,
        TaskStatus::Approved if expires_at.is_some_and(|e| e <= now) => {
            status = TaskStatus::Ended;
            ended_at = expires_at;
            ended_by = Some(TaskEndedBy::Expiry);
        }
        _ => {}
    }
    Ok(TaskInfo {
        id: parse_id(&row.try_get::<String, _>("id")?)?,
        agent_id: parse_id(&row.try_get::<String, _>("agent_id")?)?,
        agent_name: row.try_get("agent_name")?,
        status,
        request: Blob::new(row.try_get::<Vec<u8>, _>("request")?),
        created_at: row.try_get("created_at")?,
        decide_by,
        decided_at: row.try_get("decided_at")?,
        decision: row
            .try_get::<Option<Vec<u8>>, _>("decision")?
            .map(Blob::new),
        signature: row
            .try_get::<Option<Vec<u8>>, _>("signature")?
            .map(Blob::new),
        revision: crate::vaultdb::to_u64(row.try_get("revision")?),
        expires_at,
        ended_at,
        ended_by,
    })
}

/// Which tasks [`sweep`] looks at.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Sweep {
    /// Every account (the periodic clean-up).
    All,
    /// One account.
    Account(AccountId),
    /// One agent.
    Agent(AgentId),
}

/// Ends the approved tasks past their `expires_at` and logs `task.ended`
/// (by `expiry`) the first time the server notices (ADR 0021 §9); marks
/// pending requests past `decide_by` as expired. Returns the tasks ended.
///
/// Each account is ended in a transaction of its own. With [`Sweep::All`]
/// (the periodic purge), an account that fails is logged and skipped, so
/// it never stops the others; a scoped sweep fails its request.
pub(crate) async fn sweep(state: &AppState, scope: Sweep, now: i64) -> ApiResult<u64> {
    let (filter, value) = match scope {
        Sweep::All => ("", None),
        Sweep::Account(a) => (" AND account_id = $3", Some(a.to_string())),
        Sweep::Agent(a) => (" AND agent_id = $3", Some(a.to_string())),
    };
    let mut expire = sqlx::query(sqlx::AssertSqlSafe(format!(
        "UPDATE tasks SET status = $1 WHERE status = 'pending' AND decide_by <= $2{filter}"
    )))
    .bind(TaskStatus::Expired.as_str())
    .bind(now);
    if let Some(v) = &value {
        expire = expire.bind(v.clone());
    }
    expire.execute(&state.db().pool).await?;
    // The accounts with a task to end: each is ended in a transaction of
    // its own, under that account's lock.
    let mut select = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
        "SELECT DISTINCT account_id FROM tasks WHERE status = $1 AND expires_at <= $2{filter}"
    )))
    .bind(TaskStatus::Approved.as_str())
    .bind(now);
    if let Some(v) = &value {
        select = select.bind(v.clone());
    }
    let accounts: Vec<String> = select.fetch_all(&state.db().pool).await?;
    let mut ended = 0;
    for account in accounts {
        let result = match parse_id::<AccountId>(&account) {
            Ok(id) => end_expired(state, id, scope, now).await,
            Err(e) => Err(e),
        };
        match result {
            Ok(n) => ended += n,
            // The periodic sweep goes on with the other accounts, as the
            // account deletions do: this one's tasks stay approved (read
            // as ended) until a run logs them. A request's sweep fails it.
            Err(e) if matches!(scope, Sweep::All) => tracing::error!(
                account = %account,
                error = ?e,
                "ending expired tasks failed; the next sweep tries again"
            ),
            Err(e) => return Err(e),
        }
    }
    Ok(ended)
}

/// Ends `account`'s approved tasks in `scope` past their `expires_at`, and
/// logs each one's `task.ended` (by `expiry`) in the same transaction,
/// under the account's lock first as every transaction that logs in itself
/// takes it. One `UPDATE … RETURNING`: only the tasks it ended are logged,
/// never one that another sweep, a revocation or an end ended meanwhile.
async fn end_expired(
    state: &AppState,
    account: AccountId,
    scope: Sweep,
    now: i64,
) -> ApiResult<u64> {
    let agent = match scope {
        Sweep::Agent(a) => Some(a.to_string()),
        Sweep::All | Sweep::Account(_) => None,
    };
    let filter = if agent.is_some() {
        " AND agent_id = $6"
    } else {
        ""
    };
    let mut tx = state.db().pool.begin().await?;
    crate::deletion::lock_account(&mut tx, account).await?;
    let mut update = sqlx::query(sqlx::AssertSqlSafe(format!(
        "UPDATE tasks SET status = $1, ended_at = expires_at, ended_by = $2 \
         WHERE account_id = $3 AND status = $4 AND expires_at <= $5{filter} \
         RETURNING id, agent_id, expires_at"
    )))
    .bind(TaskStatus::Ended.as_str())
    .bind(TaskEndedBy::Expiry.as_str())
    .bind(account.to_string())
    .bind(TaskStatus::Approved.as_str())
    .bind(now);
    if let Some(a) = agent {
        update = update.bind(a);
    }
    let mut rows = Vec::new();
    for row in update.fetch_all(&mut *tx).await? {
        let task: TaskId = parse_id(&row.try_get::<String, _>("id")?)?;
        let agent: AgentId = parse_id(&row.try_get::<String, _>("agent_id")?)?;
        rows.push((row.try_get::<i64, _>("expires_at")?, task, agent));
    }
    // Logged in the order the tasks expired.
    rows.sort_by_key(|(expires_at, task, _)| (*expires_at, task.to_string()));
    for (expires_at, task, agent) in &rows {
        // Nobody acted: the server attests that it saw the expiry.
        let mut event = AuditEvent::new(ActorKind::Agent, "task.ended");
        event.agent_id = Some(*agent);
        event.task_id = Some(*task);
        event.outcome = Some(TaskEndedBy::Expiry.as_str().to_owned());
        event.decided_at = Some(*expires_at);
        // Stamped when it is logged, as `audit::append` does. No `alerts`:
        // they are only for an agent's access events.
        audit::append_in(&mut tx, account, &mut event, now_ms()).await?;
    }
    tx.commit().await?;
    for (_, task, _) in &rows {
        state.task_changed(*task);
    }
    Ok(u64::try_from(rows.len()).unwrap_or(u64::MAX))
}

/// The live task of this agent that lets `permission` on `item` through on
/// `domain`, if any (ADR 0021 §4–5): approved, before `expires_at`, not
/// ended, with a target row for the item and permission, and a signed
/// decision that covers the host. With `only`, just that task.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn covering_task(
    state: &AppState,
    agent: AgentId,
    permission: Permission,
    vault: VaultId,
    project: ProjectId,
    item: ItemId,
    domain: Option<&str>,
    only: Option<TaskId>,
) -> ApiResult<Option<TaskId>> {
    let now = now_ms();
    sweep(state, Sweep::Agent(agent), now).await?;
    let rows = sqlx::query(
        "SELECT t.id, t.decision FROM tasks t JOIN task_targets tt ON tt.task_id = t.id \
         WHERE t.agent_id = $1 AND t.status = $2 AND t.expires_at > $3 AND tt.target_key = $4 \
         ORDER BY t.expires_at, t.id",
    )
    .bind(agent.to_string())
    .bind(TaskStatus::Approved.as_str())
    .bind(now)
    .bind(task_target_key(permission, vault, project, item))
    .fetch_all(&state.db().pool)
    .await?;
    for row in rows {
        let id: TaskId = parse_id(&row.try_get::<String, _>("id")?)?;
        if only.is_some_and(|wanted| wanted != id) {
            continue;
        }
        let Some(bytes) = row.try_get::<Option<Vec<u8>>, _>("decision")? else {
            continue;
        };
        let decision: TaskDecision = serde_json::from_slice(&bytes)
            .map_err(|_| ApiError::Internal("corrupt task decision".into()))?;
        if decision.covers(vault, project, item, permission, domain) {
            return Ok(Some(id));
        }
    }
    Ok(None)
}

/// Ends every live task of a revoked agent (`ended_by = revocation`) and
/// denies its pending requests, inside the revocation's transaction.
/// Returns the tasks ended, for the caller to log in that transaction
/// ([`log_revocation_ends`]): exactly the rows this update changed
/// (`RETURNING`). The expiry sweep now takes the account lock first too,
/// but an older instance's sweep, during a deploy, does not: a task read
/// as approved first could be ended meanwhile by it, and would get a
/// second `task.ended`.
pub(crate) async fn end_on_revocation(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    agent: AgentId,
    now: i64,
) -> ApiResult<Vec<TaskId>> {
    let ids: Vec<String> = sqlx::query_scalar(
        "UPDATE tasks SET status = $1, ended_at = $2, ended_by = $3 \
         WHERE agent_id = $4 AND status = $5 RETURNING id",
    )
    .bind(TaskStatus::Ended.as_str())
    .bind(now)
    .bind(TaskEndedBy::Revocation.as_str())
    .bind(agent.to_string())
    .bind(TaskStatus::Approved.as_str())
    .fetch_all(&mut **tx)
    .await?;
    sqlx::query(
        "UPDATE tasks SET status = $1, decided_at = $2 WHERE agent_id = $3 AND status = $4",
    )
    .bind(TaskStatus::Denied.as_str())
    .bind(now)
    .bind(agent.to_string())
    .bind(TaskStatus::Pending.as_str())
    .execute(&mut **tx)
    .await?;
    ids.iter().map(|id| parse_id(id)).collect()
}

/// Logs `task.ended` by revocation inside `tx` (the revocation's own
/// transaction, which the caller commits) for the tasks
/// [`end_on_revocation`] ended. The caller wakes their long-polls after
/// the commit.
pub(crate) async fn log_revocation_ends(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    auth: &Auth,
    agent: AgentId,
    tasks: &[TaskId],
    at: i64,
) -> ApiResult<()> {
    for task in tasks {
        let mut event = AuditEvent::new(ActorKind::Person, "task.ended");
        event.device_id = Some(auth.device_id);
        event.agent_id = Some(agent);
        event.task_id = Some(*task);
        event.outcome = Some(TaskEndedBy::Revocation.as_str().to_owned());
        event.decided_at = Some(at);
        audit::append_in(tx, auth.account_id, &mut event, now_ms()).await?;
    }
    Ok(())
}

/// Takes the agent's row lock inside `tx`, so that a count and the write
/// that depends on it happen as one step: concurrent requests of the same
/// agent wait for each other instead of all passing a cap they share
/// (Postgres: the row lock; SQLite: the write lock). Also used by the
/// approval requests ([`crate::routes::agent_access`]).
pub(crate) async fn lock_agent(conn: &mut sqlx::AnyConnection, agent: AgentId) -> ApiResult<()> {
    sqlx::query("UPDATE agents SET status = status WHERE id = $1")
        .bind(agent.to_string())
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// The agent's tasks in `status`, counted inside the caller's transaction
/// (after [`lock_agent`]).
async fn count(
    conn: &mut sqlx::AnyConnection,
    agent: AgentId,
    status: TaskStatus,
    now: i64,
) -> ApiResult<i64> {
    let column = match status {
        TaskStatus::Pending => "decide_by",
        _ => "expires_at",
    };
    Ok(sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
        "SELECT COUNT(*) FROM tasks WHERE agent_id = $1 AND status = $2 AND {column} > $3"
    )))
    .bind(agent.to_string())
    .bind(status.as_str())
    .bind(now)
    .fetch_one(&mut *conn)
    .await?)
}

// ---------------------------------------------------------------- agent --

/// `POST /v1/agent/tasks`: the agent's request, stored verbatim.
async fn request(
    State(state): State<AppState>,
    auth: AgentAuth,
) -> ApiResult<(StatusCode, Json<PendingTask>)> {
    let req: TaskRequest = auth.logged_json()?;
    req.validate()
        .map_err(|e| ApiError::bad_request(e.to_string()))?;
    let grant = load_grant(&state, &auth).await?;
    for access in &req.access {
        if grant.projects.get(&access.project_id) != Some(&access.vault_id) {
            return Err(ApiError::bad_request(format!(
                "project {} is not in the agent's grant",
                access.project_id
            )));
        }
        let found: Option<String> = sqlx::query_scalar(
            "SELECT id FROM items WHERE id = $1 AND vault_id = $2 AND project_id = $3 \
             AND purged_at IS NULL AND trashed_at IS NULL \
             AND vault_id IN (SELECT id FROM vaults WHERE deleted_at IS NULL)",
        )
        .bind(access.item_id.to_string())
        .bind(access.vault_id.to_string())
        .bind(access.project_id.to_string())
        .fetch_optional(&state.db().pool)
        .await?;
        if found.is_none() {
            return Err(ApiError::bad_request(format!(
                "item {} is not in project {}",
                access.item_id, access.project_id
            )));
        }
    }
    let now = now_ms();
    sweep(&state, Sweep::Agent(auth.agent_id), now).await?;
    // Count and insert as one step (layer 06 of the 2026-11 round): two
    // requests at once cannot both take the last free place. The account's
    // lock first, as every transaction that logs in itself takes it.
    let mut tx = state.db().pool.begin().await?;
    crate::deletion::lock_account(&mut tx, auth.account_id).await?;
    lock_agent(&mut tx, auth.agent_id).await?;
    if count(&mut tx, auth.agent_id, TaskStatus::Pending, now).await? >= MAX_PENDING_TASKS
        || count(&mut tx, auth.agent_id, TaskStatus::Approved, now).await? >= MAX_LIVE_TASKS
    {
        return Err(ApiError::TooManyRequests {
            retry_after_secs: 60,
        });
    }
    let id = TaskId::generate();
    let decide_by = now + TASK_DECIDE_TTL_MS;
    sqlx::query(
        "INSERT INTO tasks (id, account_id, agent_id, status, request, created_at, decide_by) \
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(id.to_string())
    .bind(auth.account_id.to_string())
    .bind(auth.agent_id.to_string())
    .bind(TaskStatus::Pending.as_str())
    .bind(auth.body.to_vec())
    .bind(now)
    .bind(decide_by)
    .execute(&mut *tx)
    .await?;
    // Logged in the task's own transaction: a request the log refuses (its
    // signed time out of the window by now) leaves no task behind.
    let mut event = AuditEvent::new(ActorKind::Agent, "task.requested");
    event.agent_id = Some(auth.agent_id);
    event.task_id = Some(id);
    event.reason = Some(req.reason.trim().to_owned());
    event.agent_proof = Some(auth.proof.clone());
    // Stamped when it is logged, as `audit::append` does.
    audit::append_in(&mut tx, auth.account_id, &mut event, now_ms()).await?;
    tx.commit().await?;
    // Only the kind and the ID: no title, reason or agent name (T75).
    state.push(auth.account_id, PushKind::Task, id.to_string());
    Ok((
        StatusCode::ACCEPTED,
        Json(PendingTask {
            pending_task_id: id,
            expires_at: decide_by,
        }),
    ))
}

async fn fetch_for_agent(state: &AppState, agent: AgentId, id: TaskId) -> ApiResult<AnyRow> {
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT {TASK_COLUMNS} FROM tasks t JOIN agents a ON a.id = t.agent_id \
         WHERE t.id = $1 AND t.agent_id = $2"
    )))
    .bind(id.to_string())
    .bind(agent.to_string())
    .fetch_optional(&state.db().pool)
    .await?
    .ok_or(ApiError::NotFound)
}

/// One of `agent`'s tasks as the API shows it.
pub(crate) async fn agent_task_info(
    state: &AppState,
    agent: AgentId,
    id: TaskId,
) -> ApiResult<TaskInfo> {
    task_from_row(&fetch_for_agent(state, agent, id).await?, now_ms())
}

/// `GET /v1/agent/tasks`: the agent's tasks, newest first.
async fn agent_list(State(state): State<AppState>, auth: AgentAuth) -> ApiResult<Json<TaskList>> {
    let now = now_ms();
    sweep(&state, Sweep::Agent(auth.agent_id), now).await?;
    let rows = sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT {TASK_COLUMNS} FROM tasks t JOIN agents a ON a.id = t.agent_id \
         WHERE t.agent_id = $1 ORDER BY t.created_at DESC LIMIT {LIST_LIMIT}"
    )))
    .bind(auth.agent_id.to_string())
    .fetch_all(&state.db().pool)
    .await?;
    Ok(Json(TaskList {
        tasks: rows
            .iter()
            .map(|r| task_from_row(r, now))
            .collect::<ApiResult<_>>()?,
    }))
}

/// `?wait=` on [`agent_get`].
#[derive(Debug, Default, Deserialize)]
struct WaitQuery {
    #[serde(default)]
    wait: Option<u64>,
}

/// `GET /v1/agent/tasks/{id}[?wait=N]`: with `wait`, a long-poll like the
/// approvals' (ADR 0015 §4): it answers as soon as the request is decided
/// or expires, or after `N` seconds (at most 30).
async fn agent_get(
    State(state): State<AppState>,
    Path(task_id): Path<String>,
    Query(query): Query<WaitQuery>,
    auth: AgentAuth,
) -> ApiResult<Json<TaskInfo>> {
    let id: TaskId = path_id(&task_id)?;
    let wait = Duration::from_secs(query.wait.unwrap_or(0).min(MAX_TASK_WAIT_SECS));
    let deadline = tokio::time::Instant::now() + wait;
    // Subscribe before reading, so a decision in between is not missed.
    let mut changed = state.subscribe_tasks();
    loop {
        let now = now_ms();
        sweep(&state, Sweep::Agent(auth.agent_id), now).await?;
        let info = task_from_row(&fetch_for_agent(&state, auth.agent_id, id).await?, now)?;
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        if info.status != TaskStatus::Pending || left.is_zero() {
            return Ok(Json(info));
        }
        let until_expiry =
            Duration::from_millis(u64::try_from(info.decide_by - now).unwrap_or(0) + 1);
        let nap = WAIT_RECHECK.min(left).min(until_expiry);
        tokio::select! {
            () = change_on(&mut changed, id) => {}
            () = tokio::time::sleep(nap) => {}
        }
    }
}

/// Returns when `id` is announced as changed (or announcements were lost).
async fn change_on(rx: &mut broadcast::Receiver<TaskId>, id: TaskId) {
    loop {
        match rx.recv().await {
            Ok(changed) if changed == id => return,
            Ok(_) => {}
            Err(broadcast::error::RecvError::Lagged(_)) => return,
            Err(broadcast::error::RecvError::Closed) => std::future::pending::<()>().await,
        }
    }
}

/// `POST /v1/agent/tasks/{id}/end`: the agent finished (or withdraws a
/// pending request).
async fn agent_end(
    State(state): State<AppState>,
    Path(task_id): Path<String>,
    auth: AgentAuth,
) -> ApiResult<Json<TaskInfo>> {
    let id: TaskId = path_id(&task_id)?;
    let req: AgentEndTask = auth.logged_json()?;
    let reason = check_reason(&req.reason)?;
    let now = now_ms();
    sweep(&state, Sweep::Agent(auth.agent_id), now).await?;
    let info = task_from_row(&fetch_for_agent(&state, auth.agent_id, id).await?, now)?;
    if !matches!(info.status, TaskStatus::Approved | TaskStatus::Pending) {
        return Err(ApiError::conflict(format!(
            "the task is already {}",
            info.status.as_str()
        )));
    }
    // The end and its event in one transaction, under the account's lock:
    // an end the log refuses (its signed time out of the window by now)
    // leaves the task as it was.
    let mut tx = state.db().pool.begin().await?;
    crate::deletion::lock_account(&mut tx, auth.account_id).await?;
    let updated = sqlx::query(
        "UPDATE tasks SET status = $1, ended_at = $2, ended_by = $3 \
         WHERE id = $4 AND status = $5",
    )
    .bind(TaskStatus::Ended.as_str())
    .bind(now)
    .bind(TaskEndedBy::Agent.as_str())
    .bind(id.to_string())
    .bind(info.status.as_str())
    .execute(&mut *tx)
    .await?;
    if updated.rows_affected() != 1 {
        return Err(ApiError::conflict("the task changed meanwhile: try again"));
    }
    let mut event = AuditEvent::new(ActorKind::Agent, "task.ended");
    event.agent_id = Some(auth.agent_id);
    event.task_id = Some(id);
    event.outcome = Some(TaskEndedBy::Agent.as_str().to_owned());
    event.reason = Some(reason);
    event.decided_at = Some(now);
    event.agent_proof = Some(auth.proof.clone());
    // Stamped when it is logged, as `audit::append` does.
    audit::append_in(&mut tx, auth.account_id, &mut event, now_ms()).await?;
    tx.commit().await?;
    state.task_changed(id);
    task_from_row(&fetch_for_agent(&state, auth.agent_id, id).await?, now_ms()).map(Json)
}

// --------------------------------------------------------------- person --

async fn fetch(state: &AppState, account: AccountId, id: TaskId) -> ApiResult<AnyRow> {
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT {TASK_COLUMNS} FROM tasks t JOIN agents a ON a.id = t.agent_id \
         WHERE t.id = $1 AND t.account_id = $2"
    )))
    .bind(id.to_string())
    .bind(account.to_string())
    .fetch_optional(&state.db().pool)
    .await?
    .ok_or(ApiError::NotFound)
}

/// `GET /v1/tasks`: the account's tasks, newest first.
async fn list(State(state): State<AppState>, auth: Auth) -> ApiResult<Json<TaskList>> {
    let now = now_ms();
    sweep(&state, Sweep::Account(auth.account_id), now).await?;
    let rows = sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT {TASK_COLUMNS} FROM tasks t JOIN agents a ON a.id = t.agent_id \
         WHERE t.account_id = $1 ORDER BY t.created_at DESC LIMIT {LIST_LIMIT}"
    )))
    .bind(auth.account_id.to_string())
    .fetch_all(&state.db().pool)
    .await?;
    Ok(Json(TaskList {
        tasks: rows
            .iter()
            .map(|r| task_from_row(r, now))
            .collect::<ApiResult<_>>()?,
    }))
}

async fn get_one(
    State(state): State<AppState>,
    auth: Auth,
    Path(task_id): Path<String>,
) -> ApiResult<Json<TaskInfo>> {
    let now = now_ms();
    sweep(&state, Sweep::Account(auth.account_id), now).await?;
    task_from_row(
        &fetch(&state, auth.account_id, path_id(&task_id)?).await?,
        now,
    )
    .map(Json)
}

fn signature(blob: &Blob) -> ApiResult<Signature> {
    let bytes: [u8; SIGNATURE_LEN] = blob
        .as_bytes()
        .try_into()
        .map_err(|_| ApiError::bad_request("signature: expected 64 bytes"))?;
    Ok(Signature::from_bytes(bytes))
}

/// Inserts the target rows of an approved decision (replacing any).
async fn write_targets(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    task: TaskId,
    decision: &TaskDecision,
) -> ApiResult<()> {
    sqlx::query("DELETE FROM task_targets WHERE task_id = $1")
        .bind(task.to_string())
        .execute(&mut **tx)
        .await?;
    for access in &decision.access {
        let hosts = serde_json::to_string(&access.domains)
            .map_err(|e| ApiError::Internal(format!("hosts: {e}")))?;
        for permission in &access.permissions {
            sqlx::query(
                "INSERT INTO task_targets (task_id, target_key, hosts) VALUES ($1, $2, $3)",
            )
            .bind(task.to_string())
            .bind(task_target_key(
                *permission,
                access.vault_id,
                access.project_id,
                access.item_id,
            ))
            .bind(&hosts)
            .execute(&mut **tx)
            .await?;
        }
    }
    Ok(())
}

/// `POST /v1/tasks`: the person offers an agent a task without a request
/// (ADR 0022 §6, «Fix my reused passwords»). The decision is signed over
/// an empty request and carries the person's title and reason (`offer`);
/// the task is approved from the start and the agent finds it with
/// `GET /v1/agent/tasks`. Same checks as approving a request: an active
/// agent of this account, items alive in projects of its grant, at most
/// [`MAX_LIVE_TASKS`] running, the clock and the signature.
async fn offer(
    State(state): State<AppState>,
    auth: Auth,
    ApiJson(req): ApiJson<OfferTask>,
) -> ApiResult<(StatusCode, Json<TaskInfo>)> {
    let now = now_ms();
    if (req.decided_at - now).abs() > CLOCK_SKEW_MS {
        return Err(ApiError::bad_request(
            "decided_at is too far from the server's clock",
        ));
    }
    let decided_at_ms =
        u64::try_from(req.decided_at).map_err(|_| ApiError::bad_request("decided_at"))?;
    let decision: TaskDecision = serde_json::from_slice(req.decision.as_bytes())
        .map_err(|e| ApiError::bad_request(format!("decision: {e}")))?;
    decision
        .validate(true)
        .and_then(|()| decision.check_offered(decided_at_ms))
        .map_err(|e| ApiError::bad_request(e.to_string()))?;
    if decision.task_id != req.task_id || decision.agent_id != req.agent_id {
        return Err(ApiError::bad_request(
            "the decision is for another task or agent",
        ));
    }
    let agent =
        sqlx::query("SELECT status, expires_at FROM agents WHERE id = $1 AND account_id = $2")
            .bind(req.agent_id.to_string())
            .bind(auth.account_id.to_string())
            .fetch_optional(&state.db().pool)
            .await?
            .ok_or(ApiError::NotFound)?;
    if effective_status(
        &agent.try_get::<String, _>("status")?,
        agent.try_get("expires_at")?,
        now,
    )? != AgentStatus::Active
    {
        return Err(ApiError::conflict("the agent is no longer active"));
    }
    let grant = grant_of(&state, req.agent_id).await.map_err(|e| match e {
        ApiError::Forbidden => ApiError::conflict("the agent has no grant yet"),
        other => other,
    })?;
    for access in &decision.access {
        if grant.projects.get(&access.project_id) != Some(&access.vault_id) {
            return Err(ApiError::bad_request(format!(
                "project {} is not in the agent's grant",
                access.project_id
            )));
        }
        // A deleted vault is out of reach until restored (layer 07).
        let found: Option<String> = sqlx::query_scalar(
            "SELECT id FROM items WHERE id = $1 AND vault_id = $2 AND project_id = $3 \
             AND purged_at IS NULL AND trashed_at IS NULL \
             AND vault_id IN (SELECT id FROM vaults WHERE deleted_at IS NULL)",
        )
        .bind(access.item_id.to_string())
        .bind(access.vault_id.to_string())
        .bind(access.project_id.to_string())
        .fetch_optional(&state.db().pool)
        .await?;
        if found.is_none() {
            return Err(ApiError::bad_request(format!(
                "item {} is not in project {}",
                access.item_id, access.project_id
            )));
        }
    }
    sweep(&state, Sweep::Agent(req.agent_id), now).await?;
    let sig = signature(&req.signature)?;
    agent_crypto::verify_task_decision(
        &account_identity(&state, auth.account_id).await?,
        &TaskDecisionToSign {
            task: req.task_id,
            agent: req.agent_id,
            request: &[],
            decision: req.decision.as_bytes(),
            approve: true,
            decided_at_ms,
        },
        &sig,
    )
    .map_err(|_| ApiError::bad_request("the decision's signature does not verify"))?;

    let id = req.task_id;
    let mut tx = state.db().pool.begin().await?;
    // The account's lock first, as every write that logs in its own
    // transaction takes it: then the agent's.
    crate::deletion::lock_account(&mut tx, auth.account_id).await?;
    // The cap on running tasks is counted under the agent's lock, in the
    // transaction that inserts the offer (layer 06 of the 2026-11 round).
    lock_agent(&mut tx, req.agent_id).await?;
    if count(&mut tx, req.agent_id, TaskStatus::Approved, now).await? >= MAX_LIVE_TASKS {
        return Err(ApiError::conflict(
            "the agent already has 10 running tasks: end one first",
        ));
    }
    let inserted = sqlx::query(
        "INSERT INTO tasks (id, account_id, agent_id, status, request, created_at, decide_by, \
         decided_at, decision, signature, revision, expires_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
    )
    .bind(id.to_string())
    .bind(auth.account_id.to_string())
    .bind(req.agent_id.to_string())
    .bind(TaskStatus::Approved.as_str())
    .bind(Vec::<u8>::new())
    .bind(now)
    .bind(now)
    .bind(req.decided_at)
    .bind(req.decision.as_bytes().to_vec())
    .bind(req.signature.as_bytes().to_vec())
    .bind(to_i64(decision.revision)?)
    .bind(to_i64(decision.expires_at_ms)?)
    .execute(&mut *tx)
    .await;
    match inserted {
        Ok(_) => {}
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
            return Err(ApiError::conflict("a task with this ID already exists"));
        }
        Err(e) => return Err(e.into()),
    }
    write_targets(&mut tx, id, &decision).await?;
    // Logged in the offer's own transaction: a client that goes away
    // never leaves the task without its `task.decided`.
    let mut event = AuditEvent::new(ActorKind::Person, "task.decided");
    event.device_id = Some(auth.device_id);
    event.agent_id = Some(req.agent_id);
    event.task_id = Some(id);
    event.outcome = Some("approve".to_owned());
    event.decided_at = Some(req.decided_at);
    event.signed = Some(req.decision.clone());
    event.task_request = Some(Blob::new(Vec::new()));
    event.account_signature = Some(req.signature.clone());
    // Stamped when it is logged, as `audit::append` does.
    audit::append_in(&mut tx, auth.account_id, &mut event, now_ms()).await?;
    tx.commit().await?;
    state.task_changed(id);
    Ok((
        StatusCode::CREATED,
        Json(task_from_row(
            &fetch(&state, auth.account_id, id).await?,
            now_ms(),
        )?),
    ))
}

/// `POST /v1/tasks/{id}/decide`: the person's signed decision on a pending
/// request, or a revision of a live task («Add to the task», ADR 0021 §6:
/// the next revision only, same expiry, nothing removed).
async fn decide(
    State(state): State<AppState>,
    auth: Auth,
    Path(task_id): Path<String>,
    ApiJson(req): ApiJson<DecideTask>,
) -> ApiResult<Json<TaskInfo>> {
    let id: TaskId = path_id(&task_id)?;
    let now = now_ms();
    sweep(&state, Sweep::Account(auth.account_id), now).await?;
    let info = task_from_row(&fetch(&state, auth.account_id, id).await?, now)?;
    if (req.decided_at - now).abs() > CLOCK_SKEW_MS {
        return Err(ApiError::bad_request(
            "decided_at is too far from the server's clock",
        ));
    }
    let decided_at_ms =
        u64::try_from(req.decided_at).map_err(|_| ApiError::bad_request("decided_at"))?;
    let decision: TaskDecision = serde_json::from_slice(req.decision.as_bytes())
        .map_err(|e| ApiError::bad_request(format!("decision: {e}")))?;
    decision
        .validate(req.approve)
        .map_err(|e| ApiError::bad_request(e.to_string()))?;
    if decision.task_id != id || decision.agent_id != info.agent_id {
        return Err(ApiError::bad_request(
            "the decision is for another task or agent",
        ));
    }
    let previous = match info.status {
        TaskStatus::Pending => {
            // Only a request from an agent is pending: an offered task
            // (empty request) is approved from the start.
            let request: TaskRequest = serde_json::from_slice(info.request.as_bytes())
                .map_err(|_| ApiError::Internal("corrupt task request".into()))?;
            if req.approve {
                decision
                    .check_first(&request, decided_at_ms)
                    .map_err(|e| ApiError::bad_request(e.to_string()))?;
            }
            None
        }
        TaskStatus::Approved => {
            if !req.approve {
                return Err(ApiError::conflict(
                    "the task is running: end it instead of denying it",
                ));
            }
            let bytes = info
                .decision
                .as_ref()
                .ok_or_else(|| ApiError::Internal("approved task without decision".into()))?;
            let previous: TaskDecision = serde_json::from_slice(bytes.as_bytes())
                .map_err(|_| ApiError::Internal("corrupt task decision".into()))?;
            decision.check_extends(&previous).map_err(|e| {
                if previous.revision.checked_add(1) == Some(decision.revision) {
                    ApiError::bad_request(e.to_string())
                } else {
                    ApiError::conflict(e.to_string())
                }
            })?;
            Some(previous)
        }
        other => {
            return Err(ApiError::conflict(format!(
                "the task is already {}",
                other.as_str()
            )));
        }
    };
    // The agent must still be active.
    let agent = sqlx::query("SELECT status, expires_at FROM agents WHERE id = $1")
        .bind(info.agent_id.to_string())
        .fetch_one(&state.db().pool)
        .await?;
    if effective_status(
        &agent.try_get::<String, _>("status")?,
        agent.try_get("expires_at")?,
        now,
    )? != AgentStatus::Active
    {
        return Err(ApiError::conflict("the agent is no longer active"));
    }
    let sig = signature(&req.signature)?;
    agent_crypto::verify_task_decision(
        &account_identity(&state, auth.account_id).await?,
        &TaskDecisionToSign {
            task: id,
            agent: info.agent_id,
            request: info.request.as_bytes(),
            decision: req.decision.as_bytes(),
            approve: req.approve,
            decided_at_ms,
        },
        &sig,
    )
    .map_err(|_| ApiError::bad_request("the decision's signature does not verify"))?;

    let mut tx = state.db().pool.begin().await?;
    // The account's lock first, as every write that logs in its own
    // transaction takes it: then the agent's.
    crate::deletion::lock_account(&mut tx, auth.account_id).await?;
    // The cap on running tasks is counted under the agent's lock, in the
    // transaction that approves (layer 06 of the 2026-11 round).
    lock_agent(&mut tx, info.agent_id).await?;
    if req.approve
        && previous.is_none()
        && count(&mut tx, info.agent_id, TaskStatus::Approved, now).await? >= MAX_LIVE_TASKS
    {
        return Err(ApiError::conflict(
            "the agent already has 10 running tasks: end one first",
        ));
    }
    let updated = if let Some(previous) = &previous {
        sqlx::query(
            "UPDATE tasks SET decided_at = $1, decision = $2, signature = $3, revision = $4 \
             WHERE id = $5 AND status = $6 AND revision = $7 AND expires_at > $8",
        )
        .bind(req.decided_at)
        .bind(req.decision.as_bytes().to_vec())
        .bind(req.signature.as_bytes().to_vec())
        .bind(to_i64(decision.revision)?)
        .bind(id.to_string())
        .bind(TaskStatus::Approved.as_str())
        .bind(to_i64(previous.revision)?)
        .bind(now)
        .execute(&mut *tx)
        .await?
    } else {
        let status = if req.approve {
            TaskStatus::Approved
        } else {
            TaskStatus::Denied
        };
        let expires_at = req
            .approve
            .then(|| to_i64(decision.expires_at_ms))
            .transpose()?;
        sqlx::query(
            "UPDATE tasks SET status = $1, decided_at = $2, decision = $3, signature = $4, \
             revision = $5, expires_at = $6 WHERE id = $7 AND status = $8 AND decide_by > $9",
        )
        .bind(status.as_str())
        .bind(req.decided_at)
        .bind(req.decision.as_bytes().to_vec())
        .bind(req.signature.as_bytes().to_vec())
        .bind(to_i64(decision.revision)?)
        .bind(expires_at)
        .bind(id.to_string())
        .bind(TaskStatus::Pending.as_str())
        .bind(now)
        .execute(&mut *tx)
        .await?
    };
    if updated.rows_affected() != 1 {
        return Err(ApiError::conflict(
            "the task was decided, revised or ended meanwhile",
        ));
    }
    if req.approve {
        write_targets(&mut tx, id, &decision).await?;
    }
    // Logged in the decision's own transaction: a client that goes away
    // never leaves the decision without its `task.decided`.
    let mut event = AuditEvent::new(ActorKind::Person, "task.decided");
    event.device_id = Some(auth.device_id);
    event.agent_id = Some(info.agent_id);
    event.task_id = Some(id);
    event.outcome = Some(if req.approve { "approve" } else { "deny" }.to_owned());
    event.decided_at = Some(req.decided_at);
    event.signed = Some(req.decision.clone());
    event.task_request = Some(info.request.clone());
    event.account_signature = Some(req.signature.clone());
    // Stamped when it is logged, as `audit::append` does.
    audit::append_in(&mut tx, auth.account_id, &mut event, now_ms()).await?;
    tx.commit().await?;
    state.task_changed(id);
    task_from_row(&fetch(&state, auth.account_id, id).await?, now_ms()).map(Json)
}

/// `POST /v1/tasks/{id}/end`: the person ends a running task («End task»),
/// signed like a revocation (spec §13.8).
async fn end(
    State(state): State<AppState>,
    auth: Auth,
    Path(task_id): Path<String>,
    ApiJson(req): ApiJson<EndTask>,
) -> ApiResult<Json<TaskInfo>> {
    let id: TaskId = path_id(&task_id)?;
    let now = now_ms();
    sweep(&state, Sweep::Account(auth.account_id), now).await?;
    let info = task_from_row(&fetch(&state, auth.account_id, id).await?, now)?;
    if info.status != TaskStatus::Approved {
        return Err(ApiError::conflict(format!(
            "the task is {}: only a running task can be ended",
            info.status.as_str()
        )));
    }
    if (req.ended_at - now).abs() > CLOCK_SKEW_MS {
        return Err(ApiError::bad_request(
            "ended_at is too far from the server's clock",
        ));
    }
    let sig = signature(&req.signature)?;
    agent_crypto::verify_task_end(
        &account_identity(&state, auth.account_id).await?,
        auth.account_id,
        id,
        info.agent_id,
        u64::try_from(req.ended_at).map_err(|_| ApiError::bad_request("ended_at"))?,
        &sig,
    )
    .map_err(|_| ApiError::bad_request("the signature does not verify"))?;
    let mut tx = state.db().pool.begin().await?;
    // The account's lock first, as every write that logs in its own
    // transaction takes it. A revocation of the agent takes it too, before
    // it reads the tasks it ends: the two never both end this task.
    crate::deletion::lock_account(&mut tx, auth.account_id).await?;
    let updated = sqlx::query(
        "UPDATE tasks SET status = $1, ended_at = $2, ended_by = $3, end_signature = $4 \
         WHERE id = $5 AND status = $6",
    )
    .bind(TaskStatus::Ended.as_str())
    .bind(req.ended_at)
    .bind(TaskEndedBy::Person.as_str())
    .bind(req.signature.as_bytes().to_vec())
    .bind(id.to_string())
    .bind(TaskStatus::Approved.as_str())
    .execute(&mut *tx)
    .await?;
    if updated.rows_affected() != 1 {
        return Err(ApiError::conflict("the task changed meanwhile: try again"));
    }
    // Logged in the end's own transaction: a client that goes away never
    // leaves the task ended without its `task.ended`.
    let mut event = AuditEvent::new(ActorKind::Person, "task.ended");
    event.device_id = Some(auth.device_id);
    event.agent_id = Some(info.agent_id);
    event.task_id = Some(id);
    event.outcome = Some(TaskEndedBy::Person.as_str().to_owned());
    event.decided_at = Some(req.ended_at);
    event.account_signature = Some(req.signature.clone());
    // Stamped when it is logged, as `audit::append` does.
    audit::append_in(&mut tx, auth.account_id, &mut event, now_ms()).await?;
    tx.commit().await?;
    state.task_changed(id);
    task_from_row(&fetch(&state, auth.account_id, id).await?, now_ms()).map(Json)
}
