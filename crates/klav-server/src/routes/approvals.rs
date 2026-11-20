//! Approval requests as the person sees them (design §5.3, ADR 0014 §5):
//! list them and sign a decision. The server checks the signature with the
//! account identity, so it cannot approve on the person's behalf (T11).

use axum::extract::{Path, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use klav_core::crypto::agent::{self, ApprovalToSign};
use klav_core::crypto::sign::{SIGNATURE_LEN, Signature};
use klav_core::ids::{AgentId, ApprovalId, ItemId};
use klav_proto::Blob;
use klav_proto::agent::{
    AgentStatus, ApprovalInfo, ApprovalList, ApprovalRequest, ApprovalStatus, DecideApproval,
};
use klav_proto::audit::{ActorKind, AuditEvent};
use sqlx::Row;
use sqlx::any::AnyRow;

use crate::agentauth::{CLOCK_SKEW_MS, effective_status};
use crate::audit;
use crate::db::now_ms;
use crate::error::{ApiError, ApiJson, ApiResult};
use crate::routes::agents::account_identity;
use crate::routes::tasks::covering_task;
use crate::session::{Auth, parse_id};
use crate::state::AppState;
use crate::vaultdb::path_id;

/// Longest lease a person can give ("approve for…").
pub(crate) const MAX_LEASE_MS: i64 = 24 * 3600 * 1000;
/// Decided approvals kept in the list.
const LIST_LIMIT: i64 = 100;

pub(crate) const APPROVAL_COLUMNS: &str = "id, agent_id, status, request, created_at, expires_at, \
     decided_at, lease_until, signature, used_at";

pub(super) fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/approvals", get(list))
        .route("/v1/approvals/{approval_id}", get(get_one))
        .route("/v1/approvals/{approval_id}/decide", post(decide))
}

/// Status, with an unanswered request past its deadline read as expired.
pub(crate) fn effective_approval_status(
    status: &str,
    expires_at: i64,
    now: i64,
) -> ApiResult<ApprovalStatus> {
    let status = ApprovalStatus::parse(status)
        .ok_or_else(|| ApiError::Internal("corrupt approval status".into()))?;
    Ok(match status {
        ApprovalStatus::Pending if expires_at <= now => ApprovalStatus::Expired,
        other => other,
    })
}

pub(crate) fn approval_from_row(row: &AnyRow, now: i64) -> ApiResult<ApprovalInfo> {
    let expires_at: i64 = row.try_get("expires_at")?;
    Ok(ApprovalInfo {
        id: parse_id(&row.try_get::<String, _>("id")?)?,
        agent_id: parse_id(&row.try_get::<String, _>("agent_id")?)?,
        status: effective_approval_status(&row.try_get::<String, _>("status")?, expires_at, now)?,
        request: Blob::new(row.try_get::<Vec<u8>, _>("request")?),
        created_at: row.try_get("created_at")?,
        expires_at,
        decided_at: row.try_get("decided_at")?,
        lease_until: row.try_get("lease_until")?,
        signature: row
            .try_get::<Option<Vec<u8>>, _>("signature")?
            .map(Blob::new),
        used_at: row.try_get("used_at")?,
    })
}

async fn fetch(state: &AppState, auth: &Auth, id: ApprovalId) -> ApiResult<AnyRow> {
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT {APPROVAL_COLUMNS}, grant_version FROM approvals WHERE id = $1 AND account_id = $2"
    )))
    .bind(id.to_string())
    .bind(auth.account_id.to_string())
    .fetch_optional(&state.db().pool)
    .await?
    .ok_or(ApiError::NotFound)
}

/// `GET /v1/approvals`: pending requests and the last decided ones.
async fn list(State(state): State<AppState>, auth: Auth) -> ApiResult<Json<ApprovalList>> {
    let rows = sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT {APPROVAL_COLUMNS} FROM approvals WHERE account_id = $1 \
         ORDER BY created_at DESC LIMIT {LIST_LIMIT}"
    )))
    .bind(auth.account_id.to_string())
    .fetch_all(&state.db().pool)
    .await?;
    let now = now_ms();
    Ok(Json(ApprovalList {
        approvals: rows
            .iter()
            .map(|r| approval_from_row(r, now))
            .collect::<ApiResult<_>>()?,
    }))
}

async fn get_one(
    State(state): State<AppState>,
    auth: Auth,
    Path(approval_id): Path<String>,
) -> ApiResult<Json<ApprovalInfo>> {
    let row = fetch(&state, &auth, path_id(&approval_id)?).await?;
    approval_from_row(&row, now_ms()).map(Json)
}

/// `POST /v1/approvals/{id}/decide`: a signed decision on a pending
/// request of an agent that is still active under the same grant.
async fn decide(
    State(state): State<AppState>,
    auth: Auth,
    Path(approval_id): Path<String>,
    ApiJson(req): ApiJson<DecideApproval>,
) -> ApiResult<Json<ApprovalInfo>> {
    let id: ApprovalId = path_id(&approval_id)?;
    let row = fetch(&state, &auth, id).await?;
    let now = now_ms();
    let info = approval_from_row(&row, now)?;
    if info.status != ApprovalStatus::Pending {
        return Err(ApiError::conflict(format!(
            "the request is already {}",
            info.status.as_str()
        )));
    }
    if (req.decided_at - now).abs() > CLOCK_SKEW_MS {
        return Err(ApiError::bad_request(
            "decided_at is too far from the server's clock",
        ));
    }
    if req.lease_until != 0
        && (!req.approve
            || req.lease_until <= req.decided_at
            || req.lease_until - req.decided_at > MAX_LEASE_MS)
    {
        return Err(ApiError::bad_request(
            "lease_until must be 0, or a time after decided_at and at most 24 h later (approvals only)",
        ));
    }
    // The agent must still be active under the grant the request was made
    // with: a new grant or a revocation voids pending requests.
    let agent_id: AgentId = info.agent_id;
    let agent = sqlx::query("SELECT status, expires_at, grant_version FROM agents WHERE id = $1")
        .bind(agent_id.to_string())
        .fetch_one(&state.db().pool)
        .await?;
    let agent_status = effective_status(
        &agent.try_get::<String, _>("status")?,
        agent.try_get("expires_at")?,
        now,
    )?;
    let grant_version: i64 = row.try_get("grant_version")?;
    if agent_status != AgentStatus::Active
        || agent.try_get::<i64, _>("grant_version")? != grant_version
    {
        sqlx::query("UPDATE approvals SET status = $1 WHERE id = $2 AND status = $3")
            .bind(ApprovalStatus::Expired.as_str())
            .bind(id.to_string())
            .bind(ApprovalStatus::Pending.as_str())
            .execute(&state.db().pool)
            .await?;
        return Err(ApiError::conflict(
            "the agent was revoked or its grant changed: the request expired",
        ));
    }
    let signature: [u8; SIGNATURE_LEN] = req
        .signature
        .as_bytes()
        .try_into()
        .map_err(|_| ApiError::bad_request("signature: expected 64 bytes"))?;
    let to_sign = ApprovalToSign {
        approval: id,
        agent: agent_id,
        request: info.request.as_bytes(),
        approve: req.approve,
        lease_until_ms: u64::try_from(req.lease_until).unwrap_or(0),
        decided_at_ms: u64::try_from(req.decided_at)
            .map_err(|_| ApiError::bad_request("decided_at out of range"))?,
    };
    let account = account_identity(&state, auth.account_id).await?;
    agent::verify_approval(&account, &to_sign, &Signature::from_bytes(signature))
        .map_err(|_| ApiError::bad_request("the decision's signature does not verify"))?;
    let request: ApprovalRequest = serde_json::from_slice(info.request.as_bytes())
        .map_err(|_| ApiError::Internal("corrupt approval request".into()))?;
    // «Add to the task»: the task must be this agent's, running, and cover
    // the request now (the person revised it first).
    if let Some(task) = req.task_id {
        let item: ItemId = request.item_id.ok_or_else(|| {
            ApiError::bad_request("a request without an item cannot go in a task")
        })?;
        let covered = covering_task(
            &state,
            agent_id,
            request.permission,
            request.vault_id,
            request.project_id,
            item,
            request.claims.domain.as_deref(),
            Some(task),
        )
        .await?;
        if !req.approve || covered.is_none() {
            return Err(ApiError::bad_request(
                "task_id: approve the request into a running task of the agent that covers it",
            ));
        }
    }
    let status = if req.approve {
        ApprovalStatus::Approved
    } else {
        ApprovalStatus::Denied
    };
    let mut event = AuditEvent::new(ActorKind::Person, "approval.decided");
    event.task_id = req.task_id;
    event.device_id = Some(auth.device_id);
    event.agent_id = Some(agent_id);
    event.approval_id = Some(id);
    event.vault_id = Some(request.vault_id);
    event.project_id = Some(request.project_id);
    event.item_id = request.item_id;
    event.permission = Some(request.permission);
    event.outcome = Some(if req.approve { "approve" } else { "deny" }.to_owned());
    event.lease_until = Some(req.lease_until);
    event.decided_at = Some(req.decided_at);
    event.signed = Some(info.request.clone());
    event.account_signature = Some(Blob::new(signature.to_vec()));
    // The alerts `audit::append` adds (`denied` for a denial).
    let mut alerts = audit::alerts(&state, &event, now_ms()).await?;
    event.alerts.append(&mut alerts);
    // Logged in the decision's own transaction, under the account's lock
    // first as every transaction that logs in itself takes it: a decision
    // is never stored without its `approval.decided`, even if the client
    // goes away before the handler logs it.
    let mut tx = state.db().pool.begin().await?;
    crate::deletion::lock_account(&mut tx, auth.account_id).await?;
    let updated = sqlx::query(
        "UPDATE approvals SET status = $1, decided_at = $2, lease_until = $3, signature = $4, \
         task_id = $8 WHERE id = $5 AND status = $6 AND expires_at > $7",
    )
    .bind(status.as_str())
    .bind(req.decided_at)
    .bind(req.lease_until)
    .bind(req.signature.into_bytes())
    .bind(id.to_string())
    .bind(ApprovalStatus::Pending.as_str())
    .bind(now)
    .bind(req.task_id.map(|t| t.to_string()))
    .execute(&mut *tx)
    .await?;
    if updated.rows_affected() != 1 {
        return Err(ApiError::conflict(
            "the request was decided or expired meanwhile",
        ));
    }
    audit::append_in(&mut tx, auth.account_id, &mut event, now_ms()).await?;
    tx.commit().await?;
    // Wake the agent's long-poll at once (ADR 0015 §4).
    state.approval_decided(id);
    let row = fetch(&state, &auth, id).await?;
    approval_from_row(&row, now_ms()).map(Json)
}
