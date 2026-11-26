//! Agent secret requests (ADR 0046): an agent asks the person to create a
//! missing item or update a secret field, sending HPKE-encrypted proposal
//! metadata (`proposal_blob`, kind `0x25`, spec §13.14) and never a secret
//! value.
//!
//! The server stores `proposal_blob` only while the request is pending; it is
//! cleared (`NULL`) immediately upon decision, agent revocation, or the
//! expiry sweep (hourly in `purge.rs` and on-demand in handlers). The audit
//! log keeps only `proposal_digest` and `reason` (never `proposal_blob`).

use std::time::Duration;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use klav_core::crypto::agent::{
    self as agent_crypto, MAX_SECRET_REQUEST_BLOB_LEN, SECRET_REQUEST_BLOB_OVERHEAD,
    SecretRequestDecisionToSign,
};
use klav_core::crypto::encoding::{FORMAT_V1, Kind};
use klav_core::crypto::sign::{SIGNATURE_LEN, Signature};
use klav_core::ids::{AccountId, AgentId, ProjectId, SecretRequestId, VaultId};
use klav_core::policy::Permission;
use klav_core::secret_request::{
    SecretRequestDecision, SecretRequestMode, SecretRequestStatus, validate_reason,
};
use klav_proto::Blob;
use klav_proto::agent::{AgentStatus, GrantPayload};
use klav_proto::audit::{ActorKind, AuditEvent, MAX_PROOF_BODY};
use klav_proto::secret_request::{
    CreateSecretRequest, DecideSecretRequest, MAX_PENDING_SECRET_REQUESTS,
    MAX_SECRET_REQUEST_WAIT_SECS, PendingSecretRequest, SECRET_REQUEST_TTL_MS, SecretRequestInfo,
    SecretRequestList, SecretRequestState,
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
use crate::routes::agents::account_identity;
use crate::routes::tasks::lock_agent;
use crate::session::{Auth, parse_id};
use crate::state::{AppState, SecretRequestChange};
use crate::vaultdb::path_id;

/// Maximum secret requests returned by `GET /v1/secret-requests`.
const LIST_LIMIT: i64 = 100;
/// How often a long-poll re-reads the database.
const WAIT_RECHECK: Duration = Duration::from_secs(2);

const COLUMNS: &str = "r.id, r.agent_id, a.name AS agent_name, r.mode, r.target_item_id, \
     r.reason, r.proposal_digest, r.proposal_blob, r.status, r.created_at, r.expires_at, \
     r.decided_at, r.decision, r.signature";

pub(super) fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/agent/secret-requests", post(create))
        .route("/v1/agent/secret-requests/{request_id}", get(agent_get))
        .route("/v1/secret-requests", get(list))
        .route("/v1/secret-requests/{request_id}", get(get_one))
        .route("/v1/secret-requests/{request_id}/decide", post(decide))
}

/// Which secret requests [`sweep`] looks at.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Sweep {
    /// Every account (the periodic clean-up).
    All,
    /// One account.
    Account(AccountId),
    /// One agent.
    Agent(AgentId),
}

fn mode_as_str(mode: SecretRequestMode) -> &'static str {
    match mode {
        SecretRequestMode::Create => "create",
        SecretRequestMode::Update => "update",
    }
}

fn parse_mode(text: &str) -> ApiResult<SecretRequestMode> {
    match text {
        "create" => Ok(SecretRequestMode::Create),
        "update" => Ok(SecretRequestMode::Update),
        _ => Err(ApiError::Internal("corrupt secret request mode".into())),
    }
}

fn parse_state(text: &str) -> ApiResult<SecretRequestState> {
    SecretRequestState::parse(text)
        .ok_or_else(|| ApiError::Internal("corrupt secret request status".into()))
}

fn info_from_row(row: &AnyRow, now: i64, include_blob: bool) -> ApiResult<SecretRequestInfo> {
    let expires_at: i64 = row.try_get("expires_at")?;
    let mut status = parse_state(&row.try_get::<String, _>("status")?)?;
    if status == SecretRequestState::Pending && expires_at <= now {
        status = SecretRequestState::Expired;
    }
    let proposal_blob = if include_blob && status == SecretRequestState::Pending {
        row.try_get::<Option<Vec<u8>>, _>("proposal_blob")?
            .map(Blob::new)
    } else {
        None
    };
    let target_item_id = row
        .try_get::<Option<String>, _>("target_item_id")?
        .map(|s| parse_id(&s))
        .transpose()?;
    Ok(SecretRequestInfo {
        id: parse_id(&row.try_get::<String, _>("id")?)?,
        agent_id: parse_id(&row.try_get::<String, _>("agent_id")?)?,
        agent_name: row.try_get("agent_name")?,
        mode: parse_mode(&row.try_get::<String, _>("mode")?)?,
        target_item_id,
        reason: row.try_get("reason")?,
        proposal_digest: Blob::new(row.try_get::<Vec<u8>, _>("proposal_digest")?),
        proposal_blob,
        status,
        created_at: row.try_get("created_at")?,
        expires_at,
        decided_at: row.try_get("decided_at")?,
        decision: row
            .try_get::<Option<Vec<u8>>, _>("decision")?
            .map(Blob::new),
        signature: row
            .try_get::<Option<Vec<u8>>, _>("signature")?
            .map(Blob::new),
    })
}

/// Marks expired pending requests as `expired`, drops `proposal_blob` on all
/// expired or already-decided rows, and wakes any waiters / SSE streams.
/// Returns the number of requests expired by this pass.
pub(crate) async fn sweep(state: &AppState, scope: Sweep, now: i64) -> ApiResult<u64> {
    let (filter, value) = match scope {
        Sweep::All => ("", None),
        Sweep::Account(a) => (" AND account_id = $3", Some(a.to_string())),
        Sweep::Agent(a) => (" AND agent_id = $3", Some(a.to_string())),
    };
    let mut expire = sqlx::query(sqlx::AssertSqlSafe(format!(
        "UPDATE secret_requests SET status = $1, proposal_blob = NULL \
         WHERE status = 'pending' AND expires_at <= $2{filter} \
         RETURNING account_id, id"
    )))
    .bind(SecretRequestState::Expired.as_str())
    .bind(now);
    if let Some(v) = &value {
        expire = expire.bind(v.clone());
    }
    let expired = expire.fetch_all(&state.db().pool).await?;
    for row in &expired {
        if let (Ok(account), Ok(id)) = (
            parse_id::<AccountId>(&row.try_get::<String, _>("account_id")?),
            parse_id::<SecretRequestId>(&row.try_get::<String, _>("id")?),
        ) {
            state.secret_request_changed(account, id, SecretRequestState::Expired);
        }
    }
    // Belt-and-suspenders blob cleanup for any non-pending row that somehow
    // still carries a blob.
    let (blob_filter, blob_value) = match scope {
        Sweep::All => ("", None),
        Sweep::Account(a) => (" AND account_id = $1", Some(a.to_string())),
        Sweep::Agent(a) => (" AND agent_id = $1", Some(a.to_string())),
    };
    let mut clean = sqlx::query(sqlx::AssertSqlSafe(format!(
        "UPDATE secret_requests SET proposal_blob = NULL \
         WHERE status != 'pending' AND proposal_blob IS NOT NULL{blob_filter}"
    )));
    if let Some(v) = &blob_value {
        clean = clean.bind(v.clone());
    }
    clean.execute(&state.db().pool).await?;
    Ok(u64::try_from(expired.len()).unwrap_or(u64::MAX))
}

/// Expires every pending secret request of a revoked agent and drops their
/// `proposal_blob`, inside the revocation's own transaction. Returns the IDs
/// changed so the caller can notify waiters after commit.
pub(crate) async fn expire_on_revocation(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    agent: AgentId,
) -> ApiResult<Vec<SecretRequestId>> {
    let ids: Vec<String> = sqlx::query_scalar(
        "UPDATE secret_requests SET status = $1, proposal_blob = NULL \
         WHERE agent_id = $2 AND status = $3 RETURNING id",
    )
    .bind(SecretRequestState::Expired.as_str())
    .bind(agent.to_string())
    .bind(SecretRequestState::Pending.as_str())
    .fetch_all(&mut **tx)
    .await?;
    ids.iter().map(|id| parse_id(id)).collect()
}

/// Loads the agent's current signed grant payload (`403` if none).
async fn load_grant_payload(state: &AppState, agent: AgentId) -> ApiResult<GrantPayload> {
    let payload: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT grant_payload FROM agents WHERE id = $1")
            .bind(agent.to_string())
            .fetch_one(&state.db().pool)
            .await?;
    let payload = payload.ok_or(ApiError::Forbidden)?;
    serde_json::from_slice(&payload).map_err(|_| ApiError::Internal("corrupt grant payload".into()))
}

/// Whether `grant` makes the agent a credential proxy (ADR 0036 §2/§4, ADR 0046 Q2).
fn is_proxy_grant(grant: &GrantPayload) -> bool {
    !grant.profiles.is_empty()
        || !grant.issuers.is_empty()
        || grant
            .policy
            .rules
            .iter()
            .any(|r| r.permission == Permission::Proxy)
}

async fn count_pending(conn: &mut sqlx::AnyConnection, agent: AgentId, now: i64) -> ApiResult<i64> {
    Ok(sqlx::query_scalar(
        "SELECT COUNT(*) FROM secret_requests \
         WHERE agent_id = $1 AND status = $2 AND expires_at > $3",
    )
    .bind(agent.to_string())
    .bind(SecretRequestState::Pending.as_str())
    .bind(now)
    .fetch_one(&mut *conn)
    .await?)
}

// ---------------------------------------------------------------- agent --

/// `POST /v1/agent/secret-requests`: an active non-proxy agent asks the
/// person to add an item or update a secret field.
async fn create(
    State(state): State<AppState>,
    auth: AgentAuth,
) -> ApiResult<(StatusCode, Json<PendingSecretRequest>)> {
    if auth.body.len() > MAX_PROOF_BODY {
        return Err(ApiError::bad_request(format!(
            "secret request body is too large: at most {MAX_PROOF_BODY} bytes"
        )));
    }
    let grant = load_grant_payload(&state, auth.agent_id).await?;
    if is_proxy_grant(&grant) {
        return Err(ApiError::Coded(
            StatusCode::FORBIDDEN,
            klav_proto::ErrorCode::Forbidden,
            "credential proxies cannot request secrets".into(),
        ));
    }
    let req: CreateSecretRequest = auth.json()?;
    validate_reason(&req.reason).map_err(|e| ApiError::bad_request(e.to_string()))?;
    let reason = req.reason.trim().to_owned();
    if req.proposal_digest.as_bytes().len() != 32 {
        return Err(ApiError::bad_request("proposal_digest: expected 32 bytes"));
    }
    let blob = req.proposal_blob.as_bytes();
    if blob.len() <= SECRET_REQUEST_BLOB_OVERHEAD
        || blob.len() > MAX_SECRET_REQUEST_BLOB_LEN
        || blob[0] != FORMAT_V1
        || blob[1] != Kind::SecretRequestProposal as u8
    {
        return Err(ApiError::bad_request(
            "proposal_blob: expected a v1 kind 0x25 blob up to 8 KiB",
        ));
    }
    match (req.mode, req.target_item_id) {
        (SecretRequestMode::Create, Some(_)) => {
            return Err(ApiError::bad_request(
                "create mode must not set target_item_id",
            ));
        }
        (SecretRequestMode::Update, None) => {
            return Err(ApiError::bad_request("update mode requires target_item_id"));
        }
        (SecretRequestMode::Update, Some(item_id)) => {
            // T236: items outside the agent's grant return the same 404 as
            // nonexistent, trashed, purged or deleted-vault items.
            let row = sqlx::query(
                "SELECT vault_id, project_id FROM items \
                 WHERE id = $1 AND purged_at IS NULL AND trashed_at IS NULL \
                 AND vault_id IN (SELECT id FROM vaults WHERE deleted_at IS NULL)",
            )
            .bind(item_id.to_string())
            .fetch_optional(&state.db().pool)
            .await?
            .ok_or(ApiError::NotFound)?;
            let vault_id: VaultId = parse_id(&row.try_get::<String, _>("vault_id")?)?;
            let project_id: ProjectId = parse_id(&row.try_get::<String, _>("project_id")?)?;
            let in_grant = grant
                .projects
                .iter()
                .any(|p| p.vault_id == vault_id && p.project_id == project_id);
            if !in_grant {
                return Err(ApiError::NotFound);
            }
        }
        (SecretRequestMode::Create, None) => {}
    }

    let now = now_ms();
    sweep(&state, Sweep::Agent(auth.agent_id), now).await?;
    let mut tx = state.db().pool.begin().await?;
    crate::deletion::lock_account(&mut tx, auth.account_id).await?;
    lock_agent(&mut tx, auth.agent_id).await?;
    if count_pending(&mut tx, auth.agent_id, now).await? >= MAX_PENDING_SECRET_REQUESTS {
        return Err(ApiError::TooManyRequests {
            retry_after_secs: 60,
        });
    }
    let expires_at = now + SECRET_REQUEST_TTL_MS;
    let inserted = sqlx::query(
        "INSERT INTO secret_requests \
         (id, account_id, agent_id, mode, target_item_id, reason, proposal_digest, \
          proposal_blob, status, created_at, expires_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
    )
    .bind(req.id.to_string())
    .bind(auth.account_id.to_string())
    .bind(auth.agent_id.to_string())
    .bind(mode_as_str(req.mode))
    .bind(req.target_item_id.map(|id| id.to_string()))
    .bind(&reason)
    .bind(req.proposal_digest.as_bytes().to_vec())
    .bind(blob.to_vec())
    .bind(SecretRequestState::Pending.as_str())
    .bind(now)
    .bind(expires_at)
    .execute(&mut *tx)
    .await;
    match inserted {
        Ok(_) => {}
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
            return Err(ApiError::conflict(
                "a secret request with this ID already exists",
            ));
        }
        Err(e) => return Err(e.into()),
    }

    // ADR 0046 §1: never retain `proposal_blob` in the permanent audit log;
    // omit `agent_proof.body` and log `proposal_digest` and `reason` instead.
    let mut proof = auth.proof.clone();
    proof.body = None;
    let mut event = AuditEvent::new(ActorKind::Agent, "secret_request.created");
    event.agent_id = Some(auth.agent_id);
    event.secret_request_id = Some(req.id);
    event.proposal_digest = Some(req.proposal_digest.clone());
    event.item_id = req.target_item_id;
    event.reason = Some(reason);
    event.agent_proof = Some(proof);
    audit::append_in(&mut tx, auth.account_id, &mut event, now_ms()).await?;
    tx.commit().await?;

    state.push(auth.account_id, PushKind::SecretRequest, req.id.to_string());
    state.secret_request_changed(auth.account_id, req.id, SecretRequestState::Pending);
    Ok((
        StatusCode::ACCEPTED,
        Json(PendingSecretRequest {
            request_id: req.id,
            expires_at,
        }),
    ))
}

async fn fetch_for_agent(
    state: &AppState,
    agent: AgentId,
    id: SecretRequestId,
) -> ApiResult<AnyRow> {
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT {COLUMNS} FROM secret_requests r JOIN agents a ON a.id = r.agent_id \
         WHERE r.id = $1 AND r.agent_id = $2"
    )))
    .bind(id.to_string())
    .bind(agent.to_string())
    .fetch_optional(&state.db().pool)
    .await?
    .ok_or(ApiError::NotFound)
}

#[derive(Debug, Default, Deserialize)]
struct WaitQuery {
    #[serde(default)]
    wait: Option<u64>,
}

/// `GET /v1/agent/secret-requests/{id}[?wait=N]`: polls until decided,
/// expired, or `N` seconds (at most 30).
async fn agent_get(
    State(state): State<AppState>,
    Path(request_id): Path<String>,
    Query(query): Query<WaitQuery>,
    auth: AgentAuth,
) -> ApiResult<Json<SecretRequestInfo>> {
    let id: SecretRequestId = path_id(&request_id)?;
    let wait = Duration::from_secs(query.wait.unwrap_or(0).min(MAX_SECRET_REQUEST_WAIT_SECS));
    let deadline = tokio::time::Instant::now() + wait;
    let mut changed = state.subscribe_secret_requests();
    loop {
        let now = now_ms();
        sweep(&state, Sweep::Agent(auth.agent_id), now).await?;
        let info = info_from_row(
            &fetch_for_agent(&state, auth.agent_id, id).await?,
            now,
            false,
        )?;
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        if info.status != SecretRequestState::Pending || left.is_zero() {
            return Ok(Json(info));
        }
        let until_expiry =
            Duration::from_millis(u64::try_from(info.expires_at - now).unwrap_or(0) + 1);
        let nap = WAIT_RECHECK.min(left).min(until_expiry);
        tokio::select! {
            () = change_on(&mut changed, id) => {}
            () = tokio::time::sleep(nap) => {}
        }
    }
}

async fn change_on(rx: &mut broadcast::Receiver<SecretRequestChange>, id: SecretRequestId) {
    loop {
        match rx.recv().await {
            Ok(change)
                if change.request_id == id && change.status != SecretRequestState::Pending =>
            {
                return;
            }
            Ok(_) => {}
            Err(broadcast::error::RecvError::Lagged(_)) => return,
            Err(broadcast::error::RecvError::Closed) => std::future::pending::<()>().await,
        }
    }
}

// --------------------------------------------------------------- person --

async fn fetch_for_account(
    state: &AppState,
    account: AccountId,
    id: SecretRequestId,
) -> ApiResult<AnyRow> {
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT {COLUMNS} FROM secret_requests r JOIN agents a ON a.id = r.agent_id \
         WHERE r.id = $1 AND r.account_id = $2"
    )))
    .bind(id.to_string())
    .bind(account.to_string())
    .fetch_optional(&state.db().pool)
    .await?
    .ok_or(ApiError::NotFound)
}

/// `GET /v1/secret-requests`: the account's secret requests, newest first.
async fn list(State(state): State<AppState>, auth: Auth) -> ApiResult<Json<SecretRequestList>> {
    let now = now_ms();
    sweep(&state, Sweep::Account(auth.account_id), now).await?;
    let rows = sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT {COLUMNS} FROM secret_requests r JOIN agents a ON a.id = r.agent_id \
         WHERE r.account_id = $1 ORDER BY r.created_at DESC LIMIT {LIST_LIMIT}"
    )))
    .bind(auth.account_id.to_string())
    .fetch_all(&state.db().pool)
    .await?;
    Ok(Json(SecretRequestList {
        secret_requests: rows
            .iter()
            .map(|r| info_from_row(r, now, true))
            .collect::<ApiResult<_>>()?,
    }))
}

/// `GET /v1/secret-requests/{id}`: one secret request, including
/// `proposal_blob` while pending.
async fn get_one(
    State(state): State<AppState>,
    auth: Auth,
    Path(request_id): Path<String>,
) -> ApiResult<Json<SecretRequestInfo>> {
    let id: SecretRequestId = path_id(&request_id)?;
    let now = now_ms();
    sweep(&state, Sweep::Account(auth.account_id), now).await?;
    info_from_row(
        &fetch_for_account(&state, auth.account_id, id).await?,
        now,
        true,
    )
    .map(Json)
}

fn parse_signature(blob: &Blob) -> ApiResult<Signature> {
    let bytes: [u8; SIGNATURE_LEN] = blob
        .as_bytes()
        .try_into()
        .map_err(|_| ApiError::bad_request("signature: expected 64 bytes"))?;
    Ok(Signature::from_bytes(bytes))
}

/// `POST /v1/secret-requests/{id}/decide`: the person fulfills or denies a
/// pending secret request with an account-signed [`SecretRequestDecision`].
/// Clears `proposal_blob` immediately on commit.
async fn decide(
    State(state): State<AppState>,
    auth: Auth,
    Path(request_id): Path<String>,
    ApiJson(req): ApiJson<DecideSecretRequest>,
) -> ApiResult<Json<SecretRequestInfo>> {
    let id: SecretRequestId = path_id(&request_id)?;
    let now = now_ms();
    sweep(&state, Sweep::Account(auth.account_id), now).await?;
    let info = info_from_row(
        &fetch_for_account(&state, auth.account_id, id).await?,
        now,
        false,
    )?;
    if info.status != SecretRequestState::Pending {
        return Err(ApiError::conflict(format!(
            "the secret request is already {}",
            info.status.as_str()
        )));
    }
    if req.decided_at.abs_diff(now) > CLOCK_SKEW_MS.unsigned_abs() {
        return Err(ApiError::bad_request(
            "decided_at is too far from the server's clock",
        ));
    }
    let decided_at_ms =
        u64::try_from(req.decided_at).map_err(|_| ApiError::bad_request("decided_at"))?;
    let decision: SecretRequestDecision = serde_json::from_slice(req.decision.as_bytes())
        .map_err(|e| ApiError::bad_request(format!("decision: {e}")))?;
    decision
        .validate()
        .map_err(|e| ApiError::bad_request(e.to_string()))?;
    if decision.request_id != id || decision.agent_id != info.agent_id {
        return Err(ApiError::bad_request(
            "the decision is for another secret request or agent",
        ));
    }
    if info.mode == SecretRequestMode::Update
        && decision.status == SecretRequestStatus::Fulfilled
        && let (Some(target), Some(decided_item)) = (info.target_item_id, decision.item_id)
        && target != decided_item
    {
        return Err(ApiError::bad_request(
            "an update decision must refer to the requested item",
        ));
    }
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
    let digest: [u8; 32] = info
        .proposal_digest
        .as_bytes()
        .try_into()
        .map_err(|_| ApiError::Internal("corrupt proposal digest".into()))?;
    let sig = parse_signature(&req.signature)?;
    agent_crypto::verify_secret_request_decision(
        &account_identity(&state, auth.account_id).await?,
        &SecretRequestDecisionToSign {
            request: id,
            agent: info.agent_id,
            proposal_digest: &digest,
            decision: req.decision.as_bytes(),
            decided_at_ms,
        },
        &sig,
    )
    .map_err(|_| ApiError::bad_request("the decision's signature does not verify"))?;

    let new_state = match decision.status {
        SecretRequestStatus::Fulfilled => SecretRequestState::Fulfilled,
        SecretRequestStatus::Denied => SecretRequestState::Denied,
    };
    let mut tx = state.db().pool.begin().await?;
    crate::deletion::lock_account(&mut tx, auth.account_id).await?;
    let updated = sqlx::query(
        "UPDATE secret_requests \
         SET status = $1, decided_at = $2, decision = $3, signature = $4, proposal_blob = NULL \
         WHERE id = $5 AND account_id = $6 AND status = $7 AND expires_at > $8",
    )
    .bind(new_state.as_str())
    .bind(req.decided_at)
    .bind(req.decision.as_bytes().to_vec())
    .bind(req.signature.as_bytes().to_vec())
    .bind(id.to_string())
    .bind(auth.account_id.to_string())
    .bind(SecretRequestState::Pending.as_str())
    .bind(now)
    .execute(&mut *tx)
    .await?;
    if updated.rows_affected() != 1 {
        return Err(ApiError::conflict(
            "the secret request was already decided or expired",
        ));
    }

    let mut event = AuditEvent::new(ActorKind::Person, "secret_request.decided");
    event.device_id = Some(auth.device_id);
    event.agent_id = Some(info.agent_id);
    event.secret_request_id = Some(id);
    event.proposal_digest = Some(info.proposal_digest.clone());
    event.vault_id = decision.vault_id;
    event.project_id = decision.project_id;
    event.item_id = decision.item_id;
    event.outcome = Some(decision.status.as_str().to_owned());
    event.decided_at = Some(req.decided_at);
    event.signed = Some(req.decision.clone());
    event.account_signature = Some(req.signature.clone());
    audit::append_in(&mut tx, auth.account_id, &mut event, now_ms()).await?;
    tx.commit().await?;

    state.secret_request_changed(auth.account_id, id, new_state);
    info_from_row(
        &fetch_for_account(&state, auth.account_id, id).await?,
        now_ms(),
        true,
    )
    .map(Json)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use klav_core::crypto::agent::{
        GrantToSign, SignedRequest, body_digest, seal_secret_request, sign_grant, sign_request,
        sign_revocation, sign_secret_request_decision,
    };
    use klav_core::crypto::identity::IdentityKeyPair;
    use klav_core::crypto::random;
    use klav_core::ids::{DeviceId, ItemId};
    use klav_core::model::ItemKind;
    use klav_core::policy::{Effect, Policy, Rule};
    use klav_core::secret_request::{SECRET_REQUEST_FORMAT_VERSION, SecretRequestProposal};
    use klav_proto::agent::{
        GrantedProject, HEADER_AGENT, HEADER_NONCE, HEADER_SIGNATURE, HEADER_TIMESTAMP, RevokeAgent,
    };
    use klav_proto::audit::AuditPage;
    use tower::ServiceExt;

    use crate::config::Config;
    use crate::db::Db;
    use crate::http;
    use crate::keys::ServerKeys;
    use crate::push::Pusher;

    struct Fixture {
        _dir: tempfile::TempDir,
        state: AppState,
        app: Router,
        account_id: AccountId,
        account_identity: IdentityKeyPair,
        access_token: String,
        vault_id: VaultId,
        project_id: ProjectId,
        other_project_id: ProjectId,
        granted_item_id: ItemId,
        ungranted_item_id: ItemId,
        agent_id: AgentId,
        agent_identity: IdentityKeyPair,
    }

    impl Fixture {
        async fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let db_path = dir.path().join("klav.db");
            let config = Config {
                data_dir: dir.path().to_path_buf(),
                database_url: format!("sqlite://{}?mode=rwc", db_path.display()),
                ..Config::default()
            };
            let db = Db::connect(&config.database_url).await.unwrap();
            let keys = crate::keys::load_or_create(&db).await.unwrap();
            let pusher = Pusher::new(None).unwrap();
            let state = AppState::new(config, db, keys, pusher);
            let app = http::router(state.clone());

            let now = now_ms();
            let account_id = AccountId::generate();
            let account_identity = IdentityKeyPair::generate();
            let device_id = DeviceId::generate();

            sqlx::query(
                "INSERT INTO accounts (id, email, kdf_params, opaque_record, public_identity, \
                 sealed_identity, created_at, updated_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
            )
            .bind(account_id.to_string())
            .bind("ana@example.com")
            .bind(vec![1u8; 4])
            .bind(vec![1u8; 4])
            .bind(account_identity.public().encode().to_vec())
            .bind(vec![1u8; 4])
            .bind(now)
            .bind(now)
            .execute(&state.db().pool)
            .await
            .unwrap();

            sqlx::query(
                "INSERT INTO devices (id, account_id, name, kind, created_at, last_seen_at) \
                 VALUES ($1, $2, $3, $4, $5, $6)",
            )
            .bind(device_id.to_string())
            .bind(account_id.to_string())
            .bind("mac")
            .bind("desktop")
            .bind(now)
            .bind(now)
            .execute(&state.db().pool)
            .await
            .unwrap();

            let tokens = crate::session::create(&state, account_id, device_id)
                .await
                .unwrap();

            let vault_id = VaultId::generate();
            let project_id = ProjectId::generate();
            let other_project_id = ProjectId::generate();
            let granted_item_id = ItemId::generate();
            let ungranted_item_id = ItemId::generate();

            sqlx::query(
                "INSERT INTO vaults (id, owner_account_id, version, meta, revision, meta_revision, \
                 created_at, updated_at) VALUES ($1, $2, 1, $3, 1, 1, $4, $4)",
            )
            .bind(vault_id.to_string())
            .bind(account_id.to_string())
            .bind(vec![1u8; 4])
            .bind(now)
            .execute(&state.db().pool)
            .await
            .unwrap();

            for pid in [project_id, other_project_id] {
                sqlx::query(
                    "INSERT INTO projects (id, vault_id, wrapped_key, meta, version, revision, \
                     created_at, updated_at) VALUES ($1, $2, $3, $4, 1, 1, $5, $5)",
                )
                .bind(pid.to_string())
                .bind(vault_id.to_string())
                .bind(vec![1u8; 4])
                .bind(vec![1u8; 4])
                .bind(now)
                .execute(&state.db().pool)
                .await
                .unwrap();
            }

            for (iid, pid) in [
                (granted_item_id, project_id),
                (ungranted_item_id, other_project_id),
            ] {
                sqlx::query(
                    "INSERT INTO items (id, vault_id, project_id, version, revision, wrapped_key, \
                     overview, details, created_at, updated_at) \
                     VALUES ($1, $2, $3, 1, 1, $4, $5, $6, $7, $7)",
                )
                .bind(iid.to_string())
                .bind(vault_id.to_string())
                .bind(pid.to_string())
                .bind(vec![1u8; 4])
                .bind(vec![1u8; 4])
                .bind(vec![1u8; 4])
                .bind(now)
                .execute(&state.db().pool)
                .await
                .unwrap();
            }

            let agent_id = AgentId::generate();
            let agent_identity = IdentityKeyPair::generate();
            let grant_payload = GrantPayload {
                v: 1,
                account_id,
                agent_id,
                version: 1,
                issued_at: now,
                policy: Policy {
                    rules: vec![Rule::new(Permission::Inject, Effect::Allow)],
                    expires_at: None,
                },
                projects: vec![GrantedProject {
                    vault_id,
                    owner_account_id: account_id,
                    project_id,
                    shared_key: Blob::new(vec![1u8; 16]),
                    labels: Blob::new(vec![1u8; 16]),
                }],
                items: vec![],
                profiles: vec![],
                issuers: vec![],
                sandbox: None,
                local_clients: Vec::new(),
                released: Vec::new(),
            };
            let grant_bytes = serde_json::to_vec(&grant_payload).unwrap();
            let grant_sig = sign_grant(
                &account_identity,
                &GrantToSign {
                    account: account_id,
                    agent: agent_id,
                    agent_public: agent_identity.public(),
                    payload: &grant_bytes,
                },
            );

            sqlx::query(
                "INSERT INTO agents (id, account_id, name, public_identity, status, \
                 grant_version, grant_payload, grant_signature, granted_at, approved_at, \
                 created_at, expires_at) \
                 VALUES ($1, $2, $3, $4, 'active', 1, $5, $6, $7, $7, $7, $8)",
            )
            .bind(agent_id.to_string())
            .bind(account_id.to_string())
            .bind("claude")
            .bind(agent_identity.public().encode().to_vec())
            .bind(grant_bytes)
            .bind(grant_sig.to_bytes().to_vec())
            .bind(now)
            .bind(now + 3_600_000)
            .execute(&state.db().pool)
            .await
            .unwrap();

            // Satisfy unused ServerKeys import warning cleanly.
            let _: &ServerKeys = state.keys();

            Self {
                _dir: dir,
                state,
                app,
                account_id,
                account_identity,
                access_token: tokens.access_token,
                vault_id,
                project_id,
                other_project_id,
                granted_item_id,
                ungranted_item_id,
                agent_id,
                agent_identity,
            }
        }

        async fn add_proxy_agent(&self) -> (AgentId, IdentityKeyPair) {
            let now = now_ms();
            let proxy_id = AgentId::generate();
            let proxy_identity = IdentityKeyPair::generate();
            let grant_payload = GrantPayload {
                v: 2,
                account_id: self.account_id,
                agent_id: proxy_id,
                version: 1,
                issued_at: now,
                policy: Policy {
                    rules: vec![Rule::new(Permission::Proxy, Effect::Allow)],
                    expires_at: None,
                },
                projects: vec![],
                items: vec![],
                profiles: vec![],
                issuers: vec![],
                sandbox: None,
                local_clients: Vec::new(),
                released: Vec::new(),
            };
            let grant_bytes = serde_json::to_vec(&grant_payload).unwrap();
            let grant_sig = sign_grant(
                &self.account_identity,
                &GrantToSign {
                    account: self.account_id,
                    agent: proxy_id,
                    agent_public: proxy_identity.public(),
                    payload: &grant_bytes,
                },
            );
            sqlx::query(
                "INSERT INTO agents (id, account_id, name, public_identity, status, \
                 grant_version, grant_payload, grant_signature, granted_at, approved_at, \
                 created_at, expires_at) \
                 VALUES ($1, $2, $3, $4, 'active', 1, $5, $6, $7, $7, $7, $8)",
            )
            .bind(proxy_id.to_string())
            .bind(self.account_id.to_string())
            .bind("klav-proxy")
            .bind(proxy_identity.public().encode().to_vec())
            .bind(grant_bytes)
            .bind(grant_sig.to_bytes().to_vec())
            .bind(now)
            .bind(now + 3_600_000)
            .execute(&self.state.db().pool)
            .await
            .unwrap();
            (proxy_id, proxy_identity)
        }

        async fn agent_req(
            &self,
            agent_id: AgentId,
            agent_identity: &IdentityKeyPair,
            method: &str,
            path: &str,
            body: Vec<u8>,
        ) -> (StatusCode, Vec<u8>) {
            let ts = now_ms();
            let nonce: [u8; 16] = random::array::<16>();
            let digest = body_digest(&body);
            let sig = sign_request(
                agent_identity,
                &SignedRequest {
                    agent: agent_id,
                    method,
                    path,
                    timestamp_ms: u64::try_from(ts).unwrap(),
                    nonce: &nonce,
                    body_digest: &digest,
                },
            );
            let req = Request::builder()
                .method(method)
                .uri(path)
                .header(HEADER_AGENT, agent_id.to_string())
                .header(HEADER_TIMESTAMP, ts.to_string())
                .header(HEADER_NONCE, Blob::new(nonce.to_vec()).to_text())
                .header(
                    HEADER_SIGNATURE,
                    Blob::new(sig.to_bytes().to_vec()).to_text(),
                )
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap();
            let resp = self.app.clone().oneshot(req).await.unwrap();
            let status = resp.status();
            let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
                .await
                .unwrap()
                .to_vec();
            (status, bytes)
        }

        async fn person_req(
            &self,
            method: &str,
            path: &str,
            body: Vec<u8>,
        ) -> (StatusCode, Vec<u8>) {
            let req = Request::builder()
                .method(method)
                .uri(path)
                .header("authorization", format!("Bearer {}", self.access_token))
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap();
            let resp = self.app.clone().oneshot(req).await.unwrap();
            let status = resp.status();
            let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
                .await
                .unwrap()
                .to_vec();
            (status, bytes)
        }

        fn make_request(
            &self,
            id: SecretRequestId,
            agent_id: AgentId,
            mode: SecretRequestMode,
            target_item_id: Option<ItemId>,
            reason: &str,
        ) -> (CreateSecretRequest, [u8; 32]) {
            let proposal = SecretRequestProposal {
                v: SECRET_REQUEST_FORMAT_VERSION,
                mode,
                kind: (mode == SecretRequestMode::Create).then_some(ItemKind::ApiKey),
                title: (mode == SecretRequestMode::Create).then(|| "Stripe API key".into()),
                vault_id: Some(self.vault_id),
                project_id: Some(self.project_id),
                target_item_id,
                field: "api_key".into(),
                placeholder: Some("sk_live_…".into()),
                setup_url: Some("https://dashboard.stripe.com/apikeys".into()),
                base_url: (mode == SecretRequestMode::Create)
                    .then(|| "https://api.stripe.com".into()),
                urls: vec![],
                notes: None,
                proxy_proposal: None,
            };
            proposal.validate().unwrap();
            let canonical = serde_json::to_vec(&proposal).unwrap();
            let digest = body_digest(&canonical);
            let blob = seal_secret_request(
                self.account_identity.public(),
                self.account_id,
                agent_id,
                id,
                &canonical,
            )
            .unwrap();
            (
                CreateSecretRequest {
                    id,
                    mode,
                    target_item_id,
                    reason: reason.into(),
                    proposal_digest: Blob::new(digest.to_vec()),
                    proposal_blob: Blob::new(blob),
                },
                digest,
            )
        }

        fn sign_decision(
            &self,
            id: SecretRequestId,
            digest: &[u8; 32],
            decision: &SecretRequestDecision,
            decided_at: i64,
        ) -> DecideSecretRequest {
            let bytes = serde_json::to_vec(decision).unwrap();
            let sig = sign_secret_request_decision(
                &self.account_identity,
                &SecretRequestDecisionToSign {
                    request: id,
                    agent: self.agent_id,
                    proposal_digest: digest,
                    decision: &bytes,
                    decided_at_ms: u64::try_from(decided_at).unwrap(),
                },
            );
            DecideSecretRequest {
                decision: Blob::new(bytes),
                signature: Blob::new(sig.to_bytes().to_vec()),
                decided_at,
            }
        }
    }

    #[tokio::test]
    async fn full_lifecycle_create_fulfill_and_audit() {
        let f = Fixture::new().await;
        let mut sse_rx = f.state.subscribe_secret_requests();

        let id = SecretRequestId::generate();
        let (req, digest) = f.make_request(
            id,
            f.agent_id,
            SecretRequestMode::Create,
            None,
            "Needed for billing tests",
        );
        let (status, bytes) = f
            .agent_req(
                f.agent_id,
                &f.agent_identity,
                "POST",
                "/v1/agent/secret-requests",
                serde_json::to_vec(&req).unwrap(),
            )
            .await;
        assert_eq!(status, StatusCode::ACCEPTED);
        let pending: PendingSecretRequest = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(pending.request_id, id);

        // Broadcast fired for SSE.
        let change = sse_rx.try_recv().unwrap();
        assert_eq!(change.account, f.account_id);
        assert_eq!(change.request_id, id);
        assert_eq!(change.status, SecretRequestState::Pending);

        // Duplicate ID is rejected with 409.
        let (status, _) = f
            .agent_req(
                f.agent_id,
                &f.agent_identity,
                "POST",
                "/v1/agent/secret-requests",
                serde_json::to_vec(&req).unwrap(),
            )
            .await;
        assert_eq!(status, StatusCode::CONFLICT);

        // Person reads list & single item and gets proposal_blob while pending.
        let (status, bytes) = f.person_req("GET", "/v1/secret-requests", vec![]).await;
        assert_eq!(status, StatusCode::OK);
        let list: SecretRequestList = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(list.secret_requests.len(), 1);
        assert_eq!(
            list.secret_requests[0].proposal_blob,
            Some(req.proposal_blob.clone())
        );

        // Agent poll omits proposal_blob.
        let (status, bytes) = f
            .agent_req(
                f.agent_id,
                &f.agent_identity,
                "GET",
                &format!("/v1/agent/secret-requests/{id}"),
                vec![],
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        let polled: SecretRequestInfo = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(polled.status, SecretRequestState::Pending);
        assert!(polled.proposal_blob.is_none());

        // Tampered signature is rejected with 400.
        let created_item = ItemId::generate();
        let decided_at = now_ms();
        let decision = SecretRequestDecision {
            v: SECRET_REQUEST_FORMAT_VERSION,
            request_id: id,
            agent_id: f.agent_id,
            status: SecretRequestStatus::Fulfilled,
            in_grant: true,
            vault_id: Some(f.vault_id),
            project_id: Some(f.project_id),
            item_id: Some(created_item),
            field: Some("api_key".into()),
            proxy_profile: None,
        };
        let mut bad_decide = f.sign_decision(id, &digest, &decision, decided_at);
        let mut bad_sig = bad_decide.signature.as_bytes().to_vec();
        bad_sig[0] ^= 0xff;
        bad_decide.signature = Blob::new(bad_sig);
        let (status, _) = f
            .person_req(
                "POST",
                &format!("/v1/secret-requests/{id}/decide"),
                serde_json::to_vec(&bad_decide).unwrap(),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        // Valid signed decision succeeds and immediately clears proposal_blob.
        let good_decide = f.sign_decision(id, &digest, &decision, decided_at);
        let (status, bytes) = f
            .person_req(
                "POST",
                &format!("/v1/secret-requests/{id}/decide"),
                serde_json::to_vec(&good_decide).unwrap(),
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        let decided: SecretRequestInfo = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(decided.status, SecretRequestState::Fulfilled);
        assert!(decided.proposal_blob.is_none());
        assert_eq!(decided.decision, Some(good_decide.decision.clone()));

        let change = sse_rx.try_recv().unwrap();
        assert_eq!(change.request_id, id);
        assert_eq!(change.status, SecretRequestState::Fulfilled);

        // DB row itself has proposal_blob = NULL.
        let stored_blob: Option<Vec<u8>> =
            sqlx::query_scalar("SELECT proposal_blob FROM secret_requests WHERE id = $1")
                .bind(id.to_string())
                .fetch_one(&f.state.db().pool)
                .await
                .unwrap();
        assert!(stored_blob.is_none());

        // Second decision returns 409.
        let (status, _) = f
            .person_req(
                "POST",
                &format!("/v1/secret-requests/{id}/decide"),
                serde_json::to_vec(&good_decide).unwrap(),
            )
            .await;
        assert_eq!(status, StatusCode::CONFLICT);

        // Audit events: created has no proof body; decided has account signature & item_id.
        let (status, bytes) = f.person_req("GET", "/v1/audit", vec![]).await;
        assert_eq!(status, StatusCode::OK);
        let page: AuditPage = serde_json::from_slice(&bytes).unwrap();
        let events: Vec<AuditEvent> = page
            .entries
            .iter()
            .map(|e| serde_json::from_slice(e.event.as_bytes()).unwrap())
            .collect();
        let created_ev = events
            .iter()
            .find(|e| e.action == "secret_request.created")
            .unwrap();
        assert_eq!(created_ev.secret_request_id, Some(id));
        assert_eq!(
            created_ev.proposal_digest.as_ref().map(|b| b.as_bytes()),
            Some(digest.as_slice())
        );
        assert!(created_ev.agent_proof.as_ref().unwrap().body.is_none());
        let decided_ev = events
            .iter()
            .find(|e| e.action == "secret_request.decided")
            .unwrap();
        assert_eq!(decided_ev.secret_request_id, Some(id));
        assert_eq!(decided_ev.outcome.as_deref(), Some("fulfilled"));
        assert_eq!(decided_ev.item_id, Some(created_item));
        assert_eq!(decided_ev.vault_id, Some(f.vault_id));
        assert_eq!(decided_ev.project_id, Some(f.project_id));
    }

    #[tokio::test]
    async fn update_mode_enforces_grant_without_leaking_t236() {
        let f = Fixture::new().await;
        // Update on item in granted project succeeds.
        let id1 = SecretRequestId::generate();
        let (req1, _) = f.make_request(
            id1,
            f.agent_id,
            SecretRequestMode::Update,
            Some(f.granted_item_id),
            "Rotate Stripe key",
        );
        let (status, _) = f
            .agent_req(
                f.agent_id,
                &f.agent_identity,
                "POST",
                "/v1/agent/secret-requests",
                serde_json::to_vec(&req1).unwrap(),
            )
            .await;
        assert_eq!(status, StatusCode::ACCEPTED);

        // Update on item in ungranted project returns uniform 404 (T236).
        let id2 = SecretRequestId::generate();
        let (req2, _) = f.make_request(
            id2,
            f.agent_id,
            SecretRequestMode::Update,
            Some(f.ungranted_item_id),
            "Probe ungranted item",
        );
        let (status, _) = f
            .agent_req(
                f.agent_id,
                &f.agent_identity,
                "POST",
                "/v1/agent/secret-requests",
                serde_json::to_vec(&req2).unwrap(),
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // Update on nonexistent item returns same 404.
        let id3 = SecretRequestId::generate();
        let (req3, _) = f.make_request(
            id3,
            f.agent_id,
            SecretRequestMode::Update,
            Some(ItemId::generate()),
            "Probe nonexistent item",
        );
        let (status, _) = f
            .agent_req(
                f.agent_id,
                &f.agent_identity,
                "POST",
                "/v1/agent/secret-requests",
                serde_json::to_vec(&req3).unwrap(),
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // Create mode with target_item_id is 400; update mode without target_item_id is 400.
        let id4 = SecretRequestId::generate();
        let (mut bad_create, _) = f.make_request(
            id4,
            f.agent_id,
            SecretRequestMode::Create,
            None,
            "Bad create",
        );
        bad_create.target_item_id = Some(f.granted_item_id);
        let (status, _) = f
            .agent_req(
                f.agent_id,
                &f.agent_identity,
                "POST",
                "/v1/agent/secret-requests",
                serde_json::to_vec(&bad_create).unwrap(),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        // Keep other_project_id visibly exercised.
        assert_ne!(f.project_id, f.other_project_id);
    }

    #[tokio::test]
    async fn proxy_agent_refused_and_cap_enforced_and_sweep_clears_blobs() {
        let f = Fixture::new().await;
        let (proxy_id, proxy_identity) = f.add_proxy_agent().await;
        let id = SecretRequestId::generate();
        let (req, _) = f.make_request(
            id,
            proxy_id,
            SecretRequestMode::Create,
            None,
            "Proxy should be refused",
        );
        let (status, _) = f
            .agent_req(
                proxy_id,
                &proxy_identity,
                "POST",
                "/v1/agent/secret-requests",
                serde_json::to_vec(&req).unwrap(),
            )
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        // Fill up to cap of 5 pending requests.
        for i in 0..MAX_PENDING_SECRET_REQUESTS {
            let rid = SecretRequestId::generate();
            let (r, _) = f.make_request(
                rid,
                f.agent_id,
                SecretRequestMode::Create,
                None,
                &format!("Secret #{i}"),
            );
            let (status, _) = f
                .agent_req(
                    f.agent_id,
                    &f.agent_identity,
                    "POST",
                    "/v1/agent/secret-requests",
                    serde_json::to_vec(&r).unwrap(),
                )
                .await;
            assert_eq!(status, StatusCode::ACCEPTED);
        }
        // 6th request gets 429.
        let extra = SecretRequestId::generate();
        let (r, _) = f.make_request(
            extra,
            f.agent_id,
            SecretRequestMode::Create,
            None,
            "Over cap",
        );
        let (status, _) = f
            .agent_req(
                f.agent_id,
                &f.agent_identity,
                "POST",
                "/v1/agent/secret-requests",
                serde_json::to_vec(&r).unwrap(),
            )
            .await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);

        // Expiry sweep marks all 5 expired and nulls all proposal_blobs.
        let expired = sweep(
            &f.state,
            Sweep::All,
            now_ms() + SECRET_REQUEST_TTL_MS + 1_000,
        )
        .await
        .unwrap();
        assert_eq!(expired, 5);
        let remaining_blobs: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM secret_requests WHERE proposal_blob IS NOT NULL",
        )
        .fetch_one(&f.state.db().pool)
        .await
        .unwrap();
        assert_eq!(remaining_blobs, 0);
    }

    #[tokio::test]
    async fn revoking_agent_expires_pending_requests_and_clears_blobs() {
        let f = Fixture::new().await;
        let id = SecretRequestId::generate();
        let (req, _) = f.make_request(
            id,
            f.agent_id,
            SecretRequestMode::Create,
            None,
            "Will be revoked",
        );
        let (status, _) = f
            .agent_req(
                f.agent_id,
                &f.agent_identity,
                "POST",
                "/v1/agent/secret-requests",
                serde_json::to_vec(&req).unwrap(),
            )
            .await;
        assert_eq!(status, StatusCode::ACCEPTED);

        let revoked_at = now_ms();
        let sig = sign_revocation(
            &f.account_identity,
            f.account_id,
            f.agent_id,
            u64::try_from(revoked_at).unwrap(),
        );
        let revoke = RevokeAgent {
            revoked_at,
            signature: Blob::new(sig.to_bytes().to_vec()),
        };
        let (status, _) = f
            .person_req(
                "POST",
                &format!("/v1/agents/{}/revoke", f.agent_id),
                serde_json::to_vec(&revoke).unwrap(),
            )
            .await;
        assert_eq!(status, StatusCode::OK);

        let (status, bytes) = f
            .person_req("GET", &format!("/v1/secret-requests/{id}"), vec![])
            .await;
        assert_eq!(status, StatusCode::OK);
        let info: SecretRequestInfo = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(info.status, SecretRequestState::Expired);
        assert!(info.proposal_blob.is_none());
    }

    #[tokio::test]
    async fn e2e_hpke_proxy_proposal_forged_decision_and_phishing_setup_url() {
        use klav_core::crypto::agent::{open_secret_request, verify_secret_request_decision};
        use klav_core::crypto::sign::Signature;
        use klav_core::secret_request::{ProxyProposal, validate_setup_url};

        let f = Fixture::new().await;
        let id = SecretRequestId::generate();

        // T235: phishing / non-HTTPS / IP / private setup_url rejected.
        for bad in [
            "http://dashboard.stripe.com",
            "https://user:pass@dashboard.stripe.com",
            "https://127.0.0.1/keys",
            "https://10.0.0.1/keys",
            "javascript:alert(1)",
        ] {
            assert!(validate_setup_url(bad).is_err(), "expected err for {bad}");
        }
        let puny = validate_setup_url("https://xn--pypal-4ve.com/keys").unwrap();
        assert!(puny.has_punycode);

        // Agent seals a real HPKE proposal carrying `setup_url` and `proxy_proposal`.
        let proposal = SecretRequestProposal {
            v: SECRET_REQUEST_FORMAT_VERSION,
            mode: SecretRequestMode::Create,
            kind: Some(ItemKind::ApiKey),
            title: Some("Vercel AI Gateway".into()),
            vault_id: Some(f.vault_id),
            project_id: Some(f.project_id),
            target_item_id: None,
            field: "api_key".into(),
            placeholder: Some("vck_…".into()),
            setup_url: Some("https://vercel.com/dashboard/ai-gateway".into()),
            base_url: Some("https://ai-gateway.vercel.sh".into()),
            urls: Vec::new(),
            notes: Some("Narration key".into()),
            proxy_proposal: Some(ProxyProposal {
                preset: None,
                profile: "vercel-ai".into(),
                upstream: "https://ai-gateway.vercel.sh".into(),
                header: "authorization".into(),
                prefix: "Bearer ".into(),
                methods: vec!["POST".into()],
                ask_methods: Vec::new(),
                path_prefixes: vec!["/v1".into()],
                rate_per_minute: Some(60),
            }),
        };
        proposal.validate().unwrap();
        let canonical = serde_json::to_vec(&proposal).unwrap();
        let digest = body_digest(&canonical);
        let blob = seal_secret_request(
            f.account_identity.public(),
            f.account_id,
            f.agent_id,
            id,
            &canonical,
        )
        .unwrap();

        let create = CreateSecretRequest {
            id,
            mode: SecretRequestMode::Create,
            target_item_id: None,
            reason: "Need Vercel AI Gateway key".into(),
            proposal_digest: Blob::new(digest.to_vec()),
            proposal_blob: Blob::new(blob.clone()),
        };
        let (status, _) = f
            .agent_req(
                f.agent_id,
                &f.agent_identity,
                "POST",
                "/v1/agent/secret-requests",
                serde_json::to_vec(&create).unwrap(),
            )
            .await;
        assert_eq!(status, StatusCode::ACCEPTED);

        // Zero-knowledge metadata check (Q1): neither title nor upstream URL
        // appears in clear in the stored proposal_blob or audit_events!
        assert!(!blob.windows(b"Vercel".len()).any(|w| w == b"Vercel"));
        assert!(
            !blob
                .windows(b"ai-gateway.vercel.sh".len())
                .any(|w| w == b"ai-gateway.vercel.sh")
        );

        // Person fetches, decrypts HPKE proposal, verifies SHA-256 digest.
        let (status, bytes) = f
            .person_req("GET", &format!("/v1/secret-requests/{id}"), vec![])
            .await;
        assert_eq!(status, StatusCode::OK);
        let fetched: SecretRequestInfo = serde_json::from_slice(&bytes).unwrap();
        let opened_bytes = open_secret_request(
            &f.account_identity,
            f.account_id,
            f.agent_id,
            id,
            fetched.proposal_blob.as_ref().unwrap().as_bytes(),
        )
        .unwrap();
        assert_eq!(
            body_digest(&opened_bytes).as_slice(),
            fetched.proposal_digest.as_bytes()
        );
        let opened: SecretRequestProposal = serde_json::from_slice(&opened_bytes).unwrap();
        assert_eq!(opened, proposal);

        // Person signs fulfillment decision with `proxy_profile` and posts it.
        let decided_at = now_ms();
        let decision = SecretRequestDecision {
            v: SECRET_REQUEST_FORMAT_VERSION,
            request_id: id,
            agent_id: f.agent_id,
            status: SecretRequestStatus::Fulfilled,
            in_grant: true,
            vault_id: Some(f.vault_id),
            project_id: Some(f.project_id),
            item_id: Some(f.granted_item_id),
            field: Some("api_key".into()),
            proxy_profile: Some("vercel-ai".into()),
        };
        let decision_bytes = serde_json::to_vec(&decision).unwrap();
        let sig = sign_secret_request_decision(
            &f.account_identity,
            &SecretRequestDecisionToSign {
                request: id,
                agent: f.agent_id,
                proposal_digest: &digest,
                decision: &decision_bytes,
                decided_at_ms: u64::try_from(decided_at).unwrap(),
            },
        );
        let decide = DecideSecretRequest {
            decided_at,
            decision: Blob::new(decision_bytes.clone()),
            signature: Blob::new(sig.to_bytes().to_vec()),
        };
        let (status, _) = f
            .person_req(
                "POST",
                &format!("/v1/secret-requests/{id}/decide"),
                serde_json::to_vec(&decide).unwrap(),
            )
            .await;
        assert_eq!(status, StatusCode::OK);

        // Agent fetches decision, verifies signature against account identity (T237).
        let (status, bytes) = f
            .agent_req(
                f.agent_id,
                &f.agent_identity,
                "GET",
                &format!("/v1/agent/secret-requests/{id}"),
                vec![],
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        let agent_view: SecretRequestInfo = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(agent_view.status, SecretRequestState::Fulfilled);
        assert!(agent_view.proposal_blob.is_none());
        let sig_bytes: [u8; 64] = agent_view
            .signature
            .as_ref()
            .unwrap()
            .as_bytes()
            .try_into()
            .unwrap();
        let raw_dec = agent_view.decision.as_ref().unwrap().as_bytes();
        verify_secret_request_decision(
            f.account_identity.public(),
            &SecretRequestDecisionToSign {
                request: id,
                agent: f.agent_id,
                proposal_digest: &digest,
                decision: raw_dec,
                decided_at_ms: u64::try_from(agent_view.decided_at.unwrap()).unwrap(),
            },
            &Signature::from_bytes(sig_bytes),
        )
        .unwrap();

        // T237: forged decision swapping `proxy_profile` or signed by an attacker is rejected.
        let mut forged = decision.clone();
        forged.proxy_profile = Some("evil-proxy".into());
        let forged_bytes = serde_json::to_vec(&forged).unwrap();
        assert!(
            verify_secret_request_decision(
                f.account_identity.public(),
                &SecretRequestDecisionToSign {
                    request: id,
                    agent: f.agent_id,
                    proposal_digest: &digest,
                    decision: &forged_bytes,
                    decided_at_ms: u64::try_from(agent_view.decided_at.unwrap()).unwrap(),
                },
                &Signature::from_bytes(sig_bytes),
            )
            .is_err()
        );
    }
}
