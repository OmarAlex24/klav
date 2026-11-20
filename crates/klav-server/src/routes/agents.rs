//! Agents (design §5.1): registration, the person's approval with a signed
//! grant, and the agent's view of itself.
//!
//! * `POST /v1/agents/register`: the agent registers (no authentication).
//!   The answer is the same for every e-mail, so it does not reveal which
//!   accounts exist; requests for unknown e-mails are simply not stored.
//! * `GET /v1/agents`, `GET /v1/agents/{id}`, `POST /v1/agents/{id}/grant`,
//!   `POST /v1/agents/{id}/deny`, `POST /v1/agents/{id}/revoke`: the person
//!   (bearer session).
//! * `POST /v1/agents/pause`, `POST /v1/agents/{id}/pause`: the person
//!   pauses or resumes every agent, or one, with a decision signed by the
//!   account (ADR 0033 §7, spec §13.9).
//! * `GET /v1/agent/me`: the agent (signed request), in any state.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use klav_core::crypto::agent::{self as agent_crypto, GrantToSign, PauseScope, PauseToSign};
use klav_core::crypto::encoding::Kind;
use klav_core::crypto::identity::PublicIdentity;
use klav_core::crypto::share::SHARED_KEY_LEN;
use klav_core::crypto::sign::{SIGNATURE_LEN, Signature};
use klav_core::ids::{AccountId, AgentId};
use klav_proto::Blob;
use klav_proto::agent::{
    AgentInfo, AgentList, AgentMe, AgentPauses, AgentStatus, GrantPayload, PauseAgents, PauseState,
    RegisterAgent, RegisterAgentResponse, RevokeAgent, SignedGrant,
};
use klav_proto::audit::{ActorKind, AuditEvent};
use sqlx::Row;
use sqlx::any::AnyRow;

use crate::agentauth::{AgentAuth, effective_status};
use crate::audit;
use crate::db::now_ms;
use crate::error::{ApiError, ApiJson, ApiResult};
use crate::push::PushKind;
use crate::ratelimit::{ClientIp, Quota};
use crate::session::{Auth, parse_id};
use crate::state::AppState;
use crate::validate;
use crate::vaultdb::{path_id, require_member, to_i64, to_u64};

/// How long a registration waits for the person.
pub(crate) const PENDING_TTL_MS: i64 = 60 * 60 * 1000;
/// Pending registrations kept per account; more are silently dropped.
const MAX_PENDING: i64 = 20;
/// Longest note an agent can attach to its registration.
const MAX_NOTE: usize = 500;

pub(super) fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/agents/register", post(register))
        .route("/v1/agents", get(list))
        .route("/v1/agents/{agent_id}", get(get_one))
        .route("/v1/agents/{agent_id}/grant", post(grant))
        .route("/v1/agents/{agent_id}/deny", post(deny))
        .route("/v1/agents/{agent_id}/revoke", post(revoke))
        .route("/v1/agents/pause", post(pause_all))
        .route("/v1/agents/{agent_id}/pause", post(pause_one))
        .route("/v1/agent/me", get(me))
}

const AGENT_COLUMNS: &str = "id, name, note, public_identity, status, created_at, expires_at, \
     approved_at, revoked_at, last_seen_at, grant_payload, grant_signature";

pub(crate) fn agent_from_row(row: &AnyRow, now: i64) -> ApiResult<AgentInfo> {
    let grant = match (
        row.try_get::<Option<Vec<u8>>, _>("grant_payload")?,
        row.try_get::<Option<Vec<u8>>, _>("grant_signature")?,
    ) {
        (Some(payload), Some(signature)) => Some(SignedGrant {
            payload: Blob::new(payload),
            signature: Blob::new(signature),
        }),
        _ => None,
    };
    let expires_at: i64 = row.try_get("expires_at")?;
    Ok(AgentInfo {
        id: parse_id(&row.try_get::<String, _>("id")?)?,
        name: row.try_get("name")?,
        note: row.try_get("note")?,
        public_identity: Blob::new(row.try_get("public_identity")?),
        status: effective_status(&row.try_get::<String, _>("status")?, expires_at, now)?,
        created_at: row.try_get("created_at")?,
        expires_at,
        approved_at: row.try_get("approved_at")?,
        revoked_at: row.try_get("revoked_at")?,
        last_seen_at: row.try_get("last_seen_at")?,
        grant,
        paused: None,
    })
}

/// Fills [`AgentInfo::paused`] for the agents a pause can hold: active
/// ones and pending ones (a pause on them holds once they are approved).
fn with_pause(mut info: AgentInfo, pauses: &[klav_proto::agent::AgentPause]) -> AgentInfo {
    if matches!(info.status, AgentStatus::Active | AgentStatus::Pending) {
        info.paused = crate::pause::for_agent(pauses, info.id);
    }
    info
}

/// The agent `agent_id` of the caller's account (404 otherwise).
pub(crate) async fn fetch_agent(
    state: &AppState,
    account: AccountId,
    agent_id: AgentId,
) -> ApiResult<AgentInfo> {
    let row = sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT {AGENT_COLUMNS} FROM agents WHERE id = $1 AND account_id = $2"
    )))
    .bind(agent_id.to_string())
    .bind(account.to_string())
    .fetch_optional(&state.db().pool)
    .await?
    .ok_or(ApiError::NotFound)?;
    let now = now_ms();
    let pauses = crate::pause::in_effect(&state.db().pool, account, now).await?;
    Ok(with_pause(agent_from_row(&row, now)?, &pauses))
}

async fn register(
    State(state): State<AppState>,
    Extension(ip): Extension<ClientIp>,
    ApiJson(req): ApiJson<RegisterAgent>,
) -> ApiResult<(StatusCode, Json<RegisterAgentResponse>)> {
    let rl = &state.config().rate_limit;
    state.limiter().enforce(
        &format!("auth-ip:{}", ip.key()),
        Quota {
            per_minute: rl.auth_ip_per_minute,
            burst: rl.auth_ip_burst,
        },
    )?;
    let email = validate::email(&req.email)?;
    let name = validate::agent_name(&req.name)?;
    let note = req
        .note
        .as_deref()
        .map(str::trim)
        .filter(|n| !n.is_empty())
        .map(str::to_owned);
    if note
        .as_deref()
        .is_some_and(|n| n.chars().count() > MAX_NOTE || n.chars().any(klav_core::text::is_hidden))
    {
        return Err(ApiError::bad_request(
            "note must have at most 500 characters and no control, format or separator characters",
        ));
    }
    validate::exact(
        &req.public_identity,
        Kind::PublicIdentity,
        klav_core::crypto::identity::PUBLIC_IDENTITY_LEN,
        "public_identity",
    )?;
    PublicIdentity::decode(req.public_identity.as_bytes())
        .map_err(|_| ApiError::bad_request("public_identity: invalid public keys"))?;

    let now = now_ms();
    let response = RegisterAgentResponse {
        id: req.id,
        status: AgentStatus::Pending,
        expires_at: now + PENDING_TTL_MS,
    };
    let pool = &state.db().pool;
    // Checked before the e-mail, so a reused ID answers the same for
    // every address.
    let exists: Option<String> = sqlx::query_scalar("SELECT id FROM agents WHERE id = $1")
        .bind(req.id.to_string())
        .fetch_optional(pool)
        .await?;
    if exists.is_some() {
        return Err(ApiError::conflict("agent ID already exists"));
    }
    let account: Option<String> = sqlx::query_scalar("SELECT id FROM accounts WHERE email = $1")
        .bind(&email)
        .fetch_optional(pool)
        .await?;
    let Some(account) = account else {
        // Unknown e-mail: same answer, nothing stored.
        return Ok((StatusCode::ACCEPTED, Json(response)));
    };
    // Count and insert as one step, under the account row's lock (layer 07
    // of the 2026-11 round): concurrent registrations cannot all pass the
    // cap. The lock is an `UPDATE`, which also makes the SQLite
    // transaction a writer from the start.
    let mut tx = pool.begin().await?;
    sqlx::query("UPDATE accounts SET updated_at = updated_at WHERE id = $1")
        .bind(&account)
        .execute(&mut *tx)
        .await?;
    // An account whose deletion the person asked for takes no new agents
    // (ADR 0037 §2). The same answer as an unknown e-mail, and no push:
    // anyone who knows the address must not learn that it is going.
    if crate::deletion::delete_at(&mut *tx, parse_id(&account)?)
        .await?
        .is_some()
    {
        return Ok((StatusCode::ACCEPTED, Json(response)));
    }
    let pending: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM agents WHERE account_id = $1 AND status = $2 AND expires_at > $3",
    )
    .bind(&account)
    .bind(AgentStatus::Pending.as_str())
    .bind(now)
    .fetch_one(&mut *tx)
    .await?;
    if pending >= MAX_PENDING {
        tracing::warn!("too many pending agent registrations; request dropped");
        return Ok((StatusCode::ACCEPTED, Json(response)));
    }
    let inserted = sqlx::query(
        "INSERT INTO agents (id, account_id, name, note, public_identity, status, created_at, \
         expires_at, grant_version) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
         ON CONFLICT DO NOTHING",
    )
    .bind(req.id.to_string())
    .bind(&account)
    .bind(&name)
    .bind(note)
    .bind(req.public_identity.into_bytes())
    .bind(AgentStatus::Pending.as_str())
    .bind(now)
    .bind(response.expires_at)
    .bind(0_i64)
    .execute(&mut *tx)
    .await?;
    if inserted.rows_affected() == 0 {
        // The same ID registered concurrently: the same answer as above.
        return Err(ApiError::conflict("agent ID already exists"));
    }
    // Logged in the registration's own transaction: the person never sees
    // an agent the chain has no `agent.registered` for, even if the handler
    // is dropped (its client went away).
    let mut event = AuditEvent::new(ActorKind::Agent, "agent.registered");
    event.agent_id = Some(req.id);
    let account = parse_id(&account)?;
    audit::append_in(&mut tx, account, &mut event, now_ms()).await?;
    tx.commit().await?;
    state.push(account, PushKind::Agent, req.id.to_string());
    Ok((StatusCode::ACCEPTED, Json(response)))
}

async fn list(State(state): State<AppState>, auth: Auth) -> ApiResult<Json<AgentList>> {
    let rows = sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT {AGENT_COLUMNS} FROM agents WHERE account_id = $1 ORDER BY created_at DESC, id"
    )))
    .bind(auth.account_id.to_string())
    .fetch_all(&state.db().pool)
    .await?;
    let now = now_ms();
    let pauses = crate::pause::in_effect(&state.db().pool, auth.account_id, now).await?;
    let agents = rows
        .iter()
        .map(|row| agent_from_row(row, now).map(|a| with_pause(a, &pauses)))
        .collect::<ApiResult<Vec<_>>>()?;
    Ok(Json(AgentList { agents }))
}

async fn get_one(
    State(state): State<AppState>,
    auth: Auth,
    Path(agent_id): Path<String>,
) -> ApiResult<Json<AgentInfo>> {
    let agent_id: AgentId = path_id(&agent_id)?;
    Ok(Json(fetch_agent(&state, auth.account_id, agent_id).await?))
}

/// The account's public identity.
pub(crate) async fn account_identity(
    state: &AppState,
    account: AccountId,
) -> ApiResult<PublicIdentity> {
    let bytes: Vec<u8> = sqlx::query_scalar("SELECT public_identity FROM accounts WHERE id = $1")
        .bind(account.to_string())
        .fetch_one(&state.db().pool)
        .await?;
    PublicIdentity::decode(&bytes).map_err(|_| ApiError::Internal("corrupt account".into()))
}

/// Checks a grant: payload format, account and agent, next version, ID-only
/// scopes, projects the account can open, key blobs, and the account's
/// signature (defence in depth: the agent verifies it too).
async fn check_grant(
    state: &AppState,
    auth: &Auth,
    agent: &AgentInfo,
    current_version: i64,
    grant: &SignedGrant,
) -> ApiResult<GrantPayload> {
    let payload: GrantPayload = serde_json::from_slice(grant.payload.as_bytes())
        .map_err(|e| ApiError::bad_request(format!("grant payload: {e}")))?;
    // Version 1, or version 2 with its rules (ADR 0036 §2): items without
    // projects, profiles for granted items, `proxy` rules that name their
    // items and hosts, and `reveal`, `inject` and `fill` always denied.
    payload
        .check_format()
        .map_err(|e| ApiError::bad_request(format!("grant payload: {e}")))?;
    if payload.account_id != auth.account_id || payload.agent_id != agent.id {
        return Err(ApiError::bad_request(
            "grant payload: wrong account or agent",
        ));
    }
    if payload.version != to_u64(current_version) + 1 {
        return Err(ApiError::stale(current_version));
    }
    // `passkey` and `rotate` only exist inside a task (ADR 0021 §5).
    payload
        .policy
        .check_grantable()
        .map_err(|e| ApiError::bad_request(e.to_string()))?;
    if !payload.policy.rules.iter().all(|r| r.scope.uses_ids_only()) {
        return Err(ApiError::bad_request(
            "grant policy: name vaults and projects by ID (the server cannot read names)",
        ));
    }
    // A sandbox issuer (`v: 3`, ADR 0036 §4) holds no keys: its grant only
    // says which proxy it talks to.
    if payload.projects.is_empty() && payload.items.is_empty() && payload.sandbox.is_none() {
        return Err(ApiError::bad_request(
            "a grant needs at least one project or item",
        ));
    }
    // The agents a `v: 3` grant names are of this account.
    let named = payload.issuers.iter().map(|i| i.agent_id).chain(
        payload
            .sandbox
            .as_ref()
            .and_then(|s| s.proxy.as_ref())
            .map(|p| p.agent_id),
    );
    for other in named {
        let found: Option<String> =
            sqlx::query_scalar("SELECT id FROM agents WHERE id = $1 AND account_id = $2")
                .bind(other.to_string())
                .bind(auth.account_id.to_string())
                .fetch_optional(&state.db().pool)
                .await?;
        if found.is_none() {
            return Err(ApiError::bad_request(format!(
                "grant: agent {other} is not an agent of this account"
            )));
        }
    }
    // An item in the trash may stay in a grant: a grant re-issued after a
    // new item key keeps every item it had (ADR 0036 §18), and a trashed
    // item is not reachable through `access` anyway. Purged items, and
    // deleted projects and vaults, are refused.
    for item in &payload.items {
        require_member(state, item.vault_id, auth.account_id).await?;
        let found: Option<String> = sqlx::query_scalar(
            "SELECT v.owner_account_id FROM items i JOIN vaults v ON v.id = i.vault_id \
             JOIN projects p ON p.id = i.project_id \
             WHERE i.id = $1 AND i.vault_id = $2 AND i.project_id = $3 AND i.purged_at IS NULL \
             AND p.deleted_at IS NULL AND v.deleted_at IS NULL",
        )
        .bind(item.item_id.to_string())
        .bind(item.vault_id.to_string())
        .bind(item.project_id.to_string())
        .fetch_optional(&state.db().pool)
        .await?;
        if found != Some(item.owner_account_id.to_string()) {
            return Err(ApiError::bad_request(format!(
                "grant: item {} not found in project {} of vault {}",
                item.item_id, item.project_id, item.vault_id
            )));
        }
        validate::exact(
            &item.shared_key,
            Kind::SharedItemKey,
            SHARED_KEY_LEN,
            "shared_key",
        )?;
    }
    for project in &payload.projects {
        require_member(state, project.vault_id, auth.account_id).await?;
        let owner: Option<String> = sqlx::query_scalar(
            "SELECT v.owner_account_id FROM projects p JOIN vaults v ON v.id = p.vault_id \
             WHERE p.id = $1 AND p.vault_id = $2 AND p.deleted_at IS NULL \
             AND v.deleted_at IS NULL",
        )
        .bind(project.project_id.to_string())
        .bind(project.vault_id.to_string())
        .fetch_optional(&state.db().pool)
        .await?;
        if owner != Some(project.owner_account_id.to_string()) {
            return Err(ApiError::bad_request(format!(
                "grant: project {} not found in vault {}",
                project.project_id, project.vault_id
            )));
        }
        validate::exact(
            &project.shared_key,
            Kind::SharedProjectKey,
            SHARED_KEY_LEN,
            "shared_key",
        )?;
        validate::sized(
            &project.labels,
            Kind::GrantLabels,
            klav_core::crypto::aead::OVERHEAD,
            klav_proto::agent::MAX_LABELS_BLOB,
            "labels",
        )?;
    }
    let signature: [u8; SIGNATURE_LEN] = grant
        .signature
        .as_bytes()
        .try_into()
        .map_err(|_| ApiError::bad_request("grant signature: expected 64 bytes"))?;
    let agent_public = PublicIdentity::decode(agent.public_identity.as_bytes())
        .map_err(|_| ApiError::Internal("corrupt agent identity".into()))?;
    agent_crypto::verify_grant(
        &account_identity(state, auth.account_id).await?,
        &GrantToSign {
            account: auth.account_id,
            agent: agent.id,
            agent_public: &agent_public,
            payload: grant.payload.as_bytes(),
        },
        &Signature::from_bytes(signature),
    )
    .map_err(|_| ApiError::bad_request("grant signature does not verify"))?;
    Ok(payload)
}

/// Approves a pending agent, or replaces the grant of an active one.
async fn grant(
    State(state): State<AppState>,
    auth: Auth,
    Path(agent_id): Path<String>,
    ApiJson(grant): ApiJson<SignedGrant>,
) -> ApiResult<Json<AgentInfo>> {
    let agent_id: AgentId = path_id(&agent_id)?;
    let agent = fetch_agent(&state, auth.account_id, agent_id).await?;
    if !matches!(agent.status, AgentStatus::Pending | AgentStatus::Active) {
        return Err(ApiError::conflict(
            "the agent is denied or revoked: it must register again",
        ));
    }
    let current: i64 = sqlx::query_scalar("SELECT grant_version FROM agents WHERE id = $1")
        .bind(agent_id.to_string())
        .fetch_one(&state.db().pool)
        .await?;
    let payload = check_grant(&state, &auth, &agent, current, &grant).await?;

    let now = now_ms();
    let mut tx = state.db().pool.begin().await?;
    // The account's lock first, as every other write that logs in its own
    // transaction takes it (`audit::append_in` takes it again below).
    sqlx::query("UPDATE accounts SET updated_at = updated_at WHERE id = $1")
        .bind(auth.account_id.to_string())
        .execute(&mut *tx)
        .await?;
    let updated = sqlx::query(
        "UPDATE agents SET status = $1, grant_version = $2, grant_payload = $3, \
         grant_signature = $4, granted_at = $5, approved_at = COALESCE(approved_at, $5) \
         WHERE id = $6 AND grant_version = $7 AND status IN ('pending', 'active')",
    )
    .bind(AgentStatus::Active.as_str())
    .bind(to_i64(payload.version)?)
    .bind(grant.payload.as_bytes().to_vec())
    .bind(grant.signature.as_bytes().to_vec())
    .bind(now)
    .bind(agent_id.to_string())
    .bind(current)
    .execute(&mut *tx)
    .await?;
    if updated.rows_affected() != 1 {
        return Err(ApiError::stale(current));
    }
    sqlx::query("DELETE FROM agent_projects WHERE agent_id = $1")
        .bind(agent_id.to_string())
        .execute(&mut *tx)
        .await?;
    for project in &payload.projects {
        sqlx::query(
            "INSERT INTO agent_projects (agent_id, vault_id, project_id) VALUES ($1, $2, $3)",
        )
        .bind(agent_id.to_string())
        .bind(project.vault_id.to_string())
        .bind(project.project_id.to_string())
        .execute(&mut *tx)
        .await?;
    }
    // Requests asked under the old grant are void.
    sqlx::query(
        "UPDATE approvals SET status = 'expired' WHERE agent_id = $1 AND status = 'pending'",
    )
    .bind(agent_id.to_string())
    .execute(&mut *tx)
    .await?;
    // Logged in the grant's own transaction: an agent is never active
    // without the `agent.granted` that vouches for its key in the person's
    // chain, even if the handler is dropped (its client went away).
    let mut event = AuditEvent::new(ActorKind::Person, "agent.granted");
    event.device_id = Some(auth.device_id);
    event.agent_id = Some(agent_id);
    event.signed = Some(grant.payload.clone());
    event.account_signature = Some(grant.signature.clone());
    audit::append_in(&mut tx, auth.account_id, &mut event, now).await?;
    tx.commit().await?;
    Ok(Json(fetch_agent(&state, auth.account_id, agent_id).await?))
}

/// Rejects a pending registration.
async fn deny(
    State(state): State<AppState>,
    auth: Auth,
    Path(agent_id): Path<String>,
) -> ApiResult<StatusCode> {
    let agent_id: AgentId = path_id(&agent_id)?;
    let agent = fetch_agent(&state, auth.account_id, agent_id).await?;
    if agent.status != AgentStatus::Pending {
        return Err(ApiError::conflict(
            "only pending registrations can be denied",
        ));
    }
    let mut tx = state.db().pool.begin().await?;
    // The account's lock first, as every write that logs in its own
    // transaction takes it before the agent's row (`audit::append_in`
    // takes it again below).
    crate::deletion::lock_account(&mut tx, auth.account_id).await?;
    let denied = sqlx::query("UPDATE agents SET status = $1 WHERE id = $2 AND status = $3")
        .bind(AgentStatus::Denied.as_str())
        .bind(agent_id.to_string())
        .bind(AgentStatus::Pending.as_str())
        .execute(&mut *tx)
        .await?;
    if denied.rows_affected() != 1 {
        // Denied (or approved) meanwhile: one `agent.denied` at most.
        return Err(ApiError::conflict(
            "only pending registrations can be denied",
        ));
    }
    // Logged in the same transaction: a denied agent always has its
    // `agent.denied` in the chain, even if the handler is dropped.
    let mut event = AuditEvent::new(ActorKind::Person, "agent.denied");
    event.device_id = Some(auth.device_id);
    event.agent_id = Some(agent_id);
    audit::append_in(&mut tx, auth.account_id, &mut event, now_ms()).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Revokes an agent: signed by the account (spec §13.6), effective on the
/// agent's next request; its pending approval requests are denied.
async fn revoke(
    State(state): State<AppState>,
    auth: Auth,
    Path(agent_id): Path<String>,
    ApiJson(req): ApiJson<RevokeAgent>,
) -> ApiResult<Json<AgentInfo>> {
    let agent_id: AgentId = path_id(&agent_id)?;
    let agent = fetch_agent(&state, auth.account_id, agent_id).await?;
    match agent.status {
        AgentStatus::Active => {}
        AgentStatus::Pending => {
            return Err(ApiError::conflict(
                "the agent was never approved: deny its registration instead",
            ));
        }
        other => {
            return Err(ApiError::conflict(format!(
                "the agent is already {}",
                other.as_str()
            )));
        }
    }
    let now = now_ms();
    if (req.revoked_at - now).abs() > crate::agentauth::CLOCK_SKEW_MS {
        return Err(ApiError::bad_request(
            "revoked_at is too far from the server's clock",
        ));
    }
    let signature: [u8; SIGNATURE_LEN] = req
        .signature
        .as_bytes()
        .try_into()
        .map_err(|_| ApiError::bad_request("signature: expected 64 bytes"))?;
    let account = account_identity(&state, auth.account_id).await?;
    agent_crypto::verify_revocation(
        &account,
        auth.account_id,
        agent_id,
        u64::try_from(req.revoked_at).map_err(|_| ApiError::bad_request("revoked_at"))?,
        &Signature::from_bytes(signature),
    )
    .map_err(|_| ApiError::bad_request("the revocation's signature does not verify"))?;
    let mut tx = state.db().pool.begin().await?;
    // The account's lock first, as every write that logs in its own
    // transaction takes it before the agent's row (`audit::append_in`
    // takes it again below).
    crate::deletion::lock_account(&mut tx, auth.account_id).await?;
    let updated =
        sqlx::query("UPDATE agents SET status = $1, revoked_at = $2 WHERE id = $3 AND status = $4")
            .bind(AgentStatus::Revoked.as_str())
            .bind(req.revoked_at)
            .bind(agent_id.to_string())
            .bind(AgentStatus::Active.as_str())
            .execute(&mut *tx)
            .await?;
    if updated.rows_affected() != 1 {
        return Err(ApiError::conflict("the agent changed meanwhile: try again"));
    }
    sqlx::query(
        "UPDATE approvals SET status = 'denied', decided_at = $1 \
         WHERE agent_id = $2 AND status = 'pending'",
    )
    .bind(now)
    .bind(agent_id.to_string())
    .execute(&mut *tx)
    .await?;
    // The agent's running tasks end with it (ADR 0021 §5).
    let ended = crate::routes::tasks::end_on_revocation(&mut tx, agent_id, now).await?;
    // Logged in the revocation's own transaction, `agent.revoked` and then
    // each `task.ended` it caused: none of them is lost if the handler is
    // dropped (its client went away), and none is logged for a revocation
    // that did not commit.
    let mut event = AuditEvent::new(ActorKind::Person, "agent.revoked");
    event.device_id = Some(auth.device_id);
    event.agent_id = Some(agent_id);
    event.decided_at = Some(req.revoked_at);
    event.account_signature = Some(Blob::new(signature.to_vec()));
    audit::append_in(&mut tx, auth.account_id, &mut event, now_ms()).await?;
    crate::routes::tasks::log_revocation_ends(&mut tx, &auth, agent_id, &ended, now).await?;
    tx.commit().await?;
    for task in &ended {
        state.task_changed(*task);
    }
    fetch_agent(&state, auth.account_id, agent_id)
        .await
        .map(Json)
}

/// The agent's own state and grant, the pause that holds it and the
/// deletion of the account, if any: the one route a paused agent, or one
/// whose account is being deleted, can still call (ADR 0033 §7.4, ADR 0037
/// §3).
async fn me(State(state): State<AppState>, auth: AgentAuth) -> ApiResult<Json<AgentMe>> {
    let account_public = account_identity(&state, auth.account_id).await?;
    let (grant, paused, payload) = if auth.status == AgentStatus::Active {
        let info = fetch_agent(&state, auth.account_id, auth.agent_id).await?;
        let payload: Option<GrantPayload> = info
            .grant
            .as_ref()
            .and_then(|g| serde_json::from_slice(g.payload.as_bytes()).ok());
        (info.grant, info.paused, payload)
    } else {
        (None, None, None)
    };
    // A proxy ends the sandboxes of an issuer the person removed or
    // revoked (ADR 0036 E3.3, Q-C).
    let gone_issuers = crate::routes::sandboxes::gone_issuers(
        &state,
        auth.account_id,
        auth.agent_id,
        payload.as_ref(),
    )
    .await?;
    // A pending request that lapsed reads as denied (`effective_status`);
    // say so, so the agent can ask again instead of treating it as the
    // person's decision (ADR 0033 E2.2).
    let lapsed = if auth.status == AgentStatus::Denied {
        let row = sqlx::query("SELECT status FROM agents WHERE id = $1")
            .bind(auth.agent_id.to_string())
            .fetch_one(&state.db().pool)
            .await?;
        row.try_get::<String, _>("status")? == AgentStatus::Pending.as_str()
    } else {
        false
    };
    // Why everything else is refused while the deletion is asked for
    // (ADR 0037 §3).
    let account_delete_at = crate::deletion::delete_at(&state.db().pool, auth.account_id).await?;
    Ok(Json(AgentMe {
        id: auth.agent_id,
        name: auth.name,
        status: auth.status,
        lapsed,
        account_id: auth.account_id,
        account_public_identity: Blob::new(account_public.encode().to_vec()),
        grant,
        paused,
        account_delete_at,
        gone_issuers,
    }))
}

/// Pauses or resumes every agent of the account.
async fn pause_all(
    State(state): State<AppState>,
    auth: Auth,
    ApiJson(req): ApiJson<PauseAgents>,
) -> ApiResult<Json<AgentPauses>> {
    decide_pause(&state, &auth, PauseScope::All, req).await
}

/// Pauses or resumes one agent.
async fn pause_one(
    State(state): State<AppState>,
    auth: Auth,
    Path(agent_id): Path<String>,
    ApiJson(req): ApiJson<PauseAgents>,
) -> ApiResult<Json<AgentPauses>> {
    let agent_id: AgentId = path_id(&agent_id)?;
    let agent = fetch_agent(&state, auth.account_id, agent_id).await?;
    if matches!(agent.status, AgentStatus::Denied | AgentStatus::Revoked) {
        return Err(ApiError::conflict(format!(
            "the agent is {}: there is nothing to pause or resume",
            agent.status.as_str()
        )));
    }
    decide_pause(&state, &auth, PauseScope::Agent(agent_id), req).await
}

/// A pause or a resume (spec §13.9): signed by the account, within ±5 min
/// of the server's clock, and later than the last decision on the same
/// scope, so an old resume cannot be replayed. The decision and its audit
/// event are written in one transaction, under the account's lock: the
/// chain orders them exactly as the database does. A resume of a scope
/// that is not paused is accepted (it moves the scope's clock forward and
/// is logged); resuming every agent does not lift the pauses of single
/// agents.
async fn decide_pause(
    state: &AppState,
    auth: &Auth,
    scope: PauseScope,
    req: PauseAgents,
) -> ApiResult<Json<AgentPauses>> {
    let now = now_ms();
    // `abs_diff`: a made-up `at` near `i64::MIN` or `MAX` must not overflow.
    if req.at.abs_diff(now) > crate::agentauth::CLOCK_SKEW_MS.unsigned_abs() {
        return Err(ApiError::bad_request(
            "at is too far from the server's clock",
        ));
    }
    let pause = req.state == PauseState::Pause;
    if !pause && req.until != 0 {
        return Err(ApiError::bad_request("a resume has no until"));
    }
    if pause && req.until != 0 && req.until <= now.max(req.at) {
        return Err(ApiError::bad_request("until is already past"));
    }
    let signature: [u8; SIGNATURE_LEN] = req
        .signature
        .as_bytes()
        .try_into()
        .map_err(|_| ApiError::bad_request("signature: expected 64 bytes"))?;
    let account = account_identity(state, auth.account_id).await?;
    agent_crypto::verify_pause(
        &account,
        &PauseToSign {
            account: auth.account_id,
            scope,
            pause,
            at_ms: u64::try_from(req.at).map_err(|_| ApiError::bad_request("at"))?,
            until_ms: u64::try_from(req.until).map_err(|_| ApiError::bad_request("until"))?,
        },
        &Signature::from_bytes(signature),
    )
    .map_err(|_| ApiError::bad_request("the pause's signature does not verify"))?;
    let (scope_key, agent_id) = match scope {
        PauseScope::All => (crate::pause::SCOPE_ALL.to_owned(), None),
        PauseScope::Agent(agent) => (agent.to_string(), Some(agent)),
    };
    let state_text = if pause {
        crate::pause::STATE_PAUSE
    } else {
        crate::pause::STATE_RESUME
    };
    let mut tx = state.db().pool.begin().await?;
    // The account's lock first: decisions on a scope, and the agents'
    // allowed actions, are serialised behind it (ADR 0033 §7.6).
    sqlx::query("UPDATE accounts SET updated_at = updated_at WHERE id = $1")
        .bind(auth.account_id.to_string())
        .execute(&mut *tx)
        .await?;
    let last: Option<i64> =
        sqlx::query_scalar("SELECT at_ms FROM agent_pauses WHERE account_id = $1 AND scope = $2")
            .bind(auth.account_id.to_string())
            .bind(&scope_key)
            .fetch_optional(&mut *tx)
            .await?;
    match last {
        // `last_at` in the body: a device whose pause was decided before
        // this decision reached the server (Klav locked, ADR 0033 §7.5)
        // signs it again after it, rather than dropping it.
        Some(last) if req.at <= last => return Err(ApiError::LaterPause(last)),
        Some(_) => {
            sqlx::query(
                "UPDATE agent_pauses SET state = $1, at_ms = $2, until_ms = $3, \
                 signature = $4, device_id = $5 WHERE account_id = $6 AND scope = $7",
            )
            .bind(state_text)
            .bind(req.at)
            .bind(req.until)
            .bind(signature.to_vec())
            .bind(auth.device_id.to_string())
            .bind(auth.account_id.to_string())
            .bind(&scope_key)
            .execute(&mut *tx)
            .await?;
        }
        None => {
            sqlx::query(
                "INSERT INTO agent_pauses (account_id, scope, state, at_ms, until_ms, \
                 signature, device_id) VALUES ($1, $2, $3, $4, $5, $6, $7)",
            )
            .bind(auth.account_id.to_string())
            .bind(&scope_key)
            .bind(state_text)
            .bind(req.at)
            .bind(req.until)
            .bind(signature.to_vec())
            .bind(auth.device_id.to_string())
            .execute(&mut *tx)
            .await?;
        }
    }
    let mut event = AuditEvent::new(
        ActorKind::Person,
        if pause {
            "agents.paused"
        } else {
            "agents.resumed"
        },
    );
    event.device_id = Some(auth.device_id);
    event.agent_id = agent_id;
    event.decided_at = Some(req.at);
    event.until = (req.until != 0).then_some(req.until);
    event.account_signature = Some(Blob::new(signature.to_vec()));
    audit::append_in(&mut tx, auth.account_id, &mut event, now).await?;
    tx.commit().await?;
    // The person's other devices learn it on their next sync (`GET
    // /v1/sync` lists the pauses in effect, ADR 0033 §7.2).
    let pauses = crate::pause::in_effect(&state.db().pool, auth.account_id, now).await?;
    Ok(Json(AgentPauses { pauses }))
}
