//! Reading the audit log, storing signed chain heads and the person's own
//! events (design §6, `docs/api.md` §9).

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use klav_core::crypto::audit::verify_head;
use klav_core::crypto::sign::{SIGNATURE_LEN, Signature};
use klav_core::ids::{AgentId, ProjectId, VaultId};
use klav_proto::Blob;
use klav_proto::audit::{
    ActorKind, AuditEntry, AuditEvent, AuditHead, AuditHeads, AuditPage, AuditQuery,
    PERSON_ACTIONS, PersonEvent, SignHead,
};
use sqlx::Row;

use crate::audit;
use crate::db::now_ms;
use crate::error::{ApiError, ApiJson, ApiQuery, ApiResult};
use crate::ratelimit::Quota;
use crate::routes::agents::account_identity;
use crate::session::{Auth, parse_id};
use crate::state::AppState;
use crate::vaultdb::{require_member, to_i64, to_u64};

/// Page size of `GET /v1/audit`.
const PAGE: u32 = 1000;

/// `POST /v1/audit/person` per device, on top of the account's quota: a
/// device that signs in with passkeys all day stays well below it; one
/// that floods the chain does not get far.
const PERSON_EVENTS: Quota = Quota {
    per_minute: 60,
    burst: 30,
};

pub(super) fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/audit", get(events))
        .route("/v1/audit/heads", get(heads).post(sign_head))
        .route("/v1/audit/person", post(person_event))
}

async fn events(
    State(state): State<AppState>,
    auth: Auth,
    ApiQuery(query): ApiQuery<AuditQuery>,
) -> ApiResult<Json<AuditPage>> {
    let limit = i64::from(query.limit.unwrap_or(PAGE).clamp(1, PAGE));
    let rows = sqlx::query(
        "SELECT seq, event, hash FROM audit_events WHERE account_id = $1 AND seq > $2 \
         ORDER BY seq LIMIT $3",
    )
    .bind(auth.account_id.to_string())
    .bind(to_i64(query.after)?)
    .bind(limit)
    .fetch_all(&state.db().pool)
    .await?;
    let head: Option<i64> =
        sqlx::query_scalar("SELECT MAX(seq) FROM audit_events WHERE account_id = $1")
            .bind(auth.account_id.to_string())
            .fetch_one(&state.db().pool)
            .await?;
    Ok(Json(AuditPage {
        entries: rows
            .iter()
            .map(|r| {
                Ok(AuditEntry {
                    seq: to_u64(r.try_get("seq")?),
                    event: Blob::new(r.try_get::<Vec<u8>, _>("event")?),
                    hash: Blob::new(r.try_get::<Vec<u8>, _>("hash")?),
                })
            })
            .collect::<ApiResult<_>>()?,
        head_seq: head.map_or(0, to_u64),
    }))
}

/// `GET /v1/audit/heads` returns the account's latest heads...
const LATEST_HEADS: i64 = 100;

/// ...and each device's latest head beyond them, for this many devices at
/// most (those whose latest head was signed most recently). An account has
/// no device limit (each new installation, or sign-in without a device,
/// adds one, and revoked devices stay), so this bounds the response: 1,100
/// heads, a few hundred KiB, far below the clients' 128 MiB cap on a JSON
/// response.
const DEVICE_HEADS: i64 = 1000;

/// The account's latest [`LATEST_HEADS`] signed heads, plus each device's
/// latest one ([`DEVICE_HEADS`] more at most), newest first. A device
/// that verifies often (each sandbox list does) used to push the other
/// devices' heads out of the latest 100, and with them the check that the
/// chain still holds what those devices saw; each device's latest head now
/// stays in the list. A device's latest head is the one furthest along the
/// chain (its highest `seq`), not its last post: an older head stored
/// before posts were deduplicated, or posted through an older server
/// during a deploy, never stands in for it.
async fn heads(State(state): State<AppState>, auth: Auth) -> ApiResult<Json<AuditHeads>> {
    // The latest heads come first in this order, so the limit only ever
    // drops the heads of the devices whose latest head was signed longest
    // ago.
    let rows = sqlx::query(
        "SELECT seq, hash, signature, device_id, signed_at FROM ( \
           SELECT seq, hash, signature, device_id, signed_at, \
             ROW_NUMBER() OVER ( \
               PARTITION BY device_id ORDER BY seq DESC, signed_at DESC \
             ) AS per_device, \
             ROW_NUMBER() OVER ( \
               ORDER BY signed_at DESC, seq DESC, device_id DESC \
             ) AS overall \
           FROM audit_heads WHERE account_id = $1 \
         ) h \
         WHERE overall <= $2 OR per_device = 1 \
         ORDER BY signed_at DESC, seq DESC, device_id DESC \
         LIMIT $3",
    )
    .bind(auth.account_id.to_string())
    .bind(LATEST_HEADS)
    .bind(LATEST_HEADS + DEVICE_HEADS)
    .fetch_all(&state.db().pool)
    .await?;
    Ok(Json(AuditHeads {
        heads: rows
            .iter()
            .map(|r| {
                Ok(AuditHead {
                    seq: to_u64(r.try_get("seq")?),
                    hash: Blob::new(r.try_get::<Vec<u8>, _>("hash")?),
                    signature: Blob::new(r.try_get::<Vec<u8>, _>("signature")?),
                    device_id: parse_id(&r.try_get::<String, _>("device_id")?)?,
                    signed_at: r.try_get("signed_at")?,
                })
            })
            .collect::<ApiResult<_>>()?,
    }))
}

/// Stores a head signed by a device of the person after verifying the
/// chain: it must match the stored chain and verify with the account key.
/// A head this device already posted, or one behind its latest, is a
/// `204` that stores nothing.
async fn sign_head(
    State(state): State<AppState>,
    auth: Auth,
    ApiJson(req): ApiJson<SignHead>,
) -> ApiResult<StatusCode> {
    let hash: [u8; 32] = req
        .hash
        .as_bytes()
        .try_into()
        .map_err(|_| ApiError::bad_request("hash: expected 32 bytes"))?;
    let signature: [u8; SIGNATURE_LEN] = req
        .signature
        .as_bytes()
        .try_into()
        .map_err(|_| ApiError::bad_request("signature: expected 64 bytes"))?;
    let stored: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT hash FROM audit_events WHERE account_id = $1 AND seq = $2")
            .bind(auth.account_id.to_string())
            .bind(to_i64(req.seq)?)
            .fetch_optional(&state.db().pool)
            .await?;
    if stored.as_deref() != Some(&hash[..]) {
        return Err(ApiError::conflict(
            "the head does not match the stored chain",
        ));
    }
    let account = account_identity(&state, auth.account_id).await?;
    verify_head(
        &account,
        auth.account_id,
        req.seq,
        &hash,
        &Signature::from_bytes(signature),
    )
    .map_err(|_| ApiError::bad_request("the head's signature does not verify"))?;
    // Stored only if this device has no head at this position or later:
    // posting the same head again (or an older one) is a `204` that adds
    // no row, so a device that verifies in a loop cannot grow the table
    // (and every `GET`, which reads all of the account's heads). A head
    // at the same position with another hash cannot reach this point: the
    // check above held it to the stored chain. Two posts at the same moment
    // may both be stored, which only leaves one duplicate row.
    sqlx::query(
        "INSERT INTO audit_heads (account_id, seq, hash, signature, device_id, signed_at) \
         SELECT $1, $2, $3, $4, $5, $6 \
         WHERE NOT EXISTS ( \
           SELECT 1 FROM audit_heads WHERE account_id = $1 AND device_id = $5 AND seq >= $2 \
         )",
    )
    .bind(auth.account_id.to_string())
    .bind(to_i64(req.seq)?)
    .bind(hash.to_vec())
    .bind(signature.to_vec())
    .bind(auth.device_id.to_string())
    .bind(now_ms())
    .execute(&state.db().pool)
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Appends an event that happened only on a device of the person
/// (ADR 0020 §10). Only device sessions reach it (agents sign their own
/// requests and have no [`Auth`]). The item must be in a vault of the
/// account and not purged; an agent comes only with a task of the account
/// that is that agent's. The server adds the vault, the project and the
/// device; the event carries no site.
async fn person_event(
    State(state): State<AppState>,
    auth: Auth,
    ApiJson(req): ApiJson<PersonEvent>,
) -> ApiResult<StatusCode> {
    state
        .limiter()
        .enforce(&format!("audit-person:{}", auth.device_id), PERSON_EVENTS)?;
    if !PERSON_ACTIONS.contains(&req.action.as_str()) {
        return Err(ApiError::bad_request("action: not a person event"));
    }
    let row =
        sqlx::query("SELECT vault_id, project_id FROM items WHERE id = $1 AND purged_at IS NULL")
            .bind(req.item_id.to_string())
            .fetch_optional(&state.db().pool)
            .await?
            .ok_or(ApiError::NotFound)?;
    let vault_id: VaultId = parse_id(&row.try_get::<String, _>("vault_id")?)?;
    let project_id: ProjectId = parse_id(&row.try_get::<String, _>("project_id")?)?;
    require_member(&state, vault_id, auth.account_id).await?;
    match (req.agent_id, req.task_id) {
        (None, None) => {}
        (Some(agent_id), Some(task_id)) => {
            let owner: Option<String> =
                sqlx::query_scalar("SELECT agent_id FROM tasks WHERE id = $1 AND account_id = $2")
                    .bind(task_id.to_string())
                    .bind(auth.account_id.to_string())
                    .fetch_optional(&state.db().pool)
                    .await?;
            let owner: AgentId = parse_id(&owner.ok_or(ApiError::NotFound)?)?;
            if owner != agent_id {
                return Err(ApiError::bad_request("agent_id: not the task's agent"));
            }
        }
        _ => {
            return Err(ApiError::bad_request("agent_id and task_id go together"));
        }
    }
    let mut event = AuditEvent::new(ActorKind::Person, &req.action);
    event.device_id = Some(auth.device_id);
    event.agent_id = req.agent_id;
    event.task_id = req.task_id;
    event.vault_id = Some(vault_id);
    event.project_id = Some(project_id);
    event.item_id = Some(req.item_id);
    audit::append(&state, auth.account_id, event).await?;
    Ok(StatusCode::NO_CONTENT)
}
