//! The account: `GET /v1/account`, and deleting it (ADR 0037).
//!
//! Deleting takes the master password again, through a full OPAQUE
//! exchange inside the person's session: `start` answers KE2 for the
//! session's account (never an e-mail the client sends), and `finish`
//! checks KE3 and, if it verifies, schedules the deletion in the same
//! request. The proof is spent in the act: there is no "freshly checked"
//! session that could delete for a few minutes. A wrong password answers
//! `403 reauth_failed`, never `401`, because clients take every `401` for
//! the end of the session.
//!
//! The account goes 7 days later (`crate::deletion`). Until then any of
//! the person's devices can cancel it.

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use klav_core::crypto::opaque;
use klav_core::ids::AccountId;
use klav_proto::Blob;
use klav_proto::agent::McpGatewaySwitch;
use klav_proto::auth::{
    AccountDeleteFinishRequest, AccountDeleteStartRequest, AccountDeleteStartResponse,
    AccountDeletion, AccountInfo,
};
use sqlx::Row;

use super::auth::{keyset, limit_email, limit_ip};
use crate::db::now_ms;
use crate::deletion::{self, DELETION_DELAY_MS, lock_account};
use crate::error::{ApiError, ApiJson, ApiResult};
use crate::logins::Purpose;
use crate::push::PushKind;
use crate::ratelimit::ClientIp;
use crate::session::Auth;
use crate::state::AppState;

pub(super) fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/account", get(account))
        .route("/v1/account/delete/start", post(delete_start))
        .route("/v1/account/delete/finish", post(delete_finish))
        .route("/v1/account/delete/cancel", post(delete_cancel))
        .route(
            "/v1/account/mcp-gateway",
            get(mcp_gateway).post(mcp_gateway_on),
        )
}

/// When the account's `mcp_gateway` switch was turned on (Unix ms), or
/// `None` while it is off (ADR 0049 §9).
pub(crate) async fn mcp_gateway_since<'e, E>(db: E, account: AccountId) -> ApiResult<Option<i64>>
where
    E: sqlx::Executor<'e, Database = sqlx::Any>,
{
    let since: Option<Option<i64>> =
        sqlx::query_scalar("SELECT mcp_gateway_at FROM accounts WHERE id = $1")
            .bind(account.to_string())
            .fetch_optional(db)
            .await?;
    Ok(since.flatten())
}

/// `GET /v1/account/mcp-gateway`: the switch, for the person's sheet. An
/// older server answers `404`, and the sheet says it can't do this yet.
async fn mcp_gateway(
    State(state): State<AppState>,
    auth: Auth,
) -> ApiResult<Json<McpGatewaySwitch>> {
    let since = mcp_gateway_since(&state.db().pool, auth.account_id).await?;
    Ok(Json(McpGatewaySwitch {
        mcp_gateway: since.is_some(),
        since,
    }))
}

/// `POST /v1/account/mcp-gateway`: turns the switch on (ADR 0049 §9), only
/// in the person's session, after the sheet's "update every device first".
/// Nothing turns it off: the grants and approvals signed with it stay as
/// signed. Turning it on again keeps its first time.
async fn mcp_gateway_on(
    State(state): State<AppState>,
    auth: Auth,
) -> ApiResult<Json<McpGatewaySwitch>> {
    let pool = &state.db().pool;
    sqlx::query("UPDATE accounts SET mcp_gateway_at = $1 WHERE id = $2 AND mcp_gateway_at IS NULL")
        .bind(now_ms())
        .bind(auth.account_id.to_string())
        .execute(pool)
        .await?;
    let since = mcp_gateway_since(pool, auth.account_id).await?;
    Ok(Json(McpGatewaySwitch {
        mcp_gateway: since.is_some(),
        since,
    }))
}

/// The keyset, and the deletion the person asked for, if any.
async fn account(State(state): State<AppState>, auth: Auth) -> ApiResult<Json<AccountInfo>> {
    let pool = &state.db().pool;
    let row = sqlx::query(
        "SELECT id, email, kdf_params, public_identity, sealed_identity FROM accounts WHERE id = $1",
    )
    .bind(auth.account_id.to_string())
    .fetch_one(pool)
    .await?;
    Ok(Json(AccountInfo {
        keyset: keyset(&row)?,
        deletion: deletion::pending(pool, auth.account_id).await?,
    }))
}

/// The first half of the reauthentication: KE2 for the session's account.
///
/// Counts in the authentication limits by IP and by e-mail and IP, with the
/// account's e-mail, and in its own budget of 5 per account and hour. A
/// deletion already asked for answers `409`, and one asked 3 times in 7
/// days `429`, before any OPAQUE work here. The client already ran its
/// Argon2id (KE1 comes out of it): to spare it, clients read `deletion`
/// in `GET /v1/account` or `/v1/sync` first.
async fn delete_start(
    State(state): State<AppState>,
    Extension(ip): Extension<ClientIp>,
    auth: Auth,
    ApiJson(req): ApiJson<AccountDeleteStartRequest>,
) -> ApiResult<Json<AccountDeleteStartResponse>> {
    limit_ip(&state, ip)?;
    let pool = &state.db().pool;
    let row = sqlx::query("SELECT email, opaque_record FROM accounts WHERE id = $1")
        .bind(auth.account_id.to_string())
        .fetch_one(pool)
        .await?;
    let email: String = row.try_get("email")?;
    limit_email(&state, &email, ip)?;
    if deletion::delete_at(pool, auth.account_id).await?.is_some() {
        return Err(ApiError::conflict(
            "the deletion of this account is already scheduled",
        ));
    }
    let now = now_ms();
    state.deletion_limits().may_request(auth.account_id, now)?;
    state.deletion_limits().start(auth.account_id, now)?;
    let record: Vec<u8> = row.try_get("opaque_record")?;
    let (login, response) = opaque::server_start_login(
        &state.keys().opaque,
        Some(&record),
        req.credential_request.as_bytes(),
        email.as_bytes(),
    )
    .map_err(|_| ApiError::bad_request("invalid credential_request"))?;
    let handle = state
        .logins()
        .insert(
            login,
            Some(auth.account_id),
            Purpose::DeleteAccount {
                session_id: auth.session_id.clone(),
            },
        )
        .ok_or(ApiError::Unavailable)?;
    Ok(Json(AccountDeleteStartResponse {
        handle,
        credential_response: Blob::new(response),
    }))
}

/// The second half: if KE3 verifies, the deletion is scheduled for 7 days
/// later, in this same request.
async fn delete_finish(
    State(state): State<AppState>,
    Extension(ip): Extension<ClientIp>,
    auth: Auth,
    ApiJson(req): ApiJson<AccountDeleteFinishRequest>,
) -> ApiResult<(StatusCode, Json<AccountDeletion>)> {
    limit_ip(&state, ip)?;
    // The handle is spent here whatever happens next. One from a login,
    // from another session, expired or used answers like a wrong password.
    let pending = state
        .logins()
        .take(
            &req.handle,
            &Purpose::DeleteAccount {
                session_id: auth.session_id.clone(),
            },
        )
        .ok_or(ApiError::ReauthFailed)?;
    if pending.account_id != Some(auth.account_id)
        || pending
            .login
            .finish(req.credential_finalization.as_bytes())
            .is_err()
    {
        tracing::info!(account = %auth.account_id, "account deletion: reauthentication failed");
        return Err(ApiError::ReauthFailed);
    }

    let now = now_ms();
    let delete_at = now.saturating_add(DELETION_DELAY_MS);
    let mut tx = state.db().pool.begin().await?;
    // The lock that canceling and the purge take, and that an agent's
    // allowed action takes to be logged: once this commits, no agent
    // action is allowed.
    if !lock_account(&mut tx, auth.account_id).await? {
        return Err(ApiError::Unauthorized);
    }
    let inserted = sqlx::query(
        "INSERT INTO account_deletions (account_id, device_id, requested_at, delete_at) \
         VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
    )
    .bind(auth.account_id.to_string())
    .bind(auth.device_id.to_string())
    .bind(now)
    .bind(delete_at)
    .execute(&mut *tx)
    .await?;
    if inserted.rows_affected() == 0 {
        return Err(ApiError::conflict(
            "the deletion of this account is already scheduled",
        ));
    }
    // Counted only when it is scheduled; over the limit, nothing is.
    state.deletion_limits().request(auth.account_id, now)?;
    let scheduled = deletion::pending(&mut *tx, auth.account_id)
        .await?
        .ok_or_else(|| ApiError::Internal("deletion row vanished".into()))?;
    tx.commit().await?;
    tracing::info!(
        account = %auth.account_id,
        device = %auth.device_id,
        delete_at,
        "account deletion requested"
    );
    state.push(auth.account_id, PushKind::AccountDeletion, String::new());
    Ok((StatusCode::ACCEPTED, Json(scheduled)))
}

/// Cancels the deletion, from any device with a session (ADR 0037 P8):
/// undoing must not cost anything, and one cancel too many only delays the
/// deletion, with a notice to the phones.
async fn delete_cancel(State(state): State<AppState>, auth: Auth) -> ApiResult<StatusCode> {
    let mut tx = state.db().pool.begin().await?;
    if !lock_account(&mut tx, auth.account_id).await? {
        return Err(ApiError::Unauthorized);
    }
    let removed = sqlx::query("DELETE FROM account_deletions WHERE account_id = $1")
        .bind(auth.account_id.to_string())
        .execute(&mut *tx)
        .await?;
    if removed.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    tx.commit().await?;
    tracing::info!(
        account = %auth.account_id,
        device = %auth.device_id,
        "account deletion canceled"
    );
    state.push(auth.account_id, PushKind::AccountCanceled, String::new());
    Ok(StatusCode::NO_CONTENT)
}
