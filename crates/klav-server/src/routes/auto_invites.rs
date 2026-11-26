//! Auto-issued beta invites (ADR 0050): the internal routes `klav-web`
//! calls, over Railway's private network, to issue a bound, single-use
//! invite for a waitlist email, and to revoke it again if the email with
//! the code could not be sent.
//!
//! They are on the same listener as the rest of the API, so the bearer
//! token is the access control, not the network. Each route answers `404`
//! unless the server is in `invite` mode with `invites.auto_max > 0` and a
//! token, and `401` on a missing or wrong token before the body is read or
//! the database touched.
//!
//! What they can do is narrow on purpose: only `max_uses = 1` invites,
//! bound to one email, expiring in 14 days, tagged `note = 'auto-beta'`,
//! and at most `auto_max` of them not revoked at any time. They can revoke
//! only an unused `auto-beta` invite. The code goes out once, in the `201`
//! body, and is never logged; neither is the token.

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use klav_core::crypto::invite::InviteCode;
use klav_core::crypto::token;
use klav_proto::RegistrationMode;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::db::now_ms;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;
use crate::validate;

/// The note every auto-issued invite carries; it is also what the cap
/// counts.
pub(crate) const AUTO_NOTE: &str = "auto-beta";
/// Lifetime of an auto-issued invite.
const AUTO_EXPIRES_MS: i64 = 14 * 24 * 60 * 60 * 1000;
/// Largest body the issue route reads: one email and a little JSON.
const MAX_BODY_BYTES: usize = 1024;
/// The key of the Postgres advisory lock that serializes issuance, so two
/// requests can't both see the last free seat (`klavauto` in ASCII).
const PG_LOCK_KEY: i64 = 0x6b6c_6176_6175_746f;

pub(super) fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/internal/invites/auto", post(issue))
        .route("/v1/internal/invites/auto/{id}/revoke", post(revoke))
}

/// `{ "email" }`: nothing else.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IssueRequest {
    email: String,
}

/// The `201` body. Not `Debug`: it carries the code.
#[derive(Serialize)]
struct IssueResponse {
    id: String,
    code: String,
    /// Unix milliseconds, as everywhere in this API.
    expires_at: i64,
}

/// `409` with a machine-readable reason, for `klav-web` only.
fn refused(reason: &'static str, message: &'static str) -> Response {
    (
        StatusCode::CONFLICT,
        Json(json!({ "error": reason, "message": message })),
    )
        .into_response()
}

/// `404` unless the routes are on; `401` unless `headers` carry the token.
/// Runs before the body is read and before the database is touched.
fn gate(state: &AppState, headers: &HeaderMap) -> ApiResult<()> {
    let config = state.config();
    let Some(expected) = config.invites.auto_token.as_ref() else {
        return Err(ApiError::NotFound);
    };
    if config.invites.auto_max == 0 || config.registration_mode() != RegistrationMode::Invite {
        return Err(ApiError::NotFound);
    }
    let given = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("");
    if given.is_empty() || !token::same_token(given, expected) {
        tracing::warn!("auto invite: refused a bad or missing token");
        return Err(ApiError::Unauthorized);
    }
    Ok(())
}

/// `POST /v1/internal/invites/auto`: `201 { id, code, expires_at }`, or
/// `409 already_invited` (this email already has an `auto-beta` invite
/// that isn't revoked, used or not), or `409 cap_reached`.
async fn issue(State(state): State<AppState>, headers: HeaderMap, body: Body) -> Response {
    match issue_inner(&state, &headers, body).await {
        Ok(response) => response,
        Err(e) => e.into_response(),
    }
}

async fn issue_inner(state: &AppState, headers: &HeaderMap, body: Body) -> ApiResult<Response> {
    gate(state, headers)?;
    let bytes = axum::body::to_bytes(body, MAX_BODY_BYTES)
        .await
        .map_err(|_| ApiError::PayloadTooLarge)?;
    let req: IssueRequest = serde_json::from_slice(&bytes)
        .map_err(|_| ApiError::bad_request("expected {\"email\": \"…\"}"))?;
    let email = validate::email(&req.email)?;
    let max = i64::try_from(state.config().invites.auto_max).unwrap_or(i64::MAX);

    let code = InviteCode::generate();
    let digest = code
        .digest()
        .map_err(|_| ApiError::Internal("generated an invalid invite code".into()))?;
    let id = crate::invites::random_uuid();
    let now = now_ms();
    let expires_at = now.saturating_add(AUTO_EXPIRES_MS);

    // The write is the first statement, so SQLite takes its write lock at
    // once and never upgrades a read lock; the checks live in its WHERE.
    // On Postgres, READ COMMITTED would let two requests both see the last
    // free seat, so an advisory lock serializes them for the transaction.
    let mut tx = state.db().pool.begin().await?;
    if state.config().database_url.starts_with("postgres") {
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(PG_LOCK_KEY)
            .execute(&mut *tx)
            .await?;
    }
    let inserted = sqlx::query(
        "INSERT INTO registration_invites \
         (id, code_hash, bound_email, max_uses, used_count, expires_at, note, created_at) \
         SELECT $1, $2, $3, 1, 0, $4, $5, $6 \
         WHERE NOT EXISTS (SELECT 1 FROM registration_invites \
             WHERE bound_email = $3 AND note = $5 AND revoked_at IS NULL) \
         AND (SELECT CAST(COUNT(*) AS BIGINT) FROM registration_invites \
             WHERE note = $5 AND revoked_at IS NULL) < $7",
    )
    .bind(&id)
    .bind(digest.to_vec())
    .bind(&email)
    .bind(expires_at)
    .bind(AUTO_NOTE)
    .bind(now)
    .bind(max)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if inserted == 1 {
        tx.commit().await?;
        // The id only: never the code, never the email.
        tracing::info!(invite = %id, "auto invite issued");
        let body = IssueResponse {
            id,
            code: code.expose().to_owned(),
            expires_at,
        };
        return Ok((StatusCode::CREATED, Json(body)).into_response());
    }
    // Nothing inserted: say why, from inside the same transaction.
    let has_one: Option<String> = sqlx::query_scalar(
        "SELECT id FROM registration_invites \
         WHERE bound_email = $1 AND note = $2 AND revoked_at IS NULL",
    )
    .bind(&email)
    .bind(AUTO_NOTE)
    .fetch_optional(&mut *tx)
    .await?;
    drop(tx);
    Ok(match has_one {
        Some(_) => refused(
            "already_invited",
            "this email already has an auto-issued invite",
        ),
        None => {
            tracing::info!(max, "auto invite: cap reached");
            refused("cap_reached", "every auto-issued invite seat is taken")
        }
    })
}

/// `POST /v1/internal/invites/auto/{id}/revoke`: `204` when it revoked an
/// unused `auto-beta` invite, `404` for anything else (no such invite,
/// already revoked, already used, or not auto-issued). Revoking frees the
/// seat and the email for a later try.
async fn revoke(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    gate(&state, &headers)?;
    let done = sqlx::query(
        "UPDATE registration_invites SET revoked_at = $1 \
         WHERE id = $2 AND note = $3 AND used_count = 0 AND revoked_at IS NULL",
    )
    .bind(now_ms())
    .bind(&id)
    .bind(AUTO_NOTE)
    .execute(&state.db().pool)
    .await?;
    if done.rows_affected() == 1 {
        tracing::info!(invite = %id, "auto invite revoked");
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::NotFound)
    }
}
