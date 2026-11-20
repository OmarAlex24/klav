//! Sessions: short-lived access tokens plus single-use refresh tokens, bound
//! to a device. Only token digests are stored (`klav_core::crypto::token`).

use axum::extract::FromRequestParts;
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use klav_core::crypto::random;
use klav_core::crypto::token::{digest_str, generate_token, token_digest};
use klav_core::ids::{AccountId, DeviceId};
use klav_proto::auth::SessionTokens;
use secrecy::ExposeSecret;
use sqlx::Row;

use crate::db::now_ms;
use crate::error::{ApiError, ApiResult};
use crate::ratelimit::Quota;
use crate::state::AppState;

const ACCESS_PREFIX: &str = "kat_";
const REFRESH_PREFIX: &str = "krt_";
/// `last_seen_at` is only written when older than this (avoids a write per
/// request).
const LAST_SEEN_GRANULARITY_MS: i64 = 60_000;

/// An authenticated caller. Extracting it validates the bearer token,
/// checks that neither the session nor the device is revoked or expired, and
/// applies the per-account rate limit.
#[derive(Debug, Clone)]
pub(crate) struct Auth {
    pub(crate) account_id: AccountId,
    pub(crate) device_id: DeviceId,
    pub(crate) session_id: String,
    /// When the access token expires (Unix ms); long-lived streams end then.
    pub(crate) expires_at: i64,
}

impl FromRequestParts<AppState> for Auth {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, ApiError> {
        let token = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .filter(|t| t.starts_with(ACCESS_PREFIX))
            .ok_or(ApiError::Unauthorized)?;
        let digest = digest_str(token);
        let now = now_ms();
        let row = sqlx::query(
            "SELECT s.id, s.account_id, s.device_id, s.access_expires_at, d.last_seen_at \
             FROM sessions s JOIN devices d ON d.id = s.device_id \
             WHERE s.access_digest = $1 AND s.revoked_at IS NULL \
               AND d.revoked_at IS NULL AND s.access_expires_at > $2",
        )
        .bind(digest.to_vec())
        .bind(now)
        .fetch_optional(&state.db().pool)
        .await?
        .ok_or(ApiError::Unauthorized)?;

        let auth = Self {
            session_id: row.try_get("id")?,
            account_id: parse_id(&row.try_get::<String, _>("account_id")?)?,
            device_id: parse_id(&row.try_get::<String, _>("device_id")?)?,
            expires_at: row.try_get("access_expires_at")?,
        };
        let rl = &state.config().rate_limit;
        state.limiter().enforce(
            &format!("account:{}", auth.account_id),
            Quota {
                per_minute: rl.account_per_minute,
                burst: rl.account_burst,
            },
        )?;
        let last_seen: i64 = row.try_get("last_seen_at")?;
        if now - last_seen > LAST_SEEN_GRANULARITY_MS {
            sqlx::query("UPDATE devices SET last_seen_at = $1 WHERE id = $2")
                .bind(now)
                .bind(auth.device_id.to_string())
                .execute(&state.db().pool)
                .await?;
        }
        Ok(auth)
    }
}

/// Parses an ID stored by this server; a failure means a corrupt row.
pub(crate) fn parse_id<T: std::str::FromStr>(text: &str) -> ApiResult<T> {
    text.parse()
        .map_err(|_| ApiError::Internal("corrupt ID in database".into()))
}

struct Issued {
    tokens: SessionTokens,
    access_digest: Vec<u8>,
    refresh_digest: Vec<u8>,
}

fn issue(state: &AppState, now: i64) -> Issued {
    let cfg = &state.config().sessions;
    let access = generate_token(ACCESS_PREFIX);
    let refresh = generate_token(REFRESH_PREFIX);
    let secs_to_ms = |secs: u64| i64::try_from(secs.saturating_mul(1000)).unwrap_or(i64::MAX);
    Issued {
        access_digest: token_digest(&access).to_vec(),
        refresh_digest: token_digest(&refresh).to_vec(),
        tokens: SessionTokens {
            access_token: access.expose_secret().to_owned(),
            access_expires_at: now.saturating_add(secs_to_ms(cfg.access_ttl_secs)),
            refresh_token: refresh.expose_secret().to_owned(),
            refresh_expires_at: now.saturating_add(secs_to_ms(cfg.refresh_ttl_secs)),
        },
    }
}

fn random_id() -> String {
    random::array::<16>()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Opens a new session for `device_id`.
pub(crate) async fn create(
    state: &AppState,
    account_id: AccountId,
    device_id: DeviceId,
) -> ApiResult<SessionTokens> {
    let now = now_ms();
    let issued = issue(state, now);
    sqlx::query(
        "INSERT INTO sessions (id, account_id, device_id, access_digest, access_expires_at, \
         refresh_digest, refresh_expires_at, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(random_id())
    .bind(account_id.to_string())
    .bind(device_id.to_string())
    .bind(issued.access_digest)
    .bind(issued.tokens.access_expires_at)
    .bind(issued.refresh_digest)
    .bind(issued.tokens.refresh_expires_at)
    .bind(now)
    .execute(&state.db().pool)
    .await?;
    Ok(issued.tokens)
}

/// Rotates a refresh token. Presenting a refresh token that was already
/// rotated revokes the session: either the client is buggy or the token was
/// stolen, and in both cases the safe answer is to log the device out.
pub(crate) async fn refresh(state: &AppState, refresh_token: &str) -> ApiResult<SessionTokens> {
    if !refresh_token.starts_with(REFRESH_PREFIX) {
        return Err(ApiError::Unauthorized);
    }
    let digest = digest_str(refresh_token).to_vec();
    let now = now_ms();
    let pool = &state.db().pool;
    let row = sqlx::query(
        "SELECT s.id, s.refresh_expires_at FROM sessions s JOIN devices d ON d.id = s.device_id \
         WHERE s.refresh_digest = $1 AND s.revoked_at IS NULL AND d.revoked_at IS NULL",
    )
    .bind(digest.clone())
    .fetch_optional(pool)
    .await?;
    let Some(row) = row else {
        let reused = sqlx::query(
            "UPDATE sessions SET revoked_at = $1 \
             WHERE previous_refresh_digest = $2 AND revoked_at IS NULL",
        )
        .bind(now)
        .bind(digest)
        .execute(pool)
        .await?;
        if reused.rows_affected() > 0 {
            tracing::warn!("refresh token reuse detected; session revoked");
        }
        return Err(ApiError::Unauthorized);
    };
    let session_id: String = row.try_get("id")?;
    if row.try_get::<i64, _>("refresh_expires_at")? <= now {
        return Err(ApiError::Unauthorized);
    }
    let issued = issue(state, now);
    // Compare-and-swap on the old digest: of two concurrent refreshes with the
    // same token, only one wins.
    let updated = sqlx::query(
        "UPDATE sessions SET access_digest = $1, access_expires_at = $2, refresh_digest = $3, \
         previous_refresh_digest = $4, refresh_expires_at = $5 \
         WHERE id = $6 AND refresh_digest = $7 AND revoked_at IS NULL",
    )
    .bind(issued.access_digest)
    .bind(issued.tokens.access_expires_at)
    .bind(issued.refresh_digest)
    .bind(digest.clone())
    .bind(issued.tokens.refresh_expires_at)
    .bind(session_id)
    .bind(digest)
    .execute(pool)
    .await?;
    if updated.rows_affected() == 1 {
        Ok(issued.tokens)
    } else {
        Err(ApiError::Unauthorized)
    }
}

/// `true` while the session (and its device) is neither revoked nor expired.
pub(crate) async fn is_active(state: &AppState, session_id: &str) -> ApiResult<bool> {
    let found: Option<String> = sqlx::query_scalar(
        "SELECT s.id FROM sessions s JOIN devices d ON d.id = s.device_id \
         WHERE s.id = $1 AND s.revoked_at IS NULL AND d.revoked_at IS NULL \
         AND s.access_expires_at > $2",
    )
    .bind(session_id)
    .bind(now_ms())
    .fetch_optional(&state.db().pool)
    .await?;
    Ok(found.is_some())
}

/// Revokes one session (log-out).
pub(crate) async fn revoke(state: &AppState, session_id: &str) -> ApiResult<()> {
    sqlx::query("UPDATE sessions SET revoked_at = $1 WHERE id = $2 AND revoked_at IS NULL")
        .bind(now_ms())
        .bind(session_id)
        .execute(&state.db().pool)
        .await?;
    Ok(())
}
