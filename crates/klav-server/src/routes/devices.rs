//! Devices of the account: list, revoke, and the push token of the
//! current device (ADR 0018 §5).

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{delete, get, put};
use axum::{Json, Router};
use klav_core::ids::DeviceId;
use klav_proto::auth::{Device, DeviceKind, DeviceList, PushRegistration};
use sqlx::Row;

use crate::db::now_ms;
use crate::error::{ApiError, ApiResult};
use crate::session::{Auth, parse_id};
use crate::state::AppState;

pub(super) fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/devices", get(list))
        .route("/v1/devices/{device_id}", delete(revoke))
        .route(
            "/v1/devices/current/push",
            put(register_push).delete(unregister_push),
        )
}

/// `PUT /v1/devices/current/push`: where to send this device's approval
/// pushes. A token another device of the same account had is moved here (a
/// reinstalled app), and so is one left on a revoked device. A token that
/// an active device of **another** account still holds is `409`: otherwise
/// whoever learnt a phone's token could take its pushes away from their
/// owner. That account signs out there (which forgets the token) or
/// revokes the device first.
async fn register_push(
    State(state): State<AppState>,
    auth: Auth,
    Json(req): Json<PushRegistration>,
) -> ApiResult<StatusCode> {
    let token = req.token.trim().to_ascii_lowercase();
    if !crate::push::valid_token(&token) {
        return Err(ApiError::BadRequest("invalid push token".into()));
    }
    let mut tx = state.db().pool.begin().await?;
    let taken: Option<String> = sqlx::query_scalar(
        "SELECT p.device_id FROM push_tokens p JOIN devices d ON d.id = p.device_id \
         WHERE p.token = $1 AND p.account_id <> $2 AND d.revoked_at IS NULL",
    )
    .bind(&token)
    .bind(auth.account_id.to_string())
    .fetch_optional(&mut *tx)
    .await?;
    if taken.is_some() {
        return Err(ApiError::conflict(
            "this push token belongs to an active device of another account: sign out there first",
        ));
    }
    sqlx::query("DELETE FROM push_tokens WHERE token = $1 AND device_id <> $2")
        .bind(&token)
        .bind(auth.device_id.to_string())
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO push_tokens (device_id, account_id, token, environment, updated_at) \
         VALUES ($1, $2, $3, $4, $5) ON CONFLICT (device_id) DO UPDATE SET \
         account_id = excluded.account_id, token = excluded.token, \
         environment = excluded.environment, updated_at = excluded.updated_at",
    )
    .bind(auth.device_id.to_string())
    .bind(auth.account_id.to_string())
    .bind(&token)
    .bind(req.environment.as_str())
    .bind(now_ms())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    // Never the token itself.
    tracing::info!(account = %auth.account_id, device = %auth.device_id, "push token registered");
    Ok(StatusCode::NO_CONTENT)
}

/// `DELETE /v1/devices/current/push`: no more pushes to this device.
async fn unregister_push(State(state): State<AppState>, auth: Auth) -> ApiResult<StatusCode> {
    forget_push(&state, &auth.device_id.to_string()).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Removes a device's push token (also on revocation and logout).
pub(crate) async fn forget_push(state: &AppState, device_id: &str) -> ApiResult<()> {
    sqlx::query("DELETE FROM push_tokens WHERE device_id = $1")
        .bind(device_id)
        .execute(&state.db().pool)
        .await?;
    Ok(())
}

async fn list(State(state): State<AppState>, auth: Auth) -> ApiResult<Json<DeviceList>> {
    let rows = sqlx::query(
        "SELECT id, name, kind, created_at, last_seen_at, revoked_at FROM devices \
         WHERE account_id = $1 ORDER BY created_at DESC, id",
    )
    .bind(auth.account_id.to_string())
    .fetch_all(&state.db().pool)
    .await?;
    let devices = rows
        .iter()
        .map(|row| {
            let id: DeviceId = parse_id(&row.try_get::<String, _>("id")?)?;
            Ok(Device {
                id,
                name: row.try_get("name")?,
                kind: DeviceKind::parse(&row.try_get::<String, _>("kind")?)
                    .unwrap_or(DeviceKind::Other),
                created_at: row.try_get("created_at")?,
                last_seen_at: row.try_get("last_seen_at")?,
                revoked_at: row.try_get("revoked_at")?,
                current: id == auth.device_id,
            })
        })
        .collect::<ApiResult<Vec<_>>>()?;
    Ok(Json(DeviceList { devices }))
}

/// Revokes a device and all its sessions at once. Revoking the current
/// device logs it out.
async fn revoke(
    State(state): State<AppState>,
    auth: Auth,
    Path(device_id): Path<String>,
) -> ApiResult<StatusCode> {
    let device_id: DeviceId = device_id.parse().map_err(|_| ApiError::NotFound)?;
    let now = now_ms();
    let mut tx = state.db().pool.begin().await?;
    let revoked = sqlx::query(
        "UPDATE devices SET revoked_at = $1 \
         WHERE id = $2 AND account_id = $3 AND revoked_at IS NULL",
    )
    .bind(now)
    .bind(device_id.to_string())
    .bind(auth.account_id.to_string())
    .execute(&mut *tx)
    .await?;
    if revoked.rows_affected() == 0 {
        // Unknown, already revoked or from another account: same answer.
        return Err(ApiError::NotFound);
    }
    sqlx::query("UPDATE sessions SET revoked_at = $1 WHERE device_id = $2 AND revoked_at IS NULL")
        .bind(now)
        .bind(device_id.to_string())
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM push_tokens WHERE device_id = $1")
        .bind(device_id.to_string())
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    tracing::info!(account = %auth.account_id, device = %device_id, "device revoked");
    Ok(StatusCode::NO_CONTENT)
}
