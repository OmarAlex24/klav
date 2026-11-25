//! `GET /v1/health`: liveness plus a database round-trip.

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use klav_proto::{HealthResponse, RegistrationMode};

use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

pub(super) fn router() -> Router<AppState> {
    Router::new().route("/v1/health", get(health))
}

async fn health(State(state): State<AppState>) -> ApiResult<Json<HealthResponse>> {
    state.db().ping().await.map_err(|e| {
        tracing::warn!(error = %e, "health check: database unavailable");
        ApiError::Unavailable
    })?;
    let mode = state.config().registration_mode();
    Ok(Json(HealthResponse {
        status: "ok".into(),
        version: crate::VERSION.into(),
        // `false` in `invite` mode: a client from before ADR 0048 stops
        // before writing an emergency kit or deriving keys (§1.2).
        registration_open: Some(mode == RegistrationMode::Open),
        registration_mode: Some(mode),
        // Any server with this version lets the person delete the account,
        // with no setting to turn it off (ADR 0037 §4).
        account_deletion: Some(true),
    }))
}
