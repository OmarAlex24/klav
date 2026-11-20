//! Router assembly and cross-cutting HTTP layers: security headers, body
//! limits, rate limiting, request tracing.

use axum::extract::DefaultBodyLimit;
use axum::http::{HeaderName, HeaderValue, header};
use axum::response::IntoResponse;
use axum::{Router, middleware};
use tower_http::set_header::SetResponseHeaderLayer;

use crate::error::ApiError;
use crate::state::AppState;
use crate::{ratelimit, routes, telemetry};

/// Headers added to every response. The API serves JSON only, so the
/// strictest browser policies apply.
const SECURITY_HEADERS: &[(&str, &str)] = &[
    (
        "strict-transport-security",
        "max-age=63072000; includeSubDomains",
    ),
    ("x-content-type-options", "nosniff"),
    ("x-frame-options", "DENY"),
    ("referrer-policy", "no-referrer"),
    (
        "content-security-policy",
        "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
    ),
    ("cross-origin-resource-policy", "same-origin"),
    ("permissions-policy", "interest-cohort=()"),
    ("cache-control", "no-store"),
];

pub(crate) fn router(state: AppState) -> Router {
    let mut app = routes::router(state.config().limits.max_attachment_chunk_bytes)
        .fallback(|| async { ApiError::NotFound.into_response() })
        .layer(DefaultBodyLimit::max(
            state.config().limits.max_json_body_bytes,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            ratelimit::limit_by_ip,
        ))
        .layer(telemetry::trace_layer());
    for (name, value) in SECURITY_HEADERS {
        app = app.layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static(name),
            HeaderValue::from_static(value),
        ));
    }
    app.layer(SetResponseHeaderLayer::if_not_present(
        header::SERVER,
        HeaderValue::from_static("klav"),
    ))
    .with_state(state)
}
