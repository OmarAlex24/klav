//! Structured logging with `tracing`.
//!
//! What gets logged per request: method, matched route template (e.g.
//! `/v1/vaults/{vault_id}`), status and latency. Never request or response
//! bodies, never headers (so never `Authorization`), never query strings.

use axum::extract::{MatchedPath, Request};
use tower_http::classify::{ServerErrorsAsFailures, SharedClassifier};
use tower_http::trace::{DefaultOnResponse, TraceLayer};
use tracing::{Level, Span};
use tracing_subscriber::EnvFilter;

use crate::config::{LogConfig, LogFormat};

/// Dependencies are noisy at `debug`; keep them at `warn` unless the filter
/// names them explicitly.
const QUIET_DEPENDENCIES: &str = "sqlx=warn,hyper=warn,h2=warn,tower=warn";

/// Installs the global subscriber. Call once, from `main`.
pub fn init(config: &LogConfig) {
    let filter = EnvFilter::try_new(format!("{QUIET_DEPENDENCIES},{}", config.filter))
        .unwrap_or_else(|_| EnvFilter::new("info"));
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true);
    let _ = match config.format {
        LogFormat::Json => builder.json().flatten_event(true).try_init(),
        LogFormat::Pretty => builder.try_init(),
    };
}

fn make_span(req: &Request) -> Span {
    let path = req
        .extensions()
        .get::<MatchedPath>()
        .map_or("<unmatched>", MatchedPath::as_str);
    tracing::info_span!("request", method = %req.method(), path)
}

/// Concrete type of [`trace_layer`].
pub(crate) type RequestTraceLayer = TraceLayer<
    SharedClassifier<ServerErrorsAsFailures>,
    fn(&Request) -> Span,
    (),
    DefaultOnResponse,
    (),
    (),
    (),
>;

/// Request tracing layer (no bodies, no headers, no query strings).
pub(crate) fn trace_layer() -> RequestTraceLayer {
    TraceLayer::new_for_http()
        .make_span_with(make_span as fn(&Request) -> Span)
        .on_request(())
        .on_response(
            DefaultOnResponse::new()
                .level(Level::INFO)
                .include_headers(false),
        )
        .on_body_chunk(())
        .on_eos(())
        .on_failure(())
}
