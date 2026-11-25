//! API error type. Converts into a JSON [`ErrorBody`] that never carries
//! internal details: database and I/O errors are logged server-side (without
//! request data) and the client only sees a generic message.

use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{FromRequest, Request};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use klav_proto::agent::AgentPaused;
use klav_proto::{ErrorBody, ErrorCode};
use serde::de::DeserializeOwned;

/// Error returned by handlers.
#[derive(Debug)]
pub(crate) enum ApiError {
    BadRequest(String),
    Unauthorized,
    Forbidden,
    /// Forbidden with a reason the caller may see (a policy decision).
    Denied(String),
    /// The person paused this agent, or every agent (ADR 0033 §7.4).
    Paused(AgentPaused),
    /// The master password given to delete the account is wrong, or its
    /// OPAQUE handle is expired, used, or not for this (ADR 0037 §1).
    ReauthFailed,
    /// The person asked to delete the account, which happens at this time
    /// (Unix ms): agents are refused until then (ADR 0037 §3).
    AccountDeleting(i64),
    NotFound,
    Conflict {
        message: String,
        current_version: Option<u64>,
    },
    /// A pause or a resume older than the scope's latest decision, whose
    /// `at` (Unix ms) goes in the body (409, ADR 0033 §7.6).
    LaterPause(i64),
    /// A person's revocation of sandboxes no later than the last one on
    /// the same proxy and scope (spec §13.11): `409` with that one's
    /// `last_at`, so a device signs a later one.
    LaterRevocation(i64),
    PayloadTooLarge,
    TooManyRequests {
        retry_after_secs: u64,
    },
    Unavailable,
    /// A refusal with its own code and a message the caller may see (the
    /// sandbox routes, ADR 0036 E1.3).
    Coded(StatusCode, ErrorCode, String),
    /// Unexpected failure. The string goes to the log only.
    Internal(String),
}

pub(crate) type ApiResult<T> = Result<T, ApiError>;

impl ApiError {
    pub(crate) fn bad_request(message: impl Into<String>) -> Self {
        Self::BadRequest(message.into())
    }

    pub(crate) fn conflict(message: impl Into<String>) -> Self {
        Self::Conflict {
            message: message.into(),
            current_version: None,
        }
    }

    /// `403 invite_invalid`: one answer for every reason an invite cannot
    /// be used, which never says whether the email has an account (ADR 0048
    /// §1.3).
    pub(crate) fn invite_invalid() -> Self {
        Self::Coded(
            StatusCode::FORBIDDEN,
            ErrorCode::InviteInvalid,
            "This invite code isn't valid for this email".into(),
        )
    }

    /// `403 quota_exceeded` with a message naming the limit, the use and the
    /// maximum (ADR 0048 §3.2).
    pub(crate) fn quota_exceeded(message: String) -> Self {
        Self::Coded(StatusCode::FORBIDDEN, ErrorCode::QuotaExceeded, message)
    }

    pub(crate) fn stale(current_version: i64) -> Self {
        Self::Conflict {
            message: "stale version: fetch the latest version and retry".into(),
            current_version: u64::try_from(current_version).ok(),
        }
    }

    fn parts(&self) -> (StatusCode, ErrorCode, String) {
        match self {
            Self::BadRequest(m) => (StatusCode::BAD_REQUEST, ErrorCode::BadRequest, m.clone()),
            Self::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                ErrorCode::Unauthorized,
                "invalid or expired credentials".into(),
            ),
            Self::Forbidden => (
                StatusCode::FORBIDDEN,
                ErrorCode::Forbidden,
                "not allowed".into(),
            ),
            Self::Denied(m) => (StatusCode::FORBIDDEN, ErrorCode::Forbidden, m.clone()),
            Self::ReauthFailed => (
                StatusCode::FORBIDDEN,
                ErrorCode::ReauthFailed,
                "the master password is not right".into(),
            ),
            Self::AccountDeleting(_) => (
                StatusCode::FORBIDDEN,
                ErrorCode::AccountDeleting,
                "the person asked Klav to delete this account".into(),
            ),
            Self::Paused(_) => (
                StatusCode::FORBIDDEN,
                ErrorCode::AgentsPaused,
                "the person paused Klav for agents".into(),
            ),
            Self::NotFound => (
                StatusCode::NOT_FOUND,
                ErrorCode::NotFound,
                "not found".into(),
            ),
            Self::Conflict { message, .. } => {
                (StatusCode::CONFLICT, ErrorCode::Conflict, message.clone())
            }
            Self::LaterPause(_) => (
                StatusCode::CONFLICT,
                ErrorCode::Conflict,
                "a later pause or resume of these agents exists: this one is old or repeated"
                    .into(),
            ),
            Self::LaterRevocation(_) => (
                StatusCode::CONFLICT,
                ErrorCode::Conflict,
                "a later revocation of this scope exists: this one is old or repeated".into(),
            ),
            Self::PayloadTooLarge => (
                StatusCode::PAYLOAD_TOO_LARGE,
                ErrorCode::PayloadTooLarge,
                "request body too large".into(),
            ),
            Self::TooManyRequests { .. } => (
                StatusCode::TOO_MANY_REQUESTS,
                ErrorCode::TooManyRequests,
                "too many requests".into(),
            ),
            Self::Unavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                ErrorCode::Unavailable,
                "service unavailable".into(),
            ),
            Self::Coded(status, code, m) => (*status, *code, m.clone()),
            Self::Internal(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorCode::Internal,
                "internal server error".into(),
            ),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        if let Self::Internal(detail) = &self {
            tracing::error!(error = %detail, "internal error");
        }
        let (status, code, message) = self.parts();
        let current_version = match &self {
            Self::Conflict {
                current_version, ..
            } => *current_version,
            _ => None,
        };
        let paused = match &self {
            Self::Paused(p) => Some(*p),
            _ => None,
        };
        let last_at = match &self {
            Self::LaterPause(at) | Self::LaterRevocation(at) => Some(*at),
            _ => None,
        };
        let delete_at = match &self {
            Self::AccountDeleting(at) => Some(*at),
            _ => None,
        };
        let mut response = (
            status,
            Json(ErrorBody {
                error: code,
                message,
                current_version,
                paused,
                last_at,
                delete_at,
            }),
        )
            .into_response();
        if let Self::TooManyRequests { retry_after_secs } = self {
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from(retry_after_secs));
        }
        response
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(err: sqlx::Error) -> Self {
        // sqlx error messages contain SQL text and driver messages, never the
        // bound values, so they are safe to log; they are not sent to clients.
        Self::Internal(format!("database: {err}"))
    }
}

impl From<std::io::Error> for ApiError {
    fn from(err: std::io::Error) -> Self {
        Self::Internal(format!("io: {err}"))
    }
}

/// JSON body extractor whose rejection is an [`ApiError`] (JSON error body,
/// 413 for oversized bodies). The body is never logged.
pub(crate) struct ApiJson<T>(pub(crate) T);

impl<S, T> FromRequest<S> for ApiJson<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        match Json::<T>::from_request(req, state).await {
            Ok(Json(value)) => Ok(Self(value)),
            Err(rejection) => Err(json_rejection(&rejection)),
        }
    }
}

/// Query-string extractor whose rejection is a JSON [`ApiError`].
pub(crate) struct ApiQuery<T>(pub(crate) T);

impl<S, T> axum::extract::FromRequestParts<S> for ApiQuery<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        axum::extract::Query::<T>::from_request_parts(parts, state)
            .await
            .map(|axum::extract::Query(value)| Self(value))
            .map_err(|e| ApiError::bad_request(format!("invalid query: {}", e.body_text())))
    }
}

fn json_rejection(rejection: &JsonRejection) -> ApiError {
    if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE {
        return ApiError::PayloadTooLarge;
    }
    match rejection {
        JsonRejection::MissingJsonContentType(_) => {
            ApiError::bad_request("expected Content-Type: application/json")
        }
        // The serde message helps client developers; it is returned to the
        // caller only and never logged.
        JsonRejection::JsonDataError(e) => ApiError::bad_request(format!("invalid body: {e}")),
        _ => ApiError::bad_request("invalid JSON body"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn internal_errors_do_not_leak() {
        let (status, code, message) =
            ApiError::Internal("database: secret table exploded".into()).parts();
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(code, ErrorCode::Internal);
        assert!(!message.contains("secret"));
    }

    #[test]
    fn a_pause_says_which_since_and_until() {
        use axum::body::to_bytes;
        let response = ApiError::Paused(AgentPaused {
            scope: klav_proto::agent::PauseScope::All,
            since: 5,
            until: Some(9),
        })
        .into_response();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = futures_body(response);
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["error"], "agents_paused");
        assert_eq!(value["scope"], "all");
        assert_eq!(value["since"], 5);
        assert_eq!(value["until"], 9);
        let parsed: ErrorBody = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed.paused.map(|p| p.since), Some(5));
        // Other errors carry no pause.
        let parsed: ErrorBody =
            serde_json::from_str(r#"{"error":"forbidden","message":"not allowed"}"#).unwrap();
        assert!(parsed.paused.is_none());

        fn futures_body(response: Response) -> Vec<u8> {
            tokio::runtime::Builder::new_current_thread()
                .build()
                .unwrap()
                .block_on(to_bytes(response.into_body(), 4096))
                .unwrap()
                .to_vec()
        }
    }

    #[test]
    fn a_deletion_says_when_and_a_wrong_password_is_not_a_401() {
        use axum::body::to_bytes;
        let body = |e: ApiError| {
            let response = e.into_response();
            let status = response.status();
            let bytes = tokio::runtime::Builder::new_current_thread()
                .build()
                .unwrap()
                .block_on(to_bytes(response.into_body(), 4096))
                .unwrap();
            (
                status,
                serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(),
            )
        };
        let (status, value) = body(ApiError::AccountDeleting(1_234));
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(value["error"], "account_deleting");
        assert_eq!(value["delete_at"], 1_234);
        let (status, value) = body(ApiError::ReauthFailed);
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(value["error"], "reauth_failed");
        assert!(value.get("delete_at").is_none());
    }

    #[test]
    fn stale_carries_current_version() {
        match ApiError::stale(7) {
            ApiError::Conflict {
                current_version, ..
            } => assert_eq!(current_version, Some(7)),
            other => panic!("unexpected {other:?}"),
        }
    }
}
