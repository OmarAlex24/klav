//! Klav Cloud's hosted proxy inside an AWS Nitro Enclave (ADR 0051): the
//! same proxy as a self-hosted one, serving many accounts, each under keys
//! derived from one seed that lives only in enclave memory.
//!
//! - [`attest`]: the Nitro Secure Module behind [`AttestationProvider`]:
//!   `/dev/nsm` on Linux, a fake with a test P-384 chain in tests.
//! - [`trust`]: what the enclave trusts, [`Anchors`] (AWS's root and the
//!   release authority's keys), and where it reads the published manifests
//!   ([`ManifestSource`]).
//! - [`registry`]: the enrollments, the only state besides the seed that a
//!   hand-off carries.
//! - [`quota`]: the per-account quotas (§3.3).
//! - [`engine`]: the [`Enclave`]: the seed, the accounts and their
//!   [`crate::proxy::ProxyState`]s, the channel routed by SNI (§3.4), the
//!   public API (`/v1/manifest`, `/v1/attest`, `/v1/enroll`) and the
//!   attested hand-off (§4.2).
//!
//! Nothing here writes to a disk. The seed and every derived private key
//! stay in [`klav_core`] types that zeroize and print nothing; no log line
//! carries a key, a token, an e-mail or a body.

pub mod attest;
pub mod engine;
pub mod quota;
pub mod registry;
pub mod trust;

#[cfg(all(test, feature = "enclave-testkit"))]
mod tests;

pub use attest::{AttestRequest, AttestationProvider};
pub use engine::{Enclave, EnclaveConfig};
pub use quota::QuotaLimits;
pub use trust::{Anchors, ManifestSource, PublishedRepo, SignedManifest};

use axum::Json;
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};

/// The current time, Unix milliseconds.
pub(crate) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// A refusal in the proxy's format (ADR 0036 §10): the status, the
/// `Klav-Error` header and `{error, message, next}`; `retry_after` when
/// waiting helps.
pub(crate) fn refuse(
    status: StatusCode,
    code: &'static str,
    message: &'static str,
    next: &'static str,
    retry_after: Option<u64>,
) -> Response {
    let mut body = serde_json::json!({ "error": code, "message": message, "next": next });
    if let Some(secs) = retry_after {
        body["retry_after"] = serde_json::json!(secs);
    }
    let mut res = (status, Json(body)).into_response();
    res.headers_mut()
        .insert(crate::errors::KLAV_ERROR, HeaderValue::from_static(code));
    if let Some(secs) = retry_after
        && let Ok(v) = HeaderValue::from_str(&secs.to_string())
    {
        res.headers_mut().insert("retry-after", v);
    }
    res
}

/// The channel name of `agent`'s account under `endpoint`:
/// `a<agent_id hex>.<endpoint>` (ADR 0051 §3.4).
pub fn channel_name(agent: klav_core::ids::AgentId, endpoint: &str) -> String {
    format!(
        "a{}.{}",
        data_encoding::HEXLOWER.encode(agent.as_bytes()),
        endpoint.to_ascii_lowercase()
    )
}
