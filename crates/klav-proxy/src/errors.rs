//! The answers the proxy gives instead of the provider's (ADR 0036 §10):
//! an HTTP status, a `Klav-Error` header and a JSON body with `error`,
//! `message` and `next`. The texts are fixed: never the provider's body,
//! a header value, a path or anything decrypted.

use axum::Json;
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use klav_core::ids::ApprovalId;
use serde_json::json;

/// The header that marks an answer as the proxy's.
pub const KLAV_ERROR: &str = "klav-error";

/// What went wrong, in the closed list of ADR 0036 §10
/// (`klav_proxy_unreachable` is the forwarder's).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyError {
    /// The proxy cannot reach the Klav server.
    ServerUnreachable,
    /// The person paused the agents (ADR 0033 §7).
    AgentsPaused,
    /// Outside the profile, refused by the policy, or the proxy was revoked.
    NotAllowed(NotAllowed),
    /// The path is not in its one canonical spelling: why, naming at most
    /// the one character or escape refused (`paths::path_problem`).
    PathRefused(String),
    /// The person has to decide first.
    ApprovalPending {
        /// The approval.
        approval_id: ApprovalId,
        /// Until when she can decide (Unix ms).
        expires_at: i64,
    },
    /// The person said no.
    ApprovalDenied,
    /// Too many calls through this profile.
    RateLimited {
        /// Seconds until a call fits again.
        retry_after: u64,
    },
    /// The provider's answer cannot go back as it is, or the provider
    /// could not be reached safely.
    UpstreamBlocked(Blocked),
    /// A sandbox's call: the server says the sandbox or its issuer is over
    /// (`403 sandbox_revoked`), or the proxy no longer has it.
    SandboxRevoked,
    /// A sandbox's call: the sandbox's time ran out while the call waited
    /// for the server.
    SandboxExpired,
    /// A sandbox's call: the proxy ended the sandbox while the call waited
    /// for the server, and says why ([`ended_message`]).
    SandboxEnded(klav_proto::sandbox::SandboxEnd),
}

/// What the key of an ended sandbox is told: why it ended, in fixed words
/// (papercut 4). A theft reads the same for both claimers.
pub fn ended_message(reason: klav_proto::sandbox::SandboxEnd) -> &'static str {
    use klav_proto::sandbox::SandboxEnd;
    match reason {
        SandboxEnd::Stop => {
            "This sandbox's access to Klav's credential proxy has ended: the agent that started it stopped it."
        }
        SandboxEnd::Ttl => "This sandbox's time with Klav's credential proxy is over.",
        SandboxEnd::Inactivity => {
            "This sandbox's access to Klav's credential proxy has ended: an hour went by without a connection from it."
        }
        SandboxEnd::Theft => {
            "This sandbox's access to Klav's credential proxy has ended: its one-time package was claimed a second time, from another forwarder, so the proxy ended it in case someone copied its environment. Neither forwarder is told which claim came first."
        }
        SandboxEnd::Released => {
            "This sandbox's access to Klav's credential proxy has ended: its forwarder released it (`klav-forward down`)."
        }
        SandboxEnd::IssuerRemoved => {
            "This sandbox's access to Klav's credential proxy has ended: the person removed or revoked the agent that started it."
        }
        SandboxEnd::Person | SandboxEnd::PersonLocal => {
            "This sandbox's access to Klav's credential proxy has ended: the person revoked it."
        }
    }
}

/// The `error` code of an ended sandbox: `klav_sandbox_expired` for its
/// time running out, `klav_sandbox_revoked` for every other end.
pub fn ended_code(reason: klav_proto::sandbox::SandboxEnd) -> &'static str {
    match reason {
        klav_proto::sandbox::SandboxEnd::Ttl => "klav_sandbox_expired",
        _ => "klav_sandbox_revoked",
    }
}

/// Why a call is not allowed (shown in `message`; none of them holds data
/// from the request beyond what the caller already knows).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotAllowed {
    /// No profile with that name in the proxy's grant.
    UnknownProfile,
    /// The policy refuses this method, host or path (checked here).
    Policy,
    /// The Klav server refused the call (`403`): its policy, the person
    /// revoked the proxy, or the account is being deleted; the server
    /// answers the first two alike.
    ServerDenied,
    /// The request is not one the proxy forwards as it is (absolute-form,
    /// a path the URL parser would re-encode, a body over the limit).
    Malformed,
    /// The Klav server did not accept the proxy's signature (`401`): an
    /// agent it does not know, or a clock off by more than 5 minutes.
    ProxyRefused,
    /// A request that carries a browser's `Origin` or `Sec-Fetch-Site`, or
    /// addressed to another host name than the proxy's own address (DNS
    /// rebinding).
    NotLocal,
    /// The query names a method (`_method` and the like), which the policy
    /// cannot judge.
    MethodInQuery,
    /// The server's answer did not check out (a rollback, another item, an
    /// approval the account did not sign for this request).
    Unverifiable,
    /// A call on the loopback listener of a proxy started with
    /// `--no-local-calls` (ADR 0042 §3): only sandboxes, through the
    /// channel, reach its profiles.
    LocalCallsOff,
    /// The server refused the call, and the proxy's own copy of the grant
    /// says why: its rules for this credential and host allow other paths,
    /// never this one. Which paths is not said.
    OutsidePath,
    /// The same, for the method.
    OutsideMethod,
    /// The same: some rules allow this method, others this path, none
    /// both together.
    OutsideMethodOnPath,
}

/// Why the provider's answer was blocked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Blocked {
    /// The host resolved to a private, loopback, link-local or metadata
    /// address, or did not resolve.
    Address,
    /// A redirect (never followed).
    Redirect,
    /// A compressed or otherwise encoded body (not decompressed yet).
    Encoded,
    /// The provider did not answer in time, or the connection failed.
    Unreachable,
    /// The body could not be checked to the end (a redacted stretch too
    /// long to hold, or the stream broke).
    Body,
}

impl ProxyError {
    /// The `error` code.
    pub fn code(&self) -> &'static str {
        match self {
            Self::ServerUnreachable => "klav_server_unreachable",
            Self::AgentsPaused => "klav_agents_paused",
            Self::NotAllowed(_) | Self::PathRefused(_) => "klav_not_allowed",
            Self::ApprovalPending { .. } => "klav_approval_pending",
            Self::ApprovalDenied => "klav_approval_denied",
            Self::RateLimited { .. } => "klav_rate_limited",
            Self::UpstreamBlocked(_) => "klav_upstream_blocked",
            Self::SandboxRevoked => "klav_sandbox_revoked",
            Self::SandboxExpired => "klav_sandbox_expired",
            Self::SandboxEnded(reason) => ended_code(*reason),
        }
    }

    /// The HTTP status.
    pub fn status(&self) -> StatusCode {
        match self {
            Self::ServerUnreachable => StatusCode::SERVICE_UNAVAILABLE,
            Self::AgentsPaused => StatusCode::LOCKED,
            Self::NotAllowed(_) | Self::PathRefused(_) | Self::ApprovalDenied => {
                StatusCode::FORBIDDEN
            }
            Self::ApprovalPending { .. } => StatusCode::CONFLICT,
            Self::RateLimited { .. } => StatusCode::TOO_MANY_REQUESTS,
            Self::UpstreamBlocked(_) => StatusCode::BAD_GATEWAY,
            Self::SandboxRevoked | Self::SandboxExpired | Self::SandboxEnded(_) => {
                StatusCode::UNAUTHORIZED
            }
        }
    }

    pub(crate) fn message(&self) -> std::borrow::Cow<'static, str> {
        if let Self::SandboxEnded(reason) = self {
            return ended_message(*reason).into();
        }
        if let Self::PathRefused(why) = self {
            return format!(
                "Klav's credential proxy only forwards a path in its one canonical spelling, and this one is not: {why}."
            )
            .into();
        }
        let text: &'static str = match self {
            Self::ServerUnreachable => {
                "Klav's credential proxy could not reach the Klav server, so it cannot check this call."
            }
            Self::AgentsPaused => {
                "The person paused Klav's agents: no call goes through until they resume them."
            }
            Self::NotAllowed(NotAllowed::UnknownProfile) => {
                "Klav's credential proxy has no profile with that name."
            }
            Self::NotAllowed(NotAllowed::Policy) => {
                "This call is outside what the person allowed for this credential (host, method or path)."
            }
            Self::NotAllowed(NotAllowed::Malformed) => {
                "Klav's credential proxy only forwards plain requests to its own address, with a path it can send exactly as received and a body within its limit."
            }
            Self::NotAllowed(NotAllowed::NotLocal) => {
                "Klav's credential proxy only takes requests addressed to 127.0.0.1 or localhost and its port, and refuses requests that carry a browser's Origin or Sec-Fetch-Site header."
            }
            Self::NotAllowed(NotAllowed::MethodInQuery) => {
                "Klav's credential proxy refuses a query that names the method (such as _method): the person's rules judge the request's own method."
            }
            Self::NotAllowed(NotAllowed::ServerDenied) => {
                "The Klav server refused this call: it is outside what the person allowed for this credential, the person revoked this credential proxy, or the account is being deleted."
            }
            Self::NotAllowed(NotAllowed::ProxyRefused) => {
                "The Klav server did not accept this credential proxy's signature: it does not know the proxy, or the proxy's clock is off by more than 5 minutes."
            }
            Self::NotAllowed(NotAllowed::LocalCallsOff) => {
                "Klav's credential proxy was started with --no-local-calls: it serves no calls from programs on its own machine, only sandboxes through their forwarder."
            }
            Self::NotAllowed(NotAllowed::OutsidePath) => {
                "This call's path is outside what the person allowed for this credential."
            }
            Self::NotAllowed(NotAllowed::OutsideMethod) => {
                "This call's method is outside what the person allowed for this credential."
            }
            Self::NotAllowed(NotAllowed::OutsideMethodOnPath) => {
                "This call's method on this path is outside what the person allowed for this credential."
            }
            Self::NotAllowed(NotAllowed::Unverifiable) => {
                "Klav's credential proxy could not verify the Klav server's answer, so it did not use the credential."
            }
            Self::ApprovalPending { .. } => "This call needs the person's approval first.",
            Self::ApprovalDenied => "The person denied this call.",
            Self::RateLimited { .. } => {
                "Too many calls through this credential in the last minute."
            }
            Self::UpstreamBlocked(Blocked::Address) => {
                "The provider's address is private, local or a cloud metadata address, so Klav's credential proxy did not connect."
            }
            Self::UpstreamBlocked(Blocked::Redirect) => {
                "The provider answered with a redirect, which Klav's credential proxy never follows."
            }
            Self::UpstreamBlocked(Blocked::Encoded) => {
                "The provider sent a compressed or otherwise encoded answer that Klav's credential proxy cannot check yet."
            }
            Self::UpstreamBlocked(Blocked::Unreachable) => {
                "Klav's credential proxy could not reach the provider."
            }
            Self::UpstreamBlocked(Blocked::Body) => {
                "Klav's credential proxy could not check the provider's answer to the end, so it cut it."
            }
            Self::SandboxRevoked => {
                "This sandbox's access to Klav's credential proxy has ended: it was stopped, revoked, or its issuer was removed or paused."
            }
            Self::SandboxExpired => "This sandbox's time with Klav's credential proxy is over.",
            Self::PathRefused(_) | Self::SandboxEnded(_) => unreachable!("handled above"),
        };
        text.into()
    }

    fn next(&self) -> &'static str {
        match self {
            Self::ApprovalPending { .. } => {
                "Tell the person what you asked for and that it waits for their approval on their phone or Mac. Retry the same request once they approve; do not change it to get around the approval."
            }
            Self::RateLimited { .. } => {
                "Wait retry_after seconds before the next call. Do not retry in a loop."
            }
            Self::PathRefused(_) => {
                "Send the same request with the path written as the message says (the character itself instead of its escape). If your HTTP client escapes it on its own, tell the person this message; do not look for the token elsewhere."
            }
            Self::SandboxRevoked | Self::SandboxExpired | Self::SandboxEnded(_) => {
                "Tell the person this exact message and stop. Only the person or the agent that started the sandbox can start another one. Do not retry and do not look for the token elsewhere."
            }
            Self::ApprovalDenied | Self::NotAllowed(_) => {
                "Tell the person this exact message and stop. Do not retry another way and do not look for the token elsewhere."
            }
            _ => {
                "Tell the person this exact message and stop. Do not retry in a loop and do not look for the token elsewhere."
            }
        }
    }
}

impl IntoResponse for ProxyError {
    fn into_response(self) -> Response {
        let mut body = json!({
            "error": self.code(),
            "message": self.message(),
            "next": self.next(),
        });
        match &self {
            Self::ApprovalPending {
                approval_id,
                expires_at,
            } => {
                body["approval_id"] = json!(approval_id.to_string());
                body["expires_at"] = json!(expires_at);
            }
            Self::RateLimited { retry_after } => body["retry_after"] = json!(retry_after),
            _ => {}
        }
        let mut res = (self.status(), Json(body)).into_response();
        res.headers_mut()
            .insert(KLAV_ERROR, HeaderValue::from_static(self.code()));
        if let Self::RateLimited { retry_after } = &self
            && let Ok(v) = HeaderValue::from_str(&retry_after.to_string())
        {
            res.headers_mut().insert("retry-after", v);
        }
        res
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_error_carries_its_code_in_the_header_and_body() {
        let all = [
            ProxyError::ServerUnreachable,
            ProxyError::AgentsPaused,
            ProxyError::NotAllowed(NotAllowed::Policy),
            ProxyError::NotAllowed(NotAllowed::LocalCallsOff),
            ProxyError::ApprovalPending {
                approval_id: ApprovalId::generate(),
                expires_at: 1,
            },
            ProxyError::ApprovalDenied,
            ProxyError::RateLimited { retry_after: 3 },
            ProxyError::UpstreamBlocked(Blocked::Redirect),
            ProxyError::SandboxRevoked,
            ProxyError::SandboxExpired,
        ];
        let statuses = [503, 423, 403, 403, 409, 403, 429, 502, 401, 401];
        for (e, status) in all.into_iter().zip(statuses) {
            let code = e.code();
            let res = e.into_response();
            assert_eq!(res.status().as_u16(), status, "{code}");
            assert_eq!(res.headers()[KLAV_ERROR], code);
        }
    }
}
