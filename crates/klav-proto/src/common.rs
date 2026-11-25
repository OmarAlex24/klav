//! Types shared by every endpoint.

use serde::{Deserialize, Serialize};

/// Machine-readable error code returned in [`ErrorBody::error`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ErrorCode {
    /// The request is malformed or fails validation (400).
    BadRequest,
    /// Missing, invalid, expired or revoked credentials (401).
    Unauthorized,
    /// Authenticated, but not allowed to touch this resource (403).
    Forbidden,
    /// The resource does not exist or is not visible to the caller (404).
    NotFound,
    /// Stale version, duplicate ID or invalid state transition (409).
    Conflict,
    /// The request body exceeds the configured limit (413).
    PayloadTooLarge,
    /// Rate limit exceeded; see the `Retry-After` header (429).
    TooManyRequests,
    /// Unexpected server error; details are only in the server log (500).
    Internal,
    /// The server (or its database) is temporarily unavailable (503).
    Unavailable,
    /// The person paused this agent, or every agent (403, ADR 0033 §7.4):
    /// the body says which pause, since when and until when.
    AgentsPaused,
    /// The master password given to confirm deleting the account is wrong,
    /// or the OPAQUE handle is expired, used, from another session or from
    /// a log-in (403, ADR 0037 §1). Never a `401`: the session is still
    /// valid.
    ReauthFailed,
    /// The person asked to delete the account: every signed agent request
    /// but `GET /v1/agent/me` is refused until the deletion is canceled or
    /// done (403, ADR 0037 §3). The body carries `delete_at`.
    AccountDeleting,
    /// The issuer a credential proxy names is not among the issuers of its
    /// grant, or is no longer an active agent whose grant names this proxy
    /// (403, ADR 0036 §4, E1.3).
    NotIssuer,
    /// A sandbox asked for a profile its issuer was not given (403, ADR
    /// 0036 E1.3).
    ProfileNotAllowed,
    /// The issuer already has as many live sandboxes as its grant allows
    /// (409, ADR 0036 E1.3).
    TooManySandboxes,
    /// The sandbox was revoked or ended, or its issuer was removed: nothing
    /// more can be recorded for it but its end, and not twice (403, ADR
    /// 0036 E3.3).
    SandboxRevoked,
    /// The sandbox was already claimed: a second claim is the theft signal,
    /// which the proxy records as its end (409, ADR 0036 §5).
    SandboxClaimed,
    /// The sandbox routes do not know this sandbox: this proxy never logged
    /// its `sandbox.issued` (404, ADR 0036 E3.3). Only this code tells a
    /// proxy the server never had the sandbox, so its end can be dropped;
    /// the generic `not_found` of a route the server does not have says
    /// nothing about it. Older servers answer `not_found`.
    SandboxNotFound,
    /// The server is in `invite` mode and this invite code cannot be used
    /// by this email now: unknown, revoked, expired, used up or bound to
    /// another email. One answer for every reason, and it never says
    /// whether the email has an account (403, ADR 0048 §1.3).
    InviteInvalid,
    /// The write would take the account over one of its quotas
    /// (attachments, vault data, items or vaults). The message names the
    /// limit, how much is used and the maximum (403, ADR 0048 §3.2).
    QuotaExceeded,
}

/// Body of every non-2xx JSON response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorBody {
    /// Machine-readable code.
    pub error: ErrorCode,
    /// Human-readable message. Never contains internal details.
    pub message: String,
    /// On a version conflict (409), the version currently stored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_version: Option<u64>,
    /// With [`ErrorCode::AgentsPaused`]: `scope`, `since` and `until` at
    /// the top level of the body.
    #[serde(flatten, default, skip_serializing_if = "Option::is_none")]
    pub paused: Option<crate::agent::AgentPaused>,
    /// On a 409 to a pause or a resume whose `at` is not later than the
    /// scope's latest decision: that decision's `at` (Unix ms), so the
    /// caller can sign again after it (ADR 0033 §7.6).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_at: Option<i64>,
    /// With [`ErrorCode::AccountDeleting`]: when the account is deleted
    /// (Unix ms, ADR 0037 §3).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delete_at: Option<i64>,
}

/// `GET /v1/health`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthResponse {
    /// `"ok"` when the server and its database respond.
    pub status: String,
    /// Server version (`CARGO_PKG_VERSION`).
    pub version: String,
    /// Whether the server accepts new accounts, so clients can say so
    /// before asking for a password (ADR 0028 §3). Absent on older servers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registration_open: Option<bool>,
    /// Whether the person can delete the account from the apps and the CLI
    /// (`POST /v1/account/delete/…`, ADR 0037 §4). Clients ask before
    /// asking for Face ID, Touch ID or the password. Absent on older
    /// servers, which cannot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_deletion: Option<bool>,
    /// How the server takes new accounts (ADR 0048 §1.2). Clients read it
    /// first and fall back to `registration_open` when it is absent (an
    /// older server). In `invite` mode `registration_open` is `false`, so
    /// older clients stop before writing an emergency kit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registration_mode: Option<RegistrationMode>,
}

/// How a server takes new accounts (`registration_mode`, ADR 0048 §1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RegistrationMode {
    /// Anyone can sign up.
    Open,
    /// Signing up needs a valid invite code.
    Invite,
    /// Nobody can sign up.
    Closed,
    /// A mode this client does not know (a newer server). Clients treat it
    /// as closed; a server never sends it.
    #[serde(other)]
    Unknown,
}

impl RegistrationMode {
    /// The name used in the configuration and on the wire.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Invite => "invite",
            Self::Closed => "closed",
            Self::Unknown => "unknown",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_reads_with_and_without_a_registration_mode() {
        let old: HealthResponse =
            serde_json::from_str(r#"{"status":"ok","version":"0.9.2","registration_open":false}"#)
                .unwrap();
        assert_eq!(old.registration_mode, None);
        let new: HealthResponse = serde_json::from_str(
            r#"{"status":"ok","version":"0.10.0","registration_open":false,"registration_mode":"invite"}"#,
        )
        .unwrap();
        assert_eq!(new.registration_mode, Some(RegistrationMode::Invite));
        // A mode from a newer server does not break the whole answer.
        let newer: HealthResponse = serde_json::from_str(
            r#"{"status":"ok","version":"9.0.0","registration_mode":"waitlist"}"#,
        )
        .unwrap();
        assert_eq!(newer.registration_mode, Some(RegistrationMode::Unknown));
        for mode in [
            RegistrationMode::Open,
            RegistrationMode::Invite,
            RegistrationMode::Closed,
        ] {
            assert_eq!(
                serde_json::to_string(&mode).unwrap(),
                format!("\"{}\"", mode.as_str())
            );
        }
    }

    #[test]
    fn new_error_codes_are_snake_case() {
        assert_eq!(
            serde_json::to_string(&ErrorCode::InviteInvalid).unwrap(),
            "\"invite_invalid\""
        );
        assert_eq!(
            serde_json::to_string(&ErrorCode::QuotaExceeded).unwrap(),
            "\"quota_exceeded\""
        );
    }
}
