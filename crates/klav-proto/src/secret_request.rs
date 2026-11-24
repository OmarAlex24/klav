//! Agent secret requests (ADR 0046, `docs/api.md` §8.12): an agent asks the
//! person to add a missing item or update a secret field, sending only
//! HPKE-encrypted proposal metadata (never a secret value). The person enters
//! the value on their own device and signs a [`klav_core::secret_request::SecretRequestDecision`].

use klav_core::ids::{AgentId, ItemId, SecretRequestId};
use klav_core::secret_request::SecretRequestMode;
use serde::{Deserialize, Serialize};

use crate::Blob;

/// How long a person has to answer a secret request (Unix ms): 1 hour
/// (ADR 0046 §1).
pub const SECRET_REQUEST_TTL_MS: i64 = 60 * 60 * 1000;
/// Longest `?wait=` of `GET /v1/agent/secret-requests/{id}` (seconds, like
/// approvals and tasks).
pub const MAX_SECRET_REQUEST_WAIT_SECS: u64 = 30;
/// Maximum pending secret requests per agent (ADR 0046 Q2).
pub const MAX_PENDING_SECRET_REQUESTS: i64 = 5;

/// Lifecycle state of a secret request on the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretRequestState {
    /// Waiting for the person.
    Pending,
    /// The person saved the secret and signed the decision.
    Fulfilled,
    /// The person denied the request and signed the decision.
    Denied,
    /// The request expired (or the agent was revoked) before a decision.
    Expired,
}

impl SecretRequestState {
    /// Storage form.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Fulfilled => "fulfilled",
            Self::Denied => "denied",
            Self::Expired => "expired",
        }
    }

    /// Parses [`SecretRequestState::as_str`].
    pub fn parse(text: &str) -> Option<Self> {
        Some(match text {
            "pending" => Self::Pending,
            "fulfilled" => Self::Fulfilled,
            "denied" => Self::Denied,
            "expired" => Self::Expired,
            _ => return None,
        })
    }
}

/// `POST /v1/agent/secret-requests`: an agent asks the person for a secret.
///
/// The agent picks `id` before calling because `id` is bound into the HPKE
/// `info` tuple that sealed `proposal_blob` (spec §13.14).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateSecretRequest {
    /// Client-generated request ID (`409` if already used).
    pub id: SecretRequestId,
    /// Create a new item or update a field of an existing one.
    pub mode: SecretRequestMode,
    /// Item to update; required when `mode == update`, absent when `mode == create`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_item_id: Option<ItemId>,
    /// Short explanation shown to the person and logged in the audit chain.
    pub reason: String,
    /// SHA-256 of the canonical [`klav_core::secret_request::SecretRequestProposal`]
    /// JSON bytes before sealing (32 bytes).
    pub proposal_digest: Blob,
    /// Proposal sealed with HPKE to the account's X25519 identity (kind `0x25`).
    pub proposal_blob: Blob,
}

/// `POST /v1/agent/secret-requests` → `202`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingSecretRequest {
    /// Request ID to poll with `GET /v1/agent/secret-requests/{id}?wait=N`.
    pub request_id: SecretRequestId,
    /// When the request expires if unanswered (Unix ms).
    pub expires_at: i64,
}

/// A secret request as stored and returned by the API.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretRequestInfo {
    /// Request ID.
    pub id: SecretRequestId,
    /// Agent that asked.
    pub agent_id: AgentId,
    /// Agent name.
    pub agent_name: String,
    /// Create or update.
    pub mode: SecretRequestMode,
    /// Target item in `update` mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_item_id: Option<ItemId>,
    /// Plaintext reason.
    pub reason: String,
    /// SHA-256 of the canonical proposal JSON (32 bytes).
    pub proposal_digest: Blob,
    /// HPKE-sealed proposal blob (kind `0x25`); present only while pending for
    /// the person's devices and cleared on decision or expiry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proposal_blob: Option<Blob>,
    /// Current state.
    pub status: SecretRequestState,
    /// Created at (Unix ms).
    pub created_at: i64,
    /// Expires at (Unix ms).
    pub expires_at: i64,
    /// Decided at (Unix ms), as signed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decided_at: Option<i64>,
    /// Signed JSON bytes of `klav_core::secret_request::SecretRequestDecision`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision: Option<Blob>,
    /// Account Ed25519 signature over the decision (spec §13.14).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<Blob>,
}

/// `GET /v1/secret-requests`: the account's secret requests, newest first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretRequestList {
    /// Newest first (at most 100).
    pub secret_requests: Vec<SecretRequestInfo>,
}

/// `POST /v1/secret-requests/{id}/decide`: the person's signed decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecideSecretRequest {
    /// Exact JSON bytes of `klav_core::secret_request::SecretRequestDecision`, as signed.
    pub decision: Blob,
    /// Account Ed25519 signature over the decision (spec §13.14).
    pub signature: Blob,
    /// When the person decided (Unix ms), as signed.
    pub decided_at: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn states_roundtrip() {
        for state in [
            SecretRequestState::Pending,
            SecretRequestState::Fulfilled,
            SecretRequestState::Denied,
            SecretRequestState::Expired,
        ] {
            assert_eq!(SecretRequestState::parse(state.as_str()), Some(state));
            assert_eq!(
                serde_json::to_value(state).unwrap(),
                serde_json::Value::String(state.as_str().into())
            );
        }
        assert_eq!(SecretRequestState::parse("other"), None);
    }
}
