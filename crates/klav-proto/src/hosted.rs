//! Klav Cloud's hosted proxy, its public API (ADR 0051 §6.4): what the
//! enclave answers through its parent and what the person's devices send
//! it. Every answer is self-authenticating (the manifest is signed by the
//! release authority, the attestation by AWS's Nitro PKI) or signed by the
//! account, so the transport is not trusted. One definition for the enclave
//! (`klav-proxy --features enclave`) and the devices (`klav-client`).

use serde::{Deserialize, Serialize};

use crate::Blob;
use klav_core::ids::{AccountId, AgentId};

/// `GET /v1/manifest`: the signed Klav Enclave Transparency Manifest, its
/// exact text and the signature in hex (ADR 0051 §2.4).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestWire {
    /// The manifest's bytes (UTF-8 JSON), as signed.
    pub manifest: String,
    /// The signature, 128 hex characters.
    pub signature: String,
}

/// `GET /v1/attest?account&nonce` answer (ADR 0051 §2.2 step 1).
#[derive(Debug, Serialize, Deserialize)]
pub struct AttestAnswer {
    /// The attestation document, `user_data` = the account's binding.
    pub document: Blob,
    /// The account's hosted agent.
    pub agent_id: AgentId,
    /// Its generation.
    pub generation: u32,
    /// The `seq` of the manifest the enclave serves.
    pub manifest_seq: u64,
}

/// `POST /v1/enroll` (ADR 0051 §6.1 step 2).
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollRequest {
    /// The account.
    pub account_id: AccountId,
    /// Its e-mail, for the agent's registration.
    pub email: String,
    /// Its identity (kind `0x05`), which signed this request.
    pub account_public_identity: Blob,
    /// The generation asked for.
    pub generation: u32,
    /// When it was signed (Unix ms).
    pub at_ms: u64,
    /// `tuple("klav/v1/sig/hosted-proxy-enroll", …)`, by the account.
    pub signature: Blob,
}

/// `POST /v1/enroll` answer.
#[derive(Debug, Serialize, Deserialize)]
pub struct EnrollAnswer {
    /// The account's hosted agent, pending until the person approves it.
    pub agent_id: AgentId,
    /// Its generation.
    pub generation: u32,
    /// Its channel name (`a<agent_id hex>.<endpoint>`).
    pub channel: String,
    /// When the pending agent lapses (Unix ms), as the server said.
    pub expires_at: i64,
}

/// The `error` of an enclave's refusal for an account it doesn't know
/// (`404`): never enrolled, or enrolled under a seed it lost (ADR 0051
/// §4.4 step 2).
pub const NOT_ENROLLED: &str = "klav_hosted_not_enrolled";
/// The `error` of an enclave's refusal for an account the server says is
/// not entitled (`402` or `403`, ADR 0051 §3.5, §16).
pub const NOT_ENTITLED: &str = "klav_hosted_not_entitled";
