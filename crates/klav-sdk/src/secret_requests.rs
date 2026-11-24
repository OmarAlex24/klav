//! Agent secret requests, agent side (ADR 0046): an agent seals proposal
//! metadata with HPKE to the account's pinned X25519 identity (`kind 0x25`,
//! spec §13.14), sends `POST /v1/agent/secret-requests`, optionally long-polls
//! `GET /v1/agent/secret-requests/{id}?wait=N`, and verifies the person's
//! signed decision against the pinned account identity before acting on it
//! (T237).

use std::time::{Duration, Instant};

use klav_client::{ClientError, ClientResult};
use klav_core::crypto::agent::{
    self as agent_crypto, SecretRequestDecisionToSign, seal_secret_request,
    verify_secret_request_decision,
};
use klav_core::crypto::identity::PublicIdentity;
use klav_core::crypto::sign::{SIGNATURE_LEN, Signature};
use klav_core::ids::{AgentId, ItemId, ProjectId, SecretRequestId, VaultId};
use klav_core::model::item::ItemKind;
use klav_core::secret_request::{
    ProxyProposal, SECRET_REQUEST_FORMAT_VERSION, SecretRequestDecision, SecretRequestMode,
    SecretRequestProposal, SecretRequestStatus, validate_reason,
};
use klav_proto::Blob;
use klav_proto::secret_request::{
    CreateSecretRequest, MAX_SECRET_REQUEST_WAIT_SECS, PendingSecretRequest, SecretRequestInfo,
    SecretRequestState,
};
use reqwest::Method;
use serde::{Deserialize, Serialize};

use crate::agent::Agent;
use crate::session::Session;

/// High-level request built by an agent for [`Session::request_secret`].
#[derive(Debug, Clone)]
pub struct SecretRequestSpec {
    /// `create` or `update`.
    pub mode: SecretRequestMode,
    /// Why the agent needs this secret (1–500 chars, plain text).
    pub reason: String,
    /// Item kind (`create` mode: `api_key`, `login`, `note`, `ssh_key`, `totp`).
    pub kind: Option<ItemKind>,
    /// Suggested item title (`create` mode).
    pub title: Option<String>,
    /// Suggested project (`vault/project` or unique project name in the grant,
    /// `create` mode).
    pub project: Option<String>,
    /// Target item reference (`update` mode: `klav://…` or item ID).
    pub reference: Option<String>,
    /// Target secret field name (e.g. `"api_key"`, `"password"`).
    pub field: String,
    /// Optional short placeholder for the hidden input (e.g. `"sk_live_…"`).
    pub placeholder: Option<String>,
    /// Optional `https://` provider setup/dashboard URL (T235).
    pub setup_url: Option<String>,
    /// Optional API base URL (`api_key` in `create` mode).
    pub base_url: Option<String>,
    /// Optional login URLs (`login` in `create` mode; unchecked by default on
    /// the person's card, T234).
    pub urls: Vec<String>,
    /// Optional notes shown as suggested by the agent.
    pub notes: Option<String>,
    /// Optional `klav-proxy` profile proposal (ADR 0046 Q3).
    pub proxy_proposal: Option<ProxyProposal>,
    /// How long to long-poll before returning `Pending` (`Duration::ZERO`
    /// returns immediately).
    pub wait: Duration,
}

/// Verified outcome of an agent secret request. Never carries a secret value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum SecretRequestOutcome {
    /// Still waiting for the person to respond.
    Pending {
        /// Request ID to poll later.
        request_id: SecretRequestId,
        /// Expiry timestamp (Unix ms).
        expires_at: i64,
    },
    /// The person saved the secret and signed the decision.
    Fulfilled {
        /// Request ID.
        request_id: SecretRequestId,
        /// Whether the saved item lives in a project granted to this agent.
        in_grant: bool,
        /// Resolved `klav://<Vault>/<Project>/<Title>/<field>` reference when
        /// `in_grant` is `true` and the item is visible in this session.
        #[serde(rename = "ref", default, skip_serializing_if = "Option::is_none")]
        reference: Option<String>,
        /// Vault ID (`Some` only when `in_grant` is `true`, T236).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        vault_id: Option<VaultId>,
        /// Project ID (`Some` only when `in_grant` is `true`, T236).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        project_id: Option<ProjectId>,
        /// Item ID (`Some` only when `in_grant` is `true`, T236).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        item_id: Option<ItemId>,
        /// Name of the secret field saved.
        field: String,
        /// `klav-proxy` profile granted, if the person enabled the toggle.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        proxy_profile: Option<String>,
    },
    /// The person denied the request (verified signature).
    Denied {
        /// Request ID.
        request_id: SecretRequestId,
    },
    /// The request expired before a decision.
    Expired {
        /// Request ID.
        request_id: SecretRequestId,
    },
}

impl Agent {
    /// Seals `proposal` with HPKE to the pinned account identity and posts
    /// `POST /v1/agent/secret-requests`. Returns the pending handle and the
    /// canonical `proposal_digest` (32 bytes) to pin against T237.
    pub async fn create_secret_request(
        &self,
        reason: &str,
        proposal: &SecretRequestProposal,
    ) -> ClientResult<(PendingSecretRequest, [u8; 32])> {
        validate_reason(reason).map_err(|e| ClientError::Invalid(e.to_string()))?;
        proposal
            .validate()
            .map_err(|e| ClientError::Invalid(e.to_string()))?;
        let account = self.account_identity()?;
        let account_id = self.account_id()?;
        let id = SecretRequestId::generate();
        let canonical = serde_json::to_vec(proposal)
            .map_err(|e| ClientError::Invalid(format!("proposal: {e}")))?;
        let digest = agent_crypto::body_digest(&canonical);
        let blob = seal_secret_request(&account, account_id, self.id(), id, &canonical)?;
        let req = CreateSecretRequest {
            id,
            mode: proposal.mode,
            target_item_id: proposal.target_item_id,
            reason: reason.trim().to_owned(),
            proposal_digest: Blob::new(digest.to_vec()),
            proposal_blob: Blob::new(blob),
        };
        let pending: PendingSecretRequest = self
            .call(Method::POST, "/v1/agent/secret-requests", Some(&req))
            .await?;
        if pending.request_id != id {
            return Err(ClientError::Security(
                "the server answered with another secret request ID".into(),
            ));
        }
        Ok((pending, digest))
    }

    /// Reads one secret request, long-polling up to `wait` (at most
    /// [`MAX_SECRET_REQUEST_WAIT_SECS`]).
    pub async fn secret_request(
        &self,
        id: SecretRequestId,
        wait: Duration,
    ) -> ClientResult<SecretRequestInfo> {
        let secs = wait.as_secs().min(MAX_SECRET_REQUEST_WAIT_SECS);
        let path = if secs == 0 {
            format!("/v1/agent/secret-requests/{id}")
        } else {
            format!("/v1/agent/secret-requests/{id}?wait={secs}")
        };
        let info: SecretRequestInfo = self.call::<(), _>(Method::GET, &path, None).await?;
        if info.id != id || info.agent_id != self.id() {
            return Err(ClientError::Security(
                "the server answered for another secret request or agent".into(),
            ));
        }
        Ok(info)
    }

    /// Long-polls until secret request `id` is decided, expires, or `timeout`
    /// elapses.
    pub async fn wait_secret_request(
        &self,
        id: SecretRequestId,
        timeout: Duration,
    ) -> ClientResult<SecretRequestInfo> {
        let deadline = Instant::now() + timeout;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            let asked = Instant::now();
            let info = self.secret_request(id, left).await?;
            if info.status != SecretRequestState::Pending || left.as_secs() == 0 {
                return Ok(info);
            }
            // A server without long-polls answers at once.
            let pause = Duration::from_secs(1).saturating_sub(asked.elapsed());
            tokio::time::sleep(pause.min(left)).await;
        }
    }

    /// Verifies the signed decision of `info` against the pinned account
    /// identity (T237). When `expected_digest` is provided, also checks that
    /// the server returned the same `proposal_digest` this agent sealed.
    pub fn verify_secret_request(
        &self,
        info: &SecretRequestInfo,
        expected_digest: Option<&[u8; 32]>,
    ) -> ClientResult<Option<SecretRequestDecision>> {
        verify_secret_request_info(&self.account_identity()?, self.id(), info, expected_digest)
    }
}

/// Pure verifier for [`Agent::verify_secret_request`] against a pinned
/// `account` identity (T237).
pub fn verify_secret_request_info(
    account: &PublicIdentity,
    agent: AgentId,
    info: &SecretRequestInfo,
    expected_digest: Option<&[u8; 32]>,
) -> ClientResult<Option<SecretRequestDecision>> {
    if info.agent_id != agent {
        return Err(ClientError::Security(
            "the server answered for another agent's secret request".into(),
        ));
    }
    let digest: [u8; 32] = info
        .proposal_digest
        .as_bytes()
        .try_into()
        .map_err(|_| ClientError::Security("proposal digest has a wrong length".into()))?;
    if let Some(expected) = expected_digest
        && &digest != expected
    {
        return Err(ClientError::Security(format!(
            "secret request {} proposal digest differs from what this agent sent",
            info.id
        )));
    }
    let (Some(bytes), Some(sig), Some(decided_at)) =
        (&info.decision, &info.signature, info.decided_at)
    else {
        if matches!(
            info.status,
            SecretRequestState::Fulfilled | SecretRequestState::Denied
        ) {
            return Err(ClientError::Security(format!(
                "secret request {} is {} without a signed decision",
                info.id,
                info.status.as_str()
            )));
        }
        return Ok(None);
    };
    let sig_bytes: [u8; SIGNATURE_LEN] = sig
        .as_bytes()
        .try_into()
        .map_err(|_| ClientError::Security("secret request signature has a wrong length".into()))?;
    let decided_at_ms = u64::try_from(decided_at).unwrap_or(0);
    verify_secret_request_decision(
        account,
        &SecretRequestDecisionToSign {
            request: info.id,
            agent,
            proposal_digest: &digest,
            decision: bytes.as_bytes(),
            decided_at_ms,
        },
        &Signature::from_bytes(sig_bytes),
    )
    .map_err(|_| {
        ClientError::Security(format!(
            "the decision of secret request {} is not signed by the account",
            info.id
        ))
    })?;
    let decision: SecretRequestDecision = serde_json::from_slice(bytes.as_bytes())
        .map_err(|e| ClientError::Corrupt(format!("secret request {}: decision: {e}", info.id)))?;
    decision.validate().map_err(|e| {
        ClientError::Security(format!(
            "the decision of secret request {} is invalid: {e}",
            info.id
        ))
    })?;
    let status_matches = matches!(
        (info.status, decision.status),
        (
            SecretRequestState::Fulfilled,
            SecretRequestStatus::Fulfilled
        ) | (SecretRequestState::Denied, SecretRequestStatus::Denied)
    );
    if decision.request_id != info.id || decision.agent_id != agent || !status_matches {
        return Err(ClientError::Security(format!(
            "the decision of secret request {} does not match the request",
            info.id
        )));
    }
    Ok(Some(decision))
}

impl Session {
    /// Creates a secret request, optionally waits up to `spec.wait`, verifies
    /// the account's signature on any decision, and refreshes the session's
    /// item list when fulfilled inside this agent's grant so `ref` resolves.
    pub async fn request_secret(
        &mut self,
        spec: &SecretRequestSpec,
        scope: Option<(&str, &str)>,
    ) -> ClientResult<SecretRequestOutcome> {
        let (vault_id, project_id, target_item_id) = match spec.mode {
            SecretRequestMode::Create => {
                if spec.reference.is_some() {
                    return Err(ClientError::Invalid(
                        "create mode must not set a target item reference".into(),
                    ));
                }
                match spec.project.as_deref() {
                    Some(project) => {
                        let (v, p) = self.resolve_project(project)?;
                        (Some(v), Some(p), None)
                    }
                    None => (None, None, None),
                }
            }
            SecretRequestMode::Update => {
                let reference = spec.reference.as_deref().ok_or_else(|| {
                    ClientError::Invalid("update mode requires a target item reference".into())
                })?;
                let (item_id, _field) = self.locate(reference, scope)?;
                let entry = self
                    .items
                    .get(&item_id)
                    .ok_or_else(|| ClientError::NotFound(reference.to_owned()))?;
                (Some(entry.vault), Some(entry.project), Some(item_id))
            }
        };
        let proposal = SecretRequestProposal {
            v: SECRET_REQUEST_FORMAT_VERSION,
            mode: spec.mode,
            kind: spec.kind,
            title: spec.title.clone(),
            vault_id,
            project_id,
            target_item_id,
            field: spec.field.clone(),
            placeholder: spec.placeholder.clone(),
            setup_url: spec.setup_url.clone(),
            base_url: spec.base_url.clone(),
            urls: spec.urls.clone(),
            notes: spec.notes.clone(),
            proxy_proposal: spec.proxy_proposal.clone(),
        };
        let (pending, digest) = self
            .agent
            .create_secret_request(&spec.reason, &proposal)
            .await?;
        if spec.wait.is_zero() {
            return Ok(SecretRequestOutcome::Pending {
                request_id: pending.request_id,
                expires_at: pending.expires_at,
            });
        }
        let info = self
            .agent
            .wait_secret_request(pending.request_id, spec.wait)
            .await?;
        self.finish_secret_request(&info, Some(&digest)).await
    }

    /// Waits on an existing secret request `id`, verifies the account's
    /// signature, and resolves its `klav://` reference if fulfilled in grant.
    pub async fn wait_secret_request(
        &mut self,
        id: SecretRequestId,
        timeout: Duration,
    ) -> ClientResult<SecretRequestOutcome> {
        let info = self.agent.wait_secret_request(id, timeout).await?;
        self.finish_secret_request(&info, None).await
    }

    async fn finish_secret_request(
        &mut self,
        info: &SecretRequestInfo,
        expected_digest: Option<&[u8; 32]>,
    ) -> ClientResult<SecretRequestOutcome> {
        let decision = self.agent.verify_secret_request(info, expected_digest)?;
        match info.status {
            SecretRequestState::Pending => Ok(SecretRequestOutcome::Pending {
                request_id: info.id,
                expires_at: info.expires_at,
            }),
            SecretRequestState::Expired => Ok(SecretRequestOutcome::Expired {
                request_id: info.id,
            }),
            SecretRequestState::Denied => Ok(SecretRequestOutcome::Denied {
                request_id: info.id,
            }),
            SecretRequestState::Fulfilled => {
                let decision = decision.ok_or_else(|| {
                    ClientError::Security(format!(
                        "secret request {} is fulfilled without a decision",
                        info.id
                    ))
                })?;
                let field = decision.field.unwrap_or_default();
                let mut reference = None;
                if decision.in_grant
                    && let Some(item_id) = decision.item_id
                {
                    let _ = self.refresh().await;
                    if let Some(entry) = self.items.get(&item_id)
                        && let Some(project) = self.grant.keys.get(&entry.project)
                    {
                        reference = Some(format!(
                            "klav://{}/{}/{}/{}",
                            project.labels.vault,
                            project.labels.project,
                            entry.overview.title,
                            field
                        ));
                    }
                }
                Ok(SecretRequestOutcome::Fulfilled {
                    request_id: info.id,
                    in_grant: decision.in_grant,
                    reference,
                    vault_id: decision.vault_id,
                    project_id: decision.project_id,
                    item_id: decision.item_id,
                    field,
                    proxy_profile: decision.proxy_profile,
                })
            }
        }
    }

    fn resolve_project(&self, wanted: &str) -> ClientResult<(VaultId, ProjectId)> {
        let wanted = wanted.trim();
        if let Ok(pid) = wanted.parse::<ProjectId>()
            && let Some(p) = self.grant.keys.get(&pid)
        {
            return Ok((p.ctx.vault, pid));
        }
        let matches: Vec<(VaultId, ProjectId)> = self
            .grant
            .keys
            .iter()
            .filter(|(_, p)| {
                let full = format!("{}/{}", p.labels.vault, p.labels.project);
                full.eq_ignore_ascii_case(wanted) || p.labels.project.eq_ignore_ascii_case(wanted)
            })
            .map(|(pid, p)| (p.ctx.vault, *pid))
            .collect();
        match matches.as_slice() {
            [one] => Ok(*one),
            [] => Err(ClientError::NotFound(format!("granted project {wanted:?}"))),
            _ => Err(ClientError::Ambiguous(format!(
                "project {wanted:?} matches {} granted projects; use Vault/Project",
                matches.len()
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use klav_core::crypto::agent::sign_secret_request_decision;
    use klav_core::crypto::identity::IdentityKeyPair;

    fn signed_info(
        account: &IdentityKeyPair,
        agent: AgentId,
        digest: [u8; 32],
        decision: &SecretRequestDecision,
        status: SecretRequestState,
    ) -> SecretRequestInfo {
        let bytes = serde_json::to_vec(decision).unwrap();
        let decided_at = 1_700_000_000_000i64;
        let sig = sign_secret_request_decision(
            account,
            &SecretRequestDecisionToSign {
                request: decision.request_id,
                agent,
                proposal_digest: &digest,
                decision: &bytes,
                decided_at_ms: u64::try_from(decided_at).unwrap(),
            },
        );
        SecretRequestInfo {
            id: decision.request_id,
            agent_id: agent,
            agent_name: "claude".into(),
            mode: SecretRequestMode::Create,
            target_item_id: None,
            reason: "Need Stripe key".into(),
            proposal_digest: Blob::new(digest.to_vec()),
            proposal_blob: None,
            status,
            created_at: decided_at - 1000,
            expires_at: decided_at + 3_600_000,
            decided_at: Some(decided_at),
            decision: Some(Blob::new(bytes)),
            signature: Some(Blob::new(sig.to_bytes().to_vec())),
        }
    }

    #[test]
    fn verifies_signed_fulfillment_and_rejects_forgeries_t237() {
        let account = IdentityKeyPair::generate();
        let attacker = IdentityKeyPair::generate();
        let agent = AgentId::generate();
        let req_id = SecretRequestId::generate();
        let digest = [0x11u8; 32];
        let decision = SecretRequestDecision {
            v: SECRET_REQUEST_FORMAT_VERSION,
            request_id: req_id,
            agent_id: agent,
            status: SecretRequestStatus::Fulfilled,
            in_grant: true,
            vault_id: Some(VaultId::generate()),
            project_id: Some(ProjectId::generate()),
            item_id: Some(ItemId::generate()),
            field: Some("api_key".into()),
            proxy_profile: Some("stripe".into()),
        };
        let info = signed_info(
            &account,
            agent,
            digest,
            &decision,
            SecretRequestState::Fulfilled,
        );
        let verified = verify_secret_request_info(account.public(), agent, &info, Some(&digest))
            .unwrap()
            .unwrap();
        assert_eq!(verified, decision);

        // Wrong expected digest (server swapped proposal) -> Security error.
        let other_digest = [0x22u8; 32];
        assert!(matches!(
            verify_secret_request_info(account.public(), agent, &info, Some(&other_digest)),
            Err(ClientError::Security(_))
        ));

        // Forged by another key -> Security error.
        let forged = signed_info(
            &attacker,
            agent,
            digest,
            &decision,
            SecretRequestState::Fulfilled,
        );
        assert!(matches!(
            verify_secret_request_info(account.public(), agent, &forged, Some(&digest)),
            Err(ClientError::Security(_))
        ));

        // Fulfilled without signature -> Security error.
        let mut unsigned = info.clone();
        unsigned.signature = None;
        assert!(matches!(
            verify_secret_request_info(account.public(), agent, &unsigned, Some(&digest)),
            Err(ClientError::Security(_))
        ));

        // Denied decision verifies cleanly too.
        let denied = SecretRequestDecision {
            v: SECRET_REQUEST_FORMAT_VERSION,
            request_id: req_id,
            agent_id: agent,
            status: SecretRequestStatus::Denied,
            in_grant: false,
            vault_id: None,
            project_id: None,
            item_id: None,
            field: None,
            proxy_profile: None,
        };
        let denied_info = signed_info(&account, agent, digest, &denied, SecretRequestState::Denied);
        assert_eq!(
            verify_secret_request_info(account.public(), agent, &denied_info, Some(&digest))
                .unwrap(),
            Some(denied)
        );
    }
}
