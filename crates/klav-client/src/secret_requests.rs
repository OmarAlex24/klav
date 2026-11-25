//! Agent secret requests as the person sees and fulfills them (ADR 0046).
//!
//! Each pending request carries an HPKE-encrypted proposal (`proposal_blob`,
//! kind `0x25`, spec §13.14) sealed to the account's X25519 identity. This
//! module opens it locally, checks its SHA-256 digest against the server's
//! `proposal_digest`, validates `setup_url` (T235), resolves existing item
//! metadata from the person's own vault in `update` mode (never trusting an
//! agent's label), keeps agent-suggested `login` URLs unchecked by default
//! (T234), enforces T236 when saving outside the asking agent's grant
//! (`in_grant: false`, omitting `vault_id`/`project_id`/`item_id`), and signs
//! the decision with `klav/v1/sig/secret-request-decision`.

use std::collections::HashMap;

use klav_core::crypto::agent::{
    self, SecretRequestDecisionToSign, open_secret_request, sign_secret_request_decision,
    verify_secret_request_decision,
};
use klav_core::crypto::identity::PublicIdentity;
use klav_core::crypto::sign::{SIGNATURE_LEN, Signature};
use klav_core::ids::{AccountId, AgentId, ItemId, ProjectId, SecretRequestId, VaultId};
use klav_core::model::item::{FieldKind, ItemKind, validate_field_name};
use klav_core::secret_request::{
    ProxyProposal, SECRET_REQUEST_FORMAT_VERSION, SecretRequestDecision, SecretRequestMode,
    SecretRequestProposal, SecretRequestStatus, validate_setup_url,
};
use klav_proto::Blob;
use klav_proto::secret_request::{
    DecideSecretRequest, SecretRequestInfo, SecretRequestList, SecretRequestState,
};
use reqwest::Method;
use serde::{Deserialize, Serialize};

use crate::api::Body;
use crate::error::{ClientError, ClientResult};
use crate::ops::{FieldInput, ItemPatch, NewItem, SecretText};
use crate::proxy_admin::{PairingCheck, ProxyCredentialSpec};
use crate::session::{ItemSummary, Unlocked, now_ms};

/// Validated `setup_url` surfaced on a [`SecretRequestCard`] (T235).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretRequestSetupUrl {
    /// Canonical `https://…` URL.
    pub url: String,
    /// Lowercase ASCII host to display prominently in the warning banner.
    pub host: String,
    /// `true` when any label starts with `xn--` (IDN homograph cue).
    pub has_punycode: bool,
}

/// A secret request as the person sees it (CLI, `klavd`, Mac, iOS, extension).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretRequestCard {
    /// Request ID.
    pub id: SecretRequestId,
    /// Lifecycle state on the server.
    pub status: SecretRequestState,
    /// Asking agent ID.
    pub agent_id: AgentId,
    /// Asking agent name.
    pub agent: String,
    /// `create` or `update`.
    pub mode: SecretRequestMode,
    /// Target item ID in `update` mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_item_id: Option<ItemId>,
    /// `klav://Vault/Project/Title` resolved from this device's own vault in
    /// `update` mode (never taken from the agent).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_reference: Option<String>,
    /// Existing item title from this device's vault in `update` mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_title: Option<String>,
    /// Existing item kind from this device's vault in `update` mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_kind: Option<ItemKind>,
    /// Plaintext reason supplied by the agent.
    pub reason: String,
    /// Created at (Unix ms).
    pub created_at: i64,
    /// Expires at (Unix ms).
    pub expires_at: i64,
    /// Decided at (Unix ms), if decided.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decided_at: Option<i64>,
    /// Lowercase hex SHA-256 of the canonical proposal JSON (ADR 0030 §5):
    /// passed back when fulfilling or denying so nothing is signed if the
    /// server swaps the proposal.
    pub proposal_digest: String,
    /// Decrypted and validated proposal (present while pending and valid).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proposal: Option<SecretRequestProposal>,
    /// Why a pending proposal could not be opened or validated (refuses
    /// fulfillment while set).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proposal_error: Option<String>,
    /// Validated `setup_url` with host and punycode cue (T235).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setup_url: Option<SecretRequestSetupUrl>,
    /// Projects currently in the asking agent's verified grant, so the UI can
    /// tell the person whether their chosen destination is `in_grant`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub agent_projects: Vec<(VaultId, ProjectId)>,
    /// Verified decision once fulfilled or denied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision: Option<SecretRequestDecision>,
}

impl SecretRequestCard {
    /// Whether the person can still fulfill or deny this request.
    pub fn is_pending(&self) -> bool {
        self.status == SecretRequestState::Pending
    }
}

/// Inputs supplied by the person when fulfilling a pending secret request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FulfillSecretRequest {
    /// [`SecretRequestCard::proposal_digest`] (hex) of the card the person
    /// reviewed.
    pub digest: String,
    /// Secret value entered by the person (hidden input / stdin). Never logged.
    pub secret: SecretText,
    /// Destination vault name or ID (`create` mode; defaults to the proposal's
    /// `vault_id` or the default vault).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault: Option<String>,
    /// Destination project name or ID (`create` mode; defaults to the
    /// proposal's `project_id` or the default project).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
    /// Title override (`create` mode; defaults to `proposal.title`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Field name override (defaults to `proposal.field`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    /// Login URLs explicitly confirmed by the person (`create` mode for
    /// `login` items). `None` saves **no** agent-suggested URLs (T234).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub urls: Option<Vec<String>>,
    /// Notes override (`create` mode).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<SecretText>,
    /// Allow creating an item whose title matches another live item in the
    /// same project.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub allow_duplicate: bool,
    /// Whether the person explicitly opted in to granting `klav-proxy` access
    /// to this item (unchecked by default, ADR 0046 Q3 / T239).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub grant_proxy: bool,
    /// Expected proxy grant version shown in the preview when `grant_proxy` is
    /// `true` (staleness check, same as `ProxyGrant`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_base_version: Option<u64>,
    /// Person confirmed every device is updated when this is the account's
    /// first per-item grant.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub every_device_updated: bool,
    /// Pairing words shown when the proxy has no grant yet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shown_words: Option<String>,
    /// Optional edited proxy credential spec (defaults to
    /// `proxy_spec_from_proposal(&proposal.proxy_proposal, field)`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_credential: Option<ProxyCredentialSpec>,
}

/// Result of fulfilling a secret request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FulfillSecretResult {
    /// Updated card (status `fulfilled`).
    pub card: SecretRequestCard,
    /// Item created or updated in the person's vault.
    pub item: ItemSummary,
    /// Whether the saved item lives in a project granted to the asking agent.
    pub in_grant: bool,
    /// Profile name granted to `klav-proxy`, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_profile: Option<String>,
    /// Any warnings produced by the optional proxy grant step.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proxy_warnings: Vec<String>,
}

/// Converts a validated [`ProxyProposal`] into a [`ProxyCredentialSpec`] for
/// [`Unlocked::prepare_proxy_grant`] / [`Unlocked::preview_proxy_grant`].
pub fn proxy_spec_from_proposal(proposal: &ProxyProposal, field: &str) -> ProxyCredentialSpec {
    ProxyCredentialSpec {
        profile: proposal.profile.clone(),
        upstream: proposal.upstream.clone(),
        header: proposal.header.clone(),
        prefix: proposal.prefix.clone(),
        field: Some(field.to_owned()),
        methods: proposal.methods.clone(),
        path_prefixes: proposal.path_prefixes.clone(),
        ask: false,
        ask_methods: proposal.ask_methods.clone(),
        rate_per_minute: proposal.rate_per_minute,
        mcp: None,
    }
}

/// Finds a secret request by full ID or unique prefix.
pub fn find_secret_request<'a>(
    cards: &'a [SecretRequestCard],
    wanted: &str,
) -> ClientResult<&'a SecretRequestCard> {
    let wanted = wanted.trim();
    if wanted.is_empty() {
        return Err(ClientError::Invalid("secret request ID is empty".into()));
    }
    if let Ok(id) = wanted.parse::<SecretRequestId>() {
        return cards
            .iter()
            .find(|c| c.id == id)
            .ok_or_else(|| ClientError::NotFound(format!("secret request {id}")));
    }
    let matches: Vec<&SecretRequestCard> = cards
        .iter()
        .filter(|c| c.id.to_string().starts_with(wanted))
        .collect();
    match matches.as_slice() {
        [one] => Ok(*one),
        [] => Err(ClientError::NotFound(format!("secret request {wanted:?}"))),
        _ => Err(ClientError::Ambiguous(format!(
            "secret request prefix {wanted:?} matches {} requests; give more characters",
            matches.len()
        ))),
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(&mut out, "{b:02x}");
    }
    out
}

/// Opens and validates a pending request's HPKE `proposal_blob`, checking its
/// SHA-256 digest against `info.proposal_digest` and mode/target consistency.
fn open_and_check_proposal(
    identity: &klav_core::crypto::identity::IdentityKeyPair,
    account_id: AccountId,
    info: &SecretRequestInfo,
) -> Result<(SecretRequestProposal, Option<SecretRequestSetupUrl>), String> {
    let Some(blob) = info.proposal_blob.as_ref() else {
        return Err("missing proposal blob on pending secret request".into());
    };
    let plaintext = open_secret_request(
        identity,
        account_id,
        info.agent_id,
        info.id,
        blob.as_bytes(),
    )
    .map_err(|e| format!("cannot decrypt proposal: {e}"))?;
    let actual_digest = agent::body_digest(&plaintext);
    if info.proposal_digest.as_bytes() != actual_digest.as_slice() {
        return Err("proposal digest does not match decrypted proposal".into());
    }
    let proposal: SecretRequestProposal =
        serde_json::from_slice(&plaintext).map_err(|e| format!("proposal JSON is invalid: {e}"))?;
    proposal
        .validate()
        .map_err(|e| format!("proposal failed validation: {e}"))?;
    if proposal.mode != info.mode {
        return Err("proposal mode does not match request mode".into());
    }
    if proposal.target_item_id != info.target_item_id {
        return Err("proposal target_item_id does not match request".into());
    }
    let setup_url = proposal
        .setup_url
        .as_deref()
        .map(validate_setup_url)
        .transpose()
        .map_err(|e| format!("setup_url is invalid: {e}"))?
        .map(|u| SecretRequestSetupUrl {
            url: u.url,
            host: u.host,
            has_punycode: u.has_punycode,
        });
    Ok((proposal, setup_url))
}

/// Verifies a decided request's signed [`SecretRequestDecision`] against
/// `account`.
pub fn verify_decision(
    account: &PublicIdentity,
    info: &SecretRequestInfo,
) -> ClientResult<Option<SecretRequestDecision>> {
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
    let digest: [u8; 32] = info
        .proposal_digest
        .as_bytes()
        .try_into()
        .map_err(|_| ClientError::Security("proposal digest has a wrong length".into()))?;
    let sig_bytes: [u8; SIGNATURE_LEN] = sig
        .as_bytes()
        .try_into()
        .map_err(|_| ClientError::Security("secret request signature has a wrong length".into()))?;
    let decided_at_ms = u64::try_from(decided_at).unwrap_or(0);
    verify_secret_request_decision(
        account,
        &SecretRequestDecisionToSign {
            request: info.id,
            agent: info.agent_id,
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
    if decision.request_id != info.id || decision.agent_id != info.agent_id || !status_matches {
        return Err(ClientError::Security(format!(
            "the decision of secret request {} does not match the request",
            info.id
        )));
    }
    Ok(Some(decision))
}

/// Builds a [`SecretRequestDecision`] enforcing T236: when `in_grant` is
/// `false`, `vault_id`, `project_id` and `item_id` are omitted.
pub(crate) fn build_fulfillment_decision(
    request_id: SecretRequestId,
    agent_id: AgentId,
    item: &ItemSummary,
    in_grant: bool,
    field: String,
    proxy_profile: Option<String>,
) -> ClientResult<SecretRequestDecision> {
    let decision = SecretRequestDecision {
        v: SECRET_REQUEST_FORMAT_VERSION,
        request_id,
        agent_id,
        status: SecretRequestStatus::Fulfilled,
        in_grant,
        vault_id: in_grant.then_some(item.vault_id),
        project_id: in_grant.then_some(item.project_id),
        item_id: in_grant.then_some(item.id),
        field: Some(field),
        proxy_profile,
    };
    decision
        .validate()
        .map_err(|e| ClientError::Invalid(e.to_string()))?;
    Ok(decision)
}

impl Unlocked {
    async fn secret_request_info(
        &mut self,
        id: SecretRequestId,
    ) -> ClientResult<SecretRequestInfo> {
        let res = self
            .authed(
                Method::GET,
                &format!("/v1/secret-requests/{id}"),
                &Body::Empty,
            )
            .await?;
        crate::api::json(res).await
    }

    async fn agent_projects_map(&mut self) -> HashMap<AgentId, Vec<(VaultId, ProjectId)>> {
        let mut map = HashMap::new();
        if let Ok(agents) = self.agents().await {
            for a in agents {
                if let Some(grant) = a.grant {
                    let projects = grant
                        .projects
                        .into_iter()
                        .map(|p| (p.vault_id, p.project_id))
                        .collect();
                    map.insert(a.id, projects);
                }
            }
        }
        map
    }

    fn build_secret_request_card(
        &self,
        info: &SecretRequestInfo,
        agent_projects: Vec<(VaultId, ProjectId)>,
    ) -> ClientResult<SecretRequestCard> {
        let (proposal, setup_url, proposal_error) = if info.status == SecretRequestState::Pending {
            match open_and_check_proposal(&self.identity, self.account.account_id, info) {
                Ok((p, s)) => (Some(p), s, None),
                Err(err) => (None, None, Some(err)),
            }
        } else {
            (None, None, None)
        };
        let decision = verify_decision(self.identity.public(), info)?;
        let (target_reference, target_title, target_kind) = match info.target_item_id {
            Some(item_id) => match self
                .find_item(&item_id.to_string())
                .and_then(|loc| self.item_summary(loc))
            {
                Ok(s) => (
                    Some(format!("klav://{}/{}/{}", s.vault, s.project, s.title)),
                    Some(s.title),
                    Some(s.kind),
                ),
                Err(_) => (None, None, None),
            },
            None => (None, None, None),
        };
        Ok(SecretRequestCard {
            id: info.id,
            status: info.status,
            agent_id: info.agent_id,
            agent: info.agent_name.clone(),
            mode: info.mode,
            target_item_id: info.target_item_id,
            target_reference,
            target_title,
            target_kind,
            reason: info.reason.clone(),
            created_at: info.created_at,
            expires_at: info.expires_at,
            decided_at: info.decided_at,
            proposal_digest: hex_encode(info.proposal_digest.as_bytes()),
            proposal,
            proposal_error,
            setup_url,
            agent_projects,
            decision,
        })
    }

    /// Lists secret requests for this account (newest first). When `all` is
    /// `false`, returns only pending requests.
    pub async fn secret_requests(&mut self, all: bool) -> ClientResult<Vec<SecretRequestCard>> {
        let res = self
            .authed(Method::GET, "/v1/secret-requests", &Body::Empty)
            .await?;
        let list: SecretRequestList = crate::api::json(res).await?;
        let projects_by_agent = self.agent_projects_map().await;
        let mut cards = Vec::new();
        for info in list.secret_requests {
            if !all && info.status != SecretRequestState::Pending {
                continue;
            }
            let projects = projects_by_agent
                .get(&info.agent_id)
                .cloned()
                .unwrap_or_default();
            cards.push(self.build_secret_request_card(&info, projects)?);
        }
        Ok(cards)
    }

    /// Loads one secret request by full ID or unique prefix.
    pub async fn secret_request(&mut self, wanted: &str) -> ClientResult<SecretRequestCard> {
        if let Ok(id) = wanted.trim().parse::<SecretRequestId>() {
            let info = self.secret_request_info(id).await?;
            let projects = self
                .agent_projects_map()
                .await
                .remove(&info.agent_id)
                .unwrap_or_default();
            return self.build_secret_request_card(&info, projects);
        }
        let cards = self.secret_requests(true).await?;
        Ok(find_secret_request(&cards, wanted)?.clone())
    }

    /// Fulfills pending secret request `id`: saves the secret into the person's
    /// vault (creating a new item or updating the requested field), optionally
    /// grants a `klav-proxy` profile if `input.grant_proxy` is set, and posts
    /// the account-signed [`SecretRequestDecision`].
    pub async fn fulfill_secret_request(
        &mut self,
        id: SecretRequestId,
        input: &FulfillSecretRequest,
    ) -> ClientResult<FulfillSecretResult> {
        if input.secret.expose().is_empty() {
            return Err(ClientError::Invalid("secret value cannot be empty".into()));
        }
        let info = self.secret_request_info(id).await?;
        if info.id != id {
            return Err(ClientError::Security(format!(
                "the server answered with another secret request than {id}"
            )));
        }
        if info.status != SecretRequestState::Pending {
            return Err(ClientError::Invalid(format!(
                "secret request {id} is {}, not pending",
                info.status.as_str()
            )));
        }
        let actual_hex = hex_encode(info.proposal_digest.as_bytes());
        if actual_hex != input.digest.trim().to_ascii_lowercase() {
            return Err(ClientError::Security(format!(
                "secret request {id} changed since it was shown; reload and review it again"
            )));
        }
        let projects = self
            .agent_projects_map()
            .await
            .remove(&info.agent_id)
            .unwrap_or_default();
        let card = self.build_secret_request_card(&info, projects.clone())?;
        if let Some(err) = card.proposal_error {
            return Err(ClientError::Security(format!(
                "secret request {id} cannot be fulfilled: {err}"
            )));
        }
        let proposal = card.proposal.ok_or_else(|| {
            ClientError::Security(format!("secret request {id} has no decrypted proposal"))
        })?;

        let field = input
            .field
            .clone()
            .unwrap_or_else(|| proposal.field.clone());
        validate_field_name(&field)
            .map_err(|_| ClientError::Invalid(format!("invalid field name {field:?}")))?;

        let item = match proposal.mode {
            SecretRequestMode::Create => {
                let kind = proposal.kind.ok_or_else(|| {
                    ClientError::Invalid("create proposal is missing item kind".into())
                })?;
                let title = input
                    .title
                    .clone()
                    .or_else(|| proposal.title.clone())
                    .ok_or_else(|| {
                        ClientError::Invalid("create proposal is missing item title".into())
                    })?;
                let vault = input
                    .vault
                    .clone()
                    .or_else(|| proposal.vault_id.map(|v| v.to_string()));
                let project = input
                    .project
                    .clone()
                    .or_else(|| proposal.project_id.map(|p| p.to_string()));
                let mut fields = vec![FieldInput {
                    name: field.clone(),
                    value: input.secret.clone(),
                    kind: (kind == ItemKind::Totp && field == "totp").then_some(FieldKind::Totp),
                    secret: true,
                }];
                if kind == ItemKind::ApiKey
                    && let Some(base_url) = &proposal.base_url
                {
                    fields.push(FieldInput {
                        name: "base_url".into(),
                        value: SecretText::new(base_url.clone()),
                        kind: Some(FieldKind::Url),
                        secret: false,
                    });
                }
                // T234: never auto-save agent-suggested `proposal.urls` on
                // login items; only save URLs explicitly confirmed by the person.
                let urls = input.urls.clone().unwrap_or_default();
                let notes = input
                    .notes
                    .clone()
                    .or_else(|| proposal.notes.clone().map(SecretText::new));
                let new_item = NewItem {
                    kind,
                    title,
                    vault,
                    project,
                    fields,
                    urls,
                    tags: Vec::new(),
                    notes,
                    allow_duplicate: input.allow_duplicate,
                };
                self.create(&new_item).await?
            }
            SecretRequestMode::Update => {
                let target_id = proposal.target_item_id.ok_or_else(|| {
                    ClientError::Invalid("update proposal is missing target_item_id".into())
                })?;
                let patch = ItemPatch {
                    set: vec![FieldInput {
                        name: field.clone(),
                        value: input.secret.clone(),
                        kind: None,
                        secret: true,
                    }],
                    ..ItemPatch::default()
                };
                self.edit(&target_id.to_string(), &patch).await?
            }
        };

        let mut proxy_profile = None;
        let mut proxy_warnings = Vec::new();
        if input.grant_proxy {
            let spec = match (&input.proxy_credential, &proposal.proxy_proposal) {
                (Some(s), _) => s.clone(),
                (None, Some(pp)) => proxy_spec_from_proposal(pp, &field),
                (None, None) => {
                    return Err(ClientError::Invalid(
                        "grant_proxy requested, but neither the proposal nor the caller supplied a proxy profile".into(),
                    ));
                }
            };
            let prepared = self
                .prepare_proxy_grant(&item.id.to_string(), &spec, PairingCheck::InPrompt)
                .await?;
            let view = prepared.view();
            if let Some(expected_version) = input.proxy_base_version
                && view.base_version != expected_version
            {
                return Err(ClientError::Invalid(format!(
                    "the grant of the proxy {:?} changed since it was shown (version {}); try again",
                    view.agent, view.base_version
                )));
            }
            if view.first && input.shown_words.as_deref() != Some(view.pairing_code.as_str()) {
                return Err(ClientError::Security(format!(
                    "the key of the proxy {:?} is not the one whose words were shown; nothing granted",
                    view.agent
                )));
            }
            prepared.require_updated_devices(input.every_device_updated)?;
            proxy_warnings.extend(view.warnings.iter().cloned());
            self.commit_proxy_change(prepared).await?;
            proxy_profile = Some(spec.profile);
        }

        let in_grant = projects
            .iter()
            .any(|(v, p)| *v == item.vault_id && *p == item.project_id);
        let decision = build_fulfillment_decision(
            id,
            info.agent_id,
            &item,
            in_grant,
            field,
            proxy_profile.clone(),
        )?;
        let decided_card = self
            .send_secret_request_decision(&info, &decision, projects)
            .await?;
        Ok(FulfillSecretResult {
            card: decided_card,
            item,
            in_grant,
            proxy_profile,
            proxy_warnings,
        })
    }

    /// Denies pending secret request `id` with an account-signed decision.
    pub async fn deny_secret_request(
        &mut self,
        id: SecretRequestId,
        digest: &str,
    ) -> ClientResult<SecretRequestCard> {
        let info = self.secret_request_info(id).await?;
        if info.id != id {
            return Err(ClientError::Security(format!(
                "the server answered with another secret request than {id}"
            )));
        }
        if info.status != SecretRequestState::Pending {
            return Err(ClientError::Invalid(format!(
                "secret request {id} is {}, not pending",
                info.status.as_str()
            )));
        }
        let actual_hex = hex_encode(info.proposal_digest.as_bytes());
        if actual_hex != digest.trim().to_ascii_lowercase() {
            return Err(ClientError::Security(format!(
                "secret request {id} changed since it was shown; reload and review it again"
            )));
        }
        let projects = self
            .agent_projects_map()
            .await
            .remove(&info.agent_id)
            .unwrap_or_default();
        let decision = SecretRequestDecision {
            v: SECRET_REQUEST_FORMAT_VERSION,
            request_id: id,
            agent_id: info.agent_id,
            status: SecretRequestStatus::Denied,
            in_grant: false,
            vault_id: None,
            project_id: None,
            item_id: None,
            field: None,
            proxy_profile: None,
        };
        decision
            .validate()
            .map_err(|e| ClientError::Invalid(e.to_string()))?;
        self.send_secret_request_decision(&info, &decision, projects)
            .await
    }

    async fn send_secret_request_decision(
        &mut self,
        info: &SecretRequestInfo,
        decision: &SecretRequestDecision,
        projects: Vec<(VaultId, ProjectId)>,
    ) -> ClientResult<SecretRequestCard> {
        let digest: [u8; 32] = info
            .proposal_digest
            .as_bytes()
            .try_into()
            .map_err(|_| ClientError::Security("proposal digest has a wrong length".into()))?;
        let bytes = serde_json::to_vec(decision)
            .map_err(|e| ClientError::Invalid(format!("decision: {e}")))?;
        let decided_at = now_ms();
        let decided_at_ms = u64::try_from(decided_at).unwrap_or(0);
        let signature = sign_secret_request_decision(
            &self.identity,
            &SecretRequestDecisionToSign {
                request: info.id,
                agent: info.agent_id,
                proposal_digest: &digest,
                decision: &bytes,
                decided_at_ms,
            },
        );
        let decided: SecretRequestInfo = self
            .send_json(
                Method::POST,
                &format!("/v1/secret-requests/{}/decide", info.id),
                &DecideSecretRequest {
                    decision: Blob::new(bytes),
                    signature: Blob::new(signature.to_bytes().to_vec()),
                    decided_at,
                },
            )
            .await?;
        self.build_secret_request_card(&decided, projects)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use klav_core::crypto::agent::seal_secret_request;
    use klav_core::crypto::identity::IdentityKeyPair;

    fn sample_proposal() -> SecretRequestProposal {
        SecretRequestProposal {
            v: SECRET_REQUEST_FORMAT_VERSION,
            mode: SecretRequestMode::Create,
            kind: Some(ItemKind::ApiKey),
            title: Some("Stripe API key".into()),
            vault_id: None,
            project_id: None,
            target_item_id: None,
            field: "api_key".into(),
            placeholder: Some("sk_live_…".into()),
            setup_url: Some("https://dashboard.stripe.com/apikeys".into()),
            base_url: Some("https://api.stripe.com".into()),
            urls: vec![],
            notes: Some("Needed for billing tests".into()),
            proxy_proposal: Some(ProxyProposal {
                preset: None,
                profile: "stripe".into(),
                upstream: "https://api.stripe.com".into(),
                header: "authorization".into(),
                prefix: "Bearer ".into(),
                methods: vec!["GET".into(), "POST".into()],
                ask_methods: vec!["DELETE".into()],
                path_prefixes: vec!["/v1".into()],
                rate_per_minute: Some(60),
            }),
        }
    }

    #[test]
    fn open_and_check_proposal_verifies_digest_and_setup_url() {
        let account_id = AccountId::generate();
        let identity = IdentityKeyPair::generate();
        let agent_id = AgentId::generate();
        let req_id = SecretRequestId::generate();
        let proposal = sample_proposal();
        let canonical = serde_json::to_vec(&proposal).unwrap();
        let digest = agent::body_digest(&canonical);
        let blob = seal_secret_request(identity.public(), account_id, agent_id, req_id, &canonical)
            .unwrap();
        let mut info = SecretRequestInfo {
            id: req_id,
            agent_id,
            agent_name: "claude".into(),
            mode: SecretRequestMode::Create,
            target_item_id: None,
            reason: "Need Stripe key".into(),
            proposal_digest: Blob::new(digest.to_vec()),
            proposal_blob: Some(Blob::new(blob)),
            status: SecretRequestState::Pending,
            created_at: 1_700_000_000_000,
            expires_at: 1_700_003_600_000,
            decided_at: None,
            decision: None,
            signature: None,
        };
        let (opened, setup) = open_and_check_proposal(&identity, account_id, &info).unwrap();
        assert_eq!(opened, proposal);
        let setup = setup.unwrap();
        assert_eq!(setup.host, "dashboard.stripe.com");
        assert!(!setup.has_punycode);

        // Tampered digest is rejected.
        let mut bad_digest = digest;
        bad_digest[0] ^= 0xff;
        info.proposal_digest = Blob::new(bad_digest.to_vec());
        let err = open_and_check_proposal(&identity, account_id, &info).unwrap_err();
        assert!(err.contains("digest"), "{err}");
    }

    #[test]
    fn build_fulfillment_decision_enforces_t236_and_verifies() {
        let identity = IdentityKeyPair::generate();
        let req_id = SecretRequestId::generate();
        let agent_id = AgentId::generate();
        let item = ItemSummary {
            id: ItemId::generate(),
            reference: "klav://Personal/Private/Stripe".into(),
            vault_id: VaultId::generate(),
            vault: "Personal".into(),
            project_id: ProjectId::generate(),
            project: "Private".into(),
            kind: ItemKind::ApiKey,
            title: "Stripe".into(),
            username: None,
            urls: vec![],
            confirmed_urls: vec![],
            pending_urls: vec![],
            tags: vec![],
            version: 1,
            updated_at: 0,
            trashed: false,
            passkey: None,
            author_agent_id: None,
        };

        // Outside grant: IDs must be omitted (T236).
        let outside = build_fulfillment_decision(
            req_id,
            agent_id,
            &item,
            false,
            "api_key".into(),
            Some("stripe".into()),
        )
        .unwrap();
        assert!(!outside.in_grant);
        assert!(outside.vault_id.is_none());
        assert!(outside.project_id.is_none());
        assert!(outside.item_id.is_none());
        assert_eq!(outside.proxy_profile.as_deref(), Some("stripe"));

        // In grant: IDs included and signature round-trips.
        let inside =
            build_fulfillment_decision(req_id, agent_id, &item, true, "api_key".into(), None)
                .unwrap();
        let digest = [0x42u8; 32];
        let bytes = serde_json::to_vec(&inside).unwrap();
        let decided_at = 1_700_000_000_000i64;
        let sig = sign_secret_request_decision(
            &identity,
            &SecretRequestDecisionToSign {
                request: req_id,
                agent: agent_id,
                proposal_digest: &digest,
                decision: &bytes,
                decided_at_ms: u64::try_from(decided_at).unwrap(),
            },
        );
        let info = SecretRequestInfo {
            id: req_id,
            agent_id,
            agent_name: "claude".into(),
            mode: SecretRequestMode::Create,
            target_item_id: None,
            reason: "Need Stripe key".into(),
            proposal_digest: Blob::new(digest.to_vec()),
            proposal_blob: None,
            status: SecretRequestState::Fulfilled,
            created_at: decided_at - 1000,
            expires_at: decided_at + 3_600_000,
            decided_at: Some(decided_at),
            decision: Some(Blob::new(bytes)),
            signature: Some(Blob::new(sig.to_bytes().to_vec())),
        };
        let verified = verify_decision(identity.public(), &info).unwrap().unwrap();
        assert_eq!(verified, inside);

        // Proxy spec conversion preserves every field.
        let spec = proxy_spec_from_proposal(
            sample_proposal().proxy_proposal.as_ref().unwrap(),
            "api_key",
        );
        assert_eq!(spec.profile, "stripe");
        assert_eq!(spec.field.as_deref(), Some("api_key"));
        assert!(!spec.ask);
    }
}
