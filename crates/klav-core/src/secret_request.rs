//! Agent secret requests (ADR 0046): an agent proposes a new vault item or a
//! secret-field update on an existing one (with metadata only — never a secret
//! value), the person enters the secret into a hidden input on their device,
//! and the signed decision returns only the resulting reference or proxy
//! profile.
//!
//! This module holds the wire-independent formats and pure validation rules
//! shared by `klav-server`, `klav-client`, `klav-sdk`, `klav-cli`, `klavd`
//! and `klav-ffi`:
//!
//! * [`SecretRequestProposal`]: the JSON document sealed with HPKE (kind
//!   `0x25`, spec §13.14) to the account's public identity. Rejects unknown
//!   fields so no agent can attach a secret value.
//! * [`ProxyProposal`]: an optional `klav-proxy` profile suggested alongside
//!   the item (unchecked by default on the person's card; presence required).
//! * [`SecretRequestDecision`]: the person's signed decision
//!   (`klav/v1/sig/secret-request-decision`). Enforces T236: when the person
//!   saves outside the agent's grant (`in_grant: false`), `vault_id`,
//!   `project_id` and `item_id` are omitted.
//! * [`validate_setup_url`]: strict anti-phishing validation for agent-
//!   suggested provider links (T235), including punycode/IDN detection.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::{Host, Url};

use crate::ids::{AgentId, ItemId, ProjectId, SecretRequestId, VaultId};
use crate::model::item::{ItemKind, validate_field_name};
use crate::policy::{HttpMethod, PathPrefix};

/// Format version of [`SecretRequestProposal`] and [`SecretRequestDecision`].
pub const SECRET_REQUEST_FORMAT_VERSION: u32 = 1;
/// Longest reason (characters; plain text, stored in clear like ADR 0021).
pub const MAX_SECRET_REQUEST_REASON: usize = 500;
/// Longest item title in a proposal (characters).
pub const MAX_SECRET_REQUEST_TITLE: usize = 256;
/// Longest placeholder hint (characters).
pub const MAX_SECRET_REQUEST_PLACEHOLDER: usize = 64;
/// Longest notes text in a proposal (characters).
pub const MAX_SECRET_REQUEST_NOTES: usize = 2000;
/// Most login URLs an agent may suggest in a `create` proposal.
pub const MAX_SECRET_REQUEST_URLS: usize = 10;
/// Longest URL accepted in a proposal (bytes).
pub const MAX_SECRET_REQUEST_URL_LEN: usize = 2048;
/// Most HTTP methods across `methods` and `ask_methods` in one proxy proposal
/// (matches `MAX_GRANT_METHODS` so the confirmation card shows them all).
pub const MAX_PROXY_METHODS: usize = 4;
/// Most path prefixes in one proxy proposal.
pub const MAX_PROXY_PATH_PREFIXES: usize = 16;
/// Longest HTTP header name or prefix text in a proxy proposal (bytes).
pub const MAX_PROXY_HEADER_LEN: usize = 64;
/// Highest per-minute rate a proxy proposal may suggest.
pub const MAX_PROXY_RATE_PER_MINUTE: u32 = 600;
/// Most pending secret requests one agent may hold at once (ADR 0046 §1).
pub const MAX_PENDING_SECRET_REQUESTS: usize = 5;

/// Why a secret request, its setup URL, or its decision is not valid.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SecretRequestError {
    /// Unknown format version.
    #[error("unsupported secret request format version {0}")]
    Version(u32),
    /// A single-line text field is empty, too long, or contains hidden/control
    /// characters.
    #[error(
        "`{field}` must have 1 to {max} characters, written as plain text (no control or invisible formatting characters)"
    )]
    Text {
        /// Field name.
        field: &'static str,
        /// Maximum allowed characters.
        max: usize,
    },
    /// Notes text is too long or contains forbidden control/formatting
    /// characters.
    #[error(
        "`notes` must be at most {MAX_SECRET_REQUEST_NOTES} characters without invisible formatting or control characters"
    )]
    Notes,
    /// Item kind is not allowed in a secret request (ADR 0046 Q4).
    #[error("item kind `{0:?}` is not allowed in a secret request")]
    Kind(ItemKind),
    /// Field name does not follow Klav's item field rule.
    #[error("invalid field name {0:?}")]
    FieldName(String),
    /// Proposal fields do not match `mode` (`create` vs `update`).
    #[error("invalid secret request proposal: {0}")]
    Proposal(&'static str),
    /// `setup_url`, `base_url` or a login URL failed validation (T235).
    #[error("invalid {field}: {reason}")]
    Url {
        /// Which URL field failed.
        field: &'static str,
        /// Why it was rejected.
        reason: &'static str,
    },
    /// Too many URLs in `urls`.
    #[error("at most {MAX_SECRET_REQUEST_URLS} URLs may be suggested")]
    TooManyUrls,
    /// `proxy_proposal` failed validation (T239).
    #[error("invalid proxy proposal: {0}")]
    ProxyProposal(&'static str),
    /// Decision fields violate the contract (e.g. T236 cross-project leak).
    #[error("invalid secret request decision: {0}")]
    Decision(&'static str),
}

/// Whether the request asks for a new item or an update to one secret field of
/// an existing item (ADR 0046 Q5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretRequestMode {
    /// Create a new item in the vault.
    Create,
    /// Replace or set one secret field on an existing item.
    Update,
}

impl SecretRequestMode {
    /// Wire and storage representation.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Update => "update",
        }
    }
}

/// Outcome of a secret request decided by the person.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretRequestStatus {
    /// The person saved the secret (and optionally granted the proxy profile).
    Fulfilled,
    /// The person declined the request.
    Denied,
}

impl SecretRequestStatus {
    /// Wire and storage representation.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fulfilled => "fulfilled",
            Self::Denied => "denied",
        }
    }
}

/// A validated `setup_url` returned by [`validate_setup_url`], with its
/// normalized form and whether its host contains punycode/IDN labels (T235).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetupUrl {
    /// Canonical serialized `https://…` URL.
    pub url: String,
    /// Normalized ASCII host (lowercase).
    pub host: String,
    /// `true` if any label of `host` starts with `xn--` (IDN homograph cue).
    pub has_punycode: bool,
}

/// Validates a plain-text single-line field (non-empty, `<= max` chars, no
/// control or invisible formatting characters).
fn check_line(field: &'static str, text: &str, max: usize) -> Result<(), SecretRequestError> {
    let ok = !text.trim().is_empty()
        && text.chars().count() <= max
        && !text.chars().any(crate::text::is_hidden);
    if ok {
        Ok(())
    } else {
        Err(SecretRequestError::Text { field, max })
    }
}

/// Validates `reason`: mandatory, 1..=500 chars, plain text without hidden or
/// control characters.
pub fn validate_reason(reason: &str) -> Result<(), SecretRequestError> {
    check_line("reason", reason, MAX_SECRET_REQUEST_REASON)
}

/// Validates a profile identifier (`[a-z0-9][a-z0-9_-]{0,63}`).
pub fn validate_profile_name(name: &str) -> Result<(), SecretRequestError> {
    let bytes = name.as_bytes();
    let ok = !bytes.is_empty()
        && bytes.len() <= 64
        && (bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'_' || *b == b'-');
    if ok {
        Ok(())
    } else {
        Err(SecretRequestError::ProxyProposal(
            "profile name must match [a-z0-9][a-z0-9_-]{0,63}",
        ))
    }
}

/// Whether `kind` may be created through a secret request (ADR 0046 Q4):
/// `api_key`, `login`, `note`, `ssh_key`, `totp`.
pub const fn is_allowed_kind(kind: ItemKind) -> bool {
    matches!(
        kind,
        ItemKind::ApiKey | ItemKind::Login | ItemKind::Note | ItemKind::SshKey | ItemKind::Totp
    )
}

/// Validates an agent-suggested `https://` public URL (used for `setup_url`,
/// `base_url` and `proxy_proposal.upstream`).
///
/// Rejects:
/// * non-`https` schemes (`http`, `javascript`, `data`, `file`, …);
/// * embedded credentials (`user:pass@host`);
/// * IPv4 or IPv6 literals (including loopback, private and link-local
///   metadata addresses);
/// * `localhost`, `*.localhost`, `*.local`, `*.internal`, `*.home.arpa`, and
///   single-label hosts without a dot;
/// * control, bidi or invisible formatting characters (`crate::text::is_hidden`).
pub fn validate_setup_url(raw: &str) -> Result<SetupUrl, SecretRequestError> {
    validate_public_https("setup_url", raw, true)
}

fn validate_public_https(
    field: &'static str,
    raw: &str,
    allow_query_and_fragment: bool,
) -> Result<SetupUrl, SecretRequestError> {
    if raw.is_empty() || raw.len() > MAX_SECRET_REQUEST_URL_LEN {
        return Err(SecretRequestError::Url {
            field,
            reason: "must be 1 to 2048 bytes",
        });
    }
    if raw.chars().any(crate::text::is_hidden) {
        return Err(SecretRequestError::Url {
            field,
            reason: "contains control or invisible formatting characters",
        });
    }
    let parsed = Url::parse(raw).map_err(|_| SecretRequestError::Url {
        field,
        reason: "is not a valid URL",
    })?;
    if parsed.scheme() != "https" {
        return Err(SecretRequestError::Url {
            field,
            reason: "must use https://",
        });
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(SecretRequestError::Url {
            field,
            reason: "must not contain user credentials",
        });
    }
    if !allow_query_and_fragment && (parsed.query().is_some() || parsed.fragment().is_some()) {
        return Err(SecretRequestError::Url {
            field,
            reason: "must not carry a query string or fragment",
        });
    }
    let host = match parsed.host() {
        Some(Host::Domain(domain)) => domain.trim_end_matches('.').to_ascii_lowercase(),
        Some(Host::Ipv4(_) | Host::Ipv6(_)) => {
            return Err(SecretRequestError::Url {
                field,
                reason: "IP address literals are not allowed",
            });
        }
        None => {
            return Err(SecretRequestError::Url {
                field,
                reason: "missing host",
            });
        }
    };
    if is_local_or_private_domain(&host) {
        return Err(SecretRequestError::Url {
            field,
            reason: "local or private host names are not allowed",
        });
    }
    let has_punycode = host
        .split('.')
        .any(|label| label.starts_with("xn--") || label.starts_with("XN--"));
    Ok(SetupUrl {
        url: parsed.into(),
        host,
        has_punycode,
    })
}

fn is_local_or_private_domain(host: &str) -> bool {
    if host.is_empty() || !host.contains('.') {
        return true;
    }
    if host.split('.').any(str::is_empty) {
        return true;
    }
    host == "localhost"
        || host.ends_with(".localhost")
        || host.ends_with(".local")
        || host.ends_with(".internal")
        || host.ends_with(".home.arpa")
        || host.ends_with(".localdomain")
}

/// Validates a login URL suggested in `urls` (ADR 0046 Q4). Login URLs stay
/// unchecked/unconfirmed by default on the person's card; we still reject
/// non-http(s) schemes, credentials and hidden characters up front.
fn validate_login_url(raw: &str) -> Result<(), SecretRequestError> {
    if raw.is_empty() || raw.len() > MAX_SECRET_REQUEST_URL_LEN {
        return Err(SecretRequestError::Url {
            field: "urls",
            reason: "must be 1 to 2048 bytes",
        });
    }
    if raw.chars().any(crate::text::is_hidden) {
        return Err(SecretRequestError::Url {
            field: "urls",
            reason: "contains control or invisible formatting characters",
        });
    }
    let parsed = Url::parse(raw).map_err(|_| SecretRequestError::Url {
        field: "urls",
        reason: "is not a valid URL",
    })?;
    if !matches!(parsed.scheme(), "https" | "http") {
        return Err(SecretRequestError::Url {
            field: "urls",
            reason: "must use https:// or http://",
        });
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(SecretRequestError::Url {
            field: "urls",
            reason: "must not contain user credentials",
        });
    }
    if parsed.host().is_none() {
        return Err(SecretRequestError::Url {
            field: "urls",
            reason: "missing host",
        });
    }
    Ok(())
}

/// Validates an HTTP header token (RFC 9110 `tchar`, non-empty, `<= 64` bytes).
fn validate_header_name(name: &str) -> Result<(), SecretRequestError> {
    let bytes = name.as_bytes();
    let ok = !bytes.is_empty()
        && bytes.len() <= MAX_PROXY_HEADER_LEN
        && bytes.iter().all(|&b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        });
    if ok {
        Ok(())
    } else {
        Err(SecretRequestError::ProxyProposal(
            "header must be a valid HTTP header name (1 to 64 token bytes)",
        ))
    }
}

/// Optional `klav-proxy` profile suggested by the agent for a sandbox
/// credential (ADR 0046 §2, Q3).
///
/// The person's card renders this behind an explicit toggle (unchecked by
/// default) with the same preview, warnings and presence requirement as
/// `klav proxy grant`. Never touches sandbox issuers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyProposal {
    /// Optional preset name (e.g. `"northflank"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preset: Option<String>,
    /// Profile name (`[a-z0-9][a-z0-9_-]{0,63}`).
    pub profile: String,
    /// Upstream base URL (`https://…`, no userinfo, IP literal, query or
    /// fragment).
    pub upstream: String,
    /// HTTP header where the proxy puts the secret (e.g. `"authorization"`).
    pub header: String,
    /// Optional prefix before the secret value (e.g. `"Bearer "`).
    #[serde(default)]
    pub prefix: String,
    /// HTTP methods allowed without per-call approval.
    #[serde(default)]
    pub methods: Vec<String>,
    /// HTTP methods that ask the person per call.
    #[serde(default)]
    pub ask_methods: Vec<String>,
    /// Allowed path prefixes (at least one, each starting with `/`).
    pub path_prefixes: Vec<String>,
    /// Optional per-minute rate limit (`1..=600`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_per_minute: Option<u32>,
}

impl ProxyProposal {
    /// Checks every field of the proposed proxy profile.
    pub fn validate(&self) -> Result<(), SecretRequestError> {
        if let Some(preset) = &self.preset {
            validate_profile_name(preset)
                .map_err(|_| SecretRequestError::ProxyProposal("invalid preset name"))?;
        }
        validate_profile_name(&self.profile)?;
        validate_public_https("proxy_proposal.upstream", &self.upstream, false)?;
        validate_header_name(&self.header)?;
        if self.prefix.len() > MAX_PROXY_HEADER_LEN
            || self.prefix.chars().any(crate::text::is_hidden)
        {
            return Err(SecretRequestError::ProxyProposal(
                "prefix must be at most 64 bytes without control or invisible characters",
            ));
        }
        let mut seen = BTreeSet::new();
        for raw in &self.methods {
            let method = HttpMethod::parse(raw).map_err(|_| {
                SecretRequestError::ProxyProposal("methods must be valid HTTP method names")
            })?;
            if !seen.insert(method.as_str().to_owned()) {
                return Err(SecretRequestError::ProxyProposal(
                    "duplicate HTTP method in methods",
                ));
            }
        }
        for raw in &self.ask_methods {
            let method = HttpMethod::parse(raw).map_err(|_| {
                SecretRequestError::ProxyProposal("ask_methods must be valid HTTP method names")
            })?;
            if !seen.insert(method.as_str().to_owned()) {
                return Err(SecretRequestError::ProxyProposal(
                    "duplicate or overlapping HTTP method across methods and ask_methods",
                ));
            }
        }
        if seen.is_empty() || seen.len() > MAX_PROXY_METHODS {
            return Err(SecretRequestError::ProxyProposal(
                "proxy proposal must carry 1 to 4 HTTP methods in total",
            ));
        }
        if self.path_prefixes.is_empty() || self.path_prefixes.len() > MAX_PROXY_PATH_PREFIXES {
            return Err(SecretRequestError::ProxyProposal(
                "proxy proposal must carry 1 to 16 path prefixes",
            ));
        }
        let mut seen_paths = BTreeSet::new();
        for raw in &self.path_prefixes {
            let parsed = PathPrefix::parse(raw).map_err(|_| {
                SecretRequestError::ProxyProposal("path_prefixes must be valid path prefixes")
            })?;
            if !seen_paths.insert(parsed.as_str().to_owned()) {
                return Err(SecretRequestError::ProxyProposal(
                    "duplicate path prefix in path_prefixes",
                ));
            }
        }
        if let Some(rate) = self.rate_per_minute
            && (rate == 0 || rate > MAX_PROXY_RATE_PER_MINUTE)
        {
            return Err(SecretRequestError::ProxyProposal(
                "rate_per_minute must be between 1 and 600",
            ));
        }
        Ok(())
    }
}

/// Proposal JSON sealed inside kind `0x25` (`proposal_blob`, ADR 0046 §1).
///
/// Rejects unknown fields (`deny_unknown_fields`): there is no `value` field,
/// so an agent can never attach a secret to a secret request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretRequestProposal {
    /// Format version (`1`).
    pub v: u32,
    /// `create` or `update`.
    pub mode: SecretRequestMode,
    /// Item kind (`api_key`, `login`, `note`, `ssh_key`, `totp`). Required in
    /// `create` mode; must be omitted in `update` mode (the card uses the
    /// existing item's real kind from the person's vault).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<ItemKind>,
    /// Suggested title. Required in `create` mode; omitted in `update` mode
    /// (the card reads the real title from the person's vault).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Optional suggested vault ID (if known from a grant).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault_id: Option<VaultId>,
    /// Optional suggested project ID (if known from a grant).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_id: Option<ProjectId>,
    /// Target item ID. Required in `update` mode; must be omitted in `create`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_item_id: Option<ItemId>,
    /// Secret field name to populate (e.g. `"api_key"`, `"password"`).
    pub field: String,
    /// Optional short placeholder for the hidden input (e.g. `"vck_…"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placeholder: Option<String>,
    /// Optional provider dashboard / key-creation URL (`https://` only, T235).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setup_url: Option<String>,
    /// Optional API base URL (only for `api_key` in `create` mode).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,
    /// Optional suggested login URLs (only for `login` in `create` mode; kept
    /// unchecked/unconfirmed by default on the person's card, ADR 0046 Q4).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub urls: Vec<String>,
    /// Optional plain-text notes (shown as suggested by the agent).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    /// Optional `klav-proxy` profile proposal for a sandbox credential.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_proposal: Option<ProxyProposal>,
}

impl SecretRequestProposal {
    /// Checks every invariant of the proposal before sealing or displaying.
    pub fn validate(&self) -> Result<(), SecretRequestError> {
        if self.v != SECRET_REQUEST_FORMAT_VERSION {
            return Err(SecretRequestError::Version(self.v));
        }
        validate_field_name(&self.field)
            .map_err(|_| SecretRequestError::FieldName(self.field.clone()))?;
        match self.mode {
            SecretRequestMode::Create => {
                if self.target_item_id.is_some() {
                    return Err(SecretRequestError::Proposal(
                        "`target_item_id` is only allowed in `update` mode",
                    ));
                }
                let kind = self.kind.ok_or(SecretRequestError::Proposal(
                    "`kind` is required in `create` mode",
                ))?;
                if !is_allowed_kind(kind) {
                    return Err(SecretRequestError::Kind(kind));
                }
                let title = self.title.as_deref().ok_or(SecretRequestError::Proposal(
                    "`title` is required in `create` mode",
                ))?;
                check_line("title", title, MAX_SECRET_REQUEST_TITLE)?;
                if self.project_id.is_some() && self.vault_id.is_none() {
                    return Err(SecretRequestError::Proposal(
                        "`project_id` requires `vault_id`",
                    ));
                }
                if !self.urls.is_empty() && kind != ItemKind::Login {
                    return Err(SecretRequestError::Proposal(
                        "`urls` is only allowed for `login` items",
                    ));
                }
                if self.base_url.is_some() && kind != ItemKind::ApiKey {
                    return Err(SecretRequestError::Proposal(
                        "`base_url` is only allowed for `api_key` items",
                    ));
                }
            }
            SecretRequestMode::Update => {
                if self.target_item_id.is_none() {
                    return Err(SecretRequestError::Proposal(
                        "`target_item_id` is required in `update` mode",
                    ));
                }
                if self.kind.is_some() {
                    return Err(SecretRequestError::Proposal(
                        "`kind` must be omitted in `update` mode",
                    ));
                }
                if self.title.is_some() {
                    return Err(SecretRequestError::Proposal(
                        "`title` must be omitted in `update` mode (the card uses the vault's real title)",
                    ));
                }
                if !self.urls.is_empty() || self.base_url.is_some() {
                    return Err(SecretRequestError::Proposal(
                        "`urls` and `base_url` are not allowed in `update` mode",
                    ));
                }
                if self.project_id.is_some() && self.vault_id.is_none() {
                    return Err(SecretRequestError::Proposal(
                        "`project_id` requires `vault_id`",
                    ));
                }
            }
        }
        if let Some(placeholder) = &self.placeholder {
            check_line("placeholder", placeholder, MAX_SECRET_REQUEST_PLACEHOLDER)?;
        }
        if let Some(setup_url) = &self.setup_url {
            validate_setup_url(setup_url)?;
        }
        if let Some(base_url) = &self.base_url {
            validate_public_https("base_url", base_url, false)?;
        }
        if self.urls.len() > MAX_SECRET_REQUEST_URLS {
            return Err(SecretRequestError::TooManyUrls);
        }
        for url in &self.urls {
            validate_login_url(url)?;
        }
        if let Some(notes) = &self.notes {
            let bad_char = notes
                .chars()
                .any(|c| c != '\n' && crate::text::is_hidden(c));
            if notes.chars().count() > MAX_SECRET_REQUEST_NOTES || bad_char {
                return Err(SecretRequestError::Notes);
            }
        }
        if let Some(proxy) = &self.proxy_proposal {
            proxy.validate()?;
        }
        Ok(())
    }
}

/// The person's signed decision on a secret request (ADR 0046 §3).
///
/// Signed verbatim under `klav/v1/sig/secret-request-decision` (spec §13.14).
/// Never contains a secret value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretRequestDecision {
    /// Format version (`1`).
    pub v: u32,
    /// The secret request being decided.
    pub request_id: SecretRequestId,
    /// The agent that made the request.
    pub agent_id: AgentId,
    /// `fulfilled` or `denied`.
    pub status: SecretRequestStatus,
    /// Whether the saved item lives in a project covered by the asking agent's
    /// grant. Always `false` when `denied`.
    pub in_grant: bool,
    /// Vault ID — present **only** when `fulfilled` and `in_grant` (T236).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault_id: Option<VaultId>,
    /// Project ID — present **only** when `fulfilled` and `in_grant` (T236).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_id: Option<ProjectId>,
    /// Item ID — present **only** when `fulfilled` and `in_grant` (T236).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub item_id: Option<ItemId>,
    /// Name of the field saved — present **only** when `fulfilled`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    /// Profile granted to `klav-proxy` — present **only** when `fulfilled` and
    /// the person enabled and confirmed the proxy grant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_profile: Option<String>,
}

impl SecretRequestDecision {
    /// Checks every invariant of the decision before signing or accepting it.
    pub fn validate(&self) -> Result<(), SecretRequestError> {
        if self.v != SECRET_REQUEST_FORMAT_VERSION {
            return Err(SecretRequestError::Version(self.v));
        }
        match self.status {
            SecretRequestStatus::Denied => {
                if self.in_grant
                    || self.vault_id.is_some()
                    || self.project_id.is_some()
                    || self.item_id.is_some()
                    || self.field.is_some()
                    || self.proxy_profile.is_some()
                {
                    return Err(SecretRequestError::Decision(
                        "a denied decision must not carry item, grant or proxy fields",
                    ));
                }
            }
            SecretRequestStatus::Fulfilled => {
                let field = self.field.as_deref().ok_or(SecretRequestError::Decision(
                    "a fulfilled decision must name `field`",
                ))?;
                validate_field_name(field)
                    .map_err(|_| SecretRequestError::FieldName(field.to_owned()))?;
                if self.in_grant {
                    if self.vault_id.is_none()
                        || self.project_id.is_none()
                        || self.item_id.is_none()
                    {
                        return Err(SecretRequestError::Decision(
                            "`in_grant: true` requires `vault_id`, `project_id` and `item_id`",
                        ));
                    }
                } else if self.vault_id.is_some()
                    || self.project_id.is_some()
                    || self.item_id.is_some()
                {
                    return Err(SecretRequestError::Decision(
                        "`in_grant: false` must omit `vault_id`, `project_id` and `item_id` (T236)",
                    ));
                }
                if let Some(profile) = &self.proxy_profile {
                    validate_profile_name(profile).map_err(|_| {
                        SecretRequestError::Decision("invalid `proxy_profile` name")
                    })?;
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::agent::{
        SecretRequestDecisionToSign, body_digest, open_secret_request, seal_secret_request,
        sign_secret_request_decision, verify_secret_request_decision,
    };
    use crate::crypto::identity::IdentityKeyPair;
    use crate::ids::AccountId;

    fn sample_proxy() -> ProxyProposal {
        ProxyProposal {
            preset: None,
            profile: "vercel-ai".into(),
            upstream: "https://ai-gateway.vercel.sh".into(),
            header: "authorization".into(),
            prefix: "Bearer ".into(),
            methods: vec!["POST".into()],
            ask_methods: Vec::new(),
            path_prefixes: vec!["/v1".into()],
            rate_per_minute: Some(60),
        }
    }

    fn sample_create() -> SecretRequestProposal {
        SecretRequestProposal {
            v: SECRET_REQUEST_FORMAT_VERSION,
            mode: SecretRequestMode::Create,
            kind: Some(ItemKind::ApiKey),
            title: Some("Vercel AI Gateway".into()),
            vault_id: Some(VaultId::generate()),
            project_id: Some(ProjectId::generate()),
            target_item_id: None,
            field: "api_key".into(),
            placeholder: Some("vck_…".into()),
            setup_url: Some("https://vercel.com/dashboard/ai-gateway".into()),
            base_url: Some("https://ai-gateway.vercel.sh".into()),
            urls: Vec::new(),
            notes: Some("Used by voz.mjs\nto generate narration".into()),
            proxy_proposal: Some(sample_proxy()),
        }
    }

    #[test]
    fn valid_create_and_update_proposals_pass() {
        let create = sample_create();
        create.validate().expect("valid create");

        let update = SecretRequestProposal {
            v: 1,
            mode: SecretRequestMode::Update,
            kind: None,
            title: None,
            vault_id: None,
            project_id: None,
            target_item_id: Some(ItemId::generate()),
            field: "api_key".into(),
            placeholder: None,
            setup_url: None,
            base_url: None,
            urls: Vec::new(),
            notes: None,
            proxy_proposal: None,
        };
        update.validate().expect("valid update");
    }

    #[test]
    fn smuggled_value_field_is_rejected_by_deserializer() {
        let raw = serde_json::json!({
            "v": 1,
            "mode": "create",
            "kind": "api_key",
            "title": "Stripe",
            "field": "api_key",
            "value": "sk_live_never_allowed"
        });
        assert!(serde_json::from_value::<SecretRequestProposal>(raw).is_err());
    }

    #[test]
    fn setup_url_rejects_phishing_schemes_credentials_ips_and_local_hosts() {
        for bad in [
            "",
            "http://vercel.com/keys",
            "javascript:alert(1)",
            "data:text/html,hi",
            "file:///etc/passwd",
            "https://vercel.com@evil.com/keys",
            "https://user:pass@vercel.com/keys",
            "https://127.0.0.1/keys",
            "https://169.254.169.254/latest/meta-data",
            "https://10.0.0.1/keys",
            "https://[::1]/keys",
            "https://localhost/keys",
            "https://app.localhost/keys",
            "https://printer.local/keys",
            "https://api.internal/keys",
            "https://router.home.arpa/keys",
            "https://intranet/keys",
            "https://vercel.com/\u{202E}keys",
        ] {
            assert!(validate_setup_url(bad).is_err(), "must reject {bad:?}");
        }

        let clean = validate_setup_url("https://vercel.com/dashboard/ai-gateway").expect("valid");
        assert_eq!(clean.host, "vercel.com");
        assert!(!clean.has_punycode);

        let idn = validate_setup_url("https://xn--vercl-dsa.com/keys").expect("valid idn");
        assert!(idn.has_punycode);

        let unicode_idn = validate_setup_url("https://vercél.com/keys").expect("unicode idn");
        assert!(unicode_idn.has_punycode);
    }

    #[test]
    fn disallowed_kinds_and_mode_mismatches_are_rejected() {
        for bad_kind in [
            ItemKind::Card,
            ItemKind::Identity,
            ItemKind::File,
            ItemKind::GeneratorHistory,
            ItemKind::Preferences,
        ] {
            let mut p = sample_create();
            p.kind = Some(bad_kind);
            p.base_url = None;
            assert!(matches!(p.validate(), Err(SecretRequestError::Kind(_))));
        }

        // `update` must not carry a title, kind or urls (card reads real vault item).
        let update_with_title = SecretRequestProposal {
            v: 1,
            mode: SecretRequestMode::Update,
            kind: None,
            title: Some("Fake Bank".into()),
            vault_id: None,
            project_id: None,
            target_item_id: Some(ItemId::generate()),
            field: "password".into(),
            placeholder: None,
            setup_url: None,
            base_url: None,
            urls: Vec::new(),
            notes: None,
            proxy_proposal: None,
        };
        assert!(update_with_title.validate().is_err());

        // `urls` only allowed on `login`.
        let mut api_with_urls = sample_create();
        api_with_urls.urls = vec!["https://example.com".into()];
        assert!(api_with_urls.validate().is_err());

        // `login` with valid URLs passes; `base_url` on `login` fails.
        let mut login = sample_create();
        login.kind = Some(ItemKind::Login);
        login.base_url = None;
        login.urls = vec!["https://github.com/login".into()];
        login.validate().expect("valid login proposal");
    }

    #[test]
    fn proxy_proposal_enforces_method_limit_overlap_and_upstream_rules() {
        // More than 4 methods in total.
        let mut too_many = sample_proxy();
        too_many.methods = vec!["GET".into(), "POST".into(), "PUT".into(), "PATCH".into()];
        too_many.ask_methods = vec!["DELETE".into()];
        assert!(too_many.validate().is_err());

        // Overlapping method between methods and ask_methods.
        let mut overlap = sample_proxy();
        overlap.methods = vec!["POST".into()];
        overlap.ask_methods = vec!["post".into()];
        assert!(overlap.validate().is_err());

        // Query string or http upstream rejected.
        let mut bad_upstream = sample_proxy();
        bad_upstream.upstream = "https://api.example.com/?x=1".into();
        assert!(bad_upstream.validate().is_err());

        // Control char in prefix rejected (header injection).
        let mut bad_prefix = sample_proxy();
        bad_prefix.prefix = "Bearer \r\nX-Evil: 1".into();
        assert!(bad_prefix.validate().is_err());

        // Rate limit bounds.
        let mut bad_rate = sample_proxy();
        bad_rate.rate_per_minute = Some(0);
        assert!(bad_rate.validate().is_err());
        bad_rate.rate_per_minute = Some(601);
        assert!(bad_rate.validate().is_err());
    }

    #[test]
    fn decision_enforces_t236_no_cross_project_leak() {
        let req = SecretRequestId::generate();
        let agent = AgentId::generate();

        let outside_grant_ok = SecretRequestDecision {
            v: 1,
            request_id: req,
            agent_id: agent,
            status: SecretRequestStatus::Fulfilled,
            in_grant: false,
            vault_id: None,
            project_id: None,
            item_id: None,
            field: Some("api_key".into()),
            proxy_profile: Some("vercel-ai".into()),
        };
        outside_grant_ok.validate().expect("valid outside grant");

        let mut leaked = outside_grant_ok.clone();
        leaked.item_id = Some(ItemId::generate());
        assert!(leaked.validate().is_err(), "T236 must reject leaked IDs");

        let in_grant_missing = SecretRequestDecision {
            v: 1,
            request_id: req,
            agent_id: agent,
            status: SecretRequestStatus::Fulfilled,
            in_grant: true,
            vault_id: Some(VaultId::generate()),
            project_id: None,
            item_id: Some(ItemId::generate()),
            field: Some("api_key".into()),
            proxy_profile: None,
        };
        assert!(in_grant_missing.validate().is_err());

        let denied_ok = SecretRequestDecision {
            v: 1,
            request_id: req,
            agent_id: agent,
            status: SecretRequestStatus::Denied,
            in_grant: false,
            vault_id: None,
            project_id: None,
            item_id: None,
            field: None,
            proxy_profile: None,
        };
        denied_ok.validate().expect("valid denied");

        let mut denied_with_proxy = denied_ok;
        denied_with_proxy.proxy_profile = Some("vercel-ai".into());
        assert!(denied_with_proxy.validate().is_err());
    }

    #[test]
    fn proposal_hpke_seal_and_signed_decision_round_trip() {
        let account = IdentityKeyPair::generate();
        let other = IdentityKeyPair::generate();
        let account_id = AccountId::generate();
        let agent_id = AgentId::generate();
        let request_id = SecretRequestId::generate();

        let proposal = sample_create();
        proposal.validate().expect("valid");
        let proposal_bytes = serde_json::to_vec(&proposal).expect("json");
        let digest = body_digest(&proposal_bytes);

        let blob = seal_secret_request(
            account.public(),
            account_id,
            agent_id,
            request_id,
            &proposal_bytes,
        )
        .expect("seal");
        assert_eq!(&blob[..2], &[0x01, 0x25]);

        let opened =
            open_secret_request(&account, account_id, agent_id, request_id, &blob).expect("open");
        assert_eq!(opened.as_slice(), proposal_bytes.as_slice());
        assert_eq!(body_digest(&opened), digest);

        // Wrong account, agent or request ID fails to open.
        assert!(open_secret_request(&other, account_id, agent_id, request_id, &blob).is_err());
        assert!(
            open_secret_request(&account, account_id, AgentId::generate(), request_id, &blob)
                .is_err()
        );
        assert!(
            open_secret_request(
                &account,
                account_id,
                agent_id,
                SecretRequestId::generate(),
                &blob
            )
            .is_err()
        );

        let decision = SecretRequestDecision {
            v: 1,
            request_id,
            agent_id,
            status: SecretRequestStatus::Fulfilled,
            in_grant: true,
            vault_id: proposal.vault_id,
            project_id: proposal.project_id,
            item_id: Some(ItemId::generate()),
            field: Some("api_key".into()),
            proxy_profile: Some("vercel-ai".into()),
        };
        decision.validate().expect("valid decision");
        let decision_bytes = serde_json::to_vec(&decision).expect("json");

        let to_sign = SecretRequestDecisionToSign {
            request: request_id,
            agent: agent_id,
            proposal_digest: &digest,
            decision: &decision_bytes,
            decided_at_ms: 1_800_000_000_500,
        };
        let sig = sign_secret_request_decision(&account, &to_sign);
        verify_secret_request_decision(account.public(), &to_sign, &sig).expect("verifies");

        // Tampered digest or other account rejected (T237).
        let mut wrong_digest = digest;
        wrong_digest[0] ^= 0x01;
        assert!(
            verify_secret_request_decision(
                account.public(),
                &SecretRequestDecisionToSign {
                    proposal_digest: &wrong_digest,
                    ..to_sign
                },
                &sig,
            )
            .is_err()
        );
        assert!(verify_secret_request_decision(other.public(), &to_sign, &sig).is_err());
    }

    #[test]
    fn reason_rejects_empty_too_long_and_bidi() {
        validate_reason("Generate voice narration with Vercel AI Gateway").expect("ok");
        assert!(validate_reason("   ").is_err());
        assert!(validate_reason(&"a".repeat(MAX_SECRET_REQUEST_REASON + 1)).is_err());
        assert!(validate_reason("ok\u{202E}reversed").is_err());
        assert!(validate_reason("line1\nline2").is_err());
    }
}
