//! Klav as a passkey provider on the desktop (ADR 0020): the three
//! operations `klavd` serves to the browser extension.
//!
//! - [`Unlocked::passkey_candidates`]: the logins whose passkey is for the
//!   page's rpId (metadata only).
//! - [`Unlocked::passkey_get`]: signs an assertion with one of them.
//! - [`Unlocked::passkey_create`]: creates a passkey in a new or existing
//!   login and returns the registration.
//!
//! The origin is the one the browser reported for the sender, never one
//! the page wrote (T80). `clientDataJSON` is built here from it. When the
//! rpId does not pass `klav_core::passkey::rp`, Klav does not answer: the
//! result says so and the extension hands the call to the browser.
//!
//! User verification is the caller's business (`klavd` asks for Touch ID
//! or the master password first): `user_verified` only sets the UV flag.
//! Signing writes nothing: the sign count stays 0 (ADR 0020 §5). The use
//! goes to the audit log afterwards, best effort, as `passkey.used`
//! ([`Unlocked::passkey_used_post`], ADR 0020 §10).

use klav_core::crypto::context::VaultContext;
use klav_core::ids::{AgentId, ItemId, ProjectId, TaskId, VaultId};
use klav_core::model::item::{Item, ItemKind};
use klav_core::model::{Passkey, PasskeyAccount};
use klav_core::passkey::rp::{self, RelyingParty};
use klav_core::passkey::webauthn::{self, ALG_ES256, Ceremony};
use klav_proto::audit::PersonEvent;
use reqwest::{Method, StatusCode};
use serde::{Deserialize, Serialize};

use crate::api::{self, Api, Body};
use crate::session::{ItemLocation, ItemSummary, Unlocked, now_ms};
use crate::{ClientError, ClientResult};

const B64: data_encoding::Encoding = data_encoding::BASE64URL_NOPAD;

/// Longest challenge accepted, in bytes (WebAuthn asks for at least 16;
/// nothing needs more than a few hundred).
pub const MAX_CHALLENGE_LEN: usize = 1024;
/// Most credential IDs accepted in `allowCredentials` or
/// `excludeCredentials`.
pub const MAX_CREDENTIAL_LIST: usize = 256;

/// Transports Klav reports for its credentials (ADR 0020 §5).
pub const TRANSPORTS: [&str; 2] = ["internal", "hybrid"];

/// A login that holds a passkey for the rpId. No secrets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasskeyCandidate {
    /// The login.
    pub item: ItemId,
    /// Its title.
    pub title: String,
    /// `user.name` of the passkey.
    pub user_name: String,
    /// Credential ID, base64url.
    pub credential_id: String,
    /// Vault name, to tell logins of different vaults apart.
    pub vault: String,
}

/// The answer to «which passkeys does Klav have here?».
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasskeyCandidates {
    /// The rpId, when Klav handles this page. `None`: the origin or the
    /// rpId did not pass the checks of ADR 0020 §7, and the call goes to
    /// the browser.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rp_id: Option<String>,
    /// Matching logins (exact rpId; filtered by `allowCredentials` when the
    /// page gave one).
    pub candidates: Vec<PasskeyCandidate>,
}

/// An assertion for the page (`PublicKeyCredential` of a `get`). Every
/// binary value is base64url without padding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasskeyAssertion {
    /// Credential ID (also `rawId`).
    pub credential_id: String,
    /// `clientDataJSON`.
    pub client_data_json: String,
    /// `authenticatorData`.
    pub authenticator_data: String,
    /// ES256 signature, DER.
    pub signature: String,
    /// `userHandle`.
    pub user_handle: String,
    /// The login that signed.
    pub item: ItemId,
}

/// What the page asks to create (`PublicKeyCredentialCreationOptions`,
/// already reduced by the extension).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasskeyCreateRequest {
    /// The sender's origin, as the browser reported it.
    pub origin: String,
    /// `rp.id`; the origin's host when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rp_id: Option<String>,
    /// `rp.name`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rp_name: Option<String>,
    /// `user.id`, base64url.
    pub user_id: String,
    /// `user.name`.
    pub user_name: String,
    /// `user.displayName`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_display_name: Option<String>,
    /// `challenge`, base64url.
    pub challenge: String,
    /// `excludeCredentials`, base64url IDs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclude_credentials: Vec<String>,
    /// Put it in this existing login (ID) instead of a new one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub item: Option<String>,
    /// The person confirmed replacing the passkey of the same account
    /// (same rpId and user handle, ADR 0020 §2).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub replace: bool,
    /// Vault of a new login (default vault when absent).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault: Option<String>,
    /// Project of a new login (default project when absent).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
}

impl PasskeyCreateRequest {
    /// A registration the platform hands over (the iOS extension): the
    /// values as bytes, the origin `https://<rp_id>` (iOS checked the
    /// site's associated domains) and no challenge, since the platform
    /// builds the `clientDataJSON` and Klav signs nothing over it.
    pub fn from_platform(
        rp_id: &str,
        rp_name: Option<String>,
        user_handle: &[u8],
        user_name: String,
        user_display_name: Option<String>,
        exclude_credentials: &[Vec<u8>],
    ) -> Self {
        Self {
            origin: format!("https://{rp_id}"),
            rp_id: Some(rp_id.to_owned()),
            rp_name,
            user_id: B64.encode(user_handle),
            user_name,
            user_display_name,
            challenge: String::new(),
            exclude_credentials: exclude_credentials.iter().map(|c| B64.encode(c)).collect(),
            item: None,
            replace: false,
            vault: None,
            project: None,
        }
    }
}

/// A created passkey, for the page (`PublicKeyCredential` of a `create`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasskeyRegistration {
    /// Credential ID (also `rawId`).
    pub credential_id: String,
    /// `clientDataJSON`.
    pub client_data_json: String,
    /// `attestationObject` (`none`).
    pub attestation_object: String,
    /// `getAuthenticatorData()`.
    pub authenticator_data: String,
    /// `getPublicKey()`: SubjectPublicKeyInfo DER.
    pub public_key: String,
    /// `getPublicKeyAlgorithm()`: -7.
    pub public_key_algorithm: i64,
    /// `getTransports()`.
    pub transports: Vec<String>,
    /// The login that holds it.
    pub item: ItemId,
    /// Its title.
    pub title: String,
}

/// The outcome of a `create`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum PasskeyCreateOutcome {
    /// Created; give it to the page.
    Created(Box<PasskeyRegistration>),
    /// The rpId did not pass the checks: hand the call to the browser.
    Browser,
    /// A credential of `excludeCredentials` is in Klav: the page gets
    /// `InvalidStateError` (only after the person consented, T86).
    Excluded,
    /// This account (rpId and user handle) already has a passkey in this
    /// login: ask the person and retry with `replace`.
    Exists {
        /// The login.
        item: ItemId,
        /// Its title.
        title: String,
    },
}

/// The audit action of a passkey sign-in.
pub const PASSKEY_USED: &str = "passkey.used";

/// A `passkey.used` event ready to send without the session (the token was
/// taken when it was built), so that `klavd` does not hold the vault while
/// it talks to the server.
pub struct PasskeyUsedPost {
    api: Api,
    access: zeroize::Zeroizing<String>,
    event: PersonEvent,
}

impl PasskeyUsedPost {
    /// `POST /v1/audit/person`. `Ok(false)` when the server refused the
    /// token (expired or rotated meanwhile): send it with
    /// [`Unlocked::log_passkey_used`] instead.
    pub async fn send(self) -> ClientResult<bool> {
        let res = self
            .api
            .send_body(
                Method::POST,
                "/v1/audit/person",
                Some(&self.access),
                &Body::json(&self.event)?,
            )
            .await?;
        if res.status() == StatusCode::UNAUTHORIZED {
            return Ok(false);
        }
        api::empty(res).await.map(|()| true)
    }
}

fn passkey_used(item: ItemId, agent: Option<(AgentId, TaskId)>) -> PersonEvent {
    PersonEvent {
        action: PASSKEY_USED.into(),
        item_id: item,
        agent_id: agent.map(|(a, _)| a),
        task_id: agent.map(|(_, t)| t),
    }
}

fn decode_b64(text: &str, what: &str, max: usize) -> ClientResult<Vec<u8>> {
    let bytes = B64
        .decode(text.trim_end_matches('=').as_bytes())
        .map_err(|_| ClientError::Invalid(format!("{what} is not base64url")))?;
    if bytes.len() > max {
        return Err(ClientError::Invalid(format!("{what} is too long")));
    }
    Ok(bytes)
}

fn decode_list(list: &[String], what: &str) -> ClientResult<Vec<Vec<u8>>> {
    if list.len() > MAX_CREDENTIAL_LIST {
        return Err(ClientError::Invalid(format!("too many {what}")));
    }
    list.iter()
        .map(|id| decode_b64(id, what, klav_core::crypto::passkey::MAX_CREDENTIAL_ID_LEN))
        .collect()
}

/// What [`Unlocked::prepare_passkey`] decided.
pub(crate) enum Prepared {
    /// Klav holds one of the excluded credentials.
    Excluded,
    /// The account already has a passkey in `item`.
    Exists { item: ItemId, title: String },
    /// The item with its new passkey, to store.
    Ready(Box<ReadyPasskey>),
}

/// A new passkey, set in its login but not stored yet.
pub(crate) struct ReadyPasskey {
    pub(crate) loc: ItemLocation,
    pub(crate) item: Item,
    /// A new login (else the next version of `loc`).
    pub(crate) new: bool,
    pub(crate) registration: webauthn::Registration,
    pub(crate) credential_id: String,
}

impl Unlocked {
    fn passkey_summaries(&self, rp_id: &str) -> Vec<(ItemLocation, ItemSummary)> {
        self.live_items()
            .into_iter()
            .filter(|(_, s, _)| {
                s.kind == ItemKind::Login && s.passkey.as_ref().is_some_and(|p| p.rp_id == rp_id)
            })
            .map(|(loc, s, _)| (loc, s))
            .collect()
    }

    /// The logins with a passkey for the page. `allow_credentials` (the
    /// page's `allowCredentials`, base64url) narrows the list when it is
    /// not empty.
    pub fn passkey_candidates(
        &self,
        origin: &str,
        rp_id: Option<&str>,
        allow_credentials: &[String],
    ) -> ClientResult<PasskeyCandidates> {
        let Ok(rp) = rp::validate(origin, rp_id) else {
            return Ok(PasskeyCandidates {
                rp_id: None,
                candidates: Vec::new(),
            });
        };
        let allow = decode_list(allow_credentials, "allowCredentials")?;
        let mut candidates: Vec<PasskeyCandidate> = self
            .passkey_summaries(&rp.rp_id)
            .into_iter()
            .filter_map(|(_, s)| {
                let p = s.passkey?;
                let id = B64.decode(p.credential_id.as_bytes()).ok()?;
                if !allow.is_empty() && !allow.contains(&id) {
                    return None;
                }
                Some(PasskeyCandidate {
                    item: s.id,
                    title: s.title,
                    user_name: p.user_name,
                    credential_id: p.credential_id,
                    vault: s.vault,
                })
            })
            .collect();
        candidates.sort_by_key(|c| c.title.to_lowercase());
        Ok(PasskeyCandidates {
            rp_id: Some(rp.rp_id),
            candidates,
        })
    }

    /// Signs an assertion with the passkey of the login `item` for the page
    /// at `origin`. The login's passkey must be for exactly that rpId.
    pub fn passkey_get(
        &self,
        origin: &str,
        rp_id: Option<&str>,
        challenge: &str,
        item: &str,
        user_verified: bool,
    ) -> ClientResult<PasskeyAssertion> {
        let rp = rp::validate(origin, rp_id)
            .map_err(|e| ClientError::Denied(format!("not a passkey page: {e}")))?;
        let challenge = decode_b64(challenge, "challenge", MAX_CHALLENGE_LEN)?;
        let id: ItemId = item
            .parse()
            .map_err(|_| ClientError::Invalid("invalid item ID".into()))?;
        let (loc, _) = self
            .passkey_summaries(&rp.rp_id)
            .into_iter()
            .find(|(loc, _)| loc.item == id)
            .ok_or_else(|| ClientError::NotFound("a passkey for this site".into()))?;
        let opened = self.open_item(loc)?;
        let passkey = opened
            .passkey()
            .filter(|p| p.rp_id() == rp.rp_id)
            .ok_or_else(|| ClientError::NotFound("a passkey for this site".into()))?;
        let key = passkey.open_key(
            self.vault_key(loc.vault)?.0,
            &self.vault_ctx(loc.vault)?,
            loc.item,
        )?;
        let client_data = webauthn::client_data_json(Ceremony::Get, &challenge, &rp.origin);
        let assertion = webauthn::assert(
            &key,
            &rp.rp_id,
            user_verified,
            &webauthn::client_data_hash(client_data.as_bytes()),
        );
        Ok(PasskeyAssertion {
            credential_id: B64.encode(passkey.credential_id()),
            client_data_json: B64.encode(client_data.as_bytes()),
            authenticator_data: B64.encode(&assertion.authenticator_data),
            signature: B64.encode(&assertion.signature),
            user_handle: B64.encode(passkey.user_handle()),
            item: loc.item,
        })
    }

    /// Creates a passkey for the page and stores it: in `request.item` when
    /// given, else in the login of the same account (same rpId and user
    /// handle) when `replace`, else in a new login.
    pub async fn passkey_create(
        &mut self,
        request: &PasskeyCreateRequest,
        user_verified: bool,
    ) -> ClientResult<PasskeyCreateOutcome> {
        let Ok(rp) = rp::validate(&request.origin, request.rp_id.as_deref()) else {
            return Ok(PasskeyCreateOutcome::Browser);
        };
        let challenge = decode_b64(&request.challenge, "challenge", MAX_CHALLENGE_LEN)?;
        let ready = match self.prepare_passkey(&rp, request, user_verified)? {
            Prepared::Excluded => return Ok(PasskeyCreateOutcome::Excluded),
            Prepared::Exists { item, title } => {
                return Ok(PasskeyCreateOutcome::Exists { item, title });
            }
            Prepared::Ready(ready) => *ready,
        };
        let ReadyPasskey {
            loc,
            item,
            new,
            registration,
            credential_id,
        } = ready;
        if new {
            self.add_item(loc.vault, loc.project, &item).await?;
        } else {
            self.update_item(loc, &item).await?;
        }
        let client_data = webauthn::client_data_json(Ceremony::Create, &challenge, &rp.origin);
        Ok(PasskeyCreateOutcome::Created(Box::new(
            PasskeyRegistration {
                credential_id,
                client_data_json: B64.encode(client_data.as_bytes()),
                attestation_object: B64.encode(&registration.attestation_object),
                authenticator_data: B64.encode(&registration.auth_data),
                public_key: B64.encode(&registration.public_key_spki),
                public_key_algorithm: ALG_ES256,
                transports: TRANSPORTS.iter().map(|t| (*t).to_owned()).collect(),
                item: loc.item,
                title: item.title().to_owned(),
            },
        )))
    }

    /// The common part of creating a passkey, online or queued: the
    /// checks (excluded credentials, the account's own passkey), where it
    /// goes, and the item with its new passkey (not stored yet).
    pub(crate) fn prepare_passkey(
        &self,
        rp: &RelyingParty,
        request: &PasskeyCreateRequest,
        user_verified: bool,
    ) -> ClientResult<Prepared> {
        let user_handle = decode_b64(
            &request.user_id,
            "user.id",
            klav_core::crypto::passkey::MAX_USER_HANDLE_LEN,
        )?;
        if user_handle.is_empty() {
            return Err(ClientError::Invalid("user.id is empty".into()));
        }
        let exclude = decode_list(&request.exclude_credentials, "excludeCredentials")?;

        // Who already has a passkey for this rpId.
        let mut same_account: Option<(ItemLocation, String)> = None;
        for (loc, summary) in self.passkey_summaries(&rp.rp_id) {
            let item = self.open_item(loc)?;
            let Some(p) = item.passkey() else { continue };
            if exclude.iter().any(|id| id.as_slice() == p.credential_id()) {
                return Ok(Prepared::Excluded);
            }
            if p.user_handle() == user_handle.as_slice() {
                same_account = Some((loc, summary.title));
            }
        }

        // Where it goes.
        let target: Option<ItemLocation> = match &request.item {
            Some(query) => {
                let loc = self.find_item(query)?;
                let item = self.open_item(loc)?;
                if item.kind() != ItemKind::Login {
                    return Err(ClientError::Invalid("a passkey goes in a login".into()));
                }
                if let Some(p) = item.passkey() {
                    let same = p.rp_id() == rp.rp_id && p.user_handle() == user_handle.as_slice();
                    if !same {
                        // Another account's passkey: another login (ADR 0020 §2).
                        return Err(ClientError::Invalid(
                            "this login already has a passkey for another account".into(),
                        ));
                    }
                    if !request.replace {
                        return Ok(Prepared::Exists {
                            item: loc.item,
                            title: item.title().to_owned(),
                        });
                    }
                } else if !self.for_site(loc, rp)? {
                    return Err(ClientError::Denied(
                        "this login is not saved for this site".into(),
                    ));
                }
                Some(loc)
            }
            None => match same_account {
                Some((loc, title)) if !request.replace => {
                    return Ok(Prepared::Exists {
                        item: loc.item,
                        title,
                    });
                }
                Some((loc, _)) => Some(loc),
                None => None,
            },
        };

        let (loc, mut item, new) = match target {
            Some(loc) => {
                let mut item = self.open_item(loc)?;
                self.drop_pending_urls(loc, &mut item)?;
                (loc, item, false)
            }
            None => {
                let (vault, project) =
                    self.destination(request.vault.as_deref(), request.project.as_deref())?;
                let item = self.new_passkey_login(vault, project, rp, request)?;
                let loc = ItemLocation {
                    vault,
                    project,
                    item: item.id(),
                };
                (loc, item, true)
            }
        };
        let account = PasskeyAccount {
            rp_id: &rp.rp_id,
            rp_name: request.rp_name.as_deref().filter(|n| !n.is_empty()),
            user_handle: &user_handle,
            user_name: &request.user_name,
            user_display_name: request
                .user_display_name
                .as_deref()
                .filter(|n| !n.is_empty()),
            created_at: now_ms(),
        };
        let (passkey, key) = Passkey::create(
            self.vault_key(loc.vault)?.0,
            &self.vault_ctx(loc.vault)?,
            loc.item,
            &account,
        )?;
        let registration =
            webauthn::register(&key, &rp.rp_id, passkey.credential_id(), user_verified)?;
        let credential_id = B64.encode(passkey.credential_id());
        item.set_passkey(passkey)?;
        Ok(Prepared::Ready(Box::new(ReadyPasskey {
            loc,
            item,
            new,
            registration,
            credential_id,
        })))
    }

    /// A new login for a passkey: titled after `rp.name` (or the rpId),
    /// with a free title in its project, the user name in `username` and
    /// the page's site among its URLs.
    fn new_passkey_login(
        &self,
        vault: VaultId,
        project: ProjectId,
        rp: &RelyingParty,
        request: &PasskeyCreateRequest,
    ) -> ClientResult<Item> {
        let base = request
            .rp_name
            .as_deref()
            .map(str::trim)
            .filter(|n| !n.is_empty() && !n.chars().any(char::is_control))
            .map(|n| n.chars().take(200).collect::<String>())
            .unwrap_or_else(|| rp.rp_id.clone());
        let mut title = base.clone();
        let mut n = 2;
        while !self.titled(vault, project, &title).is_empty() {
            title = format!("{base} ({n})");
            n += 1;
        }
        let mut item = Item::from_template(ItemKind::Login, &title)?;
        if !request.user_name.is_empty()
            && let Some(field) = item.field_mut("username")
        {
            field.set_value(&request.user_name)?;
        }
        // The page's own origin; `set_passkey` adds `https://<rp_id>` when
        // the page is on a subdomain.
        item.add_url(&rp.origin)?;
        Ok(item)
    }

    /// The `passkey.used` event of a sign-in with the passkey of `item`
    /// (by `agent` inside its task, when an agent used it), to send after
    /// answering the page. `None` when the access token is about to
    /// expire: use [`Unlocked::log_passkey_used`]. The event names only the
    /// item, never the site (ADR 0020 §10).
    pub fn passkey_used_post(
        &self,
        item: ItemId,
        agent: Option<(AgentId, TaskId)>,
    ) -> Option<PasskeyUsedPost> {
        let (api, access) = self.bearer()?;
        Some(PasskeyUsedPost {
            api,
            access,
            event: passkey_used(item, agent),
        })
    }

    /// Sends `passkey.used` with the session, refreshing the token if needed.
    pub async fn log_passkey_used(
        &mut self,
        item: ItemId,
        agent: Option<(AgentId, TaskId)>,
    ) -> ClientResult<()> {
        let res = self
            .authed(
                Method::POST,
                "/v1/audit/person",
                &Body::json(&passkey_used(item, agent))?,
            )
            .await?;
        api::empty(res).await
    }

    /// Whether a login chosen for a new passkey is for the page's site: by
    /// the URLs the person confirmed, as in the logins the frame offers
    /// (`suggest`); one an agent added does not count (ADR 0030 §7). A
    /// login without any URL is for no site yet: the passkey gives it one.
    fn for_site(&self, loc: ItemLocation, rp: &RelyingParty) -> ClientResult<bool> {
        let summary = self.item_summary(loc)?;
        Ok(
            klav_core::site::url_matches(&rp.origin, &summary.confirmed_urls)
                || (summary.confirmed_urls.is_empty() && summary.pending_urls.is_empty()),
        )
    }

    /// Removes the URLs an agent added that the person has not confirmed
    /// (ADR 0030 §7) from an item about to get a passkey. Saving writes a
    /// version of the person, which would confirm every URL in it without
    /// the person seeing them: an agent's site would start to fill. Fails
    /// closed: the agent can add it again for the person to confirm.
    pub(crate) fn drop_pending_urls(&self, loc: ItemLocation, item: &mut Item) -> ClientResult<()> {
        for url in self.item_summary(loc)?.pending_urls {
            item.remove_url(&url);
        }
        Ok(())
    }

    pub(crate) fn vault_ctx(&self, vault: VaultId) -> ClientResult<VaultContext> {
        Ok(VaultContext {
            account: self.vault_key(vault)?.1,
            vault,
        })
    }
}
