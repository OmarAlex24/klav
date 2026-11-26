//! Per-item grants (ADR 0036 §2, spec §13.4 `v: 2`): an agent, such as the
//! credential proxy, gets the keys of single items (kind `0x23`), never of
//! a project, and the profiles that say where each value may go.
//!
//! Revoking such a grant changes the key of every item it shared (ADR 0036
//! §18): the revoked agent may have kept the old key, so the item gets a
//! new one, its sections are sealed again and every attachment key is
//! wrapped again with it, in one write. Other agents that still hold the
//! item get a new grant with the new key.

use std::collections::{BTreeSet, HashSet};

use klav_core::crypto::agent::{self, GrantToSign};
use klav_core::crypto::context::{AttachmentContext, ProjectContext};
use klav_core::crypto::identity::PublicIdentity;
use klav_core::crypto::keys::ItemKey;
use klav_core::crypto::share::{share_item_key, share_project_key};
use klav_core::crypto::wrap::{unwrap_attachment_key, wrap_attachment_key, wrap_item_key};
use klav_core::ids::{AgentId, ItemId, ProjectId};
use klav_core::model::seal_item;
use klav_core::policy::Policy;
use klav_proto::Blob;
use klav_proto::agent::{
    AgentInfo, AgentStatus, GRANT_PAYLOAD_VERSION_ITEMS, GrantLabels, GrantPayload, GrantedItem,
    LocalClient, ProxyProfile, SandboxIssuer, SignedGrant,
};
use klav_proto::vault::{Item as WireItem, RewrappedAttachmentKey, UpdateItem};
use reqwest::Method;
use serde::{Deserialize, Serialize};

use crate::agents::AgentView;
use crate::api::Body;
use crate::error::{ClientError, ClientResult};
use crate::session::{ItemLocation, Unlocked, now_ms};

/// What to grant item by item.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ItemGrantRequest {
    /// The items whose keys the agent receives.
    pub items: Vec<ItemLocation>,
    /// Where each value may go (ADR 0036 §2).
    #[serde(default)]
    pub profiles: Vec<ProxyProfile>,
    /// The policy: `proxy` rules that name the items and their hosts, and
    /// `deny` for `reveal`, `inject` and `fill`. Vault and project
    /// selectors may use names.
    pub policy: Policy,
    /// The agents that may start sandboxes through this proxy (`v: 3`,
    /// ADR 0036 §4). A change to the credentials carries them over.
    #[serde(default)]
    pub issuers: Vec<SandboxIssuer>,
    /// The MCP clients on the person's Mac that may use its MCP profiles
    /// (`v: 4`, ADR 0049 §3.2). A change to the credentials carries them
    /// over.
    #[serde(default)]
    pub local_clients: Vec<LocalClient>,
}

/// Result of [`Unlocked::grant_items`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ItemGrantReport {
    /// The agent: with its new grant when `granted`, else as it was.
    pub agent: AgentView,
    /// The new grant was uploaded. `false` when giving the dropped items
    /// new keys or uploading the grant failed (`failed` says which): the
    /// agent keeps its old grant, which lists items whose new keys it
    /// cannot open, and running it again finishes. The other holders are
    /// re-issued either way.
    pub granted: bool,
    /// Items the new grant no longer shares whose key changed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rekeyed: Vec<ItemId>,
    /// Other agents that got a new grant with the new item keys.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub regranted: Vec<String>,
    /// Other agents whose grant could not be re-issued (`name: why`): they
    /// still hold the old keys of those items. Run it again.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub not_regranted: Vec<String>,
    /// What stopped the key changes, if they stopped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failed: Option<String>,
    /// Items whose key still has to change (the failed one first).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pending: Vec<ItemId>,
    /// Items whose new key the server took, but whose sync after it failed:
    /// the key changed on the server and this device has not confirmed it,
    /// so the agents in `to_reissue` could not get it. Run it again.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unconfirmed: Vec<ItemId>,
    /// The other agents that hold an item in `unconfirmed` and need a new
    /// grant with its new key (empty if they could not be listed).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub to_reissue: Vec<String>,
    /// Items that dropped out of the grant that this device no longer sees
    /// (purged): no key left to change, but the agent may have kept their
    /// values.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub gone: Vec<ItemId>,
    /// This only re-issued the grants of other agents that still hold an
    /// item the proxy no longer has (a retry after a failed re-issue).
    #[serde(default)]
    pub reissue_only: bool,
}

impl ItemGrantReport {
    /// Whether everything finished: the grant is uploaded, every key that
    /// had to change changed, and every other holder was re-issued. When
    /// not, the command that made it must exit with an error.
    pub fn complete(&self) -> bool {
        self.granted
            && self.failed.is_none()
            && self.not_regranted.is_empty()
            && self.pending.is_empty()
            && self.unconfirmed.is_empty()
    }
}

/// Grants re-issued by [`Unlocked::regrant_agents`]: the agents that got
/// one, and those that did not (`name: why`).
#[derive(Debug, Default)]
pub(crate) struct Regrants {
    pub(crate) done: Vec<String>,
    pub(crate) failed: Vec<String>,
}

impl Regrants {
    /// The sentence for a report's `failed`, if some re-issue failed.
    pub(crate) fn failure(&self) -> Option<String> {
        (!self.failed.is_empty()).then(|| {
            format!(
                "re-issuing the grants of the other agents failed for {}",
                self.failed.join("; ")
            )
        })
    }
}

/// Item keys changed after a grant stopped sharing them.
#[derive(Debug, Default)]
pub(crate) struct Rekeys {
    pub(crate) done: Vec<ItemId>,
    pub(crate) failed: Option<String>,
    pub(crate) pending: Vec<ItemId>,
    /// The server took the new key, and the sync after it failed.
    pub(crate) unconfirmed: Vec<ItemId>,
    /// This device no longer sees them (purged): no key to change.
    pub(crate) gone: Vec<ItemId>,
}

impl Unlocked {
    /// Approves an agent with a per-item grant (or replaces its per-item
    /// grant). `pairing_code` is what the person compared with the agent's
    /// screen. Items the old grant shared and the new one does not get a
    /// new key, and other agents holding them a new grant.
    ///
    /// An agent that holds projects keeps them: its grant is not turned
    /// into a per-item one (revoke it and pair the proxy as a new agent).
    pub async fn grant_items(
        &mut self,
        id: AgentId,
        request: ItemGrantRequest,
        pairing_code: &str,
    ) -> ClientResult<ItemGrantReport> {
        self.grant_items_at(id, request, pairing_code, None).await
    }

    /// [`Self::grant_items`], refused when `expected` is given and the
    /// agent's current grant version (0 without a grant) is not it: a
    /// change prepared from one grant is never applied to a newer one,
    /// whose items it would drop.
    pub(crate) async fn grant_items_at(
        &mut self,
        id: AgentId,
        request: ItemGrantRequest,
        pairing_code: &str,
        expected: Option<u64>,
    ) -> ClientResult<ItemGrantReport> {
        if request.items.is_empty() {
            return Err(ClientError::Invalid("grant at least one item".into()));
        }
        self.sync().await?;
        let info = self.agent_info(id).await?;
        match info.status {
            AgentStatus::Pending | AgentStatus::Active => {}
            other => {
                return Err(ClientError::Invalid(format!(
                    "agent {} is {}; it cannot be approved",
                    info.name,
                    other.as_str()
                )));
            }
        }
        if self.cache.revocations.contains_key(&id) {
            return Err(ClientError::Security(format!(
                "agent {} was revoked from this device; it is never granted again",
                info.name
            )));
        }
        let public = PublicIdentity::decode(info.public_identity.as_bytes())?;
        if !agent::pairing_code_matches(&public, pairing_code) {
            return Err(ClientError::Security(format!(
                "the pairing words of agent {} do not match; do not approve it",
                info.name
            )));
        }
        // Klav Cloud's proxy: verified before anything changes (an item
        // key, a dropped item's rekey); `upload_grant` checks it again
        // right before the grant leaves.
        self.check_hosted_wrap(id, &public).await?;
        let current = match &info.grant {
            Some(g) => Some(self.open_grant(id, &public, g)?),
            None => None,
        };
        let version = current.as_ref().map_or(0, |g| g.version);
        if expected.is_some_and(|v| v != version) {
            return Err(ClientError::Invalid(format!(
                "the grant of agent {} changed since this was prepared (version {version}); run it again",
                info.name
            )));
        }
        if current.as_ref().is_some_and(|g| !g.projects.is_empty()) {
            return Err(ClientError::Invalid(format!(
                "agent {} holds the keys of whole projects; revoke it and pair the proxy as a new agent",
                info.name
            )));
        }
        let policy = self.resolve_policy(request.policy)?;
        let mut seen = HashSet::new();
        let wanted: Vec<ItemLocation> = request
            .items
            .into_iter()
            .filter(|loc| seen.insert(loc.item))
            .collect();
        // Items it no longer gets: it may have kept their keys.
        let dropped: Vec<ItemId> = current
            .iter()
            .flat_map(|g| g.items.iter().map(|i| i.item_id))
            .filter(|i| !seen.contains(i))
            .collect();
        // Everything that can fail without changing anything comes first:
        // sharing the wanted items (an item in the trash is refused) and
        // checking the new payload. A failure here leaves every key and
        // every grant as it was.
        // An item the grant already holds keeps its place even in the trash
        // (as a re-issue does): taking another item away must not fail
        // because this one waits in the trash. A new one must be live.
        let held: HashSet<ItemId> = current
            .iter()
            .flat_map(|g| g.items.iter().map(|i| i.item_id))
            .collect();
        let mut items = Vec::with_capacity(wanted.len());
        for loc in wanted {
            items.push(if held.contains(&loc.item) {
                self.reshare_item(&public, loc)?
            } else {
                self.share_item(&public, loc)?
            });
        }
        let mut payload = GrantPayload {
            v: GRANT_PAYLOAD_VERSION_ITEMS,
            account_id: self.account.account_id,
            agent_id: id,
            version: version + 1,
            issued_at: now_ms(),
            policy,
            projects: Vec::new(),
            items,
            profiles: request.profiles,
            issuers: request.issuers,
            sandbox: None,
            local_clients: request.local_clients,
            released: Vec::new(),
        };
        // At least 2 (it is a per-item grant), 3 only while it carries
        // issuers.
        payload.v = payload
            .version_after(current.as_ref().map_or(0, |g| g.v))
            .max(GRANT_PAYLOAD_VERSION_ITEMS);
        check_payload(&payload)?;
        // Then the dropped items get a new key, **before** the new grant is
        // uploaded: if anything after this fails, the agent keeps its old
        // grant (listing items whose new keys it cannot open) and a retry
        // finds them again. The other way round, a failure would leave a
        // grant without them and nothing to retry. The wanted items keep
        // their keys, so what was shared above stays valid.
        let rekeys = self.rekey_items(&dropped).await;
        let mut report = ItemGrantReport {
            agent: self.view(info)?,
            granted: false,
            rekeyed: rekeys.done.clone(),
            regranted: Vec::new(),
            not_regranted: Vec::new(),
            failed: rekeys.failed.clone(),
            pending: rekeys.pending.clone(),
            unconfirmed: rekeys.unconfirmed.clone(),
            to_reissue: Vec::new(),
            gone: rekeys.gone.clone(),
            reissue_only: false,
        };
        // Their new keys are on the server but not on this device, so the
        // other holders cannot be re-issued now: name them (best effort,
        // the network may be what failed).
        if !rekeys.unconfirmed.is_empty() {
            report.to_reissue = self
                .holders_of(&rekeys.unconfirmed, Some(id))
                .await
                .unwrap_or_default();
        }
        if rekeys.failed.is_none() {
            match self.upload_grant(id, &public, payload).await {
                Ok(agent) => {
                    report.agent = agent;
                    report.granted = true;
                }
                Err(e) => report.failed = Some(format!("uploading the new grant: {e}")),
            }
        }
        // Whatever happened to this agent's grant, the other holders of
        // what got a new key need it now; this agent never does (its new
        // grant no longer lists those items, and its old one must not get
        // their new keys).
        if !rekeys.done.is_empty() {
            match self.regrant_agents(&[], &rekeys.done, Some(id)).await {
                Ok(r) => {
                    if report.failed.is_none() {
                        report.failed = r.failure();
                    }
                    report.regranted = r.done;
                    report.not_regranted = r.failed;
                }
                Err(e) => {
                    report.not_regranted = vec![format!("the other agents: {e}")];
                    if report.failed.is_none() {
                        report.failed =
                            Some(format!("re-issuing the grants of the other agents: {e}"));
                    }
                }
            }
        }
        Ok(report)
    }

    /// The item key of `loc` sealed for `public` (kind `0x23`), for a new
    /// grant: an item in the trash is refused.
    fn share_item(&self, public: &PublicIdentity, loc: ItemLocation) -> ClientResult<GrantedItem> {
        if self.item_parts(loc)?.2.trashed_at.is_some() {
            return Err(ClientError::Invalid(format!(
                "item {} is in the trash",
                loc.item
            )));
        }
        self.reshare_item(public, loc)
    }

    /// The item key of `loc` sealed for `public`, for a grant that already
    /// had it (a re-issue): an item in the trash keeps its place, with its
    /// current key, so a restore does not need a new approval.
    fn reshare_item(
        &self,
        public: &PublicIdentity,
        loc: ItemLocation,
    ) -> ClientResult<GrantedItem> {
        if klav_core::model::history::is_system_project(loc.vault, loc.project) {
            return Err(ClientError::Invalid(
                "items of Klav's system project cannot be granted to an agent".into(),
            ));
        }
        let (ctx, key, _) = self.item_parts(loc)?;
        if ctx.project != loc.project {
            return Err(ClientError::NotFound(format!(
                "item {} in project {}",
                loc.item, loc.project
            )));
        }
        Ok(GrantedItem {
            vault_id: ctx.vault,
            owner_account_id: ctx.account,
            project_id: ctx.project,
            item_id: ctx.item,
            shared_key: Blob::new(share_item_key(public, &ctx, &key)?),
        })
    }

    /// Where `item` lives now (in the trash too), if this device sees it.
    pub(crate) fn locate_item(&self, item: ItemId) -> Option<ItemLocation> {
        self.vaults.keys().find_map(|vault| {
            self.wire(*vault, item).map(|w| ItemLocation {
                vault: *vault,
                project: w.project_id,
                item,
            })
        })
    }

    /// The completed attachments of `item` that are not deleted, as
    /// cached.
    fn item_attachments(
        &self,
        vault: klav_core::ids::VaultId,
        item: ItemId,
    ) -> Vec<(klav_core::ids::AttachmentId, &klav_proto::sync::Attachment)> {
        self.cache
            .vaults
            .get(&vault)
            .map(|v| {
                v.attachments
                    .iter()
                    .filter(|(_, a)| {
                        a.item_id == item && a.deleted_at.is_none() && a.completed_at.is_some()
                    })
                    .map(|(id, a)| (*id, a))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Signs `payload` after checking its format, and uploads it.
    pub(crate) async fn upload_grant(
        &mut self,
        id: AgentId,
        public: &PublicIdentity,
        payload: GrantPayload,
    ) -> ClientResult<AgentView> {
        // Every grant this device signs goes through here: an agent it
        // revoked never gets one again, whatever the server says of it
        // (T24). Its keys may have changed since; a grant would hand it
        // the new ones.
        if self.cache.revocations.contains_key(&id) {
            return Err(ClientError::Security(format!(
                "agent {id} was revoked from this device; it is never granted again"
            )));
        }
        // Klav Cloud's proxy gets a grant only once its attestation, with a
        // fresh nonce, binds exactly `public` (ADR 0051 §2.2 step 7). A
        // build without the feature refuses it.
        self.check_hosted_wrap(id, public).await?;
        // The protection of environments (ADR 0032 §3.1): the inherited
        // rules of the grant in force are kept unless this device can prove
        // their release, and the protected items it reaches are added.
        let previous = match self.agent_info(id).await?.grant {
            Some(grant) => Some(self.open_grant(id, public, &grant)?),
            None => None,
        };
        let mut payload = payload;
        self.protect_grant(&mut payload, previous.as_ref())?;
        check_payload(&payload)?;
        // Before the server sees it: a later revocation changes the keys of
        // every project and item this device ever granted it, whatever grant the
        // server serves or where it ends the log (T189).
        let projects: BTreeSet<ProjectId> = payload.projects.iter().map(|p| p.project_id).collect();
        let items: BTreeSet<ItemId> = payload.items.iter().map(|i| i.item_id).collect();
        self.note_signing(id, &projects, &items)?;
        let version = payload.version;
        let bytes = serde_json::to_vec(&payload)
            .map_err(|e| ClientError::Invalid(format!("grant: {e}")))?;
        let signature = agent::sign_grant(
            &self.identity,
            &GrantToSign {
                account: self.account.account_id,
                agent: id,
                agent_public: public,
                payload: &bytes,
            },
        );
        let grant = SignedGrant {
            payload: Blob::new(bytes),
            signature: Blob::new(signature.to_bytes().to_vec()),
        };
        let info: AgentInfo = self
            .send_json(Method::POST, &format!("/v1/agents/{id}/grant"), &grant)
            .await?;
        // After the server took it: the log must now hold it.
        if let Err(e) = self.note_signed(id, version) {
            self.warnings.push(format!(
                "the grant is in force, but this device could not write down that it signed version {version}: {e}"
            ));
        }
        self.view(info)
    }

    /// Re-issues a grant as it is, with the current keys of its projects
    /// and items: every other field is copied and `v` never goes down.
    /// Projects this device no longer sees (deleted) drop out, as before
    /// per-item grants; an item it no longer sees fails it, since profiles
    /// and rules name it and the grant is not rewritten behind the
    /// person's back.
    pub(crate) async fn reissue_grant(
        &mut self,
        id: AgentId,
        public: &PublicIdentity,
        old: GrantPayload,
    ) -> ClientResult<AgentView> {
        let mut payload = old;
        payload.version += 1;
        payload.issued_at = now_ms();
        // What the payload now carries: 3 only with issuers or a sandbox
        // proxy, and never 2 back to 1.
        payload.v = payload.version_after(payload.v);
        payload
            .projects
            .retain(|p| self.projects.contains_key(&p.project_id));
        for project in &mut payload.projects {
            let entry = self
                .projects
                .get(&project.project_id)
                .ok_or_else(|| ClientError::NotFound(format!("project {}", project.project_id)))?;
            let ctx = ProjectContext {
                account: project.owner_account_id,
                vault: project.vault_id,
                project: project.project_id,
            };
            project.shared_key = Blob::new(share_project_key(public, &ctx, &entry.key)?);
            // Sealed with the project key: sealed again with the current
            // one, with the current names (as a new approval would).
            let vault = self
                .vaults
                .get(&project.vault_id)
                .map(|v| v.meta.name().to_owned())
                .unwrap_or_default();
            let labels = serde_json::to_vec(&GrantLabels {
                vault,
                project: entry.meta.name().to_owned(),
            })
            .map_err(|e| ClientError::Invalid(format!("grant labels: {e}")))?;
            project.labels = Blob::new(agent::seal_grant_labels(&entry.key, &ctx, id, &labels));
        }
        for item in &mut payload.items {
            let loc = ItemLocation {
                vault: item.vault_id,
                project: item.project_id,
                item: item.item_id,
            };
            *item = self.reshare_item(public, loc)?;
        }
        self.upload_grant(id, public, payload).await
    }

    /// Changes the key of each item in `items`, in order, and stops at the
    /// first failure (the rest stay pending). Items this device no longer
    /// sees (purged) have no key left to change: they go to `gone`. A key
    /// the server took whose sync then failed goes to `unconfirmed`, never
    /// to `pending`: it did change.
    pub(crate) async fn rekey_items(&mut self, items: &[ItemId]) -> Rekeys {
        let mut out = Rekeys::default();
        let mut left = items.iter().copied();
        for item in left.by_ref() {
            let Some(loc) = self.locate_item(item) else {
                out.gone.push(item);
                continue;
            };
            if let Err(e) = self.put_new_key(loc).await {
                out.failed = Some(format!("changing the key of item {item}: {e}"));
                out.pending.push(item);
                break;
            }
            if let Err(e) = self.sync().await {
                out.failed = Some(format!(
                    "the key of item {item} changed on the server, but this device could not sync it afterwards: {e}"
                ));
                out.unconfirmed.push(item);
                break;
            }
            out.done.push(item);
        }
        out.pending.extend(left);
        out
    }

    /// The names of the active agents other than `except` whose grant
    /// names one of `items` as a per-item credential.
    pub(crate) async fn holders_of(
        &mut self,
        items: &[ItemId],
        except: Option<AgentId>,
    ) -> ClientResult<Vec<String>> {
        Ok(self
            .agents()
            .await?
            .into_iter()
            .filter(|a| {
                Some(a.id) != except
                    && a.status == AgentStatus::Active
                    && a.grant
                        .as_ref()
                        .is_some_and(|g| g.items.iter().any(|i| items.contains(&i.item_id)))
            })
            .map(|a| a.name)
            .collect())
    }

    /// Gives an item a new key (ADR 0036 §18): its sections sealed again
    /// as the next version and every attachment key wrapped again, in one
    /// write. Older versions keep their own wrapped keys. A write that
    /// races with another one is tried again once after a sync.
    pub async fn rekey_item(&mut self, loc: ItemLocation) -> ClientResult<()> {
        self.put_new_key(loc).await?;
        self.sync().await?;
        Ok(())
    }

    /// The write of [`Self::rekey_item`], without the sync after it: once
    /// this returns `Ok`, the server has the new key.
    async fn put_new_key(&mut self, loc: ItemLocation) -> ClientResult<()> {
        self.writable(loc.vault)?;
        let mut retried = false;
        loop {
            let body = self.rekeyed_version(loc)?;
            let res: ClientResult<WireItem> = self
                .send_json(
                    Method::PUT,
                    &format!("/v1/vaults/{}/items/{}", loc.vault, loc.item),
                    &body,
                )
                .await;
            match res {
                Ok(_) => break,
                Err(ClientError::Conflict(_) | ClientError::Api { status: 409, .. })
                    if !retried =>
                {
                    retried = true;
                    self.sync().await?;
                }
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// The next version of `loc` under a fresh item key.
    fn rekeyed_version(&self, loc: ItemLocation) -> ClientResult<UpdateItem> {
        // An item in the trash gets a new key too and stays in the trash
        // (the server takes this one write there): a restore later must not
        // hand a revoked holder an item it can open.
        let (ctx, old_key, wire) = self.item_parts(loc)?;
        let item = self.open_item(loc)?;
        let version = wire
            .version
            .checked_add(1)
            .ok_or_else(|| ClientError::Corrupt(format!("item {}: version overflow", loc.item)))?;
        let project = self
            .projects
            .get(&ctx.project)
            .ok_or_else(|| ClientError::NotFound(format!("project {}", ctx.project)))?;
        let project_version = project.version;
        let new_key = ItemKey::generate();
        let wrapped = wrap_item_key(&project.key, &ctx, &new_key);
        let mut attachment_keys = Vec::new();
        for (id, attachment) in self.item_attachments(loc.vault, loc.item) {
            let actx = AttachmentContext {
                account: ctx.account,
                vault: ctx.vault,
                project: ctx.project,
                item: ctx.item,
                attachment: id,
            };
            let blob = attachment
                .wrapped_key
                .as_ref()
                .ok_or_else(|| ClientError::Corrupt(format!("attachment {id} without key")))?;
            let key = unwrap_attachment_key(&old_key, &actx, blob.as_bytes())?;
            attachment_keys.push(RewrappedAttachmentKey {
                attachment_id: id,
                wrapped_key: Blob::new(wrap_attachment_key(&new_key, &actx, &key)),
            });
        }
        let sealed = seal_item(&new_key, &ctx, version, &item);
        Ok(UpdateItem {
            version,
            wrapped_key: Blob::new(wrapped),
            project_version,
            overview: Blob::new(sealed.overview),
            details: Blob::new(sealed.details),
            attachment_keys: Some(attachment_keys),
        })
    }

    /// Re-issues the grant of every active agent that holds one of
    /// `projects` or `items`, with the current keys and everything else as
    /// signed ([`Self::reissue_grant`]). Only agents whose current grant
    /// this account signed are touched: the person already approved their
    /// keys.
    ///
    /// An agent this device revoked (the one being revoked included) is
    /// never re-granted, even if the server reports it active: a server
    /// that "un-revokes" an agent does not get it the new keys.
    pub(crate) async fn regrant_agents(
        &mut self,
        projects: &[ProjectId],
        items: &[ItemId],
        except: Option<AgentId>,
    ) -> ClientResult<Regrants> {
        let projects: BTreeSet<ProjectId> = projects.iter().copied().collect();
        let items: BTreeSet<ItemId> = items.iter().copied().collect();
        let res = self.authed(Method::GET, "/v1/agents", &Body::Empty).await?;
        let list: klav_proto::agent::AgentList = crate::api::json(res).await?;
        let mut out = Regrants::default();
        for info in list.agents {
            if info.status != AgentStatus::Active
                || self.cache.revocations.contains_key(&info.id)
                || Some(info.id) == except
            {
                continue;
            }
            let Some(grant) = info.grant.clone() else {
                continue;
            };
            // One agent that fails does not stop the others: each keeps
            // working only with its new grant.
            match self.regrant_one(&info, &grant, &projects, &items).await {
                Ok(true) => out.done.push(info.name),
                Ok(false) => {}
                Err(e) => out.failed.push(format!("{}: {e}", info.name)),
            }
        }
        Ok(out)
    }

    /// Re-issues the grant of `info` if it holds one of `projects` or
    /// `items` (`true`), else leaves it (`false`).
    async fn regrant_one(
        &mut self,
        info: &klav_proto::agent::AgentInfo,
        grant: &klav_proto::agent::SignedGrant,
        projects: &BTreeSet<ProjectId>,
        items: &BTreeSet<ItemId>,
    ) -> ClientResult<bool> {
        let public = PublicIdentity::decode(info.public_identity.as_bytes())?;
        let payload = self.open_grant(info.id, &public, grant)?;
        let holds = payload
            .projects
            .iter()
            .any(|p| projects.contains(&p.project_id))
            || payload.items.iter().any(|i| items.contains(&i.item_id));
        if !holds {
            return Ok(false);
        }
        self.reissue_grant(info.id, &public, payload).await?;
        Ok(true)
    }
}

/// What the person's client checks before signing a grant (the server
/// checks it again).
fn check_payload(payload: &GrantPayload) -> ClientResult<()> {
    payload
        .policy
        .check_grantable()
        .map_err(|e| ClientError::Invalid(e.to_string()))?;
    payload.check_format().map_err(ClientError::Invalid)
}
