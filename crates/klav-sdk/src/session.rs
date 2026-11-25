//! An approved agent at work: its grant opened, the items it may list, and
//! the policy checked here **and** on the server for every use (ADR 0014
//! §4).
//!
//! Item details (where secrets live) only arrive through
//! `POST /v1/agent/access`, one item at a time, after the policy allows the
//! action; this runtime then decrypts them with the project key from the
//! grant. The values stay in zeroizing types: what leaves this module is an
//! action (fill, inject, a TOTP code) unless the policy allows `reveal`.

use std::collections::HashMap;
use std::time::Duration;

use klav_client::{ClientError, ClientResult};
use klav_core::crypto::agent::{ApprovalToSign, verify_approval};
use klav_core::crypto::attachment::{
    HEADER_LEN, MIN_CHUNK_SIZE, TAG_LEN, decrypt_attachment_bytes,
};
use klav_core::crypto::context::{AttachmentContext, ItemContext};
use klav_core::crypto::sign::{SIGNATURE_LEN, Signature};
use klav_core::crypto::wrap::{unwrap_attachment_key, unwrap_item_key};
use klav_core::ids::{ApprovalId, AttachmentId, ItemId, ProjectId, TaskId, VaultId};
use klav_core::model::item::{FieldKind, FieldValue, ItemKind, Overview};
use klav_core::model::{
    Catalog, Item, Named, Reference, SealedItem, SecretValue, open_item, open_overview,
    open_project_meta, resolve_field,
};
use klav_core::policy::{self, Decision, Effect, Permission, Target};
use klav_core::totp::Totp;
use klav_proto::agent::{
    AccessGranted, AccessRequest, AgentItems, AgentStatus, ApprovalInfo, ApprovalRequest,
    ApprovalStatus, Claims, MAX_AGENT_ATTACHMENTS_BYTES, PendingApproval,
};
use reqwest::{Method, StatusCode};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::agent::{Agent, now_ms};
use crate::grant::OpenGrant;

/// An item as an agent may see it: metadata only.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ItemInfo {
    /// Item ID.
    pub id: ItemId,
    /// `klav://Vault/Project/Title`.
    pub reference: String,
    /// Vault name (from the grant).
    pub vault: String,
    /// Project name (from the grant).
    pub project: String,
    /// Item type.
    pub kind: ItemKind,
    /// Title.
    pub title: String,
    /// User name, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// URLs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub urls: Vec<String>,
    /// Tags.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// How many attached files it has (each in a `file` field, named as
    /// the person attached it; ADR 0016).
    #[serde(default, skip_serializing_if = "is_zero")]
    pub attachments: usize,
}

fn is_zero(n: &usize) -> bool {
    *n == 0
}

/// Result of asking to use an item.
pub enum Access {
    /// The item, decrypted.
    Granted(Box<Item>),
    /// The person has to decide first.
    Pending {
        /// Approval to wait for and retry with.
        approval_id: ApprovalId,
        /// Until when the person can decide (Unix ms).
        expires_at: i64,
    },
}

#[derive(Clone)]
pub(crate) struct Entry {
    pub(crate) vault: VaultId,
    pub(crate) project: ProjectId,
    pub(crate) version: u64,
    pub(crate) wrapped_key: Vec<u8>,
    pub(crate) overview: Overview,
    /// Its attachments, as listed (metadata only).
    pub(crate) attachments: Vec<AttachmentId>,
}

/// Decrypted attachments of an item, by ID.
pub type Files = HashMap<AttachmentId, Zeroizing<Vec<u8>>>;

/// What [`Session::access_inner`] got.
enum Got {
    Granted(Box<Item>, Files),
    Pending(ApprovalId, i64),
}

/// An approval the caller named for its next action (ADR 0015 §3): the
/// action checks it is for what it does before doing anything, and only
/// the matching request carries it to the server.
#[derive(Debug, Clone)]
pub struct Claim {
    /// The approval.
    pub id: ApprovalId,
    /// What it was asked for.
    pub permission: Permission,
    /// The project.
    pub project: ProjectId,
    /// The item (`None` for `create`).
    pub item: Option<ItemId>,
    /// The site, for `fill`.
    pub domain: Option<String>,
    /// Already sent with a request of this action.
    pub used: bool,
}

/// An approved agent with its grant open.
pub struct Session {
    pub(crate) agent: Agent,
    pub(crate) grant: OpenGrant,
    pub(crate) items: HashMap<ItemId, Entry>,
    /// Current version of each granted project whose key is the one in the
    /// grant (its metadata opened with it): what writes send as
    /// `project_version`. A project whose key rotated after the grant is
    /// missing, and nothing is written to it.
    pub(crate) project_versions: HashMap<ProjectId, u64>,
    /// Normalized Git repositories (`host/owner/repo`) linked to each granted
    /// project, read from its decrypted project metadata (ADR 0032 §2).
    pub(crate) project_repos: HashMap<ProjectId, Vec<String>>,
    pub(crate) claim: Option<Claim>,
    /// Running tasks, with their decision verified (ADR 0021).
    pub(crate) tasks: Vec<crate::tasks::LiveTask>,
    /// The task the caller named for its next action (`task_id`).
    pub(crate) task: Option<klav_core::ids::TaskId>,
    /// Text values this session already wrote to files (`inject_file`):
    /// a later `run` redacts them too (ADR 0030 §2).
    pub(crate) injected: Vec<Zeroizing<String>>,
    /// For each item read, the URLs of the version delivered whose site the
    /// person confirmed (ADR 0030 §7): those an agent added and she has not
    /// confirmed are left out. Only these are filled.
    pub(crate) confirmed: HashMap<ItemId, Vec<String>>,
}

/// How many injected values a session remembers for redaction.
const MAX_REMEMBERED: usize = 256;

/// How long an approve-once decision serves after the person took it (ADR
/// 0015 §2). The server applies it too; the runtime checks it on the
/// signed `decided_at` so an old approval never serves because the server
/// says so (ADR 0030 §3).
pub const ONCE_WINDOW_MS: i64 = 10 * 60 * 1000;

/// What an action is, to match it with an approval or a task.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ActionTarget<'a> {
    pub(crate) permission: Permission,
    pub(crate) vault: VaultId,
    pub(crate) project: ProjectId,
    pub(crate) item: Option<ItemId>,
    pub(crate) domain: Option<&'a str>,
}

/// Whether an approved decision still serves at `now`: a lease that has
/// not ended, or an approve-once decision taken less than
/// [`ONCE_WINDOW_MS`] ago and (unless `spent_ok`, when this runtime's own
/// request just spent it) not used yet. Both times are signed.
pub(crate) fn approval_window(
    lease_until: i64,
    decided_at: i64,
    used: bool,
    now: i64,
    spent_ok: bool,
) -> Result<(), &'static str> {
    if lease_until != 0 {
        return if lease_until > now {
            Ok(())
        } else {
            Err("its lease ended")
        };
    }
    if used && !spent_ok {
        return Err("it was approved once and is already used");
    }
    if decided_at <= now.saturating_sub(ONCE_WINDOW_MS) {
        return Err("it was approved once more than 10 minutes ago");
    }
    Ok(())
}

pub(crate) fn now_secs() -> u64 {
    u64::try_from(now_ms() / 1000).unwrap_or(0)
}

impl Session {
    /// Checks the agent is active and not paused, verifies its grant and
    /// loads the items it may list. A paused agent gets
    /// [`ClientError::Paused`] (ADR 0033 §7.4), and one whose account waits
    /// to be deleted [`ClientError::AccountDeleting`] (ADR 0037 §3).
    pub async fn open(mut agent: Agent) -> ClientResult<Self> {
        let me = agent.me().await?;
        if me.status != AgentStatus::Active {
            return Err(ClientError::Denied(format!(
                "agent {} is {}: {}",
                agent.name(),
                me.status.as_str(),
                match me.status {
                    AgentStatus::Pending =>
                        "the person has not approved it yet (`klav agent approve` on their device, or `klav proxy issuer add` for an agent that starts sandboxes)",
                    AgentStatus::Revoked => "it was revoked; register a new agent",
                    _ => "register it again",
                }
            )));
        }
        if let Some(paused) = me.paused {
            return Err(ClientError::Paused(Some(paused)));
        }
        // The person asked to delete the account (ADR 0037 §3): every
        // other request would be refused with the same.
        if let Some(at) = me.account_delete_at {
            return Err(ClientError::AccountDeleting(Some(at)));
        }
        let grant = agent.verify_grant(&me)?;
        let mut session = Self {
            agent,
            grant,
            items: HashMap::new(),
            project_versions: HashMap::new(),
            project_repos: HashMap::new(),
            claim: None,
            tasks: Vec::new(),
            task: None,
            injected: Vec::new(),
            confirmed: HashMap::new(),
        };
        session.refresh().await?;
        Ok(session)
    }

    /// Remembers values written to a file in this session, so a later
    /// `run` redacts them from its output.
    pub(crate) fn remember_injected<'a>(&mut self, values: impl IntoIterator<Item = &'a str>) {
        for value in values {
            if value.is_empty() || self.injected.iter().any(|v| v.as_str() == value) {
                continue;
            }
            if self.injected.len() >= MAX_REMEMBERED {
                self.injected.remove(0);
            }
            self.injected.push(Zeroizing::new(value.to_owned()));
        }
    }

    /// Values this session wrote to files (see [`Self::remember_injected`]).
    pub(crate) fn injected(&self) -> impl Iterator<Item = &str> {
        self.injected.iter().map(|v| v.as_str())
    }

    /// The agent.
    pub fn agent(&self) -> &Agent {
        &self.agent
    }

    /// The opened grant.
    pub fn grant(&self) -> &OpenGrant {
        &self.grant
    }

    /// Reloads the item list. If the person issued a newer grant (after a
    /// key rotation, for instance), verifies it and uses its keys.
    pub async fn refresh(&mut self) -> ClientResult<()> {
        let mut list: AgentItems = self
            .agent
            .call::<(), _>(Method::GET, "/v1/agent/items", None)
            .await?;
        if list.grant_version > self.grant.payload.version {
            let me = self.agent.me().await?;
            let grant = self.agent.verify_grant(&me)?;
            if grant.payload.version > self.grant.payload.version {
                self.grant = grant;
                list = self
                    .agent
                    .call::<(), _>(Method::GET, "/v1/agent/items", None)
                    .await?;
            }
        }
        let mut items = HashMap::new();
        let mut project_versions = HashMap::new();
        let mut project_repos = HashMap::new();
        for mut project in list.projects {
            let attachments = std::mem::take(&mut project.attachments);
            let Some(granted) = self.grant.keys.get(&project.project_id) else {
                continue;
            };
            if granted.ctx.vault != project.vault_id {
                return Err(ClientError::Security(
                    "the server listed a project in another vault than the grant".into(),
                ));
            }
            // The version goes in the AAD of the metadata: it opens only
            // with this key at this version, so a write never claims the
            // current version with a key the person already rotated.
            if let Ok(meta) = open_project_meta(
                &granted.key,
                &granted.ctx,
                project.project_version,
                project.project_meta.as_bytes(),
            ) {
                project_versions.insert(project.project_id, project.project_version);
                if !meta.repos().is_empty() {
                    project_repos.insert(project.project_id, meta.repos().to_vec());
                }
            }
            for wire in project.items {
                if wire.project_id != project.project_id || wire.vault_id != project.vault_id {
                    return Err(ClientError::Security(
                        "the server listed an item outside its project".into(),
                    ));
                }
                let (Some(wrapped), Some(overview)) = (&wire.wrapped_key, &wire.overview) else {
                    continue;
                };
                // Never back to an older version than this session already
                // saw (T7 in the agent, ADR 0030 §3): the copy it has stays.
                if let Some(seen) = self.items.get(&wire.id)
                    && seen.version > wire.version
                    && seen.project == wire.project_id
                {
                    items.insert(wire.id, seen.clone());
                    continue;
                }
                let ctx = item_ctx(&granted.ctx, wire.id);
                // An item that does not open is skipped, never shown half
                // decrypted (it may have been tampered with).
                let Ok(key) = unwrap_item_key(&granted.key, &ctx, wrapped.as_bytes()) else {
                    continue;
                };
                let Ok(overview) = open_overview(&key, &ctx, wire.version, overview.as_bytes())
                else {
                    continue;
                };
                items.insert(
                    wire.id,
                    Entry {
                        vault: wire.vault_id,
                        project: wire.project_id,
                        version: wire.version,
                        wrapped_key: wrapped.as_bytes().to_vec(),
                        overview,
                        attachments: attachments
                            .iter()
                            .filter(|a| a.item_id == wire.id && a.vault_id == wire.vault_id)
                            .map(|a| a.id)
                            .collect(),
                    },
                );
            }
        }
        self.items = items;
        self.project_versions = project_versions;
        self.project_repos = project_repos;
        self.load_tasks().await
    }

    /// Granted `(vault_name, project_name)` pairs linked to `normalized_repo`
    /// (ADR 0032 §2). Strictly scoped to projects already in this agent's
    /// signed grant (T125): never reveals or grants access to other projects.
    pub fn projects_for_repo(&self, normalized_repo: &str) -> Vec<(String, String)> {
        let mut out: Vec<(String, String)> = self
            .project_repos
            .iter()
            .filter(|(_, repos)| repos.iter().any(|r| r == normalized_repo))
            .filter_map(|(id, _)| {
                let g = self.grant.keys.get(id)?;
                Some((g.labels.vault.clone(), g.labels.project.clone()))
            })
            .collect();
        out.sort_by(|a, b| {
            (a.0.to_lowercase(), a.1.to_lowercase()).cmp(&(b.0.to_lowercase(), b.1.to_lowercase()))
        });
        out
    }

    /// The `project_version` to write to `project` with the key of the
    /// grant (see [`Self::project_versions`]).
    pub(crate) fn project_version(&self, project: ProjectId) -> ClientResult<u64> {
        self.project_versions.get(&project).copied().ok_or_else(|| {
            ClientError::Denied(
                "the key of this project changed after the agent's grant: the person must \
                 re-approve the agent (a revocation with --rotate re-issues the grants)"
                    .into(),
            )
        })
    }

    pub(crate) fn names(&self, project: ProjectId) -> (String, String) {
        self.grant.keys.get(&project).map_or_else(
            || (String::new(), String::new()),
            |g| (g.labels.vault.clone(), g.labels.project.clone()),
        )
    }

    /// The exact policy decision for `permission` on `item` (with its real
    /// tags) and `domain`.
    pub fn evaluate(&self, item: ItemId, permission: Permission, domain: Option<&str>) -> Decision {
        let Some(e) = self.items.get(&item) else {
            return Decision {
                effect: Effect::Deny,
                reason: policy::Reason::OutOfScope,
            };
        };
        self.evaluate_entry(e, permission, domain, &e.overview.tags)
    }

    /// [`Self::evaluate`] with `tags` instead of the listed ones (the tags
    /// of the version actually delivered, or the ones after a patch).
    pub(crate) fn evaluate_entry(
        &self,
        e: &Entry,
        permission: Permission,
        domain: Option<&str>,
        tags: &[String],
    ) -> Decision {
        let (vault, project) = self.names(e.project);
        policy::evaluate(
            &self.grant.payload.policy,
            &policy::Request {
                permission,
                vault: Target {
                    id: e.vault,
                    name: vault,
                },
                project: Target {
                    id: e.project,
                    name: project,
                },
                tags: tags.to_vec(),
                domain: domain.map(str::to_owned),
                // Items, methods and paths only appear in proxy rules
                // (ADR 0036 §2), which this path never evaluates: left
                // out, such a rule does not match.
                item: None,
                method: None,
                path: None,
                now: now_secs(),
            },
        )
    }

    /// Whether the policy lets the agent list `item` (see it at all): an
    /// item it may not list is never named, described or matched by a
    /// reference.
    pub(crate) fn listable(&self, item: ItemId) -> bool {
        self.evaluate(item, Permission::List, None).effect == Effect::Allow
    }

    /// The effect of a permission in a project for a new item with `tags`
    /// (for `create`).
    pub fn evaluate_in(
        &self,
        project: ProjectId,
        permission: Permission,
        tags: &[String],
    ) -> ClientResult<(VaultId, Decision)> {
        let granted = self
            .grant
            .keys
            .get(&project)
            .ok_or_else(|| ClientError::NotFound(format!("project {project} in the grant")))?;
        let decision = policy::evaluate(
            &self.grant.payload.policy,
            &policy::Request {
                permission,
                vault: Target {
                    id: granted.ctx.vault,
                    name: granted.labels.vault.clone(),
                },
                project: Target {
                    id: project,
                    name: granted.labels.project.clone(),
                },
                tags: tags.to_vec(),
                domain: None,
                item: None,
                method: None,
                path: None,
                now: now_secs(),
            },
        );
        Ok((granted.ctx.vault, decision))
    }

    pub(crate) fn info(&self, id: ItemId, e: &Entry) -> ItemInfo {
        let (vault, project) = self.names(e.project);
        let reference = Reference {
            vault: klav_core::model::Selector::Name(vault.clone()),
            project: klav_core::model::Selector::Name(project.clone()),
            item: klav_core::model::Selector::Name(e.overview.title.clone()),
            field: klav_core::model::Selector::Name("x".into()),
        }
        .to_string();
        // Drop only the placeholder field: an item titled `x` keeps its own.
        let reference = reference
            .strip_suffix("/x")
            .unwrap_or(&reference)
            .to_owned();
        ItemInfo {
            id,
            reference,
            vault,
            project,
            kind: e.overview.kind,
            title: e.overview.title.clone(),
            username: e.overview.username.clone(),
            urls: e.overview.urls.clone(),
            tags: e.overview.tags.clone(),
            attachments: e.attachments.len(),
        }
    }

    /// Items the policy lets the agent list, optionally only in `scope`
    /// (`(vault, project)` names, from `klav.toml`) and matching `query`
    /// (title, user name, URL or tag).
    pub fn items(&self, scope: Option<(&str, &str)>, query: Option<&str>) -> Vec<ItemInfo> {
        let query = query.map(str::to_lowercase);
        let mut out: Vec<ItemInfo> = self
            .items
            .iter()
            .filter(|(id, _)| self.listable(**id))
            .map(|(id, e)| self.info(*id, e))
            .filter(|i| {
                scope.is_none_or(|(v, p)| {
                    i.vault.eq_ignore_ascii_case(v) && i.project.eq_ignore_ascii_case(p)
                })
            })
            .filter(|i| {
                query.as_deref().is_none_or(|q| {
                    i.title.to_lowercase().contains(q)
                        || i.username
                            .as_deref()
                            .is_some_and(|u| u.to_lowercase().contains(q))
                        || i.urls.iter().any(|u| u.to_lowercase().contains(q))
                        || i.tags.iter().any(|t| t.to_lowercase() == q)
                })
            })
            .collect();
        out.sort_by(|a, b| a.reference.cmp(&b.reference));
        out
    }

    /// Metadata of one item the agent may list.
    pub fn item_info(&self, item: ItemId) -> ClientResult<ItemInfo> {
        let e = self
            .items
            .get(&item)
            .filter(|_| self.listable(item))
            .ok_or_else(|| ClientError::NotFound(format!("item {item}")))?;
        Ok(self.info(item, e))
    }

    /// Resolves `klav://Vault/Project/Item[/field]`, or the short form
    /// `Item[/field]` inside `scope` (`klav.toml`'s `project`), to an item
    /// and the field name, if given.
    pub fn locate(
        &self,
        reference: &str,
        scope: Option<(&str, &str)>,
    ) -> ClientResult<(ItemId, Option<String>)> {
        let text = reference.trim();
        let scheme = klav_core::model::reference::SCHEME;
        let full = match (text.get(..scheme.len()), scope) {
            (Some(s), _) if s.eq_ignore_ascii_case(scheme) => text.to_owned(),
            (_, Some((vault, project))) => {
                format!("klav://{}/{}/{text}", encode(vault), encode(project))
            }
            (_, None) => {
                return Err(ClientError::Invalid(format!(
                    "{text:?} is not a klav:// reference (short references need `project` in klav.toml)"
                )));
            }
        };
        let segments = full["klav://".len()..].split('/').count();
        let (parsed, has_field) = if segments == 3 {
            (Reference::parse(&format!("{full}/x"))?, false)
        } else {
            (Reference::parse(&full)?, true)
        };
        let resolved = parsed.resolve(self)?;
        let field = has_field.then(|| match &resolved.field {
            klav_core::model::Selector::Name(n) => n.clone(),
            klav_core::model::Selector::Id(id) => id.to_string(),
        });
        if let Some((vault, project)) = scope {
            let info = self.item_info(resolved.item)?;
            if !info.vault.eq_ignore_ascii_case(vault)
                || !info.project.eq_ignore_ascii_case(project)
            {
                return Err(ClientError::Denied(format!(
                    "{text} is outside the project of klav.toml ({vault}/{project})"
                )));
            }
        }
        Ok((resolved.item, field))
    }

    /// Asks to use `item` for `permission`: checks the policy here, then on
    /// the server, and decrypts the details if both allow it.
    pub async fn access(
        &mut self,
        item: ItemId,
        permission: Permission,
        reason: &str,
        domain: Option<&str>,
        approval_id: Option<ApprovalId>,
    ) -> ClientResult<Access> {
        Ok(
            match self
                .access_inner(item, permission, reason, domain, approval_id, false)
                .await?
            {
                Got::Granted(item, _) => Access::Granted(item),
                Got::Pending(approval_id, expires_at) => Access::Pending {
                    approval_id,
                    expires_at,
                },
            },
        )
    }

    /// [`Session::access`], also asking for the item's attachments when
    /// `with_files` (only with `inject`, ADR 0016): they come in the same
    /// answer, under the same decision, and are decrypted here.
    async fn access_inner(
        &mut self,
        item: ItemId,
        permission: Permission,
        reason: &str,
        domain: Option<&str>,
        approval_id: Option<ApprovalId>,
        with_files: bool,
    ) -> ClientResult<Got> {
        if reason.trim().is_empty() {
            return Err(ClientError::Invalid(
                "a reason is mandatory: say why the agent needs this".into(),
            ));
        }
        crate::text::check_declared("reason", reason)?;
        if let Some(domain) = domain {
            crate::text::check_declared("domain", domain)?;
        }
        // Evaluated here too (with the real tags), but the request still
        // goes to the server so that a denial is logged (and alerts).
        let decision = self.evaluate(item, permission, domain);
        let local_denial = || {
            ClientError::Denied(format!(
                "the policy denies `{}` on this item{}",
                permission_name(permission),
                domain.map(|d| format!(" for {d}")).unwrap_or_default()
            ))
        };
        let entry = self
            .items
            .get(&item)
            .ok_or_else(|| ClientError::NotFound(format!("item {item}")))?;
        let target = ActionTarget {
            permission,
            vault: entry.vault,
            project: entry.project,
            item: Some(item),
            domain,
        };
        let task_id = self.task_for(item, permission, domain);
        let body = AccessRequest {
            item_id: item,
            permission,
            reason: reason.trim().to_owned(),
            claims: Claims {
                tags: entry.overview.tags.clone(),
                domain: domain.map(str::to_owned),
                ..Claims::default()
            },
            approval_id,
            task_id,
            include_attachments: with_files,
            sandbox: None,
        };
        let bytes =
            serde_json::to_vec(&body).map_err(|e| ClientError::Invalid(format!("request: {e}")))?;
        let res = self
            .agent
            .send(Method::POST, "/v1/agent/access", Some(&bytes))
            .await?;
        match res.status() {
            StatusCode::ACCEPTED => {
                let p: PendingApproval = klav_client::api::json(res).await?;
                Ok(Got::Pending(p.pending_approval_id, p.expires_at))
            }
            StatusCode::FORBIDDEN => Err(forbidden(res).await),
            _ if decision.effect == Effect::Deny => {
                drop(res);
                Err(local_denial())
            }
            _ => {
                let granted: AccessGranted = klav_client::api::json(res).await?;
                // The policy here says `ask`: the server must have used an
                // approval this runtime verifies, or a verified task
                // (ADR 0030 §3), before anything is decrypted.
                if decision.effect == Effect::Ask {
                    self.backed(&target, approval_id, granted.approval_id, task_id)
                        .await?;
                }
                let opened = self.decrypt(item, &granted)?;
                // The policy again, with the tags of the version delivered
                // (the listed one may be older): never more than it allows.
                let entry = self
                    .items
                    .get(&item)
                    .ok_or_else(|| ClientError::NotFound(format!("item {item}")))?;
                let real = self.evaluate_entry(entry, permission, domain, opened.tags());
                if real.effect == Effect::Deny {
                    return Err(local_denial());
                }
                if real.effect > decision.effect {
                    self.backed(&target, approval_id, granted.approval_id, task_id)
                        .await?;
                }
                let files = if with_files {
                    self.decrypt_files(item, &granted, &opened)?
                } else {
                    Files::new()
                };
                let confirmed = self.confirmed_of(item, &granted, &opened);
                self.confirmed.insert(item, confirmed);
                // Remember the version read (for a following update), and
                // what it really says (title, tags and URLs).
                if let Some(entry) = self.items.get_mut(&item) {
                    entry.version = granted.item.version;
                    if let Some(key) = &granted.item.wrapped_key {
                        entry.wrapped_key = key.as_bytes().to_vec();
                    }
                    entry.overview = opened.overview();
                }
                Ok(Got::Granted(Box::new(opened), files))
            }
        }
    }

    /// Decrypts the attachments delivered with `granted`: each must belong
    /// to `item`, be one the decrypted item lists, be no larger than its
    /// authenticated size allows, and open with a key wrapped by the item
    /// key (the project key from the grant opens that one).
    fn decrypt_files(
        &self,
        item: ItemId,
        granted: &AccessGranted,
        opened: &Item,
    ) -> ClientResult<Files> {
        let mut files = Files::new();
        if granted.attachments.is_empty() {
            return Ok(files);
        }
        let total: u64 = granted
            .attachments
            .iter()
            .map(|a| a.content.as_bytes().len() as u64)
            .sum();
        if total > MAX_AGENT_ATTACHMENTS_BYTES {
            return Err(ClientError::Security(
                "the server delivered more than 16 MiB of attachments".into(),
            ));
        }
        let entry = self
            .items
            .get(&item)
            .ok_or_else(|| ClientError::NotFound(format!("item {item}")))?;
        let granted_key = self
            .grant
            .keys
            .get(&entry.project)
            .ok_or_else(|| ClientError::NotFound("project key".into()))?;
        let ctx = item_ctx(&granted_key.ctx, item);
        let wrapped = granted
            .item
            .wrapped_key
            .as_ref()
            .map_or(entry.wrapped_key.as_slice(), |b| b.as_bytes());
        let item_key = unwrap_item_key(&granted_key.key, &ctx, wrapped)?;
        for delivered in &granted.attachments {
            let meta = &delivered.attachment;
            if meta.item_id != item || meta.vault_id != entry.vault {
                return Err(ClientError::Security(
                    "the server returned an attachment of another item".into(),
                ));
            }
            // The size that counts is the one sealed in the item, not the
            // one the server lists.
            let authentic = opened
                .attachments()
                .iter()
                .find(|a| a.id == meta.id)
                .ok_or_else(|| {
                    ClientError::Security(format!(
                        "the server delivered attachment {} that the item does not list",
                        meta.id
                    ))
                })?
                .size;
            let received = delivered.content.as_bytes().len() as u64;
            if received != meta.size || received > ciphertext_bound(authentic) {
                return Err(ClientError::Corrupt(format!(
                    "attachment {}: {received} bytes received for a {authentic}-byte file",
                    meta.id,
                )));
            }
            let actx = AttachmentContext {
                account: ctx.account,
                vault: ctx.vault,
                project: ctx.project,
                item,
                attachment: meta.id,
            };
            let wrapped = meta.wrapped_key.as_ref().ok_or_else(|| {
                ClientError::Corrupt(format!("attachment {} without key", meta.id))
            })?;
            let key = unwrap_attachment_key(&item_key, &actx, wrapped.as_bytes())?;
            let plain = decrypt_attachment_bytes(&key, &actx, delivered.content.as_bytes())?;
            if plain.len() as u64 != authentic {
                return Err(ClientError::Corrupt(format!(
                    "attachment {}: {} bytes instead of {authentic}",
                    meta.id,
                    plain.len()
                )));
            }
            files.insert(meta.id, plain);
        }
        Ok(files)
    }

    /// The URLs of `opened` this runtime may fill (ADR 0030 §7): all of
    /// them if the person wrote the current version, or if this agent wrote
    /// every version and she none (`sole_author`: the item it created, ADR
    /// 0022 §7; no secret of hers is in it). With another agent as the
    /// author, those whose host is among the URLs of her last version
    /// (`person_version`, opened with the project key; none if missing or
    /// if it does not open).
    fn confirmed_of(&self, item: ItemId, granted: &AccessGranted, opened: &Item) -> Vec<String> {
        let author = granted.item.author_agent_id;
        if author.is_none()
            || (granted.sole_author
                && author == Some(self.agent().id())
                && granted.person_version.is_none())
        {
            return opened.urls().to_vec();
        }
        let person = (|| -> Option<Vec<String>> {
            let found = granted.person_version.as_ref()?;
            let entry = self.items.get(&item)?;
            let granted_key = self.grant.keys.get(&entry.project)?;
            let ctx: ItemContext = item_ctx(&granted_key.ctx, item);
            let key = unwrap_item_key(&granted_key.key, &ctx, found.wrapped_key.as_bytes()).ok()?;
            open_overview(&key, &ctx, found.version, found.overview.as_bytes())
                .ok()
                .map(|o| o.urls)
        })()
        .unwrap_or_default();
        opened
            .urls()
            .iter()
            .filter(|u| {
                klav_core::site::item_host(u)
                    .is_some_and(|h| klav_core::site::host_matches(&h, &person))
            })
            .cloned()
            .collect()
    }

    /// The URLs of `item` whose site the person confirmed, as of the version
    /// this session last read (empty before the first read), or all of them
    /// on an item only this agent ever wrote. Only these are filled (ADR
    /// 0030 §7).
    pub fn confirmed_urls(&self, item: ItemId) -> &[String] {
        self.confirmed
            .get(&item)
            .map(Vec::as_slice)
            .unwrap_or_default()
    }

    /// Fails unless `host` is one of the sites of `item` the person
    /// confirmed (or of an item only this agent ever wrote), as of the
    /// version this session last read (ADR 0030 §7).
    pub(crate) fn check_confirmed(&self, item: ItemId, host: &str) -> ClientResult<()> {
        if klav_core::site::host_matches(host, self.confirmed_urls(item)) {
            return Ok(());
        }
        Err(ClientError::Denied(format!(
            "{host} was added to the item by an agent and the person has not confirmed it: Klav does not fill it until she does (phishing protection)"
        )))
    }

    fn decrypt(&self, item: ItemId, granted: &AccessGranted) -> ClientResult<Item> {
        let wire = &granted.item;
        if wire.id != item {
            return Err(ClientError::Security(
                "the server returned another item".into(),
            ));
        }
        let entry = self
            .items
            .get(&item)
            .ok_or_else(|| ClientError::NotFound(format!("item {item}")))?;
        if wire.project_id != entry.project || wire.vault_id != entry.vault {
            return Err(ClientError::Security(
                "the server moved the item to another project".into(),
            ));
        }
        let granted_key = self
            .grant
            .keys
            .get(&entry.project)
            .ok_or_else(|| ClientError::NotFound("project key".into()))?;
        let ctx: ItemContext = item_ctx(&granted_key.ctx, item);
        let wrapped = wire
            .wrapped_key
            .as_ref()
            .map_or(entry.wrapped_key.as_slice(), |b| b.as_bytes());
        let key = unwrap_item_key(&granted_key.key, &ctx, wrapped)?;
        let sealed = SealedItem {
            overview: wire
                .overview
                .as_ref()
                .ok_or_else(|| ClientError::Corrupt("item without overview".into()))?
                .as_bytes()
                .to_vec(),
            details: wire
                .details
                .as_ref()
                .ok_or_else(|| ClientError::Corrupt("item without details".into()))?
                .as_bytes()
                .to_vec(),
        };
        if wire.version < entry.version {
            return Err(ClientError::Rollback(format!(
                "item {item} went back from version {} to {}",
                entry.version, wire.version
            )));
        }
        Ok(open_item(&key, &ctx, wire.version, &sealed)?)
    }

    async fn approval_info(
        &self,
        approval: ApprovalId,
        wait: Duration,
    ) -> ClientResult<ApprovalInfo> {
        self.agent.approval(approval, wait).await
    }

    /// See [`Agent::wait_decision`].
    pub async fn wait_decision(
        &self,
        approval: ApprovalId,
        timeout: Duration,
    ) -> ClientResult<ApprovalInfo> {
        self.agent.wait_decision(approval, timeout).await
    }

    /// [`Session::wait_decision`], returning only the state.
    pub async fn wait_approval(
        &self,
        approval: ApprovalId,
        timeout: Duration,
    ) -> ClientResult<ApprovalStatus> {
        Ok(self.wait_decision(approval, timeout).await?.status)
    }

    /// Names an approval for the next action (MCP `approval_id`, `--approval`):
    /// it must be this agent's and still usable. The action then checks it
    /// is for what it does ([`Session::check_claim`]) before acting.
    pub async fn claim_approval(&mut self, id: ApprovalId) -> ClientResult<()> {
        let info = self.approval_info(id, Duration::ZERO).await?;
        let request = self.approval_request(id, &info)?;
        match info.status {
            ApprovalStatus::Denied => {
                return Err(ClientError::Denied(format!(
                    "the person denied approval {id}: do not retry it another way"
                )));
            }
            ApprovalStatus::Expired => {
                return Err(ClientError::Denied(format!(
                    "approval {id} expired without a decision: call the tool without approval_id to ask again"
                )));
            }
            ApprovalStatus::Approved => {
                self.check_approval(&info, false)?;
            }
            ApprovalStatus::Pending => {
                if info.expires_at <= now_ms() {
                    return Err(ClientError::Denied(format!(
                        "approval {id} expired without a decision: call the tool without approval_id to ask again"
                    )));
                }
            }
        }
        self.claim = Some(Claim {
            id,
            permission: request.permission,
            project: request.project_id,
            item: request.item_id,
            domain: request.claims.domain,
            used: false,
        });
        Ok(())
    }

    /// The request of approval `id` as `info` carries it, checked to be
    /// that approval of this agent.
    fn approval_request(
        &self,
        id: ApprovalId,
        info: &ApprovalInfo,
    ) -> ClientResult<ApprovalRequest> {
        let request: ApprovalRequest = serde_json::from_slice(info.request.as_bytes())
            .map_err(|_| ClientError::Corrupt("approval request".into()))?;
        if info.id != id
            || info.agent_id != self.agent.id()
            || request.approval_id != id
            || request.agent_id != self.agent.id()
        {
            return Err(ClientError::Security(
                "the server answered with another approval".into(),
            ));
        }
        Ok(request)
    }

    /// Checks an `Approved` decision (ADR 0030 §3): the account's signature
    /// with the identity this agent pinned (spec §13.5), and that it still
    /// serves ([`approval_window`]). A bad or missing signature is a
    /// [`ClientError::Security`]; a decision that no longer serves, an
    /// [`ClientError::Invalid`].
    pub(crate) fn check_approval(&self, info: &ApprovalInfo, spent_ok: bool) -> ClientResult<()> {
        let id = info.id;
        let forged = || {
            ClientError::Security(format!(
                "approval {id} is not signed by the account: the server let something through the person did not approve"
            ))
        };
        let signature: [u8; SIGNATURE_LEN] = info
            .signature
            .as_ref()
            .ok_or_else(forged)?
            .as_bytes()
            .try_into()
            .map_err(|_| forged())?;
        let decided_at = info.decided_at.ok_or_else(forged)?;
        let lease_until = info.lease_until.unwrap_or(0);
        verify_approval(
            &self.agent.account_identity()?,
            &ApprovalToSign {
                approval: id,
                agent: self.agent.id(),
                request: info.request.as_bytes(),
                approve: true,
                lease_until_ms: u64::try_from(lease_until).map_err(|_| forged())?,
                decided_at_ms: u64::try_from(decided_at).map_err(|_| forged())?,
            },
            &Signature::from_bytes(signature),
        )
        .map_err(|_| forged())?;
        approval_window(
            lease_until,
            decided_at,
            info.used_at.is_some(),
            now_ms(),
            spent_ok,
        )
        .map_err(|why| {
            ClientError::Invalid(format!(
                "approval {id} no longer serves ({why}): call the tool without approval_id to ask again"
            ))
        })
    }

    /// Waits up to `wait` for the person's decision on `id`; an approval is
    /// verified ([`Self::check_approval`]) before it is reported.
    pub(crate) async fn wait_verified(
        &self,
        id: ApprovalId,
        wait: Duration,
    ) -> ClientResult<ApprovalStatus> {
        let info = self.wait_decision(id, wait).await?;
        self.approval_request(id, &info)?;
        if info.status == ApprovalStatus::Approved {
            self.check_approval(&info, false)?;
        }
        Ok(info.status)
    }

    /// A `2xx` for `target` when the policy here says `ask` (ADR 0030 §3):
    /// it must come with an approval for exactly this action that the
    /// account signed and that still serves (`sent` is the one this runtime
    /// named; `returned` the one the server says it used), or else a
    /// running task this runtime verified that covers it. Otherwise the
    /// server let through what the policy asks the person about.
    pub(crate) async fn backed(
        &self,
        target: &ActionTarget<'_>,
        sent: Option<ApprovalId>,
        returned: Option<ApprovalId>,
        task: Option<TaskId>,
    ) -> ClientResult<()> {
        let name = permission_name(target.permission);
        if let (Some(sent), Some(returned)) = (sent, returned)
            && sent != returned
        {
            return Err(ClientError::Security(format!(
                "the server used another approval than {sent} for `{name}`"
            )));
        }
        if let Some(id) = returned.or(sent) {
            // This runtime's request just spent an approve-once decision.
            return self.approval_fits(target, id, true).await;
        }
        if self.task_covers(target, task) {
            return Ok(());
        }
        Err(ClientError::Security(format!(
            "the server let `{name}` through without an approval or task this runtime can verify, but the agent's policy asks the person: its answer is refused"
        )))
    }

    /// Approval `id` is approved for exactly `target`, signed by the account
    /// and still serves (`spent_ok`: this runtime's request just spent it).
    pub(crate) async fn approval_fits(
        &self,
        target: &ActionTarget<'_>,
        id: ApprovalId,
        spent_ok: bool,
    ) -> ClientResult<()> {
        let name = permission_name(target.permission);
        let info = self.approval_info(id, Duration::ZERO).await?;
        let request = self.approval_request(id, &info)?;
        if info.status != ApprovalStatus::Approved {
            return Err(ClientError::Security(format!(
                "the server let `{name}` through with approval {id}, which is not approved"
            )));
        }
        self.check_approval(&info, spent_ok).map_err(|e| match e {
            ClientError::Invalid(m) => ClientError::Security(format!(
                "the server let `{name}` through with an approval that no longer serves: {m}"
            )),
            other => other,
        })?;
        let fits = request.permission == target.permission
            && request.vault_id == target.vault
            && request.project_id == target.project
            && request.item_id == target.item
            && request
                .claims
                .domain
                .as_deref()
                .map(str::to_ascii_lowercase)
                == target.domain.map(str::to_ascii_lowercase);
        if !fits {
            return Err(ClientError::Security(format!(
                "the server let `{name}` through with approval {id}, which is for another action"
            )));
        }
        Ok(())
    }

    /// A running task this runtime verified covers `target` (with `task`,
    /// only that one). Actions without an item are never covered.
    pub(crate) fn task_covers(&self, target: &ActionTarget<'_>, task: Option<TaskId>) -> bool {
        let Some(item) = target.item else {
            return false;
        };
        let now = now_ms();
        self.tasks.iter().any(|t| {
            t.expires_at > now
                && task.is_none_or(|id| id == t.id)
                && t.decision.covers(
                    target.vault,
                    target.project,
                    item,
                    target.permission,
                    target.domain,
                )
        })
    }

    /// Forgets the named approval (after the action).
    pub fn release_claim(&mut self) -> Option<Claim> {
        self.claim.take()
    }

    /// Fails, before acting, if the named approval is not for this action:
    /// `permission` on one of `items`, or (with no items, for `create`) a
    /// new item in `project`.
    pub fn check_claim(
        &self,
        permission: Permission,
        items: &[ItemId],
        project: Option<ProjectId>,
    ) -> ClientResult<()> {
        let Some(claim) = &self.claim else {
            return Ok(());
        };
        let fits = claim.permission == permission
            && match (claim.item, items.is_empty()) {
                (Some(item), false) => items.contains(&item),
                (None, true) => project.is_some_and(|p| p == claim.project),
                _ => false,
            };
        if fits {
            return Ok(());
        }
        let on = claim
            .item
            .and_then(|i| self.item_info(i).ok())
            .map_or_else(|| "a new item".to_owned(), |i| i.reference);
        Err(ClientError::Invalid(format!(
            "approval_id {} is for `{}` on {on}, not for this action: nothing was done. Retry the action it was asked for, or call without approval_id",
            claim.id,
            permission_name(claim.permission)
        )))
    }

    /// The named approval if it is for this request and was not sent yet,
    /// after waiting up to `wait` for the person if it is still pending.
    pub(crate) async fn claimed(
        &mut self,
        item: Option<ItemId>,
        permission: Permission,
        domain: Option<&str>,
        wait: Duration,
    ) -> ClientResult<Option<ApprovalId>> {
        let Some(claim) = self.claim.clone() else {
            return Ok(None);
        };
        if claim.used || claim.permission != permission || claim.item != item {
            return Ok(None);
        }
        if claim.domain.as_deref().map(str::to_ascii_lowercase)
            != domain.map(str::to_ascii_lowercase)
        {
            return Err(ClientError::Invalid(format!(
                "approval_id {} is for {}, but this is {}: nothing was done",
                claim.id,
                claim.domain.as_deref().unwrap_or("no site"),
                domain.unwrap_or("no site")
            )));
        }
        // Checked again right before it is sent: the lease may have ended.
        let status = self.wait_verified(claim.id, wait).await?;
        match status {
            ApprovalStatus::Approved => {
                if let Some(c) = &mut self.claim {
                    c.used = true;
                }
                Ok(Some(claim.id))
            }
            ApprovalStatus::Pending => Err(pending(claim.id, permission)),
            ApprovalStatus::Denied => {
                Err(ClientError::Denied("the person denied the request".into()))
            }
            ApprovalStatus::Expired => Err(ClientError::Denied(
                "nobody approved the request in time".into(),
            )),
        }
    }

    /// [`Session::access`], waiting up to `wait` for the person when the
    /// policy says `ask`. Fails with [`ClientError::PendingApproval`] if
    /// nobody decides in time. A named approval for this request
    /// ([`Session::claim_approval`]) is used instead of asking.
    pub async fn access_waiting(
        &mut self,
        item: ItemId,
        permission: Permission,
        reason: &str,
        domain: Option<&str>,
        wait: Duration,
    ) -> ClientResult<Item> {
        Ok(self
            .access_waiting_inner(item, permission, reason, domain, wait, false)
            .await?
            .0)
    }

    /// [`Session::access_waiting`] for `inject`: the item and, if it has
    /// any, its attachments decrypted (ADR 0016), under one decision.
    pub async fn access_for_inject(
        &mut self,
        item: ItemId,
        reason: &str,
        wait: Duration,
    ) -> ClientResult<(Item, Files)> {
        let with_files = self
            .items
            .get(&item)
            .is_some_and(|e| !e.attachments.is_empty());
        self.access_waiting_inner(item, Permission::Inject, reason, None, wait, with_files)
            .await
    }

    async fn access_waiting_inner(
        &mut self,
        item: ItemId,
        permission: Permission,
        reason: &str,
        domain: Option<&str>,
        wait: Duration,
        with_files: bool,
    ) -> ClientResult<(Item, Files)> {
        if let Some(id) = self.claimed(Some(item), permission, domain, wait).await? {
            return match self
                .access_inner(item, permission, reason, domain, Some(id), with_files)
                .await?
            {
                Got::Granted(item, files) => Ok((*item, files)),
                Got::Pending(approval_id, _) => Err(pending(approval_id, permission)),
            };
        }
        match self
            .access_inner(item, permission, reason, domain, None, with_files)
            .await?
        {
            Got::Granted(item, files) => Ok((*item, files)),
            Got::Pending(approval_id, _) => {
                let status = if wait.is_zero() {
                    ApprovalStatus::Pending
                } else {
                    self.wait_verified(approval_id, wait).await?
                };
                match status {
                    ApprovalStatus::Approved => {
                        match self
                            .access_inner(
                                item,
                                permission,
                                reason,
                                domain,
                                Some(approval_id),
                                with_files,
                            )
                            .await?
                        {
                            Got::Granted(item, files) => Ok((*item, files)),
                            Got::Pending(approval_id, _) => Err(pending(approval_id, permission)),
                        }
                    }
                    ApprovalStatus::Pending => Err(pending(approval_id, permission)),
                    ApprovalStatus::Denied => {
                        Err(ClientError::Denied("the person denied the request".into()))
                    }
                    ApprovalStatus::Expired => Err(ClientError::Denied(
                        "nobody approved the request in time".into(),
                    )),
                }
            }
        }
    }

    /// The current TOTP code of `item` (first one-time password field, or
    /// `field`), and the seconds it is still valid.
    pub async fn totp(
        &mut self,
        item: ItemId,
        field: Option<&str>,
        reason: &str,
        wait: Duration,
    ) -> ClientResult<(SecretValue, u64)> {
        self.check_claim(Permission::Totp, &[item], None)?;
        let item = self
            .access_waiting(item, Permission::Totp, reason, None, wait)
            .await?;
        totp_code(&item, field)
    }
}

/// A `403` from the server: denied, with its message marked as the
/// server's word (it reaches the LLM).
pub(crate) async fn forbidden(res: reqwest::Response) -> ClientError {
    let message = match klav_client::api::json::<serde_json::Value>(res).await {
        // The person paused it (ADR 0033 §7.4): not a denial, exit 7.
        Err(ClientError::Paused(paused)) => return ClientError::Paused(paused),
        // The person asked to delete the account (ADR 0037 §3): exit 8.
        Err(ClientError::AccountDeleting(at)) => return ClientError::AccountDeleting(at),
        Err(ClientError::Api { message, .. }) => message,
        _ => "forbidden".to_owned(),
    };
    ClientError::Denied(format!(
        "the server refused it; {}",
        crate::text::untrusted(&message)
    ))
}

pub(crate) fn pending(approval_id: ApprovalId, permission: Permission) -> ClientError {
    ClientError::PendingApproval {
        id: approval_id,
        message: format!(
            "`{}` needs the person's approval: they approve it with `klav approval approve {approval_id}`; wait for it with `klav approval wait {approval_id}`, then retry with this approval (`--approval {approval_id}` or approval_id)",
            permission_name(permission)
        ),
    }
}

/// `list`, `fill`…
pub fn permission_name(permission: Permission) -> String {
    serde_json::to_value(permission)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default()
}

/// The value of a text field of `item` (`field` by name or ID).
pub fn field_value(item: &Item, field: &str) -> ClientResult<(FieldKind, SecretValue)> {
    let selector = match field.parse() {
        Ok(id) => klav_core::model::Selector::Id(id),
        Err(_) => klav_core::model::Selector::Name(field.to_owned()),
    };
    let f = resolve_field(item, &selector)?;
    let value = match f.value() {
        FieldValue::Plain(s) => SecretValue::new(s.clone()),
        FieldValue::Secret(s) => s.clone(),
        FieldValue::File(_) => {
            return Err(ClientError::Invalid(format!(
                "field {field:?} is an attachment: agents can only write it to a file (inject_file with `ref`, or `[files]` in klav.toml)"
            )));
        }
    };
    Ok((f.kind(), value))
}

/// The value of any field of `item` as bytes: text as UTF-8, an attachment
/// from `files` (delivered with an `inject`, ADR 0016). A one-time password
/// seed is refused: it would skip the `totp` permission (ADR 0030 §2, T26).
pub fn field_bytes(
    item: &Item,
    field: &str,
    files: &Files,
) -> ClientResult<(FieldKind, Zeroizing<Vec<u8>>)> {
    let selector = match field.parse() {
        Ok(id) => klav_core::model::Selector::Id(id),
        Err(_) => klav_core::model::Selector::Name(field.to_owned()),
    };
    let f = resolve_field(item, &selector)?;
    if f.kind() == FieldKind::Totp {
        return Err(ClientError::Denied(format!(
            "field {field:?} is a one-time password seed: it is never injected. Ask for the current code with get_totp (or `klav agent totp`), which goes through the `totp` permission"
        )));
    }
    let value = match f.value() {
        FieldValue::Plain(s) => Zeroizing::new(s.as_bytes().to_vec()),
        FieldValue::Secret(s) => Zeroizing::new(s.expose().as_bytes().to_vec()),
        FieldValue::File(id) => files.get(id).cloned().ok_or_else(|| {
            ClientError::NotFound(format!(
                "the attachment of field {field:?} (the server did not deliver it)"
            ))
        })?,
    };
    Ok((f.kind(), value))
}

/// The TOTP code of `item`, from a one-time password field only: any other
/// secret used as a seed would turn `totp` into an oracle on it.
pub fn totp_code(item: &Item, field: Option<&str>) -> ClientResult<(SecretValue, u64)> {
    let f = match field {
        Some(name) => item
            .field(name)
            .filter(|f| f.kind() == FieldKind::Totp)
            .ok_or_else(|| ClientError::NotFound(format!("a one-time password field {name:?}")))?,
        None => item
            .fields()
            .iter()
            .find(|f| f.kind() == FieldKind::Totp && !f.is_empty())
            .ok_or_else(|| ClientError::NotFound("a one-time password field".into()))?,
    };
    let FieldValue::Secret(secret) = f.value() else {
        return Err(ClientError::Invalid("not a one-time password field".into()));
    };
    let totp = Totp::from_field_value(secret.expose())
        .map_err(|e| ClientError::Invalid(format!("invalid TOTP secret: {e}")))?;
    let now = now_secs();
    let code = totp.generate(now);
    Ok((
        SecretValue::new(secrecy::ExposeSecret::expose_secret(&code).to_owned()),
        totp.seconds_remaining(now),
    ))
}

/// The largest ciphertext a `size`-byte attachment can have (STREAM, spec
/// §10): the header, the plaintext and one tag per chunk of the smallest
/// size, plus the final one.
fn ciphertext_bound(size: u64) -> u64 {
    let chunks = size / u64::from(MIN_CHUNK_SIZE) + 1;
    (HEADER_LEN as u64)
        .saturating_add(size)
        .saturating_add(chunks.saturating_mul(TAG_LEN as u64))
}

/// A reference segment for a name.
fn encode(segment: &str) -> String {
    let full = Reference {
        vault: klav_core::model::Selector::Name(segment.to_owned()),
        project: klav_core::model::Selector::Name("p".into()),
        item: klav_core::model::Selector::Name("i".into()),
        field: klav_core::model::Selector::Name("f".into()),
    }
    .to_string();
    full["klav://".len()..]
        .trim_end_matches("/p/i/f")
        .to_owned()
}

impl Catalog for Session {
    fn vaults(&self) -> Vec<Named<VaultId>> {
        let mut seen: HashMap<VaultId, String> = HashMap::new();
        for g in self.grant.keys.values() {
            seen.entry(g.ctx.vault)
                .or_insert_with(|| g.labels.vault.clone());
        }
        seen.into_iter()
            .map(|(id, name)| Named { id, name })
            .collect()
    }

    fn projects(&self, vault: VaultId) -> Vec<Named<ProjectId>> {
        self.grant
            .keys
            .iter()
            .filter(|(_, g)| g.ctx.vault == vault)
            .map(|(id, g)| Named {
                id: *id,
                name: g.labels.project.clone(),
            })
            .collect()
    }

    fn items(&self, vault: VaultId, project: ProjectId) -> Vec<Named<ItemId>> {
        self.items
            .iter()
            .filter(|(id, e)| e.vault == vault && e.project == project && self.listable(**id))
            .map(|(id, e)| Named {
                id: *id,
                name: e.overview.title.clone(),
            })
            .collect()
    }
}

pub(crate) fn item_ctx(
    project: &klav_core::crypto::context::ProjectContext,
    item: ItemId,
) -> ItemContext {
    ItemContext {
        account: project.account,
        vault: project.vault,
        project: project.project,
        item,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn login() -> Item {
        let mut item = Item::from_template(ItemKind::Login, "Site").unwrap();
        item.field_mut("password")
            .unwrap()
            .set_value("hunter2")
            .unwrap();
        item.field_mut("totp")
            .unwrap()
            .set_value("JBSWY3DPEHPK3PXP")
            .unwrap();
        item
    }

    #[test]
    fn approvals_serve_only_inside_their_signed_window() {
        let now = 1_000_000_000;
        // A lease serves until it ends, used or not.
        assert!(approval_window(now + 1, now - ONCE_WINDOW_MS * 9, true, now, false).is_ok());
        assert!(approval_window(now, now - 1, false, now, false).is_err());
        // Approve-once: unused and decided less than 10 minutes ago.
        assert!(approval_window(0, now - 1, false, now, false).is_ok());
        assert!(approval_window(0, now - 1, true, now, false).is_err());
        assert!(approval_window(0, now - 1, true, now, true).is_ok());
        assert!(approval_window(0, now - ONCE_WINDOW_MS, false, now, false).is_err());
        assert!(approval_window(0, now - 3 * 24 * 3600 * 1000, false, now, true).is_err());
    }

    #[test]
    fn the_ciphertext_bound_covers_every_chunk_size() {
        use klav_core::crypto::attachment::encrypt_attachment_bytes;
        use klav_core::crypto::keys::AttachmentKey;
        let ctx = AttachmentContext {
            account: klav_core::ids::AccountId::generate(),
            vault: VaultId::generate(),
            project: ProjectId::generate(),
            item: ItemId::generate(),
            attachment: AttachmentId::generate(),
        };
        let key = AttachmentKey::generate();
        for size in [0usize, 1, 63, 64, 65, 70_000] {
            let sealed = encrypt_attachment_bytes(&key, &ctx, &vec![7u8; size]);
            assert!(
                sealed.len() as u64 <= ciphertext_bound(size as u64),
                "{size}"
            );
        }
        assert!(ciphertext_bound(10) < 10 + 4096);
    }

    #[test]
    fn codes_come_only_from_one_time_password_fields() {
        let mut item = login();
        // A password that happens to be valid base32 is still no seed.
        item.field_mut("password")
            .unwrap()
            .set_value("JBSWY3DPEHPK3PXP")
            .unwrap();
        assert!(totp_code(&item, Some("totp")).is_ok());
        assert!(totp_code(&item, None).is_ok());
        assert!(matches!(
            totp_code(&item, Some("password")),
            Err(ClientError::NotFound(_))
        ));
        // Without a one-time password field, no other secret stands in.
        item.field_mut("totp").unwrap().set_value("").unwrap();
        assert!(matches!(
            totp_code(&item, None),
            Err(ClientError::NotFound(_))
        ));
    }

    #[test]
    fn a_totp_seed_is_never_injected() {
        let item = login();
        let files = Files::new();
        assert!(field_bytes(&item, "password", &files).is_ok());
        let err = field_bytes(&item, "totp", &files).err().unwrap();
        assert!(
            matches!(&err, ClientError::Denied(m) if m.contains("get_totp")),
            "{err}"
        );
    }
}
