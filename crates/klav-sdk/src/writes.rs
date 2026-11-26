//! Agent writes (`create`, `update`, `delete`): the runtime seals the item
//! with the granted project key; the server checks the policy and logs the
//! action with its reason (ADR 0014 §4).
//!
//! An update reads the current item first (`access` with `update`), merges
//! the patch and writes the next version with the same item key. With `ask`
//! the read and the write are two requests: approving the first "for a few
//! minutes" (a lease) covers both.

use std::time::Duration;

use klav_client::ops::{FieldInput, ItemPatch, NewItem, SecretText, build_item, patch_item};
use klav_client::{ClientError, ClientResult};
use klav_core::crypto::keys::ItemKey;
use klav_core::crypto::wrap::{unwrap_item_key, wrap_item_key};
use klav_core::generator::{
    self, GeneratorKind, GeneratorOptions, RulesFallback, RulesSource, SiteHints, Strength,
};
use klav_core::ids::{ApprovalId, ItemId, ProjectId, TaskId};
use klav_core::model::item::{FieldKind, ItemKind, template};
use klav_core::model::seal_item;
use klav_core::policy::{Effect, Permission};
use klav_proto::Blob;
use klav_proto::agent::{
    AgentAsk, AgentAsked, AgentCreateItem, AgentTrashItem, AgentTrashed, AgentUpdateItem,
    AgentWritten, ApprovalStatus, Claims, PendingApproval,
};
use klav_proto::vault::{CreateItem, UpdateItem};
use reqwest::{Method, StatusCode};
use secrecy::ExposeSecret;
use serde::Serialize;

use crate::session::{ActionTarget, ItemInfo, Session, item_ctx, pending, permission_name};

/// A write the policy here denies is not even sent (ADR 0030 §3): its body
/// carries the sealed item, and a server that ignores the policy could
/// apply it.
fn denied_here(permission: Permission) -> ClientError {
    ClientError::Denied(format!(
        "the policy denies `{}` on this item",
        permission_name(permission)
    ))
}

/// A write the server applied without a backing this runtime verifies.
fn applied_unbacked(e: ClientError) -> ClientError {
    match e {
        ClientError::Security(m) => ClientError::Security(format!(
            "{m} (the server already applied the write: tell the person)"
        )),
        other => other,
    }
}

/// What a write asks the person **before** its body goes out, when the
/// policy here says `ask` (ADR 0030 §3, residual risk 35).
struct AskFirst<'a> {
    target: ActionTarget<'a>,
    reason: String,
    tags: Vec<String>,
    task: Option<TaskId>,
}

impl Session {
    /// The approval for a write that the policy here asks about, obtained
    /// before the sealed item is sent (`POST /v1/agent/approvals`): the
    /// person's decision, verified (the account's signature, for exactly
    /// this write), or an approval for the same target that still serves.
    /// `None` only if a task this runtime verified covers the write. A
    /// server that answers that no approval is needed is not believed:
    /// nothing is sent.
    async fn ask_first(
        &mut self,
        first: &AskFirst<'_>,
        wait: Duration,
    ) -> ClientResult<Option<ApprovalId>> {
        let target = &first.target;
        let permission = target.permission;
        let body = serde_json::to_vec(&AgentAsk {
            permission,
            vault_id: target.vault,
            project_id: target.project,
            item_id: target.item,
            reason: first.reason.clone(),
            claims: Claims {
                tags: first.tags.clone(),
                domain: None,
                ..Claims::default()
            },
            task_id: first.task,
        })
        .map_err(|e| ClientError::Invalid(format!("request: {e}")))?;
        let res = self
            .agent
            .send(Method::POST, "/v1/agent/approvals", Some(&body))
            .await?;
        match res.status() {
            StatusCode::ACCEPTED => {
                let p: PendingApproval = klav_client::api::json(res).await?;
                let id = p.pending_approval_id;
                if wait.is_zero() {
                    return Err(pending(id, permission));
                }
                match self.wait_verified(id, wait).await? {
                    ApprovalStatus::Approved => {
                        self.approval_fits(target, id, false).await?;
                        Ok(Some(id))
                    }
                    ApprovalStatus::Pending => Err(pending(id, permission)),
                    ApprovalStatus::Denied => {
                        Err(ClientError::Denied("the person denied the request".into()))
                    }
                    ApprovalStatus::Expired => Err(ClientError::Denied(
                        "nobody approved the request in time".into(),
                    )),
                }
            }
            StatusCode::FORBIDDEN => Err(crate::session::forbidden(res).await),
            StatusCode::OK => {
                let asked: AgentAsked = klav_client::api::json(res).await?;
                if let Some(id) = asked.approval_id {
                    self.approval_fits(target, id, false).await?;
                    return Ok(Some(id));
                }
                if let Some(task) = asked.task_id {
                    // A task approved since the session loaded them.
                    self.load_tasks().await?;
                    if self.task_covers(target, Some(task)) {
                        return Ok(None);
                    }
                }
                Err(ClientError::Security(format!(
                    "the server says `{}` needs no approval, but the agent's policy asks the person and nothing this runtime can verify covers it: nothing was sent",
                    permission_name(permission)
                )))
            }
            _ => {
                klav_client::api::empty(res).await?;
                Err(ClientError::Invalid("unexpected answer".into()))
            }
        }
    }

    /// Sends a gated write; on `202` waits up to `wait` for the person and
    /// repeats it with the approval (verified first). A named approval for
    /// it ([`Session::claim_approval`]) is sent from the start. With
    /// `first` (the policy here says `ask`), the approval is obtained and
    /// verified before the body is sent at all ([`Self::ask_first`]), unless
    /// a task this runtime verified covers the write. Returns the answer
    /// and the approval sent with it.
    #[allow(clippy::too_many_arguments)]
    async fn gated(
        &mut self,
        method: Method,
        path: &str,
        permission: Permission,
        item: Option<ItemId>,
        wait: Duration,
        first: Option<AskFirst<'_>>,
        body: impl Fn(Option<ApprovalId>) -> ClientResult<Vec<u8>>,
    ) -> ClientResult<(reqwest::Response, Option<ApprovalId>)> {
        // What the person reads on the approval card and in the log.
        let reason = body(None).ok().and_then(|b| {
            serde_json::from_slice::<serde_json::Value>(&b)
                .ok()
                .and_then(|v| v["reason"].as_str().map(str::to_owned))
        });
        if let Some(reason) = reason {
            if reason.trim().is_empty() {
                return Err(ClientError::Invalid(
                    "a reason is mandatory: say why the agent needs this".into(),
                ));
            }
            crate::text::check_declared("reason", &reason)?;
        }
        // A named approval for this write goes with the first request.
        let mut approval = self.claimed(item, permission, None, wait).await?;
        if approval.is_none()
            && let Some(first) = &first
            && !self.task_covers(&first.target, first.task)
        {
            approval = self.ask_first(first, wait).await?;
        }
        loop {
            let bytes = body(approval)?;
            let res = self.agent.send(method.clone(), path, Some(&bytes)).await?;
            match res.status() {
                StatusCode::ACCEPTED => {
                    let p: PendingApproval = klav_client::api::json(res).await?;
                    if approval.is_some() || wait.is_zero() {
                        return Err(pending(p.pending_approval_id, permission));
                    }
                    match self.wait_verified(p.pending_approval_id, wait).await? {
                        ApprovalStatus::Approved => approval = Some(p.pending_approval_id),
                        ApprovalStatus::Pending => {
                            return Err(pending(p.pending_approval_id, permission));
                        }
                        ApprovalStatus::Denied => {
                            return Err(ClientError::Denied(
                                "the person denied the request".into(),
                            ));
                        }
                        ApprovalStatus::Expired => {
                            return Err(ClientError::Denied(
                                "nobody approved the request in time".into(),
                            ));
                        }
                    }
                }
                StatusCode::FORBIDDEN => return Err(crate::session::forbidden(res).await),
                status if status.is_success() => return Ok((res, approval)),
                _ => {
                    klav_client::api::empty(res).await?;
                    return Err(ClientError::Invalid("unexpected answer".into()));
                }
            }
        }
    }

    /// The granted project named `vault/project` (labels), or the only one
    /// in `scope`.
    pub fn granted_project(
        &self,
        vault: Option<&str>,
        project: Option<&str>,
        scope: Option<(&str, &str)>,
    ) -> ClientResult<ProjectId> {
        let (vault, project) = match (vault, project, scope) {
            (Some(v), Some(p), _) => (Some(v), p),
            (None, Some(p), Some((v, _))) => (Some(v), p),
            (None, Some(p), None) => (None, p),
            (_, None, Some((v, p))) => (Some(v), p),
            (_, None, None) => {
                return Err(ClientError::Invalid(
                    "say in which project (vault and project)".into(),
                ));
            }
        };
        if let Some((sv, sp)) = scope
            && (vault.is_some_and(|v| !v.eq_ignore_ascii_case(sv))
                || !project.eq_ignore_ascii_case(sp))
        {
            return Err(ClientError::Denied(format!(
                "outside the project of klav.toml ({sv}/{sp})"
            )));
        }
        let found: Vec<ProjectId> = self
            .grant
            .keys
            .iter()
            .filter(|(_, g)| {
                g.labels.project.eq_ignore_ascii_case(project)
                    && vault.is_none_or(|v| g.labels.vault.eq_ignore_ascii_case(v))
            })
            .map(|(id, _)| *id)
            .collect();
        match found.as_slice() {
            [one] => Ok(*one),
            [] => Err(ClientError::NotFound(format!(
                "project {project:?} in the agent's grant"
            ))),
            _ => Err(ClientError::Invalid(format!(
                "several granted projects are called {project:?}: give the vault"
            ))),
        }
    }

    /// The reference of a live item of `project` titled `title`
    /// (case-insensitive), other than `except`.
    fn titled(&self, project: ProjectId, title: &str, except: Option<ItemId>) -> Option<String> {
        let title = title.trim();
        let mut found: Vec<(&ItemId, _)> = self
            .items
            .iter()
            .filter(|(id, e)| {
                Some(**id) != except
                    && e.project == project
                    && e.overview.title.trim().eq_ignore_ascii_case(title)
                    && self.listable(**id)
            })
            .collect();
        found.sort_by_key(|(id, _)| id.to_string());
        found.first().map(|(id, e)| self.info(**id, e).reference)
    }

    /// Creates an item in a granted project.
    pub async fn create_item(
        &mut self,
        project: ProjectId,
        new: &NewItem,
        reason: &str,
        wait: Duration,
    ) -> ClientResult<ItemInfo> {
        self.check_claim(Permission::Create, &[], Some(project))?;
        let item = build_item(new)?;
        let tags = item.tags().to_vec();
        let (vault_id, decision) = self.evaluate_in(project, Permission::Create, &tags)?;
        if decision.effect == Effect::Deny {
            return Err(denied_here(Permission::Create));
        }
        // Titles name items in references: a second item with the same
        // title would make every reference to them ambiguous.
        if let Some(existing) = self.titled(project, item.title(), None) {
            return Err(ClientError::Invalid(format!(
                "{existing} already exists: use update_item to change it, or choose another title"
            )));
        }
        let granted = self
            .grant
            .keys
            .get(&project)
            .ok_or_else(|| ClientError::NotFound("project key".into()))?;
        let ctx = item_ctx(&granted.ctx, item.id());
        let project_version = self.project_version(project)?;
        let key = ItemKey::generate();
        let sealed = seal_item(&key, &ctx, 1, &item);
        let create = CreateItem {
            id: item.id(),
            project_id: project,
            version: 1,
            wrapped_key: Blob::new(wrap_item_key(&granted.key, &ctx, &key)),
            project_version,
            overview: Blob::new(sealed.overview),
            details: Blob::new(sealed.details),
        };
        let reason = reason.trim().to_owned();
        let first = (decision.effect == Effect::Ask).then(|| AskFirst {
            target: ActionTarget {
                permission: Permission::Create,
                vault: vault_id,
                project,
                item: None,
                domain: None,
            },
            reason: reason.clone(),
            tags: tags.clone(),
            task: None,
        });
        let (res, sent) = self
            .gated(
                Method::POST,
                "/v1/agent/items",
                Permission::Create,
                None,
                wait,
                first,
                |approval_id| {
                    serde_json::to_vec(&AgentCreateItem {
                        vault_id,
                        item: create.clone(),
                        reason: reason.clone(),
                        claims: Claims {
                            tags: tags.clone(),
                            domain: None,
                            ..Claims::default()
                        },
                        approval_id,
                        task_id: None,
                    })
                    .map_err(|e| ClientError::Invalid(format!("request: {e}")))
                },
            )
            .await?;
        let returned = self.written(res).await?;
        if decision.effect == Effect::Ask {
            let target = ActionTarget {
                permission: Permission::Create,
                vault: vault_id,
                project,
                item: None,
                domain: None,
            };
            self.backed(&target, sent, returned, None)
                .await
                .map_err(applied_unbacked)?;
        }
        self.refresh().await?;
        self.item_info(item.id())
    }

    /// Reads `item`, applies `patch` and writes the next version.
    pub async fn update_item(
        &mut self,
        item: ItemId,
        patch: &ItemPatch,
        reason: &str,
        wait: Duration,
    ) -> ClientResult<ItemInfo> {
        self.check_claim(Permission::Update, &[item], None)?;
        // Same rule as create (agents never override it): refused before
        // asking for anything, so an impossible rename leaves no request.
        if let Some(title) = &patch.title {
            let project = self
                .items
                .get(&item)
                .ok_or_else(|| ClientError::NotFound(format!("item {item}")))?
                .project;
            if let Some(existing) = self.titled(project, title, Some(item)) {
                return Err(ClientError::Invalid(format!(
                    "{existing} already exists: choose another title"
                )));
            }
        }
        let mut current = self
            .access_waiting(item, Permission::Update, reason, None, wait)
            .await?;
        patch_item(&mut current, patch)?;
        let entry = self
            .items
            .get(&item)
            .ok_or_else(|| ClientError::NotFound(format!("item {item}")))?;
        // The policy with the tags the item will have: `add_tags` must not
        // widen what `update` may touch (ronda 2).
        let before =
            self.evaluate_entry(item, entry, Permission::Update, None, &entry.overview.tags);
        let after = self.evaluate_entry(item, entry, Permission::Update, None, current.tags());
        let decision = before.effect.max(after.effect);
        if decision == Effect::Deny {
            return Err(denied_here(Permission::Update));
        }
        let target_vault = entry.vault;
        let target_project = entry.project;
        let granted = self
            .grant
            .keys
            .get(&entry.project)
            .ok_or_else(|| ClientError::NotFound("project key".into()))?;
        let ctx = item_ctx(&granted.ctx, item);
        let key = unwrap_item_key(&granted.key, &ctx, &entry.wrapped_key)?;
        let version = entry.version + 1;
        let sealed = seal_item(&key, &ctx, version, &current);
        let update = UpdateItem {
            version,
            wrapped_key: Blob::new(entry.wrapped_key.clone()),
            project_version: self.project_version(entry.project)?,
            overview: Blob::new(sealed.overview),
            details: Blob::new(sealed.details),
            attachment_keys: None,
        };
        let tags = current.tags().to_vec();
        let reason = reason.trim().to_owned();
        let task_id = self.task_for(item, Permission::Update, None);
        let first = (decision == Effect::Ask).then(|| AskFirst {
            target: ActionTarget {
                permission: Permission::Update,
                vault: target_vault,
                project: target_project,
                item: Some(item),
                domain: None,
            },
            reason: reason.clone(),
            tags: tags.clone(),
            task: task_id,
        });
        let (res, sent) = self
            .gated(
                Method::PUT,
                &format!("/v1/agent/items/{item}"),
                Permission::Update,
                Some(item),
                wait,
                first,
                |approval_id| {
                    serde_json::to_vec(&AgentUpdateItem {
                        item: update.clone(),
                        reason: reason.clone(),
                        claims: Claims {
                            tags: tags.clone(),
                            domain: None,
                            ..Claims::default()
                        },
                        approval_id,
                        task_id,
                    })
                    .map_err(|e| ClientError::Invalid(format!("request: {e}")))
                },
            )
            .await?;
        let returned = self.written(res).await?;
        if decision == Effect::Ask {
            let target = ActionTarget {
                permission: Permission::Update,
                vault: target_vault,
                project: target_project,
                item: Some(item),
                domain: None,
            };
            self.backed(&target, sent, returned, task_id)
                .await
                .map_err(applied_unbacked)?;
        }
        self.refresh().await?;
        self.item_info(item)
    }

    /// The answer to a create or an update. A `409` that is not a stale
    /// item version means the project key rotated in between: the session
    /// reloads (the new grant, if the person issued one) so the caller can
    /// try again.
    async fn written(&mut self, res: reqwest::Response) -> ClientResult<Option<ApprovalId>> {
        match klav_client::api::json::<AgentWritten>(res).await {
            Ok(written) => Ok(written.approval_id),
            Err(e @ ClientError::Api { status: 409, .. }) => {
                self.refresh().await?;
                Err(e)
            }
            Err(e) => Err(e),
        }
    }

    /// Moves `item` to the trash (the person can restore it).
    pub async fn trash_item(
        &mut self,
        item: ItemId,
        reason: &str,
        wait: Duration,
    ) -> ClientResult<()> {
        self.check_claim(Permission::Delete, &[item], None)?;
        let entry = self
            .items
            .get(&item)
            .ok_or_else(|| ClientError::NotFound(format!("item {item}")))?;
        let tags = entry.overview.tags.clone();
        let target_vault = entry.vault;
        let target_project = entry.project;
        let decision = self.evaluate(item, Permission::Delete, None).effect;
        if decision == Effect::Deny {
            return Err(denied_here(Permission::Delete));
        }
        let reason = reason.trim().to_owned();
        let first = (decision == Effect::Ask).then(|| AskFirst {
            target: ActionTarget {
                permission: Permission::Delete,
                vault: target_vault,
                project: target_project,
                item: Some(item),
                domain: None,
            },
            reason: reason.clone(),
            tags: tags.clone(),
            task: None,
        });
        let (res, sent) = self
            .gated(
                Method::POST,
                &format!("/v1/agent/items/{item}/trash"),
                Permission::Delete,
                Some(item),
                wait,
                first,
                |approval_id| {
                    serde_json::to_vec(&AgentTrashItem {
                        reason: reason.clone(),
                        claims: Claims {
                            tags: tags.clone(),
                            domain: None,
                            ..Claims::default()
                        },
                        approval_id,
                        task_id: None,
                    })
                    .map_err(|e| ClientError::Invalid(format!("request: {e}")))
                },
            )
            .await?;
        let trashed: AgentTrashed = klav_client::api::json(res).await?;
        if decision == Effect::Ask {
            let target = ActionTarget {
                permission: Permission::Delete,
                vault: target_vault,
                project: target_project,
                item: Some(item),
                domain: None,
            };
            self.backed(&target, sent, trashed.approval_id, None)
                .await
                .map_err(applied_unbacked)?;
        }
        self.refresh().await
    }
}

/// How [`Session::create_item_generated`] makes the password (ADR 0022 §7):
/// the runtime generates it and seals it in the new item; the caller only
/// learns [`GeneratedInfo`].
#[derive(Debug, Clone, Default)]
pub struct GenerateSpec {
    /// Which kind (default `smart`: the site's rules, else 20 random
    /// characters).
    pub kind: GeneratorKind,
    /// The site whose rules apply (default: the host of the item's first
    /// URL).
    pub site: Option<String>,
    /// The field that gets it (default: `password` for a login, else the
    /// item type's first password or concealed field).
    pub field: Option<String>,
}

/// What is known about a generated password: never the value.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct GeneratedInfo {
    /// The field that holds it.
    pub field: String,
    /// The kind generated.
    #[serde(rename = "type")]
    pub kind: GeneratorKind,
    /// Its entropy in bits.
    pub bits: f64,
    /// Its strength label.
    pub strength: Strength,
    /// The site's host whose rules were looked up, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub site: Option<String>,
    /// The site rules a `smart` password follows.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rules: Option<RulesSource>,
    /// The site's rules make it weaker than Klav would choose.
    pub limited: bool,
    /// A `smart` password that could not follow the site's rules.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fallback: Option<RulesFallback>,
}

/// Generates the password `spec` asks for into a field of `new`. The value
/// only goes into the returned field, which zeroizes it.
pub fn generated_field(
    new: &NewItem,
    spec: &GenerateSpec,
) -> ClientResult<(FieldInput, GeneratedInfo)> {
    let builtin = template(new.kind);
    let field = match spec.field.as_deref().map(str::trim) {
        Some(f) if !f.is_empty() => f.to_owned(),
        _ if new.kind == ItemKind::Login => "password".to_owned(),
        _ => builtin
            .iter()
            .find(|(_, _, k)| matches!(k, FieldKind::Password | FieldKind::Concealed))
            .map(|(n, _, _)| (*n).to_owned())
            .ok_or_else(|| {
                ClientError::Invalid(format!(
                    "a {:?} item has no password field: say which field gets the generated password",
                    new.kind
                ))
            })?,
    };
    if new.fields.iter().any(|f| f.name == field) {
        return Err(ClientError::Invalid(format!(
            "`fields` already sets {field:?}: either give it a value or let Klav generate it, not both"
        )));
    }
    let kind = match builtin.iter().find(|(n, _, _)| *n == field) {
        Some((_, _, k @ (FieldKind::Password | FieldKind::Concealed))) => *k,
        Some(_) => {
            return Err(ClientError::Invalid(format!(
                "{field:?} is not a password field: Klav only generates passwords into password or concealed fields"
            )));
        }
        None => FieldKind::Password,
    };
    let site = match spec.site.as_deref().map(str::trim) {
        Some(s) if !s.is_empty() => Some(klav_core::site::item_host(s).ok_or_else(|| {
            ClientError::Invalid(format!("{s:?} is not a site (a host such as example.com)"))
        })?),
        _ => new.urls.iter().find_map(|u| klav_core::site::item_host(u)),
    };
    let options = GeneratorOptions {
        kind: spec.kind,
        ..GeneratorOptions::default()
    };
    let hints = SiteHints {
        host: site.clone(),
        ..SiteHints::default()
    };
    let generated = generator::generate(&options, &hints)
        .map_err(|e| ClientError::Invalid(format!("generator: {e}")))?;
    let info = GeneratedInfo {
        field: field.clone(),
        kind: generated.kind,
        bits: (generated.bits * 10.0).round() / 10.0,
        strength: generated.strength,
        site,
        rules: generated.rules.clone(),
        limited: generated.limited,
        fallback: generated.fallback,
    };
    let input = FieldInput {
        name: field,
        value: SecretText::new(generated.value.expose_secret()),
        kind: Some(kind),
        secret: true,
    };
    Ok((input, info))
}

impl Session {
    /// [`Session::create_item`] with a password the runtime generates
    /// (ADR 0022 §7): it is sealed in the item and never returned, so an
    /// agent can open an account with a strong password it does not see.
    /// Governed by `create`, like any other new item. It does not enter
    /// the person's generator history (§2): the agent holds no key to it,
    /// and the value is in the item from its first version.
    pub async fn create_item_generated(
        &mut self,
        project: ProjectId,
        mut new: NewItem,
        spec: &GenerateSpec,
        reason: &str,
        wait: Duration,
    ) -> ClientResult<(ItemInfo, GeneratedInfo)> {
        let (field, info) = generated_field(&new, spec)?;
        new.fields.push(field);
        let item = self.create_item(project, &new, reason, wait).await?;
        Ok((item, info))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn login(urls: &[&str]) -> NewItem {
        NewItem {
            kind: ItemKind::Login,
            title: "Shop".into(),
            vault: None,
            project: None,
            fields: vec![FieldInput {
                name: "username".into(),
                value: SecretText::new("ana"),
                kind: None,
                secret: false,
            }],
            urls: urls.iter().map(|u| (*u).to_owned()).collect(),
            tags: Vec::new(),
            notes: None,
            allow_duplicate: false,
        }
    }

    #[test]
    fn a_login_gets_a_password_with_its_site_rules() {
        let new = login(&["https://www.accor.com/signup"]);
        let (field, info) = generated_field(&new, &GenerateSpec::default()).unwrap();
        assert_eq!(field.name, "password");
        assert_eq!(field.kind, Some(FieldKind::Password));
        assert!(field.secret);
        assert_eq!(info.field, "password");
        assert_eq!(info.kind, GeneratorKind::Smart);
        assert_eq!(info.site.as_deref(), Some("accor.com"));
        assert!(matches!(info.rules, Some(RulesSource::Bundled { .. })));
        // What the caller sees says nothing of the value.
        let shown = serde_json::to_string(&info).unwrap();
        assert!(!shown.contains(field.value.expose()));
        assert!(!format!("{field:?}").contains(field.value.expose()));
    }

    #[test]
    fn other_kinds_and_explicit_choices() {
        let new = login(&[]);
        let spec = GenerateSpec {
            kind: GeneratorKind::Pin,
            site: None,
            field: None,
        };
        let (field, info) = generated_field(&new, &spec).unwrap();
        assert_eq!(field.value.expose().len(), 6);
        assert!(field.value.expose().chars().all(|c| c.is_ascii_digit()));
        assert_eq!(info.site, None);
        let mut key = login(&[]);
        key.kind = ItemKind::ApiKey;
        key.fields.clear();
        let (field, _) = generated_field(&key, &GenerateSpec::default()).unwrap();
        assert_eq!(field.name, "api_key");
        assert_eq!(field.kind, Some(FieldKind::Concealed));
        // Refused: no password field, a field set twice, a plain field.
        let mut note = key.clone();
        note.kind = ItemKind::Note;
        assert!(generated_field(&note, &GenerateSpec::default()).is_err());
        let mut twice = login(&[]);
        twice.fields.push(FieldInput {
            name: "password".into(),
            value: SecretText::new("x"),
            kind: None,
            secret: true,
        });
        assert!(generated_field(&twice, &GenerateSpec::default()).is_err());
        let plain = GenerateSpec {
            field: Some("username".into()),
            ..GenerateSpec::default()
        };
        assert!(generated_field(&login(&[]), &plain).is_err());
        let site = GenerateSpec {
            site: Some("https://bank.example.com/x".into()),
            ..GenerateSpec::default()
        };
        let (_, info) = generated_field(&login(&[]), &site).unwrap();
        assert_eq!(info.site.as_deref(), Some("bank.example.com"));
    }
}
