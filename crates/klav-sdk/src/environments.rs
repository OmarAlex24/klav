//! Environments per repository from the agent's side (ADR 0032 §3.1, §4.4,
//! §4.5 and §5).
//!
//! An agent reads an `environment` item with `inject`, like any item. When
//! the policy says «ask every time» for it (a protected environment), the
//! access names the protected items its references may point to in
//! `items`, so **one** approval covers the environment and those items
//! (§3.1); each item is then fetched with its own access naming that
//! approval. The runtime cannot read the references before the
//! environment opens, so it takes those items from the `origin:
//! "protected"` rules of the grant the account signed, narrowed to what
//! this session learned the environment references.
//!
//! The double barrier (§4.4): an environment this runtime can read and
//! whose effective flag (§3) is on needs an approval the account signed
//! even if the server and the grant say `allow`; so do the references of
//! the person's protected version. Otherwise the answer is a
//! [`ClientError::Security`] and no value is used.
//!
//! Nothing here returns or logs a value outside zeroizing buffers.

use std::collections::BTreeSet;
use std::time::Duration;

use klav_client::{ClientError, ClientResult};
use klav_core::ids::ItemId;
use klav_core::model::environment::VariableSource;
use klav_core::model::item::{FieldKind, ItemKind};
use klav_core::policy::{Effect, Permission};
use klav_proto::agent::MAX_APPROVAL_ITEMS;
use zeroize::Zeroizing;

use crate::session::{Claim, Session};

/// Largest attachment a variable's reference may deliver as text (ADR 0032
/// §1), as on the person's side.
pub const MAX_VARIABLE_ATTACHMENT: usize = 64 * 1024;

/// An environment the agent may list: names only.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EnvironmentInfo {
    /// The item.
    pub id: ItemId,
    /// Its name (`development`, `production`…).
    pub name: String,
    /// Vault name.
    pub vault: String,
    /// Project name.
    pub project: String,
    /// Its variables' names, as its overview lists them.
    pub variables: Vec<String>,
}

/// An environment's values, ready for a process: variable → value.
pub struct EnvironmentValues {
    /// The environment's name.
    pub name: String,
    /// Its variables, in order, with their values.
    pub values: Vec<(String, Zeroizing<String>)>,
}

impl Session {
    /// The environments of `scope` (`vault`, `project`), or of every
    /// granted project, that the agent may list, sorted by name.
    pub fn environments(&self, scope: Option<(&str, &str)>) -> Vec<EnvironmentInfo> {
        let mut out: Vec<EnvironmentInfo> = self
            .items
            .iter()
            .filter(|(_, e)| e.overview.kind == ItemKind::Environment)
            .filter(|(id, _)| self.listable(**id))
            .filter_map(|(id, e)| {
                let (vault, project) = self.names(e.project);
                if let Some((v, p)) = scope
                    && (!v.eq_ignore_ascii_case(&vault) || !p.eq_ignore_ascii_case(&project))
                {
                    return None;
                }
                Some(EnvironmentInfo {
                    id: *id,
                    name: e.overview.title.clone(),
                    vault,
                    project,
                    variables: e
                        .overview
                        .environment
                        .as_ref()
                        .map(|s| s.variables.clone())
                        .unwrap_or_default(),
                })
            })
            .collect();
        out.sort_by(|a, b| {
            (a.name.as_str(), a.vault.as_str(), a.project.as_str()).cmp(&(
                b.name.as_str(),
                b.vault.as_str(),
                b.project.as_str(),
            ))
        });
        out
    }

    /// The environment called `name` in `scope` (or, without one, the only
    /// granted environment with that name), if there is one.
    pub fn find_environment(
        &self,
        scope: Option<(&str, &str)>,
        name: &str,
    ) -> ClientResult<Option<EnvironmentInfo>> {
        let mut found: Vec<EnvironmentInfo> = self
            .environments(scope)
            .into_iter()
            .filter(|e| e.name == name)
            .collect();
        match found.len() {
            0 => Ok(None),
            1 => Ok(found.pop()),
            _ => Err(ClientError::Invalid(format!(
                "several projects have an environment {name:?}: name the project (`project` in klav.toml)"
            ))),
        }
    }

    /// The other items one approval for `env` covers (ADR 0032 §3.1): the
    /// items the grant's inherited `inject` rules protect, that this agent
    /// lists, that are not environments and that the policy does not deny,
    /// narrowed to the environment's references when this session already
    /// read it; at most [`MAX_APPROVAL_ITEMS`]. Kept in one function so how
    /// the runtime learns the references can change without touching the
    /// callers.
    pub(crate) fn bundle_for(&self, env: ItemId) -> Vec<ItemId> {
        let known = self.env_refs.get(&env);
        let protected: BTreeSet<ItemId> = self
            .grant
            .payload
            .policy
            .protected_pairs()
            .into_iter()
            .filter(|(p, _)| *p == Permission::Inject)
            .map(|(_, i)| i)
            .collect();
        protected
            .into_iter()
            .filter(|i| *i != env)
            .filter(|i| known.is_none_or(|refs| refs.contains(i)))
            .filter(|i| {
                self.items
                    .get(i)
                    .is_some_and(|e| e.overview.kind != ItemKind::Environment)
            })
            .filter(|i| self.listable(*i))
            .filter(|i| self.evaluate(*i, Permission::Inject, None).effect != Effect::Deny)
            .take(MAX_APPROVAL_ITEMS)
            .collect()
    }

    /// The values of environment `env` (ADR 0032 §4.5): one `inject` of the
    /// environment (with the bundle of [`Self::bundle_for`] when it always
    /// asks), then one `inject` of each item its references point to,
    /// naming that approval when it lists the item; references to
    /// unprotected items are judged by their own rules. Waits up to `wait`
    /// for the person.
    pub async fn environment_values(
        &mut self,
        env: ItemId,
        reason: &str,
        wait: Duration,
    ) -> ClientResult<EnvironmentValues> {
        let once = self.evaluate(env, Permission::Inject, None).once;
        let bundle = if once {
            self.bundle_for(env)
        } else {
            Vec::new()
        };
        self.check_claim(Permission::Inject, &[env], None)?;
        self.last_approval = None;
        let (opened, _) = self
            .access_waiting_inner(env, Permission::Inject, reason, None, wait, false, &bundle)
            .await?;
        let approval = self.last_approval;
        let environment = opened.environment().ok_or_else(|| {
            ClientError::Corrupt(format!("{} is not an environment", opened.title()))
        })?;
        let refs = environment.reference_targets();
        // What the runtime learned: the next bundle for it asks for these.
        self.env_refs.insert(env, refs.clone());
        // The references of the person's protected version need a signed
        // approval whatever the server says (§4.4); `access` checks it.
        if self.last_by_person && environment.protected() {
            for item in &refs {
                if !self.must_approve.contains(item) {
                    self.must_approve.push(*item);
                }
            }
        }
        // The members of the approval go through the claim machinery: each
        // listed item's access names it, once.
        let previous = self.claim.take();
        let named_for_env = previous
            .as_ref()
            .is_some_and(|c| c.item == Some(env) && !c.members.is_empty());
        if named_for_env {
            self.claim = previous.clone();
        } else if let Some(id) = approval
            && !bundle.is_empty()
        {
            let entry = self
                .items
                .get(&env)
                .ok_or_else(|| ClientError::NotFound(format!("item {env}")))?;
            self.claim = Some(Claim {
                id,
                permission: Permission::Inject,
                project: entry.project,
                item: Some(env),
                domain: None,
                used: true,
                members: bundle.clone(),
                members_used: Vec::new(),
            });
        }
        let mut values = Vec::with_capacity(environment.variables().len());
        let mut references: Vec<(String, String)> = Vec::new();
        for variable in environment.variables() {
            match variable.source() {
                VariableSource::Value(v) => {
                    values.push((
                        variable.name().to_owned(),
                        Zeroizing::new(v.expose().to_owned()),
                    ));
                }
                VariableSource::Ref(r) => {
                    references.push((variable.name().to_owned(), r.to_string()));
                }
            }
        }
        let resolved = if references.is_empty() {
            Ok(Vec::new())
        } else {
            let list: Vec<String> = references.iter().map(|(_, r)| r.clone()).collect();
            // Any project or vault (§1): no `klav.toml` scope here.
            self.resolve(&list, None, reason, wait).await
        };
        // An approval named for this environment has served its call: the
        // rest of the run is judged without it.
        self.claim = if named_for_env { None } else { previous };
        let resolved = resolved?;
        for ((name, _), value) in references.iter().zip(resolved) {
            if value.kind == FieldKind::File && value.value.len() > MAX_VARIABLE_ATTACHMENT {
                return Err(ClientError::Invalid(format!(
                    "{name}: its reference is an attachment larger than 64 KiB; use [files] in klav.toml"
                )));
            }
            let text = value.text().map_err(|_| {
                ClientError::Invalid(format!(
                    "{name}: its reference is an attachment that is not UTF-8 text; use [files] in klav.toml"
                ))
            })?;
            values.push((name.clone(), Zeroizing::new(text.to_owned())));
        }
        // In the order of the environment.
        let order: Vec<&str> = environment.variables().iter().map(|v| v.name()).collect();
        values.sort_by_key(|(n, _)| order.iter().position(|o| o == n));
        Ok(EnvironmentValues {
            name: opened.title().to_owned(),
            values,
        })
    }
}
