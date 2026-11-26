//! Environments per repository, from the person's side (ADR 0032).
//!
//! * **What is protected** ([`Protection`]): for each `environment` item,
//!   what its latest version **written by the person** protects (itself,
//!   when protected, and the targets of its references), computed with
//!   `klav-core`'s functions and kept in its own sealed file,
//!   [`PROTECTION_FILE`] (spec §12.2, purpose `protection`), apart from
//!   `cache.bin` so an older Klav still opens the cache. The set only
//!   shrinks with proof: a person's version of the environment that left
//!   the item out. When the person's version of an environment cannot be
//!   fetched or does not open, its vault is *uncertain*: every value of it
//!   asks for presence, and no grant is signed until a clean sync (§3.1).
//! * **Grants** ([`Unlocked::protect_grant`]): every grant this device
//!   signs keeps the `origin: "protected"` rules of the grant it replaces
//!   and adds `ask once` rules for the protected items the agent can reach,
//!   writing each permission's default first as an explicit rule (ADR 0006
//!   §2). An item leaves only with proof, and is named in `released`.
//! * **Editing** ([`Unlocked::prepare_environment`] and
//!   [`Unlocked::commit_environment`]): a version that makes the protection
//!   grow reissues the affected grants **before** it is uploaded, and none
//!   is saved if that fails; one that shrinks it is uploaded first, then
//!   the grants name what they release.
//!
//! Nothing here prints or logs a value: errors name variables, never what
//! they hold.

use std::collections::{BTreeMap, BTreeSet};

use klav_core::crypto::context::ItemContext;
use klav_core::crypto::keys::LocalKey;
use klav_core::crypto::local::{LocalContext, open_local_data, seal_local_data};
use klav_core::crypto::wrap::unwrap_item_key;
use klav_core::ids::{AgentId, FieldId, ItemId, ProjectId, VaultId};
use klav_core::model::environment::{
    Author, Environment, EnvironmentVersion, Variable, VariableSource, effective_protected,
    is_production_name,
};
use klav_core::model::item::{FieldKind, FieldValue, Item, ItemKind};
use klav_core::model::reference::{Reference, Selector, resolve_field, resolve_variable};
use klav_core::model::{SealedItem, open_item};
use klav_core::policy::{PROTECTED_PERMISSIONS, Rule};
use klav_proto::Blob;
use klav_proto::agent::GrantPayload;
use klav_proto::vault::{ItemHistory, ItemVersion};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::{ClientError, ClientResult};
use crate::home::{Home, write_private};
use crate::ops::{SecretBytes, SecretText};
use crate::session::{ItemLocation, Unlocked};

/// `$KLAV_HOME/protection.bin`: what protected environments protect (ADR
/// 0032 §3.1). Sealed with the local key (spec §12.2, purpose
/// `protection`).
pub const PROTECTION_FILE: &str = "protection.bin";
const PURPOSE_PROTECTION: &str = "protection";
const PROTECTION_VERSION: u32 = 1;

/// Largest attachment a variable's reference may deliver as text (ADR 0032
/// §1): a `.pem`, not a binary.
pub const MAX_VARIABLE_ATTACHMENT: usize = 64 * 1024;

/// What one environment protects, from its latest version by the person
/// (or, when only agents wrote it, failing closed).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Contribution {
    /// Its vault.
    pub(crate) vault: Option<VaultId>,
    /// Its name then.
    pub(crate) title: String,
    /// The environment itself is protected (ADR 0032 §3).
    pub(crate) protected: bool,
    /// The items its references point to, when it is protected in the
    /// person's version (§3.1).
    pub(crate) items: BTreeSet<ItemId>,
}

/// The latest version of an environment the person wrote, fetched for the
/// current version `for_version` (an agent's), as the server sent it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CachedEnvVersion {
    pub(crate) for_version: u64,
    pub(crate) project_version: u64,
    /// `None`: no version of the person (an agent created it).
    pub(crate) found: Option<EnvVersionBlobs>,
}

/// Enough of a version to open it whole.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EnvVersionBlobs {
    pub(crate) version: u64,
    pub(crate) project_id: ProjectId,
    pub(crate) created_at: i64,
    pub(crate) wrapped_key: Blob,
    pub(crate) overview: Blob,
    pub(crate) details: Blob,
}

/// [`PROTECTION_FILE`]'s contents.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProtectionFile {
    v: u32,
    #[serde(default)]
    contributions: BTreeMap<ItemId, Contribution>,
    #[serde(default)]
    seen: BTreeSet<ItemId>,
    #[serde(default)]
    from_grants: BTreeSet<ItemId>,
    #[serde(default)]
    uncertain: BTreeSet<VaultId>,
    #[serde(default)]
    person_versions: BTreeMap<ItemId, CachedEnvVersion>,
}

/// What this device knows of the protection (ADR 0032 §3.1).
#[derive(Debug, Clone, Default)]
pub struct Protection {
    /// The file exists and did not open: nothing is known until a clean
    /// refresh. Every value asks, and no grant is signed.
    pub(crate) unreadable: bool,
    /// Per environment item.
    pub(crate) contributions: BTreeMap<ItemId, Contribution>,
    /// Every item a contribution ever named: only those can leave the set,
    /// with proof.
    pub(crate) seen: BTreeSet<ItemId>,
    /// Items the `origin: "protected"` rules of the verified grants name:
    /// another device's protection reaches this one before the
    /// environment does.
    pub(crate) from_grants: BTreeSet<ItemId>,
    /// Vaults where an environment's person version could not be learned.
    pub(crate) uncertain: BTreeSet<VaultId>,
    pub(crate) person_versions: BTreeMap<ItemId, CachedEnvVersion>,
}

impl Protection {
    /// Reads [`PROTECTION_FILE`]. Absent: nothing protected yet. One that
    /// exists and does not open counts as unknown ([`Self::unreadable`]):
    /// it fails closed until the next refresh.
    pub(crate) fn load(home: &Home, key: &LocalKey, ctx: &LocalContext) -> Self {
        let blob = match std::fs::read(home.file(PROTECTION_FILE)) {
            Ok(blob) => blob,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Self::default(),
            Err(_) => {
                return Self {
                    unreadable: true,
                    ..Self::default()
                };
            }
        };
        match open_local_data(key, ctx, PURPOSE_PROTECTION, &blob)
            .ok()
            .and_then(|json| serde_json::from_slice::<ProtectionFile>(&json).ok())
            .filter(|f| f.v == PROTECTION_VERSION)
        {
            Some(f) => Self {
                unreadable: false,
                contributions: f.contributions,
                seen: f.seen,
                from_grants: f.from_grants,
                uncertain: f.uncertain,
                person_versions: f.person_versions,
            },
            None => Self {
                unreadable: true,
                ..Self::default()
            },
        }
    }

    pub(crate) fn save(&self, home: &Home, key: &LocalKey, ctx: &LocalContext) -> ClientResult<()> {
        let json = Zeroizing::new(
            serde_json::to_vec(&ProtectionFile {
                v: PROTECTION_VERSION,
                contributions: self.contributions.clone(),
                seen: self.seen.clone(),
                from_grants: self.from_grants.clone(),
                uncertain: self.uncertain.clone(),
                person_versions: self.person_versions.clone(),
            })
            .expect("serializes"),
        );
        let blob = seal_local_data(key, ctx, PURPOSE_PROTECTION, &json)?;
        home.ensure()?;
        write_private(&home.file(PROTECTION_FILE), &blob)
    }

    /// The protected environments.
    pub(crate) fn environments(&self) -> BTreeSet<ItemId> {
        self.contributions
            .iter()
            .filter(|(_, c)| c.protected)
            .map(|(id, _)| *id)
            .collect()
    }

    /// Items some contribution protects (environments included).
    fn named(&self) -> BTreeSet<ItemId> {
        let mut out = self.environments();
        for c in self.contributions.values() {
            out.extend(c.items.iter().copied());
        }
        out
    }

    /// Whether the set may drop `item`: this device knows every
    /// environment's person version, saw `item` protected once, and no
    /// environment protects it now.
    pub(crate) fn releasable(&self, item: ItemId) -> bool {
        !self.unreadable
            && self.uncertain.is_empty()
            && self.seen.contains(&item)
            && !self.named().contains(&item)
    }

    /// The protected set: environments, the items they protect, and what
    /// the grants protect that this device cannot release.
    pub fn items(&self) -> BTreeSet<ItemId> {
        let mut out = self.named();
        out.extend(
            self.from_grants
                .iter()
                .copied()
                .filter(|i| !self.releasable(*i)),
        );
        out
    }

    /// Whether `item` asks for presence every time.
    pub fn protects(&self, item: ItemId) -> bool {
        self.items().contains(&item)
    }

    /// Why `item` is protected, by environment name; empty when it is not.
    pub fn protected_by(&self, item: ItemId) -> Vec<String> {
        let mut names: Vec<String> = self
            .contributions
            .iter()
            .filter(|(id, c)| (c.protected && **id == item) || c.items.contains(&item))
            .map(|(_, c)| c.title.clone())
            .collect();
        names.sort();
        names.dedup();
        if names.is_empty() && self.from_grants.contains(&item) && !self.releasable(item) {
            names.push("a protected environment".into());
        }
        names
    }

    /// Whether nothing is known for `vault` (or for any vault).
    pub fn uncertain(&self, vault: VaultId) -> bool {
        self.unreadable || self.uncertain.contains(&vault)
    }
}

/// An environment item as the session sees it.
#[derive(Debug, Clone)]
pub(crate) struct EnvEntry {
    pub(crate) loc: ItemLocation,
    pub(crate) version: u64,
    pub(crate) author: Option<AgentId>,
    pub(crate) updated_at: i64,
    pub(crate) title: String,
    pub(crate) trashed: bool,
}

/// One environment, for `klav env ls`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvironmentListing {
    /// The item.
    pub id: ItemId,
    /// Vault ID and name.
    pub vault_id: VaultId,
    pub vault: String,
    /// Project ID and name.
    pub project_id: ProjectId,
    pub project: String,
    /// Its name.
    pub name: String,
    /// How many variables.
    pub variables: usize,
    /// Protected (the effective flag, ADR 0032 §3).
    pub protected: bool,
    /// Last change (Unix ms).
    pub updated_at: i64,
    /// The agent that wrote the current version, if one did.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author_agent_id: Option<AgentId>,
}

/// Where a variable's value comes from, without the value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "origin", rename_all = "snake_case")]
pub enum VariableOrigin {
    /// Its own value, stored in the environment.
    Value,
    /// A field of another item.
    Reference {
        /// The reference as stored (four IDs).
        reference: String,
        /// The item and field by name ("Stripe › api_key"), when this
        /// device sees it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        target: Option<String>,
        /// The target is in the protected set.
        #[serde(default)]
        protected: bool,
    },
}

/// One variable, without its value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VariableView {
    /// Its name.
    pub name: String,
    /// Value or reference.
    #[serde(flatten)]
    pub origin: VariableOrigin,
    /// `klav://<vault>/<project>/<environment>/<NAME>` by IDs: what `run`,
    /// `inject` and `--reveal` resolve.
    pub resolve: String,
}

/// The variables an agent changed since the person's latest version (ADR
/// 0032 §3, answer 7).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentChanges {
    /// The agent that wrote the current version.
    pub agent_id: AgentId,
    /// Its name, when this device could learn it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
    /// When (Unix ms).
    pub at: i64,
    /// Variables added, changed or removed since the person's version.
    pub variables: Vec<String>,
}

/// One environment, for `klav env show`, `run` and `inject`: names and
/// origins, never values.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvironmentDetail {
    #[serde(flatten)]
    pub listing: EnvironmentListing,
    /// Its variables, in order.
    pub variables: Vec<VariableView>,
    /// What an agent changed since the person's latest version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_changes: Option<AgentChanges>,
}

/// A variable to set.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewVariable {
    /// Its name.
    pub name: String,
    /// Its own value…
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<SecretText>,
    /// …or a `klav://` reference (by name or by IDs).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
}

impl std::fmt::Debug for NewVariable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewVariable")
            .field("name", &self.name)
            .field("value", &self.value.as_ref().map(|_| "…"))
            .field("reference", &self.reference)
            .finish()
    }
}

/// A change to an environment (`klav env create|set|rm|import`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct EnvironmentEdit {
    /// Create it if it does not exist (else: it must exist).
    pub create: bool,
    /// Must not exist yet (`klav env create`).
    pub must_be_new: bool,
    /// Turn `protected` on or off.
    pub protected: Option<bool>,
    /// Variables to add or replace.
    pub set: Vec<NewVariable>,
    /// Variables to remove.
    pub remove: Vec<String>,
}

/// What a prepared edit would do.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvironmentPlan {
    /// The environment's name.
    pub name: String,
    /// It is new.
    pub created: bool,
    /// Protected after the edit.
    pub protected: bool,
    /// Items that become protected, by name.
    pub newly_protected: Vec<String>,
    /// Items that stop being protected by it, by name.
    pub unprotected: Vec<String>,
    /// The edit lowers the protection: presence first (ADR 0032 §3).
    pub shrinks: bool,
    /// Variables an agent changed since the person's version, overwritten
    /// by this edit.
    #[serde(default)]
    pub warnings: Vec<String>,
}

/// An edit ready to commit ([`Unlocked::prepare_environment`]).
pub struct PreparedEnvironment {
    loc: ItemLocation,
    item: Item,
    exists: bool,
    grow: BTreeSet<ItemId>,
    shrink: BTreeSet<ItemId>,
    /// What it would do.
    pub plan: EnvironmentPlan,
}

/// What saving did.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EnvironmentSaved {
    /// The environment's name.
    pub name: String,
    /// Its item.
    pub id: Option<ItemId>,
    /// It was created.
    pub created: bool,
    /// Protected after the edit.
    pub protected: bool,
    /// Items that became protected, by name.
    pub newly_protected: Vec<String>,
    /// Items it stopped protecting, by name.
    pub unprotected: Vec<String>,
    /// Agents whose grants were issued again, by name.
    pub agents: Vec<String>,
    /// What did not work (a grant that could not release an item: it stays
    /// over-protected until the next change).
    pub warnings: Vec<String>,
}

/// What one variable of the value comparison of `klav env import` is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImportStatus {
    /// Not in the environment yet.
    New,
    /// In it, with another value or a reference.
    Changed,
    /// In it with the same value (or a reference to the same value).
    Same,
}

/// The review of one variable of `klav env import`, never with its value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportReview {
    /// Its name.
    pub name: String,
    /// New, changed or the same.
    pub status: ImportStatus,
    /// A field of an existing item with the same value: proposed as a
    /// reference instead of a copy (by IDs), with its name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matches: Option<ImportMatch>,
}

/// A field with the same value as an imported variable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportMatch {
    /// `klav://` by IDs.
    pub reference: String,
    /// "Vault/Project/Item › field".
    pub name: String,
    /// That item is already protected.
    pub protected: bool,
}

/// Whether the edit's references and variables are well formed.
fn check_variable_name(name: &str) -> ClientResult<()> {
    klav_core::model::environment::validate_variable_name(name)
        .map_err(|_| ClientError::Invalid(format!("invalid variable name {name:?}")))
}

/// The reference that resolves variable `name` of the environment at `loc`.
pub fn variable_reference(loc: ItemLocation, name: &str) -> String {
    format!("klav://{}/{}/{}/{name}", loc.vault, loc.project, loc.item)
}

impl Unlocked {
    // ------------------------------------------------------- protection --

    /// What this device knows of the protection.
    pub fn protection(&self) -> &Protection {
        &self.protection
    }

    /// Recomputes what the environments protect from the person's versions
    /// (fetching the ones an agent's current version hides), and saves it.
    /// Called after every sync; what it cannot learn leaves that vault
    /// uncertain, with a notice.
    pub(crate) async fn refresh_protection(&mut self, notices: &mut Vec<String>) {
        let entries = self.environment_entries();
        let mut next: BTreeMap<ItemId, Contribution> = BTreeMap::new();
        let mut uncertain = BTreeSet::new();
        let mut keep_versions = BTreeMap::new();
        for entry in &entries {
            match self.person_environment(entry).await {
                Ok((person, cached)) => {
                    if let Some(cached) = cached {
                        keep_versions.insert(entry.loc.item, cached);
                    }
                    let contribution = match &person {
                        Some((item, _)) => contribution_of(entry.loc.vault, item),
                        // Only agents wrote it: its references protect
                        // nothing; it is protected itself if its flag is on
                        // or its name is production's (fails closed).
                        None => {
                            let current = self.open_item(entry.loc).ok();
                            let protected = match current
                                .as_ref()
                                .and_then(|i| i.environment().map(|e| (i.title().to_owned(), e)))
                            {
                                Some((title, env)) => effective_protected(&[EnvironmentVersion {
                                    item: entry.loc.item,
                                    version: entry.version,
                                    author: Author::Agent,
                                    title: &title,
                                    environment: env,
                                }]),
                                None => true,
                            };
                            Contribution {
                                vault: Some(entry.loc.vault),
                                title: entry.title.clone(),
                                protected,
                                items: BTreeSet::new(),
                            }
                        }
                    };
                    next.insert(entry.loc.item, contribution);
                }
                Err(why) => {
                    uncertain.insert(entry.loc.vault);
                    notices.push(format!(
                        "environment {:?}: Klav cannot read the person's latest version ({why}); \
                         every value of its vault asks for your presence, and no grant is signed, \
                         until the next sync works",
                        entry.title
                    ));
                    let kept = self
                        .protection
                        .contributions
                        .get(&entry.loc.item)
                        .cloned()
                        .unwrap_or(Contribution {
                            vault: Some(entry.loc.vault),
                            title: entry.title.clone(),
                            protected: true,
                            items: BTreeSet::new(),
                        });
                    next.insert(entry.loc.item, kept);
                }
            }
        }
        // An environment this device no longer sees (purged, or in a
        // project or vault that does not open) keeps what it protected:
        // there is no person's version that leaves anything out.
        for (id, c) in &self.protection.contributions {
            next.entry(*id).or_insert_with(|| c.clone());
        }
        let mut seen = self.protection.seen.clone();
        for (id, c) in &next {
            if c.protected {
                seen.insert(*id);
            }
            seen.extend(c.items.iter().copied());
        }
        let updated = Protection {
            unreadable: false,
            contributions: next,
            seen,
            from_grants: self.protection.from_grants.clone(),
            uncertain,
            person_versions: keep_versions,
        };
        if let Err(e) = updated.save(&self.home, &self.local_key, &self.ctx) {
            notices.push(format!("cannot save what environments protect: {e}"));
        }
        self.protection = updated;
    }

    /// The person's latest version of an environment, opened: the current
    /// one when the person wrote it, else fetched (and kept for as long as
    /// the item's version and its project's key don't change). `None`
    /// inside: no version of the person.
    #[allow(clippy::type_complexity)]
    async fn person_environment(
        &mut self,
        entry: &EnvEntry,
    ) -> Result<(Option<(Item, i64)>, Option<CachedEnvVersion>), String> {
        if entry.author.is_none() {
            let item = self.open_item(entry.loc).map_err(|e| e.to_string())?;
            return Ok((Some((item, entry.updated_at)), None));
        }
        let project_version = self
            .projects
            .get(&entry.loc.project)
            .map_or(0, |p| p.version);
        let cached = match self.protection.person_versions.get(&entry.loc.item) {
            Some(c) if c.for_version == entry.version && c.project_version == project_version => {
                c.clone()
            }
            _ => CachedEnvVersion {
                for_version: entry.version,
                project_version,
                found: self
                    .fetch_person_version(entry.loc)
                    .await
                    .map_err(|e| e.to_string())?,
            },
        };
        let opened = match &cached.found {
            Some(blobs) => Some((
                self.open_blobs(entry.loc, blobs)
                    .map_err(|e| e.to_string())?,
                blobs.created_at,
            )),
            None => None,
        };
        Ok((opened, Some(cached)))
    }

    /// The last stored version of an item the person wrote, whole.
    async fn fetch_person_version(
        &mut self,
        loc: ItemLocation,
    ) -> ClientResult<Option<EnvVersionBlobs>> {
        let history: ItemHistory = self
            .get(&format!(
                "/v1/vaults/{}/items/{}/versions",
                loc.vault, loc.item
            ))
            .await?;
        let Some(wanted) = history
            .versions
            .iter()
            .find(|v| v.author_agent_id.is_none())
            .map(|v| v.version)
        else {
            return Ok(None);
        };
        let got: ItemVersion = self
            .get(&format!(
                "/v1/vaults/{}/items/{}/versions/{wanted}",
                loc.vault, loc.item
            ))
            .await?;
        if got.item_id != loc.item || got.version != wanted || got.author_agent_id.is_some() {
            return Err(ClientError::Security(format!(
                "the server answered another version than {wanted} of item {}",
                loc.item
            )));
        }
        Ok(Some(EnvVersionBlobs {
            version: got.version,
            project_id: got.project_id,
            created_at: got.created_at,
            wrapped_key: got.wrapped_key,
            overview: got.overview,
            details: got.details,
        }))
    }

    fn open_blobs(&self, loc: ItemLocation, blobs: &EnvVersionBlobs) -> ClientResult<Item> {
        let project = self
            .projects
            .get(&blobs.project_id)
            .ok_or_else(|| ClientError::NotFound(format!("project {}", blobs.project_id)))?;
        let (_, owner) = self.vault_key(loc.vault)?;
        let ctx = ItemContext {
            account: owner,
            vault: loc.vault,
            project: blobs.project_id,
            item: loc.item,
        };
        let key = unwrap_item_key(&project.key, &ctx, blobs.wrapped_key.as_bytes())?;
        let item = open_item(
            &key,
            &ctx,
            blobs.version,
            &SealedItem {
                overview: blobs.overview.as_bytes().to_vec(),
                details: blobs.details.as_bytes().to_vec(),
            },
        )?;
        if item.kind() != ItemKind::Environment {
            return Err(ClientError::Corrupt(format!(
                "the person's version of {} is not an environment",
                loc.item
            )));
        }
        Ok(item)
    }

    /// Why reading these items needs presence every time (ADR 0032 §3 and
    /// §3.1), in words for the prompt; `None` when it does not.
    pub fn protection_reason(&self, items: &[ItemLocation]) -> Option<String> {
        let set = self.protection.items();
        for loc in items {
            if self.protection.uncertain(loc.vault) {
                return Some(
                    "Klav cannot tell what this vault's protected environments protect until the \
                     next sync works, so every value asks"
                        .into(),
                );
            }
            if !set.contains(&loc.item) {
                continue;
            }
            let title = self
                .item_summary(*loc)
                .map_or_else(|_| loc.item.to_string(), |s| s.title);
            let by = self.protection.protected_by(loc.item);
            return Some(if by.len() == 1 && by[0] == title {
                format!("“{title}” is a protected environment")
            } else {
                format!("uses “{title}”, protected by “{}”", by.join("”, “"))
            });
        }
        None
    }

    /// The items `references` read, the hop of an environment's reference
    /// included (what [`Self::protection_reason`] checks for `run` and
    /// `inject`).
    pub fn reference_targets(&self, references: &[String]) -> ClientResult<Vec<ItemLocation>> {
        let mut out = Vec::new();
        for reference in references {
            let (loc, hop) = self.reference_locations(reference)?;
            out.push(loc);
            out.extend(hop);
        }
        Ok(out)
    }

    /// Where a reference points, and, through an environment's reference
    /// variable, the item behind it.
    pub(crate) fn reference_locations(
        &self,
        reference: &str,
    ) -> ClientResult<(ItemLocation, Option<ItemLocation>)> {
        let parsed = Reference::parse(reference.trim())?;
        let resolved = parsed.resolve(self)?;
        let loc = ItemLocation {
            vault: resolved.vault,
            project: resolved.project,
            item: resolved.item,
        };
        let item = self.open_item(loc)?;
        if item.kind() != ItemKind::Environment {
            resolve_field(&item, &resolved.field)?;
            return Ok((loc, None));
        }
        let variable = resolve_variable(&item, &resolved.field)?;
        match variable.source() {
            VariableSource::Value(_) => Ok((loc, None)),
            VariableSource::Ref(target) => {
                let (hop, _) = self.target_of(target)?;
                Ok((loc, Some(hop)))
            }
        }
    }

    /// The item and field an environment's reference points to (never
    /// another environment).
    fn target_of(&self, target: &Reference) -> ClientResult<(ItemLocation, Item)> {
        let resolved = target.resolve(self)?;
        let loc = ItemLocation {
            vault: resolved.vault,
            project: resolved.project,
            item: resolved.item,
        };
        let item = self.open_item(loc)?;
        if item.kind() == ItemKind::Environment {
            return Err(ClientError::Invalid(
                "a variable points to another environment".into(),
            ));
        }
        resolve_field(&item, &resolved.field)?;
        Ok((loc, item))
    }

    /// The value of variable `field` of the environment `item` (`run`,
    /// `inject`): its own, or the field its reference points to; an
    /// attachment only as UTF-8 text of up to 64 KiB (ADR 0032 §1).
    pub(crate) async fn variable_value(
        &mut self,
        item: &Item,
        field: &Selector<FieldId>,
    ) -> ClientResult<SecretBytes> {
        let variable = resolve_variable(item, field)?;
        let name = variable.name().to_owned();
        let target = match variable.source() {
            VariableSource::Value(value) => {
                return Ok(SecretBytes::new(Zeroizing::new(
                    value.expose().as_bytes().to_vec(),
                )));
            }
            VariableSource::Ref(target) => target.clone(),
        };
        let resolved = target.resolve(&*self)?;
        let (loc, target_item) = self.target_of(&target)?;
        let field = resolve_field(&target_item, &resolved.field)?;
        let bytes = match field.value() {
            FieldValue::Plain(s) => Zeroizing::new(s.as_bytes().to_vec()),
            FieldValue::Secret(s) => Zeroizing::new(s.expose().as_bytes().to_vec()),
            FieldValue::File(id) => {
                let id = *id;
                let content = self.download_attachment(loc, id).await?;
                if content.len() > MAX_VARIABLE_ATTACHMENT || std::str::from_utf8(&content).is_err()
                {
                    return Err(ClientError::Invalid(format!(
                        "{name}: its reference is an attachment that is not UTF-8 text of up to \
                         64 KiB; use [files] in klav.toml"
                    )));
                }
                content
            }
        };
        Ok(SecretBytes::new(bytes))
    }

    /// Whether an approval or a task for `item` must ask every time: no
    /// lease, no task (ADR 0032 §3.1, the cards of `klavd`).
    pub fn always_asks(&self, item: ItemId) -> bool {
        self.protection.protects(item)
            || self
                .locate(item)
                .is_some_and(|(loc, _)| self.protection.uncertain(loc.vault))
    }

    /// Adds what the `origin: "protected"` rules of a verified grant name
    /// to what feeds the set (§3.1), and saves it if it changed.
    pub(crate) fn note_grant_protection(&mut self, payload: &GrantPayload) {
        let before = self.protection.from_grants.len();
        self.protection.from_grants.extend(
            payload
                .policy
                .rules
                .iter()
                .filter(|r| r.is_protected())
                .flat_map(|r| r.scope.items.iter().copied()),
        );
        if self.protection.from_grants.len() != before {
            let _ = self.protection.save(&self.home, &self.local_key, &self.ctx);
        }
    }

    /// Writes the protection into a grant about to be signed (ADR 0032
    /// §3.1 and §4.3): keeps every inherited rule of `previous` (the grant
    /// in force, verified) except for items this device has proof to
    /// release, which go in `released`; adds `ask once` rules for the
    /// protected items the grant reaches; and, before the first inherited
    /// rule of a permission that had none, writes its default as an
    /// explicit rule (ADR 0006 §2). Refuses while this device does not
    /// know what some vault protects.
    pub(crate) fn protect_grant(
        &mut self,
        payload: &mut GrantPayload,
        previous: Option<&GrantPayload>,
    ) -> ClientResult<()> {
        if let Some(previous) = previous {
            self.note_grant_protection(previous);
        }
        let previous_items: BTreeSet<ItemId> = previous
            .map(|p| {
                p.policy
                    .protected_pairs()
                    .into_iter()
                    .map(|(_, i)| i)
                    .collect()
            })
            .unwrap_or_default();
        let set = self.protection.items();
        let projects: BTreeSet<ProjectId> = payload.projects.iter().map(|p| p.project_id).collect();
        let granted_items: BTreeSet<ItemId> = payload.items.iter().map(|i| i.item_id).collect();
        let reachable: BTreeSet<ItemId> = set
            .iter()
            .copied()
            .filter(|id| {
                granted_items.contains(id)
                    || self
                        .locate(*id)
                        .or_else(|| {
                            self.pending_protection
                                .filter(|p| p.item == *id)
                                .map(|p| (p, ItemKind::Environment))
                        })
                        .is_some_and(|(loc, _)| projects.contains(&loc.project))
            })
            .collect();
        let released: BTreeSet<ItemId> = previous_items
            .iter()
            .copied()
            .filter(|i| self.protection.releasable(*i) && !reachable.contains(i))
            .collect();
        let mut keep: BTreeSet<ItemId> = previous_items.difference(&released).copied().collect();
        keep.extend(reachable);
        let had_protected = payload.policy.rules.iter().any(Rule::is_protected);
        if keep.is_empty() && released.is_empty() && !had_protected {
            return Ok(());
        }
        if !keep.is_empty() && (self.protection.unreadable || !self.protection.uncertain.is_empty())
        {
            return Err(ClientError::Invalid(
                "Klav cannot tell what a protected environment protects until the next sync \
                 works; no grant is signed until then"
                    .into(),
            ));
        }
        write_protection(&mut payload.policy, &keep);
        payload.released = released.into_iter().collect();
        payload
            .policy
            .check_once()
            .map_err(|e| ClientError::Invalid(e.to_string()))?;
        Ok(())
    }

    // ------------------------------------------------------ environments --

    /// The environments of `project` (`vault/project`, a project name or
    /// ID), or of every project.
    pub fn environments(&self, project: Option<&str>) -> ClientResult<Vec<EnvironmentListing>> {
        let only = project.map(|p| self.find_project_anywhere(p)).transpose()?;
        let mut out: Vec<EnvironmentListing> = self
            .environment_entries()
            .into_iter()
            .filter(|e| !e.trashed && only.is_none_or(|p| p == e.loc.project))
            .filter_map(|e| self.listing(&e).ok())
            .collect();
        out.sort_by(|a, b| (&a.vault, &a.project, &a.name).cmp(&(&b.vault, &b.project, &b.name)));
        Ok(out)
    }

    fn listing(&self, e: &EnvEntry) -> ClientResult<EnvironmentListing> {
        let summary = self.item_summary(e.loc)?;
        let item = self.open_item(e.loc)?;
        let variables = item.environment().map_or(0, |env| env.variables().len());
        Ok(EnvironmentListing {
            id: e.loc.item,
            vault_id: e.loc.vault,
            vault: summary.vault,
            project_id: e.loc.project,
            project: summary.project,
            name: e.title.clone(),
            variables,
            protected: self.environment_protected(e.loc.item, &item),
            updated_at: e.updated_at,
            author_agent_id: e.author,
        })
    }

    /// The effective flag: the person's version's, as the protection
    /// state has it; failing closed with the current version.
    fn environment_protected(&self, id: ItemId, current: &Item) -> bool {
        match self.protection.contributions.get(&id) {
            Some(c) => c.protected,
            None => {
                current.environment().is_some_and(Environment::protected)
                    || is_production_name(current.title())
            }
        }
    }

    /// The live environment called `name` in `project`.
    pub(crate) fn find_environment(
        &self,
        project: ProjectId,
        name: &str,
    ) -> ClientResult<Option<EnvEntry>> {
        let mut found: Vec<EnvEntry> = self
            .environment_entries()
            .into_iter()
            .filter(|e| !e.trashed && e.loc.project == project && e.title == name)
            .collect();
        match found.len() {
            0 => Ok(None),
            1 => Ok(found.pop()),
            _ => Err(ClientError::Ambiguous(format!(
                "project has {} environments called {name:?}",
                found.len()
            ))),
        }
    }

    /// A project by `vault/project`, a name unique across vaults or an ID;
    /// with none, the default vault's default project.
    pub fn environment_project(&self, project: Option<&str>) -> ClientResult<ProjectId> {
        match project {
            Some(p) => self.find_project_anywhere(p).or_else(|e| {
                self.projects
                    .keys()
                    .find(|id| id.to_string() == p)
                    .copied()
                    .ok_or(e)
            }),
            None => Ok(self.destination(None, None)?.1),
        }
    }

    /// One environment: names, origins and what an agent changed; never a
    /// value. `None`: there is none of that name.
    pub async fn environment_detail(
        &mut self,
        project: Option<&str>,
        name: &str,
    ) -> ClientResult<Option<EnvironmentDetail>> {
        let project = self.environment_project(project)?;
        let Some(entry) = self.find_environment(project, name)? else {
            return Ok(None);
        };
        let listing = self.listing(&entry)?;
        let item = self.open_item(entry.loc)?;
        let set = self.protection.items();
        let mut variables = Vec::new();
        for v in item
            .environment()
            .map(Environment::variables)
            .unwrap_or(&[])
        {
            let origin = match v.source() {
                VariableSource::Value(_) => VariableOrigin::Value,
                VariableSource::Ref(target) => {
                    let named = self.target_of(target).ok().and_then(|(loc, it)| {
                        let resolved = target.resolve(&*self).ok()?;
                        let field = resolve_field(&it, &resolved.field).ok()?;
                        Some((loc, format!("{} › {}", it.title(), field.name())))
                    });
                    VariableOrigin::Reference {
                        reference: target.to_string(),
                        protected: named
                            .as_ref()
                            .is_some_and(|(loc, _)| set.contains(&loc.item)),
                        target: named.map(|(_, n)| n),
                    }
                }
            };
            variables.push(VariableView {
                name: v.name().to_owned(),
                origin,
                resolve: variable_reference(entry.loc, v.name()),
            });
        }
        let agent_changes = match entry.author {
            Some(agent) => {
                let person = self.person_environment(&entry).await.ok().and_then(|p| p.0);
                let changed = changed_variables(person.as_ref().map(|(i, _)| i), &item);
                if changed.is_empty() {
                    None
                } else {
                    let name = self
                        .agents()
                        .await
                        .ok()
                        .and_then(|list| list.into_iter().find(|a| a.id == agent))
                        .map(|a| a.name);
                    Some(AgentChanges {
                        agent_id: agent,
                        agent: name,
                        at: entry.updated_at,
                        variables: changed,
                    })
                }
            }
            None => None,
        };
        Ok(Some(EnvironmentDetail {
            listing,
            variables,
            agent_changes,
        }))
    }

    /// A reference given by the person, as an environment stores it: four
    /// IDs, to a field of an item that is not an environment.
    fn stored_reference(&self, name: &str, text: &str) -> ClientResult<(Reference, ItemId)> {
        let parsed = Reference::parse(text.trim())?;
        let resolved = parsed.resolve(self)?;
        let loc = ItemLocation {
            vault: resolved.vault,
            project: resolved.project,
            item: resolved.item,
        };
        let item = self.open_item(loc)?;
        if item.kind() == ItemKind::Environment {
            return Err(ClientError::Invalid(format!(
                "{name}: a variable cannot point to another environment"
            )));
        }
        let field = resolve_field(&item, &resolved.field)?;
        Ok((
            Reference {
                vault: Selector::Id(loc.vault),
                project: Selector::Id(loc.project),
                item: Selector::Id(loc.item),
                field: Selector::Id(field.id()),
            },
            loc.item,
        ))
    }

    fn item_name(&self, id: ItemId) -> String {
        self.locate(id)
            .and_then(|(loc, _)| self.item_summary(loc).ok())
            .map_or_else(|| format!("item {id}"), |s| s.title)
    }

    /// Syncs (a failed sync or a rollback stops here: nothing is signed or
    /// saved on an old view), then builds the new version of environment
    /// `name` and works out what it does to the protection.
    pub async fn prepare_environment(
        &mut self,
        project: Option<&str>,
        name: &str,
        edit: &EnvironmentEdit,
    ) -> ClientResult<PreparedEnvironment> {
        klav_core::model::environment::validate_environment_name(name).map_err(|_| {
            ClientError::Invalid(format!(
                "invalid environment name {name:?}: use [a-z0-9][a-z0-9_-]{{0,63}}"
            ))
        })?;
        self.sync().await?;
        let project = self.environment_project(project)?;
        let vault = self
            .projects
            .get(&project)
            .map(|p| p.vault)
            .ok_or_else(|| ClientError::NotFound(format!("project {project}")))?;
        let existing = self.find_environment(project, name)?;
        if existing.is_some() && edit.must_be_new {
            return Err(ClientError::Invalid(format!(
                "environment {name:?} already exists"
            )));
        }
        let mut warnings = Vec::new();
        let (loc, mut item, exists) = match &existing {
            Some(entry) => {
                if let Some(agent) = entry.author {
                    let person = self.person_environment(entry).await.ok().and_then(|p| p.0);
                    let current = self.open_item(entry.loc)?;
                    let changed = changed_variables(person.as_ref().map(|(i, _)| i), &current);
                    if !changed.is_empty() {
                        warnings.push(format!(
                            "agent {agent} changed {} since your last version; saving keeps its \
                             changes in your version",
                            changed.join(", ")
                        ));
                    }
                }
                (entry.loc, self.open_item(entry.loc)?, true)
            }
            None if edit.create => {
                let item = Item::new(ItemKind::Environment, name)?;
                let loc = ItemLocation {
                    vault,
                    project,
                    item: item.id(),
                };
                (loc, item, false)
            }
            None => return Err(ClientError::NotFound(format!("environment {name:?}"))),
        };
        let before = self
            .protection
            .contributions
            .get(&loc.item)
            .cloned()
            .unwrap_or_default();
        let env = item
            .environment_mut()
            .ok_or_else(|| ClientError::Corrupt("environment without variables".into()))?;
        if let Some(protected) = edit.protected {
            env.set_protected(protected);
        }
        for name in &edit.remove {
            if env.remove(name).is_none() {
                return Err(ClientError::NotFound(format!("variable {name:?}")));
            }
        }
        // References resolve against this device's view; values are moved
        // in as they are, never printed.
        let mut refs = Vec::new();
        for new in &edit.set {
            check_variable_name(&new.name)?;
            match (&new.value, &new.reference) {
                (Some(_), None) | (None, Some(_)) => {}
                _ => {
                    return Err(ClientError::Invalid(format!(
                        "{}: give a value or a reference, not both",
                        new.name
                    )));
                }
            }
            if let Some(text) = &new.reference {
                refs.push((new.name.clone(), self.stored_reference(&new.name, text)?.0));
            }
        }
        let env = item
            .environment_mut()
            .ok_or_else(|| ClientError::Corrupt("environment without variables".into()))?;
        let mut refs = refs.into_iter();
        for new in &edit.set {
            let variable = match &new.value {
                Some(value) => Variable::with_value(&new.name, value.expose())?,
                None => {
                    let (_, reference) = refs.next().expect("one per reference");
                    Variable::with_reference(&new.name, reference)?
                }
            };
            env.set(variable)?;
        }
        let own = loc.item;
        item.environment()
            .expect("an environment")
            .check_references(own, |id| self.locate(id).map(|(_, k)| k))?;
        let after = contribution_of(loc.vault, &item);
        let mut before_all = before.items.clone();
        if before.protected {
            before_all.insert(own);
        }
        let mut after_all = after.items.clone();
        if after.protected {
            after_all.insert(own);
        }
        let set = self.protection.items();
        let grow: BTreeSet<ItemId> = after_all
            .iter()
            .copied()
            .filter(|i| !set.contains(i) || !before_all.contains(i))
            .collect();
        let shrink: BTreeSet<ItemId> = before_all.difference(&after_all).copied().collect();
        let names = |ids: &BTreeSet<ItemId>| -> Vec<String> {
            ids.iter()
                .filter(|i| **i != own)
                .map(|i| self.item_name(*i))
                .collect()
        };
        let plan = EnvironmentPlan {
            name: name.to_owned(),
            created: !exists,
            protected: after.protected,
            newly_protected: names(&grow.difference(&set).copied().collect()),
            unprotected: names(&shrink),
            // Turning `protected` off, or removing a reference of a
            // protected environment, lowers the protection (§3).
            shrinks: before.protected && !shrink.is_empty(),
            warnings,
        };
        Ok(PreparedEnvironment {
            loc,
            item,
            exists,
            grow,
            shrink,
            plan,
        })
    }

    /// The agents whose grants reach any of `items` (by their project, or
    /// shared one by one), issued again: the grant first when the
    /// protection grows (§3.1).
    async fn regrant_for(
        &mut self,
        items: &BTreeSet<ItemId>,
    ) -> ClientResult<crate::item_grants::Regrants> {
        let mut projects = Vec::new();
        for id in items {
            if let Some((loc, _)) = self.locate(*id) {
                projects.push(loc.project);
            }
        }
        let items: Vec<ItemId> = items.iter().copied().collect();
        self.regrant_agents(&projects, &items, None).await
    }

    /// Saves a prepared version (ADR 0032 §3.1): when the protection grows,
    /// the affected grants are issued again **first**, and if one fails the
    /// version is not saved; when it shrinks, the version goes first and
    /// then the grants, which name what they release. Presence for a
    /// shrinking edit is the caller's ([`EnvironmentPlan::shrinks`]).
    pub async fn commit_environment(
        &mut self,
        prepared: PreparedEnvironment,
    ) -> ClientResult<EnvironmentSaved> {
        let PreparedEnvironment {
            loc,
            item,
            exists,
            grow,
            shrink,
            plan,
        } = prepared;
        let mut saved = EnvironmentSaved {
            name: plan.name.clone(),
            id: Some(loc.item),
            created: plan.created,
            protected: plan.protected,
            newly_protected: plan.newly_protected.clone(),
            unprotected: plan.unprotected.clone(),
            agents: Vec::new(),
            warnings: plan.warnings.clone(),
        };
        if !grow.is_empty() {
            // The grants see the new protection before the version exists.
            let previous = self.protection.contributions.get(&loc.item).cloned();
            let mut grown = previous.clone().unwrap_or(Contribution {
                vault: Some(loc.vault),
                title: plan.name.clone(),
                protected: false,
                items: BTreeSet::new(),
            });
            grown.title.clone_from(&plan.name);
            if grow.contains(&loc.item) {
                grown.protected = true;
            }
            grown
                .items
                .extend(grow.iter().copied().filter(|i| *i != loc.item));
            self.protection.contributions.insert(loc.item, grown);
            self.protection.seen.extend(grow.iter().copied());
            let mut reach = grow.clone();
            reach.insert(loc.item);
            let outcome = self.regrant_for_new(&reach, loc).await;
            let regrants = match outcome {
                Ok(r) if r.failed.is_empty() => r,
                Ok(r) => {
                    self.restore_contribution(loc.item, previous);
                    return Err(ClientError::Invalid(format!(
                        "could not protect {} for {}: the environment was not saved",
                        name_list(&plan.newly_protected, &plan.name),
                        r.failed.join("; ")
                    )));
                }
                Err(e) => {
                    self.restore_contribution(loc.item, previous);
                    return Err(ClientError::Invalid(format!(
                        "could not protect {} for the agents ({e}): the environment was not saved",
                        name_list(&plan.newly_protected, &plan.name)
                    )));
                }
            };
            saved.agents.extend(regrants.done);
        }
        if exists {
            self.put_item(loc, &item, &[]).await?;
        } else {
            self.post_item(loc.vault, loc.project, &item).await?;
        }
        self.sync().await?;
        if !shrink.is_empty() {
            match self.regrant_for(&shrink).await {
                Ok(r) => {
                    for name in r.done {
                        if !saved.agents.contains(&name) {
                            saved.agents.push(name);
                        }
                    }
                    for failed in r.failed {
                        saved.warnings.push(format!(
                            "{failed}: its grant still protects what this version released, \
                             until its next change"
                        ));
                    }
                }
                Err(e) => saved.warnings.push(format!(
                    "the grants still protect what this version released, until their next \
                     change ({e})"
                )),
            }
        }
        Ok(saved)
    }

    /// [`Self::regrant_for`], with the environment itself, which may not be
    /// in this device's view yet: its project counts.
    async fn regrant_for_new(
        &mut self,
        items: &BTreeSet<ItemId>,
        env: ItemLocation,
    ) -> ClientResult<crate::item_grants::Regrants> {
        let mut projects = vec![env.project];
        for id in items {
            if let Some((loc, _)) = self.locate(*id) {
                projects.push(loc.project);
            }
        }
        let items: Vec<ItemId> = items.iter().copied().collect();
        self.pending_protection = Some(env);
        let out = self.regrant_agents(&projects, &items, None).await;
        self.pending_protection = None;
        out
    }

    fn restore_contribution(&mut self, id: ItemId, previous: Option<Contribution>) {
        match previous {
            Some(c) => self.protection.contributions.insert(id, c),
            None => self.protection.contributions.remove(&id),
        };
    }

    /// Moves environment `name` to the trash. A protected one is first
    /// saved unprotected (presence is the caller's), so the person's
    /// version proves what it stops protecting, and the grants release it.
    pub async fn trash_environment(
        &mut self,
        project: Option<&str>,
        name: &str,
    ) -> ClientResult<EnvironmentSaved> {
        let prepared = self
            .prepare_environment(
                project,
                name,
                &EnvironmentEdit {
                    protected: Some(false),
                    ..EnvironmentEdit::default()
                },
            )
            .await?;
        let loc = prepared.loc;
        let protected_before = self
            .protection
            .contributions
            .get(&loc.item)
            .is_some_and(|c| c.protected);
        let mut saved = if protected_before {
            self.commit_environment(prepared).await?
        } else {
            EnvironmentSaved {
                name: name.to_owned(),
                id: Some(loc.item),
                ..EnvironmentSaved::default()
            }
        };
        self.trash_item(loc).await?;
        saved.protected = false;
        Ok(saved)
    }

    /// The review of `klav env import` (ADR 0032 §6): per variable, whether
    /// it is new, changed or the same in the environment, and a field of
    /// another item with the same value, compared in memory. Nothing of a
    /// value leaves this function.
    pub fn import_review(
        &self,
        project: Option<&str>,
        name: &str,
        variables: &[(String, SecretText)],
    ) -> ClientResult<Vec<ImportReview>> {
        let project = self.environment_project(project)?;
        let current = match self.find_environment(project, name)? {
            Some(entry) => Some(self.open_item(entry.loc)?),
            None => None,
        };
        let set = self.protection.items();
        // Every text field of the live items this device opens, but
        // environments: what a value may match.
        let mut fields: Vec<(ItemLocation, Item)> = Vec::new();
        for (loc, summary, _) in self.live_items() {
            if summary.kind == ItemKind::Environment {
                continue;
            }
            if let Ok(item) = self.open_item(loc) {
                fields.push((loc, item));
            }
        }
        let mut out = Vec::new();
        for (var, value) in variables {
            check_variable_name(var)?;
            let value = value.expose();
            let matches = fields.iter().find_map(|(loc, item)| {
                item.fields().iter().find_map(|f| {
                    let same = match f.value() {
                        FieldValue::Plain(s) => !s.is_empty() && s == value,
                        FieldValue::Secret(s) => !s.expose().is_empty() && s.expose() == value,
                        FieldValue::File(_) => false,
                    };
                    (same && f.kind() != FieldKind::Totp).then(|| {
                        let summary = self.item_summary(*loc).ok();
                        ImportMatch {
                            reference: Reference {
                                vault: Selector::Id(loc.vault),
                                project: Selector::Id(loc.project),
                                item: Selector::Id(loc.item),
                                field: Selector::Id(f.id()),
                            }
                            .to_string(),
                            name: summary.map_or_else(
                                || format!("{} › {}", item.title(), f.name()),
                                |s| format!("{}/{}/{} › {}", s.vault, s.project, s.title, f.name()),
                            ),
                            protected: set.contains(&loc.item),
                        }
                    })
                })
            });
            let status = match current
                .as_ref()
                .and_then(|i| i.environment())
                .and_then(|e| e.variable(var))
            {
                None => ImportStatus::New,
                Some(existing) => match existing.source() {
                    VariableSource::Value(v) if v.expose() == value => ImportStatus::Same,
                    VariableSource::Ref(r) => {
                        let same = matches.as_ref().is_some_and(|m| {
                            Reference::parse(&m.reference).is_ok_and(|mr| mr == *r)
                        });
                        if same {
                            ImportStatus::Same
                        } else {
                            ImportStatus::Changed
                        }
                    }
                    VariableSource::Value(_) => ImportStatus::Changed,
                },
            };
            out.push(ImportReview {
                name: var.clone(),
                status,
                matches,
            });
        }
        Ok(out)
    }
}

/// Replaces the inherited rules of `policy` with `ask once` rules for
/// `items` (ADR 0032 §3.1 and §4.3). Before the first inherited rule of a
/// permission that had no rules, its default goes in as an explicit rule
/// with no scope: without it, the inherited rule would leave everything else
/// in `deny` (ADR 0006 §2).
pub(crate) fn write_protection(policy: &mut klav_core::policy::Policy, items: &BTreeSet<ItemId>) {
    policy.rules.retain(|r| !r.is_protected());
    if items.is_empty() {
        return;
    }
    let items: Vec<ItemId> = items.iter().copied().collect();
    for permission in PROTECTED_PERMISSIONS {
        if !policy.rules.iter().any(|r| r.permission == permission) {
            policy
                .rules
                .push(Rule::new(permission, permission.default_effect()));
        }
        policy
            .rules
            .push(Rule::protected(permission, items.clone()));
    }
}

/// What the person's version `item` of an environment protects.
fn contribution_of(vault: VaultId, item: &Item) -> Contribution {
    let env = item.environment();
    let protected = env.is_some_and(Environment::protected);
    Contribution {
        vault: Some(vault),
        title: item.title().to_owned(),
        protected,
        items: if protected {
            env.map(|e| e.reference_targets().into_iter().collect())
                .unwrap_or_default()
        } else {
            BTreeSet::new()
        },
    }
}

/// The variables that differ between the person's version and the current
/// one (added, changed or removed), by name. With no person's version,
/// every current variable.
fn changed_variables(person: Option<&Item>, current: &Item) -> Vec<String> {
    let empty: &[Variable] = &[];
    let now = current.environment().map_or(empty, Environment::variables);
    let then = person
        .and_then(Item::environment)
        .map_or(empty, Environment::variables);
    let mut out: Vec<String> = Vec::new();
    for v in now {
        let before = then.iter().find(|p| p.name() == v.name());
        if before.is_none_or(|p| p.source() != v.source()) {
            out.push(v.name().to_owned());
        }
    }
    for p in then {
        if !now.iter().any(|v| v.name() == p.name()) {
            out.push(p.name().to_owned());
        }
    }
    out
}

fn name_list(names: &[String], env: &str) -> String {
    if names.is_empty() {
        format!("“{env}”")
    } else {
        names
            .iter()
            .map(|n| format!("“{n}”"))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contribution(title: &str, protected: bool, items: &[ItemId]) -> Contribution {
        Contribution {
            vault: None,
            title: title.into(),
            protected,
            items: items.iter().copied().collect(),
        }
    }

    #[test]
    fn the_set_only_shrinks_with_proof() {
        let env = ItemId::generate();
        let stripe = ItemId::generate();
        let other = ItemId::generate();
        let mut p = Protection::default();
        p.contributions
            .insert(env, contribution("production", true, &[stripe]));
        p.seen.extend([env, stripe]);
        // Another device's protection, known only from a grant.
        p.from_grants.insert(other);
        assert!(p.protects(env) && p.protects(stripe) && p.protects(other));
        assert_eq!(p.protected_by(stripe), vec!["production".to_owned()]);
        assert_eq!(p.protected_by(env), vec!["production".to_owned()]);
        assert_eq!(
            p.protected_by(other),
            vec!["a protected environment".to_owned()]
        );
        // The person's version leaves Stripe out: proof.
        p.contributions
            .insert(env, contribution("production", true, &[]));
        assert!(p.releasable(stripe));
        assert!(!p.protects(stripe));
        // Never seen protected here: no proof, it stays.
        assert!(!p.releasable(other));
        // Uncertain: nothing can be released.
        p.uncertain.insert(VaultId::generate());
        assert!(!p.releasable(stripe));
        p.uncertain.clear();
        p.unreadable = true;
        assert!(!p.releasable(stripe));
    }

    #[test]
    fn inherited_rules_change_nothing_but_the_protected_items() {
        use klav_core::policy::{Effect, Permission, Policy, Request, Target, evaluate};
        let vault = VaultId::generate();
        let project = ProjectId::generate();
        let protected = ItemId::generate();
        let other = ItemId::generate();
        let request = |permission, item| Request {
            permission,
            vault: Target {
                id: vault,
                name: "Personal".into(),
            },
            project: Target {
                id: project,
                name: "acme-api".into(),
            },
            tags: Vec::new(),
            domain: Some("example.com".into()),
            item: Some(item),
            method: None,
            path: None,
            mcp_tool: None,
            now: 1_800_000_000,
        };
        // A grant with defaults only, and one with an explicit rule.
        for before in [
            Policy::default(),
            Policy {
                rules: vec![Rule::new(Permission::Reveal, Effect::Allow)],
                expires_at: None,
            },
        ] {
            let mut after = before.clone();
            write_protection(&mut after, &BTreeSet::from([protected]));
            after.check_once().unwrap();
            for permission in Permission::GRANTABLE {
                let was = evaluate(&before, &request(permission, other));
                let now = evaluate(&after, &request(permission, other));
                assert_eq!(
                    (was.effect, was.once),
                    (now.effect, now.once),
                    "{permission:?} on an unprotected item"
                );
                let on = evaluate(&after, &request(permission, protected));
                if PROTECTED_PERMISSIONS.contains(&permission) {
                    // Never looser than ask once, whatever the grant said.
                    assert!(
                        on.effect == Effect::Deny || (on.effect == Effect::Ask && on.once),
                        "{permission:?} on the protected item: {on:?}"
                    );
                }
            }
            // Written again from scratch, and gone with no items.
            write_protection(&mut after, &BTreeSet::new());
            assert!(!after.rules.iter().any(Rule::is_protected));
        }
    }

    #[test]
    fn what_an_agent_changed_since_the_persons_version() {
        let mut person = Item::new(ItemKind::Environment, "production").unwrap();
        {
            let env = person.environment_mut().unwrap();
            env.add(Variable::with_value("A", "1").unwrap()).unwrap();
            env.add(Variable::with_value("B", "2").unwrap()).unwrap();
            env.add(Variable::with_value("C", "3").unwrap()).unwrap();
        }
        let mut agent = person.clone();
        {
            let env = agent.environment_mut().unwrap();
            env.set(Variable::with_value("B", "changed").unwrap())
                .unwrap();
            env.remove("C");
            env.add(Variable::with_value("D", "4").unwrap()).unwrap();
        }
        assert_eq!(
            changed_variables(Some(&person), &agent),
            vec!["B", "D", "C"]
        );
        assert!(changed_variables(Some(&person), &person).is_empty());
        assert_eq!(changed_variables(None, &person), vec!["A", "B", "C"]);
    }

    #[test]
    fn the_protection_file_round_trips_and_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let home = Home::at(dir.path());
        let key = LocalKey::generate();
        let ctx = LocalContext {
            account: klav_core::ids::AccountId::generate(),
            device: klav_core::ids::DeviceId::generate(),
        };
        assert!(!Protection::load(&home, &key, &ctx).unreadable);
        let env = ItemId::generate();
        let mut p = Protection::default();
        p.contributions.insert(env, contribution("prod", true, &[]));
        p.save(&home, &key, &ctx).unwrap();
        let back = Protection::load(&home, &key, &ctx);
        assert!(!back.unreadable && back.protects(env));
        // Another key: unknown, never empty.
        assert!(Protection::load(&home, &LocalKey::generate(), &ctx).unreadable);
    }
}
