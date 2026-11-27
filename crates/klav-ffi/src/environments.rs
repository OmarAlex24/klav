//! Environments in the apps (ADR 0032 §6, layer 4b): the list, one
//! environment's variables with their origin and never a value, a value
//! the person asked to show or copy, and the edits.
//!
//! On iOS (`KlavCore`) the protection is applied here (§3, §3.1): showing
//! or copying a value that a protected environment reaches, lowering the
//! protection and trashing a protected environment ask for the device's
//! owner first, through the keystore (Face ID, or the passcode), and fail
//! closed when it cannot ask. On the Mac (`DaemonEngine`) `klavd` asks for
//! Touch ID itself, or for the master password (the `_with_password`
//! calls, as the answer to `PresenceRequired`).

use klav_client::Unlocked;
use klav_client::environments::{
    AgentChanges, EnvironmentDetail, EnvironmentEdit, EnvironmentListing, EnvironmentSaved,
    NewVariable, VariableOrigin, VariableView,
};
use klav_client::ops::SecretText;

use crate::biometric::PlatformKeystore;
use crate::{KlavCore, KlavError, KlavResult};

/// One environment, without its variables (`klav env ls`).
#[derive(Debug, Clone, uniffi::Record)]
pub struct EnvironmentInfo {
    /// Its item's ID.
    pub id: String,
    /// Vault ID and name.
    pub vault_id: String,
    pub vault: String,
    /// Project ID and name.
    pub project_id: String,
    pub project: String,
    /// Its name (`development`, `production`).
    pub name: String,
    /// How many variables.
    pub variables: u32,
    /// The effective protected flag (ADR 0032 §3).
    pub protected: bool,
    /// Last change (Unix ms).
    pub updated_at: i64,
    /// The agent that wrote the current version, if one did.
    pub author_agent_id: Option<String>,
}

impl From<EnvironmentListing> for EnvironmentInfo {
    fn from(l: EnvironmentListing) -> Self {
        Self {
            id: l.id.to_string(),
            vault_id: l.vault_id.to_string(),
            vault: l.vault,
            project_id: l.project_id.to_string(),
            project: l.project,
            name: l.name,
            variables: u32::try_from(l.variables).unwrap_or(u32::MAX),
            protected: l.protected,
            updated_at: l.updated_at,
            author_agent_id: l.author_agent_id.map(|a| a.to_string()),
        }
    }
}

/// One variable, without its value.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct VariableInfo {
    /// Its name (`STRIPE_KEY`).
    pub name: String,
    /// The `klav://` reference it stores (by IDs), when it points to a
    /// field of another item; `None` for its own value.
    pub reference: Option<String>,
    /// That item and field by name («Stripe › api_key»), when this device
    /// sees it.
    pub target: Option<String>,
    /// That item is protected (ADR 0032 §3.1).
    pub target_protected: bool,
    /// What showing or copying its value reads (`variable_value`).
    pub resolve: String,
}

impl From<VariableView> for VariableInfo {
    fn from(v: VariableView) -> Self {
        let (reference, target, target_protected) = match v.origin {
            VariableOrigin::Value => (None, None, false),
            VariableOrigin::Reference {
                reference,
                target,
                protected,
            } => (Some(reference), target, protected),
        };
        Self {
            name: v.name,
            reference,
            target,
            target_protected,
            resolve: v.resolve,
        }
    }
}

/// The variables an agent changed since the person's latest version (ADR
/// 0032 §3, answer 7).
#[derive(Debug, Clone, uniffi::Record)]
pub struct AgentChangesInfo {
    /// The agent's ID.
    pub agent_id: String,
    /// Its name, when this device could learn it.
    pub agent: Option<String>,
    /// When (Unix ms).
    pub at: i64,
    /// Variables added, changed or removed.
    pub variables: Vec<String>,
}

impl From<AgentChanges> for AgentChangesInfo {
    fn from(c: AgentChanges) -> Self {
        Self {
            agent_id: c.agent_id.to_string(),
            agent: c.agent,
            at: c.at,
            variables: c.variables,
        }
    }
}

/// One environment: its variables in order, never a value.
#[derive(Debug, Clone, uniffi::Record)]
pub struct EnvironmentDetailInfo {
    /// The environment.
    pub info: EnvironmentInfo,
    /// Its variables.
    pub variables: Vec<VariableInfo>,
    /// What an agent changed since the person's latest version.
    pub agent_changes: Option<AgentChangesInfo>,
}

impl From<EnvironmentDetail> for EnvironmentDetailInfo {
    fn from(d: EnvironmentDetail) -> Self {
        Self {
            info: d.listing.into(),
            variables: d.variables.into_iter().map(VariableInfo::from).collect(),
            agent_changes: d.agent_changes.map(AgentChangesInfo::from),
        }
    }
}

/// A variable to add or replace: its own value or a reference, never both.
#[derive(Clone, uniffi::Record)]
pub struct VariableInput {
    /// Its name.
    pub name: String,
    /// Its own value…
    pub value: Option<String>,
    /// …or a `klav://` reference to a field of another item.
    pub reference: Option<String>,
}

impl std::fmt::Debug for VariableInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VariableInput")
            .field("name", &self.name)
            .field("value", &self.value.as_ref().map(|_| "…"))
            .field("reference", &self.reference)
            .finish()
    }
}

/// A change to an environment.
#[derive(Debug, Clone, uniffi::Record)]
pub struct EnvironmentEditInput {
    /// Create it if it does not exist.
    pub create: bool,
    /// It must not exist yet («New environment»).
    pub must_be_new: bool,
    /// Turn `protected` on or off.
    pub protected: Option<bool>,
    /// Variables to add or replace.
    pub set: Vec<VariableInput>,
    /// Variables to remove.
    pub remove: Vec<String>,
}

impl From<EnvironmentEditInput> for EnvironmentEdit {
    fn from(e: EnvironmentEditInput) -> Self {
        Self {
            create: e.create,
            must_be_new: e.must_be_new,
            protected: e.protected,
            set: e
                .set
                .into_iter()
                .map(|v| NewVariable {
                    name: v.name,
                    value: v.value.map(SecretText::new),
                    reference: v.reference,
                })
                .collect(),
            remove: e.remove,
        }
    }
}

/// What saving did.
#[derive(Debug, Clone, uniffi::Record)]
pub struct EnvironmentSavedInfo {
    /// The environment's name.
    pub name: String,
    /// Its item's ID.
    pub id: Option<String>,
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
    /// What did not work.
    pub warnings: Vec<String>,
}

impl From<EnvironmentSaved> for EnvironmentSavedInfo {
    fn from(s: EnvironmentSaved) -> Self {
        Self {
            name: s.name,
            id: s.id.map(|i| i.to_string()),
            created: s.created,
            protected: s.protected,
            newly_protected: s.newly_protected,
            unprotected: s.unprotected,
            agents: s.agents,
            warnings: s.warnings,
        }
    }
}

/// The one value of a `resolve` of a single variable, as text.
pub(crate) fn single_text(values: Vec<klav_client::ops::ResolvedValue>) -> KlavResult<String> {
    let value = values
        .into_iter()
        .next()
        .ok_or_else(|| KlavError::invalid("no value came back"))?;
    Ok(value.text()?.to_owned())
}

/// Asks for the device's owner with `reason`, failing closed: a device that
/// cannot ask hands nothing out (ADR 0032 §3: «Face ID every time»).
fn confirm(keystore: &dyn PlatformKeystore, reason: String) -> KlavResult<()> {
    crate::biometric::confirm_protected(keystore, reason)
}

/// The project an environment call names, by ID or `vault/project`.
fn project_arg(project_id: Option<String>) -> Option<String> {
    project_id
        .map(|p| p.trim().to_owned())
        .filter(|p| !p.is_empty())
}

#[uniffi::export]
impl KlavCore {
    /// The environments of a project, or of every project (ADR 0032 §6).
    pub fn environments(&self, project_id: Option<String>) -> KlavResult<Vec<EnvironmentInfo>> {
        let project = project_arg(project_id);
        self.with(|u| {
            Ok(u.environments(project.as_deref())?
                .into_iter()
                .map(EnvironmentInfo::from)
                .collect())
        })
    }

    /// One environment: names and origins, never a value. `None` when the
    /// project has none of that name.
    pub fn environment(
        &self,
        project_id: String,
        name: String,
    ) -> KlavResult<Option<EnvironmentDetailInfo>> {
        let project = project_arg(Some(project_id));
        self.with(|u| {
            Ok(self
                .runtime
                .block_on(u.environment_detail(project.as_deref(), &name))?
                .map(EnvironmentDetailInfo::from))
        })
    }

    /// The value of one variable (`VariableInfo::resolve`), which the
    /// person asked to show or copy. In a protected environment, or through
    /// a reference to a protected item, it asks for Face ID first, every
    /// time (ADR 0032 §3.1), showing `reason` (the app's words, in its
    /// language).
    pub fn variable_value(
        &self,
        reference: String,
        reason: String,
        keystore: std::sync::Arc<dyn PlatformKeystore>,
    ) -> KlavResult<String> {
        let references = vec![reference];
        self.with(|u| {
            u.variable_environments(&references)?;
            if protection(u, &references)?.is_some() {
                confirm(keystore.as_ref(), reason)?;
            }
            single_text(self.runtime.block_on(u.resolve_all(&references))?)
        })
    }

    /// Why showing or copying a value of this item asks for Face ID every
    /// time (ADR 0032 §3.1), in words for the prompt; `None` when it does
    /// not. The item page asks before `field_value`, `notes` and `totp`.
    pub fn value_protection(&self, id: String) -> KlavResult<Option<String>> {
        self.with(|u| {
            let loc = crate::location(u, &id)?;
            Ok(u.protection_reason(&[loc]))
        })
    }

    /// Saves a change to an environment: one that makes the protection
    /// grow reissues the agents' grants first; one that lowers it asks for
    /// Face ID first, showing `reason` (ADR 0032 §3, §3.1).
    pub fn save_environment(
        &self,
        project_id: String,
        name: String,
        edit: EnvironmentEditInput,
        reason: String,
        keystore: std::sync::Arc<dyn PlatformKeystore>,
    ) -> KlavResult<EnvironmentSavedInfo> {
        let project = project_arg(Some(project_id));
        let edit = EnvironmentEdit::from(edit);
        self.writing(|u| {
            let prepared =
                self.runtime
                    .block_on(u.prepare_environment(project.as_deref(), &name, &edit))?;
            if prepared.plan.shrinks {
                confirm(keystore.as_ref(), reason.clone())?;
            }
            Ok(self
                .runtime
                .block_on(u.commit_environment(prepared))?
                .into())
        })
    }

    /// Moves an environment to the trash; a protected one asks for Face ID
    /// first, showing `reason`, since it stops protecting what it pointed
    /// to.
    pub fn trash_environment(
        &self,
        project_id: String,
        name: String,
        reason: String,
        keystore: std::sync::Arc<dyn PlatformKeystore>,
    ) -> KlavResult<EnvironmentSavedInfo> {
        let project = project_arg(Some(project_id));
        self.writing(|u| {
            let protected = u
                .environments(project.as_deref())?
                .into_iter()
                .any(|l| l.name == name && l.protected);
            if protected {
                confirm(keystore.as_ref(), reason.clone())?;
            }
            Ok(self
                .runtime
                .block_on(u.trash_environment(project.as_deref(), &name))?
                .into())
        })
    }
}

/// Why reading `references` asks for presence every time, the item behind
/// a variable's reference included.
fn protection(u: &Unlocked, references: &[String]) -> KlavResult<Option<String>> {
    let items = u.reference_targets(references)?;
    Ok(u.protection_reason(&items))
}

#[cfg(feature = "daemon")]
mod daemon {
    use klav_client::environments::{EnvironmentDetail, EnvironmentListing, EnvironmentSaved};
    use klav_client::ops::{ResolvedValue, SecretText};
    use klav_daemon::protocol::Request;

    use super::{
        EnvironmentDetailInfo, EnvironmentEditInput, EnvironmentInfo, EnvironmentSavedInfo,
        project_arg, single_text,
    };
    use crate::{DaemonEngine, KlavResult};

    #[uniffi::export]
    impl DaemonEngine {
        /// The environments of a project, or of every project (ADR 0032 §6).
        pub fn environments(&self, project_id: Option<String>) -> KlavResult<Vec<EnvironmentInfo>> {
            let listings: Vec<EnvironmentListing> = self.call(Request::Environments {
                project: project_arg(project_id),
            })?;
            Ok(listings.into_iter().map(EnvironmentInfo::from).collect())
        }

        /// One environment: names and origins, never a value.
        pub fn environment(
            &self,
            project_id: String,
            name: String,
        ) -> KlavResult<Option<EnvironmentDetailInfo>> {
            let detail: Option<EnvironmentDetail> = self.call(Request::Environment {
                project: project_arg(Some(project_id)),
                name,
            })?;
            Ok(detail.map(EnvironmentDetailInfo::from))
        }

        /// The value of one variable. `klavd` refuses anything but an
        /// environment's variable, and asks for Touch ID in a protected
        /// one; with the presence gate on it may answer `PresenceRequired`:
        /// then [`Self::variable_value_with_password`].
        pub fn variable_value(&self, reference: String) -> KlavResult<String> {
            self.variable_value_with(reference, None)
        }

        /// `variable_value` with the master password, as the answer to its
        /// `PresenceRequired`.
        pub fn variable_value_with_password(
            &self,
            reference: String,
            password: String,
        ) -> KlavResult<String> {
            self.variable_value_with(reference, Some(password))
        }

        /// Saves a change to an environment; lowering the protection asks
        /// for Touch ID in `klavd` (or `PasswordRequired` where there is
        /// none: then the `_with_password` call).
        pub fn save_environment(
            &self,
            project_id: String,
            name: String,
            edit: EnvironmentEditInput,
        ) -> KlavResult<EnvironmentSavedInfo> {
            self.save_environment_with_password(project_id, name, edit, None)
        }

        /// `save_environment` with the master password.
        pub fn save_environment_with_password(
            &self,
            project_id: String,
            name: String,
            edit: EnvironmentEditInput,
            password: Option<String>,
        ) -> KlavResult<EnvironmentSavedInfo> {
            let saved: EnvironmentSaved = self.call(Request::EnvironmentSave {
                project: project_arg(Some(project_id)),
                name,
                edit: edit.into(),
                password: password.map(SecretText::new),
            })?;
            Ok(saved.into())
        }

        /// Moves an environment to the trash; a protected one asks for
        /// Touch ID in `klavd` first.
        pub fn trash_environment(
            &self,
            project_id: String,
            name: String,
        ) -> KlavResult<EnvironmentSavedInfo> {
            self.trash_environment_with_password(project_id, name, None)
        }

        /// `trash_environment` with the master password.
        pub fn trash_environment_with_password(
            &self,
            project_id: String,
            name: String,
            password: Option<String>,
        ) -> KlavResult<EnvironmentSavedInfo> {
            let saved: EnvironmentSaved = self.call(Request::EnvironmentTrash {
                project: project_arg(Some(project_id)),
                name,
                password: password.map(SecretText::new),
            })?;
            Ok(saved.into())
        }
    }

    impl DaemonEngine {
        fn variable_value_with(
            &self,
            reference: String,
            password: Option<String>,
        ) -> KlavResult<String> {
            let values: Vec<ResolvedValue> = self.held_value(
                |password| Request::Resolve {
                    references: vec![reference.clone()],
                    variables_only: true,
                    password,
                },
                password,
            )?;
            single_text(values)
        }
    }
}
