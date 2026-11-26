//! Changing an active agent's grant (ADR 0033, amendment of 2026-11-10,
//! F3): what the editor shows, the sheet of differences the person signs,
//! and whether the change widens (and so asks for presence, P8) or only
//! narrows.
//!
//! The flow is prepare, then sign:
//!
//! 1. [`Unlocked::grant_editor`]: the grant in force in the editor's model
//!    ([`EditorPolicy`]), or read-only with the reason.
//! 2. [`Unlocked::prepare_grant_change`] syncs, verifies the grant in force
//!    and computes the differences, whether they widen
//!    ([`klav_core::narrowing`]) and a digest that binds them to that grant
//!    and to the change as the caller sent it. It signs nothing.
//! 3. The caller asks for presence when [`GrantChangePreview::widens`]
//!    (`klavd` builds the dialog), then [`Unlocked::commit_grant_change`]
//!    signs. A caller that prepared earlier prepares again right before
//!    signing and checks the digest the person saw with
//!    [`PreparedGrantChange::check_shown`]: nothing is signed if the grant
//!    in force changed meanwhile (T188).
//!
//! The rule for every path that issues a grant again (T190): everything
//! that does not change on purpose is copied (items, profiles, issuers,
//! the sandbox proxy), `v` never goes down, and a grant this device cannot
//! read whole is never signed. The pairing words are not asked again: the
//! agent's public identity is inside the signature of the grant in force,
//! verified with the identity the server gives (spec §13.4).

use std::collections::BTreeSet;

use klav_core::crypto::agent;
use klav_core::crypto::identity::PublicIdentity;
use klav_core::ids::{AgentId, ProjectId};
use klav_core::narrowing::{expiry_narrows, policy_narrows};
use klav_core::policy::{DomainPattern, Effect, Permission, Policy, Rule, Scope, TimeWindow};
use klav_proto::agent::{AgentStatus, GrantPayload};
use serde::{Deserialize, Serialize};

use crate::agents::{AgentView, GrantedProjectView};
use crate::error::{ClientError, ClientResult};
use crate::revoke::RotationReport;
use crate::session::{Unlocked, now_ms};

/// The permissions the editor sets, in the order it shows them: every
/// grantable one but `proxy`, which only the credential proxy's grant uses
/// (ADR 0036 §2) and `klav proxy …` changes.
pub const EDITABLE: [Permission; 8] = [
    Permission::List,
    Permission::Fill,
    Permission::Inject,
    Permission::Totp,
    Permission::Reveal,
    Permission::Create,
    Permission::Update,
    Permission::Delete,
];

/// One permission in the editor: an effect, or none for its default
/// (no rule, ADR 0006 §1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PermissionSetting {
    /// The permission.
    pub permission: Permission,
    /// Its effect; `None` for the default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effect: Option<Effect>,
}

/// The policies the editor can show and write: what `klav agent approve`
/// writes with `--allow`, `--ask`, `--deny`, `--fill-domain`, `--hours`
/// and `--expires`. A grant whose policy is anything else is read-only in
/// the apps ([`ReadOnlyReason::Rules`]).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EditorPolicy {
    /// One per permission it sets; a permission left out is its default.
    #[serde(default)]
    pub permissions: Vec<PermissionSetting>,
    /// Where `fill` may fill (`--fill-domain`); with sites, `fill` has no
    /// effect of its own.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fill_sites: Vec<DomainPattern>,
    /// Weekly windows for every rule (`--hours`); none is "always".
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hours: Vec<TimeWindow>,
    /// When the whole grant ends (Unix seconds); none is "never".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

impl EditorPolicy {
    /// The effect set for `permission` (`None`: its default).
    #[must_use]
    pub fn effect(&self, permission: Permission) -> Option<Effect> {
        self.permissions
            .iter()
            .find(|s| s.permission == permission)
            .and_then(|s| s.effect)
    }

    /// What `permission` gets wherever the rules apply: its effect, or its
    /// default.
    #[must_use]
    pub fn effective(&self, permission: Permission) -> Effect {
        self.effect(permission)
            .unwrap_or_else(|| permission.default_effect())
    }

    /// The policy, written as `klav agent approve` writes it: the
    /// permissions with an effect, then the `fill` sites, then, with
    /// hours, a rule for every grantable permission (its default when it
    /// had none) and the windows on every rule.
    ///
    /// # Errors
    ///
    /// A permission the editor does not set, one set twice, or `fill` with
    /// both sites and an effect.
    pub fn to_policy(&self) -> Result<Policy, String> {
        let mut seen = BTreeSet::new();
        for s in &self.permissions {
            if !EDITABLE.contains(&s.permission) {
                return Err(format!(
                    "`{}` is not set in this editor",
                    s.permission.as_str()
                ));
            }
            if !seen.insert(s.permission) {
                return Err(format!("`{}` is set twice", s.permission.as_str()));
            }
        }
        if !self.fill_sites.is_empty() && self.effect(Permission::Fill).is_some() {
            return Err("`fill` takes either sites or an effect, not both".into());
        }
        let mut rules = Vec::new();
        for effect in [Effect::Allow, Effect::Ask, Effect::Deny] {
            for p in EDITABLE {
                if self.effect(p) == Some(effect) {
                    rules.push(Rule::new(p, effect));
                }
            }
        }
        if !self.fill_sites.is_empty() {
            rules.push(Rule {
                scope: Scope {
                    domains: self.fill_sites.clone(),
                    ..Scope::default()
                },
                ..Rule::new(Permission::Fill, Effect::Allow)
            });
        }
        if !self.hours.is_empty() {
            for p in Permission::GRANTABLE {
                if !rules.iter().any(|r| r.permission == p) {
                    rules.push(Rule::new(p, p.default_effect()));
                }
            }
            for rule in &mut rules {
                rule.scope.hours.clone_from(&self.hours);
            }
        }
        Ok(Policy {
            rules,
            expires_at: self.expires_at,
        })
    }

    /// The editor's model of `policy`, if [`Self::to_policy`] writes it
    /// back with the same rules (in any order) and the same expiry; `None`
    /// for anything else (tags, vault or project scopes, a rule's own
    /// expiry, several rules for one permission, `proxy` rules).
    #[must_use]
    pub fn from_policy(policy: &Policy) -> Option<Self> {
        let hours = policy
            .rules
            .first()
            .map(|r| r.scope.hours.clone())
            .unwrap_or_default();
        let plain = Scope {
            hours: hours.clone(),
            ..Scope::default()
        };
        let mut permissions = Vec::new();
        let mut fill_sites = Vec::new();
        for p in EDITABLE {
            let rules: Vec<&Rule> = policy.rules.iter().filter(|r| r.permission == p).collect();
            match rules.as_slice() {
                [] => {}
                [r] if r.scope == plain && r.expires_at.is_none() => {
                    // With hours every permission has a rule, and one with
                    // its default is the editor's "default".
                    if hours.is_empty() || r.effect != p.default_effect() {
                        permissions.push(PermissionSetting {
                            permission: p,
                            effect: Some(r.effect),
                        });
                    }
                }
                [r] if p == Permission::Fill
                    && r.effect == Effect::Allow
                    && r.expires_at.is_none()
                    && !r.scope.domains.is_empty()
                    && r.scope
                        == Scope {
                            domains: r.scope.domains.clone(),
                            ..plain.clone()
                        } =>
                {
                    fill_sites.clone_from(&r.scope.domains);
                }
                _ => return None,
            }
        }
        let model = Self {
            permissions,
            fill_sites,
            hours,
            expires_at: policy.expires_at,
        };
        let back = model.to_policy().ok()?;
        (back.expires_at == policy.expires_at && same_rules(&back.rules, &policy.rules))
            .then_some(model)
    }
}

/// The same rules, as a multiset.
fn same_rules(a: &[Rule], b: &[Rule]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut left: Vec<&Rule> = b.iter().collect();
    a.iter().all(|r| match left.iter().position(|x| *x == r) {
        Some(i) => {
            left.swap_remove(i);
            true
        }
        None => false,
    })
}

/// Why the apps cannot change a grant (they show it in words instead).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadOnlyReason {
    /// The agent is not active (pending, denied or revoked).
    NotActive,
    /// It has no grant.
    NoGrant,
    /// This device cannot read its grant whole.
    Unreadable,
    /// The credential proxy's grant (items, profiles, sandbox issuers or
    /// `proxy` rules): `klav proxy …` changes it (ADR 0036).
    Proxy,
    /// An issuer's grant (it starts sandboxes): the apps leave it to the
    /// CLI, which keeps its proxy (ADR 0036 §4).
    Issuer,
    /// Rules the editor does not model: `klav agent approve
    /// --policy-file` changes them.
    Rules,
}

/// An agent's grant in force, as the editor shows it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrantEditor {
    /// The agent.
    pub agent_id: AgentId,
    /// Its name (the agent's own words: show it as such, T136).
    pub name: String,
    /// The grant's version (0 without one).
    pub version: u64,
    /// Its projects.
    #[serde(default)]
    pub projects: Vec<GrantedProjectView>,
    /// Whether the editor can change it.
    pub editable: bool,
    /// Why not, when it cannot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<ReadOnlyReason>,
    /// The policy in the editor's model, when it fits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub editor: Option<EditorPolicy>,
    /// The policy as signed, when this device reads it (to show a
    /// read-only grant in words).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<Policy>,
}

/// A change to an active agent's grant, as the editor or the CLI sends it.
/// Its exact JSON goes into the digest of the sheet (F3): send the same
/// value to prepare and to apply.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantChange {
    /// The projects of the new grant: `vault/project`, a project name
    /// unique across vaults, or an ID.
    #[serde(default)]
    pub projects: Vec<String>,
    /// Vaults whose current projects are all in the new grant.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub vaults: Vec<String>,
    /// The new policy.
    pub policy: ChangePolicy,
    /// Also change the key of each project taken away (P9: offered,
    /// unchecked): `rotate_project_key`, and new grants for the other
    /// agents that hold it.
    #[serde(default)]
    pub rotate_removed: bool,
}

/// The new policy of a [`GrantChange`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangePolicy {
    /// From the editor's model.
    Editor(EditorPolicy),
    /// A whole policy, as `klav agent approve` builds it (names allowed in
    /// selectors: resolved to IDs before signing).
    Rules(Policy),
}

/// One line of the sheet: before → after.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangeLine {
    /// What changes.
    #[serde(flatten)]
    pub what: ChangeWhat,
    /// Whether this line lets the agent do more.
    pub widens: bool,
}

/// What a [`ChangeLine`] changes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ChangeWhat {
    /// A project added (`vault/project`).
    ProjectAdded {
        /// `vault/project`.
        project: String,
    },
    /// A project taken away.
    ProjectRemoved {
        /// `vault/project`.
        project: String,
    },
    /// A permission's effect.
    Permission {
        /// The permission.
        permission: Permission,
        /// Effect before.
        before: Effect,
        /// Whether that was its default (no rule).
        before_default: bool,
        /// Effect after.
        after: Effect,
        /// Whether this is its default (no rule).
        after_default: bool,
    },
    /// The sites `fill` may fill (none: wherever its effect says).
    FillSites {
        /// Before.
        before: Vec<String>,
        /// After.
        after: Vec<String>,
    },
    /// The weekly windows (none: always).
    Hours {
        /// Before, as `mon-fri 09:00-18:00 -06:00`.
        before: Vec<String>,
        /// After.
        after: Vec<String>,
    },
    /// When the grant ends (Unix seconds; none: never).
    Expires {
        /// Before.
        before: Option<u64>,
        /// After.
        after: Option<u64>,
    },
    /// Rules outside the editor's model changed (only from the CLI).
    Rules,
}

impl ChangeLine {
    /// The line in English, for the terminal.
    #[must_use]
    pub fn text(&self) -> String {
        let effect = |e: Effect, default: bool| {
            let word = match e {
                Effect::Allow => "allow",
                Effect::Ask => "ask",
                Effect::Deny => "deny",
            };
            if default {
                format!("{word} (default)")
            } else {
                word.to_owned()
            }
        };
        let list = |l: &[String], none: &str| {
            if l.is_empty() {
                none.to_owned()
            } else {
                l.join(", ")
            }
        };
        let when = |t: Option<u64>| t.map_or_else(|| "never".to_owned(), |s| format!("{s} (Unix)"));
        let text = match &self.what {
            ChangeWhat::ProjectAdded { project } => format!("+ {project}"),
            ChangeWhat::ProjectRemoved { project } => format!("- {project}"),
            ChangeWhat::Permission {
                permission,
                before,
                before_default,
                after,
                after_default,
            } => format!(
                "{}: {} -> {}",
                permission.as_str(),
                effect(*before, *before_default),
                effect(*after, *after_default)
            ),
            ChangeWhat::FillSites { before, after } => format!(
                "fill sites: {} -> {}",
                list(before, "anywhere"),
                list(after, "anywhere")
            ),
            ChangeWhat::Hours { before, after } => format!(
                "hours: {} -> {}",
                list(before, "always"),
                list(after, "always")
            ),
            ChangeWhat::Expires { before, after } => {
                format!("expires: {} -> {}", when(*before), when(*after))
            }
            ChangeWhat::Rules => "rules: changed (see the policy file)".to_owned(),
        };
        if self.widens {
            format!("{text}  [widens]")
        } else {
            text
        }
    }
}

/// The sheet of a change: what the person signs. No secrets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantChangePreview {
    /// The agent.
    pub agent_id: AgentId,
    /// Its name (the agent's own words, T136).
    pub name: String,
    /// The version the new grant will have.
    pub version: u64,
    /// Only the differences, one per line.
    pub lines: Vec<ChangeLine>,
    /// Whether the change lets the agent do more: it asks for Touch ID or
    /// the master password (P8). Prudent: what cannot be shown to narrow
    /// widens.
    pub widens: bool,
    /// Binds the sheet to the grant in force and to the change (F3).
    pub digest: String,
    /// Projects taken away (`vault/project`): the sheet offers to change
    /// their keys (P9).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub removed_projects: Vec<String>,
    /// Whether the change also changes those keys.
    #[serde(default)]
    pub rotate_removed: bool,
    /// What could not be checked, and what the person should know.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

/// A change checked by [`Unlocked::prepare_grant_change`], ready to sign.
#[derive(Debug, Clone)]
pub struct PreparedGrantChange {
    preview: GrantChangePreview,
    public: PublicIdentity,
    old: GrantPayload,
    policy: Policy,
    wanted: Vec<ProjectId>,
    removed: Vec<ProjectId>,
}

impl PreparedGrantChange {
    /// The sheet.
    #[must_use]
    pub fn preview(&self) -> &GrantChangePreview {
        &self.preview
    }

    /// Whether signing asks for presence.
    #[must_use]
    pub fn widens(&self) -> bool {
        self.preview.widens
    }

    /// The lines that widen, in the sheet's order (for the presence
    /// dialog).
    #[must_use]
    pub fn widening_lines(&self) -> Vec<&ChangeLine> {
        self.preview.lines.iter().filter(|l| l.widens).collect()
    }

    /// Refuses to go on unless `shown` is this change's digest: the sheet
    /// the person saw was built from the same grant in force and the same
    /// change.
    ///
    /// # Errors
    ///
    /// [`ClientError::Security`] when they differ: nothing was signed.
    pub fn check_shown(&self, shown: &str) -> ClientResult<()> {
        if shown.trim().eq_ignore_ascii_case(&self.preview.digest) {
            Ok(())
        } else {
            Err(ClientError::Security(
                "the grant changed while you were looking at it: nothing was signed; open it again"
                    .into(),
            ))
        }
    }
}

/// What [`Unlocked::commit_grant_change`] did.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrantChangeReport {
    /// The agent, with its new grant.
    pub agent: AgentView,
    /// Keys of projects taken away that changed (with `rotate_removed`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rotated: Vec<RotationReport>,
    /// Other agents that got a new grant with those keys.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub regranted: Vec<String>,
    /// Other agents whose grant could not be issued again (`name: why`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub not_regranted: Vec<String>,
    /// What stopped the key changes, if they stopped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failed: Option<String>,
    /// Projects whose key still has to change (`vault/project`): `klavd`
    /// goes on with them by itself after the next unlock (P11).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pending: Vec<String>,
    /// Projects whose key cannot change from this device, and why
    /// (`vault/project: why`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub skipped: Vec<String>,
}

impl GrantChangeReport {
    /// Everything asked for is done.
    #[must_use]
    pub fn complete(&self) -> bool {
        self.failed.is_none() && self.pending.is_empty() && self.not_regranted.is_empty()
    }
}

/// `TimeWindow` as `--hours` writes it.
fn window_text(w: &TimeWindow) -> String {
    let days = if w.days.is_empty() {
        "daily".to_owned()
    } else {
        w.days
            .iter()
            .map(|d| {
                serde_json::to_value(d)
                    .ok()
                    .and_then(|v| v.as_str().map(str::to_owned))
                    .unwrap_or_default()
            })
            .collect::<Vec<_>>()
            .join(",")
    };
    format!("{days} {}-{} {}", w.start, w.end, w.utc_offset)
}

/// The grant's read-only reason from what it carries, if any.
fn read_only(payload: &GrantPayload) -> Option<ReadOnlyReason> {
    if !payload.items.is_empty()
        || !payload.profiles.is_empty()
        || !payload.issuers.is_empty()
        || payload.policy.may_proxy()
    {
        Some(ReadOnlyReason::Proxy)
    } else if payload.sandbox.is_some() {
        Some(ReadOnlyReason::Issuer)
    } else if EditorPolicy::from_policy(&payload.policy).is_none() {
        Some(ReadOnlyReason::Rules)
    } else {
        None
    }
}

/// The lines of the sheet between two policies (projects apart).
fn policy_lines(old: &Policy, new: &Policy, widens: bool) -> Vec<ChangeLine> {
    let (Some(before), Some(after)) = (
        EditorPolicy::from_policy(old),
        EditorPolicy::from_policy(new),
    ) else {
        return if old == new {
            Vec::new()
        } else {
            vec![ChangeLine {
                what: ChangeWhat::Rules,
                widens,
            }]
        };
    };
    let mut lines = Vec::new();
    for p in EDITABLE {
        let (b, a) = (before.effect(p), after.effect(p));
        if b == a {
            continue;
        }
        let (be, ae) = (before.effective(p), after.effective(p));
        if be == ae && (p == Permission::Fill) && before.fill_sites != after.fill_sites {
            // The sites line says it.
            continue;
        }
        lines.push(ChangeLine {
            what: ChangeWhat::Permission {
                permission: p,
                before: be,
                before_default: b.is_none(),
                after: ae,
                after_default: a.is_none(),
            },
            widens: ae < be,
        });
    }
    if before.fill_sites != after.fill_sites {
        let inside = after
            .fill_sites
            .iter()
            .all(|s| before.fill_sites.contains(s));
        let narrows = before.fill_sites.is_empty()
            || (inside && !after.fill_sites.is_empty())
            || after.effective(Permission::Fill) == Effect::Deny;
        lines.push(ChangeLine {
            what: ChangeWhat::FillSites {
                before: before.fill_sites.iter().map(ToString::to_string).collect(),
                after: after.fill_sites.iter().map(ToString::to_string).collect(),
            },
            widens: !narrows,
        });
    }
    if before.hours != after.hours {
        let inside = after.hours.iter().all(|w| before.hours.contains(w));
        let narrows = before.hours.is_empty() || (inside && !after.hours.is_empty());
        lines.push(ChangeLine {
            what: ChangeWhat::Hours {
                before: before.hours.iter().map(window_text).collect(),
                after: after.hours.iter().map(window_text).collect(),
            },
            widens: !narrows,
        });
    }
    if before.expires_at != after.expires_at {
        lines.push(ChangeLine {
            what: ChangeWhat::Expires {
                before: before.expires_at,
                after: after.expires_at,
            },
            widens: !expiry_narrows(before.expires_at, after.expires_at),
        });
    }
    lines
}

impl Unlocked {
    /// The grant of agent `id` as the editor shows it, or read-only with
    /// the reason (F4 `grant_editor`). A grant this device cannot read is
    /// read-only, never an error.
    pub async fn grant_editor(&mut self, id: AgentId) -> ClientResult<GrantEditor> {
        let info = self.agent_info(id).await?;
        let mut editor = GrantEditor {
            agent_id: id,
            name: info.name.clone(),
            version: 0,
            projects: Vec::new(),
            editable: false,
            reason: None,
            editor: None,
            policy: None,
        };
        if info.status != AgentStatus::Active || self.cache.revocations.contains_key(&id) {
            editor.reason = Some(ReadOnlyReason::NotActive);
            return Ok(editor);
        }
        let Some(grant) = info.grant.as_ref() else {
            editor.reason = Some(ReadOnlyReason::NoGrant);
            return Ok(editor);
        };
        let payload = PublicIdentity::decode(info.public_identity.as_bytes())
            .map_err(ClientError::from)
            .and_then(|public| self.open_grant(id, &public, grant));
        let Ok(payload) = payload else {
            editor.reason = Some(ReadOnlyReason::Unreadable);
            return Ok(editor);
        };
        editor.version = payload.version;
        editor.reason = read_only(&payload);
        editor.editable = editor.reason.is_none();
        editor.editor = EditorPolicy::from_policy(&payload.policy);
        editor.policy = Some(payload.policy.clone());
        editor.projects = self.grant_view(payload).projects;
        Ok(editor)
    }

    /// Checks a change to active agent `id`'s grant and builds its sheet,
    /// without signing (F4 `grant_change_prepare`). Syncs first; reads and
    /// verifies the grant in force itself, so whether it widens never
    /// depends on the caller.
    pub async fn prepare_grant_change(
        &mut self,
        id: AgentId,
        change: &GrantChange,
    ) -> ClientResult<PreparedGrantChange> {
        let synced = self.sync().await.map(|_| ());
        let info = self.agent_info(id).await?;
        // Before anything else: the server may call a revoked agent active
        // (T24); `upload_grant` refuses it again when signing.
        if self.cache.revocations.contains_key(&id) {
            return Err(ClientError::Security(format!(
                "agent {} was revoked from this device; its grant never changes again",
                info.name
            )));
        }
        if info.status != AgentStatus::Active {
            return Err(ClientError::Invalid(format!(
                "agent {} is {}: only an active agent's grant changes; approve a pending one",
                info.name,
                info.status.as_str()
            )));
        }
        let grant = info.grant.as_ref().ok_or_else(|| {
            ClientError::Invalid(format!("agent {} has no grant to change", info.name))
        })?;
        let public = PublicIdentity::decode(info.public_identity.as_bytes())?;
        let old = self.open_grant(id, &public, grant)?;
        if read_only(&old) == Some(ReadOnlyReason::Proxy) {
            return Err(ClientError::Invalid(format!(
                "agent {} has the credential proxy's grant: change it with `klav proxy …`, not here",
                info.name
            )));
        }
        // The editor's model cannot say what a rules or issuer grant holds:
        // a change in that model would sign a simpler copy (F3). The whole
        // policy (`klav agent approve --policy-file`) still can.
        if matches!(change.policy, ChangePolicy::Editor(_))
            && let Some(reason @ (ReadOnlyReason::Rules | ReadOnlyReason::Issuer)) = read_only(&old)
        {
            return Err(ClientError::Invalid(format!(
                "agent {}'s grant {}: the editor does not change it; use `klav agent approve {} --policy-file <file>`",
                info.name,
                match reason {
                    ReadOnlyReason::Issuer => "starts sandboxes",
                    _ => "has rules the editor cannot show",
                },
                info.name
            )));
        }
        let mut warnings = crate::agents::proxy_check(id, &info.name, synced, self.preferences())?;
        let policy = match &change.policy {
            ChangePolicy::Editor(model) => model.to_policy().map_err(ClientError::Invalid)?,
            ChangePolicy::Rules(policy) => policy.clone(),
        };
        let policy = self.resolve_policy(policy)?;
        self.refuse_open_protected(&policy)?;
        policy
            .check_grantable()
            .map_err(|e| ClientError::Invalid(e.to_string()))?;
        let mut wanted = Vec::new();
        for project in &change.projects {
            wanted.push(self.find_project_anywhere(project)?);
        }
        for vault in &change.vaults {
            let vault = self.find_vault(vault)?;
            let mut whole: Vec<ProjectId> = self
                .projects(Some(vault))
                .into_iter()
                .map(|p| p.id)
                .collect();
            whole.sort();
            wanted.extend(whole);
        }
        let mut seen = BTreeSet::new();
        wanted.retain(|p| seen.insert(*p));
        let before: BTreeSet<ProjectId> = old.projects.iter().map(|p| p.project_id).collect();
        if wanted.is_empty() && !before.is_empty() {
            return Err(ClientError::Invalid(
                "keep at least one project, or revoke the agent".into(),
            ));
        }
        if old.sandbox.is_some() && crate::issuers::inject_allowed(&policy) {
            warnings.push(format!(
                "agent {} starts sandboxes, and this policy lets it `inject` without asking: it could pass a provider's token to the command that creates a sandbox (T171)",
                info.name
            ));
        }
        let added: Vec<ProjectId> = wanted
            .iter()
            .copied()
            .filter(|p| !before.contains(p))
            .collect();
        let removed: Vec<ProjectId> = old
            .projects
            .iter()
            .map(|p| p.project_id)
            .filter(|p| !wanted.contains(p))
            .collect();
        let widens = !added.is_empty() || !policy_narrows(&old.policy, &policy);
        let mut lines: Vec<ChangeLine> = added
            .iter()
            .map(|p| ChangeLine {
                what: ChangeWhat::ProjectAdded {
                    project: self.place(*p),
                },
                widens: true,
            })
            .chain(removed.iter().map(|p| ChangeLine {
                what: ChangeWhat::ProjectRemoved {
                    project: self.place(*p),
                },
                widens: false,
            }))
            .collect();
        lines.extend(policy_lines(&old.policy, &policy, widens));
        if lines.is_empty() {
            return Err(ClientError::Invalid(
                "nothing changes: the new grant is the one in force".into(),
            ));
        }
        if widens && !lines.iter().any(|l| l.widens) {
            // Prudent: say it on the sheet even if no single line shows it.
            lines.push(ChangeLine {
                what: ChangeWhat::Rules,
                widens: true,
            });
        }
        // What the change resolves to, not how it was asked: names and
        // whole vaults are resolved again when signing, so a project created
        // in between changes the digest and the sheet must be seen again
        // (T188).
        #[derive(Serialize)]
        struct Resolved<'a> {
            projects: &'a [ProjectId],
            policy: &'a Policy,
            rotate_removed: bool,
        }
        // By ID: the same projects give the same digest, whatever order a
        // whole vault's projects came in (two names apart only in case).
        let mut resolved = wanted.clone();
        resolved.sort();
        let change_bytes = serde_json::to_vec(&Resolved {
            projects: &resolved,
            policy: &policy,
            rotate_removed: change.rotate_removed,
        })
        .map_err(|e| ClientError::Invalid(format!("grant change: {e}")))?;
        let digest = agent::grant_change_digest(grant.payload.as_bytes(), &change_bytes);
        let removed_projects = removed.iter().map(|p| self.place(*p)).collect();
        Ok(PreparedGrantChange {
            preview: GrantChangePreview {
                agent_id: id,
                name: info.name,
                version: old.version + 1,
                lines,
                widens,
                digest,
                removed_projects,
                rotate_removed: change.rotate_removed && !removed.is_empty(),
                warnings,
            },
            public,
            old,
            policy,
            wanted,
            removed,
        })
    }

    /// Signs a change checked by [`Self::prepare_grant_change`] (F4
    /// `grant_change_apply`, after presence when it widens). The server
    /// refuses it if the grant changed meanwhile (`409`, the version must
    /// be the next one). With `rotate_removed`, then changes the key of
    /// each project taken away; a failure there leaves the new grant in
    /// force and says what is left.
    pub async fn commit_grant_change(
        &mut self,
        prepared: PreparedGrantChange,
    ) -> ClientResult<GrantChangeReport> {
        let PreparedGrantChange {
            preview,
            public,
            old,
            policy,
            wanted,
            removed,
        } = prepared;
        let id = preview.agent_id;
        let floor = old.v;
        let mut payload = old;
        payload.projects = self.granted_projects(id, &public, wanted)?;
        payload.policy = policy;
        payload.version = preview.version;
        payload.issued_at = now_ms();
        payload.v = payload.version_after(floor);
        // The key change is written down before the grant that asks for it
        // goes out, so `klavd` resumes it after a lock or a restart (P11);
        // put back as it was if the server does not take the grant.
        let narrowing = preview.rotate_removed && !removed.is_empty();
        let before = if narrowing {
            Some(self.note_narrowing(id, &preview.name, &removed)?)
        } else {
            None
        };
        let agent = match self.upload_grant(id, &public, payload).await {
            Ok(agent) => agent,
            Err(e) => {
                if let Some(before) = before
                    && let Err(undo) = self.restore_narrowing(id, before)
                {
                    self.warnings.push(format!(
                        "the grant did not change, but a key change for it stays written down: {undo}"
                    ));
                }
                return Err(e);
            }
        };
        let mut report = GrantChangeReport {
            agent,
            rotated: Vec::new(),
            regranted: Vec::new(),
            not_regranted: Vec::new(),
            failed: None,
            pending: Vec::new(),
            skipped: Vec::new(),
        };
        if !narrowing {
            return Ok(report);
        }
        // From here the grant is in force: whatever stops the key change
        // is the key change's, said in the report, never a failed grant
        // change (third re-check, N6).
        loop {
            let step = match self.rotation_step(id).await {
                Ok(step) => step,
                Err(e) => {
                    report.failed = Some(format!(
                        "the new grant is in force, but the key change of the projects taken away stopped: {e}"
                    ));
                    break;
                }
            };
            report.rotated.extend(step.rotated);
            report.regranted.extend(step.regranted);
            report.not_regranted.extend(step.not_regranted);
            for why in step.skipped {
                if !report.skipped.contains(&why) {
                    report.skipped.push(why);
                }
            }
            if step.failed.is_some() {
                report.failed = step.failed;
                break;
            }
            if step.done {
                break;
            }
        }
        match self.narrowing_left(id) {
            Ok(left) => report.pending = left,
            Err(e) => {
                report.failed.get_or_insert(format!(
                    "the new grant is in force, but what its key change still owes cannot be read: {e}"
                ));
            }
        }
        Ok(report)
    }

    /// Prepares and signs in one go, checking `shown` (the digest of the
    /// sheet the person saw) against the grant in force now. For callers
    /// that already have the person's presence (the master password opened
    /// this process).
    pub async fn change_grant(
        &mut self,
        id: AgentId,
        change: &GrantChange,
        shown: &str,
    ) -> ClientResult<GrantChangeReport> {
        let prepared = self.prepare_grant_change(id, change).await?;
        prepared.check_shown(shown)?;
        self.commit_grant_change(prepared).await
    }

    /// `vault/project`, or the ID if this device does not see it.
    pub(crate) fn place(&self, project: ProjectId) -> String {
        self.projects.get(&project).map_or_else(
            || project.to_string(),
            |entry| {
                let vault = self
                    .vaults
                    .get(&entry.vault)
                    .map_or_else(|| entry.vault.to_string(), |v| v.meta.name().to_owned());
                format!("{vault}/{}", entry.meta.name())
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(p: Permission, e: Effect) -> Rule {
        Rule::new(p, e)
    }

    fn sites(list: &[&str]) -> Vec<DomainPattern> {
        list.iter().map(|s| s.parse().unwrap()).collect()
    }

    fn windows(list: &[&str]) -> Vec<TimeWindow> {
        list.iter().map(|s| s.parse().unwrap()).collect()
    }

    fn model(settings: &[(Permission, Effect)]) -> EditorPolicy {
        EditorPolicy {
            permissions: settings
                .iter()
                .map(|(p, e)| PermissionSetting {
                    permission: *p,
                    effect: Some(*e),
                })
                .collect(),
            ..EditorPolicy::default()
        }
    }

    /// What `klav agent approve` builds from its flags (`build_policy` in
    /// `klav-cli`), for the round trip below.
    fn approve_flags(
        allow: &[Permission],
        ask: &[Permission],
        deny: &[Permission],
        fill: &[&str],
        hours: &[&str],
        expires: Option<u64>,
    ) -> Policy {
        let mut policy = Policy::default();
        for (list, effect) in [
            (allow, Effect::Allow),
            (ask, Effect::Ask),
            (deny, Effect::Deny),
        ] {
            for p in list {
                policy.rules.push(rule(*p, effect));
            }
        }
        if !fill.is_empty() {
            policy.rules.push(Rule {
                scope: Scope {
                    domains: sites(fill),
                    ..Scope::default()
                },
                ..rule(Permission::Fill, Effect::Allow)
            });
        }
        if !hours.is_empty() {
            for p in Permission::GRANTABLE {
                if !policy.rules.iter().any(|r| r.permission == p) {
                    policy.rules.push(rule(p, p.default_effect()));
                }
            }
            for r in &mut policy.rules {
                if r.scope.hours.is_empty() {
                    r.scope.hours = windows(hours);
                }
            }
        }
        policy.expires_at = expires;
        policy
    }

    #[test]
    fn every_policy_klav_agent_approve_writes_round_trips_through_the_editor() {
        use Permission::*;
        let cases = [
            approve_flags(&[], &[], &[], &[], &[], None),
            approve_flags(&[Reveal], &[], &[], &[], &[], None),
            approve_flags(&[], &[Reveal, Totp], &[Delete, Inject], &[], &[], Some(99)),
            approve_flags(&[], &[], &[], &["github.com", "*.gitlab.com"], &[], None),
            approve_flags(&[List], &[Update], &[], &["github.com"], &[], None),
            approve_flags(&[], &[], &[], &[], &["mon-fri 09:00-18:00 -06:00"], None),
            approve_flags(
                &[Reveal],
                &[Create],
                &[Delete],
                &["github.com"],
                &["mon-fri 09:00-18:00 -06:00", "sat 10:00-12:00 +01:00"],
                Some(1_900_000_000),
            ),
            // An explicit default with hours is the same policy.
            approve_flags(&[List], &[], &[], &[], &["daily 00:00-00:00 +00:00"], None),
        ];
        for policy in cases {
            let model = EditorPolicy::from_policy(&policy)
                .unwrap_or_else(|| panic!("not editable: {policy:?}"));
            let back = model.to_policy().unwrap();
            assert!(
                same_rules(&back.rules, &policy.rules),
                "{policy:?}\n{back:?}"
            );
            assert_eq!(back.expires_at, policy.expires_at);
            // And the model of what it writes is itself.
            assert_eq!(EditorPolicy::from_policy(&back), Some(model));
        }
    }

    #[test]
    fn rules_the_editor_does_not_model_are_read_only() {
        let tagged = Policy {
            rules: vec![Rule {
                scope: Scope {
                    tags: vec!["prod".into()],
                    ..Scope::default()
                },
                ..rule(Permission::Reveal, Effect::Ask)
            }],
            expires_at: None,
        };
        let two_rules = Policy {
            rules: vec![
                rule(Permission::Fill, Effect::Deny),
                Rule {
                    scope: Scope {
                        domains: sites(&["github.com"]),
                        ..Scope::default()
                    },
                    ..rule(Permission::Fill, Effect::Allow)
                },
            ],
            expires_at: None,
        };
        let rule_expiry = Policy {
            rules: vec![Rule {
                expires_at: Some(5),
                ..rule(Permission::Reveal, Effect::Allow)
            }],
            expires_at: None,
        };
        let mixed_hours = Policy {
            rules: vec![
                Rule {
                    scope: Scope {
                        hours: windows(&["mon 09:00-10:00 +00:00"]),
                        ..Scope::default()
                    },
                    ..rule(Permission::Reveal, Effect::Ask)
                },
                rule(Permission::List, Effect::Allow),
            ],
            expires_at: None,
        };
        let proxy = Policy {
            rules: vec![rule(Permission::Proxy, Effect::Deny)],
            expires_at: None,
        };
        for policy in [tagged, two_rules, rule_expiry, mixed_hours, proxy] {
            assert_eq!(EditorPolicy::from_policy(&policy), None, "{policy:?}");
        }
    }

    #[test]
    fn the_model_refuses_what_it_cannot_write() {
        let mut m = model(&[(Permission::Fill, Effect::Allow)]);
        m.fill_sites = sites(&["github.com"]);
        assert!(m.to_policy().unwrap_err().contains("not both"));
        let m = model(&[(Permission::Proxy, Effect::Allow)]);
        assert!(m.to_policy().unwrap_err().contains("not set"));
        let m = model(&[
            (Permission::Reveal, Effect::Allow),
            (Permission::Reveal, Effect::Deny),
        ]);
        assert!(m.to_policy().unwrap_err().contains("twice"));
    }

    fn lines(old: &EditorPolicy, new: &EditorPolicy) -> Vec<ChangeLine> {
        let (o, n) = (old.to_policy().unwrap(), new.to_policy().unwrap());
        policy_lines(&o, &n, !policy_narrows(&o, &n))
    }

    #[test]
    fn the_sheet_shows_only_the_differences_and_marks_what_widens() {
        let old = model(&[(Permission::Reveal, Effect::Deny)]);
        let mut new = model(&[(Permission::Reveal, Effect::Ask)]);
        new.expires_at = Some(10);
        let l = lines(&old, &new);
        assert_eq!(l.len(), 2, "{l:?}");
        assert_eq!(
            l[0].what,
            ChangeWhat::Permission {
                permission: Permission::Reveal,
                before: Effect::Deny,
                before_default: false,
                after: Effect::Ask,
                after_default: false,
            }
        );
        assert!(l[0].widens);
        assert!(!l[1].widens, "an expiry where there was none narrows");
        assert_eq!(l[0].text(), "reveal: deny -> ask  [widens]");
        // Back to the default: `reveal` denies by default, so narrower.
        let l = lines(&new, &EditorPolicy::default());
        assert!(matches!(
            l[0].what,
            ChangeWhat::Permission {
                after: Effect::Deny,
                after_default: true,
                ..
            }
        ));
        assert!(!l[0].widens);
        assert!(l[1].widens, "no expiry is later than one");
    }

    #[test]
    fn fill_sites_and_hours_lines() {
        let old = EditorPolicy {
            fill_sites: sites(&["github.com", "gitlab.com"]),
            hours: windows(&["mon-fri 09:00-18:00 -06:00"]),
            ..EditorPolicy::default()
        };
        let mut fewer = old.clone();
        fewer.fill_sites = sites(&["github.com"]);
        let l = lines(&old, &fewer);
        assert_eq!(l.len(), 1);
        assert!(!l[0].widens);
        // Dropping the sites lets `fill` through everywhere.
        let mut none = old.clone();
        none.fill_sites.clear();
        let l = lines(&old, &none);
        assert_eq!(l.len(), 1, "{l:?}");
        assert!(matches!(l[0].what, ChangeWhat::FillSites { .. }));
        assert!(l[0].widens);
        // Hours to always widens, and says so.
        let mut always = old.clone();
        always.hours.clear();
        let l = lines(&old, &always);
        assert_eq!(l.len(), 1);
        assert_eq!(
            l[0].what,
            ChangeWhat::Hours {
                before: vec!["mon,tue,wed,thu,fri 09:00-18:00 -06:00".into()],
                after: Vec::new(),
            }
        );
        assert!(l[0].widens);
    }

    #[test]
    fn a_change_serializes_as_the_digest_expects() {
        let change = GrantChange {
            projects: vec!["Personal/General".into()],
            vaults: Vec::new(),
            policy: ChangePolicy::Editor(model(&[(Permission::Reveal, Effect::Ask)])),
            rotate_removed: false,
        };
        let json = serde_json::to_value(&change).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "projects": ["Personal/General"],
                "policy": {"editor": {"permissions": [{"permission": "reveal", "effect": "ask"}]}},
                "rotate_removed": false,
            })
        );
        let back: GrantChange = serde_json::from_value(json).unwrap();
        assert_eq!(back, change);
    }
}
