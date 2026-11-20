//! Revoking an agent and changing its grant from the apps (ADR 0033,
//! amendment of 2026-11-10, F5): "what it saw", the revocation and its key
//! changes, the grant in the editor's model and the sheet of differences.
//!
//! The Mac reads them from `klavd` (`DaemonEngine`); the iPhone reads
//! "what it saw" and revokes through `KlavCore` (layer 5), one project per
//! call. The editor's records are only `DaemonEngine`'s for now (P10).
//!
//! Every text an agent chose (its name, the names of the other agents in a
//! report) is cleaned as `AgentItem`'s are (T136). No record holds a
//! secret.

// The editor's records are only `DaemonEngine`'s for now (P10).
#![cfg_attr(not(feature = "daemon"), allow(dead_code))]

use std::str::FromStr;

use klav_client::agents::{AgentView, GrantedProjectView};
use klav_client::grant_change::{
    ChangeLine, ChangePolicy, ChangeWhat, EDITABLE, EditorPolicy, GrantChange, GrantChangePreview,
    GrantChangeReport, GrantEditor, PermissionSetting, ReadOnlyReason,
};
use klav_client::revoke::{Exposure, PendingRevocation, RevokeReport, RotationStep, SeenItem};
use klav_core::ids::ProjectId;
use klav_core::policy::{
    ClockTime, DomainPattern, Effect, Policy, Rule, TimeWindow, UtcOffset, Weekday,
};

use crate::types::AgentItem;
use crate::{KlavError, KlavResult, MAX_AGENT_TEXT, agent_item, permission};

/// An agent's own words, cleaned for one line (T136).
fn agent_text(text: &str) -> String {
    klav_core::text::shown(text, MAX_AGENT_TEXT)
}

/// Longest message from a report shown in the app.
const MAX_REPORT_TEXT: usize = 1000;

/// A report's message, which can carry agents' names (`name: why`, joined
/// by `Regrants::failure`) and the server's words: one line, nothing
/// hidden (T136).
pub(crate) fn report_text(text: &str) -> String {
    klav_core::text::shown(text, MAX_REPORT_TEXT)
}

/// `name: why` from a report, with the agent's name cleaned. The reason
/// is Klav's.
fn agent_line(line: &str) -> String {
    match line.split_once(": ") {
        Some((name, why)) => format!("{}: {why}", agent_text(name)),
        None => agent_text(line),
    }
}

fn effect_name(effect: Effect) -> String {
    match effect {
        Effect::Allow => "allow",
        Effect::Ask => "ask",
        Effect::Deny => "deny",
    }
    .to_owned()
}

fn effect(name: &str) -> KlavResult<Effect> {
    match name.trim() {
        "allow" => Ok(Effect::Allow),
        "ask" => Ok(Effect::Ask),
        "deny" => Ok(Effect::Deny),
        other => Err(KlavError::invalid(format!("not an effect: {other}"))),
    }
}

fn weekday_name(day: Weekday) -> String {
    serde_json::to_value(day)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default()
}

fn weekday(name: &str) -> KlavResult<Weekday> {
    serde_json::from_value(serde_json::Value::String(name.trim().to_lowercase()))
        .map_err(|_| KlavError::invalid(format!("not a day: {name}")))
}

// MARK: - Projects

/// A project an agent holds the key of.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct GrantedProjectInfo {
    pub vault_id: String,
    /// Empty if this device no longer sees it.
    pub vault: String,
    pub project_id: String,
    /// Empty if this device no longer sees it.
    pub project: String,
}

pub(crate) fn project_info(p: &GrantedProjectView) -> GrantedProjectInfo {
    GrantedProjectInfo {
        vault_id: p.vault_id.to_string(),
        vault: p.vault.clone(),
        project_id: p.project_id.to_string(),
        project: p.project.clone(),
    }
}

// MARK: - "What it saw"

/// One item an agent used, from the audit log.
#[derive(Debug, Clone, uniffi::Record)]
pub struct SeenItemInfo {
    pub item_id: String,
    /// `klav://…`, if this device still sees the item.
    pub reference: Option<String>,
    /// Permissions it used and were allowed (`fill`, `reveal`…).
    pub permissions: Vec<String>,
    /// It obtained a secret value from it.
    pub secret: bool,
    /// Attachments delivered to it.
    pub attachments: u64,
    /// Allowed uses.
    pub uses: u64,
    pub first_ms: i64,
    pub last_ms: i64,
    /// In the trash now.
    pub trashed: bool,
    /// Gone from this device.
    pub deleted: bool,
}

fn seen_item(s: SeenItem) -> SeenItemInfo {
    SeenItemInfo {
        item_id: s.item_id.to_string(),
        reference: s.reference,
        permissions: s.permissions,
        secret: s.secret,
        attachments: s.attachments,
        uses: s.uses,
        first_ms: s.first_at,
        last_ms: s.last_at,
        trashed: s.trashed,
        deleted: s.deleted,
    }
}

/// What changing the keys of an agent's projects costs (F2, item 2): the
/// items whose keys are wrapped again and the other agents that get a new
/// grant by themselves.
#[derive(Debug, Clone, Default, uniffi::Record)]
pub struct KeyChangeCostInfo {
    /// Items in those projects, as this device lists them, the trash
    /// included. Each stored version of each one is wrapped again too.
    pub items: u32,
    /// Other active agents that hold one of those projects (their names,
    /// cleaned).
    pub other_agents: Vec<String>,
    /// A project's items could not be listed: `items` is a lower bound.
    pub items_at_least: bool,
    /// The agents, or one agent's grant, could not be read: others may
    /// get a new grant too.
    pub others_at_least: bool,
}

/// "What it saw" (F2, item 1): the projects whose keys it held, what the
/// audit log says it used, and how many attempts were denied.
#[derive(Debug, Clone, uniffi::Record)]
pub struct ExposureInfo {
    pub agent: AgentItem,
    pub projects: Vec<GrantedProjectInfo>,
    /// Most recent first.
    pub items: Vec<SeenItemInfo>,
    pub denied: u64,
    /// Why `items` and `denied` are empty: the log could not be read as
    /// this device holds it. Revoking still works.
    pub log_warning: Option<String>,
    /// What «Also change its projects' keys» costs.
    pub cost: KeyChangeCostInfo,
    /// `projects` is empty because this device cannot tell which projects
    /// it held, not because it held none: the key change still looks for
    /// them.
    pub projects_unknown: bool,
}

pub(crate) fn exposure_info(e: Exposure, cost: KeyChangeCostInfo) -> ExposureInfo {
    ExposureInfo {
        projects: e.projects.iter().map(project_info).collect(),
        agent: agent_item(e.agent),
        items: e.items.into_iter().map(seen_item).collect(),
        denied: e.denied,
        log_warning: e.log_warning.as_deref().map(report_text),
        cost,
        projects_unknown: e.projects_unknown,
    }
}

/// The cost line of a key change, from what the engine answered: how many items
/// each listing of the projects found (a failed one makes the count a
/// lower bound), and the agents (a failed read, or an active agent whose
/// grant this device cannot read, means others may get a new grant too).
/// Never a zero it could not count.
pub(crate) fn cost_of(
    agent: &str,
    projects: &[GrantedProjectInfo],
    listings: &[KlavResult<usize>],
    agents: KlavResult<Vec<AgentView>>,
) -> KeyChangeCostInfo {
    let mut cost = KeyChangeCostInfo::default();
    for listed in listings {
        match listed {
            Ok(n) => {
                cost.items = cost
                    .items
                    .saturating_add(u32::try_from(*n).unwrap_or(u32::MAX));
            }
            Err(_) => cost.items_at_least = true,
        }
    }
    let ids: std::collections::BTreeSet<&str> =
        projects.iter().map(|p| p.project_id.as_str()).collect();
    match agents {
        Ok(list) => {
            // An active agent whose grant this device cannot read may hold
            // one of them: it is not left out silently.
            cost.others_at_least = list.iter().any(|a| {
                a.id.to_string() != agent
                    && a.status == klav_proto::agent::AgentStatus::Active
                    && a.grant_error.is_some()
            });
            for other in agent_items_with_grants(list) {
                if other.0.id != agent
                    && other.0.status == "active"
                    && other.1.iter().any(|p| ids.contains(p.as_str()))
                {
                    cost.other_agents.push(other.0.name);
                }
            }
        }
        Err(_) => cost.others_at_least = true,
    }
    cost
}

/// The agents with the IDs of their granted projects.
fn agent_items_with_grants(list: Vec<AgentView>) -> Vec<(AgentItem, Vec<String>)> {
    list.into_iter()
        .map(|a| {
            let projects = a
                .grant
                .as_ref()
                .map(|g| {
                    g.projects
                        .iter()
                        .map(|p| p.project_id.to_string())
                        .collect()
                })
                .unwrap_or_default();
            (agent_item(a), projects)
        })
        .collect()
}

// MARK: - Revoking

/// What revoking did (F2). The app calls it twice: without the key change
/// first («Revoked»), then with it; «Done» only with `complete` from the
/// second call.
#[derive(Debug, Clone, uniffi::Record)]
pub struct RevokeReportInfo {
    /// The agent, now revoked.
    pub agent: AgentItem,
    pub exposure: ExposureInfo,
    /// `vault/project` whose key changed in this call.
    pub rotated: Vec<String>,
    /// `vault/project` changed by an earlier call for this revocation.
    pub already_rotated: Vec<String>,
    /// Items granted one by one whose key changed.
    pub rekeyed_items: u32,
    /// Items whose key still has to change.
    pub items_pending: u32,
    /// Other agents that got a new grant (names, cleaned).
    pub regranted: Vec<String>,
    /// Other agents whose grant could not be issued again (`name: why`).
    pub not_regranted: Vec<String>,
    /// What stopped the key changes, if they stopped.
    pub failed: Option<String>,
    /// `vault/project` still to change.
    pub pending: Vec<String>,
    pub warnings: Vec<String>,
    /// The key change went ahead without the audit log, which may list
    /// another project: not done until it is read.
    pub log_unchecked: bool,
    /// `vault/project: why` of projects whose key cannot change from this
    /// Mac: they do not keep it from being complete.
    pub skipped: Vec<String>,
    /// Everything asked for is done.
    pub complete: bool,
}

pub(crate) fn revoke_report_info(r: RevokeReport, cost: KeyChangeCostInfo) -> RevokeReportInfo {
    let complete = r.complete();
    RevokeReportInfo {
        agent: agent_item(r.agent),
        exposure: exposure_info(r.exposure, cost),
        rotated: r.rotated.into_iter().map(|p| p.project).collect(),
        already_rotated: r.already_rotated,
        rekeyed_items: u32::try_from(r.rekeyed.len()).unwrap_or(u32::MAX),
        items_pending: u32::try_from(r.items_pending.len()).unwrap_or(u32::MAX),
        regranted: r.regranted.iter().map(|n| agent_text(n)).collect(),
        not_regranted: r.not_regranted.iter().map(|l| agent_line(l)).collect(),
        failed: r.failed.as_deref().map(report_text),
        pending: r.pending,
        warnings: r.warnings.iter().map(|w| report_text(w)).collect(),
        log_unchecked: r.log_unchecked,
        skipped: r.skipped.iter().map(|s| report_text(s)).collect(),
        complete,
    }
}

/// What one step of a revocation's key change did on the iPhone
/// (`KlavCore::revocation_step`): at most one project, so the vault never
/// waits on a whole key change, and a step cut off by iOS loses nothing
/// (the record says what is left).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct RevocationStepInfo {
    /// `vault/project` whose key changed in this step.
    pub rotated: Option<String>,
    /// Items granted one by one whose key changed in this step.
    pub rekeyed_items: u32,
    /// Other agents that got a new grant (names, cleaned).
    pub regranted: Vec<String>,
    /// Other agents whose grant could not be issued again (`name: why`).
    pub not_regranted: Vec<String>,
    /// What Klav can't reach (`vault/project: why`, `item <id>: why`).
    pub skipped: Vec<String>,
    /// What stopped this step.
    pub failed: Option<String>,
    /// Nothing is left of the key change.
    pub done: bool,
    /// `vault/project` still to change after this step, in order: a
    /// revocation's projects (none when the person declined the key
    /// change, P7), then those of a narrowing. Gone projects are in
    /// `skipped`, not here. See [`owed_projects`].
    pub pending: Vec<String>,
    /// The step moved the key change: it changed a key, issued a grant
    /// again, or changed what the record says is left. The app stops after
    /// two steps in a row that move nothing, as `klavd` does: they would
    /// only repeat each other (review of #308, N1).
    pub moved: bool,
}

/// The projects still owed after a step, in the order they change.
///
/// - The record of the agent opened after the step (`after`): what it says
///   is pending, the revocation's (none when the person declined the key
///   change, P7) and the narrowing's.
/// - It did not open after the step, but did before (`before`): what was
///   pending then, without the project this step changed (`changed`). For
///   a revocation with the key change, the cache's projects not yet
///   rotated (`revocation_left`), which already count this step.
/// - Neither opened: [`klav_client::Unlocked::rotation_step`] reads the
///   record first, so a step that ran had one. Without any record nothing
///   tells a revocation with the key change from one without it, or a
///   narrowing: the cache's projects then, never "nothing owed".
pub(crate) fn owed_projects(
    before: Option<&[PendingRevocation]>,
    after: Option<&[PendingRevocation]>,
    changed: Option<&str>,
    revocation_left: impl FnOnce() -> Vec<String>,
) -> Vec<String> {
    let mut owed: Vec<String> = Vec::new();
    let mut add = |project: &String| {
        if !owed.contains(project) {
            owed.push(project.clone());
        }
    };
    match (after, before) {
        (Some(entries), _) => entries.iter().flat_map(|p| &p.pending).for_each(&mut add),
        (None, Some(entries)) => {
            let mut left = Some(revocation_left);
            for entry in entries {
                if entry.narrowed {
                    entry
                        .pending
                        .iter()
                        .filter(|p| Some(p.as_str()) != changed)
                        .for_each(&mut add);
                } else if !entry.without_key_change
                    && let Some(left) = left.take()
                {
                    left().iter().for_each(&mut add);
                }
            }
        }
        (None, None) => revocation_left().iter().for_each(&mut add),
    }
    owed
}

pub(crate) fn revocation_step_info(
    s: RotationStep,
    pending: Vec<String>,
    record_changed: bool,
) -> RevocationStepInfo {
    let moved =
        s.rotated.is_some() || !s.rekeyed.is_empty() || !s.regranted.is_empty() || record_changed;
    RevocationStepInfo {
        moved,
        rotated: s.rotated.map(|r| r.project),
        rekeyed_items: count(s.rekeyed.len()),
        regranted: s.regranted.iter().map(|n| agent_text(n)).collect(),
        not_regranted: s.not_regranted.iter().map(|l| agent_line(l)).collect(),
        skipped: s.skipped.iter().map(|x| report_text(x)).collect(),
        failed: s.failed.as_deref().map(report_text),
        done: s.done,
        pending,
    }
}

/// A revocation whose key change was asked for and is not finished:
/// «Revoked. Keys left to change (3 of 5)».
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct RevocationInfo {
    pub agent_id: String,
    /// Its name when it was revoked (cleaned); none while `klavd` is
    /// locked.
    pub name: Option<String>,
    /// Projects whose key it held.
    pub projects: u32,
    /// Those already changed.
    pub rotated: u32,
    /// Changed projects whose other agents still need a new grant.
    pub regrants: u32,
    /// This device does not know which projects it had: never «Done».
    pub unknown_projects: bool,
    /// The agent is active: the key change of projects taken away from it
    /// (`rotate_removed`), not a revocation. Never offer «Finish» for it:
    /// that revokes. `klavd` goes on with it at the next unlock.
    pub narrowed: bool,
    /// Items shared with it one by one still without a new key.
    pub items: u32,
    /// The audit log has not been read for this key change yet: never
    /// «Done».
    pub log_unchecked: bool,
    /// A revocation without the key change: only items shared one by one
    /// change their keys, so never a word about every key, and what is
    /// skipped is items.
    pub without_key_change: bool,
    /// Projects and items whose key cannot change from this Mac (deleted,
    /// no longer this account's, or an item this Mac no longer sees): they
    /// do not keep it from being done.
    pub skipped: u32,
    /// `vault/project: why` of those (`agent_revocations` only; empty in
    /// `status`, which only counts).
    pub skipped_projects: Vec<String>,
    /// Projects whose key is still to change (skipped ones aside).
    pub to_change: u32,
    /// Something is left that `klavd` or «Finish» can do. False when only
    /// skipped ones are left: then it is over as far as Klav can reach,
    /// and the page says which it could not.
    pub needs_work: bool,
    /// `klavd` is changing keys for it right now.
    pub running: bool,
    /// What stopped the last step; none while locked.
    pub last_error: Option<String>,
    /// `vault/project` still to change; empty in `status`, which only
    /// counts.
    pub pending: Vec<String>,
}

fn count(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

pub(crate) fn pending_revocation_info(p: PendingRevocation) -> RevocationInfo {
    RevocationInfo {
        agent_id: p.agent_id.to_string(),
        name: Some(agent_text(&p.name)).filter(|n| !n.is_empty()),
        projects: count(p.projects.len()),
        rotated: count(p.rotated.len()),
        regrants: count(p.regrants.len()),
        unknown_projects: p.unknown_projects,
        narrowed: p.narrowed,
        items: count(p.items),
        log_unchecked: p.log_unchecked,
        without_key_change: p.without_key_change,
        skipped: count(p.skipped.len()),
        skipped_projects: p.skipped.iter().map(|s| report_text(s)).collect(),
        to_change: count(p.pending.len()),
        needs_work: p.needs_work(),
        running: false,
        last_error: p.last_error.as_deref().map(report_text),
        pending: p.pending,
    }
}

#[cfg(feature = "daemon")]
pub(crate) fn revocation_progress_info(
    p: klav_daemon::protocol::RevocationProgress,
) -> RevocationInfo {
    RevocationInfo {
        agent_id: p.agent_id.to_string(),
        name: p.name.as_deref().map(agent_text).filter(|n| !n.is_empty()),
        projects: count(p.projects),
        rotated: count(p.rotated),
        regrants: count(p.regrants),
        unknown_projects: p.unknown_projects,
        narrowed: p.narrowed,
        items: count(p.items),
        log_unchecked: p.log_unchecked,
        without_key_change: p.without_key_change,
        skipped: count(p.skipped),
        skipped_projects: Vec::new(),
        to_change: count(p.to_change),
        needs_work: p.needs_work,
        running: p.running,
        last_error: p.last_error.as_deref().map(report_text),
        pending: Vec::new(),
    }
}

// MARK: - The grant in the editor (F3)

/// A weekly window, as the editor shows and sends it back. Sent back
/// untouched, it is the same window (the days keep their order).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct TimeWindowInfo {
    /// `mon` … `sun`; empty: every day.
    pub days: Vec<String>,
    /// Minutes since midnight (inclusive).
    pub start_minutes: u16,
    /// Minutes since midnight (exclusive); at or before `start`: it ends
    /// the next day.
    pub end_minutes: u16,
    /// Minutes east of UTC of the clock it is written in.
    pub utc_offset_minutes: i16,
}

fn window_info(w: &TimeWindow) -> TimeWindowInfo {
    TimeWindowInfo {
        days: w.days.iter().map(|d| weekday_name(*d)).collect(),
        start_minutes: w.start.minutes(),
        end_minutes: w.end.minutes(),
        utc_offset_minutes: w.utc_offset.minutes(),
    }
}

fn clock(minutes: u16) -> KlavResult<ClockTime> {
    ClockTime::new(minutes / 60, minutes % 60)
        .ok_or_else(|| KlavError::invalid(format!("not a time of day: {minutes} minutes")))
}

fn window(w: &TimeWindowInfo) -> KlavResult<TimeWindow> {
    Ok(TimeWindow {
        days: w
            .days
            .iter()
            .map(|d| weekday(d))
            .collect::<KlavResult<_>>()?,
        start: clock(w.start_minutes)?,
        end: clock(w.end_minutes)?,
        utc_offset: UtcOffset::from_minutes(w.utc_offset_minutes).ok_or_else(|| {
            KlavError::invalid(format!(
                "not a UTC offset: {} minutes",
                w.utc_offset_minutes
            ))
        })?,
    })
}

/// A window in the sheet's text (`mon,tue 09:00-18:00 -06:00`), as the
/// app's records.
fn window_text_info(text: &str) -> Option<TimeWindowInfo> {
    TimeWindow::from_str(text).ok().map(|w| window_info(&w))
}

/// One permission in the editor.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PermissionSettingInfo {
    /// `list`, `fill`, `inject`, `totp`, `reveal`, `create`, `update`,
    /// `delete`.
    pub permission: String,
    /// `allow`, `ask` or `deny`; none: its default.
    pub effect: Option<String>,
    /// What it gets without a rule (ADR 0006 §1).
    pub default_effect: String,
}

/// A grant's policy in the editor's model: every permission it edits, in
/// order, the `fill` sites, the hours and the expiry.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct EditorPolicyInfo {
    /// The eight editable permissions, always, in the editor's order.
    pub permissions: Vec<PermissionSettingInfo>,
    /// Where `fill` may fill; with sites, `fill` has no effect of its own.
    pub fill_sites: Vec<String>,
    /// None: always.
    pub hours: Vec<TimeWindowInfo>,
    /// When the whole grant ends (Unix seconds); none: never.
    pub expires_at_secs: Option<u64>,
}

fn editor_policy_info(e: &EditorPolicy) -> EditorPolicyInfo {
    EditorPolicyInfo {
        permissions: EDITABLE
            .iter()
            .map(|p| PermissionSettingInfo {
                permission: p.as_str().to_owned(),
                effect: e.effect(*p).map(effect_name),
                default_effect: effect_name(p.default_effect()),
            })
            .collect(),
        fill_sites: e.fill_sites.iter().map(ToString::to_string).collect(),
        hours: e.hours.iter().map(window_info).collect(),
        expires_at_secs: e.expires_at,
    }
}

/// A rule of a grant the editor cannot change, to show it in words.
#[derive(Debug, Clone, uniffi::Record)]
pub struct RuleInfo {
    pub permission: String,
    pub effect: String,
    /// Sites it applies to; empty: anywhere.
    pub sites: Vec<String>,
    /// Item tags it applies to; empty: any.
    pub tags: Vec<String>,
    /// Vaults and projects it is narrowed to (how many).
    pub places: u32,
    pub hours: Vec<TimeWindowInfo>,
    /// When the rule alone ends (Unix seconds).
    pub expires_at_secs: Option<u64>,
    /// It also has conditions the app does not name (items, HTTP methods
    /// or paths of the credential proxy).
    pub more: bool,
}

fn rule_info(r: &Rule) -> RuleInfo {
    RuleInfo {
        permission: r.permission.as_str().to_owned(),
        effect: effect_name(r.effect),
        sites: r.scope.domains.iter().map(ToString::to_string).collect(),
        tags: r.scope.tags.clone(),
        places: count(r.scope.vaults.len() + r.scope.projects.len()),
        hours: r.scope.hours.iter().map(window_info).collect(),
        expires_at_secs: r.expires_at,
        more: !r.scope.items.is_empty()
            || !r.scope.methods.is_empty()
            || !r.scope.path_prefixes.is_empty(),
    }
}

/// Why the apps cannot change a grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ReadOnlyKind {
    /// The agent is not active.
    NotActive,
    /// It has no grant.
    NoGrant,
    /// This device cannot read it whole.
    Unreadable,
    /// The credential proxy's grant: `klav proxy …` changes it.
    Proxy,
    /// An issuer's grant (it starts sandboxes): the CLI changes it.
    Issuer,
    /// Rules the editor does not model: `klav agent approve
    /// --policy-file` changes them.
    Rules,
    /// The `klavd` running is older than changing a grant from the app.
    OlderKlavd,
}

/// An agent's grant in force, for «Permissions» and the editor.
#[derive(Debug, Clone, uniffi::Record)]
pub struct GrantEditorInfo {
    pub agent_id: String,
    /// Its name (cleaned): the agent's own words.
    pub name: String,
    /// The grant's version (0 without one).
    pub version: u64,
    pub projects: Vec<GrantedProjectInfo>,
    /// «Change permissions…» shows only then.
    pub editable: bool,
    /// Why not, when it cannot.
    pub read_only: Option<ReadOnlyKind>,
    /// The policy in the editor's model, when it fits.
    pub editor: Option<EditorPolicyInfo>,
    /// The policy's rules as signed, when this device reads them (empty
    /// for the defaults alone).
    pub rules: Vec<RuleInfo>,
    /// The whole grant's expiry (Unix seconds), when this device reads it.
    pub expires_at_secs: Option<u64>,
}

fn read_only_kind(r: ReadOnlyReason) -> ReadOnlyKind {
    match r {
        ReadOnlyReason::NotActive => ReadOnlyKind::NotActive,
        ReadOnlyReason::NoGrant => ReadOnlyKind::NoGrant,
        ReadOnlyReason::Unreadable => ReadOnlyKind::Unreadable,
        ReadOnlyReason::Proxy => ReadOnlyKind::Proxy,
        ReadOnlyReason::Issuer => ReadOnlyKind::Issuer,
        ReadOnlyReason::Rules => ReadOnlyKind::Rules,
    }
}

pub(crate) fn grant_editor_info(g: GrantEditor) -> GrantEditorInfo {
    let policy: Option<&Policy> = g.policy.as_ref();
    GrantEditorInfo {
        agent_id: g.agent_id.to_string(),
        name: agent_text(&g.name),
        version: g.version,
        projects: g.projects.iter().map(project_info).collect(),
        // Editable only with the model to edit.
        editable: g.editable && g.editor.is_some(),
        read_only: g.reason.map(read_only_kind),
        editor: g.editor.as_ref().map(editor_policy_info),
        rules: policy
            .map(|p| p.rules.iter().map(rule_info).collect())
            .unwrap_or_default(),
        expires_at_secs: policy.and_then(|p| p.expires_at),
    }
}

/// What a `klavd` older than the editor answers: read-only, said so.
pub(crate) fn older_klavd_editor(agent_id: String) -> GrantEditorInfo {
    GrantEditorInfo {
        agent_id,
        name: String::new(),
        version: 0,
        projects: Vec::new(),
        editable: false,
        read_only: Some(ReadOnlyKind::OlderKlavd),
        editor: None,
        rules: Vec::new(),
        expires_at_secs: None,
    }
}

// MARK: - The change (F3)

/// One permission as the editor sends it.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PermissionSettingInput {
    pub permission: String,
    /// `allow`, `ask` or `deny`; none: its default.
    pub effect: Option<String>,
}

/// A change to an active agent's grant, as the editor sends it. The app
/// sends the same value to prepare and to apply: `klavd` binds the sheet
/// to it (F3).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct GrantChangeInput {
    /// The projects of the new grant (IDs).
    pub project_ids: Vec<String>,
    /// Permissions with an effect; one left out is its default.
    pub permissions: Vec<PermissionSettingInput>,
    pub fill_sites: Vec<String>,
    pub hours: Vec<TimeWindowInfo>,
    /// Unix seconds; none: never.
    pub expires_at_secs: Option<u64>,
    /// Also change the key of each project taken away (P9: offered,
    /// unchecked).
    pub rotate_removed: bool,
}

/// The `GrantChange` that both prepare and apply send: one function, so
/// the JSON `klavd` hashes is the same both times. Nothing here depends on
/// the time or on anything but `input`.
pub(crate) fn grant_change(input: &GrantChangeInput) -> KlavResult<GrantChange> {
    let mut projects = Vec::with_capacity(input.project_ids.len());
    for p in &input.project_ids {
        let id = ProjectId::from_str(p.trim())
            .map_err(|_| KlavError::invalid(format!("not a project ID: {p}")))?;
        projects.push(id.to_string());
    }
    let permissions = input
        .permissions
        .iter()
        .map(|s| -> KlavResult<PermissionSetting> {
            Ok(PermissionSetting {
                permission: permission(&s.permission)?,
                effect: s.effect.as_deref().map(effect).transpose()?,
            })
        })
        .collect::<KlavResult<Vec<_>>>()?
        .into_iter()
        // A permission at its default is the same as none: leave it out,
        // so an editor that lists all eight sends what one that lists only
        // the changed ones sends.
        .filter(|s| s.effect.is_some())
        .collect();
    let fill_sites = input
        .fill_sites
        .iter()
        .map(|s| {
            DomainPattern::parse(s.trim())
                .map_err(|e| KlavError::invalid(format!("not a site: {e}")))
        })
        .collect::<KlavResult<Vec<_>>>()?;
    let hours = input
        .hours
        .iter()
        .map(window)
        .collect::<KlavResult<Vec<_>>>()?;
    let editor = EditorPolicy {
        permissions,
        fill_sites,
        hours,
        expires_at: input.expires_at_secs,
    };
    // The same check klavd makes, before anything goes out.
    editor.to_policy().map_err(KlavError::invalid)?;
    Ok(GrantChange {
        projects,
        vaults: Vec::new(),
        policy: ChangePolicy::Editor(editor),
        rotate_removed: input.rotate_removed,
    })
}

/// The change that leaves `editor` as it is (for tests and the sample).
#[cfg(test)]
fn unchanged(editor: &GrantEditorInfo) -> GrantChangeInput {
    let policy = editor.editor.clone().expect("editable");
    GrantChangeInput {
        project_ids: editor
            .projects
            .iter()
            .map(|p| p.project_id.clone())
            .collect(),
        permissions: policy
            .permissions
            .into_iter()
            .map(|p| PermissionSettingInput {
                permission: p.permission,
                effect: p.effect,
            })
            .collect(),
        fill_sites: policy.fill_sites,
        hours: policy.hours,
        expires_at_secs: policy.expires_at_secs,
        rotate_removed: false,
    }
}

// MARK: - The sheet (F3)

/// What one line of the sheet changes, for the app to say in its words.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum ChangeKind {
    ProjectAdded {
        /// `vault/project`.
        project: String,
    },
    ProjectRemoved {
        project: String,
    },
    Permission {
        permission: String,
        before: String,
        before_default: bool,
        after: String,
        after_default: bool,
    },
    /// Empty: wherever `fill`'s effect says.
    FillSites {
        before: Vec<String>,
        after: Vec<String>,
    },
    /// Empty: always.
    Hours {
        before: Vec<TimeWindowInfo>,
        after: Vec<TimeWindowInfo>,
    },
    /// Unix seconds; none: never.
    Expires {
        before_secs: Option<u64>,
        after_secs: Option<u64>,
    },
    /// Rules outside the editor's model changed (only from the CLI).
    Rules,
}

/// One line of the sheet: before → after.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ChangeLineInfo {
    pub kind: ChangeKind,
    /// It lets the agent do more.
    pub widens: bool,
}

fn windows(list: &[String]) -> Vec<TimeWindowInfo> {
    list.iter().filter_map(|w| window_text_info(w)).collect()
}

fn change_line(l: &ChangeLine) -> ChangeLineInfo {
    let kind = match &l.what {
        ChangeWhat::ProjectAdded { project } => ChangeKind::ProjectAdded {
            project: project.clone(),
        },
        ChangeWhat::ProjectRemoved { project } => ChangeKind::ProjectRemoved {
            project: project.clone(),
        },
        ChangeWhat::Permission {
            permission,
            before,
            before_default,
            after,
            after_default,
        } => ChangeKind::Permission {
            permission: permission.as_str().to_owned(),
            before: effect_name(*before),
            before_default: *before_default,
            after: effect_name(*after),
            after_default: *after_default,
        },
        ChangeWhat::FillSites { before, after } => ChangeKind::FillSites {
            before: before.clone(),
            after: after.clone(),
        },
        ChangeWhat::Hours { before, after } => ChangeKind::Hours {
            before: windows(before),
            after: windows(after),
        },
        ChangeWhat::Expires { before, after } => ChangeKind::Expires {
            before_secs: *before,
            after_secs: *after,
        },
        ChangeWhat::Rules => ChangeKind::Rules,
    };
    ChangeLineInfo {
        kind,
        widens: l.widens,
    }
}

/// The sheet of a change: only the differences.
#[derive(Debug, Clone, uniffi::Record)]
pub struct GrantChangePreviewInfo {
    pub agent_id: String,
    /// Its name (cleaned).
    pub name: String,
    /// The version the new grant will have.
    pub version: u64,
    pub lines: Vec<ChangeLineInfo>,
    /// It asks for Touch ID or the master password (P8).
    pub widens: bool,
    /// Send it back to apply: nothing is signed if the grant changed.
    pub digest: String,
    /// Projects taken away (`vault/project`).
    pub removed_projects: Vec<String>,
    pub rotate_removed: bool,
    pub warnings: Vec<String>,
}

pub(crate) fn preview_info(p: &GrantChangePreview) -> GrantChangePreviewInfo {
    GrantChangePreviewInfo {
        agent_id: p.agent_id.to_string(),
        name: agent_text(&p.name),
        version: p.version,
        lines: p.lines.iter().map(change_line).collect(),
        widens: p.widens,
        digest: p.digest.clone(),
        removed_projects: p.removed_projects.clone(),
        rotate_removed: p.rotate_removed,
        // They name agents and projects (the agents' own words, T136).
        warnings: p.warnings.iter().map(|w| report_text(w)).collect(),
    }
}

/// What signing a change did.
#[derive(Debug, Clone, uniffi::Record)]
pub struct GrantChangeReportInfo {
    /// The agent, with its new grant.
    pub agent: AgentItem,
    /// `vault/project` whose key changed (with `rotate_removed`).
    pub rotated: Vec<String>,
    pub regranted: Vec<String>,
    pub not_regranted: Vec<String>,
    pub failed: Option<String>,
    /// `vault/project` whose key still has to change: `klavd` goes on with
    /// them at the next unlock.
    pub pending: Vec<String>,
    /// `vault/project: why` of projects whose key cannot change from this
    /// Mac.
    pub skipped: Vec<String>,
    pub complete: bool,
}

pub(crate) fn change_report_info(r: GrantChangeReport) -> GrantChangeReportInfo {
    let complete = r.complete();
    GrantChangeReportInfo {
        agent: agent_item(r.agent),
        rotated: r.rotated.into_iter().map(|p| p.project).collect(),
        regranted: r.regranted.iter().map(|n| agent_text(n)).collect(),
        not_regranted: r.not_regranted.iter().map(|l| agent_line(l)).collect(),
        failed: r.failed.as_deref().map(report_text),
        pending: r.pending,
        skipped: r.skipped.iter().map(|s| report_text(s)).collect(),
        complete,
    }
}

/// The editor of a policy with `rules` (to build grants in tests).
#[cfg(test)]
fn editor_of(policy: &Policy) -> GrantEditorInfo {
    let model = EditorPolicy::from_policy(policy).expect("fits the editor");
    GrantEditorInfo {
        agent_id: klav_core::ids::AgentId::generate().to_string(),
        name: "bot".into(),
        version: 2,
        projects: vec![GrantedProjectInfo {
            vault_id: klav_core::ids::VaultId::generate().to_string(),
            vault: "Work".into(),
            project_id: ProjectId::generate().to_string(),
            project: "Backend".into(),
        }],
        editable: true,
        read_only: None,
        editor: Some(editor_policy_info(&model)),
        rules: policy.rules.iter().map(rule_info).collect(),
        expires_at_secs: policy.expires_at,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use klav_core::policy::Permission;

    fn rich_policy() -> Policy {
        let model = EditorPolicy {
            permissions: vec![
                PermissionSetting {
                    permission: Permission::Reveal,
                    effect: Some(Effect::Ask),
                },
                PermissionSetting {
                    permission: Permission::List,
                    effect: Some(Effect::Deny),
                },
            ],
            fill_sites: vec![DomainPattern::parse("*.example.com").unwrap()],
            hours: vec![
                // Days out of order on purpose: they must come back as they
                // were.
                TimeWindow::from_str("fri,mon,wed 09:00-18:00 -06:00").unwrap(),
                TimeWindow::from_str("daily 22:00-02:00 +01:00").unwrap(),
            ],
            expires_at: Some(1_900_000_000),
        };
        model.to_policy().unwrap()
    }

    /// The grant in force, sent back untouched, is the same policy: an
    /// editor opened and closed changes nothing (and klavd refuses a
    /// no-op, so nothing is signed).
    #[test]
    fn the_grant_sent_back_untouched_is_the_same_policy() {
        let policy = rich_policy();
        let editor = editor_of(&policy);
        let change = grant_change(&unchanged(&editor)).unwrap();
        let ChangePolicy::Editor(back) = &change.policy else {
            panic!("the editor's model");
        };
        assert_eq!(back, &EditorPolicy::from_policy(&policy).unwrap());
        assert_eq!(back.to_policy().unwrap(), policy);
        assert_eq!(change.projects, vec![editor.projects[0].project_id.clone()]);
    }

    /// Prepare and apply send the same JSON: what klavd hashes into the
    /// sheet's digest (F3, T188).
    #[test]
    fn prepare_and_apply_send_the_same_change() {
        let editor = editor_of(&rich_policy());
        let mut input = unchanged(&editor);
        input.permissions.retain(|p| p.permission != "reveal");
        input.rotate_removed = true;
        let first = serde_json::to_string(&grant_change(&input).unwrap()).unwrap();
        let again = serde_json::to_string(&grant_change(&input.clone()).unwrap()).unwrap();
        assert_eq!(first, again);
        // A permission at its default and one left out are the same change.
        let mut listed = input.clone();
        listed.permissions.push(PermissionSettingInput {
            permission: "reveal".into(),
            effect: None,
        });
        assert_eq!(
            serde_json::to_string(&grant_change(&listed).unwrap()).unwrap(),
            first
        );
    }

    #[test]
    fn a_change_the_editor_cannot_write_is_refused_before_klavd() {
        let editor = editor_of(&rich_policy());
        let mut input = unchanged(&editor);
        input.permissions.push(PermissionSettingInput {
            permission: "fill".into(),
            effect: Some("allow".into()),
        });
        assert!(matches!(
            grant_change(&input),
            Err(KlavError::Invalid { .. })
        ));
        for bad in [
            GrantChangeInput {
                project_ids: vec!["Work/Backend".into()],
                ..unchanged(&editor)
            },
            GrantChangeInput {
                permissions: vec![PermissionSettingInput {
                    permission: "proxy".into(),
                    effect: Some("allow".into()),
                }],
                ..unchanged(&editor)
            },
            GrantChangeInput {
                permissions: vec![PermissionSettingInput {
                    permission: "reveal".into(),
                    effect: Some("maybe".into()),
                }],
                ..unchanged(&editor)
            },
            GrantChangeInput {
                hours: vec![TimeWindowInfo {
                    days: vec!["someday".into()],
                    start_minutes: 0,
                    end_minutes: 60,
                    utc_offset_minutes: 0,
                }],
                ..unchanged(&editor)
            },
        ] {
            assert!(
                matches!(grant_change(&bad), Err(KlavError::Invalid { .. })),
                "{bad:?}"
            );
        }
    }

    /// The editor always lists the eight permissions, in order, with their
    /// defaults.
    #[test]
    fn the_editor_lists_every_permission_with_its_default() {
        let editor = editor_of(&rich_policy());
        let policy = editor.editor.unwrap();
        let names: Vec<&str> = policy
            .permissions
            .iter()
            .map(|p| p.permission.as_str())
            .collect();
        assert_eq!(
            names,
            [
                "list", "fill", "inject", "totp", "reveal", "create", "update", "delete"
            ]
        );
        let reveal = &policy.permissions[4];
        assert_eq!(
            (reveal.effect.as_deref(), reveal.default_effect.as_str()),
            (Some("ask"), "deny")
        );
        assert_eq!(policy.fill_sites, ["*.example.com"]);
        assert_eq!(policy.hours[0].days, ["fri", "mon", "wed"]);
        assert_eq!(policy.hours[0].utc_offset_minutes, -360);
        assert_eq!(policy.hours[1].days, Vec::<String>::new());
    }

    /// Every kind of line keeps its parts for the app to word them; the
    /// hours come back as windows.
    #[test]
    fn the_sheets_lines_keep_their_parts() {
        let line = |what| change_line(&ChangeLine { what, widens: true });
        assert_eq!(
            line(ChangeWhat::Hours {
                before: vec!["mon,tue 09:00-18:00 -06:00".into()],
                after: Vec::new(),
            })
            .kind,
            ChangeKind::Hours {
                before: vec![TimeWindowInfo {
                    days: vec!["mon".into(), "tue".into()],
                    start_minutes: 540,
                    end_minutes: 1080,
                    utc_offset_minutes: -360,
                }],
                after: Vec::new(),
            }
        );
        let permission = line(ChangeWhat::Permission {
            permission: Permission::Update,
            before: Effect::Ask,
            before_default: true,
            after: Effect::Allow,
            after_default: false,
        });
        assert!(permission.widens);
        assert_eq!(
            permission.kind,
            ChangeKind::Permission {
                permission: "update".into(),
                before: "ask".into(),
                before_default: true,
                after: "allow".into(),
                after_default: false,
            }
        );
    }

    /// The agent's words in a report are cleaned like its name (T136);
    /// Klav's reason after the colon stays.
    #[test]
    fn agent_names_in_reports_are_cleaned() {
        let line = agent_line("bad\u{202e}bot: the server said no");
        assert!(!line.contains('\u{202e}'), "{line:?}");
        assert!(line.ends_with(": the server said no"));
    }

    /// An entry as `pending_revocations` builds it: a declined revocation
    /// lists no project as pending (P7).
    fn entry(narrowed: bool, without_key_change: bool, pending: &[&str]) -> PendingRevocation {
        let pending: Vec<String> = pending.iter().map(|p| (*p).to_owned()).collect();
        PendingRevocation {
            agent_id: klav_core::ids::AgentId::generate(),
            name: "bot".into(),
            projects: pending.clone(),
            rotated: Vec::new(),
            regrants: Vec::new(),
            unknown_projects: false,
            narrowed,
            items: 0,
            log_unchecked: false,
            without_key_change,
            skipped: Vec::new(),
            last_error: None,
            pending,
        }
    }

    fn owned(projects: &[&str]) -> Vec<String> {
        projects.iter().map(|p| (*p).to_owned()).collect()
    }

    /// Review of #316, 1: a narrowing's projects are owed, a declined
    /// revocation's never are, and a record that does not open after the
    /// step neither drops a narrowing nor lists a declined one's projects.
    #[test]
    fn owed_projects_are_what_the_record_says_is_left() {
        let cache = || owned(&["Personal/Work", "Personal/Old"]);
        let asked = entry(false, false, &["Personal/Work"]);
        let declined = entry(false, true, &[]);
        let narrowing = entry(true, false, &["Personal/Ops", "Personal/Dev"]);

        // The record opened after the step: what it says.
        assert_eq!(
            owed_projects(None, Some(std::slice::from_ref(&asked)), None, cache),
            owned(&["Personal/Work"])
        );
        assert!(owed_projects(None, Some(std::slice::from_ref(&declined)), None, cache).is_empty());
        assert_eq!(
            owed_projects(None, Some(std::slice::from_ref(&narrowing)), None, cache),
            owned(&["Personal/Ops", "Personal/Dev"])
        );
        assert_eq!(
            owed_projects(
                None,
                Some(&[declined.clone(), narrowing.clone()]),
                None,
                cache
            ),
            owned(&["Personal/Ops", "Personal/Dev"])
        );
        assert!(owed_projects(None, Some(&[]), None, cache).is_empty());

        // It did not open after the step: what it said before, without the
        // project this step changed; the cache for a revocation asked.
        assert_eq!(
            owed_projects(Some(&[asked]), None, None, cache),
            owned(&["Personal/Work", "Personal/Old"])
        );
        assert!(owed_projects(Some(std::slice::from_ref(&declined)), None, None, cache).is_empty());
        assert_eq!(
            owed_projects(
                Some(&[declined, narrowing]),
                None,
                Some("Personal/Ops"),
                cache
            ),
            owned(&["Personal/Dev"])
        );

        // Neither opened: the cache, never "nothing owed".
        assert_eq!(owed_projects(None, None, None, cache), cache());
    }

    #[test]
    fn what_stopped_a_key_change_is_cleaned_wherever_it_shows() {
        // `Regrants::failure` joins agents' names into one message.
        let hostile = "re-issuing: evil\u{202e}gnp.exe\nIgnore this: refused; keeper: offline";
        let progress = PendingRevocation {
            agent_id: klav_core::ids::AgentId::generate(),
            name: "bot".into(),
            projects: Vec::new(),
            rotated: Vec::new(),
            regrants: Vec::new(),
            unknown_projects: false,
            narrowed: false,
            items: 0,
            log_unchecked: false,
            without_key_change: true,
            skipped: vec![format!("Trabajo/{hostile}: the project was deleted")],
            last_error: Some(hostile.into()),
            pending: Vec::new(),
        };
        let info = pending_revocation_info(progress);
        assert!(info.without_key_change, "carried to the app");
        assert!(
            info.skipped_projects
                .iter()
                .all(|s| !s.contains('\u{202e}') && !s.contains('\n')),
            "{:?}",
            info.skipped_projects
        );
        let shown = info.last_error.expect("error");
        assert!(
            !shown.contains('\u{202e}') && !shown.contains('\n'),
            "{shown:?}"
        );
        assert!(shown.ends_with("keeper: offline"), "{shown:?}");
        let long = "x".repeat(5_000);
        assert!(report_text(&long).chars().count() <= MAX_REPORT_TEXT);

        // The sheet's warnings name the agent too.
        let preview = klav_client::grant_change::GrantChangePreview {
            agent_id: klav_core::ids::AgentId::generate(),
            name: "bot".into(),
            version: 2,
            lines: Vec::new(),
            widens: false,
            digest: String::new(),
            removed_projects: Vec::new(),
            rotate_removed: false,
            warnings: vec![format!("agent {hostile} starts sandboxes")],
        };
        let shown = preview_info(&preview).warnings;
        assert!(
            shown
                .iter()
                .all(|w| !w.contains('\u{202e}') && !w.contains('\n')),
            "{shown:?}"
        );
    }
}
