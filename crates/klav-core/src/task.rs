//! Task requests (ADR 0021): an agent asks at once for the items and
//! permissions a job needs, the person approves one card and Klav lets the
//! agent use that set of targets until the task expires.
//!
//! This module holds the formats and the pure rules every side shares:
//!
//! * [`TaskSpec`]: what the agent writes (`tarea.toml`, the MCP
//!   `request_task` arguments), with `klav://` references and a duration
//!   such as `2h`. The runtime resolves it into a [`TaskRequest`].
//! * [`TaskRequest`]: what reaches the server, with IDs only. The server
//!   stores its bytes verbatim; the person signs them (spec §13.8).
//! * [`TaskDecision`]: what the person approved, signed by the account
//!   (`klav/v1/sig/task-decision`, spec §13.8), stored verbatim. A task
//!   the person offers an agent without a request (ADR 0022 §6) has an
//!   empty request and carries its title and reason in
//!   [`TaskDecision::offer`].
//! * [`propose`]: the card the person's client builds from the request and
//!   the decrypted vault (ADR 0021 §3).
//! * [`TaskDecision::covers`]: whether a live task lets an action through
//!   (ADR 0021 §4–5). The server and the agent runtime both use it.
//!
//! What never goes in a task: `reveal` and `delete` (irreversible, ADR
//! 0021 §2), and `list` and `create` (the grant gives them).

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::ids::{AgentId, ItemId, ProjectId, TaskId, VaultId};
use crate::policy::{Decision, Effect, Permission, normalize_host};
use crate::site;

/// Version of [`TaskRequest`] and [`TaskDecision`].
pub const TASK_FORMAT_VERSION: u32 = 1;
/// Most accesses in one task (ADR 0021 Q6).
pub const MAX_TASK_ACCESS: usize = 50;
/// Shortest duration an agent may ask for (seconds).
pub const MIN_TASK_DURATION_SECS: u64 = 5 * 60;
/// Longest duration of a task, like approval leases (seconds, ADR 0021 Q4).
pub const MAX_TASK_DURATION_SECS: u64 = 24 * 60 * 60;
/// Longest task title (characters).
pub const MAX_TASK_TITLE: usize = 120;
/// Longest task reason (characters).
pub const MAX_TASK_REASON: usize = 500;

/// The permissions an access of a task may carry (ADR 0021 §1).
pub const TASK_PERMISSIONS: [Permission; 6] = [
    Permission::Fill,
    Permission::Totp,
    Permission::Inject,
    Permission::Update,
    Permission::Passkey,
    Permission::Rotate,
];

/// Why a task request or decision is not valid.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum TaskError {
    /// Unknown format version.
    #[error("unsupported task format version {0}")]
    Version(u32),
    /// `task` or `reason` is empty, too long or has control, format (bidi,
    /// zero-width) or line separator characters.
    #[error(
        "`{field}` must have 1 to {max} characters, written as plain text (no control or invisible formatting characters)"
    )]
    Text {
        /// `task` or `reason`.
        field: &'static str,
        /// Longest accepted.
        max: usize,
    },
    /// The duration text does not parse.
    #[error("invalid duration {0:?}: use 30m, 2h or 1h30m")]
    Duration(String),
    /// The duration is out of range.
    #[error("a task lasts from 5 minutes to 24 hours")]
    DurationRange,
    /// Too few or too many accesses.
    #[error("a task has from 1 to 50 accesses")]
    AccessCount,
    /// An access without permissions.
    #[error("every access needs at least one permission")]
    NoPermissions,
    /// The same permission twice in one access.
    #[error("permission `{0}` is listed twice for the same item")]
    DuplicatePermission(Permission),
    /// The same item twice.
    #[error("item {0} is listed twice: put all its permissions in one access")]
    DuplicateItem(ItemId),
    /// `reveal` in a task.
    #[error(
        "`reveal` never goes in a task: what is revealed cannot be taken back; ask for it with the normal tool, one card per value"
    )]
    Reveal,
    /// `delete` in a task.
    #[error(
        "`delete` never goes in a task: it is not approved in bulk; use the normal tool, one card per item"
    )]
    Delete,
    /// `list` or `create` in a task.
    #[error(
        "`{0}` is not asked for in a task: `list` comes from the grant and `create` has no item to point at"
    )]
    GrantOnly(Permission),
    /// Not a host name.
    #[error("invalid domain {0:?}: use a host such as signin.aws.amazon.com")]
    Domain(String),
    /// Decision fields that do not fit the task.
    #[error("invalid task decision: {0}")]
    Decision(&'static str),
}

/// Whether `permission` may go in a task, with the reason when not.
pub fn check_task_permission(permission: Permission) -> Result<(), TaskError> {
    match permission {
        Permission::Reveal => Err(TaskError::Reveal),
        Permission::Delete => Err(TaskError::Delete),
        // The proxy is per call, under its own grant (ADR 0036 §2).
        Permission::List | Permission::Create | Permission::Proxy => {
            Err(TaskError::GrantOnly(permission))
        }
        Permission::Fill
        | Permission::Totp
        | Permission::Inject
        | Permission::Update
        | Permission::Passkey
        | Permission::Rotate => Ok(()),
    }
}

/// Checks `task` or `reason`: not blank, at most `max` characters, no
/// control characters. Agents should not put secrets there: it is stored
/// in clear (T20).
/// Non-empty, at most `max` characters, and nothing that makes it read as
/// something else on the card: no control, format (bidi, zero-width), line
/// or paragraph separator characters ([`crate::text::is_hidden`]).
fn check_text(field: &'static str, text: &str, max: usize) -> Result<(), TaskError> {
    let ok = !text.trim().is_empty()
        && text.chars().count() <= max
        && !text.chars().any(crate::text::is_hidden);
    if ok {
        Ok(())
    } else {
        Err(TaskError::Text { field, max })
    }
}

fn check_duration(secs: u64) -> Result<(), TaskError> {
    if (MIN_TASK_DURATION_SECS..=MAX_TASK_DURATION_SECS).contains(&secs) {
        Ok(())
    } else {
        Err(TaskError::DurationRange)
    }
}

fn check_permissions(permissions: &[Permission]) -> Result<(), TaskError> {
    if permissions.is_empty() {
        return Err(TaskError::NoPermissions);
    }
    let mut seen = BTreeSet::new();
    for &permission in permissions {
        check_task_permission(permission)?;
        if !seen.insert(permission) {
            return Err(TaskError::DuplicatePermission(permission));
        }
    }
    Ok(())
}

/// A host as stored in a task: lowercase, without a trailing dot.
fn check_host(host: &str) -> Result<String, TaskError> {
    normalize_host(host).ok_or_else(|| TaskError::Domain(host.to_owned()))
}

/// Parses a task duration: one or more `<number><unit>` with units `s`, `m`
/// and `h` (`30m`, `2h`, `1h30m`). Returns seconds; the range is checked
/// separately ([`MIN_TASK_DURATION_SECS`]–[`MAX_TASK_DURATION_SECS`]).
pub fn parse_duration(text: &str) -> Result<u64, TaskError> {
    let err = || TaskError::Duration(text.to_owned());
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Err(err());
    }
    let mut total: u64 = 0;
    let mut number = String::new();
    for c in trimmed.chars() {
        if c.is_ascii_digit() {
            number.push(c);
            continue;
        }
        let unit = match c {
            's' => 1,
            'm' => 60,
            'h' => 3600,
            _ => return Err(err()),
        };
        let n: u64 = number.parse().map_err(|_| err())?;
        number.clear();
        total = n
            .checked_mul(unit)
            .and_then(|s| total.checked_add(s))
            .ok_or_else(err)?;
    }
    if !number.is_empty() || total == 0 {
        return Err(err());
    }
    Ok(total)
}

// ------------------------------------------------------------ the spec ----

/// What the agent writes: `tarea.toml` / `tarea.json` in the CLI and the
/// arguments of the MCP tool `request_task` (ADR 0021 §1). Keys in English,
/// like `klav.toml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskSpec {
    /// Short title (at most 120 characters), written by the agent.
    pub task: String,
    /// Why (at most 500 characters). Mandatory.
    pub reason: String,
    /// `30m`, `2h`…: from 5 minutes to 24 hours, counted from the approval.
    pub duration: String,
    /// From 1 to 50 accesses.
    pub access: Vec<TaskSpecAccess>,
}

/// One access of a [`TaskSpec`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskSpecAccess {
    /// A `klav://` reference or the short form of `klav.toml`; the runtime
    /// turns it into IDs before sending.
    #[serde(rename = "ref")]
    pub reference: String,
    /// `fill`, `totp`, `inject`, `update`, `passkey` or `rotate`.
    pub permissions: Vec<Permission>,
    /// Expected host; without it the item's URLs are used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
}

impl TaskSpec {
    /// Checks everything but the references (the runtime resolves those)
    /// and returns the duration in seconds.
    pub fn validate(&self) -> Result<u64, TaskError> {
        check_text("task", &self.task, MAX_TASK_TITLE)?;
        check_text("reason", &self.reason, MAX_TASK_REASON)?;
        let secs = parse_duration(&self.duration)?;
        check_duration(secs)?;
        if !(1..=MAX_TASK_ACCESS).contains(&self.access.len()) {
            return Err(TaskError::AccessCount);
        }
        for access in &self.access {
            check_permissions(&access.permissions)?;
            if let Some(domain) = &access.domain {
                check_host(domain)?;
            }
        }
        Ok(secs)
    }
}

// --------------------------------------------------------- the request ----

/// What the agent sends (`POST /v1/agent/tasks`), with IDs only. The server
/// stores these bytes verbatim and the person signs them (spec §13.8).
/// `task` and `reason` stay in clear, like `reason` today (T20).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskRequest {
    /// [`TASK_FORMAT_VERSION`].
    pub v: u32,
    /// Title, in the agent's words.
    pub task: String,
    /// Why, in the agent's words.
    pub reason: String,
    /// How long the task lasts once approved (seconds).
    pub duration_secs: u64,
    /// What it needs.
    pub access: Vec<TaskAccessRequest>,
}

/// One access of a [`TaskRequest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskAccessRequest {
    /// Vault of the item.
    pub vault_id: VaultId,
    /// Project of the item.
    pub project_id: ProjectId,
    /// The item.
    pub item_id: ItemId,
    /// What for.
    pub permissions: Vec<Permission>,
    /// Expected host, if the agent gave one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
}

impl TaskRequest {
    /// Checks the limits of ADR 0021 §1–2.
    pub fn validate(&self) -> Result<(), TaskError> {
        if self.v != TASK_FORMAT_VERSION {
            return Err(TaskError::Version(self.v));
        }
        check_text("task", &self.task, MAX_TASK_TITLE)?;
        check_text("reason", &self.reason, MAX_TASK_REASON)?;
        check_duration(self.duration_secs)?;
        if !(1..=MAX_TASK_ACCESS).contains(&self.access.len()) {
            return Err(TaskError::AccessCount);
        }
        let mut items = BTreeSet::new();
        for access in &self.access {
            check_permissions(&access.permissions)?;
            if let Some(domain) = &access.domain {
                check_host(domain)?;
            }
            if !items.insert(access.item_id) {
                return Err(TaskError::DuplicateItem(access.item_id));
            }
        }
        Ok(())
    }

    /// The access for `item`, if requested.
    pub fn access_for(&self, item: ItemId) -> Option<&TaskAccessRequest> {
        self.access.iter().find(|a| a.item_id == item)
    }
}

// -------------------------------------------------------- the decision ----

/// What the person approved (spec §13.8). Signed by the account and stored
/// verbatim. A denial has no accesses and `expires_at_ms = 0`. Each «Add to
/// the task» signs a new one with `revision + 1` and the same expiry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskDecision {
    /// [`TASK_FORMAT_VERSION`].
    pub v: u32,
    /// The task.
    pub task_id: TaskId,
    /// The agent.
    pub agent_id: AgentId,
    /// 1 for the first decision; each addition the next one.
    pub revision: u64,
    /// When the task ends (Unix ms); `0` in a denial.
    pub expires_at_ms: u64,
    /// What was approved.
    pub access: Vec<TaskAccessDecision>,
    /// Only in a task the person offered without a request (ADR 0022 §6):
    /// the title and reason, written by the person. Absent (and not
    /// serialized) in a task the agent asked for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offer: Option<TaskOffer>,
}

/// The person's own title and reason of an offered task (ADR 0022 §6),
/// signed inside the decision. Same limits as a request's.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskOffer {
    /// Title.
    pub task: String,
    /// Why.
    pub reason: String,
}

impl TaskOffer {
    fn check(&self) -> Result<(), TaskError> {
        check_text("task", &self.task, MAX_TASK_TITLE)?;
        check_text("reason", &self.reason, MAX_TASK_REASON)
    }
}

/// One approved access of a [`TaskDecision`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskAccessDecision {
    /// Vault of the item.
    pub vault_id: VaultId,
    /// Project of the item.
    pub project_id: ProjectId,
    /// The item.
    pub item_id: ItemId,
    /// Approved permissions.
    pub permissions: Vec<Permission>,
    /// Approved hosts (lowercase): a `fill`, `passkey` or `rotate` passes on
    /// one of them or a subdomain, and never with this list empty (ADR 0030
    /// §6). For a card or an identity, which have no URL, it is the host the
    /// agent asked for and the person saw («according to the agent»).
    pub domains: Vec<String>,
    /// The permissions Klav added on the person's client, not the agent
    /// (`totp` on a login with TOTP, `passkey`; ADR 0021 §3). A subset of
    /// `permissions`.
    pub added_by_klav: Vec<Permission>,
}

impl TaskAccessDecision {
    fn check(&self) -> Result<(), TaskError> {
        check_permissions(&self.permissions)?;
        for added in &self.added_by_klav {
            if !self.permissions.contains(added) {
                return Err(TaskError::Decision(
                    "added_by_klav lists a permission that is not approved",
                ));
            }
        }
        // `rotate` fills the current password into a change form and
        // writes a new one: only on the item's own site (T99), never on
        // any page.
        if self.permissions.contains(&Permission::Rotate) && self.domains.is_empty() {
            return Err(TaskError::Decision(
                "rotate needs the item's site: approve it only on a login with a URL",
            ));
        }
        let mut hosts = BTreeSet::new();
        for domain in &self.domains {
            if check_host(domain)? != *domain {
                return Err(TaskError::Domain(domain.clone()));
            }
            if !hosts.insert(domain) {
                return Err(TaskError::Decision("a domain is listed twice"));
            }
        }
        Ok(())
    }

    /// Whether this access lets `permission` through on `domain`. A
    /// permission that checks the site (`fill`, `passkey`, `rotate`) never
    /// passes without approved hosts (ADR 0030 §6): an old decision signed
    /// with `domains = []` fails closed.
    pub fn allows(&self, permission: Permission, domain: Option<&str>) -> bool {
        if !self.permissions.contains(&permission) {
            return false;
        }
        if !permission.checks_domain() {
            return true;
        }
        !self.domains.is_empty()
            && domain.is_some_and(|host| site::host_matches(host, &self.domains))
    }

    /// A permission that checks the site needs at least one host (ADR 0030
    /// §6). Checked when a decision is signed or accepted, not when an old
    /// one is read: [`Self::allows`] already refuses those.
    fn check_site(&self) -> Result<(), TaskError> {
        if self.domains.is_empty() && self.permissions.iter().any(|p| p.checks_domain()) {
            return Err(TaskError::Decision(
                "fill, passkey and rotate need a site: the item has none",
            ));
        }
        Ok(())
    }
}

impl TaskDecision {
    /// Checks the shape of a decision: version, revision, accesses (1 to 50
    /// when approving, none when denying), permissions and hosts.
    pub fn validate(&self, approve: bool) -> Result<(), TaskError> {
        if self.v != TASK_FORMAT_VERSION {
            return Err(TaskError::Version(self.v));
        }
        if self.revision == 0 {
            return Err(TaskError::Decision("revisions start at 1"));
        }
        if !approve {
            if !self.access.is_empty()
                || self.expires_at_ms != 0
                || self.revision != 1
                || self.offer.is_some()
            {
                return Err(TaskError::Decision(
                    "a denial has revision 1, no accesses, no offer and expires_at_ms 0",
                ));
            }
            return Ok(());
        }
        if let Some(offer) = &self.offer {
            offer.check()?;
        }
        if self.expires_at_ms == 0 {
            return Err(TaskError::Decision("an approval needs expires_at_ms"));
        }
        if !(1..=MAX_TASK_ACCESS).contains(&self.access.len()) {
            return Err(TaskError::AccessCount);
        }
        let mut items = BTreeSet::new();
        for access in &self.access {
            access.check()?;
            if !items.insert(access.item_id) {
                return Err(TaskError::DuplicateItem(access.item_id));
            }
        }
        Ok(())
    }

    /// Checks a first approval (revision 1) against the request it answers:
    /// only requested items, each permission requested or added by Klav
    /// (`totp`, `passkey`), and an expiry after `decided_at_ms` and no later
    /// than the requested duration allows.
    pub fn check_first(&self, request: &TaskRequest, decided_at_ms: u64) -> Result<(), TaskError> {
        if self.revision != 1 {
            return Err(TaskError::Decision("the first decision has revision 1"));
        }
        if self.offer.is_some() {
            return Err(TaskError::Decision(
                "a decision on an agent's request carries no offer",
            ));
        }
        for access in &self.access {
            access.check_site()?;
        }
        let longest = request.duration_secs.min(MAX_TASK_DURATION_SECS) * 1000;
        if self.expires_at_ms <= decided_at_ms
            || self.expires_at_ms > decided_at_ms.saturating_add(longest)
        {
            return Err(TaskError::Decision(
                "the task must end after the decision and no later than the requested duration",
            ));
        }
        for access in &self.access {
            let asked = request
                .access_for(access.item_id)
                .filter(|a| a.vault_id == access.vault_id && a.project_id == access.project_id)
                .ok_or(TaskError::Decision("an approved item was not requested"))?;
            for permission in &access.permissions {
                let requested = asked.permissions.contains(permission);
                let added = access.added_by_klav.contains(permission);
                if requested == added {
                    return Err(TaskError::Decision(
                        "each approved permission is either requested or added by Klav",
                    ));
                }
                if added && !matches!(permission, Permission::Totp | Permission::Passkey) {
                    return Err(TaskError::Decision("Klav only adds totp or passkey"));
                }
            }
        }
        Ok(())
    }

    /// Checks the decision of a task the person offers an agent without a
    /// request (ADR 0022 §6; the signed request is empty): revision 1, the
    /// person's title and reason in [`Self::offer`], an expiry after
    /// `decided_at_ms` and at most 24 hours later, and Klav adding only
    /// `totp` or `passkey` (the person chose everything else).
    pub fn check_offered(&self, decided_at_ms: u64) -> Result<(), TaskError> {
        if self.revision != 1 {
            return Err(TaskError::Decision("an offered task starts at revision 1"));
        }
        let offer = self.offer.as_ref().ok_or(TaskError::Decision(
            "an offered task carries the person's title and reason",
        ))?;
        offer.check()?;
        if self.expires_at_ms <= decided_at_ms
            || self.expires_at_ms > decided_at_ms.saturating_add(MAX_TASK_DURATION_SECS * 1000)
        {
            return Err(TaskError::Decision(
                "an offered task ends after the decision and within 24 hours",
            ));
        }
        for access in &self.access {
            if access
                .added_by_klav
                .iter()
                .any(|p| !matches!(p, Permission::Totp | Permission::Passkey))
            {
                return Err(TaskError::Decision("Klav only adds totp or passkey"));
            }
        }
        Ok(())
    }

    /// For an offered task (see [`Self::check_offered`]), the request it
    /// stands for, to show it like any other: the person's title and
    /// reason, the duration from `decided_at_ms` to the expiry, and no
    /// accesses (everything in [`Self::access`] was chosen by the person).
    /// `None` for a decision without an offer.
    pub fn offered_request(&self, decided_at_ms: u64) -> Option<TaskRequest> {
        let offer = self.offer.as_ref()?;
        Some(TaskRequest {
            v: TASK_FORMAT_VERSION,
            task: offer.task.clone(),
            reason: offer.reason.clone(),
            duration_secs: self.expires_at_ms.saturating_sub(decided_at_ms) / 1000,
            access: Vec::new(),
        })
    }

    /// Checks a revision («Add to the task», ADR 0021 §6) against the one in
    /// force: the next number, the same task, agent and expiry, and nothing
    /// taken away.
    pub fn check_extends(&self, previous: &TaskDecision) -> Result<(), TaskError> {
        if self.task_id != previous.task_id || self.agent_id != previous.agent_id {
            return Err(TaskError::Decision(
                "a revision is for the same task and agent",
            ));
        }
        if previous.revision.checked_add(1) != Some(self.revision) {
            return Err(TaskError::Decision("only the next revision is accepted"));
        }
        if self.expires_at_ms != previous.expires_at_ms {
            return Err(TaskError::Decision("a revision keeps the same expiry"));
        }
        if self.offer != previous.offer {
            return Err(TaskError::Decision(
                "a revision keeps the offer's title and reason",
            ));
        }
        for access in &self.access {
            access.check_site()?;
        }
        for old in &previous.access {
            let new = self
                .access
                .iter()
                .find(|a| a.item_id == old.item_id)
                .filter(|a| a.vault_id == old.vault_id && a.project_id == old.project_id)
                .ok_or(TaskError::Decision("a revision cannot remove an item"))?;
            if !old.permissions.iter().all(|p| new.permissions.contains(p))
                || !old.domains.iter().all(|d| new.domains.contains(d))
            {
                return Err(TaskError::Decision(
                    "a revision cannot remove a permission or a site",
                ));
            }
        }
        Ok(())
    }

    /// The access for `item`, if approved.
    pub fn access_for(&self, item: ItemId) -> Option<&TaskAccessDecision> {
        self.access.iter().find(|a| a.item_id == item)
    }

    /// Whether this decision lets `permission` on `item` (in `vault` and
    /// `project`) through on `domain` (ADR 0021 §4). Liveness (approved,
    /// before `expires_at_ms`, not ended, agent not revoked) is the
    /// caller's to check, on every use.
    pub fn covers(
        &self,
        vault: VaultId,
        project: ProjectId,
        item: ItemId,
        permission: Permission,
        domain: Option<&str>,
    ) -> bool {
        self.access_for(item).is_some_and(|a| {
            a.vault_id == vault && a.project_id == project && a.allows(permission, domain)
        })
    }

    /// What the agent asked for and the person did not approve, per item
    /// (for the agent's answer, ADR 0021 §7).
    pub fn removed_from(&self, request: &TaskRequest) -> Vec<TaskAccessRequest> {
        request
            .access
            .iter()
            .filter_map(|asked| {
                let approved = self.access_for(asked.item_id);
                let missing: Vec<Permission> = asked
                    .permissions
                    .iter()
                    .copied()
                    .filter(|p| approved.is_none_or(|a| !a.permissions.contains(p)))
                    .collect();
                (!missing.is_empty()).then(|| TaskAccessRequest {
                    permissions: missing,
                    ..asked.clone()
                })
            })
            .collect()
    }
}

// -------------------------------------------------------- the proposal ----

/// What the person's client knows about an item after decrypting it (ADR
/// 0021 §3): never what the agent said.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ItemFacts {
    /// The item is a login.
    pub is_login: bool,
    /// The item has no URL by nature (a card, an identity): a `fill` on it
    /// is tied to the host the agent asks for, shown as its claim (ADR 0030
    /// §6). A login without URLs is not siteless: it just lacks them.
    pub siteless: bool,
    /// Its URLs: for the task card, only the confirmed ones (ADR 0030 §7).
    pub urls: Vec<String>,
    /// URLs an agent added that the person has not confirmed (ADR 0030
    /// §7): an asked domain that only matches these is a mismatch.
    pub pending_urls: Vec<String>,
    /// It has a TOTP secret.
    pub has_totp: bool,
    /// It has a password.
    pub has_password: bool,
    /// It has a passkey (ADR 0020).
    pub has_passkey: bool,
}

/// One permission on the card.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProposedPermission {
    /// The permission.
    pub permission: Permission,
    /// Checked (approved if the person does not uncheck it).
    pub checked: bool,
    /// Added by Klav, not asked for by the agent.
    pub added_by_klav: bool,
    /// The person's policy denies it: shown struck through and it cannot
    /// be checked (a task never widens a `deny`, ADR 0006).
    pub denied_by_policy: bool,
    /// It checks the site and the item has none («No site», ADR 0030 §6):
    /// it cannot be checked.
    pub no_site: bool,
    /// The grant says `ask once` for it (ADR 0032 §4.2): a protected
    /// environment or an item it points to. «Always asks for approval»:
    /// unchecked, and it cannot be checked (the server rejects a decision
    /// that includes it).
    pub always_asks: bool,
}

/// One item on the card.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProposalRow {
    /// Vault.
    pub vault_id: VaultId,
    /// Project.
    pub project_id: ProjectId,
    /// Item.
    pub item_id: ItemId,
    /// The item is not in the person's vault (deleted or not granted): it
    /// cannot be approved.
    pub missing: bool,
    /// The agent's `domain` matches none of the item's URLs: «The site does
    /// not match the item», unchecked, and it cannot be checked (T92).
    pub domain_mismatch: bool,
    /// The item has no valid host and a permission on the row checks the
    /// site («No site», ADR 0030 §6): those permissions cannot be checked.
    pub no_site: bool,
    /// `domains` is the host the agent asked for, on an item without URLs
    /// by nature (a card, an identity): shown «according to the agent».
    pub domain_claimed: bool,
    /// The hosts that will be approved (from the vault, or the agent's
    /// claim when `domain_claimed`).
    pub domains: Vec<String>,
    /// Permissions, in order.
    pub permissions: Vec<ProposedPermission>,
}

impl ProposalRow {
    /// Whether some permission is checked.
    pub fn any_checked(&self) -> bool {
        self.permissions.iter().any(|p| p.checked)
    }

    /// Checks or unchecks `permission` (every permission with `None`).
    /// Permissions the policy denies, a site-checking permission without a
    /// site, a row whose site does not match and missing items never get
    /// checked (T92).
    pub fn set(&mut self, permission: Option<Permission>, checked: bool) {
        let row_ok = !self.missing && !self.domain_mismatch;
        for p in &mut self.permissions {
            if permission.is_none_or(|wanted| wanted == p.permission) {
                p.checked =
                    checked && row_ok && !p.denied_by_policy && !p.no_site && !p.always_asks;
            }
        }
    }

    /// Whether `p` may be checked on this row.
    pub fn can_check(&self, p: &ProposedPermission) -> bool {
        !p.denied_by_policy
            && !p.no_site
            && !p.always_asks
            && !self.missing
            && !self.domain_mismatch
    }
}

/// The card of a task request, completed by the person's client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proposal {
    /// One row per requested item.
    pub rows: Vec<ProposalRow>,
}

/// The hosts of an item's URLs, deduplicated, in order.
fn item_hosts(urls: &[String]) -> Vec<String> {
    let mut hosts = Vec::new();
    for host in urls.iter().filter_map(|u| site::item_host(u)) {
        if let Some(host) = normalize_host(&host)
            && !hosts.contains(&host)
        {
            hosts.push(host);
        }
    }
    hosts
}

/// Builds the card for `request` (ADR 0021 §3).
///
/// * `facts` gives what the vault says about each item (`None`: not found).
/// * `evaluate` is the grant policy (`klav_core::policy::evaluate` with the
///   item's real vault, project and tags) for a permission on a host. Its
///   `once` marks a target that always asks (ADR 0032 §4.2); for `passkey`
///   and `rotate`, which the policy always denies outside a task, the
///   caller sets it when the item is protected
///   ([`crate::policy::Policy::may_require_once`]).
///
/// Rules: hosts come from the item's URLs; a `domain` that matches none of
/// them leaves the row unchecked and uncheckable; `fill`, `passkey` and
/// `rotate` on an item without hosts are «No site» and uncheckable, except
/// on a card or an identity, where they are tied to the `domain` the agent
/// asked for (`domain_claimed`, ADR 0030 §6); `totp` is added (checked, «added by
/// Klav») to a `fill` on a login with TOTP; a login with a passkey and no
/// password gets `passkey` instead of `fill`, one with both gets `passkey`
/// unchecked; a permission the policy denies is struck through.
pub fn propose(
    request: &TaskRequest,
    facts: impl Fn(&TaskAccessRequest) -> Option<ItemFacts>,
    evaluate: impl Fn(&TaskAccessRequest, Permission, Option<&str>) -> Decision,
) -> Proposal {
    let rows = request
        .access
        .iter()
        .map(|asked| {
            let Some(item) = facts(asked) else {
                return ProposalRow {
                    vault_id: asked.vault_id,
                    project_id: asked.project_id,
                    item_id: asked.item_id,
                    missing: true,
                    domain_mismatch: false,
                    no_site: false,
                    domain_claimed: false,
                    domains: Vec::new(),
                    permissions: asked
                        .permissions
                        .iter()
                        .map(|&permission| ProposedPermission {
                            permission,
                            checked: false,
                            added_by_klav: false,
                            denied_by_policy: false,
                            no_site: false,
                            always_asks: false,
                        })
                        .collect(),
                };
            };
            let hosts = item_hosts(&item.urls);
            let asked_host = asked.domain.as_deref().and_then(normalize_host);
            // (domains, mismatch, claimed)
            let (domains, domain_mismatch, domain_claimed) = match asked_host {
                // Only on a site an agent added: «the site does not match».
                Some(host)
                    if !site::host_matches(&host, &hosts)
                        && site::host_matches(&host, &item.pending_urls) =>
                {
                    (hosts, true, false)
                }
                Some(host) if hosts.is_empty() && item.siteless => (vec![host], false, true),
                Some(_) if hosts.is_empty() => (Vec::new(), false, false),
                Some(host) if site::host_matches(&host, &hosts) => (vec![host], false, false),
                Some(_) => (hosts, true, false),
                None => (hosts, false, false),
            };
            // Requested, then what Klav adds.
            let mut wanted: Vec<(Permission, bool, bool)> = Vec::new();
            let mut push = |permission, checked, added: bool| {
                if !wanted.iter().any(|(p, _, _)| *p == permission) {
                    wanted.push((permission, checked, added));
                }
            };
            let passkey_only = item.is_login && item.has_passkey && !item.has_password;
            for &permission in &asked.permissions {
                if permission == Permission::Fill && passkey_only {
                    push(Permission::Passkey, true, true);
                } else {
                    push(permission, true, false);
                }
            }
            if item.is_login && asked.permissions.contains(&Permission::Fill) {
                if item.has_totp {
                    push(Permission::Totp, true, true);
                }
                if item.has_passkey && item.has_password {
                    push(Permission::Passkey, false, true);
                }
            }
            let permissions: Vec<ProposedPermission> = wanted
                .into_iter()
                .map(|(permission, checked, added_by_klav)| {
                    let decisions: Vec<Decision> =
                        if permission.checks_domain() && !domains.is_empty() {
                            domains
                                .iter()
                                .map(|d| evaluate(asked, permission, Some(d)))
                                .collect()
                        } else {
                            vec![evaluate(asked, permission, None)]
                        };
                    let denied = decisions.iter().all(|d| d.effect == Effect::Deny);
                    // `ask once` on any of its hosts: never in a task.
                    let always_asks = decisions.iter().any(|d| d.once);
                    // passkey and rotate are `deny` for any policy outside
                    // a task: only an explicit deny on fill would matter,
                    // and that is not theirs. Never strike them.
                    let denied_by_policy = denied && !permission.requires_task();
                    let no_site = permission.checks_domain() && domains.is_empty();
                    ProposedPermission {
                        permission,
                        checked: checked
                            && !denied_by_policy
                            && !domain_mismatch
                            && !no_site
                            && !always_asks,
                        added_by_klav,
                        denied_by_policy,
                        no_site,
                        always_asks,
                    }
                })
                .collect();
            ProposalRow {
                vault_id: asked.vault_id,
                project_id: asked.project_id,
                item_id: asked.item_id,
                missing: false,
                domain_mismatch,
                no_site: permissions.iter().any(|p| p.no_site),
                domain_claimed,
                domains,
                permissions,
            }
        })
        .collect();
    Proposal { rows }
}

impl Proposal {
    /// The row of `item`.
    pub fn row_mut(&mut self, item: ItemId) -> Option<&mut ProposalRow> {
        self.rows.iter_mut().find(|r| r.item_id == item)
    }

    /// Whether something is checked (an approval needs at least one access).
    pub fn any_checked(&self) -> bool {
        self.rows.iter().any(ProposalRow::any_checked)
    }

    /// The decision to sign for what is checked.
    pub fn decision(&self, task_id: TaskId, agent_id: AgentId, expires_at_ms: u64) -> TaskDecision {
        let access = self
            .rows
            .iter()
            .filter(|row| !row.missing && row.any_checked())
            .map(|row| {
                let checked: Vec<&ProposedPermission> =
                    row.permissions.iter().filter(|p| p.checked).collect();
                TaskAccessDecision {
                    vault_id: row.vault_id,
                    project_id: row.project_id,
                    item_id: row.item_id,
                    permissions: checked.iter().map(|p| p.permission).collect(),
                    domains: row.domains.clone(),
                    added_by_klav: checked
                        .iter()
                        .filter(|p| p.added_by_klav)
                        .map(|p| p.permission)
                        .collect(),
                }
            })
            .collect();
        TaskDecision {
            v: TASK_FORMAT_VERSION,
            task_id,
            agent_id,
            revision: 1,
            expires_at_ms,
            access,
            offer: None,
        }
    }
}

/// When a task approved at `decided_at_ms` ends: after the requested
/// duration, or earlier if the person shortened it (`shorter_secs`). Never
/// later than requested nor than 24 hours.
pub fn expiry(decided_at_ms: u64, requested_secs: u64, shorter_secs: Option<u64>) -> u64 {
    let secs = shorter_secs
        .map_or(requested_secs, |s| s.min(requested_secs))
        .min(MAX_TASK_DURATION_SECS);
    decided_at_ms.saturating_add(secs * 1000)
}

/// A denial, as signed (spec §13.8).
pub fn denial(task_id: TaskId, agent_id: AgentId) -> TaskDecision {
    TaskDecision {
        v: TASK_FORMAT_VERSION,
        task_id,
        agent_id,
        revision: 1,
        expires_at_ms: 0,
        access: Vec::new(),
        offer: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{Decision, Reason};

    fn decided(effect: Effect) -> Decision {
        Decision {
            effect,
            reason: Reason::Default,
            once: false,
        }
    }

    fn ids() -> (VaultId, ProjectId, ItemId, ItemId) {
        (
            VaultId::from_bytes([1; 16]),
            ProjectId::from_bytes([2; 16]),
            ItemId::from_bytes([3; 16]),
            ItemId::from_bytes([4; 16]),
        )
    }

    fn request() -> TaskRequest {
        let (vault, project, aws, telmex) = ids();
        TaskRequest {
            v: 1,
            task: "Descargar las facturas de octubre".into(),
            reason: "Conciliar los gastos del mes".into(),
            duration_secs: 2 * 3600,
            access: vec![
                TaskAccessRequest {
                    vault_id: vault,
                    project_id: project,
                    item_id: aws,
                    permissions: vec![Permission::Fill],
                    domain: None,
                },
                TaskAccessRequest {
                    vault_id: vault,
                    project_id: project,
                    item_id: telmex,
                    permissions: vec![Permission::Fill],
                    domain: Some("telmex.com".into()),
                },
            ],
        }
    }

    #[test]
    fn durations_parse_and_have_limits() {
        assert_eq!(parse_duration("30m"), Ok(1800));
        assert_eq!(parse_duration("2h"), Ok(7200));
        assert_eq!(parse_duration("1h30m"), Ok(5400));
        assert_eq!(parse_duration(" 90s "), Ok(90));
        for bad in [
            "",
            "2",
            "h",
            "2d",
            "-1h",
            "0m",
            "1.5h",
            "99999999999999999999h",
        ] {
            assert!(parse_duration(bad).is_err(), "{bad}");
        }
        assert_eq!(check_duration(299), Err(TaskError::DurationRange));
        assert_eq!(check_duration(300), Ok(()));
        assert_eq!(check_duration(86_400), Ok(()));
        assert_eq!(check_duration(86_401), Err(TaskError::DurationRange));
    }

    #[test]
    fn spec_parses_from_json_and_validates() {
        let spec: TaskSpec = serde_json::from_str(
            r#"{"task":"Facturas","reason":"Conciliar","duration":"2h",
                "access":[{"ref":"Facturas/AWS","permissions":["fill","totp"]},
                          {"ref":"Facturas/Telmex","permissions":["fill"],"domain":"telmex.com"}]}"#,
        )
        .unwrap();
        assert_eq!(spec.validate(), Ok(7200));
        assert_eq!(spec.access[0].reference, "Facturas/AWS");
        // Unknown keys and permissions are rejected by the parser.
        assert!(
            serde_json::from_str::<TaskSpec>(
                r#"{"task":"a","reason":"b","duration":"1h","access":[],"extra":1}"#
            )
            .is_err()
        );
        assert!(serde_json::from_str::<TaskSpec>(
            r#"{"task":"a","reason":"b","duration":"1h","access":[{"ref":"x","permissions":["fly"]}]}"#
        )
        .is_err());
    }

    #[test]
    fn what_never_goes_in_a_task() {
        let mut r = request();
        for (permission, error) in [
            (Permission::Reveal, TaskError::Reveal),
            (Permission::Delete, TaskError::Delete),
            (Permission::List, TaskError::GrantOnly(Permission::List)),
            (Permission::Create, TaskError::GrantOnly(Permission::Create)),
        ] {
            r.access[0].permissions = vec![Permission::Fill, permission];
            assert_eq!(r.validate(), Err(error));
        }
        for permission in TASK_PERMISSIONS {
            r.access[0].permissions = vec![permission];
            assert_eq!(r.validate(), Ok(()));
        }
    }

    #[test]
    fn request_limits() {
        assert_eq!(request().validate(), Ok(()));
        let mut r = request();
        r.task = "x".repeat(121);
        assert!(matches!(
            r.validate(),
            Err(TaskError::Text { field: "task", .. })
        ));
        r.task = "x".repeat(120);
        assert_eq!(r.validate(), Ok(()));
        r.task = "  ".into();
        assert!(r.validate().is_err());
        r.task = "a\nb".into();
        assert!(r.validate().is_err());
        // Nor what would make the card read otherwise (layer 06): bidi
        // overrides and isolates, zero-width marks, line and paragraph
        // separators.
        for bad in [
            "facturas\u{202E}fdp.exe",
            "a\u{202A}b",
            "a\u{2066}b",
            "a\u{2069}b",
            "a\u{200B}b",
            "a\u{2028}b",
            "a\u{2029}b",
        ] {
            r.task = bad.into();
            assert!(r.validate().is_err(), "{bad:?}");
        }
        r.task = "Facturas de café ✓".into();
        assert_eq!(r.validate(), Ok(()));
        let mut r = request();
        r.reason = "é".repeat(500);
        assert_eq!(r.validate(), Ok(()));
        r.reason = "é".repeat(501);
        assert!(matches!(
            r.validate(),
            Err(TaskError::Text {
                field: "reason",
                ..
            })
        ));
        r.reason = String::new();
        assert!(r.validate().is_err());

        let mut r = request();
        r.duration_secs = 60;
        assert_eq!(r.validate(), Err(TaskError::DurationRange));
        r.duration_secs = 25 * 3600;
        assert_eq!(r.validate(), Err(TaskError::DurationRange));

        let mut r = request();
        r.access.clear();
        assert_eq!(r.validate(), Err(TaskError::AccessCount));
        let template = request().access[0].clone();
        r.access = (0..=MAX_TASK_ACCESS)
            .map(|i| TaskAccessRequest {
                item_id: ItemId::from_bytes([u8::try_from(i).unwrap(); 16]),
                ..template.clone()
            })
            .collect();
        assert_eq!(r.validate(), Err(TaskError::AccessCount));
        r.access.pop();
        assert_eq!(r.validate(), Ok(()));

        let mut r = request();
        r.access[1].item_id = r.access[0].item_id;
        assert!(matches!(r.validate(), Err(TaskError::DuplicateItem(_))));
        let mut r = request();
        r.access[0].permissions = vec![];
        assert_eq!(r.validate(), Err(TaskError::NoPermissions));
        r.access[0].permissions = vec![Permission::Fill, Permission::Fill];
        assert!(matches!(
            r.validate(),
            Err(TaskError::DuplicatePermission(Permission::Fill))
        ));
        let mut r = request();
        r.access[0].domain = Some("https://aws.amazon.com".into());
        assert!(matches!(r.validate(), Err(TaskError::Domain(_))));
        let mut r = request();
        r.v = 2;
        assert_eq!(r.validate(), Err(TaskError::Version(2)));
    }

    fn login(urls: &[&str], totp: bool) -> ItemFacts {
        ItemFacts {
            is_login: true,
            siteless: false,
            urls: urls.iter().map(|u| (*u).to_owned()).collect(),
            pending_urls: Vec::new(),
            has_totp: totp,
            has_password: true,
            has_passkey: false,
        }
    }

    #[test]
    fn a_site_an_agent_added_does_not_match() {
        // ADR 0030 §7: a domain only among the hosts an agent added (not
        // confirmed by the person) is a mismatch, also when the item has no
        // confirmed host at all.
        for confirmed in [&["https://bank.example"][..], &[][..]] {
            let r = siteless_request(Some("bank-fake.example"), &[Permission::Fill]);
            let facts = ItemFacts {
                pending_urls: vec!["https://bank-fake.example".into()],
                ..login(confirmed, false)
            };
            let mut proposal = propose(
                &r,
                |_| Some(facts.clone()),
                |_, _, _| decided(Effect::Allow),
            );
            let row = &mut proposal.rows[0];
            assert!(row.domain_mismatch, "{confirmed:?}");
            assert!(!row.domains.iter().any(|d| d == "bank-fake.example"));
            row.set(Some(Permission::Fill), true);
            assert!(!row.permissions[0].checked);
        }
    }

    #[test]
    fn the_proposal_comes_from_the_vault() {
        let (_, _, aws, telmex) = ids();
        let r = request();
        let proposal = propose(
            &r,
            |a| {
                Some(if a.item_id == aws {
                    login(
                        &["https://signin.aws.amazon.com/", "https://www.amazon.com"],
                        true,
                    )
                } else {
                    // The agent said telmex.com; the item is the bank.
                    login(&["https://banco.example"], false)
                })
            },
            |_, _, _| decided(Effect::Ask),
        );
        let aws_row = &proposal.rows[0];
        assert_eq!(
            aws_row.domains,
            vec!["signin.aws.amazon.com".to_owned(), "amazon.com".to_owned()]
        );
        assert!(!aws_row.domain_mismatch);
        assert_eq!(
            aws_row.permissions,
            vec![
                ProposedPermission {
                    permission: Permission::Fill,
                    checked: true,
                    added_by_klav: false,
                    denied_by_policy: false,
                    no_site: false,
                    always_asks: false,
                },
                ProposedPermission {
                    permission: Permission::Totp,
                    checked: true,
                    added_by_klav: true,
                    denied_by_policy: false,
                    no_site: false,
                    always_asks: false,
                },
            ]
        );
        let telmex_row = &proposal.rows[1];
        assert!(telmex_row.domain_mismatch);
        assert!(!telmex_row.any_checked());
        assert_eq!(telmex_row.domains, vec!["banco.example".to_owned()]);
        // T92: a row whose site does not match cannot be checked again.
        let mut again = proposal.clone();
        again.rows[1].set(None, true);
        assert!(!again.rows[1].any_checked());

        let decision =
            proposal.decision(TaskId::from_bytes([9; 16]), AgentId::from_bytes([8; 16]), 1);
        assert_eq!(decision.access.len(), 1);
        assert_eq!(decision.access[0].item_id, aws);
        assert_eq!(decision.access[0].added_by_klav, vec![Permission::Totp]);
        assert!(decision.access_for(telmex).is_none());
        assert_eq!(decision.removed_from(&r).len(), 1);
    }

    #[test]
    fn the_policy_strikes_what_it_denies() {
        let r = request();
        let mut proposal = propose(
            &r,
            |_| Some(login(&["https://telmex.com"], true)),
            |_, permission, _| {
                decided(if permission == Permission::Totp {
                    Effect::Deny
                } else {
                    Effect::Allow
                })
            },
        );
        let row = &mut proposal.rows[1];
        let totp = row.permissions[1];
        assert_eq!(totp.permission, Permission::Totp);
        assert!(totp.denied_by_policy && !totp.checked);
        // It cannot be checked again.
        row.set(Some(Permission::Totp), true);
        assert!(!row.permissions[1].checked);
        row.set(None, false);
        assert!(!row.any_checked());
        row.set(Some(Permission::Fill), true);
        assert!(row.permissions[0].checked);
    }

    #[test]
    fn passkeys_replace_or_join_fill() {
        let r = request();
        let only = ItemFacts {
            has_password: false,
            has_passkey: true,
            ..login(&["https://signin.aws.amazon.com"], false)
        };
        let proposal = propose(&r, |_| Some(only.clone()), |_, _, _| decided(Effect::Allow));
        let perms: Vec<_> = proposal.rows[0]
            .permissions
            .iter()
            .map(|p| (p.permission, p.checked, p.added_by_klav))
            .collect();
        assert_eq!(perms, vec![(Permission::Passkey, true, true)]);
        let both = ItemFacts {
            has_passkey: true,
            ..login(&["https://signin.aws.amazon.com"], false)
        };
        let proposal = propose(&r, |_| Some(both.clone()), |_, _, _| decided(Effect::Allow));
        let perms: Vec<_> = proposal.rows[0]
            .permissions
            .iter()
            .map(|p| (p.permission, p.checked, p.added_by_klav))
            .collect();
        assert_eq!(
            perms,
            vec![
                (Permission::Fill, true, false),
                (Permission::Passkey, false, true)
            ]
        );
    }

    #[test]
    fn missing_items_cannot_be_approved() {
        let r = request();
        let mut proposal = propose(&r, |_| None, |_, _, _| decided(Effect::Allow));
        assert!(proposal.rows.iter().all(|row| row.missing));
        proposal.rows[0].set(None, true);
        assert!(!proposal.any_checked());
    }

    #[test]
    fn ask_once_targets_never_go_in_a_task() {
        let (_, _, aws, _) = ids();
        let r = request();
        let mut proposal = propose(
            &r,
            |_| Some(login(&["https://signin.aws.amazon.com/"], true)),
            |asked, permission, _| Decision {
                once: asked.item_id == aws && permission == Permission::Fill,
                ..decided(Effect::Ask)
            },
        );
        let row = proposal.row_mut(aws).unwrap();
        let fill = row
            .permissions
            .iter()
            .find(|p| p.permission == Permission::Fill)
            .copied()
            .unwrap();
        assert!(fill.always_asks && !fill.checked && !row.can_check(&fill));
        row.set(Some(Permission::Fill), true);
        assert!(
            !row.permissions
                .iter()
                .any(|p| p.permission == Permission::Fill && p.checked)
        );
        let decision = proposal.decision(TaskId::generate(), AgentId::generate(), 1);
        assert!(
            !decision
                .access
                .iter()
                .any(|a| a.item_id == aws && a.permissions.contains(&Permission::Fill))
        );
    }

    fn approved() -> (TaskRequest, TaskDecision) {
        let r = request();
        let proposal = propose(
            &r,
            |a| {
                Some(if a.domain.is_some() {
                    login(&["https://telmex.com"], false)
                } else {
                    login(&["https://signin.aws.amazon.com"], true)
                })
            },
            |_, _, _| decided(Effect::Ask),
        );
        let decision = proposal.decision(
            TaskId::from_bytes([9; 16]),
            AgentId::from_bytes([8; 16]),
            expiry(1_000, r.duration_secs, None),
        );
        (r, decision)
    }

    #[test]
    fn decisions_validate_against_the_request() {
        let (r, d) = approved();
        assert_eq!(d.validate(true), Ok(()));
        assert_eq!(d.check_first(&r, 1_000), Ok(()));
        assert_eq!(d.expires_at_ms, 1_000 + 7_200_000);
        // Longer than asked.
        let mut longer = d.clone();
        longer.expires_at_ms += 1;
        assert!(longer.check_first(&r, 1_000).is_err());
        // An item that was not requested.
        let mut extra = d.clone();
        extra.access[0].item_id = ItemId::from_bytes([7; 16]);
        assert!(extra.check_first(&r, 1_000).is_err());
        // A permission neither requested nor added by Klav.
        let mut widened = d.clone();
        widened.access[1].permissions.push(Permission::Inject);
        assert!(widened.check_first(&r, 1_000).is_err());
        // Klav does not add inject.
        widened.access[1].added_by_klav.push(Permission::Inject);
        assert!(widened.check_first(&r, 1_000).is_err());
        // added_by_klav must be approved.
        let mut stray = d.clone();
        stray.access[1].added_by_klav.push(Permission::Totp);
        assert!(stray.validate(true).is_err());
        // Hosts are stored lowercase.
        let mut upper = d.clone();
        upper.access[0].domains = vec!["SIGNIN.aws.amazon.com".into()];
        assert!(upper.validate(true).is_err());
        // Reveal is not approvable either.
        let mut reveal = d.clone();
        reveal.access[0].permissions.push(Permission::Reveal);
        assert_eq!(reveal.validate(true), Err(TaskError::Reveal));
        // Denials are empty.
        let deny = denial(d.task_id, d.agent_id);
        assert_eq!(deny.validate(false), Ok(()));
        assert!(d.validate(false).is_err());
        assert!(deny.validate(true).is_err());
    }

    #[test]
    fn revisions_only_add() {
        let (_, d) = approved();
        let mut next = d.clone();
        next.revision = 2;
        next.access[1].permissions.push(Permission::Totp);
        assert_eq!(next.check_extends(&d), Ok(()));
        let mut skip = next.clone();
        skip.revision = 3;
        assert!(skip.check_extends(&d).is_err());
        let mut longer = next.clone();
        longer.expires_at_ms += 1;
        assert!(longer.check_extends(&d).is_err());
        let mut fewer = next.clone();
        fewer.access.remove(0);
        assert!(fewer.check_extends(&d).is_err());
        let mut no_fill = next.clone();
        no_fill.access[1]
            .permissions
            .retain(|p| *p != Permission::Fill);
        assert!(no_fill.check_extends(&d).is_err());
        let mut new_item = next.clone();
        new_item.access.push(TaskAccessDecision {
            item_id: ItemId::from_bytes([7; 16]),
            ..d.access[0].clone()
        });
        assert_eq!(new_item.check_extends(&d), Ok(()));
    }

    #[test]
    fn coverage_checks_item_permission_and_site() {
        let (vault, project, aws, telmex) = ids();
        let (_, d) = approved();
        let covers = |item, permission, domain| d.covers(vault, project, item, permission, domain);
        assert!(covers(aws, Permission::Fill, Some("signin.aws.amazon.com")));
        assert!(covers(
            aws,
            Permission::Fill,
            Some("eu.signin.aws.amazon.com")
        ));
        assert!(!covers(
            aws,
            Permission::Fill,
            Some("console.aws.amazon.com")
        ));
        assert!(!covers(aws, Permission::Fill, Some("evil.example")));
        assert!(!covers(aws, Permission::Fill, None));
        // totp has no site.
        assert!(covers(aws, Permission::Totp, None));
        assert!(!covers(telmex, Permission::Totp, None));
        assert!(covers(telmex, Permission::Fill, Some("telmex.com")));
        assert!(!covers(aws, Permission::Inject, None));
        assert!(!d.covers(
            VaultId::from_bytes([5; 16]),
            project,
            aws,
            Permission::Totp,
            None
        ));
        // Without hosts a site-checking permission never passes (ADR 0030
        // §6): an old decision signed with `domains = []` fails closed.
        let old = TaskAccessDecision {
            vault_id: vault,
            project_id: project,
            item_id: ItemId::from_bytes([6; 16]),
            permissions: vec![Permission::Fill, Permission::Totp],
            domains: vec![],
            added_by_klav: vec![],
        };
        assert!(!old.allows(Permission::Fill, Some("shop.example")));
        assert!(!old.allows(Permission::Fill, None));
        assert!(old.allows(Permission::Totp, None), "totp has no site");
        // A card tied to the host the agent asked for.
        let card = TaskAccessDecision {
            domains: vec!["shop.example".into()],
            ..old
        };
        assert!(card.allows(Permission::Fill, Some("shop.example")));
        assert!(card.allows(Permission::Fill, Some("pay.shop.example")));
        assert!(!card.allows(Permission::Fill, Some("evil.example")));
        assert!(!card.allows(Permission::Fill, None));
    }

    fn siteless_request(domain: Option<&str>, permissions: &[Permission]) -> TaskRequest {
        let mut r = request();
        r.access.truncate(1);
        r.access[0].permissions = permissions.to_vec();
        r.access[0].domain = domain.map(str::to_owned);
        r
    }

    fn card_facts() -> ItemFacts {
        ItemFacts {
            siteless: true,
            ..ItemFacts::default()
        }
    }

    #[test]
    fn a_login_without_urls_has_no_site() {
        // ADR 0030 §6: fill on a login without hosts is «No site», with or
        // without a domain from the agent; totp and inject still go.
        for domain in [None, Some("bank.example")] {
            let r = siteless_request(domain, &[Permission::Fill, Permission::Inject]);
            let mut proposal = propose(
                &r,
                |_| Some(login(&[], true)),
                |_, _, _| decided(Effect::Ask),
            );
            let row = &mut proposal.rows[0];
            assert!(row.no_site && !row.domain_claimed && row.domains.is_empty());
            let fill = row.permissions[0];
            assert_eq!(fill.permission, Permission::Fill);
            assert!(fill.no_site && !fill.checked);
            row.set(None, true);
            assert!(!row.permissions[0].checked, "cannot be checked");
            let totp = row
                .permissions
                .iter()
                .find(|p| p.permission == Permission::Totp)
                .unwrap();
            assert!(totp.checked && !totp.no_site);
            assert!(
                row.permissions
                    .iter()
                    .find(|p| p.permission == Permission::Inject)
                    .unwrap()
                    .checked
            );
        }
    }

    #[test]
    fn a_card_is_tied_to_the_site_the_agent_asked_for() {
        // With a domain: checked, tied to it, shown as the agent's claim.
        let r = siteless_request(Some("Shop.Example"), &[Permission::Fill]);
        let proposal = propose(&r, |_| Some(card_facts()), |_, _, _| decided(Effect::Ask));
        let row = &proposal.rows[0];
        assert!(row.domain_claimed && !row.no_site && !row.domain_mismatch);
        assert_eq!(row.domains, vec!["shop.example".to_owned()]);
        assert!(row.permissions[0].checked);
        let d = proposal.decision(
            TaskId::from_bytes([9; 16]),
            AgentId::from_bytes([8; 16]),
            expiry(1_000, r.duration_secs, None),
        );
        assert_eq!(d.check_first(&r, 1_000), Ok(()));
        let (vault, project, item, _) = ids();
        assert!(d.covers(vault, project, item, Permission::Fill, Some("shop.example")));
        assert!(!d.covers(vault, project, item, Permission::Fill, Some("evil.example")));
        // Without a domain: «No site», not checked.
        let r = siteless_request(None, &[Permission::Fill]);
        let proposal = propose(&r, |_| Some(card_facts()), |_, _, _| decided(Effect::Ask));
        assert!(proposal.rows[0].no_site);
        assert!(!proposal.any_checked());
    }

    #[test]
    fn a_decision_without_a_site_is_refused() {
        let (r, mut d) = approved();
        d.access[0].domains.clear();
        assert_eq!(d.validate(true), Ok(()), "old decisions still read");
        assert!(d.check_first(&r, 1_000).is_err());
        let (_, previous) = approved();
        let mut next = previous.clone();
        next.revision = 2;
        next.access.push(TaskAccessDecision {
            item_id: ItemId::from_bytes([7; 16]),
            permissions: vec![Permission::Fill],
            domains: vec![],
            ..previous.access[0].clone()
        });
        assert!(next.check_extends(&previous).is_err());
        // Without a site-checking permission an empty list is fine.
        next.access.last_mut().unwrap().permissions = vec![Permission::Inject];
        next.access.last_mut().unwrap().added_by_klav.clear();
        assert_eq!(next.check_extends(&previous), Ok(()));
    }

    #[test]
    fn expiry_never_grows() {
        assert_eq!(expiry(0, 7200, None), 7_200_000);
        assert_eq!(expiry(0, 7200, Some(3600)), 3_600_000);
        assert_eq!(expiry(0, 7200, Some(10_800)), 7_200_000);
        assert_eq!(expiry(0, 100_000, None), 86_400_000);
    }

    fn offered(expires_at_ms: u64) -> TaskDecision {
        let (vault, project, aws, _) = ids();
        TaskDecision {
            v: 1,
            task_id: TaskId::from_bytes([5; 16]),
            agent_id: AgentId::from_bytes([6; 16]),
            revision: 1,
            expires_at_ms,
            access: vec![TaskAccessDecision {
                vault_id: vault,
                project_id: project,
                item_id: aws,
                permissions: vec![Permission::Rotate, Permission::Totp],
                domains: vec!["signin.aws.amazon.com".into()],
                added_by_klav: vec![Permission::Totp],
            }],
            offer: Some(TaskOffer {
                task: "Arreglar mis contraseñas repetidas".into(),
                reason: "Cada sitio con su propia contraseña".into(),
            }),
        }
    }

    #[test]
    fn an_offered_task_carries_the_persons_title_and_lasts_up_to_a_day() {
        let at = 1_800_000_000_000;
        let ok = offered(at + 3_600_000);
        assert_eq!(ok.validate(true), Ok(()));
        assert_eq!(ok.check_offered(at), Ok(()));
        let shown = ok.offered_request(at).unwrap();
        assert_eq!(shown.task, "Arreglar mis contraseñas repetidas");
        assert_eq!(shown.duration_secs, 3600);
        assert!(shown.access.is_empty());
        // Without the offer, past 24 hours, already expired or at a later
        // revision, it is refused.
        let mut bare = ok.clone();
        bare.offer = None;
        assert!(bare.check_offered(at).is_err());
        assert!(bare.offered_request(at).is_none());
        assert!(offered(at + 86_400_001).check_offered(at).is_err());
        assert!(offered(at).check_offered(at).is_err());
        let mut later = ok.clone();
        later.revision = 2;
        assert!(later.check_offered(at).is_err());
        // Klav only adds totp or passkey.
        let mut added = ok.clone();
        added.access[0].added_by_klav = vec![Permission::Rotate];
        assert!(added.check_offered(at).is_err());
        // A blank title is refused by validate.
        let mut blank = ok.clone();
        blank.offer = Some(TaskOffer {
            task: " ".into(),
            reason: "x".into(),
        });
        assert!(blank.validate(true).is_err());
        // The offer is never part of a decision on an agent's request,
        // and a revision keeps it.
        assert!(ok.check_first(&request(), at).is_err());
        let mut next = ok.clone();
        next.revision = 2;
        assert_eq!(next.check_extends(&ok), Ok(()));
        next.offer = None;
        assert!(next.check_extends(&ok).is_err());
        // An offer is never serialized when absent: decisions on requests
        // keep their bytes.
        let json = serde_json::to_string(&denial(ok.task_id, ok.agent_id)).unwrap();
        assert!(!json.contains("offer"));
    }

    #[test]
    fn rotate_needs_the_items_site() {
        let at = 1_800_000_000_000;
        let mut d = offered(at + 3_600_000);
        d.access[0].domains.clear();
        assert!(d.validate(true).is_err());
        // On the card, rotate on an item without URLs stays unchecked and
        // cannot be checked.
        let (vault, project, aws, _) = ids();
        let req = TaskRequest {
            access: vec![TaskAccessRequest {
                vault_id: vault,
                project_id: project,
                item_id: aws,
                permissions: vec![Permission::Rotate],
                domain: None,
            }],
            ..request()
        };
        let facts = |_: &TaskAccessRequest| {
            Some(ItemFacts {
                is_login: true,
                has_password: true,
                ..ItemFacts::default()
            })
        };
        let mut proposal = propose(&req, facts, |_, _, _| decided(Effect::Ask));
        assert!(!proposal.any_checked());
        proposal.rows[0].set(Some(Permission::Rotate), true);
        assert!(!proposal.any_checked());
        // With a URL it is checked and the decision validates.
        let with_url = |_: &TaskAccessRequest| {
            Some(ItemFacts {
                is_login: true,
                has_password: true,
                urls: vec!["https://bank.example/login".into()],
                ..ItemFacts::default()
            })
        };
        let proposal = propose(&req, with_url, |_, _, _| decided(Effect::Ask));
        assert!(proposal.any_checked());
        let decision = proposal.decision(
            TaskId::from_bytes([5; 16]),
            AgentId::from_bytes([6; 16]),
            at + 1,
        );
        assert_eq!(decision.validate(true), Ok(()));
        assert_eq!(decision.access[0].domains, ["bank.example"]);
    }
}
