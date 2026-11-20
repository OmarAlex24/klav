//! Tasks the person offers an agent (ADR 0022 §6): «Fix my reused
//! passwords».
//!
//! The person, not the agent, starts it. Their client builds the list (the
//! logins that share a password, from the vault health report, with each
//! site's change page), the person unchecks what they do not want, and one
//! approval signs a task decision without a request from the agent
//! (`klav/v1/sig/task-decision` over an empty request, spec §13.8). The
//! decision carries `rotate` on each login, plus `totp` («Added by Klav»)
//! on those with a one-time code, and the person's own title and reason
//! (`offer`). It goes to the server with `POST /v1/tasks`.
//!
//! The agent never sees the reused list: it finds the task with
//! `list_tasks()` and gets only the sites. The rows here are sorted by
//! host, not by group, so the order of the sites in the task says nothing
//! about which ones shared a password; the default title and reason do not
//! say «reused» either.
//!
//! [`Unlocked::task_progress`] reads each site's state (changed, pending or
//! failed) from the `rotate.*` events of the task (ADR 0022 §5).

use klav_core::crypto::agent::{self, TaskDecisionToSign};
use klav_core::generator::change_password::{self, ChangePasswordUrl};
use klav_core::ids::{AgentId, ItemId, ProjectId, TaskId, VaultId};
use klav_core::model::ItemKind;
use klav_core::policy::{Effect, Permission};
use klav_core::task::{
    self, TASK_FORMAT_VERSION, TaskAccessDecision, TaskAccessRequest, TaskDecision, TaskOffer,
};
use klav_proto::Blob;
use klav_proto::agent::AgentStatus;
use klav_proto::task::{OfferTask, TaskInfo};
use reqwest::Method;
use serde::{Deserialize, Serialize};

use crate::agents::{AgentView, GrantView};
use crate::audit::{LogFilter, LogLine, log_unreadable};
use crate::error::{ClientError, ClientResult};
use crate::session::{ItemLocation, Unlocked, now_ms};
use crate::tasks::{TaskCard, facts_of, hosts_of};

/// The title of an offered task when the person writes none. Neutral on
/// purpose: the agent reads it (ADR 0022 §6).
pub const DEFAULT_OFFER_TASK: &str = "Change passwords";
/// The reason of an offered task when the person writes none.
pub const DEFAULT_OFFER_REASON: &str =
    "Give each of these sites a new password that Klav generates and keeps";
/// How long an offered task lasts when the person does not say (2 hours).
pub const DEFAULT_OFFER_SECS: u64 = 2 * 3600;
/// The most logins one task holds (ADR 0021 Q6).
pub const MAX_OFFER_ITEMS: usize = 50;

/// Why a login cannot go in the task. Shown unchecked, and cannot be
/// checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OfferBlock {
    /// Its project is not in the agent's grant.
    NotGranted,
    /// It has no website: a password change happens on the item's site
    /// (T99).
    NoSite,
    /// Not a login with a password.
    NotLogin,
    /// The shared password is not the login's main password, the one an
    /// assisted change replaces.
    OtherField,
}

/// One login on the offer card. Metadata only: never a value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfferRow {
    /// Item.
    pub item_id: ItemId,
    /// Vault.
    pub vault_id: VaultId,
    /// Project.
    pub project_id: ProjectId,
    /// `klav://vault/project/item`.
    pub reference: String,
    /// Title.
    pub title: String,
    /// Username.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// The item's hosts (normalized): where the agent may change it.
    pub hosts: Vec<String>,
    /// The site's change-password page (`change_password_url`, ADR 0022
    /// §1.3).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change_url: Option<ChangePasswordUrl>,
    /// Which group of logins sharing one password it is in (1, 2…), for
    /// the person only: the agent never gets it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<usize>,
    /// What the task would hold: `rotate`, and `totp` if the login has a
    /// one-time code and the policy does not deny it.
    pub permissions: Vec<Permission>,
    /// Why it cannot go in the task, if so.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocked: Option<OfferBlock>,
}

/// An agent the person can offer the task to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfferAgent {
    /// ID.
    pub id: AgentId,
    /// Name.
    pub name: String,
}

/// The «Fix my reused passwords» card: the agents that can take it and the
/// logins that share a password, with their change pages.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReusedOffer {
    /// Active agents with a grant.
    pub agents: Vec<OfferAgent>,
    /// The agent the rows were checked against (its grant and policy).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<OfferAgent>,
    /// The logins, sorted by host. Blocked ones last.
    pub rows: Vec<OfferRow>,
    /// Default title, reason and duration.
    pub task: String,
    /// Default reason.
    pub reason: String,
    /// Default duration (seconds).
    pub duration_secs: u64,
}

/// What the person approves: the agent, the logins left checked, and
/// optionally their own title, reason and duration.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfferRequest {
    /// The agent (ID, unique ID prefix or name).
    pub agent: String,
    /// The logins.
    pub items: Vec<ItemId>,
    /// Title ([`DEFAULT_OFFER_TASK`] when absent).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task: Option<String>,
    /// Reason ([`DEFAULT_OFFER_REASON`] when absent).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Duration in seconds ([`DEFAULT_OFFER_SECS`] when absent; 5 minutes
    /// to 24 hours).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_secs: Option<u64>,
}

/// An offer checked by [`Unlocked::prepare_offer`], ready to sign. No
/// secrets.
#[derive(Debug, Clone)]
pub struct PreparedOffer {
    agent: AgentId,
    agent_name: String,
    rows: Vec<OfferRow>,
    offer: TaskOffer,
    duration_secs: u64,
}

impl PreparedOffer {
    /// The agent's name.
    #[must_use]
    pub fn agent_name(&self) -> &str {
        &self.agent_name
    }

    /// How many logins.
    #[must_use]
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    /// Never empty once prepared.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }
}

/// A site's state in a task with `rotate` (`klav log --task`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SiteState {
    /// The agent confirmed the new password (`rotate.confirmed`).
    Changed,
    /// Not started, or started and neither confirmed nor cancelled.
    Pending,
    /// Cancelled (the site refused it, or the agent gave up), or refused
    /// by Klav when it started.
    Failed,
}

/// One site of a task with `rotate`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SiteProgress {
    /// Item.
    pub item_id: ItemId,
    /// `klav://…`, if this device knows the item.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
    /// Title, if this device knows the item.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// The hosts the task allows.
    pub hosts: Vec<String>,
    /// State.
    pub state: SiteState,
    /// The agent started a change and has not closed it yet.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub started: bool,
    /// Time of the last `rotate.*` event for this site (Unix ms).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<i64>,
}

/// The sites of a task with `rotate` and where each one is.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskProgress {
    /// The task.
    pub task_id: TaskId,
    /// Its card, while the server still lists it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub card: Option<TaskCard>,
    /// One per login with `rotate`, in the task's order. Empty, with
    /// [`Self::log_warning`], when the audit log cannot be read: where each
    /// site is comes from it.
    pub sites: Vec<SiteProgress>,
    /// Why `sites` is empty: the audit log could not be read as this
    /// device holds it (ADR 0033 §8.4). The card still comes from the
    /// server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_warning: Option<String>,
}

/// Each `rotate` site's state from the task's events (oldest first): the
/// last `rotate.*` event of the item wins, except that a site once changed
/// stays changed when a later try fails (the changed password is still
/// current). A refused start counts as failed; a refused confirm or cancel
/// changes nothing.
#[must_use]
pub fn site_states(
    decision: &TaskDecision,
    events: &[LogLine],
) -> Vec<(ItemId, SiteState, bool, Option<i64>)> {
    decision
        .access
        .iter()
        .filter(|a| a.permissions.contains(&Permission::Rotate))
        .map(|a| {
            let mut state = (SiteState::Pending, false, None);
            let mut changed = false;
            for e in events.iter().filter(|e| e.item_id == Some(a.item_id)) {
                // The person's own close of a change (from the item's
                // card) has no policy outcome: it happened.
                // Told apart by who wrote it, not by the name: an agent
                // may be called `you`.
                let allowed = e.outcome.as_deref() == Some("allow") || !e.by_agent;
                // Once changed, a later try that fails leaves the changed
                // password current.
                let failed = if changed {
                    SiteState::Changed
                } else {
                    SiteState::Failed
                };
                state = match (e.action.as_str(), allowed) {
                    ("rotate.started", true) => (SiteState::Pending, true, Some(e.at)),
                    ("rotate.started", false) => (failed, false, Some(e.at)),
                    ("rotate.confirmed", true) => {
                        changed = true;
                        (SiteState::Changed, false, Some(e.at))
                    }
                    ("rotate.cancelled", true) => (failed, false, Some(e.at)),
                    _ => state,
                };
            }
            (a.item_id, state.0, state.1, state.2)
        })
        .collect()
}

/// The decision of an offered task (ADR 0022 §6), checked as the server
/// will check it.
pub fn offer_decision(
    task_id: TaskId,
    agent_id: AgentId,
    rows: &[OfferRow],
    offer: TaskOffer,
    decided_at_ms: u64,
    duration_secs: u64,
) -> ClientResult<TaskDecision> {
    if !(task::MIN_TASK_DURATION_SECS..=task::MAX_TASK_DURATION_SECS).contains(&duration_secs) {
        return Err(ClientError::Invalid(
            "an offered task lasts from 5 minutes to 24 hours".into(),
        ));
    }
    let mut rows: Vec<&OfferRow> = rows.iter().filter(|r| r.blocked.is_none()).collect();
    if rows.is_empty() {
        return Err(ClientError::Invalid(
            "nothing to offer: no login can go in the task".into(),
        ));
    }
    if rows.len() > MAX_OFFER_ITEMS {
        return Err(ClientError::Invalid(format!(
            "a task holds at most {MAX_OFFER_ITEMS} logins: leave some out"
        )));
    }
    // By site, never by group: the order says nothing about which logins
    // shared a password.
    rows.sort_by(|a, b| a.hosts.cmp(&b.hosts).then(a.item_id.cmp(&b.item_id)));
    let access = rows
        .iter()
        .map(|r| TaskAccessDecision {
            vault_id: r.vault_id,
            project_id: r.project_id,
            item_id: r.item_id,
            permissions: r.permissions.clone(),
            domains: r.hosts.clone(),
            added_by_klav: r
                .permissions
                .iter()
                .copied()
                .filter(|p| *p == Permission::Totp)
                .collect(),
        })
        .collect();
    let decision = TaskDecision {
        v: TASK_FORMAT_VERSION,
        task_id,
        agent_id,
        revision: 1,
        expires_at_ms: decided_at_ms.saturating_add(duration_secs * 1000),
        access,
        offer: Some(offer),
    };
    decision
        .validate(true)
        .and_then(|()| decision.check_offered(decided_at_ms))
        .map_err(|e| ClientError::Invalid(e.to_string()))?;
    Ok(decision)
}

#[cfg_attr(not(feature = "health"), allow(dead_code))]
fn offer_agent(agent: &AgentView) -> OfferAgent {
    OfferAgent {
        id: agent.id,
        name: agent.name.clone(),
    }
}

impl Unlocked {
    /// The agents a task can be offered to: active, with a grant.
    #[cfg_attr(not(feature = "health"), allow(dead_code))]
    async fn offer_agents(&mut self) -> ClientResult<Vec<AgentView>> {
        Ok(self
            .agents()
            .await?
            .into_iter()
            .filter(|a| a.status == AgentStatus::Active && a.grant.is_some())
            .collect())
    }

    async fn offer_agent(&mut self, wanted: &str) -> ClientResult<AgentView> {
        let agent = crate::agents::find_agent(self.agents().await?, wanted)?;
        if agent.status != AgentStatus::Active {
            return Err(ClientError::Invalid(format!(
                "agent {} is {}, not active",
                agent.name,
                agent.status.as_str()
            )));
        }
        if agent.grant.is_none() {
            return Err(ClientError::Invalid(format!(
                "agent {} has no grant yet",
                agent.name
            )));
        }
        Ok(agent)
    }

    /// The offer card's row for one login, against `grant` (if any). The
    /// shared field, when known, must be the login's main password.
    pub(crate) fn offer_row(
        &self,
        loc: ItemLocation,
        grant: Option<&GrantView>,
        shared_field: Option<&str>,
        group: Option<usize>,
    ) -> ClientResult<OfferRow> {
        let summary = self.item_summary(loc)?;
        if summary.trashed {
            return Err(ClientError::NotFound(format!(
                "{} is in the trash",
                summary.reference
            )));
        }
        let item = self.open_item(loc)?;
        let facts = facts_of(&item, &summary);
        // Only the sites the person confirmed (ADR 0030 §7): a host an agent
        // added is no place to type the current and the new password.
        let hosts = hosts_of(&summary.confirmed_urls);
        let main = crate::rotate::main_password_field(&item);
        let blocked = if summary.kind != ItemKind::Login || main.is_none() {
            Some(OfferBlock::NotLogin)
        } else if shared_field.is_some_and(|f| Some(f) != main.as_deref()) {
            Some(OfferBlock::OtherField)
        } else if hosts.is_empty() {
            Some(OfferBlock::NoSite)
        } else if grant.is_some_and(|g| {
            !g.projects
                .iter()
                .any(|p| p.project_id == loc.project && p.vault_id == loc.vault)
        }) {
            Some(OfferBlock::NotGranted)
        } else {
            None
        };
        let mut permissions = vec![Permission::Rotate];
        if facts.has_totp
            && let Some(grant) = grant
        {
            let asked = TaskAccessRequest {
                vault_id: loc.vault,
                project_id: loc.project,
                item_id: loc.item,
                permissions: vec![Permission::Rotate],
                domain: None,
            };
            // Like a card on a request (ADR 0021 §3): the policy's deny
            // wins, on every host of the item.
            let denied = hosts.iter().all(|h| {
                self.task_effect(grant, &asked, Permission::Totp, Some(h)) == Effect::Deny
            });
            if !denied {
                permissions.push(Permission::Totp);
            }
        }
        Ok(OfferRow {
            item_id: loc.item,
            vault_id: loc.vault,
            project_id: loc.project,
            reference: summary.reference,
            title: summary.title,
            username: summary.username,
            change_url: change_password::for_item(&summary.confirmed_urls),
            hosts,
            group,
            permissions,
            blocked,
        })
    }

    /// Checks an offer before the person is asked for presence: the
    /// agent is active with a grant, and every login can go in the task.
    /// Nothing is signed or sent; see [`Self::send_offer`].
    pub async fn prepare_offer(&mut self, request: &OfferRequest) -> ClientResult<PreparedOffer> {
        let agent = self.offer_agent(&request.agent).await?;
        if request.items.is_empty() {
            return Err(ClientError::Invalid(
                "nothing to offer: pick at least one login".into(),
            ));
        }
        let mut rows = Vec::new();
        for item in &request.items {
            let loc = self.find_item(&item.to_string())?;
            let row = self.offer_row(loc, agent.grant.as_ref(), None, None)?;
            if let Some(block) = row.blocked {
                return Err(ClientError::Invalid(format!(
                    "{} cannot go in the task: {}",
                    row.reference,
                    block_text(block)
                )));
            }
            if !rows.iter().any(|r: &OfferRow| r.item_id == row.item_id) {
                rows.push(row);
            }
        }
        let offer = TaskOffer {
            task: request
                .task
                .clone()
                .unwrap_or_else(|| DEFAULT_OFFER_TASK.to_owned()),
            reason: request
                .reason
                .clone()
                .unwrap_or_else(|| DEFAULT_OFFER_REASON.to_owned()),
        };
        let duration_secs = request.duration_secs.unwrap_or(DEFAULT_OFFER_SECS);
        // The same checks the signed decision will pass.
        offer_decision(
            TaskId::generate(),
            agent.id,
            &rows,
            offer.clone(),
            u64::try_from(now_ms()).unwrap_or(0),
            duration_secs,
        )?;
        Ok(PreparedOffer {
            agent: agent.id,
            agent_name: agent.name,
            rows,
            offer,
            duration_secs,
        })
    }

    /// Signs a prepared offer with the account identity over an empty
    /// request and sends it (`POST /v1/tasks`). The caller asked for
    /// presence first.
    pub async fn send_offer(&mut self, prepared: PreparedOffer) -> ClientResult<TaskCard> {
        let PreparedOffer {
            agent: agent_id,
            rows,
            offer,
            duration_secs,
            ..
        } = prepared;
        let task_id = TaskId::generate();
        let decided_at = now_ms();
        let decided_at_ms = u64::try_from(decided_at).unwrap_or(0);
        let decision = offer_decision(
            task_id,
            agent_id,
            &rows,
            offer,
            decided_at_ms,
            duration_secs,
        )?;
        let bytes = serde_json::to_vec(&decision)
            .map_err(|e| ClientError::Invalid(format!("decision: {e}")))?;
        let signature = agent::sign_task_decision(
            &self.identity,
            &TaskDecisionToSign {
                task: task_id,
                agent: agent_id,
                request: &[],
                decision: &bytes,
                approve: true,
                decided_at_ms,
            },
        );
        let info: TaskInfo = self
            .send_json(
                Method::POST,
                "/v1/tasks",
                &OfferTask {
                    task_id,
                    agent_id,
                    decision: Blob::new(bytes),
                    decided_at,
                    signature: Blob::new(signature.to_bytes().to_vec()),
                },
            )
            .await?;
        self.card(&info).await
    }

    /// Offers `request.agent` a task with `rotate` (and `totp` where the
    /// login has a code) on `request.items` (ADR 0022 §6):
    /// [`Self::prepare_offer`], then [`Self::send_offer`]. The caller asked
    /// for presence first.
    pub async fn offer_task(&mut self, request: &OfferRequest) -> ClientResult<TaskCard> {
        let prepared = self.prepare_offer(request).await?;
        self.send_offer(prepared).await
    }

    /// Each `rotate` site of a task and its state, from the task's
    /// `rotate.*` events (oldest first) and its verified decision.
    pub(crate) fn sites_of(
        &self,
        card: Option<&TaskCard>,
        decision: Option<&TaskDecision>,
        events: &[LogLine],
    ) -> Vec<SiteProgress> {
        let Some(decision) = decision else {
            return Vec::new();
        };
        site_states(decision, events)
            .into_iter()
            .map(|(item_id, state, started, at)| {
                let row = card.and_then(|c| c.rows.iter().find(|r| r.item_id == item_id));
                let hosts = decision
                    .access
                    .iter()
                    .find(|a| a.item_id == item_id)
                    .map(|a| a.domains.clone())
                    .unwrap_or_default();
                SiteProgress {
                    item_id,
                    reference: row.map(|r| r.reference.clone()),
                    title: row.and_then(|r| r.title.clone()),
                    hosts,
                    state,
                    started,
                    at,
                }
            })
            .collect()
    }

    /// Where each site of a task with `rotate` is (ID or unique prefix):
    /// changed, pending or failed. For the popup's progress; the agent
    /// never asks for it.
    pub async fn task_progress(&mut self, wanted: &str) -> ClientResult<TaskProgress> {
        // A full ID (the popup's polling) goes straight to the task.
        let info = match wanted.parse::<TaskId>() {
            Ok(id) => self.task_info(id).await?,
            Err(_) => {
                let id = self.task(wanted).await?.id;
                self.task_info(id).await?
            }
        };
        let card = self.card(&info).await?;
        let decision = crate::tasks::verify_decision(self.identity.public(), &info)?;
        let mut events = match self
            .audit_log(&LogFilter {
                task: Some(card.id.to_string()),
                ..LogFilter::default()
            })
            .await
        {
            Ok(events) => events,
            // The card does not depend on the log; where each site is
            // does, so none is said rather than all «pending».
            Err(e @ ClientError::Security(_)) => {
                return Ok(TaskProgress {
                    task_id: card.id,
                    card: Some(card),
                    sites: Vec::new(),
                    log_warning: Some(log_unreadable("The task is shown", &e)),
                });
            }
            Err(e) => return Err(e),
        };
        events.reverse();
        let sites = self.sites_of(Some(&card), decision.as_ref(), &events);
        Ok(TaskProgress {
            task_id: card.id,
            card: Some(card),
            sites,
            log_warning: None,
        })
    }
}

/// What an [`OfferBlock`] means, for messages.
#[must_use]
pub fn block_text(block: OfferBlock) -> &'static str {
    match block {
        OfferBlock::NotGranted => "its project is not in the agent's grant",
        OfferBlock::NoSite => "it has no website, and a password change happens on the item's site",
        OfferBlock::NotLogin => "it is not a login with a password",
        OfferBlock::OtherField => "the shared password is not the login's main password",
    }
}

#[cfg(feature = "health")]
impl Unlocked {
    /// The «Fix my reused passwords» card (ADR 0022 §6): the logins that
    /// share a password with another item, sorted by host, with their
    /// change pages, checked against `agent`'s grant (the only active
    /// agent with a grant when `agent` is `None`, if there is just one).
    pub async fn reused_offer(&mut self, agent: Option<&str>) -> ClientResult<ReusedOffer> {
        let report = self.health_scan(now_ms()).finish(None).await;
        self.reused_offer_from(&report, agent).await
    }

    /// [`Self::reused_offer`] from a report already computed (`klavd`
    /// scans off the async workers: `zxcvbn` is CPU work).
    pub async fn reused_offer_from(
        &mut self,
        report: &crate::health::VaultHealth,
        agent: Option<&str>,
    ) -> ClientResult<ReusedOffer> {
        let agents = self.offer_agents().await?;
        let chosen = match agent {
            Some(wanted) => Some(self.offer_agent(wanted).await?),
            None if agents.len() == 1 => agents.first().cloned(),
            None => None,
        };
        let grant = chosen.as_ref().and_then(|a| a.grant.as_ref());
        let mut rows: Vec<OfferRow> = Vec::new();
        for (index, group) in report.reused.iter().enumerate() {
            for item in &group.items {
                if rows.iter().any(|r| r.item_id == item.id) {
                    continue;
                }
                let loc = ItemLocation {
                    vault: item.vault_id,
                    project: item.project_id,
                    item: item.id,
                };
                if let Ok(row) = self.offer_row(loc, grant, Some(&item.field), Some(index + 1)) {
                    rows.push(row);
                }
            }
        }
        rows.sort_by(|a, b| {
            a.blocked
                .is_some()
                .cmp(&b.blocked.is_some())
                .then(a.hosts.cmp(&b.hosts))
                .then(a.title.cmp(&b.title))
        });
        Ok(ReusedOffer {
            agents: agents.iter().map(offer_agent).collect(),
            agent: chosen.as_ref().map(offer_agent),
            rows,
            task: DEFAULT_OFFER_TASK.to_owned(),
            reason: DEFAULT_OFFER_REASON.to_owned(),
            duration_secs: DEFAULT_OFFER_SECS,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(host: &str, item: [u8; 16], permissions: Vec<Permission>) -> OfferRow {
        OfferRow {
            item_id: ItemId::from_bytes(item),
            vault_id: VaultId::from_bytes([1; 16]),
            project_id: ProjectId::from_bytes([2; 16]),
            reference: format!("klav://Personal/General/{host}"),
            title: host.to_owned(),
            username: None,
            hosts: vec![host.to_owned()],
            change_url: None,
            group: Some(1),
            permissions,
            blocked: None,
        }
    }

    fn offer() -> TaskOffer {
        TaskOffer {
            task: DEFAULT_OFFER_TASK.into(),
            reason: DEFAULT_OFFER_REASON.into(),
        }
    }

    const AT: u64 = 1_800_000_000_000;

    #[test]
    fn an_offer_holds_rotate_and_klavs_totp_sorted_by_site() {
        let rows = vec![
            row("shop.example", [3; 16], vec![Permission::Rotate]),
            row(
                "bank.example",
                [4; 16],
                vec![Permission::Rotate, Permission::Totp],
            ),
            OfferRow {
                blocked: Some(OfferBlock::NoSite),
                ..row("none.example", [5; 16], vec![Permission::Rotate])
            },
        ];
        let d = offer_decision(
            TaskId::from_bytes([7; 16]),
            AgentId::from_bytes([8; 16]),
            &rows,
            offer(),
            AT,
            3600,
        )
        .expect("decision");
        assert_eq!(d.revision, 1);
        assert_eq!(d.expires_at_ms, AT + 3_600_000);
        assert_eq!(d.offer, Some(offer()));
        // Blocked rows stay out; the rest go by host, not by group.
        let hosts: Vec<&str> = d.access.iter().map(|a| a.domains[0].as_str()).collect();
        assert_eq!(hosts, ["bank.example", "shop.example"]);
        assert_eq!(
            d.access[0].permissions,
            [Permission::Rotate, Permission::Totp]
        );
        assert_eq!(d.access[0].added_by_klav, [Permission::Totp]);
        assert!(d.access[1].added_by_klav.is_empty());
        assert_eq!(d.check_offered(AT), Ok(()));
        // The decision never names the group.
        let json = serde_json::to_string(&d).expect("json");
        assert!(!json.contains("group"), "{json}");
    }

    #[test]
    fn an_offer_needs_a_login_and_a_sane_duration() {
        let ok = vec![row("bank.example", [4; 16], vec![Permission::Rotate])];
        let make = |rows: &[OfferRow], secs| {
            offer_decision(
                TaskId::from_bytes([7; 16]),
                AgentId::from_bytes([8; 16]),
                rows,
                offer(),
                AT,
                secs,
            )
        };
        assert!(make(&ok, 60).is_err(), "under 5 minutes");
        assert!(make(&ok, 86_401).is_err(), "over a day");
        assert!(make(&[], 3600).is_err(), "nothing to offer");
        let blocked = vec![OfferRow {
            blocked: Some(OfferBlock::NotGranted),
            ..ok[0].clone()
        }];
        assert!(make(&blocked, 3600).is_err(), "only blocked rows");
        let many: Vec<OfferRow> = (0..=MAX_OFFER_ITEMS)
            .map(|i| {
                let mut id = [9; 16];
                id[0] = u8::try_from(i).expect("small");
                row(&format!("s{i}.example"), id, vec![Permission::Rotate])
            })
            .collect();
        assert!(make(&many, 3600).is_err(), "over 50 logins");
    }

    fn line(action: &str, outcome: &str, item: ItemId, at: i64) -> LogLine {
        LogLine {
            seq: 0,
            at,
            actor: "bot".into(),
            by_agent: true,
            agent_id: None,
            agent_name: None,
            action: action.into(),
            permission: Some("rotate".into()),
            outcome: Some(outcome.into()),
            item: None,
            item_id: Some(item),
            vault: None,
            reason: None,
            domain: None,
            attachments: Vec::new(),
            task_id: None,
            approval_id: None,
            until: None,
            alerts: Vec::new(),
            verified: false,
        }
    }

    #[test]
    fn each_site_is_changed_pending_or_failed_by_its_last_event() {
        let ids: Vec<ItemId> = (1..=5u8).map(|i| ItemId::from_bytes([i; 16])).collect();
        let rows: Vec<OfferRow> = ids
            .iter()
            .enumerate()
            .map(|(i, _)| {
                row(
                    &format!("s{i}.example"),
                    [u8::try_from(i + 1).expect("small"); 16],
                    vec![Permission::Rotate],
                )
            })
            .collect();
        let d = offer_decision(
            TaskId::from_bytes([7; 16]),
            AgentId::from_bytes([8; 16]),
            &rows,
            offer(),
            AT,
            3600,
        )
        .expect("decision");
        let events = vec![
            line("rotate.started", "allow", ids[0], 1),
            line("rotate.confirmed", "allow", ids[0], 2),
            line("rotate.started", "allow", ids[1], 3),
            line("rotate.cancelled", "allow", ids[1], 4),
            line("rotate.started", "allow", ids[2], 5),
            line("rotate.started", "deny", ids[3], 6),
            // A refused confirm changes nothing.
            line("rotate.confirmed", "deny", ids[2], 7),
        ];
        let states = site_states(&d, &events);
        let by = |id: ItemId| states.iter().find(|s| s.0 == id).expect("site");
        assert_eq!(by(ids[0]).1, SiteState::Changed);
        assert_eq!(by(ids[1]).1, SiteState::Failed);
        assert_eq!(
            (by(ids[2]).1, by(ids[2]).2, by(ids[2]).3),
            (SiteState::Pending, true, Some(5))
        );
        assert_eq!(by(ids[3]).1, SiteState::Failed);
        assert_eq!(
            (by(ids[4]).1, by(ids[4]).2, by(ids[4]).3),
            (SiteState::Pending, false, None)
        );
        // A new try after the change: in progress, then failed, and the
        // site stays changed.
        let mut again = events.clone();
        again.push(line("rotate.started", "allow", ids[0], 8));
        assert_eq!(site_states(&d, &again)[0].1, SiteState::Pending);
        again.push(line("rotate.cancelled", "allow", ids[0], 9));
        assert_eq!(site_states(&d, &again)[0].1, SiteState::Changed);

        // The person's own close (no outcome) counts; an agent's event
        // without one does not, even if the agent is called `you`.
        let mut by_person = line("rotate.confirmed", "", ids[4], 10);
        by_person.outcome = None;
        let mut named_you = by_person.clone();
        named_you.actor = "you".into();
        by_person.actor = "you".into();
        by_person.by_agent = false;
        assert_eq!(
            site_states(&d, &[named_you])
                .iter()
                .find(|s| s.0 == ids[4])
                .expect("site")
                .1,
            SiteState::Pending
        );
        assert_eq!(
            site_states(&d, &[by_person])
                .iter()
                .find(|s| s.0 == ids[4])
                .expect("site")
                .1,
            SiteState::Changed
        );
    }
}
