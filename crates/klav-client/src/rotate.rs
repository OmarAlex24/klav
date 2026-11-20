//! Assisted password changes (ADR 0022 §5), the person's half: what the
//! person's `klavd` checks before it generates, stores and fills a new
//! password for an agent, and the two ways a pending password ends.
//!
//! The agent starts a change with the server (`/v1/agent/rotations`, API
//! §8.6) and then hands `klavd` the request it signed. To confirm or
//! cancel it, it first asks `klavd` whether this change's password is
//! still pending here ([`Unlocked::rotation_pending`], read only), then
//! sends the step to the server, and hands `klavd` the same signed request
//! only once the server recorded it: a step the server refuses changes
//! nothing in the item, so the card and a retry still work. (An older
//! SDK hands `klavd` the step first; `klavd` takes both orders.) `klavd`
//! trusts neither the agent nor the server (ADR 0020 §9, step 3):
//!
//! * the agent's signature on that request, with the identity in the grant
//!   the account signed; the path and body name this item (and this change);
//!   the request is at most 5 minutes old and is used once;
//! * the task, fetched with the person's session: its decision is signed by
//!   the account, it is approved, live and not ended, it belongs to that
//!   agent, and it covers `rotate` on the item and on the host of the page;
//! * the page itself, as the browser reports it: the host the agent claimed,
//!   and one of the item's addresses (T61, T99).
//!
//! Only then does it write a new version of the item with the new password
//! as `pending` in its record (`0x16`), and only after that write succeeds
//! is anything typed into the page. The agent gets back field names and
//! the change's ID, never a value.

use klav_core::crypto::agent::{self, SignedRequest};
use klav_core::crypto::identity::PublicIdentity;
use klav_core::crypto::sign::{SIGNATURE_LEN, Signature};
use klav_core::generator::{self, GeneratorOptions, SiteHints};
use klav_core::ids::{AgentId, ItemId, RotationId, TaskId};
use klav_core::model::item::{FieldKind, FieldValue, ItemKind};
use klav_core::model::record::PendingValue;
use klav_core::model::{Item, SecretValue};
use klav_core::policy::{Permission, normalize_host};
use klav_core::site;
use klav_core::task::TaskDecision;
use klav_proto::agent::AgentStatus;
use klav_proto::rotate::{AgentRequestProof, AgentRotateFinish, AgentRotateStart, RotationInfo};
use klav_proto::task::TaskStatus;
use reqwest::Method;
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};

use crate::error::{ClientError, ClientResult};
use crate::ops::SecretText;
use crate::session::{ItemLocation, RecordEdit, Unlocked, now_ms};
use crate::tasks::verify_decision;

/// How old a signed agent request may be (the server's window, spec §13.3).
pub const PROOF_WINDOW_MS: i64 = 5 * 60 * 1000;
const NONCE_LEN: usize = 16;

/// One step of a change, as the agent hands it to `klavd`
/// (`agent_rotate_begin`, `agent_rotate_confirm`, `agent_rotate_cancel`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RotationStep {
    /// The agent.
    pub agent_id: AgentId,
    /// The task that covers the change.
    pub task_id: TaskId,
    /// The change (the server's `RotationInfo::id`, the agent's
    /// `pending_id`).
    pub rotation_id: RotationId,
    /// The item.
    pub item_id: ItemId,
    /// The request the agent signed for this step.
    pub request: AgentRequestProof,
}

/// A change whose checks passed, waiting for the page's rules. Not
/// `Debug`: it holds the current password.
pub struct RotationPlan {
    /// The item.
    pub loc: ItemLocation,
    /// Its title, for the person.
    pub title: String,
    /// Its addresses (metadata).
    pub urls: Vec<String>,
    /// The host of the change page, as the agent signed it.
    pub host: String,
    /// The password field the change replaces.
    pub field: String,
    /// The agent's name, for the in-page notice.
    pub agent_name: String,
    /// The agent's reason, for the in-page notice.
    pub reason: String,
    /// The task.
    pub task_id: TaskId,
    /// The change.
    pub rotation_id: RotationId,
    current: SecretText,
}

impl RotationPlan {
    /// The current password, to type into «current password».
    pub fn current(&self) -> &SecretText {
        &self.current
    }

    /// Checks the frame Klav is about to fill, by the address the browser
    /// gives: it must be on the host the agent signed and on one of the
    /// item's addresses (T61, T99).
    pub fn check_page(&self, url: &str) -> ClientResult<()> {
        let host = site::fillable_host(url).map_err(|e| ClientError::Denied(e.to_string()))?;
        if host != self.host {
            return Err(ClientError::Denied(format!(
                "the page is on {host}, not on {}: nothing was filled",
                self.host
            )));
        }
        // The page URL, not its host: an item address with a port covers
        // only that port.
        if !site::url_matches(url, &self.urls) {
            return Err(ClientError::Denied(format!(
                "{host} is not one of the addresses of {}: Klav does not fill it (phishing protection)",
                self.title
            )));
        }
        Ok(())
    }
}

/// What the page says about the new password (the field's
/// `passwordrules`, `minlength` and `maxlength`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct PageRules {
    /// `passwordrules`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password_rules: Option<String>,
    /// `minlength`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_length: Option<usize>,
    /// `maxlength`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_length: Option<usize>,
}

/// The name of the field an assisted change replaces: the first
/// non-empty `password` field of the login.
pub(crate) fn main_password_field(item: &Item) -> Option<String> {
    password_of(item).map(|(name, _)| name)
}

/// The first `password` field of a login, and its value.
fn password_of(item: &Item) -> Option<(String, SecretValue)> {
    item.fields()
        .iter()
        .find(|f| f.kind() == FieldKind::Password)
        .and_then(|f| match f.value() {
            FieldValue::Secret(v) if !v.expose().is_empty() => {
                Some((f.name().to_owned(), v.clone()))
            }
            _ => None,
        })
}

/// Ends the message of a task that does not cover the use.
const USE_SUFFIX: &str = " (not in what the person approved)";

fn denied(message: impl Into<String>) -> ClientError {
    ClientError::Denied(message.into())
}

/// What to tell the person when their choice on the card (`accept`) is not
/// what the agent already recorded for the change, by the server's `409`
/// («the password change is already confirmed», or «cancelled»). No value.
fn disagreement(accept: bool, message: &str) -> Option<String> {
    if !accept && message.contains("already confirmed") {
        Some(
            "You kept the current password, but the change was already recorded as confirmed: the site took the new one, as the agent reported (the log says confirmed). The new password is in this item's history, marked generated, not confirmed: if the current one no longer signs you in, use that one.".into(),
        )
    } else if accept && message.contains("already cancelled") {
        Some(
            "You chose the new password, but the change was already recorded as cancelled: the site refused it, as the agent reported (the log says cancelled). The previous password is in this item's history: if the new one does not sign you in, use that one.".into(),
        )
    } else {
        None
    }
}

impl Unlocked {
    /// The identity of `agent`, from the grant the account signed for it
    /// (the server cannot swap it). Only an active agent.
    async fn verified_agent(&mut self, agent: AgentId) -> ClientResult<PublicIdentity> {
        let info = self.agent_info(agent).await?;
        if info.status != AgentStatus::Active {
            return Err(denied(format!("agent {agent} is not active")));
        }
        let public = PublicIdentity::decode(info.public_identity.as_bytes())?;
        let grant = info
            .grant
            .as_ref()
            .ok_or_else(|| denied(format!("agent {agent} has no grant")))?;
        self.open_grant(agent, &public, grant)?;
        Ok(public)
    }

    /// Checks the agent's signed request for one step: method, path, age,
    /// signature, and that it was not used before. Returns its body.
    pub(crate) async fn check_proof<'a>(
        &mut self,
        agent: AgentId,
        proof: &'a AgentRequestProof,
        path: &str,
    ) -> ClientResult<&'a [u8]> {
        if proof.method != "POST" || proof.path != path {
            return Err(denied(format!(
                "the agent's request is not POST {path}: it does not prove this step"
            )));
        }
        let now = now_ms();
        let at = i64::try_from(proof.timestamp_ms).unwrap_or(i64::MAX);
        if (now - at).abs() > PROOF_WINDOW_MS {
            return Err(denied(
                "the agent's request is older than 5 minutes (or its clock is off)",
            ));
        }
        let nonce: [u8; NONCE_LEN] = proof
            .nonce
            .as_bytes()
            .try_into()
            .map_err(|_| ClientError::Invalid("the agent's request: nonce".into()))?;
        let signature: [u8; SIGNATURE_LEN] = proof
            .signature
            .as_bytes()
            .try_into()
            .map_err(|_| ClientError::Invalid("the agent's request: signature".into()))?;
        let public = self.verified_agent(agent).await?;
        agent::verify_request(
            &public,
            &SignedRequest {
                agent,
                method: &proof.method,
                path: &proof.path,
                timestamp_ms: proof.timestamp_ms,
                nonce: &nonce,
                body_digest: &agent::body_digest(proof.body.as_bytes()),
            },
            &Signature::from_bytes(signature),
        )
        .map_err(|_| {
            ClientError::Security(format!(
                "the request is not signed by agent {agent}: nothing was done"
            ))
        })?;
        // Once: a same-user process replaying the agent's request gets
        // nothing more than the agent already got.
        // Per agent: one agent's nonce never blocks another's request.
        self.seen_proofs
            .retain(|(_, _, t)| now - t <= 2 * PROOF_WINDOW_MS);
        if self
            .seen_proofs
            .iter()
            .any(|(a, n, _)| *a == agent && *n == nonce)
        {
            return Err(denied("this signed request was already used"));
        }
        self.seen_proofs.push((agent, nonce, now));
        Ok(proof.body.as_bytes())
    }

    /// The task, as the person's account signed it: approved, live, not
    /// ended, of `agent`, with `rotate` on `loc` (and on `host`, if given).
    async fn rotate_task(
        &mut self,
        task: TaskId,
        agent: AgentId,
        loc: ItemLocation,
        host: Option<&str>,
    ) -> ClientResult<(String, TaskDecision)> {
        self.task_using(task, agent, loc, Permission::Rotate, host)
            .await
            .map_err(|e| match e {
                ClientError::Denied(m) if m.ends_with(USE_SUFFIX) => denied(format!(
                    "task {task} does not let this agent change this password{}",
                    host.map(|h| format!(" on {h}")).unwrap_or_default()
                )),
                e => e,
            })
    }

    /// The task, as the person's account signed it: approved, live, not
    /// ended, of `agent`, with `permission` on `loc` (and on `host`, if
    /// given). The agent's name comes with it.
    pub(crate) async fn task_using(
        &mut self,
        task: TaskId,
        agent: AgentId,
        loc: ItemLocation,
        permission: Permission,
        host: Option<&str>,
    ) -> ClientResult<(String, TaskDecision)> {
        let info = self.task_info(task).await?;
        let decision = verify_decision(self.identity.public(), &info)?
            .ok_or_else(|| denied(format!("task {task} is not decided")))?;
        let now = now_ms();
        if info.status != TaskStatus::Approved
            || info.ended_at.is_some()
            || info.expires_at.is_none_or(|e| e <= now)
            || i64::try_from(decision.expires_at_ms).unwrap_or(0) <= now
        {
            return Err(denied(format!("task {task} is not running")));
        }
        if info.agent_id != agent || decision.agent_id != agent {
            return Err(denied(format!("task {task} belongs to another agent")));
        }
        let covered = match host {
            Some(host) => decision.covers(loc.vault, loc.project, loc.item, permission, Some(host)),
            None => decision.access_for(loc.item).is_some_and(|a| {
                a.vault_id == loc.vault
                    && a.project_id == loc.project
                    && a.permissions.contains(&permission)
            }),
        };
        if !covered {
            return Err(denied(format!(
                "task {task} does not give this agent `{}` on this item{}{USE_SUFFIX}",
                permission.as_str(),
                host.map(|h| format!(" on {h}")).unwrap_or_default()
            )));
        }
        Ok((info.agent_name, decision))
    }

    /// Checks `agent_rotate_begin` (ADR 0022 §5, step 2): the agent's
    /// signed `POST /v1/agent/rotations` for this item, its task, and the
    /// item (a login with a password and the claimed host among its
    /// addresses). Nothing is written yet.
    ///
    /// Refused while the item holds the pending password of another change
    /// under the same task: the server may already have that one recorded
    /// as confirmed, and a new pending password would move it to the
    /// history, unconfirmed. This runs after the server recorded the new
    /// start, so the agent's runtime cancels that change at once. A pending
    /// password left by another task (ended, or an older client's) is
    /// replaced as before.
    pub async fn rotation_begin(&mut self, step: &RotationStep) -> ClientResult<RotationPlan> {
        let body = self
            .check_proof(step.agent_id, &step.request, "/v1/agent/rotations")
            .await?;
        let start: AgentRotateStart = serde_json::from_slice(body)
            .map_err(|_| ClientError::Invalid("the agent's request: body".into()))?;
        if start.item_id != step.item_id || start.task_id.is_some_and(|t| t != step.task_id) {
            return Err(denied(
                "the agent's request names another item or task: it does not prove this change",
            ));
        }
        let host = start
            .claims
            .domain
            .as_deref()
            .and_then(normalize_host)
            .ok_or_else(|| ClientError::Invalid("the agent's request has no host".into()))?;
        let loc = self.find_item(&step.item_id.to_string())?;
        let summary = self.item_summary(loc)?;
        if summary.kind != ItemKind::Login {
            return Err(ClientError::Invalid(
                "only a login's password can be changed".into(),
            ));
        }
        // Only the sites the person confirmed (ADR 0030 §7).
        if !site::host_matches(&host, &summary.confirmed_urls) {
            return Err(denied(format!(
                "{host} is not one of the addresses of {}: Klav does not change it there",
                summary.title
            )));
        }
        let (agent_name, _) = self
            .rotate_task(step.task_id, step.agent_id, loc, Some(&host))
            .await?;
        let item = self.open_item(loc)?;
        let task = step.task_id.to_string();
        if let Some(other) = self.pending_of(loc, &item).and_then(|p| {
            (p.task_id.as_deref() == Some(task.as_str())
                && p.rotation_id.as_deref() != Some(step.rotation_id.to_string().as_str()))
            .then_some(p.rotation_id)
        }) {
            let other = other.unwrap_or_else(|| "?".to_owned());
            return Err(ClientError::Invalid(format!(
                "{} still holds the new password of change {other} as pending, under this same task: finish that change first (rotate_confirm or rotate_cancel with pending_id {other}), or ask the person, who decides from the item's card",
                summary.title
            )));
        }
        let (field, current) = password_of(&item).ok_or_else(|| {
            ClientError::Invalid(format!("{} has no password to change", summary.title))
        })?;
        Ok(RotationPlan {
            loc,
            title: summary.title,
            urls: summary.confirmed_urls,
            host,
            field,
            agent_name,
            reason: start
                .reason
                .chars()
                .filter(|c| !c.is_control())
                .take(500)
                .collect(),
            task_id: step.task_id,
            rotation_id: step.rotation_id,
            current: SecretText::from(&current),
        })
    }

    /// Generates the new password with the page's rules (else Klav's
    /// bundled ones for the host) and stores it as pending in a new version
    /// of the item (step 4). Returns it only once the server has that
    /// version: if this fails, nothing may be typed into the page.
    pub async fn rotation_store_pending(
        &mut self,
        plan: &RotationPlan,
        rules: &PageRules,
    ) -> ClientResult<SecretText> {
        let item = self.open_item(plan.loc)?;
        // The item may have changed while the page was asked for its rules.
        if password_of(&item)
            .is_none_or(|(f, v)| f != plan.field || v.expose() != plan.current.expose())
        {
            return Err(ClientError::Invalid(format!(
                "the password of {} changed meanwhile: start the change again",
                plan.title
            )));
        }
        let generated = generator::generate(
            &GeneratorOptions::default(),
            &SiteHints {
                host: Some(plan.host.clone()),
                password_rules: rules.password_rules.clone(),
                min_length: rules.min_length,
                max_length: rules.max_length,
            },
        )
        .map_err(|e| ClientError::Invalid(format!("generator: {e}")))?;
        let new = SecretText::new(generated.value.expose_secret());
        drop(generated);
        let pending = PendingValue {
            field: plan.field.clone(),
            value: SecretValue::new(new.expose()),
            created_at_ms: now_ms(),
            task_id: Some(plan.task_id.to_string()),
            rotation_id: Some(plan.rotation_id.to_string()),
        };
        self.put_item_with(plan.loc, &item, &[], Some(RecordEdit::Begin(pending)))
            .await?;
        // The version is on the server; a failed sync after it only delays
        // the local copy.
        if let Err(e) = self.sync().await {
            self.push_warning(format!(
                "could not sync after storing the pending password ({e})"
            ));
        }
        Ok(new)
    }

    /// `agent_rotate_confirm` and `agent_rotate_cancel` (step 7): checks the
    /// agent's signed `POST /v1/agent/rotations/{id}/confirm` (or
    /// `/cancel`) and its task, and that the item's pending password is this
    /// change's, generated under this task. Confirming makes it current
    /// (the old one goes to the history with its end date); cancelling
    /// keeps the current one and moves the pending one to the history,
    /// unconfirmed.
    pub async fn rotation_finish(
        &mut self,
        step: &RotationStep,
        confirm: bool,
    ) -> ClientResult<()> {
        let path = format!(
            "/v1/agent/rotations/{}/{}",
            step.rotation_id,
            if confirm { "confirm" } else { "cancel" }
        );
        let body = self
            .check_proof(step.agent_id, &step.request, &path)
            .await?;
        let finish: AgentRotateFinish = serde_json::from_slice(body)
            .map_err(|_| ClientError::Invalid("the agent's request: body".into()))?;
        if finish.item_id != step.item_id {
            return Err(denied(
                "the agent's request names another item: it does not prove this change",
            ));
        }
        let loc = self.find_item(&step.item_id.to_string())?;
        self.rotate_task(step.task_id, step.agent_id, loc, None)
            .await?;
        self.settle(loc, confirm, Some((step.rotation_id, step.task_id)))
            .await
    }

    /// `agent_rotate_pending`: whether the item's pending password is this
    /// change's, checked before the agent sends a confirm or a cancel to
    /// the server. Takes the agent's signed `POST
    /// /v1/agent/rotations/{id}/pending`, a path the server has no route
    /// for, so the request proves no step to it; checked as for a step
    /// (signature, age, once, the task). Changes nothing.
    ///
    /// `false` means the change was settled here already (by the person
    /// from the item's card, or by an older client that applied the step
    /// before the server refused it) or its password was never stored: the
    /// record does not say which, so the agent records nothing.
    pub async fn rotation_pending(&mut self, step: &RotationStep) -> ClientResult<bool> {
        let path = format!("/v1/agent/rotations/{}/pending", step.rotation_id);
        let body = self
            .check_proof(step.agent_id, &step.request, &path)
            .await?;
        let finish: AgentRotateFinish = serde_json::from_slice(body)
            .map_err(|_| ClientError::Invalid("the agent's request: body".into()))?;
        if finish.item_id != step.item_id {
            return Err(denied(
                "the agent's request names another item: it does not prove this change",
            ));
        }
        let loc = self.find_item(&step.item_id.to_string())?;
        self.rotate_task(step.task_id, step.agent_id, loc, None)
            .await?;
        let item = self.open_item(loc)?;
        let id = step.rotation_id.to_string();
        Ok(self
            .pending_of(loc, &item)
            .is_some_and(|p| p.rotation_id.as_deref() == Some(id.as_str())))
    }

    /// The person decides on a pending password from the item's card
    /// («Use the new one» or «Keep the current one», ADR 0022 §5). Then,
    /// if an agent's change left it, closes that change with the server
    /// under the person, so the agent's later step logs nothing false.
    /// The item is the truth: a server that cannot be reached is a
    /// warning. Returns the warnings for the person: that one, or that the
    /// log already holds the agent's other outcome. They are returned, not
    /// kept in the session, whose warnings the sync after the decision
    /// replaces.
    pub async fn resolve_pending(
        &mut self,
        loc: ItemLocation,
        accept: bool,
    ) -> ClientResult<Vec<String>> {
        let item = self.open_item(loc)?;
        let rotation = self
            .pending_of(loc, &item)
            .and_then(|p| p.rotation_id)
            .and_then(|id| id.parse::<RotationId>().ok());
        self.settle(loc, accept, None).await?;
        let Some(id) = rotation else {
            return Ok(Vec::new());
        };
        let step = if accept { "confirm" } else { "cancel" };
        let closed: ClientResult<RotationInfo> = self
            .send_json(
                Method::POST,
                &format!("/v1/rotations/{id}/{step}"),
                &serde_json::json!({}),
            )
            .await;
        Ok(match closed {
            Ok(_) => Vec::new(),
            // The agent closed it first (or its task ended): nothing to
            // record. If the agent recorded the other outcome, the item and
            // the log now disagree: say so, and where each password is.
            Err(ClientError::Api {
                status: 409,
                message,
                ..
            }) => disagreement(accept, &message).into_iter().collect(),
            Err(e) => vec![format!(
                "the agent's change {id} stays open with the server ({e}). The item has nothing pending now, so this Klav's rotate_confirm and rotate_cancel record nothing for it (an older agent's cancel, or the cancel an agent makes on its own after a fill that failed, still can); until something closes it, new changes of this item wait until the agent's task ends"
            )],
        })
    }

    async fn settle(
        &mut self,
        loc: ItemLocation,
        accept: bool,
        rotation: Option<(RotationId, TaskId)>,
    ) -> ClientResult<()> {
        let item = self.open_item(loc)?;
        let record = self.record_of(loc, &item)?;
        let pending = record.pending().ok_or_else(|| {
            ClientError::NotFound(format!("a pending password in {}", item.title()))
        })?;
        if let Some((id, task)) = rotation {
            if pending.rotation_id.as_deref() != Some(id.to_string().as_str()) {
                return Err(ClientError::NotFound(format!(
                    "the pending password of change {id} in {} (the person may have decided already)",
                    item.title()
                )));
            }
            if pending
                .task_id
                .as_deref()
                .is_some_and(|t| t != task.to_string())
            {
                return Err(denied(
                    "the pending password was generated under another task: this request does not prove its change",
                ));
            }
        }
        let (new, edit) = if accept {
            let mut new = item.clone();
            new.field_mut(&pending.field)
                .ok_or_else(|| ClientError::NotFound(format!("field {:?}", pending.field)))?
                .set_value(pending.value.expose())?;
            (new, RecordEdit::Confirm)
        } else {
            (item.clone(), RecordEdit::Cancel)
        };
        drop(record);
        self.put_item_with(loc, &new, &[], Some(edit)).await?;
        if let Err(e) = self.sync().await {
            self.push_warning(format!("could not sync after the change ({e})"));
        }
        Ok(())
    }

    /// The pending password of a login, if it has one (for the page menu,
    /// which offers it next to the current one while nobody decided).
    pub(crate) fn pending_of(&self, loc: ItemLocation, item: &Item) -> Option<PendingValue> {
        self.record_of(loc, item)
            .ok()
            .and_then(|r| r.pending().cloned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan(urls: &[&str], host: &str) -> RotationPlan {
        RotationPlan {
            loc: ItemLocation {
                vault: klav_core::ids::VaultId::generate(),
                project: klav_core::ids::ProjectId::generate(),
                item: ItemId::generate(),
            },
            title: "Bank".into(),
            urls: urls.iter().map(|u| (*u).to_owned()).collect(),
            host: host.into(),
            field: "password".into(),
            agent_name: "bot".into(),
            reason: "rotate".into(),
            task_id: TaskId::generate(),
            rotation_id: RotationId::generate(),
            current: SecretText::new("old"),
        }
    }

    #[test]
    fn a_card_choice_against_what_the_agent_recorded_is_told() {
        let confirmed = "the password change is already confirmed";
        let cancelled = "the password change is already cancelled";
        assert!(
            disagreement(false, confirmed)
                .unwrap()
                .contains("log says confirmed")
        );
        assert!(
            disagreement(true, cancelled)
                .unwrap()
                .contains("log says cancelled")
        );
        // The same outcome, or a change that ended with its task: nothing.
        assert!(disagreement(true, confirmed).is_none());
        assert!(disagreement(false, cancelled).is_none());
        assert!(disagreement(false, "the password change is already abandoned").is_none());
    }

    #[test]
    fn the_page_must_be_the_signed_host_and_the_items_site() {
        let p = plan(&["https://bank.example/login"], "bank.example");
        assert!(
            p.check_page("https://bank.example/settings/password")
                .is_ok()
        );
        // Another host than the one the agent signed, even of the same site.
        assert!(matches!(
            p.check_page("https://www.bank.example/password"),
            Err(ClientError::Denied(_))
        ));
        // A look-alike.
        assert!(p.check_page("https://bank.example.evil.io/").is_err());
        // Plain http on a remote host is never filled.
        assert!(p.check_page("http://bank.example/").is_err());
        // The signed host is not one of the item's addresses.
        let q = plan(&["https://other.example"], "bank.example");
        assert!(q.check_page("https://bank.example/").is_err());
        // An address with a port covers that port only.
        let r = plan(&["https://bank.example:8443/login"], "bank.example");
        assert!(r.check_page("https://bank.example:8443/password").is_ok());
        assert!(r.check_page("https://bank.example/password").is_err());
        assert!(r.check_page("https://bank.example:9443/password").is_err());
    }
}
