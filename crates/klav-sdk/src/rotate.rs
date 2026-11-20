//! Assisted password changes (ADR 0022 §5), the agent's half: the agent
//! asks the server for each step and hands the request it signed to the
//! person's `klavd`, which generates the new password, stores it as pending
//! in the item and fills the change form. The agent never sees the current
//! password nor the new one: it gets the field names it filled and the
//! change's ID (`pending_id`), or `ok`.
//!
//! * [`Session::change_password_url`]: the site's change-password page
//!   (bundled, or `/.well-known/change-password`), with `list`.
//! * [`Session::rotate_password`]: `POST /v1/agent/rotations`, then
//!   `agent_rotate_begin` in `klavd`. Only the `extension` target: with
//!   `sdk:` the new value would go through the agent's runtime.
//! * [`Session::rotate_confirm`] and [`Session::rotate_cancel`]: `klavd`
//!   is asked first whether this change's password is still pending in the
//!   item (`agent_rotate_pending`, read only); then the server records the
//!   step, and only then does `klavd` apply it, with the same signed
//!   request. A step the server refuses (a pause, a revocation, a deletion
//!   request, a stale signature) changes nothing in the item, so the card
//!   and a retry still work. A change `klavd` holds no pending password
//!   for gets nothing recorded by this call: it was settled here already,
//!   or never stored, and the record does not say which.
//!
//! `rotate` only exists inside a task (ADR 0021 §5): no grant holds it, so
//! these never go through the grant's policy or approvals. The task is the
//! one the caller named, or the only running one that covers `rotate` on
//! the item and the page's host; the server and `klavd` check it again.

use klav_client::rotate::RotationStep;
use klav_client::{ClientError, ClientResult};
use klav_core::generator::change_password::{self, ChangePasswordUrl};
use klav_core::ids::{ItemId, RotationId, TaskId};
use klav_core::policy::{Effect, Permission};
use klav_daemon::client::DaemonClient;
use klav_daemon::protocol::{self, ErrorCode, Request};
use klav_proto::agent::Claims;
use klav_proto::rotate::{AgentRotateFinish, AgentRotateStart, RotationInfo, RotationStarted};
use serde::{Deserialize, Serialize};

use crate::browser::{Target, daemon_error, fillable_host, url_matches};
use crate::session::Session;

/// What [`Session::rotate_password`] answers, and all the agent learns:
/// the fields `klavd` filled and the change's ID. No value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotateReport {
    /// Field names, as `klavd` filled them (`new_password`,
    /// `confirm_password`, `current_password`).
    pub filled: Vec<String>,
    /// The change, for [`Session::rotate_confirm`] or
    /// [`Session::rotate_cancel`].
    pub pending_id: RotationId,
}

/// Why `target` cannot carry a password change, if it cannot.
pub fn refuse_target(target: &str) -> Option<String> {
    let target = target.trim();
    (target != "extension").then(|| {
        if target.starts_with("sdk:") {
            format!(
                "{target:?}: a password change only goes to the person's browser (target \"extension\"), never to a browser of your runtime: there the new password would pass through you (ADR 0022 §5)"
            )
        } else {
            format!("unknown target {target:?}: a password change only takes \"extension\"")
        }
    })
}

fn klavd_home(target: &Target) -> ClientResult<&klav_client::Home> {
    match target {
        Target::Extension { home } => Ok(home),
        Target::Cdp(_) => Err(ClientError::Denied(
            "a password change only goes to the person's browser (target \"extension\"), never to a browser of your runtime".into(),
        )),
    }
}

async fn connect(home: &klav_client::Home) -> ClientResult<DaemonClient> {
    DaemonClient::connect(home).await.ok_or_else(|| {
        ClientError::NotFound(
            "klavd, with the person's browser attached (open the browser with Klav's extension)"
                .into(),
        )
    })
}

/// What `klavd` says about a change before the server gets its step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Here {
    /// The item's pending password is this change's.
    Pending,
    /// It is not: settled here already (from the item's card, or by an
    /// older client), or never stored.
    NotPending,
    /// An older `klavd`, without `agent_rotate_pending`.
    Unknown,
}

/// How a step that did not finish ended ([`Session::finish`]).
enum Unfinished {
    /// The server has no record of it from this call, and the change stays
    /// open there: refused, or stopped before it (`klavd`'s question
    /// failed or said «not pending»).
    NotRecorded(ClientError),
    /// The server already has the change closed (its `409` names the other
    /// outcome, or it answered for another item): this step was not
    /// recorded, and `klavd` was not asked.
    Closed(ClientError),
    /// No answer the SDK could read (a transport failure, or a reply too
    /// large or not JSON): the server may or may not have recorded it.
    Unanswered(ClientError),
    /// The server recorded it (or an earlier call had), and `klavd` did
    /// not say it applied it.
    Recorded(ClientError),
}

impl Unfinished {
    fn into_error(self) -> ClientError {
        match self {
            Self::NotRecorded(e) | Self::Closed(e) | Self::Unanswered(e) | Self::Recorded(e) => e,
        }
    }
}

/// What ending a task costs the agent, said wherever ending one is advice.
const END_TASK_COST: &str = "ending the task also ends its other sites, and going on with them needs a new task from the person: finish the other sites first, or ask the person";

/// `e` with `note` after its message, of the same kind (a pause or a
/// deletion request carries no message, and stays as it is).
fn noted(e: ClientError, note: &str) -> ClientError {
    match e {
        ClientError::Denied(m) => ClientError::Denied(format!("{m}. {note}")),
        ClientError::NotFound(m) => ClientError::NotFound(format!("{m}. {note}")),
        ClientError::Invalid(m) => ClientError::Invalid(format!("{m}. {note}")),
        ClientError::Security(m) => ClientError::Security(format!("{m}. {note}")),
        ClientError::Network(m) => ClientError::Network(format!("{m}. {note}")),
        other => other,
    }
}

/// Whether the server has the change closed after the automatic cancel
/// ([`Session::close_failed`]): by it, or already before it.
fn closed_with_server(closed: &Result<(), Unfinished>) -> bool {
    matches!(closed, Ok(()) | Err(Unfinished::Closed(_)))
}

/// Cuts `klavd`'s hint to cancel a change whose pending password it kept
/// ([`protocol::ROTATE_KEPT_PENDING`]): said once the server has the change
/// closed ([`closed_with_server`]).
fn cut_kept_pending(e: &mut protocol::ErrorBody) {
    if let Some(at) = e.message.find(protocol::ROTATE_KEPT_PENDING) {
        e.message.truncate(at);
    }
}

/// What the agent is told about the automatic cancel of a change `klavd`
/// did not fill ([`Session::close_failed`]).
fn close_note(rotation: RotationId, closed: &Result<(), Unfinished>) -> String {
    match closed {
        Ok(()) => format!("this change ({rotation}) was cancelled"),
        // The wrapped error says whether the item still holds the password.
        Err(Unfinished::Recorded(e)) => {
            format!("the server cancelled this change ({rotation}), and then: {e}")
        }
        Err(Unfinished::Closed(e)) => format!(
            "the server already has this change ({rotation}) closed, so there is nothing left to cancel ({e})"
        ),
        Err(Unfinished::Unanswered(e)) => format!(
            "the cancel of this change may not have reached the server ({e}). If it did not, the change is still open there (pending_id {rotation}): call rotate_cancel with that pending_id. If that answers that klavd holds no pending password, new changes of this item are refused as «already in progress» until this task ends: ending it (end_task) frees the item, but {END_TASK_COST}"
        ),
        Err(Unfinished::NotRecorded(e)) => format!(
            "this change could not be cancelled ({e}), so it stays open with the server (pending_id {rotation}). Call rotate_cancel with that pending_id; if it answers that klavd holds no pending password, new changes of this item are refused as «already in progress» until this task ends: ending it (end_task) frees the item, but {END_TASK_COST}"
        ),
    }
}

/// `agent_rotate_pending`'s answer.
#[derive(Deserialize)]
struct PendingHere {
    pending: bool,
}

/// The outcome a step records, as the server's `409` names it.
fn outcome(confirm: bool) -> &'static str {
    if confirm { "confirmed" } else { "cancelled" }
}

/// The step's name, for the agent.
fn step_name(confirm: bool) -> &'static str {
    if confirm { "confirm" } else { "cancel" }
}

/// The path the question to `klavd` is signed for. The server has no
/// route there, so the request proves nothing to it: only a confirm or a
/// cancel path records a step.
fn pending_path(rotation: RotationId) -> String {
    format!("/v1/agent/rotations/{rotation}/pending")
}

impl Session {
    /// The change-password page of `item`'s site: Klav's bundled one, or
    /// `https://<host>/.well-known/change-password`, on the item's own
    /// port if its URL has one (ADR 0022 §1.3).
    /// Needs `list` on the item, like its other metadata.
    pub fn change_password_url(&self, item: ItemId) -> ClientResult<ChangePasswordUrl> {
        if self.evaluate(item, Permission::List, None).effect != Effect::Allow {
            return Err(ClientError::Denied(
                "the agent's grant does not let it see this item".into(),
            ));
        }
        let info = self.item_info(item)?;
        change_password::for_item(&info.urls).ok_or_else(|| {
            ClientError::Invalid(format!(
                "{} has no address: Klav does not know its site (ask the person for the change page)",
                info.reference
            ))
        })
    }

    /// The task that covers `rotate` on `item` at `host`: the one named
    /// with [`Session::use_task`], or the only running one that covers it.
    fn rotate_task(&self, item: ItemId, host: &str) -> ClientResult<TaskId> {
        if let Some(task) = self.task {
            return Ok(task);
        }
        let entry = self
            .items
            .get(&item)
            .ok_or_else(|| ClientError::NotFound(format!("item {item}")))?;
        let now = crate::agent::now_ms();
        let covering: Vec<TaskId> = self
            .tasks
            .iter()
            .filter(|t| {
                t.expires_at > now
                    && t.decision.covers(
                        entry.vault,
                        entry.project,
                        item,
                        Permission::Rotate,
                        Some(host),
                    )
            })
            .map(|t| t.id)
            .collect();
        match covering.as_slice() {
            [one] => Ok(*one),
            [] => Err(ClientError::Denied(format!(
                "no running task covers `rotate` on this item at {host}. rotate only exists inside a task: use the one the person offered you (list_tasks), or ask for one with request_task and permissions [\"rotate\"]"
            ))),
            _ => Err(ClientError::Invalid(format!(
                "several running tasks cover `rotate` on this item at {host}: pass task_id"
            ))),
        }
    }

    /// The task of a confirm or cancel: the one named with
    /// [`Session::use_task`], or the only running one with `rotate` on
    /// `item` (on any host: the change already passed the host check).
    /// `klavd` checks that the pending password was generated under it.
    fn finish_task(&self, item: ItemId) -> ClientResult<TaskId> {
        if let Some(task) = self.task {
            return Ok(task);
        }
        let now = crate::agent::now_ms();
        let covering: Vec<TaskId> = self
            .tasks
            .iter()
            .filter(|t| {
                t.expires_at > now
                    && t.decision
                        .access_for(item)
                        .is_some_and(|a| a.permissions.contains(&Permission::Rotate))
            })
            .map(|t| t.id)
            .collect();
        match covering.as_slice() {
            [one] => Ok(*one),
            [] => Err(ClientError::Denied(
                "no running task covers `rotate` on this item: the change's task ended (the person can still decide from the item's card)".into(),
            )),
            _ => Err(ClientError::Invalid(
                "several running tasks cover `rotate` on this item: pass task_id".into(),
            )),
        }
    }

    /// Starts changing `item`'s password in the active tab of the person's
    /// browser (ADR 0022 §5, steps 2–5). Checks the tab against the item's
    /// addresses, starts the change with the server and hands the signed
    /// request to `klavd`, which verifies it and the task, generates the
    /// new password with the page's rules, stores it as pending and fills.
    ///
    /// If `klavd` fills nothing and `submit` is off, the change is cancelled
    /// at once, so the item is free for another try. With `submit`, the
    /// same if `klavd` holds no pending password for it (nothing was
    /// typed); otherwise the page may have taken it, and the change stays
    /// open for [`Self::rotate_confirm`] or [`Self::rotate_cancel`]. The
    /// error says whether that cancel went through.
    pub async fn rotate_password(
        &mut self,
        target: &Target,
        item: ItemId,
        reason: &str,
        submit: bool,
    ) -> ClientResult<RotateReport> {
        let home = klavd_home(target)?;
        let info = self.item_info(item)?;
        let mut daemon = connect(home).await?;
        let (tab, _): (protocol::BrowserTab, _) = daemon
            .call(Request::BrowserTab)
            .await
            .map_err(daemon_error)?;
        let host = fillable_host(&tab.url)?;
        // The tab's origin, port included: an item address with a port
        // covers only that port.
        if !url_matches(&tab.url, &info.urls) {
            return Err(ClientError::Denied(format!(
                "the active tab is on {host}, which is not one of the item's addresses ({}): Klav does not change a password there (phishing protection). Open the change page of the item's site (change_password_url)",
                if info.urls.is_empty() {
                    "it has none".to_owned()
                } else {
                    info.urls.join(", ")
                }
            )));
        }
        let task = self.rotate_task(item, &host)?;
        let (started, request): (RotationStarted, _) = self
            .agent
            .call_proved(
                "/v1/agent/rotations",
                &AgentRotateStart {
                    item_id: item,
                    reason: reason.trim().to_owned(),
                    claims: Claims {
                        tags: Vec::new(),
                        domain: Some(host.clone()),
                        ..Claims::default()
                    },
                    task_id: Some(task),
                },
            )
            .await?;
        let rotation = started.rotation;
        let step = RotationStep {
            agent_id: self.agent.id(),
            task_id: rotation.task_id,
            rotation_id: rotation.id,
            item_id: item,
            request,
        };
        match daemon
            .call::<RotateReport>(Request::AgentRotateBegin {
                tab: tab.tab,
                step,
                submit,
            })
            .await
        {
            Ok((report, _)) => Ok(report),
            Err(mut e) if submit => {
                // `klavd` types nothing before the pending password is
                // stored: if it holds none for this change, nothing reached
                // the page, and the change is closed now (a cancel later
                // could not tell it from one settled here).
                let here = self
                    .pending_here(&mut daemon, item, rotation.id, rotation.task_id)
                    .await;
                if matches!(here, Ok(Here::NotPending)) {
                    let closed = self
                        .close_failed(target, rotation.id, rotation.task_id, item)
                        .await;
                    if closed_with_server(&closed) {
                        cut_kept_pending(&mut e);
                    }
                    return Err(noted(
                        daemon_error(e),
                        &format!(
                            "klavd stored no new password for this change, so nothing was typed: {}",
                            close_note(rotation.id, &closed)
                        ),
                    ));
                }
                Err(ClientError::Invalid(format!(
                    "{}. The change stays open (pending_id {}): if the site took a new password, call rotate_confirm; if not, rotate_cancel",
                    daemon_error(e),
                    rotation.id
                )))
            }
            Err(mut e) => {
                let closed = self
                    .close_failed(target, rotation.id, rotation.task_id, item)
                    .await;
                // The hint to cancel is no longer true once the server has
                // the change closed.
                if closed_with_server(&closed) {
                    cut_kept_pending(&mut e);
                }
                Err(noted(daemon_error(e), &close_note(rotation.id, &closed)))
            }
        }
    }

    /// Cancels a change `klavd` did not fill: with the server, and in
    /// `klavd` in case it stored the pending password before failing (it
    /// goes to the history, unconfirmed). Under the change's own task
    /// (`task`), not one looked up again. The caller reports the original
    /// error, with [`close_note`] saying how far this got.
    async fn close_failed(
        &self,
        target: &Target,
        rotation: RotationId,
        task: TaskId,
        item: ItemId,
    ) -> Result<(), Unfinished> {
        self.finish_steps(
            target,
            item,
            rotation,
            "klavd did not fill the change form",
            false,
            Some(task),
        )
        .await
    }

    /// Asks `klavd` whether `item`'s pending password is `rotation`'s
    /// (`agent_rotate_pending`), with a signed request of its own, on a
    /// path the server has no route for ([`pending_path`]). An older
    /// `klavd` does not know the question.
    async fn pending_here(
        &self,
        daemon: &mut DaemonClient,
        item: ItemId,
        rotation: RotationId,
        task: TaskId,
    ) -> ClientResult<Here> {
        let request = self.agent.sign_post(
            &pending_path(rotation),
            &AgentRotateFinish {
                item_id: item,
                reason: "is this change pending here?".into(),
            },
        )?;
        let step = RotationStep {
            agent_id: self.agent.id(),
            task_id: task,
            rotation_id: rotation,
            item_id: item,
            request,
        };
        match daemon
            .call::<PendingHere>(Request::AgentRotatePending { step })
            .await
        {
            Ok((here, _)) if here.pending => Ok(Here::Pending),
            Ok(_) => Ok(Here::NotPending),
            Err(e) if e.code == ErrorCode::BadRequest => Ok(Here::Unknown),
            Err(e) => Err(daemon_error(e)),
        }
    }

    /// Confirms or cancels a change (ADR 0022 §5, step 7), in three calls:
    ///
    /// 1. `klavd`: is this change's password still pending in the item? If
    ///    not, nothing is recorded: the change was settled here (by the
    ///    person from the item's card, or by an older client), or its
    ///    password was never stored. `unstored` lets a cancel through all
    ///    the same, for a change `klavd` just failed to fill
    ///    ([`Self::close_failed`]). An older `klavd` cannot say.
    /// 2. The server records the step, or already did: its `409` for this
    ///    same outcome means an earlier call recorded it and `klavd` did
    ///    not apply it then. Any other refusal changes nothing in the item;
    ///    the log may keep the step's event without its row's update (a
    ///    revocation between the two, or a `409` for a change closed
    ///    meanwhile), as for any agent write refused after its event.
    /// 3. `klavd` applies it, with the same signed request.
    ///
    /// Wherever the item and the log may end up disagreeing, the error
    /// says which one says what. It never holds a password.
    async fn finish(
        &self,
        target: &Target,
        item: ItemId,
        rotation: RotationId,
        reason: &str,
        confirm: bool,
    ) -> ClientResult<()> {
        self.finish_steps(target, item, rotation, reason, confirm, None)
            .await
            .map_err(Unfinished::into_error)
    }

    /// [`Self::finish`], saying whether the server recorded the step.
    /// `unstored` is the task of a change `klavd` just failed to fill
    /// ([`Self::close_failed`]): its cancel goes through even if `klavd`
    /// holds no pending password for it.
    async fn finish_steps(
        &self,
        target: &Target,
        item: ItemId,
        rotation: RotationId,
        reason: &str,
        confirm: bool,
        unstored: Option<TaskId>,
    ) -> Result<(), Unfinished> {
        use Unfinished::{Closed, NotRecorded, Recorded, Unanswered};
        let home = klavd_home(target).map_err(NotRecorded)?;
        let task = match unstored {
            Some(task) => task,
            None => self.finish_task(item).map_err(NotRecorded)?,
        };
        let name = step_name(confirm);
        let mut daemon = connect(home).await.map_err(NotRecorded)?;
        let here = self
            .pending_here(&mut daemon, item, rotation, task)
            .await
            .map_err(NotRecorded)?;
        if here == Here::NotPending && (confirm || unstored.is_none()) {
            return Err(NotRecorded(ClientError::NotFound(format!(
                "klavd holds no pending password for change {rotation}: an earlier rotate_confirm or rotate_cancel of yours may have been applied (its answer lost), the person may have decided already from the item's card, an older Klav may have settled it, or it was never stored. This call recorded nothing (the log may already hold an earlier step of this change): ask the person, the item's card and its password history show what it holds. If the server still has the change open, new changes of this item are refused as «already in progress» until this task ends: ending the task (end_task) frees the item, but {END_TASK_COST}"
            ))));
        }
        let request = self
            .agent
            .sign_post(
                &format!("/v1/agent/rotations/{rotation}/{name}"),
                &AgentRotateFinish {
                    item_id: item,
                    reason: reason.trim().to_owned(),
                },
            )
            .map_err(NotRecorded)?;
        match self.agent.send_proved::<RotationInfo>(&request).await {
            Ok(info) if info.item_id != item => {
                return Err(Closed(ClientError::Security(format!(
                    "the server answered for another item, so klavd was not asked to apply this {name}: the item stays as it is. Tell the person"
                ))));
            }
            Ok(_) => {}
            // This same outcome, recorded by an earlier call whose `klavd`
            // step did not happen: finish that step now.
            Err(ClientError::Api {
                status: 409,
                message,
                ..
            }) if message.contains(&format!("already {}", outcome(confirm))) => {}
            // The other outcome is recorded (by this agent, by the person
            // from the item's card, or as abandoned when its task ended):
            // klavd is not asked, so the item stays as it is.
            Err(ClientError::Api {
                status: 409,
                message,
                ..
            }) => {
                let other = if confirm { "cancelled" } else { "confirmed" };
                return Err(Closed(ClientError::Invalid(
                    if message.contains(&format!("already {other}")) {
                        format!(
                            "{message}: the log already says the change was {other}, so this {name} was not recorded and klavd was not asked to apply it. If the new password is still pending in the item (the person may have decided on its card meanwhile), call rotate_{} to finish what the log says; if the log is wrong, tell the person, who decides from the item's card",
                            if confirm { "cancel" } else { "confirm" }
                        )
                    } else {
                        format!(
                            "{message}: change {rotation} was already closed another way (by the person from the item's card, or as abandoned when its task ended). This {name} was not recorded, and klavd was not asked to apply it: the item stays as it is"
                        )
                    },
                )));
            }
            // Sent, and no answer came: the server may have recorded it.
            // Nothing changed in the item, so the card and a retry still
            // work.
            Err(e @ ClientError::Network(_)) => return Err(Unanswered(e)),
            // Refused (paused, revoked, the account's deletion asked for,
            // a stale request): nothing changed in the item, so the card
            // and a retry still work.
            Err(e) => return Err(NotRecorded(e)),
        }
        let step = RotationStep {
            agent_id: self.agent.id(),
            task_id: task,
            rotation_id: rotation,
            item_id: item,
            request,
        };
        let call = if confirm {
            Request::AgentRotateConfirm { step }
        } else {
            Request::AgentRotateCancel { step }
        };
        match daemon.call::<serde_json::Value>(call).await {
            Ok(_) => Ok(()),
            // A cancel of a change klavd never stored a password for: the
            // server closed it, and there is nothing to move.
            Err(e)
                if e.code == ErrorCode::NotFound
                    && !confirm
                    && matches!(here, Here::NotPending | Here::Unknown) =>
            {
                Ok(())
            }
            // The pending password went between the question and now: the
            // person decided from the item's card meanwhile, or another call
            // of this change finished it.
            Err(e) if e.code == ErrorCode::NotFound => {
                Err(Recorded(ClientError::Invalid(if confirm {
                    format!(
                        "the server recorded that the site took the new password (change {rotation}), but the item no longer had it pending: the person decided from the item's card meanwhile, or another call of yours finished this change. If the person kept the current one, the item and the log disagree: the new password is in the item's history, marked generated, not confirmed. Tell the person"
                    )
                } else {
                    format!(
                        "the server recorded that the site refused the new password (change {rotation}), but the item no longer had it pending: the person decided from the item's card meanwhile, or another call of yours finished this change. If the person chose the new one, the item and the log disagree: the previous password is in the item's history. Tell the person"
                    )
                })))
            }
            // klavd refused, or its answer never came: it may have applied
            // the step all the same (only the answer lost).
            Err(e) => Err(Recorded(ClientError::Invalid(format!(
                "the server recorded the {name} of change {rotation}, but klavd did not say it applied it ({}). If it did not, the new password is still pending in the item, and the item and the log disagree until it is applied. Call rotate_{name} again: it finishes the step if klavd did not apply it, and answers that klavd holds no pending password if it did (then nothing is left to do). Or ask the person to choose «{}» on the item's card",
                daemon_error(e),
                if confirm {
                    "Use the new one"
                } else {
                    "Keep the current one"
                }
            )))),
        }
    }

    /// The site took the new password (ADR 0022 §5, step 7): it becomes
    /// the item's current one, and the old one goes to its history.
    pub async fn rotate_confirm(
        &self,
        target: &Target,
        item: ItemId,
        pending_id: RotationId,
        reason: &str,
    ) -> ClientResult<()> {
        self.finish(target, item, pending_id, reason, true).await
    }

    /// The site refused the new password, or the agent gives up: the
    /// current one stays, and the new one goes to the history marked
    /// «generated, not confirmed». Records nothing when `klavd` holds no
    /// pending password for the change (settled here, or never stored: the
    /// record does not say which); a change `klavd` did not fill is
    /// cancelled by [`Self::rotate_password`] itself.
    pub async fn rotate_cancel(
        &self,
        target: &Target,
        item: ItemId,
        pending_id: RotationId,
        reason: &str,
    ) -> ClientResult<()> {
        self.finish(target, item, pending_id, reason, false).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_extension_carries_a_change() {
        assert_eq!(refuse_target("extension"), None);
        assert_eq!(refuse_target(" extension "), None);
        let sdk = refuse_target("sdk:shop").unwrap();
        assert!(sdk.contains("\"extension\"") && sdk.contains("pass through you"));
        assert!(refuse_target("chrome").unwrap().contains("unknown target"));
    }

    #[test]
    fn the_report_carries_only_fields_and_the_change() {
        let id = RotationId::generate();
        let report: RotateReport = serde_json::from_value(serde_json::json!({
            "filled": ["new_password"],
            "pending_id": id,
        }))
        .unwrap();
        let value = serde_json::to_value(&report).unwrap();
        let keys: Vec<&String> = value.as_object().unwrap().keys().collect();
        assert_eq!(keys, ["filled", "pending_id"]);
    }
}
