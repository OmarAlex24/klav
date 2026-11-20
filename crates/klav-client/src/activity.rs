//! «Who used it» (ADR 0033 §8.1): what agents did with one item, from the
//! audit log this device downloaded, with how each use went.
//!
//! Nothing new is stored and no value is shown: the log has none. The
//! item's title comes from this device's vault (the log only has IDs); an
//! agent's reason, site and task title are the agent's own words, shown as
//! such (T136).

use std::collections::HashMap;

use klav_core::ids::{ApprovalId, ItemId, TaskId};
use klav_core::task::TaskRequest;
use serde::{Deserialize, Serialize};

use crate::audit::{Entry, LogFilter, LogLine};
use crate::error::ClientResult;
use crate::session::Unlocked;

/// How an agent's use of an item went, for the app to say in words: «allowed
/// by your policy», «approved once», «approved for 15 min», «inside the task
/// “…”», «asked you» or «denied».
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum How {
    /// The grant's policy allowed it.
    Policy,
    /// The person approved this one request.
    ApprovedOnce,
    /// The person approved such requests for a while ([`ItemUse::lease_until`]).
    ApprovedFor,
    /// A task the person approved let it through ([`ItemUse::task`]).
    Task,
    /// The policy asked the person; the request waited for them.
    Asked,
    /// The policy or the person denied it.
    Denied,
    /// Anything else (an action of a later version).
    #[serde(other)]
    Other,
}

/// One agent event about the item.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ItemUse {
    /// The event, as `klav log` shows it (the agent's name in `actor`).
    #[serde(flatten)]
    pub line: LogLine,
    /// How it went.
    pub how: How,
    /// With [`How::ApprovedFor`]: when the approval ran out (Unix ms).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_until: Option<i64>,
    /// With an approval: when the person decided it (Unix ms), so the app
    /// can say «approved for 15 min».
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved_at: Option<i64>,
    /// With [`How::Task`]: the task's title, in the agent's words.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task: Option<String>,
}

/// «Who used it» for one item.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ItemActivity {
    /// The item.
    pub item_id: ItemId,
    /// Its reference on this device (`klav://…`), if this device has it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
    /// In the trash.
    #[serde(default)]
    pub trashed: bool,
    /// Not on this device any more (purged): shown as «(deleted)».
    #[serde(default)]
    pub deleted: bool,
    /// The agents' events about it, newest first.
    pub uses: Vec<ItemUse>,
}

/// What the approvals decided in the log said: approval → (when decided,
/// lease end; `0`: once). Only approvals the person granted.
fn approvals(entries: &[Entry]) -> HashMap<ApprovalId, (i64, i64)> {
    entries
        .iter()
        .map(|e| &e.event)
        .filter(|e| e.action == "approval.decided" && e.outcome.as_deref() == Some("approve"))
        .filter_map(|e| {
            Some((
                e.approval_id?,
                (e.decided_at.unwrap_or(e.at), e.lease_until.unwrap_or(0)),
            ))
        })
        .collect()
}

/// The title of each task in the log, from the agent's request: the one
/// the person's decision answers (`task.decided`, the last one, which
/// comes after the request in the chain), or else the one it sent
/// (`task.requested`).
fn task_titles(entries: &[Entry]) -> HashMap<TaskId, String> {
    let mut titles = HashMap::new();
    for e in entries.iter().map(|e| &e.event) {
        let Some(task) = e.task_id else {
            continue;
        };
        let (request, decided) = match e.action.as_str() {
            "task.decided" => (e.task_request.as_ref(), true),
            "task.requested" => (e.agent_proof.as_ref().and_then(|p| p.body.as_ref()), false),
            _ => (None, false),
        };
        let Some(request) =
            request.and_then(|b| serde_json::from_slice::<TaskRequest>(b.as_bytes()).ok())
        else {
            continue;
        };
        if decided {
            titles.insert(task, request.task);
        } else {
            titles.entry(task).or_insert(request.task);
        }
    }
    titles
}

/// How `line` went: the policy's outcome, and for an allowed use what let
/// it through (a task first: an approval «Add to the task» left is bound to
/// it). An approval whose decision is not in the chain proves nothing:
/// [`How::Other`], with no approval details.
pub(crate) fn how(
    line: &LogLine,
    approvals: &HashMap<ApprovalId, (i64, i64)>,
) -> (How, Option<(i64, i64)>) {
    match line.outcome.as_deref() {
        Some("deny") => (How::Denied, None),
        Some("ask") => (How::Asked, None),
        Some("allow") if line.task_id.is_some() => (How::Task, None),
        Some("allow") => match line.approval_id {
            None => (How::Policy, None),
            Some(id) => match approvals.get(&id) {
                Some(&(at, until)) if until > 0 => (How::ApprovedFor, Some((at, until))),
                Some(&decided) => (How::ApprovedOnce, Some(decided)),
                None => (How::Other, None),
            },
        },
        _ => (How::Other, None),
    }
}

impl Unlocked {
    /// «Who used it» for an item (reference, title or ID; the ID also
    /// finds one this device no longer has): every event an agent wrote
    /// about it, newest first, with how it went.
    pub async fn item_activity(&mut self, item: &str) -> ClientResult<ItemActivity> {
        let item_id = match item.trim().parse::<ItemId>() {
            Ok(id) => id,
            Err(_) => self.find_item(item)?.item,
        };
        let entries = self.audit_entries().await?;
        let agents = self.agent_names().await?;
        let lines = self.log_lines(
            &entries,
            &agents,
            &LogFilter {
                item: Some(item_id.to_string()),
                ..LogFilter::default()
            },
        )?;
        Ok(self.activity_of(item_id, &entries, lines))
    }

    /// [`Self::item_activity`] over what is already downloaded.
    pub(crate) fn activity_of(
        &self,
        item_id: ItemId,
        entries: &[Entry],
        lines: Vec<LogLine>,
    ) -> ItemActivity {
        let approvals = approvals(entries);
        let titles = task_titles(entries);
        let reference = lines.iter().find_map(|l| l.item.clone());
        let uses = lines
            .into_iter()
            .filter(|l| l.by_agent)
            .map(|line| {
                let (how, approval) = how(&line, &approvals);
                let task = (how == How::Task)
                    .then(|| line.task_id.and_then(|t| titles.get(&t).cloned()))
                    .flatten();
                ItemUse {
                    how,
                    lease_until: approval.map(|(_, until)| until).filter(|u| *u > 0),
                    approved_at: approval.map(|(at, _)| at),
                    task,
                    line,
                }
            })
            .collect();
        let trashed = self.item_trashed(item_id);
        ItemActivity {
            item_id,
            reference,
            trashed: trashed.unwrap_or(false),
            deleted: trashed.is_none(),
            uses,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use klav_proto::audit::{ActorKind, AgentProof, AuditEvent};

    fn line(outcome: &str, approval: Option<ApprovalId>, task: Option<TaskId>) -> LogLine {
        LogLine {
            seq: 1,
            at: 10,
            actor: "cursor".into(),
            by_agent: true,
            agent_id: None,
            agent_name: None,
            action: "agent.access".into(),
            permission: Some("fill".into()),
            outcome: Some(outcome.into()),
            item: None,
            item_id: None,
            vault: None,
            reason: None,
            domain: None,
            attachments: Vec::new(),
            task_id: task,
            approval_id: approval,
            until: None,
            alerts: Vec::new(),
            verified: false,
        }
    }

    #[test]
    fn each_use_says_what_let_it_through() {
        let once = ApprovalId::generate();
        let lease = ApprovalId::generate();
        let unknown = ApprovalId::generate();
        let task = TaskId::generate();
        let approvals = HashMap::from([(once, (5, 0)), (lease, (5, 900_005))]);
        assert_eq!(
            how(&line("allow", None, None), &approvals),
            (How::Policy, None)
        );
        assert_eq!(
            how(&line("allow", Some(once), None), &approvals),
            (How::ApprovedOnce, Some((5, 0)))
        );
        assert_eq!(
            how(&line("allow", Some(lease), None), &approvals),
            (How::ApprovedFor, Some((5, 900_005)))
        );
        // An approval whose decision is not in the chain: nothing says the
        // person approved it.
        assert_eq!(
            how(&line("allow", Some(unknown), None), &approvals),
            (How::Other, None)
        );
        // A task first, even with the approval «Add to the task» left.
        assert_eq!(
            how(&line("allow", Some(once), Some(task)), &approvals),
            (How::Task, None)
        );
        assert_eq!(
            how(&line("ask", Some(once), None), &approvals),
            (How::Asked, None)
        );
        assert_eq!(
            how(&line("deny", None, None), &approvals),
            (How::Denied, None)
        );
        assert_eq!(
            how(&line("person", None, None), &approvals),
            (How::Other, None)
        );
        // An unknown kind from a later `klavd` still reads.
        let later: How = serde_json::from_str("\"approved_by_magic\"").expect("other");
        assert_eq!(later, How::Other);
    }

    fn task_event(action: &str, task: TaskId, title: &str) -> Entry {
        let request = TaskRequest {
            v: 1,
            task: title.into(),
            reason: "facturas".into(),
            duration_secs: 1800,
            access: Vec::new(),
        };
        let body = klav_proto::Blob::new(serde_json::to_vec(&request).expect("json"));
        let mut event = AuditEvent::new(ActorKind::Agent, action);
        event.task_id = Some(task);
        if action == "task.decided" {
            event.actor = ActorKind::Person;
            event.task_request = Some(body);
        } else {
            event.agent_proof = Some(AgentProof {
                method: "POST".into(),
                path: "/v1/agent/tasks".into(),
                timestamp: 1,
                nonce: klav_proto::Blob::new(vec![0; 16]),
                body_digest: klav_proto::Blob::new(vec![0; 32]),
                body: Some(body),
                signature: klav_proto::Blob::new(vec![0; 64]),
            });
        }
        Entry {
            seq: 1,
            bytes: Vec::new(),
            hash: [0; 32],
            event,
        }
    }

    #[test]
    fn a_tasks_title_is_the_one_the_person_decided_on() {
        let decided = TaskId::generate();
        let asked = TaskId::generate();
        let titles = task_titles(&[
            task_event("task.requested", decided, "lo que pidió"),
            task_event("task.decided", decided, "lo que se aprobó"),
            task_event("task.requested", asked, "solo pedida"),
            // A later revision of the decision wins too.
            task_event("task.decided", decided, "la revisión"),
        ]);
        assert_eq!(titles[&decided], "la revisión");
        assert_eq!(titles[&asked], "solo pedida");
        // The decision first in the chain (an odd order) still wins.
        let titles = task_titles(&[
            task_event("task.decided", decided, "lo que se aprobó"),
            task_event("task.requested", decided, "lo que pidió"),
        ]);
        assert_eq!(titles[&decided], "lo que se aprobó");
    }
}
