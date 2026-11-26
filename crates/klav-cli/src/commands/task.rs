//! `task` (person side) and `agent task` (agent side): task requests, ADR
//! 0021.

use std::time::Duration;

use klav_client::offer::{SiteProgress, SiteState};
use klav_client::tasks::{TaskCard, TaskCardRow, TaskChoice, TaskLog};
use klav_core::ids::{ItemId, TaskId};
use klav_core::model::reference::{same_name, same_path};
use klav_core::policy::Permission;
use klav_daemon::protocol::Request;
use klav_proto::task::{TaskEndedBy, TaskStatus};
use klav_sdk::{Agent, Session, TaskView};

use crate::backend::{Backend, call};
use crate::cli::{AgentTaskCommand, TaskCommand};
use crate::commands::agent::{toml_scope, with_presence};
use crate::context::Ctx;
use crate::error::{CliError, CliResult, EXIT_DENIED, EXIT_EXPIRED, EXIT_PENDING, usage};
use crate::output;
use crate::time::{format_utc, now_ms};

// ---------------------------------------------------------------- person side

pub(crate) async fn task_cmd(ctx: &mut Ctx, cmd: TaskCommand) -> CliResult<()> {
    match cmd {
        TaskCommand::List { all, json } => {
            let cards = cards(ctx, all).await?;
            if json.json {
                return output::json(&cards);
            }
            if cards.is_empty() {
                output::info("No tasks pending or running.");
                return Ok(());
            }
            let rows: Vec<Vec<String>> = cards
                .iter()
                .map(|c| {
                    vec![
                        c.id.to_string(),
                        status_text(c),
                        c.agent.clone(),
                        c.rows.len().to_string(),
                        c.task.clone(),
                    ]
                })
                .collect();
            output::table(&["ID", "STATUS", "AGENT", "ITEMS", "TASK"], &rows);
            Ok(())
        }
        TaskCommand::Show { id, json } => {
            let all = cards(ctx, true).await?;
            let card = klav_client::tasks::find_task(&all, &id)?;
            if json.json {
                return output::json(card);
            }
            print_card(card);
            Ok(())
        }
        TaskCommand::Approve {
            id,
            without,
            duration,
            yes,
            json,
        } => {
            let pending = cards(ctx, false).await?;
            let card = klav_client::tasks::find_task(&pending, &id)?.clone();
            if !card.is_pending() {
                return Err(usage(format!(
                    "task {} is {}, not pending",
                    card.id,
                    card.status.as_str()
                )));
            }
            let choice = TaskChoice {
                without: without
                    .iter()
                    .map(|w| without_ref(&card, w))
                    .collect::<CliResult<_>>()?,
                with: Vec::new(),
                for_secs: duration.map(|d| d.as_secs()),
            };
            // The card the person approves is the one signed (ADR 0030 §5).
            if !json.json {
                print_card(&card);
                crate::commands::agent::confirm_approval("Approve this task?", yes)?;
            }
            let decided = decide(ctx, &card, true, choice).await?;
            if json.json {
                return output::json(&decided);
            }
            output::info(&format!(
                "Approved: {} may work on «{}» until {}.",
                decided.agent,
                decided.task,
                decided.expires_at.map(format_utc).unwrap_or_default()
            ));
            Ok(())
        }
        TaskCommand::Deny { id, json } => {
            let pending = cards(ctx, false).await?;
            let card = klav_client::tasks::find_task(&pending, &id)?.clone();
            let decided = decide(ctx, &card, false, TaskChoice::default()).await?;
            if json.json {
                return output::json(&decided);
            }
            output::info(&format!(
                "Denied: {} asked for «{}».",
                decided.agent, decided.task
            ));
            Ok(())
        }
        TaskCommand::End { id, json } => {
            let ended: TaskCard = match ctx.backend().await? {
                Backend::Direct(u) => {
                    let live = u.tasks(false).await?;
                    let found = klav_client::tasks::find_task(&live, &id)?.id;
                    u.end_task(found).await?
                }
                Backend::Daemon(d) => call(d, Request::EndTask { task: id }).await?,
            };
            if json.json {
                return output::json(&ended);
            }
            output::info(&format!(
                "Ended: {} can no longer use «{}».",
                ended.agent, ended.task
            ));
            Ok(())
        }
    }
}

async fn cards(ctx: &mut Ctx, all: bool) -> CliResult<Vec<TaskCard>> {
    Ok(match ctx.backend().await? {
        Backend::Direct(u) => u.tasks(all).await?,
        Backend::Daemon(d) => call(d, Request::Tasks { all }).await?,
    })
}

async fn decide(
    ctx: &mut Ctx,
    card: &TaskCard,
    approve: bool,
    choice: TaskChoice,
) -> CliResult<TaskCard> {
    let id = card.id;
    let digest = card.request_digest.clone();
    Ok(match ctx.backend().await? {
        Backend::Direct(u) => u.decide_task(id, approve, &choice, &digest).await?,
        Backend::Daemon(_) if approve => {
            with_presence(ctx, |password| Request::DecideTask {
                task: id.to_string(),
                approve,
                digest: digest.clone(),
                choice: choice.clone(),
                password,
            })
            .await?
        }
        Backend::Daemon(d) => {
            call(
                d,
                Request::DecideTask {
                    task: id.to_string(),
                    approve,
                    digest,
                    choice,
                    password: None,
                },
            )
            .await?
        }
    })
}

/// `--without REF[:permission]`, resolved against the rows of the card:
/// the item ID, its `klav://` reference or its title (unique on the card).
fn without_ref(card: &TaskCard, text: &str) -> CliResult<(ItemId, Option<Permission>)> {
    let parsed = text.rsplit_once(':').and_then(|(head, tail)| {
        serde_json::from_value::<Permission>(serde_json::Value::from(tail.trim()))
            .ok()
            .map(|p| (head, Some(p)))
    });
    let (reference, permission) = parsed.unwrap_or((text, None));
    let reference = reference.trim();
    let found: Vec<&TaskCardRow> = card
        .rows
        .iter()
        .filter(|r| {
            r.item_id.to_string() == reference
                || r.reference.eq_ignore_ascii_case(reference)
                || same_path(&r.reference, reference)
                || r.title
                    .as_deref()
                    .is_some_and(|t| t.eq_ignore_ascii_case(reference))
                || r.reference.rsplit_once('/').is_some_and(|(_, last)| {
                    last.eq_ignore_ascii_case(reference) || same_name(last, reference)
                })
        })
        .collect();
    let row = match found.as_slice() {
        [one] => *one,
        [] => {
            return Err(usage(format!(
                "{reference:?} is not on the card of this task"
            )));
        }
        _ => {
            return Err(usage(format!(
                "{reference:?} matches several items on the card; use its klav:// reference"
            )));
        }
    };
    if let Some(p) = permission
        && !row.permissions.iter().any(|x| x.permission == p)
    {
        return Err(usage(format!(
            "`{p}` is not on the card for {}",
            row.reference
        )));
    }
    Ok((row.item_id, permission))
}

fn status_text(c: &TaskCard) -> String {
    match (c.status, c.ended_by) {
        (TaskStatus::Ended, Some(by)) => format!("ended ({})", by.as_str()),
        (s, _) => s.as_str().to_owned(),
    }
}

/// A duration in minutes, or hours and minutes.
pub(crate) fn minutes_text(ms: i64) -> String {
    minutes(ms)
}

fn minutes(ms: i64) -> String {
    let mins = ms.max(0) / 60_000;
    if mins >= 60 {
        format!("{} h {} min", mins / 60, mins % 60)
    } else {
        format!("{mins} min")
    }
}

/// The warning next to a permission on the card (ADR 0021 §4).
fn warning(permission: Permission) -> Option<&'static str> {
    match permission {
        Permission::Totp => Some("2FA stops being a second factor for this agent"),
        Permission::Passkey => {
            Some("the agent will sign in with your passkey; your approval counts as verification")
        }
        Permission::Rotate => Some("the agent will change this password"),
        _ => None,
    }
}

fn print_card(c: &TaskCard) {
    let now = now_ms();
    output::line(&format!("Task {}  {}", c.id, status_text(c)));
    output::line(&format!("  agent:   {}", c.agent));
    let whose = if c.offered {
        "(yours: you offered it)"
    } else {
        "(according to the agent)"
    };
    output::line(&format!("  task:    {}   {whose}", c.task));
    output::line(&format!("  reason:  {}   {whose}", c.reason));
    match c.status {
        TaskStatus::Pending => {
            output::line(&format!(
                "  lasts:   {} from approval (would end at {})",
                minutes(i64::try_from(c.duration_secs).unwrap_or(0) * 1000),
                format_utc(now + i64::try_from(c.duration_secs).unwrap_or(0) * 1000)
            ));
            output::line(&format!("  decide:  within {}", minutes(c.decide_by - now)));
        }
        TaskStatus::Approved => {
            if let Some(until) = c.expires_at {
                output::line(&format!(
                    "  ends:    {} ({} left)",
                    format_utc(until),
                    minutes(until - now)
                ));
            }
        }
        _ => {
            if let Some(at) = c.ended_at {
                output::line(&format!("  ended:   {}", format_utc(at)));
            }
        }
    }
    for row in &c.rows {
        let mut head = format!(
            "  [{}] {}",
            if row.permissions.iter().any(|p| p.checked) {
                "x"
            } else {
                " "
            },
            row.reference
        );
        if let Some(user) = &row.username {
            head.push_str(&format!("  ({user})"));
        }
        if !row.domains.is_empty() {
            head.push_str(&format!("  {}", row.domains.join(", ")));
            if row.domain_claimed {
                head.push_str("   (according to the agent)");
            }
        }
        output::line(&head);
        if row.missing {
            output::line(
                "        not in your vault or outside the agent's grant: cannot be approved",
            );
        }
        if row.domain_mismatch {
            output::line(&format!(
                "        the site does not match the item (the agent said {}): cannot be approved",
                row.asked_domain.as_deref().unwrap_or("?")
            ));
        }
        if row.no_site {
            output::line(
                "        no site: the item has no URL, so fill, passkey and rotate cannot go in a task",
            );
        }
        for p in &row.permissions {
            let name = klav_sdk::session::permission_name(p.permission);
            let mut text = if p.denied_by_policy {
                format!("        [-] {name}: your policy denies it")
            } else if p.always_asks {
                // ADR 0032 §4.2: unchecked and cannot be checked.
                format!(
                    "        [-] {name}: Always asks for approval (protected; it never goes in a task)"
                )
            } else if p.no_site {
                format!("        [-] {name}: no site")
            } else {
                format!("        [{}] {name}", if p.checked { "x" } else { " " })
            };
            if p.added_by_klav {
                text.push_str("  (added by Klav)");
            }
            if !p.denied_by_policy
                && !p.always_asks
                && !p.no_site
                && let Some(w) = warning(p.permission)
            {
                text.push_str(&format!("  — {w}"));
            }
            output::line(&text);
        }
    }
    if c.is_pending() {
        output::info(&format!(
            "\nApprove with `klav task approve {}` (leave things out with --without REF[:permission], shorten with --for 1h) or deny with `klav task deny {}`.",
            c.id, c.id
        ));
    }
}

// --------------------------------------------------------------- `log --task`

pub(crate) async fn task_log(ctx: &mut Ctx, wanted: &str, json: bool) -> CliResult<()> {
    let log: TaskLog = match ctx.backend().await? {
        Backend::Direct(u) => u.task_log(wanted).await?,
        Backend::Daemon(d) => {
            call(
                d,
                Request::TaskLog {
                    task: wanted.to_owned(),
                },
            )
            .await?
        }
    };
    if json {
        return output::json(&log);
    }
    output::line(&format!("Task {}", log.task_id));
    if let Some(card) = &log.card {
        output::line(&format!("  agent:   {}", card.agent));
        output::line(&format!("  task:    {}", card.task));
        if card.offered {
            output::line("  offered: by the person, without a request from the agent");
        }
        output::line(&format!("  reason:  {}", card.reason));
        output::line(&format!("  status:  {}", status_text(card)));
    }
    let rows: Vec<Vec<String>> = log
        .events
        .iter()
        .map(|l| {
            let what = match l.action.as_str() {
                "task.requested" => "requested".to_owned(),
                "task.decided" => format!(
                    "{} by {}",
                    match l.outcome.as_deref() {
                        Some("approve") => "approved",
                        Some("deny") => "denied",
                        _ => "decided",
                    },
                    l.actor
                ),
                "task.ended" => format!("ended ({})", l.outcome.as_deref().unwrap_or("?")),
                // Assisted password changes (ADR 0022 §5).
                "rotate.started" | "rotate.confirmed" | "rotate.cancelled" => format!(
                    "password change {} → {}",
                    l.action.trim_start_matches("rotate."),
                    l.outcome.as_deref().unwrap_or("?")
                ),
                _ => format!(
                    "{} → {}",
                    l.permission.as_deref().unwrap_or(&l.action),
                    l.outcome.as_deref().unwrap_or("?")
                ),
            };
            vec![
                format_utc(l.at),
                l.actor.clone(),
                what,
                l.item
                    .clone()
                    .or_else(|| l.item_id.map(|i| i.to_string()))
                    .unwrap_or_default(),
                l.domain.clone().unwrap_or_default(),
                l.reason.clone().unwrap_or_default(),
            ]
        })
        .collect();
    if !rows.is_empty() || log.log_warning.is_none() {
        output::table(&["WHEN", "WHO", "WHAT", "ITEM", "HOST", "REASON"], &rows);
    }
    if !log.sites.is_empty() {
        print_sites(&log.sites);
    }
    if let Some(warning) = &log.log_warning {
        output::warn(warning);
    }
    if !log.outside.is_empty() {
        output::line("\nOutside the task (asked for separately while it ran):");
        let rows: Vec<Vec<String>> = log
            .outside
            .iter()
            .map(|l| {
                vec![
                    format_utc(l.at),
                    format!(
                        "{} → {}",
                        l.permission.as_deref().unwrap_or(&l.action),
                        l.outcome.as_deref().unwrap_or("?")
                    ),
                    l.item
                        .clone()
                        .or_else(|| l.item_id.map(|i| i.to_string()))
                        .unwrap_or_default(),
                    l.domain.clone().unwrap_or_default(),
                    l.approval_id.map(|a| a.to_string()).unwrap_or_default(),
                ]
            })
            .collect();
        output::table(&["WHEN", "WHAT", "ITEM", "HOST", "APPROVAL"], &rows);
    }
    Ok(())
}

/// Each site of a task with `rotate` (ADR 0022 §6): changed, pending or
/// failed.
fn print_sites(sites: &[SiteProgress]) {
    let changed = sites
        .iter()
        .filter(|s| s.state == SiteState::Changed)
        .count();
    let failed = sites
        .iter()
        .filter(|s| s.state == SiteState::Failed)
        .count();
    output::line(&format!(
        "\nPasswords: {changed} changed, {} pending, {failed} failed",
        sites.len() - changed - failed
    ));
    let rows: Vec<Vec<String>> = sites
        .iter()
        .map(|s| {
            let state = match (s.state, s.started) {
                (SiteState::Changed, _) => "changed",
                (SiteState::Pending, true) => "pending (in progress)",
                (SiteState::Pending, false) => "pending",
                (SiteState::Failed, _) => "failed",
            };
            vec![
                s.reference.clone().unwrap_or_else(|| s.item_id.to_string()),
                s.hosts.join(", "),
                state.to_owned(),
                s.at.map(format_utc).unwrap_or_default(),
            ]
        })
        .collect();
    output::table(&["ITEM", "SITE", "STATE", "SINCE"], &rows);
}

// ----------------------------------------------------------------- agent side

pub(crate) async fn agent_task_cmd(ctx: &mut Ctx, cmd: AgentTaskCommand) -> CliResult<()> {
    match cmd {
        AgentTaskCommand::Request {
            file,
            wait,
            agent,
            json,
        } => {
            let spec = crate::task_file::read(&file)?;
            let session = open(ctx, agent.as_deref()).await?;
            let scope = toml_scope()?;
            let scope = scope.as_ref().map(|(v, p)| (v.as_str(), p.as_str()));
            let request = session.task_request(&spec, scope)?;
            let pending = session.submit_task(&request).await?;
            let id = pending.pending_task_id;
            let info = match wait {
                Some(timeout) => {
                    if !json.json {
                        output::info(&format!(
                            "Asked for task {id}; waiting for the person (`klav task approve {id}`)…"
                        ));
                    }
                    session.agent().wait_task(id, timeout).await?
                }
                None => session.agent().task(id, Duration::ZERO).await?,
            };
            report(&session, &info, json.json)
        }
        AgentTaskCommand::Wait {
            id,
            timeout,
            agent,
            json,
        } => {
            let id = task_id(&id)?;
            let session = open(ctx, agent.as_deref()).await?;
            if !json.json {
                output::info(&format!("Waiting for the person to decide on task {id}…"));
            }
            let info = session.agent().wait_task(id, timeout).await?;
            report(&session, &info, json.json)
        }
        AgentTaskCommand::Show { id, agent, json } => {
            let id = task_id(&id)?;
            let session = open(ctx, agent.as_deref()).await?;
            let info = session.agent().task(id, Duration::ZERO).await?;
            let view = session.task_view(&info)?;
            if json.json {
                return output::json(&view);
            }
            print_view(&view);
            Ok(())
        }
        AgentTaskCommand::End {
            id,
            reason,
            agent,
            json,
        } => {
            let id = task_id(&id)?;
            let session = open(ctx, agent.as_deref()).await?;
            let info = session.agent().end_task(id, &reason).await?;
            let view = session.task_view(&info)?;
            if json.json {
                return output::json(&view);
            }
            output::info(&format!("Task {id} ended."));
            Ok(())
        }
    }
}

async fn open(ctx: &Ctx, agent: Option<&str>) -> CliResult<Session> {
    let name = klav_sdk::config::pick(&ctx.home, agent)?;
    let agent = Agent::load(&ctx.home, &name)?;
    Ok(Session::open(agent).await?)
}

/// A task ID given by an agent (in full).
fn task_id(text: &str) -> CliResult<TaskId> {
    text.trim()
        .parse()
        .map_err(|_| usage(format!("{text:?} is not a task ID")))
}

/// The exit code of a task's state (ADR 0015 §4): 0 approved, 4 pending,
/// 5 denied (or ended by the person or a revocation), 6 expired (or ended
/// by time or by the agent).
fn exit_code(view: &TaskView) -> CliResult<()> {
    match (view.status, view.ended_by) {
        (TaskStatus::Approved, _) => Ok(()),
        (TaskStatus::Pending, _) => Err(CliError::Exit(EXIT_PENDING)),
        (TaskStatus::Denied, _)
        | (TaskStatus::Ended, Some(TaskEndedBy::Person | TaskEndedBy::Revocation)) => {
            Err(CliError::Exit(EXIT_DENIED))
        }
        (TaskStatus::Expired | TaskStatus::Ended, _) => Err(CliError::Exit(EXIT_EXPIRED)),
    }
}

fn report(session: &Session, info: &klav_proto::task::TaskInfo, json: bool) -> CliResult<()> {
    let view = session.task_view(info)?;
    if json {
        output::json(&view)?;
    } else {
        print_view(&view);
        output::info(&match view.status {
            TaskStatus::Approved => {
                "Approved: work with what came back approved; ask for anything else with the normal tools.".to_owned()
            }
            TaskStatus::Pending => format!(
                "No decision yet: the person approves it with `klav task approve {id}`; wait with `klav agent task wait {id}`.",
                id = view.task_id
            ),
            TaskStatus::Denied => "The person denied it: do not try another way.".to_owned(),
            TaskStatus::Expired => "It expired without a decision.".to_owned(),
            TaskStatus::Ended => "The task is over.".to_owned(),
        });
    }
    exit_code(&view)
}

fn print_view(v: &TaskView) {
    output::line(&format!(
        "{}  {}{}",
        v.task_id,
        v.status.as_str(),
        v.ended_by
            .map(|b| format!(" ({})", b.as_str()))
            .unwrap_or_default()
    ));
    output::line(&format!("  task:  {}", v.task));
    if let Some(reason) = v.reason.as_deref().filter(|_| v.offered) {
        output::line("  offered by the person");
        output::line(&format!("  reason: {reason}"));
    }
    match v.status {
        TaskStatus::Pending => {
            output::line(&format!("  decide before: {}", format_utc(v.expires_at)));
        }
        TaskStatus::Approved => {
            output::line(&format!("  ends:  {}", format_utc(v.expires_at)));
        }
        _ => {}
    }
    for a in &v.access {
        let mut text = format!(
            "  + {}: {}",
            a.reference,
            a.permissions
                .iter()
                .map(|p| klav_sdk::session::permission_name(*p))
                .collect::<Vec<_>>()
                .join(", ")
        );
        if !a.domains.is_empty() {
            text.push_str(&format!(" on {}", a.domains.join(", ")));
        }
        if !a.added_by_klav.is_empty() {
            text.push_str(&format!(
                " (added by Klav: {})",
                a.added_by_klav
                    .iter()
                    .map(|p| klav_sdk::session::permission_name(*p))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        output::line(&text);
    }
    for r in &v.removed {
        output::line(&format!(
            "  - {}: {} (left out by the person)",
            r.reference,
            r.permissions
                .iter()
                .map(|p| klav_sdk::session::permission_name(*p))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
}
