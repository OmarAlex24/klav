//! `log`: the audit log (design §6) and its verification.

use std::io::{BufRead, IsTerminal, Write};

use klav_client::audit::{ChainStatus, LogFilter, LogLine, VerifyReport};
use klav_daemon::client::DaemonClient;
use klav_daemon::protocol::{DaemonStatus, ErrorCode, Request};

use crate::backend::{Backend, call};
use crate::cli::{LogArgs, LogCommand};
use crate::context::Ctx;
use crate::error::{CliError, CliResult, usage};
use crate::output;
use crate::time::format_utc;

pub(crate) async fn log_cmd(ctx: &mut Ctx, args: LogArgs) -> CliResult<()> {
    match args.command {
        Some(LogCommand::Verify(flag)) => return verify(ctx, flag.json).await,
        Some(LogCommand::Reset(reset_args)) => return reset(ctx, reset_args.yes).await,
        None => {}
    }
    if let Some(task) = &args.task {
        return super::task::task_log(ctx, task, args.json).await;
    }
    let filter = LogFilter {
        item: args.item,
        agent: args.agent,
        vault: args.vault,
        since: args.since,
        until: args.until,
        alerts: args.alerts,
        task: None,
        permissions: args.permissions,
        outcomes: args.outcomes,
        text: args.text,
        // `--limit` cuts after counting them all ("10 of 42 events").
        limit: None,
    };
    let (mut lines, status): (Vec<LogLine>, Option<ChainStatus>) = match ctx.backend().await? {
        Backend::Direct(u) => {
            let lines = u
                .audit_log(&filter)
                .await
                .map_err(|e| reset_hint(e.into()))?;
            (lines, Some(u.audit_status()))
        }
        Backend::Daemon(d) => {
            let lines = call(
                d,
                Request::AuditLog {
                    filter: filter.clone(),
                },
            )
            .await
            .map_err(reset_hint)?;
            // An older klavd knows neither the status nor the new filters.
            (lines, call(d, Request::AuditStatus).await.ok())
        }
    };
    lines.retain(|l| filter.keeps(l));
    if args.json {
        return output::json(&lines);
    }
    if args.csv {
        return write_csv(&lines);
    }
    if lines.is_empty() {
        output::info("No events.");
        return Ok(());
    }
    let total = lines.len();
    lines.truncate(args.limit);
    let rows: Vec<Vec<String>> = lines
        .iter()
        .map(|l| {
            vec![
                format_utc(l.at),
                who(l),
                action(l),
                l.item
                    .clone()
                    .or_else(|| l.item_id.map(|i| i.to_string()))
                    .unwrap_or_default(),
                l.reason.clone().unwrap_or_default(),
                l.alerts.join(","),
            ]
        })
        .collect();
    output::table(&["WHEN", "WHO", "WHAT", "ITEM", "REASON", "ALERTS"], &rows);
    if total > lines.len() {
        output::info(&format!(
            "{} of {total} events (use --limit, or --json/--csv for all).",
            lines.len()
        ));
    }
    if let Some(note) = status.as_ref().and_then(unverified_note) {
        output::info(&note);
    }
    Ok(())
}

/// What the table says about the events `klav log verify` has not checked
/// yet, if any.
fn unverified_note(status: &ChainStatus) -> Option<String> {
    match (status.unverified(), status.verified) {
        (0, _) => None,
        (_, None) => {
            Some("This device has not verified the log yet: run `klav log verify`.".to_owned())
        }
        (n, Some(seq)) => Some(format!(
            "Verified up to event {seq}: run `klav log verify` for the {n} after it."
        )),
    }
}

/// The WHO column: `you` or the agent's name, and the start of its ID for
/// an agent whose name reads like the person (an agent may be called
/// `you`; the server refuses that name since ADR 0033's review).
fn who(l: &LogLine) -> String {
    match l.agent_id {
        Some(id) if l.by_agent && l.actor.trim().eq_ignore_ascii_case("you") => {
            let id = id.to_string();
            format!("{} (agent {})", l.actor, &id[..8.min(id.len())])
        }
        _ => l.actor.clone(),
    }
}

/// `agent.access fill → allow`.
fn action(l: &LogLine) -> String {
    let mut text = l.action.clone();
    if let Some(p) = &l.permission {
        text.push(' ');
        text.push_str(p);
    }
    if let Some(o) = &l.outcome {
        text.push_str(" → ");
        text.push_str(o);
    }
    if let Some(agent) = granted_to(l) {
        text.push_str(" for ");
        text.push_str(&agent);
    }
    text
}

/// Who the person's `agent.granted` was for: the agent's name as the
/// server lists it, escaped, and the start of its ID; the ID alone when
/// the server no longer lists it or an older klavd does not say.
fn granted_to(l: &LogLine) -> Option<String> {
    if l.action != "agent.granted" || l.by_agent {
        return None;
    }
    let id = l.agent_id?.to_string();
    let short = &id[..8.min(id.len())];
    Some(match &l.agent_name {
        Some(name) => format!("{name:?} ({short})"),
        None => format!("agent {short}"),
    })
}

/// Keeps spreadsheet programs from reading a cell as a formula: the reason
/// and the domain come from agents.
fn cell(text: &str) -> String {
    if text.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        format!("'{text}")
    } else {
        text.to_owned()
    }
}

fn write_csv(lines: &[LogLine]) -> CliResult<()> {
    let mut out = csv::Writer::from_writer(std::io::stdout().lock());
    let fail = |e: csv::Error| usage(format!("cannot write the CSV: {e}"));
    out.write_record([
        "seq",
        "time",
        "actor",
        "agent_id",
        "action",
        "permission",
        "outcome",
        "item",
        "item_id",
        "vault",
        "reason",
        "domain",
        "alerts",
    ])
    .map_err(fail)?;
    for l in lines {
        out.write_record([
            l.seq.to_string(),
            format_utc(l.at),
            cell(&l.actor),
            l.agent_id.map(|a| a.to_string()).unwrap_or_default(),
            l.action.clone(),
            l.permission.clone().unwrap_or_default(),
            l.outcome.clone().unwrap_or_default(),
            cell(l.item.as_deref().unwrap_or_default()),
            l.item_id.map(|i| i.to_string()).unwrap_or_default(),
            cell(l.vault.as_deref().unwrap_or_default()),
            cell(l.reason.as_deref().unwrap_or_default()),
            cell(l.domain.as_deref().unwrap_or_default()),
            l.alerts.join(","),
        ])
        .map_err(fail)?;
    }
    out.flush()
        .map_err(|e| usage(format!("cannot write the CSV: {e}")))?;
    Ok(())
}

/// `klav log reset` (ADR 0033 §8.4): forgets this device's copy of the
/// log and the head it verified. Through `klavd` when it runs (also
/// locked), which holds the copy in memory while unlocked; else the files
/// alone. No network and no password: it only removes files of this
/// `KLAV_HOME`, which any program of this user could remove too.
async fn reset(ctx: &mut Ctx, yes: bool) -> CliResult<()> {
    // A person's account here, not an empty home.
    klav_client::account(&ctx.home)?;
    confirm_log_reset(yes)?;
    let removed: Vec<String> = match DaemonClient::connect(&ctx.home).await {
        Some(mut d) => match d.call::<Vec<String>>(Request::AuditReset).await {
            Ok((removed, warnings)) => {
                for w in &warnings {
                    output::warn(w);
                }
                removed
            }
            // A klavd older than this command: locked, it holds no copy in
            // memory, so removing the files is enough.
            Err(e) if e.code == ErrorCode::BadRequest => {
                let status: DaemonStatus = call(&mut d, Request::Status).await?;
                if status.unlocked {
                    return Err(CliError::Other(
                        "this klavd is older than `klav log reset` and keeps the log's copy in \
                         memory: lock it (`klav lock`) and run this again"
                            .into(),
                    ));
                }
                forget_files(ctx)?
            }
            Err(e) => return Err(CliError::Daemon(e)),
        },
        None => forget_files(ctx)?,
    };
    if removed.is_empty() {
        output::info("This device had no copy of the audit log to forget.");
    } else {
        output::info(&format!(
            "Forgot {}. The next `klav log` downloads the chain the server has now, and \
             `klav log verify` starts over from it.",
            removed.join(" and ")
        ));
    }
    Ok(())
}

fn forget_files(ctx: &Ctx) -> CliResult<Vec<String>> {
    Ok(klav_client::audit::forget_audit_copy(&ctx.home)?
        .into_iter()
        .map(str::to_owned)
        .collect())
}

/// A chain that does not match this device's (exit code 3) names the way
/// out for a server restored from a backup the person trusts.
fn reset_hint(e: CliError) -> CliError {
    const HINT: &str = ". It may be tampering: check the server. If it was restored from a \
                        backup you trust, `klav log reset` makes this device accept the chain \
                        it has now";
    match e {
        CliError::Client(klav_client::ClientError::Security(why)) => {
            CliError::Client(klav_client::ClientError::Security(format!("{why}{HINT}")))
        }
        CliError::Daemon(mut d) if d.code == ErrorCode::Security => {
            d.message.push_str(HINT);
            CliError::Daemon(d)
        }
        other => other,
    }
}

/// `klav log reset` asks first: it is a decision of trust.
fn confirm_log_reset(yes: bool) -> CliResult<()> {
    if yes {
        return Ok(());
    }
    if !std::io::stdin().is_terminal() {
        return Err(CliError::Other(
            "`klav log reset` makes this device accept the server's audit log as it is now: \
             pass --yes to confirm"
                .into(),
        ));
    }
    eprint!(
        "This device will accept the audit log the server has now as the good one. It forgets \
         the copy it downloaded and the head it verified, which are what showed that the \
         server's chain is shorter or different. Do it only if the server was restored from a \
         backup you trust; otherwise, check the server first. Continue? [y/N] "
    );
    let _ = std::io::stderr().flush();
    let mut answer = String::new();
    std::io::stdin().lock().read_line(&mut answer)?;
    if matches!(
        answer.trim().to_lowercase().as_str(),
        "y" | "yes" | "s" | "si" | "sí"
    ) {
        Ok(())
    } else {
        Err(CliError::Other("cancelled".into()))
    }
}

async fn verify(ctx: &mut Ctx, json: bool) -> CliResult<()> {
    let report: VerifyReport = match ctx.backend().await? {
        Backend::Direct(u) => u.verify_audit().await.map_err(|e| reset_hint(e.into()))?,
        Backend::Daemon(d) => call(d, Request::VerifyAudit).await.map_err(reset_hint)?,
    };
    if json {
        return output::json(&report);
    }
    output::info(&format!(
        "The audit log is intact: {} events, {} agent signatures, {} account signatures, {} signed heads.",
        report.events, report.agent_signatures, report.account_signatures, report.heads
    ));
    if let Some(seq) = report.signed_head {
        output::info(&format!("This device's signed head is at event {seq}."));
    }
    // What could not be checked, without being tampering (ADR 0030 §4).
    for warning in &report.warnings {
        output::warn(warning);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use klav_client::audit::LogLine;
    use klav_core::ids::AgentId;

    use super::action;

    fn line(action: &str, by_agent: bool, agent_name: Option<&str>) -> LogLine {
        LogLine {
            seq: 1,
            at: 1,
            actor: if by_agent { "bot" } else { "you" }.into(),
            by_agent,
            agent_id: Some(AgentId::from_bytes([0x1a; 16])),
            agent_name: agent_name.map(str::to_owned),
            action: action.into(),
            permission: None,
            outcome: None,
            item: None,
            item_id: None,
            vault: None,
            reason: None,
            domain: None,
            attachments: Vec::new(),
            task_id: None,
            approval_id: None,
            until: None,
            alerts: Vec::new(),
            verified: false,
            mcp_tool: None,
            local_client: None,
        }
    }

    /// The table says who a grant was for, by name and the start of the
    /// ID, escaped; by ID alone when the name is not known.
    #[test]
    fn a_grant_says_who_it_was_for() {
        assert_eq!(
            action(&line("agent.granted", false, Some("release-bot"))),
            "agent.granted for \"release-bot\" (1a1a1a1a)"
        );
        assert_eq!(
            action(&line("agent.granted", false, Some("a\u{1b}]0;x\u{7}b"))),
            "agent.granted for \"a\\u{1b}]0;x\\u{7}b\" (1a1a1a1a)"
        );
        assert_eq!(
            action(&line("agent.granted", false, None)),
            "agent.granted for agent 1a1a1a1a"
        );
        // Other actions are as before.
        assert_eq!(
            action(&line("agent.revoked", false, Some("bot"))),
            "agent.revoked"
        );
        assert_eq!(
            action(&line("agent.registered", true, Some("bot"))),
            "agent.registered"
        );
    }

    /// The proxy's end of a sandbox reads with its reason, as
    /// docs/try-sandboxes.md quotes it: `sandbox.revoked → theft`.
    #[test]
    fn a_theft_end_reads_with_its_reason() {
        let mut end = line("sandbox.revoked", true, Some("klav-proxy"));
        end.outcome = Some("theft".into());
        assert_eq!(action(&end), "sandbox.revoked → theft");
    }
}
