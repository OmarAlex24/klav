//! `health`: the vault health report (ADR 0022 §4). It names items, hosts
//! and reasons; it never shows a value.

use std::io::{BufRead, IsTerminal, Write};

use klav_client::health::{
    AgeSource, BREACH_CHECK_NOTICE, BreachReport, HealthItem, HealthSettings, VaultHealth,
};
use klav_client::offer::{OfferRequest, OfferRow, ReusedOffer, block_text};
use klav_client::tasks::TaskCard;
use klav_core::model::reference::{same_name, same_path};
use klav_core::policy::Permission;
use klav_daemon::protocol::Request;

use crate::backend::Backend;
use crate::cli::{HealthArgs, HealthCommand, OnOff};
use crate::commands::agent::with_presence;
use crate::context::Ctx;
use crate::error::{CliError, CliResult, usage};
use crate::output;
use crate::time::format_utc;

pub(crate) async fn health_cmd(ctx: &mut Ctx, args: HealthArgs) -> CliResult<()> {
    if let Some(HealthCommand::BreachCheck { state }) = args.command {
        return breach_check(ctx, state);
    }
    if let Some(agent) = args.fix_with.clone() {
        return fix_with(ctx, &agent, args).await;
    }
    let report = ctx.backend().await?.vault_health().await?;
    if args.json.json {
        return output::json(&report);
    }
    print_report(&report);
    Ok(())
}

/// The breach check setting: local to this home, and it says what it sends.
fn breach_check(ctx: &Ctx, state: Option<OnOff>) -> CliResult<()> {
    let mut settings = HealthSettings::load(&ctx.home)?;
    if let Some(state) = state {
        settings.breach_check = state == OnOff::On;
        settings.save(&ctx.home)?;
    }
    output::line(&format!(
        "Breach check: {}",
        if settings.breach_check { "on" } else { "off" }
    ));
    output::info(BREACH_CHECK_NOTICE);
    if !settings.breach_check {
        output::info("Turn it on with `klav health breach-check on`.");
    }
    Ok(())
}

fn site(item: &HealthItem) -> String {
    item.hosts.join(", ")
}

fn name(item: &HealthItem) -> String {
    if item.field == "password" {
        item.title.clone()
    } else {
        format!("{} ({})", item.title, item.field_label)
    }
}

fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

fn print_report(report: &VaultHealth) {
    output::line(&format!(
        "Checked {} in {}.",
        plural(report.passwords, "password", "passwords"),
        plural(report.items, "item", "items"),
    ));
    if report.skipped > 0 {
        output::warn(&format!(
            "{} could not be opened and were left out",
            plural(report.skipped, "item", "items")
        ));
    }

    output::line("");
    output::line(&format!(
        "Reused: {}",
        plural(report.reused.len(), "group", "groups")
    ));
    for (i, group) in report.reused.iter().enumerate() {
        output::line(&format!(
            "  {}. same password in {}:",
            i + 1,
            plural(group.items.len(), "item", "items")
        ));
        for item in &group.items {
            let host = site(item);
            if host.is_empty() {
                output::line(&format!("     {}", name(item)));
            } else {
                output::line(&format!("     {}  {host}", name(item)));
            }
        }
    }

    output::line("");
    output::line(&format!("Weak: {}", report.weak.len()));
    if !report.weak.is_empty() {
        let rows: Vec<Vec<String>> = report
            .weak
            .iter()
            .map(|w| {
                let why = match w.generated_bits {
                    Some(bits) if bits < 40 => format!("generated, {bits} bits"),
                    _ => format!("strength {}/4", w.score),
                };
                vec![name(&w.item), site(&w.item), why]
            })
            .collect();
        output::table(&["ITEM", "SITE", "WHY"], &rows);
    }

    output::line("");
    output::line(&format!(
        "Old (unchanged for over a year): {}",
        report.old.len()
    ));
    if !report.old.is_empty() {
        let rows: Vec<Vec<String>> = report
            .old
            .iter()
            .map(|o| {
                let since = format_utc(o.since_ms);
                let since = match o.source {
                    AgeSource::Record => since,
                    AgeSource::Created => format!("{since} (created)"),
                };
                vec![name(&o.item), site(&o.item), since, o.days.to_string()]
            })
            .collect();
        output::table(&["ITEM", "SITE", "SINCE", "DAYS"], &rows);
    }

    output::line("");
    match &report.breaches {
        BreachReport::Off => {
            output::line("Breached: not checked (the breach check is off)");
            output::info("See `klav health breach-check` for what it sends before turning it on.");
        }
        BreachReport::Checked { found, .. } => {
            output::line(&format!("Breached: {}", found.len()));
            if !found.is_empty() {
                let rows: Vec<Vec<String>> = found
                    .iter()
                    .map(|b| vec![name(&b.item), site(&b.item), b.count.to_string()])
                    .collect();
                output::table(&["ITEM", "SITE", "TIMES SEEN"], &rows);
            }
        }
        BreachReport::Failed { message } => {
            output::line("Breached: not checked");
            output::warn(&format!("the breach check failed: {message}"));
        }
    }
    if report.is_clean() {
        output::line("");
        output::line("Nothing needs attention.");
    }
}

// ------------------------------------------------- `health --fix-with`

/// Whether `text` names `row`: its ID, `klav://` reference, title or the
/// last part of the reference (case-insensitive). References and their
/// last part match written as shown or percent-encoded (`Mi%20banco`).
fn names(row: &OfferRow, text: &str) -> bool {
    let text = text.trim();
    row.item_id.to_string() == text
        || row.reference.eq_ignore_ascii_case(text)
        || same_path(&row.reference, text)
        || row.title.eq_ignore_ascii_case(text)
        || row
            .reference
            .rsplit_once('/')
            .is_some_and(|(_, last)| last.eq_ignore_ascii_case(text) || same_name(last, text))
}

/// The rows `--only` or `--skip` name; every name must match one row.
fn named<'a>(rows: &'a [OfferRow], wanted: &[String]) -> CliResult<Vec<&'a OfferRow>> {
    let mut found = Vec::new();
    for text in wanted {
        let hits: Vec<&OfferRow> = rows.iter().filter(|r| names(r, text)).collect();
        match hits.as_slice() {
            [one] => found.push(*one),
            [] => {
                return Err(usage(format!(
                    "{text:?} is not among the logins that share a password"
                )));
            }
            _ => {
                return Err(usage(format!(
                    "{text:?} names several logins; use its klav:// reference"
                )));
            }
        }
    }
    Ok(found)
}

fn print_offer_rows(rows: &[OfferRow], chosen: &[bool]) {
    for (i, (row, on)) in rows.iter().zip(chosen).enumerate() {
        let mark = match (row.blocked, on) {
            (Some(_), _) => "-",
            (None, true) => "x",
            (None, false) => " ",
        };
        let mut head = format!("  {:>2}. [{mark}] {}", i + 1, row.reference);
        if let Some(user) = &row.username {
            head.push_str(&format!("  ({user})"));
        }
        if let Some(group) = row.group {
            head.push_str(&format!("  group {group}"));
        }
        output::line(&head);
        if let Some(block) = row.blocked {
            output::line(&format!(
                "          cannot go in the task: {}",
                block_text(block)
            ));
            continue;
        }
        if let Some(page) = &row.change_url {
            output::line(&format!("          change it at {}", page.url));
        }
        if row.permissions.contains(&Permission::Totp) {
            output::line(
                "          + one-time code (added by Klav): 2FA stops being a second factor for this agent",
            );
        }
    }
}

fn read_answer(prompt: &str) -> CliResult<String> {
    eprint!("{prompt}");
    let _ = std::io::stderr().flush();
    let mut answer = String::new();
    std::io::stdin().lock().read_line(&mut answer)?;
    Ok(answer.trim().to_owned())
}

/// Lets the person uncheck rows by number, on a terminal.
fn choose_on_terminal(rows: &[OfferRow], chosen: &mut [bool]) -> CliResult<()> {
    loop {
        let answer = read_answer(
            "Numbers to leave out or put back, separated by spaces (Enter to go on): ",
        )?;
        if answer.is_empty() {
            return Ok(());
        }
        for part in answer.split([' ', ',']).filter(|p| !p.is_empty()) {
            match part.parse::<usize>() {
                Ok(n) if (1..=rows.len()).contains(&n) && rows[n - 1].blocked.is_none() => {
                    chosen[n - 1] = !chosen[n - 1];
                }
                _ => output::warn(&format!("{part:?} is not a number on the list")),
            }
        }
        print_offer_rows(rows, chosen);
    }
}

/// `klav health --fix-with <agent>` (ADR 0022 §6).
async fn fix_with(ctx: &mut Ctx, agent: &str, args: HealthArgs) -> CliResult<()> {
    let offer: ReusedOffer = ctx.backend().await?.reused_offer(agent).await?;
    let agent_name = offer
        .agent
        .as_ref()
        .map_or_else(|| agent.to_owned(), |a| a.name.clone());
    if offer.rows.is_empty() {
        output::info("No login shares its password with another item: nothing to fix.");
        return Ok(());
    }
    let rows = offer.rows;
    let mut chosen: Vec<bool> = rows.iter().map(|r| r.blocked.is_none()).collect();
    if !args.only.is_empty() {
        let only = named(&rows, &args.only)?;
        for (i, row) in rows.iter().enumerate() {
            chosen[i] = row.blocked.is_none() && only.iter().any(|o| o.item_id == row.item_id);
        }
    }
    for skip in named(&rows, &args.skip)? {
        if let Some(i) = rows.iter().position(|r| r.item_id == skip.item_id) {
            chosen[i] = false;
        }
    }
    if let Some(row) = named(&rows, &args.only)?
        .into_iter()
        .find(|r| r.blocked.is_some())
    {
        return Err(usage(format!(
            "{} cannot go in the task: {}",
            row.reference,
            block_text(row.blocked.expect("blocked"))
        )));
    }
    let terminal = std::io::stdin().is_terminal();
    if !args.json.json {
        output::line(&format!(
            "Logins that share a password with another item ({}), for {agent_name}:",
            rows.len()
        ));
        print_offer_rows(&rows, &chosen);
    }
    if terminal && !args.yes && args.only.is_empty() && args.skip.is_empty() {
        choose_on_terminal(&rows, &mut chosen)?;
    }
    let items: Vec<_> = rows
        .iter()
        .zip(&chosen)
        .filter(|(_, on)| **on)
        .map(|(r, _)| r.item_id)
        .collect();
    if items.is_empty() {
        return Err(usage("nothing left to offer"));
    }
    let duration_secs = args.duration.map_or(offer.duration_secs, |d| d.as_secs());
    let request = OfferRequest {
        agent: offer
            .agent
            .as_ref()
            .map_or_else(|| agent.to_owned(), |a| a.id.to_string()),
        items,
        task: args.task.clone(),
        reason: args.reason.clone(),
        duration_secs: Some(duration_secs),
    };
    output::info(&format!(
        "{agent_name} will get the task «{}» with the sites of these {} logins, never which ones share a password. It changes each password on its site through your browser with Klav, without seeing the old one or the new one.",
        request.task.as_deref().unwrap_or(&offer.task),
        request.items.len()
    ));
    if !args.yes {
        if !terminal {
            return Err(usage(
                "add --yes to offer the task without a terminal (choose with --only or --skip)",
            ));
        }
        let answer = read_answer(&format!(
            "Offer {agent_name} this task for {}? [y/N] ",
            crate::commands::task::minutes_text(i64::try_from(duration_secs).unwrap_or(0) * 1000)
        ))?;
        if !matches!(
            answer.to_lowercase().as_str(),
            "y" | "yes" | "s" | "si" | "sí"
        ) {
            return Err(CliError::Other("not offered".into()));
        }
    }
    let card: TaskCard = match ctx.backend().await? {
        Backend::Direct(u) => u.offer_task(&request).await?,
        Backend::Daemon(_) => {
            with_presence(ctx, |password| Request::OfferTask {
                offer: request.clone(),
                password,
            })
            .await?
        }
    };
    if args.json.json {
        return output::json(&card);
    }
    output::info(&format!(
        "Offered: {} sees task {} with `list_tasks` until {}. Follow it with `klav log --task {}`.",
        card.agent,
        card.id,
        card.expires_at.map(format_utc).unwrap_or_default(),
        card.id
    ));
    Ok(())
}

#[cfg(test)]
mod tests {
    use klav_core::ids::{ItemId, ProjectId, VaultId};

    use super::*;

    fn row(reference: &str, title: &str) -> OfferRow {
        OfferRow {
            item_id: ItemId::generate(),
            vault_id: VaultId::generate(),
            project_id: ProjectId::generate(),
            reference: reference.into(),
            title: title.into(),
            username: None,
            hosts: vec![],
            change_url: None,
            group: None,
            permissions: vec![],
            blocked: None,
        }
    }

    #[test]
    fn rows_match_references_as_shown_or_encoded() {
        // References are shown with names as written; what older versions
        // showed (and people saved in scripts) still names the same row.
        let r = row("klav://Personal/General/Mi banco", "Mi banco");
        for text in [
            "klav://Personal/General/Mi banco",
            "klav://Personal/General/Mi%20banco",
            "klav://personal/general/MI BANCO",
            "Mi banco",
            "Mi%20banco",
            &r.item_id.to_string(),
        ] {
            assert!(names(&r, text), "{text}");
        }
        assert!(!names(&r, "klav://Personal/General/Mi"));

        let r = row("klav://Bóveda/a%2Fb/50%25 off", "50% off");
        for text in [
            "klav://B%C3%B3veda/a%2Fb/50%25%20off",
            "klav://bóveda/A%2FB/50%25 off",
            "50% off",
            "50%25 off",
        ] {
            assert!(names(&r, text), "{text}");
        }
    }
}
