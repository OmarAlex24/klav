//! `klav proxy …` (ADR 0036 §3, §13, §14): the person's side of the
//! credential proxy. `use`, `grant` and `revoke` ask for Touch ID or the
//! master password in `klavd` (or need the master password to unlock
//! without it), so an agent cannot run them usefully. Nothing printed is a
//! value, a key or a piece of one.

use std::io::{BufRead, IsTerminal, Write};

use klav_client::issuers::{IssuerChangeView, IssuerReport, IssuerSpec};
use klav_client::item_grants::ItemGrantReport;
use klav_client::proxy_admin::{
    OLDER_CLIENTS_PREFERENCES, PairingCheck, ProxyChangeView, ProxyCredentialView, ProxyIssuerView,
    ProxyStatus, REPLACES_AGENT_PREFERENCES,
};
use klav_client::sandboxes::PREFERENCES_BY_AGENT;
use klav_core::model::preferences::ProxyMode;
use klav_daemon::protocol::{ErrorCode, Request};
use klav_proto::agent::AgentStatus;

use super::agent::{with_presence, with_presence_skipping};
use crate::backend::{Backend, call};
use crate::cli::{
    ProxyCommand, ProxyGrantArgs, ProxyIssuerAddArgs, ProxyIssuerCommand, ProxyIssuerRemoveArgs,
    ProxyRevokeArgs, ProxyUseArgs, ProxyUseMode,
};
use crate::context::Ctx;
use crate::error::{CliError, CliResult, EXIT_SECURITY, usage};
use crate::output;

pub(crate) async fn proxy_cmd(ctx: &mut Ctx, cmd: ProxyCommand) -> CliResult<()> {
    match cmd {
        ProxyCommand::Status(flag) => {
            let status = status(ctx).await?;
            if flag.json {
                return output::json(&status);
            }
            print_status(&status);
            if status.mode == ProxyMode::Own && status.agent.is_some() {
                super::proxy_sandboxes::status_line(ctx).await?;
            }
            Ok(())
        }
        ProxyCommand::Use(args) => use_cmd(ctx, args).await,
        ProxyCommand::Grant(args) => grant(ctx, *args).await,
        ProxyCommand::Revoke(args) => revoke(ctx, args).await,
        ProxyCommand::Issuer(ProxyIssuerCommand::Add(args)) => issuer_add(ctx, *args).await,
        ProxyCommand::Issuer(ProxyIssuerCommand::Remove(args)) => issuer_remove(ctx, args).await,
        ProxyCommand::Sandboxes(args) => super::proxy_sandboxes::sandboxes_cmd(ctx, args).await,
    }
}

pub(super) async fn status(ctx: &mut Ctx) -> CliResult<ProxyStatus> {
    match ctx.backend().await? {
        Backend::Direct(u) => Ok(u.proxy_status().await?),
        Backend::Daemon(d) => call(d, Request::ProxyStatus).await.map_err(older_klavd),
    }
}

/// A klavd from before `klav proxy` answers its requests with a generic
/// «malformed request»: say what to do instead.
fn older_klavd(e: CliError) -> CliError {
    match &e {
        CliError::Daemon(body) if body.code == ErrorCode::BadRequest => CliError::Other(
            "The klavd running is older than `klav proxy`. Update klavd to this klav's version and restart it (`klav lock --stop`, then `klav unlock`), then try again.".into(),
        ),
        _ => e,
    }
}

async fn use_cmd(ctx: &mut Ctx, args: ProxyUseArgs) -> CliResult<()> {
    let agent = match (args.mode, args.agent) {
        (ProxyUseMode::Own, Some(agent)) => Some(agent),
        (ProxyUseMode::Own, None) => {
            return Err(usage(
                "name the proxy's agent: `klav proxy use own <agent>` (`klav agent list` shows it)",
            ));
        }
        (ProxyUseMode::None, None) => None,
        (ProxyUseMode::None, Some(_)) => {
            return Err(usage("`klav proxy use none` takes no agent"));
        }
    };
    // Before presence: the first setting creates the preferences item,
    // which older clients skip with a warning. Preferences an agent wrote
    // are what `use` replaces: the problem and what `use` does about it
    // are said here, before Touch ID, on both paths; any other security
    // failure stops here. `prepare_proxy_use` reads them again.
    let mut said_replace = false;
    match status(ctx).await {
        Ok(status) => {
            if status.mode == ProxyMode::None && agent.is_some() {
                output::warn(OLDER_CLIENTS_PREFERENCES);
            }
        }
        Err(e)
            if e.exit_code() == EXIT_SECURITY
                && e.message()
                    .is_some_and(|m| m.contains(PREFERENCES_BY_AGENT)) =>
        {
            output::warn(&e.message().unwrap_or_default());
            output::warn(REPLACES_AGENT_PREFERENCES);
            said_replace = true;
        }
        Err(e) => return Err(e),
    }
    // What was said above is not said again after the write.
    let said = |w: &str| {
        w == OLDER_CLIENTS_PREFERENCES || (said_replace && w.contains(REPLACES_AGENT_PREFERENCES))
    };
    let after = match ctx.backend().await? {
        Backend::Direct(u) => {
            let prepared = u.prepare_proxy_use(agent.as_deref()).await?;
            // The master password unlocked this process: that is the
            // presence here. Said before anything is written.
            for w in prepared.warnings.iter().filter(|w| !said(w)) {
                output::warn(w);
            }
            let resigned = u.commit_proxy_use(prepared).await?;
            for name in &resigned.done {
                output::warn(&format!(
                    "issuer {name:?} now names no proxy: make it an issuer of the new one with `klav proxy issuer add`"
                ));
            }
            if !resigned.failed.is_empty() {
                output::warn(&format!(
                    "the grants of these issuers still name the old proxy; run the same `klav proxy use` again to finish: {}",
                    resigned
                        .failed
                        .iter()
                        .map(|f| format!("{f:?}"))
                        .collect::<Vec<_>>()
                        .join("; ")
                ));
                return Err(CliError::Other("the change is not finished".into()));
            }
            u.proxy_status().await?
        }
        Backend::Daemon(_) => with_presence_skipping(
            ctx,
            |password| Request::ProxyUse {
                agent: agent.clone(),
                password,
            },
            said,
        )
        .await
        .map_err(older_klavd)?,
    };
    if args.json.json {
        return output::json(&after);
    }
    print_status(&after);
    if after.mode == ProxyMode::Own && after.credentials.is_empty() {
        output::info(
            "\nNext: grant it a credential with `klav proxy grant <item> --profile … --upstream … --header … --method … --path-prefix …`. Its first grant asks you to compare its 6 words.",
        );
    }
    Ok(())
}

async fn grant(ctx: &mut Ctx, args: ProxyGrantArgs) -> CliResult<()> {
    // The preset, if any, with every flag given on top: the one spec the
    // preview below shows and klavd's confirmation signs.
    let (spec, note) = super::proxy_preset::grant_spec(&args)?;
    if let Some(note) = note {
        output::info(&note);
    }
    let preview: ProxyChangeView = match ctx.backend().await? {
        Backend::Direct(u) => u.preview_proxy_grant(&args.item, &spec).await?,
        Backend::Daemon(d) => call(
            d,
            Request::ProxyGrantPreview {
                item: args.item.clone(),
                credential: spec.clone(),
            },
        )
        .await
        .map_err(older_klavd)?,
    };
    print_change(&preview);
    for warning in &preview.warnings {
        output::warn(warning);
    }
    // Before presence, so nothing is asked for a grant klavd refuses. klavd
    // checks it again.
    if preview.first_on_account && !args.every_device_updated {
        // Only names the words check below; it does not run it any sooner.
        let words = if preview.first && args.words.is_none() && !std::io::stdin().is_terminal() {
            " and, with no terminal to confirm the proxy's words, --words \"…\" (the six words `klav-proxy init` showed)"
        } else {
            ""
        };
        return Err(usage(format!(
            "this is the account's first per-item grant: update every device first (see the warning above), then run it again with --every-device-is-updated{words}",
        )));
    }
    if preview.mcp_first && !args.every_device_updated {
        return Err(usage(
            "this MCP profile needs every device and klav-proxy on a Klav with the MCP gateway (see the warning above): update them first, then run it again with --every-device-is-updated",
        ));
    }
    // A convenience: klavd's prompt shows the words of the key it signs
    // for, and that is the check that counts.
    let words = if preview.first {
        Some(confirm_words(&preview, args.words.as_deref())?)
    } else {
        None
    };
    let report: ItemGrantReport = match ctx.backend().await? {
        Backend::Direct(u) => {
            let prepared = u
                .prepare_proxy_grant(&args.item, &spec, PairingCheck::Typed(words.as_deref()))
                .await?;
            if prepared.view().base_version != preview.base_version {
                return Err(CliError::Other(format!(
                    "the grant of the proxy {:?} changed meanwhile; run it again",
                    preview.agent
                )));
            }
            if prepared.view().item_id != preview.item_id {
                return Err(CliError::Other(format!(
                    "{:?} names another item than the one shown; nothing granted. Run it again",
                    args.item
                )));
            }
            prepared.require_updated_devices(args.every_device_updated)?;
            u.commit_proxy_change(prepared).await?
        }
        Backend::Daemon(_) => with_presence(ctx, |password| Request::ProxyGrant {
            item: args.item.clone(),
            credential: spec.clone(),
            base_version: preview.base_version,
            every_device_updated: args.every_device_updated,
            shown_words: preview.first.then(|| preview.pairing_code.clone()),
            shown_item: Some(preview.item_id),
            password,
        })
        .await
        .map_err(older_klavd)?,
    };
    if args.json.json {
        output::json(&report)?;
    } else {
        for line in grant_lines(&report, &preview.title, &preview.agent) {
            output::info(&line);
        }
    }
    finished(&report)
}

async fn revoke(ctx: &mut Ctx, args: ProxyRevokeArgs) -> CliResult<()> {
    let report: ItemGrantReport = match ctx.backend().await? {
        Backend::Direct(u) => {
            let prepared = u.prepare_proxy_revoke(&args.item).await?;
            // Before it signs: which issuers lose a profile, by name.
            // (Through klavd, its dialog counts them before presence.)
            for warning in &prepared.view().warnings {
                output::warn(warning);
            }
            u.commit_proxy_change(prepared).await?
        }
        Backend::Daemon(_) => with_presence(ctx, |password| Request::ProxyRevoke {
            item: args.item.clone(),
            password,
        })
        .await
        .map_err(older_klavd)?,
    };
    if args.json.json {
        output::json(&report)?;
    } else {
        for line in revoke_lines(&report, &args.item) {
            output::info(&line);
        }
    }
    finished(&report)
}

async fn issuer_add(ctx: &mut Ctx, args: ProxyIssuerAddArgs) -> CliResult<()> {
    let spec = IssuerSpec {
        profiles: args.profiles,
        url: args.url,
        max_ttl_secs: args.max_ttl.map(|d| d.as_secs()),
        max_live: args.max_live,
        inject_ask: args.inject_ask,
    };
    let preview: IssuerChangeView = match ctx.backend().await? {
        Backend::Direct(u) => u.preview_issuer_add(&args.agent, &spec).await?,
        Backend::Daemon(d) => call(
            d,
            Request::ProxyIssuerPreview {
                agent: args.agent.clone(),
                issuer: spec.clone(),
            },
        )
        .await
        .map_err(older_klavd)?,
    };
    for line in issuer_lines(&preview) {
        output::info(&line);
    }
    for warning in &preview.warnings {
        output::warn(warning);
    }
    if preview.first_on_account && !args.every_device_updated {
        // Only names the words check below; it does not run it any sooner.
        let words = if preview.pending && args.words.is_none() && !std::io::stdin().is_terminal() {
            " and, with no terminal to confirm the agent's words, --words \"…\" (the six words it showed)"
        } else {
            ""
        };
        return Err(usage(format!(
            "this is the account's first sandbox issuer: update every device and klav-proxy first (see the warning above), then run it again with --every-device-is-updated{words}",
        )));
    }
    let words = if preview.pending {
        Some(confirm_agent_words(
            &preview.issuer,
            &preview.pairing_code,
            args.words.as_deref(),
        )?)
    } else {
        None
    };
    let report: IssuerReport = match ctx.backend().await? {
        Backend::Direct(u) => {
            let prepared = u
                .prepare_issuer_add(&args.agent, &spec, PairingCheck::Typed(words.as_deref()))
                .await?;
            let view = prepared.view();
            if view.proxy_base_version != preview.proxy_base_version
                || view.issuer_base_version != preview.issuer_base_version
                || view.issuer_id != preview.issuer_id
                || view.proxy_id != preview.proxy_id
            {
                return Err(CliError::Other(
                    "a grant changed meanwhile; run it again".into(),
                ));
            }
            prepared.require_updated_devices(args.every_device_updated)?;
            u.commit_issuer_change(prepared).await?
        }
        Backend::Daemon(_) => with_presence(ctx, |password| Request::ProxyIssuerAdd {
            agent: args.agent.clone(),
            issuer: spec.clone(),
            proxy_base_version: preview.proxy_base_version,
            issuer_base_version: preview.issuer_base_version,
            shown_issuer: preview.issuer_id,
            shown_proxy: preview.proxy_id,
            every_device_updated: args.every_device_updated,
            shown_words: preview.pending.then(|| preview.pairing_code.clone()),
            password,
        })
        .await
        .map_err(older_klavd)?,
    };
    if args.json.json {
        output::json(&report)?;
    } else {
        for line in issuer_report_lines(&report, &preview) {
            output::info(&line);
        }
    }
    if report.complete() {
        Ok(())
    } else {
        Err(CliError::Other("the change is not finished".into()))
    }
}

async fn issuer_remove(ctx: &mut Ctx, args: ProxyIssuerRemoveArgs) -> CliResult<()> {
    let (report, view): (IssuerReport, Option<IssuerChangeView>) = match ctx.backend().await? {
        Backend::Direct(u) => {
            let prepared = u.prepare_issuer_remove(&args.agent).await?;
            let view = prepared.view().clone();
            (u.commit_issuer_change(prepared).await?, Some(view))
        }
        Backend::Daemon(_) => (
            with_presence(ctx, |password| Request::ProxyIssuerRemove {
                agent: args.agent.clone(),
                password,
            })
            .await
            .map_err(older_klavd)?,
            None,
        ),
    };
    if args.json.json {
        output::json(&report)?;
    } else {
        for line in issuer_remove_lines(&report, view.as_ref().map(|v| v.proxy.as_str())) {
            output::info(&line);
        }
    }
    if report.complete() {
        Ok(())
    } else {
        Err(CliError::Other("the change is not finished".into()))
    }
}

/// `8h`, or `90m` when not whole hours.
fn ttl_words(secs: u64) -> String {
    if secs.is_multiple_of(3600) {
        format!("{}h", secs / 3600)
    } else {
        format!("{}m", secs.div_ceil(60))
    }
}

/// What `klav proxy issuer add` will sign, before presence.
fn issuer_lines(view: &IssuerChangeView) -> Vec<String> {
    let ttl = ttl_words(view.max_ttl_secs);
    let mut lines = vec![
        format!(
            "Let {:?} ({}) start sandboxes through the credential proxy {:?} ({}):",
            view.issuer, view.issuer_id, view.proxy, view.proxy_id
        ),
        format!("  proxy address  {}", view.url),
        format!("  profiles       {}", view.profiles.join(", ")),
        format!(
            "  limits         up to {} at once, each for at most {ttl}",
            view.max_live
        ),
    ];
    if view.inject_ask {
        lines.push("  inject         each `inject` of it asks you first".into());
    }
    if view.pending {
        lines.push(format!(
            "It is pending: this approves it, with no projects. Its words are:\n\n    {}\n",
            view.pairing_code
        ));
    }
    lines
}

/// What an issuer change did, in the state it left.
fn issuer_report_lines(report: &IssuerReport, view: &IssuerChangeView) -> Vec<String> {
    if report.complete() {
        return vec![format!(
            "{:?} may start sandboxes through the proxy {:?} (`klav sandbox start`).",
            view.issuer, view.proxy
        )];
    }
    let failed = report.failed.as_deref().unwrap_or("not finished");
    let state = match (report.issuer_done, report.proxy_done) {
        (false, _) => "nothing changed".to_owned(),
        (true, false) => format!(
            "{:?}'s grant names the proxy, but the proxy does not list it yet, so it refuses its sandboxes",
            view.issuer
        ),
        (true, true) => "both grants changed".to_owned(),
    };
    vec![format!(
        "{failed}: {state}. Run the same command again to finish."
    )]
}

/// What `klav proxy issuer remove` did, in the state it left. The proxy's
/// grant changes first, so a half-done remove already refuses sandboxes.
fn issuer_remove_lines(report: &IssuerReport, proxy: Option<&str>) -> Vec<String> {
    let issuer = &report.issuer.name;
    if report.complete() {
        return vec![format!(
            "{issuer:?} can no longer start sandboxes{}.",
            proxy
                .map(|p| format!(" through the proxy {p:?}"))
                .unwrap_or_default()
        )];
    }
    let failed = report.failed.as_deref().unwrap_or("not finished");
    let state = if report.proxy_done {
        format!(
            "the proxy no longer lists {issuer:?}, so it refuses its sandboxes, but {issuer:?}'s grant still names the proxy"
        )
    } else {
        "nothing changed".to_owned()
    };
    vec![format!(
        "{failed}: {state}. Run the same command again to finish."
    )]
}

/// The words of a pending agent: `--words`, or a y/N on the terminal. A
/// convenience: klavd's dialog shows the words of the key it signs for.
fn confirm_agent_words(agent: &str, pairing_code: &str, given: Option<&str>) -> CliResult<String> {
    let norm = |w: &str| {
        w.split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .to_lowercase()
    };
    if let Some(words) = given {
        if norm(words) != norm(pairing_code) {
            return Err(CliError::Other(format!(
                "nothing signed: the pairing words of {agent:?} do not match; do not approve it"
            )));
        }
        return Ok(words.to_owned());
    }
    if !std::io::stdin().is_terminal() {
        return Err(usage(
            "the agent is pending: pass the six words it showed with --words \"…\"",
        ));
    }
    eprint!("Are they exactly the words the agent showed? [y/N] ");
    let _ = std::io::stderr().flush();
    let mut answer = String::new();
    std::io::stdin().lock().read_line(&mut answer)?;
    if matches!(
        answer.trim().to_lowercase().as_str(),
        "y" | "yes" | "s" | "si" | "sí"
    ) {
        Ok(pairing_code.to_owned())
    } else {
        Err(CliError::Other(
            "nothing signed: the words did not match (deny that agent with `klav agent deny`)"
                .into(),
        ))
    }
}

/// Exits with an error unless everything finished, also with `--json`.
fn finished(report: &ItemGrantReport) -> CliResult<()> {
    if report.complete() {
        Ok(())
    } else {
        Err(CliError::Other("the change is not finished".into()))
    }
}

/// What a `klav proxy grant` did, in the state it left.
fn grant_lines(report: &ItemGrantReport, title: &str, agent: &str) -> Vec<String> {
    let mut lines = Vec::new();
    if report.granted {
        lines.push(format!(
            "{title:?} granted to the proxy {agent:?} (grant version {}).",
            report.agent.grant.as_ref().map_or(0, |g| g.version)
        ));
    } else if !report.unconfirmed.is_empty() {
        lines.push(format!(
            "Not granted: {}. The proxy keeps its old grant, which still lists that item and cannot open its new key.",
            report.failed.as_deref().unwrap_or("the sync failed")
        ));
        lines.extend(unconfirmed_lines(
            report,
            "Run the same command again to finish.",
        ));
    } else if report.rekeyed.is_empty() {
        lines.push(format!(
            "Not granted: {}. Nothing changed: the proxy keeps its grant. Run the same command again.",
            report.failed.as_deref().unwrap_or("the upload failed")
        ));
    } else {
        lines.push(format!(
            "Not granted: {}. The items that dropped out of the grant got new keys, but the proxy's grant was not uploaded: it still lists them and cannot open them. Run the same command again.",
            report.failed.as_deref().unwrap_or("the upload failed")
        ));
    }
    if report.granted && !report.rekeyed.is_empty() {
        lines.push(format!(
            "New keys for {} item(s) that dropped out of the grant.",
            report.rekeyed.len()
        ));
    }
    if !report.gone.is_empty() {
        lines.push(format!(
            "{} item(s) dropped out that this device no longer sees (purged), so there was no key to change: {}. The proxy held those tokens in memory: rotate them at their providers.",
            report.gone.len(),
            ids(&report.gone)
        ));
    }
    lines.extend(regrant_lines(report, None));
    lines
}

/// A key the server took whose sync then failed: changed, not confirmed.
fn unconfirmed_lines(report: &ItemGrantReport, retry: &str) -> Vec<String> {
    let holders = if report.to_reissue.is_empty() {
        "Any other agent that holds it still needs".to_owned()
    } else {
        format!("Agents {} still need", names(&report.to_reissue))
    };
    vec![format!(
        "The key of {} changed on the server, but this device has not confirmed it. {holders} a grant with the new key and cannot open it until then. {retry}",
        ids(&report.unconfirmed)
    )]
}

/// Item IDs, comma-separated.
fn ids(list: &[klav_core::ids::ItemId]) -> String {
    list.iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// What a `klav proxy revoke` did, in the state it left.
fn revoke_lines(report: &ItemGrantReport, item: &str) -> Vec<String> {
    let agent = &report.agent.name;
    let mut lines = Vec::new();
    let failed = report.failed.as_deref().unwrap_or("the upload failed");
    let rotate = "The proxy held this token in memory: rotate it at its provider too, and store the new one in the item.";
    let purged = "this device no longer sees the item (purged), so there was no key to change. The proxy held this token in memory: rotate it at its provider.";
    // A purged item is named only by its ID: the grant's list.
    let target_gone = item
        .trim()
        .parse::<klav_core::ids::ItemId>()
        .is_ok_and(|id| report.gone.contains(&id));
    if report.reissue_only {
        if !report.regranted.is_empty() {
            lines.push(format!(
                "{item:?} was already taken away from the proxy {agent:?}: re-issued the grants of {}.",
                names(&report.regranted)
            ));
        }
    } else if report.granted && target_gone {
        lines.push(format!(
            "{item:?} taken away from the proxy {agent:?}; {purged}"
        ));
        // Other items that dropped out with it may still have changed key.
        if !report.rekeyed.is_empty() {
            lines.push(format!(
                "New keys for {} other item(s) that dropped out of the grant.",
                report.rekeyed.len()
            ));
        }
    } else if report.granted {
        lines.push(format!(
            "{item:?} taken away from the proxy {agent:?}, and its key changed."
        ));
        // ADR 0036 §18: the proxy had the token itself, so a new key
        // protects the vault but not the provider.
        lines.push(rotate.into());
    } else if !report.unconfirmed.is_empty() {
        lines.push(format!(
            "{item:?} is still granted to the proxy {agent:?}: {failed}. Its grant was not changed, and it cannot open the new key."
        ));
        lines.extend(unconfirmed_lines(
            report,
            &format!("Run `klav proxy revoke {item:?}` again to finish."),
        ));
    } else if report.rekeyed.is_empty() {
        lines.push(format!(
            "{item:?} is still granted to the proxy {agent:?}, key not changed: {failed}. Run the same command again."
        ));
    } else {
        lines.push(format!(
            "{item:?}'s key changed, but the proxy's new grant was not uploaded: {failed}. The proxy still lists it and cannot open it. Run the same command again."
        ));
    }
    lines.extend(regrant_lines(report, Some(item)));
    lines
}

/// The other agents' re-issues: those done, and those that failed, who
/// cannot open the items whose key changed until a re-issue succeeds.
fn regrant_lines(report: &ItemGrantReport, item: Option<&str>) -> Vec<String> {
    let mut lines = Vec::new();
    if !report.regranted.is_empty() && !(item.is_some() && report.rekeyed.is_empty()) {
        lines.push(format!(
            "Other agents re-issued with the new keys: {}.",
            names(&report.regranted)
        ));
    }
    if !report.not_regranted.is_empty() {
        let retry = match item {
            Some(item) => format!("`klav proxy revoke {item:?}` runs again"),
            None => format!(
                "`klav proxy revoke <id>` runs for each item that dropped out ({})",
                report
                    .rekeyed
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        };
        lines.push(format!(
            "Agents {} were not re-issued and have lost access to it until {retry}: {}",
            names(
                &report
                    .not_regranted
                    .iter()
                    .map(|f| f.split(':').next().unwrap_or(f).to_owned())
                    .collect::<Vec<_>>()
            ),
            report
                .not_regranted
                .iter()
                .map(|f| format!("{f:?}"))
                .collect::<Vec<_>>()
                .join("; ")
        ));
    }
    lines
}

/// `"a", "b" and "c"`, quoted as `agent approve` prints names.
fn names(list: &[String]) -> String {
    let quoted: Vec<String> = list.iter().map(|n| format!("{n:?}")).collect();
    match quoted.as_slice() {
        [] => String::new(),
        [one] => one.clone(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
}

/// The proxy's words for its first credential: `--words`, or a y/N on the
/// terminal.
fn confirm_words(preview: &ProxyChangeView, given: Option<&str>) -> CliResult<String> {
    if let Some(words) = given {
        let norm = |w: &str| {
            w.split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
                .to_lowercase()
        };
        if norm(words) != norm(&preview.pairing_code) {
            return Err(CliError::Other(format!(
                "nothing granted: the pairing words of {} do not match; do not grant it anything (revoke that agent with `klav agent revoke`)",
                quoted(&preview.agent)
            )));
        }
        return Ok(words.to_owned());
    }
    if !std::io::stdin().is_terminal() {
        return Err(usage(
            "this is the proxy's first credential: pass the six words `klav-proxy init` showed with --words \"…\"",
        ));
    }
    output::info(&format!(
        "\nThis is the first credential of {}. Its pairing words are:\n\n    {}\n",
        quoted(&preview.agent),
        preview.pairing_code
    ));
    eprint!("Are they exactly the words `klav-proxy init` showed? [y/N] ");
    let _ = std::io::stderr().flush();
    let mut answer = String::new();
    std::io::stdin().lock().read_line(&mut answer)?;
    if matches!(
        answer.trim().to_lowercase().as_str(),
        "y" | "yes" | "s" | "si" | "sí"
    ) {
        Ok(preview.pairing_code.clone())
    } else {
        Err(CliError::Other(
            "nothing granted: the words did not match (revoke that agent with `klav agent revoke`)"
                .into(),
        ))
    }
}

/// A name from outside, as `klav agent approve` prints it: escaped.
fn quoted(text: &str) -> String {
    format!("{text:?}")
}

fn print_status(status: &ProxyStatus) {
    match (status.mode, &status.agent) {
        (ProxyMode::Own, Some(agent)) => {
            output::line(&format!(
                "Credential proxy: {} ({}), {}{}",
                quoted(&agent.name),
                agent.id,
                agent.status.as_str(),
                if agent.paused { ", paused" } else { "" }
            ));
            output::line(&format!("Pairing words: {}", agent.pairing_code));
        }
        (ProxyMode::Own, None) => output::line(&format!(
            "Credential proxy: agent {} (not found)",
            status.agent_id.map(|id| id.to_string()).unwrap_or_default()
        )),
        (ProxyMode::Klav, _) => {
            output::line("Credential proxy: Klav's hosted proxy (not supported yet)")
        }
        (ProxyMode::None, _) => output::line("Credential proxy: none"),
    }
    for problem in &status.problems {
        output::warn(problem);
    }
    if status.mode == ProxyMode::Own {
        if status.credentials.is_empty() {
            output::line("No credentials yet.");
        } else {
            output::line("\nCredentials:");
            for credential in &status.credentials {
                for line in credential_lines(credential) {
                    output::line(&line);
                }
            }
        }
        // Absent when not known (an older klavd, or a grant this device
        // cannot read): nothing said, never «none».
        if let Some(issuers) = &status.issuers {
            for line in issuers_lines(issuers) {
                output::line(&line);
            }
        }
        if !status.local_clients.is_empty() {
            output::line("\nLocal MCP clients (`klav client connect <client> --mcp …`):");
            for c in &status.local_clients {
                output::line(&format!("  {}: {}", c.name, c.profiles.join(", ")));
            }
        }
    }
    if !status.lost.is_empty() {
        output::line("\nWithout a working proxy, the account does not have:");
        for lost in &status.lost {
            output::line(&format!("  - {lost}"));
        }
        output::line(
            "Local agents keep working (`klav run`, `inject`, MCP). Set one up: `klav-proxy init`, then `klav proxy use own <agent>`.",
        );
    }
}

/// The agents the proxy's verified grant lets start sandboxes: name and
/// ID, state when not active (the server's word), profiles and limits.
fn issuers_lines(issuers: &[ProxyIssuerView]) -> Vec<String> {
    if issuers.is_empty() {
        return vec!["No sandbox issuers (`klav proxy issuer add`).".into()];
    }
    let mut lines = vec!["\nSandbox issuers:".to_owned()];
    for i in issuers {
        let who = match &i.name {
            Some(name) => format!("{} ({})", quoted(name), i.agent_id),
            None => format!("agent {} (the server no longer lists it)", i.agent_id),
        };
        let state = match i.status {
            Some(AgentStatus::Active) | None => String::new(),
            Some(other) => format!(", {}", other.as_str()),
        };
        lines.push(format!(
            "  {who}{state}: profiles {}; up to {} at once, each for at most {}",
            i.profiles.join(", "),
            i.max_live,
            ttl_words(i.max_ttl_secs)
        ));
    }
    lines
}

/// The lines that describe a credential: its profile and rules.
fn credential_lines(credential: &ProxyCredentialView) -> Vec<String> {
    let title = if credential.title.is_empty() {
        format!("item {}", credential.item_id)
    } else {
        quoted(&credential.title)
    };
    let mut lines = Vec::new();
    match &credential.profile {
        Some(p) => {
            lines.push(format!("  {title} → profile {}", p.name));
            lines.push(format!("      upstream  {}", p.upstream));
            lines.push(format!(
                "      header    {}: {}<{}>",
                p.header,
                p.prefix,
                p.field.as_deref().unwrap_or("value")
            ));
            lines.push(format!("      rate      {} calls/min", p.rate()));
            if let Some(mcp) = &p.mcp {
                lines.push(format!(
                    "      mcp       {}{} (only this path; tools filtered and judged one by one)",
                    p.upstream, mcp.endpoint
                ));
                for h in &mcp.headers {
                    lines.push(format!("      mcp header {}: {}", h.name, quoted(&h.value)));
                }
            }
        }
        None => lines.push(format!("  {title} (no profile)")),
    }
    let any = |list: &[String]| {
        if list.is_empty() {
            "any".to_owned()
        } else {
            list.join(",")
        }
    };
    let is_mcp = credential.profile.as_ref().is_some_and(|p| p.mcp.is_some());
    for rule in credential.rules.iter().filter(|r| r.mcp_tools.is_empty()) {
        lines.push(format!(
            "      {:<9} {} {} {}{}",
            format!("{:?}", rule.effect).to_lowercase(),
            any(&rule.methods),
            rule.hosts.join(","),
            any(&rule.path_prefixes),
            if is_mcp && rule.effect != klav_core::policy::Effect::Deny {
                "   (the MCP session: connect and list tools, never a tool call)"
            } else {
                ""
            }
        ));
    }
    lines.extend(tool_lines(credential));
    lines
}

/// The tool rules of an MCP profile (ADR 0049 §5.3), every pattern in
/// full, grouped by allow, ask and deny, and what happens to the rest.
fn tool_lines(credential: &ProxyCredentialView) -> Vec<String> {
    use klav_core::policy::Effect;
    if !credential.profile.as_ref().is_some_and(|p| p.mcp.is_some()) {
        return Vec::new();
    }
    let mut lines = Vec::new();
    for (effect, label) in [
        (Effect::Allow, "allow"),
        (Effect::Ask, "ask"),
        (Effect::Deny, "deny"),
    ] {
        let mut patterns: Vec<String> = credential
            .rules
            .iter()
            .filter(|r| r.effect == effect)
            .flat_map(|r| r.mcp_tools.iter().cloned())
            .collect();
        patterns.dedup();
        if patterns.is_empty() {
            continue;
        }
        let shown: Vec<String> = patterns
            .iter()
            .map(|p| {
                if p == "*" && effect != Effect::Deny {
                    "* (EVERY tool, also ones the server adds later)".to_owned()
                } else {
                    p.clone()
                }
            })
            .collect();
        lines.push(format!("      tools {label:<5} {}", shown.join(", ")));
    }
    lines.push(
        "      tools other denied and hidden from the agent's list (no rule names them)".to_owned(),
    );
    lines
}

fn print_change(view: &ProxyChangeView) {
    output::info(&format!(
        "Grant to the credential proxy {} ({}):",
        quoted(&view.agent),
        view.agent_id
    ));
    // On stderr: stdout stays for `--json`. Where the item lives, since
    // its title alone may not say which it is.
    if !view.place.is_empty() {
        output::info(&format!(
            "  item {} in {}{}",
            view.item_id,
            quoted(&view.place),
            view.site
                .as_deref()
                .map(|s| format!(", for {}", quoted(s)))
                .unwrap_or_default()
        ));
    }
    if let Some(credential) = &view.credential {
        for line in credential_lines(credential) {
            output::info(&line);
        }
    }
    if view.replaces {
        output::info("It replaces the profile and rules this credential had.");
    }
    for id in &view.dropped {
        output::warn(&format!(
            "item {id} drops out of the proxy's grant: this device no longer sees it where the grant names it"
        ));
    }
}

#[cfg(test)]
mod tests {
    use klav_client::agents::AgentView;
    use klav_core::ids::{AgentId, ItemId};

    use super::*;

    fn report(granted: bool) -> ItemGrantReport {
        ItemGrantReport {
            agent: AgentView {
                id: AgentId::from_bytes([1; 16]),
                name: "klav-proxy".into(),
                note: None,
                status: AgentStatus::Active,
                pairing_code: String::new(),
                created_at: 0,
                expires_at: 0,
                approved_at: None,
                revoked_at: None,
                last_seen_at: None,
                grant: None,
                grant_error: None,
                paused: None,
            },
            granted,
            rekeyed: Vec::new(),
            regranted: Vec::new(),
            not_regranted: Vec::new(),
            failed: None,
            pending: Vec::new(),
            unconfirmed: Vec::new(),
            to_reissue: Vec::new(),
            gone: Vec::new(),
            reissue_only: false,
        }
    }

    fn says(lines: &[String], text: &str) {
        assert!(
            lines.iter().any(|l| l.contains(text)),
            "{text:?} in {lines:?}"
        );
    }

    #[test]
    fn a_revoke_says_the_state_it_left_and_fails_unless_finished() {
        let item = ItemId::generate();
        // Done: the key changed, and the provider's token should too.
        let mut done = report(true);
        done.rekeyed = vec![item];
        assert!(finished(&done).is_ok());
        let lines = revoke_lines(&done, "Northflank");
        says(
            &lines,
            "taken away from the proxy \"klav-proxy\", and its key changed",
        );
        says(&lines, "rotate it at its provider");

        // The key change failed: still granted, nothing changed.
        let mut no_key = report(false);
        no_key.failed = Some("the server refused".into());
        no_key.pending = vec![item];
        assert!(finished(&no_key).is_err());
        says(
            &revoke_lines(&no_key, "Northflank"),
            "is still granted to the proxy \"klav-proxy\", key not changed",
        );

        // The upload failed after the key changed.
        let mut no_upload = report(false);
        no_upload.rekeyed = vec![item];
        no_upload.failed = Some("upload failed".into());
        assert!(finished(&no_upload).is_err());
        says(
            &revoke_lines(&no_upload, "Northflank"),
            "key changed, but the proxy's new grant was not uploaded",
        );

        // A re-issue failed: revoked, but those agents lost access.
        let mut no_reissue = report(true);
        no_reissue.rekeyed = vec![item];
        no_reissue.not_regranted = vec!["ci: offline".into(), "deploy: offline".into()];
        assert!(finished(&no_reissue).is_err());
        let lines = revoke_lines(&no_reissue, "Northflank");
        says(&lines, "and its key changed");
        says(
            &lines,
            "Agents \"ci\" and \"deploy\" were not re-issued and have lost access to it until `klav proxy revoke \"Northflank\"` runs again",
        );

        // The server took the new key and the sync after it failed: the
        // key did change, and the holders still need it.
        let mut unconfirmed = report(false);
        unconfirmed.failed = Some("the key of item x changed on the server, but…".into());
        unconfirmed.unconfirmed = vec![item];
        unconfirmed.to_reissue = vec!["ci".into()];
        assert!(finished(&unconfirmed).is_err());
        let lines = revoke_lines(&unconfirmed, "Northflank");
        says(
            &lines,
            "changed on the server, but this device has not confirmed it",
        );
        says(&lines, "Agents \"ci\" still need a grant with the new key");
        says(&lines, "Run `klav proxy revoke \"Northflank\"` again");
        assert!(
            !lines.iter().any(|l| l.contains("key not changed")),
            "{lines:?}"
        );

        // A purged item: taken away, no key to change, and the token
        // still has to be rotated at its provider, even when another item
        // that dropped out with it did change key.
        let mut purged = report(true);
        purged.gone = vec![item];
        purged.rekeyed = vec![ItemId::generate()];
        assert!(finished(&purged).is_ok());
        let named = item.to_string();
        let lines = revoke_lines(&purged, &named);
        assert!(
            !lines.iter().any(|l| l.contains("and its key changed")),
            "{lines:?}"
        );
        says(&lines, "New keys for 1 other item(s)");
        says(
            &lines,
            "taken away from the proxy \"klav-proxy\"; this device no longer sees the item (purged)",
        );
        says(&lines, "rotate it at its provider");

        // The retry that finishes it.
        let mut retry = report(true);
        retry.reissue_only = true;
        retry.regranted = vec!["ci".into(), "deploy".into()];
        assert!(finished(&retry).is_ok());
        let lines = revoke_lines(&retry, "Northflank");
        says(&lines, "already taken away from the proxy");
        assert!(!lines.iter().any(|l| l.contains("rotate")), "{lines:?}");
    }

    #[test]
    fn a_grant_says_the_state_it_left_and_fails_unless_finished() {
        let ok = report(true);
        assert!(finished(&ok).is_ok());
        says(
            &grant_lines(&ok, "Northflank", "klav-proxy"),
            "granted to the proxy",
        );

        let mut nothing = report(false);
        nothing.failed = Some("the server refused".into());
        assert!(finished(&nothing).is_err());
        says(
            &grant_lines(&nothing, "Northflank", "klav-proxy"),
            "Nothing changed: the proxy keeps its grant",
        );

        let mut dropped = report(true);
        let gone = ItemId::generate();
        dropped.rekeyed = vec![gone];
        dropped.not_regranted = vec!["ci: offline".into()];
        assert!(finished(&dropped).is_err());
        says(
            &grant_lines(&dropped, "Northflank", "klav-proxy"),
            &format!("`klav proxy revoke <id>` runs for each item that dropped out ({gone})"),
        );

        let mut unconfirmed = report(false);
        unconfirmed.unconfirmed = vec![gone];
        unconfirmed.failed = Some("sync failed".into());
        assert!(finished(&unconfirmed).is_err());
        let lines = grant_lines(&unconfirmed, "Northflank", "klav-proxy");
        says(&lines, "Any other agent that holds it still needs a grant");
        says(&lines, "Run the same command again to finish");

        let mut purged = report(true);
        purged.gone = vec![gone];
        says(
            &grant_lines(&purged, "Northflank", "klav-proxy"),
            "no longer sees (purged), so there was no key to change",
        );
    }

    #[test]
    fn names_from_outside_are_escaped() {
        assert_eq!(quoted("evil\n\u{1b}[2J"), "\"evil\\n\\u{1b}[2J\"");
        assert_eq!(names(&["a\"b".into()]), "\"a\\\"b\"");
    }

    /// The issuers of the proxy's grant: name and ID, a state other than
    /// active, the profiles and limits; one the server no longer lists by
    /// ID; none says how to add one.
    #[test]
    fn status_lists_the_issuers() {
        let issuer = |name: Option<&str>, status: Option<AgentStatus>| ProxyIssuerView {
            agent_id: AgentId::from_bytes([2; 16]),
            name: name.map(str::to_owned),
            status,
            profiles: vec!["railway".into(), "northflank".into()],
            max_ttl_secs: 8 * 3600,
            max_live: 2,
        };
        let id = AgentId::from_bytes([2; 16]);
        assert_eq!(
            issuers_lines(&[
                issuer(Some("t3-code"), Some(AgentStatus::Active)),
                issuer(Some("t3\u{1b}[2J"), Some(AgentStatus::Pending)),
                issuer(None, None),
            ]),
            [
                "\nSandbox issuers:".to_owned(),
                format!(
                    "  \"t3-code\" ({id}): profiles railway, northflank; up to 2 at once, each for at most 8h"
                ),
                format!(
                    "  \"t3\\u{{1b}}[2J\" ({id}), pending: profiles railway, northflank; up to 2 at once, each for at most 8h"
                ),
                format!(
                    "  agent {id} (the server no longer lists it): profiles railway, northflank; up to 2 at once, each for at most 8h"
                ),
            ]
        );
        assert_eq!(
            issuers_lines(&[]),
            ["No sandbox issuers (`klav proxy issuer add`)."]
        );
    }
}
