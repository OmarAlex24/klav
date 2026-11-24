//! `agent`: registration (agent side) and approval (person side), design
//! §5.1 and ADR 0014.

use std::io::{BufRead, IsTerminal, Write};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use klav_client::agents::{AgentView, ApprovalView, GrantRequest};
use klav_client::grant_change::{ChangePolicy, GrantChange, GrantChangePreview, GrantChangeReport};
use klav_client::ops::SecretText;
use klav_client::revoke::{Exposure, PendingRevocation, RevokeReport};
use klav_core::ids::AgentId;
use klav_core::policy::{Effect, Permission, Policy, Rule, Scope, TimeWindow};
use klav_daemon::client::DaemonClient;
use klav_daemon::protocol::{ErrorCode, PauseInEffect, Request};
use klav_proto::agent::AgentStatus;
use klav_sdk::{Agent, AgentState, KeyStore, KeyStoreChoice, Registration};

use crate::backend::{Backend, call};
use crate::cli::{
    AgentApproveArgs, AgentCommand, AgentPauseArgs, AgentRegisterArgs, AgentResumeArgs,
    AgentStatusArgs, AgentTotpArgs, ApprovalCommand, KeyStoreArg,
};
use crate::context::Ctx;
use crate::error::{CliError, CliResult, usage};
use crate::output;

pub(crate) async fn agent_cmd(ctx: &mut Ctx, cmd: AgentCommand) -> CliResult<()> {
    match cmd {
        AgentCommand::Register(args) => register(ctx, args).await,
        AgentCommand::Status(args) => status(ctx, args).await,
        AgentCommand::List(flag) => {
            let agents = agents(ctx).await?;
            if flag.json {
                return output::json(&agents);
            }
            print_agents(&agents);
            Ok(())
        }
        AgentCommand::Approve(args) => approve(ctx, args).await,
        AgentCommand::Totp(args) => agent_totp(ctx, args).await,
        AgentCommand::Run(args) => super::agent_actions::run_cmd(ctx, args).await,
        AgentCommand::Inject(args) => super::agent_actions::inject_cmd(ctx, args).await,
        AgentCommand::Fill(args) => super::agent_actions::fill_cmd(ctx, args).await,
        AgentCommand::Browser(cmd) => super::agent_actions::browser_cmd(ctx, cmd),
        AgentCommand::Task(cmd) => super::task::agent_task_cmd(ctx, cmd).await,
        AgentCommand::SecretRequest(cmd) => {
            super::secret_request::agent_secret_request_cmd(ctx, cmd).await
        }
        AgentCommand::Show { agent, json } => {
            let found = find(ctx, &agent).await?;
            let exposure: Exposure = match ctx.backend().await? {
                Backend::Direct(u) => u.agent_exposure(found.id).await?,
                Backend::Daemon(d) => call(d, Request::AgentExposure { agent: found.id }).await?,
            };
            if json.json {
                return output::json(&exposure);
            }
            print_agents(std::slice::from_ref(&exposure.agent));
            if let Some(grant) = &exposure.agent.grant {
                output::info(&format!(
                    "Grant v{} ({} rules{}).",
                    grant.version,
                    grant.policy.rules.len(),
                    grant
                        .policy
                        .expires_at
                        .map(|t| format!(
                            ", expires {}",
                            crate::time::format_utc(
                                i64::try_from(t).unwrap_or(i64::MAX / 1000) * 1000
                            )
                        ))
                        .unwrap_or_default()
                ));
            }
            print_exposure(&exposure);
            if exposure.agent.status == AgentStatus::Revoked {
                print_revocation_left(ctx, &exposure.agent).await;
            }
            Ok(())
        }
        AgentCommand::Revoke {
            agent,
            rotate,
            yes,
            json,
        } => revoke(ctx, &agent, rotate, yes, json.json).await,
        AgentCommand::Pause(args) => pause(ctx, args).await,
        AgentCommand::Resume(args) => resume(ctx, args).await,
        AgentCommand::Deny { agent } => {
            let found = find(ctx, &agent).await?;
            match ctx.backend().await? {
                Backend::Direct(u) => u.deny_agent(found.id).await?,
                Backend::Daemon(d) => {
                    let _: serde_json::Value =
                        call(d, Request::DenyAgent { agent: found.id }).await?;
                }
            }
            output::info(&format!("Agent {} denied.", found.name));
            Ok(())
        }
    }
}

// ---------------------------------------------------------------- agent side

async fn register(ctx: &mut Ctx, args: AgentRegisterArgs) -> CliResult<()> {
    let account = klav_client::account(&ctx.home).ok();
    let server = match args
        .server
        .or_else(|| account.as_ref().map(|a| a.server.clone()))
    {
        Some(server) => server,
        None => crate::commands::account::choose_server(None)?,
    };
    let email = args
        .email
        .or_else(|| account.as_ref().map(|a| a.email.clone()))
        .ok_or_else(|| usage("give the account e-mail with --email"))?;
    let choice = match args.key_store {
        KeyStoreArg::Auto => KeyStoreChoice::Auto,
        KeyStoreArg::Keychain => KeyStoreChoice::Keychain,
        KeyStoreArg::File => KeyStoreChoice::File,
    };
    let key_store = KeyStore::choose(&ctx.home, &args.name, choice, args.key_file.as_deref())?;
    let (_, registered) = Agent::register(
        &ctx.home,
        Registration {
            name: args.name,
            server,
            email: email.clone(),
            note: args.note,
            key_store,
        },
    )
    .await?;
    if args.json {
        return output::json(&registered);
    }
    output::info(&format!(
        "Agent {:?} registered ({}); its key is in the {}.",
        registered.name, registered.agent_id, registered.key_store
    ));
    output::info(&format!(
        "Ask the owner of {email} to approve it within {} with the command for what it does, and to check that the words match:\n",
        human_minutes(registered.expires_at)
    ));
    output::line(&format!("    {}", registered.pairing_code));
    output::info(&format!(
        "\nIf it reads projects:\n\n    klav agent approve {name} --project <vault/project>\n\nIf it starts sandboxes (never give it projects):\n\n    klav proxy issuer add {name} --profile … --url …\n\nA credential proxy registers with `klav-proxy init`, not with this command.\nThen check it with `klav agent status --wait`.",
        name = registered.name
    ));
    Ok(())
}

fn human_minutes(until_ms: i64) -> String {
    let left = (until_ms - now_ms()).max(0) / 60_000;
    format!("{left} minutes")
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

async fn status(ctx: &mut Ctx, args: AgentStatusArgs) -> CliResult<()> {
    let name = klav_sdk::config::pick(&ctx.home, args.agent.as_deref())?;
    let mut agent = Agent::load(&ctx.home, &name)?;
    let mut state = agent.state().await?;
    if args.wait {
        let mut announced = false;
        while state.status == AgentStatus::Pending {
            if !announced {
                output::info(&format!(
                    "Waiting for approval (pairing words: {})…",
                    state.pairing_code
                ));
                announced = true;
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
            state = agent.state().await?;
        }
    }
    if args.json.json {
        output::json(&state)?;
    } else {
        print_state(&state);
        if let Some(note) = crate::commands::skill::outdated_note(ctx) {
            output::info(&note);
        }
    }
    if args.wait && state.status != AgentStatus::Active {
        if state.lapsed {
            return Err(CliError::Other(format!(
                "the request of agent {} lapsed without a decision: nobody approved or denied it. `klav client connect` asks again",
                state.name
            )));
        }
        return Err(CliError::Other(format!(
            "agent {} is {}",
            state.name,
            state.status.as_str()
        )));
    }
    // Approved, but paused: it cannot work yet (exit 7, ADR 0033 §7.4).
    if args.wait && state.paused.is_some() {
        return Err(klav_client::ClientError::Paused(state.paused).into());
    }
    // The account waits to be deleted: it never will work (exit 8, ADR
    // 0037 §3).
    if args.wait && state.account_delete_at.is_some() {
        return Err(klav_client::ClientError::AccountDeleting(state.account_delete_at).into());
    }
    Ok(())
}

fn print_state(s: &AgentState) {
    output::line(&format!("agent:     {} ({})", s.name, s.agent_id));
    output::line(&format!("server:    {}", s.server));
    output::line(&format!(
        "status:    {}{}",
        s.status.as_str(),
        if s.lapsed {
            " (the request lapsed without a decision)"
        } else {
            ""
        }
    ));
    output::line(&format!("words:     {}", s.pairing_code));
    if let Some(code) = &s.account_code {
        output::line(&format!("account:   {code}"));
    }
    if let Some(p) = &s.paused {
        output::line(&format!(
            "paused:    {} since {}{}",
            match p.scope {
                klav_proto::agent::PauseScope::All => "every agent",
                klav_proto::agent::PauseScope::Agent => "this agent",
            },
            crate::time::format_utc(p.since),
            p.until
                .map(|t| format!(", until {}", crate::time::format_utc(t)))
                .unwrap_or_else(|| ", until the person resumes".into())
        ));
    }
    if let Some(at) = s.account_delete_at {
        output::line(&format!(
            "deleting:  the person asked Klav to delete the account on {} UTC; every action is refused until then",
            crate::time::format_utc(at)
        ));
    }
    if let Some(version) = s.grant_version {
        output::line(&format!(
            "grant:     version {version}, {} project(s){}",
            s.projects,
            s.expires_at
                .map(|t| format!(", expires at {t} (Unix)"))
                .unwrap_or_default()
        ));
    }
}

// --------------------------------------------------------------- person side

pub(crate) async fn agents(ctx: &mut Ctx) -> CliResult<Vec<AgentView>> {
    match ctx.backend().await? {
        Backend::Direct(u) => Ok(u.agents().await?),
        Backend::Daemon(d) => call(d, Request::Agents).await,
    }
}

async fn find(ctx: &mut Ctx, wanted: &str) -> CliResult<AgentView> {
    let all = agents(ctx).await?;
    Ok(klav_client::agents::find_agent(all, wanted)?)
}

/// The "what it saw" report.
fn print_exposure(exposure: &Exposure) {
    let name = &exposure.agent.name;
    if !exposure.projects.is_empty() {
        output::info(&format!(
            "{name} held the keys of: {}. It could read the titles, usernames and URLs of their items.",
            exposure
                .projects
                .iter()
                .map(|p| format!("{}/{}", p.vault, p.project))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if let Some(warning) = &exposure.log_warning {
        output::warn(warning);
        return;
    }
    if exposure.items.is_empty() {
        output::info(&format!(
            "The audit log shows no item used by {name} ({} denied attempts).",
            exposure.denied
        ));
        return;
    }
    let rows: Vec<Vec<String>> = exposure
        .items
        .iter()
        .map(|i| {
            let id = i.item_id.to_string();
            let mut item = i.reference.clone().unwrap_or_else(|| id.clone());
            if i.deleted {
                item.push_str(" (deleted)");
            } else if i.trashed {
                item.push_str(" (in trash)");
            }
            vec![
                id.chars().take(8).collect(),
                item,
                i.permissions.join(","),
                match (i.secret, i.attachments) {
                    (true, 0) => "yes",
                    (true, _) => "yes (file)",
                    (false, _) => "no",
                }
                .to_owned(),
                i.uses.to_string(),
                crate::time::format_utc(i.last_at),
            ]
        })
        .collect();
    output::info(&format!("What {name} used (from the audit log):"));
    output::table(
        &["ID", "ITEM", "PERMISSIONS", "SECRET", "USES", "LAST"],
        &rows,
    );
    if exposure.denied > 0 {
        output::info(&format!("{} attempts were denied.", exposure.denied));
    }
    if exposure.items.iter().any(|i| i.secret) {
        output::warn(
            "It obtained the secrets marked `yes`: change them where they are used (the site, the API) if you no longer trust it.",
        );
    }
}

/// What a key change still owes for `agent`, from this device's record
/// (ADR 0033, amendment of 2026-11-10, F4 `agent_revocations`): a
/// revocation's, or a narrowing's. Says nothing when nothing is left, or
/// when an older `klavd` cannot tell; a record that cannot be read is said.
async fn print_revocation_left(ctx: &mut Ctx, agent: &AgentView) {
    let pending: Vec<PendingRevocation> = match ctx.backend().await {
        Ok(Backend::Direct(u)) => match u.pending_revocations() {
            Ok(list) => list,
            Err(e) => {
                output::warn(&e.to_string());
                return;
            }
        },
        Ok(Backend::Daemon(d)) => match d.call(Request::AgentRevocations).await {
            Ok((list, _)) => list,
            // An older klavd does not know the request.
            Err(e) if e.code == ErrorCode::BadRequest => return,
            Err(e) => {
                output::warn(&e.message);
                return;
            }
        },
        Err(_) => return,
    };
    let Some(left) = pending.iter().find(|p| p.agent_id == agent.id) else {
        return;
    };
    if let Some(text) = revocation_left_text(left, &agent.id.to_string()) {
        output::warn(&text);
    }
}

/// Whether the person asked for the projects' keys to change (P7 of the
/// ADR 0033 amendment of 2026-11-10). `without_key_change` says they
/// declined. A `klavd` older than it doesn't send the field, but it counts
/// projects, and writes unknown projects, an unread log or grants to issue
/// again, only for a revocation with the key change. Nothing to tell it
/// from: declined, so no hint ever changes a key nobody asked for.
fn key_change_asked(left: &PendingRevocation) -> bool {
    !left.without_key_change
        && !left.narrowed
        && (!left.projects.is_empty()
            || left.unknown_projects
            || left.log_unchecked
            || !left.regrants.is_empty())
}

/// [`print_revocation_left`]'s words. `None` when nothing is left to say.
/// A hint to finish it runs `klav agent revoke` with `--rotate` only when
/// the person asked for the projects' keys to change.
fn revocation_left_text(left: &PendingRevocation, agent: &str) -> Option<String> {
    let asked = key_change_asked(left);
    if left.unknown_projects && asked {
        return Some(
            "This device does not know which projects the agent had, so their keys did not change. Check the audit log with `klav log verify`, then revoke it again with `--rotate`.".into(),
        );
    }
    let mut parts = Vec::new();
    if !left.pending.is_empty() || !left.regrants.is_empty() || !left.rotated.is_empty() {
        let mut text = if left.narrowed {
            format!(
                "Keys of the projects taken away from it still to change: {} of {} changed",
                left.rotated.len(),
                left.projects.len()
            )
        } else {
            format!(
                "Keys still to change: {} of {} projects rotated",
                left.rotated.len(),
                left.projects.len()
            )
        };
        if !left.pending.is_empty() {
            text.push_str(&format!("; left: {}", left.pending.join(", ")));
        }
        if !left.regrants.is_empty() {
            text.push_str(&format!(
                "; other agents still waiting for a grant with the new key of: {}",
                left.regrants.join(", ")
            ));
        }
        if !left.pending.is_empty() || !left.regrants.is_empty() {
            parts.push(text);
        }
    }
    if left.items > 0 {
        parts.push(format!(
            "{} item(s) shared with it one by one still need a new key",
            left.items
        ));
    }
    if left.log_unchecked {
        parts.push(
            "the audit log, which lists every project it was granted, has not been read for this key change yet, so it is not done".into(),
        );
    }
    let working = !parts.is_empty();
    if !left.skipped.is_empty() {
        parts.push(format!(
            "these keys cannot change from this device: {}",
            left.skipped.join("; ")
        ));
    }
    if parts.is_empty() {
        return None;
    }
    let mut text = parts.join(". ");
    if let Some(why) = &left.last_error {
        text.push_str(&format!(". It stopped: {why}"));
    }
    if working {
        if left.narrowed {
            text.push_str(". klavd goes on by itself when it unlocks.");
        } else if asked {
            text.push_str(&format!(
                ". klavd finishes it by itself when it unlocks; or run `klav agent revoke {agent} --rotate`."
            ));
        } else if left.without_key_change {
            // Declined: only the items shared one by one are owed, and
            // `--rotate` would change every project key the person kept.
            text.push_str(&format!(
                ". klavd finishes it by itself when it unlocks; or run `klav agent revoke {agent}` (without `--rotate`: you chose not to change its projects' keys)."
            ));
        } else {
            // Asked, with no project to change (a credential proxy holds
            // only items): nothing says the person declined anything.
            text.push_str(&format!(
                ". klavd finishes it by itself when it unlocks; or run `klav agent revoke {agent}`."
            ));
        }
    } else {
        text.push('.');
    }
    Some(text)
}

async fn revoke(ctx: &mut Ctx, wanted: &str, rotate: bool, yes: bool, json: bool) -> CliResult<()> {
    let found = find(ctx, wanted).await?;
    if !yes && std::io::stdin().is_terminal() {
        eprint!(
            "Revoke agent {:?} ({})? It must register again to come back. [y/N] ",
            found.name, found.id
        );
        let _ = std::io::stderr().flush();
        let mut answer = String::new();
        std::io::stdin().lock().read_line(&mut answer)?;
        if !matches!(
            answer.trim().to_lowercase().as_str(),
            "y" | "yes" | "s" | "si" | "sí"
        ) {
            return Err(CliError::Other("not revoked".into()));
        }
    }
    let report: RevokeReport = match ctx.backend().await? {
        Backend::Direct(u) => u.revoke_agent(found.id, rotate).await?,
        Backend::Daemon(d) => {
            call(
                d,
                Request::RevokeAgent {
                    agent: found.id,
                    rotate,
                    background: false,
                },
            )
            .await?
        }
    };
    if json {
        output::json(&report)?;
        if !report.complete() {
            return Err(CliError::Other("the rotation is not finished".into()));
        }
        return Ok(());
    }
    output::info(&format!(
        "Revoked {}: the server refuses its next request.",
        report.agent.name
    ));
    print_exposure(&report.exposure);
    for r in &report.rotated {
        output::info(&format!(
            "Rotated the key of {}: {} items and {} stored versions re-wrapped.",
            r.project, r.items, r.versions
        ));
    }
    if !report.already_rotated.is_empty() {
        output::info(&format!(
            "Already rotated by an earlier run (not rotated again): {}.",
            report.already_rotated.join(", ")
        ));
    }
    if !report.regranted.is_empty() {
        output::info(&format!(
            "New grants with the new keys for: {}.",
            report.regranted.join(", ")
        ));
    }
    if !report.not_regranted.is_empty() {
        output::warn(&format!(
            "No new grant for: {}. They still hold the old keys; run `klav agent revoke {}` again.",
            report.not_regranted.join("; "),
            report.agent.name
        ));
    }
    if let Some(failed) = &report.failed {
        output::warn(&format!("The rotation stopped: {failed}."));
    }
    if !report.pending.is_empty() {
        output::warn(&format!(
            "Still to rotate: {}. Run `klav agent revoke {} --rotate` again to finish.",
            report.pending.join(", "),
            report.agent.name
        ));
    }
    if let Some(text) = skipped_text(&report.skipped) {
        output::warn(&text);
    }
    if !report.complete() {
        return Err(CliError::Other("the rotation is not finished".into()));
    }
    if rotate {
        output::info(
            "Rotation protects items created from now on. Item keys do not change: if the server also leaks, the revoked agent could still open what was in these projects.",
        );
    } else if !report.exposure.projects.is_empty() {
        output::info("To also rotate its projects' keys: run again with --rotate.");
    }
    Ok(())
}

/// `klav agent pause` (ADR 0033 §7, P2): no presence. Every agent goes
/// through a running `klavd` as it is, locked or not; one agent needs the
/// account unlocked, to find it.
async fn pause(ctx: &mut Ctx, args: AgentPauseArgs) -> CliResult<()> {
    let until = args
        .duration
        .map(|d| now_ms().saturating_add(i64::try_from(d.as_millis()).unwrap_or(i64::MAX)));
    let daemon = if args.agent.is_none() && !ctx.no_daemon {
        DaemonClient::connect(&ctx.home).await
    } else {
        None
    };
    let (pauses, who, id): (Vec<PauseInEffect>, String, Option<AgentId>) = match daemon {
        Some(mut d) => (
            call(&mut d, Request::PauseAgents { agent: None, until }).await?,
            "Every agent".to_owned(),
            None,
        ),
        None => {
            let found = match &args.agent {
                Some(a) => Some(find(ctx, a).await?),
                None => None,
            };
            let id = found.as_ref().map(|a| a.id);
            let pauses = match ctx.backend().await? {
                Backend::Direct(u) => {
                    let signed = u.pause_agents(id, until.unwrap_or(0)).await?;
                    signed.iter().map(PauseInEffect::signed).collect()
                }
                Backend::Daemon(d) => call(d, Request::PauseAgents { agent: id, until }).await?,
            };
            let who =
                found.map_or_else(|| "Every agent".to_owned(), |a| format!("Agent {}", a.name));
            (pauses, who, id)
        }
    };
    if args.json.json {
        return output::json(&pauses);
    }
    let when = until.map_or_else(
        || "until you resume".to_owned(),
        |t| format!("until {}", crate::time::format_utc(t)),
    );
    // The pause of this scope as `klavd` answered: only here when the
    // server did not take it (locked, offline, or an older server).
    let ours = pauses.iter().find(|p| p.agent_id == id);
    output::info(&pause_said(&who, id.is_none(), &when, ours));
    output::info(&format!(
        "Resume with `klav agent resume {}`.",
        args.agent.as_deref().unwrap_or("--all")
    ));
    Ok(())
}

/// What `klav agent pause` says: the server refuses the agents, or, for a
/// pause that holds only here (`local`), only what `klavd` mediates stops
/// for now. `klavd` adds why in a warning (locked, offline, an older
/// server).
fn pause_said(who: &str, every: bool, when: &str, ours: Option<&PauseInEffect>) -> String {
    let (they, them) = if every {
        ("they", "them")
    } else {
        ("it", "it")
    };
    match ours {
        Some(p) if p.local && p.server_unsupported => format!(
            "{who} paused {when} on this computer only: klavd refuses what it mediates for {them} (browser fills, password changes and passkeys), but this server does not support pausing agents, so what {they} ask the server still goes through. Update the server."
        ),
        Some(p) if p.local => format!(
            "{who} paused {when} on this computer only, for now: klavd refuses what it mediates for {them} (browser fills, password changes and passkeys), and the server refuses the rest once klavd tells it."
        ),
        _ => format!("{who} paused {when}: the server refuses what {they} ask until then."),
    }
}

/// `klav agent resume`: Touch ID through `klavd`, else the master password
/// that unlocks this process (ADR 0033 P2).
async fn resume(ctx: &mut Ctx, args: AgentResumeArgs) -> CliResult<()> {
    let found = match &args.agent {
        Some(a) => Some(find(ctx, a).await?),
        None => None,
    };
    let id = found.as_ref().map(|a| a.id);
    let pauses: Vec<PauseInEffect> = match ctx.backend().await? {
        Backend::Direct(u) => {
            let signed = u.resume_agents(id).await?;
            signed.iter().map(PauseInEffect::signed).collect()
        }
        Backend::Daemon(_) => {
            with_presence(ctx, |password| Request::ResumeAgents {
                agent: id,
                password,
            })
            .await?
        }
    };
    if args.json.json {
        return output::json(&pauses);
    }
    output::info(&format!(
        "{} resumed.",
        found.map_or_else(|| "Every agent".to_owned(), |a| format!("Agent {}", a.name))
    ));
    // Resuming every agent leaves the single pauses alone (and one agent's
    // resume, the pause of every agent).
    let still: Vec<String> = pauses
        .iter()
        .filter(|p| id.is_none() || p.agent_id.is_none() || p.agent_id == id)
        .map(|p| {
            p.agent_id
                .map_or_else(|| "every agent".to_owned(), |a| format!("agent {a}"))
        })
        .collect();
    if !still.is_empty() {
        output::warn(&format!("still paused: {}", still.join(", ")));
    }
    Ok(())
}

fn print_agents(agents: &[AgentView]) {
    let rows: Vec<Vec<String>> = agents
        .iter()
        .map(|a| {
            vec![
                a.name.clone(),
                a.status.as_str().to_owned(),
                a.paused.as_ref().map_or_else(String::new, |p| {
                    p.until.map_or_else(
                        || "yes".to_owned(),
                        |t| format!("until {}", crate::time::format_utc(t)),
                    )
                }),
                a.grant.as_ref().map_or_else(String::new, |g| {
                    g.projects
                        .iter()
                        .map(|p| format!("{}/{}", p.vault, p.project))
                        .collect::<Vec<_>>()
                        .join(", ")
                }),
                a.pairing_code.clone(),
                a.id.to_string(),
            ]
        })
        .collect();
    output::table(
        &["AGENT", "STATUS", "PAUSED", "PROJECTS", "WORDS", "ID"],
        &rows,
    );
}

fn permissions(list: &[String]) -> CliResult<Vec<Permission>> {
    list.iter()
        .filter(|p| !p.trim().is_empty())
        .map(|p| {
            let permission: Permission =
                serde_json::from_value(serde_json::Value::String(p.trim().to_lowercase()))
                    .map_err(|_| {
                        usage(format!(
                            "unknown permission {p:?} (list, fill, inject, totp, reveal, create, update, delete)"
                        ))
                    })?;
            if permission.requires_task() {
                return Err(usage(format!(
                    "`{permission}` cannot go in a grant: it only exists inside a task the agent asks for (klav agent task request) and you approve"
                )));
            }
            Ok(permission)
        })
        .collect()
}

/// The policy from `--policy-file` and the flags.
pub(crate) fn build_policy(args: &AgentApproveArgs, now_secs: u64) -> CliResult<Policy> {
    let mut policy = match &args.policy_file {
        Some(path) => {
            let text = std::fs::read(path)
                .map_err(|e| usage(format!("cannot read {}: {e}", path.display())))?;
            serde_json::from_slice(&text)
                .map_err(|e| usage(format!("{}: invalid policy: {e}", path.display())))?
        }
        None => Policy::default(),
    };
    for (list, effect) in [
        (&args.allow, Effect::Allow),
        (&args.ask, Effect::Ask),
        (&args.deny, Effect::Deny),
    ] {
        for permission in permissions(list)? {
            policy.rules.push(Rule::new(permission, effect));
        }
    }
    if !args.fill_domains.is_empty() {
        let domains = args
            .fill_domains
            .iter()
            .map(|d| klav_core::policy::DomainPattern::parse(d))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| usage(e.to_string()))?;
        policy.rules.push(Rule {
            scope: Scope {
                domains,
                ..Scope::default()
            },
            ..Rule::new(Permission::Fill, Effect::Allow)
        });
    }
    if !args.hours.is_empty() {
        let windows = args
            .hours
            .iter()
            .map(|h| {
                h.parse::<TimeWindow>().map_err(|_| {
                    usage(format!(
                        "invalid --hours {h:?}: use DAYS HH:MM-HH:MM OFFSET, e.g. \"mon-fri 09:00-18:00 -06:00\""
                    ))
                })
            })
            .collect::<CliResult<Vec<_>>>()?;
        // Every permission gets a rule (its default when it had none), and
        // every rule the window: outside it nothing applies, so everything
        // is denied.
        for permission in Permission::GRANTABLE {
            if !policy.rules.iter().any(|r| r.permission == permission) {
                policy
                    .rules
                    .push(Rule::new(permission, permission.default_effect()));
            }
        }
        for rule in &mut policy.rules {
            if rule.scope.hours.is_empty() {
                rule.scope.hours.clone_from(&windows);
            }
        }
    }
    if let Some(expires) = args.expires {
        policy.expires_at = Some(now_secs + expires.as_secs());
    }
    policy.check_grantable().map_err(|e| usage(e.to_string()))?;
    Ok(policy)
}

/// Asks on the terminal whether the words match (or checks `--words`).
fn confirm_words(agent: &AgentView, given: Option<&str>) -> CliResult<String> {
    if let Some(words) = given {
        return Ok(words.to_owned());
    }
    if !std::io::stdin().is_terminal() {
        return Err(usage(
            "pass the six words the agent shows with --words \"…\" (no terminal to confirm them)",
        ));
    }
    output::info(&format!(
        "Agent {:?} ({}) asks for access.{}\nIts pairing words are:\n\n    {}\n",
        agent.name,
        agent.id,
        agent
            .note
            .as_ref()
            .map(|n| format!("\nNote: {n}"))
            .unwrap_or_default(),
        agent.pairing_code
    ));
    eprint!("Are they exactly the words the agent shows? [y/N] ");
    let _ = std::io::stderr().flush();
    let mut answer = String::new();
    std::io::stdin().lock().read_line(&mut answer)?;
    if matches!(
        answer.trim().to_lowercase().as_str(),
        "y" | "yes" | "s" | "si" | "sí"
    ) {
        Ok(agent.pairing_code.clone())
    } else {
        Err(CliError::Other(
            "not approved: the words did not match (deny it with `klav agent deny`)".into(),
        ))
    }
}

async fn approve(ctx: &mut Ctx, args: AgentApproveArgs) -> CliResult<()> {
    let now = u64::try_from(now_ms() / 1000).unwrap_or(0);
    let policy = build_policy(&args, now)?;
    let found = find(ctx, &args.agent).await?;
    if found.status == AgentStatus::Active {
        return change_grant(ctx, &args, &found, policy).await;
    }
    if args.rotate_removed {
        return Err(usage(
            "--rotate-removed is for an active agent, whose grant loses projects",
        ));
    }
    let pairing_code = confirm_words(&found, args.words.as_deref())?;
    let grant = GrantRequest {
        projects: args.projects.clone(),
        vaults: args.vaults.clone(),
        policy,
    };
    let view = match ctx.backend().await? {
        Backend::Direct(u) => {
            let prepared = u.prepare_grant(found.id, grant, &pairing_code).await?;
            for warning in prepared.warnings() {
                output::warn(warning);
            }
            u.grant_prepared(prepared).await?
        }
        Backend::Daemon(_) => {
            with_presence(ctx, |password| Request::ApproveAgent {
                agent: found.id,
                grant: grant.clone(),
                pairing_code: pairing_code.clone(),
                password,
            })
            .await?
        }
    };
    let projects = view
        .grant
        .as_ref()
        .map(|g| {
            g.projects
                .iter()
                .map(|p| format!("{}/{}", p.vault, p.project))
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_default();
    output::info(&format!(
        "Agent {} approved (grant version {}): {projects}.",
        view.name,
        view.grant.as_ref().map_or(0, |g| g.version)
    ));
    Ok(())
}

/// `klav agent approve` on an active agent (ADR 0033, amendment of
/// 2026-11-10, F4): the differences, `[y/N]`, and presence only when the
/// change widens (P8), as `klavd` computes it. The agent's words are not
/// asked again: its identity is inside the signature of its grant in force
/// (F3).
async fn change_grant(
    ctx: &mut Ctx,
    args: &AgentApproveArgs,
    found: &AgentView,
    policy: Policy,
) -> CliResult<()> {
    let change = GrantChange {
        projects: args.projects.clone(),
        vaults: args.vaults.clone(),
        policy: ChangePolicy::Rules(policy),
        rotate_removed: args.rotate_removed,
    };
    let preview: GrantChangePreview = match ctx.backend().await? {
        Backend::Direct(u) => u
            .prepare_grant_change(found.id, &change)
            .await?
            .preview()
            .clone(),
        Backend::Daemon(d) => call(
            d,
            Request::GrantChangePrepare {
                agent: found.id,
                change: change.clone(),
            },
        )
        .await
        .map_err(|e| match &e {
            // A klavd from before this answers with «malformed request».
            CliError::Daemon(body) if body.code == ErrorCode::BadRequest => CliError::Other(
                "The klavd running is older than changing an active agent's grant. Update klavd to this klav's version and restart it (`klav lock --stop`, then `klav unlock`), or run this with --no-daemon.".into(),
            ),
            _ => e,
        })?,
    };
    output::info(&format!(
        "Agent {:?} is active. What changes in its grant (version {}):",
        preview.name, preview.version
    ));
    for line in &preview.lines {
        output::info(&format!("  {}", line.text()));
    }
    for warning in &preview.warnings {
        output::warn(warning);
    }
    if !preview.removed_projects.is_empty() && !preview.rotate_removed {
        output::info(
            "It already has the keys of the projects taken away: with an honest server it can no longer use them. --rotate-removed also changes those keys.",
        );
    }
    output::info(if preview.widens {
        "This widens what it can do: confirm with Touch ID or the master password."
    } else {
        "This only narrows what it can do: no Touch ID needed."
    });
    output::info("A new grant version expires the agent's pending requests.");
    if !args.yes && std::io::stdin().is_terminal() {
        eprint!("Sign it? [y/N] ");
        let _ = std::io::stderr().flush();
        let mut answer = String::new();
        std::io::stdin().lock().read_line(&mut answer)?;
        if !matches!(
            answer.trim().to_lowercase().as_str(),
            "y" | "yes" | "s" | "si" | "sí"
        ) {
            return Err(CliError::Other("not changed".into()));
        }
    }
    let apply = |password| Request::GrantChangeApply {
        agent: found.id,
        change: change.clone(),
        digest: preview.digest.clone(),
        password,
    };
    let report: GrantChangeReport = match ctx.backend().await? {
        // The master password that opened this process is the presence.
        Backend::Direct(u) => u.change_grant(found.id, &change, &preview.digest).await?,
        Backend::Daemon(_) if preview.widens => with_presence(ctx, apply).await?,
        Backend::Daemon(d) => call(d, apply(None)).await?,
    };
    output::info(&format!(
        "Grant of agent {} changed (version {}).",
        report.agent.name,
        report.agent.grant.as_ref().map_or(0, |g| g.version)
    ));
    for r in &report.rotated {
        output::info(&format!(
            "Changed the key of {}: {} items and {} stored versions re-wrapped.",
            r.project, r.items, r.versions
        ));
    }
    if !report.regranted.is_empty() {
        output::info(&format!(
            "New grants with the new keys for: {}.",
            report.regranted.join(", ")
        ));
    }
    if !report.not_regranted.is_empty() {
        output::warn(&format!(
            "No new grant for: {}. They still hold the old keys.",
            report.not_regranted.join("; ")
        ));
    }
    if let Some(failed) = &report.failed {
        output::warn(&format!("The key change stopped: {failed}."));
    }
    if !report.pending.is_empty() {
        output::warn(&format!(
            "The new grant is signed, but these keys did not change: {}. Their items are as safe as before the change.",
            report.pending.join(", ")
        ));
    }
    if let Some(text) = skipped_text(&report.skipped) {
        output::warn(&text);
    }
    if !report.complete() {
        return Err(CliError::Other("the key change is not finished".into()));
    }
    Ok(())
}

/// A daemon request that needs presence: Touch ID first, then the master
/// password if Touch ID is unavailable or fails.
pub(crate) async fn with_presence<T: serde::de::DeserializeOwned>(
    ctx: &mut Ctx,
    request: impl Fn(Option<SecretText>) -> Request,
) -> CliResult<T> {
    with_presence_skipping(ctx, request, |_| false).await
}

/// [`with_presence`], leaving out of klavd's warnings those `said` marks:
/// what this command already printed before presence.
pub(crate) async fn with_presence_skipping<T: serde::de::DeserializeOwned>(
    ctx: &mut Ctx,
    request: impl Fn(Option<SecretText>) -> Request,
    said: impl Fn(&str) -> bool,
) -> CliResult<T> {
    let Backend::Daemon(d) = ctx.backend().await? else {
        return Err(CliError::Other("klavd is not running".into()));
    };
    output::info("Confirm with Touch ID…");
    // `klavd`'s warnings: cleaned with the presence gate on, as every other
    // text of the gate; with it off, byte for byte as before (the ADR's own
    // choice 41; the second review of layer 3).
    let gate = d.presence_gate();
    let warn = |warnings: &[String]| {
        for w in warnings.iter().filter(|w| !said(w)) {
            if gate {
                output::warn(&crate::presence::said(w));
            } else {
                output::warn(w);
            }
        }
    };
    match d.call::<T>(request(None)).await {
        Ok((value, warnings)) => {
            warn(&warnings);
            Ok(value)
        }
        Err(e)
            if matches!(
                e.code,
                ErrorCode::BiometryFailed | ErrorCode::BiometryUnavailable
            ) =>
        {
            let message = if gate {
                crate::presence::said(&e.message)
            } else {
                e.message
            };
            output::warn(&format!("{message}; confirm with the master password"));
            let account = klav_client::account(&ctx.home)?;
            // With the presence gate on, a question typed on the terminal
            // names it and says what the answer opens: this one action
            // (layer 3's review, finding 1). From stdin, as before.
            let password = if gate && !ctx.input.password_from_stdin() {
                crate::presence::confirm_password(&account.email)?
            } else {
                ctx.input
                    .password(&format!("Master password for {}: ", account.email))?
            };
            let Backend::Daemon(d) = ctx.backend().await? else {
                unreachable!("daemon backend")
            };
            let (value, warnings) = d
                .call::<T>(request(Some(SecretText::new(password.as_str()))))
                .await
                .map_err(|e| crate::presence::refused(e, crate::presence::Busy::Password))?;
            warn(&warnings);
            Ok(value)
        }
        // With the presence gate on, another dialog is open (ADR 0041
        // §2.4): said in the CLI's words, as for a value.
        Err(e) => Err(crate::presence::refused(e, crate::presence::Busy::Dialog)),
    }
}

/// The `project` of the nearest `klav.toml`, as `(vault, project)`.
pub(crate) fn toml_scope() -> CliResult<Option<(String, String)>> {
    let Some(config) = crate::project::load(None)? else {
        return Ok(None);
    };
    Ok(config.project_scope())
}

async fn agent_totp(ctx: &mut Ctx, args: AgentTotpArgs) -> CliResult<()> {
    let name = klav_sdk::config::pick(&ctx.home, args.agent.as_deref())?;
    let agent = Agent::load(&ctx.home, &name)?;
    let mut session = klav_sdk::Session::open(agent).await?;
    let scope = toml_scope()?;
    let scope = scope.as_ref().map(|(v, p)| (v.as_str(), p.as_str()));
    let (item, _) = session.locate(&args.reference, scope)?;
    if let Some(id) = &args.approval {
        session.claim_approval(approval_id(id)?).await?;
    }
    let wait = args.wait.unwrap_or_default();
    if !wait.is_zero() {
        output::info("Waiting for the person's approval if needed…");
    }
    let (code, remaining) = session
        .totp(item, args.field.as_deref(), &args.reason, wait)
        .await?;
    output::line(code.expose());
    output::info(&format!("valid for {remaining}s"));
    Ok(())
}

// ------------------------------------------------------------- approvals

pub(crate) async fn approval_cmd(ctx: &mut Ctx, cmd: ApprovalCommand) -> CliResult<()> {
    match cmd {
        ApprovalCommand::List { all, json } => {
            let list: Vec<ApprovalView> = match ctx.backend().await? {
                Backend::Direct(u) => u.approvals(all).await?,
                Backend::Daemon(d) => call(d, Request::Approvals { all }).await?,
            };
            if json.json {
                return output::json(&list);
            }
            if list.is_empty() {
                output::info("No requests waiting.");
                return Ok(());
            }
            let rows: Vec<Vec<String>> = list
                .iter()
                .map(|a| {
                    vec![
                        a.id.to_string(),
                        a.status.as_str().to_owned(),
                        a.agent.clone(),
                        klav_sdk::session::permission_name(a.permission),
                        a.target.clone(),
                        a.domain.clone().unwrap_or_default(),
                        a.reason.clone(),
                        a.task
                            .as_ref()
                            .map(|t| {
                                format!(
                                    "outside «{}»{}",
                                    t.task,
                                    if t.can_add { " (--add-to-task)" } else { "" }
                                )
                            })
                            .unwrap_or_default(),
                    ]
                })
                .collect();
            output::table(
                &[
                    "ID",
                    "STATUS",
                    "AGENT",
                    "WANTS",
                    "ON",
                    "SITE (AGENT SAYS)",
                    "REASON",
                    "TASK",
                ],
                &rows,
            );
            Ok(())
        }
        ApprovalCommand::Approve {
            id,
            lease,
            add_to_task,
            yes,
        } => {
            let view = pending_approval(ctx, &id).await?;
            print_approval(&view);
            if add_to_task {
                confirm_approval("Add it to the task and approve it once?", yes)?;
                return add_approval_to_task(ctx, &view).await;
            }
            let question = match lease {
                Some(d) => format!("Approve it for {} min?", d.as_secs() / 60),
                None => "Approve it once?".to_owned(),
            };
            confirm_approval(&question, yes)?;
            decide(ctx, &view, true, lease).await
        }
        ApprovalCommand::Deny { id } => {
            let view = pending_approval(ctx, &id).await?;
            print_approval(&view);
            decide(ctx, &view, false, None).await
        }
        ApprovalCommand::Wait {
            id,
            timeout,
            agent,
            json,
        } => approval_wait(ctx, &id, timeout, agent.as_deref(), json.json).await,
    }
}

/// The pending approval `wanted` (ID or unique prefix), as the person sees
/// it: the card printed and the digest sent come from the same answer.
async fn pending_approval(ctx: &mut Ctx, wanted: &str) -> CliResult<ApprovalView> {
    Ok(match ctx.backend().await? {
        Backend::Direct(u) => u.find_approval(wanted).await?,
        Backend::Daemon(d) => {
            let list: Vec<ApprovalView> = call(d, Request::Approvals { all: false }).await?;
            klav_client::agents::pick_approval(list, wanted)?
        }
    })
}

/// The whole request before deciding (ADR 0030 §5): what the agent says
/// (reason, site) is labelled as such.
fn print_approval(a: &ApprovalView) {
    let id = a.agent_id.to_string();
    output::line(&format!("Request {}", a.id));
    output::line(&format!(
        "  agent:   {}  ({}…)",
        a.agent,
        id.get(..8).unwrap_or(&id)
    ));
    output::line(&format!(
        "  wants:   {}",
        klav_sdk::session::permission_name(a.permission)
    ));
    output::line(&format!("  on:      {}", a.target));
    match &a.domain {
        Some(site) => output::line(&format!("  site:    {site}   (according to the agent)")),
        None => output::line("  site:    none given"),
    }
    output::line(&format!(
        "  reason:  {}   (according to the agent)",
        a.reason
    ));
    if let Some(task) = &a.task {
        output::line(&format!(
            "  task:    outside its running task «{}» (until {}){}",
            task.task,
            crate::time::format_utc(task.expires_at),
            if task.can_add {
                "; --add-to-task adds it"
            } else {
                ""
            }
        ));
    }
    output::line(&format!(
        "  decide:  before {}",
        crate::time::format_utc(a.expires_at)
    ));
}

/// Asks on the terminal before signing; `--yes` or no terminal skip it
/// (like `klav agent revoke`).
pub(crate) fn confirm_approval(question: &str, yes: bool) -> CliResult<()> {
    if yes || !std::io::stdin().is_terminal() {
        return Ok(());
    }
    eprint!("{question} [y/N] ");
    let _ = std::io::stderr().flush();
    let mut answer = String::new();
    std::io::stdin().lock().read_line(&mut answer)?;
    if matches!(
        answer.trim().to_lowercase().as_str(),
        "y" | "yes" | "s" | "si" | "sí"
    ) {
        Ok(())
    } else {
        Err(CliError::Other("not approved".into()))
    }
}

async fn add_approval_to_task(ctx: &mut Ctx, view: &ApprovalView) -> CliResult<()> {
    let card: klav_client::tasks::TaskCard = match ctx.backend().await? {
        Backend::Direct(u) => u.add_to_task(view.id, &view.request_digest).await?,
        Backend::Daemon(_) => {
            with_presence(ctx, |password| Request::AddToTask {
                approval: view.id.to_string(),
                digest: view.request_digest.clone(),
                password,
            })
            .await?
        }
    };
    output::info(&format!(
        "Added to the task «{}» (until {}) and approved once.",
        card.task,
        card.expires_at
            .map(crate::time::format_utc)
            .unwrap_or_default()
    ));
    Ok(())
}

/// An approval ID given by an agent (in full).
pub(crate) fn approval_id(text: &str) -> CliResult<klav_core::ids::ApprovalId> {
    text.trim()
        .parse()
        .map_err(|_| usage(format!("{text:?} is not an approval ID")))
}

/// `klav approval wait`, agent side (ADR 0015 §4): signed requests with
/// the agent's own key, never the person's vault.
async fn approval_wait(
    ctx: &Ctx,
    id: &str,
    timeout: Duration,
    agent: Option<&str>,
    json: bool,
) -> CliResult<()> {
    use klav_proto::agent::ApprovalStatus;

    let id = approval_id(id)?;
    let name = klav_sdk::config::pick(&ctx.home, agent)?;
    let agent = Agent::load(&ctx.home, &name)?;
    if !json {
        output::info(&format!("Waiting for the person to decide on {id}…"));
    }
    let info = agent.wait_decision(id, timeout).await?;
    let lease = info.lease_until.unwrap_or(0);
    let used = lease == 0 && info.used_at.is_some();
    if json {
        output::line(
            &serde_json::json!({
                "approval_id": id,
                "status": info.status.as_str(),
                "lease_until": info.lease_until,
                "used": used,
                "expires_at": info.expires_at,
            })
            .to_string(),
        );
    } else {
        output::line(info.status.as_str());
        output::info(&match info.status {
            ApprovalStatus::Approved if used => "Approved, but already used: ask again.".to_owned(),
            ApprovalStatus::Approved => {
                format!("Approved: retry the action with approval_id {id} (--approval {id}).")
            }
            ApprovalStatus::Pending => "No decision yet.".to_owned(),
            ApprovalStatus::Denied => "The person denied it: do not try another way.".to_owned(),
            ApprovalStatus::Expired => "It expired without a decision.".to_owned(),
        });
    }
    match info.status {
        ApprovalStatus::Approved => Ok(()),
        ApprovalStatus::Pending => Err(CliError::Exit(crate::error::EXIT_PENDING)),
        ApprovalStatus::Denied => Err(CliError::Exit(crate::error::EXIT_DENIED)),
        ApprovalStatus::Expired => Err(CliError::Exit(crate::error::EXIT_EXPIRED)),
    }
}

async fn decide(
    ctx: &mut Ctx,
    shown: &ApprovalView,
    approve: bool,
    lease: Option<Duration>,
) -> CliResult<()> {
    let id = shown.id;
    let digest = shown.request_digest.clone();
    let view: ApprovalView = match ctx.backend().await? {
        Backend::Direct(u) => u.decide_approval(id, approve, lease, &digest).await?,
        Backend::Daemon(_) if approve => {
            with_presence(ctx, |password| Request::DecideApproval {
                approval: id.to_string(),
                approve,
                digest: digest.clone(),
                lease_secs: lease.map(|d| d.as_secs()),
                password,
            })
            .await?
        }
        Backend::Daemon(d) => {
            call(
                d,
                Request::DecideApproval {
                    approval: id.to_string(),
                    approve,
                    digest,
                    lease_secs: None,
                    password: None,
                },
            )
            .await?
        }
    };
    let what = klav_sdk::session::permission_name(view.permission);
    output::info(&match (approve, lease) {
        (false, _) => format!("Denied: {} wanted `{what}` on {}.", view.agent, view.target),
        (true, None) => format!(
            "Approved once: {} may `{what}` {}.",
            view.agent, view.target
        ),
        (true, Some(d)) => format!(
            "Approved for {} min: {} may `{what}` {}.",
            d.as_secs() / 60,
            view.agent,
            view.target
        ),
    });
    Ok(())
}

/// What a key change skipped because Klav can't reach it: a report can be
/// complete with skips, and must never read as "every key changed".
fn skipped_text(skipped: &[String]) -> Option<String> {
    (!skipped.is_empty()).then(|| {
        format!(
            "Not every key changed: Klav can't reach these, so their keys did not change: {}.",
            skipped.join("; ")
        )
    })
}

#[cfg(test)]
mod tests {
    use super::{revocation_left_text, skipped_text};
    use klav_client::revoke::PendingRevocation;

    fn left(projects: &[&str], items: usize, without_key_change: bool) -> PendingRevocation {
        let projects: Vec<String> = projects.iter().map(|p| (*p).to_owned()).collect();
        PendingRevocation {
            agent_id: "6f1c1b2e-0c1d-4a7b-9e55-1f2a3b4c5d6e".parse().expect("id"),
            name: "bot".into(),
            pending: projects.clone(),
            projects,
            rotated: Vec::new(),
            regrants: Vec::new(),
            unknown_projects: false,
            narrowed: false,
            items,
            log_unchecked: false,
            without_key_change,
            skipped: Vec::new(),
            last_error: None,
        }
    }

    /// P7: a person who declined the key change is never told to run
    /// `--rotate`, which would change every project key they kept.
    #[test]
    fn show_suggests_rotate_only_when_the_key_change_was_asked() {
        let asked =
            revocation_left_text(&left(&["Personal/General"], 0, false), "bot").expect("said");
        assert!(asked.contains("klav agent revoke bot --rotate"), "{asked}");

        let declined = revocation_left_text(&left(&[], 1, true), "bot").expect("said");
        assert!(!declined.contains("revoke bot --rotate"), "{declined}");
        assert!(declined.contains("`klav agent revoke bot`"), "{declined}");

        // An older klavd sends no `without_key_change`, and counts projects
        // only for a revocation with the key change: none counted, declined.
        let older = revocation_left_text(&left(&[], 1, false), "bot").expect("said");
        assert!(!older.contains("revoke bot --rotate"), "{older}");

        // Unknown projects are written only for a key change; a declined
        // entry that carries them gets no `--rotate` either.
        let mut odd = left(&[], 1, true);
        odd.unknown_projects = true;
        let odd = revocation_left_text(&odd, "bot").expect("said");
        assert!(
            !odd.contains("again with `--rotate`") && !odd.contains("revoke bot --rotate"),
            "{odd}"
        );
    }

    /// A credential proxy revoked with `--rotate` holds only items: no
    /// project counts as asked, and nothing says the person declined
    /// (review of #315, 1).
    #[test]
    fn show_never_says_declined_to_a_person_who_asked() {
        let proxy = revocation_left_text(&left(&[], 1, false), "proxy").expect("said");
        assert!(
            proxy.ends_with("or run `klav agent revoke proxy`."),
            "{proxy}"
        );
        assert!(!proxy.contains("you chose not"), "{proxy}");

        let declined = revocation_left_text(&left(&[], 1, true), "bot").expect("said");
        assert!(declined.contains("you chose not to change"), "{declined}");
    }

    /// The other entries #315 left untested: a narrowing (klavd goes on,
    /// no command), and a revocation with the key change asked that only
    /// has an unread log or grants to issue again (`--rotate`).
    #[test]
    fn show_hints_each_kind_of_entry() {
        let mut narrowing = left(&["Personal/Work"], 0, false);
        narrowing.narrowed = true;
        let narrowing = revocation_left_text(&narrowing, "bot").expect("said");
        assert!(
            narrowing.ends_with("klavd goes on by itself when it unlocks."),
            "{narrowing}"
        );
        assert!(!narrowing.contains("klav agent revoke"), "{narrowing}");

        let mut log = left(&[], 0, false);
        log.log_unchecked = true;
        let log = revocation_left_text(&log, "bot").expect("said");
        assert!(log.contains("klav agent revoke bot --rotate"), "{log}");

        let mut regrants = left(&[], 0, false);
        regrants.regrants = vec!["Personal/General".into()];
        let regrants = revocation_left_text(&regrants, "bot").expect("said");
        assert!(
            regrants.contains("klav agent revoke bot --rotate"),
            "{regrants}"
        );
    }

    #[test]
    fn a_complete_key_change_with_skips_says_them() {
        assert_eq!(skipped_text(&[]), None);
        let text =
            skipped_text(&["Personal/Old: the project was deleted".to_owned()]).expect("said");
        assert!(text.starts_with("Not every key changed"), "{text}");
        assert!(
            text.contains("Personal/Old: the project was deleted"),
            "{text}"
        );
    }
}
