//! `secret-request` (person side) and `agent secret-request` (agent side),
//! ADR 0046.
//!
//! Secret values are read only on the person's side via a hidden TTY prompt or
//! `--secret-stdin` (never from argv) and are never printed to stdout or
//! stderr.

use std::time::Duration;

use klav_client::ops::SecretText;
use klav_client::secret_requests::{FulfillSecretRequest, FulfillSecretResult, SecretRequestCard};
use klav_core::ids::SecretRequestId;
use klav_core::model::item::ItemKind;
use klav_core::secret_request::{ProxyProposal, SecretRequestMode};
use klav_daemon::protocol::Request;
use klav_proto::secret_request::SecretRequestState;
use klav_sdk::{Agent, SecretRequestOutcome, SecretRequestSpec, Session};

use crate::backend::{Backend, call};
use crate::cli::{
    AgentSecretRequestCommand, AgentSecretRequestCreateArgs, SecretRequestCommand,
    SecretRequestFulfillArgs, SecretRequestKindArg, SecretRequestModeArg,
};
use crate::commands::agent::with_presence;
use crate::context::Ctx;
use crate::error::{CliError, CliResult, EXIT_DENIED, EXIT_EXPIRED, EXIT_PENDING, usage};
use crate::output;
use crate::time::format_utc;

// ---------------------------------------------------------------- person side

pub(crate) async fn secret_request_cmd(ctx: &mut Ctx, cmd: SecretRequestCommand) -> CliResult<()> {
    match cmd {
        SecretRequestCommand::List { all, json } => {
            let cards = cards(ctx, all).await?;
            if json.json {
                return output::json(&cards);
            }
            if cards.is_empty() {
                output::info(if all {
                    "No secret requests."
                } else {
                    "No pending secret requests."
                });
                return Ok(());
            }
            let rows: Vec<Vec<String>> = cards
                .iter()
                .map(|c| {
                    let target = card_target(c);
                    vec![
                        c.id.to_string(),
                        c.status.as_str().to_owned(),
                        c.agent.clone(),
                        c.mode.as_str().to_owned(),
                        target,
                        c.reason.clone(),
                    ]
                })
                .collect();
            output::table(
                &["ID", "STATUS", "AGENT", "MODE", "TARGET", "REASON"],
                &rows,
            );
            Ok(())
        }
        SecretRequestCommand::Show { id, json } => {
            let all = cards(ctx, true).await?;
            let card = klav_client::secret_requests::find_secret_request(&all, &id)?;
            if json.json {
                return output::json(card);
            }
            print_card(card);
            Ok(())
        }
        SecretRequestCommand::Fulfill(args) => fulfill(ctx, *args).await,
        SecretRequestCommand::Deny { id, json } => {
            let pending = cards(ctx, false).await?;
            let card = klav_client::secret_requests::find_secret_request(&pending, &id)?.clone();
            if !card.is_pending() {
                return Err(usage(format!(
                    "secret request {} is {}, not pending",
                    card.id,
                    card.status.as_str()
                )));
            }
            let decided = deny(ctx, &card).await?;
            if json.json {
                return output::json(&decided);
            }
            output::info(&format!(
                "Denied secret request {} from «{}».",
                decided.id, decided.agent
            ));
            Ok(())
        }
    }
}

async fn cards(ctx: &mut Ctx, all: bool) -> CliResult<Vec<SecretRequestCard>> {
    Ok(match ctx.backend().await? {
        Backend::Direct(u) => u.secret_requests(all).await?,
        Backend::Daemon(d) => call(d, Request::SecretRequests { all }).await?,
    })
}

async fn deny(ctx: &mut Ctx, card: &SecretRequestCard) -> CliResult<SecretRequestCard> {
    let id = card.id;
    let digest = card.proposal_digest.clone();
    Ok(match ctx.backend().await? {
        Backend::Direct(u) => u.deny_secret_request(id, &digest).await?,
        Backend::Daemon(d) => {
            call(
                d,
                Request::DenySecretRequest {
                    request: id.to_string(),
                    digest,
                },
            )
            .await?
        }
    })
}

async fn fulfill(ctx: &mut Ctx, args: SecretRequestFulfillArgs) -> CliResult<()> {
    let pending = cards(ctx, false).await?;
    let card = klav_client::secret_requests::find_secret_request(&pending, &args.id)?.clone();
    if !card.is_pending() {
        return Err(usage(format!(
            "secret request {} is {}, not pending",
            card.id,
            card.status.as_str()
        )));
    }
    if let Some(err) = &card.proposal_error {
        return Err(CliError::Other(format!(
            "secret request {} cannot be fulfilled: {err}",
            card.id
        )));
    }
    let proposal = card.proposal.as_ref().ok_or_else(|| {
        CliError::Other(format!(
            "secret request {} has no decrypted proposal",
            card.id
        ))
    })?;

    if !args.json.json {
        print_card(&card);
    }

    if args.grant_proxy && proposal.proxy_proposal.is_none() {
        return Err(usage(
            "this secret request does not carry a proxy proposal; omit --grant-proxy",
        ));
    }

    let field_name = args.field.clone().unwrap_or_else(|| proposal.field.clone());

    // T234: never auto-save agent-suggested `login` URLs unless the person
    // explicitly passes `--url` or `--confirm-suggested-urls`.
    let urls = if !args.urls.is_empty() {
        Some(args.urls.clone())
    } else if args.confirm_suggested_urls {
        Some(proposal.urls.clone())
    } else {
        None
    };

    if !args.json.json && !args.secret_stdin {
        crate::commands::agent::confirm_approval("Save this secret into your vault?", args.yes)?;
    }

    let secret = if args.secret_stdin {
        let line = ctx.input.stdin_line(&format!("value for {field_name}"))?;
        SecretText::new(line.as_str())
    } else {
        let prompt = match proposal.placeholder.as_deref() {
            Some(ph) if !ph.is_empty() => format!("{field_name} ({ph}): "),
            _ => format!("{field_name}: "),
        };
        let value = ctx.input.prompt_hidden(&prompt)?;
        SecretText::new(value.as_str())
    };

    let input = FulfillSecretRequest {
        digest: card.proposal_digest.clone(),
        secret,
        vault: args.vault,
        project: args.project,
        title: args.title,
        field: args.field,
        urls,
        notes: args.notes.map(SecretText::new),
        allow_duplicate: args.allow_duplicate,
        grant_proxy: args.grant_proxy,
        proxy_base_version: None,
        every_device_updated: args.every_device_updated,
        shown_words: args.words,
        proxy_credential: None,
    };

    let id = card.id;
    let result: FulfillSecretResult = match ctx.backend().await? {
        Backend::Direct(u) => u.fulfill_secret_request(id, &input).await?,
        Backend::Daemon(_) if input.grant_proxy => {
            with_presence(ctx, |password| Request::FulfillSecretRequest {
                request: id.to_string(),
                input: input.clone(),
                password,
            })
            .await?
        }
        Backend::Daemon(d) => {
            call(
                d,
                Request::FulfillSecretRequest {
                    request: id.to_string(),
                    input,
                    password: None,
                },
            )
            .await?
        }
    };

    for warning in &result.proxy_warnings {
        output::warn(warning);
    }
    if args.json.json {
        return output::json(&result);
    }
    output::info(&format!(
        "Saved {} (field `{}`).",
        result.item.reference,
        result
            .card
            .decision
            .as_ref()
            .and_then(|d| d.field.as_deref())
            .unwrap_or(&field_name),
    ));
    if result.in_grant {
        output::info(&format!(
            "Shared with «{}» (agent received the item reference).",
            result.card.agent
        ));
    } else {
        output::info(&format!(
            "Not in «{}»'s grant (vault/project/item IDs were omitted from the signed decision).",
            result.card.agent
        ));
    }
    if let Some(profile) = &result.proxy_profile {
        output::info(&format!("Granted credential proxy profile `{profile}`."));
    }
    Ok(())
}

fn card_target(card: &SecretRequestCard) -> String {
    match card.mode {
        SecretRequestMode::Update => card
            .target_reference
            .clone()
            .or_else(|| card.target_title.clone())
            .or_else(|| card.target_item_id.map(|i| i.to_string()))
            .unwrap_or_else(|| "(unknown item)".into()),
        SecretRequestMode::Create => card
            .proposal
            .as_ref()
            .and_then(|p| p.title.clone())
            .unwrap_or_else(|| "(encrypted)".into()),
    }
}

fn print_card(card: &SecretRequestCard) {
    output::line(&format!(
        "{}  {}  ({} · {})",
        card.id,
        card.status.as_str(),
        card.mode.as_str(),
        card.agent_id
    ));
    output::line(&format!(
        "  agent:   «{}» (name set by the agent)",
        card.agent
    ));
    output::line(&format!(
        "  reason:  {} (according to the agent)",
        card.reason
    ));
    output::line(&format!("  created: {}", format_utc(card.created_at)));
    output::line(&format!("  expires: {}", format_utc(card.expires_at)));
    if let Some(decided_at) = card.decided_at {
        output::line(&format!("  decided: {}", format_utc(decided_at)));
    }
    if let Some(err) = &card.proposal_error {
        output::warn(&format!("proposal error: {err}"));
        return;
    }
    if let Some(proposal) = &card.proposal {
        match proposal.mode {
            SecretRequestMode::Create => {
                if let Some(kind) = proposal.kind {
                    output::line(&format!("  kind:    {kind:?}"));
                }
                if let Some(title) = &proposal.title {
                    output::line(&format!("  title:   {title}"));
                }
                output::line(&format!("  field:   {}", proposal.field));
                if let (Some(v), Some(p)) = (proposal.vault_id, proposal.project_id) {
                    let shared = card.agent_projects.contains(&(v, p));
                    output::line(&format!(
                        "  project: {v}/{p} ({})",
                        if shared {
                            format!("shared with «{}»", card.agent)
                        } else {
                            format!("not shared with «{}»", card.agent)
                        }
                    ));
                }
                if let Some(base_url) = &proposal.base_url {
                    output::line(&format!(
                        "  base_url: {base_url} (suggested by «{}»)",
                        card.agent
                    ));
                }
                if !proposal.urls.is_empty() {
                    output::line(&format!(
                        "  urls (suggested by «{}», NOT saved by default — pass --confirm-suggested-urls or --url to save):",
                        card.agent
                    ));
                    for url in &proposal.urls {
                        output::line(&format!("    - {url}"));
                    }
                }
                if let Some(notes) = &proposal.notes {
                    output::line(&format!(
                        "  notes:   {notes} (suggested by «{}»)",
                        card.agent
                    ));
                }
            }
            SecretRequestMode::Update => {
                let target = card
                    .target_reference
                    .as_deref()
                    .or(card.target_title.as_deref())
                    .unwrap_or("(not found in this device's vault)");
                output::line(&format!(
                    "  target:  Replace `{}` of {target} (previous value stays in password history)",
                    proposal.field
                ));
            }
        }
        if let Some(setup) = &card.setup_url {
            output::line(&format!(
                "  setup_url: {}  [host: {}]",
                setup.url, setup.host
            ));
            output::warn(&format!(
                "Link suggested by «{}» — check the domain before opening.",
                card.agent
            ));
            if setup.has_punycode {
                output::warn(
                    "setup_url contains punycode (IDN) labels — verify the domain carefully.",
                );
            }
        }
        if let Some(pp) = &proposal.proxy_proposal {
            output::line(
                "  proxy_proposal (unchecked by default; pass --grant-proxy to grant with presence):",
            );
            output::line(&format!("    profile:  {}", pp.profile));
            output::line(&format!("    upstream: {}", pp.upstream));
            output::line(&format!(
                "    header:   {} (prefix {:?})",
                pp.header, pp.prefix
            ));
            if !pp.methods.is_empty() {
                output::line(&format!("    allow:    {}", pp.methods.join(", ")));
            }
            if !pp.ask_methods.is_empty() {
                output::line(&format!("    ask:      {}", pp.ask_methods.join(", ")));
            }
            output::line(&format!("    paths:    {}", pp.path_prefixes.join(", ")));
            if let Some(rate) = pp.rate_per_minute {
                output::line(&format!("    rate:     {rate}/min"));
            }
        }
    }
    if let Some(decision) = &card.decision {
        output::line(&format!(
            "  decision: {} (in_grant: {}{})",
            decision.status.as_str(),
            decision.in_grant,
            decision
                .proxy_profile
                .as_deref()
                .map(|p| format!(", proxy_profile: {p}"))
                .unwrap_or_default()
        ));
    }
}

// ----------------------------------------------------------------- agent side

pub(crate) async fn agent_secret_request_cmd(
    ctx: &mut Ctx,
    cmd: AgentSecretRequestCommand,
) -> CliResult<()> {
    match cmd {
        AgentSecretRequestCommand::Create(args) => agent_create(ctx, *args).await,
        AgentSecretRequestCommand::Wait {
            id,
            timeout,
            agent,
            json,
        } => {
            let id = secret_request_id(&id)?;
            let mut session = open_session(ctx, agent.as_deref()).await?;
            if !json.json {
                output::info(&format!(
                    "Waiting for the person to decide on secret request {id}…"
                ));
            }
            let outcome = session.wait_secret_request(id, timeout).await?;
            report_outcome(&outcome, json.json)
        }
        AgentSecretRequestCommand::Show { id, agent, json } => {
            let id = secret_request_id(&id)?;
            let mut session = open_session(ctx, agent.as_deref()).await?;
            let outcome = session.wait_secret_request(id, Duration::ZERO).await?;
            report_outcome(&outcome, json.json)
        }
    }
}

async fn agent_create(ctx: &mut Ctx, args: AgentSecretRequestCreateArgs) -> CliResult<()> {
    let mut session = open_session(ctx, args.agent.as_deref()).await?;
    let scope = crate::commands::agent::toml_scope()?;
    let scope = scope.as_ref().map(|(v, p)| (v.as_str(), p.as_str()));
    let mode = match args.mode {
        SecretRequestModeArg::Create => SecretRequestMode::Create,
        SecretRequestModeArg::Update => SecretRequestMode::Update,
    };
    let kind = args.kind.map(kind_from_arg);
    let field = match args.field.clone() {
        Some(f) => f,
        None if mode == SecretRequestMode::Create => {
            default_field_for_kind(kind.unwrap_or(ItemKind::ApiKey)).to_owned()
        }
        None => {
            return Err(usage("--field is required when --mode update"));
        }
    };
    let proxy_proposal = build_proxy_proposal(&args)?;
    let wait = args.wait.unwrap_or(Duration::ZERO);
    let spec = SecretRequestSpec {
        mode,
        kind,
        title: args.title,
        reference: args.reference,
        project: args.project,
        field,
        reason: args.reason,
        placeholder: args.placeholder,
        setup_url: args.setup_url,
        base_url: args.base_url,
        urls: args.urls,
        notes: args.notes,
        proxy_proposal,
        wait,
    };
    let outcome = session.request_secret(&spec, scope).await?;
    report_outcome(&outcome, args.json.json)
}

fn default_field_for_kind(kind: ItemKind) -> &'static str {
    match kind {
        ItemKind::ApiKey => "api_key",
        ItemKind::Login => "password",
        ItemKind::SshKey => "private_key",
        ItemKind::Totp => "totp",
        _ => "secret",
    }
}

fn kind_from_arg(arg: SecretRequestKindArg) -> ItemKind {
    match arg {
        SecretRequestKindArg::ApiKey => ItemKind::ApiKey,
        SecretRequestKindArg::Login => ItemKind::Login,
        SecretRequestKindArg::Note => ItemKind::Note,
        SecretRequestKindArg::SshKey => ItemKind::SshKey,
        SecretRequestKindArg::Totp => ItemKind::Totp,
    }
}

fn build_proxy_proposal(args: &AgentSecretRequestCreateArgs) -> CliResult<Option<ProxyProposal>> {
    let any = args.proxy_profile.is_some()
        || args.proxy_upstream.is_some()
        || args.proxy_header.is_some()
        || args.proxy_prefix.is_some()
        || !args.proxy_methods.is_empty()
        || !args.proxy_ask_methods.is_empty()
        || !args.proxy_path_prefixes.is_empty()
        || args.proxy_rate.is_some();
    if !any {
        return Ok(None);
    }
    let profile = args
        .proxy_profile
        .clone()
        .ok_or_else(|| usage("--proxy-profile is required when proposing a proxy grant"))?;
    let upstream = args
        .proxy_upstream
        .clone()
        .ok_or_else(|| usage("--proxy-upstream is required when proposing a proxy grant"))?;
    let header = args
        .proxy_header
        .clone()
        .unwrap_or_else(|| "authorization".into());
    let prefix = args
        .proxy_prefix
        .clone()
        .unwrap_or_else(|| "Bearer ".into());
    let methods = if args.proxy_methods.is_empty() && args.proxy_ask_methods.is_empty() {
        vec!["GET".into(), "POST".into()]
    } else {
        args.proxy_methods.clone()
    };
    let path_prefixes = if args.proxy_path_prefixes.is_empty() {
        vec!["/".into()]
    } else {
        args.proxy_path_prefixes.clone()
    };
    let proposal = ProxyProposal {
        preset: None,
        profile,
        upstream,
        header,
        prefix,
        methods,
        ask_methods: args.proxy_ask_methods.clone(),
        path_prefixes,
        rate_per_minute: args.proxy_rate,
    };
    proposal
        .validate()
        .map_err(|e| usage(format!("invalid proxy proposal: {e}")))?;
    Ok(Some(proposal))
}

async fn open_session(ctx: &Ctx, agent: Option<&str>) -> CliResult<Session> {
    let name = klav_sdk::config::pick(&ctx.home, agent)?;
    let agent = Agent::load(&ctx.home, &name)?;
    Ok(Session::open(agent).await?)
}

fn secret_request_id(text: &str) -> CliResult<SecretRequestId> {
    text.trim()
        .parse()
        .map_err(|_| usage(format!("{text:?} is not a secret request ID")))
}

fn report_outcome(outcome: &SecretRequestOutcome, json: bool) -> CliResult<()> {
    if json {
        output::json(outcome)?;
    } else {
        match outcome {
            SecretRequestOutcome::Pending {
                request_id,
                expires_at,
            } => {
                output::line(&format!("{request_id}  pending"));
                output::line(&format!("  expires: {}", format_utc(*expires_at)));
                output::info(&format!(
                    "Waiting for the person: `klav secret-request fulfill {request_id}` (wait with `klav agent secret-request wait {request_id}`)."
                ));
            }
            SecretRequestOutcome::Fulfilled {
                request_id,
                in_grant,
                reference,
                field,
                proxy_profile,
                ..
            } => {
                output::line(&format!("{request_id}  fulfilled"));
                if let Some(reference) = reference {
                    output::line(&format!("  ref:     {reference}"));
                } else {
                    output::line(&format!("  field:   {field} (in_grant: {in_grant})"));
                }
                if let Some(profile) = proxy_profile {
                    output::line(&format!("  proxy:   {profile}"));
                }
            }
            SecretRequestOutcome::Denied { request_id } => {
                output::line(&format!("{request_id}  denied"));
                output::info("The person denied this secret request. Do not try another way.");
            }
            SecretRequestOutcome::Expired { request_id } => {
                output::line(&format!("{request_id}  expired"));
                output::info("This secret request expired without a decision.");
            }
        }
    }
    match outcome {
        SecretRequestOutcome::Fulfilled { .. } => Ok(()),
        SecretRequestOutcome::Pending { .. } => Err(CliError::Exit(EXIT_PENDING)),
        SecretRequestOutcome::Denied { .. } => Err(CliError::Exit(EXIT_DENIED)),
        SecretRequestOutcome::Expired { .. } => Err(CliError::Exit(EXIT_EXPIRED)),
    }
}

#[allow(dead_code)]
fn _state_check(state: SecretRequestState) -> &'static str {
    state.as_str()
}
