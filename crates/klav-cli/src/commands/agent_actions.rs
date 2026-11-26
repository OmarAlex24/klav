//! Agent-side actions (`klav agent run | inject | fill | browser`): the
//! agent uses secrets without receiving them (design §5.4). Nothing here
//! prints a value: `run` redacts its child's output, `inject` only writes
//! files, `fill` types into a browser.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use klav_sdk::browser::{self, BrowserTarget, FieldSelector, Target};
use klav_sdk::{Agent, InjectRequest, RunRequest, Session};

use crate::cli::{AgentActionArgs, AgentFillArgs, AgentInjectArgs, AgentRunArgs, BrowserCommand};
use crate::context::Ctx;
use crate::error::{CliError, CliResult, usage};
use crate::output;
use crate::project::{self, ProjectConfig, is_reference};
use crate::secret_files::{Cleanup, Signals, human, not_ignored_warning, warn_leftovers};

struct Opened {
    session: Session,
    config: Option<ProjectConfig>,
    scope: Option<(String, String)>,
}

impl Opened {
    fn expand(&self, reference: &str) -> CliResult<String> {
        let project = self.config.as_ref().and_then(|c| c.project.as_deref());
        project::expand(project, reference).map_err(usage)
    }
}

async fn open(
    ctx: &Ctx,
    action: &AgentActionArgs,
    config: Option<&std::path::Path>,
) -> CliResult<Opened> {
    let name = klav_sdk::config::pick(&ctx.home, action.agent.as_deref())?;
    let agent = Agent::load(&ctx.home, &name)?;
    let config = project::load(config)?;
    let scope = config.as_ref().and_then(ProjectConfig::project_scope);
    let mut session = Session::open(agent).await?;
    if let Some(id) = &action.approval {
        session
            .claim_approval(super::agent::approval_id(id)?)
            .await?;
    }
    Ok(Opened {
        session,
        config,
        scope,
    })
}

fn wait(action: &AgentActionArgs) -> Duration {
    let wait = action.wait.unwrap_or_default();
    if !wait.is_zero() {
        output::info("Waiting for the person's approval if needed…");
    }
    wait
}

/// What an agent's run takes from environments (ADR 0032 §4.5 and §5):
/// `None` for today's flat `[env]` (or no `klav.toml`); otherwise the
/// vault's environment to read, if the vault has it, and `[env.NAME]` of
/// `klav.toml`. The same order as `klav run`; it never guesses
/// `development`.
pub(crate) type AgentEnvironment = Option<(Option<String>, BTreeMap<String, String>)>;

/// See [`AgentEnvironment`]. `requested` is `--env` or MCP's `environment`.
pub(crate) fn agent_environment(
    session: &Session,
    config: Option<&ProjectConfig>,
    scope: Option<(&str, &str)>,
    requested: Option<&str>,
) -> Result<AgentEnvironment, String> {
    let vault: Vec<String> = session
        .environments(scope)
        .into_iter()
        .map(|e| e.name)
        .collect();
    let name = match requested {
        Some(name) => name.to_owned(),
        None => match project::default_environment(config, &vault)? {
            Some(name) => name,
            None => return Ok(None),
        },
    };
    let in_vault = session
        .find_environment(scope, &name)
        .map_err(|e| e.to_string())?
        .is_some();
    let from_toml = config.and_then(|c| c.envs.get(&name)).cloned();
    if !in_vault && from_toml.is_none() {
        return Err(project::no_such_environment(&name, config, &vault));
    }
    Ok(Some((
        in_vault.then_some(name),
        from_toml.unwrap_or_default(),
    )))
}

/// The process's own `NAME=klav://…` variables.
pub(crate) fn inherited_references() -> BTreeMap<String, String> {
    let mut env = BTreeMap::new();
    for (name, value) in std::env::vars_os() {
        if let (Some(name), Some(value)) = (name.to_str(), value.to_str())
            && is_reference(value)
        {
            env.insert(name.to_owned(), value.trim().to_owned());
        }
    }
    env
}

pub(crate) async fn run_cmd(ctx: &mut Ctx, args: AgentRunArgs) -> CliResult<()> {
    let mut o = open(ctx, &args.action, args.config.as_deref()).await?;
    // `--env NAME=REF` is `-e`, as before environments.
    let mut pairs = args.vars.clone();
    let mut named = Vec::new();
    for value in &args.environment {
        if value.contains('=') {
            pairs.push(value.clone());
        } else {
            named.push(value.clone());
        }
    }
    if named.len() > 1 {
        return Err(usage("give one --env"));
    }
    let mut extra: BTreeMap<String, String> = BTreeMap::new();
    for pair in &pairs {
        let (name, value) = pair
            .split_once('=')
            .ok_or_else(|| usage(format!("-e expects NAME=REF, got {pair:?}")))?;
        extra.insert(name.to_owned(), o.expand(value)?);
    }
    let scope_pair = o.scope.clone();
    let scope_ref = scope_pair.as_ref().map(|(v, p)| (v.as_str(), p.as_str()));
    let chosen = agent_environment(
        &o.session,
        o.config.as_ref(),
        scope_ref,
        named.first().map(String::as_str),
    )
    .map_err(usage)?;
    let inherited = inherited_references();
    let (environment, env, fallback_env) = match chosen {
        Some((vault_env, mut from_toml)) => {
            from_toml.extend(extra);
            let fallback: Vec<(String, String)> = inherited.into_iter().collect();
            (vault_env, from_toml, fallback)
        }
        None => {
            let mut env = inherited;
            if let Some(c) = &o.config {
                env.extend(c.env.clone());
            }
            env.extend(extra);
            (None, env, Vec::new())
        }
    };
    let files: Vec<(PathBuf, String)> = match (&o.config, args.no_files) {
        (Some(c), false) => c.files.clone().into_iter().collect(),
        _ => Vec::new(),
    };
    let wait = wait(&args.action);
    let scope = o.scope.clone();
    let scope = scope.as_ref().map(|(v, p)| (v.as_str(), p.as_str()));
    let paths: Vec<PathBuf> = files.iter().map(|(p, _)| p.clone()).collect();
    let ran = klav_sdk::run(
        &mut o.session,
        scope,
        RunRequest {
            env: env.into_iter().collect(),
            files,
            command: args.command,
            cwd: None,
            reason: args.action.reason,
            wait,
            timeout: args.timeout,
            environment,
            fallback_env,
        },
    )
    .await;
    // After the call, whatever its outcome: its own temporaries are gone,
    // or named by its error.
    let paths: Vec<&std::path::Path> = paths.iter().map(PathBuf::as_path).collect();
    let out = match ran {
        Ok(out) => out,
        Err(e) => {
            warn_leftovers(&paths, Some(&e.to_string()));
            return Err(e.into());
        }
    };
    print!("{}", out.stdout);
    eprint!("{}", out.stderr);
    if out.redactions > 0 {
        output::warn(&format!(
            "secret values were removed from the output in {} place(s)",
            out.redactions
        ));
    }
    warn_leftovers(&paths, None);
    if out.timed_out {
        return Err(CliError::Other(format!(
            "the command was killed after {}",
            human(args.timeout)
        )));
    }
    match out.code {
        Some(0) => Ok(()),
        Some(code) => Err(CliError::Exit(u8::try_from(code).unwrap_or(1))),
        None => Err(CliError::Exit(1)),
    }
}

pub(crate) async fn inject_cmd(ctx: &mut Ctx, args: AgentInjectArgs) -> CliResult<()> {
    let mut o = open(ctx, &args.action, args.config.as_deref()).await?;
    let template = match &args.template {
        Some(path) => Some(
            std::fs::read_to_string(path).map_err(|e| usage(format!("{}: {e}", path.display())))?,
        ),
        None => None,
    };
    let reference = args.reference.as_deref().map(|r| o.expand(r)).transpose()?;
    let wait = wait(&args.action);
    let mut signals = Signals::new()?;
    let scope = o.scope.clone();
    let scope = scope.as_ref().map(|(v, p)| (v.as_str(), p.as_str()));
    let injected = klav_sdk::inject_file(
        &mut o.session,
        scope,
        InjectRequest {
            template,
            reference,
            path: args.out.clone(),
            force: args.force,
            reason: args.action.reason,
            wait,
        },
    )
    .await;
    drop(o);
    // After the call, whatever its outcome (`warn_leftovers`).
    if let Err(e) = injected {
        warn_leftovers(&[&args.out], Some(&e.to_string()));
        return Err(e.into());
    }
    // klav_sdk writes it through a temporary `*.klav-tmp` next to it,
    // which the advice names too.
    if let Some(warning) = not_ignored_warning(&args.out) {
        output::warn(&warning);
    }
    warn_leftovers(&[&args.out], None);
    let Some(ttl) = args.ttl else {
        output::info(&format!(
            "Wrote {} (mode 0600). Delete it when done.",
            args.out.display()
        ));
        return Ok(());
    };
    let mut cleanup = Cleanup::default();
    cleanup.add(args.out.clone());
    output::info(&format!(
        "Wrote {} (mode 0600); removing it in {}.",
        args.out.display(),
        human(ttl)
    ));
    tokio::select! {
        () = tokio::time::sleep(ttl) => {}
        _ = signals.recv() => {}
    }
    cleanup.remove_all();
    output::info(&format!("Removed {}.", args.out.display()));
    Ok(())
}

pub(crate) async fn fill_cmd(ctx: &mut Ctx, args: AgentFillArgs) -> CliResult<()> {
    let target = match (&args.cdp, &args.session) {
        _ if args.extension => browser::resolve_target(&ctx.home, "extension")?,
        (Some(cdp), _) => Target::Cdp(BrowserTarget {
            endpoint: cdp.clone(),
            target_id: args.target.clone(),
        }),
        (None, Some(name)) => Target::Cdp(browser::load_session(&ctx.home, name)?),
        (None, None) => return Err(usage("give --cdp, --session or --extension")),
    };
    let selectors: Vec<FieldSelector> = args
        .selectors
        .iter()
        .map(|s| {
            s.split_once('=')
                .map(|(field, selector)| FieldSelector {
                    field: field.trim().to_owned(),
                    selector: selector.trim().to_owned(),
                })
                .ok_or_else(|| usage(format!("--selector expects FIELD=CSS, got {s:?}")))
        })
        .collect::<CliResult<_>>()?;
    let mut o = open(ctx, &args.action, args.config.as_deref()).await?;
    let wait = wait(&args.action);
    let scope = o.scope.clone();
    let scope = scope.as_ref().map(|(v, p)| (v.as_str(), p.as_str()));
    let report = klav_sdk::fill_target(
        &mut o.session,
        &target,
        &args.reference,
        scope,
        &klav_sdk::FillOptions {
            selectors: &selectors,
            submit: args.submit,
            totp: false,
        },
        &args.action.reason,
        wait,
    )
    .await?;
    if args.json {
        return output::json(&report);
    }
    for warning in &report.warnings {
        output::warn(warning);
    }
    output::info(&format!(
        "Filled {} on {}.",
        report.filled.join(", "),
        report.url
    ));
    if report.submitted {
        output::info(&match (report.navigated, &report.url_after) {
            (Some(true), Some(url)) => format!("Submitted the form: the page is now {url}."),
            _ => "Submitted the form: no new page loaded (check the page).".to_owned(),
        });
    }
    Ok(())
}

pub(crate) fn browser_cmd(ctx: &Ctx, cmd: BrowserCommand) -> CliResult<()> {
    match cmd {
        BrowserCommand::Register { name, cdp, target } => {
            browser::register_session(
                &ctx.home,
                &name,
                &BrowserTarget {
                    endpoint: cdp,
                    target_id: target,
                },
            )?;
            output::info(&format!("Registered the browser as sdk:{name}."));
            Ok(())
        }
        BrowserCommand::Forget { name } => {
            browser::forget_session(&ctx.home, &name)?;
            output::info(&format!("Forgot sdk:{name}."));
            Ok(())
        }
    }
}
