//! `klav run -- <cmd>`: resolves `klav.toml` (`[env]`, `[files]`), `-e`
//! and inherited `NAME=klav://…` variables, or an environment (`--env`,
//! ADR 0032 §5), then runs the command with the values in its environment
//! only. Nothing goes in argv or on stdout.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use klav_client::environments::EnvironmentDetail;
use klav_core::model::item::FieldKind;
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use zeroize::Zeroizing;

use crate::cli::RunArgs;
use crate::context::Ctx;
use crate::error::{CliError, CliResult, usage};
use crate::output;
use crate::project::{self, ProjectConfig, is_reference};
use crate::secret_files::{
    Cleanup, Signals, warn_if_not_ignored, warn_leftovers, write_new_private,
};

/// The environment `klav run` uses without `--env` (ADR 0032 §5, see
/// [`project::default_environment`]).
async fn default_environment(
    ctx: &mut Ctx,
    config: Option<&ProjectConfig>,
) -> CliResult<Option<String>> {
    let mut vault = Vec::new();
    if project::default_needs_vault(config)
        && let Some(project) = config.and_then(|c| c.project.as_deref())
    {
        vault = ctx
            .backend()
            .await?
            .environments(Some(project))
            .await?
            .into_iter()
            .map(|l| l.name)
            .collect();
    }
    project::default_environment(config, &vault).map_err(usage)
}

/// An environment ready to inject: variable → reference, the confirmation
/// it needs, and the vault's environment (for its flag and agent changes).
pub(crate) struct ChosenEnvironment {
    pub(crate) env: BTreeMap<String, String>,
    pub(crate) confirmation: project::EnvConfirmation,
    pub(crate) detail: Option<EnvironmentDetail>,
}

/// The variables of environment `name` (ADR 0032 §5), later sources
/// winning: `inherited` (the process's `klav://` variables), the project's
/// environment item `name`, `[env.name]` of `klav.toml`, then `extra`
/// (`-e`). Fails before anything runs when neither the vault nor the
/// `klav.toml` has it.
pub(crate) async fn environment_variables(
    ctx: &mut Ctx,
    config: Option<&ProjectConfig>,
    name: &str,
    inherited: BTreeMap<String, String>,
    extra: &[(String, String)],
) -> CliResult<ChosenEnvironment> {
    let mut project = config.and_then(|c| c.project.clone());
    let mut warnings = Vec::new();
    let repo = std::env::current_dir()
        .ok()
        .and_then(|d| project::detect_git_repo(&d, "origin"));
    // The link only suggests a project, and only through the same question
    // (ADR 0032 §2).
    let projects = ctx.backend().await?.projects(None).await?;
    if project.is_none()
        && let Some(repo) = &repo
    {
        let linked: Vec<&klav_client::ProjectSummary> =
            projects.iter().filter(|p| p.repos.contains(repo)).collect();
        if let [one] = linked.as_slice() {
            let suggested = format!("{}/{}", one.vault, one.name);
            match ctx.input.question(&format!(
                "This repository looks like {suggested}, by origin = {repo}. Use it? [y/N] "
            ))? {
                Some(a) if matches!(a.to_lowercase().as_str(), "y" | "yes" | "s" | "si" | "sí") => {
                    project = Some(suggested);
                }
                Some(_) => return Err(usage("cancelled")),
                // No terminal to ask on: the link only suggests, so the
                // run goes on with what klav.toml names, without the
                // vault's environment of that project.
                None => warnings.push(format!(
                    "this repository looks like {suggested}: write project = \"{suggested}\" in klav.toml to use its environments"
                )),
            }
        }
    }
    if let (Some(project), Some(repo)) = (&project, &repo) {
        let wanted = projects
            .iter()
            .find(|p| format!("{}/{}", p.vault, p.name).eq_ignore_ascii_case(project));
        let linked_elsewhere = projects.iter().any(|p| p.repos.contains(repo));
        if let Some(p) = wanted
            && !p.repos.contains(repo)
            && linked_elsewhere
        {
            warnings.push(format!(
                "this klav.toml asks for secrets from {project}, which isn't linked to {repo}"
            ));
        }
        if let Some(c) = config {
            let prefix = format!("klav://{project}/");
            for reference in c.envs.get(name).into_iter().flat_map(|e| e.values()) {
                if !reference.to_lowercase().starts_with(&prefix.to_lowercase())
                    && let Some(other) = reference
                        .strip_prefix("klav://")
                        .map(|r| r.splitn(3, '/').take(2).collect::<Vec<_>>().join("/"))
                {
                    let note = format!(
                        "this klav.toml asks for secrets from {other}, which isn't linked to {repo}"
                    );
                    if !warnings.contains(&note) {
                        warnings.push(note);
                    }
                }
            }
        }
    }
    let detail = match &project {
        Some(p) => ctx.backend().await?.environment(Some(p), name).await?,
        None => None,
    };
    let from_toml = config.and_then(|c| c.envs.get(name));
    if detail.is_none() && from_toml.is_none() {
        let mut vault = Vec::new();
        if let Some(p) = &project {
            vault = ctx
                .backend()
                .await?
                .environments(Some(p))
                .await?
                .into_iter()
                .map(|l| l.name)
                .collect();
        }
        return Err(usage(project::no_such_environment(name, config, &vault)));
    }
    let mut env = inherited;
    let mut origins: BTreeMap<String, String> = env
        .keys()
        .map(|k| (k.clone(), "process environment".to_owned()))
        .collect();
    if let Some(d) = &detail {
        for v in &d.variables {
            env.insert(v.name.clone(), v.resolve.clone());
            origins.insert(
                v.name.clone(),
                match &v.origin {
                    klav_client::environments::VariableOrigin::Value => "vault".to_owned(),
                    o => format!("vault, {}", crate::commands::env::origin_text(o)),
                },
            );
        }
    }
    if let Some(vars) = from_toml {
        for (k, v) in vars {
            env.insert(k.clone(), v.clone());
            origins.insert(k.clone(), "klav.toml".to_owned());
        }
    }
    for (k, v) in extra {
        env.insert(k.clone(), v.clone());
        origins.insert(k.clone(), "-e".to_owned());
    }
    Ok(ChosenEnvironment {
        env,
        confirmation: project::EnvConfirmation {
            project,
            environment: name.to_owned(),
            variables: origins.into_iter().collect(),
            warnings,
        },
        detail,
    })
}

/// Before a value of an environment is read: what an agent changed since
/// the person's version, and that a protected one asks for presence (ADR
/// 0032 §3), on stderr.
pub(crate) fn before_presence(chosen: &ChosenEnvironment) {
    if let Some(d) = &chosen.detail {
        if let Some(changes) = &d.agent_changes {
            output::warn(&crate::commands::env::agent_changes_text(changes));
        }
        if d.listing.protected {
            output::info(&format!(
                "“{}” is protected: Klav asks for your presence for this command.",
                d.listing.name
            ));
        }
    }
}

pub(crate) async fn run_cmd(ctx: &mut Ctx, args: RunArgs) -> CliResult<()> {
    let config = project::load(args.config.as_deref())?;
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
    let project_name = config.as_ref().and_then(|c| c.project.clone());
    let mut extra = Vec::new();
    for pair in &pairs {
        let (name, value) = pair
            .split_once('=')
            .ok_or_else(|| usage(format!("-e expects NAME=REF, got {pair:?}")))?;
        let reference = project::expand(project_name.as_deref(), value)
            .map_err(|e| usage(format!("-e {name}: {e}")))?;
        extra.push((name.to_owned(), reference));
    }
    let mut inherited: BTreeMap<String, String> = BTreeMap::new();
    for (name, value) in std::env::vars_os() {
        if let (Some(name), Some(value)) = (name.to_str(), value.to_str())
            && is_reference(value)
        {
            inherited.insert(name.to_owned(), value.trim().to_owned());
        }
    }
    let environment = match named.pop() {
        Some(name) => Some(name),
        None => default_environment(ctx, config.as_ref()).await?,
    };

    // Variable → reference. Later sources win: inherited, klav.toml, -e.
    let env: BTreeMap<String, String> = match &environment {
        Some(name) => {
            let chosen =
                environment_variables(ctx, config.as_ref(), name, inherited, &extra).await?;
            project::confirm_environment(
                &ctx.home,
                config.as_ref(),
                &chosen.confirmation,
                args.trust,
            )?;
            before_presence(&chosen);
            chosen.env
        }
        None => {
            if let Some(c) = &config {
                project::confirm_trusted(&ctx.home, c, args.trust)?;
            }
            let mut all = inherited;
            if let Some(c) = &config {
                all.extend(c.env.clone());
            }
            all.extend(extra);
            all
        }
    };
    let files: BTreeMap<PathBuf, String> = match (&config, args.no_files) {
        (Some(c), false) => c.files.clone(),
        _ => BTreeMap::new(),
    };
    if env.is_empty() && files.is_empty() {
        output::warn("no references to resolve (no klav.toml, -e or NAME=klav://… variables)");
    }

    let mut cleanup = Cleanup::default();
    let mut signals = None;
    let mut values: Vec<(String, Zeroizing<String>)> = Vec::new();
    if !env.is_empty() || !files.is_empty() {
        let references: Vec<String> = env.values().chain(files.values()).cloned().collect();
        let backend = ctx.backend().await?;
        let resolved = backend.resolve(&references).await?;
        // Handle signals before writing any file, so that one arriving
        // right after a write still removes it (not earlier: Ctrl-C must
        // still interrupt the password prompt).
        signals = Some(Signals::new()?);
        let (env_values, file_values) = resolved.split_at(env.len());
        for ((name, _), value) in env.iter().zip(env_values) {
            if value.kind == FieldKind::File {
                return Err(usage(format!(
                    "{name}: {} is a file; put it under [files] in klav.toml",
                    value.canonical
                )));
            }
            values.push((name.clone(), Zeroizing::new(value.text()?.to_owned())));
        }
        // Leftover temporaries are reported once the writes are done (or
        // one failed), from one listing per directory.
        let mut tried: Vec<&Path> = Vec::new();
        for ((path, _), value) in files.iter().zip(file_values) {
            if let Some(parent) = path.parent()
                && let Err(e) = std::fs::create_dir_all(parent)
            {
                warn_leftovers(&tried, None);
                return Err(e.into());
            }
            cleanup.add(path.clone());
            tried.push(path);
            if let Err(e) = write_new_private(path, value.value.expose(), false) {
                // Not ours: never remove a file that was already there.
                cleanup.forget(path);
                warn_leftovers(&tried, e.message().as_deref());
                return Err(e);
            }
            warn_if_not_ignored(path);
        }
        warn_leftovers(&tried, None);
        drop(resolved);
    }
    // Forget the unlocked vault while the child runs.
    ctx.close();

    let mut signals = match signals {
        Some(s) => s,
        None => Signals::new()?,
    };
    let (program, rest) = args
        .command
        .split_first()
        .ok_or_else(|| usage("missing command"))?;
    let mut command = tokio::process::Command::new(program);
    command.args(rest);
    for (name, value) in &values {
        command.env(name, value.as_str());
    }
    let spawned = command.spawn();
    // `Command` keeps its own copies of the environment, which cannot be
    // zeroized; drop it and ours right away (docs/cli.md, threat T33).
    drop(command);
    drop(values);
    let mut child = spawned
        .map_err(|e| CliError::Other(format!("cannot run {}: {e}", program.to_string_lossy())))?;

    let status = loop {
        tokio::select! {
            status = child.wait() => break status?,
            signal = signals.recv() => {
                // Ctrl-C already reaches the child through the terminal's
                // process group; forward the others.
                if signal != Signal::SIGINT
                    && let Some(pid) = child.id()
                    && let Ok(pid) = i32::try_from(pid)
                {
                    let _ = kill(Pid::from_raw(pid), signal);
                }
            }
        }
    };
    cleanup.remove_all();
    let code = match status.code() {
        Some(code) => u8::try_from(code).unwrap_or(1),
        None => {
            use std::os::unix::process::ExitStatusExt;
            status
                .signal()
                .and_then(|s| u8::try_from(128 + s).ok())
                .unwrap_or(1)
        }
    };
    if code == 0 {
        Ok(())
    } else {
        Err(CliError::Exit(code))
    }
}
