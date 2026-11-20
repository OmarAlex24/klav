//! `klav run -- <cmd>`: resolves `klav.toml` (`[env]`, `[files]`), `-e`
//! and inherited `NAME=klav://…` variables, then runs the command with the
//! values in its environment only. Nothing goes in argv or on stdout.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use klav_core::model::item::FieldKind;
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use zeroize::Zeroizing;

use crate::cli::RunArgs;
use crate::context::Ctx;
use crate::error::{CliError, CliResult, usage};
use crate::output;
use crate::project::{self, is_reference};
use crate::secret_files::{
    Cleanup, Signals, warn_if_not_ignored, warn_leftovers, write_new_private,
};

pub(crate) async fn run_cmd(ctx: &mut Ctx, args: RunArgs) -> CliResult<()> {
    let config = project::load(args.config.as_deref())?;
    if let Some(c) = &config {
        project::confirm_trusted(&ctx.home, c, args.trust)?;
    }
    let project_name = config.as_ref().and_then(|c| c.project.clone());

    // Variable → reference. Later sources win: inherited, klav.toml, -e.
    let mut env: BTreeMap<String, String> = BTreeMap::new();
    for (name, value) in std::env::vars_os() {
        if let (Some(name), Some(value)) = (name.to_str(), value.to_str())
            && is_reference(value)
        {
            env.insert(name.to_owned(), value.trim().to_owned());
        }
    }
    if let Some(c) = &config {
        env.extend(c.env.clone());
    }
    for pair in &args.env {
        let (name, value) = pair
            .split_once('=')
            .ok_or_else(|| usage(format!("-e expects NAME=REF, got {pair:?}")))?;
        let reference = project::expand(project_name.as_deref(), value).map_err(usage)?;
        env.insert(name.to_owned(), reference);
    }
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
