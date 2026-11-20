//! `klav sandbox start | ls | stop`: an issuer agent's sandboxes, through
//! the credential proxy on this machine (ADR 0036 §4, E6.1).
//!
//! The package (`ksb1_…`) holds the sandbox's one-time secret. It leaves
//! this command in one of two ways only: the environment of the command
//! after `--` (`KLAV_SANDBOX`), or a new 0600 file (`--package-file`). It
//! is never printed, not in `--json` either, and the child's output is
//! redacted as `klav agent run`'s is. That stops leaks by mistake, not an
//! issuer that wants the package: it controls the command (E6.1).
//!
//! With `--json`, a failure also prints one JSON line on stdout,
//! `{"error", "message", "next"}`, as `klav-forward` does ([`JsonError`]);
//! stderr and the exit code stay what they are without `--json`.

use std::path::Path;
use std::time::Duration;

use klav_core::ids::SandboxId;
use klav_sdk::Agent;
use klav_sdk::sandbox::{self, LiveSandbox, SandboxError, StartRequest};
use klav_sdk::secret_file::SecretFile;
use klav_sdk::{Redactor, StreamRedactor};
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::cli::{
    SandboxAgentArgs, SandboxCommand, SandboxLsArgs, SandboxStartArgs, SandboxStopArgs,
};
use crate::context::Ctx;
use crate::error::{CliError, CliResult, EXIT_ACCOUNT_DELETING, EXIT_DENIED, EXIT_PAUSED, usage};
use crate::output;
use crate::secret_files::Signals;

/// The variable the command after `--` gets the package in.
pub(crate) const PACKAGE_ENV: &str = "KLAV_SANDBOX";

/// The sandbox's setup script (ADR 0036 §14, E1.3), no secrets:
/// - `klav-forward down --if-other-package` stops a forwarder still
///   running from another package (a sandbox resumed with its memory
///   alive, then handed a new one), which would hold the port. It leaves
///   one for this same package alone (the script run again), and does
///   nothing where none runs; exit 0 in all three.
/// - `klav-forward up --daemon` claims the sandbox and keeps forwarding in
///   the background, or says this package's forwarder already runs.
/// - `env` gives the shell the local URLs wherever `up` could write them.
///
/// `crates/klav-forward/tests/up.rs` runs exactly these lines, read from
/// this file (`the_setup_lines_…`), and `tests/sandbox.rs` pins them.
pub(crate) const SETUP: [&str; 3] = [
    "klav-forward down --if-other-package",
    "klav-forward up --daemon",
    "eval \"$(klav-forward env)\"",
];

/// The profile whose sandboxes get [`NORTHFLANK_SETUP`]: the one the
/// `northflank` preset of `klav proxy grant` makes.
pub(crate) const NORTHFLANK_PROFILE: &str = "northflank";

/// The call [`NORTHFLANK_SETUP`]'s `northflank login` makes to check its
/// context (`GET <host>/v1/login`): the `northflank` profile must let it
/// through without an approval step.
pub(crate) const NORTHFLANK_LOGIN_CHECK: (&str, &str) = ("GET", "/v1/login");

/// For a sandbox with the `northflank` profile, after [`SETUP`] (ADR 0036
/// §5, decision of 2026-11-16): points the Northflank CLI at the
/// forwarder, through the URL `eval "$(klav-forward env)"` just set, with
/// a placeholder token. The proxy drops any `Authorization` a tool sends
/// and adds the real one: the placeholder never leaves the sandbox as a
/// credential. `--override` replaces a `klav` context left by an earlier
/// start.
pub(crate) const NORTHFLANK_SETUP: &str = "northflank login -n klav -t klav-placeholder --override --host \"$KLAV_FORWARD_NORTHFLANK_URL\"";

/// The setup lines for a sandbox with `profiles`: [`SETUP`], then
/// [`NORTHFLANK_SETUP`] only when `northflank` is among them.
fn setup_lines(profiles: &[String]) -> Vec<String> {
    let mut lines: Vec<String> = SETUP.iter().map(|l| (*l).to_owned()).collect();
    if profiles.iter().any(|p| p == NORTHFLANK_PROFILE) {
        lines.push(NORTHFLANK_SETUP.to_owned());
    }
    lines
}

/// `start`'s next step. With the `northflank` line, also what it needs
/// from the profile the person signed.
fn start_next(id: SandboxId, profiles: &[String]) -> String {
    let mut next = format!(
        "Put the setup lines in the sandbox's setup script as they are. When the work is done, run `klav sandbox stop {id}` and delete the sandbox at the provider. Unclaimed, it ends {INACTIVITY} after it starts, or at its expiry if that comes first."
    );
    if profiles.iter().any(|p| p == NORTHFLANK_PROFILE) {
        let (method, path) = NORTHFLANK_LOGIN_CHECK;
        next.push_str(&format!(
            " The `northflank login` line needs the `northflank` profile to allow `{method} {path}` without an approval step."
        ));
    }
    next
}

/// What a sandbox lasts without being claimed (the proxy's sweeper, ADR
/// 0036 §4): until layer 6's `klav-forward` claims them, every sandbox
/// ends this long after it starts.
const INACTIVITY: &str = "1 hour";

/// How long the command's output may still take to end once a signal
/// asks `klav` to stop waiting for it.
const OUTPUT_GRACE: Duration = Duration::from_millis(500);

pub(crate) async fn sandbox_cmd(ctx: &Ctx, cmd: SandboxCommand) -> CliResult<()> {
    let json = match &cmd {
        SandboxCommand::Start(args) => args.json.json,
        SandboxCommand::Ls(args) => args.json.json,
        SandboxCommand::Stop(args) => args.json.json,
    };
    // What `stop` had stopped when it failed (`--json` only).
    let mut stopped = None;
    let result = match cmd {
        SandboxCommand::Start(args) => start_cmd(ctx, *args).await,
        SandboxCommand::Ls(args) => ls_cmd(ctx, args).await,
        SandboxCommand::Stop(args) => stop_cmd(ctx, args, &mut stopped).await,
    };
    if json
        && let Err(e) = &result
        && let Some(error) = JsonError::of(e, stopped)
    {
        // Best effort: a closed stdout (`| head -0`) must not turn this
        // error into a write error, with another exit code and text.
        let _ = output::json_line(&error);
    }
    result
}

/// The `--json` failure line of `klav proxy sandboxes`: the same line as
/// this module's commands print, best effort.
pub(crate) fn print_json_failure(e: &CliError) {
    if let Some(error) = JsonError::of(e, None) {
        let _ = output::json_line(&error);
    }
}

/// A failure under `--json`: one line on stdout, as `klav-forward`'s
/// refusals. The text on stderr and the exit code do not change.
///
/// `error` is a `klav_*` code only where Klav already has one: the
/// proxy's refusal (well-formed codes only), `klav_no_proxy`,
/// `klav_proxy_unreachable`, `klav_agents_paused` and
/// `klav_account_deleting`. Every other failure (a usage error, a signal,
/// a lost answer, this agent's own state, the Klav server) has
/// `"error": null`, and the exit code tells them apart. Never the
/// package: no error carries it.
#[derive(Serialize)]
struct JsonError {
    error: Option<String>,
    message: String,
    next: Option<String>,
    /// `stop` that failed halfway: what it had stopped by then.
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    stopped: Option<StoppedView>,
}

impl JsonError {
    /// `None` for the exit code of the command after `--`: its stdout is
    /// the command's, and the command said why it failed.
    fn of(e: &CliError, stopped: Option<StoppedView>) -> Option<Self> {
        let (error, message, next) = match e {
            CliError::Exit(_) => return None,
            CliError::Coded {
                error,
                message,
                next,
                ..
            } => (error.clone(), message.clone(), next.clone()),
            CliError::Client(klav_client::ClientError::Paused(_)) => (
                Some("klav_agents_paused".into()),
                shown(&e.message().unwrap_or_default()),
                None,
            ),
            CliError::Client(klav_client::ClientError::AccountDeleting(_)) => (
                Some("klav_account_deleting".into()),
                shown(&e.message().unwrap_or_default()),
                None,
            ),
            // A name or a path the agent gave can be in the text: no
            // terminal escapes or hidden characters on the line.
            _ => (None, shown(&e.message().unwrap_or_default()), None),
        };
        Some(Self {
            error,
            message,
            next,
            stopped,
        })
    }
}

/// `code` if it has the shape of Klav's codes (`klav_` and lower-case
/// letters, digits or `_`): a code is read from whatever answers on the
/// proxy's port, and anything else is not one.
fn klav_code(code: &str) -> Option<String> {
    let ok = code.len() <= 64
        && code.strip_prefix("klav_").is_some_and(|rest| {
            !rest.is_empty()
                && rest
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        });
    ok.then(|| code.to_owned())
}

fn load(ctx: &Ctx, target: &SandboxAgentArgs) -> CliResult<Agent> {
    let name = klav_sdk::config::pick(&ctx.home, target.agent.as_deref())?;
    Ok(Agent::load(&ctx.home, &name)?)
}

/// The exit code and the `next` of an error from the proxy or the SDK.
/// Errors of this agent's own state (pause, account deletion, rollback)
/// keep the codes every agent command uses.
fn sandbox_error(e: SandboxError) -> CliError {
    let next = match &e {
        SandboxError::Client(_) | SandboxError::AnswerLost(_) => None,
        SandboxError::NoProxy => Some(
            "Tell the person this message, and that they can let this agent start sandboxes again with `klav proxy issuer add <agent>` (after `klav proxy use` if the account has no proxy), or in the Klav app (Development › Sandboxes). Do not run it yourself and do not copy keys into the sandbox. If the code can run on this machine, offer to run it here with `run_with_secrets` or `klav agent run`."
                .to_owned(),
        ),
        SandboxError::ProxyUnreachable => Some(
            "Check that `klav-proxy serve` runs on this machine and on this port (`--proxy-port`). If it does not, tell the person; do not retry in a loop."
                .to_owned(),
        ),
        SandboxError::Refused { next, .. } => Some(shown(next)),
    };
    let code = match e.code() {
        "klav_no_proxy"
        | "klav_not_issuer"
        | "klav_profile_not_allowed"
        | "klav_too_many_sandboxes" => EXIT_DENIED,
        "klav_agents_paused" => EXIT_PAUSED,
        "klav_account_deleting" => EXIT_ACCOUNT_DELETING,
        _ => 1,
    };
    match e {
        SandboxError::Client(e) => CliError::Client(e),
        e => {
            // Whatever answers on the port wrote the refusal's texts: no
            // terminal escapes or hidden characters reach the agent.
            let error = match &e {
                SandboxError::AnswerLost(_) => None,
                e => klav_code(e.code()),
            };
            CliError::Coded {
                code,
                error,
                message: shown(&e.to_string()),
                next: next.filter(|n| !n.is_empty()),
            }
        }
    }
}

/// `text` without control, format or separator characters.
fn shown(text: &str) -> String {
    text.chars()
        .filter(|c| !klav_core::text::is_hidden(*c))
        .collect()
}

/// `in 6h 12m`, `in 40m`, or `expired`.
pub(crate) fn expires_in(at_ms: i64) -> String {
    let left = (at_ms - crate::time::now_ms()) / 60_000;
    if left <= 0 {
        return "expired".into();
    }
    match (left / 60, left % 60) {
        (0, m) => format!("in {m}m"),
        (h, 0) => format!("in {h}h"),
        (h, m) => format!("in {h}h {m}m"),
    }
}

/// `--json` of `start`: never the package (E6.1, P4).
#[derive(Serialize)]
struct StartedView<'a> {
    sandbox_id: SandboxId,
    label: &'a str,
    profiles: &'a [String],
    expires_at: i64,
    /// The lines for the sandbox's setup script ([`setup_lines`]): no
    /// secrets.
    setup: Vec<String>,
    next: String,
}

async fn start_cmd(ctx: &Ctx, args: SandboxStartArgs) -> CliResult<()> {
    if args.package_file.is_none() && args.command.is_empty() {
        return Err(usage(
            "say where the package goes: `klav sandbox start … -- <command>` runs the command with it in KLAV_SANDBOX, or `--package-file PATH` writes it to a new file",
        ));
    }
    let mut agent = load(ctx, &args.target)?;
    // Before the file and the start: a signal from here on is read, never
    // left pending for the command spawned later.
    let mut signals = Signals::new()?;
    // The file first: a path that is taken, or a file that cannot be
    // created, fails before any sandbox exists. Only its 0600 temporary
    // exists until the package is here; then it takes its name whole, in
    // one step (`klav_sdk::secret_file`), so the name never holds an empty
    // or partial package. Dropped on any early return, the temporary goes.
    let file = match &args.package_file {
        Some(path) => {
            if std::fs::symlink_metadata(path).is_ok() {
                return Err(usage(format!(
                    "{} already exists: give --package-file a path that does not exist yet",
                    path.display()
                )));
            }
            Some(SecretFile::create(path, false).map_err(|e| usage(e.to_string()))?)
        }
        None => None,
    };
    let request = StartRequest {
        label: args.label.clone(),
        profiles: args.profiles.clone(),
        ttl_secs: args.ttl.map(|t| t.as_secs()),
    };
    let result = tokio::select! {
        result = sandbox::start(&mut agent, args.target.proxy_port, &request) => result,
        signal = signals.recv() => {
            return Err(interrupted(signal, "while the sandbox was being started; `klav sandbox ls` shows whether one started, and `klav sandbox stop <id>` ends it".into()));
        }
    };
    let started = match result {
        Ok(s) => s,
        // Only the proxy's answer: an error before it was asked (the Klav
        // server unreachable) started nothing.
        Err(SandboxError::AnswerLost(why)) => {
            return Err(CliError::Other(format!(
                "Klav's credential proxy did not give a usable answer ({}). A sandbox may have started anyway: `klav sandbox ls` shows it, and `klav sandbox stop <id>` ends it.",
                shown(&why)
            )));
        }
        Err(e) => {
            return Err(sandbox_error(e));
        }
    };
    let id = started.sandbox_id;
    // A signal that came with the answer: nothing is handed out.
    if let Ok(signal) = tokio::time::timeout(Duration::ZERO, signals.recv()).await {
        drop(started);
        let ended = stop_unheld(&agent, args.target.proxy_port, id).await;
        return Err(interrupted(
            signal,
            format!("before the package was handed out; {ended}"),
        ));
    }
    let next = start_next(id, &args.profiles);
    let view = StartedView {
        sandbox_id: id,
        label: &args.label,
        profiles: &args.profiles,
        expires_at: started.expires_at,
        setup: setup_lines(&args.profiles),
        next: next.clone(),
    };

    if let (Some(file), Some(path)) = (file, &args.package_file) {
        // A name taken since the check above is refused, never replaced,
        // and a failed write leaves nothing under it.
        let written = file.write(started.package.as_bytes());
        drop(started);
        // On stderr, whatever the write's outcome; `--json` is unchanged.
        crate::secret_files::warn_leftovers(
            &[path.as_path()],
            written.as_ref().err().map(ToString::to_string).as_deref(),
        );
        if let Err(e) = written {
            // Nobody can have the package: end the sandbox now.
            let ended = stop_unheld(&agent, args.target.proxy_port, id).await;
            let why = match e.io_error() {
                Some(cause) => format!("cannot write {}: {cause}", path.display()),
                None => format!(
                    "{} was created by someone else while the sandbox started, and was left as it is",
                    path.display()
                ),
            };
            return Err(CliError::Other(format!(
                "{why}{}; {ended}",
                e.leftover_note()
            )));
        }
        return report(&args, &view, Some(path), false);
    }

    // `-- <command>`: our own lines go to stderr, so stdout is the
    // command's (redacted) output.
    report(&args, &view, None, true)?;
    let redactor = || Redactor::new([started.package.as_str()]);
    let (program, rest) = args
        .command
        .split_first()
        .ok_or_else(|| usage("missing command"))?;
    let mut command = tokio::process::Command::new(program);
    command
        .args(rest)
        .env(PACKAGE_ENV, started.package.as_str())
        // No input: the redaction holds back the end of each output until
        // more comes, so a prompt would never show (as `klav agent run`).
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let spawned = command.spawn();
    // `Command` keeps its own copy of the environment, which cannot be
    // zeroized: drop it right away (as `klav run`, threat T33).
    drop(command);
    let (out_redactor, err_redactor) = (redactor(), redactor());
    drop(started);
    let mut child = match spawned {
        Ok(c) => c,
        Err(e) => {
            let ended = stop_unheld(&agent, args.target.proxy_port, id).await;
            return Err(CliError::Other(format!(
                "cannot run {}: {e}; {ended}",
                program.to_string_lossy()
            )));
        }
    };
    let stdout = child.stdout.take().ok_or_else(|| usage("no stdout"))?;
    let stderr = child.stderr.take().ok_or_else(|| usage("no stderr"))?;
    let pump_out = tokio::spawn(pump(stdout, tokio::io::stdout(), out_redactor));
    let pump_err = tokio::spawn(pump(stderr, tokio::io::stderr(), err_redactor));
    let aborts = [pump_out.abort_handle(), pump_err.abort_handle()];
    // A signal while the command runs is remembered: once it is done,
    // `klav` then waits for the output only a moment, so a process left
    // holding the output does not need a second signal.
    let mut signalled = false;
    let status = loop {
        tokio::select! {
            status = child.wait() => break status?,
            signal = signals.recv() => {
                signalled = true;
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
    // The command is done; a process it left behind may keep its output
    // open. Still answer signals while waiting for the output's end.
    // A signal that came with the command's exit (Ctrl-C to the group)
    // must not cut what the command already wrote: the readers get a
    // moment to finish before the signal counts.
    let mut redactions = 0;
    let mut cut = false;
    let joined = async { [pump_out.await, pump_err.await] };
    tokio::pin!(joined);
    let pumped = if signalled {
        tokio::time::timeout(OUTPUT_GRACE, &mut joined).await.ok()
    } else {
        tokio::select! {
            pumped = &mut joined => Some(pumped),
            _ = signals.recv() => tokio::time::timeout(OUTPUT_GRACE, &mut joined).await.ok(),
        }
    };
    match pumped {
        Some(pumped) => {
            for pumped in pumped {
                match pumped {
                    Ok(Ok(n)) => redactions += n,
                    Ok(Err(Pumped::Overflow)) => cut = true,
                    Ok(Err(Pumped::Io)) | Err(_) => {}
                }
            }
        }
        None => {
            for abort in &aborts {
                abort.abort();
            }
            output::warn(
                "stopped reading the command's output: a process it started still holds it open",
            );
        }
    }
    if redactions > 0 {
        output::warn(&format!(
            "the sandbox's package was removed from the command's output in {redactions} place(s)"
        ));
    }
    if cut {
        output::warn("the command's output was cut: it held back too much around the package");
    }
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
        output::warn(&format!(
            "the command failed; sandbox {id} is still live: if the command did not create it, run `klav sandbox stop {id}`"
        ));
        Err(CliError::Exit(code))
    }
}

/// Ends a sandbox whose package nobody got, and says whether it did.
async fn stop_unheld(agent: &Agent, port: u16, id: SandboxId) -> String {
    match sandbox::stop(agent, port, id).await {
        Ok(_) => format!("sandbox {id} was stopped"),
        Err(_) => format!("sandbox {id} could not be stopped: run `klav sandbox stop {id}`"),
    }
}

/// The exit for a signal that came before the command ran: 128 plus its
/// number, as a shell reports it.
fn interrupted(signal: Signal, what: String) -> CliError {
    CliError::Coded {
        code: u8::try_from(128 + signal as i32).unwrap_or(1),
        error: None,
        message: format!("interrupted ({signal}) {what}"),
        next: None,
    }
}

enum Pumped {
    Overflow,
    Io,
}

/// Copies `from` to `to` through `redactor`; returns how many places it
/// replaced. A stretch it would have to hold past its limit cuts the rest
/// of the output (fail closed).
async fn pump(
    mut from: impl AsyncRead + Unpin,
    mut to: impl AsyncWrite + Unpin,
    redactor: Redactor,
) -> Result<usize, Pumped> {
    let mut stream = StreamRedactor::new(redactor);
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let n = from.read(&mut buf).await.map_err(|_| Pumped::Io)?;
        if n == 0 {
            break;
        }
        let Ok(out) = stream.push(&buf[..n]) else {
            // Drain the rest unseen so the child is not blocked on a pipe.
            while from.read(&mut buf).await.map_err(|_| Pumped::Io)? > 0 {}
            return Err(Pumped::Overflow);
        };
        to.write_all(&out).await.map_err(|_| Pumped::Io)?;
        to.flush().await.map_err(|_| Pumped::Io)?;
    }
    let (rest, n) = stream.finish_counted();
    to.write_all(&rest).await.map_err(|_| Pumped::Io)?;
    to.flush().await.map_err(|_| Pumped::Io)?;
    Ok(n)
}

/// What `start` says: on stdout, or on stderr when a command runs after.
fn report(
    args: &SandboxStartArgs,
    view: &StartedView<'_>,
    file: Option<&Path>,
    to_stderr: bool,
) -> CliResult<()> {
    if args.json.json {
        if to_stderr {
            let text = serde_json::to_string(view).map_err(|e| CliError::Other(e.to_string()))?;
            eprintln!("{text}");
            return Ok(());
        }
        return output::json(view);
    }
    let mut lines = vec![format!(
        "Started sandbox {} ({}), with {}; it expires {} ({} UTC).",
        view.sandbox_id,
        view.label,
        view.profiles.join(", "),
        expires_in(view.expires_at),
        crate::time::format_utc_minutes(view.expires_at),
    )];
    match file {
        Some(path) => lines.push(format!(
            "Its package is in {} (mode 0600): put it in the sandbox's environment as {PACKAGE_ENV} and delete the file.",
            path.display()
        )),
        None => lines.push(format!("The command gets its package in {PACKAGE_ENV}.")),
    }
    lines.push("Setup lines for the sandbox (no secrets):".to_owned());
    lines.extend(view.setup.iter().map(|l| format!("  {l}")));
    lines.push(format!("Next: {}", view.next));
    for line in lines {
        if to_stderr {
            output::info(&line);
        } else {
            output::line(&line);
        }
    }
    Ok(())
}

#[derive(Serialize)]
struct LsView<'a> {
    sandboxes: &'a [LiveSandbox],
}

async fn ls_cmd(ctx: &Ctx, args: SandboxLsArgs) -> CliResult<()> {
    let agent = load(ctx, &args.target)?;
    // Labels and profiles come from whatever answers on the port: shown
    // without control or hidden characters, in the table and the JSON.
    let live: Vec<LiveSandbox> = sandbox::list(&agent, args.target.proxy_port)
        .await
        .map_err(sandbox_error)?
        .into_iter()
        .map(|mut s| {
            s.label = shown(&s.label);
            for p in &mut s.profiles {
                *p = shown(p);
            }
            s
        })
        .collect();
    if args.json.json {
        return output::json(&LsView { sandboxes: &live });
    }
    if live.is_empty() {
        output::info("No live sandboxes.");
        return Ok(());
    }
    let rows: Vec<Vec<String>> = live
        .iter()
        .map(|s| {
            vec![
                s.sandbox_id.to_string(),
                s.label.clone(),
                s.profiles.join(","),
                expires_in(s.expires_at),
                if s.claimed {
                    "claimed".into()
                } else {
                    "waiting for claim".into()
                },
            ]
        })
        .collect();
    output::table(&["ID", "LABEL", "PROFILES", "EXPIRES", "STATE"], &rows);
    Ok(())
}

#[derive(Serialize)]
struct StoppedView {
    stopped: Vec<SandboxId>,
    /// Whether Klav's log already has every end (otherwise the proxy sends
    /// them when it can reach the server).
    logged: bool,
}

/// `stop`. Under `--json`, a failure halfway leaves what it had stopped in
/// `partial`, which goes in the error's line (one JSON document on
/// stdout, never two).
async fn stop_cmd(
    ctx: &Ctx,
    args: SandboxStopArgs,
    partial: &mut Option<StoppedView>,
) -> CliResult<()> {
    let agent = load(ctx, &args.target)?;
    let port = args.target.proxy_port;
    let ids: Vec<SandboxId> = match &args.id {
        Some(text) => vec![
            text.trim()
                .parse()
                .map_err(|_| usage(format!("{text:?} is not a sandbox ID")))?,
        ],
        None => sandbox::list(&agent, port)
            .await
            .map_err(sandbox_error)?
            .into_iter()
            .map(|s| s.sandbox_id)
            .collect(),
    };
    let mut view = StoppedView {
        stopped: Vec::new(),
        logged: true,
    };
    let all = args.id.is_none();
    for id in ids {
        match sandbox::stop(&agent, port, id).await {
            Ok(logged) => {
                view.logged &= logged;
                view.stopped.push(id);
            }
            // Ended by the sweeper since the list: nothing to stop.
            Err(SandboxError::Refused { code, .. }) if all && code == "klav_sandbox_not_found" => {}
            // What was stopped before the error is said on stdout, in
            // `--json` too, and the error after it.
            Err(e) => {
                if args.json.json {
                    // One ID: nothing else was stopped, so nothing to say.
                    if all {
                        *partial = Some(view);
                    }
                } else {
                    for done in &view.stopped {
                        output::line(&format!("Stopped sandbox {done}."));
                    }
                }
                return Err(sandbox_error(e));
            }
        }
    }
    if args.json.json {
        return output::json(&view);
    }
    if view.stopped.is_empty() {
        output::info("No live sandboxes.");
    }
    for id in &view.stopped {
        output::line(&format!("Stopped sandbox {id}."));
    }
    if !view.logged {
        output::info(
            "Klav's log records the end when the proxy can reach the server again; the sandbox is already stopped.",
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profiles(names: &[&str]) -> Vec<String> {
        names.iter().map(|n| (*n).to_owned()).collect()
    }

    /// The `northflank login` line comes after the three lines, only with
    /// the `northflank` profile, and its `--host` is the variable the
    /// `eval` line sets: never a fixed port.
    #[test]
    fn the_northflank_line_comes_only_with_its_profile() {
        let plain: Vec<String> = SETUP.iter().map(|l| (*l).to_owned()).collect();
        for without in [&[][..], &["railway"], &["northflank-eu"], &["Northflank"]] {
            assert_eq!(setup_lines(&profiles(without)), plain, "{without:?}");
            let next = start_next(SandboxId::generate(), &profiles(without));
            assert!(!next.contains("northflank"), "{next}");
        }
        for with in [&["northflank"][..], &["railway", "northflank"]] {
            let lines = setup_lines(&profiles(with));
            assert_eq!(lines.len(), 4, "{lines:?}");
            assert_eq!(lines[..3], plain[..]);
            assert_eq!(
                lines[3],
                "northflank login -n klav -t klav-placeholder --override --host \"$KLAV_FORWARD_NORTHFLANK_URL\""
            );
            assert!(
                lines[2].starts_with("eval ") && lines[3].contains("$KLAV_FORWARD_NORTHFLANK_URL"),
                "the line reads what the eval line sets"
            );
            assert!(!lines[3].contains("127.0.0.1") && !lines[3].contains(":8790"));
            let next = start_next(SandboxId::generate(), &profiles(with));
            assert!(next.contains("GET /v1/login"), "{next}");
        }
    }

    /// No setup line carries a secret: the only token is the fixed
    /// placeholder, the package's variable is never named, and nothing in
    /// them depends on the sandbox, its package or the environment.
    #[test]
    fn the_setup_lines_never_hold_a_secret() {
        let lines = setup_lines(&profiles(&["railway", "northflank"]));
        for line in &lines {
            assert!(!line.contains(PACKAGE_ENV), "{line}");
            assert!(!line.contains("ksb1_"), "{line}");
        }
        let tokens: Vec<&str> = lines
            .iter()
            .flat_map(|l| l.split_once(" -t ").map(|(_, rest)| rest))
            .map(|rest| rest.split(' ').next().unwrap_or(""))
            .collect();
        assert_eq!(tokens, ["klav-placeholder"]);
        // The same for every sandbox: built from constants and the
        // profile names alone.
        assert_eq!(lines, setup_lines(&profiles(&["railway", "northflank"])));
    }
}
