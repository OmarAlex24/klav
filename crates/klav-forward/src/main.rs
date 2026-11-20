//! `klav-forward`: the sandbox's side of Klav's credential proxy (ADR 0036
//! §5, §7 mode (a), §10). It holds no vault code.
//!
//! `up` reads the package from `KLAV_SANDBOX` and hands it to a child
//! process of its own through a pipe, never through the child's arguments
//! or environment (the child starts with `KLAV_SANDBOX` removed). The
//! child makes the channel key in memory, claims the sandbox, forgets the
//! secret and relays `127.0.0.1:PORT` to the proxy.

#![allow(clippy::print_stdout, clippy::print_stderr)]

/// The commit this binary was built from (`klav-daemon/build.rs`): only
/// `--version` reads it.
#[allow(dead_code)]
mod build {
    include!(concat!(env!("OUT_DIR"), "/build_identity.rs"));
}

use std::io::{BufRead, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{ExitCode, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use clap::{Parser, Subcommand};
use klav_core::crypto::channel::TlsSigner;
use klav_core::crypto::sandbox::decode_package;
use klav_forward::forward::{self, Bound, Proxy, Refusal};
use klav_forward::http;
use klav_forward::setup::{self, Claimed, DEFAULT_PORT, DEFAULT_PROFILE_FILE, State};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// The control socket `down` stops the forwarder through. A module of
/// the binary, like the skill: the library `klav-proxy` links is unchanged.
mod control;
/// The Klav skill `up` installs (ADR 0036 E1.4). A module of the binary,
/// so the library `klav-proxy` links never reads `skill/SKILL.md`.
mod skill;
#[cfg(test)]
mod test_dir;
#[cfg(test)]
pub(crate) use test_dir::TestDir;

/// The environment variable that holds the package until the claim.
const PACKAGE_ENV: &str = "KLAV_SANDBOX";
/// The longest package text read from the pipe.
const MAX_PACKAGE: u64 = 4096;

/// Exit codes, as `klav` uses them (ADR 0015).
const EXIT_USAGE: u8 = 2;
const EXIT_DENIED: u8 = 5;
const EXIT_EXPIRED: u8 = 6;
const EXIT_PAUSED: u8 = 7;

#[derive(Parser)]
#[command(
    name = "klav-forward",
    version = crate::build::version(),
    about = "Lets this sandbox use Klav's credential proxy: your API keys stay at the proxy, never in the sandbox.",
    after_help = "Errors come as JSON with `error`, `message` and `next`. Tell the person the message and follow `next`: never retry in a loop, and never look for a token elsewhere."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Claim the sandbox in KLAV_SANDBOX (from `klav sandbox start`) and forward
    /// http://127.0.0.1:PORT/<profile>/… to the proxy.
    Up {
        /// Keep running in the background after the claim (for a setup script).
        #[arg(long)]
        daemon: bool,
        /// The local port.
        #[arg(long, default_value_t = DEFAULT_PORT)]
        port: u16,
        /// Where the state, the log and the fallback shell lines go
        /// (default: $KLAV_FORWARD_HOME or ~/.klav-forward).
        #[arg(long)]
        state_dir: Option<PathBuf>,
        /// Where the shell lines with the local URLs go.
        #[arg(long, default_value = DEFAULT_PROFILE_FILE)]
        profile_file: PathBuf,
        /// Do not install the Klav skill for this sandbox's user.
        #[arg(long)]
        no_skill: bool,
        /// How long to keep trying while the proxy or Klav's server does not answer.
        #[arg(long, default_value_t = 120, hide = true)]
        claim_wait_secs: u64,
        /// How often the forwarder asks the proxy whether its sandbox lives.
        #[arg(long, default_value_t = forward::KEEP_ALIVE.as_secs(), hide = true)]
        keep_alive_secs: u64,
        /// Print the result as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Whether this sandbox can still use the proxy. Exit codes: 0 live,
    /// 5 revoked, 6 expired, 7 agents paused, 1 anything else.
    Status {
        /// The state directory of `up`.
        #[arg(long)]
        state_dir: Option<PathBuf>,
        /// Print the result as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Print the shell lines with the local URLs (no secrets).
    Env {
        /// The state directory of `up`.
        #[arg(long)]
        state_dir: Option<PathBuf>,
        /// Print the URLs as one line of JSON instead.
        #[arg(long)]
        json: bool,
    },
    /// Release this sandbox at the proxy and stop its forwarder, freeing the
    /// port. Exit 0 when nothing runs here too. A new forwarder needs a new
    /// package from `klav sandbox start`.
    Down {
        /// The state directory of `up`.
        #[arg(long)]
        state_dir: Option<PathBuf>,
        /// Print the result as JSON.
        #[arg(long)]
        json: bool,
        /// Stop the forwarder here only if it belongs to another package
        /// than the one in KLAV_SANDBOX (the first line of a sandbox's
        /// setup script). One for this package is left alone, and so is
        /// any when KLAV_SANDBOX or state.json cannot be read: exit 0, and
        /// `up` says what it finds.
        #[arg(long)]
        if_other_package: bool,
    },
    /// The forwarder itself, started by `up` (the package comes on stdin).
    #[command(hide = true)]
    Serve {
        #[arg(long)]
        port: u16,
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long)]
        claim_wait_secs: u64,
        #[arg(long, default_value_t = forward::KEEP_ALIVE.as_secs())]
        keep_alive_secs: u64,
    },
}

/// What the child tells `up` once, on its stdout.
#[derive(Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
enum Ready {
    Claimed {
        sandbox: Bound,
        port: u16,
        /// Why it has no control socket, if it has none: `down` cannot
        /// stop it then, and `up` says so.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        no_down: Option<String>,
    },
    Refused {
        status: u16,
        refusal: Refusal,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let code = match cli.command {
        Command::Up {
            daemon,
            port,
            state_dir,
            profile_file,
            no_skill,
            claim_wait_secs,
            keep_alive_secs,
            json,
        } => up(&UpArgs {
            daemon,
            port,
            state_dir: state_dir.unwrap_or_else(setup::default_state_dir),
            profile_file,
            no_skill,
            claim_wait_secs,
            keep_alive_secs,
            json,
        }),
        Command::Status { state_dir, json } => runtime().block_on(status(
            &state_dir.unwrap_or_else(setup::default_state_dir),
            json,
        )),
        Command::Env { state_dir, json } => {
            env(&state_dir.unwrap_or_else(setup::default_state_dir), json)
        }
        Command::Down {
            state_dir,
            json,
            if_other_package,
        } => {
            let state_dir = state_dir.unwrap_or_else(setup::default_state_dir);
            if if_other_package {
                runtime().block_on(down_if_other_package(&state_dir, json))
            } else {
                runtime().block_on(down(&state_dir, json))
            }
        }
        Command::Serve {
            port,
            state_dir,
            claim_wait_secs,
            keep_alive_secs,
        } => runtime().block_on(serve(
            port,
            &state_dir,
            claim_wait_secs,
            Duration::from_secs(keep_alive_secs.max(1)),
        )),
    };
    ExitCode::from(code)
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
}

/// The exit code of a refusal (ADR 0015's codes).
fn exit_code(error: &str) -> u8 {
    match error {
        "klav_sandbox_revoked" | "klav_not_allowed" => EXIT_DENIED,
        "klav_sandbox_expired" => EXIT_EXPIRED,
        "klav_agents_paused" => EXIT_PAUSED,
        _ => 1,
    }
}

/// Prints a refusal: JSON on stdout with `--json`, else the message and
/// the next step on stderr.
fn print_refusal(refusal: &Refusal, json: bool) {
    if json {
        println!("{}", serde_json::to_string(refusal).expect("json"));
    } else {
        eprintln!("klav-forward: {}", refusal.message);
        if let Some(next) = &refusal.next {
            eprintln!("{next}");
        }
    }
}

fn usage(message: &str, next: &str, json: bool) -> u8 {
    print_refusal(
        &Refusal {
            status: 0,
            error: "klav_bad_request".into(),
            message: message.into(),
            next: (!next.is_empty()).then(|| next.into()),
        },
        json,
    );
    EXIT_USAGE
}

struct UpArgs {
    daemon: bool,
    port: u16,
    state_dir: PathBuf,
    profile_file: PathBuf,
    no_skill: bool,
    claim_wait_secs: u64,
    keep_alive_secs: u64,
    json: bool,
}

/// What `KLAV_SANDBOX` holds: its text (only `up` keeps it, to hand it to
/// the child) and its sandbox ID, which is not secret. Nothing else of the
/// package stays, and none of it is ever printed or logged, not even in
/// an error.
enum PackageEnv {
    Unset,
    NotAPackage,
    Package {
        text: Zeroizing<String>,
        sandbox_id: String,
    },
}

/// Reads `KLAV_SANDBOX` as `up` and `down --if-other-package` both do.
fn read_package_env() -> PackageEnv {
    let Some(text) = std::env::var_os(PACKAGE_ENV) else {
        return PackageEnv::Unset;
    };
    let text = Zeroizing::new(text.into_string().unwrap_or_default());
    let Ok(package) = decode_package(text.trim()) else {
        return PackageEnv::NotAPackage;
    };
    let sandbox_id = package.sandbox_id.to_string();
    drop(package);
    PackageEnv::Package { text, sandbox_id }
}

fn up(args: &UpArgs) -> u8 {
    // Checked here so a typo fails before anything starts. Nothing about
    // the package is printed; only its sandbox ID, which is not secret,
    // stays.
    let (text, sandbox_id) = match read_package_env() {
        PackageEnv::Package { text, sandbox_id } => (text, sandbox_id),
        PackageEnv::Unset => {
            return usage(
                "KLAV_SANDBOX is not set.",
                "Run `klav-forward up` in the sandbox's setup script, where `klav sandbox start` put KLAV_SANDBOX. Do not ask the person for an API key.",
                args.json,
            );
        }
        PackageEnv::NotAPackage => {
            return usage(
                "KLAV_SANDBOX does not hold a Klav sandbox package.",
                "Ask the agent that started the sandbox for the setup lines of `klav sandbox start` again; do not edit the package.",
                args.json,
            );
        }
    };
    // Never another directory here: one this user cannot reach may be
    // where this package was already claimed (a setup script run as
    // another user), and a claim from a new directory is a second one.
    if let Err(e) = setup::create_private_dir(&args.state_dir) {
        return usage(
            &format!("cannot create {}: {e}", args.state_dir.display()),
            "Tell the person this exact message and stop: klav-forward cannot reach its state directory as this user. If this sandbox's package was already used from that directory (a setup script run as another user), a new sandbox needs `klav sandbox start`. Do not run `klav-forward up` with another state directory.",
            args.json,
        );
    }
    if let Some(code) = runtime().block_on(already_here(&args.state_dir, &sandbox_id, args.json)) {
        return code;
    }
    let exe = match std::env::current_exe() {
        Ok(exe) => exe,
        Err(e) => return usage(&format!("cannot find this program: {e}"), "", args.json),
    };
    let mut command = std::process::Command::new(exe);
    command
        .arg("serve")
        .arg("--port")
        .arg(args.port.to_string())
        .arg("--state-dir")
        .arg(&args.state_dir)
        .arg("--claim-wait-secs")
        .arg(args.claim_wait_secs.to_string())
        .arg("--keep-alive-secs")
        .arg(args.keep_alive_secs.to_string())
        .env_remove(PACKAGE_ENV)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped());
    if args.daemon {
        use std::os::unix::fs::OpenOptionsExt;
        use std::os::unix::process::CommandExt;
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(args.state_dir.join(setup::LOG_FILE));
        match log {
            Ok(log) => command.stderr(log),
            Err(_) => command.stderr(Stdio::null()),
        };
        // Its own process group: the end of the setup script does not end it.
        command.process_group(0);
    }
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(e) => return usage(&format!("cannot start the forwarder: {e}"), "", args.json),
    };
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(text.trim().as_bytes());
    }
    drop(text);
    let mut line = String::new();
    if let Some(stdout) = child.stdout.take() {
        let _ = std::io::BufReader::new(stdout).read_line(&mut line);
    }
    let ready: Option<Ready> = serde_json::from_str(line.trim()).ok();
    match ready {
        Some(Ready::Claimed {
            sandbox,
            port,
            no_down,
        }) => {
            claimed(args, &sandbox, port);
            if let Some(why) = no_down {
                eprintln!(
                    "klav-forward: this forwarder has no control socket ({why}), so `klav-forward down` cannot stop it or release its sandbox. A shorter --state-dir avoids this: a unix socket's path has at most 103 bytes on macOS and 107 on Linux."
                );
            }
            if args.daemon {
                return 0;
            }
            match child.wait() {
                Ok(status) => status
                    .code()
                    .and_then(|c| u8::try_from(c).ok())
                    .unwrap_or(1),
                Err(_) => 1,
            }
        }
        Some(Ready::Refused {
            status,
            mut refusal,
        }) => {
            refusal.status = status;
            let _ = child.wait();
            print_refusal(&refusal, args.json);
            exit_code(&refusal.error)
        }
        None => {
            let _ = child.kill();
            let _ = child.wait();
            print_refusal(&Refusal::unreachable(), args.json);
            1
        }
    }
}

/// What `up` answers without starting anything, if anything (ADR 0036
/// §5), in this order:
///
/// 1. A forwarder of this state directory that answers for this sandbox:
///    it runs, so there is nothing to do (or the proxy's refusal, as
///    `status` says it). Only a forwarder that answers counts, so a stale
///    `state.json` or a dead daemon falls through.
/// 2. Claimed from here before, and no forwarder answers for it: the
///    sandbox's marker (anything but [`Claimed::No`], an unreadable one
///    too), or a `state.json` that names it, which is only written after a
///    claim succeeded. It is never claimed again. Read even in a directory
///    that is not private: a planted marker can only make `up` refuse.
/// 3. Only on the way to a new claim, the state directory must be private
///    to this user ([`setup::check_state_dir`]): in one another user can
///    write, a marker can be deleted. Its refusal claims nothing and never
///    says the package was not used: nothing here looked at it.
async fn already_here(state_dir: &Path, sandbox_id: &str, json: bool) -> Option<u8> {
    let named = setup::load_state(state_dir)
        .ok()
        .flatten()
        .filter(|state| state.sandbox.sandbox_id == sandbox_id);
    if let Some(state) = &named {
        match tokio::time::timeout(RUNNING_CHECK, ask_status(state.port)).await {
            Ok(Ok(live)) if live.sandbox_id == sandbox_id => {
                if json {
                    println!(
                        "{}",
                        serde_json::json!({
                            "status": "running",
                            "sandbox": live,
                            "url": format!("http://127.0.0.1:{}", state.port),
                        })
                    );
                } else {
                    println!(
                        "klav-forward is already running for sandbox «{}» ({}) at http://127.0.0.1:{}: nothing to do.",
                        live.label, live.sandbox_id, state.port
                    );
                }
                return Some(0);
            }
            // A forwarder's or the proxy's own refusal for it (revoked,
            // expired, the proxy down): what `status` would say.
            Ok(Err(Asked::Klav(r))) => {
                print_refusal(&r, json);
                return Some(exit_code(&r.error));
            }
            // Its port answers for another sandbox, nothing listens, or
            // another program holds it now (an answer without a Klav
            // code, or none in time): on to the marker.
            Ok(Ok(_) | Err(Asked::NotRunning(_) | Asked::Other(_))) | Err(_) => {}
        }
        // No forwarder answers: its own stopped once the proxy revoked the
        // sandbox, and `ended.json` says why. One this version cannot read
        // is passed over: the marker below still refuses a second claim.
        if let setup::EndedRead::Ended(r) = setup::load_ended(state_dir, sandbox_id) {
            print_refusal(&r, json);
            return Some(exit_code(&r.error));
        }
    }
    let claimed = setup::read_marker(state_dir, sandbox_id);
    let why = match (&claimed, &named) {
        (Claimed::No, None) => None,
        (Claimed::No, Some(_)) => Some(" (its state.json names it)".to_owned()),
        (claimed, _) => Some(marker_why(claimed)),
    };
    if let Some(why) = why {
        print_refusal(&already_claimed(sandbox_id, &why), json);
        return Some(1);
    }
    if let Err((fix, why)) = setup::check_state_dir(state_dir) {
        print_refusal(&not_private(state_dir, &fix, &why), json);
        return Some(1);
    }
    None
}

/// What [`already_claimed`] adds about the marker.
fn marker_why(claimed: &Claimed) -> String {
    match claimed {
        Claimed::No | Claimed::Yes(_) => String::new(),
        Claimed::OtherVersion(v) => {
            format!(" (its claim marker has format v{v}, from another version of klav-forward)")
        }
        Claimed::Unreadable(e) => format!(" (its claim marker cannot be read: {e})"),
    }
}

/// The refusal of a package this state directory already began to claim;
/// `why` is what says so, in parentheses (or nothing for a plain marker).
/// Names the sandbox, never the package or anything of its secret.
fn already_claimed(sandbox_id: &str, why: &str) -> Refusal {
    Refusal {
        status: 0,
        error: "klav_forward_already_claimed".into(),
        message: format!(
            "This sandbox ({sandbox_id}) was already claimed from here{why}, and no forwarder for it answers from this state directory now. Its package can be claimed only once: claiming it again would end the sandbox as a theft."
        ),
        next: Some(
            "Tell the person this exact message. A new sandbox needs a new package: ask the person or the agent that started this one to run `klav sandbox start` again. Do not run `klav-forward up` with this package again."
                .into(),
        ),
    }
}

/// The refusal of a state directory that is not private to this user.
fn not_private(state_dir: &Path, fix: &Path, why: &str) -> Refusal {
    Refusal {
        status: 0,
        error: "klav_forward_state_not_private".into(),
        message: format!(
            "klav-forward keeps its claim markers in {}, which is not private to this user: {why}. Another user could delete a marker, and a later claim would end the sandbox as a theft.",
            state_dir.display()
        ),
        next: Some(format!(
            "Run `chmod 700 {}` as the user that owns it (and `chown` it to this user if needed), then run `klav-forward up` again. This run claimed nothing. Do not run `klav-forward up` with another state directory: only the person may choose one, and only if this package was never used from anywhere, because a claim from a new directory is a second claim and ends the sandbox as a theft.",
            fix.display()
        )),
    }
}

/// After the claim: the shell lines, the skill, and what `up` says.
fn claimed(args: &UpArgs, sandbox: &Bound, port: u16) {
    let env = setup::write_env(&args.profile_file, &args.state_dir, port, &sandbox.profiles);
    let skills = if args.no_skill {
        Vec::new()
    } else {
        let home = std::env::var_os("HOME").map_or_else(|| PathBuf::from("."), PathBuf::from);
        skill::install(&home)
    };
    let env_path = env.as_ref().ok().map(|e| e.path().to_owned());
    if args.json {
        println!(
            "{}",
            serde_json::json!({
                "sandbox": sandbox,
                "url": format!("http://127.0.0.1:{port}"),
                "env_file": env_path,
                "skill": skills.iter().map(skill::Outcome::line).collect::<Vec<_>>(),
            })
        );
        return;
    }
    println!(
        "Claimed sandbox «{}» ({}). Profiles: {}.",
        sandbox.label,
        sandbox.sandbox_id,
        sandbox.profiles.join(", ")
    );
    println!(
        "Calls go to http://127.0.0.1:{port}/<profile>/… and Klav's proxy adds the credential."
    );
    match &env {
        Ok(setup::EnvWritten::There(p)) => println!("Shell lines: . {}", p.display()),
        Ok(setup::EnvWritten::Fallback { wanted, written }) => println!(
            "Could not write {} (not root?): the shell lines are in {} instead: . {}",
            wanted.display(),
            written.display(),
            written.display()
        ),
        Err(e) => eprintln!("klav-forward: could not write the shell lines: {e}"),
    }
    for outcome in &skills {
        println!("{}", outcome.line());
    }
    if args.daemon {
        println!(
            "Running in the background; its log is {}.",
            args.state_dir.join(setup::LOG_FILE).display()
        );
    }
}

/// The child: reads the package, claims, relays.
async fn serve(port: u16, state_dir: &Path, claim_wait_secs: u64, keep_alive: Duration) -> u8 {
    let mut text = Zeroizing::new(String::new());
    if std::io::stdin()
        .take(MAX_PACKAGE)
        .read_to_string(&mut text)
        .is_err()
    {
        return 1;
    }
    let Ok(package) = decode_package(text.trim()) else {
        return 1;
    };
    drop(text);
    let sandbox_id = package.sandbox_id.to_string();
    let ready = |r: &Ready| {
        let mut out = std::io::stdout().lock();
        let _ = writeln!(out, "{}", serde_json::to_string(r).expect("json"));
        let _ = out.flush();
    };
    let refused = |refusal: Refusal| {
        let code = exit_code(&refusal.error);
        ready(&Ready::Refused {
            status: refusal.status,
            refusal,
        });
        code
    };
    // The port first: a port in use fails before the secret is spent.
    let listener = match tokio::net::TcpListener::bind(("127.0.0.1", port)).await {
        Ok(l) => l,
        Err(e) => {
            let holder = klav_forward::http::port_holder(port, RUNNING_CHECK).await;
            return refused(port_in_use(port, &e, holder));
        }
    };
    // The marker before the first byte of the claim: an answer that never
    // arrives may still have bound this key, and a second claim from
    // another key ends the sandbox as a theft.
    let marker = setup::Marker {
        v: setup::MARKER_VERSION,
        sandbox_id: sandbox_id.clone(),
        at: now_ms(),
    };
    let placed = match setup::write_marker(state_dir, &marker) {
        Ok(placed @ (setup::Placed::Exclusive | setup::Placed::Replaced)) => placed,
        // Another `up` began between this one's check and now.
        Ok(setup::Placed::AlreadyThere) => {
            return refused(already_claimed(
                &sandbox_id,
                &marker_why(&setup::read_marker(state_dir, &sandbox_id)),
            ));
        }
        Err(e) => return refused(cannot_record(state_dir, &sandbox_id, &e)),
    };
    // No byte of any claim left: the package was not used, so its marker
    // goes and a later `up` may claim, but only one this process linked:
    // one renamed into place may be another `up`'s, claiming right now,
    // and stays, which the `next` says.
    let unused = |mut refusal: Refusal| {
        let released = setup::release_unused_marker(state_dir, &sandbox_id, placed);
        if let Err(e) = &released {
            forward::tracing_line(&format!("could not remove the claim marker: {e}"));
        }
        refusal.next = Some(unused_next(state_dir, &sandbox_id, &released));
        refused(refusal)
    };
    let proxy = match Proxy::new(&package.url, package.proxy_pin, TlsSigner::channel_key()) {
        Ok(p) => Arc::new(p),
        Err(_) => return unused(Refusal::unreachable()),
    };
    let deadline = tokio::time::Instant::now() + Duration::from_secs(claim_wait_secs);
    let sent = AtomicBool::new(false);
    let claim = proxy.claim_until(&package, deadline, &sent).await;
    // Step 4: the secret goes, claimed or not.
    drop(package);
    let sandbox = match claim {
        Ok(b) => b,
        Err(refusal) if !sent.load(Ordering::SeqCst) => return unused(refusal),
        Err(refusal) => return refused(refusal),
    };
    let port = listener.local_addr().map_or(port, |a| a.port());
    let state = State {
        v: 1,
        pid: std::process::id(),
        port,
        sandbox: sandbox.clone(),
    };
    if let Err(e) = setup::save_state(state_dir, &state) {
        forward::tracing_line(&format!("could not save its state: {e}"));
    }
    // Why an earlier forwarder here stopped no longer applies.
    if let Err(e) = setup::remove_ended(state_dir) {
        forward::tracing_line(&format!("could not remove {}: {e}", setup::ENDED_FILE));
    }
    // Before `up` returns, so a `down` right after finds it.
    let (mut control, no_down) = match control::Control::bind(state_dir) {
        Ok(c) => (Some(c), None),
        Err(e) => {
            forward::tracing_line(&format!(
                "no control socket ({e}), so `klav-forward down` cannot stop this forwarder or release its sandbox; only a signal stops it, without releasing"
            ));
            (None, Some(e))
        }
    };
    ready(&Ready::Claimed {
        sandbox: sandbox.clone(),
        port,
        no_down,
    });
    forward::tracing_line(&format!("forwarding 127.0.0.1:{port}"));
    let ended = async {
        use tokio::signal::unix::{SignalKind, signal};
        let (Ok(mut term), Ok(mut hup)) = (
            signal(SignalKind::terminate()),
            signal(SignalKind::hangup()),
        ) else {
            return std::future::pending().await;
        };
        loop {
            tokio::select! {
                _ = term.recv() => return,
                _ = tokio::signal::ctrl_c() => return,
                // The setup script's terminal going away is not an end.
                _ = hup.recv() => {}
            }
        }
    };
    let asked = async {
        match control.as_mut() {
            Some(c) => c.wait_for_down().await,
            None => std::future::pending().await,
        }
    };
    // A signal stops it without releasing; only `down` releases. A sandbox
    // the proxy ended stops it too, and frees the port (papercut 13).
    let down = tokio::select! {
        () = forward::serve(listener, Arc::clone(&proxy)) => Stop::Signal,
        () = ended => Stop::Signal,
        refusal = forward::keep_alive(Arc::clone(&proxy), keep_alive, state.sandbox.expires_at) => Stop::Ended(refusal),
        stream = asked => Stop::Down(stream),
    };
    // The listener went with `serve`: the port is free from here.
    let stream = match down {
        Stop::Down(stream) => Some(stream),
        Stop::Signal => None,
        Stop::Ended(refusal) => {
            forward::tracing_line(&format!(
                "stopping: 127.0.0.1:{port} is free, and `klav-forward status` says why"
            ));
            let code = exit_code(&refusal.error);
            // Only if `state.json` is still this process's: `state.json`
            // stays as it is, and `ended.json` says why.
            if matches!(setup::load_state(state_dir), Ok(Some(s)) if s.pid == state.pid)
                && let Err(e) = setup::save_ended(state_dir, &state.sandbox.sandbox_id, &refusal)
            {
                forward::tracing_line(&format!("could not save why it stopped: {e}"));
            }
            if let Some(c) = control {
                c.close();
            }
            return code;
        }
    };
    let Some(stream) = stream else {
        // A signal: as before `down` existed.
        let _ = std::fs::remove_file(state_dir.join(setup::STATE_FILE));
        if let Some(c) = control {
            c.close();
        }
        return 0;
    };
    forward::tracing_line("`klav-forward down`: releasing the sandbox and stopping");
    let (release, logged, refusal) = release(&proxy).await;
    remove_own_state(state_dir);
    if let Some(c) = control {
        c.close();
    }
    control::answer(
        stream,
        &control::Stopped {
            v: control::VERSION,
            sandbox,
            port,
            release,
            logged,
            refusal,
        },
    )
    .await;
    0
}

/// How the forwarder's serving ended.
enum Stop {
    /// A signal: it stops without releasing.
    Signal,
    /// The proxy ended its sandbox: it stops and says why.
    Ended(Refusal),
    /// `klav-forward down`, on this connection of the control socket.
    Down(tokio::net::UnixStream),
}

/// The refusal of a port `up` cannot listen on: what holds it, as its
/// answer says ([`klav_forward::http::port_holder`]), and the flag that
/// moves this forwarder. Nothing was claimed yet.
fn port_in_use(port: u16, e: &std::io::Error, holder: klav_forward::http::PortHolder) -> Refusal {
    use klav_forward::http::PortHolder;
    let who = match holder {
        PortHolder::Forwarder => "another klav-forward listens there",
        PortHolder::Proxy => {
            "klav-proxy listens there (its default port is 8790 too, so the two collide when both run on one machine)"
        }
        PortHolder::Other => "another program listens there",
        PortHolder::Unknown => {
            "something listens there and did not answer like a klav-forward or a klav-proxy (both default to 8790)"
        }
    };
    let next = match holder {
        // Most likely this sandbox's own forwarder, from another state
        // directory: a second claim from here would end it as a theft.
        PortHolder::Forwarder => {
            "Run `klav-forward status` to see it. Do not run `klav-forward up` again with this sandbox's package: it can be claimed once, and a second claim ends the sandbox as a theft."
        }
        // It did not answer in time: it may be a forwarder, maybe this
        // sandbox's, so never an invitation to claim again.
        PortHolder::Unknown => {
            "This run claimed nothing. Run `klav-forward status` in a few seconds: if a forwarder answers for this sandbox, it already runs. Do not run `klav-forward up` again with this package: it can be claimed once, and a second claim ends the sandbox as a theft. Tell the person what holds the port."
        }
        PortHolder::Proxy | PortHolder::Other => {
            "This run claimed nothing, so it did not spend this sandbox's package. Run `klav-forward up --port <a free port>` (`klav-forward env` then gives the URLs on that port), or move the other program: klav-proxy takes `serve --port <another port>`. Do not retry in a loop."
        }
    };
    Refusal {
        status: 0,
        error: "klav_forward_port_in_use".into(),
        message: format!("127.0.0.1:{port} is not free ({e}): {who}."),
        next: Some(next.into()),
    }
}

/// Removes `state.json` if it is still this process's: a later forwarder
/// of the same state directory may have written its own.
fn remove_own_state(state_dir: &Path) {
    if let Ok(Some(state)) = setup::load_state(state_dir)
        && state.pid == std::process::id()
    {
        let _ = std::fs::remove_file(state_dir.join(setup::STATE_FILE));
    }
}

/// Releases the sandbox at the proxy, once, within
/// [`forward::RELEASE_TIMEOUT`].
async fn release(proxy: &Proxy) -> (control::Release, Option<bool>, Option<Refusal>) {
    use control::Release;
    let sent = AtomicBool::new(false);
    match proxy.release(&sent).await {
        Ok(logged) => (Release::Released, Some(logged), None),
        Err(r) if r.error == "klav_sandbox_revoked" || r.error == "klav_sandbox_expired" => {
            (Release::AlreadyEnded, None, Some(r))
        }
        // Cut off after the request left: most likely done, not known.
        Err(r) if r.error == "klav_proxy_unreachable" && sent.load(Ordering::SeqCst) => {
            (Release::Unknown, None, Some(r))
        }
        Err(r) => (Release::NotReleased, None, Some(r)),
    }
}

/// The `next` of a claim that never left: the package can be used again.
/// The refusal when the marker could not be written (or made durable). A
/// marker can stay after the error, one renamed into place (never taken
/// back) or another attempt's, and then the package is not called unused
/// for a new state directory.
fn cannot_record(state_dir: &Path, sandbox_id: &str, e: &std::io::Error) -> Refusal {
    let next = match setup::read_marker(state_dir, sandbox_id) {
        Claimed::No => "Pass --state-dir with a directory only this user can write and run `klav-forward up` again: the package was not used.".to_owned(),
        _ => marker_stays_next(state_dir, sandbox_id),
    };
    Refusal {
        status: 0,
        error: "klav_forward_cannot_record".into(),
        message: format!(
            "klav-forward could not record this claim in {} ({e}), so it did not claim the sandbox.",
            state_dir.display()
        ),
        next: Some(next),
    }
}

/// The `next` of a claim that never left, once [`setup::release_unused_marker`]
/// answered `released`: `up` may run again only if the marker is gone.
/// `Ok(false)` is a marker renamed into place (maybe another `up`'s); an
/// error is this process's own marker that it could not remove.
fn unused_next(state_dir: &Path, sandbox_id: &str, released: &std::io::Result<bool>) -> String {
    match released {
        Ok(true) => UNUSED_NEXT.into(),
        Ok(false) => marker_stays_next(state_dir, sandbox_id),
        Err(e) => format!(
            "Tell the person this exact message and stop. This run sent no claim, so it did not use the package, but it could not remove its own claim marker at {} ({e}), so `klav-forward up` with this package refuses in this state directory. The person may remove that file and run `klav-forward up` again. Do not remove it yourself, and do not retry in a loop.",
            setup::marker_path(state_dir, sandbox_id).display()
        ),
    }
}

/// The `next` of a claim that never left while a marker stays that may not
/// be this run's (renamed into place, or another attempt's): this run did
/// not use the package, but another `up` at the same instant may have, so
/// only the person may decide that the marker goes.
fn marker_stays_next(state_dir: &Path, sandbox_id: &str) -> String {
    format!(
        "Tell the person this exact message and stop. This run sent no claim, so it did not use the package, but a claim marker stays at {}, and klav-forward cannot tell whether another `klav-forward up` with the same package, started at the same moment, placed it and may have claimed with it. Only if the person knows no other `klav-forward up` ran with this package may they remove that file and run `up` again; otherwise a new sandbox needs `klav sandbox start`. Do not remove the file yourself, and do not retry in a loop.",
        setup::marker_path(state_dir, sandbox_id).display()
    )
}

const UNUSED_NEXT: &str = "Tell the person this exact message. No claim reached the proxy, so this sandbox's package was not used: `klav-forward up` can run again once the proxy answers. Do not retry in a loop.";

/// The code of `status` when no forwarder answers here.
const NOT_RUNNING: &str = "klav_forward_not_running";

fn not_running(why: &str) -> Refusal {
    Refusal {
        status: 0,
        error: NOT_RUNNING.into(),
        message: format!("klav-forward is not running here ({why})."),
        next: Some(
            "Tell the person. A new sandbox needs a new package: the agent that started it runs `klav sandbox start` again."
                .into(),
        ),
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_millis()).ok())
        .unwrap_or_default()
}

/// How long `up` waits for a forwarder on the stored port to answer: a
/// live one whose proxy is down answers after its connect timeout.
const RUNNING_CHECK: Duration = Duration::from_secs(forward::CONNECT_TIMEOUT.as_secs() + 5);

/// The `klav-error` codes a forwarder or the proxy answers `status` with.
const STATUS_CODES: &[&str] = &[
    "klav_sandbox_revoked",
    "klav_sandbox_expired",
    "klav_agents_paused",
    "klav_not_allowed",
    "klav_proxy_unreachable",
    "klav_server_unreachable",
    "klav_rate_limited",
    "klav_proxy_store",
    "klav_forward_busy",
];

/// Why the forwarder on a port did not say its sandbox.
enum Asked {
    /// Nothing listens there.
    NotRunning(Refusal),
    /// A refusal with one of the [`STATUS_CODES`] in `klav-error`.
    Klav(Refusal),
    /// Anything else: an answer without a Klav code, a cut one, none.
    Other(Refusal),
}

impl Asked {
    fn refusal(self) -> Refusal {
        match self {
            Self::NotRunning(r) | Self::Klav(r) | Self::Other(r) => r,
        }
    }
}

/// The sandbox, as the forwarder on `port` asks the proxy (30 s at most).
async fn ask_status(port: u16) -> Result<Bound, Asked> {
    let asked = async {
        let mut tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .map_err(|_| Asked::NotRunning(not_running("nothing listens on its port")))?;
        tokio::io::AsyncWriteExt::write_all(
            &mut tcp,
            b"GET /_klav/status HTTP/1.1\r\nhost: klav-proxy\r\nconnection: close\r\n\r\n",
        )
        .await
        .map_err(|_| Asked::NotRunning(not_running("its port closed")))?;
        http::read_answer(&mut tcp)
            .await
            .map_err(|_| Asked::Other(Refusal::unreachable()))
    };
    let answer = tokio::time::timeout(Duration::from_secs(30), asked)
        .await
        .map_err(|_| Asked::Other(Refusal::unreachable()))??;
    if answer.status != 200 {
        let refusal = Refusal::of(&answer);
        let klav = answer
            .header("klav-error")
            .is_some_and(|code| STATUS_CODES.contains(&code) && code == refusal.error);
        return Err(if klav {
            Asked::Klav(refusal)
        } else {
            Asked::Other(refusal)
        });
    }
    serde_json::from_slice::<Bound>(&answer.body).map_err(|_| Asked::Other(Refusal::unreachable()))
}

async fn status(state_dir: &Path, json: bool) -> u8 {
    let state = match setup::load_state(state_dir) {
        Ok(Some(s)) => s,
        Ok(None) => {
            print_refusal(&not_running("no state"), json);
            return 1;
        }
        Err(e) => {
            print_refusal(&not_running(&e), json);
            return 1;
        }
    };
    let sandbox = match ask_status(state.port).await {
        Ok(sandbox) => sandbox,
        // A forwarder answers: its word, whatever `ended.json` says.
        Err(Asked::Klav(r)) => {
            print_refusal(&r, json);
            return exit_code(&r.error);
        }
        // None does: its own may have stopped once the proxy revoked the
        // sandbox, and `ended.json` says why.
        Err(asked) => {
            let r = match setup::load_ended(state_dir, &state.sandbox.sandbox_id) {
                setup::EndedRead::Ended(r) => r,
                setup::EndedRead::Unreadable(why) => not_running(&format!(
                    "it stopped, and why it did is in a file this version cannot read: {why}"
                )),
                setup::EndedRead::No => asked.refusal(),
            };
            print_refusal(&r, json);
            return exit_code(&r.error);
        }
    };
    if json {
        println!(
            "{}",
            serde_json::json!({
                "status": "live",
                "sandbox": sandbox,
                "url": format!("http://127.0.0.1:{}", state.port),
            })
        );
    } else {
        println!(
            "Sandbox «{}» ({}) is live. Profiles: {}. Calls go to http://127.0.0.1:{}/<profile>/…",
            sandbox.label,
            sandbox.sandbox_id,
            sandbox.profiles.join(", "),
            state.port
        );
    }
    0
}

/// `down`: asks the forwarder of `state_dir`, over its control socket, to
/// release its sandbox and stop. Never signals a process and creates
/// nothing; exit 0 when it stopped one or none runs here, 1 when one
/// answers on the port and cannot be reached.
async fn down(state_dir: &Path, json: bool) -> u8 {
    // What `state.json` names before asking, checked again after: whatever
    // answers on the socket, a setup script never hears "free" while the
    // port is taken.
    let before = setup::load_state(state_dir).ok().flatten();
    let why = match control::ask_down(state_dir).await {
        control::Asked::Stopped(stopped) => {
            let mut taken = None;
            if listens(stopped.port).await {
                taken = Some(stopped.port);
            } else if let Some(state) = &before
                && state.port != stopped.port
                && answers_for(state).await
            {
                taken = Some(state.port);
            }
            if let Some(port) = taken {
                // Another `down` and `up` of this directory ran meanwhile.
                if let Ok(Some(now)) = setup::load_state(state_dir)
                    && now.sandbox.sandbox_id != stopped.sandbox.sandbox_id
                    && now.port == port
                    && answers_for(&now).await
                {
                    print_refusal(&newer_holds(&stopped, &now), json);
                    return 1;
                }
                print_refusal(&still_taken(state_dir, port), json);
                return 1;
            }
            print_stopped(&stopped, json);
            return 0;
        }
        control::Asked::NoAnswer(why) => {
            print_refusal(&no_answer(state_dir, &why), json);
            return 1;
        }
        // Nothing was asked of a forwarder: the state and the port say
        // whether one runs. One that stopped for another `down` at the same
        // time has closed its port and removed its `state.json` by now.
        control::Asked::Nobody(why) => (why, false),
        control::Asked::Closed(why) => (why, true),
    };
    let (why, busy) = why;
    // No forwarder on the socket. One without it (another version, or a
    // path too long to bind) may still hold the port: the check `up`
    // makes, which never trusts the pid in `state.json`.
    // A `state.json` that cannot be read or parsed says nothing about
    // what runs: refused, never "nothing to stop".
    let state = match setup::load_state(state_dir) {
        Ok(state) => state,
        Err(e) => {
            print_refusal(&unreadable_state(&e, &why), json);
            return 1;
        }
    };
    if let Some(state) = &state
        && answers_for(state).await
    {
        print_refusal(&cannot_stop(state_dir, state, &why, busy), json);
        return 1;
    }
    let message = if state.is_some() {
        "klav-forward is not running here (its state.json is from a forwarder that is gone): nothing to stop."
    } else {
        "klav-forward is not running here: nothing to stop."
    };
    if json {
        println!(
            "{}",
            serde_json::json!({ "status": "not_running", "message": message })
        );
    } else {
        println!("{message}");
    }
    0
}

/// `down --if-other-package`, the first line of a sandbox's setup script:
/// [`down`] only when this state directory's forwarder belongs to another
/// package than the one in `KLAV_SANDBOX` (a sandbox resumed with its
/// memory alive, then handed a new package). In this order, and nothing
/// is contacted, released, written or removed before the decision:
/// 1. the package (only its sandbox ID): none readable, nothing stopped;
/// 2. `state.json`: unreadable, nothing stopped;
/// 3. it names this package's sandbox: nothing touched, whether its
///    forwarder is live, busy or gone (`up` then says it runs, passes on
///    the proxy's refusal, or refuses the spent package, as it always
///    did);
/// 4. this package's claim marker is here (any but [`Claimed::No`], as
///    `up` reads it): `up` is certain to refuse it, so nothing is
///    stopped, not another package's forwarder that took over since (an
///    old package replayed) nor this one's without a `state.json`;
/// 5. otherwise [`down`].
///
/// A line whose job is not to stop the wrong forwarder never guesses.
/// Exit 0 in cases 1 to 4.
async fn down_if_other_package(state_dir: &Path, json: bool) -> u8 {
    let kept = |status: &str, message: &str, sandbox: Option<&forward::Bound>| {
        if json {
            let mut out = serde_json::json!({ "status": status, "message": message });
            if let Some(sandbox) = sandbox {
                out["sandbox"] = serde_json::json!(sandbox);
            }
            println!("{out}");
        } else {
            println!("{message}");
        }
        0
    };
    let sandbox_id = match read_package_env() {
        // The text is dropped (and zeroed) here: only the ID is compared.
        PackageEnv::Package { sandbox_id, .. } => sandbox_id,
        PackageEnv::Unset => {
            return kept(
                "no_package",
                "KLAV_SANDBOX is not set, so `klav-forward down --if-other-package` cannot tell which forwarder is this package's: nothing stopped.",
                None,
            );
        }
        PackageEnv::NotAPackage => {
            return kept(
                "no_package",
                "KLAV_SANDBOX does not hold a Klav sandbox package, so `klav-forward down --if-other-package` cannot tell which forwarder is this package's: nothing stopped.",
                None,
            );
        }
    };
    let state = match setup::load_state(state_dir) {
        Ok(state) => state,
        Err(e) => {
            return kept(
                "unreadable_state",
                &format!(
                    "This state directory's state.json cannot be read ({e}), so `klav-forward down --if-other-package` cannot tell whether its forwarder is this package's: nothing stopped."
                ),
                None,
            );
        }
    };
    if let Some(state) = &state
        && state.sandbox.sandbox_id == sandbox_id
    {
        return kept(
            "same_package",
            &format!(
                "The forwarder of this state directory is for this package's sandbox «{}» ({}): left alone, nothing stopped.",
                state.sandbox.label, state.sandbox.sandbox_id
            ),
            Some(&state.sandbox),
        );
    }
    if !matches!(setup::read_marker(state_dir, &sandbox_id), Claimed::No) {
        return kept(
            "already_claimed_here",
            &format!(
                "This package's sandbox ({sandbox_id}) was already claimed from this state directory: nothing stopped; `klav-forward up` says what to do."
            ),
            None,
        );
    }
    down(state_dir, json).await
}

/// Whether the forwarder of `state` still answers on its port: the check
/// `up` makes, which never trusts the pid in `state.json`.
async fn answers_for(state: &State) -> bool {
    match tokio::time::timeout(RUNNING_CHECK, ask_status(state.port)).await {
        Ok(Ok(live)) => live.sandbox_id == state.sandbox.sandbox_id,
        // A forwarder relaying the proxy's code (or its own).
        Ok(Err(Asked::Klav(_))) => true,
        Ok(Err(Asked::NotRunning(_) | Asked::Other(_))) | Err(_) => false,
    }
}

/// Whether anything at all listens on `127.0.0.1:port`.
async fn listens(port: u16) -> bool {
    tokio::time::timeout(
        forward::CONNECT_TIMEOUT,
        tokio::net::TcpStream::connect(("127.0.0.1", port)),
    )
    .await
    .is_ok_and(|c| c.is_ok())
}

/// What `down` says once the forwarder stopped.
fn print_stopped(stopped: &control::Stopped, json: bool) {
    use control::Release;
    let url = format!("http://127.0.0.1:{}", stopped.port);
    if json {
        let mut out = serde_json::json!({
            "status": "stopped",
            "sandbox": stopped.sandbox,
            "url": url,
            "release": stopped.release,
        });
        if let Some(logged) = stopped.logged {
            out["logged"] = logged.into();
        }
        // The proxy's code and words, without its `next`: that is for a
        // call that failed, and `down` did not ("stop" would end a setup
        // script right before its `up`).
        if let Some(r) = &stopped.refusal {
            out["release_error"] = serde_json::json!({ "error": r.error, "message": r.message });
        }
        println!("{out}");
        return;
    }
    let s = &stopped.sandbox;
    // The proxy's own words, as a sentence of their own.
    let said = stopped
        .refusal
        .as_ref()
        .map_or(String::new(), |r| format!(" The proxy said: {}", r.message));
    let first = match stopped.release {
        Release::Released => format!(
            "Released sandbox «{}» ({}) at the proxy and stopped its forwarder; {url} is free.",
            s.label, s.sandbox_id
        ),
        Release::AlreadyEnded => format!(
            "Stopped the forwarder of sandbox «{}» ({}); {url} is free. The proxy had already ended the sandbox.{said}",
            s.label, s.sandbox_id
        ),
        Release::NotReleased => format!(
            "Stopped the forwarder of sandbox «{}» ({}); {url} is free. The sandbox was NOT released: it stays live at the proxy, though nothing can use it from here, until `klav sandbox stop {}` on the issuer's side, its expiry, or 1 hour without calls.{said}",
            s.label, s.sandbox_id, s.sandbox_id
        ),
        Release::Unknown => format!(
            "Stopped the forwarder of sandbox «{}» ({}); {url} is free. The proxy did not answer the release in time, so the sandbox may still be live there: `klav sandbox ls` on the issuer's side says, and `klav sandbox stop {}` ends it.",
            s.label, s.sandbox_id, s.sandbox_id
        ),
    };
    println!("{first}");
    println!("A new forwarder needs a new package from `klav sandbox start`.");
}

/// `down`'s refusal when a forwarder answers on the port of `state.json`
/// but not on the control socket. `busy` when a socket was there and kept
/// closing on `down` (every reader taken): only then may a later `down`
/// get through. Without a socket at all (another version, or a path too
/// long to bind), no `down` ever will.
fn cannot_stop(state_dir: &Path, state: &State, why: &str, busy: bool) -> Refusal {
    let (cause, first) = if busy {
        (
            "the forwarder may be busy with other connections on that socket, or be from another version of klav-forward",
            "Run `klav-forward down` once more in a few seconds; do not retry in a loop. If it refuses again, tell the person this exact message: only",
        )
    } else {
        (
            "it may be from another version of klav-forward",
            "Tell the person this exact message and stop. Only",
        )
    };
    Refusal {
        status: 0,
        error: "klav_forward_cannot_stop".into(),
        message: format!(
            "A forwarder answers on 127.0.0.1:{} for this state directory, but `klav-forward down` cannot reach it through its control socket ({why}): {cause}. Nothing was stopped or released.",
            state.port
        ),
        next: Some(format!(
            "{first} the person may stop that forwarder by hand (the pid in {} may be it, or may be stale); stopping it that way does not release the sandbox, and `klav sandbox stop {}` on the issuer's side does. A new forwarder needs 127.0.0.1:{} free and a new package from `klav sandbox start`.",
            state_dir.join(setup::STATE_FILE).display(),
            state.sandbox.sandbox_id,
            state.port
        )),
    }
}

/// `down`'s refusal when its control socket does not answer and
/// `state.json` cannot be read: it cannot tell whether a forwarder runs.
fn unreadable_state(e: &str, why: &str) -> Refusal {
    Refusal {
        status: 0,
        error: "klav_forward_cannot_stop".into(),
        message: format!(
            "`klav-forward down` cannot tell whether a forwarder runs here: no forwarder answers on its control socket ({why}), and its state cannot be read ({e}). Nothing was stopped or released."
        ),
        next: Some(
            "Tell the person this exact message and stop. Do not remove or edit the state directory yourself."
                .into(),
        ),
    }
}

/// `down`'s refusal when it stopped its forwarder, and meanwhile another
/// `down` and `up` of the same state directory started a newer one, which
/// holds the port now.
fn newer_holds(stopped: &control::Stopped, now: &State) -> Refusal {
    let release = serde_json::to_value(stopped.release)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default();
    let old = &stopped.sandbox;
    Refusal {
        status: 0,
        error: "klav_forward_cannot_stop".into(),
        message: format!(
            "`klav-forward down` stopped the forwarder of sandbox «{}» ({}) (release: {release}), and a newer forwarder of this state directory (sandbox {}) now holds 127.0.0.1:{}.",
            old.label, old.sandbox_id, now.sandbox.sandbox_id, now.port
        ),
        next: Some(format!(
            "Tell the person this message. The newer forwarder still runs; this `down` did not touch it. Unless the release was `released` or `already_ended`, `klav sandbox stop {}` on the issuer's side ends the old sandbox.",
            old.sandbox_id
        )),
    }
}

/// `down`'s refusal when its control socket answered that the forwarder
/// stopped, and the port is still taken.
fn still_taken(state_dir: &Path, port: u16) -> Refusal {
    Refusal {
        status: 0,
        error: "klav_forward_cannot_stop".into(),
        message: format!(
            "The control socket of {} answered that its forwarder stopped, but 127.0.0.1:{port} is still taken: something other than this state directory's forwarder may hold the socket or the port. `klav-forward down` cannot tell what was stopped or released.",
            state_dir.display()
        ),
        next: Some(format!(
            "Tell the person this exact message and stop. Do not start a forwarder on 127.0.0.1:{port} until the person says it is free."
        )),
    }
}

/// `down`'s refusal when the forwarder took the request, `down` committed,
/// and no answer came: it may be stopping or may have stopped, and `down`
/// cannot say it still runs.
fn no_answer(state_dir: &Path, why: &str) -> Refusal {
    Refusal {
        status: 0,
        error: "klav_forward_cannot_stop".into(),
        message: format!(
            "`klav-forward down` asked the forwarder of {} to release its sandbox and stop, and {why}: it may still be stopping, or it may have stopped already.",
            state_dir.display()
        ),
        next: Some(
            "Run `klav-forward status` to see whether it still runs, and tell the person. Do not retry in a loop."
                .into(),
        ),
    }
}

fn env(state_dir: &Path, json: bool) -> u8 {
    let Ok(Some(state)) = setup::load_state(state_dir) else {
        if json {
            print_refusal(&not_running("no state"), true);
        } else {
            eprintln!(
                "klav-forward: no forwarder state in {}: run `klav-forward up` first.",
                state_dir.display()
            );
        }
        return 1;
    };
    if json {
        println!("{}", setup::env_json(state.port, &state.sandbox.profiles));
    } else {
        print!("{}", setup::env_lines(state.port, &state.sandbox.profiles));
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Papercut 12: a port another forwarder or an unknown holder has may
    /// be this sandbox's own forwarder, so its advice never claims again
    /// on another port; klav-proxy or another program gets `--port`.
    #[test]
    fn a_taken_port_moves_only_from_a_holder_that_is_not_a_forwarder() {
        use klav_forward::http::PortHolder;
        let e = std::io::Error::from(std::io::ErrorKind::AddrInUse);
        for (holder, who) in [
            (PortHolder::Forwarder, "another klav-forward listens there"),
            (PortHolder::Unknown, "did not answer like a klav-forward"),
        ] {
            let r = port_in_use(8790, &e, holder);
            let next = r.next.unwrap();
            assert!(r.message.contains(who), "{}", r.message);
            assert!(next.contains("klav-forward status"), "{next}");
            assert!(!next.contains("--port"), "{next}");
            assert!(
                next.contains("a second claim ends the sandbox as a theft"),
                "{next}"
            );
        }
        for (holder, who) in [
            (PortHolder::Proxy, "klav-proxy listens there"),
            (PortHolder::Other, "another program listens there"),
        ] {
            let r = port_in_use(8790, &e, holder);
            let next = r.next.unwrap();
            assert!(r.message.contains(who), "{}", r.message);
            assert!(
                next.contains("klav-forward up --port <a free port>"),
                "{next}"
            );
            assert!(next.contains("serve --port <another port>"), "{next}");
        }
    }

    fn marker(dir: &Path, sandbox_id: &str) {
        std::fs::create_dir_all(dir.join(setup::CLAIMED_DIR)).unwrap();
        std::fs::write(
            setup::marker_path(dir, sandbox_id),
            serde_json::to_vec(&setup::Marker {
                v: setup::MARKER_VERSION,
                sandbox_id: sandbox_id.into(),
                at: 1,
            })
            .unwrap(),
        )
        .unwrap();
    }

    /// A claim that never left says the package can be claimed again only
    /// when its marker is gone: a renamed marker stays (it may be another
    /// `up`'s), and then the person decides, never the agent.
    #[test]
    fn a_marker_that_stays_is_never_called_gone() {
        let dir = TestDir::new();
        let state = dir.path().join("state");
        let id = "11111111-2222-3333-4444-555555555555";
        assert_eq!(unused_next(&state, id, &Ok(true)), UNUSED_NEXT);
        marker(&state, id);
        let released = setup::release_unused_marker(&state, id, setup::Placed::Replaced);
        assert!(matches!(released, Ok(false)));
        let next = unused_next(&state, id, &released);
        assert!(!next.contains("can run again"), "{next}");
        assert!(next.contains("may have claimed"), "{next}");
        assert!(next.contains("Do not remove the file yourself"), "{next}");
        assert!(
            next.contains(&setup::marker_path(&state, id).display().to_string()),
            "{next}"
        );
        // Its own marker that it could not remove: no other `up` is
        // involved, and the agent still leaves the file to the person.
        let own = unused_next(&state, id, &Err(std::io::Error::other("busy")));
        assert!(!own.contains("can run again"), "{own}");
        assert!(!own.contains("another `klav-forward up`"), "{own}");
        assert!(own.contains("Do not remove it yourself"), "{own}");
    }

    /// A marker that could not be made durable but stays (renamed into
    /// place, then a failed sync) is not called unused for another state
    /// directory; with no marker, it is.
    #[test]
    fn cannot_record_says_unused_only_with_no_marker_left() {
        let dir = TestDir::new();
        let state = dir.path().join("state");
        let id = "11111111-2222-3333-4444-555555555555";
        let e = std::io::Error::other("sync failed");
        let clean = cannot_record(&state, id, &e);
        assert!(clean.next.unwrap().contains("the package was not used"));
        marker(&state, id);
        let left = cannot_record(&state, id, &e).next.unwrap();
        assert!(!left.to_lowercase().contains("state-dir"), "{left}");
        assert!(left.contains("may have claimed"), "{left}");
    }
}
