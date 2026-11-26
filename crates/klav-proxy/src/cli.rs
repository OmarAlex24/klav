//! `klav-proxy`'s command line: `init`, `serve` and `status` (ADR 0036
//! §14), and, in a build with the `enclave` feature, `enclave` (Klav
//! Cloud's hosted proxy inside an AWS Nitro Enclave, ADR 0051). The `klav-proxy` binary is only [`main`]; the `klav` binary runs
//! the same [`main`] when it is started as `klav-proxy` (its `argv[0]`),
//! which is how the Mac app runs the proxy from its one `klav` helper
//! (ADR 0036, layer 11).
//!
//! What it prints is the pairing code, the profiles and errors: never a
//! value (none reaches this file).
//!
//! [`main`] reads what the operator asked of the memory lock, then hardens
//! the process (ADR 0044 §3.1), before the tokio runtime starts its threads
//! and before `init`, `serve` or `status` reads or makes the proxy's key.

#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::io::IsTerminal;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use crate::app::{
    self, ControlSocket, DEFAULT_NAME, DEFAULT_PORT, InitOptions, ServeOptions, StartEnv,
};
use crate::memory::{self, LockChoice, MemoryReport};
use crate::proxy::{DEFAULT_MAX_BODY, DEFAULT_REQUEST_TIMEOUT};
use clap::{CommandFactory, FromArgMatches, Parser, Subcommand, ValueEnum};
use klav_client::Home;
use klav_sdk::KeyStoreChoice;

#[derive(Parser)]
#[command(
    name = "klav-proxy",
    about = "Klav's credential proxy: puts the credentials you grant it into HTTP requests, without handing them to the agent that asks"
)]
struct Cli {
    /// The proxy's data directory (its registration and, by default, its
    /// key). Default: KLAV_HOME, else Klav's usual directory.
    #[arg(long, global = true)]
    home: Option<PathBuf>,
    /// The agent name the proxy registered with.
    #[arg(long, global = true, default_value = DEFAULT_NAME)]
    name: String,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Registers the proxy with the account and shows the 6 words to compare.
    Init {
        /// E-mail of the Klav account.
        #[arg(long)]
        email: String,
        /// Klav server (default: Klav's).
        #[arg(long, default_value = "")]
        server: String,
        /// Where to keep the proxy's key.
        #[arg(long, value_enum, default_value_t = Store::File)]
        key_store: Store,
        /// The key file (mode 0600), instead of <home>/agents/<name>.key.
        #[arg(long)]
        key_file: Option<PathBuf>,
        /// Machine-readable output.
        #[arg(long)]
        json: bool,
        /// Refuse to start when the memory can't be locked out of swap
        /// (also KLAV_PROXY_REQUIRE_MEMORY_LOCK=1).
        #[arg(long)]
        require_memory_lock: bool,
        /// Don't lock the memory out of swap (also
        /// KLAV_PROXY_MEMORY_LOCK=off). Core dumps stay off.
        #[arg(long, conflicts_with = "require_memory_lock")]
        no_memory_lock: bool,
    },
    /// Serves mode (a) on 127.0.0.1: http://127.0.0.1:PORT/<profile>/<path>.
    Serve {
        /// Port on 127.0.0.1 (the address is always loopback).
        #[arg(long, default_value_t = DEFAULT_PORT)]
        port: u16,
        /// Also listen for sandboxes' forwarders on this address
        /// (`HOST:PORT`, such as a Tailscale address): TLS 1.3 with this
        /// proxy's key, which the sandbox package pins. The person's
        /// `klav proxy issuer add --url tls://…` must name it.
        #[arg(long)]
        channel: Option<std::net::SocketAddr>,
        /// Largest request body, in bytes.
        #[arg(long, default_value_t = DEFAULT_MAX_BODY)]
        max_body: usize,
        /// Longest call to a provider, in seconds, answer included; for a
        /// stream (`text/event-stream`), its headers only: then it may stay
        /// open 15 minutes, and 2 minutes without a chunk.
        #[arg(long, default_value_t = DEFAULT_REQUEST_TIMEOUT.as_secs())]
        timeout: u64,
        /// Refuse every profile call on 127.0.0.1 (`403 klav_not_allowed`):
        /// only sandboxes, through `--channel`, reach the credentials. The
        /// issuers' signed API keeps working.
        #[arg(long)]
        no_local_calls: bool,
        /// The local socket for the Klav app and `klav proxy local` on this
        /// machine (this user only), instead of <home>/agents/<name>.sock.
        #[arg(long, value_name = "PATH", conflicts_with = "no_control_socket")]
        control_socket: Option<PathBuf>,
        /// No local socket.
        #[arg(long)]
        no_control_socket: bool,
        /// Exit 0 without serving when no proxy is registered under this
        /// name, another klav-proxy already answers on its local socket, or
        /// the proxy is pending, revoked or its account is being deleted
        /// (the Mac app's LaunchAgent).
        #[arg(long)]
        if_registered: bool,
        /// Refuse to start when the memory can't be locked out of swap
        /// (also KLAV_PROXY_REQUIRE_MEMORY_LOCK=1).
        #[arg(long)]
        require_memory_lock: bool,
        /// Don't lock the memory out of swap (also
        /// KLAV_PROXY_MEMORY_LOCK=off). Core dumps stay off.
        #[arg(long, conflicts_with = "require_memory_lock")]
        no_memory_lock: bool,
    },
    /// Shows the proxy's state and the profiles it holds (never a value).
    Status {
        /// Machine-readable output.
        #[arg(long)]
        json: bool,
    },
    /// Klav Cloud's hosted proxy inside an AWS Nitro Enclave (ADR 0051):
    /// opens /dev/nsm, listens on vsock, and starts a new seed or joins a
    /// live peer through the attested hand-off. Only inside an enclave.
    #[cfg(feature = "enclave")]
    Enclave(crate::enclave::run::Args),
}

#[derive(Clone, Copy, ValueEnum)]
enum Store {
    /// A 0600 file.
    File,
    /// The macOS keychain.
    Keychain,
}

fn init_logs() {
    let filter = tracing_subscriber::EnvFilter::try_from_env("KLAV_LOG")
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let json = std::env::var("KLAV_LOG_FORMAT").is_ok_and(|f| f == "json");
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr);
    // No color codes in a log file or a container's log; on a terminal,
    // the default stays.
    let builder = if std::io::stderr().is_terminal() {
        builder
    } else {
        builder.with_ansi(false)
    };
    if json {
        builder.json().init();
    } else {
        builder.init();
    }
}

/// What is left until `until_ms` (Unix ms), as `agent register` says it.
fn minutes_left(until_ms: i64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX));
    format!("{} minutes", (until_ms - now).max(0) / 60_000)
}

/// What the operator asked of the memory lock (ADR 0044 §3.2): read
/// before the process hardens, from the subcommand's flags and the
/// environment.
fn lock_choice(command: &Command) -> Result<LockChoice, String> {
    let env = |name: &str| std::env::var_os(name);
    match command {
        Command::Init {
            require_memory_lock,
            no_memory_lock,
            ..
        }
        | Command::Serve {
            require_memory_lock,
            no_memory_lock,
            ..
        } => LockChoice::for_start(*no_memory_lock, *require_memory_lock, env),
        Command::Status { .. } => LockChoice::for_status(env),
        // An enclave has no swap and no disk; the lock is best effort and
        // core dumps stay off, as for `serve`.
        #[cfg(feature = "enclave")]
        Command::Enclave(_) => LockChoice::for_start(false, false, env),
    }
}

/// The whole `klav-proxy` program: called first thing by the binary's
/// `main`, before any thread starts (the memory hardening below must come
/// before the runtime's threads). `version` is what `--version` prints
/// after the name: the calling binary's own build identity
/// (`klav-daemon/build.rs`), so the library carries no marker and `klav`,
/// started as `klav-proxy`, still holds exactly one.
pub fn main(version: &'static str) -> ExitCode {
    let cli = match Cli::command()
        .version(version)
        .try_get_matches()
        .and_then(|m| Cli::from_arg_matches(&m))
    {
        Ok(cli) => cli,
        Err(e) => e.exit(),
    };
    let choice = match lock_choice(&cli.command) {
        Ok(choice) => choice,
        Err(e) => {
            eprintln!("klav-proxy: {e}");
            return ExitCode::FAILURE;
        }
    };
    // First, before any thread and before the key (ADR 0044 §3.1): `init`
    // makes it, and `serve` and `status` read it. Fatal only when core
    // dumps can't be turned off or, on Linux, the process stays dumpable;
    // the lock never stops it here (a required lock: `enforce`). The test
    // below keeps this call above the runtime; the binary never refuses for
    // threads that already run (a preloaded library's, an emulator's).
    // Like the hardening, it applies to the whole process.
    let memory = match memory::harden_process(choice.lock) {
        Ok(report) => report,
        Err(e) => {
            eprintln!("klav-proxy: {e}");
            return ExitCode::FAILURE;
        }
    };
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(e) => {
            eprintln!("klav-proxy: cannot start the runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    runtime.block_on(run(cli, memory, choice.required))
}

async fn run(cli: Cli, memory: MemoryReport, required: bool) -> ExitCode {
    // The enclave has no home directory, no registration and no key file:
    // it starts before any of them is looked for.
    #[cfg(feature = "enclave")]
    let cli = match cli {
        Cli {
            command: Command::Enclave(args),
            ..
        } => return run_enclave(args, &memory, required).await,
        cli => cli,
    };
    // The real environment, read once here: what the SDK and rustls would
    // read too.
    let env = StartEnv::from_process();
    let home = match cli.home {
        Some(dir) => Home::at(dir),
        None => match Home::from_env() {
            Ok(home) => home,
            Err(e) => {
                eprintln!("klav-proxy: {e}");
                return ExitCode::FAILURE;
            }
        },
    };
    match cli.command {
        Command::Init {
            email,
            server,
            key_store,
            key_file,
            json,
            ..
        } => {
            // On stderr: `--json` keeps stdout for the report alone.
            if let Some(warning) = memory::unlocked_warning(&memory) {
                eprintln!("klav-proxy: {warning}");
            }
            if let Err(e) = memory::enforce(&memory, required) {
                eprintln!("klav-proxy: {e}");
                return ExitCode::FAILURE;
            }
            let opts = InitOptions {
                home,
                name: cli.name,
                server,
                email,
                key_store: match key_store {
                    Store::File => KeyStoreChoice::File,
                    Store::Keychain => KeyStoreChoice::Keychain,
                },
                key_file,
                env,
            };
            match app::init(opts).await {
                Ok(report) if json => {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&report).unwrap_or_default()
                    );
                    ExitCode::SUCCESS
                }
                Ok(report) => {
                    println!("Registered {} ({}).", report.name, report.agent_id);
                    println!("Key: {}", report.key_store);
                    println!();
                    println!("Pairing code: {}", report.pairing_code);
                    println!();
                    println!(
                        "Next, on a device of yours: `klav proxy use own {}`, then `klav proxy grant <item> …` within {}, before this request lapses. The first grant shows these 6 words: check they match before you confirm.",
                        report.agent_id,
                        minutes_left(report.expires_at)
                    );
                    println!(
                        "Never approve it with `klav agent approve` or from the Requests list of the Klav app: that gives it whole projects, and a proxy must only get credentials one by one. Run `klav proxy use` first: from then on Klav refuses that approval."
                    );
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("klav-proxy: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        Command::Serve {
            port,
            channel,
            max_body,
            timeout,
            no_local_calls,
            control_socket,
            no_control_socket,
            if_registered,
            ..
        } => {
            init_logs();
            if if_registered && !app::is_registered(&home, &cli.name) {
                tracing::info!(
                    name = %cli.name,
                    "no proxy is registered under this name here: nothing to serve"
                );
                return ExitCode::SUCCESS;
            }
            if if_registered && app::answers_locally(&home, &cli.name) {
                tracing::info!(
                    name = %cli.name,
                    "another klav-proxy already serves this registration"
                );
                return ExitCode::SUCCESS;
            }
            if if_registered && let Some(why) = app::never_serves(&home, &cli.name, &env).await {
                tracing::info!(name = %cli.name, why, "this proxy can't serve yet: not starting");
                eprintln!("klav-proxy: not serving: {why}.");
                return ExitCode::SUCCESS;
            }
            if let Err(e) = memory::enforce(&memory, required) {
                tracing::error!(error = %e, "klav-proxy did not start");
                eprintln!("klav-proxy: {e}");
                return ExitCode::FAILURE;
            }
            let opts = ServeOptions {
                home,
                name: cli.name,
                port,
                channel,
                max_body,
                request_timeout: Duration::from_secs(timeout.max(1)),
                no_local_calls,
                control_socket: match (control_socket, no_control_socket) {
                    (_, true) => ControlSocket::Off,
                    (Some(path), false) => ControlSocket::At(path),
                    (None, false) => ControlSocket::Default,
                },
                env,
            };
            match app::serve(opts, memory).await {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    tracing::error!(error = %e, "klav-proxy stopped");
                    eprintln!("klav-proxy: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        Command::Status { json } => {
            // Decision 26 (ADR 0044): what this process's own hardening
            // got, from the report `main` got above (no second lock), on
            // stderr and before `status` reads the registration or calls the
            // server (own choice L26), so a dry run under a unit's or a
            // container's settings shows it even when those fail. Stdout
            // stays the report's alone. Nothing on macOS (L25).
            if let Some(line) = memory::status_own_line(&memory, memory::CAN_LOCK_HERE) {
                eprintln!("{line}");
            }
            match app::status(&home, &cli.name, &env).await {
                Ok(report) if json => {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&report).unwrap_or_default()
                    );
                    ExitCode::SUCCESS
                }
                Ok(report) => {
                    println!(
                        "{} ({}): {}",
                        report.agent.name,
                        report.agent.agent_id,
                        report.agent.status.as_str()
                    );
                    println!("Pairing code: {}", report.agent.pairing_code);
                    if report.agent.paused.is_some() {
                        println!("Paused by the person: no call goes through.");
                    }
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX));
                    println!("{}", app::memory_words(&report, now));
                    if report.profiles.is_empty() {
                        println!("No profiles yet.");
                    }
                    for p in report.profiles {
                        println!(
                            "  {:<16} {} (header {}, {} calls/min)",
                            p.name, p.upstream, p.header, p.rate_per_minute
                        );
                    }
                    if let Some(e) = &report.store_error {
                        println!("Sandboxes: the store cannot be read: {e}");
                    } else if report.sandboxes.is_empty() {
                        println!("No live sandboxes.");
                    } else {
                        println!("Live sandboxes:");
                    }
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX));
                    for s in &report.sandboxes {
                        let left = s.expires_at.saturating_sub(now).max(0) / 60_000;
                        // The issuer wrote the label: nothing hidden reaches
                        // the terminal.
                        let label: String = s
                            .label
                            .chars()
                            .filter(|c| !klav_core::text::is_hidden(*c))
                            .collect();
                        println!(
                            "  {} {:<24} {} issuer {} ({} min left{})",
                            s.sandbox_id,
                            label,
                            s.profiles.join(","),
                            s.issuer_id,
                            left,
                            if s.claimed { ", claimed" } else { "" }
                        );
                    }
                    if !report.unconfirmed_thefts.is_empty() {
                        println!(
                            "Theft signals this proxy could not confirm the Klav server logged (the server already counted the sandbox as over). Check the person's log for each:"
                        );
                        for t in &report.unconfirmed_thefts {
                            println!(
                                "  {} (the right secret came from a second channel key)",
                                t.sandbox_id
                            );
                        }
                    }
                    if let Some(e) = &report.redactions_error {
                        println!("Redaction counts: cannot be read: {e}");
                    }
                    if let Some(counts) = &report.redactions {
                        for (profile, c) in counts.profiles.iter().filter(|(_, c)| c.partial > 0) {
                            println!(
                                "  {profile}: {} piece(s) of the injected value came back in answers and were left as they are. A caller may be making the service echo guesses: check who calls this profile.",
                                c.partial
                            );
                        }
                        for (profile, c) in counts.profiles.iter().filter(|(_, c)| c.redacted > 0) {
                            println!(
                                "  {profile}: the whole injected value was redacted from answers {} time(s).",
                                c.redacted
                            );
                        }
                    }
                    if report.unsent_ends > 0 {
                        println!(
                            "{} sandbox ends wait for the Klav server.",
                            report.unsent_ends
                        );
                    }
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("klav-proxy: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        // Taken at the top, before the home directory is read.
        #[cfg(feature = "enclave")]
        Command::Enclave(_) => unreachable!("klav-proxy enclave starts before the home is read"),
    }
}

/// `klav-proxy enclave` (ADR 0051): JSON logs on stderr for the parent's
/// console, then the enclave until it stops.
#[cfg(feature = "enclave")]
async fn run_enclave(
    args: crate::enclave::run::Args,
    memory: &MemoryReport,
    required: bool,
) -> ExitCode {
    init_logs();
    if let Some(warning) = memory::unlocked_warning(memory) {
        tracing::warn!("{warning}");
    }
    if let Err(e) = memory::enforce(memory, required) {
        tracing::error!(error = %e, "klav-proxy enclave did not start");
        return ExitCode::FAILURE;
    }
    match crate::enclave::run::run(args).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(error = %e, "klav-proxy enclave stopped");
            eprintln!("klav-proxy: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    /// ADR 0044 §3.1 (and L13, withdrawn): `main` hardens the process
    /// before it builds the tokio runtime and before `run` reads or makes
    /// the key, and nowhere else. A source check, so that moving the call
    /// fails here, on every system, without the binary refusing to start.
    #[test]
    fn main_hardens_before_the_runtime_and_the_key() {
        let source = include_str!("cli.rs");
        let main = source
            .split_once("\npub fn main(version: &'static str) -> ExitCode {")
            .and_then(|(_, rest)| rest.split_once("\n}\n"))
            .map(|(body, _)| body)
            .expect("fn main");
        let at = |what: &str| {
            main.find(what)
                .unwrap_or_else(|| panic!("`{what}` is not in main"))
        };
        let harden = at("memory::harden_process(");
        assert!(
            harden < at("tokio::runtime::Builder"),
            "harden after the runtime"
        );
        assert!(harden < at("block_on(run("), "harden after run");
        let code = source
            .split_once(concat!("#[cfg", "(test)]"))
            .map_or(source, |(code, _)| code);
        assert_eq!(
            code.matches("harden_process(").count(),
            1,
            "harden_process is called once, in main"
        );
        assert!(!code.contains("#[tokio::main]"));
    }
}
