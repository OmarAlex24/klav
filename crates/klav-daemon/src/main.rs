//! `klavd`: Klav local daemon. See `docs/klavd.md`.

use std::process::ExitCode;
use std::time::Duration;

use clap::Parser;
use klav_client::Home;
use klav_daemon::{Build, Config, SYNC_AFTER, serve};

/// The commit this binary was built from (`build.rs`).
mod build {
    include!(concat!(env!("OUT_DIR"), "/build_identity.rs"));
}

/// Keeps your Klav account unlocked in memory for `klav` and locks it
/// after inactivity or when the machine sleeps.
#[derive(Debug, Parser)]
#[command(name = "klavd", version = build::version())]
struct Args {
    /// Lock after this long without use (`90s`, `15m`, `1h`).
    #[arg(long, default_value = "15m", value_parser = parse_duration)]
    idle_lock: Duration,
    /// Do not offer Touch ID (also `KLAV_NO_TOUCH_ID=1`).
    #[arg(long, env = "KLAV_NO_TOUCH_ID", value_parser = clap::builder::BoolishValueParser::new())]
    no_touch_id: bool,
    /// Exit successfully if a `klavd` already answers for this home (the
    /// Mac app's LaunchAgent: another one is not an error to retry).
    #[arg(long)]
    if_not_running: bool,
}

fn parse_duration(text: &str) -> Result<Duration, String> {
    let text = text.trim();
    let split = text
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(text.len());
    let (number, unit) = text.split_at(split);
    let n: u64 = number
        .parse()
        .map_err(|_| format!("invalid duration {text:?}"))?;
    let secs = match unit {
        "" | "s" => n,
        "m" => n.saturating_mul(60),
        "h" => n.saturating_mul(3600),
        _ => return Err(format!("invalid duration unit {unit:?} (s, m or h)")),
    };
    if secs == 0 {
        return Err("the duration must be positive".into());
    }
    Ok(Duration::from_secs(secs))
}

async fn stop_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    let (Ok(mut term), Ok(mut int), Ok(mut hup)) = (
        signal(SignalKind::terminate()),
        signal(SignalKind::interrupt()),
        signal(SignalKind::hangup()),
    ) else {
        return std::future::pending().await;
    };
    tokio::select! {
        _ = term.recv() => {}
        _ = int.recv() => {}
        _ = hup.recv() => {}
    }
}

#[allow(clippy::print_stderr)] // a daemon's only output: startup errors
fn main() -> ExitCode {
    // Started from a browser (through klav-native-host), klavd would
    // otherwise inherit the browser's crash handlers (docs/extension.md).
    klav_touchid::detach_crash_handlers();
    if let Err(e) = klav_daemon::forbid_same_user_debuggers() {
        eprintln!("klavd: {e}");
        return ExitCode::FAILURE;
    }
    let args = Args::parse();
    let home = match Home::from_env() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("klavd: {e}");
            return ExitCode::FAILURE;
        }
    };
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("klavd: {e}");
            return ExitCode::FAILURE;
        }
    };
    let config = Config {
        home,
        idle_lock: args.idle_lock,
        touch_id: !args.no_touch_id,
        sync_after: SYNC_AFTER,
        build: build::commit().map(|(commit, time)| Build {
            commit: commit.to_owned(),
            commit_time: time,
        }),
    };
    if args.if_not_running
        && runtime
            .block_on(klav_daemon::client::DaemonClient::connect(&config.home))
            .is_some()
    {
        return ExitCode::SUCCESS;
    }
    match runtime.block_on(serve(config, stop_signal())) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("klavd: {e}");
            ExitCode::FAILURE
        }
    }
}
