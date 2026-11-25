//! `klav-server` binary.
//!
//! ```text
//! klav-server [--config <path>]               serve
//! klav-server healthcheck [--config <path>]   exit 0 if GET /v1/health answers 200
//! klav-server invite create|ls|revoke …       manage registration invites (ADR 0048 §1.4)
//! klav-server --version                       version, commit and its time
//! ```
//!
//! The config path can also come from `KLAV_CONFIG`; every setting can be
//! overridden with `KLAV_*` variables (see `docs/self-hosting.md`).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use klav_server::{Config, Server, invites, telemetry};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// The commit this binary was built from (`klav-daemon/build.rs`): only
/// `--version` reads it.
#[allow(dead_code)]
mod build {
    include!(concat!(env!("OUT_DIR"), "/build_identity.rs"));
}

const USAGE: &str = "usage: klav-server [healthcheck | invite …] [--config <path>] | --version";

enum Command {
    Serve,
    Healthcheck,
    Invite(invites::Command),
    Version,
}

fn parse_args() -> Result<(Command, Option<PathBuf>), String> {
    let mut args = std::env::args().skip(1);
    let mut path = std::env::var_os("KLAV_CONFIG").map(PathBuf::from);
    let mut command = Command::Serve;
    let mut invite: Option<Vec<String>> = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" | "-c" => {
                path = Some(PathBuf::from(args.next().ok_or("--config needs a path")?));
            }
            _ if invite.is_some() => invite.get_or_insert_default().push(arg),
            "--version" | "-V" => command = Command::Version,
            "healthcheck" => command = Command::Healthcheck,
            "invite" => invite = Some(Vec::new()),
            other => return Err(format!("unknown argument {other}\n{USAGE}")),
        }
    }
    if let Some(rest) = invite {
        command = Command::Invite(invites::parse(&rest)?);
    }
    Ok((command, path))
}

/// Usage, version and start-up errors go to the terminal, not to the log.
#[allow(clippy::print_stderr, clippy::print_stdout)]
fn say(to_stderr: bool, message: &str) {
    if to_stderr {
        eprintln!("{message}");
    } else {
        println!("{message}");
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        () = ctrl_c => {}
        () = terminate => {}
    }
    tracing::info!("shutting down");
}

/// Minimal HTTP/1.1 probe of `/v1/health` on the configured listener, so the
/// container image needs no `curl`.
async fn healthcheck(config: &Config) -> bool {
    let ip = match config.listen.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(ip) if ip.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        ip => ip,
    };
    let addr = SocketAddr::new(ip, config.listen.port());
    let probe = async {
        let mut stream = tokio::net::TcpStream::connect(addr).await.ok()?;
        stream
            .write_all(b"GET /v1/health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .ok()?;
        let mut head = [0u8; 12];
        stream.read_exact(&mut head).await.ok()?;
        Some(&head == b"HTTP/1.1 200")
    };
    matches!(
        tokio::time::timeout(Duration::from_secs(3), probe).await,
        Ok(Some(true))
    )
}

#[tokio::main]
async fn main() -> ExitCode {
    let (command, path) = match parse_args() {
        Ok(parsed) => parsed,
        Err(message) => {
            say(true, &message);
            return ExitCode::from(2);
        }
    };
    if let Command::Version = command {
        say(false, &format!("klav-server {}", build::version()));
        return ExitCode::SUCCESS;
    }
    let config = match Config::load(path.as_deref(), std::env::vars()) {
        Ok(config) => config,
        Err(e) => {
            say(true, &format!("klav-server: {e}"));
            return ExitCode::FAILURE;
        }
    };
    let command = match command {
        Command::Healthcheck => {
            return if healthcheck(&config).await {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            };
        }
        // No telemetry: the code goes to stdout only, and nothing is
        // logged (ADR 0048 §1.4, T251).
        Command::Invite(invite) => {
            return match invites::run(&config, invite).await {
                Ok(out) => {
                    say(false, out.trim_end());
                    ExitCode::SUCCESS
                }
                Err(message) => {
                    say(true, &format!("klav-server: {message}"));
                    ExitCode::FAILURE
                }
            };
        }
        other => other,
    };
    let Command::Serve = command else {
        return ExitCode::FAILURE;
    };
    telemetry::init(&config.log);

    let listen = config.listen;
    let server = match Server::new(config).await {
        Ok(server) => server,
        Err(e) => {
            tracing::error!(error = %e, "startup failed");
            return ExitCode::FAILURE;
        }
    };
    let listener = match tokio::net::TcpListener::bind(listen).await {
        Ok(listener) => listener,
        Err(e) => {
            tracing::error!(error = %e, %listen, "cannot bind");
            return ExitCode::FAILURE;
        }
    };
    // The bound address, not the configured one: with port 0 the system
    // picks the port, and the integration tests read it from this line.
    let listen = listener.local_addr().unwrap_or(listen);
    tracing::info!(%listen, version = klav_server::VERSION, "klav-server listening");
    match server.serve(listener, shutdown_signal()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(error = %e, "server error");
            ExitCode::FAILURE
        }
    }
}
