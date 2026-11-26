//! `klav proxy local …` (ADR 0036 E3.5, layer 11): the credential proxy
//! that runs on this machine, through its local socket. `status` and
//! `revoke` need neither `klavd` nor an unlocked vault: the socket answers
//! this user only, shows metadata, and revoking only takes access away
//! (risk 64). `init` registers a proxy for this machine by running this
//! binary as `klav-proxy init`.

use std::path::PathBuf;

use klav_client::local_proxy::{self, LocalProxyError, LocalSandbox, LocalSandboxes, codes};
use klav_core::ids::SandboxId;
use serde_json::json;

use crate::cli::{ProxyLocalCommand, ProxyLocalInitArgs, ProxyLocalRevokeArgs};
use crate::context::Ctx;
use crate::error::{CliError, CliResult};
use crate::output;

pub(crate) async fn local_cmd(ctx: &mut Ctx, cmd: ProxyLocalCommand) -> CliResult<()> {
    let path = local_proxy::socket_path(&ctx.home, local_proxy::DEFAULT_NAME);
    match cmd {
        ProxyLocalCommand::Status(flag) => status(path, flag.json).await,
        ProxyLocalCommand::Revoke(args) => revoke(path, args).await,
        ProxyLocalCommand::Init(args) => init(ctx, args),
    }
}

/// Runs the blocking socket client off the runtime's threads.
async fn ask<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, LocalProxyError> + Send + 'static,
) -> CliResult<T> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| CliError::Other(e.to_string()))?
        .map_err(refusal)
}

fn refusal(e: LocalProxyError) -> CliError {
    match e {
        LocalProxyError::NotRunning(_) => CliError::Coded {
            code: 1,
            error: Some("klav_local_proxy_not_running".into()),
            message: "No credential proxy runs on this machine.".into(),
            next: Some(
                "Start it from the Klav app (Development › Sandboxes), or run `klav-proxy serve`. To revoke sandboxes of a proxy elsewhere: `klav proxy sandboxes revoke`."
                    .into(),
            ),
        },
        LocalProxyError::Refused { code, message } if code == codes::NOT_FOUND => {
            CliError::Coded {
                code: 1,
                error: Some(code),
                message,
                next: Some("`klav proxy local status` lists its live sandboxes.".into()),
            }
        }
        other => CliError::Other(other.to_string()),
    }
}

async fn status(path: PathBuf, json_out: bool) -> CliResult<()> {
    let at = path.clone();
    let listed = ask(move || local_proxy::sandboxes(&at)).await?;
    if json_out {
        return output::json(&listed);
    }
    for line in status_lines(&listed, now_ms()) {
        output::line(&line);
    }
    Ok(())
}

/// `status`'s lines. The label is the issuer's words: quoted and without
/// hidden characters (T136, T157).
fn status_lines(listed: &LocalSandboxes, now: i64) -> Vec<String> {
    let mut lines = vec![format!(
        "Credential proxy on this machine: {} on 127.0.0.1:{}{}",
        listed.proxy_id,
        listed.port,
        if listed.channel {
            ", and a channel for sandboxes"
        } else {
            ""
        }
    )];
    if !listed.local_calls {
        lines.push("Local calls are off (--no-local-calls): local MCP clients get nothing.".into());
    }
    if !listed.mcp_profiles.is_empty() {
        lines.push(format!(
            "MCP servers{}: {}",
            if listed.mcp_gateway {
                ""
            } else {
                " (the gateway is off)"
            },
            listed
                .mcp_profiles
                .iter()
                .map(|p| format!("http://127.0.0.1:{}/{p}/…", listed.port))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if listed.sandboxes.is_empty() {
        lines.push("No live sandboxes.".into());
    } else {
        lines.push(format!("Live sandboxes ({}):", listed.sandboxes.len()));
    }
    for s in &listed.sandboxes {
        lines.push(row(s, now));
    }
    if listed.unsent_ends > 0 {
        lines.push(format!(
            "{} sandbox ends wait for the Klav server.",
            listed.unsent_ends
        ));
    }
    lines
}

fn row(s: &LocalSandbox, now: i64) -> String {
    let label: String = s
        .label
        .chars()
        .filter(|c| !klav_core::text::is_hidden(*c))
        .take(64)
        .collect();
    let state = if s.connected {
        "connected".to_owned()
    } else if !s.claimed {
        "waiting for its claim".to_owned()
    } else {
        match s.last_seen_at {
            Some(at) => format!(
                "not connected, last seen {} min ago",
                (now - at).max(0) / 60_000
            ),
            None => "not connected".to_owned(),
        }
    };
    format!(
        "  {}  {:?} (as its issuer says)  {}  {}, {} min left",
        short(&s.sandbox_id),
        label,
        s.profiles.join(","),
        state,
        (s.expires_at - now).max(0) / 60_000
    )
}

fn short(id: &SandboxId) -> String {
    id.to_string().chars().take(8).collect()
}

async fn revoke(path: PathBuf, args: ProxyLocalRevokeArgs) -> CliResult<()> {
    let target = match (&args.id, args.all) {
        (_, true) => None,
        (Some(id), false) => Some(resolve(&path, id).await?),
        (None, false) => return Err(crate::error::usage("name a sandbox, or --all")),
    };
    let at = path.clone();
    let revoked = ask(move || local_proxy::revoke(&at, target)).await?;
    if args.json.json {
        return output::json(&json!({
            "revoked": revoked.revoked,
            "logged": revoked.logged,
        }));
    }
    match revoked.revoked.len() {
        0 => output::line("No live sandbox to revoke."),
        n => {
            output::line(&format!(
                "Revoked {n} sandbox{} on this machine: {}.",
                if n == 1 { "" } else { "es" },
                revoked
                    .revoked
                    .iter()
                    .map(short)
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
            if revoked.logged {
                output::line("The Klav server has it: it gets no access from now on.");
            } else {
                output::line(
                    "The proxy serves it no more; it tells the Klav server as soon as it can.",
                );
            }
        }
    }
    Ok(())
}

/// A whole ID, or the first 8 characters of one live sandbox.
async fn resolve(path: &std::path::Path, id: &str) -> CliResult<SandboxId> {
    if let Ok(whole) = id.parse::<SandboxId>() {
        return Ok(whole);
    }
    if id.len() < 8 {
        return Err(crate::error::usage(
            "a sandbox ID, or at least its first 8 characters",
        ));
    }
    let at = path.to_owned();
    let listed = ask(move || local_proxy::sandboxes(&at)).await?;
    let found: Vec<SandboxId> = listed
        .sandboxes
        .iter()
        .map(|s| s.sandbox_id)
        .filter(|s| s.to_string().starts_with(id))
        .collect();
    match found.as_slice() {
        [one] => Ok(*one),
        [] => Err(refusal(LocalProxyError::Refused {
            code: codes::NOT_FOUND.into(),
            message: "this proxy has no live sandbox with that ID".into(),
        })),
        _ => Err(crate::error::usage(
            "more than one sandbox starts that way: give more of its ID",
        )),
    }
}

/// `klav-proxy init`, this binary started as `klav-proxy`, with this
/// home: its key in a 0600 file, its output as is.
fn init(ctx: &Ctx, args: ProxyLocalInitArgs) -> CliResult<()> {
    use std::os::unix::process::CommandExt;
    let exe = std::env::current_exe()?;
    let mut cmd = std::process::Command::new(exe);
    cmd.arg0(crate::PROXY_ARGV0)
        .arg("--home")
        .arg(ctx.home.dir())
        .args(["init", "--email", &args.email]);
    if let Some(server) = &args.server {
        cmd.args(["--server", server]);
    }
    if args.json.json {
        cmd.arg("--json");
    }
    let status = cmd.status()?;
    match status.code() {
        Some(0) => Ok(()),
        Some(code) => Err(CliError::Exit(u8::try_from(code).unwrap_or(1))),
        None => Err(CliError::Other("klav-proxy init was stopped".into())),
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;
    use klav_core::ids::AgentId;

    #[test]
    fn status_says_the_label_is_the_issuers_and_hides_nothing_else() {
        let id = SandboxId::generate();
        let listed = LocalSandboxes {
            v: 1,
            proxy_id: AgentId::generate(),
            port: 8790,
            local_calls: true,
            channel: false,
            mcp_gateway: true,
            mcp_profiles: vec!["maple".into()],
            sandboxes: vec![LocalSandbox {
                sandbox_id: id,
                issuer_id: AgentId::generate(),
                label: "chat\u{202e}-1".into(),
                profiles: vec!["northflank".into()],
                issued_at: 0,
                expires_at: 3_600_000,
                claimed: true,
                connected: true,
                last_seen_at: Some(0),
            }],
            unsent_ends: 0,
        };
        let lines = status_lines(&listed, 0);
        assert!(lines[0].ends_with("on 127.0.0.1:8790"), "{lines:?}");
        assert!(lines[1].contains("http://127.0.0.1:8790/maple/…"));
        let row = &lines[3];
        assert!(row.contains(&short(&id)));
        assert!(row.contains("\"chat-1\" (as its issuer says)"), "{row}");
        assert!(row.contains("connected, 60 min left"), "{row}");
    }
}
