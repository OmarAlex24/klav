//! `klav client connect <client> --mcp <profile>…` and `klav client
//! disconnect <client> --mcp` (ADR 0049 §3): an agent client on this Mac
//! reaches the MCP profiles of the person's credential proxy on loopback,
//! one entry per profile, each with the client's local client token.
//!
//! The token (`klc1_…`) is made here, with `klav-core`, and goes only into
//! the client's settings file (or the client's own CLI, on its standard
//! input). `klavd` and the server get its digest, signed into the proxy's
//! grant. Nothing printed holds it: the entries are shown by URL.

use std::io::Write;
use std::path::{Path, PathBuf};

use klav_client::item_grants::ItemGrantReport;
use klav_client::proxy_admin::{LocalClientChange, LocalClientChangeView};
use klav_core::crypto::mcp::LocalClientToken;
use klav_daemon::protocol::Request;
use klav_proto::Blob;
use serde::Serialize;
use serde_json::{Value, json};

use super::agent::with_presence;
use super::client::{ask, client_path};
use crate::backend::{Backend, call};
use crate::cli::{ClientConnectArgs, ClientDisconnectArgs};
use crate::clients::files::{self, Target};
use crate::clients::{ClientId, Env};
use crate::context::Ctx;
use crate::error::{CliError, CliResult, usage};
use crate::output;

/// Longest a client's CLI may take.
const TOOL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// What is shown in place of the token.
const TOKEN_SHOWN: &str = "Bearer klc1_••••••••";

/// How an entry reaches a client's settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Writer {
    /// Claude Code: its own CLI, `claude mcp add-json --scope user NAME -`,
    /// with the entry on standard input (never on the command line, which
    /// other processes can read).
    ClaudeCli,
    /// A JSON file, the entry in `mcpServers`; `typed` adds
    /// `"type": "http"`.
    Json { typed: bool },
    /// Codex's `config.toml`: `url` and `http_headers` (its CLI takes a
    /// bearer only from an environment variable).
    Toml,
}

/// Which clients take a gateway entry, and how (ADR 0049 §3.1, §14). The
/// shapes come from each client's documentation and CLI help (Claude Code
/// 2.1.331, Codex 0.166.0); the hand tests of layer 7 check them against
/// the running clients.
fn writer(client: ClientId) -> CliResult<Writer> {
    match client {
        ClientId::ClaudeCode => Ok(Writer::ClaudeCli),
        ClientId::Codex => Ok(Writer::Toml),
        ClientId::Cursor => Ok(Writer::Json { typed: false }),
        ClientId::Vscode => Ok(Writer::Json { typed: true }),
        other => Err(usage(format!(
            "{} does not take MCP gateway entries yet: Klav writes them for Claude Code, Codex, Cursor and VS Code (ADR 0049 §3.1)",
            other.name()
        ))),
    }
}

/// The loopback URL of `profile`'s endpoint.
fn url(port: u16, profile: &str, endpoint: &str) -> String {
    format!("http://127.0.0.1:{port}/{profile}{endpoint}")
}

/// The entry as the client's settings hold it.
fn entry_value(writer: Writer, url: &str, token: &LocalClientToken) -> Value {
    let bearer = format!("Bearer {}", token.expose());
    match writer {
        Writer::ClaudeCli | Writer::Json { typed: true } => json!({
            "type": "http",
            "url": url,
            "headers": { "Authorization": bearer },
        }),
        Writer::Json { typed: false } => json!({
            "url": url,
            "headers": { "Authorization": bearer },
        }),
        // Written as TOML by `set_http_member`, never through this.
        Writer::Toml => json!({ "url": url, "http_headers": { "Authorization": bearer } }),
    }
}

/// Whether an entry found under `profile`'s name is one Klav writes: a
/// loopback URL under `/<profile>/` and a local client token as its only
/// credential. Anything else is the person's, and only `--replace` (or
/// `--force` to remove it) touches it.
fn is_gateway_entry(value: &Value, profile: &str) -> bool {
    let Some(url) = value.get("url").and_then(Value::as_str) else {
        return false;
    };
    let Some(rest) = url.strip_prefix("http://127.0.0.1:") else {
        return false;
    };
    let Some((port, path)) = rest.split_once('/') else {
        return false;
    };
    if port.parse::<u16>().is_err()
        || !(profile.is_empty() || path.starts_with(&format!("{profile}/")))
    {
        return false;
    }
    let headers = value
        .get("headers")
        .or_else(|| value.get("http_headers"))
        .and_then(Value::as_object);
    headers.is_some_and(|h| {
        h.len() == 1
            && h.iter().all(|(k, v)| {
                k.eq_ignore_ascii_case("authorization")
                    && v.as_str().is_some_and(|v| v.starts_with("Bearer klc1_"))
            })
    })
}

/// One entry of the plan.
#[derive(Debug, Serialize)]
struct EntryStep {
    profile: String,
    url: String,
    /// `add`, `replace` (Klav's own entry, with a new token), `replace
    /// yours` (`--replace`), `remove`, `keep` (not Klav's, left).
    action: &'static str,
}

/// What `connect --mcp` or `disconnect --mcp` will do, shown first.
#[derive(Debug, Serialize)]
struct McpPlan {
    client: ClientId,
    file: PathBuf,
    proxy: String,
    local_client: String,
    /// The client's profiles in the proxy's grant after this.
    profiles: Vec<String>,
    /// A new token is made and signed.
    new_token: bool,
    entries: Vec<EntryStep>,
    warnings: Vec<String>,
    dry_run: bool,
}

fn show(plan: &McpPlan, json: bool, connect: bool) -> CliResult<()> {
    if json {
        return output::json(plan);
    }
    output::info(&format!(
        "{} {} {} the MCP gateway of the credential proxy {:?}:",
        if plan.dry_run { "Would" } else { "Will" },
        if connect { "connect" } else { "disconnect" },
        plan.client.name(),
        plan.proxy
    ));
    output::info(&format!("  settings      {}", plan.file.display()));
    output::info(&format!(
        "  local client  {}{}",
        plan.local_client,
        if plan.new_token {
            format!(", with a new token ({TOKEN_SHOWN}), written only to that file and never shown")
        } else {
            String::new()
        }
    ));
    if connect {
        output::info(&format!("  may use       {}", plan.profiles.join(", ")));
    } else if plan.profiles.is_empty() {
        output::info("  may use       nothing: it leaves the proxy's grant");
    } else {
        output::info(&format!("  keeps         {}", plan.profiles.join(", ")));
    }
    for e in &plan.entries {
        output::info(&format!("  {:<13} {}  ({})", e.profile, e.url, e.action));
    }
    for w in &plan.warnings {
        output::warn(w);
    }
    Ok(())
}

/// The preview of a change, from `klavd` or this process.
async fn preview(
    ctx: &mut Ctx,
    name: &str,
    change: &LocalClientChange,
) -> CliResult<LocalClientChangeView> {
    Ok(match ctx.backend().await? {
        Backend::Direct(u) => u.prepare_local_client(name, change).await?.view().clone(),
        Backend::Daemon(d) => {
            call(
                d,
                Request::LocalClientPreview {
                    name: name.to_owned(),
                    change: change.clone(),
                },
            )
            .await?
        }
    })
}

/// Signs a change, after presence, if the grant is what `shown` showed.
async fn sign(
    ctx: &mut Ctx,
    name: &str,
    change: LocalClientChange,
    shown: &LocalClientChangeView,
) -> CliResult<ItemGrantReport> {
    match ctx.backend().await? {
        Backend::Direct(u) => {
            // The master password unlocked this process: that is the
            // presence here.
            let prepared = u.prepare_local_client(name, &change).await?;
            let view = prepared.view();
            if view.base_version != shown.base_version || view.agent_id != shown.agent_id {
                return Err(CliError::Other(format!(
                    "the grant of the proxy {:?} changed meanwhile; run it again",
                    shown.agent
                )));
            }
            Ok(u.commit_local_client(prepared).await?)
        }
        Backend::Daemon(_) => {
            with_presence(ctx, |password| Request::LocalClientChange {
                name: name.to_owned(),
                change: change.clone(),
                base_version: shown.base_version,
                shown_proxy: shown.agent_id,
                password,
            })
            .await
        }
    }
}

/// A settings file, as read.
struct Settings {
    target: Target,
    text: String,
    existed: bool,
}

fn read(path: &Path, env: &Env, writer: Writer) -> CliResult<Settings> {
    let target = Target::resolve(path)?;
    if writer != Writer::ClaudeCli
        && let Some(why) = target.refusal(env)
    {
        return Err(CliError::Other(format!("{why}. Nothing was written")));
    }
    let bytes = target.read()?;
    let existed = bytes.is_some();
    let text = match bytes {
        None => String::new(),
        Some(b) => String::from_utf8(b)
            .map_err(|_| CliError::Other(format!("{} is not UTF-8 text", target.real.display())))?,
    };
    Ok(Settings {
        target,
        text,
        existed,
    })
}

/// The entry under `profile` in `settings`, as JSON.
fn found(settings: &Settings, writer: Writer, profile: &str) -> CliResult<Option<Value>> {
    if !settings.existed {
        return Ok(None);
    }
    let read = match writer {
        Writer::Toml => crate::clients::toml::member(&settings.text, profile),
        Writer::ClaudeCli | Writer::Json { .. } => {
            crate::clients::json::member(&settings.text, "mcpServers", profile)
        }
    };
    read.map_err(|e| {
        CliError::Other(format!(
            "{}: {e}. Nothing was written",
            settings.target.real.display()
        ))
    })
}

pub(crate) async fn connect(ctx: &mut Ctx, args: ClientConnectArgs) -> CliResult<()> {
    let env = Env::from_env()?;
    let client = args.client;
    let writer = writer(client)?;
    let path = client_path(client, &env)?;
    let name = client.id().to_owned();
    if writer == Writer::ClaudeCli && env.which("claude").is_none() {
        return Err(CliError::Other(
            "cannot connect Claude Code without its `claude` command, which is not in PATH: Klav writes its settings only through it".into(),
        ));
    }
    let settings = read(&path, &env, writer)?;
    if !settings.existed
        && writer != Writer::ClaudeCli
        && settings.target.real.parent().is_some_and(|d| !d.is_dir())
    {
        return Err(CliError::Other(format!(
            "{} has no folder {} yet, and Klav does not create it. Open {} once and connect again. Nothing was written",
            client.name(),
            settings
                .target
                .real
                .parent()
                .map(|d| d.display().to_string())
                .unwrap_or_default(),
            client.name()
        )));
    }
    let wanted = LocalClientChange::Set {
        profiles: args.mcp.clone(),
        token_digest: None,
    };
    let shown = preview(ctx, &name, &wanted).await?;
    let mut entries = Vec::new();
    for (profile, endpoint) in &shown.endpoints {
        let action = match found(&settings, writer, profile)? {
            None => "add",
            Some(v) if is_gateway_entry(&v, profile) => "replace",
            Some(_) if args.replace => "replace yours",
            Some(_) => {
                return Err(CliError::Other(format!(
                    "{} already has an MCP server named {profile:?} that Klav did not write. Nothing was written: rerun with --replace to put the gateway's entry in its place (a backup is kept)",
                    client.name()
                )));
            }
        };
        entries.push(EntryStep {
            profile: profile.clone(),
            url: url(args.proxy_port, profile, endpoint),
            action,
        });
    }
    let mut warnings = shown.warnings.clone();
    warnings.extend(settings.target.link_warnings(&env));
    warnings.push(format!(
        "the token works only on this Mac's loopback, for the profiles above; any program running as you can read it from {} (ADR 0049, residual risk 104)",
        settings.target.path.display()
    ));
    let plan = McpPlan {
        client,
        file: settings.target.path.clone(),
        proxy: shown.agent.clone(),
        local_client: name.clone(),
        profiles: shown.profiles.clone(),
        // Every connect writes the entries, so every connect makes one.
        new_token: true,
        entries,
        warnings,
        dry_run: args.dry_run,
    };
    show(&plan, args.json.json, true)?;
    if args.dry_run {
        return Ok(());
    }
    if !args.yes && !ask("Sign it and write the entries?")? {
        return Err(usage(
            "nothing was signed or written (without a terminal, pass --yes)",
        ));
    }
    let token = LocalClientToken::generate();
    let digest = token
        .digest(shown.agent_id)
        .map_err(|e| CliError::Other(e.to_string()))?;
    let report = sign(
        ctx,
        &name,
        LocalClientChange::Set {
            profiles: shown.profiles.clone(),
            token_digest: Some(Blob::new(digest.to_vec())),
        },
        &shown,
    )
    .await?;
    if !report.granted {
        return Err(CliError::Other(format!(
            "the proxy's grant was not signed ({}); nothing was written. Run it again",
            report.failed.as_deref().unwrap_or("the upload failed")
        )));
    }
    let wrote = write_entries(ctx, client, writer, &settings, &plan, &token);
    if let Err(e) = wrote {
        return Err(CliError::Other(format!(
            "the proxy's grant now names {name} with a new token, but its entries were not written: {}. Run the same command again, which makes another token",
            e.message().unwrap_or_default()
        )));
    }
    if !args.json.json {
        output::info(&format!(
            "Connected {} to {} through the proxy {:?}. {}",
            client.name(),
            shown.profiles.join(", "),
            shown.agent,
            if client.needs_restart() || writer == Writer::Toml {
                "Restart it to load the entries; the proxy takes the new token within 30 s."
            } else {
                "The proxy takes the new token within 30 s."
            }
        ));
    }
    Ok(())
}

/// Writes every entry of `plan` with `token`, with a backup of the file
/// first; nothing else of the file changes.
fn write_entries(
    ctx: &Ctx,
    client: ClientId,
    writer: Writer,
    settings: &Settings,
    plan: &McpPlan,
    token: &LocalClientToken,
) -> CliResult<()> {
    if writer == Writer::ClaudeCli {
        let cli = Env::from_env()?
            .which("claude")
            .ok_or_else(|| CliError::Other("`claude` is not in PATH".into()))?;
        for e in &plan.entries {
            if e.action != "add" {
                run_claude(
                    &cli,
                    &["mcp", "remove", "--scope", "user", &e.profile],
                    None,
                )?;
            }
            let value = entry_value(writer, &e.url, token);
            let body = serde_json::to_vec(&value).map_err(|e| CliError::Other(e.to_string()))?;
            run_claude(
                &cli,
                &["mcp", "add-json", "--scope", "user", &e.profile, "-"],
                Some(&body),
            )?;
        }
        return Ok(());
    }
    let mut text = settings.text.clone();
    for e in &plan.entries {
        text = match writer {
            Writer::Toml => crate::clients::toml::set_http_member(
                &text,
                &e.profile,
                &e.url,
                &[("Authorization".into(), format!("Bearer {}", token.expose()))],
            ),
            _ => crate::clients::json::set_member(
                &text,
                "mcpServers",
                &e.profile,
                &entry_value(writer, &e.url, token),
            ),
        }
        .map_err(|e| CliError::Other(e.to_string()))?;
    }
    save(ctx, client, writer, settings, &text, &plan.entries)
}

/// Backs the file up and writes `text`, after checking that only the
/// entries named changed.
fn save(
    ctx: &Ctx,
    client: ClientId,
    writer: Writer,
    settings: &Settings,
    text: &str,
    entries: &[EntryStep],
) -> CliResult<()> {
    // Check each member alone: strip the others from both sides first.
    let mut before = settings.text.clone();
    let mut after = text.to_owned();
    if settings.existed {
        for e in entries {
            let strip = |t: &str| match writer {
                Writer::Toml => crate::clients::toml::remove_member(t, &e.profile),
                _ => crate::clients::json::remove_member(t, "mcpServers", &e.profile),
            };
            before = strip(&before).map_err(|e| CliError::Other(e.to_string()))?;
            after = strip(&after).map_err(|e| CliError::Other(e.to_string()))?;
        }
        let same = match writer {
            Writer::Toml => before.trim_end() == after.trim_end(),
            _ => {
                crate::clients::json::only_member_changed(&before, &after, "mcpServers", "").is_ok()
            }
        };
        if !same {
            return Err(CliError::Other(
                "another setting of the file would change; nothing was written".into(),
            ));
        }
        files::backup(
            &ctx.home,
            client,
            &files::backup_name(&settings.target.path),
            settings.text.as_bytes(),
        )?;
    }
    files::write_atomic(
        &settings.target.real,
        text.as_bytes(),
        settings.target.mode(),
    )
}

/// Runs the client's CLI with `input` on its standard input; never puts
/// it, or the output, on the screen.
fn run_claude(cli: &Path, args: &[&str], input: Option<&[u8]>) -> CliResult<()> {
    let mut child = std::process::Command::new(cli)
        .args(args)
        .stdin(if input.is_some() {
            std::process::Stdio::piped()
        } else {
            std::process::Stdio::null()
        })
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| CliError::Other(format!("cannot run {}: {e}", cli.display())))?;
    if let (Some(input), Some(mut stdin)) = (input, child.stdin.take()) {
        stdin.write_all(input)?;
    }
    let started = std::time::Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if started.elapsed() > TOOL_TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            return Err(CliError::Other(format!(
                "`claude {}` did not finish in {} s",
                args.iter().take(2).copied().collect::<Vec<_>>().join(" "),
                TOOL_TIMEOUT.as_secs()
            )));
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    };
    // `remove` of an entry that is not there fails: fine.
    if status.success() || args.get(1) == Some(&"remove") {
        return Ok(());
    }
    // Claude Code refuses an entry on standard input from inside one of
    // its own sessions; say so, nothing else of what it wrote.
    let mut why = String::new();
    if let Some(mut err) = child.stderr.take() {
        use std::io::Read;
        let _ = err.read_to_string(&mut why);
    }
    let inside = why.contains("inside a Claude Code session");
    Err(CliError::Other(format!(
        "`claude {}` failed ({}){}",
        args.iter().take(2).copied().collect::<Vec<_>>().join(" "),
        status
            .code()
            .map_or_else(|| "killed".into(), |c| format!("exit {c}")),
        if inside {
            ": Claude Code takes an entry on standard input only outside its own sessions. Run this command in your own terminal"
        } else {
            ""
        }
    )))
}

pub(crate) async fn disconnect(ctx: &mut Ctx, args: ClientDisconnectArgs) -> CliResult<()> {
    let env = Env::from_env()?;
    let client = args.client;
    let writer = writer(client)?;
    let path = client_path(client, &env)?;
    let name = client.id().to_owned();
    let settings = read(&path, &env, writer)?;
    let named = args.mcp.clone().unwrap_or_default();
    // What the grant holds for the client now: the preview of its removal
    // says (none: the grant does not name it).
    let before = match preview(ctx, &name, &LocalClientChange::Remove).await {
        Ok(view) => view.before,
        Err(CliError::Client(klav_client::ClientError::NotFound(_))) => None,
        Err(e) => return Err(e),
    };
    let removing: Vec<String> = if named.is_empty() {
        before.clone().unwrap_or_default()
    } else {
        named.clone()
    };
    let keeping: Vec<String> = before
        .clone()
        .unwrap_or_default()
        .into_iter()
        .filter(|p| !removing.contains(p))
        .collect();
    let change = match &before {
        None => None,
        Some(_) if keeping.is_empty() => Some(LocalClientChange::Remove),
        Some(_) => Some(LocalClientChange::Set {
            profiles: keeping.clone(),
            token_digest: None,
        }),
    };
    let shown = match &change {
        Some(c) => Some(preview(ctx, &name, c).await?),
        None => None,
    };
    let mut entries = Vec::new();
    let mut warnings = Vec::new();
    // Entries in the file: those named, or every gateway entry when none.
    let candidates: Vec<String> = if named.is_empty() {
        let all = match writer {
            Writer::Toml => list_members_toml(&settings),
            _ => list_members_json(&settings),
        };
        all.into_iter()
            .filter(|(_, v)| is_gateway_entry(v, ""))
            .map(|(k, _)| k)
            .chain(removing.iter().cloned())
            .collect()
    } else {
        named.clone()
    };
    let mut seen = std::collections::HashSet::new();
    for profile in candidates {
        if !seen.insert(profile.clone()) {
            continue;
        }
        match found(&settings, writer, &profile)? {
            None => {}
            Some(v) if is_gateway_entry(&v, &profile) || args.force => {
                entries.push(EntryStep {
                    url: v
                        .get("url")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned(),
                    profile,
                    action: "remove",
                });
            }
            Some(_) => warnings.push(format!(
                "the entry {profile:?} of {} is not one Klav wrote, so it stays (--force removes it)",
                client.name()
            )),
        }
    }
    if before.is_none() {
        warnings.push(format!(
            "the proxy's grant names no local client {name}: nothing to sign"
        ));
    }
    let plan = McpPlan {
        client,
        file: settings.target.path.clone(),
        proxy: shown.as_ref().map(|s| s.agent.clone()).unwrap_or_default(),
        local_client: name.clone(),
        profiles: keeping.clone(),
        new_token: false,
        entries,
        warnings,
        dry_run: args.dry_run,
    };
    show(&plan, args.json.json, false)?;
    if args.dry_run {
        return Ok(());
    }
    if plan.entries.is_empty() && change.is_none() {
        return Ok(());
    }
    if !args.yes && !ask("Go ahead?")? {
        return Err(usage(
            "nothing was signed or removed (without a terminal, pass --yes)",
        ));
    }
    // The grant first: that is what stops the token working.
    if let (Some(change), Some(shown)) = (change, &shown) {
        let report = sign(ctx, &name, change, shown).await?;
        if !report.granted {
            return Err(CliError::Other(format!(
                "the proxy's grant was not signed ({}); nothing was removed. Run it again",
                report.failed.as_deref().unwrap_or("the upload failed")
            )));
        }
    }
    if !plan.entries.is_empty() {
        if writer == Writer::ClaudeCli {
            let cli = env
                .which("claude")
                .ok_or_else(|| CliError::Other("`claude` is not in PATH".into()))?;
            for e in &plan.entries {
                run_claude(
                    &cli,
                    &["mcp", "remove", "--scope", "user", &e.profile],
                    None,
                )?;
            }
        } else {
            let mut text = settings.text.clone();
            for e in &plan.entries {
                text = match writer {
                    Writer::Toml => crate::clients::toml::remove_member(&text, &e.profile),
                    _ => crate::clients::json::remove_member(&text, "mcpServers", &e.profile),
                }
                .map_err(|e| CliError::Other(e.to_string()))?;
            }
            save(ctx, client, writer, &settings, &text, &plan.entries)?;
        }
    }
    if !args.json.json {
        output::info(&format!(
            "Disconnected {} from {}.",
            client.name(),
            if removing.is_empty() {
                "the MCP gateway".to_owned()
            } else {
                removing.join(", ")
            }
        ));
    }
    Ok(())
}

/// The servers of a JSON settings file, by name.
fn list_members_json(settings: &Settings) -> Vec<(String, Value)> {
    if !settings.existed {
        return Vec::new();
    }
    crate::clients::json::value(&settings.text)
        .ok()
        .and_then(|v| v.get("mcpServers").and_then(Value::as_object).cloned())
        .map(|o| o.into_iter().collect())
        .unwrap_or_default()
}

/// The servers of Codex's `config.toml`, by name.
fn list_members_toml(settings: &Settings) -> Vec<(String, Value)> {
    if !settings.existed {
        return Vec::new();
    }
    let Ok(doc) = settings.text.parse::<toml_edit::DocumentMut>() else {
        return Vec::new();
    };
    doc.get("mcp_servers")
        .and_then(toml_edit::Item::as_table_like)
        .map(|t| {
            t.iter()
                .filter_map(|(k, _)| {
                    crate::clients::toml::member(&settings.text, k)
                        .ok()
                        .flatten()
                        .map(|v| (k.to_owned(), v))
                })
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_loopback_entries_with_a_local_token_are_klavs() {
        let token = LocalClientToken::generate();
        for writer in [
            Writer::ClaudeCli,
            Writer::Json { typed: true },
            Writer::Json { typed: false },
            Writer::Toml,
        ] {
            let v = entry_value(writer, "http://127.0.0.1:8790/maple/mcp", &token);
            assert!(is_gateway_entry(&v, "maple"), "{writer:?}");
            assert!(is_gateway_entry(&v, ""), "{writer:?}");
            assert!(!is_gateway_entry(&v, "linear"), "{writer:?}");
        }
        for other in [
            json!({ "url": "https://mcp.example.com/maple/mcp", "headers": { "Authorization": "Bearer klc1_x" } }),
            json!({ "url": "http://127.0.0.1:8790/maple/mcp", "headers": { "Authorization": "Bearer sk_live" } }),
            json!({ "url": "http://127.0.0.1:8790/maple/mcp", "headers": { "Authorization": "Bearer klc1_x", "X-Key": "k" } }),
            json!({ "command": "maple-mcp" }),
        ] {
            assert!(!is_gateway_entry(&other, "maple"), "{other}");
        }
    }

    #[test]
    fn the_entry_shapes_carry_the_token_only_in_the_header() {
        let token = LocalClientToken::generate();
        let v = entry_value(
            Writer::Json { typed: false },
            "http://127.0.0.1:8790/maple/mcp",
            &token,
        );
        assert!(v.get("type").is_none());
        let typed = entry_value(
            Writer::Json { typed: true },
            "http://127.0.0.1:8790/maple/mcp",
            &token,
        );
        assert_eq!(typed["type"], "http");
        assert_eq!(
            typed["headers"]["Authorization"],
            format!("Bearer {}", token.expose())
        );
        assert!(!typed["url"].as_str().unwrap().contains("klc1_"));
    }

    #[test]
    fn only_four_clients_take_gateway_entries() {
        for c in [
            ClientId::ClaudeCode,
            ClientId::Codex,
            ClientId::Cursor,
            ClientId::Vscode,
        ] {
            assert!(writer(c).is_ok(), "{c:?}");
        }
        for c in [ClientId::ClaudeDesktop, ClientId::Antigravity] {
            assert!(writer(c).is_err(), "{c:?}");
        }
    }
}
