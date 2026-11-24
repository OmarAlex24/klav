//! Settings an organization manages (MDM profiles, `managed-mcp.json`,
//! `requirements.toml`, VS Code policies): read only, never written (ADR
//! 0033 §4). When they keep user MCP servers off, or do not allow `klav`,
//! Klav writes nothing: the entry would not start, and writing it would
//! look connected when it is not.

use std::path::{Path, PathBuf};

use serde::Serialize;
use serde_json::Value;

use super::{ClientId, Entry, Env};

/// What an organization's settings say about adding `klav`.
#[derive(Debug, Clone, Default, Serialize)]
pub(crate) struct Managed {
    /// The rule that keeps `klav` out, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) blocked: Option<String>,
    /// Managed settings that exist but do not decide it, or Klav cannot
    /// read.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) notes: Vec<String>,
}

impl Managed {
    fn block(&mut self, rule: String) {
        if self.blocked.is_none() {
            self.blocked = Some(rule);
        }
    }
}

/// Reads what applies to `client`.
pub(crate) fn check(client: ClientId, env: &Env, entry: &Entry) -> Managed {
    let mut out = Managed::default();
    match client {
        ClientId::ClaudeCode => {
            let dir = if cfg!(target_os = "macos") {
                env.system("/Library/Application Support/ClaudeCode")
            } else {
                env.system("/etc/claude-code")
            };
            let mcp = dir.join("managed-mcp.json");
            if mcp.exists() {
                out.block(format!(
                    "{} gives your organization sole control of Claude Code's MCP servers (`claude mcp add` fails)",
                    mcp.display()
                ));
            }
            let settings = dir.join("managed-settings.json");
            if let Some(text) = read(&settings) {
                match super::json::value(&text) {
                    Ok(v) => claude_code_rules(&v, &settings.display().to_string(), entry, &mut out),
                    Err(e) => out.notes.push(format!("{} could not be read ({e})", settings.display())),
                }
            }
            for (path, v) in profiles(env, "com.anthropic.claudecode") {
                match v {
                    Some(v) => claude_code_rules(&v, &path.display().to_string(), entry, &mut out),
                    None => out.notes.push(unreadable(&path)),
                }
            }
        }
        ClientId::ClaudeDesktop => {
            for (path, v) in profiles(env, "com.anthropic.claudefordesktop") {
                match v {
                    Some(v) if v["isLocalDevMcpEnabled"] == Value::Bool(false) => out.block(format!(
                        "isLocalDevMcpEnabled is off in {}: local MCP servers do not start",
                        path.display()
                    )),
                    Some(_) => {}
                    None => out.notes.push(unreadable(&path)),
                }
            }
        }
        ClientId::Codex => {
            let requirements = env.system("/etc/codex/requirements.toml");
            if let Some(text) = read(&requirements) {
                codex_rules(&text, &requirements, entry, &mut out);
            }
            for (path, _) in profiles(env, "com.openai.codex") {
                out.notes.push(format!(
                    "a configuration profile manages Codex ({}); Klav does not read its requirements",
                    path.display()
                ));
            }
        }
        ClientId::Cursor => out.notes.push(
            "a Cursor team's list of allowed MCP servers lives in Cursor's dashboard, not on this Mac: if the entry does not load, ask your team's admin".into(),
        ),
        ClientId::Vscode => {
            for (path, v) in profiles(env, "com.microsoft.VSCode") {
                let Some(v) = v else {
                    out.notes.push(unreadable(&path));
                    continue;
                };
                if v["ChatMCP"] == Value::Bool(false) || v["ChatMCP"] == "none" {
                    out.block(format!("ChatMCP turns MCP servers off ({})", path.display()));
                }
                if v["ChatAllowManagedMcpServersOnly"] == Value::Bool(true) {
                    out.block(format!(
                        "ChatAllowManagedMcpServersOnly only lets your organization's MCP servers run ({})",
                        path.display()
                    ));
                }
                for key in ["ChatAllowedMcpServers", "ChatDeniedMcpServers", "ChatStrictPluginOnlyCustomization"] {
                    if !v[key].is_null() {
                        out.notes.push(format!("{key} is set ({}); it may keep klav from loading", path.display()));
                    }
                }
            }
        }
        ClientId::Antigravity => {}
    }
    out
}

/// `allowManagedMcpServersOnly`, `deniedMcpServers` and
/// `allowedMcpServers` of Claude Code's managed settings.
fn claude_code_rules(v: &Value, source: &str, entry: &Entry, out: &mut Managed) {
    if v["allowManagedMcpServersOnly"] == Value::Bool(true) {
        out.block(format!(
            "allowManagedMcpServersOnly only lets your organization's MCP servers run ({source})"
        ));
    }
    let names_klav = |list: &Value| {
        list.as_array().is_some_and(|rules| {
            rules.iter().any(|rule| {
                rule["serverName"] == "klav"
                    || rule["serverCommand"].as_array().is_some_and(|cmd| {
                        let mut ours = vec![entry.command.as_str()];
                        ours.extend(entry.args.iter().map(String::as_str));
                        cmd.iter().map(Value::as_str).collect::<Vec<_>>()
                            == ours.into_iter().map(Some).collect::<Vec<_>>()
                    })
            })
        })
    };
    if names_klav(&v["deniedMcpServers"]) {
        out.block(format!("deniedMcpServers names klav ({source})"));
    }
    if v["allowedMcpServers"].is_array() && !names_klav(&v["allowedMcpServers"]) {
        out.block(format!("allowedMcpServers does not list klav ({source})"));
    }
}

/// `[mcp_servers]` of Codex's `requirements.toml`: an allow list by name
/// and command; empty, it turns MCP off.
fn codex_rules(text: &str, path: &Path, entry: &Entry, out: &mut Managed) {
    let Ok(table) = text.parse::<::toml::Table>() else {
        out.notes
            .push(format!("{} could not be read", path.display()));
        return;
    };
    let Some(servers) = table.get("mcp_servers") else {
        return;
    };
    let Some(servers) = servers.as_table() else {
        out.notes
            .push(format!("{}: mcp_servers is not a table", path.display()));
        return;
    };
    if servers.is_empty() {
        out.block(format!(
            "{} has an empty mcp_servers: MCP is off",
            path.display()
        ));
        return;
    }
    let Some(klav) = servers.get("klav") else {
        out.block(format!(
            "{} does not list klav in mcp_servers",
            path.display()
        ));
        return;
    };
    let command = klav
        .get("identity")
        .and_then(|i| i.get("command"))
        .or_else(|| klav.get("command"))
        .and_then(|c| c.as_str());
    if let Some(command) = command
        && command != entry.command
    {
        out.block(format!(
            "{} allows klav only with the command {command}",
            path.display()
        ));
    }
}

fn read(path: &Path) -> Option<String> {
    std::fs::read_to_string(path).ok()
}

fn unreadable(path: &Path) -> String {
    format!("{} exists but could not be read", path.display())
}

/// The managed preferences of `domain` (computer and user level), read
/// with `plutil` on macOS: `(path, contents)`, `None` when unreadable.
fn profiles(env: &Env, domain: &str) -> Vec<(PathBuf, Option<Value>)> {
    if !cfg!(target_os = "macos") {
        return Vec::new();
    }
    let dir = env.system("/Library/Managed Preferences");
    let user = std::env::var("USER").unwrap_or_default();
    [
        dir.join(format!("{domain}.plist")),
        dir.join(&user).join(format!("{domain}.plist")),
    ]
    .into_iter()
    .filter(|p| p.is_file())
    .map(|p| {
        let value = std::process::Command::new("/usr/bin/plutil")
            .args(["-convert", "json", "-o", "-"])
            .arg(&p)
            .stdin(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .output()
            .ok()
            .filter(|o| o.status.success())
            .and_then(|o| serde_json::from_slice(&o.stdout).ok());
        (p, value)
    })
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry() -> Entry {
        Entry {
            stdio_type: false,
            command: "/usr/local/bin/klav".into(),
            args: vec!["mcp".into(), "--agent".into(), "claude-code".into()],
            env: Vec::new(),
        }
    }

    #[test]
    fn claude_code_rules_block_klav() {
        let mut out = Managed::default();
        claude_code_rules(
            &serde_json::json!({"allowedMcpServers": [{"serverName": "github"}]}),
            "s",
            &entry(),
            &mut out,
        );
        assert!(out.blocked.expect("blocked").contains("does not list klav"));
        let mut out = Managed::default();
        claude_code_rules(
            &serde_json::json!({"allowedMcpServers": [{"serverName": "klav"}]}),
            "s",
            &entry(),
            &mut out,
        );
        assert!(out.blocked.is_none());
        let mut out = Managed::default();
        claude_code_rules(
            &serde_json::json!({"deniedMcpServers": [{"serverCommand": ["/usr/local/bin/klav", "mcp", "--agent", "claude-code"]}]}),
            "s",
            &entry(),
            &mut out,
        );
        assert!(out.blocked.expect("blocked").contains("deniedMcpServers"));
        let mut out = Managed::default();
        claude_code_rules(
            &serde_json::json!({"allowManagedMcpServersOnly": true}),
            "s",
            &entry(),
            &mut out,
        );
        assert!(out.blocked.is_some());
    }

    #[test]
    fn codex_requirements_allow_or_block_klav() {
        let path = Path::new("/etc/codex/requirements.toml");
        let mut out = Managed::default();
        codex_rules("[mcp_servers]\n", path, &entry(), &mut out);
        assert!(out.blocked.expect("blocked").contains("MCP is off"));
        let mut out = Managed::default();
        codex_rules(
            "[mcp_servers.docs]\nidentity = { command = \"docs\" }\n",
            path,
            &entry(),
            &mut out,
        );
        assert!(out.blocked.expect("blocked").contains("does not list klav"));
        let mut out = Managed::default();
        codex_rules(
            "[mcp_servers.klav]\nidentity = { command = \"/usr/local/bin/klav\" }\n",
            path,
            &entry(),
            &mut out,
        );
        assert!(out.blocked.is_none());
        let mut out = Managed::default();
        codex_rules(
            "[mcp_servers.klav]\nidentity = { command = \"/opt/klav\" }\n",
            path,
            &entry(),
            &mut out,
        );
        assert!(
            out.blocked
                .expect("blocked")
                .contains("only with the command")
        );
        let mut out = Managed::default();
        codex_rules("model = \"x\"\n", path, &entry(), &mut out);
        assert!(out.blocked.is_none() && out.notes.is_empty());
    }
}
