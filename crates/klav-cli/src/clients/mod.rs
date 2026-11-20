//! Agent clients (Claude Code, Claude Desktop, Codex, Cursor, VS Code):
//! where each keeps its MCP settings and skills, whether it is installed,
//! and whether an organization manages it (ADR 0033 §2).
//!
//! Everything comes from each client's documentation, checked on
//! [`CHECKED`]. When a client moves its files, this table changes; Klav
//! never guesses another place.
//!
//! Only the user level is touched: never a repository's `.mcp.json`,
//! `.cursor/`, `.vscode/` or `.codex/`, and never `AGENTS.md`, `CLAUDE.md`
//! or other instruction files of the person.

pub(crate) mod files;
pub(crate) mod json;
pub(crate) mod managed;
pub(crate) mod registry;
pub(crate) mod toml;

use std::path::{Path, PathBuf};

use clap::ValueEnum;
use serde::Serialize;

use crate::error::{CliResult, usage};

/// When the table below was last checked against each client's docs.
pub(crate) const CHECKED: &str = "2026-11-05";

/// Environment variable that moves every system path this module reads
/// (`/Applications`, `/Library`, `/etc`, `/usr/local/bin`, and the system
/// directories on `PATH`) under another root. Only for tests, which cannot
/// create files there and must not see the programs of the machine they run
/// on, and only in debug builds: a release `klav` always uses `/`, so nobody
/// can point it at a made-up `/usr/local/bin/klav` or hide a managed
/// configuration.
pub(crate) const SYSTEM_ROOT_ENV: &str = "KLAV_SYSTEM_ROOT";

/// The system's directories: Klav never writes under them, and
/// [`SYSTEM_ROOT_ENV`] moves them.
const SYSTEM_DIRS: [&str; 9] = [
    "/System",
    "/Library",
    "/usr",
    "/bin",
    "/sbin",
    "/etc",
    "/private/etc",
    "/opt",
    "/Applications",
];

/// The `klav` inside the Klav app (ADR 0033 §3.2).
pub(crate) const APP_KLAV: &str = "/Applications/Klav.app/Contents/Helpers/klav";

/// The user's and the system's directories this module looks at.
#[derive(Debug, Clone)]
pub(crate) struct Env {
    /// `$HOME`.
    pub(crate) home: PathBuf,
    /// `$CODEX_HOME`, else `~/.codex`.
    pub(crate) codex_home: PathBuf,
    /// `$CLAUDE_CONFIG_DIR`, where Claude Code keeps `.claude.json` and its
    /// skills when it is set (deduced from Claude Code's settings docs).
    pub(crate) claude_dir: Option<PathBuf>,
    /// `/`, or [`SYSTEM_ROOT_ENV`].
    root: PathBuf,
    /// `$PATH`.
    path: Option<std::ffi::OsString>,
}

impl Env {
    pub(crate) fn from_env() -> CliResult<Self> {
        let var = |name: &str| std::env::var_os(name).filter(|v| !v.is_empty());
        let home = var("HOME")
            .map(PathBuf::from)
            .ok_or_else(|| usage("HOME is not set"))?;
        let codex_home = var("CODEX_HOME").map_or_else(|| home.join(".codex"), PathBuf::from);
        Ok(Self {
            codex_home,
            claude_dir: var("CLAUDE_CONFIG_DIR").map(PathBuf::from),
            root: var(SYSTEM_ROOT_ENV)
                .filter(|_| cfg!(debug_assertions))
                .map_or_else(|| PathBuf::from("/"), PathBuf::from),
            path: var("PATH"),
            home,
        })
    }

    /// A system path (`/Applications/…`) under the root.
    pub(crate) fn system(&self, absolute: &str) -> PathBuf {
        self.root.join(absolute.trim_start_matches('/'))
    }

    /// Whether `path` is under a system directory, where Klav never writes.
    pub(crate) fn is_system(&self, path: &Path) -> bool {
        SYSTEM_DIRS
            .iter()
            .any(|dir| path.starts_with(self.system(dir)) || path.starts_with(dir))
            && !path.starts_with(&self.home)
    }

    /// A program on `PATH`. Its system directories (`/usr/bin`, `/bin`,
    /// `/opt/homebrew/bin`) are read under the root, like every other
    /// system path.
    pub(crate) fn which(&self, name: &str) -> Option<PathBuf> {
        let paths = self.path.as_ref()?;
        std::env::split_paths(paths)
            .map(|dir| self.path_dir(&dir).join(name))
            .find(|p| is_executable(p))
    }

    /// A `PATH` directory as [`Self::which`] reads it: a system one under
    /// the root, any other as it is. With the root at `/`, every directory
    /// is already under it and none moves.
    fn path_dir(&self, dir: &Path) -> PathBuf {
        let moves = SYSTEM_DIRS.iter().any(|d| dir.starts_with(d))
            && !dir.starts_with(&self.root)
            && !dir.starts_with(&self.home);
        match dir.strip_prefix("/") {
            Ok(relative) if moves => self.root.join(relative),
            _ => dir.to_path_buf(),
        }
    }

    /// An app bundle in `/Applications` or `~/Applications`.
    fn app(&self, bundle: &str) -> Option<PathBuf> {
        [
            self.system("/Applications").join(bundle),
            self.home.join("Applications").join(bundle),
        ]
        .into_iter()
        .find(|p| p.is_dir())
    }

    fn claude_dir(&self) -> PathBuf {
        self.claude_dir
            .clone()
            .unwrap_or_else(|| self.home.join(".claude"))
    }
}

fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

/// The clients Klav knows. Their names are also the names of their agents
/// (ADR 0033 §3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ClientId {
    ClaudeCode,
    ClaudeDesktop,
    Codex,
    Cursor,
    Vscode,
}

pub(crate) const ALL: [ClientId; 5] = [
    ClientId::ClaudeCode,
    ClientId::ClaudeDesktop,
    ClientId::Codex,
    ClientId::Cursor,
    ClientId::Vscode,
];

/// How a client's MCP settings are written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Format {
    /// JSON with the servers in the object `container`; `stdio_type` adds
    /// `"type": "stdio"` to the entry.
    Json {
        container: &'static str,
        stdio_type: bool,
    },
    /// TOML, `[mcp_servers.klav]`.
    Toml,
}

/// Where a client reads its skills from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SkillHome {
    /// `~/.claude/skills`.
    Claude,
    /// `~/.agents/skills`, shared by Codex, Cursor and VS Code.
    Agents,
    /// No folder: the skills live in the account (Claude Desktop).
    None,
}

impl ClientId {
    pub(crate) fn id(self) -> &'static str {
        match self {
            ClientId::ClaudeCode => "claude-code",
            ClientId::ClaudeDesktop => "claude-desktop",
            ClientId::Codex => "codex",
            ClientId::Cursor => "cursor",
            ClientId::Vscode => "vscode",
        }
    }

    pub(crate) fn from_id(id: &str) -> Option<Self> {
        ALL.into_iter().find(|c| c.id() == id)
    }

    pub(crate) fn name(self) -> &'static str {
        match self {
            ClientId::ClaudeCode => "Claude Code",
            ClientId::ClaudeDesktop => "Claude Desktop",
            ClientId::Codex => "Codex",
            ClientId::Cursor => "Cursor",
            ClientId::Vscode => "VS Code",
        }
    }

    pub(crate) fn format(self) -> Format {
        match self {
            ClientId::ClaudeCode | ClientId::ClaudeDesktop => Format::Json {
                container: "mcpServers",
                stdio_type: false,
            },
            ClientId::Cursor | ClientId::Vscode => Format::Json {
                container: "mcpServers",
                stdio_type: true,
            },
            ClientId::Codex => Format::Toml,
        }
    }

    /// The key Klav writes, as shown to the person.
    pub(crate) fn key(self) -> &'static str {
        match self.format() {
            Format::Json { .. } => "mcpServers.klav",
            Format::Toml => "mcp_servers.klav",
        }
    }

    /// The client's own command-line tool, which writes its settings when
    /// it is installed (ADR 0033 §3.6).
    pub(crate) fn cli(self) -> Option<&'static str> {
        match self {
            ClientId::ClaudeCode => Some("claude"),
            ClientId::Codex => Some("codex"),
            _ => None,
        }
    }

    /// Klav writes this client only through its CLI: the client rewrites
    /// its own file (`~/.claude.json`), and editing it from outside would
    /// race with it.
    pub(crate) fn cli_only(self) -> bool {
        self == ClientId::ClaudeCode
    }

    /// The client has to be restarted to see a new entry.
    pub(crate) fn needs_restart(self) -> bool {
        self == ClientId::ClaudeDesktop
    }

    pub(crate) fn skill_home(self) -> SkillHome {
        match self {
            ClientId::ClaudeCode => SkillHome::Claude,
            ClientId::ClaudeDesktop => SkillHome::None,
            ClientId::Codex | ClientId::Cursor | ClientId::Vscode => SkillHome::Agents,
        }
    }

    /// The user-level MCP settings file; `None` where the client does not
    /// exist (Claude Desktop outside macOS).
    pub(crate) fn config_path(self, env: &Env) -> Option<PathBuf> {
        match self {
            ClientId::ClaudeCode => Some(
                env.claude_dir
                    .as_ref()
                    .map_or_else(|| env.home.join(".claude.json"), |d| d.join(".claude.json")),
            ),
            ClientId::ClaudeDesktop if cfg!(target_os = "macos") => Some(
                env.home
                    .join("Library/Application Support/Claude/claude_desktop_config.json"),
            ),
            ClientId::ClaudeDesktop => None,
            ClientId::Codex => Some(env.codex_home.join("config.toml")),
            ClientId::Cursor => Some(env.home.join(".cursor/mcp.json")),
            // The portable format, the one VS Code's guided flow writes. VS
            // Code's own `mcp.json` (now «deprecated») is not written.
            ClientId::Vscode => Some(env.home.join(".copilot/mcp-config.json")),
        }
    }

    /// The skills folder (`…/skills`, which holds `klav/SKILL.md`).
    pub(crate) fn skills_dir(self, env: &Env) -> Option<PathBuf> {
        skills_dir(self.skill_home(), env)
    }

    /// What says the client is installed, if anything.
    pub(crate) fn installed(self, env: &Env) -> Option<String> {
        let found = |p: PathBuf| p.exists().then(|| p.display().to_string());
        match self {
            ClientId::ClaudeCode => env
                .which("claude")
                .map(|p| p.display().to_string())
                .or_else(|| found(env.claude_dir())),
            ClientId::ClaudeDesktop if cfg!(target_os = "macos") => env
                .app("Claude.app")
                .map(|p| p.display().to_string())
                .or_else(|| found(env.home.join("Library/Application Support/Claude"))),
            ClientId::ClaudeDesktop => None,
            ClientId::Codex => env
                .which("codex")
                .map(|p| p.display().to_string())
                .or_else(|| env.app("Codex.app").map(|p| p.display().to_string()))
                .or_else(|| found(env.codex_home.clone())),
            ClientId::Cursor => env
                .app("Cursor.app")
                .map(|p| p.display().to_string())
                .or_else(|| env.which("cursor").map(|p| p.display().to_string()))
                .or_else(|| found(env.home.join(".cursor"))),
            ClientId::Vscode => env
                .app("Visual Studio Code.app")
                .map(|p| p.display().to_string())
                .or_else(|| env.which("code").map(|p| p.display().to_string())),
        }
    }
}

/// The skills folder of a [`SkillHome`].
pub(crate) fn skills_dir(home: SkillHome, env: &Env) -> Option<PathBuf> {
    match home {
        SkillHome::Claude => Some(env.claude_dir().join("skills")),
        SkillHome::Agents => Some(env.home.join(".agents/skills")),
        SkillHome::None => None,
    }
}

/// Every folder where a `klav` skill may sit, Klav's or not: the two Klav
/// writes, and those some clients also read (`~/.cursor/skills`,
/// `~/.copilot/skills`) or used to (`~/.codex/skills`).
pub(crate) fn known_skill_dirs(env: &Env) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = [SkillHome::Claude, SkillHome::Agents]
        .into_iter()
        .filter_map(|h| skills_dir(h, env))
        .collect();
    for extra in [
        env.codex_home.join("skills"),
        env.home.join(".cursor/skills"),
        env.home.join(".copilot/skills"),
    ] {
        if !dirs.contains(&extra) {
            dirs.push(extra);
        }
    }
    dirs
}

/// The `klav` entry Klav writes (ADR 0033 §3.2): an absolute command, the
/// agent in `args`, and never a key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Entry {
    /// `"type": "stdio"`, where the format asks for it.
    pub(crate) stdio_type: bool,
    pub(crate) command: String,
    pub(crate) args: Vec<String>,
    /// Only `KLAV_HOME`, when it is not the default one: without it the
    /// client would start `klav mcp` on another state directory.
    pub(crate) env: Vec<(String, String)>,
}

/// Environment variables of a `klav` entry whose values are shown: they
/// name a directory or an agent, never a secret.
const SHOWN_ENV: [&str; 3] = ["KLAV_HOME", "KLAV_AGENT", "KLAV_BROWSER_HOME"];

impl Entry {
    /// The entry for `client` with this command and agent.
    pub(crate) fn new(client: ClientId, command: &Path, agent: &str, home: Option<&Path>) -> Self {
        Self {
            stdio_type: matches!(
                client.format(),
                Format::Json {
                    stdio_type: true,
                    ..
                }
            ),
            command: command.display().to_string(),
            args: vec!["mcp".into(), "--agent".into(), agent.into()],
            env: home
                .map(|h| vec![("KLAV_HOME".to_owned(), h.display().to_string())])
                .unwrap_or_default(),
        }
    }

    /// As JSON (keys sorted), for hashing and showing.
    pub(crate) fn to_value(&self) -> serde_json::Value {
        let mut out = serde_json::json!({ "command": self.command, "args": self.args });
        if self.stdio_type {
            out["type"] = "stdio".into();
        }
        if !self.env.is_empty() {
            out["env"] = self
                .env
                .iter()
                .map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone())))
                .collect::<serde_json::Map<_, _>>()
                .into();
        }
        out
    }

    /// Whether `found` (an entry read back) runs the same command: same
    /// command, arguments and variables of ours. A `type` of `stdio` and an
    /// empty `env` that a client's CLI adds are fine.
    pub(crate) fn matches(&self, found: &serde_json::Value) -> bool {
        let strings = |v: &serde_json::Value| -> Option<Vec<String>> {
            v.as_array()?
                .iter()
                .map(|a| a.as_str().map(str::to_owned))
                .collect()
        };
        if found["command"].as_str() != Some(self.command.as_str())
            || strings(&found["args"]).as_deref() != Some(self.args.as_slice())
        {
            return false;
        }
        if let Some(kind) = found.get("type")
            && kind.as_str() != Some("stdio")
        {
            return false;
        }
        let env = found.get("env").and_then(serde_json::Value::as_object);
        let count = env.map_or(0, serde_json::Map::len);
        count == self.env.len()
            && self
                .env
                .iter()
                .all(|(k, v)| env.and_then(|e| e.get(k)).and_then(|x| x.as_str()) == Some(v))
    }
}

impl Entry {
    /// `value` as an entry Klav would write, if it has that shape: a
    /// `command`, string `args`, at most `"type": "stdio"`, an `env` with
    /// nothing but `KLAV_HOME`, and nothing that [`shown_entry`] hides.
    /// Anything else (another variable, `headers`, a `url`, an argument
    /// that is not `klav mcp`'s, like `sh -c "TOKEN=… klav mcp"`) may carry
    /// a key: Klav does not adopt such an entry, print it as a command line
    /// or pass it to a client's CLI.
    pub(crate) fn from_value(client: ClientId, value: &serde_json::Value) -> Option<Self> {
        if shown_entry(value) != *value {
            return None;
        }
        let object = value.as_object()?;
        if object
            .keys()
            .any(|k| !["type", "command", "args", "env"].contains(&k.as_str()))
        {
            return None;
        }
        if let Some(kind) = object.get("type")
            && kind.as_str() != Some("stdio")
        {
            return None;
        }
        let command = object.get("command")?.as_str()?.to_owned();
        let args = match object.get("args") {
            None => Vec::new(),
            Some(a) => a
                .as_array()?
                .iter()
                .map(|x| x.as_str().map(str::to_owned))
                .collect::<Option<Vec<_>>>()?,
        };
        let mut env = Vec::new();
        if let Some(vars) = object.get("env") {
            for (k, v) in vars.as_object()? {
                if k != "KLAV_HOME" {
                    return None;
                }
                env.push((k.clone(), v.as_str()?.to_owned()));
            }
        }
        let mut out = Self::new(client, Path::new(&command), "", None);
        out.command = command;
        out.args = args;
        out.env = env;
        Some(out)
    }
}

/// SHA-256 of an entry as read (compact JSON, keys sorted).
pub(crate) fn entry_sha256(value: &serde_json::Value) -> String {
    crate::skill::sha256(&serde_json::to_vec(value).unwrap_or_default())
}

/// SHA-256 of the `klav` member, or of its absence: what a client written
/// with its own CLI is compared by (ADR 0033 §3.6). The CLI client rewrites
/// the rest of its file for itself.
pub(crate) fn member_sha256(value: Option<&serde_json::Value>) -> String {
    entry_sha256(value.unwrap_or(&serde_json::Value::Null))
}

/// What stands for a hidden value.
const HIDDEN: &str = "••••••••";

/// Arguments of `klav mcp` whose values are shown, when they look like
/// what `klav mcp` takes: an agent name, a duration.
const SHOWN_FLAGS: [&str; 2] = ["--agent", "--wait"];

/// Whether `value`, after `flag`, looks like what `klav mcp` takes there.
fn shown_flag_value(flag: &str, value: &str) -> bool {
    match flag {
        "--agent" => klav_sdk::config::validate_name(value).is_ok(),
        "--wait" => crate::cli::parse_duration(value).is_ok(),
        _ => false,
    }
}

/// An entry to show the person: only Klav's member, and in it only what
/// cannot be a secret (an entry put there by hand may carry one). Shown:
/// `type`, `command`, the arguments of `klav mcp`, the names of `env` and
/// `headers` with the values of [`SHOWN_ENV`], a URL's scheme and host, and
/// numbers and booleans. Every other value is hidden.
pub(crate) fn shown_entry(value: &serde_json::Value) -> serde_json::Value {
    use serde_json::Value;
    let Some(object) = value.as_object() else {
        return hidden(value);
    };
    let shown = object.iter().map(|(key, v)| {
        let v = match key.as_str() {
            "type" if v.is_string() => v.clone(),
            "command" if v.as_str().is_some_and(shown_command) => v.clone(),
            "args" => shown_args(v),
            "env" | "headers" => match v.as_object() {
                Some(vars) => Value::Object(
                    vars.iter()
                        .map(|(k, x)| {
                            let keep = key == "env" && SHOWN_ENV.contains(&k.as_str());
                            (k.clone(), if keep { x.clone() } else { hidden(x) })
                        })
                        .collect(),
                ),
                None => hidden(v),
            },
            "url" => v
                .as_str()
                .map_or_else(|| hidden(v), |u| Value::String(shown_url(u))),
            _ => hidden(v),
        };
        (key.clone(), v)
    });
    Value::Object(shown.collect())
}

/// Whether a `command` is shown: what Klav writes. A command edited by
/// hand like `TOKEN=ghp_… /usr/local/bin/klav`, or a bare word, may carry
/// a key, so it is hidden, and then the entry is not one Klav prints,
/// adopts or passes to a client's CLI ([`Entry::from_value`]).
fn shown_command(command: &str) -> bool {
    command_shown(command, own_command().ok())
}

/// [`shown_command`], with `own` the command of this `klav`
/// ([`own_command`]): an absolute path with no white space and no `=`, or
/// exactly `own`, which may have spaces (`/Applications/Klav 2.app/…`).
fn command_shown(command: &str, own: Option<&Path>) -> bool {
    (command.starts_with('/') && !command.chars().any(|c| c.is_whitespace() || c == '='))
        || own.is_some_and(|own| {
            own.is_absolute() && own.as_os_str() == std::ffi::OsStr::new(command)
        })
}

/// This `klav` as an entry names it when it is not the app's root-owned
/// link: the running executable, canonical (`klav client connect` writes
/// it, and [`shown_command`] recognizes it).
pub(crate) fn own_command() -> Result<&'static Path, String> {
    static OWN: std::sync::OnceLock<Result<PathBuf, String>> = std::sync::OnceLock::new();
    OWN.get_or_init(|| {
        let exe = std::env::current_exe()
            .map(crate::mcp::live_exe)
            .map_err(|e| e.to_string())?;
        Ok(std::fs::canonicalize(&exe).unwrap_or(exe))
    })
    .as_deref()
    .map_err(Clone::clone)
}

/// A value hidden: strings, arrays and objects; numbers, booleans and
/// `null` say nothing secret.
fn hidden(value: &serde_json::Value) -> serde_json::Value {
    use serde_json::Value;
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) => value.clone(),
        _ => HIDDEN.into(),
    }
}

/// `args`, with only `klav mcp`'s own arguments shown.
fn shown_args(value: &serde_json::Value) -> serde_json::Value {
    use serde_json::Value;
    let Some(args) = value.as_array() else {
        return hidden(value);
    };
    let mut out = Vec::with_capacity(args.len());
    let mut after: Option<&str> = None;
    for arg in args {
        let shown = arg.as_str().is_some_and(|a| {
            after.is_some_and(|flag| shown_flag_value(flag, a))
                || a == "mcp"
                || SHOWN_FLAGS.contains(&a)
                || SHOWN_FLAGS.iter().any(|f| {
                    a.strip_prefix(f)
                        .and_then(|r| r.strip_prefix('='))
                        .is_some_and(|v| shown_flag_value(f, v))
                })
        });
        after = arg
            .as_str()
            .and_then(|a| SHOWN_FLAGS.iter().copied().find(|f| *f == a));
        out.push(if shown { arg.clone() } else { hidden(arg) });
    }
    Value::Array(out)
}

/// A URL with only its scheme and host: user names, passwords, paths and
/// queries often hold a token. The host is shown only when Klav can tell
/// it apart: after the last `@`, before the first `/`, `?` or `#`, and
/// made of the characters a host name or address has. A `@` after one of
/// those (a password with a `?` or `/` in it, or a `@` in the path) leaves
/// it unclear where the host is, so only the scheme is shown.
fn shown_url(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return HIDDEN.into();
    };
    let scheme_ok = scheme
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic())
        && scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'));
    if !scheme_ok {
        return HIDDEN.into();
    }
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (user, host_and_tail) = match rest.rfind('@') {
        Some(at) if at > end => return format!("{scheme}://{HIDDEN}"),
        Some(at) => (true, &rest[at + 1..]),
        None => (false, rest),
    };
    let (host, tail) = host_and_tail.split_at(
        host_and_tail
            .find(['/', '?', '#'])
            .unwrap_or(host_and_tail.len()),
    );
    let host_ok = !host.is_empty()
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']'));
    let host = if host_ok { host } else { HIDDEN };
    let user = if user {
        format!("{HIDDEN}@")
    } else {
        String::new()
    };
    let tail = if tail.is_empty() || tail == "/" {
        tail.to_owned()
    } else {
        format!("/{HIDDEN}")
    };
    format!("{scheme}://{user}{host}{tail}")
}

/// The command of an entry, if it has one.
pub(crate) fn entry_command(value: &serde_json::Value) -> Option<&str> {
    value["command"].as_str()
}

/// A settings file Klav could not parse: where, never what.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct Malformed {
    pub(crate) line: usize,
    pub(crate) column: usize,
    pub(crate) problem: String,
}

impl std::fmt::Display for Malformed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} at line {}, column {}",
            self.problem, self.line, self.column
        )
    }
}

/// 1-based line and column of byte `offset` in `text`.
pub(crate) fn line_column(text: &str, offset: usize) -> (usize, usize) {
    let before = &text[..offset.min(text.len())];
    let line = before.matches('\n').count() + 1;
    let column = before.rsplit('\n').next().map_or(0, |l| l.chars().count()) + 1;
    (line, column)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn shown_entries_hide_whatever_may_be_a_secret() {
        let entry = json!({
            "type": "stdio",
            "command": "/usr/local/bin/klav",
            "args": ["mcp", "--agent", "cursor", "--token", "sk-1", "--wait=60s"],
            "env": { "KLAV_HOME": "/k", "API_KEY": "sk-2" },
            "headers": { "Authorization": "Bearer sk-3" },
            "url": "https://user:sk-4@mcp.example.com/sk-5/mcp?key=sk-6",
            "token": "sk-7",
            "nested": { "a": "sk-8" },
            "list": ["sk-9"],
            "disabled": false,
            "timeout": 30
        });
        let shown = shown_entry(&entry);
        let text = shown.to_string();
        for n in 1..=9 {
            assert!(!text.contains(&format!("sk-{n}")), "sk-{n}: {text}");
        }
        assert_eq!(shown["command"], "/usr/local/bin/klav");
        assert_eq!(
            shown["args"],
            json!(["mcp", "--agent", "cursor", HIDDEN, HIDDEN, "--wait=60s"])
        );
        assert_eq!(shown["env"]["KLAV_HOME"], "/k");
        assert_eq!(shown["env"]["API_KEY"], HIDDEN);
        assert_eq!(shown["headers"]["Authorization"], HIDDEN);
        assert_eq!(
            shown["url"],
            format!("https://{HIDDEN}@mcp.example.com/{HIDDEN}")
        );
        assert_eq!(shown["disabled"], false);
        assert_eq!(shown["timeout"], 30);
        assert_eq!(
            shown_url("https://mcp.example.com/"),
            "https://mcp.example.com/"
        );
        assert_eq!(shown_url("sk-10"), HIDDEN);
        // A command edited by hand is hidden whole (#205's re-review).
        for command in [
            "GITHUB_TOKEN=sk-11 /usr/local/bin/klav",
            "sk-12",
            "/k --key sk-13",
        ] {
            let shown = shown_entry(&json!({ "command": command }));
            assert_eq!(shown["command"], HIDDEN, "{command}");
        }
    }

    #[test]
    fn this_klavs_own_path_is_shown_even_with_spaces() {
        let own = Path::new("/Applications/Klav 2.app/Contents/Helpers/klav");
        let command = "/Applications/Klav 2.app/Contents/Helpers/klav";
        assert!(command_shown(command, Some(own)));
        // Another klav's path with spaces is not recognized.
        assert!(!command_shown(command, None));
        assert!(!command_shown(
            command,
            Some(Path::new("/Applications/Klav.app/Contents/Helpers/klav"))
        ));
        // Only that very path: anything around it stays hidden.
        for edited in [
            "TOKEN=sk-1 /Applications/Klav 2.app/Contents/Helpers/klav",
            "/Applications/Klav 2.app/Contents/Helpers/klav --key sk-2",
            "/Applications/Klav 2.app/Contents/Helpers/klav ",
            "/Applications/Klav 2.app/Contents/Helpers/klav/",
        ] {
            assert!(!command_shown(edited, Some(own)), "{edited}");
        }
        assert!(command_shown("/usr/local/bin/klav", Some(own)));
        // What `klav client connect` writes for this klav, shown (and so
        // adoptable).
        let mine = own_command().expect("this klav");
        let mine = mine.to_str().expect("utf-8");
        let entry = json!({ "command": mine, "args": ["mcp", "--agent", "cursor"] });
        assert_eq!(shown_entry(&entry), entry);
        assert!(Entry::from_value(ClientId::Cursor, &entry).is_some());
    }

    #[test]
    fn urls_show_a_host_only_when_it_is_clearly_one() {
        // A password with `?`, `#` or `/`: the last `@` is past the first
        // of those, so where the host starts is unclear.
        for url in [
            "https://bob:hunter2?xyz@mcp.example.com/path",
            "https://bob:hunter2#xyz@mcp.example.com",
            "https://bob:hun/ter2@mcp.example.com",
            "https://mcp.example.com/users/@hunter2",
        ] {
            let shown = shown_url(url);
            assert_eq!(shown, format!("https://{HIDDEN}"), "{url}");
            assert!(!shown.contains("hunter2") && !shown.contains("bob"));
        }
        assert_eq!(
            shown_url("https://bob:a@b@mcp.example.com"),
            format!("https://{HIDDEN}@mcp.example.com")
        );
        assert_eq!(shown_url("http://[::1]:8080/"), "http://[::1]:8080/");
        // A host with characters no host has, or a scheme that is not one.
        assert_eq!(
            shown_url("https://hunter2!x/"),
            format!("https://{HIDDEN}/")
        );
        assert_eq!(shown_url("hun ter2://mcp.example.com"), HIDDEN);
    }

    #[test]
    fn flag_values_are_shown_only_when_they_look_like_klav_mcps() {
        let shown = shown_args(&json!([
            "mcp",
            "--agent",
            "GITHUB_TOKEN=ghp_1",
            "--agent=ghp 2",
            "--wait",
            "ghp_3",
            "--wait=ghp_4",
            "--agent",
            "cursor",
            "--wait",
            "90s"
        ]));
        assert_eq!(
            shown,
            json!([
                "mcp", "--agent", HIDDEN, HIDDEN, "--wait", HIDDEN, HIDDEN, "--agent", "cursor",
                "--wait", "90s"
            ])
        );
    }

    #[test]
    fn only_klav_shaped_entries_come_back_as_entries() {
        let ours = json!({
            "type": "stdio",
            "command": "/k",
            "args": ["mcp", "--agent", "x"],
            "env": { "KLAV_HOME": "/h" }
        });
        let entry = Entry::from_value(ClientId::Cursor, &ours).expect("ours");
        assert!(entry.matches(&ours));
        assert_eq!(entry.env, vec![("KLAV_HOME".to_owned(), "/h".to_owned())]);
        let bare = json!({ "command": "/k", "args": ["mcp"], "env": {} });
        assert!(Entry::from_value(ClientId::ClaudeCode, &bare).is_some());
        for theirs in [
            json!({ "command": "/k", "env": { "KLAV_AGENT_KEY": "x" } }),
            json!({ "command": "/k", "headers": {} }),
            json!({ "type": "http", "url": "https://x" }),
            json!({ "command": "/k", "args": [1] }),
            json!("/k"),
            // Arguments that are not `klav mcp`'s: shown hidden, so not an
            // entry Klav prints or passes to a client's CLI.
            json!({ "command": "/bin/sh", "args": ["-c", "GITHUB_TOKEN=ghp_x exec klav mcp"] }),
            json!({ "command": "/k", "args": ["mcp", "--agent", "TOKEN=ghp_x"] }),
            // A command edited by hand: a variable before the path, white
            // space, or not a path at all. Hidden, so not an entry.
            json!({ "command": "TOKEN=ghp_x /usr/local/bin/klav", "args": ["mcp"] }),
            json!({ "command": "/usr/local/bin/klav --token ghp_x", "args": ["mcp"] }),
            json!({ "command": "/opt/x=ghp_x/klav", "args": ["mcp"] }),
            json!({ "command": "klav", "args": ["mcp"] }),
            json!({ "command": "ghp_x", "args": ["mcp"] }),
        ] {
            assert!(
                Entry::from_value(ClientId::Cursor, &theirs).is_none(),
                "{theirs}"
            );
        }
    }

    #[test]
    fn system_directories_on_path_are_read_under_the_root() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let own = dir.path().join("bin");
        let env = Env {
            home: dir.path().join("home"),
            codex_home: dir.path().join("home/.codex"),
            claude_dir: None,
            root: dir.path().join("system"),
            path: Some(
                std::env::join_paths([Path::new("/usr/bin"), Path::new("/bin"), &own])
                    .expect("PATH"),
            ),
        };
        // Every machine has a `/bin/sh`; under the root there is none.
        assert_eq!(env.which("sh"), None);
        // A program in the made-up `/usr/bin`, and one in a directory that
        // is not the system's.
        for (dir, name) in [(env.system("/usr/bin"), "code"), (own, "codex")] {
            std::fs::create_dir_all(&dir).expect("mkdir");
            let program = dir.join(name);
            std::fs::write(&program, "#!/bin/sh\n").expect("write");
            std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755))
                .expect("chmod");
            assert_eq!(env.which(name), Some(program));
        }
        // With the root at `/`, as in a release build, `PATH` is read as
        // it is.
        let real = Env {
            root: PathBuf::from("/"),
            ..env
        };
        let sh = real.which("sh").expect("sh");
        assert!(
            sh == Path::new("/usr/bin/sh") || sh == Path::new("/bin/sh"),
            "{sh:?}"
        );
    }
}
