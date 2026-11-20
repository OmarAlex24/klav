//! `klav client list | connect | disconnect | restore` (ADR 0033 §1–§5):
//! the `klav` entry and the skill of each agent client.
//!
//! Nothing of a client's file is ever shown but Klav's own entry: the other
//! servers often carry API keys in their `env`.

use std::io::{BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};

use klav_client::{ClientError, Home};
use klav_proto::agent::AgentStatus;
use klav_sdk::{Agent, KeyStore, KeyStoreChoice, Registration};
use serde::Serialize;
use serde_json::{Value, json};

use crate::cli::{
    ClientCommand, ClientConnectArgs, ClientDisconnectArgs, ClientRestoreArgs, JsonFlag,
    KeyStoreArg,
};
use crate::clients::files::{self, Target};
use crate::clients::managed::{self, Managed};
use crate::clients::registry::{ClientRecord, Method, Registry};
use crate::clients::{self, ALL, ClientId, Entry, Env, Format, Malformed};
use crate::context::Ctx;
use crate::error::{CliError, CliResult, usage};
use crate::output;
use crate::skill::{self, CopyState};

/// Longest a client's CLI may take.
const TOOL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

pub(crate) async fn client_cmd(ctx: &mut Ctx, cmd: ClientCommand) -> CliResult<()> {
    match cmd {
        ClientCommand::List(flag) => list(ctx, &flag),
        ClientCommand::Connect(args) => connect(ctx, args).await,
        ClientCommand::Disconnect(args) => disconnect(ctx, &args),
        ClientCommand::Restore(args) => restore(ctx, &args),
    }
}

// ------------------------------------------------------------ the command

/// The `klav` this entry runs, and what the person should know about it.
struct KlavCommand {
    path: PathBuf,
    warning: Option<String>,
}

/// The absolute command of the entry (ADR 0033 §3.2): the app's
/// root-owned link when this `klav` is the app's, else this `klav`.
fn klav_command(env: &Env) -> CliResult<KlavCommand> {
    // The same path `shown_command` recognizes as Klav's, spaces and all.
    let exe = clients::own_command()
        .map_err(|e| CliError::Other(format!("cannot find this klav: {e}")))?
        .to_path_buf();
    let in_bundle = exe
        .parent()
        .filter(|d| d.ends_with("Contents/Helpers"))
        .and_then(|d| d.parent()?.parent())
        .is_some_and(|app| app.extension().is_some_and(|e| e == "app"));
    if in_bundle {
        let link = env.system("/usr/local/bin/klav");
        if link_is_ours(&link, &exe) {
            return Ok(KlavCommand {
                path: link,
                warning: None,
            });
        }
        return Ok(KlavCommand {
            path: exe,
            warning: None,
        });
    }
    let writable = exe
        .parent()
        .is_some_and(|d| nix::unistd::access(d, nix::unistd::AccessFlags::W_OK).is_ok());
    let warning = writable.then(|| {
        format!(
            "the entry runs {}, in a folder your user can write: another program running as you could replace it. The Klav app installs a link owned by root instead",
            exe.display()
        )
    });
    Ok(KlavCommand { path: exe, warning })
}

/// `/usr/local/bin/klav` is the app's link: owned by root and pointing at
/// this `klav` (ADR 0027 §4).
fn link_is_ours(link: &Path, exe: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    std::fs::symlink_metadata(link).is_ok_and(|m| m.file_type().is_symlink() && m.uid() == 0)
        && std::fs::canonicalize(link).is_ok_and(|p| p == exe)
}

/// `KLAV_HOME`, absolute, when it is not the default one: the client
/// starts `klav mcp` without the person's environment, and from another
/// working directory.
fn home_for_entry(home: &Home, env: &Env) -> CliResult<Option<PathBuf>> {
    if std::env::var_os(klav_client::home::HOME_ENV)
        .filter(|v| !v.is_empty())
        .is_none()
    {
        return Ok(None);
    }
    let dir = std::path::absolute(home.dir())
        .map_err(|e| CliError::Other(format!("KLAV_HOME {}: {e}", home.dir().display())))?;
    // Where `Home::from_env` looks without `KLAV_HOME`.
    let default = if cfg!(target_os = "macos") {
        env.home.join("Library/Application Support/klav")
    } else {
        std::env::var_os("XDG_CONFIG_HOME")
            .filter(|d| !d.is_empty())
            .map_or_else(|| env.home.join(".config"), PathBuf::from)
            .join("klav")
    };
    Ok((dir != default).then_some(dir))
}

// ------------------------------------------------------------- the state

/// What a settings file holds.
struct Settings {
    target: Target,
    /// `None`: the file does not exist.
    text: Option<String>,
    /// SHA-256 of the file as read.
    sha256: Option<String>,
    /// The `klav` entry, or why the file could not be read.
    entry: Result<Option<Value>, Malformed>,
}

fn read_settings(client: ClientId, path: &Path) -> CliResult<Settings> {
    let target = Target::resolve(path)?;
    let bytes = target.read()?;
    let sha256 = bytes.as_deref().map(skill::sha256);
    let text = match bytes {
        None => None,
        Some(b) => Some(String::from_utf8(b).map_err(|_| {
            CliError::Other(format!("{} is not UTF-8 text", target.real.display()))
        })?),
    };
    let entry = match &text {
        None => Ok(None),
        Some(t) => parse_entry(client, t),
    };
    Ok(Settings {
        target,
        text,
        sha256,
        entry,
    })
}

fn parse_entry(client: ClientId, text: &str) -> Result<Option<Value>, Malformed> {
    match client.format() {
        Format::Json { container, .. } => clients::json::entry(text, container),
        Format::Toml => clients::toml::entry(text),
    }
}

/// Whose the `klav` entry is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Owner {
    /// There is none.
    None,
    /// Klav wrote it and it did not change.
    Klav,
    /// Klav wrote it and it changed since.
    Changed,
    /// Klav did not write it (or does not remember doing so): the person's.
    Person,
}

fn owner(entry: Option<&Value>, record: Option<&ClientRecord>) -> Owner {
    match (entry, record) {
        (None, _) => Owner::None,
        (Some(v), Some(r)) if clients::entry_sha256(v) == r.entry_sha256 => Owner::Klav,
        (Some(_), Some(_)) => Owner::Changed,
        (Some(_), None) => Owner::Person,
    }
}

/// Whether an entry's command looks like a `klav` program (for «Adopt»).
fn runs_klav(entry: &Value) -> bool {
    clients::entry_command(entry)
        .map(Path::new)
        .is_some_and(|p| {
            p.file_name().is_some_and(|n| n == "klav") && p.is_absolute() && p.is_file()
        })
}

/// Whether a command is this `klav`, the app's link or the `klav` of the
/// app in `/Applications` (ADR 0033 §4, T131): anything else is shown in
/// red by the app. A `Klav.app` elsewhere (`~/Downloads`) is not trusted by
/// its name; when the app itself runs this `klav`, `ours` is its path.
/// `/usr/local/bin/klav` counts only when it is the app's link (owned by
/// root and pointing at this `klav` or the app's), never by its path: a
/// file or link the user put there could run anything. This is a check of
/// the path alone: nobody checks the signature of the program the entry
/// runs. The app shows `unknown_command` in red at launch and in Clients
/// (ADR 0033 §4, T131); checking that signature is left for later (ADR
/// 0033, «En código» of layer 5).
fn command_is_known(entry: &Value, ours: &Path, env: &Env) -> bool {
    let Some(command) = clients::entry_command(entry).map(Path::new) else {
        return false;
    };
    let link = env.system("/usr/local/bin/klav");
    let app = env.system(clients::APP_KLAV);
    command == ours
        || command == app
        || (command == link
            && (link_is_ours(&link, ours)
                || std::fs::canonicalize(&app).is_ok_and(|app| link_is_ours(&link, &app))))
}

// ----------------------------------------------------------------- list

#[derive(Serialize)]
struct ClientRow {
    id: ClientId,
    name: &'static str,
    /// `unavailable`, `not_installed`, `managed`, `malformed`,
    /// `not_connected`, `connected`, `changed` or `person`.
    state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    installed: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    config: Option<ConfigView>,
    /// How Klav writes it: `cli` or `file` (`null` when it cannot).
    method: Option<Method>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cli: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    entry: Option<Value>,
    /// The entry runs a `klav` other than the app's link or bundle, or
    /// this one (shown in red).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    unknown_command: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    agent: Option<AgentView>,
    managed: Managed,
    restart_required: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    skills_dir: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    note: Option<String>,
}

#[derive(Serialize)]
struct ConfigView {
    path: PathBuf,
    exists: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    link_to: Option<PathBuf>,
    key: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    malformed: Option<Malformed>,
}

#[derive(Serialize)]
struct AgentView {
    name: String,
    /// Whether this `KLAV_HOME` has it (`agents/<name>.json`).
    registered_here: bool,
}

fn list(ctx: &Ctx, flag: &JsonFlag) -> CliResult<()> {
    let env = Env::from_env()?;
    let registry = Registry::load(&ctx.home)?;
    let command = klav_command(&env)?;
    let rows: Vec<ClientRow> = ALL
        .into_iter()
        .map(|c| row(c, &env, &ctx.home, &registry, &command.path))
        .collect();
    if flag.json {
        return output::json(&json!({ "checked": clients::CHECKED, "clients": rows }));
    }
    output::table(
        &["CLIENT", "STATE", "AGENT", "SETTINGS"],
        &rows
            .iter()
            .map(|r| {
                vec![
                    r.id.id().to_owned(),
                    r.state.replace('_', " "),
                    r.agent.as_ref().map(|a| a.name.clone()).unwrap_or_default(),
                    r.config
                        .as_ref()
                        .map(|c| c.path.display().to_string())
                        .unwrap_or_default(),
                ]
            })
            .collect::<Vec<_>>(),
    );
    for r in &rows {
        if let Some(rule) = &r.managed.blocked {
            output::info(&format!(
                "{}: your organization manages its MCP servers: {rule}",
                r.name
            ));
        }
        if r.unknown_command {
            output::warn(&format!(
                "{}: the klav entry runs a program that is not this Klav's: check it",
                r.name
            ));
        }
        if let Some(note) = &r.note {
            output::info(&format!("{}: {note}", r.name));
        }
    }
    Ok(())
}

fn row(client: ClientId, env: &Env, home: &Home, registry: &Registry, ours: &Path) -> ClientRow {
    let record = registry.clients.get(client.id());
    let mut out = ClientRow {
        id: client,
        name: client.name(),
        state: "unavailable",
        installed: client.installed(env),
        config: None,
        method: None,
        cli: client.cli().and_then(|c| env.which(c)),
        entry: None,
        unknown_command: false,
        agent: None,
        managed: Managed::default(),
        restart_required: client.needs_restart(),
        skills_dir: client.skills_dir(env),
        note: None,
    };
    let Some(path) = client.config_path(env) else {
        out.note = Some("not available on this system".into());
        return out;
    };
    out.method = match (&out.cli, client.cli_only()) {
        (Some(_), _) => Some(Method::Cli),
        (None, true) => None,
        (None, false) => Some(Method::File),
    };
    let settings = match read_settings(client, &path) {
        Ok(s) => s,
        Err(e) => {
            out.state = "malformed";
            out.note = e.message();
            out.config = Some(ConfigView {
                path,
                exists: true,
                link_to: None,
                key: client.key(),
                malformed: None,
            });
            return out;
        }
    };
    let agent_name = record.map_or_else(|| client.id().to_owned(), |r| r.agent.clone());
    out.agent = Some(AgentView {
        registered_here: klav_sdk::config::AgentConfig::exists(home, &agent_name),
        name: agent_name.clone(),
    });
    out.config = Some(ConfigView {
        path,
        exists: settings.text.is_some(),
        link_to: settings.target.link.clone(),
        key: client.key(),
        malformed: settings.entry.as_ref().err().cloned(),
    });
    let entry_for = Entry::new(client, ours, &agent_name, None);
    out.managed = managed::check(client, env, &entry_for);
    if out.method.is_none() {
        out.note = Some(format!(
            "Klav writes {} only with its `{}` command, which is not in PATH",
            client.name(),
            client.cli().unwrap_or_default()
        ));
    }
    out.state = match &settings.entry {
        Err(_) => "malformed",
        Ok(entry) => {
            out.entry = entry.as_ref().map(clients::shown_entry);
            out.unknown_command = entry
                .as_ref()
                .is_some_and(|e| !command_is_known(e, ours, env));
            match owner(entry.as_ref(), record) {
                Owner::Klav => "connected",
                Owner::Changed => "changed",
                Owner::Person => "person",
                Owner::None if out.managed.blocked.is_some() => "managed",
                Owner::None if out.installed.is_none() => "not_installed",
                Owner::None => {
                    if record.is_some() {
                        out.note = Some("the klav entry Klav wrote is no longer there".into());
                    }
                    "not_connected"
                }
            }
        }
    };
    if out.state == "person" {
        out.note = Some(
            "the klav entry was not written by Klav: `klav client connect` asks before replacing or adopting it".into(),
        );
    }
    out
}

// -------------------------------------------------------------- connect

/// What happens to the `klav` entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Action {
    Add,
    Replace,
    Remove,
    /// Recorded as Klav's as it is.
    Adopt,
    /// Nothing to do.
    Keep,
    /// `--dry-run` only: there is a `klav` entry Klav did not write, or
    /// that changed since; writing needs `--replace` (or `--adopt`).
    Conflict,
}

/// What happens to a skill copy.
#[derive(Debug, Clone, Serialize)]
struct SkillStep {
    path: PathBuf,
    /// `install`, `replace`, `remove`, `keep` or `leave` (not Klav's, or
    /// edited: untouched).
    action: &'static str,
    state: Option<CopyState>,
    version: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    note: Option<String>,
}

/// The agent a connection uses.
#[derive(Debug, Clone, Serialize)]
struct AgentStep {
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    /// `pending`, `active`, or `new` (registered by this command).
    status: String,
    /// The six words the person compares on the approval card.
    #[serde(skip_serializing_if = "Option::is_none")]
    words: Option<String>,
    registers: bool,
}

#[derive(Debug, Clone, Serialize)]
struct McpStep {
    action: Action,
    /// Whose the `klav` entry there is.
    owner: Owner,
    method: Method,
    file: PathBuf,
    #[serde(skip_serializing_if = "Option::is_none")]
    link_to: Option<PathBuf>,
    key: &'static str,
    /// Klav's entry before, alone.
    before: Option<Value>,
    /// Klav's entry after, alone.
    after: Option<Value>,
    /// The client's command Klav runs.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    commands: Vec<Vec<String>>,
    /// SHA-256 of the file now.
    #[serde(skip_serializing_if = "Option::is_none")]
    file_sha256: Option<String>,
    /// What `--expect-sha256` takes to bind the write to this summary: the
    /// SHA-256 of the whole file when Klav edits it, of the `klav` member
    /// alone when the client's CLI writes it.
    expect_sha256: String,
    /// Where the copy of the file goes (or went).
    #[serde(skip_serializing_if = "Option::is_none")]
    backup: Option<PathBuf>,
    restart_required: bool,
}

#[derive(Debug, Serialize)]
struct Plan {
    client: ClientId,
    dry_run: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    agent: Option<AgentStep>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mcp: Option<McpStep>,
    skill: Vec<SkillStep>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    warnings: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    notes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    next: Option<String>,
}

/// Asks a yes/no question on the terminal (`false` without one).
fn ask(question: &str) -> CliResult<bool> {
    if !std::io::stdin().is_terminal() {
        return Ok(false);
    }
    eprint!("{question} [y/N] ");
    let _ = std::io::stderr().flush();
    let mut answer = String::new();
    std::io::stdin().lock().read_line(&mut answer)?;
    Ok(matches!(
        answer.trim().to_lowercase().as_str(),
        "y" | "yes" | "s" | "si" | "sí"
    ))
}

fn client_path(client: ClientId, env: &Env) -> CliResult<PathBuf> {
    client
        .config_path(env)
        .ok_or_else(|| usage(format!("{} is not available on this system", client.name())))
}

/// The client's CLI to write with, or the file; an error when the client
/// can only be written with a CLI that is not there.
fn method(client: ClientId, env: &Env, entry: &Entry) -> CliResult<(Method, Option<PathBuf>)> {
    if let Some(cli) = client.cli()
        && let Some(path) = env.which(cli)
    {
        return Ok((Method::Cli, Some(path)));
    }
    if client.cli_only() {
        return Err(CliError::Other(format!(
            "cannot connect {} without its `{}` command, which is not in PATH. With it installed, Klav runs:\n\n    {}",
            client.name(),
            client.cli().unwrap_or_default(),
            shell_line(&add_command(client, "claude", entry))
        )));
    }
    Ok((Method::File, None))
}

/// `claude mcp add …` / `codex mcp add …`: the name before `--env`, and
/// `--` after it. Claude Code's `--env` takes every value up to the next
/// option, so a name right after it would be read as another `KEY=value`
/// pair and refused (its MCP docs); `--` ends the list.
fn add_command(client: ClientId, cli: &str, entry: &Entry) -> Vec<String> {
    let mut out = vec![cli.to_owned(), "mcp".into(), "add".into()];
    if client == ClientId::ClaudeCode {
        out.extend(["--scope", "user", "--transport", "stdio"].map(String::from));
    }
    out.push("klav".into());
    for (k, v) in &entry.env {
        out.push("--env".into());
        out.push(format!("{k}={v}"));
    }
    out.push("--".into());
    out.push(entry.command.clone());
    out.extend(entry.args.iter().cloned());
    out
}

/// `claude mcp remove …` / `codex mcp remove …`.
fn remove_command(client: ClientId, cli: &str) -> Vec<String> {
    let mut out = vec![cli.to_owned(), "mcp".into(), "remove".into(), "klav".into()];
    if client == ClientId::ClaudeCode {
        out.extend(["--scope", "user"].map(String::from));
    }
    out
}

fn shell_line(words: &[String]) -> String {
    words
        .iter()
        .map(|w| crate::mcp::sh_quote(w))
        .collect::<Vec<_>>()
        .join(" ")
}

/// The malformed-file error of ADR 0033 §4: where, and the entry to paste
/// by hand.
fn malformed_error(
    settings: &Settings,
    e: &Malformed,
    entry: &Entry,
    client: ClientId,
) -> CliError {
    let pasted = match client.format() {
        Format::Json { .. } => format!(
            "\"klav\": {}",
            serde_json::to_string_pretty(&entry.to_value()).unwrap_or_default()
        ),
        Format::Toml => clients::toml::set_entry("", entry).unwrap_or_default(),
    };
    if client.cli_only() {
        return CliError::Other(format!(
            "{} is {e}; Klav does not touch it. Once {} has fixed it, Klav runs:\n\n    {}",
            settings.target.real.display(),
            client.name(),
            shell_line(&add_command(
                client,
                client.cli().unwrap_or_default(),
                entry
            ))
        ));
    }
    CliError::Other(format!(
        "{} is {e}; Klav does not touch it. Fix it, or add this under `{}` by hand:\n\n{pasted}",
        settings.target.real.display(),
        client.key().trim_end_matches(".klav")
    ))
}

/// The agent step: an existing agent of this name, or a new one.
async fn agent_step(
    home: &Home,
    client: ClientId,
    name: &str,
    dry_run: bool,
) -> CliResult<AgentStep> {
    klav_sdk::config::validate_name(name)?;
    if !klav_sdk::config::AgentConfig::exists(home, name) {
        if klav_client::account(home).is_err() {
            return Err(usage(format!(
                "no Klav account on this device to register agent {name:?} with: run `klav agent register --name {name} --email <account e-mail>` first, then connect again"
            )));
        }
        return Ok(AgentStep {
            name: name.to_owned(),
            id: None,
            status: "new".into(),
            words: None,
            registers: true,
        });
    }
    let config = klav_sdk::config::AgentConfig::load(home, name)?;
    let words =
        klav_core::crypto::identity::PublicIdentity::decode(config.public_identity.as_bytes())
            .ok()
            .map(|p| klav_core::crypto::agent::pairing_code(&p));
    if dry_run {
        return Ok(AgentStep {
            name: name.to_owned(),
            id: Some(config.agent_id.to_string()),
            status: "registered".into(),
            words,
            registers: false,
        });
    }
    let mut agent = Agent::load(home, name)?;
    let state = agent.state().await?;
    match state.status {
        AgentStatus::Active | AgentStatus::Pending => Ok(AgentStep {
            name: name.to_owned(),
            id: Some(state.agent_id.to_string()),
            status: state.status.as_str().to_owned(),
            words: Some(state.pairing_code),
            registers: false,
        }),
        // Nobody decided: the request lapsed. Asking again is not going
        // around a decision; it is forgotten here and registered anew.
        AgentStatus::Denied if state.lapsed => Ok(AgentStep {
            name: name.to_owned(),
            id: Some(state.agent_id.to_string()),
            status: LAPSED.into(),
            words: None,
            registers: true,
        }),
        // The person already decided (ADR 0033 E2.2): no second
        // registration from here. The name stays taken in this KLAV_HOME,
        // so the way back is a new agent under another name.
        AgentStatus::Denied | AgentStatus::Revoked => {
            Err(CliError::Client(ClientError::Denied(format!(
                "agent {name:?} is {}: the person already decided on it, and Klav does not register it again from here. To connect {} with a new agent, the person runs in their own terminal `klav agent register --name <another name>` and then `klav client connect {} --agent <another name>`",
                state.status.as_str(),
                client.name(),
                client.id(),
            ))))
        }
    }
}

/// The status of an agent whose pending request lapsed without a decision.
const LAPSED: &str = "lapsed";

/// Forgets a lapsed agent here (its config and its key) before asking
/// again: the server will never approve it, and its name is needed.
fn forget_lapsed(home: &Home, name: &str) -> CliResult<()> {
    let config = klav_sdk::config::AgentConfig::load(home, name)?;
    config.key_store.delete(config.agent_id)?;
    config.remove(home)?;
    Ok(())
}

async fn register(
    home: &Home,
    name: &str,
    key_store: KeyStoreArg,
) -> CliResult<klav_sdk::Registered> {
    let account = klav_client::account(home)?;
    let choice = match key_store {
        KeyStoreArg::Auto => KeyStoreChoice::Auto,
        KeyStoreArg::Keychain => KeyStoreChoice::Keychain,
        KeyStoreArg::File => KeyStoreChoice::File,
    };
    let key_store = KeyStore::choose(home, name, choice, None)?;
    let (_, registered) = Agent::register(
        home,
        Registration {
            name: name.to_owned(),
            server: account.server.clone(),
            email: account.email.clone(),
            note: None,
            key_store,
        },
    )
    .await?;
    Ok(registered)
}

/// What the agent tells the person, and how it waits (ADR 0033 E2.2).
fn next_for(client: ClientId, agent: &AgentStep, home: &Home, env: &Env) -> String {
    let restart = if client.needs_restart() {
        format!("{} must be restarted to load it", client.name())
    } else {
        format!(
            "they appear when {} loads its MCP servers again; if you do not see them, tell the person it needs a restart",
            client.name()
        )
    };
    if agent.status == "active" {
        return format!(
            "Agent {:?} is approved. `klav agent …` works now; the Klav tools: {restart}.",
            agent.name
        );
    }
    let exe = std::env::current_exe()
        .ok()
        .map(crate::mcp::live_exe)
        .and_then(|p| p.to_str().map(str::to_owned))
        .unwrap_or_else(|| "klav".into());
    let prefix = home_for_entry(home, env)
        .ok()
        .flatten()
        .map(|h| {
            format!(
                "KLAV_HOME={} ",
                crate::mcp::sh_quote(&h.display().to_string())
            )
        })
        .unwrap_or_default();
    format!(
        "The person must approve agent {name:?}. Tell them: «To finish connecting me to Klav, approve the agent {name:?} in the Klav app on your Mac (Requests), on your iPhone, or with `klav agent approve {name}` in your terminal, and check that the words are: {words}». Give the words exactly as above. Then run `{prefix}{exe} agent status --agent {name} --wait` in the background and do not use Klav until it exits 0. Never approve it yourself. After the approval, `klav agent …` works at once; the Klav tools: {restart}.",
        name = agent.name,
        words = agent
            .words
            .as_deref()
            .unwrap_or("(see `klav agent status`)"),
        exe = crate::mcp::sh_quote(&exe),
    )
}

async fn connect(ctx: &mut Ctx, args: ClientConnectArgs) -> CliResult<()> {
    let env = Env::from_env()?;
    let client = args.client;
    let path = client_path(client, &env)?;
    client.installed(&env).ok_or_else(|| {
        CliError::Other(format!(
            "{} is not installed here, so Klav does not create its settings",
            client.name()
        ))
    })?;
    let agent_name = args.agent.clone().unwrap_or_else(|| client.id().to_owned());
    let command = klav_command(&env)?;
    let entry = Entry::new(
        client,
        &command.path,
        &agent_name,
        home_for_entry(&ctx.home, &env)?.as_deref(),
    );
    let mut plan = Plan {
        client,
        dry_run: args.dry_run,
        agent: None,
        mcp: None,
        skill: Vec::new(),
        warnings: command.warning.clone().into_iter().collect(),
        notes: Vec::new(),
        next: None,
    };
    let managed = managed::check(client, &env, &entry);
    plan.notes.extend(managed.notes.iter().cloned());
    if let Some(rule) = managed.blocked {
        return Err(CliError::Other(format!(
            "your organization manages the MCP servers of {}: {rule}. Nothing was written: the entry would not start",
            client.name()
        )));
    }
    let (method, cli) = method(client, &env, &entry)?;
    // The plan is made without the lock (it asks the person and reads the
    // server); the write takes it and checks the plan again.
    let settings = read_settings(client, &path)?;
    if method == Method::File {
        if let Some(why) = settings.target.refusal(&env) {
            return Err(CliError::Other(format!("{why}. Nothing was written")));
        }
        // A new file only in the client's own folder (ADR 0033 §4): Klav
        // never creates `~/.cursor` or `~/.copilot` itself.
        if settings.text.is_none()
            && let Some(dir) = settings.target.real.parent()
            && !dir.is_dir()
        {
            return Err(CliError::Other(format!(
                "{} has no folder {} yet, and Klav does not create it. Open {} once (or create the folder) and connect again. Nothing was written",
                client.name(),
                dir.display(),
                client.name()
            )));
        }
    }
    let current = match &settings.entry {
        Ok(e) => e.clone(),
        Err(e) => return Err(malformed_error(&settings, e, &entry, client)),
    };
    let registry = Registry::load(&ctx.home)?;
    let record = registry.clients.get(client.id()).cloned();
    let owner = owner(current.as_ref(), record.as_ref());
    let action = match (owner, current.as_ref()) {
        (Owner::None, _) => Action::Add,
        (Owner::Klav, Some(v)) if entry.matches(v) => Action::Keep,
        (Owner::Klav, _) => Action::Replace,
        (Owner::Changed, _) if args.replace => Action::Replace,
        // An entry Klav did not write is the person's: only they decide to
        // replace or adopt it, at a terminal (ADR 0033 §3.4). `--yes` does
        // not stand in for them: an agent passes it.
        (Owner::Person, Some(v)) if args.replace || args.adopt => {
            let action = if args.replace {
                Action::Replace
            } else {
                if !runs_klav(v) {
                    return Err(CliError::Other(format!(
                        "the klav entry of {} does not run a klav program, so Klav does not adopt it; use --replace",
                        client.name()
                    )));
                }
                if Entry::from_value(client, v).is_none() {
                    return Err(CliError::Other(format!(
                        "the klav entry of {} carries more than a command, its arguments and KLAV_HOME (another variable, headers or a URL may hold a key), so Klav does not adopt it; use --replace",
                        client.name()
                    )));
                }
                Action::Adopt
            };
            if args.dry_run {
                plan.notes.push(
                    "the klav entry there was not written by Klav: replacing or adopting it needs the person at a terminal, where Klav asks".to_owned(),
                );
            } else {
                confirm_persons_entry(&settings.target.path, v, action)?;
            }
            action
        }
        (Owner::Changed | Owner::Person, Some(_)) if args.dry_run => {
            plan.notes.push(if owner == Owner::Changed {
                "the Klav entry changed since Klav wrote it: `--replace` puts Klav's back (with a copy)".to_owned()
            } else {
                "there is a klav entry Klav did not write: at a terminal, `--replace` uses Klav's (with a copy) and `--adopt` keeps that one as Klav's".to_owned()
            });
            Action::Conflict
        }
        (Owner::Changed, Some(v)) => {
            let question = format!(
                "The Klav entry in {} changed since Klav wrote it. Now: {}\nPut Klav's back (a copy of the file is kept)?",
                settings.target.path.display(),
                clients::shown_entry(v)
            );
            if ask(&question)? {
                Action::Replace
            } else {
                return Err(CliError::Other(format!(
                    "the Klav entry in {} changed since Klav wrote it; nothing was written. `--replace` puts Klav's back (with a copy)",
                    client.name()
                )));
            }
        }
        (Owner::Person, Some(v)) => {
            let question = format!(
                "{} already has a klav entry Klav did not write: {}\nReplace it with Klav's (a copy of the file is kept)?",
                settings.target.path.display(),
                clients::shown_entry(v)
            );
            if ask(&question)? {
                Action::Replace
            } else {
                return Err(CliError::Other(format!(
                    "{} already has a klav entry Klav did not write; it is left as it is. At a terminal, `--replace` uses Klav's (with a copy) and `--adopt` keeps that one as Klav's",
                    client.name()
                )));
            }
        }
        (Owner::Changed | Owner::Person, None) => Action::Add,
    };
    let guard = guard_sha256(client, method, settings.text.as_deref().map(str::as_bytes))
        .unwrap_or_default();
    if let Some(expected) = &args.expect_sha256
        && guard != expected.trim()
    {
        return Err(CliError::Other(format!(
            "{} changed since the summary; nothing was written. Look again",
            settings.target.real.display()
        )));
    }
    plan.warnings.extend(settings.target.link_warnings(&env));
    let mut commands = Vec::new();
    if method == Method::Cli && matches!(action, Action::Add | Action::Replace) {
        let cli_name = client.cli().unwrap_or_default();
        if action == Action::Replace {
            commands.push(remove_command(client, cli_name));
        }
        commands.push(add_command(client, cli_name, &entry));
    }
    plan.mcp = Some(McpStep {
        action,
        owner,
        method,
        file: settings.target.path.clone(),
        link_to: settings.target.link.clone(),
        key: client.key(),
        before: current.as_ref().map(clients::shown_entry),
        after: Some(match action {
            Action::Adopt | Action::Keep | Action::Conflict => {
                clients::shown_entry(current.as_ref().unwrap_or(&Value::Null))
            }
            _ => entry.to_value(),
        }),
        commands,
        file_sha256: settings.sha256.clone(),
        expect_sha256: guard,
        backup: (settings.text.is_some() && matches!(action, Action::Add | Action::Replace))
            .then(|| files::backup_dir(&ctx.home, client)),
        restart_required: client.needs_restart() && action != Action::Keep,
    });
    plan.skill = connect_skill_steps(client, &env, &registry, args.no_skill);
    let agent = agent_step(&ctx.home, client, &agent_name, args.dry_run).await?;
    if agent.status == LAPSED {
        plan.notes.push(format!(
            "the request of agent {agent_name:?} lapsed without a decision: Klav forgets it here and asks again"
        ));
    }
    plan.agent = Some(agent);
    if args.dry_run {
        return show_plan(&plan, args.json.json, "Nothing was changed (--dry-run).");
    }
    if !args.yes {
        if !std::io::stdin().is_terminal() {
            show_plan(&plan, args.json.json, "")?;
            return Err(CliError::Other(
                "nothing was written: without a terminal to confirm, run it again with --yes"
                    .into(),
            ));
        }
        show_plan(&plan, false, "")?;
        if !ask("Do it?")? {
            return Err(CliError::Other("nothing was written".into()));
        }
    }

    // From here to saving `clients.json`, no other `klav client` or
    // `klav skill` run changes a client. What the plan saw is checked
    // again: the record, and the agent (the file is checked by
    // `write_entry`). The skill steps are made again from the fresh record;
    // they never overwrite a copy that is not Klav's.
    let _lock = Registry::lock(&ctx.home)?;
    let mut registry = Registry::load(&ctx.home)?;
    let agent = plan.agent.as_mut().expect("set above");
    if registry.clients.get(client.id()) != record.as_ref()
        || local_agent_id(&ctx.home, &agent_name) != agent.id
    {
        return Err(CliError::Other(format!(
            "another `klav client` or `klav skill` run changed {} or its agent while you looked; nothing was written. Look again",
            client.name()
        )));
    }
    plan.skill = connect_skill_steps(client, &env, &registry, args.no_skill);

    // 1. The agent: its registration is the only request made with the
    // lock held, so that two runs never register the same name. Its
    // requests have a time limit.
    let agent = plan.agent.as_mut().expect("set above");
    if agent.registers {
        if agent.status == LAPSED {
            forget_lapsed(&ctx.home, &agent_name)?;
        }
        let registered = register(&ctx.home, &agent_name, args.key_store).await?;
        agent.id = Some(registered.agent_id.to_string());
        agent.status = "pending".into();
        agent.words = Some(registered.pairing_code.clone());
    }
    // 2. The entry, recorded as soon as it is written: whatever happens
    // next, Klav remembers it is its own.
    let mcp = plan.mcp.as_mut().expect("set above");
    let written = write_entry(
        &ctx.home,
        client,
        &env,
        &settings,
        current.as_ref(),
        action,
        cli.as_deref(),
        &entry,
    )?;
    mcp.backup = written.backup;
    plan.warnings.extend(written.warning);
    if action != Action::Keep || record.is_none() {
        let after = read_settings(client, &path)?;
        let found = after.entry.ok().flatten().ok_or_else(|| {
            CliError::Other("the klav entry is not in the file after writing".into())
        })?;
        registry.clients.insert(
            client.id().to_owned(),
            ClientRecord {
                agent: agent_name.clone(),
                file: path.clone(),
                key: client.key().to_owned(),
                method,
                entry_sha256: clients::entry_sha256(&found),
                file_sha256: after.sha256.unwrap_or_default(),
                at: crate::time::now_ms(),
            },
        );
        registry.save(&ctx.home)?;
    }
    // 3. The skill: the client is connected without it, so a failure here
    // is a warning, not an error.
    for step in &mut plan.skill {
        if let Err(e) = apply_skill_step(step, &mut registry) {
            plan.warnings.push(format!(
                "the skill was not installed in {}: {}. The klav entry is written; `klav skill install --client {}` tries again",
                step.path.display(),
                e.message().unwrap_or_else(|| "it failed".into()),
                client.id()
            ));
            step.action = "failed";
        }
    }
    registry.save(&ctx.home)?;
    let agent = plan.agent.clone().expect("set above");
    plan.next = Some(next_for(client, &agent, &ctx.home, &env));
    show_plan(&plan, args.json.json, "")?;
    Ok(())
}

/// Replacing or adopting a `klav` entry Klav did not write: asked at a
/// terminal, never without one (ADR 0033 §3.4).
fn confirm_persons_entry(path: &Path, entry: &Value, action: Action) -> CliResult<()> {
    let doing = if action == Action::Adopt {
        "adopting"
    } else {
        "replacing"
    };
    if !std::io::stdin().is_terminal() {
        return Err(CliError::Other(format!(
            "the klav entry in {} was not written by Klav, and {doing} it needs the person at a terminal to confirm; --yes does not stand in for that. Nothing was written",
            path.display()
        )));
    }
    let question = format!(
        "{} has a klav entry Klav did not write: {}\n{}?",
        path.display(),
        clients::shown_entry(entry),
        if action == Action::Adopt {
            "Keep it as Klav's, as it is"
        } else {
            "Replace it with Klav's (a copy of the file is kept)"
        }
    );
    if ask(&question)? {
        Ok(())
    } else {
        Err(CliError::Other("nothing was written".into()))
    }
}

/// What a write is bound to (`--expect-sha256`, and the read right before
/// writing): the whole file when Klav edits it, only the `klav` member when
/// the client's own CLI writes it, because the client rewrites the rest of
/// that file for itself all the time (`~/.claude.json`). `None` when the
/// file cannot be read as settings.
fn guard_sha256(client: ClientId, method: Method, bytes: Option<&[u8]>) -> Option<String> {
    match method {
        Method::File => Some(skill::sha256(bytes.unwrap_or_default())),
        Method::Cli => {
            let entry = match bytes {
                None => None,
                Some(b) => parse_entry(client, std::str::from_utf8(b).ok()?).ok()?,
            };
            Some(clients::member_sha256(entry.as_ref()))
        }
    }
}

/// The ID of the agent `name` of this `KLAV_HOME`, if it has one.
fn local_agent_id(home: &Home, name: &str) -> Option<String> {
    klav_sdk::config::AgentConfig::exists(home, name)
        .then(|| klav_sdk::config::AgentConfig::load(home, name).ok())
        .flatten()
        .map(|c| c.agent_id.to_string())
}

/// The skill steps of `connect` (none with `--no-skill`).
fn connect_skill_steps(
    client: ClientId,
    env: &Env,
    registry: &Registry,
    no_skill: bool,
) -> Vec<SkillStep> {
    if no_skill {
        return Vec::new();
    }
    client
        .skills_dir(env)
        .map(|dir| skill_step_for_connect(&dir, registry))
        .into_iter()
        .collect()
}

/// The skill copy `connect` installs in `skills_dir`.
fn skill_step_for_connect(skills_dir: &Path, registry: &Registry) -> SkillStep {
    let path = skill::file_in(skills_dir);
    let copy = skill::inspect(&path, registry);
    let (action, note) = match copy.as_ref().map(|c| c.state) {
        None => ("install", None),
        // The person removed it: never put back by itself (ADR 0033 §6).
        Some(CopyState::Removed) => (
            "leave",
            Some("you removed it, so Klav leaves it out: `klav skill install` brings it back".to_owned()),
        ),
        Some(CopyState::Older) => ("replace", None),
        Some(CopyState::Current | CopyState::Newer) => ("keep", None),
        Some(CopyState::Edited) => (
            "leave",
            Some("it has changes: Klav leaves it (`klav skill status`)".to_owned()),
        ),
        Some(CopyState::Unmanaged) => (
            "leave",
            Some(
                "a klav skill Klav did not write is there: Klav leaves it (`klav skill install --adopt` or `--replace`)"
                    .to_owned(),
            ),
        ),
    };
    SkillStep {
        path,
        action,
        state: copy.map(|c| c.state),
        version: skill::version(),
        note,
    }
}

fn apply_skill_step(step: &SkillStep, registry: &mut Registry) -> CliResult<()> {
    match step.action {
        "install" | "replace" => skill::write(&step.path, registry),
        "remove" => skill::remove(&step.path, registry),
        _ => Ok(()),
    }
}

/// What [`write_entry`] did.
#[derive(Default)]
struct Written {
    /// Where the copy of the file went.
    backup: Option<PathBuf>,
    /// The client's CLI failed, but the file has what Klav asked for.
    warning: Option<String>,
}

/// The `klav` member of the settings right now; `None` when the file
/// cannot be read as settings, so Klav cannot tell.
fn member_now(client: ClientId, path: &Path) -> Option<Option<Value>> {
    read_settings(client, path).ok()?.entry.ok()
}

/// Runs the client's CLI. A tool may write the file and then fail (or be
/// killed by [`TOOL_TIMEOUT`] right after writing): when it fails, Klav
/// reads the `klav` member again, and if `done` says it is what Klav asked
/// for, the write counts, with a warning. Otherwise the tool's error.
fn run_tool_checked(
    cli: &Path,
    args: &[String],
    client: ClientId,
    path: &Path,
    done: impl Fn(Option<&Value>) -> bool,
) -> CliResult<Option<String>> {
    let Err(error) = run_tool(cli, args) else {
        return Ok(None);
    };
    match member_now(client, path) {
        Some(member) if done(member.as_ref()) => Ok(Some(format!(
            "{}, but the klav entry in {} is what Klav asked for, so Klav counts it as written",
            error.message().unwrap_or_else(|| "it failed".into()),
            path.display()
        ))),
        _ => Err(error),
    }
}

/// Writes the entry. `current` is the `klav` entry there was when the plan
/// was made.
#[allow(clippy::too_many_arguments)]
fn write_entry(
    home: &Home,
    client: ClientId,
    env: &Env,
    settings: &Settings,
    current: Option<&Value>,
    action: Action,
    cli: Option<&Path>,
    entry: &Entry,
) -> CliResult<Written> {
    if matches!(action, Action::Keep | Action::Adopt) {
        return Ok(Written::default());
    }
    let method = if cli.is_some() {
        Method::Cli
    } else {
        Method::File
    };
    let name = files::backup_name(&settings.target.path);
    // Read again right before writing (ADR 0033 §3.6).
    let now = settings.target.read()?;
    let planned = guard_sha256(client, method, settings.text.as_deref().map(str::as_bytes));
    if guard_sha256(client, method, now.as_deref()) != planned {
        return Err(CliError::Other(format!(
            "{} changed while you looked; nothing was written",
            settings.target.real.display()
        )));
    }
    let backup = now
        .as_deref()
        .map(|b| files::backup(home, client, &name, b))
        .transpose()?;
    let backup_shown = || {
        backup.as_ref().map_or_else(
            || "(none: it did not exist)".into(),
            |b| b.display().to_string(),
        )
    };
    let mut warning = None;
    match cli {
        Some(cli) => {
            let cli_name = client.cli().unwrap_or_default();
            let path = &settings.target.path;
            let removed = |m: Option<&Value>| m.is_none();
            let added = |m: Option<&Value>| m.is_some_and(|f| entry.matches(f));
            let remove = remove_command(client, cli_name);
            let add = add_command(client, cli_name, entry);
            warning = match action {
                Action::Remove => run_tool_checked(cli, &remove[1..], client, path, removed)?,
                Action::Replace => {
                    let first = run_tool_checked(cli, &remove[1..], client, path, removed)?;
                    match run_tool(cli, &add[1..]) {
                        Ok(()) => first,
                        Err(e) => Some(add_failed_after_remove(
                            client,
                            cli,
                            settings,
                            entry,
                            current,
                            &e,
                            &backup_shown(),
                        )?),
                    }
                }
                _ => run_tool_checked(cli, &add[1..], client, path, added)?,
            };
            let after = read_settings(client, &settings.target.path)?;
            let found = after
                .entry
                .map_err(|e| CliError::Other(format!("after `{cli_name}`: {e}")))?;
            let ok = match action {
                Action::Remove => found.is_none(),
                _ => found.as_ref().is_some_and(|f| entry.matches(f)),
            };
            if !ok {
                let back = if client.cli_only() {
                    format!(
                        "Klav does not put a copy over {} by hand ({} rewrites that file for itself): check it with `{cli_name} mcp get klav`; `{}` takes it out. A copy of the file from before is in {}",
                        settings.target.path.display(),
                        client.name(),
                        shell_line(&remove_command(client, cli_name)),
                        backup_shown()
                    )
                } else {
                    format!(
                        "A copy of the file from before is in {} (`klav client restore {}` puts it back)",
                        backup_shown(),
                        client.id()
                    )
                };
                return Err(CliError::Other(format!(
                    "`{cli_name}` ran, but the klav entry in {} is not what Klav asked for. {back}",
                    settings.target.path.display()
                )));
            }
        }
        None => edit_file(
            client,
            env,
            settings,
            action,
            entry,
            now.as_deref(),
            &backup_shown(),
        )?,
    }
    Ok(Written { backup, warning })
}

/// `<cli> mcp add` failed after `<cli> mcp remove` took the old `klav`
/// entry out. The tool may have written before failing, so Klav reads the
/// member first:
///
/// - it is the new entry: written after all, a warning (`Ok`);
/// - there is none: Klav puts the old one back, but only if it is an entry
///   Klav could have written with nothing hidden in it ([`Entry::from_value`]):
///   one that may carry a key never goes on a command line, nor to the
///   client's CLI. Either way it is an error;
/// - anything else, or a file Klav cannot read: an error, nothing retried.
fn add_failed_after_remove(
    client: ClientId,
    cli: &Path,
    settings: &Settings,
    entry: &Entry,
    removed: Option<&Value>,
    error: &CliError,
    backup: &str,
) -> CliResult<String> {
    let cli_name = client.cli().unwrap_or_default();
    let path = &settings.target.path;
    let error = error.message().unwrap_or_else(|| "it failed".into());
    let fail = |text: String| Err(CliError::Other(format!("{error}. {text}")));
    match member_now(client, path) {
        Some(Some(found)) if entry.matches(&found) => {
            return Ok(format!(
                "{error}, but the klav entry in {} is what Klav asked for, so Klav counts it as written",
                path.display()
            ));
        }
        Some(None) => {}
        Some(Some(_)) | None => {
            return fail(format!(
                "`{cli_name} mcp remove` had already taken out the klav entry there was, and now {} has a klav entry that is neither that one nor Klav's. Check it with `{cli_name} mcp get klav`; a copy of the file from before is in {backup}",
                path.display()
            ));
        }
    }
    let Some(old) = removed.and_then(|v| Entry::from_value(client, v)) else {
        return fail(format!(
            "`{cli_name} mcp remove` had already taken out the klav entry there was. Klav did not write that entry and does not print it or pass it to `{cli_name}`, because it may carry a key: put it back by hand from the copy of the file from before, in {backup}"
        ));
    };
    let again = add_command(client, cli_name, &old);
    // Read whatever `add` says: it may write and fail this time too.
    let _ = run_tool(cli, &again[1..]);
    let back = member_now(client, path)
        .flatten()
        .is_some_and(|f| old.matches(&f));
    if back {
        fail(format!(
            "`{cli_name} mcp remove` had already taken out the klav entry there was; Klav put it back ({}), so the settings are as before",
            old.to_value()
        ))
    } else {
        fail(format!(
            "`{cli_name} mcp remove` had already taken out the klav entry there was ({}), and putting it back failed too. To add it again: `{}`. A copy of the file from before is in {backup}",
            old.to_value(),
            shell_line(&again)
        ))
    }
}

/// The minimal edit of a file, checked afterwards and undone if anything
/// else changed (ADR 0033 §3.6).
fn edit_file(
    client: ClientId,
    env: &Env,
    settings: &Settings,
    action: Action,
    entry: &Entry,
    before: Option<&[u8]>,
    backup: &str,
) -> CliResult<()> {
    let text = settings.text.clone().unwrap_or_default();
    let edited = match (client.format(), action) {
        (Format::Json { container, .. }, Action::Remove) => {
            clients::json::remove_entry(&text, container)
        }
        (Format::Json { container, .. }, _) => clients::json::set_entry(&text, container, entry),
        (Format::Toml, Action::Remove) => clients::toml::remove_entry(&text),
        (Format::Toml, _) => clients::toml::set_entry(&text, entry),
    }
    .map_err(|e| CliError::Other(format!("{}: {e}", settings.target.real.display())))?;
    let real = &settings.target.real;
    // `connect` checked that the folder exists: Klav never creates it.
    if before.is_none() && settings.target.refusal(env).is_some() {
        return Err(CliError::Other(format!("cannot write {}", real.display())));
    }
    files::write_atomic(real, edited.as_bytes(), settings.target.mode())?;
    // Check: valid, and only Klav's member changed.
    let written = std::fs::read(real)?;
    let written_text = String::from_utf8_lossy(&written);
    let check = match client.format() {
        Format::Json { container, .. } => {
            clients::json::only_klav_changed(&text, &written_text, container).and_then(|()| {
                clients::json::entry(&written_text, container).map_err(|e| e.to_string())
            })
        }
        Format::Toml => clients::toml::only_klav_changed(&text, &written_text)
            .and_then(|()| clients::toml::entry(&written_text).map_err(|e| e.to_string())),
    };
    let good = match (&check, action) {
        (Ok(found), Action::Remove) => found.is_none(),
        (Ok(found), _) => found.as_ref().is_some_and(|f| entry.matches(f)),
        (Err(_), _) => false,
    };
    if good {
        return Ok(());
    }
    let why = check
        .err()
        .unwrap_or_else(|| "the klav entry is not the one Klav wrote".into());
    // Put the file back only if it is still exactly what Klav wrote: a
    // newer file (the client, or the person, wrote it meanwhile) is never
    // overwritten with an older copy.
    if std::fs::read(real).ok().as_deref() != Some(edited.as_bytes()) {
        return Err(CliError::Other(format!(
            "the check after writing {} failed ({why}), and the file changed again since Klav wrote it, so Klav did not put its copy over it. A copy of the file from before is in {backup}",
            real.display()
        )));
    }
    match before {
        Some(bytes) => files::write_atomic(real, bytes, settings.target.mode())?,
        None => {
            let _ = std::fs::remove_file(real);
        }
    }
    Err(CliError::Other(format!(
        "the check after writing {} failed ({why}); the file was put back as it was",
        real.display()
    )))
}

/// Runs a client's CLI (`claude`, `codex`) with `args`, without a terminal,
/// for at most [`TOOL_TIMEOUT`].
///
/// What the tool prints is never read nor passed on: its errors may quote
/// a line of its settings, with another server's key in it. A failure says
/// only how it ended and the command to run by hand to see why.
fn run_tool(cli: &Path, args: &[String]) -> CliResult<()> {
    let name = cli
        .file_name()
        .map_or_else(|| "tool".into(), |n| n.to_string_lossy().into_owned());
    let by_hand = || {
        let mut words = vec![name.clone()];
        words.extend(args.iter().cloned());
        shell_line(&words)
    };
    let mut child = std::process::Command::new(cli)
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| CliError::Other(format!("cannot run {}: {e}", cli.display())))?;
    let started = std::time::Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if started.elapsed() > TOOL_TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            return Err(CliError::Other(format!(
                "`{name} mcp {}` did not finish in {} s (to see why, run it by hand: `{}`)",
                args.get(1).map(String::as_str).unwrap_or_default(),
                TOOL_TIMEOUT.as_secs(),
                by_hand()
            )));
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    };
    if status.success() {
        return Ok(());
    }
    Err(CliError::Other(format!(
        "`{name} mcp {}` failed ({}; to see why, run it by hand: `{}`)",
        args.get(1).map(String::as_str).unwrap_or_default(),
        status
            .code()
            .map_or_else(|| "killed".into(), |c| format!("exit {c}")),
        by_hand()
    )))
}

fn show_plan(plan: &Plan, json: bool, footer: &str) -> CliResult<()> {
    if json {
        return output::json(plan);
    }
    if let Some(mcp) = &plan.mcp {
        let what = match mcp.action {
            Action::Add => "add",
            Action::Replace => "replace",
            Action::Remove => "remove",
            Action::Adopt => "keep as Klav's",
            Action::Keep => "already there",
            Action::Conflict => "would need --replace or --adopt for",
        };
        output::info(&format!(
            "{}: {what} `{}` in {}{}",
            plan.client.name(),
            mcp.key,
            mcp.file.display(),
            mcp.link_to
                .as_ref()
                .map(|l| format!(" → {}", l.display()))
                .unwrap_or_default()
        ));
        if mcp.action != Action::Keep {
            if let Some(before) = &mcp.before {
                output::info(&format!("  before: {before}"));
            }
            if let Some(after) = &mcp.after {
                output::info(&format!("  after:  {after}"));
            }
            for command in &mcp.commands {
                output::info(&format!("  runs:   {}", shell_line(command)));
            }
            if let Some(b) = &mcp.backup {
                output::info(&format!("  copy:   {}", b.display()));
            }
        }
        if mcp.restart_required {
            output::info(&format!(
                "  {} must be restarted to load it.",
                plan.client.name()
            ));
        }
    }
    for s in &plan.skill {
        output::info(&format!(
            "skill: {} {}{}",
            s.action,
            s.path.display(),
            s.note
                .as_ref()
                .map(|n| format!(" ({n})"))
                .unwrap_or_default()
        ));
    }
    if let Some(a) = &plan.agent {
        let state = if a.registers && a.words.is_none() {
            "will be registered and wait for approval".to_owned()
        } else {
            a.status.clone()
        };
        output::info(&format!("agent: {} ({state})", a.name));
    }
    for w in &plan.warnings {
        output::warn(w);
    }
    for n in &plan.notes {
        output::info(&format!("note: {n}"));
    }
    if let Some(a) = &plan.agent
        && let Some(words) = &a.words
        && plan.next.is_some()
        && a.status != "active"
    {
        output::info(
            "\nThe person approves it in the Klav app (Requests), on their iPhone or with",
        );
        output::info(&format!(
            "`klav agent approve {}`, and checks that the words match:\n",
            a.name
        ));
        output::line(&format!("    {words}"));
    }
    if let Some(next) = &plan.next
        && plan.agent.as_ref().is_some_and(|a| a.status == "active")
    {
        output::info(next);
    }
    if !footer.is_empty() {
        output::info(footer);
    }
    Ok(())
}

// ----------------------------------------------------------- disconnect

fn disconnect(ctx: &Ctx, args: &ClientDisconnectArgs) -> CliResult<()> {
    let env = Env::from_env()?;
    let client = args.client;
    let path = client_path(client, &env)?;
    // The plan is made without the lock (it may ask the person); the write
    // takes it and checks the plan again.
    let registry = Registry::load(&ctx.home)?;
    let record = registry.clients.get(client.id()).cloned();
    let settings = read_settings(client, &path)?;
    let current = match &settings.entry {
        Ok(e) => e.clone(),
        Err(e) => {
            return Err(CliError::Other(format!(
                "{} is {e}; Klav does not touch it",
                settings.target.real.display()
            )));
        }
    };
    let agent_name = record
        .as_ref()
        .map_or_else(|| client.id().to_owned(), |r| r.agent.clone());
    let owner = owner(current.as_ref(), record.as_ref());
    let action = match owner {
        Owner::None => Action::Keep,
        Owner::Klav => Action::Remove,
        Owner::Changed if args.force => Action::Remove,
        Owner::Changed => {
            let shown = current
                .as_ref()
                .map(clients::shown_entry)
                .unwrap_or_default();
            if ask(&format!(
                "The Klav entry in {} changed since Klav wrote it. Now: {shown}\nRemove it anyway (a copy of the file is kept)?",
                settings.target.path.display()
            ))? {
                Action::Remove
            } else {
                return Err(CliError::Other(format!(
                    "the Klav entry in {} changed since Klav wrote it; nothing was removed (`--force` removes it, with a copy)",
                    client.name()
                )));
            }
        }
        Owner::Person => {
            return Err(CliError::Other(format!(
                "the klav entry in {} was not written by Klav: Klav only removes its own. Remove it by hand if you want it gone",
                settings.target.path.display()
            )));
        }
    };
    let (method, cli) = if action == Action::Remove {
        match client.cli().and_then(|c| env.which(c)) {
            Some(p) => (Method::Cli, Some(p)),
            None if client.cli_only() => {
                return Err(CliError::Other(format!(
                    "cannot remove the entry of {} without its `{}` command; run `{}` once it is installed",
                    client.name(),
                    client.cli().unwrap_or_default(),
                    shell_line(&remove_command(client, client.cli().unwrap_or_default()))
                )));
            }
            None => (Method::File, None),
        }
    } else {
        (record.as_ref().map_or(Method::File, |r| r.method), None)
    };
    if method == Method::File
        && action == Action::Remove
        && let Some(why) = settings.target.refusal(&env)
    {
        return Err(CliError::Other(format!("{why}. Nothing was changed")));
    }
    let mut plan = Plan {
        client,
        dry_run: args.dry_run,
        agent: None,
        mcp: Some(McpStep {
            action,
            owner,
            method,
            file: settings.target.path.clone(),
            link_to: settings.target.link.clone(),
            key: client.key(),
            before: current.as_ref().map(clients::shown_entry),
            after: None,
            commands: if method == Method::Cli && action == Action::Remove {
                vec![remove_command(client, client.cli().unwrap_or_default())]
            } else {
                Vec::new()
            },
            file_sha256: settings.sha256.clone(),
            expect_sha256: guard_sha256(
                client,
                method,
                settings.text.as_deref().map(str::as_bytes),
            )
            .unwrap_or_default(),
            backup: (action == Action::Remove).then(|| files::backup_dir(&ctx.home, client)),
            restart_required: client.needs_restart() && action == Action::Remove,
        }),
        skill: disconnect_skill_steps(client, &env, &registry, args),
        warnings: settings.target.link_warnings(&env),
        notes: vec![format!(
            "the agent {agent_name:?} keeps its access with its key: to cut it off, pause or revoke it (`klav agent revoke {agent_name}`)"
        )],
        next: None,
    };
    if args.dry_run {
        return show_plan(&plan, args.json.json, "Nothing was changed (--dry-run).");
    }
    if !args.yes && action == Action::Remove {
        if !std::io::stdin().is_terminal() {
            show_plan(&plan, args.json.json, "")?;
            return Err(CliError::Other(
                "nothing was changed: without a terminal to confirm, run it again with --yes"
                    .into(),
            ));
        }
        show_plan(&plan, false, "")?;
        if !ask("Do it?")? {
            return Err(CliError::Other("nothing was changed".into()));
        }
    }
    // From here to saving `clients.json`, no other run changes a client:
    // the record is checked again (the file, by `write_entry`), and the
    // skill steps are made again from the fresh record.
    let _lock = Registry::lock(&ctx.home)?;
    let mut registry = Registry::load(&ctx.home)?;
    if registry.clients.get(client.id()) != record.as_ref() {
        return Err(CliError::Other(format!(
            "another `klav client` or `klav skill` run changed {} while you looked; nothing was changed. Look again",
            client.name()
        )));
    }
    plan.skill = disconnect_skill_steps(client, &env, &registry, args);
    let entry = Entry::new(client, Path::new(""), &agent_name, None);
    if action == Action::Remove {
        let written = write_entry(
            &ctx.home,
            client,
            &env,
            &settings,
            current.as_ref(),
            Action::Remove,
            cli.as_deref(),
            &entry,
        )?;
        if let Some(mcp) = plan.mcp.as_mut() {
            mcp.backup = written.backup;
        }
        plan.warnings.extend(written.warning);
    }
    // Recorded as soon as the entry is out: whatever happens to the skill,
    // Klav no longer counts the entry as its own.
    registry.clients.remove(client.id());
    registry.save(&ctx.home)?;
    // The skill: the entry is out without it, so a failure here is a
    // warning, as in `connect`.
    for step in &mut plan.skill {
        if let Err(e) = apply_skill_step(step, &mut registry) {
            plan.warnings.push(format!(
                "the skill was not removed from {}: {}. The klav entry is out; `klav skill uninstall --client {}` tries again",
                step.path.display(),
                e.message().unwrap_or_else(|| "it failed".into()),
                client.id()
            ));
            step.action = "failed";
        }
    }
    registry.save(&ctx.home)?;
    show_plan(&plan, args.json.json, "")
}

/// The skill steps of `disconnect`: the copy goes only if no other
/// connected client reads its folder and it did not change.
fn disconnect_skill_steps(
    client: ClientId,
    env: &Env,
    registry: &Registry,
    args: &ClientDisconnectArgs,
) -> Vec<SkillStep> {
    if args.keep_skill {
        return Vec::new();
    }
    let Some(dir) = client.skills_dir(env) else {
        return Vec::new();
    };
    let others: Vec<&str> = registry
        .clients
        .keys()
        .filter(|k| k.as_str() != client.id())
        .filter(|k| {
            ClientId::from_id(k)
                .and_then(|c| c.skills_dir(env))
                .as_ref()
                == Some(&dir)
        })
        .map(String::as_str)
        .collect();
    let path = skill::file_in(&dir);
    let Some(copy) = skill::inspect(&path, registry) else {
        return Vec::new();
    };
    let (action, note) = if !others.is_empty() {
        ("keep", Some(format!("{} also reads it", others.join(", "))))
    } else {
        match copy.state {
            CopyState::Current | CopyState::Older | CopyState::Newer => ("remove", None),
            CopyState::Edited if args.force => ("remove", None),
            CopyState::Edited => (
                "leave",
                Some("it has changes: Klav leaves it (`--force` removes it)".to_owned()),
            ),
            CopyState::Removed => ("remove", None),
            CopyState::Unmanaged => ("leave", Some("not written by Klav".to_owned())),
        }
    };
    vec![SkillStep {
        path,
        action,
        state: Some(copy.state),
        version: skill::version(),
        note,
    }]
}

// -------------------------------------------------------------- restore

fn restore(ctx: &Ctx, args: &ClientRestoreArgs) -> CliResult<()> {
    let env = Env::from_env()?;
    let client = args.client;
    let path = client_path(client, &env)?;
    let name = files::backup_name(&path);
    if client.cli_only() {
        return Err(CliError::Other(cli_only_restore(ctx, client, &path, &name)));
    }
    // The plan is made without the lock (it may ask the person); the write
    // takes it and checks the plan again.
    let registry = Registry::load(&ctx.home)?;
    let record = registry.clients.get(client.id()).cloned();
    let target = Target::resolve(&path)?;
    if let Some(why) = target.refusal(&env) {
        return Err(CliError::Other(format!("{why}. Nothing was changed")));
    }
    let Some(latest) = files::backups(&ctx.home, client, &name).pop() else {
        return Err(CliError::Other(format!(
            "there is no copy of {} in {}",
            path.display(),
            files::backup_dir(&ctx.home, client).display()
        )));
    };
    let now = target.read()?;
    let bytes = std::fs::read(&latest)?;
    let restart = client.needs_restart();
    // Already the copy (a restore just ran): nothing to do. Restoring again
    // must not undo the first restore.
    if now.as_deref() == Some(bytes.as_slice()) {
        if args.json.json {
            return output::json(&json!({
                "client": client,
                "file": path,
                "restored_from": latest,
                "already": true,
                "restart_required": false,
            }));
        }
        output::info(&format!(
            "{} is already the copy {}; nothing was changed.",
            path.display(),
            latest.display()
        ));
        return Ok(());
    }
    let now_sha = now.as_deref().map(skill::sha256);
    let unchanged = record
        .as_ref()
        .is_some_and(|r| now_sha.as_deref() == Some(r.file_sha256.as_str()));
    if !unchanged && !args.force {
        let question = format!(
            "{} changed since Klav last wrote it: restoring the copy {} loses those changes (they are kept as another copy). Restore?",
            path.display(),
            latest.display()
        );
        if !ask(&question)? {
            return Err(CliError::Other(format!(
                "{} changed since Klav last wrote it; nothing was restored (`--force` restores it, keeping the current one as a copy)",
                path.display()
            )));
        }
    }
    // From here to saving `clients.json`, no other run changes a client:
    // the record, the file and the latest copy must be what the plan saw.
    let _lock = Registry::lock(&ctx.home)?;
    let mut registry = Registry::load(&ctx.home)?;
    if registry.clients.get(client.id()) != record.as_ref()
        || target.read()? != now
        || files::backups(&ctx.home, client, &name).pop().as_ref() != Some(&latest)
    {
        return Err(CliError::Other(format!(
            "{} or its copies changed while you looked; nothing was restored. Look again",
            path.display()
        )));
    }
    // What the file had is kept apart from the backups, so it never
    // becomes the copy the next restore brings back.
    let kept = now
        .as_deref()
        .map(|b| files::backup(&ctx.home, client, &files::replaced_name(&path), b))
        .transpose()?;
    files::write_atomic(&target.real, &bytes, target.mode())?;
    registry.clients.remove(client.id());
    registry.save(&ctx.home)?;
    if args.json.json {
        return output::json(&json!({
            "client": client,
            "file": path,
            "restored_from": latest,
            "current_kept_as": kept,
            "restart_required": restart,
        }));
    }
    output::info(&format!(
        "Restored {} from {}.",
        path.display(),
        latest.display()
    ));
    if let Some(k) = kept {
        output::info(&format!("What it had is kept in {}.", k.display()));
    }
    if restart {
        output::info(&format!("Restart {} to load it.", client.name()));
    }
    Ok(())
}

/// Why `klav client restore` does not write a client Klav only writes with
/// its CLI (`~/.claude.json`, which Claude Code rewrites for itself, ADR
/// 0033 §2), and the commands that go back to the copy.
fn cli_only_restore(ctx: &Ctx, client: ClientId, path: &Path, name: &str) -> String {
    let cli = client.cli().unwrap_or_default();
    let Some(latest) = files::backups(&ctx.home, client, name).pop() else {
        return format!(
            "Klav does not write {} by hand ({} rewrites it for itself), and there is no copy of it in {}. `{}` takes Klav's entry out",
            path.display(),
            client.name(),
            files::backup_dir(&ctx.home, client).display(),
            shell_line(&remove_command(client, cli))
        );
    };
    let now = read_settings(client, path)
        .ok()
        .and_then(|s| s.entry.ok().flatten());
    let then = std::fs::read(&latest)
        .ok()
        .and_then(|b| String::from_utf8(b).ok())
        .and_then(|t| parse_entry(client, &t).ok().flatten());
    let mut commands = Vec::new();
    if now.is_some() {
        commands.push(format!("    {}", shell_line(&remove_command(client, cli))));
    }
    let mut by_hand = None;
    if let Some(v) = then.as_ref() {
        match Entry::from_value(client, v) {
            Some(old) => commands.push(format!(
                "    {}",
                shell_line(&add_command(client, cli, &old))
            )),
            // Not an entry Klav could have written, with nothing hidden: it
            // may carry a key, so it is neither printed nor made a command.
            None => {
                by_hand = Some(format!(
                    "put back by hand the klav entry the copy has (under `mcpServers` in {}): Klav did not write it, and does not print it or pass it to `{cli}`, because it may carry a key",
                    latest.display()
                ))
            }
        }
    }
    let steps = match (commands.is_empty(), by_hand) {
        (true, None) => "Its klav entry is already as in the copy.".to_owned(),
        (true, Some(h)) => format!("To go back to it, {h}."),
        (false, None) => format!("To go back to it, run:\n\n{}", commands.join("\n")),
        (false, Some(h)) => format!(
            "To go back to it, run:\n\n{}\n\nand then {h}.",
            commands.join("\n")
        ),
    };
    format!(
        "Klav does not write {} by hand: {} rewrites that file for itself, so a copy put over it would lose what it wrote since. The copy from before Klav's last change is {}. {steps}",
        path.display(),
        client.name(),
        latest.display()
    )
}
