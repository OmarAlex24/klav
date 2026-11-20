//! Command-line syntax. Secrets are never accepted as arguments: they come
//! from a hidden TTY prompt or from stdin.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

/// Klav: an end-to-end encrypted password manager for people and agents.
#[derive(Debug, Parser)]
#[command(name = "klav", version = crate::build::version(), propagate_version = true)]
pub(crate) struct Cli {
    /// Read the master password from the first line of stdin instead of a
    /// TTY prompt (for scripts). Values for `--secret-stdin` follow, one per
    /// line.
    #[arg(long, global = true)]
    pub(crate) password_stdin: bool,

    /// Do not use `klavd` even if it is running: unlock in this process.
    #[arg(long, global = true, env = "KLAV_NO_DAEMON", value_parser = clap::builder::BoolishValueParser::new())]
    pub(crate) no_daemon: bool,

    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Create an account on a server and set up this device.
    Signup(SignupArgs),
    /// Set up this device for an existing account.
    Login(LoginArgs),
    /// Unlock (keeps `klavd` unlocked; Touch ID when enrolled).
    Unlock(UnlockArgs),
    /// Lock `klavd` now.
    Lock(LockArgs),
    /// Presence before `klavd` hands out a value (ADR 0041): how often it
    /// asks for Touch ID or the master password.
    #[command(subcommand)]
    Presence(PresenceCommand),
    /// Sign this device out and delete its copy of the account from
    /// `$KLAV_HOME` (vaults, session, Secret Key file). The account stays
    /// on the server.
    Logout(LogoutArgs),
    /// Account, device and daemon status (no password needed).
    Status(JsonFlag),
    /// Pull changes from the server.
    Sync(SyncArgs),
    /// The account on this device: its server and its emergency kit.
    #[command(subcommand)]
    Account(AccountCommand),
    /// Vaults.
    #[command(subcommand)]
    Vault(VaultCommand),
    /// Projects inside vaults.
    #[command(subcommand)]
    Project(ProjectCommand),
    /// Items: add, show, edit, remove, list and search.
    #[command(subcommand)]
    Item(ItemCommand),
    /// Current one-time password of an item.
    Totp(TotpArgs),
    /// Generate a password or a passphrase.
    Generate(GenerateArgs),
    /// The passwords Klav generated.
    #[command(subcommand)]
    Generated(GeneratedCommand),
    /// Vault health: reused, weak and old passwords, and breached ones if
    /// the breach check is on (values never shown).
    Health(HealthArgs),
    /// Import from another password manager or a browser: new items are
    /// created, repeats merged, and no password is lost (ADR 0024).
    Import(ImportArgs),
    /// Run a command with secrets in its environment (`klav.toml`).
    Run(RunArgs),
    /// Write secrets into a file or a named pipe (template or one reference).
    Inject(InjectArgs),
    /// AI agents: register one (agent side); list, approve or deny them
    /// (person side).
    #[command(subcommand)]
    Agent(AgentCommand),
    /// The credential proxy (ADR 0036): which agent it is, what it holds,
    /// and granting or taking away credentials one by one (person side).
    #[command(subcommand)]
    Proxy(ProxyCommand),
    /// Sandboxes an issuer agent starts through the account's credential
    /// proxy (ADR 0036 §4): their API keys stay with the proxy (agent side).
    #[command(subcommand)]
    Sandbox(SandboxCommand),
    /// Requests of agents waiting for your approval (`ask` in their policy).
    #[command(subcommand)]
    Approval(ApprovalCommand),
    /// Task requests of agents: several items and permissions for one job,
    /// approved with one card (person side, ADR 0021).
    #[command(subcommand)]
    Task(TaskCommand),
    /// The audit log: who used what, when and why; `log verify` checks it.
    Log(LogArgs),
    /// Browser extension: native messaging host manifests.
    #[command(subcommand)]
    Extension(ExtensionCommand),
    /// MCP server over stdio for an AI agent, with the agent's identity
    /// (`klav client connect` sets it up in a client).
    Mcp(McpArgs),
    /// Agent clients (Claude Code, Claude Desktop, Codex, Cursor, VS Code):
    /// connect Klav's MCP server and skill to them, or disconnect it.
    #[command(subcommand)]
    Client(ClientCommand),
    /// The Klav skill in the agent clients' skill folders: install it and
    /// keep it up to date without overwriting a copy someone edited.
    #[command(subcommand)]
    Skill(SkillCommand),
}

/// `klav client …` (ADR 0033 §1).
#[derive(Debug, Subcommand)]
pub(crate) enum ClientCommand {
    /// Which clients are here and how Klav is set up in each one. Changes
    /// nothing.
    #[command(alias = "ls")]
    List(JsonFlag),
    /// Connect a client: register its agent (or use the one it has), add
    /// the `klav` entry to its MCP settings (with a backup) and install the
    /// skill. Shows what it will change first.
    Connect(ClientConnectArgs),
    /// Remove Klav's entry (and skill) from a client. The agent keeps its
    /// access: pause or revoke it for that.
    Disconnect(ClientDisconnectArgs),
    /// Put back the client's settings file as it was before Klav's last
    /// change (from `$KLAV_HOME/client-backups`).
    Restore(ClientRestoreArgs),
}

/// A client Klav knows.
pub(crate) use crate::clients::ClientId as ClientArg;

#[derive(Debug, Args)]
pub(crate) struct ClientConnectArgs {
    /// The client.
    #[arg(value_enum)]
    pub(crate) client: ClientArg,
    /// Agent name (default: the client's name, e.g. `cursor`).
    #[arg(long)]
    pub(crate) agent: Option<String>,
    /// Do not install the skill.
    #[arg(long)]
    pub(crate) no_skill: bool,
    /// Show what would change and change nothing.
    #[arg(long)]
    pub(crate) dry_run: bool,
    /// Write without asking (needed without a terminal).
    #[arg(long, short = 'y')]
    pub(crate) yes: bool,
    /// Replace a `klav` entry Klav did not write, or one that changed since
    /// it did (a copy is kept).
    #[arg(long, conflicts_with = "adopt")]
    pub(crate) replace: bool,
    /// Keep a `klav` entry Klav did not write as Klav's, as it is, if it
    /// runs a `klav` program.
    #[arg(long)]
    pub(crate) adopt: bool,
    /// Only write if the settings file still has this SHA-256 (the
    /// `file_sha256` of `--dry-run --json`).
    #[arg(long, value_name = "HEX")]
    pub(crate) expect_sha256: Option<String>,
    /// Where a new agent keeps its private key.
    #[arg(long, value_enum, default_value = "auto")]
    pub(crate) key_store: KeyStoreArg,
    #[command(flatten)]
    pub(crate) json: JsonFlag,
}

#[derive(Debug, Args)]
pub(crate) struct ClientDisconnectArgs {
    /// The client.
    #[arg(value_enum)]
    pub(crate) client: ClientArg,
    /// Leave the skill where it is.
    #[arg(long)]
    pub(crate) keep_skill: bool,
    /// Show what would change and change nothing.
    #[arg(long)]
    pub(crate) dry_run: bool,
    /// Do not ask (needed without a terminal).
    #[arg(long, short = 'y')]
    pub(crate) yes: bool,
    /// Also remove a Klav entry or skill that changed since Klav wrote it
    /// (a copy of the settings is kept).
    #[arg(long)]
    pub(crate) force: bool,
    #[command(flatten)]
    pub(crate) json: JsonFlag,
}

#[derive(Debug, Args)]
pub(crate) struct ClientRestoreArgs {
    /// The client.
    #[arg(value_enum)]
    pub(crate) client: ClientArg,
    /// Restore even if the file changed since Klav wrote it (its current
    /// content is kept as another backup).
    #[arg(long)]
    pub(crate) force: bool,
    #[command(flatten)]
    pub(crate) json: JsonFlag,
}

/// `klav skill …` (ADR 0033 §6).
#[derive(Debug, Subcommand)]
pub(crate) enum SkillCommand {
    /// The skill this `klav` carries, and every copy found in the clients'
    /// folders: up to date, older, edited, removed or not Klav's.
    Status(JsonFlag),
    /// Install the skill (default: in the folders of the clients installed
    /// here).
    Install(SkillInstallArgs),
    /// Replace Klav's unchanged copies that are older than this `klav`'s
    /// skill. Edited copies are never overwritten.
    Update(SkillUpdateArgs),
    /// Remove Klav's copies of the skill.
    Uninstall(SkillUninstallArgs),
    /// Print the skill this `klav` carries.
    Show,
}

/// Where `klav skill install|uninstall` work.
#[derive(Debug, Args)]
pub(crate) struct SkillWhere {
    /// The folders of this client (repeatable).
    #[arg(long = "client", value_enum, conflicts_with = "dirs")]
    pub(crate) clients: Vec<ClientArg>,
    /// A skills folder: the skill goes in `<DIR>/klav/SKILL.md`
    /// (repeatable).
    #[arg(long = "dir", value_name = "DIR")]
    pub(crate) dirs: Vec<PathBuf>,
}

#[derive(Debug, Args)]
pub(crate) struct SkillInstallArgs {
    #[command(flatten)]
    pub(crate) place: SkillWhere,
    /// Show what would change and change nothing.
    #[arg(long)]
    pub(crate) dry_run: bool,
    /// Replace a copy that is not Klav's, or that someone edited: it is
    /// kept next to it as `SKILL.md.mine-<time>`.
    #[arg(long, conflicts_with = "adopt")]
    pub(crate) replace: bool,
    /// Keep a copy Klav did not write as Klav's, if it is identical to a
    /// skill Klav published.
    #[arg(long)]
    pub(crate) adopt: bool,
    #[command(flatten)]
    pub(crate) json: JsonFlag,
}

#[derive(Debug, Args)]
pub(crate) struct SkillUpdateArgs {
    /// Keep the edited copies as they are, and stop pointing them out
    /// until there is a newer skill.
    #[arg(long)]
    pub(crate) keep_mine: bool,
    /// Only the copy in this skills folder (repeatable).
    #[arg(long = "dir", value_name = "DIR")]
    pub(crate) dirs: Vec<PathBuf>,
    #[command(flatten)]
    pub(crate) json: JsonFlag,
}

#[derive(Debug, Args)]
pub(crate) struct SkillUninstallArgs {
    #[command(flatten)]
    pub(crate) place: SkillWhere,
    /// Also remove a copy someone edited.
    #[arg(long)]
    pub(crate) force: bool,
    #[command(flatten)]
    pub(crate) json: JsonFlag,
}

#[derive(Debug, Args)]
pub(crate) struct McpArgs {
    /// Agent name (default: `$KLAV_AGENT` or the only one).
    #[arg(long, env = "KLAV_AGENT")]
    pub(crate) agent: Option<String>,
    /// How long a tool waits for the person when the policy says `ask`
    /// (each call can ask for another `wait_seconds`, up to 10 min).
    #[arg(long, value_name = "DURATION", default_value = "60s", value_parser = parse_duration)]
    pub(crate) wait: std::time::Duration,
}

#[derive(Debug, Args)]
#[command(args_conflicts_with_subcommands = true)]
pub(crate) struct LogArgs {
    #[command(subcommand)]
    pub(crate) command: Option<LogCommand>,
    /// Only events about this item (reference, ID or title).
    #[arg(long)]
    pub(crate) item: Option<String>,
    /// Only events of this agent (name or ID).
    #[arg(long)]
    pub(crate) agent: Option<String>,
    /// Only events in this vault.
    #[arg(long)]
    pub(crate) vault: Option<String>,
    /// From: a duration back from now (`24h`, `7d`), a date (`2026-11-02`)
    /// or a UTC time (`2026-11-02T14:30`).
    #[arg(long, value_name = "WHEN", value_parser = parse_when)]
    pub(crate) since: Option<i64>,
    /// Until (same formats as `--since`; a date means its end).
    #[arg(long, value_name = "WHEN", value_parser = parse_until)]
    pub(crate) until: Option<i64>,
    /// Only events with alerts (first use, bursts, denials).
    #[arg(long)]
    pub(crate) alerts: bool,
    /// Only events with this permission (`fill`, `inject`, `totp`,
    /// `reveal`, `list`, `create`, `update`, `delete`, `passkey`,
    /// `rotate`). Repeat it for several.
    #[arg(long = "permission", value_name = "PERMISSION", value_parser = parse_permission)]
    pub(crate) permissions: Vec<klav_core::policy::Permission>,
    /// Only events with this outcome: `allow`, `ask` or `deny` (the
    /// policy), `approve` (the person's decision). Repeat it for several.
    #[arg(long = "outcome", value_name = "OUTCOME", value_parser = ["allow", "ask", "deny", "approve"])]
    pub(crate) outcomes: Vec<String>,
    /// Only events whose item, agent, reason or site contain this text.
    #[arg(long, value_name = "TEXT")]
    pub(crate) text: Option<String>,
    /// The summary of one task: who approved it, every use, what was
    /// approved outside it and how it ended (ID or its first characters).
    #[arg(long, value_name = "ID", conflicts_with_all = ["item", "agent", "vault", "since", "until", "alerts", "csv", "permissions", "outcomes", "text"])]
    pub(crate) task: Option<String>,
    /// At most this many events (newest first).
    #[arg(long, short = 'n', default_value_t = 50)]
    pub(crate) limit: usize,
    /// JSON output (every matching event, ignores `--limit`).
    #[arg(long, conflicts_with = "csv")]
    pub(crate) json: bool,
    /// CSV output (every matching event, ignores `--limit`).
    #[arg(long)]
    pub(crate) csv: bool,
}

#[derive(Debug, Subcommand)]
pub(crate) enum LogCommand {
    /// Check the hash chain, the signatures in it and the signed heads; then
    /// sign the current head with this device. Exit code 3 if it was altered.
    Verify(JsonFlag),
    /// Forget this device's copy of the log and the head it verified, after
    /// the server was restored from a backup you trust: from then on this
    /// device takes the server's chain as it is now as the good one. Asks
    /// first. No network.
    Reset(LogResetArgs),
}

#[derive(Debug, Args)]
pub(crate) struct LogResetArgs {
    /// Do not ask: you accept the chain the server has now.
    #[arg(long)]
    pub(crate) yes: bool,
}

/// `--permission`: one of the permissions of a policy (design §5.2).
pub(crate) fn parse_permission(text: &str) -> Result<klav_core::policy::Permission, String> {
    serde_json::from_value(serde_json::Value::String(text.trim().to_lowercase())).map_err(|_| {
        format!(
            "unknown permission {text:?} (one of: list, fill, inject, totp, reveal, create, update, delete, passkey, rotate)"
        )
    })
}

/// `--since`: a duration back from now, a date or a UTC date and time.
pub(crate) fn parse_when(text: &str) -> Result<i64, String> {
    crate::time::parse_when(text, false)
}

/// `--until`: like `--since`, but a bare date means the end of that day.
pub(crate) fn parse_until(text: &str) -> Result<i64, String> {
    crate::time::parse_when(text, true)
}

#[derive(Debug, Subcommand)]
pub(crate) enum ApprovalCommand {
    /// Pending requests (`--all`: also the recent decided ones).
    #[command(alias = "ls")]
    List {
        /// Include decided and expired requests.
        #[arg(long)]
        all: bool,
        #[command(flatten)]
        json: JsonFlag,
    },
    /// Approve a request (Touch ID or the master password).
    Approve {
        /// Request ID (or its first characters).
        id: String,
        /// Approve the same action on the same item for this long (e.g.
        /// `15m`, at most `24h`) instead of once.
        #[arg(long = "for", value_name = "DURATION", value_parser = parse_duration, conflicts_with = "add_to_task")]
        lease: Option<std::time::Duration>,
        /// «Add to the task»: add it to the agent's running task (same
        /// end time) and approve this request once.
        #[arg(long)]
        add_to_task: bool,
        /// Do not ask for confirmation after showing the request.
        #[arg(long, short = 'y')]
        yes: bool,
    },
    /// Deny a request.
    Deny {
        /// Request ID (or its first characters).
        id: String,
    },
    /// Wait, as the agent, until the person decides on its request (agent
    /// side). Exit code: 0 approved, 4 still pending at `--timeout`, 5
    /// denied, 6 expired.
    Wait {
        /// Request ID (the full `pending_approval_id`).
        id: String,
        /// Give up after this long (the request itself expires 10 minutes
        /// after it was made).
        #[arg(long, value_name = "DURATION", default_value = "10m", value_parser = parse_duration)]
        timeout: std::time::Duration,
        /// Agent name (default: `$KLAV_AGENT` or the only one).
        #[arg(long, env = "KLAV_AGENT")]
        agent: Option<String>,
        #[command(flatten)]
        json: JsonFlag,
    },
}

#[derive(Debug, Subcommand)]
pub(crate) enum TaskCommand {
    /// Pending and running tasks (`--all`: also the recent ended ones).
    #[command(alias = "ls")]
    List {
        /// Include denied, expired and ended tasks.
        #[arg(long)]
        all: bool,
        #[command(flatten)]
        json: JsonFlag,
    },
    /// The card of a task: what Klav proposes (pending) or what was
    /// approved.
    Show {
        /// Task ID (or its first characters).
        id: String,
        #[command(flatten)]
        json: JsonFlag,
    },
    /// Approve a task as the card proposes it, minus what you leave out
    /// (Touch ID or the master password).
    Approve {
        /// Task ID (or its first characters).
        id: String,
        /// Leave out an item, or one of its permissions: `REF` or
        /// `REF:permission` (REF: `klav://…`, the title or the item ID).
        /// Repeatable.
        #[arg(long, value_name = "REF[:PERMISSION]")]
        without: Vec<String>,
        /// End it sooner than the agent asked (e.g. `1h`; at least `5m`).
        #[arg(long = "for", value_name = "DURATION", value_parser = parse_duration)]
        duration: Option<std::time::Duration>,
        /// Do not ask for confirmation after showing the card.
        #[arg(long, short = 'y')]
        yes: bool,
        #[command(flatten)]
        json: JsonFlag,
    },
    /// Deny a task.
    Deny {
        /// Task ID (or its first characters).
        id: String,
        #[command(flatten)]
        json: JsonFlag,
    },
    /// End a running task now («End task»).
    End {
        /// Task ID (or its first characters).
        id: String,
        #[command(flatten)]
        json: JsonFlag,
    },
}

#[derive(Debug, Subcommand)]
pub(crate) enum AgentTaskCommand {
    /// Ask the person for a task described in a file (`tarea.toml` or
    /// `.json`; `-` reads JSON from stdin). Exit code: 0 approved, 4
    /// pending, 5 denied, 6 expired.
    Request {
        /// The task file.
        file: PathBuf,
        /// Wait for the person (default `10m` when given without a value).
        #[arg(long, value_name = "DURATION", num_args = 0..=1, default_missing_value = "10m", value_parser = parse_duration)]
        wait: Option<std::time::Duration>,
        /// Agent name (default: `$KLAV_AGENT` or the only one).
        #[arg(long, env = "KLAV_AGENT")]
        agent: Option<String>,
        #[command(flatten)]
        json: JsonFlag,
    },
    /// Wait until the person decides on a task. Exit code: 0 approved, 4
    /// still pending at `--timeout`, 5 denied (or ended by the person), 6
    /// expired.
    Wait {
        /// Task ID (the full `pending_task_id`).
        id: String,
        /// Give up after this long (a task request expires 10 minutes
        /// after it was made).
        #[arg(long, value_name = "DURATION", default_value = "10m", value_parser = parse_duration)]
        timeout: std::time::Duration,
        /// Agent name (default: `$KLAV_AGENT` or the only one).
        #[arg(long, env = "KLAV_AGENT")]
        agent: Option<String>,
        #[command(flatten)]
        json: JsonFlag,
    },
    /// A task of this agent: its state and what the person approved.
    Show {
        /// Task ID.
        id: String,
        /// Agent name (default: `$KLAV_AGENT` or the only one).
        #[arg(long, env = "KLAV_AGENT")]
        agent: Option<String>,
        #[command(flatten)]
        json: JsonFlag,
    },
    /// End a task of this agent when the job is done.
    End {
        /// Task ID.
        id: String,
        /// Why (mandatory; logged).
        #[arg(long)]
        reason: String,
        /// Agent name (default: `$KLAV_AGENT` or the only one).
        #[arg(long, env = "KLAV_AGENT")]
        agent: Option<String>,
        #[command(flatten)]
        json: JsonFlag,
    },
}

#[derive(Debug, Subcommand)]
pub(crate) enum AgentCommand {
    /// Register this machine as an agent of an account (agent side). Prints
    /// the six pairing words the person must see when approving it.
    Register(AgentRegisterArgs),
    /// State of a registered agent (agent side).
    Status(AgentStatusArgs),
    /// The account's agents (person side).
    #[command(alias = "ls")]
    List(JsonFlag),
    /// Current one-time password of an item, as the agent (agent side;
    /// `totp` is `ask` by default).
    Totp(AgentTotpArgs),
    /// Run a command with secrets in its environment, as the agent (agent
    /// side): `klav.toml` and `-e`; the output comes back with the values
    /// redacted.
    Run(AgentRunArgs),
    /// Write secrets into a new 0600 file, as the agent (agent side; never
    /// to stdout).
    Inject(AgentInjectArgs),
    /// Type a login or card into a browser page, over CDP or through Klav's
    /// extension, as the agent (agent side): the values never come back.
    Fill(AgentFillArgs),
    /// Name a browser so `klav mcp` can fill into it (`sdk:<name>`).
    #[command(subcommand)]
    Browser(BrowserCommand),
    /// Task requests: several items and permissions for one job, approved
    /// with one card (agent side, ADR 0021).
    #[command(subcommand)]
    Task(AgentTaskCommand),
    /// Approve an agent, or change its grant (person side; Touch ID or the
    /// master password).
    Approve(AgentApproveArgs),
    /// Deny a pending registration (person side).
    Deny {
        /// Agent name or ID.
        agent: String,
    },
    /// An agent, its grant and what it saw according to the audit log
    /// (person side).
    Show {
        /// Agent name or ID.
        agent: String,
        #[command(flatten)]
        json: JsonFlag,
    },
    /// Pause every agent, or one, now (person side, ADR 0033 §7): the
    /// server refuses all they ask until you resume. No Touch ID: pausing
    /// must cost nothing. With `klavd` running, `--all` works locked.
    Pause(AgentPauseArgs),
    /// Resume every agent, or one, after a pause (person side; Touch ID or
    /// the master password). Resuming every agent leaves the agents you
    /// paused one by one paused.
    Resume(AgentResumeArgs),
    /// Revoke an agent now and print what it saw (person side).
    Revoke {
        /// Agent name or ID.
        agent: String,
        /// Also rotate the keys of its projects and re-issue the grants of
        /// the other agents that share them.
        #[arg(long)]
        rotate: bool,
        /// Do not ask for confirmation.
        #[arg(long, short = 'y')]
        yes: bool,
        #[command(flatten)]
        json: JsonFlag,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub(crate) enum KeyStoreArg {
    /// The macOS keychain when available, else a file.
    Auto,
    /// The macOS login keychain.
    Keychain,
    /// A file with mode 0600.
    File,
}

#[derive(Debug, Args)]
pub(crate) struct AgentRegisterArgs {
    /// Name of the agent (shown to the person; also its local name).
    #[arg(long)]
    pub(crate) name: String,
    /// Server URL (default: the server of the account on this device,
    /// else https://api.klav.dev).
    #[arg(long, env = "KLAV_SERVER")]
    pub(crate) server: Option<String>,
    /// E-mail of the account to join (default: the account on this device).
    #[arg(long)]
    pub(crate) email: Option<String>,
    /// A note for the person (e.g. what the agent is for).
    #[arg(long)]
    pub(crate) note: Option<String>,
    /// Where to keep the agent's private key.
    #[arg(long, value_enum, default_value = "auto")]
    pub(crate) key_store: KeyStoreArg,
    /// Key file for `--key-store file` (default: `$KLAV_HOME/agents/<name>.key`).
    #[arg(long, value_name = "PATH")]
    pub(crate) key_file: Option<PathBuf>,
    /// Print the result as JSON on stdout: the agent ID, its public
    /// identity, the six words and when the request lapses.
    #[arg(long)]
    pub(crate) json: bool,
}

#[derive(Debug, Args)]
pub(crate) struct AgentPauseArgs {
    /// Agent name or ID.
    #[arg(required_unless_present = "all", conflicts_with = "all")]
    pub(crate) agent: Option<String>,
    /// Every agent of the account.
    #[arg(long)]
    pub(crate) all: bool,
    /// End the pause by itself after this long (e.g. `1h`); by default it
    /// lasts until you resume.
    #[arg(long = "for", value_name = "DURATION", value_parser = parse_duration)]
    pub(crate) duration: Option<std::time::Duration>,
    #[command(flatten)]
    pub(crate) json: JsonFlag,
}

#[derive(Debug, Args)]
pub(crate) struct AgentResumeArgs {
    /// Agent name or ID.
    #[arg(required_unless_present = "all", conflicts_with = "all")]
    pub(crate) agent: Option<String>,
    /// Every agent of the account.
    #[arg(long)]
    pub(crate) all: bool,
    #[command(flatten)]
    pub(crate) json: JsonFlag,
}

#[derive(Debug, Args)]
pub(crate) struct AgentStatusArgs {
    /// Agent name (default: `$KLAV_AGENT` or the only one).
    #[arg(long)]
    pub(crate) agent: Option<String>,
    /// Wait until the person approves or denies it.
    #[arg(long)]
    pub(crate) wait: bool,
    #[command(flatten)]
    pub(crate) json: JsonFlag,
}

#[derive(Debug, Args)]
pub(crate) struct AgentTotpArgs {
    /// `klav://Vault/Project/Item` (or `Item` with `project` in klav.toml).
    pub(crate) reference: String,
    /// Why the agent needs it (mandatory; the person sees it).
    #[arg(long)]
    pub(crate) reason: String,
    /// Field (default: the first one-time password field).
    #[arg(long)]
    pub(crate) field: Option<String>,
    /// Wait this long for the person when it needs approval (e.g. `2m`).
    #[arg(long, value_name = "DURATION", value_parser = parse_duration)]
    pub(crate) wait: Option<std::time::Duration>,
    /// Use this approval (the ID of a request the person approved, after
    /// `klav approval wait`); refused if it is for another action.
    #[arg(long, value_name = "ID")]
    pub(crate) approval: Option<String>,
    /// Agent name (default: `$KLAV_AGENT` or the only one).
    #[arg(long)]
    pub(crate) agent: Option<String>,
}

/// What every agent action takes.
#[derive(Debug, Args)]
pub(crate) struct AgentActionArgs {
    /// Why the agent needs it (mandatory; logged and shown to the person).
    #[arg(long)]
    pub(crate) reason: String,
    /// Wait this long for the person when it needs approval (e.g. `2m`).
    #[arg(long, value_name = "DURATION", value_parser = parse_duration)]
    pub(crate) wait: Option<std::time::Duration>,
    /// Use this approval (the ID of a request the person approved, after
    /// `klav approval wait`); refused if it is for another action.
    #[arg(long, value_name = "ID")]
    pub(crate) approval: Option<String>,
    /// Agent name (default: `$KLAV_AGENT` or the only one).
    #[arg(long)]
    pub(crate) agent: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct AgentRunArgs {
    #[command(flatten)]
    pub(crate) action: AgentActionArgs,
    /// Project file (default: the nearest `klav.toml`).
    #[arg(long, value_name = "PATH")]
    pub(crate) config: Option<PathBuf>,
    /// Extra variable `NAME=REF` (repeatable).
    #[arg(short = 'e', long = "env", value_name = "NAME=REF")]
    pub(crate) env: Vec<String>,
    /// Do not write the `[files]` of `klav.toml`.
    #[arg(long)]
    pub(crate) no_files: bool,
    /// Kill the command after this long.
    #[arg(long, value_name = "DURATION", default_value = "10m", value_parser = parse_duration)]
    pub(crate) timeout: std::time::Duration,
    /// The command and its arguments (after `--`).
    #[arg(trailing_var_arg = true, required = true, value_name = "COMMAND")]
    pub(crate) command: Vec<std::ffi::OsString>,
}

#[derive(Debug, Args)]
pub(crate) struct AgentInjectArgs {
    #[command(flatten)]
    pub(crate) action: AgentActionArgs,
    /// Template with `{{ klav://… }}` references.
    #[arg(
        short = 'i',
        long = "in-file",
        value_name = "PATH",
        conflicts_with = "reference",
        required_unless_present = "reference"
    )]
    pub(crate) template: Option<PathBuf>,
    /// One reference whose value is written as is.
    #[arg(short = 'r', long = "reference", value_name = "REF")]
    pub(crate) reference: Option<String>,
    /// Output file, created with mode 0600.
    #[arg(short = 'o', long = "out-file", value_name = "PATH")]
    pub(crate) out: PathBuf,
    /// Replace the output file if it exists.
    #[arg(long)]
    pub(crate) force: bool,
    /// Remove the file after this long (waits in the foreground).
    #[arg(long, value_name = "DURATION", value_parser = parse_duration)]
    pub(crate) ttl: Option<std::time::Duration>,
    /// Project file for short references (default: nearest `klav.toml`).
    #[arg(long, value_name = "PATH")]
    pub(crate) config: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub(crate) struct AgentFillArgs {
    #[command(flatten)]
    pub(crate) action: AgentActionArgs,
    /// `klav://Vault/Project/Item` (username and password, or the card)
    /// or `…/Item/field`.
    pub(crate) reference: String,
    /// The browser's CDP address (`http://127.0.0.1:9222`).
    #[arg(
        long,
        value_name = "URL",
        conflicts_with_all = ["session", "extension"],
        required_unless_present_any = ["session", "extension"]
    )]
    pub(crate) cdp: Option<String>,
    /// Tab (CDP target ID); default: the first tab.
    #[arg(long, value_name = "ID")]
    pub(crate) target: Option<String>,
    /// A browser registered with `klav agent browser register`.
    #[arg(long, value_name = "NAME", conflicts_with = "extension")]
    pub(crate) session: Option<String>,
    /// The active tab of the person's browser, through Klav's extension.
    #[arg(long)]
    pub(crate) extension: bool,
    /// CSS selector for a field: `password=#pass` (repeatable).
    #[arg(long = "selector", value_name = "FIELD=CSS")]
    pub(crate) selectors: Vec<String>,
    /// Submit the form after filling.
    #[arg(long)]
    pub(crate) submit: bool,
    /// Print the report as JSON (field names and addresses, never values).
    #[arg(long)]
    pub(crate) json: bool,
    /// Project file (default: nearest `klav.toml`).
    #[arg(long, value_name = "PATH")]
    pub(crate) config: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
pub(crate) enum BrowserCommand {
    /// Register a browser (CDP address and tab) as `sdk:<name>`.
    Register {
        /// Session name.
        name: String,
        /// The browser's CDP address (`http://127.0.0.1:9222`).
        #[arg(long, value_name = "URL")]
        cdp: String,
        /// Tab (CDP target ID); default: the first tab.
        #[arg(long, value_name = "ID")]
        target: Option<String>,
    },
    /// Forget a registered browser.
    Forget {
        /// Session name.
        name: String,
    },
}

/// `klav proxy …` (ADR 0036 §14): the person's commands. An agent never
/// runs them: `use`, `grant` and `revoke` ask for Touch ID or the master
/// password.
#[derive(Debug, Subcommand)]
pub(crate) enum ProxyCommand {
    /// The account's credential proxy, its 6 words, the credentials and
    /// profiles it holds, and what is lost without one. Never a value.
    Status(JsonFlag),
    /// Set which agent is the account's credential proxy: `use own AGENT`,
    /// or `use none`. Pair the proxy first with `klav-proxy init`.
    Use(ProxyUseArgs),
    /// Grant one credential to the proxy with a profile: where its value
    /// may go and how. Shows the profile, then asks for Touch ID.
    Grant(Box<ProxyGrantArgs>),
    /// Take one credential away from the proxy and change the item's key.
    Revoke(ProxyRevokeArgs),
    /// Let an agent start sandboxes through the proxy, or stop it. Run it
    /// yourself: it asks for Touch ID, and an agent must never run it.
    #[command(subcommand)]
    Issuer(ProxyIssuerCommand),
    /// The sandboxes of the account's proxy, from the verified log and the
    /// proxy's heartbeat; `revoke` takes one or all of them away.
    Sandboxes(ProxySandboxesArgs),
}

/// `klav proxy sandboxes [--ended] [--json]` and its `revoke`.
#[derive(Debug, Args)]
#[command(args_conflicts_with_subcommands = true)]
pub(crate) struct ProxySandboxesArgs {
    #[command(subcommand)]
    pub(crate) command: Option<ProxySandboxesCommand>,
    /// Also those that ended, and those whose proxy was revoked.
    #[arg(long)]
    pub(crate) ended: bool,
    #[command(flatten)]
    pub(crate) json: JsonFlag,
}

#[derive(Debug, Subcommand)]
pub(crate) enum ProxySandboxesCommand {
    /// Revoke one sandbox of the account's proxy, or all it issued so far.
    /// Signed with the account, without Touch ID: it only takes access
    /// away. Run it yourself: an agent must never run it.
    Revoke(ProxySandboxRevokeArgs),
}

#[derive(Debug, Args)]
pub(crate) struct ProxySandboxRevokeArgs {
    /// The sandbox's ID, whole or its first 8 characters as the list shows
    /// them.
    #[arg(required_unless_present = "all", conflicts_with = "all")]
    pub(crate) id: Option<String>,
    /// Every sandbox of the account's proxy issued so far.
    #[arg(long)]
    pub(crate) all: bool,
    /// Wait until the proxy logs their end (at most 2 minutes).
    #[arg(long)]
    pub(crate) wait: bool,
    #[command(flatten)]
    pub(crate) json: JsonFlag,
}

#[derive(Debug, Subcommand)]
pub(crate) enum SandboxCommand {
    /// Start a sandbox and hand its one-time package to the command after
    /// `--` (in `KLAV_SANDBOX`) or to a new file (`--package-file`). The
    /// package is never printed.
    Start(Box<SandboxStartArgs>),
    /// This agent's live sandboxes.
    Ls(SandboxLsArgs),
    /// End one of this agent's sandboxes now, or all of them.
    Stop(SandboxStopArgs),
}

/// What every `klav sandbox` command takes.
#[derive(Debug, Args)]
pub(crate) struct SandboxAgentArgs {
    /// Agent name (default: `$KLAV_AGENT` or the only one).
    #[arg(long)]
    pub(crate) agent: Option<String>,
    /// Port of `klav-proxy serve` on this machine.
    #[arg(long = "proxy-port", value_name = "PORT", default_value_t = klav_sdk::sandbox::DEFAULT_PROXY_PORT)]
    pub(crate) proxy_port: u16,
}

#[derive(Debug, Args)]
pub(crate) struct SandboxStartArgs {
    /// What the sandbox is for, as the person will see it (`chat-123`).
    #[arg(long)]
    pub(crate) label: String,
    /// A profile of the proxy the sandbox may use (repeat for more).
    #[arg(long = "profile", value_name = "PROFILE", required = true)]
    pub(crate) profiles: Vec<String>,
    /// How long it may live (`8h`, `90m`; default 8h, or this agent's
    /// limit if the person set a shorter one; never past that limit).
    #[arg(long, value_name = "DURATION", value_parser = parse_duration)]
    pub(crate) ttl: Option<std::time::Duration>,
    /// Write the package to this new file (mode 0600) instead of running a
    /// command; for a program that passes it on and deletes the file.
    #[arg(long = "package-file", value_name = "PATH", conflicts_with = "command")]
    pub(crate) package_file: Option<PathBuf>,
    #[command(flatten)]
    pub(crate) target: SandboxAgentArgs,
    #[command(flatten)]
    pub(crate) json: JsonFlag,
    /// The command that creates the sandbox, run with the package in
    /// `KLAV_SANDBOX` (after `--`).
    #[arg(trailing_var_arg = true, value_name = "COMMAND")]
    pub(crate) command: Vec<std::ffi::OsString>,
}

#[derive(Debug, Args)]
pub(crate) struct SandboxLsArgs {
    #[command(flatten)]
    pub(crate) target: SandboxAgentArgs,
    #[command(flatten)]
    pub(crate) json: JsonFlag,
}

#[derive(Debug, Args)]
pub(crate) struct SandboxStopArgs {
    /// The sandbox's ID (from `klav sandbox start` or `ls`).
    #[arg(
        value_name = "ID",
        required_unless_present = "all",
        conflicts_with = "all"
    )]
    pub(crate) id: Option<String>,
    /// Every live sandbox of this agent.
    #[arg(long)]
    pub(crate) all: bool,
    #[command(flatten)]
    pub(crate) target: SandboxAgentArgs,
    #[command(flatten)]
    pub(crate) json: JsonFlag,
}

#[derive(Debug, Subcommand)]
pub(crate) enum ProxyIssuerCommand {
    /// Let AGENT start sandboxes through the account's proxy, with some of
    /// its profiles. Shows what it signs, then asks for Touch ID.
    Add(Box<ProxyIssuerAddArgs>),
    /// Stop AGENT from starting sandboxes.
    Remove(ProxyIssuerRemoveArgs),
}

#[derive(Debug, Args)]
pub(crate) struct ProxyIssuerAddArgs {
    /// The agent: name or ID.
    pub(crate) agent: String,
    /// A profile of the proxy its sandboxes may use (repeat for more).
    #[arg(long = "profile", value_name = "PROFILE", required = true)]
    pub(crate) profiles: Vec<String>,
    /// Where a sandbox reaches the proxy: `tls://host:port`.
    #[arg(long, value_name = "URL")]
    pub(crate) url: String,
    /// Longest a sandbox it starts may live (`8h`, `90m`; at most 24h).
    #[arg(long = "max-ttl", value_name = "DURATION", value_parser = parse_duration)]
    pub(crate) max_ttl: Option<std::time::Duration>,
    /// Most of its sandboxes alive at once (default 3).
    #[arg(long = "max-live", value_name = "N")]
    pub(crate) max_live: Option<u32>,
    /// Make each `inject` of this agent ask you first (recommended: an
    /// issuer could otherwise hand a provider's token to the command that
    /// creates the sandbox).
    #[arg(long = "inject-ask")]
    pub(crate) inject_ask: bool,
    /// The agent's 6 pairing words, when it is still pending (asked if
    /// missing).
    #[arg(long, value_name = "WORDS")]
    pub(crate) words: Option<String>,
    /// Every device and klav-proxy runs a Klav with sandbox issuers: needed
    /// for the account's first issuer, which older ones cannot read.
    #[arg(long = "every-device-is-updated")]
    pub(crate) every_device_updated: bool,
    #[command(flatten)]
    pub(crate) json: JsonFlag,
}

#[derive(Debug, Args)]
pub(crate) struct ProxyIssuerRemoveArgs {
    /// The agent: name or ID.
    pub(crate) agent: String,
    #[command(flatten)]
    pub(crate) json: JsonFlag,
}

/// `klav proxy use` mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum ProxyUseMode {
    /// Your own proxy, an agent of the account.
    Own,
    /// No proxy.
    None,
}

#[derive(Debug, Args)]
pub(crate) struct ProxyUseArgs {
    /// `own` or `none`.
    #[arg(value_enum)]
    pub(crate) mode: ProxyUseMode,
    /// The proxy's agent name or ID (with `own`).
    pub(crate) agent: Option<String>,
    #[command(flatten)]
    pub(crate) json: JsonFlag,
}

#[derive(Debug, Args)]
pub(crate) struct ProxyGrantArgs {
    /// The item: title, ID or `vault/project/item`.
    pub(crate) item: String,
    /// Start from a provider's profile: `northflank` (GET, POST and PATCH
    /// on api.northflank.com; DELETE asks you; PUT is refused; nothing in
    /// it guards role or token changes by path, so a POST or PATCH that
    /// changes a role or a token goes through like any other call). Each
    /// flag you also give replaces that part of it. `railway` and `maple`
    /// need modes the proxy does not have yet.
    #[arg(long, value_name = "NAME")]
    pub(crate) preset: Option<String>,
    /// Profile name: the first segment of the proxy's local URL
    /// (`http://127.0.0.1:8790/<profile>/…`).
    #[arg(long, required_unless_present = "preset")]
    pub(crate) profile: Option<String>,
    /// Where requests go: `https://host` or `https://host:port`.
    #[arg(long, required_unless_present = "preset")]
    pub(crate) upstream: Option<String>,
    /// The header the value goes in (`authorization`).
    #[arg(long, required_unless_present = "preset")]
    pub(crate) header: Option<String>,
    /// Text before the value (`"Bearer "`; default: none).
    #[arg(long)]
    pub(crate) prefix: Option<String>,
    /// The field holding the value (default: the item's main secret).
    #[arg(long)]
    pub(crate) field: Option<String>,
    /// HTTP methods let through (comma-separated or repeated).
    #[arg(long = "method", value_name = "METHOD", value_delimiter = ',')]
    pub(crate) methods: Vec<String>,
    /// Path prefixes let through (`/v1`; `/` for every path).
    #[arg(long = "path-prefix", value_name = "PREFIX")]
    pub(crate) path_prefixes: Vec<String>,
    /// Every call asks you first instead of going through.
    #[arg(long)]
    pub(crate) ask: bool,
    /// More methods, each call of which asks you first.
    #[arg(long = "ask-method", value_name = "METHOD", value_delimiter = ',')]
    pub(crate) ask_methods: Vec<String>,
    /// Most calls per minute through this profile.
    #[arg(long = "rate", value_name = "PER_MINUTE")]
    pub(crate) rate: Option<u32>,
    /// The proxy's 6 pairing words, for its first credential (asked if
    /// missing).
    #[arg(long, value_name = "WORDS")]
    pub(crate) words: Option<String>,
    /// Every device of the account runs a Klav with per-item grants: needed
    /// for the account's first one, which older devices cannot read.
    #[arg(long = "every-device-is-updated")]
    pub(crate) every_device_updated: bool,
    #[command(flatten)]
    pub(crate) json: JsonFlag,
}

#[derive(Debug, Args)]
pub(crate) struct ProxyRevokeArgs {
    /// The item: title or ID.
    pub(crate) item: String,
    #[command(flatten)]
    pub(crate) json: JsonFlag,
}

#[derive(Debug, Args)]
pub(crate) struct AgentApproveArgs {
    /// Agent name or ID.
    pub(crate) agent: String,
    /// Project to share: `vault/project` (repeatable).
    #[arg(long = "project", value_name = "VAULT/PROJECT")]
    pub(crate) projects: Vec<String>,
    /// Share every project of a vault (repeatable).
    #[arg(long = "vault", value_name = "VAULT")]
    pub(crate) vaults: Vec<String>,
    /// Allow permissions (comma-separated: list, fill, inject, totp, reveal,
    /// create, update, delete).
    #[arg(long, value_name = "PERMS", value_delimiter = ',')]
    pub(crate) allow: Vec<String>,
    /// Ask the person each time for these permissions.
    #[arg(long, value_name = "PERMS", value_delimiter = ',')]
    pub(crate) ask: Vec<String>,
    /// Deny these permissions.
    #[arg(long, value_name = "PERMS", value_delimiter = ',')]
    pub(crate) deny: Vec<String>,
    /// Allow `fill` only on these hosts (`example.com`, `*.example.com`).
    #[arg(long = "fill-domain", value_name = "PATTERN")]
    pub(crate) fill_domains: Vec<String>,
    /// Only work inside this weekly window, e.g. `mon-fri 09:00-18:00 -06:00`
    /// (repeatable).
    #[arg(long = "hours", value_name = "WINDOW")]
    pub(crate) hours: Vec<String>,
    /// The grant stops working after this long (e.g. `8h`, `30d`).
    #[arg(long, value_name = "DURATION", value_parser = parse_duration)]
    pub(crate) expires: Option<std::time::Duration>,
    /// A policy file (JSON, `docs/diseno.md` §5.2) used as the base.
    #[arg(long, value_name = "PATH")]
    pub(crate) policy_file: Option<PathBuf>,
    /// The six pairing words shown by the agent (asked if missing). Only
    /// for a pending agent: an active one's words are inside its grant.
    #[arg(long, value_name = "WORDS")]
    pub(crate) words: Option<String>,
    /// An active agent: also change the key of each project taken away,
    /// and give the other agents that hold it a new grant.
    #[arg(long)]
    pub(crate) rotate_removed: bool,
    /// An active agent: sign the differences without asking `[y/N]` (a
    /// change that widens still asks for Touch ID or the master password).
    #[arg(long, short = 'y')]
    pub(crate) yes: bool,
}

#[derive(Debug, Args)]
pub(crate) struct RunArgs {
    /// Project file (default: the nearest `klav.toml` from the current
    /// directory upwards).
    #[arg(long, value_name = "PATH")]
    pub(crate) config: Option<PathBuf>,
    /// Extra variable `NAME=klav://…` (repeatable).
    #[arg(short = 'e', long = "env", value_name = "NAME=REF")]
    pub(crate) env: Vec<String>,
    /// Do not write the `[files]` of `klav.toml`.
    #[arg(long)]
    pub(crate) no_files: bool,
    /// Use a `klav.toml` that is new or changed since you approved it
    /// without asking (it is pinned as approved).
    #[arg(long)]
    pub(crate) trust: bool,
    /// The command and its arguments (after `--`).
    #[arg(trailing_var_arg = true, required = true, value_name = "COMMAND")]
    pub(crate) command: Vec<std::ffi::OsString>,
}

#[derive(Debug, Args)]
pub(crate) struct InjectArgs {
    /// Template with `{{ klav://… }}` references (default: stdin).
    #[arg(
        short = 'i',
        long = "in-file",
        value_name = "PATH",
        conflicts_with = "reference"
    )]
    pub(crate) template: Option<PathBuf>,
    /// One reference whose value (text or file) is written as is.
    #[arg(short = 'r', long = "reference", value_name = "REF")]
    pub(crate) reference: Option<String>,
    /// Output file, created with mode 0600 (default: stdout).
    #[arg(short = 'o', long = "out-file", value_name = "PATH")]
    pub(crate) out: Option<PathBuf>,
    /// Replace the output file if it exists.
    #[arg(long)]
    pub(crate) force: bool,
    /// Remove the file after this long (e.g. `30s`, `10m`, `1h`); `klav`
    /// waits in the foreground and also removes it on Ctrl-C/SIGTERM.
    #[arg(long, value_name = "DURATION", value_parser = parse_duration)]
    pub(crate) ttl: Option<std::time::Duration>,
    /// Serve the value through a named pipe at `--out-file` (Unix): it is
    /// read once and never touches the disk. Waits for the reader up to
    /// `--ttl` (default 10m).
    #[arg(long, requires = "out")]
    pub(crate) fifo: bool,
    /// Project file for short references (default: nearest `klav.toml`).
    #[arg(long, value_name = "PATH")]
    pub(crate) config: Option<PathBuf>,
}

/// `90`, `30s`, `10m`, `1h`, `1d`.
pub(crate) fn parse_duration(text: &str) -> Result<std::time::Duration, String> {
    let text = text.trim();
    let split = text
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(text.len());
    let (number, unit) = text.split_at(split);
    let n: u64 = number
        .parse()
        .map_err(|_| format!("invalid duration {text:?} (try 30s, 10m, 1h)"))?;
    let secs = match unit {
        "" | "s" => n,
        "m" => n.saturating_mul(60),
        "h" => n.saturating_mul(3600),
        "d" => n.saturating_mul(86_400),
        _ => return Err(format!("invalid duration unit {unit:?} (s, m, h or d)")),
    };
    if secs == 0 {
        return Err("the duration must be positive".into());
    }
    Ok(std::time::Duration::from_secs(secs))
}

#[derive(Debug, Args)]
pub(crate) struct JsonFlag {
    /// Machine-readable JSON output.
    #[arg(long)]
    pub(crate) json: bool,
}

#[derive(Debug, Args)]
pub(crate) struct SignupArgs {
    /// Your own server's URL (https://…; http:// only for localhost).
    /// Default: https://api.klav.dev (klav.dev).
    #[arg(long, env = "KLAV_SERVER")]
    pub(crate) server: Option<String>,
    /// Account e-mail.
    #[arg(long)]
    pub(crate) email: String,
    /// Name of this device (default: the host name).
    #[arg(long)]
    pub(crate) device_name: Option<String>,
    /// Write the emergency kit (with the Secret Key) to this new file
    /// (mode 0600) instead of showing it on the terminal.
    #[arg(long)]
    pub(crate) emergency_kit: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub(crate) struct LoginArgs {
    /// Your own server's URL (the one in your emergency kit). Default:
    /// https://api.klav.dev (klav.dev).
    #[arg(long, env = "KLAV_SERVER")]
    pub(crate) server: Option<String>,
    /// Account e-mail.
    #[arg(long)]
    pub(crate) email: String,
    /// Name of this device (default: the host name).
    #[arg(long)]
    pub(crate) device_name: Option<String>,
    /// Read the Secret Key from an emergency kit file (else it is asked).
    #[arg(long)]
    pub(crate) emergency_kit: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
pub(crate) enum AccountCommand {
    /// Move the account on this device to another server URL: a full log-in
    /// there with the master password, kept only if the server has this
    /// same account (ADR 0028 §4). Also the way out if a domain is down.
    SetServer {
        /// The new server URL (taken as typed).
        url: String,
    },
    /// Show the emergency kit again, with the server this device uses today
    /// (asks for the master password: the kit shows the Secret Key).
    Kit {
        /// Write it to this new file (mode 0600) instead of the terminal.
        #[arg(long)]
        emergency_kit: Option<PathBuf>,
    },
    /// Delete the account: everything it has on the server, 7 days after
    /// you ask (ADR 0037). Only at a terminal: you type the account email,
    /// then Touch ID if `klavd` uses it, then the master password. Not with
    /// `--no-daemon` where Touch ID is set up.
    Delete {
        /// Cancel the deletion asked for, from any device. Asks for Touch
        /// ID through `klavd`, or the master password, like resuming
        /// agents.
        #[arg(long)]
        cancel: bool,
    },
}

#[derive(Debug, Args)]
pub(crate) struct LogoutArgs {
    /// Do not ask (needed without a terminal).
    #[arg(long, short = 'y')]
    pub(crate) yes: bool,
    /// Sign out even with generated passwords or passkeys not uploaded
    /// yet: they are lost with this device's copy.
    #[arg(long)]
    pub(crate) discard_unsent: bool,
}

#[derive(Debug, Args)]
pub(crate) struct UnlockArgs {
    /// Use the master password even if Touch ID is enrolled.
    #[arg(long)]
    pub(crate) password: bool,
    /// When `klavd` has to be started: lock after this long without use.
    #[arg(long, value_name = "DURATION", default_value = "15m", value_parser = parse_duration)]
    pub(crate) idle_lock: std::time::Duration,
}

#[derive(Debug, Args)]
pub(crate) struct LockArgs {
    /// Also stop `klavd`.
    #[arg(long)]
    pub(crate) stop: bool,
}

#[derive(Debug, Subcommand)]
pub(crate) enum VaultCommand {
    /// List vaults.
    Ls(JsonFlag),
    /// Create a vault (with a "General" project).
    Create {
        /// Name.
        name: String,
    },
}

#[derive(Debug, Subcommand)]
pub(crate) enum ProjectCommand {
    /// List projects.
    Ls {
        /// Only this vault.
        #[arg(long)]
        vault: Option<String>,
        #[command(flatten)]
        json: JsonFlag,
    },
    /// Create a project.
    Create {
        /// Vault name or ID.
        #[arg(long)]
        vault: Option<String>,
        /// Name.
        name: String,
    },
}

/// Item types accepted on the command line.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub(crate) enum KindArg {
    Login,
    Card,
    Identity,
    SshKey,
    Totp,
    Note,
    ApiKey,
}

/// Item types `item ls --kind` filters by (every listed type, plurals too).
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum ListKindArg {
    #[value(alias = "logins")]
    Login,
    #[value(alias = "cards")]
    Card,
    #[value(alias = "identities")]
    Identity,
    #[value(alias = "ssh", alias = "ssh-keys")]
    SshKey,
    #[value(alias = "files")]
    File,
    Totp,
    #[value(alias = "notes")]
    Note,
    #[value(alias = "api-keys")]
    ApiKey,
}

/// How to set field values (shared by `add` and `edit`).
#[derive(Debug, Args, Default)]
pub(crate) struct FieldArgs {
    /// Set a non-secret field: `NAME=VALUE` (repeatable).
    #[arg(short = 'f', long = "field", value_name = "NAME=VALUE")]
    pub(crate) fields: Vec<String>,
    /// Ask for a secret field on the TTY, without echo (repeatable).
    #[arg(short = 's', long = "secret", value_name = "NAME")]
    pub(crate) secrets: Vec<String>,
    /// Read a secret field from the next line of stdin (repeatable).
    #[arg(long = "secret-stdin", value_name = "NAME")]
    pub(crate) secrets_stdin: Vec<String>,
    /// Fill a secret field with a generated password (repeatable).
    #[arg(short = 'g', long = "generate", value_name = "NAME")]
    pub(crate) generate: Vec<String>,
    /// Add a URL (repeatable).
    #[arg(long = "url")]
    pub(crate) urls: Vec<String>,
    /// Add a tag (repeatable).
    #[arg(long = "tag")]
    pub(crate) tags: Vec<String>,
    /// Read the notes from the rest of stdin.
    #[arg(long)]
    pub(crate) notes_stdin: bool,
}

#[derive(Debug, Subcommand)]
pub(crate) enum ItemCommand {
    /// Add an item.
    Add {
        /// Type.
        kind: KindArg,
        /// Title (the item name in `klav://` references).
        #[arg(long)]
        title: String,
        /// Vault (default: Personal).
        #[arg(long)]
        vault: Option<String>,
        /// Project (default: General).
        #[arg(long)]
        project: Option<String>,
        /// Username (same as `--field username=…`).
        #[arg(long)]
        username: Option<String>,
        /// Add it even if the project already has an item with this title
        /// (references by title become ambiguous).
        #[arg(long)]
        allow_duplicate: bool,
        #[command(flatten)]
        fields: FieldArgs,
        #[command(flatten)]
        json: JsonFlag,
    },
    /// Store a file in a `file` field of an item (encrypted attachment).
    Attach {
        /// Item reference, ID or title.
        item: String,
        /// Field name (created if missing).
        field: String,
        /// File to read.
        path: PathBuf,
        /// File name to record (default: the name of `path`).
        #[arg(long)]
        name: Option<String>,
        #[command(flatten)]
        json: JsonFlag,
    },
    /// Show an item. Secret values stay hidden unless `--reveal`.
    Get {
        /// `klav://vault/project/item[/field]`, `vault/project/item`, ID or title.
        item: String,
        /// Show secret values.
        #[arg(long)]
        reveal: bool,
        /// Print only this field's value.
        #[arg(long)]
        field: Option<String>,
        #[command(flatten)]
        json: JsonFlag,
    },
    /// Edit an item.
    Edit {
        /// Item reference, ID or title.
        item: String,
        /// New title.
        #[arg(long)]
        title: Option<String>,
        /// Rename even if the project already has an item with the new
        /// title (references by title become ambiguous).
        #[arg(long, requires = "title")]
        allow_duplicate: bool,
        /// Remove a field (repeatable).
        #[arg(long = "rm-field", value_name = "NAME")]
        remove: Vec<String>,
        #[command(flatten)]
        fields: FieldArgs,
        #[command(flatten)]
        json: JsonFlag,
    },
    /// The sites of an item: those the person confirmed, and those an agent
    /// added that wait for her (ADR 0030 §7). Only confirmed sites are
    /// autofilled, suggested or filled by agents.
    Sites {
        /// Item reference, ID or title.
        item: String,
        /// Confirm every site an agent added (writes a new version as you).
        #[arg(long, conflicts_with = "remove")]
        confirm: bool,
        /// Remove this URL (repeatable).
        #[arg(long, value_name = "URL")]
        remove: Vec<String>,
        #[command(flatten)]
        json: JsonFlag,
    },
    /// Move an item to the trash.
    Rm {
        /// Item reference, ID or title.
        item: String,
    },
    /// List items (metadata only).
    Ls {
        /// Only this vault.
        #[arg(long)]
        vault: Option<String>,
        /// Only this project.
        #[arg(long)]
        project: Option<String>,
        /// Only these types: `--kind login,card` or `--kind login --kind card`.
        #[arg(long, value_name = "TYPE", value_delimiter = ',')]
        kind: Vec<ListKindArg>,
        /// Only items with a one-time code, of any type (`klav totp` shows it).
        #[arg(long)]
        codes: bool,
        /// Only items with this tag.
        #[arg(long)]
        tag: Option<String>,
        /// List the trash.
        #[arg(long)]
        trash: bool,
        #[command(flatten)]
        json: JsonFlag,
    },
    /// Search titles, usernames, URLs and tags.
    Search {
        /// Text to look for.
        query: String,
        #[command(flatten)]
        json: JsonFlag,
    },
    /// Previous passwords of an item, newest first (values hidden).
    History {
        /// Item title or ID.
        item: String,
        /// Print previous password `N` (from the list) instead.
        #[arg(long, value_name = "N")]
        reveal: Option<usize>,
        #[command(flatten)]
        json: JsonFlag,
    },
}

#[derive(Debug, Args)]
pub(crate) struct TotpArgs {
    /// Item reference, ID or title.
    pub(crate) item: String,
    /// TOTP field (default: the first one).
    #[arg(long)]
    pub(crate) field: Option<String>,
    #[command(flatten)]
    pub(crate) json: JsonFlag,
}

#[derive(Debug, Args)]
pub(crate) struct GenerateArgs {
    /// What to generate (default: smart, which follows the site's rules
    /// with --site or --rules, and is a 20-character random password
    /// otherwise).
    #[arg(short = 't', long = "type", value_enum)]
    pub(crate) kind: Option<GeneratorTypeArg>,
    /// Site the password is for: its bundled rules (smart).
    #[arg(long, value_name = "HOST")]
    pub(crate) site: Option<String>,
    /// The site's `passwordrules` text (smart), e.g. "minlength: 8; required: digit;".
    #[arg(long, value_name = "RULES")]
    pub(crate) rules: Option<String>,
    /// Password length (random; preferred length for smart).
    #[arg(short, long, default_value_t = klav_core::generator::DEFAULT_LENGTH)]
    pub(crate) length: usize,
    /// Words of a memorable passphrase (implies --type memorable).
    #[arg(short, long)]
    pub(crate) words: Option<usize>,
    /// Passphrase separator: 1 to 8 bytes, no ASCII letter or digit, no
    /// control or invisible character.
    #[arg(long, default_value = "-")]
    pub(crate) separator: String,
    /// Passphrase words in lowercase.
    #[arg(long)]
    pub(crate) no_capitalize: bool,
    /// Passphrase without a digit.
    #[arg(long)]
    pub(crate) no_number: bool,
    /// Digits of a PIN.
    #[arg(long, default_value_t = 6)]
    pub(crate) pin_length: usize,
    /// No symbols.
    #[arg(long)]
    pub(crate) no_symbols: bool,
    /// No digits.
    #[arg(long)]
    pub(crate) no_digits: bool,
    /// No uppercase letters.
    #[arg(long)]
    pub(crate) no_uppercase: bool,
    /// Avoid look-alike characters (0/O, 1/l/I…).
    #[arg(long)]
    pub(crate) avoid_ambiguous: bool,
    /// Do not keep the password in the generator history.
    #[arg(long)]
    pub(crate) no_history: bool,
}

/// `klav presence` (ADR 0041 §2.4).
#[derive(Debug, Subcommand)]
pub(crate) enum PresenceCommand {
    /// Show how often `klavd` asks for your presence before it hands out a
    /// value, or set it. Loosening asks for Touch ID or the master
    /// password; tightening asks for nothing. Needs an unlocked `klavd`.
    Window {
        /// `always` (every value), `5m` (once per 5 minutes per terminal
        /// session), or `unlocked` (once until Klav locks).
        window: Option<PresenceWindowArg>,
        #[command(flatten)]
        json: JsonFlag,
    },
}

/// The presence settings (`klav presence window`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum PresenceWindowArg {
    /// Every value asks.
    Always,
    /// Once every 5 minutes, per terminal session.
    #[value(name = "5m")]
    FiveMinutes,
    /// Once, until Klav locks.
    Unlocked,
}

/// `klav generated`: the generator history (ADR 0022 §2).
#[derive(Debug, Subcommand)]
pub(crate) enum GeneratedCommand {
    /// List the passwords Klav generated, newest first (values hidden).
    Ls {
        #[command(flatten)]
        json: JsonFlag,
    },
    /// Print one generated password (`N` from `klav generated ls`).
    Show {
        /// Position in the list.
        index: usize,
    },
    /// Delete entries of the generator history.
    Rm {
        /// Positions in the list.
        #[arg(required_unless_present = "all", conflicts_with = "all")]
        index: Vec<usize>,
        /// Delete the whole history.
        #[arg(long)]
        all: bool,
    },
}

#[derive(Debug, Args)]
#[command(args_conflicts_with_subcommands = true)]
pub(crate) struct HealthArgs {
    #[command(subcommand)]
    pub(crate) command: Option<HealthCommand>,
    /// «Fix my reused passwords» (ADR 0022 §6): offer this agent a task to
    /// change the passwords you reuse, one site after another. The agent
    /// gets the sites, never the list of reused passwords. Asks for Touch
    /// ID or the master password once.
    #[arg(long, value_name = "AGENT")]
    pub(crate) fix_with: Option<String>,
    /// With --fix-with: only these logins (reference, title or ID;
    /// repeatable).
    #[arg(
        long,
        value_name = "REF",
        requires = "fix_with",
        conflicts_with = "skip"
    )]
    pub(crate) only: Vec<String>,
    /// With --fix-with: leave these logins out (reference, title or ID;
    /// repeatable).
    #[arg(long, value_name = "REF", requires = "fix_with")]
    pub(crate) skip: Vec<String>,
    /// With --fix-with: how long the agent has (5m to 24h; default 2h).
    #[arg(long = "for", value_name = "DURATION", value_parser = parse_duration, requires = "fix_with")]
    pub(crate) duration: Option<std::time::Duration>,
    /// With --fix-with: the task's title, as the agent will read it.
    #[arg(long, value_name = "TEXT", requires = "fix_with")]
    pub(crate) task: Option<String>,
    /// With --fix-with: the reason, as the agent will read it.
    #[arg(long, value_name = "TEXT", requires = "fix_with")]
    pub(crate) reason: Option<String>,
    /// With --fix-with: do not ask before offering (needed without a
    /// terminal).
    #[arg(long, short = 'y', requires = "fix_with")]
    pub(crate) yes: bool,
    #[command(flatten)]
    pub(crate) json: JsonFlag,
}

#[derive(Debug, Subcommand)]
pub(crate) enum HealthCommand {
    /// Show, turn on or turn off the breach check (Have I Been Pwned, off
    /// by default; a setting of this device only).
    BreachCheck {
        /// `on` or `off`; without it, show the setting.
        state: Option<OnOff>,
    },
}

/// A switch.
#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub(crate) enum OnOff {
    On,
    Off,
}

/// Generator types (ADR 0022 §1.1).
#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub(crate) enum GeneratorTypeArg {
    Smart,
    Random,
    Memorable,
    Pin,
}

/// `klav import`.
#[derive(Debug, Args)]
pub(crate) struct ImportArgs {
    /// Export files, detected by their content: Bitwarden (`.json`,
    /// `.csv`), 1Password (`.1pux`, `.csv`), Google Authenticator (photos
    /// of its QR codes as `.png`, or `-` to paste its
    /// `otpauth-migration://` links on stdin) and browser CSVs (Chrome,
    /// Edge, Brave, Firefox, Safari). Several files are imported together.
    #[arg(required = true, value_name = "FILE")]
    pub(crate) files: Vec<PathBuf>,
    /// Where the files come from, when detection is not enough:
    /// bitwarden, 1password, google, chrome (edge, brave), firefox, safari
    /// or csv.
    #[arg(long, value_name = "SOURCE")]
    pub(crate) from: Option<String>,
    /// Destination vault (default: Personal).
    #[arg(long)]
    pub(crate) vault: Option<String>,
    /// Destination project (default: General).
    #[arg(long)]
    pub(crate) project: Option<String>,
    /// Show what would happen, change nothing.
    #[arg(long)]
    pub(crate) dry_run: bool,
    /// Machine-readable JSON output (the preview, and the result).
    #[arg(long)]
    pub(crate) json: bool,
}

/// `klav extension …`.
#[derive(Debug, Subcommand)]
pub(crate) enum ExtensionCommand {
    /// Let the browser extension talk to `klavd`: write the native
    /// messaging host manifests (Chrome, Chromium, Brave, Arc, Edge, Dia,
    /// Firefox) for this `KLAV_HOME`.
    InstallHost(HostArgs),
    /// Remove the native messaging host manifests.
    UninstallHost(HostArgs),
    /// Where each installed browser's manifest points, and whether it runs
    /// this `KLAV_HOME`'s host (`--host`): finds an install from another
    /// path before replacing it. Changes nothing.
    HostStatus(HostArgs),
}

/// Browsers with a native messaging host directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum Browser {
    Chrome,
    Chromium,
    Brave,
    Arc,
    Edge,
    Dia,
    Firefox,
}

#[derive(Debug, Args)]
pub(crate) struct HostArgs {
    /// Only this browser (repeatable; default: every installed one).
    #[arg(long, value_enum)]
    pub(crate) browser: Vec<Browser>,
    /// A Chromium profile directory (`--user-data-dir` of the browser)
    /// instead of the browser's default one.
    #[arg(long, value_name = "DIR")]
    pub(crate) user_data_dir: Option<PathBuf>,
    /// Also allow this extension: a Chromium ID (store build) or a Firefox
    /// add-on ID (repeatable).
    #[arg(long = "extension-id", value_name = "ID")]
    pub(crate) extension_id: Vec<String>,
    /// Also allow the development build for Chromium browsers (the
    /// unpacked `apps/extension/dist/chromium`). Its ID comes from a public
    /// key in the repository, so any unpacked extension can claim it: only
    /// on a machine where you load the extension yourself.
    #[arg(long)]
    pub(crate) dev: bool,
    /// Path of `klav-native-host` (default: next to `klav`, or in PATH).
    #[arg(long, value_name = "PATH")]
    pub(crate) host: Option<PathBuf>,
    #[command(flatten)]
    pub(crate) json: JsonFlag,
}

#[derive(Debug, Args)]
pub(crate) struct SyncArgs {
    /// Forget this device's copy of the vaults and its rollback marks, and
    /// download everything again. For when the server was restored from a
    /// backup you trust (every sync is refused as a rollback), or to drop
    /// vaults the server no longer lists. Revoked agents and signed vault
    /// keys are kept.
    #[arg(long)]
    pub(crate) reset_cache: bool,
    /// Do not ask for confirmation.
    #[arg(long, requires = "reset_cache")]
    pub(crate) yes: bool,
}

#[cfg(test)]
mod tests {
    /// clap's own checks of every command (names in `conflicts_with`,
    /// `requires`, …), which otherwise only fail when that command runs.
    #[test]
    fn the_command_line_is_consistent() {
        use clap::CommandFactory;
        super::Cli::command().debug_assert();
    }
}
