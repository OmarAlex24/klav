//! `klav mcp`: a Model Context Protocol server over stdio for an AI agent
//! (design §5.4–§5.5, ADR 0014 §8).
//!
//! JSON-RPC 2.0, one message per line. Stdout carries nothing else; logs go
//! to stderr. It runs with the agent's own identity and decrypts here: the
//! LLM gets actions and metadata, never values, except through `reveal`
//! (denied by default) and `get_totp` without a target (a one-time code,
//! `ask` by default). Every tool takes a mandatory `reason`, logged with
//! the action. With `project` in `klav.toml` (in the directory it starts
//! in), the tools only see that project.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use klav_client::ClientError;
use klav_client::ops::{FieldInput, ItemPatch, NewItem, SecretText};
use klav_core::generator::GeneratorKind;
use klav_core::ids::{ApprovalId, RotationId, TaskId};
use klav_core::model::item::{ItemKind, template};
use klav_core::policy::Permission;
use klav_sdk::browser::{self, FieldSelector};
use klav_sdk::{Access, Agent, FillOptions, GenerateSpec, InjectRequest, RunRequest, Session};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use crate::cli::McpArgs;
use crate::context::Ctx;
use crate::error::CliResult;
use crate::project::{self, ProjectConfig};
use crate::secret_files::{Cleanup, Signals};

/// Protocol version answered when the client asks for none.
const PROTOCOL_VERSION: &str = "2025-06-18";
/// Protocol versions this server speaks; anything else gets ours.
const KNOWN_VERSIONS: [&str; 3] = ["2024-11-05", "2025-03-26", PROTOCOL_VERSION];
/// Longest JSON-RPC message accepted on stdin (layer 04).
const MAX_LINE: usize = 4 << 20;
/// Items `search_items` returns unless asked for fewer.
const SEARCH_LIMIT: usize = 50;
/// Most items `search_items` returns at once.
const MAX_SEARCH_LIMIT: usize = 200;
/// Longest wait for the person a tool call may ask for.
const MAX_WAIT: Duration = Duration::from_secs(600);
/// Longest command a tool call may run.
const MAX_RUN: Duration = Duration::from_secs(1800);
/// Longest TTL of an injected file.
const MAX_TTL: Duration = Duration::from_secs(24 * 3600);

struct Server {
    home: klav_client::Home,
    agent_name: Option<String>,
    wait: Duration,
    cwd: PathBuf,
    config: Option<ProjectConfig>,
    session: Option<Session>,
    /// `approval_id` of the call in progress, claimed when the session
    /// opens.
    claim: Option<ApprovalId>,
    /// `task_id` of the call in progress, named when the session opens.
    task: Option<TaskId>,
    /// Injected files with a TTL that have not expired yet: removed when
    /// the server exits, even before their time.
    expiring: Arc<Mutex<Cleanup>>,
}

/// A tool failure shown to the LLM (`isError`), not a protocol error.
enum ToolError {
    Msg(String),
    /// Waiting for the person: answered with the commands to follow it
    /// (ADR 0015 §5).
    Pending(ApprovalId),
}

impl From<ClientError> for ToolError {
    fn from(e: ClientError) -> Self {
        match &e {
            ClientError::PendingApproval { id, .. } => Self::Pending(*id),
            // The person paused Klav for agents (ADR 0033 §7.4).
            ClientError::Paused(paused) => Self::Msg(paused_payload(paused.as_ref())),
            // The person asked to delete the account (ADR 0037 §3).
            ClientError::AccountDeleting(at) => Self::Msg(deleting_payload(*at)),
            _ if e.is_rollback() => Self::Msg(format!(
                "{e}. This is a security check: stop, tell the person, and do not retry or work around it."
            )),
            ClientError::Denied(_) => Self::Msg(format!(
                "{e}. Do not work around it: explain to the person why you need it, or use request_access."
            )),
            // The server's own words reach the LLM only marked and cut
            // (layer 04): a hostile server must not write it instructions.
            ClientError::Api {
                status, message, ..
            } => Self::Msg(format!(
                "error {status}; {}",
                klav_sdk::text::untrusted(message)
            )),
            _ => Self::Msg(e.to_string()),
        }
    }
}

/// What the LLM gets when the person paused it (ADR 0033 §7.4).
pub(crate) fn paused_payload(paused: Option<&klav_proto::agent::AgentPaused>) -> String {
    serde_json::to_string_pretty(&json!({
        "status": "paused",
        "scope": paused.map(|p| p.scope),
        "since": paused.map(|p| p.since),
        "until": paused.and_then(|p| p.until),
        "next": "The person paused Klav for agents. Do not retry or work around it; tell the person you need Klav and ask them to resume it.",
    }))
    .unwrap_or_default()
}

/// What the LLM gets while the account waits to be deleted (ADR 0037 §3):
/// the same for every tool, and nothing to work around.
pub(crate) fn deleting_payload(delete_at: Option<i64>) -> String {
    serde_json::to_string_pretty(&json!({
        "status": "account_deleting",
        "delete_at": delete_at,
        "next": "The person asked Klav to delete this account. Stop and tell the person; do not retry.",
    }))
    .unwrap_or_default()
}

impl From<crate::error::CliError> for ToolError {
    fn from(e: crate::error::CliError) -> Self {
        use klav_daemon::protocol::ErrorCode;
        match e {
            crate::error::CliError::Client(ClientError::Paused(paused)) => {
                Self::Msg(paused_payload(paused.as_ref()))
            }
            crate::error::CliError::Client(ClientError::AccountDeleting(at)) => {
                Self::Msg(deleting_payload(at))
            }
            // `klavd` refuses what it brokers for agents too.
            crate::error::CliError::Daemon(d)
                if matches!(
                    d.code,
                    ErrorCode::AccountDeleting | ErrorCode::AccountDeleted
                ) =>
            {
                Self::Msg(deleting_payload(None))
            }
            // `klavd` says which pause holds the agent, as the server does.
            crate::error::CliError::Daemon(d) if d.code == ErrorCode::AgentsPaused => {
                Self::Msg(paused_payload(d.paused.as_ref()))
            }
            e => Self::Msg(e.message().unwrap_or_else(|| "error".into())),
        }
    }
}

/// `text` as one shell word.
pub(crate) fn sh_quote(text: &str) -> String {
    if !text.is_empty()
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "_-./:=@%+,".contains(c))
    {
        text.to_owned()
    } else {
        format!("'{}'", text.replace('\'', "'\\''"))
    }
}

/// The running executable's path as a command run later should name it.
/// On Linux, `current_exe()` reads `/proc/self/exe`, which ends in
/// ` (deleted)` once the file was replaced while klav runs (an upgrade, or
/// a rebuild): the binary now at the original path is the one to run.
pub(crate) fn live_exe(exe: PathBuf) -> PathBuf {
    let live = exe
        .to_str()
        .and_then(|p| p.strip_suffix(" (deleted)"))
        .map(PathBuf::from);
    match live {
        Some(live) if !exe.exists() && live.exists() => live,
        _ => exe,
    }
}

type ToolResult = Result<Value, ToolError>;

fn arg<'a>(args: &'a Value, name: &str) -> Option<&'a str> {
    args.get(name)
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
}

fn required<'a>(args: &'a Value, name: &str) -> Result<&'a str, ToolError> {
    arg(args, name).ok_or_else(|| ToolError::Msg(format!("`{name}` is required")))
}

fn seconds(args: &Value, name: &str, default: Duration, max: Duration) -> Duration {
    args.get(name)
        .and_then(Value::as_u64)
        .map_or(default, Duration::from_secs)
        .min(max)
}

fn string_map(args: &Value, name: &str) -> Result<Vec<(String, String)>, ToolError> {
    match args.get(name) {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Object(map)) => map
            .iter()
            .map(|(k, v)| {
                v.as_str()
                    .map(|v| (k.clone(), v.to_owned()))
                    .ok_or_else(|| ToolError::Msg(format!("`{name}.{k}` must be a string")))
            })
            .collect(),
        Some(_) => Err(ToolError::Msg(format!("`{name}` must be an object"))),
    }
}

fn string_list(args: &Value, name: &str) -> Vec<String> {
    args.get(name)
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

fn fields(args: &Value, name: &str) -> Result<Vec<FieldInput>, ToolError> {
    Ok(string_map(args, name)?
        .into_iter()
        .map(|(name, value)| FieldInput {
            name,
            value: SecretText::new(value),
            kind: None,
            // Values arrive over the pipe, never in argv.
            secret: true,
        })
        .collect())
}

/// `path` inside `cwd` (its parent must exist; symlinks resolved).
fn inside(cwd: &Path, path: &str) -> Result<PathBuf, ToolError> {
    let joined = cwd.join(path);
    let name = joined
        .file_name()
        .ok_or_else(|| ToolError::Msg(format!("{path:?} is not a file path")))?
        .to_owned();
    let parent = joined
        .parent()
        .ok_or_else(|| ToolError::Msg(format!("{path:?} is not a file path")))?;
    let parent = parent
        .canonicalize()
        .map_err(|_| ToolError::Msg(format!("the directory of {path:?} does not exist")))?;
    let root = cwd
        .canonicalize()
        .map_err(|e| ToolError::Msg(format!("working directory: {e}")))?;
    if !parent.starts_with(&root) {
        return Err(ToolError::Msg(format!(
            "{path:?} is outside the working directory: inject_file only writes inside it"
        )));
    }
    Ok(parent.join(name))
}

fn kind(text: &str) -> Result<ItemKind, ToolError> {
    serde_json::from_value(Value::String(text.trim().to_lowercase().replace('-', "_"))).map_err(
        |_| {
            ToolError::Msg(format!(
                "unknown item type {text:?} (login, card, identity, ssh_key, totp, note, api_key)"
            ))
        },
    )
}

/// `generate` of `create_item` (ADR 0022 §7): `true`, or `{type?, site?,
/// field?}`; absent or `false` for none.
fn generate_spec(args: &Value) -> Result<Option<GenerateSpec>, ToolError> {
    match args.get("generate") {
        None | Some(Value::Null | Value::Bool(false)) => Ok(None),
        Some(Value::Bool(true)) => Ok(Some(GenerateSpec::default())),
        Some(Value::Object(_)) => {
            let spec = &args["generate"];
            let kind = match arg(spec, "type") {
                Some(t) => {
                    serde_json::from_value::<GeneratorKind>(Value::String(t.trim().to_lowercase()))
                        .map_err(|_| {
                            ToolError::Msg(format!(
                                "unknown generator type {t:?} (smart, random, memorable, pin)"
                            ))
                        })?
                }
                None => GeneratorKind::default(),
            };
            Ok(Some(GenerateSpec {
                kind,
                site: arg(spec, "site").map(str::to_owned),
                field: arg(spec, "field").map(str::to_owned),
            }))
        }
        Some(_) => Err(ToolError::Msg(
            "`generate` is true or an object {type?, site?, field?}".into(),
        )),
    }
}

fn rotation_id(text: &str) -> Result<RotationId, ToolError> {
    text.trim()
        .parse()
        .map_err(|_| ToolError::Msg(format!("pending_id {text:?} is not a change ID")))
}

/// A failed step of a password change: a denial points at tasks, not at
/// `request_access` (`rotate` never goes in a grant).
fn passkey_error(e: ClientError) -> ToolError {
    match e {
        ClientError::Denied(message) => ToolError::Msg(format!(
            "{message}. Do not work around it: tell the person why."
        )),
        other => other.into(),
    }
}

fn rotate_error(e: ClientError) -> ToolError {
    match e {
        ClientError::Denied(message) => ToolError::Msg(format!(
            "{message}. Do not work around it, and never try to see, copy or type the password yourself: tell the person why."
        )),
        other => other.into(),
    }
}

fn permission(text: &str) -> Result<Permission, ToolError> {
    serde_json::from_value(Value::String(text.trim().to_lowercase()))
        .map_err(|_| ToolError::Msg(format!("unknown permission {text:?}")))
}

impl Server {
    fn scope(&self) -> Option<(String, String)> {
        self.config.as_ref().and_then(ProjectConfig::project_scope)
    }

    fn expand(&self, reference: &str) -> Result<String, ToolError> {
        let project = self.config.as_ref().and_then(|c| c.project.as_deref());
        if reference.trim().starts_with("klav://") || project.is_none() {
            return Ok(reference.trim().to_owned());
        }
        // `Item` or `Item/field` inside the project.
        Ok(format!(
            "klav://{}/{}",
            project.unwrap_or_default(),
            reference.trim()
        ))
    }

    async fn session(&mut self) -> Result<&mut Session, ToolError> {
        match &mut self.session {
            Some(s) => {
                s.refresh().await?;
            }
            None => {
                let name = klav_sdk::config::pick(&self.home, self.agent_name.as_deref())?;
                let agent = Agent::load(&self.home, &name)?;
                self.session = Some(Session::open(agent).await?);
            }
        }
        let session = self
            .session
            .as_mut()
            .ok_or_else(|| ToolError::Msg("no session".into()))?;
        if let Some(id) = self.claim.take() {
            session.claim_approval(id).await?;
        }
        if let Some(id) = self.task.take() {
            session.use_task(id)?;
        }
        Ok(session)
    }

    /// The agent's command to wait for the person (ADR 0015 §5): absolute
    /// path, `KLAV_HOME`, the agent's name, never `KLAV_AGENT_KEY`.
    fn wait_command(&self, what: &str) -> String {
        let agent = self
            .session
            .as_ref()
            .map(|s| s.agent().name().to_owned())
            .or_else(|| self.agent_name.clone());
        let exe = std::env::current_exe()
            .ok()
            .map(live_exe)
            .and_then(|p| p.to_str().map(str::to_owned))
            .unwrap_or_else(|| "klav".into());
        let home = self.home.dir().to_string_lossy().into_owned();
        format!(
            "KLAV_HOME={} {} {what}{} --timeout 10m --json",
            sh_quote(&home),
            sh_quote(&exe),
            agent
                .map(|a| format!(" --agent {}", sh_quote(&a)))
                .unwrap_or_default()
        )
    }

    /// What `request_secret` and `get_secret_request` answer (ADR 0046 §4).
    fn secret_request_payload(&self, outcome: &klav_sdk::SecretRequestOutcome) -> ToolResult {
        use klav_sdk::SecretRequestOutcome;
        match outcome {
            SecretRequestOutcome::Pending {
                request_id,
                expires_at,
            } => Ok(json!({
                "status": "pending",
                "request_id": request_id,
                "expires_at": expires_at,
                "fulfill_command": format!("klav secret-request fulfill {request_id}"),
                "wait_command": self.wait_command(&format!("agent secret-request wait {request_id}")),
                "next": format!(
                    "The person must enter this secret in Klav (Mac, iPhone, extension, or `klav secret-request fulfill {request_id}`). 1) Tell them what secret you need and why (never ask them to paste it in chat). 2) Run wait_command now in the background so you are woken when they save or deny it. 3) When it exits 0, call get_secret_request with request_id \"{request_id}\" (or read wait_command's JSON output) and use the returned reference or proxy_profile. Exit 5 means denied and 6 expired: tell the person and do not try another way. Exit 4 means nobody decided in time: ask whether to wait longer."
                ),
            })),
            SecretRequestOutcome::Fulfilled {
                request_id,
                in_grant,
                reference,
                vault_id,
                project_id,
                item_id,
                field,
                proxy_profile,
            } => {
                let mut out = json!({
                    "status": "fulfilled",
                    "request_id": request_id,
                    "in_grant": in_grant,
                    "field": field,
                });
                if let Some(reference) = reference {
                    out["ref"] = json!(reference);
                }
                if let Some(v) = vault_id {
                    out["vault_id"] = json!(v);
                }
                if let Some(p) = project_id {
                    out["project_id"] = json!(p);
                }
                if let Some(i) = item_id {
                    out["item_id"] = json!(i);
                }
                if let Some(profile) = proxy_profile {
                    out["proxy_profile"] = json!(profile);
                }
                out["next"] = json!(if *in_grant {
                    "The person saved the secret in Klav. Use `ref` with run_with_secrets, inject_file, or fill_login — never ask for or reveal the value."
                } else if let Some(profile) = proxy_profile {
                    return Ok({
                        out["next"] = json!(format!(
                            "The person saved the secret outside your local project grant and granted credential proxy profile `{profile}`. Use `--profile {profile}` in a sandbox (if your issuer already holds it), or ask the person to add `{profile}` to your issuer."
                        ));
                        out
                    });
                } else {
                    "The person saved the secret outside your project grant. Tell them if you need local access to use it."
                });
                Ok(out)
            }
            SecretRequestOutcome::Denied { request_id } => Err(ToolError::Msg(format!(
                "the person denied secret request {request_id}. Do not ask them to paste the secret or try another way."
            ))),
            SecretRequestOutcome::Expired { request_id } => Err(ToolError::Msg(format!(
                "secret request {request_id} expired without a decision. Ask the person before requesting it again."
            ))),
        }
    }

    /// What `request_task` and `get_task` answer (ADR 0021 §7).
    fn task_payload(&self, view: &klav_sdk::TaskView) -> ToolResult {
        use klav_proto::task::TaskStatus;
        let id = view.task_id;
        let mut out = serde_json::to_value(view).unwrap_or_default();
        match view.status {
            TaskStatus::Pending => {
                out["pending_task_id"] = json!(id);
                out["approve_command"] = json!(format!("klav task approve {id}"));
                out["wait_command"] = json!(self.wait_command(&format!("agent task wait {id}")));
                out["next"] = json!(format!(
                    "The person must approve this task. 1) Tell them what it is for, and that they approve it with `klav task approve {id}` (they can leave things out). 2) Run wait_command now in the background so you are woken when they decide; do not ask them to tell you. 3) When it exits 0, call get_task with task_id \"{id}\" and work only with what came back in `access`. Exit 5 means denied and 6 expired: tell the person and do not try another way. Exit 4 means nobody decided in time: ask the person whether to wait longer. Do not request the task again while you wait."
                ));
            }
            TaskStatus::Approved => {
                out["next"] = json!(
                    "Work only with what is in `access` (Klav may have added permissions, and the person may have removed some: see `removed`). Use the normal tools; they pick this task by themselves (or pass task_id). Anything outside it goes through the normal approval (the person sees it as outside the task); do not request a new task to get around it. Call end_task when the job is done."
                );
            }
            TaskStatus::Denied => {
                return Err(ToolError::Msg(format!(
                    "the person denied task {id}. Do not try another way: ask them what they prefer."
                )));
            }
            TaskStatus::Expired => {
                return Err(ToolError::Msg(format!(
                    "task {id} expired without a decision. Ask the person before requesting it again."
                )));
            }
            TaskStatus::Ended => {
                out["next"] = json!(
                    "This task is over. If the job is not done, tell the person and ask before requesting another one."
                );
            }
        }
        Ok(out)
    }

    /// What the LLM gets when the person has not decided yet: the request,
    /// the person's command, the agent's wait command and what to do next
    /// (ADR 0015 §5).
    async fn pending_payload(&self, id: ApprovalId) -> Value {
        let expires_at = match &self.session {
            Some(s) => s
                .agent()
                .approval(id, Duration::ZERO)
                .await
                .ok()
                .map(|i| i.expires_at),
            None => None,
        };
        let wait_command = self.wait_command(&format!("approval wait {id}"));
        json!({
            "status": "pending",
            "pending_approval_id": id,
            "expires_at": expires_at,
            "approve_command": format!("klav approval approve {id}"),
            "wait_command": wait_command,
            "next": format!(
                "The person must approve this. 1) Tell them what you asked for and why, and that they approve it with `klav approval approve {id}` (or `--for 15m`). 2) Run wait_command now in the background (e.g. a background shell) so you are woken when they decide; do not ask them to tell you. 3) When it exits 0, call this same tool again with the same arguments plus approval_id \"{id}\". Exit 5 means denied and 6 expired: tell the person and do not try another way. Exit 4 means nobody decided in time: ask the person whether to wait longer. Do not call the tool again in a loop while you wait and do not make a new request for the same thing. This approval_id only works for this action."
            ),
        })
    }

    async fn call(&mut self, name: &str, args: &Value) -> ToolResult {
        // Reading its own tasks or secret requests needs no reason; everything else does.
        let reason = match name {
            "get_task" | "list_tasks" | "get_secret_request" => {
                arg(args, "reason").unwrap_or_default().to_owned()
            }
            _ => required(args, "reason")?.to_owned(),
        };
        // The person reads these on the card (layer 04): no bidi overrides,
        // zero-width marks or line breaks that make them say something else.
        klav_sdk::text::check_declared("reason", &reason)?;
        if let Some(domain) = arg(args, "domain") {
            klav_sdk::text::check_declared("domain", domain)?;
        }
        self.task = arg(args, "task_id")
            .filter(|_| {
                !matches!(
                    name,
                    "request_task"
                        | "get_task"
                        | "end_task"
                        | "list_tasks"
                        | "request_secret"
                        | "get_secret_request"
                )
            })
            .map(task_id)
            .transpose()?;
        self.claim = arg(args, "approval_id")
            .map(|id| {
                id.trim().parse::<ApprovalId>().map_err(|_| {
                    ToolError::Msg(format!("approval_id {id:?} is not an approval ID"))
                })
            })
            .transpose()?;
        let wait = seconds(args, "wait_seconds", self.wait, MAX_WAIT);
        let scope = self.scope();
        let scope = scope.as_ref().map(|(v, p)| (v.as_str(), p.as_str()));
        match name {
            "search_items" => {
                let query = arg(args, "query").map(str::to_owned);
                let vault = arg(args, "vault").map(str::to_lowercase);
                let project = arg(args, "project").map(str::to_lowercase);
                let kind = arg(args, "type").map(kind).transpose()?;
                let session = self.session().await?;
                let items: Vec<_> = session
                    .items(scope, query.as_deref())
                    .into_iter()
                    .filter(|i| vault.as_deref().is_none_or(|v| i.vault.to_lowercase() == v))
                    .filter(|i| {
                        project
                            .as_deref()
                            .is_none_or(|p| i.project.to_lowercase() == p)
                    })
                    .filter(|i| kind.is_none_or(|k| i.kind == k))
                    .collect();
                let limit = args
                    .get("limit")
                    .and_then(Value::as_u64)
                    .map_or(SEARCH_LIMIT, |n| usize::try_from(n).unwrap_or(usize::MAX))
                    .clamp(1, MAX_SEARCH_LIMIT);
                let truncated = items.len() > limit;
                let items = &items[..items.len().min(limit)];
                let mut out = json!({ "items": items });
                if truncated {
                    out["truncated"] = json!(true);
                    out["note"] = json!(format!(
                        "only the first {limit}: narrow the query, vault, project or type"
                    ));
                }
                Ok(out)
            }
            "get_item" => {
                let reference = self.expand(required(args, "ref")?)?;
                let session = self.session().await?;
                let (item, _) = session.locate(&reference, scope)?;
                let info = session.item_info(item)?;
                let field_names: Vec<&str> =
                    template(info.kind).iter().map(|(n, _, _)| *n).collect();
                let mut out = json!({ "item": info, "fields": field_names, "note": "values are never shown: use fill_login, run_with_secrets or inject_file" });
                if info.attachments > 0 {
                    out["attachments_note"] = json!(format!(
                        "it has {} attached file(s), each in a file field named as the person attached it (often `key` or `file`): write one with inject_file and ref \"Item/field\"; ask the person for the field name if unsure",
                        info.attachments
                    ));
                }
                Ok(out)
            }
            "fill_login" | "fill_card" => {
                let target = required(args, "target")?;
                let target = browser::resolve_target(&self.home, target)?;
                let reference = match arg(args, "ref") {
                    Some(r) => self.expand(r)?,
                    None if name == "fill_login" => {
                        let url = required(args, "url")?.to_owned();
                        let host = browser::fillable_host(&url)?;
                        let session = self.session().await?;
                        let found: Vec<_> = session
                            .items(scope, None)
                            .into_iter()
                            .filter(|i| {
                                i.kind == ItemKind::Login && browser::url_matches(&url, &i.urls)
                            })
                            .collect();
                        match found.as_slice() {
                            [one] => one.reference.clone(),
                            [] => return Err(ToolError::Msg(format!("no login for {host}"))),
                            many => {
                                return Err(ToolError::Msg(format!(
                                    "several logins for {host}: pass `ref` ({})",
                                    many.iter()
                                        .map(|i| i.reference.as_str())
                                        .collect::<Vec<_>>()
                                        .join(", ")
                                )));
                            }
                        }
                    }
                    None => return Err(ToolError::Msg("`ref` is required".into())),
                };
                let selectors: Vec<FieldSelector> = string_map(args, "selectors")?
                    .into_iter()
                    .map(|(field, selector)| FieldSelector { field, selector })
                    .collect();
                let submit = name == "fill_login"
                    && args.get("submit").and_then(Value::as_bool).unwrap_or(false);
                let session = self.session().await?;
                let report = klav_sdk::fill_target(
                    session,
                    &target,
                    &reference,
                    scope,
                    &FillOptions {
                        selectors: &selectors,
                        submit,
                        totp: false,
                    },
                    &reason,
                    wait,
                )
                .await?;
                let mut out = json!({ "ok": true, "filled": report.filled, "url": report.url });
                if report.submitted {
                    out["submitted"] = json!(true);
                    out["navigated"] = json!(report.navigated);
                    out["url_after"] = json!(report.url_after);
                }
                if !report.warnings.is_empty() {
                    out["warning"] = json!(report.warnings.join(" "));
                }
                Ok(out)
            }
            "run_with_secrets" => {
                let command: Vec<std::ffi::OsString> = string_list(args, "command")
                    .into_iter()
                    .map(Into::into)
                    .collect();
                if command.is_empty() {
                    return Err(ToolError::Msg(
                        "`command` must be a non-empty array: [program, args…]".into(),
                    ));
                }
                let mut env: Vec<(String, String)> = Vec::new();
                let mut files = Vec::new();
                if args
                    .get("use_project")
                    .and_then(Value::as_bool)
                    .unwrap_or(true)
                    && let Some(c) = &self.config
                {
                    env.extend(c.env.clone());
                    for (path, reference) in &c.files {
                        files.push((self.cwd.join(path), reference.clone()));
                    }
                }
                for (name, reference) in string_map(args, "env")? {
                    env.push((name, self.expand(&reference)?));
                }
                let cwd = self.cwd.clone();
                let timeout = seconds(args, "timeout_seconds", Duration::from_secs(600), MAX_RUN);
                let session = self.session().await?;
                let out = klav_sdk::run(
                    session,
                    scope,
                    RunRequest {
                        env,
                        files,
                        command,
                        cwd: Some(cwd),
                        reason,
                        wait,
                        timeout,
                    },
                )
                .await?;
                Ok(serde_json::to_value(&out).unwrap_or_default())
            }
            "inject_file" => {
                let path = inside(&self.cwd, required(args, "path")?)?;
                let reference = arg(args, "ref").map(|r| self.expand(r)).transpose()?;
                let template = arg(args, "template").map(str::to_owned);
                let ttl = args
                    .get("ttl_seconds")
                    .and_then(Value::as_u64)
                    .map(|s| Duration::from_secs(s).min(MAX_TTL));
                let force = args
                    .get("overwrite")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                let session = self.session().await?;
                klav_sdk::inject_file(
                    session,
                    scope,
                    InjectRequest {
                        template,
                        reference,
                        path: path.clone(),
                        force,
                        reason,
                        wait,
                    },
                )
                .await?;
                if let Some(ttl) = ttl {
                    lock(&self.expiring).add(path.clone());
                    let expiring = Arc::clone(&self.expiring);
                    let p = path.clone();
                    tokio::spawn(async move {
                        tokio::time::sleep(ttl).await;
                        let mut expiring = lock(&expiring);
                        expiring.forget(&p);
                        let _ = std::fs::remove_file(p);
                    });
                }
                // The size is not returned: it is the length of the secret.
                let mut out = json!({ "ok": true, "path": path, "mode": "0600", "removed_after_seconds": ttl.map(|t| t.as_secs()) });
                // The git advice and leftover temporaries. Only after a
                // write that succeeded: a failed call's answer is its
                // error, which this does not change.
                if let Some(warning) = crate::secret_files::inject_file_warning(&path) {
                    out["warning"] = json!(warning);
                }
                Ok(out)
            }
            "get_totp" => {
                let reference = self.expand(required(args, "ref")?)?;
                if let Some(target) = arg(args, "target") {
                    let target = browser::resolve_target(&self.home, target)?;
                    let session = self.session().await?;
                    let (item, field) = session.locate(&reference, scope)?;
                    let info = session.item_info(item)?;
                    let field = field.unwrap_or_else(|| "totp".into());
                    let full = format!("{}/{field}", info.reference);
                    // Typed with the `totp` permission, never `fill`, and
                    // only from a one-time password field.
                    let report = klav_sdk::fill_target(
                        session,
                        &target,
                        &full,
                        scope,
                        &FillOptions {
                            totp: true,
                            ..FillOptions::default()
                        },
                        &reason,
                        wait,
                    )
                    .await?;
                    let mut out = json!({ "ok": true, "filled": report.filled, "url": report.url });
                    if !report.warnings.is_empty() {
                        out["warning"] = json!(report.warnings.join(" "));
                    }
                    return Ok(out);
                }
                let session = self.session().await?;
                let (item, field) = session.locate(&reference, scope)?;
                let (code, remaining) = session.totp(item, field.as_deref(), &reason, wait).await?;
                Ok(json!({ "code": code.expose(), "valid_for_seconds": remaining }))
            }
            "reveal" => {
                let reference = self.expand(required(args, "ref")?)?;
                let field_arg = arg(args, "field").map(str::to_owned);
                let session = self.session().await?;
                let (item, field) = session.locate(&reference, scope)?;
                let field = field
                    .or(field_arg)
                    .ok_or_else(|| ToolError::Msg("`field` is required".into()))?;
                session.check_claim(Permission::Reveal, &[item], None)?;
                let opened = session
                    .access_waiting(item, Permission::Reveal, &reason, None, wait)
                    .await?;
                let (_, value) = klav_sdk::session::field_value(&opened, &field)?;
                Ok(
                    json!({ "field": field, "value": value.expose(), "warning": "this value is now in your context: do not repeat it" }),
                )
            }
            "create_item" => {
                let generate = generate_spec(args)?;
                let new = NewItem {
                    kind: kind(required(args, "type")?)?,
                    title: required(args, "title")?.to_owned(),
                    vault: None,
                    project: None,
                    fields: fields(args, "fields")?,
                    urls: string_list(args, "urls"),
                    tags: string_list(args, "tags"),
                    notes: arg(args, "notes").map(SecretText::new),
                    // Agents never create a second item with the same title.
                    allow_duplicate: false,
                };
                let vault = arg(args, "vault").map(str::to_owned);
                let project = arg(args, "project").map(str::to_owned);
                let session = self.session().await?;
                let project =
                    session.granted_project(vault.as_deref(), project.as_deref(), scope)?;
                let Some(spec) = generate else {
                    let info = session.create_item(project, &new, &reason, wait).await?;
                    return Ok(json!({ "ok": true, "item": info }));
                };
                let (info, generated) = session
                    .create_item_generated(project, new, &spec, &reason, wait)
                    .await?;
                Ok(json!({
                    "ok": true,
                    "item": info,
                    "generated": generated,
                    "note": "Klav generated the password and sealed it in the item: you never see it. Type it into a page with fill_login.",
                }))
            }
            "change_password_url" => {
                let reference = self.expand(required(args, "ref")?)?;
                let session = self.session().await?;
                let (item, _) = session.locate(&reference, scope)?;
                let page = session.change_password_url(item)?;
                let mut out = serde_json::to_value(&page).unwrap_or_default();
                out["next"] = json!(
                    "Open this page in the person's browser, sign in if it asks (fill_login), put the focus on the new-password field if you can, and call rotate_password with target \"extension\"."
                );
                Ok(out)
            }
            "rotate_password" => {
                // Before anything else: the new value never goes through a
                // browser of the agent's runtime (ADR 0022 §5).
                if let Some(why) = klav_sdk::rotate::refuse_target(required(args, "target")?) {
                    return Err(ToolError::Msg(why));
                }
                let reference = self.expand(required(args, "ref")?)?;
                let target = browser::resolve_target(&self.home, "extension")?;
                let submit = args.get("submit").and_then(Value::as_bool).unwrap_or(false);
                let session = self.session().await?;
                let (item, _) = session.locate(&reference, scope)?;
                let report = session
                    .rotate_password(&target, item, &reason, submit)
                    .await
                    .map_err(rotate_error)?;
                Ok(json!({ "filled": report.filled, "pending_id": report.pending_id }))
            }
            "passkey_sign_in" => {
                // Before anything else: the page's origin never comes from
                // the agent's runtime (ADR 0020 §9).
                if let Some(why) = klav_sdk::passkeys::refuse_target(required(args, "target")?) {
                    return Err(ToolError::Msg(why));
                }
                let reference = self.expand(required(args, "ref")?)?;
                let target = browser::resolve_target(&self.home, "extension")?;
                let session = self.session().await?;
                let (item, _) = session.locate(&reference, scope)?;
                let armed = session
                    .passkey_sign_in(&target, item, &reason)
                    .await
                    .map_err(passkey_error)?;
                let mut out = json!({ "used": armed.used, "rp_id": armed.rp_id });
                if let Some(secs) = armed.expires_in_s {
                    out["armed"] = json!(true);
                    out["expires_in_s"] = json!(secs);
                    out["next"] = json!(format!(
                        "Klav will answer the next passkey sign-in of {} in that tab. Click the site's «Sign in with a passkey» button now (within {secs} s); the page signs in by itself.",
                        armed.rp_id
                    ));
                }
                Ok(out)
            }
            "rotate_confirm" | "rotate_cancel" => {
                let reference = self.expand(required(args, "ref")?)?;
                let pending = rotation_id(required(args, "pending_id")?)?;
                let target = browser::resolve_target(&self.home, "extension")?;
                let session = self.session().await?;
                let (item, _) = session.locate(&reference, scope)?;
                if name == "rotate_confirm" {
                    session
                        .rotate_confirm(&target, item, pending, &reason)
                        .await
                } else {
                    session.rotate_cancel(&target, item, pending, &reason).await
                }
                .map_err(rotate_error)?;
                Ok(json!({ "ok": true }))
            }
            "update_item" => {
                let reference = self.expand(required(args, "ref")?)?;
                let patch_value = args.get("patch").cloned().unwrap_or(Value::Null);
                let patch = ItemPatch {
                    title: arg(&patch_value, "title").map(str::to_owned),
                    set: fields(&patch_value, "set")?,
                    remove: string_list(&patch_value, "remove"),
                    add_urls: string_list(&patch_value, "add_urls"),
                    remove_urls: Vec::new(),
                    add_tags: string_list(&patch_value, "add_tags"),
                    notes: arg(&patch_value, "notes").map(SecretText::new),
                    // Agents never rename onto another item's title.
                    allow_duplicate: false,
                };
                let session = self.session().await?;
                let (item, _) = session.locate(&reference, scope)?;
                let info = session.update_item(item, &patch, &reason, wait).await?;
                Ok(json!({ "ok": true, "item": info }))
            }
            "delete_item" => {
                let reference = self.expand(required(args, "ref")?)?;
                let session = self.session().await?;
                let (item, _) = session.locate(&reference, scope)?;
                session.trash_item(item, &reason, wait).await?;
                Ok(
                    json!({ "ok": true, "trashed": true, "note": "the person can restore it from the trash" }),
                )
            }
            "request_access" => {
                let reference = self.expand(required(args, "ref")?)?;
                let wanted = permission(required(args, "permission")?)?;
                let session = self.session().await?;
                let (item, _) = session.locate(&reference, scope)?;
                let decision = session.evaluate(item, wanted, arg(args, "domain"));
                if decision.effect == klav_core::policy::Effect::Deny {
                    let name = session.agent().name().to_owned();
                    return Err(ToolError::Msg(format!(
                        "the agent's grant denies `{}` on {reference}. Only the person can change it: ask them to run `klav agent approve {name} … --allow {}` if they agree, and tell them why.",
                        klav_sdk::session::permission_name(wanted),
                        klav_sdk::session::permission_name(wanted),
                    )));
                }
                match session
                    .access(item, wanted, &reason, arg(args, "domain"), None)
                    .await?
                {
                    Access::Granted(_) => Ok(
                        json!({ "status": "allowed", "note": "the policy already allows it: use the tool for it" }),
                    ),
                    Access::Pending { approval_id, .. } => {
                        Ok(self.pending_payload(approval_id).await)
                    }
                }
            }
            "request_task" => {
                let spec: klav_core::task::TaskSpec = serde_json::from_value(json!({
                    "task": required(args, "task")?,
                    "reason": reason,
                    "duration": required(args, "duration")?,
                    "access": args.get("access").cloned().unwrap_or(Value::Null),
                }))
                .map_err(|e| ToolError::Msg(format!("invalid task: {e}")))?;
                let session = self.session().await?;
                let view = session.request_task(&spec, scope, wait).await?;
                self.task_payload(&view)
            }
            "get_task" => {
                let id = task_id(required(args, "task_id")?)?;
                let wait = seconds(args, "wait_seconds", Duration::ZERO, MAX_WAIT);
                let session = self.session().await?;
                let info = session.agent().wait_task(id, wait).await?;
                let view = session.task_view(&info)?;
                self.task_payload(&view)
            }
            "list_tasks" => {
                let session = self.session().await?;
                let infos = session.agent().tasks().await?;
                let views = infos
                    .iter()
                    .map(|i| session.task_view(i))
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(json!({ "tasks": views }))
            }
            "end_task" => {
                let id = task_id(required(args, "task_id")?)?;
                let session = self.session().await?;
                let info = session.agent().end_task(id, &reason).await?;
                let view = session.task_view(&info)?;
                Ok(json!({ "ok": true, "task": view }))
            }
            "request_secret" => {
                let mode = match arg(args, "mode").unwrap_or("create") {
                    "create" => klav_core::secret_request::SecretRequestMode::Create,
                    "update" => klav_core::secret_request::SecretRequestMode::Update,
                    other => {
                        return Err(ToolError::Msg(format!(
                            "mode must be \"create\" or \"update\", got {other:?}"
                        )));
                    }
                };
                let kind = match arg(args, "type") {
                    None => None,
                    Some("api_key" | "api-key") => Some(klav_core::model::item::ItemKind::ApiKey),
                    Some("login") => Some(klav_core::model::item::ItemKind::Login),
                    Some("note") => Some(klav_core::model::item::ItemKind::Note),
                    Some("ssh_key" | "ssh-key") => Some(klav_core::model::item::ItemKind::SshKey),
                    Some("totp") => Some(klav_core::model::item::ItemKind::Totp),
                    Some(other) => {
                        return Err(ToolError::Msg(format!(
                            "unsupported item type {other:?} for request_secret (allowed: api_key, login, note, ssh_key, totp)"
                        )));
                    }
                };
                let urls = args
                    .get("urls")
                    .and_then(Value::as_array)
                    .map(|arr| {
                        arr.iter()
                            .filter_map(Value::as_str)
                            .map(str::to_owned)
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                let proxy_proposal: Option<klav_core::secret_request::ProxyProposal> = match args
                    .get("proxy_proposal")
                    .or_else(|| args.get("proxy_profile"))
                {
                    None | Some(Value::Null) => None,
                    Some(v) => Some(
                        serde_json::from_value(v.clone())
                            .map_err(|e| ToolError::Msg(format!("invalid proxy_proposal: {e}")))?,
                    ),
                };
                let field = match arg(args, "field") {
                    Some(f) => f.to_owned(),
                    None if mode == klav_core::secret_request::SecretRequestMode::Create => {
                        match kind.unwrap_or(klav_core::model::item::ItemKind::ApiKey) {
                            klav_core::model::item::ItemKind::ApiKey => "api_key",
                            klav_core::model::item::ItemKind::Login => "password",
                            klav_core::model::item::ItemKind::SshKey => "private_key",
                            klav_core::model::item::ItemKind::Totp => "totp",
                            _ => "secret",
                        }
                        .to_owned()
                    }
                    None => {
                        return Err(ToolError::Msg(
                            "field is required when mode is \"update\"".into(),
                        ));
                    }
                };
                let spec = klav_sdk::SecretRequestSpec {
                    mode,
                    kind,
                    title: arg(args, "title").map(str::to_owned),
                    reference: arg(args, "ref").map(str::to_owned),
                    project: arg(args, "project").map(str::to_owned),
                    field,
                    reason,
                    placeholder: arg(args, "placeholder").map(str::to_owned),
                    setup_url: arg(args, "setup_url").map(str::to_owned),
                    base_url: arg(args, "base_url").map(str::to_owned),
                    urls,
                    notes: arg(args, "notes").map(str::to_owned),
                    proxy_proposal,
                    wait,
                };
                let session = self.session().await?;
                let outcome = session.request_secret(&spec, scope).await?;
                self.secret_request_payload(&outcome)
            }
            "get_secret_request" => {
                let raw_id = required(args, "request_id")?;
                let id: klav_core::ids::SecretRequestId = raw_id.trim().parse().map_err(|_| {
                    ToolError::Msg(format!("request_id {raw_id:?} is not a secret request ID"))
                })?;
                let wait = seconds(args, "wait_seconds", Duration::ZERO, MAX_WAIT);
                let session = self.session().await?;
                let outcome = session.wait_secret_request(id, wait).await?;
                self.secret_request_payload(&outcome)
            }
            other => Err(ToolError::Msg(format!("unknown tool {other:?}"))),
        }
    }
}

fn task_id(text: &str) -> Result<TaskId, ToolError> {
    text.trim()
        .parse()
        .map_err(|_| ToolError::Msg(format!("task_id {text:?} is not a task ID")))
}

fn schema(properties: Value, required: &[&str]) -> Value {
    let mut props = properties;
    props["reason"] = json!({ "type": "string", "description": "Why you need this (mandatory; the person sees it and it is logged)." });
    props["wait_seconds"] = json!({ "type": "integer", "description": "How long to wait for the person's approval when the policy says ask (default 60, set by `klav mcp --wait`; max 600)." });
    props["approval_id"] = json!({ "type": "string", "description": "Retry with this approval: the pending_approval_id the person approved (after its wait_command exits 0). Refused if it is for another action." });
    props["task_id"] = json!({ "type": "string", "description": "Do this inside this running task (optional: with a single running task that covers the action, it is picked by itself)." });
    let mut req = vec!["reason"];
    req.extend_from_slice(required);
    json!({ "type": "object", "properties": props, "required": req })
}

pub(crate) fn tools() -> Value {
    let reference = json!({ "type": "string", "description": "klav://Vault/Project/Item[/field], or Item[/field] inside klav.toml's project" });
    let target = json!({ "type": "string", "description": "`extension`: the active tab of the person's browser, through Klav's extension (they see a notice in the page); or sdk:<session>, a browser registered by your runtime" });
    let map = json!({ "type": "object", "additionalProperties": { "type": "string" } });
    let request_secret_tool = json!({
        "name": "request_secret",
        "description": "Ask the person to save a missing secret (or update a secret field on an existing item) via a hidden input card on their Mac, iPhone, extension or terminal. You send only metadata (and an optional proxy_proposal for sandboxes); the value never touches the server or your context. Waits up to wait_seconds; while pending, follow `next`. When fulfilled, returns only the klav:// reference (if inside your grant) and/or granted proxy_profile.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "reason": { "type": "string", "description": "why you need this secret (mandatory, max 500 chars; the person sees it and it is logged)" },
                "mode": { "type": "string", "enum": ["create", "update"], "description": "create a new item (default) or update a secret field of an existing one" },
                "type": { "type": "string", "enum": ["api_key", "login", "note", "ssh_key", "totp"], "description": "item kind in create mode (default: api_key)" },
                "title": { "type": "string", "description": "suggested item title (create mode)" },
                "ref": reference.clone(),
                "field": { "type": "string", "description": "target secret field name (default depends on type, e.g. api_key)" },
                "project": { "type": "string", "description": "suggested granted project as Vault/Project or project ID (create mode)" },
                "placeholder": { "type": "string", "description": "short hint for the hidden input (e.g. sk_live_…)" },
                "setup_url": { "type": "string", "description": "https:// URL where the person can create or copy the key (never auto-opened; full domain shown with warning)" },
                "base_url": { "type": "string", "description": "non-secret API base URL (for api_key items)" },
                "urls": { "type": "array", "items": { "type": "string" }, "description": "suggested login URLs (unchecked by default on the person's card)" },
                "notes": { "type": "string", "description": "non-secret notes (create mode)" },
                "proxy_proposal": {
                    "type": "object",
                    "description": "optional klav-proxy profile proposal (unchecked by default; requires separate presence)",
                    "properties": {
                        "preset": { "type": ["string", "null"] },
                        "profile": { "type": "string" },
                        "upstream": { "type": "string" },
                        "header": { "type": "string" },
                        "prefix": { "type": "string" },
                        "methods": { "type": "array", "items": { "type": "string" } },
                        "ask_methods": { "type": "array", "items": { "type": "string" } },
                        "path_prefixes": { "type": "array", "items": { "type": "string" } },
                        "rate_per_minute": { "type": "integer" }
                    },
                    "required": ["profile", "upstream", "header", "prefix", "path_prefixes"]
                },
                "wait_seconds": { "type": "integer", "description": "how long to wait for the person (default 60, max 600)" }
            },
            "required": ["reason"]
        }
    });
    let get_secret_request_tool = json!({
        "name": "get_secret_request",
        "description": "Check the verified status and result of one of your secret requests (optional long-poll with wait_seconds). Never returns the secret value.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "request_id": { "type": "string" },
                "wait_seconds": { "type": "integer", "description": "wait this long while pending (default 0, max 600)" }
            },
            "required": ["request_id"]
        }
    });
    let mut list = json!([
        { "name": "search_items", "description": "Find items by title, user name, URL or tag. Metadata only, never values. Start here.",
          "inputSchema": schema(json!({ "query": { "type": "string" }, "vault": { "type": "string" }, "project": { "type": "string" }, "type": { "type": "string" }, "limit": { "type": "integer", "description": "at most this many items (default 50, max 200)" } }), &[]) },
        { "name": "get_item", "description": "Metadata and field names of an item. Never values.",
          "inputSchema": schema(json!({ "ref": reference }), &["ref"]) },
        { "name": "fill_login", "description": "Type a login's username and password into a browser page. Open the login page first; with target `extension`, if it says the tab is on another site, ask the person to open the right page. Klav checks the page's address against the item, types the password only into a password input that still has the focus, and submits only a form on the page's own origin: if it refuses, tell the person, and do not pick other selectors to get around it. Returns only the field names; with submit, also `navigated` and `url_after` (an origin only): check them, since a page that did not change may show an error or ask for a code.",
          "inputSchema": schema(json!({ "ref": reference, "url": { "type": "string", "description": "find the login by the page's address instead of ref" }, "target": target, "selectors": map, "submit": { "type": "boolean", "description": "submit the form after filling (default false)" } }), &["target"]) },
        { "name": "fill_card", "description": "Type a payment card into a browser page. Returns only the field names.",
          "inputSchema": schema(json!({ "ref": reference, "target": target, "selectors": map }), &["ref", "target"]) },
        { "name": "run_with_secrets", "description": "Run a command with secrets in its environment: env: {\"API_KEY\": \"klav://…/api_key\"}, plus klav.toml's [env] and [files]. Never put a secret or a value in `command`. The output comes back with the values replaced by [redacted by klav] (also those inject_file wrote in this session): do not try to recover them (encoding, splitting, lengths or prefixes). The redaction is a courtesy, not a sealed channel: the command itself has the values.",
          "inputSchema": schema(json!({ "command": { "type": "array", "items": { "type": "string" }, "description": "[program, args…]; no secrets here" }, "env": map, "use_project": { "type": "boolean", "description": "also load klav.toml's [env] and [files] (default true)" }, "timeout_seconds": { "type": "integer" } }), &["command"]) },
        { "name": "inject_file", "description": "Prefer run_with_secrets (with env or klav.toml's [files], which Klav removes when the command ends) whenever possible; use inject_file only when a tool needs a file on disk beforehand. Write secrets into a new 0600 file inside the working directory: one reference, or a template with at least one {{ klav://… }}. Returns the path, never the content. Pass ttl_seconds so it disappears, and tell the person the file exists. Attachments (a .p8, a certificate, a key file) go with ref (Item/<attachment name>, as get_item lists it), never in a template. Never cat the file into your context. A `warning` says git would commit the file (add it and *.klav-tmp to .gitignore, or remove the file before any commit), or names a temporary file of a write that was interrupted or is still in progress (tell the person; never delete it yourself).",
          "inputSchema": schema(json!({ "path": { "type": "string" }, "ref": reference, "template": { "type": "string" }, "ttl_seconds": { "type": "integer", "description": "remove the file after this long" }, "overwrite": { "type": "boolean" } }), &["path"]) },
        { "name": "get_totp", "description": "Current one-time code of an item. Pass target so it is typed into the page instead of returned (preferred). Needs the person's approval by default. A TOTP seed is never injected: run_with_secrets, inject_file and templates refuse …/totp.",
          "inputSchema": schema(json!({ "ref": reference, "target": target }), &["ref"]) },
        { "name": "reveal", "description": "Return a secret value into your context. Denied by default: prefer fill_login, run_with_secrets or inject_file.",
          "inputSchema": schema(json!({ "ref": reference, "field": { "type": "string" } }), &["ref"]) },
        { "name": "create_item", "description": "Create an item (login, api_key, note…) in a granted project. For a new account, pass generate: true (no password in fields): Klav generates a strong password with the site's rules and seals it in the item; you get only its metadata, never the value. Never ask the person to paste an existing API key or secret into the chat so you can store it here: use request_secret instead so they enter it in a hidden field on their device. Titles are unique in a project: if the title exists and you meant that item, use update_item; otherwise choose a more specific title. Never create a copy to get around an update that needs approval.",
          "inputSchema": schema(json!({ "type": { "type": "string", "description": "item type: login, api_key, note…" }, "title": { "type": "string" }, "vault": { "type": "string" }, "project": { "type": "string" }, "fields": map, "urls": { "type": "array", "items": { "type": "string" } }, "tags": { "type": "array", "items": { "type": "string" } }, "notes": { "type": "string" },
              "generate": { "description": "true, or { type?: smart|random|memorable|pin (default smart: the site's rules), site?: host whose rules apply (default: the first URL's), field?: which field (default password) }", "oneOf": [ { "type": "boolean" }, { "type": "object", "properties": { "type": { "type": "string", "enum": ["smart", "random", "memorable", "pin"] }, "site": { "type": "string" }, "field": { "type": "string" } } } ] } }), &["type", "title"]) },
        { "name": "update_item", "description": "Change an item: patch = { title?, set?: {field: value}, remove?: [field], add_urls?, add_tags?, notes? }. Needs the person's approval by default: wait for it, never create a copy of the item instead. A new title must not be another item's in the project.",
          "inputSchema": schema(json!({ "ref": reference, "patch": { "type": "object" } }), &["ref", "patch"]) },
        { "name": "delete_item", "description": "Move an item to the trash (the person can restore it). Denied by default.",
          "inputSchema": schema(json!({ "ref": reference }), &["ref"]) },
        { "name": "request_access", "description": "Ask the person for a permission on an item (list, fill, inject, totp, reveal, update, delete) instead of failing.",
          "inputSchema": schema(json!({ "ref": reference, "permission": { "type": "string" }, "domain": { "type": "string" } }), &["ref", "permission"]) },
        { "name": "change_password_url", "description": "The page where the item's site lets you change the password (Klav's bundled list, or the site's /.well-known/change-password). Metadata only. First step of a password change.",
          "inputSchema": schema(json!({ "ref": reference }), &["ref"]) },
        { "name": "rotate_password", "description": "Change a login's password in the person's browser, inside a task with `rotate` (one the person offered you in list_tasks, or request_task). Klav generates the new password with the page's rules, keeps it as pending in the item and types the current and the new one into the change form on the active tab (the focused password field first). You never see either: you get only {filled, pending_id}. Then submit the form, read the result, and call rotate_confirm or rotate_cancel: never leave a change open. Never try to see, copy or type either password yourself.",
          "inputSchema": schema(json!({ "ref": reference, "target": { "type": "string", "enum": ["extension"], "description": "only `extension`: the person's browser with Klav's extension. sdk:<session> is refused (the new password would pass through your runtime)" }, "submit": { "type": "boolean", "description": "submit the form after filling (default false). If filling fails, Klav cancels the change at once, unless submit is on and klavd stored the new password (the page may have taken it): then the change stays open for rotate_confirm or rotate_cancel. The error says which, and whether the cancel went through" } }), &["ref", "target"]) },
        { "name": "passkey_sign_in", "description": "Sign in to a site with the person's passkey, in the person's browser, inside a task with `passkey` (one the person offered you in list_tasks, or request_task). Open the site's sign-in page in the person's browser first. Klav's klavd signs in the page; you never get the key nor the assertion. Returns {used: true, rp_id} when the page was already asking for a passkey and got it; otherwise {used: false, armed: true, rp_id, expires_in_s: 60}: click the site's passkey button now, and the next passkey sign-in of that site in that tab gets it (once). Fails with Klav locked: ask the person to unlock.",
          "inputSchema": schema(json!({ "ref": reference, "target": { "type": "string", "enum": ["extension"], "description": "only `extension`: the person's browser with Klav's extension. sdk:<session> is refused (the page's origin would come from your runtime)" } }), &["ref", "target"]) },
        { "name": "rotate_confirm", "description": "The site took the new password: Klav records it, then makes it the item's current one and keeps the old one in its history. Returns {ok: true}. Fails, recording nothing, when Klav holds no pending password for the change (the person may have decided on the item's card): ask the person.",
          "inputSchema": schema(json!({ "ref": reference, "pending_id": { "type": "string", "description": "the pending_id rotate_password returned" } }), &["ref", "pending_id"]) },
        { "name": "rotate_cancel", "description": "The site refused the new password (or you give up): Klav records it, then the current one stays and the new one is kept in the history as generated, not confirmed. Returns {ok: true}. Fails, recording nothing, when Klav holds no pending password for the change (the person may have decided on the item's card): ask the person.",
          "inputSchema": schema(json!({ "ref": reference, "pending_id": { "type": "string", "description": "the pending_id rotate_password returned" } }), &["ref", "pending_id"]) },
        { "name": "request_task", "description": "Before a job that touches several items or sites, ask the person once for everything it needs (one card instead of one approval per item). Waits up to wait_seconds; while pending, follow `next`. reveal and delete never go in a task.",
          "inputSchema": { "type": "object", "properties": {
              "task": { "type": "string", "description": "short title of the job (max 120 characters; the person sees it)" },
              "reason": { "type": "string", "description": "why (max 500 characters; the person sees it and it is logged)" },
              "duration": { "type": "string", "description": "how long, from approval: 30m, 2h, 1h30m (5m to 24h); ask for what the job needs" },
              "access": { "type": "array", "description": "1 to 50 items, each once", "items": { "type": "object", "properties": {
                  "ref": reference.clone(),
                  "permissions": { "type": "array", "items": { "type": "string", "enum": ["fill", "totp", "inject", "update", "passkey", "rotate"] } },
                  "domain": { "type": "string", "description": "expected host (optional; by default the item's URLs)" } }, "required": ["ref", "permissions"] } },
              "wait_seconds": { "type": "integer", "description": "how long to wait for the person (default 60, max 600)" } },
            "required": ["task", "reason", "duration", "access"] } },
        { "name": "get_task", "description": "State of one of your tasks and what the person approved (access, removed).",
          "inputSchema": { "type": "object", "properties": { "task_id": { "type": "string" }, "wait_seconds": { "type": "integer", "description": "wait this long while it is pending (default 0, max 600)" } }, "required": ["task_id"] } },
        { "name": "list_tasks", "description": "Your recent tasks: pending, running and ended, also those the person offered you without a request (offered: true, with their reason), such as changing reused passwords. Work only with what is in each task's access.",
          "inputSchema": { "type": "object", "properties": {} } },
        { "name": "end_task", "description": "End one of your tasks when the job is done (or to withdraw a pending one).",
          "inputSchema": { "type": "object", "properties": { "task_id": { "type": "string" }, "reason": { "type": "string" } }, "required": ["task_id", "reason"] } },
    ]);
    if let Some(arr) = list.as_array_mut() {
        arr.push(request_secret_tool);
        arr.push(get_secret_request_tool);
    }
    list
}

fn reply(id: &Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

fn error(id: &Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

impl Server {
    /// Handles one message; `None` for notifications.
    async fn handle(&mut self, message: Value) -> Option<Value> {
        let id = message.get("id").cloned();
        let method = message
            .get("method")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let Some(id) = id else {
            return None; // notifications/initialized, cancelled…
        };
        let params = message.get("params").cloned().unwrap_or(Value::Null);
        Some(match method {
            "initialize" => {
                let version = params
                    .get("protocolVersion")
                    .and_then(Value::as_str)
                    .filter(|v| KNOWN_VERSIONS.contains(v))
                    .unwrap_or(PROTOCOL_VERSION);
                reply(
                    &id,
                    json!({
                        "protocolVersion": version,
                        "capabilities": { "tools": { "listChanged": false } },
                        "serverInfo": { "name": "klav", "version": env!("CARGO_PKG_VERSION") },
                        "instructions": "Klav keeps the person's secrets. Search first (search_items), prefer fill_login, run_with_secrets and inject_file over reveal, always give a real reason, and ask (request_access) instead of working around a denial. When an existing secret is missing (or needs updating), call request_secret (with proxy_proposal when a sandbox needs it) instead of asking the person to paste it in chat. When a tool answers status \"pending\", follow its `next`: tell the person, run its wait_command in the background, and continue when it exits 0. Before a job that touches several items or sites, ask for one task with request_task, and call end_task when done. To change a password, work inside a task with rotate (list_tasks shows the ones the person offered you): change_password_url, open the page, rotate_password with target \"extension\", submit the form, then rotate_confirm or rotate_cancel; never try to see, copy or type the password yourself. For a new account, create_item with generate: true.",
                    }),
                )
            }
            "ping" => reply(&id, json!({})),
            "tools/list" => reply(&id, json!({ "tools": tools() })),
            "resources/list" => reply(&id, json!({ "resources": [] })),
            "resources/templates/list" => reply(&id, json!({ "resourceTemplates": [] })),
            "prompts/list" => reply(&id, json!({ "prompts": [] })),
            "tools/call" => {
                let name = params
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned();
                let args = params
                    .get("arguments")
                    .cloned()
                    .unwrap_or_else(|| json!({}));
                let result = self.call(&name, &args).await;
                // A named approval or task only counts for the call it came
                // with.
                self.claim = None;
                self.task = None;
                if let Some(s) = &mut self.session {
                    s.release_claim();
                    s.release_task();
                }
                let (text, is_error) = match result {
                    Ok(value) => (
                        serde_json::to_string_pretty(&value).unwrap_or_default(),
                        false,
                    ),
                    Err(ToolError::Msg(message)) => (message, true),
                    Err(ToolError::Pending(id)) => (
                        serde_json::to_string_pretty(&self.pending_payload(id).await)
                            .unwrap_or_default(),
                        true,
                    ),
                };
                reply(
                    &id,
                    json!({ "content": [{ "type": "text", "text": text }], "isError": is_error }),
                )
            }
            _ => error(&id, -32601, &format!("method not found: {method}")),
        })
    }
}

pub(crate) async fn mcp_cmd(ctx: &Ctx, args: McpArgs) -> CliResult<()> {
    let cwd = std::env::current_dir()?;
    let config = project::load(None)?;
    let mut server = Server {
        home: ctx.home.clone(),
        agent_name: args.agent,
        wait: args.wait.min(MAX_WAIT),
        cwd,
        config,
        session: None,
        claim: None,
        task: None,
        expiring: Arc::default(),
    };
    let expiring = Arc::clone(&server.expiring);
    let mut signals = Signals::new()?;
    eprintln!("klav mcp: ready (stdio)");
    let result = tokio::select! {
        r = serve(&mut server) => r,
        _ = signals.recv() => Ok(()),
    };
    // The client went away: injected files do not outlive the session.
    lock(&expiring).remove_all();
    result
}

fn lock(cleanup: &Mutex<Cleanup>) -> std::sync::MutexGuard<'_, Cleanup> {
    cleanup
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// One line of stdin, at most [`MAX_LINE`] bytes: `None` at the end,
/// `Some(Err(()))` for a longer line (read to its end and dropped).
async fn next_frame<R: tokio::io::AsyncBufRead + Unpin>(
    input: &mut R,
) -> std::io::Result<Option<Result<Vec<u8>, ()>>> {
    let mut line = Vec::new();
    let mut too_long = false;
    loop {
        let chunk = input.fill_buf().await?;
        if chunk.is_empty() {
            return Ok(match (too_long, line.is_empty()) {
                (true, _) => Some(Err(())),
                (false, true) => None,
                (false, false) => Some(Ok(line)),
            });
        }
        let (part, done) = match chunk.iter().position(|&b| b == b'\n') {
            Some(i) => (&chunk[..=i], true),
            None => (chunk, false),
        };
        let used = part.len();
        if !too_long && line.len() + used <= MAX_LINE + 1 {
            line.extend_from_slice(part);
        } else {
            too_long = true;
            line = Vec::new();
        }
        input.consume(used);
        if done {
            return Ok(Some(if too_long { Err(()) } else { Ok(line) }));
        }
    }
}

/// The answer to one frame: `-32700` for what is not JSON (invalid UTF-8
/// included, or longer than [`MAX_LINE`]), `-32600` for JSON that is not a
/// request object (layer 04: a bad frame never ends the server).
async fn answer(server: &mut Server, frame: Result<Vec<u8>, ()>) -> Option<Value> {
    let Ok(bytes) = frame else {
        return Some(error(&Value::Null, -32700, "parse error: message too long"));
    };
    let Ok(text) = std::str::from_utf8(&bytes) else {
        return Some(error(&Value::Null, -32700, "parse error: not UTF-8"));
    };
    if text.trim().is_empty() {
        return None;
    }
    match serde_json::from_str::<Value>(text) {
        Ok(message) if message.is_object() => server.handle(message).await,
        Ok(_) => Some(error(&Value::Null, -32600, "invalid request")),
        Err(_) => Some(error(&Value::Null, -32700, "parse error")),
    }
}

async fn serve(server: &mut Server) -> CliResult<()> {
    let mut input = BufReader::new(tokio::io::stdin());
    let mut stdout = tokio::io::stdout();
    while let Some(frame) = next_frame(&mut input).await? {
        let answer = answer(server, frame).await;
        if let Some(answer) = answer {
            let mut text = answer.to_string();
            text.push('\n');
            stdout.write_all(text.as_bytes()).await?;
            stdout.flush().await?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{ToolError, live_exe, sh_quote};

    #[test]
    fn a_pause_from_klavd_keeps_its_scope_and_times() {
        let paused = klav_proto::agent::AgentPaused {
            scope: klav_proto::agent::PauseScope::Agent,
            since: 1_000,
            until: Some(2_000),
        };
        let from_klavd = crate::error::CliError::Daemon(klav_daemon::protocol::ErrorBody {
            code: klav_daemon::protocol::ErrorCode::AgentsPaused,
            message: "paused".into(),
            paused: Some(paused),
            presence: None,
        });
        let ToolError::Msg(text) = ToolError::from(from_klavd) else {
            panic!("a message");
        };
        let json: serde_json::Value = serde_json::from_str(&text).expect("json");
        assert_eq!(json["status"], "paused");
        assert_eq!(json["scope"], "agent");
        assert_eq!(json["since"], 1_000);
        assert_eq!(json["until"], 2_000);
    }

    #[test]
    fn wait_commands_name_the_binary_that_replaced_a_deleted_one() {
        let dir = tempfile::tempdir().expect("tempdir");
        let klav = dir.path().join("klav");
        std::fs::write(&klav, b"").expect("klav");
        let deleted = dir.path().join("klav (deleted)");
        // Linux's name for a replaced binary: the new one at the same path.
        assert_eq!(live_exe(deleted.clone()), klav);
        // Nothing at the original path any more: keep what the OS said.
        std::fs::remove_file(&klav).expect("remove");
        assert_eq!(live_exe(deleted.clone()), deleted);
        // A file really named like that is left alone.
        std::fs::write(&klav, b"").expect("klav");
        std::fs::write(&deleted, b"").expect("named so");
        assert_eq!(live_exe(deleted.clone()), deleted);
        // A normal path is unchanged.
        assert_eq!(live_exe(klav.clone()), klav);
    }

    #[test]
    fn wait_commands_quote_paths_for_the_shell() {
        assert_eq!(sh_quote("/usr/local/bin/klav"), "/usr/local/bin/klav");
        assert_eq!(
            sh_quote("/Users/a b/klav-prueba"),
            "'/Users/a b/klav-prueba'"
        );
        assert_eq!(sh_quote("it's"), r"'it'\''s'");
        assert_eq!(sh_quote("$(rm -rf ~)"), "'$(rm -rf ~)'");
        assert_eq!(sh_quote(""), "''");
    }

    #[test]
    fn request_secret_tool_schema_carries_no_secret_value_field() {
        let list = super::tools();
        let arr = list.as_array().expect("tools array");
        let tool = arr
            .iter()
            .find(|t| t["name"] == "request_secret")
            .expect("request_secret tool");
        let props = tool["inputSchema"]["properties"]
            .as_object()
            .expect("properties");
        assert!(props.contains_key("reason"));
        assert!(props.contains_key("proxy_proposal"));
        assert!(!props.contains_key("value"));
        assert!(!props.contains_key("secret"));
        assert!(
            arr.iter().any(|t| t["name"] == "get_secret_request"),
            "get_secret_request tool present"
        );
    }
}
