//! `DaemonEngine`: the Mac app's vault engine (ADR 0027 §3). A client of
//! `klavd` over its socket in `$KLAV_HOME`, the same protocol as `klav` and
//! `klav-native-host` (`docs/klavd.md` §3), so the app, the CLI and the
//! browser extension share one unlocked state and one Touch ID enrolment.
//!
//! The app never holds the account's keys: `klavd` decrypts, signs and
//! asks for Touch ID. Values the person reveals or copies cross as
//! `String`, as with `KlavCore` (ADR 0018 §1).
//!
//! Only with the `daemon` feature, which the Mac slice of the XCFramework
//! is built with: the iOS bindings do not have this object. The records it
//! shares with `KlavCore` (the activity, the pauses) are in every build.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, TryLockError};
use std::time::Instant;

use klav_client::Home;
use klav_client::activity::ItemActivity;
use klav_client::agents::{AgentView, ApprovalView};
use klav_client::proxy_admin::ProxyStatus;

use crate::mcp::McpServersInfo;
use klav_client::audit::{ChainStatus, LogLine, VerifyReport};
use klav_client::history::{GeneratedSelection, GeneratedView, PasswordHistoryView};
use klav_client::ops::{ItemView, SecretText, TotpCode};
use klav_client::secret_requests::{FulfillSecretResult, SecretRequestCard};
use klav_client::tasks::TaskCard;
use klav_client::{ItemSummary, ProjectSummary, SyncReport, VaultSummary};
use klav_daemon::client::DaemonClient;
use klav_daemon::protocol::{
    DaemonStatus, ErrorBody, ErrorCode, PauseInEffect, PresencePurpose, Request,
};
use serde::Deserialize;
use serde::de::DeserializeOwned;

use crate::activity::{
    AuditStatusInfo, ItemActivityInfo, LogEntryInfo, LogFilterInput, VerifyInfo, audit_status_info,
    item_activity_info, log_entry, log_filter, verify_info,
};
use crate::grants::{
    ExposureInfo, GrantChangeInput, GrantChangePreviewInfo, GrantChangeReportInfo, GrantEditorInfo,
    GrantedProjectInfo, KeyChangeCostInfo, RevocationInfo, RevokeReportInfo, change_report_info,
    cost_of, exposure_info, grant_change, grant_editor_info, older_klavd_editor,
    pending_revocation_info, preview_info, revocation_progress_info, revoke_report_info,
};
use crate::health::{
    HealthSettingsInfo, OfferInput, PasswordHistoryInfo, ReusedOfferInfo, TaskProgressInfo,
    VaultHealthInfo, history_info, offer_request, reused_offer_info, task_progress_info,
    vault_health_info,
};
use crate::pause::{DevAgentInfo, PauseInfo, agent_id, dev_agents, optional_agent};
use crate::presence::{
    CHANGED_WHILE_CONFIRMING, HELD_WAIT, Held, HeldInfo, PASSWORD_CHECK_RUNNING, PresenceSetting,
    UnlockOutcome, UnlockQuestionInfo,
};
use crate::sandboxes::{
    SandboxListCheckedInfo, SandboxListInfo, SandboxRevokeInfo, revoke_info, sandbox_list_info,
};
use crate::types::{
    AccountDeletionInfo, AgentItem, ApprovalItem, GeneratedEntryInfo, ItemDetail, ItemEdit,
    ItemInfo, ItemQuery, NewItemInput, ProjectInfo, SecretRequestFulfillInput,
    SecretRequestFulfillOutput, SecretRequestItem, SignOutCheck, SyncInfo, TaskChoiceInput,
    TaskItem, TotpInfo, VaultInfo,
};
use crate::{
    KlavError, KlavResult, agent_item, agent_items, approval_item, default_grant,
    fulfill_secret_request_input, fulfill_secret_request_output, generated_entry, item_filter,
    item_infos, item_patch, new_item, project_infos, secret_request_item, task_choice, task_item,
    vault_infos,
};

/// What the Mac app shows of `klavd` (the menu bar's state).
#[derive(Debug, Clone, uniffi::Record)]
pub struct DaemonInfo {
    /// `klavd` answers on the socket of this home.
    pub running: bool,
    /// Its version (the app restarts one that is not its own, ADR 0027
    /// §4.1).
    pub version: Option<String>,
    /// Its process ID.
    pub pid: Option<u32>,
    /// An account exists in this home (read from `account.json` when
    /// `klavd` is not running).
    pub logged_in: bool,
    /// The account's e-mail, when logged in.
    pub email: Option<String>,
    /// Holding the unlocked account.
    pub unlocked: bool,
    /// `password` or `touch_id`.
    pub unlocked_with: Option<String>,
    /// Seconds without use before it locks.
    pub idle_lock_secs: u64,
    /// Seconds left before it locks, when unlocked.
    pub locks_in_secs: Option<u64>,
    /// Touch ID works on this Mac.
    pub touch_id_available: bool,
    /// A Secure Enclave key protects this home's local key.
    pub touch_id_enrolled: bool,
    /// Why the master password is needed next time, if it is.
    pub password_required: Option<String>,
    /// Moves when what the reads answer may have changed: read again.
    pub revision: u64,
    /// A background sync is in flight.
    pub syncing: bool,
    /// Browsers whose extension attached to this `klavd` («Connected in
    /// Dia», ADR 0027 §4), newest first.
    pub browsers: Vec<BrowserLink>,
    /// The pauses of agents in effect (ADR 0033 §7), also while locked:
    /// «Pause agents» in the menu bar and above Development › Agents.
    pub agents_paused: Vec<PauseInfo>,
    /// The deletion of the account the person asked for (ADR 0037 §3), as
    /// `klavd` last learned it, also while locked: Settings › Account and
    /// the notice above the vault. Kept after the deletion, for its date.
    /// `klavd` keeps it in `account-deletion.json`, so it holds across a
    /// restart of `klavd` until the next sync says otherwise.
    pub account_deletion: Option<AccountDeletionInfo>,
    /// Klav deleted the account: `klavd` no longer syncs and the copy
    /// stays, read-only, until the person deletes it (T165).
    pub account_deleted: bool,
    /// Revocations whose key change was asked for and is not finished
    /// (ADR 0033, amendment of 2026-11-10, F2), also while locked: then
    /// only counts, without names or errors. Empty from a `klavd` older
    /// than the amendment.
    pub revocations: Vec<RevocationInfo>,
    /// `klavd` could not read this device's record of owed key changes:
    /// `revocations` may be out of date, and no key change is finished
    /// until it reads again («Revoke…» says why). False from an older
    /// `klavd`.
    pub revocations_unreadable: bool,
    /// With `revocations_unreadable`: a newer Klav wrote the record.
    /// Updating Klav reads it; nothing says to move it aside. False from an
    /// older `klavd`.
    pub revocations_newer: bool,
    /// The commit this `klavd` was built from: with `commit_time`, what
    /// tells two builds of the same `version` apart (ADR 0027 §4.1). None
    /// from an older `klavd` or a build without Git history.
    #[uniffi(default = None)]
    pub commit: Option<String>,
    /// That commit's committer time, in Unix seconds.
    #[uniffi(default = None)]
    pub commit_time: Option<u64>,
    /// The presence gate is on in this `klavd` (ADR 0041; `status` carries
    /// `presence`). False from an older `klavd` and with the gate off.
    #[uniffi(default = false)]
    pub presence_gate: bool,
}

/// A browser whose extension attached to `klavd`.
#[derive(Debug, Clone, uniffi::Record)]
pub struct BrowserLink {
    /// The name the extension gave (`Dia`, `Google Chrome`, `Firefox`…).
    pub browser: String,
    /// Attached now.
    pub connected: bool,
    /// When it last attached or left (Unix ms).
    pub at_ms: u64,
}

/// The vault through `klavd`.
#[derive(uniffi::Object)]
pub struct DaemonEngine {
    home: Home,
    runtime: tokio::runtime::Runtime,
    /// The one long connection (ADR 0041 §1.2): `hold`, then `unlock` and
    /// the values, one call at a time. Everything else opens its own.
    held: Mutex<Held>,
    /// Open a new long connection, with `hold`, at its next use: Settings
    /// moved the presence setting off Always, which dropped the old one's
    /// declaration (the ADR's own choice 1).
    reopen: AtomicBool,
}

impl DaemonEngine {
    /// The Klav directory this engine talks to `klavd` in.
    pub(crate) fn home_dir(&self) -> &Home {
        &self.home
    }

    /// The long connection, waiting at most [`HELD_WAIT`] for another call
    /// on it (a Touch ID dialog that is open, say): then the app is told
    /// it is busy, rather than lining up behind it.
    fn lock_held(&self) -> KlavResult<MutexGuard<'_, Held>> {
        let deadline = Instant::now() + HELD_WAIT;
        loop {
            let mut held = match self.held.try_lock() {
                Ok(held) => held,
                // A call panicked holding it: what it held is unknown, so
                // the connection goes.
                Err(TryLockError::Poisoned(p)) => {
                    let mut held = p.into_inner();
                    held.drop_connection();
                    self.held.clear_poison();
                    held
                }
                Err(TryLockError::WouldBlock) => {
                    if Instant::now() >= deadline {
                        return Err(KlavError::PresenceBusy {
                            password_check: false,
                            in_this_app: true,
                            message: "Klav is already confirming something else in this app".into(),
                        });
                    }
                    std::thread::sleep(std::time::Duration::from_millis(20));
                    continue;
                }
            };
            if self.reopen.swap(false, Ordering::AcqRel) {
                held.drop_connection();
            }
            return Ok(held);
        }
    }

    /// A request of the window (ADR 0041 §3) on the long connection: with
    /// `password`, only as the answer to `klavd`'s ask on it.
    fn held_value<R: DeserializeOwned>(
        &self,
        make: impl Fn(Option<SecretText>) -> Request + Sync,
        password: Option<String>,
    ) -> KlavResult<R> {
        let mut held = self.lock_held()?;
        let (answer, _warnings) = self
            .runtime
            .block_on(held.value::<R>(&self.home, &make, password))?;
        Ok(answer)
    }

    /// One request on a new connection. A connection is cheap (a Unix
    /// socket) and keeps a long call, such as an unlock waiting for Touch
    /// ID, from holding up the menu bar's status.
    fn call<R: DeserializeOwned>(&self, request: Request) -> KlavResult<R> {
        self.runtime.block_on(async {
            let mut client = DaemonClient::connect(&self.home)
                .await
                .ok_or_else(not_running)?;
            let password = carries_password(&request);
            client
                .call::<R>(request)
                .await
                .map(|(answer, _warnings)| answer)
                .map_err(|e| sent_error(e, password))
        })
    }

    /// A request a `klavd` older than the operation does not know: `None`
    /// when it answers that the request is malformed, as one older than
    /// the amendment of 2026-11-10 does for its new operations.
    fn call_new<R: DeserializeOwned>(&self, request: Request) -> KlavResult<Option<R>> {
        self.runtime.block_on(async {
            let mut client = DaemonClient::connect(&self.home)
                .await
                .ok_or_else(not_running)?;
            let password = carries_password(&request);
            match client.call::<R>(request).await {
                Ok((answer, _warnings)) => Ok(Some(answer)),
                Err(e) if older_klavd(&e) => Ok(None),
                Err(e) => Err(sent_error(e, password)),
            }
        })
    }

    /// What changing the keys of `projects` costs: the items in them,
    /// the trash included, and the other active agents that hold one (F2,
    /// item 2). Best effort, and says so: what cannot be read makes it a
    /// lower bound (`items_at_least`, `others_at_least`), never a zero.
    fn key_change_cost(&self, agent: &str, projects: &[GrantedProjectInfo]) -> KeyChangeCostInfo {
        let mut listings = Vec::new();
        for p in projects {
            for trash in [false, true] {
                listings.push(
                    self.call::<Vec<ItemSummary>>(Request::List {
                        filter: klav_client::ItemFilter {
                            project: Some(p.project_id.clone()),
                            trash,
                            ..klav_client::ItemFilter::default()
                        },
                    })
                    .map(|items| items.len()),
                );
            }
        }
        cost_of(
            agent,
            projects,
            &listings,
            self.call::<Vec<AgentView>>(Request::Agents),
        )
    }

    /// The item's fields with their values (`view` with `reveal`), on the
    /// long connection.
    fn revealed(&self, id: &str, password: Option<String>) -> KlavResult<ItemView> {
        let query = crate::item_id(id)?.to_string();
        self.held_value(
            |password| Request::View {
                query: query.clone(),
                reveal: true,
                password,
            },
            password,
        )
    }

    fn field_of(view: ItemView, field: &str) -> KlavResult<String> {
        let found = view
            .fields
            .into_iter()
            .find(|f| f.name == field)
            .ok_or_else(|| KlavError::NotFound {
                message: format!("field {field:?}"),
            })?;
        found
            .value
            .map(|v| v.expose().to_owned())
            .ok_or_else(|| KlavError::invalid("this field has no text value"))
    }

    fn totp_info(code: TotpCode) -> TotpInfo {
        // `klavd` does not send the period; almost every site uses 30 s,
        // and a code with more time left than that is a 60 s one.
        let period = if code.remaining > 30 { 60 } else { 30 };
        TotpInfo {
            code: code.code.expose().to_owned(),
            remaining: code.remaining,
            period,
        }
    }
}

impl DaemonEngine {
    fn revoke_sandboxes(
        &self,
        proxy_id: String,
        sandbox_id: Option<String>,
    ) -> KlavResult<SandboxRevokeInfo> {
        let proxy = agent_id(&proxy_id)?;
        let scope = match crate::sandboxes::revoke_target(sandbox_id)? {
            klav_proto::sandbox::RevokeTarget::All => klav_proto::sandbox::SCOPE_ALL.to_owned(),
            klav_proto::sandbox::RevokeTarget::One(id) => id.to_string(),
        };
        let outcome: Option<klav_client::sandbox_revoke::RevokeOutcome> =
            self.call_new(Request::SandboxRevoke { proxy, scope })?;
        outcome.map(revoke_info).ok_or_else(update_klavd_sandboxes)
    }
}

impl DaemonEngine {
    fn totp_with(&self, id: String, password: Option<String>) -> KlavResult<TotpInfo> {
        let query = crate::item_id(&id)?.to_string();
        let code: TotpCode = self.held_value(
            |password| Request::Totp {
                query: query.clone(),
                field: None,
                password,
            },
            password,
        )?;
        Ok(Self::totp_info(code))
    }

    fn previous_with(
        &self,
        id: String,
        index: u32,
        password: Option<String>,
    ) -> KlavResult<String> {
        let query = crate::item_id(&id)?.to_string();
        let index = usize::try_from(index).unwrap_or(usize::MAX);
        let value: SecretText = self.held_value(
            |password| Request::PreviousPassword {
                query: query.clone(),
                index,
                password,
            },
            password,
        )?;
        Ok(value.expose().to_owned())
    }

    fn generated_with(&self, created_at: i64, password: Option<String>) -> KlavResult<String> {
        let value: SecretText = self.held_value(
            |password| Request::GeneratedValue {
                created_at,
                password,
            },
            password,
        )?;
        Ok(value.expose().to_owned())
    }

    /// The long connection's state (for the tests).
    #[doc(hidden)]
    pub fn held_connection(&self) -> HeldInfo {
        match self.held.lock() {
            Ok(held) => held.info(),
            Err(p) => p.into_inner().info(),
        }
    }
}

/// `{ "window": … }` of `presence_window`.
#[derive(Deserialize)]
struct WindowReply {
    window: klav_daemon::uv::Window,
}

/// `presence_window` from a `klavd` older than the gate.
fn older_klavd_presence() -> KlavError {
    KlavError::NotSupported {
        message: "The klavd running is older than the presence setting. Update Klav.".into(),
    }
}

/// What a `klavd` that does not know an operation or a field answers.
/// The app sends only well-formed requests, so any `bad_request` means
/// this `klavd` does not know it; the code is enough, whatever the words.
fn older_klavd(e: &ErrorBody) -> bool {
    e.code == ErrorCode::BadRequest
}

/// The words for an operation a `klavd` this old does not have.
fn update_klavd() -> KlavError {
    KlavError::invalid(
        "The klavd running is older than changing an agent's permissions from the app. Update Klav, or use `klav agent approve` in the terminal.",
    )
}

/// The words for the sandboxes (their list and their revocation) on a
/// `klavd` older than them.
fn update_klavd_sandboxes() -> KlavError {
    KlavError::invalid(
        "The klavd running is older than the sandbox list and revocation. Update Klav, then try again.",
    )
}

pub(crate) fn not_running() -> KlavError {
    KlavError::DaemonUnavailable {
        message: "klavd is not running".into(),
    }
}

/// Whether `request` carries the master password: then a `presence_busy`
/// means another password check is running, as the CLI says it from what
/// it sent (klavd's one code covers a dialog, a password check and a
/// setting change).
pub(crate) fn carries_password(request: &Request) -> bool {
    match request {
        Request::Unlock { password, .. }
        | Request::View { password, .. }
        | Request::Totp { password, .. }
        | Request::Resolve { password, .. }
        | Request::Autofill { password, .. }
        | Request::PasskeyGet { password, .. }
        | Request::PasskeyCreate { password, .. }
        | Request::ApproveAgent { password, .. }
        | Request::DecideApproval { password, .. }
        | Request::DecideTask { password, .. }
        | Request::AddToTask { password, .. }
        | Request::FulfillSecretRequest { password, .. }
        | Request::GrantChangeApply { password, .. }
        | Request::ProxyUse { password, .. }
        | Request::ProxyGrant { password, .. }
        | Request::ProxyRevoke { password, .. }
        | Request::ProxyIssuerAdd { password, .. }
        | Request::ProxyIssuerRemove { password, .. }
        | Request::ResumeAgents { password, .. }
        | Request::CancelAccountDeletion { password, .. }
        | Request::GeneratedValue { password, .. }
        | Request::PreviousPassword { password, .. }
        | Request::OfferTask { password, .. }
        | Request::PasskeyUv { password, .. }
        | Request::PresenceWindow { password, .. } => password.is_some(),
        _ => false,
    }
}

/// [`daemon_error`] for a request that did (or didn't) carry the master
/// password.
pub(crate) fn sent_error(e: ErrorBody, password: bool) -> KlavError {
    match daemon_error(e) {
        KlavError::PresenceBusy {
            in_this_app: false,
            message,
            ..
        } if password => KlavError::PresenceBusy {
            password_check: true,
            in_this_app: false,
            message,
        },
        other => other,
    }
}

/// `klavd`'s error codes as the app's errors. Messages never hold secrets.
pub(crate) fn daemon_error(e: ErrorBody) -> KlavError {
    // klavd's words can carry an agent's name («agent bot is revoked»):
    // one line, nothing hidden (T136).
    let message = crate::grants::report_text(&e.message);
    match e.code {
        ErrorCode::Locked => KlavError::Locked,
        ErrorCode::NotLoggedIn => KlavError::NotLoggedIn,
        ErrorCode::WrongCredentials => KlavError::WrongCredentials,
        ErrorCode::SessionExpired => KlavError::SessionExpired,
        ErrorCode::Network => KlavError::Network { message },
        ErrorCode::Rollback => KlavError::Rollback { message },
        ErrorCode::Security => KlavError::Security { message },
        ErrorCode::NotFound => KlavError::NotFound { message },
        // With the gate off, another master password being checked is a
        // `conflict` too (own choice 18): not an item that changed. And an
        // item edited between the question and the hand-out is its own
        // case (Omar's decision F). Told apart by klavd's words, pinned in
        // the tests.
        ErrorCode::Conflict if e.message.starts_with(PASSWORD_CHECK_RUNNING) => {
            KlavError::PresenceBusy {
                password_check: true,
                in_this_app: false,
                message,
            }
        }
        ErrorCode::Conflict if e.message.starts_with(CHANGED_WHILE_CONFIRMING) => {
            KlavError::ChangedWhileConfirming { message }
        }
        ErrorCode::Conflict => KlavError::Conflict { version: 0 },
        // Only the browser's native host sends `ExtensionNotAllowed`; klavd never
        // does.
        ErrorCode::Denied | ErrorCode::ExtensionNotAllowed => KlavError::Denied { message },
        // A pause refuses like a denial (ADR 0033 §7.4). Its own variant
        // can come with the Mac app's pause (layer 5), without changing the
        // Swift bindings now.
        ErrorCode::AgentsPaused => KlavError::Denied { message },
        // The account waits to be deleted, or is gone (ADR 0037 §3). klavd
        // sends the date in `status`, not here.
        ErrorCode::AccountDeleting => KlavError::AccountDeleting { message },
        ErrorCode::AccountDeleted => KlavError::AccountDeleted {
            delete_at: None,
            message,
        },
        ErrorCode::BiometryFailed => KlavError::BiometryFailed { message },
        // The policy's «enter the password» comes in `status`
        // (`password_required`); here every refusal of Touch ID is one.
        ErrorCode::BiometryUnavailable => KlavError::BiometryUnavailable { message },
        // The presence gate (ADR 0041, layer 5).
        ErrorCode::PresenceRequired => match e.presence {
            Some(ask) => KlavError::PresenceRequired { ask: (*ask).into() },
            None => KlavError::Denied { message },
        },
        // Said by what was sent ([`sent_error`]): a request without the
        // password met another program's dialog.
        ErrorCode::PresenceBusy => KlavError::PresenceBusy {
            password_check: false,
            in_this_app: false,
            message,
        },
        ErrorCode::NotSupported => KlavError::NotSupported { message },
        // Only an agent's browser request gets it (ADR 0041 §3.1), never
        // the app's.
        ErrorCode::BrowserAmbiguous => KlavError::Denied { message },
        // The client's own errors: the socket closed or never answered.
        ErrorCode::Internal if message.starts_with("klavd c") => {
            KlavError::DaemonUnavailable { message }
        }
        ErrorCode::Invalid | ErrorCode::BadRequest | ErrorCode::Internal => {
            KlavError::Invalid { message }
        }
    }
}

/// `{ "created_at": … }` of `generator_record`.
#[derive(Deserialize)]
struct Recorded {
    created_at: i64,
}

/// `{ "removed": … }` of `generator_delete`.
#[derive(Deserialize)]
struct Removed {
    removed: usize,
}

/// `{ "canceled": … }` of `cancel_account_deletion`.
#[derive(Deserialize)]
struct Canceled {
    canceled: bool,
}

/// `{ "breach_check": … }` of `health_settings`.
#[derive(Deserialize)]
struct Settings {
    breach_check: bool,
}

fn pause_info(p: PauseInEffect) -> PauseInfo {
    PauseInfo {
        agent_id: p.agent_id.map(|a| a.to_string()),
        since_ms: p.since,
        until_ms: p.until,
        local: p.local,
        server_unsupported: p.server_unsupported,
    }
}

#[uniffi::export]
impl DaemonEngine {
    /// The `klavd` of `home_dir` (on macOS, `~/Library/Application
    /// Support/klav`). Nothing is contacted yet.
    #[uniffi::constructor]
    pub fn new(home_dir: String) -> KlavResult<Arc<Self>> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| KlavError::invalid(format!("cannot start the runtime: {e}")))?;
        Ok(Arc::new(Self {
            home: Home::at(home_dir),
            runtime,
            held: Mutex::new(Held::new()),
            reopen: AtomicBool::new(false),
        }))
    }

    /// The socket's path, for messages.
    pub fn socket_path(&self) -> String {
        self.home.socket_path().display().to_string()
    }

    /// `klavd`'s state, or `running: false` when nobody answers.
    pub fn status(&self) -> DaemonInfo {
        let account = klav_client::account(&self.home).ok();
        let device = account.as_ref().map(|a| a.device_id);
        match self.call::<DaemonStatus>(Request::Status) {
            Ok(s) => DaemonInfo {
                running: true,
                version: Some(s.version),
                pid: Some(s.pid),
                logged_in: s.logged_in,
                email: s.email.or_else(|| account.map(|a| a.email)),
                unlocked: s.unlocked,
                unlocked_with: s.unlocked_with,
                idle_lock_secs: s.idle_lock_secs,
                locks_in_secs: s.locks_in_secs,
                touch_id_available: s.touch_id.available,
                touch_id_enrolled: s.touch_id.enrolled,
                password_required: s.touch_id.password_required,
                revision: s.revision,
                syncing: s.syncing,
                browsers: s
                    .browsers
                    .into_iter()
                    .map(|b| BrowserLink {
                        browser: b.browser,
                        connected: b.connected,
                        at_ms: b.at_ms,
                    })
                    .collect(),
                agents_paused: s.agents_paused.into_iter().map(pause_info).collect(),
                account_deletion: s.account_deletion.map(|d| AccountDeletionInfo {
                    requested_at: d.requested_at,
                    delete_at: d.delete_at,
                    // Without `account.json` there is no device to compare.
                    this_device: device == Some(d.device_id),
                    device_name: d.device_name,
                    deleted: s.account_deleted,
                }),
                account_deleted: s.account_deleted,
                revocations: s
                    .revocations
                    .into_iter()
                    .map(revocation_progress_info)
                    .collect(),
                revocations_unreadable: s.revocations_unreadable,
                revocations_newer: s.revocations_newer,
                commit: s.commit,
                commit_time: s.commit_time,
                presence_gate: s.presence.is_some(),
            },
            Err(_) => DaemonInfo {
                running: false,
                version: None,
                pid: None,
                logged_in: account.is_some(),
                email: account.map(|a| a.email),
                unlocked: false,
                unlocked_with: None,
                idle_lock_secs: 0,
                locks_in_secs: None,
                touch_id_available: false,
                touch_id_enrolled: false,
                password_required: None,
                revision: 0,
                syncing: false,
                browsers: Vec::new(),
                agents_paused: Vec::new(),
                account_deletion: None,
                account_deleted: false,
                revocations: Vec::new(),
                revocations_unreadable: false,
                revocations_newer: false,
                commit: None,
                commit_time: None,
                presence_gate: false,
            },
        }
    }

    /// What the unlock's question may say (ADR 0041 §2.4): opens a new
    /// long connection, declares `hold` on it, and reads `status` there, so
    /// what it says is that connection's. Call it when the lock screen
    /// shows, before the person types; the password then goes to
    /// [`Self::unlock`] on that same connection, with `shown` set to what
    /// the question said.
    pub fn unlock_question(&self) -> KlavResult<UnlockQuestionInfo> {
        let mut held = self.lock_held()?;
        self.runtime.block_on(async {
            held.open(&self.home).await?;
            let client = held.connected(&self.home).await?;
            let status: DaemonStatus = client
                .call(Request::Status)
                .await
                .map(|(s, _)| s)
                .map_err(daemon_error)?;
            Ok(UnlockQuestionInfo::of(status.presence))
        })
    }

    /// Unlocks `klavd` on the long connection: with Touch ID when
    /// `password` is absent (the system prompt names `klavd`, riesgo
    /// residual 43), or with the master password, which also enrols Touch
    /// ID (ADR 0013 §5).
    ///
    /// With the presence gate on (ADR 0041 §1.2, §2.4): a Touch ID unlock
    /// opens a new long connection and declares `hold` on it first, so the
    /// unlock can hold it until Klav locks. A password unlock goes on the
    /// connection [`Self::unlock_question`] opened, and sends `shown`: the
    /// window the app's question said it opens (`None`: the question named
    /// none, so it opens none). The app types the password into its own
    /// window, so nothing says it was untyped (own choice 46).
    pub fn unlock(
        &self,
        password: Option<String>,
        shown: Option<PresenceSetting>,
    ) -> KlavResult<UnlockOutcome> {
        let password = password.map(zeroize::Zeroizing::new);
        let mut held = self.lock_held()?;
        self.runtime.block_on(async {
            if password.is_none() || held.client.is_none() {
                held.open(&self.home).await?;
            }
            let mut tries = 0;
            loop {
                tries += 1;
                let client = held.connected(&self.home).await?;
                let answer = async {
                    // The envelope's fields only for a klavd that has them:
                    // an older one refuses unknown fields.
                    let status: DaemonStatus = client.call(Request::Status).await?.0;
                    let gate = status.presence.is_some();
                    let presence = klav_daemon::client::Presence {
                        notify: false,
                        shown: (gate && password.is_some())
                            .then(|| shown.map_or(klav_daemon::uv::Window::Always, Into::into)),
                        untyped: false,
                    };
                    client
                        .call_presence::<DaemonStatus>(
                            Request::Unlock {
                                password: password.as_ref().map(|p| SecretText::new(p.as_str())),
                                passkey_flow: false,
                            },
                            presence,
                            &mut |_| {},
                        )
                        .await
                }
                .await;
                match answer {
                    Ok((status, warnings)) => {
                        return Ok(UnlockOutcome::of(status.already_unlocked, warnings));
                    }
                    // klavd restarted under the app: once more, on a new
                    // long connection.
                    Err(e) if crate::presence::gone(&e) && tries == 1 => {
                        held.open(&self.home).await?;
                    }
                    Err(e) => return Err(sent_error(e, password.is_some())),
                }
            }
        })
    }

    /// Locks `klavd`: the CLI and the extension lock too.
    pub fn lock(&self) -> KlavResult<()> {
        self.call::<serde::de::IgnoredAny>(Request::Lock)?;
        Ok(())
    }

    /// Stops `klavd` (after an update, ADR 0027 §4.1: the LaunchAgent then
    /// starts the new one). The long connection goes first.
    pub fn shutdown(&self) -> KlavResult<()> {
        if let Ok(mut held) = self.lock_held() {
            held.drop_connection();
        }
        self.call::<serde::de::IgnoredAny>(Request::Shutdown)?;
        Ok(())
    }

    /// The presence setting (ADR 0041 §2.4), only from an unlocked `klavd`:
    /// `Locked` while locked (Q-N2), `NotSupported` with the gate off or
    /// from an older `klavd`.
    pub fn presence_window(&self) -> KlavResult<PresenceSetting> {
        let answer: Option<WindowReply> = self.call_new(Request::PresenceWindow {
            window: None,
            password: None,
        })?;
        answer
            .map(|a| a.window.into())
            .ok_or_else(older_klavd_presence)
    }

    /// Changes the presence setting. Tightening asks nothing; loosening
    /// asks for Touch ID in `klavd`, or, where Touch ID can't confirm
    /// (`BiometryUnavailable`), for `password`, and opens no window. A move
    /// off Always opens a new long connection with `hold` (the ADR's own
    /// choice 1): Always dropped the old one's declaration.
    pub fn set_presence_window(
        &self,
        window: PresenceSetting,
        password: Option<String>,
    ) -> KlavResult<PresenceSetting> {
        let before = self.presence_window()?;
        let answer: Option<WindowReply> = self.call_new(Request::PresenceWindow {
            window: Some(window.into()),
            password: password.map(SecretText::new),
        })?;
        let now: PresenceSetting = answer
            .map(|a| a.window.into())
            .ok_or_else(older_klavd_presence)?;
        if before == PresenceSetting::Always && now != PresenceSetting::Always {
            self.reopen.store(true, Ordering::Release);
            // Now if the long connection is free; otherwise at its next use.
            if let Ok(mut held) = self.lock_held() {
                let _ = self.runtime.block_on(held.open(&self.home));
            }
        }
        Ok(now)
    }

    /// The app closed its master-password window without an answer: the
    /// long connection takes other values again.
    pub fn presence_cancel(&self) {
        if let Ok(mut held) = self.lock_held() {
            held.forget_ask();
        }
    }

    /// Whether this account's server lets the person delete the account
    /// from the app (`account_deletion` in `/v1/health`, ADR 0037 §4).
    /// Asked before Touch ID or the password.
    pub fn deletion_supported(&self) -> KlavResult<bool> {
        let account = klav_client::account(&self.home)?;
        Ok(self
            .runtime
            .block_on(klav_client::deletion::supported(&account.server))?)
    }

    /// Asks the server to delete the account in 7 days (ADR 0037 §1), in
    /// this process, as the sign-in does (ADR 0027 §3). The Touch ID key is
    /// `klavd`'s, so where `klavd` has Touch ID set up it confirms the
    /// person's presence first (`confirm_presence`, which deletes nothing).
    /// `klavd` never sees the password (T164): it is checked here and
    /// proved to the server with OPAQUE. Then an unlocked `klavd` syncs,
    /// and stops what it mediates for agents at once.
    ///
    /// Touch ID is required whenever its enrolment exists in this home,
    /// not only when `klavd` says it is available: a Touch ID locked out
    /// after failed attempts, or a closed lid, refuses instead of leaving
    /// the password alone. Then `klavd` must answer, so stopping it is not
    /// a way around Touch ID either. A wrong password is
    /// `WrongCredentials`; a server that cannot is `DeletionUnsupported`,
    /// before Touch ID.
    pub fn request_account_deletion(&self, password: String) -> KlavResult<AccountDeletionInfo> {
        // The string uniffi hands over is wiped when dropped.
        let password = zeroize::Zeroizing::new(password);
        let account = klav_client::account(&self.home)?;
        if !self
            .runtime
            .block_on(klav_client::deletion::supported(&account.server))?
        {
            return Err(klav_client::ClientError::DeletionUnsupported.into());
        }
        if klav_daemon::client::touch_id_enrolled(&self.home) {
            self.call::<serde::de::IgnoredAny>(Request::ConfirmPresence {
                purpose: PresencePurpose::DeleteAccount,
            })?;
        }
        let unlocked_daemon = self
            .call::<DaemonStatus>(Request::Status)
            .is_ok_and(|s| s.unlocked);
        let (unlocked, asked) =
            self.runtime
                .block_on(klav_client::deletion::request_account_deletion(
                    &self.home,
                    &klav_core::crypto::kdf::MasterPassword::new(password.as_str()),
                ))?;
        drop(unlocked);
        if unlocked_daemon {
            // Best effort: otherwise klavd learns it at its next sync.
            let _ = self.call::<serde::de::IgnoredAny>(Request::Sync);
        }
        Ok(crate::deletion_info(&asked, account.device_id, false))
    }

    /// Cancels the deletion of the account with the session `klavd` holds
    /// (the vault must be unlocked). Canceling brings the agents back, so
    /// `klavd` asks what resuming them asks (ADR 0037 A2): Touch ID. Where
    /// it can't, `BiometryUnavailable` or `PasswordRequired` say the app
    /// should ask for the master password and call
    /// [`Self::cancel_account_deletion_with_password`]. `false` when there
    /// was none to cancel.
    pub fn cancel_account_deletion(&self) -> KlavResult<bool> {
        self.cancel_account_deletion_with_password(None)
    }

    /// `cancel_account_deletion` with the master password instead of Touch
    /// ID; a wrong one cancels nothing.
    pub fn cancel_account_deletion_with_password(
        &self,
        password: Option<String>,
    ) -> KlavResult<bool> {
        let reply: Canceled = self.call(Request::CancelAccountDeletion {
            password: password.map(SecretText::new),
        })?;
        Ok(reply.canceled)
    }

    /// What «Delete this Mac’s copy» would lose (ADR 0037, Q3 of the
    /// re-review): the generated passwords that never went up, only in
    /// this Mac's generator outbox. The Mac has no passkey outbox. The file
    /// decides (it is gone when empty); `klavd`, unlocked, says how many
    /// with the generator history, which lists them to copy. Locked, or
    /// when its list has none of them, it is `locked_with_queue`: something
    /// may be waiting.
    pub fn delete_copy_check(&self) -> KlavResult<SignOutCheck> {
        let waiting = self
            .home
            .file(klav_client::history::OUTBOX_FILE)
            .try_exists()
            .unwrap_or(true);
        let counted = if waiting {
            self.call::<Vec<GeneratedView>>(Request::GeneratorHistory)
                .map_or(0, |list| list.iter().filter(|e| e.pending).count())
        } else {
            0
        };
        Ok(SignOutCheck {
            unsent_passkeys: 0,
            unsent_generated: u32::try_from(counted).unwrap_or(u32::MAX),
            locked_with_queue: waiting && counted == 0,
        })
    }

    /// «Delete this Mac’s copy» (ADR 0037 §3, §7.6): stops `klavd`, which
    /// holds the account and writes its files, and deletes this Mac's copy
    /// of the account, the same files as `klav logout`. Nothing goes to the
    /// server: the account is gone. Only the person asks for it; no answer
    /// of the server deletes a copy (T165).
    ///
    /// Generated passwords that never went up are only here: without
    /// `discard_unsent` (the person's «Delete anyway»), any in the
    /// generator outbox refuses with `Denied`, as `klav logout` does
    /// without `--discard-unsent` (Q3). Checked before `klavd` stops, so
    /// it keeps running to list them, and again under the home's lock once
    /// it stopped: if that refuses, `klavd` is stopped and the app starts
    /// it again.
    pub fn delete_this_copy(&self, discard_unsent: bool) -> KlavResult<()> {
        let accepted = (!discard_unsent).then(klav_client::passkey_outbox::AcceptedUnsent::default);
        if accepted.is_some()
            && self
                .home
                .file(klav_client::history::OUTBOX_FILE)
                .try_exists()
                .unwrap_or(true)
        {
            return Err(KlavError::Denied {
                message: "generated passwords that never went up are only on this Mac: copy them, or delete this copy anyway".into(),
            });
        }
        if let Ok(mut held) = self.lock_held() {
            held.drop_connection();
        }
        self.runtime.block_on(async {
            if let Some(mut client) = DaemonClient::connect(&self.home).await {
                let _ = client
                    .call::<serde::de::IgnoredAny>(Request::Shutdown)
                    .await;
                for _ in 0..50 {
                    if DaemonClient::connect(&self.home).await.is_none() {
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            }
        });
        if self
            .runtime
            .block_on(DaemonClient::connect(&self.home))
            .is_some()
        {
            return Err(KlavError::invalid(
                "klavd is still running: quit it and try again",
            ));
        }
        klav_client::passkey_outbox::forget_account_unless_queued(&self.home, None, accepted)?;
        for name in klav_daemon::client::ACCOUNT_FILES {
            let _ = std::fs::remove_file(self.home.file(name));
        }
        Ok(())
    }

    /// Pulls every change from the server.
    pub fn sync(&self) -> KlavResult<SyncInfo> {
        let report: SyncReport = self.call(Request::Sync)?;
        Ok(SyncInfo {
            vaults_updated: u32::try_from(report.vaults_updated).unwrap_or(u32::MAX),
            items_received: u32::try_from(report.items_received).unwrap_or(u32::MAX),
            // The Mac has no passkey outbox (iOS only, ADR 0020 §11).
            passkeys_waiting: 0,
            passkey_queues_set_aside: 0,
            passkey_queue_set_aside_ids: Vec::new(),
        })
    }

    /// Vaults, by name.
    pub fn vaults(&self) -> KlavResult<Vec<VaultInfo>> {
        Ok(vault_infos(
            self.call::<Vec<VaultSummary>>(Request::Vaults)?,
        ))
    }

    /// Projects of a vault (or of all vaults), by name.
    pub fn projects(&self, vault_id: Option<String>) -> KlavResult<Vec<ProjectInfo>> {
        Ok(project_infos(self.call::<Vec<ProjectSummary>>(
            Request::Projects { vault: vault_id },
        )?))
    }

    /// Replaces the normalized Git repositories linked to a project (ADR 0032).
    pub fn set_project_repos(
        &self,
        vault_id: String,
        project_id: String,
        repos: Vec<String>,
    ) -> KlavResult<ProjectInfo> {
        let updated: ProjectSummary = self.call(Request::SetProjectRepos {
            vault: Some(vault_id),
            project: project_id,
            repos,
        })?;
        Ok(updated.into())
    }

    /// Items matching `query`, by title.
    pub fn items(&self, query: ItemQuery) -> KlavResult<Vec<ItemInfo>> {
        Ok(item_infos(self.call::<Vec<ItemSummary>>(
            Request::List {
                filter: item_filter(query),
            },
        )?))
    }

    /// An item, without secret values.
    pub fn item(&self, id: String) -> KlavResult<ItemDetail> {
        let view: ItemView = self.call(Request::View {
            query: crate::item_id(&id)?.to_string(),
            reveal: false,
            password: None,
        })?;
        Ok(view.into())
    }

    /// One field's value (the person asked to reveal or copy it). `klavd`
    /// answers the whole item revealed; the other values are dropped (and
    /// zeroized) here. With the presence gate on it may answer
    /// `PresenceRequired`: then [`Self::field_value_with_password`].
    pub fn field_value(&self, id: String, field: String) -> KlavResult<String> {
        Self::field_of(self.revealed(&id, None)?, &field)
    }

    /// `field_value` with the master password, as the answer to its
    /// `PresenceRequired`, on the connection that got it (own choice 32).
    pub fn field_value_with_password(
        &self,
        id: String,
        field: String,
        password: String,
    ) -> KlavResult<String> {
        Self::field_of(self.revealed(&id, Some(password))?, &field)
    }

    /// The item's notes (the person asked to see them).
    pub fn notes(&self, id: String) -> KlavResult<Option<String>> {
        Ok(self
            .revealed(&id, None)?
            .notes
            .map(|n| n.expose().to_owned()))
    }

    /// `notes` with the master password, as the answer to its
    /// `PresenceRequired`.
    pub fn notes_with_password(&self, id: String, password: String) -> KlavResult<Option<String>> {
        Ok(self
            .revealed(&id, Some(password))?
            .notes
            .map(|n| n.expose().to_owned()))
    }

    /// The current one-time password of an item.
    pub fn totp(&self, id: String) -> KlavResult<TotpInfo> {
        self.totp_with(id, None)
    }

    /// `totp` with the master password, as the answer to its
    /// `PresenceRequired`.
    pub fn totp_with_password(&self, id: String, password: String) -> KlavResult<TotpInfo> {
        self.totp_with(id, Some(password))
    }

    /// Creates an item (a repeated title is refused).
    pub fn create_item(&self, input: NewItemInput) -> KlavResult<ItemInfo> {
        let summary: ItemSummary = self.call(Request::Create {
            item: new_item(input),
        })?;
        Ok(summary.into())
    }

    /// Edits an item and uploads the next version.
    pub fn edit_item(&self, id: String, edit: ItemEdit) -> KlavResult<ItemInfo> {
        let summary: ItemSummary = self.call(Request::Edit {
            query: crate::item_id(&id)?.to_string(),
            patch: item_patch(edit),
        })?;
        Ok(summary.into())
    }

    /// Moves an item to the trash.
    pub fn trash_item(&self, id: String) -> KlavResult<()> {
        self.call::<serde::de::IgnoredAny>(Request::Trash {
            query: crate::item_id(&id)?.to_string(),
        })?;
        Ok(())
    }

    /// The previous passwords of an item, without values.
    pub fn password_history(&self, id: String) -> KlavResult<PasswordHistoryInfo> {
        let view: PasswordHistoryView = self.call(Request::PasswordHistory {
            query: crate::item_id(&id)?.to_string(),
        })?;
        Ok(history_info(view))
    }

    /// One previous password (the person asked to reveal or copy it).
    pub fn previous_password(&self, id: String, index: u32) -> KlavResult<String> {
        self.previous_with(id, index, None)
    }

    /// `previous_password` with the master password, as the answer to its
    /// `PresenceRequired`.
    pub fn previous_password_with_password(
        &self,
        id: String,
        index: u32,
        password: String,
    ) -> KlavResult<String> {
        self.previous_with(id, index, Some(password))
    }

    /// «Use the new one» or «Keep the current one» (ADR 0022 §5).
    pub fn resolve_pending(&self, id: String, accept: bool) -> KlavResult<PasswordHistoryInfo> {
        let view: PasswordHistoryView = self.call(Request::ResolvePending {
            query: crate::item_id(&id)?.to_string(),
            accept,
        })?;
        Ok(history_info(view))
    }

    /// Keeps a generated password in the generator history first.
    pub fn record_generated(&self, value: String, host: Option<String>) -> KlavResult<i64> {
        let recorded: Recorded = self.call(Request::GeneratorRecord {
            value: SecretText::new(value),
            host: host.as_deref().and_then(klav_core::site::item_host),
        })?;
        Ok(recorded.created_at)
    }

    /// The generator history, newest first, without values.
    pub fn generator_history(&self) -> KlavResult<Vec<GeneratedEntryInfo>> {
        let list: Vec<GeneratedView> = self.call(Request::GeneratorHistory)?;
        Ok(list.into_iter().map(generated_entry).collect())
    }

    /// The value of one generator history entry.
    pub fn generated_value(&self, created_at: i64) -> KlavResult<String> {
        self.generated_with(created_at, None)
    }

    /// `generated_value` with the master password, as the answer to its
    /// `PresenceRequired`.
    pub fn generated_value_with_password(
        &self,
        created_at: i64,
        password: String,
    ) -> KlavResult<String> {
        self.generated_with(created_at, Some(password))
    }

    /// Deletes the whole generator history.
    pub fn clear_generator_history(&self) -> KlavResult<u32> {
        let removed: Removed = self.call(Request::GeneratorDelete {
            which: GeneratedSelection::All,
        })?;
        Ok(u32::try_from(removed.removed).unwrap_or(u32::MAX))
    }

    /// Pending approval requests from agents.
    pub fn approvals(&self) -> KlavResult<Vec<ApprovalItem>> {
        let list: Vec<ApprovalView> = self.call(Request::Approvals { all: false })?;
        let names = self.mcp_names(crate::mcp::approvals_need_names(&list));
        Ok(list.into_iter().map(|a| approval_item(a, &names)).collect())
    }

    /// Deny, approve once (`lease_minutes = 0`) or for a while. Approving
    /// asks for Touch ID in `klavd`. `request_digest` is the one of the
    /// [`ApprovalItem`] the person decided on: nothing is signed if the
    /// request changed since (ADR 0030 §5).
    pub fn decide_approval(
        &self,
        id: String,
        approve: bool,
        lease_minutes: u32,
        request_digest: String,
    ) -> KlavResult<()> {
        self.decide_approval_with_password(id, approve, lease_minutes, request_digest, None)
    }

    /// `decide_approval` with the master password instead of Touch ID (a
    /// Mac without it, or after Touch ID refused: `BiometryUnavailable`).
    pub fn decide_approval_with_password(
        &self,
        id: String,
        approve: bool,
        lease_minutes: u32,
        request_digest: String,
        password: Option<String>,
    ) -> KlavResult<()> {
        self.call::<serde::de::IgnoredAny>(Request::DecideApproval {
            approval: id,
            approve,
            digest: request_digest,
            lease_secs: (approve && lease_minutes > 0).then(|| u64::from(lease_minutes) * 60),
            password: password.map(SecretText::new),
        })?;
        Ok(())
    }

    /// Task requests waiting and running tasks.
    pub fn tasks(&self) -> KlavResult<Vec<TaskItem>> {
        let cards: Vec<TaskCard> = self.call(Request::Tasks { all: false })?;
        Ok(cards.into_iter().map(task_item).collect())
    }

    /// Approves a pending task with the person's changes, or denies it.
    /// Approving asks for Touch ID in `klavd`. `request_digest` is the one
    /// of the [`TaskItem`] the person decided on (ADR 0030 §5).
    pub fn decide_task(
        &self,
        id: String,
        approve: bool,
        choice: Option<TaskChoiceInput>,
        request_digest: String,
    ) -> KlavResult<TaskItem> {
        self.decide_task_with_password(id, approve, choice, request_digest, None)
    }

    /// `decide_task` with the master password instead of Touch ID.
    pub fn decide_task_with_password(
        &self,
        id: String,
        approve: bool,
        choice: Option<TaskChoiceInput>,
        request_digest: String,
        password: Option<String>,
    ) -> KlavResult<TaskItem> {
        let card: TaskCard = self.call(Request::DecideTask {
            task: id,
            approve,
            digest: request_digest,
            choice: task_choice(choice.unwrap_or_default())?,
            password: password.map(SecretText::new),
        })?;
        Ok(task_item(card))
    }

    /// «Add to the task» (ADR 0021 §6). Asks for Touch ID in `klavd`.
    /// `request_digest` is the one of the [`ApprovalItem`] the person
    /// decided on (ADR 0030 §5).
    pub fn add_to_task(&self, approval_id: String, request_digest: String) -> KlavResult<TaskItem> {
        self.add_to_task_with_password(approval_id, request_digest, None)
    }

    /// `add_to_task` with the master password instead of Touch ID.
    pub fn add_to_task_with_password(
        &self,
        approval_id: String,
        request_digest: String,
        password: Option<String>,
    ) -> KlavResult<TaskItem> {
        let card: TaskCard = self.call(Request::AddToTask {
            approval: approval_id,
            digest: request_digest,
            password: password.map(SecretText::new),
        })?;
        Ok(task_item(card))
    }

    /// Pending secret requests from agents, opened and verified by `klavd`
    /// (ADR 0046).
    pub fn secret_requests(&self) -> KlavResult<Vec<SecretRequestItem>> {
        let cards: Vec<SecretRequestCard> = self.call(Request::SecretRequests { all: false })?;
        Ok(cards.into_iter().map(secret_request_item).collect())
    }

    /// Fulfills a pending secret request through `klavd`. When
    /// `input.grant_proxy` is true, `klavd` asks for Touch ID.
    pub fn fulfill_secret_request(
        &self,
        id: String,
        input: SecretRequestFulfillInput,
    ) -> KlavResult<SecretRequestFulfillOutput> {
        self.fulfill_secret_request_with_password(id, input, None)
    }

    /// `fulfill_secret_request` with the master password instead of Touch ID
    /// when `input.grant_proxy` is true.
    pub fn fulfill_secret_request_with_password(
        &self,
        id: String,
        input: SecretRequestFulfillInput,
        password: Option<String>,
    ) -> KlavResult<SecretRequestFulfillOutput> {
        let res: FulfillSecretResult = self.call(Request::FulfillSecretRequest {
            request: id,
            input: fulfill_secret_request_input(input),
            password: password.map(SecretText::new),
        })?;
        Ok(fulfill_secret_request_output(res))
    }

    /// Denies a pending secret request through `klavd` (signed by the account).
    pub fn deny_secret_request(
        &self,
        id: String,
        proposal_digest: String,
    ) -> KlavResult<SecretRequestItem> {
        let card: SecretRequestCard = self.call(Request::DenySecretRequest {
            request: id,
            digest: proposal_digest,
        })?;
        Ok(secret_request_item(card))
    }

    /// «End task».
    pub fn end_task(&self, id: String) -> KlavResult<TaskItem> {
        let card: TaskCard = self.call(Request::EndTask { task: id })?;
        Ok(task_item(card))
    }

    /// The account's agents: pending registrations first, then newest.
    pub fn agents(&self) -> KlavResult<Vec<AgentItem>> {
        let list: Vec<AgentView> = self.call(Request::Agents)?;
        Ok(agent_items(list))
    }

    /// Approves an agent's registration with the default policy, as
    /// `KlavCore::approve_agent`. Asks for Touch ID in `klavd`.
    pub fn approve_agent(
        &self,
        id: String,
        pairing_words: String,
        project_ids: Vec<String>,
        expires_in_days: Option<u32>,
    ) -> KlavResult<AgentItem> {
        self.approve_agent_with_password(id, pairing_words, project_ids, expires_in_days, None)
    }

    /// `approve_agent` with the master password instead of Touch ID.
    pub fn approve_agent_with_password(
        &self,
        id: String,
        pairing_words: String,
        project_ids: Vec<String>,
        expires_in_days: Option<u32>,
        password: Option<String>,
    ) -> KlavResult<AgentItem> {
        let view: AgentView = self.call(Request::ApproveAgent {
            agent: agent_id(&id)?,
            grant: default_grant(project_ids, expires_in_days)?,
            pairing_code: pairing_words,
            password: password.map(SecretText::new),
        })?;
        Ok(agent_item(view))
    }

    /// Denies a pending registration.
    pub fn deny_agent(&self, id: String) -> KlavResult<()> {
        self.call::<serde::de::IgnoredAny>(Request::DenyAgent {
            agent: agent_id(&id)?,
        })?;
        Ok(())
    }

    /// «What it saw» (ADR 0033, amendment of 2026-11-10, F2): the
    /// projects whose keys the agent held, what the log says it used, and
    /// what changing those keys costs. Read-only: no presence.
    pub fn agent_exposure(&self, id: String) -> KlavResult<ExposureInfo> {
        let exposure: klav_client::revoke::Exposure = self.call(Request::AgentExposure {
            agent: agent_id(&id)?,
        })?;
        let projects: Vec<GrantedProjectInfo> = exposure
            .projects
            .iter()
            .map(|p| GrantedProjectInfo {
                vault_id: p.vault_id.to_string(),
                vault: p.vault.clone(),
                project_id: p.project_id.to_string(),
                project: p.project.clone(),
            })
            .collect();
        let cost = self.key_change_cost(id.trim(), &projects);
        Ok(exposure_info(exposure, cost))
    }

    /// Revokes the agent, without presence (ADR 0014 §7.1). With
    /// `rotate`, then changes its projects' keys one at a time and answers
    /// when they are done (or stopped). A key change cut off by a lock goes
    /// on by itself at the next unlock (P11), and `status` says what is
    /// left meanwhile.
    pub fn revoke_agent(&self, id: String, rotate: bool) -> KlavResult<RevokeReportInfo> {
        let report: klav_client::revoke::RevokeReport = self.call(Request::RevokeAgent {
            agent: agent_id(&id)?,
            rotate,
            background: false,
        })?;
        Ok(revoke_report_info(report, KeyChangeCostInfo::default()))
    }

    /// Revokes the agent and has `klavd` change its projects' keys in the
    /// background (F2): the answer comes once the agent is revoked and the
    /// key change is written down, so it outlives the app (P11). `status`
    /// follows it (`revocations`); once the agent is no longer there, every
    /// key changed. `pending` lists what is left when it answers.
    ///
    /// None from a `klavd` older than this: nothing was done, and the app
    /// revokes without the key change, then asks for it (`revoke_agent`
    /// twice).
    pub fn revoke_agent_in_background(&self, id: String) -> KlavResult<Option<RevokeReportInfo>> {
        let report: Option<klav_client::revoke::RevokeReport> =
            self.call_new(Request::RevokeAgent {
                agent: agent_id(&id)?,
                rotate: true,
                background: true,
            })?;
        Ok(report.map(|r| revoke_report_info(r, KeyChangeCostInfo::default())))
    }

    /// The revocations whose key change was asked for and is not finished,
    /// with what is left. Empty from a `klavd` older than the amendment,
    /// which keeps no such record.
    pub fn agent_revocations(&self) -> KlavResult<Vec<RevocationInfo>> {
        let list: Option<Vec<klav_client::revoke::PendingRevocation>> =
            self.call_new(Request::AgentRevocations)?;
        Ok(list
            .unwrap_or_default()
            .into_iter()
            .map(pending_revocation_info)
            .collect())
    }

    /// The agent's grant in force in the editor's model, or read-only with
    /// the reason (F3). A `klavd` older than the editor gives a read-only
    /// grant that says so (`OlderKlavd`).
    pub fn grant_editor(&self, id: String) -> KlavResult<GrantEditorInfo> {
        let agent = agent_id(&id)?;
        let editor: Option<klav_client::grant_change::GrantEditor> =
            self.call_new(Request::GrantEditor { agent })?;
        Ok(editor.map_or_else(|| older_klavd_editor(agent.to_string()), grant_editor_info))
    }

    /// The sheet of a change: only the differences, whether it widens and
    /// the digest to send back with the same `change`. Signs nothing.
    pub fn grant_change_prepare(
        &self,
        id: String,
        change: GrantChangeInput,
    ) -> KlavResult<GrantChangePreviewInfo> {
        let preview: Option<klav_client::grant_change::GrantChangePreview> =
            self.call_new(Request::GrantChangePrepare {
                agent: agent_id(&id)?,
                change: grant_change(&change)?,
            })?;
        preview.as_ref().map(preview_info).ok_or_else(update_klavd)
    }

    /// Signs the change the sheet showed. `klavd` prepares it again and
    /// refuses if `digest` no longer matches («the grant changed while you
    /// were looking at it»); when it widens, it asks for Touch ID.
    pub fn grant_change_apply(
        &self,
        id: String,
        change: GrantChangeInput,
        digest: String,
    ) -> KlavResult<GrantChangeReportInfo> {
        self.grant_change_apply_with_password(id, change, digest, None)
    }

    /// `grant_change_apply` with the master password instead of Touch ID.
    pub fn grant_change_apply_with_password(
        &self,
        id: String,
        change: GrantChangeInput,
        digest: String,
        password: Option<String>,
    ) -> KlavResult<GrantChangeReportInfo> {
        let report: Option<klav_client::grant_change::GrantChangeReport> =
            self.call_new(Request::GrantChangeApply {
                agent: agent_id(&id)?,
                change: grant_change(&change)?,
                digest,
                password: password.map(SecretText::new),
            })?;
        report.map(change_report_info).ok_or_else(update_klavd)
    }

    /// The vault health report (ADR 0022 §4).
    pub fn vault_health(&self) -> KlavResult<VaultHealthInfo> {
        Ok(vault_health_info(self.call(Request::VaultHealth)?))
    }

    /// The breach check's setting of this home.
    pub fn health_settings(&self) -> KlavResult<HealthSettingsInfo> {
        let s: Settings = self.call(Request::HealthSettings { breach_check: None })?;
        Ok(HealthSettingsInfo {
            breach_check: s.breach_check,
        })
    }

    /// Turns the breach check on or off.
    pub fn set_breach_check(&self, on: bool) -> KlavResult<HealthSettingsInfo> {
        let s: Settings = self.call(Request::HealthSettings {
            breach_check: Some(on),
        })?;
        Ok(HealthSettingsInfo {
            breach_check: s.breach_check,
        })
    }

    /// The «Fix my reused passwords» card (ADR 0022 §6): the logins that
    /// share a password, checked against `agent`'s grant (the only agent
    /// with one when absent), and the agents that can take the task. For
    /// the person only: no agent command asks for it.
    pub fn reused_offer(&self, agent: Option<String>) -> KlavResult<ReusedOfferInfo> {
        let offer: klav_client::offer::ReusedOffer = self.call(Request::ReusedOffer { agent })?;
        Ok(reused_offer_info(offer))
    }

    /// Offers the agent a task with `rotate` on these logins, signed by the
    /// account without a request from the agent (ADR 0022 §6). `klavd`
    /// checks the offer before it asks for Touch ID, or for `password` on a
    /// Mac without it.
    pub fn offer_task_with_password(
        &self,
        offer: OfferInput,
        password: Option<String>,
    ) -> KlavResult<TaskItem> {
        let offer = offer_request(offer)?;
        if offer.items.is_empty() {
            return Err(KlavError::invalid(
                "nothing to offer: pick at least one login",
            ));
        }
        let card: TaskCard = self.call(Request::OfferTask {
            offer,
            password: password.map(SecretText::new),
        })?;
        Ok(task_item(card))
    }

    /// Where each site of a task with `rotate` is: changed, pending or
    /// failed.
    pub fn task_progress(&self, task_id: String) -> KlavResult<TaskProgressInfo> {
        let progress: klav_client::offer::TaskProgress = self.call(Request::TaskProgress {
            task: task_id.trim().to_owned(),
        })?;
        Ok(task_progress_info(progress))
    }

    /// «Activity» (ADR 0033 §8): the log this Mac downloaded, newest first,
    /// with the filters. Only what is new is downloaded; each event says
    /// whether it is verified yet.
    pub fn audit_log(&self, filter: LogFilterInput) -> KlavResult<Vec<LogEntryInfo>> {
        let limit = filter.limit.map(|l| l as usize);
        let filter = log_filter(filter)?;
        let mut lines: Vec<LogLine> = self.call(Request::AuditLog {
            filter: filter.clone(),
        })?;
        // A klavd of the same build applies them; this keeps the app right
        // with any other.
        lines.retain(|l| filter.keeps(l));
        if let Some(limit) = limit {
            lines.truncate(limit);
        }
        let names = self.mcp_names(crate::mcp::lines_need_names(&lines));
        Ok(crate::mcp::fold_sessions(
            lines.into_iter().map(|l| log_entry(l, &names)).collect(),
        ))
    }

    /// «Who used it» for one item (its ID or reference).
    pub fn item_activity(&self, item: String) -> KlavResult<ItemActivityInfo> {
        let activity: ItemActivity = self.call(Request::ItemActivity { item })?;
        let names = self.mcp_names(crate::activity::uses_need_names(&activity));
        Ok(item_activity_info(activity, &names))
    }

    /// «Development › MCP servers» (ADR 0049 §3, §9): the proxy's MCP
    /// profiles with their tool rules, the local clients its grant names,
    /// and the account's switch (`None` from a server older than the
    /// gateway). Never a value, a token or a token's digest.
    pub fn mcp_servers(&self) -> KlavResult<McpServersInfo> {
        let status: ProxyStatus = self.call(Request::ProxyStatus)?;
        let gateway_on: Option<bool> = self.call(Request::McpGateway)?;
        Ok(crate::mcp::mcp_servers_info(status, gateway_on))
    }

    /// Turns the account's MCP gateway switch on (ADR 0049 §9), after the
    /// sheet's «update every device first»: `every_device_updated` is that
    /// acknowledgement, and `klavd` refuses without it. Asks for Touch ID
    /// in `klavd` unless the switch is already on. Nothing turns it off.
    pub fn turn_mcp_gateway_on(&self, every_device_updated: bool) -> KlavResult<bool> {
        self.turn_mcp_gateway_on_with_password(every_device_updated, None)
    }

    /// `turn_mcp_gateway_on` with the master password instead of Touch ID.
    pub fn turn_mcp_gateway_on_with_password(
        &self,
        every_device_updated: bool,
        password: Option<String>,
    ) -> KlavResult<bool> {
        self.call(Request::McpGatewayOn {
            every_device_updated,
            password: password.map(SecretText::new),
        })
    }

    /// How much of the log this Mac has downloaded and verified, without
    /// contacting the server.
    pub fn audit_status(&self) -> KlavResult<AuditStatusInfo> {
        let status: ChainStatus = self.call(Request::AuditStatus)?;
        Ok(audit_status_info(&status))
    }

    /// «Verify»: downloads the whole chain, checks every signature and that
    /// it still holds what this Mac downloaded before, and signs its head
    /// (`klav log verify`). A failure is `Security`.
    pub fn verify_audit(&self) -> KlavResult<VerifyInfo> {
        let report: VerifyReport = self.call(Request::VerifyAudit)?;
        Ok(verify_info(report))
    }

    /// «Sandboxes» (ADR 0036 E2.1): the sandboxes in the verified log, with
    /// the last heartbeat of the account's proxy, as `klavd` checks them.
    /// Only the account's proxy's, unless `all_proxies`.
    pub fn sandbox_list(&self, all_proxies: bool) -> KlavResult<SandboxListInfo> {
        let list: Option<klav_client::sandboxes::SandboxList> =
            self.call_new(Request::SandboxList)?;
        list.map(|l| sandbox_list_info(l, all_proxies))
            .ok_or_else(update_klavd_sandboxes)
    }

    /// [`Self::sandbox_list`] for an app that shows `security` (see
    /// `KlavCore::sandbox_list_flagged`). A `klavd` older than the flag
    /// answers `bad_request`: then this asks `sandbox_list`, which fails
    /// with `Security` where this would flag, so an older `klavd` never
    /// gives a list without the problem.
    pub fn sandbox_list_flagged(&self, all_proxies: bool) -> KlavResult<SandboxListInfo> {
        let list: Option<klav_client::sandboxes::SandboxList> =
            match self.call_new(Request::SandboxListFlagged)? {
                Some(list) => Some(list),
                None => self.call_new(Request::SandboxList)?,
            };
        list.map(|l| sandbox_list_info(l, all_proxies))
            .ok_or_else(update_klavd_sandboxes)
    }

    /// [`Self::sandbox_list_flagged`] with the check that refused the list
    /// apart (see `KlavCore::sandbox_list_checked`). A `klavd` older than it
    /// answers `bad_request`: then this asks `sandbox_list_flagged`, which
    /// fails with `Security` where this would name the check, so no `klavd`
    /// gives a list a check refused.
    pub fn sandbox_list_checked(&self, all_proxies: bool) -> KlavResult<SandboxListCheckedInfo> {
        match self.call_new::<klav_client::sandboxes::CheckedList>(Request::SandboxListChecked)? {
            Some(answer) => Ok(crate::sandboxes::checked_answer(answer, all_proxies)),
            None => self
                .sandbox_list_flagged(all_proxies)
                .map(|list| SandboxListCheckedInfo::Listed { list }),
        }
    }

    /// Revokes one sandbox of `proxy_id`, signed by `klavd` with the
    /// account and without Touch ID (ADR 0036 E2.3).
    pub fn revoke_sandbox(
        &self,
        proxy_id: String,
        sandbox_id: String,
    ) -> KlavResult<SandboxRevokeInfo> {
        self.revoke_sandboxes(proxy_id, Some(sandbox_id))
    }

    /// Revokes every sandbox of `proxy_id` issued so far («Revoke all»).
    pub fn revoke_all_sandboxes(&self, proxy_id: String) -> KlavResult<SandboxRevokeInfo> {
        self.revoke_sandboxes(proxy_id, None)
    }

    /// The account's agents with their last use, verified role, person-owned
    /// labels (ADR 0047) and pause, for Development › Agents: pending
    /// registrations first, then newest.
    pub fn dev_agents(&self) -> KlavResult<Vec<DevAgentInfo>> {
        let list: Vec<AgentView> = self.call(Request::Agents)?;
        // Older `klavd` instances do not know `agent_labels` yet: fall back to
        // empty labels instead of breaking the Agents list.
        let labels: klav_core::model::agent_labels::AgentLabels =
            self.call(Request::AgentLabels).unwrap_or_default();
        Ok(dev_agents(list, &labels))
    }

    /// Sets or clears the person-owned label and/or machine host for an agent
    /// (ADR 0047). Stored E2E-encrypted in the personal vault's system project.
    pub fn set_agent_label(
        &self,
        id: String,
        label: Option<String>,
        host: Option<String>,
    ) -> KlavResult<()> {
        let agent = agent_id(&id)?;
        let _: klav_core::model::agent_labels::AgentLabels =
            self.call(Request::SetAgentLabel { agent, label, host })?;
        Ok(())
    }

    /// «Pause agents» (ADR 0033 §7): every agent without `agent_id`, until
    /// `until_ms` or until the person resumes. Nothing is asked: pausing
    /// is for a scare. Answers the pauses in effect.
    pub fn pause_agents(
        &self,
        agent_id: Option<String>,
        until_ms: Option<i64>,
    ) -> KlavResult<Vec<PauseInfo>> {
        let pauses: Vec<PauseInEffect> = self.call(Request::PauseAgents {
            agent: optional_agent(agent_id)?,
            until: until_ms,
        })?;
        Ok(pauses.into_iter().map(pause_info).collect())
    }

    /// «Resume»: asks for Touch ID in `klavd`, as approving does.
    pub fn resume_agents(&self, agent_id: Option<String>) -> KlavResult<Vec<PauseInfo>> {
        self.resume_agents_with_password(agent_id, None)
    }

    /// `resume_agents` with the master password instead of Touch ID.
    pub fn resume_agents_with_password(
        &self,
        agent_id: Option<String>,
        password: Option<String>,
    ) -> KlavResult<Vec<PauseInfo>> {
        let pauses: Vec<PauseInEffect> = self.call(Request::ResumeAgents {
            agent: optional_agent(agent_id)?,
            password: password.map(SecretText::new),
        })?;
        Ok(pauses.into_iter().map(pause_info).collect())
    }
}

impl DaemonEngine {
    /// The proxy's MCP profiles, when `wanted`: best effort, from
    /// `proxy_status` (ADR 0049 §5.4, §6). A failure names nothing.
    fn mcp_names(&self, wanted: bool) -> crate::mcp::McpNames {
        let status = wanted
            .then(|| self.call::<ProxyStatus>(Request::ProxyStatus).ok())
            .flatten();
        crate::mcp::McpNames::from_status(status.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn project() -> GrantedProjectInfo {
        GrantedProjectInfo {
            vault_id: "v".into(),
            vault: "Personal".into(),
            project_id: "p".into(),
            project: "General".into(),
        }
    }

    #[test]
    fn the_cost_line_never_shows_a_count_it_could_not_make() {
        // Everything read: exact.
        let exact = cost_of("bot", &[project()], &[Ok(2), Ok(1)], Ok(Vec::new()));
        assert_eq!(exact.items, 3);
        assert!(!exact.items_at_least && !exact.others_at_least);

        // One listing failed: what was counted, as a lower bound.
        let items = cost_of(
            "bot",
            &[project()],
            &[Ok(2), Err(KlavError::Locked)],
            Ok(Vec::new()),
        );
        assert_eq!(items.items, 2);
        assert!(items.items_at_least && !items.others_at_least);

        // The agents could not be read: others may get a new grant.
        let others = cost_of("bot", &[project()], &[Ok(0), Ok(0)], Err(KlavError::Locked));
        assert!(others.others_at_least && !others.items_at_least);
        assert!(others.other_agents.is_empty());
        // Another active agent whose grant this device cannot read may
        // hold one of them.
        let unreadable: AgentView = serde_json::from_value(serde_json::json!({
            "id": "6f1c1b2e-0c1d-4a7b-9e55-1f2a3b4c5d6e",
            "name": "other",
            "status": "active",
            "pairing_code": "a b c d e f",
            "created_at": 0,
            "expires_at": 0,
            "grant_error": "a format this device does not know",
        }))
        .expect("agent");
        let hidden = cost_of("bot", &[project()], &[Ok(1), Ok(0)], Ok(vec![unreadable]));
        assert!(hidden.others_at_least && !hidden.items_at_least);
    }
}
