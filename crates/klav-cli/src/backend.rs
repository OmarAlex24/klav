//! Where commands run: in this process (direct mode: unlock with the master
//! password, sync, act, forget) or, when `klavd` is running, in the daemon.

use klav_client::health::{BREACH_API, HealthSettings, VaultHealth};
use klav_client::history::{GeneratedSelection, GeneratedView, PasswordHistoryView};
use klav_client::import::{ImportPreview, ImportResult};
use klav_client::klav_import::{ImportSet, Source};
use klav_client::offer::ReusedOffer;
use klav_client::ops::{ItemPatch, ItemView, NewItem, ResolvedValue, TotpCode};
use klav_client::{
    ClientError, Home, ItemFilter, ItemSummary, ProjectSummary, SyncReport, Unlocked, VaultSummary,
    unlock_with_password,
};
use klav_core::crypto::kdf::MasterPassword;

use klav_client::ops::{SecretBytes, SecretText};
use klav_daemon::client::DaemonClient;
use klav_daemon::protocol::{DaemonStatus, ErrorCode, ImportAdded, Request};
use zeroize::Zeroizing;

use crate::error::{CliError, CliResult};
use crate::input::Input;
use crate::output;
use crate::presence::{self, Busy};

/// Pieces of a file sent to `klavd` (its lines carry up to 100 MiB, base64).
const IMPORT_PIECE: usize = 16 * 1024 * 1024;

/// An export file read for `klav import`.
pub(crate) struct ImportFile {
    /// Its name, for messages.
    pub(crate) name: String,
    /// Its bytes.
    pub(crate) data: Zeroizing<Vec<u8>>,
}

/// Files read and waiting to be imported.
pub(crate) enum PendingImport {
    Local(Box<ImportSet>),
    Daemon(String),
}

pub(crate) enum Backend {
    Direct(Box<Unlocked>),
    Daemon(DaemonClient),
}

/// One daemon call: prints its warnings, maps its errors.
pub(crate) async fn call<R: serde::de::DeserializeOwned>(
    client: &mut DaemonClient,
    request: Request,
) -> CliResult<R> {
    let (result, warnings) = client.call(request).await.map_err(CliError::Daemon)?;
    for w in &warnings {
        output::warn(w);
    }
    Ok(result)
}

/// Connects to a running `klavd` and makes sure it is unlocked (asking
/// for the master password if needed). `None` when no daemon is running.
pub(crate) async fn daemon(home: &Home, input: &mut Input) -> CliResult<Option<Backend>> {
    let Some(mut client) = DaemonClient::connect(home).await else {
        return Ok(None);
    };
    let status: DaemonStatus = call(&mut client, Request::Status).await?;
    // Asks for `klavd`'s notice before a value's Touch ID dialog only from
    // one whose `status` says the gate is on (ADR 0041, Omar's decision 2
    // of 2026-11-19): an older `klavd` refuses the field.
    client.set_presence_gate(presence::gate_on(&status));
    if !status.unlocked {
        unlock_daemon(&mut client, &status, home, input, false).await?;
    }
    Ok(Some(Backend::Daemon(client)))
}

/// Unlocks the daemon: biometrics first when enrolled (unless
/// `password_only`), then the master password.
pub(crate) async fn unlock_daemon(
    client: &mut DaemonClient,
    status: &DaemonStatus,
    home: &Home,
    input: &mut Input,
    password_only: bool,
) -> CliResult<DaemonStatus> {
    if !status.logged_in {
        return Err(ClientError::NotLoggedIn.into());
    }
    // A password given on stdin means "use it" (scripts never wait on a
    // fingerprint).
    let password_only = password_only || input.password_from_stdin();
    let gate = status.presence.as_ref();
    if !password_only && status.touch_id.enrolled && status.touch_id.password_required.is_none() {
        // With the presence gate on, the dialog names the terminal it
        // unlocks for: say the same name here, so the person can compare
        // (ADR 0041 §2.4). Without it, as before.
        if gate.is_some() {
            output::info(&presence::touch_id_line());
        } else {
            output::info("Touch ID…");
        }
        match client
            .call::<DaemonStatus>(Request::Unlock {
                password: None,
                passkey_flow: false,
            })
            .await
        {
            Ok((unlocked, warnings)) => {
                warn_from(gate.is_some(), &warnings);
                if unlocked.already_unlocked {
                    output::warn(&presence::already_unlocked_text());
                }
                return Ok(unlocked);
            }
            Err(e)
                if matches!(
                    e.code,
                    ErrorCode::BiometryFailed | ErrorCode::BiometryUnavailable
                ) =>
            {
                output::warn(&format!(
                    "{}; using the master password",
                    from_klavd(gate.is_some(), &e.message)
                ));
            }
            // Another unlock's dialog is open: no queue behind it (ADR
            // 0041 §2.4, N2).
            Err(e) => return Err(presence::refused(e, Busy::Dialog)),
        }
    } else if let Some(reason) = &status.touch_id.password_required {
        output::info(&from_klavd(gate.is_some(), reason));
    }
    let account = klav_client::account(home)?;
    // With the gate on, the question names this terminal and says what the
    // password opens, and `klavd` opens no more than that (`shown`, layer
    // 3's review, finding 1). A password from stdin unlocks, opens no
    // window and is no passkey verification: it is no one's presence
    // (Omar's decisions 4 and B of 2026-11-19), and `untyped` says so.
    let (password, shown) = match gate {
        Some(presence) if !input.password_from_stdin() => (
            presence::unlock_password(presence, &account.email)?,
            Some(presence::unlock_shown(presence)),
        ),
        Some(_) => (
            input.password(&format!("Master password for {}: ", account.email))?,
            Some(klav_daemon::uv::Window::Always),
        ),
        None => (
            input.password(&format!("Master password for {}: ", account.email))?,
            None,
        ),
    };
    let answer = client
        .call_presence::<DaemonStatus>(
            Request::Unlock {
                password: Some(SecretText::new(password.as_str())),
                passkey_flow: false,
            },
            klav_daemon::client::Presence {
                notify: false,
                shown,
                untyped: gate.is_some() && input.password_from_stdin(),
            },
            &mut |_| {},
        )
        .await;
    drop(password);
    let (unlocked, warnings) = answer.map_err(|e| presence::refused(e, Busy::Password))?;
    warn_from(gate.is_some(), &warnings);
    if gate.is_some() && input.password_from_stdin() {
        output::info(
            "The master password came from stdin: Klav is unlocked, and no window opened. Each \
             value asks for your presence on the terminal, and so does the next passkey use",
        );
    }
    // Another key unlocked it first, while this one asked.
    if unlocked.already_unlocked {
        match (gate, input.password_from_stdin()) {
            (Some(_), true) => output::warn(&presence::already_unlocked_text()),
            (Some(_), false) => output::warn(
                "Klav was already unlocked elsewhere; your master password opened at most what \
                 its question said",
            ),
            // The gate off: the password was this caller's own
            // verification (Omar's decision on Q-N1).
            (None, _) => output::warn(
                "Klav was already unlocked elsewhere; your master password counted as this \
                 command's own presence",
            ),
        }
    }
    Ok(unlocked)
}

/// `klavd`'s own words: cleaned with the presence gate on, as every other
/// text of the gate; with it off, as before.
fn from_klavd(gate: bool, text: &str) -> String {
    if gate {
        presence::said(text)
    } else {
        text.to_owned()
    }
}

fn warn_from(gate: bool, warnings: &[String]) {
    for w in warnings {
        output::warn(&from_klavd(gate, w));
    }
}

/// Unlocks in this process and syncs. Offline, when the server fails a
/// security check (a rollback), or once the account was deleted, it goes on
/// with the local copy, which the failed sync left untouched, with a
/// warning: a hostile server must not lock the person out of their vault.
/// `klav sync` reports it as an error.
pub(crate) async fn direct(home: &Home, input: &mut Input) -> CliResult<Backend> {
    let account = klav_client::account(home)?;
    let password = input.password(&format!("Master password for {}: ", account.email))?;
    let mut unlocked = unlock_with_password(home, &MasterPassword::new(password.as_str()))?;
    drop(password);
    // An old server URL moves only if the new host has this account
    // (ADR 0028 §4); `klav status` says so once.
    unlocked.migrate_server().await;
    match unlocked.sync().await {
        Ok(_) => {}
        Err(ClientError::Network(e)) => {
            output::warn(&format!("offline ({e}); using the local copy"));
        }
        Err(e @ (ClientError::Rollback(_) | ClientError::Security(_))) => {
            output::warn(&format!(
                "{e}. Using this device's copy, unchanged. If the server was restored from a \
                 backup you trust, `klav sync --reset-cache` starts over"
            ));
        }
        // The account is gone: the copy stays, read-only (ADR 0037 §3).
        // Nothing here deletes it (T165).
        Err(ClientError::AccountDeleted(at)) => {
            output::warn(&crate::error::deleted_message(at));
        }
        Err(e) => return Err(e.into()),
    }
    for w in unlocked.warnings() {
        output::warn(w);
    }
    Ok(Backend::Direct(Box::new(unlocked)))
}

impl Backend {
    pub(crate) async fn reset_cache(&mut self) -> CliResult<SyncReport> {
        match self {
            Backend::Direct(u) => {
                let report = u.reset_cache().await?;
                for w in u.warnings() {
                    output::warn(w);
                }
                Ok(report)
            }
            Backend::Daemon(d) => call(d, Request::ResetCache).await,
        }
    }

    pub(crate) async fn sync(&mut self) -> CliResult<SyncReport> {
        match self {
            Backend::Direct(u) => Ok(u.sync().await?),
            Backend::Daemon(d) => call(d, Request::Sync).await,
        }
    }

    pub(crate) async fn vaults(&mut self) -> CliResult<Vec<VaultSummary>> {
        match self {
            Backend::Direct(u) => Ok(u.vaults()),
            Backend::Daemon(d) => call(d, Request::Vaults).await,
        }
    }

    pub(crate) async fn projects(&mut self, vault: Option<&str>) -> CliResult<Vec<ProjectSummary>> {
        match self {
            Backend::Direct(u) => {
                let vault = vault.map(|v| u.find_vault(v)).transpose()?;
                Ok(u.projects(vault))
            }
            Backend::Daemon(d) => {
                call(
                    d,
                    Request::Projects {
                        vault: vault.map(str::to_owned),
                    },
                )
                .await
            }
        }
    }

    pub(crate) async fn create_vault(&mut self, name: &str) -> CliResult<()> {
        match self {
            Backend::Direct(u) => {
                u.create_vault(name).await?;
                Ok(())
            }
            Backend::Daemon(d) => {
                let _: serde_json::Value = call(
                    d,
                    Request::CreateVault {
                        name: name.to_owned(),
                    },
                )
                .await?;
                Ok(())
            }
        }
    }

    pub(crate) async fn create_project(
        &mut self,
        vault: Option<&str>,
        name: &str,
    ) -> CliResult<()> {
        match self {
            Backend::Direct(u) => {
                let (vault, _) = u.destination(vault, None)?;
                u.create_project(vault, name).await?;
                Ok(())
            }
            Backend::Daemon(d) => {
                let _: serde_json::Value = call(
                    d,
                    Request::CreateProject {
                        vault: vault.map(str::to_owned),
                        name: name.to_owned(),
                    },
                )
                .await?;
                Ok(())
            }
        }
    }

    pub(crate) async fn list(&mut self, filter: &ItemFilter) -> CliResult<Vec<ItemSummary>> {
        match self {
            Backend::Direct(u) => Ok(u.list_items(filter)?),
            Backend::Daemon(d) => {
                call(
                    d,
                    Request::List {
                        filter: filter.clone(),
                    },
                )
                .await
            }
        }
    }

    pub(crate) async fn view(&mut self, query: &str, reveal: bool) -> CliResult<ItemView> {
        match self {
            Backend::Direct(u) => Ok(u.view_item(query, reveal)?),
            // Without `reveal`, no value: `klavd` never asks for presence.
            Backend::Daemon(d) => {
                presence::value_call(d, |password| Request::View {
                    query: query.to_owned(),
                    reveal,
                    password,
                })
                .await
            }
        }
    }

    pub(crate) async fn create(&mut self, new: &NewItem) -> CliResult<ItemSummary> {
        match self {
            Backend::Direct(u) => Ok(u.create(new).await?),
            Backend::Daemon(d) => call(d, Request::Create { item: new.clone() }).await,
        }
    }

    /// Reads the export files: here, or in `klavd` (in pieces of
    /// [`IMPORT_PIECE`]). Errors name the file, never its values.
    pub(crate) async fn import_load(
        &mut self,
        files: &[ImportFile],
        from: Option<Source>,
        from_text: Option<&str>,
    ) -> CliResult<PendingImport> {
        match self {
            Backend::Direct(_) => {
                let mut set = ImportSet::new();
                for f in files {
                    set.add(&f.name, &f.data, from)
                        .map_err(|e| CliError::Other(format!("{}: {e}", f.name)))?;
                }
                Ok(PendingImport::Local(Box::new(set)))
            }
            Backend::Daemon(d) => {
                let mut session: Option<String> = None;
                for f in files {
                    let mut pieces = f.data.chunks(IMPORT_PIECE).peekable();
                    // An empty file still goes once (and is refused there).
                    let mut first = true;
                    while first || pieces.peek().is_some() {
                        first = false;
                        let piece = pieces.next().unwrap_or_default();
                        let request = Request::ImportAdd {
                            session: session.clone(),
                            name: f.name.clone(),
                            from: from_text.map(str::to_owned),
                            data: SecretBytes::new(Zeroizing::new(piece.to_vec())),
                            more: pieces.peek().is_some(),
                        };
                        let added: ImportAdded =
                            d.call(request).await.map(|(added, _)| added).map_err(|e| {
                                CliError::Other(format!("{}: {}", f.name, e.message))
                            })?;
                        session = Some(added.session);
                    }
                }
                session
                    .map(PendingImport::Daemon)
                    .ok_or_else(|| CliError::Other("no files to import".into()))
            }
        }
    }

    /// What importing would do.
    pub(crate) async fn import_preview(
        &mut self,
        pending: &PendingImport,
        vault: Option<&str>,
        project: Option<&str>,
    ) -> CliResult<ImportPreview> {
        match (self, pending) {
            (Backend::Direct(u), PendingImport::Local(set)) => {
                Ok(u.import_preview(set, vault, project, usize::MAX)?)
            }
            (Backend::Daemon(d), PendingImport::Daemon(session)) => {
                call(
                    d,
                    Request::ImportPreview {
                        session: session.clone(),
                        vault: vault.map(str::to_owned),
                        project: project.map(str::to_owned),
                    },
                )
                .await
            }
            _ => Err(CliError::Other("import from another backend".into())),
        }
    }

    /// Imports.
    pub(crate) async fn import_apply(
        &mut self,
        pending: &PendingImport,
        vault: Option<&str>,
        project: Option<&str>,
    ) -> CliResult<ImportResult> {
        match (self, pending) {
            (Backend::Direct(u), PendingImport::Local(set)) => {
                Ok(u.import_apply(set, vault, project).await?)
            }
            (Backend::Daemon(d), PendingImport::Daemon(session)) => {
                call(
                    d,
                    Request::ImportApply {
                        session: session.clone(),
                        vault: vault.map(str::to_owned),
                        project: project.map(str::to_owned),
                    },
                )
                .await
            }
            _ => Err(CliError::Other("import from another backend".into())),
        }
    }

    /// Forgets an import that will not be applied.
    pub(crate) async fn import_cancel(&mut self, pending: &PendingImport) -> CliResult<()> {
        if let (Backend::Daemon(d), PendingImport::Daemon(session)) = (self, pending) {
            let _: serde_json::Value = call(
                d,
                Request::ImportCancel {
                    session: session.clone(),
                },
            )
            .await?;
        }
        Ok(())
    }

    pub(crate) async fn edit(&mut self, query: &str, patch: &ItemPatch) -> CliResult<ItemSummary> {
        match self {
            Backend::Direct(u) => Ok(u.edit(query, patch).await?),
            Backend::Daemon(d) => {
                call(
                    d,
                    Request::Edit {
                        query: query.to_owned(),
                        patch: patch.clone(),
                    },
                )
                .await
            }
        }
    }

    pub(crate) async fn trash(&mut self, query: &str) -> CliResult<ItemSummary> {
        match self {
            Backend::Direct(u) => Ok(u.trash(query).await?),
            Backend::Daemon(d) => {
                call(
                    d,
                    Request::Trash {
                        query: query.to_owned(),
                    },
                )
                .await
            }
        }
    }

    pub(crate) async fn totp(&mut self, query: &str, field: Option<&str>) -> CliResult<TotpCode> {
        match self {
            Backend::Direct(u) => Ok(u.totp_code(query, field)?),
            Backend::Daemon(d) => {
                presence::value_call(d, |password| Request::Totp {
                    query: query.to_owned(),
                    field: field.map(str::to_owned),
                    password,
                })
                .await
            }
        }
    }

    pub(crate) async fn resolve(&mut self, references: &[String]) -> CliResult<Vec<ResolvedValue>> {
        match self {
            Backend::Direct(u) => Ok(u.resolve_all(references).await?),
            Backend::Daemon(d) => {
                presence::value_call(d, |password| Request::Resolve {
                    references: references.to_vec(),
                    password,
                })
                .await
            }
        }
    }

    pub(crate) async fn attach(
        &mut self,
        query: &str,
        field: &str,
        file_name: &str,
        content: &[u8],
    ) -> CliResult<ItemSummary> {
        match self {
            Backend::Direct(u) => Ok(u.attach(query, field, file_name, None, content).await?),
            Backend::Daemon(d) => {
                call(
                    d,
                    Request::Attach {
                        query: query.to_owned(),
                        field: field.to_owned(),
                        file_name: file_name.to_owned(),
                        content: SecretBytes::new(zeroize::Zeroizing::new(content.to_vec())),
                    },
                )
                .await
            }
        }
    }
    /// The «Fix my reused passwords» card (ADR 0022 §6) for `agent`.
    pub(crate) async fn reused_offer(&mut self, agent: &str) -> CliResult<ReusedOffer> {
        match self {
            Backend::Direct(u) => Ok(u.reused_offer(Some(agent)).await?),
            Backend::Daemon(d) => {
                call(
                    d,
                    Request::ReusedOffer {
                        agent: Some(agent.to_owned()),
                    },
                )
                .await
            }
        }
    }

    /// The vault health report (ADR 0022 §4). The breach check runs only
    /// if this home's setting turns it on.
    pub(crate) async fn vault_health(&mut self) -> CliResult<VaultHealth> {
        match self {
            Backend::Direct(u) => {
                let settings = HealthSettings::load(u.home())?;
                let scan = u.health_scan(crate::time::now_ms());
                Ok(scan
                    .finish(settings.breach_check.then_some(BREACH_API))
                    .await)
            }
            Backend::Daemon(d) => call(d, Request::VaultHealth).await,
        }
    }

    pub(crate) async fn password_history(&mut self, query: &str) -> CliResult<PasswordHistoryView> {
        match self {
            Backend::Direct(u) => {
                let loc = u.find_item(query)?;
                Ok(u.password_history(loc)?)
            }
            Backend::Daemon(d) => {
                call(
                    d,
                    Request::PasswordHistory {
                        query: query.to_owned(),
                    },
                )
                .await
            }
        }
    }

    pub(crate) async fn previous_password(
        &mut self,
        query: &str,
        index: usize,
    ) -> CliResult<SecretText> {
        match self {
            Backend::Direct(u) => {
                let loc = u.find_item(query)?;
                Ok(u.previous_password(loc, index)?)
            }
            Backend::Daemon(d) => {
                presence::value_call(d, |password| Request::PreviousPassword {
                    query: query.to_owned(),
                    index,
                    password,
                })
                .await
            }
        }
    }

    pub(crate) async fn generator_history(&mut self) -> CliResult<Vec<GeneratedView>> {
        match self {
            Backend::Direct(u) => Ok(u.generator_history()?),
            Backend::Daemon(d) => call(d, Request::GeneratorHistory).await,
        }
    }

    pub(crate) async fn generated_value(&mut self, created_at: i64) -> CliResult<SecretText> {
        match self {
            Backend::Direct(u) => Ok(u.generated_value(created_at)?),
            Backend::Daemon(d) => {
                presence::value_call(d, |password| Request::GeneratedValue {
                    created_at,
                    password,
                })
                .await
            }
        }
    }

    pub(crate) async fn delete_generated(&mut self, which: GeneratedSelection) -> CliResult<usize> {
        match self {
            Backend::Direct(u) => Ok(u.delete_generated(&which).await?),
            Backend::Daemon(d) => {
                #[derive(serde::Deserialize)]
                struct Removed {
                    removed: usize,
                }
                let r: Removed = call(d, Request::GeneratorDelete { which }).await?;
                Ok(r.removed)
            }
        }
    }
}
