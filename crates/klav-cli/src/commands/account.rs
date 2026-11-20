//! `signup`, `login`, `unlock`, `lock`, `status`, `sync` and `account`.

use std::io::IsTerminal;
use std::path::Path;

use klav_client::{LoginRequest, SignupRequest, kit, login, server, signup_with};
use klav_core::crypto::kdf::MasterPassword;
use klav_core::crypto::secret_key::{EmergencyKit, SecretKey};
use klav_proto::auth::DeviceKind;
use serde::Serialize;
use zeroize::Zeroizing;

use std::time::Duration;

use klav_client::Home;
use klav_daemon::client::DaemonClient;
use klav_daemon::protocol::{DaemonStatus, Request};

use crate::backend::{call, unlock_daemon};
use crate::cli::{AccountCommand, JsonFlag, LockArgs, LoginArgs, SignupArgs, UnlockArgs};
use crate::context::{Ctx, hostname};
use crate::error::CliError;
use crate::error::{CliResult, usage};
use crate::output;
use crate::secret_files::human;

/// The server for `signup`, `login` and `agent register` (ADR 0028 §2):
/// `--server` or `KLAV_SERVER` through the table of moves, else the
/// default, unless `KLAV_NO_DEFAULT_SERVER` is set. Always said on stderr.
pub(crate) fn choose_server(explicit: Option<String>) -> CliResult<String> {
    if let Some(text) = explicit {
        let server = server::resolve(&text)?;
        output::info(&format!(
            "Server: {server} ({}).",
            server::display_name(&server)
        ));
        return Ok(server);
    }
    let server = server::default_server()
        .ok_or_else(|| usage("give the server with --server (or KLAV_SERVER)"))?;
    output::info(&format!(
        "Server: {server} ({}). Use --server URL for your own.",
        server::DEFAULT_SERVER_NAME
    ));
    Ok(server.to_owned())
}

/// Where an emergency kit goes, checked before anything is created or
/// shown: a new file, or a terminal.
fn check_kit_target(path: Option<&Path>) -> CliResult<()> {
    match path {
        None if !std::io::stderr().is_terminal() => Err(usage(
            "no terminal to show the emergency kit on: use --emergency-kit <new file>",
        )),
        Some(path) if path.exists() => Err(usage(format!("{} already exists", path.display()))),
        _ => Ok(()),
    }
}

/// Writes the kit to `path`, or shows it on the terminal (stderr only,
/// never stdout or a log).
fn hand_over_kit(emergency: &EmergencyKit, path: Option<&Path>) -> CliResult<()> {
    match path {
        Some(path) => {
            kit::write_new(emergency, path)?;
            output::info(&format!(
                "Emergency kit written to {} (mode 0600). It contains your Secret Key: print it or store it offline, then delete the file.",
                path.display()
            ));
        }
        None => {
            output::info("");
            output::info(&kit::render(emergency));
        }
    }
    Ok(())
}

pub(crate) async fn signup_cmd(ctx: &mut Ctx, args: SignupArgs) -> CliResult<()> {
    // Decide where the kit goes before creating anything.
    check_kit_target(args.emergency_kit.as_deref())?;
    let server = choose_server(args.server)?;
    // A closed registration is said before the password is asked (ADR
    // 0028 §3). A server that does not say lets the sign-up decide.
    if server::registration_open(&server).await? == Some(false) {
        return Err(CliError::Other(server::registration_closed_message(
            &server,
        )));
    }
    let password = ctx.input.new_password()?;
    output::info("Deriving keys (Argon2id, 256 MiB)…");
    // The kit is written (or shown) before the account is registered: a
    // kit file that cannot be written leaves nothing on the server, and an
    // account never exists without its kit (`klav account kit` shows it
    // again).
    let kit_path = args.emergency_kit.clone();
    let result = signup_with(
        &ctx.home,
        SignupRequest {
            server,
            email: args.email,
            password: MasterPassword::new(password.as_str()),
            device_name: args.device_name.unwrap_or_else(hostname),
            device_kind: DeviceKind::Cli,
        },
        |emergency| {
            match &kit_path {
                Some(path) => kit::write_new(emergency, path)?,
                None => {
                    // Only to the terminal (stderr), never to stdout or a log.
                    output::info("");
                    output::info(&kit::render(emergency));
                }
            }
            Ok(())
        },
    )
    .await;
    drop(password);
    let unlocked = match result {
        Ok((unlocked, _)) => unlocked,
        Err(e) => {
            if let Some(path) = kit_path.as_ref().filter(|p| p.exists()) {
                output::warn(&format!(
                    "sign-up failed. If `klav status` shows no account, {} belongs to no \
                     account: delete it",
                    path.display()
                ));
            }
            return Err(e.into());
        }
    };
    for w in unlocked.warnings() {
        output::warn(w);
    }
    let account = unlocked.account();
    output::info(&format!(
        "Account created: {} (account {}), device {} ({}).",
        account.email, account.account_id, account.device_name, account.device_id
    ));
    match &kit_path {
        Some(path) => output::info(&format!(
            "Emergency kit written to {} (mode 0600). It contains your Secret Key: print it or store it offline, then delete the file.",
            path.display()
        )),
        None => output::info(
            "Write down the Secret Key above now: it is needed to log in on other devices \
             (`klav account kit` shows it again on this device).",
        ),
    }
    output::info(&format!("Local state: {}", ctx.home.dir().display()));
    Ok(())
}

/// Finds `Secret Key: K1-…` in an emergency kit file.
fn secret_key_from_kit(path: &Path) -> CliResult<SecretKey> {
    let text = Zeroizing::new(std::fs::read_to_string(path)?);
    let line = text
        .lines()
        .find_map(|l| l.trim().strip_prefix("Secret Key:"))
        .ok_or_else(|| usage(format!("no \"Secret Key:\" line in {}", path.display())))?;
    Ok(SecretKey::parse(line.trim()).map_err(klav_client::ClientError::from)?)
}

pub(crate) async fn login_cmd(ctx: &mut Ctx, args: LoginArgs) -> CliResult<()> {
    let server = choose_server(args.server)?;
    let secret_key = match &args.emergency_kit {
        Some(path) => secret_key_from_kit(path)?,
        None => {
            let text = ctx.input.prompt_hidden("Secret Key (K1-…): ")?;
            SecretKey::parse(text.trim()).map_err(klav_client::ClientError::from)?
        }
    };
    let password = ctx.input.password("Master password: ")?;
    output::info("Deriving keys (Argon2id, 256 MiB)…");
    let unlocked = login(
        &ctx.home,
        LoginRequest {
            server,
            email: args.email,
            password: MasterPassword::new(password.as_str()),
            secret_key,
            device_name: args.device_name.unwrap_or_else(hostname),
            device_kind: DeviceKind::Cli,
        },
    )
    .await?;
    drop(password);
    let account = unlocked.account();
    output::info(&format!(
        "Logged in as {} on device {} ({}). {} vault(s) synced.",
        account.email,
        account.device_name,
        account.device_id,
        unlocked.vaults().len()
    ));
    Ok(())
}

pub(crate) async fn unlock_cmd(ctx: &mut Ctx, args: UnlockArgs) -> CliResult<()> {
    if ctx.no_daemon {
        ctx.backend().await?;
        output::info(
            "Password correct and vault synced. Without `klavd`, every command asks for the password again.",
        );
        return Ok(());
    }
    klav_client::account(&ctx.home)?;
    let mut client = match DaemonClient::connect(&ctx.home).await {
        Some(c) => c,
        None => start_daemon(&ctx.home, args.idle_lock).await?,
    };
    let status: DaemonStatus = call(&mut client, Request::Status).await?;
    let status = if status.unlocked {
        // Already unlocked: nothing is sent, so nothing can race with a
        // lock in between (layer 3's review, finding 3). With the presence
        // gate on, one unlocked by another key gave this terminal nothing,
        // and no password is asked for (ADR 0041 §2.4; Omar's decision 5
        // of 2026-11-19).
        if status.presence.as_ref().is_some_and(|p| p.elsewhere) {
            output::warn(&crate::presence::already_unlocked_text());
            return Ok(());
        }
        status
    } else {
        let unlocked = unlock_daemon(
            &mut client,
            &status,
            &ctx.home,
            &mut ctx.input,
            args.password,
        )
        .await?;
        // Unlocked by another key while this one asked: said already, and
        // this unlock isn't what unlocked it (finding 5).
        if unlocked.already_unlocked {
            return Ok(());
        }
        unlocked
    };
    output::info(&format!(
        "Unlocked{} (klavd, pid {}); locks after {} without use. `klav lock` locks now.",
        status
            .unlocked_with
            .as_deref()
            .map(|m| format!(" with {}", m.replace('_', " ")))
            .unwrap_or_default(),
        status.pid,
        human(Duration::from_secs(status.idle_lock_secs)),
    ));
    Ok(())
}

/// Starts `klavd` in the background for this home and connects to it.
async fn start_daemon(home: &Home, idle_lock: Duration) -> CliResult<DaemonClient> {
    klav_daemon::client::spawn_daemon(home, idle_lock)
        .await
        .map_err(CliError::Other)
}

pub(crate) async fn lock_cmd(ctx: &mut Ctx, args: LockArgs) -> CliResult<()> {
    let Some(mut client) = DaemonClient::connect(&ctx.home).await else {
        output::info("`klavd` is not running: nothing stays unlocked between commands.");
        return Ok(());
    };
    if args.stop {
        let _: serde_json::Value = call(&mut client, Request::Shutdown).await?;
        output::info("Locked; klavd stopped.");
    } else {
        let _: DaemonStatus = call(&mut client, Request::Lock).await?;
        output::info("Locked.");
    }
    Ok(())
}

#[derive(Serialize)]
struct Status {
    home: String,
    logged_in: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    server: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    account_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    device: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    device_id: Option<String>,
    /// Pairing words of the account identity (agents show them too).
    #[serde(skip_serializing_if = "Option::is_none")]
    account_words: Option<String>,
    /// The host the account moved off since the last `klav status`
    /// (ADR 0028 §4; said once).
    #[serde(skip_serializing_if = "Option::is_none")]
    moved_from: Option<String>,
    daemon: String,
    /// The deletion of the account the person asked for, as `klavd` last
    /// saw it (ADR 0037 §4): without `klavd` the CLI cannot tell, its copy
    /// is sealed.
    #[serde(skip_serializing_if = "Option::is_none")]
    deletion: Option<klav_client::deletion::AccountDeletion>,
    /// `klavd` found the account deleted.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    deleted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    klavd: Option<DaemonStatus>,
}

pub(crate) async fn status_cmd(ctx: &mut Ctx, args: JsonFlag) -> CliResult<()> {
    let account = klav_client::account(&ctx.home).ok();
    let status = Status {
        home: ctx.home.dir().display().to_string(),
        logged_in: account.is_some(),
        server: account.as_ref().map(|a| a.server.clone()),
        email: account.as_ref().map(|a| a.email.clone()),
        account_id: account.as_ref().map(|a| a.account_id.to_string()),
        device: account.as_ref().map(|a| a.device_name.clone()),
        device_id: account.as_ref().map(|a| a.device_id.to_string()),
        account_words: account.as_ref().and_then(|a| {
            klav_core::crypto::identity::PublicIdentity::decode(a.public_identity.as_bytes())
                .ok()
                .map(|p| klav_core::crypto::agent::pairing_code(&p))
        }),
        moved_from: account.as_ref().and_then(|_| server::take_move(&ctx.home)),
        daemon: "not running".into(),
        deletion: None,
        deleted: false,
        klavd: None,
    };
    let mut status = status;
    if let Some(mut client) = DaemonClient::connect(&ctx.home).await
        && let Ok(d) = call::<DaemonStatus>(&mut client, Request::Status).await
    {
        status.daemon = match (d.unlocked, d.locks_in_secs) {
            (true, Some(left)) => format!(
                "unlocked{} (pid {}), locks in {}",
                d.unlocked_with
                    .as_deref()
                    .map(|m| format!(" with {}", m.replace('_', " ")))
                    .unwrap_or_default(),
                d.pid,
                human(Duration::from_secs(left.max(1)))
            ),
            _ => format!("locked (pid {})", d.pid),
        };
        status.deletion.clone_from(&d.account_deletion);
        status.deleted = d.account_deleted;
        status.klavd = Some(d);
    }
    if args.json {
        return output::json(&status);
    }
    output::line(&format!("home:      {}", status.home));
    match &account {
        Some(a) => {
            match &status.moved_from {
                Some(old) => output::line(&format!("server:    {} (moved from {old})", a.server)),
                None => output::line(&format!("server:    {}", a.server)),
            }
            output::line(&format!("account:   {} ({})", a.email, a.account_id));
            output::line(&format!("device:    {} ({})", a.device_name, a.device_id));
            if let Some(words) = &status.account_words {
                output::line(&format!("words:     {words}"));
            }
        }
        None => output::line("account:   none (run `klav signup` or `klav login`)"),
    }
    output::line(&format!("daemon:    {}", status.daemon));
    match (&status.deletion, status.deleted) {
        (Some(d), true) => output::line(&format!(
            "deletion:  Klav deleted this account on {} UTC; this copy is read-only, and `klav logout` deletes it",
            crate::time::format_utc_minutes(d.delete_at)
        )),
        (Some(d), false) => output::line(&format!(
            "deletion:  the account is deleted on {} UTC; `klav account delete --cancel` cancels it",
            crate::time::format_utc_minutes(d.delete_at)
        )),
        (None, _) => {}
    }
    for p in status.klavd.iter().flat_map(|d| &d.agents_paused) {
        output::line(&format!(
            "agents:    {} paused {}{}",
            p.agent_id
                .map_or_else(|| "every agent".to_owned(), |a| format!("agent {a}")),
            p.until.map_or_else(
                || "until you resume".to_owned(),
                |t| format!("until {}", crate::time::format_utc(t))
            ),
            match (p.local, p.server_unsupported) {
                (true, true) => {
                    " (on this computer only: this server does not support pausing agents; update it)"
                }
                (true, false) => " (on this computer only: unlock Klav to pause them everywhere)",
                _ => "",
            }
        ));
    }
    Ok(())
}

pub(crate) async fn sync_cmd(ctx: &mut Ctx, args: &crate::cli::SyncArgs) -> CliResult<()> {
    if args.reset_cache {
        confirm_reset(args.yes)?;
        let report = ctx.backend().await?.reset_cache().await?;
        output::info(&format!(
            "Downloaded everything again: {} vault(s), {} item(s). Until now this device \
             could not tell a rollback older than this moment (T7).",
            report.vaults_updated, report.items_received
        ));
        return Ok(());
    }
    let report = ctx.backend().await?.sync().await?;
    output::info(&format!(
        "Synced: {} vault(s) updated, {} item change(s), {} vault(s) removed.",
        report.vaults_updated, report.items_received, report.vaults_removed
    ));
    if report.vaults_removed > 0 {
        output::warn(
            "the server no longer lists some vaults: this device keeps their copy, read-only \
             (`klav sync --reset-cache` drops it)",
        );
    }
    if report.vaults_signed > 0 {
        output::info(&format!(
            "Signed the key of {} vault(s) created before vault keys were signed.",
            report.vaults_signed
        ));
    }
    Ok(())
}

pub(crate) async fn account_cmd(ctx: &mut Ctx, cmd: AccountCommand) -> CliResult<()> {
    match cmd {
        AccountCommand::SetServer { url } => set_server_cmd(ctx, &url).await,
        AccountCommand::Kit { emergency_kit } => kit_cmd(ctx, emergency_kit.as_deref()),
        AccountCommand::Delete { cancel: false } => super::deletion::delete_cmd(ctx).await,
        AccountCommand::Delete { cancel: true } => super::deletion::cancel_cmd(ctx).await,
    }
}

async fn set_server_cmd(ctx: &mut Ctx, url: &str) -> CliResult<()> {
    let account = klav_client::account(&ctx.home)?;
    let target = klav_client::ServerUrl::parse(url)?;
    if target.as_str() == account.server {
        output::info(&format!("The account already uses {}.", account.server));
        return Ok(());
    }
    output::info(&format!(
        "Moving {} from {} to {}: logging in there to check it has this account.",
        account.email,
        account.server,
        target.as_str()
    ));
    let password = ctx
        .input
        .password(&format!("Master password for {}: ", account.email))?;
    output::info("Deriving keys (Argon2id, 256 MiB)…");
    let saved = klav_client::set_server(
        &ctx.home,
        &MasterPassword::new(password.as_str()),
        target.as_str(),
        DeviceKind::Cli,
    )
    .await?;
    drop(password);
    // A running klavd still talks to the old URL: lock it, so the next
    // unlock reads the new one.
    if let Some(mut client) = DaemonClient::connect(&ctx.home).await {
        let _: DaemonStatus = call(&mut client, Request::Lock).await?;
        output::info("klavd locked: unlock again to use the new server.");
    }
    output::info(&format!("The account now uses {saved}."));
    Ok(())
}

fn kit_cmd(ctx: &mut Ctx, path: Option<&Path>) -> CliResult<()> {
    check_kit_target(path)?;
    let account = klav_client::account(&ctx.home)?;
    let password = ctx
        .input
        .password(&format!("Master password for {}: ", account.email))?;
    let emergency = klav_client::emergency_kit(&ctx.home, &MasterPassword::new(password.as_str()))?;
    drop(password);
    hand_over_kit(&emergency, path)
}

/// `--reset-cache` drops the rollback marks: never without a yes.
fn confirm_reset(yes: bool) -> CliResult<()> {
    use std::io::{BufRead, IsTerminal, Write};
    if yes {
        return Ok(());
    }
    if !std::io::stdin().is_terminal() {
        return Err(CliError::Other(
            "--reset-cache forgets this device's rollback marks: pass --yes to confirm".into(),
        ));
    }
    eprint!(
        "This forgets this device's copy of your vaults and the marks that detect a server \
         rolled back to older data. Revoked agents and signed vault keys are kept. Continue? [y/N] "
    );
    let _ = std::io::stderr().flush();
    let mut answer = String::new();
    std::io::stdin().lock().read_line(&mut answer)?;
    if matches!(
        answer.trim().to_lowercase().as_str(),
        "y" | "yes" | "s" | "si" | "sí"
    ) {
        Ok(())
    } else {
        Err(CliError::Other("cancelled".into()))
    }
}
