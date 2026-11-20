//! `account delete [--cancel]` and `logout` (ADR 0037).
//!
//! Asking to delete the account happens in this process, never in `klavd`
//! (T164): `klavd` only confirms the person's presence with Touch ID when
//! it uses it, and the master password goes to the server through OPAQUE
//! from here. Only a person at a terminal can ask: no `--password-stdin`,
//! no `--yes`, and the account email typed back first.
//!
//! Nothing here deletes this device's copy except `klav logout`, which the
//! person runs.
//!
//! Cancelling asks for presence like `klav agent resume` (ADR 0037 A2):
//! Touch ID through `klavd`, or the master password; without `klavd`, the
//! password that unlocks this process. An agent that can reach the
//! person's session must not cancel to bring itself back.

use std::io::{BufRead, IsTerminal, Write};
use std::time::Duration;

use klav_client::{ClientError, deletion};
use klav_core::crypto::kdf::MasterPassword;
use klav_daemon::client::DaemonClient;
use klav_daemon::protocol::{DaemonStatus, ErrorCode, PresencePurpose, Request};

use crate::backend::{Backend, call};
use crate::cli::LogoutArgs;
use crate::context::Ctx;
use crate::error::{CliError, CliResult, usage};
use crate::output;
use crate::time::format_utc_minutes;

/// How long a `klavd` started only for Touch ID stays unlocked: it is
/// started locked and only asked for presence.
const PRESENCE_DAEMON_IDLE: Duration = Duration::from_secs(15 * 60);

/// What `klav --no-daemon account delete` says where Touch ID is set up
/// (ADR 0037 A1).
const NO_DAEMON_WITH_TOUCH_ID: &str = "Klav uses Touch ID on this Mac, so deleting the account needs it, and --no-daemon skips klavd, which asks for it. Delete the account without --no-daemon, with the lid open and Touch ID available; from the Klav app on this Mac; or from your iPhone.";

/// What `klav account delete` says when `klavd` can't confirm Touch ID
/// right now: what to do, as the Mac app's sheet says it (N6 of the
/// re-review).
const TOUCH_ID_UNAVAILABLE: &str = "Touch ID isn't available right now, and Klav uses it on this Mac to delete the account. Open the lid (or unlock the Mac with its password if Touch ID is locked out) and try again, or delete the account from another of your devices.";

/// What it says when the enrolled fingers changed: `klavd` forgot the
/// enrolment, as unlocking does, so the next try asks for the master
/// password alone (ADR 0037 §1, D-D).
const TOUCH_ID_CHANGED: &str = "Touch ID changed on this Mac, so Klav stopped using it here. Run `klav account delete` again to delete the account with the master password.";

/// `klav account delete`: asks the server to delete the account in 7 days.
pub(crate) async fn delete_cmd(ctx: &mut Ctx) -> CliResult<()> {
    // T164: never from a program. Checked before anything is asked.
    if ctx.input.password_from_stdin() {
        return Err(usage(
            "`klav account delete` does not take --password-stdin: a person types the master password at a terminal",
        ));
    }
    // ADR 0037 A1: where klavd has Touch ID set up, skipping klavd would
    // skip Touch ID. Refused before anything is asked.
    if ctx.no_daemon && klav_daemon::client::touch_id_enrolled(&ctx.home) {
        return Err(CliError::Other(NO_DAEMON_WITH_TOUCH_ID.into()));
    }
    if !(std::io::stdin().is_terminal() && std::io::stderr().is_terminal()) {
        return Err(CliError::Other(
            "`klav account delete` needs a terminal: it asks you to type the account email and the master password"
                .into(),
        ));
    }
    let account = klav_client::account(&ctx.home)?;
    // Before Touch ID or the password (ADR 0037 §4).
    if !deletion::supported(&account.server).await? {
        return Err(ClientError::DeletionUnsupported.into());
    }
    let (mut daemon, status) = presence_daemon(ctx).await?;
    if let Some(asked) = status.as_ref().and_then(|s| s.account_deletion.as_ref()) {
        return Err(CliError::Other(format!(
            "The deletion of this account is already scheduled for {} UTC; `klav account delete --cancel` cancels it.",
            format_utc_minutes(asked.delete_at)
        )));
    }

    output::info(&format!(
        "This deletes everything account {} has on {}:\n\
         vaults, items, versions, files, devices, agents and the audit log. It happens\n\
         in 7 days; until then, `klav account delete --cancel` cancels it.",
        account.email, account.server
    ));
    // The CLI's first confirmation: a terminal has no button to read.
    let typed = ask_line("Type the account email to continue: ")?;
    if !typed.trim().eq_ignore_ascii_case(account.email.trim()) {
        return Err(CliError::Other(
            "that is not the account email; nothing was asked".into(),
        ));
    }
    // Touch ID first, where klavd uses it (ADR 0037 §1). Its enrolment
    // decides, not whether Touch ID answers right now: locked out after
    // failed attempts, or with the lid closed, `klavd` refuses instead of
    // leaving the password alone.
    if let Some(client) = daemon.as_mut()
        && klav_daemon::client::touch_id_enrolled(&ctx.home)
    {
        let _: serde_json::Value = call(
            client,
            Request::ConfirmPresence {
                purpose: PresencePurpose::DeleteAccount,
            },
        )
        .await
        .map_err(|e| presence_refused(e, "klav account delete"))?;
    }
    // The transcript of ADR 0037 §7.8: nothing between the password and
    // the answer.
    let password = ctx.input.password("Master password: ")?;
    let (_unlocked, asked) =
        deletion::request_account_deletion(&ctx.home, &MasterPassword::new(password.as_str()))
            .await?;
    drop(password);
    output::info(&format!(
        "Deletion scheduled for {} UTC. Your agents are stopped now.",
        format_utc_minutes(asked.delete_at)
    ));
    // An unlocked klavd learns it now, and stops what it mediates for
    // agents too.
    if let (Some(client), Some(status)) = (daemon.as_mut(), status.as_ref())
        && status.unlocked
    {
        let _: Result<serde_json::Value, _> = call(client, Request::Sync).await;
    }
    Ok(())
}

/// What `klavd`'s refusal of the presence step means for the person.
/// Touch ID unavailable: what to do instead (N6). A `bad_request`: an
/// older `klavd` that does not know the operation (it answers with `id` 0,
/// «malformed request»), which refuses correctly but says nothing useful
/// (N7). Anything else stays as it is.
fn presence_refused(e: CliError, command: &str) -> CliError {
    let CliError::Daemon(body) = &e else {
        return e;
    };
    match body.code {
        ErrorCode::BiometryUnavailable if body.message.contains("changed") => {
            CliError::Other(TOUCH_ID_CHANGED.into())
        }
        ErrorCode::BiometryUnavailable => {
            CliError::Other(format!("{TOUCH_ID_UNAVAILABLE} (klavd: {})", body.message))
        }
        ErrorCode::BadRequest => CliError::Other(format!(
            "The klavd running is older than `{command}`, so it can't confirm it's you. Update klavd to this klav's version and restart it (`klav lock --stop`, then `klav unlock`), then try again."
        )),
        _ => e,
    }
}

/// `klavd` for the Touch ID step, and its status: the running one, or one
/// started now when Touch ID is set up for it, so that stopping `klavd`
/// does not skip Touch ID. None with `--no-daemon`: the CLI without
/// `klavd` asks for the password only (ADR 0037 §1).
async fn presence_daemon(ctx: &Ctx) -> CliResult<(Option<DaemonClient>, Option<DaemonStatus>)> {
    if ctx.no_daemon {
        return Ok((None, None));
    }
    let mut client = match DaemonClient::connect(&ctx.home).await {
        Some(c) => c,
        None if klav_daemon::client::touch_id_enrolled(&ctx.home) => {
            klav_daemon::client::spawn_daemon(&ctx.home, PRESENCE_DAEMON_IDLE)
                .await
                .map_err(CliError::Other)?
        }
        None => return Ok((None, None)),
    };
    let status: DaemonStatus = call(&mut client, Request::Status).await?;
    Ok((Some(client), Some(status)))
}

/// One line typed at the terminal.
fn ask_line(prompt: &str) -> CliResult<String> {
    eprint!("{prompt}");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    Ok(line.trim_end_matches(['\r', '\n']).to_owned())
}

/// `klav account delete --cancel`: any device with a session, with
/// presence as `klav agent resume` asks for it (ADR 0037 A2): Touch ID
/// through `klavd`, else the master password; without `klavd`, the
/// password that unlocks this process.
pub(crate) async fn cancel_cmd(ctx: &mut Ctx) -> CliResult<()> {
    let canceled = match ctx.backend().await? {
        Backend::Direct(u) => u.cancel_account_deletion().await?,
        Backend::Daemon(_) => {
            let reply: serde_json::Value = crate::commands::agent::with_presence(ctx, |password| {
                Request::CancelAccountDeletion { password }
            })
            .await
            .map_err(|e| presence_refused(e, "klav account delete --cancel"))?;
            reply["canceled"].as_bool().unwrap_or(false)
        }
    };
    if canceled {
        output::info("The deletion was canceled. Your agents work again.");
    } else {
        output::info("No deletion of this account is scheduled.");
    }
    Ok(())
}

/// `klav logout`: signs this device out and deletes its copy of the
/// account. The account stays on the server (or is already gone).
pub(crate) async fn logout_cmd(ctx: &mut Ctx, args: LogoutArgs) -> CliResult<()> {
    let account = match klav_client::account(&ctx.home) {
        Ok(a) => a,
        Err(ClientError::NotLoggedIn) => {
            output::info("No account on this device.");
            return Ok(());
        }
        Err(e) => return Err(e.into()),
    };
    confirm_logout(args.yes, &account.email, &ctx.home)?;
    // klavd holds the account and writes its files: stop it first.
    if let Some(mut client) = DaemonClient::connect(&ctx.home).await {
        let _: serde_json::Value = call(&mut client, Request::Shutdown).await?;
        wait_for_daemon_exit(&ctx.home).await;
    }
    // The tokens are sealed with this device's key: the password opens
    // them to end the session on the server.
    let password = ctx
        .input
        .password(&format!("Master password for {}: ", account.email))?;
    output::info("Deriving keys (Argon2id, 256 MiB)…");
    let mut unlocked =
        klav_client::unlock_with_password(&ctx.home, &MasterPassword::new(password.as_str()))?;
    drop(password);
    // Generated passwords and passkeys not uploaded yet go first, if they
    // can: the person agreed to lose this device's copy, not them. What is
    // still queued after that (no network, or an account the server
    // deleted, where every upload fails) is refused unless the person
    // says to lose it, before the server is told anything (review
    // finding 1).
    let _ = unlocked.flush_generated().await;
    let _ = unlocked.flush_passkey_outbox().await;
    let generated = unlocked.pending_generated();
    let passkeys = unlocked.passkey_outbox()?.passkeys.len();
    if !args.discard_unsent && (generated > 0 || passkeys > 0) {
        return Err(CliError::Other(unsent_message(generated, passkeys)));
    }
    // The last count and the delete under the home's lock, as the apps do:
    // nothing queued since is deleted unseen. The server is told after, so
    // a refusal never follows a finished sign-out.
    let accepted = (!args.discard_unsent).then_some(klav_client::passkey_outbox::AcceptedUnsent {
        passkeys,
        generated,
    });
    klav_client::passkey_outbox::forget_account_unless_queued(
        &ctx.home,
        Some(&unlocked),
        accepted,
    )?;
    match unlocked.logout().await {
        Ok(()) => {}
        // Already gone on the server: nothing to end there.
        Err(ClientError::AccountDeleted(_) | ClientError::SessionExpired) => {}
        Err(e) => output::warn(&format!(
            "the server did not end this device's session ({e}); remove the device from another one"
        )),
    }
    // Telling the server may have written two files again: a refreshed
    // token, or the deletion marker when the server answered that the
    // account is gone. Only those: anything else was counted above.
    let _ = std::fs::remove_file(ctx.home.session_path());
    let _ = std::fs::remove_file(ctx.home.file(deletion::DELETION_FILE));
    for name in klav_daemon::client::ACCOUNT_FILES {
        let _ = std::fs::remove_file(ctx.home.file(name));
    }
    output::info(&format!(
        "Signed out. This device's copy of {} was deleted from {}.",
        account.email,
        ctx.home.dir().display()
    ));
    Ok(())
}

/// Why `klav logout` refuses: what would be lost, how to keep it, and
/// how to sign out anyway.
fn unsent_message(generated: usize, passkeys: usize) -> String {
    let mut what = Vec::new();
    if generated > 0 {
        what.push(format!("{generated} generated password(s)"));
    }
    if passkeys > 0 {
        what.push(format!("{passkeys} passkey(s)"));
    }
    format!(
        "{} not uploaded yet would be lost with this device's copy. Connect and run `klav sync` \
         to upload them; `klav generated ls` lists the generated passwords and `klav generated \
         show N` prints one, to keep it somewhere else. To sign out anyway and lose them, run \
         `klav logout --discard-unsent`.",
        what.join(" and ")
    )
}

/// Deleting the local copy is never done without a yes.
fn confirm_logout(yes: bool, email: &str, home: &klav_client::Home) -> CliResult<()> {
    if yes {
        return Ok(());
    }
    if !std::io::stdin().is_terminal() {
        return Err(CliError::Other(
            "`klav logout` deletes this device's copy of the account: pass --yes to confirm".into(),
        ));
    }
    let answer = ask_line(&format!(
        "This signs this device out and deletes its copy of {email} from {}: the vaults, the \
         session and the Secret Key file. The account stays on the server. Continue? [y/N] ",
        home.dir().display()
    ))?;
    if matches!(
        answer.trim().to_lowercase().as_str(),
        "y" | "yes" | "s" | "si" | "sí"
    ) {
        Ok(())
    } else {
        Err(CliError::Other("cancelled".into()))
    }
}

/// Waits (a few seconds at most) until `klavd` no longer answers.
async fn wait_for_daemon_exit(home: &klav_client::Home) {
    for _ in 0..50 {
        if DaemonClient::connect(home).await.is_none() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[cfg(test)]
mod tests {
    use klav_daemon::protocol::ErrorBody;

    use super::*;

    fn refused(code: ErrorCode, message: &str) -> String {
        let e = CliError::Daemon(ErrorBody {
            code,
            message: message.into(),
            paused: None,
            presence: None,
        });
        match presence_refused(e, "klav account delete") {
            CliError::Other(m) => m,
            CliError::Daemon(body) => format!("unchanged: {}", body.message),
            _ => "another error".into(),
        }
    }

    #[test]
    fn touch_id_unavailable_says_what_to_do() {
        let m = refused(ErrorCode::BiometryUnavailable, "Touch ID is not available");
        assert!(m.contains("Open the lid"), "{m}");
        assert!(m.contains("another of your devices"), "{m}");
        assert!(m.ends_with("(klavd: Touch ID is not available)"), "{m}");
        let m = refused(
            ErrorCode::BiometryUnavailable,
            "the enrolled fingerprints changed; the master password sets Touch ID up again",
        );
        assert!(m.contains("Run `klav account delete` again"), "{m}");
    }

    #[test]
    fn an_older_klavd_says_to_update_it() {
        let m = refused(ErrorCode::BadRequest, "malformed request");
        assert!(m.contains("older than `klav account delete`"), "{m}");
        assert!(m.contains("Update klavd"), "{m}");
        assert!(m.contains("`klav lock --stop`"), "{m}");
    }

    #[test]
    fn other_refusals_stay() {
        assert_eq!(
            refused(ErrorCode::BiometryFailed, "cancelled"),
            "unchanged: cancelled"
        );
    }
}
