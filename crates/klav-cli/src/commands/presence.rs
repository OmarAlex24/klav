//! `klav presence window` (ADR 0041 §2.4): how often `klavd` asks for the
//! person's presence before it hands out a value. The setting is sealed in
//! `klavd`'s local data, so it is read and changed only through an
//! unlocked `klavd`, never from the files (Omar's decision on Q-N2).

use klav_daemon::client::DaemonClient;
use klav_daemon::protocol::{ErrorBody, ErrorCode, Request};
use klav_daemon::uv::Window;
use serde::Deserialize;

use crate::cli::{PresenceCommand, PresenceWindowArg};
use crate::context::Ctx;
use crate::error::{CliError, CliResult};
use crate::output;
use crate::presence::{self, Busy};

/// `presence_window`'s answer.
#[derive(Deserialize)]
struct Answer {
    window: Window,
}

impl From<PresenceWindowArg> for Window {
    fn from(arg: PresenceWindowArg) -> Self {
        match arg {
            PresenceWindowArg::Always => Window::Always,
            PresenceWindowArg::FiveMinutes => Window::FiveMinutes,
            PresenceWindowArg::Unlocked => Window::Unlocked,
        }
    }
}

pub(crate) async fn presence_cmd(ctx: &Ctx, cmd: PresenceCommand) -> CliResult<()> {
    match cmd {
        PresenceCommand::Window { window, json } => {
            window_cmd(ctx, window.map(Window::from), json.json).await
        }
    }
}

async fn window_cmd(ctx: &Ctx, to: Option<Window>, json: bool) -> CliResult<()> {
    if ctx.no_daemon {
        return Err(CliError::Other(
            "the presence setting is klavd's, and `--no-daemon` doesn't use klavd: without it, \
             every command asks for the master password"
                .into(),
        ));
    }
    // Never started or unlocked from here: the setting shows only from an
    // unlocked `klavd` (ADR 0041 §2.4).
    let Some(mut client) = DaemonClient::connect(&ctx.home).await else {
        return Err(CliError::Other(
            "klavd isn't running, and the presence setting is klavd's: start and unlock it \
             with `klav unlock`, then try again"
                .into(),
        ));
    };
    let read = Request::PresenceWindow {
        window: None,
        password: None,
    };
    let current = client
        .call::<Answer>(read)
        .await
        .map_err(unavailable)?
        .0
        .window;
    let now = match to {
        None => current,
        Some(to) if to == current => current,
        // Tightening asks for nothing, and shortens open windows at once.
        Some(to) if to < current => {
            let change = Request::PresenceWindow {
                window: Some(to),
                password: None,
            };
            let (answer, warnings) = client
                .call::<Answer>(change)
                .await
                .map_err(setting_refused)?;
            // Only a `klavd` with the gate on answers here: its words,
            // cleaned (the second review of layer 3).
            presence::warn_all(&warnings);
            answer.window
        }
        Some(to) => {
            let value = presence::loosen(&mut client, current, to)
                .await
                .map_err(|e| match e {
                    CliError::Daemon(body) => setting_refused(body),
                    e => e,
                })?;
            serde_json::from_value::<Answer>(value)
                .map_err(|e| CliError::Other(format!("klavd's answer: {e}")))?
                .window
        }
    };
    if json {
        return output::json(&serde_json::json!({ "window": now }));
    }
    output::line(&format!(
        "Klav asks for your presence {} (`{}`).",
        presence::window_words(now),
        name(now)
    ));
    match to {
        Some(to) if to > current => output::info(
            "The change opens no window: the next value asks once more, with the new setting.",
        ),
        Some(to) if to < current => {
            output::info("Windows already open now last no longer than the new setting allows.");
        }
        _ => {}
    }
    Ok(())
}

/// A setting's name on the command line and in `--json`.
fn name(window: Window) -> &'static str {
    match window {
        Window::Always => "always",
        Window::FiveMinutes => "5m",
        Window::Unlocked => "unlocked",
    }
}

/// Why `klavd` has no setting to show: locked, the gate off, or older.
fn unavailable(e: ErrorBody) -> CliError {
    match e.code {
        ErrorCode::Locked => CliError::Other(
            "Klav is locked, and the presence setting shows only while it is unlocked: it is \
             sealed with your vault's keys. Run `klav unlock`, then try again"
                .into(),
        ),
        ErrorCode::NotSupported => CliError::Other(
            "this klavd doesn't ask for presence before it hands out values (the presence \
             gate is off), so it has no presence setting to show or change"
                .into(),
        ),
        // An older `klavd` can't read the request at all.
        ErrorCode::BadRequest => CliError::Other(
            "this klavd is older than the presence setting. Update Klav and restart klavd \
             (`klav lock --stop`, then `klav unlock`), then try again"
                .into(),
        ),
        _ => CliError::Daemon(e),
    }
}

/// A change `klavd` refused: locked since the read, busy, or anything
/// else as `klavd` said it.
fn setting_refused(e: ErrorBody) -> CliError {
    match e.code {
        ErrorCode::Locked | ErrorCode::NotSupported | ErrorCode::BadRequest => unavailable(e),
        _ => presence::refused(e, Busy::Setting),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(code: ErrorCode) -> ErrorBody {
        ErrorBody {
            code,
            message: "klavd's words".into(),
            paused: None,
            presence: None,
        }
    }

    #[test]
    fn each_klavd_without_a_setting_to_show_gets_its_own_true_message() {
        let locked = unavailable(body(ErrorCode::Locked)).message().unwrap();
        assert!(
            locked.contains("Klav is locked") && locked.contains("`klav unlock`"),
            "{locked}"
        );
        let off = unavailable(body(ErrorCode::NotSupported))
            .message()
            .unwrap();
        assert!(off.contains("the presence gate is off"), "{off}");
        let older = unavailable(body(ErrorCode::BadRequest)).message().unwrap();
        assert!(
            older.contains("older") && older.contains("Update Klav"),
            "{older}"
        );
        // Each says something different, and none claims a setting.
        assert!(locked != off && off != older && locked != older);
        let other = unavailable(body(ErrorCode::Internal)).message().unwrap();
        assert_eq!(other, "klavd's words");
    }

    #[test]
    fn a_busy_change_says_what_may_be_running() {
        let busy = setting_refused(body(ErrorCode::PresenceBusy))
            .message()
            .unwrap();
        assert!(busy.contains("change of the setting"), "{busy}");
        let wrong = setting_refused(body(ErrorCode::WrongCredentials));
        assert_eq!(wrong.message().unwrap(), "klavd's words");
    }

    #[test]
    fn the_names_are_the_wire_names() {
        for window in [Window::Always, Window::FiveMinutes, Window::Unlocked] {
            assert_eq!(
                serde_json::to_value(window).unwrap(),
                serde_json::Value::from(name(window))
            );
        }
        assert_eq!(
            Window::from(PresenceWindowArg::FiveMinutes),
            Window::FiveMinutes
        );
    }
}
