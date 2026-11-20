//! CLI errors and exit codes.

use klav_client::ClientError;

/// Exit code for usage errors (clap uses 2 as well).
pub(crate) const EXIT_USAGE: u8 = 2;
/// Exit code for a detected rollback (threat T7) or another security check.
pub(crate) const EXIT_SECURITY: u8 = 3;
/// Exit code when an agent action waits for the person's approval.
pub(crate) const EXIT_PENDING: u8 = 4;
/// Exit code when the policy (or the person) denied an agent action.
pub(crate) const EXIT_DENIED: u8 = 5;
/// Exit code of `klav approval wait` when the request expired undecided.
pub(crate) const EXIT_EXPIRED: u8 = 6;
/// Exit code when the person paused the agent, or every agent (ADR 0033
/// §7.4): stop and tell the person.
pub(crate) const EXIT_PAUSED: u8 = 7;
/// Exit code when the person asked Klav to delete the account (ADR 0037
/// §3): every agent stops. Stop and tell the person.
pub(crate) const EXIT_ACCOUNT_DELETING: u8 = 8;
/// Exit code when `klavd` needs the person's presence before it hands out
/// a value and `klav` has no terminal to ask for the master password on
/// (ADR 0041 §3.2): run the command from a terminal.
pub(crate) const EXIT_NO_TERMINAL: u8 = 9;

#[derive(Debug)]
pub(crate) enum CliError {
    Client(ClientError),
    Usage(String),
    Other(String),
    /// An error reported by `klavd`.
    Daemon(klav_daemon::protocol::ErrorBody),
    /// Exit with this code without a message (the exit code of `klav run`'s child).
    Exit(u8),
    /// A refusal with its own exit code and message (`klav sandbox`): the
    /// `klav_*` code when there is one, and the next step, which the text
    /// adds after `\nNext: `.
    Coded {
        code: u8,
        error: Option<String>,
        message: String,
        next: Option<String>,
    },
}

pub(crate) type CliResult<T> = Result<T, CliError>;

impl From<ClientError> for CliError {
    fn from(e: ClientError) -> Self {
        CliError::Client(e)
    }
}

impl From<std::io::Error> for CliError {
    fn from(e: std::io::Error) -> Self {
        CliError::Other(e.to_string())
    }
}

impl CliError {
    pub(crate) fn exit_code(&self) -> u8 {
        match self {
            CliError::Client(e) if e.is_rollback() => EXIT_SECURITY,
            CliError::Client(ClientError::PendingApproval { .. }) => EXIT_PENDING,
            CliError::Client(ClientError::Denied(_)) => EXIT_DENIED,
            CliError::Client(ClientError::Paused(_)) => EXIT_PAUSED,
            CliError::Daemon(e) if e.code == klav_daemon::protocol::ErrorCode::AgentsPaused => {
                EXIT_PAUSED
            }
            CliError::Client(ClientError::AccountDeleting(_)) => EXIT_ACCOUNT_DELETING,
            CliError::Daemon(e) if e.code == klav_daemon::protocol::ErrorCode::AccountDeleting => {
                EXIT_ACCOUNT_DELETING
            }
            CliError::Daemon(e)
                if matches!(
                    e.code,
                    klav_daemon::protocol::ErrorCode::Rollback
                        | klav_daemon::protocol::ErrorCode::Security
                ) =>
            {
                EXIT_SECURITY
            }
            CliError::Usage(_) => EXIT_USAGE,
            CliError::Exit(code) | CliError::Coded { code, .. } => *code,
            _ => 1,
        }
    }

    pub(crate) fn message(&self) -> Option<String> {
        match self {
            // «Klav deleted your account» (ADR 0037 §3), with the date.
            CliError::Client(ClientError::AccountDeleted(at)) => Some(deleted_message(*at)),
            // Scheduled on the server, not written down here: say when.
            CliError::Client(ClientError::DeletionNotRecorded {
                scheduled: Some(at),
                why,
            }) => Some(format!(
                "The deletion is scheduled on the server for {} UTC, but this device could not \
                 record it ({why}). Asking again answers that it is already scheduled; \
                 `klav account delete --cancel` cancels it, and the next sync records it here.",
                crate::time::format_utc_minutes(*at)
            )),
            CliError::Client(e) => Some(e.to_string()),
            CliError::Coded {
                message,
                next: Some(next),
                ..
            } => Some(format!("{message}\nNext: {next}")),
            CliError::Usage(m)
            | CliError::Other(m)
            | CliError::Coded {
                message: m,
                next: None,
                ..
            } => Some(m.clone()),
            CliError::Daemon(e) => Some(e.message.clone()),
            CliError::Exit(_) => None,
        }
    }
}

/// What a device that knew the date says once the account is gone.
pub(crate) fn deleted_message(at: i64) -> String {
    format!(
        "Klav deleted your account on {} UTC. This device still keeps an encrypted copy, \
         read-only. Destroy your emergency kit too: with it and your password, any leftover \
         copy opens. `klav logout` deletes this device's copy.",
        crate::time::format_utc_minutes(at)
    )
}

pub(crate) fn usage(msg: impl Into<String>) -> CliError {
    CliError::Usage(msg.into())
}
