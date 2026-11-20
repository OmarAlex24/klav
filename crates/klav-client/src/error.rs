//! Errors of the client library. Messages never contain secret values.

use klav_core::crypto::CryptoError;
use klav_core::model::{ModelError, ReferenceError};
use klav_proto::ErrorCode;
use thiserror::Error;

/// Result alias.
pub type ClientResult<T> = Result<T, ClientError>;

/// Everything that can go wrong in a client operation.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ClientError {
    /// The server URL is invalid or uses plain HTTP to a non-loopback host.
    #[error("invalid server URL: {0}")]
    ServerUrl(String),
    /// The server could not be reached or the response could not be read.
    #[error("cannot reach the server: {0}")]
    Network(String),
    /// The server answered with an error.
    #[error("server error ({status}): {message}")]
    Api {
        /// HTTP status.
        status: u16,
        /// Machine-readable code, if the body had one.
        code: Option<ErrorCode>,
        /// Server message.
        message: String,
        /// On a version conflict, the version the server has.
        current_version: Option<u64>,
    },
    /// Wrong master password or Secret Key.
    #[error("wrong master password or Secret Key")]
    WrongCredentials,
    /// The session was revoked or expired: log in again.
    #[error("the session expired or was revoked; run `klav login` again")]
    SessionExpired,
    /// No account is set up in this home directory.
    #[error("no account on this device; run `klav signup` or `klav login` first")]
    NotLoggedIn,
    /// An account is already set up in this home directory.
    #[error("this device already has an account ({0}); use another KLAV_HOME to add a second one")]
    AlreadyLoggedIn(String),
    /// **Possible rollback attack** (threat T7): the server returned an
    /// older state than this device has already seen.
    #[error(
        "SECURITY: the server returned older data than this device has already seen ({0}). Refusing to sync: this can be a rollback attack or a server restored from an old backup"
    )]
    Rollback(String),
    /// **Security problem** other than a rollback: an identity that
    /// changed, a grant or approval whose signature does not verify.
    #[error("SECURITY: {0}")]
    Security(String),
    /// The policy (or the person) refused the action.
    #[error("denied: {0}")]
    Denied(String),
    /// The person paused this agent, or every agent (ADR 0033 §7.4): stop,
    /// tell the person, and do not retry or work around it. The pause, when
    /// the server said which (`agents_paused`).
    #[error("{}", paused_message(.0.as_ref()))]
    Paused(Option<klav_proto::agent::AgentPaused>),
    /// The person asked Klav to delete the account (ADR 0037 §3): every
    /// agent is stopped until the deletion is canceled or done. Stop, tell
    /// the person, and do not retry. When the account is deleted (Unix ms),
    /// if the server or `klavd` said.
    #[error("{}", deleting_message(*.0))]
    AccountDeleting(Option<i64>),
    /// The server deleted the account (ADR 0037 §3): this device knew the
    /// date (Unix ms), it passed, and the server no longer knows the
    /// session. The local copy stays, read-only; nothing deletes it but
    /// the person.
    #[error("{}", deleted_message(*.0))]
    AccountDeleted(i64),
    /// The server is older than account deletion (`account_deletion`
    /// absent from `GET /v1/health`, ADR 0037 §4, §7.7).
    #[error("This server can't delete accounts from the app. Ask whoever runs it.")]
    DeletionUnsupported,
    /// The deletion of the account is already scheduled (`409` from
    /// `POST /v1/account/delete/start`, ADR 0037 §5.1): asked from another
    /// device, or from this one by a request whose answer was lost. Sync
    /// to see when; cancel it from any device.
    #[error(
        "The deletion of this account is already scheduled; `klav account delete --cancel` cancels it, and `klav sync` shows when it happens."
    )]
    DeletionAlreadyScheduled,
    /// The server's limits on asking for the deletion (`429`, ADR 0037
    /// §5.6): 5 tries per account and hour, 3 deletions every 7 days.
    #[error(
        "Klav limits how often the deletion can be asked for (5 tries an hour, 3 deletions every 7 days). Try again later."
    )]
    DeletionRateLimited,
    /// The server took the request, but this device could not write it
    /// down (ADR 0037 §3; review finding 7). `scheduled`: the deletion is
    /// scheduled for then (Unix ms); `None`: it was canceled. The next sync
    /// records it.
    #[error("{}", not_recorded_message(*.scheduled, .why))]
    DeletionNotRecorded {
        /// When the scheduled deletion happens; `None` after a cancel.
        scheduled: Option<i64>,
        /// Why this device could not record it.
        why: String,
    },
    /// The action needs a person's approval (`ask`, design §5.3).
    #[error("waiting for approval {id}: {message}")]
    PendingApproval {
        /// The approval to wait for (`pending_approval_id`).
        id: klav_core::ids::ApprovalId,
        /// What to tell the agent.
        message: String,
    },
    /// Something the caller asked for does not exist.
    #[error("not found: {0}")]
    NotFound(String),
    /// A name matches several entries.
    #[error("{0}")]
    Ambiguous(String),
    /// The input is invalid.
    #[error("{0}")]
    Invalid(String),
    /// Someone else changed the item first.
    #[error("the item changed on the server (now at version {0}); sync and retry")]
    Conflict(u64),
    /// A pause or a resume older than the scope's latest decision, decided
    /// at this time (Unix ms, ADR 0033 §7.6). Sign again after it to keep
    /// the decision.
    #[error("{}", later_pause_message(*.0))]
    LaterPause(i64),
    /// A person's revocation of sandboxes older than the latest one of the
    /// same proxy and scope, signed at this time (Unix ms, spec §13.11).
    /// Revoke again after it.
    #[error("{}", later_revocation_message(*.0))]
    LaterRevocation(i64),
    /// A reference could not be parsed or resolved.
    #[error(transparent)]
    Reference(#[from] ReferenceError),
    /// The item model rejected a value.
    #[error(transparent)]
    Model(#[from] ModelError),
    /// A blob failed to decrypt or verify.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    /// Local state is unreadable.
    #[error("local state is corrupt or from another version: {0}")]
    Corrupt(String),
    /// A local file written by a newer Klav, in a format this one does not
    /// read (`v` above what it knows). The file is left as it is: updating
    /// Klav reads it again. Never "move it aside", which would lose what it
    /// holds.
    #[error(
        "{0} was written by a newer version of Klav, which this one cannot read. Update Klav; nothing in the file was changed"
    )]
    NewerFormat(String),
    /// Filesystem error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// What a paused agent is told.
fn paused_message(paused: Option<&klav_proto::agent::AgentPaused>) -> String {
    let scope = match paused.map(|p| p.scope) {
        Some(klav_proto::agent::PauseScope::Agent) => "this agent",
        _ => "agents",
    };
    let until = paused
        .and_then(|p| p.until)
        .map(|t| format!(" until {t} (Unix ms)"))
        .unwrap_or_default();
    format!(
        "agents_paused: the person paused Klav for {scope}{until}; do not retry or work around it, tell the person you need Klav and ask them to resume it"
    )
}

/// What an agent of an account being deleted is told (ADR 0037 §3).
fn deleting_message(delete_at: Option<i64>) -> String {
    let when = delete_at
        .map(|t| format!(" (it is deleted at {t}, Unix ms)"))
        .unwrap_or_default();
    format!(
        "account_deleting: the person asked Klav to delete this account{when}; stop and tell the person, and do not retry"
    )
}

/// The server did it, this device could not record it (review finding 7):
/// a retry must not look like a failure.
fn not_recorded_message(scheduled: Option<i64>, why: &str) -> String {
    match scheduled {
        Some(at) => format!(
            "The deletion is scheduled on the server (at {at}, Unix ms), but this device could not record it ({why}). Asking again answers that it is already scheduled; `klav account delete --cancel` cancels it, and the next sync records it here."
        ),
        None => format!(
            "The deletion was canceled on the server, but this device could not record it ({why}). The next sync records it here."
        ),
    }
}

/// What a device that knew the date hears once the account is gone (the
/// apps and the CLI say it in their own words, with the date).
fn deleted_message(at: i64) -> String {
    format!(
        "Klav deleted this account (due at {at}, Unix ms). This device still keeps its encrypted copy, read-only; nothing deletes it but you"
    )
}

/// What a decision older than the scope's latest one hears: from when a
/// new one is taken. The server takes only a later `at`, so a decision
/// made after `last` by this device's clock goes through; with `last`
/// ahead of that clock (another device's clock runs ahead, or a pause was
/// signed again just after it), it says how long that is.
fn later_pause_message(last: i64) -> String {
    later_pause_message_at(last, crate::session::now_ms())
}

fn later_pause_message_at(last: i64, now: i64) -> String {
    later_message_at(
        &format!(
            "a later pause or resume of these agents exists (decided at {last}, Unix ms): this one is old or repeated"
        ),
        "decid",
        last,
        now,
    )
}

fn later_revocation_message(last: i64) -> String {
    later_revocation_message_at(last, crate::session::now_ms())
}

fn later_revocation_message_at(last: i64, now: i64) -> String {
    later_message_at(
        &format!(
            "a later revocation of these sandboxes exists (signed at {last}, Unix ms): this one is old or repeated"
        ),
        "revok",
        last,
        now,
    )
}

/// `head`, and when doing it again (`verb` + `ing` / `e`) goes through.
fn later_message_at(head: &str, verb: &str, last: i64, now: i64) -> String {
    if last < now {
        format!("{head}; {verb}ing again now goes through")
    } else {
        // Whole seconds, rounded up, past `last`.
        let wait = (last - now) / 1000 + 1;
        format!(
            "{head}; that decision is {wait}s ahead of this device's clock, so {verb}e again in {wait}s (after {}, Unix ms)",
            last.saturating_add(1)
        )
    }
}

impl ClientError {
    /// `true` for errors that mean "the server may be lying" (T7, T10,
    /// T11): rollbacks and signatures or identities that do not check out.
    pub fn is_rollback(&self) -> bool {
        matches!(self, ClientError::Rollback(_) | ClientError::Security(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_later_pause_says_from_when_to_decide_again() {
        let now = 1_000_000_000;
        // In the past: now goes through.
        let past = later_pause_message_at(now - 1, now);
        assert!(past.ends_with("deciding again now goes through"), "{past}");
        // Ahead of this clock (a pause signed again at `last_at + 1`, say):
        // how long, rounded up, and the time.
        let ahead = later_pause_message_at(now + 2_500, now);
        assert!(
            ahead.contains(
                "3s ahead of this device's clock, so decide again in 3s (after 1000002501, Unix ms)"
            ),
            "{ahead}"
        );
        let same = later_pause_message_at(now, now);
        assert!(same.contains("decide again in 1s"), "{same}");
    }

    #[test]
    fn a_later_revocation_speaks_of_revoking_not_of_a_pause() {
        let now = 1_000_000_000;
        let past = later_revocation_message_at(now - 1, now);
        assert!(
            past.starts_with("a later revocation of these sandboxes exists"),
            "{past}"
        );
        assert!(past.ends_with("revoking again now goes through"), "{past}");
        assert!(!past.contains("pause"), "{past}");
        let ahead = later_revocation_message_at(now + 2_500, now);
        assert!(ahead.contains("so revoke again in 3s"), "{ahead}");
    }
}
