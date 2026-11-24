//! Errors as the app sees them. Messages never contain secret values.

use klav_client::ClientError;

/// Everything a `KlavCore` call can fail with. The app tells these cases
/// apart (wrong password, locked, offline, security problem…); `message`
/// is for display and logs and never holds a secret.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum KlavError {
    /// Wrong master password or Secret Key.
    #[error("wrong master password or Secret Key")]
    WrongCredentials,
    /// No account on this device yet.
    #[error("no account on this device")]
    NotLoggedIn,
    /// The account is locked: unlock it first.
    #[error("locked")]
    Locked,
    /// The session expired or was revoked: sign in again.
    #[error("the session expired or was revoked")]
    SessionExpired,
    /// The server could not be reached.
    #[error("{message}")]
    Network {
        /// What happened.
        message: String,
    },
    /// The server returned older data than this device has seen (T7).
    #[error("{message}")]
    Rollback {
        /// What happened.
        message: String,
    },
    /// A signature, identity or pairing code does not check out.
    #[error("{message}")]
    Security {
        /// What happened.
        message: String,
    },
    /// Face ID was cancelled or did not match; the enrolment is kept.
    #[error("{message}")]
    BiometryFailed {
        /// What happened.
        message: String,
    },
    /// Face ID cannot unlock (not set up, key invalidated, unavailable).
    #[error("{message}")]
    BiometryUnavailable {
        /// Why.
        message: String,
    },
    /// The policy asks for the master password (every 14 days, or after a
    /// restart) before Face ID works again.
    #[error("{message}")]
    PasswordRequired {
        /// Why.
        message: String,
    },
    /// Something asked for does not exist.
    #[error("{message}")]
    NotFound {
        /// What.
        message: String,
    },
    /// Someone else changed the item first.
    #[error("the item changed on the server (now at version {version})")]
    Conflict {
        /// Version on the server.
        version: u64,
    },
    /// The site does not belong to the item (anti-phishing, T21).
    #[error("{message}")]
    SiteMismatch {
        /// What.
        message: String,
    },
    /// The server or the policy refused.
    #[error("{message}")]
    Denied {
        /// Why.
        message: String,
    },
    /// `klavd` does not answer (Mac app, ADR 0027): not running, or it
    /// closed the connection.
    #[cfg(feature = "daemon")]
    #[error("{message}")]
    DaemonUnavailable {
        /// What happened.
        message: String,
    },
    /// The presence gate (ADR 0041 §2.4, layer 5): Touch ID can't confirm
    /// this value, so the app asks for the master password in its own
    /// window, worded from `ask`, and calls the same method's
    /// `_with_password` form. `DaemonEngine` sends it on the connection that
    /// got the ask (own choice 32).
    #[cfg(feature = "daemon")]
    #[error("Klav needs the master password")]
    PresenceRequired {
        /// What the password grants.
        ask: crate::presence::PresenceAskInfo,
    },
    /// Another confirmation is running: try again once it is done (ADR 0041
    /// §2.4, own choice 18). `password_check`: `klavd` is checking another
    /// master password (with the gate off it says so with `conflict`).
    /// `in_this_app`: this app is already confirming something (a Touch ID
    /// dialog, or a password question for another value). Otherwise
    /// another program's Touch ID dialog is open.
    #[cfg(feature = "daemon")]
    #[error("{message}")]
    PresenceBusy {
        /// Another master password is being checked.
        password_check: bool,
        /// The other confirmation is this app's own.
        in_this_app: bool,
        /// `klavd`'s words, or the engine's.
        message: String,
    },
    /// This `klavd` doesn't offer it: the presence setting with the gate
    /// off, or a `klavd` older than it.
    #[cfg(feature = "daemon")]
    #[error("{message}")]
    NotSupported {
        /// What happened.
        message: String,
    },
    /// The item changed between the question and the hand-out: nothing was
    /// handed out (Omar's decision F of 2026-11-19). Ask again.
    #[cfg(feature = "daemon")]
    #[error("{message}")]
    ChangedWhileConfirming {
        /// What happened.
        message: String,
    },
    /// Klav deleted the account on the server (ADR 0037 §3): this device
    /// knew the date and it passed. Its copy stays, read-only, until the
    /// person deletes it; nothing here deletes it.
    #[error("{message}")]
    AccountDeleted {
        /// When (Unix ms). `None` when `klavd` says so, which sends the
        /// date in its `status` instead.
        delete_at: Option<i64>,
        /// What happened.
        message: String,
    },
    /// The person asked to delete the account: what Klav does for agents
    /// is refused until then (ADR 0037 §3).
    #[error("{message}")]
    AccountDeleting {
        /// What happened, with the date.
        message: String,
    },
    /// This server cannot delete accounts from the app (ADR 0037 §4).
    #[error("{message}")]
    DeletionUnsupported {
        /// What to tell the person.
        message: String,
    },
    /// A deletion of the account is already scheduled (`409`): asked from
    /// another device, or from this one by a request whose answer was
    /// lost. Sync to see when.
    #[error("{message}")]
    DeletionAlreadyScheduled {
        /// What happened (English; the apps say it in their language).
        message: String,
    },
    /// The server's limits on asking for the deletion (`429`).
    #[error("{message}")]
    DeletionRateLimited {
        /// What happened (English; the apps say it in their language).
        message: String,
    },
    /// The server scheduled (or canceled) the deletion, but this device
    /// could not write it down; the next sync does (review finding 7).
    #[error("{message}")]
    DeletionNotRecorded {
        /// When the scheduled deletion happens (Unix ms); `None` after a
        /// cancel.
        delete_at: Option<i64>,
        /// What happened.
        message: String,
    },
    /// Invalid input or unexpected state.
    #[error("{message}")]
    Invalid {
        /// What.
        message: String,
    },
}

/// Longest error message handed to the app. The text can come from the
/// server, which is not trusted: one line, no control or format characters
/// (bidi, zero-width), and short (layer 11 of the 2026-11 round).
pub(crate) const MAX_ERROR_TEXT: usize = 300;

impl From<ClientError> for KlavError {
    fn from(e: ClientError) -> Self {
        let message = klav_core::text::shown(&e.to_string(), MAX_ERROR_TEXT);
        match e {
            ClientError::WrongCredentials => Self::WrongCredentials,
            ClientError::NotLoggedIn => Self::NotLoggedIn,
            ClientError::SessionExpired => Self::SessionExpired,
            ClientError::Network(_) => Self::Network { message },
            ClientError::Rollback(_) => Self::Rollback { message },
            ClientError::Security(_) => Self::Security { message },
            ClientError::NotFound(_) => Self::NotFound { message },
            ClientError::Conflict(version) => Self::Conflict { version },
            ClientError::Denied(_) | ClientError::PendingApproval { .. } => {
                Self::Denied { message }
            }
            ClientError::Api { status: 401, .. } => Self::SessionExpired,
            ClientError::AccountDeleted(at) => Self::AccountDeleted {
                delete_at: Some(at),
                message,
            },
            ClientError::AccountDeleting(_) => Self::AccountDeleting { message },
            ClientError::DeletionUnsupported => Self::DeletionUnsupported { message },
            ClientError::DeletionAlreadyScheduled => Self::DeletionAlreadyScheduled { message },
            ClientError::DeletionRateLimited => Self::DeletionRateLimited { message },
            ClientError::DeletionNotRecorded { scheduled, .. } => Self::DeletionNotRecorded {
                delete_at: scheduled,
                message,
            },
            _ => Self::Invalid { message },
        }
    }
}

impl From<klav_core::crypto::CryptoError> for KlavError {
    fn from(e: klav_core::crypto::CryptoError) -> Self {
        Self::Invalid {
            message: e.to_string(),
        }
    }
}

impl KlavError {
    pub(crate) fn invalid(message: impl Into<String>) -> Self {
        Self::Invalid {
            message: message.into(),
        }
    }
}

/// Result alias.
pub type KlavResult<T> = Result<T, KlavError>;
