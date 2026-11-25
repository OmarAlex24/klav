//! The presence gate as the Mac app sees it (ADR 0041 §1.2, §2.4, layer
//! 5): what `klavd`'s `presence_required` asks for, what an unlock's
//! question may say, the presence setting, and the held connection that
//! `DaemonEngine` keeps for `unlock` and the values.
//!
//! Only with the `daemon` feature: the iOS bindings do not have these.

use std::time::{Duration, Instant};

use klav_client::ops::SecretText;
use klav_daemon::client::DaemonClient;
use klav_daemon::protocol::{
    AskLasts, AskValue, AskValueKind, ErrorBody, ErrorCode, PresenceAsk, PresenceKey, Request,
    StatusPresence,
};
use klav_daemon::uv::Window;
use serde::Deserialize;

use crate::{KlavError, KlavResult};

/// The presence setting (ADR 0041 §2.4): how long one verification lets a
/// program use the vault. The same three values as the passkey setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum PresenceSetting {
    /// Every value asks.
    Always,
    /// One verification lasts 5 minutes (the default).
    FiveMinutes,
    /// One verification lasts until Klav locks.
    WhileUnlocked,
}

impl From<Window> for PresenceSetting {
    fn from(w: Window) -> Self {
        match w {
            Window::Always => Self::Always,
            Window::FiveMinutes => Self::FiveMinutes,
            Window::Unlocked => Self::WhileUnlocked,
        }
    }
}

impl From<PresenceSetting> for Window {
    fn from(s: PresenceSetting) -> Self {
        match s {
            PresenceSetting::Always => Self::Always,
            PresenceSetting::FiveMinutes => Self::FiveMinutes,
            PresenceSetting::WhileUnlocked => Self::Unlocked,
        }
    }
}

/// What a window is keyed on (`presence.key`, `docs/klavd.md` §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum PresenceKeyKind {
    /// A terminal session.
    Session,
    /// A parent process.
    Parent,
    /// This connection only. The app's own connection, when it isn't
    /// held.
    Connection,
    /// No window at all: each value asks.
    NoWindow,
}

impl From<PresenceKey> for PresenceKeyKind {
    fn from(k: PresenceKey) -> Self {
        match k {
            PresenceKey::Session => Self::Session,
            PresenceKey::Parent => Self::Parent,
            PresenceKey::Connection => Self::Connection,
            PresenceKey::None => Self::NoWindow,
        }
    }
}

/// How long what the password grants lasts (`presence.lasts`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum PresenceLasts {
    /// Five minutes.
    FiveMinutes,
    /// Until Klav locks.
    UntilLock,
}

impl From<AskLasts> for PresenceLasts {
    fn from(l: AskLasts) -> Self {
        match l {
            AskLasts::FiveMinutes => Self::FiveMinutes,
            AskLasts::UntilLock => Self::UntilLock,
        }
    }
}

/// The kind of the one value a password hands out (`presence.value.kind`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum PresenceValueKind {
    /// An item's values.
    Show,
    /// A previous password.
    Previous,
    /// A one-time code.
    Code,
    /// A fill in a browser.
    Fill,
    /// A generated password.
    Generated,
    /// The values of a command's references.
    Resolve,
}

impl From<AskValueKind> for PresenceValueKind {
    fn from(k: AskValueKind) -> Self {
        match k {
            AskValueKind::Show => Self::Show,
            AskValueKind::Previous => Self::Previous,
            AskValueKind::Code => Self::Code,
            AskValueKind::Fill => Self::Fill,
            AskValueKind::Generated => Self::Generated,
            AskValueKind::Resolve => Self::Resolve,
        }
    }
}

/// The one value a password hands out, for the app to word in its own
/// language. The title is the item's in the vault, a hint and not proof
/// (Omar's decision D of 2026-11-19), cleaned again here.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PresenceValueInfo {
    pub kind: PresenceValueKind,
    pub title: Option<String>,
    pub count: Option<u32>,
}

/// What `klavd`'s `presence_required` says the app's password question
/// must say it grants (ADR 0041 §2.4). The app words its question from
/// `lasts`, never from `window` alone.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PresenceAskInfo {
    /// What the window is keyed on.
    pub key: PresenceKeyKind,
    /// The presence setting now.
    pub window: PresenceSetting,
    /// The asking connection's controlling terminal; never for the app.
    pub terminal: Option<String>,
    /// The connection declared `hold`: the password would hold it until
    /// Klav locks.
    pub declared: bool,
    /// The window the password opens; `None`: only `value`, this once.
    pub lasts: Option<PresenceLasts>,
    /// With no window: the one value it hands out.
    pub value: Option<PresenceValueInfo>,
}

/// Longest title handed to the app from an ask.
const MAX_TITLE: usize = 120;

impl From<PresenceAsk> for PresenceAskInfo {
    fn from(a: PresenceAsk) -> Self {
        Self {
            key: a.key.into(),
            window: a.window.into(),
            terminal: a.terminal.map(|t| klav_core::text::shown(&t, 32)),
            declared: a.declared,
            lasts: a.lasts.map(Into::into),
            value: a.value.map(|v: AskValue| PresenceValueInfo {
                kind: v.kind.into(),
                title: v.title.map(|t| klav_core::text::shown(&t, MAX_TITLE)),
                count: v.count,
            }),
        }
    }
}

/// What the app's unlock question may say (`status`'s `presence`, read on
/// the held connection, so `declared` and the key are that connection's).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct UnlockQuestionInfo {
    /// The presence gate is on in this `klavd`. Without it the question
    /// says what it always said, and nothing below applies.
    pub gate: bool,
    /// `klavd` is unlocked, and another program unlocked it (Q-N1).
    pub elsewhere: bool,
    /// What a window would be keyed on.
    pub key: PresenceKeyKind,
    /// The held connection declared `hold`.
    pub declared: bool,
    /// The window a typed master password opens; `None`: none (the first
    /// unlock since `klavd` started, Always, or no window). The app's
    /// question says it, and sends it back as `shown`.
    pub lasts: Option<PresenceLasts>,
}

impl UnlockQuestionInfo {
    pub(crate) fn of(presence: Option<StatusPresence>) -> Self {
        match presence {
            Some(p) => Self {
                gate: true,
                elsewhere: p.elsewhere,
                key: p.key.into(),
                declared: p.declared,
                lasts: p.lasts.map(Into::into),
            },
            None => Self {
                gate: false,
                elsewhere: false,
                key: PresenceKeyKind::Connection,
                declared: false,
                lasts: None,
            },
        }
    }
}

/// What an `unlock` answered.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct UnlockOutcome {
    /// Another program had already unlocked Klav (Q-N1). Without the
    /// master password this unlock gave the app nothing: the app says so
    /// ("If you didn't unlock it, lock Klav"). With it, the password still
    /// counted as the app's own verification.
    pub already_unlocked: bool,
    /// `klavd` no longer reads the old passkey setting, and deleted it
    /// (Q-N3): passkeys now ask every time. Said once, by this unlock.
    pub passkey_setting_reset: bool,
    /// `klavd`'s other warnings, one line each, cleaned.
    pub warnings: Vec<String>,
}

/// The start of `klavd`'s warning when it found and deleted the old
/// `passkeys.json` (ADR 0041 §2.4, Q-N3; `docs/klavd.md` §3).
const PASSKEY_SETTING_WARNING: &str = "Klav no longer reads your old passkey setting";

impl UnlockOutcome {
    pub(crate) fn of(already_unlocked: bool, warnings: Vec<String>) -> Self {
        let mut passkey_setting_reset = false;
        let warnings = warnings
            .into_iter()
            .filter(|w| {
                let old = w.starts_with(PASSKEY_SETTING_WARNING);
                passkey_setting_reset |= old;
                !old
            })
            .map(|w| klav_core::text::shown(&w, crate::error::MAX_ERROR_TEXT))
            .collect();
        Self {
            already_unlocked,
            passkey_setting_reset,
            warnings,
        }
    }
}

/// What `hold` answered on the held connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HoldState {
    /// Not sent yet: no connection.
    NotSent,
    /// Declared; `held` once an unlock or a window verification on it
    /// held it until Klav locks.
    Declared { held: bool },
    /// `not_supported`: until layer 6 on macOS, always on Linux, and with
    /// the gate off. The connection stays, an ordinary one.
    NotSupported,
    /// `bad_request` from a `klavd` older than `hold`: it has no gate,
    /// nothing asks. The connection stays.
    OlderKlavd,
    /// Another answer (kept for the report; the connection stays).
    Other,
}

/// The held connection's state, for the tests and the report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeldInfo {
    /// A connection is open.
    pub connected: bool,
    /// Counts the long connections opened: a new one, a new number.
    pub generation: u64,
    /// What `hold` answered on it.
    pub hold: HoldState,
    /// A `presence_required` waits for the master password on it.
    pub asking: bool,
}

/// How long a `presence_required` keeps the held connection for its
/// answer before another value may go on it.
const ASK_KEPT: Duration = Duration::from_secs(10 * 60);

/// The longest a call waits for the held connection while another call
/// (a Touch ID dialog, say) uses it, before it is told the app is busy.
pub(crate) const HELD_WAIT: Duration = Duration::from_secs(3);

/// `{declared, held}` of `hold`.
#[derive(Deserialize)]
struct HoldReply {
    #[serde(default)]
    #[allow(dead_code)]
    declared: bool,
    #[serde(default)]
    held: bool,
}

/// The one long connection (ADR 0041 §1.2): `hold` first, then `unlock`
/// and the window's values, one at a time. `klavd` keeps the last ask per
/// connection, and checks a password only as the answer to it on that same
/// connection (own choice 32), so a password is resent here and nowhere
/// else.
pub(crate) struct Held {
    pub(crate) client: Option<DaemonClient>,
    pub(crate) generation: u64,
    pub(crate) hold: HoldState,
    /// The request `klavd` answered `presence_required` for, without its
    /// password, and when.
    pending: Option<(Vec<u8>, Instant)>,
}

impl Held {
    pub(crate) const fn new() -> Self {
        Self {
            client: None,
            generation: 0,
            hold: HoldState::NotSent,
            pending: None,
        }
    }

    pub(crate) fn info(&self) -> HeldInfo {
        HeldInfo {
            connected: self.client.is_some(),
            generation: self.generation,
            hold: self.hold,
            asking: self.pending.is_some(),
        }
    }

    /// Forgets the connection: the next call opens a new one.
    pub(crate) fn drop_connection(&mut self) {
        self.client = None;
        self.hold = HoldState::NotSent;
        self.pending = None;
    }

    /// Forgets the ask (the app closed its password window).
    pub(crate) fn forget_ask(&mut self) {
        self.pending = None;
    }

    fn pending_for(&mut self, body: &[u8]) -> Option<bool> {
        if self
            .pending
            .as_ref()
            .is_some_and(|(_, at)| at.elapsed() > ASK_KEPT)
        {
            self.pending = None;
        }
        self.pending.as_ref().map(|(asked, _)| asked == body)
    }

    /// A new connection to `klavd`, with `hold` as its first request.
    pub(crate) async fn open(&mut self, home: &klav_client::Home) -> KlavResult<()> {
        self.drop_connection();
        let mut client = DaemonClient::connect(home)
            .await
            .ok_or_else(crate::daemon::not_running)?;
        self.generation += 1;
        self.hold = match client.call::<HoldReply>(Request::Hold).await {
            Ok((reply, _)) => HoldState::Declared { held: reply.held },
            Err(e) if e.code == ErrorCode::NotSupported => HoldState::NotSupported,
            // An older `klavd` refuses the unknown request and keeps the
            // connection: it has no gate, so nothing was granted (§1.2).
            Err(e) if e.code == ErrorCode::BadRequest => HoldState::OlderKlavd,
            Err(e) if gone(&e) => return Err(crate::daemon::daemon_error(e)),
            Err(_) => HoldState::Other,
        };
        self.client = Some(client);
        Ok(())
    }

    /// The connection, opened (with `hold`) when there is none.
    pub(crate) async fn connected(
        &mut self,
        home: &klav_client::Home,
    ) -> KlavResult<&mut DaemonClient> {
        if self.client.is_none() {
            self.open(home).await?;
        }
        self.client.as_mut().ok_or_else(crate::daemon::not_running)
    }

    /// Sends a request that may meet the gate, built by `make` with or
    /// without the master password. The password goes only as the answer
    /// to the ask `klavd` sent on this connection for this same request;
    /// otherwise it is dropped and the request goes without it, so
    /// `klavd` asks again with its own words. A connection that closed is
    /// opened again (with `hold`) once.
    pub(crate) async fn value<R: serde::de::DeserializeOwned>(
        &mut self,
        home: &klav_client::Home,
        make: &(dyn Fn(Option<SecretText>) -> Request + Sync),
        password: Option<String>,
    ) -> KlavResult<(R, Vec<String>)> {
        let password = password.map(zeroize::Zeroizing::new);
        let body = serde_json::to_vec(&make(None))
            .map_err(|e| KlavError::invalid(format!("cannot write the request: {e}")))?;
        let password = match (self.pending_for(&body), password) {
            (Some(true), Some(password)) => Some(password),
            // Another value's question is open: this one would replace
            // `klavd`'s ask, and that question's password would no longer
            // be checked.
            (Some(false), _) => return Err(waiting_for_password()),
            // Not asked on this connection: never sent.
            (None | Some(true), _) => None,
        };
        let resend = password.is_some();
        let request = || make(password.as_ref().map(|p| SecretText::new(p.as_str())));
        let mut answer = self.send::<R>(home, request()).await;
        if let Err(e) = &answer
            && gone(e)
        {
            // `klavd` restarted, or the connection dropped. The ask went
            // with it: a password is not sent again on another connection.
            self.drop_connection();
            answer = self.send::<R>(home, make(None)).await;
        }
        drop(password);
        match answer {
            Ok(ok) => {
                self.pending = None;
                Ok(ok)
            }
            Err(e) if e.code == ErrorCode::PresenceRequired => {
                self.pending = Some((body, Instant::now()));
                Err(crate::daemon::daemon_error(e))
            }
            // `klavd` took its ask off the connection when the password
            // came: a wrong one, or another password check running. Asked
            // again here, with nothing, so the person's next try answers
            // it: on a Mac where Touch ID can't confirm, `klavd` only asks.
            Err(e)
                if resend
                    && (e.code == ErrorCode::WrongCredentials
                        || e.code == ErrorCode::PresenceBusy
                        || (e.code == ErrorCode::Conflict
                            && e.message.starts_with(PASSWORD_CHECK_RUNNING))) =>
            {
                self.pending = None;
                if let Err(again) = self.send::<serde::de::IgnoredAny>(home, make(None)).await
                    && again.code == ErrorCode::PresenceRequired
                {
                    self.pending = Some((body, Instant::now()));
                }
                Err(crate::daemon::sent_error(e, resend))
            }
            Err(e) => {
                self.pending = None;
                Err(crate::daemon::sent_error(e, resend))
            }
        }
    }

    async fn send<R: serde::de::DeserializeOwned>(
        &mut self,
        home: &klav_client::Home,
        request: Request,
    ) -> Result<(R, Vec<String>), ErrorBody> {
        let client = match self.connected(home).await {
            Ok(c) => c,
            Err(_) => return Err(closed()),
        };
        client.call::<R>(request).await
    }
}

/// The socket closed or never answered (the client's own errors).
pub(crate) fn gone(e: &ErrorBody) -> bool {
    e.code == ErrorCode::Internal && e.message.starts_with("klavd c")
}

fn closed() -> ErrorBody {
    ErrorBody {
        code: ErrorCode::Internal,
        message: "klavd closed the connection".into(),
        paused: None,
        presence: None,
    }
}

/// Another value of this app waits for the master password.
pub(crate) fn waiting_for_password() -> KlavError {
    KlavError::PresenceBusy {
        password_check: false,
        in_this_app: true,
        message: "Klav is waiting for your master password for another value".into(),
    }
}

/// The start of `klavd`'s `conflict` when another master password is being
/// checked, with the gate off (own choice 18; `docs/klavd.md` §3).
pub(crate) const PASSWORD_CHECK_RUNNING: &str = "klavd is checking another master password";

/// The start of `klavd`'s `conflict` when the item changed between the ask
/// and the hand-out (Omar's decision F of 2026-11-19; `docs/klavd.md` §3).
pub(crate) const CHANGED_WHILE_CONFIRMING: &str = "the item changed while you confirmed";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_old_passkey_warning_is_a_flag_and_the_rest_stay_lines() {
        let o = UnlockOutcome::of(
            true,
            vec![
                "Klav no longer reads your old passkey setting: passkeys now ask every time. Choose again in the extension's settings".into(),
                "offline\nsecond line".into(),
            ],
        );
        assert!(o.already_unlocked && o.passkey_setting_reset);
        assert_eq!(o.warnings.len(), 1);
        assert!(!o.warnings[0].contains('\n'), "{:?}", o.warnings);
    }

    #[test]
    fn an_unlock_question_from_an_older_or_gate_off_klavd_says_nothing_new() {
        let q = UnlockQuestionInfo::of(None);
        assert!(!q.gate && !q.elsewhere && q.lasts.is_none());
        let q = UnlockQuestionInfo::of(Some(StatusPresence {
            elsewhere: true,
            key: PresenceKey::Connection,
            terminal: None,
            declared: true,
            lasts: Some(AskLasts::UntilLock),
        }));
        assert!(q.gate && q.elsewhere && q.declared);
        assert_eq!(q.lasts, Some(PresenceLasts::UntilLock));
    }

    #[test]
    fn an_asks_title_is_one_cleaned_line() {
        let ask = PresenceAsk {
            key: PresenceKey::None,
            window: Window::Always,
            terminal: Some("ttys003".into()),
            declared: false,
            lasts: None,
            value: Some(AskValue {
                kind: AskValueKind::Code,
                title: Some("Git\u{1b}[2JHub\u{202e}\nx".into()),
                count: None,
            }),
            browser: None,
        };
        let info = PresenceAskInfo::from(ask);
        let title = info.value.and_then(|v| v.title).expect("title");
        assert!(
            !title.contains('\u{1b}') && !title.contains('\u{202e}') && !title.contains('\n'),
            "{title:?}"
        );
        assert_eq!(info.key, PresenceKeyKind::NoWindow);
        assert_eq!(info.window, PresenceSetting::Always);
    }

    #[test]
    fn the_setting_round_trips() {
        for s in [
            PresenceSetting::Always,
            PresenceSetting::FiveMinutes,
            PresenceSetting::WhileUnlocked,
        ] {
            assert_eq!(PresenceSetting::from(Window::from(s)), s);
        }
    }
}
