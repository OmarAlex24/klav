//! Presence before `klavd` hands out a value (ADR 0041, layer 3): the
//! CLI's side of the gate that `klavd --presence-gate` turns on.
//!
//! - **Whether the gate is on** comes from `status` (`presence`), which the
//!   CLI reads anyway before it uses `klavd`. A `klavd` that sends none has
//!   the gate off or is older, and the CLI does what it did before.
//! - **Who asks.** With Touch ID, `klavd` shows the dialog itself and the
//!   request waits for it; just before, `klavd` sends a notice and the CLI
//!   prints its terminal's name (Omar's decision 2 of 2026-11-19). Without
//!   it (Linux, a Mac without Touch ID or with it off), `klavd` answers
//!   `presence_required`, and `klav` asks for the master password on its
//!   **controlling terminal** (`/dev/tty`), as the terminal's foreground
//!   job, never on stdin, and sends the request once more with it. With no
//!   terminal it stops with [`EXIT_NO_TERMINAL`].
//! - **What a password grants** is what `klavd`'s ask says, in the CLI's
//!   words, and `klavd` grants no more: it checks the password only if it
//!   would still ask exactly that (layer 3's review, finding 2).
//! - **The terminal's name** goes before the question, read the way `klavd`
//!   reads a peer's and named with its conversion
//!   ([`klav_daemon::peer::own_terminal`], [`klav_daemon::peer::terminal_name`]),
//!   so the person can compare it with the name in what `klavd` grants.
//! - **`presence_busy`** gets the CLI's own words: from what it sent, it
//!   knows which of `klavd`'s reasons it is.
//! - **`klavd`'s own words** that this module prints (the refusals of the
//!   gate's requests, and the warnings of the calls made through it) go
//!   through [`said`], so a program that isn't the real `klavd` can't write
//!   control sequences to the terminal there. Not all of `klavd`'s text is
//!   cleaned: the warnings of every other call (`backend.rs`), every
//!   `klavd` error message (`error.rs`), the warnings of `log reset` and a
//!   refusal `proxy use` reads from `status` (`commands/log.rs`,
//!   `commands/proxy.rs`) still print as they came, with the gate on too
//!   (the ADR's own choice 41 lists them).

use std::io::{Read, Write};

use klav_client::ops::SecretText;
use klav_daemon::client::{self, DaemonClient};
use klav_daemon::protocol::{
    AskLasts, AskValue, AskValueKind, DaemonStatus, ErrorBody, ErrorCode, Notice, PresenceAsk,
    PresenceKey, Request, StatusPresence,
};
use klav_daemon::uv::Window;
use serde::de::DeserializeOwned;
use zeroize::Zeroizing;

use crate::error::{CliError, CliResult, EXIT_NO_TERMINAL};
use crate::output;

/// How many times one command asks for the master password for a value:
/// once, and once more only when `klavd` asks something else instead of
/// checking the first (the ADR's own choice 33).
const MOST_QUESTIONS: usize = 2;

/// Longest master password the terminal question reads, in bytes.
const MAX_PASSWORD: usize = 1024;

/// Whether `klavd`'s `status` says the presence gate is on.
pub(crate) fn gate_on(status: &DaemonStatus) -> bool {
    status.presence.is_some()
}

/// `klavd`'s own words, cleaned for the terminal: no control or invisible
/// characters, one line, and short. Text with none of those, and not too
/// long, comes back unchanged, so the real `klavd`'s messages print exactly
/// as before (the ADR's own choice 41).
pub(crate) fn said(text: &str) -> String {
    const MAX: usize = 1000;
    if text.chars().count() <= MAX && !text.chars().any(klav_core::text::is_hidden) {
        return text.to_owned();
    }
    klav_core::text::shown(text, MAX)
}

/// The name of this process's controlling terminal, as `klavd` would give
/// it, when it has one and it can be named.
fn own_terminal_name() -> Option<String> {
    klav_daemon::peer::own_terminal().and_then(klav_daemon::peer::terminal_name)
}

/// "the terminal ttys003", or "a terminal" when it can't be named: the
/// words of `klavd`'s prompt (`docs/klavd.md` §6.1; the ADR's own choice 2
/// for the fallback).
fn terminal_words(name: Option<&str>) -> String {
    match name.filter(|n| plain_name(n)) {
        Some(name) => format!("the terminal {name}"),
        None => "a terminal".to_owned(),
    }
}

/// What this process calls its own controlling terminal.
pub(crate) fn this_terminal() -> String {
    terminal_words(own_terminal_name().as_deref())
}

/// The line before a Touch ID dialog `klavd` shows for this terminal: an
/// unlock's, or a value's after `klavd`'s notice (ADR 0041 §2.4, N9).
pub(crate) fn touch_id_line() -> String {
    // With no controlling terminal, "this program", as for an unlock that
    // gave nothing (the ADR's own choice 30).
    let whom = match klav_daemon::peer::own_terminal() {
        Some(_) => this_terminal(),
        None => "this program".to_owned(),
    };
    format!("klav: Touch ID for {whom}")
}

/// A terminal's name that may be printed: what `klavd` itself allows
/// (letters, digits and `/._-`, up to 32 bytes). Anything else, from a
/// `klavd` that isn't the real one, is not printed.
fn plain_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 32
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/._-".contains(&b))
}

/// An item's title from `klavd`, cleaned and quoted as `klavd`'s English
/// prompts quote it.
fn quoted(title: &str) -> String {
    let clean = klav_core::text::shown(title, 40).replace(['“', '”', '"'], "'");
    if clean.is_empty() {
        "(no name)".to_owned()
    } else {
        format!("“{clean}”")
    }
}

/// The one value an ask names, in the CLI's words: the kind `klavd` sent and
/// the title it resolved (layer 3's review, finding 6: one language).
fn value_words(value: Option<&AskValue>) -> String {
    let Some(value) = value else {
        return "have this value".to_owned();
    };
    let title = value.title.as_deref().map(quoted);
    match (value.kind, title) {
        (AskValueKind::Show, Some(t)) => format!("show the values of {t}"),
        (AskValueKind::Previous, Some(t)) => format!("show a previous password of {t}"),
        (AskValueKind::Code, Some(t)) => format!("show the code of {t}"),
        (AskValueKind::Fill, Some(t)) => format!("fill {t} in a browser"),
        (
            AskValueKind::Show | AskValueKind::Previous | AskValueKind::Code | AskValueKind::Fill,
            None,
        ) => "show a value from your vault".to_owned(),
        (AskValueKind::Generated, _) => "show a password you generated".to_owned(),
        (AskValueKind::Resolve, _) => match value.count {
            Some(1) => "use a value from your vault in a command".to_owned(),
            Some(n) => format!("use {n} values from your vault in a command"),
            None => "use values from your vault in a command".to_owned(),
        },
    }
}

/// Who a window is for, from the key `klavd` named.
fn who_words(key: PresenceKey, declared: bool, terminal: Option<&str>) -> String {
    if declared {
        return "the program that asked".to_owned();
    }
    match key {
        PresenceKey::Session => terminal_words(terminal),
        PresenceKey::Parent => "a program with no terminal".to_owned(),
        PresenceKey::Connection | PresenceKey::None => "this connection".to_owned(),
    }
}

/// How long a window lasts.
fn lasts_words(lasts: AskLasts) -> &'static str {
    match lasts {
        AskLasts::FiveMinutes => "for 5 minutes",
        AskLasts::UntilLock => "until Klav locks",
    }
}

/// What the verification grants, as `klavd`'s ask says it (ADR 0041 §2.4):
/// a window for a key, or one value. The words follow `lasts`, which is
/// what `klavd` binds the password to, never the setting or the key alone
/// (layer 3's review, finding 4).
pub(crate) fn grant(ask: Option<&PresenceAsk>) -> String {
    let Some(ask) = ask else {
        return "It lets klav have this value.".to_owned();
    };
    match ask.lasts {
        Some(lasts) => format!(
            "It lets {} use your vault {}.",
            who_words(ask.key, ask.declared, ask.terminal.as_deref()),
            lasts_words(lasts)
        ),
        None => format!(
            "It lets klav {}, this once.",
            value_words(ask.value.as_ref())
        ),
    }
}

/// What a master password typed for `unlock` opens, from `status`'s
/// `presence` (layer 3's review, finding 1). With no `lasts`, none: also at
/// the first unlock since `klavd` started, when it can't read the setting
/// (Omar's decision A of 2026-11-19), so the next value asks.
pub(crate) fn unlock_grant(presence: &StatusPresence) -> String {
    match presence.lasts {
        Some(lasts) => format!(
            "It unlocks Klav, and lets {} use your vault {}.",
            who_words(
                presence.key,
                presence.declared,
                presence.terminal.as_deref()
            ),
            lasts_words(lasts)
        ),
        None => "It unlocks Klav, and opens no window: the next value asks for your presence."
            .to_owned(),
    }
}

/// The window an unlock's question said it opens, as `klavd` reads it back
/// in the envelope's `shown` (`always`: none).
pub(crate) fn unlock_shown(presence: &StatusPresence) -> Window {
    match presence.lasts {
        None => Window::Always,
        Some(AskLasts::FiveMinutes) => Window::FiveMinutes,
        Some(AskLasts::UntilLock) => Window::Unlocked,
    }
}

/// What the CLI writes on the terminal before it reads the password: this
/// terminal's name, what the password is for, and the question.
fn question(own: &str, purpose: &str, email: Option<&str>) -> String {
    let asks = match email {
        Some(email) => format!(
            "Master password for {}: ",
            klav_core::text::shown(email, 120)
        ),
        None => "Master password: ".to_owned(),
    };
    format!("klav: master password for {own}\n{purpose}\n{asks}")
}

/// What the master password is asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Need {
    /// A value, or the window that hands it out.
    Value,
    /// Loosening the presence setting.
    Setting,
}

/// The refusal when there is no terminal to ask on: its own exit code,
/// and what to do.
pub(crate) fn no_terminal(need: Need) -> CliError {
    let message = match need {
        Need::Value => {
            "Klav needs your presence before it hands out this value, and klav has no terminal \
             to ask for the master password on"
        }
        Need::Setting => {
            "Loosening the presence setting needs your presence, and klav has no terminal to \
             ask for the master password on"
        }
    };
    CliError::Coded {
        code: EXIT_NO_TERMINAL,
        error: None,
        message: message.to_owned(),
        next: Some(
            "run the command from a terminal, where klav asks for it. It never reads it from \
             stdin for this: `--password-stdin` doesn't count as presence"
                .to_owned(),
        ),
    }
}

/// Why the terminal question gave no password.
#[derive(Debug)]
pub(crate) enum Unasked {
    /// No controlling terminal, or `klav` isn't its foreground job.
    NoTerminal,
    /// The person pressed Ctrl-C, or Ctrl-D on an empty line.
    Canceled,
    /// The line went past [`MAX_PASSWORD`] bytes: refused whole, read to its
    /// end, and nothing queued after it left for the shell.
    TooLong,
    /// Reading or setting up the terminal failed.
    Failed(String),
}

/// Puts the terminal back as it was when dropped: after Enter, Ctrl-C, an
/// error or a panic alike (layer 3's review, finding 8).
struct Restore {
    tty: std::fs::File,
    saved: nix::sys::termios::Termios,
}

impl Drop for Restore {
    fn drop(&mut self) {
        let _ = nix::sys::termios::tcsetattr(
            &self.tty,
            nix::sys::termios::SetArg::TCSANOW,
            &self.saved,
        );
        let _ = self.tty.write_all(b"\n");
    }
}

/// Reads one line without echo on this process's controlling terminal,
/// after writing `prompt` there. Only as the terminal's foreground job: a
/// background job, or no terminal at all, is [`Unasked::NoTerminal`].
/// Ctrl-C and Ctrl-D reach it as characters (`ISIG` off), so the question
/// ends, and the terminal is restored, before `klav` stops. What was typed
/// before the question is thrown away first (type-ahead, the second review
/// of layer 3, finding 8), and only then is the question written: what the
/// person types once they see it is kept.
pub(crate) fn read_on_terminal(prompt: &str) -> Result<Zeroizing<String>, Unasked> {
    use nix::sys::termios::{self, FlushArg, LocalFlags, SetArg, SpecialCharacterIndices};
    let tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|_| Unasked::NoTerminal)?;
    // Only the foreground job reads the terminal: a background one would
    // compete with whatever is in front, and be stopped by the kernel.
    match nix::unistd::tcgetpgrp(&tty) {
        Ok(front) if front == nix::unistd::getpgrp() => {}
        _ => return Err(Unasked::NoTerminal),
    }
    let failed = |e: &dyn std::fmt::Display| Unasked::Failed(format!("the terminal: {e}"));
    let saved = termios::tcgetattr(&tty).map_err(|e| failed(&e))?;
    let mut quiet = saved.clone();
    quiet
        .local_flags
        .remove(LocalFlags::ECHO | LocalFlags::ECHONL | LocalFlags::ICANON | LocalFlags::ISIG);
    quiet.control_chars[SpecialCharacterIndices::VMIN as usize] = 1;
    quiet.control_chars[SpecialCharacterIndices::VTIME as usize] = 0;
    let mut out = tty.try_clone().map_err(|e| failed(&e))?;
    let restore = Restore {
        tty: tty.try_clone().map_err(|e| failed(&e))?,
        saved,
    };
    termios::tcsetattr(&tty, SetArg::TCSANOW, &quiet).map_err(|e| failed(&e))?;
    termios::tcflush(&tty, FlushArg::TCIFLUSH).map_err(|e| failed(&e))?;
    out.write_all(prompt.as_bytes()).map_err(|e| failed(&e))?;
    let line = read_line(&tty);
    // A line refused for its length was read to its end; what is still
    // queued after it (the rest of a paste) is thrown away while echo is
    // still off, so none of it reaches the shell once the terminal is back.
    if matches!(line, Err(Unasked::TooLong)) {
        let _ = termios::tcflush(&tty, FlushArg::TCIFLUSH);
    }
    drop(restore);
    line
}

/// Where the reader is in an escape sequence a key sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Escape {
    /// Not in one.
    No,
    /// After ESC.
    Start,
    /// After ESC `[` (CSI): parameters and intermediates up to a final byte.
    Csi,
    /// After ESC `O` (SS3): parameters, as some terminals send for a
    /// modified key (ESC `O 5 D`), up to a final byte.
    Ss3,
}

/// The line being typed, in a buffer of fixed size that is made empty and
/// never moved once a byte is in it (every method borrows it), so no copy
/// of the password is left behind; zeroed on drop, and every byte erased is
/// zeroed as it goes.
struct Typed {
    bytes: Zeroizing<[u8; MAX_PASSWORD]>,
    len: usize,
}

impl Typed {
    fn new() -> Self {
        Typed {
            bytes: Zeroizing::new([0; MAX_PASSWORD]),
            len: 0,
        }
    }

    /// Adds `byte`; `false`, with nothing added, once the buffer is full.
    #[must_use]
    fn push(&mut self, byte: u8) -> bool {
        let Some(slot) = self.bytes.get_mut(self.len) else {
            return false;
        };
        *slot = byte;
        self.len += 1;
        true
    }

    /// The last byte, zeroed and taken off.
    fn pop(&mut self) -> Option<u8> {
        let last = self.len.checked_sub(1)?;
        let byte = std::mem::take(&mut self.bytes[last]);
        self.len = last;
        Some(byte)
    }

    fn last(&self) -> Option<u8> {
        self.len.checked_sub(1).map(|i| self.bytes[i])
    }

    /// Backspace: the last character, all of its UTF-8 bytes.
    fn erase_char(&mut self) {
        while let Some(byte) = self.pop() {
            if byte & 0xC0 != 0x80 {
                break;
            }
        }
    }

    /// Ctrl-W: the blanks before the cursor, then the word before them, as
    /// a terminal's `werase` does.
    fn erase_word(&mut self) {
        let blank = |b: u8| b == b' ' || b == b'\t';
        while self.last().is_some_and(blank) {
            self.pop();
        }
        while self.last().is_some_and(|b| !blank(b)) {
            self.pop();
        }
    }

    /// Ctrl-U: everything.
    fn erase_all(&mut self) {
        while self.pop().is_some() {}
    }

    /// The line as text: a copy into a `Zeroizing` string, read in place;
    /// this buffer is zeroed when dropped.
    fn text(&self) -> Result<Zeroizing<String>, Unasked> {
        let bytes = self.bytes[..self.len].to_vec();
        String::from_utf8(bytes).map(Zeroizing::new).map_err(|e| {
            drop(Zeroizing::new(e.into_bytes()));
            Unasked::Failed("the terminal sent text that isn't UTF-8".into())
        })
    }
}

/// The bytes typed up to Enter, edited as a terminal would (the second
/// review of layer 3, finding 8):
///
/// - Every printable character goes in, Tab and UTF-8 included.
/// - Backspace (DEL or Ctrl-H) erases a character, Ctrl-U the line, Ctrl-W
///   a word; erased bytes are zeroed.
/// - The escape sequences keys send never go in: ESC `[` up to its final
///   byte (arrows, Home, Delete, function keys, a paste's brackets), ESC `O`
///   up to its final byte (an arrow, or a modified one: ESC `O 5 D`), and
///   ESC with a printable ASCII byte (Alt and a key). A lone ESC goes
///   nowhere and takes the printable ASCII byte after it with it, as Alt
///   and that key would: a password typed with ESC in it loses a character
///   and fails, never gains one. A control character after ESC (Enter,
///   Ctrl-C) still counts as itself.
/// - Ctrl-C, and Ctrl-D on an empty line, cancel; other control characters
///   are dropped.
/// - A line past [`MAX_PASSWORD`] bytes is refused whole
///   ([`Unasked::TooLong`]), but only at its end (Enter, Ctrl-C, or the
///   terminal closing): every byte up to there is read and dropped, so none
///   of it is left for the shell. What was kept is zeroed at once.
fn read_line(mut tty: impl Read) -> Result<Zeroizing<String>, Unasked> {
    let mut line = Typed::new();
    let mut escape = Escape::No;
    let mut too_long = false;
    let mut byte = [0u8; 1];
    loop {
        match tty.read(&mut byte) {
            Ok(0) if too_long => return Err(Unasked::TooLong),
            Ok(0) => return Err(Unasked::Canceled),
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(Unasked::Failed(format!("the terminal: {e}"))),
        }
        let b = std::mem::take(&mut byte[0]);
        if too_long {
            match b {
                b'\r' | b'\n' | 0x03 => return Err(Unasked::TooLong),
                _ => continue,
            }
        }
        let printable = (0x20..=0x7e).contains(&b);
        match escape {
            Escape::No => {}
            Escape::Start if b == b'[' => {
                escape = Escape::Csi;
                continue;
            }
            Escape::Start if b == b'O' => {
                escape = Escape::Ss3;
                continue;
            }
            Escape::Start if b == 0x1b => continue,
            Escape::Csi | Escape::Ss3 if (0x20..=0x3f).contains(&b) => continue,
            Escape::Start | Escape::Csi | Escape::Ss3 if printable => {
                escape = Escape::No;
                continue;
            }
            // A control character, or a byte past ASCII, ends it and counts
            // as itself.
            Escape::Start | Escape::Csi | Escape::Ss3 => escape = Escape::No,
        }
        match b {
            b'\r' | b'\n' => break,
            // Ctrl-C; Ctrl-D on an empty line.
            0x03 => return Err(Unasked::Canceled),
            0x04 if line.len == 0 => return Err(Unasked::Canceled),
            0x1b => escape = Escape::Start,
            0x7f | 0x08 => line.erase_char(),
            0x15 => line.erase_all(),
            0x17 => line.erase_word(),
            // Other control characters, Ctrl-Z and Ctrl-\ among them.
            b if b < 0x20 && b != b'\t' => {}
            b => {
                if !line.push(b) {
                    line.erase_all();
                    too_long = true;
                }
            }
        }
    }
    line.text()
}

/// The master password, asked on this process's controlling terminal and
/// nowhere else; with no terminal, `none` is the error.
fn ask_password(
    purpose: &str,
    email: Option<&str>,
    none: impl FnOnce() -> CliError,
) -> CliResult<Zeroizing<String>> {
    read_on_terminal(&question(&this_terminal(), purpose, email)).map_err(|e| match e {
        Unasked::NoTerminal => none(),
        Unasked::Canceled => CliError::Other("canceled: no master password was sent".into()),
        Unasked::TooLong => CliError::Other(format!(
            "the master password is longer than {MAX_PASSWORD} bytes: nothing was sent"
        )),
        Unasked::Failed(why) => {
            CliError::Other(format!("cannot ask for the master password: {why}"))
        }
    })
}

/// The master password for an `unlock` with the gate on, asked as every
/// other question of the gate is (layer 3's review, finding 1): this
/// terminal's name, and what it opens. With no terminal, the error
/// `prompt_hidden` gives, as before.
pub(crate) fn unlock_password(
    presence: &StatusPresence,
    email: &str,
) -> CliResult<Zeroizing<String>> {
    ask_password(&unlock_grant(presence), Some(email), || {
        crate::error::usage(
            "no terminal to ask for the master password; pipe it on stdin (see --password-stdin)",
        )
    })
}

/// The master password for an operation that already asks (`klavd`'s own
/// Touch ID failed or isn't there), with the gate on: it confirms that one
/// action and opens no window.
pub(crate) fn confirm_password(email: &str) -> CliResult<Zeroizing<String>> {
    ask_password(
        "It confirms this one action, and opens no window.",
        Some(email),
        || {
            crate::error::usage(
                "no terminal to ask for the master password; pipe it on stdin (see \
                 --password-stdin)",
            )
        },
    )
}

/// Why `klavd` answered `presence_busy`, as the CLI can tell from what it
/// sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Busy {
    /// Sent without a password: an open Touch ID dialog.
    Dialog,
    /// Sent with the master password: another password being checked.
    Password,
    /// A change of the setting: a dialog, or another change.
    Setting,
}

/// The CLI's words for `presence_busy` (`docs/klavd.md` §3, the gate).
pub(crate) fn busy_text(busy: Busy) -> &'static str {
    match busy {
        Busy::Dialog => {
            "another program is asking for Touch ID in Klav: try again once that dialog closes"
        }
        Busy::Password => "klavd is checking another master password: try again in a moment",
        Busy::Setting => {
            "another Touch ID dialog, password check or change of the setting is running in \
             Klav: try again once it ends"
        }
    }
}

/// `klavd`'s refusal, with the CLI's words for `presence_busy`. Any other
/// code keeps `klavd`'s message, cleaned (with the gate off, a password
/// check that finds another one running is `conflict`, whose message says
/// so).
pub(crate) fn refused(e: ErrorBody, busy: Busy) -> CliError {
    let message = if e.code == ErrorCode::PresenceBusy {
        busy_text(busy).to_owned()
    } else {
        said(&e.message)
    };
    CliError::Daemon(ErrorBody { message, ..e })
}

/// A request that hands out a value (ADR 0041 §3, the «window» row): sent
/// as is; when `klavd` answers `presence_required`, the master password is
/// asked on the terminal, in the words of `klavd`'s ask, and the request
/// goes once more with it. If `klavd` then asks something else (the setting
/// or the item changed in between), it didn't check the password, and the
/// CLI asks once more with the new words ([`MOST_QUESTIONS`]). Any other
/// refusal is the answer (`wrong_credentials` for a wrong password).
pub(crate) async fn value_call<R: DeserializeOwned>(
    client: &mut DaemonClient,
    request: impl Fn(Option<SecretText>) -> Request,
) -> CliResult<R> {
    // A notice only from a `klavd` that said the gate is on: an older one
    // refuses the field.
    let presence = client::Presence {
        notify: client.presence_gate(),
        shown: None,
        untyped: false,
    };
    let mut notice = |n: Notice| match n {
        Notice::TouchId => output::info(&touch_id_line()),
    };
    let mut ask = match client
        .call_presence::<R>(request(None), presence, &mut notice)
        .await
    {
        Ok((value, warnings)) => {
            warn_all(&warnings);
            return Ok(value);
        }
        Err(e) if e.code == ErrorCode::PresenceRequired => e.presence,
        Err(e) => return Err(refused(e, Busy::Dialog)),
    };
    let email = account_email(client).await;
    for asked in 1..=MOST_QUESTIONS {
        let password = ask_password(&grant(ask.as_deref()), email.as_deref(), || {
            no_terminal(Need::Value)
        })?;
        let answer = client
            .call_presence::<R>(
                request(Some(SecretText::new(password.as_str()))),
                presence,
                &mut notice,
            )
            .await;
        drop(password);
        match answer {
            Ok((value, warnings)) => {
                warn_all(&warnings);
                return Ok(value);
            }
            // Not checked: `klavd` asks something else now.
            Err(e) if e.code == ErrorCode::PresenceRequired && asked < MOST_QUESTIONS => {
                output::warn(
                    "klavd asks for something else now (the setting or the item changed): \
                     your password wasn't used",
                );
                ask = e.presence;
            }
            Err(e) => return Err(refused(e, Busy::Password)),
        }
    }
    unreachable!("the last question returns")
}

/// A change of the presence setting that loosens it: Touch ID in `klavd`,
/// or, where it has none, the master password on the terminal.
pub(crate) async fn loosen(
    client: &mut DaemonClient,
    from: Window,
    to: Window,
) -> CliResult<serde_json::Value> {
    let change = |password| Request::PresenceWindow {
        window: Some(to),
        password,
    };
    let touch_id = client
        .call::<DaemonStatus>(Request::Status)
        .await
        .is_ok_and(|(status, _)| status.touch_id.available);
    if touch_id {
        output::info(&format!(
            "Confirm with Touch ID to {}…",
            setting_change(from, to)
        ));
    }
    match client.call::<serde_json::Value>(change(None)).await {
        Ok((value, warnings)) => {
            warn_all(&warnings);
            return Ok(value);
        }
        // Touch ID canceled, or none to show: the master password.
        Err(e) if e.code == ErrorCode::BiometryFailed => {
            output::warn(&format!(
                "{}; confirm with the master password",
                said(&e.message)
            ));
        }
        Err(e) if e.code == ErrorCode::BiometryUnavailable => {}
        Err(e) => return Err(refused(e, Busy::Setting)),
    }
    let email = account_email(client).await;
    let purpose = format!("It confirms: {}.", setting_change(from, to));
    let password = ask_password(&purpose, email.as_deref(), || no_terminal(Need::Setting))?;
    let answer = client
        .call::<serde_json::Value>(change(Some(SecretText::new(password.as_str()))))
        .await;
    drop(password);
    let (value, warnings) = answer.map_err(|e| refused(e, Busy::Setting))?;
    warn_all(&warnings);
    Ok(value)
}

/// `klavd`'s words for a loosening (`docs/klavd.md` §6.1).
fn setting_change(from: Window, to: Window) -> String {
    format!(
        "ask for your presence {} instead of {}",
        window_words(to),
        window_words(from)
    )
}

/// How often a setting asks, in `klavd`'s words.
pub(crate) fn window_words(window: Window) -> &'static str {
    match window {
        Window::Always => "for every value",
        Window::FiveMinutes => "every 5 minutes",
        Window::Unlocked => "once until Klav locks",
    }
}

/// What the person reads when their `unlock` found `klavd` unlocked by
/// another key and sent no password (Omar's decision on Q-N1). "this
/// program" with no controlling terminal (the ADR's own choice 30).
pub(crate) fn already_unlocked_text() -> String {
    already_unlocked_words(klav_daemon::peer::own_terminal().is_some())
}

fn already_unlocked_words(terminal: bool) -> String {
    let what = if terminal {
        "this terminal"
    } else {
        "this program"
    };
    format!(
        "Klav was already unlocked elsewhere; this unlock gave {what} nothing. If you didn't \
         unlock it, lock Klav (`klav lock`)"
    )
}

/// The account's email, for the question, from `klavd`.
async fn account_email(client: &mut DaemonClient) -> Option<String> {
    client
        .call::<DaemonStatus>(Request::Status)
        .await
        .ok()
        .and_then(|(status, _)| status.email)
}

/// `klavd`'s warnings, cleaned.
pub(crate) fn warn_all(warnings: &[String]) {
    for w in warnings {
        output::warn(&said(w));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ask(key: PresenceKey, lasts: Option<AskLasts>) -> PresenceAsk {
        PresenceAsk {
            key,
            window: Window::FiveMinutes,
            terminal: Some("pts/3".into()),
            declared: false,
            lasts,
            value: lasts.is_none().then(|| AskValue {
                kind: AskValueKind::Code,
                title: Some("GitHub".into()),
                count: None,
            }),
        }
    }

    #[test]
    fn the_grant_says_what_the_ask_grants_never_the_setting_alone() {
        let cases = [
            (
                PresenceKey::Session,
                Some(AskLasts::FiveMinutes),
                "It lets the terminal pts/3 use your vault for 5 minutes.",
            ),
            (
                PresenceKey::Session,
                Some(AskLasts::UntilLock),
                "It lets the terminal pts/3 use your vault until Klav locks.",
            ),
            (
                PresenceKey::Connection,
                Some(AskLasts::FiveMinutes),
                "It lets this connection use your vault for 5 minutes.",
            ),
            (
                PresenceKey::Parent,
                Some(AskLasts::UntilLock),
                "It lets a program with no terminal use your vault until Klav locks.",
            ),
            // An every-time ask with a 5-minute setting (a window already
            // open elsewhere, a busy key): one value, never a window.
            (
                PresenceKey::Session,
                None,
                "It lets klav show the code of “GitHub”, this once.",
            ),
            (
                PresenceKey::None,
                None,
                "It lets klav show the code of “GitHub”, this once.",
            ),
        ];
        for (key, lasts, text) in cases {
            assert_eq!(grant(Some(&ask(key, lasts))), text, "{key:?} {lasts:?}");
        }
        let mut declared = ask(PresenceKey::Session, Some(AskLasts::UntilLock));
        declared.declared = true;
        assert_eq!(
            grant(Some(&declared)),
            "It lets the program that asked use your vault until Klav locks."
        );
        // No `presence` object (a klavd that sent none): still a question,
        // with no claim about a window.
        assert_eq!(grant(None), "It lets klav have this value.");
    }

    #[test]
    fn each_kind_of_value_has_english_words_and_a_cleaned_title() {
        let value = |kind, title: Option<&str>, count| AskValue {
            kind,
            title: title.map(str::to_owned),
            count,
        };
        let cases = [
            (
                value(AskValueKind::Show, Some("Bank"), None),
                "show the values of “Bank”",
            ),
            (
                value(AskValueKind::Previous, Some("Bank"), None),
                "show a previous password of “Bank”",
            ),
            (
                value(AskValueKind::Fill, Some("Bank"), None),
                "fill “Bank” in a browser",
            ),
            (
                value(AskValueKind::Show, None, None),
                "show a value from your vault",
            ),
            (
                value(AskValueKind::Generated, None, None),
                "show a password you generated",
            ),
            (
                value(AskValueKind::Resolve, None, Some(1)),
                "use a value from your vault in a command",
            ),
            (
                value(AskValueKind::Resolve, None, Some(3)),
                "use 3 values from your vault in a command",
            ),
            // An escape sequence, a direction override and quotes in a
            // title never reach the terminal as such.
            (
                value(
                    AskValueKind::Code,
                    Some("Git\u{1b}[2JHub\u{202e}\"x\""),
                    None,
                ),
                "show the code of “Git [2JHub 'x'”",
            ),
            (
                value(AskValueKind::Code, Some("\u{1b}"), None),
                "show the code of (no name)",
            ),
        ];
        for (value, words) in cases {
            assert_eq!(value_words(Some(&value)), words, "{:?}", value.kind);
        }
    }

    #[test]
    fn an_unlock_question_says_what_the_password_opens() {
        let presence = |lasts| StatusPresence {
            elsewhere: false,
            key: PresenceKey::Session,
            terminal: Some("ttys003".into()),
            declared: false,
            lasts,
        };
        assert_eq!(
            unlock_grant(&presence(Some(AskLasts::FiveMinutes))),
            "It unlocks Klav, and lets the terminal ttys003 use your vault for 5 minutes."
        );
        assert_eq!(
            unlock_grant(&presence(None)),
            "It unlocks Klav, and opens no window: the next value asks for your presence."
        );
        assert_eq!(unlock_shown(&presence(None)), Window::Always);
        assert_eq!(
            unlock_shown(&presence(Some(AskLasts::FiveMinutes))),
            Window::FiveMinutes
        );
        assert_eq!(
            unlock_shown(&presence(Some(AskLasts::UntilLock))),
            Window::Unlocked
        );
    }

    #[test]
    fn a_terminal_klav_cant_name_or_shouldnt_print_is_a_terminal() {
        let mut unnamed = ask(PresenceKey::Session, Some(AskLasts::FiveMinutes));
        unnamed.terminal = None;
        assert_eq!(
            grant(Some(&unnamed)),
            "It lets a terminal use your vault for 5 minutes."
        );
        // An escape sequence from a klavd that isn't the real one never
        // reaches the terminal.
        unnamed.terminal = Some("pts/3\u{1b}[2J".into());
        assert_eq!(
            grant(Some(&unnamed)),
            "It lets a terminal use your vault for 5 minutes."
        );
        assert_eq!(terminal_words(Some("ttys003")), "the terminal ttys003");
        assert_eq!(terminal_words(None), "a terminal");
    }

    #[test]
    fn klavds_own_words_are_cleaned() {
        assert_eq!(said("bad\u{1b}]0;x\u{7}\nline"), "bad ]0;x line");
        // Plain text, even with double spaces, stays as klavd wrote it.
        assert_eq!(
            said("klavd is locked:  run `klav unlock`"),
            "klavd is locked:  run `klav unlock`"
        );
        let body = ErrorBody {
            code: ErrorCode::Locked,
            message: "locked\u{1b}[2J".into(),
            paused: None,
            presence: None,
        };
        assert_eq!(
            refused(body, Busy::Dialog).message().as_deref(),
            Some("locked [2J")
        );
    }

    #[test]
    fn the_question_names_this_terminal_before_it_asks() {
        let text = question(
            "the terminal pts/3",
            "It lets the terminal pts/3 use your vault for 5 minutes.",
            Some("ana@example.com"),
        );
        assert_eq!(
            text,
            "klav: master password for the terminal pts/3\n\
             It lets the terminal pts/3 use your vault for 5 minutes.\n\
             Master password for ana@example.com: "
        );
    }

    #[test]
    fn the_line_reader_edits_and_stops_like_a_terminal() {
        let read = |bytes: &[u8]| read_line(bytes).map(|s| s.as_str().to_owned());
        assert_eq!(read(b"secret\n").unwrap(), "secret");
        assert_eq!(read(b"secret\r").unwrap(), "secret");
        assert_eq!(read(b"secrex\x7ft\n").unwrap(), "secret");
        assert_eq!(read("ñu\x7f\x7fa\n".as_bytes()).unwrap(), "a");
        assert_eq!(read(b"wrong\x15secret\n").unwrap(), "secret");
        assert_eq!(read(b"se\x1acret\n").unwrap(), "secret");
        // The second review of layer 3, finding 8: Tab is a character of
        // the password; Ctrl-W erases a word, blanks first; Ctrl-H is
        // Backspace.
        assert_eq!(read(b"a\tb c\n").unwrap(), "a\tb c");
        assert_eq!(read(b"keep this  \x17that\n").unwrap(), "keep that");
        assert_eq!(read(b"one\ttwo\x17\x17x\n").unwrap(), "x");
        assert_eq!(read(b"ab\x08c\n").unwrap(), "ac");
        // Keys' escape sequences never go in: arrows (CSI and SS3), Home,
        // Delete, F5, Alt-x, a paste's brackets.
        assert_eq!(read(b"se\x1b[Acr\x1bOBet\n").unwrap(), "secret");
        assert_eq!(read(b"\x1b[Hsec\x1b[3~ret\x1b[15~\n").unwrap(), "secret");
        assert_eq!(read(b"sec\x1bxret\n").unwrap(), "secret");
        assert_eq!(read(b"\x1b[200~secret\x1b[201~\n").unwrap(), "secret");
        assert_eq!(read(b"sec\x1b[1;5Dret\n").unwrap(), "secret");
        // A lone ESC goes nowhere; Enter or Ctrl-C after it count.
        assert_eq!(read(b"secret\x1b\n").unwrap(), "secret");
        assert_eq!(read(b"secret\x1b\x1b\n").unwrap(), "secret");
        assert!(matches!(read(b"sec\x1b[\x03"), Err(Unasked::Canceled)));
        // A character past ASCII after ESC is itself.
        assert_eq!(read("\x1bñ\n".as_bytes()).unwrap(), "ñ");
        assert!(matches!(read(b"sec\x03ret\n"), Err(Unasked::Canceled)));
        assert!(matches!(read(b"\x04"), Err(Unasked::Canceled)));
        assert!(matches!(read(b"no newline"), Err(Unasked::Canceled)));
        assert!(matches!(read(b"\xff\n"), Err(Unasked::Failed(_))));
        // A modified arrow sent as SS3 with a parameter (ESC O 5 D): the
        // whole sequence is dropped, its final byte included.
        assert_eq!(read(b"sec\x1bO5Dret\n").unwrap(), "secret");
        assert_eq!(read(b"sec\x1bO1;5Cret\n").unwrap(), "secret");
        // A lone ESC takes the printable byte after it: the password loses
        // a character (it fails), never gains one.
        assert_eq!(read(b"sec\x1bXret\n").unwrap(), "secret");
        // Past the bound: refused whole, at the end of the line, whatever
        // ends it; never cut and sent.
        let long = vec![b'a'; MAX_PASSWORD + 1];
        assert!(matches!(read(&long), Err(Unasked::TooLong)));
        let mut pasted = vec![b'a'; MAX_PASSWORD + 500];
        pasted.extend_from_slice(b"\nnext line\n");
        let mut rest = pasted.as_slice();
        assert!(matches!(read_line(&mut rest), Err(Unasked::TooLong)));
        assert_eq!(rest, b"next line\n", "read to the end of its line");
        let mut canceled = vec![b'a'; MAX_PASSWORD + 1];
        canceled.push(0x03);
        assert!(matches!(read(&canceled), Err(Unasked::TooLong)));
        let mut exact = vec![b'a'; MAX_PASSWORD];
        exact.push(b'\n');
        assert_eq!(read(&exact).unwrap().len(), MAX_PASSWORD);
    }

    /// Every byte an edit erases is zeroed in the buffer at once, not left
    /// behind past the line's end.
    #[test]
    fn erased_bytes_are_zeroed_in_place() {
        let mut line = Typed::new();
        for &b in b"one two" {
            assert!(line.push(b));
        }
        line.erase_word();
        assert_eq!(&line.bytes[..line.len], b"one ");
        line.erase_char();
        assert!(line.push(b'x'));
        line.erase_all();
        assert_eq!(line.len, 0);
        assert!(line.bytes.iter().all(|&b| b == 0), "nothing left behind");
    }

    #[test]
    fn busy_is_said_by_what_was_sent_and_conflict_stays_klavds() {
        let body = |code, message: &str| ErrorBody {
            code,
            message: message.into(),
            paused: None,
            presence: None,
        };
        let busy = body(ErrorCode::PresenceBusy, "klavd's words");
        for (kind, words) in [
            (Busy::Dialog, "Touch ID"),
            (Busy::Password, "another master password"),
            (Busy::Setting, "change of the setting"),
        ] {
            let e = refused(busy.clone(), kind);
            assert_eq!(e.exit_code(), 1);
            assert!(e.message().unwrap().contains(words), "{kind:?}");
        }
        // The gate off: klavd answers `conflict` to a second password
        // check, and says so itself.
        let conflict = body(
            ErrorCode::Conflict,
            "klavd is checking another master password: try again in a moment",
        );
        let e = refused(conflict.clone(), Busy::Password);
        assert_eq!(e.message(), Some(conflict.message));
        assert_eq!(e.exit_code(), 1);
    }

    #[test]
    fn no_terminal_has_its_own_exit_code_and_says_what_to_do() {
        for need in [Need::Value, Need::Setting] {
            let e = no_terminal(need);
            assert_eq!(e.exit_code(), EXIT_NO_TERMINAL);
            let text = e.message().unwrap();
            assert!(text.contains("no terminal"), "{text}");
            assert!(
                text.contains("\nNext: run the command from a terminal"),
                "{text}"
            );
            assert!(text.contains("--password-stdin"), "{text}");
        }
    }

    #[test]
    fn already_unlocked_says_this_terminal_or_this_program() {
        assert!(already_unlocked_words(true).contains("gave this terminal nothing"));
        assert!(already_unlocked_words(false).contains("gave this program nothing"));
    }

    #[test]
    fn a_loosening_is_named_in_klavds_words() {
        assert_eq!(
            setting_change(Window::Always, Window::FiveMinutes),
            "ask for your presence every 5 minutes instead of for every value"
        );
        assert_eq!(
            setting_change(Window::FiveMinutes, Window::Unlocked),
            "ask for your presence once until Klav locks instead of every 5 minutes"
        );
    }
}
