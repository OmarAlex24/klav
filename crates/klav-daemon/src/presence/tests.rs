//! The gate's rules (ADR 0041, layer 2's test list), on the [`Presence`]
//! the server keeps, with a fake verifier and a mock clock. The wiring
//! through the socket, with the master password, is in
//! `tests/presence.rs`.

use std::cell::{Cell, RefCell};
use std::time::Duration;

use klav_core::ids::{AccountId, DeviceId};

use super::*;

const RIGHT: &str = "correct horse battery staple";

/// A verifier that counts prompts, says yes unless told otherwise, and
/// can run something while its "dialog" is open.
struct Fake<'a> {
    touch_id: bool,
    answer: Cell<bool>,
    prompts: RefCell<Vec<String>>,
    during: RefCell<Option<Box<dyn FnMut() + 'a>>>,
    /// How many master passwords it checked.
    checks: Cell<usize>,
}

impl<'a> Fake<'a> {
    fn new() -> Self {
        Fake {
            touch_id: true,
            answer: Cell::new(true),
            prompts: RefCell::new(Vec::new()),
            during: RefCell::new(None),
            checks: Cell::new(0),
        }
    }

    fn without_touch_id() -> Self {
        Fake {
            touch_id: false,
            ..Fake::new()
        }
    }

    fn while_open(&self, during: impl FnMut() + 'a) {
        *self.during.borrow_mut() = Some(Box::new(during));
    }

    fn asked(&self) -> usize {
        self.prompts.borrow().len()
    }

    fn last(&self) -> String {
        self.prompts.borrow().last().cloned().unwrap_or_default()
    }
}

impl Verify for Fake<'_> {
    fn touch_id_available(&self) -> bool {
        self.touch_id
    }

    fn touch_id(&self, reason: &str) -> Result<(), Refused> {
        self.prompts.borrow_mut().push(reason.to_owned());
        if let Some(during) = self.during.borrow_mut().as_mut() {
            during();
        }
        if self.answer.get() {
            Ok(())
        } else {
            Err(Refused::Failed(ErrorBody {
                code: ErrorCode::BiometryFailed,
                message: "canceled".into(),
                paused: None,
                presence: None,
            }))
        }
    }

    fn password(&self, password: SecretText) -> Result<(), ErrorBody> {
        self.checks.set(self.checks.get() + 1);
        if password.expose() == RIGHT {
            Ok(())
        } else {
            Err(ErrorBody {
                code: ErrorCode::WrongCredentials,
                message: "wrong".into(),
                paused: None,
                presence: None,
            })
        }
    }
}

/// A clock the test moves by hand.
struct Clock(Cell<Instant>);

impl Clock {
    fn new() -> Self {
        Clock(Cell::new(Instant::now()))
    }

    fn now(&self) -> Instant {
        self.0.get()
    }

    fn advance(&self, secs: u64) {
        self.0.set(self.0.get() + Duration::from_secs(secs));
    }
}

fn session(id: i32) -> Key {
    Key::Session(peer::Session {
        id,
        leader_start: peer::StartTime(7),
    })
}

fn caller(conn: u64, key: Key) -> Caller {
    Caller {
        conn,
        key,
        terminal: Some("ttys003".into()),
        source: Some(Source::Terminal),
        notify: None,
        untyped: false,
    }
}

/// The value every test asks for: the code of «GitHub».
fn code() -> AskValue {
    AskValue {
        kind: AskValueKind::Code,
        title: Some("GitHub".into()),
        count: None,
    }
}

const GEN: u64 = 1;

fn settings(presence: Window) -> Settings {
    Settings {
        presence,
        passkey: Window::Always,
    }
}

/// `klavd` unlocked by `by` (a password unlock: the window the setting
/// gives).
fn unlocked(presence: Window, by: &Caller, clock: &Clock) -> Presence {
    let p = Presence::default();
    p.open(
        GEN,
        settings(presence),
        by,
        Some(Window::Unlocked),
        true,
        false,
        clock.now(),
    );
    p
}

fn value(p: &Presence, who: &Caller, verify: &dyn Verify, clock: &Clock) -> Result<(), ErrorBody> {
    p.require(
        GEN,
        who,
        Purpose::Window { value: &code() },
        None,
        &Bound::default(),
        None,
        verify,
        Lang::En,
        &|| clock.now(),
    )
    .map(|passed| handed_out(p, who, passed, clock))
}

/// What the server does once the hand-out found what was asked about:
/// opens the window the answer stated (Omar's decision G of 2026-11-19).
fn handed_out(p: &Presence, who: &Caller, passed: Passed, clock: &Clock) {
    if let Some(opening) = passed.opens {
        p.open_window(who, opening, clock.now());
    }
}

/// The master password sent again for [`value`]'s request: checked only as
/// the answer to the ask `klavd` sent last on `who`'s connection.
fn with_password(
    p: &Presence,
    who: &Caller,
    password: &str,
    verify: &dyn Verify,
    clock: &Clock,
) -> Result<(), ErrorBody> {
    p.require(
        GEN,
        who,
        Purpose::Window { value: &code() },
        Some(SecretText::new(password)),
        &Bound::default(),
        None,
        verify,
        Lang::En,
        &|| clock.now(),
    )
    .map(|passed| handed_out(p, who, passed, clock))
}

#[test]
fn every_operation_of_the_table_has_its_row() {
    let pw = || None;
    let window = [
        Request::View {
            query: "GitHub".into(),
            reveal: true,
            password: pw(),
        },
        Request::PreviousPassword {
            query: "GitHub".into(),
            index: 0,
            password: pw(),
        },
        Request::Totp {
            query: "GitHub".into(),
            field: None,
            password: pw(),
        },
        Request::GeneratedValue {
            created_at: 1,
            password: pw(),
        },
        Request::Resolve {
            references: vec!["klav://a/b/c/password".into()],
            password: pw(),
        },
        Request::Autofill {
            item: "x".into(),
            url: "https://github.com".into(),
            part: klav_client::fill::FillPart::All,
            chosen: false,
            password: pw(),
        },
    ];
    for mut request in window {
        assert_eq!(gate(&request), Gate::Window, "{request:?}");
        // The gate's password comes out of each, and the operation never
        // sees it.
        set_password(&mut request);
        assert!(take_password(&mut request).is_some(), "{request:?}");
        assert!(take_password(&mut request).is_none());
    }
    assert_eq!(
        gate(&Request::View {
            query: "GitHub".into(),
            reveal: false,
            password: None,
        }),
        Gate::NoValue
    );
    assert_eq!(gate(&Request::Hold), Gate::Declares);
    assert_eq!(gate(&Request::SandboxListChecked), Gate::NoValue);
    assert_eq!(
        gate(&Request::PresenceWindow {
            window: None,
            password: None
        }),
        Gate::NoValue
    );
    assert_eq!(
        gate(&Request::PresenceWindow {
            window: Some(Window::Unlocked),
            password: None
        }),
        Gate::Setting
    );
    assert_eq!(
        gate(&Request::ExtensionAttach {
            browser: "Dia".into()
        }),
        Gate::ExtensionConnection
    );
    assert_eq!(gate(&Request::BrowserTab), Gate::BrowserChannel);
    let decide = |approve| Request::DecideApproval {
        approval: "a".into(),
        approve,
        digest: "d".into(),
        lease_secs: None,
        password: None,
    };
    assert_eq!(gate(&decide(true)), Gate::AlreadyAsks);
    assert_eq!(gate(&decide(false)), Gate::NoValue);
    // The extension's host never passes `hold` (§1.2) nor the setting.
    assert!(crate::native::check_request(&Request::Hold).is_err());
}

fn set_password(request: &mut Request) {
    match request {
        Request::View { password, .. }
        | Request::PreviousPassword { password, .. }
        | Request::Totp { password, .. }
        | Request::GeneratedValue { password, .. }
        | Request::Resolve { password, .. }
        | Request::Autofill { password, .. } => *password = Some(SecretText::new(RIGHT)),
        _ => {}
    }
}

#[test]
fn a_window_lasts_five_minutes_on_the_mock_clock_and_the_lock_drops_it() {
    let clock = Clock::new();
    let a = caller(1, session(40));
    let fake = Fake::new();
    // The unlock was a's verification: no prompt for 5 minutes.
    let p = unlocked(Window::FiveMinutes, &a, &clock);
    clock.advance(300);
    value(&p, &a, &fake, &clock).unwrap();
    assert_eq!(fake.asked(), 0);
    clock.advance(1);
    value(&p, &a, &fake, &clock).unwrap();
    assert_eq!(fake.asked(), 1);
    assert_eq!(
        fake.last(),
        "let the terminal ttys003 use your vault for 5 minutes"
    );
    // Locking drops it: locked, then a new session with no window.
    p.close(GEN + 1);
    assert_eq!(
        value(&p, &a, &fake, &clock).unwrap_err().code,
        ErrorCode::Locked
    );
    let other = caller(9, session(41));
    p.open(
        GEN + 1,
        settings(Window::FiveMinutes),
        &other,
        Some(Window::Unlocked),
        true,
        false,
        clock.now(),
    );
    let _ = p
        .require(
            GEN + 1,
            &a,
            Purpose::Window { value: &code() },
            None,
            &Bound::default(),
            None,
            &fake,
            Lang::En,
            &|| clock.now(),
        )
        .unwrap();
    assert_eq!(fake.asked(), 2);
}

#[test]
fn two_keys_never_share_a_window_and_always_asks_for_each_value() {
    let clock = Clock::new();
    let a = caller(1, session(40));
    let b = caller(2, session(41));
    let fake = Fake::new();
    let p = unlocked(Window::Unlocked, &a, &clock);
    value(&p, &a, &fake, &clock).unwrap();
    assert_eq!(fake.asked(), 0);
    value(&p, &b, &fake, &clock).unwrap();
    assert_eq!(fake.asked(), 1);
    assert_eq!(
        fake.last(),
        "let the terminal ttys003 use your vault until Klav locks"
    );
    // A connection key is its own connection's.
    let c1 = caller(3, Key::Connection(3));
    let c2 = caller(4, Key::Connection(4));
    value(&p, &c1, &fake, &clock).unwrap();
    assert_eq!(
        fake.last(),
        "let this connection use your vault until Klav locks"
    );
    value(&p, &c2, &fake, &clock).unwrap();
    assert_eq!(fake.asked(), 3);
    // Always: every value asks, with the value's own text, open windows
    // included.
    p.set_presence(GEN, Window::Always).unwrap();
    value(&p, &a, &fake, &clock).unwrap();
    value(&p, &a, &fake, &clock).unwrap();
    assert_eq!(fake.asked(), 5);
    assert_eq!(
        fake.last(),
        "show the code of “GitHub” (for the terminal ttys003)"
    );
}

#[test]
fn a_second_key_gets_busy_while_a_prompt_is_open_and_no_queue_forms() {
    let clock = Clock::new();
    let a = caller(1, session(40));
    let b = caller(2, session(41));
    let p = unlocked(Window::FiveMinutes, &caller(9, session(50)), &clock);
    let seen = RefCell::new(Vec::new());
    let inner = Fake::new();
    let fake = Fake::new();
    fake.while_open(|| {
        // Another key, and the same one, while a's dialog is open.
        seen.borrow_mut()
            .push(value(&p, &b, &inner, &clock).unwrap_err().code);
        seen.borrow_mut()
            .push(value(&p, &a, &inner, &clock).unwrap_err().code);
    });
    value(&p, &a, &fake, &clock).unwrap();
    assert_eq!(
        *seen.borrow(),
        [ErrorCode::PresenceBusy, ErrorCode::PresenceBusy]
    );
    // Nobody's dialog came after a's.
    assert_eq!((fake.asked(), inner.asked()), (1, 0));
    // Closed: b asks now.
    value(&p, &b, &inner, &clock).unwrap();
    assert_eq!(inner.asked(), 1);
}

#[test]
fn a_canceled_prompt_grants_nothing_and_frees_the_next() {
    let clock = Clock::new();
    let a = caller(1, session(40));
    let p = unlocked(Window::FiveMinutes, &caller(9, session(50)), &clock);
    let fake = Fake::new();
    fake.answer.set(false);
    assert_eq!(
        value(&p, &a, &fake, &clock).unwrap_err().code,
        ErrorCode::BiometryFailed
    );
    fake.answer.set(true);
    value(&p, &a, &fake, &clock).unwrap();
    value(&p, &a, &fake, &clock).unwrap();
    assert_eq!(fake.asked(), 2);
}

#[test]
fn a_verification_that_ends_after_a_lock_grants_nothing() {
    let clock = Clock::new();
    let a = caller(1, session(40));
    let p = unlocked(Window::Unlocked, &caller(9, session(50)), &clock);
    let fake = Fake::new();
    fake.while_open(|| p.close(GEN + 1));
    assert_eq!(
        value(&p, &a, &fake, &clock).unwrap_err().code,
        ErrorCode::Locked
    );
    p.open(
        GEN + 1,
        settings(Window::Unlocked),
        &caller(9, session(50)),
        Some(Window::Unlocked),
        true,
        false,
        clock.now(),
    );
    let next = Fake::new();
    let _ = p
        .require(
            GEN + 1,
            &a,
            Purpose::Window { value: &code() },
            None,
            &Bound::default(),
            None,
            &next,
            Lang::En,
            &|| clock.now(),
        )
        .unwrap();
    assert_eq!(next.asked(), 1);
}

#[test]
fn without_touch_id_the_client_is_told_what_to_ask() {
    let clock = Clock::new();
    let a = caller(1, session(40));
    let p = unlocked(Window::FiveMinutes, &caller(9, session(50)), &clock);
    let fake = Fake::without_touch_id();
    let e = value(&p, &a, &fake, &clock).unwrap_err();
    assert_eq!(e.code, ErrorCode::PresenceRequired);
    assert_eq!(
        e.presence,
        Some(Box::new(PresenceAsk {
            key: PresenceKey::Session,
            window: Window::FiveMinutes,
            terminal: Some("ttys003".into()),
            declared: false,
            lasts: Some(AskLasts::FiveMinutes),
            value: None,
        }))
    );
    // A wrong password grants nothing; the right one opens the window.
    assert_eq!(
        with_password(&p, &a, "wrong", &fake, &clock)
            .unwrap_err()
            .code,
        ErrorCode::WrongCredentials
    );
    assert_eq!(
        value(&p, &a, &fake, &clock).unwrap_err().code,
        ErrorCode::PresenceRequired
    );
    with_password(&p, &a, RIGHT, &fake, &clock).unwrap();
    value(&p, &a, &fake, &clock).unwrap();
    // No window (Linux before 6.5): the value itself, and each asks. A
    // password that answers no ask isn't checked: the answer is the ask.
    let none = caller(2, Key::NoWindow(2));
    let checked = fake.checks.get();
    let e = with_password(&p, &none, RIGHT, &fake, &clock).unwrap_err();
    assert_eq!(e.code, ErrorCode::PresenceRequired);
    assert_eq!(fake.checks.get(), checked);
    with_password(&p, &none, RIGHT, &fake, &clock).unwrap();
    let e = value(&p, &none, &fake, &clock).unwrap_err();
    let ask = e.presence.unwrap();
    assert_eq!(ask.key, PresenceKey::None);
    assert_eq!(ask.lasts, None);
    assert_eq!(ask.value, Some(code()));
}

#[test]
fn a_held_connection_reads_until_lock_with_five_minutes_and_is_never_shared() {
    let clock = Clock::new();
    let app = caller(1, Key::Connection(1));
    let p = unlocked(Window::FiveMinutes, &caller(9, session(50)), &clock);
    assert_eq!(p.declare(app.conn), (true, false));
    let fake = Fake::new();
    value(&p, &app, &fake, &clock).unwrap();
    assert_eq!(
        fake.last(),
        "let the program that asked use your vault until Klav locks"
    );
    assert!(p.is_held(app.conn));
    clock.advance(86_400);
    value(&p, &app, &fake, &clock).unwrap();
    assert_eq!(fake.asked(), 1);
    // Another connection of the same key isn't held, and no window was
    // opened for the key.
    let same_key = caller(2, Key::Connection(1));
    value(&p, &same_key, &fake, &clock).unwrap();
    assert_eq!(fake.asked(), 2);
    // An `EveryTime` value asks on a held connection too.
    let _ = p
        .require(
            GEN,
            &app,
            Purpose::EveryTime {
                reason: "show “Prod DB”",
            },
            None,
            &Bound::default(),
            None,
            &fake,
            Lang::En,
            &|| clock.now(),
        )
        .unwrap();
    assert_eq!(fake.last(), "show “Prod DB”");
    // Locking drops it; the declaration stays for the next unlock.
    p.close(GEN + 1);
    assert!(!p.is_held(app.conn));
    let held = p.open(
        GEN + 1,
        settings(Window::FiveMinutes),
        &app,
        Some(Window::Unlocked),
        true,
        false,
        clock.now(),
    );
    assert_eq!(held, Unlocked { held: true });
    // Closing the connection forgets both.
    p.forget_connection(app.conn);
    assert!(!p.is_held(app.conn) && !p.is_declared(app.conn));
}

#[test]
fn with_always_a_declaration_has_no_effect_and_each_value_asks() {
    let clock = Clock::new();
    let app = caller(1, Key::Connection(1));
    let p = unlocked(Window::Always, &caller(9, session(50)), &clock);
    assert_eq!(p.declare(app.conn), (false, false));
    let fake = Fake::new();
    value(&p, &app, &fake, &clock).unwrap();
    value(&p, &app, &fake, &clock).unwrap();
    assert_eq!(fake.asked(), 2);
    assert!(!p.is_held(app.conn));
}

#[test]
fn moving_to_always_drops_held_connections_and_declarations_for_good() {
    let clock = Clock::new();
    let app = caller(1, Key::Connection(1));
    let p = unlocked(Window::Unlocked, &caller(9, session(50)), &clock);
    p.declare(app.conn);
    let fake = Fake::new();
    value(&p, &app, &fake, &clock).unwrap();
    assert!(p.is_held(app.conn));
    p.set_presence(GEN, Window::Always).unwrap();
    assert!(!p.is_held(app.conn) && !p.is_declared(app.conn));
    // Back to 5 minutes: neither comes back; the connection is ordinary.
    p.set_presence(GEN, Window::FiveMinutes).unwrap();
    value(&p, &app, &fake, &clock).unwrap();
    assert_eq!(
        fake.last(),
        "let this connection use your vault for 5 minutes"
    );
    assert!(!p.is_held(app.conn));
}

#[test]
fn other_verifications_on_a_declared_connection_do_not_hold_it() {
    let clock = Clock::new();
    let app = caller(1, Key::Connection(1));
    let p = unlocked(Window::FiveMinutes, &caller(9, session(50)), &clock);
    p.declare(app.conn);
    let fake = Fake::new();
    // An `EveryTime` presence, a passkey use: their own text, not held.
    let _ = p
        .require(
            GEN,
            &app,
            Purpose::EveryTime { reason: "x" },
            None,
            &Bound::default(),
            None,
            &fake,
            Lang::En,
            &|| clock.now(),
        )
        .unwrap();
    p.passkey_checked(GEN, &app, clock.now());
    assert!(!p.is_held(app.conn));
    // `confirm_presence` and the other "already asks" operations never
    // reach the gate's state (the server calls `touchid` directly).
}

#[test]
fn a_window_opened_under_five_minutes_stays_five_after_a_move_to_while_unlocked() {
    let clock = Clock::new();
    let a = caller(1, session(40));
    let p = unlocked(Window::FiveMinutes, &caller(9, session(50)), &clock);
    let fake = Fake::new();
    value(&p, &a, &fake, &clock).unwrap();
    p.set_presence(GEN, Window::Unlocked).unwrap();
    clock.advance(301);
    value(&p, &a, &fake, &clock).unwrap();
    assert_eq!(fake.asked(), 2);
    // The new one lasts until lock.
    assert_eq!(
        fake.last(),
        "let the terminal ttys003 use your vault until Klav locks"
    );
    clock.advance(86_400);
    value(&p, &a, &fake, &clock).unwrap();
    assert_eq!(fake.asked(), 2);
}

#[test]
fn loosening_opens_nothing_and_a_tightening_is_never_undone() {
    let clock = Clock::new();
    let a = caller(1, session(40));
    let p = unlocked(Window::Always, &caller(9, session(50)), &clock);
    let fake = Fake::new();
    // Under Always a verification covers its one value...
    value(&p, &a, &fake, &clock).unwrap();
    // ...and loosening doesn't stretch it: the next value asks.
    p.set_presence(GEN, Window::Unlocked).unwrap();
    value(&p, &a, &fake, &clock).unwrap();
    assert_eq!(fake.asked(), 2);
    value(&p, &a, &fake, &clock).unwrap();
    assert_eq!(fake.asked(), 2);
    // While unlocked → Always → While unlocked: the old window is gone.
    p.set_presence(GEN, Window::Always).unwrap();
    p.set_presence(GEN, Window::Unlocked).unwrap();
    value(&p, &a, &fake, &clock).unwrap();
    assert_eq!(fake.asked(), 3);
    // Unlocked → 5 minutes shortens it at once.
    p.set_presence(GEN, Window::FiveMinutes).unwrap();
    clock.advance(301);
    value(&p, &a, &fake, &clock).unwrap();
    assert_eq!(fake.asked(), 4);
}

#[test]
fn the_passkey_window_is_per_key_and_loosening_it_opens_nothing() {
    let clock = Clock::new();
    let a = caller(1, session(40));
    let b = caller(2, session(41));
    let p = Presence::default();
    p.open(
        GEN,
        Settings {
            presence: Window::FiveMinutes,
            passkey: Window::FiveMinutes,
        },
        &a,
        Some(Window::Unlocked),
        true,
        false,
        clock.now(),
    );
    // a's unlock covers a's passkey uses, not b's.
    assert!(!p.passkey_needs(&a, clock.now()));
    assert!(p.passkey_needs(&b, clock.now()));
    p.passkey_checked(GEN, &b, clock.now());
    assert!(!p.passkey_needs(&b, clock.now()));
    clock.advance(301);
    assert!(p.passkey_needs(&b, clock.now()));
    // Under Always a check is spent by its use; loosening doesn't bring
    // it back.
    p.set_passkey(GEN, Window::Always).unwrap();
    p.passkey_checked(GEN, &b, clock.now());
    p.passkey_spend(&b);
    p.set_passkey(GEN, Window::Unlocked).unwrap();
    assert!(p.passkey_needs(&b, clock.now()));
}

#[test]
fn the_unlock_rule_tells_another_key_and_a_password_opens_its_window() {
    let clock = Clock::new();
    let a = caller(1, session(40));
    let b = caller(2, session(41));
    let p = unlocked(Window::FiveMinutes, &a, &clock);
    assert!(!p.unlocked_by_other(&a));
    assert!(p.unlocked_by_other(&b));
    // Without the password b got nothing: its value asks.
    let fake = Fake::without_touch_id();
    assert_eq!(
        value(&p, &b, &fake, &clock).unwrap_err().code,
        ErrorCode::PresenceRequired
    );
    // With it, b's own window.
    p.password_at_unlock(GEN, &b, Some(Window::FiveMinutes), true, false, clock.now());
    value(&p, &b, &fake, &clock).unwrap();
    // An unlock prompt is open only while its guard lives, and while it is
    // no other prompt opens.
    assert!(!p.unlock_prompt_open());
    let open = p.open_prompt(PromptKind::Unlock).unwrap();
    assert!(p.unlock_prompt_open());
    assert_eq!(
        p.open_prompt(PromptKind::Presence).err().map(|e| e.code),
        Some(ErrorCode::PresenceBusy)
    );
    drop(open);
    assert!(!p.unlock_prompt_open() && !p.prompt_open());
}

/// The first look at a value, before its text is read (the third layer-2
/// review, finding A): a window that covers it passes; otherwise it asks
/// for the text, having opened nothing, and says whether Touch ID would
/// show. It never asks the client, never checks a password and keeps no
/// ask (the second review of layer 3, finding 7).
#[test]
fn the_first_look_passes_a_window_and_otherwise_only_asks_for_the_text() {
    let clock = Clock::new();
    let a = caller(1, session(40));
    let b = caller(2, session(41));
    let first = |p: &Presence, who: &Caller, password: bool, verify: &dyn Verify| {
        p.first(GEN, who, password, verify, &|| clock.now())
    };
    // a's unlock opened a's window: no text, no prompt.
    let p = unlocked(Window::FiveMinutes, &a, &clock);
    let fake = Fake::new();
    assert_eq!(first(&p, &a, false, &fake), Ok(Untitled::Passed));
    // b, under 5 minutes: nothing covers it, so the text first.
    assert_eq!(
        first(&p, &b, false, &fake),
        Ok(Untitled::NeedsText { touch: true })
    );
    // Under Always too.
    p.set_presence(GEN, Window::Always).unwrap();
    assert_eq!(
        first(&p, &a, false, &fake),
        Ok(Untitled::NeedsText { touch: true })
    );
    assert!(!p.prompt_open(), "no prompt opened before the text");
    assert_eq!(fake.asked(), 0);
    // With a password: no Touch ID, and nothing checked.
    assert_eq!(
        first(&p, &a, true, &fake),
        Ok(Untitled::NeedsText { touch: false })
    );
    assert_eq!(fake.checks.get(), 0);
    // `presence_busy` while another prompt is open, where Touch ID would
    // show.
    let open = p.open_prompt(PromptKind::Presence).unwrap();
    assert_eq!(
        first(&p, &a, false, &fake).map_err(|e| e.code),
        Err(ErrorCode::PresenceBusy)
    );
    drop(open);
    // Without Touch ID, the client's prompt will name it.
    assert_eq!(
        first(&p, &a, false, &Fake::without_touch_id()),
        Ok(Untitled::NeedsText { touch: false })
    );
    // It kept no ask: a password sent now answers none, so it isn't
    // checked, and `require` asks.
    let e = with_password(&p, &a, RIGHT, &Fake::without_touch_id(), &clock).unwrap_err();
    assert_eq!(e.code, ErrorCode::PresenceRequired);
}

/// [`Presence::lock`] (the third layer-2 review, finding A): a waiter that
/// asks is busy at once while a prompt is open, and as soon as one opens
/// while it waits; with `only`, just that kind stops it. A free lock is
/// taken at once.
#[tokio::test(flavor = "multi_thread")]
async fn a_waiter_that_asks_is_busy_as_soon_as_a_prompt_opens() {
    use std::sync::Arc;
    let bound = Duration::from_secs(10);
    let settle = Duration::from_millis(100);
    let p = Arc::new(Presence::default());
    let lock = Arc::new(tokio::sync::Mutex::new(()));
    let waiter = |only: Option<PromptKind>| {
        let (p, lock) = (Arc::clone(&p), Arc::clone(&lock));
        tokio::spawn(async move {
            p.lock(&lock, true, only)
                .await
                .map(drop)
                .map_err(|e| e.code)
        })
    };
    let held = Arc::clone(&lock).lock_owned().await;
    // Open now: busy at once.
    let open = p.open_prompt(PromptKind::Presence).unwrap();
    assert_eq!(
        p.lock(&lock, true, None).await.err().map(|e| e.code),
        Some(ErrorCode::PresenceBusy)
    );
    drop(open);
    // Opens while it waits: busy then, with the lock still held.
    let any = waiter(None);
    tokio::time::sleep(settle).await;
    assert!(!any.is_finished());
    let open = p.open_prompt(PromptKind::Presence).unwrap();
    let answer = tokio::time::timeout(bound, any).await.expect("at once");
    assert_eq!(answer.unwrap(), Err(ErrorCode::PresenceBusy));
    drop(open);
    // Only unlock prompts: a presence prompt doesn't stop it, an unlock
    // prompt does.
    let unlock = waiter(Some(PromptKind::Unlock));
    let open = p.open_prompt(PromptKind::Presence).unwrap();
    tokio::time::sleep(settle).await;
    assert!(!unlock.is_finished());
    drop(open);
    let open = p.open_prompt(PromptKind::Unlock).unwrap();
    let answer = tokio::time::timeout(bound, unlock).await.expect("at once");
    assert_eq!(answer.unwrap(), Err(ErrorCode::PresenceBusy));
    drop(open);
    // Freed: taken.
    drop(held);
    let (_guard, behind) = p.lock(&lock, true, None).await.expect("free");
    assert!(!behind);
}

/// A waiter that doesn't ask waits as before, and says whether a prompt was
/// open, or opened, while it waited: its own prompt would follow that one.
/// One thread, so the waiter is known to be waiting after a `yield_now`.
#[tokio::test(flavor = "current_thread")]
async fn a_waiter_that_does_not_ask_says_a_prompt_opened_while_it_waited() {
    use std::sync::Arc;
    let p = Arc::new(Presence::default());
    let lock = Arc::new(tokio::sync::Mutex::new(()));
    let waiter = || {
        let (p, lock) = (Arc::clone(&p), Arc::clone(&lock));
        tokio::spawn(async move { p.lock(&lock, false, None).await.map(|(_, behind)| behind) })
    };
    // Nothing opened meanwhile.
    let held = Arc::clone(&lock).lock_owned().await;
    let quiet = waiter();
    tokio::task::yield_now().await;
    drop(held);
    assert!(!quiet.await.unwrap().expect("taken"));
    // One opened and closed meanwhile: it still waited, and says so.
    let held = Arc::clone(&lock).lock_owned().await;
    let behind = waiter();
    tokio::task::yield_now().await;
    drop(p.open_prompt(PromptKind::Presence).unwrap());
    tokio::task::yield_now().await;
    assert!(!behind.is_finished(), "it waits for the lock");
    drop(held);
    assert!(behind.await.unwrap().expect("taken"));
    // One open when it started.
    let held = Arc::clone(&lock).lock_owned().await;
    let open = p.open_prompt(PromptKind::Presence).unwrap();
    let behind = waiter();
    tokio::task::yield_now().await;
    drop(open);
    drop(held);
    assert!(behind.await.unwrap().expect("taken"));
}

/// A verifier whose Touch ID panics (finding 7 of the second layer-2
/// review).
struct Panics;

impl Verify for Panics {
    fn touch_id_available(&self) -> bool {
        true
    }

    fn touch_id(&self, _reason: &str) -> Result<(), Refused> {
        panic!("the Touch ID call panicked");
    }

    fn password(&self, _password: SecretText) -> Result<(), ErrorBody> {
        unreachable!()
    }
}

#[test]
fn a_panic_during_touch_id_leaves_no_prompt_open() {
    let clock = Clock::new();
    let a = caller(1, session(40));
    let p = unlocked(Window::FiveMinutes, &caller(9, session(50)), &clock);
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        value(&p, &a, &Panics, &clock)
    }));
    assert!(unwound.is_err());
    assert!(!p.prompt_open(), "a panic left the prompt open");
    // So the next request asks instead of getting `presence_busy` for good.
    let fake = Fake::new();
    value(&p, &a, &fake, &clock).unwrap();
    assert_eq!(fake.asked(), 1);
    // The same for a guard taken by the server around its own prompts.
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _open = p.open_prompt(PromptKind::Unlock).unwrap();
        panic!("the unlock's Touch ID panicked");
    }));
    assert!(unwound.is_err());
    assert!(!p.unlock_prompt_open() && !p.prompt_open());
}

#[test]
fn one_password_check_at_a_time_and_a_panic_frees_it() {
    let one = OnePassword::default();
    let inner = one.one(true, || {
        assert!(one.running());
        Ok(one.one(true, || Ok(())).unwrap_err().code)
    });
    assert_eq!(inner.unwrap(), ErrorCode::PresenceBusy);
    // With the gate off, a code older clients know.
    let off = one.one(false, || Ok(one.one(false, || Ok(())).unwrap_err().code));
    assert_eq!(off.unwrap(), ErrorCode::Conflict);
    assert!(!one.running());
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        one.one::<()>(true, || panic!("Argon2id panicked"))
    }));
    assert!(unwound.is_err());
    assert!(!one.running());
    // No session to check against: no proof.
    assert_eq!(
        one.check(true, None, SecretText::new(RIGHT))
            .unwrap_err()
            .code,
        ErrorCode::WrongCredentials
    );
}

#[test]
fn the_unlock_prompt_says_the_window_it_opens_or_none() {
    let clock = Clock::new();
    let a = caller(1, session(40));
    let p = Presence::default();
    // Before any unlock `klavd` doesn't know the setting: no window said,
    // and none opened.
    assert_eq!(
        unlock_window(&p, &a, false),
        (None, Who::Terminal("ttys003"), None)
    );
    p.open(
        GEN,
        settings(Window::Unlocked),
        &a,
        None,
        true,
        false,
        clock.now(),
    );
    let fake = Fake::new();
    value(&p, &a, &fake, &clock).unwrap();
    assert_eq!(fake.asked(), 1);
    p.close(GEN + 1);
    assert_eq!(
        unlock_window(&p, &a, false),
        (
            Some(Window::Unlocked),
            Who::Terminal("ttys003"),
            Some(Lasts::UntilLock)
        )
    );
    assert_eq!(
        unlock_window(&p, &a, true),
        (
            Some(Window::Unlocked),
            Who::Declared,
            Some(Lasts::UntilLock)
        )
    );
    let text = |who, lasts| {
        Prompt::UnlockPresence {
            email: "ana@example.com",
            who,
            lasts,
        }
        .reason(Lang::En, Some(Source::Terminal))
    };
    assert_eq!(
        text(Who::Terminal("ttys003"), Some(Lasts::FiveMinutes)),
        "unlock your vault for the terminal ttys003, and let it use the vault for 5 minutes (ana@example.com)"
    );
    assert_eq!(
        text(Who::Declared, Some(Lasts::UntilLock)),
        "unlock your vault and let the program that asked use it until Klav locks (ana@example.com)"
    );
    assert_eq!(
        text(Who::ATerminal, None),
        "unlock your vault (ana@example.com)"
    );
}

#[test]
fn the_prompts_in_both_languages() {
    let es = |prompt: Prompt<'_>| prompt.reason(Lang::Es, Some(Source::Terminal));
    assert_eq!(
        es(Prompt::Presence {
            who: Who::Terminal("ttys003"),
            lasts: Lasts::FiveMinutes
        }),
        "dejar que la terminal ttys003 use tu bóveda durante 5 minutos"
    );
    assert_eq!(
        es(Prompt::Presence {
            who: Who::Connection,
            lasts: Lasts::FiveMinutes
        }),
        "dejar que esta conexión use tu bóveda durante 5 minutos"
    );
    assert_eq!(
        es(Prompt::Presence {
            who: Who::Declared,
            lasts: Lasts::UntilLock
        }),
        "dejar que el programa que lo pidió use tu bóveda hasta que Klav se bloquee"
    );
    assert_eq!(
        es(Prompt::Presence {
            who: Who::NoTerminal,
            lasts: Lasts::UntilLock
        }),
        "dejar que un programa sin terminal use tu bóveda hasta que Klav se bloquee"
    );
    assert_eq!(
        Prompt::Presence {
            who: Who::Browser,
            lasts: Lasts::FiveMinutes
        }
        .reason(Lang::En, Some(Source::Browser)),
        "let a browser use your vault for 5 minutes"
    );
    assert_eq!(
        Prompt::Presence {
            who: Who::BrowserConnection,
            lasts: Lasts::UntilLock
        }
        .reason(Lang::En, None),
        "let this browser connection use your vault until Klav locks"
    );
    assert_eq!(
        es(Prompt::UnlockPresence {
            email: "ana@example.com",
            who: Who::Terminal("ttys003"),
            lasts: Some(Lasts::FiveMinutes),
        }),
        "desbloquear tu bóveda para la terminal ttys003 y dejar que la use durante 5 minutos (ana@example.com)"
    );
    // With no window, the value and who it is for (Omar's decision C of
    // 2026-11-19), for every `Who` but a declared connection, which never
    // asks under Always.
    use crate::prompt::ValueAsk;
    let value = |ask, who, lang| Prompt::Value { ask, who }.reason(lang, None);
    let cases = [
        (
            ValueAsk::Code(Some("GitHub")),
            Who::Terminal("ttys003"),
            "show the code of “GitHub” (for the terminal ttys003)",
            "mostrar el código de «GitHub» (para la terminal ttys003)",
        ),
        (
            ValueAsk::Show(Some("GitHub")),
            Who::ATerminal,
            "show the values of “GitHub” (for a terminal)",
            "mostrar los valores de «GitHub» (para una terminal)",
        ),
        (
            ValueAsk::Previous(Some("GitHub")),
            Who::NoTerminal,
            "show a previous password of “GitHub” (for a program with no terminal)",
            "mostrar una contraseña anterior de «GitHub» (para un programa sin terminal)",
        ),
        (
            ValueAsk::Fill(Some("GitHub")),
            Who::Browser,
            "fill “GitHub” in a browser",
            "rellenar «GitHub» en un navegador",
        ),
        (
            ValueAsk::Fill(Some("GitHub")),
            Who::BrowserConnection,
            "fill “GitHub” in a browser (for this browser connection)",
            "rellenar «GitHub» en un navegador (para esta conexión del navegador)",
        ),
        (
            ValueAsk::Generated,
            Who::Connection,
            "show a password you generated (for this connection)",
            "mostrar una contraseña que generaste (para esta conexión)",
        ),
        (
            ValueAsk::Resolve(3),
            Who::Terminal("ttys003"),
            "use 3 values from your vault in a command (for the terminal ttys003)",
            "usar 3 valores de tu bóveda en un comando (para la terminal ttys003)",
        ),
    ];
    for (ask, who, en, spanish) in cases {
        assert_eq!(value(ask, who, Lang::En), en);
        assert_eq!(value(ask, who, Lang::Es), spanish);
    }
    // The terminal's name, from outside, is cleaned there too.
    assert_eq!(
        value(
            ValueAsk::Code(Some("GitHub")),
            Who::Terminal("ttys\u{1b}[2J3"),
            Lang::En
        ),
        "show the code of “GitHub” (for the terminal ttys [2J3)"
    );
    assert_eq!(
        Prompt::PresenceWindow {
            from: Window::Always,
            to: Window::FiveMinutes
        }
        .reason(Lang::En, Some(Source::Terminal)),
        "ask for your presence every 5 minutes instead of for every value"
    );
    assert_eq!(
        es(Prompt::PresenceWindow {
            from: Window::FiveMinutes,
            to: Window::Unlocked
        }),
        "pedir tu presencia una vez hasta que Klav se bloquee en vez de cada 5 minutos"
    );
    // A name from outside goes through `clean`.
    assert_eq!(
        Prompt::Presence {
            who: Who::Terminal("ttys\u{202e}1"),
            lasts: Lasts::FiveMinutes
        }
        .reason(Lang::En, None),
        "let the terminal ttys1 use your vault for 5 minutes"
    );
}

fn ctx() -> LocalContext {
    LocalContext {
        account: AccountId::generate(),
        device: DeviceId::generate(),
    }
}

#[test]
fn the_settings_are_sealed_missing_means_the_default_and_damage_means_always() {
    let dir = tempfile::tempdir().unwrap();
    let home = Home::at(dir.path().join("home"));
    let key = LocalKey::generate();
    let c = ctx();
    assert_eq!(
        load_settings(&home, &key, &c),
        Settings {
            presence: Window::FiveMinutes,
            passkey: Window::Always,
        }
    );
    save(&home, &key, &c, Which::Presence, Window::Unlocked).unwrap();
    save(&home, &key, &c, Which::Passkey, Window::FiveMinutes).unwrap();
    assert_eq!(
        load_settings(&home, &key, &c),
        Settings {
            presence: Window::Unlocked,
            passkey: Window::FiveMinutes,
        }
    );
    // Local data, kind 0x41, version 1.
    let blob = std::fs::read(home.file(PRESENCE_FILE)).unwrap();
    assert_eq!(&blob[..2], &[0x01, 0x41]);
    // Another key (another account or device), an edited byte, or one
    // setting's blob in the other's place: Always.
    assert_eq!(
        load_settings(&home, &LocalKey::generate(), &c).presence,
        Window::Always
    );
    assert_eq!(load_settings(&home, &key, &ctx()).presence, Window::Always);
    std::fs::copy(home.file(PASSKEY_FILE), home.file(PRESENCE_FILE)).unwrap();
    assert_eq!(load_settings(&home, &key, &c).presence, Window::Always);
    let mut edited = blob.clone();
    let last = edited.len() - 1;
    edited[last] ^= 1;
    std::fs::write(home.file(PRESENCE_FILE), &edited).unwrap();
    assert_eq!(load_settings(&home, &key, &c).presence, Window::Always);
    // Another version, sealed properly: Always.
    let v2 = seal_local_data(
        &key,
        &c,
        PRESENCE_PURPOSE,
        br#"{"v":2,"window":"unlocked"}"#,
    )
    .unwrap();
    std::fs::write(home.file(PRESENCE_FILE), v2).unwrap();
    assert_eq!(load_settings(&home, &key, &c).presence, Window::Always);
    // A plain file a program wrote: Always, never "unlocked".
    std::fs::write(home.file(PRESENCE_FILE), br#"{"v":1,"window":"unlocked"}"#).unwrap();
    assert_eq!(load_settings(&home, &key, &c).presence, Window::Always);
    // Deleted: the default again (risk 75).
    std::fs::remove_file(home.file(PRESENCE_FILE)).unwrap();
    assert_eq!(load_settings(&home, &key, &c).presence, Window::FiveMinutes);
}

#[test]
fn the_old_passkey_file_is_only_checked_for_then_deleted_and_warned_once() {
    let dir = tempfile::tempdir().unwrap();
    let home = Home::at(dir.path().join("home"));
    home.ensure().unwrap();
    assert_eq!(forget_old_passkey_file(&home), None);
    // Whatever it says, even something no reader would accept.
    std::fs::write(home.file(OLD_PASSKEY_FILE), b"\xff not json").unwrap();
    assert_eq!(forget_old_passkey_file(&home), Some(OLD_PASSKEY_WARNING));
    assert!(!home.file(OLD_PASSKEY_FILE).exists());
    assert_eq!(forget_old_passkey_file(&home), None);
}

/// What a connection remembers of the request its ask was for is a digest
/// (the second review of layer 3, finding 5). That it has a fixed size is
/// true by type (`Bound::request` is `[u8; 32]`), so it isn't asserted
/// here; what can fail is: a `resolve` of over 1 MiB of references keeps
/// the same digest each time, two requests that differ in one byte keep
/// different ones, and through the gate a password sent for the other
/// request isn't checked.
#[test]
fn the_remembered_request_is_a_fixed_size_digest() {
    let resolve = |last: &str| {
        let mut references = vec!["klav://Personal/General/Deploy/api_key".to_owned(); 28_000];
        references.push(last.to_owned());
        Request::Resolve {
            references,
            password: None,
        }
    };
    let big = resolve("klav://Personal/General/Deploy/a");
    assert!(serde_json::to_vec(&big).unwrap().len() > 1024 * 1024);
    let digest = request_digest(&big).unwrap();
    assert_eq!(request_digest(&big).unwrap(), digest, "the same request");
    assert_ne!(
        request_digest(&resolve("klav://Personal/General/Deploy/b")).unwrap(),
        digest,
        "another request"
    );
    // Through the gate: a password for another request isn't checked.
    let clock = Clock::new();
    let a = caller(1, session(40));
    let p = unlocked(Window::Always, &caller(9, session(50)), &clock);
    let fake = Fake::without_touch_id();
    let bound = |request: &Request| Bound {
        request: request_digest(request).unwrap(),
        item: None,
    };
    let ask = |request: &Request, password: Option<&str>| {
        p.require(
            GEN,
            &a,
            Purpose::Window { value: &code() },
            password.map(SecretText::new),
            &bound(request),
            None,
            &fake,
            Lang::En,
            &|| clock.now(),
        )
    };
    assert_eq!(
        ask(&big, None).unwrap_err().code,
        ErrorCode::PresenceRequired
    );
    let other = resolve("klav://Personal/General/Deploy/b");
    assert_eq!(
        ask(&other, Some(RIGHT)).unwrap_err().code,
        ErrorCode::PresenceRequired
    );
    assert_eq!(fake.checks.get(), 0);
    let _ = ask(&other, Some(RIGHT)).unwrap();
    assert_eq!(fake.checks.get(), 1);
}

/// A verification that passes opens no window by itself (Omar's decision G
/// of 2026-11-19): the window the answer stated opens only through
/// `open_window`, which the server calls once the hand-out found what was
/// asked about. Dropped, as after a `conflict`, the next value asks again;
/// by Touch ID and by the password sent again alike.
#[test]
fn a_passed_answer_opens_its_window_only_when_handed_out() {
    let clock = Clock::new();
    let a = caller(1, session(40));
    let p = unlocked(Window::FiveMinutes, &caller(9, session(50)), &clock);
    let require = |password: Option<&str>, verify: &dyn Verify| {
        p.require(
            GEN,
            &a,
            Purpose::Window { value: &code() },
            password.map(SecretText::new),
            &Bound::default(),
            None,
            verify,
            Lang::En,
            &|| clock.now(),
        )
    };
    // Touch ID: passed, with a 5-minute window to open, not open.
    let fake = Fake::new();
    let passed = require(None, &fake).unwrap();
    assert!(passed.opens.is_some());
    assert!(!p.inner().covers(&a, Window::FiveMinutes, clock.now()));
    drop(passed);
    let _ = require(None, &fake).unwrap();
    assert_eq!(fake.asked(), 2, "a dropped answer leaves the next to ask");
    // The password sent again: the same.
    let typed = Fake::without_touch_id();
    assert_eq!(
        require(None, &typed).unwrap_err().code,
        ErrorCode::PresenceRequired
    );
    let passed = require(Some(RIGHT), &typed).unwrap();
    assert!(!p.inner().covers(&a, Window::FiveMinutes, clock.now()));
    drop(passed);
    assert_eq!(
        require(None, &typed).unwrap_err().code,
        ErrorCode::PresenceRequired
    );
    // Handed out: the window opens, and covers the next value.
    let passed = require(Some(RIGHT), &typed).unwrap();
    handed_out(&p, &a, passed, &clock);
    assert!(p.inner().covers(&a, Window::FiveMinutes, clock.now()));
    let passed = require(None, &typed).unwrap();
    assert_eq!(
        passed.opens, None,
        "covered: nothing asked, nothing to open"
    );
    assert_eq!(typed.checks.get(), 2);
}
