//! The presence gate in the Mac app's engine (ADR 0041, layer 5):
//! `DaemonEngine` keeps one long connection, declares `hold` first on it,
//! sends `unlock` and the values there, and resends a value with the master
//! password only on the connection that got `presence_required` (own choice
//! 32). A password unlock sends `shown` (own choice 34).
//!
//! Two kinds of test. Against a real `klavd`, in this process, with
//! `--presence-gate` on and off, Touch ID off: what `klavd` checks (a
//! password resent anywhere else would not be). Against a scripted `klavd`
//! on the socket: exactly what the engine sends and on which connection,
//! and the answers a real one can't be made to give here (an older
//! `klavd`, `already_unlocked` from another key, busy answers).
//!
//! Nothing touches the real `KLAV_HOME`: every home is a temporary
//! directory, deleted at the end.

#![cfg(feature = "daemon")]

mod common;

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::ServerProcess;
use klav_ffi::{
    DaemonEngine, FieldEdit, FieldType, HoldState, ItemEdit, Kind, KlavCore, KlavError,
    NewItemInput, PresenceKeyKind, PresenceLasts, PresenceSetting, PresenceValueKind,
};
use serde_json::{Value, json};

const PASSWORD: &str = "correct horse battery staple";
const SECRET: &str = "MARKER-presence-mac-41";

// ---------------------------------------------------------------------------
// A real klavd.

/// A `klavd` for `home` on its own runtime, stopped when dropped.
struct Daemon {
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Daemon {
    fn start(home: &std::path::Path, presence_gate: bool) -> Self {
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let home = klav_client::Home::at(home);
        let thread = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .expect("test setup");
            let config = klav_daemon::Config {
                home,
                idle_lock: Duration::from_secs(15 * 60),
                touch_id: false,
                sync_after: klav_daemon::SYNC_AFTER,
                build: None,
                presence_gate,
            };
            let _ = rt.block_on(klav_daemon::serve(config, async {
                let _ = stopped.await;
            }));
        });
        Self {
            stop: Some(stop),
            thread: Some(thread),
        }
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn wait_until(what: &str, mut ok: impl FnMut() -> bool) {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while std::time::Instant::now() < deadline {
        if ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("timed out waiting for {what}");
}

/// An account in `home`, signed up by the app's process and let go, and
/// a `klavd` on it: the app's engine, locked.
fn account(
    server: &ServerProcess,
    home: &std::path::Path,
    gate: bool,
) -> (Daemon, Arc<DaemonEngine>) {
    let core = KlavCore::new(home.display().to_string()).expect("core");
    core.sign_up(
        server.url.clone(),
        "mac@example.com".into(),
        PASSWORD.into(),
        "Mac de prueba".into(),
    )
    .expect("sign up");
    core.lock();
    drop(core);
    let daemon = Daemon::start(home, gate);
    let engine = DaemonEngine::new(home.display().to_string()).expect("engine");
    wait_until("klavd", || engine.status().running);
    (daemon, engine)
}

fn login(title: &str) -> NewItemInput {
    NewItemInput {
        kind: Kind::Login,
        title: title.into(),
        vault_id: None,
        project_id: None,
        fields: vec![
            FieldEdit {
                name: "username".into(),
                value: "ana".into(),
                kind: Some(FieldType::Username),
            },
            FieldEdit {
                name: "password".into(),
                value: SECRET.into(),
                kind: Some(FieldType::Password),
            },
        ],
        urls: vec!["https://github.com".into()],
        tags: Vec::new(),
        notes: None,
    }
}

fn asked(result: Result<String, KlavError>) -> klav_ffi::PresenceAskInfo {
    match result {
        Err(KlavError::PresenceRequired { ask }) => ask,
        other => panic!("expected presence_required, got {other:?}"),
    }
}

#[test]
fn with_the_gate_on_the_app_answers_presence_on_the_connection_that_asked() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let home = dir.path().join("klav");
    // An old passkey setting from before the gate (ADR 0041 §2.4, Q-N3).
    std::fs::create_dir_all(&home).expect("home");
    let (_daemon, engine) = account(&server, &home, true);
    std::fs::write(home.join("passkeys.json"), r#"{"v":1,"window":"unlocked"}"#)
        .expect("old setting");

    let status = engine.status();
    assert!(status.presence_gate, "status carries `presence`");
    // Q-N2: the setting can't be read while locked.
    assert!(matches!(engine.presence_window(), Err(KlavError::Locked)));

    // The first unlock since klavd started: its question names no window
    // (Omar's decision A), and the long connection is declared first.
    let question = engine.unlock_question().expect("question");
    assert!(question.gate && !question.elsewhere);
    assert_eq!(question.lasts, None);
    let held = engine.held_connection();
    assert!(held.connected);
    // `hold` stays `not_supported` until layer 6: the connection stays,
    // an ordinary one.
    assert_eq!(held.hold, HoldState::NotSupported);
    let generation = held.generation;
    let outcome = engine.unlock(Some(PASSWORD.into()), None).expect("unlock");
    assert!(!outcome.already_unlocked);
    // The old setting is said once, and deleted.
    assert!(outcome.passkey_setting_reset, "{outcome:?}");
    assert!(!home.join("passkeys.json").exists());
    assert_eq!(
        engine.held_connection().generation,
        generation,
        "same connection"
    );

    let item = engine.create_item(login("GitHub")).expect("create");
    // The first value asks: no window was opened by the first unlock.
    let ask = asked(engine.field_value(item.id.clone(), "password".into()));
    assert_eq!(ask.window, PresenceSetting::FiveMinutes);
    assert_eq!(ask.lasts, Some(PresenceLasts::FiveMinutes));
    assert!(!ask.declared);
    assert!(engine.held_connection().asking);

    // Another value while the question is open isn't sent: it would take
    // the ask's place, and the password would no longer be checked.
    assert!(matches!(
        engine.totp(item.id.clone()),
        Err(KlavError::PresenceBusy {
            in_this_app: true,
            ..
        })
    ));

    // The same password on any other connection is never checked, while
    // the question is open on the long one: that is why the engine resends
    // on the connection that asked (own choice 32).
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test setup");
    let other = rt.block_on(async {
        let mut client = klav_daemon::client::DaemonClient::connect(&klav_client::Home::at(&home))
            .await
            .expect("connect");
        client
            .call::<serde::de::IgnoredAny>(klav_daemon::protocol::Request::View {
                query: item.id.clone(),
                reveal: true,
                password: Some(klav_client::ops::SecretText::new(PASSWORD)),
            })
            .await
    });
    assert!(
        matches!(&other, Err(e) if e.code == klav_daemon::protocol::ErrorCode::PresenceRequired),
        "{other:?}"
    );

    // A wrong password: refused, and the question stays answerable.
    assert!(matches!(
        engine.field_value_with_password(item.id.clone(), "password".into(), "wrong".into()),
        Err(KlavError::WrongCredentials)
    ));
    assert!(
        engine.held_connection().asking,
        "asked again after the wrong one"
    );
    // The right one, on the same connection: checked, and the value goes.
    assert_eq!(
        engine
            .field_value_with_password(item.id.clone(), "password".into(), PASSWORD.into())
            .expect("value"),
        SECRET
    );
    assert!(!engine.held_connection().asking);
    // Its window is open now: the next value asks nothing.
    assert_eq!(
        engine
            .field_value(item.id.clone(), "password".into())
            .expect("inside the window"),
        SECRET
    );

    // The setting: read while unlocked; tightening asks nothing and closes
    // the window at once.
    assert_eq!(
        engine.presence_window().expect("setting"),
        PresenceSetting::FiveMinutes
    );
    assert_eq!(
        engine
            .set_presence_window(PresenceSetting::Always, None)
            .expect("tighten"),
        PresenceSetting::Always
    );
    let ask = asked(engine.field_value(item.id.clone(), "password".into()));
    assert_eq!(ask.lasts, None, "Always: this value only");
    let value = ask.value.expect("the value it hands out");
    assert_eq!(value.kind, PresenceValueKind::Show);
    assert_eq!(value.title.as_deref(), Some("GitHub"));
    // The app closes its question unanswered.
    engine.presence_cancel();
    assert!(!engine.held_connection().asking);

    // Loosening asks for Touch ID, off here, so the password; it opens no
    // window, and moving off Always opens a new long connection with
    // `hold` (the ADR's own choice 1).
    let before = engine.held_connection().generation;
    assert!(matches!(
        engine.set_presence_window(PresenceSetting::FiveMinutes, None),
        Err(KlavError::BiometryUnavailable { .. })
    ));
    assert_eq!(
        engine.held_connection().generation,
        before,
        "nothing changed"
    );
    assert_eq!(
        engine
            .set_presence_window(PresenceSetting::FiveMinutes, Some(PASSWORD.into()))
            .expect("loosen"),
        PresenceSetting::FiveMinutes
    );
    let after = engine.held_connection();
    assert_eq!(after.generation, before + 1, "a new long connection");
    assert!(after.connected);
    assert_eq!(after.hold, HoldState::NotSupported);
    let ask = asked(engine.field_value(item.id.clone(), "password".into()));
    assert_eq!(ask.lasts, Some(PresenceLasts::FiveMinutes));
    // 5 minutes → While unlocked isn't a move off Always: same connection.
    let before = engine.held_connection().generation;
    engine.presence_cancel();
    engine
        .set_presence_window(PresenceSetting::WhileUnlocked, Some(PASSWORD.into()))
        .expect("loosen again");
    assert_eq!(engine.held_connection().generation, before);
    engine
        .set_presence_window(PresenceSetting::FiveMinutes, None)
        .expect("tighten again");

    // An item edited between the question and the answer is not handed
    // out (Omar's decision F), and klavd's `conflict` is told apart.
    let ask = asked(engine.field_value(item.id.clone(), "password".into()));
    assert_eq!(ask.lasts, Some(PresenceLasts::FiveMinutes));
    engine
        .edit_item(
            item.id.clone(),
            ItemEdit {
                title: Some("GitHub (work)".into()),
                ..ItemEdit::default()
            },
        )
        .expect("edit");
    assert!(matches!(
        engine.field_value_with_password(item.id.clone(), "password".into(), PASSWORD.into()),
        Err(KlavError::ChangedWhileConfirming { .. })
    ));

    // A later unlock: its question names the window, the app's password
    // unlock sends it as `shown`, and the window opens.
    engine.lock().expect("lock");
    let question = engine.unlock_question().expect("question");
    assert_eq!(question.lasts, Some(PresenceLasts::FiveMinutes));
    engine
        .unlock(Some(PASSWORD.into()), Some(PresenceSetting::FiveMinutes))
        .expect("unlock");
    assert_eq!(
        engine
            .field_value(item.id.clone(), "password".into())
            .expect("the unlock's window"),
        SECRET
    );
    // An unlock whose question said nothing (`shown` Always) opens none.
    engine.lock().expect("lock");
    engine.unlock_question().expect("question");
    engine.unlock(Some(PASSWORD.into()), None).expect("unlock");
    asked(engine.field_value(item.id.clone(), "password".into()));
    engine.presence_cancel();

    // The other values of the window row go the same way.
    assert!(matches!(
        engine.notes(item.id.clone()),
        Err(KlavError::PresenceRequired { .. })
    ));
    engine.presence_cancel();
    assert!(matches!(
        engine.previous_password(item.id.clone(), 0),
        Err(KlavError::PresenceRequired { .. }
            | KlavError::NotFound { .. }
            | KlavError::Invalid { .. })
    ));
    engine.presence_cancel();

    // `shutdown` drops the long connection first.
    engine.shutdown().expect("shutdown");
    assert!(!engine.held_connection().connected);
}

#[test]
fn with_the_gate_off_nothing_asks_and_the_setting_is_not_offered() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let home = dir.path().join("klav");
    let (_daemon, engine) = account(&server, &home, false);
    assert!(!engine.status().presence_gate);
    let question = engine.unlock_question().expect("question");
    assert!(!question.gate);
    assert_eq!(engine.held_connection().hold, HoldState::NotSupported);
    let outcome = engine.unlock(Some(PASSWORD.into()), None).expect("unlock");
    assert!(!outcome.already_unlocked && !outcome.passkey_setting_reset);
    let item = engine.create_item(login("GitHub")).expect("create");
    assert_eq!(
        engine
            .field_value(item.id.clone(), "password".into())
            .expect("value"),
        SECRET
    );
    // A password the engine wasn't asked for is never sent.
    assert_eq!(
        engine
            .field_value_with_password(item.id.clone(), "password".into(), "anything".into())
            .expect("value"),
        SECRET
    );
    assert!(matches!(
        engine.presence_window(),
        Err(KlavError::NotSupported { .. })
    ));
    assert!(matches!(
        engine.set_presence_window(PresenceSetting::WhileUnlocked, None),
        Err(KlavError::NotSupported { .. })
    ));
    // A Touch ID unlock opens a new long connection, declared first.
    let generation = engine.held_connection().generation;
    let _ = engine.unlock(None, None);
    assert_eq!(engine.held_connection().generation, generation + 1);
}

// ---------------------------------------------------------------------------
// A scripted klavd on the socket.

/// Every request line the scripted `klavd` read, with its connection's
/// number (from 1, in the order they connected).
type Log = Arc<Mutex<Vec<(usize, Value)>>>;

/// What the scripted `klavd` answers: `None` closes the connection.
type Script = Arc<dyn Fn(usize, &Value) -> Option<Value> + Send + Sync>;

struct Scripted {
    log: Log,
    _dir: tempfile::TempDir,
    home: String,
}

impl Scripted {
    fn start(script: impl Fn(usize, &Value) -> Option<Value> + Send + Sync + 'static) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let listener = UnixListener::bind(dir.path().join("klavd.sock")).expect("bind");
        let log: Log = Arc::default();
        let script: Script = Arc::new(script);
        let thread_log = log.clone();
        std::thread::spawn(move || {
            for (n, stream) in listener.incoming().enumerate() {
                let Ok(stream) = stream else { return };
                let log = thread_log.clone();
                let script = script.clone();
                std::thread::spawn(move || serve(n + 1, stream, &log, &*script));
            }
        });
        Self {
            log,
            home: dir.path().display().to_string(),
            _dir: dir,
        }
    }

    fn log(&self) -> Vec<(usize, Value)> {
        self.log.lock().expect("log").clone()
    }

    /// The requests sent on connection `conn`, as `op`s.
    fn ops_on(&self, conn: usize) -> Vec<String> {
        self.log()
            .into_iter()
            .filter(|(c, _)| *c == conn)
            .map(|(_, e)| e["request"]["op"].as_str().unwrap_or("?").to_owned())
            .collect()
    }
}

fn serve(
    conn: usize,
    stream: UnixStream,
    log: &Log,
    script: &(dyn Fn(usize, &Value) -> Option<Value> + Send + Sync),
) {
    let mut writer = stream.try_clone().expect("clone");
    let reader = BufReader::new(stream);
    for line in reader.lines() {
        let Ok(line) = line else { return };
        let envelope: Value = serde_json::from_str(&line).expect("json");
        log.lock().expect("log").push((conn, envelope.clone()));
        let Some(mut answer) = script(conn, &envelope) else {
            return;
        };
        answer["v"] = json!(1);
        if answer.get("id").is_none() {
            answer["id"] = envelope["id"].clone();
        }
        let mut out = serde_json::to_vec(&answer).expect("json");
        out.push(b'\n');
        if writer.write_all(&out).is_err() {
            return;
        }
    }
}

fn op(envelope: &Value) -> &str {
    envelope["request"]["op"].as_str().unwrap_or("")
}

fn ok(value: Value) -> Option<Value> {
    Some(json!({ "ok": value }))
}

fn error(code: &str, message: &str) -> Option<Value> {
    Some(json!({ "error": { "code": code, "message": message } }))
}

/// `status`, with `presence` when the gate is on.
fn status(unlocked: bool, presence: Option<Value>) -> Option<Value> {
    let mut s = json!({
        "version": "0.9.2", "protocol": 1, "pid": 4242, "logged_in": true,
        "unlocked": unlocked, "idle_lock_secs": 900,
    });
    if let Some(p) = presence {
        s["presence"] = p;
    }
    ok(s)
}

fn view(secret: &str) -> Option<Value> {
    ok(json!({
        "id": ITEM, "reference": "klav://Personal/General/GitHub",
        "vault_id": "6f1c1b2e-0c1d-4a7b-9e55-1f2a3b4c5d6f", "vault": "Personal",
        "project_id": "6f1c1b2e-0c1d-4a7b-9e55-1f2a3b4c5d70", "project": "General",
        "kind": "login", "title": "GitHub", "urls": [], "tags": [], "version": 1,
        "updated_at": 0, "trashed": false,
        "fields": [{
            "id": "6f1c1b2e-0c1d-4a7b-9e55-1f2a3b4c5d71", "name": "password",
            "label": "Password", "kind": "password", "secret": true, "filled": true,
            "value": secret,
        }],
        "has_notes": false, "revealed": true,
    }))
}

const ITEM: &str = "6f1c1b2e-0c1d-4a7b-9e55-1f2a3b4c5d6e";

fn the_ask() -> Value {
    json!({ "key": "connection", "window": "5m", "lasts": "5m" })
}

#[test]
fn an_older_klavd_refuses_hold_and_the_long_connection_goes_on() {
    let klavd = Scripted::start(|_, e| match op(e) {
        // A klavd older than `hold` can't read the request: `id` 0.
        "hold" => Some(
            json!({ "id": 0, "error": { "code": "bad_request", "message": "malformed request" } }),
        ),
        "status" => status(true, None),
        "view" => view(SECRET),
        "totp" => ok(json!({ "code": "123456", "remaining": 20 })),
        _ => error("internal", "unexpected"),
    });
    let engine = DaemonEngine::new(klavd.home.clone()).expect("engine");
    assert!(engine.status().running);
    assert_eq!(
        engine
            .field_value(ITEM.into(), "password".into())
            .expect("value"),
        SECRET
    );
    assert_eq!(engine.totp(ITEM.into()).expect("code").code, "123456");
    assert!(engine.status().running);
    assert_eq!(engine.held_connection().hold, HoldState::OlderKlavd);

    // The status poll on its own connection each time; `hold` first on the
    // long one, then both values on it.
    let log = klavd.log();
    let long = log
        .iter()
        .find(|(_, e)| op(e) == "hold")
        .map(|(c, _)| *c)
        .expect("hold sent");
    assert_eq!(klavd.ops_on(long), ["hold", "view", "totp"]);
    let polls: Vec<usize> = log
        .iter()
        .filter(|(_, e)| op(e) == "status")
        .map(|(c, _)| *c)
        .collect();
    assert_eq!(polls.len(), 2);
    assert!(
        polls
            .iter()
            .all(|c| *c != long && klavd.ops_on(*c) == ["status"])
    );
}

#[test]
fn the_password_goes_only_where_it_was_asked_for() {
    let klavd = Scripted::start(|conn, e| match op(e) {
        "hold" => ok(json!({ "declared": true, "held": false })),
        "view" if e["request"]["password"].is_null() => Some(
            json!({ "error": { "code": "presence_required", "message": "presence", "presence": the_ask() } }),
        ),
        // klavd restarted: the first connection closes at the resend.
        "view" if conn == 1 && e["request"]["password"] == "restart" => None,
        // Another master password is being checked (the gate on).
        "view" if e["request"]["password"] == "busy" => error(
            "presence_busy",
            "another program is asking for presence in Klav: try again once that prompt closes",
        ),
        "view" => view(SECRET),
        "totp" => ok(json!({ "code": "654321", "remaining": 10 })),
        _ => error("internal", "unexpected"),
    });
    let engine = DaemonEngine::new(klavd.home.clone()).expect("engine");

    let ask = asked(engine.field_value(ITEM.into(), "password".into()));
    assert_eq!(ask.key, PresenceKeyKind::Connection);
    assert_eq!(ask.lasts, Some(PresenceLasts::FiveMinutes));
    assert_eq!(
        engine.held_connection().hold,
        HoldState::Declared { held: false }
    );
    // Another value waits: nothing is sent for it.
    assert!(matches!(
        engine.totp(ITEM.into()),
        Err(KlavError::PresenceBusy {
            in_this_app: true,
            ..
        })
    ));
    assert_eq!(klavd.ops_on(1), ["hold", "view"]);
    // Busy with another password check: said so, and the question stays
    // answerable (asked again, with nothing).
    assert!(matches!(
        engine.field_value_with_password(ITEM.into(), "password".into(), "busy".into()),
        Err(KlavError::PresenceBusy {
            password_check: true,
            in_this_app: false,
            ..
        })
    ));
    assert!(engine.held_connection().asking);
    assert_eq!(klavd.ops_on(1), ["hold", "view", "view", "view"]);
    // The answer: the same request, with the password, on connection 1.
    assert_eq!(
        engine
            .field_value_with_password(ITEM.into(), "password".into(), PASSWORD.into())
            .expect("value"),
        SECRET
    );
    let sent = klavd.log();
    let (conn, resend) = sent.last().expect("resend");
    assert_eq!(*conn, 1);
    assert_eq!(resend["request"]["password"], PASSWORD);
    assert_eq!(resend["request"]["query"], ITEM);
    assert_eq!(resend["request"]["reveal"], true);
    // A value nobody asked about goes without the password it came with.
    assert_eq!(
        engine
            .totp_with_password(ITEM.into(), PASSWORD.into())
            .expect("code")
            .code,
        "654321"
    );
    let (_, totp) = klavd.log().last().cloned().expect("totp");
    assert!(totp["request"]["password"].is_null(), "{totp}");

    // klavd goes away at the resend: the ask went with the connection, so
    // the password is not sent again on the new one, which asks anew.
    asked(engine.field_value(ITEM.into(), "password".into()));
    let ask =
        asked(engine.field_value_with_password(ITEM.into(), "password".into(), "restart".into()));
    assert_eq!(ask.lasts, Some(PresenceLasts::FiveMinutes));
    assert_eq!(klavd.ops_on(2), ["hold", "view"]);
    assert!(
        klavd
            .log()
            .iter()
            .filter(|(c, _)| *c == 2)
            .all(|(_, e)| e["request"]["password"].is_null()),
        "no password on the new connection"
    );
}

#[test]
fn a_password_unlock_says_what_its_question_said_on_the_declared_connection() {
    let klavd = Scripted::start(|_, e| match op(e) {
        "hold" => ok(json!({ "declared": true, "held": false })),
        "status" => status(
            false,
            Some(json!({ "key": "connection", "declared": true, "lasts": "until_lock" })),
        ),
        "unlock" => ok(json!({
            "version": "0.9.2", "protocol": 1, "pid": 4242, "logged_in": true,
            "unlocked": true, "idle_lock_secs": 900,
        })),
        _ => error("internal", "unexpected"),
    });
    let engine = DaemonEngine::new(klavd.home.clone()).expect("engine");
    let q = engine.unlock_question().expect("question");
    assert!(q.gate && q.declared);
    assert_eq!(q.lasts, Some(PresenceLasts::UntilLock));
    engine
        .unlock(Some(PASSWORD.into()), Some(PresenceSetting::WhileUnlocked))
        .expect("unlock");
    // `hold`, the question's `status`, then the unlock's own `status` and
    // the unlock, all on the connection the question opened.
    assert_eq!(klavd.ops_on(1), ["hold", "status", "status", "unlock"]);
    let (_, unlock) = klavd
        .log()
        .into_iter()
        .find(|(_, e)| op(e) == "unlock")
        .expect("unlock");
    assert_eq!(unlock["shown"], "unlocked");
    assert!(unlock.get("untyped").is_none(), "typed in the app's window");
    assert!(unlock.get("notify").is_none());

    // With no window named, `always`: the unlock opens none.
    engine.unlock(Some(PASSWORD.into()), None).expect("unlock");
    let (_, unlock) = klavd
        .log()
        .into_iter()
        .rfind(|(_, e)| op(e) == "unlock")
        .expect("unlock");
    assert_eq!(unlock["shown"], "always");

    // A Touch ID unlock: a new long connection, `hold` first, no `shown`.
    engine.unlock(None, None).expect("touch id");
    assert_eq!(klavd.ops_on(2), ["hold", "status", "unlock"]);
    let (_, unlock) = klavd.log().last().cloned().expect("unlock");
    assert!(unlock.get("shown").is_none());
}

#[test]
fn an_older_klavd_gets_no_new_envelope_fields() {
    let klavd = Scripted::start(|_, e| match op(e) {
        "hold" => Some(
            json!({ "id": 0, "error": { "code": "bad_request", "message": "malformed request" } }),
        ),
        "status" => status(false, None),
        "unlock" if e.get("shown").is_some() => Some(
            json!({ "id": 0, "error": { "code": "bad_request", "message": "malformed request" } }),
        ),
        "unlock" => status(true, None),
        "presence_window" => Some(
            json!({ "id": 0, "error": { "code": "bad_request", "message": "malformed request" } }),
        ),
        _ => error("internal", "unexpected"),
    });
    let engine = DaemonEngine::new(klavd.home.clone()).expect("engine");
    assert!(!engine.unlock_question().expect("question").gate);
    engine
        .unlock(Some(PASSWORD.into()), Some(PresenceSetting::FiveMinutes))
        .expect("unlock");
    assert!(matches!(
        engine.presence_window(),
        Err(KlavError::NotSupported { .. })
    ));
}

#[test]
fn already_unlocked_and_the_old_passkey_setting_reach_the_app() {
    let klavd = Scripted::start(|_, e| match op(e) {
        "hold" => error("not_supported", "this klavd does not hold connections yet"),
        "status" => status(
            true,
            Some(json!({ "elsewhere": true, "key": "connection" })),
        ),
        "unlock" => Some(json!({
            "ok": {
                "version": "0.9.2", "protocol": 1, "pid": 4242, "logged_in": true,
                "unlocked": true, "idle_lock_secs": 900, "already_unlocked": true,
            },
            "warnings": [
                "Klav no longer reads your old passkey setting: passkeys now ask every time. Choose again in the extension's settings",
                "offline: \u{1b}[2Jthe server didn't answer",
            ],
        })),
        _ => error("internal", "unexpected"),
    });
    let engine = DaemonEngine::new(klavd.home.clone()).expect("engine");
    let q = engine.unlock_question().expect("question");
    assert!(q.elsewhere);
    let outcome = engine.unlock(None, None).expect("unlock");
    assert!(outcome.already_unlocked);
    assert!(outcome.passkey_setting_reset);
    assert_eq!(outcome.warnings.len(), 1);
    assert!(
        !outcome.warnings[0].contains('\u{1b}'),
        "{:?}",
        outcome.warnings
    );
}

#[test]
fn busy_answers_and_conflicts_are_told_apart() {
    // klavd's words, as `crates/klav-daemon/src/presence.rs` and
    // `server.rs` write them: the engine tells these `conflict`s apart by
    // their start.
    let klavd = Scripted::start(|_, e| match op(e) {
        "hold" => error("not_supported", "no"),
        "view" => error(
            "presence_busy",
            "another program is asking for presence in Klav: try again once that prompt closes",
        ),
        "totp" => error(
            "conflict",
            "klavd is checking another master password: try again in a moment",
        ),
        "previous_password" => error(
            "conflict",
            "the item changed while you confirmed: nothing was handed out; run the command again",
        ),
        "generated_value" => error("conflict", "version 3 on the server"),
        "decide_approval" => error(
            "conflict",
            "klavd is checking another master password: try again in a moment",
        ),
        _ => error("internal", "unexpected"),
    });
    let engine = DaemonEngine::new(klavd.home.clone()).expect("engine");
    assert!(matches!(
        engine.field_value(ITEM.into(), "password".into()),
        Err(KlavError::PresenceBusy {
            password_check: false,
            in_this_app: false,
            ..
        })
    ));
    assert!(matches!(
        engine.totp(ITEM.into()),
        Err(KlavError::PresenceBusy {
            password_check: true,
            ..
        })
    ));
    assert!(matches!(
        engine.previous_password(ITEM.into(), 0),
        Err(KlavError::ChangedWhileConfirming { .. })
    ));
    assert!(matches!(
        engine.generated_value(1),
        Err(KlavError::Conflict { .. })
    ));
    // Gate off: an operation that already asks, whose password check finds
    // another running, is busy, not "the item changed on another device".
    assert!(matches!(
        engine.decide_approval_with_password(
            "a".into(),
            true,
            0,
            "d".into(),
            Some(PASSWORD.into())
        ),
        Err(KlavError::PresenceBusy {
            password_check: true,
            ..
        })
    ));
}

#[test]
fn a_call_on_the_long_connection_never_queues_behind_a_dialog_for_long() {
    // A Touch ID unlock that waits on its dialog holds the long connection;
    // a value meanwhile is told the app is busy instead of waiting on it.
    let (release, wait) = std::sync::mpsc::channel::<()>();
    let wait = Mutex::new(wait);
    let klavd = Scripted::start(move |_, e| match op(e) {
        "hold" => error("not_supported", "no"),
        "status" => status(false, None),
        "unlock" => {
            let _ = wait
                .lock()
                .expect("wait")
                .recv_timeout(Duration::from_secs(20));
            status(true, None)
        }
        "view" => view(SECRET),
        _ => error("internal", "unexpected"),
    });
    let engine = DaemonEngine::new(klavd.home.clone()).expect("engine");
    let unlocking = {
        let engine = engine.clone();
        std::thread::spawn(move || engine.unlock(None, None))
    };
    wait_until("the unlock's request", || {
        klavd.log().iter().any(|(_, e)| op(e) == "unlock")
    });
    let started = std::time::Instant::now();
    assert!(matches!(
        engine.field_value(ITEM.into(), "password".into()),
        Err(KlavError::PresenceBusy {
            in_this_app: true,
            ..
        })
    ));
    assert!(started.elapsed() < Duration::from_secs(10));
    // The menu bar's status never waits for it.
    assert!(engine.status().running);
    release.send(()).expect("release");
    unlocking.join().expect("thread").expect("unlock");
    assert_eq!(
        engine
            .field_value(ITEM.into(), "password".into())
            .expect("value"),
        SECRET
    );
}
