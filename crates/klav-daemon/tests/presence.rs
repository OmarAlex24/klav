//! The presence gate through the socket (ADR 0041, layer 2), with Touch
//! ID off so the master password stands in for it: what each gated
//! operation answers, the window the unlock opens, the sealed settings,
//! and the old passkey file. The gate is always on since layer 6.
//!
//! Each test talks over one connection: where this process has no
//! terminal (CI on Linux), its window key is the connection, and a new
//! connection would be a new key. Two keys are in the unit tests
//! (`presence/tests.rs`).

mod common;

use std::time::Duration;

use common::ServerProcess;
use klav_client::ops::SecretText;
use klav_client::{Home, SignupRequest, signup};
use klav_core::crypto::kdf::MasterPassword;
use klav_core::model::item::{Item, ItemKind};
use klav_daemon::client::DaemonClient;
use klav_daemon::protocol::{AskValue, AskValueKind, DaemonStatus, ErrorBody, ErrorCode, Request};
use klav_daemon::uv::Window;
use klav_daemon::{Config, serve};
use serde_json::Value;

const PASSWORD: &str = "correct horse battery staple";

/// An account with one login, «GitHub», and the home `klavd` will use.
async fn account(server: &ServerProcess, home: &Home) {
    let (mut unlocked, _kit) = signup(
        home,
        SignupRequest {
            server: server.url.clone(),
            email: "ana@example.com".into(),
            password: MasterPassword::new(PASSWORD),
            device_name: "laptop".into(),
            device_kind: klav_proto::auth::DeviceKind::Cli,
            invite: None,
        },
    )
    .await
    .expect("sign-up");
    let vault = unlocked.vaults()[0].id;
    let project = unlocked.projects(Some(vault))[0].id;
    let item = Item::from_template(ItemKind::Login, "GitHub").expect("template");
    unlocked.add_item(vault, project, &item).await.expect("add");
}

struct Daemon {
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<Result<(), String>>,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }
}

async fn daemon(home: &Home) -> Daemon {
    let config = Config {
        home: home.clone(),
        idle_lock: Duration::from_secs(600),
        touch_id: false,
        sync_after: klav_daemon::SYNC_AFTER,
        build: None,
    };
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(serve(config, async {
        let _ = stopped.await;
    }));
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    while DaemonClient::connect(home).await.is_none() {
        assert!(!task.is_finished(), "klavd stopped before it listened");
        assert!(
            tokio::time::Instant::now() < deadline,
            "klavd did not listen"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    Daemon {
        stop: Some(stop),
        task,
    }
}

/// One connection to `klavd`, reused for every request of a test.
struct Conn(tokio::sync::Mutex<DaemonClient>);

async fn conn(home: &Home) -> Conn {
    Conn(tokio::sync::Mutex::new(
        DaemonClient::connect(home).await.expect("klavd"),
    ))
}

async fn call<T: serde::de::DeserializeOwned>(
    c: &Conn,
    request: Request,
) -> Result<(T, Vec<String>), ErrorBody> {
    c.0.lock().await.call::<T>(request).await
}

async fn unlock(c: &Conn) -> (DaemonStatus, Vec<String>) {
    call(
        c,
        Request::Unlock {
            password: Some(SecretText::new(PASSWORD)),
            passkey_flow: false,
        },
    )
    .await
    .expect("unlock")
}

async fn lock(c: &Conn) {
    let (status, _) = call::<DaemonStatus>(c, Request::Lock).await.expect("lock");
    assert!(!status.unlocked);
}

async fn status(c: &Conn) -> DaemonStatus {
    call(c, Request::Status).await.expect("status").0
}

fn view(password: Option<&str>) -> Request {
    Request::View {
        query: "GitHub".into(),
        reveal: true,
        password: password.map(SecretText::new),
    }
}

async fn presence_window(c: &Conn, window: Option<Window>, password: Option<&str>) -> Value {
    call::<Value>(
        c,
        Request::PresenceWindow {
            window,
            password: password.map(SecretText::new),
        },
    )
    .await
    .map(|(v, _)| v)
    .unwrap_or_else(|e| panic!("presence_window: {e:?}"))
}

async fn code(c: &Conn, request: Request) -> ErrorCode {
    call::<Value>(c, request).await.expect_err("refused").code
}

/// Every operation of §3's «window» row.
/// One request per operation of the window row, each naming something that
/// exists: an instant of the generator history (`created_at`) and a
/// reference to a field (`reference`), since `klavd` resolves both before
/// it asks (Omar's decision K of 2026-11-19).
fn window_ops(created_at: i64, reference: &str) -> Vec<Request> {
    vec![
        view(None),
        Request::PreviousPassword {
            query: "GitHub".into(),
            index: 0,
            password: None,
        },
        Request::Totp {
            query: "GitHub".into(),
            field: None,
            password: None,
        },
        Request::GeneratedValue {
            created_at,
            password: None,
        },
        Request::Resolve {
            references: vec![reference.to_owned()],
            variables_only: false,
            password: None,
        },
        Request::Autofill {
            item: "GitHub".into(),
            url: "https://github.com".into(),
            part: klav_client::fill::FillPart::All,
            chosen: false,
            password: None,
        },
    ]
}

#[tokio::test(flavor = "multi_thread")]
async fn with_the_gate_on_values_follow_the_window_and_the_sealed_setting() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let home = Home::at(dir.path().join("home"));
    account(&server, &home).await;
    // A passkey setting from before the gate: only checked for, then gone.
    std::fs::write(home.file("passkeys.json"), br#"{"window":"unlocked"}"#).unwrap();
    let _klavd = daemon(&home).await;
    let c = conn(&home).await;

    // Locked: both settings say `locked`, and `status` leaves the passkey
    // setting out.
    assert_eq!(
        code(
            &c,
            Request::PresenceWindow {
                window: None,
                password: None
            }
        )
        .await,
        ErrorCode::Locked
    );
    assert_eq!(
        code(
            &c,
            Request::PasskeyUv {
                window: None,
                password: None
            }
        )
        .await,
        ErrorCode::Locked
    );
    assert_eq!(status(&c).await.passkey_uv, None);

    // The unlock warns once and deletes the old file; the passkey setting
    // is Always.
    let (s, warnings) = unlock(&c).await;
    assert!(s.unlocked && !s.already_unlocked);
    assert_eq!(
        warnings
            .iter()
            .filter(|w| w.contains("old passkey setting"))
            .count(),
        1,
        "{warnings:?}"
    );
    assert!(!home.file("passkeys.json").exists());
    assert_eq!(status(&c).await.passkey_uv, Some(Window::Always));

    // No presence blob: 5 minutes. Which window the unlock opened depends
    // on the key of whatever runs this test (a terminal, a parent, or none
    // at all), so this binary test doesn't assert it: `server::gate_tests`
    // does, through the socket, with fixed keys.
    assert_eq!(
        presence_window(&c, None, None).await,
        serde_json::json!({ "window": "5m" })
    );

    // Tightening needs no verification and closes nothing it shouldn't…
    assert_eq!(
        presence_window(&c, Some(Window::Always), None).await["window"],
        "always"
    );
    // …but now every value asks, and the client is told what to ask for.
    let created_at = call::<Value>(
        &c,
        Request::GeneratorRecord {
            value: SecretText::new("generated for the test"),
            host: None,
        },
    )
    .await
    .expect("recorded")
    .0["created_at"]
        .as_i64()
        .expect("created_at");
    let github = call::<Value>(
        &c,
        Request::View {
            query: "GitHub".into(),
            reveal: false,
            password: None,
        },
    )
    .await
    .expect("metadata");
    let reference = format!(
        "{}/username",
        github.0["reference"].as_str().expect("reference")
    );
    for request in window_ops(created_at, &reference) {
        let what = format!("{request:?}");
        let e = call::<Value>(&c, request).await.expect_err(&what);
        assert_eq!(e.code, ErrorCode::PresenceRequired, "{what}: {e:?}");
        let ask = e.presence.expect("payload");
        assert_eq!(ask.window, Window::Always, "{what}");
        assert_eq!(ask.lasts, None, "{what}");
        assert!(ask.value.is_some(), "{what}");
    }
    let ask = call::<Value>(&c, view(None))
        .await
        .expect_err("asks")
        .presence
        .expect("payload");
    // The kind of value and the item klavd resolved, for the client to
    // word: never prose in the Mac's language (finding 6 of layer 3's
    // review).
    assert_eq!(
        ask.value,
        Some(AskValue {
            kind: AskValueKind::Show,
            title: Some("GitHub".into()),
            count: None,
        })
    );
    // A wrong password grants nothing, and spends the ask: one try each.
    assert_eq!(
        code(&c, view(Some("not the password"))).await,
        ErrorCode::WrongCredentials
    );
    assert_eq!(
        code(&c, view(Some(PASSWORD))).await,
        ErrorCode::PresenceRequired,
        "a password that answers no ask isn't checked"
    );
    // The right one, answering the ask, covers one value.
    call::<Value>(&c, view(Some(PASSWORD)))
        .await
        .expect("with the password");
    assert_eq!(code(&c, view(None)).await, ErrorCode::PresenceRequired);

    // The setting is sealed local data (kind 0x41).
    let blob = std::fs::read(home.file("presence.bin")).expect("sealed setting");
    assert_eq!(&blob[..2], &[0x01, 0x41]);

    // Loosening asks for the person, and its verification opens nothing.
    assert_eq!(
        code(
            &c,
            Request::PresenceWindow {
                window: Some(Window::FiveMinutes),
                password: None
            }
        )
        .await,
        ErrorCode::BiometryUnavailable
    );
    assert_eq!(
        presence_window(&c, Some(Window::FiveMinutes), Some(PASSWORD)).await["window"],
        "5m"
    );
    assert_eq!(code(&c, view(None)).await, ErrorCode::PresenceRequired);

    // The passkey setting is sealed the same way, never as the old file.
    let (v, _) = call::<Value>(
        &c,
        Request::PasskeyUv {
            window: Some(Window::FiveMinutes),
            password: Some(SecretText::new(PASSWORD)),
        },
    )
    .await
    .expect("passkey setting");
    assert_eq!(v["window"], "5m");
    assert!(home.file("passkey-window.bin").exists());
    assert!(!home.file("passkeys.json").exists());

    // An unlock while unlocked, from the same key, with the password:
    // nobody else unlocked it.
    let (s, _) = unlock(&c).await;
    assert!(s.unlocked && !s.already_unlocked);

    // `hold` is for layer 6.
    assert_eq!(code(&c, Request::Hold).await, ErrorCode::NotSupported);

    // The local key opens the settings again after a lock: the unlock
    // holds it.
    lock(&c).await;
    assert_eq!(status(&c).await.passkey_uv, None);
    let (_, warnings) = unlock(&c).await;
    assert!(
        !warnings.iter().any(|w| w.contains("old passkey setting")),
        "warned once: {warnings:?}"
    );
    assert_eq!(presence_window(&c, None, None).await["window"], "5m");
    assert_eq!(status(&c).await.passkey_uv, Some(Window::FiveMinutes));

    // An edited blob reads as Always; a deleted one as the default.
    lock(&c).await;
    let mut edited = std::fs::read(home.file("presence.bin")).unwrap();
    let last = edited.len() - 1;
    edited[last] ^= 1;
    std::fs::write(home.file("presence.bin"), edited).unwrap();
    unlock(&c).await;
    assert_eq!(presence_window(&c, None, None).await["window"], "always");
    assert_eq!(code(&c, view(None)).await, ErrorCode::PresenceRequired);
    lock(&c).await;
    std::fs::remove_file(home.file("presence.bin")).unwrap();
    unlock(&c).await;
    assert_eq!(presence_window(&c, None, None).await["window"], "5m");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_socket_renamed_and_replaced_stops_klavd() {
    let dir = tempfile::tempdir().expect("tempdir");
    let home = Home::at(dir.path().join("home"));
    home.ensure().expect("home");
    let mut klavd = daemon(&home).await;
    let socket = home.socket_path();
    std::fs::rename(&socket, dir.path().join("moved.sock")).unwrap();
    let relay = tokio::net::UnixListener::bind(&socket).expect("a relay binds the path");
    let stopped = tokio::time::timeout(Duration::from_secs(15), &mut klavd.task)
        .await
        .expect("klavd stops when the path names another socket");
    assert!(stopped.expect("join").is_ok());
    // It leaves the other socket alone.
    assert!(socket.exists());
    drop(relay);
}
