//! The presence gate through the socket, with a fake Touch ID and window
//! keys the test chooses (ADR 0041, layer 2; the second layer-2 review).
//! The fake never reaches the Secure Enclave or shows a dialog: every Touch
//! ID call of `klavd` goes through [`Biometric`], and the fake answers all
//! of them. The keys don't depend on what runs the test: each connection
//! takes the next one from [`TestSeams::keys`].

#[path = "../../tests/common/mod.rs"]
mod common;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::ServerProcess;
use klav_client::ops::SecretText;
use klav_client::{Home, SignupRequest, signup};
use klav_core::crypto::kdf::{KdfParams, MasterPassword, derive_kek};
use klav_core::crypto::keys::LocalKey;
use klav_core::crypto::local::{LocalContext, derive_local_key};
use klav_core::crypto::secret_key::SecretKey;
use klav_core::model::item::{Item, ItemKind};
use serde_json::Value;

use super::{BeforePrompt, Config, TestSeams, serve_with};
use crate::client::DaemonClient;
use crate::peer;
use crate::presence::Key;
use crate::protocol::{AskLasts, BiometricStatus, DaemonStatus, ErrorBody, ErrorCode, Request};
use crate::touchid::Biometric;
use crate::uv::Window;

const PERSON: &str = "correct horse battery staple";
const THEIRS: &str = "a password the program chose";

/// The files `unlock_with_password` reads to open an account.
const FILES: [&str; 4] = ["account.json", "secret-key", "session.bin", "cache.bin"];

// ------------------------------------------------------------ the fake

/// One prompt held open until the test releases it.
struct Hold {
    opened: mpsc::Sender<()>,
    release: mpsc::Receiver<()>,
}

/// A Touch ID that says yes, counts its prompts, and can hold one open.
struct Fake {
    available: AtomicBool,
    /// The person cancels every gate prompt (`authenticate`).
    cancels: AtomicBool,
    prompts: Mutex<Vec<String>>,
    hold: Mutex<Option<Hold>>,
}

impl Fake {
    fn new(available: bool) -> Arc<Fake> {
        Arc::new(Fake {
            available: AtomicBool::new(available),
            cancels: AtomicBool::new(false),
            prompts: Mutex::new(Vec::new()),
            hold: Mutex::new(None),
        })
    }

    fn asked(&self) -> usize {
        self.prompts.lock().unwrap().len()
    }

    fn last(&self) -> String {
        self.prompts
            .lock()
            .unwrap()
            .last()
            .cloned()
            .unwrap_or_default()
    }

    /// The next prompt stays open until `release` is sent to; `opened`
    /// says when it opened.
    fn hold_next(&self) -> (mpsc::Receiver<()>, mpsc::Sender<()>) {
        let (opened_tx, opened) = mpsc::channel();
        let (release, release_rx) = mpsc::channel();
        *self.hold.lock().unwrap() = Some(Hold {
            opened: opened_tx,
            release: release_rx,
        });
        (opened, release)
    }

    /// A prompt: refused when Touch ID isn't available, else recorded and,
    /// if held, kept open.
    fn prompt(&self, reason: &str) -> bool {
        if !self.available.load(Ordering::SeqCst) {
            return false;
        }
        self.prompts.lock().unwrap().push(reason.to_owned());
        let hold = self.hold.lock().unwrap().take();
        if let Some(hold) = hold {
            let _ = hold.opened.send(());
            let _ = hold.release.recv();
        }
        true
    }
}

fn unavailable() -> ErrorBody {
    ErrorBody {
        code: ErrorCode::BiometryUnavailable,
        message: "Touch ID is not available".into(),
        paused: None,
        presence: None,
    }
}

struct Shared(Arc<Fake>);

impl Biometric for Shared {
    fn status(&self, _home: &Home, enabled: bool) -> BiometricStatus {
        let available = enabled && self.0.available.load(Ordering::SeqCst);
        BiometricStatus {
            available,
            enrolled: available,
            password_required: None,
        }
    }

    fn enrol(&self, _home: &Home, _ctx: LocalContext, _key: &LocalKey) -> Result<(), String> {
        Ok(())
    }

    /// The local key the person's Touch ID would unwrap: derived here from
    /// the person's password, as the enrolment wrapped it.
    fn unlock(&self, home: &Home, ctx: LocalContext, reason: &str) -> Result<LocalKey, ErrorBody> {
        if !self.0.prompt(reason) {
            return Err(unavailable());
        }
        let account = klav_client::account(home).expect("account");
        let text = std::fs::read_to_string(home.file("secret-key")).expect("secret key");
        let secret_key = SecretKey::parse(text.trim()).expect("secret key");
        let params = KdfParams::decode(account.kdf_params.as_bytes()).expect("params");
        let kek = derive_kek(&MasterPassword::new(PERSON), &secret_key, &params).expect("kek");
        Ok(derive_local_key(&kek, &ctx))
    }

    fn confirm_with_key(
        &self,
        _home: &Home,
        _ctx: LocalContext,
        reason: &str,
    ) -> Result<(), ErrorBody> {
        if self.0.prompt(reason) {
            Ok(())
        } else {
            Err(unavailable())
        }
    }

    fn available(&self) -> bool {
        self.0.available.load(Ordering::SeqCst)
    }

    fn authenticate(&self, reason: &str) -> Result<(), klav_touchid::Error> {
        if self.0.available.load(Ordering::SeqCst) && self.0.cancels.load(Ordering::SeqCst) {
            self.0.prompts.lock().unwrap().push(reason.to_owned());
            return Err(klav_touchid::Error::Cancelled);
        }
        if self.0.prompt(reason) {
            Ok(())
        } else {
            Err(klav_touchid::Error::Unavailable)
        }
    }
}

// ------------------------------------------------------------ set-up

/// An account with one login, «GitHub», at `home`.
async fn account(server: &ServerProcess, home: &Home, email: &str, password: &str) {
    let (mut unlocked, _kit) = signup(
        home,
        SignupRequest {
            server: server.url.clone(),
            email: email.into(),
            password: MasterPassword::new(password),
            device_name: "laptop".into(),
            device_kind: klav_proto::auth::DeviceKind::Cli,
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
}

impl Drop for Daemon {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }
}

/// A test `klavd` for `home`, with the fake Touch ID. Each connection takes
/// the next of `keys`.
async fn daemon(home: &Home, fake: &Arc<Fake>, keys: &[Key], hold: bool) -> Daemon {
    daemon_with(home, fake, keys, hold, BeforePrompt::default()).await
}

/// [`daemon`], with the pause before a prompt the test sets through
/// `before_prompt` ([`pause_before_prompt`]).
async fn daemon_with(
    home: &Home,
    fake: &Arc<Fake>,
    keys: &[Key],
    hold: bool,
    before_prompt: BeforePrompt,
) -> Daemon {
    daemon_seams(
        home,
        fake,
        keys,
        hold,
        before_prompt,
        BeforePrompt::default(),
    )
    .await
}

/// [`daemon_with`], with the pause between the window gate's two passes
/// too.
async fn daemon_seams(
    home: &Home,
    fake: &Arc<Fake>,
    keys: &[Key],
    hold: bool,
    before_prompt: BeforePrompt,
    between_passes: BeforePrompt,
) -> Daemon {
    let config = Config {
        home: home.clone(),
        idle_lock: Duration::from_secs(600),
        // On: every Touch ID call reaches the fake, never the shim.
        touch_id: true,
        sync_after: crate::SYNC_AFTER,
        build: None,
    };
    let seams = TestSeams {
        keys: Mutex::new(keys.iter().copied().collect()),
        hold,
        before_prompt,
        between_passes,
    };
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(serve_with(
        config,
        async {
            let _ = stopped.await;
        },
        Box::new(Shared(Arc::clone(fake))),
        seams,
    ));
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    while std::fs::symlink_metadata(home.socket_path()).is_err() {
        assert!(!task.is_finished(), "klavd stopped before it listened");
        assert!(
            tokio::time::Instant::now() < deadline,
            "klavd did not listen"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    Daemon { stop: Some(stop) }
}

fn session(id: i32) -> Key {
    Key::Session(peer::Session {
        id,
        leader_start: peer::StartTime(7),
    })
}

/// One connection, which takes the next key.
struct Conn(tokio::sync::Mutex<DaemonClient>);

async fn conn(home: &Home) -> Arc<Conn> {
    let client = DaemonClient::connect(home).await.expect("klavd");
    // A request, so `klavd` has accepted it (and given it its key) before
    // the next connection opens.
    let c = Arc::new(Conn(tokio::sync::Mutex::new(client)));
    call::<Value>(&c, Request::Status).await.expect("status");
    c
}

async fn call<T: serde::de::DeserializeOwned>(c: &Conn, request: Request) -> Result<T, ErrorBody> {
    c.0.lock().await.call::<T>(request).await.map(|(v, _)| v)
}

async fn code(c: &Conn, request: Request) -> ErrorCode {
    call::<Value>(c, request).await.expect_err("refused").code
}

fn secret(password: Option<&str>) -> Option<SecretText> {
    password.map(SecretText::new)
}

fn unlock(password: Option<&str>) -> Request {
    Request::Unlock {
        password: secret(password),
        passkey_flow: false,
    }
}

/// An `unlock` with the password as the CLI sends it with the gate on:
/// `shown` is what its question said, from `status`'s `presence`.
///
/// The `lasts` → `shown` mapping below re-implements the CLI's own
/// (`presence::unlock_shown` in `klav-cli`, which this crate can't depend
/// on), so a change to one side only would not fail these tests. The CLI's
/// own mapping is driven against a real `klavd` by
/// `a_typed_unlock_opens_the_window_its_question_names` in
/// `crates/klav-cli/tests/presence.rs`, which pins both unlocks: the first
/// since `klavd` started (no window) and a later one (5 minutes).
async fn unlock_shown(c: &Conn, password: &str) -> Result<DaemonStatus, ErrorBody> {
    let status: DaemonStatus = call(c, Request::Status).await?;
    let shown = status.presence.map(|p| match p.lasts {
        None => Window::Always,
        Some(AskLasts::FiveMinutes) => Window::FiveMinutes,
        Some(AskLasts::UntilLock) => Window::Unlocked,
    });
    let presence = crate::client::Presence {
        notify: false,
        shown,
        untyped: false,
    };
    c.0.lock()
        .await
        .call_presence::<DaemonStatus>(unlock(Some(password)), presence, &mut |_| {})
        .await
        .map(|(v, _)| v)
}

fn view(password: Option<&str>) -> Request {
    Request::View {
        query: "GitHub".into(),
        reveal: true,
        password: secret(password),
    }
}

fn presence_window(window: Option<Window>, password: Option<&str>) -> Request {
    Request::PresenceWindow {
        window,
        password: secret(password),
    }
}

fn cancel_deletion(password: Option<&str>) -> Request {
    Request::CancelAccountDeletion {
        password: secret(password),
    }
}

/// A registration of user `ana-<n>` (`n` from 1 to 5) on `shop.example`.
fn passkey_create(n: usize) -> Request {
    // `ana-1` … `ana-5`, base64url.
    const IDS: [&str; 5] = ["YW5hLTE", "YW5hLTI", "YW5hLTM", "YW5hLTQ", "YW5hLTU"];
    Request::PasskeyCreate {
        request: klav_client::passkeys::PasskeyCreateRequest {
            origin: "https://login.shop.example".into(),
            rp_id: Some("shop.example".into()),
            rp_name: Some("Shop".into()),
            user_id: IDS[n - 1].into(),
            user_name: format!("ana-{n}"),
            user_display_name: None,
            // `create-challenge-0123456789`, base64url.
            challenge: "Y3JlYXRlLWNoYWxsZW5nZS0wMTIzNDU2Nzg5".into(),
            ..klav_client::passkeys::PasskeyCreateRequest::default()
        },
        password: None,
    }
}

/// A sign-in on `shop.example` with the passkey in `item`.
fn passkey_get(item: &str) -> Request {
    Request::PasskeyGet {
        origin: "https://login.shop.example".into(),
        rp_id: Some("shop.example".into()),
        // `get-challenge-0123456789`, base64url.
        challenge: "Z2V0LWNoYWxsZW5nZS0wMTIzNDU2Nzg5".into(),
        item: item.into(),
        password: None,
    }
}

/// Moves `from`'s account files into `to`, keeping `to`'s in `aside`.
fn swap(to: &Home, from: &Home, aside: &std::path::Path) {
    std::fs::create_dir_all(aside).unwrap();
    for name in FILES {
        std::fs::rename(to.file(name), aside.join(name)).unwrap();
        std::fs::copy(from.file(name), to.file(name)).unwrap();
    }
}

fn put_back(to: &Home, aside: &std::path::Path) {
    for name in FILES {
        std::fs::rename(aside.join(name), to.file(name)).unwrap();
    }
}

/// Waits, off the async workers, for a held prompt to open.
async fn opened(rx: mpsc::Receiver<()>) {
    tokio::task::spawn_blocking(move || rx.recv_timeout(Duration::from_secs(30)))
        .await
        .unwrap()
        .expect("the prompt opened");
}

/// Holds `klavd` right before it next marks a Touch ID prompt open, with
/// whatever lock it holds still held: the first receiver says it got there,
/// and sending to the sender lets it go on.
fn pause_before_prompt(seam: &BeforePrompt) -> (mpsc::Receiver<()>, mpsc::Sender<()>) {
    let (reached_tx, reached) = mpsc::channel();
    let (go, go_rx) = mpsc::channel::<()>();
    *seam.lock().unwrap() = Some(Box::new(move || {
        let _ = reached_tx.send(());
        let _ = go_rx.recv();
    }));
    (reached, go)
}

/// An answer that must come at once: a request that queued behind a prompt
/// the test holds open would wait there for good, so it fails after a bound
/// instead of hanging.
async fn at_once<T>(answer: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(10), answer)
        .await
        .expect("answered without waiting for the open prompt")
}

/// How long a test lets a request that must wait start waiting.
const SETTLE: Duration = Duration::from_millis(300);

/// Two homes: the person's, and a scratch account a program made with the
/// genuine `klav` under a password it chose.
async fn two_accounts(server: &ServerProcess, dir: &std::path::Path) -> (Home, Home) {
    let person = Home::at(dir.join("person"));
    let scratch = Home::at(dir.join("scratch"));
    account(server, &person, "ana@example.com", PERSON).await;
    account(server, &scratch, "scratch@example.com", THEIRS).await;
    (person, scratch)
}

// ------------------------------------------------------------ finding 1

/// A consistent set of files under another password, put in the home of
/// an unlocked `klavd`, makes that password no presence: not for a value
/// (the gate), not for an operation that already asks (`confirm`), and not
/// for an `unlock` while unlocked. The person's own works again once the
/// files are back; while they are swapped it fails too, closed.
#[tokio::test(flavor = "multi_thread")]
async fn a_password_for_swapped_files_is_no_presence_with_the_gate_on() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().unwrap();
    let (person, scratch) = two_accounts(&server, dir.path()).await;
    // Touch ID can't be shown: the password is the verification.
    let fake = Fake::new(false);
    let _klavd = daemon(&person, &fake, &[session(40)], false).await;
    let c = conn(&person).await;
    call::<DaemonStatus>(&c, unlock(Some(PERSON)))
        .await
        .expect("unlock");
    // Every value asks.
    call::<Value>(&c, presence_window(Some(Window::Always), None))
        .await
        .expect("tighten");

    let aside = dir.path().join("aside");
    swap(&person, &scratch, &aside);
    // A password answers the ask klavd sent (layer 3's review, finding 2).
    assert_eq!(code(&c, view(None)).await, ErrorCode::PresenceRequired);
    assert_eq!(
        code(&c, view(Some(THEIRS))).await,
        ErrorCode::WrongCredentials
    );
    assert_eq!(
        code(&c, cancel_deletion(Some(THEIRS))).await,
        ErrorCode::WrongCredentials
    );
    assert_eq!(
        code(&c, unlock(Some(THEIRS))).await,
        ErrorCode::WrongCredentials
    );
    assert_eq!(
        code(&c, presence_window(Some(Window::Unlocked), Some(THEIRS))).await,
        ErrorCode::WrongCredentials
    );
    // Swapped, the person's own fails as well: the Secret Key on disk is
    // the program's.
    assert_eq!(code(&c, view(None)).await, ErrorCode::PresenceRequired);
    assert_eq!(
        code(&c, view(Some(PERSON))).await,
        ErrorCode::WrongCredentials
    );

    for name in FILES {
        std::fs::remove_file(person.file(name)).unwrap();
    }
    put_back(&person, &aside);
    assert_eq!(code(&c, view(None)).await, ErrorCode::PresenceRequired);
    call::<Value>(&c, view(Some(PERSON))).await.expect("value");
    call::<Value>(&c, cancel_deletion(Some(PERSON)))
        .await
        .expect("cancel");
    let s: DaemonStatus = call(&c, unlock(Some(PERSON))).await.expect("unlock");
    assert!(s.unlocked);
    assert_eq!(fake.asked(), 0, "no Touch ID was shown");
}

/// Where Touch ID is available, a password that comes along is the
/// verification and no dialog shows; a wrong one grants nothing.
#[tokio::test(flavor = "multi_thread")]
async fn a_password_brought_where_touch_id_is_available_shows_no_dialog() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().unwrap();
    let home = Home::at(dir.path().join("home"));
    account(&server, &home, "ana@example.com", PERSON).await;
    let fake = Fake::new(true);
    let _klavd = daemon(&home, &fake, &[session(40)], false).await;
    let c = conn(&home).await;
    call::<DaemonStatus>(&c, unlock(Some(PERSON)))
        .await
        .expect("unlock");
    call::<Value>(&c, presence_window(Some(Window::Always), None))
        .await
        .expect("tighten");
    // A password that answers no ask isn't checked: the answer is the ask
    // (layer 3's review, finding 2). Sent again, it is.
    let ask = call::<Value>(&c, view(Some(THEIRS)))
        .await
        .expect_err("asks")
        .presence
        .expect("what to ask");
    assert_eq!(ask.lasts, None);
    assert_eq!(
        code(&c, view(Some(THEIRS))).await,
        ErrorCode::WrongCredentials
    );
    assert_eq!(
        code(&c, view(Some(PERSON))).await,
        ErrorCode::PresenceRequired
    );
    call::<Value>(&c, view(Some(PERSON))).await.expect("value");
    assert_eq!(fake.asked(), 0);
    // Without it, Touch ID asks.
    call::<Value>(&c, view(None)).await.expect("value");
    assert_eq!(fake.asked(), 1);
}

// ------------------------------------------------------------ keys

/// Two keys through the socket: the one that unlocked has its window; the
/// other is told `already_unlocked` and gets no window without the
/// password, and its own with it. Neither depends on what runs the test.
#[tokio::test(flavor = "multi_thread")]
async fn another_key_is_told_already_unlocked_and_gets_no_window() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().unwrap();
    let home = Home::at(dir.path().join("home"));
    account(&server, &home, "ana@example.com", PERSON).await;
    let fake = Fake::new(false);
    let _klavd = daemon(&home, &fake, &[session(40), session(41)], false).await;
    let a = conn(&home).await;
    let b = conn(&home).await;
    // The first unlock since klavd started opens no window (Omar's
    // decision A of 2026-11-19); a later one opens a's.
    let s = unlock_shown(&a, PERSON).await.expect("unlock");
    assert!(s.unlocked && !s.already_unlocked);
    assert_eq!(code(&a, view(None)).await, ErrorCode::PresenceRequired);
    call::<DaemonStatus>(&a, Request::Lock).await.expect("lock");
    let s = unlock_shown(&a, PERSON).await.expect("unlock");
    assert!(s.unlocked && !s.already_unlocked);
    // a's unlock opened a's window (5 minutes, the default).
    call::<Value>(&a, view(None)).await.expect("a's window");
    // b: unlocked by another key; without the password, nothing.
    let s: DaemonStatus = call(&b, Request::Status).await.expect("status");
    assert!(s.presence.expect("gate on").elsewhere);
    let s: DaemonStatus = call(&b, unlock(None)).await.expect("unlock");
    assert!(s.already_unlocked);
    assert_eq!(code(&b, view(None)).await, ErrorCode::PresenceRequired);
    // A password whose question said nothing opens nothing either.
    let s: DaemonStatus = call(&b, unlock(Some(PERSON))).await.expect("unlock");
    assert!(s.already_unlocked);
    assert_eq!(code(&b, view(None)).await, ErrorCode::PresenceRequired);
    // With the window its question said, b's own window, and still
    // `already_unlocked`.
    let s = unlock_shown(&b, PERSON).await.expect("unlock");
    assert!(s.already_unlocked);
    call::<Value>(&b, view(None)).await.expect("b's window");
    // a again: it unlocked, so not `already_unlocked`.
    let s: DaemonStatus = call(&a, unlock(Some(PERSON))).await.expect("unlock");
    assert!(!s.already_unlocked);
    assert_eq!(fake.asked(), 0);
}

/// The passkey window is per key (§2.5), through `passkey_create` and
/// `passkey_get`.
#[tokio::test(flavor = "multi_thread")]
async fn the_passkey_window_is_per_key_through_the_socket() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().unwrap();
    let home = Home::at(dir.path().join("home"));
    account(&server, &home, "ana@example.com", PERSON).await;
    let fake = Fake::new(true);
    let _klavd = daemon(&home, &fake, &[session(40), session(41)], false).await;
    let a = conn(&home).await;
    let b = conn(&home).await;
    call::<DaemonStatus>(&a, unlock(Some(PERSON)))
        .await
        .expect("unlock");
    // Always (the default): each use asks, even right after the unlock's.
    let created = call::<Value>(&a, passkey_create(1)).await.expect("created");
    let item = created["item"].as_str().expect("the login").to_owned();
    call::<Value>(&a, passkey_create(2)).await.expect("created");
    assert_eq!(fake.asked(), 2);
    // Loosening asks, and opens nothing.
    call::<Value>(
        &a,
        Request::PasskeyUv {
            window: Some(Window::FiveMinutes),
            password: None,
        },
    )
    .await
    .expect("loosen");
    assert_eq!(fake.asked(), 3);
    call::<Value>(&a, passkey_create(3)).await.expect("created");
    assert_eq!(fake.asked(), 4);
    // a's window covers a's next uses, a sign-in too, and not b's.
    call::<Value>(&a, passkey_create(4)).await.expect("created");
    call::<Value>(&a, passkey_get(&item))
        .await
        .expect("signed in");
    assert_eq!(fake.asked(), 4);
    call::<Value>(&b, passkey_get(&item))
        .await
        .expect("signed in");
    assert_eq!(fake.asked(), 5);
    // b's sign-in opened b's own window.
    call::<Value>(&b, passkey_create(5)).await.expect("created");
    assert_eq!(fake.asked(), 5);
}

// ------------------------------------------------------------ one prompt

/// While an unlock's Touch ID is open, a second `unlock` gets
/// `presence_busy` at once instead of queuing behind it (N2).
#[tokio::test(flavor = "multi_thread")]
async fn a_second_unlock_while_the_unlock_prompt_is_open_is_busy() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().unwrap();
    let home = Home::at(dir.path().join("home"));
    account(&server, &home, "ana@example.com", PERSON).await;
    let fake = Fake::new(true);
    let _klavd = daemon(&home, &fake, &[session(40), session(41)], false).await;
    let a = conn(&home).await;
    let b = conn(&home).await;
    let (open, release) = fake.hold_next();
    let first = {
        let a = Arc::clone(&a);
        tokio::spawn(async move { call::<DaemonStatus>(&a, unlock(None)).await })
    };
    opened(open).await;
    assert_eq!(
        at_once(code(&b, unlock(None))).await,
        ErrorCode::PresenceBusy
    );
    assert_eq!(
        at_once(code(&b, unlock(Some(PERSON)))).await,
        ErrorCode::PresenceBusy
    );
    release.send(()).unwrap();
    let s = first.await.unwrap().expect("unlocked");
    assert!(s.unlocked);
    assert_eq!(fake.asked(), 1);
}

/// An `unlock` that waits for the one running now is busy as soon as that
/// one's prompt opens (N2; the third layer-2 review, finding A), instead
/// of waiting for it to close and showing its own right after a cancel.
#[tokio::test(flavor = "multi_thread")]
async fn a_waiting_unlock_is_busy_once_the_unlock_prompt_opens() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().unwrap();
    let home = Home::at(dir.path().join("home"));
    account(&server, &home, "ana@example.com", PERSON).await;
    let fake = Fake::new(true);
    let seam = BeforePrompt::default();
    let keys = [session(40), session(41)];
    let _klavd = daemon_with(&home, &fake, &keys, false, Arc::clone(&seam)).await;
    let a = conn(&home).await;
    let b = conn(&home).await;
    let (reached, go) = pause_before_prompt(&seam);
    let (open, release) = fake.hold_next();
    let first = {
        let a = Arc::clone(&a);
        tokio::spawn(async move { call::<DaemonStatus>(&a, unlock(None)).await })
    };
    // The first unlock runs, and its dialog isn't open yet.
    opened(reached).await;
    let second = {
        let b = Arc::clone(&b);
        tokio::spawn(async move { code(&b, unlock(None)).await })
    };
    tokio::time::sleep(SETTLE).await;
    assert!(!second.is_finished(), "it waits for the unlock running now");
    go.send(()).unwrap();
    opened(open).await;
    assert_eq!(at_once(second).await.unwrap(), ErrorCode::PresenceBusy);
    release.send(()).unwrap();
    let s = first.await.unwrap().expect("unlocked");
    assert!(s.unlocked);
    assert_eq!(fake.asked(), 1);
}

/// A request that will show a prompt never waits for the session's lock
/// behind a dialog that keeps it (§2.4; the third layer-2 review, finding
/// A). An operation that already asks shows its Touch ID inside the
/// session's lock; meanwhile a value from another key, under 5 minutes and
/// under Always, another operation that already asks and a passkey use are
/// answered `presence_busy` at once.
#[tokio::test(flavor = "multi_thread")]
async fn no_prompt_waits_behind_a_dialog_that_holds_the_session() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().unwrap();
    let home = Home::at(dir.path().join("home"));
    account(&server, &home, "ana@example.com", PERSON).await;
    let fake = Fake::new(true);
    let _klavd = daemon(&home, &fake, &[session(40), session(41)], false).await;
    let a = conn(&home).await;
    let b = conn(&home).await;
    call::<DaemonStatus>(&a, unlock(Some(PERSON)))
        .await
        .expect("unlock");
    for setting in [Window::FiveMinutes, Window::Always] {
        call::<Value>(&a, presence_window(Some(setting), None))
            .await
            .expect("setting");
        let before = fake.asked();
        let (open, release) = fake.hold_next();
        let first = {
            let a = Arc::clone(&a);
            tokio::spawn(async move { call::<Value>(&a, cancel_deletion(None)).await })
        };
        opened(open).await;
        for request in [view(None), cancel_deletion(None), passkey_create(1)] {
            let what = format!("{setting:?} {request:?}");
            assert_eq!(
                at_once(code(&b, request)).await,
                ErrorCode::PresenceBusy,
                "{what}"
            );
        }
        release.send(()).unwrap();
        first.await.unwrap().expect("cancel");
        assert_eq!(fake.asked(), before + 1, "no second dialog");
    }
}

/// The same when the dialog opens only after the requests started waiting:
/// an operation that already asks holds the session's lock and stops right
/// before its prompt; another operation that already asks and a value under
/// Always, from other keys, wait for that lock, and are answered
/// `presence_busy` as soon as the dialog opens, not after it closes.
#[tokio::test(flavor = "multi_thread")]
async fn a_prompt_waiting_for_the_session_is_busy_once_a_dialog_opens() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().unwrap();
    let home = Home::at(dir.path().join("home"));
    account(&server, &home, "ana@example.com", PERSON).await;
    let fake = Fake::new(true);
    let seam = BeforePrompt::default();
    let keys = [session(40), session(41), session(42)];
    let _klavd = daemon_with(&home, &fake, &keys, false, Arc::clone(&seam)).await;
    let a = conn(&home).await;
    let b = conn(&home).await;
    let c = conn(&home).await;
    call::<DaemonStatus>(&a, unlock(Some(PERSON)))
        .await
        .expect("unlock");
    // Every value names its item.
    call::<Value>(&a, presence_window(Some(Window::Always), None))
        .await
        .expect("tighten");
    let (reached, go) = pause_before_prompt(&seam);
    let (open, release) = fake.hold_next();
    let first = {
        let a = Arc::clone(&a);
        tokio::spawn(async move { call::<Value>(&a, cancel_deletion(None)).await })
    };
    opened(reached).await;
    let operation = {
        let b = Arc::clone(&b);
        tokio::spawn(async move { code(&b, cancel_deletion(None)).await })
    };
    let value = {
        let c = Arc::clone(&c);
        tokio::spawn(async move { code(&c, view(None)).await })
    };
    tokio::time::sleep(SETTLE).await;
    assert!(!operation.is_finished(), "it waits for the session's lock");
    assert!(!value.is_finished(), "it waits for the session's lock");
    go.send(()).unwrap();
    opened(open).await;
    assert_eq!(at_once(operation).await.unwrap(), ErrorCode::PresenceBusy);
    assert_eq!(at_once(value).await.unwrap(), ErrorCode::PresenceBusy);
    release.send(()).unwrap();
    first.await.unwrap().expect("cancel");
    assert_eq!(fake.asked(), 1, "no second dialog");
}

/// A value whose window is open needs no prompt, and still waits for the
/// session's lock like any request, as before this layer's fixes: it is
/// served once the dialog that holds the lock closes, with no prompt of its
/// own.
#[tokio::test(flavor = "multi_thread")]
async fn a_value_under_an_open_window_still_waits_for_the_session() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().unwrap();
    let home = Home::at(dir.path().join("home"));
    account(&server, &home, "ana@example.com", PERSON).await;
    let fake = Fake::new(true);
    let _klavd = daemon(&home, &fake, &[session(40), session(41)], false).await;
    let a = conn(&home).await;
    let b = conn(&home).await;
    // a's second unlock opened a's window (5 minutes, the default): the
    // first since klavd started opens none.
    unlock_shown(&a, PERSON).await.expect("unlock");
    call::<DaemonStatus>(&a, Request::Lock).await.expect("lock");
    unlock_shown(&a, PERSON).await.expect("unlock");
    let (open, release) = fake.hold_next();
    let first = {
        let b = Arc::clone(&b);
        tokio::spawn(async move { call::<Value>(&b, cancel_deletion(None)).await })
    };
    opened(open).await;
    let value = {
        let a = Arc::clone(&a);
        tokio::spawn(async move { call::<Value>(&a, view(None)).await })
    };
    tokio::time::sleep(SETTLE).await;
    assert!(!value.is_finished(), "it waits for the session's lock");
    release.send(()).unwrap();
    first.await.unwrap().expect("cancel");
    at_once(value).await.unwrap().expect("value");
    assert_eq!(fake.asked(), 1, "the value showed no prompt");
}

/// With the gate on, every prompt `klavd` shows takes part in the
/// one-prompt rule (finding 5 of the second layer-2 review): while a value's
/// prompt is open, an operation that already asks, a setting's loosening,
/// a passkey use and `confirm_presence` all get `presence_busy`, and no
/// second dialog shows.
#[tokio::test(flavor = "multi_thread")]
async fn every_prompt_waits_for_none_while_another_is_open() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().unwrap();
    let home = Home::at(dir.path().join("home"));
    account(&server, &home, "ana@example.com", PERSON).await;
    let fake = Fake::new(true);
    let _klavd = daemon(&home, &fake, &[session(40), session(41)], false).await;
    let a = conn(&home).await;
    let b = conn(&home).await;
    call::<DaemonStatus>(&a, unlock(Some(PERSON)))
        .await
        .expect("unlock");
    call::<Value>(&a, presence_window(Some(Window::Always), None))
        .await
        .expect("tighten");
    let (open, release) = fake.hold_next();
    let value = {
        let a = Arc::clone(&a);
        tokio::spawn(async move { call::<Value>(&a, view(None)).await })
    };
    opened(open).await;
    for request in [
        cancel_deletion(None),
        presence_window(Some(Window::FiveMinutes), None),
        passkey_create(1),
        Request::ConfirmPresence {
            purpose: crate::protocol::PresencePurpose::DeleteAccount,
        },
        view(None),
    ] {
        let what = format!("{request:?}");
        assert_eq!(
            at_once(code(&b, request)).await,
            ErrorCode::PresenceBusy,
            "{what}"
        );
    }
    release.send(()).unwrap();
    value.await.unwrap().expect("value");
    assert_eq!(fake.asked(), 1, "no second dialog");
    // Closed: the next one asks.
    call::<Value>(&b, cancel_deletion(None))
        .await
        .expect("cancel");
    assert_eq!(fake.asked(), 2);
}

// ------------------------------------------------------------ settings

/// One setting change at a time (finding 3 of the second layer-2 review):
/// while a loosening waits for its verification, another change of either
/// setting gets `presence_busy`, so no change decided against a stale value
/// lands after it. Disk and memory agree afterwards.
#[tokio::test(flavor = "multi_thread")]
async fn a_setting_change_while_another_runs_is_busy() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().unwrap();
    let home = Home::at(dir.path().join("home"));
    account(&server, &home, "ana@example.com", PERSON).await;
    let fake = Fake::new(true);
    let _klavd = daemon(&home, &fake, &[session(40), session(41)], false).await;
    let a = conn(&home).await;
    let b = conn(&home).await;
    call::<DaemonStatus>(&a, unlock(Some(PERSON)))
        .await
        .expect("unlock");
    let (open, release) = fake.hold_next();
    let loosening = {
        let a = Arc::clone(&a);
        tokio::spawn(async move {
            call::<Value>(&a, presence_window(Some(Window::Unlocked), None)).await
        })
    };
    opened(open).await;
    // A tightening, and the passkey setting, while it runs.
    assert_eq!(
        at_once(code(&b, presence_window(Some(Window::Always), None))).await,
        ErrorCode::PresenceBusy
    );
    assert_eq!(
        at_once(code(
            &b,
            Request::PasskeyUv {
                window: Some(Window::Always),
                password: None,
            }
        ))
        .await,
        ErrorCode::PresenceBusy
    );
    // Reading takes no turn.
    let read: Value = at_once(call(&b, presence_window(None, None)))
        .await
        .expect("read");
    assert_eq!(read["window"], "5m");
    release.send(()).unwrap();
    let done = loosening.await.unwrap().expect("loosened");
    assert_eq!(done["window"], "unlocked");
    // Now the tightening goes through, and what is stored is what is used.
    let tight: Value = call(&b, presence_window(Some(Window::Always), None))
        .await
        .expect("tighten");
    assert_eq!(tight["window"], "always");
    call::<DaemonStatus>(&a, Request::Lock).await.expect("lock");
    call::<DaemonStatus>(&a, unlock(Some(PERSON)))
        .await
        .expect("unlock");
    let read: Value = call(&a, presence_window(None, None)).await.expect("read");
    assert_eq!(read["window"], "always");
}

// ------------------------------------------------------------ held

/// A declared connection (`hold`, with layer 6's switch on in this test):
/// `confirm_presence` and an operation that already asks, verified on it,
/// don't hold it; the gate's own window verification does.
#[tokio::test(flavor = "multi_thread")]
async fn other_verifications_on_a_declared_connection_do_not_hold_it() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().unwrap();
    let home = Home::at(dir.path().join("home"));
    account(&server, &home, "ana@example.com", PERSON).await;
    let fake = Fake::new(true);
    let keys = [session(40), Key::Connection(0), Key::Connection(0)];
    let _klavd = daemon(&home, &fake, &keys, true).await;
    let person = conn(&home).await;
    let app = conn(&home).await;
    let other = conn(&home).await;
    call::<DaemonStatus>(&person, unlock(Some(PERSON)))
        .await
        .expect("unlock");
    let declared: Value = call(&app, Request::Hold).await.expect("hold");
    assert_eq!(
        declared,
        serde_json::json!({ "declared": true, "held": false })
    );
    call::<Value>(
        &app,
        Request::ConfirmPresence {
            purpose: crate::protocol::PresencePurpose::DeleteAccount,
        },
    )
    .await
    .expect("confirm_presence");
    call::<Value>(&app, cancel_deletion(None))
        .await
        .expect("cancel");
    assert_eq!(fake.asked(), 2);
    let declared: Value = call(&app, Request::Hold).await.expect("hold");
    assert_eq!(declared["held"], false, "confirm_presence held it");
    // A value asks, with the declared connection's text, and holds it.
    call::<Value>(&app, view(None)).await.expect("value");
    assert_eq!(fake.asked(), 3);
    assert_eq!(
        fake.last(),
        "let the program that asked use your vault until Klav locks"
    );
    let declared: Value = call(&app, Request::Hold).await.expect("hold");
    assert_eq!(declared["held"], true);
    call::<Value>(&app, view(None)).await.expect("value");
    assert_eq!(fake.asked(), 3);
    // Never shared: another connection asks.
    call::<Value>(&other, view(None)).await.expect("value");
    assert_eq!(fake.asked(), 4);
    // Lock drops it.
    call::<DaemonStatus>(&person, Request::Lock)
        .await
        .expect("lock");
    let declared: Value = call(&app, Request::Hold).await.expect("hold");
    assert_eq!(declared["held"], false);
}

// ------------------------------------------------------------ layer 3's review

/// A password sent again after `presence_required` is checked only if
/// `klavd` would still ask exactly what it asked (finding 2 of layer 3's
/// review): a setting loosened in between, or a rename that makes the
/// request name another item, gets a new ask and the password isn't
/// checked; the password that answers the new ask grants what it says.
#[tokio::test(flavor = "multi_thread")]
async fn a_password_grants_only_what_its_ask_said() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().unwrap();
    let home = Home::at(dir.path().join("home"));
    account(&server, &home, "ana@example.com", PERSON).await;
    let fake = Fake::new(false);
    let _klavd = daemon(&home, &fake, &[session(40), session(41)], false).await;
    let a = conn(&home).await;
    let other = conn(&home).await;
    unlock_shown(&a, PERSON).await.expect("unlock");
    call::<Value>(&a, presence_window(Some(Window::Always), None))
        .await
        .expect("tighten");

    // Always: the ask names the one value.
    let ask = call::<Value>(&a, view(None))
        .await
        .expect_err("asks")
        .presence
        .expect("what to ask");
    assert_eq!(ask.lasts, None);
    // The setting is loosened elsewhere before the password comes: the
    // password isn't checked (a wrong one isn't refused as wrong), and the
    // new ask says the window it would open now.
    call::<Value>(
        &other,
        presence_window(Some(Window::Unlocked), Some(PERSON)),
    )
    .await
    .expect("loosen");
    let e = call::<Value>(&a, view(Some(THEIRS)))
        .await
        .expect_err("asks again");
    assert_eq!(e.code, ErrorCode::PresenceRequired);
    let ask = e.presence.expect("what to ask");
    assert_eq!(ask.lasts, Some(AskLasts::UntilLock));
    assert_eq!(ask.value, None);
    // The password that answers it opens what it said.
    call::<Value>(&a, view(Some(PERSON))).await.expect("value");
    call::<Value>(&a, view(None)).await.expect("a's window");

    // Always again; the ask names «GitHub». Then «GitHub» is renamed and
    // another item takes its title: the same query now names another
    // item, so the password isn't checked and the new ask is answered.
    call::<Value>(&a, presence_window(Some(Window::Always), None))
        .await
        .expect("tighten");
    assert_eq!(code(&a, view(None)).await, ErrorCode::PresenceRequired);
    call::<Value>(
        &other,
        Request::Edit {
            query: "GitHub".into(),
            patch: klav_client::ops::ItemPatch {
                title: Some("GitHub (old)".into()),
                ..Default::default()
            },
        },
    )
    .await
    .expect("rename");
    call::<Value>(
        &other,
        Request::Create {
            item: klav_client::ops::NewItem {
                kind: ItemKind::Login,
                title: "GitHub".into(),
                vault: None,
                project: None,
                fields: Vec::new(),
                urls: Vec::new(),
                tags: Vec::new(),
                notes: None,
                allow_duplicate: false,
            },
        },
    )
    .await
    .expect("another «GitHub»");
    assert_eq!(
        code(&a, view(Some(THEIRS))).await,
        ErrorCode::PresenceRequired,
        "another item: asked again, the password unchecked"
    );
    call::<Value>(&a, view(Some(PERSON))).await.expect("value");
    // A password with no ask at all is never checked.
    assert_eq!(
        code(&a, view(Some(THEIRS))).await,
        ErrorCode::PresenceRequired
    );
    assert_eq!(fake.asked(), 0);
}

/// Omar's decision 2 of 2026-11-19: just before a value's Touch ID dialog,
/// `klavd` writes a notice to a request that asked for one (`notify`), so
/// the CLI prints its terminal's name; a request that didn't ask gets none
/// (a plain client would refuse a line it didn't ask for).
#[tokio::test(flavor = "multi_thread")]
async fn a_notice_goes_before_the_dialog_only_to_a_request_that_asked() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().unwrap();
    let home = Home::at(dir.path().join("home"));
    account(&server, &home, "ana@example.com", PERSON).await;
    let fake = Fake::new(true);
    let _klavd = daemon(&home, &fake, &[session(40)], false).await;
    let a = conn(&home).await;
    unlock_shown(&a, PERSON).await.expect("unlock");
    call::<Value>(&a, presence_window(Some(Window::Always), None))
        .await
        .expect("tighten");

    // Asked: the notice arrives while the dialog is still open.
    let (open, release) = fake.hold_next();
    let (tx, notices) = std::sync::mpsc::channel();
    let asked = {
        let a = Arc::clone(&a);
        tokio::spawn(async move {
            let presence = crate::client::Presence {
                notify: true,
                shown: None,
                untyped: false,
            };
            let mut seen = move |n| {
                let _ = tx.send(n);
            };
            a.0.lock()
                .await
                .call_presence::<Value>(view(None), presence, &mut seen)
                .await
                .map(drop)
        })
    };
    opened(open).await;
    let notice = notices
        .recv_timeout(Duration::from_secs(10))
        .expect("a notice before the dialog closed");
    assert_eq!(notice, crate::protocol::Notice::TouchId);
    release.send(()).unwrap();
    at_once(asked).await.unwrap().expect("value");
    assert!(notices.try_recv().is_err(), "one notice");
    assert_eq!(fake.asked(), 1);

    // Not asked: the same dialog, and no notice line (the plain client
    // fails on one).
    call::<Value>(&a, view(None)).await.expect("value");
    assert_eq!(fake.asked(), 2);
}

/// A password unlock opens what the client's question said, and only when
/// that is what `klavd` would open (finding 1 of layer 3's review); a
/// password the CLI didn't read on its terminal opens none (Omar's decision
/// 4 of 2026-11-19).
#[tokio::test(flavor = "multi_thread")]
async fn a_password_unlock_opens_only_what_its_question_said() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().unwrap();
    let home = Home::at(dir.path().join("home"));
    account(&server, &home, "ana@example.com", PERSON).await;
    let fake = Fake::new(false);
    let _klavd = daemon(&home, &fake, &[session(40); 6], false).await;
    {
        let a = conn(&home).await;
        let unlock_with = |shown: Option<Window>| {
            let a = Arc::clone(&a);
            async move {
                let presence = crate::client::Presence {
                    notify: false,
                    shown,
                    untyped: false,
                };
                a.0.lock()
                    .await
                    .call_presence::<DaemonStatus>(unlock(Some(PERSON)), presence, &mut |_| {})
                    .await
                    .map(|(s, _)| s)
            }
        };
        // Before the first unlock the setting is sealed: `status` promises
        // no window, and the unlock opens none whatever the client says
        // (Omar's decision A of 2026-11-19).
        let s: DaemonStatus = call(&a, Request::Status).await.expect("status");
        let p = s.presence.expect("gate on");
        assert_eq!(p.lasts, None);
        assert!(!p.elsewhere);
        unlock_with(Some(Window::FiveMinutes))
            .await
            .expect("unlock");
        assert_eq!(code(&a, view(None)).await, ErrorCode::PresenceRequired);
        call::<DaemonStatus>(&a, Request::Lock).await.expect("lock");
        // From stdin (the CLI says `always`): unlocked, no window.
        unlock_with(Some(Window::Always)).await.expect("unlock");
        assert_eq!(code(&a, view(None)).await, ErrorCode::PresenceRequired);
        // Locked again: now klavd knows the setting, and a question that
        // said more than it opens no window.
        call::<DaemonStatus>(&a, Request::Lock).await.expect("lock");
        let s: DaemonStatus = call(&a, Request::Status).await.expect("status");
        assert_eq!(
            s.presence.expect("gate on").lasts,
            Some(AskLasts::FiveMinutes)
        );
        unlock_with(Some(Window::Unlocked)).await.expect("unlock");
        assert_eq!(code(&a, view(None)).await, ErrorCode::PresenceRequired);
        // An older client that says nothing: none either.
        call::<DaemonStatus>(&a, Request::Lock).await.expect("lock");
        unlock_with(None).await.expect("unlock");
        assert_eq!(code(&a, view(None)).await, ErrorCode::PresenceRequired);
        // What it said: the window.
        call::<DaemonStatus>(&a, Request::Lock).await.expect("lock");
        unlock_with(Some(Window::FiveMinutes))
            .await
            .expect("unlock");
        call::<Value>(&a, view(None)).await.expect("the window");
    }
}

// ------------------------------------------------------------ layer 3's second review

/// A setting changed between the window gate's two passes leaves an ask
/// the resend can answer (the second review of layer 3, finding 7): only
/// the second pass keeps and compares asks, so the ask kept and the one
/// compared have the same shape. Before the fix the first pass compared
/// an ask with no item against the one kept with it, and the password the
/// person typed was never checked.
#[tokio::test(flavor = "multi_thread")]
async fn a_setting_changed_between_the_passes_leaves_an_ask_the_resend_answers() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().unwrap();
    let home = Home::at(dir.path().join("home"));
    account(&server, &home, "ana@example.com", PERSON).await;
    let fake = Fake::new(false);
    let between = BeforePrompt::default();
    let keys = [session(40), session(41)];
    let _klavd = daemon_seams(
        &home,
        &fake,
        &keys,
        false,
        BeforePrompt::default(),
        Arc::clone(&between),
    )
    .await;
    let a = conn(&home).await;
    let other = conn(&home).await;
    unlock_shown(&a, PERSON).await.expect("unlock");
    call::<Value>(&a, presence_window(Some(Window::Always), None))
        .await
        .expect("tighten");
    // The value's first pass sees Always; before its second, the setting
    // moves to 5 minutes.
    let (reached, go) = pause_before_prompt(&between);
    let asked = {
        let a = Arc::clone(&a);
        tokio::spawn(async move { call::<Value>(&a, view(None)).await })
    };
    opened(reached).await;
    call::<Value>(
        &other,
        presence_window(Some(Window::FiveMinutes), Some(PERSON)),
    )
    .await
    .expect("loosen");
    go.send(()).unwrap();
    let ask = at_once(asked)
        .await
        .unwrap()
        .expect_err("asks")
        .presence
        .expect("what to ask");
    assert_eq!(ask.lasts, Some(AskLasts::FiveMinutes));
    // The password that answers it is checked, and opens what it said.
    call::<Value>(&a, view(Some(PERSON)))
        .await
        .expect("the resend is answered");
    call::<Value>(&a, view(None)).await.expect("a's window");
    assert_eq!(fake.asked(), 0);
}

/// A login titled `title`, made through `klavd` on `c`.
async fn create(c: &Conn, title: &str) {
    call::<Value>(
        c,
        Request::Create {
            item: klav_client::ops::NewItem {
                kind: ItemKind::Login,
                title: title.into(),
                vault: None,
                project: None,
                fields: Vec::new(),
                urls: Vec::new(),
                tags: Vec::new(),
                notes: None,
                allow_duplicate: true,
            },
        },
    )
    .await
    .expect("created");
}

/// Renames the item `from` to `to`, through `klavd` on `c`.
async fn rename(c: &Conn, from: &str, to: &str) {
    call::<Value>(
        c,
        Request::Edit {
            query: from.into(),
            patch: klav_client::ops::ItemPatch {
                title: Some(to.into()),
                ..Default::default()
            },
        },
    )
    .await
    .expect("renamed");
}

fn view_of(query: &str, password: Option<&str>) -> Request {
    Request::View {
        query: query.into(),
        reveal: true,
        password: secret(password),
    }
}

/// A value request whose query names no item, or more than one, is
/// answered as `dispatch` answers it, before anything is asked (the second
/// review of layer 3, finding 2): no dialog that says "a value from your
/// vault", no `presence_required`, and so nothing a program could rename
/// its target into while the person confirms. Under 5 minutes and Always,
/// with Touch ID and without.
#[tokio::test(flavor = "multi_thread")]
async fn a_query_that_names_no_single_item_is_refused_before_any_ask() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().unwrap();
    let home = Home::at(dir.path().join("home"));
    account(&server, &home, "ana@example.com", PERSON).await;
    let fake = Fake::new(true);
    let _klavd = daemon(&home, &fake, &[session(40), session(41)], false).await;
    let a = conn(&home).await;
    let b = conn(&home).await;
    call::<DaemonStatus>(&a, unlock(Some(PERSON)))
        .await
        .expect("unlock");
    create(&a, "Twin").await;
    create(&a, "Twin").await;
    // 5 minutes is the default and Always a tightening: neither needs a
    // password, and a change that fails fails the test.
    for setting in [Window::FiveMinutes, Window::Always] {
        call::<Value>(&a, presence_window(Some(setting), None))
            .await
            .expect("setting");
        for available in [true, false] {
            fake.available.store(available, Ordering::SeqCst);
            let what = format!("{setting:?}, Touch ID {available}");
            for (query, wanted) in [
                ("Nothing by that name", ErrorCode::NotFound),
                ("Twin", ErrorCode::Invalid),
            ] {
                let e = call::<Value>(&b, view_of(query, None))
                    .await
                    .expect_err("refused");
                assert_eq!(e.code, wanted, "{what}: {query}");
                assert!(e.presence.is_none(), "{what}: {query}");
                // What `view` without `reveal` says, and no more.
                let plain = call::<Value>(
                    &b,
                    Request::View {
                        query: query.into(),
                        reveal: false,
                        password: None,
                    },
                )
                .await
                .expect_err("refused");
                assert_eq!(e.message, plain.message, "{what}: {query}");
                // A password with it isn't checked either.
                let e = call::<Value>(&b, view_of(query, Some(THEIRS)))
                    .await
                    .expect_err("refused");
                assert_eq!(e.code, wanted, "{what}: {query}");
            }
        }
    }
    fake.available.store(true, Ordering::SeqCst);
    assert_eq!(fake.asked(), 0, "no dialog");
}

/// The value requests bound to an item, each asking for «GitHub» by its
/// title, with `password` sent along.
fn by_title(password: Option<&str>) -> Vec<(&'static str, Request)> {
    vec![
        ("view", view_of("GitHub", password)),
        (
            "totp",
            Request::Totp {
                query: "GitHub".into(),
                field: None,
                password: secret(password),
            },
        ),
        ("previous_password", previous(password)),
        (
            "autofill",
            Request::Autofill {
                item: "GitHub".into(),
                url: "https://github.com".into(),
                part: klav_client::fill::FillPart::All,
                chosen: false,
                password: secret(password),
            },
        ),
    ]
}

/// An item renamed while its dialog is open is never handed out in its
/// place (the second review of layer 3, finding 2), for every value request
/// bound to an item: `view`, `totp`, `previous_password` and `autofill`
/// (by title: an item ID names the same item whatever its title). The
/// dialog names «GitHub»; while it is open a program renames «GitHub» away
/// and gives another item that title; the person approves, and the answer
/// is `conflict` with no value, re-read under the session's lock in the
/// same hold that would hand it out. Under 5 minutes, that `conflict` opens
/// no window: the rerun asks again (Omar's decision G of 2026-11-19).
///
/// With the password sent again instead, the swap between the ask and the
/// resend makes `klavd` ask again: the request now names another item, so
/// the password is not checked and the answer is a new `presence_required`.
#[tokio::test(flavor = "multi_thread")]
async fn an_item_renamed_while_its_dialog_is_open_is_not_handed_out() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().unwrap();
    let home = Home::at(dir.path().join("home"));
    account(&server, &home, "ana@example.com", PERSON).await;
    let fake = Fake::new(true);
    let _klavd = daemon(&home, &fake, &[session(40), session(41)], false).await;
    let a = conn(&home).await;
    let program = conn(&home).await;
    call::<DaemonStatus>(&a, unlock(Some(PERSON)))
        .await
        .expect("unlock");
    create(&a, "Bank").await;
    // A previous password for «GitHub», so its request reaches the gate.
    set_password(&a, "edit 1").await;
    set_password(&a, "edit 2").await;
    let swap = || async {
        rename(&program, "GitHub", "GitHub (old)").await;
        rename(&program, "Bank", "GitHub").await;
    };
    let back = || async {
        rename(&program, "GitHub", "Bank").await;
        rename(&program, "GitHub (old)", "GitHub").await;
    };
    for setting in [Window::Always, Window::FiveMinutes] {
        call::<Value>(&a, presence_window(Some(setting), Some(PERSON)))
            .await
            .expect("setting");
        for ((what, request), (_, rerun)) in by_title(None).into_iter().zip(by_title(None)) {
            let what = format!("{what}, {setting:?}");
            // Touch ID.
            let (open, release) = fake.hold_next();
            let asked = {
                let a = Arc::clone(&a);
                tokio::spawn(async move { call::<Value>(&a, request).await })
            };
            opened(open).await;
            if setting == Window::Always && what.starts_with("view") {
                assert_eq!(
                    fake.last(),
                    "show the values of “GitHub” (for the terminal ttys040)"
                );
            }
            swap().await;
            release.send(()).unwrap();
            let e = at_once(asked).await.unwrap().expect_err("refused");
            assert_eq!(e.code, ErrorCode::Conflict, "{what}");
            assert!(
                e.message.contains("nothing was handed out"),
                "{what}: {}",
                e.message
            );
            back().await;
            // No window from that answer: the rerun asks again.
            let before = fake.asked();
            let _ = call::<Value>(&a, rerun).await;
            assert_eq!(fake.asked(), before + 1, "{what}: the rerun asks");
            // Whatever the rerun opened, closed for the next round.
            call::<DaemonStatus>(&a, Request::Lock).await.expect("lock");
            call::<DaemonStatus>(&a, unlock(Some(PERSON)))
                .await
                .expect("unlock");
        }
        // The password sent again.
        fake.available.store(false, Ordering::SeqCst);
        for ((what, request), (_, resend)) in by_title(None).into_iter().zip(by_title(Some(PERSON)))
        {
            let what = format!("{what}, {setting:?}, password");
            let e = call::<Value>(&a, request).await.expect_err("asks");
            assert_eq!(e.code, ErrorCode::PresenceRequired, "{what}");
            swap().await;
            let e = call::<Value>(&a, resend).await.expect_err("asks again");
            assert_eq!(e.code, ErrorCode::PresenceRequired, "{what}");
            back().await;
        }
        fake.available.store(true, Ordering::SeqCst);
    }
}

/// A `conflict` opens no window (Omar's decision G of 2026-11-19): under 5
/// minutes, an answer that would have opened the terminal's window is
/// refused because the item was edited, and the window stays shut, so the
/// rerun asks again; once a hand-out goes through, the window it stated
/// opens and covers the next value. By Touch ID (one key) and by the
/// password sent again (another key).
#[tokio::test(flavor = "multi_thread")]
async fn a_conflict_opens_no_window() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().unwrap();
    let home = Home::at(dir.path().join("home"));
    account(&server, &home, "ana@example.com", PERSON).await;
    let fake = Fake::new(true);
    let keys = [session(40), session(41), session(42)];
    let _klavd = daemon(&home, &fake, &keys, false).await;
    let a = conn(&home).await;
    let b = conn(&home).await;
    let program = conn(&home).await;
    call::<DaemonStatus>(&a, unlock(Some(PERSON)))
        .await
        .expect("unlock");
    call::<Value>(&a, presence_window(Some(Window::Always), None))
        .await
        .expect("tighten");
    call::<Value>(&a, presence_window(Some(Window::FiveMinutes), Some(PERSON)))
        .await
        .expect("5 minutes, and no window from that");
    // Touch ID on a's key.
    let (open, release) = fake.hold_next();
    let asked = {
        let a = Arc::clone(&a);
        tokio::spawn(async move { call::<Value>(&a, view(None)).await })
    };
    opened(open).await;
    assert_eq!(
        fake.last(),
        "let the terminal ttys040 use your vault for 5 minutes"
    );
    set_password(&program, "edit 1").await;
    release.send(()).unwrap();
    let e = at_once(asked).await.unwrap().expect_err("refused");
    assert_eq!(e.code, ErrorCode::Conflict);
    call::<Value>(&a, view(None)).await.expect("asked again");
    assert_eq!(fake.asked(), 2, "the conflict opened no window");
    call::<Value>(&a, view(None)).await.expect("covered");
    assert_eq!(fake.asked(), 2, "the hand-out opened it");
    // The password sent again, on b's key.
    fake.available.store(false, Ordering::SeqCst);
    assert_eq!(code(&b, view(None)).await, ErrorCode::PresenceRequired);
    set_password(&program, "edit 2").await;
    assert_eq!(code(&b, view(Some(PERSON))).await, ErrorCode::Conflict);
    assert_eq!(
        code(&b, view(None)).await,
        ErrorCode::PresenceRequired,
        "the conflict opened no window"
    );
    call::<Value>(&b, view(Some(PERSON)))
        .await
        .expect("handed out");
    call::<Value>(&b, view(None)).await.expect("covered");
}

/// An `unlock` with `presence` fields, as a client sends it.
async fn unlock_with(
    c: &Conn,
    password: &str,
    shown: Option<Window>,
    untyped: bool,
) -> Result<DaemonStatus, ErrorBody> {
    let presence = crate::client::Presence {
        notify: false,
        shown,
        untyped,
    };
    c.0.lock()
        .await
        .call_presence::<DaemonStatus>(unlock(Some(password)), presence, &mut |_| {})
        .await
        .map(|(v, _)| v)
}

async fn passkey_verified(c: &Conn) -> bool {
    let s: DaemonStatus = call(c, Request::Status).await.expect("status");
    s.passkey_verified
}

/// A password the client didn't read on its terminal (`untyped`) unlocks,
/// and is no passkey verification of ADR 0020 §8, with the gate on (Omar's
/// decision B of 2026-11-19): neither at an unlock nor on an already
/// unlocked `klavd`. A typed one still is. The passkey setting is loosened
/// to 5 minutes first: under Always, the default, no unlock outside the
/// passkey frame covers a use anyway. Besides `status`, a real passkey
/// sign-in (`passkey_get`, through `passkey_presence`) is tried after each
/// unlock: after an untyped one it asks for a verification (no Touch ID
/// here, so it is refused); after a typed one it goes through.
#[tokio::test(flavor = "multi_thread")]
async fn an_untyped_unlock_is_no_passkey_verification_with_the_gate_on() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().unwrap();
    let home = Home::at(dir.path().join("home"));
    account(&server, &home, "ana@example.com", PERSON).await;
    let fake = Fake::new(false);
    let _klavd = daemon(&home, &fake, &[session(40), session(41)], false).await;
    let a = conn(&home).await;
    let b = conn(&home).await;
    unlock_shown(&a, PERSON).await.expect("unlock");
    call::<Value>(
        &a,
        Request::PasskeyUv {
            window: Some(Window::FiveMinutes),
            password: secret(Some(PERSON)),
        },
    )
    .await
    .expect("loosen");
    // A passkey to sign in with, made with the password (no Touch ID).
    let mut create = passkey_create(1);
    if let Request::PasskeyCreate { password, .. } = &mut create {
        *password = secret(Some(PERSON));
    }
    let created = call::<Value>(&a, create).await.expect("created");
    let item = created["item"].as_str().expect("the login").to_owned();
    call::<DaemonStatus>(&a, Request::Lock).await.expect("lock");
    // Untyped: unlocked, no window, no passkey verification, even with a
    // `shown` that matches.
    let s = unlock_with(&a, PERSON, Some(Window::FiveMinutes), true)
        .await
        .expect("unlock");
    assert!(s.unlocked);
    assert_eq!(
        code(&a, passkey_get(&item)).await,
        ErrorCode::BiometryUnavailable,
        "the sign-in asks for a verification"
    );
    assert!(!passkey_verified(&a).await);
    assert_eq!(code(&a, view(None)).await, ErrorCode::PresenceRequired);
    // Already unlocked, another key: the same.
    unlock_with(&b, PERSON, Some(Window::FiveMinutes), true)
        .await
        .expect("unlock");
    assert!(!passkey_verified(&b).await);
    assert_eq!(
        code(&b, passkey_get(&item)).await,
        ErrorCode::BiometryUnavailable,
        "the sign-in asks for a verification"
    );
    // Typed: both.
    unlock_with(&b, PERSON, Some(Window::FiveMinutes), false)
        .await
        .expect("unlock");
    assert!(passkey_verified(&b).await);
    call::<Value>(&b, passkey_get(&item))
        .await
        .expect("the typed unlock covers the sign-in");
    call::<DaemonStatus>(&a, Request::Lock).await.expect("lock");
    unlock_with(&a, PERSON, Some(Window::FiveMinutes), false)
        .await
        .expect("unlock");
    assert!(passkey_verified(&a).await);
    call::<Value>(&a, passkey_get(&item))
        .await
        .expect("the typed unlock covers the sign-in");
    call::<Value>(&a, view(None)).await.expect("a's window");
}

/// With the setting on Always, the value's dialog names who asks, as the
/// dialogs that open a window do (Omar's decision C of 2026-11-19): the
/// terminal, so the CLI's "Touch ID for the terminal …" line has something
/// to be compared with, and "this connection" for a caller with no
/// terminal and no window key of its own.
#[tokio::test(flavor = "multi_thread")]
async fn the_always_dialog_names_who_asks() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().unwrap();
    let home = Home::at(dir.path().join("home"));
    account(&server, &home, "ana@example.com", PERSON).await;
    let fake = Fake::new(true);
    let keys = [session(40), Key::Connection(0)];
    let _klavd = daemon(&home, &fake, &keys, false).await;
    let terminal = conn(&home).await;
    let connection = conn(&home).await;
    call::<DaemonStatus>(&terminal, unlock(Some(PERSON)))
        .await
        .expect("unlock");
    call::<Value>(&terminal, presence_window(Some(Window::Always), None))
        .await
        .expect("tighten");
    call::<Value>(&terminal, view(None)).await.expect("value");
    assert_eq!(
        fake.last(),
        "show the values of “GitHub” (for the terminal ttys040)"
    );
    call::<Value>(
        &connection,
        Request::Totp {
            query: "GitHub".into(),
            field: None,
            password: None,
        },
    )
    .await
    .ok();
    assert_eq!(
        fake.last(),
        "show the code of “GitHub” (for this connection)"
    );
    assert_eq!(fake.asked(), 2);
}

/// Sets the password of «GitHub» to `value`, through `klavd` on `c`: the
/// old one becomes the newest entry of its history.
async fn set_password(c: &Conn, value: &str) {
    call::<Value>(
        c,
        Request::Edit {
            query: "GitHub".into(),
            patch: password_patch(value),
        },
    )
    .await
    .expect("edited");
}

fn password_patch(value: &str) -> klav_client::ops::ItemPatch {
    klav_client::ops::ItemPatch {
        set: vec![klav_client::ops::FieldInput {
            name: "password".into(),
            value: SecretText::new(value),
            kind: None,
            secret: true,
        }],
        ..Default::default()
    }
}

/// The newest previous password of «GitHub».
fn previous(password: Option<&str>) -> Request {
    Request::PreviousPassword {
        query: "GitHub".into(),
        index: 0,
        password: secret(password),
    }
}

/// Whether a value `klavd` handed out holds `value` (never printed).
fn holds(answer: &Value, value: &str) -> bool {
    answer.to_string().contains(value)
}

/// An item edited between the ask and the hand-out is not handed out
/// (Omar's decision F of 2026-11-19): `klavd` remembers the version of the
/// item it asked about and answers `conflict` if the hand-out finds another,
/// for `view` and `previous_password`, under Touch ID (the dialog held open
/// while a program changes the password) and under the password sent again
/// (the change made between `presence_required` and the resend). Without
/// the check, "show a previous password of “GitHub”" would hand out what
/// the person's current password was a moment before. An item nobody edited
/// is still handed out, by both paths.
#[tokio::test(flavor = "multi_thread")]
async fn an_item_edited_while_its_dialog_is_open_is_not_handed_out() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().unwrap();
    let home = Home::at(dir.path().join("home"));
    account(&server, &home, "ana@example.com", PERSON).await;
    let fake = Fake::new(true);
    let _klavd = daemon(&home, &fake, &[session(40), session(41)], false).await;
    let a = conn(&home).await;
    let program = conn(&home).await;
    call::<DaemonStatus>(&a, unlock(Some(PERSON)))
        .await
        .expect("unlock");
    // Always: every value asks, so each round below is an ask of its own.
    call::<Value>(&a, presence_window(Some(Window::Always), None))
        .await
        .expect("tighten");
    set_password(&a, "edit 1").await;
    set_password(&a, "edit 2").await;
    let mut edits = 2;
    for (what, request) in [
        ("view", view as fn(Option<&str>) -> Request),
        ("previous", previous),
    ] {
        // Touch ID: the program edits while the dialog is open.
        let (open, release) = fake.hold_next();
        let asked = {
            let a = Arc::clone(&a);
            tokio::spawn(async move { call::<Value>(&a, request(None)).await })
        };
        opened(open).await;
        edits += 1;
        set_password(&program, &format!("edit {edits}")).await;
        release.send(()).unwrap();
        let e = at_once(asked).await.unwrap().expect_err("refused");
        assert_eq!(e.code, ErrorCode::Conflict, "{what}, Touch ID");
        assert!(e.message.contains("nothing was handed out"), "{what}");
        // The password sent again: the program edits between the ask and
        // the resend. The password is checked (it answers the ask), and the
        // hand-out still finds another version.
        fake.available.store(false, Ordering::SeqCst);
        assert_eq!(
            code(&a, request(None)).await,
            ErrorCode::PresenceRequired,
            "{what}"
        );
        edits += 1;
        set_password(&program, &format!("edit {edits}")).await;
        let e = call::<Value>(&a, request(Some(PERSON)))
            .await
            .expect_err("refused");
        assert_eq!(e.code, ErrorCode::Conflict, "{what}, password");
        fake.available.store(true, Ordering::SeqCst);
    }
    // Nobody edits: handed out, by both paths.
    let (open, release) = fake.hold_next();
    let asked = {
        let a = Arc::clone(&a);
        tokio::spawn(async move { call::<Value>(&a, view(None)).await })
    };
    opened(open).await;
    release.send(()).unwrap();
    let shown = at_once(asked).await.unwrap().expect("handed out");
    assert!(holds(&shown, &format!("edit {edits}")), "the current one");
    let old = call::<Value>(&a, previous(None)).await.expect("handed out");
    assert!(
        holds(&old, &format!("edit {}", edits - 1)),
        "the newest old one"
    );
    fake.available.store(false, Ordering::SeqCst);
    for request in [view as fn(Option<&str>) -> Request, previous] {
        assert_eq!(code(&a, request(None)).await, ErrorCode::PresenceRequired);
        call::<Value>(&a, request(Some(PERSON)))
            .await
            .expect("handed out");
    }
}

/// A sync that brings a new version of the item from the server while the
/// dialog is open counts as an edit (Omar's decision F of 2026-11-19): the
/// password is changed on another device of the account, and `klavd` syncs
/// before the person answers.
#[tokio::test(flavor = "multi_thread")]
async fn a_new_version_synced_during_the_dialog_is_not_handed_out() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().unwrap();
    let home = Home::at(dir.path().join("home"));
    account(&server, &home, "ana@example.com", PERSON).await;
    let secret_key = std::fs::read_to_string(home.file("secret-key")).expect("secret key");
    let mut phone = klav_client::login(
        &Home::at(dir.path().join("phone")),
        klav_client::LoginRequest {
            server: server.url.clone(),
            email: "ana@example.com".into(),
            password: MasterPassword::new(PERSON),
            secret_key: SecretKey::parse(secret_key.trim()).expect("secret key"),
            device_name: "phone".into(),
            device_kind: klav_proto::auth::DeviceKind::Cli,
        },
    )
    .await
    .expect("another device");
    let fake = Fake::new(true);
    let _klavd = daemon(&home, &fake, &[session(40), session(41)], false).await;
    let a = conn(&home).await;
    let program = conn(&home).await;
    call::<DaemonStatus>(&a, unlock(Some(PERSON)))
        .await
        .expect("unlock");
    call::<Value>(&a, presence_window(Some(Window::Always), None))
        .await
        .expect("tighten");
    let (open, release) = fake.hold_next();
    let asked = {
        let a = Arc::clone(&a);
        tokio::spawn(async move { call::<Value>(&a, view(None)).await })
    };
    opened(open).await;
    phone.sync().await.expect("the phone syncs");
    phone
        .edit("GitHub", &password_patch("from the phone"))
        .await
        .expect("edited on the phone");
    call::<Value>(&program, Request::Sync)
        .await
        .expect("klavd syncs");
    release.send(()).unwrap();
    let e = at_once(asked).await.unwrap().expect_err("refused");
    assert_eq!(e.code, ErrorCode::Conflict);
    // The next ask is about the synced version, and hands it out.
    let shown = call::<Value>(&a, view(None)).await.expect("handed out");
    assert!(holds(&shown, "from the phone"));
}

/// The reference, by name, of the field `field` of the item titled
/// `title`, read through `klavd` without a value.
async fn reference_of(c: &Conn, title: &str, field: &str) -> String {
    let view = call::<Value>(c, view_of(title, None).without_reveal())
        .await
        .expect("view");
    let reference = view["reference"].as_str().expect("reference");
    format!("{reference}/{field}")
}

impl Request {
    /// The same `view`, without `reveal`: metadata only, outside the gate.
    fn without_reveal(self) -> Request {
        match self {
            Request::View { query, .. } => Request::View {
                query,
                reveal: false,
                password: None,
            },
            other => other,
        }
    }
}

fn resolve_of(references: &[String], password: Option<&str>) -> Request {
    Request::Resolve {
        references: references.to_vec(),
        password: secret(password),
    }
}

/// The text values a `resolve` handed out (never printed).
fn resolved(answer: Value) -> Vec<String> {
    serde_json::from_value::<Vec<klav_client::ops::ResolvedValue>>(answer)
        .expect("resolved values")
        .iter()
        .map(|v| v.text().expect("text").to_owned())
        .collect()
}

/// `resolve` is bound to what its references named when it was asked
/// about (Omar's decision K of 2026-11-19): every reference is resolved to
/// its item before the ask, each item's version is kept with it, and the
/// hand-out answers `conflict` if any of them was edited, renamed away or
/// replaced in between, under Touch ID (the dialog held open) and under the
/// password sent again. Under 5 minutes, that `conflict` opens no window,
/// so the rerun asks again. A reference that names nothing is refused
/// before any ask. Unedited items are still handed out, by both paths.
#[tokio::test(flavor = "multi_thread")]
async fn a_resolve_whose_items_change_while_it_asks_hands_out_nothing() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().unwrap();
    let home = Home::at(dir.path().join("home"));
    account(&server, &home, "ana@example.com", PERSON).await;
    let fake = Fake::new(true);
    let keys = [session(40), session(41), session(42)];
    let _klavd = daemon(&home, &fake, &keys, false).await;
    let a = conn(&home).await;
    let b = conn(&home).await;
    let program = conn(&home).await;
    call::<DaemonStatus>(&a, unlock(Some(PERSON)))
        .await
        .expect("unlock");
    create(&a, "Bank").await;
    set_password(&a, "github 1").await;
    call::<Value>(
        &a,
        Request::Edit {
            query: "Bank".into(),
            patch: password_patch("bank 1"),
        },
    )
    .await
    .expect("edited");
    // By title, so a rename can point them at another item.
    let references = vec![
        reference_of(&a, "GitHub", "password").await,
        reference_of(&a, "Bank", "password").await,
    ];
    assert!(
        references[0].ends_with("/GitHub/password"),
        "{references:?}"
    );

    // A reference that names nothing: refused before any ask.
    let nothing = vec![references[0].replace("/GitHub/", "/Nowhere/")];
    let e = call::<Value>(&a, resolve_of(&nothing, None))
        .await
        .expect_err("refused");
    // As the hand-out refuses it: a reference error is `invalid`.
    assert_eq!(e.code, ErrorCode::Invalid, "{}", e.message);
    assert!(e.message.contains("not found"), "{}", e.message);
    assert_eq!(fake.asked(), 0, "nothing was asked");

    call::<Value>(&a, presence_window(Some(Window::FiveMinutes), Some(PERSON)))
        .await
        .expect("5 minutes");
    let mut edits = 1;
    // Touch ID: the program edits the second item while the dialog is
    // open, then swaps the first one's title.
    for change in ["edit", "rename"] {
        let (open, release) = fake.hold_next();
        let asked = {
            let a = Arc::clone(&a);
            let request = resolve_of(&references, None);
            tokio::spawn(async move { call::<Value>(&a, request).await })
        };
        opened(open).await;
        assert_eq!(
            fake.last(),
            "let the terminal ttys040 use your vault for 5 minutes",
            "{change}"
        );
        if change == "edit" {
            edits += 1;
            call::<Value>(
                &program,
                Request::Edit {
                    query: "Bank".into(),
                    patch: password_patch(&format!("bank {edits}")),
                },
            )
            .await
            .expect("edited");
        } else {
            rename(&program, "GitHub", "GitHub (old)").await;
            create(&program, "GitHub").await;
            set_password(&program, "replaced").await;
        }
        release.send(()).unwrap();
        let e = at_once(asked).await.unwrap().expect_err("refused");
        assert_eq!(e.code, ErrorCode::Conflict, "{change}, Touch ID");
        assert!(e.message.contains("nothing was handed out"), "{change}");
        if change == "rename" {
            call::<Value>(
                &program,
                Request::Trash {
                    query: "GitHub".into(),
                },
            )
            .await
            .expect("trashed");
            rename(&program, "GitHub (old)", "GitHub").await;
        }
        // No window from that answer: the rerun asks again, and the
        // unedited items are handed out.
        let before = fake.asked();
        let values = resolved(
            call::<Value>(&a, resolve_of(&references, None))
                .await
                .expect("handed out"),
        );
        assert_eq!(fake.asked(), before + 1, "{change}: the rerun asks");
        assert_eq!(values, ["github 1".to_owned(), format!("bank {edits}")]);
        call::<DaemonStatus>(&a, Request::Lock).await.expect("lock");
        call::<DaemonStatus>(&a, unlock(Some(PERSON)))
            .await
            .expect("unlock");
    }

    // The password sent again, on b's key: an edit between the ask and the
    // resend is a `conflict` (the password answers the ask, and is
    // checked); a swap makes `klavd` ask again (the request names other
    // items now).
    fake.available.store(false, Ordering::SeqCst);
    assert_eq!(
        code(&b, resolve_of(&references, None)).await,
        ErrorCode::PresenceRequired
    );
    edits += 1;
    call::<Value>(
        &program,
        Request::Edit {
            query: "Bank".into(),
            patch: password_patch(&format!("bank {edits}")),
        },
    )
    .await
    .expect("edited");
    assert_eq!(
        code(&b, resolve_of(&references, Some(PERSON))).await,
        ErrorCode::Conflict
    );
    assert_eq!(
        code(&b, resolve_of(&references, None)).await,
        ErrorCode::PresenceRequired,
        "the conflict opened no window"
    );
    rename(&program, "GitHub", "GitHub (old)").await;
    create(&program, "GitHub").await;
    set_password(&program, "replaced").await;
    assert_eq!(
        code(&b, resolve_of(&references, Some(PERSON))).await,
        ErrorCode::PresenceRequired,
        "another item now: asked again, the password unchecked"
    );
    call::<Value>(
        &program,
        Request::Trash {
            query: "GitHub".into(),
        },
    )
    .await
    .expect("trashed");
    rename(&program, "GitHub (old)", "GitHub").await;
    assert_eq!(
        code(&b, resolve_of(&references, None)).await,
        ErrorCode::PresenceRequired
    );
    let values = resolved(
        call::<Value>(&b, resolve_of(&references, Some(PERSON)))
            .await
            .expect("handed out"),
    );
    assert_eq!(values, ["github 1".to_owned(), format!("bank {edits}")]);
    call::<Value>(&b, resolve_of(&references, None))
        .await
        .expect("covered by the window the hand-out opened");
}

/// `generated_value` is bound to its generator history entry when it is
/// asked about (Omar's decision K of 2026-11-19): an instant that names no
/// entry is refused before any ask, and an entry deleted while the dialog
/// is open is a `conflict` that opens no window, where the hand-out used
/// to look the instant up afresh. An entry nobody touched is handed out.
#[tokio::test(flavor = "multi_thread")]
async fn a_generated_value_whose_entry_goes_while_it_asks_hands_out_nothing() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().unwrap();
    let home = Home::at(dir.path().join("home"));
    account(&server, &home, "ana@example.com", PERSON).await;
    let fake = Fake::new(true);
    let _klavd = daemon(&home, &fake, &[session(40), session(41)], false).await;
    let a = conn(&home).await;
    let program = conn(&home).await;
    call::<DaemonStatus>(&a, unlock(Some(PERSON)))
        .await
        .expect("unlock");
    call::<Value>(&a, presence_window(Some(Window::FiveMinutes), Some(PERSON)))
        .await
        .expect("5 minutes");
    let record = |value: &'static str| {
        let a = Arc::clone(&a);
        async move {
            let answer = call::<Value>(
                &a,
                Request::GeneratorRecord {
                    value: SecretText::new(value),
                    host: None,
                },
            )
            .await
            .expect("recorded");
            answer["created_at"].as_i64().expect("created_at")
        }
    };
    let generated = |created_at: i64, password: Option<&str>| Request::GeneratedValue {
        created_at,
        password: secret(password),
    };
    let first = record("generated one").await;
    // An instant that names no entry: refused before any ask.
    let e = call::<Value>(&a, generated(first - 1, None))
        .await
        .expect_err("refused");
    assert_eq!(e.code, ErrorCode::NotFound, "{}", e.message);
    assert_eq!(fake.asked(), 0, "nothing was asked");
    // Deleted while the dialog is open.
    let (open, release) = fake.hold_next();
    let asked = {
        let a = Arc::clone(&a);
        tokio::spawn(async move { call::<Value>(&a, generated(first, None)).await })
    };
    opened(open).await;
    call::<Value>(
        &program,
        Request::GeneratorDelete {
            which: klav_client::history::GeneratedSelection::Some(vec![first]),
        },
    )
    .await
    .expect("deleted");
    release.send(()).unwrap();
    let e = at_once(asked).await.unwrap().expect_err("refused");
    assert_eq!(e.code, ErrorCode::Conflict, "{}", e.message);
    assert!(e.message.contains("nothing was handed out"));
    // Untouched: handed out, and the window it opened covers the next.
    let second = record("generated two").await;
    let before = fake.asked();
    let shown = call::<Value>(&a, generated(second, None))
        .await
        .expect("handed out");
    assert_eq!(fake.asked(), before + 1, "the conflict opened no window");
    assert!(holds(&shown, "generated two"));
    call::<Value>(&a, generated(second, None))
        .await
        .expect("covered");
    assert_eq!(fake.asked(), before + 1);
}

// ------------------------------------------------- the extension (layer 4)

/// A browser's extension on the socket, as `klav-native-host` relays it.
/// Events and the answers to its own requests share the line: an event
/// read while it waits for an answer is kept for [`Ext::event`].
struct Ext {
    reader: tokio::io::BufReader<tokio::net::unix::OwnedReadHalf>,
    writer: tokio::net::unix::OwnedWriteHalf,
    next: u64,
    events: std::collections::VecDeque<Value>,
}

impl Ext {
    /// Connects and attaches: the connection takes the next key.
    async fn attach(home: &Home) -> Ext {
        let stream = tokio::net::UnixStream::connect(home.socket_path())
            .await
            .expect("connect");
        let (read, writer) = stream.into_split();
        let mut ext = Ext {
            reader: tokio::io::BufReader::new(read),
            writer,
            next: 1,
            events: std::collections::VecDeque::new(),
        };
        let answer = ext
            .request(serde_json::json!({ "op": "extension_attach", "browser": "Chrome" }))
            .await;
        assert!(answer.get("ok").is_some(), "{answer}");
        ext
    }

    async fn line(&mut self) -> Value {
        use tokio::io::AsyncBufReadExt;
        let mut line = String::new();
        tokio::time::timeout(Duration::from_secs(30), self.reader.read_line(&mut line))
            .await
            .expect("a line in time")
            .expect("read");
        serde_json::from_str(&line).expect("json line")
    }

    /// Sends `request` and returns its answer.
    async fn request(&mut self, request: Value) -> Value {
        use tokio::io::AsyncWriteExt;
        let id = self.next;
        self.next += 1;
        let line = serde_json::json!({ "v": 1, "id": id, "request": request });
        let mut bytes = serde_json::to_vec(&line).expect("json");
        bytes.push(b'\n');
        self.writer.write_all(&bytes).await.expect("write");
        loop {
            let line = self.line().await;
            if line.get("event").is_some() {
                self.events.push_back(line["event"].clone());
            } else {
                assert_eq!(line["id"], id, "{line}");
                return line;
            }
        }
    }

    /// The next event `klavd` sends this extension.
    async fn event(&mut self) -> Value {
        if let Some(event) = self.events.pop_front() {
            return event;
        }
        let line = self.line().await;
        assert!(line["event"].is_object(), "expected an event, got {line}");
        line["event"].clone()
    }

    /// Whether `klavd` sends this extension no event for a while.
    async fn quiet(&mut self) -> bool {
        use tokio::io::AsyncBufReadExt;
        if !self.events.is_empty() {
            return false;
        }
        let mut line = String::new();
        tokio::time::timeout(SETTLE, self.reader.read_line(&mut line))
            .await
            .is_err()
    }

    /// Answers event `event` with `body` (`{"ok": …}` or `{"error": …}`).
    async fn reply(&mut self, event: &Value, mut body: Value) -> Value {
        body["op"] = "extension_reply".into();
        body["event"] = event["id"].clone();
        self.request(body).await
    }

    /// Answers the next event, a `tab`, with tab 3 of this browser.
    async fn tab(&mut self, focused: bool) {
        let event = self.event().await;
        assert_eq!(event["kind"], "tab", "{event}");
        let answer = self
            .reply(
                &event,
                serde_json::json!({ "ok": {
                    "tab_id": 3, "url": "https://github.com/login", "focused": focused
                } }),
            )
            .await;
        assert!(answer.get("ok").is_some(), "{answer}");
    }

    /// Answers the next event, a `fill`, with the fields it got; returns it.
    async fn filled(&mut self) -> Value {
        let event = self.event().await;
        assert_eq!(event["kind"], "fill", "{event}");
        let names: Vec<Value> = event["fields"]
            .as_array()
            .expect("fields")
            .iter()
            .map(|f| f["name"].clone())
            .collect();
        let answer = self
            .reply(
                &event,
                serde_json::json!({ "ok": { "url": "https://github.com", "filled": names } }),
            )
            .await;
        assert!(answer.get("ok").is_some(), "{answer}");
        event
    }
}

/// A process the extension's connection is keyed on (macOS: the browser).
fn browser_parent() -> Key {
    Key::Parent(peer::Process {
        pid: 4242,
        start: peer::StartTime(9),
    })
}

/// The ID of «GitHub», the account's one login.
async fn github(c: &Conn) -> klav_core::ids::ItemId {
    let request: Request =
        serde_json::from_value(serde_json::json!({ "op": "list", "filter": {} })).expect("list");
    let items: Value = call(c, request).await.expect("list");
    serde_json::from_value(items[0]["id"].clone()).expect("item id")
}

/// An agent's fill of «GitHub» into `tab`.
fn agent_fill(tab: &str, item: Option<klav_core::ids::ItemId>) -> Request {
    Request::BrowserFill {
        tab: tab.to_owned(),
        host: "github.com".into(),
        agent: "claude-code".into(),
        agent_id: None,
        reason: "log in to check CI".into(),
        item,
        kind: ItemKind::Login,
        fields: serde_json::from_value(serde_json::json!([
            { "name": "password", "kind": "password", "value": "MARKER-pw" }
        ]))
        .expect("fields"),
        selectors: Vec::new(),
        submit: false,
    }
}

/// Sends `request` from `c` in the background.
fn spawn_call(
    c: &Arc<Conn>,
    request: Request,
) -> tokio::task::JoinHandle<Result<Value, ErrorBody>> {
    let c = Arc::clone(c);
    tokio::spawn(async move { call::<Value>(&c, request).await })
}

/// The agent's `browser_tab`, answered by `ext` (the only one attached).
async fn agent_tab(agent: &Arc<Conn>, ext: &mut Ext) -> String {
    let asked = spawn_call(agent, Request::BrowserTab);
    ext.tab(false).await;
    let tab = at_once(asked).await.unwrap().expect("tab");
    tab["tab"].as_str().expect("tab").to_owned()
}

/// ADR 0041 §3.1 with Touch ID: one presence per extension connection
/// until Klav locks, with the text that names the fill; nothing asked again
/// for the next fill; a lock drops it, and a locked `klavd` fills nothing.
#[tokio::test(flavor = "multi_thread")]
async fn an_extension_connection_asks_once_until_klav_locks() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().unwrap();
    let home = Home::at(dir.path().join("home"));
    account(&server, &home, "ana@example.com", PERSON).await;
    let fake = Fake::new(true);
    let _klavd = daemon(
        &home,
        &fake,
        &[browser_parent(), session(1), session(2)],
        false,
    )
    .await;
    let mut ext = Ext::attach(&home).await;
    let person = conn(&home).await;
    let agent = conn(&home).await;
    call::<DaemonStatus>(&person, unlock(None))
        .await
        .expect("unlock");
    assert_eq!(fake.asked(), 1);
    let item = github(&person).await;
    let tab = agent_tab(&agent, &mut ext).await;

    let filled = spawn_call(&agent, agent_fill(&tab, Some(item)));
    let event = ext.filled().await;
    assert_eq!(event["fields"][0]["value"], "MARKER-pw");
    let report = at_once(filled).await.unwrap().expect("filled");
    assert!(!report.to_string().contains("MARKER"), "{report}");
    assert_eq!(fake.asked(), 2);
    assert_eq!(
        fake.last(),
        "let agents fill in a browser until Klav locks, starting with “claude-code”'s fill of “GitHub”"
    );
    // The next fill on that connection asks nothing.
    let filled = spawn_call(&agent, agent_fill(&tab, Some(item)));
    ext.filled().await;
    at_once(filled).await.unwrap().expect("filled");
    assert_eq!(fake.asked(), 2);

    // Locked: nothing reaches the page, and the agent hears why.
    call::<Value>(&person, Request::Lock).await.expect("lock");
    let e = call::<Value>(&agent, agent_fill(&tab, Some(item)))
        .await
        .expect_err("locked");
    assert_eq!(e.code, ErrorCode::Locked);
    assert!(ext.quiet().await, "no event while locked");
    // Unlocked again: the connection asks once more.
    call::<DaemonStatus>(&person, unlock(None))
        .await
        .expect("unlock");
    assert_eq!(fake.asked(), 3);
    let filled = spawn_call(&agent, agent_fill(&tab, Some(item)));
    ext.filled().await;
    at_once(filled).await.unwrap().expect("filled");
    assert_eq!(fake.asked(), 4);
}

/// With the setting on Always every event asks, with the one Always text
/// (Omar's decision of 2026-11-19); a fill from an SDK that names no item
/// names none. Canceled: `denied`, and the page gets nothing.
#[tokio::test(flavor = "multi_thread")]
async fn on_always_every_agent_event_asks_and_a_cancel_fills_nothing() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().unwrap();
    let home = Home::at(dir.path().join("home"));
    account(&server, &home, "ana@example.com", PERSON).await;
    let fake = Fake::new(true);
    let _klavd = daemon(
        &home,
        &fake,
        &[browser_parent(), session(1), session(2)],
        false,
    )
    .await;
    let mut ext = Ext::attach(&home).await;
    let person = conn(&home).await;
    let agent = conn(&home).await;
    call::<DaemonStatus>(&person, unlock(None))
        .await
        .expect("unlock");
    call::<Value>(&person, presence_window(Some(Window::Always), None))
        .await
        .expect("tighten");
    let item = github(&person).await;
    let tab = agent_tab(&agent, &mut ext).await;
    for n in 2..4 {
        let filled = spawn_call(&agent, agent_fill(&tab, Some(item)));
        ext.filled().await;
        at_once(filled).await.unwrap().expect("filled");
        assert_eq!(fake.asked(), n);
        assert_eq!(
            fake.last(),
            "let a browser connection receive “claude-code”'s values for “GitHub”"
        );
    }
    let filled = spawn_call(&agent, agent_fill(&tab, None));
    ext.filled().await;
    at_once(filled).await.unwrap().expect("filled");
    assert_eq!(
        fake.last(),
        "let a browser connection receive “claude-code”'s values"
    );

    fake.cancels.store(true, Ordering::SeqCst);
    let e = call::<Value>(&agent, agent_fill(&tab, Some(item)))
        .await
        .expect_err("declined");
    assert_eq!(e.code, ErrorCode::Denied);
    assert!(
        e.message.contains("declined in the browser"),
        "{}",
        e.message
    );
    assert!(ext.quiet().await, "the page got nothing");
}

/// Without Touch ID (Linux, or a Mac without it): the extension connection
/// that will get the fill is asked, in Klav's frame, with what `klavd`'s
/// dialog would say, as data; the count of connections as a hint. Only a
/// master password `klavd` checks, sent on that connection, verifies it:
/// not a wrong one (the frame asks again), not another connection's, not
/// an `extension_reply`. Canceling in the frame is `denied`.
#[tokio::test(flavor = "multi_thread")]
async fn without_touch_id_the_frame_asks_on_the_connection_that_gets_the_fill() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().unwrap();
    let home = Home::at(dir.path().join("home"));
    account(&server, &home, "ana@example.com", PERSON).await;
    let fake = Fake::new(false);
    let _klavd = daemon(
        &home,
        &fake,
        &[
            Key::Connection(0),
            Key::Connection(0),
            session(1),
            session(2),
        ],
        false,
    )
    .await;
    let mut front = Ext::attach(&home).await;
    let mut other = Ext::attach(&home).await;
    let person = conn(&home).await;
    let agent = conn(&home).await;
    call::<DaemonStatus>(&person, unlock(Some(PERSON)))
        .await
        .expect("unlock");
    let item = github(&person).await;
    // Two attached: the tab is the focused one's.
    let asked = spawn_call(&agent, Request::BrowserTab);
    other.tab(false).await;
    front.tab(true).await;
    let tab = at_once(asked).await.unwrap().expect("tab");
    let tab = tab["tab"].as_str().unwrap().to_owned();

    let filled = spawn_call(&agent, agent_fill(&tab, Some(item)));
    // Focus again before the prompt (P25), then the ask.
    other.tab(false).await;
    front.tab(true).await;
    let ask = front.event().await;
    assert_eq!(ask["kind"], "presence", "{ask}");
    assert_eq!(ask["tab_id"], 3);
    assert_eq!(
        ask["presence"],
        serde_json::json!({
            "key": "connection", "window": "5m", "lasts": "until_lock",
            "browser": {
                "event": "fill", "agent": "claude-code", "title": "GitHub",
                "attached": 2, "connection": true,
            },
        })
    );
    let id = ask["id"].clone();
    // A wrong password: refused, and the frame may try again.
    let wrong = front
        .request(serde_json::json!({ "op": "extension_presence", "event": id, "password": THEIRS }))
        .await;
    assert_eq!(wrong["error"]["code"], "wrong_credentials", "{wrong}");
    // Only the connection that got the ask answers it.
    let elsewhere = other
        .request(serde_json::json!({ "op": "extension_presence", "event": id, "password": PERSON }))
        .await;
    assert_eq!(elsewhere["error"]["code"], "not_found", "{elsewhere}");
    // The extension's own word verifies nothing.
    let said = front.reply(&ask, serde_json::json!({ "ok": {} })).await;
    assert_eq!(said["error"]["code"], "bad_request", "{said}");
    let right = front
        .request(serde_json::json!({ "op": "extension_presence", "event": id, "password": PERSON }))
        .await;
    assert!(right.get("ok").is_some(), "{right}");
    // Focus once more, right before the values go.
    other.tab(false).await;
    front.tab(true).await;
    front.filled().await;
    at_once(filled).await.unwrap().expect("filled");
    assert_eq!(fake.asked(), 0, "no Touch ID");

    // Verified until Klav locks: no ask, only the focus check.
    let filled = spawn_call(&agent, agent_fill(&tab, Some(item)));
    other.tab(false).await;
    front.tab(true).await;
    front.filled().await;
    at_once(filled).await.unwrap().expect("filled");

    // On Always, every event asks; canceling in the frame fills nothing.
    call::<Value>(&person, presence_window(Some(Window::Always), None))
        .await
        .expect("tighten");
    let filled = spawn_call(&agent, agent_fill(&tab, Some(item)));
    other.tab(false).await;
    front.tab(true).await;
    let ask = front.event().await;
    assert_eq!(ask["kind"], "presence", "{ask}");
    assert_eq!(ask["presence"]["window"], "always");
    assert!(ask["presence"].get("lasts").is_none(), "{ask}");
    let canceled = front
        .reply(
            &ask,
            serde_json::json!({ "error": { "code": "denied", "message": "canceled" } }),
        )
        .await;
    assert!(canceled.get("ok").is_some(), "{canceled}");
    let e = at_once(filled).await.unwrap().expect_err("declined");
    assert_eq!(e.code, ErrorCode::Denied);
    assert!(
        e.message.contains("declined in the browser"),
        "{}",
        e.message
    );
    assert!(front.quiet().await, "the page got nothing");
    // A password with no ask open is never checked.
    let late = front
        .request(serde_json::json!({ "op": "extension_presence", "event": id, "password": PERSON }))
        .await;
    assert_eq!(late["error"]["code"], "not_found", "{late}");
}

/// P25 (Omar's decisions on N5 and Q-N5): with two connections attached,
/// `browser_tab` and each value-carrying event go out only when exactly one
/// reports focus, checked again just before the event; otherwise
/// `browser_ambiguous`, nobody is asked, and no value goes.
#[tokio::test(flavor = "multi_thread")]
async fn with_two_browsers_only_the_one_in_front_gets_values() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().unwrap();
    let home = Home::at(dir.path().join("home"));
    account(&server, &home, "ana@example.com", PERSON).await;
    let fake = Fake::new(true);
    let _klavd = daemon(
        &home,
        &fake,
        &[browser_parent(), browser_parent(), session(1), session(2)],
        false,
    )
    .await;
    let mut a = Ext::attach(&home).await;
    let mut b = Ext::attach(&home).await;
    let person = conn(&home).await;
    let agent = conn(&home).await;
    call::<DaemonStatus>(&person, unlock(None))
        .await
        .expect("unlock");
    let asked_before = fake.asked();
    let item = github(&person).await;
    // Newest first: `b` is asked before `a`.
    for (a_focused, b_focused) in [(false, false), (true, true)] {
        let asked = spawn_call(&agent, Request::BrowserTab);
        b.tab(b_focused).await;
        a.tab(a_focused).await;
        let e = at_once(asked).await.unwrap().expect_err("ambiguous");
        assert_eq!(e.code, ErrorCode::BrowserAmbiguous);
        assert!(e.message.contains("to the front"), "{}", e.message);
    }
    let asked = spawn_call(&agent, Request::BrowserTab);
    b.tab(true).await;
    a.tab(false).await;
    let tab = at_once(asked).await.unwrap().expect("tab");
    let tab = tab["tab"].as_str().unwrap().to_owned();

    // The person moved to the other browser before the fill: refused
    // before the prompt.
    let filled = spawn_call(&agent, agent_fill(&tab, Some(item)));
    b.tab(false).await;
    a.tab(true).await;
    let e = at_once(filled).await.unwrap().expect_err("ambiguous");
    assert_eq!(e.code, ErrorCode::BrowserAmbiguous);
    assert_eq!(fake.asked(), asked_before, "nobody was asked");
    assert!(a.quiet().await && b.quiet().await, "no value went");

    // Back in front: asked (with the count), then checked again, filled.
    let filled = spawn_call(&agent, agent_fill(&tab, Some(item)));
    b.tab(true).await;
    a.tab(false).await;
    b.tab(true).await;
    a.tab(false).await;
    b.filled().await;
    at_once(filled).await.unwrap().expect("filled");
    assert_eq!(fake.asked(), asked_before + 1);
    assert_eq!(
        fake.last(),
        "let agents fill in a browser until Klav locks, starting with “claude-code”'s fill of “GitHub”; 2 browser connections are attached"
    );

    // Verified, but both in front right before the event: no value goes.
    let filled = spawn_call(&agent, agent_fill(&tab, Some(item)));
    b.tab(true).await;
    a.tab(true).await;
    let e = at_once(filled).await.unwrap().expect_err("ambiguous");
    assert_eq!(e.code, ErrorCode::BrowserAmbiguous);
    assert!(a.quiet().await && b.quiet().await, "no value went");
    // Neither in front: the same.
    let filled = spawn_call(&agent, agent_fill(&tab, Some(item)));
    b.tab(false).await;
    a.tab(false).await;
    let e = at_once(filled).await.unwrap().expect_err("ambiguous");
    assert_eq!(e.code, ErrorCode::BrowserAmbiguous);
    // One closes: the other is the only one, as with one browser.
    drop(a);
    tokio::time::sleep(SETTLE).await;
    let filled = spawn_call(&agent, agent_fill(&tab, Some(item)));
    b.filled().await;
    at_once(filled).await.unwrap().expect("filled");
    assert_eq!(fake.asked(), asked_before + 1);
}
