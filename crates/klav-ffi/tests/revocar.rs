//! Revoking an agent from the phone (ADR 0033, amendment of 2026-11-10,
//! layer 5, P10): «what it saw» first, the revocation at once and written
//! down, then the projects' keys one per call, so «Revoked» shows before
//! the key change ends. A key change cut off (the network gone, the app
//! killed) is in the phone's record and finishes from there, never
//! rotating a project twice; «Done» only once the record has nothing left.

mod common;

use common::ServerProcess;
use klav_client::agents::GrantRequest;
use klav_client::{Home, SignupRequest, Unlocked};
use klav_core::crypto::kdf::MasterPassword;
use klav_core::model::item::{Item, ItemKind};
use klav_core::policy::Policy;
use klav_ffi::KlavCore;
use klav_proto::auth::DeviceKind;
use klav_sdk::{Agent, KeyStore, Registration};
use secrecy::ExposeSecret;

const PASSWORD: &str = "correct horse battery staple";
const EMAIL: &str = "ana@example.com";

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test setup")
}

async fn register(server: &ServerProcess, dir: &tempfile::TempDir, name: &str) -> Agent {
    let (agent, _) = Agent::register(
        &Home::at(dir.path().join(format!("agent-{name}"))),
        Registration {
            name: name.into(),
            server: server.url.clone(),
            email: EMAIL.into(),
            note: None,
            key_store: KeyStore::File {
                path: dir.path().join(format!("{name}.key")),
            },
        },
    )
    .await
    .expect("register");
    agent
}

async fn approve(laptop: &mut Unlocked, agent: &Agent, projects: &[&str]) {
    laptop
        .approve_agent(
            agent.id(),
            GrantRequest {
                projects: projects.iter().map(|p| (*p).to_owned()).collect(),
                vaults: Vec::new(),
                policy: Policy::default(),
            },
            &agent.pairing_code(),
        )
        .await
        .expect("approve");
}

/// The laptop's account with two projects of one item each, `bot` on both
/// and `keeper` on General; the phone signed in to it, through a gate that
/// can hold its next request. Returns the gate (the phone needs it alive),
/// the phone and the two agents' IDs.
fn setup(
    server: &ServerProcess,
    dir: &tempfile::TempDir,
    rt: &tokio::runtime::Runtime,
) -> (common::Gate, std::sync::Arc<KlavCore>, String, String) {
    let (secret_key, bot, keeper) = rt.block_on(async {
        let (mut laptop, kit) = klav_client::signup(
            &Home::at(dir.path().join("laptop")),
            SignupRequest {
                server: server.url.clone(),
                email: EMAIL.into(),
                password: MasterPassword::new(PASSWORD),
                device_name: "laptop".into(),
                device_kind: DeviceKind::Cli,
                invite: None,
            },
        )
        .await
        .expect("sign-up");
        let vault = laptop.find_vault("Personal").expect("vault");
        laptop.create_project(vault, "Work").await.expect("project");
        for (project, title) in [("General", "GitHub"), ("Work", "Jira")] {
            let project = laptop.find_project(vault, project).expect("project");
            laptop
                .add_item(
                    vault,
                    project,
                    &Item::from_template(ItemKind::Login, title).expect("item"),
                )
                .await
                .expect("add");
        }
        let bot = register(server, dir, "bot").await;
        approve(&mut laptop, &bot, &["Personal/General", "Personal/Work"]).await;
        let keeper = register(server, dir, "keeper").await;
        approve(&mut laptop, &keeper, &["Personal/General"]).await;
        (
            kit.secret_key().to_text().expose_secret().to_owned(),
            bot.id().to_string(),
            keeper.id().to_string(),
        )
    });
    // Never production: this test's own server, on loopback.
    assert!(
        server.url.starts_with("http://127.0.0.1:"),
        "{}",
        server.url
    );
    let gate = common::Gate::start(&server.url);
    assert!(gate.url.starts_with("http://127.0.0.1:"), "{}", gate.url);
    let core = KlavCore::new(dir.path().join("phone").display().to_string()).expect("core");
    core.sign_in(
        gate.url.clone(),
        EMAIL.into(),
        PASSWORD.into(),
        secret_key,
        "iPhone".into(),
        None,
    )
    .expect("sign in");
    (gate, core, bot, keeper)
}

#[test]
fn the_phone_revokes_first_then_changes_keys_one_project_per_call() {
    let mut server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let rt = runtime();
    let (_gate, core, bot, _keeper) = setup(&server, &dir, &rt);

    // «What it saw»: both projects, their items, and who else gets a grant.
    let seen = core.agent_exposure(bot.clone()).expect("what it saw");
    assert_eq!(seen.projects.len(), 2, "{seen:?}");
    assert!(!seen.projects_unknown);
    assert_eq!(seen.cost.items, 2, "{:?}", seen.cost);
    assert!(!seen.cost.items_at_least, "{:?}", seen.cost);
    assert_eq!(seen.cost.other_agents, vec!["keeper".to_owned()]);

    // Revoked at once, nothing rotated yet: never complete.
    let first = core.revoke_agent_first(bot.clone(), true).expect("revoke");
    assert_eq!(first.agent.status, "revoked");
    assert!(first.rotated.is_empty(), "{first:?}");
    assert_eq!(first.pending.len(), 2, "{first:?}");
    assert!(!first.complete, "{first:?}");
    let listed = core.agents().expect("agents");
    let revoked = listed.iter().find(|a| a.id == bot).expect("bot");
    assert_eq!(revoked.status, "revoked");
    let left = core.agent_revocations().expect("record");
    assert_eq!(left.len(), 1, "{left:?}");
    assert_eq!((left[0].projects, left[0].to_change), (2, 2), "{left:?}");
    assert!(left[0].needs_work);

    // One project per call.
    let step = core.revocation_step(bot.clone()).expect("step");
    assert!(step.rotated.is_some() && !step.done, "{step:?}");
    assert!(step.moved, "{step:?}");
    assert!(step.failed.is_none(), "{step:?}");
    assert_eq!(step.pending.len(), 1, "{step:?}");

    // The network goes: the step says why, and the record keeps the rest.
    server.stop();
    let cut = core.revocation_step(bot.clone()).expect("step");
    assert!(cut.failed.is_some() && !cut.done, "{cut:?}");
    let left = core.agent_revocations().expect("record");
    assert_eq!((left[0].rotated, left[0].to_change), (1, 1), "{left:?}");
    assert!(left[0].last_error.is_some(), "{left:?}");

    // The app is killed: a new start of the app reads the same record.
    drop(core);
    server.restart();
    let core = KlavCore::new(dir.path().join("phone").display().to_string()).expect("core");
    core.unlock_with_password(PASSWORD.into(), None)
        .expect("unlock");
    let left = core.agent_revocations().expect("record");
    assert_eq!((left[0].rotated, left[0].to_change), (1, 1), "{left:?}");

    // «Finish»: the steps go on from there, and nothing is left at the end.
    let mut rotated = Vec::new();
    for _ in 0..10 {
        let step = core.revocation_step(bot.clone()).expect("step");
        assert!(step.failed.is_none(), "{step:?}");
        rotated.extend(step.rotated);
        if step.done {
            break;
        }
    }
    assert_eq!(
        rotated.len(),
        1,
        "the project already rotated is not rotated again: {rotated:?}"
    );
    assert!(core.agent_revocations().expect("record").is_empty());
}

#[test]
fn revoking_from_the_phone_without_the_key_change_changes_no_project_key() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let rt = runtime();
    let (_gate, core, bot, _keeper) = setup(&server, &dir, &rt);

    let report = core.revoke_agent_first(bot.clone(), false).expect("revoke");
    assert_eq!(report.agent.status, "revoked");
    assert!(report.complete, "{report:?}");
    assert!(
        report.pending.is_empty() && report.rotated.is_empty(),
        "{report:?}"
    );
    assert!(core.agent_revocations().expect("record").is_empty());
    // A step owes nothing and rotates nothing.
    let step = core.revocation_step(bot).expect("step");
    assert!(step.done && step.rotated.is_none(), "{step:?}");
    // Nothing was owed: a step that moves nothing says so, and lists no
    // project as still to change.
    assert!(!step.moved, "{step:?}");
    assert!(step.pending.is_empty(), "{step:?}");
}

/// Which call is in flight when the person locks and unlocks again.
#[derive(Clone, Copy, Debug)]
enum InFlight {
    /// `revoke_agent_first`: it writes the revocation's record (the
    /// projects owed and the never-re-grant mark) into `cache.bin`.
    Revoke,
    /// `revocation_step`: it writes that a project's key changed.
    Step,
}

/// The person locks while a call is in flight (the server frozen, so the
/// call waits on it) and unlocks before it ends: the new session reads
/// `cache.bin` before the old call writes it. A save of the new session,
/// asked after the old call ended or while it ran (it waits for it), must
/// not write that stale copy back over what the old call wrote. A new
/// start of the app, which reads only the files, sees the record.
fn lock_and_unlock_during(call: InFlight, save_waits: bool) {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let rt = runtime();
    let (gate, core, bot, _keeper) = setup(&server, &dir, &rt);
    if matches!(call, InFlight::Step) {
        core.revoke_agent_first(bot.clone(), true).expect("revoke");
    }

    let frozen = gate.hold();
    let old = {
        let (core, bot) = (core.clone(), bot.clone());
        std::thread::spawn(move || match call {
            InFlight::Revoke => core.revoke_agent_first(bot, true).map(|_| ()),
            InFlight::Step => core.revocation_step(bot).map(|_| ()),
        })
    };
    // The old call holds the account and waits on the server.
    frozen.wait_arrived();
    core.lock();
    core.unlock_with_password(PASSWORD.into(), None)
        .expect("unlock again");
    let save = save_waits.then(|| {
        let core = core.clone();
        std::thread::spawn(move || core.sync().map(|_| ()))
    });
    drop(frozen);
    // Its result is not handed out: the vault was locked meanwhile.
    let ended = old.join().expect("old call");
    assert!(
        matches!(ended, Err(klav_ffi::KlavError::Locked)),
        "{ended:?}"
    );
    match save {
        Some(save) => save.join().expect("save").expect("sync"),
        None => drop(core.sync().expect("sync")),
    }

    drop(core);
    let core = KlavCore::new(dir.path().join("phone").display().to_string()).expect("core");
    core.unlock_with_password(PASSWORD.into(), None)
        .expect("unlock");
    let left = core.agent_revocations().expect("record");
    assert_eq!(left.len(), 1, "the revocation's record is kept: {left:?}");
    let rotated_before = match call {
        InFlight::Revoke => 0,
        InFlight::Step => 1,
    };
    assert_eq!(
        (left[0].projects, left[0].rotated),
        (2, rotated_before),
        "{left:?}"
    );
    let mut rotated = Vec::new();
    for _ in 0..10 {
        let step = core.revocation_step(bot.clone()).expect("step");
        assert!(step.failed.is_none(), "{step:?}");
        rotated.extend(step.rotated);
        if step.done {
            break;
        }
    }
    assert_eq!(
        rotated.len(),
        2 - usize::try_from(rotated_before).expect("small"),
        "{rotated:?}"
    );
    assert!(core.agent_revocations().expect("record").is_empty());
}

#[test]
fn a_lock_and_unlock_during_the_revocation_keep_its_record() {
    lock_and_unlock_during(InFlight::Revoke, false);
}

#[test]
fn a_lock_and_unlock_during_the_revocation_keep_its_record_with_a_save_waiting() {
    lock_and_unlock_during(InFlight::Revoke, true);
}

#[test]
fn a_lock_and_unlock_during_a_step_keep_the_changed_key() {
    lock_and_unlock_during(InFlight::Step, false);
}

#[test]
fn a_lock_and_unlock_during_a_step_keep_the_changed_key_with_a_save_waiting() {
    lock_and_unlock_during(InFlight::Step, true);
}

/// A keystore that holds the unlock between reading the files and
/// publishing the session (its `available` waits for the test), then says
/// Face ID is not available.
struct HeldKeystore {
    reached: std::sync::mpsc::SyncSender<()>,
    release: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
}

impl klav_ffi::PlatformKeystore for HeldKeystore {
    fn available(&self) -> bool {
        let _ = self.reached.send(());
        let _ = self.release.lock().expect("test setup").recv();
        false
    }

    fn create_key(&self) -> Result<klav_ffi::KeystoreKey, klav_ffi::KeystoreError> {
        Err(klav_ffi::KeystoreError::Unavailable)
    }

    fn wrap(&self, _: Vec<u8>) -> Result<klav_ffi::KeystoreWrap, klav_ffi::KeystoreError> {
        Err(klav_ffi::KeystoreError::Unavailable)
    }

    fn unwrap(
        &self,
        _: Vec<u8>,
        _: Vec<u8>,
        _: String,
    ) -> Result<Vec<u8>, klav_ffi::KeystoreError> {
        Err(klav_ffi::KeystoreError::Unavailable)
    }

    fn boot_time(&self) -> u64 {
        0
    }

    fn confirm_owner(&self, _: String) -> Result<(), klav_ffi::KeystoreError> {
        Err(klav_ffi::KeystoreError::Unavailable)
    }
}

/// The other order: the old call ends while the new unlock is opening
/// (it read `cache.bin`, and has not published the session yet). The
/// session it publishes must not be the stale one.
#[test]
fn a_revocation_that_ends_while_the_vault_opens_again_keeps_its_record() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let rt = runtime();
    let (gate, core, bot, _keeper) = setup(&server, &dir, &rt);

    let frozen = gate.hold();
    let old = {
        let (core, bot) = (core.clone(), bot.clone());
        std::thread::spawn(move || core.revoke_agent_first(bot, true).map(|_| ()))
    };
    frozen.wait_arrived();
    core.lock();
    let (reached, held) = std::sync::mpsc::sync_channel(1);
    let (release, released) = std::sync::mpsc::channel();
    let keystore: std::sync::Arc<dyn klav_ffi::PlatformKeystore> =
        std::sync::Arc::new(HeldKeystore {
            reached,
            release: std::sync::Mutex::new(released),
        });
    let unlock = {
        let core = core.clone();
        std::thread::spawn(move || core.unlock_with_password(PASSWORD.into(), Some(keystore)))
    };
    // The unlock read the files and waits before publishing.
    held.recv().expect("the unlock reached the keystore");
    drop(frozen);
    let ended = old.join().expect("old call");
    assert!(
        matches!(ended, Err(klav_ffi::KlavError::Locked)),
        "{ended:?}"
    );
    release.send(()).expect("release");
    unlock.join().expect("unlock").expect("unlocked");
    core.sync().expect("sync");

    drop(core);
    let core = KlavCore::new(dir.path().join("phone").display().to_string()).expect("core");
    core.unlock_with_password(PASSWORD.into(), None)
        .expect("unlock");
    let left = core.agent_revocations().expect("record");
    assert_eq!(left.len(), 1, "the revocation's record is kept: {left:?}");
    assert_eq!((left[0].projects, left[0].rotated), (2, 0), "{left:?}");
}

/// Locked and not unlocked again: the call in flight ends, its keys go,
/// and the next call finds the vault locked.
#[test]
fn a_call_that_ends_after_a_lock_leaves_the_vault_locked() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let rt = runtime();
    let (gate, core, bot, _keeper) = setup(&server, &dir, &rt);

    let frozen = gate.hold();
    let old = {
        let (core, bot) = (core.clone(), bot.clone());
        std::thread::spawn(move || core.revoke_agent_first(bot, true).map(|_| ()))
    };
    frozen.wait_arrived();
    core.lock();
    drop(frozen);
    let ended = old.join().expect("old call");
    assert!(
        matches!(ended, Err(klav_ffi::KlavError::Locked)),
        "{ended:?}"
    );
    assert!(!core.status().unlocked);
    let next = core.agent_revocations();
    assert!(matches!(next, Err(klav_ffi::KlavError::Locked)), "{next:?}");
}

/// A keystore that works like the Secure Enclave without one. Face ID can
/// be held at its prompt (`unwrap`) until the test lets it answer, and
/// made to fail (the person cancels).
struct FaceIdKeystore {
    secrets: std::sync::Mutex<std::collections::HashMap<Vec<u8>, Vec<u8>>>,
    hold: std::sync::Mutex<
        Option<(
            std::sync::mpsc::SyncSender<()>,
            std::sync::mpsc::Receiver<()>,
        )>,
    >,
    cancel: std::sync::atomic::AtomicBool,
}

impl FaceIdKeystore {
    fn new() -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self {
            secrets: std::sync::Mutex::new(std::collections::HashMap::new()),
            hold: std::sync::Mutex::new(None),
            cancel: std::sync::atomic::AtomicBool::new(false),
        })
    }

    /// The next prompt says it is open on `reached`, and answers when
    /// `release` gets something.
    fn hold_next(
        &self,
    ) -> (
        std::sync::mpsc::Receiver<()>,
        std::sync::mpsc::SyncSender<()>,
    ) {
        let (reached, at) = std::sync::mpsc::sync_channel(1);
        let (release, wait) = std::sync::mpsc::sync_channel(1);
        *self.hold.lock().expect("test setup") = Some((reached, wait));
        (at, release)
    }
}

fn point() -> Vec<u8> {
    let mut p = vec![0x04];
    for _ in 0..5 {
        p.extend(uuid_bytes());
    }
    p.truncate(65);
    p
}

fn uuid_bytes() -> Vec<u8> {
    klav_core::ids::ItemId::generate().as_bytes().to_vec()
}

impl klav_ffi::PlatformKeystore for FaceIdKeystore {
    fn available(&self) -> bool {
        true
    }

    fn create_key(&self) -> Result<klav_ffi::KeystoreKey, klav_ffi::KeystoreError> {
        Ok(klav_ffi::KeystoreKey {
            handle: b"handle".to_vec(),
            public_key: point(),
        })
    }

    fn wrap(&self, _: Vec<u8>) -> Result<klav_ffi::KeystoreWrap, klav_ffi::KeystoreError> {
        let ephemeral = point();
        let mut secret = uuid_bytes();
        secret.extend(uuid_bytes());
        self.secrets
            .lock()
            .expect("test setup")
            .insert(ephemeral.clone(), secret.clone());
        Ok(klav_ffi::KeystoreWrap {
            ephemeral_public: ephemeral,
            secret,
        })
    }

    fn unwrap(
        &self,
        _: Vec<u8>,
        ephemeral_public: Vec<u8>,
        _: String,
    ) -> Result<Vec<u8>, klav_ffi::KeystoreError> {
        let held = self.hold.lock().expect("test setup").take();
        if let Some((reached, wait)) = held {
            let _ = reached.send(());
            let _ = wait.recv();
        }
        if self.cancel.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(klav_ffi::KeystoreError::Cancelled);
        }
        self.secrets
            .lock()
            .expect("test setup")
            .get(&ephemeral_public)
            .cloned()
            .ok_or(klav_ffi::KeystoreError::Other)
    }

    fn boot_time(&self) -> u64 {
        1_700_000_000
    }

    fn confirm_owner(&self, _: String) -> Result<(), klav_ffi::KeystoreError> {
        Ok(())
    }
}

/// The revocation of `bot` in flight, held at the gate: returns once its
/// first request reached the gate, which it sends only after taking the
/// account out of the slot. Dropping the hold lets the request through.
fn revocation_in_flight(
    gate: &common::Gate,
    core: &std::sync::Arc<KlavCore>,
    bot: &str,
) -> (
    common::Held,
    std::thread::JoinHandle<Result<klav_ffi::RevokeReportInfo, klav_ffi::KlavError>>,
) {
    let frozen = gate.hold();
    let old = {
        let (core, bot) = (core.clone(), bot.to_owned());
        std::thread::spawn(move || core.revoke_agent_first(bot, true))
    };
    frozen.wait_arrived();
    (frozen, old)
}

/// Holds the next read of the phone's secret-key file, which an unlock
/// with the password reads first, right after it counts as under way and
/// before the key derivation: the file is a named pipe until [`Self::put_back`].
struct HeldSecretKey {
    path: std::path::PathBuf,
    bytes: Vec<u8>,
    permissions: std::fs::Permissions,
}

impl HeldSecretKey {
    fn new(dir: &tempfile::TempDir) -> Self {
        let path = dir.path().join("phone").join("secret-key");
        let bytes = std::fs::read(&path).expect("secret key");
        let permissions = std::fs::metadata(&path).expect("secret key").permissions();
        std::fs::remove_file(&path).expect("secret key");
        let made = std::process::Command::new("mkfifo")
            .arg("-m")
            .arg("600")
            .arg(&path)
            .status()
            .expect("mkfifo");
        assert!(made.success(), "mkfifo");
        Self {
            path,
            bytes,
            permissions,
        }
    }

    /// Blocks until an unlock opens the file for reading: it is under way.
    /// Fails after 30 s, instead of hanging the suite, if none does.
    fn reached(&self) -> std::fs::File {
        self.reached_within(std::time::Duration::from_secs(30))
    }

    fn reached_within(&self, deadline: std::time::Duration) -> std::fs::File {
        let (opened, wait) = std::sync::mpsc::channel();
        let path = self.path.clone();
        let opener = std::thread::spawn(move || {
            let _ = opened.send(std::fs::OpenOptions::new().write(true).open(&path));
        });
        if let Ok(file) = wait.recv_timeout(deadline) {
            let _ = opener.join();
            return file.expect("the unlock reads the secret key");
        }
        // Opening the other end lets the stuck open return: no thread is
        // left behind.
        let reader = std::fs::File::open(&self.path);
        let _ = opener.join();
        drop(reader);
        panic!("no unlock opened the secret key within {deadline:?}");
    }

    /// Lets the unlock read the secret key.
    fn answer(&self, mut reader_end: std::fs::File) {
        use std::io::Write;
        reader_end.write_all(&self.bytes).expect("secret key");
    }

    /// The file as it was.
    fn put_back(self) {
        drop(self);
    }
}

impl Drop for HeldSecretKey {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
        let _ = std::fs::write(&self.path, &self.bytes);
        let _ = std::fs::set_permissions(&self.path, self.permissions.clone());
    }
}

/// With no unlock under way, waiting for one fails instead of hanging the
/// suite, and the file is put back as it was.
#[test]
fn waiting_for_an_unlock_that_never_comes_fails() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let rt = runtime();
    let (_gate, _core, _bot, _keeper) = setup(&server, &dir, &rt);
    let path = dir.path().join("phone").join("secret-key");
    let before = std::fs::read(&path).expect("secret key");
    let held = HeldSecretKey::new(&dir);
    let waited = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        held.reached_within(std::time::Duration::from_millis(200))
    }));
    assert!(waited.is_err(), "no unlock was under way");
    held.put_back();
    // Not `assert_eq!`: on a failure it would print the Secret Key's bytes.
    assert!(
        std::fs::read(&path).expect("secret key") == before,
        "the secret key is back as it was"
    );
}

/// A closed gate frees its port: nothing answers there any more.
#[test]
fn a_closed_gate_frees_its_port() {
    let server = ServerProcess::start(900);
    let gate = common::Gate::start(&server.url);
    let address = gate.url.trim_start_matches("http://").to_owned();
    std::net::TcpStream::connect(&address).expect("the gate listens");
    drop(gate);
    assert!(
        std::net::TcpStream::connect(&address).is_err(),
        "the gate still listens on {address}"
    );
}

/// A new start of the app, which reads only the files, still owes the
/// whole key change for `bot`: its record and never-re-grant mark were
/// not written over.
fn record_kept(core: std::sync::Arc<KlavCore>, dir: &tempfile::TempDir) {
    drop(core);
    let core = KlavCore::new(dir.path().join("phone").display().to_string()).expect("core");
    core.unlock_with_password(PASSWORD.into(), None)
        .expect("unlock");
    let left = core.agent_revocations().expect("record");
    assert_eq!(left.len(), 1, "the revocation's record is kept: {left:?}");
    assert_eq!((left[0].projects, left[0].rotated), (2, 0), "{left:?}");
}

/// Follow-up A of #309's re-check: unlocking again while unlocked (turning
/// Face ID on in Settings) while a call is in flight, with no lock. The
/// unlock reads the files before the call writes them and publishes its
/// session first. The call must keep what it wrote, and hand its result
/// out: nothing locked.
#[test]
fn an_unlock_while_unlocked_keeps_what_a_call_in_flight_wrote() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let rt = runtime();
    let (gate, core, bot, _keeper) = setup(&server, &dir, &rt);

    let (frozen, old) = revocation_in_flight(&gate, &core, &bot);
    core.unlock_with_password(PASSWORD.into(), Some(FaceIdKeystore::new()))
        .expect("unlock again");
    drop(frozen);
    let ended = old.join().expect("old call");
    let report = ended.expect("not locked: its result is handed out");
    assert_eq!(report.agent.status, "revoked");
    assert!(core.status().unlocked);
    core.sync().expect("sync");
    record_kept(core, &dir);
}

/// A's other order: the call ends while the unlock is still opening (it
/// read the files and waits at the keystore), so the call's session is
/// back in its place when the unlock publishes. The unlock must not
/// replace it with the copy it read.
#[test]
fn an_unlock_while_unlocked_that_publishes_after_the_call_keeps_its_writes() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let rt = runtime();
    let (gate, core, bot, _keeper) = setup(&server, &dir, &rt);

    let (frozen, old) = revocation_in_flight(&gate, &core, &bot);
    let (reached, held) = std::sync::mpsc::sync_channel(1);
    let (release, released) = std::sync::mpsc::channel();
    let keystore: std::sync::Arc<dyn klav_ffi::PlatformKeystore> =
        std::sync::Arc::new(HeldKeystore {
            reached,
            release: std::sync::Mutex::new(released),
        });
    let unlock = {
        let core = core.clone();
        std::thread::spawn(move || core.unlock_with_password(PASSWORD.into(), Some(keystore)))
    };
    held.recv().expect("the unlock read the files");
    drop(frozen);
    let ended = old.join().expect("old call");
    ended.expect("not locked: its result is handed out");
    release.send(()).expect("release");
    unlock.join().expect("unlock").expect("unlocked");
    assert!(core.status().unlocked);
    core.sync().expect("sync");
    record_kept(core, &dir);
}

/// C: Face ID unlocks after a lock while a call is in flight; the call
/// ends after it published, and what it wrote is kept.
#[test]
fn a_face_id_unlock_during_a_call_keeps_what_it_wrote() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let rt = runtime();
    let (gate, core, bot, _keeper) = setup(&server, &dir, &rt);
    let keystore = FaceIdKeystore::new();
    let dynamic: std::sync::Arc<dyn klav_ffi::PlatformKeystore> = keystore.clone();
    assert!(
        core.unlock_with_password(PASSWORD.into(), Some(dynamic.clone()))
            .expect("Face ID set up")
    );

    let (frozen, old) = revocation_in_flight(&gate, &core, &bot);
    core.lock();
    core.unlock_with_biometrics(dynamic, "unlock Klav".into())
        .expect("Face ID");
    drop(frozen);
    let ended = old.join().expect("old call");
    assert!(
        matches!(ended, Err(klav_ffi::KlavError::Locked)),
        "{ended:?}"
    );
    assert!(core.status().unlocked);
    core.sync().expect("sync");
    record_kept(core, &dir);
}

/// C: Face ID fails (the person cancels) while the call ends. The call
/// ends while the prompt is open, with no unlock under way yet: its keys
/// go, and Klav stays locked.
#[test]
fn a_failed_face_id_while_the_call_ends_leaves_the_vault_locked() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let rt = runtime();
    let (gate, core, bot, _keeper) = setup(&server, &dir, &rt);
    let keystore = FaceIdKeystore::new();
    let dynamic: std::sync::Arc<dyn klav_ffi::PlatformKeystore> = keystore.clone();
    assert!(
        core.unlock_with_password(PASSWORD.into(), Some(dynamic.clone()))
            .expect("Face ID set up")
    );

    let (frozen, old) = revocation_in_flight(&gate, &core, &bot);
    core.lock();
    let (prompt_open, answer) = keystore.hold_next();
    keystore
        .cancel
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let unlock = {
        let core = core.clone();
        std::thread::spawn(move || core.unlock_with_biometrics(dynamic, "unlock Klav".into()))
    };
    prompt_open.recv().expect("the prompt is open");
    drop(frozen);
    let ended = old.join().expect("old call");
    assert!(
        matches!(ended, Err(klav_ffi::KlavError::Locked)),
        "{ended:?}"
    );
    answer.send(()).expect("answer");
    let failed = unlock.join().expect("unlock");
    assert!(failed.is_err(), "the person cancelled");
    assert!(!core.status().unlocked);
    let next = core.agent_revocations();
    assert!(matches!(next, Err(klav_ffi::KlavError::Locked)), "{next:?}");
    record_kept(core, &dir);
}

/// C: a wrong master password while the call ends. The call ends while
/// the unlock is under way (held before its key derivation), so its
/// session is handed over; the unlock then fails, and that session goes.
/// Klav stays locked (review of #316, 3: the order is forced).
#[test]
fn a_wrong_password_while_the_call_ends_leaves_the_vault_locked() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let rt = runtime();
    let (gate, core, bot, _keeper) = setup(&server, &dir, &rt);

    let (frozen, old) = revocation_in_flight(&gate, &core, &bot);
    core.lock();
    let secret_key = HeldSecretKey::new(&dir);
    let unlock = {
        let core = core.clone();
        std::thread::spawn(move || core.unlock_with_password("not the password".into(), None))
    };
    let held = secret_key.reached();
    drop(frozen);
    let ended = old.join().expect("old call");
    assert!(
        matches!(ended, Err(klav_ffi::KlavError::Locked)),
        "{ended:?}"
    );
    secret_key.answer(held);
    let failed = unlock.join().expect("unlock");
    secret_key.put_back();
    assert!(
        matches!(failed, Err(klav_ffi::KlavError::WrongCredentials)),
        "{failed:?}"
    );
    assert!(!core.status().unlocked);
    let next = core.agent_revocations();
    assert!(matches!(next, Err(klav_ffi::KlavError::Locked)), "{next:?}");
    // The next unlock after a failed one does not get the dropped session.
    core.unlock_with_password(PASSWORD.into(), None)
        .expect("unlock");
    assert!(core.status().unlocked);
    record_kept(core, &dir);
}

/// C: lock, unlock, lock again while the call is in flight. When it ends
/// Klav is locked, with no unlock under way: its keys go, and Klav stays
/// locked. The record it wrote is on disk.
#[test]
fn a_lock_an_unlock_and_a_lock_during_a_call_leave_the_vault_locked() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let rt = runtime();
    let (gate, core, bot, _keeper) = setup(&server, &dir, &rt);

    let (frozen, old) = revocation_in_flight(&gate, &core, &bot);
    core.lock();
    core.unlock_with_password(PASSWORD.into(), None)
        .expect("unlock");
    core.lock();
    drop(frozen);
    let ended = old.join().expect("old call");
    assert!(
        matches!(ended, Err(klav_ffi::KlavError::Locked)),
        "{ended:?}"
    );
    assert!(!core.status().unlocked);
    let next = core.agent_revocations();
    assert!(matches!(next, Err(klav_ffi::KlavError::Locked)), "{next:?}");
    record_kept(core, &dir);
}

/// Review of #316, 4: a wrong master password while already unlocked, with
/// a call in flight that ends while that unlock is under way. Nothing
/// locked: the call keeps what it wrote and hands its result out, and the
/// failed unlock leaves the vault as it was.
#[test]
fn a_wrong_password_while_unlocked_keeps_a_call_in_flight() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let rt = runtime();
    let (gate, core, bot, _keeper) = setup(&server, &dir, &rt);

    let (frozen, old) = revocation_in_flight(&gate, &core, &bot);
    let secret_key = HeldSecretKey::new(&dir);
    let unlock = {
        let core = core.clone();
        std::thread::spawn(move || core.unlock_with_password("not the password".into(), None))
    };
    let held = secret_key.reached();
    drop(frozen);
    let report = old
        .join()
        .expect("old call")
        .expect("not locked: its result is handed out");
    assert_eq!(report.agent.status, "revoked");
    secret_key.answer(held);
    let failed = unlock.join().expect("unlock");
    secret_key.put_back();
    assert!(
        matches!(failed, Err(klav_ffi::KlavError::WrongCredentials)),
        "{failed:?}"
    );
    assert!(core.status().unlocked);
    core.sync().expect("sync");
    record_kept(core, &dir);
}

/// Review of #316, 4: signing out while a call is in flight. Sign-out first
/// counts what is waiting through the account, so it waits for the call;
/// the call hands its result out, and then nothing of the account is left
/// on the phone: no write of the call comes back after the sign-out.
#[test]
fn a_sign_out_during_a_call_waits_for_it_and_leaves_nothing() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let rt = runtime();
    let (gate, core, bot, _keeper) = setup(&server, &dir, &rt);

    let (frozen, old) = revocation_in_flight(&gate, &core, &bot);
    let out = {
        let core = core.clone();
        std::thread::spawn(move || core.sign_out(klav_ffi::AcceptedLoss::Unknown))
    };
    drop(frozen);
    let ended = old.join().expect("old call");
    ended.expect("the call ended before the sign-out");
    out.join().expect("sign-out").expect("signed out");

    let status = core.status();
    assert!(!status.unlocked && !status.has_account, "{status:?}");
    let phone = dir.path().join("phone");
    for name in [
        "account.json",
        "secret-key",
        "cache.bin",
        klav_client::revoke::REVOCATIONS_FILE,
    ] {
        assert!(!phone.join(name).exists(), "{name} is left");
    }
    let next = core.agent_revocations();
    assert!(next.is_err(), "{next:?}");
}
