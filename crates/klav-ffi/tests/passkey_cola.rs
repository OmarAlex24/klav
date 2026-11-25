//! The iPhone's passkey outbox (ADR 0020 §11, T138) in the cases the
//! security review of the passkey layers found, against the real server:
//!
//! - signing out takes the outbox with the account, and an outbox a later
//!   sign-in cannot open is set aside instead of breaking every passkey use;
//! - a replacement queued while the server already has the new login (its
//!   upload went through, the rest of the flush did not) is uploaded, not
//!   dropped;
//! - a passkey queued offline does not bury a newer one another device
//!   registered meanwhile: the newer stays current, the other in history.

mod common;

use common::ServerProcess;
use klav_client::passkeys::{PasskeyCreateOutcome, PasskeyCreateRequest};
use klav_client::{Home, ItemFilter, ItemLocation, SignupRequest, Unlocked};
use klav_core::crypto::kdf::MasterPassword;
use klav_ffi::{AcceptedLoss, KlavCore, PasskeyRegistrationInput, PasskeyRegistrationOutcome};
use klav_proto::auth::DeviceKind;
use secrecy::ExposeSecret;

const PASSWORD: &str = "correct horse battery staple";
const RP: &str = "example.com";
const HANDLE: [u8; 16] = [5u8; 16];

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test setup")
}

fn input(replace: bool) -> PasskeyRegistrationInput {
    PasskeyRegistrationInput {
        rp_id: RP.into(),
        rp_name: Some("Example".into()),
        user_name: "ana".into(),
        user_display_name: None,
        user_handle: HANDLE.to_vec(),
        exclude_credentials: Vec::new(),
        item_id: None,
        replace,
        vault: None,
        project: None,
    }
}

fn created(outcome: PasskeyRegistrationOutcome) -> (Vec<u8>, String) {
    match outcome {
        PasskeyRegistrationOutcome::Created {
            credential_id,
            item_id,
            ..
        } => (credential_id, item_id),
        other => panic!("not created: {other:?}"),
    }
}

struct World {
    server: ServerProcess,
    dir: tempfile::TempDir,
    rt: tokio::runtime::Runtime,
    laptop_home: Home,
    secret_key: String,
}

impl World {
    fn new() -> Self {
        let server = ServerProcess::start(900);
        let dir = tempfile::tempdir().expect("test setup");
        let rt = runtime();
        let laptop_home = Home::at(dir.path().join("laptop"));
        let (_, kit) = rt
            .block_on(klav_client::signup(
                &laptop_home,
                SignupRequest {
                    server: server.url.clone(),
                    email: "ana@example.com".into(),
                    password: MasterPassword::new(PASSWORD),
                    device_name: "laptop".into(),
                    device_kind: DeviceKind::Cli,
                    invite: None,
                },
            ))
            .expect("test setup");
        let secret_key = kit.secret_key().to_text().expose_secret().to_owned();
        Self {
            server,
            dir,
            rt,
            laptop_home,
            secret_key,
        }
    }

    fn phone(&self) -> std::path::PathBuf {
        self.dir.path().join("phone")
    }

    fn sign_in_phone(&self) -> std::sync::Arc<KlavCore> {
        let app = KlavCore::new(self.phone().display().to_string()).expect("test setup");
        app.sign_in(
            self.server.url.clone(),
            "ana@example.com".into(),
            PASSWORD.into(),
            self.secret_key.clone(),
            "iPhone".into(),
            None,
        )
        .expect("sign-in");
        app
    }

    /// The AutoFill extension: the phone's home, its own process.
    fn extension(&self) -> std::sync::Arc<KlavCore> {
        let ext = KlavCore::new(self.phone().display().to_string()).expect("test setup");
        ext.unlock_with_password(PASSWORD.into(), None)
            .expect("unlock");
        ext
    }

    fn laptop(&self) -> Unlocked {
        klav_client::unlock_with_password(&self.laptop_home, &MasterPassword::new(PASSWORD))
            .expect("laptop")
    }

    fn outbox(&self) -> std::path::PathBuf {
        self.phone().join("outbox.bin")
    }
}

fn location(laptop: &Unlocked, item_id: &str) -> ItemLocation {
    let s = laptop
        .list_items(&ItemFilter::default())
        .expect("list")
        .into_iter()
        .find(|s| s.id.to_string() == item_id)
        .expect("the login on the laptop");
    ItemLocation {
        vault: s.vault_id,
        project: s.project_id,
        item: s.id,
    }
}

fn current_credential(laptop: &Unlocked, loc: ItemLocation) -> Vec<u8> {
    laptop
        .open_item(loc)
        .expect("open")
        .passkey()
        .expect("a passkey")
        .credential_id()
        .to_vec()
}

#[test]
fn signing_out_takes_the_outbox_and_a_stale_one_does_not_break_passkeys() {
    let mut w = World::new();
    let app = w.sign_in_phone();

    // A passkey made offline and uploaded: a synced passkey of this phone.
    w.server.stop();
    let ext = w.extension();
    let (cred, _) = created(ext.passkey_registration(input(false)).expect("register"));
    drop(ext);
    w.server.restart();
    drop(app);
    let app = w.extension();
    app.sync().expect("sync");
    assert!(!w.outbox().exists());

    // Offline again: a sign-in queues its `passkey.used`. Keep a copy of
    // that outbox, sealed with this sign-in's local key.
    w.server.stop();
    let ext = w.extension();
    ext.passkey_assertion(RP.into(), cred.clone(), vec![1; 32])
        .expect("signs offline");
    let stale = std::fs::read(w.outbox()).expect("the use is queued");
    // Signing out offline: nothing can go up, and the file goes anyway
    // (a queued sign-in is no key: nothing to warn about).
    drop(ext);
    app.sign_out(AcceptedLoss::Nothing).expect("sign out");
    assert!(!w.outbox().exists(), "the outbox goes with the account");

    // Signed in again (new device, new local key), with the old file back
    // (a copy the sign-out could not remove, or a restored backup).
    w.server.restart();
    drop(app);
    let app = w.sign_in_phone();
    std::fs::write(w.outbox(), &stale).expect("test setup");
    let ext = w.extension();
    let signed = ext
        .passkey_assertion(RP.into(), cred.clone(), vec![2; 32])
        .expect("a synced passkey still signs");
    assert_eq!(signed.credential_id, cred);
    assert_eq!(set_aside(&w).len(), 1);
    // The outbox works again: the new use is in it, readable.
    assert_eq!(ext.passkey_outbox().expect("outbox").uses, 1);
    // The app says what the extension set aside, until it acknowledges
    // it: a check before signing out, or a report nobody saw, loses
    // nothing.
    let flushed = app.flush_passkey_outbox().expect("flush");
    assert_eq!(
        (flushed.uses_sent, flushed.left, flushed.set_aside),
        (1, 0, 1),
        "{:?}",
        flushed.error
    );
    app.sign_out_check().expect("check");
    let synced = app.sync().expect("sync");
    assert_eq!(synced.passkey_queues_set_aside, 1);
    let shown = synced.passkey_queue_set_aside_ids;
    assert_eq!(shown, flushed.set_aside_ids);

    // A stale file when the app flushes first: set aside, and said.
    std::fs::write(w.outbox(), &stale).expect("test setup");
    let flushed = app.flush_passkey_outbox().expect("flush");
    // Acknowledging the notice shown before covers only what it counted:
    // the outbox set aside since is still reported.
    assert_eq!(
        app.acknowledge_passkey_queues_set_aside(shown.clone())
            .expect("ack"),
        1
    );
    let synced = app.sync().expect("sync");
    assert_eq!(synced.passkey_queues_set_aside, 1);
    assert!(!synced.passkey_queue_set_aside_ids.contains(&shown[0]));
    // A name that is not a set-aside outbox is ignored.
    assert_eq!(
        app.acknowledge_passkey_queues_set_aside(vec!["../outbox.bin".into()])
            .expect("ack"),
        0
    );
    assert!(
        flushed
            .error
            .as_deref()
            .is_some_and(|e| e.contains("set aside")),
        "{flushed:?}"
    );
    assert_eq!(flushed.set_aside, 2, "with the one not acknowledged yet");
    assert!(!w.outbox().exists());
    assert_eq!(app.passkey_outbox().expect("outbox").uses, 0);
    // The second one did not replace the first.
    assert_eq!(set_aside(&w).len(), 2);

    // Signing out removes the set-aside files too.
    app.sign_out(AcceptedLoss::Nothing).expect("sign out");
    assert!(set_aside(&w).is_empty());
}

/// The outboxes set aside in the phone's home.
fn set_aside(w: &World) -> Vec<std::path::PathBuf> {
    std::fs::read_dir(w.phone())
        .expect("home")
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("outbox.unreadable-"))
        })
        .collect()
}

#[test]
fn signing_out_does_not_lose_a_passkey_that_is_not_uploaded() {
    let mut w = World::new();
    let app = w.sign_in_phone();

    // Offline: the extension registers a passkey; its key is only in the
    // outbox.
    w.server.stop();
    let ext = w.extension();
    let (cred, item_id) = created(ext.passkey_registration(input(false)).expect("register"));
    drop(ext);
    drop(app);
    let app = w.extension();

    // Still offline: the app says what would be lost, and refuses.
    let check = app.sign_out_check().expect("check");
    assert_eq!((check.unsent_passkeys, check.locked_with_queue), (1, false));
    let refused = app.sign_out(AcceptedLoss::Nothing).expect_err("refused");
    assert!(refused.to_string().contains("not uploaded"), "{refused}");
    assert!(w.outbox().exists(), "nothing was removed");
    assert_eq!(
        app.passkey_outbox().expect("still unlocked").passkeys.len(),
        1
    );

    // The person agreed to lose the one the dialog counted; another one
    // saved while the dialog was open makes Klav refuse, and nothing is
    // removed.
    let other = PasskeyRegistrationInput {
        user_name: "bea".into(),
        user_handle: b"bea-0001".to_vec(),
        ..input(false)
    };
    let (other_cred, _) = created(app.passkey_registration(other).expect("register"));
    let refused = app
        .sign_out(AcceptedLoss::Unsent {
            passkeys: 1,
            generated: 0,
        })
        .expect_err("one more than accepted");
    assert!(refused.to_string().contains("2 passkey"), "{refused}");
    assert_eq!(
        app.passkey_outbox().expect("still unlocked").passkeys.len(),
        2
    );
    assert!(
        app.passkey_identities()
            .expect("identities")
            .iter()
            .any(|i| i.credential_id == other_cred),
        "the refused sign-out kept the account unlocked"
    );

    // An outbox it cannot read is not «nothing to lose»: the check fails
    // and signing out without `force` refuses.
    let outbox = w.outbox();
    let moved = outbox.with_extension("moved");
    std::fs::rename(&outbox, &moved).expect("test setup");
    std::fs::create_dir(&outbox).expect("test setup");
    assert!(app.sign_out_check().is_err());
    assert!(app.sign_out(AcceptedLoss::Nothing).is_err());
    std::fs::remove_dir(&outbox).expect("test setup");
    std::fs::rename(&moved, &outbox).expect("test setup");

    // Locked: the outbox cannot be read, so it refuses too.
    app.lock();
    let check = app.sign_out_check().expect("check");
    assert!(check.locked_with_queue);
    assert!(app.sign_out(AcceptedLoss::Nothing).is_err());
    assert!(w.outbox().exists());

    // Back online and unlocked: the check uploads it first, and then
    // signing out loses nothing.
    w.server.restart();
    app.unlock_with_password(PASSWORD.into(), None)
        .expect("unlock");
    let synced = app.sync().expect("sync");
    assert_eq!(
        (synced.passkeys_waiting, synced.passkey_queues_set_aside),
        (0, 0)
    );
    assert_eq!(app.sign_out_check().expect("check").unsent_passkeys, 0);
    let mut laptop = w.laptop();
    w.rt.block_on(laptop.sync()).expect("sync");
    let loc = location(&laptop, &item_id);
    assert_eq!(current_credential(&laptop, loc), cred);
    app.sign_out(AcceptedLoss::Nothing).expect("sign out");
    assert!(!w.outbox().exists());
}

#[test]
fn a_replacement_queued_after_the_new_login_went_up_is_not_dropped() {
    let mut w = World::new();
    let app = w.sign_in_phone();

    // Offline: a new login with passkey 1, then its replacement, passkey 2.
    // The cache has no such login yet, so passkey 2 is queued as a new
    // login too (no base version).
    w.server.stop();
    let ext = w.extension();
    let (first, item_id) = created(ext.passkey_registration(input(false)).expect("register"));
    let only_first = std::fs::read(w.outbox()).expect("queued");
    let (second, same) = created(ext.passkey_registration(input(true)).expect("replace"));
    assert_eq!(same, item_id);
    assert_ne!(second, first);
    let with_second = std::fs::read(w.outbox()).expect("queued");
    drop(ext);

    // The flush uploads the new login with passkey 1 and stops before it
    // cleans up (here: the queue still holds the replacement).
    w.server.restart();
    drop(app);
    std::fs::write(w.outbox(), &only_first).expect("test setup");
    let app = w.extension();
    assert_eq!(app.flush_passkey_outbox().expect("flush").uploaded, 1);
    std::fs::write(w.outbox(), &with_second).expect("test setup");

    // Next flush: the server has the login (passkey 1) and the queue holds
    // passkey 2 as a new login. It goes up as a replacement.
    let flushed = app.flush_passkey_outbox().expect("flush");
    assert_eq!(
        (flushed.uploaded, flushed.left),
        (1, 0),
        "{:?}",
        flushed.error
    );
    assert!(!w.outbox().exists());
    let mut laptop = w.laptop();
    w.rt.block_on(laptop.sync()).expect("sync");
    let loc = location(&laptop, &item_id);
    assert_eq!(current_credential(&laptop, loc), second);
}

#[test]
fn a_newer_passkey_from_another_device_stays_and_the_queued_one_goes_to_history() {
    let mut w = World::new();
    let app = w.sign_in_phone();

    // A synced login with passkey 1.
    w.server.stop();
    let ext = w.extension();
    let (first, item_id) = created(ext.passkey_registration(input(false)).expect("register"));
    drop(ext);
    w.server.restart();
    drop(app);
    let app = w.extension();
    app.sync().expect("sync");

    // The phone replaces it offline (passkey 2, on version 1)...
    w.server.stop();
    let ext = w.extension();
    let (second, _) = created(ext.passkey_registration(input(true)).expect("replace"));
    drop(ext);
    // ...and later the laptop replaces it too (passkey 3, version 2).
    std::thread::sleep(std::time::Duration::from_millis(5));
    w.server.restart();
    let mut laptop = w.laptop();
    w.rt.block_on(laptop.sync()).expect("sync");
    let loc = location(&laptop, &item_id);
    let request = PasskeyCreateRequest {
        origin: format!("https://{RP}"),
        rp_name: Some("Example".into()),
        user_id: klav_proto::Blob::from(&HANDLE[..]).to_text(),
        user_name: "ana".into(),
        challenge: "AAAAAAAAAAAAAAAAAAAAAA".into(),
        item: Some(item_id.clone()),
        replace: true,
        ..PasskeyCreateRequest::default()
    };
    let outcome =
        w.rt.block_on(laptop.passkey_create(&request, true))
            .expect("the laptop replaces it");
    assert!(
        matches!(outcome, PasskeyCreateOutcome::Created(_)),
        "{outcome:?}"
    );
    let third = current_credential(&laptop, loc);
    assert!(third != first && third != second);

    // The phone's flush: the laptop's passkey is newer and stays current;
    // the phone's is in the login's history, not lost.
    drop(app);
    let app = w.extension();
    let flushed = app.flush_passkey_outbox().expect("flush");
    assert_eq!(
        (flushed.uploaded, flushed.left),
        (1, 0),
        "{:?}",
        flushed.error
    );
    assert!(flushed.error.is_none(), "{:?}", flushed.error);
    w.rt.block_on(laptop.sync()).expect("sync");
    assert_eq!(current_credential(&laptop, loc), third);
    let versions = w.rt.block_on(laptop.item_versions(loc)).expect("versions");
    let mut in_history = false;
    for v in versions {
        let item =
            w.rt.block_on(laptop.item_version(loc, v.version))
                .expect("a version");
        in_history |= item
            .passkey()
            .is_some_and(|p| p.credential_id() == second.as_slice());
    }
    assert!(in_history, "the phone's passkey is in the login's history");
}
