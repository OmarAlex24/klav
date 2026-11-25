//! Deleting the account from the app through `KlavCore` (ADR 0037): Face
//! ID first wherever Klav uses it, then the master password; Face ID
//! unavailable refuses and keeps the enrolment; turning Face ID off asks
//! for the device owner (A4); 409 and 429 are their own errors; cancel
//! with the password when there is no Face ID (A2); ask from a locked
//! core, as the Mac app does; and after the purge, "Klav deleted your
//! account" with the copy still readable, also offline after a restart,
//! until the person deletes it.

mod common;

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::ServerProcess;
use klav_client::{Home, SignupRequest};
use klav_core::crypto::kdf::MasterPassword;
use klav_core::ids::ItemId;
use klav_core::model::item::{Item, ItemKind};
use klav_ffi::{
    AcceptedLoss, ItemQuery, KeystoreError, KeystoreKey, KeystoreWrap, KlavCore, KlavError,
    PlatformKeystore,
};
use klav_proto::auth::DeviceKind;
use secrecy::ExposeSecret;

const PASSWORD: &str = "correct horse battery staple";
const REASON: &str = "confirm it’s you to delete your account";
const DAY_MS: i64 = 24 * 3600 * 1000;

const OK: u8 = 0;
const CANCEL: u8 = 1;
const INVALIDATED: u8 = 2;
/// For [`FakeKeystore::owner`]: the device has no passcode.
const NO_PASSCODE: u8 = 3;

/// A keystore that behaves like the Secure Enclave without one, and
/// counts its prompts. `available` false is Face ID locked out (or not
/// enrolled in the system); `owner` is how the device-owner check goes.
struct FakeKeystore {
    mode: AtomicU8,
    available: AtomicBool,
    owner: AtomicU8,
    secrets: Mutex<HashMap<Vec<u8>, Vec<u8>>>,
    prompts: Mutex<Vec<String>>,
    owner_prompts: Mutex<Vec<String>>,
}

impl FakeKeystore {
    fn new() -> Self {
        Self {
            mode: AtomicU8::new(OK),
            available: AtomicBool::new(true),
            owner: AtomicU8::new(OK),
            secrets: Mutex::new(HashMap::new()),
            prompts: Mutex::new(Vec::new()),
            owner_prompts: Mutex::new(Vec::new()),
        }
    }
}

fn point() -> Vec<u8> {
    let mut p = vec![0x04];
    for _ in 0..4 {
        p.extend(ItemId::generate().as_bytes());
    }
    p.truncate(65);
    p
}

impl PlatformKeystore for FakeKeystore {
    fn available(&self) -> bool {
        self.available.load(Ordering::SeqCst)
    }

    fn create_key(&self) -> Result<KeystoreKey, KeystoreError> {
        Ok(KeystoreKey {
            handle: b"handle".to_vec(),
            public_key: point(),
        })
    }

    fn wrap(&self, _public_key: Vec<u8>) -> Result<KeystoreWrap, KeystoreError> {
        let ephemeral = point();
        let mut secret = ItemId::generate().as_bytes().to_vec();
        secret.extend(ItemId::generate().as_bytes());
        self.secrets
            .lock()
            .expect("test setup")
            .insert(ephemeral.clone(), secret.clone());
        Ok(KeystoreWrap {
            ephemeral_public: ephemeral,
            secret,
        })
    }

    fn unwrap(
        &self,
        _handle: Vec<u8>,
        ephemeral_public: Vec<u8>,
        reason: String,
    ) -> Result<Vec<u8>, KeystoreError> {
        self.prompts.lock().expect("test setup").push(reason);
        match self.mode.load(Ordering::SeqCst) {
            CANCEL => Err(KeystoreError::Cancelled),
            INVALIDATED => Err(KeystoreError::Invalidated),
            _ => self
                .secrets
                .lock()
                .expect("test setup")
                .get(&ephemeral_public)
                .cloned()
                .ok_or(KeystoreError::Other),
        }
    }

    fn boot_time(&self) -> u64 {
        1_700_000_000
    }

    fn confirm_owner(&self, reason: String) -> Result<(), KeystoreError> {
        self.owner_prompts.lock().expect("test setup").push(reason);
        match self.owner.load(Ordering::SeqCst) {
            CANCEL => Err(KeystoreError::Cancelled),
            NO_PASSCODE => Err(KeystoreError::Unavailable),
            _ => Ok(()),
        }
    }
}

fn now_ms() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_millis(),
    )
    .expect("ms")
}

/// Signs up on "the laptop" with one login; returns the Secret Key.
fn laptop(server: &str, dir: &std::path::Path) -> String {
    let rt = tokio::runtime::Runtime::new().expect("test setup");
    rt.block_on(async {
        let (mut laptop, kit) = klav_client::signup(
            &Home::at(dir.join("laptop")),
            SignupRequest {
                server: server.to_owned(),
                email: "ana@example.com".into(),
                password: MasterPassword::new(PASSWORD),
                device_name: "laptop".into(),
                device_kind: DeviceKind::Cli,
                invite: None,
            },
        )
        .await
        .expect("sign-up");
        let vault = laptop.find_vault("Personal").expect("vault");
        let project = laptop.find_project(vault, "General").expect("project");
        let item = Item::from_template(ItemKind::Login, "GitHub").expect("template");
        laptop.add_item(vault, project, &item).await.expect("item");
        kit.secret_key().to_text().expose_secret().to_owned()
    })
}

/// Moves the deletion of every account to `at`, in the server's SQLite
/// database. `false` without the `sqlite3` program, which says so.
#[allow(clippy::print_stderr)]
fn move_delete_at(server: &ServerProcess, at: i64) -> bool {
    let sql = format!("PRAGMA busy_timeout = 5000; UPDATE account_deletions SET delete_at = {at};");
    match std::process::Command::new("sqlite3")
        .arg(server.dir.path().join("klav.db"))
        .arg(sql)
        .output()
    {
        Ok(out) => {
            assert!(
                out.status.success(),
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );
            true
        }
        Err(_) => {
            eprintln!("no sqlite3 here: the deleted account is not checked");
            false
        }
    }
}

/// How many accounts the server's SQLite database still has (needs the
/// `sqlite3` program, which [`move_delete_at`] already checked).
fn account_count(server: &ServerProcess) -> u64 {
    let out = std::process::Command::new("sqlite3")
        .args(["-cmd", ".timeout 5000"])
        .arg(server.dir.path().join("klav.db"))
        .arg("SELECT count(*) FROM accounts;")
        .output()
        .expect("sqlite3");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse()
        .expect("a count")
}

#[test]
fn face_id_then_the_password_cancel_and_after_the_purge_the_copy_stays() {
    let mut server = ServerProcess::start_purging();
    let dir = tempfile::tempdir().expect("tempdir");
    let secret_key = laptop(&server.url, dir.path());
    let ks = Arc::new(FakeKeystore::new());
    let keystore: Arc<dyn PlatformKeystore> = ks.clone();
    let phone = KlavCore::new(dir.path().join("phone").display().to_string()).expect("core");
    let enrolled = phone
        .sign_in(
            server.url.clone(),
            "ana@example.com".into(),
            PASSWORD.into(),
            secret_key,
            "iPhone".into(),
            Some(keystore.clone()),
        )
        .expect("sign in");
    assert!(enrolled, "Face ID is set up");
    assert!(phone.deletion_supported().expect("health"));
    assert_eq!(phone.account_deletion().expect("unlocked"), None);
    let prompts = || ks.prompts.lock().expect("test setup").len();

    // T162: Face ID first. Cancelled, nothing is asked.
    ks.mode.store(CANCEL, Ordering::SeqCst);
    let err = phone
        .request_account_deletion(PASSWORD.into(), Some(keystore.clone()), REASON.into())
        .expect_err("cancelled");
    assert!(matches!(err, KlavError::BiometryFailed { .. }), "{err:?}");
    assert_eq!(prompts(), 1);
    assert_eq!(
        ks.prompts.lock().expect("test setup")[0],
        REASON,
        "the prompt says why"
    );
    // Set up, so not skipped by leaving the keystore out.
    let err = phone
        .request_account_deletion(PASSWORD.into(), None, REASON.into())
        .expect_err("no keystore");
    assert!(
        matches!(err, KlavError::BiometryUnavailable { .. }),
        "{err:?}"
    );
    ks.mode.store(OK, Ordering::SeqCst);
    // A wrong password after Face ID: refused here, nothing asked.
    let err = phone
        .request_account_deletion("wrong".into(), Some(keystore.clone()), REASON.into())
        .expect_err("wrong password");
    assert!(matches!(err, KlavError::WrongCredentials), "{err:?}");
    assert_eq!(phone.account_deletion().expect("unlocked"), None);

    // Asked: 7 days, from this iPhone.
    let asked = phone
        .request_account_deletion(PASSWORD.into(), Some(keystore.clone()), REASON.into())
        .expect("ask");
    assert_eq!(asked.delete_at - asked.requested_at, 7 * DAY_MS);
    assert!(asked.this_device);
    assert_eq!(asked.device_name, "iPhone");
    assert_eq!(
        phone.account_deletion().expect("unlocked"),
        Some(asked.clone())
    );

    // A second ask while it is pending: its own error, for the app to say
    // in its language.
    let err = phone
        .request_account_deletion(PASSWORD.into(), Some(keystore.clone()), REASON.into())
        .expect_err("already scheduled");
    assert!(
        matches!(err, KlavError::DeletionAlreadyScheduled { .. }),
        "{err:?}"
    );

    // Cancelling with the password, where there is no Face ID or the
    // person chose it (A2): a wrong one cancels nothing. The app asks for
    // Face ID itself before the plain cancel.
    let err = phone
        .cancel_account_deletion_with_password("wrong".into())
        .expect_err("wrong password");
    assert!(matches!(err, KlavError::WrongCredentials), "{err:?}");
    assert_eq!(phone.account_deletion().expect("unlocked"), Some(asked));
    assert!(
        phone
            .cancel_account_deletion_with_password(PASSWORD.into())
            .expect("cancel")
    );
    assert!(!phone.cancel_account_deletion().expect("nothing left"));
    assert_eq!(phone.account_deletion().expect("unlocked"), None);

    // Faces changed (biometryCurrentSet): refused, and the enrolment is
    // gone, as for the unlock. From then on Klav does not use Face ID here
    // and the password alone asks (ADR 0037 §1).
    ks.mode.store(INVALIDATED, Ordering::SeqCst);
    let err = phone
        .request_account_deletion(PASSWORD.into(), Some(keystore.clone()), REASON.into())
        .expect_err("invalidated");
    assert!(
        matches!(err, KlavError::BiometryUnavailable { .. }),
        "{err:?}"
    );
    assert!(!phone.biometric_state(keystore.clone()).enrolled);
    ks.mode.store(OK, Ordering::SeqCst);

    // Asked again from a locked core, as the Mac app does: the account
    // opens for the request only.
    phone.lock();
    let asked = phone
        .request_account_deletion(PASSWORD.into(), None, REASON.into())
        .expect("ask locked");
    assert!(asked.this_device);
    assert!(!phone.status().unlocked, "still locked");
    phone
        .unlock_with_password(PASSWORD.into(), Some(keystore.clone()))
        .expect("unlock");
    assert_eq!(phone.account_deletion().expect("unlocked"), Some(asked));

    // A passkey AutoFill saved while the account was there; the sync
    // uploads it.
    let passkey = phone
        .passkey_registration(klav_ffi::PasskeyRegistrationInput {
            rp_id: "example.com".into(),
            rp_name: Some("Example".into()),
            user_handle: vec![1, 2, 3],
            user_name: "ana".into(),
            user_display_name: Some("Ana".into()),
            exclude_credentials: Vec::new(),
            item_id: None,
            replace: false,
            vault: None,
            project: None,
        })
        .expect("passkey");
    let klav_ffi::PasskeyRegistrationOutcome::Created { credential_id, .. } = passkey else {
        panic!("not created: {passkey:?}");
    };

    // The time comes in a few seconds; the phone syncs before it.
    let delete_at = now_ms() + 4_000;
    if !move_delete_at(&server, delete_at) {
        return;
    }
    phone.sync().expect("sync before the purge");
    let passkey_outbox = dir
        .path()
        .join("phone")
        .join(klav_client::passkey_outbox::PASSKEY_OUTBOX_FILE);
    assert!(!passkey_outbox.exists(), "the passkey went up");
    assert!(now_ms() < delete_at, "too slow: the sync must come first");

    // Then, without network, a generated password waits in this iPhone's
    // outbox. The server comes back only once the account is gone, so it
    // can never go up.
    server.stop();
    phone
        .record_generated("generated offline".into(), None)
        .expect("queued");
    let outbox = dir.path().join("phone").join("generator-outbox.bin");
    assert!(outbox.exists(), "the generated password waits");
    while now_ms() <= delete_at {
        std::thread::sleep(Duration::from_millis(100));
    }
    server.restart();
    let deadline = Instant::now() + Duration::from_secs(30);
    while account_count(&server) > 0 {
        assert!(Instant::now() < deadline, "not purged");
        std::thread::sleep(Duration::from_millis(200));
    }
    let deleted = loop {
        std::thread::sleep(Duration::from_millis(500));
        match phone.sync() {
            Err(KlavError::AccountDeleted { delete_at, .. }) => break delete_at,
            Ok(_) => assert!(Instant::now() < deadline, "not purged"),
            Err(e) => panic!("{e:?}"),
        }
    };
    assert_eq!(deleted, Some(delete_at));
    // T165: nothing deleted the copy; it still reads.
    let items = phone.items(ItemQuery::default()).expect("items");
    assert_eq!(items.len(), 2);
    assert!(phone.status().has_account);
    let seen = phone
        .account_deletion()
        .expect("unlocked")
        .expect("the deletion");
    assert!(seen.deleted);

    // D-C: restarted with no server, it still knows, from its own copy:
    // it reads, and it neither syncs nor takes a new passkey.
    drop(phone);
    drop(server);
    let phone = KlavCore::new(dir.path().join("phone").display().to_string()).expect("core");
    phone
        .unlock_with_password(PASSWORD.into(), Some(keystore.clone()))
        .expect("unlock offline");
    let seen = phone
        .account_deletion()
        .expect("unlocked")
        .expect("the deletion");
    assert!(seen.deleted);
    assert_eq!(seen.delete_at, delete_at);
    match phone.sync() {
        Err(KlavError::AccountDeleted { delete_at: at, .. }) => assert_eq!(at, Some(delete_at)),
        other => panic!("{other:?}"),
    }
    let items = phone.items(ItemQuery::default()).expect("items");
    assert_eq!(items.len(), 2);
    // The passkey still signs in, from the copy, but queues no
    // `passkey.used`: no audit log is left to take it (N4).
    phone
        .passkey_assertion("example.com".into(), credential_id, vec![7; 32])
        .expect("sign in");
    assert!(!passkey_outbox.exists(), "nothing queued");
    // Nothing writes either, not even what would wait in an outbox.
    let edit = phone.edit_item(
        items[0].id.clone(),
        klav_ffi::ItemEdit {
            title: Some("renamed".into()),
            ..Default::default()
        },
    );
    assert!(
        matches!(edit, Err(KlavError::AccountDeleted { .. })),
        "edit: {:?}",
        edit.err()
    );
    let generated = phone.record_generated("a generated password".into(), None);
    assert!(
        matches!(generated, Err(KlavError::AccountDeleted { .. })),
        "generator: {:?}",
        generated.err()
    );
    let trash = phone.trash_item(items[0].id.clone());
    assert!(
        matches!(trash, Err(KlavError::AccountDeleted { .. })),
        "trash: {:?}",
        trash.err()
    );
    assert_eq!(
        phone.items(ItemQuery::default()).expect("items")[0].title,
        items[0].title
    );
    let err = phone
        .passkey_registration(klav_ffi::PasskeyRegistrationInput {
            rp_id: "example.com".into(),
            rp_name: Some("Example".into()),
            user_handle: vec![1, 2, 3],
            user_name: "ana".into(),
            user_display_name: Some("Ana".into()),
            exclude_credentials: Vec::new(),
            item_id: None,
            replace: false,
            vault: None,
            project: None,
        })
        .expect_err("read-only");
    assert!(matches!(err, KlavError::AccountDeleted { .. }), "{err:?}");

    // «Delete this iPhone’s copy» (Q3 of the re-review): the generated
    // password that never went up is only here, so Klav refuses until the
    // person copies it (the history lists it) or chooses «Delete anyway».
    assert!(outbox.exists(), "still queued: the account is gone");
    let check = phone.sign_out_check().expect("check");
    assert_eq!(
        (
            check.unsent_generated,
            check.unsent_passkeys,
            check.locked_with_queue
        ),
        (1, 0, false)
    );
    let history = phone.generator_history().expect("the history reads");
    assert_eq!(history.len(), 1);
    assert!(history[0].pending);
    assert_eq!(
        phone.generated_value(history[0].created_at).expect("copy"),
        "generated offline"
    );
    let refused = phone.sign_out(AcceptedLoss::Nothing);
    assert!(
        matches!(refused, Err(KlavError::Denied { .. })),
        "{refused:?}"
    );
    assert!(phone.status().has_account && phone.status().unlocked);
    assert!(outbox.exists(), "nothing deleted");
    // Locked, Klav can't count: any outbox is too many.
    phone.lock();
    let check = phone.sign_out_check().expect("check");
    assert!(check.locked_with_queue);
    assert!(phone.sign_out(AcceptedLoss::Nothing).is_err());
    assert!(outbox.exists(), "nothing deleted");
    phone
        .unlock_with_password(PASSWORD.into(), Some(keystore.clone()))
        .expect("unlock");
    // What the dialog said is what may go: one more is too many.
    assert!(
        phone
            .sign_out(AcceptedLoss::Unsent {
                passkeys: 0,
                generated: 0,
            })
            .is_err()
    );
    // «Delete anyway».
    phone.sign_out(AcceptedLoss::Unknown).expect("sign out");
    assert!(!phone.status().has_account);
    for name in [
        "account.json",
        "cache.bin",
        "session.bin",
        "secret-key",
        "faceid.json",
        "deletion.bin",
        "generator-outbox.bin",
    ] {
        assert!(
            !dir.path().join("phone").join(name).exists(),
            "{name} is left"
        );
    }
}

/// A phone signed in with Face ID set up, on its own server.
fn phone_with_face_id(
    server: &ServerProcess,
    dir: &std::path::Path,
    keystore: &Arc<dyn PlatformKeystore>,
) -> Arc<KlavCore> {
    let secret_key = laptop(&server.url, dir);
    let phone = KlavCore::new(dir.join("phone").display().to_string()).expect("core");
    let enrolled = phone
        .sign_in(
            server.url.clone(),
            "ana@example.com".into(),
            PASSWORD.into(),
            secret_key,
            "iPhone".into(),
            Some(keystore.clone()),
        )
        .expect("sign in");
    assert!(enrolled, "Face ID is set up");
    phone
}

/// Review blocker 1 (A4, T162): turning Face ID off in Klav asks for the
/// device owner (Face ID or the iPhone's passcode), never nothing and
/// never the master password alone. Refused, Face ID still guards the
/// deletion.
#[test]
fn turning_face_id_off_asks_for_the_device_owner() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let ks = Arc::new(FakeKeystore::new());
    let keystore: Arc<dyn PlatformKeystore> = ks.clone();
    let phone = phone_with_face_id(&server, dir.path(), &keystore);
    let enrolment = dir.path().join("phone").join("faceid.json");
    const OFF: &str = "turn off Face ID for Klav";

    // The owner does not confirm: nothing changes.
    ks.owner.store(CANCEL, Ordering::SeqCst);
    let err = phone
        .forget_biometrics(keystore.clone(), OFF.into())
        .expect_err("not confirmed");
    assert!(matches!(err, KlavError::BiometryFailed { .. }), "{err:?}");
    assert!(enrolment.exists());
    assert!(phone.biometric_state(keystore.clone()).enrolled);
    assert_eq!(*ks.owner_prompts.lock().expect("test setup"), [OFF]);
    // So the deletion still asks for Face ID first.
    ks.mode.store(CANCEL, Ordering::SeqCst);
    let err = phone
        .request_account_deletion(PASSWORD.into(), Some(keystore.clone()), REASON.into())
        .expect_err("Face ID cancelled");
    assert!(matches!(err, KlavError::BiometryFailed { .. }), "{err:?}");
    assert_eq!(ks.prompts.lock().expect("test setup").len(), 1);
    ks.mode.store(OK, Ordering::SeqCst);

    // No passcode to ask for, but Face ID works: refused all the same.
    ks.owner.store(NO_PASSCODE, Ordering::SeqCst);
    let err = phone
        .forget_biometrics(keystore.clone(), OFF.into())
        .expect_err("no owner check");
    assert!(
        matches!(err, KlavError::BiometryUnavailable { .. }),
        "{err:?}"
    );
    assert!(enrolment.exists());
    // No passcode and no Face ID (removing the passcode turns Face ID
    // off): the key no longer opens, and the enrolment goes.
    ks.available.store(false, Ordering::SeqCst);
    phone
        .forget_biometrics(keystore.clone(), OFF.into())
        .expect("nothing left to guard");
    assert!(!enrolment.exists());

    // Set up again by the password; the owner confirms: off.
    ks.available.store(true, Ordering::SeqCst);
    ks.owner.store(OK, Ordering::SeqCst);
    phone
        .unlock_with_password(PASSWORD.into(), Some(keystore.clone()))
        .expect("unlock");
    assert!(enrolment.exists());
    let face_id_prompts = ks.prompts.lock().expect("test setup").len();
    phone
        .forget_biometrics(keystore.clone(), OFF.into())
        .expect("owner confirmed");
    assert!(!enrolment.exists());
    assert!(!phone.biometric_state(keystore.clone()).enrolled);
    assert_eq!(
        ks.prompts.lock().expect("test setup").len(),
        face_id_prompts,
        "the owner check opens no key"
    );
    // Nothing set up: nothing to ask.
    let owner_prompts = ks.owner_prompts.lock().expect("test setup").len();
    phone
        .forget_biometrics(keystore.clone(), OFF.into())
        .expect("already off");
    assert_eq!(
        ks.owner_prompts.lock().expect("test setup").len(),
        owner_prompts
    );
}

/// Review findings 2 and 3 (iOS): Face ID locked out (or gone from the
/// system) refuses the deletion and keeps the enrolment, so the password
/// alone never asks; and the server's limits are their own error.
#[test]
fn face_id_unavailable_refuses_and_the_limits_are_their_own_error() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let ks = Arc::new(FakeKeystore::new());
    let keystore: Arc<dyn PlatformKeystore> = ks.clone();
    let phone = phone_with_face_id(&server, dir.path(), &keystore);
    let enrolment = dir.path().join("phone").join("faceid.json");

    ks.available.store(false, Ordering::SeqCst);
    let err = phone
        .request_account_deletion(PASSWORD.into(), Some(keystore.clone()), REASON.into())
        .expect_err("Face ID unavailable");
    assert!(
        matches!(err, KlavError::BiometryUnavailable { .. }),
        "{err:?}"
    );
    assert!(enrolment.exists(), "refused, not forgotten");
    assert!(ks.prompts.lock().expect("test setup").is_empty());
    assert_eq!(phone.account_deletion().expect("unlocked"), None);

    // Face ID back: three deletions in 7 days, then the limit.
    ks.available.store(true, Ordering::SeqCst);
    for _ in 0..3 {
        phone
            .request_account_deletion(PASSWORD.into(), Some(keystore.clone()), REASON.into())
            .expect("ask");
        assert!(phone.cancel_account_deletion().expect("cancel"));
    }
    let err = phone
        .request_account_deletion(PASSWORD.into(), Some(keystore.clone()), REASON.into())
        .expect_err("limited");
    assert!(
        matches!(err, KlavError::DeletionRateLimited { .. }),
        "{err:?}"
    );
    assert_eq!(phone.account_deletion().expect("unlocked"), None);
}
