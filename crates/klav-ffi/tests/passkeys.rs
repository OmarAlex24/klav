//! Passkeys on the iPhone (ADR 0020 §11) against the real server: the
//! AutoFill extension registers and signs without network, the passkey works
//! at once from the outbox, and the app uploads it (renamed if its title was
//! taken meanwhile), with the `passkey.used` events; a replaced passkey goes
//! on the login's newest version even if the laptop changed it meanwhile.

mod common;

use common::ServerProcess;
use klav_client::{Home, ItemFilter, ItemLocation, SignupRequest, Unlocked};
use klav_core::crypto::kdf::MasterPassword;
use klav_core::crypto::passkey::verify_es256;
use klav_core::model::item::{Item, ItemKind};
use klav_core::passkey::webauthn::rp_id_hash;
use klav_ffi::{KlavCore, KlavError, PasskeyRegistrationInput, PasskeyRegistrationOutcome};
use klav_proto::auth::DeviceKind;
use secrecy::ExposeSecret;

const PASSWORD: &str = "correct horse battery staple";
const RP: &str = "example.com";

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test setup")
}

fn input(user_handle: &[u8], exclude: Vec<Vec<u8>>, replace: bool) -> PasskeyRegistrationInput {
    PasskeyRegistrationInput {
        rp_id: RP.into(),
        rp_name: Some("Example".into()),
        user_name: "ana".into(),
        user_display_name: Some("Ana".into()),
        user_handle: user_handle.to_vec(),
        exclude_credentials: exclude,
        item_id: None,
        replace,
        vault: None,
        project: None,
    }
}

/// The public key inside a registration's authenticator data (COSE EC2
/// with x at -2 and y at -3), uncompressed.
fn public_key(auth_data: &[u8]) -> Vec<u8> {
    let cred_len = usize::from(u16::from_be_bytes([auth_data[53], auth_data[54]]));
    let cose = &auth_data[55 + cred_len..];
    let at = |label: &[u8]| {
        let i = cose
            .windows(3)
            .position(|w| w == label)
            .expect("coordinate in the COSE key");
        &cose[i + 3..i + 35]
    };
    let mut key = vec![0x04];
    key.extend_from_slice(at(&[0x21, 0x58, 0x20]));
    key.extend_from_slice(at(&[0x22, 0x58, 0x20]));
    key
}

fn created(outcome: PasskeyRegistrationOutcome) -> (Vec<u8>, Vec<u8>, String, String) {
    match outcome {
        PasskeyRegistrationOutcome::Created {
            credential_id,
            authenticator_data,
            item_id,
            title,
            ..
        } => (credential_id, authenticator_data, item_id, title),
        other => panic!("not created: {other:?}"),
    }
}

/// After a server restart: the devices open again (their pooled
/// connections went with the old server process).
fn reopen(laptop_home: &Home, phone: &std::path::Path) -> (Unlocked, std::sync::Arc<KlavCore>) {
    let laptop = klav_client::unlock_with_password(laptop_home, &MasterPassword::new(PASSWORD))
        .expect("test setup");
    let app = KlavCore::new(phone.display().to_string()).expect("test setup");
    app.unlock_with_password(PASSWORD.into(), None)
        .expect("test setup");
    (laptop, app)
}

fn passkey_items(laptop: &Unlocked) -> Vec<klav_client::ItemSummary> {
    laptop
        .list_items(&ItemFilter::default())
        .expect("list")
        .into_iter()
        .filter(|s| s.passkey.is_some())
        .collect()
}

#[test]
fn the_extension_registers_offline_and_the_app_uploads_it() {
    let mut server = ServerProcess::start(900);
    let dir = tempfile::tempdir().unwrap();
    let rt = runtime();

    // The laptop signs up; the iPhone app signs in on the same account.
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
            },
        ))
        .unwrap();
    let secret_key = kit.secret_key().to_text().expose_secret().to_owned();
    let phone = dir.path().join("phone");
    let app = KlavCore::new(phone.display().to_string()).unwrap();
    app.sign_in(
        server.url.clone(),
        "ana@example.com".into(),
        PASSWORD.into(),
        secret_key,
        "iPhone".into(),
        None,
    )
    .unwrap();

    // The extension: same home, its own process, no network.
    server.stop();
    let ext = KlavCore::new(phone.display().to_string()).unwrap();
    ext.unlock_with_password(PASSWORD.into(), None).unwrap();
    let handle = [7u8; 16];
    let (cred, auth_data, item_id, title) = created(
        ext.passkey_registration(input(&handle, Vec::new(), false))
            .unwrap(),
    );
    assert_eq!(title, "Example");
    assert_eq!(cred.len(), 16);
    assert_eq!(&auth_data[..32], &rp_id_hash(RP)[..]);

    // Usable at once on this iPhone: listed, signs, and the same account is
    // told apart (asked, or excluded after presence).
    let ids = ext.passkey_identities().unwrap();
    assert_eq!(ids.len(), 1);
    assert_eq!(ids[0].rp_id, RP);
    assert_eq!(ids[0].credential_id, cred);
    assert_eq!(ids[0].user_handle, handle);
    assert!(matches!(
        ext.passkey_registration(input(&handle, Vec::new(), false)).unwrap(),
        PasskeyRegistrationOutcome::Exists { item_id: ref i, .. } if *i == item_id
    ));
    assert!(matches!(
        ext.passkey_registration(input(&[8u8; 16], vec![cred.clone()], false))
            .unwrap(),
        PasskeyRegistrationOutcome::Excluded
    ));
    let hash = [9u8; 32];
    let signed = ext
        .passkey_assertion(RP.into(), cred.clone(), hash.to_vec())
        .unwrap();
    assert_eq!(signed.item_id, item_id);
    assert_eq!(signed.user_handle, handle);
    assert_eq!(&signed.authenticator_data[..32], &rp_id_hash(RP)[..]);
    // UP, UV (Face ID opened the extension), BE and BS; counter 0.
    assert_eq!(signed.authenticator_data[32], 0x1d);
    assert_eq!(&signed.authenticator_data[33..37], &[0, 0, 0, 0]);
    let mut message = signed.authenticator_data.clone();
    message.extend_from_slice(&hash);
    verify_es256(&public_key(&auth_data), &message, &signed.signature).unwrap();
    // Only for its own site, and only over a SHA-256.
    assert!(matches!(
        ext.passkey_assertion("other.com".into(), cred.clone(), hash.to_vec()),
        Err(KlavError::NotFound { .. })
    ));
    assert!(
        ext.passkey_assertion(RP.into(), cred.clone(), vec![1; 31])
            .is_err()
    );

    // Waiting for the app, in a 0x43 blob: nothing in clear on disk.
    let outbox = ext.passkey_outbox().unwrap();
    assert_eq!(outbox.passkeys.len(), 1);
    assert_eq!(outbox.passkeys[0].title, "Example");
    assert_eq!(outbox.uses, 1);
    let blob = std::fs::read(phone.join("outbox.bin")).unwrap();
    assert_eq!(&blob[..2], &[0x01, 0x43]);
    assert!(!blob.windows(7).any(|w| w == b"Example"));

    // Meanwhile the laptop saves another «Example».
    server.restart();
    let (mut laptop, app) = reopen(&laptop_home, &phone);
    let vault = laptop.find_vault("Personal").unwrap();
    let project = laptop.find_project(vault, "General").unwrap();
    let other = Item::from_template(ItemKind::Login, "Example").unwrap();
    rt.block_on(laptop.add_item(vault, project, &other))
        .unwrap();

    // The app comes to the foreground: its sync empties the outbox.
    app.sync().unwrap();
    assert_eq!(app.passkey_outbox().unwrap().passkeys.len(), 0);
    assert_eq!(app.passkey_outbox().unwrap().uses, 0);
    assert!(!phone.join("outbox.bin").exists());
    assert_eq!(app.flush_passkey_outbox().unwrap().uploaded, 0);

    // The laptop gets it, renamed, with the same key and the same ID.
    rt.block_on(laptop.sync()).unwrap();
    let found = passkey_items(&laptop);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].id.to_string(), item_id);
    assert_eq!(found[0].title, "Example (2)");
    let laptop_signed = laptop
        .passkey_get(
            "https://example.com",
            None,
            "AAAAAAAAAAAAAAAAAAAAAA",
            &item_id,
            true,
        )
        .unwrap();
    assert_eq!(laptop_signed.user_handle, "BwcHBwcHBwcHBwcHBwcHBw");
    // The sign-in made offline is in the log, attested by the server.
    let entries = rt.block_on(laptop.audit_entries()).unwrap();
    let used: Vec<_> = entries
        .iter()
        .filter(|e| e.event.action == "passkey.used")
        .collect();
    assert_eq!(used.len(), 1);
    assert_eq!(
        used[0].event.item_id.map(|i| i.to_string()),
        Some(item_id.clone())
    );

    // A replacement made offline (the extension opens again, on the cache
    // the app synced) lands on the login's newest version, even though the
    // laptop changed the login meanwhile.
    server.stop();
    drop(ext);
    let ext = KlavCore::new(phone.display().to_string()).unwrap();
    ext.unlock_with_password(PASSWORD.into(), None).unwrap();
    let (new_cred, _, replaced_id, _) = created(
        ext.passkey_registration(input(&handle, Vec::new(), true))
            .unwrap(),
    );
    assert_eq!(replaced_id, item_id);
    assert_ne!(new_cred, cred);
    assert_eq!(ext.passkey_identities().unwrap()[0].credential_id, new_cred);
    server.restart();
    let (mut laptop, app) = reopen(&laptop_home, &phone);
    let loc = ItemLocation {
        vault,
        project,
        item: item_id.parse().unwrap(),
    };
    let mut edited = laptop.open_item(loc).unwrap();
    edited.add_url("https://login.example.com").unwrap();
    rt.block_on(laptop.update_item(loc, &edited)).unwrap();
    let flushed = app.flush_passkey_outbox().unwrap();
    assert_eq!(
        (flushed.uploaded, flushed.left),
        (1, 0),
        "{:?}",
        flushed.error
    );
    rt.block_on(laptop.sync()).unwrap();
    let now = laptop.open_item(loc).unwrap();
    assert_eq!(now.passkey().unwrap().credential_id(), new_cred.as_slice());
    assert!(now.urls().iter().any(|u| u == "https://login.example.com"));
}

#[test]
fn replacing_a_queued_passkey_offline_keeps_one_upload() {
    let mut server = ServerProcess::start(900);
    let dir = tempfile::tempdir().unwrap();
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
            },
        ))
        .unwrap();
    let phone = dir.path().join("phone");
    let app = KlavCore::new(phone.display().to_string()).unwrap();
    app.sign_in(
        server.url.clone(),
        "ana@example.com".into(),
        PASSWORD.into(),
        kit.secret_key().to_text().expose_secret().to_owned(),
        "iPhone".into(),
        None,
    )
    .unwrap();

    // Registered, then replaced twice, all before the app opens.
    server.stop();
    let ext = KlavCore::new(phone.display().to_string()).unwrap();
    ext.unlock_with_password(PASSWORD.into(), None).unwrap();
    let handle = [5u8; 16];
    let (first, _, item_id, _) = created(
        ext.passkey_registration(input(&handle, Vec::new(), false))
            .unwrap(),
    );
    let mut last = first.clone();
    for _ in 0..2 {
        let (cred, _, id, _) = created(
            ext.passkey_registration(input(&handle, Vec::new(), true))
                .unwrap(),
        );
        assert_eq!(id, item_id);
        assert_ne!(cred, last);
        last = cred;
    }
    assert_eq!(ext.passkey_outbox().unwrap().passkeys.len(), 1);
    let ids = ext.passkey_identities().unwrap();
    assert_eq!(ids.len(), 1);
    assert_eq!(ids[0].credential_id, last);

    // One login on the server, with the last passkey.
    server.restart();
    let (mut laptop, app) = reopen(&laptop_home, &phone);
    let flushed = app.flush_passkey_outbox().unwrap();
    assert_eq!(
        (flushed.uploaded, flushed.left),
        (1, 0),
        "{:?}",
        flushed.error
    );
    rt.block_on(laptop.sync()).unwrap();
    let found = passkey_items(&laptop);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].id.to_string(), item_id);
    let loc = ItemLocation {
        vault: found[0].vault_id,
        project: found[0].project_id,
        item: found[0].id,
    };
    assert_eq!(
        laptop
            .open_item(loc)
            .unwrap()
            .passkey()
            .unwrap()
            .credential_id(),
        last.as_slice()
    );
}
