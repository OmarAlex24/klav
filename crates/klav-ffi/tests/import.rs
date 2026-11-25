//! The iOS import wizard's library calls against the real server (ADR
//! 0024), with the synthetic exports of `klav_import::samples`: Bitwarden,
//! then Google Authenticator's two QR codes (as their text, the way the
//! app reads them), then 1Password over the same bank. No value reaches
//! the preview, and no password is lost.

mod common;

use common::ServerProcess;
use klav_client::{Home, SignupRequest};
use klav_core::crypto::kdf::MasterPassword;
use klav_ffi::{ImportSession, ItemQuery, Kind, KlavCore, KlavError};
use klav_import::samples;
use klav_proto::auth::DeviceKind;
use secrecy::ExposeSecret;

const PASSWORD: &str = "correct horse battery staple";

/// An empty account made on a laptop; its Secret Key.
fn laptop(server: &str, dir: &std::path::Path) -> String {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test setup");
    rt.block_on(async {
        let (_, kit) = klav_client::signup(
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
        .expect("test setup");
        kit.secret_key().to_text().expose_secret().to_owned()
    })
}

/// Nothing from the sample files' secrets in what the app shows.
fn no_values(text: &str) {
    for marker in ["sample-", "JBSWY3DP", "4111111111111111", "otpauth"] {
        assert!(!text.contains(marker), "{marker} in {text}");
    }
}

#[test]
fn the_phone_imports_merges_and_keeps_every_password() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().unwrap();
    let secret_key = laptop(&server.url, dir.path());
    let core = KlavCore::new(dir.path().join("phone").display().to_string()).unwrap();

    // Locked: the files are read, nothing else.
    let bitwarden = ImportSession::new();
    bitwarden
        .add(
            "bitwarden.json".into(),
            samples::bitwarden_json().into_bytes(),
            Some("bitwarden".into()),
        )
        .unwrap();
    assert!(matches!(
        core.import_preview(bitwarden.clone(), None, None),
        Err(KlavError::Locked)
    ));
    core.sign_in(
        server.url.clone(),
        "ana@example.com".into(),
        PASSWORD.into(),
        secret_key,
        "iPhone".into(),
        None,
    )
    .unwrap();

    // Bitwarden: five entries and the trash told apart; the passkey comes
    // with its key, so none is left out.
    let state = bitwarden.state();
    assert_eq!((state.entries, state.passkeys), (5, 0));
    assert_eq!(state.files.len(), 1);
    assert_eq!(state.files[0].format, "Bitwarden");
    assert!(
        state.files[0]
            .skipped
            .iter()
            .any(|r| r.at == "item 6" && r.reason.contains("trash")),
        "{:?}",
        state.files[0].skipped
    );
    let preview = core.import_preview(bitwarden.clone(), None, None).unwrap();
    assert_eq!(
        (preview.vault.as_str(), preview.project.as_str()),
        ("Personal", "General")
    );
    assert_eq!((preview.new, preview.merged, preview.duplicates), (5, 0, 0));
    assert_eq!(preview.rows.len(), 5);
    assert!(preview.rows.iter().all(|r| r.action == "new"));
    no_values(&format!("{preview:?}"));
    // The preview changed nothing.
    assert!(core.items(ItemQuery::default()).unwrap().is_empty());
    let result = core.import_apply(bitwarden.clone(), None, None).unwrap();
    assert_eq!((result.created, result.updated, result.passkeys), (5, 0, 0));
    assert_eq!(core.items(ItemQuery::default()).unwrap().len(), 5);
    // The same file again adds nothing.
    let again = core.import_preview(bitwarden, None, None).unwrap();
    assert_eq!((again.new, again.merged, again.duplicates), (0, 0, 5));

    // Google Authenticator: one QR code says the other is missing; with
    // both, GitHub's code joins its login and the other is its own item.
    let google = ImportSession::new();
    let [first, second] = samples::google_links();
    google
        .add("QR 1".into(), first.into_bytes(), Some("google".into()))
        .unwrap();
    let state = google.state();
    assert_eq!(state.missing.len(), 1);
    assert_eq!(
        (state.missing[0].size, state.missing[0].missing.clone()),
        (2, vec![2])
    );
    google
        .add("QR 2".into(), second.into_bytes(), Some("google".into()))
        .unwrap();
    assert!(google.state().missing.is_empty());
    let preview = core.import_preview(google.clone(), None, None).unwrap();
    assert_eq!((preview.new, preview.merged), (1, 1));
    let github = preview.rows.iter().find(|r| r.action == "merge").unwrap();
    assert_eq!(github.target, "GitHub");
    assert_eq!(github.changes, vec!["totp_added".to_owned()]);
    let own = preview.rows.iter().find(|r| r.action == "new").unwrap();
    assert_eq!(own.kind, Kind::Totp);
    assert_eq!(own.changes, vec!["totp_item".to_owned()]);
    no_values(&format!("{preview:?}"));
    let result = core.import_apply(google, None, None).unwrap();
    assert_eq!((result.created, result.updated), (1, 1));
    let items = core.items(ItemQuery::default()).unwrap();
    let github = items.iter().find(|i| i.title == "GitHub").unwrap();
    assert!(core.item(github.id.clone()).unwrap().has_totp);

    // 1Password has a newer bank password: Bitwarden's goes to the history.
    let onepassword = ImportSession::new();
    onepassword
        .add("1password.1pux".into(), samples::onepux(), None)
        .unwrap();
    assert_eq!(onepassword.state().files[0].format, "1Password");
    let preview = core
        .import_preview(onepassword.clone(), None, None)
        .unwrap();
    let bank = preview
        .rows
        .iter()
        .find(|r| r.title == "Example Bank")
        .unwrap();
    assert_eq!(bank.action, "merge");
    assert!(
        bank.changes.contains(&"password_replaced".to_owned()),
        "{:?}",
        bank.changes
    );
    core.import_apply(onepassword, None, None).unwrap();
    let items = core.items(ItemQuery::default()).unwrap();
    let bank = items.iter().find(|i| i.title == "Example Bank").unwrap();
    let history = core.password_history(bank.id.clone()).unwrap();
    assert_eq!(
        history.entries.len(),
        2,
        "Bitwarden's bank password and its own history are kept"
    );
}

#[test]
fn files_that_do_not_fit_are_refused_without_values() {
    let session = ImportSession::new();
    // A Bitwarden export chosen as Firefox.
    let err = session
        .add(
            "bitwarden.json".into(),
            samples::bitwarden_json().into_bytes(),
            Some("firefox".into()),
        )
        .unwrap_err();
    let KlavError::Invalid { message } = err else {
        panic!("{err:?}")
    };
    assert!(message.starts_with("bitwarden.json: "), "{message}");
    no_values(&message);
    // An unknown source, and garbage.
    assert!(
        session
            .add("x".into(), b"{}".to_vec(), Some("lastpass-ish".into()))
            .is_err()
    );
    assert!(session.add("x.bin".into(), vec![0xff; 64], None).is_err());
    // Nothing was added.
    let state = session.state();
    assert!(state.files.is_empty() && state.entries == 0);
}
