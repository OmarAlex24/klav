//! Imports (ADR 0024) against the real server, with the synthetic samples
//! of `klav-import`: Bitwarden, then 1Password over it (a newer password
//! for the same login), Google Authenticator codes joining their login,
//! and importing everything again adds nothing. No password is lost.

mod common;

use common::ServerProcess;
use klav_client::klav_import::{Action, Change, ImportSet, Source, samples};
use klav_client::{Home, ItemFilter, SignupRequest, signup};
use klav_core::crypto::kdf::MasterPassword;
use klav_core::model::item::{FieldKind, FieldValue, ItemKind};
use klav_proto::auth::DeviceKind;

#[tokio::test(flavor = "multi_thread")]
async fn imports_merge_and_keep_every_password() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().unwrap();
    let home = Home::at(dir.path().join("a"));
    let (mut u, _kit) = signup(
        &home,
        SignupRequest {
            server: server.url.clone(),
            email: "import@example.com".into(),
            password: MasterPassword::new("correct horse battery staple"),
            device_name: "laptop".into(),
            device_kind: DeviceKind::Cli,
        },
    )
    .await
    .expect("sign-up");

    // Bitwarden first.
    let mut set = ImportSet::new();
    set.add("bitwarden.json", samples::bitwarden_json().as_bytes(), None)
        .unwrap();
    let preview = u.import_preview(&set, None, None, 100).unwrap();
    assert_eq!(
        (preview.vault.as_str(), preview.project.as_str()),
        ("Personal", "General")
    );
    assert_eq!(preview.totals.new, 5);
    // The shop's passkey comes with its key: none is left out.
    assert_eq!(preview.passkeys, 0);
    // The preview changes nothing.
    assert!(u.list_items(&ItemFilter::default()).unwrap().is_empty());
    let done = u.import_apply(&set, None, None).await.unwrap();
    assert_eq!((done.created, done.updated), (5, 0));
    let shop = u.find_item("Passkey Shop").unwrap();
    let passkey = u.item_summary(shop).unwrap().passkey.expect("the passkey");
    assert_eq!(passkey.rp_id, "shop.example.com");
    let bank = u.find_item("Example Bank").unwrap();
    let history = u.password_history(bank).unwrap();
    assert_eq!(history.entries.len(), 1, "Bitwarden's own history");
    assert_eq!(
        u.previous_password(bank, 0).unwrap().expose(),
        "sample-bank-2025"
    );

    // 1Password: the same bank login with a newer password, and a new one.
    let mut set = ImportSet::new();
    set.add(
        "1password.1pux",
        &samples::onepux(),
        Some(Source::OnePassword),
    )
    .unwrap();
    let [first, second] = samples::google_links();
    set.add("qr 1", first.as_bytes(), None).unwrap();
    set.add("qr 2", second.as_bytes(), None).unwrap();
    let preview = u.import_preview(&set, None, None, 100).unwrap();
    let bank_row = preview
        .rows
        .iter()
        .find(|r| r.title == "Example Bank")
        .unwrap();
    assert_eq!(bank_row.action, Action::Merge);
    // Its password is newer than the one Klav has (Bitwarden's history
    // says since when that one is in use).
    assert_eq!(
        bank_row.changes,
        vec![Change::PasswordReplaced, Change::TagsAdded]
    );
    let code_row = preview
        .rows
        .iter()
        .find(|r| r.kind == ItemKind::Totp && r.title == "GitHub")
        .unwrap();
    assert_eq!(
        (code_row.action, code_row.target.as_str()),
        (Action::Merge, "GitHub")
    );
    assert_eq!(preview.sources[2].skipped.len(), 1, "the HOTP code");
    let done = u.import_apply(&set, None, None).await.unwrap();
    assert_eq!((done.created, done.updated), (2, 2));

    // The bank's three passwords: current, Bitwarden's and its history.
    let item = u.open_item(bank).unwrap();
    let FieldValue::Secret(current) = item.field("password").unwrap().value() else {
        panic!("password is a secret");
    };
    assert_eq!(current.expose(), "sample-bank-2026b");
    let history = u.password_history(bank).unwrap();
    let previous: Vec<String> = (0..history.entries.len())
        .map(|i| u.previous_password(bank, i).unwrap().expose().to_owned())
        .collect();
    assert_eq!(previous, ["sample-bank-2026", "sample-bank-2025"]);
    // GitHub gained its one-time code from Google Authenticator.
    let github = u.open_item(u.find_item("GitHub").unwrap()).unwrap();
    assert!(!github.field("totp").unwrap().is_empty());
    assert_eq!(
        github
            .fields()
            .iter()
            .filter(|f| f.kind() == FieldKind::Totp)
            .count(),
        1
    );
    assert!(u.find_item("Discord").is_ok());

    // Everything again: nothing new.
    let mut all = ImportSet::new();
    all.add("bitwarden.json", samples::bitwarden_json().as_bytes(), None)
        .unwrap();
    all.add("1password.1pux", &samples::onepux(), None).unwrap();
    all.add("qr", first.as_bytes(), None).unwrap();
    let before = u.list_items(&ItemFilter::default()).unwrap().len();
    let preview = u.import_preview(&all, None, None, 100).unwrap();
    assert_eq!(preview.totals.new, 0);
    assert_eq!(preview.totals.merged, 0, "{:?}", preview.rows);
    let done = u.import_apply(&all, None, None).await.unwrap();
    assert_eq!((done.created, done.updated), (0, 0));
    assert_eq!(u.list_items(&ItemFilter::default()).unwrap().len(), before);
    // The bank keeps 1Password's password; Bitwarden's older one stays in
    // the history instead of coming back.
    let FieldValue::Secret(current) = u
        .open_item(bank)
        .unwrap()
        .field("password")
        .unwrap()
        .value()
        .clone()
    else {
        panic!("password is a secret");
    };
    assert_eq!(current.expose(), "sample-bank-2026b");
}
