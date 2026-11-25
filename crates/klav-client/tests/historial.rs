//! The generator history and the password history (ADR 0022 §2–§3)
//! against the real server: the outbox reaches a system project that a
//! second device reads, lists never show it, deleting purges the versions
//! that held the values, and an edit keeps the previous password.

mod common;

use common::ServerProcess;
use klav_client::history::GeneratedSelection;
use klav_client::{
    ClientError, Home, ItemFilter, LoginRequest, SignupRequest, login, signup, unlock_with_password,
};
use klav_core::crypto::kdf::MasterPassword;
use klav_core::crypto::secret_key::SecretKey;
use klav_core::model::history::system_project_id;
use klav_core::model::item::{Item, ItemKind, SecretValue};
use klav_proto::auth::DeviceKind;
use secrecy::ExposeSecret;

const PASSWORD: &str = "correct horse battery staple";

#[tokio::test(flavor = "multi_thread")]
async fn generated_passwords_reach_every_device_and_can_be_deleted() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().unwrap();
    let home_a = Home::at(dir.path().join("a"));
    let (mut a, kit) = signup(
        &home_a,
        SignupRequest {
            server: server.url.clone(),
            email: "gen@example.com".into(),
            password: MasterPassword::new(PASSWORD),
            device_name: "laptop".into(),
            device_kind: DeviceKind::Cli,
            invite: None,
        },
    )
    .await
    .expect("sign-up");
    let secret_key = kit.secret_key().to_text().expose_secret().to_owned();

    // Recorded offline-first: in the outbox, sealed, before any upload.
    let first = a
        .record_generated("MARKER-gen-1", Some("Example.com"))
        .unwrap();
    let second = a.record_generated("MARKER-gen-2", None).unwrap();
    assert!(second > first, "IDs are increasing instants");
    assert_eq!(a.pending_generated(), 2);
    let outbox = std::fs::read(home_a.dir().join("generator-outbox.bin")).unwrap();
    assert!(!String::from_utf8_lossy(&outbox).contains("MARKER-"));
    let shown = a.generator_history().unwrap();
    assert_eq!(shown.len(), 2);
    assert!(shown.iter().all(|e| e.pending));
    assert_eq!(shown[1].host.as_deref(), Some("example.com"));

    // Flushed into the system project, which no list shows.
    assert_eq!(a.flush_generated().await.unwrap(), 2);
    assert_eq!(a.pending_generated(), 0);
    assert!(a.generator_history().unwrap().iter().all(|e| !e.pending));
    let vault = a.find_vault("Personal").unwrap();
    assert!(a.projects(None).iter().all(|p| p.name != "Klav"));
    assert!(a.find_project(vault, "Klav").is_err());
    assert!(a.list_items(&ItemFilter::default()).unwrap().is_empty());
    assert_eq!(a.vaults()[0].items, 0);
    // Flushing twice changes nothing.
    assert_eq!(a.flush_generated().await.unwrap(), 0);

    // Another device reads it after its first sync.
    let home_b = Home::at(dir.path().join("b"));
    let mut b = login(
        &home_b,
        LoginRequest {
            server: server.url.clone(),
            email: "gen@example.com".into(),
            password: MasterPassword::new(PASSWORD),
            secret_key: SecretKey::parse(&secret_key).unwrap(),
            device_name: "phone".into(),
            device_kind: DeviceKind::Cli,
        },
    )
    .await
    .expect("login");
    let seen = b.generator_history().unwrap();
    assert_eq!(seen.len(), 2);
    assert_eq!(b.generated_value(first).unwrap().expose(), "MARKER-gen-1");
    // B adds one; A, which has not synced since, adds another and flushes:
    // its write conflicts, it syncs and merges, and nothing is lost.
    b.record_generated("MARKER-gen-3", None).unwrap();
    assert_eq!(b.flush_generated().await.unwrap(), 1);
    let fourth = a.record_generated("MARKER-gen-5", None).unwrap();
    assert_eq!(a.flush_generated().await.unwrap(), 1);
    assert_eq!(a.generator_history().unwrap().len(), 4);
    b.sync().await.unwrap();
    assert_eq!(b.generator_history().unwrap().len(), 4);
    assert_eq!(b.generated_value(fourth).unwrap().expose(), "MARKER-gen-5");

    // Saving a generated password in a login links the entry to it.
    let project = a.find_project(vault, "General").unwrap();
    let mut login_item = Item::from_template(ItemKind::Login, "Example").unwrap();
    login_item
        .field_mut("password")
        .unwrap()
        .set_value("MARKER-gen-1")
        .unwrap();
    let loc = a.add_item(vault, project, &login_item).await.unwrap();
    a.link_generated(loc.item, &SecretValue::new("MARKER-gen-1"))
        .await;
    let linked = a.generator_history().unwrap();
    let entry = linked.iter().find(|e| e.created_at == first).unwrap();
    assert_eq!(entry.saved_in, Some(loc.item));
    assert_eq!(entry.saved_in_title.as_deref(), Some("Example"));

    // Deleting one entry, then the rest: the stored versions that held
    // them are purged too.
    assert_eq!(
        a.delete_generated(&GeneratedSelection::Some(vec![second]))
            .await
            .unwrap(),
        1
    );
    let history_loc = a.system_items(vault, ItemKind::GeneratorHistory)[0];
    assert_eq!(history_loc.project, system_project_id(vault));
    let versions = a.item_versions(history_loc).await.unwrap();
    assert!(versions.len() <= 1, "{} versions left", versions.len());
    assert!(matches!(
        a.generated_value(second),
        Err(ClientError::NotFound(_))
    ));
    assert_eq!(
        a.delete_generated(&GeneratedSelection::All).await.unwrap(),
        3
    );
    b.sync().await.unwrap();
    assert!(b.generator_history().unwrap().is_empty());
    drop(b);

    // The history survives a restart (unlocked from the cache).
    a.record_generated("MARKER-gen-4", None).unwrap();
    drop(a);
    let a = unlock_with_password(&home_a, &MasterPassword::new(PASSWORD)).unwrap();
    assert_eq!(a.pending_generated(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_edit_keeps_the_previous_password() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().unwrap();
    let home = Home::at(dir.path().join("h"));
    let (mut u, _kit) = signup(
        &home,
        SignupRequest {
            server: server.url.clone(),
            email: "rec@example.com".into(),
            password: MasterPassword::new(PASSWORD),
            device_name: "laptop".into(),
            device_kind: DeviceKind::Cli,
            invite: None,
        },
    )
    .await
    .expect("sign-up");
    let vault = u.find_vault("Personal").unwrap();
    let project = u.find_project(vault, "General").unwrap();
    let mut item = Item::from_template(ItemKind::Login, "Site").unwrap();
    item.field_mut("password")
        .unwrap()
        .set_value("MARKER-one")
        .unwrap();
    let loc = u.add_item(vault, project, &item).await.unwrap();
    for value in ["MARKER-two", "MARKER-three"] {
        let mut edited = u.open_item(loc).unwrap();
        edited
            .field_mut("password")
            .unwrap()
            .set_value(value)
            .unwrap();
        u.update_item(loc, &edited).await.unwrap();
    }
    // An edit of another field adds nothing.
    let mut edited = u.open_item(loc).unwrap();
    edited.set_title("Site 2").unwrap();
    u.update_item(loc, &edited).await.unwrap();

    let history = u.password_history(loc).unwrap();
    let fields: Vec<&str> = history.entries.iter().map(|e| e.field.as_str()).collect();
    assert_eq!(fields, ["password", "password"]);
    assert_eq!(u.previous_password(loc, 0).unwrap().expose(), "MARKER-two");
    assert_eq!(u.previous_password(loc, 1).unwrap().expose(), "MARKER-one");
    assert!(u.previous_password(loc, 2).is_err());
    // Every entry is dated, the first one from the item's creation.
    assert!(history.entries.iter().all(|e| e.from_ms.is_some()));
    assert!(history.entries[1].from_ms <= Some(history.entries[1].to_ms));
    // The record is not in the item's details in the clear.
    let opened = u.open_item(loc).unwrap();
    let blob = opened.password_record().expect("a record");
    assert_eq!(&blob[..2], &[0x01, 0x16]);
    assert!(!String::from_utf8_lossy(blob).contains("MARKER-"));
}

/// Two devices that both created the generator history: retention applies
/// to both items, also when reading, and the second one is emptied.
#[tokio::test(flavor = "multi_thread")]
async fn retention_reaches_every_generator_history_item() {
    use klav_core::model::history::GeneratedEntry;
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().unwrap();
    let (mut a, kit) = signup(
        &Home::at(dir.path().join("a")),
        SignupRequest {
            server: server.url.clone(),
            email: "keep@example.com".into(),
            password: MasterPassword::new(PASSWORD),
            device_name: "laptop".into(),
            device_kind: DeviceKind::Cli,
            invite: None,
        },
    )
    .await
    .expect("sign-up");
    let mut b = login(
        &Home::at(dir.path().join("b")),
        LoginRequest {
            server: server.url.clone(),
            email: "keep@example.com".into(),
            password: MasterPassword::new(PASSWORD),
            secret_key: SecretKey::parse(kit.secret_key().to_text().expose_secret()).unwrap(),
            device_name: "phone".into(),
            device_kind: DeviceKind::Cli,
        },
    )
    .await
    .expect("login");
    // Each device creates its own history item before seeing the other.
    a.record_generated("MARKER-a", None).unwrap();
    a.flush_generated().await.unwrap();
    b.record_generated("MARKER-b", None).unwrap();
    b.flush_generated().await.unwrap();
    let vault = b.find_vault("Personal").unwrap();
    let items = b.system_items(vault, ItemKind::GeneratorHistory);
    assert_eq!(items.len(), 2, "two history items");

    // An entry older than a year sits in one of them.
    let old_at = klav_client_now() - 400 * 24 * 3600 * 1000;
    let target = items[1];
    let mut item = b.open_item(target).unwrap();
    let mut entries: Vec<GeneratedEntry> = item.generated().to_vec();
    entries.push(GeneratedEntry {
        value: SecretValue::new("MARKER-old"),
        created_at: old_at,
        host: None,
        saved_in: None,
    });
    item.set_generated(entries).unwrap();
    b.update_item(target, &item).await.unwrap();
    // Reading already applies the retention.
    assert!(b.generated_value(old_at).is_err());
    assert!(
        b.generator_history()
            .unwrap()
            .iter()
            .all(|e| e.created_at != old_at)
    );

    // The next write merges everything into one item and empties the other.
    a.sync().await.unwrap();
    a.record_generated("MARKER-a2", None).unwrap();
    a.flush_generated().await.unwrap();
    let items = a.system_items(vault, ItemKind::GeneratorHistory);
    let mut sizes: Vec<usize> = items
        .iter()
        .map(|loc| a.open_item(*loc).unwrap().generated().len())
        .collect();
    sizes.sort_unstable();
    assert_eq!(
        sizes,
        [0, 3],
        "MARKER-a, MARKER-b and MARKER-a2 in one item"
    );
    for loc in items {
        let item = a.open_item(loc).unwrap();
        assert!(
            item.generated()
                .iter()
                .all(|e| e.value.expose() != "MARKER-old")
        );
    }
}

fn klav_client_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}
