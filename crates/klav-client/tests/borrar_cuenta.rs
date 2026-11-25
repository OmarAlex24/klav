//! Deleting the account from a device, end to end (ADR 0037 §9.3): ask,
//! cancel from another device, ask again, the time comes, the server
//! purges. No table keeps a row and no file is left; the device that knew
//! the date reads "Klav deleted your account" and keeps its copy (T165),
//! and one that never synced sees an ordinary expired session.
//!
//! The clock is not moved: `delete_at` is moved a few seconds ahead in the
//! server's database, and the server purges every second.

mod common;

use std::path::Path;
use std::time::{Duration, Instant};

use common::ServerProcess;
use klav_client::deletion::{self, AccountDeletion};
use klav_client::{
    ClientError, Home, LoginRequest, SignupRequest, Unlocked, login, signup, unlock_with_password,
};
use klav_core::crypto::kdf::MasterPassword;
use klav_core::crypto::secret_key::SecretKey;
use klav_core::model::item::{Item, ItemKind};
use klav_proto::auth::DeviceKind;
use secrecy::ExposeSecret;
use sqlx::AnyPool;
use sqlx::any::AnyPoolOptions;

const PASSWORD: &str = "correct horse battery staple";
const EMAIL: &str = "ana@example.com";
const DAY_MS: i64 = 24 * 3600 * 1000;
/// How far ahead `delete_at` is moved: time for the other device to sync
/// before the purge.
const AHEAD: Duration = Duration::from_secs(5);

fn now_ms() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_millis(),
    )
    .expect("ms")
}

/// The server's database, opened next to the running server (SQLite in
/// WAL mode takes a second connection).
async fn server_db(server: &ServerProcess) -> AnyPool {
    sqlx::any::install_default_drivers();
    let url = format!("sqlite://{}", server.dir.path().join("klav.db").display());
    AnyPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .expect("open server db")
}

/// Every table of the server with its number of rows.
async fn row_counts(pool: &AnyPool) -> Vec<(String, i64)> {
    let tables: Vec<String> = sqlx::query_scalar(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
    )
    .fetch_all(pool)
    .await
    .expect("tables");
    let mut counts = Vec::new();
    for table in tables {
        let n: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
            "SELECT COUNT(*) FROM \"{table}\""
        )))
        .fetch_one(pool)
        .await
        .expect("count");
        counts.push((table, n));
    }
    counts
}

/// The regular files under `dir`, recursively.
fn files_under(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.extend(files_under(&path));
        } else {
            out.push(path);
        }
    }
    out
}

async fn second_device(server: &ServerProcess, home: &Home, secret_key: &str) -> Unlocked {
    login(
        home,
        LoginRequest {
            server: server.url.clone(),
            email: EMAIL.into(),
            password: MasterPassword::new(PASSWORD),
            secret_key: SecretKey::parse(secret_key).expect("secret key"),
            device_name: "phone".into(),
            device_kind: DeviceKind::Cli,
        },
    )
    .await
    .expect("login")
}

fn assert_same(seen: Option<&AccountDeletion>, asked: &AccountDeletion) {
    assert_eq!(seen, Some(asked), "the deletion this device knows");
}

#[tokio::test(flavor = "multi_thread")]
async fn ask_cancel_ask_again_and_the_purge_leaves_nothing() {
    let server = ServerProcess::start_purging();
    let dir = tempfile::tempdir().expect("tempdir");
    let home_a = Home::at(dir.path().join("a"));
    let home_b = Home::at(dir.path().join("b"));
    let home_c = Home::at(dir.path().join("c"));

    let (mut a, kit) = signup(
        &home_a,
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
    let secret_key = kit.secret_key().to_text().expose_secret().to_owned();
    // Something for the purge to remove: an item, its versions and a file.
    let vault = a.find_vault("personal").expect("vault");
    let project = a.find_project(vault, "general").expect("project");
    let mut item = Item::from_template(ItemKind::Login, "GitHub").expect("template");
    item.field_mut("username")
        .expect("username")
        .set_value("ana")
        .expect("set");
    a.add_item(vault, project, &item).await.expect("add");
    a.attach("GitHub", "notes", "notes.txt", Some("text/plain"), b"notes")
        .await
        .expect("attach");
    let data = server.dir.path().join("data");
    assert!(!files_under(&data).is_empty(), "the file is on disk");

    let mut b = second_device(&server, &home_b, &secret_key).await;
    // C signs in and never syncs again.
    let c = second_device(&server, &home_c, &secret_key).await;

    // The server says it can (ADR 0037 §4).
    assert!(deletion::supported(&server.url).await.expect("health"));

    // A wrong password is refused here, before the server: the session
    // stays and nothing is scheduled.
    assert!(matches!(
        a.request_account_deletion(&MasterPassword::new("wrong"))
            .await,
        Err(ClientError::WrongCredentials)
    ));
    assert!(a.account_deletion().is_none());

    // Asked: 7 days, remembered by the device that asked.
    let asked = a
        .request_account_deletion(&MasterPassword::new(PASSWORD))
        .await
        .expect("ask");
    assert_eq!(asked.delete_at - asked.requested_at, 7 * DAY_MS);
    assert_eq!(asked.device_id, a.account().device_id);
    assert_eq!(asked.device_name, "laptop");
    assert_same(a.account_deletion(), &asked);
    assert_eq!(a.deletion_due(), None);
    // A second one while it is pending: 409, said as such.
    assert!(matches!(
        a.request_account_deletion(&MasterPassword::new(PASSWORD))
            .await,
        Err(ClientError::DeletionAlreadyScheduled)
    ));
    // Kept outside `cache.bin` (review finding 5), and across a restart,
    // without the server.
    drop(a);
    let mut a = unlock_with_password(&home_a, &MasterPassword::new(PASSWORD)).expect("unlock A");
    assert_same(a.account_deletion(), &asked);
    assert!(home_a.file("deletion.bin").exists());

    // B learns it when it syncs and cancels it, with no password (P8).
    b.sync().await.expect("B syncs");
    assert_same(b.account_deletion(), &asked);
    assert!(b.cancel_account_deletion().await.expect("cancel"));
    assert!(b.account_deletion().is_none());
    // Nothing left to cancel.
    assert!(!b.cancel_account_deletion().await.expect("cancel again"));
    a.sync().await.expect("A syncs");
    assert!(a.account_deletion().is_none(), "A sees it canceled");

    // Asked again, from a locked device, as `klav account delete` does:
    // the same Argon2id run unlocks it and proves the password.
    drop(a);
    let (a, asked) = deletion::request_account_deletion(&home_a, &MasterPassword::new(PASSWORD))
        .await
        .expect("ask again");
    assert_same(a.account_deletion(), &asked);
    drop(a);
    // The sealed cache keeps it across an unlock.
    let a = unlock_with_password(&home_a, &MasterPassword::new(PASSWORD)).expect("unlock A");
    assert_same(a.account_deletion(), &asked);
    drop(a);

    // The time comes: `delete_at` a few seconds from now. B syncs before
    // it and knows the date; A and C never sync again.
    let pool = server_db(&server).await;
    let delete_at = now_ms() + i64::try_from(AHEAD.as_millis()).expect("ms");
    sqlx::query("UPDATE account_deletions SET delete_at = $1")
        .bind(delete_at)
        .execute(&pool)
        .await
        .expect("move delete_at");
    b.sync().await.expect("B syncs before the purge");
    assert!(
        now_ms() < delete_at,
        "too slow: B must learn the date before the purge"
    );
    assert_eq!(b.account_deletion().map(|d| d.delete_at), Some(delete_at));
    assert_eq!(b.deletion_due(), None);

    // The purge: within a second of `delete_at`.
    let deadline = Instant::now() + AHEAD + Duration::from_secs(30);
    loop {
        let left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM accounts")
            .fetch_one(&pool)
            .await
            .expect("accounts");
        if left == 0 {
            break;
        }
        assert!(Instant::now() < deadline, "the account was not purged");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(now_ms() >= delete_at, "purged before its time");

    // No table keeps a row, but the server's own: its migrations and its
    // keys (`server_state`, no account in it). No file is left.
    let left: Vec<_> = row_counts(&pool)
        .await
        .into_iter()
        .filter(|(table, n)| {
            *n > 0 && !["_sqlx_migrations", "server_state"].contains(&table.as_str())
        })
        .collect();
    assert!(left.is_empty(), "rows left after the purge: {left:?}");
    assert_eq!(files_under(&data), Vec::<std::path::PathBuf>::new());
    pool.close().await;

    // B knew the date: "Klav deleted your account", and its copy stays.
    let b_files: Vec<_> = files_under(home_b.dir());
    match b.sync().await {
        Err(ClientError::AccountDeleted(at)) => assert_eq!(at, delete_at),
        other => panic!("B: {:?}", other.map(|_| ())),
    }
    assert!(b.find_item("GitHub").is_ok(), "B still reads its copy");
    drop(b);
    for file in &b_files {
        assert!(
            file.exists(),
            "nothing deleted B's copy: {}",
            file.display()
        );
    }
    let b = unlock_with_password(&home_b, &MasterPassword::new(PASSWORD)).expect("unlock B");
    assert!(b.find_item("GitHub").is_ok());
    assert!(b.deletion_due().is_some());
    // B remembers that the server deleted it, with no network needed.
    assert!(b.account_deleted());
    drop(b);

    // A asked with the first date and never synced since: to A it is not
    // due yet, so the 401 reads as an expired session. C never knew.
    let mut a = unlock_with_password(&home_a, &MasterPassword::new(PASSWORD)).expect("unlock A");
    let mut c = c;
    for (name, device) in [("A", &mut a), ("C", &mut c)] {
        match device.sync().await {
            Err(ClientError::SessionExpired) => {}
            other => panic!("{name}: {:?}", other.map(|_| ())),
        }
        assert!(device.find_item("GitHub").is_ok(), "{name} keeps its copy");
    }
    assert!(home_c.dir().join("account.json").exists());

    // Signing in again fails like a wrong password: no account to tell.
    let again = login(
        &Home::at(dir.path().join("d")),
        LoginRequest {
            server: server.url.clone(),
            email: EMAIL.into(),
            password: MasterPassword::new(PASSWORD),
            secret_key: SecretKey::parse(&secret_key).expect("secret key"),
            device_name: "new".into(),
            device_kind: DeviceKind::Cli,
        },
    )
    .await;
    assert!(matches!(again, Err(ClientError::WrongCredentials)));
}
