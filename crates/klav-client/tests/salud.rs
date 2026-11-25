//! The vault health report (ADR 0022 §4) against the real server: reused,
//! weak and old passwords, without values in the report; and the optional
//! breach check against a local stand-in for Have I Been Pwned (the tests
//! never reach the real service), which only receives 5-character prefixes.
#![cfg(feature = "health")]

mod common;

use std::sync::{Arc, Mutex};

use common::ServerProcess;
use klav_client::health::{AgeSource, BreachReport, HealthItem, OLD_AFTER_MS};
use klav_client::{Home, SignupRequest, signup};
use klav_core::crypto::kdf::MasterPassword;
use klav_core::model::item::{Item, ItemKind};
use klav_proto::auth::DeviceKind;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const PASSWORD: &str = "correct horse battery staple";
const SHARED: &str = "MARKER-Vq7#kL2!zR9-shared";
const WEAK: &str = "password1";
const UNIQUE: &str = "MARKER-Hn4$wT8%pX3-unique";
const PIN: &str = "48213957";
// SHA-1("password1") = E38AD214943DAAD1D64C102FAEC29DE4AFE9DA3D.
const WEAK_PREFIX: &str = "E38AD";
const WEAK_SUFFIX: &str = "214943DAAD1D64C102FAEC29DE4AFE9DA3D";

fn titles(items: &[HealthItem]) -> Vec<&str> {
    items.iter().map(|i| i.title.as_str()).collect()
}

fn login(title: &str, url: &str, password: &str) -> Item {
    let mut item = Item::from_template(ItemKind::Login, title).expect("test setup");
    item.add_url(url).expect("test setup");
    item.field_mut("username")
        .expect("test setup")
        .set_value("ana@example.com")
        .expect("test setup");
    item.field_mut("password")
        .expect("test setup")
        .set_value(password)
        .expect("test setup");
    item
}

/// A stand-in for `api.pwnedpasswords.com`: answers every `/range/` with
/// padding lines, and lists `password1` (42 times) for its prefix. Keeps
/// each request's head.
async fn fake_hibp() -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("test setup");
    let base = format!("http://{}", listener.local_addr().expect("test setup"));
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            let log = log.clone();
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut buf = [0u8; 1024];
                while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                    match socket.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => head.extend_from_slice(&buf[..n]),
                    }
                }
                let head = String::from_utf8_lossy(&head).into_owned();
                let path = head.split_whitespace().nth(1).unwrap_or("").to_owned();
                log.lock().expect("test setup").push(head);
                let mut body = String::from("00000000000000000000000000000000000:0\r\n");
                if path == format!("/range/{WEAK_PREFIX}") {
                    body.push_str(&format!("{WEAK_SUFFIX}:42\r\n"));
                }
                body.push_str("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:0\r\n");
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
            });
        }
    });
    (base, seen)
}

#[tokio::test(flavor = "multi_thread")]
async fn the_report_finds_reused_weak_and_old_passwords_without_values() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().unwrap();
    let home = Home::at(dir.path().join("h"));
    let (mut u, _kit) = signup(
        &home,
        SignupRequest {
            server: server.url.clone(),
            email: "health@example.com".into(),
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

    for (title, url, password) in [
        ("Bank", "https://bank.example/login", SHARED),
        ("Shop", "https://www.shop.example/", SHARED),
        ("Forum", "https://forum.example/", WEAK),
        ("Mail", "https://mail.example/", UNIQUE),
    ] {
        u.add_item(vault, project, &login(title, url, password))
            .await
            .unwrap();
    }
    // A generated 8-digit PIN: ~26.6 bits, weak whatever zxcvbn says.
    u.record_generated(PIN, Some("door.example")).unwrap();
    u.add_item(vault, project, &login("Door", "https://door.example/", PIN))
        .await
        .unwrap();
    // Not looked at: a card PIN (concealed), and a login in the trash.
    let mut card = Item::from_template(ItemKind::Card, "Visa").unwrap();
    if let Some(pin) = card.field_mut("pin") {
        pin.set_value("1234").unwrap();
    }
    u.add_item(vault, project, &card).await.unwrap();
    let trashed = u
        .add_item(
            vault,
            project,
            &login("Old forum", "https://old.example/", WEAK),
        )
        .await
        .unwrap();
    u.trash_item(trashed).await.unwrap();
    // Mail changes its password: the record dates the current one.
    let mail = u.find_item("Mail").unwrap();
    let mut edited = u.open_item(mail).unwrap();
    edited
        .field_mut("password")
        .unwrap()
        .set_value("MARKER-Hn4$wT8%pX3-unique-2")
        .unwrap();
    u.update_item(mail, &edited).await.unwrap();

    let now = klav_client_now();
    let report = u.vault_health(now, None).await;
    assert_eq!(report.items, 6, "five logins and the card");
    assert_eq!(report.passwords, 5);
    assert_eq!(report.skipped, 0);
    assert_eq!(report.reused.len(), 1);
    assert_eq!(titles(&report.reused[0].items), ["Bank", "Shop"]);
    assert_eq!(report.reused[0].items[1].hosts, ["shop.example"]);
    assert_eq!(report.reused[0].items[0].field, "password");
    let weak: Vec<&str> = report.weak.iter().map(|w| w.item.title.as_str()).collect();
    assert!(weak.contains(&"Forum"), "{weak:?}");
    assert!(weak.contains(&"Door"), "{weak:?}");
    assert!(
        !weak.contains(&"Mail") && !weak.contains(&"Bank"),
        "{weak:?}"
    );
    let forum = report
        .weak
        .iter()
        .find(|w| w.item.title == "Forum")
        .unwrap();
    assert!(forum.score <= 2);
    assert_eq!(forum.generated_bits, None);
    let door = report.weak.iter().find(|w| w.item.title == "Door").unwrap();
    assert_eq!(door.generated_bits, Some(26));
    assert!(report.old.is_empty(), "nothing is a year old yet");
    assert_eq!(report.breaches, BreachReport::Off);
    assert!(!report.is_clean());

    // No value, hash or hint in the report.
    let json = serde_json::to_string(&report).unwrap();
    for secret in [SHARED, WEAK, UNIQUE, PIN, WEAK_SUFFIX, "MARKER"] {
        assert!(!json.contains(secret), "{secret} leaked into the report");
    }

    // A year and a day later, every password is old; Mail's age comes from
    // its record, the others' from when they were created.
    let later = u.vault_health(now + OLD_AFTER_MS + 86_400_000, None).await;
    assert_eq!(later.old.len(), 5);
    let mail_old = later.old.iter().find(|o| o.item.title == "Mail").unwrap();
    assert_eq!(mail_old.source, AgeSource::Record);
    assert!(later.old.iter().all(|o| o.days >= 365));
    assert!(
        later
            .old
            .iter()
            .filter(|o| o.item.title != "Mail")
            .all(|o| o.source == AgeSource::Created)
    );

    // The breach check sends only 5-character prefixes, padded answers
    // and all; the report names the item, never the value.
    let (base, seen) = fake_hibp().await;
    let checked = u.vault_health(now, Some(&base)).await;
    let BreachReport::Checked { found, queries } = &checked.breaches else {
        panic!("breach check failed: {:?}", checked.breaches);
    };
    assert_eq!(*queries, 4, "four distinct passwords");
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].item.title, "Forum");
    assert_eq!(found[0].count, 42);
    let requests = seen.lock().unwrap().clone();
    assert_eq!(requests.len(), 4);
    for head in &requests {
        let path = head.split_whitespace().nth(1).unwrap();
        let prefix = path.strip_prefix("/range/").expect("range path");
        assert_eq!(prefix.len(), 5, "{path}");
        assert!(
            prefix
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_lowercase())
        );
        assert!(
            head.to_ascii_lowercase()
                .contains("\r\nadd-padding: true\r\n"),
            "{head}"
        );
        for secret in [SHARED, WEAK, UNIQUE, PIN, WEAK_SUFFIX] {
            assert!(!head.contains(secret));
        }
    }
    let json = serde_json::to_string(&checked).unwrap();
    assert!(!json.contains(WEAK_SUFFIX) && !json.contains(WEAK));

    // An unreachable service fails the breach check only.
    let unreachable = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        format!("http://{}", l.local_addr().unwrap())
    };
    let failed = u.vault_health(now, Some(&unreachable)).await;
    assert!(matches!(failed.breaches, BreachReport::Failed { .. }));
    assert_eq!(failed.reused, report.reused);
    assert_eq!(failed.weak, report.weak);
}

fn klav_client_now() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_millis(),
    )
    .expect("clock")
}
