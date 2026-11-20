//! End to end: sign up, log in on device A, create a vault, a project, an
//! item and an attachment with `klav-core`, then log in on device B, sync
//! everything from scratch, decrypt it and compare. Device B also follows a
//! live change over server-sent events. Finally, every byte the server
//! stored (database rows, SQLite files, attachment files) is scanned for the
//! plaintext secrets.

mod common;

use std::path::Path;
use std::time::Duration;

use common::TestServer;
use common::client::Session;
use common::vault::{TestProject, TestVault, decrypt, field, login_item};
use futures_util::StreamExt;
use klav_core::crypto::attachment::{decrypt_attachment_bytes, encrypt_attachment_bytes};
use klav_core::crypto::context::VaultContext;
use klav_core::crypto::keys::AttachmentKey;
use klav_core::crypto::share::open_shared_vault_key;
use klav_core::crypto::wrap::{unwrap_attachment_key, unwrap_item_key, wrap_attachment_key};
use klav_core::ids::{AttachmentId, VaultId};
use klav_proto::Blob;
use klav_proto::sync::{Attachment, ChangeEvent, Changes, CreateAttachment, SyncState};
use reqwest::StatusCode;
use sqlx::{Column, Row};

const PASSWORD: &str = "MARKER-master-password-5e1d";
const USERNAME: &str = "MARKER-username-0b7a";
const SECRET_V1: &str = "MARKER-item-secret-v1-c4f2";
const SECRET_V2: &str = "MARKER-item-secret-v2-93aa";
const TITLE: &str = "MARKER-title-77d0";
const FILE: &[u8] = b"MARKER-attachment-body -----BEGIN PRIVATE KEY----- 2f61";

async fn changes(server: &TestServer, s: &Session, vault: VaultId, since: u64) -> Changes {
    let res = server
        .get_auth(s, &format!("/v1/vaults/{vault}/changes?since={since}"))
        .send()
        .await
        .expect("request");
    assert_eq!(res.status(), StatusCode::OK);
    res.json().await.expect("changes")
}

/// Reads server-sent events until one named `name` arrives.
async fn next_event(
    stream: &mut (impl futures_util::Stream<Item = reqwest::Result<bytes::Bytes>> + Unpin),
    buffer: &mut String,
    name: &str,
) -> Option<String> {
    loop {
        while let Some(end) = buffer.find("\n\n") {
            let frame: String = buffer.drain(..end + 2).collect();
            let mut event = None;
            let mut data = String::new();
            for line in frame.lines() {
                if let Some(e) = line.strip_prefix("event: ") {
                    event = Some(e.to_owned());
                } else if let Some(d) = line.strip_prefix("data: ") {
                    data.push_str(d);
                }
            }
            if event.as_deref() == Some(name) {
                return Some(data);
            }
        }
        let chunk = tokio::time::timeout(Duration::from_secs(5), stream.next())
            .await
            .ok()??
            .ok()?;
        buffer.push_str(&String::from_utf8_lossy(&chunk));
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Every text and binary value in every table of the server database.
async fn database_values(server: &TestServer) -> Vec<(String, Vec<u8>)> {
    let db = server.raw_db().await;
    let mut values = Vec::new();
    for table in [
        "server_state",
        "accounts",
        "devices",
        "sessions",
        "vaults",
        "vault_members",
        "projects",
        "items",
        "item_versions",
        "attachments",
    ] {
        let rows = sqlx::query(sqlx::AssertSqlSafe(format!("SELECT * FROM {table}")))
            .fetch_all(&db)
            .await
            .expect("select");
        for row in rows {
            for column in row.columns() {
                let name = format!("{table}.{}", column.name());
                if let Ok(Some(bytes)) = row.try_get::<Option<Vec<u8>>, _>(column.ordinal()) {
                    values.push((name, bytes));
                } else if let Ok(Some(text)) = row.try_get::<Option<String>, _>(column.ordinal()) {
                    values.push((name, text.into_bytes()));
                }
            }
        }
    }
    db.close().await;
    values
}

/// Every file under `dir` (SQLite database, WAL, attachments).
fn files(dir: &Path, out: &mut Vec<(String, Vec<u8>)>) {
    for entry in std::fs::read_dir(dir).expect("read_dir") {
        let path = entry.expect("entry").path();
        if path.is_dir() {
            files(&path, out);
        } else {
            out.push((
                path.display().to_string(),
                std::fs::read(&path).expect("read"),
            ));
        }
    }
}

#[tokio::test]
async fn second_device_syncs_and_decrypts_everything_the_first_one_wrote() {
    let server = TestServer::start().await;

    // Device A: sign up, log in, create a vault, a project and an item.
    let creds = server.signup("ana@example.com", PASSWORD).await;
    let laptop = server.login(&creds, "laptop").await;
    let vault = server.create_vault(&laptop).await;
    let project = server.create_project(&laptop, &vault).await;
    let mut item = login_item(TITLE, USERNAME, SECRET_V1);
    let (item_key, _) = server.create_item(&laptop, &vault, &project, &item).await;

    // …and an attachment on that item, uploaded in two chunks.
    let attachment_id = AttachmentId::generate();
    let attachment_ctx = vault
        .item_ctx(project.id, item.id())
        .attachment(attachment_id);
    let attachment_key = AttachmentKey::generate();
    let ciphertext = encrypt_attachment_bytes(&attachment_key, &attachment_ctx, FILE);
    let res = server
        .post_auth(
            &laptop,
            &format!("/v1/vaults/{}/items/{}/attachments", vault.id, item.id()),
        )
        .json(&CreateAttachment {
            item_version: None,
            id: attachment_id,
            size: ciphertext.len() as u64,
            wrapped_key: Blob::new(wrap_attachment_key(
                &item_key,
                &attachment_ctx,
                &attachment_key,
            )),
        })
        .send()
        .await
        .expect("request");
    assert_eq!(res.status(), StatusCode::CREATED);
    let base = format!("/v1/vaults/{}/attachments/{attachment_id}", vault.id);
    let half = ciphertext.len() / 2;
    for (offset, chunk) in [(0, &ciphertext[..half]), (half, &ciphertext[half..])] {
        let res = server
            .put_auth(&laptop, &format!("{base}/content?offset={offset}"))
            .body(chunk.to_vec())
            .send()
            .await
            .expect("request");
        assert_eq!(res.status(), StatusCode::OK);
    }
    let res = server
        .post_auth(&laptop, &format!("{base}/complete"))
        .send()
        .await
        .expect("request");
    assert_eq!(res.status(), StatusCode::OK);

    // Device B: log in with the same password and Secret Key. It knows
    // nothing else: it discovers the vault and rebuilds every key from the
    // server's (encrypted) copies.
    let phone = server.login(&creds, "phone").await;
    assert_ne!(phone.device_id, laptop.device_id);
    let state: SyncState = server
        .get_auth(&phone, "/v1/sync")
        .send()
        .await
        .expect("request")
        .json()
        .await
        .expect("sync state");
    assert_eq!(state.vaults.len(), 1);
    assert_eq!(state.vaults[0].vault_id, vault.id);
    let full = changes(&server, &phone, vault.id, 0).await;
    assert_eq!(full.revision, state.vaults[0].revision);

    let wire_vault = full.vault.as_ref().expect("vault");
    let ctx = VaultContext {
        account: wire_vault.owner_account_id,
        vault: vault.id,
    };
    let own = full
        .members
        .iter()
        .find(|m| m.member_id == phone.account_id.to_string())
        .expect("own membership");
    let phone_vault = TestVault {
        id: vault.id,
        owner: wire_vault.owner_account_id,
        key: open_shared_vault_key(&phone.identity, &ctx, own.shared_key.as_bytes())
            .expect("vault key opens on device B"),
    };
    assert_eq!(full.projects.len(), 1);
    let wire_project = &full.projects[0];
    let phone_project: TestProject = TestServer::open_project(
        &phone_vault,
        wire_project.id,
        wire_project
            .wrapped_key
            .as_ref()
            .expect("wrapped")
            .as_bytes(),
    );
    assert_eq!(full.items.len(), 1);
    let synced = decrypt(&phone_vault, &phone_project, &full.items[0]);
    assert_eq!(synced.title(), TITLE);
    assert_eq!(field(&synced, "username"), USERNAME);
    assert_eq!(field(&synced, "password"), SECRET_V1);

    assert_eq!(full.attachments.len(), 1);
    let wire_attachment: &Attachment = &full.attachments[0];
    let phone_item_key = unwrap_item_key(
        &phone_project.key,
        &phone_vault.item_ctx(phone_project.id, item.id()),
        full.items[0]
            .wrapped_key
            .as_ref()
            .expect("wrapped")
            .as_bytes(),
    )
    .expect("item key opens");
    let phone_attachment_key = unwrap_attachment_key(
        &phone_item_key,
        &attachment_ctx,
        wire_attachment
            .wrapped_key
            .as_ref()
            .expect("wrapped")
            .as_bytes(),
    )
    .expect("attachment key opens");
    let downloaded = server
        .get_auth(&phone, &format!("{base}/content"))
        .send()
        .await
        .expect("request")
        .bytes()
        .await
        .expect("body");
    assert_eq!(
        *decrypt_attachment_bytes(&phone_attachment_key, &attachment_ctx, &downloaded)
            .expect("attachment decrypts"),
        FILE
    );

    // Live: device B listens, device A edits the item, B pulls the delta.
    let mut events = server
        .get_auth(&phone, "/v1/events")
        .send()
        .await
        .expect("request")
        .bytes_stream();
    let mut buffer = String::new();
    next_event(&mut events, &mut buffer, "ready")
        .await
        .expect("ready");
    item.field_mut("password")
        .expect("password")
        .set_value(SECRET_V2)
        .expect("set");
    let res = server
        .put_item(&laptop, &vault, &project, &item, &item_key, 2)
        .await;
    assert_eq!(res.status(), StatusCode::OK);
    let data = next_event(&mut events, &mut buffer, "change")
        .await
        .expect("change event");
    let event: ChangeEvent = serde_json::from_str(&data).expect("event json");
    assert_eq!(event.vault_id, vault.id);
    assert_eq!(event.revision, full.revision + 1);
    let delta = changes(&server, &phone, vault.id, full.revision).await;
    assert_eq!(delta.revision, event.revision);
    assert_eq!(delta.items.len(), 1);
    assert!(delta.attachments.is_empty() && delta.projects.is_empty());
    let updated = decrypt(&phone_vault, &phone_project, &delta.items[0]);
    assert_eq!(delta.items[0].version, 2);
    assert_eq!(field(&updated, "password"), SECRET_V2);
    drop(events);

    // Nothing the server stored contains a secret in the clear: not the
    // master password or the Secret Key, not the item fields (current or
    // history), not the attachment.
    let mut stored = database_values(&server).await;
    files(server.data_dir.path(), &mut stored);
    // Control: the scan does see what is stored in the clear (the e-mail).
    assert!(
        stored.iter().any(|(_, v)| contains(v, b"ana@example.com")),
        "the scan reads the stored data"
    );
    let stored_item = full.items[0].details.as_ref().expect("details").as_bytes();
    assert!(stored.iter().any(|(_, v)| v == stored_item), "rows scanned");
    assert!(
        stored.iter().any(|(_, v)| *v == ciphertext),
        "attachment files scanned"
    );
    let markers: [&[u8]; 8] = [
        PASSWORD.as_bytes(),
        creds.secret_key_text.as_bytes(),
        USERNAME.as_bytes(),
        SECRET_V1.as_bytes(),
        SECRET_V2.as_bytes(),
        TITLE.as_bytes(),
        FILE,
        b"MARKER-",
    ];
    for (place, value) in &stored {
        for marker in markers {
            assert!(
                !contains(value, marker),
                "plaintext {:?} found in {place}",
                String::from_utf8_lossy(marker)
            );
        }
    }
}
