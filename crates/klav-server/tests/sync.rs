//! Delta sync, server-sent events and encrypted attachments.

mod common;

use std::time::Duration;

use common::TestServer;
use common::client::Session;
use common::vault::{decrypt, field, login_item};
use futures_util::StreamExt;
use klav_core::crypto::attachment::{decrypt_attachment_bytes, encrypt_attachment_bytes};
use klav_core::crypto::keys::AttachmentKey;
use klav_core::crypto::wrap::{unwrap_attachment_key, wrap_attachment_key};
use klav_core::ids::{AttachmentId, VaultId};
use klav_proto::Blob;
use klav_proto::sync::{
    Attachment, ChangeEvent, Changes, CreateAttachment, SyncState, UploadProgress,
};
use reqwest::StatusCode;

async fn changes(server: &TestServer, s: &Session, vault: VaultId, since: u64) -> Changes {
    let res = server
        .get_auth(s, &format!("/v1/vaults/{vault}/changes?since={since}"))
        .send()
        .await
        .expect("request");
    assert_eq!(res.status(), StatusCode::OK);
    res.json().await.expect("changes")
}

fn now() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_millis(),
    )
    .expect("clock")
}

#[tokio::test]
async fn deltas_carry_only_what_changed_including_tombstones() {
    let server = TestServer::start().await;
    let creds = server.signup("ana@example.com", "pw").await;
    let ana = server.login(&creds, "laptop").await;
    let vault = server.create_vault(&ana).await;
    let project = server.create_project(&ana, &vault).await;
    let mut a = login_item("A", "ana", "a-1");
    let b = login_item("B", "ana", "b-1");
    let (key_a, _) = server.create_item(&ana, &vault, &project, &a).await;
    server.create_item(&ana, &vault, &project, &b).await;

    let full = changes(&server, &ana, vault.id, 0).await;
    assert_eq!(full.revision, 4);
    assert!(full.vault.is_some());
    assert_eq!(full.members.len(), 1);
    assert_eq!(full.projects.len(), 1);
    assert_eq!(full.items.len(), 2);
    assert!(full.items.iter().all(|i| i.details.is_some()));

    let nothing = changes(&server, &ana, vault.id, full.revision).await;
    assert_eq!(nothing.revision, full.revision);
    assert!(nothing.vault.is_none() && nothing.items.is_empty() && nothing.projects.is_empty());

    a.field_mut("password").unwrap().set_value("a-2").unwrap();
    server.put_item(&ana, &vault, &project, &a, &key_a, 2).await;
    let delta = changes(&server, &ana, vault.id, full.revision).await;
    assert_eq!(delta.revision, full.revision + 1);
    assert_eq!(delta.items.len(), 1);
    assert_eq!(delta.items[0].id, a.id());
    assert_eq!(
        field(&decrypt(&vault, &project, &delta.items[0]), "password"),
        "a-2"
    );

    // Trash + purge: the item comes back as a tombstone.
    let items = format!("/v1/vaults/{}/items", vault.id);
    server
        .delete_auth(&ana, &format!("{items}/{}", b.id()))
        .send()
        .await
        .unwrap();
    server
        .post_auth(&ana, &format!("{items}/{}/purge", b.id()))
        .send()
        .await
        .unwrap();
    let delta2 = changes(&server, &ana, vault.id, delta.revision).await;
    assert_eq!(delta2.revision, delta.revision + 2);
    assert_eq!(delta2.items.len(), 1);
    let tomb = &delta2.items[0];
    assert!(tomb.purged_at.is_some());
    assert!(tomb.overview.is_none() && tomb.details.is_none() && tomb.wrapped_key.is_none());

    // A client that claims to be ahead of the server gets the real revision
    // back and must treat the gap as a rollback (threat T7).
    let ahead = changes(&server, &ana, vault.id, delta2.revision + 10).await;
    assert_eq!(ahead.revision, delta2.revision);
    assert!(ahead.items.is_empty());
}

#[tokio::test]
async fn sync_state_lists_every_vault_with_its_revision() {
    let server = TestServer::start().await;
    let creds = server.signup("ana@example.com", "pw").await;
    let ana = server.login(&creds, "laptop").await;
    let v1 = server.create_vault(&ana).await;
    let v2 = server.create_vault(&ana).await;
    server.create_project(&ana, &v2).await;
    server
        .delete_auth(&ana, &format!("/v1/vaults/{}", v1.id))
        .send()
        .await
        .unwrap();

    let state: SyncState = server
        .get_auth(&ana, "/v1/sync")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(state.vaults.len(), 2);
    let r1 = state.vaults.iter().find(|v| v.vault_id == v1.id).unwrap();
    let r2 = state.vaults.iter().find(|v| v.vault_id == v2.id).unwrap();
    assert_eq!((r1.revision, r1.deleted_at.is_some()), (2, true));
    assert_eq!((r2.revision, r2.deleted_at.is_some()), (2, false));
    // The deletion itself is a change of the vault.
    let delta = changes(&server, &ana, v1.id, 1).await;
    assert!(delta.vault.unwrap().deleted_at.is_some());
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

#[tokio::test]
async fn events_announce_changes_only_to_members() {
    let server = TestServer::start().await;
    let ana_creds = server.signup("ana@example.com", "pw").await;
    let ana = server.login(&ana_creds, "laptop").await;
    let bob_creds = server.signup("bob@example.com", "pw").await;
    let bob = server.login(&bob_creds, "laptop").await;
    let vault = server.create_vault(&ana).await;

    let open = |s: &Session| server.get_auth(s, "/v1/events").send();
    let ana_res = open(&ana).await.unwrap();
    assert_eq!(ana_res.status(), StatusCode::OK);
    assert!(
        ana_res.headers()["content-type"]
            .to_str()
            .unwrap()
            .starts_with("text/event-stream")
    );
    let mut ana_stream = ana_res.bytes_stream();
    let mut ana_buf = String::new();
    let mut bob_stream = open(&bob).await.unwrap().bytes_stream();
    let mut bob_buf = String::new();
    assert!(
        next_event(&mut ana_stream, &mut ana_buf, "ready")
            .await
            .is_some()
    );
    assert!(
        next_event(&mut bob_stream, &mut bob_buf, "ready")
            .await
            .is_some()
    );

    // Ana changes her vault, then Bob creates his own.
    server.create_project(&ana, &vault).await;
    let bob_vault = server.create_vault(&bob).await;

    let data = next_event(&mut ana_stream, &mut ana_buf, "change")
        .await
        .unwrap();
    let event: ChangeEvent = serde_json::from_str(&data).unwrap();
    assert_eq!(
        event,
        ChangeEvent {
            vault_id: vault.id,
            revision: 2
        }
    );
    // Bob's first change event is his own vault, never Ana's.
    let data = next_event(&mut bob_stream, &mut bob_buf, "change")
        .await
        .unwrap();
    let event: ChangeEvent = serde_json::from_str(&data).unwrap();
    assert_eq!(event.vault_id, bob_vault.id);

    let res = server
        .http
        .get(server.url("/v1/events"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn event_streams_end_when_the_access_token_expires() {
    let server = TestServer::start_with(|c| c.sessions.access_ttl_secs = 1).await;
    let creds = server.signup("ana@example.com", "pw").await;
    let ana = server.login(&creds, "laptop").await;
    let mut stream = server
        .get_auth(&ana, "/v1/events")
        .send()
        .await
        .unwrap()
        .bytes_stream();
    let ended = tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(chunk) = stream.next().await {
            if chunk.is_err() {
                break;
            }
        }
    })
    .await;
    assert!(ended.is_ok(), "the stream closes on expiry");
}

#[tokio::test]
async fn attachments_upload_in_chunks_download_with_ranges_and_decrypt() {
    let server = TestServer::start().await;
    let creds = server.signup("ana@example.com", "pw").await;
    let ana = server.login(&creds, "laptop").await;
    let vault = server.create_vault(&ana).await;
    let project = server.create_project(&ana, &vault).await;
    let item = login_item("Apple", "ana", "x");
    let (item_key, _) = server.create_item(&ana, &vault, &project, &item).await;

    // Client side: encrypt a 200 KiB "AuthKey.p8" with its own key.
    let plaintext: Vec<u8> = (0..200 * 1024).map(|i| (i % 251) as u8).collect();
    let id = AttachmentId::generate();
    let ctx = vault.item_ctx(project.id, item.id()).attachment(id);
    let att_key = AttachmentKey::generate();
    let ciphertext = encrypt_attachment_bytes(&att_key, &ctx, &plaintext);
    let wrapped = wrap_attachment_key(&item_key, &ctx, &att_key);
    let base = format!("/v1/vaults/{}/attachments/{id}", vault.id);

    let res = server
        .post_auth(
            &ana,
            &format!("/v1/vaults/{}/items/{}/attachments", vault.id, item.id()),
        )
        .json(&CreateAttachment {
            item_version: None,
            id,
            size: ciphertext.len() as u64,
            wrapped_key: Blob::new(wrapped),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    let before = changes(&server, &ana, vault.id, 0).await;
    assert!(
        before.attachments.is_empty(),
        "pending uploads are invisible"
    );

    let put = |offset: usize, chunk: Vec<u8>| {
        server
            .put_auth(&ana, &format!("{base}/content?offset={offset}"))
            .body(chunk)
            .send()
    };
    let third = ciphertext.len() / 3;
    let res = put(0, ciphertext[..third].to_vec()).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let progress: UploadProgress = res.json().await.unwrap();
    assert_eq!(progress.received, third as u64);
    // Wrong offset → 409; completing early → 409.
    assert_eq!(
        put(0, vec![1, 2]).await.unwrap().status(),
        StatusCode::CONFLICT
    );
    let res = server
        .post_auth(&ana, &format!("{base}/complete"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CONFLICT);
    // Resume from what the server reports.
    let meta: Attachment = server
        .get_auth(&ana, &base)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(meta.received, third as u64);
    put(third, ciphertext[third..2 * third].to_vec())
        .await
        .unwrap();
    put(2 * third, ciphertext[2 * third..].to_vec())
        .await
        .unwrap();
    // Past the declared size → 400.
    let res = put(ciphertext.len(), vec![0]).await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let res = server
        .post_auth(&ana, &format!("{base}/complete"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let done: Attachment = res.json().await.unwrap();
    assert!(done.completed_at.is_some());
    assert_eq!(done.revision, before.revision + 1);

    // Full download, byte-for-byte, then decrypt on the "second device".
    let res = server
        .get_auth(&ana, &format!("{base}/content"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.headers()["content-type"], "application/octet-stream");
    let downloaded = res.bytes().await.unwrap().to_vec();
    assert_eq!(downloaded, ciphertext);
    let delta = changes(&server, &ana, vault.id, before.revision).await;
    assert_eq!(delta.attachments.len(), 1);
    let key = unwrap_attachment_key(
        &item_key,
        &ctx,
        delta.attachments[0]
            .wrapped_key
            .as_ref()
            .unwrap()
            .as_bytes(),
    )
    .unwrap();
    assert_eq!(
        *decrypt_attachment_bytes(&key, &ctx, &downloaded).unwrap(),
        plaintext
    );

    // Ranged download.
    let res = server
        .get_auth(&ana, &format!("{base}/content"))
        .header("range", "bytes=100-199")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(res.bytes().await.unwrap().to_vec(), ciphertext[100..200]);

    // Delete: tombstone in sync, file gone.
    let res = server.delete_auth(&ana, &base).send().await.unwrap();
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
    let res = server
        .get_auth(&ana, &format!("{base}/content"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    let delta = changes(&server, &ana, vault.id, done.revision).await;
    assert!(delta.attachments[0].deleted_at.is_some());
    let file = server
        .data_dir
        .path()
        .join("data/attachments")
        .join(vault.id.to_string())
        .join(id.to_string());
    assert!(!file.exists());
}

#[tokio::test]
async fn attachment_limits_and_validation() {
    let server = TestServer::start_with(|c| {
        c.limits.max_attachment_bytes = 4096;
        c.limits.max_attachment_chunk_bytes = 1024;
    })
    .await;
    let creds = server.signup("ana@example.com", "pw").await;
    let ana = server.login(&creds, "laptop").await;
    let vault = server.create_vault(&ana).await;
    let project = server.create_project(&ana, &vault).await;
    let item = login_item("A", "a", "a");
    let (item_key, _) = server.create_item(&ana, &vault, &project, &item).await;
    let create = |size: u64| {
        let id = AttachmentId::generate();
        let ctx = vault.item_ctx(project.id, item.id()).attachment(id);
        let wrapped = wrap_attachment_key(&item_key, &ctx, &AttachmentKey::generate());
        let req = server
            .post_auth(
                &ana,
                &format!("/v1/vaults/{}/items/{}/attachments", vault.id, item.id()),
            )
            .json(&CreateAttachment {
                item_version: None,
                id,
                size,
                wrapped_key: Blob::new(wrapped),
            });
        async move { (id, req.send().await.unwrap().status()) }
    };
    assert_eq!(create(5000).await.1, StatusCode::BAD_REQUEST, "too large");
    assert_eq!(create(10).await.1, StatusCode::BAD_REQUEST, "too small");
    let (id, status) = create(3000).await;
    assert_eq!(status, StatusCode::CREATED);
    let content = format!("/v1/vaults/{}/attachments/{id}/content?offset=0", vault.id);
    // Not an encrypted attachment → 400.
    let res = server
        .put_auth(&ana, &content)
        .body(vec![0u8; 100])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    // Chunk above the limit → 413.
    let mut big = vec![0u8; 2000];
    big[0] = 0x01;
    big[1] = 0x30;
    let res = server
        .put_auth(&ana, &content)
        .body(big)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn purging_an_item_removes_its_attachments() {
    let server = TestServer::start().await;
    let creds = server.signup("ana@example.com", "pw").await;
    let ana = server.login(&creds, "laptop").await;
    let vault = server.create_vault(&ana).await;
    let project = server.create_project(&ana, &vault).await;
    let item = login_item("A", "a", "a");
    let (item_key, _) = server.create_item(&ana, &vault, &project, &item).await;
    let id = AttachmentId::generate();
    let ctx = vault.item_ctx(project.id, item.id()).attachment(id);
    let key = AttachmentKey::generate();
    let ciphertext = encrypt_attachment_bytes(&key, &ctx, b"-----BEGIN PRIVATE KEY-----");
    let res = server
        .post_auth(
            &ana,
            &format!("/v1/vaults/{}/items/{}/attachments", vault.id, item.id()),
        )
        .json(&CreateAttachment {
            item_version: None,
            id,
            size: ciphertext.len() as u64,
            wrapped_key: Blob::new(wrap_attachment_key(&item_key, &ctx, &key)),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED, "declare");
    let base = format!("/v1/vaults/{}/attachments/{id}", vault.id);
    let res = server
        .put_auth(&ana, &format!("{base}/content?offset=0"))
        .body(ciphertext)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK, "upload");
    let res = server
        .post_auth(&ana, &format!("{base}/complete"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK, "complete");
    let file = server
        .data_dir
        .path()
        .join("data/attachments")
        .join(vault.id.to_string())
        .join(id.to_string());
    assert!(file.exists());

    server
        .delete_auth(
            &ana,
            &format!("/v1/vaults/{}/items/{}", vault.id, item.id()),
        )
        .send()
        .await
        .unwrap();
    server
        .server_handle()
        .purge_expired(now() + 31 * 24 * 3600 * 1000)
        .await
        .unwrap();
    assert!(!file.exists());
    let res = server.get_auth(&ana, &base).send().await.unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}
