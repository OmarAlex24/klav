//! Per-account quotas (ADR 0048 §3): attachments, vault data, items and
//! vaults; only growth is refused, under the owner's account lock, and `0`
//! means unlimited.

mod common;

use common::TestServer;
use common::client::Session;
use common::vault::{TestProject, TestVault, login_item};
use futures_util::future::join_all;
use klav_core::crypto::context::VaultContext;
use klav_core::crypto::keys::{AttachmentKey, ItemKey, VaultKey};
use klav_core::crypto::random;
use klav_core::crypto::share::{share_vault_key, sign_vault_key};
use klav_core::crypto::wrap::wrap_attachment_key;
use klav_core::ids::{AttachmentId, ItemId, VaultId};
use klav_proto::vault::CreateVault;
use klav_proto::{Blob, ErrorBody, ErrorCode};
use klav_server::Config;
use reqwest::StatusCode;

async fn session(server: &TestServer, email: &str) -> Session {
    let creds = server.signup(email, "pw").await;
    server.login(&creds, "mac").await
}

/// `POST /v1/vaults` without asserting the answer.
async fn try_create_vault(server: &TestServer, session: &Session) -> reqwest::Response {
    let id = VaultId::generate();
    let ctx = VaultContext {
        account: session.account_id,
        vault: id,
    };
    let shared =
        share_vault_key(session.identity.public(), &ctx, &VaultKey::generate()).expect("share");
    let signature = sign_vault_key(&session.identity, &ctx, &shared).expect("sign");
    server
        .post_auth(session, "/v1/vaults")
        .json(&CreateVault {
            id,
            meta: Blob::new(random::array::<48>().to_vec()),
            shared_key: Blob::new(shared),
            shared_key_signature: Blob::new(signature.to_bytes().to_vec()),
        })
        .send()
        .await
        .expect("request")
}

/// `POST …/items` for a login with a password of `len` characters.
async fn try_create_item(
    server: &TestServer,
    session: &Session,
    vault: &TestVault,
    project: &TestProject,
    len: usize,
) -> (
    reqwest::Response,
    ItemId,
    ItemKey,
    klav_core::model::item::Item,
) {
    let item = login_item("quota", "ana", &"p".repeat(len));
    let (key, body) = server
        .create_item_body(session, vault, project, &item)
        .await;
    let res = server
        .post_auth(session, &format!("/v1/vaults/{}/items", vault.id))
        .json(&body)
        .send()
        .await
        .expect("request");
    (res, item.id(), key, item)
}

async fn assert_quota(res: reqwest::Response, words: &str) {
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    let body: ErrorBody = res.json().await.expect("error body");
    assert_eq!(body.error, ErrorCode::QuotaExceeded);
    assert!(body.message.contains(words), "{}", body.message);
}

/// Declares an attachment of `size` bytes on `item` (the server only checks
/// the declaration here).
async fn declare(
    server: &TestServer,
    session: &Session,
    vault: &TestVault,
    project: &TestProject,
    item: ItemId,
    size: u64,
) -> reqwest::Response {
    let id = AttachmentId::generate();
    let ctx = vault.item_ctx(project.id, item).attachment(id);
    server
        .post_auth(
            session,
            &format!("/v1/vaults/{}/items/{item}/attachments", vault.id),
        )
        .json(&klav_proto::sync::CreateAttachment {
            item_version: None,
            id,
            size,
            wrapped_key: Blob::new(wrap_attachment_key(
                &ItemKey::generate(),
                &ctx,
                &AttachmentKey::generate(),
            )),
        })
        .send()
        .await
        .expect("request")
}

#[tokio::test]
async fn vaults_are_counted_until_purged_and_zero_is_unlimited() {
    let server = TestServer::start_with(|c| c.limits.max_vaults_per_account = 2).await;
    let ana = session(&server, "ana@example.com").await;
    let first = server.create_vault(&ana).await;
    server.create_vault(&ana).await;
    assert_quota(try_create_vault(&server, &ana).await, "2 vaults").await;
    // A deleted vault still counts until it is purged.
    let res = server
        .delete_auth(&ana, &format!("/v1/vaults/{}", first.id))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
    assert_quota(try_create_vault(&server, &ana).await, "2 vaults").await;
    // Another account has its own count.
    let bob = session(&server, "bob@example.com").await;
    server.create_vault(&bob).await;

    let unlimited = TestServer::start_with(|c| c.limits.max_vaults_per_account = 0).await;
    let ana = session(&unlimited, "ana@example.com").await;
    for _ in 0..4 {
        unlimited.create_vault(&ana).await;
    }
}

#[tokio::test]
async fn vaults_created_at_once_cannot_pass_the_quota() {
    let server = TestServer::start_with(|c| c.limits.max_vaults_per_account = 3).await;
    let ana = session(&server, "ana@example.com").await;
    let statuses: Vec<StatusCode> = join_all((0..10).map(|_| try_create_vault(&server, &ana)))
        .await
        .into_iter()
        .map(|r| r.status())
        .collect();
    let created = statuses
        .iter()
        .filter(|s| **s == StatusCode::CREATED)
        .count();
    assert_eq!(created, 3, "{statuses:?}");
}

#[tokio::test]
async fn items_count_the_trash_and_free_up_when_purged() {
    let server = TestServer::start_with(|c| c.limits.max_items_per_account = 2).await;
    let ana = session(&server, "ana@example.com").await;
    let vault = server.create_vault(&ana).await;
    let project = server.create_project(&ana, &vault).await;
    let (res, first, _, _) = try_create_item(&server, &ana, &vault, &project, 8).await;
    assert_eq!(res.status(), StatusCode::CREATED);
    let (res, ..) = try_create_item(&server, &ana, &vault, &project, 8).await;
    assert_eq!(res.status(), StatusCode::CREATED);
    let (res, ..) = try_create_item(&server, &ana, &vault, &project, 8).await;
    assert_quota(res, "2 items").await;
    // Trashing is never refused, and the trash still counts.
    let path = format!("/v1/vaults/{}/items/{first}", vault.id);
    let res = server.delete_auth(&ana, &path).send().await.unwrap();
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
    let (res, ..) = try_create_item(&server, &ana, &vault, &project, 8).await;
    assert_quota(res, "the trash included").await;
    // Purged, it frees its place.
    let res = server
        .post_auth(&ana, &format!("{path}/purge"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
    let (res, ..) = try_create_item(&server, &ana, &vault, &project, 8).await;
    assert_eq!(res.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn items_created_at_once_cannot_pass_the_quota() {
    let server = TestServer::start_with(|c| c.limits.max_items_per_account = 3).await;
    let ana = session(&server, "ana@example.com").await;
    // Two vaults, so the vaults' own locks don't serialize the writes: only
    // the owner's account lock keeps them from passing the quota together.
    let first = server.create_vault(&ana).await;
    let second = server.create_vault(&ana).await;
    let targets = [
        (server.create_project(&ana, &first).await, &first),
        (server.create_project(&ana, &second).await, &second),
    ];
    let statuses: Vec<StatusCode> = join_all((0..8).map(|i| {
        let (project, vault) = &targets[i % 2];
        async { try_create_item(&server, &ana, vault, project, 8).await.0 }
    }))
    .await
    .into_iter()
    .map(|r| r.status())
    .collect();
    let created = statuses
        .iter()
        .filter(|s| **s == StatusCode::CREATED)
        .count();
    assert_eq!(created, 3, "{statuses:?}");
}

#[tokio::test]
async fn vault_data_counts_versions_and_only_growth_is_refused() {
    let server = TestServer::start_with(|c| {
        c.limits.max_account_vault_bytes = 30_000;
        // One kept version: an edit of the same size drops one as it adds
        // one, so it doesn't grow the account.
        c.limits.max_item_versions = 1;
    })
    .await;
    let ana = session(&server, "ana@example.com").await;
    let vault = server.create_vault(&ana).await;
    let project = server.create_project(&ana, &vault).await;
    let (res, a, a_key, a_item) = try_create_item(&server, &ana, &vault, &project, 4000).await;
    assert_eq!(res.status(), StatusCode::CREATED);
    // Version 2: version 1 goes to the history and keeps counting.
    let res = server
        .put_item(&ana, &vault, &project, &a_item, &a_key, 2)
        .await;
    assert_eq!(res.status(), StatusCode::OK);

    // Fill up until a new item no longer fits.
    let mut others = Vec::new();
    let mut refused = None;
    for _ in 0..10 {
        let (res, id, ..) = try_create_item(&server, &ana, &vault, &project, 4000).await;
        if res.status() == StatusCode::CREATED {
            others.push(id);
        } else {
            refused = Some(res);
            break;
        }
    }
    assert_quota(refused.expect("the quota is reached"), "Vault data").await;
    assert!(!others.is_empty());

    // An edit of the same size: version 1 dropped, version 2 kept, net 0.
    let res = server
        .put_item(&ana, &vault, &project, &a_item, &a_key, 3)
        .await;
    assert_eq!(res.status(), StatusCode::OK, "same size is never refused");
    // An edit that grows past what is left is refused.
    let mut bigger = a_item.clone();
    bigger
        .field_mut("password")
        .unwrap()
        .set_value(&"p".repeat(9000))
        .unwrap();
    let res = server
        .put_item(&ana, &vault, &project, &bigger, &a_key, 4)
        .await;
    assert_quota(res, "kept item versions included").await;

    // Cleaning up is never refused: forget versions, trash, purge.
    let res = server
        .delete_auth(&ana, &format!("/v1/vaults/{}/items/{a}/versions", vault.id))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
    let gone = others[0];
    let path = format!("/v1/vaults/{}/items/{gone}", vault.id);
    assert_eq!(
        server
            .delete_auth(&ana, &path)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        server
            .post_auth(&ana, &format!("{path}/purge"))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::NO_CONTENT
    );
    // And it makes room again.
    let res = server
        .put_item(&ana, &vault, &project, &bigger, &a_key, 4)
        .await;
    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn attachment_bytes_count_from_the_declaration() {
    let server = TestServer::start_with(|c| {
        c.limits.max_attachment_bytes = 4096;
        c.limits.max_account_attachment_bytes = 10_000;
    })
    .await;
    let ana = session(&server, "ana@example.com").await;
    let vault = server.create_vault(&ana).await;
    let project = server.create_project(&ana, &vault).await;
    let (res, item, ..) = try_create_item(&server, &ana, &vault, &project, 8).await;
    assert_eq!(res.status(), StatusCode::CREATED);

    // Six declared at once: only two fit, pending or not.
    let statuses: Vec<StatusCode> =
        join_all((0..6).map(|_| declare(&server, &ana, &vault, &project, item, 4000)))
            .await
            .into_iter()
            .map(|r| r.status())
            .collect();
    let created = statuses
        .iter()
        .filter(|s| **s == StatusCode::CREATED)
        .count();
    assert_eq!(created, 2, "{statuses:?}");
    let res = declare(&server, &ana, &vault, &project, item, 4000).await;
    assert_quota(res, "Attachments for this account").await;
    // A smaller one still fits in what is left.
    let res = declare(&server, &ana, &vault, &project, item, 1500).await;
    assert_eq!(res.status(), StatusCode::CREATED);

    // Deleting one frees its bytes.
    let created: klav_proto::sync::Attachment = res.json().await.unwrap();
    let res = server
        .delete_auth(
            &ana,
            &format!("/v1/vaults/{}/attachments/{}", vault.id, created.id),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
    let res = declare(&server, &ana, &vault, &project, item, 1500).await;
    assert_eq!(res.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn a_configuration_whose_attachment_quota_cannot_hold_one_attachment_fails() {
    let err = Config::load(
        None,
        [(
            "KLAV_MAX_ACCOUNT_ATTACHMENT_BYTES".to_owned(),
            "1000".to_owned(),
        )],
    )
    .unwrap_err();
    assert!(err.to_string().contains("max_attachment_bytes"), "{err}");
}
