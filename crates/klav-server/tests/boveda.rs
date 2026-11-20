//! Encrypted CRUD of vaults, projects and items: revisions, versions,
//! optimistic concurrency, trash, history and isolation between accounts.

mod common;

use common::client::Session;
use common::vault::{TestProject, TestVault, decrypt, field, login_item};
use common::{TestServer, until_dropped};
use klav_core::ids::{AgentId, ItemId, VaultId};
use klav_proto::audit::{ActorKind, AuditEvent};
use klav_proto::vault::{
    Item, ItemHistory, ItemList, ItemVersion, MemberList, MemberType, ProjectList, Role,
    UpdateVault, Vault, VaultList,
};
use klav_proto::{Blob, ErrorBody, ErrorCode};
use reqwest::{Method, StatusCode};
use sqlx::Row;

async fn vault_info(server: &TestServer, s: &common::client::Session, id: VaultId) -> Vault {
    server
        .get_auth(s, &format!("/v1/vaults/{id}"))
        .send()
        .await
        .expect("request")
        .json()
        .await
        .expect("vault")
}

async fn get_item(
    server: &TestServer,
    s: &common::client::Session,
    vault: VaultId,
    item: ItemId,
) -> reqwest::Response {
    server
        .get_auth(s, &format!("/v1/vaults/{vault}/items/{item}"))
        .send()
        .await
        .expect("request")
}

#[tokio::test]
async fn vault_project_item_roundtrip_and_revisions() {
    let server = TestServer::start().await;
    let creds = server.signup("ana@example.com", "pw").await;
    let ana = server.login(&creds, "laptop").await;

    let vault = server.create_vault(&ana).await;
    assert_eq!(vault_info(&server, &ana, vault.id).await.revision, 1);
    let project = server.create_project(&ana, &vault).await;
    assert_eq!(vault_info(&server, &ana, vault.id).await.revision, 2);

    let item = login_item("GitHub", "ana", "hunter2-secret");
    let (_, created) = server.create_item(&ana, &vault, &project, &item).await;
    assert_eq!(created.version, 1);
    assert_eq!(created.revision, 3);

    let vaults: VaultList = server
        .get_auth(&ana, "/v1/vaults")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(vaults.vaults.len(), 1);
    assert_eq!(vaults.vaults[0].role, Role::Owner);
    assert_eq!(vaults.vaults[0].owner_account_id, ana.account_id);

    let projects: ProjectList = server
        .get_auth(&ana, &format!("/v1/vaults/{}/projects", vault.id))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(projects.projects.len(), 1);

    // Listing returns overviews only.
    let list: ItemList = server
        .get_auth(&ana, &format!("/v1/vaults/{}/items", vault.id))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(list.items.len(), 1);
    assert!(list.items[0].overview.is_some());
    assert!(list.items[0].details.is_none());

    // A single item comes with details and decrypts on the client.
    let wire: Item = get_item(&server, &ana, vault.id, item.id())
        .await
        .json()
        .await
        .unwrap();
    let opened = decrypt(&vault, &project, &wire);
    assert_eq!(opened.title(), "GitHub");
    assert_eq!(field(&opened, "password"), "hunter2-secret");

    let members: MemberList = server
        .get_auth(&ana, &format!("/v1/vaults/{}/members", vault.id))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(members.members.len(), 1);
    assert_eq!(members.members[0].member_type, MemberType::Account);
    assert_eq!(members.members[0].member_id, ana.account_id.to_string());
}

#[tokio::test]
async fn updates_require_the_next_version() {
    let server = TestServer::start().await;
    let creds = server.signup("ana@example.com", "pw").await;
    let ana = server.login(&creds, "laptop").await;
    let vault = server.create_vault(&ana).await;
    let project = server.create_project(&ana, &vault).await;
    let mut item = login_item("GitHub", "ana", "v1-secret");
    let (key, _) = server.create_item(&ana, &vault, &project, &item).await;

    item.field_mut("password")
        .unwrap()
        .set_value("v2-secret")
        .unwrap();
    let res = server
        .put_item(&ana, &vault, &project, &item, &key, 2)
        .await;
    assert_eq!(res.status(), StatusCode::OK);
    let updated: Item = res.json().await.unwrap();
    assert_eq!(updated.version, 2);

    // A second device that still believes the item is at version 1 writes
    // version 2 again: stale → 409 with the current version.
    item.field_mut("password")
        .unwrap()
        .set_value("stale")
        .unwrap();
    let res = server
        .put_item(&ana, &vault, &project, &item, &key, 2)
        .await;
    assert_eq!(res.status(), StatusCode::CONFLICT);
    let err: ErrorBody = res.json().await.unwrap();
    assert_eq!(err.error, ErrorCode::Conflict);
    assert_eq!(err.current_version, Some(2));
    // Skipping a version is also rejected.
    let res = server
        .put_item(&ana, &vault, &project, &item, &key, 4)
        .await;
    assert_eq!(res.status(), StatusCode::CONFLICT);

    // The stored item is still version 2, intact.
    let wire: Item = get_item(&server, &ana, vault.id, item.id())
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(
        field(&decrypt(&vault, &project, &wire), "password"),
        "v2-secret"
    );

    // Vault metadata follows the same rule.
    let res = server
        .put_auth(&ana, &format!("/v1/vaults/{}", vault.id))
        .json(&UpdateVault {
            version: 3,
            meta: Blob::new(vec![1, 2, 3]),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CONFLICT);
    let res = server
        .put_auth(&ana, &format!("/v1/vaults/{}", vault.id))
        .json(&UpdateVault {
            version: 2,
            meta: Blob::new(vec![1, 2, 3]),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn history_keeps_previous_versions_that_still_decrypt() {
    let server = TestServer::start_with(|c| c.limits.max_item_versions = 2).await;
    let creds = server.signup("ana@example.com", "pw").await;
    let ana = server.login(&creds, "laptop").await;
    let vault = server.create_vault(&ana).await;
    let project = server.create_project(&ana, &vault).await;
    let mut item = login_item("GitHub", "ana", "pw-1");
    let (key, _) = server.create_item(&ana, &vault, &project, &item).await;
    for v in 2..=4 {
        item.field_mut("password")
            .unwrap()
            .set_value(&format!("pw-{v}"))
            .unwrap();
        let res = server
            .put_item(&ana, &vault, &project, &item, &key, v)
            .await;
        assert_eq!(res.status(), StatusCode::OK);
    }
    let history: ItemHistory = server
        .get_auth(
            &ana,
            &format!("/v1/vaults/{}/items/{}/versions", vault.id, item.id()),
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let versions: Vec<u64> = history.versions.iter().map(|v| v.version).collect();
    assert_eq!(
        versions,
        vec![4, 3, 2],
        "current + the 2 most recent previous"
    );

    let old: ItemVersion = server
        .get_auth(
            &ana,
            &format!("/v1/vaults/{}/items/{}/versions/3", vault.id, item.id()),
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let wire = Item {
        id: old.item_id,
        vault_id: vault.id,
        project_id: old.project_id,
        version: old.version,
        revision: 0,
        wrapped_key: Some(old.wrapped_key),
        overview: Some(old.overview),
        details: Some(old.details),
        created_at: 0,
        updated_at: 0,
        trashed_at: None,
        purged_at: None,
        author_agent_id: None,
    };
    assert_eq!(field(&decrypt(&vault, &project, &wire), "password"), "pw-3");
    let res = server
        .get_auth(
            &ana,
            &format!("/v1/vaults/{}/items/{}/versions/1", vault.id, item.id()),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND, "pruned");

    // The person can forget every stored version; the current one stays.
    let path = format!("/v1/vaults/{}/items/{}/versions", vault.id, item.id());
    let res = server.delete_auth(&ana, &path).send().await.unwrap();
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
    let history: ItemHistory = server
        .get_auth(&ana, &path)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let versions: Vec<u64> = history.versions.iter().map(|v| v.version).collect();
    assert_eq!(versions, vec![4]);
    let res = server
        .get_auth(
            &ana,
            &format!("/v1/vaults/{}/items/{}/versions/3", vault.id, item.id()),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    // Someone else's item: not found, nothing purged.
    let bob_creds = server.signup("bob@example.com", "pw").await;
    let bob = server.login(&bob_creds, "laptop").await;
    let res = server.delete_auth(&bob, &path).send().await.unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn trash_restore_purge_and_retention() {
    let server = TestServer::start().await;
    let creds = server.signup("ana@example.com", "pw").await;
    let ana = server.login(&creds, "laptop").await;
    let vault = server.create_vault(&ana).await;
    let project = server.create_project(&ana, &vault).await;
    let a = login_item("A", "ana", "a");
    let b = login_item("B", "ana", "b");
    let (key_a, _) = server.create_item(&ana, &vault, &project, &a).await;
    server.create_item(&ana, &vault, &project, &b).await;
    let items_path = format!("/v1/vaults/{}/items", vault.id);

    let res = server
        .delete_auth(&ana, &format!("{items_path}/{}", a.id()))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
    let list: ItemList = server
        .get_auth(&ana, &items_path)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(list.items.len(), 1);
    let trash: ItemList = server
        .get_auth(&ana, &format!("{items_path}?trash=only"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(trash.items.len(), 1);
    assert!(trash.items[0].trashed_at.is_some());
    // Trashed items cannot be edited.
    let res = server.put_item(&ana, &vault, &project, &a, &key_a, 2).await;
    assert_eq!(res.status(), StatusCode::CONFLICT);

    let res = server
        .post_auth(&ana, &format!("{items_path}/{}/restore", a.id()))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let list: ItemList = server
        .get_auth(&ana, &items_path)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(list.items.len(), 2);

    // Only trashed items can be purged by hand.
    let res = server
        .post_auth(&ana, &format!("{items_path}/{}/purge", b.id()))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CONFLICT);
    server
        .delete_auth(&ana, &format!("{items_path}/{}", b.id()))
        .send()
        .await
        .unwrap();
    let res = server
        .post_auth(&ana, &format!("{items_path}/{}/purge", b.id()))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        get_item(&server, &ana, vault.id, b.id()).await.status(),
        StatusCode::NOT_FOUND
    );

    // Retention: trash `a` again and run the purge 31 days later.
    server
        .delete_auth(&ana, &format!("{items_path}/{}", a.id()))
        .send()
        .await
        .unwrap();
    let now = klav_now();
    let report = server.server_handle().purge_expired(now).await.unwrap();
    assert_eq!(report.items, 0, "not yet expired");
    let report = server
        .server_handle()
        .purge_expired(now + 31 * 24 * 3600 * 1000)
        .await
        .unwrap();
    assert_eq!(report.items, 1);
    assert_eq!(
        get_item(&server, &ana, vault.id, a.id()).await.status(),
        StatusCode::NOT_FOUND
    );
    // The tombstone keeps no ciphertext.
    let db = server.raw_db().await;
    let row =
        sqlx::query("SELECT overview, details, wrapped_key, purged_at FROM items WHERE id = $1")
            .bind(a.id().to_string())
            .fetch_one(&db)
            .await
            .unwrap();
    assert!(
        row.try_get::<Option<Vec<u8>>, _>("overview")
            .unwrap()
            .is_none()
    );
    assert!(
        row.try_get::<Option<Vec<u8>>, _>("details")
            .unwrap()
            .is_none()
    );
    assert!(
        row.try_get::<Option<i64>, _>("purged_at")
            .unwrap()
            .is_some()
    );

    // Now the project is empty and can be deleted.
    let res = server
        .delete_auth(
            &ana,
            &format!("/v1/vaults/{}/projects/{}", vault.id, project.id),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
}

fn klav_now() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_millis(),
    )
    .expect("clock")
}

#[tokio::test]
async fn non_empty_projects_cannot_be_deleted() {
    let server = TestServer::start().await;
    let creds = server.signup("ana@example.com", "pw").await;
    let ana = server.login(&creds, "laptop").await;
    let vault = server.create_vault(&ana).await;
    let project = server.create_project(&ana, &vault).await;
    server
        .create_item(&ana, &vault, &project, &login_item("A", "a", "a"))
        .await;
    let res = server
        .delete_auth(
            &ana,
            &format!("/v1/vaults/{}/projects/{}", vault.id, project.id),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn vault_delete_restore_and_purge() {
    let server = TestServer::start().await;
    let creds = server.signup("ana@example.com", "pw").await;
    let ana = server.login(&creds, "laptop").await;
    let vault = server.create_vault(&ana).await;
    let project = server.create_project(&ana, &vault).await;
    let item = login_item("A", "a", "a");
    server.create_item(&ana, &vault, &project, &item).await;
    let path = format!("/v1/vaults/{}", vault.id);

    let res = server.delete_auth(&ana, &path).send().await.unwrap();
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
    let list: VaultList = server
        .get_auth(&ana, "/v1/vaults")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(list.vaults.is_empty());
    // Writes to a deleted vault fail.
    let res = server
        .put_item(
            &ana,
            &vault,
            &project,
            &item,
            &klav_core::crypto::keys::ItemKey::generate(),
            2,
        )
        .await;
    assert_eq!(res.status(), StatusCode::NOT_FOUND);

    let res = server
        .post_auth(&ana, &format!("{path}/restore"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let restored: Vault = res.json().await.unwrap();
    assert!(restored.deleted_at.is_none());
    assert_eq!(
        get_item(&server, &ana, vault.id, item.id()).await.status(),
        StatusCode::OK
    );

    server.delete_auth(&ana, &path).send().await.unwrap();
    let report = server
        .server_handle()
        .purge_expired(klav_now() + 31 * 24 * 3600 * 1000)
        .await
        .unwrap();
    assert_eq!(report.vaults, 1);
    assert_eq!(
        server.get_auth(&ana, &path).send().await.unwrap().status(),
        StatusCode::NOT_FOUND
    );
    let db = server.raw_db().await;
    let left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM items")
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(left, 0);
}

#[tokio::test]
async fn other_accounts_cannot_see_or_touch_a_vault() {
    let server = TestServer::start().await;
    let ana_creds = server.signup("ana@example.com", "pw").await;
    let ana = server.login(&ana_creds, "laptop").await;
    let bob_creds = server.signup("bob@example.com", "pw").await;
    let bob = server.login(&bob_creds, "laptop").await;
    let vault = server.create_vault(&ana).await;
    let project = server.create_project(&ana, &vault).await;
    let item = login_item("A", "a", "a");
    let (key, _) = server.create_item(&ana, &vault, &project, &item).await;

    for path in [
        format!("/v1/vaults/{}", vault.id),
        format!("/v1/vaults/{}/projects", vault.id),
        format!("/v1/vaults/{}/members", vault.id),
        format!("/v1/vaults/{}/items", vault.id),
        format!("/v1/vaults/{}/items/{}", vault.id, item.id()),
        format!("/v1/vaults/{}/items/{}/versions", vault.id, item.id()),
    ] {
        let res = server.get_auth(&bob, &path).send().await.unwrap();
        assert_eq!(res.status(), StatusCode::NOT_FOUND, "{path}");
    }
    let res = server
        .put_item(&bob, &vault, &project, &item, &key, 2)
        .await;
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    let res = server
        .delete_auth(&bob, &format!("/v1/vaults/{}", vault.id))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    let list: VaultList = server
        .get_auth(&bob, "/v1/vaults")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(list.vaults.is_empty());
}

#[tokio::test]
async fn ids_are_unique_and_blobs_are_checked() {
    let server = TestServer::start().await;
    let creds = server.signup("ana@example.com", "pw").await;
    let ana = server.login(&creds, "laptop").await;
    let vault = server.create_vault(&ana).await;
    let project = server.create_project(&ana, &vault).await;
    let item = login_item("A", "a", "a");
    let (key, _) = server.create_item(&ana, &vault, &project, &item).await;

    // Same item ID again → 409.
    let upload = common::vault::seal(&vault, &project, &item, &key, 1);
    let mut body = serde_json::json!({
        "id": item.id(),
        "project_id": project.id,
        "version": 1,
        "wrapped_key": Blob::new(upload.wrapped_key.clone()),
        "project_version": 1,
        "overview": Blob::new(upload.sealed.overview.clone()),
        "details": Blob::new(upload.sealed.details.clone()),
    });
    let items_path = format!("/v1/vaults/{}/items", vault.id);
    let res = server
        .post_auth(&ana, &items_path)
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CONFLICT);

    // Overview and details swapped: wrong kind → 400.
    body["id"] = serde_json::json!(ItemId::generate());
    body["overview"] = serde_json::json!(Blob::new(upload.sealed.details.clone()));
    let res = server
        .post_auth(&ana, &items_path)
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    // Version other than 1 on create → 400.
    body["overview"] = serde_json::json!(Blob::new(upload.sealed.overview.clone()));
    body["version"] = serde_json::json!(2);
    let res = server
        .post_auth(&ana, &items_path)
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    // Unknown project → 400.
    body["version"] = serde_json::json!(1);
    body["project_id"] = serde_json::json!(klav_core::ids::ProjectId::generate());
    let res = server
        .post_auth(&ana, &items_path)
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    // Bad query strings get a JSON error.
    let res = server
        .get_auth(&ana, &format!("{items_path}?trash=maybe"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let err: ErrorBody = res.json().await.unwrap();
    assert_eq!(err.error, ErrorCode::BadRequest);

    // Oversized details → 400.
    let small = TestServer::start_with(|c| c.limits.max_details_bytes = 64).await;
    let creds = small.signup("ana@example.com", "pw").await;
    let ana = small.login(&creds, "laptop").await;
    let vault = small.create_vault(&ana).await;
    let project = small.create_project(&ana, &vault).await;
    let mut big = login_item("A", "a", "a");
    big.set_notes(Some(&"x".repeat(200)));
    let upload = common::vault::seal(&vault, &project, &big, &key, 1);
    let res = small
        .post_auth(&ana, &format!("/v1/vaults/{}/items", vault.id))
        .json(&serde_json::json!({
            "id": big.id(),
            "project_id": project.id,
            "version": 1,
            "wrapped_key": Blob::new(upload.wrapped_key),
            "project_version": 1,
            "overview": Blob::new(upload.sealed.overview),
            "details": Blob::new(upload.sealed.details),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn item_bodies_are_stored_exactly_as_received() {
    let server = TestServer::start().await;
    let creds = server.signup("ana@example.com", "pw").await;
    let ana = server.login(&creds, "laptop").await;
    let vault = server.create_vault(&ana).await;
    let project = server.create_project(&ana, &vault).await;
    let secret = "PLAINTEXT-MARKER-91c2";
    let item = login_item("Bank", "ana", secret);
    let key = klav_core::crypto::keys::ItemKey::generate();
    let upload = common::vault::seal(&vault, &project, &item, &key, 1);
    let res = server
        .post_auth(&ana, &format!("/v1/vaults/{}/items", vault.id))
        .json(&klav_proto::vault::CreateItem {
            id: item.id(),
            project_id: project.id,
            version: 1,
            wrapped_key: Blob::new(upload.wrapped_key.clone()),
            project_version: 1,
            overview: Blob::new(upload.sealed.overview.clone()),
            details: Blob::new(upload.sealed.details.clone()),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);

    // Byte-for-byte in the database…
    let db = server.raw_db().await;
    let row = sqlx::query("SELECT wrapped_key, overview, details FROM items WHERE id = $1")
        .bind(item.id().to_string())
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(
        row.try_get::<Vec<u8>, _>("wrapped_key").unwrap(),
        upload.wrapped_key
    );
    assert_eq!(
        row.try_get::<Vec<u8>, _>("overview").unwrap(),
        upload.sealed.overview
    );
    assert_eq!(
        row.try_get::<Vec<u8>, _>("details").unwrap(),
        upload.sealed.details
    );
    // …and byte-for-byte back to clients.
    let wire: Item = get_item(&server, &ana, vault.id, item.id())
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(wire.details.unwrap().as_bytes(), upload.sealed.details);
    // The plaintext never reached the server.
    let details = row.try_get::<Vec<u8>, _>("details").unwrap();
    assert!(
        !details
            .windows(secret.len())
            .any(|w| w == secret.as_bytes())
    );
}

#[tokio::test]
async fn concurrent_writers_get_exactly_one_winner_and_distinct_revisions() {
    let server = std::sync::Arc::new(TestServer::start().await);
    let creds = server.signup("ana@example.com", "pw").await;
    let ana = std::sync::Arc::new(server.login(&creds, "laptop").await);
    let vault = std::sync::Arc::new(server.create_vault(&ana).await);
    let project = std::sync::Arc::new(server.create_project(&ana, &vault).await);
    let item = login_item("A", "a", "v1");
    let (key, _) = server.create_item(&ana, &vault, &project, &item).await;
    let key = std::sync::Arc::new(key);

    let mut tasks = Vec::new();
    for n in 0..8 {
        let (server, ana, vault, project, key) = (
            server.clone(),
            ana.clone(),
            vault.clone(),
            project.clone(),
            key.clone(),
        );
        let mut item = item.clone();
        tasks.push(tokio::spawn(async move {
            item.field_mut("password")
                .unwrap()
                .set_value(&format!("writer-{n}"))
                .unwrap();
            server
                .put_item(&ana, &vault, &project, &item, &key, 2)
                .await
                .status()
        }));
    }
    let mut statuses = Vec::new();
    for t in tasks {
        statuses.push(t.await.unwrap());
    }
    assert_eq!(statuses.iter().filter(|s| **s == StatusCode::OK).count(), 1);
    assert_eq!(
        statuses
            .iter()
            .filter(|s| **s == StatusCode::CONFLICT)
            .count(),
        7
    );

    // Independent creates in parallel each get their own revision.
    let mut tasks = Vec::new();
    for n in 0..6 {
        let (server, ana, vault, project) =
            (server.clone(), ana.clone(), vault.clone(), project.clone());
        tasks.push(tokio::spawn(async move {
            let item = login_item(&format!("P{n}"), "a", "x");
            server
                .create_item(&ana, &vault, &project, &item)
                .await
                .1
                .revision
        }));
    }
    let mut revisions = Vec::new();
    for t in tasks {
        revisions.push(t.await.unwrap());
    }
    revisions.sort_unstable();
    revisions.dedup();
    assert_eq!(revisions.len(), 6, "no two changes share a revision");
}

/// ADR 0030 §7: each version keeps who wrote it, and pruning the history
/// never drops the last version the person wrote (its sites are the
/// confirmed ones). The agent's writes are played by marking the current
/// row as an agent's, as the agent routes do.
#[tokio::test]
async fn history_keeps_the_author_and_the_persons_last_version() {
    let server = TestServer::start_with(|c| c.limits.max_item_versions = 2).await;
    let creds = server.signup("ana@example.com", "pw").await;
    let ana = server.login(&creds, "laptop").await;
    let vault = server.create_vault(&ana).await;
    let project = server.create_project(&ana, &vault).await;
    let mut item = login_item("GitHub", "ana", "pw-1");
    let (key, _) = server.create_item(&ana, &vault, &project, &item).await;
    let bot = AgentId::generate();
    let db = server.raw_db().await;
    for v in 2..=4 {
        item.field_mut("password")
            .unwrap()
            .set_value(&format!("pw-{v}"))
            .unwrap();
        let res = server
            .put_item(&ana, &vault, &project, &item, &key, v)
            .await;
        assert_eq!(res.status(), StatusCode::OK);
        sqlx::query("UPDATE items SET author_agent_id = $1 WHERE id = $2")
            .bind(bot.to_string())
            .bind(item.id().to_string())
            .execute(&db)
            .await
            .unwrap();
    }
    let history: ItemHistory = server
        .get_auth(
            &ana,
            &format!("/v1/vaults/{}/items/{}/versions", vault.id, item.id()),
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let got: Vec<(u64, Option<AgentId>)> = history
        .versions
        .iter()
        .map(|v| (v.version, v.author_agent_id))
        .collect();
    assert_eq!(
        got,
        vec![(4, Some(bot)), (3, Some(bot)), (2, Some(bot)), (1, None)],
        "the 2 most recent previous versions, and the person's last one"
    );
    let first: ItemVersion = server
        .get_auth(
            &ana,
            &format!("/v1/vaults/{}/items/{}/versions/1", vault.id, item.id()),
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(first.author_agent_id, None);
    let current: Item = get_item(&server, &ana, vault.id, item.id())
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(current.author_agent_id, Some(bot));
}

// ------------------------------ item events in the write's transaction --

/// A change the person makes to an item, and the event it logs.
#[derive(Clone, Copy, Debug)]
enum Change {
    Created,
    Updated,
    Trashed,
    Restored,
    Purged,
    VersionsPurged,
}

const CHANGES: [Change; 6] = [
    Change::Created,
    Change::Updated,
    Change::Trashed,
    Change::Restored,
    Change::Purged,
    Change::VersionsPurged,
];

impl Change {
    fn action(self) -> &'static str {
        match self {
            Change::Created => "item.created",
            Change::Updated => "item.updated",
            Change::Trashed => "item.trashed",
            Change::Restored => "item.restored",
            Change::Purged => "item.purged",
            Change::VersionsPurged => "item.versions_purged",
        }
    }
}

/// One person's vault and project, with a raw connection to the database.
struct Items {
    server: TestServer,
    ana: Session,
    vault: TestVault,
    project: TestProject,
    db: sqlx::AnyPool,
}

async fn items() -> Items {
    // Six changes of up to `DROP_TRIES` tries each, every one with its own
    // item, more than the default bursts allow when every try finishes
    // first.
    let server = TestServer::start_with(|c| {
        c.rate_limit.ip_burst = 10_000;
        c.rate_limit.account_burst = 10_000;
    })
    .await;
    let ana = server
        .login(&server.signup("ana@example.com", "pw").await, "laptop")
        .await;
    let vault = server.create_vault(&ana).await;
    let project = server.create_project(&ana, &vault).await;
    let db = server.raw_db().await;
    Items {
        server,
        ana,
        vault,
        project,
        db,
    }
}

/// The request that makes a change: method, path and JSON body.
struct ChangeRequest {
    method: Method,
    path: String,
    body: serde_json::Value,
}

impl Items {
    /// A new item in the state `change` starts from (not there yet, for a
    /// creation), and the request that makes it.
    async fn before(&self, change: Change) -> (ItemId, ChangeRequest) {
        let item = login_item("GitHub", "ana", "hunter2");
        let id = item.id();
        let items = format!("/v1/vaults/{}/items", self.vault.id);
        let one = format!("{items}/{id}");
        if let Change::Created = change {
            let (_, body) = self
                .server
                .create_item_body(&self.ana, &self.vault, &self.project, &item)
                .await;
            let request = ChangeRequest {
                method: Method::POST,
                path: items,
                body: serde_json::to_value(&body).expect("test"),
            };
            return (id, request);
        }
        let (key, _) = self
            .server
            .create_item(&self.ana, &self.vault, &self.project, &item)
            .await;
        if matches!(change, Change::Restored | Change::Purged) {
            let res = self
                .server
                .delete_auth(&self.ana, &one)
                .send()
                .await
                .expect("test");
            assert_eq!(res.status(), StatusCode::NO_CONTENT);
        }
        if let Change::VersionsPurged = change {
            let res = self
                .server
                .put_item(&self.ana, &self.vault, &self.project, &item, &key, 2)
                .await;
            assert_eq!(res.status(), StatusCode::OK);
        }
        let request = match change {
            Change::Created => unreachable!(),
            Change::Updated => {
                let body = self
                    .server
                    .update_item_body(&self.ana, &self.vault, &self.project, &item, &key, 2)
                    .await;
                ChangeRequest {
                    method: Method::PUT,
                    path: one,
                    body: serde_json::to_value(&body).expect("test"),
                }
            }
            Change::Trashed => ChangeRequest {
                method: Method::DELETE,
                path: one,
                body: serde_json::json!({}),
            },
            Change::Restored => ChangeRequest {
                method: Method::POST,
                path: format!("{one}/restore"),
                body: serde_json::json!({}),
            },
            Change::Purged => ChangeRequest {
                method: Method::POST,
                path: format!("{one}/purge"),
                body: serde_json::json!({}),
            },
            Change::VersionsPurged => ChangeRequest {
                method: Method::DELETE,
                path: format!("{one}/versions"),
                body: serde_json::json!({}),
            },
        };
        (id, request)
    }

    /// Sends `request` as Ana.
    fn send(
        &self,
        request: &ChangeRequest,
    ) -> impl std::future::Future<Output = reqwest::Result<reqwest::Response>> + use<> {
        let builder = match request.method {
            Method::POST => self.server.post_auth(&self.ana, &request.path),
            Method::PUT => self.server.put_auth(&self.ana, &request.path),
            Method::DELETE => self.server.delete_auth(&self.ana, &request.path),
            ref other => panic!("no change is a {other}"),
        };
        builder.json(&request.body).send()
    }

    /// Whether `change` of item `id` is stored, read straight from the
    /// database.
    async fn stored(&self, change: Change, id: ItemId) -> bool {
        let row: Option<(i64, Option<i64>, Option<i64>)> =
            sqlx::query_as("SELECT version, trashed_at, purged_at FROM items WHERE id = $1")
                .bind(id.to_string())
                .fetch_optional(&self.db)
                .await
                .expect("test");
        let versions: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM item_versions WHERE item_id = $1")
                .bind(id.to_string())
                .fetch_one(&self.db)
                .await
                .expect("test");
        match (change, row) {
            (_, None) => false,
            (Change::Created, Some(_)) => true,
            (Change::Updated, Some((version, _, _))) => version == 2,
            (Change::Trashed, Some((_, trashed, _))) => trashed.is_some(),
            (Change::Restored, Some((_, trashed, _))) => trashed.is_none(),
            (Change::Purged, Some((_, _, purged))) => purged.is_some(),
            (Change::VersionsPurged, Some(_)) => versions == 0,
        }
    }

    /// Ana's events of `change` for item `id`, read straight from the
    /// database.
    async fn logged(&self, change: Change, id: ItemId) -> Vec<AuditEvent> {
        let rows: Vec<Vec<u8>> = sqlx::query_scalar(
            "SELECT event FROM audit_events WHERE account_id = $1 AND action = $2 ORDER BY seq",
        )
        .bind(self.ana.account_id.to_string())
        .bind(change.action())
        .fetch_all(&self.db)
        .await
        .expect("test");
        rows.iter()
            .map(|bytes| serde_json::from_slice::<AuditEvent>(bytes).expect("test"))
            .filter(|e| e.item_id == Some(id))
            .collect()
    }
}

/// Each change the person makes to an item is never stored without its
/// event when the client goes away: the call is driven through the router
/// by hand and dropped as soon as the change reads as stored, before the
/// handler sees its commit (a try that finished first is made again on a
/// new item).
#[tokio::test]
async fn an_item_change_whose_client_goes_away_is_logged_with_it() {
    let w = items().await;
    for change in CHANGES {
        let id = until_dropped(async || {
            let (id, request) = w.before(change).await;
            let status = w
                .server
                .call_dropped_with(
                    request.method.clone(),
                    Some(&w.ana),
                    &request.path,
                    &request.body,
                    || w.stored(change, id),
                )
                .await;
            (status, id)
        })
        .await;
        let logged = w.logged(change, id).await;
        assert_eq!(logged.len(), 1, "{change:?}");
        let event = &logged[0];
        assert_eq!(event.actor, ActorKind::Person, "{change:?}");
        assert_eq!(event.device_id, Some(w.ana.device_id), "{change:?}");
        assert_eq!(event.vault_id, Some(w.vault.id), "{change:?}");
        assert_eq!(event.project_id, Some(w.project.id), "{change:?}");
        assert!(event.alerts.is_empty(), "{change:?}");
    }
}

/// A change whose event the log refuses is not made: neither the change
/// nor its event is stored, and the same request succeeds once the log
/// takes it.
#[tokio::test]
async fn an_item_change_that_cannot_be_logged_is_not_made() {
    let w = items().await;
    for change in CHANGES {
        let (id, request) = w.before(change).await;
        w.server.refuse_audit_action(change.action()).await;
        let res = w.send(&request).await.expect("test");
        assert_eq!(
            res.status(),
            StatusCode::INTERNAL_SERVER_ERROR,
            "{change:?}"
        );
        assert!(!w.stored(change, id).await, "{change:?}");
        assert!(w.logged(change, id).await.is_empty(), "{change:?}");
        w.server.allow_audit_action(change.action()).await;
        let res = w.send(&request).await.expect("test");
        assert!(res.status().is_success(), "{change:?}: {}", res.status());
        assert!(w.stored(change, id).await, "{change:?}");
        assert_eq!(w.logged(change, id).await.len(), 1, "{change:?}");
    }
}

impl Change {
    /// The table whose row the change writes: the item's, or the previous
    /// versions' for their purge.
    fn table(self) -> &'static str {
        match self {
            Change::VersionsPurged => "item_versions",
            _ => "items",
        }
    }
}

/// A change the database refuses to store logs no event: the event is
/// appended in the change's transaction, not in one of its own before it.
/// The same request then succeeds with one event.
#[tokio::test]
async fn an_item_change_that_cannot_be_stored_is_not_logged() {
    let w = items().await;
    for change in CHANGES {
        let (id, request) = w.before(change).await;
        w.server.refuse_writes(change.table()).await;
        let res = w.send(&request).await.expect("test");
        w.server.allow_writes(change.table()).await;
        assert_eq!(
            res.status(),
            StatusCode::INTERNAL_SERVER_ERROR,
            "{change:?}"
        );
        assert!(!w.stored(change, id).await, "{change:?}");
        assert!(w.logged(change, id).await.is_empty(), "{change:?}");
        let res = w.send(&request).await.expect("test");
        assert!(res.status().is_success(), "{change:?}: {}", res.status());
        assert!(w.stored(change, id).await, "{change:?}");
        assert_eq!(w.logged(change, id).await.len(), 1, "{change:?}");
    }
}

/// Postgres only: each change writes and logs in one transaction. Its
/// event is compared with the vault's row, which every change bumps in its
/// transaction, and with the item's row, except for the purge of its
/// versions, which only deletes rows.
#[tokio::test]
async fn an_item_change_and_its_event_share_one_transaction() {
    let w = items().await;
    if !w.server.is_postgres() {
        return;
    }
    for change in CHANGES {
        let (id, request) = w.before(change).await;
        let res = w.send(&request).await.expect("test");
        assert!(res.status().is_success(), "{change:?}: {}", res.status());
        let vault = w.vault.id.to_string();
        w.server
            .assert_written_with(&w.db, w.ana.account_id, "vaults", &vault, change.action())
            .await;
        if !matches!(change, Change::VersionsPurged) {
            w.server
                .assert_written_with(
                    &w.db,
                    w.ana.account_id,
                    "items",
                    &id.to_string(),
                    change.action(),
                )
                .await;
        }
    }
}

/// Postgres only: each change takes the account's lock before the vault's,
/// as every transaction that logs in itself does. One that took the vault
/// first would deadlock with a transaction holding the account and asking
/// for the vault.
#[tokio::test]
async fn an_item_change_locks_the_account_before_the_vault() {
    let w = items().await;
    if !w.server.is_postgres() {
        return;
    }
    for change in CHANGES {
        let (id, request) = w.before(change).await;
        let res = w
            .server
            .assert_account_locked_first(
                w.ana.account_id,
                "UPDATE vaults SET revision = revision WHERE id = $1",
                w.vault.id.to_string(),
                w.send(&request),
            )
            .await;
        assert!(res.status().is_success(), "{change:?}: {}", res.status());
        assert!(w.stored(change, id).await, "{change:?}");
    }
}
