//! The owner's signature over its shared vault key (ADR 0030 §1, spec
//! §8.3): required to create a vault, and uploaded once (TOFU) for vaults
//! created before it existed.

mod common;

use common::TestServer;
use common::client::Session;
use klav_core::crypto::context::VaultContext;
use klav_core::crypto::keys::VaultKey;
use klav_core::crypto::share::{share_vault_key, sign_vault_key, verify_vault_key};
use klav_core::crypto::sign::Signature;
use klav_core::ids::VaultId;
use klav_proto::Blob;
use klav_proto::sync::Changes;
use klav_proto::vault::{SignVaultKey, Vault};
use reqwest::StatusCode;
use serde_json::json;

async fn vault_info(server: &TestServer, s: &Session, id: VaultId) -> Vault {
    server
        .get_auth(s, &format!("/v1/vaults/{id}"))
        .send()
        .await
        .expect("request")
        .json()
        .await
        .expect("vault")
}

fn sig_bytes(vault: &Vault) -> [u8; 64] {
    vault
        .shared_key_signature
        .as_ref()
        .expect("signed")
        .as_bytes()
        .try_into()
        .expect("64 bytes")
}

#[tokio::test]
async fn creating_a_vault_requires_the_owner_signature() {
    let server = TestServer::start().await;
    let creds = server.signup("ana@example.com", "pw").await;
    let ana = server.login(&creds, "laptop").await;
    let id = VaultId::generate();
    let ctx = VaultContext {
        account: ana.account_id,
        vault: id,
    };
    let shared = share_vault_key(ana.identity.public(), &ctx, &VaultKey::generate()).unwrap();
    let meta = Blob::new(vec![7; 48]);

    // An old client (no signature field) gets 400.
    let res = server
        .post_auth(&ana, "/v1/vaults")
        .json(&json!({ "id": id, "meta": meta, "shared_key": Blob::new(shared.clone()) }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    // A signature over another vault ID does not verify.
    let other = VaultContext {
        vault: VaultId::generate(),
        ..ctx
    };
    let wrong = sign_vault_key(&ana.identity, &other, &shared).unwrap();
    let res = server
        .post_auth(&ana, "/v1/vaults")
        .json(&json!({
            "id": id, "meta": meta, "shared_key": Blob::new(shared.clone()),
            "shared_key_signature": Blob::new(wrong.to_bytes().to_vec()),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    let good = sign_vault_key(&ana.identity, &ctx, &shared).unwrap();
    let res = server
        .post_auth(&ana, "/v1/vaults")
        .json(&json!({
            "id": id, "meta": meta, "shared_key": Blob::new(shared.clone()),
            "shared_key_signature": Blob::new(good.to_bytes().to_vec()),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    let vault = vault_info(&server, &ana, id).await;
    verify_vault_key(
        ana.identity.public(),
        &ctx,
        vault.shared_key.as_bytes(),
        &Signature::from_bytes(sig_bytes(&vault)),
    )
    .expect("stored signature verifies");
}

#[tokio::test]
async fn an_unsigned_vault_is_signed_once() {
    let server = TestServer::start().await;
    let creds = server.signup("ana@example.com", "pw").await;
    let ana = server.login(&creds, "laptop").await;
    let bob_creds = server.signup("bob@example.com", "pw").await;
    let bob = server.login(&bob_creds, "laptop").await;
    let vault = server.create_vault(&ana).await;
    let ctx = VaultContext {
        account: ana.account_id,
        vault: vault.id,
    };
    let signed = vault_info(&server, &ana, vault.id).await;
    let signature = sig_bytes(&signed);

    // A vault from before the migration: no signature stored.
    let db = server.raw_db().await;
    sqlx::query("UPDATE vault_members SET shared_key_signature = NULL WHERE vault_id = $1")
        .bind(vault.id.to_string())
        .execute(&db)
        .await
        .unwrap();
    let legacy = vault_info(&server, &ana, vault.id).await;
    assert!(legacy.shared_key_signature.is_none());
    let path = format!("/v1/vaults/{}/signature", vault.id);
    let body = |sig: [u8; 64]| SignVaultKey {
        shared_key_signature: Blob::new(sig.to_vec()),
    };

    // Someone else's signature, or another account, is refused.
    let wrong = sign_vault_key(&bob.identity, &ctx, legacy.shared_key.as_bytes()).unwrap();
    let res = server
        .put_auth(&ana, &path)
        .json(&body(wrong.to_bytes()))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let res = server
        .put_auth(&bob, &path)
        .json(&body(signature))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);

    // The owner signs: the revision moves and `changes` re-sends the vault.
    let res = server
        .put_auth(&ana, &path)
        .json(&body(signature))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let after: Vault = res.json().await.unwrap();
    assert_eq!(after.revision, legacy.revision + 1);
    assert_eq!(sig_bytes(&after), signature);
    let changes: Changes = server
        .get_auth(
            &ana,
            &format!("/v1/vaults/{}/changes?since={}", vault.id, legacy.revision),
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        sig_bytes(changes.vault.as_ref().expect("vault record")),
        signature
    );

    // Retrying with the same bytes is a no-op.
    let res = server
        .put_auth(&ana, &path)
        .json(&body(signature))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        vault_info(&server, &ana, vault.id).await.revision,
        after.revision
    );

    // A different signature already stored is never replaced.
    sqlx::query("UPDATE vault_members SET shared_key_signature = $1 WHERE vault_id = $2")
        .bind(vec![9u8; 64])
        .bind(vault.id.to_string())
        .execute(&db)
        .await
        .unwrap();
    let res = server
        .put_auth(&ana, &path)
        .json(&body(signature))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CONFLICT);
}
