//! A malicious server against the vault-key signature (ADR 0030 §1, spec
//! §8.3) and against the local cache (a blob that does not decrypt never
//! replaces a good copy). The server's SQLite file is edited while the
//! server is stopped, as an operator with database access would.

mod common;

use std::future::Future;

use common::ServerProcess;
use klav_client::{
    Home, ItemFilter, LoginRequest, SignupRequest, Unlocked, login, signup, unlock_with_password,
};
use klav_core::crypto::context::VaultContext;
use klav_core::crypto::identity::{IdentityKeyPair, PublicIdentity};
use klav_core::crypto::kdf::MasterPassword;
use klav_core::crypto::keys::VaultKey;
use klav_core::crypto::secret_key::SecretKey;
use klav_core::crypto::share::{share_vault_key, sign_vault_key, verify_vault_key};
use klav_core::crypto::sign::Signature;
use klav_core::ids::{AccountId, VaultId};
use klav_core::model::item::{Item, ItemKind};
use klav_core::model::{Meta, seal_vault_meta};
use klav_proto::auth::DeviceKind;
use secrecy::ExposeSecret;
use sqlx::AnyPool;
use sqlx::any::AnyPoolOptions;

const PASSWORD: &str = "correct horse battery staple";

/// Runs `edit` on the server database with the server stopped.
async fn with_db<F, Fut, T>(server: &mut ServerProcess, edit: F) -> T
where
    F: FnOnce(AnyPool) -> Fut,
    Fut: Future<Output = T>,
{
    server.stop();
    sqlx::any::install_default_drivers();
    let url = format!("sqlite://{}", server.dir.path().join("klav.db").display());
    let pool = AnyPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .expect("open server db");
    let out = edit(pool.clone()).await;
    pool.close().await;
    server.restart();
    out
}

async fn exec(pool: &AnyPool, sql: &str, binds: &[&str]) {
    let mut q = sqlx::query(sqlx::AssertSqlSafe(sql.to_owned()));
    for b in binds {
        q = q.bind(b.to_string());
    }
    q.execute(pool).await.expect(sql);
}

/// Bumps the vault revision and re-sends its record, as any change would.
async fn bump_vault(pool: &AnyPool, vault: VaultId) {
    exec(
        pool,
        "UPDATE vaults SET revision = revision + 1, meta_revision = revision + 1 WHERE id = $1",
        &[&vault.to_string()],
    )
    .await;
}

async fn new_account(
    server: &ServerProcess,
    dir: &tempfile::TempDir,
    email: &str,
) -> (Unlocked, String) {
    let (u, kit) = signup(
        &Home::at(dir.path().join(email)),
        SignupRequest {
            server: server.url.clone(),
            email: email.into(),
            password: MasterPassword::new(PASSWORD),
            device_name: "laptop".into(),
            device_kind: DeviceKind::Cli,
            invite: None,
        },
    )
    .await
    .expect("sign-up");
    let secret = kit.secret_key().to_text().expose_secret().to_owned();
    (u, secret)
}

async fn new_device(
    server: &ServerProcess,
    dir: &tempfile::TempDir,
    name: &str,
    email: &str,
    secret: &str,
) -> Unlocked {
    login(
        &Home::at(dir.path().join(name)),
        LoginRequest {
            server: server.url.clone(),
            email: email.into(),
            password: MasterPassword::new(PASSWORD),
            secret_key: SecretKey::parse(secret).expect("secret key"),
            device_name: name.into(),
            device_kind: DeviceKind::Cli,
        },
    )
    .await
    .expect("login")
}

fn public(u: &Unlocked) -> PublicIdentity {
    PublicIdentity::decode(u.account().public_identity.as_bytes()).expect("identity")
}

/// Inserts a vault the server made up: a key it chose, sealed for
/// `member`'s identity, owned by `owner`, with `signature` (or none).
async fn inject_vault(
    pool: &AnyPool,
    owner: AccountId,
    member: AccountId,
    member_public: &PublicIdentity,
    signer: Option<&IdentityKeyPair>,
    name: &str,
) -> VaultId {
    let id = VaultId::generate();
    let ctx = VaultContext {
        account: owner,
        vault: id,
    };
    let key = VaultKey::generate();
    let shared = share_vault_key(member_public, &ctx, &key).expect("share");
    let meta = seal_vault_meta(&key, &ctx, 1, &Meta::new(name, None).expect("meta"));
    let sig = signer.map(|s| hex(&sign_vault_key(s, &ctx, &shared).expect("sign").to_bytes()));
    exec(
        pool,
        &format!(
            "INSERT INTO vaults (id, owner_account_id, revision, version, meta, meta_revision, \
             created_at, updated_at) VALUES ($1, $2, 1, 1, X'{}', 1, 0, 0)",
            hex(&meta)
        ),
        &[&id.to_string(), &owner.to_string()],
    )
    .await;
    exec(
        pool,
        &format!(
            "INSERT INTO vault_members (vault_id, member_type, member_id, role, shared_key, \
             shared_key_signature, revision, created_at, updated_at) \
             VALUES ($1, 'account', $2, 'owner', X'{}', {}, 1, 0, 0)",
            hex(&shared),
            sig.map_or("NULL".to_owned(), |s| format!("X'{s}'"))
        ),
        &[&id.to_string(), &member.to_string()],
    )
    .await;
    id
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

async fn stored_signature(server: &mut ServerProcess, vault: VaultId) -> Option<Vec<u8>> {
    with_db(server, |pool| async move {
        sqlx::query_scalar::<_, Option<Vec<u8>>>(
            "SELECT shared_key_signature FROM vault_members WHERE vault_id = $1",
        )
        .bind(vault.to_string())
        .fetch_one(&pool)
        .await
        .expect("stored signature")
    })
    .await
}

fn mentions(u: &Unlocked, what: &str) -> bool {
    u.warnings().iter().any(|w| w.contains(what))
}

#[tokio::test(flavor = "multi_thread")]
async fn a_vault_key_the_account_did_not_sign_is_refused() {
    let mut server = ServerProcess::start(900);
    let dir = tempfile::tempdir().unwrap();
    let (mut ana, _) = new_account(&server, &dir, "ana@example.com").await;
    let (bob, _) = new_account(&server, &dir, "bob@example.com").await;
    let ana_id = ana.account().account_id;
    let ana_public = public(&ana);
    let bob_id = bob.account().account_id;
    let server_keys = IdentityKeyPair::generate();

    let injected = with_db(&mut server, |pool| async move {
        // A key the server chose, sealed for Ana: unsigned, signed by
        // another identity, and owned by another account.
        vec![
            inject_vault(&pool, ana_id, ana_id, &ana_public, None, "Unsigned").await,
            inject_vault(
                &pool,
                ana_id,
                ana_id,
                &ana_public,
                Some(&server_keys),
                "Forged",
            )
            .await,
            inject_vault(
                &pool,
                bob_id,
                ana_id,
                &ana_public,
                Some(&server_keys),
                "Bobs",
            )
            .await,
        ]
    })
    .await;

    let report = ana.sync().await.expect("sync");
    assert_eq!(
        report.vaults_signed, 0,
        "nothing new is ever signed after the first sync"
    );
    let names: Vec<String> = ana.vaults().into_iter().map(|v| v.name).collect();
    assert_eq!(names, vec![klav_client::DEFAULT_VAULT.to_owned()]);
    for id in &injected {
        assert!(
            mentions(&ana, &format!("vault {id} is not used")),
            "{:?}",
            ana.warnings()
        );
        assert!(ana.find_vault(&id.to_string()).is_err());
    }
    // Still refused after a restart (from the persisted cache).
    drop(ana);
    let ana = unlock_with_password(
        &Home::at(dir.path().join("ana@example.com")),
        &MasterPassword::new(PASSWORD),
    )
    .unwrap();
    assert_eq!(ana.vaults().len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unsigned_vault_is_signed_once_and_a_signed_one_never_loses_it() {
    let mut server = ServerProcess::start(900);
    let dir = tempfile::tempdir().unwrap();
    let email = "ana@example.com";
    let (mut a, secret) = new_account(&server, &dir, email).await;
    let vault = a.find_vault("Personal").unwrap();
    let project = a.find_project(vault, "General").unwrap();
    let mut item = Item::from_template(ItemKind::Login, "GitHub").unwrap();
    item.add_url("https://github.com").unwrap();
    a.add_item(vault, project, &item).await.unwrap();
    let original = stored_signature(&mut server, vault)
        .await
        .expect("signed at creation");

    // The vault as it was before the migration: no signature.
    with_db(&mut server, |pool| async move {
        exec(
            &pool,
            "UPDATE vault_members SET shared_key_signature = NULL WHERE vault_id = $1",
            &[&vault.to_string()],
        )
        .await;
        bump_vault(&pool, vault).await;
    })
    .await;

    // Device A had seen it signed: the unsigned copy is refused and A keeps
    // its own (same revision, still usable).
    let before = a.revisions();
    a.sync().await.expect("sync");
    assert!(
        mentions(&a, "comes without a signature"),
        "{:?}",
        a.warnings()
    );
    assert_eq!(a.revisions(), before);
    assert_eq!(a.list_items(&ItemFilter::default()).unwrap().len(), 1);

    // A new device signs it, once, and says so.
    let mut b = new_device(&server, &dir, "phone", email, &secret).await;
    assert!(mentions(&b, "new to this device"), "{:?}", b.warnings());
    assert!(mentions(&b, "\"Personal\""), "{:?}", b.warnings());
    assert!(b.warnings().iter().any(|w| w.contains(&vault.to_string())));
    assert_eq!(b.list_items(&ItemFilter::default()).unwrap().len(), 1);
    let resigned = stored_signature(&mut server, vault)
        .await
        .expect("signed by B");
    // Ed25519 is deterministic: the same bytes A signed at creation.
    assert_eq!(resigned, original);
    verify_vault_key(
        &public(&b),
        &VaultContext {
            account: b.account().account_id,
            vault,
        },
        &stored_shared_key(&mut server, vault).await,
        &Signature::from_bytes(resigned.try_into().unwrap()),
    )
    .unwrap();
    assert_eq!(b.sync().await.unwrap().vaults_signed, 0, "only once");
    // A accepts the signed copy again and moves on.
    a.sync().await.expect("sync");
    assert!(!mentions(&a, "comes without a signature"));
    assert_ne!(a.revisions(), before);

    // Once signed on a device, an unsigned copy is refused there forever.
    with_db(&mut server, |pool| async move {
        exec(
            &pool,
            "UPDATE vault_members SET shared_key_signature = NULL WHERE vault_id = $1",
            &[&vault.to_string()],
        )
        .await;
        bump_vault(&pool, vault).await;
    })
    .await;
    let before = b.revisions();
    let report = b.sync().await.expect("sync");
    assert_eq!(report.vaults_signed, 0);
    assert!(
        mentions(&b, "comes without a signature"),
        "{:?}",
        b.warnings()
    );
    assert_eq!(b.revisions(), before);
    assert!(
        stored_signature(&mut server, vault).await.is_none(),
        "not re-signed"
    );
}

async fn stored_shared_key(server: &mut ServerProcess, vault: VaultId) -> Vec<u8> {
    with_db(server, |pool| async move {
        sqlx::query_scalar::<_, Vec<u8>>("SELECT shared_key FROM vault_members WHERE vault_id = $1")
            .bind(vault.to_string())
            .fetch_one(&pool)
            .await
            .expect("stored key")
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn a_blob_that_does_not_decrypt_never_replaces_a_good_copy() {
    let mut server = ServerProcess::start(900);
    let dir = tempfile::tempdir().unwrap();
    let (mut a, _) = new_account(&server, &dir, "ana@example.com").await;
    let vault = a.find_vault("Personal").unwrap();
    let project = a.find_project(vault, "General").unwrap();
    let github = a
        .add_item(
            vault,
            project,
            &Item::from_template(ItemKind::Login, "GitHub").unwrap(),
        )
        .await
        .unwrap();
    let gitlab = a
        .add_item(
            vault,
            project,
            &Item::from_template(ItemKind::Login, "GitLab").unwrap(),
        )
        .await
        .unwrap();
    let version = a.item_summary(github).unwrap().version;

    // Same version and revision: GitHub's overview becomes GitLab's bytes
    // (well-formed, but they do not open under GitHub's key and AAD).
    with_db(&mut server, |pool| async move {
        exec(
            &pool,
            "UPDATE items SET overview = (SELECT overview FROM items WHERE id = $1), \
             revision = (SELECT revision + 1 FROM vaults WHERE id = $2) WHERE id = $3",
            &[
                &gitlab.item.to_string(),
                &vault.to_string(),
                &github.item.to_string(),
            ],
        )
        .await;
        exec(
            &pool,
            "UPDATE vaults SET revision = revision + 1 WHERE id = $1",
            &[&vault.to_string()],
        )
        .await;
    })
    .await;

    let before = a.revisions();
    let report = a.sync().await.expect("sync");
    assert_eq!(report.vaults_updated, 0);
    assert!(
        mentions(&a, &format!("item {}", github.item)),
        "{:?}",
        a.warnings()
    );
    assert_eq!(a.revisions(), before, "the revision does not advance");
    let summary = a.item_summary(github).expect("still there");
    assert_eq!(summary.title, "GitHub");
    assert_eq!(summary.version, version);
    // Persisted: after a restart the good copy is still there.
    drop(a);
    let a = unlock_with_password(
        &Home::at(dir.path().join("ana@example.com")),
        &MasterPassword::new(PASSWORD),
    )
    .unwrap();
    assert_eq!(a.item_summary(github).unwrap().title, "GitHub");
}
