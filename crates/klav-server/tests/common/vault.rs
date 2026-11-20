//! Client-side helpers to build vaults, projects and items with `klav-core`
//! (keys generated, wrapped and shared locally; only ciphertext uploaded).

use klav_core::crypto::context::{ItemContext, ProjectContext, VaultContext};
use klav_core::crypto::keys::{ItemKey, ProjectKey, VaultKey};
use klav_core::crypto::random;
use klav_core::crypto::share::{open_shared_vault_key, share_vault_key, sign_vault_key};
use klav_core::crypto::wrap::{
    unwrap_item_key, unwrap_project_key, wrap_item_key, wrap_project_key,
};
use klav_core::ids::{AccountId, ItemId, ProjectId, VaultId};
use klav_core::model::item::{FieldValue, Item, ItemKind, SealedItem, open_item, seal_item};
use klav_proto::Blob;
use klav_proto::vault::{
    CreateItem, CreateProject, CreateVault, Item as WireItem, ProjectList, UpdateItem, Vault,
};
use reqwest::StatusCode;

use super::TestServer;
use super::client::Session;

pub struct TestVault {
    pub id: VaultId,
    pub owner: AccountId,
    pub key: VaultKey,
}

pub struct TestProject {
    pub id: ProjectId,
    pub key: ProjectKey,
}

impl TestVault {
    pub fn project_ctx(&self, project: ProjectId) -> ProjectContext {
        ProjectContext {
            account: self.owner,
            vault: self.id,
            project,
        }
    }

    pub fn item_ctx(&self, project: ProjectId, item: ItemId) -> ItemContext {
        ItemContext {
            account: self.owner,
            vault: self.id,
            project,
            item,
        }
    }
}

/// A login item with a secret password.
pub fn login_item(title: &str, username: &str, password: &str) -> Item {
    let mut item = Item::from_template(ItemKind::Login, title).expect("template");
    item.field_mut("username")
        .expect("username")
        .set_value(username)
        .expect("set");
    item.field_mut("password")
        .expect("password")
        .set_value(password)
        .expect("set");
    item
}

/// Encrypted form of an item for upload.
pub struct Upload {
    pub wrapped_key: Vec<u8>,
    pub sealed: SealedItem,
}

pub fn seal(
    vault: &TestVault,
    project: &TestProject,
    item: &Item,
    key: &ItemKey,
    version: u64,
) -> Upload {
    let ctx = vault.item_ctx(project.id, item.id());
    Upload {
        wrapped_key: wrap_item_key(&project.key, &ctx, key),
        sealed: seal_item(key, &ctx, version, item),
    }
}

impl TestServer {
    pub async fn create_vault(&self, session: &Session) -> TestVault {
        let id = VaultId::generate();
        let key = VaultKey::generate();
        let ctx = VaultContext {
            account: session.account_id,
            vault: id,
        };
        let shared = share_vault_key(session.identity.public(), &ctx, &key).expect("share");
        let signature = sign_vault_key(&session.identity, &ctx, &shared).expect("sign");
        let res = self
            .post_auth(session, "/v1/vaults")
            .json(&CreateVault {
                id,
                // Vault metadata format arrives with the CLI; random bytes here.
                meta: Blob::new(random::array::<48>().to_vec()),
                shared_key: Blob::new(shared),
                shared_key_signature: Blob::new(signature.to_bytes().to_vec()),
            })
            .send()
            .await
            .expect("request");
        assert_eq!(res.status(), StatusCode::CREATED);
        TestVault {
            id,
            owner: session.account_id,
            key,
        }
    }

    /// Opens the vault key from the server's copy, like a second device would.
    pub async fn open_vault(&self, session: &Session, id: VaultId) -> TestVault {
        let vault: Vault = self
            .get_auth(session, &format!("/v1/vaults/{id}"))
            .send()
            .await
            .expect("request")
            .json()
            .await
            .expect("vault");
        let ctx = VaultContext {
            account: vault.owner_account_id,
            vault: id,
        };
        TestVault {
            id,
            owner: vault.owner_account_id,
            key: open_shared_vault_key(&session.identity, &ctx, vault.shared_key.as_bytes())
                .expect("vault key opens"),
        }
    }

    pub async fn create_project(&self, session: &Session, vault: &TestVault) -> TestProject {
        let id = ProjectId::generate();
        let key = ProjectKey::generate();
        let wrapped = wrap_project_key(&vault.key, &vault.project_ctx(id), &key);
        let res = self
            .post_auth(session, &format!("/v1/vaults/{}/projects", vault.id))
            .json(&CreateProject {
                id,
                wrapped_key: Blob::new(wrapped),
                meta: Blob::new(random::array::<32>().to_vec()),
            })
            .send()
            .await
            .expect("request");
        assert_eq!(res.status(), StatusCode::CREATED);
        TestProject { id, key }
    }

    pub fn open_project(vault: &TestVault, id: ProjectId, wrapped: &[u8]) -> TestProject {
        TestProject {
            id,
            key: unwrap_project_key(&vault.key, &vault.project_ctx(id), wrapped)
                .expect("project key opens"),
        }
    }

    /// Current version of `project`, as a synced client knows it (what item
    /// writes send as `project_version`); 1 for a session that cannot list
    /// the vault's projects.
    pub async fn project_version(
        &self,
        session: &Session,
        vault: &TestVault,
        project: &TestProject,
    ) -> u64 {
        let res = self
            .get_auth(session, &format!("/v1/vaults/{}/projects", vault.id))
            .send()
            .await
            .expect("request");
        if !res.status().is_success() {
            return 1;
        }
        let list: ProjectList = res.json().await.expect("projects");
        list.projects
            .iter()
            .find(|p| p.id == project.id)
            .map_or(1, |p| p.version)
    }

    /// Creates `item` at version 1. Returns the item key.
    pub async fn create_item(
        &self,
        session: &Session,
        vault: &TestVault,
        project: &TestProject,
        item: &Item,
    ) -> (ItemKey, WireItem) {
        let (key, body) = self.create_item_body(session, vault, project, item).await;
        let res = self
            .post_auth(session, &format!("/v1/vaults/{}/items", vault.id))
            .json(&body)
            .send()
            .await
            .expect("request");
        assert_eq!(res.status(), StatusCode::CREATED);
        (key, res.json().await.expect("item"))
    }

    /// The body that creates `item` at version 1, and its new item key.
    pub async fn create_item_body(
        &self,
        session: &Session,
        vault: &TestVault,
        project: &TestProject,
        item: &Item,
    ) -> (ItemKey, CreateItem) {
        let key = ItemKey::generate();
        let upload = seal(vault, project, item, &key, 1);
        let project_version = self.project_version(session, vault, project).await;
        let body = CreateItem {
            id: item.id(),
            project_id: project.id,
            version: 1,
            wrapped_key: Blob::new(upload.wrapped_key),
            project_version,
            overview: Blob::new(upload.sealed.overview),
            details: Blob::new(upload.sealed.details),
        };
        (key, body)
    }

    /// Writes `item` as `version` (expects `current + 1`). Returns the response.
    pub async fn put_item(
        &self,
        session: &Session,
        vault: &TestVault,
        project: &TestProject,
        item: &Item,
        key: &ItemKey,
        version: u64,
    ) -> reqwest::Response {
        let body = self
            .update_item_body(session, vault, project, item, key, version)
            .await;
        self.put_auth(
            session,
            &format!("/v1/vaults/{}/items/{}", vault.id, item.id()),
        )
        .json(&body)
        .send()
        .await
        .expect("request")
    }

    /// The body that writes `item` as `version`.
    pub async fn update_item_body(
        &self,
        session: &Session,
        vault: &TestVault,
        project: &TestProject,
        item: &Item,
        key: &ItemKey,
        version: u64,
    ) -> UpdateItem {
        let upload = seal(vault, project, item, key, version);
        let project_version = self.project_version(session, vault, project).await;
        UpdateItem {
            version,
            wrapped_key: Blob::new(upload.wrapped_key),
            project_version,
            overview: Blob::new(upload.sealed.overview),
            details: Blob::new(upload.sealed.details),
            attachment_keys: None,
        }
    }
}

/// Decrypts an item downloaded from the server (key unwrapped from the
/// server's copy, version taken from the sync metadata).
pub fn decrypt(vault: &TestVault, project: &TestProject, wire: &WireItem) -> Item {
    let ctx = vault.item_ctx(project.id, wire.id);
    let key = unwrap_item_key(
        &project.key,
        &ctx,
        wire.wrapped_key.as_ref().expect("wrapped key").as_bytes(),
    )
    .expect("item key opens");
    open_item(
        &key,
        &ctx,
        wire.version,
        &SealedItem {
            overview: wire
                .overview
                .as_ref()
                .expect("overview")
                .as_bytes()
                .to_vec(),
            details: wire.details.as_ref().expect("details").as_bytes().to_vec(),
        },
    )
    .expect("item decrypts")
}

/// The value of a field, for assertions.
pub fn field(item: &Item, name: &str) -> String {
    match item.field(name).expect("field").value() {
        FieldValue::Plain(s) => s.clone(),
        FieldValue::Secret(s) => s.expose().to_owned(),
        FieldValue::File(id) => id.to_string(),
    }
}

impl TestServer {
    /// Declares an attachment of `content` (any bytes, sealed with a fresh
    /// key: the server cannot tell) on `item` and uploads it in one chunk.
    /// With `complete`, publishes it too. Returns its ID.
    pub async fn upload_attachment(
        &self,
        session: &Session,
        vault: &TestVault,
        project: &TestProject,
        item: ItemId,
        content: &[u8],
        complete: bool,
    ) -> klav_core::ids::AttachmentId {
        use klav_core::crypto::attachment::encrypt_attachment_bytes;
        use klav_core::crypto::keys::AttachmentKey;
        use klav_core::crypto::wrap::wrap_attachment_key;
        let id = klav_core::ids::AttachmentId::generate();
        let ctx = vault.item_ctx(project.id, item).attachment(id);
        let key = AttachmentKey::generate();
        let ciphertext = encrypt_attachment_bytes(&key, &ctx, content);
        let res = self
            .post_auth(
                session,
                &format!("/v1/vaults/{}/items/{item}/attachments", vault.id),
            )
            .json(&klav_proto::sync::CreateAttachment {
                item_version: None,
                id,
                size: ciphertext.len() as u64,
                wrapped_key: Blob::new(wrap_attachment_key(&ItemKey::generate(), &ctx, &key)),
            })
            .send()
            .await
            .expect("request");
        assert_eq!(res.status(), StatusCode::CREATED, "declare attachment");
        let base = format!("/v1/vaults/{}/attachments/{id}", vault.id);
        let res = self
            .put_auth(session, &format!("{base}/content?offset=0"))
            .body(ciphertext)
            .send()
            .await
            .expect("request");
        assert_eq!(res.status(), StatusCode::OK, "upload chunk");
        if complete {
            let res = self
                .post_auth(session, &format!("{base}/complete"))
                .send()
                .await
                .expect("request");
            assert_eq!(res.status(), StatusCode::OK, "complete");
        }
        id
    }
}
