//! An opened grant: the verified payload and the project and item keys it
//! carries.

use std::collections::HashMap;

use klav_client::{ClientError, ClientResult};
use klav_core::crypto::agent::open_grant_labels;
use klav_core::crypto::context::{ItemContext, ProjectContext};
use klav_core::crypto::identity::IdentityKeyPair;
use klav_core::crypto::keys::{ItemKey, ProjectKey};
use klav_core::crypto::share::{open_shared_item_key, open_shared_project_key};
use klav_core::ids::{ItemId, ProjectId};
use klav_proto::agent::{GrantLabels, GrantPayload};

/// A shared project with its key, opened with the agent's identity.
pub struct GrantedKey {
    /// Where the project lives (part of every AAD inside it).
    pub ctx: ProjectContext,
    /// The project key.
    pub key: ProjectKey,
    /// Vault and project names as the person saw them when approving.
    pub labels: GrantLabels,
}

/// An item shared one by one (kind `0x23`, ADR 0036 §2), with its key.
pub struct GrantedItemKey {
    /// Where the item lives (part of every AAD inside it).
    pub ctx: ItemContext,
    /// The item key.
    pub key: ItemKey,
}

/// A grant whose signature checked out, with its keys opened.
pub struct OpenGrant {
    /// The signed payload.
    pub payload: GrantPayload,
    /// Project keys by project.
    pub keys: HashMap<ProjectId, GrantedKey>,
    /// Item keys by item (a per-item grant). Only `proxy` uses them; the
    /// item is never listed with the project's.
    pub items: HashMap<ItemId, GrantedItemKey>,
}

impl OpenGrant {
    pub(crate) fn open(identity: &IdentityKeyPair, payload: GrantPayload) -> ClientResult<Self> {
        let mut keys = HashMap::new();
        for project in &payload.projects {
            let ctx = ProjectContext {
                account: project.owner_account_id,
                vault: project.vault_id,
                project: project.project_id,
            };
            let key = open_shared_project_key(identity, &ctx, project.shared_key.as_bytes())?;
            let labels =
                open_grant_labels(&key, &ctx, payload.agent_id, project.labels.as_bytes())?;
            let labels: GrantLabels = serde_json::from_slice(&labels)
                .map_err(|e| ClientError::Corrupt(format!("grant labels: {e}")))?;
            keys.insert(project.project_id, GrantedKey { ctx, key, labels });
        }
        let mut items = HashMap::new();
        for item in &payload.items {
            let ctx = ItemContext {
                account: item.owner_account_id,
                vault: item.vault_id,
                project: item.project_id,
                item: item.item_id,
            };
            let key = open_shared_item_key(identity, &ctx, item.shared_key.as_bytes())?;
            items.insert(item.item_id, GrantedItemKey { ctx, key });
        }
        Ok(Self {
            payload,
            keys,
            items,
        })
    }
}
