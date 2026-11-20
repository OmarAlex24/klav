//! What a device persists (see the table in the crate docs).

use std::collections::{BTreeMap, BTreeSet};

use klav_core::crypto::keys::LocalKey;
use klav_core::crypto::local::{LocalContext, open_local_data, seal_local_data};
use klav_core::ids::{AccountId, AgentId, DeviceId, ItemId, ProjectId, VaultId};
use klav_proto::Blob;
use klav_proto::auth::SessionTokens;
use klav_proto::sync::Attachment;
use klav_proto::vault::{Item, Project, Vault};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::{ClientError, ClientResult};
use crate::home::{Home, write_private};

/// Version of the local file formats.
const STATE_VERSION: u32 = 1;
/// Local data purpose of the session tokens.
const PURPOSE_SESSION: &str = "session";
/// Local data purpose of the sync cache.
const PURPOSE_CACHE: &str = "cache";

/// `account.json`: everything needed to unlock this device. Contains no
/// plaintext secrets (the keyset and the local identity are ciphertext).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountFile {
    /// Format version (1).
    pub v: u32,
    /// Server base URL.
    pub server: String,
    /// Normalised account e-mail.
    pub email: String,
    /// Account ID.
    pub account_id: AccountId,
    /// This device, as registered with the server.
    pub device_id: DeviceId,
    /// This device's name.
    pub device_name: String,
    /// Argon2id parameters of the account (kind `0x06`), checked against
    /// the production floor at every unlock.
    pub kdf_params: Blob,
    /// Public identity (kind `0x05`).
    pub public_identity: Blob,
    /// Identity private keys sealed with the KEK (kind `0x01`).
    pub sealed_identity: Blob,
    /// Identity private keys sealed with the local key (kind `0x40`), for
    /// biometric unlock.
    pub local_identity: Blob,
}

impl AccountFile {
    /// The local key context of this device.
    pub fn local_context(&self) -> LocalContext {
        LocalContext {
            account: self.account_id,
            device: self.device_id,
        }
    }

    pub(crate) fn load(home: &Home) -> ClientResult<Self> {
        let bytes = match std::fs::read(home.account_path()) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(ClientError::NotLoggedIn);
            }
            Err(e) => return Err(e.into()),
        };
        let file: Self = serde_json::from_slice(&bytes)
            .map_err(|e| ClientError::Corrupt(format!("account.json: {e}")))?;
        if file.v != STATE_VERSION {
            return Err(ClientError::Corrupt(format!(
                "account.json version {}",
                file.v
            )));
        }
        Ok(file)
    }

    pub(crate) fn save(&self, home: &Home) -> ClientResult<()> {
        home.ensure()?;
        let mut bytes = serde_json::to_vec_pretty(self).expect("serializes");
        bytes.push(b'\n');
        write_private(&home.account_path(), &bytes)
    }
}

/// Session tokens, kept sealed on disk and zeroized in memory.
pub(crate) struct Tokens {
    pub(crate) access: Zeroizing<String>,
    pub(crate) access_expires_at: i64,
    pub(crate) refresh: Zeroizing<String>,
    pub(crate) refresh_expires_at: i64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTokens {
    v: u32,
    access_token: String,
    access_expires_at: i64,
    refresh_token: String,
    refresh_expires_at: i64,
}

impl Drop for RawTokens {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.access_token.zeroize();
        self.refresh_token.zeroize();
    }
}

impl Tokens {
    pub(crate) fn from_wire(mut wire: SessionTokens) -> Self {
        Self {
            access: Zeroizing::new(std::mem::take(&mut wire.access_token)),
            access_expires_at: wire.access_expires_at,
            refresh: Zeroizing::new(std::mem::take(&mut wire.refresh_token)),
            refresh_expires_at: wire.refresh_expires_at,
        }
    }

    pub(crate) fn save(&self, home: &Home, key: &LocalKey, ctx: &LocalContext) -> ClientResult<()> {
        let raw = RawTokens {
            v: STATE_VERSION,
            access_token: self.access.to_string(),
            access_expires_at: self.access_expires_at,
            refresh_token: self.refresh.to_string(),
            refresh_expires_at: self.refresh_expires_at,
        };
        let json = Zeroizing::new(serde_json::to_vec(&raw).expect("serializes"));
        let blob = seal_local_data(key, ctx, PURPOSE_SESSION, &json)?;
        write_private(&home.session_path(), &blob)
    }

    pub(crate) fn load(home: &Home, key: &LocalKey, ctx: &LocalContext) -> ClientResult<Self> {
        let blob = match std::fs::read(home.session_path()) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(ClientError::SessionExpired);
            }
            Err(e) => return Err(e.into()),
        };
        let json = open_local_data(key, ctx, PURPOSE_SESSION, &blob)
            .map_err(|_| ClientError::Corrupt("session.bin does not open".into()))?;
        let mut raw: RawTokens = serde_json::from_slice(&json)
            .map_err(|_| ClientError::Corrupt("session.bin".into()))?;
        Ok(Self {
            access: Zeroizing::new(std::mem::take(&mut raw.access_token)),
            access_expires_at: raw.access_expires_at,
            refresh: Zeroizing::new(std::mem::take(&mut raw.refresh_token)),
            refresh_expires_at: raw.refresh_expires_at,
        })
    }
}

/// One synced vault, exactly as the server sent it (ciphertext).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CachedVault {
    /// Highest revision applied.
    pub(crate) revision: u64,
    pub(crate) vault: Option<Vault>,
    pub(crate) projects: BTreeMap<ProjectId, Project>,
    pub(crate) items: BTreeMap<ItemId, Item>,
    pub(crate) attachments: BTreeMap<klav_core::ids::AttachmentId, Attachment>,
    /// For each item whose current version an agent wrote: the last
    /// version the person wrote, whose hosts are the confirmed ones (ADR
    /// 0030 §7). Ciphertext, as the server sent it.
    #[serde(default)]
    pub(crate) person_versions: BTreeMap<ItemId, CachedPersonVersion>,
    /// The server stopped listing this vault (purged, or access lost). The
    /// copy stays, read-only, until the person drops it with
    /// `klav sync --reset-cache` (T14).
    #[serde(default)]
    pub(crate) unlisted: bool,
}

/// The last version of an item the person wrote, fetched for the current
/// version `for_version` (an agent's).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CachedPersonVersion {
    /// The item's current version when this was fetched: a newer one
    /// means fetching again.
    pub(crate) for_version: u64,
    /// The project's version when this was fetched: a rotation rewraps
    /// the stored versions with the new key, so a newer one means fetching
    /// again. `0` in caches from before it was kept: fetched again once.
    #[serde(default)]
    pub(crate) project_version: u64,
    /// `None`: the server keeps no version of the person (the agent
    /// created the item): no host is confirmed.
    pub(crate) found: Option<PersonVersionBlobs>,
}

/// Enough of a version to read its sites.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PersonVersionBlobs {
    pub(crate) version: u64,
    pub(crate) project_id: ProjectId,
    pub(crate) wrapped_key: Blob,
    pub(crate) overview: Blob,
}

/// High-water marks (threat T7): the highest revision and versions this
/// device has ever seen. They survive the removal of a vault or an item, so
/// an old copy coming back is still detected.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Marks {
    pub(crate) vault_revisions: BTreeMap<VaultId, u64>,
    pub(crate) vault_versions: BTreeMap<VaultId, u64>,
    pub(crate) project_versions: BTreeMap<ProjectId, u64>,
    pub(crate) item_versions: BTreeMap<ItemId, u64>,
    pub(crate) purged_items: BTreeSet<ItemId>,
    pub(crate) deleted_projects: BTreeSet<ProjectId>,
    /// Vaults this device has seen with a valid signature over their key
    /// (spec §8.3): an unsigned copy is refused from then on.
    #[serde(default)]
    pub(crate) signed_vaults: BTreeSet<VaultId>,
    /// This device already signed every unsigned vault it had (TOFU, ADR
    /// 0030 §1). From then on any unsigned vault is refused.
    #[serde(default)]
    pub(crate) vault_keys_signed: bool,
}

impl Marks {
    /// How many marks this device keeps (see [`crate::sync::MAX_MARKS`]).
    pub(crate) fn len(&self) -> usize {
        self.vault_revisions.len()
            + self.vault_versions.len()
            + self.project_versions.len()
            + self.item_versions.len()
            + self.purged_items.len()
            + self.deleted_projects.len()
            + self.signed_vaults.len()
    }
}

/// An agent this account revoked from this device, and how far the
/// rotation of its projects went (ADR 0014 §7).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Revocation {
    /// The projects whose keys it held, as its signed grant said when it
    /// was revoked (a later answer from the server cannot shrink them).
    pub(crate) projects: BTreeSet<ProjectId>,
    /// The projects whose key a `--rotate` already rotated: a retry does
    /// not rotate them again.
    #[serde(default)]
    pub(crate) rotated: BTreeSet<ProjectId>,
}

/// `cache.bin` contents.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Cache {
    pub(crate) v: u32,
    pub(crate) vaults: BTreeMap<VaultId, CachedVault>,
    pub(crate) marks: Marks,
    /// Agents this account revoked: never re-granted after a rotation,
    /// whatever status the server reports for them.
    #[serde(default)]
    pub(crate) revocations: BTreeMap<AgentId, Revocation>,
    /// Read, never written: where builds of ADR 0037's layer 3 before
    /// review finding 5 kept the account's deletion. It moves to
    /// `deletion.bin` when the account opens ([`crate::auth`]), and
    /// `cache.bin` is written again without it. **Never add a field that
    /// is written here:** an older klav, `klavd` or app refuses a
    /// `cache.bin` with a field it does not know (`deny_unknown_fields`),
    /// and cannot unlock. Keep new state in its own sealed file.
    #[serde(default, rename = "deletion", skip_serializing)]
    pub(crate) legacy_deletion: Option<klav_proto::auth::AccountDeletion>,
}

impl Cache {
    pub(crate) fn empty() -> Self {
        Self {
            v: STATE_VERSION,
            ..Self::default()
        }
    }

    /// The cache without any vault and without the rollback marks (T7),
    /// keeping what must never be forgotten: the agents this account
    /// revoked (never re-granted) and which vault keys were signed (an
    /// unsigned copy stays refused, ADR 0030 §1). For a device whose marks
    /// a server poisoned, or that keeps copies of vaults the server no
    /// longer lists.
    pub(crate) fn reset(&self) -> Self {
        Self {
            v: STATE_VERSION,
            vaults: BTreeMap::new(),
            marks: Marks {
                signed_vaults: self.marks.signed_vaults.clone(),
                vault_keys_signed: self.marks.vault_keys_signed,
                ..Marks::default()
            },
            revocations: self.revocations.clone(),
            legacy_deletion: None,
        }
    }

    pub(crate) fn load(home: &Home, key: &LocalKey, ctx: &LocalContext) -> ClientResult<Self> {
        let blob = match std::fs::read(home.cache_path()) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::empty()),
            Err(e) => return Err(e.into()),
        };
        let json = open_local_data(key, ctx, PURPOSE_CACHE, &blob)
            .map_err(|_| ClientError::Corrupt("cache.bin does not open".into()))?;
        let cache: Self = serde_json::from_slice(&json)
            .map_err(|e| ClientError::Corrupt(format!("cache.bin: {e}")))?;
        if cache.v != STATE_VERSION {
            return Err(ClientError::Corrupt(format!(
                "cache.bin version {}",
                cache.v
            )));
        }
        Ok(cache)
    }

    pub(crate) fn save(&self, home: &Home, key: &LocalKey, ctx: &LocalContext) -> ClientResult<()> {
        let json = serde_json::to_vec(self).expect("serializes");
        let blob = seal_local_data(key, ctx, PURPOSE_CACHE, &json)?;
        write_private(&home.cache_path(), &blob)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Review finding 5 (ADR 0037): an older klav, `klavd` or app reads
    /// `cache.bin` with `deny_unknown_fields`, and a field it does not know
    /// stops it from unlocking. These are the top-level fields every
    /// reader since the format's version 1 knows: a new one goes in a file
    /// of its own (`deletion.bin`, `audit-chain.bin`).
    #[test]
    fn cache_bin_keeps_only_the_fields_older_readers_know() {
        let mut cache = Cache::empty();
        cache
            .vaults
            .insert(VaultId::generate(), CachedVault::default());
        cache
            .revocations
            .insert(AgentId::generate(), Revocation::default());
        cache.legacy_deletion = Some(klav_proto::auth::AccountDeletion {
            requested_at: 1,
            delete_at: 2,
            device_id: DeviceId::generate(),
            device_name: "laptop".into(),
        });
        let json: serde_json::Value = serde_json::to_value(&cache).unwrap();
        let fields: BTreeSet<&str> = json
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            fields,
            BTreeSet::from(["v", "vaults", "marks", "revocations"])
        );
    }

    /// A `cache.bin` written by layer 3 before that fix still opens, and
    /// hands its deletion over (`open_rest` moves it to `deletion.bin`).
    #[test]
    fn a_cache_with_the_old_deletion_field_still_opens() {
        let device = DeviceId::generate();
        let json = serde_json::json!({
            "v": 1,
            "vaults": {},
            "marks": Marks::default(),
            "revocations": {},
            "deletion": {
                "requested_at": 1,
                "delete_at": 2,
                "device_id": device,
                "device_name": "laptop",
            },
        });
        let cache: Cache = serde_json::from_value(json).unwrap();
        assert_eq!(cache.legacy_deletion.unwrap().device_id, device);
    }
}
