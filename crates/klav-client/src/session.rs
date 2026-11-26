//! An unlocked account: decrypted keys in memory, an authenticated session
//! and the synced cache.

use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use klav_core::crypto::context::{ItemContext, ProjectContext, VaultContext};
use klav_core::crypto::identity::IdentityKeyPair;
use klav_core::crypto::keys::{ItemKey, LocalKey, ProjectKey, VaultKey};
use klav_core::crypto::local::LocalContext;
use klav_core::crypto::share::{open_shared_vault_key, share_vault_key, sign_vault_key};
use klav_core::crypto::wrap::{
    unwrap_item_key, unwrap_project_key, wrap_item_key, wrap_project_key,
};
use klav_core::ids::{AccountId, AgentId, ItemId, ProjectId, VaultId, looks_like_id};
use klav_core::model::history::is_system_project;
use klav_core::model::item::{FieldKind, FieldValue, ItemKind, Overview};
use klav_core::model::record::{PasswordRecord, is_recorded};
use klav_core::model::{
    Catalog, Item, Meta, ModelError, Named, Reference, SealedItem, SecretValue, open_item,
    open_overview, open_project_meta, open_vault_meta, resolve_field, seal_item, seal_project_meta,
    seal_vault_meta,
};
use klav_core::totp::Totp;
use klav_proto::Blob;
use klav_proto::auth::{RefreshRequest, SessionTokens};
use klav_proto::sync::{Changes, SyncState};
use klav_proto::vault::{
    CreateItem, CreateProject, CreateVault, Item as WireItem, ItemHistory, ItemVersion,
    SignVaultKey, UpdateItem,
};
use reqwest::{Method, StatusCode};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::api::{self, Api, Body};
use crate::error::{ClientError, ClientResult};
use crate::home::Home;
use crate::state::{
    AccountFile, Cache, CachedPersonVersion, CachedVault, Marks, PersonVersionBlobs, Tokens,
};
use crate::sync::{self, SyncReport};
use crate::vault_key::{self, KeyTrust};

/// Refresh the access token when it has less than this left (ms).
const REFRESH_MARGIN_MS: i64 = 30_000;
/// The token exchange of [`Unlocked::refresh`], serialised with other
/// processes (CLI, daemon) through a file lock: refresh tokens are
/// single-use. Saves what it gets before returning.
async fn exchange_tokens(
    api: Api,
    home: Home,
    key: std::sync::Arc<LocalKey>,
    ctx: LocalContext,
    presented: zeroize::Zeroizing<String>,
    expires_at: i64,
) -> ClientResult<Tokens> {
    let _lock = home.lock()?;
    if let Ok(on_disk) = Tokens::load(&home, &key, &ctx)
        && *on_disk.refresh != *presented
    {
        // Someone else refreshed while we waited.
        return Ok(on_disk);
    }
    if expires_at <= now_ms() {
        return Err(ClientError::SessionExpired);
    }
    let res = api
        .send(
            Method::POST,
            "/v1/auth/refresh",
            None,
            Some(&RefreshRequest {
                refresh_token: presented.to_string(),
            }),
        )
        .await?;
    if res.status() == StatusCode::UNAUTHORIZED {
        return Err(ClientError::SessionExpired);
    }
    let wire: SessionTokens = api::json(res).await?;
    let tokens = Tokens::from_wire(wire);
    tokens.save(&home, &key, &ctx)?;
    Ok(tokens)
}

/// Stored versions read to fill a password record for the first time.
const MAX_BACKFILL_VERSIONS: usize = 100;

pub(crate) fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

/// A `409` other than a stale item version: an item ID that already
/// exists, or a `project_version` that is no longer the current one.
fn is_conflict(e: &ClientError) -> bool {
    matches!(e, ClientError::Api { status: 409, .. })
}

pub(crate) struct VaultEntry {
    pub(crate) owner: AccountId,
    pub(crate) key: VaultKey,
    pub(crate) meta: Meta,
    pub(crate) deleted: bool,
}

pub(crate) struct ProjectEntry {
    pub(crate) vault: VaultId,
    pub(crate) key: ProjectKey,
    pub(crate) meta: Meta,
    /// Version of the project row: item writes send it as
    /// `project_version` (the key they wrap with).
    pub(crate) version: u64,
}

struct ItemEntry {
    vault: VaultId,
    project: ProjectId,
    version: u64,
    updated_at: i64,
    trashed: bool,
    overview: Overview,
    /// Whether the details hold a filled one-time password field. Worked
    /// out (by opening the details) the first time a list asks for codes,
    /// and kept across syncs while the item keeps its version.
    has_code: OnceLock<bool>,
    /// The agent that wrote the current version (ADR 0030 §7).
    author: Option<AgentId>,
    /// URLs whose host the person confirmed: the only ones that fill.
    confirmed_urls: Vec<String>,
    /// URLs an agent added, waiting for the person.
    pending_urls: Vec<String>,
}

/// The URLs of an item split into confirmed and pending (ADR 0030 §7): with
/// the person as the author of the current version, all are confirmed;
/// with an agent, only those whose host is among the URLs of the last
/// version the person wrote (`person`; none if unknown: fails closed).
fn split_sites(
    urls: &[String],
    author: Option<AgentId>,
    person: Option<&[String]>,
) -> (Vec<String>, Vec<String>) {
    if author.is_none() {
        return (urls.to_vec(), Vec::new());
    }
    let person = person.unwrap_or_default();
    urls.iter().cloned().partition(|u| {
        klav_core::site::item_host(u).is_some_and(|h| klav_core::site::host_matches(&h, person))
    })
}

/// The warning for an item whose overview does not open. A kind this build
/// does not know was written by a newer Klav: not tampering, so it says so
/// (ADR 0032 §1); the item is skipped all the same, and this build can
/// neither edit nor overwrite it.
fn item_open_warning(item_id: ItemId, error: &ClientError) -> String {
    match error {
        ClientError::Model(ModelError::UnknownKind(kind)) => {
            format!("item {item_id} is of an unknown item kind ({kind:?}); update Klav to see it")
        }
        e => format!("item {item_id} does not decrypt: {e}"),
    }
}

/// The URLs of the person's last version of an item, if it opens.
fn person_urls(
    account_id: AccountId,
    vault_id: VaultId,
    item_id: ItemId,
    current_version: u64,
    cached: Option<&CachedPersonVersion>,
    projects: &[(ProjectId, ProjectEntry)],
) -> Option<Vec<String>> {
    let cached = cached.filter(|c| c.for_version == current_version)?;
    let Some(found) = &cached.found else {
        return Some(Vec::new());
    };
    let (_, project) = projects.iter().find(|(id, _)| *id == found.project_id)?;
    let ictx = ItemContext {
        account: account_id,
        vault: vault_id,
        project: found.project_id,
        item: item_id,
    };
    let ikey = unwrap_item_key(&project.key, &ictx, found.wrapped_key.as_bytes()).ok()?;
    open_overview(&ikey, &ictx, found.version, found.overview.as_bytes())
        .ok()
        .map(|o| o.urls)
}

impl ItemEntry {
    /// Klav's own items (the generator history) and anything in a system
    /// project: never listed, never found by title.
    fn is_system(&self) -> bool {
        self.overview.kind.is_system() || is_system_project(self.vault, self.project)
    }
}

/// Everything that opens in one cached vault.
struct OpenedVault {
    vault: VaultEntry,
    projects: Vec<(ProjectId, ProjectEntry)>,
    items: Vec<(ItemId, ItemEntry)>,
    /// Projects and items that did not open (skipped, never shown).
    pub(crate) warnings: Vec<String>,
}

/// Opens a cached vault: checks who chose its key (ADR 0030 §1), then
/// decrypts the key, the names and the overviews. `queued`: the passkey
/// outbox (ADR 0020 §11), whose items go over the cached ones. `Ok(None)`
/// if the cache has no vault record yet; `Err` (a warning) if the vault
/// must not be used.
fn open_vault(
    identity: &IdentityKeyPair,
    account_id: AccountId,
    vault_id: VaultId,
    cached: &CachedVault,
    marks: &Marks,
    queued: &HashMap<ItemId, (VaultId, WireItem)>,
) -> Result<Option<OpenedVault>, String> {
    let Some(vault) = &cached.vault else {
        return Ok(None);
    };
    let refuse = |why: String| format!("vault {vault_id} is not used: {why}");
    vault_key::check(identity.public(), account_id, vault_id, vault, marks).map_err(refuse)?;
    // The context is always this account's, never what the server says.
    let vctx = VaultContext {
        account: account_id,
        vault: vault_id,
    };
    let (key, meta) = open_shared_vault_key(identity, &vctx, vault.shared_key.as_bytes())
        .map_err(ClientError::from)
        .and_then(|key| {
            let meta = open_vault_meta(&key, &vctx, vault.version, vault.meta.as_bytes())?;
            Ok((key, meta))
        })
        .map_err(|e| format!("vault {vault_id} does not decrypt: {e}"))?;
    let mut warnings = Vec::new();
    let mut projects = Vec::new();
    for (project_id, project) in &cached.projects {
        let pctx = ProjectContext {
            account: account_id,
            vault: vault_id,
            project: *project_id,
        };
        let opened = (|| -> ClientResult<_> {
            let wrapped = project
                .wrapped_key
                .as_ref()
                .ok_or_else(|| ClientError::Corrupt("project without key".into()))?;
            let pkey = unwrap_project_key(&key, &pctx, wrapped.as_bytes())?;
            let meta = open_project_meta(
                &pkey,
                &pctx,
                project.version,
                project.meta.as_ref().map_or(&[][..], Blob::as_bytes),
            )?;
            Ok((pkey, meta))
        })();
        match opened {
            Ok((pkey, pmeta)) => projects.push((
                *project_id,
                ProjectEntry {
                    vault: vault_id,
                    key: pkey,
                    meta: pmeta,
                    version: project.version,
                },
            )),
            Err(e) => warnings.push(format!("project {project_id} does not decrypt: {e}")),
        }
    }
    let mut items = Vec::new();
    let queued_here = queued
        .iter()
        .filter(|(_, (v, _))| *v == vault_id)
        .map(|(id, (_, w))| (id, w));
    let merged = cached
        .items
        .iter()
        .filter(|(id, _)| !queued.contains_key(id))
        .chain(queued_here);
    for (item_id, item) in merged {
        let Some((_, project)) = projects.iter().find(|(id, _)| *id == item.project_id) else {
            warnings.push(format!("item {item_id} is in an unknown project"));
            continue;
        };
        let ictx = ItemContext {
            account: account_id,
            vault: vault_id,
            project: item.project_id,
            item: *item_id,
        };
        let opened = (|| -> ClientResult<Overview> {
            let wrapped = item
                .wrapped_key
                .as_ref()
                .ok_or_else(|| ClientError::Corrupt("item without key".into()))?;
            let ikey = unwrap_item_key(&project.key, &ictx, wrapped.as_bytes())?;
            let overview = item
                .overview
                .as_ref()
                .ok_or_else(|| ClientError::Corrupt("item without overview".into()))?;
            Ok(open_overview(
                &ikey,
                &ictx,
                item.version,
                overview.as_bytes(),
            )?)
        })();
        match opened {
            Ok(overview) => {
                let person = item.author_agent_id.and_then(|_| {
                    person_urls(
                        account_id,
                        vault_id,
                        *item_id,
                        item.version,
                        cached.person_versions.get(item_id),
                        &projects,
                    )
                });
                let (confirmed_urls, pending_urls) =
                    split_sites(&overview.urls, item.author_agent_id, person.as_deref());
                items.push((
                    *item_id,
                    ItemEntry {
                        vault: vault_id,
                        project: item.project_id,
                        version: item.version,
                        updated_at: item.updated_at,
                        trashed: item.trashed_at.is_some(),
                        overview,
                        author: item.author_agent_id,
                        confirmed_urls,
                        pending_urls,
                        has_code: OnceLock::new(),
                    },
                ));
            }
            Err(e) => warnings.push(item_open_warning(*item_id, &e)),
        }
    }
    Ok(Some(OpenedVault {
        vault: VaultEntry {
            owner: account_id,
            key,
            meta,
            deleted: vault.deleted_at.is_some(),
        },
        projects,
        items,
        warnings,
    }))
}

/// The one-time notice of the vaults this device signed (ADR 0030 §1).
/// Names the vaults so the person can spot one that is not theirs.
fn signed_notice(signed: &[(VaultId, String, bool)]) -> String {
    let list = |cached: bool| {
        signed
            .iter()
            .filter(|(_, _, c)| *c == cached)
            .map(|(id, name, _)| format!("{name:?} ({id})"))
            .collect::<Vec<_>>()
    };
    let mut notice = String::from(
        "signed the key of vaults created before vault keys were signed (this happens once)",
    );
    let known = list(true);
    if !known.is_empty() {
        notice.push_str(&format!(
            "; matched this device's copy: {}",
            known.join(", ")
        ));
    }
    let new = list(false);
    if !new.is_empty() {
        notice.push_str(&format!(
            "; new to this device, trusted as the server listed them: {}",
            new.join(", ")
        ));
    }
    notice
}

/// A vault as shown to the user.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct VaultSummary {
    /// ID.
    pub id: VaultId,
    /// Name.
    pub name: String,
    /// In the trash.
    pub deleted: bool,
    /// Number of live items.
    pub items: usize,
}

/// A project as shown to the user.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct ProjectSummary {
    /// ID.
    pub id: ProjectId,
    /// Vault ID.
    pub vault_id: VaultId,
    /// Vault name.
    pub vault: String,
    /// Name.
    pub name: String,
    /// Linked Git repositories in normalized `host/owner/repo` form (ADR 0032 §2).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub repos: Vec<String>,
}

/// A change to an item's password record that is not a field edit (the
/// assisted change, ADR 0022 §5), made by [`Unlocked::put_item_with`] after
/// the values the edit replaces went to the history.
pub(crate) enum RecordEdit {
    /// Store a new pending value (a stale one goes to the history).
    Begin(klav_core::model::record::PendingValue),
    /// The pending value became current: the caller already wrote it into
    /// its field, so the record only forgets it.
    Confirm,
    /// The pending value goes to the history, unconfirmed.
    Cancel,
}

impl RecordEdit {
    fn apply(self, record: &mut PasswordRecord, now: i64) {
        match self {
            Self::Begin(pending) => {
                record.begin_pending(pending, now);
            }
            Self::Confirm => {
                record.take_pending();
            }
            Self::Cancel => {
                record.cancel_pending(now);
            }
        }
    }
}

/// Where an item lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, serde::Deserialize)]
pub struct ItemLocation {
    /// Vault.
    pub vault: VaultId,
    /// Project.
    pub project: ProjectId,
    /// Item.
    pub item: ItemId,
}

/// Item metadata (the overview): never contains secrets.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct ItemSummary {
    /// Item ID.
    pub id: ItemId,
    /// `klav://vault/project/item` (by name).
    pub reference: String,
    /// Vault ID.
    pub vault_id: VaultId,
    /// Vault name.
    pub vault: String,
    /// Project ID.
    pub project_id: ProjectId,
    /// Project name.
    pub project: String,
    /// Type.
    pub kind: ItemKind,
    /// Title.
    pub title: String,
    /// Username, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// URLs.
    pub urls: Vec<String>,
    /// Tags.
    pub tags: Vec<String>,
    /// Version.
    pub version: u64,
    /// Last change (Unix ms).
    pub updated_at: i64,
    /// In the trash.
    pub trashed: bool,
    /// The login's passkey, without secrets (ADR 0020).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passkey: Option<klav_core::model::PasskeySummary>,
    /// The URLs whose site the person confirmed (ADR 0030 §7): the only
    /// ones autofill, suggestions and agents' fills use.
    #[serde(default)]
    pub confirmed_urls: Vec<String>,
    /// URLs an agent added that the person has not confirmed yet: shown as
    /// «Sites added by <agent>», with confirm and remove.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pending_urls: Vec<String>,
    /// The agent that wrote the current version, if one did.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author_agent_id: Option<AgentId>,
    /// The environments whose references protect this item, or that it is
    /// itself (a protected environment), by name (ADR 0032 §3.1): copying
    /// or showing it asks for presence every time. Empty: not protected.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub protected_by: Vec<String>,
}

/// Which items to list.
#[derive(Debug, Clone, Default, Serialize, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ItemFilter {
    /// Vault name or ID.
    pub vault: Option<String>,
    /// Project name or ID.
    pub project: Option<String>,
    /// Item type.
    pub kind: Option<ItemKind>,
    /// Any of these types (together with `kind`). Empty: every type.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub kinds: Vec<ItemKind>,
    /// Only items with a filled one-time password field, of any type
    /// (the «Codes» view). Lists metadata only, never the code.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub codes: bool,
    /// Tag.
    pub tag: Option<String>,
    /// Text to search in titles, usernames, URLs and tags.
    pub query: Option<String>,
    /// List the trash instead of live items.
    pub trash: bool,
}

impl ItemFilter {
    /// Whether the type filters (`kind` and `kinds`) let `kind` through.
    pub fn wants_kind(&self, kind: ItemKind) -> bool {
        if self.kind.is_none() && self.kinds.is_empty() {
            return true;
        }
        self.kind == Some(kind) || self.kinds.contains(&kind)
    }
}

/// A resolved `klav://` field reference.
pub struct Resolved {
    /// Canonical reference (by name).
    pub reference: String,
    /// Field type.
    pub kind: FieldKind,
    /// The value. Secret fields stay in a zeroizing [`SecretValue`].
    pub value: SecretValue,
}

/// An unlocked account. Holds keys in memory (zeroized on drop).
pub struct Unlocked {
    pub(crate) home: Home,
    pub(crate) account: AccountFile,
    pub(crate) ctx: LocalContext,
    /// Shared with a token refresh in flight (see [`Self::refresh`]).
    pub(crate) local_key: std::sync::Arc<LocalKey>,
    pub(crate) identity: IdentityKeyPair,
    pub(crate) api: Api,
    pub(crate) tokens: Tokens,
    pub(crate) cache: Cache,
    pub(crate) vaults: HashMap<VaultId, VaultEntry>,
    pub(crate) projects: HashMap<ProjectId, ProjectEntry>,
    items: HashMap<ItemId, ItemEntry>,
    pub(crate) warnings: Vec<String>,
    /// Moves every time a sync changes the cache (see [`Unlocked::generation`]).
    generation: u64,
    /// Signed agent requests already used for an assisted change or a
    /// passkey (agent and nonce, with when; ADR 0022 §5): each one proves
    /// one step, once.
    pub(crate) seen_proofs: Vec<(AgentId, [u8; 16], i64)>,
    /// Registrations queued without network (the iOS passkey outbox, ADR
    /// 0020 §11), merged over the cache by item until the app uploads them.
    queued: HashMap<ItemId, (VaultId, WireItem)>,
    /// While the outbox is being sent, the cache shows the server's versions only.
    pub(crate) outbox_paused: bool,
    /// How this device reaches Klav Cloud's proxy (ADR 0051).
    pub(crate) hosted: crate::hosted_proxy::HostedConfig,
    /// Pauses of the account's agents in effect, as the last sync (or this
    /// device's own decision) left them, each checked against the
    /// account's signature (ADR 0033 §7).
    pub(crate) agent_pauses: Vec<klav_proto::agent::AgentPause>,
    /// This device's copy of the audit chain (ADR 0033 §8.4), once read
    /// from `audit-chain.bin` or downloaded: the views ask the server only
    /// for what is new.
    pub(crate) audit_chain: Option<Vec<crate::audit::Entry>>,
    /// What this device knows of the account's deletion (ADR 0037 §3), as
    /// [`crate::deletion::DELETION_FILE`] keeps it.
    pub(crate) deletion: crate::deletion::DeletionMarker,
    /// What protected environments protect (ADR 0032 §3.1), as
    /// [`crate::environments::PROTECTION_FILE`] keeps it.
    pub(crate) protection: crate::environments::Protection,
    /// An environment being created protected: not in this device's view
    /// yet, but its grants must already name it (ADR 0032 §4.3).
    pub(crate) pending_protection: Option<ItemLocation>,
}

/// A sync planned under the account and fetched without it
/// ([`Unlocked::sync_plan`]): the server's answers, not yet checked or
/// applied. Holds an access token: no `Debug`.
pub struct SyncPlan {
    api: Api,
    access: zeroize::Zeroizing<String>,
    generation: u64,
    revisions: std::collections::BTreeMap<VaultId, u64>,
}

/// What [`SyncPlan::fetch`] brought back, for [`Unlocked::finish_sync`].
pub struct SyncFetch {
    generation: u64,
    state: SyncState,
    changes: Vec<(VaultId, u64, u64, Changes)>,
}

impl SyncPlan {
    /// `GET /v1/sync` and the `changes` it calls for, with the access token
    /// taken at planning time. `None` when the server refuses that token
    /// (expired or rotated meanwhile): sync with the account instead
    /// ([`Unlocked::sync`]), which refreshes it.
    pub async fn fetch(self) -> ClientResult<Option<SyncFetch>> {
        let Some(state) = self.get::<SyncState>("/v1/sync").await? else {
            return Ok(None);
        };
        // The marks are checked on apply; the fan-out is bounded here.
        sync::check_shape(&state)?;
        let mut changes = Vec::new();
        for (vault, since, listed) in sync::pending_from(&self.revisions, &state) {
            let path = format!("/v1/vaults/{vault}/changes?since={since}");
            let Some(delta) = self.get::<Changes>(&path).await? else {
                return Ok(None);
            };
            changes.push((vault, since, listed, delta));
        }
        Ok(Some(SyncFetch {
            generation: self.generation,
            state,
            changes,
        }))
    }

    async fn get<R: DeserializeOwned>(&self, path: &str) -> ClientResult<Option<R>> {
        let res = self
            .api
            .send_body(Method::GET, path, Some(&self.access), &Body::Empty)
            .await?;
        if res.status() == StatusCode::UNAUTHORIZED {
            return Ok(None);
        }
        api::json(res).await.map(Some)
    }
}

impl Unlocked {
    pub(crate) fn assemble(
        home: Home,
        account: AccountFile,
        local_key: LocalKey,
        identity: IdentityKeyPair,
        api: Api,
        tokens: Tokens,
        cache: Cache,
    ) -> Self {
        let ctx = account.local_context();
        let mut unlocked = Self {
            home,
            account,
            ctx,
            local_key: std::sync::Arc::new(local_key),
            identity,
            api,
            tokens,
            cache,
            vaults: HashMap::new(),
            projects: HashMap::new(),
            items: HashMap::new(),
            warnings: Vec::new(),
            generation: 0,
            seen_proofs: Vec::new(),
            queued: HashMap::new(),
            outbox_paused: false,
            hosted: crate::hosted_proxy::HostedConfig::from_env(),
            agent_pauses: Vec::new(),
            audit_chain: None,
            deletion: crate::deletion::DeletionMarker::default(),
            protection: crate::environments::Protection::default(),
            pending_protection: None,
        };
        unlocked.protection = crate::environments::Protection::load(
            &unlocked.home,
            &unlocked.local_key,
            &unlocked.ctx,
        );
        unlocked.rebuild();
        // Environments in the cache that the set has never heard of: the
        // file is missing (deleted, or never written) and nothing is known
        // until a refresh works, so it fails closed (ADR 0032 §3.1). A
        // refresh records every environment it sees.
        let entries = unlocked.environment_entries();
        if !entries.is_empty()
            && entries
                .iter()
                .all(|e| !unlocked.protection.contributions.contains_key(&e.loc.item))
        {
            unlocked.protection.unreadable = true;
        }
        unlocked
    }

    /// The account file of this device.
    pub fn account(&self) -> &AccountFile {
        &self.account
    }

    /// The state directory.
    pub fn home(&self) -> &Home {
        &self.home
    }

    /// The local key (for biometric enrolment; never leaves `klav-core`
    /// except wrapped by the platform keystore).
    pub fn local_key(&self) -> &LocalKey {
        &self.local_key
    }

    /// Problems found while decrypting the cache (entries that failed to
    /// open are skipped, never shown half-decrypted).
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    /// Highest revision applied per vault.
    pub fn revisions(&self) -> Vec<(VaultId, u64)> {
        self.cache
            .vaults
            .iter()
            .map(|(id, v)| (*id, v.revision))
            .collect()
    }

    // ------------------------------------------------------------ session --

    /// Rotates the session. Serialised with other processes (CLI, daemon)
    /// through a file lock: refresh tokens are single-use and presenting a
    /// rotated one revokes the whole session.
    ///
    /// The exchange runs in its own task, which saves the new tokens
    /// itself: a caller that is cancelled half-way (`klavd` locking while a
    /// request waits on the network) must not lose the rotated token, or
    /// the next refresh would present the spent one and the server would
    /// revoke the session.
    async fn refresh(&mut self) -> ClientResult<()> {
        let task = tokio::spawn(exchange_tokens(
            self.api.clone(),
            self.home.clone(),
            std::sync::Arc::clone(&self.local_key),
            self.ctx,
            zeroize::Zeroizing::new(self.tokens.refresh.to_string()),
            self.tokens.refresh_expires_at,
        ));
        let tokens = task
            .await
            .map_err(|e| ClientError::Network(format!("session refresh: {e}")))??;
        self.tokens = tokens;
        Ok(())
    }

    /// Sends a request with the session, refreshing it when needed. A
    /// session the server no longer knows is [`ClientError::SessionExpired`],
    /// or [`ClientError::AccountDeleted`] when this device knew the date of
    /// the account's deletion and it passed (ADR 0037 §3).
    pub(crate) async fn authed(
        &mut self,
        method: Method,
        path: &str,
        body: &Body<'_>,
    ) -> ClientResult<reqwest::Response> {
        match self.authed_once(method, path, body).await {
            Err(ClientError::SessionExpired) => Err(self.session_ended()),
            other => other,
        }
    }

    /// What a session the server refused means on this device: the
    /// account was deleted if this device knew the date and it passed,
    /// else the session expired or was revoked. A device that was offline
    /// the whole waiting period never learned the date, and sees the
    /// latter (ADR 0037 §3). The deletion is written down, so the device
    /// still knows after a restart without network.
    pub(crate) fn session_ended(&mut self) -> ClientError {
        let Some(at) = self.deletion_due() else {
            return ClientError::SessionExpired;
        };
        if !self.deletion.deleted {
            self.deletion.deleted = true;
            // Best effort: the next refused request writes it again.
            let _ = self.deletion.save(&self.home, &self.local_key, &self.ctx);
            self.generation += 1;
        }
        ClientError::AccountDeleted(at)
    }

    async fn authed_once(
        &mut self,
        method: Method,
        path: &str,
        body: &Body<'_>,
    ) -> ClientResult<reqwest::Response> {
        if self.access_expiring() {
            self.refresh().await?;
        }
        let res = self
            .api
            .send_body(method.clone(), path, Some(&self.tokens.access), body)
            .await?;
        if res.status() != StatusCode::UNAUTHORIZED {
            return Ok(res);
        }
        self.refresh().await?;
        let res = self
            .api
            .send_body(method, path, Some(&self.tokens.access), body)
            .await?;
        if res.status() == StatusCode::UNAUTHORIZED {
            return Err(ClientError::SessionExpired);
        }
        Ok(res)
    }

    pub(crate) async fn get<R: DeserializeOwned>(&mut self, path: &str) -> ClientResult<R> {
        let res = self.authed(Method::GET, path, &Body::Empty).await?;
        api::json(res).await
    }

    pub(crate) async fn send_json<B: Serialize, R: DeserializeOwned>(
        &mut self,
        method: Method,
        path: &str,
        body: &B,
    ) -> ClientResult<R> {
        let res = self.authed(method, path, &Body::json(body)?).await?;
        api::json(res).await
    }

    /// Ends the session on the server (logout) and forgets the tokens.
    pub async fn logout(mut self) -> ClientResult<()> {
        let res = self
            .authed(Method::POST, "/v1/auth/logout", &Body::Empty)
            .await?;
        api::empty(res).await?;
        let _ = std::fs::remove_file(self.home.session_path());
        Ok(())
    }

    // --------------------------------------------------------------- sync --

    /// Pulls every change from the server. Refuses (and changes nothing) if
    /// the server shows an older state than this device has seen (T7).
    ///
    /// A vault whose changes would stop opening something that opens now
    /// (a vault, project or item replaced by a blob that does not decrypt,
    /// or a signed vault key that comes back unsigned) keeps its previous
    /// copy and revision, with a warning: the server cannot hide what this
    /// device already has. Then every vault created before the vault-key
    /// signature is signed, once per device (ADR 0030 §1).
    pub async fn sync(&mut self) -> ClientResult<SyncReport> {
        let state: SyncState = self.get("/v1/sync").await?;
        sync::check_listing(&self.cache, &state)?;
        let mut changes = Vec::new();
        for (vault, since, listed) in sync::pending(&self.cache, &state) {
            let delta: Changes = self
                .get(&format!("/v1/vaults/{vault}/changes?since={since}"))
                .await?;
            changes.push((vault, since, listed, delta));
        }
        self.commit_sync(&state, changes).await
    }

    /// Counts the syncs that changed the cache. A [`SyncPlan`] made at one
    /// generation is applied only at that same generation.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Plans a sync to fetch without holding the account (klavd's
    /// stale-while-revalidate, ADR 0026). `None` when the access token is
    /// about to expire: refresh it first ([`Unlocked::refresh_session`]).
    pub fn sync_plan(&self) -> Option<SyncPlan> {
        let (api, access) = self.bearer()?;
        Some(SyncPlan {
            api,
            access,
            generation: self.generation,
            revisions: sync::revisions(&self.cache),
        })
    }

    /// The server and the access token, for a request made without the
    /// session (see [`SyncPlan`]); `None` when the token is about to expire.
    pub(crate) fn bearer(&self) -> Option<(Api, zeroize::Zeroizing<String>)> {
        if self.access_expiring() {
            return None;
        }
        Some((self.api.clone(), self.tokens.access.clone()))
    }

    /// Applies a fetched sync with the same checks as [`Unlocked::sync`]
    /// (T7). `Ok(None)` when another sync changed the cache since the plan:
    /// the fetch is dropped and nothing changes.
    pub async fn finish_sync(&mut self, fetched: SyncFetch) -> ClientResult<Option<SyncReport>> {
        if fetched.generation != self.generation {
            return Ok(None);
        }
        self.commit_sync(&fetched.state, fetched.changes)
            .await
            .map(Some)
    }

    /// The access token has less than `REFRESH_MARGIN_MS` left.
    fn access_expiring(&self) -> bool {
        self.tokens
            .access_expires_at
            .saturating_sub(REFRESH_MARGIN_MS)
            <= now_ms()
    }

    /// Refreshes the session if the access token is about to expire.
    pub async fn refresh_session(&mut self) -> ClientResult<()> {
        if self.access_expiring() {
            match self.refresh().await {
                Err(ClientError::SessionExpired) => return Err(self.session_ended()),
                other => other?,
            }
        }
        Ok(())
    }

    /// Checks a sync against the high-water marks, applies it to a copy of
    /// the cache, signs the vault keys still unsigned (ADR 0030 §1) and
    /// saves it; on any error the cache is left untouched. Changes to a
    /// vault that would hide something this device opens now are dropped,
    /// with a notice. It talks to the server only when there is a vault key
    /// left to sign, or an agent-written item whose last version by the
    /// person is not cached yet (ADR 0030 §7).
    async fn commit_sync(
        &mut self,
        state: &SyncState,
        changes: Vec<(VaultId, u64, u64, Changes)>,
    ) -> ClientResult<SyncReport> {
        sync::check_listing(&self.cache, state)?;
        let mut cache = self.cache.clone();
        let mut report = SyncReport::default();
        let mut notices = Vec::new();
        for (vault, since, listed, delta) in changes {
            let before = cache.clone();
            let items = sync::apply(&mut cache, vault, since, listed, delta)?;
            if let Some(why) = self.regression(&cache, vault) {
                cache = before;
                notices.push(format!(
                    "vault {vault}: the server sent changes that do not decrypt ({why}); \
                     keeping this device's copy"
                ));
                continue;
            }
            report.items_received += items;
            report.vaults_updated += 1;
        }
        report.vaults_removed = sync::mark_unlisted(&mut cache, state);
        self.agent_pauses = self.checked_pauses(&state.agent_pauses, &mut notices);
        // The deletion the person asked for, or none since it was canceled
        // (ADR 0037 §3). Never a reason to delete anything here (T165). The
        // server answered this session, so the account is not gone.
        let deletion = crate::deletion::DeletionMarker {
            asked: state.deletion.clone(),
            deleted: false,
        };
        let deletion_changed = self.deletion != deletion;
        self.fetch_person_versions(&mut cache, &mut notices).await;
        let signed = self.sign_vault_keys(&mut cache, &mut notices).await?;
        report.vaults_signed = signed.len();
        if !signed.is_empty() {
            notices.push(signed_notice(&signed));
        }
        cache.save(&self.home, &self.local_key, &self.ctx)?;
        if deletion_changed {
            deletion.save(&self.home, &self.local_key, &self.ctx)?;
            self.deletion = deletion;
        }
        self.cache = cache;
        self.rebuild();
        // What protected environments protect, from the person's versions
        // (ADR 0032 §3.1). Never fails the sync: what it cannot learn
        // leaves the vault asking for presence every time.
        self.refresh_protection(&mut notices).await;
        self.warnings.extend(notices);
        if report != SyncReport::default() || deletion_changed {
            self.generation += 1;
        }
        Ok(report)
    }

    /// Records the deletion of the account this device just asked for, or
    /// that it just canceled (`None`), as the next sync would (ADR 0037
    /// §3).
    pub(crate) fn remember_deletion(
        &mut self,
        deletion: Option<klav_proto::auth::AccountDeletion>,
    ) -> ClientResult<()> {
        let marker = crate::deletion::DeletionMarker {
            asked: deletion,
            deleted: false,
        };
        if self.deletion == marker {
            return Ok(());
        }
        // Shown at once whether or not it is written down: the server
        // already did it.
        self.deletion = marker;
        self.generation += 1;
        self.deletion.save(&self.home, &self.local_key, &self.ctx)
    }

    /// Refuses writes to a vault the server no longer lists: its copy is
    /// read-only.
    pub(crate) fn writable(&self, vault: VaultId) -> ClientResult<()> {
        if self.cache.vaults.get(&vault).is_some_and(|v| v.unlisted) {
            return Err(ClientError::Invalid(format!(
                "vault {vault} is no longer listed by the server; this device's copy is read-only"
            )));
        }
        Ok(())
    }

    /// Forgets every cached vault and the rollback marks (T7), keeping the
    /// revoked agents and which vault keys were signed, then syncs from
    /// scratch. The way out for a device whose marks a hostile server
    /// poisoned (every sync refused as a rollback), or that keeps copies of
    /// vaults the server no longer lists. Until the next sync this device
    /// detects no rollback older than now: the caller warns the person.
    pub async fn reset_cache(&mut self) -> ClientResult<SyncReport> {
        let reset = self.cache.reset();
        reset.save(&self.home, &self.local_key, &self.ctx)?;
        self.cache = reset;
        self.rebuild();
        self.sync().await
    }

    /// For every item whose current version an agent wrote, the last
    /// version the person wrote (ADR 0030 §7), fetched once per current
    /// version. One that cannot be fetched leaves the agent's hosts
    /// pending (fails closed), with a notice.
    async fn fetch_person_versions(&mut self, cache: &mut Cache, notices: &mut Vec<String>) {
        let mut wanted = Vec::new();
        for (vault_id, cached) in &mut cache.vaults {
            if cached.unlisted {
                continue;
            }
            let items = &cached.items;
            cached.person_versions.retain(|id, _| {
                items
                    .get(id)
                    .is_some_and(|i| i.author_agent_id.is_some() && i.purged_at.is_none())
            });
            for (item_id, item) in items {
                // The project key wraps the stored copy: after a rotation it
                // is fetched again, rewrapped.
                let project_version = cached
                    .projects
                    .get(&item.project_id)
                    .map_or(0, |p| p.version);
                if item.author_agent_id.is_some()
                    && item.purged_at.is_none()
                    && cached.person_versions.get(item_id).is_none_or(|p| {
                        p.for_version != item.version || p.project_version != project_version
                    })
                {
                    wanted.push((*vault_id, *item_id, item.version, project_version));
                }
            }
        }
        for (vault_id, item_id, for_version, project_version) in wanted {
            match self.person_version(vault_id, item_id).await {
                Ok(found) => {
                    if let Some(cached) = cache.vaults.get_mut(&vault_id) {
                        cached.person_versions.insert(
                            item_id,
                            CachedPersonVersion {
                                for_version,
                                project_version,
                                found,
                            },
                        );
                    }
                }
                Err(e) => notices.push(format!(
                    "item {item_id}: the sites an agent added stay pending ({e})"
                )),
            }
        }
    }

    /// The last stored version of `item` the person wrote, if the server
    /// keeps one.
    async fn person_version(
        &mut self,
        vault_id: VaultId,
        item_id: ItemId,
    ) -> ClientResult<Option<PersonVersionBlobs>> {
        let history: ItemHistory = self
            .get(&format!("/v1/vaults/{vault_id}/items/{item_id}/versions"))
            .await?;
        let Some(wanted) = history
            .versions
            .iter()
            .find(|v| v.author_agent_id.is_none())
            .map(|v| v.version)
        else {
            return Ok(None);
        };
        let got: ItemVersion = self
            .get(&format!(
                "/v1/vaults/{vault_id}/items/{item_id}/versions/{wanted}"
            ))
            .await?;
        if got.item_id != item_id || got.version != wanted || got.author_agent_id.is_some() {
            return Err(ClientError::Security(format!(
                "the server answered another version than {wanted} of item {item_id}"
            )));
        }
        Ok(Some(PersonVersionBlobs {
            version: got.version,
            project_id: got.project_id,
            wrapped_key: got.wrapped_key,
            overview: got.overview,
        }))
    }

    /// Why applying the changes of `vault` to `cache` would hide something
    /// this device can open now.
    fn regression(&self, cache: &Cache, vault_id: VaultId) -> Option<String> {
        if !self.vaults.contains_key(&vault_id) {
            return None;
        }
        let cached = cache.vaults.get(&vault_id)?;
        let opened = match open_vault(
            &self.identity,
            self.account.account_id,
            vault_id,
            cached,
            &cache.marks,
            // The server's state alone, without the passkey outbox.
            &HashMap::new(),
        ) {
            Ok(Some(o)) => o,
            Ok(None) => return Some("the vault record is missing".into()),
            Err(e) => return Some(e),
        };
        let projects: std::collections::HashSet<_> = opened.projects.iter().map(|p| p.0).collect();
        if let Some(id) = self
            .projects
            .iter()
            .filter(|(id, p)| p.vault == vault_id && cached.projects.contains_key(*id))
            .map(|(id, _)| id)
            .find(|id| !projects.contains(*id))
        {
            return Some(format!("project {id}"));
        }
        let items: std::collections::HashSet<_> = opened.items.iter().map(|i| i.0).collect();
        self.items
            .iter()
            .filter(|(id, i)| i.vault == vault_id && cached.items.contains_key(*id))
            .map(|(id, _)| id)
            .find(|id| !items.contains(*id))
            .map(|id| format!("item {id}"))
    }

    /// Signs the key of every unsigned vault this device can use, once per
    /// device (TOFU, ADR 0030 §1), and records which vaults are signed.
    /// Returns the vaults it signed and whether this device had them
    /// cached before. Fails (and the sync with it) if the server does not
    /// store a signature: otherwise this device would keep accepting
    /// unsigned vaults.
    async fn sign_vault_keys(
        &mut self,
        cache: &mut Cache,
        notices: &mut Vec<String>,
    ) -> ClientResult<Vec<(VaultId, String, bool)>> {
        let mut signed = Vec::new();
        let ids: Vec<VaultId> = cache.vaults.keys().copied().collect();
        for vault_id in ids {
            // Never sign (or upload anything for) a vault the server no
            // longer lists.
            if cache.vaults[&vault_id].unlisted {
                continue;
            }
            let Some(vault) = cache.vaults[&vault_id].vault.clone() else {
                continue;
            };
            let trust = vault_key::check(
                self.identity.public(),
                self.account.account_id,
                vault_id,
                &vault,
                &cache.marks,
            );
            match trust {
                Ok(KeyTrust::Signed) => {
                    cache.marks.signed_vaults.insert(vault_id);
                    continue;
                }
                Err(_) => continue,
                Ok(KeyTrust::Unsigned) => {}
            }
            // Never sign a key this device cannot open.
            let name = match open_vault(
                &self.identity,
                self.account.account_id,
                vault_id,
                &cache.vaults[&vault_id],
                &cache.marks,
                // The server's state alone, without the passkey outbox.
                &HashMap::new(),
            ) {
                Ok(Some(opened)) => opened.vault.meta.name().to_owned(),
                _ => continue,
            };
            // With the vault already in this device's sealed cache, the
            // listed key must be that one, byte for byte.
            let previous = self
                .cache
                .vaults
                .get(&vault_id)
                .and_then(|c| c.vault.as_ref());
            let known = match vault_key::tofu(previous, &vault) {
                Ok(known) => known,
                Err(why) => {
                    notices.push(why);
                    continue;
                }
            };
            let ctx = VaultContext {
                account: self.account.account_id,
                vault: vault_id,
            };
            let signature = sign_vault_key(&self.identity, &ctx, vault.shared_key.as_bytes())?;
            let sig_blob = Blob::new(signature.to_bytes().to_vec());
            let stored: klav_proto::vault::Vault = self
                .send_json(
                    Method::PUT,
                    &format!("/v1/vaults/{vault_id}/signature"),
                    &SignVaultKey {
                        shared_key_signature: sig_blob.clone(),
                    },
                )
                .await?;
            if stored.shared_key.as_bytes() != vault.shared_key.as_bytes()
                || stored.shared_key_signature.as_ref().map(Blob::as_bytes)
                    != Some(sig_blob.as_bytes())
            {
                return Err(ClientError::Security(format!(
                    "vault {vault_id}: the server did not store this device's key signature"
                )));
            }
            if let Some(record) = cache
                .vaults
                .get_mut(&vault_id)
                .and_then(|c| c.vault.as_mut())
            {
                record.shared_key_signature = Some(sig_blob);
            }
            cache.marks.signed_vaults.insert(vault_id);
            signed.push((vault_id, name, known));
        }
        cache.marks.vault_keys_signed = true;
        Ok(signed)
    }

    /// Decrypts keys, names and overviews from the cache, with the passkey
    /// outbox over it.
    pub(crate) fn rebuild(&mut self) {
        // Whether an item has a code holds for as long as its version: keep
        // what earlier lists worked out, so a sync does not open them again.
        let known_codes: HashMap<ItemId, (u64, bool)> = self
            .items
            .iter()
            .filter_map(|(id, e)| e.has_code.get().map(|has| (*id, (e.version, *has))))
            .collect();
        self.vaults.clear();
        self.projects.clear();
        self.items.clear();
        self.warnings.clear();
        self.queued.clear();
        if !self.outbox_paused {
            match crate::passkey_outbox::overlay(
                &self.home,
                &self.local_key,
                &self.ctx,
                &self.cache,
            ) {
                Ok(list) => {
                    for (vault, wire) in list {
                        self.queued.insert(wire.id, (vault, wire));
                    }
                }
                Err(e) => self
                    .warnings
                    .push(format!("the passkey outbox does not open: {e}")),
            }
        }
        for (vault_id, cached) in &self.cache.vaults {
            match open_vault(
                &self.identity,
                self.account.account_id,
                *vault_id,
                cached,
                &self.cache.marks,
                &self.queued,
            ) {
                Ok(Some(opened)) => {
                    if cached.unlisted {
                        self.warnings.push(format!(
                            "vault {:?} ({vault_id}) is no longer listed by the server \
                             (purged, or access lost); this device keeps its copy, read-only. \
                             `klav sync --reset-cache` drops it",
                            opened.vault.meta.name()
                        ));
                    }
                    self.vaults.insert(*vault_id, opened.vault);
                    self.projects.extend(opened.projects);
                    self.items.extend(opened.items);
                    self.warnings.extend(opened.warnings);
                }
                Ok(None) => {}
                Err(e) => self.warnings.push(e),
            }
        }
        for (id, e) in &self.items {
            if let Some((version, has)) = known_codes.get(id)
                && *version == e.version
            {
                let _ = e.has_code.set(*has);
            }
        }
    }

    // ------------------------------------------------------ vaults/projects --

    /// Vaults, sorted by name.
    pub fn vaults(&self) -> Vec<VaultSummary> {
        let mut out: Vec<VaultSummary> = self
            .vaults
            .iter()
            .map(|(id, v)| VaultSummary {
                id: *id,
                name: v.meta.name().to_owned(),
                deleted: v.deleted,
                items: self
                    .items
                    .values()
                    .filter(|i| i.vault == *id && !i.trashed && !i.is_system())
                    .count(),
            })
            .collect();
        out.sort_by_key(|a| a.name.to_lowercase());
        out
    }

    /// Projects (of one vault, or all), sorted by vault and name.
    pub fn projects(&self, vault: Option<VaultId>) -> Vec<ProjectSummary> {
        let mut out: Vec<ProjectSummary> = self
            .projects
            .iter()
            .filter(|(_, p)| vault.is_none_or(|v| p.vault == v))
            .filter(|(id, p)| !is_system_project(p.vault, **id))
            .filter_map(|(id, p)| {
                Some(ProjectSummary {
                    id: *id,
                    vault_id: p.vault,
                    vault: self.vaults.get(&p.vault)?.meta.name().to_owned(),
                    name: p.meta.name().to_owned(),
                    repos: p.meta.repos().to_vec(),
                })
            })
            .collect();
        out.sort_by_key(|a| (a.vault.to_lowercase(), a.name.to_lowercase()));
        out
    }

    /// Finds a vault by name (case-insensitive) or ID.
    pub fn find_vault(&self, wanted: &str) -> ClientResult<VaultId> {
        let live = self.vaults.iter().filter(|(_, v)| !v.deleted);
        pick(
            "vault",
            wanted,
            live.map(|(id, v)| (*id, id.to_string(), v.meta.name().to_owned())),
        )
    }

    /// Finds a project of `vault` by name or ID.
    pub fn find_project(&self, vault: VaultId, wanted: &str) -> ClientResult<ProjectId> {
        pick(
            "project",
            wanted,
            self.projects
                .iter()
                .filter(|(id, p)| p.vault == vault && !is_system_project(vault, **id))
                .map(|(id, p)| (*id, id.to_string(), p.meta.name().to_owned())),
        )
    }

    /// Creates a vault (with its "General" project) owned by this account.
    pub async fn create_vault(&mut self, name: &str) -> ClientResult<VaultId> {
        let meta = Meta::new(name, None)?;
        if self.find_vault(name).is_ok() {
            return Err(ClientError::Invalid(format!(
                "a vault named {name:?} already exists"
            )));
        }
        let id = VaultId::generate();
        let key = VaultKey::generate();
        let ctx = VaultContext {
            account: self.account.account_id,
            vault: id,
        };
        let shared = share_vault_key(self.identity.public(), &ctx, &key)?;
        let signature = sign_vault_key(&self.identity, &ctx, &shared)?;
        let created: klav_proto::vault::Vault = self
            .send_json(
                Method::POST,
                "/v1/vaults",
                &CreateVault {
                    id,
                    meta: Blob::new(seal_vault_meta(&key, &ctx, 1, &meta)),
                    shared_key: Blob::new(shared.clone()),
                    shared_key_signature: Blob::new(signature.to_bytes().to_vec()),
                },
            )
            .await?;
        if created.shared_key.as_bytes() != shared.as_slice() {
            return Err(ClientError::Security(format!(
                "vault {id}: the server answered with another key than the one created"
            )));
        }
        let body = project_body(&key, self.account.account_id, id, crate::DEFAULT_PROJECT)?;
        self.post_project(id, body).await?;
        self.sync().await?;
        // The vault now listed must carry the very blob sealed here (so it
        // opens to the key generated here) and be in use.
        let listed = self
            .cache
            .vaults
            .get(&id)
            .and_then(|c| c.vault.as_ref())
            .map(|v| v.shared_key.as_bytes());
        if listed != Some(shared.as_slice()) || !self.vaults.contains_key(&id) {
            return Err(ClientError::Security(format!(
                "vault {id}: the server lists another key than the one created"
            )));
        }
        Ok(id)
    }

    async fn post_project(&mut self, vault: VaultId, body: CreateProject) -> ClientResult<()> {
        let _: klav_proto::vault::Project = self
            .send_json(Method::POST, &format!("/v1/vaults/{vault}/projects"), &body)
            .await?;
        Ok(())
    }

    /// Creates a project in `vault`.
    pub async fn create_project(&mut self, vault: VaultId, name: &str) -> ClientResult<ProjectId> {
        if self.find_project(vault, name).is_ok() {
            return Err(ClientError::Invalid(format!(
                "a project named {name:?} already exists"
            )));
        }
        let entry = self
            .vaults
            .get(&vault)
            .ok_or_else(|| ClientError::NotFound(format!("vault {vault}")))?;
        let body = project_body(&entry.key, entry.owner, vault, name)?;
        let id = body.id;
        self.post_project(vault, body).await?;
        self.sync().await?;
        Ok(id)
    }

    /// Replaces the normalized Git repositories linked to `project` (ADR 0032 §2).
    pub async fn set_project_repos(
        &mut self,
        vault: VaultId,
        project: ProjectId,
        repos: Vec<String>,
    ) -> ClientResult<ProjectSummary> {
        if is_system_project(vault, project) {
            return Err(ClientError::Invalid(
                "cannot link repositories to Klav's system project".into(),
            ));
        }
        let mut attempt = 0;
        loop {
            match self
                .write_project_repos(vault, project, repos.clone())
                .await
            {
                Err(ClientError::Conflict(_)) if attempt == 0 => {
                    self.sync().await?;
                    attempt += 1;
                }
                other => return other,
            }
        }
    }

    async fn write_project_repos(
        &mut self,
        vault: VaultId,
        project: ProjectId,
        repos: Vec<String>,
    ) -> ClientResult<ProjectSummary> {
        let vault_entry = self
            .vaults
            .get(&vault)
            .ok_or_else(|| ClientError::NotFound(format!("vault {vault}")))?;
        let owner = vault_entry.owner;
        let vault_name = vault_entry.meta.name().to_owned();
        let entry = self
            .projects
            .get(&project)
            .filter(|p| p.vault == vault)
            .ok_or_else(|| ClientError::NotFound(format!("project {project}")))?;
        let updated_meta =
            Meta::new(entry.meta.name(), entry.meta.description())?.with_repos(repos)?;
        if updated_meta.repos() == entry.meta.repos() {
            return Ok(ProjectSummary {
                id: project,
                vault_id: vault,
                vault: vault_name,
                name: entry.meta.name().to_owned(),
                repos: entry.meta.repos().to_vec(),
            });
        }
        let pctx = ProjectContext {
            account: owner,
            vault,
            project,
        };
        let wrapped_key = self
            .cache
            .vaults
            .get(&vault)
            .and_then(|c| c.projects.get(&project))
            .and_then(|p| p.wrapped_key.clone())
            .unwrap_or_else(|| {
                Blob::new(klav_core::crypto::wrap::wrap_project_key(
                    &vault_entry.key,
                    &pctx,
                    &entry.key,
                ))
            });
        let new_version = entry.version + 1;
        let sealed_meta = Blob::new(seal_project_meta(
            &entry.key,
            &pctx,
            new_version,
            &updated_meta,
        ));
        let body = klav_proto::vault::UpdateProject {
            version: new_version,
            wrapped_key,
            meta: sealed_meta,
        };
        let _: klav_proto::vault::Project = self
            .send_json(
                Method::PUT,
                &format!("/v1/vaults/{vault}/projects/{project}"),
                &body,
            )
            .await?;
        self.sync().await?;
        Ok(ProjectSummary {
            id: project,
            vault_id: vault,
            vault: vault_name,
            name: updated_meta.name().to_owned(),
            repos: updated_meta.repos().to_vec(),
        })
    }

    // -------------------------------------------------------------- items --

    fn summary(&self, id: ItemId, e: &ItemEntry) -> Option<ItemSummary> {
        let vault = self.vaults.get(&e.vault)?;
        let project = self.projects.get(&e.project)?;
        let reference = Reference {
            vault: klav_core::model::Selector::Name(vault.meta.name().to_owned()),
            project: klav_core::model::Selector::Name(project.meta.name().to_owned()),
            item: klav_core::model::Selector::Name(e.overview.title.clone()),
            field: klav_core::model::Selector::Name("x".into()),
        }
        .to_string();
        Some(ItemSummary {
            id,
            // Only the placeholder field: an item titled `x` keeps its own.
            reference: reference
                .strip_suffix("/x")
                .unwrap_or(&reference)
                .to_owned(),
            vault_id: e.vault,
            vault: vault.meta.name().to_owned(),
            project_id: e.project,
            project: project.meta.name().to_owned(),
            kind: e.overview.kind,
            title: e.overview.title.clone(),
            username: e.overview.username.clone(),
            urls: e.overview.urls.clone(),
            tags: e.overview.tags.clone(),
            version: e.version,
            updated_at: e.updated_at,
            trashed: e.trashed,
            passkey: e.overview.passkey.clone(),
            confirmed_urls: e.confirmed_urls.clone(),
            pending_urls: e.pending_urls.clone(),
            author_agent_id: e.author,
            protected_by: self.protection.protected_by(id),
        })
    }

    /// Every item of kind `environment` this device opens, trashed ones
    /// included: where it is, its version, who wrote it, when, its title
    /// and whether it is in the trash.
    pub(crate) fn environment_entries(&self) -> Vec<crate::environments::EnvEntry> {
        self.items
            .iter()
            .filter(|(_, e)| e.overview.kind == ItemKind::Environment && !e.is_system())
            .map(|(id, e)| crate::environments::EnvEntry {
                loc: ItemLocation {
                    vault: e.vault,
                    project: e.project,
                    item: *id,
                },
                version: e.version,
                author: e.author,
                updated_at: e.updated_at,
                title: e.overview.title.clone(),
                trashed: e.trashed,
            })
            .collect()
    }

    /// Where an item this device opens lives, and its kind.
    pub(crate) fn locate(&self, id: ItemId) -> Option<(ItemLocation, ItemKind)> {
        self.items.get(&id).map(|e| {
            (
                ItemLocation {
                    vault: e.vault,
                    project: e.project,
                    item: id,
                },
                e.overview.kind,
            )
        })
    }

    /// Every live (not trashed), non-system item: where it is, its
    /// summary and when it was created (Unix ms), sorted by title.
    pub(crate) fn live_items(&self) -> Vec<(ItemLocation, ItemSummary, i64)> {
        let mut out: Vec<(ItemLocation, ItemSummary, i64)> = self
            .items
            .iter()
            .filter(|(_, e)| !e.trashed && !e.is_system())
            .filter_map(|(id, e)| {
                let summary = self.summary(*id, e)?;
                let created_at = self
                    .wire(e.vault, *id)
                    .map_or(e.updated_at, |w| w.created_at);
                let loc = ItemLocation {
                    vault: e.vault,
                    project: e.project,
                    item: *id,
                };
                Some((loc, summary, created_at))
            })
            .collect();
        out.sort_by(|a, b| {
            (a.1.title.to_lowercase(), a.1.id).cmp(&(b.1.title.to_lowercase(), b.1.id))
        });
        out
    }

    /// Whether an item has a filled one-time password field. Opens its
    /// details once per version; an item that does not open has none.
    fn has_code(&self, id: ItemId, e: &ItemEntry) -> bool {
        *e.has_code.get_or_init(|| {
            let loc = ItemLocation {
                vault: e.vault,
                project: e.project,
                item: id,
            };
            self.open_item(loc).is_ok_and(|item| {
                item.fields()
                    .iter()
                    .any(|f| f.kind() == FieldKind::Totp && !f.is_empty())
            })
        })
    }

    /// Lists item metadata. Only `codes` opens the details, to see whether
    /// an item has a code; nothing secret leaves this function.
    pub fn list_items(&self, filter: &ItemFilter) -> ClientResult<Vec<ItemSummary>> {
        let vault = filter
            .vault
            .as_deref()
            .map(|v| self.find_vault(v))
            .transpose()?;
        let project = match (&filter.project, vault) {
            (Some(p), Some(v)) => Some(self.find_project(v, p)?),
            (Some(p), None) => {
                let matches: Vec<ProjectId> = self
                    .projects
                    .keys()
                    .copied()
                    .filter(|id| {
                        let e = &self.projects[id];
                        id.to_string() == *p || e.meta.name().eq_ignore_ascii_case(p)
                    })
                    .collect();
                if matches.is_empty() {
                    return Err(ClientError::NotFound(format!("project {p:?}")));
                }
                return Ok(self
                    .list_items(&ItemFilter {
                        project: None,
                        ..filter.clone()
                    })?
                    .into_iter()
                    .filter(|s| matches.contains(&s.project_id))
                    .collect());
            }
            _ => None,
        };
        let query = filter.query.as_deref().map(str::to_lowercase);
        let mut out: Vec<ItemSummary> = self
            .items
            .iter()
            .filter(|(_, e)| e.trashed == filter.trash && !e.is_system())
            .filter(|(_, e)| vault.is_none_or(|v| e.vault == v))
            .filter(|(_, e)| project.is_none_or(|p| e.project == p))
            .filter(|(_, e)| filter.wants_kind(e.overview.kind))
            .filter(|(_, e)| {
                filter
                    .tag
                    .as_deref()
                    .is_none_or(|t| e.overview.tags.iter().any(|x| x.eq_ignore_ascii_case(t)))
            })
            .filter(|(_, e)| {
                query
                    .as_deref()
                    .is_none_or(|q| matches_query(&e.overview, q))
            })
            .filter(|(id, e)| !filter.codes || self.has_code(**id, e))
            .filter_map(|(id, e)| self.summary(*id, e))
            .collect();
        out.sort_by_key(|a| {
            (
                a.vault.to_lowercase(),
                a.project.to_lowercase(),
                a.title.to_lowercase(),
            )
        });
        Ok(out)
    }

    /// Finds an item: a `klav://vault/project/item[/field]` reference, a
    /// `vault/project/item` path, an item ID or a unique title.
    pub fn find_item(&self, wanted: &str) -> ClientResult<ItemLocation> {
        let wanted = wanted.trim();
        let scheme = klav_core::model::reference::SCHEME;
        let as_ref = if wanted
            .get(..scheme.len())
            .is_some_and(|s| s.eq_ignore_ascii_case(scheme))
        {
            Some(wanted.to_owned())
        } else if wanted.split('/').count() == 3 {
            Some(format!("klav://{wanted}"))
        } else {
            None
        };
        if let Some(text) = as_ref {
            let text = if text["klav://".len()..].split('/').count() == 3 {
                format!("{text}/x")
            } else {
                text
            };
            let resolved = Reference::parse(&text)?.resolve(self)?;
            return Ok(ItemLocation {
                vault: resolved.vault,
                project: resolved.project,
                item: resolved.item,
            });
        }
        if looks_like_id(wanted) {
            let id: ItemId = wanted
                .parse()
                .map_err(|_| ClientError::Invalid("invalid item ID".into()))?;
            return self
                .items
                .get(&id)
                .map(|e| ItemLocation {
                    vault: e.vault,
                    project: e.project,
                    item: id,
                })
                .ok_or_else(|| ClientError::NotFound(format!("item {id}")));
        }
        let matches: Vec<ItemLocation> = self
            .items
            .iter()
            .filter(|(_, e)| {
                !e.trashed && !e.is_system() && e.overview.title.eq_ignore_ascii_case(wanted)
            })
            .map(|(id, e)| ItemLocation {
                vault: e.vault,
                project: e.project,
                item: *id,
            })
            .collect();
        match matches.as_slice() {
            [one] => Ok(*one),
            [] => Err(ClientError::NotFound(format!("item {wanted:?}"))),
            many => Err(ClientError::Ambiguous(format!(
                "{} items are called {wanted:?}; use one of: {}",
                many.len(),
                many.iter()
                    .filter_map(|l| self.summary(l.item, &self.items[&l.item]))
                    .map(|s| format!("{} (ID {})", s.reference, s.id))
                    .collect::<Vec<_>>()
                    .join(", ")
            ))),
        }
    }

    /// Whether the item has a secret value other than attachments (a secret
    /// field or notes); `None` if this device cannot open it.
    pub(crate) fn item_has_text_secrets(&self, id: ItemId) -> Option<bool> {
        let e = self.items.get(&id)?;
        let item = self
            .open_item(ItemLocation {
                vault: e.vault,
                project: e.project,
                item: id,
            })
            .ok()?;
        let fields = item.fields().iter().any(|f| {
            matches!(f.value(), klav_core::model::item::FieldValue::Secret(s) if !s.expose().is_empty())
        });
        let notes = item.notes().is_some_and(|n| !n.expose().is_empty());
        Some(fields || notes)
    }

    /// Whether the item is in the trash; `None` if this device does not
    /// have it (purged, or never synced).
    pub(crate) fn item_trashed(&self, id: ItemId) -> Option<bool> {
        self.items.get(&id).map(|e| e.trashed)
    }

    /// Metadata of one item.
    pub fn item_summary(&self, loc: ItemLocation) -> ClientResult<ItemSummary> {
        self.items
            .get(&loc.item)
            .and_then(|e| self.summary(loc.item, e))
            .ok_or_else(|| ClientError::NotFound(format!("item {}", loc.item)))
    }

    /// The item as stored: the queued registration over the cache.
    pub(crate) fn wire(&self, vault: VaultId, item: ItemId) -> Option<&WireItem> {
        if let Some((v, w)) = self.queued.get(&item) {
            return (*v == vault).then_some(w);
        }
        self.cache
            .vaults
            .get(&vault)
            .and_then(|v| v.items.get(&item))
    }

    pub(crate) fn item_parts(
        &self,
        loc: ItemLocation,
    ) -> ClientResult<(ItemContext, ItemKey, &WireItem)> {
        let wire = self
            .wire(loc.vault, loc.item)
            .ok_or_else(|| ClientError::NotFound(format!("item {}", loc.item)))?;
        let vault = self
            .vaults
            .get(&loc.vault)
            .ok_or_else(|| ClientError::NotFound(format!("vault {}", loc.vault)))?;
        let project = self
            .projects
            .get(&wire.project_id)
            .ok_or_else(|| ClientError::NotFound(format!("project {}", wire.project_id)))?;
        let ctx = ItemContext {
            account: vault.owner,
            vault: loc.vault,
            project: wire.project_id,
            item: loc.item,
        };
        let wrapped = wire
            .wrapped_key
            .as_ref()
            .ok_or_else(|| ClientError::Corrupt("item without key".into()))?;
        let key = unwrap_item_key(&project.key, &ctx, wrapped.as_bytes())?;
        Ok((ctx, key, wire))
    }

    /// The cached (completed, not deleted) attachment `id` of `vault`.
    pub(crate) fn cached_attachment(
        &self,
        vault: VaultId,
        id: klav_core::ids::AttachmentId,
    ) -> Option<&klav_proto::sync::Attachment> {
        self.cache
            .vaults
            .get(&vault)
            .and_then(|v| v.attachments.get(&id))
            .filter(|a| a.deleted_at.is_none() && a.completed_at.is_some())
    }

    /// Decrypts a full item, secrets included.
    pub fn open_item(&self, loc: ItemLocation) -> ClientResult<Item> {
        let (ctx, key, wire) = self.item_parts(loc)?;
        let sealed = SealedItem {
            overview: wire
                .overview
                .as_ref()
                .ok_or_else(|| ClientError::Corrupt("item without overview".into()))?
                .as_bytes()
                .to_vec(),
            details: wire
                .details
                .as_ref()
                .ok_or_else(|| ClientError::Corrupt("item without details".into()))?
                .as_bytes()
                .to_vec(),
        };
        Ok(open_item(&key, &ctx, wire.version, &sealed)?)
    }

    /// The key of `vault` and the account that owns it.
    pub(crate) fn vault_key(&self, vault: VaultId) -> ClientResult<(&VaultKey, AccountId)> {
        self.vaults
            .get(&vault)
            .map(|v| (&v.key, v.owner))
            .ok_or_else(|| ClientError::NotFound(format!("vault {vault}")))
    }

    /// Encrypts and uploads a new item (version 1), then syncs.
    pub async fn add_item(
        &mut self,
        vault: VaultId,
        project: ProjectId,
        item: &Item,
    ) -> ClientResult<ItemLocation> {
        let loc = self.post_item(vault, project, item).await?;
        self.sync().await?;
        Ok(loc)
    }

    /// Encrypts and uploads a new item without syncing. If the project key
    /// rotated since the last sync (`409` on `project_version`), syncs and
    /// wraps the item key again with the new one, once.
    pub(crate) async fn post_item(
        &mut self,
        vault: VaultId,
        project: ProjectId,
        item: &Item,
    ) -> ClientResult<ItemLocation> {
        self.writable(vault)?;
        let key = ItemKey::generate();
        let mut retried = false;
        loop {
            let v = self
                .vaults
                .get(&vault)
                .ok_or_else(|| ClientError::NotFound(format!("vault {vault}")))?;
            let p = self
                .projects
                .get(&project)
                .filter(|p| p.vault == vault)
                .ok_or_else(|| ClientError::NotFound(format!("project {project}")))?;
            let ctx = ItemContext {
                account: v.owner,
                vault,
                project,
                item: item.id(),
            };
            let sealed = seal_item(&key, &ctx, 1, item);
            let project_version = p.version;
            let body = CreateItem {
                id: item.id(),
                project_id: project,
                version: 1,
                wrapped_key: Blob::new(wrap_item_key(&p.key, &ctx, &key)),
                project_version,
                overview: Blob::new(sealed.overview),
                details: Blob::new(sealed.details),
            };
            let res: ClientResult<WireItem> = self
                .send_json(Method::POST, &format!("/v1/vaults/{vault}/items"), &body)
                .await;
            match res {
                Ok(_) => {
                    return Ok(ItemLocation {
                        vault,
                        project,
                        item: item.id(),
                    });
                }
                Err(e) if !retried && is_conflict(&e) => {
                    retried = true;
                    if !self.project_rotated(project, project_version).await? {
                        return Err(e);
                    }
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// After a `409`: syncs and says whether `project` moved past `sent`,
    /// so the write is worth wrapping again.
    async fn project_rotated(&mut self, project: ProjectId, sent: u64) -> ClientResult<bool> {
        self.sync().await?;
        Ok(self
            .projects
            .get(&project)
            .is_some_and(|p| p.version != sent))
    }

    /// Uploads `item` as the next version of the item at `loc`.
    pub async fn update_item(&mut self, loc: ItemLocation, item: &Item) -> ClientResult<()> {
        self.put_item(loc, item, &[]).await?;
        self.sync().await?;
        Ok(())
    }

    /// Uploads the next version without syncing afterwards. `extra` are
    /// more values for the password record (an import's older passwords).
    /// Like [`Self::post_item`], a rotation in between is retried once with
    /// the item key wrapped with the new project key.
    pub(crate) async fn put_item(
        &mut self,
        loc: ItemLocation,
        item: &Item,
        extra: &[klav_import::HistoryPush],
    ) -> ClientResult<()> {
        self.put_item_with(loc, item, extra, None).await
    }

    /// [`Self::put_item`] with a change to the item's password record made
    /// after the usual bookkeeping (the assisted change, ADR 0022 §5). With
    /// `edit`, a record that cannot be read fails the write instead of
    /// becoming a warning: the pending value must be stored or nothing is.
    pub(crate) async fn put_item_with(
        &mut self,
        loc: ItemLocation,
        item: &Item,
        extra: &[klav_import::HistoryPush],
        edit: Option<RecordEdit>,
    ) -> ClientResult<()> {
        if item.id() != loc.item {
            return Err(ClientError::Invalid("item ID mismatch".into()));
        }
        self.writable(loc.vault)?;
        if self.item_parts(loc)?.2.trashed_at.is_some() {
            return Err(ClientError::Invalid("the item is in the trash".into()));
        }
        let item = &self.with_password_record(loc, item, extra, edit).await?;
        let mut retried = false;
        loop {
            let (ctx, key, wire) = self.item_parts(loc)?;
            let version = wire.version.checked_add(1).ok_or_else(|| {
                ClientError::Corrupt(format!("item {}: version overflow", loc.item))
            })?;
            let wrapped = wire.wrapped_key.clone().unwrap_or_default();
            let project_version = self
                .projects
                .get(&loc.project)
                .ok_or_else(|| ClientError::NotFound(format!("project {}", loc.project)))?
                .version;
            let sealed = seal_item(&key, &ctx, version, item);
            let body = UpdateItem {
                version,
                wrapped_key: wrapped,
                project_version,
                overview: Blob::new(sealed.overview),
                details: Blob::new(sealed.details),
                attachment_keys: None,
            };
            let res: ClientResult<WireItem> = self
                .send_json(
                    Method::PUT,
                    &format!("/v1/vaults/{}/items/{}", loc.vault, loc.item),
                    &body,
                )
                .await;
            match res {
                Ok(_) => return Ok(()),
                Err(ClientError::Conflict(current)) => {
                    self.sync().await?;
                    return Err(ClientError::Conflict(current));
                }
                Err(e) if !retried && is_conflict(&e) => {
                    retried = true;
                    if !self.project_rotated(loc.project, project_version).await? {
                        return Err(e);
                    }
                    // Someone else wrote the item meanwhile: that is a
                    // version conflict, not something to overwrite.
                    let now = self.item_parts(loc)?.2.version;
                    if now + 1 != version {
                        return Err(ClientError::Conflict(now));
                    }
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// `item` with its password record brought up to date (ADR 0022 §3):
    /// the values of `password`/`concealed` fields that this edit replaces
    /// or removes go to the record, sealed with the vault key. The first
    /// time an item with such fields is written, the record is filled from
    /// the versions the server still has (G6). Problems with the record
    /// never block the edit: they become warnings.
    async fn with_password_record(
        &mut self,
        loc: ItemLocation,
        item: &Item,
        extra: &[klav_import::HistoryPush],
        edit: Option<RecordEdit>,
    ) -> ClientResult<Item> {
        let mut new = item.clone();
        let before = match self.open_item(loc) {
            Ok(before) => before,
            Err(e) if edit.is_some() => return Err(e),
            Err(_) => return Ok(new),
        };
        if before.kind().is_system() {
            if edit.is_some() {
                return Err(ClientError::Invalid(
                    "a system item has no password record".into(),
                ));
            }
            return Ok(new);
        }
        // A caller that rebuilt the item without the record keeps it.
        if new.password_record().is_none() && before.password_record().is_some() {
            new.set_password_record(before.password_record().map(<[u8]>::to_vec))?;
        }
        let Some(vault) = self.vaults.get(&loc.vault) else {
            if edit.is_some() {
                return Err(ClientError::NotFound(format!("vault {}", loc.vault)));
            }
            return Ok(new);
        };
        let vctx = VaultContext {
            account: vault.owner,
            vault: loc.vault,
        };
        let mut reconciled = false;
        let (mut record, existed) = match before.password_record() {
            Some(blob) => match PasswordRecord::open(&vault.key, &vctx, loc.item, blob) {
                Ok(mut record) => {
                    // An agent with `update` may have changed a password
                    // and kept the record as it was: the values it
                    // replaced since the person's last version go in now.
                    if self.item_parts(loc)?.2.author_agent_id.is_some() {
                        match self.reconcile_record(loc, &before, &mut record).await {
                            Ok(added) => reconciled = added,
                            Err(e) => self.warnings.push(format!(
                                "passwords an agent replaced in {} could not be read from its \
                                 versions ({e})",
                                before.title()
                            )),
                        }
                    }
                    (record, true)
                }
                Err(e) if edit.is_some() => return Err(e.into()),
                Err(e) => {
                    self.warnings.push(format!(
                        "the password history of {} could not be read ({e}); it was left as it was",
                        before.title()
                    ));
                    return Ok(new);
                }
            },
            None => {
                let recorded = |i: &Item| {
                    i.fields()
                        .iter()
                        .any(|f| is_recorded(f.kind()) && !f.is_empty())
                };
                if !recorded(&before) && !recorded(&new) && extra.is_empty() && edit.is_none() {
                    return Ok(new);
                }
                let mut record = PasswordRecord::new();
                if let Err(e) = self.backfill_record(loc, &before, &mut record).await {
                    self.warnings.push(format!(
                        "older passwords of {} could not be read from its versions ({e})",
                        before.title()
                    ));
                }
                (record, false)
            }
        };
        let now = now_ms();
        let mut changed = record.note_changes(&before, &new, now);
        changed |= push_extra(&mut record, &new, extra);
        if let Some(edit) = edit {
            edit.apply(&mut record, now);
            changed = true;
        }
        if changed || reconciled || !existed {
            let vault = self.vaults.get(&loc.vault).expect("checked above");
            new.set_password_record(Some(record.seal(&vault.key, &vctx, loc.item)))?;
        }
        Ok(new)
    }

    /// Seals a password record with `extra` for a new item of `vault`.
    pub(crate) fn new_record(
        &self,
        vault: VaultId,
        item: &Item,
        extra: &[klav_import::HistoryPush],
    ) -> ClientResult<Option<Vec<u8>>> {
        let mut record = PasswordRecord::new();
        if !push_extra(&mut record, item, extra) {
            return Ok(None);
        }
        let v = self
            .vaults
            .get(&vault)
            .ok_or_else(|| ClientError::NotFound(format!("vault {vault}")))?;
        let vctx = VaultContext {
            account: v.owner,
            vault,
        };
        Ok(Some(record.seal(&v.key, &vctx, item.id())))
    }

    /// Adds to `record` the values that the agents' versions after the
    /// person's last version replaced: the record was up to date when the
    /// person last wrote, and agents do not keep it.
    async fn reconcile_record(
        &mut self,
        loc: ItemLocation,
        current: &Item,
        record: &mut PasswordRecord,
    ) -> ClientResult<bool> {
        let current_version = self.item_parts(loc)?.2.version;
        let mut versions = Vec::new();
        for info in self
            .item_versions(loc)
            .await?
            .into_iter()
            .take(MAX_BACKFILL_VERSIONS)
        {
            if info.version == current_version {
                continue;
            }
            let person = info.author_agent_id.is_none();
            match self.item_version(loc, info.version).await {
                Ok(item) => versions.push((info.created_at, item)),
                Err(ClientError::NotFound(_) | ClientError::Crypto(_) | ClientError::Model(_)) => {}
                Err(e) => return Err(e),
            }
            // Newest first: stop at the person's last version, included.
            if person {
                break;
            }
        }
        if versions.is_empty() {
            return Ok(false);
        }
        let current_at = self.item_summary(loc)?.updated_at;
        versions.push((current_at, current.clone()));
        Ok(record.backfill(&mut versions, current))
    }

    /// Fills `record` from the stored versions of the item at `loc`.
    async fn backfill_record(
        &mut self,
        loc: ItemLocation,
        current: &Item,
        record: &mut PasswordRecord,
    ) -> ClientResult<()> {
        let mut versions = Vec::new();
        let current_version = self.item_parts(loc)?.2.version;
        let current_at = self.item_summary(loc)?.updated_at;
        versions.push((current_at, current.clone()));
        // The server keeps 50 by default; a hostile one must not turn this
        // into thousands of requests.
        for info in self
            .item_versions(loc)
            .await?
            .into_iter()
            .take(MAX_BACKFILL_VERSIONS)
        {
            if info.version == current_version {
                continue;
            }
            match self.item_version(loc, info.version).await {
                Ok(item) => versions.push((info.created_at, item)),
                // A version this device cannot open (a project it lost
                // access to) is skipped.
                Err(ClientError::NotFound(_) | ClientError::Crypto(_) | ClientError::Model(_)) => {}
                Err(e) => return Err(e),
            }
        }
        record.backfill(&mut versions, current);
        Ok(())
    }

    /// The versions the server keeps of an item, newest first (the current
    /// one included).
    pub async fn item_versions(
        &mut self,
        loc: ItemLocation,
    ) -> ClientResult<Vec<klav_proto::vault::ItemVersionInfo>> {
        let history: klav_proto::vault::ItemHistory = self
            .get(&format!(
                "/v1/vaults/{}/items/{}/versions",
                loc.vault, loc.item
            ))
            .await?;
        Ok(history.versions)
    }

    /// Decrypts one stored version of an item.
    pub async fn item_version(&mut self, loc: ItemLocation, version: u64) -> ClientResult<Item> {
        let wire: klav_proto::vault::ItemVersion = self
            .get(&format!(
                "/v1/vaults/{}/items/{}/versions/{version}",
                loc.vault, loc.item
            ))
            .await?;
        if wire.item_id != loc.item || wire.version != version {
            return Err(ClientError::Corrupt(
                "the server sent another version".into(),
            ));
        }
        let vault = self
            .vaults
            .get(&loc.vault)
            .ok_or_else(|| ClientError::NotFound(format!("vault {}", loc.vault)))?;
        let project = self
            .projects
            .get(&wire.project_id)
            .ok_or_else(|| ClientError::NotFound(format!("project {}", wire.project_id)))?;
        let ctx = ItemContext {
            account: vault.owner,
            vault: loc.vault,
            project: wire.project_id,
            item: loc.item,
        };
        let key = unwrap_item_key(&project.key, &ctx, wire.wrapped_key.as_bytes())?;
        let sealed = SealedItem {
            overview: wire.overview.as_bytes().to_vec(),
            details: wire.details.as_bytes().to_vec(),
        };
        Ok(open_item(&key, &ctx, version, &sealed)?)
    }

    /// Forgets every stored previous version of an item (the current one
    /// stays), so values removed from it are gone from the server too.
    pub async fn purge_item_versions(&mut self, loc: ItemLocation) -> ClientResult<()> {
        let res = self
            .authed(
                Method::DELETE,
                &format!("/v1/vaults/{}/items/{}/versions", loc.vault, loc.item),
                &Body::Empty,
            )
            .await?;
        api::empty(res).await
    }

    /// Live items of `vault`'s system project of `kind`, oldest ID first.
    pub fn system_items(&self, vault: VaultId, kind: ItemKind) -> Vec<ItemLocation> {
        let mut out: Vec<ItemLocation> = self
            .items
            .iter()
            .filter(|(_, e)| {
                e.vault == vault
                    && !e.trashed
                    && e.overview.kind == kind
                    && is_system_project(vault, e.project)
            })
            .map(|(id, e)| ItemLocation {
                vault: e.vault,
                project: e.project,
                item: *id,
            })
            .collect();
        out.sort_by_key(|l| l.item.to_string());
        out
    }

    /// Items of `vault`'s system project that this device has but could
    /// not open (skipped with a warning): a reader of Klav's own items must
    /// not take one of them as absent.
    pub(crate) fn unopened_system_items(&self, vault: VaultId) -> Vec<ItemId> {
        let Some(cached) = self.cache.vaults.get(&vault) else {
            return Vec::new();
        };
        cached
            .items
            .iter()
            .filter(|(id, i)| {
                i.trashed_at.is_none()
                    && is_system_project(vault, i.project_id)
                    && !self.items.contains_key(*id)
            })
            .map(|(id, _)| *id)
            .collect()
    }

    /// Creates `vault`'s system project if it does not exist yet.
    pub(crate) async fn ensure_system_project(
        &mut self,
        vault: VaultId,
    ) -> ClientResult<ProjectId> {
        let id = klav_core::model::history::system_project_id(vault);
        if self.projects.contains_key(&id) {
            return Ok(id);
        }
        let entry = self
            .vaults
            .get(&vault)
            .ok_or_else(|| ClientError::NotFound(format!("vault {vault}")))?;
        let body = project_body_with_id(
            &entry.key,
            entry.owner,
            vault,
            id,
            klav_core::model::history::SYSTEM_PROJECT_NAME,
        )?;
        match self.post_project(vault, body).await {
            // Another device created it first.
            Ok(()) | Err(ClientError::Api { status: 409, .. }) => {}
            Err(e) => return Err(e),
        }
        self.sync().await?;
        Ok(id)
    }

    /// Adds a warning for the caller to show.
    pub(crate) fn push_warning(&mut self, warning: String) {
        self.warnings.push(warning);
    }

    /// Moves an item to the trash.
    pub async fn trash_item(&mut self, loc: ItemLocation) -> ClientResult<()> {
        // Klav's own items (the generator history, the account's
        // preferences) are found by ID, but never trashed by hand: a
        // trashed preferences item reads as «no proxy», a change that
        // `set_proxy_setting` makes only with presence (ADR 0036 §3).
        if is_system_project(loc.vault, loc.project) {
            return Err(ClientError::Invalid(
                "this item belongs to Klav and cannot be moved to the trash".into(),
            ));
        }
        self.writable(loc.vault)?;
        let res = self
            .authed(
                Method::DELETE,
                &format!("/v1/vaults/{}/items/{}", loc.vault, loc.item),
                &Body::Empty,
            )
            .await?;
        api::empty(res).await?;
        self.sync().await?;
        Ok(())
    }

    /// Resolves a `klav://vault/project/item/field` reference to its value.
    pub fn resolve(&self, reference: &str) -> ClientResult<Resolved> {
        let parsed = Reference::parse(reference.trim())?;
        let resolved = parsed.resolve(self)?;
        let loc = ItemLocation {
            vault: resolved.vault,
            project: resolved.project,
            item: resolved.item,
        };
        let item = self.open_item(loc)?;
        let field = resolve_field(&item, &resolved.field)?;
        let value = match field.value() {
            FieldValue::Plain(s) => SecretValue::new(s.clone()),
            FieldValue::Secret(s) => s.clone(),
            FieldValue::File(_) => {
                return Err(ClientError::Invalid(
                    "file fields cannot be resolved to text yet".into(),
                ));
            }
        };
        Ok(Resolved {
            reference: format!("{}/{}", self.item_summary(loc)?.reference, field.name()),
            kind: field.kind(),
            value,
        })
    }

    /// The current TOTP code of an item (first `totp` field, or `field`).
    pub fn totp(&self, loc: ItemLocation, field: Option<&str>) -> ClientResult<(SecretValue, u64)> {
        let item = self.open_item(loc)?;
        let f = match field {
            Some(name) => item
                .field(name)
                .ok_or_else(|| ClientError::NotFound(format!("field {name:?}")))?,
            None => item
                .fields()
                .iter()
                .find(|f| f.kind() == FieldKind::Totp && !f.is_empty())
                .ok_or_else(|| ClientError::NotFound("a one-time password field".into()))?,
        };
        let FieldValue::Secret(secret) = f.value() else {
            return Err(ClientError::Invalid("not a one-time password field".into()));
        };
        let totp = Totp::from_field_value(secret.expose())
            .map_err(|e| ClientError::Invalid(format!("invalid TOTP secret: {e}")))?;
        let now = u64::try_from(now_ms() / 1000).unwrap_or(0);
        let code = totp.generate(now);
        Ok((
            SecretValue::new(secrecy::ExposeSecret::expose_secret(&code).to_owned()),
            totp.seconds_remaining(now),
        ))
    }
}

impl Catalog for Unlocked {
    fn vaults(&self) -> Vec<Named<VaultId>> {
        self.vaults
            .iter()
            .filter(|(_, v)| !v.deleted)
            .map(|(id, v)| Named {
                id: *id,
                name: v.meta.name().to_owned(),
            })
            .collect()
    }

    fn projects(&self, vault: VaultId) -> Vec<Named<ProjectId>> {
        self.projects
            .iter()
            .filter(|(id, p)| p.vault == vault && !is_system_project(vault, **id))
            .map(|(id, p)| Named {
                id: *id,
                name: p.meta.name().to_owned(),
            })
            .collect()
    }

    fn items(&self, vault: VaultId, project: ProjectId) -> Vec<Named<ItemId>> {
        self.items
            .iter()
            .filter(|(_, e)| {
                e.vault == vault && e.project == project && !e.trashed && !e.is_system()
            })
            .map(|(id, e)| Named {
                id: *id,
                name: e.overview.title.clone(),
            })
            .collect()
    }
}

/// Builds the request that creates a project with a fresh key.
fn project_body(
    vault_key: &VaultKey,
    owner: AccountId,
    vault: VaultId,
    name: &str,
) -> ClientResult<CreateProject> {
    project_body_with_id(vault_key, owner, vault, ProjectId::generate(), name)
}

fn project_body_with_id(
    vault_key: &VaultKey,
    owner: AccountId,
    vault: VaultId,
    id: ProjectId,
    name: &str,
) -> ClientResult<CreateProject> {
    let meta = Meta::new(name, None)?;
    let key = ProjectKey::generate();
    let ctx = ProjectContext {
        account: owner,
        vault,
        project: id,
    };
    Ok(CreateProject {
        id,
        wrapped_key: Blob::new(wrap_project_key(vault_key, &ctx, &key)),
        meta: Blob::new(seal_project_meta(&key, &ctx, 1, &meta)),
    })
}

fn matches_query(o: &Overview, q: &str) -> bool {
    o.title.to_lowercase().contains(q)
        || o.username
            .as_deref()
            .is_some_and(|u| u.to_lowercase().contains(q))
        || o.urls.iter().any(|u| u.to_lowercase().contains(q))
        || o.tags.iter().any(|t| t.to_lowercase().contains(q))
}

fn pick<I: Copy>(
    what: &str,
    wanted: &str,
    entries: impl Iterator<Item = (I, String, String)>,
) -> ClientResult<I> {
    let entries: Vec<(I, String, String)> = entries.collect();
    if let Some((id, _, _)) = entries.iter().find(|(_, id, _)| id == wanted) {
        return Ok(*id);
    }
    let matches: Vec<I> = entries
        .iter()
        .filter(|(_, _, name)| name.eq_ignore_ascii_case(wanted))
        .map(|(id, _, _)| *id)
        .collect();
    match matches.as_slice() {
        [one] => Ok(*one),
        [] => Err(ClientError::NotFound(format!("{what} {wanted:?}"))),
        _ => Err(ClientError::Ambiguous(format!(
            "several {what}s are called {wanted:?}; use the ID"
        ))),
    }
}

/// Adds `extra` to `record`, skipping values it already has and the
/// item's current ones. Whether anything was added.
fn push_extra(
    record: &mut PasswordRecord,
    item: &Item,
    extra: &[klav_import::HistoryPush],
) -> bool {
    let mut changed = false;
    for h in extra {
        let current = item
            .field(&h.field)
            .is_some_and(|f| matches!(f.value(), FieldValue::Secret(v) if v == &h.value));
        let known = record
            .field_history(&h.field)
            .iter()
            .any(|p| p.value == h.value);
        if !current && !known {
            changed |= record.push(&h.field, &h.value, None, h.until_ms);
        }
    }
    changed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unknown_kind_asks_to_update_instead_of_crying_tampering() {
        let id = ItemId::generate();
        let unknown = ClientError::Model(ModelError::UnknownKind("vault_of_the_future".into()));
        let warning = item_open_warning(id, &unknown);
        assert!(warning.contains(&id.to_string()), "{warning}");
        assert!(warning.contains("\"vault_of_the_future\""), "{warning}");
        assert!(warning.contains("update Klav"), "{warning}");
        assert!(!warning.contains("does not decrypt"), "{warning}");

        let broken = ClientError::Corrupt("item without key".into());
        let warning = item_open_warning(id, &broken);
        assert!(warning.contains("does not decrypt"), "{warning}");
        assert!(!warning.contains("update Klav"), "{warning}");
    }
}
