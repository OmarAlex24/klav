//! Passkeys without network: the iOS outbox (ADR 0020 §11, spec §14.7).
//!
//! The iOS Credential Provider Extension has no network (ADR 0018 §4). When
//! it registers a passkey it builds the whole item here (a new item key
//! wrapped with the project key, both sections sealed, the `0x15` key
//! inside the details) and queues it in `outbox.bin`, a `0x43` blob sealed
//! with the local key. A sign-in queues its `passkey.used` event the same
//! way. Reading merges the queue over the synced cache, so the new passkey
//! works at once on that phone; the app empties the queue when it comes to
//! the foreground ([`Unlocked::flush_passkey_outbox`]): a normal create (or
//! update) with the ID the device chose, renamed if another item took its
//! title meanwhile, and then the events.
//!
//! The app and its extension are two processes on one home: every change
//! to the file happens under the home's inter-process lock, and the flush
//! removes only what it sent.

use klav_core::crypto::context::ItemContext;
use klav_core::crypto::keys::{ItemKey, LocalKey};
use klav_core::crypto::local::{LocalContext, open_local_outbox, seal_local_outbox};
use klav_core::crypto::wrap::{unwrap_item_key, wrap_item_key};
use klav_core::ids::{ItemId, ProjectId, VaultId};
use klav_core::model::item::ItemKind;
use klav_core::model::passkey::Passkey;
use klav_core::model::{Item, SealedItem, open_item, seal_item};
use klav_core::passkey::rp;
use klav_core::passkey::webauthn;
use klav_proto::Blob;
use klav_proto::vault::Item as WireItem;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::{ClientError, ClientResult};
use crate::home::{Home, write_private};
use crate::passkeys::{PasskeyCreateRequest, Prepared, ReadyPasskey};
use crate::session::{ItemLocation, Unlocked, now_ms};
use crate::state::Cache;

const B64: data_encoding::Encoding = data_encoding::BASE64URL_NOPAD;

/// File of the passkey outbox, in the home directory.
pub const PASSKEY_OUTBOX_FILE: &str = "outbox.bin";
/// Where an outbox this account cannot open goes, as
/// `outbox.unreadable-<ms>.bin`: one an earlier sign-in on this device
/// sealed with its own local key, or a damaged one. Each keeps its own
/// name (a second one never replaces the first), for a look; sign-out
/// removes them with the rest of the account.
pub const PASSKEY_OUTBOX_UNREADABLE_PREFIX: &str = "outbox.unreadable-";
/// What is said when an outbox had to be set aside.
pub(crate) const SET_ASIDE: &str = "the passkey outbox could not be opened (an earlier sign-in on this device wrote it, or it is damaged): it was set aside as outbox.unreadable-<time>.bin, and passkeys work again; what it held is not uploaded";

/// Marks a set-aside outbox the app already reported.
const SEEN: &str = ".seen.bin";

/// The set-aside outboxes in `home` ([`PASSKEY_OUTBOX_UNREADABLE_PREFIX`]).
pub(crate) fn unreadable_outboxes(home: &Home) -> Vec<std::path::PathBuf> {
    let Ok(dir) = std::fs::read_dir(home.file(".")) else {
        return Vec::new();
    };
    dir.filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| {
            p.file_name().and_then(|n| n.to_str()).is_some_and(|n| {
                n.starts_with(PASSKEY_OUTBOX_UNREADABLE_PREFIX) && n.ends_with(".bin")
            })
        })
        .collect()
}
const OUTBOX_VERSION: u32 = 1;
/// Most registrations waiting (a phone that never opens the app).
const MAX_QUEUED_PASSKEYS: usize = 200;
/// Most `passkey.used` events waiting; the oldest go first.
const MAX_QUEUED_USES: usize = 1000;

/// A registration waiting for the app: the item exactly as it will be
/// uploaded. The sections are sealed with the item key, which travels
/// wrapped with the project key; nothing here is in clear.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct QueuedPasskey {
    vault: VaultId,
    project: ProjectId,
    item: ItemId,
    /// `None`: a new login (version 1). `Some(v)`: the next version of an
    /// item that was at version `v` (a replaced passkey).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    base_version: Option<u64>,
    wrapped_key: Blob,
    overview: Blob,
    details: Blob,
    created_at: i64,
}

impl QueuedPasskey {
    fn version(&self) -> u64 {
        self.base_version.map_or(1, |v| v + 1)
    }

    /// The item as the cache would hold it once uploaded.
    fn wire(&self) -> WireItem {
        WireItem {
            id: self.item,
            vault_id: self.vault,
            project_id: self.project,
            version: self.version(),
            revision: 0,
            wrapped_key: Some(self.wrapped_key.clone()),
            overview: Some(self.overview.clone()),
            details: Some(self.details.clone()),
            created_at: self.created_at,
            updated_at: self.created_at,
            trashed_at: None,
            purged_at: None,
            // The person registered it: their version (ADR 0030 §7).
            author_agent_id: None,
        }
    }
}

/// A sign-in waiting to be logged (`passkey.used`).
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct QueuedUse {
    /// Random, to remove exactly what was sent.
    id: String,
    item: ItemId,
    at: i64,
}

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawOutbox {
    v: u32,
    #[serde(default)]
    passkeys: Vec<QueuedPasskey>,
    #[serde(default)]
    used: Vec<QueuedUse>,
}

fn read(home: &Home, key: &LocalKey, ctx: &LocalContext) -> ClientResult<RawOutbox> {
    let blob = match std::fs::read(home.file(PASSKEY_OUTBOX_FILE)) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(RawOutbox {
                v: OUTBOX_VERSION,
                ..RawOutbox::default()
            });
        }
        Err(e) => return Err(e.into()),
    };
    let plain = open_local_outbox(key, ctx, &blob)?;
    let raw: RawOutbox = serde_json::from_slice(&plain)
        .map_err(|_| ClientError::Corrupt("passkey outbox".into()))?;
    if raw.v != OUTBOX_VERSION {
        return Err(ClientError::Corrupt("passkey outbox version".into()));
    }
    Ok(raw)
}

fn write(home: &Home, key: &LocalKey, ctx: &LocalContext, raw: &RawOutbox) -> ClientResult<()> {
    let path = home.file(PASSKEY_OUTBOX_FILE);
    if raw.passkeys.is_empty() && raw.used.is_empty() {
        return match std::fs::remove_file(&path) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.into()),
            _ => Ok(()),
        };
    }
    let json = Zeroizing::new(serde_json::to_vec(raw).expect("outbox serializes"));
    write_private(&path, &seal_local_outbox(key, ctx, &json))
}

/// [`read`], with the home's lock held. An outbox this account cannot open
/// would never open again and would break every later passkey use on this
/// device: it is moved aside (`true`: the caller reports it).
fn load(home: &Home, key: &LocalKey, ctx: &LocalContext) -> ClientResult<(RawOutbox, bool)> {
    match read(home, key, ctx) {
        Ok(raw) => Ok((raw, false)),
        Err(ClientError::Crypto(_) | ClientError::Corrupt(_)) => {
            // A name of its own, never an earlier set-aside one.
            let mut at = now_ms();
            let aside = loop {
                let name = home.file(&format!("{PASSKEY_OUTBOX_UNREADABLE_PREFIX}{at}.bin"));
                if !name.exists() {
                    break name;
                }
                at += 1;
            };
            std::fs::rename(home.file(PASSKEY_OUTBOX_FILE), aside)?;
            Ok((
                RawOutbox {
                    v: OUTBOX_VERSION,
                    ..RawOutbox::default()
                },
                true,
            ))
        }
        Err(e) => Err(e),
    }
}

/// Reads, changes and writes the outbox under the home's lock.
fn change<T>(
    home: &Home,
    key: &LocalKey,
    ctx: &LocalContext,
    f: impl FnOnce(&mut RawOutbox) -> ClientResult<T>,
) -> ClientResult<T> {
    let _lock = home.lock()?;
    let (mut raw, _) = load(home, key, ctx)?;
    let out = f(&mut raw)?;
    write(home, key, ctx, &raw)?;
    Ok(out)
}

/// The queued registrations that still apply over `cache`, by item: a new
/// login the cache does not have yet, or the next version of an item the
/// cache still has at its base version.
pub(crate) fn overlay(
    home: &Home,
    key: &LocalKey,
    ctx: &LocalContext,
    cache: &Cache,
) -> ClientResult<Vec<(VaultId, WireItem)>> {
    let raw = read(home, key, ctx)?;
    Ok(raw
        .passkeys
        .iter()
        .filter(|q| {
            let cached = cache
                .vaults
                .get(&q.vault)
                .and_then(|v| v.items.get(&q.item));
            match (q.base_version, cached) {
                (None, None) => true,
                (Some(v), Some(c)) => c.version == v,
                _ => false,
            }
        })
        .map(|q| (q.vault, q.wire()))
        .collect())
}

/// A passkey for the platform's list of credentials
/// (`ASPasskeyCredentialIdentity`). Nothing secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasskeyIdentity {
    /// The login.
    pub item: ItemId,
    /// Its title.
    pub title: String,
    /// Relying party ID.
    pub rp_id: String,
    /// `user.name`.
    pub user_name: String,
    /// Credential ID.
    pub credential_id: Vec<u8>,
    /// User handle.
    pub user_handle: Vec<u8>,
}

/// A signature over a `clientDataHash` the platform built (iOS hands the
/// hash, not the JSON). Nothing secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasskeyHashAssertion {
    /// Credential ID.
    pub credential_id: Vec<u8>,
    /// Authenticator data.
    pub authenticator_data: Vec<u8>,
    /// ES256 signature (DER).
    pub signature: Vec<u8>,
    /// User handle.
    pub user_handle: Vec<u8>,
    /// The login that signed.
    pub item: ItemId,
}

/// A registration made without network. Nothing secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasskeyQueuedRegistration {
    /// Credential ID.
    pub credential_id: Vec<u8>,
    /// Attestation object (`fmt: none`).
    pub attestation_object: Vec<u8>,
    /// Authenticator data.
    pub authenticator_data: Vec<u8>,
    /// The login, already usable on this device; it syncs when the app opens.
    pub item: ItemId,
    /// Its title.
    pub title: String,
}

/// How a registration without network ends.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum PasskeyQueuedOutcome {
    /// Created and queued.
    Created(Box<PasskeyQueuedRegistration>),
    /// Klav holds one of the excluded credentials (only after presence, T86).
    Excluded,
    /// The account already has a passkey in `item`: ask, then `replace`.
    Exists {
        /// The login.
        item: ItemId,
        /// Its title.
        title: String,
    },
}

/// What waits in the outbox, for «Open Klav to sync this passkey».
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasskeyOutbox {
    /// The logins with a queued passkey, by title.
    pub passkeys: Vec<(ItemId, String)>,
    /// Sign-ins waiting to be logged.
    pub uses: usize,
}

/// What the flush did.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasskeyOutboxFlush {
    /// Registrations uploaded (or found already on the server).
    pub uploaded: usize,
    /// New logins renamed because another item took their title.
    pub renamed: usize,
    /// `passkey.used` events sent.
    pub uses_sent: usize,
    /// Entries left for the next time (the error of the first one).
    pub left: usize,
    /// Why the first entry left failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Outboxes set aside (by this flush or by the AutoFill extension's
    /// write, [`SET_ASIDE`]) that the app has not acknowledged yet
    /// ([`acknowledge_set_aside_outboxes`]): counted again until it does,
    /// so a flush whose report nobody saw loses nothing.
    #[serde(default)]
    pub set_aside: usize,
    /// The names of those outboxes, to acknowledge exactly these once the
    /// notice is shown: one set aside later is not covered.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub set_aside_ids: Vec<String>,
}

impl Unlocked {
    /// Every passkey this device can sign with: the synced ones and the
    /// queued ones, sorted by title.
    pub fn passkey_identities(&self) -> ClientResult<Vec<PasskeyIdentity>> {
        let mut out = Vec::new();
        for (loc, summary, _) in self.live_items() {
            if summary.kind != ItemKind::Login || summary.passkey.is_none() {
                continue;
            }
            let item = self.open_item(loc)?;
            let Some(p) = item.passkey() else { continue };
            out.push(PasskeyIdentity {
                item: loc.item,
                title: summary.title,
                rp_id: p.rp_id().to_owned(),
                user_name: p.user_name().to_owned(),
                credential_id: p.credential_id().to_vec(),
                user_handle: p.user_handle().to_vec(),
            });
        }
        Ok(out)
    }

    /// Signs for `rp_id` with the passkey `credential_id` over the
    /// platform's `client_data_hash`, with UV (iOS asked for Face ID to
    /// open the extension, ADR 0020 §8), and queues its `passkey.used`.
    pub fn passkey_assert_hash(
        &self,
        rp_id: &str,
        credential_id: &[u8],
        client_data_hash: &[u8],
    ) -> ClientResult<PasskeyHashAssertion> {
        let hash: [u8; 32] = client_data_hash
            .try_into()
            .map_err(|_| ClientError::Invalid("clientDataHash is not 32 bytes".into()))?;
        let wanted = B64.encode(credential_id);
        for (loc, summary, _) in self.live_items() {
            if summary
                .passkey
                .as_ref()
                .is_none_or(|p| p.rp_id != rp_id || p.credential_id != wanted)
            {
                continue;
            }
            let item = self.open_item(loc)?;
            let Some(passkey) = item.passkey().filter(|p| p.rp_id() == rp_id) else {
                continue;
            };
            let key = passkey.open_key(
                self.vault_key(loc.vault)?.0,
                &self.vault_ctx(loc.vault)?,
                loc.item,
            )?;
            let assertion = webauthn::assert(&key, rp_id, true, &hash);
            // The sign-in is done: if its `passkey.used` cannot be queued,
            // the event is lost (it is best effort, ADR 0020 §10), not the
            // assertion the page waits for. Once the server deleted the
            // account the copy still signs in, read-only, but queues
            // nothing: no audit log is left to take it (ADR 0037 §3).
            if !self.account_deleted() {
                let _ = self.queue_passkey_used(loc.item);
            }
            return Ok(PasskeyHashAssertion {
                credential_id: passkey.credential_id().to_vec(),
                authenticator_data: assertion.authenticator_data,
                signature: assertion.signature,
                user_handle: passkey.user_handle().to_vec(),
                item: loc.item,
            });
        }
        Err(ClientError::NotFound("this passkey".into()))
    }

    fn queue_passkey_used(&self, item: ItemId) -> ClientResult<()> {
        let id = B64.encode(&rand_bytes());
        change(&self.home, &self.local_key, &self.ctx, |raw| {
            raw.used.push(QueuedUse {
                id,
                item,
                at: now_ms(),
            });
            if raw.used.len() > MAX_QUEUED_USES {
                let extra = raw.used.len() - MAX_QUEUED_USES;
                raw.used.drain(..extra);
            }
            Ok(())
        })
    }

    /// Registers a passkey without network for `request` (its `origin` is
    /// `https://<rp_id>`; iOS checked the app's associated domains). The
    /// same rules as [`Unlocked::passkey_create`]; the login goes to the
    /// outbox and is usable at once on this device.
    pub fn passkey_register_queued(
        &mut self,
        request: &PasskeyCreateRequest,
    ) -> ClientResult<PasskeyQueuedOutcome> {
        let rp = rp::validate(&request.origin, request.rp_id.as_deref())
            .map_err(|e| ClientError::Invalid(format!("not a passkey site: {e}")))?;
        let ready = match self.prepare_passkey(&rp, request, true)? {
            Prepared::Excluded => return Ok(PasskeyQueuedOutcome::Excluded),
            Prepared::Exists { item, title } => {
                return Ok(PasskeyQueuedOutcome::Exists { item, title });
            }
            Prepared::Ready(ready) => *ready,
        };
        let ReadyPasskey {
            loc,
            item,
            new,
            registration,
            ..
        } = ready;
        let credential_id = item
            .passkey()
            .map(|p| p.credential_id().to_vec())
            .ok_or_else(|| ClientError::Corrupt("new passkey missing".into()))?;
        let queued = self.seal_for_queue(loc, &item, new)?;
        change(&self.home, &self.local_key, &self.ctx, |raw| {
            if raw.passkeys.len() >= MAX_QUEUED_PASSKEYS {
                return Err(ClientError::Invalid(
                    "too many passkeys wait for the app: open Klav to sync them".into(),
                ));
            }
            // A newer replacement of the same login takes the place of the old one.
            raw.passkeys.retain(|q| q.item != queued.item);
            raw.passkeys.push(queued);
            Ok(())
        })?;
        self.rebuild();
        Ok(PasskeyQueuedOutcome::Created(Box::new(
            PasskeyQueuedRegistration {
                credential_id,
                attestation_object: registration.attestation_object,
                authenticator_data: registration.auth_data,
                item: loc.item,
                title: item.title().to_owned(),
            },
        )))
    }

    /// Seals `item` as it will be uploaded: version 1 with a new item key
    /// when the server does not have the login yet (new, or itself still
    /// queued), else the next version of what the synced cache holds, with
    /// the login's own key.
    fn seal_for_queue(
        &self,
        loc: ItemLocation,
        item: &Item,
        new: bool,
    ) -> ClientResult<QueuedPasskey> {
        let account = self.vault_key(loc.vault)?.1;
        let ctx = ItemContext {
            account,
            vault: loc.vault,
            project: loc.project,
            item: loc.item,
        };
        let synced = self
            .cache
            .vaults
            .get(&loc.vault)
            .and_then(|v| v.items.get(&loc.item))
            .filter(|_| !new);
        let (base_version, key, wrapped) = match synced {
            None => {
                let project = self
                    .projects
                    .get(&loc.project)
                    .ok_or_else(|| ClientError::NotFound(format!("project {}", loc.project)))?;
                let key = ItemKey::generate();
                let wrapped = Blob::new(wrap_item_key(&project.key, &ctx, &key));
                (None, key, wrapped)
            }
            Some(wire) => {
                if wire.trashed_at.is_some() {
                    return Err(ClientError::Invalid("the item is in the trash".into()));
                }
                let wrapped = wire
                    .wrapped_key
                    .clone()
                    .ok_or_else(|| ClientError::Corrupt("item without key".into()))?;
                let project = self
                    .projects
                    .get(&wire.project_id)
                    .ok_or_else(|| ClientError::NotFound(format!("project {}", wire.project_id)))?;
                let key = unwrap_item_key(&project.key, &ctx, wrapped.as_bytes())?;
                (Some(wire.version), key, wrapped)
            }
        };
        let sealed = seal_item(&key, &ctx, base_version.map_or(1, |v| v + 1), item);
        Ok(QueuedPasskey {
            vault: loc.vault,
            project: loc.project,
            item: loc.item,
            base_version,
            wrapped_key: wrapped,
            overview: Blob::new(sealed.overview),
            details: Blob::new(sealed.details),
            created_at: now_ms(),
        })
    }

    /// What waits in the outbox.
    pub fn passkey_outbox(&self) -> ClientResult<PasskeyOutbox> {
        let (raw, _) = {
            let _lock = self.home.lock()?;
            load(&self.home, &self.local_key, &self.ctx)?
        };
        let mut passkeys = Vec::new();
        for q in &raw.passkeys {
            let title = self
                .open_queued(q)
                .map_or_else(|_| q.item.to_string(), |i| i.title().to_owned());
            passkeys.push((q.item, title));
        }
        Ok(PasskeyOutbox {
            passkeys,
            uses: raw.used.len(),
        })
    }

    /// The item a queued registration holds.
    fn open_queued(&self, q: &QueuedPasskey) -> ClientResult<Item> {
        let project = self
            .projects
            .get(&q.project)
            .filter(|p| p.vault == q.vault)
            .ok_or_else(|| ClientError::NotFound(format!("project {}", q.project)))?;
        let ctx = ItemContext {
            account: self.vault_key(q.vault)?.1,
            vault: q.vault,
            project: q.project,
            item: q.item,
        };
        let key = unwrap_item_key(&project.key, &ctx, q.wrapped_key.as_bytes())?;
        let sealed = SealedItem {
            overview: q.overview.as_bytes().to_vec(),
            details: q.details.as_bytes().to_vec(),
        };
        let item = open_item(&key, &ctx, q.version(), &sealed)?;
        if item.id() != q.item {
            return Err(ClientError::Corrupt("passkey outbox item ID".into()));
        }
        Ok(item)
    }

    /// Uploads what the outbox holds (the app, in the foreground): each
    /// registration as a normal create or update, then the `passkey.used`
    /// events. Removes only what went through; the rest waits for the next
    /// time.
    pub async fn flush_passkey_outbox(&mut self) -> ClientResult<PasskeyOutboxFlush> {
        let (raw, set_aside, newly_aside) = {
            let _lock = self.home.lock()?;
            let (raw, set_aside) = load(&self.home, &self.local_key, &self.ctx)?;
            (raw, set_aside, unreported(&self.home))
        };
        let (newly_aside, aside_ids) = (newly_aside.len(), newly_aside);
        if set_aside {
            self.warnings.push(SET_ASIDE.to_owned());
            self.rebuild();
            return Ok(PasskeyOutboxFlush {
                error: Some(SET_ASIDE.to_owned()),
                set_aside: newly_aside,
                set_aside_ids: aside_ids,
                ..PasskeyOutboxFlush::default()
            });
        }
        if raw.passkeys.is_empty() && raw.used.is_empty() {
            return Ok(PasskeyOutboxFlush {
                set_aside: newly_aside,
                set_aside_ids: aside_ids,
                ..PasskeyOutboxFlush::default()
            });
        }
        // The queue must not hide the server's versions while it is sent.
        self.outbox_paused = true;
        let result = self.flush_entries(&raw).await;
        self.outbox_paused = false;
        let (mut report, sent_passkeys, sent_uses) = result?;
        report.set_aside = newly_aside;
        report.set_aside_ids = aside_ids;
        change(&self.home, &self.local_key, &self.ctx, |now| {
            now.passkeys.retain(|q| {
                !sent_passkeys
                    .iter()
                    .any(|(item, at)| *item == q.item && *at == q.created_at)
            });
            now.used.retain(|u| !sent_uses.contains(&u.id));
            Ok(())
        })?;
        self.rebuild();
        Ok(report)
    }

    async fn flush_entries(
        &mut self,
        raw: &RawOutbox,
    ) -> ClientResult<(PasskeyOutboxFlush, Vec<(ItemId, i64)>, Vec<String>)> {
        self.sync().await?;
        let mut report = PasskeyOutboxFlush::default();
        let mut sent_passkeys = Vec::new();
        let mut sent_uses = Vec::new();
        for q in &raw.passkeys {
            match self.flush_one(q, &mut report).await {
                Ok(()) => {
                    report.uploaded += 1;
                    sent_passkeys.push((q.item, q.created_at));
                }
                Err(e) => {
                    report.left += 1;
                    report.error.get_or_insert_with(|| e.to_string());
                }
            }
        }
        if report.uploaded > 0 {
            self.sync().await?;
        }
        for u in &raw.used {
            // A sign-in with a passkey still waiting to upload waits too.
            if raw.passkeys.iter().any(|q| q.item == u.item)
                && !sent_passkeys.iter().any(|(item, _)| *item == u.item)
            {
                report.left += 1;
                continue;
            }
            match self.log_passkey_used(u.item, None).await {
                Ok(()) => {
                    report.uses_sent += 1;
                    sent_uses.push(u.id.clone());
                }
                // The login is gone (deleted elsewhere): nothing to log.
                Err(ClientError::NotFound(_)) => sent_uses.push(u.id.clone()),
                Err(e) => {
                    report.left += 1;
                    report.error.get_or_insert_with(|| e.to_string());
                }
            }
        }
        Ok((report, sent_passkeys, sent_uses))
    }

    async fn flush_one(
        &mut self,
        q: &QueuedPasskey,
        report: &mut PasskeyOutboxFlush,
    ) -> ClientResult<()> {
        let mut queued = self.open_queued(q)?;
        let passkey = queued
            .passkey()
            .cloned()
            .ok_or_else(|| ClientError::Corrupt("queued login without passkey".into()))?;
        let loc = ItemLocation {
            vault: q.vault,
            project: q.project,
            item: q.item,
        };
        let cached = self.item_parts(loc).ok().map(|(_, _, w)| w.version);
        match (q.base_version, cached) {
            (None, None) => {
                let title = queued.title().to_owned();
                let mut name = title.clone();
                let mut n = 2;
                while self
                    .titled(q.vault, q.project, &name)
                    .iter()
                    .any(|s| s.id != q.item)
                {
                    name = format!("{title} ({n})");
                    n += 1;
                }
                if name != title {
                    queued.set_title(&name)?;
                    report.renamed += 1;
                }
                self.post_item(q.vault, q.project, &queued).await?;
                Ok(())
            }
            (Some(base), Some(version)) if version == base => {
                self.put_item(loc, &queued, &[]).await
            }
            // The server has the login at another version than the one this
            // entry was sealed over: uploaded before and not removed from
            // the queue (the same passkey), or changed meanwhile, here or
            // elsewhere (another passkey). A new login queued again after
            // its first upload is a replacement too (T138: only what the
            // server took leaves the queue).
            (_, Some(_)) => self.merge_queued_passkey(loc, passkey, report).await,
            (Some(_), None) => Err(ClientError::NotFound(format!("item {}", q.item))),
        }
    }

    /// Puts a queued passkey on the login's current version. The newer of
    /// the two passkeys (by `created_at`) is the current one; the other
    /// stays in the login's history (the server keeps its versions), so no
    /// key is lost.
    async fn merge_queued_passkey(
        &mut self,
        loc: ItemLocation,
        passkey: Passkey,
        report: &mut PasskeyOutboxFlush,
    ) -> ClientResult<()> {
        let mut current = self.open_item(loc)?;
        let theirs = current.passkey().cloned();
        if theirs
            .as_ref()
            .is_some_and(|p| p.credential_id() == passkey.credential_id())
        {
            return Ok(());
        }
        // That version may be an agent's: its sites stay unconfirmed.
        self.drop_pending_urls(loc, &mut current)?;
        let Some(newer) = theirs.filter(|p| p.created_at() > passkey.created_at()) else {
            current.set_passkey(passkey)?;
            return self.put_item(loc, &current, &[]).await;
        };
        // Another device registered a newer one: it stays current. The
        // queued one goes in a version of its own first, so it is in the
        // history; once that version is up, the entry is done.
        let queued = passkey.credential_id().to_vec();
        current.set_passkey(passkey)?;
        self.put_item(loc, &current, &[]).await?;
        let restored = async {
            // The newer passkey goes back on the version the server has
            // now, not on a copy from before: whatever another device
            // wrote meanwhile stays. If that device already changed the
            // passkey, its choice stands.
            self.sync().await?;
            let mut now = self.open_item(loc)?;
            if now.passkey().map(Passkey::credential_id) != Some(queued.as_slice()) {
                return Ok(());
            }
            self.drop_pending_urls(loc, &mut now)?;
            now.set_passkey(newer)?;
            self.put_item(loc, &now, &[]).await
        }
        .await;
        if let Err(e) = restored {
            // Both passkeys are on the server; only which one is current
            // is off. Said, and not retried as if nothing were uploaded.
            report.error.get_or_insert_with(|| {
                format!("a newer passkey from another device is in the login's history, not current: {e}")
            });
        }
        Ok(())
    }
}

/// The set-aside outboxes the app has not acknowledged yet.
fn unacknowledged(home: &Home) -> Vec<std::path::PathBuf> {
    unreadable_outboxes(home)
        .into_iter()
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| !n.ends_with(SEEN))
        })
        .collect()
}

/// The names of the set-aside outboxes the app has not acknowledged yet,
/// sorted.
fn unreported(home: &Home) -> Vec<String> {
    let mut names: Vec<String> = unacknowledged(home)
        .iter()
        .filter_map(|p| p.file_name().and_then(|n| n.to_str()).map(str::to_owned))
        .collect();
    names.sort();
    names
}

/// Marks the set-aside outboxes named in `ids` as reported
/// (`…-<ms>.seen.bin`), once the app has shown the person the notice that
/// counted them ([`PasskeyOutboxFlush::set_aside_ids`]): they are not
/// counted again. Only those: one set aside since is still reported. Names
/// that are not an unacknowledged set-aside outbox are ignored. Returns
/// how many it marked.
pub fn acknowledge_set_aside_outboxes(home: &Home, ids: &[String]) -> ClientResult<usize> {
    let _lock = home.lock()?;
    let mut count = 0;
    for path in unacknowledged(home) {
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !ids.iter().any(|id| id == name) {
            continue;
        }
        let seen = path.with_file_name(format!("{}{SEEN}", name.trim_end_matches(".bin")));
        std::fs::rename(&path, seen)?;
        count += 1;
    }
    Ok(count)
}

/// What the person agreed to lose with this device's copy: at most this
/// many passkeys and generated passwords that never went up.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AcceptedUnsent {
    /// Passkeys registered offline, only in [`PASSKEY_OUTBOX_FILE`].
    pub passkeys: usize,
    /// Generated passwords, only in the generator outbox
    /// ([`crate::history::OUTBOX_FILE`]).
    pub generated: usize,
}

/// Removes this device's copy of the account (sign-out, or deleting the
/// copy of a deleted account), unless more is waiting to upload than the
/// person agreed to lose (`accepted`; `None`: whatever is there, when Klav
/// could not count or the person chose to lose it). Counted and removed
/// under the home's lock, so a passkey the AutoFill extension saves
/// meanwhile is either counted or written after the removal: never deleted
/// unseen. With `open` (the account unlocked) both outboxes are counted;
/// without it, any outbox file counts as more than none (ADR 0037, Q3 of
/// the re-review: the generated passwords count too).
pub fn forget_account_unless_queued(
    home: &Home,
    open: Option<&Unlocked>,
    accepted: Option<AcceptedUnsent>,
) -> ClientResult<()> {
    let _lock = home.lock()?;
    if let Some(max) = accepted {
        match open {
            Some(u) => {
                let passkeys = load(home, &u.local_key, &u.ctx)?.0.passkeys.len();
                let generated = u.unsent_generated()?;
                if passkeys > max.passkeys || generated > max.generated {
                    return Err(ClientError::Denied(format!(
                        "{passkeys} passkey(s) and {generated} generated password(s) are not uploaded yet and would be lost: upload them or copy them first, or delete this copy anyway"
                    )));
                }
            }
            // Locked: the outboxes cannot be counted, so any is too many.
            None => {
                let waiting = [PASSKEY_OUTBOX_FILE, crate::history::OUTBOX_FILE]
                    .iter()
                    .any(|name| home.file(name).try_exists().unwrap_or(true));
                if waiting {
                    return Err(ClientError::Denied(
                        "Klav is locked and passkeys or generated passwords may be waiting to upload: unlock to upload or copy them, or delete this copy anyway".into(),
                    ));
                }
            }
        }
    }
    crate::auth::forget_account(home);
    Ok(())
}

fn rand_bytes() -> [u8; 16] {
    let mut b = [0u8; 16];
    klav_core::crypto::random::fill(&mut b);
    b
}
