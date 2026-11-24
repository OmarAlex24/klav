//! Klav client bindings for Swift and Kotlin (uniffi, ADR 0018).
//!
//! One object, [`KlavCore`], wraps `klav-client` for the mobile apps: sign
//! in on a new device, unlock (master password or Face ID), sync, browse and
//! edit items, TOTP and the codes of `otpauth://` links (`codes`, ADR
//! 0035), approvals, task requests and agent registrations, the agents'
//! pauses and activity on the audit log (`pause`, `activity`, ADR 0033
//! §9), revoking an agent and changing its grant (`grants`, the amendment
//! of 2026-11-10), the vault health and assisted password changes (`health`), and
//! what the iOS AutoFill extension needs. Every method blocks until it finishes; the app
//! calls them off the main thread.
//!
//! No cryptography lives here: everything goes through `klav-client` and
//! `klav-core`. The platform keystore (Secure Enclave) is a foreign trait
//! implemented in Swift ([`PlatformKeystore`]).
//!
//! Secret values (the master password in, revealed fields and codes out)
//! cross the FFI as plain strings; the app keeps them only while a view
//! shows them (threat model, mobile section).

use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use klav_client::agents::{AgentView, GrantRequest};
use klav_client::ops::{FieldInput, ItemPatch, NewItem, SecretText};
use klav_client::passkey_outbox::PasskeyQueuedOutcome;
use klav_client::passkeys::PasskeyCreateRequest;
use klav_client::secret_requests::{FulfillSecretRequest, FulfillSecretResult, SecretRequestCard};
use klav_client::tasks::{TaskCard, TaskChoice};
use klav_client::{Home, ItemFilter, ItemLocation, LoginRequest, Unlocked};
use klav_core::crypto::kdf::MasterPassword;
use klav_core::crypto::secret_key::SecretKey;
use klav_core::ids::{AgentId, ApprovalId, ItemId, ProjectId, SecretRequestId, TaskId, VaultId};
use klav_core::model::item::{FieldKind, FieldValue, ItemKind};
use klav_core::policy::{Permission, Policy};
use klav_core::site;
use klav_core::totp::Totp;
use klav_proto::auth::{DeviceKind, PushEnvironment};
use secrecy::ExposeSecret;
use serde::Serialize;

mod activity;
mod biometric;
mod codes;
#[cfg(feature = "daemon")]
mod daemon;
mod error;
mod grants;
mod health;
mod import;
mod pause;
mod sandboxes;
mod types;

pub use activity::{
    AuditStatusInfo, ItemActivityInfo, ItemUseInfo, LogEntryInfo, LogFilterInput, UnpinnedHead,
    UseHow, VerifyInfo,
};
pub use biometric::{KeystoreError, KeystoreKey, KeystoreWrap, PlatformKeystore};
pub use codes::{CodeLink, CodeLinkInfo, CodeSaveOutcome, CodeState, CodeTarget, NewCodeLogin};
#[cfg(feature = "daemon")]
pub use daemon::{BrowserLink, DaemonEngine, DaemonInfo};
pub use error::{KlavError, KlavResult};
pub use grants::*;
pub use health::*;
pub use import::ImportSession;
pub use pause::{AgentPauseInfo, DevAgentInfo, PauseInfo};
pub use sandboxes::{
    ProxyNoSigns, SandboxCheckInfo, SandboxEndInfo, SandboxInfo, SandboxListCheckedInfo,
    SandboxListInfo, SandboxProxyInfo, SandboxRevokeInfo, SandboxSecurityInfo, SandboxStatusInfo,
};
pub use types::*;

uniffi::setup_scaffolding!();

/// Version of `klav-core` this library is built against.
#[uniffi::export]
pub fn core_version() -> String {
    klav_core::VERSION.to_owned()
}

/// The server the app signs in to unless the person opens «Use my own
/// server» (ADR 0028 §2); `None` when `KLAV_NO_DEFAULT_SERVER` is set
/// (the tests).
#[uniffi::export]
pub fn default_server() -> Option<String> {
    klav_client::server::default_server().map(str::to_owned)
}

/// The server a person typed in «Use my own server»: `https://` added
/// when missing; `klav.dev`, `api.klav.dev` and old URLs of klav.dev mean
/// the default (ADR 0028 §3).
#[uniffi::export]
pub fn server_from_input(text: String) -> KlavResult<String> {
    Ok(klav_client::server::from_input(&text)?)
}

/// How the interface names a server: «klav.dev» for the default, else its
/// host.
#[uniffi::export]
pub fn server_name(server: String) -> String {
    klav_client::server::display_name(&server)
}

/// A random password (`length` characters; letters and digits, plus
/// symbols when `symbols`).
#[uniffi::export]
pub fn generate_password(length: u32, symbols: bool) -> KlavResult<String> {
    let policy = klav_core::generator::PasswordPolicy {
        length: usize::try_from(length).unwrap_or(usize::MAX),
        symbols,
        ..Default::default()
    };
    let password = klav_core::generator::generate_password(&policy)
        .map_err(|e| KlavError::invalid(e.to_string()))?;
    Ok(password.expose_secret().to_owned())
}

/// A password from the generator (ADR 0022 §1), following the bundled
/// rules of `host` when the type is `smart`.
#[uniffi::export]
pub fn generate(input: GeneratorInput, host: Option<String>) -> KlavResult<GeneratedPassword> {
    use klav_core::generator::{RulesFallback, RulesSource, SiteHints, Strength};
    let as_usize = |n: u32| usize::try_from(n).unwrap_or(usize::MAX);
    let options = klav_core::generator::GeneratorOptions {
        kind: input.kind.into(),
        length: as_usize(input.length),
        digits: input.digits,
        symbols: input.symbols,
        avoid_ambiguous: true,
        words: as_usize(input.words),
        pin_length: as_usize(input.pin_length),
        ..Default::default()
    };
    let site = SiteHints {
        host: host.as_deref().and_then(klav_core::site::item_host),
        ..SiteHints::default()
    };
    let g = klav_core::generator::generate(&options, &site)
        .map_err(|e| KlavError::invalid(e.to_string()))?;
    Ok(GeneratedPassword {
        value: g.value.expose_secret().to_owned(),
        bits: g.bits,
        strength: match g.strength {
            Strength::Weak => "weak",
            Strength::Fair => "fair",
            Strength::Strong => "strong",
            Strength::VeryStrong => "very_strong",
        }
        .to_owned(),
        rules_domain: match g.rules {
            Some(RulesSource::Bundled { domain }) => Some(domain),
            _ => None,
        },
        limited: g.limited,
        fallback: g.fallback.map(|f| {
            match f {
                RulesFallback::Unreadable => "unreadable",
                RulesFallback::Impossible => "impossible",
            }
            .to_owned()
        }),
    })
}

/// The host an iOS service identifier stands for: a URL (`https://…`) or
/// a bare domain (`github.com`). Only `https` (or `http` on this device)
/// qualifies, as in the browser extension (ADR 0017 §5).
#[uniffi::export]
pub fn service_host(service: String) -> KlavResult<String> {
    let service = service.trim();
    let url = if service.contains("://") {
        service.to_owned()
    } else {
        format!("https://{service}")
    };
    site::fillable_host(&url).map_err(|e| KlavError::SiteMismatch {
        message: e.to_string(),
    })
}

/// How the site `host` relates to a login's `urls` (ADR 0025 §3); `None`
/// when the login is not for it at all.
#[uniffi::export]
pub fn site_relation(host: String, urls: Vec<String>) -> Option<SiteRelation> {
    site::host_relation(&host, &urls).map(SiteRelation::from)
}

/// The account in one home directory, locked or unlocked.
#[derive(uniffi::Object)]
pub struct KlavCore {
    home: Home,
    runtime: tokio::runtime::Runtime,
    /// The unlocked account while no call is using it. Held only for an
    /// instant: a call takes the account out for its duration (network
    /// included), so `status()` and `lock()` never wait for a sync that
    /// hangs.
    unlocked: Mutex<Option<Unlocked>>,
    /// Serialises the calls that use the account.
    calls: Mutex<()>,
    /// Whether the account is unlocked (also while a call holds it).
    is_unlocked: AtomicBool,
    /// Bumped by every lock: a call in flight does not put the account
    /// back when it ends, and its result is not returned. Its keys go,
    /// unless the vault is being opened again ([`Self::opening`]).
    generation: AtomicU64,
    /// The account's pairing words, for `status()`.
    words: Mutex<Option<String>>,
    /// Unlocks under way, and the session of a call that ended after a
    /// lock while one was. Taken after [`Self::unlocked`], never before.
    opening: Mutex<Opening>,
}

/// See [`KlavCore::opening`].
#[derive(Default)]
struct Opening {
    unlocks: u32,
    /// The session of a call in flight when the person locked, that ended
    /// while the vault was being opened again: it holds what that call
    /// wrote, which the session being opened may have read too early.
    ended: Option<Unlocked>,
}

/// An unlock under way ([`KlavCore::opening`]): while one is, a call that
/// ends after a lock hands its session over instead of dropping it. When
/// the last one ends, a session nobody took goes.
struct Unlocking<'a>(&'a KlavCore);

impl<'a> Unlocking<'a> {
    fn start(core: &'a KlavCore) -> Self {
        guard(&core.opening).unlocks += 1;
        Self(core)
    }
}

impl Drop for Unlocking<'_> {
    fn drop(&mut self) {
        let left = {
            let mut opening = guard(&self.0.opening);
            opening.unlocks = opening.unlocks.saturating_sub(1);
            if opening.unlocks == 0 {
                opening.ended.take()
            } else {
                None
            }
        };
        drop(left);
    }
}

fn guard<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Whether two sessions are of the same account on the same device sign-in.
fn same_session(a: &Unlocked, b: &Unlocked) -> bool {
    let (a, b) = (a.account(), b.account());
    a.account_id == b.account_id && a.device_id == b.device_id
}

impl KlavCore {
    fn state(&self) -> MutexGuard<'_, Option<Unlocked>> {
        guard(&self.unlocked)
    }

    /// Runs `f` on the unlocked account, without holding the lock that
    /// `status()` and `lock()` use.
    fn with<T>(&self, f: impl FnOnce(&mut Unlocked) -> KlavResult<T>) -> KlavResult<T> {
        let _one = guard(&self.calls);
        let generation = self.generation.load(Ordering::SeqCst);
        let mut unlocked = self.state().take().ok_or(KlavError::Locked)?;
        let result = f(&mut unlocked);
        let mut slot = self.state();
        if self.generation.load(Ordering::SeqCst) != generation {
            // Locked meanwhile: the result is not handed out. A session
            // opened since read the files before this call wrote them (a
            // revocation's record, a key it changed), and a save of its own
            // would write that stale `cache.bin` back over them. It could
            // run no call meanwhile (`calls`), so this session holds all it
            // holds and what this call wrote: it takes its place, or is
            // handed to the unlock under way. Still locked, the keys go now.
            if slot
                .as_ref()
                .is_some_and(|newer| same_session(newer, &unlocked))
            {
                *slot = Some(unlocked);
            } else if slot.is_none() {
                let mut opening = guard(&self.opening);
                if opening.unlocks > 0 {
                    opening.ended = Some(unlocked);
                } else {
                    drop(opening);
                    drop(unlocked);
                }
            } else {
                drop(unlocked);
            }
            return Err(KlavError::Locked);
        }
        if let Some(newer) = slot.as_ref() {
            // Unlocked again while this call ran, with no lock in between
            // (Face ID turned on, `AppModel.enableFaceID`): that session
            // read the files before this call wrote them, and could run no
            // call meanwhile (`calls`). This one holds all it holds and
            // what this call wrote, so it takes its place. Another
            // account's session stays, and this call's result goes.
            if !same_session(newer, &unlocked) {
                drop(unlocked);
                return Err(KlavError::Locked);
            }
        }
        *slot = Some(unlocked);
        result
    }

    /// [`Self::with`] for a call that changes the vault. The copy of a
    /// deleted account is read-only (ADR 0037 §3, D-C): the write is
    /// refused here, without network, so nothing waits in an outbox for
    /// an account that is gone.
    fn writing<T>(&self, f: impl FnOnce(&mut Unlocked) -> KlavResult<T>) -> KlavResult<T> {
        self.with(|u| {
            refuse_deleted(u)?;
            f(u)
        })
    }

    /// Publishes a freshly unlocked account, or a newer session of the
    /// same account: the one already in place (an unlock while unlocked,
    /// after a call put back what it wrote), or the session of a call that
    /// ended after the lock while it was opening ([`Opening::ended`]).
    fn publish(&self, unlocked: Unlocked) {
        let mut slot = self.state();
        let ended = guard(&self.opening).ended.take();
        let unlocked = match (slot.take(), ended) {
            // Unlocked meanwhile, with no lock in between: what is in place
            // was opened before this, or put back by a call that wrote
            // after this read the files.
            (Some(current), ended) if same_session(&current, &unlocked) => {
                drop(ended);
                drop(unlocked);
                current
            }
            (current, Some(ended)) if same_session(&ended, &unlocked) => {
                drop(current);
                drop(unlocked);
                ended
            }
            (current, ended) => {
                drop(current);
                drop(ended);
                unlocked
            }
        };
        *guard(&self.words) = Some(unlocked.account_pairing_code());
        *slot = Some(unlocked);
        self.is_unlocked.store(true, Ordering::SeqCst);
    }

    /// Forgets the account now; a call in flight drops it when it ends.
    fn forget(&self) -> Option<Unlocked> {
        self.generation.fetch_add(1, Ordering::SeqCst);
        self.is_unlocked.store(false, Ordering::SeqCst);
        *guard(&self.words) = None;
        self.state().take()
    }

    /// Keeps `unlocked` and, with a keystore, (re)enrols Face ID.
    fn opened(
        &self,
        unlocked: Unlocked,
        keystore: Option<Arc<dyn PlatformKeystore>>,
    ) -> KlavResult<bool> {
        let enrolled = match keystore {
            Some(k) => biometric::enrol(
                &self.home,
                unlocked.account().local_context(),
                unlocked.local_key(),
                &k,
            )
            .unwrap_or(false),
            None => false,
        };
        self.publish(unlocked);
        Ok(enrolled)
    }
}

fn item_id(id: &str) -> KlavResult<ItemId> {
    ItemId::from_str(id.trim()).map_err(|_| KlavError::invalid(format!("not an item ID: {id}")))
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn wire_name(value: &impl Serialize) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default()
}

fn field_inputs(fields: Vec<FieldEdit>) -> Vec<FieldInput> {
    fields
        .into_iter()
        .map(|f| FieldInput {
            name: f.name,
            value: SecretText::new(f.value),
            kind: f.kind.map(FieldKind::from),
            // Typed in the app, never on a command line.
            secret: true,
        })
        .collect()
}

/// Once this device saw the account deleted (ADR 0037 §3), the copy only
/// reads: no sync and no write, answered without network.
fn refuse_deleted(u: &Unlocked) -> KlavResult<()> {
    if u.account_deleted()
        && let Some(at) = u.account_deletion().map(|d| d.delete_at)
    {
        return Err(klav_client::ClientError::AccountDeleted(at).into());
    }
    Ok(())
}

fn location(u: &Unlocked, id: &str) -> KlavResult<ItemLocation> {
    Ok(u.find_item(&item_id(id)?.to_string())?)
}

/// The host of `service` must belong to one of the login's URLs (T21): its
/// host or a subdomain. A login saved for a subdomain of `service` (ADR
/// 0025) only when `chosen`: the person picked it in the sheet's «Saved
/// for a subdomain» group. QuickType and anything without the person never
/// set it.
fn check_site(u: &Unlocked, loc: ItemLocation, service: &str, chosen: bool) -> KlavResult<()> {
    let host = service_host(service.to_owned())?;
    let summary = u.item_summary(loc)?;
    // Only the sites the person confirmed (ADR 0030 §7).
    let allowed = match site::host_relation(&host, &summary.confirmed_urls) {
        Some(site::HostRelation::Parent) => chosen,
        Some(_) => true,
        None => false,
    };
    if summary.kind != ItemKind::Login || !allowed {
        return Err(KlavError::SiteMismatch {
            message: format!("{} is not saved for this site", summary.title),
        });
    }
    Ok(())
}

fn totp_of(u: &Unlocked, loc: ItemLocation) -> KlavResult<TotpInfo> {
    let item = u.open_item(loc)?;
    let field = item
        .fields()
        .iter()
        .find(|f| f.kind() == FieldKind::Totp && !f.is_empty())
        .ok_or_else(|| KlavError::NotFound {
            message: "this item has no one-time password".into(),
        })?;
    let FieldValue::Secret(secret) = field.value() else {
        return Err(KlavError::invalid("not a one-time password field"));
    };
    let totp = Totp::from_field_value(secret.expose())
        .map_err(|e| KlavError::invalid(format!("invalid one-time password secret: {e}")))?;
    let now = now_secs();
    let code = totp.generate(now);
    Ok(TotpInfo {
        code: code.expose_secret().to_owned(),
        remaining: totp.seconds_remaining(now),
        period: totp.period(),
    })
}

fn task_id(id: &str) -> KlavResult<TaskId> {
    TaskId::from_str(id.trim()).map_err(|_| KlavError::invalid(format!("not a task ID: {id}")))
}

fn secret_request_id(id: &str) -> KlavResult<SecretRequestId> {
    SecretRequestId::from_str(id.trim())
        .map_err(|_| KlavError::invalid(format!("not a secret request ID: {id}")))
}

pub(crate) fn secret_request_item(card: SecretRequestCard) -> SecretRequestItem {
    let (kind, title, vault_id, project_id, field, placeholder, base_url, urls, notes, proxy) =
        match card.proposal {
            Some(p) => (
                p.kind.map(|k| wire_name(&k)),
                p.title,
                p.vault_id.map(|v| v.to_string()),
                p.project_id.map(|id| id.to_string()),
                Some(p.field),
                p.placeholder,
                p.base_url,
                p.urls,
                p.notes,
                p.proxy_proposal.map(|pp| SecretRequestProxyProposalItem {
                    preset: pp.preset,
                    profile: pp.profile,
                    upstream: pp.upstream,
                    header: pp.header,
                    prefix: pp.prefix,
                    methods: pp.methods,
                    ask_methods: pp.ask_methods,
                    path_prefixes: pp.path_prefixes,
                    rate_per_minute: pp.rate_per_minute,
                }),
            ),
            None => (
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                Vec::new(),
                None,
                None,
            ),
        };
    SecretRequestItem {
        id: card.id.to_string(),
        status: card.status.as_str().to_owned(),
        agent_id: card.agent_id.to_string(),
        agent: klav_core::text::shown(&card.agent, MAX_AGENT_TEXT),
        mode: card.mode.as_str().to_owned(),
        target_item_id: card.target_item_id.map(|i| i.to_string()),
        target_reference: card.target_reference,
        target_title: card.target_title,
        target_kind: card.target_kind.map(|k| wire_name(&k)),
        reason: card.reason,
        created_at: card.created_at,
        expires_at: card.expires_at,
        decided_at: card.decided_at,
        proposal_digest: card.proposal_digest,
        proposal_error: card.proposal_error,
        kind,
        title,
        vault_id,
        project_id,
        field,
        placeholder,
        setup_url: card.setup_url.map(|s| SecretRequestSetupUrlItem {
            url: s.url,
            host: s.host,
            has_punycode: s.has_punycode,
        }),
        base_url,
        urls,
        notes,
        proxy_proposal: proxy,
        agent_projects: card
            .agent_projects
            .into_iter()
            .map(|(v, p)| SecretRequestProjectPair {
                vault_id: v.to_string(),
                project_id: p.to_string(),
            })
            .collect(),
    }
}

pub(crate) fn fulfill_secret_request_input(
    input: SecretRequestFulfillInput,
) -> FulfillSecretRequest {
    FulfillSecretRequest {
        digest: input.digest,
        secret: SecretText::new(input.secret),
        vault: input.vault,
        project: input.project,
        title: input.title,
        field: input.field,
        urls: input.urls,
        notes: input.notes.map(SecretText::new),
        allow_duplicate: input.allow_duplicate,
        grant_proxy: input.grant_proxy,
        proxy_base_version: input.proxy_base_version,
        every_device_updated: input.every_device_updated,
        shown_words: input.shown_words,
        proxy_credential: None,
    }
}

pub(crate) fn fulfill_secret_request_output(
    res: FulfillSecretResult,
) -> SecretRequestFulfillOutput {
    SecretRequestFulfillOutput {
        card: secret_request_item(res.card),
        item: ItemInfo::from(res.item),
        in_grant: res.in_grant,
        proxy_profile: res.proxy_profile,
        proxy_warnings: res.proxy_warnings,
    }
}

fn task_item(card: TaskCard) -> TaskItem {
    TaskItem {
        id: card.id.to_string(),
        status: card.status.as_str().to_owned(),
        agent_id: card.agent_id.to_string(),
        agent: klav_core::text::shown(&card.agent, MAX_AGENT_TEXT),
        task: card.task,
        reason: card.reason,
        offered: card.offered,
        duration_secs: card.duration_secs,
        created_at: card.created_at,
        decide_by: card.decide_by,
        decided_at: card.decided_at,
        revision: card.revision,
        expires_at: card.expires_at,
        ended_at: card.ended_at,
        ended_by: card.ended_by.map(|e| e.as_str().to_owned()),
        request_digest: card.request_digest,
        rows: card
            .rows
            .into_iter()
            .map(|r| TaskRowItem {
                vault_id: r.vault_id.to_string(),
                project_id: r.project_id.to_string(),
                item_id: r.item_id.to_string(),
                reference: r.reference,
                title: r.title,
                username: r.username,
                missing: r.missing,
                asked_domain: r.asked_domain,
                domain_mismatch: r.domain_mismatch,
                no_site: r.no_site,
                domain_claimed: r.domain_claimed,
                domains: r.domains,
                permissions: r
                    .permissions
                    .into_iter()
                    .map(|p| TaskPermissionItem {
                        permission: p.permission.as_str().to_owned(),
                        checked: p.checked,
                        asked: p.asked,
                        added_by_klav: p.added_by_klav,
                        denied_by_policy: p.denied_by_policy,
                        no_site: p.no_site,
                    })
                    .collect(),
            })
            .collect(),
    }
}

fn permission(name: &str) -> KlavResult<Permission> {
    serde_json::from_value(serde_json::Value::String(name.trim().to_owned()))
        .map_err(|_| KlavError::invalid(format!("not a permission: {name}")))
}

fn task_choice(input: TaskChoiceInput) -> KlavResult<TaskChoice> {
    let entries = |list: Vec<TaskChoiceEntry>| -> KlavResult<Vec<(ItemId, Option<Permission>)>> {
        list.into_iter()
            .map(|e| {
                Ok((
                    item_id(&e.item_id)?,
                    e.permission.as_deref().map(permission).transpose()?,
                ))
            })
            .collect()
    };
    Ok(TaskChoice {
        without: entries(input.without)?,
        with: entries(input.with)?,
        for_secs: input.for_secs,
    })
}

/// Longest agent name or note shown in the app (the agent chose them).
const MAX_AGENT_TEXT: usize = 64;

fn agent_item(a: AgentView) -> AgentItem {
    AgentItem {
        id: a.id.to_string(),
        // The agent chose its name and note: no control or format
        // characters (bidi, zero-width), and short (layer 06 of the 2026-11
        // round).
        name: klav_core::text::shown(&a.name, MAX_AGENT_TEXT),
        note: a
            .note
            .map(|n| klav_core::text::shown(&n, MAX_AGENT_TEXT))
            .filter(|n| !n.is_empty()),
        status: a.status.as_str().to_owned(),
        pairing_words: a.pairing_code,
        created_at: a.created_at,
        expires_at: a.expires_at,
        projects: a
            .grant
            .map(|g| {
                g.projects
                    .into_iter()
                    .map(|p| format!("{}/{}", p.vault, p.project))
                    .collect()
            })
            .unwrap_or_default(),
    }
}

fn new_item(input: NewItemInput) -> NewItem {
    NewItem {
        kind: input.kind.into(),
        title: input.title,
        vault: input.vault_id,
        project: input.project_id,
        fields: field_inputs(input.fields),
        urls: input.urls,
        tags: input.tags,
        notes: input.notes.map(SecretText::new),
        allow_duplicate: false,
    }
}

fn item_patch(edit: ItemEdit) -> ItemPatch {
    ItemPatch {
        title: edit.title,
        set: field_inputs(edit.set),
        remove: edit.remove,
        add_urls: edit.add_urls,
        remove_urls: edit.remove_urls,
        add_tags: edit.add_tags,
        notes: edit.notes.map(SecretText::new),
        allow_duplicate: false,
    }
}

fn item_filter(query: ItemQuery) -> ItemFilter {
    ItemFilter {
        vault: query.vault_id,
        project: query.project_id,
        kind: query.kind.map(ItemKind::from),
        kinds: query.kinds.into_iter().map(ItemKind::from).collect(),
        codes: query.codes,
        tag: None,
        query: query.text.filter(|t| !t.trim().is_empty()),
        trash: query.trash,
    }
}

/// Live vaults, by name.
fn vault_infos(list: Vec<klav_client::VaultSummary>) -> Vec<VaultInfo> {
    let mut vaults: Vec<VaultInfo> = list
        .into_iter()
        .filter(|v| !v.deleted)
        .map(VaultInfo::from)
        .collect();
    vaults.sort_by_key(|v| v.name.to_lowercase());
    vaults
}

/// Projects, by vault and name.
fn project_infos(list: Vec<klav_client::ProjectSummary>) -> Vec<ProjectInfo> {
    let mut projects: Vec<ProjectInfo> = list.into_iter().map(ProjectInfo::from).collect();
    projects.sort_by_key(|p| (p.vault.to_lowercase(), p.name.to_lowercase()));
    projects
}

/// Items, by title.
fn item_infos(list: Vec<klav_client::ItemSummary>) -> Vec<ItemInfo> {
    let mut items: Vec<ItemInfo> = list.into_iter().map(ItemInfo::from).collect();
    items.sort_by(|a, b| {
        a.title
            .to_lowercase()
            .cmp(&b.title.to_lowercase())
            .then_with(|| a.id.cmp(&b.id))
    });
    items
}

fn generated_entry(e: klav_client::history::GeneratedView) -> GeneratedEntryInfo {
    GeneratedEntryInfo {
        created_at: e.created_at,
        host: e.host,
        saved_in_title: e.saved_in_title,
        pending: e.pending,
    }
}

fn approval_item(a: klav_client::agents::ApprovalView) -> ApprovalItem {
    ApprovalItem {
        id: a.id.to_string(),
        status: wire_name(&a.status),
        agent_id: a.agent_id.to_string(),
        agent: klav_core::text::shown(&a.agent, MAX_AGENT_TEXT),
        permission: wire_name(&a.permission),
        target: a.target,
        reason: a.reason,
        domain: a.domain,
        created_at: a.created_at,
        expires_at: a.expires_at,
        task: a.task.map(|t| OutsideTaskItem {
            id: t.id.to_string(),
            task: t.task,
            expires_at: t.expires_at,
            can_add: t.can_add,
        }),
        request_digest: a.request_digest,
    }
}

/// Pending registrations first, then newest.
fn agent_items(list: Vec<AgentView>) -> Vec<AgentItem> {
    let mut agents: Vec<AgentItem> = list.into_iter().map(agent_item).collect();
    agents.sort_by_key(|a| (a.status != "pending", std::cmp::Reverse(a.created_at)));
    agents
}

/// The grant `approve_agent` signs: the projects, the default policy
/// (design §5.2, as `klav agent approve` without options) and an optional
/// expiry.
fn default_grant(
    project_ids: Vec<String>,
    expires_in_days: Option<u32>,
) -> KlavResult<GrantRequest> {
    for p in &project_ids {
        ProjectId::from_str(p.trim())
            .map_err(|_| KlavError::invalid(format!("not a project ID: {p}")))?;
    }
    let expires_at = expires_in_days
        .filter(|d| *d > 0)
        .map(|days| now_secs() + u64::from(days) * 86_400);
    Ok(GrantRequest {
        projects: project_ids,
        vaults: Vec::new(),
        policy: Policy {
            rules: Vec::new(),
            expires_at,
        },
    })
}

/// This device's kind on the server: the iPhone, or the Mac (ADR 0027 §3),
/// whose device the CLI and `klavd` share.
const DEVICE_KIND: DeviceKind = if cfg!(target_os = "macos") {
    DeviceKind::Macos
} else {
    DeviceKind::Ios
};

#[uniffi::export]
impl KlavCore {
    /// The account stored in `home_dir` (on iOS, `<App Group>/klav`).
    /// Nothing is read or unlocked yet.
    #[uniffi::constructor]
    pub fn new(home_dir: String) -> KlavResult<Arc<Self>> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| KlavError::invalid(format!("cannot start the runtime: {e}")))?;
        Ok(Arc::new(Self {
            home: Home::at(home_dir),
            runtime,
            unlocked: Mutex::new(None),
            calls: Mutex::new(()),
            opening: Mutex::new(Opening::default()),
            is_unlocked: AtomicBool::new(false),
            generation: AtomicU64::new(0),
            words: Mutex::new(None),
        }))
    }

    /// The state of this device (no secrets needed).
    pub fn status(&self) -> CoreStatus {
        let account = klav_client::account(&self.home).ok();
        let unlocked = self.is_unlocked.load(Ordering::SeqCst);
        CoreStatus {
            has_account: account.is_some(),
            unlocked,
            email: account.as_ref().map(|a| a.email.clone()),
            server: account.as_ref().map(|a| a.server.clone()),
            device_name: account.as_ref().map(|a| a.device_name.clone()),
            account_words: guard(&self.words).clone().filter(|_| unlocked),
        }
    }

    /// Signs this device in to an existing account (e-mail, master
    /// password and the Secret Key of the emergency kit) and syncs it.
    /// With a keystore, Face ID is set up right away. Returns whether Face
    /// ID is enrolled.
    pub fn sign_in(
        &self,
        server: String,
        email: String,
        password: String,
        secret_key: String,
        device_name: String,
        keystore: Option<Arc<dyn PlatformKeystore>>,
    ) -> KlavResult<bool> {
        // The strings uniffi hands over are wiped when dropped.
        let secret_key = zeroize::Zeroizing::new(secret_key);
        let password = zeroize::Zeroizing::new(password);
        let secret_key = SecretKey::parse(secret_key.trim())?;
        let unlocked = self.runtime.block_on(klav_client::login(
            &self.home,
            LoginRequest {
                server,
                email,
                password: MasterPassword::new(password.as_str()),
                secret_key,
                device_name,
                device_kind: DEVICE_KIND,
            },
        ))?;
        self.opened(unlocked, keystore)
    }

    /// Creates an account on `server` (ADR 0027 §3, as `klav signup`):
    /// generates the Secret Key, registers with OPAQUE, signs this device in
    /// and creates the «Personal» vault. Returns the emergency kit as text,
    /// which holds the Secret Key: the app shows it, offers it as a PDF the
    /// person saves where they choose, and never logs or keeps a copy. The
    /// account stays unlocked in this object until [`Self::lock`]; the Mac
    /// app locks it right away and asks `klavd` to unlock instead.
    pub fn sign_up(
        &self,
        server: String,
        email: String,
        password: String,
        device_name: String,
    ) -> KlavResult<String> {
        // The string uniffi hands over is wiped when dropped.
        let password = zeroize::Zeroizing::new(password);
        let (unlocked, kit) = self.runtime.block_on(klav_client::signup(
            &self.home,
            klav_client::SignupRequest {
                server,
                email,
                password: MasterPassword::new(password.as_str()),
                device_name,
                device_kind: DEVICE_KIND,
            },
        ))?;
        self.publish(unlocked);
        Ok(klav_client::kit::render(&kit).to_string())
    }

    /// Unlocks with the master password (offline). With a keystore, Face
    /// ID is set up (or its 14-day period restarts). Returns whether Face ID
    /// is enrolled.
    pub fn unlock_with_password(
        &self,
        password: String,
        keystore: Option<Arc<dyn PlatformKeystore>>,
    ) -> KlavResult<bool> {
        let password = zeroize::Zeroizing::new(password);
        let _opening = Unlocking::start(self);
        let unlocked =
            klav_client::unlock_with_password(&self.home, &MasterPassword::new(password.as_str()))?;
        self.opened(unlocked, keystore)
    }

    /// The emergency kit as text, rebuilt with the server this iPhone uses
    /// today (ADR 0028 §4). Checks the master password first: the kit
    /// shows the Secret Key.
    pub fn emergency_kit(&self, password: String) -> KlavResult<String> {
        let kit = klav_client::emergency_kit(&self.home, &MasterPassword::new(password))?;
        Ok(klav_client::kit::render(&kit).to_string())
    }

    /// Moves the account to `server` by hand (ADR 0028 §4): a full OPAQUE
    /// sign-in there for this iPhone, kept only if it is the same account.
    /// The vault opens again on the new server. Returns the URL saved.
    pub fn set_server(&self, password: String, server: String) -> KlavResult<String> {
        let password = MasterPassword::new(password);
        // One call at a time, like those that use the account: one in
        // flight holds the account with the old URL and would put it back
        // when it ends.
        let _one = guard(&self.calls);
        let saved = self.runtime.block_on(klav_client::set_server(
            &self.home,
            &password,
            &server,
            DEVICE_KIND,
        ))?;
        if self.is_unlocked.load(Ordering::SeqCst) {
            let generation = self.generation.load(Ordering::SeqCst);
            // Argon2id, without the lock that `status()` and `lock()` use.
            let reopened = klav_client::unlock_with_password(&self.home, &password)?;
            let mut slot = self.state();
            // Not if it was locked meanwhile.
            if self.generation.load(Ordering::SeqCst) == generation && slot.is_some() {
                *slot = Some(reopened);
            }
        }
        Ok(saved)
    }

    /// Face ID state for the lock screen.
    pub fn biometric_state(&self, keystore: Arc<dyn PlatformKeystore>) -> BiometricState {
        biometric::state(&self.home, &keystore)
    }

    /// Unlocks with Face ID (shows the prompt with `reason`).
    pub fn unlock_with_biometrics(
        &self,
        keystore: Arc<dyn PlatformKeystore>,
        reason: String,
    ) -> KlavResult<()> {
        let account = klav_client::account(&self.home)?;
        let local_key = biometric::unlock(&self.home, account.local_context(), &keystore, &reason)?;
        // After the prompt: a session handed over waits only for the files.
        let _opening = Unlocking::start(self);
        let unlocked = klav_client::unlock_with_local_key(&self.home, local_key)?;
        self.publish(unlocked);
        Ok(())
    }

    /// Turns Face ID off in Klav (the password sets it up again). Asks for
    /// the device owner first, showing `reason`: Face ID, or the iPhone's
    /// passcode, never the master password alone (ADR 0037 A4). Nothing
    /// changes when the owner does not confirm.
    pub fn forget_biometrics(
        &self,
        keystore: Arc<dyn PlatformKeystore>,
        reason: String,
    ) -> KlavResult<()> {
        biometric::turn_off(&self.home, &keystore, &reason)
    }

    /// Locks: drops every key from memory.
    pub fn lock(&self) {
        drop(self.forget());
    }

    /// What signing out (or deleting the copy of a deleted account) now
    /// would lose: uploads what it can first (generated passwords, the
    /// passkey outbox), then counts what is still only on this iPhone:
    /// passkeys, whose private keys go with the account, and generated
    /// passwords. A deleted account uploads nothing: every try would fail.
    /// Fails closed: an outbox it cannot read is an error, not «none», and
    /// one it cannot tell exists while locked counts as a queue.
    pub fn sign_out_check(&self) -> KlavResult<SignOutCheck> {
        let counted = self.with(|u| {
            if !u.account_deleted() {
                let _ = self.runtime.block_on(u.flush_generated());
                let _ = self.runtime.block_on(u.flush_passkey_outbox());
            }
            Ok((u.passkey_outbox()?.passkeys.len(), u.unsent_generated()?))
        });
        let count = |n: usize| u32::try_from(n).unwrap_or(u32::MAX);
        match counted {
            Ok((passkeys, generated)) => Ok(SignOutCheck {
                unsent_passkeys: count(passkeys),
                unsent_generated: count(generated),
                locked_with_queue: false,
            }),
            Err(KlavError::Locked) => Ok(SignOutCheck {
                unsent_passkeys: 0,
                unsent_generated: 0,
                locked_with_queue: [
                    klav_client::passkey_outbox::PASSKEY_OUTBOX_FILE,
                    klav_client::history::OUTBOX_FILE,
                ]
                .iter()
                .any(|name| self.home.file(name).try_exists().unwrap_or(true)),
            }),
            Err(e) => Err(e),
        }
    }

    /// Marks the passkey outboxes set aside as reported, once the app has
    /// shown the notice that counted them: exactly `ids`
    /// ([`SyncInfo::passkey_queue_set_aside_ids`]). Until then every sync
    /// counts them again, and one set aside since is not covered (T138).
    pub fn acknowledge_passkey_queues_set_aside(&self, ids: Vec<String>) -> KlavResult<u32> {
        let n = klav_client::passkey_outbox::acknowledge_set_aside_outboxes(&self.home, &ids)?;
        Ok(u32::try_from(n).unwrap_or(u32::MAX))
    }

    /// Signs this device out: deletes the local state, then ends the
    /// session on the server (best effort). Also «Delete this iPhone’s
    /// copy» of a deleted account (ADR 0037 §3). Passkeys registered
    /// offline and generated passwords not uploaded would be lost with it:
    /// Klav refuses (`Denied`), and nothing changes, if more are waiting
    /// than the person agreed to lose (`accepted`, what the dialog they
    /// confirmed said). The last count and the delete happen under the
    /// home's lock, after uploading what it can, so a passkey AutoFill
    /// saves while the dialog is open (or while this runs) is counted,
    /// never deleted unseen. The server is told afterwards, so a refusal
    /// never follows a finished logout.
    pub fn sign_out(&self, accepted: AcceptedLoss) -> KlavResult<()> {
        // Uploads what it can first; the count that decides comes below.
        let _ = self.sign_out_check();
        let count = |n: u32| usize::try_from(n).unwrap_or(usize::MAX);
        let max = match accepted {
            AcceptedLoss::Nothing => Some(klav_client::passkey_outbox::AcceptedUnsent::default()),
            AcceptedLoss::Unsent {
                passkeys,
                generated,
            } => Some(klav_client::passkey_outbox::AcceptedUnsent {
                passkeys: count(passkeys),
                generated: count(generated),
            }),
            AcceptedLoss::Unknown => None,
        };
        let unlocked = self.forget();
        if let Err(e) = klav_client::passkey_outbox::forget_account_unless_queued(
            &self.home,
            unlocked.as_ref(),
            max,
        ) {
            if let Some(unlocked) = unlocked {
                self.publish(unlocked);
            }
            return Err(e.into());
        }
        if let Some(unlocked) = unlocked {
            let _ = self.runtime.block_on(unlocked.logout());
            // Telling the server may have written two files again: a
            // refreshed token, or the deletion marker when it answered that
            // the account is gone.
            let _ = std::fs::remove_file(self.home.session_path());
            let _ = std::fs::remove_file(self.home.file(klav_client::deletion::DELETION_FILE));
        }
        let _ = std::fs::remove_file(self.home.file("faceid.json"));
        Ok(())
    }

    /// Whether this account's server lets the person delete the account
    /// from the app (`account_deletion` in `/v1/health`, ADR 0037 §4).
    /// Asked before Face ID or the password.
    pub fn deletion_supported(&self) -> KlavResult<bool> {
        let account = klav_client::account(&self.home)?;
        Ok(self
            .runtime
            .block_on(klav_client::deletion::supported(&account.server))?)
    }

    /// The deletion of the account the person asked for, as the last sync
    /// (or this device's own request) left it, and whether the server
    /// already deleted the account; `None` without one. Read from this
    /// device's copy, without network. Needs the account unlocked.
    pub fn account_deletion(&self) -> KlavResult<Option<AccountDeletionInfo>> {
        self.with(|u| {
            let device = u.account().device_id;
            let deleted = u.account_deleted();
            Ok(u.account_deletion()
                .map(|d| deletion_info(d, device, deleted)))
        })
    }

    /// Asks the server to delete the account in 7 days (ADR 0037 §1).
    /// Face ID comes first wherever Klav uses it (`faceid.json` set up):
    /// then `keystore` is required, the prompt says `reason`, and the
    /// opened key is dropped at once. Then the master password, checked
    /// here and proved to the server with OPAQUE. Works unlocked (iOS) and
    /// locked (the Mac app, whose account `klavd` holds): locked, the
    /// account opens here for the request only.
    ///
    /// A wrong password is `WrongCredentials` and asks nothing; a server
    /// that cannot is `DeletionUnsupported`, before Face ID.
    pub fn request_account_deletion(
        &self,
        password: String,
        keystore: Option<Arc<dyn PlatformKeystore>>,
        reason: String,
    ) -> KlavResult<AccountDeletionInfo> {
        // The string uniffi hands over is wiped when dropped.
        let password = zeroize::Zeroizing::new(password);
        let account = klav_client::account(&self.home)?;
        if !self
            .runtime
            .block_on(klav_client::deletion::supported(&account.server))?
        {
            return Err(klav_client::ClientError::DeletionUnsupported.into());
        }
        // Face ID first, where Klav uses it (T162). Not a fallback to the
        // password: without the keystore, nothing is asked.
        if biometric::enrolled(&self.home) {
            let keystore = keystore.ok_or_else(|| KlavError::BiometryUnavailable {
                message: "Face ID is set up on this device: it confirms the deletion".into(),
            })?;
            biometric::confirm(&self.home, account.local_context(), &keystore, &reason)?;
        }
        let password = MasterPassword::new(password.as_str());
        let device = account.device_id;
        let asked = if self.is_unlocked.load(Ordering::SeqCst) {
            self.with(|u| {
                Ok(self
                    .runtime
                    .block_on(u.request_account_deletion(&password))?)
            })?
        } else {
            let _one = guard(&self.calls);
            let (unlocked, asked) =
                self.runtime
                    .block_on(klav_client::deletion::request_account_deletion(
                        &self.home, &password,
                    ))?;
            drop(unlocked);
            asked
        };
        Ok(deletion_info(&asked, device, false))
    }

    /// Cancels the deletion of the account, from any device with a
    /// session. `false` when there was none to cancel. Cancelling brings
    /// the agents back, so the app asks for presence first, as for
    /// resuming them (ADR 0037 A2): Face ID here, or
    /// [`Self::cancel_account_deletion_with_password`].
    pub fn cancel_account_deletion(&self) -> KlavResult<bool> {
        self.with(|u| Ok(self.runtime.block_on(u.cancel_account_deletion())?))
    }

    /// Cancels the deletion with the master password as the presence,
    /// where there is no Face ID or the person chose the password, like
    /// [`Self::resume_agents_with_password`]. A wrong password cancels
    /// nothing.
    pub fn cancel_account_deletion_with_password(&self, password: String) -> KlavResult<bool> {
        // The string uniffi hands over is wiped when dropped.
        let password = zeroize::Zeroizing::new(password);
        klav_client::unlock_with_password(&self.home, &MasterPassword::new(password.as_str()))
            .map(drop)?;
        self.cancel_account_deletion()
    }

    /// Pulls every change from the server (refuses a rollback, T7). Once
    /// this device saw the account deleted, it no longer syncs: the answer
    /// is [`KlavError::AccountDeleted`], without network (ADR 0037 §3).
    pub fn sync(&self) -> KlavResult<SyncInfo> {
        self.with(|u| {
            refuse_deleted(u)?;
            // An old server URL moves only if the new host has this
            // account (ADR 0028 §4).
            self.runtime.block_on(u.migrate_server());
            let report = self.runtime.block_on(u.sync())?;
            // Generated passwords queued while offline go up now, and the
            // passkeys the AutoFill extension registered or used (ADR 0020 §11).
            let _ = self.runtime.block_on(u.flush_generated());
            let mut flushed = self.runtime.block_on(u.flush_passkey_outbox()).ok();
            let waiting = u.passkey_outbox().map_or(0, |o| o.passkeys.len());
            let n = |v: usize| u32::try_from(v).unwrap_or(u32::MAX);
            Ok(SyncInfo {
                vaults_updated: n(report.vaults_updated),
                items_received: n(report.items_received),
                passkeys_waiting: n(waiting),
                passkey_queues_set_aside: n(flushed.as_ref().map_or(0, |f| f.set_aside)),
                passkey_queue_set_aside_ids: flushed
                    .as_mut()
                    .map(|f| std::mem::take(&mut f.set_aside_ids))
                    .unwrap_or_default(),
            })
        })
    }

    /// Vaults, by name.
    pub fn vaults(&self) -> KlavResult<Vec<VaultInfo>> {
        self.with(|u| Ok(vault_infos(u.vaults())))
    }

    /// Projects of a vault (or of all vaults), by name.
    pub fn projects(&self, vault_id: Option<String>) -> KlavResult<Vec<ProjectInfo>> {
        self.with(|u| {
            let vault = vault_id
                .map(|v| VaultId::from_str(v.trim()))
                .transpose()
                .map_err(|_| KlavError::invalid("not a vault ID"))?;
            Ok(project_infos(u.projects(vault)))
        })
    }

    /// Items matching `query`, by title.
    pub fn items(&self, query: ItemQuery) -> KlavResult<Vec<ItemInfo>> {
        self.with(|u| Ok(item_infos(u.list_items(&item_filter(query))?)))
    }

    /// An item, without secret values.
    pub fn item(&self, id: String) -> KlavResult<ItemDetail> {
        self.with(|u| Ok(u.view_item(&item_id(&id)?.to_string(), false)?.into()))
    }

    /// One field's value (the person asked to reveal or copy it).
    pub fn field_value(&self, id: String, field: String) -> KlavResult<String> {
        self.with(|u| {
            let loc = location(u, &id)?;
            let item = u.open_item(loc)?;
            let found = item.field(&field).ok_or_else(|| KlavError::NotFound {
                message: format!("field {field:?}"),
            })?;
            match found.value() {
                FieldValue::Plain(s) => Ok(s.clone()),
                FieldValue::Secret(s) => Ok(s.expose().to_owned()),
                FieldValue::File(_) => Err(KlavError::invalid("this field is an attachment")),
            }
        })
    }

    /// The item's notes (the person asked to see them).
    pub fn notes(&self, id: String) -> KlavResult<Option<String>> {
        self.with(|u| {
            let loc = location(u, &id)?;
            Ok(u.open_item(loc)?.notes().map(|n| n.expose().to_owned()))
        })
    }

    /// The current one-time password of an item.
    pub fn totp(&self, id: String) -> KlavResult<TotpInfo> {
        self.with(|u| {
            let loc = location(u, &id)?;
            totp_of(u, loc)
        })
    }

    /// Creates an item. A title another live item of the project already
    /// has is refused (references by title would be ambiguous).
    pub fn create_item(&self, input: NewItemInput) -> KlavResult<ItemInfo> {
        self.writing(|u| {
            let new = new_item(input);
            Ok(self.runtime.block_on(u.create(&new))?.into())
        })
    }

    /// Edits an item and uploads the next version.
    pub fn edit_item(&self, id: String, edit: ItemEdit) -> KlavResult<ItemInfo> {
        self.writing(|u| {
            let patch = item_patch(edit);
            let id = item_id(&id)?.to_string();
            Ok(self.runtime.block_on(u.edit(&id, &patch))?.into())
        })
    }

    /// Keeps a generated password in the generator history (ADR 0022 §2)
    /// before the person uses it: in this device's outbox first, then
    /// uploaded when the server answers (it stays queued otherwise).
    pub fn record_generated(&self, value: String, host: Option<String>) -> KlavResult<i64> {
        self.writing(|u| {
            let host = host.as_deref().and_then(klav_core::site::item_host);
            let at = u.record_generated(&value, host.as_deref())?;
            let _ = self.runtime.block_on(u.flush_generated());
            Ok(at)
        })
    }

    /// The generator history, newest first, without values.
    pub fn generator_history(&self) -> KlavResult<Vec<GeneratedEntryInfo>> {
        self.with(|u| {
            Ok(u.generator_history()?
                .into_iter()
                .map(generated_entry)
                .collect())
        })
    }

    /// The value of one generator history entry (to copy it).
    pub fn generated_value(&self, created_at: i64) -> KlavResult<String> {
        self.with(|u| Ok(u.generated_value(created_at)?.expose().to_owned()))
    }

    /// Deletes the whole generator history (and the versions that held it).
    pub fn clear_generator_history(&self) -> KlavResult<u32> {
        self.writing(|u| {
            let n = self
                .runtime
                .block_on(u.delete_generated(&klav_client::history::GeneratedSelection::All))?;
            Ok(u32::try_from(n).unwrap_or(u32::MAX))
        })
    }

    /// One previous password (the person asked to reveal or copy it).
    pub fn previous_password(&self, id: String, index: u32) -> KlavResult<String> {
        self.with(|u| {
            let loc = location(u, &id)?;
            let index = usize::try_from(index).unwrap_or(usize::MAX);
            Ok(u.previous_password(loc, index)?.expose().to_owned())
        })
    }

    /// Moves an item to the trash.
    pub fn trash_item(&self, id: String) -> KlavResult<()> {
        self.writing(|u| {
            let id = item_id(&id)?.to_string();
            self.runtime.block_on(u.trash(&id))?;
            Ok(())
        })
    }

    /// Pending approval requests from agents, newest first.
    pub fn approvals(&self) -> KlavResult<Vec<ApprovalItem>> {
        self.with(|u| {
            let list = self.runtime.block_on(u.approvals(false))?;
            Ok(list.into_iter().map(approval_item).collect())
        })
    }

    /// Signs a decision: deny, approve once (`lease_minutes = 0`) or
    /// approve for a while. The app checks presence (Face ID) first.
    /// `request_digest` is the one of the [`ApprovalItem`] the person
    /// decided on: nothing is signed if the request changed since (ADR
    /// 0030 §5).
    pub fn decide_approval(
        &self,
        id: String,
        approve: bool,
        lease_minutes: u32,
        request_digest: String,
    ) -> KlavResult<()> {
        self.with(|u| {
            let id = ApprovalId::from_str(id.trim())
                .map_err(|_| KlavError::invalid("not an approval ID"))?;
            let lease = (approve && lease_minutes > 0)
                .then(|| std::time::Duration::from_secs(u64::from(lease_minutes) * 60));
            self.runtime
                .block_on(u.decide_approval(id, approve, lease, &request_digest))?;
            Ok(())
        })
    }

    /// Task requests waiting for a decision and running tasks, newest
    /// first (ADR 0021 §8). Rows come from this device's vault.
    pub fn tasks(&self) -> KlavResult<Vec<TaskItem>> {
        self.with(|u| {
            let cards = self.runtime.block_on(u.tasks(false))?;
            Ok(cards.into_iter().map(task_item).collect())
        })
    }

    /// Approves pending task `id` with the person's changes (`choice`), or
    /// denies it, and signs the decision (spec §13.8). The app checks
    /// presence (Face ID) before approving; denying asks for nothing.
    /// `request_digest` is the one of the [`TaskItem`] the person decided
    /// on: nothing is signed if the request changed since (ADR 0030 §5).
    pub fn decide_task(
        &self,
        id: String,
        approve: bool,
        choice: Option<TaskChoiceInput>,
        request_digest: String,
    ) -> KlavResult<TaskItem> {
        self.with(|u| {
            let id = task_id(&id)?;
            let choice = task_choice(choice.unwrap_or_default())?;
            let card =
                self.runtime
                    .block_on(u.decide_task(id, approve, &choice, &request_digest))?;
            Ok(task_item(card))
        })
    }

    /// «Add to the task» (ADR 0021 §6): signs the next revision of the
    /// agent's running task with this request's item, permission and site
    /// (same end), then approves the request once. The app checks presence
    /// (Face ID) first. `request_digest` is the one of the
    /// [`ApprovalItem`] the person decided on (ADR 0030 §5).
    pub fn add_to_task(&self, approval_id: String, request_digest: String) -> KlavResult<TaskItem> {
        self.with(|u| {
            let id = ApprovalId::from_str(approval_id.trim())
                .map_err(|_| KlavError::invalid("not an approval ID"))?;
            let card = self.runtime.block_on(u.add_to_task(id, &request_digest))?;
            Ok(task_item(card))
        })
    }

    /// «End task»: ends running task `id`, signed by the account. Asks for
    /// no presence, like denying.
    pub fn end_task(&self, id: String) -> KlavResult<TaskItem> {
        self.with(|u| {
            let id = task_id(&id)?;
            let card = self.runtime.block_on(u.end_task(id))?;
            Ok(task_item(card))
        })
    }

    /// Pending secret requests from agents, newest first (ADR 0046). Each
    /// proposal is opened locally with the account's X25519 key and verified
    /// against `proposal_digest`.
    pub fn secret_requests(&self) -> KlavResult<Vec<SecretRequestItem>> {
        self.with(|u| {
            let cards = self.runtime.block_on(u.secret_requests(false))?;
            Ok(cards.into_iter().map(secret_request_item).collect())
        })
    }

    /// Fulfills pending secret request `id`: saves the secret entered in the
    /// hidden input into the person's vault, optionally grants `klav-proxy`
    /// access if `input.grant_proxy` is true (the app checks Face ID first),
    /// and posts the account-signed decision.
    pub fn fulfill_secret_request(
        &self,
        id: String,
        input: SecretRequestFulfillInput,
    ) -> KlavResult<SecretRequestFulfillOutput> {
        self.with(|u| {
            let id = secret_request_id(&id)?;
            let req = fulfill_secret_request_input(input);
            let res = self.runtime.block_on(u.fulfill_secret_request(id, &req))?;
            Ok(fulfill_secret_request_output(res))
        })
    }

    /// Denies pending secret request `id` with an account-signed decision.
    pub fn deny_secret_request(
        &self,
        id: String,
        proposal_digest: String,
    ) -> KlavResult<SecretRequestItem> {
        self.with(|u| {
            let id = secret_request_id(&id)?;
            let card = self
                .runtime
                .block_on(u.deny_secret_request(id, &proposal_digest))?;
            Ok(secret_request_item(card))
        })
    }

    /// The account's agents: pending registrations first, then newest.
    pub fn agents(&self) -> KlavResult<Vec<AgentItem>> {
        self.with(|u| {
            let list = self.runtime.block_on(u.agents())?;
            Ok(agent_items(list))
        })
    }

    /// «What it saw» before revoking (ADR 0033, amendment of 2026-11-10,
    /// F2, P10): the projects whose keys the agent held, what the audit
    /// log says it used, and what changing those keys costs. Read-only.
    pub fn agent_exposure(&self, id: String) -> KlavResult<ExposureInfo> {
        let agent = pause::agent_id(&id)?;
        self.with(|u| {
            let exposure = self.runtime.block_on(u.agent_exposure(agent))?;
            let projects: Vec<GrantedProjectInfo> =
                exposure.projects.iter().map(grants::project_info).collect();
            let mut listings = Vec::new();
            for p in &projects {
                for trash in [false, true] {
                    let filter = ItemFilter {
                        project: Some(p.project_id.clone()),
                        trash,
                        ..ItemFilter::default()
                    };
                    listings.push(
                        u.list_items(&filter)
                            .map(|items| items.len())
                            .map_err(KlavError::from),
                    );
                }
            }
            let agents = self.runtime.block_on(u.agents()).map_err(KlavError::from);
            let cost = grants::cost_of(&agent.to_string(), &projects, &listings, agents);
            Ok(grants::exposure_info(exposure, cost))
        })
    }

    /// Revokes the agent, without presence (ADR 0014 §7.1), and writes
    /// the revocation down before anything else (`revocations.bin`). The
    /// keys of items granted one by one change here. With `rotate`, it also
    /// writes down that the person asked for the projects' keys to change,
    /// without changing any: [`Self::revocation_step`] does one project per
    /// call, so «Revoked» shows at once, the vault never waits on a whole
    /// key change, and iOS suspending or killing the app loses nothing.
    pub fn revoke_agent_first(&self, id: String, rotate: bool) -> KlavResult<RevokeReportInfo> {
        let agent = pause::agent_id(&id)?;
        self.writing(|u| {
            let mut report = self.runtime.block_on(u.revoke_first(agent, rotate))?;
            if rotate && report.failed.is_none() {
                report.pending = u.rotation_left(agent);
            }
            Ok(grants::revoke_report_info(
                report,
                KeyChangeCostInfo::default(),
            ))
        })
    }

    /// One step of a key change this iPhone owes for agent `id`: its items
    /// first, then one project and the other agents' grants for it. What
    /// it did is written down before it answers. Never changes a project's
    /// key unless the person asked for it (P7), and never one twice. Call
    /// it again until `done` or `failed`.
    pub fn revocation_step(&self, id: String) -> KlavResult<RevocationStepInfo> {
        let agent = pause::agent_id(&id)?;
        self.writing(|u| {
            let of =
                |u: &klav_client::Unlocked| -> Option<Vec<klav_client::revoke::PendingRevocation>> {
                    u.pending_revocations()
                        .ok()
                        .map(|l| l.into_iter().filter(|p| p.agent_id == agent).collect())
                };
            let before = of(u);
            let step = self.runtime.block_on(u.rotation_step(agent))?;
            let after = of(u);
            let changed = before != after;
            let pending = grants::owed_projects(
                before.as_deref(),
                after.as_deref(),
                step.rotated.as_ref().map(|r| r.project.as_str()),
                || u.rotation_left(agent),
            );
            Ok(grants::revocation_step_info(step, pending, changed))
        })
    }

    /// The key changes this iPhone still owes, from its sealed record. A
    /// record that does not open is an error, never an empty list.
    pub fn agent_revocations(&self) -> KlavResult<Vec<RevocationInfo>> {
        self.with(|u| {
            Ok(u.pending_revocations()?
                .into_iter()
                .map(grants::pending_revocation_info)
                .collect())
        })
    }

    /// Approves an agent's registration: signs a grant with the keys of
    /// `project_ids` and the default policy (design §5.2, as `klav agent
    /// approve` without options), optionally expiring after
    /// `expires_in_days`. `pairing_words` are the words the person
    /// compared; the agent's key must still produce them.
    pub fn approve_agent(
        &self,
        id: String,
        pairing_words: String,
        project_ids: Vec<String>,
        expires_in_days: Option<u32>,
    ) -> KlavResult<AgentItem> {
        self.with(|u| {
            let agent =
                AgentId::from_str(id.trim()).map_err(|_| KlavError::invalid("not an agent ID"))?;
            let request = default_grant(project_ids, expires_in_days)?;
            let view = self
                .runtime
                .block_on(u.approve_agent(agent, request, &pairing_words))?;
            Ok(agent_item(view))
        })
    }

    /// Denies a pending registration.
    pub fn deny_agent(&self, id: String) -> KlavResult<()> {
        self.with(|u| {
            let agent =
                AgentId::from_str(id.trim()).map_err(|_| KlavError::invalid("not an agent ID"))?;
            self.runtime.block_on(u.deny_agent(agent))?;
            Ok(())
        })
    }

    /// The account's agents with their last use and their pause, for
    /// Agents (ADR 0033 §9): pending registrations first, then newest.
    pub fn dev_agents(&self) -> KlavResult<Vec<DevAgentInfo>> {
        self.with(|u| Ok(pause::dev_agents(self.runtime.block_on(u.agents())?)))
    }

    /// The pauses in effect, as this iPhone last learned them (its sync,
    /// or its own decision), each with the account's signature checked.
    /// `Locked` while locked; after an unlock, none until the first sync
    /// brings them (the iPhone does not keep them on disk, as `klavd` does).
    pub fn agents_paused(&self) -> KlavResult<Vec<PauseInfo>> {
        self.with(|u| {
            Ok(u.agent_pauses()
                .iter()
                .map(pause::signed_pause_info)
                .collect())
        })
    }

    /// «Pause agents» (ADR 0033 §7): every agent without `agent_id`, until
    /// `until_ms` or until the person resumes. Nothing is asked: pausing is
    /// for a scare. Signed with the account and sent at once; answers the
    /// pauses in effect.
    pub fn pause_agents(
        &self,
        agent_id: Option<String>,
        until_ms: Option<i64>,
    ) -> KlavResult<Vec<PauseInfo>> {
        let agent = pause::optional_agent(agent_id)?;
        self.with(|u| {
            let pauses = self
                .runtime
                .block_on(u.pause_agents(agent, until_ms.unwrap_or(0).max(0)))?;
            Ok(pauses.iter().map(pause::signed_pause_info).collect())
        })
    }

    /// «Resume»: the app checks Face ID first, as approving. Resuming
    /// every agent does not lift the pause of a single one.
    pub fn resume_agents(&self, agent_id: Option<String>) -> KlavResult<Vec<PauseInfo>> {
        let agent = pause::optional_agent(agent_id)?;
        self.with(|u| {
            let pauses = self.runtime.block_on(u.resume_agents(agent))?;
            Ok(pauses.iter().map(pause::signed_pause_info).collect())
        })
    }

    /// `resume_agents` with the master password, on an iPhone without
    /// Face ID (ADR 0033 P2): a wrong one is `WrongCredentials` and nothing
    /// is signed. The password is required; after Face ID the app calls
    /// `resume_agents`.
    pub fn resume_agents_with_password(
        &self,
        agent_id: Option<String>,
        password: String,
    ) -> KlavResult<Vec<PauseInfo>> {
        // The string uniffi hands over is wiped when dropped.
        let password = zeroize::Zeroizing::new(password);
        klav_client::unlock_with_password(&self.home, &MasterPassword::new(password.as_str()))
            .map(drop)?;
        self.resume_agents(agent_id)
    }

    /// «Sandboxes» (ADR 0036 E2.1): the sandboxes in the verified log, with
    /// the last heartbeat of the account's proxy; only the account's
    /// proxy's, unless `all_proxies`. Verifies the whole log first, so it
    /// takes a moment. `Security` on tampering, on a heartbeat the proxy
    /// did not sign, or when the server does not list the proxy the
    /// account's setting names. Preferences this iPhone cannot read give
    /// every proxy's rows, no proxy and a warning. A heartbeat older than
    /// one this iPhone already accepted is no error: the proxy shows
    /// `ProxyNoSigns::Rollback`, with a warning.
    pub fn sandbox_list(&self, all_proxies: bool) -> KlavResult<SandboxListInfo> {
        self.with(|u| {
            let list = self.runtime.block_on(u.sandbox_list())?;
            Ok(sandboxes::sandbox_list_info(list, all_proxies))
        })
    }

    /// [`Self::sandbox_list`] for an app that shows `security`: preferences
    /// an agent wrote give every proxy's rows, no proxy and
    /// `SandboxSecurityInfo::PreferencesByAgent` instead of a `Security`
    /// error. The app shows it as a security problem and offers to set the
    /// proxy again.
    pub fn sandbox_list_flagged(&self, all_proxies: bool) -> KlavResult<SandboxListInfo> {
        self.with(|u| {
            let list = self.runtime.block_on(u.sandbox_list_flagged())?;
            Ok(sandboxes::sandbox_list_info(list, all_proxies))
        })
    }

    /// [`Self::sandbox_list_flagged`] with the check that refused the list
    /// apart, so the app says it in its own words: the log, the proxy's
    /// heartbeat, or a proxy the server does not list. Any other failure,
    /// a `Security` one included, is the same error.
    pub fn sandbox_list_checked(&self, all_proxies: bool) -> KlavResult<SandboxListCheckedInfo> {
        self.with(|u| {
            let checked = self.runtime.block_on(u.sandbox_list_checked())?;
            Ok(sandboxes::checked_info(checked, all_proxies))
        })
    }

    /// Revokes one sandbox of `proxy_id` (ADR 0036 E2.3): signed with the
    /// account, without Face ID, like a pause, since it only takes access
    /// away. The server bars it at once; the proxy logs its end later.
    pub fn revoke_sandbox(
        &self,
        proxy_id: String,
        sandbox_id: String,
    ) -> KlavResult<SandboxRevokeInfo> {
        self.revoke_sandboxes(proxy_id, Some(sandbox_id))
    }

    /// Revokes every sandbox of `proxy_id` issued so far («Revoke all»).
    pub fn revoke_all_sandboxes(&self, proxy_id: String) -> KlavResult<SandboxRevokeInfo> {
        self.revoke_sandboxes(proxy_id, None)
    }

    /// «Activity» (ADR 0033 §8, §9): the account's log, newest first, with
    /// the filters. Only what is new is downloaded (the chain is cached,
    /// §8.4); each event says whether it is verified yet.
    pub fn audit_log(&self, filter: LogFilterInput) -> KlavResult<Vec<LogEntryInfo>> {
        let filter = activity::log_filter(filter)?;
        self.with(|u| {
            let lines = self.runtime.block_on(u.audit_log(&filter))?;
            Ok(lines.into_iter().map(activity::log_entry).collect())
        })
    }

    /// «Who used it» for one item (its ID or reference): what the agents
    /// did with it, newest first.
    pub fn item_activity(&self, item: String) -> KlavResult<ItemActivityInfo> {
        self.with(|u| {
            let activity = self.runtime.block_on(u.item_activity(&item))?;
            Ok(activity::item_activity_info(activity))
        })
    }

    /// How much of the log this iPhone has downloaded and verified, without
    /// contacting the server.
    pub fn audit_status(&self) -> KlavResult<AuditStatusInfo> {
        self.with(|u| Ok(activity::audit_status_info(&u.audit_status())))
    }

    /// «Verify now»: downloads the whole chain, checks every signature and
    /// that it still holds what this iPhone downloaded before, and signs its
    /// head (`klav log verify`). A failure is `Security`.
    pub fn verify_audit(&self) -> KlavResult<VerifyInfo> {
        self.with(|u| {
            Ok(activity::verify_info(
                self.runtime.block_on(u.verify_audit())?,
            ))
        })
    }

    /// Registers this device's APNs token (hex) for approval pushes.
    /// `sandbox` for development builds.
    pub fn register_push_token(&self, token: String, sandbox: bool) -> KlavResult<()> {
        self.with(|u| {
            let environment = if sandbox {
                PushEnvironment::Sandbox
            } else {
                PushEnvironment::Production
            };
            self.runtime
                .block_on(u.register_push(token.trim(), environment))?;
            Ok(())
        })
    }

    /// Stops approval pushes to this device.
    pub fn unregister_push_token(&self) -> KlavResult<()> {
        self.with(|u| {
            self.runtime.block_on(u.unregister_push())?;
            Ok(())
        })
    }

    /// Logins whose URLs match `service` (a URL or a domain): exact host
    /// first, then subdomain, then by title (ADR 0025 §3). Never one saved
    /// for a subdomain of `service`: see [`Self::parent_suggestions`].
    pub fn suggestions(&self, service: String) -> KlavResult<Vec<ItemInfo>> {
        let host = service_host(service)?;
        self.with(|u| {
            let filter = ItemFilter {
                kind: Some(ItemKind::Login),
                ..ItemFilter::default()
            };
            let mut items: Vec<(site::HostRelation, ItemInfo)> = u
                .list_items(&filter)?
                .into_iter()
                .filter_map(|s| {
                    site::host_relation(&host, &s.confirmed_urls)
                        .filter(|r| r.matches())
                        .map(|r| (r, ItemInfo::from(s)))
                })
                .collect();
            items.sort_by_cached_key(|(r, i)| (*r, i.title.to_lowercase()));
            Ok(items.into_iter().map(|(_, i)| i).collect())
        })
    }

    /// Logins saved for a subdomain of `service` (ADR 0025): the sheet
    /// lists them apart, «Saved for a subdomain», with the host they were
    /// saved for, and fills one only when the person picks it
    /// ([`Self::password_credential`] with `chosen`). By title.
    pub fn parent_suggestions(&self, service: String) -> KlavResult<Vec<ParentSuggestion>> {
        let host = service_host(service)?;
        self.with(|u| {
            let filter = ItemFilter {
                kind: Some(ItemKind::Login),
                ..ItemFilter::default()
            };
            let mut items: Vec<ParentSuggestion> = u
                .list_items(&filter)?
                .into_iter()
                // Only the sites the person confirmed (ADR 0030 §7).
                .filter(|s| {
                    site::host_relation(&host, &s.confirmed_urls)
                        == Some(site::HostRelation::Parent)
                })
                .filter_map(|s| {
                    let saved_host = site::saved_subdomain(&host, &s.confirmed_urls)?;
                    Some(ParentSuggestion {
                        item: ItemInfo::from(s),
                        saved_host,
                    })
                })
                .collect();
            items.sort_by_cached_key(|p| p.item.title.to_lowercase());
            Ok(items)
        })
    }

    /// The user name and password of a login, for `service`. Refused when
    /// the site does not belong to the item (T21), whatever the caller
    /// listed before. `chosen`: the person picked a login saved for a
    /// subdomain of `service` in the sheet (ADR 0025 §2); never from
    /// QuickType.
    pub fn password_credential(
        &self,
        id: String,
        service: String,
        chosen: bool,
    ) -> KlavResult<PasswordCredential> {
        self.with(|u| {
            let loc = location(u, &id)?;
            check_site(u, loc, &service, chosen)?;
            let item = u.open_item(loc)?;
            let text = |name: &str| match item.field(name).map(|f| f.value()) {
                Some(FieldValue::Plain(s)) => s.clone(),
                Some(FieldValue::Secret(s)) => s.expose().to_owned(),
                _ => String::new(),
            };
            let password = text("password");
            if password.is_empty() {
                return Err(KlavError::NotFound {
                    message: "this login has no password".into(),
                });
            }
            Ok(PasswordCredential {
                username: text("username"),
                password,
            })
        })
    }

    /// The current one-time password of a login, for `service` (same
    /// site check as [`Self::password_credential`]).
    pub fn one_time_code(&self, id: String, service: String, chosen: bool) -> KlavResult<TotpInfo> {
        self.with(|u| {
            let loc = location(u, &id)?;
            check_site(u, loc, &service, chosen)?;
            totp_of(u, loc)
        })
    }

    /// Identities for the QuickType bar: every live login with a URL the
    /// person confirmed (ADR 0030 §7).
    pub fn credential_identities(&self) -> KlavResult<Vec<CredentialIdentity>> {
        self.with(|u| {
            let filter = ItemFilter {
                kind: Some(ItemKind::Login),
                ..ItemFilter::default()
            };
            let mut out = Vec::new();
            for summary in u.list_items(&filter)? {
                let hosts: Vec<String> = summary
                    .confirmed_urls
                    .iter()
                    .filter_map(|url| site::item_host(url))
                    .collect();
                if hosts.is_empty() {
                    continue;
                }
                let loc = ItemLocation {
                    vault: summary.vault_id,
                    project: summary.project_id,
                    item: summary.id,
                };
                let Ok(item) = u.open_item(loc) else {
                    continue;
                };
                let filled = |kind: FieldKind| {
                    item.fields()
                        .iter()
                        .any(|f| f.kind() == kind && !f.is_empty())
                };
                out.push(CredentialIdentity {
                    item_id: summary.id.to_string(),
                    title: summary.title.clone(),
                    username: summary.username.clone().unwrap_or_default(),
                    hosts,
                    has_password: filled(FieldKind::Password),
                    has_totp: filled(FieldKind::Totp),
                });
            }
            Ok(out)
        })
    }

    // ------------------------------------------------------- passkeys --

    /// The passkeys this iPhone can sign with, synced and queued, for
    /// `ASCredentialIdentityStore` (ADR 0020 §11).
    pub fn passkey_identities(&self) -> KlavResult<Vec<PasskeyIdentityInfo>> {
        self.with(|u| {
            Ok(u.passkey_identities()?
                .into_iter()
                .map(|p| PasskeyIdentityInfo {
                    item_id: p.item.to_string(),
                    title: p.title,
                    rp_id: p.rp_id,
                    user_name: p.user_name,
                    credential_id: p.credential_id,
                    user_handle: p.user_handle,
                })
                .collect())
        })
    }

    /// Signs in with the passkey `credential_id` for `rp_id` over the
    /// `clientDataHash` iOS built. No network: the `passkey.used` event
    /// waits in the outbox for the app. Once the server deleted the
    /// account it still signs in, from the read-only copy (ADR 0037 §3,
    /// D-C), but queues no event: none could ever upload.
    pub fn passkey_assertion(
        &self,
        rp_id: String,
        credential_id: Vec<u8>,
        client_data_hash: Vec<u8>,
    ) -> KlavResult<PasskeyAssertionInfo> {
        self.with(|u| {
            let a = u.passkey_assert_hash(&rp_id, &credential_id, &client_data_hash)?;
            Ok(PasskeyAssertionInfo {
                credential_id: a.credential_id,
                authenticator_data: a.authenticator_data,
                signature: a.signature,
                user_handle: a.user_handle,
                item_id: a.item.to_string(),
            })
        })
    }

    /// Registers a passkey without network: the login is usable at once
    /// on this iPhone and waits in the outbox until the app opens.
    pub fn passkey_registration(
        &self,
        input: PasskeyRegistrationInput,
    ) -> KlavResult<PasskeyRegistrationOutcome> {
        // The copy of a deleted account is read-only (ADR 0037 §3): a new
        // passkey would wait in the outbox for an account that is gone, and
        // the site would keep a login Klav can't keep.
        self.writing(|u| {
            let mut request = PasskeyCreateRequest::from_platform(
                &input.rp_id,
                input.rp_name,
                &input.user_handle,
                input.user_name,
                input.user_display_name,
                &input.exclude_credentials,
            );
            request.item = input.item_id;
            request.replace = input.replace;
            request.vault = input.vault;
            request.project = input.project;
            Ok(match u.passkey_register_queued(&request)? {
                PasskeyQueuedOutcome::Created(r) => PasskeyRegistrationOutcome::Created {
                    credential_id: r.credential_id,
                    attestation_object: r.attestation_object,
                    authenticator_data: r.authenticator_data,
                    item_id: r.item.to_string(),
                    title: r.title,
                },
                PasskeyQueuedOutcome::Excluded => PasskeyRegistrationOutcome::Excluded,
                PasskeyQueuedOutcome::Exists { item, title } => {
                    PasskeyRegistrationOutcome::Exists {
                        item_id: item.to_string(),
                        title,
                    }
                }
            })
        })
    }

    /// What waits in the passkey outbox.
    pub fn passkey_outbox(&self) -> KlavResult<PasskeyOutboxInfo> {
        self.with(|u| {
            let o = u.passkey_outbox()?;
            Ok(PasskeyOutboxInfo {
                passkeys: o
                    .passkeys
                    .into_iter()
                    .map(|(item, title)| QueuedPasskeyInfo {
                        item_id: item.to_string(),
                        title,
                    })
                    .collect(),
                uses: u32::try_from(o.uses).unwrap_or(u32::MAX),
            })
        })
    }

    /// Uploads the passkey outbox (the app, in the foreground; `sync` does
    /// it too).
    pub fn flush_passkey_outbox(&self) -> KlavResult<PasskeyFlushInfo> {
        self.with(|u| {
            let f = self.runtime.block_on(u.flush_passkey_outbox())?;
            let n = |v: usize| u32::try_from(v).unwrap_or(u32::MAX);
            Ok(PasskeyFlushInfo {
                uploaded: n(f.uploaded),
                renamed: n(f.renamed),
                uses_sent: n(f.uses_sent),
                left: n(f.left),
                error: f.error,
                set_aside: n(f.set_aside),
                set_aside_ids: f.set_aside_ids,
            })
        })
    }
}

/// A deletion as the app shows it.
fn deletion_info(
    d: &klav_client::deletion::AccountDeletion,
    this_device: klav_core::ids::DeviceId,
    deleted: bool,
) -> AccountDeletionInfo {
    AccountDeletionInfo {
        requested_at: d.requested_at,
        delete_at: d.delete_at,
        device_name: d.device_name.clone(),
        this_device: d.device_id == this_device,
        deleted,
    }
}

impl KlavCore {
    fn revoke_sandboxes(
        &self,
        proxy_id: String,
        sandbox_id: Option<String>,
    ) -> KlavResult<SandboxRevokeInfo> {
        let proxy = pause::agent_id(&proxy_id)?;
        let target = sandboxes::revoke_target(sandbox_id)?;
        self.with(|u| {
            let outcome = self
                .runtime
                .block_on(u.revoke_sandboxes_outcome(proxy, target))?;
            Ok(sandboxes::revoke_info(outcome))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_agents_name_and_note_are_shown_plain_and_short() {
        let item = agent_item(AgentView {
            id: klav_core::ids::AgentId::generate(),
            name: "facturas\u{202E}exe.pdf\u{200B}".into(),
            note: Some(format!("{}\n{}", "x".repeat(80), "\u{2066}")),
            status: klav_proto::agent::AgentStatus::Pending,
            pairing_code: "a b c d e f".into(),
            created_at: 0,
            expires_at: 0,
            approved_at: None,
            revoked_at: None,
            last_seen_at: None,
            grant: None,
            grant_error: None,
            paused: None,
        });
        assert_eq!(item.name, "facturas exe.pdf");
        let note = item.note.expect("note");
        assert_eq!(note.chars().count(), MAX_AGENT_TEXT);
        assert!(!note.chars().any(klav_core::text::is_hidden));
    }
}
