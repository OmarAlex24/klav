//! Records and enums that cross the FFI. IDs travel as their text form.

use klav_client::ops::{FieldView, ItemView};
use klav_client::{ItemSummary, ProjectSummary, VaultSummary};
use klav_core::model::item::{FieldKind, ItemKind};

/// Item types (mirror of `klav_core::model::item::ItemKind`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum Kind {
    /// Website or app login.
    Login,
    /// Payment card.
    Card,
    /// Identity / address.
    Identity,
    /// SSH key.
    SshKey,
    /// File.
    File,
    /// Standalone TOTP secret.
    Totp,
    /// Secure note.
    Note,
    /// API key / token.
    ApiKey,
}

impl From<ItemKind> for Kind {
    fn from(k: ItemKind) -> Self {
        match k {
            ItemKind::Login => Self::Login,
            ItemKind::Card => Self::Card,
            ItemKind::Identity => Self::Identity,
            ItemKind::SshKey => Self::SshKey,
            ItemKind::File => Self::File,
            ItemKind::Totp => Self::Totp,
            // System items (the generator history, the preferences) are
            // never listed: they live in the system project. A note is the
            // closest shape if one ever shows up.
            ItemKind::Note
            | ItemKind::GeneratorHistory
            | ItemKind::Preferences
            | ItemKind::AgentLabels => Self::Note,
            ItemKind::ApiKey => Self::ApiKey,
        }
    }
}

impl From<Kind> for ItemKind {
    fn from(k: Kind) -> Self {
        match k {
            Kind::Login => Self::Login,
            Kind::Card => Self::Card,
            Kind::Identity => Self::Identity,
            Kind::SshKey => Self::SshKey,
            Kind::File => Self::File,
            Kind::Totp => Self::Totp,
            Kind::Note => Self::Note,
            Kind::ApiKey => Self::ApiKey,
        }
    }
}

/// Field types (mirror of `klav_core::model::item::FieldKind`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FieldType {
    /// User name.
    Username,
    /// Password.
    Password,
    /// TOTP secret.
    Totp,
    /// Attachment reference.
    File,
    /// Free text.
    Text,
    /// Other secret text.
    Concealed,
    /// URL.
    Url,
    /// E-mail.
    Email,
    /// Phone.
    Phone,
    /// Date.
    Date,
    /// Month and year.
    MonthYear,
}

impl From<FieldKind> for FieldType {
    fn from(k: FieldKind) -> Self {
        match k {
            FieldKind::Username => Self::Username,
            FieldKind::Password => Self::Password,
            FieldKind::Totp => Self::Totp,
            FieldKind::File => Self::File,
            FieldKind::Text => Self::Text,
            FieldKind::Concealed => Self::Concealed,
            FieldKind::Url => Self::Url,
            FieldKind::Email => Self::Email,
            FieldKind::Phone => Self::Phone,
            FieldKind::Date => Self::Date,
            FieldKind::MonthYear => Self::MonthYear,
        }
    }
}

impl From<FieldType> for FieldKind {
    fn from(k: FieldType) -> Self {
        match k {
            FieldType::Username => Self::Username,
            FieldType::Password => Self::Password,
            FieldType::Totp => Self::Totp,
            FieldType::File => Self::File,
            FieldType::Text => Self::Text,
            FieldType::Concealed => Self::Concealed,
            FieldType::Url => Self::Url,
            FieldType::Email => Self::Email,
            FieldType::Phone => Self::Phone,
            FieldType::Date => Self::Date,
            FieldType::MonthYear => Self::MonthYear,
        }
    }
}

/// The state of this device.
#[derive(Debug, Clone, uniffi::Record)]
pub struct CoreStatus {
    /// An account is set up here.
    pub has_account: bool,
    /// The account is unlocked in this process.
    pub unlocked: bool,
    /// Account e-mail.
    pub email: Option<String>,
    /// Server URL.
    pub server: Option<String>,
    /// This device's name.
    pub device_name: Option<String>,
    /// The account's six pairing words (agents compare them), when unlocked.
    pub account_words: Option<String>,
}

/// Face ID state.
#[derive(Debug, Clone, uniffi::Record)]
pub struct BiometricState {
    /// The platform keystore can be used.
    pub available: bool,
    /// Face ID is set up for this account.
    pub enrolled: bool,
    /// Why the master password is needed first, if it is.
    pub password_required: Option<String>,
}

/// What a sync did.
#[derive(Debug, Clone, uniffi::Record)]
pub struct SyncInfo {
    /// Vaults whose revision moved.
    pub vaults_updated: u32,
    /// Items received.
    pub items_received: u32,
    /// Passkeys the AutoFill extension registered offline that are still
    /// not on the server after this sync (ADR 0020 §11).
    pub passkeys_waiting: u32,
    /// Passkey outboxes that could not be opened and were set aside, not
    /// acknowledged yet (T138): what they held is not uploaded.
    pub passkey_queues_set_aside: u32,
    /// Their IDs, for [`crate::KlavCore::acknowledge_passkey_queues_set_aside`]
    /// once the notice is shown.
    pub passkey_queue_set_aside_ids: Vec<String>,
}

/// A vault.
#[derive(Debug, Clone, uniffi::Record)]
pub struct VaultInfo {
    /// ID.
    pub id: String,
    /// Name.
    pub name: String,
    /// Live items.
    pub items: u32,
}

impl From<VaultSummary> for VaultInfo {
    fn from(v: VaultSummary) -> Self {
        Self {
            id: v.id.to_string(),
            name: v.name,
            items: u32::try_from(v.items).unwrap_or(u32::MAX),
        }
    }
}

/// A project.
#[derive(Debug, Clone, uniffi::Record)]
pub struct ProjectInfo {
    /// ID.
    pub id: String,
    /// Vault ID.
    pub vault_id: String,
    /// Vault name.
    pub vault: String,
    /// Name.
    pub name: String,
    /// Linked Git repositories in normalized `host/owner/repo` form (ADR 0032).
    pub repos: Vec<String>,
}

impl From<ProjectSummary> for ProjectInfo {
    fn from(p: ProjectSummary) -> Self {
        Self {
            id: p.id.to_string(),
            vault_id: p.vault_id.to_string(),
            vault: p.vault,
            name: p.name,
            repos: p.repos,
        }
    }
}

/// Item metadata (never secrets).
#[derive(Debug, Clone, uniffi::Record)]
pub struct ItemInfo {
    /// ID.
    pub id: String,
    /// `klav://vault/project/item`.
    pub reference: String,
    /// Vault ID.
    pub vault_id: String,
    /// Vault name.
    pub vault: String,
    /// Project ID.
    pub project_id: String,
    /// Project name.
    pub project: String,
    /// Type.
    pub kind: Kind,
    /// Title.
    pub title: String,
    /// User name, if any.
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
    /// The URLs whose site the person confirmed (ADR 0030 §7): the only
    /// ones autofill and suggestions use.
    #[uniffi(default = [])]
    pub confirmed_urls: Vec<String>,
    /// URLs an agent added that the person has not confirmed yet: never
    /// filled, shown as «Sites added by an agent» with confirm and remove.
    #[uniffi(default = [])]
    pub pending_urls: Vec<String>,
    /// The agent that wrote the current version, if one did.
    #[uniffi(default = None)]
    pub author_agent_id: Option<String>,
}

impl From<ItemSummary> for ItemInfo {
    fn from(s: ItemSummary) -> Self {
        Self {
            id: s.id.to_string(),
            reference: s.reference,
            vault_id: s.vault_id.to_string(),
            vault: s.vault,
            project_id: s.project_id.to_string(),
            project: s.project,
            kind: s.kind.into(),
            title: s.title,
            username: s.username,
            urls: s.urls,
            tags: s.tags,
            version: s.version,
            updated_at: s.updated_at,
            trashed: s.trashed,
            confirmed_urls: s.confirmed_urls,
            pending_urls: s.pending_urls,
            author_agent_id: s.author_agent_id.map(|a| a.to_string()),
        }
    }
}

/// A field. `value` holds plain fields only; secret ones come one at a
/// time from `KlavCore::field_value`, when the person asks.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FieldInfo {
    /// Name.
    pub name: String,
    /// Label.
    pub label: String,
    /// Type.
    pub kind: FieldType,
    /// Secret type.
    pub secret: bool,
    /// Has a value.
    pub filled: bool,
    /// Plain value (never set for secret fields).
    pub value: Option<String>,
}

impl From<FieldView> for FieldInfo {
    fn from(f: FieldView) -> Self {
        let value = if f.secret {
            None
        } else {
            f.value.map(|v| v.expose().to_owned())
        };
        Self {
            name: f.name,
            label: f.label,
            kind: f.kind.into(),
            secret: f.secret,
            filled: f.filled,
            value,
        }
    }
}

/// An attachment's metadata (the content stays on the server).
#[derive(Debug, Clone, uniffi::Record)]
pub struct AttachmentInfo {
    /// ID.
    pub id: String,
    /// File name.
    pub file_name: String,
    /// Size in bytes.
    pub size: u64,
    /// Media type.
    pub media_type: Option<String>,
}

/// An item without its secret values.
#[derive(Debug, Clone, uniffi::Record)]
pub struct ItemDetail {
    /// Metadata.
    pub info: ItemInfo,
    /// Fields.
    pub fields: Vec<FieldInfo>,
    /// Has notes (read them with `KlavCore::notes`).
    pub has_notes: bool,
    /// Has a filled one-time password field.
    pub has_totp: bool,
    /// Attachments.
    pub attachments: Vec<AttachmentInfo>,
}

impl From<ItemView> for ItemDetail {
    fn from(v: ItemView) -> Self {
        let has_totp = v
            .fields
            .iter()
            .any(|f| f.kind == FieldKind::Totp && f.filled);
        Self {
            info: v.summary.into(),
            fields: v.fields.into_iter().map(FieldInfo::from).collect(),
            has_notes: v.has_notes,
            has_totp,
            attachments: v
                .attachments
                .into_iter()
                .map(|a| AttachmentInfo {
                    id: a.id.to_string(),
                    file_name: a.file_name,
                    size: a.size,
                    media_type: a.media_type,
                })
                .collect(),
        }
    }
}

/// Which items to list.
#[derive(Debug, Clone, Default, uniffi::Record)]
pub struct ItemQuery {
    /// Vault ID.
    #[uniffi(default = None)]
    pub vault_id: Option<String>,
    /// Project ID.
    #[uniffi(default = None)]
    pub project_id: Option<String>,
    /// Text in titles, user names, URLs and tags.
    #[uniffi(default = None)]
    pub text: Option<String>,
    /// Type.
    #[uniffi(default = None)]
    pub kind: Option<Kind>,
    /// Any of these types (together with `kind`). Empty: every type.
    #[uniffi(default = [])]
    pub kinds: Vec<Kind>,
    /// Only items with a filled one-time code, of any type (the «Codes»
    /// view).
    #[uniffi(default = false)]
    pub codes: bool,
    /// The trash instead of live items.
    #[uniffi(default = false)]
    pub trash: bool,
}

/// A field value to set. Values typed in the app count as entered in
/// secret (never on a command line). Not `Debug` (T34).
#[derive(Clone, uniffi::Record)]
pub struct FieldEdit {
    /// Field name.
    pub name: String,
    /// Value.
    pub value: String,
    /// Type, for a field the item does not have yet.
    #[uniffi(default = None)]
    pub kind: Option<FieldType>,
}

/// A new item. Not `Debug`: it carries values (T34).
#[derive(Clone, uniffi::Record)]
pub struct NewItemInput {
    /// Type.
    pub kind: Kind,
    /// Title.
    pub title: String,
    /// Vault ID (default: Personal).
    #[uniffi(default = None)]
    pub vault_id: Option<String>,
    /// Project ID (default: General).
    #[uniffi(default = None)]
    pub project_id: Option<String>,
    /// Fields.
    #[uniffi(default = [])]
    pub fields: Vec<FieldEdit>,
    /// URLs.
    #[uniffi(default = [])]
    pub urls: Vec<String>,
    /// Tags.
    #[uniffi(default = [])]
    pub tags: Vec<String>,
    /// Notes.
    #[uniffi(default = None)]
    pub notes: Option<String>,
}

/// Changes to an item. Not `Debug`: it carries values (T34).
#[derive(Clone, Default, uniffi::Record)]
pub struct ItemEdit {
    /// New title.
    #[uniffi(default = None)]
    pub title: Option<String>,
    /// Fields to set.
    #[uniffi(default = [])]
    pub set: Vec<FieldEdit>,
    /// Fields to clear (template fields) or remove (custom fields).
    #[uniffi(default = [])]
    pub remove: Vec<String>,
    /// URLs to add.
    #[uniffi(default = [])]
    pub add_urls: Vec<String>,
    /// URLs to remove, exactly as stored: sites an agent added that the
    /// person does not want (ADR 0030 §7, like `klav item sites --remove`).
    /// Any edit by the person confirms the sites that stay.
    #[uniffi(default = [])]
    pub remove_urls: Vec<String>,
    /// Tags to add.
    #[uniffi(default = [])]
    pub add_tags: Vec<String>,
    /// New notes (empty clears them).
    #[uniffi(default = None)]
    pub notes: Option<String>,
}

/// A TOTP code. Not `Debug` (T34).
#[derive(Clone, uniffi::Record)]
pub struct TotpInfo {
    /// The code.
    pub code: String,
    /// Seconds until it changes.
    pub remaining: u64,
    /// Period in seconds.
    pub period: u64,
}

/// An approval request from an agent.
#[derive(Debug, Clone, uniffi::Record)]
pub struct ApprovalItem {
    /// ID.
    pub id: String,
    /// `pending`, `approved`, `denied`, `expired`, `used`.
    pub status: String,
    /// Agent ID.
    pub agent_id: String,
    /// Agent name.
    pub agent: String,
    /// Permission (`fill`, `totp`, `reveal`…).
    pub permission: String,
    /// The item (`klav://…`) or the project.
    pub target: String,
    /// The agent's reason.
    pub reason: String,
    /// Site it claims the value is for.
    pub domain: Option<String>,
    /// Asked at (Unix ms).
    pub created_at: i64,
    /// Decide before (Unix ms).
    pub expires_at: i64,
    /// The agent's running task this request falls outside of («Outside
    /// the task», ADR 0021 §6), if it has one.
    pub task: Option<OutsideTaskItem>,
    /// `SHA-256` (hex) of the exact request this item was built from (ADR
    /// 0030 §5). `decide_approval` and `add_to_task` take it back and sign
    /// nothing if the request changed since.
    pub request_digest: String,
    /// An MCP tool call through the credential proxy (ADR 0049 §5.4): the
    /// tool, according to the MCP server. Only once it passed the tool
    /// grammar on this device (`A-Z a-z 0-9 _ - .`).
    #[uniffi(default = None)]
    pub mcp_tool: Option<String>,
    /// The MCP profile the call goes through (`maple`), from the proxy's
    /// grant the account signed, when this device knows it.
    #[uniffi(default = None)]
    pub mcp_profile: Option<String>,
    /// The local MCP client the call is for, according to the proxy: only
    /// in its grammar (`a-z 0-9 -`).
    #[uniffi(default = None)]
    pub local_client: Option<String>,
    /// The sandbox the call is for, according to the proxy.
    #[uniffi(default = None)]
    pub sandbox_id: Option<String>,
    /// The request names an MCP tool or a caller in a form the server
    /// should have refused (ADR 0049 §5.4, T260): the card shows the app's
    /// fixed text and nothing to decide, and nothing of the offending
    /// field ever reaches it. `klavd` and `klav-client` refuse to decide
    /// it either way, before any prompt.
    #[uniffi(default = false)]
    pub security: bool,
}

/// The running task an approval request falls outside of (ADR 0021 §6).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct OutsideTaskItem {
    /// The task's ID.
    pub id: String,
    /// Its title, in the agent's words.
    pub task: String,
    /// When it ends (Unix ms).
    pub expires_at: i64,
    /// «Add to the task» is offered: `fill`, `totp`, `inject` or `update`
    /// on an item (and for `fill`, a site that matches it). `reveal` and
    /// `delete` only get «Approve once» and «Deny».
    pub can_add: bool,
}

/// A task request as the person sees it (ADR 0021 §3–4): mirror of
/// `klav_client::tasks::TaskCard`.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct TaskItem {
    /// ID.
    pub id: String,
    /// `pending`, `approved`, `denied`, `expired`, `ended`.
    pub status: String,
    /// Agent ID.
    pub agent_id: String,
    /// Agent name.
    pub agent: String,
    /// Title, in the agent's words.
    pub task: String,
    /// Why, in the agent's words.
    pub reason: String,
    /// Offered by the person, without a request from the agent (ADR 0022
    /// §6): title and reason are the person's.
    pub offered: bool,
    /// Requested duration (seconds), counted from the approval.
    pub duration_secs: u64,
    /// Asked at (Unix ms).
    pub created_at: i64,
    /// Decide before (Unix ms).
    pub decide_by: i64,
    /// Decided at (Unix ms; each «Add to the task» signs a new one).
    pub decided_at: Option<i64>,
    /// Revision of the decision in force (0 while pending).
    pub revision: u64,
    /// When an approved task ends (Unix ms).
    pub expires_at: Option<i64>,
    /// When it ended (Unix ms).
    pub ended_at: Option<i64>,
    /// Who ended it: `person`, `agent`, `expiry`, `revocation`.
    pub ended_by: Option<String>,
    /// One row per item: the proposal while pending, what was approved
    /// (and, unchecked, what was left out) once decided.
    pub rows: Vec<TaskRowItem>,
    /// `SHA-256` (hex) of the exact request this card was built from (ADR
    /// 0030 §5). `decide_task` takes it back and signs nothing if the
    /// request changed since.
    pub request_digest: String,
}

/// One item on a task card. Title, user name and hosts come from the
/// person's vault, never from the agent.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct TaskRowItem {
    /// Vault ID.
    pub vault_id: String,
    /// Project ID.
    pub project_id: String,
    /// Item ID.
    pub item_id: String,
    /// `klav://vault/project/item`, or `item <id>` when this device does
    /// not have it.
    pub reference: String,
    /// Title, from the vault.
    pub title: Option<String>,
    /// User name, from the vault.
    pub username: Option<String>,
    /// Not in the vault, in the trash or outside the agent's grant: it
    /// cannot be approved.
    pub missing: bool,
    /// The host the agent gave, if any.
    pub asked_domain: Option<String>,
    /// The agent's host matches none of the item's URLs: unchecked, and
    /// it cannot be checked (T92).
    pub domain_mismatch: bool,
    /// The hosts that are (or will be) approved.
    pub domains: Vec<String>,
    /// Permissions, in order.
    pub permissions: Vec<TaskPermissionItem>,
    /// The item has no site and a permission on the row needs one («No
    /// site», ADR 0030 §6).
    pub no_site: bool,
    /// `domains` is the host the agent asked for, on a card or an
    /// identity: shown «according to the agent».
    pub domain_claimed: bool,
}

/// One permission on a task card.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct TaskPermissionItem {
    /// `fill`, `totp`, `inject`, `update`, `passkey`, `rotate`.
    pub permission: String,
    /// Checked: approved if the person leaves it (or approved, once
    /// decided).
    pub checked: bool,
    /// The agent asked for it.
    pub asked: bool,
    /// Added by Klav, not by the agent («Added by Klav»).
    pub added_by_klav: bool,
    /// The person's policy denies it: struck through, cannot be checked.
    pub denied_by_policy: bool,
    /// It checks the site and the item has none: cannot be checked.
    pub no_site: bool,
}

/// What the person changed on a pending task card before approving
/// (mirror of `klav_client::tasks::TaskChoice`; uniffi has no tuples).
#[derive(Debug, Clone, Default, PartialEq, Eq, uniffi::Record)]
pub struct TaskChoiceInput {
    /// Unchecked: whole items or single permissions.
    pub without: Vec<TaskChoiceEntry>,
    /// Checked by hand: what Klav offered unchecked. Never what the policy
    /// denies.
    pub with: Vec<TaskChoiceEntry>,
    /// A shorter duration (seconds); never longer than requested, at least
    /// 5 minutes.
    pub for_secs: Option<u64>,
}

/// An item, or one of its permissions, in a [`TaskChoiceInput`].
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct TaskChoiceEntry {
    /// Item ID.
    pub item_id: String,
    /// The permission (`None`: the whole item).
    pub permission: Option<String>,
}

/// An agent of the account.
#[derive(Debug, Clone, uniffi::Record)]
pub struct AgentItem {
    /// ID.
    pub id: String,
    /// Name.
    pub name: String,
    /// Note from the registration.
    pub note: Option<String>,
    /// `pending`, `active`, `denied`, `revoked`.
    pub status: String,
    /// Six pairing words.
    pub pairing_words: String,
    /// Registered at (Unix ms).
    pub created_at: i64,
    /// A pending registration expires at (Unix ms).
    pub expires_at: i64,
    /// Granted projects (`vault/project`), when active.
    pub projects: Vec<String>,
}

/// A password for the AutoFill extension.
#[derive(uniffi::Record)]
pub struct PasswordCredential {
    /// User name.
    pub username: String,
    /// Password.
    pub password: String,
}

impl std::fmt::Debug for PasswordCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PasswordCredential")
            .field("username", &self.username)
            .finish_non_exhaustive()
    }
}

/// How a site relates to a login's URLs (ADR 0025 §3), in the order
/// logins are offered: exact host, then a subdomain of the item's, then the
/// parent of the item's (only when the person picks it).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum SiteRelation {
    /// The site's host is one of the item's.
    Exact,
    /// The site is a subdomain of one of the item's hosts.
    Subdomain,
    /// The site is the parent domain of one of the item's hosts
    /// (`1password.com` for an item of `my.1password.com`).
    Parent,
}

impl From<klav_core::site::HostRelation> for SiteRelation {
    fn from(r: klav_core::site::HostRelation) -> Self {
        use klav_core::site::HostRelation;
        match r {
            HostRelation::Exact => Self::Exact,
            HostRelation::Subdomain => Self::Subdomain,
            HostRelation::Parent => Self::Parent,
        }
    }
}

/// A login saved for a subdomain of the site AutoFill asked for (ADR
/// 0025): offered apart, «Saved for a subdomain», with `saved_host` in view.
#[derive(Debug, Clone, uniffi::Record)]
pub struct ParentSuggestion {
    /// The login.
    pub item: ItemInfo,
    /// The host it was saved for (`my.1password.com`).
    pub saved_host: String,
}

/// What iOS shows in the QuickType bar (`ASCredentialIdentityStore`):
/// metadata only, never secrets.
#[derive(Debug, Clone, uniffi::Record)]
pub struct CredentialIdentity {
    /// Item ID (the record identifier).
    pub item_id: String,
    /// Title.
    pub title: String,
    /// User name (may be empty).
    pub username: String,
    /// Hosts of the item's URLs (lowercase, no `www.`).
    pub hosts: Vec<String>,
    /// Has a password.
    pub has_password: bool,
    /// Has a one-time password.
    pub has_totp: bool,
}

/// Generator types (ADR 0022 §1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum GeneratorType {
    /// Follows the site's rules; 20 random characters without them.
    Smart,
    /// Letters, digits and symbols.
    Random,
    /// Words from the EFF list.
    Memorable,
    /// Digits only.
    Pin,
}

impl From<GeneratorType> for klav_core::generator::GeneratorKind {
    fn from(k: GeneratorType) -> Self {
        match k {
            GeneratorType::Smart => Self::Smart,
            GeneratorType::Random => Self::Random,
            GeneratorType::Memorable => Self::Memorable,
            GeneratorType::Pin => Self::Pin,
        }
    }
}

/// What the person chose in the generator.
#[derive(Debug, Clone, uniffi::Record)]
pub struct GeneratorInput {
    /// Type.
    pub kind: GeneratorType,
    /// Length (`random`).
    pub length: u32,
    /// Digits (`random`).
    pub digits: bool,
    /// Symbols (`random`).
    pub symbols: bool,
    /// Words (`memorable`).
    pub words: u32,
    /// Digits of a PIN.
    pub pin_length: u32,
}

/// A generated password and how strong it is. Not logged.
#[derive(Clone, uniffi::Record)]
pub struct GeneratedPassword {
    /// The password.
    pub value: String,
    /// Bits of entropy.
    pub bits: f64,
    /// `weak`, `fair`, `strong` or `very_strong`.
    pub strength: String,
    /// The domain whose bundled rules it followed (`smart`).
    pub rules_domain: Option<String>,
    /// The site does not allow a stronger one.
    pub limited: bool,
    /// The site's rules could not be used: `unreadable` or `impossible`.
    pub fallback: Option<String>,
}

/// One generator history entry, without its value.
#[derive(Debug, Clone, uniffi::Record)]
pub struct GeneratedEntryInfo {
    /// When (Unix ms); also its ID.
    pub created_at: i64,
    /// The site.
    pub host: Option<String>,
    /// Title of the login it was saved in.
    pub saved_in_title: Option<String>,
    /// Still only on this device.
    pub pending: bool,
}

/// A remark about part of an imported file (`row 4`: why), no values.
#[derive(Debug, Clone, uniffi::Record)]
pub struct ImportRemarkInfo {
    /// Where in the file.
    pub at: String,
    /// Why it was skipped or shortened.
    pub reason: String,
}

/// What one file (or QR code) of an import contributed.
#[derive(Debug, Clone, uniffi::Record)]
pub struct ImportFileInfo {
    /// File name, as given.
    pub name: String,
    /// What it is (`Bitwarden`, `Google Authenticator`…), for the person.
    pub format: String,
    /// Entries read.
    pub items: u32,
    /// Parts not imported.
    pub skipped: Vec<ImportRemarkInfo>,
    /// Parts imported with something left out.
    pub notes: Vec<ImportRemarkInfo>,
    /// Remarks counted but not listed.
    pub more_remarks: u32,
    /// Passkeys found (not imported).
    pub passkeys: u32,
}

/// Google Authenticator QR codes still missing from an export in several.
#[derive(Debug, Clone, uniffi::Record)]
pub struct ImportMissingInfo {
    /// How many QR codes the export has.
    pub size: u32,
    /// Which ones are not here yet, from 1.
    pub missing: Vec<u32>,
}

/// The files of an import so far.
#[derive(Debug, Clone, uniffi::Record)]
pub struct ImportStateInfo {
    /// One per file, in order.
    pub files: Vec<ImportFileInfo>,
    /// Entries read.
    pub entries: u32,
    /// Passkeys found (not imported).
    pub passkeys: u32,
    /// QR codes still missing.
    pub missing: Vec<ImportMissingInfo>,
}

/// One line of an import preview: no values.
#[derive(Debug, Clone, uniffi::Record)]
pub struct ImportRowInfo {
    /// Title in the file.
    pub title: String,
    /// Item type.
    pub kind: Kind,
    /// User name or account, if any.
    pub username: Option<String>,
    /// The site, if any.
    pub host: Option<String>,
    /// `new`, `merge` or `duplicate`.
    pub action: String,
    /// The title of the item it ends up in.
    pub target: String,
    /// What changes (`password_replaced`, `totp_added`…).
    pub changes: Vec<String>,
    /// The sites a merge adds (with `urls_added`), by host: the preview
    /// names them (T119).
    pub sites_added: Vec<String>,
}

/// What an import would do.
#[derive(Debug, Clone, uniffi::Record)]
pub struct ImportPreviewInfo {
    /// Destination vault.
    pub vault: String,
    /// Destination project.
    pub project: String,
    /// New items.
    pub new: u32,
    /// Entries merged into an item.
    pub merged: u32,
    /// Entries already in Klav.
    pub duplicates: u32,
    /// The first rows.
    pub rows: Vec<ImportRowInfo>,
    /// Rows in all.
    pub rows_total: u32,
    /// Passkeys not imported.
    pub passkeys: u32,
    /// QR codes still missing.
    pub missing: Vec<ImportMissingInfo>,
}

/// What an import did.
#[derive(Debug, Clone, uniffi::Record)]
pub struct ImportResultInfo {
    /// Destination vault.
    pub vault: String,
    /// Destination project.
    pub project: String,
    /// Items created.
    pub created: u32,
    /// Items updated.
    pub updated: u32,
    /// Entries already in Klav.
    pub duplicates: u32,
    /// Passkeys not imported.
    pub passkeys: u32,
    /// Passkeys that could not be saved, as `"<title>: <why>"`: their
    /// login was imported without them.
    pub passkeys_failed: Vec<String>,
}

/// A passkey for `ASCredentialIdentityStore` (`ASPasskeyCredentialIdentity`):
/// metadata only, never the key (ADR 0020 §11).
#[derive(Debug, Clone, uniffi::Record)]
pub struct PasskeyIdentityInfo {
    /// Item ID (the record identifier).
    pub item_id: String,
    /// Title of the login.
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

/// A sign-in with a passkey, over the `clientDataHash` iOS built.
#[derive(Debug, Clone, uniffi::Record)]
pub struct PasskeyAssertionInfo {
    /// Credential ID.
    pub credential_id: Vec<u8>,
    /// Authenticator data (UP and UV: Face ID opened the extension).
    pub authenticator_data: Vec<u8>,
    /// ES256 signature, DER.
    pub signature: Vec<u8>,
    /// User handle.
    pub user_handle: Vec<u8>,
    /// The login that signed.
    pub item_id: String,
}

/// A registration from `ASPasskeyCredentialRequest`, without network.
#[derive(Debug, Clone, uniffi::Record)]
pub struct PasskeyRegistrationInput {
    /// Relying party ID (iOS checked it against the site's associated domains).
    pub rp_id: String,
    /// The site's name, when iOS gives one.
    pub rp_name: Option<String>,
    /// `user.name`.
    pub user_name: String,
    /// `user.displayName`.
    pub user_display_name: Option<String>,
    /// `user.id` (1 to 64 bytes).
    pub user_handle: Vec<u8>,
    /// `excludeCredentials`.
    pub exclude_credentials: Vec<Vec<u8>>,
    /// Save it in this login (else the account's own, else a new one).
    pub item_id: Option<String>,
    /// The person confirmed replacing the account's passkey.
    pub replace: bool,
    /// Vault of a new login (default: the person's default).
    pub vault: Option<String>,
    /// Project of a new login.
    pub project: Option<String>,
}

/// How a registration without network ends.
#[derive(Debug, Clone, uniffi::Enum)]
pub enum PasskeyRegistrationOutcome {
    /// Created: usable now on this iPhone, and queued for the app.
    Created {
        /// Credential ID.
        credential_id: Vec<u8>,
        /// Attestation object (`fmt: none`).
        attestation_object: Vec<u8>,
        /// Authenticator data.
        authenticator_data: Vec<u8>,
        /// The login.
        item_id: String,
        /// Its title.
        title: String,
    },
    /// Klav holds one of the excluded credentials (iOS answers with its error).
    Excluded,
    /// The account already has a passkey: ask, then retry with `replace`.
    Exists {
        /// The login.
        item_id: String,
        /// Its title.
        title: String,
    },
}

/// A passkey waiting for the app to upload it.
#[derive(Debug, Clone, uniffi::Record)]
pub struct QueuedPasskeyInfo {
    /// The login.
    pub item_id: String,
    /// Its title.
    pub title: String,
}

/// What waits in the passkey outbox («Open Klav to sync this passkey»).
#[derive(Debug, Clone, uniffi::Record)]
pub struct PasskeyOutboxInfo {
    /// Registrations waiting.
    pub passkeys: Vec<QueuedPasskeyInfo>,
    /// Sign-ins waiting to be logged.
    pub uses: u32,
}

/// What the person agreed to lose by signing out or deleting this
/// device's copy (ADR 0020 §11, T138; ADR 0037 Q3): what the dialog they
/// confirmed said. Klav refuses if, when it deletes the copy, more is
/// waiting than that.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum AcceptedLoss {
    /// The dialog said nothing was waiting.
    Nothing,
    /// The dialog said these would be lost.
    Unsent {
        /// Passkeys registered offline.
        passkeys: u32,
        /// Generated passwords.
        generated: u32,
    },
    /// The dialog said Klav could not tell (locked with a queue, or the
    /// check failed), or the person chose «Delete anyway»: whatever is
    /// waiting.
    Unknown,
}

/// A deletion of the account the person asked for (ADR 0037 §3): the
/// server deletes the account at `delete_at` unless a device cancels it.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct AccountDeletionInfo {
    /// When it was asked for (Unix ms).
    pub requested_at: i64,
    /// When the server deletes the account (Unix ms): 7 days later.
    pub delete_at: i64,
    /// The device that asked, as the device list names it.
    pub device_name: String,
    /// This device asked.
    pub this_device: bool,
    /// The server already deleted the account: this device knew the date
    /// and got a `401` after it (ADR 0037 §3). Kept on disk, so it holds
    /// after a restart without network. The copy stays, read-only.
    pub deleted: bool,
}

/// What signing out, or deleting this device's copy, would lose (ADR
/// 0020 §11, T138; ADR 0037 Q3).
#[derive(Debug, Clone, uniffi::Record)]
pub struct SignOutCheck {
    /// Passkeys registered offline that could not be uploaded just now:
    /// their private keys exist only in this iPhone's outbox.
    pub unsent_passkeys: u32,
    /// Generated passwords that could not be uploaded just now: only in
    /// this device's generator outbox (the history lists them, to copy).
    pub unsent_generated: u32,
    /// Klav could not count what waits (locked, or on the Mac a queue
    /// `klavd` does not list) and an outbox is not empty: count it as
    /// something.
    pub locked_with_queue: bool,
}

/// What emptying the passkey outbox did.
#[derive(Debug, Clone, uniffi::Record)]
pub struct PasskeyFlushInfo {
    /// Registrations uploaded.
    pub uploaded: u32,
    /// New logins renamed because their title was taken meanwhile.
    pub renamed: u32,
    /// `passkey.used` events sent.
    pub uses_sent: u32,
    /// Entries left for the next time.
    pub left: u32,
    /// Why the first of those failed.
    pub error: Option<String>,
    /// Outboxes set aside since the last flush (T138).
    pub set_aside: u32,
    /// Their IDs, to acknowledge once the notice is shown.
    pub set_aside_ids: Vec<String>,
}

/// Validated `setup_url` on a [`SecretRequestItem`] (ADR 0046, T235).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SecretRequestSetupUrlItem {
    /// Canonical `https://…` URL.
    pub url: String,
    /// Lowercase ASCII host displayed prominently in the warning banner.
    pub host: String,
    /// `true` when any label starts with `xn--` (IDN homograph cue).
    pub has_punycode: bool,
}

/// Optional `klav-proxy` profile proposed inside a secret request (ADR 0046 Q3,
/// T239). Always unchecked by default on the person's card.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SecretRequestProxyProposalItem {
    /// Optional preset name.
    pub preset: Option<String>,
    /// Profile name (`vercel-ai`, `stripe`, …).
    pub profile: String,
    /// Upstream `https://…` URL.
    pub upstream: String,
    /// Header name (`authorization`, …).
    pub header: String,
    /// Prefix before the secret (`Bearer `, …).
    pub prefix: String,
    /// Allowed HTTP methods.
    pub methods: Vec<String>,
    /// HTTP methods that ask per call.
    pub ask_methods: Vec<String>,
    /// Allowed path prefixes.
    pub path_prefixes: Vec<String>,
    /// Optional per-minute rate limit (`1..=600`).
    pub rate_per_minute: Option<u32>,
}

/// A `(vault_id, project_id)` pair inside the asking agent's grant.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SecretRequestProjectPair {
    pub vault_id: String,
    pub project_id: String,
}

/// A secret request from an agent as the person sees it (ADR 0046).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SecretRequestItem {
    /// Secret request ID.
    pub id: String,
    /// `pending`, `fulfilled`, `denied`, `expired`.
    pub status: String,
    /// Asking agent ID.
    pub agent_id: String,
    /// Asking agent name (sanitized; "name set by the agent").
    pub agent: String,
    /// `create` or `update`.
    pub mode: String,
    /// Target item ID (`update` mode).
    pub target_item_id: Option<String>,
    /// Real `klav://Vault/Project/Title` from this device's vault (`update` mode).
    pub target_reference: Option<String>,
    /// Real item title from this device's vault (`update` mode).
    pub target_title: Option<String>,
    /// Real item kind from this device's vault (`update` mode).
    pub target_kind: Option<String>,
    /// Plaintext reason supplied by the agent.
    pub reason: String,
    /// Created at (Unix ms).
    pub created_at: i64,
    /// Expires at (Unix ms).
    pub expires_at: i64,
    /// Decided at (Unix ms), if decided.
    pub decided_at: Option<i64>,
    /// SHA-256 (hex) of the canonical proposal JSON reviewed by the person.
    pub proposal_digest: String,
    /// Non-empty when the proposal could not be opened or validated (refuses
    /// fulfillment).
    pub proposal_error: Option<String>,
    /// Proposed item kind (`create` mode: `api_key`, `login`, `note`, `ssh_key`, `totp`).
    pub kind: Option<String>,
    /// Proposed item title (`create` mode).
    pub title: Option<String>,
    /// Proposed destination vault ID (`create` mode).
    pub vault_id: Option<String>,
    /// Proposed destination project ID (`create` mode).
    pub project_id: Option<String>,
    /// Proposed secret field name (`api_key`, `password`, …).
    pub field: Option<String>,
    /// Short placeholder hint for the hidden input.
    pub placeholder: Option<String>,
    /// Validated `setup_url` with full host and punycode cue (T235).
    pub setup_url: Option<SecretRequestSetupUrlItem>,
    /// Proposed non-secret `base_url` (`api_key` items).
    pub base_url: Option<String>,
    /// Agent-suggested `login` URLs (unchecked by default, T234).
    pub urls: Vec<String>,
    /// Proposed non-secret notes (`create` mode).
    pub notes: Option<String>,
    /// Optional proposed `klav-proxy` profile (unchecked by default, T239).
    pub proxy_proposal: Option<SecretRequestProxyProposalItem>,
    /// Projects in the asking agent's verified grant, so the card can badge
    /// "Shared with `<agent>`" vs "Not shared with `<agent>`".
    pub agent_projects: Vec<SecretRequestProjectPair>,
}

/// Values the person enters to fulfill a pending secret request (ADR 0046).
/// Never implements `Debug` or `Display` (T34).
#[derive(Clone, uniffi::Record)]
pub struct SecretRequestFulfillInput {
    /// `proposal_digest` (hex) of the card the person reviewed.
    pub digest: String,
    /// Secret value entered in the hidden input (never logged).
    pub secret: String,
    /// Destination vault name or ID (`create` mode).
    pub vault: Option<String>,
    /// Destination project name or ID (`create` mode).
    pub project: Option<String>,
    /// Title override (`create` mode).
    pub title: Option<String>,
    /// Secret field name override.
    pub field: Option<String>,
    /// Explicitly confirmed login URLs (`None` saves no agent-suggested URLs, T234).
    pub urls: Option<Vec<String>>,
    /// Notes override (`create` mode).
    pub notes: Option<String>,
    /// Allow duplicate title in the destination project.
    pub allow_duplicate: bool,
    /// Explicitly opted-in proxy grant (unchecked by default, requires presence, T239).
    pub grant_proxy: bool,
    /// Expected proxy grant base version (staleness check when `grant_proxy` is true).
    pub proxy_base_version: Option<u64>,
    /// Person confirmed every device is updated (first per-item grant on account).
    pub every_device_updated: bool,
    /// Proxy pairing words shown (first grant for a pending proxy).
    pub shown_words: Option<String>,
}

/// Result of fulfilling a secret request (ADR 0046). Carries no secret values.
#[derive(Debug, Clone, uniffi::Record)]
pub struct SecretRequestFulfillOutput {
    /// Updated card with the signed decision.
    pub card: SecretRequestItem,
    /// Created or updated vault item summary.
    pub item: ItemInfo,
    /// Whether the saved item is inside the asking agent's grant (T236).
    pub in_grant: bool,
    /// Granted `klav-proxy` profile name, if `grant_proxy` succeeded.
    pub proxy_profile: Option<String>,
    /// Warnings returned by the proxy grant step, if any.
    pub proxy_warnings: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    // T34: what carries a value across the FFI never prints it.
    static_assertions::assert_not_impl_any!(FieldEdit: std::fmt::Debug, std::fmt::Display);
    static_assertions::assert_not_impl_any!(NewItemInput: std::fmt::Debug, std::fmt::Display);
    static_assertions::assert_not_impl_any!(ItemEdit: std::fmt::Debug, std::fmt::Display);
    static_assertions::assert_not_impl_any!(TotpInfo: std::fmt::Debug, std::fmt::Display);
    static_assertions::assert_not_impl_any!(GeneratedPassword: std::fmt::Debug, std::fmt::Display);
    static_assertions::assert_not_impl_any!(
        SecretRequestFulfillInput: std::fmt::Debug,
        std::fmt::Display
    );
}
