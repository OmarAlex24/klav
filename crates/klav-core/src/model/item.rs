//! Items and typed fields (design §3).
//!
//! An item is stored as two JSON documents, each encrypted separately (spec
//! §7): the [`Overview`] (metadata visible with the `list` permission) and the
//! details (fields, notes, attachments). Both carry a schema version `v`.

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::Zeroizing;

use super::history::GeneratedEntry;
use super::passkey::{Passkey, PasskeySummary, RawPasskey};
use super::preferences::Preferences;
use crate::crypto::CryptoError;
use crate::crypto::context::ItemContext;
use crate::crypto::encoding::Kind;
use crate::crypto::item::{Section, decrypt_item_section, encrypt_item_section};
use crate::crypto::keys::ItemKey;
use crate::ids::{AttachmentId, FieldId, ItemId, looks_like_id};

/// Schema version of the overview and details JSON documents.
pub const SCHEMA_VERSION: u32 = 1;
/// Maximum length of a title, tag or label, in characters.
pub const MAX_TEXT_LEN: usize = 256;
/// Maximum length of a field name, in bytes.
pub const MAX_FIELD_NAME_LEN: usize = 64;
/// Maximum length of a URL, in bytes.
pub const MAX_URL_LEN: usize = 2048;

/// Errors of the item model.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ModelError {
    /// The title is empty, too long or contains control characters.
    #[error("invalid title")]
    InvalidTitle,
    /// A field name does not match `[a-z0-9][a-z0-9_-]{0,63}` or looks like an ID.
    #[error("invalid field name {0:?}")]
    InvalidFieldName(String),
    /// Two fields share a name or an ID.
    #[error("duplicate field {0:?}")]
    DuplicateField(String),
    /// A field value does not fit its type.
    #[error("invalid value for field {field:?}: {reason}")]
    InvalidFieldValue {
        /// Field name.
        field: String,
        /// What is wrong.
        reason: &'static str,
    },
    /// A tag, label or URL is empty, too long or contains control characters.
    #[error("invalid {0}")]
    InvalidText(&'static str),
    /// The document declares an unknown schema version.
    #[error("unsupported item schema version {0}")]
    UnsupportedSchema(u32),
    /// The overview and details belong to items of different kinds.
    #[error("overview and details do not match")]
    SectionMismatch,
    /// The JSON is invalid. The message never contains field values.
    #[error("invalid item JSON: {0}")]
    Json(String),
    /// Encryption or decryption failed.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
}

/// Item types (design §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ItemKind {
    /// Website or app login.
    Login,
    /// Payment card.
    Card,
    /// Identity / address.
    Identity,
    /// SSH key.
    SshKey,
    /// File (`.p8`, PDF…), stored as an attachment.
    File,
    /// Standalone TOTP secret.
    Totp,
    /// Secure note.
    Note,
    /// API key / token.
    ApiKey,
    /// The account's generator history (ADR 0022 §2). Lives only in the
    /// system project; never listed, never in a grant.
    GeneratorHistory,
    /// The account's preferences (ADR 0032 §7, ADR 0036 §3). Lives only in
    /// the system project; never listed, never in a grant.
    Preferences,
}

impl ItemKind {
    /// Whether items of this kind belong to Klav itself and are never shown
    /// in lists or created by hand.
    pub fn is_system(self) -> bool {
        matches!(self, ItemKind::GeneratorHistory | ItemKind::Preferences)
    }
}

/// Field types. Secret types ([`FieldKind::is_secret`]) never appear in the overview.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldKind {
    /// User name or login identifier.
    Username,
    /// Password.
    Password,
    /// TOTP secret: an `otpauth://` URI or a bare base32 secret.
    Totp,
    /// Reference to one of the item's attachments.
    File,
    /// Free text.
    Text,
    /// Any other secret text (API keys, card numbers, PINs, private keys).
    Concealed,
    /// URL.
    Url,
    /// E-mail address.
    Email,
    /// Phone number.
    Phone,
    /// Date (`YYYY-MM-DD`).
    Date,
    /// Month and year (`YYYY-MM`), e.g. card expiry.
    MonthYear,
}

impl FieldKind {
    /// Whether values of this type are secrets.
    pub fn is_secret(self) -> bool {
        matches!(
            self,
            FieldKind::Password | FieldKind::Totp | FieldKind::Concealed
        )
    }
}

/// A secret string. Not `Debug`, not `Display`; zeroized on drop.
pub struct SecretValue(SecretString);

impl SecretValue {
    /// Wraps a secret.
    pub fn new(value: impl Into<String>) -> Self {
        Self(SecretString::from(value.into()))
    }

    /// The secret. Callers must not log or display it.
    pub fn expose(&self) -> &str {
        self.0.expose_secret()
    }
}

impl Clone for SecretValue {
    fn clone(&self) -> Self {
        Self::new(self.expose())
    }
}

impl PartialEq for SecretValue {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.expose().as_bytes().ct_eq(other.expose().as_bytes()))
    }
}

impl Eq for SecretValue {}

/// The value of a field.
#[derive(Clone, PartialEq, Eq)]
pub enum FieldValue {
    /// Non-secret text.
    Plain(String),
    /// Secret text.
    Secret(SecretValue),
    /// Attachment of the same item.
    File(AttachmentId),
}

impl FieldValue {
    /// The value as text, as stored in the details JSON. Exposes secrets.
    fn expose_text(&self) -> std::borrow::Cow<'_, str> {
        match self {
            FieldValue::Plain(s) => s.as_str().into(),
            FieldValue::Secret(s) => s.expose().into(),
            FieldValue::File(id) => id.to_string().into(),
        }
    }
}

/// A typed field of an item.
#[derive(Clone, PartialEq, Eq)]
pub struct Field {
    id: FieldId,
    name: String,
    label: String,
    kind: FieldKind,
    value: FieldValue,
}

/// Checks a field name: `[a-z0-9][a-z0-9_-]{0,63}`, not shaped like an ID.
pub fn validate_field_name(name: &str) -> Result<(), ModelError> {
    let valid = !name.is_empty()
        && name.len() <= MAX_FIELD_NAME_LEN
        && name.bytes().enumerate().all(|(i, b)| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || (i > 0 && (b == b'_' || b == b'-'))
        })
        && !looks_like_id(name);
    if valid {
        Ok(())
    } else {
        Err(ModelError::InvalidFieldName(name.to_string()))
    }
}

/// Derives a field name from a human label: lowercase ASCII letters and
/// digits, other runs become `_`. Returns `None` if nothing usable remains.
pub fn slugify(label: &str) -> Option<String> {
    let mut out = String::new();
    let mut pending_sep = false;
    for c in label.chars().flat_map(char::to_lowercase) {
        if c.is_ascii_lowercase() || c.is_ascii_digit() {
            if pending_sep && !out.is_empty() {
                out.push('_');
            }
            pending_sep = false;
            out.push(c);
        } else {
            pending_sep = true;
        }
        if out.len() >= MAX_FIELD_NAME_LEN {
            break;
        }
    }
    out.truncate(MAX_FIELD_NAME_LEN);
    let out = out.trim_end_matches('_').to_string();
    validate_field_name(&out).ok().map(|()| out)
}

fn validate_text(text: &str, what: &'static str, allow_empty: bool) -> Result<(), ModelError> {
    if (!allow_empty && text.trim().is_empty())
        || text.chars().count() > MAX_TEXT_LEN
        || text.chars().any(char::is_control)
    {
        return Err(ModelError::InvalidText(what));
    }
    Ok(())
}

fn validate_url(url: &str) -> Result<(), ModelError> {
    if url.trim().is_empty() || url.len() > MAX_URL_LEN || url.chars().any(char::is_control) {
        return Err(ModelError::InvalidText("URL"));
    }
    Ok(())
}

/// What a new autofill URL must be (threat T21): a web address, `http` or
/// `https` or bare (`github.com`, read as `https`), with a host and no user
/// name or password in it (`https://github.com@evil.io` is `evil.io`).
/// Only new URLs are checked: items saved before keep theirs, and the
/// matching rule ([`crate::site`]) does not fill from other schemes.
fn validate_item_url(url: &str) -> Result<(), ModelError> {
    validate_url(url)?;
    let url = url.trim();
    let parsed = if url.contains("://") {
        url::Url::parse(url)
    } else {
        url::Url::parse(&format!("https://{url}"))
    }
    .map_err(|_| ModelError::InvalidText("URL (not a web address)"))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(ModelError::InvalidText(
            "URL (only http or https addresses)",
        ));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(ModelError::InvalidText(
            "URL (no user name or password in the address)",
        ));
    }
    if parsed.host_str().is_none_or(str::is_empty) {
        return Err(ModelError::InvalidText("URL (no host)"));
    }
    Ok(())
}

impl Field {
    /// Builds a field, interpreting `value` according to `kind`.
    pub fn new(name: &str, label: &str, kind: FieldKind, value: &str) -> Result<Self, ModelError> {
        Self::with_id(FieldId::generate(), name, label, kind, value)
    }

    fn with_id(
        id: FieldId,
        name: &str,
        label: &str,
        kind: FieldKind,
        value: &str,
    ) -> Result<Self, ModelError> {
        validate_field_name(name)?;
        validate_text(label, "label", true)?;
        let value = Self::parse_value(name, kind, value)?;
        Ok(Self {
            id,
            name: name.to_string(),
            label: label.to_string(),
            kind,
            value,
        })
    }

    fn parse_value(name: &str, kind: FieldKind, value: &str) -> Result<FieldValue, ModelError> {
        let invalid = |reason| ModelError::InvalidFieldValue {
            field: name.to_string(),
            reason,
        };
        Ok(match kind {
            FieldKind::File => {
                if value.is_empty() {
                    return Err(invalid("a file field must reference an attachment ID"));
                }
                FieldValue::File(value.parse().map_err(|_| invalid("not an attachment ID"))?)
            }
            FieldKind::Totp if !value.is_empty() => {
                crate::totp::Totp::from_field_value(value)
                    .map_err(|_| invalid("not a valid TOTP secret"))?;
                FieldValue::Secret(SecretValue::new(value))
            }
            k if k.is_secret() => FieldValue::Secret(SecretValue::new(value)),
            FieldKind::Url if !value.is_empty() => {
                validate_url(value).map_err(|_| invalid("not a valid URL"))?;
                FieldValue::Plain(value.to_string())
            }
            FieldKind::Date if !value.is_empty() && !is_date(value, true) => {
                return Err(invalid("expected YYYY-MM-DD"));
            }
            FieldKind::MonthYear if !value.is_empty() && !is_date(value, false) => {
                return Err(invalid("expected YYYY-MM"));
            }
            _ => FieldValue::Plain(value.to_string()),
        })
    }

    /// Stable ID.
    pub fn id(&self) -> FieldId {
        self.id
    }

    /// Reference name (`klav://…/<name>`).
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Human label.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Type.
    pub fn kind(&self) -> FieldKind {
        self.kind
    }

    /// Value.
    pub fn value(&self) -> &FieldValue {
        &self.value
    }

    /// Replaces the value, validating it against the field type.
    pub fn set_value(&mut self, value: &str) -> Result<(), ModelError> {
        self.value = Self::parse_value(&self.name, self.kind, value)?;
        Ok(())
    }

    /// Whether the value is empty.
    pub fn is_empty(&self) -> bool {
        self.value.expose_text().is_empty()
    }
}

fn is_date(value: &str, with_day: bool) -> bool {
    let parts: Vec<&str> = value.split('-').collect();
    let digits = |s: &str, n: usize| s.len() == n && s.bytes().all(|b| b.is_ascii_digit());
    let in_range =
        |s: &str, lo: u32, hi: u32| s.parse::<u32>().is_ok_and(|v| (lo..=hi).contains(&v));
    match (with_day, parts.as_slice()) {
        (true, [y, m, d]) => {
            digits(y, 4) && digits(m, 2) && digits(d, 2) && in_range(m, 1, 12) && in_range(d, 1, 31)
        }
        (false, [y, m]) => digits(y, 4) && digits(m, 2) && in_range(m, 1, 12),
        _ => false,
    }
}

/// Metadata of an attachment (its bytes are encrypted separately, spec §10).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttachmentMeta {
    /// Attachment ID (bound into the attachment AAD).
    pub id: AttachmentId,
    /// Original file name.
    pub file_name: String,
    /// Plaintext size in bytes.
    pub size: u64,
    /// Media type, if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
}

/// Metadata visible with the `list` permission. Contains no secrets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Overview {
    /// Schema version.
    pub v: u32,
    /// Item type.
    pub kind: ItemKind,
    /// Title (also the item name in `klav://` references).
    pub title: String,
    /// First `username` field, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// URLs used for autofill.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub urls: Vec<String>,
    /// Tags.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// Summary of the login's passkey (ADR 0020 §3), without secrets.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passkey: Option<PasskeySummary>,
}

/// An item: a login, card, identity, SSH key, file, TOTP, note or API key.
#[derive(Clone, PartialEq, Eq)]
pub struct Item {
    id: ItemId,
    kind: ItemKind,
    title: String,
    tags: Vec<String>,
    urls: Vec<String>,
    fields: Vec<Field>,
    notes: Option<SecretValue>,
    attachments: Vec<AttachmentMeta>,
    /// Sealed password record (blob `0x16`), opaque here: only a client
    /// with the vault key opens it (`model::record`).
    password_record: Option<Vec<u8>>,
    /// Entries of a `generator_history` item.
    generated: Vec<GeneratedEntry>,
    /// What a `preferences` item holds.
    preferences: Option<Preferences>,
    /// The login's passkey, its key sealed with the vault key (ADR 0020).
    passkey: Option<Passkey>,
}

/// Field templates per item type: `(name, label, type)`.
pub fn template(kind: ItemKind) -> &'static [(&'static str, &'static str, FieldKind)] {
    use FieldKind as F;
    match kind {
        ItemKind::Login => &[
            ("username", "Username", F::Username),
            ("password", "Password", F::Password),
            ("totp", "One-time password", F::Totp),
        ],
        ItemKind::Card => &[
            ("cardholder", "Cardholder name", F::Text),
            ("number", "Number", F::Concealed),
            ("expiry", "Expiry date", F::MonthYear),
            ("cvv", "Verification code", F::Concealed),
            ("pin", "PIN", F::Concealed),
        ],
        ItemKind::Identity => &[
            ("first_name", "First name", F::Text),
            ("last_name", "Last name", F::Text),
            ("email", "E-mail", F::Email),
            ("phone", "Phone", F::Phone),
            ("address", "Address", F::Text),
            ("city", "City", F::Text),
            ("region", "State / region", F::Text),
            ("postal_code", "Postal code", F::Text),
            ("country", "Country", F::Text),
            ("birth_date", "Birth date", F::Date),
        ],
        ItemKind::SshKey => &[
            ("private_key", "Private key", F::Concealed),
            ("public_key", "Public key", F::Text),
            ("fingerprint", "Fingerprint", F::Text),
            ("passphrase", "Passphrase", F::Password),
        ],
        ItemKind::File => &[],
        ItemKind::Totp => &[("totp", "One-time password", F::Totp)],
        ItemKind::Note | ItemKind::GeneratorHistory | ItemKind::Preferences => &[],
        ItemKind::ApiKey => &[
            ("api_key", "API key", F::Concealed),
            ("key_id", "Key ID", F::Text),
            ("base_url", "Base URL", F::Url),
            ("expires", "Expires", F::Date),
        ],
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawField {
    id: FieldId,
    name: String,
    #[serde(default)]
    label: String,
    #[serde(rename = "type")]
    kind: FieldKind,
    value: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawGenerated {
    value: String,
    created_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    saved_in: Option<ItemId>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDetails {
    v: u32,
    kind: ItemKind,
    #[serde(default)]
    fields: Vec<RawField>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    notes: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    attachments: Vec<AttachmentMeta>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    password_record: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    generated: Vec<RawGenerated>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    preferences: Option<Preferences>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    passkey: Option<RawPasskey>,
}

impl Drop for RawGenerated {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.value);
    }
}

/// Smallest `0x16` blob: header, nonce and tag around an empty plaintext.
const MIN_RECORD_LEN: usize = crate::crypto::aead::OVERHEAD;

fn check_record_blob(blob: &[u8]) -> Result<(), ModelError> {
    if blob.len() < MIN_RECORD_LEN || blob[..2] != Kind::PasswordRecord.header() {
        return Err(ModelError::InvalidText("password record"));
    }
    Ok(())
}

impl Drop for RawField {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.value);
    }
}

impl Drop for RawDetails {
    fn drop(&mut self) {
        if let Some(notes) = self.notes.as_mut() {
            zeroize::Zeroize::zeroize(notes);
        }
    }
}

fn json_error(err: serde_json::Error) -> ModelError {
    // serde_json messages can quote input fragments; keep only the position.
    ModelError::Json(format!(
        "{:?} error at line {} column {}",
        err.classify(),
        err.line(),
        err.column()
    ))
}

impl Item {
    /// A new, empty item.
    pub fn new(kind: ItemKind, title: &str) -> Result<Self, ModelError> {
        validate_text(title, "title", false).map_err(|_| ModelError::InvalidTitle)?;
        Ok(Self {
            id: ItemId::generate(),
            kind,
            title: title.to_string(),
            tags: Vec::new(),
            urls: Vec::new(),
            fields: Vec::new(),
            notes: None,
            attachments: Vec::new(),
            password_record: None,
            generated: Vec::new(),
            preferences: None,
            passkey: None,
        })
    }

    /// A new item with the empty fields of its type's [`template`].
    pub fn from_template(kind: ItemKind, title: &str) -> Result<Self, ModelError> {
        let mut item = Self::new(kind, title)?;
        for (name, label, field_kind) in template(kind) {
            item.add_field(Field::new(name, label, *field_kind, "")?)?;
        }
        Ok(item)
    }

    /// Item ID.
    pub fn id(&self) -> ItemId {
        self.id
    }

    /// Item type.
    pub fn kind(&self) -> ItemKind {
        self.kind
    }

    /// Title.
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Renames the item.
    pub fn set_title(&mut self, title: &str) -> Result<(), ModelError> {
        validate_text(title, "title", false).map_err(|_| ModelError::InvalidTitle)?;
        self.title = title.to_string();
        Ok(())
    }

    /// Tags.
    pub fn tags(&self) -> &[String] {
        &self.tags
    }

    /// Adds a tag (ignored if already present, case-insensitively).
    pub fn add_tag(&mut self, tag: &str) -> Result<(), ModelError> {
        validate_text(tag, "tag", false)?;
        if !self.has_tag(tag) {
            self.tags.push(tag.to_string());
        }
        Ok(())
    }

    /// Whether the item has `tag` (case-insensitive).
    pub fn has_tag(&self, tag: &str) -> bool {
        let tag = tag.to_lowercase();
        self.tags.iter().any(|t| t.to_lowercase() == tag)
    }

    /// URLs used for autofill.
    pub fn urls(&self) -> &[String] {
        &self.urls
    }

    /// Adds a URL for autofill: an `http` or `https` address (or a bare
    /// host), without user info.
    pub fn add_url(&mut self, url: &str) -> Result<(), ModelError> {
        validate_item_url(url)?;
        self.urls.push(url.to_string());
        Ok(())
    }

    /// Removes every URL equal to `url`; whether one was there.
    pub fn remove_url(&mut self, url: &str) -> bool {
        let before = self.urls.len();
        self.urls.retain(|u| u != url);
        self.urls.len() != before
    }

    /// Fields, in display order.
    pub fn fields(&self) -> &[Field] {
        &self.fields
    }

    /// Adds a field; its name and ID must be unique in the item.
    pub fn add_field(&mut self, field: Field) -> Result<(), ModelError> {
        if self
            .fields
            .iter()
            .any(|f| f.name == field.name || f.id == field.id)
        {
            return Err(ModelError::DuplicateField(field.name));
        }
        self.fields.push(field);
        Ok(())
    }

    /// Removes a field by name.
    pub fn remove_field(&mut self, name: &str) -> Option<Field> {
        let index = self.fields.iter().position(|f| f.name == name)?;
        Some(self.fields.remove(index))
    }

    /// Field by name (exact match).
    pub fn field(&self, name: &str) -> Option<&Field> {
        self.fields.iter().find(|f| f.name == name)
    }

    /// Field by ID.
    pub fn field_by_id(&self, id: FieldId) -> Option<&Field> {
        self.fields.iter().find(|f| f.id == id)
    }

    /// Mutable field by name.
    pub fn field_mut(&mut self, name: &str) -> Option<&mut Field> {
        self.fields.iter_mut().find(|f| f.name == name)
    }

    /// Secure notes.
    pub fn notes(&self) -> Option<&SecretValue> {
        self.notes.as_ref()
    }

    /// Replaces the notes.
    pub fn set_notes(&mut self, notes: Option<&str>) {
        self.notes = notes.filter(|n| !n.is_empty()).map(SecretValue::new);
    }

    /// Attachments' metadata.
    pub fn attachments(&self) -> &[AttachmentMeta] {
        &self.attachments
    }

    /// Records an attachment.
    pub fn add_attachment(&mut self, meta: AttachmentMeta) -> Result<(), ModelError> {
        validate_text(&meta.file_name, "file name", false)?;
        self.attachments.push(meta);
        Ok(())
    }

    /// Forgets an attachment's metadata.
    pub fn remove_attachment(&mut self, id: AttachmentId) -> Option<AttachmentMeta> {
        let index = self.attachments.iter().position(|a| a.id == id)?;
        Some(self.attachments.remove(index))
    }

    /// The sealed password record (blob `0x16`), if the item has one.
    pub fn password_record(&self) -> Option<&[u8]> {
        self.password_record.as_deref()
    }

    /// Replaces the sealed password record. Only clients holding the vault
    /// key produce one (`model::record::PasswordRecord::seal`).
    pub fn set_password_record(&mut self, blob: Option<Vec<u8>>) -> Result<(), ModelError> {
        if let Some(b) = &blob {
            check_record_blob(b)?;
            if self.kind.is_system() {
                return Err(ModelError::InvalidText("password record"));
            }
        }
        self.password_record = blob;
        Ok(())
    }

    /// Entries of a `generator_history` item.
    pub fn generated(&self) -> &[GeneratedEntry] {
        &self.generated
    }

    /// Replaces the entries of a `generator_history` item.
    pub fn set_generated(&mut self, entries: Vec<GeneratedEntry>) -> Result<(), ModelError> {
        if self.kind != ItemKind::GeneratorHistory && !entries.is_empty() {
            return Err(ModelError::InvalidText("generated entries"));
        }
        for e in &entries {
            e.validate()?;
        }
        self.generated = entries;
        Ok(())
    }

    /// What a `preferences` item holds (`None` in any other item, and in
    /// a `preferences` item that holds nothing yet).
    pub fn preferences(&self) -> Option<&Preferences> {
        self.preferences.as_ref()
    }

    /// Replaces what a `preferences` item holds. Any other kind refuses.
    pub fn set_preferences(&mut self, preferences: Option<Preferences>) -> Result<(), ModelError> {
        if self.kind != ItemKind::Preferences && preferences.is_some() {
            return Err(ModelError::InvalidText(
                "preferences outside a preferences item",
            ));
        }
        if let Some(p) = &preferences {
            p.validate()?;
        }
        self.preferences = preferences;
        Ok(())
    }

    /// The login's passkey, if any.
    pub fn passkey(&self) -> Option<&Passkey> {
        self.passkey.as_ref()
    }

    /// Puts `passkey` in this login, replacing the one it had (ADR 0020 §2:
    /// the caller confirms a replacement first). Only logins carry
    /// passkeys. If no URL of the login has the rpId as its host,
    /// `https://<rp_id>` is added so the login is offered there.
    pub fn set_passkey(&mut self, passkey: Passkey) -> Result<(), ModelError> {
        if self.kind != ItemKind::Login {
            return Err(ModelError::InvalidText("passkey outside a login"));
        }
        let rp_id = passkey.rp_id();
        let has_rp_url = self.urls.iter().any(|u| {
            url::Url::parse(u)
                .ok()
                .and_then(|u| u.host_str().map(str::to_ascii_lowercase))
                .is_some_and(|host| host == rp_id)
        });
        if !has_rp_url {
            self.add_url(&format!("https://{rp_id}"))?;
        }
        self.passkey = Some(passkey);
        Ok(())
    }

    /// Removes the login's passkey. The URLs stay.
    pub fn remove_passkey(&mut self) -> Option<Passkey> {
        self.passkey.take()
    }

    /// The overview: what `list` may see.
    pub fn overview(&self) -> Overview {
        Overview {
            v: SCHEMA_VERSION,
            kind: self.kind,
            title: self.title.clone(),
            username: self
                .fields
                .iter()
                .find(|f| f.kind == FieldKind::Username && !f.is_empty())
                .map(|f| f.value.expose_text().into_owned()),
            urls: self.urls.clone(),
            tags: self.tags.clone(),
            passkey: self.passkey.as_ref().map(Passkey::summary),
        }
    }

    /// Serializes the two sections: `(overview JSON, details JSON)`.
    pub fn encode_sections(&self) -> (Vec<u8>, Zeroizing<Vec<u8>>) {
        let overview = serde_json::to_vec(&self.overview()).expect("overview serializes");
        let details = RawDetails {
            v: SCHEMA_VERSION,
            kind: self.kind,
            fields: self
                .fields
                .iter()
                .map(|f| RawField {
                    id: f.id,
                    name: f.name.clone(),
                    label: f.label.clone(),
                    kind: f.kind,
                    value: f.value.expose_text().into_owned(),
                })
                .collect(),
            notes: self.notes.as_ref().map(|n| n.expose().to_string()),
            attachments: self.attachments.clone(),
            password_record: self
                .password_record
                .as_deref()
                .map(|b| data_encoding::BASE64URL_NOPAD.encode(b)),
            generated: self
                .generated
                .iter()
                .map(|e| RawGenerated {
                    value: e.value.expose().to_owned(),
                    created_at: e.created_at,
                    host: e.host.clone(),
                    saved_in: e.saved_in,
                })
                .collect(),
            preferences: self.preferences.clone(),
            passkey: self.passkey.as_ref().map(Passkey::to_raw),
        };
        let details = Zeroizing::new(serde_json::to_vec(&details).expect("details serialize"));
        (overview, details)
    }

    /// Parses an overview section.
    pub fn decode_overview(overview: &[u8]) -> Result<Overview, ModelError> {
        let overview: Overview = serde_json::from_slice(overview).map_err(json_error)?;
        if overview.v != SCHEMA_VERSION {
            return Err(ModelError::UnsupportedSchema(overview.v));
        }
        Ok(overview)
    }

    /// Rebuilds an item from its two sections.
    pub fn decode_sections(
        id: ItemId,
        overview: &[u8],
        details: &[u8],
    ) -> Result<Self, ModelError> {
        let overview = Self::decode_overview(overview)?;
        let details: RawDetails = serde_json::from_slice(details).map_err(json_error)?;
        if details.v != SCHEMA_VERSION {
            return Err(ModelError::UnsupportedSchema(details.v));
        }
        if details.kind != overview.kind {
            return Err(ModelError::SectionMismatch);
        }
        let mut item = Self::new(overview.kind, &overview.title)?;
        item.id = id;
        for tag in &overview.tags {
            item.add_tag(tag)?;
        }
        // Read as saved: a URL that the rules for new ones refuse now
        // stays, and the site rule decides whether it fills.
        for url in &overview.urls {
            validate_url(url)?;
            item.urls.push(url.clone());
        }
        for raw in &details.fields {
            item.add_field(Field::with_id(
                raw.id, &raw.name, &raw.label, raw.kind, &raw.value,
            )?)?;
        }
        item.set_notes(details.notes.as_deref());
        for meta in &details.attachments {
            item.add_attachment(meta.clone())?;
        }
        if let Some(text) = &details.password_record {
            let blob = data_encoding::BASE64URL_NOPAD
                .decode(text.as_bytes())
                .map_err(|_| ModelError::InvalidText("password record"))?;
            item.set_password_record(Some(blob))?;
        }
        item.set_generated(
            details
                .generated
                .iter()
                .map(|e| GeneratedEntry {
                    value: SecretValue::new(e.value.as_str()),
                    created_at: e.created_at,
                    host: e.host.clone(),
                    saved_in: e.saved_in,
                })
                .collect(),
        )?;
        item.set_preferences(details.preferences.clone())?;
        if let Some(raw) = &details.passkey {
            if overview.kind != ItemKind::Login {
                return Err(ModelError::InvalidText("passkey outside a login"));
            }
            // Directly, not through `set_passkey`: decoding never adds a URL.
            item.passkey = Some(Passkey::from_raw(raw)?);
        }
        let derived = item.overview();
        if derived.username != overview.username || derived.passkey != overview.passkey {
            return Err(ModelError::SectionMismatch);
        }
        Ok(item)
    }
}

/// The two ciphertexts of an item (spec §7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedItem {
    /// Overview ciphertext (kind `0x10`).
    pub overview: Vec<u8>,
    /// Details ciphertext (kind `0x11`).
    pub details: Vec<u8>,
}

/// Encrypts an item at `version`. `ctx.item` must equal `item.id()`.
pub fn seal_item(key: &ItemKey, ctx: &ItemContext, version: u64, item: &Item) -> SealedItem {
    assert_eq!(ctx.item, item.id, "item context does not match the item ID");
    let (overview, details) = item.encode_sections();
    SealedItem {
        overview: encrypt_item_section(key, ctx, version, Section::Overview, &overview),
        details: encrypt_item_section(key, ctx, version, Section::Details, &details),
    }
}

/// Decrypts only the overview (enough for `list`).
pub fn open_overview(
    key: &ItemKey,
    ctx: &ItemContext,
    version: u64,
    overview: &[u8],
) -> Result<Overview, ModelError> {
    let plain = decrypt_item_section(key, ctx, version, Section::Overview, overview)?;
    Item::decode_overview(&plain)
}

/// Decrypts and rebuilds a full item.
pub fn open_item(
    key: &ItemKey,
    ctx: &ItemContext,
    version: u64,
    sealed: &SealedItem,
) -> Result<Item, ModelError> {
    let overview = decrypt_item_section(key, ctx, version, Section::Overview, &sealed.overview)?;
    let details = decrypt_item_section(key, ctx, version, Section::Details, &sealed.details)?;
    Item::decode_sections(ctx.item, &overview, &details)
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;
    use crate::ids::{AccountId, ProjectId, VaultId};

    static_assertions::assert_not_impl_any!(SecretValue: std::fmt::Debug, std::fmt::Display);
    static_assertions::assert_not_impl_any!(FieldValue: std::fmt::Debug, std::fmt::Display);
    static_assertions::assert_not_impl_any!(Field: std::fmt::Debug, std::fmt::Display);
    static_assertions::assert_not_impl_any!(Item: std::fmt::Debug, std::fmt::Display);

    fn has_unique_fields(item: &Item) -> bool {
        let mut names = HashSet::new();
        let mut ids = HashSet::new();
        item.fields
            .iter()
            .all(|f| names.insert(f.name.as_str()) && ids.insert(f.id))
    }

    fn login() -> Item {
        let mut item = Item::from_template(ItemKind::Login, "GitHub").unwrap();
        item.field_mut("username")
            .unwrap()
            .set_value("omar")
            .unwrap();
        item.field_mut("password")
            .unwrap()
            .set_value("hunter2")
            .unwrap();
        item.add_url("https://github.com/login").unwrap();
        item.add_tag("dev").unwrap();
        item.set_notes(Some("recovery codes in the safe"));
        item
    }

    fn ctx(item: &Item) -> ItemContext {
        ItemContext {
            account: AccountId::generate(),
            vault: VaultId::generate(),
            project: ProjectId::generate(),
            item: item.id(),
        }
    }

    #[test]
    fn templates_are_valid_for_every_kind() {
        for kind in [
            ItemKind::Login,
            ItemKind::Card,
            ItemKind::Identity,
            ItemKind::SshKey,
            ItemKind::File,
            ItemKind::Totp,
            ItemKind::Note,
            ItemKind::ApiKey,
        ] {
            let item = Item::from_template(kind, "x").unwrap();
            assert_eq!(item.fields().len(), template(kind).len());
            assert!(has_unique_fields(&item));
            let (o, d) = item.encode_sections();
            assert!(Item::decode_sections(item.id(), &o, &d).unwrap() == item);
        }
    }

    #[test]
    fn overview_has_no_secrets() {
        let item = login();
        let overview = item.overview();
        assert_eq!(overview.username.as_deref(), Some("omar"));
        let (o, d) = item.encode_sections();
        let o = String::from_utf8(o).unwrap();
        assert!(!o.contains("hunter2") && !o.contains("recovery"));
        assert!(String::from_utf8(d.to_vec()).unwrap().contains("hunter2"));
    }

    #[test]
    fn seal_open_roundtrip() {
        let item = login();
        let key = ItemKey::generate();
        let ctx = ctx(&item);
        let sealed = seal_item(&key, &ctx, 3, &item);
        assert!(open_item(&key, &ctx, 3, &sealed).unwrap() == item);
        assert_eq!(
            open_overview(&key, &ctx, 3, &sealed.overview).unwrap(),
            item.overview()
        );
        assert!(matches!(
            open_item(&key, &ctx, 4, &sealed),
            Err(ModelError::Crypto(CryptoError::Decryption))
        ));
        // Swapping the sections is detected by the AAD.
        let swapped = SealedItem {
            overview: sealed.details.clone(),
            details: sealed.overview.clone(),
        };
        assert!(open_item(&key, &ctx, 3, &swapped).is_err());
    }

    #[test]
    fn crypto_vector_plaintexts_follow_the_schema() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../docs/vectores/elemento.json");
        let doc: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let cases = doc["cases"].as_array().unwrap();
        let text = |name: &str| {
            cases.iter().find(|c| c["name"] == name).unwrap()["plaintext"]
                .as_str()
                .unwrap()
                .as_bytes()
                .to_vec()
        };
        // The two cases are independent items: check each section on its own.
        let overview = Item::decode_overview(&text("overview-v1")).unwrap();
        assert_eq!(overview.username.as_deref(), Some("omar"));
        let bare_overview = serde_json::to_vec(&Overview {
            v: SCHEMA_VERSION,
            kind: ItemKind::Login,
            title: "x".into(),
            username: None,
            urls: vec![],
            tags: vec![],
            passkey: None,
        })
        .unwrap();
        let item =
            Item::decode_sections(ItemId::generate(), &bare_overview, &text("details-v7")).unwrap();
        assert!(
            matches!(item.field("password").unwrap().value(), FieldValue::Secret(s) if s.expose() == "hunter2")
        );
    }

    #[test]
    fn field_validation() {
        for bad in [
            "",
            "Password",
            "_x",
            "-x",
            "a b",
            "a/b",
            "ñ",
            &"x".repeat(65),
            "6f3e2c1a-8b7d-4e5f-9a0b-1c2d3e4f5a6b",
        ] {
            assert!(validate_field_name(bad).is_err(), "{bad}");
        }
        for good in ["password", "api_key", "x", "a-1", "2fa"] {
            assert!(validate_field_name(good).is_ok(), "{good}");
        }
        assert!(Field::new("expiry", "", FieldKind::MonthYear, "2027-13").is_err());
        assert!(Field::new("expiry", "", FieldKind::MonthYear, "2027-09").is_ok());
        assert!(Field::new("born", "", FieldKind::Date, "1990-02-30").is_ok());
        assert!(Field::new("born", "", FieldKind::Date, "90-02-03").is_err());
        assert!(Field::new("file", "", FieldKind::File, "not-an-id").is_err());
        assert!(Field::new("totp", "", FieldKind::Totp, "!!!").is_err());
        assert!(Field::new("totp", "", FieldKind::Totp, "JBSWY3DPEHPK3PXP").is_ok());
        let mut item = login();
        assert_eq!(
            item.add_field(Field::new("password", "", FieldKind::Password, "x").unwrap()),
            Err(ModelError::DuplicateField("password".into()))
        );
        assert!(Item::new(ItemKind::Note, "  ").is_err());
        assert!(item.add_tag("a\nb").is_err());
    }

    #[test]
    fn slugify_labels() {
        assert_eq!(slugify("API Key").as_deref(), Some("api_key"));
        assert_eq!(
            slugify("  Número de tarjeta ").as_deref(),
            Some("n_mero_de_tarjeta")
        );
        assert_eq!(slugify("2FA code!").as_deref(), Some("2fa_code"));
        assert_eq!(slugify("¡¿?!"), None);
    }

    #[test]
    fn new_urls_are_web_addresses_and_old_ones_still_read() {
        let mut item = login();
        for bad in [
            "javascript://github.com/%0aalert(1)",
            "ftp://github.com",
            "data:text/html,x",
            "https://github.com@evil.io",
            "https://user:pass@github.com",
            "https://",
        ] {
            assert!(item.add_url(bad).is_err(), "{bad}");
        }
        for good in [
            "github.com",
            "https://github.com/login",
            "http://localhost:3000",
            "https://router",
        ] {
            item.add_url(good).unwrap();
        }
        // An item saved before keeps its URLs: reading never fails on them.
        let (o, d) = item.encode_sections();
        let mut old: serde_json::Value = serde_json::from_slice(&o).unwrap();
        old["urls"] = serde_json::json!(["ftp://github.com", "https://a@evil.io"]);
        let read =
            Item::decode_sections(item.id(), &serde_json::to_vec(&old).unwrap(), &d).unwrap();
        assert_eq!(read.urls(), ["ftp://github.com", "https://a@evil.io"]);
    }

    #[test]
    fn rejects_bad_documents() {
        let item = login();
        let (o, d) = item.encode_sections();
        let mut v2: serde_json::Value = serde_json::from_slice(&o).unwrap();
        v2["v"] = 2.into();
        assert_eq!(
            Item::decode_sections(item.id(), &serde_json::to_vec(&v2).unwrap(), &d).err(),
            Some(ModelError::UnsupportedSchema(2))
        );
        let mut other_kind: serde_json::Value = serde_json::from_slice(&o).unwrap();
        other_kind["kind"] = "note".into();
        assert_eq!(
            Item::decode_sections(item.id(), &serde_json::to_vec(&other_kind).unwrap(), &d).err(),
            Some(ModelError::SectionMismatch)
        );
        // JSON errors never echo the input (which may contain secrets).
        let err = Item::decode_sections(
            item.id(),
            &o,
            b"{\"v\":1,\"kind\":\"login\",\"fields\":[{\"value\":\"hunter2\"",
        )
        .err()
        .expect("truncated JSON is rejected");
        assert!(!err.to_string().contains("hunter2"));
    }

    #[test]
    fn password_record_survives_edits_of_other_fields() {
        use crate::crypto::context::VaultContext;
        use crate::crypto::keys::VaultKey;
        use crate::ids::{AccountId, VaultId};
        use crate::model::record::PasswordRecord;

        let mut item = login();
        let ctx = VaultContext {
            account: AccountId::generate(),
            vault: VaultId::generate(),
        };
        let mut record = PasswordRecord::new();
        record.push("password", &SecretValue::new("old"), None, 1);
        let blob = record.seal(&VaultKey::generate(), &ctx, item.id());
        item.set_password_record(Some(blob.clone())).unwrap();
        // Round trip through the details JSON, as every writer does
        // (klav-client, klav-sdk for agents, klavd), with an edit of a
        // plain field in between: the blob stays byte for byte.
        let (o, d) = item.encode_sections();
        let mut decoded = Item::decode_sections(item.id(), &o, &d).unwrap();
        decoded
            .field_mut("username")
            .unwrap()
            .set_value("bea")
            .unwrap();
        decoded.set_title("GitHub (bea)").unwrap();
        let (o, d) = decoded.encode_sections();
        let again = Item::decode_sections(item.id(), &o, &d).unwrap();
        assert_eq!(again.password_record(), Some(blob.as_slice()));
        let json: serde_json::Value = serde_json::from_slice(&d).unwrap();
        assert_eq!(
            json["password_record"].as_str().unwrap(),
            data_encoding::BASE64URL_NOPAD.encode(&blob)
        );
        // Only `0x16` blobs.
        assert!(item.set_password_record(Some(vec![1, 0x11, 0, 0])).is_err());
        let mut wrong = blob.clone();
        wrong[1] = 0x15;
        assert!(item.set_password_record(Some(wrong)).is_err());
        let mut bad: serde_json::Value = serde_json::from_slice(&d).unwrap();
        bad["password_record"] = "not base64!".into();
        assert!(Item::decode_sections(item.id(), &o, &serde_json::to_vec(&bad).unwrap()).is_err());
    }

    #[test]
    fn preferences_items() {
        use crate::ids::AgentId;
        use crate::model::preferences::{Preferences, ProxySetting};

        assert!(ItemKind::Preferences.is_system());
        let agent = AgentId::generate();
        let mut item = Item::new(ItemKind::Preferences, "Preferences").unwrap();
        item.set_preferences(Some(Preferences {
            developer: None,
            proxy: Some(ProxySetting::own(agent)),
        }))
        .unwrap();
        let (o, d) = item.encode_sections();
        let json: serde_json::Value = serde_json::from_slice(&d).unwrap();
        assert_eq!(json["kind"], "preferences");
        // Only what was chosen: no `developer` nobody set.
        assert_eq!(
            json["preferences"],
            serde_json::json!({"proxy": {"mode": "own", "agent_id": agent.to_string()}})
        );
        let back = Item::decode_sections(item.id(), &o, &d).unwrap();
        assert_eq!(
            back.preferences().unwrap().proxy(),
            ProxySetting::own(agent)
        );
        assert!(back.preferences().unwrap().developer());
        // Only in a preferences item, and only valid settings.
        let mut login = Item::new(ItemKind::Login, "x").unwrap();
        assert!(login.set_preferences(Some(Preferences::default())).is_err());
        let mut bad = json.clone();
        bad["preferences"]["proxy"] = serde_json::json!({"mode": "own"});
        assert!(Item::decode_sections(item.id(), &o, &serde_json::to_vec(&bad).unwrap()).is_err());
        bad["preferences"] = serde_json::json!({"proxy": {"mode": "none"}, "other": 1});
        assert!(Item::decode_sections(item.id(), &o, &serde_json::to_vec(&bad).unwrap()).is_err());
    }

    #[test]
    fn generator_history_items() {
        use crate::model::history::GeneratedEntry;

        assert!(ItemKind::GeneratorHistory.is_system());
        assert!(!ItemKind::Login.is_system());
        let mut item = Item::new(ItemKind::GeneratorHistory, "Generator history").unwrap();
        let entry = GeneratedEntry {
            value: SecretValue::new("Xy7!generated"),
            created_at: 1_700_000_000_000,
            host: Some("github.com".into()),
            saved_in: Some(ItemId::generate()),
        };
        item.set_generated(vec![entry.clone()]).unwrap();
        let (o, d) = item.encode_sections();
        assert!(!String::from_utf8_lossy(&o).contains("Xy7!generated"));
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&o).unwrap()["kind"],
            "generator_history"
        );
        let back = Item::decode_sections(item.id(), &o, &d).unwrap();
        assert!(back.generated() == [entry.clone()]);
        // Entries only in a generator history; no record there.
        let mut other = login();
        assert!(other.set_generated(vec![entry]).is_err());
        assert!(
            item.set_password_record(Some(vec![1, 0x16].into_iter().chain([0; 40]).collect()))
                .is_err()
        );
        let mut forged: serde_json::Value =
            serde_json::from_slice(&login().encode_sections().1).unwrap();
        forged["generated"] = serde_json::json!([{"value":"x","created_at":1}]);
        let lo = login();
        assert!(
            Item::decode_sections(
                lo.id(),
                &lo.encode_sections().0,
                &serde_json::to_vec(&forged).unwrap()
            )
            .is_err()
        );
    }
}
