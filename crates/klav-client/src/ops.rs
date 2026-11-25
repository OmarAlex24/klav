//! High-level operations shared by the CLI (direct mode) and the daemon:
//! serialisable inputs and outputs, so the same requests can travel over
//! the daemon socket.

use klav_core::ids::{FieldId, ProjectId, VaultId};
use klav_core::model::item::{Field, FieldKind, FieldValue, ItemKind, template};
use klav_core::model::reference::{Reference, resolve_field};
use klav_core::model::{Item, SecretValue};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroizing;

use crate::error::{ClientError, ClientResult};
use crate::session::{ItemLocation, ItemSummary, Unlocked};

/// Text that may be secret. Zeroized on drop; `Debug` never shows it. It
/// serialises in the clear because it only travels over the local daemon
/// socket (same user) and is never logged.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct SecretText(Zeroizing<String>);

impl SecretText {
    /// Wraps a value.
    pub fn new(value: impl Into<String>) -> Self {
        Self(Zeroizing::new(value.into()))
    }

    /// The value.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for SecretText {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretText(…)")
    }
}

impl Serialize for SecretText {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SecretText {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(Self::new(String::deserialize(deserializer)?))
    }
}

impl From<&SecretValue> for SecretText {
    fn from(v: &SecretValue) -> Self {
        Self::new(v.expose())
    }
}

/// A field value to set.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FieldInput {
    /// Field name (`[a-z0-9][a-z0-9_-]{0,63}`).
    pub name: String,
    /// Value.
    pub value: SecretText,
    /// Type for a field the item does not have yet (default: `text`, or
    /// `concealed` when `secret` is set).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<FieldKind>,
    /// The value was entered as a secret (prompt or stdin).
    #[serde(default)]
    pub secret: bool,
}

/// A new item.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewItem {
    /// Type.
    pub kind: ItemKind,
    /// Title.
    pub title: String,
    /// Vault name or ID (default: the "Personal" vault, or the only one).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault: Option<String>,
    /// Project name or ID (default: "General").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
    /// Field values.
    #[serde(default)]
    pub fields: Vec<FieldInput>,
    /// URLs.
    #[serde(default)]
    pub urls: Vec<String>,
    /// Tags.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Notes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<SecretText>,
    /// Create it even if an item with the same title already exists in the
    /// project (references by title become ambiguous).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub allow_duplicate: bool,
}

/// Changes to an item.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ItemPatch {
    /// New title.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Fields to set (created if missing).
    #[serde(default)]
    pub set: Vec<FieldInput>,
    /// Fields to remove.
    #[serde(default)]
    pub remove: Vec<String>,
    /// URLs to add.
    #[serde(default)]
    pub add_urls: Vec<String>,
    /// URLs to remove (exactly as stored): a site an agent added that the
    /// person does not want (ADR 0030 §7).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub remove_urls: Vec<String>,
    /// Tags to add.
    #[serde(default)]
    pub add_tags: Vec<String>,
    /// New notes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<SecretText>,
    /// Rename even if another live item of the project already has the
    /// new title (references by title become ambiguous).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub allow_duplicate: bool,
}

/// One field as shown to the user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldView {
    /// ID (for stable references).
    pub id: FieldId,
    /// Name (in `klav://…/<field>`).
    pub name: String,
    /// Label.
    pub label: String,
    /// Type.
    pub kind: FieldKind,
    /// Secret type.
    pub secret: bool,
    /// Has a value.
    pub filled: bool,
    /// The value: plain fields always; secret fields only when revealed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<SecretText>,
}

/// An item as shown to the user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ItemView {
    /// Metadata.
    #[serde(flatten)]
    pub summary: ItemSummary,
    /// Fields.
    pub fields: Vec<FieldView>,
    /// Has notes.
    pub has_notes: bool,
    /// Notes, only when revealed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<SecretText>,
    /// Attachments (name and size; content via `inject`).
    #[serde(default)]
    pub attachments: Vec<klav_core::model::item::AttachmentMeta>,
    /// Secret values are included.
    pub revealed: bool,
}

/// Bytes that may be secret (a resolved value or a file). Zeroized on
/// drop; base64url (no padding) in JSON; `Debug` shows only the length.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct SecretBytes(Zeroizing<Vec<u8>>);

impl SecretBytes {
    /// Wraps bytes.
    pub fn new(bytes: Zeroizing<Vec<u8>>) -> Self {
        Self(bytes)
    }

    /// The bytes.
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretBytes({} bytes)", self.0.len())
    }
}

impl Serialize for SecretBytes {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let text = Zeroizing::new(data_encoding::BASE64URL_NOPAD.encode(&self.0));
        serializer.serialize_str(&text)
    }
}

impl<'de> Deserialize<'de> for SecretBytes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = Zeroizing::new(String::deserialize(deserializer)?);
        data_encoding::BASE64URL_NOPAD
            .decode(text.as_bytes())
            .map(|b| Self(Zeroizing::new(b)))
            .map_err(|_| serde::de::Error::custom("invalid base64url (no padding)"))
    }
}

/// A complete item in transit (CSV import through the daemon): its two
/// plaintext sections, as `klav-core` encodes them before encryption.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableItem {
    /// Item ID.
    pub id: klav_core::ids::ItemId,
    /// Overview section (JSON).
    pub overview: SecretBytes,
    /// Details section (JSON, with the secrets).
    pub details: SecretBytes,
}

impl PortableItem {
    /// Packs an item.
    pub fn from_item(item: &Item) -> Self {
        let (overview, details) = item.encode_sections();
        Self {
            id: item.id(),
            overview: SecretBytes::new(Zeroizing::new(overview)),
            details: SecretBytes::new(details),
        }
    }

    /// Unpacks (and validates) the item.
    pub fn to_item(&self) -> ClientResult<Item> {
        Ok(Item::decode_sections(
            self.id,
            self.overview.expose(),
            self.details.expose(),
        )?)
    }
}

/// A secret produced for the caller (`run`, `inject`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedValue {
    /// The reference as asked.
    pub reference: String,
    /// The canonical reference.
    pub canonical: String,
    /// Field type (`file` for attachments).
    pub kind: FieldKind,
    /// Value: UTF-8 text, or the file content for `file` fields.
    pub value: SecretBytes,
}

impl ResolvedValue {
    /// The value as text (fails for binary files).
    pub fn text(&self) -> ClientResult<&str> {
        std::str::from_utf8(self.value.expose()).map_err(|_| {
            ClientError::Invalid(format!("{} is a binary file, not text", self.reference))
        })
    }
}

/// A TOTP code.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpCode {
    /// The code.
    pub code: SecretText,
    /// Seconds until it changes.
    pub remaining: u64,
}

fn apply_field(item: &mut Item, input: &FieldInput) -> ClientResult<()> {
    if let Some(field) = item.field_mut(&input.name) {
        field.set_value(input.value.expose())?;
        return Ok(());
    }
    let kind = input.kind.unwrap_or(if input.secret {
        FieldKind::Concealed
    } else {
        FieldKind::Text
    });
    item.add_field(Field::new(&input.name, "", kind, input.value.expose())?)?;
    Ok(())
}

fn ensure_not_secret_in_plain(item: &Item, inputs: &[FieldInput]) -> ClientResult<()> {
    for input in inputs {
        let kind = item.field(&input.name).map(Field::kind).or(input.kind);
        if !input.secret
            && kind.is_some_and(FieldKind::is_secret)
            && !input.value.expose().is_empty()
        {
            return Err(ClientError::Invalid(format!(
                "field {:?} is secret: enter it with a prompt or stdin, not on the command line",
                input.name
            )));
        }
    }
    Ok(())
}

/// Builds an item from a [`NewItem`].
pub fn build_item(new: &NewItem) -> ClientResult<Item> {
    if new.kind.is_system() {
        return Err(ClientError::Invalid(
            "items of this kind belong to Klav and cannot be created by hand".into(),
        ));
    }
    let mut item = Item::from_template(new.kind, &new.title)?;
    ensure_not_secret_in_plain(&item, &new.fields)?;
    for f in &new.fields {
        apply_field(&mut item, f)?;
    }
    for url in &new.urls {
        item.add_url(url)?;
    }
    for tag in &new.tags {
        item.add_tag(tag)?;
    }
    if let Some(notes) = &new.notes {
        item.set_notes(Some(notes.expose()));
    }
    Ok(item)
}

/// Applies a patch to a decrypted item.
pub fn patch_item(item: &mut Item, patch: &ItemPatch) -> ClientResult<()> {
    ensure_not_secret_in_plain(item, &patch.set)?;
    if let Some(title) = &patch.title {
        item.set_title(title)?;
    }
    for name in &patch.remove {
        let builtin = template(item.kind()).iter().any(|(n, _, _)| n == name);
        if builtin {
            item.field_mut(name)
                .ok_or_else(|| ClientError::NotFound(format!("field {name:?}")))?
                .set_value("")?;
        } else if item.remove_field(name).is_none() {
            return Err(ClientError::NotFound(format!("field {name:?}")));
        }
    }
    for f in &patch.set {
        apply_field(item, f)?;
    }
    for url in &patch.remove_urls {
        if !item.remove_url(url) {
            return Err(ClientError::NotFound(format!("URL {url:?}")));
        }
    }
    for url in &patch.add_urls {
        item.add_url(url)?;
    }
    for tag in &patch.add_tags {
        if !item.has_tag(tag) {
            item.add_tag(tag)?;
        }
    }
    if let Some(notes) = &patch.notes {
        let text = notes.expose();
        item.set_notes((!text.is_empty()).then_some(text));
    }
    Ok(())
}

/// The user-facing view of an item; secrets only when `reveal`.
pub fn view(summary: ItemSummary, item: &Item, reveal: bool) -> ItemView {
    let fields = item
        .fields()
        .iter()
        .map(|f| {
            let secret = f.kind().is_secret();
            let value = match f.value() {
                FieldValue::Plain(s) => Some(SecretText::new(s.clone())),
                FieldValue::Secret(s) if reveal => Some(SecretText::from(s)),
                FieldValue::Secret(_) => None,
                FieldValue::File(id) => Some(SecretText::new(id.to_string())),
            };
            FieldView {
                id: f.id(),
                name: f.name().to_owned(),
                label: f.label().to_owned(),
                kind: f.kind(),
                secret,
                filled: !f.is_empty(),
                value,
            }
        })
        .collect();
    ItemView {
        summary,
        fields,
        has_notes: item.notes().is_some(),
        notes: if reveal {
            item.notes().map(SecretText::from)
        } else {
            None
        },
        attachments: item.attachments().to_vec(),
        revealed: reveal,
    }
}

impl Unlocked {
    /// The default vault: "Personal" if it exists, else the only vault.
    pub(crate) fn default_vault(&self) -> ClientResult<klav_core::ids::VaultId> {
        if let Ok(v) = self.find_vault(crate::DEFAULT_VAULT) {
            return Ok(v);
        }
        match self.vaults().as_slice() {
            [only] => Ok(only.id),
            [] => Err(ClientError::NotFound("a vault".into())),
            _ => Err(ClientError::Invalid(
                "several vaults: choose one with --vault".into(),
            )),
        }
    }

    /// Resolves the destination of a new item.
    pub fn destination(
        &self,
        vault: Option<&str>,
        project: Option<&str>,
    ) -> ClientResult<(klav_core::ids::VaultId, klav_core::ids::ProjectId)> {
        let vault = match vault {
            Some(v) => self.find_vault(v)?,
            None => self.default_vault()?,
        };
        let project = self.find_project(vault, project.unwrap_or(crate::DEFAULT_PROJECT))?;
        Ok((vault, project))
    }

    /// Creates an item from a [`NewItem`]. Refuses a title that another
    /// live item of the project already has, unless `allow_duplicate`:
    /// references by title would become ambiguous.
    pub async fn create(&mut self, new: &NewItem) -> ClientResult<ItemSummary> {
        let item = build_item(new)?;
        let (vault, project) = self.destination(new.vault.as_deref(), new.project.as_deref())?;
        if !new.allow_duplicate
            && let Some(existing) = self.titled(vault, project, item.title()).first()
        {
            return Err(duplicate_title(existing));
        }
        let loc = self.add_item(vault, project, &item).await?;
        self.link_saved_login(loc).await;
        self.item_summary(loc)
    }

    /// Live items of a project with this title (case-insensitive).
    pub fn titled(&self, vault: VaultId, project: ProjectId, title: &str) -> Vec<ItemSummary> {
        let title = title.trim();
        let mut found: Vec<ItemSummary> = self
            .list_items(&crate::ItemFilter::default())
            .unwrap_or_default()
            .into_iter()
            .filter(|s| {
                s.vault_id == vault
                    && s.project_id == project
                    && s.title.trim().eq_ignore_ascii_case(title)
            })
            .collect();
        found.sort_by_key(|s| s.id.to_string());
        found
    }

    /// Applies `patch` to the item `query` and uploads the next version.
    /// A new title that another live item of the project already has is
    /// refused unless `patch.allow_duplicate` (same rule as [`Self::create`]).
    pub async fn edit(&mut self, query: &str, patch: &ItemPatch) -> ClientResult<ItemSummary> {
        let loc = self.find_item(query)?;
        if let Some(title) = &patch.title
            && !patch.allow_duplicate
            && let Some(existing) = self
                .titled(loc.vault, loc.project, title)
                .into_iter()
                .find(|s| s.id != loc.item)
        {
            return Err(duplicate_title(&existing));
        }
        let mut item = self.open_item(loc)?;
        let dropped: Vec<_> = patch
            .remove
            .iter()
            .filter_map(|name| item.field(name))
            .filter_map(|f| match f.value() {
                FieldValue::File(id) => Some(*id),
                _ => None,
            })
            .collect();
        patch_item(&mut item, patch)?;
        for id in &dropped {
            item.remove_attachment(*id);
        }
        self.update_item(loc, &item).await?;
        if !patch.set.is_empty() {
            self.link_saved_login(loc).await;
        }
        for id in dropped {
            // Best effort: the item no longer references it.
            let _ = self.delete_attachment(loc, id).await;
        }
        self.item_summary(loc)
    }

    /// The view of the item `query`.
    pub fn view_item(&self, query: &str, reveal: bool) -> ClientResult<ItemView> {
        let loc = self.find_item(query)?;
        let item = self.open_item(loc)?;
        Ok(view(self.item_summary(loc)?, &item, reveal))
    }

    /// The items `references` name, in order, as [`Self::resolve_all`]
    /// finds them, without reading any value: each reference parsed, its
    /// item found and its field checked, with the same errors. `klavd`
    /// binds a `resolve` to these, and their versions, before it asks for
    /// presence (ADR 0041, Omar's decision K of 2026-11-19).
    pub fn reference_items(&self, references: &[String]) -> ClientResult<Vec<ItemLocation>> {
        references
            .iter()
            .map(|reference| {
                let parsed = Reference::parse(reference.trim())?;
                let resolved = parsed.resolve(self)?;
                let loc = ItemLocation {
                    vault: resolved.vault,
                    project: resolved.project,
                    item: resolved.item,
                };
                let item = self.open_item(loc)?;
                resolve_field(&item, &resolved.field)?;
                Ok(loc)
            })
            .collect()
    }

    /// Resolves `klav://vault/project/item/field` references to their
    /// values (`run`, `inject`); `file` fields are downloaded.
    pub async fn resolve_all(&mut self, references: &[String]) -> ClientResult<Vec<ResolvedValue>> {
        let mut out = Vec::with_capacity(references.len());
        for reference in references {
            let parsed = Reference::parse(reference.trim())?;
            let resolved = parsed.resolve(&*self)?;
            let loc = ItemLocation {
                vault: resolved.vault,
                project: resolved.project,
                item: resolved.item,
            };
            let item = self.open_item(loc)?;
            let field = resolve_field(&item, &resolved.field)?;
            let canonical = format!("{}/{}", self.item_summary(loc)?.reference, field.name());
            let kind = field.kind();
            let value = match field.value() {
                FieldValue::Plain(s) => Zeroizing::new(s.as_bytes().to_vec()),
                FieldValue::Secret(s) => Zeroizing::new(s.expose().as_bytes().to_vec()),
                FieldValue::File(id) => {
                    let id = *id;
                    drop(item);
                    self.download_attachment(loc, id).await?
                }
            };
            out.push(ResolvedValue {
                reference: reference.clone(),
                canonical,
                kind,
                value: SecretBytes::new(value),
            });
        }
        Ok(out)
    }

    /// The TOTP code of the item `query`.
    pub fn totp_code(&self, query: &str, field: Option<&str>) -> ClientResult<TotpCode> {
        let loc: ItemLocation = self.find_item(query)?;
        let (code, remaining) = self.totp(loc, field)?;
        Ok(TotpCode {
            code: SecretText::from(&code),
            remaining,
        })
    }

    /// Moves the item `query` to the trash.
    pub async fn trash(&mut self, query: &str) -> ClientResult<ItemSummary> {
        let loc = self.find_item(query)?;
        let summary = self.item_summary(loc)?;
        self.trash_item(loc).await?;
        Ok(summary)
    }
}

/// The error for a title another live item of the project already has.
fn duplicate_title(existing: &ItemSummary) -> ClientError {
    ClientError::Invalid(format!(
        "{} already exists (item {}): change it with `klav item edit`, choose another title, or pass --allow-duplicate",
        existing.reference, existing.id
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_fields_cannot_come_from_plain_input() {
        let new = NewItem {
            kind: ItemKind::Login,
            title: "x".into(),
            vault: None,
            project: None,
            fields: vec![FieldInput {
                name: "password".into(),
                value: SecretText::new("hunter2"),
                kind: None,
                secret: false,
            }],
            urls: vec![],
            tags: vec![],
            notes: None,
            allow_duplicate: false,
        };
        assert!(matches!(build_item(&new), Err(ClientError::Invalid(_))));
        // Nobody creates Klav's own items by hand (agents included: the
        // SDK builds items here too).
        let system = NewItem {
            kind: ItemKind::GeneratorHistory,
            fields: vec![],
            ..new.clone()
        };
        assert!(matches!(build_item(&system), Err(ClientError::Invalid(_))));
        let mut ok = new.clone();
        ok.fields[0].secret = true;
        let item = build_item(&ok).unwrap();
        let shown = view(dummy_summary(), &item, false);
        let pw = shown.fields.iter().find(|f| f.name == "password").unwrap();
        assert!(pw.secret && pw.filled && pw.value.is_none());
        let revealed = view(dummy_summary(), &item, true);
        let pw = revealed
            .fields
            .iter()
            .find(|f| f.name == "password")
            .unwrap();
        assert_eq!(pw.value.as_ref().unwrap().expose(), "hunter2");
        assert_eq!(format!("{:?}", pw.value), "Some(SecretText(…))");
    }

    #[test]
    fn patches_add_set_and_remove_fields() {
        let mut item = Item::from_template(ItemKind::ApiKey, "Stripe").unwrap();
        let patch = ItemPatch {
            title: Some("Stripe live".into()),
            set: vec![
                FieldInput {
                    name: "api_key".into(),
                    value: SecretText::new("sk_live"),
                    kind: None,
                    secret: true,
                },
                FieldInput {
                    name: "account".into(),
                    value: SecretText::new("acme"),
                    kind: None,
                    secret: false,
                },
            ],
            add_tags: vec!["prod".into()],
            ..ItemPatch::default()
        };
        patch_item(&mut item, &patch).unwrap();
        assert_eq!(item.title(), "Stripe live");
        assert_eq!(item.field("account").unwrap().kind(), FieldKind::Text);
        assert!(item.has_tag("prod"));
        let remove = ItemPatch {
            remove: vec!["account".into(), "api_key".into()],
            ..ItemPatch::default()
        };
        patch_item(&mut item, &remove).unwrap();
        assert!(item.field("account").is_none());
        assert!(item.field("api_key").unwrap().is_empty());
    }

    fn dummy_summary() -> ItemSummary {
        ItemSummary {
            id: klav_core::ids::ItemId::generate(),
            reference: "klav://a/b/c".into(),
            vault_id: klav_core::ids::VaultId::generate(),
            vault: "a".into(),
            project_id: klav_core::ids::ProjectId::generate(),
            project: "b".into(),
            kind: ItemKind::Login,
            title: "c".into(),
            username: None,
            urls: vec![],
            tags: vec![],
            version: 1,
            updated_at: 0,
            trashed: false,
            passkey: None,
            confirmed_urls: vec![],
            pending_urls: vec![],
            author_agent_id: None,
        }
    }
}
