//! A passkey inside a login (spec §14.2, ADR 0020 §2–3).
//!
//! At most one per login. The private key travels in the details as a
//! `0x15` blob sealed with the **vault key** ([`crate::crypto::passkey`]):
//! whoever reads the details (an agent with `fill`, `reveal` or `update`)
//! sees the metadata and an opaque blob, never the scalar.
//!
//! `credential_id`, `rp_id`, `user_handle` and the key are immutable: an
//! edit of the login keeps the passkey as it is, and only
//! [`crate::model::Item::set_passkey`] and
//! [`crate::model::Item::remove_passkey`] change it.

use serde::{Deserialize, Serialize};

use super::item::ModelError;
use crate::crypto::context::VaultContext;
use crate::crypto::keys::VaultKey;
#[cfg(test)]
use crate::crypto::keys::sealed::Sealed;
use crate::crypto::passkey::{
    self as sealed, CREDENTIAL_ID_LEN, PasskeyBinding, PasskeyPrivateKey,
};
use crate::crypto::random;
use crate::ids::ItemId;
use crate::passkey::webauthn::ALG_ES256;

/// Longest `rp_name`, `user_name` or `user_display_name`, in characters.
pub const MAX_PASSKEY_TEXT_LEN: usize = 256;

const B64: data_encoding::Encoding = data_encoding::BASE64URL_NOPAD;

/// A passkey of a login. Nothing in it is secret in the clear: the private
/// key is the sealed `0x15` blob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Passkey {
    credential_id: Vec<u8>,
    rp_id: String,
    rp_name: Option<String>,
    user_handle: Vec<u8>,
    user_name: String,
    user_display_name: Option<String>,
    created_at: i64,
    key: Vec<u8>,
}

/// What the overview says about the passkey of a login: what `list` may see.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasskeySummary {
    /// Relying party ID.
    pub rp_id: String,
    /// Credential ID, base64url without padding.
    pub credential_id: String,
    /// `user.name`.
    pub user_name: String,
}

/// The account a new passkey is for, as the relying party describes it.
#[derive(Debug, Clone, Copy)]
pub struct PasskeyAccount<'a> {
    /// Relying party ID (already validated for the origin, `passkey::rp`).
    pub rp_id: &'a str,
    /// `rp.name`, only for display.
    pub rp_name: Option<&'a str>,
    /// `user.id` (1 to 64 bytes).
    pub user_handle: &'a [u8],
    /// `user.name`.
    pub user_name: &'a str,
    /// `user.displayName`.
    pub user_display_name: Option<&'a str>,
    /// Creation time, Unix milliseconds.
    pub created_at: i64,
}

impl Passkey {
    /// A new passkey for `item`: a fresh key and a random 16-byte credential
    /// ID, the key sealed with the vault key. Returns the key too, to sign
    /// the registration without opening the blob again.
    pub fn create(
        vault_key: &VaultKey,
        ctx: &VaultContext,
        item: ItemId,
        account: &PasskeyAccount<'_>,
    ) -> Result<(Self, PasskeyPrivateKey), ModelError> {
        let key = PasskeyPrivateKey::generate();
        let credential_id = random::array::<CREDENTIAL_ID_LEN>();
        let passkey = Self::import(vault_key, ctx, item, &credential_id, account, &key)?;
        Ok((passkey, key))
    }

    /// A passkey whose key and credential ID come from elsewhere (an
    /// importer). The key is sealed with the vault key for `item`.
    pub fn import(
        vault_key: &VaultKey,
        ctx: &VaultContext,
        item: ItemId,
        credential_id: &[u8],
        account: &PasskeyAccount<'_>,
        key: &PasskeyPrivateKey,
    ) -> Result<Self, ModelError> {
        let mut passkey = Self {
            credential_id: credential_id.to_vec(),
            rp_id: account.rp_id.to_owned(),
            rp_name: account.rp_name.map(str::to_owned),
            user_handle: account.user_handle.to_vec(),
            user_name: account.user_name.to_owned(),
            user_display_name: account.user_display_name.map(str::to_owned),
            created_at: account.created_at,
            key: Vec::new(),
        };
        passkey.validate_metadata()?;
        passkey.key = sealed::seal_passkey_key(vault_key, ctx, item, &passkey.binding(), key)?;
        Ok(passkey)
    }

    /// Opens the private key. Only a client of the person holds the vault
    /// key; any other key, item, credential, rpId or user fails.
    pub fn open_key(
        &self,
        vault_key: &VaultKey,
        ctx: &VaultContext,
        item: ItemId,
    ) -> Result<PasskeyPrivateKey, ModelError> {
        Ok(sealed::open_passkey_key(
            vault_key,
            ctx,
            item,
            &self.binding(),
            &self.key,
        )?)
    }

    /// What the sealed key is bound to.
    pub fn binding(&self) -> PasskeyBinding<'_> {
        PasskeyBinding {
            credential_id: &self.credential_id,
            rp_id: &self.rp_id,
            user_handle: &self.user_handle,
        }
    }

    /// Credential ID.
    pub fn credential_id(&self) -> &[u8] {
        &self.credential_id
    }

    /// Relying party ID.
    pub fn rp_id(&self) -> &str {
        &self.rp_id
    }

    /// `rp.name`.
    pub fn rp_name(&self) -> Option<&str> {
        self.rp_name.as_deref()
    }

    /// `user.id`.
    pub fn user_handle(&self) -> &[u8] {
        &self.user_handle
    }

    /// `user.name`.
    pub fn user_name(&self) -> &str {
        &self.user_name
    }

    /// `user.displayName`.
    pub fn user_display_name(&self) -> Option<&str> {
        self.user_display_name.as_deref()
    }

    /// COSE algorithm: always ES256 (`-7`).
    pub fn alg(&self) -> i64 {
        ALG_ES256
    }

    /// Creation time, Unix milliseconds.
    pub fn created_at(&self) -> i64 {
        self.created_at
    }

    /// The sealed private key (`0x15`), opaque.
    pub fn sealed_key(&self) -> &[u8] {
        &self.key
    }

    /// The summary for the overview.
    pub fn summary(&self) -> PasskeySummary {
        PasskeySummary {
            rp_id: self.rp_id.clone(),
            credential_id: B64.encode(&self.credential_id),
            user_name: self.user_name.clone(),
        }
    }

    fn validate_metadata(&self) -> Result<(), ModelError> {
        self.binding()
            .validate()
            .map_err(|_| ModelError::InvalidText("passkey"))?;
        for text in [
            Some(self.user_name.as_str()),
            self.rp_name.as_deref(),
            self.user_display_name.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            if text.chars().count() > MAX_PASSKEY_TEXT_LEN || text.chars().any(char::is_control) {
                return Err(ModelError::InvalidText("passkey"));
            }
        }
        Ok(())
    }

    fn validate(&self) -> Result<(), ModelError> {
        self.validate_metadata()?;
        sealed::check_sealed_passkey_key(&self.key)
            .map_err(|_| ModelError::InvalidText("passkey key"))
    }

    pub(crate) fn to_raw(&self) -> RawPasskey {
        RawPasskey {
            credential_id: B64.encode(&self.credential_id),
            rp_id: self.rp_id.clone(),
            rp_name: self.rp_name.clone(),
            user_handle: B64.encode(&self.user_handle),
            user_name: self.user_name.clone(),
            user_display_name: self.user_display_name.clone(),
            alg: ALG_ES256,
            created_at: self.created_at,
            key: B64.encode(&self.key),
        }
    }

    pub(crate) fn from_raw(raw: &RawPasskey) -> Result<Self, ModelError> {
        if raw.alg != ALG_ES256 {
            return Err(ModelError::InvalidText("passkey algorithm"));
        }
        let decode = |text: &str| {
            B64.decode(text.as_bytes())
                .map_err(|_| ModelError::InvalidText("passkey"))
        };
        let passkey = Self {
            credential_id: decode(&raw.credential_id)?,
            rp_id: raw.rp_id.clone(),
            rp_name: raw.rp_name.clone(),
            user_handle: decode(&raw.user_handle)?,
            user_name: raw.user_name.clone(),
            user_display_name: raw.user_display_name.clone(),
            created_at: raw.created_at,
            key: decode(&raw.key)?,
        };
        passkey.validate()?;
        Ok(passkey)
    }
}

/// The `passkey` object of the details JSON (spec §14.2).
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawPasskey {
    credential_id: String,
    rp_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    rp_name: Option<String>,
    user_handle: String,
    user_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    user_display_name: Option<String>,
    alg: i64,
    created_at: i64,
    key: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::context::ItemContext;
    use crate::crypto::keys::{ItemKey, ProjectKey};
    use crate::crypto::wrap::{unwrap_item_key, wrap_item_key};
    use crate::ids::{AccountId, ProjectId, VaultId};
    use crate::model::item::{Item, ItemKind, open_item, seal_item};
    use crate::model::reference::{Selector, resolve_field};
    use crate::passkey::webauthn;

    struct World {
        vault_key: VaultKey,
        ctx: ItemContext,
    }

    impl World {
        fn new(item: ItemId) -> Self {
            Self {
                vault_key: VaultKey::generate(),
                ctx: ItemContext {
                    account: AccountId::generate(),
                    vault: VaultId::generate(),
                    project: ProjectId::generate(),
                    item,
                },
            }
        }

        fn vault(&self) -> VaultContext {
            VaultContext {
                account: self.ctx.account,
                vault: self.ctx.vault,
            }
        }
    }

    const ACCOUNT: PasskeyAccount<'static> = PasskeyAccount {
        rp_id: "example.com",
        rp_name: Some("Example"),
        user_handle: b"user-0001",
        user_name: "ana@example.com",
        user_display_name: Some("Ana"),
        created_at: 1_800_000_000_000,
    };

    fn login_with_passkey() -> (Item, World, PasskeyPrivateKey) {
        let mut item = Item::from_template(ItemKind::Login, "Example").unwrap();
        item.field_mut("username")
            .unwrap()
            .set_value("ana")
            .unwrap();
        item.field_mut("password")
            .unwrap()
            .set_value("hunter2")
            .unwrap();
        let world = World::new(item.id());
        let (passkey, key) =
            Passkey::create(&world.vault_key, &world.vault(), item.id(), &ACCOUNT).unwrap();
        item.set_passkey(passkey).unwrap();
        (item, world, key)
    }

    #[test]
    fn round_trips_through_both_sections() {
        let (item, world, key) = login_with_passkey();
        let item_key = ItemKey::generate();
        let sealed = seal_item(&item_key, &world.ctx, 1, &item);
        let back = open_item(&item_key, &world.ctx, 1, &sealed).unwrap();
        let passkey = back.passkey().unwrap();
        assert_eq!(passkey, item.passkey().unwrap());
        assert_eq!(passkey.credential_id().len(), 16);
        assert_eq!(passkey.sealed_key().len(), 74);
        assert_eq!(passkey.alg(), -7);
        // The URL of the rpId was added, once.
        assert_eq!(back.urls(), ["https://example.com"]);
        // The overview carries the summary, and nothing secret.
        let overview = back.overview();
        let summary = overview.passkey.as_ref().unwrap();
        assert_eq!(summary.rp_id, "example.com");
        assert_eq!(summary.user_name, "ana@example.com");
        let (overview_json, details_json) = back.encode_sections();
        let text = String::from_utf8(overview_json).unwrap();
        assert!(!text.contains("\"key\""));
        assert!(!text.contains("user_handle"));
        let details: serde_json::Value = serde_json::from_slice(&details_json).unwrap();
        assert_eq!(details["passkey"]["alg"], -7);
        // The person (vault key) opens the key; it is the same key.
        let opened = passkey
            .open_key(&world.vault_key, &world.vault(), item.id())
            .unwrap();
        assert_eq!(opened.public_key(), key.public_key());
    }

    #[test]
    fn an_existing_url_of_the_rp_is_kept_and_none_is_added() {
        let mut item = Item::from_template(ItemKind::Login, "Example").unwrap();
        item.add_url("https://EXAMPLE.com/login").unwrap();
        let world = World::new(item.id());
        let (passkey, _) =
            Passkey::create(&world.vault_key, &world.vault(), item.id(), &ACCOUNT).unwrap();
        item.set_passkey(passkey).unwrap();
        assert_eq!(item.urls(), ["https://EXAMPLE.com/login"]);
        // A subdomain is not the rpId's host: the rpId's URL is added.
        let mut item = Item::from_template(ItemKind::Login, "Example").unwrap();
        item.add_url("https://login.example.com").unwrap();
        let world = World::new(item.id());
        let (passkey, _) =
            Passkey::create(&world.vault_key, &world.vault(), item.id(), &ACCOUNT).unwrap();
        item.set_passkey(passkey).unwrap();
        assert_eq!(
            item.urls(),
            ["https://login.example.com", "https://example.com"]
        );
    }

    #[test]
    fn only_logins_carry_a_passkey() {
        let mut note = Item::new(ItemKind::Note, "Note").unwrap();
        let world = World::new(note.id());
        let (passkey, _) =
            Passkey::create(&world.vault_key, &world.vault(), note.id(), &ACCOUNT).unwrap();
        assert!(note.set_passkey(passkey.clone()).is_err());
        // A note whose details carry a passkey is rejected on decode.
        let (login, ..) = login_with_passkey();
        let (_, details) = login.encode_sections();
        let mut details: serde_json::Value = serde_json::from_slice(&details).unwrap();
        details["kind"] = "note".into();
        let mut overview: serde_json::Value =
            serde_json::from_slice(&login.encode_sections().0).unwrap();
        overview["kind"] = "note".into();
        assert!(
            Item::decode_sections(
                login.id(),
                &serde_json::to_vec(&overview).unwrap(),
                &serde_json::to_vec(&details).unwrap()
            )
            .is_err()
        );
    }

    #[test]
    fn the_overview_summary_must_match_the_details() {
        let (item, ..) = login_with_passkey();
        let (overview, details) = item.encode_sections();
        let decode = |o: &serde_json::Value, d: &[u8]| {
            Item::decode_sections(item.id(), &serde_json::to_vec(o).unwrap(), d)
        };
        let good: serde_json::Value = serde_json::from_slice(&overview).unwrap();
        assert!(decode(&good, &details).is_ok());
        for (key, value) in [
            ("rp_id", "evil.example"),
            ("user_name", "mallory"),
            ("credential_id", "AAAAAAAAAAAAAAAAAAAAAA"),
        ] {
            let mut bad = good.clone();
            bad["passkey"][key] = value.into();
            assert_eq!(
                decode(&bad, &details).err(),
                Some(ModelError::SectionMismatch),
                "{key}"
            );
        }
        let mut missing = good.clone();
        missing.as_object_mut().unwrap().remove("passkey");
        assert_eq!(
            decode(&missing, &details).err(),
            Some(ModelError::SectionMismatch)
        );
        // Unknown keys and other algorithms are rejected.
        let mut raw: serde_json::Value = serde_json::from_slice(&details).unwrap();
        raw["passkey"]["alg"] = (-8).into();
        assert!(decode(&good, &serde_json::to_vec(&raw).unwrap()).is_err());
        let mut raw: serde_json::Value = serde_json::from_slice(&details).unwrap();
        raw["passkey"]["prf"] = "x".into();
        assert!(decode(&good, &serde_json::to_vec(&raw).unwrap()).is_err());
        let mut raw: serde_json::Value = serde_json::from_slice(&details).unwrap();
        raw["passkey"]["key"] = "AQMA".into();
        assert!(decode(&good, &serde_json::to_vec(&raw).unwrap()).is_err());
    }

    #[test]
    fn edits_of_the_login_keep_the_passkey_intact() {
        let (mut item, world, key) = login_with_passkey();
        let before = item.passkey().unwrap().clone();
        item.set_title("Example (work)").unwrap();
        item.field_mut("password")
            .unwrap()
            .set_value("new")
            .unwrap();
        item.add_url("https://example.org").unwrap();
        item.set_notes(Some("notes"));
        assert!(item.remove_field("totp").is_some());
        let item_key = ItemKey::generate();
        let back = open_item(
            &item_key,
            &world.ctx,
            2,
            &seal_item(&item_key, &world.ctx, 2, &item),
        )
        .unwrap();
        assert_eq!(back.passkey(), Some(&before));
        let opened = back
            .passkey()
            .unwrap()
            .open_key(&world.vault_key, &world.vault(), item.id())
            .unwrap();
        assert_eq!(opened.public_key(), key.public_key());
        // Only remove_passkey takes it away.
        assert_eq!(item.remove_passkey(), Some(before));
        assert!(item.overview().passkey.is_none());
    }

    #[test]
    fn the_key_is_bound_to_its_item_and_vault() {
        let (item, world, _) = login_with_passkey();
        let passkey = item.passkey().unwrap();
        // Copied into another item (an agent with `update` or `create`).
        assert!(
            passkey
                .open_key(&world.vault_key, &world.vault(), ItemId::generate())
                .is_err()
        );
        assert!(
            passkey
                .open_key(&VaultKey::generate(), &world.vault(), item.id())
                .is_err()
        );
        // Moved to another rpId by editing the details JSON.
        let (overview, details) = item.encode_sections();
        let mut d: serde_json::Value = serde_json::from_slice(&details).unwrap();
        let mut o: serde_json::Value = serde_json::from_slice(&overview).unwrap();
        d["passkey"]["rp_id"] = "evil.example".into();
        o["passkey"]["rp_id"] = "evil.example".into();
        let moved = Item::decode_sections(
            item.id(),
            &serde_json::to_vec(&o).unwrap(),
            &serde_json::to_vec(&d).unwrap(),
        )
        .unwrap();
        assert!(
            moved
                .passkey()
                .unwrap()
                .open_key(&world.vault_key, &world.vault(), item.id())
                .is_err()
        );
    }

    /// ADR 0020 §4 and T85: an agent with `reveal` on the login receives
    /// its project key, the wrapped item key and both sections. It reads
    /// every field, but the passkey is metadata and a `0x15` blob that none
    /// of the keys it holds opens; the vault key never reaches an agent.
    #[test]
    fn an_agent_with_reveal_cannot_open_the_passkey_key() {
        let (item, world, key) = login_with_passkey();
        // What the person uploads.
        let project_key = ProjectKey::generate();
        let item_key = ItemKey::generate();
        let wrapped = wrap_item_key(&project_key, &world.ctx, &item_key);
        let sealed = seal_item(&item_key, &world.ctx, 1, &item);

        // What the agent does with its grant: project key → item key → item.
        let agent_item_key = unwrap_item_key(&project_key, &world.ctx, &wrapped).unwrap();
        let seen = open_item(&agent_item_key, &world.ctx, 1, &sealed).unwrap();
        let passkey = seen.passkey().unwrap();
        // `reveal` resolves fields; there is no field that holds the key.
        for name in ["passkey", "key", "private_key", "credential_id"] {
            assert!(resolve_field(&seen, &Selector::Name(name.into())).is_err());
        }
        // The blob is ciphertext: the scalar is not in it, nor in the
        // details JSON the agent decrypted.
        let scalar = key.scalar();
        let (_, details) = seen.encode_sections();
        let b64 = B64.encode(&*scalar);
        let hex: String = scalar.iter().map(|b| format!("{b:02x}")).collect();
        let details = String::from_utf8(details.to_vec()).unwrap();
        assert!(!details.contains(&b64) && !details.contains(&hex));
        assert!(!passkey.sealed_key().windows(32).any(|w| w == *scalar));
        // None of the agent's keys opens the blob as an AEAD key.
        let binding = passkey.binding();
        let vault_ctx = world.vault();
        for agent_key in [project_key.secret_bytes(), agent_item_key.secret_bytes()] {
            assert!(
                crate::crypto::aead::open(
                    agent_key,
                    crate::crypto::encoding::Kind::PasskeyKey,
                    &binding_tuple(&binding, &vault_ctx, item.id()),
                    passkey.sealed_key(),
                )
                .is_err()
            );
        }
        // And the type system already says so: opening needs a VaultKey,
        // which an agent never receives (ADR 0014 §2.2).
        assert!(
            passkey
                .open_key(&world.vault_key, &vault_ctx, item.id())
                .is_ok()
        );
        // Signing for the agent is klavd's job (ADR 0020 §9): an assertion
        // made with the person's key verifies with the registered public key.
        let a = webauthn::assert(&key, "example.com", true, &[7; 32]);
        let mut message = a.authenticator_data.clone();
        message.extend_from_slice(&[7; 32]);
        crate::crypto::passkey::verify_es256(&key.public_key(), &message, &a.signature).unwrap();
    }

    fn binding_tuple(
        binding: &PasskeyBinding<'_>,
        ctx: &VaultContext,
        item: ItemId,
    ) -> crate::crypto::encoding::Tuple {
        let mut tuple = crate::crypto::encoding::Tuple::new(sealed::LABEL_PASSKEY_KEY);
        tuple
            .push(ctx.account.as_bytes())
            .push(ctx.vault.as_bytes())
            .push(item.as_bytes())
            .push(binding.credential_id)
            .push(binding.rp_id.as_bytes())
            .push(binding.user_handle);
        tuple
    }

    #[test]
    fn metadata_is_validated() {
        let world = World::new(ItemId::generate());
        let bad = [
            PasskeyAccount {
                rp_id: "Example.com",
                ..ACCOUNT
            },
            PasskeyAccount {
                user_handle: &[],
                ..ACCOUNT
            },
            PasskeyAccount {
                user_handle: &[0; 65],
                ..ACCOUNT
            },
            PasskeyAccount {
                user_name: "a\u{7}b",
                ..ACCOUNT
            },
            PasskeyAccount {
                rp_name: Some("x\ny"),
                ..ACCOUNT
            },
        ];
        for account in &bad {
            assert!(
                Passkey::create(&world.vault_key, &world.vault(), world.ctx.item, account).is_err()
            );
        }
    }
}
