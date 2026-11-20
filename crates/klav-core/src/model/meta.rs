//! Vault and project metadata (spec §7.2).
//!
//! The plaintext is a JSON object that rejects unknown keys:
//!
//! ```json
//! { "v": 1, "name": "Trabajo", "description": "optional" }
//! ```
//!
//! `name` is what `klav://<vault>/<project>/…` references match
//! (case-insensitively).

use serde::{Deserialize, Serialize};

use super::item::ModelError;
use crate::crypto::context::{ProjectContext, VaultContext};
use crate::crypto::keys::{ProjectKey, VaultKey};
use crate::crypto::meta;
use crate::ids::looks_like_id;

/// Schema version of the metadata JSON.
pub const META_SCHEMA_VERSION: u32 = 1;
/// Maximum length of a vault or project name, in characters.
pub const MAX_NAME_LEN: usize = 64;
/// Maximum length of a description, in characters.
pub const MAX_DESCRIPTION_LEN: usize = 1024;

/// Name and description of a vault or a project.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Meta {
    name: String,
    description: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawMeta {
    v: u32,
    name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    description: Option<String>,
}

/// Checks a vault or project name: 1–64 characters, no control characters,
/// no surrounding spaces, no `/` and not shaped like an ID (references would
/// read it as one).
pub fn validate_name(name: &str) -> Result<(), ModelError> {
    let count = name.chars().count();
    if !(1..=MAX_NAME_LEN).contains(&count)
        || name.chars().any(|c| c.is_control() || c == '/')
        || name.trim() != name
        || looks_like_id(name)
    {
        return Err(ModelError::InvalidText("name"));
    }
    Ok(())
}

impl Meta {
    /// Builds metadata with a validated name.
    pub fn new(name: &str, description: Option<&str>) -> Result<Self, ModelError> {
        validate_name(name)?;
        if let Some(d) = description
            && (d.chars().count() > MAX_DESCRIPTION_LEN
                || d.chars().any(|c| c.is_control() && c != '\n'))
        {
            return Err(ModelError::InvalidText("description"));
        }
        Ok(Self {
            name: name.to_owned(),
            description: description.map(str::to_owned),
        })
    }

    /// The name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The description, if any.
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    /// JSON plaintext.
    pub fn encode(&self) -> Vec<u8> {
        serde_json::to_vec(&RawMeta {
            v: META_SCHEMA_VERSION,
            name: self.name.clone(),
            description: self.description.clone(),
        })
        .expect("metadata always serializes")
    }

    /// Parses and validates the JSON plaintext.
    pub fn decode(bytes: &[u8]) -> Result<Self, ModelError> {
        let raw: RawMeta =
            serde_json::from_slice(bytes).map_err(|e| ModelError::Json(e.to_string()))?;
        if raw.v != META_SCHEMA_VERSION {
            return Err(ModelError::UnsupportedSchema(raw.v));
        }
        Self::new(&raw.name, raw.description.as_deref())
    }
}

/// Seals vault metadata at `version`.
pub fn seal_vault_meta(key: &VaultKey, ctx: &VaultContext, version: u64, meta: &Meta) -> Vec<u8> {
    meta::encrypt_vault_meta(key, ctx, version, &meta.encode())
}

/// Opens vault metadata sealed for `version`.
pub fn open_vault_meta(
    key: &VaultKey,
    ctx: &VaultContext,
    version: u64,
    blob: &[u8],
) -> Result<Meta, ModelError> {
    Meta::decode(&meta::decrypt_vault_meta(key, ctx, version, blob)?)
}

/// Seals project metadata at `version`.
pub fn seal_project_meta(
    key: &ProjectKey,
    ctx: &ProjectContext,
    version: u64,
    meta: &Meta,
) -> Vec<u8> {
    meta::encrypt_project_meta(key, ctx, version, &meta.encode())
}

/// Opens project metadata sealed for `version`.
pub fn open_project_meta(
    key: &ProjectKey,
    ctx: &ProjectContext,
    version: u64,
    blob: &[u8],
) -> Result<Meta, ModelError> {
    Meta::decode(&meta::decrypt_project_meta(key, ctx, version, blob)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::{AccountId, ProjectId, VaultId};

    #[test]
    fn names_are_validated() {
        for ok in [
            "Personal",
            "Trabajo",
            "acme-api",
            "Familia & amigos",
            "ñandú",
        ] {
            assert!(Meta::new(ok, None).is_ok(), "{ok}");
        }
        for bad in [
            "",
            " x",
            "x ",
            "a/b",
            "a\nb",
            "4f1c3c1e-6a0b-4c1e-9f1e-2b3c4d5e6f70",
            &"x".repeat(65),
        ] {
            assert!(Meta::new(bad, None).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn json_roundtrip_rejects_unknown_keys_and_versions() {
        let meta = Meta::new("Trabajo", Some("work stuff")).unwrap();
        assert_eq!(Meta::decode(&meta.encode()).unwrap(), meta);
        assert!(Meta::decode(br#"{"v":1,"name":"x","extra":1}"#).is_err());
        assert_eq!(
            Meta::decode(br#"{"v":2,"name":"x"}"#),
            Err(ModelError::UnsupportedSchema(2))
        );
    }

    #[test]
    fn sealed_roundtrip() {
        let p = ProjectContext {
            account: AccountId::generate(),
            vault: VaultId::generate(),
            project: ProjectId::generate(),
        };
        let meta = Meta::new("acme-api", None).unwrap();
        let vk = VaultKey::generate();
        let blob = seal_vault_meta(&vk, &p.vault_context(), 1, &meta);
        assert_eq!(
            open_vault_meta(&vk, &p.vault_context(), 1, &blob).unwrap(),
            meta
        );
        let pk = ProjectKey::generate();
        let blob = seal_project_meta(&pk, &p, 1, &meta);
        assert_eq!(open_project_meta(&pk, &p, 1, &blob).unwrap(), meta);
        assert!(matches!(
            open_project_meta(&pk, &p, 2, &blob),
            Err(ModelError::Crypto(_))
        ));
    }
}
