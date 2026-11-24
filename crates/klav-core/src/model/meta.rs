//! Vault and project metadata (spec §7.2, ADR 0032 §2).
//!
//! The plaintext is a JSON object that rejects unknown keys:
//!
//! ```json
//! { "v": 1, "name": "Trabajo", "description": "optional", "repos": ["github.com/omar/acme-api"] }
//! ```
//!
//! `name` is what `klav://<vault>/<project>/…` references match
//! (case-insensitively). `repos` is omitted when empty so existing metadata
//! serializes identically.

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
/// Maximum length of a repository URL or normalized identifier, in bytes.
pub const MAX_REPO_LEN: usize = 256;
/// Maximum number of repositories linked to one project.
pub const MAX_PROJECT_REPOS: usize = 32;

/// Name, description and optional linked repositories of a vault or a project.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Meta {
    name: String,
    description: Option<String>,
    repos: Vec<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawMeta {
    v: u32,
    name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    repos: Vec<String>,
}

/// Normalizes a Git repository remote URL (or bare `host/owner/repo` string)
/// into the canonical lowercase `host/path` form specified in ADR 0032 §2:
///
/// - `git@github.com:Omar/acme-api.git` → `github.com/omar/acme-api`
/// - `ssh://git@github.com:22/Omar/acme-api` → `github.com/omar/acme-api`
/// - `https://github.com/Omar/acme-api/` → `github.com/omar/acme-api`
/// - `https://gitlab.com/group/sub/repo.git` → `gitlab.com/group/sub/repo`
/// - `github.com/Omar/acme-api` → `github.com/omar/acme-api`
pub fn normalize_repo_url(raw: &str) -> Result<String, ModelError> {
    if raw.chars().any(char::is_control) {
        return Err(ModelError::InvalidText("repository"));
    }
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.len() > MAX_REPO_LEN {
        return Err(ModelError::InvalidText("repository"));
    }

    let (host, path): (String, String) = if trimmed.contains("://") {
        let parsed = url::Url::parse(trimmed).map_err(|_| ModelError::InvalidText("repository"))?;
        if !matches!(parsed.scheme(), "http" | "https" | "ssh" | "git") {
            return Err(ModelError::InvalidText("repository"));
        }
        let host = parsed
            .host_str()
            .filter(|h| !h.is_empty())
            .ok_or(ModelError::InvalidText("repository"))?
            .to_ascii_lowercase();
        (host, parsed.path().to_owned())
    } else if let Some((left, right)) = trimmed.split_once(':') {
        // SCP-style SSH: `git@github.com:owner/repo.git` or `github.com:owner/repo`.
        if left.contains('/') {
            return Err(ModelError::InvalidText("repository"));
        }
        let host = left
            .rsplit_once('@')
            .map_or(left, |(_, h)| h)
            .trim()
            .to_ascii_lowercase();
        (host, right.to_owned())
    } else {
        // Bare canonical form: `github.com/owner/repo(.git)`
        let without_user = trimmed.rsplit_once('@').map_or(trimmed, |(_, rest)| rest);
        let Some((host, path)) = without_user.split_once('/') else {
            return Err(ModelError::InvalidText("repository"));
        };
        let host = host.split(':').next().unwrap_or(host).to_ascii_lowercase();
        (host, path.to_owned())
    };

    if host.is_empty()
        || host.chars().any(|c| c.is_whitespace() || c == '/')
        || host.starts_with('.')
        || host.ends_with('.')
        || host.contains("..")
    {
        return Err(ModelError::InvalidText("repository"));
    }

    // Drop query/fragment if present on non-URL inputs, strip leading/trailing
    // slashes, and strip a single trailing `.git` suffix (case-insensitive).
    let path = path
        .split(['?', '#'])
        .next()
        .unwrap_or("")
        .trim_matches('/');
    let path = if path.len() >= 4 && path[path.len() - 4..].eq_ignore_ascii_case(".git") {
        &path[..path.len() - 4]
    } else {
        path
    }
    .trim_matches('/');

    let segments: Vec<String> = path
        .split('/')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_ascii_lowercase())
        .collect();
    if segments.len() < 2
        || segments
            .iter()
            .any(|s| s == "." || s == ".." || s.chars().any(char::is_whitespace))
    {
        return Err(ModelError::InvalidText("repository"));
    }

    let normalized = format!("{host}/{}", segments.join("/"));
    if normalized.len() > MAX_REPO_LEN {
        return Err(ModelError::InvalidText("repository"));
    }
    Ok(normalized)
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
            repos: Vec::new(),
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

    /// Normalized repository identifiers linked to this project (ADR 0032 §2).
    pub fn repos(&self) -> &[String] {
        &self.repos
    }

    /// Sets the linked repositories, normalizing and deduplicating them.
    pub fn with_repos(mut self, repos: Vec<String>) -> Result<Self, ModelError> {
        let mut clean = Vec::new();
        for raw in repos {
            let norm = normalize_repo_url(&raw)?;
            if !clean.contains(&norm) {
                if clean.len() >= MAX_PROJECT_REPOS {
                    return Err(ModelError::InvalidText("too many repositories"));
                }
                clean.push(norm);
            }
        }
        self.repos = clean;
        Ok(self)
    }

    /// Adds a repository link, returning its normalized form.
    pub fn add_repo(&mut self, raw: &str) -> Result<String, ModelError> {
        let norm = normalize_repo_url(raw)?;
        if !self.repos.contains(&norm) {
            if self.repos.len() >= MAX_PROJECT_REPOS {
                return Err(ModelError::InvalidText("too many repositories"));
            }
            self.repos.push(norm.clone());
        }
        Ok(norm)
    }

    /// Removes a repository link (matching after normalization). Returns
    /// whether it was present.
    pub fn remove_repo(&mut self, raw: &str) -> Result<bool, ModelError> {
        let norm = normalize_repo_url(raw)?;
        let before = self.repos.len();
        self.repos.retain(|r| r != &norm);
        Ok(self.repos.len() != before)
    }

    /// JSON plaintext.
    pub fn encode(&self) -> Vec<u8> {
        serde_json::to_vec(&RawMeta {
            v: META_SCHEMA_VERSION,
            name: self.name.clone(),
            description: self.description.clone(),
            repos: self.repos.clone(),
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
        Self::new(&raw.name, raw.description.as_deref())?.with_repos(raw.repos)
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
        let encoded = meta.encode();
        // Empty `repos` must be omitted to stay byte-compatible with older readers.
        assert!(
            !String::from_utf8(encoded.clone())
                .unwrap()
                .contains("repos")
        );
        assert_eq!(Meta::decode(&encoded).unwrap(), meta);
        assert!(Meta::decode(br#"{"v":1,"name":"x","extra":1}"#).is_err());
        assert_eq!(
            Meta::decode(br#"{"v":2,"name":"x"}"#),
            Err(ModelError::UnsupportedSchema(2))
        );
    }

    #[test]
    fn normalize_repo_urls_follow_adr_0032() {
        for raw in [
            "git@github.com:Omar/acme-api.git",
            "ssh://git@github.com:22/Omar/acme-api",
            "ssh://git@github.com/Omar/acme-api.git/",
            "https://github.com/Omar/acme-api/",
            "https://github.com/Omar/acme-api.git",
            "https://user:token@github.com/Omar/acme-api.git",
            "git://github.com/Omar/acme-api.git",
            "github.com/Omar/acme-api",
        ] {
            assert_eq!(
                normalize_repo_url(raw).unwrap(),
                "github.com/omar/acme-api",
                "raw={raw}"
            );
        }
        assert_eq!(
            normalize_repo_url("git@gitlab.com:Group/Sub/Repo.git").unwrap(),
            "gitlab.com/group/sub/repo"
        );
        for bad in [
            "",
            "   ",
            "github.com",
            "github.com/only-owner",
            "https://github.com/omar/acme\n",
            "file:///tmp/repo",
            "https://github.com/omar/../evil",
            "github.com/omar/has space",
        ] {
            assert!(normalize_repo_url(bad).is_err(), "must reject {bad:?}");
        }
    }

    #[test]
    fn meta_repos_roundtrip_and_deduplicate() {
        let mut meta = Meta::new("acme-api", None)
            .unwrap()
            .with_repos(vec![
                "git@github.com:Omar/acme-api.git".into(),
                "https://github.com/omar/acme-api/".into(),
            ])
            .unwrap();
        assert_eq!(meta.repos(), ["github.com/omar/acme-api"]);
        assert_eq!(
            meta.add_repo("https://gitlab.com/team/sub/service.git")
                .unwrap(),
            "gitlab.com/team/sub/service"
        );
        let decoded = Meta::decode(&meta.encode()).unwrap();
        assert_eq!(decoded, meta);
        assert!(
            meta.remove_repo("https://github.com/Omar/acme-api")
                .unwrap()
        );
        assert_eq!(meta.repos(), ["gitlab.com/team/sub/service"]);
    }

    #[test]
    fn sealed_roundtrip() {
        let p = ProjectContext {
            account: AccountId::generate(),
            vault: VaultId::generate(),
            project: ProjectId::generate(),
        };
        let meta = Meta::new("acme-api", None)
            .unwrap()
            .with_repos(vec!["github.com/omar/acme-api".into()])
            .unwrap();
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
