//! Local state of an agent: `$KLAV_HOME/agents/<name>.json` (0600).
//!
//! It holds no secret: the private key lives in the keychain, in a 0600 file
//! or in `KLAV_AGENT_KEY` ([`crate::keystore`]). It pins the account
//! identity the first time the agent sees it and the highest grant version
//! it accepted, so a server cannot later swap the account key or roll a
//! grant back (ADR 0014).
//!
//! The pin is only as strong as the file: it is refused if other users may
//! write or read it. It is not sealed, so a process of the same user can
//! still edit it (a residual risk in `docs/modelo-de-amenazas.md`).

use std::path::PathBuf;

use klav_client::home::write_private;
use klav_client::{ClientError, ClientResult, Home};
use klav_core::ids::{AccountId, AgentId};
use klav_proto::Blob;
use serde::{Deserialize, Serialize};

use crate::keystore::KeyStore;

/// Version of the config file format.
const CONFIG_VERSION: u32 = 1;
/// Environment variable naming the agent to use when there are several.
pub const AGENT_ENV: &str = "KLAV_AGENT";

/// `agents/<name>.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentConfig {
    /// Format version.
    pub v: u32,
    /// Local name (also the file name).
    pub name: String,
    /// Agent ID.
    pub agent_id: AgentId,
    /// Server URL.
    pub server: String,
    /// E-mail of the account the agent asked to join.
    pub email: String,
    /// The agent's public identity (kind `0x05`).
    pub public_identity: Blob,
    /// Where the private key is.
    pub key_store: KeyStore,
    /// Registration time (Unix ms).
    pub registered_at: i64,
    /// The account, once seen.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_id: Option<AccountId>,
    /// The account's public identity, pinned the first time (TOFU).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_public_identity: Option<Blob>,
    /// Highest grant version accepted (a lower one is a rollback).
    #[serde(default)]
    pub grant_version: u64,
}

/// Agent names: they become file names.
pub fn validate_name(name: &str) -> ClientResult<()> {
    let ok = (1..=64).contains(&name.len())
        && name
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_alphanumeric())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'));
    if ok {
        Ok(())
    } else {
        Err(ClientError::Invalid(format!(
            "invalid agent name {name:?}: use 1-64 letters, digits, '-', '_' or '.', starting with a letter or digit"
        )))
    }
}

/// `$KLAV_HOME/agents`.
pub fn agents_dir(home: &Home) -> PathBuf {
    home.dir().join("agents")
}

fn config_path(home: &Home, name: &str) -> PathBuf {
    agents_dir(home).join(format!("{name}.json"))
}

impl AgentConfig {
    /// A new config.
    pub(crate) fn new(
        name: &str,
        agent_id: AgentId,
        server: &str,
        email: &str,
        public_identity: Blob,
        key_store: KeyStore,
        registered_at: i64,
    ) -> Self {
        Self {
            v: CONFIG_VERSION,
            name: name.to_owned(),
            agent_id,
            server: server.to_owned(),
            email: email.to_owned(),
            public_identity,
            key_store,
            registered_at,
            account_id: None,
            account_public_identity: None,
            grant_version: 0,
        }
    }

    /// Whether `name` is already registered in `home`.
    pub fn exists(home: &Home, name: &str) -> bool {
        config_path(home, name).exists()
    }

    /// Loads the agent `name`.
    pub fn load(home: &Home, name: &str) -> ClientResult<Self> {
        validate_name(name)?;
        let path = config_path(home, name);
        let text = std::fs::read(&path).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => ClientError::NotFound(format!(
                "agent {name:?} in {}; run `klav agent register` first",
                agents_dir(home).display()
            )),
            _ => e.into(),
        })?;
        check_private(&path)?;
        let config: Self = serde_json::from_slice(&text)
            .map_err(|e| ClientError::Corrupt(format!("{}: {e}", path.display())))?;
        if config.v != CONFIG_VERSION {
            return Err(ClientError::Corrupt(format!(
                "{}: unsupported version",
                path.display()
            )));
        }
        Ok(config)
    }

    /// Saves the config (atomic, 0600).
    pub fn save(&self, home: &Home) -> ClientResult<()> {
        home.ensure()?;
        let dir = agents_dir(home);
        std::fs::create_dir_all(&dir)?;
        klav_client::home::set_mode(&dir, 0o700)?;
        let json = serde_json::to_vec_pretty(self)
            .map_err(|e| ClientError::Invalid(format!("agent config: {e}")))?;
        write_private(&config_path(home, &self.name), &json)
    }

    /// Removes the config.
    pub fn remove(&self, home: &Home) -> ClientResult<()> {
        std::fs::remove_file(config_path(home, &self.name))?;
        Ok(())
    }
}

/// Refuses a config other users may read or change: they could re-pin the
/// account or roll the grant version back.
fn check_private(path: &std::path::Path) -> ClientResult<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)?.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(ClientError::Security(format!(
                "{} can be read or changed by other users (mode {:o}): it pins the account and the grant version; run `chmod 600` on it",
                path.display(),
                mode & 0o777
            )));
        }
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// Names of the agents registered in `home`, sorted.
pub fn list(home: &Home) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(agents_dir(home))
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            e.file_name()
                .to_str()
                .and_then(|n| n.strip_suffix(".json"))
                .map(str::to_owned)
        })
        .filter(|n| validate_name(n).is_ok())
        .collect();
    names.sort();
    names
}

/// The agent to use: `wanted`, else `$KLAV_AGENT`, else the only one.
pub fn pick(home: &Home, wanted: Option<&str>) -> ClientResult<String> {
    if let Some(name) = wanted
        .map(str::to_owned)
        .or_else(|| std::env::var(AGENT_ENV).ok().filter(|n| !n.is_empty()))
    {
        return Ok(name);
    }
    let names = list(home);
    match names.as_slice() {
        [one] => Ok(one.clone()),
        [] => Err(ClientError::NotFound(
            "an agent on this device; run `klav agent register` first".into(),
        )),
        many => Err(ClientError::Ambiguous(format!(
            "several agents on this device ({}); choose one with --agent or {AGENT_ENV}",
            many.join(", ")
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn a_config_others_can_change_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let home = Home::at(dir.path());
        let config = AgentConfig::new(
            "bot",
            AgentId::generate(),
            "https://klav.example",
            "ana@example.com",
            Blob::new(vec![0; 4]),
            KeyStore::File {
                path: dir.path().join("bot.key"),
            },
            1,
        );
        config.save(&home).unwrap();
        assert!(AgentConfig::load(&home, "bot").is_ok());
        let path = config_path(&home, "bot");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(matches!(
            AgentConfig::load(&home, "bot"),
            Err(ClientError::Security(_))
        ));
    }

    #[test]
    fn names() {
        for good in ["claude-code", "a", "bot_1.prod"] {
            assert!(validate_name(good).is_ok(), "{good}");
        }
        for bad in ["", "-x", ".x", "a/b", "a b", "../x", &"x".repeat(65)] {
            assert!(validate_name(bad).is_err(), "{bad}");
        }
    }
}
