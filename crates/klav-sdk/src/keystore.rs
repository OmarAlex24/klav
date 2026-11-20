//! Where the agent keeps its private key (design §5.1):
//!
//! * **Keychain** (macOS): a generic password of the login keychain,
//!   service `dev.klav.agent`, account = agent ID.
//! * **File**: the text form (`kag1_…`, spec §13.2) in a file with mode
//!   0600, by default `$KLAV_HOME/agents/<name>.key`.
//! * **`KLAV_AGENT_KEY`**: when set, it overrides the stored key (servers,
//!   containers, a cloud KMS that injects the variable).
//!
//! The key is never printed, logged or passed in argv.

use std::path::{Path, PathBuf};

use klav_client::home::write_private;
use klav_client::{ClientError, ClientResult, Home};
use klav_core::crypto::agent::{decode_agent_secret, encode_agent_secret};
use klav_core::crypto::identity::IdentityKeyPair;
use klav_core::ids::AgentId;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::config::agents_dir;

/// Environment variable with the agent key (text form).
pub const KEY_ENV: &str = "KLAV_AGENT_KEY";
/// Keychain service of agent keys.
pub const KEYCHAIN_SERVICE: &str = "dev.klav.agent";

/// Where an agent key is stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum KeyStore {
    /// macOS login keychain.
    Keychain,
    /// A 0600 file.
    File {
        /// Its path.
        path: PathBuf,
    },
}

/// What `klav agent register --key-store` asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyStoreChoice {
    /// The keychain on macOS when available, else a file.
    Auto,
    /// The keychain (fails where there is none).
    Keychain,
    /// A file.
    File,
}

impl KeyStore {
    /// Resolves a choice for the agent `name`. `file` overrides the default
    /// path of file stores.
    pub fn choose(
        home: &Home,
        name: &str,
        choice: KeyStoreChoice,
        file: Option<&Path>,
    ) -> ClientResult<Self> {
        let file_store = || KeyStore::File {
            path: file.map_or_else(
                || agents_dir(home).join(format!("{name}.key")),
                Path::to_path_buf,
            ),
        };
        match choice {
            KeyStoreChoice::File => Ok(file_store()),
            KeyStoreChoice::Keychain if klav_touchid::compiled_in() => Ok(KeyStore::Keychain),
            KeyStoreChoice::Keychain => Err(ClientError::Invalid(
                "the keychain is only available on macOS builds with the Swift shim; use --key-store file".into(),
            )),
            KeyStoreChoice::Auto if file.is_none() && klav_touchid::compiled_in() => {
                Ok(KeyStore::Keychain)
            }
            KeyStoreChoice::Auto => Ok(file_store()),
        }
    }

    /// Human-readable location.
    pub fn describe(&self) -> String {
        match self {
            KeyStore::Keychain => format!("macOS keychain (service {KEYCHAIN_SERVICE})"),
            KeyStore::File { path } => format!("file {} (0600)", path.display()),
        }
    }

    /// Stores the key.
    pub fn save(&self, home: &Home, agent: AgentId, keys: &IdentityKeyPair) -> ClientResult<()> {
        let text = encode_agent_secret(keys);
        match self {
            KeyStore::Keychain => {
                klav_touchid::keychain_store(KEYCHAIN_SERVICE, &agent.to_string(), text.as_bytes())
                    .map_err(|e| {
                        ClientError::Invalid(format!(
                            "cannot store the agent key in the keychain ({e}); use --key-store file"
                        ))
                    })
            }
            KeyStore::File { path } => {
                home.ensure()?;
                if let Some(dir) = path.parent() {
                    std::fs::create_dir_all(dir)?;
                }
                let mut line = Zeroizing::new(text.as_bytes().to_vec());
                line.push(b'\n');
                write_private(path, &line)
            }
        }
    }

    /// Loads the key: `KLAV_AGENT_KEY` if set, else the store.
    pub fn load(&self, agent: AgentId) -> ClientResult<IdentityKeyPair> {
        if let Some(text) = std::env::var_os(KEY_ENV).filter(|v| !v.is_empty()) {
            let text = Zeroizing::new(text.to_string_lossy().into_owned());
            return decode_agent_secret(&text)
                .map_err(|e| ClientError::Invalid(format!("{KEY_ENV}: {e}")));
        }
        let text = match self {
            KeyStore::Keychain => {
                let bytes = klav_touchid::keychain_load(KEYCHAIN_SERVICE, &agent.to_string())
                    .map_err(|e| {
                        ClientError::NotFound(format!("the agent key in the keychain ({e})"))
                    })?;
                Zeroizing::new(String::from_utf8_lossy(&bytes).into_owned())
            }
            KeyStore::File { path } => {
                check_private(path)?;
                Zeroizing::new(std::fs::read_to_string(path).map_err(|e| {
                    ClientError::NotFound(format!("agent key {}: {e}", path.display()))
                })?)
            }
        };
        decode_agent_secret(&text).map_err(ClientError::from)
    }

    /// Deletes the stored key (the environment variable is not touched).
    pub fn delete(&self, agent: AgentId) -> ClientResult<()> {
        match self {
            KeyStore::Keychain => {
                klav_touchid::keychain_delete(KEYCHAIN_SERVICE, &agent.to_string())
                    .map_err(|e| ClientError::Invalid(format!("keychain: {e}")))
            }
            KeyStore::File { path } => match std::fs::remove_file(path) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(e.into()),
            },
        }
    }
}

/// Refuses key files that other users can read.
fn check_private(path: &Path) -> ClientResult<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)
            .map_err(|e| ClientError::NotFound(format!("agent key {}: {e}", path.display())))?
            .permissions()
            .mode();
        if mode & 0o077 != 0 {
            return Err(ClientError::Invalid(format!(
                "agent key {} is readable by other users (mode {:o}); run `chmod 600` on it",
                path.display(),
                mode & 0o777
            )));
        }
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_store_roundtrip_and_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let home = Home::at(dir.path().join("home"));
        let store = KeyStore::choose(&home, "bot", KeyStoreChoice::File, None).unwrap();
        let keys = IdentityKeyPair::generate();
        let id = AgentId::generate();
        store.save(&home, id, &keys).unwrap();
        assert_eq!(store.load(id).unwrap().public(), keys.public());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let KeyStore::File { path } = &store else {
                unreachable!()
            };
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(store.load(id).is_err());
        }
        store.delete(id).unwrap();
        store.delete(id).unwrap();
    }
}
