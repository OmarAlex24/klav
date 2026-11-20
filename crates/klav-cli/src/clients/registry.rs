//! `$KLAV_HOME/clients.json` (0600): what Klav wrote in each client and
//! which skill copies are Klav's (ADR 0033 §3.4). «It is Klav's» is decided
//! here, never by a mark inside a client's file. It never leaves the Mac.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use klav_client::Home;
use serde::{Deserialize, Serialize};

use crate::error::{CliError, CliResult};

const FILE: &str = "clients.json";
/// Held from loading `clients.json` to saving it (see [`Registry::lock`]).
const LOCK: &str = "clients.lock";
/// How long a run waits for another one to let go of [`LOCK`].
const LOCK_WAIT: Duration = Duration::from_secs(5);
const VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Registry {
    pub(crate) v: u32,
    /// By client ID.
    #[serde(default)]
    pub(crate) clients: BTreeMap<String, ClientRecord>,
    /// One per skill folder Klav wrote.
    #[serde(default)]
    pub(crate) skills: Vec<SkillRecord>,
}

/// How Klav wrote an entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Method {
    /// With the client's own CLI (`claude mcp add`, `codex mcp add`).
    Cli,
    /// With a minimal edit of the file.
    File,
}

/// The `klav` entry Klav wrote in a client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ClientRecord {
    /// The agent the entry runs as.
    pub(crate) agent: String,
    /// The settings file, as the client names it.
    pub(crate) file: PathBuf,
    /// `mcpServers.klav` or `mcp_servers.klav`.
    pub(crate) key: String,
    pub(crate) method: Method,
    /// SHA-256 of the entry as read back after writing.
    pub(crate) entry_sha256: String,
    /// SHA-256 of the whole file after writing.
    pub(crate) file_sha256: String,
    /// When (Unix ms).
    pub(crate) at: i64,
}

/// A skill copy Klav wrote.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SkillRecord {
    /// `…/klav/SKILL.md`.
    pub(crate) path: PathBuf,
    /// SHA-256 of what Klav wrote.
    pub(crate) sha256: String,
    /// Its `metadata.klav-skill-version`.
    pub(crate) version: String,
    /// When (Unix ms).
    pub(crate) at: i64,
    /// The person kept their edited copy instead of this version of the
    /// skill: not asked again until a newer one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) kept_mine: Option<String>,
}

impl Default for Registry {
    fn default() -> Self {
        Self {
            v: VERSION,
            clients: BTreeMap::new(),
            skills: Vec::new(),
        }
    }
}

impl Registry {
    pub(crate) fn path(home: &Home) -> PathBuf {
        home.dir().join(FILE)
    }

    /// Takes `$KLAV_HOME/clients.lock` until the returned file is dropped,
    /// so two `klav client` or `klav skill` runs never change a client
    /// between the other's load and save of `clients.json`. Its own file:
    /// `session.lock` is taken while refreshing a session.
    ///
    /// Never waits for long: the app runs `klav skill update --json` when
    /// it starts, and must not hang behind a run that is asking the person
    /// something. Holders take it only to write, never while asking or
    /// while reading the server, except for an agent's registration, whose
    /// requests have a time limit (`klav_client::api::http_client`). After
    /// [`LOCK_WAIT`], a clear error.
    pub(crate) fn lock(home: &Home) -> CliResult<std::fs::File> {
        Self::lock_within(home, LOCK_WAIT)
    }

    pub(crate) fn lock_within(home: &Home, wait: Duration) -> CliResult<std::fs::File> {
        home.ensure()?;
        let path = home.dir().join(LOCK);
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&path)
            .map_err(|e| CliError::Other(format!("{}: {e}", path.display())))?;
        klav_client::home::set_mode(&path, 0o600)?;
        let deadline = Instant::now() + wait;
        loop {
            match file.try_lock() {
                Ok(()) => return Ok(file),
                Err(std::fs::TryLockError::WouldBlock) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(100));
                }
                Err(std::fs::TryLockError::WouldBlock) => {
                    return Err(CliError::Other(format!(
                        "another `klav client` or `klav skill` is running (it holds {}): try again once it ends",
                        path.display()
                    )));
                }
                Err(std::fs::TryLockError::Error(e)) => {
                    return Err(CliError::Other(format!("{}: {e}", path.display())));
                }
            }
        }
    }

    /// Loads it (empty if there is none yet).
    pub(crate) fn load(home: &Home) -> CliResult<Self> {
        let path = Self::path(home);
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(e) => return Err(CliError::Other(format!("{}: {e}", path.display()))),
        };
        let registry: Self = serde_json::from_slice(&bytes)
            .map_err(|e| CliError::Other(format!("{}: {e}", path.display())))?;
        if registry.v != VERSION {
            return Err(CliError::Other(format!(
                "{}: unsupported version {}",
                path.display(),
                registry.v
            )));
        }
        Ok(registry)
    }

    /// Saves it atomically with mode 0600.
    pub(crate) fn save(&self, home: &Home) -> CliResult<()> {
        home.ensure()?;
        let json = serde_json::to_vec_pretty(self).map_err(|e| CliError::Other(e.to_string()))?;
        klav_client::home::write_private(&Self::path(home), &json)?;
        Ok(())
    }

    pub(crate) fn skill(&self, path: &Path) -> Option<&SkillRecord> {
        self.skills.iter().find(|s| s.path == path)
    }

    pub(crate) fn skill_mut(&mut self, path: &Path) -> Option<&mut SkillRecord> {
        self.skills.iter_mut().find(|s| s.path == path)
    }

    /// Records (or re-records) a copy Klav just wrote.
    pub(crate) fn wrote_skill(&mut self, path: &Path, sha256: String, version: &str) {
        self.forget_skill(path);
        self.skills.push(SkillRecord {
            path: path.to_path_buf(),
            sha256,
            version: version.to_owned(),
            at: crate::time::now_ms(),
            kept_mine: None,
        });
    }

    pub(crate) fn forget_skill(&mut self, path: &Path) {
        self.skills.retain(|s| s.path != path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_lock_is_held_until_dropped_and_never_waited_on_for_long() {
        let root = tempfile::tempdir().expect("tempdir");
        let home = Home::at(root.path().join("klav"));
        let held = Registry::lock(&home).expect("lock");
        let path = home.dir().join(LOCK);
        assert_eq!(crate::tests_support::mode(&path), 0o600);
        let other = std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("open");
        assert!(other.try_lock().is_err(), "a second run waits");
        // A second run gives up with a clear message instead of hanging.
        let started = Instant::now();
        let err =
            Registry::lock_within(&home, Duration::from_millis(300)).expect_err("held elsewhere");
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(
            err.message()
                .is_some_and(|m| m.contains("another `klav client`")),
            "{err:?}"
        );
        drop(held);
        other.try_lock().expect("free once dropped");
    }
}
