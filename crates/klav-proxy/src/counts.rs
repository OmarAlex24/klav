//! What the redactor counted per profile since the proxy started (T149,
//! ADR 0036 E9): how many times it replaced the whole injected value, and
//! how many pieces of it it found and left as they are. Only numbers,
//! never what matched. The caller never sees any of it: the counts live
//! in memory and in a 0600 file that `klav-proxy status` reads, written
//! by a task of its own so no answer waits for the disk.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::Notify;

/// The file's extension, next to the agent's registration.
pub const COUNTS_EXTENSION: &str = "redactions";
const COUNTS_VERSION: u32 = 1;
/// Writes of the file are at least this far apart: a burst of answers is
/// one write.
const WRITE_EVERY: Duration = Duration::from_secs(1);

/// One profile's counts.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileCounts {
    /// Times the whole value (or an encoding of it) was replaced.
    pub redacted: u64,
    /// Pieces of the value (12 characters or more) left as they are.
    pub partial: u64,
}

/// The counts as `status` shows them.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CountsView {
    /// When the proxy that wrote them started (Unix ms).
    pub since: i64,
    /// Per profile, only those with something counted.
    pub profiles: BTreeMap<String, ProfileCounts>,
}

#[derive(Serialize, Deserialize)]
struct CountsFile {
    v: u32,
    #[serde(flatten)]
    view: CountsView,
}

/// The counts of a running proxy.
pub struct Counts {
    view: Mutex<CountsView>,
    changed: Notify,
    path: Option<PathBuf>,
}

impl Counts {
    /// Counts kept only in memory (tests, and a proxy without a home).
    pub fn in_memory() -> Self {
        Self {
            view: Mutex::new(CountsView::default()),
            changed: Notify::new(),
            path: None,
        }
    }

    /// Counts from `since`, written to `path` (replacing what a previous
    /// run left there) once now and then after each change.
    pub fn at(path: PathBuf, since: i64) -> Result<Self, String> {
        let counts = Self {
            view: Mutex::new(CountsView {
                since,
                profiles: BTreeMap::new(),
            }),
            changed: Notify::new(),
            path: Some(path),
        };
        counts.write()?;
        Ok(counts)
    }

    /// Where `status` looks for the counts of agent `name`.
    pub fn path_in(home: &klav_client::Home, name: &str) -> PathBuf {
        home.dir()
            .join("agents")
            .join(format!("{name}.{COUNTS_EXTENSION}"))
    }

    /// Adds one answer's counts and returns the profile's totals. It only
    /// touches memory; the writer task saves it later.
    pub fn add(&self, profile: &str, redacted: u64, partial: u64) -> ProfileCounts {
        let total = {
            let mut view = self.view.lock().unwrap_or_else(|e| e.into_inner());
            let total = view.profiles.entry(profile.to_owned()).or_default();
            total.redacted += redacted;
            total.partial += partial;
            *total
        };
        self.changed.notify_one();
        total
    }

    /// One profile's totals.
    pub fn get(&self, profile: &str) -> ProfileCounts {
        self.view
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .profiles
            .get(profile)
            .copied()
            .unwrap_or_default()
    }

    /// Saves the counts after each change, at most once a [`WRITE_EVERY`],
    /// until aborted.
    pub async fn write_on_change(self: std::sync::Arc<Self>) {
        loop {
            self.changed.notified().await;
            let counts = std::sync::Arc::clone(&self);
            let written = tokio::task::spawn_blocking(move || counts.write()).await;
            if let Ok(Err(e)) = written {
                tracing::warn!(error = %e, "could not save the redaction counts");
            }
            tokio::time::sleep(WRITE_EVERY).await;
        }
    }

    /// Writes the file now (0600, replaced atomically).
    pub fn write(&self) -> Result<(), String> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let view = self.view.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let bytes = serde_json::to_vec(&CountsFile {
            v: COUNTS_VERSION,
            view,
        })
        .map_err(|e| e.to_string())?;
        klav_client::home::write_private(path, &bytes).map_err(|e| e.to_string())
    }

    /// The counts a proxy left at `path`, if it ever wrote them.
    pub fn read(path: &Path) -> Result<Option<CountsView>, String> {
        let bytes = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.to_string()),
        };
        let file: CountsFile = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
        if file.v != COUNTS_VERSION {
            return Err(format!("unknown version {}", file.v));
        }
        Ok(Some(file.view))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_counts_survive_a_write_and_a_read() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("p.redactions");
        let counts = Counts::at(path.clone(), 42).expect("counts");
        assert_eq!(
            Counts::read(&path).expect("read"),
            Some(CountsView {
                since: 42,
                profiles: BTreeMap::new()
            })
        );
        assert_eq!(
            counts.add("up", 1, 0),
            ProfileCounts {
                redacted: 1,
                partial: 0
            }
        );
        counts.add("up", 0, 3);
        counts.write().expect("write");
        let view = Counts::read(&path).expect("read").expect("some");
        assert_eq!(
            view.profiles["up"],
            ProfileCounts {
                redacted: 1,
                partial: 3
            }
        );
        assert_eq!(Counts::read(&dir.path().join("none")).expect("read"), None);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).expect("meta").permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }
}
