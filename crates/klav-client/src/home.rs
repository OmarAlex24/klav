//! The local state directory and safe file writes.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::error::ClientResult;

/// Environment variable that overrides the state directory.
pub const HOME_ENV: &str = "KLAV_HOME";

/// The directory holding one account's local state.
///
/// Default: `$KLAV_HOME`, else `~/Library/Application Support/klav` on
/// macOS and `$XDG_CONFIG_HOME/klav` (or `~/.config/klav`) elsewhere.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Home {
    dir: PathBuf,
}

impl Home {
    /// The directory from the environment (see the type docs).
    pub fn from_env() -> ClientResult<Self> {
        if let Some(dir) = std::env::var_os(HOME_ENV).filter(|d| !d.is_empty()) {
            return Ok(Self::at(PathBuf::from(dir)));
        }
        let home = std::env::var_os("HOME")
            .filter(|h| !h.is_empty())
            .map(PathBuf::from)
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "HOME is not set; set KLAV_HOME",
                )
            })?;
        let dir = if cfg!(target_os = "macos") {
            home.join("Library/Application Support/klav")
        } else {
            std::env::var_os("XDG_CONFIG_HOME")
                .filter(|d| !d.is_empty())
                .map(PathBuf::from)
                .unwrap_or_else(|| home.join(".config"))
                .join("klav")
        };
        Ok(Self::at(dir))
    }

    /// A specific directory.
    pub fn at(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// The directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Creates the directory with mode 0700 if needed.
    pub fn ensure(&self) -> ClientResult<()> {
        fs::create_dir_all(&self.dir)?;
        set_mode(&self.dir, 0o700)?;
        Ok(())
    }

    /// `account.json`.
    pub fn account_path(&self) -> PathBuf {
        self.dir.join("account.json")
    }

    /// `secret-key`.
    pub fn secret_key_path(&self) -> PathBuf {
        self.dir.join("secret-key")
    }

    /// `session.bin` (sealed tokens).
    pub fn session_path(&self) -> PathBuf {
        self.dir.join("session.bin")
    }

    /// `cache.bin` (sealed sync cache).
    pub fn cache_path(&self) -> PathBuf {
        self.dir.join("cache.bin")
    }

    /// Lock file that serialises token refreshes between processes.
    pub fn lock_path(&self) -> PathBuf {
        self.dir.join("session.lock")
    }

    /// Unix socket of `klavd`.
    pub fn socket_path(&self) -> PathBuf {
        self.dir.join("klavd.sock")
    }

    /// Any other file in the directory (e.g. the Touch ID enrolment).
    pub fn file(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    /// `true` if an account is set up here.
    pub fn has_account(&self) -> bool {
        self.account_path().exists()
    }

    /// Takes the inter-process lock (blocking).
    pub(crate) fn lock(&self) -> ClientResult<File> {
        self.ensure()?;
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(self.lock_path())?;
        set_mode(&self.lock_path(), 0o600)?;
        file.lock()?;
        Ok(file)
    }
}

/// Writes `bytes` to `path` atomically (temporary file in the same
/// directory, `fsync`, rename, `fsync` of the directory) with mode 0600, so
/// a crash never leaves a half-written file, a power cut does not bring
/// back the previous one (a spent refresh token, older marks: T7), and no
/// other user can read it. On Apple platforms `sync_all` is `F_FULLFSYNC`.
pub fn write_private(path: &Path, bytes: &[u8]) -> ClientResult<()> {
    write_atomic(path, |file| file.write_all(bytes))
}

/// Removes the temporary file unless it was renamed into place.
struct TmpGuard<'a>(Option<&'a Path>);

impl Drop for TmpGuard<'_> {
    fn drop(&mut self) {
        if let Some(path) = self.0 {
            let _ = fs::remove_file(path);
        }
    }
}

fn write_atomic(
    path: &Path,
    write: impl FnOnce(&mut File) -> std::io::Result<()>,
) -> ClientResult<()> {
    let dir = path
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let tmp = dir.join(format!(".{name}.{}.tmp", std::process::id()));
    let mut guard = TmpGuard(Some(&tmp));
    {
        let mut file = create_private(&tmp)?;
        write(&mut file)?;
        file.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    guard.0 = None;
    sync_dir(dir);
    Ok(())
}

/// Makes a rename in `dir` durable. Best effort: the file is already in
/// place, and some file systems refuse to sync a directory.
fn sync_dir(dir: &Path) {
    #[cfg(unix)]
    if let Ok(d) = File::open(dir) {
        let _ = d.sync_all();
    }
    #[cfg(not(unix))]
    let _ = dir;
}

/// Creates (truncating) a file that only the owner can read and write.
pub fn create_private(path: &Path) -> ClientResult<File> {
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(path)?;
    set_mode(path, 0o600)?;
    Ok(file)
}

/// Sets Unix permissions (no-op elsewhere).
pub fn set_mode(path: &Path, mode: u32) -> ClientResult<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    }
    #[cfg(not(unix))]
    let _ = (path, mode);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_files_are_0600_and_atomic() {
        let dir = tempfile::tempdir().unwrap();
        let home = Home::at(dir.path().join("h"));
        home.ensure().unwrap();
        let path = home.file("x");
        write_private(&path, b"one").unwrap();
        write_private(&path, b"two").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"two");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
            assert_eq!(
                fs::metadata(home.dir()).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
        // No temporary files left behind.
        assert_eq!(fs::read_dir(home.dir()).unwrap().count(), 1);
    }

    #[test]
    fn a_failed_write_leaves_no_temporary_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret-key");
        write_private(&path, b"old").unwrap();
        let err = write_atomic(&path, |f| {
            f.write_all(b"half")?;
            Err(std::io::Error::other("disk full"))
        });
        assert!(err.is_err());
        assert_eq!(fs::read(&path).unwrap(), b"old");
        let names: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, vec![std::ffi::OsString::from("secret-key")]);
    }
}
