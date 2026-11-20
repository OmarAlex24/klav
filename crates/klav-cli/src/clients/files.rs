//! Reading and writing client settings files safely (ADR 0033 §3.6, §4):
//! links followed but never replaced, only the user's own files outside
//! system directories, a backup before every change, and atomic writes that
//! keep the file's mode.

use std::path::{Path, PathBuf};

use klav_client::Home;

use super::{ClientId, Env};
use crate::error::{CliError, CliResult};

/// Backups kept per client file.
pub(crate) const KEEP_BACKUPS: usize = 5;

/// A settings file as the client names it and as Klav reads and writes it.
#[derive(Debug, Clone)]
pub(crate) struct Target {
    /// The path the client reads.
    pub(crate) path: PathBuf,
    /// The file behind it: `path`, or where its link points.
    pub(crate) real: PathBuf,
    /// Where `path` points when it is a symbolic link.
    pub(crate) link: Option<PathBuf>,
}

impl Target {
    /// Follows `path` if it is a link. A link to nothing is an error: Klav
    /// would have to create a file somewhere the person did not choose.
    pub(crate) fn resolve(path: &Path) -> CliResult<Self> {
        let is_link = std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink());
        if !is_link {
            return Ok(Self {
                path: path.to_path_buf(),
                real: path.to_path_buf(),
                link: None,
            });
        }
        let real = std::fs::canonicalize(path).map_err(|_| {
            CliError::Other(format!(
                "{} is a link to a file that does not exist; fix the link or remove it",
                path.display()
            ))
        })?;
        Ok(Self {
            path: path.to_path_buf(),
            link: Some(real.clone()),
            real,
        })
    }

    /// The file's bytes, `None` if it does not exist.
    pub(crate) fn read(&self) -> CliResult<Option<Vec<u8>>> {
        match std::fs::read(&self.real) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(CliError::Other(format!("{}: {e}", self.real.display()))),
        }
    }

    /// Why Klav must not write this file, if it must not (ADR 0033 §4):
    /// not a regular file, not the user's, in a system directory, or in a
    /// directory the user cannot write. Klav never asks for an
    /// administrator's password for a client's settings.
    pub(crate) fn refusal(&self, env: &Env) -> Option<String> {
        use std::os::unix::fs::MetadataExt;
        let shown = self.real.display();
        if env.is_system(&self.real) {
            return Some(format!(
                "{shown} is in a system directory; Klav only writes the user's own settings"
            ));
        }
        match std::fs::metadata(&self.real) {
            Ok(meta) => {
                if !meta.is_file() {
                    return Some(format!("{shown} is not a regular file"));
                }
                if meta.uid() != nix::unistd::geteuid().as_raw() {
                    return Some(format!(
                        "{shown} belongs to another user; Klav does not change it"
                    ));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Some(format!("{shown}: {e}")),
        }
        let dir = self.real.parent()?;
        if dir.is_dir()
            && nix::unistd::access(
                dir,
                nix::unistd::AccessFlags::W_OK | nix::unistd::AccessFlags::X_OK,
            )
            .is_err()
        {
            return Some(format!(
                "{} cannot be written by this user; Klav does not ask for an administrator's password",
                dir.display()
            ));
        }
        None
    }

    /// Warnings about where a linked file lives (ADR 0033 §4): a git
    /// repository keeps the change, and a dotfiles tool may undo it.
    pub(crate) fn link_warnings(&self, env: &Env) -> Vec<String> {
        let mut out = Vec::new();
        if self.link.is_none() {
            return out;
        }
        if let Some(repo) = self
            .real
            .ancestors()
            .skip(1)
            .find(|dir| dir.join(".git").exists())
        {
            out.push(format!(
                "{} is in the git repository {}: the change stays there",
                self.real.display(),
                repo.display()
            ));
        }
        out.extend(tool_warning(env));
        out
    }

    /// File mode to keep (0600 for a new file).
    pub(crate) fn mode(&self) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(&self.real).map_or(0o600, |m| m.permissions().mode() & 0o7777)
    }
}

/// chezmoi rewrites the files it manages from its templates; a change made
/// outside it is lost on its next apply.
fn tool_warning(env: &Env) -> Option<String> {
    env.home
        .join(".local/share/chezmoi")
        .is_dir()
        .then(|| {
            "chezmoi is set up here: if it manages this file, its next `chezmoi apply` undoes the change (change its template instead)".to_owned()
        })
}

/// Writes `bytes` to `path` through a temporary file in the same directory
/// and an atomic rename, with `mode`.
pub(crate) fn write_atomic(path: &Path, bytes: &[u8], mode: u32) -> CliResult<()> {
    use std::io::Write;
    let dir = path
        .parent()
        .ok_or_else(|| CliError::Other(format!("{} has no directory", path.display())))?;
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let tmp = dir.join(format!(".{name}.klav-{}.tmp", std::process::id()));
    let result = (|| -> CliResult<()> {
        let mut file = klav_client::home::create_private(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        klav_client::home::set_mode(&tmp, mode)?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// `$KLAV_HOME/client-backups/<client>`.
pub(crate) fn backup_dir(home: &Home, client: ClientId) -> PathBuf {
    home.dir().join("client-backups").join(client.id())
}

/// Copies the current `bytes` of a client file to its backups
/// (`<time>-<name>`, directory 0700, file 0600) and keeps the newest
/// [`KEEP_BACKUPS`]. The copy holds other programs' secrets as the original
/// does: it is never printed, synced or logged.
pub(crate) fn backup(
    home: &Home,
    client: ClientId,
    name: &str,
    bytes: &[u8],
) -> CliResult<PathBuf> {
    home.ensure()?;
    let root = home.dir().join("client-backups");
    let dir = backup_dir(home, client);
    std::fs::create_dir_all(&dir)?;
    klav_client::home::set_mode(&root, 0o700)?;
    klav_client::home::set_mode(&dir, 0o700)?;
    let mut now = crate::time::now_ms();
    let mut path = dir.join(format!("{}-{name}", crate::time::file_stamp(now)));
    while path.exists() {
        now += 1;
        path = dir.join(format!("{}-{name}", crate::time::file_stamp(now)));
    }
    klav_client::home::write_private(&path, bytes)?;
    let all = backups(home, client, name);
    if all.len() > KEEP_BACKUPS {
        for old in &all[..all.len() - KEEP_BACKUPS] {
            let _ = std::fs::remove_file(old);
        }
    }
    Ok(path)
}

/// The backups of one client file, oldest first.
pub(crate) fn backups(home: &Home, client: ClientId, name: &str) -> Vec<PathBuf> {
    let suffix = format!("-{name}");
    let mut found: Vec<PathBuf> = std::fs::read_dir(backup_dir(home, client))
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.ends_with(&suffix) && n.len() > suffix.len() + 15)
        })
        .collect();
    found.sort();
    found
}

/// The file name backups of a client file use.
pub(crate) fn backup_name(path: &Path) -> String {
    path.file_name()
        .map_or_else(|| "settings".into(), |n| n.to_string_lossy().into_owned())
}

/// The name of what `klav client restore` replaced: kept apart from the
/// backups (and pruned to its own [`KEEP_BACKUPS`]), so a second restore
/// never brings back what the first one undid.
pub(crate) fn replaced_name(path: &Path) -> String {
    format!("{}.before-restore", backup_name(path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backups_keep_the_newest_five() {
        let root = tempfile::tempdir().expect("tempdir");
        let home = Home::at(root.path().join("klav"));
        for i in 0..7u8 {
            backup(&home, ClientId::Cursor, "mcp.json", &[i]).expect("backup");
        }
        let all = backups(&home, ClientId::Cursor, "mcp.json");
        assert_eq!(all.len(), KEEP_BACKUPS);
        assert_eq!(std::fs::read(all.last().expect("last")).expect("read"), [6]);
        assert_eq!(std::fs::read(&all[0]).expect("read"), [2]);
        assert_eq!(crate::tests_support::mode(&all[0]), 0o600);
        assert_eq!(
            crate::tests_support::mode(&backup_dir(&home, ClientId::Cursor)),
            0o700
        );
        // Another file of the same client keeps its own five, and so does
        // what `restore` replaced.
        backup(&home, ClientId::Cursor, "other.json", b"x").expect("backup");
        let replaced = replaced_name(Path::new("/h/.cursor/mcp.json"));
        backup(&home, ClientId::Cursor, &replaced, b"y").expect("backup");
        assert_eq!(backups(&home, ClientId::Cursor, "mcp.json").len(), 5);
        assert_eq!(backups(&home, ClientId::Cursor, "other.json").len(), 1);
        assert_eq!(backups(&home, ClientId::Cursor, &replaced).len(), 1);
    }

    #[test]
    fn writes_keep_the_mode_and_leave_no_temporary_file() {
        let root = tempfile::tempdir().expect("tempdir");
        let path = root.path().join("mcp.json");
        std::fs::write(&path, b"{}").expect("write");
        klav_client::home::set_mode(&path, 0o640).expect("mode");
        let target = Target::resolve(&path).expect("resolve");
        write_atomic(&target.real, b"{ }", target.mode()).expect("write");
        assert_eq!(std::fs::read(&path).expect("read"), b"{ }");
        assert_eq!(crate::tests_support::mode(&path), 0o640);
        assert_eq!(std::fs::read_dir(root.path()).expect("dir").count(), 1);
    }

    #[test]
    fn links_are_followed_and_dangling_ones_refused() {
        let root = tempfile::tempdir().expect("tempdir");
        let real = root.path().join("dotfiles/mcp.json");
        std::fs::create_dir_all(real.parent().expect("dir")).expect("dir");
        std::fs::create_dir_all(root.path().join("dotfiles/.git")).expect("git");
        std::fs::write(&real, b"{}").expect("write");
        let link = root.path().join("mcp.json");
        std::os::unix::fs::symlink(&real, &link).expect("link");
        let target = Target::resolve(&link).expect("resolve");
        assert_eq!(
            target.link.as_deref(),
            Some(std::fs::canonicalize(&real).expect("real").as_path())
        );
        let env = Env {
            home: root.path().join("home"),
            codex_home: root.path().join("home/.codex"),
            claude_dir: None,
            root: root.path().join("system"),
            path: None,
        };
        let warnings = target.link_warnings(&env);
        assert!(warnings[0].contains("git repository"), "{warnings:?}");
        std::fs::remove_file(&real).expect("rm");
        assert!(Target::resolve(&link).is_err());
    }
}
