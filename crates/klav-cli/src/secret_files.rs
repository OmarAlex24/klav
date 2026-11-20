//! Secret files written by `klav run` (`[files]`), `klav inject` and
//! `klav agent inject` (`klav_sdk::secret_file` writes them): removed on
//! exit, TTL or signal, and a warning when git would not ignore them
//! (threat T35).

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::error::{CliError, CliResult, usage};
use crate::output;

/// Writes `content` to a new 0600 file at `path` that never shows partly
/// written under its name, with `klav_sdk`'s writer
/// ([`klav_sdk::secret_file::write_secret_file`]): a hard link from a
/// temporary `.<name>.<16 hex>.klav-tmp`, never replacing what is there;
/// with `force`, a rename over it.
pub(crate) fn write_new_private(path: &Path, content: &[u8], force: bool) -> CliResult<()> {
    klav_sdk::secret_file::write_secret_file(path, content, force).map_err(cli_error)
}

/// A failure about the path (taken, a missing directory, not replaceable)
/// is a usage error (exit 2); one writing the content (a full disk) is not
/// (exit 1).
fn cli_error(e: klav_sdk::secret_file::SecretFileError) -> CliError {
    exit_for(e.is_write(), e.message(" (use --force to replace it)"))
}

fn exit_for(write: bool, message: String) -> CliError {
    if write {
        CliError::Other(message)
    } else {
        usage(message)
    }
}

/// Warns on stderr about each of `paths`' leftover temporary files
/// ([`klav_sdk::secret_file::leftover_warnings`]), after a write to them,
/// whatever its outcome: `failure` is its error message, if it failed.
/// Never deletes one, and never changes the outcome.
pub(crate) fn warn_leftovers(paths: &[&Path], failure: Option<&str>) {
    for warning in klav_sdk::secret_file::leftover_warnings(paths, failure) {
        output::warn(&warning);
    }
}

/// Files to remove when the command ends, however it ends (short of
/// SIGKILL or a power cut).
#[derive(Default)]
pub(crate) struct Cleanup {
    paths: Vec<PathBuf>,
}

impl Cleanup {
    pub(crate) fn add(&mut self, path: PathBuf) {
        self.paths.push(path);
    }

    pub(crate) fn forget(&mut self, path: &Path) {
        self.paths.retain(|p| p != path);
    }

    pub(crate) fn remove_all(&mut self) {
        for path in self.paths.drain(..) {
            match std::fs::remove_file(&path) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => output::warn(&format!("could not remove {}: {e}", path.display())),
            }
        }
    }
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        self.remove_all();
    }
}

/// Warns if `path`, a file [`write_new_private`] wrote, is inside a git
/// work tree and not ignored. The advice names `*.klav-tmp` too: a
/// `SIGKILL` or a power cut during the write can leave the temporary file
/// beside `path`, and the rule for `path` does not cover it. Silent when
/// git is missing or the path is not in a repository.
pub(crate) fn warn_if_not_ignored(path: &Path) {
    if let Some(warning) = not_ignored_warning(path) {
        output::warn(&warning);
    }
}

/// The same warning as [`warn_if_not_ignored`], as text: for a file
/// `klav agent inject` wrote (`klav mcp` puts it in the tool's JSON).
pub(crate) fn not_ignored_warning(path: &Path) -> Option<String> {
    is_not_ignored(path).then(|| {
        format!(
            "{} is not in .gitignore: add it, and *.klav-tmp, so the secret is never committed",
            path.display()
        )
    })
}

/// The `warning` of the MCP `inject_file` after its write: the git advice
/// ([`not_ignored_warning`]) and the leftover temporaries of `path`
/// ([`klav_sdk::secret_file::leftover_warnings`]). When both apply, the
/// git advice ends with a full stop and a space before the other (neither
/// text ends with one). `None` when neither does.
pub(crate) fn inject_file_warning(path: &Path) -> Option<String> {
    let git = not_ignored_warning(path);
    let leftovers = klav_sdk::secret_file::leftover_warnings(&[path], None);
    let leftovers = (!leftovers.is_empty()).then(|| leftovers.join(" "));
    match (git, leftovers) {
        (Some(git), Some(left)) => Some(format!("{git}. {left}")),
        (git, left) => git.or(left),
    }
}

/// Whether `path` is inside a git work tree and not ignored: false when
/// git is missing or the path is not in a repository.
fn is_not_ignored(path: &Path) -> bool {
    let Some(dir) = path.parent() else {
        return false;
    };
    let dir = if dir.as_os_str().is_empty() {
        Path::new(".")
    } else {
        dir
    };
    let status = Command::new("git")
        .arg("-C")
        .arg(dir)
        .arg("check-ignore")
        .arg("-q")
        .arg("--")
        .arg(path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    // 0: ignored; 1: not ignored; 128: not a repository (or other error).
    matches!(status, Ok(status) if status.code() == Some(1))
}

/// Signals that end a `klav` command waiting in the foreground.
pub(crate) struct Signals {
    int: tokio::signal::unix::Signal,
    term: tokio::signal::unix::Signal,
    hup: tokio::signal::unix::Signal,
}

impl Signals {
    pub(crate) fn new() -> CliResult<Self> {
        use tokio::signal::unix::{SignalKind, signal};
        Ok(Self {
            int: signal(SignalKind::interrupt())?,
            term: signal(SignalKind::terminate())?,
            hup: signal(SignalKind::hangup())?,
        })
    }

    /// The next signal received.
    pub(crate) async fn recv(&mut self) -> nix::sys::signal::Signal {
        use nix::sys::signal::Signal;
        tokio::select! {
            _ = self.int.recv() => Signal::SIGINT,
            _ = self.term.recv() => Signal::SIGTERM,
            _ = self.hup.recv() => Signal::SIGHUP,
        }
    }
}

/// `90s`, `10m`, `1h` for messages.
pub(crate) fn human(duration: std::time::Duration) -> String {
    let secs = duration.as_secs();
    if secs.is_multiple_of(3600) {
        format!("{}h", secs / 3600)
    } else if secs.is_multiple_of(60) {
        format!("{}m", secs / 60)
    } else {
        format!("{secs}s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Which writer errors are wrong usage (exit 2), with the `--force`
    /// hint where the path was taken, and which are not (exit 1).
    #[test]
    fn only_a_failure_about_the_path_is_a_usage_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("secret.key");
        std::fs::write(&path, b"before").expect("before");
        match write_new_private(&path, b"after", false) {
            Err(CliError::Usage(m)) => assert_eq!(
                m,
                format!(
                    "{} already exists (use --force to replace it)",
                    path.display()
                )
            ),
            other => panic!("expected a usage error, got {other:?}"),
        }
        let missing = dir.path().join("missing").join("secret.key");
        match write_new_private(&missing, b"after", false) {
            Err(CliError::Usage(m)) => assert!(
                m.starts_with(&format!("cannot create {}: ", missing.display())),
                "{m}"
            ),
            other => panic!("expected a usage error, got {other:?}"),
        }
        let taken = dir.path().join("taken");
        std::fs::create_dir(&taken).expect("dir");
        std::fs::write(taken.join("inside"), b"x").expect("inside");
        match write_new_private(&taken, b"after", true) {
            Err(CliError::Usage(m)) => assert!(
                m.starts_with(&format!("cannot replace {}: ", taken.display())),
                "{m}"
            ),
            other => panic!("expected a usage error, got {other:?}"),
        }

        // A write that fails (a full disk) is not wrong usage. The CLI
        // cannot make the writer's own write fail, so this checks the
        // mapping; `klav_sdk`'s `a_failed_write_is_told_apart_from_the_path`
        // checks that such a failure is `is_write`.
        assert!(matches!(
            exit_for(true, "cannot write".into()),
            CliError::Other(_)
        ));
        assert!(matches!(
            exit_for(false, "cannot create".into()),
            CliError::Usage(_)
        ));
    }

    /// `inject_file`'s `warning`: only the git advice, only a leftover,
    /// both (a full stop and a space between), or none.
    #[test]
    fn the_inject_file_warning_says_git_leftovers_or_both() {
        let dir = tempfile::tempdir().expect("tempdir");
        let repo = dir.path().join("repo");
        std::fs::create_dir(&repo).expect("repo");
        let git = Command::new("git")
            .args(["init", "-q"])
            .arg(&repo)
            .status()
            .expect("git");
        assert!(git.success());
        let leftover = |dest: &Path| {
            let left = dest.parent().expect("dir").join(format!(
                ".{}.0123456789abcdef.klav-tmp",
                dest.file_name().expect("name").to_string_lossy()
            ));
            std::fs::write(&left, b"x").expect("leftover");
            left
        };

        let tracked = repo.join("tracked.env");
        std::fs::write(&tracked, b"x").expect("file");
        let only_git = inject_file_warning(&tracked).expect("git advice");
        assert!(only_git.contains("is not in .gitignore"), "{only_git}");
        assert!(!only_git.contains("Klav did not delete"), "{only_git}");

        let outside = dir.path().join("outside.env");
        std::fs::write(&outside, b"x").expect("file");
        assert_eq!(inject_file_warning(&outside), None);
        let left = leftover(&outside);
        let only_left = inject_file_warning(&outside).expect("leftover");
        assert!(
            only_left.starts_with(&left.display().to_string())
                && only_left.contains("Klav did not delete it")
                && !only_left.contains(".gitignore"),
            "{only_left}"
        );

        let left = leftover(&tracked);
        let both = inject_file_warning(&tracked).expect("both");
        assert!(
            both.starts_with(&only_git)
                && both.contains(&format!("never committed. {}", left.display()))
                && both.contains("Klav did not delete it"),
            "{both}"
        );
        assert!(left.exists());
    }
}
