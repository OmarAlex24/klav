//! Secret files written for a command or an agent (threat T35): `klav
//! inject -o`, the `[files]` of `klav run`, [`crate::actions::inject_file`]
//! and [`crate::actions::run`], and `klav sandbox start --package-file`.
//!
//! [`write_secret_file`] writes a new 0600 file that never exists under its
//! name with fewer bytes than its content: a reader that waits for the
//! name sees the whole file or nothing.
//!
//! A run killed during a write (`SIGKILL`, a power cut) can leave its
//! temporary file behind, and another write of the same name may be in
//! progress. [`leftover_warnings`] reports the temporaries of the same
//! final name after a write; Klav never deletes, opens or reads one.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

/// Why [`write_secret_file`] wrote nothing under the name. It names paths
/// and the system's error, never the content.
#[derive(Debug)]
pub struct SecretFileError {
    path: PathBuf,
    failure: Failure,
    /// The temporary file, if it could not be removed, and why.
    leftover: Option<(PathBuf, std::io::Error)>,
}

#[derive(Debug)]
enum Failure {
    /// Something is at the path (a file, a symlink, even a dangling one,
    /// or a pipe), and it was left as it was.
    Exists,
    /// The file could not be created, or could not take its name.
    Create(std::io::Error),
    /// The content could not be written or synced (a full disk, a quota):
    /// not a problem with the path.
    Write(std::io::Error),
    /// What was at the path could not be replaced.
    Replace(std::io::Error),
}

impl SecretFileError {
    fn new(path: &Path, failure: Failure) -> Self {
        Self {
            path: path.to_owned(),
            failure,
            leftover: None,
        }
    }

    /// Whether the path was taken, and left as it was.
    pub fn already_exists(&self) -> bool {
        matches!(self.failure, Failure::Exists)
    }

    /// Whether writing or syncing the content failed (a full disk, a
    /// quota), rather than something about the path.
    pub fn is_write(&self) -> bool {
        matches!(self.failure, Failure::Write(_))
    }

    /// The system's error, for a caller that names the path itself; `None`
    /// when the path was taken.
    pub fn io_error(&self) -> Option<&std::io::Error> {
        match &self.failure {
            Failure::Exists => None,
            Failure::Create(e) | Failure::Write(e) | Failure::Replace(e) => Some(e),
        }
    }

    /// "; the temporary file … could not be removed: …" when the temporary
    /// file (0600, with the secret) stayed, or nothing. [`Self::message`]
    /// ends with it.
    pub fn leftover_note(&self) -> String {
        self.leftover
            .as_ref()
            .map(|(temp, e)| {
                format!(
                    "; the temporary file {} (0600, with the secret) could not be removed: {e}",
                    temp.display()
                )
            })
            .unwrap_or_default()
    }

    /// The message, with `exists_hint` after "… already exists" (for
    /// example how the command replaces a file).
    pub fn message(&self, exists_hint: &str) -> String {
        let path = self.path.display();
        let mut text = match &self.failure {
            Failure::Exists => format!("{path} already exists{exists_hint}"),
            Failure::Create(e) => format!("cannot create {path}: {e}"),
            Failure::Write(e) => format!("cannot write {path}: {e}"),
            Failure::Replace(e) => format!("cannot replace {path}: {e}"),
        };
        text.push_str(&self.leftover_note());
        text
    }
}

impl std::fmt::Display for SecretFileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message(""))
    }
}

impl std::error::Error for SecretFileError {}

impl From<SecretFileError> for klav_client::ClientError {
    fn from(e: SecretFileError) -> Self {
        Self::Invalid(e.to_string())
    }
}

/// Writes `content` to a new 0600 file at `path`, which never exists with
/// fewer bytes than `content`: [`SecretFile::create`], then
/// [`SecretFile::write`].
pub fn write_secret_file(
    path: &Path,
    content: &[u8],
    replace: bool,
) -> Result<(), SecretFileError> {
    SecretFile::create(path, replace)?.write(content)
}

/// [`write_secret_file`] with the hard link as a parameter, so a test can
/// stand in for a file system without hard links.
#[cfg(test)]
fn write_with(
    path: &Path,
    content: &[u8],
    replace: bool,
    link: impl Fn(&Path, &Path) -> std::io::Result<()>,
) -> Result<(), SecretFileError> {
    SecretFile::create(path, replace)?.write_with(content, link)
}

/// A secret file on its way: its 0600 temporary file exists, its final name
/// does not yet. A command that gets the secret later (`klav sandbox start
/// --package-file`) creates it first, so every failure to create the file
/// comes before the secret exists, and writes it once the secret is here.
/// Dropped unwritten, the temporary file is removed.
pub struct SecretFile {
    path: PathBuf,
    replace: bool,
    temp: TempFile,
}

impl SecretFile {
    /// Refuses a `path` that exists (a file, a symlink, even a dangling
    /// one, or a pipe) unless `replace`, and creates the temporary file
    /// `.<name>.<16 hex>.klav-tmp`, 0600, in the same directory
    /// (`create_new`, so never through a symlink).
    pub fn create(path: &Path, replace: bool) -> Result<Self, SecretFileError> {
        if !replace && std::fs::symlink_metadata(path).is_ok() {
            return Err(SecretFileError::new(path, Failure::Exists));
        }
        let temp =
            TempFile::next_to(path).map_err(|e| SecretFileError::new(path, Failure::Create(e)))?;
        Ok(Self {
            path: path.to_owned(),
            replace,
            temp,
        })
    }

    /// Writes `content` to the temporary file, syncs it, and only then
    /// gives it its name in one step:
    ///
    /// - without `replace`, a hard link to the name, then the temporary
    ///   name is removed. The link fails if the name was taken meanwhile,
    ///   so nothing there is ever replaced or followed. On a file system
    ///   without hard links (FAT, exFAT, some network shares:
    ///   [`is_no_link`]), a rename right after checking that the name is
    ///   still free: a file someone else creates there in between would be
    ///   replaced, but the name still never shows a partial file;
    /// - with `replace`, a rename over the name, which replaces what is
    ///   there (a symlink itself, not what it points to) in one step.
    ///
    /// The temporary file is removed on every failure; if even that fails,
    /// the error names it. A `SIGKILL` or a power cut can leave it: callers
    /// advise ignoring `*.klav-tmp` as well as the file. A command that
    /// handles signals installs its handler first, so a signal waits until
    /// the file is in place (or gone).
    pub fn write(self, content: &[u8]) -> Result<(), SecretFileError> {
        self.write_with(content, |from, to| std::fs::hard_link(from, to))
    }

    fn write_with(
        self,
        content: &[u8],
        link: impl Fn(&Path, &Path) -> std::io::Result<()>,
    ) -> Result<(), SecretFileError> {
        let Self {
            path,
            replace,
            mut temp,
        } = self;
        let path = path.as_path();
        let error = |failure| SecretFileError::new(path, failure);
        if let Err(e) = temp
            .file
            .write_all(content)
            .and_then(|()| temp.file.sync_all())
        {
            return Err(temp.fail(error(Failure::Write(e))));
        }
        if replace {
            let existed = std::fs::symlink_metadata(path).is_ok();
            return match std::fs::rename(&temp.path, path) {
                Ok(()) => {
                    temp.taken();
                    Ok(())
                }
                Err(e) if existed => Err(temp.fail(error(Failure::Replace(e)))),
                Err(e) => Err(temp.fail(error(Failure::Create(e)))),
            };
        }
        match link(&temp.path, path) {
            // The name holds the file now; the temporary name goes.
            Ok(()) => match temp.remove() {
                None => Ok(()),
                // Two names for the secret: take back the one this made,
                // and say which ones stay.
                Some(e) => {
                    let why = match std::fs::remove_file(path) {
                        Ok(()) => "its temporary name could not be removed".to_owned(),
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                            "its temporary name could not be removed".to_owned()
                        }
                        Err(again) => format!(
                            "its temporary name could not be removed, and neither could {} itself ({again}): both names hold the secret",
                            path.display()
                        ),
                    };
                    let mut failed = error(Failure::Create(std::io::Error::other(why)));
                    failed.leftover = Some((temp.path.clone(), e));
                    Err(failed)
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                Err(temp.fail(error(Failure::Exists)))
            }
            Err(e) if is_no_link(&e) => {
                if std::fs::symlink_metadata(path).is_ok() {
                    return Err(temp.fail(error(Failure::Exists)));
                }
                match std::fs::rename(&temp.path, path) {
                    Ok(()) => {
                        temp.taken();
                        Ok(())
                    }
                    Err(e) => Err(temp.fail(error(Failure::Create(e)))),
                }
            }
            Err(e) => Err(temp.fail(error(Failure::Create(e)))),
        }
    }
}

/// Whether a hard link failed because the file system has none: ENOTSUP
/// or EOPNOTSUPP on macOS (FAT, exFAT, SMB), EPERM on Linux (vfat). Not
/// EACCES, which is a permission problem a rename would not get past, and
/// not EEXIST, which is the refusal.
///
/// The errno itself, not `ErrorKind`: on macOS, ENOTSUP (45) maps to no
/// stable kind, and `PermissionDenied` covers EACCES as well as EPERM.
fn is_no_link(e: &std::io::Error) -> bool {
    use nix::errno::Errno;
    e.raw_os_error().is_some_and(|n| {
        [Errno::ENOTSUP, Errno::EOPNOTSUPP, Errno::EPERM].contains(&Errno::from_raw(n))
    })
}

/// How a temporary file's name ends, after its 16 hex digits.
const TEMP_SUFFIX: &str = ".klav-tmp";

/// The directory a temporary file for `path` goes in: `path`'s own.
fn temp_dir(path: &Path) -> &Path {
    match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    }
}

/// How a temporary file for `path` is named before its 16 hex digits:
/// `.<name>.`.
fn temp_prefix(path: &Path) -> String {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    format!(".{name}.")
}

/// Whether `name` is a temporary file's name for the destination whose
/// [`temp_prefix`] is `prefix`: the prefix, exactly 16 lowercase hex
/// digits, then [`TEMP_SUFFIX`].
fn is_temp_name(name: &str, prefix: &str) -> bool {
    name.strip_prefix(prefix)
        .and_then(|rest| rest.strip_suffix(TEMP_SUFFIX))
        .is_some_and(|hex| {
            hex.len() == 16 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        })
}

/// A temporary file of another write of the same name, interrupted (a run
/// killed during it, a power cut) or still in progress: 0600 when Klav
/// made it, and it may hold a secret. Only its path; Klav never opens or
/// reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Leftover {
    pub path: PathBuf,
}

/// The leftovers next to each of `destinations` (temporaries of other
/// writes, interrupted or still in progress): in the destination's
/// directory, a regular file (by `symlink_metadata`: a symlink is never
/// followed) named as this module names a temporary file for that same
/// destination. Each directory is listed once, however many destinations
/// it holds. A directory that cannot be read reports nothing. Only the
/// destinations with a leftover, in the order given (each once), with
/// their leftovers sorted by path.
pub fn find_leftovers(destinations: &[&Path]) -> Vec<(PathBuf, Vec<Leftover>)> {
    let mut unique: Vec<&Path> = Vec::new();
    for d in destinations {
        if !unique.contains(d) {
            unique.push(d);
        }
    }
    let mut found: Vec<Vec<Leftover>> = vec![Vec::new(); unique.len()];
    let mut dirs: Vec<(&Path, Vec<usize>)> = Vec::new();
    for (i, d) in unique.iter().enumerate() {
        let dir = temp_dir(d);
        match dirs.iter_mut().find(|(seen, _)| *seen == dir) {
            Some((_, of)) => of.push(i),
            None => dirs.push((dir, vec![i])),
        }
    }
    for (dir, of) in &dirs {
        let Ok(entries) = std::fs::read_dir(dir) else {
            continue;
        };
        let prefixes: Vec<(usize, String)> =
            of.iter().map(|&i| (i, temp_prefix(unique[i]))).collect();
        for entry in entries.flatten() {
            let name = entry.file_name();
            // Klav's temporary names are always valid UTF-8.
            let Some(name) = name.to_str() else {
                continue;
            };
            let Some((i, _)) = prefixes.iter().find(|(_, p)| is_temp_name(name, p)) else {
                continue;
            };
            let path = entry.path();
            match std::fs::symlink_metadata(&path) {
                Ok(meta) if meta.file_type().is_file() => found[*i].push(Leftover { path }),
                _ => {}
            }
        }
    }
    unique
        .into_iter()
        .zip(found)
        .filter(|(_, f)| !f.is_empty())
        .map(|(d, mut f)| {
            f.sort_by(|a, b| a.path.cmp(&b.path));
            (d.to_owned(), f)
        })
        .collect()
}

/// How many leftovers a warning names before saying how many more.
const NAMED: usize = 3;

/// The warning about `found`, the leftovers of `destination`: their paths
/// (the first [`NAMED`], then how many more), that they belong to writes
/// that were interrupted or are still in progress and may hold secrets,
/// that Klav did not delete them, and that the person can, once nothing is
/// still writing them.
pub fn leftover_warning(destination: &Path, found: &[Leftover]) -> String {
    let mut names: Vec<String> = found
        .iter()
        .take(NAMED)
        .map(|l| l.path.display().to_string())
        .collect();
    if found.len() > NAMED {
        names.push(format!("{} more", found.len() - NAMED));
    }
    let names = match names.as_slice() {
        [] => String::new(),
        [one] => one.clone(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    };
    let dest = destination.display();
    if found.len() == 1 {
        format!(
            "{names} is a temporary file of a write of {dest} that was interrupted or is still in progress, and it may hold a secret. Klav did not delete it: the person can delete it after checking that nothing is still writing it"
        )
    } else {
        format!(
            "{} temporary files of writes of {dest} that were interrupted or are still in progress may hold secrets: {names}. Klav did not delete them: the person can delete them after checking that nothing is still writing them",
            found.len()
        )
    }
}

/// One warning per destination with leftovers ([`find_leftovers`],
/// [`leftover_warning`]), for a caller to show after it tried to write
/// `destinations`, whether the write succeeded or not. `failure` is the
/// write's error message, if it failed: a temporary file it already names
/// (one this write could not remove) is not named again.
pub fn leftover_warnings(destinations: &[&Path], failure: Option<&str>) -> Vec<String> {
    find_leftovers(destinations)
        .into_iter()
        .filter_map(|(dest, found)| {
            let found: Vec<Leftover> = found
                .into_iter()
                .filter(|l| failure.is_none_or(|f| !f.contains(&l.path.display().to_string())))
                .collect();
            (!found.is_empty()).then(|| leftover_warning(&dest, &found))
        })
        .collect()
}

/// A new 0600 file with a random name next to the one it becomes, removed
/// when dropped unless it took its final name or was removed already.
struct TempFile {
    path: PathBuf,
    file: File,
    done: bool,
}

impl TempFile {
    fn next_to(path: &Path) -> std::io::Result<Self> {
        let dir = temp_dir(path);
        let prefix = temp_prefix(path);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut tries = 0;
        loop {
            let temp = dir.join(format!("{prefix}{:016x}{TEMP_SUFFIX}", random_u64()));
            match options.open(&temp) {
                Ok(file) => {
                    return Ok(Self {
                        path: temp,
                        file,
                        done: false,
                    });
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && tries < 8 => {
                    tries += 1;
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// The file has its final name, or its name is accounted for.
    fn taken(&mut self) {
        self.done = true;
    }

    /// Removes the temporary name; the error, if it stays.
    fn remove(&mut self) -> Option<std::io::Error> {
        self.done = true;
        match std::fs::remove_file(&self.path) {
            Ok(()) => None,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => Some(e),
        }
    }

    /// `error`, after removing the temporary file (or naming it).
    fn fail(mut self, mut error: SecretFileError) -> SecretFileError {
        if let Some(e) = self.remove() {
            error.leftover = Some((self.path.clone(), e));
        }
        error
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        // Only on a path that returned early without `remove` (a panic):
        // every other path removed it or named it in its error.
        if !self.done {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// 64 bits from the standard library's `RandomState` (keys taken from the
/// system's randomness once per thread), mixed with the time and the
/// process ID. Exclusive create, not this, is what makes a planted name
/// harmless.
fn random_u64() -> u64 {
    use std::hash::{BuildHasher, Hasher};
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write_u128(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos()),
    );
    hasher.write_u32(std::process::id());
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;

    /// A content large enough that writing and syncing it takes long
    /// enough for a reader to see the file in between, were it visible.
    const LARGE: usize = 32 * 1024 * 1024;

    fn text(result: Result<(), SecretFileError>) -> String {
        match result {
            Err(e) => e.to_string(),
            Ok(()) => panic!("expected an error"),
        }
    }

    /// The names in `dir`, sorted.
    fn names(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .expect("read dir")
            .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    fn mode(path: &Path) -> u32 {
        std::fs::metadata(path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777
    }

    /// Polls `path` until `done`, and returns every length it saw there
    /// (`u64::MAX` for no file once it had seen one), with how many polls
    /// found no file before the first one that did. Returns once the
    /// reader has looked at least once, so the write starts after it.
    fn watch(path: PathBuf, done: Arc<AtomicBool>) -> std::thread::JoinHandle<(Vec<u64>, u64)> {
        let looked = Arc::new(AtomicBool::new(false));
        let reader = {
            let looked = Arc::clone(&looked);
            std::thread::spawn(move || {
                let mut seen = Vec::new();
                let mut missing_first = 0;
                loop {
                    let finished = done.load(Ordering::SeqCst);
                    match std::fs::symlink_metadata(&path) {
                        Ok(meta) => seen.push(meta.len()),
                        Err(_) if seen.is_empty() => missing_first += 1,
                        Err(_) => seen.push(u64::MAX),
                    }
                    looked.store(true, Ordering::SeqCst);
                    if finished {
                        return (seen, missing_first);
                    }
                }
            })
        };
        while !looked.load(Ordering::SeqCst) {
            std::thread::yield_now();
        }
        reader
    }

    /// A reader that polls the final name during a large write only ever
    /// sees the whole file. It starts before the write and keeps polling
    /// until after it, so it cannot pass by never looking in between.
    #[test]
    fn the_final_name_never_shows_a_partial_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("secret.key");
        let content = vec![0xa5_u8; LARGE];
        let done = Arc::new(AtomicBool::new(false));
        let reader = watch(path.clone(), Arc::clone(&done));
        write_secret_file(&path, &content, false).expect("write");
        done.store(true, Ordering::SeqCst);
        let (seen, missing_first) = reader.join().expect("reader");
        assert!(missing_first > 0, "the reader started after the write");
        assert!(!seen.is_empty(), "the reader never saw the file");
        let full = u64::try_from(LARGE).expect("len");
        let partial: Vec<&u64> = seen.iter().filter(|&&len| len != full).collect();
        assert!(
            partial.is_empty(),
            "{} of {} looks saw another length: {:?}",
            partial.len(),
            seen.len(),
            &partial[..partial.len().min(5)]
        );
        assert_eq!(mode(&path), 0o600);
        assert_eq!(names(dir.path()), ["secret.key"]);
    }

    /// Without `replace`, what is at the path is left as it was, with the
    /// same refusal, and no temporary file stays: a file, a symlink to a
    /// file (never followed), and a dangling symlink.
    #[test]
    fn without_replace_an_existing_path_is_untouched() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("secret.key");
        let target = dir.path().join("target");
        std::fs::write(&path, b"before").expect("file");
        let refusal = format!("{} already exists", path.display());
        let refused = write_secret_file(&path, b"after", false).expect_err("refused");
        assert!(refused.already_exists());
        assert_eq!(refused.to_string(), refusal);
        assert_eq!(
            refused.message(" (use --force to replace it)"),
            format!("{refusal} (use --force to replace it)")
        );
        assert_eq!(std::fs::read(&path).expect("read"), b"before");
        assert_eq!(names(dir.path()), ["secret.key"]);

        std::fs::remove_file(&path).expect("remove");
        std::fs::write(&target, b"theirs").expect("target");
        std::os::unix::fs::symlink(&target, &path).expect("symlink");
        assert_eq!(text(write_secret_file(&path, b"after", false)), refusal);
        assert_eq!(std::fs::read(&target).expect("read"), b"theirs");
        assert_eq!(std::fs::read_link(&path).expect("link"), target);

        std::fs::remove_file(&target).expect("remove");
        assert_eq!(text(write_secret_file(&path, b"after", false)), refusal);
        assert!(
            std::fs::symlink_metadata(&target).is_err(),
            "followed the link"
        );
        assert_eq!(names(dir.path()), ["secret.key"]);
    }

    /// A name taken after the first check (another process got there in
    /// between): the link fails, the other file is left alone, and the
    /// temporary name is removed.
    #[test]
    fn a_name_taken_during_the_write_is_never_replaced() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("secret.key");
        let result = write_with(&path, b"after", false, |from, to| {
            std::fs::write(to, b"theirs")?;
            std::fs::hard_link(from, to)
        });
        assert_eq!(text(result), format!("{} already exists", path.display()));
        assert_eq!(std::fs::read(&path).expect("read"), b"theirs");
        assert_eq!(names(dir.path()), ["secret.key"]);
    }

    /// With `replace`, the old content is replaced in one step: a reader
    /// polling the name sees the old file or the new one, whole, and never
    /// no file. A symlink there is replaced, not followed.
    #[test]
    fn with_replace_the_old_content_is_replaced_in_one_step() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("secret.key");
        let old = LARGE / 2;
        std::fs::write(&path, vec![b'o'; old]).expect("old");
        let done = Arc::new(AtomicBool::new(false));
        let reader = watch(path.clone(), Arc::clone(&done));
        write_secret_file(&path, &vec![b'n'; LARGE], true).expect("write");
        done.store(true, Ordering::SeqCst);
        let (seen, missing_first) = reader.join().expect("reader");
        assert_eq!(missing_first, 0, "the name was missing");
        let (old, new) = (
            u64::try_from(old).expect("len"),
            u64::try_from(LARGE).expect("len"),
        );
        assert!(seen.contains(&old), "the reader started after the write");
        let other: Vec<&u64> = seen.iter().filter(|&&l| l != old && l != new).collect();
        assert!(other.is_empty(), "saw {:?}", &other[..other.len().min(5)]);
        assert_eq!(std::fs::metadata(&path).expect("meta").len(), new);
        assert_eq!(mode(&path), 0o600);
        assert_eq!(names(dir.path()), ["secret.key"]);

        let target = dir.path().join("target");
        std::fs::write(&target, b"theirs").expect("target");
        std::fs::remove_file(&path).expect("remove");
        std::os::unix::fs::symlink(&target, &path).expect("symlink");
        write_secret_file(&path, b"after", true).expect("write");
        assert_eq!(std::fs::read(&target).expect("read"), b"theirs");
        assert!(!std::fs::symlink_metadata(&path).expect("meta").is_symlink());
        assert_eq!(std::fs::read(&path).expect("read"), b"after");
    }

    /// Nothing is left behind when the write fails: a link that fails, a
    /// rename that fails (a directory in the way, with `replace`), or a
    /// directory that does not exist.
    #[test]
    fn nothing_is_left_after_a_failed_write() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("secret.key");
        let result = write_with(&path, b"after", false, |_, _| {
            Err(std::io::Error::other("no space left"))
        });
        assert_eq!(
            text(result),
            format!("cannot create {}: no space left", path.display())
        );
        assert!(names(dir.path()).is_empty(), "{:?}", names(dir.path()));

        std::fs::create_dir(&path).expect("dir");
        std::fs::write(path.join("inside"), b"x").expect("inside");
        let failed = text(write_secret_file(&path, b"after", true));
        assert!(
            failed.starts_with(&format!("cannot replace {}: ", path.display())),
            "{failed}"
        );
        assert_eq!(names(dir.path()), ["secret.key"]);
        assert_eq!(names(&path), ["inside"]);

        let missing = dir.path().join("missing").join("secret.key");
        let failed = text(write_secret_file(&missing, b"after", false));
        assert!(
            failed.starts_with(&format!("cannot create {}: ", missing.display())),
            "{failed}"
        );
        assert_eq!(names(dir.path()), ["secret.key"]);
    }

    /// A file system without hard links: the file is renamed into place,
    /// whole and 0600, after checking that the name is still free; a name
    /// taken by then is refused and left alone. The link fails with real
    /// errnos, so they go through the same mapping as the system's.
    #[test]
    fn without_hard_links_the_file_is_renamed_into_place() {
        use nix::errno::Errno;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("secret.key");
        // ENOTSUP is what macOS answers on FAT and exFAT (errno 45).
        let unsupported = |_: &Path, _: &Path| Err(std::io::Error::from(Errno::ENOTSUP));
        write_with(&path, b"after", false, unsupported).expect("write");
        assert_eq!(std::fs::read(&path).expect("read"), b"after");
        assert_eq!(mode(&path), 0o600);
        assert_eq!(names(dir.path()), ["secret.key"]);

        let other = dir.path().join("other.key");
        let result = write_with(&other, b"after", false, |_, to| {
            std::fs::write(to, b"theirs")?;
            Err(std::io::Error::from(Errno::EPERM))
        });
        assert_eq!(text(result), format!("{} already exists", other.display()));
        assert_eq!(std::fs::read(&other).expect("read"), b"theirs");
        assert_eq!(names(dir.path()), ["other.key", "secret.key"]);

        // EOPNOTSUPP, the other answer of a share without hard links.
        let third = dir.path().join("third.key");
        let unsupported = |_: &Path, _: &Path| Err(std::io::Error::from(Errno::EOPNOTSUPP));
        write_with(&third, b"after", false, unsupported).expect("write");
        assert_eq!(std::fs::read(&third).expect("read"), b"after");
        assert_eq!(names(dir.path()), ["other.key", "secret.key", "third.key"]);
    }

    /// Only a missing feature takes the rename: EACCES is a permission
    /// problem and fails as any other error, EEXIST is the refusal. Neither
    /// creates the name nor leaves the temporary file.
    #[test]
    fn other_link_errors_never_take_the_rename() {
        use nix::errno::Errno;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("secret.key");

        let denied = |_: &Path, _: &Path| Err(std::io::Error::from(Errno::EACCES));
        let failed = text(write_with(&path, b"after", false, denied));
        assert!(
            failed.starts_with(&format!("cannot create {}: ", path.display())),
            "{failed}"
        );
        assert!(names(dir.path()).is_empty(), "{:?}", names(dir.path()));

        let exists = |_: &Path, _: &Path| Err(std::io::Error::from(Errno::EEXIST));
        let refused = write_with(&path, b"after", false, exists).expect_err("refused");
        assert!(refused.already_exists());
        assert!(names(dir.path()).is_empty(), "{:?}", names(dir.path()));
    }

    /// Created first, the file has only its temporary name until it is
    /// written; dropped unwritten, nothing is left. A missing directory
    /// fails at creation, before any content exists.
    #[test]
    fn created_first_the_name_stays_free_until_the_write() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("package");
        let file = SecretFile::create(&path, false).expect("create");
        let listed = names(dir.path());
        assert_eq!(listed.len(), 1, "{listed:?}");
        assert!(
            listed[0].starts_with(".package.") && listed[0].ends_with(".klav-tmp"),
            "{listed:?}"
        );
        assert!(std::fs::symlink_metadata(&path).is_err());
        file.write(b"ksb1_after").expect("write");
        assert_eq!(std::fs::read(&path).expect("read"), b"ksb1_after");
        assert_eq!(mode(&path), 0o600);
        assert_eq!(names(dir.path()), ["package"]);

        let other = dir.path().join("other");
        drop(SecretFile::create(&other, false).expect("create"));
        assert_eq!(names(dir.path()), ["package"]);

        let missing = dir.path().join("missing").join("package");
        let failed = SecretFile::create(&missing, false)
            .err()
            .expect("refused")
            .to_string();
        assert!(
            failed.starts_with(&format!("cannot create {}: ", missing.display())),
            "{failed}"
        );
        assert!(
            SecretFile::create(&path, false)
                .err()
                .expect("refused")
                .already_exists()
        );
    }

    /// A failure to write the content (a full disk) says so, apart from
    /// the failures about the path, names the path without the content,
    /// and leaves nothing behind. The temporary file is swapped for one
    /// opened read-only, so the write fails for real.
    #[test]
    fn a_failed_write_is_told_apart_from_the_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("secret.key");
        let mut file = SecretFile::create(&path, false).expect("create");
        file.temp.file = File::open(&file.temp.path).expect("read-only");
        let failed = file.write(b"after").expect_err("write refused");
        assert!(failed.is_write(), "{failed}");
        assert!(!failed.already_exists());
        assert!(failed.io_error().is_some());
        assert_eq!(failed.leftover_note(), "");
        assert!(
            failed
                .to_string()
                .starts_with(&format!("cannot write {}: ", path.display())),
            "{failed}"
        );
        assert!(names(dir.path()).is_empty(), "{:?}", names(dir.path()));

        // The failures about the path are not write failures.
        let refused = |result: Result<(), SecretFileError>| result.expect_err("refused");
        let link_failed = refused(write_with(&path, b"after", false, |_, _| {
            Err(std::io::Error::other("no space left"))
        }));
        assert!(!link_failed.is_write() && !link_failed.already_exists());
        std::fs::write(&path, b"before").expect("before");
        let taken = refused(write_secret_file(&path, b"after", false));
        assert!(taken.already_exists() && !taken.is_write());
        assert!(taken.io_error().is_none());
        let missing = dir.path().join("missing").join("secret.key");
        assert!(!refused(write_secret_file(&missing, b"after", false)).is_write());
    }

    /// The link is made and then neither name can be removed (the
    /// directory turns read-only right after the link): the error names
    /// both, since both hold the secret. As root, modes stop nothing, and
    /// the test ends there.
    #[test]
    fn two_names_left_are_both_named() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("secret.key");
        let set_mode = |mode| {
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(mode))
                .expect("chmod");
        };
        let failed = write_with(&path, b"after", false, |from, to| {
            std::fs::hard_link(from, to)?;
            set_mode(0o500);
            Ok(())
        });
        let enforced = std::fs::write(dir.path().join("probe"), b"").is_err();
        set_mode(0o700);
        if !enforced {
            return;
        }
        let failed = text(failed);
        let left = names(dir.path());
        assert_eq!(left.len(), 2, "{left:?}");
        let temp = left
            .iter()
            .find(|n| n.ends_with(".klav-tmp"))
            .expect("temporary");
        assert!(
            failed.contains(&format!("neither could {} itself", path.display()))
                && failed.contains("both names hold the secret")
                && failed.contains(&format!(
                    "the temporary file {} (0600, with the secret) could not be removed",
                    dir.path().join(temp).display()
                )),
            "{failed}"
        );
    }

    /// A file named as a temporary of `dest` would be, with `hex` as its 16
    /// digits, holding `content` with `mode`.
    fn plant(dest: &Path, hex: &str, content: &[u8], mode: u32) -> PathBuf {
        let path = temp_dir(dest).join(format!("{}{hex}{TEMP_SUFFIX}", temp_prefix(dest)));
        std::fs::write(&path, content).expect("plant");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).expect("chmod");
        path
    }

    /// A leftover of the same name is reported after the write, which goes
    /// on as before, and stays as it was: content, mode, time. The warning
    /// never carries its content.
    #[test]
    fn a_leftover_is_reported_and_left_as_it_was() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dest = dir.path().join("secret.key");
        let left = plant(&dest, "0123456789abcdef", b"MARKER-left", 0o600);
        let before = std::fs::symlink_metadata(&left).expect("meta");
        write_secret_file(&dest, b"new", false).expect("written");
        let warnings = leftover_warnings(&[&dest], None);
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        let warning = &warnings[0];
        assert!(
            warning.starts_with(&format!("{} is a temporary file", left.display()))
                && warning.contains(&dest.display().to_string())
                && warning.contains(
                    "that was interrupted or is still in progress, and it may hold a secret"
                )
                && warning.contains("Klav did not delete it")
                && warning.contains("nothing is still writing it"),
            "{warning}"
        );
        assert!(!warning.contains("MARKER"));
        assert_eq!(std::fs::read(&left).expect("read"), b"MARKER-left");
        let after = std::fs::symlink_metadata(&left).expect("meta");
        assert_eq!(mode(&left), 0o600);
        assert_eq!(after.modified().ok(), before.modified().ok());
        assert_eq!(after.len(), before.len());
        let found = find_leftovers(&[&dest]);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].0, dest);
        assert_eq!(found[0].1, [Leftover { path: left }]);
    }

    /// Only regular files named exactly for this destination: not a
    /// symlink (never followed), not a directory, not another name's
    /// temporary, not a near miss.
    #[test]
    fn only_this_names_temporaries_are_leftovers() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dest = dir.path().join("secret.key");
        let target = dir.path().join("target");
        std::fs::write(&target, b"target").expect("target");
        let link = temp_dir(&dest).join(format!(
            "{}{}{TEMP_SUFFIX}",
            temp_prefix(&dest),
            "1111111111111111"
        ));
        std::os::unix::fs::symlink(&target, &link).expect("symlink");
        std::fs::create_dir(temp_dir(&dest).join(format!(
            "{}{}{TEMP_SUFFIX}",
            temp_prefix(&dest),
            "2222222222222222"
        )))
        .expect("dir");
        plant(
            &dir.path().join("other.key"),
            "3333333333333333",
            b"x",
            0o600,
        );
        plant(
            &dir.path().join("secret.key.old"),
            "4444444444444444",
            b"x",
            0o600,
        );
        for near in [
            "ABCDEF0123456789",
            "0123456789abcde",
            "0123456789abcdefa",
            "0123456789abcdeg",
        ] {
            plant(&dest, near, b"x", 0o600);
        }
        std::fs::write(
            dir.path().join(".secret.key.0123456789abcdef.klav-tm"),
            b"x",
        )
        .expect("x");
        assert!(find_leftovers(&[&dest]).is_empty());
        assert!(leftover_warnings(&[&dest], None).is_empty());
        assert_eq!(std::fs::read(&target).expect("read"), b"target");
        // The other name's temporary is that name's leftover.
        let other = dir.path().join("other.key");
        assert_eq!(find_leftovers(&[&other])[0].1.len(), 1);
    }

    /// The write's own temporary is never reported: gone after a write
    /// that succeeded, and, when a failed write could not remove it, named
    /// by its error and not a second time.
    #[test]
    fn the_writes_own_temporary_is_not_named_again() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dest = dir.path().join("secret.key");
        write_secret_file(&dest, b"new", false).expect("written");
        assert!(leftover_warnings(&[&dest], None).is_empty());
        std::fs::remove_file(&dest).expect("rm");

        let set_mode = |mode| {
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(mode))
                .expect("chmod");
        };
        let failed = write_with(&dest, b"after", false, |from, to| {
            std::fs::hard_link(from, to)?;
            set_mode(0o500);
            Ok(())
        });
        let enforced = std::fs::write(dir.path().join("probe"), b"").is_err();
        set_mode(0o700);
        if !enforced {
            return;
        }
        let failure = failed.expect_err("failed").to_string();
        let own = find_leftovers(&[&dest]);
        assert_eq!(own[0].1.len(), 1, "the write left its temporary");
        assert!(failure.contains(&own[0].1[0].path.display().to_string()));
        assert!(leftover_warnings(&[&dest], Some(&failure)).is_empty());
        // Another leftover beside it is still named.
        let other = plant(&dest, "fedcba9876543210", b"x", 0o600);
        let warnings = leftover_warnings(&[&dest], Some(&failure));
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(
            warnings[0].starts_with(&other.display().to_string()),
            "{warnings:?}"
        );
    }

    /// A directory that cannot be listed reports nothing, and the write
    /// there goes on as before. As root, modes stop nothing, and the test
    /// ends there.
    #[test]
    fn an_unreadable_directory_reports_nothing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dest = dir.path().join("secret.key");
        let left = plant(&dest, "0123456789abcdef", b"x", 0o600);
        let set_mode = |mode| {
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(mode))
                .expect("chmod");
        };
        set_mode(0o300);
        let enforced = std::fs::read_dir(dir.path()).is_err();
        let written = write_secret_file(&dest, b"new", false);
        let warnings = leftover_warnings(&[&dest], None);
        set_mode(0o700);
        if !enforced {
            return;
        }
        written.expect("the write is not affected");
        assert!(warnings.is_empty(), "{warnings:?}");
        assert!(left.exists());
    }

    /// Many leftovers: the first three by path, then how many more. Each
    /// destination gets its own warning, from one listing of their
    /// directory.
    #[test]
    fn many_leftovers_are_counted() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dest = dir.path().join("secret.key");
        let mut planted: Vec<PathBuf> = (1..=5)
            .map(|n| plant(&dest, &format!("{n:016x}"), b"x", 0o600))
            .collect();
        planted.sort();
        let other = dir.path().join("other.key");
        let lone = plant(&other, "00000000000000aa", b"x", 0o600);
        let warnings = leftover_warnings(&[&dest, &other, &dest], None);
        assert_eq!(warnings.len(), 2, "{warnings:?}");
        let named: Vec<String> = planted.iter().map(|p| p.display().to_string()).collect();
        assert!(
            warnings[0].starts_with(&format!(
                "5 temporary files of writes of {} that were interrupted or are still in progress may hold secrets:",
                dest.display()
            )) && warnings[0].contains(&format!(
                "{}, {}, {} and 2 more.",
                named[0], named[1], named[2]
            )) && !warnings[0].contains(&named[3])
                && warnings[0].contains("Klav did not delete them"),
            "{}",
            warnings[0]
        );
        assert!(
            warnings[1].starts_with(&lone.display().to_string()),
            "{}",
            warnings[1]
        );
        assert_eq!(names(dir.path()).len(), 6);
    }

    /// The error never carries the content, in its message or its `Debug`.
    #[test]
    fn an_error_never_carries_the_content() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("secret.key");
        let content = b"MARKER-secret-file-content";
        let failed = write_with(&path, content, false, |_, _| {
            Err(std::io::Error::other("no space left"))
        })
        .expect_err("failed");
        for shown in [failed.to_string(), format!("{failed:?}")] {
            assert!(!shown.contains("MARKER"), "the content was shown");
        }
        assert!(names(dir.path()).is_empty());
    }
}
