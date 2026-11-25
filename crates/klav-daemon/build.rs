//! The build's identity: the commit it was built from and that commit's
//! time, for `klav --version`, `klavd --version` and `klavd`'s `status`
//! (`apps/docs/src/content/docs/reference/cli-commands.mdx`, `docs/klavd.md`
//! §5). The Mac app compares it to tell an older `klav` or
//! `klavd` from its own (`docs/macos.md` §3); the version number alone
//! can't: every build of one version says the same number, and every
//! build before 0.9.0 said `0.0.0`.
//!
//! `klav-cli`, `klav-proxy`, `klav-forward` and `klav-server` run this same
//! file (`build = "../klav-daemon/build.rs"`), for `klav-proxy --version`,
//! `klav-forward --version` and `klav-server --version` too (the Linux
//! release checks the server's, ADR 0048 §5.2). Only the binaries read what
//! it writes (`OUT_DIR/build_identity.rs`), so no library crate reads the
//! commit: `GET /v1/health` still says only the version number.
//!
//! **The marker.** The binary carries one line, `klav-build-identity: `
//! followed by exactly what `--version` prints after the program's name and
//! a newline (`klav-build-identity: 0.9.0 (ce4fa5099092
//! 2026-11-13T18:17:02Z)`). `--version` is cut from that same string, so it
//! stays in the binary and never disagrees with it. The Mac app finds it by
//! reading another `klav`'s file, without running it (`docs/macos.md` §3).
//!
//! Where the identity comes from, in order:
//!
//! 1. `KLAV_BUILD_COMMIT` and `KLAV_BUILD_COMMIT_TIME` (a release script or
//!    CI): the commit's full hash, 40 lowercase hex digits, and its
//!    committer time in Unix seconds (ASCII digits only), up to
//!    9999-12-31T23:59:59Z. Both or
//!    neither; anything else stops the build.
//! 2. `git`, when this source is a Git checkout of Klav: `HEAD`'s hash and
//!    committer time. Uncommitted changes are not part of it.
//! 3. Otherwise (a source archive without `.git`, no `git` installed, the
//!    Docker images): unknown, and `--version` says so.
//!
//! Runs only `git rev-parse` and `git cat-file`, which read the repository
//! and never run hooks, a signature check or a file system monitor.

use std::path::{Path, PathBuf};
use std::process::Command;

const COMMIT_VAR: &str = "KLAV_BUILD_COMMIT";
const TIME_VAR: &str = "KLAV_BUILD_COMMIT_TIME";
/// 9999-12-31T23:59:59Z: four-digit years only.
const MAX_TIME: u64 = 253_402_300_799;
/// What starts the marker line (see the module's doc).
const MARKER_PREFIX: &str = "klav-build-identity: ";

fn main() {
    println!("cargo:rerun-if-env-changed={COMMIT_VAR}");
    println!("cargo:rerun-if-env-changed={TIME_VAR}");
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let identity = match from_env() {
        Some(identity) => Some(identity),
        None => {
            let found = from_git(&manifest);
            let ours = manifest.parent().and_then(Path::parent);
            if found.is_none() && ours.is_some_and(|dir| dir.join(".git").exists()) {
                println!(
                    "cargo:warning=git could not read this checkout; --version will say (commit unknown)"
                );
            }
            found
        }
    };
    let version = std::env::var("CARGO_PKG_VERSION").expect("CARGO_PKG_VERSION");
    let out = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));
    std::fs::write(
        out.join("build_identity.rs"),
        source(&version, identity.as_ref()),
    )
    .expect("write build_identity.rs");
}

pub(crate) struct Identity {
    pub(crate) commit: String,
    pub(crate) time: u64,
}

fn from_env() -> Option<Identity> {
    let commit = std::env::var(COMMIT_VAR).ok();
    let time = std::env::var(TIME_VAR).ok();
    parse_env(commit.as_deref(), time.as_deref()).unwrap_or_else(|message| panic!("{message}"))
}

/// `KLAV_BUILD_COMMIT` and `KLAV_BUILD_COMMIT_TIME` as they were set: both
/// or neither (an empty value counts as unset), the commit as 40 lowercase
/// hex digits, the time as ASCII decimal digits only (no sign, space or
/// `_`) up to [`MAX_TIME`]. `Err` is the message the build stops with.
/// Tested without a build: `crates/klav-daemon/tests/build_script.rs`.
pub(crate) fn parse_env(
    commit: Option<&str>,
    time: Option<&str>,
) -> Result<Option<Identity>, String> {
    match (
        commit.filter(|v| !v.is_empty()),
        time.filter(|v| !v.is_empty()),
    ) {
        (None, None) => Ok(None),
        (Some(commit), Some(time)) => {
            if commit.len() != 40 || !valid_commit(commit) {
                return Err(format!(
                    "{COMMIT_VAR} must be the full 40-digit lowercase hex hash, not {commit:?}"
                ));
            }
            // `u64::from_str` also takes a leading `+`: digits only.
            let time = time
                .bytes()
                .all(|b| b.is_ascii_digit())
                .then(|| time.parse::<u64>().ok())
                .flatten()
                .ok_or_else(|| format!("{TIME_VAR} must be Unix seconds, not {time:?}"))?;
            if time > MAX_TIME {
                return Err(format!(
                    "{TIME_VAR} must be at most {MAX_TIME} (9999-12-31T23:59:59Z), not {time}"
                ));
            }
            Ok(Some(Identity {
                commit: commit.to_owned(),
                time,
            }))
        }
        _ => Err(format!("set both {COMMIT_VAR} and {TIME_VAR}, or neither")),
    }
}

fn valid_commit(commit: &str) -> bool {
    (7..=40).contains(&commit.len())
        && commit
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn git(dir: &Path, args: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .env("GIT_OPTIONAL_LOCKS", "0")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout).ok()
}

fn from_git(manifest: &Path) -> Option<Identity> {
    let found = git(
        manifest,
        &[
            "rev-parse",
            "--path-format=absolute",
            "--show-toplevel",
            "--git-dir",
            "--git-common-dir",
        ],
    )?;
    let mut lines = found.lines().map(PathBuf::from);
    let (top, git_dir, common) = (lines.next()?, lines.next()?, lines.next()?);
    // Only Klav's own checkout: a source archive unpacked inside some other
    // repository would otherwise take that repository's commit.
    let ours = manifest.parent()?.parent()?;
    if std::fs::canonicalize(&top).ok()? != std::fs::canonicalize(ours).ok()? {
        return None;
    }
    // Build again when HEAD moves: a commit, a checkout, a rebase.
    let head = git_dir.join("HEAD");
    watch(&head);
    if let Some(branch) = std::fs::read_to_string(&head)
        .ok()
        .and_then(|h| h.strip_prefix("ref: ").map(|r| r.trim().to_owned()))
    {
        watch(&common.join(branch));
    }
    watch(&common.join("packed-refs"));
    // A commit on a packed branch writes a loose ref that wasn't watched
    // above, and always this worktree's reflog. Without a reflog yet (a
    // worktree whose `logs/HEAD` is missing, or `core.logAllRefUpdates`
    // off), the folder of loose branch refs instead: a new file there
    // changes it.
    let reflog = git_dir.join("logs").join("HEAD");
    if reflog.exists() {
        watch(&reflog);
    } else {
        watch(&common.join("refs").join("heads"));
    }
    // Reftable keeps every ref in one table list.
    watch(&common.join("reftable").join("tables.list"));

    let commit = git(
        manifest,
        &["rev-parse", "--verify", "--quiet", "HEAD^{commit}"],
    )?;
    let commit = commit.trim().to_owned();
    if !valid_commit(&commit) {
        return None;
    }
    let object = git(manifest, &["cat-file", "commit", &commit])?;
    // `committer Name <mail> 1763050925 -0600`: the seconds are the
    // second-to-last field.
    let line = object.lines().find(|l| l.starts_with("committer "))?;
    let time = line.rsplit(' ').nth(1)?.parse().ok()?;
    Some(Identity { commit, time })
}

/// `rerun-if-changed` only for a path that exists: a missing one would run
/// this script on every build.
fn watch(path: &Path) {
    if path.exists() {
        println!("cargo:rerun-if-changed={}", path.display());
    }
}

fn source(version: &str, identity: Option<&Identity>) -> String {
    let (commit, time, long) = match identity {
        Some(i) => (
            format!("Some({:?})", i.commit),
            format!("Some({})", i.time),
            format!(
                "{version} ({} {})",
                &i.commit[..i.commit.len().min(12)],
                rfc3339(i.time)
            ),
        ),
        None => (
            "None".into(),
            "None".into(),
            format!("{version} (commit unknown)"),
        ),
    };
    let marker = format!("{MARKER_PREFIX}{long}\n");
    TEMPLATE
        .replace("@COMMIT@", &commit)
        .replace("@TIME@", &time)
        .replace("@MARKER@", &format!("{marker:?}"))
        .replace("@PREFIX@", &MARKER_PREFIX.len().to_string())
}

/// `OUT_DIR/build_identity.rs`, which `klav`, `klavd`, `klav-proxy`,
/// `klav-forward` and `klav-server` include.
const TEMPLATE: &str = r#"/// The commit this binary was built from (`build.rs`).
pub(crate) const COMMIT: Option<&str> = @COMMIT@;
/// That commit's committer time, in Unix seconds.
pub(crate) const COMMIT_TIME: Option<u64> = @TIME@;
/// The marker line the Mac app reads in this file (`build.rs`).
pub(crate) static MARKER: &str = @MARKER@;

/// What `--version` prints after the program's name: the marker without its
/// prefix and newline. Read through `black_box`, so the whole marker stays
/// in the binary.
pub(crate) fn version() -> &'static str {
    let marker: &'static str = std::hint::black_box(MARKER);
    &marker[@PREFIX@..marker.len() - 1]
}

/// The commit and its time for `status`, only when the marker names that
/// commit: `--version` and `status` never disagree.
pub(crate) fn commit() -> Option<(&'static str, u64)> {
    let (commit, time) = COMMIT.zip(COMMIT_TIME)?;
    let named = format!("({} ", &commit[..commit.len().min(12)]);
    version().contains(&named).then_some((commit, time))
}
"#;

/// Unix seconds as `2026-11-13T18:22:05Z`.
fn rfc3339(secs: u64) -> String {
    let days = secs / 86_400;
    let rest = secs % 86_400;
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    )
}

/// Days since 1970-01-01 to a proleptic Gregorian date (Howard Hinnant's
/// `civil_from_days`, for days on or after the epoch).
fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + u64::from(month <= 2);
    (year, month, day)
}
