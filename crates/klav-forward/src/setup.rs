//! What `klav-forward up` leaves on disk, none of it secret (ADR 0036 §5,
//! step 5): the state a later `klav-forward status` or `env` reads, and the
//! shell lines with the base URLs of mode (a) (§7).

use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::forward::{Bound, Refusal};

/// The local port by default: the proxy's own on the person's machine, so
/// a tool set up with `http://127.0.0.1:8790/<profile>` works on both.
pub const DEFAULT_PORT: u16 = 8790;
/// Where the shell lines go by default.
pub const DEFAULT_PROFILE_FILE: &str = "/etc/profile.d/klav-forward.sh";
/// The state file's name, in the state directory.
pub const STATE_FILE: &str = "state.json";
/// The fallback for the shell lines, in the state directory.
pub const ENV_FILE: &str = "env.sh";
/// The daemon's log, in the state directory.
pub const LOG_FILE: &str = "forward.log";

/// What a running forwarder wrote about itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    /// Format version (1).
    pub v: u32,
    /// Its process.
    pub pid: u32,
    /// The local port it listens on (`127.0.0.1`).
    pub port: u16,
    /// The sandbox, as the proxy said at the claim.
    pub sandbox: Bound,
}

/// The state directory: `$KLAV_FORWARD_HOME`, or `~/.klav-forward`.
pub fn default_state_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("KLAV_FORWARD_HOME") {
        return PathBuf::from(dir);
    }
    let home = std::env::var_os("HOME").map_or_else(|| PathBuf::from("."), PathBuf::from);
    home.join(".klav-forward")
}

/// A new file at `dir/.<name>.tmp-<random>`, 0600, that did not exist
/// before (`O_EXCL`): the name cannot be guessed, and nothing already at
/// it (a link someone left there) is ever written through.
fn new_temporary(dir: &Path, name: &str) -> std::io::Result<(PathBuf, std::fs::File)> {
    use std::os::unix::fs::OpenOptionsExt;
    let nonce: [u8; 8] = klav_core::crypto::random::array();
    let hex: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
    let tmp = dir.join(format!(".{name}.tmp-{hex}"));
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)?;
    Ok((tmp, file))
}

/// Writes `bytes` to `path` with mode 0600, replacing it at once.
pub fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let dir = path.parent().unwrap_or(Path::new("."));
    std::fs::create_dir_all(dir)?;
    let (tmp, mut file) = new_temporary(
        dir,
        path.file_name().and_then(|n| n.to_str()).unwrap_or("file"),
    )?;
    let written = file.write_all(bytes).and_then(|()| file.sync_all());
    drop(file);
    written
        .and_then(|()| std::fs::rename(&tmp, path))
        .inspect_err(|_| {
            let _ = std::fs::remove_file(&tmp);
        })
}

/// Saves the state.
pub fn save_state(dir: &Path, state: &State) -> std::io::Result<()> {
    write_private(
        &dir.join(STATE_FILE),
        &serde_json::to_vec_pretty(state).expect("json"),
    )
}

/// Reads the state; `None` when no forwarder wrote one.
pub fn load_state(dir: &Path) -> Result<Option<State>, String> {
    match std::fs::read(dir.join(STATE_FILE)) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|e| format!("{}: {e}", dir.join(STATE_FILE).display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("{}: {e}", dir.join(STATE_FILE).display())),
    }
}

/// Why a forwarder stopped on its own, next to `state.json` (which stays
/// what every reader of its v1 accepts): the proxy revoked its sandbox.
pub const ENDED_FILE: &str = "ended.json";
/// The only `ended.json` format this version reads and writes.
pub const ENDED_VERSION: u32 = 1;

/// `ended.json`: the proxy's refusal of the status of `sandbox_id` once it
/// revoked it. Never a secret: a code and the proxy's own words.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ended {
    /// Format version ([`ENDED_VERSION`]).
    pub v: u32,
    /// The sandbox it is about: one of another package is ignored.
    pub sandbox_id: String,
    /// What `status` and `up` say again.
    pub refusal: Refusal,
}

/// What `ended.json` says of a sandbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EndedRead {
    /// No file, or one about another sandbox.
    No,
    /// Its forwarder stopped because the proxy revoked it.
    Ended(Refusal),
    /// A file this version cannot read: another format or a broken one.
    Unreadable(String),
}

/// Saves why the forwarder of `sandbox_id` stopped.
pub fn save_ended(dir: &Path, sandbox_id: &str, refusal: &Refusal) -> std::io::Result<()> {
    let ended = Ended {
        v: ENDED_VERSION,
        sandbox_id: sandbox_id.into(),
        refusal: refusal.clone(),
    };
    write_private(
        &dir.join(ENDED_FILE),
        &serde_json::to_vec_pretty(&ended).expect("json"),
    )
}

/// Reads `ended.json` for `sandbox_id`.
pub fn load_ended(dir: &Path, sandbox_id: &str) -> EndedRead {
    let path = dir.join(ENDED_FILE);
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return EndedRead::No,
        Err(e) => return EndedRead::Unreadable(format!("{}: {e}", path.display())),
    };
    let v = serde_json::from_slice::<serde_json::Value>(&bytes)
        .ok()
        .and_then(|j| j.get("v").and_then(serde_json::Value::as_u64));
    if let Some(v) = v
        && v != u64::from(ENDED_VERSION)
    {
        return EndedRead::Unreadable(format!(
            "{} has format v{v}, from another version of klav-forward",
            path.display()
        ));
    }
    match serde_json::from_slice::<Ended>(&bytes) {
        Ok(ended) if ended.sandbox_id == sandbox_id => EndedRead::Ended(ended.refusal),
        Ok(_) => EndedRead::No,
        Err(e) => EndedRead::Unreadable(format!("{}: {e}", path.display())),
    }
}

/// Removes `ended.json`, if any: a new forwarder runs here.
pub fn remove_ended(dir: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(dir.join(ENDED_FILE)) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

/// The directory of the claim markers, in the state directory.
pub const CLAIMED_DIR: &str = "claimed";
/// The only marker format this version reads and writes.
pub const MARKER_VERSION: u64 = 1;

/// Creates `dir` and its missing parents with mode 0700. One that exists
/// keeps its mode.
pub fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
}

/// Whether `dir` is private to the user `me`: a directory it owns that
/// neither its group nor others can write. In one that another user can
/// write, that user could delete a claim marker (a later `up` would claim
/// again, which the proxy takes for a theft) or plant one (`up` would
/// refuse). The error says how to fix it.
pub fn check_private(dir: &Path, me: u32) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    if !meta.is_dir() {
        return Err(format!("{} is not a directory", dir.display()));
    }
    if meta.uid() != me {
        return Err(format!(
            "{} belongs to another user (uid {}), not to this one (uid {me})",
            dir.display(),
            meta.uid()
        ));
    }
    if meta.mode() & 0o022 != 0 {
        return Err(format!(
            "{} can be written by its group or by other users (mode {:o}); `chmod go-w {}` fixes it",
            dir.display(),
            meta.mode() & 0o777,
            dir.display()
        ));
    }
    Ok(())
}

/// The user this process writes files as: the owner of a new file in
/// `dir` (removed at once). No `unsafe` and no new dependency for
/// `geteuid`, and it is what the file system itself records.
pub fn own_uid(dir: &Path) -> std::io::Result<u32> {
    use std::os::unix::fs::MetadataExt;
    let (probe, file) = new_temporary(dir, "probe")?;
    let uid = file.metadata().map(|m| m.uid());
    drop(file);
    let _ = std::fs::remove_file(&probe);
    uid
}

/// [`check_private`] for the state directory and, if it exists, its
/// `claimed/`, as the user that writes there. The error names the
/// directory to fix, and why.
pub fn check_state_dir(dir: &Path) -> Result<(), (PathBuf, String)> {
    let me = own_uid(dir).map_err(|e| {
        (
            dir.to_owned(),
            format!("cannot write in {}: {e}", dir.display()),
        )
    })?;
    check_private(dir, me).map_err(|why| (dir.to_owned(), why))?;
    let claimed = dir.join(CLAIMED_DIR);
    if claimed.symlink_metadata().is_ok() {
        check_private(&claimed, me).map_err(|why| (claimed, why))?;
    }
    Ok(())
}

/// That this state directory began to claim a sandbox (ADR 0036 §5):
/// `claimed/<sandbox_id>`, written before the first byte of the claim, so
/// a later `up` with the same package refuses here instead of claiming
/// again, which the proxy would take for a theft. Nothing secret: no
/// secret, no hash of one, no package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Marker {
    /// Format version ([`MARKER_VERSION`]).
    pub v: u64,
    /// The sandbox (its file's name too).
    pub sandbox_id: String,
    /// When the claim began (Unix ms).
    pub at: i64,
}

/// What the marker of a sandbox says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Claimed {
    /// None: this state directory never began to claim it.
    No,
    /// It began to claim it then.
    Yes(Marker),
    /// A marker of a format this version does not know (`v`): it counts
    /// as claimed, and is never read as absent.
    OtherVersion(u64),
    /// A marker that cannot be read or parsed: it counts as claimed.
    Unreadable(String),
}

/// The marker's path for `sandbox_id`.
pub fn marker_path(dir: &Path, sandbox_id: &str) -> PathBuf {
    dir.join(CLAIMED_DIR).join(sandbox_id)
}

/// Reads the marker of `sandbox_id`.
pub fn read_marker(dir: &Path, sandbox_id: &str) -> Claimed {
    let path = marker_path(dir, sandbox_id);
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Claimed::No,
        Err(e) => return Claimed::Unreadable(format!("{}: {e}", path.display())),
    };
    let version = serde_json::from_slice::<serde_json::Value>(&bytes)
        .ok()
        .and_then(|j| j.get("v").and_then(serde_json::Value::as_u64));
    match version {
        Some(MARKER_VERSION) => serde_json::from_slice(&bytes)
            .map(Claimed::Yes)
            .unwrap_or_else(|e| Claimed::Unreadable(format!("{}: {e}", path.display()))),
        Some(other) => Claimed::OtherVersion(other),
        None => Claimed::Unreadable(format!("{}: not a marker", path.display())),
    }
}

/// How [`write_marker`] put the marker in place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Placed {
    /// Linked to its name, which was free: this process made it, and only
    /// this process may take it back ([`release_unused_marker`]).
    Exclusive,
    /// Renamed over its name, on a file system without hard links: another
    /// `up` at the same instant may have placed one too and be claiming
    /// with it, so this marker is never removed.
    Replaced,
    /// One was already there: claimed, or being claimed, by another `up`.
    AlreadyThere,
}

/// The file system calls [`write_marker`] makes that a test replaces.
pub(crate) struct MarkerFs {
    /// `std::fs::hard_link`.
    pub(crate) link: fn(&Path, &Path) -> std::io::Result<()>,
    /// `fsync` of a directory.
    pub(crate) sync_dir: fn(&Path) -> std::io::Result<()>,
}

impl MarkerFs {
    const REAL: Self = Self {
        link: |from, to| std::fs::hard_link(from, to),
        sync_dir: |dir| std::fs::File::open(dir)?.sync_all(),
    };
}

/// Writes the marker of `sandbox_id`, at once and only if there is none:
/// a temporary file (0600, new, synced) linked to its name, so a crash
/// leaves either a whole marker or none under that name. Where the file
/// system has no hard links, an atomic rename after a check stands in; on
/// that path two `up` at the same instant (each on its own `--port`) can
/// both place a marker and both claim, because a rename does not see the
/// other's.
///
/// It is durable before this returns `Ok`: `claimed/` and the state
/// directory are synced, so a power loss after the claim cannot take the
/// marker (or `claimed/` itself) away. Any error means nothing may be
/// claimed; a marker this process linked is taken back first.
///
/// `claimed/` and the state directory must be private to this user
/// ([`check_private`]).
pub fn write_marker(dir: &Path, marker: &Marker) -> std::io::Result<Placed> {
    write_marker_with(dir, marker, &MarkerFs::REAL)
}

pub(crate) fn write_marker_with(
    dir: &Path,
    marker: &Marker,
    fs: &MarkerFs,
) -> std::io::Result<Placed> {
    // Private before anything is created in it (one made here is 0700).
    create_private_dir(dir)?;
    let me = own_uid(dir)?;
    check_private(dir, me).map_err(std::io::Error::other)?;
    let claimed = dir.join(CLAIMED_DIR);
    create_private_dir(&claimed)?;
    check_private(&claimed, me).map_err(std::io::Error::other)?;
    let path = claimed.join(&marker.sandbox_id);
    let (tmp, mut file) = new_temporary(&claimed, &marker.sandbox_id)?;
    let written = (|| {
        file.write_all(&serde_json::to_vec(marker).expect("json"))?;
        file.sync_all()
    })();
    drop(file);
    let placed = written.and_then(|()| match (fs.link)(&tmp, &path) {
        Ok(()) => Ok(Placed::Exclusive),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(Placed::AlreadyThere),
        Err(_) if path.symlink_metadata().is_ok() => Ok(Placed::AlreadyThere),
        Err(_) => std::fs::rename(&tmp, &path).map(|()| Placed::Replaced),
    });
    let _ = std::fs::remove_file(&tmp);
    let placed = placed?;
    if placed == Placed::AlreadyThere {
        return Ok(placed);
    }
    // The name in `claimed/`, and `claimed/` in the state directory.
    let synced = (fs.sync_dir)(&claimed).and_then(|()| (fs.sync_dir)(dir));
    if let Err(e) = synced {
        let _ = release_unused_marker(dir, &marker.sandbox_id, placed);
        return Err(e);
    }
    Ok(placed)
}

/// Takes back the marker of `sandbox_id` when no byte of any claim was
/// written, so the package was not used, and only if this process linked
/// it ([`Placed::Exclusive`]). `Ok(true)` when it was removed.
pub fn release_unused_marker(
    dir: &Path,
    sandbox_id: &str,
    placed: Placed,
) -> std::io::Result<bool> {
    if placed != Placed::Exclusive {
        return Ok(false);
    }
    std::fs::remove_file(marker_path(dir, sandbox_id))?;
    Ok(true)
}

/// The environment variable of a profile's base URL:
/// `KLAV_FORWARD_<PROFILE>_URL`, upper case, `-` as `_`.
pub fn profile_variable(profile: &str) -> Option<String> {
    let ok = !profile.is_empty()
        && profile
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    ok.then(|| {
        format!(
            "KLAV_FORWARD_{}_URL",
            profile.to_ascii_uppercase().replace('-', "_")
        )
    })
}

/// The shell lines of mode (a): the forwarder's URL and each profile's
/// base URL. No secret: the URLs are of `127.0.0.1`.
pub fn env_lines(port: u16, profiles: &[String]) -> String {
    let base = format!("http://127.0.0.1:{port}");
    let mut out =
        String::from("# Written by klav-forward up (ADR 0036): local URLs only, no secrets.\n");
    out.push_str(&format!("export KLAV_FORWARD_URL='{base}'\n"));
    for profile in profiles {
        if let Some(var) = profile_variable(profile) {
            out.push_str(&format!("export {var}='{base}/{profile}'\n"));
        }
    }
    out
}

/// What [`env_lines`] exports, as JSON (`klav-forward env --json`): the
/// forwarder's `url` (as `up --json` names it), each profile's base URL
/// in `profiles`, and each `export` line as `env`. A profile name
/// [`profile_variable`] refuses is left out of all three, as of the lines.
pub fn env_json(port: u16, profiles: &[String]) -> serde_json::Value {
    let base = format!("http://127.0.0.1:{port}");
    let mut by_profile = serde_json::Map::new();
    let mut env = serde_json::Map::new();
    env.insert("KLAV_FORWARD_URL".into(), base.clone().into());
    for profile in profiles {
        if let Some(var) = profile_variable(profile) {
            let url = format!("{base}/{profile}");
            by_profile.insert(profile.clone(), url.clone().into());
            env.insert(var, url.into());
        }
    }
    serde_json::json!({ "url": base, "profiles": by_profile, "env": env })
}

/// Where the shell lines went.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvWritten {
    /// Where asked.
    There(PathBuf),
    /// Not writable there (not root, say): in the state directory instead.
    Fallback {
        /// Where it was asked for.
        wanted: PathBuf,
        /// Where it went.
        written: PathBuf,
    },
}

impl EnvWritten {
    /// The file to `source`.
    pub fn path(&self) -> &Path {
        match self {
            Self::There(p) | Self::Fallback { written: p, .. } => p,
        }
    }
}

/// Writes the shell lines to `wanted`, or to the state directory when
/// `wanted` cannot be written. The file is 0644 there: it holds no secret
/// and every login shell of the sandbox reads it.
pub fn write_env(
    wanted: &Path,
    state_dir: &Path,
    port: u16,
    profiles: &[String],
) -> std::io::Result<EnvWritten> {
    let text = env_lines(port, profiles);
    let public = |path: &Path| -> std::io::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        write_private(path, text.as_bytes())?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644))
    };
    match public(wanted) {
        Ok(()) => Ok(EnvWritten::There(wanted.to_owned())),
        Err(_) => {
            let written = state_dir.join(ENV_FILE);
            public(&written)?;
            Ok(EnvWritten::Fallback {
                wanted: wanted.to_owned(),
                written,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bound() -> Bound {
        Bound {
            sandbox_id: "11111111-2222-3333-4444-555555555555".into(),
            label: "chat-1".into(),
            profiles: vec!["northflank".into(), "my-api".into()],
            expires_at: 1,
        }
    }

    #[test]
    fn the_lines_name_each_profile_and_nothing_else() {
        let text = env_lines(8790, &bound().profiles);
        assert_eq!(
            text.lines().skip(1).collect::<Vec<_>>(),
            [
                "export KLAV_FORWARD_URL='http://127.0.0.1:8790'",
                "export KLAV_FORWARD_NORTHFLANK_URL='http://127.0.0.1:8790/northflank'",
                "export KLAV_FORWARD_MY_API_URL='http://127.0.0.1:8790/my-api'",
            ]
        );
        // A name the proxy would never send is left out, never quoted in.
        assert_eq!(profile_variable("x'; rm -rf /"), None);
        assert_eq!(profile_variable(""), None);
    }

    #[test]
    fn the_state_round_trips_privately_and_the_env_falls_back() {
        use std::os::unix::fs::PermissionsExt;
        let dir = crate::TestDir::new();
        assert_eq!(load_state(dir.path()), Ok(None));
        let state = State {
            v: 1,
            pid: 7,
            port: 8790,
            sandbox: bound(),
        };
        save_state(dir.path(), &state).expect("save");
        assert_eq!(load_state(dir.path()), Ok(Some(state)));
        let mode = std::fs::metadata(dir.path().join(STATE_FILE))
            .expect("meta")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);

        let wanted = dir.path().join("profile.d/klav-forward.sh");
        let there = write_env(&wanted, dir.path(), 8790, &bound().profiles).expect("env");
        assert_eq!(there, EnvWritten::There(wanted.clone()));
        let mode = std::fs::metadata(&wanted)
            .expect("meta")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o644);

        let blocked = dir.path().join("not-a-dir");
        std::fs::write(&blocked, b"").expect("file");
        let fell = write_env(&blocked.join("x.sh"), dir.path(), 8790, &[]).expect("env");
        assert_eq!(fell.path(), dir.path().join(ENV_FILE));
    }

    #[test]
    fn a_marker_is_written_once_privately_and_never_read_as_absent() {
        use std::os::unix::fs::PermissionsExt;
        let dir = crate::TestDir::new();
        let state = dir.path().join("state");
        let id = "11111111-2222-3333-4444-555555555555";
        assert_eq!(read_marker(&state, id), Claimed::No);
        let marker = Marker {
            v: MARKER_VERSION,
            sandbox_id: id.into(),
            at: 1_700_000_000_000,
        };
        assert_eq!(
            write_marker(&state, &marker).expect("write"),
            Placed::Exclusive
        );
        assert_eq!(read_marker(&state, id), Claimed::Yes(marker.clone()));
        // Only once: a second writer finds it there.
        assert_eq!(
            write_marker(&state, &marker).expect("write"),
            Placed::AlreadyThere
        );
        let mode = |p: &Path| std::fs::metadata(p).expect("meta").permissions().mode() & 0o777;
        assert_eq!(mode(&marker_path(&state, id)), 0o600);
        assert_eq!(mode(&state.join(CLAIMED_DIR)), 0o700);
        assert_eq!(mode(&state), 0o700);
        // No temporary file is left behind.
        let names: Vec<_> = std::fs::read_dir(state.join(CLAIMED_DIR))
            .expect("dir")
            .map(|e| e.expect("entry").file_name())
            .collect();
        assert_eq!(names, [std::ffi::OsString::from(id)]);

        // Another format, or a file that does not parse: claimed.
        std::fs::write(
            marker_path(&state, id),
            br#"{"v":2,"sandbox_id":"x","at":1,"more":true}"#,
        )
        .expect("write");
        assert_eq!(read_marker(&state, id), Claimed::OtherVersion(2));
        for bad in [&b""[..], b"{\"v\":1", b"{\"v\":1,\"at\":1}", b"[1]"] {
            std::fs::write(marker_path(&state, id), bad).expect("write");
            assert!(
                matches!(read_marker(&state, id), Claimed::Unreadable(_)),
                "{}",
                String::from_utf8_lossy(bad)
            );
        }
        // One that cannot be read (a directory under its name): claimed.
        std::fs::remove_file(marker_path(&state, id)).expect("remove");
        std::fs::create_dir(marker_path(&state, id)).expect("dir");
        assert!(matches!(read_marker(&state, id), Claimed::Unreadable(_)));
        std::fs::remove_dir(marker_path(&state, id)).expect("rmdir");
        assert_eq!(read_marker(&state, id), Claimed::No);
    }

    fn marker(id: &str) -> Marker {
        Marker {
            v: MARKER_VERSION,
            sandbox_id: id.into(),
            at: 1_700_000_000_000,
        }
    }

    /// Without hard links, the marker is renamed into place, and another
    /// `up` at the same instant may have done the same and be claiming:
    /// such a marker is never taken back, though this process's claim
    /// never left. Only one this process linked is.
    #[test]
    fn only_a_marker_this_process_linked_is_taken_back() {
        let dir = crate::TestDir::new();
        let state = dir.path().join("state");
        let id = "11111111-2222-3333-4444-555555555555";
        let no_links = MarkerFs {
            link: |_, _| Err(std::io::ErrorKind::Unsupported.into()),
            ..MarkerFs::REAL
        };
        let placed = write_marker_with(&state, &marker(id), &no_links).expect("write");
        assert_eq!(placed, Placed::Replaced);
        assert!(!release_unused_marker(&state, id, placed).expect("release"));
        assert_eq!(read_marker(&state, id), Claimed::Yes(marker(id)));

        let other = "22222222-2222-3333-4444-555555555555";
        let placed = write_marker(&state, &marker(other)).expect("write");
        assert_eq!(placed, Placed::Exclusive);
        assert!(release_unused_marker(&state, other, placed).expect("release"));
        assert_eq!(read_marker(&state, other), Claimed::No);
        // Found there: never this process's to take back.
        write_marker(&state, &marker(other)).expect("write");
        let placed = write_marker(&state, &marker(other)).expect("write");
        assert_eq!(placed, Placed::AlreadyThere);
        assert!(!release_unused_marker(&state, other, placed).expect("release"));
        assert_eq!(read_marker(&state, other), Claimed::Yes(marker(other)));
    }

    /// A directory `fsync` that fails is an error, so nothing is claimed,
    /// and the marker this process linked is taken back (its claim never
    /// left); `claimed/` and the state directory are both synced.
    #[test]
    fn a_marker_that_may_not_be_durable_is_an_error() {
        let dir = crate::TestDir::new();
        let state = dir.path().join("state");
        let id = "11111111-2222-3333-4444-555555555555";
        let fails = MarkerFs {
            sync_dir: |_| Err(std::io::Error::other("fsync failed")),
            ..MarkerFs::REAL
        };
        assert!(write_marker_with(&state, &marker(id), &fails).is_err());
        assert_eq!(read_marker(&state, id), Claimed::No);

        // Which directories are synced, in order.
        static SYNCED: std::sync::Mutex<Vec<PathBuf>> = std::sync::Mutex::new(Vec::new());
        let records = MarkerFs {
            sync_dir: |d| {
                SYNCED.lock().expect("lock").push(d.to_owned());
                Ok(())
            },
            ..MarkerFs::REAL
        };
        write_marker_with(&state, &marker(id), &records).expect("write");
        assert_eq!(
            *SYNCED.lock().expect("lock"),
            [state.join(CLAIMED_DIR), state.clone()]
        );
    }

    /// The state directory and `claimed/` must be private to this user:
    /// one its group or others can write is refused, with the fix, and no
    /// marker is written there.
    #[test]
    fn a_state_directory_others_can_write_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = crate::TestDir::new();
        let state = dir.path().join("state");
        create_private_dir(&state).expect("dir");
        let me = own_uid(&state).expect("uid");
        assert_eq!(check_private(&state, me), Ok(()));
        assert!(check_state_dir(&state).is_ok());
        // The probe leaves nothing behind.
        assert_eq!(std::fs::read_dir(&state).expect("dir").count(), 0);
        assert!(check_private(&state, me.wrapping_add(1)).is_err());
        let id = "11111111-2222-3333-4444-555555555555";
        for mode in [0o777, 0o775, 0o757] {
            std::fs::set_permissions(&state, std::fs::Permissions::from_mode(mode)).expect("chmod");
            let (fix, why) = check_state_dir(&state).expect_err("not private");
            assert_eq!(fix, state);
            assert!(why.contains("chmod go-w"), "{why}");
            assert!(write_marker(&state, &marker(id)).is_err(), "{mode:o}");
            assert_eq!(read_marker(&state, id), Claimed::No, "{mode:o}");
        }
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        std::fs::create_dir(state.join(CLAIMED_DIR)).expect("claimed");
        std::fs::set_permissions(
            state.join(CLAIMED_DIR),
            std::fs::Permissions::from_mode(0o777),
        )
        .expect("chmod");
        let (fix, _) = check_state_dir(&state).expect_err("not private");
        assert_eq!(fix, state.join(CLAIMED_DIR));
        assert!(write_marker(&state, &marker(id)).is_err());
        assert_eq!(read_marker(&state, id), Claimed::No);
        // No temporary file is left in `claimed/` either.
        assert_eq!(
            std::fs::read_dir(state.join(CLAIMED_DIR))
                .expect("dir")
                .count(),
            0
        );
    }
}
