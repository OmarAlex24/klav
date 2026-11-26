//! `klav-proxy init`, `serve` and `status` (ADR 0036 §2, §14).
//!
//! The proxy pairs like any agent (ADR 0014 §1): `init` makes its identity,
//! registers it and shows the 6 words the person compares before
//! approving. Its private key lives only where the proxy runs, in a file
//! created with mode 0600 or in the macOS keychain, never in an
//! environment variable of the platform (ADR 0036 §11): the proxy refuses
//! to start with `KLAV_AGENT_KEY` set, and with a key file other users
//! could read.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use klav_client::{ClientError, ClientResult, Home};
use klav_sdk::keystore::{KEY_ENV, KeyStore, KeyStoreChoice};
use klav_sdk::{Agent, Registration, Session};
use serde::Serialize;

use crate::proxy::{GRANT_REFRESH, ProxyState, router};

/// Name the proxy registers with by default.
pub const DEFAULT_NAME: &str = "klav-proxy";
/// Port of the local listener by default.
pub const DEFAULT_PORT: u16 = 8790;
/// Longest the sweep before serving may take (ADR 0036 E3.3): a server that
/// does not answer delays the start this long at most.
const FIRST_SWEEP_LIMIT: std::time::Duration = std::time::Duration::from_secs(15);

/// Variables that replace the system's TLS roots on Linux
/// (`rustls-native-certs` loads only those paths when one is set).
pub const ROOTS_ENV: [&str; 2] = ["SSL_CERT_FILE", "SSL_CERT_DIR"];

/// Which of the variables the proxy refuses to start with are set: only
/// their names, never their values. `main` reads it from the process with
/// [`StartEnv::from_process`]; tests pass their own with
/// [`StartEnv::from_lookup`], so the machine running them cannot change
/// the outcome.
///
/// It must be the process's own environment in the binary: the agent SDK
/// reads `KLAV_AGENT_KEY` from the process when it loads the key, and
/// rustls reads `SSL_CERT_FILE`/`SSL_CERT_DIR` when it loads the roots.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StartEnv {
    set: Vec<&'static str>,
}

impl StartEnv {
    /// The variables checked, in the order they are reported.
    pub const CHECKED: [&'static str; 3] = [KEY_ENV, ROOTS_ENV[0], ROOTS_ENV[1]];

    /// From this process's environment.
    pub fn from_process() -> Self {
        Self::from_lookup(|name| std::env::var_os(name))
    }

    /// From `lookup` (a variable counts as set when it returns a value,
    /// even an empty one, as for the process).
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<std::ffi::OsString>) -> Self {
        Self {
            set: Self::CHECKED
                .into_iter()
                .filter(|name| lookup(name).is_some())
                .collect(),
        }
    }

    fn is_set(&self, name: &str) -> bool {
        self.set.contains(&name)
    }
}

/// Refuses to go on with the agent key in the environment, or with a
/// variable that replaces the TLS roots: a hosting platform keeps
/// environment variables where its staff and its API can read and change
/// them. The message names the variable, never its value (`env` does not
/// even hold it).
pub fn refuse_key_in_env(env: &StartEnv) -> ClientResult<()> {
    if env.is_set(KEY_ENV) {
        return Err(ClientError::Invalid(format!(
            "{KEY_ENV} is set: klav-proxy never takes its key from the environment (a hosting platform keeps environment variables where its staff and its API can read them). Unset it; the key lives in a 0600 file in the proxy's data directory or in the keychain"
        )));
    }
    if let Some(var) = ROOTS_ENV.iter().find(|v| env.is_set(v)) {
        return Err(ClientError::Invalid(format!(
            "{var} is set: it would replace the certificates klav-proxy trusts for the providers, and whoever can change the environment could then read every credential it sends. Unset it; the proxy uses the system's CA bundle"
        )));
    }
    Ok(())
}

/// Refuses a key file that is not a regular file of this user with mode
/// 0600, or that sits in a directory others may write to or that another
/// user owns (they could swap it).
pub fn check_key_file(path: &Path) -> ClientResult<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let meta = std::fs::symlink_metadata(path)
            .map_err(|e| ClientError::NotFound(format!("key file {}: {e}", path.display())))?;
        if !meta.file_type().is_file() {
            return Err(ClientError::Invalid(format!(
                "key file {} is not a regular file",
                path.display()
            )));
        }
        let me = nix::unistd::geteuid().as_raw();
        if meta.uid() != me {
            return Err(ClientError::Invalid(format!(
                "key file {} belongs to another user (uid {}); klav-proxy only starts with a key file of its own user",
                path.display(),
                meta.uid()
            )));
        }
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o177 != 0 {
            return Err(ClientError::Invalid(format!(
                "key file {} has mode {mode:o}; klav-proxy only starts with 600 (run `chmod 600` on it)",
                path.display()
            )));
        }
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let dir = std::fs::metadata(parent)
            .map_err(|e| ClientError::NotFound(format!("{}: {e}", parent.display())))?;
        if !dir_owner_ok(dir.uid(), me) {
            return Err(ClientError::Invalid(format!(
                "the directory of the key file, {}, belongs to another user (uid {}): they could replace the key; klav-proxy only starts when the directory is its own user's or root's",
                parent.display(),
                dir.uid()
            )));
        }
        let dir_mode = dir.permissions().mode() & 0o777;
        if dir_mode & 0o022 != 0 {
            return Err(ClientError::Invalid(format!(
                "the directory of the key file, {}, has mode {dir_mode:o}: others could replace the key; klav-proxy only starts when only its owner can write there (run `chmod go-w` on it)",
                parent.display()
            )));
        }
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// Whether a key file's directory owner can be trusted: this user, or
/// root (who can read the key anyway).
#[cfg(unix)]
fn dir_owner_ok(owner: u32, me: u32) -> bool {
    owner == me || owner == 0
}

/// What `init` needs.
pub struct InitOptions {
    /// The proxy's data directory.
    pub home: Home,
    /// Name shown to the person.
    pub name: String,
    /// Server URL.
    pub server: String,
    /// The account's e-mail.
    pub email: String,
    /// Where to keep the key.
    pub key_store: KeyStoreChoice,
    /// The key file, instead of `<home>/agents/<name>.key`.
    pub key_file: Option<PathBuf>,
    /// The variables it refuses to start with.
    pub env: StartEnv,
}

/// What `init` shows.
#[derive(Debug, Serialize)]
pub struct InitReport {
    /// Agent ID.
    pub agent_id: String,
    /// Name.
    pub name: String,
    /// The 6 words the person compares.
    pub pairing_code: String,
    /// Where the key is.
    pub key_store: String,
    /// When the request lapses (Unix ms).
    pub expires_at: i64,
}

/// Registers the proxy as an agent.
pub async fn init(opts: InitOptions) -> ClientResult<InitReport> {
    refuse_key_in_env(&opts.env)?;
    let key_store = KeyStore::choose(
        &opts.home,
        &opts.name,
        opts.key_store,
        opts.key_file.as_deref(),
    )?;
    let (_, registered) = Agent::register(
        &opts.home,
        Registration {
            name: opts.name,
            server: opts.server,
            email: opts.email,
            note: Some(
                "Klav credential proxy: puts the credentials you grant it into HTTP requests, without handing them out".into(),
            ),
            key_store,
        },
    )
    .await?;
    Ok(InitReport {
        agent_id: registered.agent_id.to_string(),
        name: registered.name,
        pairing_code: registered.pairing_code,
        key_store: registered.key_store,
        expires_at: registered.expires_at,
    })
}

/// Whether a proxy named `name` is registered in `home` (its registration
/// file exists; whether it reads is `serve`'s to say).
pub fn is_registered(home: &Home, name: &str) -> bool {
    klav_sdk::config::agents_dir(home)
        .join(format!("{name}.json"))
        .exists()
}

/// Whether another proxy answers on the local socket of `name` in `home`.
pub fn answers_locally(home: &Home, name: &str) -> bool {
    std::os::unix::net::UnixStream::connect(klav_client::local_proxy::socket_path(home, name))
        .is_ok()
}

/// Why a registered proxy never serves until the person acts: still
/// pending, revoked, or its account waits to be deleted. `serve
/// --if-registered` (the Mac's LaunchAgent) then exits 0, so launchd doesn't
/// start it again every 30 s; a pause or a network error is `None`, and
/// fails `serve` as before, so launchd retries it.
pub async fn never_serves(home: &Home, name: &str, env: &StartEnv) -> Option<&'static str> {
    let mut agent = load(home, name, env).ok()?;
    let me = agent.me().await.ok()?;
    match me.status {
        klav_proto::agent::AgentStatus::Pending => Some("the person has not approved it yet"),
        klav_proto::agent::AgentStatus::Revoked => Some("it was revoked"),
        _ if me.account_delete_at.is_some() => Some("its account waits to be deleted"),
        _ => None,
    }
}

/// Loads the proxy's agent after the key checks.
pub fn load(home: &Home, name: &str, env: &StartEnv) -> ClientResult<Agent> {
    refuse_key_in_env(env)?;
    let config = klav_sdk::AgentConfig::load(home, name)?;
    if let KeyStore::File { path } = &config.key_store {
        check_key_file(path)?;
    }
    Agent::load(home, name)
}

/// What `status` shows: never a value.
#[derive(Debug, Serialize)]
pub struct StatusReport {
    /// The agent's state as the server reports it.
    pub agent: klav_sdk::AgentState,
    /// The profiles of its grant (only when it is active).
    pub profiles: Vec<ProfileView>,
    /// The live sandboxes in its store (ADR 0036 §4).
    pub sandboxes: Vec<crate::sandboxes::SandboxView>,
    /// Sandbox ends the Klav server has not taken yet.
    pub unsent_ends: usize,
    /// Theft signals the proxy could not confirm the Klav server logged:
    /// the person's log may not show them.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub unconfirmed_thefts: Vec<crate::claims::UnconfirmedTheft>,
    /// Why the store could not be read, if it could not.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub store_error: Option<String>,
    /// What the redactor counted since the proxy last started (T149):
    /// whole values replaced and pieces left as they are, per profile.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redactions: Option<crate::counts::CountsView>,
    /// Why the counts could not be read, if they could not.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redactions_error: Option<String>,
    /// What the `klav-proxy serve` that last wrote this home's record
    /// recorded about its memory (ADR 0044 §3). A `serve` replaces the
    /// record only once it listens, and removes it when it stops if it is
    /// still its own; absent when there is none, which says nothing about
    /// whether a proxy runs. `status` can't tell whether that `serve` still
    /// runs, and this is not the `status` process's own.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory: Option<crate::memory::MemoryRecord>,
    /// Why that record could not be read, if it could not.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_error: Option<String>,
}

/// A profile, without anything secret.
#[derive(Debug, Serialize)]
pub struct ProfileView {
    /// Name.
    pub name: String,
    /// The item it uses.
    pub item_id: String,
    /// Where it sends requests.
    pub upstream: String,
    /// The header the value goes in.
    pub header: String,
    /// Calls per minute.
    pub rate_per_minute: u32,
}

/// The proxy's state and profiles.
pub async fn status(home: &Home, name: &str, env: &StartEnv) -> ClientResult<StatusReport> {
    let mut agent = load(home, name, env)?;
    let state = agent.state().await?;
    let profiles =
        if state.status == klav_proto::agent::AgentStatus::Active && state.paused.is_none() {
            let session = Session::open(agent).await?;
            crate::profiles::of(&session)
                .all()
                .into_iter()
                .map(|p| ProfileView {
                    name: p.name.clone(),
                    item_id: p.item.to_string(),
                    upstream: p.upstream.origin(),
                    header: p.header.as_str().to_owned(),
                    rate_per_minute: p.rate_per_minute,
                })
                .collect()
        } else {
            Vec::new()
        };
    // The store as `serve` left it, read with the same checks. A proxy
    // that is serving may change it meanwhile: this is a snapshot.
    let (sandboxes, unsent_ends, unconfirmed_thefts, store_error) =
        match crate::sandboxes::Sandboxes::open(
            crate::sandboxes::Sandboxes::path_in(home, name),
            Arc::new(crate::sandboxes::SystemClock),
        ) {
            Ok(store) => (
                store.views().await,
                store.unsent().await,
                store.unconfirmed_thefts().await,
                None,
            ),
            Err(e) => (Vec::new(), 0, Vec::new(), Some(e)),
        };
    let (redactions, redactions_error) =
        match crate::counts::Counts::read(&crate::counts::Counts::path_in(home, name)) {
            Ok(view) => (view, None),
            Err(e) => (None, Some(e)),
        };
    let (memory, memory_error) = match read_memory(&memory_path_in(home, name)) {
        Ok(record) => (record, None),
        Err(e) => (None, Some(e)),
    };
    Ok(StatusReport {
        agent: state,
        profiles,
        sandboxes,
        unsent_ends,
        unconfirmed_thefts,
        store_error,
        redactions,
        redactions_error,
        memory,
        memory_error,
    })
}

/// The file's extension, next to the agent's registration: what the
/// `serve` that last wrote it turned on in its memory, for `status`.
pub const MEMORY_EXTENSION: &str = "memory";

/// Where `serve` writes its memory record for agent `name`.
pub fn memory_path_in(home: &Home, name: &str) -> PathBuf {
    home.dir()
        .join("agents")
        .join(format!("{name}.{MEMORY_EXTENSION}"))
}

/// Writes `bytes` to `path` (0600, replaced atomically).
fn write_memory(path: &Path, bytes: &[u8]) -> Result<(), String> {
    klav_client::home::write_private(path, bytes).map_err(|e| e.to_string())
}

/// Removes the record at `path` when it is still `ours` (byte for byte):
/// a `serve` that stops leaves a later `serve`'s record alone.
fn remove_own_memory(path: &Path, ours: &[u8]) {
    let Ok(Some(bytes)) = read_checked(path) else {
        return;
    };
    if bytes == ours
        && let Err(e) = std::fs::remove_file(path)
    {
        tracing::warn!(error = %e, "cannot remove this serve's memory record");
    }
}

/// The record a `serve` left at `path`, if one did and has not removed it.
/// Read with the sandbox store's checks: a regular file of this user, mode
/// 0600, in a directory only its owner can write; opened without following
/// a link and without blocking (a FIFO answers at once), checked again once
/// open, and at most [`crate::memory::MAX_RECORD_BYTES`].
pub fn read_memory(path: &Path) -> Result<Option<crate::memory::MemoryRecord>, String> {
    match read_checked(path)? {
        None => Ok(None),
        Some(bytes) => crate::memory::MemoryRecord::from_file(&bytes).map(Some),
    }
}

fn read_checked(path: &Path) -> Result<Option<Vec<u8>>, String> {
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("memory record {}: {e}", path.display())),
        Ok(_) => {}
    }
    check_record_file(path)?;
    let file =
        open_no_follow(path).map_err(|e| format!("memory record {}: {e}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let meta = file
            .metadata()
            .map_err(|e| format!("memory record {}: {e}", path.display()))?;
        if !meta.file_type().is_file()
            || meta.uid() != nix::unistd::geteuid().as_raw()
            || meta.permissions().mode() & 0o177 != 0
        {
            return Err(format!(
                "memory record {} changed while it was opened; status reads only a regular 0600 file of its own user",
                path.display()
            ));
        }
    }
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(
        &mut std::io::Read::take(file, crate::memory::MAX_RECORD_BYTES + 1),
        &mut bytes,
    )
    .map_err(|e| format!("memory record {}: {e}", path.display()))?;
    if bytes.len() as u64 > crate::memory::MAX_RECORD_BYTES {
        return Err(format!(
            "memory record {} is larger than {} bytes",
            path.display(),
            crate::memory::MAX_RECORD_BYTES
        ));
    }
    Ok(Some(bytes))
}

/// [`check_key_file`]'s checks, worded for the memory record: a file
/// `status` only reads, which a `serve` of this user writes 0600.
fn check_record_file(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let shown = path.display();
        let meta =
            std::fs::symlink_metadata(path).map_err(|e| format!("memory record {shown}: {e}"))?;
        if !meta.file_type().is_file() {
            return Err(format!(
                "memory record {shown} is not a regular file; status reads only the regular 0600 file klav-proxy serve writes"
            ));
        }
        let me = nix::unistd::geteuid().as_raw();
        if meta.uid() != me {
            return Err(format!(
                "memory record {shown} belongs to another user (uid {}); status reads only a record of its own user",
                meta.uid()
            ));
        }
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o177 != 0 {
            return Err(format!(
                "memory record {shown} has mode {mode:o}; status reads only a 0600 record, as klav-proxy serve writes it"
            ));
        }
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let dir = std::fs::metadata(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
        if !dir_owner_ok(dir.uid(), me) {
            return Err(format!(
                "the directory of the memory record, {}, belongs to another user (uid {}): they could replace the record; status reads it only when the directory is its own user's or root's",
                parent.display(),
                dir.uid()
            ));
        }
        let dir_mode = dir.permissions().mode() & 0o777;
        if dir_mode & 0o022 != 0 {
            return Err(format!(
                "the directory of the memory record, {}, has mode {dir_mode:o}: others could replace the record; status reads it only when only its owner can write there",
                parent.display()
            ));
        }
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

#[cfg(unix)]
fn open_no_follow(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)
}

#[cfg(not(unix))]
fn open_no_follow(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::File::open(path)
}

/// The `Memory` lines of `status` (ADR 0044 §3, Omar's decisions 15, 24 and
/// 27 of 2026-11-19): what the `serve` that last wrote this record recorded,
/// said as that, never as this proxy's present state. A `serve` writes it
/// once it listens, so the words hold even when a later `serve` listened
/// and then failed to write its own. Every string from
/// the record goes through [`klav_core::text::is_hidden`] first; `now_ms`
/// is this clock.
pub fn memory_words(report: &StatusReport, now_ms: i64) -> String {
    memory_words_of(
        report.memory.as_ref(),
        report.memory_error.as_deref(),
        now_ms,
    )
}

fn memory_words_of(
    memory: Option<&crate::memory::MemoryRecord>,
    error: Option<&str>,
    now_ms: i64,
) -> String {
    if let Some(e) = error {
        return format!(
            "Memory: the record a klav-proxy serve writes on this home once it listens cannot be read: {}",
            visible(e)
        );
    }
    let Some(record) = memory else {
        return "Memory: no record from a klav-proxy serve on this home.".into();
    };
    let m = &record.report;
    // Decision 19's state first, also when the record says `locked` too
    // (decision 28): neither "locked" nor "not locked".
    let locked = visible(&crate::memory::lock_words(
        m,
        "--no-memory-lock or KLAV_PROXY_MEMORY_LOCK=off",
    ));
    format!(
        "Memory, as recorded by the klav-proxy serve that last wrote this record, {}; status can't tell whether that proxy still runs: core dumps {}, {}, {locked}.",
        ago(record.since, now_ms),
        m.core_dumps.as_str(),
        m.dumpable_words()
    )
}

/// `text` without the characters [`klav_core::text::is_hidden`] names.
fn visible(text: &str) -> String {
    text.chars()
        .filter(|c| !klav_core::text::is_hidden(*c))
        .collect()
}

/// When `since_ms` (Unix ms) was, from `now_ms`, in minutes, hours or days;
/// a time that is not a sane past instant is said as such.
fn ago(since_ms: i64, now_ms: i64) -> String {
    let Some(elapsed) = now_ms.checked_sub(since_ms).filter(|_| since_ms > 0) else {
        return "at a time the record does not give correctly".into();
    };
    if elapsed < 0 {
        return "at a time ahead of this machine's clock".into();
    }
    let minutes = elapsed / 60_000;
    match minutes {
        0..60 => format!("{minutes} min ago"),
        60..2880 => format!("{} h ago", minutes / 60),
        _ => format!("{} days ago", minutes / 1440),
    }
}

/// What `serve` needs.
pub struct ServeOptions {
    /// The proxy's data directory.
    pub home: Home,
    /// Its agent name.
    pub name: String,
    /// Port on 127.0.0.1.
    pub port: u16,
    /// Where sandboxes' forwarders reach it (ADR 0036 §6): the pinned TLS
    /// 1.3 channel on this address, or none.
    pub channel: Option<SocketAddr>,
    /// Largest request body.
    pub max_body: usize,
    /// Longest call to a provider.
    pub request_timeout: Duration,
    /// Refuse every profile call on the loopback listener (ADR 0042 §3):
    /// the issuer API and the channel keep working.
    pub no_local_calls: bool,
    /// The local socket for the person's apps on this machine (ADR 0036
    /// E3.5).
    pub control_socket: ControlSocket,
    /// The variables it refuses to start with.
    pub env: StartEnv,
}

/// Where the local socket listens (ADR 0036 E3.5, layer 11).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlSocket {
    /// `<home>/agents/<name>.sock`; if it cannot be bound (a path too long
    /// for a unix socket, another proxy on it), the proxy serves without it
    /// and says why.
    Default,
    /// This path; not binding it stops the proxy.
    At(PathBuf),
    /// None.
    Off,
}

/// Opens the session and serves mode (a) on `127.0.0.1` until a shutdown
/// signal. That listener only ever binds loopback. Sandboxes reach the
/// proxy only through the channel listener (`--channel`), where every
/// connection proves a key in a TLS 1.3 handshake (ADR 0036 §6).
///
/// `memory` is what `main` turned on before anything read the key (ADR
/// 0044 §3): it is logged, and written next to the registration once the
/// proxy listens, for `status`. A `serve` that fails before it listens
/// leaves an existing record as it is: it may be a running `serve`'s.
pub async fn serve(opts: ServeOptions, memory: crate::memory::MemoryReport) -> Result<(), String> {
    serve_until(opts, memory, shutdown()).await
}

/// [`serve`] until `stop` completes (tests stop it themselves).
pub async fn serve_until(
    opts: ServeOptions,
    memory: crate::memory::MemoryReport,
    stop: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<(), String> {
    log_memory(&memory);
    let record = memory_path_in(&opts.home, &opts.name);
    let bound = bind(opts).await?;
    // Listening: this `serve`'s record replaces any other at once
    // (`write_private`: a temporary file, mode 0600, renamed into place).
    let bytes = crate::memory::MemoryRecord {
        report: memory,
        since: crate::sandboxes::Clock::now_ms(&crate::sandboxes::SystemClock),
    }
    .to_file()
    .and_then(|bytes| write_memory(&record, &bytes).map(|()| bytes))
    .map_err(|e| format!("cannot write the memory record: {e}"))?;
    let result = bound.run(stop).await;
    remove_own_memory(&record, &bytes);
    result
}

/// One line with what took effect, and a warning when the memory is not
/// locked or the lock could be neither confirmed nor undone (decision 19:
/// `lock_not_undone` sits next to `locked`). Neither holds anything but
/// limits and error codes.
fn log_memory(memory: &crate::memory::MemoryReport) {
    tracing::info!(
        core_dumps = memory.core_dumps.as_str(),
        dumpable = memory.dumpable_words(),
        locked = memory.locked,
        lock_turned_off = memory.lock_turned_off,
        vm_lck_kib = memory.vm_lck_kib.unwrap_or(0),
        lock_not_undone = memory.lock_not_undone,
        "klav-proxy memory"
    );
    if let Some(warning) = crate::memory::unlocked_warning(memory) {
        tracing::warn!("{warning}");
    }
}

/// A proxy that opened its session, its store and its listener, and does
/// not serve yet ([`Bound::run`]).
pub struct Bound {
    state: Arc<ProxyState>,
    listener: tokio::net::TcpListener,
    port: u16,
    channel: Option<crate::channel::ChannelListener>,
    local: Option<crate::local::LocalSocket>,
    first_sweep_limit: Duration,
}

impl Bound {
    /// The port it listens on (the one the system picked for `--port 0`).
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The channel's address, if it serves one.
    pub fn channel_addr(&self) -> Option<SocketAddr> {
        self.channel
            .as_ref()
            .map(crate::channel::ChannelListener::local_addr)
    }

    /// Where its local socket listens, if it serves one.
    pub fn control_socket(&self) -> Option<&Path> {
        self.local.as_ref().map(crate::local::LocalSocket::path)
    }

    /// Its state (tests).
    pub fn state(&self) -> Arc<ProxyState> {
        Arc::clone(&self.state)
    }

    /// Tests: a shorter bound on the sweep before serving.
    #[cfg(test)]
    pub(crate) fn with_first_sweep_limit(mut self, limit: Duration) -> Self {
        self.first_sweep_limit = limit;
        self
    }

    /// Serves until `stop` completes, refreshing the grant, sweeping the
    /// sandboxes and sending the heartbeat meanwhile.
    pub async fn run(
        self,
        stop: impl std::future::Future<Output = ()> + Send + 'static,
    ) -> Result<(), String> {
        use futures_util::FutureExt as _;
        let Self {
            state,
            listener,
            channel,
            local,
            first_sweep_limit,
            ..
        } = self;
        let stop = stop.boxed().shared();
        // Whether the account's MCP gateway is on (ADR 0049 §9), before the
        // first call to an MCP profile rather than 30 s later. Off until
        // the server says it is on.
        if state.profiles().all().iter().any(|p| p.mcp.is_some())
            && let Err(e) = state.refresh_gone_issuers().await
        {
            tracing::warn!(
                kind = crate::proxy::redacted_kind(&e),
                "could not ask the server whether the MCP gateway is on; tool calls wait for the next refresh"
            );
        }
        let refresher = {
            let state = Arc::clone(&state);
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(GRANT_REFRESH);
                tick.tick().await;
                loop {
                    tick.tick().await;
                    if let Err(e) = state.refresh().await {
                        tracing::warn!(kind = refresh_kind(&e), "could not refresh the grant");
                    }
                }
            })
        };
        // Ends what the person revoked, what expired, went unclaimed or lost
        // its issuer: once before serving (a restart may find all of it; ADR
        // 0036 E3.3, T169), then every SWEEP_EVERY with the ends sent. The
        // first is bounded: a silent server must not keep the proxy from
        // starting, and its sandboxes get no access from that server anyway.
        // Cut short, it commits nothing it did not end (review of #348, 1).
        if tokio::time::timeout(
            first_sweep_limit,
            crate::sandboxes::end_revoked_and_due(&state),
        )
        .await
        .is_err()
        {
            tracing::warn!(
                "the first sweep took longer than {} s; serving, and the next sweep tries again",
                first_sweep_limit.as_secs()
            );
        }
        let sweeper = {
            let state = Arc::clone(&state);
            tokio::spawn(async move {
                // The ends of the first sweep go out here, unbounded and
                // without holding up the listeners: a send cut short could
                // leave an end the server took in the outbox (review of
                // #348, 5).
                let first = crate::sandboxes::flush(&state);
                sweep_every(crate::sandboxes::SWEEP_EVERY, first, || {
                    crate::sandboxes::sweep(&state)
                })
                .await;
            })
        };
        // Its store's epoch, then a heartbeat every 5 min with live
        // sandboxes, 30 without, sooner on a change (ADR 0036 E3.3).
        let heartbeat = {
            let state = Arc::clone(&state);
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(crate::heartbeat::LOOK_EVERY);
                loop {
                    tick.tick().await;
                    crate::heartbeat::beat(&state, false).await;
                }
            })
        };
        let counts = state.counts();
        let counter = tokio::spawn(Arc::clone(&counts).write_on_change());
        // The local socket (E3.5): after the first sweep, so its list never
        // shows a sandbox the person already revoked.
        let serving = crate::local::Serving {
            channel: channel.is_some(),
        };
        let local = local.map(|socket| {
            tokio::spawn(crate::local::serve(
                socket,
                Arc::clone(&state),
                serving,
                stop.clone(),
            ))
        });
        let channel = channel.map(|channel| {
            tokio::spawn(crate::channel::serve(
                channel,
                Arc::clone(&state),
                stop.clone(),
            ))
        });
        let listener = crate::listener::Limited::new(listener, crate::proxy::MAX_CONNECTIONS);
        let served = axum::serve(listener, router(state))
            .with_graceful_shutdown(stop)
            .await
            .map_err(|e| format!("server: {e}"));
        let channel = match channel {
            Some(task) => task.await.unwrap_or_else(|e| Err(format!("channel: {e}"))),
            None => Ok(()),
        };
        if let Some(task) = local {
            // It ends with `stop`, and removes its socket file.
            let _ = task.await;
        }
        refresher.abort();
        sweeper.abort();
        heartbeat.abort();
        counter.abort();
        if let Err(e) = counts.write() {
            tracing::warn!(error = %e, "could not save the redaction counts");
        }
        served.and(channel)
    }
}

/// Runs `first`, then `sweep` every `every`, counted from before `first`:
/// the first tick is now (the sweep before serving was it), so a slow
/// `first` is followed by a sweep at once rather than `every` after it
/// (second delta review of #348, 1).
async fn sweep_every<F, S, T>(every: Duration, first: F, mut sweep: S)
where
    F: std::future::Future<Output = ()>,
    S: FnMut() -> T,
    T: std::future::Future,
{
    let mut tick = tokio::time::interval(every);
    tick.tick().await;
    first.await;
    loop {
        tick.tick().await;
        sweep().await;
    }
}

/// How long the port's holder has to answer (a forwarder whose proxy is
/// out of reach answers after its connect timeout).
const PORT_PROBE: std::time::Duration = std::time::Duration::from_secs(12);

/// Why the loopback port is taken, as its holder's answer says
/// ([`klav_forward::http::port_holder`]), and the flag that moves this
/// proxy (papercut 12: `klav-forward` also defaults to 8790).
pub(crate) fn port_in_use(
    addr: SocketAddr,
    e: &std::io::Error,
    holder: klav_forward::http::PortHolder,
) -> String {
    use klav_forward::http::PortHolder;
    let who = match holder {
        PortHolder::Forwarder => {
            "klav-forward listens there (its default port is 8790 too, so the two collide when both run on one machine). Start klav-proxy with --port <another port>, or that forwarder with `klav-forward up --port <another port>`"
        }
        PortHolder::Proxy => {
            "another klav-proxy listens there. Stop it, or start this one with --port <another port>"
        }
        PortHolder::Other => {
            "another program listens there. Start klav-proxy with --port <another port>"
        }
        PortHolder::Unknown => {
            "something listens there and did not answer like a klav-forward or a klav-proxy (both default to 8790). Start klav-proxy with --port <another port>"
        }
    };
    format!("cannot listen on {addr}: {e}: {who}.")
}

/// Opens the session, the sandbox store and the loopback listener.
pub async fn bind(opts: ServeOptions) -> Result<Bound, String> {
    refuse_key_in_env(&opts.env).map_err(|e| e.to_string())?;
    let roots = crate::net::check_roots()?;
    let agent = load(&opts.home, &opts.name, &opts.env).map_err(|e| e.to_string())?;
    let session = Session::open(agent).await.map_err(|e| e.to_string())?;
    let client =
        crate::net::upstream_client().map_err(|e| format!("TLS client: {}", e.without_url()))?;
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, opts.port));
    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(listener) => listener,
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
            let holder = klav_forward::http::port_holder(opts.port, PORT_PROBE).await;
            return Err(port_in_use(addr, &e, holder));
        }
        Err(e) => return Err(format!("cannot listen on {addr}: {e}")),
    };
    // The bound address: with `--port 0` the system picks the port.
    let bound = listener
        .local_addr()
        .map_err(|e| format!("cannot read the bound address: {e}"))?;
    // Its sandboxes, in a 0600 file next to its registration: refused
    // when it cannot be read rather than started over (it would forget
    // sandboxes it still has to end).
    let store = crate::sandboxes::Sandboxes::path_in(&opts.home, &opts.name);
    let sandboxes =
        crate::sandboxes::Sandboxes::open(store.clone(), Arc::new(crate::sandboxes::SystemClock))?;
    // Its store's epoch and last heartbeat, in their own 0600 file next to
    // it: one it cannot read starts a new epoch (ADR 0036 E3.3).
    let heartbeats = crate::heartbeat::Heartbeats::open(crate::heartbeat::path_of(&store));
    // The redaction counts of this run, for `status` (T149).
    let counts = crate::counts::Counts::at(
        crate::counts::Counts::path_in(&opts.home, &opts.name),
        crate::sandboxes::Clock::now_ms(&crate::sandboxes::SystemClock),
    )
    .map_err(|e| format!("cannot write the redaction counts: {e}"))?;
    let channel = match opts.channel {
        Some(addr) => {
            let signer = session.agent().tls_server_signer();
            Some(crate::channel::bind(addr, signer).await?)
        }
        None => None,
    };
    let local = bind_local(&opts.home, &opts.name, &opts.control_socket)?;
    let state = ProxyState::new(session, client, bound.port())
        .with_max_body(opts.max_body)
        .with_request_timeout(opts.request_timeout)
        .with_sandboxes(sandboxes)
        .with_heartbeats(heartbeats)
        .with_counts(counts);
    let state = Arc::new(if opts.no_local_calls {
        state.without_local_calls()
    } else {
        state
    });
    let profiles = state.profiles();
    tracing::info!(
        listen = %bound,
        max_connections = crate::proxy::MAX_CONNECTIONS,
        max_in_flight = crate::proxy::MAX_IN_FLIGHT,
        profiles = profiles.len(),
        local_calls = !opts.no_local_calls,
        roots,
        "klav-proxy listening"
    );
    if let Some(channel) = &channel {
        tracing::info!(
            channel = %channel.local_addr(),
            max_connections = crate::channel::MAX_CHANNEL_CONNECTIONS,
            "klav-proxy channel listening (TLS 1.3, pinned keys)"
        );
    }
    if let Some(local) = &local {
        tracing::info!(
            socket = %local.path().display(),
            "klav-proxy local socket listening (this user only)"
        );
    }
    Ok(Bound {
        state,
        listener,
        port: bound.port(),
        channel,
        local,
        first_sweep_limit: FIRST_SWEEP_LIMIT,
    })
}

/// Binds the local socket `choice` names (ADR 0036 E3.5). The default
/// path is best effort: a proxy on a server, or with a home too deep for a
/// unix socket's path, serves without it.
fn bind_local(
    home: &Home,
    name: &str,
    choice: &ControlSocket,
) -> Result<Option<crate::local::LocalSocket>, String> {
    match choice {
        ControlSocket::Off => Ok(None),
        ControlSocket::At(path) => crate::local::LocalSocket::bind(path)
            .map(Some)
            .map_err(|e| format!("local socket: {e}")),
        ControlSocket::Default => {
            let path = klav_client::local_proxy::socket_path(home, name);
            match crate::local::LocalSocket::bind(&path) {
                Ok(socket) => Ok(Some(socket)),
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "serving without the local socket: the Klav app on this machine cannot list or revoke sandboxes through it"
                    );
                    Ok(None)
                }
            }
        }
    }
}

fn refresh_kind(e: &ClientError) -> &'static str {
    match e {
        ClientError::Network(_) => "network",
        ClientError::Denied(_) => "denied",
        ClientError::Paused(_) => "paused",
        _ => "other",
    }
}

async fn shutdown() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        if let Ok(mut s) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            s.recv().await;
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! {
        () = ctrl_c => {}
        () = term => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Papercut 12: a taken port names its holder and the flag that moves
    /// each program; the default port does not change.
    #[test]
    fn a_taken_port_names_its_holder_and_the_flag_that_moves_it() {
        use klav_forward::http::PortHolder;
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 8790));
        let e = std::io::Error::from(std::io::ErrorKind::AddrInUse);
        let forwarder = port_in_use(addr, &e, PortHolder::Forwarder);
        assert!(forwarder.starts_with("cannot listen on 127.0.0.1:8790: "));
        assert!(forwarder.contains("klav-forward listens there"));
        assert!(forwarder.contains("--port <another port>"));
        assert!(forwarder.contains("klav-forward up --port"));
        let proxy = port_in_use(addr, &e, PortHolder::Proxy);
        assert!(proxy.contains("another klav-proxy listens there"));
        let other = port_in_use(addr, &e, PortHolder::Other);
        assert!(other.contains("another program listens there"));
        let unknown = port_in_use(addr, &e, PortHolder::Unknown);
        assert!(unknown.contains("did not answer like a klav-forward or a klav-proxy"));
        for message in [proxy, other, unknown] {
            assert!(message.contains("--port <another port>"), "{message}");
        }
    }

    /// After a first send slower than the period, the next sweep comes at
    /// once and the one after a period from the first sweep, not a period
    /// after the send (scaled: 1 s period, 2 s send, 3.4 s watched; the
    /// order before this fix gives one sweep, at 3 s).
    #[tokio::test]
    async fn the_next_sweep_does_not_wait_for_a_slow_first_send() {
        let start = std::time::Instant::now();
        let at = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen = std::sync::Arc::clone(&at);
        let task = tokio::spawn(sweep_every(
            Duration::from_secs(1),
            tokio::time::sleep(Duration::from_secs(2)),
            move || {
                seen.lock().unwrap().push(start.elapsed());
                std::future::ready(())
            },
        ));
        tokio::time::sleep(Duration::from_millis(3400)).await;
        task.abort();
        let at = at.lock().unwrap().clone();
        assert_eq!(at.len(), 3, "{at:?}");
        assert!(at[0] < Duration::from_millis(2500), "{at:?}");
    }

    #[test]
    fn a_key_file_wider_than_0600_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("k.key");
        klav_client::home::write_private(&path, b"x").unwrap();
        check_key_file(&path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for mode in [0o640, 0o604, 0o700, 0o610] {
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
                assert!(check_key_file(&path).is_err(), "{mode:o}");
            }
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
            check_key_file(&path).unwrap();
            // A symlink to a 0600 file is not the key file.
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            let link = dir.path().join("link.key");
            std::os::unix::fs::symlink(&path, &link).unwrap();
            assert!(check_key_file(&link).is_err());
            // A directory others may write to could swap the key.
            for (mode, ok) in [(0o770, false), (0o703, false), (0o755, true), (0o700, true)] {
                std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(mode))
                    .unwrap();
                assert_eq!(check_key_file(&path).is_ok(), ok, "{mode:o}");
            }
        }
    }

    #[test]
    fn variables_that_replace_the_roots_or_hold_the_key_are_refused_by_name() {
        assert_eq!(ROOTS_ENV, ["SSL_CERT_FILE", "SSL_CERT_DIR"]);
        refuse_key_in_env(&StartEnv::default()).unwrap();
        // An unrelated variable does not count.
        let other = StartEnv::from_lookup(|n| (n == "PATH").then(|| "/usr/bin".into()));
        refuse_key_in_env(&other).unwrap();
        for var in StartEnv::CHECKED {
            for value in ["/tmp/attacker-roots.pem", ""] {
                let env = StartEnv::from_lookup(|n| (n == var).then(|| value.into()));
                let err = refuse_key_in_env(&env).unwrap_err().to_string();
                assert!(err.contains(&format!("{var} is set")), "{err}");
                assert!(!err.contains("attacker-roots"), "never the value: {err}");
            }
        }
        // The key is named first when both are set.
        let both = StartEnv::from_lookup(|n| Some(n.into()));
        let err = refuse_key_in_env(&both).unwrap_err().to_string();
        assert!(err.contains("KLAV_AGENT_KEY is set"), "{err}");
    }

    #[cfg(unix)]
    #[test]
    fn a_key_directory_of_another_user_is_refused() {
        // A directory another user owns cannot be made here without root:
        // the rule is checked on its own, and a directory of this user
        // passes in the test above.
        assert!(dir_owner_ok(501, 501));
        assert!(dir_owner_ok(0, 501));
        assert!(!dir_owner_ok(502, 501));
    }

    #[test]
    fn a_key_file_is_created_0600() {
        let dir = tempfile::tempdir().unwrap();
        let home = Home::at(dir.path().join("home"));
        let store = KeyStore::choose(&home, "p", KeyStoreChoice::File, None).unwrap();
        store
            .save(
                &home,
                klav_core::ids::AgentId::generate(),
                &klav_core::crypto::identity::IdentityKeyPair::generate(),
            )
            .unwrap();
        let KeyStore::File { path } = store else {
            unreachable!()
        };
        check_key_file(&path).unwrap();
    }

    fn record(why: &str, since: i64) -> crate::memory::MemoryRecord {
        crate::memory::MemoryRecord {
            report: crate::memory::MemoryReport {
                core_dumps: crate::memory::CoreDumps::Off,
                dumpable: Some(false),
                locked: false,
                lock_turned_off: false,
                vm_lck_kib: None,
                why: Some(why.into()),
                lock_not_undone: false,
            },
            since,
        }
    }

    /// Finding 2 of the review of #466: `status` reads the record only as
    /// the sandbox store is read, and never blocks on it.
    #[cfg(unix)]
    #[test]
    fn a_hostile_memory_record_is_refused_and_never_blocks() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("klav-proxy.memory");
        assert_eq!(read_memory(&path), Ok(None));
        let good = record("the memlock limit is 8 MiB", 7);
        klav_client::home::write_private(&path, &good.to_file().expect("bytes")).expect("write");
        assert_eq!(read_memory(&path), Ok(Some(good.clone())));
        // Another mode.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        let err = read_memory(&path).expect_err("0644");
        assert!(
            err.contains("memory record") && err.contains("644"),
            "{err}"
        );
        // Worded for a file status only reads, never as the key file.
        assert!(err.contains("status reads only a 0600 record"), "{err}");
        assert!(
            !err.contains("key") && !err.contains("only starts"),
            "{err}"
        );
        std::fs::remove_file(&path).expect("rm");
        // A link to a good record.
        let target = dir.path().join("elsewhere");
        klav_client::home::write_private(&target, &good.to_file().expect("bytes")).expect("write");
        std::os::unix::fs::symlink(&target, &path).expect("symlink");
        let err = read_memory(&path).expect_err("link");
        assert!(err.contains("not a regular file"), "{err}");
        std::fs::remove_file(&path).expect("rm");
        // A FIFO: refused at once, without waiting for a writer.
        let made = std::process::Command::new("mkfifo")
            .arg(&path)
            .status()
            .expect("mkfifo");
        assert!(made.success());
        let fifo = path.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(read_memory(&fifo));
        });
        let err = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("status blocked on a FIFO")
            .expect_err("fifo");
        assert!(err.contains("not a regular file"), "{err}");
        // The open itself never blocks either, where a FIFO replaced the
        // file after the check.
        let opened = open_no_follow(&path);
        assert!(opened.is_ok(), "{opened:?}");
        std::fs::remove_file(&path).expect("rm");
        // Too large.
        klav_client::home::write_private(&path, &vec![b' '; 5000]).expect("write");
        let err = read_memory(&path).expect_err("large");
        assert!(err.contains("larger than 4096 bytes"), "{err}");
    }

    /// A record of another user is refused. Only root can make one, and a
    /// test never escalates: by hand, as root (a Linux container will do),
    /// with `cargo test -p klav-proxy --lib
    /// app::tests::a_memory_record_of_another_user_is_refused -- --ignored`.
    #[cfg(unix)]
    #[test]
    #[ignore = "needs root to make a file of another user; run by hand"]
    fn a_memory_record_of_another_user_is_refused() {
        assert!(
            nix::unistd::geteuid().is_root(),
            "precondition not met: only root can make a file of another user"
        );
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("klav-proxy.memory");
        let good = record("the memlock limit is 8 MiB", 7);
        klav_client::home::write_private(&path, &good.to_file().expect("bytes")).expect("write");
        std::os::unix::fs::chown(&path, Some(65534), None).expect("chown");
        let err = read_memory(&path).expect_err("owner");
        assert!(err.contains("another user"), "{err}");
        assert!(
            err.contains("status reads only a record of its own user"),
            "{err}"
        );
    }

    /// Every string from the record is filtered, and no time breaks the
    /// arithmetic.
    #[test]
    fn the_memory_words_filter_the_record_and_survive_any_time() {
        let now = 1_800_000_000_000;
        let hostile = record("limit\u{1b}[2J 8 MiB\u{7}\r\n\u{202e}x", now - 120_000);
        let words = memory_words_of(Some(&hostile), None, now);
        assert!(!words.chars().any(klav_core::text::is_hidden), "{words:?}");
        assert!(words.contains("not locked: limit[2J 8 MiBx"), "{words}");
        assert!(words.contains("2 min ago; status can't tell whether that proxy still runs"));
        let err = memory_words_of(None, Some("bad\u{1b}]0;title\u{7}"), now);
        assert!(!err.chars().any(klav_core::text::is_hidden), "{err:?}");
        for since in [i64::MIN, -1, 0] {
            let words = memory_words_of(Some(&record("x", since)), None, now);
            assert!(
                words.contains("at a time the record does not give correctly"),
                "{since}: {words}"
            );
        }
        for since in [i64::MAX, now + 1] {
            let words = memory_words_of(Some(&record("x", since)), None, now);
            assert!(
                words.contains("ahead of this machine's clock"),
                "{since}: {words}"
            );
        }
        assert!(
            memory_words_of(Some(&record("x", 1)), None, i64::MIN)
                .contains("does not give correctly")
        );
        assert!(
            memory_words_of(Some(&record("x", now - 3 * 86_400_000)), None, now)
                .contains("3 days ago")
        );
        assert!(
            memory_words_of(Some(&record("x", now - 5 * 3_600_000)), None, now).contains("5 h ago")
        );
        let mut off = record(crate::memory::TURNED_OFF, now);
        off.report.lock_turned_off = true;
        assert!(
            memory_words_of(Some(&off), None, now).contains("not locked: the lock is turned off")
        );
        let mut locked = record("x", now);
        locked.report.locked = true;
        locked.report.why = None;
        locked.report.vm_lck_kib = Some(2832);
        assert!(
            memory_words_of(Some(&locked), None, now)
                .contains("locked on fault (VmLck 2832 kB at start)")
        );
        // Decision 19: a lock that could be neither confirmed nor undone is
        // said as that, never as locked or as not locked.
        let mut half = record(
            "mlockall returned success but VmLck could not be read back, and munlockall then failed (EPERM)",
            now - 60_000,
        );
        half.report.lock_not_undone = true;
        let words = memory_words_of(Some(&half), None, now);
        assert!(
            words.ends_with(
                "core dumps off, not dumpable, lock could not be confirmed and could not be undone: mlockall returned success but VmLck could not be read back, and munlockall then failed (EPERM)."
            ),
            "{words}"
        );
        assert!(
            !words.contains("not locked") && !words.contains("locked on fault"),
            "{words}"
        );
    }

    /// Decision 28 and the branch order: a record that says both `locked`
    /// and `lock_not_undone` (built here, past `from_file`'s reading) is
    /// said as the half state, never as locked; and the half state's real
    /// reason, from `lock_with`, reaches the line whole.
    #[test]
    fn the_half_state_comes_before_locked_in_the_memory_words() {
        let now = 1_800_000_000_000;
        let real = crate::memory::tests::half_state_report();
        let why = real.why.clone().expect("why");
        let mut both = record("x", now - 60_000);
        both.report = crate::memory::MemoryReport {
            locked: true,
            vm_lck_kib: Some(2832),
            ..real
        };
        let words = memory_words_of(Some(&both), None, now);
        assert!(
            words.ends_with(&format!(
                "core dumps off, not dumpable, lock could not be confirmed and could not be undone: {why}."
            )),
            "{words}"
        );
        assert!(!words.contains("locked on fault"), "{words}");
        assert!(why.contains("munlockall then failed (EPERM"), "{why}");
        assert!(why.contains("stays raised"), "{why}");
        // The same record, through its file, as `status --json` shows it.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("klav-proxy.memory");
        let mut file: serde_json::Value =
            serde_json::from_slice(&both.to_file().expect("bytes")).expect("json");
        assert_eq!(file["locked"], true, "the file says both");
        file["lock_not_undone"] = true.into();
        klav_client::home::write_private(&path, &serde_json::to_vec(&file).expect("bytes"))
            .expect("write");
        let read = read_memory(&path).expect("read").expect("record");
        assert_eq!(serde_json::to_value(&read).expect("json")["locked"], false);
        assert_eq!(memory_words_of(Some(&read), None, now), words);
    }
}
