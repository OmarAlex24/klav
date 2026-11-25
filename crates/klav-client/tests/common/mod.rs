//! Runs the real `klav-server` binary (SQLite) for integration tests.
//!
//! The binary is not a dependency (the server is AGPL, ADR 0003): it is
//! looked up next to the test executable, where `cargo test --workspace`
//! builds it.
//!
//! The server binds port 0 and the helper reads the address it got from its
//! `klav-server listening` log line, so no other process can take the port
//! between choosing it and binding it. Restarts bind that same port again,
//! because the clients keep the URL. The whole log (stdout and stderr) goes
//! to `server.log`, and a failed start prints it before the temporary
//! directory is deleted.

#![allow(dead_code, unreachable_pub)]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

/// How long one start may take before the helper gives up.
const START_TIMEOUT: Duration = Duration::from_secs(20);

/// A frozen server; dropping it lets the server run again.
pub struct Frozen(u32);

impl Drop for Frozen {
    fn drop(&mut self) {
        let _ = Command::new("kill")
            .arg("-CONT")
            .arg(self.0.to_string())
            .status();
    }
}

pub struct ServerProcess {
    pub dir: tempfile::TempDir,
    pub url: String,
    child: Option<Child>,
}

pub fn server_binary() -> PathBuf {
    let exe = std::env::current_exe().expect("current exe");
    let dir = exe
        .parent()
        .and_then(Path::parent)
        .expect("target directory");
    let bin = dir.join(format!("klav-server{}", std::env::consts::EXE_SUFFIX));
    assert!(
        bin.exists(),
        "{} not found: run `cargo build -p klav-server` (cargo test --workspace builds it)",
        bin.display()
    );
    bin
}

/// A fresh directory for the server's database and files. On Linux it goes
/// in `/dev/shm` (memory) when there is one: on the CI machine the disk is
/// shared with builds running in parallel, and a single fsync there can
/// stall for longer than [`START_TIMEOUT`]. A test server needs no durable
/// storage, and nothing is executed from this directory.
fn server_dir() -> tempfile::TempDir {
    let shm = Path::new("/dev/shm");
    if cfg!(target_os = "linux")
        && shm.is_dir()
        && let Ok(dir) = tempfile::Builder::new()
            .prefix("klav-server-")
            .tempdir_in(shm)
    {
        return dir;
    }
    tempfile::tempdir().expect("tempdir")
}

/// The address in a `klav-server listening` line of `log` (JSON format).
fn listening_address(log: &str) -> Option<SocketAddr> {
    log.lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .find(|event| event["message"] == "klav-server listening")
        .and_then(|event| event["listen"].as_str()?.parse().ok())
}

impl ServerProcess {
    /// Starts a fresh server. `access_ttl_secs` shortens the access token
    /// lifetime to exercise refreshes.
    pub fn start(access_ttl_secs: u64) -> Self {
        Self::start_with(access_ttl_secs, "")
    }

    /// A server that accepts no new accounts (`allow_registration = false`).
    pub fn start_closed() -> Self {
        Self::start_with(900, "allow_registration = false\n")
    }

    /// A server that purges every second: an account whose deletion time
    /// came is gone a second later (ADR 0037 §5.2).
    pub fn start_purging() -> Self {
        Self::start_with(900, "[retention]\npurge_interval_secs = 1\n")
    }

    /// A server in `invite` mode (ADR 0048 §1.1), as production runs it:
    /// `allow_registration = false` next to it.
    pub fn start_invite() -> Self {
        Self::start_config("registration_mode = \"invite\"\nallow_registration = false\n")
    }

    /// A server with `top` before its sections (top-level keys, or whole
    /// sections such as `[limits]`).
    pub fn start_config(top: &str) -> Self {
        Self::start_with(900, top)
    }

    /// `klav-server invite create <args>` against this server's database
    /// (ADR 0048 §1.4): returns the code and the invite's ID. The code is a
    /// test value: never printed.
    pub fn create_invite(&self, args: &[&str]) -> (String, String) {
        let out = self.invite_command(&[&["create"], args].concat());
        let field = |name: &str| {
            out.lines()
                .find_map(|l| l.strip_prefix(name))
                .map(|v| v.trim().to_owned())
                .expect("invite create prints the field")
        };
        (field("code:"), field("id:"))
    }

    /// `klav-server invite revoke <id>`.
    pub fn revoke_invite(&self, id: &str) {
        self.invite_command(&["revoke", id]);
    }

    fn invite_command(&self, args: &[&str]) -> String {
        let out = std::process::Command::new(server_binary())
            .arg("invite")
            .args(args)
            .arg("--config")
            .arg(self.dir.path().join("server.toml"))
            .output()
            .expect("run klav-server invite");
        assert!(
            out.status.success(),
            "klav-server invite {} failed: {}",
            args.first().copied().unwrap_or_default(),
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).expect("utf-8")
    }

    fn start_with(access_ttl_secs: u64, top_level: &str) -> Self {
        let dir = server_dir();
        let config = format!(
            "listen = \"127.0.0.1:0\"\n\
             database_url = \"sqlite://{db}\"\n\
             data_dir = \"{data}\"\n\
             {top_level}\
             [log]\nformat = \"json\"\nfilter = \"warn,klav_server=info\"\n\
             [sessions]\naccess_ttl_secs = {access_ttl_secs}\n\
             [rate_limit]\nauth_ip_burst = 10000\nauth_email_burst = 10000\nip_burst = 100000\naccount_burst = 100000\ninvite_ip_burst = 10000\n",
            db = dir.path().join("klav.db").display(),
            data = dir.path().join("data").display(),
        );
        std::fs::write(dir.path().join("server.toml"), config).expect("config");
        let mut server = Self {
            dir,
            url: String::new(),
            child: None,
        };
        let addr = server.boot();
        server.url = format!("http://{addr}");
        // Later boots bind this same port: the clients keep the URL.
        let config_path = server.dir.path().join("server.toml");
        let config = std::fs::read_to_string(&config_path).expect("config");
        let config = config.replacen(
            "listen = \"127.0.0.1:0\"",
            &format!("listen = \"{addr}\""),
            1,
        );
        std::fs::write(&config_path, config).expect("config");
        server
    }

    /// Spawns the server and waits for its `listening` line. Fails at once,
    /// with the log, if the server exits first.
    fn boot(&mut self) -> SocketAddr {
        let log_path = self.dir.path().join("server.log");
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .expect("server log");
        // Every boot appends to the same log; only this boot's lines count.
        let from = usize::try_from(log.metadata().expect("server log").len()).expect("log size");
        let child = Command::new(server_binary())
            .arg("--config")
            .arg(self.dir.path().join("server.toml"))
            .stdout(log.try_clone().expect("server log"))
            .stderr(log)
            .spawn()
            .expect("spawn klav-server");
        self.child = Some(child);
        let read_log = || std::fs::read(&log_path).unwrap_or_default();
        let deadline = Instant::now() + START_TIMEOUT;
        loop {
            let log = read_log();
            let this_boot = String::from_utf8_lossy(log.get(from..).unwrap_or_default());
            if let Some(addr) = listening_address(&this_boot) {
                return addr;
            }
            let exited = self
                .child
                .as_mut()
                .and_then(|child| child.try_wait().expect("klav-server status"));
            if let Some(status) = exited {
                self.child = None;
                panic!(
                    "klav-server exited before listening ({status}); server.log:\n{}",
                    String::from_utf8_lossy(&read_log())
                );
            }
            assert!(
                Instant::now() < deadline,
                "klav-server did not listen within {START_TIMEOUT:?} and is still running; server.log:\n{}",
                String::from_utf8_lossy(&log)
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// Stops the server gracefully (SIGTERM).
    pub fn stop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = Command::new("kill")
                .arg("-TERM")
                .arg(child.id().to_string())
                .status();
            let deadline = Instant::now() + Duration::from_secs(10);
            while Instant::now() < deadline {
                if child.try_wait().ok().flatten().is_some() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    /// Freezes the server (SIGSTOP): it takes connections and never
    /// answers, until the guard is dropped (SIGCONT), also on a panic.
    pub fn freeze(&self) -> Frozen {
        let pid = self.child.as_ref().expect("running").id();
        let _ = Command::new("kill")
            .arg("-STOP")
            .arg(pid.to_string())
            .status();
        Frozen(pid)
    }

    pub fn restart(&mut self) {
        self.stop();
        self.boot();
    }

    fn db_files(&self) -> Vec<PathBuf> {
        ["klav.db", "klav.db-wal", "klav.db-shm"]
            .iter()
            .map(|f| self.dir.path().join(f))
            .collect()
    }

    /// Copies the database (with its WAL) to `name` while stopped.
    pub fn snapshot(&mut self, name: &str) {
        self.stop();
        let target = self.dir.path().join(name);
        std::fs::create_dir_all(&target).expect("snapshot dir");
        for file in self.db_files() {
            if file.exists() {
                std::fs::copy(&file, target.join(file.file_name().expect("name"))).expect("copy");
            }
        }
        self.boot();
    }

    /// Puts back a snapshot: the server "forgets" everything after it, like
    /// a malicious operator or an old backup would (threat T7).
    pub fn restore(&mut self, name: &str) {
        self.stop();
        let source = self.dir.path().join(name);
        for file in self.db_files() {
            let _ = std::fs::remove_file(&file);
            let saved = source.join(file.file_name().expect("name"));
            if saved.exists() {
                std::fs::copy(&saved, &file).expect("restore");
            }
        }
        self.boot();
    }
}

impl Drop for ServerProcess {
    fn drop(&mut self) {
        self.stop();
    }
}
