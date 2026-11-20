//! Helpers for the CLI integration tests: a real `klav-server` and the
//! `klav` binary run with its own `KLAV_HOME`.

#![allow(dead_code, unreachable_pub)]

pub mod browser;
pub mod mcp;
pub mod server;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

pub use server::ServerProcess;

pub const PASSWORD: &str = "correct horse battery staple";

/// The workspace binaries `klav` may start, or that the tests start, with
/// the package that builds each one.
pub const BINARIES: [(&str, &str); 5] = [
    ("klavd", "klav-daemon"),
    ("klav-native-host", "klav-daemon"),
    ("klav-server", "klav-server"),
    ("klav-proxy", "klav-proxy"),
    ("klav-forward", "klav-forward"),
];

/// `name`, from this build's own output directory (next to `klav`), and
/// only from there: a test never runs a binary it did not build. Missing,
/// the test fails at once with the command that builds it.
#[track_caller]
pub fn built_binary(name: &str) -> PathBuf {
    let package = BINARIES
        .iter()
        .find(|(n, _)| *n == name)
        .map_or("klav-cli", |(_, p)| *p);
    let bin = Path::new(env!("CARGO_BIN_EXE_klav"))
        .with_file_name(format!("{name}{}", std::env::consts::EXE_SUFFIX));
    assert!(
        bin.is_file(),
        "{} not found: run `cargo build -p {package}` (`cargo test --workspace` builds it). The tests never fall back to an installed {name}",
        bin.display()
    );
    bin
}

/// The caller's `PATH` without any directory that holds `klav` or one of
/// [`BINARIES`] (`~/.cargo/bin`, a Homebrew or `/usr/local/bin` install):
/// where `klav` looks for `klavd` or `klav-native-host` after the
/// directory it runs from, so an installed one is never found.
pub fn path_without_installed_klav() -> std::ffi::OsString {
    without_installed_klav(&std::env::var_os("PATH").unwrap_or_default())
}

/// [`path_without_installed_klav`] for a given `PATH`.
pub fn without_installed_klav(path: &std::ffi::OsStr) -> std::ffi::OsString {
    let names = std::iter::once("klav").chain(BINARIES.iter().map(|(n, _)| *n));
    let names: Vec<&str> = names.collect();
    let kept: Vec<PathBuf> = std::env::split_paths(path)
        .filter(|dir| {
            !names.iter().any(|n| {
                dir.join(format!("{n}{}", std::env::consts::EXE_SUFFIX))
                    .exists()
            })
        })
        .collect();
    std::env::join_paths(kept).expect("PATH")
}

/// One device: a `KLAV_HOME` directory.
pub struct Device {
    pub home: PathBuf,
}

pub struct Run {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl Run {
    #[track_caller]
    pub fn ok(self) -> Self {
        assert_eq!(
            self.code, 0,
            "command failed\nstdout: {}\nstderr: {}",
            self.stdout, self.stderr
        );
        self
    }

    /// The command failed.
    #[track_caller]
    pub fn err(self) -> Self {
        assert_ne!(
            self.code, 0,
            "command succeeded\nstdout: {}\nstderr: {}",
            self.stdout, self.stderr
        );
        self
    }
}

impl Device {
    pub fn new(root: &Path, name: &str) -> Self {
        Self {
            home: root.join(name),
        }
    }

    /// `klav` with this device's home. The `klavd` it starts is the one
    /// this build made, next to it: the test fails here if it is missing,
    /// and no installed one is on the `PATH` it gets.
    #[track_caller]
    pub fn command(&self) -> Command {
        built_binary("klavd");
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_klav"));
        // Never wait on a fingerprint in tests (klavd inherits this).
        cmd.env("KLAV_HOME", &self.home)
            .env("PATH", path_without_installed_klav())
            .env("KLAV_NO_TOUCH_ID", "1")
            .env_remove("KLAV_NO_DAEMON")
            .env_remove("KLAV_SERVER")
            // No test may reach the real server by forgetting --server
            // (ADR 0028 §2).
            .env("KLAV_NO_DEFAULT_SERVER", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        cmd
    }

    /// Runs `klav <args>` feeding `stdin`.
    pub fn run(&self, args: &[&str], stdin: &str) -> Run {
        self.run_in(None, args, stdin)
    }

    /// Like [`Device::run`], in the directory `dir`.
    pub fn run_in(&self, dir: Option<&Path>, args: &[&str], stdin: &str) -> Run {
        let mut cmd = self.command();
        if let Some(dir) = dir {
            cmd.current_dir(dir);
        }
        let mut child = cmd.args(args).spawn().expect("spawn klav");
        // A command that exits without reading its input closes the pipe
        // first: not a failure of the test, which checks the result below.
        match child
            .stdin
            .take()
            .expect("stdin")
            .write_all(stdin.as_bytes())
        {
            Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {}
            other => other.expect("write stdin"),
        }
        let Output {
            status,
            stdout,
            stderr,
        } = child.wait_with_output().expect("wait klav");
        Run {
            code: status.code().unwrap_or(-1),
            stdout: String::from_utf8(stdout).expect("utf-8 stdout"),
            stderr: String::from_utf8(stderr).expect("utf-8 stderr"),
        }
    }

    /// Starts an unlocking command in the background (stdout and stderr
    /// go to files in `dir`).
    pub fn spawn_unlocked(&self, dir: &Path, args: &[&str]) -> std::process::Child {
        let mut cmd = self.command();
        cmd.current_dir(dir)
            .arg("--password-stdin")
            .args(args)
            .stdout(Stdio::null())
            .stderr(
                std::fs::File::create(dir.join("klav-bg.log")).map_or(Stdio::null(), Stdio::from),
            );
        let mut child = cmd.spawn().expect("spawn klav");
        child
            .stdin
            .take()
            .expect("stdin")
            .write_all(format!("{PASSWORD}\n").as_bytes())
            .expect("write stdin");
        child
    }

    /// Like [`Device::unlocked`], in the directory `dir`.
    pub fn unlocked_in(&self, dir: &Path, args: &[&str], extra: &str) -> Run {
        let mut all = vec!["--password-stdin"];
        all.extend_from_slice(args);
        self.run_in(Some(dir), &all, &format!("{PASSWORD}\n{extra}"))
    }

    /// Creates an account on `server` with this device; returns the path
    /// of the Emergency Kit.
    pub fn signup(&self, server: &ServerProcess, email: &str) -> PathBuf {
        let kit = self.home.with_extension("kit.txt");
        self.run(
            &[
                "--password-stdin",
                "signup",
                "--server",
                &server.url,
                "--email",
                email,
                "--device-name",
                "test",
                "--emergency-kit",
                kit.to_str().expect("utf-8 path"),
            ],
            &format!("{PASSWORD}\n"),
        )
        .ok();
        kit
    }

    /// Runs an unlocking command: the master password is the first line.
    pub fn unlocked(&self, args: &[&str], extra: &str) -> Run {
        let mut all = vec!["--password-stdin"];
        all.extend_from_slice(args);
        self.run(&all, &format!("{PASSWORD}\n{extra}"))
    }
}

/// Polls `check` every 50 ms for up to `secs` seconds.
pub fn wait_until(secs: u64, mut check: impl FnMut() -> bool) -> bool {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(secs);
    while std::time::Instant::now() < deadline {
        if check() {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    check()
}

/// Unix permission bits of `path`.
pub fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .expect("metadata")
        .permissions()
        .mode()
        & 0o777
}

/// Waits for a background child, killing it after `secs` seconds.
pub fn wait_child(child: &mut std::process::Child, secs: u64) -> i32 {
    let done = wait_until(secs, || child.try_wait().ok().flatten().is_some());
    if !done {
        let _ = child.kill();
    }
    child.wait().expect("wait").code().unwrap_or(-1)
}
