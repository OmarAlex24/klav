//! The `klav-forward` binary as a setup script runs it, against a small
//! stand-in proxy on the real pinned channel (the proxy's own logic is
//! tested end to end in `klav-proxy`): `up --daemon`, `status`, `env`,
//! `down`; and that the package never shows in the forwarder's arguments,
//! environment, output, log or files.

#![allow(clippy::unwrap_used)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

use klav_core::crypto::channel::TlsSigner;
use klav_core::crypto::identity::IdentityKeyPair;
use klav_core::crypto::sandbox::{SandboxPackage, SandboxSecret, encode_package, proxy_pin};
use klav_core::ids::SandboxId;
use tokio::io::AsyncWriteExt;
use tokio_rustls::TlsAcceptor;
use zeroize::Zeroizing;

const BIN: &str = env!("CARGO_BIN_EXE_klav-forward");
/// The skill the binary carries (its `skill` module), read where it does.
const SKILL: &str = include_str!("../../../skill/SKILL.md");

/// A directory of its own, removed when dropped.
struct Dir(PathBuf);

impl Dir {
    fn new() -> Self {
        let n: [u8; 8] = klav_core::crypto::random::array();
        // Short: `<dir>/state/down.sock` must fit a unix socket's path.
        let dir = std::env::temp_dir().join(format!(
            "kfw-{}",
            n.iter().map(|b| format!("{b:02x}")).collect::<String>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// How the stand-in proxy answers a claim.
#[derive(Clone, Copy, PartialEq)]
enum Answer {
    Claim,
    Revoked,
}

/// How the stand-in answers `POST /_klav/release` ([`StandIn::release`]).
const RELEASE_OK: u8 = 0;
/// The sandbox already ended at the proxy: `401 klav_sandbox_revoked`.
const RELEASE_ENDED: u8 = 1;
/// No answer, ever.
const RELEASE_HANG: u8 = 2;

/// How the stand-in answers `GET /_klav/status` ([`StandIn::status`]).
const STATUS_LIVE: u8 = 0;
/// The sandbox ended at the proxy: `401 klav_sandbox_revoked`.
const STATUS_REVOKED: u8 = 1;
/// The person paused the agents: `423 klav_agents_paused`.
const STATUS_PAUSED: u8 = 2;
/// The sandbox's time is over: `401 klav_sandbox_expired`.
const STATUS_EXPIRED: u8 = 3;

/// The stand-in proxy: the channel's TLS with the proxy's key, and the
/// four routes the forwarder uses. It counts the calls it relayed, the
/// claims and the releases it got.
struct StandIn {
    addr: std::net::SocketAddr,
    pin: [u8; 32],
    calls: Arc<AtomicUsize>,
    claims: Arc<AtomicUsize>,
    releases: Arc<AtomicUsize>,
    /// How it answers a release: [`RELEASE_OK`] and the others.
    release: Arc<AtomicU8>,
    /// How it answers a status: [`STATUS_LIVE`] and the others.
    status: Arc<AtomicU8>,
    accepting: tokio::task::AbortHandle,
}

impl StandIn {
    /// Stops listening: from now on nothing answers at its address.
    async fn stop(&self) {
        self.accepting.abort();
        let begun = std::time::Instant::now();
        while tokio::net::TcpStream::connect(self.addr).await.is_ok() {
            assert!(begun.elapsed() < std::time::Duration::from_secs(5));
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    }
}

async fn stand_in(answer: Answer, sandbox: SandboxId) -> StandIn {
    stand_in_at(IdentityKeyPair::generate(), "127.0.0.1:0", answer, sandbox).await
}

/// [`stand_in`] with the proxy's identity `identity`, listening on `at`.
async fn stand_in_at(
    identity: IdentityKeyPair,
    at: &str,
    answer: Answer,
    sandbox: SandboxId,
) -> StandIn {
    let pin = proxy_pin(identity.public());
    let config = klav_forward::channel::server_config(TlsSigner::server(&identity)).unwrap();
    let acceptor = TlsAcceptor::from(config);
    let listener = tokio::net::TcpListener::bind(at).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&calls);
    let claims = Arc::new(AtomicUsize::new(0));
    let claimed = Arc::clone(&claims);
    let releases = Arc::new(AtomicUsize::new(0));
    let release = Arc::new(AtomicU8::new(RELEASE_OK));
    let status = Arc::new(AtomicU8::new(STATUS_LIVE));
    let (released, how, says) = (
        Arc::clone(&releases),
        Arc::clone(&release),
        Arc::clone(&status),
    );
    let accepting = tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let (acceptor, counted, claimed, released, how, says) = (
                acceptor.clone(),
                Arc::clone(&counted),
                Arc::clone(&claimed),
                Arc::clone(&released),
                Arc::clone(&how),
                Arc::clone(&says),
            );
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let Some(head) = klav_forward::http::read_head(&mut tls).await else {
                    return;
                };
                let head = String::from_utf8_lossy(&head).into_owned();
                let line = head.lines().next().unwrap_or_default().to_owned();
                let bound = serde_json::json!({
                    "sandbox_id": sandbox.to_string(),
                    "label": "chat-1",
                    "profiles": ["northflank"],
                    "expires_at": 4_102_444_800_000_i64,
                });
                let revoked = serde_json::json!({
                    "error": "klav_sandbox_revoked",
                    "message": "This sandbox can no longer use the proxy.",
                    "next": "Stop and tell the person.",
                })
                .to_string();
                let (status, body) = if line.starts_with("POST /_klav/release ") {
                    released.fetch_add(1, Ordering::SeqCst);
                    match how.load(Ordering::SeqCst) {
                        RELEASE_OK => ("200 OK", r#"{"logged":true}"#.to_owned()),
                        RELEASE_ENDED => ("401 Unauthorized", revoked),
                        _ => std::future::pending().await,
                    }
                } else if line.starts_with("POST /_klav/claim ") {
                    claimed.fetch_add(1, Ordering::SeqCst);
                    if answer == Answer::Revoked {
                        ("401 Unauthorized", revoked)
                    } else {
                        ("200 OK", bound.to_string())
                    }
                } else if line.starts_with("GET /_klav/status ") {
                    match says.load(Ordering::SeqCst) {
                        STATUS_LIVE => ("200 OK", bound.to_string()),
                        STATUS_REVOKED => ("401 Unauthorized", revoked),
                        STATUS_EXPIRED => (
                            "401 Unauthorized",
                            serde_json::json!({
                                "error": "klav_sandbox_expired",
                                "message": "This sandbox's time is over.",
                                "next": "Stop and tell the person.",
                            })
                            .to_string(),
                        ),
                        _ => (
                            "423 Locked",
                            serde_json::json!({
                                "error": "klav_agents_paused",
                                "message": "The person paused Klav's agents.",
                                "next": "Stop and tell the person.",
                            })
                            .to_string(),
                        ),
                    }
                } else {
                    counted.fetch_add(1, Ordering::SeqCst);
                    ("200 OK", "ok".to_owned())
                };
                let code = serde_json::from_str::<serde_json::Value>(&body)
                    .ok()
                    .and_then(|v| v["error"].as_str().map(|e| format!("klav-error: {e}\r\n")))
                    .unwrap_or_default();
                let _ = tls
                    .write_all(
                        format!(
                            "HTTP/1.1 {status}\r\n{code}content-length: {}\r\nconnection: close\r\n\r\n{body}",
                            body.len()
                        )
                        .as_bytes(),
                    )
                    .await;
                let _ = tls.shutdown().await;
            });
        }
    })
    .abort_handle();
    StandIn {
        addr,
        pin,
        calls,
        claims,
        releases,
        release,
        status,
        accepting,
    }
}

/// A package for `sandbox` at the stand-in.
fn package(proxy: &StandIn, sandbox: SandboxId) -> Zeroizing<String> {
    encode_package(&SandboxPackage {
        sandbox_id: sandbox,
        secret: SandboxSecret::generate(),
        expires_at_ms: 4_102_444_800_000,
        proxy_pin: proxy.pin,
        url: format!("tls://{}", proxy.addr),
    })
    .unwrap()
}

/// `klav-forward ARGS` with `KLAV_SANDBOX` set to `package`, HOME and the
/// state in `dir`.
fn forward(dir: &Path, package: Option<&str>, args: &[&str]) -> Output {
    let mut command = forward_command(dir, args);
    if let Some(package) = package {
        command.env("KLAV_SANDBOX", package);
    }
    command.output().unwrap()
}

/// [`forward`] without a package, not started yet.
fn forward_command(dir: &Path, args: &[&str]) -> Command {
    let mut command = Command::new(BIN);
    command
        .args(args)
        .env("HOME", dir)
        .env("KLAV_FORWARD_HOME", dir.join("state"))
        .env_remove("KLAV_SANDBOX");
    command
}

fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// What a process shows of itself to others on this machine.
fn visible(pid: u32) -> String {
    let args = Command::new("ps")
        .args(["-ww", "-o", "args=", "-p", &pid.to_string()])
        .output()
        .unwrap();
    let mut seen = String::from_utf8_lossy(&args.stdout).into_owned();
    #[cfg(target_os = "linux")]
    {
        seen.push_str(
            &String::from_utf8_lossy(
                &std::fs::read(format!("/proc/{pid}/environ")).unwrap_or_default(),
            )
            .replace('\0', "\n"),
        );
    }
    #[cfg(target_os = "macos")]
    {
        let env = Command::new("ps")
            .args(["-E", "-ww", "-o", "command=", "-p", &pid.to_string()])
            .output()
            .unwrap();
        seen.push_str(&String::from_utf8_lossy(&env.stdout));
    }
    seen
}

fn every_file(dir: &Path, out: &mut String) {
    for entry in std::fs::read_dir(dir).unwrap().flatten() {
        let path = entry.path();
        if path.is_dir() {
            every_file(&path, out);
        } else {
            out.push_str(&String::from_utf8_lossy(
                &std::fs::read(&path).unwrap_or_default(),
            ));
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn up_claims_runs_in_the_background_and_keeps_the_package_to_itself() {
    let dir = Dir::new();
    let sandbox = SandboxId::generate();
    let proxy = stand_in(Answer::Claim, sandbox).await;
    let package = package(&proxy, sandbox);
    let profile_file = dir.0.join("profile.d/klav-forward.sh");
    let out = forward(
        &dir.0,
        Some(&package),
        &[
            "up",
            "--daemon",
            "--port",
            "0",
            "--profile-file",
            profile_file.to_str().unwrap(),
        ],
    );
    // The guard first, so a failed assert below never leaves the daemon
    // running.
    let state: Option<serde_json::Value> = std::fs::read(dir.0.join("state/state.json"))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok());
    let stop = state
        .as_ref()
        .and_then(|s| s["pid"].as_u64())
        .map(|pid| Kill(vec![u32::try_from(pid).unwrap()]));
    let said = text(&out);
    assert!(out.status.success(), "{said}");
    assert!(said.contains("Claimed sandbox «chat-1»"), "{said}");
    assert!(said.contains("installed the Klav skill"), "{said}");
    let state = state.expect("state.json");
    let pid = u32::try_from(state["pid"].as_u64().unwrap()).unwrap();
    let port = state["port"].as_u64().unwrap();

    // A tool's call goes through to the proxy.
    let mut tcp = tokio::net::TcpStream::connect(("127.0.0.1", u16::try_from(port).unwrap()))
        .await
        .unwrap();
    tcp.write_all(
        b"GET /northflank/v1/projects HTTP/1.1\r\nhost: localhost\r\nauthorization: Bearer klav-placeholder\r\nconnection: close\r\n\r\n",
    )
    .await
    .unwrap();
    let res = klav_forward::http::read_answer(&mut tcp).await.unwrap();
    assert_eq!((res.status, res.body.as_slice()), (200, &b"ok"[..]));
    assert_eq!(proxy.calls.load(Ordering::SeqCst), 1);

    // `status` and `env`.
    let status = forward(&dir.0, None, &["status", "--json"]);
    assert!(status.status.success(), "{}", text(&status));
    let live: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
    assert_eq!(live["status"], "live");
    assert_eq!(live["sandbox"]["label"], "chat-1");
    let env = forward(&dir.0, None, &["env"]);
    let lines = String::from_utf8(env.stdout).unwrap();
    assert!(
        lines.contains(&format!(
            "export KLAV_FORWARD_NORTHFLANK_URL='http://127.0.0.1:{port}/northflank'"
        )),
        "{lines}"
    );
    assert_eq!(std::fs::read_to_string(&profile_file).unwrap(), lines);
    assert_eq!(
        std::fs::read_to_string(dir.0.join(".claude/skills/klav/SKILL.md")).unwrap(),
        SKILL
    );

    // The package is nowhere: not in what `up` printed, not in the running
    // forwarder's arguments or environment, not in any file it wrote.
    let mut everything = said;
    everything.push_str(&visible(pid));
    every_file(&dir.0, &mut everything);
    assert!(!everything.contains(package.as_str()));
    assert!(!everything.contains("KLAV_SANDBOX="));
    drop(stop);
}

/// Kills every forwarder a test started when it ends, also when it fails.
struct Kill(Vec<u32>);

impl Kill {
    /// Every daemon `up` may have started: the one in `state.json` now.
    fn after_up(&mut self, dir: &Path) {
        if let Some(pid) = state_pid(dir)
            && !self.0.contains(&pid)
        {
            self.0.push(pid);
        }
    }

    /// `pid` is gone: never signal it again (it may be reused).
    fn forget(&mut self, pid: u32) {
        self.0.retain(|p| *p != pid);
    }
}

impl Drop for Kill {
    fn drop(&mut self) {
        for pid in &self.0 {
            let _ = Command::new("kill")
                .arg(pid.to_string())
                .stderr(std::process::Stdio::null())
                .status();
        }
        // Gone before the test's directory is removed, so nothing writes
        // in it after.
        for pid in &self.0 {
            let _ = gone(*pid);
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn up_says_why_it_could_not_start_with_klavs_exit_codes() {
    let dir = Dir::new();
    // No package.
    let out = forward(&dir.0, None, &["up", "--json"]);
    assert_eq!(out.status.code(), Some(2), "{}", text(&out));
    let said: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(
        said["next"]
            .as_str()
            .unwrap()
            .contains("klav sandbox start")
    );
    // Not a package.
    let out = forward(&dir.0, Some("ksb1_not-a-package"), &["up"]);
    assert_eq!(out.status.code(), Some(2), "{}", text(&out));
    assert!(!text(&out).contains("ksb1_not-a-package"));
    // The proxy refuses the claim: its message and next, exit 5.
    let sandbox = SandboxId::generate();
    let proxy = stand_in(Answer::Revoked, sandbox).await;
    let package = package(&proxy, sandbox);
    let out = forward(
        &dir.0,
        Some(&package),
        &["up", "--port", "0", "--no-skill", "--json"],
    );
    assert_eq!(out.status.code(), Some(5), "{}", text(&out));
    let said: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(said["error"], "klav_sandbox_revoked");
    assert_eq!(said["next"], "Stop and tell the person.");
    assert!(!text(&out).contains(package.as_str()));
    // That claim reached the proxy, so its marker stays: the same package
    // again is refused here, and never reaches the proxy.
    let out = forward(
        &dir.0,
        Some(&package),
        &["up", "--port", "0", "--no-skill", "--json"],
    );
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    let said: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(said["error"], "klav_forward_already_claimed");
    assert_eq!(proxy.claims.load(Ordering::SeqCst), 1);
    // The port is taken (a forwarder may already run for this sandbox):
    // refused before any claim, and never advice that would claim again.
    // Another sandbox, so no marker decides first.
    let sandbox = SandboxId::generate();
    let proxy = stand_in(Answer::Claim, sandbox).await;
    let fresh = self::package(&proxy, sandbox);
    let taken = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = taken.local_addr().unwrap().port().to_string();
    let out = forward(
        &dir.0,
        Some(&fresh),
        &["up", "--port", &port, "--no-skill", "--json"],
    );
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    let said: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(said["error"], "klav_forward_port_in_use");
    let next = said["next"].as_str().unwrap();
    assert!(next.contains("klav-forward status"), "{next}");
    assert!(!next.contains("--port"), "{next}");
    assert_eq!(proxy.claims.load(Ordering::SeqCst), 0);
    assert!(!text(&out).contains(fresh.as_str()));
    // Refused before the claim: no marker, so the package still works.
    assert!(!dir.0.join(format!("state/claimed/{sandbox}")).exists());
    drop(taken);
    // Nothing running, nothing to report.
    let out = forward(&dir.0, None, &["status", "--json"]);
    assert_eq!(out.status.code(), Some(1));
    let said: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(said["error"], "klav_forward_not_running");
}

/// The pid in `state.json`, if any.
fn state_pid(dir: &Path) -> Option<u32> {
    let state: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join("state/state.json")).ok()?).ok()?;
    u32::try_from(state["pid"].as_u64()?).ok()
}

/// Whether `pid` still runs.
fn alive(pid: u32) -> bool {
    Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// `up` again with the same package (ADR 0036 §5): while its forwarder
/// runs and answers, it says so and claims nothing; once that forwarder
/// is dead, with its `state.json` left behind or gone, the marker refuses
/// here, without reaching the proxy and without echoing the package.
#[tokio::test(flavor = "multi_thread")]
async fn a_second_up_says_running_or_refuses_and_never_claims_again() {
    let dir = Dir::new();
    let sandbox = SandboxId::generate();
    let proxy = stand_in(Answer::Claim, sandbox).await;
    let package = package(&proxy, sandbox);
    let up = |json: bool| {
        let mut args = vec!["up", "--daemon", "--port", "0", "--no-skill"];
        if json {
            args.push("--json");
        }
        forward(&dir.0, Some(&package), &args)
    };
    let mut stop = Kill(Vec::new());
    let first = up(false);
    stop.after_up(&dir.0);
    assert!(first.status.success(), "{}", text(&first));
    let pid = *stop.0.first().expect("state.json");
    let marker = dir.0.join(format!("state/claimed/{sandbox}"));
    let on_disk: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&marker).unwrap()).unwrap();
    assert_eq!(on_disk["v"], 1);
    assert_eq!(on_disk["sandbox_id"], sandbox.to_string());
    assert_eq!(proxy.claims.load(Ordering::SeqCst), 1);

    // Running: nothing to do, exit 0, no claim.
    let again = up(false);
    stop.after_up(&dir.0);
    let said = text(&again);
    assert!(again.status.success(), "{said}");
    assert!(
        said.contains("already running for sandbox «chat-1»"),
        "{said}"
    );
    let again = up(true);
    stop.after_up(&dir.0);
    assert!(again.status.success(), "{}", text(&again));
    let said: serde_json::Value = serde_json::from_slice(&again.stdout).unwrap();
    assert_eq!(said["status"], "running");
    assert_eq!(said["sandbox"]["sandbox_id"], sandbox.to_string());
    assert_eq!(proxy.claims.load(Ordering::SeqCst), 1);

    // Dead, its `state.json` left behind (SIGKILL): refused here.
    let killed = Command::new("kill")
        .args(["-9", &pid.to_string()])
        .status()
        .unwrap();
    assert!(killed.success());
    let begun = std::time::Instant::now();
    while alive(pid) && begun.elapsed() < std::time::Duration::from_secs(10) {
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(!alive(pid));
    assert!(dir.0.join("state/state.json").exists());
    let mut everything = String::new();
    for json in [false, true] {
        let out = up(json);
        stop.after_up(&dir.0);
        assert_eq!(out.status.code(), Some(1), "{}", text(&out));
        let said = text(&out);
        assert!(said.contains(&sandbox.to_string()), "{said}");
        assert!(said.contains("klav sandbox start"), "{said}");
        if json {
            let said: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
            assert_eq!(said["error"], "klav_forward_already_claimed");
        }
        everything.push_str(&said);
    }
    // Dead and its `state.json` gone too: still refused.
    std::fs::remove_file(dir.0.join("state/state.json")).unwrap();
    let out = up(true);
    stop.after_up(&dir.0);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    let said: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(said["error"], "klav_forward_already_claimed");
    everything.push_str(&text(&out));
    // A marker this version cannot read counts as claimed, and says why.
    std::fs::write(&marker, br#"{"v":2}"#).unwrap();
    let out = up(true);
    stop.after_up(&dir.0);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    let said: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(said["error"], "klav_forward_already_claimed");
    assert!(
        said["message"].as_str().unwrap().contains("format v2"),
        "{said}"
    );
    everything.push_str(&text(&out));

    assert_eq!(proxy.claims.load(Ordering::SeqCst), 1);
    every_file(&dir.0, &mut everything);
    assert!(!everything.contains(package.as_str()));
    drop(stop);
}

/// A claim that never left (no proxy listens at the package's address, so
/// no attempt got past connecting) does not use the package: no marker is
/// left, and the next `up` claims once the proxy is there.
#[tokio::test(flavor = "multi_thread")]
async fn a_claim_that_never_left_leaves_the_package_usable() {
    let dir = Dir::new();
    let sandbox = SandboxId::generate();
    let identity = IdentityKeyPair::generate();
    let port = {
        let free = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        free.local_addr().unwrap().port()
    };
    let package = encode_package(&SandboxPackage {
        sandbox_id: sandbox,
        secret: SandboxSecret::generate(),
        expires_at_ms: 4_102_444_800_000,
        proxy_pin: proxy_pin(identity.public()),
        url: format!("tls://127.0.0.1:{port}"),
    })
    .unwrap();
    let args = [
        "up",
        "--daemon",
        "--port",
        "0",
        "--no-skill",
        "--json",
        "--claim-wait-secs",
        "1",
    ];
    let out = forward(&dir.0, Some(&package), &args);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    let said: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(said["error"], "klav_proxy_unreachable");
    assert!(
        said["next"].as_str().unwrap().contains("was not used"),
        "{said}"
    );
    assert!(!dir.0.join(format!("state/claimed/{sandbox}")).exists());
    assert!(!text(&out).contains(package.as_str()));

    // The proxy comes up at that address: the same package claims, once.
    let proxy = stand_in_at(
        identity,
        &format!("127.0.0.1:{port}"),
        Answer::Claim,
        sandbox,
    )
    .await;
    let mut stop = Kill(Vec::new());
    let out = forward(&dir.0, Some(&package), &args);
    stop.after_up(&dir.0);
    assert!(out.status.success(), "{}", text(&out));
    assert_eq!(proxy.claims.load(Ordering::SeqCst), 1);
    assert!(dir.0.join(format!("state/claimed/{sandbox}")).exists());
    drop(stop);
}

/// `up --daemon` for `package`, its daemon in `stop`, and the claim made.
fn up_daemon(dir: &Dir, package: &str, stop: &mut Kill) {
    let out = forward(
        &dir.0,
        Some(package),
        &["up", "--daemon", "--port", "0", "--no-skill"],
    );
    stop.after_up(&dir.0);
    assert!(out.status.success(), "{}", text(&out));
}

/// Kills `pid` at once and waits until it is gone (its `state.json` stays).
fn kill_now(pid: u32) {
    let killed = Command::new("kill")
        .args(["-9", &pid.to_string()])
        .status()
        .unwrap();
    assert!(killed.success());
    let begun = std::time::Instant::now();
    while alive(pid) && begun.elapsed() < std::time::Duration::from_secs(10) {
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(!alive(pid));
}

/// Points `state.json` at `port`, as if the forwarder had listened there.
fn state_port(dir: &Path, port: u16) {
    let path = dir.join("state/state.json");
    let mut state: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    state["port"] = port.into();
    std::fs::write(&path, serde_json::to_vec(&state).unwrap()).unwrap();
}

/// The `--json` refusal of `up` with `package`, and how long it took. A
/// daemon it started anyway (a regression) goes into `stop` before any
/// assert, so it never outlives the test.
fn refused_up(
    dir: &Dir,
    package: &str,
    stop: &mut Kill,
) -> (serde_json::Value, std::time::Duration) {
    let begun = std::time::Instant::now();
    let out = forward(
        &dir.0,
        Some(package),
        &["up", "--daemon", "--port", "0", "--no-skill", "--json"],
    );
    let took = begun.elapsed();
    stop.after_up(&dir.0);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    (serde_json::from_slice(&out.stdout).unwrap(), took)
}

/// A state directory another user could write: `up` refuses before any
/// claim, says how to fix it, and leaves no marker. A forwarder already
/// running there is not broken: `up` again still says it runs.
#[tokio::test(flavor = "multi_thread")]
async fn a_state_directory_others_can_write_is_refused_before_any_claim() {
    use std::os::unix::fs::PermissionsExt;
    let dir = Dir::new();
    let state = dir.0.join("state");
    std::fs::create_dir(&state).unwrap();
    let sandbox = SandboxId::generate();
    let proxy = stand_in(Answer::Claim, sandbox).await;
    let package = package(&proxy, sandbox);
    let mut stop = Kill(Vec::new());
    for mode in [0o777, 0o775] {
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(mode)).unwrap();
        let (said, _) = refused_up(&dir, &package, &mut stop);
        assert_eq!(said["error"], "klav_forward_state_not_private", "{said}");
        let next = said["next"].as_str().unwrap();
        assert!(next.contains("chmod 700"), "{said}");
        // It never vouches for the package (it did not look at it), and
        // never sends the agent to another directory.
        assert!(!next.contains("was not used"), "{said}");
        assert!(!next.to_lowercase().contains("pass --state-dir"), "{said}");
        assert_eq!(proxy.claims.load(Ordering::SeqCst), 0);
        assert!(!state.join(format!("claimed/{sandbox}")).exists());
    }
    // A private state directory with a `claimed/` others can write: the
    // fix it gives names `claimed/`, not the state directory.
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
    let claimed = state.join("claimed");
    std::fs::create_dir(&claimed).unwrap();
    std::fs::set_permissions(&claimed, std::fs::Permissions::from_mode(0o777)).unwrap();
    let (said, _) = refused_up(&dir, &package, &mut stop);
    assert_eq!(said["error"], "klav_forward_state_not_private", "{said}");
    assert!(
        said["next"]
            .as_str()
            .unwrap()
            .contains(&format!("chmod 700 {}`", claimed.display())),
        "{said}"
    );
    assert_eq!(proxy.claims.load(Ordering::SeqCst), 0);
    assert!(!claimed.join(sandbox.to_string()).exists());
    std::fs::set_permissions(&claimed, std::fs::Permissions::from_mode(0o700)).unwrap();
    // Made private, it claims; opened again while its forwarder runs,
    // `up` still says it runs and claims nothing.
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
    up_daemon(&dir, &package, &mut stop);
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o777)).unwrap();
    let out = forward(
        &dir.0,
        Some(&package),
        &["up", "--daemon", "--port", "0", "--no-skill"],
    );
    stop.after_up(&dir.0);
    assert!(out.status.success(), "{}", text(&out));
    assert!(text(&out).contains("already running"), "{}", text(&out));
    assert_eq!(proxy.claims.load(Ordering::SeqCst), 1);
    // Its daemon gone, the directory still open to others: the marker
    // there says claimed, before any word on the directory.
    kill_now(*stop.0.first().expect("daemon"));
    let (said, _) = refused_up(&dir, &package, &mut stop);
    assert_eq!(said["error"], "klav_forward_already_claimed", "{said}");
    assert_eq!(proxy.claims.load(Ordering::SeqCst), 1);
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
}

/// A state directory another user claimed from (root in the setup script,
/// with `--state-dir`), as far as a test without root can build it: a
/// `claimed/` this user cannot read, in a directory the privacy check
/// refuses (others can write it, or this user cannot). The marker cannot
/// be ruled out, so the answer is that the package was used, never that
/// it was not.
#[tokio::test(flavor = "multi_thread")]
async fn a_claimed_directory_this_user_cannot_read_is_never_called_unused() {
    use std::os::unix::fs::PermissionsExt;
    let dir = Dir::new();
    let state = dir.0.join("state");
    let claimed = state.join("claimed");
    std::fs::create_dir_all(&claimed).unwrap();
    let sandbox = SandboxId::generate();
    let proxy = stand_in(Answer::Claim, sandbox).await;
    let package = package(&proxy, sandbox);
    let mut stop = Kill(Vec::new());
    // Both modes back before the directory is removed, even on a panic.
    struct Reopen(Vec<PathBuf>);
    impl Drop for Reopen {
        fn drop(&mut self) {
            for dir in &self.0 {
                let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
            }
        }
    }
    let _reopen = Reopen(vec![state.clone(), claimed.clone()]);
    std::fs::set_permissions(&claimed, std::fs::Permissions::from_mode(0o000)).unwrap();
    // Mode bits do not deny root or a process with CAP_DAC_OVERRIDE (CI's
    // runner): there the case cannot be built, and the unit tests cover it.
    if std::fs::read_dir(&claimed).is_ok() {
        skipped_mode_000();
        return;
    }
    for mode in [0o777, 0o555] {
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(mode)).unwrap();
        let out = forward(
            &dir.0,
            Some(&package),
            &["up", "--daemon", "--port", "0", "--no-skill", "--json"],
        );
        stop.after_up(&dir.0);
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(out.status.code(), Some(1), "{mode:o}: {}", text(&out));
        let said: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(
            said["error"], "klav_forward_already_claimed",
            "{mode:o}: {said}"
        );
        assert_eq!(proxy.claims.load(Ordering::SeqCst), 0);
    }
}

/// Says on stderr that a case needing a mode bit to deny this process was
/// skipped: mode bits do not deny root or a process with CAP_DAC_OVERRIDE.
#[allow(clippy::print_stderr)]
fn skipped_mode_000() {
    eprintln!("skipped: this process can still read a directory of mode 000");
}

/// A state directory this user cannot reach (the setup script claimed as
/// root with `--state-dir /root/kf`, and the agent runs `up` again as
/// another user): `up` stops and never sends the agent to another
/// directory, where the same package would be claimed a second time.
#[tokio::test(flavor = "multi_thread")]
async fn a_state_directory_this_user_cannot_reach_sends_nowhere_else() {
    use std::os::unix::fs::PermissionsExt;
    let dir = Dir::new();
    let locked = dir.0.join("locked");
    std::fs::create_dir(&locked).unwrap();
    struct Reopen(PathBuf);
    impl Drop for Reopen {
        fn drop(&mut self) {
            let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o700));
        }
    }
    let _reopen = Reopen(locked.clone());
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
    if std::fs::read_dir(&locked).is_ok() {
        skipped_mode_000();
        return;
    }
    let sandbox = SandboxId::generate();
    let proxy = stand_in(Answer::Claim, sandbox).await;
    let package = package(&proxy, sandbox);
    let state = locked.join("kf");
    let out = forward(
        &dir.0,
        Some(&package),
        &[
            "up",
            "--state-dir",
            state.to_str().unwrap(),
            "--port",
            "0",
            "--no-skill",
            "--json",
        ],
    );
    assert_eq!(out.status.code(), Some(2), "{}", text(&out));
    let said: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let next = said["next"].as_str().unwrap();
    assert!(!next.to_lowercase().contains("pass --state-dir"), "{said}");
    assert!(next.contains("klav sandbox start"), "{said}");
    assert_eq!(proxy.claims.load(Ordering::SeqCst), 0);
}

/// `state.json` names this sandbox only after a claim succeeded, so with
/// no forwarder answering it says the package was used, marker or not (a
/// state directory from before the marker, or a marker lost).
#[tokio::test(flavor = "multi_thread")]
async fn a_state_file_naming_this_sandbox_means_claimed_even_without_a_marker() {
    let dir = Dir::new();
    let sandbox = SandboxId::generate();
    let proxy = stand_in(Answer::Claim, sandbox).await;
    let package = package(&proxy, sandbox);
    let mut stop = Kill(Vec::new());
    up_daemon(&dir, &package, &mut stop);
    kill_now(*stop.0.first().expect("daemon"));
    std::fs::remove_file(dir.0.join(format!("state/claimed/{sandbox}"))).unwrap();
    let (said, _) = refused_up(&dir, &package, &mut stop);
    assert_eq!(said["error"], "klav_forward_already_claimed", "{said}");
    assert_eq!(proxy.claims.load(Ordering::SeqCst), 1);
}

/// Another program on the port `state.json` names, once the forwarder is
/// dead: an answer without a Klav code (a dev server's `404`) or none at
/// all falls through to the marker, within the short deadline, and never
/// claims.
#[tokio::test(flavor = "multi_thread")]
async fn another_program_on_the_stored_port_falls_through_to_the_marker() {
    let dir = Dir::new();
    let sandbox = SandboxId::generate();
    let proxy = stand_in(Answer::Claim, sandbox).await;
    let package = package(&proxy, sandbox);
    let mut stop = Kill(Vec::new());
    up_daemon(&dir, &package, &mut stop);
    kill_now(*stop.0.first().expect("daemon"));

    let dev = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    state_port(&dir.0, dev.local_addr().unwrap().port());
    tokio::spawn(async move {
        while let Ok((mut tcp, _)) = dev.accept().await {
            let _ = klav_forward::http::read_head(&mut tcp).await;
            let _ = tcp
                .write_all(b"HTTP/1.1 404 Not Found\r\ncontent-length: 9\r\nconnection: close\r\n\r\nnot found")
                .await;
        }
    });
    let (said, _) = refused_up(&dir, &package, &mut stop);
    assert_eq!(said["error"], "klav_forward_already_claimed", "{said}");

    let silent = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    state_port(&dir.0, silent.local_addr().unwrap().port());
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((tcp, _)) = silent.accept().await {
            held.push(tcp);
        }
    });
    let (said, took) = refused_up(&dir, &package, &mut stop);
    assert_eq!(said["error"], "klav_forward_already_claimed", "{said}");
    assert!(took < std::time::Duration::from_secs(25), "{took:?}");
    assert_eq!(proxy.claims.load(Ordering::SeqCst), 1);
}

/// A forwarder that runs, but that `state.json` does not name (another
/// sandbox's `up` wrote it there, or saving it failed): `up` refuses, and
/// says what it knows, that no forwarder answers from this state
/// directory, not that none runs.
#[tokio::test(flavor = "multi_thread")]
async fn a_forwarder_the_state_directory_does_not_name_is_not_claimed_again() {
    let dir = Dir::new();
    let sandbox = SandboxId::generate();
    let proxy = stand_in(Answer::Claim, sandbox).await;
    let package = package(&proxy, sandbox);
    let mut stop = Kill(Vec::new());
    up_daemon(&dir, &package, &mut stop);
    let path = dir.0.join("state/state.json");
    let mut state: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    state["sandbox"]["sandbox_id"] = SandboxId::generate().to_string().into();
    std::fs::write(&path, serde_json::to_vec(&state).unwrap()).unwrap();
    let (said, _) = refused_up(&dir, &package, &mut stop);
    assert_eq!(said["error"], "klav_forward_already_claimed", "{said}");
    let message = said["message"].as_str().unwrap();
    assert!(
        message.contains("no forwarder for it answers from this state directory"),
        "{message}"
    );
    assert_eq!(proxy.claims.load(Ordering::SeqCst), 1);
}

/// A loopback port that is free right now, outside the ephemeral range
/// (49152 and up on macOS, 32768 and up on Linux): a port the system
/// handed out for `:0` can go to any test's outgoing connection before a
/// forwarder binds it again, as 8790 never would. Only for a test that
/// binds the same port again after a forwarder let it go; any other test
/// lets its forwarder bind `:0` ([`up_any`]).
/// Never the same port twice in this process (`cargo test`); under nextest
/// each test is its own process, and anything on the machine may take the
/// port before `up` binds it: [`up_first`] and [`setup_first`] draw again
/// then.
fn free_port() -> u16 {
    static GIVEN: std::sync::Mutex<Vec<u16>> = std::sync::Mutex::new(Vec::new());
    let mut given = GIVEN
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    loop {
        let n: [u8; 2] = klav_core::crypto::random::array();
        let port = 20_000 + u16::from_le_bytes(n) % 10_000;
        if !given.contains(&port) && port_free(port) {
            given.push(port);
            return port;
        }
    }
}

/// Whether nothing listens on `port` (a listener binds it).
fn port_free(port: u16) -> bool {
    std::net::TcpListener::bind(("127.0.0.1", port)).is_ok()
}

/// How many ports [`up_first`] and [`setup_first`] draw before they give
/// up: each further draw follows a port something else took first.
const PORT_DRAWS: usize = 5;

/// Whether `out` is `up` refusing `port` because something else listens
/// there, with no claim begun from `dir`: no claim marker, which `up`
/// writes before the first byte of a claim. Only then may a test draw
/// another port; after a claim, a second one would be a theft.
fn port_taken_before_any_claim(dir: &Dir, out: &Output, port: u16) -> bool {
    let claimed = std::fs::read_dir(dir.0.join("state/claimed"))
        .map(|d| d.count())
        .unwrap_or(0);
    !out.status.success()
        && text(out).contains(&format!("127.0.0.1:{port} is not free "))
        && claimed == 0
}

/// The first `up --daemon` of a test that binds the same port again later
/// (a new package after `down`): on a port of [`free_port`], drawn again
/// only while something else took it before any claim (said on stderr).
/// Its port.
#[allow(clippy::print_stderr)]
fn up_first(dir: &Dir, package: &str, stop: &mut Kill) -> u16 {
    for _ in 0..PORT_DRAWS {
        let port = free_port();
        let out = try_up_on(dir, package, port, stop);
        if !port_taken_before_any_claim(dir, &out, port) {
            claimed_ok(dir, &out);
            return port;
        }
        eprintln!("port {port} was taken before `up` bound it: drawing another");
    }
    panic!("{PORT_DRAWS} ports in a row were taken before `up` bound them");
}

/// `up --daemon --port 0` for `package`: its forwarder binds a port the
/// system picks, so nothing can take it between choosing and binding.
/// The port it bound, from `state.json`.
fn up_any(dir: &Dir, package: &str, stop: &mut Kill) -> u16 {
    up_on(dir, package, 0, stop);
    bound_port(&dir.0).expect("state.json names its port")
}

/// The port in `state.json`, if any.
fn bound_port(dir: &Path) -> Option<u16> {
    let state: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join("state/state.json")).ok()?).ok()?;
    u16::try_from(state["port"].as_u64()?).ok()
}

/// `up --daemon` on `port` for `package` (its shell lines in `dir`); the
/// daemon goes into `stop`, and the claim must succeed.
fn up_on(dir: &Dir, package: &str, port: u16, stop: &mut Kill) {
    let out = try_up_on(dir, package, port, stop);
    claimed_ok(dir, &out);
}

/// `up --daemon` on `port` for `package`, its daemon into `stop`, whatever
/// it answers.
fn try_up_on(dir: &Dir, package: &str, port: u16, stop: &mut Kill) -> Output {
    let profile = dir.0.join("profile.sh");
    let out = forward(
        &dir.0,
        Some(package),
        &[
            "up",
            "--daemon",
            "--port",
            &port.to_string(),
            "--no-skill",
            "--profile-file",
            profile.to_str().unwrap(),
        ],
    );
    stop.after_up(&dir.0);
    out
}

/// `up` claimed and runs, or the test fails with what it said and the end
/// of its log.
fn claimed_ok(dir: &Dir, out: &Output) {
    // Nothing shown here holds the package: `up` never prints it and no
    // file of the state directory has it (the first test checks both).
    let log = std::fs::read_to_string(dir.0.join("state/forward.log")).unwrap_or_default();
    let mut tail: Vec<_> = log.lines().rev().take(20).collect();
    tail.reverse();
    assert!(
        out.status.success(),
        "up exited with {}\n--- its stdout and stderr:\n{}\n--- the end of forward.log:\n{}",
        out.status,
        text(out),
        tail.join("\n")
    );
}

/// `down --json` in `dir`: its output, its JSON and how long it took.
fn down_json(dir: &Path) -> (Output, serde_json::Value, std::time::Duration) {
    let begun = std::time::Instant::now();
    let out = forward(dir, None, &["down", "--json"]);
    let took = begun.elapsed();
    let said =
        serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("{e}: {}", text(&out)));
    // One line: a program reads it with one `read_line`.
    assert_eq!(out.stdout.iter().filter(|b| **b == b'\n').count(), 1);
    (out, said, took)
}

/// Waits up to 5 s for `pid` to be gone.
fn gone(pid: u32) -> bool {
    let begun = std::time::Instant::now();
    while alive(pid) && begun.elapsed() < std::time::Duration::from_secs(5) {
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    !alive(pid)
}

/// What `down` leaves of a forwarder it stopped: the process gone, the
/// port free, no `state.json` and no socket. The claim marker stays: the
/// package was spent, and claiming it again would be a theft.
fn stopped_cleanly(dir: &Path, pid: u32, port: u16, sandbox: SandboxId, stop: &mut Kill) {
    assert!(gone(pid), "the forwarder still runs");
    stop.forget(pid);
    assert!(port_free(port), "127.0.0.1:{port} is still taken");
    assert!(!dir.join("state/state.json").exists());
    assert!(!dir.join("state/down.sock").exists());
    assert!(dir.join(format!("state/claimed/{sandbox}")).exists());
}

/// A `down` that worked (exit 0) passes on the proxy's code and words for
/// a release that did not, never its `next`: "stop" there would end a
/// setup script right before its `up`.
#[track_caller]
fn no_instruction_to_stop(out: &Output, said: &serde_json::Value) {
    assert!(out.status.success(), "{}", text(out));
    let error = said["release_error"].as_object().expect("release_error");
    let mut keys: Vec<_> = error.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(keys, ["error", "message"], "{said}");
    assert!(!text(out).contains("and stop"), "{}", text(out));
}

/// `down` releases the sandbox at the proxy and stops its forwarder,
/// freeing the port, with no signal to any pid. Then: `down` again is a
/// quiet no-op, the same package is never claimed again, and a new
/// package runs on the same port. A plain SIGTERM still stops a forwarder
/// without releasing its sandbox.
#[tokio::test(flavor = "multi_thread")]
async fn down_releases_the_sandbox_and_frees_the_port_for_a_new_package() {
    let dir = Dir::new();
    let first = SandboxId::generate();
    let proxy = stand_in(Answer::Claim, first).await;
    let package = package(&proxy, first);
    let mut stop = Kill(Vec::new());
    let port = up_first(&dir, &package, &mut stop);
    let pid = state_pid(&dir.0).expect("state.json");
    assert!(dir.0.join("state/down.sock").exists());

    let (out, said, _) = down_json(&dir.0);
    assert!(out.status.success(), "{}", text(&out));
    assert_eq!(said["status"], "stopped", "{said}");
    assert_eq!(said["release"], "released", "{said}");
    assert_eq!(said["logged"], true, "{said}");
    assert_eq!(said["sandbox"]["sandbox_id"], first.to_string(), "{said}");
    assert_eq!(said["url"], format!("http://127.0.0.1:{port}"), "{said}");
    assert_eq!(proxy.releases.load(Ordering::SeqCst), 1);
    stopped_cleanly(&dir.0, pid, port, first, &mut stop);
    // The shell lines stay (`up` rewrites them); they hold no secret.
    assert!(dir.0.join("profile.sh").exists());

    // Again: nothing runs, exit 0, nothing released, nothing created.
    for json in [false, true] {
        let args: &[&str] = if json { &["down", "--json"] } else { &["down"] };
        let out = forward(&dir.0, None, args);
        assert!(out.status.success(), "{}", text(&out));
        assert!(text(&out).contains("not running"), "{}", text(&out));
        if json {
            let said: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
            assert_eq!(said["status"], "not_running", "{said}");
        }
    }
    assert_eq!(proxy.releases.load(Ordering::SeqCst), 1);
    assert!(!dir.0.join("state/state.json").exists());
    // Nothing `down` says offers the same package again.
    assert!(!text(&out).contains("klav-forward up"), "{}", text(&out));

    // The same package: refused here, never claimed again.
    let (said, _) = refused_up(&dir, &package, &mut stop);
    assert_eq!(said["error"], "klav_forward_already_claimed", "{said}");
    assert_eq!(proxy.claims.load(Ordering::SeqCst), 1);

    // A new package, the same port and state directory: it claims and runs.
    let second = SandboxId::generate();
    let next_proxy = stand_in(Answer::Claim, second).await;
    up_on(&dir, &self::package(&next_proxy, second), port, &mut stop);
    let pid = state_pid(&dir.0).expect("state.json");
    assert_eq!(next_proxy.claims.load(Ordering::SeqCst), 1);
    let status = forward(&dir.0, None, &["status", "--json"]);
    assert!(status.status.success(), "{}", text(&status));

    // SIGTERM: it stops, and releases nothing (unchanged).
    let term = Command::new("kill").arg(pid.to_string()).status().unwrap();
    assert!(term.success());
    assert!(gone(pid));
    stop.forget(pid);
    assert!(port_free(port));
    assert!(!dir.0.join("state/state.json").exists());
    assert_eq!(next_proxy.releases.load(Ordering::SeqCst), 0);
    drop(stop);
}

/// `down` in a state directory where nothing runs: none at all (it creates
/// nothing), an empty one, a stale `state.json` whose pid is dead, and one
/// whose pid is now an unrelated live process (never signalled). Each is
/// exit 0, and a new package then runs on the same port.
#[tokio::test(flavor = "multi_thread")]
async fn down_is_a_quiet_no_op_when_nothing_runs_and_never_signals_a_pid() {
    let dir = Dir::new();
    let state = dir.0.join("state");
    // No state directory: nothing created, not even it.
    let (out, said, _) = down_json(&dir.0);
    assert!(out.status.success(), "{}", text(&out));
    assert_eq!(said["status"], "not_running", "{said}");
    assert!(!state.exists());
    let out = forward(&dir.0, None, &["down"]);
    assert!(out.status.success(), "{}", text(&out));
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "klav-forward is not running here: nothing to stop.\n"
    );
    assert!(out.stderr.is_empty(), "{}", text(&out));
    assert!(!state.exists());
    // An empty one stays empty.
    std::fs::create_dir(&state).unwrap();
    let (out, _, _) = down_json(&dir.0);
    assert!(out.status.success(), "{}", text(&out));
    assert_eq!(std::fs::read_dir(&state).unwrap().count(), 0);

    // A forwarder killed at once (a reboot): `state.json` and the socket
    // file stay behind, and nothing answers on either.
    let first = SandboxId::generate();
    let proxy = stand_in(Answer::Claim, first).await;
    let mut stop = Kill(Vec::new());
    let port = up_first(&dir, &package(&proxy, first), &mut stop);
    let pid = state_pid(&dir.0).expect("state.json");
    kill_now(pid);
    stop.forget(pid);
    assert!(state.join("down.sock").exists());
    let (out, said, took) = down_json(&dir.0);
    assert!(out.status.success(), "{}", text(&out));
    assert_eq!(said["status"], "not_running", "{said}");
    assert!(took < std::time::Duration::from_secs(5), "{took:?}");

    // Its pid is now an unrelated process: still nothing to stop, and
    // that process lives on.
    let mut unrelated = Command::new("sleep").arg("60").spawn().unwrap();
    struct Reap<'a>(&'a mut std::process::Child);
    impl Drop for Reap<'_> {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let path = state.join("state.json");
    let mut stale: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    stale["pid"] = unrelated.id().into();
    std::fs::write(&path, serde_json::to_vec(&stale).unwrap()).unwrap();
    let unrelated = Reap(&mut unrelated);
    let (out, said, _) = down_json(&dir.0);
    assert!(out.status.success(), "{}", text(&out));
    assert_eq!(said["status"], "not_running", "{said}");
    std::thread::sleep(std::time::Duration::from_millis(200));
    assert!(
        unrelated.0.try_wait().unwrap().is_none(),
        "it was signalled"
    );
    assert_eq!(proxy.releases.load(Ordering::SeqCst), 0);
    drop(unrelated);

    // A new package on the same port and state directory claims and runs.
    let second = SandboxId::generate();
    let next_proxy = stand_in(Answer::Claim, second).await;
    up_on(&dir, &package(&next_proxy, second), port, &mut stop);
    assert_eq!(next_proxy.claims.load(Ordering::SeqCst), 1);
    let (out, said, _) = down_json(&dir.0);
    assert!(out.status.success(), "{}", text(&out));
    assert_eq!(said["release"], "released", "{said}");
    drop(stop);
}

/// The proxy already ended the sandbox (the issuer stopped it, it expired
/// or was revoked): the release is refused, and `down` still stops the
/// forwarder and frees the port, saying so. A new package then runs there.
#[tokio::test(flavor = "multi_thread")]
async fn down_stops_a_forwarder_whose_sandbox_already_ended() {
    let dir = Dir::new();
    let first = SandboxId::generate();
    let proxy = stand_in(Answer::Claim, first).await;
    let mut stop = Kill(Vec::new());
    let port = up_first(&dir, &package(&proxy, first), &mut stop);
    let pid = state_pid(&dir.0).expect("state.json");
    proxy.release.store(RELEASE_ENDED, Ordering::SeqCst);
    let out = forward(&dir.0, None, &["down"]);
    assert!(out.status.success(), "{}", text(&out));
    let said = text(&out);
    assert!(said.contains("had already ended the sandbox"), "{said}");
    assert!(
        said.contains(&format!("127.0.0.1:{port} is free")),
        "{said}"
    );
    assert!(
        said.contains("new package from `klav sandbox start`"),
        "{said}"
    );
    stopped_cleanly(&dir.0, pid, port, first, &mut stop);

    // The same with `--json`.
    let second = SandboxId::generate();
    let next_proxy = stand_in(Answer::Claim, second).await;
    next_proxy.release.store(RELEASE_ENDED, Ordering::SeqCst);
    up_on(&dir, &package(&next_proxy, second), port, &mut stop);
    let pid = state_pid(&dir.0).expect("state.json");
    let (out, said, _) = down_json(&dir.0);
    assert!(out.status.success(), "{}", text(&out));
    assert_eq!(said["release"], "already_ended", "{said}");
    assert_eq!(
        said["release_error"]["error"], "klav_sandbox_revoked",
        "{said}"
    );
    no_instruction_to_stop(&out, &said);
    stopped_cleanly(&dir.0, pid, port, second, &mut stop);

    let third = SandboxId::generate();
    let last = stand_in(Answer::Claim, third).await;
    up_on(&dir, &package(&last, third), port, &mut stop);
    assert_eq!(last.claims.load(Ordering::SeqCst), 1);
    drop(stop);
}

/// Papercut 13: the proxy revokes the sandbox, and its forwarder stops on
/// its own once its status says so: the port is free, `status` and `up`
/// with the same package say why (exit 5), and a foreground `up` exits 5.
/// A pause is not an end: the forwarder keeps running and `status` exits 7.
/// Nor does an expired sandbox stop it (ADR 0036's accepted default): each
/// tool keeps getting `klav_sandbox_expired` with its `next`, exit 6, and
/// its log says so once. Why it stopped goes to `ended.json` (its own
/// version), never into `state.json`, which stays what a v1 reader takes;
/// a live forwarder's word comes first, one this version cannot read never
/// opens a second claim, and a new package's `up` removes it.
#[tokio::test(flavor = "multi_thread")]
async fn a_forwarder_stops_once_its_sandbox_ended_and_survives_a_pause() {
    let dir = Dir::new();
    let sandbox = SandboxId::generate();
    let proxy = stand_in(Answer::Claim, sandbox).await;
    let package = package(&proxy, sandbox);
    let mut stop = Kill(Vec::new());
    let out = forward(
        &dir.0,
        Some(package.as_str()),
        &[
            "up",
            "--daemon",
            "--port",
            "0",
            "--no-skill",
            "--keep-alive-secs",
            "1",
        ],
    );
    stop.after_up(&dir.0);
    assert!(out.status.success(), "{}", text(&out));
    let pid = state_pid(&dir.0).expect("state.json");
    let port = bound_port(&dir.0).expect("state.json");
    let state_dir = dir.0.join("state");
    let ended_file = state_dir.join("ended.json");
    let ended_of = |sandbox: &SandboxId, v: u64| {
        serde_json::json!({
            "v": v,
            "sandbox_id": sandbox.to_string(),
            "refusal": {
                "status": 401,
                "error": "klav_sandbox_revoked",
                "message": "An old end.",
                "next": "Stop.",
            },
        })
        .to_string()
    };

    // A live forwarder's word comes before `ended.json`.
    std::fs::write(&ended_file, ended_of(&sandbox, 1)).unwrap();
    let out = forward(&dir.0, None, &["status"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let out = forward(
        &dir.0,
        Some(package.as_str()),
        &["up", "--daemon", "--no-skill"],
    );
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert!(text(&out).contains("already running"), "{}", text(&out));
    std::fs::remove_file(&ended_file).unwrap();

    // Paused: it runs on, and says so.
    proxy.status.store(STATUS_PAUSED, Ordering::SeqCst);
    std::thread::sleep(std::time::Duration::from_secs(3));
    assert!(alive(pid), "a pause is not an end");
    assert!(!port_free(port));
    let out = forward(&dir.0, None, &["status"]);
    assert_eq!(out.status.code(), Some(7), "{}", text(&out));

    // Expired: it runs on, and says so.
    proxy.status.store(STATUS_EXPIRED, Ordering::SeqCst);
    std::thread::sleep(std::time::Duration::from_secs(3));
    assert!(alive(pid), "an expired sandbox's forwarder keeps listening");
    assert!(!port_free(port));
    let out = forward(&dir.0, None, &["status"]);
    assert_eq!(out.status.code(), Some(6), "{}", text(&out));
    std::thread::sleep(std::time::Duration::from_secs(2));
    let log = std::fs::read_to_string(state_dir.join("forward.log")).unwrap();
    assert_eq!(
        log.matches("klav_sandbox_expired").count(),
        1,
        "logged once, not on every tick: {log}"
    );

    // Ended: it stops by itself and frees the port.
    proxy.status.store(STATUS_REVOKED, Ordering::SeqCst);
    let begun = std::time::Instant::now();
    while !gone(pid) && begun.elapsed() < std::time::Duration::from_secs(15) {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert!(gone(pid), "the forwarder stopped");
    stop.forget(pid);
    assert!(port_free(port));
    let log = std::fs::read_to_string(dir.0.join("state/forward.log")).unwrap();
    assert!(
        log.contains("the sandbox ended (klav_sandbox_revoked)"),
        "{log}"
    );
    for args in [&["status"][..], &["status", "--json"][..]] {
        let out = forward(&dir.0, None, args);
        assert_eq!(out.status.code(), Some(5), "{}", text(&out));
        assert!(
            text(&out).contains("This sandbox can no longer use the proxy."),
            "{}",
            text(&out)
        );
    }
    // `state.json` keeps exactly its v1 fields; `ended.json` has its own v.
    let state: serde_json::Value =
        serde_json::from_slice(&std::fs::read(state_dir.join("state.json")).unwrap()).unwrap();
    let mut keys: Vec<_> = state.as_object().unwrap().keys().cloned().collect();
    keys.sort();
    assert_eq!(keys, ["pid", "port", "sandbox", "v"]);
    assert_eq!(state["v"], 1);
    let ended: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&ended_file).unwrap()).unwrap();
    assert_eq!(ended["v"], 1);
    assert_eq!(ended["sandbox_id"], sandbox.to_string());
    assert_eq!(ended["refusal"]["error"], "klav_sandbox_revoked");
    // `down --if-other-package` with this package touches nothing.
    let out = forward(
        &dir.0,
        Some(package.as_str()),
        &["down", "--if-other-package"],
    );
    assert!(out.status.success(), "{}", text(&out));
    assert!(ended_file.exists());
    let out = forward(
        &dir.0,
        Some(package.as_str()),
        &["up", "--daemon", "--no-skill"],
    );
    stop.after_up(&dir.0);
    assert_eq!(out.status.code(), Some(5), "{}", text(&out));
    assert_eq!(
        proxy.claims.load(Ordering::SeqCst),
        1,
        "never claimed again"
    );
    // `down` has nothing to stop, and leaves the files as they are.
    let out = forward(&dir.0, None, &["down"]);
    assert!(out.status.success(), "{}", text(&out));
    assert!(ended_file.exists());

    // Another version's `ended.json`: `status` says it cannot read it
    // (exit 1), and `up` with the same package is still refused by its
    // marker, never claimed again.
    let saved = std::fs::read(&ended_file).unwrap();
    std::fs::write(&ended_file, ended_of(&sandbox, 2)).unwrap();
    let out = forward(&dir.0, None, &["status", "--json"]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    assert!(text(&out).contains("format v2"), "{}", text(&out));
    for broken in [ended_of(&sandbox, 2), "{not json".to_owned()] {
        std::fs::write(&ended_file, broken).unwrap();
        let out = forward(
            &dir.0,
            Some(package.as_str()),
            &["up", "--daemon", "--no-skill", "--json"],
        );
        assert_eq!(out.status.code(), Some(1), "{}", text(&out));
        assert!(
            text(&out).contains("klav_forward_already_claimed"),
            "{}",
            text(&out)
        );
    }
    assert_eq!(
        proxy.claims.load(Ordering::SeqCst),
        1,
        "never claimed again"
    );
    std::fs::write(&ended_file, saved).unwrap();

    // A new package's `up` here removes it: its sandbox lives.
    let third = SandboxId::generate();
    let renewed = stand_in(Answer::Claim, third).await;
    let fresh = package_for(&renewed, third);
    let out = forward(
        &dir.0,
        Some(fresh.as_str()),
        &["up", "--daemon", "--port", "0", "--no-skill"],
    );
    stop.after_up(&dir.0);
    assert!(out.status.success(), "{}", text(&out));
    assert!(!ended_file.exists(), "a new forwarder runs here");
    let out = forward(&dir.0, None, &["status"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let out = forward(&dir.0, None, &["down"]);
    assert!(out.status.success(), "{}", text(&out));

    // In the foreground, `up` exits with the end's code. Its own `Kill`,
    // made after its directory, so a failure stops its `serve` child before
    // the directory goes.
    let dir = Dir::new();
    let mut fore = Kill(Vec::new());
    let second = SandboxId::generate();
    let next = stand_in(Answer::Claim, second).await;
    let package = package_for(&next, second);
    let mut child = forward_command(
        &dir.0,
        &["up", "--port", "0", "--no-skill", "--keep-alive-secs", "1"],
    )
    .env("KLAV_SANDBOX", package.as_str())
    .stdout(std::process::Stdio::null())
    .stderr(std::process::Stdio::null())
    .spawn()
    .unwrap();
    let begun = std::time::Instant::now();
    while state_pid(&dir.0).is_none() && begun.elapsed() < std::time::Duration::from_secs(15) {
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    fore.after_up(&dir.0);
    next.status.store(STATUS_REVOKED, Ordering::SeqCst);
    let begun = std::time::Instant::now();
    let code = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status.code();
        }
        if begun.elapsed() > std::time::Duration::from_secs(15) {
            let _ = child.kill();
            let _ = child.wait();
            panic!("the foreground forwarder never stopped");
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    };
    assert_eq!(code, Some(5));
    if let Some(pid) = state_pid(&dir.0)
        && gone(pid)
    {
        fore.forget(pid);
    }
    drop(fore);
    drop(stop);
}

/// [`package`] under another name, for a test that shadows it.
fn package_for(proxy: &StandIn, sandbox: SandboxId) -> Zeroizing<String> {
    package(proxy, sandbox)
}

/// Papercut 12: a port another program holds is refused before any claim,
/// with what holds it and the flag that moves the forwarder; the package
/// stays unused.
#[tokio::test(flavor = "multi_thread")]
async fn a_port_another_program_holds_is_named_before_any_claim() {
    let dir = Dir::new();
    let sandbox = SandboxId::generate();
    let proxy = stand_in(Answer::Claim, sandbox).await;
    let other = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = other.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut tcp, _)) = other.accept().await {
            let _ = tcp
                .write_all(
                    b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
                )
                .await;
        }
    });
    let out = forward(
        &dir.0,
        Some(package(&proxy, sandbox).as_str()),
        &["up", "--port", &port.to_string(), "--no-skill", "--json"],
    );
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    let said: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(said["error"], "klav_forward_port_in_use", "{said}");
    let message = said["message"].as_str().unwrap();
    assert!(
        message.contains("another program listens there"),
        "{message}"
    );
    let next = said["next"].as_str().unwrap();
    assert!(next.contains("klav-forward up --port"), "{next}");
    assert!(
        next.contains("did not spend this sandbox's package"),
        "{next}"
    );
    assert_eq!(proxy.claims.load(Ordering::SeqCst), 0);
    // The flags it names exist.
    let help = Command::new(BIN).args(["up", "--help"]).output().unwrap();
    assert!(String::from_utf8_lossy(&help.stdout).contains("--port"));
}

/// The proxy cannot be reached: `down` still stops the forwarder and frees
/// the port at once, and says the sandbox was not released. A proxy that
/// takes the request and never answers holds `down` for the release's
/// short deadline only (never the claim's 120 s), and `down` says it
/// cannot tell. A new package then runs on the same port.
#[tokio::test(flavor = "multi_thread")]
async fn down_stops_a_forwarder_whose_proxy_is_gone_within_a_short_wait() {
    let dir = Dir::new();
    let first = SandboxId::generate();
    let proxy = stand_in(Answer::Claim, first).await;
    let mut stop = Kill(Vec::new());
    let port = up_first(&dir, &package(&proxy, first), &mut stop);
    let pid = state_pid(&dir.0).expect("state.json");
    proxy.stop().await;
    let (out, said, took) = down_json(&dir.0);
    assert!(out.status.success(), "{}", text(&out));
    assert_eq!(said["release"], "not_released", "{said}");
    assert_eq!(
        said["release_error"]["error"], "klav_proxy_unreachable",
        "{said}"
    );
    no_instruction_to_stop(&out, &said);
    assert!(took < std::time::Duration::from_secs(12), "{took:?}");
    stopped_cleanly(&dir.0, pid, port, first, &mut stop);
    let out = forward(&dir.0, None, &["status"]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));

    // Text: it says what is left at the proxy and how to end it.
    let second = SandboxId::generate();
    let next_proxy = stand_in(Answer::Claim, second).await;
    up_on(&dir, &package(&next_proxy, second), port, &mut stop);
    let pid = state_pid(&dir.0).expect("state.json");
    next_proxy.release.store(RELEASE_HANG, Ordering::SeqCst);
    let begun = std::time::Instant::now();
    let out = forward(&dir.0, None, &["down"]);
    let took = begun.elapsed();
    assert!(out.status.success(), "{}", text(&out));
    let said = text(&out);
    assert!(
        said.contains("did not answer the release in time"),
        "{said}"
    );
    assert!(
        said.contains(&format!("klav sandbox stop {second}")),
        "{said}"
    );
    assert!(!said.contains("and stop"), "{said}");
    assert!(took < std::time::Duration::from_secs(25), "{took:?}");
    assert_eq!(next_proxy.releases.load(Ordering::SeqCst), 1);
    stopped_cleanly(&dir.0, pid, port, second, &mut stop);

    let third = SandboxId::generate();
    let last = stand_in(Answer::Claim, third).await;
    up_on(&dir, &package(&last, third), port, &mut stop);
    assert_eq!(last.claims.load(Ordering::SeqCst), 1);
    drop(stop);
}

/// A forwarder answers on the port of `state.json` but not on the control
/// socket (another version of klav-forward, or a socket it could not
/// bind): `down` stops nothing and releases nothing, says why, exit 1.
#[tokio::test(flavor = "multi_thread")]
async fn down_never_stops_a_forwarder_it_cannot_reach_on_its_socket() {
    let dir = Dir::new();
    let sandbox = SandboxId::generate();
    let proxy = stand_in(Answer::Claim, sandbox).await;
    let mut stop = Kill(Vec::new());
    up_any(&dir, &package(&proxy, sandbox), &mut stop);
    let pid = state_pid(&dir.0).expect("state.json");
    std::fs::remove_file(dir.0.join("state/down.sock")).unwrap();
    let out = forward(&dir.0, None, &["down", "--json"]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    let said: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(said["error"], "klav_forward_cannot_stop", "{said}");
    let next = said["next"].as_str().unwrap();
    assert!(next.contains("klav sandbox start"), "{said}");
    // No socket at all: no later `down` gets through, so no retry and no
    // "busy" (that wording is for a full socket only).
    assert!(
        next.starts_with("Tell the person this exact message and stop. Only the person"),
        "{said}"
    );
    assert!(!next.contains("once more"), "{said}");
    let message = said["message"].as_str().unwrap();
    assert!(message.contains("it may be from another version"), "{said}");
    assert!(!message.contains("busy"), "{said}");
    assert!(alive(pid));
    assert_eq!(proxy.releases.load(Ordering::SeqCst), 0);
    let status = forward(&dir.0, None, &["status"]);
    assert!(status.status.success(), "{}", text(&status));
    drop(stop);
}

/// The two lines of a setup script, back to back with no wait between:
/// `down`, then `up --daemon` with a new package on the same port. `down`
/// answers once the port and `state.json` are gone, so the new forwarder
/// binds at once, and its own `down` reaches it, not the old one.
#[tokio::test(flavor = "multi_thread")]
async fn down_then_up_back_to_back_runs_the_new_package() {
    let dir = Dir::new();
    let first = SandboxId::generate();
    let proxy = stand_in(Answer::Claim, first).await;
    let mut stop = Kill(Vec::new());
    let port = up_first(&dir, &package(&proxy, first), &mut stop);
    let old = state_pid(&dir.0).expect("state.json");
    let second = SandboxId::generate();
    let next_proxy = stand_in(Answer::Claim, second).await;
    let fresh = package(&next_proxy, second);
    let out = forward(&dir.0, None, &["down"]);
    assert!(out.status.success(), "{}", text(&out));
    up_on(&dir, &fresh, port, &mut stop);
    assert_eq!(proxy.releases.load(Ordering::SeqCst), 1);
    assert_eq!(next_proxy.claims.load(Ordering::SeqCst), 1);
    assert!(gone(old));
    stop.forget(old);
    let new = state_pid(&dir.0).expect("state.json");
    assert_ne!(new, old);
    let (out, said, _) = down_json(&dir.0);
    assert!(out.status.success(), "{}", text(&out));
    assert_eq!(said["sandbox"]["sandbox_id"], second.to_string(), "{said}");
    stopped_cleanly(&dir.0, new, port, second, &mut stop);
}

/// Two `down`s at the same moment (a setup script run twice at once):
/// both exit 0, the sandbox is released once, and the port is free. The
/// one that did not stop it finds nothing running, never "cannot stop".
#[tokio::test(flavor = "multi_thread")]
async fn two_downs_at_once_both_succeed_and_release_once() {
    let dir = Dir::new();
    let mut stop = Kill(Vec::new());
    for round in 0..3 {
        let sandbox = SandboxId::generate();
        let proxy = stand_in(Answer::Claim, sandbox).await;
        let port = up_any(&dir, &package(&proxy, sandbox), &mut stop);
        let pid = state_pid(&dir.0).expect("state.json");
        let started: Vec<_> = (0..2)
            .map(|_| {
                forward_command(&dir.0, &["down", "--json"])
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    .spawn()
                    .unwrap()
            })
            .collect();
        let mut statuses = Vec::new();
        for child in started {
            let out = child.wait_with_output().unwrap();
            assert!(out.status.success(), "round {round}: {}", text(&out));
            let said: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
            statuses.push(said["status"].as_str().unwrap().to_owned());
        }
        statuses.sort();
        assert_eq!(statuses, ["not_running", "stopped"], "round {round}");
        assert_eq!(proxy.releases.load(Ordering::SeqCst), 1, "round {round}");
        stopped_cleanly(&dir.0, pid, port, sandbox, &mut stop);
    }
}

/// Idle connections on `down.sock` from this user's other programs (open,
/// silent, or a request cut short) never hold `down` up: it still
/// releases and stops at once.
#[tokio::test(flavor = "multi_thread")]
async fn idle_connections_on_the_socket_never_hold_up_down() {
    use std::io::Write;
    let dir = Dir::new();
    let sandbox = SandboxId::generate();
    let proxy = stand_in(Answer::Claim, sandbox).await;
    let mut stop = Kill(Vec::new());
    let port = up_any(&dir, &package(&proxy, sandbox), &mut stop);
    let pid = state_pid(&dir.0).expect("state.json");
    let socket = dir.0.join("state/down.sock");
    let mut idle = Vec::new();
    for n in 0..12 {
        let mut c = std::os::unix::net::UnixStream::connect(&socket).unwrap();
        if n % 2 == 0 {
            c.write_all(b"{\"v\":1,").unwrap();
        }
        idle.push(c);
    }
    let (out, said, took) = down_json(&dir.0);
    assert!(out.status.success(), "{}", text(&out));
    assert_eq!(said["release"], "released", "{said}");
    assert!(took < std::time::Duration::from_secs(3), "{took:?}");
    assert_eq!(proxy.releases.load(Ordering::SeqCst), 1);
    stopped_cleanly(&dir.0, pid, port, sandbox, &mut stop);
    drop(idle);
}

/// A `down` started in the background: killed and reaped if the test
/// ends before it is waited on.
struct Running(Option<std::process::Child>);

impl Drop for Running {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Every reader place on `down.sock` taken for longer than `down` waits:
/// `down` refuses with the "busy" wording and a `next` that says to try
/// once more in a few seconds, and stops and releases nothing. Once they
/// go, `down` stops it.
///
/// A place held after `ready` lasts the forwarder's `REQUEST_WAIT` (5 s),
/// as long as `down`'s own wait for `ready`, so the 16 connections must get
/// `ready` after `down` fixed its deadline, and by more than its pause
/// between connections. A stand-in listener on `down.sock` (the
/// forwarder's socket moved aside meanwhile) takes `down`'s first four
/// connections: it closes three, so `down` paused 100 ms three times, and
/// keeps the fourth open while the 16 take every place through the moved
/// socket. Then the socket goes back and the fourth closes: `down` spends
/// the rest of its 5 s on a full forwarder, whose places free at least
/// 300 ms after `down` gave up.
#[tokio::test(flavor = "multi_thread")]
async fn down_says_busy_when_the_socket_stays_full() {
    use std::io::{BufRead, BufReader, Write};
    let dir = Dir::new();
    let sandbox = SandboxId::generate();
    let proxy = stand_in(Answer::Claim, sandbox).await;
    let mut stop = Kill(Vec::new());
    let port = up_any(&dir, &package(&proxy, sandbox), &mut stop);
    let pid = state_pid(&dir.0).expect("state.json");
    let socket = dir.0.join("state/down.sock");
    // A connected socket stays the forwarder's under its new name.
    let aside = dir.0.join("state/down.held");
    std::fs::rename(&socket, &aside).unwrap();
    let early = tokio::net::UnixListener::bind(&socket).unwrap();
    let begun = std::time::Instant::now();
    let mut down = Running(Some(
        forward_command(&dir.0, &["down", "--json"])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap(),
    ));
    // `down` fixes its deadline before its first connection.
    let next = || async {
        tokio::time::timeout(std::time::Duration::from_secs(5), early.accept())
            .await
            .expect("down connects again within 5 s")
            .unwrap()
            .0
    };
    for _ in 0..3 {
        drop(next().await);
    }
    // Waiting for its `ready` until the forwarder's socket is back.
    let parked = next().await;
    let held: Vec<_> = (0..16)
        .map(|_| {
            let mut c = std::os::unix::net::UnixStream::connect(&aside).unwrap();
            c.write_all(b"{\"v\":1,\"op\":\"down\"}\n").unwrap();
            let mut line = String::new();
            BufReader::new(&c).read_line(&mut line).unwrap();
            assert!(line.contains("ready"), "{line}");
            c
        })
        .collect();
    std::fs::rename(&aside, &socket).unwrap();
    // The forwarder's socket is back well before `down`'s 5 s wait ends,
    // so its last tries meet the real, full forwarder. On a machine slow
    // enough to fail this, a busy answer could come from the stand-in's
    // connections alone and prove nothing.
    let back = begun.elapsed();
    assert!(back < std::time::Duration::from_secs(4), "{back:?}");
    drop(early);
    drop(parked);
    let child = down.0.take().unwrap();
    let out = tokio::task::spawn_blocking(move || child.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    let took = begun.elapsed();
    let said: serde_json::Value =
        serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("{e}: {}", text(&out)));
    // One line, as `down_json` checks: a program reads it with one
    // `read_line`.
    assert_eq!(
        out.stdout.iter().filter(|b| **b == b'\n').count(),
        1,
        "{}",
        text(&out)
    );
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    assert_eq!(said["error"], "klav_forward_cannot_stop", "{said}");
    let message = said["message"].as_str().unwrap();
    // The forwarder closed its last connections at once, or had not taken
    // the last one by the deadline: either way, busy.
    assert!(
        message.contains("may be busy with other connections"),
        "{said}"
    );
    let next = said["next"].as_str().unwrap();
    assert!(
        next.starts_with("Run `klav-forward down` once more in a few seconds"),
        "{said}"
    );
    assert!(took >= std::time::Duration::from_secs(4), "{took:?}");
    assert!(alive(pid));
    assert_eq!(proxy.releases.load(Ordering::SeqCst), 0);
    drop(held);
    let (out, said, _) = down_json(&dir.0);
    assert!(out.status.success(), "{}", text(&out));
    assert_eq!(said["release"], "released", "{said}");
    stopped_cleanly(&dir.0, pid, port, sandbox, &mut stop);
}

/// Every reader place on `down.sock` taken (16 connections that send
/// nothing): the forwarder closes `down`'s connection at once, and `down`
/// connects again every 100 ms for 5 s. Once a place frees up, it releases
/// and stops.
#[tokio::test(flavor = "multi_thread")]
async fn down_waits_out_a_full_socket_for_a_few_seconds() {
    let dir = Dir::new();
    let sandbox = SandboxId::generate();
    let proxy = stand_in(Answer::Claim, sandbox).await;
    let mut stop = Kill(Vec::new());
    let port = up_any(&dir, &package(&proxy, sandbox), &mut stop);
    let pid = state_pid(&dir.0).expect("state.json");
    let socket = dir.0.join("state/down.sock");
    let full: Vec<_> = (0..16)
        .map(|_| std::os::unix::net::UnixStream::connect(&socket).unwrap())
        .collect();
    // Taken by the forwarder's readers before `down` comes.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let closing = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_secs(1));
        drop(full);
    });
    let (out, said, took) = down_json(&dir.0);
    closing.join().unwrap();
    assert!(out.status.success(), "{}", text(&out));
    assert_eq!(said["release"], "released", "{said}");
    assert!(took >= std::time::Duration::from_millis(600), "{took:?}");
    assert!(took < std::time::Duration::from_secs(4), "{took:?}");
    stopped_cleanly(&dir.0, pid, port, sandbox, &mut stop);
}

/// Two setup scripts of one state directory: A's `down` waits on a release
/// that hangs, and meanwhile B's `up` claims the port with a new package
/// (B's `down` first would find nothing to stop: the two-`down`s test
/// covers that, and here it would eat half of the release's 10 s). When A's answer comes, A says that
/// it stopped its forwarder, with its release, and that a newer forwarder
/// of the directory holds the port: never that something unknown holds it.
#[tokio::test(flavor = "multi_thread")]
async fn a_late_down_names_the_newer_forwarder_that_took_the_port() {
    let dir = Dir::new();
    let first = SandboxId::generate();
    let proxy = stand_in(Answer::Claim, first).await;
    let mut stop = Kill(Vec::new());
    let port = up_first(&dir, &package(&proxy, first), &mut stop);
    let old = state_pid(&dir.0).expect("state.json");
    proxy.release.store(RELEASE_HANG, Ordering::SeqCst);
    let mut a = forward_command(&dir.0, &["down", "--json"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    // A committed, and its forwarder waits on the release.
    let begun = std::time::Instant::now();
    while proxy.releases.load(Ordering::SeqCst) == 0 {
        assert!(begun.elapsed() < std::time::Duration::from_secs(5));
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let second = SandboxId::generate();
    let next_proxy = stand_in(Answer::Claim, second).await;
    up_on(&dir, &package(&next_proxy, second), port, &mut stop);
    assert!(
        a.try_wait().unwrap().is_none(),
        "B's up took longer than the 10 s release window ({:?} since A's commit)",
        begun.elapsed()
    );
    let new = state_pid(&dir.0).expect("state.json");
    assert_ne!(new, old);

    let a = a.wait_with_output().unwrap();
    assert_eq!(a.status.code(), Some(1), "{}", text(&a));
    let said: serde_json::Value = serde_json::from_slice(&a.stdout).unwrap();
    assert_eq!(said["error"], "klav_forward_cannot_stop", "{said}");
    let message = said["message"].as_str().unwrap();
    assert!(message.contains("release: unknown"), "{said}");
    assert!(
        message.contains(&format!(
            "newer forwarder of this state directory (sandbox {second})"
        )),
        "{said}"
    );
    assert!(gone(old));
    stop.forget(old);
    // The newer forwarder runs on, untouched.
    assert!(alive(new));
    let status = forward(&dir.0, None, &["status"]);
    assert!(status.status.success(), "{}", text(&status));
    assert_eq!(next_proxy.releases.load(Ordering::SeqCst), 0);
}

/// A request a client wrote and left behind (it never committed) is never
/// acted on later: the forwarder keeps running and releases nothing, and
/// a real `down` after it works. Runs where CI runs (Linux) as on macOS.
#[tokio::test(flavor = "multi_thread")]
async fn a_request_left_behind_without_its_commit_is_never_acted_on() {
    use std::io::{BufRead, Write};
    let dir = Dir::new();
    let sandbox = SandboxId::generate();
    let proxy = stand_in(Answer::Claim, sandbox).await;
    let mut stop = Kill(Vec::new());
    let port = up_any(&dir, &package(&proxy, sandbox), &mut stop);
    let pid = state_pid(&dir.0).expect("state.json");
    let socket = dir.0.join("state/down.sock");
    // Gone before `ready`: the request stays in the socket's buffer.
    let mut gone_early = std::os::unix::net::UnixStream::connect(&socket).unwrap();
    gone_early
        .write_all(b"{\"v\":1,\"op\":\"down\"}\n")
        .unwrap();
    drop(gone_early);
    // Gone after `ready`, as a `down` that gave up would.
    let mut gone_late = std::os::unix::net::UnixStream::connect(&socket).unwrap();
    gone_late.write_all(b"{\"v\":1,\"op\":\"down\"}\n").unwrap();
    let mut ready = String::new();
    std::io::BufReader::new(&gone_late)
        .read_line(&mut ready)
        .unwrap();
    assert!(ready.contains("\"ready\""), "{ready}");
    drop(gone_late);
    // Longer than the forwarder waits for a commit.
    tokio::time::sleep(std::time::Duration::from_secs(6)).await;
    assert!(alive(pid));
    assert_eq!(proxy.releases.load(Ordering::SeqCst), 0);
    assert!(!port_free(port));
    let status = forward(&dir.0, None, &["status"]);
    assert!(status.status.success(), "{}", text(&status));

    let (out, said, _) = down_json(&dir.0);
    assert!(out.status.success(), "{}", text(&out));
    assert_eq!(said["release"], "released", "{said}");
    assert_eq!(proxy.releases.load(Ordering::SeqCst), 1);
    stopped_cleanly(&dir.0, pid, port, sandbox, &mut stop);
}

/// Something of this user's replaced `down.sock` and answers that the
/// forwarder stopped, while the real one still holds its port: `down`
/// checks the port and refuses (exit 1), whatever port the answer names.
/// A setup script never hears "free" while the port is taken.
#[tokio::test(flavor = "multi_thread")]
async fn down_never_believes_a_socket_while_the_port_is_taken() {
    let dir = Dir::new();
    let sandbox = SandboxId::generate();
    let proxy = stand_in(Answer::Claim, sandbox).await;
    let mut stop = Kill(Vec::new());
    let port = up_any(&dir, &package(&proxy, sandbox), &mut stop);
    let pid = state_pid(&dir.0).expect("state.json");
    let state: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.0.join("state/state.json")).unwrap()).unwrap();
    let socket = dir.0.join("state/down.sock");
    std::fs::remove_file(&socket).unwrap();
    let fake = tokio::net::UnixListener::bind(&socket).unwrap();
    let named = Arc::new(std::sync::atomic::AtomicU16::new(port));
    let named_sandbox = Arc::new(std::sync::Mutex::new(state["sandbox"].clone()));
    let answering = {
        let (named, sandbox) = (Arc::clone(&named), Arc::clone(&named_sandbox));
        tokio::spawn(async move {
            use tokio::io::{AsyncBufReadExt, BufReader};
            while let Ok((stream, _)) = fake.accept().await {
                let mut stream = BufReader::new(stream);
                let mut line = String::new();
                let _ = stream.read_line(&mut line).await;
                let _ = stream.write_all(b"{\"v\":1,\"op\":\"ready\"}\n").await;
                line.clear();
                let _ = stream.read_line(&mut line).await;
                let stopped = serde_json::json!({
                    "v": 1,
                    "sandbox": sandbox.lock().unwrap().clone(),
                    "port": named.load(Ordering::SeqCst),
                    "release": "released",
                    "logged": true,
                });
                let _ = stream.write_all(format!("{stopped}\n").as_bytes()).await;
            }
        })
    };
    // It names the forwarder's port, then another one that is free.
    for named_port in [port, free_port()] {
        named.store(named_port, Ordering::SeqCst);
        let out = forward(&dir.0, None, &["down", "--json"]);
        assert_eq!(out.status.code(), Some(1), "{}", text(&out));
        let said: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(said["error"], "klav_forward_cannot_stop", "{said}");
        assert!(
            said["message"]
                .as_str()
                .unwrap()
                .contains(&format!("127.0.0.1:{port} is still taken")),
            "{said}"
        );
        assert!(alive(pid));
        assert_eq!(proxy.releases.load(Ordering::SeqCst), 0);
    }
    // It names another sandbox on a port an unrelated program holds, while
    // the forwarder of `state.json` (newer than that one, by its sandbox)
    // answers on its own port: `down` names the port that is taken, never
    // the newer forwarder, which holds another port.
    let unrelated = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let held = unrelated.local_addr().unwrap().port();
    named.store(held, Ordering::SeqCst);
    named_sandbox.lock().unwrap()["sandbox_id"] =
        serde_json::json!(SandboxId::generate().to_string());
    let out = forward(&dir.0, None, &["down", "--json"]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    let said: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let message = said["message"].as_str().unwrap();
    assert!(
        message.contains(&format!("127.0.0.1:{held} is still taken")),
        "{said}"
    );
    assert!(!message.contains("newer forwarder"), "{said}");
    assert!(alive(pid));
    drop(unrelated);
    answering.abort();
    drop(stop);
}

/// A state directory too deep for a unix socket's path (103 bytes on
/// macOS, 107 on Linux): the forwarder runs without a control socket, `up`
/// says on stderr that `down` cannot stop it, and `down` refuses.
#[tokio::test(flavor = "multi_thread")]
async fn up_says_when_down_cannot_stop_its_forwarder() {
    let root = Dir::new();
    let deep = root.0.join("d".repeat(120));
    std::fs::create_dir(&deep).unwrap();
    let sandbox = SandboxId::generate();
    let proxy = stand_in(Answer::Claim, sandbox).await;
    let mut stop = Kill(Vec::new());
    let out = forward(
        &deep,
        Some(&package(&proxy, sandbox)),
        &["up", "--daemon", "--port", "0", "--no-skill"],
    );
    stop.after_up(&deep);
    assert!(out.status.success(), "{}", text(&out));
    let said = String::from_utf8_lossy(&out.stderr);
    assert!(said.contains("no control socket"), "{said}");
    assert!(said.contains("cannot stop it"), "{said}");
    let log = std::fs::read_to_string(deep.join("state/forward.log")).unwrap_or_default();
    assert!(log.contains("no control socket"), "{log}");
    assert!(!deep.join("state/down.sock").exists());
    let out = forward(&deep, None, &["down", "--json"]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    let said: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(said["error"], "klav_forward_cannot_stop", "{said}");
    assert_eq!(proxy.releases.load(Ordering::SeqCst), 0);
    drop(stop);
}

/// A `state.json` that cannot be parsed, with nothing on the socket:
/// `down` cannot tell whether anything runs, so it refuses (exit 1)
/// instead of saying there is nothing to stop, and changes nothing.
#[test]
fn down_refuses_when_it_cannot_read_the_state() {
    let dir = Dir::new();
    let state = dir.0.join("state");
    std::fs::create_dir(&state).unwrap();
    std::fs::write(state.join("state.json"), b"{not json").unwrap();
    let out = forward(&dir.0, None, &["down", "--json"]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    let said: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(said["error"], "klav_forward_cannot_stop", "{said}");
    assert_eq!(
        std::fs::read(state.join("state.json")).unwrap(),
        b"{not json"
    );
}

/// `env --json` is one line with what the `export` lines carry, for every
/// profile; the default output is the same bytes as before. Without a
/// state, `--json` says so as JSON, and the default as before.
#[test]
fn env_json_has_every_profile_and_the_default_lines_are_unchanged() {
    let dir = Dir::new();
    let state = dir.0.join("state");
    std::fs::create_dir(&state).unwrap();
    std::fs::write(
        state.join("state.json"),
        serde_json::to_vec(&serde_json::json!({
            "v": 1,
            "pid": 1,
            "port": 8790,
            "sandbox": {
                "sandbox_id": SandboxId::generate().to_string(),
                "label": "chat-1",
                "profiles": ["northflank", "my-api", "x'; rm -rf /"],
                "expires_at": 4_102_444_800_000_i64,
            },
        }))
        .unwrap(),
    )
    .unwrap();
    let out = forward(&dir.0, None, &["env"]);
    assert!(out.status.success(), "{}", text(&out));
    assert_eq!(
        String::from_utf8(out.stdout).unwrap(),
        concat!(
            "# Written by klav-forward up (ADR 0036): local URLs only, no secrets.\n",
            "export KLAV_FORWARD_URL='http://127.0.0.1:8790'\n",
            "export KLAV_FORWARD_NORTHFLANK_URL='http://127.0.0.1:8790/northflank'\n",
            "export KLAV_FORWARD_MY_API_URL='http://127.0.0.1:8790/my-api'\n",
        )
    );
    let out = forward(&dir.0, None, &["env", "--json"]);
    assert!(out.status.success(), "{}", text(&out));
    let line = String::from_utf8(out.stdout).unwrap();
    assert_eq!(line.matches('\n').count(), 1, "{line}");
    assert!(line.ends_with('\n'), "{line}");
    let said: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(
        said,
        serde_json::json!({
            "url": "http://127.0.0.1:8790",
            "profiles": {
                "northflank": "http://127.0.0.1:8790/northflank",
                "my-api": "http://127.0.0.1:8790/my-api",
            },
            "env": {
                "KLAV_FORWARD_URL": "http://127.0.0.1:8790",
                "KLAV_FORWARD_NORTHFLANK_URL": "http://127.0.0.1:8790/northflank",
                "KLAV_FORWARD_MY_API_URL": "http://127.0.0.1:8790/my-api",
            },
        })
    );

    std::fs::remove_file(state.join("state.json")).unwrap();
    let out = forward(&dir.0, None, &["env", "--json"]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    let said: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(said["error"], "klav_forward_not_running", "{said}");
    let out = forward(&dir.0, None, &["env"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
    assert_eq!(
        String::from_utf8(out.stderr).unwrap(),
        format!(
            "klav-forward: no forwarder state in {}: run `klav-forward up` first.\n",
            state.display()
        )
    );
}

/// Every `klav-forward <command>` (and its flags) the skill names exists:
/// `klav-forward <command> --help` knows it (ADR 0036 E1.5).
#[test]
fn every_forward_command_the_skill_names_exists() {
    let mut named = Vec::new();
    for (i, span) in SKILL.split('`').enumerate() {
        if i % 2 == 1
            && let Some(rest) = span.strip_prefix("klav-forward ")
        {
            named.push(
                rest.split_whitespace()
                    .map(str::to_owned)
                    .collect::<Vec<_>>(),
            );
        }
    }
    assert!(named.iter().any(|n| n[0] == "up"), "{named:?}");
    for words in named {
        let help = Command::new(BIN)
            .arg(&words[0])
            .arg("--help")
            .output()
            .unwrap();
        assert!(help.status.success(), "`klav-forward {}`", words[0]);
        let text = String::from_utf8_lossy(&help.stdout);
        for flag in words.iter().skip(1).filter(|w| w.starts_with("--")) {
            assert!(
                text.contains(flag.as_str()),
                "`klav-forward {}` has no {flag}",
                words[0]
            );
        }
    }
}

/// The setup lines `klav sandbox start` gives (`SETUP` in `klav-cli`,
/// whose own test checks them line by line).
/// The source of `klav sandbox start`, whose `SETUP` these tests run: the
/// lines are read from it, never copied, so they cannot drift apart.
/// `crates/klav-cli/tests/sandbox.rs` pins the same literal from its side.
const CLI_SANDBOX_RS: &str = include_str!("../../klav-cli/src/commands/sandbox.rs");

/// `SETUP` from [`CLI_SANDBOX_RS`]: each string literal of its array, with
/// `\"` and `\\` unescaped (it uses no other escape).
fn setup_lines() -> Vec<String> {
    let at = CLI_SANDBOX_RS
        .find("pub(crate) const SETUP: [&str; 3] = [\n")
        .expect("klav-cli's SETUP");
    let body = &CLI_SANDBOX_RS[at..];
    let body = &body[body.find("= [\n").expect("SETUP") + 4..];
    let body = &body[..body.find("];").expect("SETUP's end")];
    body.lines()
        .map(|line| {
            let line = line.trim().trim_end_matches(',');
            let inner = line
                .strip_prefix('"')
                .and_then(|l| l.strip_suffix('"'))
                .unwrap_or_else(|| panic!("not a plain string literal: {line}"));
            inner.replace("\\\"", "\"").replace("\\\\", "\\")
        })
        .collect()
}

/// The lines these tests run are the ones `klav sandbox start` gives, and
/// they are these (as `klav-cli`'s `tests/sandbox.rs` checks from its
/// side): a change on either side fails one of the two.
#[test]
fn the_setup_lines_are_the_ones_klav_sandbox_start_gives() {
    assert_eq!(
        setup_lines(),
        [
            "klav-forward down --if-other-package",
            "klav-forward up --daemon",
            "eval \"$(klav-forward env)\"",
        ]
    );
}

/// Runs `lines` as a setup script (`sh -e`) with `package` in
/// `KLAV_SANDBOX` and `klav-forward` on the `PATH`, as a sandbox does, then
/// prints `url=$KLAV_FORWARD_URL`. To stay inside the test's directory,
/// `up` also gets `--port` (`0`: one the system picks), `--no-skill` and
/// `--profile-file`; `down` and `env` find the port in `state.json`.
fn run_setup(dir: &Dir, package: &str, lines: &[String], port: u16) -> Output {
    let profile = dir.0.join("profile.sh");
    let mut script = String::from("set -e\n");
    for line in lines {
        script.push_str(line);
        if line == "klav-forward up --daemon" {
            script.push_str(&format!(
                " --port {port} --no-skill --profile-file '{}'",
                profile.display()
            ));
        }
        script.push('\n');
    }
    script.push_str("printf 'url=%s\\n' \"$KLAV_FORWARD_URL\"\n");
    let bin = Path::new(BIN).parent().unwrap();
    let path = std::env::var("PATH").unwrap_or_default();
    Command::new("sh")
        .arg("-c")
        .arg(script)
        .env("PATH", format!("{}:{path}", bin.display()))
        .env("HOME", &dir.0)
        .env("KLAV_FORWARD_HOME", dir.0.join("state"))
        .env("KLAV_SANDBOX", package)
        .output()
        .unwrap()
}

/// The first run of `lines` in a test that binds the same port again later
/// (a newer package taking over): on a port of [`free_port`], drawn again
/// only while something else took it before any claim. What it printed,
/// and its port. A redraw is said on stderr.
#[allow(clippy::print_stderr)]
fn setup_first(dir: &Dir, package: &str, lines: &[String]) -> (Output, u16) {
    for _ in 0..PORT_DRAWS {
        let port = free_port();
        let out = run_setup(dir, package, lines, port);
        if !port_taken_before_any_claim(dir, &out, port) {
            return (out, port);
        }
        eprintln!("port {port} was taken before `up` bound it: drawing another");
    }
    panic!("{PORT_DRAWS} ports in a row were taken before `up` bound them");
}

/// The line `down --if-other-package` prints when it leaves this
/// package's forwarder alone.
const LEFT_ALONE: &str = "is for this package's sandbox";

/// The setup lines on a first start, where `down` finds nothing (exit 0,
/// and nothing that stops the script), and on a sandbox resumed with its
/// memory alive and handed a new package, where the old package's
/// forwarder still holds the port. There the lines without `down` stop at
/// `up` (the port is taken; refused before any claim, so the new package
/// stays usable), and the lines with `down --if-other-package` first
/// release the old sandbox, stop its forwarder and claim the new package
/// on the same port.
#[tokio::test(flavor = "multi_thread")]
async fn the_setup_lines_take_over_from_a_forwarder_still_running() {
    let setup = setup_lines();
    let dir = Dir::new();
    let mut stop = Kill(Vec::new());

    // First start: `down` has nothing to stop.
    let old = SandboxId::generate();
    let old_proxy = stand_in(Answer::Claim, old).await;
    let (out, port) = setup_first(&dir, &package(&old_proxy, old), &setup);
    let url = format!("http://127.0.0.1:{port}");
    stop.after_up(&dir.0);
    assert!(out.status.success(), "{}", text(&out));
    let said = String::from_utf8_lossy(&out.stdout);
    assert!(
        said.starts_with("klav-forward is not running here: nothing to stop.\n"),
        "{said}"
    );
    assert!(said.ends_with(&format!("url={url}\n")), "{said}");
    assert_eq!(old_proxy.claims.load(Ordering::SeqCst), 1);
    let old_pid = state_pid(&dir.0).expect("state.json");

    // Resumed: the old forwarder still runs. Without `down`, `up` stops
    // the script; nothing is claimed and the old forwarder runs on.
    let new = SandboxId::generate();
    let new_proxy = stand_in(Answer::Claim, new).await;
    let new_package = package(&new_proxy, new);
    let out = run_setup(&dir, &new_package, &setup[1..], port);
    assert!(!out.status.success(), "{}", text(&out));
    assert!(
        text(&out).contains(&format!("127.0.0.1:{port} is not free")),
        "{}",
        text(&out)
    );
    assert!(!String::from_utf8_lossy(&out.stdout).contains("url="));
    assert_eq!(new_proxy.claims.load(Ordering::SeqCst), 0);
    assert_eq!(state_pid(&dir.0), Some(old_pid));
    assert!(alive(old_pid));

    // With `down --if-other-package` first: the old sandbox is released
    // and its forwarder stopped, and the same new package claims on the
    // same port.
    let out = run_setup(&dir, &new_package, &setup, port);
    stop.after_up(&dir.0);
    assert!(out.status.success(), "{}", text(&out));
    assert!(
        String::from_utf8_lossy(&out.stdout).ends_with(&format!("url={url}\n")),
        "{}",
        text(&out)
    );
    assert!(gone(old_pid), "the old forwarder still runs");
    stop.forget(old_pid);
    assert_eq!(old_proxy.releases.load(Ordering::SeqCst), 1);
    assert_eq!(new_proxy.claims.load(Ordering::SeqCst), 1);
    let new_pid = state_pid(&dir.0).expect("state.json");
    assert_ne!(new_pid, old_pid);
    let status = forward(&dir.0, None, &["status", "--json"]);
    assert!(status.status.success(), "{}", text(&status));
    drop(stop);
}

/// The same setup script run again with the same package (a provider that
/// replays it on resume, or a person rerunning it): its forwarder is left
/// alone, `up` says it already runs, and the sandbox keeps working. A
/// plain `down` first would release the sandbox and stop its forwarder,
/// and `up` would then refuse the spent package.
#[tokio::test(flavor = "multi_thread")]
async fn the_setup_lines_run_again_with_the_same_package_leave_its_forwarder_alone() {
    let setup = setup_lines();
    let dir = Dir::new();
    let mut stop = Kill(Vec::new());
    let sandbox = SandboxId::generate();
    let proxy = stand_in(Answer::Claim, sandbox).await;
    let package = package(&proxy, sandbox);
    let out = run_setup(&dir, &package, &setup, 0);
    stop.after_up(&dir.0);
    assert!(out.status.success(), "{}", text(&out));
    let port = bound_port(&dir.0).expect("state.json");
    let url = format!("http://127.0.0.1:{port}");
    let pid = state_pid(&dir.0).expect("state.json");

    let out = run_setup(&dir, &package, &setup, port);
    stop.after_up(&dir.0);
    assert!(out.status.success(), "{}", text(&out));
    let said = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<&str> = said.lines().collect();
    assert!(lines[0].contains(LEFT_ALONE), "{said}");
    assert!(lines[0].contains(&sandbox.to_string()), "{said}");
    assert!(said.contains("is already running for sandbox"), "{said}");
    assert!(said.ends_with(&format!("url={url}\n")), "{said}");
    assert!(!text(&out).contains(package.as_str()));
    assert_eq!(state_pid(&dir.0), Some(pid));
    assert!(alive(pid));
    assert_eq!(proxy.releases.load(Ordering::SeqCst), 0);
    assert_eq!(proxy.claims.load(Ordering::SeqCst), 1);
    let status = forward(&dir.0, None, &["status", "--json"]);
    assert!(status.status.success(), "{}", text(&status));

    // The same outcome in JSON, without the package.
    let out = forward(
        &dir.0,
        Some(&package),
        &["down", "--if-other-package", "--json"],
    );
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert_eq!(out.stdout.iter().filter(|b| **b == b'\n').count(), 1);
    let said: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(said["status"], "same_package", "{said}");
    assert_eq!(said["sandbox"]["sandbox_id"], sandbox.to_string(), "{said}");
    assert!(!text(&out).contains(package.as_str()));
    assert!(alive(pid));
    assert_eq!(proxy.releases.load(Ordering::SeqCst), 0);
    drop(stop);
}

/// This package's forwarder is busy (every reader of its control socket
/// taken): the flagged `down` never asks it, exits 0 and touches nothing,
/// and `up` says it already runs, as `main`'s lines (`up` first) do. A
/// plain `down` would wait for the socket and refuse with
/// `klav_forward_cannot_stop`, stopping the script.
#[tokio::test(flavor = "multi_thread")]
async fn the_setup_lines_leave_this_packages_busy_forwarder_alone() {
    use std::io::{BufRead, BufReader, Write};
    let setup = setup_lines();
    let dir = Dir::new();
    let mut stop = Kill(Vec::new());
    let sandbox = SandboxId::generate();
    let proxy = stand_in(Answer::Claim, sandbox).await;
    let package = package(&proxy, sandbox);
    let out = run_setup(&dir, &package, &setup, 0);
    stop.after_up(&dir.0);
    assert!(out.status.success(), "{}", text(&out));
    let port = bound_port(&dir.0).expect("state.json");
    let pid = state_pid(&dir.0).expect("state.json");
    let socket = dir.0.join("state/down.sock");
    let state_before = std::fs::read(dir.0.join("state/state.json")).unwrap();

    // Every reader taken (control.rs `READERS`), each waiting up to 5 s
    // (`REQUEST_WAIT`) for a commit it never gets.
    let held: Vec<_> = (0..16)
        .map(|_| {
            let mut c = std::os::unix::net::UnixStream::connect(&socket).unwrap();
            c.write_all(b"{\"v\":1,\"op\":\"down\"}\n").unwrap();
            let mut line = String::new();
            BufReader::new(&c).read_line(&mut line).unwrap();
            assert!(line.contains("ready"), "{line}");
            c
        })
        .collect();
    let busy_since = std::time::Instant::now();
    let out = run_setup(&dir, &package, &setup, port);
    let main_lines = run_setup(&dir, &package, &setup[1..], port);
    let took = busy_since.elapsed();
    assert!(out.status.success(), "{}", text(&out));
    // Both ran while every reader was still taken.
    assert!(took < std::time::Duration::from_secs(4), "{took:?}");
    let said = String::from_utf8_lossy(&out.stdout);
    assert!(said.lines().next().unwrap().contains(LEFT_ALONE), "{said}");
    assert!(said.contains("is already running for sandbox"), "{said}");
    // What `up` did is what `main`'s lines do.
    assert!(main_lines.status.success(), "{}", text(&main_lines));
    assert!(
        String::from_utf8_lossy(&main_lines.stdout).contains("is already running for sandbox"),
        "{}",
        text(&main_lines)
    );
    drop(held);
    assert_eq!(
        std::fs::read(dir.0.join("state/state.json")).unwrap(),
        state_before
    );
    assert!(socket.exists());
    assert!(alive(pid));
    assert_eq!(proxy.releases.load(Ordering::SeqCst), 0);
    let status = forward(&dir.0, None, &["status", "--json"]);
    assert!(status.status.success(), "{}", text(&status));
    drop(stop);
}

/// This package's forwarder is gone, its `state.json` still there: the
/// flagged `down` exits 0 and touches nothing, and `up` refuses the spent
/// package with `klav_forward_already_claimed`, exactly as `main`'s lines
/// (`up` first) do. A plain `down` would end the same way, saying "not
/// running"; this checks that the flag removes nothing and says why it
/// left it.
#[tokio::test(flavor = "multi_thread")]
async fn the_setup_lines_leave_a_gone_forwarder_of_this_package_to_up() {
    let setup = setup_lines();
    let dir = Dir::new();
    let mut stop = Kill(Vec::new());
    let sandbox = SandboxId::generate();
    let proxy = stand_in(Answer::Claim, sandbox).await;
    let package = package(&proxy, sandbox);
    let out = run_setup(&dir, &package, &setup, 0);
    stop.after_up(&dir.0);
    assert!(out.status.success(), "{}", text(&out));
    let port = bound_port(&dir.0).expect("state.json");
    let pid = state_pid(&dir.0).expect("state.json");
    kill_now(pid);
    stop.forget(pid);
    let state = dir.0.join("state/state.json");
    let state_before = std::fs::read(&state).unwrap();

    let out = run_setup(&dir, &package, &setup, port);
    let main_lines = run_setup(&dir, &package, &setup[1..], port);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    let said = String::from_utf8_lossy(&out.stdout);
    assert!(said.lines().next().unwrap().contains(LEFT_ALONE), "{said}");
    assert!(
        text(&out).contains("was already claimed from here"),
        "{}",
        text(&out)
    );
    assert!(!said.contains("url="), "{said}");
    // What `up` did is what `main`'s lines do.
    assert_eq!(main_lines.status.code(), Some(1), "{}", text(&main_lines));
    assert_eq!(main_lines.stderr, out.stderr);
    assert_eq!(std::fs::read(&state).unwrap(), state_before);
    assert_eq!(proxy.releases.load(Ordering::SeqCst), 0);
    assert_eq!(proxy.claims.load(Ordering::SeqCst), 1);
}

/// With `KLAV_SANDBOX` unset, empty or not a package, or `state.json`
/// unreadable, `down --if-other-package` cannot tell which forwarder is
/// this package's, so it stops none: exit 0 and one line, never anything
/// of the value. A plain `down` would stop the forwarder and release its
/// sandbox.
#[tokio::test(flavor = "multi_thread")]
async fn down_if_other_package_stops_nothing_when_it_cannot_tell() {
    let setup = setup_lines();
    let dir = Dir::new();
    let mut stop = Kill(Vec::new());
    let sandbox = SandboxId::generate();
    let proxy = stand_in(Answer::Claim, sandbox).await;
    let out = run_setup(&dir, &package(&proxy, sandbox), &setup, 0);
    stop.after_up(&dir.0);
    assert!(out.status.success(), "{}", text(&out));
    let pid = state_pid(&dir.0).expect("state.json");
    let garbage = "not-a-package-7f3a9c";
    let cases: [(&str, Option<&str>); 3] = [
        ("unset", None),
        ("empty", Some("")),
        ("garbage", Some(garbage)),
    ];
    for (case, value) in cases {
        for json in [false, true] {
            let mut args = vec!["down", "--if-other-package"];
            if json {
                args.push("--json");
            }
            let mut command = forward_command(&dir.0, &args);
            if let Some(value) = value {
                command.env("KLAV_SANDBOX", value);
            }
            let out = command.output().unwrap();
            assert_eq!(out.status.code(), Some(0), "{case}: {}", text(&out));
            assert_eq!(
                out.stdout.iter().filter(|b| **b == b'\n').count(),
                1,
                "{case}: {}",
                text(&out)
            );
            assert!(out.stderr.is_empty(), "{case}: {}", text(&out));
            assert!(!text(&out).contains(garbage), "{case}");
            let said = String::from_utf8_lossy(&out.stdout);
            if json {
                let said: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
                assert_eq!(said["status"], "no_package", "{case}: {said}");
            } else {
                assert!(said.contains("nothing stopped"), "{case}: {said}");
            }
            assert!(alive(pid), "{case}");
            assert_eq!(proxy.releases.load(Ordering::SeqCst), 0, "{case}");
        }
    }

    // Another package, with a `state.json` that cannot be read: it cannot
    // tell whether the forwarder here is that package's either.
    let state = dir.0.join("state/state.json");
    let kept = std::fs::read(&state).unwrap();
    std::fs::write(&state, b"{").unwrap();
    let other = SandboxId::generate();
    let other_proxy = stand_in(Answer::Claim, other).await;
    let out = forward(
        &dir.0,
        Some(&package(&other_proxy, other)),
        &["down", "--if-other-package", "--json"],
    );
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let said: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(said["status"], "unreadable_state", "{said}");
    assert!(alive(pid));
    assert_eq!(proxy.releases.load(Ordering::SeqCst), 0);
    std::fs::write(&state, kept).unwrap();
    drop(stop);
}

/// The line `down --if-other-package` prints when this package was
/// already claimed here.
const CLAIMED_HERE: &str = "was already claimed from this state directory: nothing stopped";

/// An old package replayed (a provider that stored the environment at
/// creation and replays it on resume) over the forwarder of a newer one
/// that took over since: the flagged `down` sees the old package's claim
/// marker and stops nothing, and `up` refuses the spent package exactly as
/// `main`'s lines (`up` first) do. Without the marker check, `down` would
/// release the newer sandbox and stop its forwarder, and `up` would refuse
/// anyway.
#[tokio::test(flavor = "multi_thread")]
async fn the_setup_lines_never_stop_a_newer_package_for_an_old_one_replayed() {
    let setup = setup_lines();
    let dir = Dir::new();
    let mut stop = Kill(Vec::new());
    let old = SandboxId::generate();
    let old_proxy = stand_in(Answer::Claim, old).await;
    let old_package = package(&old_proxy, old);
    let (out, port) = setup_first(&dir, &old_package, &setup);
    stop.after_up(&dir.0);
    assert!(out.status.success(), "{}", text(&out));
    let old_pid = state_pid(&dir.0).expect("state.json");
    // The newer package takes over.
    let new = SandboxId::generate();
    let new_proxy = stand_in(Answer::Claim, new).await;
    let out = run_setup(&dir, &package(&new_proxy, new), &setup, port);
    stop.after_up(&dir.0);
    assert!(out.status.success(), "{}", text(&out));
    assert!(gone(old_pid));
    stop.forget(old_pid);
    let new_pid = state_pid(&dir.0).expect("state.json");

    // The old package replayed.
    let out = run_setup(&dir, &old_package, &setup, port);
    let main_lines = run_setup(&dir, &old_package, &setup[1..], port);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    let said = String::from_utf8_lossy(&out.stdout);
    let first = said.lines().next().unwrap();
    assert!(first.contains(CLAIMED_HERE), "{said}");
    assert!(first.contains(&old.to_string()), "{said}");
    assert!(
        text(&out).contains("was already claimed from here"),
        "{}",
        text(&out)
    );
    assert!(!said.contains("url="), "{said}");
    assert!(!text(&out).contains(old_package.as_str()));
    // What `up` did is what `main`'s lines do.
    assert_eq!(main_lines.status.code(), Some(1), "{}", text(&main_lines));
    assert_eq!(main_lines.stderr, out.stderr);
    // The newer sandbox is untouched and still answers.
    assert_eq!(state_pid(&dir.0), Some(new_pid));
    assert!(alive(new_pid));
    assert_eq!(new_proxy.releases.load(Ordering::SeqCst), 0);
    assert_eq!(old_proxy.releases.load(Ordering::SeqCst), 1);
    assert_eq!(old_proxy.claims.load(Ordering::SeqCst), 1);
    let status = forward(&dir.0, None, &["status", "--json"]);
    assert!(status.status.success(), "{}", text(&status));

    // In JSON: its own status, and only the ID.
    let out = forward(
        &dir.0,
        Some(&old_package),
        &["down", "--if-other-package", "--json"],
    );
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert_eq!(out.stdout.iter().filter(|b| **b == b'\n').count(), 1);
    let said: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(said["status"], "already_claimed_here", "{said}");
    assert!(!text(&out).contains(old_package.as_str()));
    assert!(alive(new_pid));
    assert_eq!(new_proxy.releases.load(Ordering::SeqCst), 0);
    drop(stop);
}

/// This package's forwarder runs with no `state.json` naming it (its save
/// failed, which it only logs): the lines run again with the same package
/// find its claim marker and stop nothing, and `up` refuses the spent
/// package as `main`'s lines do, while the forwarder keeps answering.
/// Without the marker check, `down` would find no `state.json`, reach the
/// forwarder through its socket, and release the sandbox.
#[tokio::test(flavor = "multi_thread")]
async fn the_setup_lines_leave_this_packages_forwarder_without_state_json_alone() {
    let setup = setup_lines();
    let dir = Dir::new();
    let mut stop = Kill(Vec::new());
    let sandbox = SandboxId::generate();
    let proxy = stand_in(Answer::Claim, sandbox).await;
    let package = package(&proxy, sandbox);
    let out = run_setup(&dir, &package, &setup, 0);
    stop.after_up(&dir.0);
    assert!(out.status.success(), "{}", text(&out));
    let port = bound_port(&dir.0).expect("state.json");
    let pid = state_pid(&dir.0).expect("state.json");
    let state = dir.0.join("state/state.json");
    let saved = std::fs::read(&state).unwrap();
    std::fs::remove_file(&state).unwrap();

    let out = run_setup(&dir, &package, &setup, port);
    let main_lines = run_setup(&dir, &package, &setup[1..], port);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    let said = String::from_utf8_lossy(&out.stdout);
    assert!(
        said.lines().next().unwrap().contains(CLAIMED_HERE),
        "{said}"
    );
    assert!(
        text(&out).contains("was already claimed from here"),
        "{}",
        text(&out)
    );
    assert_eq!(main_lines.status.code(), Some(1), "{}", text(&main_lines));
    assert_eq!(main_lines.stderr, out.stderr);
    assert!(!state.exists());
    assert!(alive(pid));
    assert_eq!(proxy.releases.load(Ordering::SeqCst), 0);
    // Still the live forwarder of this sandbox.
    std::fs::write(&state, saved).unwrap();
    let status = forward(&dir.0, None, &["status", "--json"]);
    assert!(status.status.success(), "{}", text(&status));
    drop(stop);
}

/// A claim marker that cannot be read counts as claimed, as `up` reads it:
/// the flagged `down` stops nothing.
#[tokio::test(flavor = "multi_thread")]
async fn down_if_other_package_takes_an_unreadable_marker_as_claimed() {
    let setup = setup_lines();
    let dir = Dir::new();
    let mut stop = Kill(Vec::new());
    let running = SandboxId::generate();
    let proxy = stand_in(Answer::Claim, running).await;
    let out = run_setup(&dir, &package(&proxy, running), &setup, 0);
    stop.after_up(&dir.0);
    assert!(out.status.success(), "{}", text(&out));
    let pid = state_pid(&dir.0).expect("state.json");
    let other = SandboxId::generate();
    let other_proxy = stand_in(Answer::Claim, other).await;
    let marker = dir.0.join("state/claimed").join(other.to_string());
    std::fs::create_dir_all(marker.parent().unwrap()).unwrap();
    std::fs::write(&marker, b"not a marker").unwrap();
    let out = forward(
        &dir.0,
        Some(&package(&other_proxy, other)),
        &["down", "--if-other-package", "--json"],
    );
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let said: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(said["status"], "already_claimed_here", "{said}");
    assert!(alive(pid));
    assert_eq!(proxy.releases.load(Ordering::SeqCst), 0);
    assert_eq!(std::fs::read(&marker).unwrap(), b"not a marker");
    drop(stop);
}
