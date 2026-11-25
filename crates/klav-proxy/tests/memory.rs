//! The binary's memory (ADR 0044 §3, layer 1, and Omar's decisions of
//! 2026-11-19): where the memory flags go, the values of their variables,
//! the lock turned off, a required lock that did not take, what reaches
//! stdout, and a proxy that locked its memory serving a request.
//!
//! A child's `memlock` limit is set through `prlimit` (Linux, util-linux),
//! never on this test process, and never with more privilege than the
//! test has: a test reads the limit it inherited and asserts the branch
//! that applies to it. The tests that need a lock are `#[ignore]`d, fail
//! on their precondition when run without it, and run in CI's `test` task
//! with a raised limit (ADR 0044, layer 1).

// The locked test prints what it measured; it holds no value.
#![allow(clippy::print_stdout)]

#[path = "../../klav-client/tests/common/mod.rs"]
mod common;

use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_klav-proxy");
const REQUIRE: &str = "KLAV_PROXY_REQUIRE_MEMORY_LOCK";
const LOCK: &str = "KLAV_PROXY_MEMORY_LOCK";
const EMAIL: &str = "ana@example.com";
/// What `serve` says after the memory, on an empty home.
const NO_REGISTRATION: &str = "not found: agent";

/// The binary with none of the variables it refuses or these tests set,
/// whatever the machine running the tests sets.
fn proxy() -> Command {
    let mut cmd = Command::new(BIN);
    clean(&mut cmd);
    cmd
}

fn clean(cmd: &mut Command) {
    for var in [
        REQUIRE,
        LOCK,
        "KLAV_AGENT_KEY",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
    ] {
        cmd.env_remove(var);
    }
}

fn text(out: &Output) -> (String, String) {
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// The binary under `prlimit --memlock=<limits>` (Linux; `None` elsewhere).
/// `prlimit` sets the limit and runs the binary in its own process, so the
/// child's pid is the proxy's. Lowering a limit, or raising a soft one up
/// to the hard one, needs no privilege. A Linux host without `prlimit`
/// fails here rather than skip a branch.
fn under_memlock(limits: &str) -> Option<Command> {
    if !cfg!(target_os = "linux") {
        return None;
    }
    let found = Command::new("prlimit")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success());
    assert!(
        found,
        "these tests need prlimit (util-linux) on Linux to give a child a memlock limit"
    );
    let mut cmd = Command::new("prlimit");
    cmd.arg(format!("--memlock={limits}")).arg("--").arg(BIN);
    clean(&mut cmd);
    Some(cmd)
}

/// This process's `memlock` limit and whether it has `CAP_SYS_RESOURCE`
/// (Linux), read from `/proc/self`.
fn inherited() -> (String, String, bool) {
    let limits = std::fs::read_to_string("/proc/self/limits").expect("limits");
    let line = limits
        .lines()
        .find(|l| l.starts_with("Max locked memory"))
        .expect("Max locked memory");
    let mut words = line.split_whitespace().skip(3);
    let soft = words.next().expect("soft").to_owned();
    let hard = words.next().expect("hard").to_owned();
    let status = std::fs::read_to_string("/proc/self/status").expect("status");
    let cap_eff = status
        .lines()
        .find_map(|l| l.strip_prefix("CapEff:"))
        .and_then(|hex| u64::from_str_radix(hex.trim(), 16).ok())
        .expect("CapEff");
    (soft, hard, cap_eff & (1 << 24) != 0)
}

/// Whether the proxy, given a finite `memlock` limit through `prlimit`,
/// raises it and locks: only with `CAP_SYS_RESOURCE` (ADR 0044 §3.2).
fn raises_any_limit() -> bool {
    cfg!(target_os = "linux") && inherited().2
}

/// For the tests that need a lock: whether this process may give a child
/// an unlimited `memlock` limit (its hard limit is unlimited, or it has
/// `CAP_SYS_RESOURCE`). Run without that, they fail here rather than pass
/// having checked nothing.
fn require_an_unlimited_child() {
    if !cfg!(target_os = "linux") {
        panic!("precondition not met: only Linux locks");
    }
    let (soft, hard, cap) = inherited();
    assert!(
        hard == "unlimited" || cap,
        "precondition not met: this process's memlock limit is {soft} (hard {hard}) and it has no CAP_SYS_RESOURCE. Run it with an unlimited one (`prlimit --memlock=unlimited:unlimited -- cargo test …`, as CI's test task does)"
    );
}

#[test]
fn memory_flags_go_after_init_or_serve_and_never_on_status() {
    for args in [
        &["--require-memory-lock", "serve"][..],
        &["--no-memory-lock", "serve"],
        &["status", "--require-memory-lock"],
        &["status", "--no-memory-lock"],
    ] {
        let out = proxy().args(args).output().expect("run klav-proxy");
        let (_, stderr) = text(&out);
        assert_eq!(out.status.code(), Some(2), "{args:?}: {stderr}");
        assert!(stderr.contains("unexpected argument"), "{args:?}: {stderr}");
    }
    for sub in ["serve", "init"] {
        let out = proxy().args([sub, "--help"]).output().expect("help");
        let (help, _) = text(&out);
        assert!(help.contains("--require-memory-lock"), "{sub}");
        assert!(help.contains("--no-memory-lock"), "{sub}");
        assert!(help.contains("KLAV_PROXY_MEMORY_LOCK=off"), "{sub}");
    }
}

/// Decision 16: `KLAV_PROXY_REQUIRE_MEMORY_LOCK` takes `1`, `true`, `0` or
/// `false`. L9, which Omar accepted on 2026-11-19 (decision 21):
/// `KLAV_PROXY_MEMORY_LOCK` takes `on` or `off`.
/// Anything else stops the start before a key is read or made; `status`
/// never reads the first, and refuses the second.
#[test]
fn memory_variables_take_only_their_values() {
    let dir = tempfile::tempdir().expect("tempdir");
    let init = ["init", "--email", EMAIL, "--server", "http://127.0.0.1:9"];
    for args in [&["serve"][..], &init] {
        let out = proxy()
            .env(REQUIRE, "yes")
            .arg("--home")
            .arg(dir.path())
            .args(args)
            .output()
            .expect("run");
        let (_, stderr) = text(&out);
        assert_eq!(out.status.code(), Some(1), "{args:?}: {stderr}");
        assert!(stderr.contains(&format!("{REQUIRE} must be 1")), "{stderr}");
    }
    for args in [&["serve"][..], &init, &["status"]] {
        let out = proxy()
            .env(LOCK, "no")
            .arg("--home")
            .arg(dir.path())
            .args(args)
            .output()
            .expect("run");
        let (_, stderr) = text(&out);
        assert_eq!(out.status.code(), Some(1), "{args:?}: {stderr}");
        assert!(stderr.contains(&format!("{LOCK} must be off")), "{stderr}");
    }
    let out = proxy()
        .env(REQUIRE, "yes")
        .arg("--home")
        .arg(dir.path())
        .arg("status")
        .output()
        .expect("run");
    let (_, stderr) = text(&out);
    assert!(!out.status.success());
    assert!(!stderr.contains(REQUIRE), "{stderr}");
    assert_eq!(std::fs::read_dir(dir.path()).expect("dir").count(), 0);
}

/// Decision 12 and L10: the lock turned off and required at once is a
/// start-up error, however each was asked; `status` honours the switch and
/// never the requirement.
/// A case: the arguments, the variables, and the two names the error gives.
type Run<'a> = (&'a [&'a str], &'a [(&'a str, &'a str)], [&'a str; 2]);

#[test]
fn the_lock_turned_off_and_required_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out = proxy()
        .args(["serve", "--no-memory-lock", "--require-memory-lock"])
        .output()
        .expect("run");
    let (_, stderr) = text(&out);
    assert_eq!(out.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("cannot be used with"), "{stderr}");
    let runs: [Run<'_>; 3] = [
        (
            &["serve"],
            &[(LOCK, "off"), (REQUIRE, "1")],
            [LOCK, REQUIRE],
        ),
        (
            &["serve", "--no-memory-lock"],
            &[(REQUIRE, "true")],
            ["--no-memory-lock", REQUIRE],
        ),
        (
            &[
                "init",
                "--require-memory-lock",
                "--email",
                EMAIL,
                "--server",
                "http://127.0.0.1:9",
            ],
            &[(LOCK, "off")],
            [LOCK, "--require-memory-lock"],
        ),
    ];
    for (args, env, names) in runs {
        let mut cmd = proxy();
        for (k, v) in env {
            cmd.env(k, v);
        }
        let out = cmd
            .arg("--home")
            .arg(dir.path())
            .args(args)
            .output()
            .expect("run");
        let (_, stderr) = text(&out);
        assert_eq!(out.status.code(), Some(1), "{args:?}: {stderr}");
        assert!(stderr.contains("turned off"), "{stderr}");
        for name in names {
            assert!(stderr.contains(name), "{name}: {stderr}");
        }
        assert!(!stderr.contains(NO_REGISTRATION), "{stderr}");
    }
    let out = proxy()
        .env(LOCK, "off")
        .env(REQUIRE, "1")
        .arg("--home")
        .arg(dir.path())
        .arg("status")
        .output()
        .expect("run");
    let (_, stderr) = text(&out);
    // Never the start-up error; its own line may say the lock is turned
    // off (decision 26).
    assert!(!stderr.contains("required"), "{stderr}");
    assert!(!stderr.contains("at once"), "{stderr}");
    assert_eq!(std::fs::read_dir(dir.path()).expect("dir").count(), 0);
}

/// Decision 12 and L14: turned off, `serve` logs it, warns of nothing, and
/// goes on (here to the empty home's error).
#[test]
fn the_lock_turned_off_starts_unlocked_without_a_warning() {
    let dir = tempfile::tempdir().expect("tempdir");
    for (flag, env) in [(Some("--no-memory-lock"), None), (None, Some("off"))] {
        let mut cmd = proxy();
        cmd.env("KLAV_LOG_FORMAT", "json")
            .arg("--home")
            .arg(dir.path())
            .arg("serve");
        if let Some(flag) = flag {
            cmd.arg(flag);
        }
        if let Some(value) = env {
            cmd.env(LOCK, value);
        }
        let out = cmd.output().expect("run");
        let (_, stderr) = text(&out);
        assert_eq!(out.status.code(), Some(1), "{stderr}");
        let line = stderr
            .lines()
            .find(|l| l.contains("\"klav-proxy memory\""))
            .unwrap_or_else(|| panic!("no memory line: {stderr}"));
        assert!(line.contains("\"locked\":false"), "{line}");
        assert!(line.contains("\"lock_turned_off\":true"), "{line}");
        assert!(!stderr.contains("memory unlocked"), "{stderr}");
        assert!(stderr.contains(NO_REGISTRATION), "{stderr}");
    }
}

/// ADR 0044 §3.2: with the lock required, a process whose memory could not
/// be locked stops before anything reads or makes a key; one that locked
/// goes on. Each branch asserts what it got.
#[test]
fn a_required_lock_stops_the_start_only_when_it_did_not_take() {
    let dir = tempfile::tempdir().expect("tempdir");
    let init: &[&str] = &[
        "init",
        "--require-memory-lock",
        "--email",
        EMAIL,
        "--server",
        "http://127.0.0.1:9",
    ];
    let runs: [(&[&str], Option<&str>); 3] = [
        (&["serve", "--require-memory-lock"], None),
        (&["serve"], Some("1")),
        (init, None),
    ];
    let refused = |out: &Output, args: &[&str], why: &str| {
        let (_, stderr) = text(out);
        assert_eq!(out.status.code(), Some(1), "{args:?}: {stderr}");
        assert!(
            stderr.contains("the lock is required"),
            "{args:?}: {stderr}"
        );
        assert!(stderr.contains(why), "{args:?}: {stderr}");
        assert!(!stderr.contains(NO_REGISTRATION), "{stderr}");
    };
    if cfg!(target_os = "macos") {
        for (args, env) in runs {
            let mut cmd = proxy();
            if let Some(v) = env {
                cmd.env(REQUIRE, v);
            }
            let out = cmd
                .arg("--home")
                .arg(dir.path())
                .args(args)
                .output()
                .expect("run");
            refused(&out, args, "macOS has no mlockall");
        }
    }
    // A finite limit: never locked, so the start stops; with
    // CAP_SYS_RESOURCE the proxy raises it and locks, so it goes on.
    if cfg!(target_os = "linux") {
        for (args, env) in runs {
            let mut cmd = under_memlock("65536:65536").expect("prlimit");
            if let Some(v) = env {
                cmd.env(REQUIRE, v);
            }
            let out = cmd
                .arg("--home")
                .arg(dir.path())
                .args(args)
                .output()
                .expect("run");
            if raises_any_limit() {
                let (_, stderr) = text(&out);
                assert!(!stderr.contains("the lock is required"), "{stderr}");
            } else {
                refused(
                    &out,
                    args,
                    "the memlock limit is 64 KiB (hard limit 64 KiB)",
                );
            }
        }
    }
    // `status` with the variable set never stops for the lock.
    let out = proxy()
        .env(REQUIRE, "1")
        .arg("--home")
        .arg(dir.path())
        .arg("status")
        .output()
        .expect("run");
    assert!(!text(&out).1.contains("the lock is required"));
    assert_eq!(std::fs::read_dir(dir.path()).expect("dir").count(), 0);
}

/// ADR 0044 §3.2, the other branch: with an unlimited limit the lock
/// takes, so a required lock lets `serve` go on to the empty home.
#[test]
#[ignore = "needs a memlock limit a child may make unlimited; CI's test task runs it with one"]
fn a_required_lock_lets_a_locked_start_go_on() {
    require_an_unlimited_child();
    let dir = tempfile::tempdir().expect("tempdir");
    let out = under_memlock("unlimited:unlimited")
        .expect("Linux")
        .env("KLAV_LOG_FORMAT", "json")
        .arg("--home")
        .arg(dir.path())
        .args(["serve", "--require-memory-lock"])
        .output()
        .expect("run");
    let (_, stderr) = text(&out);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert!(!stderr.contains("the lock is required"), "{stderr}");
    assert!(stderr.contains("\"locked\":true"), "{stderr}");
    assert!(stderr.contains(NO_REGISTRATION), "{stderr}");
}

async fn account(server: &common::ServerProcess, dir: &Path) -> klav_client::Unlocked {
    use klav_core::model::item::{Item, ItemKind};
    let (mut ana, _) = klav_client::signup(
        &klav_client::Home::at(dir.join("laptop")),
        klav_client::SignupRequest {
            server: server.url.clone(),
            email: EMAIL.into(),
            password: klav_core::crypto::kdf::MasterPassword::new("correct horse battery staple"),
            device_name: "laptop".into(),
            device_kind: klav_proto::auth::DeviceKind::Cli,
            invite: None,
        },
    )
    .await
    .expect("sign-up");
    let vault = ana.find_vault("Personal").expect("vault");
    let project = ana.find_project(vault, "General").expect("project");
    let mut item = Item::from_template(ItemKind::Login, "Northflank").expect("item");
    item.field_mut("password")
        .expect("password")
        .set_value("token-0123456789")
        .expect("set");
    ana.add_item(vault, project, &item).await.expect("add item");
    ana
}

/// `init --json` keeps stdout for its report, also when it warns that the
/// memory is unlocked: a real `init` against a test server, forced to a
/// finite limit on Linux so the warning is there to keep out of stdout.
#[tokio::test(flavor = "multi_thread")]
async fn the_memory_warning_never_reaches_stdout() {
    let server = common::ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let _ana = account(&server, dir.path()).await;
    let home = dir.path().join("proxy");
    let finite = under_memlock("65536:65536");
    // Linux warns of a finite limit, unless CAP_SYS_RESOURCE raises it.
    let warned = finite.is_some() && !raises_any_limit();
    let mut cmd = finite.unwrap_or_else(proxy);
    let out = cmd
        .arg("--home")
        .arg(&home)
        .args(["init", "--json", "--email", EMAIL, "--server", &server.url])
        .output()
        .expect("run");
    let (stdout, stderr) = text(&out);
    assert!(out.status.success(), "{stdout}\n{stderr}");
    let report: serde_json::Value =
        serde_json::from_str(&stdout).expect("stdout is only the report");
    assert!(report["agent_id"].is_string(), "{stdout}");
    assert!(!stdout.contains("memory"), "{stdout}");
    if warned {
        assert!(
            stderr.contains("klav-proxy runs with its memory unlocked"),
            "{stderr}"
        );
        assert!(stderr.contains("64 KiB"), "{stderr}");
    } else {
        assert!(!stderr.contains("memory unlocked"), "{stderr}");
    }
}

fn status_kib(pid: u32, field: &str) -> u64 {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).expect("status");
    klav_proxy::memory::status_number(&status, field).unwrap_or_else(|| panic!("{field}"))
}

/// The proxy, stopped and reaped on every way out, a panic included:
/// `prlimit` runs it in its own process, so the child's pid is the
/// proxy's, and `SIGTERM` then `SIGKILL` reach it by that pid.
struct Running {
    child: Child,
}

impl Running {
    fn pid(&self) -> u32 {
        self.child.id()
    }

    fn term(&self) {
        let _ = Command::new("kill")
            .args(["-TERM", &self.pid().to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        if matches!(self.child.try_wait(), Ok(Some(_))) {
            return;
        }
        self.term();
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if matches!(self.child.try_wait(), Ok(Some(_))) {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The resident memory a locked proxy may have after one request, with 64
/// runtime workers: under 64 MiB. Locking every page as it is mapped
/// would make each worker's 2 MiB stack resident, 128 MiB for the stacks
/// alone; locked on fault, only the pages the proxy touched are. What it
/// reads varies by host and build; the readings are in one place, ADR 0044
/// §3.2, "a locked proxy under requests, measured".
const MAX_LOCKED_RSS_KIB: u64 = 64 << 10;

/// Decision 11 and finding 1 of the review of #466: the real binary,
/// started with its memory locked, answers a request through its listener,
/// and its resident memory afterwards stays under [`MAX_LOCKED_RSS_KIB`];
/// `status` shows the lock while it runs, and its record is gone once it
/// stops. The request is one the proxy refuses at the access step (a path
/// outside the grant), so nothing reaches a real provider: the binary can
/// only reach real ones (its roots and resolver are the system's). A
/// request that goes through a profile to a local fake upstream, under
/// lock, is `locked_e2e_tests` in the library's tests.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a memlock limit a child may make unlimited; CI's test task runs it with one"]
async fn a_locked_proxy_serves_a_request_and_keeps_untouched_pages_out_of_memory() {
    require_an_unlimited_child();
    use klav_client::proxy_admin::{PairingCheck, ProxyCredentialSpec};
    let server = common::ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let mut ana = account(&server, dir.path()).await;
    let home = dir.path().join("proxy");
    let key = dir.path().join("klav-proxy.key");
    klav_sdk::Agent::register(
        &klav_client::Home::at(&home),
        klav_sdk::Registration {
            name: "klav-proxy".into(),
            server: server.url.clone(),
            email: EMAIL.into(),
            note: None,
            key_store: klav_sdk::KeyStore::File { path: key },
        },
    )
    .await
    .expect("register");
    let prepared = ana
        .prepare_proxy_use(Some("klav-proxy"))
        .await
        .expect("use");
    ana.commit_proxy_use(prepared).await.expect("use");
    let spec = ProxyCredentialSpec {
        profile: "northflank".into(),
        upstream: "https://api.northflank.com".into(),
        header: "authorization".into(),
        prefix: "Bearer ".into(),
        methods: vec!["GET".into()],
        path_prefixes: vec!["/v1".into()],
        ..ProxyCredentialSpec::default()
    };
    let prepared = ana
        .prepare_proxy_grant("Northflank", &spec, PairingCheck::InPrompt)
        .await
        .expect("grant");
    prepared.require_updated_devices(true).expect("ack");
    assert!(
        ana.commit_proxy_change(prepared)
            .await
            .expect("grant")
            .complete()
    );

    let home_arg = home.to_str().expect("utf-8").to_owned();
    let mut child = under_memlock("unlimited:unlimited")
        .expect("Linux")
        .env("KLAV_LOG_FORMAT", "json")
        .env("TOKIO_WORKER_THREADS", "64")
        .args(["--home", &home_arg, "serve", "--port", "0"])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn klav-proxy");
    let stderr = child.stderr.take().expect("stderr");
    let running = Running { child };
    let (tx, rx) = std::sync::mpsc::channel::<String>();
    std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    let mut log = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(60);
    let port = loop {
        let line = rx
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .unwrap_or_else(|_| panic!("klav-proxy never listened:\n{}", log.join("\n")));
        log.push(line.clone());
        if let Ok(event) = serde_json::from_str::<serde_json::Value>(&line)
            && event["fields"]["message"] == "klav-proxy listening"
        {
            let listen: std::net::SocketAddr = event["fields"]["listen"]
                .as_str()
                .expect("listen")
                .parse()
                .expect("address");
            break listen.port();
        }
    };
    let memory_line = log
        .iter()
        .find(|l| l.contains("\"klav-proxy memory\""))
        .unwrap_or_else(|| panic!("no memory line:\n{}", log.join("\n")))
        .clone();

    let res = reqwest::Client::new()
        .get(format!("http://127.0.0.1:{port}/northflank/v2/nothing"))
        .send()
        .await
        .expect("the proxy answers");
    assert_eq!(res.status(), reqwest::StatusCode::FORBIDDEN);
    assert!(
        res.headers().contains_key("klav-error"),
        "{:?}",
        res.headers()
    );

    let shown = proxy()
        .args(["--home", &home_arg, "status", "--json"])
        .output()
        .expect("status");
    let (stdout, stderr) = text(&shown);
    assert!(shown.status.success(), "{stderr}");
    let status: serde_json::Value = serde_json::from_str(&stdout).expect("json");
    let memory = &status["memory"];
    assert_eq!(memory["core_dumps"], "off", "{status}");
    assert!(memory_line.contains("\"locked\":true"), "{memory_line}");
    assert_eq!(memory["locked"], true, "{status}");
    assert!(
        memory["vm_lck_kib"].as_u64().is_some_and(|k| k > 0),
        "{status}"
    );
    let pid = running.pid();
    let (rss, locked) = (status_kib(pid, "VmRSS:"), status_kib(pid, "VmLck:"));
    println!("locked klav-proxy after one request: VmRSS {rss} kB, VmLck {locked} kB");
    assert!(locked > 0);
    assert!(
        rss < MAX_LOCKED_RSS_KIB,
        "a locked proxy holds {rss} kB resident after one request (bound {MAX_LOCKED_RSS_KIB} kB)"
    );
    let record = home.join("agents").join("klav-proxy.memory");
    assert!(record.exists());
    let mut running = running;
    running.term();
    let deadline = Instant::now() + Duration::from_secs(30);
    while running.child.try_wait().expect("wait").is_none() {
        assert!(
            Instant::now() < deadline,
            "klav-proxy did not stop on SIGTERM"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(!record.exists(), "a serve that stopped left its record");
    drop(running);
}

/// The start of the stderr line `status` prints about its own process
/// (ADR 0044, Omar's decision 26 of 2026-11-19).
const OWN_LINE: &str =
    "klav-proxy: memory of this status process, not of any serve: core dumps off, not dumpable, ";

/// A proxy registered against `server` in `<dir>/proxy`, never paired:
/// enough for `status` to print its report.
async fn registered(server: &common::ServerProcess, dir: &Path) -> String {
    let _ana = account(server, dir).await;
    let home = dir.join("proxy");
    klav_sdk::Agent::register(
        &klav_client::Home::at(&home),
        klav_sdk::Registration {
            name: "klav-proxy".into(),
            server: server.url.clone(),
            email: EMAIL.into(),
            note: None,
            key_store: klav_sdk::KeyStore::File {
                path: dir.join("klav-proxy.key"),
            },
        },
    )
    .await
    .expect("register");
    home.to_str().expect("utf-8").to_owned()
}

/// What `status` and `status --json` print, each from a command `make`
/// builds: (stdout, stderr) of the text run, then of the JSON run, whose
/// stdout must be only the report.
fn status_both(
    make: impl Fn() -> Command,
    home: &str,
) -> ((String, String), (serde_json::Value, String)) {
    let run = |json: bool| {
        let mut cmd = make();
        cmd.args(["--home", home, "status"]);
        if json {
            cmd.arg("--json");
        }
        let out = cmd.output().expect("run status");
        let (stdout, stderr) = text(&out);
        assert!(out.status.success(), "{stdout}\n{stderr}");
        (stdout, stderr)
    };
    let text_run = run(false);
    let (stdout, stderr) = run(true);
    let report = serde_json::from_str(&stdout).expect("stdout is only the report");
    (text_run, (report, stderr))
}

/// The one line about `status`'s own process on `stderr`, if any.
fn own_line(stderr: &str) -> Option<&str> {
    let mut lines = stderr.lines().filter(|l| l.contains("memory of this"));
    let line = lines.next();
    assert!(lines.next().is_none(), "more than one line: {stderr}");
    line
}

/// Decision 26: `status` says on stderr what its own process got, labeled
/// as that process's, and stdout stays the report alone, in text and in
/// `--json`, the same whatever its own lock got. Here the branches CI's
/// main run has: a finite limit (raised and locked only with
/// `CAP_SYS_RESOURCE`) and the switch; on macOS, no line at all (L25).
/// The locked branch is the ignored test below.
#[tokio::test(flavor = "multi_thread")]
async fn status_says_what_its_own_memory_got_on_stderr_only() {
    let server = common::ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let home = registered(&server, dir.path()).await;
    let off = status_both(
        || {
            let mut cmd = proxy();
            cmd.env(LOCK, "off");
            cmd
        },
        &home,
    );
    let finite = status_both(|| under_memlock("65536:65536").unwrap_or_else(proxy), &home);
    for ((stdout, stderr), (_, json_stderr)) in [&off, &finite] {
        assert!(!stdout.contains("memory of this"), "{stdout}");
        assert!(
            stdout.contains("Memory: no record from a klav-proxy serve on this home."),
            "{stdout}"
        );
        assert_eq!(own_line(stderr), own_line(json_stderr));
    }
    // Stdout does not depend on what this process's own lock got.
    assert_eq!(off.0.0, finite.0.0);
    assert_eq!(off.1.0, finite.1.0);
    assert!(off.1.0.get("memory").is_none(), "{}", off.1.0);
    if cfg!(target_os = "linux") {
        assert_eq!(
            own_line(&off.0.1),
            Some(
                format!(
                    "{OWN_LINE}not locked: the lock is turned off (KLAV_PROXY_MEMORY_LOCK=off)."
                )
                .as_str()
            )
        );
        let line = own_line(&finite.0.1).expect("a line");
        if raises_any_limit() {
            assert!(
                line.starts_with(&format!("{OWN_LINE}locked on fault (VmLck ")),
                "{line}"
            );
        } else {
            assert!(
                line.starts_with(&format!(
                    "{OWN_LINE}not locked: the memlock limit is 64 KiB (hard limit 64 KiB) and this process may not raise it"
                )),
                "{line}"
            );
        }
    } else {
        for (stderr, json_stderr) in [(&off.0.1, &off.1.1), (&finite.0.1, &finite.1.1)] {
            assert_eq!(own_line(stderr), None, "{stderr}");
            assert_eq!(own_line(json_stderr), None, "{json_stderr}");
        }
    }
}

/// Decision 26, the locked branch: with an unlimited limit, `status` says
/// on stderr that its own process locked on fault, with `VmLck`, and stdout
/// is what it is with the lock turned off.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a memlock limit a child may make unlimited; CI's test task runs it with one"]
async fn status_says_its_own_memory_is_locked_on_stderr_only() {
    require_an_unlimited_child();
    let server = common::ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let home = registered(&server, dir.path()).await;
    let locked = status_both(
        || under_memlock("unlimited:unlimited").expect("Linux"),
        &home,
    );
    let off = status_both(
        || {
            let mut cmd = proxy();
            cmd.env(LOCK, "off");
            cmd
        },
        &home,
    );
    for stderr in [&locked.0.1, &locked.1.1] {
        let line = own_line(stderr).expect("a line");
        let kib: u64 = line
            .strip_prefix(&format!("{OWN_LINE}locked on fault (VmLck "))
            .and_then(|rest| rest.strip_suffix(" kB at start)."))
            .unwrap_or_else(|| panic!("{line}"))
            .parse()
            .expect("kB");
        assert!(kib > 0, "{line}");
    }
    assert!(!locked.0.0.contains("memory of this"), "{}", locked.0.0);
    assert_eq!(locked.0.0, off.0.0);
    assert_eq!(locked.1.0, off.1.0);
}
