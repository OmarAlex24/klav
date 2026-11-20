//! A locked proxy all the way through a profile (ADR 0044 §3.2; finding 6
//! of the re-review of #466): a child process hardens itself with the lock
//! on, as `main` does, and serves a burst of requests that each go through
//! the `northflank` profile to a local fake upstream. Under the lock, each
//! request builds the credential header, resolves the upstream's name with
//! the system resolver on tokio's blocking pool, opens a TLS connection
//! (the fake upstream closes every connection) and redacts the echoed
//! value. The parent reads the child's resident memory before and after.
//!
//! What it does not cover, said plainly: the release binary (the test
//! binary is the debug build of the library and its tests), real
//! providers, a host's load over hours, and the name the proxy really
//! resolves (the system resolver answers for `localhost`, stood in for
//! `upstream.test`, which the fixture certificate names).

// The parent prints what it measured; nothing printed holds a value.
#![allow(clippy::print_stdout)]

use std::io::{BufRead, BufReader};
use std::net::IpAddr;
use std::pin::Pin;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::AtomicI64;
use std::time::{Duration, Instant};

use crate::app::StartEnv;
use crate::channel::ChannelLimits;
use crate::channel_e2e_tests::serve_configured;
use crate::e2e_tests::Upstream;
use crate::e2e_tests::common::ServerProcess;
use crate::net::Lookup;
use crate::sandbox_e2e_tests::{Manual, credential_at, real_now, setup_with};

const NAME: &str =
    "locked_e2e_tests::a_locked_proxy_serves_a_burst_through_a_profile_and_stays_small";
/// The child's mode: the proxy's home, then its store, split by `\n`.
const CHILD: &str = "KLAV_PROXY_LOCKED_E2E_CHILD";
/// Requests in the burst, and how many at once.
const BURST: usize = 200;
const AT_ONCE: usize = 16;
/// Runtime workers in the child: their stacks are what locking every page
/// at once made resident (2 MiB each).
const WORKERS: usize = 64;
/// Fixed before the first run: the child's resident memory after the
/// burst stays under 64 MiB (64 populated worker stacks alone would be
/// 128 MiB), and grows by less than 32 MiB during it.
const MAX_RSS_KIB: u64 = 64 << 10;
const MAX_GROWTH_KIB: u64 = 32 << 10;

/// The system resolver, asked for `localhost` whatever name it is given:
/// the same call as the release build's lookup (`tokio::net::lookup_host`,
/// on the blocking pool), for a name the fixture certificate covers.
struct SystemAsLocalhost;

impl Lookup for SystemAsLocalhost {
    fn lookup(
        &self,
        _host: String,
    ) -> Pin<Box<dyn std::future::Future<Output = std::io::Result<Vec<IpAddr>>> + Send>> {
        Box::pin(async move {
            Ok(tokio::net::lookup_host(("localhost", 0))
                .await?
                .map(|a| a.ip())
                .collect())
        })
    }
}

#[test]
#[ignore = "needs a memlock limit a child may make unlimited; CI's test task runs it with one"]
fn a_locked_proxy_serves_a_burst_through_a_profile_and_stays_small() {
    if let Ok(paths) = std::env::var(CHILD) {
        child(&paths);
        return;
    }
    parent();
}

/// Hardens with the lock, as `main` does, then serves until it is killed.
fn child(paths: &str) {
    let (home, store) = paths.split_once('\n').expect("paths");
    let report = crate::memory::harden_process(true).expect("harden");
    println!(
        "\nKLAV-LOCKED {}",
        serde_json::to_string(&report).expect("json")
    );
    assert!(report.locked, "{report:?}");
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(WORKERS)
        .enable_all()
        .build()
        .expect("runtime");
    runtime.block_on(async {
        let agent = crate::app::load(
            &klav_client::Home::at(home),
            "klav-proxy",
            &StartEnv::default(),
        )
        .expect("load");
        let client = crate::net::test_client(
            Arc::new(SystemAsLocalhost),
            vec!["127.0.0.1".parse().expect("ip"), "::1".parse().expect("ip")],
            include_bytes!("../tests/fixtures/ca.der"),
        )
        .expect("client");
        let (_state, port, _channel, _stop) = serve_configured(
            agent,
            Arc::new(Manual(AtomicI64::new(real_now()))),
            store.into(),
            client,
            ChannelLimits::default(),
            None,
            |s| s,
        )
        .await;
        println!("\nKLAV-PORT {port}");
        std::future::pending::<()>().await;
    });
}

/// Killed and reaped on every way out, a panic included.
struct Running(Child);

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn status_kib(pid: u32, field: &str) -> u64 {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).expect("status");
    crate::memory::status_number(&status, field).unwrap_or_else(|| panic!("{field}"))
}

fn parent() {
    #[cfg(target_os = "linux")]
    crate::memory::tests::require_a_child_that_locks();
    if !cfg!(target_os = "linux") {
        panic!("precondition not met: only Linux locks");
    }
    measure();
}

fn measure() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let upstream = runtime.block_on(Upstream::start());
    let mut spec = credential_at(
        "northflank",
        &format!("https://upstream.test:{}", upstream.port),
    );
    spec.rate_per_minute = Some(1000);
    // The account, its Argon2 and the pairing stay in this process.
    let (_ana, proxy, _t3) = runtime.block_on(setup_with(&server, &dir, spec));
    drop(proxy);
    let home = dir.path().join("agent-klav-proxy");
    let store = dir.path().join("proxy.sandbox-store");
    let paths = format!(
        "{}\n{}",
        home.to_str().expect("utf-8"),
        store.to_str().expect("utf-8")
    );
    let mut child = Command::new(std::env::current_exe().expect("test binary"))
        .args([
            "--exact",
            NAME,
            "--nocapture",
            "--test-threads=1",
            "--include-ignored",
        ])
        .env(CHILD, paths)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn the child");
    let stdout = child.stdout.take().expect("stdout");
    let running = Running(child);
    let pid = running.0.id();
    let (tx, rx) = std::sync::mpsc::channel::<String>();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    let deadline = Instant::now() + Duration::from_secs(120);
    let mut seen = Vec::new();
    let port: u16 = loop {
        let line = rx
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .unwrap_or_else(|_| panic!("the child never listened:\n{}", seen.join("\n")));
        if let Some(port) = line.strip_prefix("KLAV-PORT ") {
            break port.parse().expect("port");
        }
        seen.push(line);
    };
    let report = seen
        .iter()
        .find_map(|l| l.split_once("KLAV-LOCKED ").map(|(_, r)| r))
        .unwrap_or_else(|| panic!("no report:\n{}", seen.join("\n")));
    assert!(report.contains("\"locked\":true"), "{report}");
    let before = status_kib(pid, "VmRSS:");
    assert!(status_kib(pid, "VmLck:") > 0);

    let answers: Vec<u16> = runtime.block_on(async {
        let caller = reqwest::Client::builder()
            .no_proxy()
            .build()
            .expect("caller");
        let gate = Arc::new(tokio::sync::Semaphore::new(AT_ONCE));
        let mut calls = tokio::task::JoinSet::new();
        for _ in 0..BURST {
            let caller = caller.clone();
            let gate = Arc::clone(&gate);
            calls.spawn(async move {
                let _turn = gate.acquire_owned().await.expect("gate");
                let res = caller
                    .get(format!("http://127.0.0.1:{port}/northflank/v1/echo"))
                    .send()
                    .await
                    .expect("an answer");
                let status = res.status().as_u16();
                let _ = res.bytes().await;
                status
            });
        }
        calls.join_all().await
    });
    assert!(answers.iter().all(|s| *s == 200), "{answers:?}");
    // Each one reached the upstream with the credential in its header.
    let seen = upstream.requests();
    assert_eq!(seen.len(), BURST);
    assert!(seen.iter().all(|r| {
        r.header("authorization")
            .is_some_and(|v| v.starts_with("Bearer "))
            && r.target == "/v1/echo"
    }));
    let after = status_kib(pid, "VmRSS:");
    let locked = status_kib(pid, "VmLck:");
    println!(
        "locked proxy (test binary, {WORKERS} workers), {BURST} requests through a profile: VmRSS {before} kB before, {after} kB after; VmLck {locked} kB"
    );
    assert!(
        after < MAX_RSS_KIB,
        "a locked proxy holds {after} kB resident after the burst (bound {MAX_RSS_KIB} kB)"
    );
    assert!(
        after.saturating_sub(before) < MAX_GROWTH_KIB,
        "the burst made {} kB resident ({before} → {after} kB; bound {MAX_GROWTH_KIB} kB)",
        after.saturating_sub(before)
    );
    drop(running);
}
