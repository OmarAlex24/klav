//! `klavd` against a server that hangs or lies: `status` and `lock` never
//! wait for a request stuck on the network, locking cancels it, and a
//! rollback is a warning that keeps the local copy (ADR 0030, layer 10).

mod common;

use std::net::TcpListener;
use std::time::Duration;

use common::ServerProcess;
use klav_client::ops::SecretText;
use klav_client::{Home, SignupRequest, SyncReport, VaultSummary, signup};
use klav_core::crypto::kdf::MasterPassword;
use klav_core::model::item::{Item, ItemKind};
use klav_daemon::client::DaemonClient;
use klav_daemon::protocol::{DaemonStatus, ErrorCode, Request};
use klav_daemon::{Config, serve};

const PASSWORD: &str = "correct horse battery staple";

async fn account(server: &ServerProcess, home: &Home) -> klav_client::Unlocked {
    let (unlocked, _kit) = signup(
        home,
        SignupRequest {
            server: server.url.clone(),
            email: "ana@example.com".into(),
            password: MasterPassword::new(PASSWORD),
            device_name: "laptop".into(),
            device_kind: klav_proto::auth::DeviceKind::Cli,
            invite: None,
        },
    )
    .await
    .expect("sign-up");
    unlocked
}

async fn daemon(home: &Home) -> tokio::sync::oneshot::Sender<()> {
    daemon_syncing_after(home, klav_daemon::SYNC_AFTER).await
}

async fn daemon_syncing_after(
    home: &Home,
    sync_after: Duration,
) -> tokio::sync::oneshot::Sender<()> {
    let config = Config {
        home: home.clone(),
        idle_lock: Duration::from_secs(600),
        touch_id: false,
        sync_after,
        build: None,
    };
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let daemon = tokio::spawn(serve(config, async {
        let _ = stopped.await;
    }));
    wait_until_listening(home, &daemon).await;
    stop
}

/// Waits until the in-process `klavd` answers on its socket. A fixed few
/// seconds of polling for the socket file were not enough on a loaded
/// machine: the loop gave up without a word and the next connection failed.
/// The bound is generous, and a `klavd` that stopped first fails at once.
async fn wait_until_listening(home: &Home, daemon: &tokio::task::JoinHandle<Result<(), String>>) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    while DaemonClient::connect(home).await.is_none() {
        assert!(!daemon.is_finished(), "klavd stopped before it listened");
        assert!(
            tokio::time::Instant::now() < deadline,
            "klavd did not listen on {} within 60 s",
            home.socket_path().display()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn client(home: &Home) -> DaemonClient {
    DaemonClient::connect(home).await.expect("klavd")
}

async fn unlock(home: &Home) -> (DaemonStatus, Vec<String>) {
    client(home)
        .await
        .call::<DaemonStatus>(Request::Unlock {
            password: Some(SecretText::new(PASSWORD)),
            passkey_flow: false,
        })
        .await
        .expect("unlock")
}

/// Replaces the server with one that accepts connections and never
/// answers.
fn hang(server: &mut ServerProcess) {
    let port: u16 = server
        .url
        .rsplit(':')
        .next()
        .and_then(|p| p.parse().ok())
        .expect("port");
    server.stop();
    let listener = TcpListener::bind(("127.0.0.1", port)).expect("same port");
    std::thread::spawn(move || {
        let mut held = Vec::new();
        for stream in listener.incoming() {
            held.push(stream);
        }
    });
}

async fn quick<T>(f: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(3), f)
        .await
        .expect("answered without waiting for the stuck request")
}

#[tokio::test(flavor = "multi_thread")]
async fn status_and_lock_do_not_wait_for_a_server_that_hangs() {
    let mut server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let home = Home::at(dir.path().join("home"));
    drop(account(&server, &home).await);
    let _stop = daemon(&home).await;
    let (status, _) = unlock(&home).await;
    assert!(status.unlocked);

    hang(&mut server);

    let stuck_home = home.clone();
    let stuck = tokio::spawn(async move {
        client(&stuck_home)
            .await
            .call::<SyncReport>(Request::Sync)
            .await
    });
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(!stuck.is_finished(), "the sync waits on the server");

    // Neither the status nor the lock queue behind it.
    let (status, _) = quick(client(&home).await.call::<DaemonStatus>(Request::Status))
        .await
        .expect("status");
    assert!(status.unlocked);
    let (status, _) = quick(client(&home).await.call::<DaemonStatus>(Request::Lock))
        .await
        .expect("lock");
    assert!(!status.unlocked);
    // The stuck request is cancelled, not answered with its result.
    let err = quick(stuck).await.expect("join").expect_err("cancelled");
    assert_eq!(err.code, ErrorCode::Locked);
    let (status, _) = quick(client(&home).await.call::<DaemonStatus>(Request::Status))
        .await
        .expect("status");
    assert!(!status.unlocked);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_rollback_is_a_warning_and_reset_cache_starts_over() {
    let mut server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let home = Home::at(dir.path().join("home"));
    let mut a = account(&server, &home).await;
    server.snapshot("before");
    a.sync().await.expect("sync after restart");
    let vault = a.vaults()[0].id;
    let project = a.projects(Some(vault))[0].id;
    let item = Item::from_template(ItemKind::Login, "GitHub").expect("template");
    a.add_item(vault, project, &item).await.expect("add");
    drop(a);
    server.restore("before");

    let _stop = daemon(&home).await;
    // Unlocking works, with the rollback as a warning.
    let (status, warnings) = unlock(&home).await;
    assert!(status.unlocked);
    assert!(
        warnings
            .iter()
            .any(|w| w.contains("SECURITY") && w.contains("reset-cache")),
        "{warnings:?}"
    );
    // With klavd unlocked, a wrong password is still refused.
    let err = client(&home)
        .await
        .call::<DaemonStatus>(Request::Unlock {
            password: Some(SecretText::new("not the password")),
            passkey_flow: false,
        })
        .await
        .expect_err("wrong password");
    assert_eq!(err.code, ErrorCode::WrongCredentials);
    // Reads keep working on the verified local copy, and keep saying why
    // (ADR 0030, layer 10, amending ADR 0026 §3).
    let (vaults, warnings) = client(&home)
        .await
        .call::<Vec<VaultSummary>>(Request::Vaults)
        .await
        .expect("vaults");
    assert_eq!(vaults.len(), 1);
    assert!(
        warnings.iter().any(|w| w.contains("reset-cache")),
        "{warnings:?}"
    );
    // An explicit sync still says what happened.
    let err = client(&home)
        .await
        .call::<SyncReport>(Request::Sync)
        .await
        .expect_err("rollback");
    assert_eq!(err.code, ErrorCode::Rollback);
    // Starting over accepts the server as it is now.
    let (_, warnings) = client(&home)
        .await
        .call::<SyncReport>(Request::ResetCache)
        .await
        .expect("reset");
    assert!(
        !warnings.iter().any(|w| w.contains("SECURITY")),
        "{warnings:?}"
    );
    client(&home)
        .await
        .call::<SyncReport>(Request::Sync)
        .await
        .expect("in sync again");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_background_sync_stuck_on_the_network_holds_up_nothing_and_locking_stops_it() {
    let mut server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let home = Home::at(dir.path().join("home"));
    drop(account(&server, &home).await);
    let _stop = daemon_syncing_after(&home, Duration::from_millis(300)).await;
    let (status, _) = unlock(&home).await;
    assert!(status.unlocked && !status.syncing);

    hang(&mut server);
    tokio::time::sleep(Duration::from_millis(400)).await;
    // The copy is stale: the read answers from it and starts a sync in the
    // background (ADR 0026), which then waits on the server.
    let (vaults, _) = quick(
        client(&home)
            .await
            .call::<Vec<VaultSummary>>(Request::Vaults),
    )
    .await
    .expect("vaults");
    assert_eq!(vaults.len(), 1);
    let (status, _) = quick(client(&home).await.call::<DaemonStatus>(Request::Status))
        .await
        .expect("status");
    assert!(status.syncing, "the background sync is in flight");
    // Reads do not queue behind it: it holds the account only to plan and
    // to apply.
    for _ in 0..3 {
        quick(
            client(&home)
                .await
                .call::<Vec<VaultSummary>>(Request::Vaults),
        )
        .await
        .expect("vaults while syncing");
    }
    // Locking does not wait for it either, and stops it.
    let (status, _) = quick(client(&home).await.call::<DaemonStatus>(Request::Lock))
        .await
        .expect("lock");
    assert!(!status.unlocked && !status.syncing);
    let err = quick(
        client(&home)
            .await
            .call::<Vec<VaultSummary>>(Request::Vaults),
    )
    .await
    .expect_err("locked");
    assert_eq!(err.code, ErrorCode::Locked);
}
