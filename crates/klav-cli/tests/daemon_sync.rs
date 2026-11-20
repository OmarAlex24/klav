//! `klavd`'s reads answer from the local copy and sync in the background
//! (ADR 0026): a remote change shows up after the sync and moves
//! `revision`; offline is a warning; a rollback (T7) found by a background
//! sync never reaches the cache and becomes a warning on every read that
//! follows, which keep answering from the verified copy (ADR 0030, layer
//! 10); `sync` still fails with it, and `reset_cache` is the way out.

mod common;

use std::time::{Duration, Instant};

use common::{Device, PASSWORD, ServerProcess};
use klav_client::ops::SecretText;
use klav_client::{Home, ItemFilter, ItemSummary};
use klav_daemon::client::DaemonClient;
use klav_daemon::protocol::{DaemonStatus, ErrorBody, ErrorCode, Request};
use klav_daemon::{Config, serve};

/// The daemon's sync interval here: short, so the test need not wait 30 s.
const SYNC_AFTER: Duration = Duration::from_millis(500);

async fn list(client: &mut DaemonClient) -> Result<(Vec<String>, Vec<String>), ErrorBody> {
    let (items, warnings): (Vec<ItemSummary>, _) = client
        .call(Request::List {
            filter: ItemFilter::default(),
        })
        .await?;
    Ok((items.into_iter().map(|i| i.title).collect(), warnings))
}

async fn status(client: &mut DaemonClient) -> DaemonStatus {
    client.call(Request::Status).await.expect("status").0
}

/// Waits for the background sync to end (or not to have started).
async fn settled(client: &mut DaemonClient) -> DaemonStatus {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let s = status(client).await;
        if !s.syncing {
            return s;
        }
        assert!(Instant::now() < deadline, "the background sync did not end");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Lets the local copy age past `SYNC_AFTER`.
async fn age() {
    tokio::time::sleep(SYNC_AFTER + Duration::from_millis(100)).await;
}

/// Adds an item from the same account without klavd (another process),
/// so klavd only learns of it by syncing.
fn add_elsewhere(device: &Device, title: &str) {
    device
        .unlocked(
            &[
                "--no-daemon",
                "item",
                "add",
                "api-key",
                "--title",
                title,
                "--secret-stdin",
                "api_key",
            ],
            "MARKER-elsewhere\n",
        )
        .ok();
}

#[tokio::test(flavor = "multi_thread")]
async fn reads_answer_at_once_and_a_rollback_found_later_warns_on_every_read() {
    let mut server = ServerProcess::start(900);
    let root = tempfile::tempdir().expect("tempdir");
    let device = Device::new(root.path(), "home");
    device.signup(&server, "swr@example.com");
    let home = Home::at(device.home.clone());
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let daemon = tokio::spawn(serve(
        Config {
            home: home.clone(),
            idle_lock: Duration::from_secs(600),
            touch_id: false,
            sync_after: SYNC_AFTER,
            build: None,
            presence_gate: false,
        },
        async {
            let _ = stopped.await;
        },
    ));
    let mut client = None;
    for _ in 0..200 {
        client = DaemonClient::connect(&home).await;
        if client.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let mut client = client.expect("klavd listens");
    let (unlocked, _): (DaemonStatus, _) = client
        .call(Request::Unlock {
            password: Some(SecretText::new(PASSWORD)),
            passkey_flow: false,
        })
        .await
        .expect("unlock");
    assert!(unlocked.unlocked && !unlocked.syncing);
    let first = unlocked.revision;

    // A change made elsewhere: the next read answers from the local copy
    // without it (it never waits on the server) and syncs behind it.
    add_elsewhere(&device, "Remote key");
    age().await;
    let (titles, _) = list(&mut client).await.expect("list");
    assert!(!titles.contains(&"Remote key".to_owned()), "{titles:?}");
    let after = settled(&mut client).await;
    assert!(after.revision > first, "the sync brought a change");
    let (titles, warnings) = list(&mut client).await.expect("list");
    assert!(titles.contains(&"Remote key".to_owned()), "{titles:?}");
    assert!(warnings.is_empty(), "{warnings:?}");
    // Nothing new: the revision stays put.
    age().await;
    list(&mut client).await.expect("list");
    assert_eq!(settled(&mut client).await.revision, after.revision);

    // Offline: the local copy, with a warning on the reads after the
    // failed sync; back online, the warning goes.
    server.stop();
    age().await;
    list(&mut client).await.expect("list offline");
    settled(&mut client).await;
    let (titles, warnings) = list(&mut client).await.expect("list offline");
    assert!(titles.contains(&"Remote key".to_owned()));
    assert!(
        warnings.iter().any(|w| w.contains("offline")),
        "{warnings:?}"
    );
    server.restart();
    settled(&mut client).await;
    list(&mut client).await.expect("list");
    settled(&mut client).await;
    let (_, warnings) = list(&mut client).await.expect("list");
    assert!(warnings.is_empty(), "{warnings:?}");

    // Rollback (T7): klavd saw a newer state, then the server goes back.
    server.snapshot("before");
    add_elsewhere(&device, "Second key");
    let _: (serde_json::Value, _) = client.call(Request::Sync).await.expect("sync");
    server.restore("before");
    age().await;
    // The read that finds the copy stale still answers from it: the copy
    // is what this device already verified.
    let (titles, _) = list(&mut client).await.expect("list");
    assert!(titles.contains(&"Second key".to_owned()));
    settled(&mut client).await;
    // Every read after the background sync refused the server's state
    // warns, and still answers from the verified copy: nothing of the
    // rolled-back state reached it.
    for _ in 0..3 {
        let (titles, warnings) = list(&mut client).await.expect("list after a rollback");
        assert!(titles.contains(&"Second key".to_owned()), "{titles:?}");
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("rollback") && w.contains("--reset-cache")),
            "{warnings:?}"
        );
        settled(&mut client).await;
    }
    let (_, warnings) = client
        .call::<serde_json::Value>(Request::View {
            query: "Second key".into(),
            reveal: false,
            password: None,
        })
        .await
        .expect("view after a rollback");
    assert!(
        warnings.iter().any(|w| w.contains("rollback")),
        "{warnings:?}"
    );
    // An explicit sync reports it (`klav sync` exits with 3), and status
    // still answers.
    let err = client
        .call::<serde_json::Value>(Request::Sync)
        .await
        .expect_err("rollback");
    assert_eq!(err.code, ErrorCode::Rollback);
    assert!(status(&mut client).await.unlocked);
    // The way out: start over from the server's state; the warning goes.
    let _: (serde_json::Value, _) = client
        .call(Request::ResetCache)
        .await
        .expect("reset the cache");
    let (titles, warnings) = list(&mut client).await.expect("list");
    assert!(!titles.contains(&"Second key".to_owned()), "{titles:?}");
    assert!(
        !warnings.iter().any(|w| w.contains("rollback")),
        "{warnings:?}"
    );

    let _ = stop.send(());
    daemon.await.expect("join").expect("serve");
}
