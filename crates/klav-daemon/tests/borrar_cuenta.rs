//! What `klavd` knows of the account's deletion (ADR 0037 §3, amendment
//! A2 and A3): it survives a restart in `account-deletion.json` (0600, no
//! secret), so a locked `klavd` still says it; a file of another account
//! is ignored; and cancelling asks for presence, as resuming agents does.

mod common;

use std::os::unix::fs::PermissionsExt;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use common::ServerProcess;
use klav_client::ops::SecretText;
use klav_client::{Home, SignupRequest, deletion, signup};
use klav_core::crypto::kdf::MasterPassword;
use klav_core::ids::AccountId;
use klav_daemon::client::{ACCOUNT_DELETION_FILE, DaemonClient};
use klav_daemon::protocol::{DaemonStatus, ErrorCode, Request};
use serde_json::Value;

const PASSWORD: &str = "correct horse battery staple";

/// The `klavd` binary for one home, Touch ID off; killed if the test
/// fails before it stops it.
struct Klavd {
    child: Child,
    client: DaemonClient,
}

fn spawn(home: &Home) -> Child {
    Command::new(env!("CARGO_BIN_EXE_klavd"))
        .env("KLAV_HOME", home.dir())
        .args(["--idle-lock", "5m", "--no-touch-id"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn klavd")
}

impl Klavd {
    // The child moves into `Klavd`, whose `Drop` kills and waits for it;
    // the lint does not follow it into the struct.
    #[allow(clippy::zombie_processes)]
    async fn start(home: &Home) -> Self {
        let mut child = spawn(home);
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(client) = DaemonClient::connect(home).await {
                return Self { child, client };
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("klavd did not start");
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    async fn status(&mut self) -> DaemonStatus {
        self.client
            .call::<DaemonStatus>(Request::Status)
            .await
            .expect("status")
            .0
    }

    async fn unlock(&mut self) {
        self.client
            .call::<DaemonStatus>(Request::Unlock {
                password: Some(SecretText::new(PASSWORD)),
                passkey_flow: false,
            })
            .await
            .expect("unlock");
        self.client
            .call::<Value>(Request::Sync)
            .await
            .expect("sync");
    }

    async fn cancel(&mut self, password: Option<&str>) -> Result<Value, ErrorCode> {
        self.client
            .call::<Value>(Request::CancelAccountDeletion {
                password: password.map(SecretText::new),
            })
            .await
            .map(|(v, _)| v)
            .map_err(|e| e.code)
    }

    /// Asks it to stop and waits until it exits.
    async fn stop(mut self) {
        let _ = self.client.call::<Value>(Request::Shutdown).await;
        let deadline = Instant::now() + Duration::from_secs(10);
        while self.child.try_wait().expect("wait klavd").is_none() {
            assert!(Instant::now() < deadline, "klavd did not stop");
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }
}

impl Drop for Klavd {
    fn drop(&mut self) {
        if matches!(self.child.try_wait(), Ok(None)) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_deletion_survives_a_restart_and_cancelling_asks_for_presence() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let home = Home::at(dir.path().join("home"));
    drop(
        signup(
            &home,
            SignupRequest {
                server: server.url.clone(),
                email: "ana@example.com".into(),
                password: MasterPassword::new(PASSWORD),
                device_name: "laptop".into(),
                device_kind: klav_proto::auth::DeviceKind::Cli,
            },
        )
        .await
        .expect("sign-up"),
    );
    // As `klav account delete` does: asked in its own process.
    let (asked_by, asked) =
        deletion::request_account_deletion(&home, &MasterPassword::new(PASSWORD))
            .await
            .expect("ask");
    let account = asked_by.account().account_id;
    drop(asked_by);

    // Unlocked, klavd learns it and writes it down.
    let mut klavd = Klavd::start(&home).await;
    klavd.unlock().await;
    assert_eq!(klavd.status().await.account_deletion.as_ref(), Some(&asked));
    let file = home.file(ACCOUNT_DELETION_FILE);
    let mode = std::fs::metadata(&file)
        .expect("saved")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
    let saved: Value = serde_json::from_slice(&std::fs::read(&file).expect("read")).expect("json");
    let mut keys: Vec<&str> = saved
        .as_object()
        .expect("object")
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(keys, ["account", "deleted", "deletion", "v"], "{saved}");
    assert_eq!(saved["v"], 1);
    assert_eq!(saved["deletion"]["delete_at"], asked.delete_at);
    klavd.stop().await;

    // A new klavd says it while locked, before anyone unlocks it.
    let mut klavd = Klavd::start(&home).await;
    let status = klavd.status().await;
    assert!(!status.unlocked);
    assert_eq!(status.account_deletion.as_ref(), Some(&asked));
    assert!(!status.account_deleted);

    // Cancelling brings the agents back: presence first (A2). Touch ID is
    // off here, so without the master password it is refused, and a wrong
    // one too; the deletion stays.
    klavd.unlock().await;
    assert_eq!(
        klavd.cancel(None).await,
        Err(ErrorCode::BiometryUnavailable)
    );
    assert!(klavd.cancel(Some("wrong")).await.is_err());
    assert_eq!(klavd.status().await.account_deletion.as_ref(), Some(&asked));
    let canceled = klavd.cancel(Some(PASSWORD)).await.expect("cancel");
    assert_eq!(canceled["canceled"], true);
    assert!(klavd.status().await.account_deletion.is_none());
    assert!(!file.exists(), "nothing to remember once canceled");
    klavd.stop().await;

    // A file written for another account says nothing about this one.
    let mut other = saved.clone();
    other["account"] = Value::String(AccountId::generate().to_string());
    assert_ne!(other["account"], Value::String(account.to_string()));
    std::fs::write(&file, serde_json::to_vec(&other).expect("json")).expect("write");
    let mut klavd = Klavd::start(&home).await;
    assert!(klavd.status().await.account_deletion.is_none());
    klavd.stop().await;
}
