//! Project repository links (ADR 0032 §2) against the real server:
//! `ProjectMeta.repos` is encrypted with the project key (`0x13`), normalized
//! across SSH/HTTPS/bare URLs, synced across devices, and omitted when empty.

mod common;

use common::ServerProcess;
use klav_client::{Home, LoginRequest, SignupRequest, login, signup};
use klav_core::crypto::kdf::MasterPassword;
use klav_core::crypto::secret_key::SecretKey;
use klav_proto::auth::DeviceKind;
use secrecy::ExposeSecret;

const PASSWORD: &str = "correct horse battery staple";

#[tokio::test(flavor = "multi_thread")]
async fn project_repos_normalize_and_sync_across_devices() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().unwrap();
    let (mut a, kit) = signup(
        &Home::at(dir.path().join("a")),
        SignupRequest {
            server: server.url.clone(),
            email: "repos@example.com".into(),
            password: MasterPassword::new(PASSWORD),
            device_name: "mac".into(),
            device_kind: DeviceKind::Cli,
            invite: None,
        },
    )
    .await
    .expect("sign-up");
    let secret_key = kit.secret_key().to_text().expose_secret().to_owned();
    let vault = a.find_vault("Personal").unwrap();
    let project = a.create_project(vault, "acme-api").await.unwrap();

    // Initially empty.
    let initial = a
        .projects(Some(vault))
        .into_iter()
        .find(|p| p.id == project)
        .unwrap();
    assert!(initial.repos.is_empty());

    // Linking normalizes and deduplicates SSH + HTTPS forms.
    let updated = a
        .set_project_repos(
            vault,
            project,
            vec![
                "git@github.com:Omar/acme-api.git".into(),
                "https://github.com/omar/acme-api/".into(),
                "https://gitlab.com/team/sub/worker.git".into(),
            ],
        )
        .await
        .unwrap();
    assert_eq!(
        updated.repos,
        vec![
            "github.com/omar/acme-api".to_owned(),
            "gitlab.com/team/sub/worker".to_owned()
        ]
    );

    // Another device syncs and sees the exact same linked repos.
    let mut b = login(
        &Home::at(dir.path().join("b")),
        LoginRequest {
            server: server.url.clone(),
            email: "repos@example.com".into(),
            password: MasterPassword::new(PASSWORD),
            secret_key: SecretKey::parse(&secret_key).unwrap(),
            device_name: "laptop".into(),
            device_kind: DeviceKind::Cli,
        },
    )
    .await
    .expect("login b");
    b.sync().await.unwrap();
    let synced = b
        .projects(Some(vault))
        .into_iter()
        .find(|p| p.id == project)
        .unwrap();
    assert_eq!(synced.repos, updated.repos);

    // Unlinking clears back to empty.
    let cleared = b.set_project_repos(vault, project, vec![]).await.unwrap();
    assert!(cleared.repos.is_empty());
    a.sync().await.unwrap();
    let after = a
        .projects(Some(vault))
        .into_iter()
        .find(|p| p.id == project)
        .unwrap();
    assert!(after.repos.is_empty());
}
