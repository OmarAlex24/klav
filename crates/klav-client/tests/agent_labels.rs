//! Person-owned agent labels (ADR 0047 §1) against the real server:
//! stored E2E-encrypted in the personal vault's system project as
//! `ItemKind::AgentLabels`, synced across devices, never listed in regular
//! item lists, and never trusted if an agent wrote the item (T240).

mod common;

use common::ServerProcess;
use klav_client::{Home, ItemFilter, LoginRequest, SignupRequest, login, signup};
use klav_core::crypto::kdf::MasterPassword;
use klav_core::crypto::secret_key::SecretKey;
use klav_core::ids::AgentId;
use klav_core::model::agent_labels::AgentLabel;
use klav_core::model::history::system_project_id;
use klav_core::model::item::ItemKind;
use klav_proto::auth::DeviceKind;
use secrecy::ExposeSecret;

const PASSWORD: &str = "correct horse battery staple";

#[tokio::test(flavor = "multi_thread")]
async fn agent_labels_sync_and_stay_in_system_project() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().unwrap();
    let (mut a, kit) = signup(
        &Home::at(dir.path().join("a")),
        SignupRequest {
            server: server.url.clone(),
            email: "labels@example.com".into(),
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

    // Empty initially and creates no system item on read.
    assert!(a.agent_labels().unwrap().labels.is_empty());
    assert!(a.system_items(vault, ItemKind::AgentLabels).is_empty());

    let proxy = AgentId::generate();
    let updated = a
        .set_agent_label(
            proxy,
            Some(AgentLabel {
                label: Some("Proxmox proxy".into()),
                host: Some("pve-home".into()),
                role_hint: None,
            }),
        )
        .await
        .unwrap();
    assert_eq!(
        updated.get(&proxy).and_then(|l| l.host.as_deref()),
        Some("pve-home")
    );
    assert_eq!(
        updated.get(&proxy).and_then(|l| l.label.as_deref()),
        Some("Proxmox proxy")
    );

    // Lives only in the system project, hidden from normal lists.
    let items = a.system_items(vault, ItemKind::AgentLabels);
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].project, system_project_id(vault));
    assert!(a.list_items(&ItemFilter::default()).unwrap().is_empty());

    // Another device syncs and reads the same labels, then clears them.
    let mut b = login(
        &Home::at(dir.path().join("b")),
        LoginRequest {
            server: server.url.clone(),
            email: "labels@example.com".into(),
            password: MasterPassword::new(PASSWORD),
            secret_key: SecretKey::parse(&secret_key).unwrap(),
            device_name: "iphone".into(),
            device_kind: DeviceKind::Cli,
        },
    )
    .await
    .expect("login b");
    b.sync().await.unwrap();
    let synced = b.agent_labels().unwrap();
    assert_eq!(
        synced.get(&proxy).and_then(|l| l.host.as_deref()),
        Some("pve-home")
    );
    assert_eq!(
        synced.get(&proxy).and_then(|l| l.label.as_deref()),
        Some("Proxmox proxy")
    );

    b.set_agent_label(proxy, None).await.unwrap();
    a.sync().await.unwrap();
    assert!(a.agent_labels().unwrap().get(&proxy).is_none());
}
