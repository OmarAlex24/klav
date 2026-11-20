//! `KlavCore` against the real server: a phone signs in to an account
//! made on a laptop, unlocks with a fake keystore (Face ID), reads and
//! edits items, fills only on the item's site, and approves an agent.

mod common;

use std::collections::HashMap;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use common::ServerProcess;
use klav_client::{Home, SignupRequest};
use klav_core::crypto::identity::IdentityKeyPair;
use klav_core::crypto::kdf::MasterPassword;
use klav_core::ids::{AgentId, ItemId};
use klav_core::model::item::{Item, ItemKind};
use klav_ffi::{
    AcceptedLoss, FieldEdit, ItemEdit, ItemInfo, ItemQuery, KeystoreError, KeystoreKey,
    KeystoreWrap, Kind, KlavCore, KlavError, NewItemInput, PlatformKeystore, SiteRelation,
    site_relation,
};
use klav_proto::Blob;
use klav_proto::agent::RegisterAgent;
use klav_proto::auth::DeviceKind;
use secrecy::ExposeSecret;

const PASSWORD: &str = "correct horse battery staple";
const SECRET: &str = "MARKER-ffi-github-password-77";
const TOTP: &str = "JBSWY3DPEHPK3PXP";

const OK: u8 = 0;
const CANCEL: u8 = 1;
const INVALIDATED: u8 = 2;
const OTHER: u8 = 3;

/// A keystore that behaves like the Secure Enclave without one: the
/// "shared secret" of a wrap is remembered by its ephemeral point.
struct FakeKeystore {
    mode: AtomicU8,
    boot: AtomicU64,
    secrets: Mutex<HashMap<Vec<u8>, Vec<u8>>>,
    created: AtomicU64,
}

impl FakeKeystore {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            mode: AtomicU8::new(OK),
            boot: AtomicU64::new(1_700_000_000),
            secrets: Mutex::new(HashMap::new()),
            created: AtomicU64::new(0),
        })
    }
}

fn random_point() -> Vec<u8> {
    let mut p = vec![0x04];
    p.extend(klav_core::ids::ItemId::generate().as_bytes());
    p.extend(klav_core::ids::ItemId::generate().as_bytes());
    p.extend(klav_core::ids::ItemId::generate().as_bytes());
    p.extend(klav_core::ids::ItemId::generate().as_bytes());
    p.truncate(65);
    p
}

impl PlatformKeystore for FakeKeystore {
    fn available(&self) -> bool {
        true
    }

    fn create_key(&self) -> Result<KeystoreKey, KeystoreError> {
        self.created.fetch_add(1, Ordering::SeqCst);
        Ok(KeystoreKey {
            handle: b"handle".to_vec(),
            public_key: random_point(),
        })
    }

    fn wrap(&self, public_key: Vec<u8>) -> Result<KeystoreWrap, KeystoreError> {
        assert_eq!(public_key.len(), 65);
        let ephemeral = random_point();
        let mut secret = ItemId::generate().as_bytes().to_vec();
        secret.extend(ItemId::generate().as_bytes());
        self.secrets
            .lock()
            .expect("test setup")
            .insert(ephemeral.clone(), secret.clone());
        Ok(KeystoreWrap {
            ephemeral_public: ephemeral,
            secret,
        })
    }

    fn unwrap(
        &self,
        handle: Vec<u8>,
        ephemeral_public: Vec<u8>,
        reason: String,
    ) -> Result<Vec<u8>, KeystoreError> {
        assert_eq!(handle, b"handle");
        assert!(!reason.is_empty());
        match self.mode.load(Ordering::SeqCst) {
            CANCEL => Err(KeystoreError::Cancelled),
            INVALIDATED => Err(KeystoreError::Invalidated),
            OTHER => Err(KeystoreError::Other),
            _ => self
                .secrets
                .lock()
                .expect("test setup")
                .get(&ephemeral_public)
                .cloned()
                .ok_or(KeystoreError::Other),
        }
    }

    fn boot_time(&self) -> u64 {
        self.boot.load(Ordering::SeqCst)
    }

    fn confirm_owner(&self, _reason: String) -> Result<(), KeystoreError> {
        Ok(())
    }
}

fn github() -> Item {
    let mut item = Item::from_template(ItemKind::Login, "GitHub").expect("test setup");
    item.field_mut("username")
        .expect("test setup")
        .set_value("ana")
        .expect("test setup");
    item.field_mut("password")
        .expect("test setup")
        .set_value(SECRET)
        .expect("test setup");
    item.field_mut("totp")
        .expect("test setup")
        .set_value(TOTP)
        .expect("test setup");
    item.add_url("https://github.com/login")
        .expect("test setup");
    item
}

/// Signs up on "the laptop" and adds a login; returns the Secret Key.
fn laptop(server: &str, dir: &std::path::Path) -> String {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test setup");
    rt.block_on(async {
        let home = Home::at(dir.join("laptop"));
        let (mut laptop, kit) = klav_client::signup(
            &home,
            SignupRequest {
                server: server.to_owned(),
                email: "ana@example.com".into(),
                password: MasterPassword::new(PASSWORD),
                device_name: "laptop".into(),
                device_kind: DeviceKind::Cli,
            },
        )
        .await
        .expect("test setup");
        let vault = laptop.find_vault("Personal").expect("test setup");
        let project = laptop.find_project(vault, "General").expect("test setup");
        laptop
            .add_item(vault, project, &github())
            .await
            .expect("test setup");
        kit.secret_key().to_text().expose_secret().to_owned()
    })
}

/// Registers an agent with its own key, as `klav agent register` does.
fn register_agent(server: &str, name: &str) -> (AgentId, String) {
    let keys = IdentityKeyPair::generate();
    let id = AgentId::generate();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test setup");
    let status = rt.block_on(async {
        reqwest::Client::new()
            .post(format!("{server}/v1/agents/register"))
            .json(&RegisterAgent {
                id,
                email: "ana@example.com".into(),
                name: name.into(),
                public_identity: Blob::new(keys.public().encode().to_vec()),
                note: Some("deploys".into()),
            })
            .send()
            .await
            .expect("test setup")
            .status()
    });
    assert_eq!(status.as_u16(), 202);
    (id, klav_core::crypto::agent::pairing_code(keys.public()))
}

#[test]
fn a_phone_signs_in_unlocks_with_face_id_and_fills_only_on_the_right_site() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().unwrap();
    let secret_key = laptop(&server.url, dir.path());
    let home = dir.path().join("phone");
    let core = KlavCore::new(home.display().to_string()).unwrap();
    let keystore = FakeKeystore::new();
    let ks: Arc<dyn PlatformKeystore> = keystore.clone();

    // Not signed in yet; everything else says "locked".
    let status = core.status();
    assert!(!status.has_account && !status.unlocked);
    assert!(matches!(
        core.items(ItemQuery::default()),
        Err(KlavError::Locked)
    ));

    // A wrong password is told apart; the right one signs in and enrols
    // Face ID.
    assert!(matches!(
        core.sign_in(
            server.url.clone(),
            "ana@example.com".into(),
            "wrong".into(),
            secret_key.clone(),
            "iPhone".into(),
            Some(ks.clone()),
        ),
        Err(KlavError::WrongCredentials)
    ));
    let enrolled = core
        .sign_in(
            server.url.clone(),
            "Ana@Example.com".into(),
            PASSWORD.into(),
            secret_key,
            "iPhone".into(),
            Some(ks.clone()),
        )
        .unwrap();
    assert!(enrolled);
    let status = core.status();
    assert!(status.has_account && status.unlocked);
    assert_eq!(status.email.as_deref(), Some("ana@example.com"));
    assert_eq!(status.account_words.unwrap().split_whitespace().count(), 6);

    // Browse: the login arrived with the sync, without secret values.
    assert_eq!(core.vaults().unwrap()[0].name, "Personal");
    let items = core.items(ItemQuery::default()).unwrap();
    assert_eq!(items.len(), 1);
    let id = items[0].id.clone();
    let detail = core.item(id.clone()).unwrap();
    assert!(detail.has_totp);
    assert!(
        detail
            .fields
            .iter()
            .filter(|f| f.secret)
            .all(|f| f.value.is_none())
    );
    assert_eq!(
        detail
            .fields
            .iter()
            .find(|f| f.name == "username")
            .and_then(|f| f.value.clone())
            .as_deref(),
        Some("ana")
    );
    assert!(!format!("{detail:?}").contains(SECRET));
    assert_eq!(
        core.field_value(id.clone(), "password".into()).unwrap(),
        SECRET
    );
    let code = core.totp(id.clone()).unwrap();
    assert_eq!(code.code.len(), 6);
    assert_eq!(code.period, 30);
    assert!(code.remaining >= 1 && code.remaining <= 30);
    let found = core
        .items(ItemQuery {
            text: Some("git".into()),
            ..ItemQuery::default()
        })
        .unwrap();
    assert_eq!(found.len(), 1);
    // Filters by type, and «Codes»: the items with a one-time code.
    let count = |q: ItemQuery| core.items(q).unwrap().len();
    assert_eq!(
        count(ItemQuery {
            codes: true,
            ..ItemQuery::default()
        }),
        1
    );
    assert_eq!(
        count(ItemQuery {
            kinds: vec![Kind::Card, Kind::Note],
            ..ItemQuery::default()
        }),
        0
    );
    assert_eq!(
        count(ItemQuery {
            kinds: vec![Kind::Note, Kind::Login],
            codes: true,
            ..ItemQuery::default()
        }),
        1
    );

    // AutoFill: only GitHub and its subdomains, never look-alikes.
    assert_eq!(core.suggestions("github.com".into()).unwrap().len(), 1);
    assert_eq!(
        core.suggestions("https://gist.github.com/x".into())
            .unwrap()
            .len(),
        1
    );
    assert!(
        core.suggestions("https://github.com.evil.io/login".into())
            .unwrap()
            .is_empty()
    );
    assert!(core.suggestions("http://github.com".into()).is_err());
    let credential = core
        .password_credential(id.clone(), "github.com".into(), false)
        .unwrap();
    assert_eq!(credential.username, "ana");
    assert_eq!(credential.password, SECRET);
    assert!(!format!("{credential:?}").contains(SECRET));
    assert!(matches!(
        core.password_credential(id.clone(), "evil.com".into(), true),
        Err(KlavError::SiteMismatch { .. })
    ));
    assert!(matches!(
        core.one_time_code(id.clone(), "githubb.com".into(), true),
        Err(KlavError::SiteMismatch { .. })
    ));
    assert_eq!(
        core.one_time_code(id.clone(), "github.com".into(), false)
            .unwrap()
            .code
            .len(),
        6
    );
    let identities = core.credential_identities().unwrap();
    assert_eq!(identities.len(), 1);
    assert_eq!(identities[0].hosts, vec!["github.com".to_owned()]);
    assert!(identities[0].has_password && identities[0].has_totp);

    // ADR 0025: exact host, then subdomain, whatever the titles; a login
    // saved for a subdomain only apart on its parent, and only `chosen`.
    let mut created = Vec::new();
    for (title, url) in [
        ("Zeta", "https://my.1password.com/signin"),
        ("Alpha", "https://1password.com"),
    ] {
        let info = core
            .create_item(NewItemInput {
                kind: Kind::Login,
                title: title.into(),
                vault_id: None,
                project_id: None,
                fields: vec![FieldEdit {
                    name: "password".into(),
                    value: "parent-pass".into(),
                    kind: None,
                }],
                urls: vec![url.into()],
                tags: vec![],
                notes: None,
            })
            .unwrap();
        created.push(info.id);
    }
    let titles = |v: Vec<ItemInfo>| v.into_iter().map(|i| i.title).collect::<Vec<_>>();
    assert_eq!(
        titles(core.suggestions("my.1password.com".into()).unwrap()),
        ["Zeta", "Alpha"]
    );
    assert_eq!(
        titles(core.suggestions("https://1password.com/".into()).unwrap()),
        ["Alpha"]
    );
    let parent = core.parent_suggestions("1password.com".into()).unwrap();
    assert_eq!(parent.len(), 1);
    assert_eq!(parent[0].item.title, "Zeta");
    assert_eq!(parent[0].saved_host, "my.1password.com");
    assert!(
        core.parent_suggestions("my.1password.com".into())
            .unwrap()
            .is_empty()
    );
    let zeta = parent[0].item.id.clone();
    assert!(matches!(
        core.password_credential(zeta.clone(), "1password.com".into(), false),
        Err(KlavError::SiteMismatch { .. })
    ));
    assert_eq!(
        core.password_credential(zeta.clone(), "1password.com".into(), true)
            .unwrap()
            .password,
        "parent-pass"
    );
    // `chosen` never opens a sibling.
    assert!(matches!(
        core.password_credential(zeta, "start.1password.com".into(), true),
        Err(KlavError::SiteMismatch { .. })
    ));
    assert_eq!(
        site_relation("1password.com".into(), vec!["my.1password.com".into()]),
        Some(SiteRelation::Parent)
    );
    assert_eq!(
        site_relation("com".into(), vec!["my.1password.com".into()]),
        None
    );
    for id in created {
        core.trash_item(id).unwrap();
    }

    // Create, refuse a duplicate title, edit, trash.
    let mail = core
        .create_item(NewItemInput {
            kind: Kind::Login,
            title: "Mail".into(),
            vault_id: None,
            project_id: None,
            fields: vec![FieldEdit {
                name: "password".into(),
                value: "mail-pass".into(),
                kind: None,
            }],
            urls: vec!["https://mail.example.com".into()],
            tags: vec![],
            notes: Some("recovery codes in the safe".into()),
        })
        .unwrap();
    assert!(
        core.create_item(NewItemInput {
            kind: Kind::Note,
            title: "mail".into(),
            vault_id: None,
            project_id: None,
            fields: vec![],
            urls: vec![],
            tags: vec![],
            notes: None,
        })
        .is_err()
    );
    let edited = core
        .edit_item(
            mail.id.clone(),
            ItemEdit {
                title: Some("Mail (work)".into()),
                set: vec![FieldEdit {
                    name: "username".into(),
                    value: "ana@work".into(),
                    kind: None,
                }],
                ..ItemEdit::default()
            },
        )
        .unwrap();
    assert_eq!(edited.title, "Mail (work)");
    assert_eq!(edited.username.as_deref(), Some("ana@work"));
    assert_eq!(
        core.notes(mail.id.clone()).unwrap().as_deref(),
        Some("recovery codes in the safe")
    );
    core.trash_item(mail.id.clone()).unwrap();
    assert_eq!(core.items(ItemQuery::default()).unwrap().len(), 1);
    assert_eq!(core.sync().unwrap().vaults_updated, 0);

    // Lock, then Face ID: cancel keeps the enrolment, success unlocks.
    core.lock();
    assert!(matches!(core.item(id.clone()), Err(KlavError::Locked)));
    let state = core.biometric_state(ks.clone());
    assert!(state.enrolled && state.password_required.is_none());
    keystore.mode.store(CANCEL, Ordering::SeqCst);
    assert!(matches!(
        core.unlock_with_biometrics(ks.clone(), "Unlock Klav".into()),
        Err(KlavError::BiometryFailed { .. })
    ));
    assert!(core.biometric_state(ks.clone()).enrolled);
    keystore.mode.store(OK, Ordering::SeqCst);
    core.unlock_with_biometrics(ks.clone(), "Unlock Klav".into())
        .unwrap();
    assert_eq!(
        core.field_value(id.clone(), "password".into()).unwrap(),
        SECRET
    );

    // After a restart the password is required (and editing the file to
    // claim otherwise does not open: the AAD binds it, spec §12.3).
    core.lock();
    keystore.boot.store(1_700_000_999, Ordering::SeqCst);
    assert!(core.biometric_state(ks.clone()).password_required.is_some());
    assert!(matches!(
        core.unlock_with_biometrics(ks.clone(), "Unlock Klav".into()),
        Err(KlavError::PasswordRequired { .. })
    ));
    let file = home.join("faceid.json");
    let text = std::fs::read_to_string(&file).unwrap();
    std::fs::write(
        &file,
        text.replace("\"boot_time_s\": 1700000000", "\"boot_time_s\": 1700000999"),
    )
    .unwrap();
    assert!(matches!(
        core.unlock_with_biometrics(ks.clone(), "Unlock Klav".into()),
        Err(KlavError::BiometryUnavailable { .. })
    ));
    assert!(!file.exists(), "a tampered enrolment is removed");

    // The password unlocks and enrols again (with a new keystore key).
    assert!(matches!(
        core.unlock_with_password("nope".into(), Some(ks.clone())),
        Err(KlavError::WrongCredentials)
    ));
    assert!(
        core.unlock_with_password(PASSWORD.into(), Some(ks.clone()))
            .unwrap()
    );
    // A passing keystore failure keeps the enrolment.
    core.lock();
    keystore.mode.store(OTHER, Ordering::SeqCst);
    assert!(matches!(
        core.unlock_with_biometrics(ks.clone(), "Unlock Klav".into()),
        Err(KlavError::BiometryFailed { .. })
    ));
    assert!(core.biometric_state(ks.clone()).enrolled);
    // A password time in the future would never expire: the password is
    // asked for.
    let file = home.join("faceid.json");
    let text = std::fs::read_to_string(&file).unwrap();
    let json: serde_json::Value = serde_json::from_str(&text).unwrap();
    let at = json["password_at_ms"].as_u64().unwrap();
    std::fs::write(
        &file,
        text.replace(&at.to_string(), &(at + 365 * 86_400_000).to_string()),
    )
    .unwrap();
    assert!(core.biometric_state(ks.clone()).password_required.is_some());
    std::fs::write(&file, &text).unwrap();
    keystore.mode.store(INVALIDATED, Ordering::SeqCst);
    assert!(matches!(
        core.unlock_with_biometrics(ks.clone(), "Unlock Klav".into()),
        Err(KlavError::BiometryUnavailable { .. })
    ));
    assert!(!core.biometric_state(ks.clone()).enrolled);
    keystore.mode.store(OK, Ordering::SeqCst);
    core.unlock_with_password(PASSWORD.into(), Some(ks.clone()))
        .unwrap();
    // One key at sign-in, a new one after each removed enrolment.
    assert_eq!(keystore.created.load(Ordering::SeqCst), 3);

    // Agents: the phone sees the pending registration with its words,
    // refuses wrong words and approves with the right ones.
    let (agent, words) = register_agent(&server.url, "deploy-bot");
    let (other, _) = register_agent(&server.url, "spammy");
    let agents = core.agents().unwrap();
    let pending = agents.iter().find(|a| a.id == agent.to_string()).unwrap();
    assert_eq!(pending.status, "pending");
    assert_eq!(pending.pairing_words, words);
    assert_eq!(pending.note.as_deref(), Some("deploys"));
    let general = core.projects(None).unwrap()[0].id.clone();
    assert!(matches!(
        core.approve_agent(
            agent.to_string(),
            "able baker charlie delta echo foxtrot".into(),
            vec![general.clone()],
            None,
        ),
        Err(KlavError::Security { .. })
    ));
    let approved = core
        .approve_agent(agent.to_string(), words, vec![general], Some(7))
        .unwrap();
    assert_eq!(approved.status, "active");
    assert_eq!(approved.projects, vec!["Personal/General".to_owned()]);
    core.deny_agent(other.to_string()).unwrap();
    assert!(core.approvals().unwrap().is_empty());

    // Push registration (the server has no APNs here: it just stores it).
    core.register_push_token("ab".repeat(32), true).unwrap();
    assert!(core.register_push_token("nope".into(), true).is_err());
    core.unregister_push_token().unwrap();

    // Signing out leaves nothing behind (the generator outbox, the pinned
    // audit head and the note of a server move, ADR 0028 §4, included).
    std::fs::write(home.join("generator-outbox.bin"), b"x").unwrap();
    std::fs::write(home.join("audit-head.json"), b"{}").unwrap();
    std::fs::write(home.join("server-moved"), b"https://old.example\n").unwrap();
    // A generator outbox that doesn't open can't be counted: «nothing» is
    // refused (fails closed), and the check fails, so the dialog says Klav
    // couldn't tell and the person accepts whatever is there.
    assert!(core.sign_out(AcceptedLoss::Nothing).is_err());
    assert!(core.sign_out_check().is_err());
    assert!(core.status().has_account);
    core.sign_out(AcceptedLoss::Unknown).expect("sign out");
    assert!(!core.status().has_account);
    assert!(!home.join("cache.bin").exists());
    assert!(!home.join("faceid.json").exists());
    assert!(!home.join("generator-outbox.bin").exists());
    assert!(!home.join("audit-head.json").exists());
    assert!(!home.join("server-moved").exists());
}

#[test]
fn service_hosts_follow_the_extension_rule() {
    assert_eq!(
        klav_ffi::service_host("GitHub.com".into()).unwrap(),
        "github.com"
    );
    assert_eq!(
        klav_ffi::service_host("https://accounts.google.com/signin".into()).unwrap(),
        "accounts.google.com"
    );
    assert_eq!(
        klav_ffi::service_host("http://127.0.0.1:8080".into()).unwrap(),
        "127.0.0.1"
    );
    assert!(klav_ffi::service_host("http://example.com".into()).is_err());
    assert!(klav_ffi::service_host("".into()).is_err());
    let password = klav_ffi::generate_password(24, true).unwrap();
    assert_eq!(password.chars().count(), 24);
}

/// ADR 0028 on the iPhone: the server field's aliases, the kit after the
/// master password with today's server, and moving the account by hand.
#[test]
fn the_phone_prints_its_kit_and_moves_to_another_url() {
    assert_eq!(
        klav_ffi::server_from_input("klav.dev".into()).unwrap(),
        klav_client::DEFAULT_SERVER
    );
    assert_eq!(
        klav_ffi::server_from_input("klav-server-production.up.railway.app".into()).unwrap(),
        klav_client::DEFAULT_SERVER
    );
    assert_eq!(
        klav_ffi::server_from_input("vault.example.com/".into()).unwrap(),
        "https://vault.example.com"
    );
    assert_eq!(
        klav_ffi::server_name(klav_client::DEFAULT_SERVER.into()),
        "klav.dev"
    );

    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let secret_key = laptop(&server.url, dir.path());
    let core = KlavCore::new(dir.path().join("phone").display().to_string()).unwrap();
    core.sign_in(
        server.url.clone(),
        "ana@example.com".into(),
        PASSWORD.into(),
        secret_key,
        "iPhone".into(),
        None,
    )
    .unwrap();

    assert!(matches!(
        core.emergency_kit("wrong".into()),
        Err(KlavError::WrongCredentials)
    ));
    let kit = core.emergency_kit(PASSWORD.into()).unwrap();
    assert!(kit.contains(&format!("Server:     {}\n", server.url)));
    assert!(kit.contains("Secret Key: K1-"));

    // The same server under another name: moved, and still unlocked.
    let new = server.url.replace("127.0.0.1", "localhost");
    assert_eq!(core.set_server(PASSWORD.into(), new.clone()).unwrap(), new);
    let status = core.status();
    assert_eq!(status.server.as_deref(), Some(new.as_str()));
    assert!(status.unlocked);
    core.sync().unwrap();
    assert!(core.emergency_kit(PASSWORD.into()).unwrap().contains(&new));

    // A server without this account: refused, nothing changes.
    let other = ServerProcess::start(900);
    assert!(core.set_server(PASSWORD.into(), other.url.clone()).is_err());
    assert_eq!(core.status().server.as_deref(), Some(new.as_str()));
}

/// `status()` and `lock()` do not wait for a sync stuck on the network,
/// and the stuck call does not hand out its result after the lock.
#[test]
fn status_and_lock_do_not_wait_for_a_server_that_hangs() {
    let server = ServerProcess::start(900);
    let proxy = Proxy::start(&server.url);
    let dir = tempfile::tempdir().unwrap();
    let secret_key = laptop(&server.url, dir.path());
    let core = KlavCore::new(dir.path().join("phone").display().to_string()).unwrap();
    core.sign_in(
        proxy.url.clone(),
        "ana@example.com".into(),
        PASSWORD.into(),
        secret_key,
        "iPhone".into(),
        None,
    )
    .unwrap();
    proxy.set(HANG);
    // The first request may still go down a pooled connection and fail at
    // once; it clears the pool.
    let _ = core.sync();
    let stuck = {
        let core = Arc::clone(&core);
        std::thread::spawn(move || core.sync())
    };
    std::thread::sleep(std::time::Duration::from_millis(500));
    let started = std::time::Instant::now();
    assert!(core.status().unlocked);
    core.lock();
    assert!(!core.status().unlocked);
    assert!(started.elapsed() < std::time::Duration::from_secs(2));
    // Only now does the server drop the stuck sync's connection (nothing
    // ends it before, short of the client's HTTP timeout): it fails, and
    // gives nothing back.
    proxy.set(REFUSE);
    assert!(matches!(stuck.join().unwrap(), Err(KlavError::Locked)));
    assert!(matches!(
        core.items(ItemQuery::default()),
        Err(KlavError::Locked)
    ));
}

/// A TCP proxy in front of a server that can start holding every
/// connection without an answer (a host that hangs) or refusing them (a
/// host that is gone). Switching closes the connections it was forwarding
/// or holding, so a call stuck on a host that hangs fails when the test
/// says, not after the client's HTTP timeout.
struct Proxy {
    url: String,
    mode: Arc<AtomicU8>,
    open: Arc<Mutex<Vec<std::net::TcpStream>>>,
}

const FORWARD: u8 = 0;
const HANG: u8 = 1;
const REFUSE: u8 = 2;

impl Proxy {
    fn start(target: &str) -> Self {
        let target = target.trim_start_matches("http://").to_owned();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind the proxy");
        let url = format!("http://{}", listener.local_addr().expect("proxy address"));
        let mode = Arc::new(AtomicU8::new(FORWARD));
        let open: Arc<Mutex<Vec<std::net::TcpStream>>> = Arc::default();
        let (m, o) = (Arc::clone(&mode), Arc::clone(&open));
        std::thread::spawn(move || {
            for client in listener.incoming().flatten() {
                // Under the lock `set` takes: a connection accepted in the
                // old mode is never kept after the switch.
                let mut open = o.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                match m.load(Ordering::SeqCst) {
                    FORWARD => {
                        let Ok(server) = std::net::TcpStream::connect(&target) else {
                            continue;
                        };
                        let Ok(kept) = client.try_clone() else {
                            continue;
                        };
                        open.push(kept);
                        let pump = |mut from: std::net::TcpStream, mut to: std::net::TcpStream| {
                            std::thread::spawn(move || {
                                let _ = std::io::copy(&mut from, &mut to);
                                let _ = to.shutdown(std::net::Shutdown::Both);
                            });
                        };
                        let (Ok(c), Ok(s)) = (client.try_clone(), server.try_clone()) else {
                            continue;
                        };
                        pump(c, s);
                        pump(server, client);
                    }
                    HANG => open.push(client),
                    _ => drop(client),
                }
            }
        });
        Self { url, mode, open }
    }

    fn set(&self, mode: u8) {
        let mut open = self
            .open
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.mode.store(mode, Ordering::SeqCst);
        for stream in open.drain(..) {
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
    }
}

/// Moving the account (ADR 0028 §4) while another call holds it on the
/// network: that call must not put back the account with the old URL when
/// it ends, so what comes after talks to the new one.
#[test]
fn a_move_is_not_undone_by_a_call_in_flight() {
    let server = ServerProcess::start(900);
    let proxy = Proxy::start(&server.url);
    let dir = tempfile::tempdir().unwrap();
    let secret_key = laptop(&server.url, dir.path());
    let core = KlavCore::new(dir.path().join("phone").display().to_string()).unwrap();
    // The phone knows the server by the proxy's URL: the old one.
    let signing_in = std::time::Instant::now();
    core.sign_in(
        proxy.url.clone(),
        "ana@example.com".into(),
        PASSWORD.into(),
        secret_key,
        "iPhone".into(),
        None,
    )
    .unwrap();
    let sign_in_took = signing_in.elapsed();

    // The old URL hangs; a sync is stuck on it.
    proxy.set(HANG);
    // The first request may still go down a pooled connection and fail at
    // once; it clears the pool.
    let _ = core.sync();
    let stuck = {
        let core = Arc::clone(&core);
        std::thread::spawn(move || core.sync())
    };
    std::thread::sleep(std::time::Duration::from_millis(500));

    // Meanwhile, the account moves to the same server under another name:
    // the move waits for the call in flight.
    let new = server.url.replace("127.0.0.1", "localhost");
    let moving = {
        let (core, new) = (Arc::clone(&core), new.clone());
        std::thread::spawn(move || core.set_server(PASSWORD.into(), new))
    };
    // A move that did not wait would be over by now: it signs in and
    // unlocks, under twice the sign-in above. Capped far below the client's
    // HTTP timeout, the only thing that could end the stuck call meanwhile.
    std::thread::sleep((3 * sign_in_took).min(std::time::Duration::from_secs(10)));
    assert!(!moving.is_finished());
    assert!(!stuck.is_finished());

    // The old URL is gone for good: the stuck call fails now, then the
    // move goes ahead and the account works on the new URL.
    proxy.set(REFUSE);
    assert!(stuck.join().unwrap().is_err());
    assert_eq!(moving.join().unwrap().unwrap(), new);
    assert_eq!(core.status().server.as_deref(), Some(new.as_str()));
    assert!(core.status().unlocked);
    core.sync().expect("sync on the new URL");
}

#[test]
fn sign_up_against_closed_server_explains_self_hosting() {
    let closed = ServerProcess::start_closed();
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("mac");
    let core = KlavCore::new(home.display().to_string()).unwrap();
    let err = core
        .sign_up(
            closed.url.clone(),
            "ana@example.com".into(),
            PASSWORD.into(),
            "Mac".into(),
        )
        .unwrap_err();
    match err {
        KlavError::Invalid { message } => {
            assert!(
                message.contains("is not open yet")
                    && message.contains(klav_client::server::SELF_HOSTING_URL),
                "{message}"
            );
        }
        other => panic!("expected Invalid with self-hosting message, got {other:?}"),
    }
    assert!(!home.join("account.json").exists());
}
