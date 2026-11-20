//! The client library against the real server: sign-up, a second device,
//! offline unlock, token refresh and rollback detection.

mod common;

use common::ServerProcess;
use klav_client::{
    ClientError, Home, ItemFilter, LoginRequest, SignupRequest, kit, login, signup,
    unlock_with_local_key, unlock_with_password,
};
use klav_core::crypto::kdf::MasterPassword;
use klav_core::crypto::secret_key::SecretKey;
use klav_core::model::item::{Item, ItemKind};
use klav_proto::auth::DeviceKind;
use secrecy::ExposeSecret;

const PASSWORD: &str = "correct horse battery staple";
const SECRET: &str = "MARKER-github-password-41";

fn github(password: &str) -> Item {
    let mut item = Item::from_template(ItemKind::Login, "GitHub").expect("template");
    item.field_mut("username")
        .expect("username")
        .set_value("ana")
        .expect("set");
    item.field_mut("password")
        .expect("password")
        .set_value(password)
        .expect("set");
    item.add_url("https://github.com").expect("url");
    item
}

#[tokio::test(flavor = "multi_thread")]
async fn two_devices_sync_and_a_rollback_is_refused() {
    // Default token lifetimes: the session survives the database restore
    // below (a real attacker would keep the sessions and roll back the
    // vault; restoring a whole snapshot also rolls back rotated tokens).
    let mut server = ServerProcess::start(900);
    let a_dir = tempfile::tempdir().unwrap();
    let b_dir = tempfile::tempdir().unwrap();
    let home_a = Home::at(a_dir.path().join("a"));
    let home_b = Home::at(b_dir.path().join("b"));

    // Device A signs up: Personal vault + General project exist.
    let (mut a, emergency) = signup(
        &home_a,
        SignupRequest {
            server: server.url.clone(),
            email: "Ana@Example.com".into(),
            password: MasterPassword::new(PASSWORD),
            device_name: "laptop".into(),
            device_kind: DeviceKind::Cli,
        },
    )
    .await
    .expect("sign-up");
    let text = kit::render(&emergency);
    assert!(text.contains("ana@example.com"));
    let secret_key_text = emergency.secret_key().to_text().expose_secret().to_owned();
    assert!(text.contains(&secret_key_text));
    assert_eq!(a.vaults().len(), 1);
    assert_eq!(a.vaults()[0].name, klav_client::DEFAULT_VAULT);
    let vault = a.find_vault("personal").unwrap();
    let project = a.find_project(vault, "general").unwrap();

    // A second sign-up in the same home is refused.
    assert!(matches!(
        signup(
            &home_a,
            SignupRequest {
                server: server.url.clone(),
                email: "other@example.com".into(),
                password: MasterPassword::new("x"),
                device_name: "x".into(),
                device_kind: DeviceKind::Cli,
            },
        )
        .await,
        Err(ClientError::AlreadyLoggedIn(_))
    ));

    let item = github(SECRET);
    let loc = a.add_item(vault, project, &item).await.expect("add");
    let listed = a.list_items(&ItemFilter::default()).unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].reference, "klav://Personal/General/GitHub");
    assert_eq!(listed[0].username.as_deref(), Some("ana"));
    let resolved = a
        .resolve("klav://personal/general/github/password")
        .unwrap();
    assert_eq!(resolved.value.expose(), SECRET);
    assert_eq!(a.find_item("GitHub").unwrap(), loc);
    assert_eq!(a.find_item("Personal/General/GitHub").unwrap(), loc);

    // The vault key never left A: B rebuilds everything from ciphertext.
    let mut b = login(
        &home_b,
        LoginRequest {
            server: server.url.clone(),
            email: "ana@example.com".into(),
            password: MasterPassword::new(PASSWORD),
            secret_key: SecretKey::parse(&secret_key_text).unwrap(),
            device_name: "phone".into(),
            device_kind: DeviceKind::Cli,
        },
    )
    .await
    .expect("login on device B");
    assert_ne!(b.account().device_id, a.account().device_id);
    assert_eq!(
        b.resolve("klav://Personal/General/GitHub/password")
            .unwrap()
            .value
            .expose(),
        SECRET
    );

    // A wrong password fails on B's login and on A's offline unlock.
    let wrong = login(
        &Home::at(b_dir.path().join("c")),
        LoginRequest {
            server: server.url.clone(),
            email: "ana@example.com".into(),
            password: MasterPassword::new("wrong"),
            secret_key: SecretKey::parse(&secret_key_text).unwrap(),
            device_name: "x".into(),
            device_kind: DeviceKind::Cli,
        },
    )
    .await;
    assert!(matches!(wrong, Err(ClientError::WrongCredentials)));
    assert!(matches!(
        unlock_with_password(&home_a, &MasterPassword::new("wrong")),
        Err(ClientError::WrongCredentials)
    ));

    // Offline unlock reads the encrypted cache; the local key alone also
    // opens the device (what Touch ID will use).
    drop(a);
    let a = unlock_with_password(&home_a, &MasterPassword::new(PASSWORD)).expect("unlock");
    assert_eq!(a.list_items(&ItemFilter::default()).unwrap().len(), 1);
    drop(a);
    let account = klav_client::account(&home_a).unwrap();
    let kek = klav_core::crypto::kdf::derive_kek(
        &MasterPassword::new(PASSWORD),
        &SecretKey::parse(&secret_key_text).unwrap(),
        &klav_core::crypto::kdf::KdfParams::decode(account.kdf_params.as_bytes()).unwrap(),
    )
    .unwrap();
    let local_key = klav_core::crypto::local::derive_local_key(&kek, &account.local_context());
    let mut a = unlock_with_local_key(&home_a, local_key).expect("unlock with the local key");

    // Nothing on disk holds the secret or the tokens in the clear.
    for home in [&home_a, &home_b] {
        for entry in std::fs::read_dir(home.dir()).unwrap() {
            let path = entry.unwrap().path();
            let bytes = std::fs::read(&path).unwrap();
            let hay = String::from_utf8_lossy(&bytes);
            assert!(!hay.contains("MARKER-"), "secret in {}", path.display());
            assert!(
                !hay.contains("kat_") && !hay.contains("krt_"),
                "token in {}",
                path.display()
            );
            assert!(!hay.contains("GitHub"), "title in {}", path.display());
        }
    }

    // Rollback (T7): snapshot the server, move forward, restore the snapshot.
    server.snapshot("before-edit");
    a.sync().await.expect("A syncs after restart");
    let mut edited = a.open_item(loc).unwrap();
    edited
        .field_mut("password")
        .unwrap()
        .set_value("MARKER-new-password-42")
        .unwrap();
    a.update_item(loc, &edited).await.expect("edit");
    b.sync().await.expect("B sees version 2");
    assert_eq!(b.item_summary(loc).unwrap().version, 2);
    let before = b.revisions();

    server.restore("before-edit");
    let err = b.sync().await.expect_err("rollback must be refused");
    assert!(err.is_rollback(), "{err}");
    assert!(err.to_string().contains("SECURITY"));
    // B keeps what it had.
    assert_eq!(b.revisions(), before);
    assert_eq!(
        b.resolve("klav://Personal/General/GitHub/password")
            .unwrap()
            .value
            .expose(),
        "MARKER-new-password-42"
    );
    // A restarted device B (marks are persisted) refuses it too.
    drop(b);
    let mut b = unlock_with_password(&home_b, &MasterPassword::new(PASSWORD)).unwrap();
    assert!(b.sync().await.unwrap_err().is_rollback());
}

#[tokio::test(flavor = "multi_thread")]
async fn two_processes_share_one_session_through_refreshes() {
    // Access tokens shorter than the client's 30 s refresh margin: every
    // request rotates the session first. Refresh tokens are single-use, and
    // reusing one revokes the session, so the two unlocked instances (think
    // CLI and daemon) must coordinate. The tokens still live long enough
    // never to expire between a refresh and the request after it: with 1 s,
    // a stall of a second on a loaded CI machine ended in `SessionExpired`.
    let server = ServerProcess::start(20);
    let dir = tempfile::tempdir().unwrap();
    let home = Home::at(dir.path().join("h"));
    let (mut first, _kit) = signup(
        &home,
        SignupRequest {
            server: server.url.clone(),
            email: "bea@example.com".into(),
            password: MasterPassword::new(PASSWORD),
            device_name: "laptop".into(),
            device_kind: DeviceKind::Cli,
        },
    )
    .await
    .expect("sign-up");
    let mut second = unlock_with_password(&home, &MasterPassword::new(PASSWORD)).unwrap();
    let vault = first.find_vault("Personal").unwrap();
    let project = first.find_project(vault, "General").unwrap();
    // Only a rotation rewrites the shared session file (sealed, so compared
    // without printing it): both instances must take turns rotating it.
    let session = || std::fs::read(home.session_path()).expect("session file");
    for round in 0..3 {
        let mut item = github(SECRET);
        item.set_title(&format!("item {round}")).unwrap();
        let before = session();
        first
            .add_item(vault, project, &item)
            .await
            .expect("first writes");
        let written = session();
        assert!(before != written, "round {round}: first rotated");
        second.sync().await.expect("second follows");
        assert!(written != session(), "round {round}: second rotated");
    }
    assert_eq!(second.list_items(&ItemFilter::default()).unwrap().len(), 3);
    first.sync().await.expect("the session is still alive");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_detached_sync_applies_only_where_it_was_planned_and_still_refuses_a_rollback() {
    // klavd's background sync (ADR 0026): planned with the account, fetched
    // without it, applied with the same checks as any sync.
    let mut server = ServerProcess::start(900);
    let dir = tempfile::tempdir().unwrap();
    let home = Home::at(dir.path().join("h"));
    let (mut a, _kit) = signup(
        &home,
        SignupRequest {
            server: server.url.clone(),
            email: "dora@example.com".into(),
            password: MasterPassword::new(PASSWORD),
            device_name: "laptop".into(),
            device_kind: DeviceKind::Cli,
        },
    )
    .await
    .expect("sign-up");
    // Another process of the same account makes the changes.
    let mut other = unlock_with_password(&home, &MasterPassword::new(PASSWORD)).expect("unlock");
    other.sync().await.expect("sync");
    let vault = other.find_vault("personal").unwrap();
    let project = other.find_project(vault, "general").unwrap();
    let add = async |other: &mut klav_client::Unlocked, title: &str| {
        let mut item = github(SECRET);
        item.set_title(title).unwrap();
        other.add_item(vault, project, &item).await.expect("add");
    };
    let titles = |a: &klav_client::Unlocked| a.list_items(&ItemFilter::default()).unwrap().len();

    // Another sync changed the cache between plan and apply: dropped.
    add(&mut other, "One").await;
    let fetched = a
        .sync_plan()
        .expect("plan")
        .fetch()
        .await
        .unwrap()
        .expect("token accepted");
    let before = a.generation();
    a.sync().await.expect("sync");
    assert_eq!(a.generation(), before + 1);
    assert!(a.finish_sync(fetched).await.unwrap().is_none());
    assert_eq!(titles(&a), 1);

    // Nothing in between: applied, and the generation moves.
    add(&mut other, "Two").await;
    let fetched = a
        .sync_plan()
        .expect("plan")
        .fetch()
        .await
        .unwrap()
        .expect("token accepted");
    let report = a.finish_sync(fetched).await.unwrap().expect("applied");
    assert_eq!(report.items_received, 1);
    assert_eq!(a.generation(), before + 2);
    assert_eq!(titles(&a), 2);
    // A sync that brings nothing leaves the generation alone.
    let fetched = a
        .sync_plan()
        .expect("plan")
        .fetch()
        .await
        .unwrap()
        .expect("token accepted");
    assert!(a.finish_sync(fetched).await.unwrap().is_some());
    assert_eq!(a.generation(), before + 2);

    // Rollback (T7): refused on apply, the cache untouched.
    server.snapshot("before");
    add(&mut other, "Three").await;
    a.sync().await.expect("sync");
    let marks = a.revisions();
    server.restore("before");
    let fetched = a
        .sync_plan()
        .expect("plan")
        .fetch()
        .await
        .unwrap()
        .expect("token accepted");
    let err = a
        .finish_sync(fetched)
        .await
        .expect_err("rollback must be refused");
    assert!(err.is_rollback(), "{err}");
    assert_eq!(a.revisions(), marks);
    assert_eq!(titles(&a), 3);
}

#[tokio::test(flavor = "multi_thread")]
async fn lists_filter_by_type_and_by_codes() {
    use klav_core::model::item::{Field, FieldKind};

    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().unwrap();
    let home = Home::at(dir.path().join("h"));
    let (mut a, _kit) = signup(
        &home,
        SignupRequest {
            server: server.url.clone(),
            email: "eva@example.com".into(),
            password: MasterPassword::new(PASSWORD),
            device_name: "laptop".into(),
            device_kind: DeviceKind::Cli,
        },
    )
    .await
    .expect("sign-up");
    let vault = a.find_vault("Personal").unwrap();
    let project = a.find_project(vault, "General").unwrap();
    const SEED: &str = "JBSWY3DPEHPK3PXP";

    let mut with_code = github(SECRET);
    with_code
        .field_mut("totp")
        .unwrap()
        .set_value(SEED)
        .unwrap();
    a.add_item(vault, project, &with_code).await.unwrap();
    let mut plain = github(SECRET);
    plain.set_title("GitLab").unwrap();
    let plain_loc = a.add_item(vault, project, &plain).await.unwrap();
    let mut standalone = Item::from_template(ItemKind::Totp, "Google").unwrap();
    standalone
        .field_mut("totp")
        .unwrap()
        .set_value(SEED)
        .unwrap();
    a.add_item(vault, project, &standalone).await.unwrap();
    // A code on a note still counts: «Codes» goes by the field, not the type.
    let mut note = Item::new(ItemKind::Note, "Router").unwrap();
    note.add_field(Field::new("otp", "", FieldKind::Totp, SEED).unwrap())
        .unwrap();
    a.add_item(vault, project, &note).await.unwrap();
    // An empty code field is no code.
    a.add_item(
        vault,
        project,
        &Item::from_template(ItemKind::Totp, "Empty").unwrap(),
    )
    .await
    .unwrap();
    a.add_item(
        vault,
        project,
        &Item::from_template(ItemKind::Card, "Visa").unwrap(),
    )
    .await
    .unwrap();
    a.add_item(
        vault,
        project,
        &Item::from_template(ItemKind::SshKey, "Server").unwrap(),
    )
    .await
    .unwrap();

    let titles = |a: &klav_client::Unlocked, filter: ItemFilter| -> Vec<String> {
        let mut t: Vec<String> = a
            .list_items(&filter)
            .unwrap()
            .into_iter()
            .map(|s| s.title)
            .collect();
        t.sort();
        t
    };
    assert_eq!(titles(&a, ItemFilter::default()).len(), 7);
    assert_eq!(
        titles(
            &a,
            ItemFilter {
                kind: Some(ItemKind::Login),
                ..ItemFilter::default()
            }
        ),
        ["GitHub", "GitLab"]
    );
    assert_eq!(
        titles(
            &a,
            ItemFilter {
                kinds: vec![ItemKind::Card, ItemKind::SshKey],
                ..ItemFilter::default()
            }
        ),
        ["Server", "Visa"]
    );
    // `kind` and `kinds` add up.
    assert_eq!(
        titles(
            &a,
            ItemFilter {
                kind: Some(ItemKind::Note),
                kinds: vec![ItemKind::Card],
                ..ItemFilter::default()
            }
        ),
        ["Router", "Visa"]
    );
    let codes = ItemFilter {
        codes: true,
        ..ItemFilter::default()
    };
    assert_eq!(titles(&a, codes.clone()), ["GitHub", "Google", "Router"]);
    assert_eq!(
        titles(
            &a,
            ItemFilter {
                kind: Some(ItemKind::Login),
                codes: true,
                query: Some("git".into()),
                ..ItemFilter::default()
            }
        ),
        ["GitHub"]
    );
    // A code added later shows up: the answer lives as long as the version.
    let mut edited = a.open_item(plain_loc).unwrap();
    edited.field_mut("totp").unwrap().set_value(SEED).unwrap();
    a.update_item(plain_loc, &edited).await.unwrap();
    assert_eq!(
        titles(&a, codes.clone()),
        ["GitHub", "GitLab", "Google", "Router"]
    );
    // The filter travels to klavd as optional fields: absent when unused.
    let wire = serde_json::to_value(ItemFilter::default()).unwrap();
    assert!(wire.get("kinds").is_none() && wire.get("codes").is_none());
    let wire = serde_json::to_value(&codes).unwrap();
    assert_eq!(wire["codes"], true);
    let back: ItemFilter = serde_json::from_value(serde_json::json!({
        "kinds": ["ssh_key", "api_key"], "codes": true, "trash": false
    }))
    .unwrap();
    assert_eq!(back.kinds, [ItemKind::SshKey, ItemKind::ApiKey]);
    assert!(back.codes);
}

#[tokio::test(flavor = "multi_thread")]
async fn suggest_lists_the_codes_on_their_own_that_name_the_page() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().unwrap();
    let home = Home::at(dir.path().join("h"));
    let (mut a, _kit) = signup(
        &home,
        SignupRequest {
            server: server.url.clone(),
            email: "eva@example.com".into(),
            password: MasterPassword::new(PASSWORD),
            device_name: "laptop".into(),
            device_kind: DeviceKind::Cli,
        },
    )
    .await
    .expect("sign-up");
    let vault = a.find_vault("Personal").unwrap();
    let project = a.find_project(vault, "General").unwrap();
    const SEED: &str = "JBSWY3DPEHPK3PXP";
    let code = |title: &str, value: &str| {
        let mut item = Item::from_template(ItemKind::Totp, title).unwrap();
        item.field_mut("totp").unwrap().set_value(value).unwrap();
        item
    };

    // A login of the page with its own code: in `logins`, never in `codes`.
    let mut login = github(SECRET);
    login.field_mut("totp").unwrap().set_value(SEED).unwrap();
    a.add_item(vault, project, &login).await.unwrap();
    // Named by its title (a Google Authenticator import), by the issuer of
    // its link, or by one of its URLs.
    a.add_item(vault, project, &code("GitHub", SEED))
        .await
        .unwrap();
    let link = format!("otpauth://totp/ana?secret={SEED}&issuer=GitHub");
    a.add_item(vault, project, &code("Work phone", &link))
        .await
        .unwrap();
    let mut with_url = code("Backup", SEED);
    with_url.add_url("https://github.com").unwrap();
    a.add_item(vault, project, &with_url).await.unwrap();
    // Another site's, and a code field still empty: not for this page.
    a.add_item(vault, project, &code("GitLab", SEED))
        .await
        .unwrap();
    a.add_item(
        vault,
        project,
        &Item::from_template(ItemKind::Totp, "github").unwrap(),
    )
    .await
    .unwrap();

    let offered = a.suggest("https://github.com/sessions/two-factor").unwrap();
    let titles = |list: &[klav_client::fill::Suggestion]| -> Vec<String> {
        list.iter().map(|s| s.title.clone()).collect()
    };
    assert_eq!(titles(&offered.logins), ["GitHub"]);
    assert!(offered.logins[0].totp);
    assert_eq!(titles(&offered.codes), ["Backup", "GitHub", "Work phone"]);
    assert!(
        offered
            .codes
            .iter()
            .all(|s| s.kind == ItemKind::Totp && s.totp)
    );
    // Metadata only: nothing of the code's link travels.
    let wire = serde_json::to_string(&offered).unwrap();
    assert!(
        !wire.contains(SEED) && !wire.contains("otpauth") && !wire.contains(SECRET),
        "{wire}"
    );

    // Another site gets none, nor does a page that puts the brand before
    // its own domain; and an older klavd's answer reads as none.
    let other = a.suggest("https://example.com/").unwrap();
    assert!(other.codes.is_empty());
    let phishing = a
        .suggest("https://github.com.attacker.example/login")
        .unwrap();
    assert!(phishing.codes.is_empty() && phishing.logins.is_empty());
    assert!(serde_json::to_value(&other).unwrap().get("codes").is_none());
    let old: klav_client::fill::Suggestions = serde_json::from_value(serde_json::json!({
        "host": "github.com", "logins": [], "cards": [], "identities": []
    }))
    .unwrap();
    assert!(old.codes.is_empty());
}
