//! What the app sees of ADR 0048 (§2, §3.2): the server's registration
//! mode, an invite checked before the master password, `sign_up` with an
//! invite, `InviteInvalid` without any account written, and a quota's
//! message as `QuotaExceeded`.

mod common;

use common::ServerProcess;
use klav_ffi::{
    FieldEdit, Kind, KlavCore, KlavError, NewItemInput, RegistrationMode, check_invite,
    registration_mode,
};

const PASSWORD: &str = "correct horse battery staple";

fn login(title: &str) -> NewItemInput {
    NewItemInput {
        kind: Kind::Login,
        title: title.into(),
        vault_id: None,
        project_id: None,
        fields: vec![FieldEdit {
            name: "password".into(),
            value: "not-a-real-password".into(),
            kind: None,
        }],
        urls: vec!["https://example.com".into()],
        tags: vec![],
        notes: None,
    }
}

#[test]
fn the_mode_follows_the_server() {
    let open = ServerProcess::start(900);
    let invite = ServerProcess::start_invite();
    let closed = ServerProcess::start_closed();
    assert_eq!(
        registration_mode(open.url.clone()).unwrap(),
        RegistrationMode::Open
    );
    assert_eq!(
        registration_mode(invite.url.clone()).unwrap(),
        RegistrationMode::Invite
    );
    assert_eq!(
        registration_mode(closed.url.clone()).unwrap(),
        RegistrationMode::Closed
    );
    assert!(matches!(
        registration_mode("http://127.0.0.1:9".into()),
        Err(KlavError::Network { .. })
    ));
}

#[test]
fn an_invite_is_checked_before_the_password_and_sent_with_the_sign_up() {
    let server = ServerProcess::start_invite();
    let (code, _) = server.create_invite(&["--email", "ana@example.com"]);
    let dir = tempfile::tempdir().unwrap();

    // Wrong email, a code that does not decode: the same answer.
    for (email, invite) in [
        ("bob@example.com", code.as_str()),
        ("ana@example.com", "KLAV-NOT-A-CODE"),
    ] {
        assert!(matches!(
            check_invite(server.url.clone(), email.into(), invite.into()),
            Err(KlavError::InviteInvalid)
        ));
    }
    check_invite(server.url.clone(), "ana@example.com".into(), code.clone()).expect("valid");

    // `sign_up` refuses without an invite, and with someone else's,
    // before writing anything.
    let home = dir.path().join("bob");
    let core = KlavCore::new(home.display().to_string()).unwrap();
    match core.sign_up(
        server.url.clone(),
        "bob@example.com".into(),
        PASSWORD.into(),
        "Mac".into(),
        None,
    ) {
        Err(KlavError::Invalid { message }) => {
            assert!(message.contains("by invite only"), "{message}");
        }
        other => panic!("expected Invalid, got {other:?}"),
    }
    let err = core
        .sign_up(
            server.url.clone(),
            "bob@example.com".into(),
            PASSWORD.into(),
            "Mac".into(),
            Some(code.clone()),
        )
        .unwrap_err();
    assert!(matches!(err, KlavError::InviteInvalid), "{err:?}");
    assert_eq!(
        err.to_string(),
        "This invite code isn't valid for this email."
    );
    assert!(!home.join("account.json").exists());

    // Its own email signs up, and the code is spent.
    let home = dir.path().join("ana");
    let core = KlavCore::new(home.display().to_string()).unwrap();
    let kit = core
        .sign_up(
            server.url.clone(),
            "ana@example.com".into(),
            PASSWORD.into(),
            "Mac".into(),
            Some(code.clone()),
        )
        .expect("sign up with the invite");
    assert!(kit.contains("Secret Key: K1-"));
    assert!(core.status().unlocked);
    assert!(matches!(
        check_invite(server.url.clone(), "ana@example.com".into(), code),
        Err(KlavError::InviteInvalid)
    ));
}

#[test]
fn a_quota_comes_with_the_servers_message() {
    let server = ServerProcess::start_config("[limits]\nmax_items_per_account = 1\n");
    let dir = tempfile::tempdir().unwrap();
    let core = KlavCore::new(dir.path().join("mac").display().to_string()).unwrap();
    // An invite given to an open server is not needed, and not sent.
    drop(
        core.sign_up(
            server.url.clone(),
            "ana@example.com".into(),
            PASSWORD.into(),
            "Mac".into(),
            Some("KLAV-HX98F-9KZK5-3TMTZ-B8ZFE-4QV96W".into()),
        )
        .expect("sign up"),
    );
    core.create_item(login("First")).expect("one item fits");
    match core.create_item(login("Second")) {
        Err(KlavError::QuotaExceeded { message }) => {
            assert!(
                message.starts_with("This account is limited to 1 items"),
                "{message}"
            );
        }
        other => panic!("expected QuotaExceeded, got {other:?}"),
    }
}
