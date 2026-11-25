//! OPAQUE sign-up and log-in, sessions and devices against the real server.

mod common;

use common::TestServer;
use common::client::Session;
use klav_core::crypto::kdf::KdfParams;
use klav_proto::auth::{
    AccountKeyset, DeviceInfo, DeviceKind, DeviceList, PreloginRequest, PreloginResponse,
    RefreshRequest, SessionTokens,
};
use klav_proto::{ErrorBody, ErrorCode};
use reqwest::StatusCode;
use sqlx::Row;

fn device(name: &str) -> DeviceInfo {
    DeviceInfo {
        id: None,
        name: name.into(),
        kind: DeviceKind::Cli,
    }
}

async fn status_of(server: &TestServer, session: &Session, path: &str) -> StatusCode {
    server
        .get_auth(session, path)
        .send()
        .await
        .expect("request")
        .status()
}

#[tokio::test]
async fn signup_login_and_unlock() {
    let server = TestServer::start().await;
    let creds = server.signup("Ana@Example.com", "correct horse").await;
    let session = server.login(&creds, "laptop").await;
    assert_eq!(session.account_id, creds.account_id);

    let keyset: AccountKeyset = server
        .get_auth(&session, "/v1/account")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(keyset.account_id, creds.account_id);
    assert_eq!(keyset.email, "ana@example.com");
    assert_eq!(
        keyset.public_identity.as_bytes(),
        session.identity.public().encode()
    );
}

#[tokio::test]
async fn wrong_password_and_unknown_account_fail_the_same_way() {
    let server = TestServer::start().await;
    let creds = server.signup("ana@example.com", "correct horse").await;
    let (res, kek) = server.login_raw(&creds, "wrong horse", device("x")).await;
    assert!(kek.is_none(), "the client cannot open the envelope");
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    let wrong: ErrorBody = res.json().await.unwrap();

    let mut ghost = server.signup("bob@example.com", "pw").await;
    ghost.email = "nobody@example.com".into();
    let (res, _) = server.login_raw(&ghost, "pw", device("x")).await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    let unknown: ErrorBody = res.json().await.unwrap();
    assert_eq!(wrong, unknown);
    assert_eq!(wrong.error, ErrorCode::Unauthorized);
}

#[tokio::test]
async fn prelogin_returns_stable_decoys_for_unknown_emails() {
    let server = TestServer::start().await;
    let creds = server.signup("ana@example.com", "pw").await;
    let ask = |email: &str| {
        let req = PreloginRequest {
            email: email.into(),
        };
        let server = &server;
        async move {
            let res: PreloginResponse = server.post_ok("/v1/auth/prelogin", &req).await;
            res.kdf_params.into_bytes()
        }
    };
    let real = ask(" ANA@example.com ").await;
    assert!(KdfParams::decode_insecure_for_tests(&real).is_ok());
    let decoy = ask("ghost@example.com").await;
    assert_eq!(decoy, ask("ghost@example.com").await, "stable");
    assert_ne!(decoy, ask("ghost2@example.com").await, "per e-mail");
    // Decoys look like real production parameters.
    assert!(KdfParams::decode(&decoy).is_ok());
    drop(creds);
}

#[tokio::test]
async fn duplicate_accounts_and_closed_registration_are_rejected() {
    let server = TestServer::start().await;
    server.signup("ana@example.com", "pw").await;
    // Same e-mail (different case) → 409.
    assert_eq!(
        server.try_signup("ANA@example.com", "pw").await.err(),
        Some(StatusCode::CONFLICT)
    );

    let closed = TestServer::start_with(|c| c.allow_registration = Some(false)).await;
    let res = closed
        .post_json(
            "/v1/auth/register/start",
            &serde_json::json!({"email": "a@b.c", "registration_request": "AAAA"}),
        )
        .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn register_enforces_the_kdf_floor() {
    // A deployed server: the test-only opt-out is off.
    let server = TestServer::start_with(|c| c.insecure_accept_weak_kdf = false).await;
    let salt = [7u8; 16];
    let weak = [
        KdfParams::insecure_for_tests(64, 1, 1, salt),
        KdfParams::insecure_for_tests(KdfParams::MIN_M_KIB - 1, 3, 4, salt),
        KdfParams::insecure_for_tests(KdfParams::MIN_M_KIB, KdfParams::MIN_T - 1, 4, salt),
        KdfParams::insecure_for_tests(KdfParams::MIN_M_KIB, 3, 0, salt),
        KdfParams::insecure_for_tests(KdfParams::MAX_M_KIB + 1, 3, 4, salt),
        KdfParams::insecure_for_tests(KdfParams::MIN_M_KIB, KdfParams::MAX_T + 1, 4, salt),
    ];
    for (i, params) in weak.into_iter().enumerate() {
        let email = format!("weak{i}@example.com");
        assert_eq!(
            server
                .try_signup_declaring(&email, "pw", Some(params))
                .await
                .err(),
            Some(StatusCode::BAD_REQUEST),
            "case {i}"
        );
    }
    // Nothing was stored for the rejected sign-ups.
    let db = server.raw_db().await;
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM accounts")
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(count, 0);
    db.close().await;

    // Production parameters are accepted.
    assert!(
        server
            .try_signup_declaring("prod@example.com", "pw", Some(KdfParams::generate()))
            .await
            .is_ok()
    );
    // Anything but the defaults stands out from the prelogin decoy of an
    // unknown e-mail, so it is refused too, even within range.
    let other = [
        KdfParams::insecure_for_tests(KdfParams::MIN_M_KIB, KdfParams::MIN_T, 1, salt),
        KdfParams::insecure_for_tests(KdfParams::DEFAULT_M_KIB, KdfParams::DEFAULT_T + 1, 4, salt),
        KdfParams::insecure_for_tests(KdfParams::DEFAULT_M_KIB * 2, KdfParams::DEFAULT_T, 4, salt),
    ];
    for (i, params) in other.into_iter().enumerate() {
        assert_eq!(
            server
                .try_signup_declaring(&format!("other{i}@example.com"), "pw", Some(params))
                .await
                .err(),
            Some(StatusCode::BAD_REQUEST),
            "case {i}"
        );
    }
}

#[tokio::test]
async fn register_validates_blob_kinds() {
    let server = TestServer::start().await;
    let res = server
        .post_json(
            "/v1/auth/register/finish",
            &serde_json::json!({
                "email": "a@b.c",
                "account_id": klav_core::ids::AccountId::generate(),
                "registration_upload": "AAAA",
                "kdf_params": "AQUAAA",
                "public_identity": "AQUA",
                "sealed_identity": "AQEA",
            }),
        )
        .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body: ErrorBody = res.json().await.unwrap();
    assert!(body.message.contains("kdf_params"), "{}", body.message);

    let res = server
        .http
        .post(server.url("/v1/auth/prelogin"))
        .body("{\"email\": \"a@b.c\"}")
        .send()
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::BAD_REQUEST,
        "missing content type"
    );
}

#[tokio::test]
async fn bearer_tokens_are_required_and_logout_revokes() {
    let server = TestServer::start().await;
    let creds = server.signup("ana@example.com", "pw").await;
    let session = server.login(&creds, "laptop").await;

    let res = server
        .http
        .get(server.url("/v1/account"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    let res = server
        .http
        .get(server.url("/v1/account"))
        .bearer_auth("kat_forged")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    // A refresh token is not an access token.
    let res = server
        .http
        .get(server.url("/v1/account"))
        .bearer_auth(&session.tokens.refresh_token)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    assert_eq!(
        status_of(&server, &session, "/v1/account").await,
        StatusCode::OK
    );
    let res = server
        .post_auth(&session, "/v1/auth/logout")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        status_of(&server, &session, "/v1/account").await,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn refresh_rotates_and_reuse_revokes_the_session() {
    let server = TestServer::start().await;
    let creds = server.signup("ana@example.com", "pw").await;
    let mut session = server.login(&creds, "laptop").await;
    let old = session.tokens.clone();

    let fresh: SessionTokens = server
        .post_ok(
            "/v1/auth/refresh",
            &RefreshRequest {
                refresh_token: old.refresh_token.clone(),
            },
        )
        .await;
    assert_ne!(fresh.access_token, old.access_token);
    assert_ne!(fresh.refresh_token, old.refresh_token);
    assert_eq!(
        status_of(&server, &session, "/v1/account").await,
        StatusCode::UNAUTHORIZED,
        "the old access token is replaced"
    );
    session.tokens = fresh;
    assert_eq!(
        status_of(&server, &session, "/v1/account").await,
        StatusCode::OK
    );

    // Replaying the rotated refresh token kills the whole session.
    let res = server
        .post_json(
            "/v1/auth/refresh",
            &RefreshRequest {
                refresh_token: old.refresh_token,
            },
        )
        .await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        status_of(&server, &session, "/v1/account").await,
        StatusCode::UNAUTHORIZED
    );
    let res = server
        .post_json(
            "/v1/auth/refresh",
            &RefreshRequest {
                refresh_token: session.tokens.refresh_token.clone(),
            },
        )
        .await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn access_tokens_expire_but_refresh_still_works() {
    let server = TestServer::start_with(|c| c.sessions.access_ttl_secs = 1).await;
    let creds = server.signup("ana@example.com", "pw").await;
    let session = server.login(&creds, "laptop").await;
    assert_eq!(
        status_of(&server, &session, "/v1/account").await,
        StatusCode::OK
    );
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    assert_eq!(
        status_of(&server, &session, "/v1/account").await,
        StatusCode::UNAUTHORIZED
    );
    let res = server
        .post_json(
            "/v1/auth/refresh",
            &RefreshRequest {
                refresh_token: session.tokens.refresh_token.clone(),
            },
        )
        .await;
    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn devices_can_be_listed_reused_and_revoked() {
    let server = TestServer::start().await;
    let creds = server.signup("ana@example.com", "pw").await;
    let laptop = server.login(&creds, "laptop").await;
    let phone = server.login(&creds, "phone").await;
    assert_ne!(laptop.device_id, phone.device_id);

    // Logging in again with a known device ID keeps it.
    let laptop2 = server
        .login_device(&creds, "laptop (renamed)", Some(laptop.device_id))
        .await;
    assert_eq!(laptop2.device_id, laptop.device_id);

    let list: DeviceList = server
        .get_auth(&laptop, "/v1/devices")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(list.devices.len(), 2);
    let me = list.devices.iter().find(|d| d.current).unwrap();
    assert_eq!(me.id, laptop.device_id);
    assert_eq!(me.name, "laptop (renamed)");

    // Revoke the phone: its access and refresh tokens die immediately.
    let res = server
        .delete_auth(&laptop, &format!("/v1/devices/{}", phone.device_id))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        status_of(&server, &phone, "/v1/account").await,
        StatusCode::UNAUTHORIZED
    );
    let res = server
        .post_json(
            "/v1/auth/refresh",
            &RefreshRequest {
                refresh_token: phone.tokens.refresh_token.clone(),
            },
        )
        .await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    // Revoking twice, or someone else's device, is a 404.
    let res = server
        .delete_auth(&laptop, &format!("/v1/devices/{}", phone.device_id))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    let other = server.signup("bob@example.com", "pw").await;
    let bob = server.login(&other, "bob").await;
    let res = server
        .delete_auth(&bob, &format!("/v1/devices/{}", laptop.device_id))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);

    // A revoked device that logs in again gets a new ID.
    let phone2 = server
        .login_device(&creds, "phone", Some(phone.device_id))
        .await;
    assert_ne!(phone2.device_id, phone.device_id);
    let list: DeviceList = server
        .get_auth(&laptop, "/v1/devices")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(list.devices.len(), 3);
    assert!(
        list.devices
            .iter()
            .any(|d| d.id == phone.device_id && d.revoked_at.is_some())
    );
}

#[tokio::test]
async fn unknown_login_handles_are_rejected() {
    let server = TestServer::start().await;
    let creds = server.signup("ana@example.com", "pw").await;
    // A forged or unknown handle fails like a wrong password.
    let res = server
        .post_json(
            "/v1/auth/login/finish",
            &serde_json::json!({
                "login_id": "lgn_nope",
                "credential_finalization": "AAAA",
                "device": {"name": "x", "kind": "cli"},
            }),
        )
        .await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    drop(creds);
}

#[tokio::test]
async fn auth_attempts_are_rate_limited_per_email() {
    let server = TestServer::start_with(|c| {
        c.rate_limit.auth_email_per_minute = 1;
        c.rate_limit.auth_email_burst = 2;
    })
    .await;
    let req = PreloginRequest {
        email: "ana@example.com".into(),
    };
    for _ in 0..2 {
        assert_eq!(
            server.post_json("/v1/auth/prelogin", &req).await.status(),
            StatusCode::OK
        );
    }
    let res = server.post_json("/v1/auth/prelogin", &req).await;
    assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);
    // Another e-mail is unaffected.
    let other = PreloginRequest {
        email: "bob@example.com".into(),
    };
    assert_eq!(
        server.post_json("/v1/auth/prelogin", &other).await.status(),
        StatusCode::OK
    );
}

/// `POST /v1/auth/prelogin` as if from `ip` (in `X-Real-IP`).
async fn prelogin_from(server: &TestServer, email: &str, ip: &str) -> StatusCode {
    server
        .http
        .post(server.url("/v1/auth/prelogin"))
        .header("x-real-ip", ip)
        .json(&PreloginRequest {
            email: email.into(),
        })
        .send()
        .await
        .expect("request")
        .status()
}

#[tokio::test]
async fn someone_else_cannot_lock_an_account_out_from_another_address() {
    // Behind a proxy that sets X-Real-IP (Railway), with the header trusted.
    let server = TestServer::start_with(|c| {
        c.trusted_ip_header = Some("x-real-ip".into());
        c.rate_limit.auth_email_per_minute = 1;
        c.rate_limit.auth_email_burst = 2;
    })
    .await;
    let attacker = "198.51.100.66";
    for _ in 0..2 {
        assert_eq!(
            prelogin_from(&server, "ana@example.com", attacker).await,
            StatusCode::OK
        );
    }
    assert_eq!(
        prelogin_from(&server, "ana@example.com", attacker).await,
        StatusCode::TOO_MANY_REQUESTS
    );
    // Ana, from her own address, still gets in.
    assert_eq!(
        prelogin_from(&server, "ana@example.com", "203.0.113.5").await,
        StatusCode::OK
    );
}

#[tokio::test]
async fn ip_headers_are_ignored_unless_configured() {
    let server = TestServer::start_with(|c| {
        c.rate_limit.auth_ip_per_minute = 1;
        c.rate_limit.auth_ip_burst = 2;
    })
    .await;
    // Inventing a new address per request does not reset the per-IP bucket.
    let mut statuses = Vec::new();
    for i in 0..3 {
        statuses.push(
            prelogin_from(
                &server,
                &format!("u{i}@example.com"),
                &format!("192.0.2.{i}"),
            )
            .await,
        );
    }
    assert_eq!(
        statuses,
        [
            StatusCode::OK,
            StatusCode::OK,
            StatusCode::TOO_MANY_REQUESTS
        ]
    );
}

#[tokio::test]
async fn the_server_never_stores_the_password_or_the_secret_key() {
    let server = TestServer::start().await;
    let password = "UNIQUE-PASSWORD-MARKER-7f3a";
    let creds = server.signup("ana@example.com", password).await;
    let _session = server.login(&creds, "laptop").await;

    let db = server.raw_db().await;
    let row = sqlx::query(
        "SELECT email, opaque_record, kdf_params, public_identity, sealed_identity FROM accounts",
    )
    .fetch_one(&db)
    .await
    .unwrap();
    let mut stored = row.try_get::<String, _>("email").unwrap().into_bytes();
    for col in [
        "opaque_record",
        "kdf_params",
        "public_identity",
        "sealed_identity",
    ] {
        stored.extend(row.try_get::<Vec<u8>, _>(col).unwrap());
    }
    for needle in [password.as_bytes(), creds.secret_key_text.as_bytes()] {
        assert!(
            !stored.windows(needle.len()).any(|w| w == needle),
            "a secret reached the accounts table"
        );
    }
    // Sessions store digests only.
    let digests: Vec<Vec<u8>> = sqlx::query_scalar("SELECT access_digest FROM sessions")
        .fetch_all(&db)
        .await
        .unwrap();
    assert!(digests.iter().all(|d| d.len() == 32));
    assert!(
        !digests
            .iter()
            .any(|d| d.as_slice() == _session.tokens.access_token.as_bytes())
    );
}

#[tokio::test]
async fn a_push_token_of_another_accounts_active_device_is_not_taken() {
    let server = TestServer::start().await;
    let ana = server.signup("ana@example.com", "pw").await;
    let bob = server.signup("bob@example.com", "pw").await;
    let phone = server.login(&ana, "phone").await;
    let tablet = server.login(&ana, "tablet").await;
    let intruder = server.login(&bob, "phone").await;
    let token = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";
    let register = |session| {
        server
            .put_auth(session, "/v1/devices/current/push")
            .json(&serde_json::json!({"token": token, "environment": "production"}))
            .send()
    };
    assert_eq!(
        register(&phone).await.unwrap().status(),
        StatusCode::NO_CONTENT
    );
    // Another account cannot take it while Ana's device is active…
    assert_eq!(
        register(&intruder).await.unwrap().status(),
        StatusCode::CONFLICT
    );
    // …her own devices can (a reinstalled app)…
    assert_eq!(
        register(&tablet).await.unwrap().status(),
        StatusCode::NO_CONTENT
    );
    // …and once that device is revoked, the token is free again.
    let res = server
        .delete_auth(&phone, &format!("/v1/devices/{}", tablet.device_id))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        register(&intruder).await.unwrap().status(),
        StatusCode::NO_CONTENT
    );
    let db = server.raw_db().await;
    let owners: Vec<String> =
        sqlx::query_scalar("SELECT account_id FROM push_tokens WHERE token = $1")
            .bind(token)
            .fetch_all(&db)
            .await
            .unwrap();
    assert_eq!(owners, [bob.account_id.to_string()]);
}
