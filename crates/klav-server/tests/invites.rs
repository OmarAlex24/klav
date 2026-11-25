//! Registration invites (ADR 0048 §1): `registration_mode`, what health
//! says, `invite/check`, the invite in `register/*`, the last use raced,
//! the invite rate limit and `klav-server invite create|ls|revoke`.

mod common;

use common::TestServer;
use futures_util::future::join_all;
use klav_proto::{ErrorBody, ErrorCode, HealthResponse, RegistrationMode};
use klav_server::Config;
use klav_server::invites::{self, Command, Create};
use reqwest::StatusCode;
use serde_json::{Value, json};

const DAY_MS: i64 = 24 * 60 * 60 * 1000;

async fn invite_server() -> TestServer {
    invite_server_with(|_| {}).await
}

/// A server in `invite` mode, configured as production will be: with
/// `allow_registration = false` next to it (ADR 0048 §1.1).
async fn invite_server_with(customize: impl FnOnce(&mut Config)) -> TestServer {
    TestServer::start_with(|c| {
        c.allow_registration = Some(false);
        c.registration_mode = Some(RegistrationMode::Invite);
        // These tests check many invites from one IP; the rate-limit test
        // lowers it again.
        c.rate_limit.invite_ip_burst = 1_000;
        customize(c);
    })
    .await
}

/// The configuration the admin command sees: the server's database.
fn admin_config(server: &TestServer) -> Config {
    Config {
        database_url: server.database_url.clone(),
        ..Config::default()
    }
}

/// `klav-server invite create …` against the server's database: the code
/// and the id it printed.
async fn create(server: &TestServer, email: Option<&str>, uses: i64) -> (String, String) {
    let out = invites::run(
        &admin_config(server),
        Command::Create(Create {
            email: email.map(str::to_owned),
            uses,
            expires_in_ms: if uses > 1 { 14 * DAY_MS } else { 30 * DAY_MS },
            note: Some("test".into()),
        }),
    )
    .await
    .expect("invite create");
    let field = |name: &str| {
        out.lines()
            .find_map(|l| l.strip_prefix(name))
            .map(|v| v.trim().to_owned())
            .unwrap_or_else(|| panic!("no {name} in {out}"))
    };
    (field("code:"), field("id:"))
}

async fn check(server: &TestServer, email: &str, invite: &str) -> reqwest::Response {
    server
        .post_json(
            "/v1/auth/invite/check",
            &json!({ "email": email, "invite": invite }),
        )
        .await
}

async fn health(server: &TestServer) -> Value {
    server
        .http
        .get(server.url("/v1/health"))
        .send()
        .await
        .expect("health request")
        .json()
        .await
        .expect("health body")
}

async fn error_body(res: reqwest::Response) -> ErrorBody {
    res.json().await.expect("error body")
}

#[tokio::test]
async fn health_tells_new_clients_the_mode_and_older_ones_to_stop() {
    let server = invite_server().await;
    let raw = health(&server).await;
    assert_eq!(raw["registration_mode"], "invite");
    // An older client only reads `registration_open`: in `invite` mode it is
    // false, so it says "not open yet" before writing a kit (§1.2).
    assert_eq!(raw["registration_open"], false);
    let typed: HealthResponse = serde_json::from_value(raw).unwrap();
    assert_eq!(typed.registration_mode, Some(RegistrationMode::Invite));

    // An older client that skips health and signs up without an invite
    // gets a plain 403 (its error enum can't read `invite_invalid`).
    let res = server
        .post_json(
            "/v1/auth/register/start",
            &json!({ "email": "a@b.c", "registration_request": "AAAA" }),
        )
        .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);

    for (customize, mode, open) in [
        (None, "open", true),
        (Some(false), "closed", false),
        (Some(true), "open", true),
    ] {
        let server = TestServer::start_with(|c| c.allow_registration = customize).await;
        let raw = health(&server).await;
        assert_eq!(raw["registration_mode"], mode);
        assert_eq!(raw["registration_open"], open);
    }
}

#[tokio::test]
async fn invite_check_does_not_exist_outside_invite_mode() {
    let open = TestServer::start().await;
    let closed = TestServer::start_with(|c| c.allow_registration = Some(false)).await;
    for server in [&open, &closed] {
        let res = check(
            server,
            "ana@example.com",
            "KLAV-00000-00000-00000-00000-000000",
        )
        .await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
    }
    // An open server ignores an invite in the sign-up; a closed one still
    // refuses it.
    assert!(
        open.signup_with_invite("ana@example.com", Some("KLAV-nonsense"))
            .await
            .is_ok()
    );
    assert_eq!(
        closed
            .signup_with_invite(
                "ana@example.com",
                Some("KLAV-00000-00000-00000-00000-000000")
            )
            .await
            .err(),
        Some(StatusCode::FORBIDDEN)
    );
}

#[tokio::test]
async fn a_bound_invite_signs_up_its_email_once() {
    let server = invite_server().await;
    let (code, id) = create(&server, Some("Ana@Example.com"), 1).await;
    assert_eq!(check(&server, "ana@example.com", &code).await.status(), 204);
    // Any spelling of the code, and of the email (normalized the same way).
    let spelled = code.to_lowercase().replace('-', " ");
    assert_eq!(
        check(&server, " ANA@example.com", &spelled).await.status(),
        204
    );
    // Bound: another email can't use it, at any step.
    let res = check(&server, "bob@example.com", &code).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    assert_eq!(error_body(res).await.error, ErrorCode::InviteInvalid);
    assert_eq!(
        server
            .signup_with_invite("bob@example.com", Some(&code))
            .await
            .err(),
        Some(StatusCode::FORBIDDEN)
    );
    // Without an invite, or with a malformed one.
    for invite in [None, Some("KLAV-oops")] {
        assert_eq!(
            server
                .signup_with_invite("ana@example.com", invite)
                .await
                .err(),
            Some(StatusCode::FORBIDDEN)
        );
    }

    let account = server
        .signup_with_invite("ana@example.com", Some(&code))
        .await
        .expect("signs up");
    // Spent: no second account, and the check says so too.
    assert_eq!(check(&server, "ana@example.com", &code).await.status(), 403);
    let db = server.raw_db().await;
    let (used, uses): (i64, i64) = sqlx::query_as(
        "SELECT CAST(used_count AS BIGINT), \
         (SELECT COUNT(*) FROM registration_invite_uses WHERE invite_id = $1 AND account_id = $2) \
         FROM registration_invites WHERE id = $1",
    )
    .bind(&id)
    .bind(account.to_string())
    .fetch_one(&db)
    .await
    .unwrap();
    assert_eq!((used, uses), (1, 1));
    // Only the digest is stored.
    let stored: Vec<Vec<u8>> = sqlx::query_scalar("SELECT code_hash FROM registration_invites")
        .fetch_all(&db)
        .await
        .unwrap();
    let digest = klav_core::crypto::invite::InviteCode::new(code.clone())
        .digest()
        .unwrap();
    assert_eq!(stored, vec![digest.to_vec()]);

    // `ls` shows who used it and never a code.
    let out = invites::run(&admin_config(&server), Command::Ls { all: true })
        .await
        .unwrap();
    assert!(out.contains(&id), "{out}");
    assert!(out.contains("ana@example.com"), "{out}");
    assert!(out.contains(&format!("used by {account}")), "{out}");
    assert!(!out.contains(&code[5..]), "{out}");
    // Used up: not in the default list.
    let usable = invites::run(&admin_config(&server), Command::Ls { all: false })
        .await
        .unwrap();
    assert!(!usable.contains(&id), "{usable}");
}

#[tokio::test]
async fn every_refusal_looks_the_same_and_never_reads_accounts() {
    let server = invite_server().await;
    // Ana already has an account (created with her own invite).
    let (ana_code, _) = create(&server, Some("ana@example.com"), 1).await;
    server
        .signup_with_invite("ana@example.com", Some(&ana_code))
        .await
        .unwrap();

    let (bound_to_bob, _) = create(&server, Some("bob@example.com"), 1).await;
    let (revoked, revoked_id) = create(&server, None, 1).await;
    invites::run(
        &admin_config(&server),
        Command::Revoke {
            id: revoked_id.clone(),
        },
    )
    .await
    .unwrap();
    let (expired, expired_id) = create(&server, None, 1).await;
    let db = server.raw_db().await;
    sqlx::query("UPDATE registration_invites SET expires_at = 1 WHERE id = $1")
        .bind(&expired_id)
        .execute(&db)
        .await
        .unwrap();
    let unknown = klav_core::crypto::invite::InviteCode::generate()
        .expose()
        .to_owned();

    let mut bodies = Vec::new();
    for (email, invite) in [
        ("ana@example.com", ana_code.as_str()),
        ("carol@example.com", ana_code.as_str()),
        ("ana@example.com", bound_to_bob.as_str()),
        ("carol@example.com", bound_to_bob.as_str()),
        ("ana@example.com", revoked.as_str()),
        ("carol@example.com", expired.as_str()),
        ("ana@example.com", unknown.as_str()),
        ("carol@example.com", "KLAV-ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZX"),
    ] {
        let res = check(&server, email, invite).await;
        assert_eq!(res.status(), StatusCode::FORBIDDEN, "{email} {invite}");
        bodies.push(res.text().await.unwrap());
    }
    bodies.dedup();
    assert_eq!(bodies.len(), 1, "one answer for every reason: {bodies:?}");

    // The check doesn't look at `accounts`: an invite bound to an email
    // that has an account passes it the same as one that doesn't (the
    // 409 comes only at `register/finish`).
    let (for_ana_again, _) = create(&server, Some("ana@example.com"), 1).await;
    assert_eq!(
        check(&server, "ana@example.com", &for_ana_again)
            .await
            .status(),
        204
    );
    assert_eq!(
        check(&server, "bob@example.com", &bound_to_bob)
            .await
            .status(),
        204
    );
}

#[tokio::test]
async fn a_conflict_gives_the_use_back() {
    let server = invite_server().await;
    let (batch, id) = create(&server, None, 2).await;
    server
        .signup_with_invite("ana@example.com", Some(&batch))
        .await
        .unwrap();
    // Ana again: 409, and the use is rolled back.
    assert_eq!(
        server
            .signup_with_invite("ANA@example.com", Some(&batch))
            .await
            .err(),
        Some(StatusCode::CONFLICT)
    );
    let db = server.raw_db().await;
    let used = |db: sqlx::AnyPool, id: String| async move {
        sqlx::query_scalar::<_, i64>(
            "SELECT CAST(used_count AS BIGINT) FROM registration_invites WHERE id = $1",
        )
        .bind(id)
        .fetch_one(&db)
        .await
        .unwrap()
    };
    assert_eq!(used(db.clone(), id.clone()).await, 1);
    // So Bob still gets the second use, and nobody a third.
    server
        .signup_with_invite("bob@example.com", Some(&batch))
        .await
        .unwrap();
    assert_eq!(used(db.clone(), id.clone()).await, 2);
    assert_eq!(
        server
            .signup_with_invite("carol@example.com", Some(&batch))
            .await
            .err(),
        Some(StatusCode::FORBIDDEN)
    );
}

#[tokio::test]
async fn racing_for_the_last_uses_only_that_many_win() {
    let server = invite_server().await;
    for uses in [1_i64, 3] {
        let (code, id) = create(&server, None, uses).await;
        // Every start passes: a check is not a reservation.
        let mut bodies = Vec::new();
        for i in 0..8 {
            bodies.push(
                server
                    .prepare_signup(&format!("racer{uses}-{i}@example.com"), "pw", Some(&code))
                    .await
                    .expect("start passes"),
            );
        }
        let statuses: Vec<StatusCode> = join_all(bodies.iter().map(|b| server.finish_signup(b)))
            .await
            .into_iter()
            .map(|r| r.status())
            .collect();
        let won = statuses
            .iter()
            .filter(|s| **s == StatusCode::CREATED)
            .count();
        assert_eq!(won, usize::try_from(uses).unwrap(), "{statuses:?}");
        assert!(
            statuses
                .iter()
                .all(|s| *s == StatusCode::CREATED || *s == StatusCode::FORBIDDEN),
            "{statuses:?}"
        );
        let db = server.raw_db().await;
        let (used, rows): (i64, i64) = sqlx::query_as(
            "SELECT CAST(used_count AS BIGINT), \
             (SELECT COUNT(*) FROM registration_invite_uses WHERE invite_id = $1) \
             FROM registration_invites WHERE id = $1",
        )
        .bind(&id)
        .fetch_one(&db)
        .await
        .unwrap();
        assert_eq!((used, rows), (uses, uses));
    }
}

#[tokio::test]
async fn invite_attempts_are_rate_limited_per_ip() {
    let server = invite_server_with(|c| {
        c.rate_limit.invite_ip_burst = 3;
        c.rate_limit.invite_ip_per_minute = 1;
    })
    .await;
    let (code, _) = create(&server, None, 1).await;
    // A start with a good invite costs nothing (only failures do).
    for i in 0..5 {
        server
            .prepare_signup(&format!("p{i}@example.com"), "pw", Some(&code))
            .await
            .expect("not charged");
    }
    // Two failures, one check: the bucket of 3 is empty.
    for _ in 0..2 {
        assert_eq!(
            server
                .prepare_signup("x@example.com", "pw", Some("KLAV-nope"))
                .await
                .err(),
            Some(StatusCode::FORBIDDEN)
        );
    }
    assert_eq!(check(&server, "x@example.com", &code).await.status(), 204);
    // Now even a good invite waits: every check, and every sign-up step.
    let res = check(&server, "x@example.com", &code).await;
    assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(res.headers().contains_key("retry-after"));
    assert_eq!(
        server
            .prepare_signup("y@example.com", "pw", Some(&code))
            .await
            .err(),
        Some(StatusCode::TOO_MANY_REQUESTS)
    );
}

#[tokio::test]
async fn the_admin_command_revokes_lists_and_never_migrates() {
    let server = invite_server().await;
    let config = admin_config(&server);
    let (code, id) = create(&server, None, 1).await;
    let (_, other) = create(&server, Some("dan@example.com"), 1).await;
    let out = invites::run(&config, Command::Revoke { id: id.clone() })
        .await
        .unwrap();
    assert!(out.contains(&id));
    assert_eq!(check(&server, "e@example.com", &code).await.status(), 403);
    assert!(
        invites::run(&config, Command::Revoke { id: id.clone() })
            .await
            .unwrap_err()
            .contains("already revoked")
    );
    assert!(
        invites::run(
            &config,
            Command::Revoke {
                id: "no-such-id".into()
            }
        )
        .await
        .unwrap_err()
        .contains("no invite")
    );
    let usable = invites::run(&config, Command::Ls { all: false })
        .await
        .unwrap();
    assert!(!usable.contains(&id) && usable.contains(&other), "{usable}");
    let all = invites::run(&config, Command::Ls { all: true })
        .await
        .unwrap();
    assert!(all.contains(&id) && all.contains("revoked"), "{all}");

    // A database that doesn't exist is not created, and none is migrated.
    if !server.is_postgres() {
        let missing = server.data_dir.path().join("nope.db");
        let err = invites::run(
            &Config {
                database_url: format!("sqlite://{}", missing.display()),
                ..Config::default()
            },
            Command::Ls { all: true },
        )
        .await
        .unwrap_err();
        assert!(err.contains("cannot open"), "{err}");
        assert!(!missing.exists());
    }
}
