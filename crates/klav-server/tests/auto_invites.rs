//! Auto-issued beta invites (ADR 0050): `POST /v1/internal/invites/auto`
//! and its revoke. Off unless configured, the token before anything else,
//! one invite per email, the cap under concurrency, and a revoke that gives
//! the seat back.

mod common;

use common::TestServer;
use futures_util::future::join_all;
use klav_proto::RegistrationMode;
use klav_server::Config;
use reqwest::StatusCode;
use serde_json::{Value, json};

const TOKEN: &str = "test-auto-invite-token-0123456789abcdef";
const DAY_MS: i64 = 24 * 60 * 60 * 1000;

/// A server in `invite` mode, as production, with auto invites up to `max`.
async fn auto_server(max: u64) -> TestServer {
    auto_server_with(|c| c.invites.auto_max = max).await
}

async fn auto_server_with(customize: impl FnOnce(&mut Config)) -> TestServer {
    TestServer::start_with(|c| {
        c.allow_registration = Some(false);
        c.registration_mode = Some(RegistrationMode::Invite);
        c.rate_limit.invite_ip_burst = 1_000;
        c.invites.auto_token = Some(TOKEN.to_owned().into());
        c.invites.auto_max = 50;
        customize(c);
    })
    .await
}

async fn issue_raw(server: &TestServer, token: Option<&str>, body: &str) -> reqwest::Response {
    let mut req = server
        .http
        .post(server.url("/v1/internal/invites/auto"))
        .header("content-type", "application/json")
        .body(body.to_owned());
    if let Some(t) = token {
        req = req.header("authorization", format!("Bearer {t}"));
    }
    req.send().await.expect("issue request")
}

/// Issues for `email` with the right token: the status and the JSON body.
async fn issue(server: &TestServer, email: &str) -> (StatusCode, Value) {
    let res = issue_raw(server, Some(TOKEN), &json!({ "email": email }).to_string()).await;
    let status = res.status();
    let body = res.json::<Value>().await.unwrap_or(Value::Null);
    (status, body)
}

async fn revoke(server: &TestServer, token: Option<&str>, id: &str) -> StatusCode {
    let mut req = server
        .http
        .post(server.url(&format!("/v1/internal/invites/auto/{id}/revoke")));
    if let Some(t) = token {
        req = req.header("authorization", format!("Bearer {t}"));
    }
    req.send().await.expect("revoke request").status()
}

/// Not revoked `auto-beta` rows.
async fn live_auto_rows(server: &TestServer) -> i64 {
    let db = server.raw_db().await;
    sqlx::query_scalar(
        "SELECT CAST(COUNT(*) AS BIGINT) FROM registration_invites \
         WHERE note = 'auto-beta' AND revoked_at IS NULL",
    )
    .fetch_one(&db)
    .await
    .expect("count auto-beta rows")
}

#[tokio::test]
async fn the_route_does_not_exist_unless_fully_configured() {
    // A default server: open mode, no token.
    let server = TestServer::start().await;
    let res = issue_raw(&server, Some(TOKEN), r#"{"email":"a@example.com"}"#).await;
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        revoke(&server, Some(TOKEN), "x").await,
        StatusCode::NOT_FOUND
    );

    // Invite mode and a token, but a cap of 0.
    let server = auto_server(0).await;
    let res = issue_raw(&server, Some(TOKEN), r#"{"email":"a@example.com"}"#).await;
    assert_eq!(res.status(), StatusCode::NOT_FOUND);

    // A token and a cap, but not in invite mode.
    for (allow, mode) in [
        (Some(true), RegistrationMode::Open),
        (Some(false), RegistrationMode::Closed),
    ] {
        let server = auto_server_with(|c| {
            c.allow_registration = allow;
            c.registration_mode = Some(mode);
        })
        .await;
        let res = issue_raw(&server, Some(TOKEN), r#"{"email":"a@example.com"}"#).await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND, "{mode:?}");
        assert_eq!(live_auto_rows(&server).await, 0);
    }
}

#[tokio::test]
async fn a_missing_or_wrong_token_is_401_before_the_body_is_read() {
    let server = auto_server(5).await;
    let wrong = format!("{TOKEN}x");
    // A body that would be a 400 (or a 413) is still a 401: the token
    // comes first.
    for body in ["not json", r#"{"email":"nope"}"#, &"x".repeat(64 * 1024)] {
        for token in [None, Some(""), Some(wrong.as_str()), Some("short")] {
            let res = issue_raw(&server, token, body).await;
            assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "{token:?}");
        }
    }
    // Another scheme is a missing token.
    let res = server
        .http
        .post(server.url("/v1/internal/invites/auto"))
        .header("authorization", format!("Basic {TOKEN}"))
        .json(&json!({ "email": "a@example.com" }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(revoke(&server, None, "x").await, StatusCode::UNAUTHORIZED);
    assert_eq!(
        revoke(&server, Some(&wrong), "x").await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(live_auto_rows(&server).await, 0);
}

#[tokio::test]
async fn bodies_are_one_valid_email_and_nothing_else() {
    let server = auto_server(5).await;
    for body in [
        "not json",
        "{}",
        r#"{"email":"not-an-email"}"#,
        r#"{"email":"a@example.com","uses":50}"#,
        r#"{"email":"a@example.com","note":"x"}"#,
        r#"{"email":42}"#,
    ] {
        let res = issue_raw(&server, Some(TOKEN), body).await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST, "{body}");
    }
    let big = json!({ "email": format!("{}@example.com", "a".repeat(2000)) }).to_string();
    let res = issue_raw(&server, Some(TOKEN), &big).await;
    assert_eq!(res.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(live_auto_rows(&server).await, 0);
}

#[tokio::test]
async fn an_issued_invite_is_bound_single_use_and_signs_its_email_up() {
    let server = auto_server(5).await;
    let before = common::agent::now_ms();
    let (status, body) = issue(&server, "  Ana@Example.COM ").await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let id = body["id"].as_str().unwrap().to_owned();
    let code = body["code"].as_str().unwrap().to_owned();
    let expires_at = body["expires_at"].as_i64().unwrap();
    assert!(code.starts_with("KLAV-"), "the code format of ADR 0048");
    assert!(expires_at >= before + 14 * DAY_MS && expires_at <= before + 14 * DAY_MS + 60_000);

    // What is stored: bound, one use, the note, never the code.
    let db = server.raw_db().await;
    let (email, max_uses, note, stored_expiry): (String, i64, String, i64) = sqlx::query_as(
        "SELECT bound_email, CAST(max_uses AS BIGINT), note, expires_at \
         FROM registration_invites WHERE id = $1",
    )
    .bind(&id)
    .fetch_one(&db)
    .await
    .unwrap();
    assert_eq!(
        (email.as_str(), max_uses, note.as_str()),
        ("ana@example.com", 1, "auto-beta")
    );
    assert_eq!(stored_expiry, expires_at);

    // Another email can't use it; its own email can, once.
    assert_eq!(
        server
            .signup_with_invite("bo@example.com", Some(&code))
            .await
            .unwrap_err(),
        StatusCode::FORBIDDEN
    );
    server
        .signup_with_invite("ana@example.com", Some(&code))
        .await
        .expect("signs up with the auto invite");
    assert!(
        server
            .signup_with_invite("ana@example.com", Some(&code))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn one_invite_per_email_used_or_not() {
    let server = auto_server(5).await;
    let (status, body) = issue(&server, "ana@example.com").await;
    assert_eq!(status, StatusCode::CREATED);
    let code = body["code"].as_str().unwrap().to_owned();
    for email in ["ana@example.com", "ANA@example.com "] {
        let (status, body) = issue(&server, email).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body["error"], "already_invited");
        assert!(body.get("code").is_none());
    }
    // Still after it is used: a used seat is never issued again.
    server
        .signup_with_invite("ana@example.com", Some(&code))
        .await
        .unwrap();
    let (status, body) = issue(&server, "ana@example.com").await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"], "already_invited");
    assert_eq!(live_auto_rows(&server).await, 1);
}

#[tokio::test]
async fn the_cap_holds_under_concurrency_and_ignores_other_invites() {
    let server = auto_server(3).await;
    // An invite Omar made by hand doesn't count against the cap.
    let db = server.raw_db().await;
    sqlx::query(
        "INSERT INTO registration_invites \
         (id, code_hash, bound_email, max_uses, used_count, expires_at, note, created_at) \
         VALUES ('manual', $1, NULL, 1, 0, NULL, 'waitlist', 0)",
    )
    .bind(vec![7u8; 32])
    .execute(&db)
    .await
    .unwrap();

    let emails: Vec<String> = (0..12).map(|i| format!("p{i}@example.com")).collect();
    let results = join_all(emails.iter().map(|e| issue(&server, e))).await;
    let created = results
        .iter()
        .filter(|(s, _)| *s == StatusCode::CREATED)
        .count();
    let capped = results
        .iter()
        .filter(|(s, b)| *s == StatusCode::CONFLICT && b["error"] == "cap_reached")
        .count();
    assert_eq!((created, capped), (3, 9), "{results:?}");
    assert_eq!(live_auto_rows(&server).await, 3);

    // A repeat of an issued email is `already_invited`, not `cap_reached`.
    let issued = emails
        .iter()
        .zip(&results)
        .find(|(_, (s, _))| *s == StatusCode::CREATED)
        .unwrap()
        .0;
    let (_, body) = issue(&server, issued).await;
    assert_eq!(body["error"], "already_invited");
}

#[tokio::test]
async fn revoking_an_unsent_invite_gives_the_seat_and_the_email_back() {
    let server = auto_server(1).await;
    let (_, first) = issue(&server, "ana@example.com").await;
    let id = first["id"].as_str().unwrap().to_owned();
    let code = first["code"].as_str().unwrap().to_owned();
    let (_, body) = issue(&server, "bo@example.com").await;
    assert_eq!(body["error"], "cap_reached");

    // The email with the code failed: klav-web revokes it.
    assert_eq!(
        revoke(&server, Some(TOKEN), &id).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(live_auto_rows(&server).await, 0);
    // A revoked code signs nobody up, and revoking twice is 404.
    assert_eq!(
        server
            .signup_with_invite("ana@example.com", Some(&code))
            .await
            .unwrap_err(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        revoke(&server, Some(TOKEN), &id).await,
        StatusCode::NOT_FOUND
    );

    // The seat is free for someone else, and the email can be tried again.
    let (status, bo) = issue(&server, "bo@example.com").await;
    assert_eq!(status, StatusCode::CREATED);
    let bo_id = bo["id"].as_str().unwrap().to_owned();
    assert_eq!(
        revoke(&server, Some(TOKEN), &bo_id).await,
        StatusCode::NO_CONTENT
    );
    let (status, again) = issue(&server, "ana@example.com").await;
    assert_eq!(status, StatusCode::CREATED);

    // A used invite can't be revoked through this route, and neither can
    // an invite that isn't auto-issued or one that doesn't exist.
    let again_code = again["code"].as_str().unwrap();
    server
        .signup_with_invite("ana@example.com", Some(again_code))
        .await
        .unwrap();
    assert_eq!(
        revoke(&server, Some(TOKEN), again["id"].as_str().unwrap()).await,
        StatusCode::NOT_FOUND
    );
    let db = server.raw_db().await;
    sqlx::query(
        "INSERT INTO registration_invites \
         (id, code_hash, bound_email, max_uses, used_count, expires_at, note, created_at) \
         VALUES ('manual', $1, NULL, 1, 0, NULL, 'waitlist', 0)",
    )
    .bind(vec![9u8; 32])
    .execute(&db)
    .await
    .unwrap();
    assert_eq!(
        revoke(&server, Some(TOKEN), "manual").await,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        revoke(&server, Some(TOKEN), "no-such-id").await,
        StatusCode::NOT_FOUND
    );
    let revoked: Option<i64> =
        sqlx::query_scalar("SELECT revoked_at FROM registration_invites WHERE id = 'manual'")
            .fetch_one(&db)
            .await
            .unwrap();
    assert_eq!(revoked, None);
}
