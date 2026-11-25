//! Signing up with an invite (ADR 0048 §2) against the real `klav-server`
//! in `open`, `invite` and `closed` modes: the mode is read first, a bad
//! invite fails before the emergency kit is delivered (and so before any
//! key is derived), a bound and a batch code each work, an older server
//! never receives an `invite` field, and a quota's message reaches the
//! caller as the server wrote it.

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use axum::Router;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use common::ServerProcess;
use klav_client::server::{self, Registration};
use klav_client::{ClientError, Home, SignupRequest, Unlocked, signup_with};
use klav_core::crypto::invite::InviteCode;
use klav_core::crypto::kdf::MasterPassword;
use klav_proto::auth::DeviceKind;
use sqlx::any::AnyPoolOptions;

const PASSWORD: &str = "correct horse battery staple";

fn request(server: &str, email: &str, invite: Option<&str>) -> SignupRequest {
    SignupRequest {
        server: server.to_owned(),
        email: email.to_owned(),
        password: MasterPassword::new(PASSWORD),
        device_name: "laptop".into(),
        device_kind: DeviceKind::Cli,
        invite: invite.map(InviteCode::new),
    }
}

/// Signs up in a fresh home under `dir`; whether the kit was delivered.
async fn sign_up(
    dir: &std::path::Path,
    name: &str,
    req: SignupRequest,
) -> (Result<Unlocked, ClientError>, bool) {
    let home = Home::at(dir.join(name));
    let delivered = AtomicBool::new(false);
    let result = signup_with(&home, req, |_| {
        delivered.store(true, Ordering::SeqCst);
        Ok(())
    })
    .await
    .map(|(unlocked, _)| unlocked);
    if result.is_err() {
        assert!(
            !dir.join(name).join("account.json").exists(),
            "a refused sign-up leaves no account"
        );
    }
    (result, delivered.load(Ordering::SeqCst))
}

/// A refused sign-up that never reached the kit.
#[track_caller]
fn refused_before_the_kit(outcome: (Result<Unlocked, ClientError>, bool)) -> ClientError {
    let (result, delivered) = outcome;
    assert!(!delivered, "the kit must not be delivered");
    match result {
        Ok(_) => panic!("the sign-up should have been refused"),
        Err(e) => e,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_mode_is_read_before_anything_else() {
    let open = ServerProcess::start(900);
    let invite = ServerProcess::start_invite();
    let closed = ServerProcess::start_closed();
    assert_eq!(
        server::registration_mode(&open.url).await.unwrap(),
        Registration::Open
    );
    assert_eq!(
        server::registration_mode(&invite.url).await.unwrap(),
        Registration::Invite
    );
    assert_eq!(
        server::registration_mode(&closed.url).await.unwrap(),
        Registration::Closed
    );
    // Older clients still stop before the kit: `registration_open` is
    // false in `invite` mode (ADR 0048 §1.2).
    assert_eq!(
        server::registration_open(&invite.url).await.unwrap(),
        Some(false)
    );

    let dir = tempfile::tempdir().unwrap();
    let e = refused_before_the_kit(
        sign_up(
            dir.path(),
            "closed",
            request(&closed.url, "ana@example.com", None),
        )
        .await,
    );
    assert!(e.to_string().contains("is not open yet"), "{e}");
    // `invite/check` is not a route of a server in another mode.
    let (code, _) = invite.create_invite(&[]);
    for other in [&open, &closed] {
        let e = server::check_invite(
            &other.url,
            "ana@example.com",
            &InviteCode::new(code.as_str()),
        )
        .await
        .unwrap_err();
        assert!(matches!(e, ClientError::Api { status: 404, .. }), "{e:?}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_bad_invite_fails_before_the_kit() {
    let server = ServerProcess::start_invite();
    let dir = tempfile::tempdir().unwrap();
    let (bound, _) = server.create_invite(&["--email", "Ana@Example.com"]);
    let (revoked, revoked_id) = server.create_invite(&["--email", "ana@example.com"]);
    server.revoke_invite(&revoked_id);
    let (expired, expired_id) = server.create_invite(&["--email", "ana@example.com"]);
    // `--expires` takes days or hours from now: put this one in the past.
    sqlx::any::install_default_drivers();
    let db = AnyPoolOptions::new()
        .max_connections(1)
        .connect(&format!(
            "sqlite://{}",
            server.dir.path().join("klav.db").display()
        ))
        .await
        .unwrap();
    sqlx::query("UPDATE registration_invites SET expires_at = 1 WHERE id = $1")
        .bind(&expired_id)
        .execute(&db)
        .await
        .unwrap();
    db.close().await;

    // No invite at all on an invite server.
    let e = refused_before_the_kit(
        sign_up(
            dir.path(),
            "none",
            request(&server.url, "ana@example.com", None),
        )
        .await,
    );
    assert!(e.to_string().contains("by invite only"), "{e}");

    for (name, email, code) in [
        ("garbage", "ana@example.com", "KLAV-NOT-A-CODE"),
        ("other-email", "bob@example.com", bound.as_str()),
        ("revoked", "ana@example.com", revoked.as_str()),
        ("expired", "ana@example.com", expired.as_str()),
    ] {
        assert!(
            matches!(
                server::check_invite(&server.url, email, &InviteCode::new(code)).await,
                Err(ClientError::InviteInvalid)
            ),
            "{name}"
        );
        let e = refused_before_the_kit(
            sign_up(dir.path(), name, request(&server.url, email, Some(code))).await,
        );
        assert!(matches!(e, ClientError::InviteInvalid), "{name}: {e:?}");
        // The message names no reason and never the code.
        assert_eq!(
            e.to_string(),
            "This invite code isn't valid for this email."
        );
    }

    // The bound one works for its email (as typed in another case), once.
    assert!(
        server::check_invite(
            &server.url,
            " ANA@example.com ",
            &InviteCode::new(bound.as_str())
        )
        .await
        .is_ok()
    );
    let (result, delivered) = sign_up(
        dir.path(),
        "ana",
        request(&server.url, "ana@example.com", Some(&bound)),
    )
    .await;
    assert!(delivered);
    let ana = result.expect("a bound invite signs its email up");
    assert_eq!(ana.account().email, "ana@example.com");
    assert!(
        ana.vaults()
            .iter()
            .any(|v| v.name == klav_client::DEFAULT_VAULT),
        "the Personal vault is there"
    );
    assert!(matches!(
        server::check_invite(
            &server.url,
            "ana@example.com",
            &InviteCode::new(bound.as_str())
        )
        .await,
        Err(ClientError::InviteInvalid)
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_batch_code_signs_up_as_many_as_it_has_uses() {
    let server = ServerProcess::start_invite();
    let dir = tempfile::tempdir().unwrap();
    let (batch, _) = server.create_invite(&["--uses", "2", "--expires", "7d", "--note", "test"]);
    for (i, email) in ["ana@example.com", "bob@example.com"]
        .into_iter()
        .enumerate()
    {
        let (result, delivered) = sign_up(
            dir.path(),
            &format!("d{i}"),
            request(&server.url, email, Some(&batch)),
        )
        .await;
        assert!(delivered);
        result.unwrap_or_else(|e| panic!("{email}: {e}"));
    }
    let e = refused_before_the_kit(
        sign_up(
            dir.path(),
            "third",
            request(&server.url, "carla@example.com", Some(&batch)),
        )
        .await,
    );
    assert!(matches!(e, ClientError::InviteInvalid), "{e:?}");
}

/// A server from before ADR 0048: `GET /v1/health` without
/// `registration_mode` (and, with `no_open`, without `registration_open`
/// either), and request types that refuse unknown fields, so a sign-up
/// carrying `invite` gets a `400`.
struct Older {
    upstream: String,
    http: reqwest::Client,
    no_open: bool,
    invites_seen: AtomicUsize,
    /// Not an older server: health and `register/*` pass untouched, and
    /// `invite/check` says yes to anything (an invite that stops working
    /// between the check and the sign-up).
    yes_to_checks: bool,
}

async fn forward(State(older): State<Arc<Older>>, req: Request) -> Response {
    let (parts, body) = req.into_parts();
    let body = axum::body::to_bytes(body, 1024 * 1024).await.expect("body");
    let path = parts
        .uri
        .path_and_query()
        .map_or("/", |p| p.as_str())
        .to_owned();
    if older.yes_to_checks && path == "/v1/auth/invite/check" {
        return StatusCode::NO_CONTENT.into_response();
    }
    if !older.yes_to_checks
        && path.starts_with("/v1/auth/register/")
        && body.windows(8).any(|w| w == b"\"invite\"")
    {
        older.invites_seen.fetch_add(1, Ordering::SeqCst);
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(serde_json::json!({
                "error": "bad_request",
                "message": "invalid body: unknown field `invite`",
            })),
        )
            .into_response();
    }
    let mut out = older
        .http
        .request(parts.method, format!("{}{path}", older.upstream));
    for (name, value) in &parts.headers {
        if name != "host" && name != "content-length" {
            out = out.header(name, value);
        }
    }
    let res = out.body(body).send().await.expect("forward");
    let status = res.status().as_u16();
    let mut bytes = res.bytes().await.expect("answer").to_vec();
    if path == "/v1/health" && !older.yes_to_checks {
        let mut health: serde_json::Value = serde_json::from_slice(&bytes).expect("health");
        let map = health.as_object_mut().expect("object");
        map.remove("registration_mode");
        if older.no_open {
            map.remove("registration_open");
        }
        bytes = serde_json::to_vec(&health).expect("json");
    }
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Body::from(bytes))
        .expect("response")
}

async fn older(upstream: &str, no_open: bool) -> (String, Arc<Older>) {
    forwarder(upstream, no_open, false).await
}

async fn forwarder(upstream: &str, no_open: bool, yes_to_checks: bool) -> (String, Arc<Older>) {
    let older = Arc::new(Older {
        upstream: upstream.trim_end_matches('/').to_owned(),
        http: reqwest::Client::new(),
        no_open,
        invites_seen: AtomicUsize::new(0),
        yes_to_checks,
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let url = format!("http://{}", listener.local_addr().expect("addr"));
    let app = Router::new()
        .fallback(forward)
        .with_state(Arc::clone(&older));
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (url, older)
}

#[tokio::test(flavor = "multi_thread")]
async fn an_older_server_never_receives_an_invite() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().unwrap();
    // `registration_open: true` only, and then nothing at all.
    for (no_open, expected, name) in [
        (false, Registration::Open, "open"),
        (true, Registration::Unknown, "silent"),
    ] {
        let (url, older) = older(&server.url, no_open).await;
        assert_eq!(server::registration_mode(&url).await.unwrap(), expected);
        let (result, delivered) = sign_up(
            dir.path(),
            name,
            request(
                &url,
                &format!("{name}@example.com"),
                Some("KLAV-HX98F-9KZK5-3TMTZ-B8ZFE-4QV96W"),
            ),
        )
        .await;
        assert!(delivered);
        result.unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(older.invites_seen.load(Ordering::SeqCst), 0, "{name}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_quota_says_which_limit_as_the_server_wrote_it() {
    let server = ServerProcess::start_config("[limits]\nmax_vaults_per_account = 1\n");
    let dir = tempfile::tempdir().unwrap();
    let (result, _) = sign_up(
        dir.path(),
        "ana",
        request(&server.url, "ana@example.com", None),
    )
    .await;
    let mut ana = result.expect("sign up");
    assert!(ana.warnings().is_empty(), "{:?}", ana.warnings());
    let e = ana.create_vault("Work").await.unwrap_err();
    match &e {
        ClientError::QuotaExceeded(message) => {
            assert!(
                message.starts_with("This account is limited to 1 vaults"),
                "{message}"
            );
            assert_eq!(e.to_string(), *message);
        }
        other => panic!("expected QuotaExceeded, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn an_invite_refused_at_sign_up_is_not_a_closed_registration() {
    // The check said yes, then `register/start` says `invite_invalid` (the
    // last use of a batch code, taken meanwhile): the person hears about
    // the invite, not "registration is not open yet".
    let server = ServerProcess::start_invite();
    let (url, _) = forwarder(&server.url, false, true).await;
    let dir = tempfile::tempdir().unwrap();
    let unknown = InviteCode::generate();
    let (result, delivered) = sign_up(
        dir.path(),
        "raced",
        request(&url, "ana@example.com", Some(unknown.expose())),
    )
    .await;
    assert!(delivered, "the check passed, so the kit went out");
    let e = result.err().expect("refused");
    assert!(matches!(e, ClientError::InviteInvalid), "{e:?}");

    // A server whose health doesn't answer stops the sign-up before the
    // kit: going on could write one for an account it then refuses.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let dead = format!("http://{}", listener.local_addr().unwrap());
    drop(listener);
    let e = refused_before_the_kit(
        sign_up(dir.path(), "dead", request(&dead, "ana@example.com", None)).await,
    );
    assert!(matches!(e, ClientError::Network(_)), "{e:?}");
}
