//! A new client against a server that predates `item_version` on an
//! attachment declaration (ADR 0036 layer 2): such a server refuses the
//! unknown field with a 400, and the client declares once more without it.
//!
//! The older server is the real one behind a forwarder that answers the
//! declaration the way an older build does whenever it carries
//! `item_version`, and passes everything else through.

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::Router;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use common::ServerProcess;
use klav_client::{Home, SignupRequest, signup};
use klav_core::crypto::kdf::MasterPassword;
use klav_core::model::item::{Item, ItemKind};
use klav_proto::auth::DeviceKind;

struct Older {
    upstream: String,
    http: reqwest::Client,
    refused: AtomicUsize,
    declared: AtomicUsize,
}

async fn forward(State(older): State<Arc<Older>>, req: Request) -> Response {
    let (parts, body) = req.into_parts();
    let body = axum::body::to_bytes(body, 64 * 1024 * 1024)
        .await
        .expect("body");
    let path = parts
        .uri
        .path_and_query()
        .map_or("/", |p| p.as_str())
        .to_owned();
    let declaring = parts.method == axum::http::Method::POST && path.ends_with("/attachments");
    if declaring {
        if body.windows(12).any(|w| w == b"item_version") {
            older.refused.fetch_add(1, Ordering::SeqCst);
            // What an older build answers: its `CreateAttachment` refuses
            // unknown fields.
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(serde_json::json!({
                    "error": "bad_request",
                    "message": "invalid body: Failed to deserialize the JSON body into the target type: unknown field `item_version`, expected one of `id`, `size`, `wrapped_key` at line 1 column 120",
                })),
            )
                .into_response();
        }
        older.declared.fetch_add(1, Ordering::SeqCst);
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
    let mut back = Response::builder().status(res.status().as_u16());
    for (name, value) in res.headers() {
        if name != "content-length" && name != "transfer-encoding" {
            back = back.header(name, value);
        }
    }
    back.body(Body::from(res.bytes().await.expect("answer")))
        .expect("response")
}

#[tokio::test(flavor = "multi_thread")]
async fn an_attachment_uploads_to_a_server_without_item_version() {
    let server = ServerProcess::start(900);
    let older = Arc::new(Older {
        upstream: server.url.trim_end_matches('/').to_owned(),
        http: reqwest::Client::new(),
        refused: AtomicUsize::new(0),
        declared: AtomicUsize::new(0),
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

    let dir = tempfile::tempdir().expect("tempdir");
    let (mut ana, _) = signup(
        &Home::at(dir.path().join("laptop")),
        SignupRequest {
            server: url,
            email: "ana@example.com".into(),
            password: MasterPassword::new("correct horse battery staple"),
            device_name: "laptop".into(),
            device_kind: DeviceKind::Cli,
        },
    )
    .await
    .expect("sign-up");
    let vault = ana.find_vault("Personal").expect("vault");
    let project = ana.find_project(vault, "General").expect("project");
    let item = Item::from_template(ItemKind::Login, "GitHub").expect("item");
    ana.add_item(vault, project, &item).await.expect("add");
    ana.attach("GitHub", "notes", "notes.txt", Some("text/plain"), b"notes")
        .await
        .expect("attach through an older server");
    assert_eq!(older.refused.load(Ordering::SeqCst), 1);
    assert_eq!(older.declared.load(Ordering::SeqCst), 1);
    let loc = ana.find_item("GitHub").expect("find");
    let opened = ana.open_item(loc).expect("open");
    let file = opened.attachments().first().map(|a| a.id).expect("file");
    let content = ana.download_attachment(loc, file).await.expect("download");
    assert_eq!(content.as_slice(), b"notes");
}
