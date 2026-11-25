//! Request logs never contain headers, query strings or bodies.
//!
//! This test binary installs a global subscriber at `trace` level that writes
//! into a buffer, then checks that markers sent in the request never reach it.

mod common;

use std::io::Write;
use std::sync::{Arc, Mutex};

use common::TestServer;
use tracing_subscriber::fmt::MakeWriter;

#[derive(Clone, Default)]
struct Buffer(Arc<Mutex<Vec<u8>>>);

impl Write for Buffer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("log buffer").extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for Buffer {
    type Writer = Buffer;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

pub const MARKER: &str = "LOGLEAKMARKER";

#[tokio::test]
async fn request_logs_contain_no_headers_queries_or_bodies() {
    let buffer = Buffer::default();
    tracing_subscriber::fmt()
        .with_env_filter("trace")
        .json()
        .with_writer(buffer.clone())
        .init();

    let server = TestServer::start().await;
    let res = server
        .http
        .post(server.url(&format!("/v1/health?token={MARKER}")))
        .header("authorization", format!("Bearer {MARKER}"))
        .header("content-type", "application/json")
        .body(format!("{{\"password\":\"{MARKER}\"}}"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 405);
    // A real JSON endpoint: the body (with the marker) is parsed, never logged.
    let res = server
        .http
        .post(server.url("/v1/auth/prelogin"))
        .json(&serde_json::json!({ "email": format!("{MARKER}@example.com") }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let res = server
        .http
        .get(server.url(&format!("/v1/health?token={MARKER}")))
        .header("authorization", format!("Bearer {MARKER}"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    drop(server);

    // Invite failures log one `warn` line with the client IP, never the
    // code or the email (ADR 0048 §1.3, T251). The code here is a valid
    // one, so it reaches the database lookup; a near-miss spelling of it
    // too.
    let code = klav_core::crypto::invite::InviteCode::generate();
    let invite_server = TestServer::start_with(|c| {
        c.allow_registration = Some(false);
        c.registration_mode = Some(klav_proto::RegistrationMode::Invite);
    })
    .await;
    for invite in [code.expose().to_owned(), format!("{MARKER}")] {
        let res = invite_server
            .post_json(
                "/v1/auth/invite/check",
                &serde_json::json!({ "email": format!("{MARKER}@example.com"), "invite": invite }),
            )
            .await;
        assert_eq!(res.status(), 403);
    }
    let bare: String = code.expose()[5..].replace('-', "");
    drop(invite_server);
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let logs = String::from_utf8(buffer.0.lock().unwrap().clone()).unwrap();
    assert!(logs.contains("/v1/health"), "request spans are logged");
    assert!(
        logs.contains("invite refused"),
        "invite failures are logged"
    );
    assert!(
        !logs.contains(&code.expose()[5..]) && !logs.contains(&bare),
        "an invite code leaked into the logs"
    );
    assert!(
        !logs.contains(MARKER),
        "a header, query or body leaked into the logs"
    );
}
