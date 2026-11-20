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
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let logs = String::from_utf8(buffer.0.lock().unwrap().clone()).unwrap();
    assert!(logs.contains("/v1/health"), "request spans are logged");
    assert!(
        !logs.contains(MARKER),
        "a header, query or body leaked into the logs"
    );
}
