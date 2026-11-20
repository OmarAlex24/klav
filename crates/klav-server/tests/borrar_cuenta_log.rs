//! The only trace a deleted account leaves on the server is one log line,
//! `account deleted`, with its `account_id` and never its e-mail (ADR 0037
//! §5.5, T167): whoever restores an older backup can delete it again.
//!
//! This test binary installs a global subscriber that writes into a
//! buffer, like `logging.rs`.

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

#[tokio::test]
async fn a_deleted_account_leaves_one_log_line_without_its_email() {
    let buffer = Buffer::default();
    tracing_subscriber::fmt()
        .with_env_filter("klav_server=trace")
        .json()
        .with_writer(buffer.clone())
        .init();

    let server = TestServer::start().await;
    let email = "ana.loglinemarker@example.com";
    let creds = server.signup(email, "pw").await;
    let ana = server.login(&creds, "laptop").await;
    let asked = server.ask_deletion(&ana, &creds).await;
    server
        .server_handle()
        .purge_expired(asked.delete_at)
        .await
        .unwrap();
    drop(server);
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let logs = String::from_utf8(buffer.0.lock().unwrap().clone()).unwrap();
    let account = creds.account_id.to_string();
    let deleted: Vec<serde_json::Value> = logs
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter(|l| l["fields"]["message"] == "account deleted")
        .collect();
    assert_eq!(deleted.len(), 1, "one `account deleted` line");
    assert_eq!(deleted[0]["fields"]["account"], account.as_str());
    assert!(
        logs.contains("account deletion requested"),
        "the request is logged too"
    );
    assert!(
        !logs.contains("loglinemarker"),
        "the e-mail reached the log"
    );
}
