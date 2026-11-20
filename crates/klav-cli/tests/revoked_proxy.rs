//! A sandbox whose proxy the account revoked (ADR 0036 E3.3): a revoked
//! proxy can never log the sandbox's end, so the list shows the row as
//! `proxy_revoked`, from the account's signed `agent.revoked` in the
//! verified chain alone, instead of `revoking`, `waiting` or `active`
//! forever. All by the direct path, without `klavd`, against a local test
//! server and a `klav-proxy` in this process.
//!
//! The server's own word that the proxy is revoked (its `agents` row,
//! played by editing the test server's SQLite file while it is stopped, as
//! `tests/preferences_by_agent.rs` does) changes no row.

mod common;

use common::{Device, ServerProcess};
use klav_client::Home;
use serde_json::Value;
use sqlx::any::AnyPoolOptions;

/// Registers an agent from its own machine and returns its 6 words.
fn register(root: &std::path::Path, server: &ServerProcess, name: &str) -> String {
    Device::new(root, name)
        .run(
            &[
                "agent",
                "register",
                "--name",
                name,
                "--server",
                &server.url,
                "--email",
                "ana@example.com",
                "--key-store",
                "file",
            ],
            "",
        )
        .ok()
        .stdout
        .trim()
        .to_owned()
}

/// The person's command without `klavd`, unlocked with the password.
fn direct(person: &Device, args: &[&str]) -> common::Run {
    let mut all = vec!["--no-daemon"];
    all.extend_from_slice(args);
    person.unlocked(&all, "")
}

/// The status of each row of the verified list, by sandbox ID.
fn statuses(person: &Device) -> Vec<(String, String)> {
    let out = direct(person, &["proxy", "sandboxes", "--ended", "--json"]).ok();
    let doc: Value = serde_json::from_str(&out.stdout).expect("one document");
    doc["sandboxes"]
        .as_array()
        .expect("rows")
        .iter()
        .map(|r| {
            (
                r["sandbox_id"].as_str().unwrap_or("").to_owned(),
                r["status"].as_str().unwrap_or("").to_owned(),
            )
        })
        .collect()
}

fn status_of(rows: &[(String, String)], id: &str) -> String {
    rows.iter()
        .find(|(i, _)| i == id)
        .map(|(_, s)| s.clone())
        .unwrap_or_else(|| panic!("no row {id}: {rows:?}"))
}

/// Sets the proxy's status in the server's own table, with the server
/// stopped: the server's word, without the account's signed revocation.
fn server_says(server: &mut ServerProcess, agent: &str, status: &str) {
    server.stop();
    let url = format!("sqlite://{}", server.dir.path().join("klav.db").display());
    tokio::runtime::Runtime::new()
        .expect("runtime")
        .block_on(async {
            sqlx::any::install_default_drivers();
            let pool = AnyPoolOptions::new()
                .max_connections(1)
                .connect(&url)
                .await
                .expect("open server db");
            let changed = sqlx::query("UPDATE agents SET status = $1 WHERE id = $2")
                .bind(status)
                .bind(agent)
                .execute(&pool)
                .await
                .expect("status");
            assert_eq!(changed.rows_affected(), 1, "the proxy");
            pool.close().await;
        });
    server.restart();
}

/// The person revokes one sandbox, the proxy is stopped before it answers,
/// and the person then revokes the proxy: that row, and one the person
/// never revoked, show `proxy_revoked`, which no server word without the
/// account's signed revocation gives; `--wait` on such a row stops at once
/// instead of running out, and does not say it ended.
#[test]
fn a_revoked_proxys_sandboxes_reach_proxy_revoked() {
    let mut server = ServerProcess::start(900);
    let root = tempfile::tempdir().expect("tempdir");
    let person = Device::new(root.path(), "person");
    person.signup(&server, "ana@example.com");
    person
        .unlocked(
            &[
                "--no-daemon",
                "item",
                "add",
                "api-key",
                "--title",
                "Railway",
                "--secret-stdin",
                "api_key",
            ],
            "MARKER-revoked-proxy-0123456789\n",
        )
        .ok();
    let proxy_words = register(root.path(), &server, "klav-proxy");
    direct(&person, &["proxy", "use", "own", "klav-proxy"]).ok();
    direct(
        &person,
        &[
            "proxy",
            "grant",
            "Railway",
            "--profile",
            "railway",
            "--upstream",
            "https://backboard.railway.app",
            "--header",
            "authorization",
            "--method",
            "POST",
            "--path-prefix",
            "/graphql",
            "--every-device-is-updated",
            "--words",
            &proxy_words,
        ],
    )
    .ok();
    let issuer_words = register(root.path(), &server, "t3-code");
    direct(
        &person,
        &[
            "proxy",
            "issuer",
            "add",
            "t3-code",
            "--profile",
            "railway",
            "--url",
            "tls://proxy.example.com:8443",
            "--max-live",
            "4",
            "--every-device-is-updated",
            "--words",
            &issuer_words,
        ],
    )
    .ok();
    let status: Value =
        serde_json::from_str(&direct(&person, &["proxy", "status", "--json"]).ok().stdout)
            .expect("status json");
    let proxy_id = status["agent_id"].as_str().expect("the proxy").to_owned();

    // The real proxy issues three sandboxes, then stops before it reads
    // any revocation: nothing it does later can end a row.
    let runtime = tokio::runtime::Runtime::new().expect("runtime");
    let bound = runtime
        .block_on(klav_proxy::app::bind(klav_proxy::app::ServeOptions {
            home: Home::at(root.path().join("klav-proxy")),
            name: "klav-proxy".into(),
            port: 0,
            channel: None,
            max_body: klav_proxy::proxy::DEFAULT_MAX_BODY,
            request_timeout: std::time::Duration::from_secs(30),
            no_local_calls: false,
            env: klav_proxy::app::StartEnv::default(),
        }))
        .expect("proxy");
    let port = bound.port().to_string();
    runtime.spawn(bound.run(std::future::pending()));
    let issuer = Device::new(root.path(), "t3-code");
    let work = tempfile::tempdir().expect("work");
    let ids: Vec<String> = ["chat-1", "chat-2", "chat-3"]
        .iter()
        .map(|label| {
            let pkg = work.path().join(label);
            let out = issuer
                .run(
                    &[
                        "sandbox",
                        "start",
                        "--label",
                        label,
                        "--profile",
                        "railway",
                        "--proxy-port",
                        &port,
                        "--package-file",
                        pkg.to_str().expect("path"),
                        "--json",
                    ],
                    "",
                )
                .ok();
            let started: Value = serde_json::from_str(&out.stdout).expect("start json");
            started["sandbox_id"].as_str().expect("id").to_owned()
        })
        .collect();
    drop(runtime);

    // The person revokes the first; the stopped proxy never answers.
    direct(&person, &["proxy", "sandboxes", "revoke", &ids[0]]).ok();
    let rows = statuses(&person);
    assert_eq!(status_of(&rows, &ids[0]), "revoking", "{rows:?}");
    assert_eq!(status_of(&rows, &ids[1]), "waiting", "{rows:?}");

    // Hostile: the server's own word that the proxy is revoked, without
    // the account's signed `agent.revoked` in the chain, changes no row.
    server_says(&mut server, &proxy_id, "revoked");
    let rows = statuses(&person);
    assert_eq!(status_of(&rows, &ids[0]), "revoking", "{rows:?}");
    assert_eq!(status_of(&rows, &ids[1]), "waiting", "{rows:?}");
    server_says(&mut server, &proxy_id, "active");

    // The person revokes the proxy: the account signs `agent.revoked`.
    direct(&person, &["agent", "revoke", "klav-proxy", "--yes"]).ok();
    let rows = statuses(&person);
    for id in &ids {
        assert_eq!(status_of(&rows, id), "proxy_revoked", "{id}: {rows:?}");
    }
    // The plain list hides them, as it does ended rows; the text with
    // `--ended` says what happened, never that it ended.
    let plain = direct(&person, &["proxy", "sandboxes"]);
    for id in &ids {
        assert!(!plain.stdout.contains(&id[..8]), "{}", plain.stdout);
    }
    // With only such rows left, it never says they ended.
    assert!(
        plain.stdout.contains(
            "No sandboxes to show without `--ended`, which also shows those that ended and those whose proxy was revoked."
        ),
        "{}",
        plain.stdout
    );
    let help = person.run(&["proxy", "sandboxes", "--help"], "").ok();
    assert!(
        help.stdout
            .contains("Also those that ended, and those whose proxy was revoked"),
        "{}",
        help.stdout
    );
    // Revoking such a row by the start of its ID (the verified row is
    // read) says no end can come, and promises none.
    let out = direct(&person, &["proxy", "sandboxes", "revoke", &ids[0][..8]]).ok();
    assert!(
        out.stdout
            .contains("Its proxy was revoked, so no end can come for it"),
        "{}",
        out.stdout
    );
    assert!(!out.stdout.contains("next read"), "{}", out.stdout);
    let all = direct(&person, &["proxy", "sandboxes", "--ended"]);
    assert!(
        all.stdout
            .contains("proxy revoked: its end can no longer be logged"),
        "{}",
        all.stdout
    );

    // `--wait` on such a row stops at once: exit 1, not ended, and says
    // why; it never waits out the 2 minutes.
    let started = std::time::Instant::now();
    let out = direct(
        &person,
        &["proxy", "sandboxes", "revoke", &ids[2], "--wait", "--json"],
    );
    assert!(
        started.elapsed() < std::time::Duration::from_secs(60),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(out.code, 1, "{}\n{}", out.stdout, out.stderr);
    let lines: Vec<Value> = out
        .stdout
        .lines()
        .map(|l| serde_json::from_str(l).expect("json"))
        .collect();
    assert_eq!(lines.len(), 2, "{}", out.stdout);
    assert_eq!(
        lines[1]["not_ended"],
        serde_json::json!([ids[2]]),
        "{}",
        out.stdout
    );
    let out = direct(
        &person,
        &["proxy", "sandboxes", "revoke", &ids[1], "--wait"],
    );
    assert_eq!(out.code, 1, "{}\n{}", out.stdout, out.stderr);
    assert!(!out.stdout.contains("logged their end"), "{}", out.stdout);
    assert!(
        out.stderr
            .contains("its proxy was revoked, so it can never log"),
        "{}",
        out.stderr
    );
}
