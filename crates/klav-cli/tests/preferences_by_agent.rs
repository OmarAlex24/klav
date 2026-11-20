//! Preferences an agent wrote, end to end through a real `klavd` and the
//! direct path (ADR 0036 §3): `klav proxy sandboxes` shows the rows with a
//! security warning and exits 3; `klav proxy status` exits 3 naming the
//! agent; an older app's `sandbox_list` on the socket still gets a
//! `security` error; and `klav proxy use`, with presence, replaces them.
//!
//! The agent's authorship is the server's word, played by editing the
//! test server's SQLite file while it is stopped, as `klav-client`'s
//! `tests/preferences.rs` does (`sqlx` as a dev-dependency, approved by
//! Omar on 2026-11-16).

mod common;

use common::{Device, ServerProcess};
use klav_client::Home;
use klav_client::ItemLocation;
use klav_client::proxy_admin::REPLACES_AGENT_PREFERENCES;
use klav_core::ids::{AgentId, VaultId};
use klav_core::model::history::system_project_id;
use klav_core::model::item::{Item, ItemKind};
use klav_core::model::preferences::{Preferences, ProxySetting};
use klav_daemon::client::DaemonClient;
use klav_daemon::protocol::{ErrorBody, ErrorCode, Request};
use serde_json::Value;
use sqlx::any::AnyPoolOptions;

/// Stops the daemon even if the test fails.
struct StopDaemon<'a>(&'a Device);

impl Drop for StopDaemon<'_> {
    fn drop(&mut self) {
        let _ = self.0.run(&["lock", "--stop"], "");
    }
}

/// A request straight to klavd, as any client of its socket can send it.
fn raw(person: &Device, request: Request) -> Result<Value, ErrorBody> {
    let home = Home::at(person.home.clone());
    tokio::runtime::Runtime::new()
        .expect("runtime")
        .block_on(async {
            let mut daemon = DaemonClient::connect(&home).await.expect("klavd");
            daemon.call::<Value>(request).await.map(|(v, _)| v)
        })
}

/// Marks every preferences item of the account as written by `agent`,
/// with the server stopped.
fn written_by(server: &mut ServerProcess, agent: AgentId) {
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
            let vault: String = sqlx::query_scalar("SELECT id FROM vaults")
                .fetch_one(&pool)
                .await
                .expect("the one vault");
            let project = system_project_id(vault.parse::<VaultId>().expect("vault id"));
            let changed = sqlx::query(
                "UPDATE items SET author_agent_id = $1, \
                 revision = (SELECT revision + 1 FROM vaults WHERE id = $2) \
                 WHERE project_id = $3",
            )
            .bind(agent.to_string())
            .bind(vault.clone())
            .bind(project.to_string())
            .execute(&pool)
            .await
            .expect("author");
            assert_eq!(changed.rows_affected(), 1, "one preferences item");
            sqlx::query("UPDATE vaults SET revision = revision + 1 WHERE id = $1")
                .bind(vault)
                .execute(&pool)
                .await
                .expect("revision");
            pool.close().await;
        });
    server.restart();
}

/// [`written_by`], then `klavd` syncs, as it would on its own.
fn written_by_and_synced(server: &mut ServerProcess, person: &Device, agent: AgentId) {
    written_by(server, agent);
    person.run(&["sync"], "").ok();
}

/// Exit 3, a security warning naming `agent` and the way out, and the
/// one-document `--json`, by both paths.
fn flagged(person: &Device, agent: AgentId) {
    for direct in [false, true] {
        let mut args = vec!["proxy", "sandboxes"];
        if direct {
            args.insert(0, "--no-daemon");
        }
        let out = person.unlocked(&args, "");
        assert_eq!(out.code, 3, "{}\n{}", out.stdout, out.stderr);
        assert!(
            out.stdout.starts_with("Proxy: security warning: ")
                && out.stdout.contains(&agent.to_string())
                && out.stdout.contains("klav proxy use"),
            "{}",
            out.stdout
        );
        args.push("--json");
        let out = person.unlocked(&args, "");
        assert_eq!(out.code, 3, "{}", out.stderr);
        let doc: Value = serde_json::from_str(&out.stdout).expect("one document");
        assert_eq!(doc["security"]["agent_id"], agent.to_string(), "{doc}");
        assert_eq!(doc["proxy"], Value::Null, "{doc}");
    }
    let out = person.run(&["proxy", "status"], "");
    assert_eq!(out.code, 3, "{}", out.stderr);
    // No proxy is trusted, so neither are the issuers its grant names.
    assert!(!out.stdout.contains("issuers"), "{}", out.stdout);
    assert!(
        out.stderr.contains("SECURITY: ")
            && out.stderr.contains(&agent.to_string())
            && out.stderr.contains("klav proxy use"),
        "{}",
        out.stderr
    );
    // `--json` too: the same exit, and no document, so a script never
    // reads a proxy or its issuers.
    let out = person.run(&["proxy", "status", "--json"], "");
    assert_eq!(out.code, 3, "{}", out.stderr);
    assert!(out.stdout.is_empty(), "{}", out.stdout);
    assert!(out.stderr.contains("SECURITY: "), "{}", out.stderr);
    // An app older than the flag asks `sandbox_list`: still an error.
    let older = raw(person, Request::SandboxList).expect_err("the plain list");
    assert_eq!(older.code, ErrorCode::Security, "{}", older.message);
    let newer = raw(person, Request::SandboxListFlagged).expect("the flagged list");
    assert_eq!(newer["security"]["kind"], "preferences_by_agent");
}

/// The list and the status read clean again, once `klavd` synced what
/// the direct path wrote.
fn clean(person: &Device) {
    person.run(&["sync"], "").ok();
    person.run(&["proxy", "sandboxes"], "").ok();
    let status: Value =
        serde_json::from_str(&person.run(&["proxy", "status", "--json"], "").ok().stdout)
            .expect("status json");
    assert_eq!(status["mode"], "none");
    raw(person, Request::SandboxList).expect("the plain list");
}

/// What `klav proxy use` says it does with them, said exactly once.
fn said_once(stderr: &str) -> usize {
    assert_eq!(
        stderr.matches(REPLACES_AGENT_PREFERENCES).count(),
        1,
        "{stderr}"
    );
    stderr.find(REPLACES_AGENT_PREFERENCES).expect("said")
}

#[test]
fn preferences_an_agent_wrote_are_flagged_and_proxy_use_replaces_them() {
    let mut server = ServerProcess::start(900);
    let root = tempfile::tempdir().expect("tempdir");
    let person = Device::new(root.path(), "person");
    person.signup(&server, "ana@example.com");
    let _stop = StopDaemon(&person);
    person.unlocked(&["unlock", "--idle-lock", "10m"], "").ok();
    // The person's item, then the server says an agent wrote it.
    person.unlocked(&["proxy", "use", "none"], "").ok();
    let agent = AgentId::generate();
    written_by_and_synced(&mut server, &person, agent);
    flagged(&person, agent);

    // Through klavd: presence (the master password, Touch ID is off in
    // tests), and the warning of what it replaces and cannot check.
    person.run(&["proxy", "use", "none"], "").err();
    let out = person.unlocked(&["proxy", "use", "none"], "").ok();
    assert!(
        out.stderr.contains(&agent.to_string()) && out.stderr.contains("former proxy"),
        "{}",
        out.stderr
    );
    // Said before presence, and not again after klavd's write.
    let presence = out.stderr.find("Confirm with Touch ID").expect("presence");
    assert!(said_once(&out.stderr) < presence, "{}", out.stderr);
    clean(&person);

    // Again, through the direct path.
    let other = AgentId::generate();
    written_by_and_synced(&mut server, &person, other);
    flagged(&person, other);
    let out = person
        .unlocked(&["--no-daemon", "proxy", "use", "none"], "")
        .ok();
    assert!(
        out.stderr.contains(&other.to_string()) && out.stderr.contains("former proxy"),
        "{}",
        out.stderr
    );
    said_once(&out.stderr);
    clean(&person);
}

/// The person's session, unlocked with the test password, as the CLI
/// keeps it in `person`'s home.
fn session(person: &Device) -> klav_client::Unlocked {
    klav_client::unlock_with_password(
        &Home::at(person.home.clone()),
        &klav_core::crypto::kdf::MasterPassword::new(common::PASSWORD),
    )
    .expect("unlock")
}

/// A second preferences item beside the person's, with `setting`: what an
/// agent would write. [`item_written_by`] then gives it that agent.
async fn agent_item(person: &Device, setting: ProxySetting) -> ItemLocation {
    let mut a = session(person);
    let vault = a.find_vault("Personal").expect("vault");
    let mut item = Item::new(ItemKind::Preferences, "Preferences").expect("item");
    item.set_preferences(Some(Preferences {
        developer: None,
        proxy: Some(setting),
    }))
    .expect("preferences");
    a.add_item(vault, system_project_id(vault), &item)
        .await
        .expect("added")
}

/// Writes `setting` in the item at `loc`, as its agent would.
async fn rewrite(person: &Device, loc: ItemLocation, setting: ProxySetting) {
    let mut a = session(person);
    a.sync().await.expect("sync");
    let mut item = a.open_item(loc).expect("open");
    item.set_preferences(Some(Preferences {
        developer: None,
        proxy: Some(setting),
    }))
    .expect("preferences");
    a.update_item(loc, &item).await.expect("updated");
}

/// Marks the item at `loc` as written by `agent`, with the server stopped.
fn item_written_by(server: &mut ServerProcess, loc: ItemLocation, agent: AgentId) {
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
            let changed = sqlx::query(
                "UPDATE items SET author_agent_id = $1, \
                 revision = (SELECT revision + 1 FROM vaults WHERE id = $2) WHERE id = $3",
            )
            .bind(agent.to_string())
            .bind(loc.vault.to_string())
            .bind(loc.item.to_string())
            .execute(&pool)
            .await
            .expect("author");
            assert_eq!(changed.rows_affected(), 1, "the item");
            sqlx::query("UPDATE vaults SET revision = revision + 1 WHERE id = $1")
                .bind(loc.vault.to_string())
                .execute(&pool)
                .await
                .expect("revision");
            pool.close().await;
        });
    server.restart();
}

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

/// The rows of the verified list, by the direct path (exit 3 while
/// flagged): each sandbox ID with its proxy and its status.
fn verified_rows(person: &Device) -> Vec<(String, String, String)> {
    let out = direct(person, &["proxy", "sandboxes", "--ended", "--json"]);
    let doc: Value = serde_json::from_str(&out.stdout).expect("one document");
    doc["sandboxes"]
        .as_array()
        .expect("rows")
        .iter()
        .map(|r| {
            (
                r["sandbox_id"].as_str().unwrap_or("").to_owned(),
                r["proxy_id"].as_str().unwrap_or("").to_owned(),
                r["status"].as_str().unwrap_or("").to_owned(),
            )
        })
        .collect()
}

/// While an agent's preferences flag the account's proxy setting, the
/// person still revokes a sandbox the verified log lists, by its whole ID
/// or the start of it, at the proxy that log names for it: preferences
/// that name another proxy cannot redirect the revocation, and
/// preferences that name none cannot suppress it. The command exits 3
/// with the warning in every outcome, as the list and `klav proxy status`
/// do, and names the proxy a revocation went to; `--all`, an ID the
/// verified log does not list and an ended one revoke nothing. All
/// by the direct path, so without `klavd` (whose socket answers the same
/// requests this path makes: the flagged list, then a revocation that
/// names its proxy). The verified log marks a row as revoked only for a
/// revocation of that row's proxy, so the rows show where each went.
#[test]
fn a_flagged_setting_cannot_redirect_or_suppress_a_revocation_by_a_verified_row() {
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
            "MARKER-flagged-revoke-0123456789\n",
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

    // The real proxy, in this process; four sandboxes in the verified log.
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
    let ids: Vec<String> = ["chat-1", "chat-2", "chat-3", "chat-4"]
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

    // Beside the person's preferences, which name the real proxy, an
    // item an agent wrote names another agent of the account, the issuer,
    // as the proxy (two items, as two devices that wrote at once leave
    // them; the agent's authorship is the server's word).
    let decoy: AgentId = status["issuers"][0]["agent_id"]
        .as_str()
        .expect("the issuer")
        .parse()
        .expect("agent id");
    assert_ne!(decoy.to_string(), proxy_id);
    let hostile = runtime.block_on(agent_item(&person, ProxySetting::own(decoy)));
    let writer = AgentId::generate();
    item_written_by(&mut server, hostile, writer);
    // Nothing else gets looser: the list and the status still exit 3.
    let out = direct(&person, &["proxy", "sandboxes"]);
    assert_eq!(out.code, 3, "{}", out.stderr);
    let out = direct(&person, &["proxy", "status"]);
    assert_eq!(out.code, 3, "{}", out.stderr);
    let rows = verified_rows(&person);
    for id in &ids {
        assert!(
            rows.contains(&(id.clone(), proxy_id.clone(), "waiting".into())),
            "{id}: {rows:?}"
        );
    }

    // By the whole ID: revoked at the proxy of its verified row, said
    // first; then exit 3 with the flag and where the revocation went.
    let revoked = |out: &common::Run, id: &str| {
        assert_eq!(out.code, 3, "{}\n{}", out.stdout, out.stderr);
        let first: Value =
            serde_json::from_str(out.stdout.lines().next().expect("a line")).expect("json");
        assert_eq!(first["outcome"], "revoked", "{}", out.stdout);
        assert_eq!(
            first["sandbox_ids"],
            serde_json::json!([id]),
            "{}",
            out.stdout
        );
        assert!(out.stderr.contains(&writer.to_string()), "{}", out.stderr);
        // The proxy it went to, by its ID, to compare with the row.
        let went = format!("went to proxy {proxy_id}, the one the verified log names");
        assert!(out.stderr.contains(&went), "{}", out.stderr);
        let error: Value =
            serde_json::from_str(out.stdout.lines().last().expect("a line")).expect("json");
        assert!(
            error["next"].as_str().is_some_and(|n| n.contains(&went)),
            "{}",
            out.stdout
        );
    };
    // A refusal under the flag: exit 3, the flag, why, nothing said as
    // revoked; with `--json`, only the error line.
    let refused = |args: &[&str], why: &str| {
        let out = direct(&person, args);
        assert_eq!(out.code, 3, "{args:?}: {}\n{}", out.stdout, out.stderr);
        assert!(out.stderr.contains(&writer.to_string()), "{}", out.stderr);
        assert!(out.stderr.contains(why), "{}", out.stderr);
        assert!(out.stderr.contains("nothing was revoked"), "{}", out.stderr);
        assert!(!out.stdout.contains("\"outcome\""), "{}", out.stdout);
        assert!(!out.stdout.contains("Revoked"), "{}", out.stdout);
    };
    let out = direct(
        &person,
        &["proxy", "sandboxes", "revoke", &ids[0], "--json"],
    );
    revoked(&out, &ids[0]);
    // By the start of an ID, as the table shows it.
    let out = direct(
        &person,
        &["proxy", "sandboxes", "revoke", &ids[1][..8], "--json"],
    );
    revoked(&out, &ids[1]);
    // The text form says the revocation, then the problem.
    let out = direct(&person, &["proxy", "sandboxes", "revoke", &ids[2]]);
    assert_eq!(out.code, 3, "{}", out.stderr);
    assert!(out.stdout.starts_with("Revoked sandbox "), "{}", out.stdout);
    assert!(out.stderr.contains("klav proxy use"), "{}", out.stderr);
    assert!(
        out.stderr.contains(&format!("went to proxy {proxy_id}")),
        "{}",
        out.stderr
    );

    // `--all` has no verified row to name its proxy: nothing revoked.
    let out = direct(&person, &["proxy", "sandboxes", "revoke", "--all"]);
    assert_eq!(out.code, 3, "{}", out.stderr);
    assert!(
        out.stderr.contains("revoke each sandbox by its ID"),
        "{}",
        out.stderr
    );
    assert!(out.stdout.is_empty(), "{}", out.stdout);
    // Nor an ID the verified log does not list, whole or its start.
    let stranger = klav_core::ids::SandboxId::generate().to_string();
    let out = direct(&person, &["proxy", "sandboxes", "revoke", &stranger]);
    assert_eq!(out.code, 3, "{}", out.stderr);
    assert!(out.stderr.contains("nothing was revoked"), "{}", out.stderr);
    assert!(out.stdout.is_empty(), "{}", out.stdout);
    refused(
        &["proxy", "sandboxes", "revoke", &stranger[..8]],
        "no sandbox in the verified log starts with",
    );
    refused(
        &["proxy", "sandboxes", "revoke", &stranger[..8], "--json"],
        "no sandbox in the verified log starts with",
    );

    // The decoy got nothing: every revocation is of the real proxy's
    // sandboxes in the verified log (a revocation of another proxy would
    // not mark them), and the fourth is untouched.
    let rows = verified_rows(&person);
    for id in &ids[..3] {
        assert!(
            rows.iter()
                .any(|(i, p, s)| i == id && *p == proxy_id && (s == "revoking" || s == "ended")),
            "{id}: {rows:?}"
        );
    }
    assert!(
        rows.contains(&(ids[3].clone(), proxy_id.clone(), "waiting".into())),
        "{rows:?}"
    );

    // Preferences that name no proxy at all cannot suppress it either.
    runtime.block_on(rewrite(&person, hostile, ProxySetting::NONE));
    item_written_by(&mut server, hostile, writer);
    // With `--wait`, the real proxy logs its end, which the verified list
    // shows; the wait still exits 3 with the warning.
    let out = direct(
        &person,
        &["proxy", "sandboxes", "revoke", &ids[3], "--wait", "--json"],
    );
    revoked(&out, &ids[3]);
    let lines: Vec<Value> = out
        .stdout
        .lines()
        .map(|l| serde_json::from_str(l).expect("json"))
        .collect();
    // The revocation, the same after the wait with nothing left open, then
    // the error line `--json` gives for the exit 3.
    assert_eq!(lines.len(), 3, "{}", out.stdout);
    assert_eq!(lines[1]["outcome"], "revoked", "{}", out.stdout);
    assert_eq!(
        lines[1]["not_ended"],
        serde_json::json!([]),
        "{}",
        out.stdout
    );
    assert!(
        lines[2]["next"]
            .as_str()
            .is_some_and(|n| n.contains(&format!("went to proxy {proxy_id}"))),
        "{}",
        out.stdout
    );
    let rows = verified_rows(&person);
    assert!(
        rows.contains(&(ids[3].clone(), proxy_id.clone(), "ended".into())),
        "{rows:?}"
    );
    // An ended one, whole or by its start: exit 3 under the flag, not 1.
    let ended = format!("sandbox {} already ended", ids[3]);
    refused(&["proxy", "sandboxes", "revoke", &ids[3]], &ended);
    refused(
        &["proxy", "sandboxes", "revoke", &ids[3][..8], "--json"],
        &ended,
    );
    drop(runtime);
}
