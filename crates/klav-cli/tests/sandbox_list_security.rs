//! `klav proxy sandboxes` and a security flag on the list (preferences an
//! agent wrote), against a stand-in `klavd` on the home's socket: a newer
//! one that flags the list, one that flags it with a kind this `klav` does
//! not know, and an older one that knows only `sandbox_list`, which fails
//! closed. Each is a security problem: exit 3, never a clean list, and
//! under `--json` one document.

mod common;

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::sync::{Arc, Mutex};

use common::{Device, ServerProcess};
use klav_core::ids::AgentId;
use serde_json::{Value, json};

/// How a stand-in `klavd` answers the two list requests.
#[derive(Clone)]
enum Klavd {
    /// Knows `sandbox_list_flagged` and answers it with `security` and
    /// [`ROW`].
    Flags(Value),
    /// Older: `bad_request` for `sandbox_list_flagged`, and `sandbox_list`
    /// fails with `security`, as every `klavd` did and does.
    Older(String),
}

/// A sandbox of some proxy, revoking: it must show, with its state.
const ROW: &str = r#"{
    "sandbox_id": "0f1e2d3c-4b5a-4968-8776-655443322110",
    "proxy_id": "11111111-2222-4333-8444-555555555555",
    "issuer_id": "66666666-7777-4888-8999-aaaaaaaaaaaa",
    "label": "chat 42", "profiles": ["railway"],
    "issued_at": 1, "expires_at": 4102444800000, "claimed_at": 2,
    "status": "revoking", "revoked_by_person_at": 3
}"#;

/// Serves `klavd` on `device`'s socket until the test ends; returns the
/// ops it was asked, in order.
fn stand_in(device: &Device, klavd: Klavd) -> Arc<Mutex<Vec<String>>> {
    let listener = UnixListener::bind(device.home.join("klavd.sock")).expect("socket");
    let ops = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&ops);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { return };
            let klavd = klavd.clone();
            let seen = Arc::clone(&seen);
            std::thread::spawn(move || {
                let mut reader = BufReader::new(&stream);
                let mut line = String::new();
                while reader.read_line(&mut line).is_ok_and(|n| n > 0) {
                    let request: Value = serde_json::from_str(&line).expect("a line");
                    line.clear();
                    let op = request["request"]["op"].as_str().unwrap_or("").to_owned();
                    seen.lock().expect("ops").push(op.clone());
                    let id = request["id"].clone();
                    let reply = match (op.as_str(), &klavd) {
                        ("status", _) => json!({"v": 1, "id": id, "ok": {
                            "version": "0.0.0", "protocol": 1, "pid": 1,
                            "logged_in": true, "unlocked": true, "idle_lock_secs": 900,
                        }}),
                        ("sandbox_list_flagged", Klavd::Flags(security)) => {
                            let row: Value = serde_json::from_str(ROW).expect("row");
                            json!({"v": 1, "id": id, "ok": {
                                "sandboxes": [row], "verified_events": 4,
                                "warnings": ["a plain warning"], "security": security,
                            }})
                        }
                        ("sandbox_list_flagged", Klavd::Older(_)) => json!({"v": 1, "id": 0,
                            "error": {"code": "bad_request", "message": "malformed request"}}),
                        ("sandbox_list", Klavd::Older(message)) => json!({"v": 1, "id": id,
                            "error": {"code": "security", "message": message}}),
                        _ => json!({"v": 1, "id": id,
                            "error": {"code": "bad_request", "message": "not in this test"}}),
                    };
                    let mut out = &stream;
                    if out.write_all(format!("{reply}\n").as_bytes()).is_err() {
                        return;
                    }
                }
            });
        }
    });
    ops
}

fn signed_up(root: &std::path::Path, server: &ServerProcess) -> Device {
    let person = Device::new(root, "person");
    person.signup(server, "ana@example.com");
    assert!(
        !person.home.join("klavd.sock").exists(),
        "a real klavd runs in this home"
    );
    person
}

#[test]
fn a_flagged_list_is_a_security_warning_with_its_rows_and_exit_3() {
    let server = ServerProcess::start(900);
    let root = tempfile::tempdir().expect("tempdir");
    let person = signed_up(root.path(), &server);
    let agent = AgentId::generate();
    let ops = stand_in(
        &person,
        Klavd::Flags(json!({"kind": "preferences_by_agent", "agent_id": agent})),
    );

    let out = person.run(&["proxy", "sandboxes"], "");
    assert_eq!(out.code, 3, "{}\n{}", out.stdout, out.stderr);
    let first = out.stdout.lines().next().unwrap_or_default();
    assert!(
        first.starts_with("Proxy: security warning: ")
            && first.contains(&agent.to_string())
            && first.contains("klav proxy use"),
        "{}",
        out.stdout
    );
    // The flag is not one of the plain warnings, which still show.
    assert!(
        out.stderr.contains("warning: a plain warning"),
        "{}",
        out.stderr
    );
    assert!(!out.stderr.contains(&agent.to_string()), "{}", out.stderr);
    assert!(
        out.stdout.contains("Verified up to event #4."),
        "{}",
        out.stdout
    );
    // The row shows, with its verified state, though no proxy is trusted.
    let row = out
        .stdout
        .lines()
        .find(|l| l.starts_with("0f1e2d3c"))
        .unwrap_or_default();
    assert!(
        row.contains("chat 42") && row.contains("revoking (revoked "),
        "{}",
        out.stdout
    );

    // `--json`: one document, with the flag, and the same exit.
    let out = person.run(&["proxy", "sandboxes", "--json"], "");
    assert_eq!(out.code, 3, "{}\n{}", out.stdout, out.stderr);
    let docs: Vec<Value> = serde_json::Deserializer::from_str(&out.stdout)
        .into_iter()
        .collect::<Result<_, _>>()
        .expect("json");
    assert_eq!(docs.len(), 1, "{}", out.stdout);
    assert_eq!(docs[0]["security"]["kind"], "preferences_by_agent");
    assert_eq!(docs[0]["security"]["agent_id"], agent.to_string());
    assert_eq!(docs[0]["proxy"], Value::Null);
    let rows = docs[0]["sandboxes"].as_array().expect("rows");
    assert_eq!(rows.len(), 1, "{}", out.stdout);
    assert_eq!(
        rows[0]["sandbox_id"],
        "0f1e2d3c-4b5a-4968-8776-655443322110"
    );
    assert_eq!(rows[0]["status"], "revoking");
    assert_eq!(rows[0]["revoked_by_person_at"], 3);

    // Only the flagged op was asked: the plain one never.
    let ops = ops.lock().expect("ops").clone();
    assert!(ops.contains(&"sandbox_list_flagged".to_owned()), "{ops:?}");
    assert!(!ops.contains(&"sandbox_list".to_owned()), "{ops:?}");
}

/// A flag of a kind this `klav` does not know, with fields beside it, is
/// still a security problem: exit 3 and «update klav».
#[test]
fn a_flag_this_klav_does_not_know_is_still_exit_3() {
    let server = ServerProcess::start(900);
    let root = tempfile::tempdir().expect("tempdir");
    let person = signed_up(root.path(), &server);
    stand_in(
        &person,
        Klavd::Flags(json!({"kind": "keys_by_server", "agent_id": AgentId::generate(), "n": 2})),
    );
    let out = person.run(&["proxy", "sandboxes"], "");
    assert_eq!(out.code, 3, "{}\n{}", out.stdout, out.stderr);
    assert!(
        out.stdout.starts_with("Proxy: security warning: ") && out.stdout.contains("update klav"),
        "{}",
        out.stdout
    );
    let out = person.run(&["proxy", "sandboxes", "--json"], "");
    assert_eq!(out.code, 3, "{}", out.stderr);
    let doc: Value = serde_json::from_str(&out.stdout).expect("one document");
    assert_eq!(doc["security"], json!({"kind": "unknown"}));
}

/// A `klavd` older than the flag: `sandbox_list_flagged` is a
/// `bad_request`, so `klav` asks `sandbox_list`, whose security error is
/// exit 3 with its words. Never «update klavd» and never a list.
#[test]
fn an_older_klavd_fails_closed_through_the_plain_list() {
    let server = ServerProcess::start(900);
    let root = tempfile::tempdir().expect("tempdir");
    let person = signed_up(root.path(), &server);
    let agent = AgentId::generate();
    let message = format!(
        "SECURITY: the account's preferences were written by agent {agent}; no agent may write them"
    );
    let ops = stand_in(&person, Klavd::Older(message.clone()));
    let out = person.run(&["proxy", "sandboxes"], "");
    assert_eq!(out.code, 3, "{}\n{}", out.stdout, out.stderr);
    assert_eq!(out.stdout, "");
    assert!(out.stderr.contains(&message), "{}", out.stderr);
    let out = person.run(&["proxy", "sandboxes", "--json"], "");
    assert_eq!(out.code, 3, "{}", out.stderr);
    let doc: Value = serde_json::from_str(&out.stdout).expect("one error document");
    assert!(doc.get("sandboxes").is_none(), "{doc}");
    assert!(
        doc["message"]
            .as_str()
            .is_some_and(|m| m.contains(&agent.to_string())),
        "{doc}"
    );
    let ops = ops.lock().expect("ops").clone();
    let lists: Vec<&String> = ops
        .iter()
        .filter(|o| o.starts_with("sandbox_list"))
        .collect();
    assert_eq!(
        lists,
        [
            "sandbox_list_flagged",
            "sandbox_list",
            "sandbox_list_flagged",
            "sandbox_list"
        ],
        "{ops:?}"
    );
}
