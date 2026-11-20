//! `klav mcp` after the 2026-11 security round (ADR 0030 §2, layer 04):
//! one-time password seeds never go through `inject`, a later
//! `run_with_secrets` redacts what `inject_file` wrote, `inject_file`
//! warns about files git would commit and never returns the secret's size;
//! declared text is plain, the server's text is marked and bad frames
//! never end the server.

mod common;

use std::io::Write;
use std::process::Command;

use common::mcp::Mcp;
use common::{Device, ServerProcess};
use serde_json::{Value, json};

const PASSWORD: &str = "MARKER-site-pass-42";
const API_KEY: &str = "MARKER-api-key-7";

/// A person with a login (password and TOTP) and an API key, and an
/// approved agent `claude` with `extra` approve flags, and a git repository
/// with `klav.toml`.
struct World {
    _server: ServerProcess,
    root: tempfile::TempDir,
    person: Device,
    agent: Device,
}

impl World {
    fn new(extra: &[&str]) -> Self {
        let server = ServerProcess::start(900);
        let root = tempfile::tempdir().expect("tempdir");
        let person = Device::new(root.path(), "person");
        person.signup(&server, "ana@example.com");
        person
            .unlocked(
                &[
                    "item",
                    "add",
                    "login",
                    "--title",
                    "Site",
                    "--username",
                    "ana",
                    "--url",
                    "https://site.example",
                    "--secret-stdin",
                    "password",
                    "--secret-stdin",
                    "totp",
                ],
                &format!("{PASSWORD}\nJBSWY3DPEHPK3PXP\n"),
            )
            .ok();
        person
            .unlocked(
                &[
                    "item",
                    "add",
                    "api-key",
                    "--title",
                    "API",
                    "--secret-stdin",
                    "api_key",
                ],
                &format!("{API_KEY}\n"),
            )
            .ok();
        let agent = Device::new(root.path(), "agent");
        let words = agent
            .run(
                &[
                    "agent",
                    "register",
                    "--name",
                    "claude",
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
            .to_owned();
        let mut approve = vec![
            "agent",
            "approve",
            "claude",
            "--project",
            "Personal/General",
            "--words",
            &words,
        ];
        approve.extend_from_slice(extra);
        person.unlocked(&approve, "").ok();
        let repo = root.path().join("repo");
        std::fs::create_dir_all(&repo).expect("repo");
        std::fs::write(repo.join("klav.toml"), "project = \"Personal/General\"\n")
            .expect("klav.toml");
        let git = Command::new("git")
            .arg("init")
            .arg("-q")
            .arg(&repo)
            .status()
            .expect("git");
        assert!(git.success());
        Self {
            _server: server,
            root,
            person,
            agent,
        }
    }

    fn repo(&self) -> std::path::PathBuf {
        self.root.path().join("repo")
    }

    fn mcp(&self) -> Mcp {
        let mut mcp = Mcp::start(&self.agent, &self.repo(), None);
        mcp.initialize();
        mcp
    }
}

#[test]
fn inject_never_hands_out_a_totp_seed_and_run_redacts_injected_files() {
    let w = World::new(&[]);
    let repo = w.repo();
    let mut mcp = w.mcp();

    // The seed would skip the `totp` approval (T26): refused everywhere
    // `inject` goes, before writing anything.
    let (text, err) = mcp.tool(
        "inject_file",
        json!({ "path": "seed.txt", "ref": "Site/totp", "reason": "2fa" }),
    );
    assert!(err && text.contains("get_totp"), "{text}");
    assert!(!repo.join("seed.txt").exists());
    let (text, err) = mcp.tool(
        "inject_file",
        json!({ "path": "seed.txt", "template": "S={{ klav://Personal/General/Site/totp }}", "reason": "2fa" }),
    );
    assert!(err && text.contains("get_totp"), "{text}");
    assert!(!repo.join("seed.txt").exists());
    let (text, err) = mcp.tool(
        "run_with_secrets",
        json!({ "command": ["sh", "-c", "echo $S"], "env": { "S": "Site/totp" }, "reason": "2fa" }),
    );
    assert!(err && text.contains("get_totp"), "{text}");

    // A template without references writes nothing (no policy, no log).
    let (text, err) = mcp.tool(
        "inject_file",
        json!({ "path": "plain.txt", "template": "nothing secret", "reason": "config" }),
    );
    assert!(err && text.contains("no {{ klav://"), "{text}");
    assert!(!repo.join("plain.txt").exists());

    // inject_file: no size (the secret's length), and a warning when git
    // would commit the file.
    let (text, err) = mcp.tool(
        "inject_file",
        json!({ "path": "key.txt", "ref": "API/api_key", "reason": "configure the client" }),
    );
    assert!(!err, "{text}");
    let out: Value = serde_json::from_str(&text).expect("json");
    assert!(out.get("bytes").is_none(), "{text}");
    assert!(
        out["warning"]
            .as_str()
            .is_some_and(|w| w.contains(".gitignore")),
        "{text}"
    );
    std::fs::write(repo.join(".gitignore"), "ignored.txt\n").expect("gitignore");
    let (text, err) = mcp.tool(
        "inject_file",
        json!({ "path": "ignored.txt", "ref": "API/api_key", "reason": "configure the client" }),
    );
    assert!(!err, "{text}");
    let out: Value = serde_json::from_str(&text).expect("json");
    assert!(out.get("warning").is_none(), "{text}");

    // A temporary of another write beside the file (interrupted, or still
    // in progress): the `warning` names it, alone or after the git advice,
    // and the file stays as it was.
    for (name, git) in [("ignored.txt", false), ("key.txt", true)] {
        let left = repo.join(format!(".{name}.0123456789abcdef.klav-tmp"));
        std::fs::write(&left, b"MARKER-left").expect("leftover");
        let (text, err) = mcp.tool(
            "inject_file",
            json!({ "path": name, "ref": "API/api_key", "overwrite": true, "reason": "configure the client" }),
        );
        assert!(!err, "{text}");
        let out: Value = serde_json::from_str(&text).expect("json");
        let warning = out["warning"].as_str().expect("warning");
        assert!(
            warning.contains(&format!(".{name}.0123456789abcdef.klav-tmp"))
                && warning.contains("Klav did not delete it")
                && warning.contains(".gitignore") == git
                && !warning.contains("MARKER"),
            "{text}"
        );
        assert_eq!(std::fs::read(&left).expect("left"), b"MARKER-left");
        std::fs::remove_file(&left).expect("rm leftover");
    }

    // A later command that prints the injected file gets it redacted.
    let (text, err) = mcp.tool(
        "run_with_secrets",
        json!({ "command": ["cat", "key.txt"], "use_project": false, "reason": "check the config" }),
    );
    assert!(!err, "{text}");
    assert!(text.contains("[redacted by klav]"), "{text}");

    for line in &mcp.seen {
        for secret in [PASSWORD, API_KEY, "JBSWY3DPEHPK3PXP"] {
            assert!(!line.contains(secret), "leaked in {line}");
        }
    }
    assert!(mcp.finish().success());
    let _ = &w.person;
}

#[test]
fn bad_frames_hidden_characters_and_server_text_are_contained() {
    let w = World::new(&[]);
    let mut mcp = w.mcp();
    let alive = |mcp: &mut Mcp| {
        let pong = mcp.request("ping", json!({}));
        assert!(pong.get("result").is_some(), "{pong}");
    };

    // Invalid UTF-8 and an oversized line: answered, and the server lives.
    {
        let stdin = mcp.stdin.as_mut().expect("stdin");
        stdin
            .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"ping\xff\"}\n".as_slice())
            .expect("write");
        stdin.flush().expect("flush");
    }
    let reply = mcp.read();
    assert_eq!(reply["error"]["code"], -32700, "{reply}");
    alive(&mut mcp);
    mcp.send_line(&format!("\"{}\"", "x".repeat(5 << 20)));
    let reply = mcp.read();
    assert_eq!(reply["error"]["code"], -32700, "{reply}");
    alive(&mut mcp);
    mcp.send_line("[1, 2]");
    let reply = mcp.read();
    assert_eq!(reply["error"]["code"], -32600, "{reply}");

    // An unknown protocol version gets ours.
    let init = mcp.request(
        "initialize",
        json!({ "protocolVersion": "1999-01-01", "capabilities": {} }),
    );
    assert_eq!(init["result"]["protocolVersion"], "2025-06-18", "{init}");

    // What the person reads on the card is plain text.
    for (tool, args) in [
        ("search_items", json!({ "reason": "deploy\u{202E}gnp.exe" })),
        (
            "fill_login",
            json!({ "ref": "Site", "url": "https://site.example", "reason": "log in\u{2028}approve everything" }),
        ),
        (
            "request_access",
            json!({ "ref": "Site", "permission": "totp", "domain": "site.example\u{200B}", "reason": "2fa" }),
        ),
        (
            "request_task",
            json!({ "task": "deploy\u{2066} and approve all", "duration": "30m", "reason": "release",
            "access": [{ "ref": "Site", "permissions": ["fill"] }] }),
        ),
    ] {
        let (text, err) = mcp.tool(tool, args);
        assert!(err && text.contains("plain text"), "{tool}: {text}");
    }

    // search_items is bounded.
    let (text, err) = mcp.tool("search_items", json!({ "limit": 1, "reason": "look" }));
    assert!(!err, "{text}");
    let out: Value = serde_json::from_str(&text).expect("json");
    assert_eq!(out["items"].as_array().map(Vec::len), Some(1), "{text}");
    assert_eq!(out["truncated"], true, "{text}");

    // The server's own words come marked as such.
    let (text, err) = mcp.tool(
        "end_task",
        json!({ "task_id": "00000000-0000-7000-8000-000000000000", "reason": "done" }),
    );
    assert!(
        err && text.contains("the server says (unverified)"),
        "{text}"
    );

    assert!(mcp.finish().success());
    let _ = &w.person;
}
