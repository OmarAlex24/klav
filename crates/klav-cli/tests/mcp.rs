//! `klav mcp` over its stdio pipes: JSON-RPC only on stdout, metadata
//! instead of values, `reveal` denied by default, files only inside the
//! working directory, command output redacted, `ask` pending.

mod common;

use common::mcp::Mcp;
use common::{Device, ServerProcess};
use serde_json::{Value, json};

const PASSWORD: &str = "MARKER-site-pass-42";
const API_KEY: &str = "MARKER-api-key-7";

#[test]
fn the_mcp_server_hands_actions_not_values() {
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
    person
        .unlocked(
            &[
                "agent",
                "approve",
                "claude",
                "--project",
                "Personal/General",
                "--words",
                &words,
            ],
            "",
        )
        .ok();
    let repo = root.path().join("repo");
    std::fs::create_dir_all(&repo).expect("repo");
    std::fs::write(
        repo.join("klav.toml"),
        "project = \"Personal/General\"\n\n[env]\nAPI_KEY = \"API/api_key\"\n",
    )
    .expect("klav.toml");

    let mut mcp = Mcp::start(&agent, &repo, None);
    let init = mcp.initialize();
    assert_eq!(init["result"]["protocolVersion"], "2025-06-18");
    assert!(init["result"]["capabilities"]["tools"].is_object());
    assert_eq!(mcp.request("ping", json!({}))["result"], json!({}));
    let tools = mcp.request("tools/list", json!({}));
    let tools = tools["result"]["tools"].as_array().expect("tools").clone();
    let names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();
    for wanted in [
        "search_items",
        "get_item",
        "fill_login",
        "fill_card",
        "run_with_secrets",
        "inject_file",
        "get_totp",
        "reveal",
        "create_item",
        "update_item",
        "delete_item",
        "request_access",
        "change_password_url",
        "rotate_password",
        "rotate_confirm",
        "rotate_cancel",
        "passkey_sign_in",
        "request_secret",
        "get_secret_request",
    ] {
        assert!(names.contains(&wanted), "{wanted} missing");
    }
    // Every tool takes a reason, except reading the agent's own tasks
    // (ADR 0021 §7: `get_task(task_id)`, `list_tasks()`) or its own secret
    // request (ADR 0046: `get_secret_request(request_id)`).
    assert!(
        tools
            .iter()
            .filter(|t| !matches!(
                t["name"].as_str(),
                Some("get_task" | "list_tasks" | "get_secret_request")
            ))
            .all(|t| {
                t["inputSchema"]["required"]
                    .as_array()
                    .is_some_and(|r| r.contains(&json!("reason")))
            })
    );
    assert_eq!(mcp.request("nope", json!({}))["error"]["code"], -32601);
    mcp.send_line("not json");
    assert_eq!(mcp.read()["error"]["code"], -32700);

    // Metadata only.
    let (text, err) = mcp.tool(
        "search_items",
        json!({ "query": "site", "reason": "find the login" }),
    );
    assert!(!err, "{text}");
    assert!(text.contains("klav://Personal/General/Site"), "{text}");
    let (text, err) = mcp.tool(
        "get_item",
        json!({ "ref": "Site", "reason": "see its fields" }),
    );
    assert!(!err && text.contains("password"), "{text}");
    let (text, err) = mcp.tool("get_item", json!({ "ref": "Site" }));
    assert!(err && text.contains("reason"), "{text}");

    // reveal is denied by default; the extension target needs the person's
    // browser attached to klavd, and asks for nothing before it is.
    let (text, err) = mcp.tool(
        "reveal",
        json!({ "ref": "Site/password", "reason": "curious" }),
    );
    assert!(err && text.contains("denies"), "{text}");
    let (text, err) = mcp.tool(
        "fill_login",
        json!({ "ref": "Site", "target": "extension", "reason": "log in" }),
    );
    assert!(err && text.contains("browser"), "{text}");

    // Files only inside the working directory; output redacted.
    let (text, err) = mcp.tool(
        "inject_file",
        json!({ "path": "../escape.txt", "ref": "API/api_key", "reason": "cfg" }),
    );
    assert!(err && text.contains("outside"), "{text}");
    let (text, err) = mcp.tool(
        "inject_file",
        json!({ "path": "key.txt", "ref": "API/api_key", "reason": "configure the client" }),
    );
    assert!(!err, "{text}");
    assert_eq!(
        std::fs::read_to_string(repo.join("key.txt")).expect("file"),
        API_KEY
    );
    assert_eq!(common::mode(&repo.join("key.txt")), 0o600);
    // A file with a TTL does not outlive the session.
    let (text, err) = mcp.tool(
        "inject_file",
        json!({ "path": "ttl.txt", "ref": "API/api_key", "ttl_seconds": 600, "reason": "configure the client for a while" }),
    );
    assert!(!err, "{text}");
    assert!(repo.join("ttl.txt").exists());
    let (text, err) = mcp.tool(
        "run_with_secrets",
        json!({ "command": ["sh", "-c", "echo key=$API_KEY"], "reason": "run the tests" }),
    );
    assert!(!err, "{text}");
    assert!(text.contains("key=[redacted by klav]"), "{text}");

    // Writes: create is allowed; update and totp ask (pending with wait 0).
    let (text, err) = mcp.tool(
        "create_item",
        json!({ "type": "api_key", "title": "New", "fields": { "api_key": "MARKER-new" }, "reason": "store the new key" }),
    );
    assert!(!err, "{text}");
    // A second item with the same title would make references ambiguous.
    let (text, err) = mcp.tool(
        "create_item",
        json!({ "type": "api_key", "title": "new", "fields": { "api_key": "MARKER-new-2" }, "reason": "store the key again" }),
    );
    assert!(
        err && text.contains("already exists") && text.contains("update_item"),
        "{text}"
    );
    // Renaming onto another item's title is refused too, before asking the
    // person anything, even if the agent asks to allow it.
    let (text, err) = mcp.tool(
        "update_item",
        json!({ "ref": "New", "patch": { "title": "api", "allow_duplicate": true }, "reason": "rename it", "wait_seconds": 0 }),
    );
    assert!(
        err && text.contains("klav://Personal/General/API already exists")
            && !text.contains("approval"),
        "{text}"
    );
    let (text, err) = mcp.tool(
        "update_item",
        json!({ "ref": "New", "patch": { "add_tags": ["ci"] }, "reason": "tag it", "wait_seconds": 0 }),
    );
    assert!(err && text.contains("klav approval approve"), "{text}");
    // Approved for 5 minutes: the read and the write both go through.
    let pending = person.unlocked(&["approval", "list", "--json"], "").ok();
    let pending: Value = serde_json::from_str(&pending.stdout).expect("json");
    let id = pending[0]["id"].as_str().expect("id").to_owned();
    person
        .unlocked(&["approval", "approve", &id, "--for", "5m"], "")
        .ok();
    let (text, err) = mcp.tool(
        "update_item",
        json!({ "ref": "New", "patch": { "add_tags": ["ci"] }, "reason": "tag it" }),
    );
    assert!(!err, "{text}");
    assert!(text.contains("\"ci\""), "{text}");
    // The agent rotates the key. It cannot read or write the item's
    // password history (sealed with the vault key, ADR 0022 §3), so the
    // person's next edit fills it from the versions: both older keys.
    let (text, err) = mcp.tool(
        "update_item",
        json!({ "ref": "New", "patch": { "set": { "api_key": "MARKER-agent-rotated" } }, "reason": "rotate it" }),
    );
    assert!(!err, "{text}");
    person
        .unlocked(&["item", "edit", "New", "-g", "api_key"], "")
        .ok();
    let history = person
        .unlocked(&["item", "history", "New", "--json"], "")
        .ok();
    assert!(!history.stdout.contains("MARKER-"), "{}", history.stdout);
    let history: Value = serde_json::from_str(&history.stdout).expect("json");
    assert_eq!(
        history["entries"].as_array().map(Vec::len),
        Some(2),
        "{history}"
    );
    for (index, value) in [("0", "MARKER-agent-rotated"), ("1", "MARKER-new")] {
        let old = person
            .unlocked(&["item", "history", "New", "--reveal", index], "")
            .ok();
        assert_eq!(old.stdout.trim(), value);
    }
    // A site the agent adds waits for the person (ADR 0030 §7): `item get`
    // shows it apart, `item sites --confirm` makes it hers.
    let (text, err) = mcp.tool(
        "update_item",
        json!({ "ref": "New", "patch": { "add_urls": ["https://new.example"] }, "reason": "its console" }),
    );
    assert!(!err, "{text}");
    let shown = person.unlocked(&["item", "get", "New"], "").ok();
    assert!(
        shown
            .stdout
            .contains("sites added by claude (not confirmed, never filled): https://new.example"),
        "{}",
        shown.stdout
    );
    let sites = person
        .unlocked(&["item", "sites", "New", "--confirm"], "")
        .ok();
    assert!(
        sites.stdout.contains("urls:      https://new.example")
            && !sites.stdout.contains("added by"),
        "{}",
        sites.stdout
    );
    // A pending answer says what to run (ADR 0015 §5), and a retry gets
    // the same request.
    let (text, err) = mcp.tool(
        "get_totp",
        json!({ "ref": "Site", "reason": "2fa", "wait_seconds": 0 }),
    );
    assert!(err, "{text}");
    let pending: Value = serde_json::from_str(&text).expect("pending JSON");
    assert_eq!(pending["status"], "pending");
    let id = pending["pending_approval_id"]
        .as_str()
        .expect("id")
        .to_owned();
    assert!(pending["expires_at"].as_i64().is_some(), "{text}");
    assert_eq!(
        pending["approve_command"],
        format!("klav approval approve {id}")
    );
    let wait_command = pending["wait_command"].as_str().expect("wait_command");
    for part in [
        format!("approval wait {id}"),
        "--agent claude".to_owned(),
        "KLAV_HOME=".to_owned(),
        "--json".to_owned(),
    ] {
        assert!(wait_command.contains(&part), "{wait_command}");
    }
    assert!(
        pending["next"]
            .as_str()
            .is_some_and(|n| n.contains("approval_id") && n.contains("background")),
        "{text}"
    );
    let (text, _) = mcp.tool(
        "get_totp",
        json!({ "ref": "Site", "reason": "2fa again", "wait_seconds": 0 }),
    );
    let again: Value = serde_json::from_str(&text).expect("pending JSON");
    assert_eq!(again["pending_approval_id"], id.as_str());
    // A named approval for another action is refused before acting.
    let (text, err) = mcp.tool(
        "update_item",
        json!({ "ref": "New", "patch": { "add_tags": ["x"] }, "reason": "tag", "approval_id": id }),
    );
    assert!(err && text.contains("not for this action"), "{text}");
    // Approved after the call returned: the retry with approval_id gets
    // the code, once.
    person.unlocked(&["approval", "approve", &id], "").ok();
    let (text, err) = mcp.tool(
        "get_totp",
        json!({ "ref": "Site", "reason": "2fa", "approval_id": id }),
    );
    assert!(!err, "{text}");
    let code: Value = serde_json::from_str(&text).expect("json");
    assert_eq!(code["code"].as_str().map(str::len), Some(6), "{text}");
    let (text, err) = mcp.tool(
        "get_totp",
        json!({ "ref": "Site", "reason": "2fa", "approval_id": id }),
    );
    assert!(err && text.contains("already used"), "{text}");
    let (text, err) = mcp.tool(
        "request_access",
        json!({ "ref": "Site", "permission": "reveal", "reason": "need it" }),
    );
    assert!(err && text.contains("klav agent approve claude"), "{text}");
    let (text, err) = mcp.tool("delete_item", json!({ "ref": "New", "reason": "clean up" }));
    assert!(err && text.contains("denies"), "{text}");

    // Nothing but JSON-RPC on stdout, and no value in it.
    for line in &mcp.seen {
        for secret in [PASSWORD, API_KEY, "MARKER-new"] {
            assert!(!line.contains(secret), "leaked in {line}");
        }
    }
    assert!(mcp.finish().success());
    assert!(
        !repo.join("ttl.txt").exists(),
        "the TTL file survived the session"
    );

    // The person sees every action with its reason.
    let log = person
        .unlocked(&["log", "--agent", "claude", "--json"], "")
        .ok();
    let log: Value = serde_json::from_str(&log.stdout).expect("json");
    let reasons: Vec<&str> = log
        .as_array()
        .expect("array")
        .iter()
        .filter_map(|e| e["reason"].as_str())
        .collect();
    for reason in [
        "curious",
        "configure the client",
        "run the tests",
        "store the new key",
    ] {
        assert!(
            reasons.contains(&reason),
            "{reason} not logged: {reasons:?}"
        );
    }
}

/// ADR 0016: an agent with `inject` writes an attachment (an APNs `.p8`)
/// to a file with `inject_file` or `[files]`, and the content never comes
/// back to the LLM. The report only marks what was delivered.
#[test]
fn agents_inject_attachments_without_seeing_them() {
    const P8: &str = "-----BEGIN PRIVATE KEY-----\nMARKER-p8-content\n-----END PRIVATE KEY-----\n";
    const BINARY: &[u8] = &[0, 1, 2, 0xff, b'M', 0];
    let server = ServerProcess::start(900);
    let root = tempfile::tempdir().expect("tempdir");
    let person = Device::new(root.path(), "person");
    person.signup(&server, "ana@example.com");
    let p8 = root.path().join("AuthKey_TEST.p8");
    std::fs::write(&p8, P8).expect("p8");
    let bin = root.path().join("blob.bin");
    std::fs::write(&bin, BINARY).expect("bin");
    for (title, file) in [("APNs", &p8), ("Blob", &bin), ("Cert", &p8)] {
        person
            .unlocked(&["item", "add", "note", "--title", title], "")
            .ok();
        person
            .unlocked(
                &[
                    "item",
                    "attach",
                    title,
                    "key",
                    file.to_str().expect("utf-8"),
                ],
                "",
            )
            .ok();
    }
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
    person
        .unlocked(
            &[
                "agent",
                "approve",
                "claude",
                "--project",
                "Personal/General",
                "--words",
                &words,
            ],
            "",
        )
        .ok();
    let repo = root.path().join("repo");
    std::fs::create_dir_all(repo.join("secrets")).expect("repo");
    std::fs::write(
        repo.join("klav.toml"),
        "project = \"Personal/General\"\n\n[files]\n\"secrets/AuthKey.p8\" = \"APNs/key\"\n",
    )
    .expect("klav.toml");
    let mut mcp = Mcp::start(&agent, &repo, None);
    mcp.initialize();

    // The agent can tell an item has files, never what they hold.
    let (text, err) = mcp.tool(
        "get_item",
        json!({ "ref": "APNs", "reason": "see what the APNs item has" }),
    );
    assert!(!err, "{text}");
    let info: Value = serde_json::from_str(&text).expect("json");
    assert_eq!(info["item"]["attachments"], 1, "{text}");
    assert!(
        info["attachments_note"]
            .as_str()
            .is_some_and(|n| n.contains("inject_file")),
        "{text}"
    );

    // inject_file with ref: the exact bytes, 0600, and only the path back.
    let (text, err) = mcp.tool(
        "inject_file",
        json!({ "path": "AuthKey.p8", "ref": "APNs/key", "reason": "sign the APNs token" }),
    );
    assert!(!err, "{text}");
    assert_eq!(
        std::fs::read_to_string(repo.join("AuthKey.p8")).expect("p8"),
        P8
    );
    assert_eq!(common::mode(&repo.join("AuthKey.p8")), 0o600);
    let (text, err) = mcp.tool(
        "inject_file",
        json!({ "path": "blob.bin", "ref": "Blob/key", "reason": "the tool reads this file" }),
    );
    assert!(!err, "{text}");
    assert_eq!(std::fs::read(repo.join("blob.bin")).expect("bin"), BINARY);

    // Failures that can be known first ask for nothing.
    let accesses = |person: &Device| {
        let log = person
            .unlocked(&["log", "--agent", "claude", "--json"], "")
            .ok();
        let log: Value = serde_json::from_str(&log.stdout).expect("json");
        log.as_array()
            .expect("array")
            .iter()
            .filter(|e| e["action"] == "agent.access")
            .count()
    };
    let before = accesses(&person);
    let (text, err) = mcp.tool(
        "inject_file",
        json!({ "path": "AuthKey.p8", "ref": "Cert/key", "reason": "again" }),
    );
    assert!(err && text.contains("already exists"), "{text}");
    assert_eq!(accesses(&person), before);
    // A template cannot hold an attachment; a binary one is no variable.
    let (text, err) = mcp.tool(
        "inject_file",
        json!({ "path": "cert.env", "template": "K={{ klav://Personal/General/Cert/key }}\n", "reason": "config" }),
    );
    assert!(err && text.contains("is an attachment"), "{text}");
    assert!(!repo.join("cert.env").exists());
    let (text, err) = mcp.tool(
        "run_with_secrets",
        json!({ "command": ["true"], "env": { "K": "Blob/key" }, "use_project": false, "reason": "x" }),
    );
    assert!(err && text.contains("binary attachment"), "{text}");

    // [files] from klav.toml: written for the command, removed after, and
    // its text redacted if the command prints it.
    let (text, err) = mcp.tool(
        "run_with_secrets",
        json!({ "command": ["cat", "secrets/AuthKey.p8"], "reason": "check the key file is there" }),
    );
    assert!(!err, "{text}");
    let out: Value = serde_json::from_str(&text).expect("json");
    assert_eq!(out["code"], 0, "{text}");
    assert!(
        out["stdout"]
            .as_str()
            .is_some_and(|s| s.contains("[redacted by klav]")),
        "{text}"
    );
    assert!(!repo.join("secrets/AuthKey.p8").exists());

    for line in &mcp.seen {
        assert!(!line.contains("MARKER-p8-content"), "leaked in {line}");
    }
    assert!(mcp.finish().success());

    // The log says which attachments were delivered; the report marks APNs
    // and Blob (files delivered), not Cert (its details hold no value and
    // no file was delivered).
    let log = person
        .unlocked(&["log", "--agent", "claude", "--json"], "")
        .ok();
    let log: Value = serde_json::from_str(&log.stdout).expect("json");
    assert!(
        log.as_array()
            .expect("array")
            .iter()
            .any(|e| e["attachments"].as_array().is_some_and(|a| a.len() == 1)),
        "{log}"
    );
    let shown = person
        .unlocked(&["agent", "show", "claude", "--json"], "")
        .ok();
    let shown: Value = serde_json::from_str(&shown.stdout).expect("json");
    let row = |title: &str| {
        shown["items"]
            .as_array()
            .expect("items")
            .iter()
            .find(|i| {
                i["reference"]
                    .as_str()
                    .is_some_and(|r| r.ends_with(&format!("/{title}")))
            })
            .cloned()
            .unwrap_or(Value::Null)
    };
    assert_eq!(row("APNs")["secret"], true, "{shown}");
    assert!(row("APNs")["attachments"].as_u64() >= Some(2), "{shown}");
    assert_eq!(row("Blob")["secret"], true, "{shown}");
    assert_eq!(row("Cert")["secret"], false, "{shown}");
    let verified = person.unlocked(&["log", "verify"], "");
    assert_eq!(verified.code, 0, "{}", verified.stderr);
    drop(server);
}
