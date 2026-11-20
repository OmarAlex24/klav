//! Phase 4 end to end, with the real binaries only: `klav-server`
//! (SQLite), the person's `klav`, an agent's `klav` (its own
//! `KLAV_HOME`), `klav mcp`, a headless Chrome and a tiny login site.
//!
//! register with 6 words → approve with a project → the agent logs in
//! through MCP `fill_login` with `submit` on an `sdk:` session (the SDK
//! types over CDP and submits the form) and the password never reaches the
//! agent → `reveal` is denied → a TOTP
//! that needs approval waits until the person approves it; one approved
//! after the call returned wakes a background `klav approval wait` and the
//! retry with `approval_id` gets the code → an APNs `.p8` attachment goes
//! to a file with `inject_file` and to `[files]` with `run_with_secrets`
//! (ADR 0016) without its content reaching the agent → the audit log
//! verifies → revocation blocks the agent at once, and the "what it saw"
//! report lists the login it filled and the attachment it received.

mod common;

use common::browser::{Chrome, LoginSite, chrome_or_skip, wait_title};
use common::mcp::Mcp;
use common::{Device, ServerProcess, wait_until};
use serde_json::{Value, json};

const PASSWORD: &str = "MARKER-e2e-site-pass-Zx8";
const API_KEY: &str = "sk_live_MARKER_e2e_agent_31";
const SEED: &str = "JBSWY3DPEHPK3PXP";
const P8_MARKER: &str = "MARKER-e2e-apns-p8";

fn json_out(device: &Device, args: &[&str]) -> Value {
    let out = device.unlocked(args, "").ok();
    serde_json::from_str(&out.stdout).expect("json")
}

#[tokio::test(flavor = "multi_thread")]
async fn phase_4_end_to_end() {
    let Some(binary) = chrome_or_skip("phase_4_end_to_end") else {
        return;
    };
    let site = LoginSite::start(PASSWORD);
    let server = ServerProcess::start(900);
    let root = tempfile::tempdir().expect("tempdir");

    // The person: a login for the site (with a TOTP seed) and an API key.
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
                &site.url,
                "--secret-stdin",
                "password",
                "--secret-stdin",
                "totp",
            ],
            &format!("{PASSWORD}\n{SEED}\n"),
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
    let p8 = root.path().join("AuthKey_E2E.p8");
    std::fs::write(
        &p8,
        format!("-----BEGIN PRIVATE KEY-----\n{P8_MARKER}\n-----END PRIVATE KEY-----\n"),
    )
    .expect("p8");
    person
        .unlocked(&["item", "add", "note", "--title", "APNs"], "")
        .ok();
    person
        .unlocked(
            &["item", "attach", "APNs", "key", p8.to_str().expect("utf-8")],
            "",
        )
        .ok();
    let p8_bytes = std::fs::read(&p8).expect("p8");
    std::fs::remove_file(&p8).expect("rm p8");

    // The agent registers; the person compares the 6 words and approves.
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
    assert_eq!(words.split_whitespace().count(), 6, "{words}");
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

    // The agent's runtime registers its browser as `sdk:browser`.
    let chrome = Chrome::launch(&binary, &site, &site.url).await;
    agent
        .run(
            &[
                "agent",
                "browser",
                "register",
                "browser",
                "--cdp",
                &chrome.endpoint,
            ],
            "",
        )
        .ok();

    let repo = root.path().join("repo");
    std::fs::create_dir_all(repo.join("secrets")).expect("repo");
    std::fs::write(
        repo.join("klav.toml"),
        "[files]\n\"secrets/AuthKey.p8\" = \"klav://Personal/General/APNs/key\"\n",
    )
    .expect("klav.toml");
    let stderr_log = root.path().join("mcp-stderr.log");
    let mut mcp = Mcp::start(&agent, &repo, Some(&stderr_log));
    mcp.initialize();

    // Log in: the agent finds the login and has it typed into the page.
    let (text, err) = mcp.tool(
        "search_items",
        json!({ "query": "site", "reason": "find the login for the site" }),
    );
    assert!(
        !err && text.contains("klav://Personal/General/Site"),
        "{text}"
    );
    // `submit: true` sends the form too, and says where the page went.
    let (text, err) = mcp.tool(
        "fill_login",
        json!({ "url": site.url, "target": "sdk:browser", "submit": true, "reason": "log in to download the report" }),
    );
    assert!(!err, "{text}");
    let filled: Value = serde_json::from_str(&text).expect("json");
    assert_eq!(filled["filled"], json!(["username", "password"]), "{text}");
    assert_eq!(filled["submitted"], true, "{text}");
    assert_eq!(filled["navigated"], true, "{text}");
    // Only the origin: a page's path and query may carry tokens (G7).
    assert_eq!(
        filled["url_after"].as_str(),
        Some(site.url.trim_end_matches("/login")),
        "{text}"
    );
    assert!(
        wait_title(&chrome.endpoint, "Welcome").await,
        "login failed"
    );
    assert_eq!(
        site.received
            .lock()
            .expect("lock")
            .first()
            .map(String::as_str),
        Some(format!("username=ana&password={PASSWORD}").as_str())
    );

    // The value itself is denied by default.
    let (text, err) = mcp.tool(
        "reveal",
        json!({ "ref": "klav://Personal/General/Site/password", "reason": "show it" }),
    );
    assert!(err && text.contains("denies"), "{text}");

    // A TOTP asks the person: the call waits until they approve it.
    let id = mcp.send(
        "tools/call",
        json!({ "name": "get_totp", "arguments": {
            "ref": "klav://Personal/General/Site",
            "reason": "second factor for the site",
            "wait_seconds": 60,
        } }),
    );
    let mut approval = String::new();
    assert!(
        wait_until(30, || {
            let out = person.unlocked(&["approval", "list", "--json"], "");
            let list: Value = serde_json::from_str(&out.stdout).unwrap_or_default();
            match list.as_array().and_then(|a| a.first()) {
                Some(a) => {
                    assert_eq!(a["reason"], "second factor for the site");
                    assert_eq!(a["permission"], "totp");
                    approval = a["id"].as_str().unwrap_or_default().to_owned();
                    true
                }
                None => false,
            }
        }),
        "the request never showed up"
    );
    person
        .unlocked(&["approval", "approve", &approval], "")
        .ok();
    let reply = mcp.read();
    assert_eq!(reply["id"], id);
    let (text, err) = Mcp::tool_reply(&reply);
    assert!(!err, "{text}");
    let code: Value = serde_json::from_str(&text).expect("json");
    assert_eq!(code["code"].as_str().map(str::len), Some(6), "{text}");

    // ADR 0015: nobody approves within the call. The agent runs the wait
    // command it got in the background, the person approves, the waiter
    // exits 0 and the retry with approval_id returns the code.
    let (text, err) = mcp.tool(
        "get_totp",
        json!({ "ref": "klav://Personal/General/Site", "reason": "second factor again", "wait_seconds": 1 }),
    );
    assert!(err, "{text}");
    let pending: Value = serde_json::from_str(&text).expect("pending JSON");
    let approval = pending["pending_approval_id"]
        .as_str()
        .expect("id")
        .to_owned();
    let waiter = std::process::Command::new("sh")
        .arg("-c")
        .arg(pending["wait_command"].as_str().expect("wait_command"))
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("background waiter");
    std::thread::sleep(std::time::Duration::from_millis(500));
    person
        .unlocked(&["approval", "approve", &approval], "")
        .ok();
    let woken = waiter.wait_with_output().expect("waiter");
    let woken_out = String::from_utf8_lossy(&woken.stdout).into_owned();
    let woken_err = String::from_utf8_lossy(&woken.stderr).into_owned();
    assert!(woken.status.success(), "{woken_out} {woken_err}");
    let line: Value = serde_json::from_str(&woken_out).expect("one JSON line");
    assert_eq!(line["status"], "approved");
    let (text, err) = mcp.tool(
        "get_totp",
        json!({ "ref": "klav://Personal/General/Site", "reason": "second factor again", "approval_id": approval }),
    );
    assert!(!err, "{text}");
    let code: Value = serde_json::from_str(&text).expect("json");
    assert_eq!(code["code"].as_str().map(str::len), Some(6), "{text}");
    for secret in [PASSWORD, API_KEY, SEED] {
        assert!(
            !woken_out.contains(secret) && !woken_err.contains(secret),
            "leaked by the waiter"
        );
    }

    // ADR 0016: the APNs key goes to a file the agent's tool reads; the
    // agent only learns the path.
    let (text, err) = mcp.tool(
        "inject_file",
        json!({ "path": "AuthKey.p8", "ref": "klav://Personal/General/APNs/key", "ttl_seconds": 600, "reason": "sign the APNs token for the push test" }),
    );
    assert!(!err, "{text}");
    assert_eq!(
        std::fs::read(repo.join("AuthKey.p8")).expect("p8"),
        p8_bytes
    );
    let (text, err) = mcp.tool(
        "run_with_secrets",
        json!({ "command": ["sh", "-c", "wc -c < secrets/AuthKey.p8; cat secrets/AuthKey.p8"], "reason": "send the test push with the APNs key" }),
    );
    assert!(!err, "{text}");
    let ran: Value = serde_json::from_str(&text).expect("json");
    let stdout = ran["stdout"].as_str().unwrap_or_default();
    assert!(
        stdout.contains(&p8_bytes.len().to_string()) && stdout.contains("[redacted by klav]"),
        "{text}"
    );
    assert!(!repo.join("secrets/AuthKey.p8").exists());

    // Nothing the agent saw holds a secret value.
    for line in &mcp.seen {
        for secret in [PASSWORD, API_KEY, SEED, P8_MARKER] {
            assert!(!line.contains(secret), "leaked in {line}");
        }
    }
    assert!(mcp.finish().success());
    assert!(
        !repo.join("AuthKey.p8").exists(),
        "the injected key outlived the session"
    );
    let stderr = std::fs::read_to_string(&stderr_log).expect("stderr");
    for secret in [PASSWORD, API_KEY, SEED, P8_MARKER] {
        assert!(!stderr.contains(secret), "leaked in stderr: {stderr}");
    }

    // The person's log has every action with its reason, and it verifies.
    let log = json_out(&person, &["log", "--agent", "claude", "--json"]);
    let log = log.as_array().expect("array");
    let find = |permission: &str| {
        log.iter()
            .find(|e| e["permission"] == permission)
            .unwrap_or_else(|| panic!("no {permission} event: {log:?}"))
    };
    assert_eq!(find("fill")["reason"], "log in to download the report");
    assert_eq!(find("reveal")["outcome"], "deny");
    for reason in ["second factor for the site", "second factor again"] {
        assert!(
            log.iter()
                .any(|e| e["permission"] == "totp" && e["reason"] == reason),
            "{reason} not logged"
        );
    }
    let verified = json_out(&person, &["log", "verify", "--json"]);
    assert!(
        verified["agent_signatures"].as_u64() > Some(0),
        "{verified}"
    );

    // Revocation blocks the agent at once; the report lists what it filled.
    let report = json_out(&person, &["agent", "revoke", "claude", "--yes", "--json"]);
    let items = report["exposure"]["items"].as_array().expect("items");
    let seen = items
        .iter()
        .find(|i| i["reference"] == "klav://Personal/General/Site")
        .unwrap_or_else(|| panic!("the filled login is not listed: {report}"));
    assert_eq!(seen["secret"], true);
    assert!(
        seen["permissions"]
            .as_array()
            .is_some_and(|p| p.contains(&json!("fill"))),
        "{seen}"
    );
    let apns = items
        .iter()
        .find(|i| i["reference"] == "klav://Personal/General/APNs")
        .unwrap_or_else(|| panic!("the attachment is not listed: {report}"));
    assert_eq!(apns["secret"], true, "{apns}");
    assert_eq!(apns["attachments"], 2, "{apns}");
    let blocked = agent.run(
        &[
            "agent",
            "fill",
            "klav://Personal/General/Site",
            "--session",
            "browser",
            "--reason",
            "log in again",
        ],
        "",
    );
    assert_ne!(blocked.code, 0);
    let mut mcp = Mcp::start(&agent, &repo, None);
    mcp.initialize();
    let (text, err) = mcp.tool(
        "search_items",
        json!({ "query": "site", "reason": "find the login again" }),
    );
    assert!(err, "a revoked agent still works: {text}");
    assert!(mcp.finish().success());
    let verified = json_out(&person, &["log", "verify", "--json"]);
    assert!(verified["events"].as_u64() > Some(0), "{verified}");
}
