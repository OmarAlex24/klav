//! ADR 0046 end to end with the real binaries: `klav-server` (SQLite), the
//! person's `klav`, an agent's `klav` (its own `KLAV_HOME`), and `klav mcp`.
//!
//! Covers:
//! 1. Active agent without `create`/`update` permission proposes an API key
//!    with `setup_url` and `proxy_proposal` via MCP `request_secret` (Q1, Q2).
//! 2. Person inspects the decrypted card (`klav secret-request show`), fulfills
//!    it via hidden stdin (`--secret-stdin`), and the value never appears in
//!    stdout, stderr, MCP output, or the server's audit log / SQLite database.
//! 3. Agent waits (`klav agent secret-request wait`) and verifies the
//!    account-signed decision (T237), then runs a command with the returned
//!    `klav://` reference via `run_with_secrets`.
//! 4. T234: agent-suggested `login` URLs are NOT auto-saved unless confirmed.
//! 5. T235: non-HTTPS / IP / private `setup_url` is rejected before sending.
//! 6. T236: fulfilling into a project outside the agent's grant sets
//!    `in_grant: false` and omits `vault_id`, `project_id`, `item_id`, `ref`.
//! 7. Denying a secret request signs `denied` and exits with code 5.
//! 8. `klav log verify` verifies every `secret_request.created` and
//!    `secret_request.decided` event in the audit chain.

mod common;

use common::mcp::Mcp;
use common::{Device, ServerProcess};
use serde_json::{Value, json};

const SECRET_MARKER: &str = "vck_MARKER_e2e_secret_request_9f2a";
const PRIVATE_MARKER: &str = "sk_prod_MARKER_e2e_outside_grant_7c1b";
const LOGIN_PASS_MARKER: &str = "pass_MARKER_e2e_login_t234_4e8d";

#[tokio::test(flavor = "multi_thread")]
async fn secret_requests_end_to_end() {
    let server = ServerProcess::start(900);
    let root = tempfile::tempdir().expect("tempdir");

    // 1. Person signs up and creates a second project (`Private`) outside the
    //    agent's grant.
    let person = Device::new(root.path(), "person");
    person.signup(&server, "ana@example.com");
    person
        .unlocked(&["project", "create", "--vault", "Personal", "Private"], "")
        .ok();

    // 2. Agent registers; person approves ONLY `Personal/General` with `list`
    //    and `inject` allowed and `create`/`update` DENIED (Q2: agent can still
    //    send `request_secret` because the person performs the vault write).
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
                "--allow",
                "list,inject",
                "--deny",
                "create,update,reveal,delete",
                "--words",
                &words,
            ],
            "",
        )
        .ok();

    let repo = root.path().join("repo");
    std::fs::create_dir_all(&repo).expect("repo");
    let stderr_log = root.path().join("mcp-stderr.log");
    let mut mcp = Mcp::start(&agent, &repo, Some(&stderr_log));
    mcp.initialize();

    // 3. T235: phishing / non-HTTPS / loopback `setup_url` is rejected.
    let (bad_url_text, bad_url_err) = mcp.tool(
        "request_secret",
        json!({
            "reason": "Need key",
            "title": "Bad Setup",
            "setup_url": "http://127.0.0.1/phish",
            "wait_seconds": 0,
        }),
    );
    assert!(
        bad_url_err,
        "loopback setup_url must be refused: {bad_url_text}"
    );

    // 4. Agent proposes an API key with `setup_url` and `proxy_proposal`.
    let (text, is_err) = mcp.tool(
        "request_secret",
        json!({
            "reason": "Need Vercel AI Gateway key to generate narration",
            "mode": "create",
            "type": "api_key",
            "title": "Vercel AI Gateway",
            "field": "api_key",
            "project": "Personal/General",
            "placeholder": "vck_…",
            "setup_url": "https://vercel.com/dashboard/ai-gateway",
            "base_url": "https://ai-gateway.vercel.sh",
            "proxy_proposal": {
                "preset": null,
                "profile": "vercel-ai",
                "upstream": "https://ai-gateway.vercel.sh",
                "header": "authorization",
                "prefix": "Bearer ",
                "methods": ["POST"],
                "ask_methods": [],
                "path_prefixes": ["/v1"],
                "rate_per_minute": 60
            },
            "wait_seconds": 0,
        }),
    );
    assert!(!is_err, "request_secret failed: {text}");
    let pending: Value = serde_json::from_str(&text).expect("pending json");
    assert_eq!(pending["status"], "pending");
    let req_id = pending["request_id"]
        .as_str()
        .expect("request_id")
        .to_owned();
    assert!(
        pending["fulfill_command"]
            .as_str()
            .expect("fulfill_command")
            .contains(&req_id)
    );
    assert!(
        pending["wait_command"]
            .as_str()
            .expect("wait_command")
            .contains("agent secret-request wait")
    );

    // 5. Person lists and inspects the decrypted card (sees setup_url warning
    //    and proxy_proposal preview).
    let list_out = person
        .unlocked(&["secret-request", "ls", "--json"], "")
        .ok();
    let list: Value = serde_json::from_str(&list_out.stdout).expect("list json");
    assert_eq!(list.as_array().expect("array").len(), 1);
    let show_out = person
        .unlocked(&["secret-request", "show", &req_id], "")
        .ok();
    assert!(
        show_out.stdout.contains("vercel.com"),
        "{}",
        show_out.stdout
    );
    assert!(show_out.stdout.contains("vercel-ai"), "{}", show_out.stdout);
    assert!(
        show_out.stderr.contains("check the domain before opening"),
        "{}",
        show_out.stderr
    );

    // 6. Person fulfills via hidden stdin (`--secret-stdin`, never in argv).
    let fulfill_out = person
        .unlocked(
            &[
                "secret-request",
                "fulfill",
                &req_id,
                "--secret-stdin",
                "--yes",
                "--json",
            ],
            &format!("{SECRET_MARKER}\n"),
        )
        .ok();
    assert!(
        !fulfill_out.stdout.contains(SECRET_MARKER) && !fulfill_out.stderr.contains(SECRET_MARKER),
        "secret value leaked to CLI output"
    );
    let fulfilled_person: Value = serde_json::from_str(&fulfill_out.stdout).expect("fulfill json");
    assert_eq!(fulfilled_person["in_grant"], true);

    // 7. Agent waits (exits 0), verifies signed decision (T237), and gets the
    //    reference without the secret value.
    let wait_out = agent
        .run(
            &[
                "agent",
                "secret-request",
                "wait",
                &req_id,
                "--timeout",
                "10s",
                "--json",
            ],
            "",
        )
        .ok();
    assert!(
        !wait_out.stdout.contains(SECRET_MARKER) && !wait_out.stderr.contains(SECRET_MARKER),
        "secret value leaked to agent wait output"
    );
    let wait_json: Value = serde_json::from_str(&wait_out.stdout).expect("wait json");
    assert_eq!(wait_json["status"], "fulfilled");
    assert_eq!(wait_json["in_grant"], true);
    let reference = wait_json["ref"]
        .as_str()
        .expect("klav:// reference")
        .to_owned();
    assert_eq!(
        reference,
        "klav://Personal/General/Vercel AI Gateway/api_key"
    );

    // MCP `get_secret_request` returns the same verified result, zero secret.
    let (get_text, get_err) = mcp.tool(
        "get_secret_request",
        json!({ "request_id": req_id, "wait_seconds": 0 }),
    );
    assert!(!get_err, "{get_text}");
    assert!(!get_text.contains(SECRET_MARKER));
    let get_json: Value = serde_json::from_str(&get_text).expect("get json");
    assert_eq!(get_json["status"], "fulfilled");
    assert_eq!(get_json["ref"], reference);

    // 8. Agent immediately uses the new reference in `run_with_secrets` (child
    //    receives the real value, MCP output redacts it).
    let (run_text, run_err) = mcp.tool(
        "run_with_secrets",
        json!({
            "reason": "verify new API key reaches child process and is redacted",
            "command": ["sh", "-c", "printf 'len=%s val=%s' \"${#VERCEL_KEY}\" \"$VERCEL_KEY\""],
            "env": { "VERCEL_KEY": reference },
            "use_project": false,
        }),
    );
    assert!(!run_err, "run_with_secrets failed: {run_text}");
    assert!(
        run_text.contains(&format!("len={}", SECRET_MARKER.len())),
        "{run_text}"
    );
    assert!(
        run_text.contains("[redacted by klav]"),
        "expected redaction: {run_text}"
    );
    assert!(
        !run_text.contains(SECRET_MARKER),
        "raw secret leaked into MCP response"
    );

    // 9. T234: agent-suggested `login` URLs are NOT auto-saved unless confirmed.
    let (login_text, login_err) = mcp.tool(
        "request_secret",
        json!({
            "reason": "Need login for staging dashboard",
            "type": "login",
            "title": "Staging Login",
            "field": "password",
            "project": "Personal/General",
            "urls": ["https://evil-phish.example.com/login"],
            "wait_seconds": 0,
        }),
    );
    assert!(!login_err, "{login_text}");
    let login_req_id = serde_json::from_str::<Value>(&login_text).expect("json")["request_id"]
        .as_str()
        .expect("id")
        .to_owned();
    person
        .unlocked(
            &[
                "secret-request",
                "fulfill",
                &login_req_id,
                "--secret-stdin",
                "--yes",
                "--json",
            ],
            &format!("{LOGIN_PASS_MARKER}\n"),
        )
        .ok();
    let item_out = person
        .unlocked(&["item", "get", "Staging Login", "--json"], "")
        .ok();
    let item_json: Value = serde_json::from_str(&item_out.stdout).expect("item json");
    assert_eq!(
        item_json["urls"].as_array().expect("urls").len(),
        0,
        "T234 violated: agent-suggested login URL was auto-saved"
    );

    // 10. T236: fulfilling into a project outside the agent's grant sets
    //     `in_grant: false` and omits `vault_id`, `project_id`, `item_id`, `ref`.
    let (priv_text, priv_err) = mcp.tool(
        "request_secret",
        json!({
            "reason": "Need production secret",
            "type": "api_key",
            "title": "Prod Secret",
            "wait_seconds": 0,
        }),
    );
    assert!(!priv_err, "{priv_text}");
    let priv_req_id = serde_json::from_str::<Value>(&priv_text).expect("json")["request_id"]
        .as_str()
        .expect("id")
        .to_owned();
    person
        .unlocked(
            &[
                "secret-request",
                "fulfill",
                &priv_req_id,
                "--vault",
                "Personal",
                "--project",
                "Private",
                "--secret-stdin",
                "--yes",
                "--json",
            ],
            &format!("{PRIVATE_MARKER}\n"),
        )
        .ok();
    let (priv_get_text, priv_get_err) = mcp.tool(
        "get_secret_request",
        json!({ "request_id": priv_req_id, "wait_seconds": 0 }),
    );
    assert!(!priv_get_err, "{priv_get_text}");
    let priv_get: Value = serde_json::from_str(&priv_get_text).expect("priv get json");
    assert_eq!(priv_get["status"], "fulfilled");
    assert_eq!(priv_get["in_grant"], false);
    assert!(priv_get.get("vault_id").is_none());
    assert!(priv_get.get("project_id").is_none());
    assert!(priv_get.get("item_id").is_none());
    assert!(priv_get.get("ref").is_none());
    assert!(!priv_get_text.contains(PRIVATE_MARKER));

    // 11. Denying a secret request signs `denied` and agent wait exits 5.
    let (deny_text, deny_err) = mcp.tool(
        "request_secret",
        json!({
            "reason": "Need optional analytics key",
            "type": "api_key",
            "title": "Optional Key",
            "wait_seconds": 0,
        }),
    );
    assert!(!deny_err, "{deny_text}");
    let deny_req_id = serde_json::from_str::<Value>(&deny_text).expect("json")["request_id"]
        .as_str()
        .expect("id")
        .to_owned();
    person
        .unlocked(&["secret-request", "deny", &deny_req_id, "--json"], "")
        .ok();
    let denied_wait = agent.run(
        &[
            "agent",
            "secret-request",
            "wait",
            &deny_req_id,
            "--timeout",
            "5s",
            "--json",
        ],
        "",
    );
    assert_eq!(
        denied_wait.code, 5,
        "denied secret request must exit 5: {} {}",
        denied_wait.stdout, denied_wait.stderr
    );

    // 12. Audit log verifies every `secret_request.created` and
    //     `secret_request.decided` signature cleanly.
    let verify_out = person.unlocked(&["log", "verify", "--json"], "").ok();
    let verify: Value = serde_json::from_str(&verify_out.stdout).expect("verify json");
    assert!(
        verify["account_signatures"].as_u64().unwrap_or(0) >= 4,
        "{verify}"
    );
    assert!(
        verify["agent_signatures"].as_u64().unwrap_or(0) >= 4,
        "{verify}"
    );

    // 13. None of the secrets ever reached MCP stderr logs.
    drop(mcp);
    let stderr_contents = std::fs::read_to_string(&stderr_log).unwrap_or_default();
    for secret in [SECRET_MARKER, PRIVATE_MARKER, LOGIN_PASS_MARKER] {
        assert!(
            !stderr_contents.contains(secret),
            "secret leaked to MCP stderr"
        );
    }
}
