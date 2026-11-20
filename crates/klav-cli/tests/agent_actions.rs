//! What an agent does with secrets without receiving them: `klav agent
//! run` (output redacted), `inject` (only to a 0600 file) and `fill` (typed
//! into a real headless Chrome over CDP, after checking the page's host).

mod common;

use common::browser::{Chrome, LoginSite, chrome_or_skip, evaluate, wait_title};
use common::mcp::Mcp;
use common::{Device, ServerProcess};
use serde_json::{Value, json};

const PASSWORD: &str = "MARKER-site-pass-42";
const API_KEY: &str = "MARKER-api-key-7";

fn setup(server: &ServerProcess, root: &std::path::Path, site: &str) -> (Device, Device) {
    let person = Device::new(root, "person");
    person.signup(server, "ana@example.com");
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
                site,
                "--secret-stdin",
                "password",
            ],
            &format!("{PASSWORD}\n"),
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
    let agent = Device::new(root, "agent");
    let out = agent
        .run(
            &[
                "agent",
                "register",
                "--name",
                "bot",
                "--server",
                &server.url,
                "--email",
                "ana@example.com",
                "--key-store",
                "file",
            ],
            "",
        )
        .ok();
    let words = out.stdout.trim().to_owned();
    person
        .unlocked(
            &[
                "agent",
                "approve",
                "bot",
                "--project",
                "Personal/General",
                "--words",
                &words,
            ],
            "",
        )
        .ok();
    (person, agent)
}

fn assert_no_secret(run: &common::Run) {
    for secret in [PASSWORD, API_KEY] {
        assert!(
            !run.stdout.contains(secret) && !run.stderr.contains(secret),
            "a secret leaked\nstdout: {}\nstderr: {}",
            run.stdout,
            run.stderr
        );
    }
}

#[test]
fn run_and_inject_never_print_values() {
    let server = ServerProcess::start(900);
    let root = tempfile::tempdir().expect("tempdir");
    let (person, agent) = setup(&server, root.path(), "https://example.com");
    let repo = root.path().join("repo");
    std::fs::create_dir_all(&repo).expect("repo");
    std::fs::write(
        repo.join("klav.toml"),
        "project = \"Personal/General\"\n\n[env]\nAPI_KEY = \"API/api_key\"\n",
    )
    .expect("klav.toml");

    // The child gets the value; its output comes back redacted.
    let run = agent.run_in(
        Some(&repo),
        &[
            "agent",
            "run",
            "--reason",
            "run the tests",
            "--",
            "sh",
            "-c",
            &format!("echo key=$API_KEY; test \"$API_KEY\" = {API_KEY} && echo same"),
        ],
        "",
    );
    assert_eq!(run.code, 0, "{}", run.stderr);
    assert!(
        run.stdout.contains("key=[redacted by klav]"),
        "{}",
        run.stdout
    );
    assert!(run.stdout.contains("same"), "{}", run.stdout);
    assert!(
        run.stderr.contains("removed from the output"),
        "{}",
        run.stderr
    );
    assert_no_secret(&run);
    // Encoded by accident (base64, hex) it is redacted too. The expected
    // encodings of the synthetic API_KEY, to check they never show.
    let run = agent.run_in(
        Some(&repo),
        &[
            "agent",
            "run",
            "--reason",
            "run the tests",
            "--",
            "sh",
            "-c",
            "echo b64=$(printf %s \"$API_KEY\" | base64); \
             echo hex=$(printf %s \"$API_KEY\" | od -An -tx1 | tr -d ' \\n')",
        ],
        "",
    );
    assert_eq!(run.code, 0, "{}", run.stderr);
    assert_eq!(
        run.stdout, "b64=[redacted by klav]\nhex=[redacted by klav]\n",
        "{}",
        run.stdout
    );
    for encoded in ["TUFSS0VSLWFwaS1rZXktNw", "4d41524b45522d6170692d6b65792d37"] {
        assert!(!run.stdout.contains(encoded), "{}", run.stdout);
    }
    // The child's exit code comes through.
    let failed = agent.run_in(
        Some(&repo),
        &["agent", "run", "--reason", "x", "--", "sh", "-c", "exit 7"],
        "",
    );
    assert_eq!(failed.code, 7);

    // inject: only into a new 0600 file.
    let out = repo.join("key.txt");
    let inject = agent
        .run_in(
            Some(&repo),
            &[
                "agent",
                "inject",
                "-r",
                "API/api_key",
                "-o",
                out.to_str().expect("path"),
                "--reason",
                "configure the client",
            ],
            "",
        )
        .ok();
    assert_no_secret(&inject);
    assert_eq!(std::fs::read_to_string(&out).expect("file"), API_KEY);
    assert_eq!(common::mode(&out), 0o600);
    let missing_out = agent.run(&["agent", "inject", "-r", "x", "--reason", "y"], "");
    assert_eq!(missing_out.code, 2);

    // Everything is in the audit log with its reason.
    let log = person
        .unlocked(&["log", "--agent", "bot", "--json"], "")
        .ok();
    let log: serde_json::Value = serde_json::from_str(&log.stdout).expect("json");
    let reasons: Vec<&str> = log
        .as_array()
        .expect("array")
        .iter()
        .filter_map(|e| e["reason"].as_str())
        .collect();
    assert!(reasons.contains(&"run the tests"));
    assert!(reasons.contains(&"configure the client"));
}

#[tokio::test(flavor = "multi_thread")]
async fn fill_types_into_the_page_and_checks_its_host() {
    let Some(binary) = chrome_or_skip("fill_types_into_the_page") else {
        return;
    };
    let site = LoginSite::start(PASSWORD);
    let server = ServerProcess::start(900);
    let root = tempfile::tempdir().expect("tempdir");
    let (person, agent) = setup(&server, root.path(), &site.url);
    let chrome = Chrome::launch(&binary, &site, &site.url).await;

    let fill = agent.run(
        &[
            "agent",
            "fill",
            "klav://Personal/General/Site",
            "--cdp",
            &chrome.endpoint,
            "--reason",
            "log in to the site",
        ],
        "",
    );
    assert_eq!(fill.code, 0, "{}", fill.stderr);
    assert!(
        fill.stderr.contains("Filled username, password"),
        "{}",
        fill.stderr
    );
    assert_no_secret(&fill);
    evaluate(&chrome.endpoint, "document.querySelector('form').submit()").await;
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

    // --submit sends the form; the JSON report has names and addresses.
    evaluate(&chrome.endpoint, &format!("location.href = {:?}", site.url)).await;
    assert!(wait_title(&chrome.endpoint, "Login").await);
    let submitted = agent.run(
        &[
            "agent",
            "fill",
            "klav://Personal/General/Site",
            "--cdp",
            &chrome.endpoint,
            "--submit",
            "--json",
            "--reason",
            "log in and send the form",
        ],
        "",
    );
    assert_eq!(submitted.code, 0, "{}", submitted.stderr);
    assert_no_secret(&submitted);
    let report: serde_json::Value = serde_json::from_str(&submitted.stdout).expect("json");
    assert_eq!(report["submitted"], true, "{report}");
    assert_eq!(report["navigated"], true, "{report}");
    assert!(wait_title(&chrome.endpoint, "Welcome").await);
    assert_eq!(site.received.lock().expect("lock").len(), 2);
    // A page without a form to send: filled, and the error says so.
    evaluate(
        &chrome.endpoint,
        "document.body.innerHTML = '<input name=user><input type=password id=pass>'",
    )
    .await;
    let no_form = agent.run(
        &[
            "agent",
            "fill",
            "klav://Personal/General/Site",
            "--cdp",
            &chrome.endpoint,
            "--submit",
            "--reason",
            "log in",
        ],
        "",
    );
    assert_ne!(no_form.code, 0);
    assert!(
        no_form.stderr.contains("not submitted"),
        "{}",
        no_form.stderr
    );
    assert_no_secret(&no_form);

    // On another host (the API key item has none of this page's), nothing
    // is typed; and only local browsers are accepted.
    evaluate(&chrome.endpoint, &format!("location.href = {:?}", site.url)).await;
    assert!(wait_title(&chrome.endpoint, "Login").await);
    let wrong = agent.run(
        &[
            "agent",
            "fill",
            "klav://Personal/General/API/api_key",
            "--cdp",
            &chrome.endpoint,
            "--selector",
            "api_key=#pass",
            "--reason",
            "phish",
        ],
        "",
    );
    assert_ne!(wrong.code, 0);
    assert!(wrong.stderr.contains("phishing"), "{}", wrong.stderr);
    assert_eq!(
        evaluate(&chrome.endpoint, "document.querySelector('#pass').value").await,
        ""
    );
    let remote = agent.run(
        &[
            "agent",
            "fill",
            "klav://Personal/General/Site",
            "--cdp",
            "http://10.1.2.3:9222",
            "--reason",
            "x",
        ],
        "",
    );
    assert_ne!(remote.code, 0);

    // A registered session works the same way.
    agent
        .run(
            &[
                "agent",
                "browser",
                "register",
                "shop",
                "--cdp",
                &chrome.endpoint,
            ],
            "",
        )
        .ok();
    let again = agent.run(
        &[
            "agent",
            "fill",
            "klav://Personal/General/Site/password",
            "--session",
            "shop",
            "--reason",
            "log in again",
        ],
        "",
    );
    assert_eq!(again.code, 0, "{}", again.stderr);
    assert_eq!(
        evaluate(
            &chrome.endpoint,
            "document.querySelector('#pass').value.length"
        )
        .await,
        PASSWORD.len()
    );
    let log = person
        .unlocked(&["log", "--agent", "bot", "--json"], "")
        .ok();
    let log: serde_json::Value = serde_json::from_str(&log.stdout).expect("json");
    let fills: Vec<&serde_json::Value> = log
        .as_array()
        .expect("array")
        .iter()
        .filter(|e| e["permission"] == "fill")
        .collect();
    // The first fill, the two with --submit and the one in the session.
    assert_eq!(fills.len(), 4);
    assert!(fills.iter().all(|e| e["domain"] == "127.0.0.1"));
}

/// The LLM picks the selectors and the page runs scripts (layer 04, G7):
/// a password only goes into a password input that has the focus of a page
/// still on the checked host, a form is only sent to the page's own origin,
/// reports name the origin only, and a one-time code is typed with the
/// `totp` permission from a TOTP field only.
#[tokio::test(flavor = "multi_thread")]
async fn fill_checks_the_input_the_focus_and_where_the_form_goes() {
    let Some(binary) = chrome_or_skip("fill_checks_the_input") else {
        return;
    };
    let site = LoginSite::start(PASSWORD);
    let server = ServerProcess::start(900);
    let root = tempfile::tempdir().expect("tempdir");
    let (person, agent) = setup(&server, root.path(), &site.url);
    person
        .unlocked(
            &[
                "item",
                "add",
                "login",
                "--title",
                "TwoFactor",
                "--username",
                "ana",
                "--url",
                &site.url,
                "--secret-stdin",
                "password",
                "--secret-stdin",
                "totp",
            ],
            &format!("{PASSWORD}\nJBSWY3DPEHPK3PXP\n"),
        )
        .ok();
    let origin = site.url.trim_end_matches("/login").to_owned();
    let page = format!("{}?token=MARKER-token#code=MARKER-code", site.url);
    let chrome = Chrome::launch(&binary, &site, &page).await;
    let fill = |reference: &str, extra: &[&str]| {
        let mut args = vec![
            "agent",
            "fill",
            reference,
            "--cdp",
            &chrome.endpoint,
            "--reason",
            "log in",
        ];
        args.extend_from_slice(extra);
        agent.run(&args, "")
    };
    let value = |selector: &str| {
        let endpoint = chrome.endpoint.clone();
        let script = format!("document.querySelector({selector:?}).value");
        async move { evaluate(&endpoint, &script).await }
    };

    // The report names the origin: no path, query or fragment.
    let report = fill("klav://Personal/General/Site", &["--json"]);
    assert_eq!(report.code, 0, "{}", report.stderr);
    let parsed: Value = serde_json::from_str(&report.stdout).expect("json");
    assert_eq!(parsed["url"], origin.as_str(), "{parsed}");
    assert!(!report.stdout.contains("MARKER-"), "{}", report.stdout);

    // A password never goes into a search box, whatever the selector says.
    evaluate(
        &chrome.endpoint,
        "document.querySelector('#pass').value = ''; \
         document.querySelector('form').insertAdjacentHTML('beforeend', '<input type=search id=q>')",
    )
    .await;
    let wrong = fill(
        "klav://Personal/General/Site/password",
        &["--selector", "password=#q"],
    );
    assert_ne!(wrong.code, 0);
    assert!(
        wrong.stderr.contains("does not go into"),
        "{}",
        wrong.stderr
    );
    assert_eq!(value("#q").await, "");
    assert_no_secret(&wrong);

    // A page that moves the focus away gets nothing typed.
    evaluate(
        &chrome.endpoint,
        "document.querySelector('#user').value = ''; document.activeElement.blur(); \
         document.querySelector('#pass').addEventListener('focus', () => document.querySelector('#user').focus())",
    )
    .await;
    let stolen = fill("klav://Personal/General/Site/password", &[]);
    assert_ne!(stolen.code, 0);
    assert!(
        stolen.stderr.contains("lost the focus"),
        "{}",
        stolen.stderr
    );
    assert_eq!(value("#pass").await, "");
    assert_eq!(value("#user").await, "");

    // A form that sends to another origin is filled, not sent.
    evaluate(&chrome.endpoint, &format!("location.href = {:?}", site.url)).await;
    assert!(wait_title(&chrome.endpoint, "Login").await);
    evaluate(
        &chrome.endpoint,
        "document.querySelector('form').action = 'http://localhost:9/steal'",
    )
    .await;
    let elsewhere = fill("klav://Personal/General/Site", &["--submit"]);
    assert_ne!(elsewhere.code, 0);
    assert!(
        elsewhere.stderr.contains("another site"),
        "{}",
        elsewhere.stderr
    );
    assert!(wait_title(&chrome.endpoint, "Login").await);
    assert!(site.received.lock().expect("lock").is_empty());

    // get_totp with a target: the `totp` permission (ask by default), and
    // only a one-time password field, even once approved.
    evaluate(&chrome.endpoint, &format!("location.href = {:?}", site.url)).await;
    assert!(wait_title(&chrome.endpoint, "Login").await);
    agent
        .run(
            &[
                "agent",
                "browser",
                "register",
                "shop",
                "--cdp",
                &chrome.endpoint,
            ],
            "",
        )
        .ok();
    let mut mcp = Mcp::start(&agent, root.path(), None);
    mcp.initialize();
    let args = json!({ "ref": "klav://Personal/General/TwoFactor/password", "target": "sdk:shop", "reason": "2fa", "wait_seconds": 0 });
    let (text, err) = mcp.tool("get_totp", args.clone());
    assert!(err, "{text}");
    let pending: Value = serde_json::from_str(&text).expect("pending");
    let id = pending["pending_approval_id"]
        .as_str()
        .expect("id")
        .to_owned();
    assert_eq!(value("#pass").await, "");
    person.unlocked(&["approval", "approve", &id], "").ok();
    let mut retry = args;
    retry["approval_id"] = json!(id);
    let (text, err) = mcp.tool("get_totp", retry);
    assert!(err && text.contains("one-time password field"), "{text}");
    assert_eq!(value("#pass").await, "");
    for line in &mcp.seen {
        assert!(!line.contains(PASSWORD), "leaked in {line}");
    }
    assert!(mcp.finish().success());
}
