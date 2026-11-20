//! Task requests end to end (ADR 0021) with the real binaries: the agent
//! asks for a task from `tarea.toml` → the person sees the card Klav
//! completed (TOTP added, a site that does not match left unchecked, what
//! the policy denies struck through), leaves something out and shortens it
//! → the agent's wait exits 0 with what was approved → `fill` (headless
//! Chrome, when there is one) and `totp` work inside the task without an
//! approval → a TOTP outside it waits for an approval of its own → the
//! person ends the task and the next use asks again → `klav log --task`
//! tells the story and the log verifies. A second test goes through
//! `klavd` (presence by master password, Touch ID off), denies a task and
//! lets the agent end another.

mod common;

use common::browser::{Chrome, LoginSite, find_chrome};
use common::mcp::Mcp;
use common::{Device, ServerProcess};
use serde_json::{Value, json};

const PASSWORD: &str = "MARKER-task-site-pass-5";
const SEED: &str = "JBSWY3DPEHPK3PXP";

const TASK: &str = r#"
task = "Download the October invoices"
reason = "Reconcile the month's expenses"
duration = "2h"

[[access]]
ref = "klav://Personal/General/Site"
permissions = ["fill"]

[[access]]
ref = "klav://Personal/General/Bank"
permissions = ["fill", "inject"]

[[access]]
ref = "klav://Personal/General/Other"
permissions = ["fill"]
domain = "evil.example"
"#;

fn json(run: &common::Run) -> Value {
    serde_json::from_str(&run.stdout)
        .unwrap_or_else(|e| panic!("json: {e}\nstdout: {}\nstderr: {}", run.stdout, run.stderr))
}

fn add_login(person: &Device, title: &str, url: &str, totp: bool) {
    let mut args = vec![
        "item",
        "add",
        "login",
        "--title",
        title,
        "--username",
        "ana",
        "--url",
        url,
        "--secret-stdin",
        "password",
    ];
    let mut stdin = format!("{PASSWORD}\n");
    if totp {
        args.extend(["--secret-stdin", "totp"]);
        stdin.push_str(&format!("{SEED}\n"));
    }
    person.unlocked(&args, &stdin).ok();
}

/// The person with three logins and the agent `bot`, approved with `ask`
/// for `fill`, `totp` and `reveal` and `deny` for `inject`.
fn setup(server: &ServerProcess, root: &std::path::Path, site: &str) -> (Device, Device) {
    let person = Device::new(root, "person");
    person.signup(server, "ana@example.com");
    add_login(&person, "Site", site, true);
    add_login(&person, "Bank", "https://bank.example.com/login", false);
    add_login(&person, "Other", "https://other.example.com", true);
    let agent = Device::new(root, "agent");
    let words = agent
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
        .ok()
        .stdout
        .trim()
        .to_owned();
    person
        .unlocked(
            &[
                "agent",
                "approve",
                "bot",
                "--project",
                "Personal/General",
                "--ask",
                "fill,totp,reveal",
                "--deny",
                "inject",
                "--words",
                &words,
            ],
            "",
        )
        .ok();
    (person, agent)
}

fn assert_no_secret(run: &common::Run) {
    assert!(
        !run.stdout.contains(PASSWORD) && !run.stderr.contains(PASSWORD),
        "a secret leaked\nstdout: {}\nstderr: {}",
        run.stdout,
        run.stderr
    );
}

fn permission<'a>(row: &'a Value, name: &str) -> &'a Value {
    row["permissions"]
        .as_array()
        .expect("permissions")
        .iter()
        .find(|p| p["permission"] == name)
        .unwrap_or_else(|| panic!("no {name} in {row}"))
}

fn row<'a>(card: &'a Value, title: &str) -> &'a Value {
    card["rows"]
        .as_array()
        .expect("rows")
        .iter()
        .find(|r| r["title"] == title)
        .unwrap_or_else(|| panic!("no row {title} in {card}"))
}

#[tokio::test(flavor = "multi_thread")]
async fn a_task_from_request_to_log() {
    let site = LoginSite::start(PASSWORD);
    let server = ServerProcess::start(900);
    let root = tempfile::tempdir().expect("tempdir");
    let (person, agent) = setup(&server, root.path(), &site.url);
    let file = root.path().join("tarea.toml");
    std::fs::write(&file, TASK).expect("tarea.toml");
    let file = file.to_str().expect("utf-8");

    // The agent asks; without --wait it exits 4 (pending).
    let asked = agent.run(&["agent", "task", "request", file, "--json"], "");
    assert_eq!(asked.code, 4, "{}", asked.stderr);
    let asked = json(&asked);
    assert_eq!(asked["status"], "pending");
    let id = asked["task_id"].as_str().expect("task_id").to_owned();
    let short = &id[..8];
    let still = agent.run(
        &["agent", "task", "wait", &id, "--timeout", "1s", "--json"],
        "",
    );
    assert_eq!(still.code, 4, "{}", still.stderr);
    // YAML is refused with its reason.
    let yaml = root.path().join("tarea.yaml");
    std::fs::write(&yaml, "task: x\n").expect("yaml");
    let refused = agent.run(
        &["agent", "task", "request", yaml.to_str().expect("utf-8")],
        "",
    );
    assert_eq!(refused.code, 2);
    assert!(refused.stderr.contains("not YAML"), "{}", refused.stderr);

    // The person sees the card Klav completed.
    let list = json(&person.unlocked(&["task", "ls", "--json"], "").ok());
    assert_eq!(list.as_array().expect("list").len(), 1, "{list}");
    let card = json(&person.unlocked(&["task", "show", short, "--json"], "").ok());
    assert_eq!(card["agent"], "bot");
    assert_eq!(card["task"], "Download the October invoices");
    let site_row = row(&card, "Site");
    assert_eq!(site_row["domains"], serde_json::json!(["127.0.0.1"]));
    assert_eq!(permission(site_row, "fill")["checked"], true);
    let totp = permission(site_row, "totp");
    assert_eq!(totp["checked"], true);
    assert_eq!(totp["added_by_klav"], true);
    assert_eq!(totp["asked"], false);
    let bank = row(&card, "Bank");
    assert_eq!(permission(bank, "inject")["denied_by_policy"], true);
    assert_eq!(permission(bank, "inject")["checked"], false);
    let other = row(&card, "Other");
    assert_eq!(other["domain_mismatch"], true);
    assert_eq!(other["asked_domain"], "evil.example");
    assert_eq!(permission(other, "fill")["checked"], false);
    let human = person.unlocked(&["task", "show", short], "").ok();
    for text in [
        "(according to the agent)",
        "(added by Klav)",
        "2FA stops being a second factor",
        "inject: your policy denies it",
        "the site does not match the item (the agent said evil.example)",
    ] {
        assert!(human.stdout.contains(text), "{text}\n{}", human.stdout);
    }

    // `--without` names a permission that is not on the card: refused.
    let bad = person.unlocked(&["task", "approve", short, "--without", "Bank:totp"], "");
    assert_eq!(bad.code, 2, "{}", bad.stderr);
    // It approves without Bank's fill (so without Bank) and for 30 min.
    let approved = json(
        &person
            .unlocked(
                &[
                    "task",
                    "approve",
                    short,
                    "--without",
                    "Bank:fill",
                    "--for",
                    "30m",
                    "--json",
                ],
                "",
            )
            .ok(),
    );
    assert_eq!(approved["status"], "approved");
    let left = approved["expires_at"].as_i64().expect("expires_at")
        - approved["decided_at"].as_i64().expect("decided_at");
    assert_eq!(left, 30 * 60 * 1000);

    // The agent's wait exits 0 with what the person approved.
    let got = agent.run(&["agent", "task", "wait", &id, "--json"], "");
    assert_eq!(got.code, 0, "{}", got.stderr);
    let got = json(&got);
    assert_eq!(got["status"], "approved");
    assert_eq!(
        got["access"],
        serde_json::json!([{
            "ref": "klav://Personal/General/Site",
            "permissions": ["fill", "totp"],
            "domains": ["127.0.0.1"],
            "added_by_klav": ["totp"],
        }])
    );
    let removed: Vec<&str> = got["removed"]
        .as_array()
        .expect("removed")
        .iter()
        .map(|r| r["ref"].as_str().expect("ref"))
        .collect();
    assert_eq!(
        removed,
        [
            "klav://Personal/General/Bank",
            "klav://Personal/General/Other"
        ]
    );

    // Inside the task: fill (with a browser) and totp need no approval.
    if let Some(binary) = find_chrome() {
        let chrome = Chrome::launch(&binary, &site, &site.url).await;
        let fill = agent.run(
            &[
                "agent",
                "fill",
                "klav://Personal/General/Site",
                "--cdp",
                &chrome.endpoint,
                "--reason",
                "log in to download the invoices",
            ],
            "",
        );
        assert_eq!(fill.code, 0, "{}", fill.stderr);
        assert_no_secret(&fill);
    } else {
        assert!(std::env::var_os("CI").is_none(), "no Chrome on CI");
        eprintln!("a_task_from_request_to_log: fill skipped, no Chrome found");
    }
    let code = agent.run(
        &[
            "agent",
            "totp",
            "klav://Personal/General/Site",
            "--reason",
            "the site asks for the 2FA code",
        ],
        "",
    );
    assert_eq!(code.code, 0, "{}", code.stderr);

    // Outside the task: a TOTP of Other waits for its own approval. The
    // person sees «Outside the task» and adds it to the task: the agent's
    // waiter exits 0, the retry gets the code, and the next code needs no
    // approval.
    let outside = agent.run(
        &[
            "agent",
            "totp",
            "klav://Personal/General/Other",
            "--reason",
            "the other site asks for a code too",
        ],
        "",
    );
    assert_eq!(outside.code, 4, "{}", outside.stderr);
    let approvals = json(&person.unlocked(&["approval", "ls", "--json"], "").ok());
    let approval = approvals[0]["id"].as_str().expect("approval id").to_owned();
    assert_eq!(approvals[0]["task"]["id"], id.as_str(), "{approvals}");
    assert_eq!(approvals[0]["task"]["can_add"], true, "{approvals}");
    let mut waiter = agent
        .command()
        .args(["approval", "wait", &approval, "--timeout", "1m"])
        .spawn()
        .expect("spawn");
    let added = person
        .unlocked(&["approval", "approve", &approval, "--add-to-task"], "")
        .ok();
    assert!(
        added.stderr.contains("Added to the task"),
        "{}",
        added.stderr
    );
    assert_eq!(common::wait_child(&mut waiter, 30), 0);
    agent
        .run(
            &[
                "agent",
                "totp",
                "klav://Personal/General/Other",
                "--reason",
                "the other site asks for a code too",
                "--approval",
                &approval,
            ],
            "",
        )
        .ok();
    let revised = json(
        &agent
            .run(&["agent", "task", "show", &id, "--json"], "")
            .ok(),
    );
    assert_eq!(revised["revision"], 2, "{revised}");
    assert!(
        revised["access"]
            .as_array()
            .expect("access")
            .iter()
            .any(|a| a["ref"] == "klav://Personal/General/Other"
                && a["permissions"] == json!(["totp"])),
        "{revised}"
    );
    assert_eq!(revised["expires_at"], approved["expires_at"]);
    agent
        .run(
            &[
                "agent",
                "totp",
                "klav://Personal/General/Other",
                "--reason",
                "another code for the other site",
            ],
            "",
        )
        .ok();

    // The person ends the task: the next use asks again, and the agent
    // learns it was ended (exit 5).
    let ended = json(&person.unlocked(&["task", "end", short, "--json"], "").ok());
    assert_eq!(ended["status"], "ended");
    assert_eq!(ended["ended_by"], "person");
    let after = agent.run(
        &[
            "agent",
            "totp",
            "klav://Personal/General/Site",
            "--reason",
            "one more code",
        ],
        "",
    );
    assert_eq!(after.code, 4, "{}", after.stderr);
    let shown = agent
        .run(&["agent", "task", "show", &id, "--json"], "")
        .ok();
    assert_eq!(json(&shown)["ended_by"], "person");
    let over = agent.run(&["agent", "task", "wait", &id], "");
    assert_eq!(over.code, 5, "{}", over.stderr);

    // `klav log --task`: the request, the decision, each use, the approval
    // outside it, and the end.
    let log = json(
        &person
            .unlocked(&["log", "--task", short, "--json"], "")
            .ok(),
    );
    assert_eq!(log["task_id"], id.as_str());
    let actions: Vec<(String, String)> = log["events"]
        .as_array()
        .expect("events")
        .iter()
        .map(|e| {
            (
                e["action"].as_str().unwrap_or_default().to_owned(),
                e["permission"].as_str().unwrap_or_default().to_owned(),
            )
        })
        .collect();
    let mut expected = vec![
        ("task.requested".to_owned(), String::new()),
        ("task.decided".to_owned(), String::new()),
    ];
    if find_chrome().is_some() {
        expected.push(("agent.access".to_owned(), "fill".to_owned()));
    }
    expected.push(("agent.access".to_owned(), "totp".to_owned()));
    // «Add to the task»: revision 2, the request approved into it (bound
    // to the task, so it shows in its log), then the next Other code
    // inside it.
    expected.push(("task.decided".to_owned(), String::new()));
    expected.push(("approval.decided".to_owned(), "totp".to_owned()));
    expected.push(("agent.access".to_owned(), "totp".to_owned()));
    expected.push(("task.ended".to_owned(), String::new()));
    assert_eq!(actions, expected, "{log}");
    let outside = log["outside"].as_array().expect("outside");
    assert!(
        outside
            .iter()
            .any(|e| e["permission"] == "totp" && e["approval_id"] == approval.as_str()),
        "{log}"
    );
    let human = person.unlocked(&["log", "--task", short], "").ok();
    assert!(
        human.stdout.contains("Outside the task"),
        "{}",
        human.stdout
    );
    person.unlocked(&["log", "verify"], "").ok();
}

/// «Add to the task» also approves the pending request once, so the
/// agent's waiter exits 0. If the agent then goes through the task instead
/// of retrying with `--approval`, that use spends the once-approval: after
/// the person ends the task, the next use of the same target asks again
/// (ADR 0021 §6) instead of reusing it within the 10-minute window.
#[test]
fn add_to_task_does_not_outlive_the_task() {
    let server = ServerProcess::start(900);
    let root = tempfile::tempdir().expect("tempdir");
    let (person, agent) = setup(&server, root.path(), "https://site.example.com/login");
    let file = root.path().join("tarea.toml");
    std::fs::write(&file, TASK).expect("tarea.toml");
    let file = file.to_str().expect("utf-8");
    let totp_other = |reason: &str| {
        agent.run(
            &[
                "agent",
                "totp",
                "klav://Personal/General/Other",
                "--reason",
                reason,
            ],
            "",
        )
    };

    let asked = json(&agent.run(&["agent", "task", "request", file, "--json"], ""));
    let id = asked["task_id"].as_str().expect("task_id").to_owned();
    let short = &id[..8];
    person
        .unlocked(&["task", "approve", short, "--without", "Bank:fill"], "")
        .ok();

    // Other is outside the task; the person adds it.
    let outside = totp_other("the other site asks for a code");
    assert_eq!(outside.code, 4, "{}", outside.stderr);
    let approvals = json(&person.unlocked(&["approval", "ls", "--json"], "").ok());
    let approval = approvals[0]["id"].as_str().expect("approval id").to_owned();
    person
        .unlocked(&["approval", "approve", &approval, "--add-to-task"], "")
        .ok();

    // The agent uses it without `--approval`: it goes through the task.
    let inside = totp_other("the code, now inside the task");
    assert_eq!(inside.code, 0, "{}", inside.stderr);

    // The person ends the task: the next use asks again.
    person.unlocked(&["task", "end", short], "").ok();
    let after = totp_other("one more code after the task");
    assert_eq!(after.code, 4, "the added approval outlived the task");
}

/// The approval «Add to the task» leaves behind is bound to the task (layer
/// 06 of the 2026-11 security round): if the agent never uses the task, it
/// still dies with the task instead of serving its 10 minutes, with or
/// without its ID.
#[test]
fn an_unused_addition_does_not_outlive_the_task() {
    let server = ServerProcess::start(900);
    let root = tempfile::tempdir().expect("tempdir");
    let (person, agent) = setup(&server, root.path(), "https://site.example.com/login");
    let file = root.path().join("tarea.toml");
    std::fs::write(&file, TASK).expect("tarea.toml");
    let file = file.to_str().expect("utf-8");
    let totp_other = |reason: &str, approval: Option<&str>| {
        let mut args = vec![
            "agent",
            "totp",
            "klav://Personal/General/Other",
            "--reason",
            reason,
        ];
        if let Some(id) = approval {
            args.extend(["--approval", id]);
        }
        agent.run(&args, "")
    };

    let asked = json(&agent.run(&["agent", "task", "request", file, "--json"], ""));
    let id = asked["task_id"].as_str().expect("task_id").to_owned();
    let short = &id[..8];
    person
        .unlocked(&["task", "approve", short, "--without", "Bank:fill"], "")
        .ok();
    let outside = totp_other("the other site asks for a code", None);
    assert_eq!(outside.code, 4, "{}", outside.stderr);
    let approvals = json(&person.unlocked(&["approval", "ls", "--json"], "").ok());
    let approval = approvals[0]["id"].as_str().expect("approval id").to_owned();
    person
        .unlocked(&["approval", "approve", &approval, "--add-to-task"], "")
        .ok();

    // The agent does nothing with it; the person ends the task.
    person.unlocked(&["task", "end", short], "").ok();
    let after = totp_other("a code after the task", None);
    assert_eq!(after.code, 4, "the added approval outlived the task");
    let named = totp_other("a code after the task", Some(&approval));
    assert_ne!(
        named.code, 0,
        "the added approval served by name after the task"
    );
}

/// Stops `klavd` when the test ends, also if it fails.
struct StopDaemon<'a>(&'a Device);

impl Drop for StopDaemon<'_> {
    fn drop(&mut self) {
        let _ = self.0.run(&["lock", "--stop"], "");
    }
}

#[test]
fn tasks_through_klavd_deny_and_agent_end() {
    let server = ServerProcess::start(900);
    let root = tempfile::tempdir().expect("tempdir");
    let (person, agent) = setup(&server, root.path(), "https://site.example.com/login");
    let file = root.path().join("tarea.json");
    std::fs::write(
        &file,
        r#"{"task":"Check the bank","reason":"Monthly statement","duration":"30m",
            "access":[{"ref":"klav://Personal/General/Bank","permissions":["fill"]}]}"#,
    )
    .expect("tarea.json");
    let file = file.to_str().expect("utf-8");

    // klavd unlocked with the password (Touch ID is off in tests).
    let _stop = StopDaemon(&person);
    person.unlocked(&["unlock", "--idle-lock", "10m"], "").ok();

    // Approve through klavd: presence falls back to the master password.
    let asked = json(&agent.run(&["agent", "task", "request", file, "--json"], ""));
    let id = asked["task_id"].as_str().expect("task_id").to_owned();
    let card = json(&person.run(&["task", "show", &id, "--json"], "").ok());
    assert_eq!(
        row(&card, "Bank")["domains"],
        serde_json::json!(["bank.example.com"])
    );
    let approved = person.unlocked(&["task", "approve", &id[..8]], "").ok();
    assert!(
        approved.stderr.contains("master password"),
        "{}",
        approved.stderr
    );
    assert_eq!(
        agent
            .run(&["agent", "task", "wait", &id, "--json"], "")
            .code,
        0
    );
    let ended = json(&person.run(&["task", "end", &id, "--json"], "").ok());
    assert_eq!(ended["ended_by"], "person");

    // Denied: the agent's wait exits 5.
    let asked = json(&agent.run(&["agent", "task", "request", file, "--json"], ""));
    let denied = asked["task_id"].as_str().expect("task_id").to_owned();
    person.run(&["task", "deny", &denied], "").ok();
    let wait = agent.run(&["agent", "task", "wait", &denied], "");
    assert_eq!(wait.code, 5, "{}", wait.stderr);

    // The agent asks with --wait, the person approves while it waits, and
    // the agent ends its own task when done.
    let mut waiting = agent
        .command()
        .args(["agent", "task", "request", file, "--wait", "--json"])
        .spawn()
        .expect("spawn");
    assert!(
        common::wait_until(20, || {
            let list = person.run(&["task", "ls", "--json"], "");
            json(&list)
                .as_array()
                .is_some_and(|l| l.iter().any(|t| t["status"] == "pending"))
        }),
        "the request did not arrive"
    );
    let pending = json(&person.run(&["task", "ls", "--json"], "").ok());
    let own = pending
        .as_array()
        .expect("list")
        .iter()
        .find(|t| t["status"] == "pending")
        .expect("pending")["id"]
        .as_str()
        .expect("id")
        .to_owned();
    person.unlocked(&["task", "approve", &own], "").ok();
    assert_eq!(common::wait_child(&mut waiting, 30), 0);
    let done = json(
        &agent
            .run(
                &[
                    "agent",
                    "task",
                    "end",
                    &own,
                    "--reason",
                    "statement downloaded",
                    "--json",
                ],
                "",
            )
            .ok(),
    );
    assert_eq!(done["status"], "ended");
    assert_eq!(done["ended_by"], "agent");
    let none = json(&person.run(&["task", "ls", "--json"], "").ok());
    assert_eq!(none, serde_json::json!([]));
    person.run(&["log", "verify"], "").ok();
}

#[test]
fn tasks_over_mcp() {
    let server = ServerProcess::start(900);
    let root = tempfile::tempdir().expect("tempdir");
    let (person, agent) = setup(&server, root.path(), "https://site.example.com/login");
    let repo = root.path().join("repo");
    std::fs::create_dir_all(&repo).expect("repo");
    let mut mcp = Mcp::start(&agent, &repo, None);
    mcp.initialize();
    let tools = mcp.request("tools/list", json!({}));
    let names: Vec<&str> = tools["result"]["tools"]
        .as_array()
        .expect("tools")
        .iter()
        .filter_map(|t| t["name"].as_str())
        .collect();
    for tool in ["request_task", "get_task", "list_tasks", "end_task"] {
        assert!(names.contains(&tool), "{names:?}");
    }

    // reveal never goes in a task.
    let (text, err) = mcp.tool(
        "request_task",
        json!({ "task": "x", "reason": "y", "duration": "1h",
                "access": [{ "ref": "klav://Personal/General/Site", "permissions": ["reveal"] }] }),
    );
    assert!(
        err && text.contains("`reveal` never goes in a task"),
        "{text}"
    );

    // Pending: the commands to approve and to wait (ADR 0015 §5).
    let (text, err) = mcp.tool(
        "request_task",
        json!({ "task": "Download the invoices", "reason": "Reconcile the month",
                "duration": "1h", "wait_seconds": 0,
                "access": [
                    { "ref": "klav://Personal/General/Site", "permissions": ["fill"] },
                    { "ref": "klav://Personal/General/Other", "permissions": ["totp"] }
                ] }),
    );
    assert!(!err, "{text}");
    let pending: Value = serde_json::from_str(&text).expect("json");
    assert_eq!(pending["status"], "pending");
    let id = pending["pending_task_id"].as_str().expect("id").to_owned();
    assert_eq!(
        pending["approve_command"],
        format!("klav task approve {id}")
    );
    let wait_command = pending["wait_command"].as_str().expect("wait_command");
    for part in [
        format!("agent task wait {id}"),
        "--agent bot".to_owned(),
        "KLAV_HOME=".to_owned(),
        "--json".to_owned(),
    ] {
        assert!(wait_command.contains(&part), "{wait_command}");
    }
    assert!(!wait_command.contains("KLAV_AGENT_KEY"), "{wait_command}");
    assert!(
        wait_command
            .split_whitespace()
            .nth(1)
            .is_some_and(|exe| exe.trim_matches('\'').starts_with('/')),
        "{wait_command}"
    );

    // The wait command, run as given in the background, exits 0 when the
    // person approves.
    let mut waiter = std::process::Command::new("sh")
        .args(["-c", wait_command])
        .env("KLAV_NO_TOUCH_ID", "1")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("sh");
    person.unlocked(&["task", "approve", &id], "").ok();
    assert_eq!(common::wait_child(&mut waiter, 30), 0);

    let (text, err) = mcp.tool("get_task", json!({ "task_id": id }));
    assert!(!err, "{text}");
    let task: Value = serde_json::from_str(&text).expect("json");
    assert_eq!(task["status"], "approved");
    let access = task["access"].as_array().expect("access");
    assert_eq!(access.len(), 2, "{text}");
    assert_eq!(access[0]["permissions"], json!(["fill", "totp"]));
    assert_eq!(access[0]["added_by_klav"], json!(["totp"]));

    // Inside the task the runtime names it by itself: no approval.
    let (text, err) = mcp.tool(
        "get_totp",
        json!({ "ref": "klav://Personal/General/Other", "reason": "the site asks for a code", "wait_seconds": 0 }),
    );
    assert!(!err, "{text}");
    let code: Value = serde_json::from_str(&text).expect("json");
    assert_eq!(code["code"].as_str().map(str::len), Some(6), "{text}");
    // A task_id that is not running is refused before acting.
    let (text, err) = mcp.tool(
        "get_totp",
        json!({ "ref": "klav://Personal/General/Other", "reason": "x",
                "task_id": "00000000-0000-4000-8000-000000000000" }),
    );
    assert!(err && text.contains("is not running"), "{text}");

    // `reveal` outside the task: «Outside the task», but never «Add to the
    // task» (ADR 0021 §6). The person denies it.
    let (text, _) = mcp.tool(
        "request_access",
        json!({ "ref": "klav://Personal/General/Bank", "permission": "reveal",
                "reason": "check the password", "wait_seconds": 0 }),
    );
    assert!(text.contains("pending_approval_id"), "{text}");
    let approvals = json(&person.unlocked(&["approval", "ls", "--json"], "").ok());
    assert_eq!(approvals[0]["permission"], "reveal", "{approvals}");
    assert_eq!(approvals[0]["task"]["id"], id.as_str(), "{approvals}");
    assert_eq!(approvals[0]["task"]["can_add"], false, "{approvals}");
    let reveal = approvals[0]["id"].as_str().expect("approval id");
    let refused = person.unlocked(&["approval", "approve", reveal, "--add-to-task"], "");
    assert_ne!(refused.code, 0, "{}", refused.stdout);
    person.unlocked(&["approval", "deny", reveal], "").ok();

    let (text, _) = mcp.tool("list_tasks", json!({}));
    assert!(text.contains(&id), "{text}");
    let (text, err) = mcp.tool(
        "end_task",
        json!({ "task_id": id, "reason": "invoices downloaded" }),
    );
    assert!(!err, "{text}");
    let ended: Value = serde_json::from_str(&text).expect("json");
    assert_eq!(ended["task"]["ended_by"], "agent");

    // After the end the same code asks the person again.
    let (text, err) = mcp.tool(
        "get_totp",
        json!({ "ref": "klav://Personal/General/Other", "reason": "one more", "wait_seconds": 0 }),
    );
    assert!(err && text.contains("pending_approval_id"), "{text}");
    mcp.finish();
}
