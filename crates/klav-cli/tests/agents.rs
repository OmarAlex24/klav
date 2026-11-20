//! `klav agent`: an agent registers on its own machine, the person
//! approves it after comparing the pairing words (directly and through
//! `klavd`, where the presence check falls back to the master password).

mod common;

use common::{Device, ServerProcess};

struct StopDaemon<'a>(&'a Device);

impl Drop for StopDaemon<'_> {
    fn drop(&mut self) {
        let _ = self.0.run(&["lock", "--stop"], "");
    }
}

fn json(out: &str) -> serde_json::Value {
    serde_json::from_str(out).expect("json output")
}

#[test]
fn register_approve_and_deny() {
    let server = ServerProcess::start(900);
    let root = tempfile::tempdir().expect("tempdir");
    let person = Device::new(root.path(), "person");
    person.signup(&server, "ana@example.com");
    person
        .unlocked(&["project", "create", "--vault", "Personal", "web"], "")
        .ok();
    let machine = Device::new(root.path(), "agent");

    // The agent registers with its own key (stored in a 0600 file).
    let out = machine
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
                "--note",
                "CI",
                "--key-store",
                "file",
            ],
            "",
        )
        .ok();
    let words = out.stdout.trim().to_owned();
    assert_eq!(words.split(' ').count(), 6, "{}", out.stdout);
    assert_eq!(common::mode(&machine.home.join("agents/bot.key")), 0o600);
    let status = json(&machine.run(&["agent", "status", "--json"], "").ok().stdout);
    assert_eq!(status["status"], "pending");
    assert_eq!(status["pairing_code"], words.as_str());

    // The person sees the same words.
    let list = json(
        &person
            .unlocked(&["agent", "list", "--json"], "")
            .ok()
            .stdout,
    );
    assert_eq!(list[0]["name"], "bot");
    assert_eq!(list[0]["status"], "pending");
    assert_eq!(list[0]["pairing_code"], words.as_str());

    // Wrong words: refused as a security problem (exit 3).
    let wrong = person.unlocked(
        &[
            "agent",
            "approve",
            "bot",
            "--project",
            "Personal/web",
            "--words",
            "uno dos tres cuatro cinco seis",
        ],
        "",
    );
    assert_eq!(wrong.code, 3, "{}", wrong.stderr);

    // Schedules need an explicit UTC offset.
    let bad = person.unlocked(
        &[
            "agent",
            "approve",
            "bot",
            "--project",
            "Personal/web",
            "--hours",
            "mon-fri 09:00-18:00",
            "--words",
            &words,
        ],
        "",
    );
    assert_eq!(bad.code, 2, "{}", bad.stderr);

    person
        .unlocked(
            &[
                "agent",
                "approve",
                "bot",
                "--project",
                "Personal/web",
                "--ask",
                "totp",
                "--deny",
                "reveal",
                "--fill-domain",
                "*.example.com",
                "--hours",
                "daily 00:00-00:00 Z",
                "--expires",
                "30d",
                "--words",
                &words,
            ],
            "",
        )
        .ok();
    let status = json(&machine.run(&["agent", "status", "--json"], "").ok().stdout);
    assert_eq!(status["status"], "active");
    assert_eq!(status["grant_version"], 1);
    assert_eq!(status["projects"], 1);
    // The agent pinned the account identity; the person sees the same words.
    let person_status = json(&person.run(&["status", "--json"], "").ok().stdout);
    assert_eq!(status["account_code"], person_status["account_words"]);

    // Through klavd: no Touch ID here, so the master password confirms.
    let _stop = StopDaemon(&person);
    person.unlocked(&["unlock"], "").ok();
    let out = person
        .unlocked(
            &[
                "agent", "approve", "bot", "--vault", "Personal", "--words", &words,
            ],
            "",
        )
        .ok();
    // The agent is active: approving again shows the differences, and
    // since they widen, klavd asks for presence (ADR 0033, amendment of
    // 2026-11-10, P8).
    assert!(out.stderr.contains("master password"), "{}", out.stderr);
    assert!(
        out.stderr.contains("+ Personal/") && out.stderr.contains("This widens"),
        "{}",
        out.stderr
    );
    let status = json(&machine.run(&["agent", "status", "--json"], "").ok().stdout);
    assert_eq!(status["grant_version"], 2);
    assert_eq!(status["projects"], 2);

    // Narrowing through klavd asks for nothing.
    let out = person
        .unlocked(
            &[
                "agent", "approve", "bot", "--vault", "Personal", "--deny", "fill",
            ],
            "",
        )
        .ok();
    assert!(
        out.stderr.contains("fill: allow (default) -> deny")
            && out.stderr.contains("only narrows")
            && !out.stderr.contains("master password"),
        "{}",
        out.stderr
    );
    let status = json(&machine.run(&["agent", "status", "--json"], "").ok().stdout);
    assert_eq!(status["grant_version"], 3);

    // A second registration is denied.
    machine
        .run(
            &[
                "agent",
                "register",
                "--name",
                "otro",
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
    person.run(&["agent", "deny", "otro"], "").ok();
    let status = json(
        &machine
            .run(&["agent", "status", "--agent", "otro", "--json"], "")
            .ok()
            .stdout,
    );
    assert_eq!(status["status"], "denied");
    // With two agents the name is needed.
    assert_ne!(machine.run(&["agent", "status"], "").code, 0);
}

/// Registers `name` on `machine` and approves it on `person` for
/// `Personal/General` with the extra approve flags.
fn approved_agent(
    server: &ServerProcess,
    person: &Device,
    machine: &Device,
    name: &str,
    flags: &[&str],
) -> String {
    let out = machine
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
        .ok();
    let words = out.stdout.trim().to_owned();
    let mut args = vec![
        "agent",
        "approve",
        name,
        "--project",
        "Personal/General",
        "--words",
        &words,
    ];
    args.extend_from_slice(flags);
    person.unlocked(&args, "").ok();
    words
}

#[test]
fn ask_goes_pending_until_the_person_approves() {
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
                "GitHub",
                "--username",
                "ana",
                "--secret-stdin",
                "password",
                "--secret-stdin",
                "totp",
            ],
            "MARKER-gh-password\nJBSWY3DPEHPK3PXP\n",
        )
        .ok();
    let machine = Device::new(root.path(), "agent");
    approved_agent(&server, &person, &machine, "bot", &[]);
    let reference = "klav://Personal/General/GitHub";

    // totp is `ask` by default: exit 4 with the request ID.
    let first = machine.run(
        &["agent", "totp", reference, "--reason", "log in to GitHub"],
        "",
    );
    assert_eq!(first.code, 4, "{}", first.stderr);
    assert!(
        first.stderr.contains("klav approval approve"),
        "{}",
        first.stderr
    );
    // A reason is mandatory.
    let no_reason = machine.run(&["agent", "totp", reference, "--reason", " "], "");
    assert_ne!(no_reason.code, 0);

    // The agent retries and waits: it gets the same request (ADR 0015),
    // and the person approves it once.
    let mut waiting = machine.command();
    waiting.args([
        "agent",
        "totp",
        reference,
        "--reason",
        "log in to GitHub",
        "--wait",
        "60s",
    ]);
    let waiting = waiting.spawn().expect("spawn agent");
    let list = person.unlocked(&["approval", "list", "--json"], "").ok();
    let list: serde_json::Value = serde_json::from_str(&list.stdout).expect("json");
    let list = list.as_array().expect("array");
    assert_eq!(list.len(), 1, "{list:?}");
    assert_eq!(list[0]["reason"], "log in to GitHub");
    assert_eq!(list[0]["permission"], "totp");
    let id = list[0]["id"].as_str().expect("id").to_owned();
    assert_eq!(
        list[0]["request_digest"].as_str().map(str::len),
        Some(64),
        "{list:?}"
    );
    // The whole request is shown before signing (ADR 0030 §5).
    let approved = person.unlocked(&["approval", "approve", &id[..8]], "").ok();
    assert!(
        approved.stdout.contains("bot")
            && approved.stdout.contains("totp")
            && approved
                .stdout
                .contains("log in to GitHub   (according to the agent)"),
        "{}",
        approved.stdout
    );
    let out = waiting.wait_with_output().expect("agent output");
    let stdout = String::from_utf8(out.stdout).expect("utf-8");
    let stderr = String::from_utf8(out.stderr).expect("utf-8");
    assert!(out.status.success(), "{stderr}");
    assert_eq!(stdout.trim().len(), 6, "{stdout}");
    assert!(!stdout.contains("MARKER") && !stderr.contains("MARKER"));

    // Spent: the next call asks again. A denial is not reused; then
    // approve the next one for 15 minutes.
    let again = machine.run(&["agent", "totp", reference, "--reason", "deploy"], "");
    assert_eq!(again.code, 4);
    let pending = person.unlocked(&["approval", "list", "--json"], "").ok();
    let pending: serde_json::Value = serde_json::from_str(&pending.stdout).expect("json");
    let denied = pending[0]["id"].as_str().expect("id").to_owned();
    assert_ne!(denied, id);
    person.unlocked(&["approval", "deny", &denied], "").ok();
    let again = machine.run(&["agent", "totp", reference, "--reason", "deploy"], "");
    assert_eq!(again.code, 4);
    let pending = person.unlocked(&["approval", "list", "--json"], "").ok();
    let pending: serde_json::Value = serde_json::from_str(&pending.stdout).expect("json");
    let id = pending[0]["id"].as_str().expect("id").to_owned();
    assert_ne!(id, denied);
    person
        .unlocked(&["approval", "approve", &id, "--for", "15m"], "")
        .ok();
    for _ in 0..2 {
        let out = machine
            .run(&["agent", "totp", reference, "--reason", "deploy"], "")
            .ok();
        assert_eq!(out.stdout.trim().len(), 6);
    }
    let all = person
        .unlocked(&["approval", "list", "--all", "--json"], "")
        .ok();
    let all: serde_json::Value = serde_json::from_str(&all.stdout).expect("json");
    assert_eq!(all.as_array().map(Vec::len), Some(3));
}

#[test]
fn the_audit_log_shows_exports_and_verifies() {
    let mut server = ServerProcess::start(900);
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
                "GitHub",
                "--secret-stdin",
                "totp",
            ],
            "JBSWY3DPEHPK3PXP\n",
        )
        .ok();
    let machine = Device::new(root.path(), "agent");
    approved_agent(&server, &person, &machine, "bot", &["--allow", "totp"]);
    let reference = "klav://Personal/General/GitHub";
    machine
        .run(
            &["agent", "totp", reference, "--reason", "=HYPERLINK(\"x\")"],
            "",
        )
        .ok();
    server.snapshot("before-second-use");
    machine
        .run(&["agent", "totp", reference, "--reason", "deploy"], "")
        .ok();

    // The table, filtered by agent and by item, newest first.
    let json = person
        .unlocked(&["log", "--agent", "bot", "--json"], "")
        .ok();
    let events: serde_json::Value = serde_json::from_str(&json.stdout).expect("json");
    let events = events.as_array().expect("array");
    assert_eq!(events[0]["action"], "agent.access");
    assert_eq!(events[0]["reason"], "deploy");
    assert_eq!(events[0]["outcome"], "allow");
    assert_eq!(events[0]["item"], "klav://Personal/General/GitHub");
    // First use of the secret raises an alert; the second does not.
    assert_eq!(events[1]["alerts"][0], "first_use");
    assert!(events[0].get("alerts").is_none());
    assert!(
        events
            .iter()
            .any(|e| e["action"] == "agent.granted" && e["agent_name"] == "bot"),
        "{events:?}"
    );
    let alerts = person
        .unlocked(&["log", "--alerts", "--item", "GitHub", "--json"], "")
        .ok();
    let alerts: serde_json::Value = serde_json::from_str(&alerts.stdout).expect("json");
    assert_eq!(alerts.as_array().map(Vec::len), Some(1));
    let table = person.unlocked(&["log", "--since", "1h"], "").ok();
    assert!(table.stdout.contains("deploy"), "{}", table.stdout);
    // Who the grant was for.
    assert!(
        table.stdout.contains("agent.granted for \"bot\" ("),
        "{}",
        table.stdout
    );
    assert!(
        table.stderr.contains("not verified the log yet"),
        "{}",
        table.stderr
    );
    let none = person.unlocked(&["log", "--until", "2000-01-01"], "").ok();
    assert!(none.stderr.contains("No events"), "{}", none.stderr);
    // By permission, outcome and text (ADR 0033 §8.1).
    let found = person
        .unlocked(
            &[
                "log",
                "--permission",
                "totp",
                "--outcome",
                "allow",
                "--text",
                "DEPLOY",
                "--json",
            ],
            "",
        )
        .ok();
    let found: serde_json::Value = serde_json::from_str(&found.stdout).expect("json");
    let found = found.as_array().expect("array");
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0]["reason"], "deploy");
    let filled = person
        .unlocked(&["log", "--permission", "fill", "--json"], "")
        .ok();
    assert_eq!(filled.stdout.trim(), "[]");
    let wrong = person.unlocked(&["log", "--permission", "peek"], "");
    assert_ne!(wrong.code, 0);
    assert!(
        wrong.stderr.contains("unknown permission"),
        "{}",
        wrong.stderr
    );

    // CSV export; an agent's reason cannot become a spreadsheet formula.
    let csv = person.unlocked(&["log", "--csv"], "").ok();
    assert!(csv.stdout.starts_with("seq,time,actor"), "{}", csv.stdout);
    assert!(csv.stdout.contains("'=HYPERLINK"), "{}", csv.stdout);

    // Verify: the chain, the agent's and the account's signatures.
    let verified = person.unlocked(&["log", "verify", "--json"], "").ok();
    let report: serde_json::Value = serde_json::from_str(&verified.stdout).expect("json");
    assert_eq!(report["agent_signatures"], 2);
    assert!(report["account_signatures"].as_u64() >= Some(1));
    assert!(report["signed_head"].as_u64().is_some());
    let again = person.unlocked(&["log", "verify", "--json"], "").ok();
    let again: serde_json::Value = serde_json::from_str(&again.stdout).expect("json");
    assert_eq!(again["heads"], 1);
    // Nothing new since: this device does not post the same head again, so
    // verifying often never pushes the other devices' heads out of an
    // older server's latest 100.
    let third = person.unlocked(&["log", "verify", "--json"], "").ok();
    let third: serde_json::Value = serde_json::from_str(&third.stdout).expect("json");
    assert_eq!(third["heads"], 1, "{third}");
    assert_eq!(third["signed_head"], again["signed_head"]);
    let table = person.unlocked(&["log"], "").ok();
    assert!(
        !table.stderr.contains("klav log verify"),
        "{}",
        table.stderr
    );
    let json = person.unlocked(&["log", "--json"], "").ok();
    let events: serde_json::Value = serde_json::from_str(&json.stdout).expect("json");
    assert!(
        events
            .as_array()
            .expect("array")
            .iter()
            .all(|e| e["verified"] == true)
    );

    // The operator puts back an old copy: the second use disappears.
    server.restore("before-second-use");
    let tampered = person.unlocked(&["log", "verify"], "");
    assert_eq!(tampered.code, 3, "{}", tampered.stderr);
    assert!(tampered.stderr.contains("audit log"), "{}", tampered.stderr);
    assert!(
        tampered.stderr.contains("klav log reset"),
        "{}",
        tampered.stderr
    );

    // Accepting the restored chain is a decision the person confirms: with
    // no terminal to ask on, only `--yes` does it.
    let asked = person.run(&["log", "reset"], "y\n");
    assert_ne!(asked.code, 0);
    assert!(asked.stderr.contains("--yes"), "{}", asked.stderr);
    let still = person.unlocked(&["log", "verify"], "");
    assert_eq!(still.code, 3, "{}", still.stderr);
    let reset = person.run(&["log", "reset", "--yes"], "").ok();
    assert!(
        reset
            .stderr
            .contains("Forgot audit-chain.bin and audit-head.json"),
        "{}",
        reset.stderr
    );
    // Nothing left to forget once the copy is gone.
    let twice = person.run(&["log", "reset", "--yes"], "").ok();
    assert!(twice.stderr.contains("no copy"), "{}", twice.stderr);
    let table = person.unlocked(&["log", "--json"], "").ok();
    let events: serde_json::Value = serde_json::from_str(&table.stdout).expect("json");
    assert!(
        events
            .as_array()
            .expect("array")
            .iter()
            .all(|e| e["reason"] != "deploy"),
        "{events}"
    );
    let verified = person.unlocked(&["log", "verify"], "").ok();
    assert!(
        verified.stderr.contains("had not verified the log before"),
        "{}",
        verified.stderr
    );
}

/// `klav log reset` through klavd (ADR 0033 §8.4): klavd forgets the copy
/// it keeps in memory too, so a restored chain is accepted without
/// locking it.
#[test]
fn a_reset_through_klavd_forgets_the_copy_it_keeps_in_memory() {
    let mut server = ServerProcess::start(900);
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
                "GitHub",
                "--secret-stdin",
                "totp",
            ],
            "JBSWY3DPEHPK3PXP\n",
        )
        .ok();
    let machine = Device::new(root.path(), "agent");
    approved_agent(&server, &person, &machine, "bot", &["--allow", "totp"]);
    let reference = "klav://Personal/General/GitHub";
    machine
        .run(&["agent", "totp", reference, "--reason", "first"], "")
        .ok();
    server.snapshot("before-second-use");
    machine
        .run(&["agent", "totp", reference, "--reason", "deploy"], "")
        .ok();

    let _stop = StopDaemon(&person);
    person.unlocked(&["unlock"], "").ok();
    person.run(&["log", "verify"], "").ok();
    server.restore("before-second-use");
    let tampered = person.run(&["log", "verify"], "");
    assert_eq!(tampered.code, 3, "{}", tampered.stderr);
    assert!(
        tampered.stderr.contains("klav log reset"),
        "{}",
        tampered.stderr
    );

    let reset = person.run(&["log", "reset", "--yes"], "").ok();
    assert!(
        reset
            .stderr
            .contains("Forgot audit-chain.bin and audit-head.json"),
        "{}",
        reset.stderr
    );
    // Still unlocked, and klavd no longer holds the longer chain.
    let verified = person.run(&["log", "verify"], "").ok();
    assert!(
        verified.stderr.contains("had not verified the log before"),
        "{}",
        verified.stderr
    );
    let status = json(&person.run(&["status", "--json"], "").ok().stdout);
    assert_eq!(status["klavd"]["unlocked"], true, "{status}");
}

#[test]
fn revoking_blocks_the_agent_and_rotation_keeps_the_others_working() {
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
                "GitHub",
                "--secret-stdin",
                "totp",
            ],
            "JBSWY3DPEHPK3PXP\n",
        )
        .ok();
    let bot = Device::new(root.path(), "bot");
    approved_agent(&server, &person, &bot, "bot", &["--allow", "totp"]);
    let helper = Device::new(root.path(), "helper");
    approved_agent(&server, &person, &helper, "helper", &["--allow", "totp"]);
    let reference = "klav://Personal/General/GitHub";
    bot.run(&["agent", "totp", reference, "--reason", "deploy"], "")
        .ok();
    let denied = bot.run(
        &[
            "agent",
            "totp",
            "klav://Personal/General/Nope",
            "--reason",
            "x",
        ],
        "",
    );
    assert_ne!(denied.code, 0);

    // What it saw, before revoking.
    let shown = person
        .unlocked(&["agent", "show", "bot", "--json"], "")
        .ok();
    let shown = json(&shown.stdout);
    assert_eq!(shown["items"][0]["reference"], reference);
    assert_eq!(shown["items"][0]["permissions"][0], "totp");
    assert_eq!(shown["items"][0]["secret"], true);
    assert_eq!(shown["projects"][0]["project"], "General");

    // Revoke and rotate: the bot is refused at once; the helper gets a new
    // grant with the new key and keeps working; the person still reads.
    let out = person
        .unlocked(
            &["agent", "revoke", "bot", "--rotate", "--yes", "--json"],
            "",
        )
        .ok();
    let report = json(&out.stdout);
    assert_eq!(report["agent"]["status"], "revoked");
    assert_eq!(report["exposure"]["items"][0]["reference"], reference);
    assert_eq!(report["rotated"][0]["items"], 1);
    assert_eq!(report["regranted"][0], "helper");
    let refused = bot.run(&["agent", "totp", reference, "--reason", "deploy"], "");
    assert_ne!(refused.code, 0);
    assert!(
        !refused.stdout.contains(char::is_numeric),
        "{}",
        refused.stdout
    );
    let code = helper
        .run(&["agent", "totp", reference, "--reason", "deploy"], "")
        .ok();
    assert_eq!(code.stdout.trim().len(), 6, "{}", code.stderr);
    person.unlocked(&["item", "get", "GitHub"], "").ok();
    let status = bot.run(&["agent", "status"], "").ok();
    assert!(status.stdout.contains("revoked"), "{}", status.stdout);

    // A second revocation is refused; the log records it and verifies.
    let again = person.unlocked(&["agent", "revoke", "bot", "--yes"], "");
    assert_ne!(again.code, 0);
    let log = person
        .unlocked(&["log", "--agent", "bot", "--json"], "")
        .ok();
    let log = json(&log.stdout);
    assert_eq!(log[0]["action"], "agent.revoked");
    let verified = person.unlocked(&["log", "verify", "--json"], "").ok();
    assert!(json(&verified.stdout)["account_signatures"].as_u64() >= Some(4));

    // The report tells items apart by ID and says when one is in the trash.
    let item_id = report["exposure"]["items"][0]["item_id"]
        .as_str()
        .expect("item id")
        .to_owned();
    person.unlocked(&["item", "rm", "GitHub"], "").ok();
    let shown = person.unlocked(&["agent", "show", "bot"], "").ok();
    let text = format!("{}{}", shown.stdout, shown.stderr);
    assert!(
        text.contains("ID") && text.contains(&item_id[..8]),
        "{text}"
    );
    assert!(text.contains("GitHub (in trash)"), "{text}");
    let shown = person
        .unlocked(&["agent", "show", "bot", "--json"], "")
        .ok();
    assert_eq!(json(&shown.stdout)["items"][0]["trashed"], true);
}

/// The newest request in the person's list.
fn newest_request(person: &Device) -> String {
    let list = person.unlocked(&["approval", "list", "--json"], "").ok();
    let list: serde_json::Value = serde_json::from_str(&list.stdout).expect("json");
    list[0]["id"].as_str().expect("id").to_owned()
}

/// `klav approval wait <id> --json` in the background.
fn spawn_wait(machine: &Device, id: &str) -> std::process::Child {
    machine
        .command()
        .args(["approval", "wait", id, "--timeout", "60s", "--json"])
        .spawn()
        .expect("spawn wait")
}

fn wait_output(child: std::process::Child) -> (i32, serde_json::Value) {
    let out = child.wait_with_output().expect("wait output");
    let stdout = String::from_utf8(out.stdout).expect("utf-8");
    assert_eq!(stdout.lines().count(), 1, "{stdout}");
    (
        out.status.code().unwrap_or(-1),
        serde_json::from_str(&stdout).expect("one JSON line"),
    )
}

/// ADR 0015: the agent waits for the decision with `klav approval wait`
/// (0 approved, 4 pending, 5 denied, 6 expired) and retries with
/// `--approval`, which is spent once and refused for another action.
#[test]
fn approval_wait_and_retry_with_the_approval() {
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
                "GitHub",
                "--username",
                "ana",
                "--secret-stdin",
                "password",
                "--secret-stdin",
                "totp",
            ],
            "MARKER-gh-password\nJBSWY3DPEHPK3PXP\n",
        )
        .ok();
    let machine = Device::new(root.path(), "agent");
    approved_agent(&server, &person, &machine, "bot", &[]);
    let reference = "klav://Personal/General/GitHub";
    let totp = |extra: &[&str]| {
        let mut args = vec!["agent", "totp", reference, "--reason", "log in to GitHub"];
        args.extend_from_slice(extra);
        machine.run(&args, "")
    };

    // Pending: the CLI says how to approve and how to wait.
    let first = totp(&[]);
    assert_eq!(first.code, 4, "{}", first.stderr);
    assert!(
        first.stderr.contains("klav approval wait"),
        "{}",
        first.stderr
    );
    let id = newest_request(&person);
    let short = machine.run(&["approval", "wait", &id, "--timeout", "1s", "--json"], "");
    assert_eq!(short.code, 4, "{}", short.stderr);
    let line: serde_json::Value = serde_json::from_str(&short.stdout).expect("json");
    assert_eq!(line["status"], "pending");

    // Approved while the agent waits in the background.
    let waiter = spawn_wait(&machine, &id);
    std::thread::sleep(std::time::Duration::from_millis(500));
    person.unlocked(&["approval", "approve", &id], "").ok();
    let (code, line) = wait_output(waiter);
    assert_eq!(code, 0, "{line}");
    assert_eq!(line["status"], "approved");
    assert_eq!(line["approval_id"], id.as_str());
    assert_eq!(line["used"], false);

    // Named for another action: refused before doing anything.
    let out = root.path().join("out.env");
    let wrong = machine.run(
        &[
            "agent",
            "inject",
            "--reason",
            "write the env",
            "-r",
            "klav://Personal/General/GitHub/password",
            "-o",
            out.to_str().expect("path"),
            "--approval",
            &id,
        ],
        "",
    );
    assert_ne!(wrong.code, 0);
    assert!(
        wrong.stderr.contains("not for this action"),
        "{}",
        wrong.stderr
    );
    assert!(!out.exists());

    // The retry with it gets the code; it is spent once.
    let code = totp(&["--approval", &id]).ok();
    assert_eq!(code.stdout.trim().len(), 6, "{}", code.stdout);
    assert!(!code.stdout.contains("MARKER") && !code.stderr.contains("MARKER"));
    let again = totp(&["--approval", &id]);
    assert_ne!(again.code, 0);
    assert!(again.stderr.contains("already used"), "{}", again.stderr);
    let (code, line) = wait_output(spawn_wait(&machine, &id));
    assert_eq!((code, &line["used"]), (0, &serde_json::json!(true)));

    // Denied.
    assert_eq!(totp(&[]).code, 4);
    let denied = newest_request(&person);
    assert_ne!(denied, id);
    let waiter = spawn_wait(&machine, &denied);
    std::thread::sleep(std::time::Duration::from_millis(500));
    person.unlocked(&["approval", "deny", &denied], "").ok();
    let (code, line) = wait_output(waiter);
    assert_eq!((code, line["status"].as_str()), (5, Some("denied")));
    let after = totp(&["--approval", &denied]);
    assert_eq!(after.code, 5, "{}", after.stderr);

    // Expired: a new grant voids the pending request. The agent is
    // active, so `approve` shows the differences and signs them (no words
    // asked again; denying `totp` only narrows, so no presence either).
    assert_eq!(totp(&[]).code, 4);
    let expired = newest_request(&person);
    let waiter = spawn_wait(&machine, &expired);
    std::thread::sleep(std::time::Duration::from_millis(500));
    let changed = person
        .unlocked(
            &[
                "agent",
                "approve",
                "bot",
                "--project",
                "Personal/General",
                "--deny",
                "totp",
            ],
            "",
        )
        .ok();
    assert!(
        changed.stderr.contains("totp: ask (default) -> deny")
            && changed.stderr.contains("only narrows"),
        "{}",
        changed.stderr
    );
    let (code, line) = wait_output(waiter);
    assert_eq!((code, line["status"].as_str()), (6, Some("expired")));
}
