//! Pausing agents (ADR 0033 §7): the person pauses every agent, or one,
//! and an agent on another machine (its own `KLAV_HOME`) is refused by the
//! server with `agents_paused` (exit 7) until the person resumes it; `klav
//! mcp` tells the LLM to stop. Through `klavd`, pausing every agent works
//! locked: it holds on this computer at once and reaches the server after
//! the next unlock.

mod common;

use common::mcp::Mcp;
use common::{Device, ServerProcess};
use serde_json::{Value, json};

const REFERENCE: &str = "klav://Personal/General/GitHub";

/// Stops the daemon even if the test fails.
struct StopDaemon<'a>(&'a Device);

impl Drop for StopDaemon<'_> {
    fn drop(&mut self) {
        let _ = self.0.run(&["lock", "--stop"], "");
    }
}

fn json_of(out: &str) -> Value {
    serde_json::from_str(out).expect("json output")
}

/// A person with a TOTP login, and agent `name` on its own machine,
/// approved with `totp` allowed.
fn approved(server: &ServerProcess, person: &Device, machine: &Device, name: &str) {
    let words = machine
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
        .to_owned();
    person
        .unlocked(
            &[
                "agent",
                "approve",
                name,
                "--project",
                "Personal/General",
                "--words",
                &words,
                "--allow",
                "totp",
            ],
            "",
        )
        .ok();
}

fn person_with_login(server: &ServerProcess, root: &std::path::Path) -> Device {
    let person = Device::new(root, "person");
    person.signup(server, "ana@example.com");
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
    person
}

/// The agent asks for a code: `0` with six digits, or its exit code.
fn totp(agent: &Device) -> i32 {
    let out = agent.run(&["agent", "totp", REFERENCE, "--reason", "deploy"], "");
    if out.code == 0 {
        assert_eq!(out.stdout.trim().len(), 6, "{}", out.stderr);
    } else {
        assert!(
            !out.stdout.contains(char::is_numeric),
            "a refused agent got a code: {}",
            out.stdout
        );
    }
    out.code
}

#[test]
fn a_paused_agent_elsewhere_is_refused_with_exit_7_until_the_person_resumes() {
    let server = ServerProcess::start(900);
    let root = tempfile::tempdir().expect("tempdir");
    let person = person_with_login(&server, root.path());
    let bot = Device::new(root.path(), "bot");
    approved(&server, &person, &bot, "bot");
    let helper = Device::new(root.path(), "helper");
    approved(&server, &person, &helper, "helper");
    assert_eq!(totp(&bot), 0);

    // Every agent, until the person resumes (direct mode: the master
    // password unlocks this process; pausing asks for nothing more).
    let out = person.unlocked(&["agent", "pause", "--all"], "").ok();
    assert!(out.stderr.contains("Every agent paused"), "{}", out.stderr);
    let refused = bot.run(&["agent", "totp", REFERENCE, "--reason", "deploy"], "");
    assert_eq!(refused.code, 7, "{}", refused.stderr);
    assert!(
        refused.stderr.contains("agents_paused"),
        "{}",
        refused.stderr
    );
    assert!(
        refused.stderr.contains("do not retry"),
        "{}",
        refused.stderr
    );
    assert_eq!(totp(&helper), 7);
    // The agent sees why, and `--wait` stops at once with exit 7.
    let status = bot.run(&["agent", "status"], "").ok();
    assert!(
        status.stdout.contains("paused:    every agent"),
        "{}",
        status.stdout
    );
    let status = bot.run(&["agent", "status", "--json"], "").ok();
    assert_eq!(json_of(&status.stdout)["paused"]["scope"], "all");
    assert_eq!(bot.run(&["agent", "status", "--wait"], "").code, 7);

    // `klav mcp` answers the LLM to stop and tell the person.
    let repo = root.path().join("repo");
    std::fs::create_dir_all(&repo).expect("repo");
    let mut mcp = Mcp::start(&bot, &repo, None);
    mcp.initialize();
    let (text, err) = mcp.tool("get_totp", json!({ "ref": REFERENCE, "reason": "deploy" }));
    assert!(err, "{text}");
    let answer: Value = serde_json::from_str(&text).expect("paused json");
    assert_eq!(answer["status"], "paused");
    assert_eq!(answer["scope"], "all");
    assert!(
        answer["next"]
            .as_str()
            .is_some_and(|n| n.contains("ask them to resume")),
        "{text}"
    );
    drop(mcp);

    // The person's list says so.
    let list = person.unlocked(&["agent", "list", "--json"], "").ok();
    let list = json_of(&list.stdout);
    assert!(
        list.as_array()
            .expect("agents")
            .iter()
            .all(|a| a["paused"]["scope"] == "all"),
        "{list}"
    );

    // Resuming (the master password is the presence here) lets them work.
    let out = person.unlocked(&["agent", "resume", "--all"], "").ok();
    assert!(out.stderr.contains("Every agent resumed"), "{}", out.stderr);
    assert_eq!(totp(&bot), 0);
    assert_eq!(totp(&helper), 0);

    // One agent, for an hour: the other keeps working.
    person
        .unlocked(&["agent", "pause", "bot", "--for", "1h"], "")
        .ok();
    assert_eq!(totp(&bot), 7);
    assert_eq!(totp(&helper), 0);
    let table = person.unlocked(&["agent", "list"], "").ok();
    let bot_row = table
        .stdout
        .lines()
        .find(|l| l.starts_with("bot "))
        .expect("bot row");
    assert!(bot_row.contains("until "), "{}", table.stdout);
    assert!(table.stdout.contains("PAUSED"), "{}", table.stdout);
    // Resuming every agent does not lift a single agent's pause.
    let out = person.unlocked(&["agent", "resume", "--all"], "").ok();
    assert!(out.stderr.contains("still paused: agent"), "{}", out.stderr);
    assert_eq!(totp(&bot), 7);
    person.unlocked(&["agent", "resume", "bot"], "").ok();
    assert_eq!(totp(&bot), 0);

    // The log has every decision, signed by the account, and verifies.
    let log = json_of(&person.unlocked(&["log", "--json"], "").ok().stdout);
    let count = |action: &str| {
        log.as_array()
            .expect("events")
            .iter()
            .filter(|e| e["action"] == action)
            .count()
    };
    assert_eq!(count("agents.paused"), 2, "{log}");
    assert_eq!(count("agents.resumed"), 3, "{log}");
    let verified = person.unlocked(&["log", "verify", "--json"], "").ok();
    let verified = json_of(&verified.stdout);
    assert!(
        verified["warnings"]
            .as_array()
            .is_none_or(|w| w.iter().all(|w| !w.to_string().contains("pause"))),
        "{verified}"
    );
}

#[test]
fn klavd_pauses_every_agent_while_locked_and_signs_it_after_unlock() {
    let server = ServerProcess::start(900);
    let root = tempfile::tempdir().expect("tempdir");
    let person = person_with_login(&server, root.path());
    let bot = Device::new(root.path(), "bot");
    approved(&server, &person, &bot, "bot");
    let _stop = StopDaemon(&person);
    person.unlocked(&["unlock", "--idle-lock", "10m"], "").ok();
    person.run(&["lock"], "").ok();

    // Locked: one click, no password. It holds on this computer only.
    let out = person.run(&["agent", "pause", "--all", "--json"], "").ok();
    assert!(
        out.stderr.contains("on this computer only"),
        "{}",
        out.stderr
    );
    let pauses = json_of(&out.stdout);
    assert_eq!(pauses[0]["local"], true, "{pauses}");
    let status = person.run(&["status", "--json"], "").ok();
    let status = json_of(&status.stdout);
    assert_eq!(status["klavd"]["unlocked"], false);
    assert_eq!(status["klavd"]["agents_paused"][0]["local"], true);
    // The server does not know yet: an agent that does not go through
    // klavd still works (ADR 0033 §7.2, said so in the warning).
    assert_eq!(totp(&bot), 0);
    // The unlock signs and sends it: now the server refuses the agent.
    person.unlocked(&["unlock"], "").ok();
    let status = json_of(&person.run(&["status", "--json"], "").ok().stdout);
    let paused = &status["klavd"]["agents_paused"];
    assert_eq!(paused.as_array().map(Vec::len), Some(1), "{status}");
    assert!(paused[0].get("local").is_none(), "{status}");
    assert_eq!(totp(&bot), 7);

    // Resuming through klavd asks for presence: Touch ID is off in tests,
    // so the master password.
    let out = person.unlocked(&["agent", "resume", "--all"], "").ok();
    assert!(out.stderr.contains("Every agent resumed"), "{}", out.stderr);
    assert_eq!(totp(&bot), 0);
    let status = json_of(&person.run(&["status", "--json"], "").ok().stdout);
    assert!(status["klavd"].get("agents_paused").is_none(), "{status}");
}

/// A pause decided while locked survives a restart of klavd (it waits in
/// `$KLAV_HOME/local-pauses.json`, 0600, with no secret), and the unlock
/// signs it even when the server already has a later decision, from a
/// device whose clock runs ahead: just after that one (ADR 0033 §7.6).
#[test]
fn a_pause_decided_locked_survives_a_restart_and_a_later_decision() {
    let server = ServerProcess::start(900);
    let root = tempfile::tempdir().expect("tempdir");
    let person = person_with_login(&server, root.path());
    let bot = Device::new(root.path(), "bot");
    approved(&server, &person, &bot, "bot");
    let _stop = StopDaemon(&person);
    person.unlocked(&["unlock", "--idle-lock", "10m"], "").ok();
    person.run(&["lock"], "").ok();
    person.run(&["agent", "pause", "--all"], "").ok();

    let file = person.home.join("local-pauses.json");
    assert_eq!(common::mode(&file), 0o600);
    let saved: Value =
        serde_json::from_str(&std::fs::read_to_string(&file).expect("local pauses")).expect("json");
    assert_eq!(saved["v"], 1, "{saved}");
    let pause = &saved["pauses"][0];
    assert_eq!(pause["locked"], true, "{saved}");
    // The program it came through, when the system says (macOS with
    // Klav's Swift shim): here, `klav`. Elsewhere (Linux CI) klavd cannot
    // tell, and says so.
    let from = match pause.get("source").map(|s| s.as_str()) {
        Some(Some("terminal")) => "from the terminal",
        None => "from a program Klav does not recognize",
        Some(other) => panic!("source {other:?}: {saved}"),
    };
    let mut keys: Vec<&str> = pause
        .as_object()
        .expect("object")
        .keys()
        .map(String::as_str)
        .filter(|k| *k != "source")
        .collect();
    keys.sort_unstable();
    assert_eq!(keys, ["account", "at", "locked", "until"], "{saved}");
    person.run(&["lock", "--stop"], "").ok();

    // Meanwhile another device, its clock 4 minutes ahead, resumed every
    // agent: that decision is later than any this computer signs now.
    let ahead = now_ms() + 4 * 60 * 1000;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
        .block_on(async {
            let mut ana = klav_client::unlock_with_password(
                &klav_client::Home::at(&person.home),
                &klav_core::crypto::kdf::MasterPassword::new(common::PASSWORD),
            )
            .expect("unlock");
            let resume = ana.sign_pause(None, false, ahead, 0);
            ana.send_pause(None, &resume).await.expect("resume");
        });
    assert_eq!(totp(&bot), 0);

    // A new klavd still holds the pause, and its unlock signs it after
    // that resume; the person hears it was decided locked, and where.
    let out = person.unlocked(&["unlock"], "").ok();
    assert!(
        out.stderr
            .contains(&format!("decided while Klav was locked ({from})")),
        "{}",
        out.stderr
    );
    assert_eq!(totp(&bot), 7);
    let status = json_of(&person.run(&["status", "--json"], "").ok().stdout);
    let paused = &status["klavd"]["agents_paused"];
    assert_eq!(paused.as_array().map(Vec::len), Some(1), "{status}");
    assert!(paused[0].get("local").is_none(), "{status}");
    assert!(paused[0]["since"].as_i64() > Some(ahead), "{status}");
    assert!(!file.exists(), "nothing waits here any more");
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}
