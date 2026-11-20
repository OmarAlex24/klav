//! Deleting the account from the CLI (ADR 0037): only a person at a
//! terminal asks (T164), and not with `--no-daemon` where Touch ID is set
//! up (A1); every agent stops with exit 8 and `klav mcp` tells the LLM to
//! stop; any device cancels, with Touch ID or the master password as
//! resuming agents asks (A2); `klav status` shows the date; and `klav
//! logout` is the only thing that deletes this device's copy (T165), never
//! with generated passwords not uploaded yet unless the person says so.
//!
//! Asking needs a terminal, which a test does not have: the tests ask
//! through `klav-client`, as `klav account delete` does after its checks.

mod common;

use common::mcp::Mcp;
use common::{Device, PASSWORD, ServerProcess};
use klav_client::Home;
use klav_client::deletion::{self, AccountDeletion};
use klav_core::crypto::kdf::MasterPassword;
use serde_json::{Value, json};

const REFERENCE: &str = "klav://Personal/General/GitHub";
const EMAIL: &str = "ana@example.com";

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

/// What `klav account delete` does once the person typed the email and
/// the password at a terminal.
fn ask(person: &Device) -> AccountDeletion {
    let runtime = tokio::runtime::Runtime::new().expect("runtime");
    runtime
        .block_on(deletion::request_account_deletion(
            &Home::at(&person.home),
            &MasterPassword::new(PASSWORD),
        ))
        .expect("ask")
        .1
}

fn person_with_login(server: &ServerProcess, root: &std::path::Path) -> Device {
    let person = Device::new(root, "person");
    person.signup(server, EMAIL);
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

/// Agent `name` on its own machine, approved with `totp` allowed.
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
                EMAIL,
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
fn only_a_person_at_a_terminal_asks_and_every_agent_stops_with_exit_8() {
    let server = ServerProcess::start(900);
    let root = tempfile::tempdir().expect("tempdir");
    let person = person_with_login(&server, root.path());
    let bot = Device::new(root.path(), "bot");
    approved(&server, &person, &bot, "bot");
    assert_eq!(totp(&bot), 0);

    // T164: no program asks. Not with the password on stdin, not with
    // stdin piped, not with a `--yes`; and nothing was asked.
    let out = person.run(
        &["--password-stdin", "account", "delete"],
        &format!("{PASSWORD}\n"),
    );
    assert_eq!(out.code, 2, "{}", out.stderr);
    assert!(out.stderr.contains("--password-stdin"), "{}", out.stderr);
    let out = person.run(&["account", "delete"], &format!("{EMAIL}\n{PASSWORD}\n"));
    assert_ne!(out.code, 0);
    assert!(out.stderr.contains("needs a terminal"), "{}", out.stderr);
    let out = person.run(&["account", "delete", "--yes"], "");
    assert_eq!(out.code, 2, "{}", out.stderr);
    assert_eq!(totp(&bot), 0, "nothing was asked");

    // Asked: every agent is refused at once with exit 8 (ADR 0037 §3).
    let asked = ask(&person);
    let refused = bot.run(&["agent", "totp", REFERENCE, "--reason", "deploy"], "");
    assert_eq!(refused.code, 8, "{}", refused.stderr);
    assert!(
        refused.stderr.contains("account_deleting"),
        "{}",
        refused.stderr
    );
    assert!(
        refused.stderr.contains("do not retry"),
        "{}",
        refused.stderr
    );
    // The agent sees why; `--wait` stops at once with exit 8.
    let status = bot.run(&["agent", "status"], "").ok();
    assert!(status.stdout.contains("deleting:"), "{}", status.stdout);
    let status = json_of(&bot.run(&["agent", "status", "--json"], "").ok().stdout);
    assert_eq!(status["account_delete_at"], asked.delete_at);
    assert_eq!(bot.run(&["agent", "status", "--wait"], "").code, 8);

    // `klav mcp` tells the LLM to stop and tell the person.
    let repo = root.path().join("repo");
    std::fs::create_dir_all(&repo).expect("repo");
    let mut mcp = Mcp::start(&bot, &repo, None);
    mcp.initialize();
    let (text, err) = mcp.tool("get_totp", json!({ "ref": REFERENCE, "reason": "deploy" }));
    assert!(err, "{text}");
    let answer: Value = serde_json::from_str(&text).expect("account_deleting json");
    assert_eq!(answer["status"], "account_deleting");
    assert_eq!(answer["delete_at"], asked.delete_at);
    assert_eq!(
        answer["next"],
        "The person asked Klav to delete this account. Stop and tell the person; do not retry."
    );
    drop(mcp);

    // Any device cancels it, here in direct mode; the agents work again.
    let out = person.unlocked(&["account", "delete", "--cancel"], "").ok();
    assert!(
        out.stderr.contains("The deletion was canceled"),
        "{}",
        out.stderr
    );
    assert_eq!(totp(&bot), 0);
    let out = person.unlocked(&["account", "delete", "--cancel"], "").ok();
    assert!(
        out.stderr
            .contains("No deletion of this account is scheduled"),
        "{}",
        out.stderr
    );
}

#[test]
fn klavd_shows_the_date_in_status_and_cancels_with_presence() {
    // Access tokens shorter than the refresh margin: every request
    // refreshes, so `klav account delete` and the running klavd, on the
    // same `KLAV_HOME`, both rotate the refresh token.
    let server = ServerProcess::start(20);
    let root = tempfile::tempdir().expect("tempdir");
    let person = person_with_login(&server, root.path());
    let _stop = StopDaemon(&person);
    person.unlocked(&["unlock", "--idle-lock", "10m"], "").ok();

    // As `klav account delete` does with klavd unlocked: asked in this
    // process, then klavd told to sync.
    let asked = ask(&person);
    person.run(&["sync"], "").ok();
    let status = json_of(&person.run(&["status", "--json"], "").ok().stdout);
    assert_eq!(status["deletion"]["delete_at"], asked.delete_at, "{status}");
    assert_eq!(
        status["klavd"]["account_deletion"]["delete_at"],
        asked.delete_at
    );
    let text = person.run(&["status"], "").ok();
    assert!(
        text.stdout.contains("deletion:  the account is deleted on"),
        "{}",
        text.stdout
    );

    // A2: canceling brings the agents back, so even an unlocked klavd
    // asks for presence, as `klav agent resume` does. Touch ID is off in
    // tests and stdin is empty: refused, and the deletion stays.
    let out = person.run(&["account", "delete", "--cancel"], "");
    assert_ne!(out.code, 0, "canceled without presence: {}", out.stderr);
    assert!(
        out.stderr.contains("confirm with the master password"),
        "{}",
        out.stderr
    );
    let status = json_of(&person.run(&["status", "--json"], "").ok().stdout);
    assert_eq!(status["deletion"]["delete_at"], asked.delete_at, "{status}");
    // With the master password, it cancels.
    let out = person.unlocked(&["account", "delete", "--cancel"], "").ok();
    assert!(
        out.stderr.contains("The deletion was canceled"),
        "{}",
        out.stderr
    );
    let status = json_of(&person.run(&["status", "--json"], "").ok().stdout);
    assert!(status.get("deletion").is_none(), "{status}");
    // klavd's session survived both: it still syncs.
    person.run(&["sync"], "").ok();
}

/// A1: where klavd has Touch ID set up, `--no-daemon` would skip it, so
/// `klav --no-daemon account delete` refuses before it asks anything, and
/// says how to delete instead.
#[test]
fn no_daemon_refuses_where_touch_id_is_set_up() {
    let server = ServerProcess::start(900);
    let root = tempfile::tempdir().expect("tempdir");
    let person = person_with_login(&server, root.path());

    // Without Touch ID set up, `--no-daemon` gets as far as the terminal
    // check (the password alone is the rule there).
    let out = person.run(&["--no-daemon", "account", "delete"], "");
    assert_ne!(out.code, 0);
    assert!(out.stderr.contains("needs a terminal"), "{}", out.stderr);

    // Only the enrolment counts, not whether Touch ID answers now.
    let enrolment = person.home.join("touchid.json");
    std::fs::write(&enrolment, "{}").expect("enrolment");
    let out = person.run(&["--no-daemon", "account", "delete"], "");
    assert_ne!(out.code, 0);
    for said in [
        "--no-daemon",
        "Touch ID",
        "the Klav app on this Mac",
        "iPhone",
    ] {
        assert!(out.stderr.contains(said), "{said}: {}", out.stderr);
    }
    assert!(!out.stderr.contains("needs a terminal"), "{}", out.stderr);
    std::fs::remove_file(&enrolment).expect("remove enrolment");
}

/// Review finding 1: `klav logout` never deletes generated passwords that
/// did not reach the server (no network, or an account the server
/// deleted) unless the person says to lose them.
#[test]
fn logout_keeps_what_is_not_uploaded_unless_told() {
    let mut server = ServerProcess::start(900);
    let root = tempfile::tempdir().expect("tempdir");
    let person = person_with_login(&server, root.path());
    let _stop = StopDaemon(&person);
    person.unlocked(&["unlock", "--idle-lock", "10m"], "").ok();
    // No server: what klavd generates waits in its outbox.
    server.stop();
    let made = person
        .run(&["generate", "--site", "https://github.com/login"], "")
        .ok();
    assert!(!made.stderr.contains("not kept"), "{}", made.stderr);

    let out = person.unlocked(&["logout", "--yes"], "");
    assert_ne!(out.code, 0, "{}", out.stderr);
    assert!(
        out.stderr
            .contains("1 generated password(s) not uploaded yet"),
        "{}",
        out.stderr
    );
    assert!(out.stderr.contains("--discard-unsent"), "{}", out.stderr);
    for name in ["account.json", "cache.bin", "generator-outbox.bin"] {
        assert!(person.home.join(name).exists(), "{name} was deleted");
    }

    // Told to lose them: signed out, and the server could not be told.
    let out = person
        .unlocked(&["logout", "--yes", "--discard-unsent"], "")
        .ok();
    assert!(out.stderr.contains("Signed out"), "{}", out.stderr);
    assert!(out.stderr.contains("did not end"), "{}", out.stderr);
    for name in [
        "account.json",
        "cache.bin",
        "session.bin",
        "secret-key",
        "generator-outbox.bin",
    ] {
        assert!(!person.home.join(name).exists(), "{name} is left");
    }
}

#[test]
fn logout_deletes_this_devices_copy_only_with_a_yes() {
    let server = ServerProcess::start(900);
    let root = tempfile::tempdir().expect("tempdir");
    let person = person_with_login(&server, root.path());
    let account = person.home.join("account.json");

    // Without a terminal, only `--yes` confirms it.
    let out = person.run(&["logout"], "");
    assert_ne!(out.code, 0);
    assert!(out.stderr.contains("--yes"), "{}", out.stderr);
    assert!(account.exists());

    let out = person.unlocked(&["logout", "--yes"], "").ok();
    assert!(out.stderr.contains("Signed out"), "{}", out.stderr);
    for name in ["account.json", "cache.bin", "session.bin", "secret-key"] {
        assert!(!person.home.join(name).exists(), "{name} is left");
    }
    // Nothing to sign out of any more.
    let out = person.run(&["logout", "--yes"], "").ok();
    assert!(
        out.stderr.contains("No account on this device"),
        "{}",
        out.stderr
    );
}

/// Moves the deletion of every account to `at` (Unix ms), in the server's
/// SQLite database. `false` without the `sqlite3` program.
fn move_delete_at(server: &ServerProcess, at: i64) -> bool {
    let sql = format!("PRAGMA busy_timeout = 5000; UPDATE account_deletions SET delete_at = {at};");
    match std::process::Command::new("sqlite3")
        .arg(server.dir.path().join("klav.db"))
        .arg(sql)
        .output()
    {
        Ok(out) => {
            assert!(
                out.status.success(),
                "sqlite3: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            true
        }
        Err(_) => {
            eprintln!("no sqlite3 here: the deleted account is not checked");
            false
        }
    }
}

fn now_ms() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_millis(),
    )
    .expect("ms")
}

#[test]
fn after_the_deletion_the_cli_says_so_and_logout_still_works() {
    let server = ServerProcess::start_purging();
    let root = tempfile::tempdir().expect("tempdir");
    let person = person_with_login(&server, root.path());
    ask(&person);
    // The time comes in a few seconds; this device syncs before it.
    let delete_at = now_ms() + 10_000;
    if !move_delete_at(&server, delete_at) {
        return;
    }
    person.unlocked(&["sync"], "").ok();
    assert!(
        now_ms() < delete_at,
        "too slow: the sync must learn the date before the purge"
    );
    assert!(common::wait_until(30, || now_ms() > delete_at + 1_500));

    // "Klav deleted your account", not an expired session, and the copy
    // stays: it still reads.
    let out = person.unlocked(&["sync"], "").err();
    assert!(
        out.stderr.contains("Klav deleted your account"),
        "{}",
        out.stderr
    );
    assert!(out.stderr.contains("klav logout"), "{}", out.stderr);
    assert!(person.home.join("cache.bin").exists());
    person
        .unlocked(&["item", "get", "GitHub", "--json"], "")
        .ok();

    // Signing out works with no account on the server.
    let out = person.unlocked(&["logout", "--yes"], "").ok();
    assert!(out.stderr.contains("Signed out"), "{}", out.stderr);
    assert!(
        !out.stderr.contains("did not end"),
        "a deleted account is not a failure: {}",
        out.stderr
    );
    for name in ["account.json", "cache.bin", "session.bin", "deletion.bin"] {
        assert!(!person.home.join(name).exists(), "{name} is left");
    }
}
