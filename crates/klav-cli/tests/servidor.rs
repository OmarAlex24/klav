//! The default server (ADR 0028) in the `klav` binary, without the real
//! network: the test harness sets `KLAV_NO_DEFAULT_SERVER`, a closed
//! registration is said before any password, `klav status` reports a move
//! once, `klav account kit` and `klav account set-server`, and an agent
//! that moves only when the new host answers for it.

mod common;

use common::{Device, ServerProcess};
use klav_client::Home;
use klav_sdk::Agent;

fn json(out: &str) -> serde_json::Value {
    serde_json::from_str(out).expect("json output")
}

/// The same server under its other loopback name.
fn other_name(url: &str) -> String {
    url.replace("127.0.0.1", "localhost")
}

#[test]
fn without_a_server_tests_fail_as_before() {
    let root = tempfile::tempdir().expect("tempdir");
    let device = Device::new(root.path(), "a");
    let kit = root.path().join("kit.txt");
    for args in [
        vec![
            "signup",
            "--email",
            "ana@example.com",
            "--emergency-kit",
            kit.to_str().unwrap(),
        ],
        vec!["login", "--email", "ana@example.com"],
    ] {
        let out = device.run(&args, "").err();
        assert_eq!(out.code, 2, "{}", out.stderr);
        assert!(
            out.stderr.contains("give the server with --server"),
            "{}",
            out.stderr
        );
        assert!(!out.stderr.contains("klav.dev"), "{}", out.stderr);
    }
    assert!(!kit.exists());
}

#[test]
fn a_closed_registration_is_said_before_the_password() {
    let server = ServerProcess::start_closed();
    let root = tempfile::tempdir().expect("tempdir");
    let device = Device::new(root.path(), "a");
    let kit = root.path().join("kit.txt");
    // No password on stdin: asking for one would fail differently.
    let out = device
        .run(
            &[
                "signup",
                "--server",
                &format!("{}/", server.url),
                "--email",
                "ana@example.com",
                "--emergency-kit",
                kit.to_str().unwrap(),
            ],
            "",
        )
        .err();
    assert!(
        out.stderr
            .contains(&format!("Server: {} (127.0.0.1).", server.url)),
        "{}",
        out.stderr
    );
    assert!(
        out.stderr
            .contains("Registration on 127.0.0.1 is not open yet. You can host your own server: https://docs.klav.dev/self-hosting/"),
        "{}",
        out.stderr
    );
    assert!(
        !out.stderr.to_lowercase().contains("password"),
        "{}",
        out.stderr
    );
    assert!(!kit.exists());
    assert!(!device.home.join("account.json").exists());
}

#[test]
fn status_reports_a_move_once_and_the_kit_and_set_server_work() {
    let server = ServerProcess::start(900);
    let root = tempfile::tempdir().expect("tempdir");
    let device = Device::new(root.path(), "a");
    device.signup(&server, "ana@example.com");

    // What a migration leaves behind (ADR 0028 §4).
    std::fs::write(
        device.home.join("server-moved"),
        "https://klav-server-production.up.railway.app\n",
    )
    .unwrap();
    let first = device.run(&["status"], "").ok().stdout;
    assert!(
        first.contains(&format!(
            "server:    {} (moved from klav-server-production.up.railway.app)",
            server.url
        )),
        "{first}"
    );
    let second = device.run(&["status"], "").ok().stdout;
    assert!(
        second.contains(&format!("server:    {}\n", server.url)),
        "{second}"
    );
    assert!(!second.contains("moved from"), "{second}");
    assert!(!device.home.join("server-moved").exists());

    // The kit again, after the master password, with today's server.
    let kit = root.path().join("again.txt");
    let wrong = device.run(
        &[
            "--password-stdin",
            "account",
            "kit",
            "--emergency-kit",
            kit.to_str().unwrap(),
        ],
        "wrong password\n",
    );
    assert_ne!(wrong.code, 0);
    assert!(!kit.exists());
    device
        .unlocked(
            &["account", "kit", "--emergency-kit", kit.to_str().unwrap()],
            "",
        )
        .ok();
    assert_eq!(common::mode(&kit), 0o600);
    let text = std::fs::read_to_string(&kit).unwrap();
    assert!(text.contains(&format!("Server:     {}\n", server.url)));
    assert!(text.contains("E-mail:     ana@example.com"));
    assert!(text.contains("Secret Key: K1-"));
    // Never overwrites.
    device
        .unlocked(
            &["account", "kit", "--emergency-kit", kit.to_str().unwrap()],
            "",
        )
        .err();

    // Move by hand to the same server under another name.
    let new = other_name(&server.url);
    let moved = device.unlocked(&["account", "set-server", &new], "").ok();
    assert!(
        moved.stderr.contains(&format!("now uses {new}")),
        "{}",
        moved.stderr
    );
    let status = json(&device.run(&["status", "--json"], "").ok().stdout);
    assert_eq!(status["server"], new.as_str());
    device.unlocked(&["sync"], "").ok();

    // A server without this account: refused, nothing changes.
    let other = ServerProcess::start(900);
    device
        .unlocked(&["account", "set-server", &other.url], "")
        .err();
    let status = json(&device.run(&["status", "--json"], "").ok().stdout);
    assert_eq!(status["server"], new.as_str());
}

#[tokio::test(flavor = "multi_thread")]
async fn an_agent_moves_only_when_the_new_host_answers_for_it() {
    let server = ServerProcess::start(900);
    let other = ServerProcess::start(900);
    let root = tempfile::tempdir().expect("tempdir");
    let person = Device::new(root.path(), "person");
    person.signup(&server, "ana@example.com");
    let machine = Device::new(root.path(), "agent");
    let words = machine
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
    let home = Home::at(&machine.home);
    let new = other_name(&server.url);

    // Not pinned yet: nothing to compare with, so it stays.
    let mut agent = Agent::load(&home, "bot").expect("agent");
    assert_eq!(
        agent
            .migrate_server_with(&[(server.url.as_str(), new.as_str())])
            .await,
        None
    );

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
    // `agent status` pins the account identity.
    let status = json(&machine.run(&["agent", "status", "--json"], "").ok().stdout);
    assert_eq!(status["status"], "active");

    // Another server does not know this agent: it stays.
    let mut agent = Agent::load(&home, "bot").expect("agent");
    assert_eq!(
        agent
            .migrate_server_with(&[(server.url.as_str(), other.url.as_str())])
            .await,
        None
    );
    assert_eq!(agent.config().server, server.url);

    // The same server under another name answers for it: it moves.
    assert_eq!(
        agent
            .migrate_server_with(&[(server.url.as_str(), new.as_str())])
            .await
            .as_deref(),
        Some(new.as_str())
    );
    assert_eq!(Agent::load(&home, "bot").unwrap().config().server, new);
    let status = json(&machine.run(&["agent", "status", "--json"], "").ok().stdout);
    assert_eq!(status["server"], new.as_str());
    assert_eq!(status["status"], "active");
}
