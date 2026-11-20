//! `klav health` (ADR 0022 §4), in direct mode and through `klavd`: it
//! names items, hosts and reasons, never values; the breach check is off
//! by default and its setting says what it sends. No test here turns the
//! breach check on before a report: the tests never reach the real service
//! (the client tests check it against a local stand-in).

mod common;

use common::{Device, ServerProcess};

const SHARED: &str = "MARKER-Vq7#kL2!zR9-shared";
const WEAK: &str = "password1";

/// Stops the daemon even if the test fails.
struct StopDaemon<'a>(&'a Device);

impl Drop for StopDaemon<'_> {
    fn drop(&mut self) {
        let _ = self.0.run(&["lock", "--stop"], "");
    }
}

fn add_login(device: &Device, title: &str, url: &str, password: &str) {
    device
        .unlocked(
            &[
                "item",
                "add",
                "login",
                "--title",
                title,
                "--url",
                url,
                "--secret-stdin",
                "password",
            ],
            &format!("{password}\n"),
        )
        .ok();
}

fn check_report(json: &str) {
    for secret in [SHARED, WEAK, "MARKER"] {
        assert!(!json.contains(secret), "{secret} in the report");
    }
    let report: serde_json::Value = serde_json::from_str(json).expect("health json");
    assert_eq!(report["passwords"], 3);
    let reused = report["reused"].as_array().expect("reused");
    assert_eq!(reused.len(), 1);
    let titles: Vec<&str> = reused[0]["items"]
        .as_array()
        .expect("items")
        .iter()
        .map(|i| i["title"].as_str().expect("title"))
        .collect();
    assert_eq!(titles, ["Bank", "Shop"]);
    assert_eq!(reused[0]["items"][0]["hosts"][0], "bank.example");
    let weak = report["weak"].as_array().expect("weak");
    assert_eq!(weak.len(), 1);
    assert_eq!(weak[0]["item"]["title"], "Forum");
    assert_eq!(report["old"].as_array().map(Vec::len), Some(0));
    assert_eq!(report["breaches"]["status"], "off");
}

#[test]
fn health_names_items_and_reasons_but_never_values() {
    let server = ServerProcess::start(900);
    let root = tempfile::tempdir().expect("tempdir");
    let device = Device::new(root.path(), "home");
    device.signup(&server, "health@example.com");
    add_login(&device, "Bank", "https://bank.example/login", SHARED);
    add_login(&device, "Shop", "https://shop.example/", SHARED);
    add_login(&device, "Forum", "https://forum.example/", WEAK);

    // Direct mode.
    let out = device
        .unlocked(&["--no-daemon", "health", "--json"], "")
        .ok();
    check_report(&out.stdout);
    let text = device.unlocked(&["--no-daemon", "health"], "").ok();
    let all = format!("{}{}", text.stdout, text.stderr);
    for secret in [SHARED, WEAK] {
        assert!(!all.contains(secret), "{secret} printed");
    }
    assert!(text.stdout.contains("Reused: 1 group"), "{}", text.stdout);
    assert!(text.stdout.contains("bank.example"), "{}", text.stdout);
    assert!(text.stdout.contains("Weak: 1"), "{}", text.stdout);
    assert!(text.stdout.contains("Forum"), "{}", text.stdout);
    assert!(
        text.stdout.contains("Breached: not checked"),
        "{}",
        text.stdout
    );

    // The breach check: off by default, local, and it says what it sends.
    let status = device.run(&["health", "breach-check"], "").ok();
    assert_eq!(status.stdout.trim(), "Breach check: off");
    assert!(
        status.stderr.contains("first 5 characters"),
        "{}",
        status.stderr
    );
    assert!(status.stderr.contains("IP address"), "{}", status.stderr);
    let on = device.run(&["health", "breach-check", "on"], "").ok();
    assert_eq!(on.stdout.trim(), "Breach check: on");
    let settings = std::fs::read_to_string(device.home.join("health.json")).expect("health.json");
    assert!(settings.contains("\"breach_check\": true"), "{settings}");
    device.run(&["health", "breach-check", "off"], "").ok();
    let status = device.run(&["health", "breach-check"], "").ok();
    assert_eq!(status.stdout.trim(), "Breach check: off");

    // Through klavd.
    common::built_binary("klavd");
    let _stop = StopDaemon(&device);
    device.unlocked(&["unlock", "--idle-lock", "10m"], "").ok();
    let out = device.run(&["health", "--json"], "").ok();
    check_report(&out.stdout);
}
