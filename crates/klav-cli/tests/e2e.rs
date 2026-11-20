//! Phase 3 end to end, with the real binaries only: `klav-server`
//! (SQLite) and `klav`.
//!
//! signup → login item with TOTP + API key → `klav run` gives a child the
//! key in its environment → `klav inject` writes a 0600 file and removes
//! it at the TTL → a second device logs in and syncs → a server rolled
//! back to an old snapshot is refused (exit code 3) and nothing is lost.

mod common;

use common::{Device, ServerProcess, mode, wait_child, wait_until};

const GH_PASSWORD: &str = "MARKER-e2e-gh-Qw9";
const API_KEY: &str = "sk_live_MARKER_e2e_77";

#[test]
fn phase_3_end_to_end() {
    // Access tokens outlive the test: restoring the snapshot must only roll
    // back vault data, not the refresh tokens (they would be stale too).
    let mut server = ServerProcess::start(900);
    let root = tempfile::tempdir().expect("tempdir");
    let laptop = Device::new(root.path(), "laptop");
    let kit = laptop.signup(&server, "e2e@example.com");

    // A login with a TOTP seed, and an API key.
    laptop
        .unlocked(
            &[
                "item",
                "add",
                "login",
                "--title",
                "GitHub",
                "--username",
                "ana",
                "--url",
                "https://github.com",
                "--secret-stdin",
                "password",
                "--secret-stdin",
                "totp",
            ],
            &format!("{GH_PASSWORD}\nJBSWY3DPEHPK3PXP\n"),
        )
        .ok();
    laptop
        .unlocked(
            &[
                "item",
                "add",
                "api-key",
                "--title",
                "Stripe",
                "--secret-stdin",
                "api_key",
            ],
            &format!("{API_KEY}\n"),
        )
        .ok();
    let totp = laptop.unlocked(&["totp", "GitHub", "--json"], "").ok();
    let totp: serde_json::Value = serde_json::from_str(&totp.stdout).expect("totp json");
    assert_eq!(totp["code"].as_str().expect("code").len(), 6);

    // klav run: the child gets STRIPE_KEY from klav.toml; klav prints
    // nothing of it.
    let repo = root.path().join("repo");
    std::fs::create_dir_all(&repo).expect("repo");
    std::fs::write(
        repo.join("klav.toml"),
        "project = \"Personal/General\"\n[env]\nSTRIPE_KEY = \"Stripe/api_key\"\n",
    )
    .expect("klav.toml");
    // A klav.toml never approved is not used without a terminal to ask.
    let refused = laptop.unlocked_in(&repo, &["run", "--", "true"], "");
    assert_ne!(refused.code, 0);
    assert!(refused.stderr.contains("--trust"), "{}", refused.stderr);
    laptop
        .unlocked_in(&repo, &["run", "--trust", "--", "true"], "")
        .ok();
    let ran = laptop
        .unlocked_in(
            &repo,
            &[
                "run",
                "--",
                "sh",
                "-c",
                "printf %s \"$STRIPE_KEY\" > child.out",
            ],
            "",
        )
        .ok();
    assert!(!ran.stdout.contains(API_KEY) && !ran.stderr.contains(API_KEY));
    assert_eq!(
        std::fs::read_to_string(repo.join("child.out")).expect("child.out"),
        API_KEY
    );
    // Changed since approved: asked again.
    std::fs::write(
        repo.join("klav.toml"),
        "project = \"Personal/General\"\n[env]\nSTRIPE_KEY = \"Stripe/api_key\"\nOTHER = \"GitHub/password\"\n",
    )
    .expect("klav.toml");
    let changed = laptop.unlocked_in(&repo, &["run", "--", "true"], "");
    assert!(changed.stderr.contains("changed"), "{}", changed.stderr);
    std::fs::write(
        repo.join("klav.toml"),
        "project = \"Personal/General\"\n[env]\nSTRIPE_KEY = \"Stripe/api_key\"\n",
    )
    .expect("klav.toml");

    // klav inject: a 0600 file that is gone after the TTL.
    let injected = repo.join("stripe.key");
    let mut child = laptop.spawn_unlocked(
        &repo,
        &[
            "inject",
            "-r",
            "Stripe/api_key",
            "-o",
            "stripe.key",
            "--ttl",
            "2s",
        ],
    );
    // Its "Wrote" line, not the file's name: the line comes once the file
    // is whole and in place (the child's stderr goes to klav-bg.log).
    let log = repo.join("klav-bg.log");
    assert!(
        wait_until(30, || std::fs::read_to_string(&log)
            .is_ok_and(|l| l.contains("Wrote ") && l.contains("stripe.key"))),
        "inject never wrote"
    );
    assert_eq!(mode(&injected), 0o600);
    assert_eq!(std::fs::read_to_string(&injected).expect("read"), API_KEY);
    assert_eq!(wait_child(&mut child, 30), 0);
    assert!(!injected.exists(), "inject left the file after the TTL");

    // A second device logs in with the Emergency Kit and syncs.
    let desktop = Device::new(root.path(), "desktop");
    desktop
        .unlocked(
            &[
                "login",
                "--server",
                &server.url,
                "--email",
                "e2e@example.com",
                "--device-name",
                "desktop",
                "--emergency-kit",
                kit.to_str().expect("utf-8"),
            ],
            "",
        )
        .ok();
    let seen = desktop
        .unlocked(
            &[
                "item",
                "get",
                "klav://Personal/General/GitHub/password",
                "--reveal",
            ],
            "",
        )
        .ok();
    assert_eq!(seen.stdout.trim(), GH_PASSWORD);

    // Rollback: snapshot the server, change an item, let the desktop see
    // it, then put the old database back.
    server.snapshot("before-edit");
    laptop
        .unlocked(&["item", "edit", "Stripe", "--title", "Stripe live"], "")
        .ok();
    desktop.unlocked(&["sync"], "").ok();
    let ls = desktop.unlocked(&["item", "ls"], "").ok();
    assert!(ls.stdout.contains("Stripe live"), "{}", ls.stdout);
    server.restore("before-edit");

    let refused = desktop.unlocked(&["sync"], "");
    assert_eq!(refused.code, 3, "{}", refused.stderr);
    assert!(refused.stderr.contains("SECURITY"), "{}", refused.stderr);
    // A command that syncs on the way warns as loudly and goes on with the
    // local copy, unchanged (a poisoned mark must not lock her out).
    let again = desktop.unlocked(&["item", "ls"], "").ok();
    assert!(again.stdout.contains("Stripe live"), "{}", again.stdout);
    assert!(again.stderr.contains("SECURITY"), "{}", again.stderr);
    assert!(again.stderr.contains("--reset-cache"), "{}", again.stderr);
    let status = desktop.run(&["status", "--json"], "").ok();
    assert!(status.stdout.contains("e2e@example.com"));
    // Nothing was applied: the local cache still has the newer title (read
    // with the server stopped, which falls back to the cache).
    server.stop();
    let offline = desktop.unlocked(&["item", "ls"], "").ok();
    assert!(offline.stdout.contains("Stripe live"), "{}", offline.stdout);
    assert!(offline.stderr.contains("offline"), "{}", offline.stderr);

    // No secret ever reached either device's disk in clear.
    for device in [&laptop, &desktop] {
        for entry in std::fs::read_dir(&device.home).expect("home") {
            let path = entry.expect("entry").path();
            if path.is_file() {
                let bytes = std::fs::read(&path).expect("read");
                for needle in [GH_PASSWORD, API_KEY, "JBSWY3DPEHPK3PXP", "Stripe live"] {
                    assert!(
                        !bytes.windows(needle.len()).any(|w| w == needle.as_bytes()),
                        "{needle} in {}",
                        path.display()
                    );
                }
            }
        }
    }
}
