//! The `klav` binary against a real server: signup, items, TOTP, CSV
//! import and a second device.

mod common;

use common::{Device, PASSWORD, ServerProcess};

const GH_PASSWORD: &str = "MARKER-gh-password-7Qx";
const API_KEY: &str = "sk_live_MARKER_51Hc";

#[test]
fn items_round_trip_through_the_cli() {
    let server = ServerProcess::start(900);
    let root = tempfile::tempdir().expect("tempdir");
    let laptop = Device::new(root.path(), "laptop");
    let kit = root.path().join("kit.txt");
    let kit_arg = kit.to_str().expect("utf-8 path");

    // Signup: the Emergency Kit goes to a new 0600 file, not to stdout.
    let out = laptop
        .run(
            &[
                "--password-stdin",
                "signup",
                "--server",
                &server.url,
                "--email",
                "ana@example.com",
                "--device-name",
                "laptop",
                "--emergency-kit",
                kit_arg,
            ],
            &format!("{PASSWORD}\n"),
        )
        .ok();
    assert!(!out.stdout.contains("K1-"), "secret key on stdout");
    let kit_text = std::fs::read_to_string(&kit).expect("kit");
    assert!(kit_text.contains("Secret Key: K1-"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&kit).expect("meta").permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    // A second signup on the same home is refused.
    let again = laptop.run(
        &[
            "--password-stdin",
            "signup",
            "--server",
            &server.url,
            "--email",
            "ana@example.com",
            "--emergency-kit",
            root.path().join("kit2.txt").to_str().expect("utf-8"),
        ],
        &format!("{PASSWORD}\n"),
    );
    assert_ne!(again.code, 0);

    // A login with a TOTP seed and an API key, secrets from stdin.
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
                "--tag",
                "dev",
            ],
            &format!("{GH_PASSWORD}\nJBSWY3DPEHPK3PXP\n"),
        )
        .ok();
    laptop
        .unlocked(&["project", "create", "--vault", "Personal", "Backend"], "")
        .ok();
    laptop
        .unlocked(
            &[
                "item",
                "add",
                "api-key",
                "--title",
                "Stripe",
                "--project",
                "Backend",
                "--secret-stdin",
                "api_key",
                "-f",
                "key_id=acct_1",
            ],
            &format!("{API_KEY}\n"),
        )
        .ok();

    // Hidden unless --reveal.
    let shown = laptop.unlocked(&["item", "get", "GitHub"], "").ok();
    assert!(!shown.stdout.contains(GH_PASSWORD));
    assert!(shown.stdout.contains("hidden"));
    let json = laptop
        .unlocked(&["item", "get", "GitHub", "--json"], "")
        .ok();
    assert!(!json.stdout.contains(GH_PASSWORD));
    let refused = laptop.unlocked(
        &["item", "get", "klav://Personal/General/GitHub/password"],
        "",
    );
    assert_eq!(refused.code, 2);
    assert!(!refused.stdout.contains(GH_PASSWORD));
    let revealed = laptop
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
    assert_eq!(revealed.stdout.trim(), GH_PASSWORD);

    // TOTP: six digits.
    let totp = laptop.unlocked(&["totp", "GitHub", "--json"], "").ok();
    let value: serde_json::Value = serde_json::from_str(&totp.stdout).expect("totp json");
    let code = value["code"].as_str().expect("code");
    assert_eq!(code.len(), 6);
    assert!(code.chars().all(|c| c.is_ascii_digit()));

    // ls / search as JSON.
    let ls = laptop.unlocked(&["item", "ls", "--json"], "").ok();
    let items: serde_json::Value = serde_json::from_str(&ls.stdout).expect("ls json");
    assert_eq!(items.as_array().expect("array").len(), 2);
    assert!(!ls.stdout.contains(API_KEY));
    // Filters: by type (with commas or repeated) and «Codes», the items
    // with a one-time code; never the code itself.
    let titles = |args: &[&str]| -> Vec<String> {
        let mut cmd = vec!["item", "ls", "--json"];
        cmd.extend_from_slice(args);
        let out = laptop.unlocked(&cmd, "").ok();
        let items: serde_json::Value = serde_json::from_str(&out.stdout).expect("ls json");
        items
            .as_array()
            .expect("array")
            .iter()
            .map(|i| i["title"].as_str().expect("title").to_owned())
            .collect()
    };
    assert_eq!(titles(&["--kind", "api-key"]), ["Stripe"]);
    assert_eq!(titles(&["--kind", "logins,api-keys"]).len(), 2);
    assert_eq!(titles(&["--kind", "card", "--kind", "ssh"]).len(), 0);
    assert_eq!(titles(&["--codes"]), ["GitHub"]);
    assert_eq!(titles(&["--codes", "--kind", "api-key"]).len(), 0);
    let codes = laptop.unlocked(&["item", "ls", "--codes"], "").ok();
    assert!(codes.stdout.contains("GitHub") && !codes.stdout.contains(code));
    let bad = laptop.run(&["item", "ls", "--kind", "codes"], "");
    assert_ne!(bad.code, 0);
    let found = laptop
        .unlocked(&["item", "search", "stripe", "--json"], "")
        .ok();
    let found: serde_json::Value = serde_json::from_str(&found.stdout).expect("search json");
    assert_eq!(found[0]["title"], "Stripe");

    // Edit: rename, generate a new password, drop the TOTP seed.
    laptop
        .unlocked(
            &[
                "item",
                "edit",
                "GitHub",
                "--title",
                "GitHub work",
                "-g",
                "password",
                "--rm-field",
                "totp",
            ],
            "",
        )
        .ok();
    let after = laptop
        .unlocked(
            &[
                "item",
                "get",
                "klav://Personal/General/GitHub%20work/password",
                "--reveal",
            ],
            "",
        )
        .ok();
    assert_ne!(after.stdout.trim(), GH_PASSWORD);
    assert!(after.stdout.trim().len() >= 20);
    assert_ne!(laptop.unlocked(&["totp", "GitHub work"], "").code, 0);
    // The old password is in the item's history (ADR 0022 §3), hidden
    // unless asked for by position.
    let history = laptop
        .unlocked(&["item", "history", "GitHub work"], "")
        .ok();
    assert!(!history.stdout.contains(GH_PASSWORD));
    assert!(history.stdout.contains("Password"), "{}", history.stdout);
    let old = laptop
        .unlocked(&["item", "history", "GitHub work", "--reveal", "0"], "")
        .ok();
    assert_eq!(old.stdout.trim(), GH_PASSWORD);
    assert_ne!(
        laptop
            .unlocked(&["item", "history", "GitHub work", "--reveal", "1"], "")
            .code,
        0
    );

    // CSV import (Chrome export) and trash.
    let csv = root.path().join("chrome.csv");
    std::fs::write(
        &csv,
        "name,url,username,password,note\nGmail,https://mail.google.com,ana,MARKER-csv-pw,\n",
    )
    .expect("csv");
    let imported = laptop
        .unlocked(&["import", csv.to_str().expect("utf-8")], "")
        .ok();
    assert!(
        imported.stderr.contains("1 item(s) created"),
        "{}",
        imported.stderr
    );
    laptop.unlocked(&["item", "rm", "Gmail"], "").ok();
    let trash = laptop.unlocked(&["item", "ls", "--trash"], "").ok();
    assert!(trash.stdout.contains("Gmail"));
    let live = laptop.unlocked(&["item", "ls"], "").ok();
    assert!(!live.stdout.contains("Gmail"));

    // A wrong password fails without touching anything.
    let wrong = laptop.run(&["--password-stdin", "item", "ls"], "not the password\n");
    assert_eq!(wrong.code, 1);
    assert!(wrong.stderr.contains("wrong master password"));

    // Second device: log in with the Emergency Kit and see the items.
    let desktop = Device::new(root.path(), "desktop");
    desktop
        .unlocked(
            &[
                "login",
                "--server",
                &server.url,
                "--email",
                "ana@example.com",
                "--device-name",
                "desktop",
                "--emergency-kit",
                kit_arg,
            ],
            "",
        )
        .ok();
    let seen = desktop
        .unlocked(
            &[
                "item",
                "get",
                "klav://Personal/Backend/Stripe/api_key",
                "--reveal",
            ],
            "",
        )
        .ok();
    assert_eq!(seen.stdout.trim(), API_KEY);
    let status = desktop.run(&["status", "--json"], "").ok();
    let status: serde_json::Value = serde_json::from_str(&status.stdout).expect("status json");
    assert_eq!(status["email"], "ana@example.com");

    // No plaintext secret or title in the local state.
    for device in [&laptop, &desktop] {
        for entry in std::fs::read_dir(&device.home).expect("home") {
            let path = entry.expect("entry").path();
            if path.is_file() {
                let bytes = std::fs::read(&path).expect("read");
                for needle in [GH_PASSWORD, API_KEY, "MARKER-csv-pw", "GitHub", "Stripe"] {
                    assert!(
                        !bytes.windows(needle.len()).any(|w| w == needle.as_bytes()),
                        "{needle} in {}",
                        path.display()
                    );
                }
            }
        }
    }
    drop(server);
}

#[test]
fn generate_needs_no_account() {
    let root = tempfile::tempdir().expect("tempdir");
    let device = Device::new(root.path(), "none");
    let out = device.run(&["generate", "--length", "32"], "").ok();
    assert_eq!(out.stdout.trim().chars().count(), 32);
    // The default (smart, no site): 20 random characters, very strong.
    let default = device.run(&["generate"], "").ok();
    assert_eq!(default.stdout.trim().chars().count(), 20);
    assert!(default.stderr.contains("very strong"), "{}", default.stderr);
    // Without klavd it is not kept in the generator history, and says so.
    assert!(
        default.stderr.contains("klavd is not running"),
        "{}",
        default.stderr
    );
    let quiet = device.run(&["generate", "--no-history"], "").ok();
    assert!(!quiet.stderr.contains("not kept"), "{}", quiet.stderr);
    // --words means memorable: capitalised words, one with a digit.
    let words = device
        .run(&["generate", "--words", "6", "--separator", " "], "")
        .ok();
    let parts: Vec<&str> = words.stdout.trim().split(' ').collect();
    assert_eq!(parts.len(), 6);
    assert!(
        parts
            .iter()
            .all(|w| w.starts_with(|c: char| c.is_ascii_uppercase()))
    );
    // A separator the estimator could not tell from the words is refused,
    // with what is allowed, whatever the type.
    for (separator, kind) in [("", "memorable"), ("x", "memorable"), ("1", "smart")] {
        let out = device.run(&["generate", "-t", kind, "--separator", separator], "");
        assert_eq!(out.code, 2, "{separator:?}: {}", out.stderr);
        assert!(out.stdout.is_empty(), "{separator:?}");
        assert!(
            out.stderr.contains(&format!(
                "--separator {separator:?}: a separator needs 1 to 8 bytes, no ASCII letter or digit, and no control or invisible character"
            )),
            "{separator:?}: {}",
            out.stderr
        );
    }
    let pin = device
        .run(&["generate", "-t", "pin", "--pin-length", "8"], "")
        .ok();
    assert!(pin.stdout.trim().len() == 8 && pin.stdout.trim().bytes().all(|b| b.is_ascii_digit()));
    assert!(pin.stderr.contains("weak"), "{}", pin.stderr);
    // Smart with a site's bundled rules, and with the field's own rules.
    let accor = device
        .run(&["generate", "--site", "https://all.accor.com/login"], "")
        .ok();
    assert!(
        accor.stderr.contains("rules of accor.com"),
        "{}",
        accor.stderr
    );
    let rules = device
        .run(
            &[
                "generate",
                "--rules",
                "minlength: 6; maxlength: 6; allowed: digit",
            ],
            "",
        )
        .ok();
    assert!(
        rules.stdout.trim().len() == 6 && rules.stdout.trim().bytes().all(|b| b.is_ascii_digit())
    );
    assert!(
        rules.stderr.contains("does not allow a stronger one"),
        "{}",
        rules.stderr
    );
    let bad = device
        .run(&["generate", "--rules", "minimum: eight"], "")
        .ok();
    assert_eq!(bad.stdout.trim().chars().count(), 20);
    assert!(bad.stderr.contains("could not be read"), "{}", bad.stderr);
    // Neither the value nor the rules text ever reach stderr.
    assert!(!default.stderr.contains(default.stdout.trim()));
}

/// Titles name items in references: a second item with the same title in
/// the same project is refused unless asked for, and an import renames
/// what would clash and skips what the project already has.
#[test]
fn duplicate_titles_are_refused_unless_asked() {
    let server = ServerProcess::start(900);
    let root = tempfile::tempdir().expect("tempdir");
    let device = Device::new(root.path(), "dup");
    device.signup(&server, "dup@example.com");
    let add = |title: &str, extra: &[&str]| {
        let mut args = vec!["item", "add", "api-key", "--title", title];
        args.extend_from_slice(extra);
        args.extend_from_slice(&["--secret-stdin", "api_key"]);
        device.unlocked(&args, "MARKER-dup-key\n")
    };
    add("Stripe", &[]).ok();
    let again = add("stripe", &[]);
    assert_ne!(again.code, 0);
    assert!(
        again
            .stderr
            .contains("klav://Personal/General/Stripe already exists")
            && again.stderr.contains("klav item edit")
            && again.stderr.contains("--allow-duplicate"),
        "{}",
        again.stderr
    );
    // Another project is another namespace.
    device
        .unlocked(&["project", "create", "--vault", "Personal", "Backend"], "")
        .ok();
    add("Stripe", &["--project", "Backend"]).ok();
    // Asked for: created, and a title then needs the ID.
    add("Stripe", &["--allow-duplicate"]).ok();
    let ls = device.unlocked(&["item", "ls", "--json"], "").ok();
    let items: serde_json::Value = serde_json::from_str(&ls.stdout).expect("ls json");
    assert_eq!(items.as_array().expect("array").len(), 3);
    let ambiguous = device.unlocked(&["item", "get", "Stripe"], "");
    assert_ne!(ambiguous.code, 0);
    assert!(
        ambiguous.stderr.matches("(ID ").count() >= 2,
        "{}",
        ambiguous.stderr
    );

    // Renaming follows the same rule: onto another item's title is
    // refused (case-insensitive), a case change of its own title is not,
    // and --allow-duplicate forces it.
    add("Twilio", &[]).ok();
    let rename = device.unlocked(&["item", "edit", "Twilio", "--title", "STRIPE"], "");
    assert_ne!(rename.code, 0);
    assert!(
        rename.stderr.contains("already exists") && rename.stderr.contains("--allow-duplicate"),
        "{}",
        rename.stderr
    );
    device
        .unlocked(&["item", "edit", "Twilio", "--title", "twilio"], "")
        .ok();
    // Another project's item with that title does not count.
    device
        .unlocked(&["item", "edit", "twilio", "--title", "Backend"], "")
        .ok();
    device
        .unlocked(
            &[
                "item",
                "edit",
                "Backend",
                "--title",
                "Twilio",
                "--allow-duplicate",
            ],
            "",
        )
        .ok();
    device
        .unlocked(
            &[
                "item",
                "edit",
                "Twilio",
                "--title",
                "Stripe",
                "--allow-duplicate",
            ],
            "",
        )
        .ok();
    let ls = device.unlocked(&["item", "ls", "--json"], "").ok();
    let items: serde_json::Value = serde_json::from_str(&ls.stdout).expect("ls json");
    let stripes = items
        .as_array()
        .expect("array")
        .iter()
        .filter(|i| i["title"] == "Stripe")
        .count();
    assert_eq!(stripes, 4, "{}", ls.stdout);

    // Import: a title the project has (for another kind of item) and a
    // title repeated in the file get the user name.
    let csv = root.path().join("dups.csv");
    std::fs::write(
        &csv,
        "name,url,username,password,note\n\
         Stripe,https://stripe.com,ana,MARKER-csv-1,\n\
         Mail,https://mail.example.com,ana,MARKER-csv-2,\n\
         Mail,https://mail.example.com,bob,MARKER-csv-3,\n",
    )
    .expect("csv");
    let csv_arg = csv.to_str().expect("utf-8");
    let imported = device.unlocked(&["import", csv_arg], "").ok();
    assert!(
        imported.stderr.contains("3 item(s) created")
            && imported.stdout.contains("as \"Mail (bob)\"")
            && imported.stdout.contains("as \"Stripe (ana)\""),
        "{}{}",
        imported.stdout,
        imported.stderr
    );
    assert!(
        !imported.stdout.contains("MARKER") && !imported.stderr.contains("MARKER"),
        "no values printed"
    );
    for title in ["Mail", "Mail (bob)", "Stripe (ana)"] {
        let r = format!(
            "klav://Personal/General/{}/password",
            title
                .replace(' ', "%20")
                .replace('(', "%28")
                .replace(')', "%29")
        );
        assert!(device.unlocked(&["item", "get", &r, "--reveal"], "").code == 0);
    }
    // The same file again adds nothing.
    let again = device.unlocked(&["import", csv_arg], "").ok();
    assert!(
        again
            .stderr
            .contains("0 item(s) created, 0 updated, 3 already there"),
        "{}",
        again.stderr
    );
    drop(server);
}

#[test]
fn reset_cache_needs_a_yes_and_downloads_again() {
    let server = ServerProcess::start(900);
    let root = tempfile::tempdir().expect("tempdir");
    let laptop = Device::new(root.path(), "laptop");
    laptop.signup(&server, "ana@example.com");
    // Without a terminal and without --yes: refused, nothing forgotten.
    let refused = laptop.unlocked(&["sync", "--reset-cache"], "");
    assert_ne!(refused.code, 0);
    assert!(refused.stderr.contains("--yes"), "{}", refused.stderr);
    let out = laptop
        .unlocked(&["sync", "--reset-cache", "--yes"], "")
        .ok();
    assert!(out.stderr.contains("1 vault(s)"), "{}", out.stderr);
    laptop.unlocked(&["sync"], "").ok();
}

#[test]
fn the_kit_comes_before_the_account_and_can_be_shown_again() {
    let server = ServerProcess::start(900);
    let root = tempfile::tempdir().expect("tempdir");
    let laptop = Device::new(root.path(), "laptop");
    let signup = |kit: &std::path::Path| {
        laptop.run(
            &[
                "--password-stdin",
                "signup",
                "--server",
                &server.url,
                "--email",
                "ana@example.com",
                "--emergency-kit",
                kit.to_str().expect("utf-8"),
            ],
            &format!("{PASSWORD}\n"),
        )
    };
    // The kit cannot be written: nothing is registered, nothing saved.
    let failed = signup(&root.path().join("no-such-dir/kit.txt"));
    assert_ne!(failed.code, 0);
    let kit = root.path().join("kit.txt");
    signup(&kit).ok();
    let original = std::fs::read_to_string(&kit).expect("kit");
    let secret = original
        .lines()
        .find(|l| l.starts_with("Secret Key:"))
        .expect("secret key line")
        .to_owned();

    // `klav account kit` rebuilds it, after the master password.
    let again = root.path().join("again.txt");
    let wrong = laptop.run(
        &[
            "--password-stdin",
            "account",
            "kit",
            "--emergency-kit",
            again.to_str().expect("utf-8"),
        ],
        "not the password\n",
    );
    assert_ne!(wrong.code, 0);
    assert!(!again.exists());
    let out = laptop
        .unlocked(
            &[
                "account",
                "kit",
                "--emergency-kit",
                again.to_str().expect("utf-8"),
            ],
            "",
        )
        .ok();
    assert!(!out.stdout.contains("K1-") && !out.stderr.contains("K1-"));
    let text = std::fs::read_to_string(&again).expect("kit again");
    assert!(text.contains(&secret));
    assert!(text.contains("ana@example.com"));
    assert_eq!(common::mode(&again) & 0o777, 0o600);
}

/// `klav --version` names the version, the commit and its time
/// (`klav 0.0.0 (ce4fa5099092 2026-11-13T18:17:02Z)`), or says the commit
/// is unknown; subcommands say the same. No server needed.
#[test]
fn version_names_the_commit_and_its_time() {
    let run = |args: &[&str]| {
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_klav"))
            .args(args)
            .env_remove("KLAV_HOME")
            .output()
            .expect("klav --version");
        assert!(out.status.success(), "{args:?}");
        String::from_utf8(out.stdout).expect("utf-8")
    };
    let text = run(&["--version"]);
    let rest = text
        .trim_end()
        .strip_prefix(&format!("klav {} (", env!("CARGO_PKG_VERSION")))
        .and_then(|r| r.strip_suffix(')'))
        .unwrap_or_else(|| panic!("unexpected --version: {text:?}"));
    if rest != "commit unknown" {
        let (short, time) = rest.split_once(' ').expect("hash and time");
        assert_eq!(short.len(), 12, "{rest}");
        assert!(
            short
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        );
        // 2026-11-13T18:17:02Z
        assert_eq!(time.len(), 20, "{time}");
        assert!(time.ends_with('Z') && time.as_bytes()[10] == b'T', "{time}");
    }
    assert_eq!(
        run(&["item", "--version"]),
        text.replacen("klav ", "klav-item ", 1)
    );
}

/// `--version` is one line, and the binary's file carries exactly one
/// marker line with the same text, which the Mac app reads without running
/// it (`crates/klav-daemon/build.rs`).
#[test]
fn version_is_one_line_and_the_file_says_it_too() {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_klav"))
        .arg("--version")
        .output()
        .expect("klav --version");
    let text = String::from_utf8(out.stdout).expect("utf-8");
    assert_eq!(text.matches('\n').count(), 1, "{text:?}");
    assert!(text.ends_with('\n'), "{text:?}");
    let shown = text.trim_end().strip_prefix("klav ").expect("klav …");

    let file = std::fs::read(env!("CARGO_BIN_EXE_klav")).expect("read klav");
    let prefix = b"klav-build-identity: ";
    let found: Vec<&[u8]> = file
        .windows(prefix.len())
        .enumerate()
        .filter(|(_, w)| *w == prefix)
        .map(|(at, _)| {
            let rest = &file[at + prefix.len()..];
            let end = rest.iter().position(|&b| b == b'\n').expect("newline");
            &rest[..end]
        })
        .collect();
    assert_eq!(
        found,
        [shown.as_bytes()],
        "one marker, the same as --version"
    );
}

/// The `klav` a test runs never finds an installed `klavd` (or another
/// workspace binary) on its `PATH`: those directories are dropped, the
/// others kept in order. On a machine with Klav installed, the `PATH` of
/// [`Device::command`] proves it against the real one.
#[test]
fn a_test_never_finds_an_installed_klavd() {
    let root = tempfile::tempdir().expect("tempdir");
    let installed = root.path().join("installed");
    let tools = root.path().join("tools");
    for (dir, file) in [(&installed, "klavd"), (&tools, "git")] {
        std::fs::create_dir_all(dir).expect("dir");
        std::fs::write(dir.join(file), "#!/bin/sh\n").expect("file");
    }
    let path = std::env::join_paths([&tools, &installed, &tools]).expect("PATH");
    let kept = common::without_installed_klav(&path);
    assert_eq!(
        std::env::split_paths(&kept).collect::<Vec<_>>(),
        [tools.clone(), tools]
    );

    let device = Device::new(root.path(), "home");
    let command = device.command();
    // The PATH it sets, or the one it inherits.
    let given = command
        .get_envs()
        .find(|(k, _)| *k == "PATH")
        .map_or_else(
            || std::env::var_os("PATH"),
            |(_, v)| v.map(ToOwned::to_owned),
        )
        .expect("a PATH");
    for dir in std::env::split_paths(&given) {
        for (name, _) in common::BINARIES {
            assert!(
                !dir.join(name).exists(),
                "{} on the PATH klav gets",
                dir.join(name).display()
            );
        }
    }
}
