//! Environments per repository (ADR 0032) and `klav env scan` (ADR 0036
//! §16) against a real server: `klav env import` without a value on any
//! output, references instead of copies, `klav run --env` and `klav inject
//! --env --dotenv` with presence for a protected environment that `--trust`
//! never skips, the grants issued again before a version that grows the
//! protection, and the repository link that only suggests.
//!
//! No test prints a value: they are compared in memory.

mod common;

use std::path::{Path, PathBuf};
use std::process::Command;

use common::{Device, PASSWORD, Run, ServerProcess, mode, wait_child, wait_until};

const STRIPE: &str = "sk_live_MARKER_env_stripe_7c1";
const DATABASE: &str = "postgres://app:pw_MARKER_env_db_42@db.internal/app";
const CERT_A: &str = "-----BEGIN MARKER_env_cert-----";
const CERT_B: &str = "MARKER_env_cert_body";
const TOKEN: &str = "tok_MARKER_env_stdin_9";
const BAD_LINE: &str = "sk_live_MARKER_env_bad_line";
const OTHER: &str = "sk_live_MARKER_env_other_3";

const MARKERS: [&str; 7] = [STRIPE, DATABASE, CERT_A, CERT_B, TOKEN, BAD_LINE, OTHER];

/// No value reached stdout or stderr.
#[track_caller]
fn no_leak(run: &Run) {
    for marker in MARKERS {
        assert!(
            !run.stdout.contains(marker) && !run.stderr.contains(marker),
            "a value reached the output"
        );
    }
}

fn git_available() -> bool {
    Command::new("git")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
}

fn git(dir: &Path, args: &[&str]) {
    let ok = Command::new("git")
        .args(["-c", "user.email=t@example.com", "-c", "user.name=t"])
        .args(args)
        .current_dir(dir)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .status()
        .expect("git")
        .success();
    assert!(ok, "git {args:?}");
}

/// An account with `Personal/acme-api/Stripe/api_key` and a repository whose
/// `klav.toml` names that project.
fn setup(server: &ServerProcess, root: &Path) -> (Device, PathBuf) {
    let device = Device::new(root, "home");
    device.signup(server, "dev@example.com");
    device
        .unlocked(
            &["project", "create", "--vault", "Personal", "acme-api"],
            "",
        )
        .ok();
    add_key(&device, "Stripe", STRIPE);
    let repo = root.join("repo");
    std::fs::create_dir_all(&repo).expect("repo");
    std::fs::write(repo.join("klav.toml"), "project = \"Personal/acme-api\"\n").expect("klav.toml");
    (device, repo)
}

fn add_key(device: &Device, title: &str, value: &str) {
    device
        .unlocked(
            &[
                "item",
                "add",
                "api-key",
                "--title",
                title,
                "--project",
                "acme-api",
                "--secret-stdin",
                "api_key",
            ],
            &format!("{value}\n"),
        )
        .ok();
}

fn json(out: &str) -> serde_json::Value {
    serde_json::from_str(out).expect("json output")
}

/// The variables of an environment, as `klav env show --json` lists them.
fn variables(device: &Device, repo: &Path, env: &str) -> Vec<serde_json::Value> {
    let shown = device
        .unlocked_in(repo, &["env", "show", env, "--json"], "")
        .ok();
    no_leak(&shown);
    json(&shown.stdout)["variables"]
        .as_array()
        .expect("variables")
        .clone()
}

fn names(vars: &[serde_json::Value]) -> Vec<String> {
    vars.iter()
        .map(|v| v["name"].as_str().expect("name").to_owned())
        .collect()
}

#[test]
fn import_reads_a_dotenv_without_printing_a_value_and_keeps_references() {
    let server = ServerProcess::start(900);
    let root = tempfile::tempdir().expect("tempdir");
    let (device, repo) = setup(&server, root.path());
    std::fs::write(
        repo.join(".env"),
        format!(
            "# local settings\nexport STRIPE_KEY={STRIPE}\nDATABASE_URL='{DATABASE}' # db\nCERT=\"{CERT_A}\n{CERT_B}\"\n\nEMPTY=\n"
        ),
    )
    .expect(".env");

    // The review names variables, never values, and proposes Stripe's
    // field as a reference.
    let review = device
        .unlocked_in(
            &repo,
            &["env", "import", ".env", "--env", "development", "--dry-run"],
            "",
        )
        .ok();
    no_leak(&review);
    assert!(
        review.stderr.contains("new      STRIPE_KEY"),
        "{}",
        review.stderr
    );
    assert!(
        review
            .stderr
            .contains("same value as Personal/acme-api/Stripe › api_key"),
        "{}",
        review.stderr
    );
    assert!(review.stderr.contains("Dry run"));
    let listed = device.unlocked_in(&repo, &["env", "ls", "--json"], "").ok();
    assert_eq!(json(&listed.stdout).as_array().map(Vec::len), Some(0));

    // Imported: Stripe as a reference, the others as values.
    let imported = device
        .unlocked_in(
            &repo,
            &["env", "import", ".env", "--env", "development", "--yes"],
            "",
        )
        .ok();
    no_leak(&imported);
    assert!(repo.join(".env").exists(), "--yes never deletes the file");
    let vars = variables(&device, &repo, "development");
    assert_eq!(
        names(&vars),
        vec!["STRIPE_KEY", "DATABASE_URL", "CERT", "EMPTY"]
    );
    assert_eq!(vars[0]["origin"], "reference");
    assert_eq!(vars[0]["target"], "Stripe › api_key");
    assert_eq!(vars[1]["origin"], "value");

    // Again: nothing changes.
    let again = device
        .unlocked_in(
            &repo,
            &["env", "import", ".env", "--env", "development", "--yes"],
            "",
        )
        .ok();
    no_leak(&again);
    assert!(again.stderr.contains("already has these values"));

    // A parse error names the line, never its text.
    std::fs::write(repo.join("bad.env"), format!("A=1\n{BAD_LINE}\n")).expect("bad.env");
    let bad = device
        .unlocked_in(
            &repo,
            &["env", "import", "bad.env", "--env", "development", "--yes"],
            "",
        )
        .err();
    no_leak(&bad);
    assert!(bad.stderr.contains("line 2: missing ="), "{}", bad.stderr);

    // From stdin, through the same wiped buffer.
    let stdin = device
        .unlocked_in(
            &repo,
            &["env", "import", "-", "--env", "staging", "--yes"],
            &format!("TOKEN={TOKEN}\n"),
        )
        .ok();
    no_leak(&stdin);
    assert_eq!(names(&variables(&device, &repo, "staging")), vec!["TOKEN"]);

    // `klav run --env` gives the child the values, the reference resolved.
    let run = device
        .unlocked_in(
            &repo,
            &[
                "run",
                "--env",
                "development",
                "--trust",
                "--",
                "sh",
                "-c",
                "printf %s \"$STRIPE_KEY\" > stripe.out; printf %s \"$CERT\" > cert.out",
            ],
            "",
        )
        .ok();
    no_leak(&run);
    assert_eq!(
        std::fs::read_to_string(repo.join("stripe.out")).unwrap(),
        STRIPE
    );
    assert_eq!(
        std::fs::read_to_string(repo.join("cert.out")).unwrap(),
        format!("{CERT_A}\n{CERT_B}")
    );
    drop(server);
}

#[test]
fn a_flat_klav_toml_moves_to_an_environment_by_reference() {
    let server = ServerProcess::start(900);
    let root = tempfile::tempdir().expect("tempdir");
    let (device, repo) = setup(&server, root.path());
    std::fs::write(
        repo.join("klav.toml"),
        "# acme\nproject = \"Personal/acme-api\"\n\n[env]\nSTRIPE_KEY = \"Stripe/api_key\"\n",
    )
    .expect("klav.toml");
    let moved = device
        .unlocked_in(
            &repo,
            &[
                "env",
                "import",
                "klav.toml",
                "--env",
                "development",
                "--yes",
            ],
            "",
        )
        .ok();
    no_leak(&moved);
    let vars = variables(&device, &repo, "development");
    assert_eq!(vars[0]["origin"], "reference");
    let text = std::fs::read_to_string(repo.join("klav.toml")).unwrap();
    assert!(text.contains("default_env = \"development\""), "{text}");
    assert!(text.contains("# acme") && !text.contains("STRIPE_KEY ="));

    // `klav run` without --env now takes `default_env`.
    let run = device
        .unlocked_in(
            &repo,
            &[
                "run",
                "--trust",
                "--",
                "sh",
                "-c",
                "printf %s \"$STRIPE_KEY\" > out",
            ],
            "",
        )
        .ok();
    no_leak(&run);
    assert_eq!(std::fs::read_to_string(repo.join("out")).unwrap(), STRIPE);
    drop(server);
}

#[test]
fn production_asks_for_presence_every_time_and_trust_never_skips_it() {
    let server = ServerProcess::start(900);
    let root = tempfile::tempdir().expect("tempdir");
    let (device, repo) = setup(&server, root.path());
    device
        .unlocked_in(&repo, &["env", "create", "development"], "")
        .ok();
    device
        .unlocked_in(
            &repo,
            &[
                "env",
                "set",
                "development",
                "--secret-stdin",
                "DATABASE_URL",
            ],
            &format!("{DATABASE}\n"),
        )
        .ok();
    let created = device
        .unlocked_in(&repo, &["env", "create", "production"], "")
        .ok();
    assert!(created.stderr.contains("protected"), "{}", created.stderr);
    let set = device
        .unlocked_in(
            &repo,
            &[
                "env",
                "set",
                "production",
                "--ref",
                "STRIPE_KEY=Stripe/api_key",
            ],
            "",
        )
        .ok();
    assert!(
        set.stderr.contains("“Stripe” is now protected"),
        "{}",
        set.stderr
    );

    // Two environments and no `default_env`: no guessing.
    let guess = device
        .unlocked_in(&repo, &["run", "--trust", "--", "true"], "")
        .err();
    assert!(
        guess
            .stderr
            .contains("there are development and production: use --env"),
        "{}",
        guess.stderr
    );

    // development: no presence.
    device
        .unlocked_in(
            &repo,
            &[
                "run",
                "--env",
                "development",
                "--trust",
                "--",
                "sh",
                "-c",
                "printf %s \"$DATABASE_URL\" > dev.out",
            ],
            "",
        )
        .ok();
    assert_eq!(
        std::fs::read_to_string(repo.join("dev.out")).unwrap(),
        DATABASE
    );

    // production with --trust and no terminal: exit 9, nothing runs.
    let refused = device.unlocked_in(
        &repo,
        &[
            "run",
            "--env",
            "production",
            "--trust",
            "--",
            "sh",
            "-c",
            "touch ran",
        ],
        "",
    );
    assert_eq!(refused.code, 9, "{}", refused.stderr);
    assert!(!repo.join("ran").exists());
    no_leak(&refused);

    // An item a reference protects is protected too: listed as such, and
    // showing it asks for presence.
    let listed = device.unlocked(&["item", "ls"], "").ok();
    assert!(
        listed.stdout.contains("protected by “production”"),
        "{}",
        listed.stdout
    );
    let shown = device.unlocked(&["item", "get", "Stripe", "--reveal"], "");
    assert_eq!(shown.code, 9, "{}", shown.stderr);
    no_leak(&shown);

    // With someone at the terminal: the master password there, then it
    // runs.
    let ran = device.in_terminal(
        Some(&repo),
        &[
            "--password-stdin",
            "run",
            "--env",
            "production",
            "--trust",
            "--",
            "sh",
            "-c",
            "printf %s \"$STRIPE_KEY\" > prod.out",
        ],
        &format!("{PASSWORD}\n"),
    );
    assert_eq!(ran.code, 0, "{}", ran.stderr);
    assert!(
        ran.stderr.contains("“production” is protected"),
        "{}",
        ran.stderr
    );
    assert_eq!(
        std::fs::read_to_string(repo.join("prod.out")).unwrap(),
        STRIPE
    );

    // `klav inject --env --dotenv`: a 0600 file a loader reads back.
    device
        .unlocked_in(
            &repo,
            &[
                "inject",
                "--env",
                "development",
                "--dotenv",
                "-o",
                "dev.env",
                "--trust",
            ],
            "",
        )
        .ok();
    assert_eq!(mode(&repo.join("dev.env")), 0o600);
    assert_eq!(
        std::fs::read_to_string(repo.join("dev.env")).unwrap(),
        format!("DATABASE_URL='{DATABASE}'\n")
    );
    // …or a named pipe read once.
    let pipe = repo.join("pipe.env");
    let mut child = device.spawn_unlocked(
        &repo,
        &[
            "inject",
            "--env",
            "development",
            "--dotenv",
            "-o",
            "pipe.env",
            "--fifo",
            "--trust",
        ],
    );
    assert!(wait_until(30, || pipe.exists()), "pipe never appeared");
    assert_eq!(mode(&pipe), 0o600);
    assert_eq!(
        std::fs::read_to_string(&pipe).unwrap(),
        format!("DATABASE_URL='{DATABASE}'\n")
    );
    assert_eq!(wait_child(&mut child, 30), 0);
    // A protected one through --dotenv asks for presence too.
    let injected = device.unlocked_in(
        &repo,
        &[
            "inject",
            "--env",
            "production",
            "--dotenv",
            "-o",
            "prod.env",
            "--trust",
        ],
        "",
    );
    assert_eq!(injected.code, 9, "{}", injected.stderr);
    assert!(!repo.join("prod.env").exists());
    drop(server);
}

#[test]
fn grants_carry_the_protection_before_the_version_and_release_it_after() {
    let server = ServerProcess::start(900);
    let root = tempfile::tempdir().expect("tempdir");
    let (person, repo) = setup(&server, root.path());
    add_key(&person, "Other", OTHER);
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
                "dev@example.com",
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
                "Personal/acme-api",
                "--words",
                &words,
            ],
            "",
        )
        .ok();
    let protected_items = |person: &Device| -> Vec<String> {
        let shown = person
            .unlocked(&["agent", "show", "bot", "--json"], "")
            .ok();
        let view = json(&shown.stdout);
        let mut items: Vec<String> = view["agent"]["grant"]["policy"]["rules"]
            .as_array()
            .expect("rules")
            .iter()
            .filter(|r| r["origin"] == "protected")
            .flat_map(|r| {
                r["scope"]["items"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default()
                    .into_iter()
                    .map(|i| i.as_str().unwrap_or_default().to_owned())
            })
            .collect();
        items.sort();
        items.dedup();
        items
    };
    let item_id = |person: &Device, title: &str| -> String {
        let got = person.unlocked(&["item", "get", title, "--json"], "").ok();
        json(&got.stdout)["id"].as_str().expect("id").to_owned()
    };
    assert!(protected_items(&person).is_empty());

    // Creating a protected environment protects it for the agent at once.
    let created = person
        .unlocked_in(&repo, &["env", "create", "production"], "")
        .ok();
    let env_id = json(
        &person
            .unlocked_in(&repo, &["env", "ls", "--json"], "")
            .ok()
            .stdout,
    )[0]["id"]
        .as_str()
        .expect("id")
        .to_owned();
    assert!(created.stderr.contains("“bot”"), "{}", created.stderr);
    assert_eq!(protected_items(&person), vec![env_id.clone()]);

    // A reference: the grant first, naming Stripe.
    let set = person
        .unlocked_in(
            &repo,
            &[
                "env",
                "set",
                "production",
                "--ref",
                "STRIPE_KEY=Stripe/api_key",
            ],
            "",
        )
        .ok();
    assert!(
        set.stderr.contains("“Stripe” is now protected for “bot”"),
        "{}",
        set.stderr
    );
    let stripe = item_id(&person, "Stripe");
    let mut want = vec![env_id.clone(), stripe.clone()];
    want.sort();
    assert_eq!(protected_items(&person), want);
    // The other permissions keep their defaults, written out (ADR 0006 §2).
    let shown = json(
        &person
            .unlocked(&["agent", "show", "bot", "--json"], "")
            .ok()
            .stdout,
    );
    let explicit_inject = shown["agent"]["grant"]["policy"]["rules"]
        .as_array()
        .expect("rules")
        .iter()
        .any(|r| r["permission"] == "inject" && r["effect"] == "allow" && r["origin"].is_null());
    assert!(explicit_inject, "{shown}");

    // If the grant cannot be issued, the version is not saved.
    let revocations = person.home.join("revocations.bin");
    let saved_file = std::fs::read(&revocations).ok();
    std::fs::write(&revocations, b"not a sealed file").expect("break revocations.bin");
    let failed = person
        .unlocked_in(
            &repo,
            &[
                "env",
                "set",
                "production",
                "--ref",
                "OTHER_KEY=Other/api_key",
            ],
            "",
        )
        .err();
    assert!(
        failed.stderr.contains("the environment was not saved"),
        "{}",
        failed.stderr
    );
    match saved_file {
        Some(bytes) => std::fs::write(&revocations, bytes).expect("restore"),
        None => std::fs::remove_file(&revocations).expect("remove"),
    }
    assert_eq!(
        names(&variables(&person, &repo, "production")),
        vec!["STRIPE_KEY"]
    );
    assert!(!protected_items(&person).contains(&item_id(&person, "Other")));

    // Removing the reference lowers the protection: presence first, so
    // without a terminal nothing changes…
    let refused = person.unlocked_in(&repo, &["env", "rm", "production", "STRIPE_KEY"], "");
    assert_eq!(refused.code, 9, "{}", refused.stderr);
    assert_eq!(
        names(&variables(&person, &repo, "production")),
        vec!["STRIPE_KEY"]
    );
    // …and with the master password at the terminal, the version goes
    // first and the grant releases Stripe.
    let removed = person.unlocked_in_terminal(
        &[
            "env",
            "rm",
            "production",
            "STRIPE_KEY",
            "--project",
            "Personal/acme-api",
        ],
        "",
    );
    assert_eq!(removed.code, 0, "{}", removed.stderr);
    assert!(
        names(&variables(&person, &repo, "production")).is_empty(),
        "the version was saved"
    );
    assert_eq!(protected_items(&person), vec![env_id]);
    let listed = person.unlocked(&["item", "ls"], "").ok();
    let stripe_row = listed
        .stdout
        .lines()
        .find(|l| l.contains("/Stripe"))
        .expect("Stripe listed");
    assert!(!stripe_row.contains("protected"), "{}", listed.stdout);
    drop(server);
}

#[test]
fn the_link_only_suggests_and_a_forged_origin_still_asks() {
    if !git_available() {
        return;
    }
    let server = ServerProcess::start(900);
    let root = tempfile::tempdir().expect("tempdir");
    let (device, repo) = setup(&server, root.path());
    device
        .unlocked(&["project", "create", "--vault", "Personal", "banco"], "")
        .ok();
    git(&repo, &["init", "-q"]);
    git(
        &repo,
        &[
            "remote",
            "add",
            "origin",
            "https://github.com/Omar/acme-api.git",
        ],
    );
    device
        .unlocked_in(&repo, &["env", "link", "--yes"], "")
        .ok();
    let projects = json(
        &device
            .unlocked(&["project", "ls", "--json"], "")
            .ok()
            .stdout,
    );
    let acme = projects
        .as_array()
        .expect("projects")
        .iter()
        .find(|p| p["name"] == "acme-api")
        .expect("acme-api")
        .clone();
    assert_eq!(acme["repos"][0], "github.com/omar/acme-api");

    // A cloned repository that forges the same origin and asks for another
    // project's secrets: warned, and still asked.
    let forged = root.path().join("forged");
    std::fs::create_dir_all(&forged).expect("forged");
    git(&forged, &["init", "-q"]);
    git(
        &forged,
        &[
            "remote",
            "add",
            "origin",
            "git@github.com:omar/acme-api.git",
        ],
    );
    std::fs::write(
        forged.join("klav.toml"),
        "project = \"Personal/banco\"\n\n[env.development]\nSTRIPE_KEY = \"klav://Personal/acme-api/Stripe/api_key\"\n",
    )
    .expect("klav.toml");
    let asked = device
        .unlocked_in(
            &forged,
            &["run", "--env", "development", "--", "sh", "-c", "touch ran"],
            "",
        )
        .err();
    assert!(!forged.join("ran").exists());
    assert!(
        asked.stderr.contains(
            "asks for secrets from Personal/banco, which isn't linked to github.com/omar/acme-api"
        ),
        "{}",
        asked.stderr
    );
    assert!(asked.stderr.contains("not confirmed"), "{}", asked.stderr);

    device.unlocked_in(&repo, &["env", "unlink"], "").ok();
    let projects = json(
        &device
            .unlocked(&["project", "ls", "--json"], "")
            .ok()
            .stdout,
    );
    let acme = projects
        .as_array()
        .expect("projects")
        .iter()
        .find(|p| p["name"] == "acme-api")
        .expect("acme-api")
        .clone();
    assert!(acme["repos"].as_array().is_none_or(Vec::is_empty));
    drop(server);
}

#[test]
fn scan_finds_dotenv_files_and_says_what_git_does_with_them() {
    if !git_available() {
        return;
    }
    let root = tempfile::tempdir().expect("tempdir");
    let device = Device::new(root.path(), "home");
    let repo = root.path().join("repo");
    std::fs::create_dir_all(repo.join("web")).expect("repo");
    git(&repo, &["init", "-q"]);
    std::fs::write(repo.join(".gitignore"), ".env.local\n").expect("gitignore");
    std::fs::write(repo.join(".env"), format!("STRIPE_KEY={STRIPE}\n")).expect(".env");
    std::fs::write(repo.join(".env.local"), format!("DB={DATABASE}\n")).expect(".env.local");
    std::fs::write(repo.join(".env.example"), "STRIPE_KEY=\n").expect(".env.example");
    std::fs::write(repo.join("web/.env.production"), format!("T={TOKEN}\n")).expect("web");
    git(&repo, &["add", ".env", ".gitignore"]);
    git(&repo, &["commit", "-q", "-m", "oops"]);

    let scanned = device
        .run_in(Some(&repo), &["env", "scan", "--json"], "")
        .ok();
    no_leak(&scanned);
    let found = json(&scanned.stdout);
    let state = |name: &str| -> String {
        found
            .as_array()
            .expect("list")
            .iter()
            .find(|f| f["path"].as_str().is_some_and(|p| p.ends_with(name)))
            .map_or_else(
                || "missing".into(),
                |f| f["git"].as_str().unwrap_or("?").to_owned(),
            )
    };
    assert_eq!(state("/.env"), "tracked");
    assert_eq!(state(".env.local"), "ignored");
    assert_eq!(state("web/.env.production"), "untracked");
    assert_eq!(state(".env.example"), "missing");
    assert_eq!(found.as_array().map(Vec::len), Some(3));

    // Without a terminal it only lists, and says how to import.
    let listed = device.run_in(Some(&repo), &["env", "scan"], "").ok();
    no_leak(&listed);
    assert!(
        listed.stdout.contains("TRACKED by git"),
        "{}",
        listed.stdout
    );
    assert!(
        listed.stderr.contains("klav env import"),
        "{}",
        listed.stderr
    );
}
