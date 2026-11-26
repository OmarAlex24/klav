//! Environments per repository end to end (ADR 0032, the roadmap's
//! checklist) against a real `klav-server`, the CLI and the agent's runtime
//! (`klav agent run` and `klav mcp`):
//!
//! 1. `klav env import` of a `.env` whose value matches an item saves a
//!    reference, and no value reaches stdout or stderr;
//! 2. `klav run --env development` runs without presence, `--env
//!    production` needs it, and `klav run` without `--env` lists the
//!    environments when there are several;
//! 3. a `klav.toml` that forges `origin` only gets the suggestion, the
//!    warning and the confirmation;
//! 4. an agent with `--env development=allow` runs development without an
//!    approval; production asks once (no lease, never in a task); an item
//!    in another project it had a direct `allow` on asks once too, because
//!    production points to it; one approval covers production and that
//!    item; and `klav log verify` passes on the whole chain;
//! 5. a server that answers `allow` on the protected environment is
//!    refused by the agent's runtime with a security error.
//!
//! No test prints a value: they are compared in memory.

mod common;

use std::path::{Path, PathBuf};
use std::process::Command;

use common::mcp::Mcp;
use common::{Device, PASSWORD, Run, ServerProcess};
use serde_json::{Value, json};

const STRIPE: &str = "sk_live_MARKER_e2e_env_stripe_51";
const DATABASE: &str = "postgres://app:pw_MARKER_e2e_env_db@db.internal/app";
const PROD_URL: &str = "https://api.MARKER-e2e-env-prod.example";
const MARKERS: [&str; 3] = [STRIPE, DATABASE, PROD_URL];

#[track_caller]
fn no_leak(run: &Run) {
    for marker in MARKERS {
        assert!(
            !run.stdout.contains(marker) && !run.stderr.contains(marker),
            "a value reached the output"
        );
    }
}

fn json_of(out: &str) -> Value {
    serde_json::from_str(out).expect("json output")
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

/// An account with `Personal/payments/Stripe/api_key` (another project)
/// and a repository whose `klav.toml` names `Personal/acme-api`, which has
/// `development` (its own value) and `production` (protected: its own
/// value and a reference to Stripe).
fn setup(server: &ServerProcess, root: &Path) -> (Device, PathBuf) {
    let person = Device::new(root, "home");
    person.signup(server, "dev@example.com");
    for project in ["acme-api", "payments"] {
        person
            .unlocked(&["project", "create", "--vault", "Personal", project], "")
            .ok();
    }
    person
        .unlocked(
            &[
                "item",
                "add",
                "api-key",
                "--title",
                "Stripe",
                "--project",
                "payments",
                "--secret-stdin",
                "api_key",
            ],
            &format!("{STRIPE}\n"),
        )
        .ok();
    let repo = root.join("repo");
    std::fs::create_dir_all(&repo).expect("repo");
    std::fs::write(repo.join("klav.toml"), "project = \"Personal/acme-api\"\n").expect("klav.toml");
    (person, repo)
}

fn environments(person: &Device, repo: &Path) {
    person
        .unlocked_in(repo, &["env", "create", "development"], "")
        .ok();
    person
        .unlocked_in(
            repo,
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
    let created = person
        .unlocked_in(repo, &["env", "create", "production"], "")
        .ok();
    assert!(created.stderr.contains("protected"), "{}", created.stderr);
    person
        .unlocked_in(
            repo,
            &["env", "set", "production", "--secret-stdin", "API_URL"],
            &format!("{PROD_URL}\n"),
        )
        .ok();
    person
        .unlocked_in(
            repo,
            &[
                "env",
                "set",
                "production",
                "--ref",
                "STRIPE_KEY=klav://Personal/payments/Stripe/api_key",
            ],
            "",
        )
        .ok();
}

/// Registers agent `bot` on its own device and approves it with `extra`.
fn agent(server: &ServerProcess, root: &Path, person: &Device, extra: &[&str]) -> Device {
    let machine = Device::new(root, "agent");
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
    let mut args = vec![
        "agent",
        "approve",
        "bot",
        "--project",
        "Personal/acme-api",
        "--project",
        "Personal/payments",
        "--words",
        &words,
    ];
    args.extend_from_slice(extra);
    let approved = person.unlocked(&args, "").ok();
    no_leak(&approved);
    machine
}

fn item_id(person: &Device, title: &str) -> String {
    let got = person.unlocked(&["item", "get", title, "--json"], "").ok();
    json_of(&got.stdout)["id"].as_str().expect("id").to_owned()
}

/// The approval ID a pending `klav agent …` names on stderr.
fn pending_id(run: &Run) -> String {
    assert_eq!(run.code, 4, "{}", run.stderr);
    let at = run
        .stderr
        .find("klav approval approve ")
        .unwrap_or_else(|| panic!("no approval in {}", run.stderr));
    run.stderr[at + "klav approval approve ".len()..]
        .chars()
        .take(36)
        .collect()
}

#[test]
fn the_person_imports_runs_and_is_never_fooled_by_a_forged_origin() {
    let server = ServerProcess::start(900);
    let root = tempfile::tempdir().expect("tempdir");
    let (person, repo) = setup(&server, root.path());

    // 1. A `.env` whose STRIPE_KEY matches Stripe's field: a reference,
    //    and no value on any output.
    std::fs::write(
        repo.join(".env"),
        format!("STRIPE_KEY={STRIPE}\nDATABASE_URL=\"{DATABASE}\"\n"),
    )
    .expect(".env");
    let imported = person
        .unlocked_in(
            &repo,
            &["env", "import", ".env", "--env", "development", "--yes"],
            "",
        )
        .ok();
    no_leak(&imported);
    let shown = person
        .unlocked_in(&repo, &["env", "show", "development", "--json"], "")
        .ok();
    no_leak(&shown);
    let vars = json_of(&shown.stdout)["variables"].clone();
    let stripe_var = vars
        .as_array()
        .expect("variables")
        .iter()
        .find(|v| v["name"] == "STRIPE_KEY")
        .expect("STRIPE_KEY")
        .clone();
    assert_eq!(stripe_var["origin"], "reference", "{stripe_var}");
    std::fs::remove_file(repo.join(".env")).ok();

    // 2. Two environments and no `default_env`: listed, never guessed.
    person
        .unlocked_in(&repo, &["env", "create", "production"], "")
        .ok();
    person
        .unlocked_in(
            &repo,
            &["env", "set", "production", "--secret-stdin", "API_URL"],
            &format!("{PROD_URL}\n"),
        )
        .ok();
    let guess = person
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
    let dev = person
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
    no_leak(&dev);
    assert_eq!(
        std::fs::read_to_string(repo.join("dev.out")).expect("dev.out"),
        DATABASE
    );
    // production: presence, which --trust never skips (no terminal: 9).
    let refused = person.unlocked_in(
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
    let ran = person.in_terminal(
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
            "printf %s \"$API_URL\" > prod.out",
        ],
        &format!("{PASSWORD}\n"),
    );
    assert_eq!(ran.code, 0, "{}", ran.stderr);
    no_leak(&ran);
    assert_eq!(
        std::fs::read_to_string(repo.join("prod.out")).expect("prod.out"),
        PROD_URL
    );

    // 3. A clone that forges `origin` and asks for this project's secrets
    //    from another project's `klav.toml`: warned and still asked.
    if git_available() {
        person
            .unlocked(&["project", "create", "--vault", "Personal", "banco"], "")
            .ok();
        git(&repo, &["init", "-q"]);
        git(
            &repo,
            &[
                "remote",
                "add",
                "origin",
                "https://github.com/omar/acme-api.git",
            ],
        );
        person
            .unlocked_in(&repo, &["env", "link", "--yes"], "")
            .ok();
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
            "project = \"Personal/banco\"\n\n[env.development]\nSTRIPE_KEY = \"klav://Personal/payments/Stripe/api_key\"\n",
        )
        .expect("klav.toml");
        let asked = person
            .unlocked_in(
                &forged,
                &["run", "--env", "development", "--", "sh", "-c", "touch ran"],
                "",
            )
            .err();
        no_leak(&asked);
        assert!(!forged.join("ran").exists());
        assert!(
            asked.stderr.contains(
                "asks for secrets from Personal/banco, which isn't linked to github.com/omar/acme-api"
            ),
            "{}",
            asked.stderr
        );
        assert!(asked.stderr.contains("not confirmed"), "{}", asked.stderr);
    }
    drop(server);
}

#[test]
fn an_agent_runs_development_and_asks_once_for_production_and_what_it_uses() {
    let server = ServerProcess::start(900);
    let root = tempfile::tempdir().expect("tempdir");
    let (person, repo) = setup(&server, root.path());
    environments(&person, &repo);

    // `--env production=allow` is refused: a protected environment always
    // asks.
    let machine_words_refused = {
        let machine = Device::new(root.path(), "refused");
        let words = machine
            .run(
                &[
                    "agent",
                    "register",
                    "--name",
                    "other",
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
        person.unlocked(
            &[
                "agent",
                "grant",
                "other",
                "--project",
                "Personal/acme-api",
                "--env",
                "production=allow",
                "--words",
                &words,
            ],
            "",
        )
    };
    assert_eq!(
        machine_words_refused.code, 2,
        "{}",
        machine_words_refused.stderr
    );
    assert!(
        machine_words_refused
            .stderr
            .contains("“production” is protected"),
        "{}",
        machine_words_refused.stderr
    );

    let machine = agent(
        &server,
        root.path(),
        &person,
        &["--env", "development=allow", "--env", "production=ask"],
    );
    let stripe = item_id(&person, "Stripe");
    let envs = json_of(
        &person
            .unlocked_in(&repo, &["env", "ls", "--json"], "")
            .ok()
            .stdout,
    );
    let prod_id = envs
        .as_array()
        .expect("envs")
        .iter()
        .find(|e| e["name"] == "production")
        .expect("production")["id"]
        .as_str()
        .expect("id")
        .to_owned();

    // development: no approval.
    let dev = machine.run_in(
        Some(&repo),
        &[
            "agent",
            "run",
            "--env",
            "development",
            "--reason",
            "start the dev server",
            "--",
            "sh",
            "-c",
            "printf %s \"$DATABASE_URL\" > agent-dev.out",
        ],
        "",
    );
    assert_eq!(dev.code, 0, "{}", dev.stderr);
    no_leak(&dev);
    assert_eq!(
        std::fs::read_to_string(repo.join("agent-dev.out")).expect("agent-dev.out"),
        DATABASE
    );
    // Without --env and two environments: the list, never a guess.
    let guess = machine.run_in(
        Some(&repo),
        &["agent", "run", "--reason", "start", "--", "true"],
        "",
    );
    assert_eq!(guess.code, 2, "{}", guess.stderr);
    assert!(
        guess
            .stderr
            .contains("there are development and production: use --env"),
        "{}",
        guess.stderr
    );

    // Stripe, which the agent could inject directly before production
    // pointed to it, now asks once: no lease, no task.
    let outside = root.path().join("outside");
    std::fs::create_dir_all(&outside).expect("outside");
    let direct = machine.run_in(
        Some(&outside),
        &[
            "agent",
            "run",
            "--reason",
            "charge a test card",
            "-e",
            "S=klav://Personal/payments/Stripe/api_key",
            "--",
            "true",
        ],
        "",
    );
    no_leak(&direct);
    let direct_id = pending_id(&direct);
    let card = json_of(
        &person
            .unlocked(&["approval", "show", &direct_id, "--json"], "")
            .ok()
            .stdout,
    );
    assert_eq!(card["always_asks"], true, "{card}");
    let leased = person.unlocked(&["approval", "approve", &direct_id, "--for", "15m"], "");
    assert_eq!(leased.code, 2, "{}", leased.stderr);
    assert!(
        leased.stderr.contains("always asks for approval"),
        "{}",
        leased.stderr
    );
    person.unlocked(&["approval", "deny", &direct_id], "").ok();

    // production: pending, one card for production and Stripe.
    let asked = machine.run_in(
        Some(&repo),
        &[
            "agent",
            "run",
            "--env",
            "production",
            "--reason",
            "run the production migration",
            "--",
            "sh",
            "-c",
            "printf '%s|%s' \"$API_URL\" \"$STRIPE_KEY\" > agent-prod.out",
        ],
        "",
    );
    no_leak(&asked);
    assert!(!repo.join("agent-prod.out").exists());
    let id = pending_id(&asked);
    let card = json_of(
        &person
            .unlocked(&["approval", "show", &id, "--json"], "")
            .ok()
            .stdout,
    );
    assert_eq!(card["item_id"], prod_id.as_str(), "{card}");
    assert_eq!(card["always_asks"], true, "{card}");
    let items: Vec<&str> = card["items"]
        .as_array()
        .expect("items")
        .iter()
        .map(|i| i["id"].as_str().expect("id"))
        .collect();
    assert_eq!(items, vec![stripe.as_str()], "{card}");
    assert!(card["items_warning"].is_null(), "{card}");
    let shown = person.unlocked(&["approval", "show", &id], "").ok();
    assert!(
        shown.stdout.contains("Always asks for approval"),
        "{}",
        shown.stdout
    );
    // No lease and no task for it.
    for refused in [
        vec!["approval", "approve", id.as_str(), "--for", "15m"],
        vec!["approval", "approve", id.as_str(), "--add-to-task"],
    ] {
        let out = person.unlocked(&refused, "");
        assert_eq!(out.code, 2, "{}", out.stderr);
    }
    person.unlocked(&["approval", "approve", &id], "").ok();

    // The retry with that approval: production and Stripe, one card.
    let ran = machine.run_in(
        Some(&repo),
        &[
            "agent",
            "run",
            "--env",
            "production",
            "--approval",
            &id,
            "--reason",
            "run the production migration",
            "--",
            "sh",
            "-c",
            "printf '%s|%s' \"$API_URL\" \"$STRIPE_KEY\" > agent-prod.out",
        ],
        "",
    );
    assert_eq!(ran.code, 0, "{}", ran.stderr);
    no_leak(&ran);
    assert_eq!(
        std::fs::read_to_string(repo.join("agent-prod.out")).expect("agent-prod.out"),
        format!("{PROD_URL}|{STRIPE}")
    );
    // The approval is spent: the same retry asks again.
    let again = machine.run_in(
        Some(&repo),
        &[
            "agent",
            "run",
            "--env",
            "production",
            "--approval",
            &id,
            "--reason",
            "run the production migration",
            "--",
            "true",
        ],
        "",
    );
    assert_ne!(again.code, 0, "{}", again.stderr);

    // A task that names production: «Always asks for approval», unchecked.
    let task = root.path().join("task.toml");
    std::fs::write(
        &task,
        "task = \"Deploy\"\nreason = \"Release 1.2\"\nduration = \"1h\"\n\n[[access]]\nref = \"klav://Personal/acme-api/production\"\npermissions = [\"inject\"]\n",
    )
    .expect("task.toml");
    let requested = machine.run_in(
        Some(&repo),
        &[
            "agent",
            "task",
            "request",
            task.to_str().expect("utf-8"),
            "--json",
        ],
        "",
    );
    assert_eq!(requested.code, 4, "{}", requested.stderr);
    let task_id = json_of(&requested.stdout)["task_id"]
        .as_str()
        .expect("task_id")
        .to_owned();
    let card = json_of(
        &person
            .unlocked(&["task", "show", &task_id, "--json"], "")
            .ok()
            .stdout,
    );
    let inject = card["rows"][0]["permissions"]
        .as_array()
        .expect("permissions")
        .iter()
        .find(|p| p["permission"] == "inject")
        .expect("inject")
        .clone();
    assert_eq!(inject["always_asks"], true, "{card}");
    assert_eq!(inject["checked"], false, "{card}");
    let printed = person.unlocked(&["task", "show", &task_id], "").ok();
    assert!(
        printed.stdout.contains("Always asks for approval"),
        "{}",
        printed.stdout
    );

    // The whole chain verifies, bundle approval included.
    let verified = person.unlocked(&["log", "verify", "--json"], "").ok();
    let report = json_of(&verified.stdout);
    // The grant, the denial and the approval of production's bundle are
    // the account's; every access is the agent's.
    assert!(report["account_signatures"].as_u64() >= Some(3), "{report}");
    assert!(report["agent_signatures"].as_u64() >= Some(4), "{report}");
    drop(server);
}

/// Opens the stopped server's database.
async fn server_db(server: &ServerProcess) -> sqlx::AnyPool {
    sqlx::any::install_default_drivers();
    let url = format!("sqlite://{}", server.dir.path().join("klav.db").display());
    sqlx::any::AnyPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .expect("open server db")
}

#[tokio::test(flavor = "multi_thread")]
async fn a_server_that_allows_a_protected_environment_is_refused_by_the_runtime() {
    let mut server = ServerProcess::start(900);
    let root = tempfile::tempdir().expect("tempdir");
    let (person, repo) = setup(&server, root.path());
    environments(&person, &repo);
    person
        .unlocked_in(&repo, &["env", "create", "staging"], "")
        .ok();
    person
        .unlocked_in(
            &repo,
            &["env", "set", "staging", "--secret-stdin", "DATABASE_URL"],
            &format!("{DATABASE}\n"),
        )
        .ok();
    let machine = agent(
        &server,
        root.path(),
        &person,
        &["--env", "development=allow"],
    );

    // The runtime opens its session with the grant the account signed:
    // staging is not protected yet, and `inject` is allowed on it.
    let mut mcp = Mcp::start(&machine, &repo, None);
    mcp.initialize();
    let (text, err) = mcp.tool(
        "run_with_secrets",
        json!({ "command": ["true"], "environment": "staging", "reason": "warm up" }),
    );
    assert!(!err, "{text}");

    // The grant as the server keeps it now.
    server.stop();
    let pool = server_db(&server).await;
    let old: Vec<(String, i64, Vec<u8>, Vec<u8>)> = sqlx::query_as(
        "SELECT id, grant_version, grant_payload, grant_signature FROM agents \
         WHERE grant_payload IS NOT NULL",
    )
    .fetch_all(&pool)
    .await
    .expect("agents");
    pool.close().await;
    server.restart();

    // The person protects staging: the grants are issued again first.
    person
        .unlocked_in(&repo, &["env", "set", "staging", "--protected", "true"], "")
        .ok();

    // A malicious server serves the old grant again and lets the agent
    // `inject` anything: its copy of the policy has no rules left.
    server.stop();
    let pool = server_db(&server).await;
    for (id, version, payload, signature) in old {
        let mut payload: Value = serde_json::from_slice(&payload).expect("payload");
        payload["policy"] = json!({ "rules": [] });
        sqlx::query(
            "UPDATE agents SET grant_version = $1, grant_payload = $2, grant_signature = $3 \
             WHERE id = $4",
        )
        .bind(version)
        .bind(serde_json::to_vec(&payload).expect("json"))
        .bind(signature)
        .bind(id)
        .execute(&pool)
        .await
        .expect("hostile grant");
    }
    pool.close().await;
    server.restart();

    // Production: the grant the runtime holds asks once for it, and the
    // server's `allow` comes with no approval.
    // Staging: the runtime's grant still allows it, but the environment it
    // reads is protected by the person's latest version (§4.4).
    for env in ["production", "staging"] {
        let (text, err) = mcp.tool(
            "run_with_secrets",
            json!({
                "command": ["sh", "-c", "printf %s \"$DATABASE_URL$STRIPE_KEY\" > leaked.out"],
                "environment": env,
                "reason": "deploy",
                "wait_seconds": 0,
            }),
        );
        assert!(err, "{env}: {text}");
        assert!(
            text.contains("without an approval") && text.to_lowercase().contains("security"),
            "{env}: {text}"
        );
        if env == "staging" {
            assert!(text.contains("“staging” is protected"), "{text}");
        }
        for marker in MARKERS {
            assert!(!text.contains(marker), "a value reached the agent");
        }
        assert!(!repo.join("leaked.out").exists(), "the command ran");
    }
    mcp.finish();
    drop(server);
}
