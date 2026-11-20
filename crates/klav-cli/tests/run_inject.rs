//! `klav run` and `klav inject` against a real server: environment
//! variables for the child only, `[files]` and injected files with mode
//! 0600 removed on exit / TTL / signal, named pipes, and templates.

mod common;

use std::path::Path;
use std::process::Command;

use common::{Device, ServerProcess, mode, wait_child, wait_until};

const API_KEY: &str = "sk_live_MARKER_run_9f2";

fn git_available() -> bool {
    Command::new("git")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
}

fn p8_bytes() -> Vec<u8> {
    let mut bytes = b"-----BEGIN PRIVATE KEY-----\n".to_vec();
    bytes.extend(0u8..=255);
    bytes
}

/// Account with `Personal/acme-api/Stripe/api_key` and the file field
/// `Personal/acme-api/APNs/key`, plus a repository using them.
fn setup(server: &ServerProcess, root: &Path) -> (Device, std::path::PathBuf) {
    let device = Device::new(root, "home");
    device.signup(server, "dev@example.com");
    device
        .unlocked(
            &["project", "create", "--vault", "Personal", "acme-api"],
            "",
        )
        .ok();
    device
        .unlocked(
            &[
                "item",
                "add",
                "api-key",
                "--title",
                "Stripe",
                "--project",
                "acme-api",
                "--secret-stdin",
                "api_key",
            ],
            &format!("{API_KEY}\n"),
        )
        .ok();
    device
        .unlocked(
            &[
                "item",
                "add",
                "note",
                "--title",
                "APNs",
                "--project",
                "acme-api",
            ],
            "",
        )
        .ok();
    let p8 = root.join("AuthKey_ABC.p8");
    std::fs::write(&p8, p8_bytes()).expect("p8");
    device
        .unlocked(
            &["item", "attach", "APNs", "key", p8.to_str().expect("utf-8")],
            "",
        )
        .ok();
    std::fs::remove_file(&p8).expect("rm p8");

    let repo = root.join("repo");
    std::fs::create_dir_all(repo.join("src")).expect("repo");
    if git_available() {
        let ok = Command::new("git")
            .args(["init", "-q"])
            .current_dir(&repo)
            .status()
            .expect("git init")
            .success();
        assert!(ok);
    }
    std::fs::write(repo.join(".gitignore"), "secrets/\n").expect("gitignore");
    std::fs::write(
        repo.join("klav.toml"),
        "project = \"Personal/acme-api\"\n\n[env]\nSTRIPE_KEY = \"Stripe/api_key\"\n\n[files]\n\"secrets/AuthKey.p8\" = \"APNs/key\"\n",
    )
    .expect("klav.toml");
    (device, repo)
}

#[test]
fn run_and_inject_deliver_secrets_without_leaving_them_behind() {
    let server = ServerProcess::start(900);
    let root = tempfile::tempdir().expect("tempdir");
    let (device, repo) = setup(&server, root.path());
    let src = repo.join("src");

    // The attachment shows as a file, not as content.
    let shown = device.unlocked(&["item", "get", "APNs"], "").ok();
    assert!(shown.stdout.contains("AuthKey_ABC.p8"), "{}", shown.stdout);

    // run, from a subdirectory: klav.toml is found upwards; the child sees
    // STRIPE_KEY and the 0600 file, which is gone afterwards.
    let script = "printf %s \"$STRIPE_KEY\" > ../env.out; \
                  cp ../secrets/AuthKey.p8 ../copy.p8; \
                  ls -l ../secrets/AuthKey.p8 | cut -c1-10 > ../mode.out";
    let out = device
        .unlocked_in(&src, &["run", "--trust", "--", "sh", "-c", script], "")
        .ok();
    assert!(!out.stdout.contains(API_KEY));
    assert_eq!(
        std::fs::read_to_string(repo.join("env.out")).expect("env.out"),
        API_KEY
    );
    assert_eq!(
        std::fs::read(repo.join("copy.p8")).expect("copy"),
        p8_bytes()
    );
    assert_eq!(
        std::fs::read_to_string(repo.join("mode.out"))
            .expect("mode")
            .trim(),
        "-rw-------"
    );
    assert!(!repo.join("secrets/AuthKey.p8").exists());
    // secrets/ is in .gitignore: no warning.
    assert!(!out.stderr.contains("gitignore"), "{}", out.stderr);

    // The child's exit code is klav's; files are removed anyway. A
    // temporary of another write beside a `[files]` entry is reported, and
    // left as it was.
    let left = repo.join("secrets/.AuthKey.p8.0123456789abcdef.klav-tmp");
    std::fs::write(&left, b"MARKER-left").expect("leftover");
    let failed = device.unlocked_in(&src, &["run", "--", "sh", "-c", "exit 7"], "");
    assert_eq!(failed.code, 7);
    assert!(!repo.join("secrets/AuthKey.p8").exists());
    assert!(
        failed
            .stderr
            .contains(".AuthKey.p8.0123456789abcdef.klav-tmp")
            && failed.stderr.contains("Klav did not delete it")
            && !failed.stderr.contains("MARKER"),
        "{}",
        failed.stderr
    );
    assert_eq!(std::fs::read(&left).expect("left"), b"MARKER-left");
    std::fs::remove_file(&left).expect("rm leftover");

    // Inherited NAME=klav://… variables and -e are resolved too.
    let mut cmd = device.command();
    cmd.current_dir(root.path())
        .env("FROM_ENV", "klav://Personal/acme-api/Stripe/api_key")
        .args([
            "--password-stdin",
            "run",
            "-e",
            "EXTRA=klav://Personal/acme-api/Stripe/api_key",
            "--",
            "sh",
            "-c",
            "printf '%s|%s' \"$FROM_ENV\" \"$EXTRA\"",
        ]);
    let mut child = cmd.spawn().expect("spawn");
    {
        use std::io::Write;
        child
            .stdin
            .take()
            .expect("stdin")
            .write_all(format!("{}\n", common::PASSWORD).as_bytes())
            .expect("stdin");
    }
    let output = child.wait_with_output().expect("wait");
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).expect("utf-8"),
        format!("{API_KEY}|{API_KEY}")
    );

    // An unknown reference fails before running anything.
    let unknown = device.unlocked_in(
        &src,
        &[
            "run",
            "-e",
            "X=klav://Personal/acme-api/Nope/x",
            "--",
            "sh",
            "-c",
            "touch ../ran",
        ],
        "",
    );
    assert_ne!(unknown.code, 0);
    assert!(!repo.join("ran").exists());

    // inject: template to a 0600 file, warning because .env is not ignored.
    std::fs::write(
        repo.join(".env.tpl"),
        "STRIPE_KEY={{ klav://Personal/acme-api/Stripe/api_key }}\nOTHER={{ keep }}\n",
    )
    .expect("tpl");
    let injected = device
        .unlocked_in(&repo, &["inject", "-i", ".env.tpl", "-o", ".env"], "")
        .ok();
    assert_eq!(
        std::fs::read_to_string(repo.join(".env")).expect(".env"),
        format!("STRIPE_KEY={API_KEY}\nOTHER={{{{ keep }}}}\n")
    );
    assert_eq!(mode(&repo.join(".env")), 0o600);
    if git_available() {
        // The advice names the temporary file too: the rule for .env does
        // not cover `..env.<16 hex>.klav-tmp`.
        assert!(
            injected.stderr.contains(".gitignore") && injected.stderr.contains("*.klav-tmp"),
            "{}",
            injected.stderr
        );
    }
    // It does not overwrite without --force.
    let again = device.unlocked_in(&repo, &["inject", "-i", ".env.tpl", "-o", ".env"], "");
    assert_ne!(again.code, 0);
    assert!(
        !again.stderr.contains("Klav did not delete"),
        "{}",
        again.stderr
    );
    device
        .unlocked_in(
            &repo,
            &["inject", "-i", ".env.tpl", "-o", ".env", "--force"],
            "",
        )
        .ok();

    // A temporary of another write beside .env is reported after the
    // write, whether it failed or not, and left as it was; the exit codes
    // are those without it.
    let left = repo.join("..env.0123456789abcdef.klav-tmp");
    std::fs::write(&left, b"MARKER-left").expect("leftover");
    std::fs::set_permissions(&left, std::os::unix::fs::PermissionsExt::from_mode(0o600))
        .expect("chmod");
    let refused = device.unlocked_in(&repo, &["inject", "-i", ".env.tpl", "-o", ".env"], "");
    assert_eq!(refused.code, again.code, "{}", refused.stderr);
    let replaced = device
        .unlocked_in(
            &repo,
            &["inject", "-i", ".env.tpl", "-o", ".env", "--force"],
            "",
        )
        .ok();
    for out in [&refused.stderr, &replaced.stderr] {
        assert!(
            out.contains("..env.0123456789abcdef.klav-tmp")
                && out.contains("Klav did not delete it"),
            "{out}"
        );
        assert!(!out.contains("MARKER"), "{out}");
    }
    assert_eq!(std::fs::read(&left).expect("left"), b"MARKER-left");
    assert_eq!(mode(&left), 0o600);
    std::fs::remove_file(&left).expect("rm leftover");

    // inject -r with a short reference and --ttl: 0600 while it lives,
    // removed when the TTL ends.
    let target = repo.join("secrets/k.p8");
    std::fs::create_dir_all(repo.join("secrets")).expect("secrets dir");
    let mut child = device.spawn_unlocked(
        &repo,
        &[
            "inject",
            "-r",
            "APNs/key",
            "-o",
            "secrets/k.p8",
            "--ttl",
            "3s",
        ],
    );
    assert!(wait_until(30, || target.exists()), "file never appeared");
    assert_eq!(mode(&target), 0o600);
    assert_eq!(std::fs::read(&target).expect("read"), p8_bytes());
    assert_eq!(wait_child(&mut child, 30), 0);
    assert!(!target.exists(), "file left after the TTL");

    // A signal removes it before the TTL.
    let mut child = device.spawn_unlocked(
        &repo,
        &[
            "inject",
            "-r",
            "APNs/key",
            "-o",
            "secrets/k.p8",
            "--ttl",
            "1h",
        ],
    );
    assert!(wait_until(30, || target.exists()), "file never appeared");
    let ok = Command::new("kill")
        .arg("-TERM")
        .arg(child.id().to_string())
        .status()
        .expect("kill")
        .success();
    assert!(ok);
    wait_child(&mut child, 30);
    assert!(!target.exists(), "file left after SIGTERM");

    // --fifo: read once through a named pipe, never written to disk.
    let pipe = repo.join("secrets/pipe");
    let mut child = device.spawn_unlocked(
        &repo,
        &[
            "inject",
            "-r",
            "klav://Personal/acme-api/Stripe/api_key",
            "-o",
            "secrets/pipe",
            "--fifo",
        ],
    );
    assert!(wait_until(30, || pipe.exists()), "pipe never appeared");
    {
        use std::os::unix::fs::FileTypeExt;
        let kind = std::fs::symlink_metadata(&pipe).expect("meta").file_type();
        assert!(kind.is_fifo());
    }
    assert_eq!(mode(&pipe), 0o600);
    assert_eq!(std::fs::read_to_string(&pipe).expect("read pipe"), API_KEY);
    assert_eq!(wait_child(&mut child, 30), 0);
    assert!(!pipe.exists(), "pipe left behind");

    drop(server);
}

/// References are shown with names as written (spaces, accents) and work
/// that way everywhere: `klav.toml`, inherited variables, `-e` and
/// templates. The fully encoded form older versions showed still works.
#[test]
fn references_with_spaces_and_accents_work_as_shown() {
    let server = ServerProcess::start(900);
    let root = tempfile::tempdir().expect("tempdir");
    let device = Device::new(root.path(), "home");
    device.signup(&server, "dev@example.com");
    device
        .unlocked(
            &["project", "create", "--vault", "Personal", "Café con leche"],
            "",
        )
        .ok();
    device
        .unlocked(
            &[
                "item",
                "add",
                "api-key",
                "--title",
                "Banco Azul",
                "--project",
                "Café con leche",
                "--secret-stdin",
                "api_key",
            ],
            &format!("{API_KEY}\n"),
        )
        .ok();

    let shown = "klav://Personal/Café con leche/Banco Azul";
    let listed = device.unlocked(&["item", "ls"], "").ok();
    assert!(listed.stdout.contains(shown), "{}", listed.stdout);
    assert!(!listed.stdout.contains("%20"), "{}", listed.stdout);
    let old = "klav://Personal/Caf%C3%A9%20con%20leche/Banco%20Azul/api_key";

    let repo = root.path().join("repo");
    std::fs::create_dir_all(&repo).expect("repo");
    std::fs::write(
        repo.join("klav.toml"),
        format!(
            "project = \"Personal/Café con leche\"\n\n[env]\nA = \"{shown}/api_key\"\nB = \"Banco Azul/api_key\"\nC = \"{old}\"\n"
        ),
    )
    .expect("klav.toml");
    let mut cmd = device.command();
    cmd.current_dir(&repo)
        .env("FROM_ENV", format!("{shown}/api_key "))
        .args([
            "--password-stdin",
            "run",
            "--trust",
            "-e",
            &format!("EXTRA={shown}/api_key"),
            "--",
            "sh",
            "-c",
            "printf '%s|%s|%s|%s|%s' \"$A\" \"$B\" \"$C\" \"$FROM_ENV\" \"$EXTRA\"",
        ]);
    let mut child = cmd.spawn().expect("spawn");
    {
        use std::io::Write;
        child
            .stdin
            .take()
            .expect("stdin")
            .write_all(format!("{}\n", common::PASSWORD).as_bytes())
            .expect("stdin");
    }
    let output = child.wait_with_output().expect("wait");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout).expect("utf-8"),
        [API_KEY; 5].join("|")
    );

    std::fs::write(
        repo.join("conf.tpl"),
        format!("A={{{{ {shown}/api_key }}}}\nC={{{{ {old} }}}}\n"),
    )
    .expect("tpl");
    let injected = device
        .unlocked_in(&repo, &["inject", "-i", "conf.tpl"], "")
        .ok();
    assert_eq!(injected.stdout, format!("A={API_KEY}\nC={API_KEY}\n"));

    drop(server);
}
