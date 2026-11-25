//! `klav signup` on a server in `invite` mode (ADR 0048 §2): the code comes
//! from `--invite`, `KLAV_INVITE` or a visible prompt, and a bad one stops
//! before the master password, the emergency kit and the key derivation.
//! Also a quota's message, as the server wrote it.

mod common;

use std::io::Write;
use std::process::Output;

use common::{Device, PASSWORD, ServerProcess};

/// `klav --password-stdin signup` on `server` with `extra` arguments, the
/// environment `env` and `stdin`. Returns the exit code and stderr.
fn signup(
    device: &Device,
    server: &ServerProcess,
    email: &str,
    kit: &std::path::Path,
    extra: &[&str],
    env: &[(&str, &str)],
    stdin: &str,
) -> (i32, String) {
    let mut cmd = device.command();
    cmd.env_remove("KLAV_INVITE");
    for (k, v) in env {
        cmd.env(k, v);
    }
    let mut args = vec![
        "signup",
        "--server",
        server.url.as_str(),
        "--email",
        email,
        "--device-name",
        "test",
        "--emergency-kit",
        kit.to_str().expect("utf-8 path"),
    ];
    if !stdin.is_empty() {
        args.insert(0, "--password-stdin");
    }
    args.extend_from_slice(extra);
    let mut child = cmd.args(&args).spawn().expect("spawn klav");
    let mut input = child.stdin.take().expect("stdin");
    match input.write_all(stdin.as_bytes()) {
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {}
        other => other.expect("write stdin"),
    }
    drop(input);
    let Output { status, stderr, .. } = child.wait_with_output().expect("wait klav");
    (
        status.code().unwrap_or(-1),
        String::from_utf8(stderr).expect("utf-8"),
    )
}

#[test]
fn an_invite_server_asks_for_the_code_before_the_password() {
    let server = ServerProcess::start_invite();
    let root = tempfile::tempdir().expect("tempdir");
    let device = Device::new(root.path(), "a");
    let kit = root.path().join("kit.txt");

    // No code and no terminal: never read from stdin (where the master
    // password goes), and say how to give it.
    let (code, stderr) = signup(&device, &server, "ana@example.com", &kit, &[], &[], "");
    assert_eq!(code, 2, "{stderr}");
    assert!(
        stderr.contains("127.0.0.1 takes new accounts by invite only")
            && stderr.contains("--invite CODE or KLAV_INVITE"),
        "{stderr}"
    );
    assert!(!stderr.to_lowercase().contains("password"), "{stderr}");
    assert!(!kit.exists());
    assert!(!device.home.join("account.json").exists());

    // A bad code, by flag or by environment, without a password on stdin:
    // asking for one would fail differently.
    let (bound, _) = server.create_invite(&["--email", "ana@example.com"]);
    for (extra, env, email) in [
        (
            vec!["--invite", "KLAV-NOT-A-CODE"],
            vec![],
            "ana@example.com",
        ),
        (
            vec![],
            vec![("KLAV_INVITE", bound.as_str())],
            "bob@example.com",
        ),
    ] {
        let extra: Vec<&str> = extra;
        let (code, stderr) = signup(&device, &server, email, &kit, &extra, &env, "");
        assert_ne!(code, 0, "{stderr}");
        assert!(
            stderr.contains(&format!(
                "This invite code isn't valid for {email}. Check the code, or request one at https://klav.dev."
            )),
            "{stderr}"
        );
        assert!(!stderr.to_lowercase().contains("password"), "{stderr}");
        assert!(!stderr.contains(&bound), "the code is never printed");
        assert!(!kit.exists());
        assert!(!device.home.join("account.json").exists());
    }

    // `--help` names the variable, never its value.
    let help = device
        .command()
        .env("KLAV_INVITE", &bound)
        .args(["signup", "--help"])
        .output()
        .expect("help");
    let help = String::from_utf8(help.stdout).expect("utf-8");
    assert!(help.contains("KLAV_INVITE"), "{help}");
    assert!(!help.contains(&bound), "{help}");
}

#[test]
fn an_invite_signs_up_from_the_flag_or_the_environment() {
    let server = ServerProcess::start_invite();
    let root = tempfile::tempdir().expect("tempdir");
    let (ana_code, _) = server.create_invite(&["--email", "ana@example.com"]);
    let (batch, _) = server.create_invite(&["--uses", "2", "--expires", "1d"]);

    let ana = Device::new(root.path(), "ana");
    let kit = root.path().join("ana-kit.txt");
    let (code, stderr) = signup(
        &ana,
        &server,
        "ana@example.com",
        &kit,
        &["--invite", &ana_code],
        &[],
        &format!("{PASSWORD}\n"),
    );
    assert_eq!(code, 0, "{stderr}");
    assert!(
        stderr.contains("Account created: ana@example.com"),
        "{stderr}"
    );
    assert!(kit.exists());
    assert!(!stderr.contains(&ana_code), "the code is never printed");

    let bob = Device::new(root.path(), "bob");
    let kit = root.path().join("bob-kit.txt");
    let (code, stderr) = signup(
        &bob,
        &server,
        "bob@example.com",
        &kit,
        &[],
        &[("KLAV_INVITE", batch.as_str())],
        &format!("{PASSWORD}\n"),
    );
    assert_eq!(code, 0, "{stderr}");
    assert!(
        stderr.contains("Account created: bob@example.com"),
        "{stderr}"
    );

    // Spent: Ana's bound code no longer signs anyone up.
    let carla = Device::new(root.path(), "carla");
    let kit = root.path().join("carla-kit.txt");
    let (code, stderr) = signup(
        &carla,
        &server,
        "ana@example.com",
        &kit,
        &["--invite", &ana_code],
        &[],
        "",
    );
    assert_ne!(code, 0, "{stderr}");
    assert!(stderr.contains("This invite code isn't valid"), "{stderr}");
    assert!(!kit.exists());
}

#[test]
fn an_open_server_takes_no_invite_and_a_closed_one_says_so() {
    let open = ServerProcess::start(900);
    let closed = ServerProcess::start_closed();
    let root = tempfile::tempdir().expect("tempdir");
    let device = Device::new(root.path(), "a");
    let kit = root.path().join("kit.txt");
    // An invite given to an open server is simply not needed.
    let (code, stderr) = signup(
        &device,
        &open,
        "ana@example.com",
        &kit,
        &["--invite", "KLAV-HX98F-9KZK5-3TMTZ-B8ZFE-4QV96W"],
        &[],
        &format!("{PASSWORD}\n"),
    );
    assert_eq!(code, 0, "{stderr}");

    let other = Device::new(root.path(), "b");
    let kit = root.path().join("kit-b.txt");
    let (code, stderr) = signup(
        &other,
        &closed,
        "bob@example.com",
        &kit,
        &["--invite", "KLAV-HX98F-9KZK5-3TMTZ-B8ZFE-4QV96W"],
        &[],
        "",
    );
    assert_ne!(code, 0);
    assert!(stderr.contains("is not open yet"), "{stderr}");
    assert!(!kit.exists());
}

#[test]
fn a_quota_is_said_in_the_servers_words() {
    let server = ServerProcess::start_config("[limits]\nmax_vaults_per_account = 1\n");
    let root = tempfile::tempdir().expect("tempdir");
    let device = Device::new(root.path(), "a");
    device.signup(&server, "ana@example.com");
    let out = device.unlocked(&["vault", "create", "Work"], "").err();
    assert!(
        out.stderr.contains("This account is limited to 1 vaults"),
        "{}",
        out.stderr
    );
}
