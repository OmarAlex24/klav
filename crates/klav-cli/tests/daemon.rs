//! `klav` with `klavd`: `unlock` starts the daemon, later commands need
//! no password, the idle timer locks it, `lock --stop` ends it.

mod common;

use common::{Device, ServerProcess, mode, wait_until};

/// Stops the daemon even if the test fails.
struct StopDaemon<'a>(&'a Device);

impl Drop for StopDaemon<'_> {
    fn drop(&mut self) {
        let _ = self.0.run(&["lock", "--stop"], "");
    }
}

fn daemon_status(device: &Device) -> serde_json::Value {
    let out = device.run(&["status", "--json"], "").ok();
    let status: serde_json::Value = serde_json::from_str(&out.stdout).expect("status json");
    status["klavd"].clone()
}

#[test]
fn the_daemon_keeps_the_account_unlocked_until_idle() {
    common::built_binary("klavd");
    let server = ServerProcess::start(900);
    let root = tempfile::tempdir().expect("tempdir");
    let device = Device::new(root.path(), "home");
    device.signup(&server, "daemon@example.com");
    let _stop = StopDaemon(&device);

    // `unlock` starts klavd and unlocks it. The idle lock is long here, so
    // that no step below depends on how fast the machine runs the commands
    // (each one is a new process); the idle lock is checked on its own
    // further down.
    let out = device.unlocked(&["unlock", "--idle-lock", "10m"], "").ok();
    assert!(out.stderr.contains("Unlocked"), "{}", out.stderr);
    let status = daemon_status(&device);
    assert_eq!(status["unlocked"], true);
    assert_eq!(status["unlocked_with"], "password");
    assert_eq!(status["idle_lock_secs"], 600);
    let socket = device.home.join("klavd.sock");
    assert_eq!(mode(&socket), 0o600);

    // No password (and no terminal) needed now.
    device
        .run(
            &[
                "item",
                "add",
                "api-key",
                "--title",
                "Daemon key",
                "--secret-stdin",
                "api_key",
            ],
            "MARKER-daemon-secret\n",
        )
        .ok();
    let got = device
        .run(
            &[
                "item",
                "get",
                "klav://Personal/General/Daemon%20key/api_key",
                "--reveal",
            ],
            "",
        )
        .ok();
    assert_eq!(got.stdout.trim(), "MARKER-daemon-secret");
    let ran = device
        .run(
            &[
                "run",
                "-e",
                "K=klav://Personal/General/Daemon%20key/api_key",
                "--",
                "sh",
                "-c",
                "printf %s \"$K\"",
            ],
            "",
        )
        .ok();
    assert_eq!(ran.stdout, "MARKER-daemon-secret");

    // The generator keeps what it makes through klavd (ADR 0022 §2), in a
    // system project that lists and grants never show.
    let made = device
        .run(&["generate", "--site", "https://github.com/login"], "")
        .ok();
    let password = made.stdout.trim().to_owned();
    assert!(password.len() >= 20, "{}", made.stdout);
    assert!(!made.stderr.contains("not kept"), "{}", made.stderr);
    let history = |device: &Device| -> serde_json::Value {
        let out = device.run(&["generated", "ls", "--json"], "").ok();
        assert!(!out.stdout.contains(&password), "a value in ls");
        serde_json::from_str(&out.stdout).expect("generated json")
    };
    let entries = history(&device);
    assert_eq!(entries.as_array().map(Vec::len), Some(1), "{entries}");
    assert_eq!(entries[0]["host"], "github.com");
    let shown = device.run(&["generated", "show", "0"], "").ok();
    assert_eq!(shown.stdout.trim(), password);
    assert!(
        wait_until(30, || history(&device)[0]["pending"] == false),
        "the outbox did not reach the generator history"
    );
    let projects = device.run(&["project", "ls"], "").ok();
    assert!(!projects.stdout.contains("Klav"), "{}", projects.stdout);
    let items = device.run(&["item", "ls", "--json"], "").ok();
    assert!(!items.stdout.contains("Generator"), "{}", items.stdout);
    // Saved in a login: the entry says where. A new password for it keeps
    // the generated one as a previous password.
    device
        .run(
            &[
                "item",
                "add",
                "login",
                "--title",
                "GitHub",
                "--url",
                "https://github.com",
                "--secret-stdin",
                "password",
            ],
            &format!("{password}\n"),
        )
        .ok();
    assert_eq!(history(&device)[0]["saved_in_title"], "GitHub");
    device
        .run(&["item", "edit", "GitHub", "-g", "password"], "")
        .ok();
    let previous = device
        .run(&["item", "history", "GitHub", "--json"], "")
        .ok();
    assert!(!previous.stdout.contains(&password));
    let previous: serde_json::Value = serde_json::from_str(&previous.stdout).expect("json");
    assert_eq!(previous["entries"].as_array().map(Vec::len), Some(1));
    assert_eq!(previous["entries"][0]["field"], "password");
    let revealed = device
        .run(&["item", "history", "GitHub", "--reveal", "0"], "")
        .ok();
    assert_eq!(revealed.stdout.trim(), password);
    let removed = device.run(&["generated", "rm", "--all"], "").ok();
    assert!(removed.stderr.contains("Deleted 1"), "{}", removed.stderr);
    assert_eq!(history(&device).as_array().map(Vec::len), Some(0));

    // --no-daemon ignores it (and has no password here).
    let direct = device.run(&["--no-daemon", "item", "ls"], "");
    assert_ne!(direct.code, 0);

    // `lock` forgets the account; a command with --password-stdin unlocks
    // it again.
    device.run(&["lock"], "").ok();
    assert_eq!(daemon_status(&device)["unlocked"], false);
    let locked = device.run(&["item", "ls"], "");
    assert_ne!(locked.code, 0, "{}", locked.stdout);
    let listed = device.unlocked(&["item", "ls"], "").ok();
    assert!(listed.stdout.contains("Daemon key"), "{}", listed.stdout);
    assert_eq!(daemon_status(&device)["unlocked"], true);

    // `lock --stop` ends it.
    device.run(&["lock", "--stop"], "").ok();
    assert!(wait_until(10, || !socket.exists()), "socket left behind");
    let status = device.run(&["status", "--json"], "").ok();
    assert!(
        status.stdout.contains("\"daemon\": \"not running\""),
        "{}",
        status.stdout
    );

    // The idle timer locks it: a new daemon with a short idle lock, and
    // nothing else to do but wait (`status` does not count as use). Only
    // "it locks within the deadline" is asserted, never a timing.
    device.unlocked(&["unlock", "--idle-lock", "2s"], "").ok();
    assert_eq!(daemon_status(&device)["idle_lock_secs"], 2);
    assert!(
        wait_until(30, || daemon_status(&device)["unlocked"] == false),
        "klavd did not lock after the idle time"
    );
    let locked = device.run(&["item", "ls"], "");
    assert_ne!(locked.code, 0, "{}", locked.stdout);
    // Its log says why it locked, and nothing of the account.
    let log = std::fs::read_to_string(device.home.join("klavd.log")).expect("klavd.log");
    assert!(
        log.contains("klavd: locked on its own at ") && log.contains(": idle for 2s"),
        "{log}"
    );
    assert!(!log.contains("MARKER-daemon-secret") && !log.contains(&password));
    drop(server);
}

/// One connection to `klavd`, kept open as the apps keep theirs.
struct Socket {
    reader: std::io::BufReader<std::os::unix::net::UnixStream>,
    writer: std::os::unix::net::UnixStream,
    next: u64,
}

impl Socket {
    fn connect(path: &std::path::Path) -> Self {
        let writer = std::os::unix::net::UnixStream::connect(path).expect("connect");
        let reader = std::io::BufReader::new(writer.try_clone().expect("clone"));
        Self {
            reader,
            writer,
            next: 1,
        }
    }

    /// `request`'s answer, or its error code.
    fn ask(&mut self, request: &serde_json::Value) -> Result<serde_json::Value, String> {
        use std::io::{BufRead, Write};
        let line = serde_json::json!({ "v": 1, "id": self.next, "request": request });
        self.next += 1;
        let mut bytes = serde_json::to_vec(&line).expect("json");
        bytes.push(b'\n');
        self.writer.write_all(&bytes).expect("write");
        let mut answer = String::new();
        self.reader.read_line(&mut answer).expect("read");
        let answer: serde_json::Value = serde_json::from_str(&answer).expect("answer json");
        match answer.get("ok") {
            Some(ok) => Ok(ok.clone()),
            None => Err(answer["error"]["code"].as_str().unwrap_or("?").to_owned()),
        }
    }

    fn locks_in_secs(&mut self) -> u64 {
        let status = self
            .ask(&serde_json::json!({ "op": "status" }))
            .expect("status");
        status["locks_in_secs"].as_u64().expect("locks_in_secs")
    }
}

/// What the Mac app and the extension ask for on their own, and other
/// reads of lists and state: none counts as use for the idle lock.
fn reads() -> Vec<serde_json::Value> {
    use serde_json::json;
    vec![
        json!({ "op": "status" }),
        json!({ "op": "approvals" }),
        json!({ "op": "agents" }),
        json!({ "op": "tasks" }),
        json!({ "op": "sandbox_list" }),
        json!({ "op": "sandbox_list_checked" }),
        json!({ "op": "proxy_status" }),
        json!({ "op": "vaults" }),
        json!({ "op": "projects" }),
        json!({ "op": "list", "filter": {} }),
        json!({ "op": "suggest", "url": "https://example.com/" }),
        json!({ "op": "password_history", "query": "Idle key" }),
        json!({ "op": "generator_history" }),
        json!({ "op": "agent_revocations" }),
        json!({ "op": "audit_status" }),
        json!({ "op": "health_settings" }),
        json!({ "op": "passkey_uv" }),
    ]
}

/// Reading lists and state does not count as use: a client that polls
/// does not keep `klavd` unlocked, and a request that hands out a value
/// still puts the idle lock off.
#[test]
fn reads_of_lists_and_state_do_not_keep_the_daemon_unlocked() {
    common::built_binary("klavd");
    let server = ServerProcess::start(900);
    let root = tempfile::tempdir().expect("tempdir");
    let device = Device::new(root.path(), "home");
    device.signup(&server, "idle@example.com");
    let _stop = StopDaemon(&device);
    let socket_path = device.home.join("klavd.sock");

    // A long idle lock first: the time left, which `status` reports, does
    // not grow with reads, and grows back with a use.
    device.unlocked(&["unlock", "--idle-lock", "60s"], "").ok();
    device
        .run(
            &[
                "item",
                "add",
                "api-key",
                "--title",
                "Idle key",
                "--secret-stdin",
                "api_key",
            ],
            "MARKER-idle-secret\n",
        )
        .ok();
    let mut socket = Socket::connect(&socket_path);
    std::thread::sleep(std::time::Duration::from_secs(3));
    let before = socket.locks_in_secs();
    assert!(before <= 57, "{before}");
    for request in reads() {
        // Each one must work: one that fails would never count anyway.
        if let Err(code) = socket.ask(&request) {
            panic!("{request}: {code}");
        }
    }
    let after = socket.locks_in_secs();
    assert!(
        after <= before,
        "a read put off the idle lock: {before} → {after}"
    );
    // One item's fields are use, also without its values.
    socket
        .ask(&serde_json::json!({ "op": "view", "query": "Idle key", "reveal": false }))
        .expect("view");
    let used = socket.locks_in_secs();
    assert!(
        used >= 58,
        "a use did not put off the idle lock: {after} → {used}"
    );
    drop(socket);

    // A short idle lock under a stream of reads, every one answered until
    // it locks: it locks all the same.
    device.run(&["lock", "--stop"], "").ok();
    assert!(
        wait_until(10, || !socket_path.exists()),
        "klavd did not stop"
    );
    device.unlocked(&["unlock", "--idle-lock", "2s"], "").ok();
    let mut socket = Socket::connect(&socket_path);
    let mut answered = 0;
    let locked = wait_until(30, || {
        for request in reads() {
            match socket.ask(&request) {
                Ok(_) => answered += 1,
                Err(code) if code == "locked" => return true,
                Err(code) => panic!("{request}: {code}"),
            }
        }
        false
    });
    assert!(
        locked,
        "klavd stayed unlocked under a stream of reads ({answered} answered)"
    );
    assert!(answered > reads().len(), "only {answered} reads answered");
    let log = std::fs::read_to_string(device.home.join("klavd.log")).expect("klavd.log");
    assert!(log.contains(": idle for 2s"), "{log}");
    assert!(!log.contains("MARKER-idle-secret"));
    drop(server);
}

/// On a Mac with Touch ID, a password unlock enrols the Secure Enclave key
/// without any prompt; using it needs a finger and is not exercised here
/// (see `klav-touchid`'s ignored test).
#[cfg(target_os = "macos")]
#[test]
fn a_password_unlock_enrols_touch_id_when_available() {
    let server = ServerProcess::start(900);
    let root = tempfile::tempdir().expect("tempdir");
    let device = Device::new(root.path(), "home");
    device.signup(&server, "touch@example.com");
    let _stop = StopDaemon(&device);
    let mut cmd = device.command();
    cmd.env_remove("KLAV_NO_TOUCH_ID")
        .args(["--password-stdin", "unlock"]);
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
    assert!(child.wait_with_output().expect("wait").status.success());
    let status = daemon_status(&device);
    let enrolment = device.home.join("touchid.json");
    if status["touch_id"]["available"] == true {
        assert_eq!(status["touch_id"]["enrolled"], true, "{status}");
        assert!(status["touch_id"]["password_required"].is_null());
        assert_eq!(mode(&enrolment), 0o600);
        let text = std::fs::read_to_string(&enrolment).expect("enrolment");
        assert!(text.contains("\"wrapped\""));
    } else {
        assert!(!enrolment.exists());
    }
    device.run(&["lock", "--stop"], "").ok();
    drop(server);
}

/// `klav --password-stdin unlock` with `program` as the CLI: `device`'s
/// environment, and no `PATH` to a `klavd`.
fn unlock_through(device: &Device, program: &std::path::Path) -> std::process::Output {
    let template = device.command();
    let mut command = std::process::Command::new(program);
    for (key, value) in template.get_envs() {
        match value {
            Some(v) => command.env(key, v),
            None => command.env_remove(key),
        };
    }
    command
        .env("PATH", "/usr/bin:/bin")
        .args(["--password-stdin", "unlock"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = command.spawn().expect("spawn klav");
    use std::io::Write as _;
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(format!("{}\n", common::PASSWORD).as_bytes())
        .expect("password");
    child.wait_with_output().expect("wait")
}

/// Through a symlink, as `/usr/local/bin/klav` → `Klav.app/Contents/
/// Helpers/klav` (ADR 0027 §4), `unlock` starts the `klavd` next to the
/// real file, without `PATH`. And `klavd --if-not-running` (the Mac app's
/// LaunchAgent) leaves a running one alone and exits successfully.
#[test]
fn a_symlinked_cli_starts_the_klavd_next_to_its_target() {
    let server = ServerProcess::start(900);
    let root = tempfile::tempdir().expect("tempdir");
    let device = Device::new(root.path(), "home");
    device.signup(&server, "link@example.com");
    let _stop = StopDaemon(&device);
    let bin = root.path().join("bin");
    std::fs::create_dir_all(&bin).expect("bin");
    let link = bin.join("klav");
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_klav"), &link).expect("symlink");

    let out = unlock_through(&device, &link);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(daemon_status(&device)["unlocked"], true);

    let klavd = common::built_binary("klavd");
    let again = std::process::Command::new(&klavd)
        .arg("--if-not-running")
        .env("KLAV_HOME", &device.home)
        .env("KLAV_NO_TOUCH_ID", "1")
        .output()
        .expect("klavd");
    assert!(
        again.status.success(),
        "{}",
        String::from_utf8_lossy(&again.stderr)
    );
    assert_eq!(
        daemon_status(&device)["unlocked"],
        true,
        "the first one still runs"
    );
}

/// Klav.app's layout (ADR 0027, note of 2026-11-05): `klavd` lives in
/// `Helpers/klavd.app`, so that the Touch ID dialog names Klav, and
/// `Helpers/klavd` is a relative link to its binary. The `klav` next to it
/// starts that `klavd` through the link, without `PATH`.
#[test]
fn the_cli_in_the_app_starts_klavd_through_the_link_to_its_bundle() {
    let server = ServerProcess::start(900);
    let root = tempfile::tempdir().expect("tempdir");
    let device = Device::new(root.path(), "home");
    device.signup(&server, "bundle@example.com");
    let _stop = StopDaemon(&device);
    // Copies, not links: `klav` looks next to its real file.
    let helpers = root.path().join("Klav.app/Contents/Helpers");
    let macos = helpers.join("klavd.app/Contents/MacOS");
    std::fs::create_dir_all(&macos).expect("klavd.app");
    let cli = helpers.join("klav");
    std::fs::copy(env!("CARGO_BIN_EXE_klav"), &cli).expect("copy klav");
    let klavd = common::built_binary("klavd");
    std::fs::copy(&klavd, macos.join("klavd")).expect("copy klavd");
    std::os::unix::fs::symlink("klavd.app/Contents/MacOS/klavd", helpers.join("klavd"))
        .expect("symlink");

    let out = unlock_through(&device, &cli);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(daemon_status(&device)["unlocked"], true);
}
