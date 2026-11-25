//! Presence through the CLI (ADR 0041, layer 3), end to end with the
//! master password: a test `klavd` started with `--presence-gate` and
//! Touch ID off, in its own temporary home, and `klav` in a
//! pseudo-terminal (`script`) or with no controlling terminal at all.
//!
//! On Linux CI this is the path people take: no Touch ID, so `klavd`
//! answers `presence_required` and `klav` asks on its terminal.

mod common;

use std::io::{Read, Write};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::{
    Device, Klavd, PASSWORD, Run, ServerProcess, path_without_installed_klav, wait_until,
};
use serde_json::{Value, json};

const VALUE: &str = "MARKER-presence-value";
const REFERENCE: &str = "klav://Personal/General/Deploy/api_key";
const EMAIL: &str = "presence@example.com";

/// Whether this test process has a controlling terminal (a developer's
/// terminal; never CI).
fn has_terminal() -> bool {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .is_ok()
}

/// The environment every `klav` here gets, as [`Device::command`] sets it.
fn klav_env(cmd: &mut Command, device: &Device) {
    cmd.env("KLAV_HOME", &device.home)
        .env("PATH", path_without_installed_klav())
        .env("KLAV_NO_TOUCH_ID", "1")
        .env("KLAV_NO_DEFAULT_SERVER", "1")
        .env("KLAV_BIN", env!("CARGO_BIN_EXE_klav"))
        .env_remove("KLAV_NO_DAEMON")
        .env_remove("KLAV_SERVER");
}

/// `klav <args>` with no controlling terminal: as is where this process
/// has none (CI); else in a new session, through `perl`'s `setsid`, so it
/// can't reach the developer's terminal.
fn detached(device: &Device, args: &[&str], stdin: &str) -> Run {
    if !has_terminal() {
        return device.run(args, stdin);
    }
    let mut cmd = Command::new("perl");
    klav_env(&mut cmd, device);
    cmd.args([
        "-MPOSIX",
        "-e",
        "POSIX::setsid() >= 0 or die qq(setsid: $!); exec @ARGV or die qq(exec: $!)",
        "--",
        env!("CARGO_BIN_EXE_klav"),
    ])
    .args(args)
    .stdin(Stdio::piped())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("perl, to run klav with no terminal");
    let _ = child
        .stdin
        .take()
        .expect("stdin")
        .write_all(stdin.as_bytes());
    let out = child.wait_with_output().expect("wait klav");
    Run {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// A shell line run with no controlling terminal, as [`detached`] runs
/// `klav`: its `klav` has the shell for a parent, not this test.
fn detached_sh(device: &Device, shell: &str) -> Run {
    let mut cmd = if has_terminal() {
        let mut cmd = Command::new("perl");
        cmd.args([
            "-MPOSIX",
            "-e",
            "POSIX::setsid() >= 0 or die qq(setsid: $!); exec @ARGV or die qq(exec: $!)",
            "--",
            "/bin/sh",
            "-c",
            shell,
        ]);
        cmd
    } else {
        let mut cmd = Command::new("/bin/sh");
        cmd.args(["-c", shell]);
        cmd
    };
    klav_env(&mut cmd, device);
    let out = cmd
        .stdin(Stdio::null())
        .output()
        .expect("sh, to run klav with no terminal");
    Run {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// A shell in a new pseudo-terminal (`script`), which is the controlling
/// terminal of everything it runs. What the terminal shows is read as it
/// comes; what the test types goes to it.
struct Terminal {
    child: Child,
    shown: Arc<Mutex<Vec<u8>>>,
}

impl Terminal {
    fn open(device: &Device, dir: &Path, shell: &str) -> Self {
        let mut cmd = Command::new("script");
        if cfg!(target_os = "macos") {
            cmd.args(["-q", "/dev/null", "/bin/sh", "-c", shell]);
        } else {
            cmd.args(["-q", "-e", "-c", shell, "/dev/null"]);
        }
        klav_env(&mut cmd, device);
        cmd.current_dir(dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        // The plan item asks for this test on Linux CI: a missing
        // `script` fails it rather than skipping it.
        let mut child = cmd
            .spawn()
            .expect("`script` (util-linux on Linux) opens a terminal");
        let mut out = child.stdout.take().expect("stdout");
        let shown = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&shown);
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok(n) = out.read(&mut buf) {
                if n == 0 {
                    break;
                }
                sink.lock().expect("shown").extend_from_slice(&buf[..n]);
            }
        });
        Terminal { child, shown }
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.shown.lock().expect("shown")).into_owned()
    }

    /// Waits until the terminal has shown `what` `times` times.
    #[track_caller]
    fn wait_for(&self, what: &str, times: usize) {
        let shown = wait_until(60, || self.text().matches(what).count() >= times);
        assert!(
            shown,
            "the terminal never showed {what:?}:\n{}",
            self.text()
        );
    }

    /// Types a line. Every caller first waits for the question that reads
    /// it: `klav` writes the question only once echo is off and what was
    /// typed before it is thrown away, so what is typed after it shows is
    /// kept, with no pause needed.
    fn type_line(&mut self, line: &str) {
        let stdin = self.child.stdin.as_mut().expect("stdin");
        stdin
            .write_all(format!("{line}\n").as_bytes())
            .expect("type");
        stdin.flush().expect("flush");
    }

    /// Writes `bytes` to the terminal as they are, as a paste does.
    fn paste(&mut self, bytes: &str) {
        let stdin = self.child.stdin.as_mut().expect("stdin");
        stdin.write_all(bytes.as_bytes()).expect("paste");
        stdin.flush().expect("flush");
    }

    /// The exit codes the shell printed (`KLAV-EXIT n`), once `n` of them
    /// have.
    #[track_caller]
    fn exits(&self, n: usize) -> Vec<i32> {
        self.wait_for("KLAV-EXIT ", n);
        self.text()
            .split("KLAV-EXIT ")
            .skip(1)
            .map(|rest| {
                rest.split_whitespace()
                    .next()
                    .and_then(|code| code.parse().ok())
                    .unwrap_or(-1)
            })
            .collect()
    }

    /// The terminal's name as `tty` gave it (`KLAV-TTY /dev/pts/3`),
    /// without `/dev/`.
    #[track_caller]
    fn name(&self) -> String {
        self.wait_for("KLAV-TTY ", 1);
        let text = self.text();
        let rest = text.split("KLAV-TTY ").nth(1).expect("tty line");
        let path = rest.split_whitespace().next().expect("tty path");
        path.strip_prefix("/dev/").expect("a /dev path").to_owned()
    }
}

impl Drop for Terminal {
    fn drop(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if matches!(self.child.try_wait(), Ok(Some(_))) {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A shell line that runs `klav <args>` and prints its exit code.
fn klav_line(args: &str) -> String {
    format!(r#""$KLAV_BIN" {args}; echo "KLAV-EXIT $?""#)
}

/// An account with one API key, «Deploy», added without `klavd`.
fn account(server: &ServerProcess, device: &Device) {
    device.signup(server, EMAIL);
    device
        .unlocked(
            &[
                "--no-daemon",
                "item",
                "add",
                "api-key",
                "--title",
                "Deploy",
                "--secret-stdin",
                "api_key",
            ],
            &format!("{VALUE}\n"),
        )
        .ok();
}

#[test]
fn with_the_gate_on_values_ask_for_the_master_password_on_the_terminal() {
    let server = ServerProcess::start(900);
    let root = tempfile::tempdir().expect("tempdir");
    let device = Device::new(root.path(), "home");
    account(&server, &device);
    // An old passkey setting: the first unlock warns once (ADR 0041 §2.4,
    // Q-N3), and the CLI shows the unlock answer's warnings.
    std::fs::write(
        device.home.join("passkeys.json"),
        r#"{"v":1,"window":"unlocked"}"#,
    )
    .expect("passkeys.json");
    let klavd = Klavd::start(&device, root.path(), true);

    // Locked: the setting doesn't show, and the CLI says how to unlock.
    let locked = detached(&device, &["presence", "window"], "").err();
    assert_eq!(locked.code, 1);
    assert!(
        locked.stderr.contains("Klav is locked") && locked.stderr.contains("`klav unlock`"),
        "{}",
        locked.stderr
    );

    let unlock = detached(
        &device,
        &["--password-stdin", "unlock"],
        &format!("{PASSWORD}\n"),
    )
    .ok();
    assert!(
        unlock.stderr.contains(&format!("pid {}", klavd.pid())),
        "the test klavd, not another: {}",
        unlock.stderr
    );
    assert!(
        unlock
            .stderr
            .contains("Klav no longer reads your old passkey setting"),
        "{}",
        unlock.stderr
    );
    assert!(!device.home.join("passkeys.json").exists());
    // A password from stdin unlocks, and opens no window (Omar's decision
    // 4 of 2026-11-19): the first value from a terminal asks, with the
    // window the 5-minute default opens, and the next one doesn't.
    assert!(
        unlock.stderr.contains(
            "The master password came from stdin: Klav is unlocked, and no window opened"
        ),
        "{}",
        unlock.stderr
    );
    // In one terminal: lock, unlock with the password from stdin, then two
    // values. Without decision 4 the unlock would open this terminal's
    // window and the first value wouldn't ask.
    let mut first = Terminal::open(
        &device,
        root.path(),
        &format!(
            r#"echo "KLAV-TTY $(tty)"; {}; printf '%s\n' '{PASSWORD}' | {}; {}; {}"#,
            klav_line("lock"),
            klav_line("--password-stdin unlock"),
            klav_line(&format!("item get {REFERENCE} --reveal")),
            klav_line(&format!("item get {REFERENCE} --reveal")),
        ),
    );
    let name = first.name();
    first.wait_for(&format!("Master password for {EMAIL}: "), 1);
    first.type_line(PASSWORD);
    assert_eq!(first.exits(4), vec![0, 0, 0, 0], "{}", first.text());
    let text = first.text();
    assert!(text.contains("no window opened"), "{text}");
    assert!(
        text.contains(&format!(
            "klav: master password for the terminal {name}\r\n\
             It lets the terminal {name} use your vault for 5 minutes.\r\n\
             Master password for {EMAIL}: "
        )),
        "the whole question, as klavd's ask says it:\n{text}"
    );
    assert_eq!(text.matches("Master password for").count(), 1, "{text}");
    assert_eq!(text.matches(VALUE).count(), 2, "{text}");
    drop(first);

    // The setting: 5 minutes by default; tightening asks for nothing, not
    // even a terminal.
    let shown = detached(&device, &["presence", "window"], "").ok();
    assert!(
        shown.stdout.contains("every 5 minutes (`5m`)"),
        "{}",
        shown.stdout
    );
    let json = detached(&device, &["presence", "window", "--json"], "").ok();
    let json: serde_json::Value = serde_json::from_str(&json.stdout).expect("json");
    assert_eq!(json, serde_json::json!({ "window": "5m" }));
    let tightened = detached(&device, &["presence", "window", "always"], "").ok();
    assert!(
        tightened.stdout.contains("for every value (`always`)"),
        "{}",
        tightened.stdout
    );

    // No terminal: its own exit code, what to do, and no value. The
    // password on stdin doesn't count as presence.
    let refused = detached(
        &device,
        &["--password-stdin", "item", "get", REFERENCE, "--reveal"],
        &format!("{PASSWORD}\n"),
    );
    assert_eq!(refused.code, 9, "{}", refused.stderr);
    assert!(
        refused
            .stderr
            .contains("no terminal to ask for the master password")
            && refused
                .stderr
                .contains("Next: run the command from a terminal"),
        "{}",
        refused.stderr
    );
    assert!(!refused.stdout.contains(VALUE) && !refused.stderr.contains(VALUE));
    let run = detached(
        &device,
        &[
            "run",
            "-e",
            &format!("K={REFERENCE}"),
            "--",
            "sh",
            "-c",
            "echo \"$K\"",
        ],
        "",
    );
    assert_eq!(run.code, 9, "{}", run.stderr);
    assert!(!run.stdout.contains(VALUE));

    // In a terminal, with standard input and output redirected: the
    // password is asked on the controlling terminal, which the CLI names
    // as `tty` does, and the value goes to the redirected output.
    let out = root.path().join("value.txt");
    let mut right = Terminal::open(
        &device,
        root.path(),
        &format!(
            r#"echo "KLAV-TTY $(tty)"; {}"#,
            klav_line(&format!(
                "item get {REFERENCE} --reveal </dev/null >'{}'",
                out.display()
            ))
        ),
    );
    let name = right.name();
    right.wait_for(&format!("Master password for {EMAIL}: "), 1);
    right.type_line(PASSWORD);
    assert_eq!(right.exits(1), vec![0], "{}", right.text());
    let text = right.text();
    assert!(
        text.contains(&format!("klav: master password for the terminal {name}")),
        "the CLI names its controlling terminal as `tty` does ({name}):\n{text}"
    );
    // Always: the one value, in the CLI's words for the kind and title
    // klavd sent.
    assert!(
        text.contains("It lets klav show the values of “Deploy”, this once."),
        "{text}"
    );
    assert_eq!(std::fs::read_to_string(&out).expect("value").trim(), VALUE);
    assert!(!text.contains(PASSWORD), "the password was echoed:\n{text}");
    drop(right);

    // A wrong password: refused, and no value.
    let mut wrong = Terminal::open(
        &device,
        root.path(),
        &klav_line(&format!("item get {REFERENCE} --reveal")),
    );
    wrong.wait_for(&format!("Master password for {EMAIL}: "), 1);
    wrong.type_line("not the master password");
    assert_eq!(wrong.exits(1), vec![1], "{}", wrong.text());
    assert!(!wrong.text().contains(VALUE), "{}", wrong.text());
    drop(wrong);

    // A password offered on stdin, from a terminal: still asked on the
    // terminal, and the stdin line is never used for it (Omar's decision 3
    // of 2026-11-19).
    let mut offered = Terminal::open(
        &device,
        root.path(),
        &format!(
            r#"printf '%s\n' 'not the master password' | "$KLAV_BIN" --password-stdin item get {REFERENCE} --reveal; echo "KLAV-EXIT $?""#
        ),
    );
    offered.wait_for(&format!("Master password for {EMAIL}: "), 1);
    offered.type_line(PASSWORD);
    assert_eq!(offered.exits(1), vec![0], "{}", offered.text());
    assert!(offered.text().contains(VALUE), "{}", offered.text());
    drop(offered);

    // Ctrl-C at the question: the command stops, and the terminal is
    // left as it was, echo on (layer 3's review, finding 8).
    let mut interrupted = Terminal::open(
        &device,
        root.path(),
        &format!(
            r#"{}; echo "STTY $(stty -a | tr '\n;' '  ') STTY-END""#,
            klav_line(&format!("item get {REFERENCE} --reveal"))
        ),
    );
    // Once the question shows, echo is off (see `type_line`).
    interrupted.wait_for(&format!("Master password for {EMAIL}: "), 1);
    {
        let stdin = interrupted.child.stdin.as_mut().expect("stdin");
        stdin.write_all(b"half\x03").expect("type");
        stdin.flush().expect("flush");
    }
    assert_eq!(interrupted.exits(1), vec![1], "{}", interrupted.text());
    interrupted.wait_for("STTY-END", 1);
    let text = interrupted.text();
    let stty: Vec<&str> = text
        .split("STTY ")
        .nth(1)
        .expect("stty line")
        .split_whitespace()
        .collect();
    for flag in ["echo", "icanon", "isig"] {
        assert!(stty.contains(&flag), "{flag} is off after Ctrl-C:\n{text}");
    }
    assert!(
        text.contains("canceled: no master password was sent"),
        "{text}"
    );
    assert!(!text.contains(VALUE), "{text}");
    drop(interrupted);

    // A background job doesn't read the terminal: no terminal, exit 9.
    let background = Terminal::open(
        &device,
        root.path(),
        &format!(
            r#"set -m; "$KLAV_BIN" item get {REFERENCE} --reveal & wait $!; echo "KLAV-EXIT $?""#
        ),
    );
    assert_eq!(background.exits(1), vec![9], "{}", background.text());
    assert!(
        !background.text().contains("Master password for"),
        "{}",
        background.text()
    );
    drop(background);

    // A command that hands out no value never reaches the gate: no
    // question, and not exit 9, with no terminal and the setting `always`.
    let agents = detached(&device, &["agent", "list"], "");
    assert_eq!(agents.code, 0, "{}", agents.stderr);
    assert!(
        !agents.stderr.contains("Master password"),
        "{}",
        agents.stderr
    );

    // Loosening asks, names the change, and opens no window: the next
    // value asks once more, and opens a window for this terminal's
    // session, so the one after it doesn't ask.
    let mut loosen = Terminal::open(
        &device,
        root.path(),
        &format!(
            r#"echo "KLAV-TTY $(tty)"; {}; {}; {}"#,
            klav_line("presence window 5m"),
            klav_line(&format!("item get {REFERENCE} --reveal")),
            klav_line(&format!("item get {REFERENCE} --reveal")),
        ),
    );
    let name = loosen.name();
    loosen.wait_for(&format!("Master password for {EMAIL}: "), 1);
    assert!(
        loosen.text().contains(
            "It confirms: ask for your presence every 5 minutes instead of for every value."
        ),
        "{}",
        loosen.text()
    );
    loosen.type_line(PASSWORD);
    loosen.wait_for(&format!("Master password for {EMAIL}: "), 2);
    let text = loosen.text();
    assert!(
        text.contains(&format!(
            "It lets the terminal {name} use your vault for 5 minutes."
        )),
        "klavd names the same terminal ({name}):\n{text}"
    );
    loosen.type_line(PASSWORD);
    assert_eq!(loosen.exits(3), vec![0, 0, 0], "{}", loosen.text());
    let text = loosen.text();
    assert_eq!(
        text.matches("Master password for").count(),
        2,
        "the window covered the last value:\n{text}"
    );
    assert_eq!(text.matches(VALUE).count(), 2, "{text}");
    assert!(text.contains("every 5 minutes (`5m`)"), "{text}");
    assert!(!text.contains(PASSWORD), "{text}");
    drop(loosen);

    // `klav unlock` from another terminal: klavd was unlocked elsewhere,
    // and this unlock gives this terminal nothing (Q-N1).
    let again = Terminal::open(&device, root.path(), &klav_line("unlock"));
    assert_eq!(again.exits(1), vec![0], "{}", again.text());
    assert!(
        again.text().contains(
            "Klav was already unlocked elsewhere; this unlock gave this terminal nothing"
        ),
        "{}",
        again.text()
    );
    drop(again);
    // With no terminal at all: "this program" (the ADR's own choice 30).
    // `; exit` keeps the shell from replacing itself with `klav`, so its
    // parent is the shell.
    let program = detached_sh(&device, r#""$KLAV_BIN" unlock; exit $?"#);
    assert_eq!(program.code, 0, "{}", program.stderr);
    assert!(
        program
            .stderr
            .contains("this unlock gave this program nothing"),
        "{}",
        program.stderr
    );

    let back = detached(&device, &["presence", "window", "always"], "").ok();
    assert!(back.stdout.contains("(`always`)"), "{}", back.stdout);

    // The question edits as a terminal does, through a real terminal (the
    // second review of layer 3, finding 8): what was typed before it is
    // thrown away, an arrow key's escape sequence never enters the
    // password, and Ctrl-W and Backspace erase. `klav` starts only once
    // the line typed ahead is in the terminal's input: the terminal echoes
    // it then (echo is still on), and the test creates `go` after seeing
    // that echo, so no pause is needed.
    let go = root.path().join("go");
    let mut keys = Terminal::open(
        &device,
        root.path(),
        &format!(
            r#"echo KLAV-READY; while [ ! -e '{}' ]; do sleep 0.1; done; {}"#,
            go.display(),
            klav_line(&format!("item get {REFERENCE} --reveal"))
        ),
    );
    keys.wait_for("KLAV-READY", 1);
    {
        let stdin = keys.child.stdin.as_mut().expect("stdin");
        stdin.write_all(b"typed ahead\n").expect("type");
        stdin.flush().expect("flush");
    }
    keys.wait_for("typed ahead", 1);
    std::fs::write(&go, b"").expect("go");
    keys.wait_for(&format!("Master password for {EMAIL}: "), 1);
    {
        let stdin = keys.child.stdin.as_mut().expect("stdin");
        let mut typed = b"not it\x17\x17\x1b[A".to_vec();
        typed.extend_from_slice(PASSWORD.as_bytes());
        typed.extend_from_slice(b"\x1bODx\x7f\n");
        stdin.write_all(&typed).expect("type");
        stdin.flush().expect("flush");
    }
    assert_eq!(keys.exits(1), vec![0], "{}", keys.text());
    assert!(keys.text().contains(VALUE), "{}", keys.text());
    assert_eq!(
        keys.text().matches("Master password for").count(),
        1,
        "{}",
        keys.text()
    );
    drop(keys);

    // A paste longer than the question reads (1024 bytes) is refused
    // whole, and none of it reaches the shell once the terminal is back:
    // the line is read to its end, and what is queued after it thrown away,
    // with echo still off (the third review of layer 3). The shell then
    // reads its terminal for a second with nothing typed: it must find
    // nothing. Before the fix, the question gave up at byte 1025 and the
    // rest of the line went to the shell, echoed.
    let mut pasted = Terminal::open(
        &device,
        root.path(),
        &format!(
            r#"{}; stty -icanon -echo min 0 time 10; echo "LEFT $(head -c 100000 | wc -c | tr -d ' ') LEFT-END""#,
            klav_line(&format!("item get {REFERENCE} --reveal"))
        ),
    );
    pasted.wait_for(&format!("Master password for {EMAIL}: "), 1);
    pasted.type_line(&"Z".repeat(1500));
    assert_eq!(pasted.exits(1), vec![1], "{}", pasted.text());
    pasted.wait_for("LEFT-END", 1);
    let text = pasted.text();
    assert!(
        text.contains("the master password is longer than 1024 bytes: nothing was sent"),
        "{text}"
    );
    assert!(
        text.contains("LEFT 0 LEFT-END"),
        "the shell got some of it:\n{text}"
    );
    assert!(!text.contains("ZZZZ"), "some of it was echoed:\n{text}");
    assert!(!text.contains(VALUE), "{text}");
    drop(pasted);

    // A paste of several lines (Omar's decision M of 2026-11-19): the
    // question takes its first line, and none of the rest reaches the
    // shell, whether it was queued when Enter arrived or arrives a moment
    // later, as a terminal emulator writes a long paste in pieces. The
    // shell then reads its terminal for a second: it must find nothing.
    // Before the fix, only an over-long line flushed, and only what was
    // queued at Enter: here the shell got the later lines. Each case runs
    // once with the correct password first (the value is handed out) and
    // once with an over-long first line (refused).
    for (what, first, ok) in [
        ("password", format!("{PASSWORD}\n"), true),
        ("over-long", format!("{}\n", "Z".repeat(1500)), false),
    ] {
        let mut several = Terminal::open(
            &device,
            root.path(),
            &format!(
                r#"{}; stty -icanon -echo min 0 time 10; echo "LEFT $(head -c 100000 | wc -c | tr -d ' ') LEFT-END""#,
                klav_line(&format!("item get {REFERENCE} --reveal"))
            ),
        );
        several.wait_for(&format!("Master password for {EMAIL}: "), 1);
        several.paste(&format!("{first}echo PASTED-TWO\necho PASTED-THREE\n"));
        std::thread::sleep(Duration::from_millis(60));
        several.paste("echo PASTED-FOUR\n");
        assert_eq!(
            several.exits(1),
            vec![if ok { 0 } else { 1 }],
            "{what}: {}",
            several.text()
        );
        several.wait_for("LEFT-END", 1);
        let text = several.text();
        assert_eq!(text.contains(VALUE), ok, "{what}: {text}");
        assert!(
            text.contains("LEFT 0 LEFT-END"),
            "{what}: the shell got some of the paste:\n{text}"
        );
        assert!(!text.contains("PASTED"), "{what}: echoed or run:\n{text}");
        drop(several);
    }
    drop(klavd);
}

/// The window an unlock's question names is the one `klavd` opens, end to
/// end with the real `klavd` and the CLI typing on its terminal: the CLI
/// words its question from `status` and sends `shown`, and `klavd` opens
/// what that says. The two sides of the mapping are pinned separately
/// elsewhere; this is where they meet.
///
/// - The first unlock since `klavd` started opens no window, and says so:
///   the next value asks (Omar's decision A of 2026-11-19).
/// - A later one opens this terminal's window for 5 minutes, and says so:
///   the next value, from the same terminal, doesn't ask.
#[test]
fn a_typed_unlock_opens_the_window_its_question_names() {
    let server = ServerProcess::start(900);
    let root = tempfile::tempdir().expect("tempdir");
    let device = Device::new(root.path(), "home");
    account(&server, &device);
    let klavd = Klavd::start(&device, root.path(), true);

    // The first unlock since klavd started.
    let mut first = Terminal::open(
        &device,
        root.path(),
        &format!(
            r#"echo "KLAV-TTY $(tty)"; {}; {}"#,
            klav_line("unlock"),
            klav_line(&format!("item get {REFERENCE} --reveal")),
        ),
    );
    let name = first.name();
    first.wait_for(&format!("Master password for {EMAIL}: "), 1);
    let text = first.text();
    assert!(
        text.contains(&format!(
            "klav: master password for the terminal {name}\r\n\
             It unlocks Klav, and opens no window: the next value asks for your presence.\r\n\
             Master password for {EMAIL}: "
        )),
        "the first unlock promises no window:\n{text}"
    );
    first.type_line(PASSWORD);
    // No window opened: the value asks, for this terminal's window.
    first.wait_for(&format!("Master password for {EMAIL}: "), 2);
    assert!(
        first.text().contains(&format!(
            "It lets the terminal {name} use your vault for 5 minutes."
        )),
        "{}",
        first.text()
    );
    first.type_line(PASSWORD);
    assert_eq!(first.exits(2), vec![0, 0], "{}", first.text());
    let text = first.text();
    assert!(
        text.contains(&format!("pid {}", klavd.pid())),
        "the test klavd, not another:\n{text}"
    );
    assert_eq!(text.matches(VALUE).count(), 1, "{text}");
    assert!(!text.contains(PASSWORD), "{text}");
    drop(first);

    // A later unlock: its question names this terminal's window, and the
    // value inside it doesn't ask.
    detached(&device, &["lock"], "").ok();
    let mut later = Terminal::open(
        &device,
        root.path(),
        &format!(
            r#"echo "KLAV-TTY $(tty)"; {}; {}"#,
            klav_line("unlock"),
            klav_line(&format!("item get {REFERENCE} --reveal")),
        ),
    );
    let name = later.name();
    later.wait_for(&format!("Master password for {EMAIL}: "), 1);
    assert!(
        later.text().contains(&format!(
            "It unlocks Klav, and lets the terminal {name} use your vault for 5 minutes."
        )),
        "{}",
        later.text()
    );
    later.type_line(PASSWORD);
    assert_eq!(later.exits(2), vec![0, 0], "{}", later.text());
    let text = later.text();
    assert_eq!(
        text.matches("Master password for").count(),
        1,
        "the window the question named covered the value:\n{text}"
    );
    assert_eq!(text.matches(VALUE).count(), 1, "{text}");
    assert!(!text.contains(PASSWORD), "{text}");
    drop(later);
    drop(klavd);
}

#[test]
fn without_the_gate_the_cli_does_what_it_did() {
    let server = ServerProcess::start(900);
    let root = tempfile::tempdir().expect("tempdir");
    let device = Device::new(root.path(), "home");
    account(&server, &device);
    let klavd = Klavd::start(&device, root.path(), false);

    let unlock = detached(
        &device,
        &["--password-stdin", "unlock"],
        &format!("{PASSWORD}\n"),
    )
    .ok();
    assert!(
        unlock.stderr.contains(&format!(
            "Unlocked with password (klavd, pid {})",
            klavd.pid()
        )),
        "{}",
        unlock.stderr
    );
    for args in [
        &["presence", "window"][..],
        &["presence", "window", "always"][..],
    ] {
        let off = detached(&device, args, "").err();
        assert_eq!(off.code, 1);
        assert!(
            off.stderr.contains("the presence gate is off"),
            "{}",
            off.stderr
        );
    }

    // A value with no prompt, from a terminal or without one; `unlock`
    // from a terminal says what it said before.
    let value = detached(&device, &["item", "get", REFERENCE, "--reveal"], "").ok();
    assert_eq!(value.stdout.trim(), VALUE);
    let term = Terminal::open(
        &device,
        root.path(),
        &format!(
            "{}; {}",
            klav_line(&format!("item get {REFERENCE} --reveal")),
            klav_line("unlock")
        ),
    );
    assert_eq!(term.exits(2), vec![0, 0], "{}", term.text());
    let text = term.text();
    assert!(!text.contains("Master password"), "{text}");
    assert!(text.contains(VALUE), "{text}");
    assert!(
        text.contains(&format!(
            "Unlocked with password (klavd, pid {})",
            klavd.pid()
        )),
        "{text}"
    );
    assert!(!text.contains("already unlocked"), "{text}");
    drop(term);
    drop(klavd);
}

/// What a scripted `klavd` answers: the lines for one request, given its
/// `op` and how many requests with that `op` came before it, plus one.
type Script = dyn Fn(&str, usize) -> Vec<Value> + Send + Sync;

/// A scripted `klavd` on the home's socket: it records every request line
/// and answers from a script, so the test sees exactly what `klav` sent.
/// Its threads end with the test process; the socket goes with the home.
struct FakeKlavd {
    seen: Arc<Mutex<Vec<String>>>,
}

impl FakeKlavd {
    fn start(
        device: &Device,
        script: impl Fn(&str, usize) -> Vec<Value> + Send + Sync + 'static,
    ) -> Self {
        let socket = device.home.join("klavd.sock");
        let _ = std::fs::remove_file(&socket);
        let listener = std::os::unix::net::UnixListener::bind(&socket).expect("bind the socket");
        let seen = Arc::new(Mutex::new(Vec::new()));
        let script: Arc<Script> = Arc::new(script);
        let record = Arc::clone(&seen);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { return };
                let record = Arc::clone(&record);
                let script = Arc::clone(&script);
                std::thread::spawn(move || serve(stream, &record, &*script));
            }
        });
        FakeKlavd { seen }
    }

    /// Every request line `klav` sent, in order.
    fn lines(&self) -> Vec<String> {
        self.seen.lock().expect("seen").clone()
    }

    /// The `request` objects with `op`, in order.
    fn requests(&self, op: &str) -> Vec<Value> {
        self.lines()
            .iter()
            .map(|l| serde_json::from_str::<Value>(l).expect("json"))
            .map(|v| v["request"].clone())
            .filter(|r| r["op"] == op)
            .collect()
    }

    fn ops(&self) -> Vec<String> {
        self.lines()
            .iter()
            .map(|l| serde_json::from_str::<Value>(l).expect("json"))
            .map(|v| v["request"]["op"].as_str().unwrap_or("").to_owned())
            .collect()
    }
}

fn serve(stream: std::os::unix::net::UnixStream, seen: &Mutex<Vec<String>>, script: &Script) {
    use std::io::BufRead;
    let mut writer = stream.try_clone().expect("clone");
    let reader = std::io::BufReader::new(stream);
    for line in reader.lines() {
        let Ok(line) = line else { return };
        let envelope: Value = serde_json::from_str(&line).expect("a JSON request");
        let op = envelope["request"]["op"].as_str().unwrap_or("").to_owned();
        let nth = {
            let mut seen = seen.lock().expect("seen");
            seen.push(line.clone());
            seen.iter()
                .filter(|l| {
                    serde_json::from_str::<Value>(l)
                        .is_ok_and(|v| v["request"]["op"] == op.as_str())
                })
                .count()
        };
        for mut answer in script(&op, nth) {
            answer["v"] = json!(1);
            answer["id"] = envelope["id"].clone();
            let _ = writeln!(writer, "{answer}");
        }
    }
}

/// A `status` answer, as a `klavd` of this version writes it.
fn fake_status(unlocked: bool, touch_id: bool, presence: Option<Value>) -> Value {
    let mut status = json!({
        "version": "0.0.0",
        "protocol": 1,
        "pid": 4242,
        "logged_in": true,
        "unlocked": unlocked,
        "email": EMAIL,
        "idle_lock_secs": 600,
        "touch_id": { "available": touch_id, "enrolled": touch_id },
    });
    if unlocked {
        status["unlocked_with"] = json!("password");
    }
    if let Some(presence) = presence {
        status["presence"] = presence;
    }
    status
}

fn ok(value: Value) -> Vec<Value> {
    vec![json!({ "ok": value })]
}

fn refusal(code: &str, message: &str, presence: Option<Value>) -> Vec<Value> {
    let mut error = json!({ "code": code, "message": message });
    if let Some(presence) = presence {
        error["presence"] = presence;
    }
    vec![json!({ "error": error })]
}

/// The end of a script: `klav` prints it and stops.
fn the_end() -> Vec<Value> {
    refusal("not_found", "FAKE-END", None)
}

/// A request with its password taken out, to compare with the first.
fn without_password(request: &Value) -> Value {
    let mut request = request.clone();
    if let Some(map) = request.as_object_mut() {
        map.remove("password");
    }
    request
}

#[test]
fn the_cli_against_a_scripted_klavd() {
    let server = ServerProcess::start(900);
    let root = tempfile::tempdir().expect("tempdir");
    let device = Device::new(root.path(), "home");
    device.signup(&server, EMAIL);
    let gate = |lasts: Option<&str>, elsewhere: bool| {
        let mut presence = json!({ "key": "parent" });
        if let Some(lasts) = lasts {
            presence["lasts"] = json!(lasts);
        }
        if elsewhere {
            presence["elsewhere"] = json!(true);
        }
        presence
    };

    // An older klavd, or one with the gate off (the same `status`):
    // unlocked, `klav unlock` sends it no `unlock`, and no request carries
    // the gate's fields, which an older one refuses.
    let older = FakeKlavd::start(&device, |op, _| match op {
        "status" => ok(fake_status(true, false, None)),
        _ => the_end(),
    });
    let unlock = detached(&device, &["unlock"], "").ok();
    assert!(
        unlock
            .stderr
            .contains("Unlocked with password (klavd, pid 4242)"),
        "{}",
        unlock.stderr
    );
    assert_eq!(older.ops(), ["status"]);
    let value = detached(&device, &["item", "get", "Deploy", "--reveal"], "");
    assert_eq!(value.code, 1, "{}", value.stderr);
    assert!(value.stderr.contains("FAKE-END"), "{}", value.stderr);
    assert_eq!(older.requests("view").len(), 1);
    for line in older.lines() {
        assert!(
            !line.contains("notify") && !line.contains("shown"),
            "{line}"
        );
    }

    // A notice nobody asked for is refused, not printed.
    let _uninvited = FakeKlavd::start(&device, |op, _| match op {
        "status" => ok(fake_status(true, false, None)),
        _ => vec![json!({ "notice": "touch_id" }), json!({ "ok": null })],
    });
    let value = detached(&device, &["item", "get", "Deploy", "--reveal"], "");
    assert_eq!(value.code, 1, "{}", value.stderr);
    assert!(
        value
            .stderr
            .contains("klavd sent a notice this request didn't ask for")
            && !value.stderr.contains("Touch ID for"),
        "{}",
        value.stderr
    );

    // The gate on: a value request asks for the notice, and the CLI says
    // who the dialog is for before it shows (Omar's decision 2).
    let notified = FakeKlavd::start(&device, |op, _| match op {
        "status" => ok(fake_status(true, true, Some(json!({ "key": "parent" })))),
        "view" => {
            let mut lines = vec![json!({ "notice": "touch_id" })];
            lines.extend(the_end());
            lines
        }
        _ => the_end(),
    });
    let value = detached(&device, &["item", "get", "Deploy", "--reveal"], "");
    assert_eq!(value.code, 1, "{}", value.stderr);
    let touch = value.stderr.find("klav: Touch ID for this program");
    let end = value.stderr.find("FAKE-END");
    assert!(touch.is_some() && touch < end, "{}", value.stderr);
    let lines = notified.lines();
    let view = lines
        .iter()
        .find(|l| l.contains(r#""op":"view""#))
        .expect("view");
    assert!(view.contains(r#""notify":true"#), "{view}");

    // `klav unlock` on a Klav unlocked by another key: nothing sent, no
    // password asked, and it says this program got nothing (decision 5);
    // so a lock in between can't make it unlock (finding 3).
    let elsewhere = FakeKlavd::start(&device, move |op, _| match op {
        "status" => ok(fake_status(true, false, Some(gate(Some("5m"), true)))),
        _ => the_end(),
    });
    let unlock = detached(&device, &["unlock"], "").ok();
    assert!(
        unlock
            .stderr
            .contains("this unlock gave this program nothing")
            && !unlock.stderr.contains("Unlocked"),
        "{}",
        unlock.stderr
    );
    assert_eq!(elsewhere.ops(), ["status"]);
    // Unlocked by this caller's own key: said, and still nothing sent.
    let own = FakeKlavd::start(&device, move |op, _| match op {
        "status" => ok(fake_status(true, false, Some(gate(Some("5m"), false)))),
        _ => the_end(),
    });
    let unlock = detached(&device, &["unlock"], "").ok();
    assert!(
        unlock.stderr.contains("Unlocked with password"),
        "{}",
        unlock.stderr
    );
    assert_eq!(own.ops(), ["status"]);

    // A Touch ID unlock that finds Klav unlocked by another key: the
    // "gave nothing" text, and no "Unlocked with" after it (finding 5).
    let raced = FakeKlavd::start(&device, move |op, _| match op {
        "status" => ok(fake_status(false, true, Some(gate(Some("5m"), false)))),
        "unlock" => {
            let mut status = fake_status(true, true, Some(gate(Some("5m"), true)));
            status["already_unlocked"] = json!(true);
            ok(status)
        }
        _ => the_end(),
    });
    let unlock = detached(&device, &["unlock"], "").ok();
    assert!(
        unlock.stderr.contains("klav: Touch ID for this program")
            && unlock
                .stderr
                .contains("this unlock gave this program nothing")
            && !unlock.stderr.contains("Unlocked with"),
        "{}",
        unlock.stderr
    );
    assert_eq!(raced.ops(), ["status", "unlock"]);

    // A password from stdin with the gate on: it says the question showed
    // no window (`shown: always`) and that the password wasn't typed
    // (`untyped`, so no passkey verification either), and klav says so
    // (Omar's decisions 4 and B).
    let stdin = FakeKlavd::start(&device, move |op, _| match op {
        "status" => ok(fake_status(false, false, Some(gate(Some("5m"), false)))),
        "unlock" => ok(fake_status(true, false, Some(gate(Some("5m"), false)))),
        _ => the_end(),
    });
    let unlock = detached(&device, &["--password-stdin", "unlock"], "fake password\n").ok();
    assert!(
        unlock.stderr.contains("no window opened"),
        "{}",
        unlock.stderr
    );
    let lines = stdin.lines();
    let sent = lines
        .iter()
        .find(|l| l.contains(r#""op":"unlock""#))
        .expect("unlock");
    assert!(sent.contains(r#""shown":"always""#), "{sent}");
    assert!(sent.contains(r#""untyped":true"#), "{sent}");
    assert!(
        unlock.stderr.contains("so does the next passkey use"),
        "{}",
        unlock.stderr
    );

    // A typed password: the question names the terminal and what it
    // opens, and the request says what it showed.
    let typed = FakeKlavd::start(&device, move |op, _| match op {
        "status" => ok(fake_status(
            false,
            false,
            Some(json!({
                "key": "session", "terminal": "ttysFAKE", "lasts": "5m"
            })),
        )),
        "unlock" => ok(fake_status(true, false, None)),
        _ => the_end(),
    });
    let mut term = Terminal::open(&device, root.path(), &klav_line("unlock"));
    term.wait_for(&format!("Master password for {EMAIL}: "), 1);
    term.type_line("typed fake password");
    assert_eq!(term.exits(1), vec![0], "{}", term.text());
    assert!(
        term.text().contains(
            "It unlocks Klav, and lets the terminal ttysFAKE use your vault for 5 minutes."
        ),
        "{}",
        term.text()
    );
    let lines = typed.lines();
    let sent = lines
        .iter()
        .find(|l| l.contains(r#""op":"unlock""#))
        .expect("unlock");
    assert!(sent.contains(r#""shown":"5m""#), "{sent}");
    assert!(!sent.contains("untyped"), "{sent}");
    drop(term);

    // An every-time ask while the setting is 5 minutes: the words of the
    // one value, never a window (finding 4). The first request has no
    // password; the CLI sends the same request once more, with it; and a
    // busy answer gets the CLI's words, deterministically. The real klavd
    // can't send this ask yet: nothing outside its tests asks with
    // `Purpose::EveryTime` until ADR 0032's protected values reach the gate,
    // so only a scripted klavd can, and the CLI must already word it as
    // one value.
    let every_time = json!({
        "key": "session", "window": "5m", "terminal": "ttysFAKE",
        "value": { "kind": "code", "title": "GitHub" }
    });
    let ask = every_time.clone();
    let once = FakeKlavd::start(&device, move |op, nth| match (op, nth) {
        ("status", _) => ok(fake_status(true, false, Some(gate(Some("5m"), false)))),
        ("view", 1) => refusal("presence_required", "presence", Some(ask.clone())),
        ("view", _) => refusal("presence_busy", "klavd's own words", None),
        _ => the_end(),
    });
    let mut term = Terminal::open(&device, root.path(), &klav_line("item get Deploy --reveal"));
    term.wait_for(&format!("Master password for {EMAIL}: "), 1);
    term.type_line("first fake password");
    assert_eq!(term.exits(1), vec![1], "{}", term.text());
    let text = term.text();
    assert!(
        text.contains("It lets klav show the code of “GitHub”, this once.")
            && !text.contains("for 5 minutes"),
        "{text}"
    );
    assert!(
        text.contains("klavd is checking another master password: try again"),
        "{text}"
    );
    drop(term);
    let views = once.requests("view");
    assert_eq!(views.len(), 2, "exactly one resend: {views:?}");
    assert!(views[0].get("password").is_none(), "{:?}", views[0]);
    assert_eq!(views[1]["password"], "first fake password");
    assert_eq!(without_password(&views[1]), views[0], "the same request");

    // klavd asks something else at the resend (the setting or the item
    // changed): the password wasn't used, the CLI asks once more with the
    // new words, and a third ask is the end (one more question at most).
    let window = json!({
        "key": "session", "window": "5m", "terminal": "ttysFAKE", "lasts": "5m"
    });
    let (first, second) = (every_time.clone(), window.clone());
    let changed = FakeKlavd::start(&device, move |op, nth| match (op, nth) {
        ("status", _) => ok(fake_status(true, false, Some(gate(Some("5m"), false)))),
        ("view", 1) => refusal("presence_required", "presence", Some(first.clone())),
        ("view", _) => refusal("presence_required", "presence", Some(second.clone())),
        _ => the_end(),
    });
    let mut term = Terminal::open(&device, root.path(), &klav_line("item get Deploy --reveal"));
    term.wait_for(&format!("Master password for {EMAIL}: "), 1);
    term.type_line("first fake password");
    term.wait_for(&format!("Master password for {EMAIL}: "), 2);
    term.type_line("second fake password");
    assert_eq!(term.exits(1), vec![1], "{}", term.text());
    let text = term.text();
    assert!(text.contains("your password wasn't used"), "{text}");
    assert!(
        text.contains("It lets the terminal ttysFAKE use your vault for 5 minutes."),
        "{text}"
    );
    assert_eq!(text.matches("Master password for").count(), 2, "{text}");
    drop(term);
    let views = changed.requests("view");
    assert_eq!(views.len(), 3, "{views:?}");
    assert_eq!(views[2]["password"], "second fake password");
    assert_eq!(without_password(&views[2]), views[0]);
}
