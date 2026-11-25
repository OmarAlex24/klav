//! `klav` in a pseudo-terminal of its own, for the commands that read a
//! value from `klavd`. With the presence gate on (ADR 0041, layer 6) such a
//! command asks for the master password on its controlling terminal, never
//! on stdin: [`Device::in_terminal`] runs it under `script` and types the
//! password there each time the question shows, as a person would.

use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::{Device, PASSWORD, Run, path_without_installed_klav};

/// What every gate question ends with (`crates/klav-cli/src/presence.rs`).
const QUESTION: &str = "Master password for ";

/// How long one command may take, questions included.
const LIMIT: Duration = Duration::from_secs(180);

/// `arg` quoted for `/bin/sh`.
fn quoted(arg: &str) -> String {
    format!("'{}'", arg.replace('\'', r"'\''"))
}

impl Device {
    /// `klav <args>` in a new pseudo-terminal (`script`), the controlling
    /// terminal of the command and of the `klavd` it may start, with
    /// `stdin` as its standard input and its standard output and error
    /// kept apart, as [`Device::run`] keeps them. Every master-password
    /// question the presence gate asks on that terminal is answered with
    /// [`PASSWORD`]. A missing `script` fails the test.
    #[track_caller]
    pub fn in_terminal(&self, dir: Option<&Path>, args: &[&str], stdin: &str) -> Run {
        let parent = self
            .home
            .parent()
            .expect("a home inside the test's directory");
        let work = tempfile::Builder::new()
            .prefix("tty-")
            .tempdir_in(parent)
            .expect("a directory for the terminal's files");
        let input = work.path().join("stdin");
        let out = work.path().join("stdout");
        let err = work.path().join("stderr");
        std::fs::write(&input, stdin).expect("stdin file");
        let cd = dir.map_or(String::new(), |dir| {
            format!("cd {} && ", quoted(dir.to_str().expect("utf-8 path")))
        });
        let line = format!(
            r#"{cd}"$KLAV_BIN" {} < {} > {} 2> {}; echo "KLAV-EXIT $?""#,
            args.iter().map(|a| quoted(a)).collect::<Vec<_>>().join(" "),
            quoted(input.to_str().expect("utf-8 path")),
            quoted(out.to_str().expect("utf-8 path")),
            quoted(err.to_str().expect("utf-8 path")),
        );
        let mut cmd = Command::new("script");
        if cfg!(target_os = "macos") {
            cmd.args(["-q", "/dev/null", "/bin/sh", "-c", &line]);
        } else {
            cmd.args(["-q", "-e", "-c", &line, "/dev/null"]);
        }
        cmd.env("KLAV_HOME", &self.home)
            .env("PATH", path_without_installed_klav())
            .env("KLAV_NO_TOUCH_ID", "1")
            .env("KLAV_NO_DEFAULT_SERVER", "1")
            .env("KLAV_BIN", env!("CARGO_BIN_EXE_klav"))
            .env_remove("KLAV_NO_DAEMON")
            .env_remove("KLAV_SERVER")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let mut child = cmd
            .spawn()
            .expect("`script` (util-linux on Linux) opens a terminal");
        let mut shown_out = child.stdout.take().expect("stdout");
        let shown = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&shown);
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok(n) = shown_out.read(&mut buf) {
                if n == 0 {
                    break;
                }
                sink.lock().expect("shown").extend_from_slice(&buf[..n]);
            }
        });
        let text = || String::from_utf8_lossy(&shown.lock().expect("shown")).into_owned();
        let deadline = Instant::now() + LIMIT;
        let mut answered = 0;
        let code = loop {
            let now = text();
            if let Some(rest) = now.split("KLAV-EXIT ").nth(1) {
                break rest
                    .split_whitespace()
                    .next()
                    .and_then(|c| c.parse().ok())
                    .unwrap_or(-1);
            }
            if now.matches(QUESTION).count() > answered {
                // `klav` writes the question only once echo is off and
                // what was typed before it is thrown away.
                let stdin = child.stdin.as_mut().expect("terminal input");
                stdin
                    .write_all(format!("{PASSWORD}\n").as_bytes())
                    .expect("type");
                stdin.flush().expect("flush");
                answered += 1;
            }
            if Instant::now() > deadline {
                let _ = child.kill();
                panic!("klav {args:?} did not finish in its terminal:\n{now}");
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        let deadline = Instant::now() + Duration::from_secs(5);
        while !matches!(child.try_wait(), Ok(Some(_))) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        let _ = child.kill();
        let _ = child.wait();
        Run {
            code,
            stdout: std::fs::read_to_string(&out).unwrap_or_default(),
            stderr: std::fs::read_to_string(&err).unwrap_or_default(),
        }
    }

    /// [`Device::in_terminal`] with `--password-stdin` and the master
    /// password as the first line of stdin, as [`Device::unlocked`] runs a
    /// command: the password unlocks `klavd` if it is locked (opening no
    /// window, ADR 0041 decision 4), and the gate's question on the
    /// terminal is answered as well.
    #[track_caller]
    pub fn unlocked_in_terminal(&self, args: &[&str], extra: &str) -> Run {
        let mut all = vec!["--password-stdin"];
        all.extend_from_slice(args);
        self.in_terminal(None, &all, &format!("{PASSWORD}\n{extra}"))
    }
}
