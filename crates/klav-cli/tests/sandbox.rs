//! `klav sandbox start | ls | stop`, the issuer's side (ADR 0036 §4, E6.1,
//! layer 5), against a real server and a real `klav-proxy` started in this
//! process: the package reaches the command's environment or a new 0600
//! file and is never printed, and each refusal has its stable exit code.

mod common;

use std::os::unix::fs::PermissionsExt;
use std::time::Duration;

use common::{Device, ServerProcess};
use klav_client::Home;
use serde_json::Value;

const SECRET: &str = "MARKER-sandbox-token-0123456789";
const PACKAGE_PREFIX: &str = "ksb1_";

/// Stops the daemon even if the test fails.
struct StopDaemon(Device);

impl Drop for StopDaemon {
    fn drop(&mut self) {
        let _ = self.0.run(&["lock", "--stop"], "");
    }
}

/// Registers an agent from its own machine and returns its 6 words.
fn register(root: &std::path::Path, server: &ServerProcess, name: &str) -> String {
    Device::new(root, name)
        .run(
            &[
                "agent",
                "register",
                "--name",
                name,
                "--server",
                &server.url,
                "--email",
                "ana@example.com",
                "--key-store",
                "file",
            ],
            "",
        )
        .ok()
        .stdout
        .trim()
        .to_owned()
}

#[track_caller]
fn never_the_package(out: &common::Run) {
    for text in [&out.stdout, &out.stderr] {
        assert!(!text.contains(PACKAGE_PREFIX), "{text}");
        assert!(!text.contains(SECRET), "{text}");
    }
}

/// Runs a failing `klav <args>` without and with `--json`: the same exit
/// code and the same stderr, byte for byte, also with `--json` and stdout
/// closed (`| head -0`); with `--json`, stdout is one line of JSON
/// `{error, message, next}` without control characters, and no run shows
/// the package. Returns that run and its JSON.
#[track_caller]
fn fails_alike(dev: &Device, args: &[&str]) -> (common::Run, Value) {
    let text = dev.run(args, "").err();
    // Before `--`: after it, `--json` would be the command's.
    let mut with_json = args.to_vec();
    let at = args.iter().position(|a| *a == "--").unwrap_or(args.len());
    with_json.insert(at, "--json");
    let json = dev.run(&with_json, "").err();
    never_the_package(&text);
    assert_eq!(json.code, text.code, "{}", json.stderr);
    assert_eq!(json.stderr, text.stderr);
    let closed = closed_stdout(dev, &with_json);
    never_the_package(&closed);
    assert_eq!(closed.code, text.code, "{}", closed.stderr);
    assert_eq!(closed.stderr, text.stderr);
    let error = json_error(&json);
    (json, error)
}

/// `klav <args>` with stdout a pipe nobody reads any more: a write there
/// fails with `EPIPE`.
fn closed_stdout(dev: &Device, args: &[&str]) -> common::Run {
    let (reader, writer) = std::io::pipe().expect("pipe");
    drop(reader);
    let out = dev
        .command()
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(writer)
        .output()
        .expect("klav");
    common::Run {
        code: out.status.code().unwrap_or(-1),
        stdout: String::new(),
        stderr: String::from_utf8(out.stderr).expect("utf-8 stderr"),
    }
}

/// The `--json` line of a failure: one line of JSON on stdout with
/// `error` (a `klav_*` code or null), `message` and `next`, and never the
/// package.
#[track_caller]
fn json_error(out: &common::Run) -> Value {
    never_the_package(out);
    assert_eq!(out.stdout.matches('\n').count(), 1, "{:?}", out.stdout);
    let v: Value = serde_json::from_str(&out.stdout).expect("error json");
    for key in ["error", "message", "next"] {
        assert!(v.get(key).is_some(), "{key} in {v}");
    }
    assert!(v["message"].as_str().is_some_and(|m| !m.is_empty()), "{v}");
    // Whatever the text quotes (a name, a path, a proxy's words): no
    // terminal escapes or other control characters on the line.
    for key in ["message", "next"] {
        if let Some(text) = v[key].as_str() {
            assert!(!text.chars().any(char::is_control), "{key} in {v}");
        }
    }
    v
}

/// What a fake listener on the proxy's port does with a connection.
#[derive(Clone)]
enum Fake {
    /// Accepts and never answers.
    Hang,
    /// Accepts and closes at once.
    Drop,
    /// Answers this raw HTTP response.
    Answer(String),
    /// Answers these, one per connection, the last one again after.
    Script(Vec<String>),
}

/// A listener on a free loopback port that treats each connection as
/// `fake` says; returns its port and a channel that gets one message per
/// connection.
fn fake_proxy(fake: Fake) -> (String, std::sync::mpsc::Receiver<()>) {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port().to_string();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut held = Vec::new();
        let mut served = 0usize;
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let _ = tx.send(());
            match &fake {
                Fake::Hang => held.push(stream),
                Fake::Drop => drop(stream),
                Fake::Answer(_) | Fake::Script(_) => {
                    let response = match &fake {
                        Fake::Script(all) => {
                            let at = served.min(all.len() - 1);
                            served += 1;
                            all[at].clone()
                        }
                        Fake::Answer(r) => r.clone(),
                        _ => unreachable!(),
                    };
                    let mut seen = Vec::new();
                    let mut buf = [0u8; 4096];
                    while !seen.windows(4).any(|w| w == b"\r\n\r\n") {
                        match stream.read(&mut buf) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => seen.extend_from_slice(&buf[..n]),
                        }
                    }
                    let _ = stream.write_all(response.as_bytes());
                }
            }
        }
    });
    (port, rx)
}

/// Sends `signal` to `child` and waits at most `limit` for it to exit.
fn signal_and_wait(
    child: std::process::Child,
    signal: nix::sys::signal::Signal,
    limit: Duration,
) -> common::Run {
    use std::io::Read;
    let mut child = child;
    let pid = nix::unistd::Pid::from_raw(i32::try_from(child.id()).expect("pid"));
    nix::sys::signal::kill(pid, signal).expect("signal");
    let started = std::time::Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().expect("wait") {
            break status;
        }
        assert!(
            started.elapsed() < limit,
            "klav did not exit within {limit:?}"
        );
        std::thread::sleep(Duration::from_millis(50));
    };
    let mut stdout = String::new();
    let mut stderr = String::new();
    child
        .stdout
        .take()
        .expect("stdout")
        .read_to_string(&mut stdout)
        .expect("stdout");
    child
        .stderr
        .take()
        .expect("stderr")
        .read_to_string(&mut stderr)
        .expect("stderr");
    common::Run {
        code: status.code().unwrap_or(-1),
        stdout,
        stderr,
    }
}

/// Kills the process whose ID is in a file, when dropped.
struct KillFromFile(std::path::PathBuf);

impl Drop for KillFromFile {
    fn drop(&mut self) {
        if let Ok(pid) = std::fs::read_to_string(&self.0)
            && let Ok(pid) = pid.trim().parse::<i32>()
        {
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(pid),
                nix::sys::signal::Signal::SIGKILL,
            );
        }
    }
}

/// Fails if `dir` holds a `*.klav-tmp` file: a `--package-file` that failed
/// must leave no temporary file next to where the package would have gone.
fn no_temporary_in(dir: &std::path::Path) {
    let left: Vec<String> = std::fs::read_dir(dir)
        .expect("read dir")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".klav-tmp"))
        .collect();
    assert!(left.is_empty(), "{left:?}");
}

fn live(issuer: &Device, port: &str) -> Vec<Value> {
    let out = issuer
        .run(&["sandbox", "ls", "--proxy-port", port, "--json"], "")
        .ok();
    never_the_package(&out);
    let v: Value = serde_json::from_str(&out.stdout).expect("ls json");
    v["sandboxes"].as_array().expect("sandboxes").clone()
}

/// The person, signed up and unlocked in `klavd`, with a proxy that holds
/// `Railway` under the `railway` profile and `t3-code` as its issuer (at
/// most two live sandboxes), and the proxy serving in this process.
struct Setup {
    runtime: tokio::runtime::Runtime,
    port: String,
    person: Device,
    issuer: Device,
    /// The proxy's pinned channel, when it serves one.
    channel: Option<std::net::SocketAddr>,
    _stop: StopDaemon,
}

fn person_proxy_and_issuer(root: &std::path::Path, server: &ServerProcess) -> Setup {
    person_proxy_and_issuer_at(
        root,
        server,
        |_| "tls://proxy.example.com:8443".into(),
        false,
        None,
    )
}

/// [`person_proxy_and_issuer`] with the issuer's proxy URL `url(proxy's
/// agent ID)`, the proxy's pinned channel on loopback with `channel`, and
/// a second issuer `(name, url)` added before the proxy starts.
fn person_proxy_and_issuer_at(
    root: &std::path::Path,
    server: &ServerProcess,
    url: impl Fn(klav_core::ids::AgentId) -> String,
    channel: bool,
    second: Option<(&str, &str)>,
) -> Setup {
    let person = Device::new(root, "person");
    person.signup(server, "ana@example.com");
    let stop = StopDaemon(Device::new(root, "person"));
    person.unlocked(&["unlock", "--idle-lock", "10m"], "").ok();
    person
        .run(
            &[
                "item",
                "add",
                "api-key",
                "--title",
                "Railway",
                "--secret-stdin",
                "api_key",
            ],
            &format!("{SECRET}\n"),
        )
        .ok();
    let proxy_words = register(root, server, "klav-proxy");
    person
        .unlocked(&["proxy", "use", "own", "klav-proxy"], "")
        .ok();
    person
        .unlocked(
            &[
                "proxy",
                "grant",
                "Railway",
                "--profile",
                "railway",
                "--upstream",
                "https://backboard.railway.app",
                "--header",
                "authorization",
                "--prefix",
                "Bearer ",
                "--method",
                "POST",
                "--path-prefix",
                "/graphql",
                "--every-device-is-updated",
                "--words",
                &proxy_words,
            ],
            "",
        )
        .ok();
    let proxy_id = klav_sdk::Agent::load(&Home::at(root.join("klav-proxy")), "klav-proxy")
        .expect("proxy agent")
        .id();
    let url = url(proxy_id);
    let words = register(root, server, "t3-code");
    // The first issuer, with neither the acknowledgement nor the words (no
    // terminal to ask): the first refusal names both.
    let out = person
        .unlocked(
            &[
                "proxy",
                "issuer",
                "add",
                "t3-code",
                "--profile",
                "railway",
                "--url",
                &url,
            ],
            "",
        )
        .err();
    assert!(
        out.stderr.contains("--every-device-is-updated") && out.stderr.contains("--words"),
        "{}",
        out.stderr
    );
    person
        .unlocked(
            &[
                "proxy",
                "issuer",
                "add",
                "t3-code",
                "--profile",
                "railway",
                "--url",
                &url,
                "--max-live",
                "2",
                "--every-device-is-updated",
                "--words",
                &words,
            ],
            "",
        )
        .ok();

    if let Some((name, url)) = second {
        let words = register(root, server, name);
        person
            .unlocked(
                &[
                    "proxy",
                    "issuer",
                    "add",
                    name,
                    "--profile",
                    "railway",
                    "--url",
                    url,
                    "--every-device-is-updated",
                    "--words",
                    &words,
                ],
                "",
            )
            .ok();
    }

    // The proxy, in this process, with the real startup path, and its
    // local socket where the person's `klav proxy local` looks (layer 11).
    let socket = klav_client::local_proxy::socket_path(
        &Home::at(&person.home),
        klav_client::local_proxy::DEFAULT_NAME,
    );
    std::fs::create_dir_all(socket.parent().expect("agents dir")).expect("agents dir");
    let runtime = tokio::runtime::Runtime::new().expect("runtime");
    let bound = runtime
        .block_on(klav_proxy::app::bind(klav_proxy::app::ServeOptions {
            home: Home::at(root.join("klav-proxy")),
            name: "klav-proxy".into(),
            port: 0,
            channel: channel.then(|| std::net::SocketAddr::from(([127, 0, 0, 1], 0))),
            max_body: klav_proxy::proxy::DEFAULT_MAX_BODY,
            request_timeout: Duration::from_secs(30),
            no_local_calls: false,
            control_socket: klav_proxy::app::ControlSocket::At(socket),
            env: klav_proxy::app::StartEnv::default(),
        }))
        .expect("proxy");
    let port = bound.port().to_string();
    let channel = bound.channel_addr();
    runtime.spawn(bound.run(std::future::pending()));
    let issuer = Device::new(root, "t3-code");
    Setup {
        runtime,
        port,
        person,
        issuer,
        channel,
        _stop: stop,
    }
}

#[test]
fn an_issuer_starts_lists_and_stops_sandboxes_without_printing_the_package() {
    let mut server = ServerProcess::start(900);
    let root = tempfile::tempdir().expect("tempdir");
    let Setup {
        runtime,
        port,
        person,
        issuer,
        _stop,
        ..
    } = person_proxy_and_issuer(root.path(), &server);
    let port = port.as_str();

    // The package must go somewhere: refused before any sandbox exists.
    // A usage error has no Klav code: `error` is null, exit 2.
    let (out, error) = fails_alike(
        &issuer,
        &[
            "sandbox",
            "start",
            "--label",
            "c-0",
            "--profile",
            "railway",
            "--proxy-port",
            port,
        ],
    );
    assert_eq!(out.code, 2, "{}", out.stderr);
    assert_eq!(error["error"], Value::Null, "{error}");
    assert!(
        out.stderr.starts_with(&format!(
            "klav: {}\n",
            error["message"].as_str().expect("message")
        )),
        "{}",
        out.stderr
    );
    assert!(live(&issuer, port).is_empty());

    // 1. `--package-file`: a new 0600 file holds the package; stdout and
    // stderr never do, nor does `--json`.
    let work = tempfile::tempdir().expect("work");
    let pkg = work.path().join("pkg");
    let pkg_s = pkg.to_str().expect("path");
    // A temporary of another write: reported on stderr, never in `--json`,
    // and left as it was.
    let left = work.path().join(".pkg.0123456789abcdef.klav-tmp");
    std::fs::write(&left, b"MARKER-left").expect("leftover");
    let out = issuer
        .run(
            &[
                "sandbox",
                "start",
                "--label",
                "chat-1",
                "--profile",
                "railway",
                "--ttl",
                "2h",
                "--proxy-port",
                port,
                "--package-file",
                pkg_s,
                "--json",
            ],
            "",
        )
        .ok();
    never_the_package(&out);
    let started: Value = serde_json::from_str(&out.stdout).expect("start json");
    let keys: Vec<&str> = started
        .as_object()
        .expect("object")
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        keys,
        [
            "expires_at",
            "label",
            "next",
            "profiles",
            "sandbox_id",
            "setup"
        ],
        "{started}"
    );
    let first = started["sandbox_id"].as_str().expect("id").to_owned();
    assert!(
        out.stderr.contains(&left.display().to_string())
            && out.stderr.contains("Klav did not delete it")
            && !out.stderr.contains("MARKER"),
        "{}",
        out.stderr
    );
    assert!(!out.stdout.contains("klav-tmp"), "{}", out.stdout);
    assert_eq!(std::fs::read(&left).expect("left"), b"MARKER-left");
    std::fs::remove_file(&left).expect("rm leftover");
    // The setup lines: `klav-forward` and nothing secret. The forwarder's
    // `crates/klav-forward/tests/up.rs` runs the same lines, read from
    // `src/commands/sandbox.rs`, and checks them against this literal too.
    assert_eq!(
        started["setup"],
        serde_json::json!([
            "klav-forward down --if-other-package",
            "klav-forward up --daemon",
            "eval \"$(klav-forward env)\""
        ])
    );
    assert!(
        started["next"]
            .as_str()
            .expect("next")
            .contains(&format!("klav sandbox stop {first}"))
    );
    let meta = std::fs::metadata(&pkg).expect("package file");
    assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    assert!(
        std::fs::read_to_string(&pkg)
            .expect("read package")
            .starts_with(PACKAGE_PREFIX)
    );

    // The proxy's store, where `serve` puts it, is no agent: the proxy's
    // home still has exactly one, so `--agent` stays optional there.
    let proxy_home = Home::at(root.path().join("klav-proxy"));
    let store = klav_proxy::sandboxes::Sandboxes::path_in(&proxy_home, "klav-proxy");
    assert!(store.starts_with(root.path().join("klav-proxy").join("agents")));
    let mode = std::fs::metadata(&store)
        .expect("store")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600);
    assert_eq!(klav_sdk::config::list(&proxy_home), ["klav-proxy"]);
    assert_eq!(
        klav_sdk::config::pick(&proxy_home, None).expect("one agent"),
        "klav-proxy"
    );

    // A path that exists, or a symlink, is refused before any sandbox.
    let out = issuer
        .run(
            &[
                "sandbox",
                "start",
                "--label",
                "chat-x",
                "--profile",
                "railway",
                "--proxy-port",
                port,
                "--package-file",
                pkg_s,
            ],
            "",
        )
        .err();
    assert_eq!(out.code, 2, "{}", out.stderr);
    assert!(
        out.stderr.contains("does not exist yet") && !out.stderr.contains("--force"),
        "{}",
        out.stderr
    );
    let link = work.path().join("link");
    std::os::unix::fs::symlink(work.path().join("target"), &link).expect("symlink");
    let out = issuer
        .run(
            &[
                "sandbox",
                "start",
                "--label",
                "chat-x",
                "--profile",
                "railway",
                "--proxy-port",
                port,
                "--package-file",
                link.to_str().expect("path"),
            ],
            "",
        )
        .err();
    assert_eq!(out.code, 2, "{}", out.stderr);
    assert!(!work.path().join("target").exists());
    assert_eq!(live(&issuer, port).len(), 1);
    // A file that cannot be created (its directory is missing) is refused
    // before any sandbox too. Its temporary file would have gone in that
    // missing directory, so there is nothing to scan: the directory is
    // still missing, and no sandbox started.
    let missing = work.path().join("missing").join("pkg");
    let out = issuer
        .run(
            &[
                "sandbox",
                "start",
                "--label",
                "chat-x",
                "--profile",
                "railway",
                "--proxy-port",
                port,
                "--package-file",
                missing.to_str().expect("path"),
            ],
            "",
        )
        .err();
    assert_eq!(out.code, 2, "{}", out.stderr);
    assert!(out.stderr.contains("cannot create"), "{}", out.stderr);
    assert_eq!(live(&issuer, port).len(), 1);
    assert!(!work.path().join("missing").exists());

    // 2. `-- <command>`: the command gets the package in KLAV_SANDBOX, and
    // what it prints of it, on either stream, is redacted.
    let script = format!(
        "test -n \"$KLAV_SANDBOX\" && printf %s \"$KLAV_SANDBOX\" > '{}' && echo \"pkg=$KLAV_SANDBOX\" && echo \"$KLAV_SANDBOX\" >&2",
        work.path().join("pkg-copy").display()
    );
    let out = issuer
        .run(
            &[
                "sandbox",
                "start",
                "--label",
                "chat-2",
                "--profile",
                "railway",
                "--proxy-port",
                port,
                "--",
                "sh",
                "-c",
                &script,
            ],
            "",
        )
        .ok();
    never_the_package(&out);
    // Neither the package nor a long piece of it, not only its prefix.
    let copy = std::fs::read_to_string(work.path().join("pkg-copy")).expect("copy");
    assert!(copy.starts_with(PACKAGE_PREFIX) && copy.len() > 60);
    for text in [&out.stdout, &out.stderr] {
        assert!(
            !text.contains(&copy) && !text.contains(&copy[20..60]),
            "{text}"
        );
    }
    assert!(out.stdout.contains("pkg="), "{}", out.stdout);
    assert!(out.stderr.contains("Started sandbox"), "{}", out.stderr);
    assert!(
        out.stderr.contains("removed from the command's output"),
        "{}",
        out.stderr
    );

    // 3. The issuer's limits: exit 5, and a file made for a refused start
    // is removed. With `--json`, the proxy's code, message and next.
    let (out, error) = fails_alike(
        &issuer,
        &[
            "sandbox",
            "start",
            "--label",
            "chat-3",
            "--profile",
            "maple",
            "--proxy-port",
            port,
            "--package-file",
            work.path().join("p3").to_str().expect("path"),
        ],
    );
    assert_eq!(out.code, 5, "{}", out.stderr);
    assert!(out.stderr.contains("Next:"), "{}", out.stderr);
    assert_eq!(error["error"], "klav_profile_not_allowed", "{error}");
    no_temporary_in(work.path());
    // The text is the JSON's message, then `Next:` and its next.
    assert_eq!(
        out.stderr,
        format!(
            "klav: {}\nNext: {}\n",
            error["message"].as_str().expect("message"),
            error["next"].as_str().expect("next")
        )
    );
    assert!(!work.path().join("p3").exists());
    let (out, error) = fails_alike(
        &issuer,
        &[
            "sandbox",
            "start",
            "--label",
            "chat-3",
            "--profile",
            "railway",
            "--proxy-port",
            port,
            "--package-file",
            work.path().join("p3").to_str().expect("path"),
        ],
    );
    assert_eq!(out.code, 5, "{}", out.stderr);
    assert!(out.stderr.contains("Next:"), "{}", out.stderr);
    assert_eq!(error["error"], "klav_too_many_sandboxes", "{error}");
    assert!(!work.path().join("p3").exists());
    no_temporary_in(work.path());

    // 4. `ls`: its own, live.
    let out = issuer
        .run(&["sandbox", "ls", "--proxy-port", port], "")
        .ok();
    never_the_package(&out);
    assert!(out.stdout.contains("chat-1") && out.stdout.contains("chat-2"));
    assert!(out.stdout.contains("waiting for claim"), "{}", out.stdout);

    // 4a. A signal while the start waits: the command never runs, the
    // package file is removed, and the exit is the signal's.
    let (hang, accepted) = fake_proxy(Fake::Hang);
    let ran = work.path().join("ran");
    let touch = format!("touch '{}'", ran.display());
    let p6 = work.path().join("p6");
    for (signal, code, extra) in [
        (
            nix::sys::signal::Signal::SIGINT,
            130,
            vec!["--", "sh", "-c", touch.as_str()],
        ),
        (
            nix::sys::signal::Signal::SIGTERM,
            143,
            vec!["--package-file", p6.to_str().expect("path"), "--json"],
        ),
    ] {
        let json = extra.contains(&"--json");
        let mut args = vec![
            "sandbox",
            "start",
            "--label",
            "chat-6",
            "--profile",
            "railway",
            "--proxy-port",
            hang.as_str(),
        ];
        args.extend(extra);
        let child = issuer.command().args(&args).spawn().expect("spawn");
        accepted
            .recv_timeout(Duration::from_secs(30))
            .expect("klav reached the port");
        let out = signal_and_wait(child, signal, Duration::from_secs(10));
        assert_eq!(out.code, code, "{}", out.stderr);
        assert!(out.stderr.contains("klav sandbox ls"), "{}", out.stderr);
        assert!(!ran.exists(), "the command ran after the signal");
        assert!(!p6.exists(), "the package file was left");
        no_temporary_in(work.path());
        // A signal has no Klav code; the exit code says which.
        if json {
            assert_eq!(json_error(&out)["error"], Value::Null, "{}", out.stdout);
        } else {
            assert!(out.stdout.is_empty(), "{}", out.stdout);
        }
    }

    // 4b. A broken answer: a sandbox may have started, and `ls` says.
    let (dropping, _) = fake_proxy(Fake::Drop);
    let (out, error) = fails_alike(
        &issuer,
        &[
            "sandbox",
            "start",
            "--label",
            "chat-7",
            "--profile",
            "railway",
            "--proxy-port",
            &dropping,
            "--package-file",
            work.path().join("p7").to_str().expect("path"),
        ],
    );
    assert_eq!(out.code, 1, "{}", out.stderr);
    assert!(out.stderr.contains("may have started"), "{}", out.stderr);
    // No code Klav documents (the SDK's internal one is not published).
    assert_eq!(error["error"], Value::Null, "{error}");
    assert!(!work.path().join("p7").exists());
    no_temporary_in(work.path());
    assert!(
        error["message"]
            .as_str()
            .expect("message")
            .contains("may have started"),
        "{error}"
    );
    let out = issuer
        .run(
            &[
                "sandbox",
                "start",
                "--label",
                "chat-7",
                "--profile",
                "railway",
                "--proxy-port",
                &dropping,
                "--",
                "true",
            ],
            "",
        )
        .err();
    assert_eq!(out.code, 1, "{}", out.stderr);
    assert!(out.stderr.contains("may have started"), "{}", out.stderr);

    // 4c. Whatever answers on the port cannot put terminal escapes or
    // hidden characters in front of the agent.
    let (squatter, _) = fake_proxy(Fake::Answer(concat!(
        "HTTP/1.1 403 Forbidden\r\ncontent-type: application/json\r\nconnection: close\r\n\r\n",
        r#"{"error":"klav_not_issuer","message":"no\u001b[2J\u202eway","next":"run\u001b]0;title\u0007 this"}"#,
    ).to_owned()));
    let (out, error) = fails_alike(&issuer, &["sandbox", "ls", "--proxy-port", &squatter]);
    assert_eq!(out.code, 5, "{}", out.stderr);
    assert_eq!(error["error"], "klav_not_issuer", "{error}");
    // Nor in the JSON: the characters go, not escaped (serde_json would
    // write ESC as `\u001b` and leave C1 and bidi characters as they are).
    assert_eq!(error["message"], "no[2Jway", "{error}");
    assert_eq!(error["next"], "run]0;title this", "{error}");
    for c in ['\u{1b}', '\u{202e}', '\u{7}'] {
        assert!(!out.stdout.contains(c), "{:?}", out.stdout);
    }
    assert!(!out.stdout.contains("\\u001b"), "{}", out.stdout);
    // A code that is not one of Klav's shape is not passed on.
    let (odd, _) = fake_proxy(Fake::Answer(
        concat!(
            "HTTP/1.1 403 Forbidden\r\ncontent-type: application/json\r\nconnection: close\r\n\r\n",
            r#"{"error":"klav_not_issuer\u001b[2J\u202e","message":"no","next":"stop"}"#,
        )
        .to_owned(),
    ));
    let (_, error) = fails_alike(&issuer, &["sandbox", "ls", "--proxy-port", &odd]);
    assert_eq!(error["error"], Value::Null, "{error}");
    let out = issuer
        .run(&["sandbox", "ls", "--proxy-port", &squatter], "")
        .err();
    assert_eq!(out.code, 5, "{}", out.stderr);
    // The escapes' characters go; their printable rest stays as text.
    assert!(out.stderr.contains("no[2Jway"), "{}", out.stderr);
    assert!(
        !out.stderr.contains('\u{1b}')
            && !out.stderr.contains('\u{202e}')
            && !out.stderr.contains('\u{7}'),
        "{:?}",
        out.stderr
    );

    // The same in a success: `ls` shows the port's labels and profiles
    // without ESC, BEL, DEL, C1 or bidi characters, in the table and in
    // `--json` (serde_json escapes only C0).
    let body = format!(
        r#"{{"sandboxes":[{{"sandbox_id":"{first}","label":"a\u001b]0;t\u0007b\u007fc\u009bd\u202ee","profiles":["p\u009b1\u202e"],"issued_at":1,"expires_at":4102444800000,"claimed":false}}]}}"#
    );
    let (lister, _) = fake_proxy(Fake::Answer(format!(
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    )));
    for json in [false, true] {
        let mut args = vec!["sandbox", "ls", "--proxy-port", lister.as_str()];
        if json {
            args.push("--json");
        }
        let out = issuer.run(&args, "").ok();
        for c in ['\u{1b}', '\u{7}', '\u{7f}', '\u{9b}', '\u{202e}'] {
            assert!(!out.stdout.contains(c), "{c:?} in {:?}", out.stdout);
        }
        assert!(
            !out.stdout.contains("\\u001b") && !out.stdout.contains("\\u0007"),
            "{}",
            out.stdout
        );
        assert!(out.stdout.contains("a]0;tbcde"), "{}", out.stdout);
        assert!(out.stdout.contains("p1"), "{}", out.stdout);
    }

    // 5. No proxy on the port: exit 1.
    let closed = std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind")
        .local_addr()
        .expect("addr")
        .port()
        .to_string();
    let (out, error) = fails_alike(&issuer, &["sandbox", "ls", "--proxy-port", &closed]);
    assert_eq!(out.code, 1, "{}", out.stderr);
    assert!(out.stderr.contains("did not answer"), "{}", out.stderr);
    assert_eq!(error["error"], "klav_proxy_unreachable", "{error}");
    let (_, error) = fails_alike(
        &issuer,
        &["sandbox", "stop", "--all", "--proxy-port", &closed],
    );
    assert_eq!(error["error"], "klav_proxy_unreachable", "{error}");

    // 6. A paused account: exit 7, until the person resumes.
    person.unlocked(&["agent", "pause", "--all"], "").ok();
    let (out, error) = fails_alike(
        &issuer,
        &[
            "sandbox",
            "start",
            "--label",
            "chat-4",
            "--profile",
            "railway",
            "--proxy-port",
            port,
            "--package-file",
            work.path().join("p4").to_str().expect("path"),
        ],
    );
    assert_eq!(out.code, 7, "{}", out.stderr);
    assert_eq!(error["error"], "klav_agents_paused", "{error}");
    assert!(!work.path().join("p4").exists());
    no_temporary_in(work.path());
    person.unlocked(&["agent", "resume", "--all"], "").ok();

    // 7. An agent the person never made an issuer: exit 5, and a `next`
    // that tells it not to grant itself.
    let _ = register(root.path(), &server, "builder");
    let (out, error) = fails_alike(
        &Device::new(root.path(), "builder"),
        &[
            "sandbox",
            "start",
            "--label",
            "chat-5",
            "--profile",
            "railway",
            "--proxy-port",
            port,
            "--package-file",
            work.path().join("p5").to_str().expect("path"),
        ],
    );
    assert_eq!(out.code, 5, "{}", out.stderr);
    assert_eq!(error["error"], "klav_not_issuer", "{error}");
    assert!(
        out.stderr.contains("klav proxy issuer add builder"),
        "{}",
        out.stderr
    );

    // 8. `stop ID`, then `stop --all`.
    let out = issuer
        .run(&["sandbox", "stop", &first, "--proxy-port", port], "")
        .ok();
    assert!(out.stdout.contains(&format!("Stopped sandbox {first}")));
    assert_eq!(live(&issuer, port).len(), 1);
    let out = issuer
        .run(
            &["sandbox", "stop", "--all", "--proxy-port", port, "--json"],
            "",
        )
        .ok();
    let stopped: Value = serde_json::from_str(&out.stdout).expect("stop json");
    assert_eq!(stopped["stopped"].as_array().expect("stopped").len(), 1);
    assert_eq!(stopped["logged"], true);
    assert!(live(&issuer, port).is_empty());
    // A stopped sandbox is not found again.
    let (out, error) = fails_alike(&issuer, &["sandbox", "stop", &first, "--proxy-port", port]);
    assert_eq!(out.code, 1, "{}", out.stderr);
    assert_eq!(error["error"], "klav_sandbox_not_found", "{error}");
    // One ID stops nothing else: no `stopped` or `logged` on the line
    // (only `stop --all` that fails halfway has them).
    assert!(
        error.get("stopped").is_none() && error.get("logged").is_none(),
        "{error}"
    );
    // Not a sandbox ID: a usage error, exit 2.
    let (out, error) = fails_alike(&issuer, &["sandbox", "stop", "nope", "--proxy-port", port]);
    assert_eq!(out.code, 2, "{}", out.stderr);
    assert_eq!(error["error"], Value::Null, "{error}");
    assert!(error.get("stopped").is_none(), "{error}");
    // A name or a path the agent gave, with a terminal escape in it: the
    // line never carries the escape, whichever error quotes it. (The name
    // error quotes it escaped already; the path error quotes it as is.)
    let (_, error) = fails_alike(
        &issuer,
        &[
            "sandbox",
            "ls",
            "--agent",
            "no\u{1b}[2Jbody",
            "--proxy-port",
            port,
        ],
    );
    assert!(
        error["message"].as_str().expect("message").contains("no"),
        "{error}"
    );
    let escaped = root.path().join("no\u{1b}[2Jdir").join("package");
    let (_, error) = fails_alike(
        &issuer,
        &[
            "sandbox",
            "start",
            "--label",
            "c-esc",
            "--profile",
            "railway",
            "--package-file",
            escaped.to_str().expect("path"),
            "--proxy-port",
            port,
        ],
    );
    assert!(
        error["message"]
            .as_str()
            .expect("message")
            .contains("no[2Jdir"),
        "{error}"
    );

    // 8a. `stop --all` that fails halfway: what it stopped is on stdout,
    // in `--json` too, before the error.
    let (one, two) = (
        klav_core::ids::SandboxId::generate(),
        klav_core::ids::SandboxId::generate(),
    );
    let reply = |status: &str, body: String| {
        format!(
            "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        )
    };
    let listed = format!(
        r#"{{"sandboxes":[{{"sandbox_id":"{one}","label":"a","profiles":["railway"],"issued_at":1,"expires_at":4102444800000,"claimed":false}},{{"sandbox_id":"{two}","label":"b","profiles":["railway"],"issued_at":1,"expires_at":4102444800000,"claimed":false}}]}}"#
    );
    for json in [true, false] {
        let (halfway, _) = fake_proxy(Fake::Script(vec![
            reply("200 OK", listed.clone()),
            reply("200 OK", r#"{"logged":true}"#.to_owned()),
            reply(
                "500 Internal Server Error",
                r#"{"error":"klav_proxy_store","message":"not saved","next":"wait"}"#.to_owned(),
            ),
        ]));
        let mut args = vec!["sandbox", "stop", "--all", "--proxy-port", halfway.as_str()];
        if json {
            args.push("--json");
        }
        let out = issuer.run(&args, "").err();
        assert_eq!(out.code, 1, "{}", out.stderr);
        assert!(out.stderr.contains("not saved"), "{}", out.stderr);
        if json {
            // One JSON document: the error, with what was stopped.
            let partial = json_error(&out);
            assert_eq!(partial["stopped"], serde_json::json!([one]));
            assert_eq!(partial["logged"], true);
            assert_eq!(partial["error"], "klav_proxy_store");
            assert_eq!(partial["message"], "not saved");
            assert_eq!(partial["next"], "wait");
        } else {
            assert_eq!(out.stdout.trim(), format!("Stopped sandbox {one}."));
        }
    }

    // 9. A command that leaves a process holding its output: once the
    // command is done, a signal still ends `klav` (no SIGKILL needed).
    let bg = work.path().join("bg");
    let shell = work.path().join("shell");
    let done = work.path().join("done");
    let script = format!(
        "echo $$ > '{}'; sleep 60 & echo $! > '{}'; touch '{}'",
        shell.display(),
        bg.display(),
        done.display()
    );
    // The `sleep` dies with the test, even if an assertion fails.
    let _kill_sleep = KillFromFile(bg.clone());
    let child = issuer
        .command()
        .args([
            "sandbox",
            "start",
            "--label",
            "chat-8",
            "--profile",
            "railway",
            "--proxy-port",
            port,
            "--",
            "sh",
            "-c",
            &script,
        ])
        .spawn()
        .expect("spawn");
    let waited = std::time::Instant::now();
    while !done.exists() {
        assert!(
            waited.elapsed() < Duration::from_secs(30),
            "the command never ran"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    // Wait until the shell is gone (and reaped by klav), so the signal
    // reaches the wait for the output, not the shell.
    let shell_pid = nix::unistd::Pid::from_raw(
        std::fs::read_to_string(&shell)
            .expect("shell pid")
            .trim()
            .parse()
            .expect("pid"),
    );
    while nix::sys::signal::kill(shell_pid, None).is_ok() {
        assert!(
            waited.elapsed() < Duration::from_secs(30),
            "the shell never exited"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    let out = signal_and_wait(
        child,
        nix::sys::signal::Signal::SIGTERM,
        Duration::from_secs(10),
    );
    assert!(out.stderr.contains("stopped reading"), "{}", out.stderr);
    assert_eq!(out.code, 0, "the command's own exit code: {}", out.stderr);
    issuer
        .run(&["sandbox", "stop", "--all", "--proxy-port", port], "")
        .ok();

    // 9b. The signal comes while the command runs: `klav` forwards it, the
    // command leaves a process holding its output and exits, and `klav`
    // ends after a moment, without a second signal.
    let bg2 = work.path().join("bg2");
    let ready = work.path().join("ready");
    let script = format!(
        "trap 'sleep 60 & echo $! > \"{}\"; exit 0' TERM; touch '{}'; while :; do sleep 0.1; done",
        bg2.display(),
        ready.display()
    );
    let _kill_sleep2 = KillFromFile(bg2.clone());
    let child = issuer
        .command()
        .args([
            "sandbox",
            "start",
            "--label",
            "chat-8b",
            "--profile",
            "railway",
            "--proxy-port",
            port,
            "--",
            "sh",
            "-c",
            &script,
        ])
        .spawn()
        .expect("spawn");
    let waited = std::time::Instant::now();
    while !ready.exists() {
        assert!(
            waited.elapsed() < Duration::from_secs(30),
            "the command never ran"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    let out = signal_and_wait(
        child,
        nix::sys::signal::Signal::SIGTERM,
        Duration::from_secs(10),
    );
    assert!(bg2.exists(), "the command got the signal: {}", out.stderr);
    assert!(out.stderr.contains("stopped reading"), "{}", out.stderr);
    assert_eq!(out.code, 0, "the command's own exit code: {}", out.stderr);
    issuer
        .run(&["sandbox", "stop", "--all", "--proxy-port", port], "")
        .ok();

    // 9c. `--json -- COMMAND`: a command that fails keeps stdout to itself
    // (no JSON line after its output) and its exit code; a command that
    // cannot run is an error line, and its sandbox is stopped. Neither
    // shows the package.
    let out = issuer
        .run(
            &[
                "sandbox",
                "start",
                "--label",
                "chat-10",
                "--profile",
                "railway",
                "--proxy-port",
                port,
                "--json",
                "--",
                "sh",
                "-c",
                "echo out; exit 3",
            ],
            "",
        )
        .err();
    never_the_package(&out);
    assert_eq!(out.code, 3, "{}", out.stderr);
    assert_eq!(out.stdout, "out\n");
    issuer
        .run(&["sandbox", "stop", "--all", "--proxy-port", port], "")
        .ok();
    let missing = work.path().join("no-such-program");
    let out = issuer
        .run(
            &[
                "sandbox",
                "start",
                "--label",
                "chat-11",
                "--profile",
                "railway",
                "--proxy-port",
                port,
                "--json",
                "--",
                missing.to_str().expect("path"),
            ],
            "",
        )
        .err();
    assert_eq!(out.code, 1, "{}", out.stderr);
    let error = json_error(&out);
    assert_eq!(error["error"], Value::Null, "{error}");
    assert!(
        error["message"]
            .as_str()
            .expect("message")
            .contains("was stopped"),
        "{error}"
    );
    assert!(live(&issuer, port).is_empty());

    // 9a. The Klav server down: the start fails before the proxy is
    // asked, so nothing may have started and the CLI does not say so.
    server.stop();
    let (out, error) = fails_alike(
        &issuer,
        &[
            "sandbox",
            "start",
            "--label",
            "chat-x",
            "--profile",
            "railway",
            "--proxy-port",
            port,
            "--package-file",
            work.path().join("p9").to_str().expect("path"),
        ],
    );
    assert_eq!(out.code, 1, "{}", out.stderr);
    assert!(!out.stderr.contains("may have started"), "{}", out.stderr);
    assert_eq!(error["error"], Value::Null, "{error}");
    let out = issuer
        .run(
            &[
                "sandbox",
                "start",
                "--label",
                "chat-x",
                "--profile",
                "railway",
                "--proxy-port",
                port,
                "--",
                "true",
            ],
            "",
        )
        .err();
    assert_eq!(out.code, 1, "{}", out.stderr);
    assert!(!out.stderr.contains("may have started"), "{}", out.stderr);
    server.restart();

    // 10. The issuer removed: its own grant names no proxy any more.
    person
        .unlocked(&["proxy", "issuer", "remove", "t3-code"], "")
        .ok();
    let (out, error) = fails_alike(
        &issuer,
        &[
            "sandbox",
            "start",
            "--label",
            "chat-9",
            "--profile",
            "railway",
            "--proxy-port",
            port,
            "--",
            "true",
        ],
    );
    assert_eq!(out.code, 5, "{}", out.stderr);
    assert_eq!(error["error"], "klav_no_proxy", "{error}");
    assert!(
        out.stderr
            .contains("stopped letting this agent start sandboxes"),
        "{}",
        out.stderr
    );
    assert!(
        out.stderr.contains("klav proxy issuer add <agent>"),
        "{}",
        out.stderr
    );
    drop(runtime);
}

/// The person's side (ADR 0036 E6.2), through `klavd` and without it: the
/// list of the account's proxy's sandboxes from the verified log, the
/// `klav proxy status` line, and the revocation by the start of an ID or
/// `--all`, with `--wait` until the real proxy logs the end. Never the
/// package; a failure under `--json` is one line.
#[test]
fn the_person_lists_and_revokes_the_proxys_sandboxes() {
    let mut server = ServerProcess::start(900);
    let root = tempfile::tempdir().expect("tempdir");
    let Setup {
        runtime,
        port,
        person,
        issuer,
        _stop,
        ..
    } = person_proxy_and_issuer(root.path(), &server);
    let list = |args: &[&str]| -> Value {
        let mut all = vec!["proxy", "sandboxes", "--json"];
        all.extend_from_slice(args);
        let out = person.run(&all, "").ok();
        never_the_package(&out);
        serde_json::from_str(&out.stdout).expect("list json")
    };

    // None yet: the account's proxy, and no rows.
    let empty = list(&[]);
    assert_eq!(empty["proxy"]["name"], "klav-proxy", "{empty}");
    let proxy_id = empty["proxy"]["agent_id"]
        .as_str()
        .expect("proxy id")
        .to_owned();
    assert_eq!(empty["sandboxes"], serde_json::json!([]), "{empty}");

    // Two sandboxes the issuer starts, their packages in files nobody reads.
    let work = tempfile::tempdir().expect("work");
    let mut ids = Vec::new();
    for label in ["chat-1", "chat-2"] {
        let pkg = work.path().join(label);
        let out = issuer
            .run(
                &[
                    "sandbox",
                    "start",
                    "--label",
                    label,
                    "--profile",
                    "railway",
                    "--proxy-port",
                    &port,
                    "--package-file",
                    pkg.to_str().expect("path"),
                    "--json",
                ],
                "",
            )
            .ok();
        let started: Value = serde_json::from_str(&out.stdout).expect("start json");
        ids.push(started["sandbox_id"].as_str().expect("id").to_owned());
    }
    let both = list(&[]);
    let rows = both["sandboxes"].as_array().expect("rows");
    let got: Vec<(&str, &str, &str, &str, &str)> = rows
        .iter()
        .map(|r| {
            (
                r["sandbox_id"].as_str().unwrap_or(""),
                r["label"].as_str().unwrap_or(""),
                r["status"].as_str().unwrap_or(""),
                r["issuer_name"].as_str().unwrap_or(""),
                r["proxy_id"].as_str().unwrap_or(""),
            )
        })
        .collect();
    assert_eq!(
        got,
        [
            (
                ids[0].as_str(),
                "chat-1",
                "waiting",
                "t3-code",
                proxy_id.as_str()
            ),
            (
                ids[1].as_str(),
                "chat-2",
                "waiting",
                "t3-code",
                proxy_id.as_str()
            ),
        ],
        "{both}"
    );

    // The table, and `klav proxy status`'s line.
    let table = person.run(&["proxy", "sandboxes"], "").ok();
    never_the_package(&table);
    for want in [
        "Proxy: \"klav-proxy\"",
        "LABEL (per the issuer)",
        "\"chat-1\"",
        "waiting for claim",
        &ids[0][..8],
        "Verified up to event #",
    ] {
        assert!(table.stdout.contains(want), "{want}: {}", table.stdout);
    }
    let status = person.run(&["proxy", "status"], "").ok();
    assert!(
        status
            .stdout
            .contains("Sandboxes: 0 active, 2 waiting for claim (`klav proxy sandboxes`)"),
        "{}",
        status.stdout
    );

    // Refused before anything is signed: not an ID, too short a start, a
    // start nothing has. A usage error: exit 2 and `error` null.
    for bad in ["nope", "abcd", "ffffffff-ff"] {
        let (out, error) = fails_alike(&person, &["proxy", "sandboxes", "revoke", bad]);
        assert_eq!(out.code, 2, "{bad}: {}", out.stderr);
        assert_eq!(error["error"], Value::Null, "{error}");
    }
    // Too short a start is refused even when it names one sandbox: the
    // list shows 8 characters, and fewer could name another one later.
    let (out, _) = fails_alike(&person, &["proxy", "sandboxes", "revoke", &ids[0][..4]]);
    assert_eq!(out.code, 2, "{}", out.stderr);
    let both_ways = person.run(&["proxy", "sandboxes", "revoke", &ids[0], "--all"], "");
    assert_eq!(both_ways.code, 2, "{}", both_ways.stderr);

    // One, by the start of its ID as the table shows it, waiting until the
    // proxy logs its end. The revocation's line comes before the wait,
    // without `not_ended`; the last one has it.
    let out = person
        .run(
            &[
                "proxy",
                "sandboxes",
                "revoke",
                &ids[0][..8],
                "--wait",
                "--json",
            ],
            "",
        )
        .ok();
    let lines: Vec<Value> = out
        .stdout
        .lines()
        .map(|l| serde_json::from_str(l).expect("revoke json"))
        .collect();
    assert_eq!(lines.len(), 2, "{}", out.stdout);
    assert!(lines[0].get("not_ended").is_none(), "{}", out.stdout);
    assert_eq!(lines[0]["sandbox_ids"], serde_json::json!([ids[0]]));
    let revoked = lines[1].clone();
    assert_eq!(revoked["outcome"], "revoked", "{revoked}");
    assert_eq!(revoked["scope"], ids[0].as_str(), "{revoked}");
    assert_eq!(
        revoked["sandbox_ids"],
        serde_json::json!([ids[0]]),
        "{revoked}"
    );
    assert_eq!(revoked["not_ended"], serde_json::json!([]), "{revoked}");

    // All of them: the other one too. Without `--wait`, no `not_ended`.
    let out = person
        .run(&["proxy", "sandboxes", "revoke", "--all", "--json"], "")
        .ok();
    let all: Value = serde_json::from_str(&out.stdout).expect("revoke json");
    assert_eq!(
        (&all["outcome"], &all["scope"]),
        (&Value::from("revoked"), &Value::from("all")),
        "{all}"
    );
    assert!(
        all["sandbox_ids"]
            .as_array()
            .expect("ids")
            .contains(&Value::from(ids[1].as_str())),
        "{all}"
    );
    assert!(all.get("not_ended").is_none(), "{all}");

    // The ended one leaves the default list and shows with `--ended`, with
    // the proxy's `person` end; also without `klavd` (`--no-daemon`).
    let open = list(&[]);
    assert!(
        open["sandboxes"]
            .as_array()
            .expect("rows")
            .iter()
            .all(|r| r["sandbox_id"] != ids[0].as_str() && r["status"] != "ended"),
        "{open}"
    );
    let out = person
        .unlocked(
            &["--no-daemon", "proxy", "sandboxes", "--ended", "--json"],
            "",
        )
        .ok();
    let ended: Value = serde_json::from_str(&out.stdout).expect("list json");
    let first = ended["sandboxes"]
        .as_array()
        .expect("rows")
        .iter()
        .find(|r| r["sandbox_id"] == ids[0].as_str())
        .expect("the revoked sandbox")
        .clone();
    assert_eq!(
        (&first["status"], &first["end_reason"]),
        (&Value::from("ended"), &Value::from("person")),
        "{ended}"
    );
    // Its start names only an ended sandbox: refused before anything is
    // signed, exit 1.
    let again = person.run(&["proxy", "sandboxes", "revoke", &ids[0][..8]], "");
    assert_eq!(again.code, 1, "{}", again.stderr);
    assert!(again.stderr.contains("already ended"), "{}", again.stderr);

    // A third one, revoked by its whole ID without `klavd`: the direct
    // path signs the same revocation.
    let pkg = work.path().join("chat-3");
    let out = issuer
        .run(
            &[
                "sandbox",
                "start",
                "--label",
                "chat-3",
                "--profile",
                "railway",
                "--proxy-port",
                &port,
                "--package-file",
                pkg.to_str().expect("path"),
                "--json",
            ],
            "",
        )
        .ok();
    let started: Value = serde_json::from_str(&out.stdout).expect("start json");
    let third = started["sandbox_id"].as_str().expect("id").to_owned();
    let out = person
        .unlocked(
            &[
                "--no-daemon",
                "proxy",
                "sandboxes",
                "revoke",
                &third,
                "--json",
            ],
            "",
        )
        .ok();
    let one: Value = serde_json::from_str(&out.stdout).expect("revoke json");
    assert_eq!(
        (&one["outcome"], &one["scope"], &one["sandbox_ids"]),
        (
            &Value::from("revoked"),
            &Value::from(third.as_str()),
            &serde_json::json!([third])
        ),
        "{one}"
    );
    let all_rows = list(&["--ended"]);
    let row = all_rows["sandboxes"]
        .as_array()
        .expect("rows")
        .iter()
        .find(|r| r["sandbox_id"] == third.as_str())
        .expect("the third sandbox")
        .clone();
    assert!(
        row["status"] == "revoking" || row["status"] == "ended",
        "{row}"
    );

    // A log that fails to verify does not keep the person from revoking by
    // the whole ID: the operator puts back an older copy of the server, so
    // the list exits 3, and the revocation of a sandbox that copy has
    // still exits 0. The issuer may hold 2 live sandboxes: the third one's
    // end comes first.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
    while list(&["--ended"])["sandboxes"]
        .as_array()
        .expect("rows")
        .iter()
        .any(|r| r["sandbox_id"] == third.as_str() && r["status"] != "ended")
    {
        assert!(
            std::time::Instant::now() < deadline,
            "the third never ended"
        );
        std::thread::sleep(std::time::Duration::from_secs(2));
    }
    let start = |label: &str| -> String {
        let pkg = work.path().join(label);
        let out = issuer
            .run(
                &[
                    "sandbox",
                    "start",
                    "--label",
                    label,
                    "--profile",
                    "railway",
                    "--proxy-port",
                    &port,
                    "--package-file",
                    pkg.to_str().expect("path"),
                    "--json",
                ],
                "",
            )
            .ok();
        let started: Value = serde_json::from_str(&out.stdout).expect("start json");
        started["sandbox_id"].as_str().expect("id").to_owned()
    };
    let fourth = start("chat-4");
    let fifth = start("chat-5");
    server.snapshot("before-stop");
    // After the snapshot the issuer stops the fifth, and the person's list
    // verifies the chain with its end.
    issuer
        .run(&["sandbox", "stop", &fifth, "--proxy-port", &port], "")
        .ok();
    let stopped = list(&["--ended"]);
    assert!(
        stopped["sandboxes"]
            .as_array()
            .expect("rows")
            .iter()
            .any(|r| r["sandbox_id"] == fifth.as_str() && r["status"] == "ended"),
        "{stopped}"
    );
    server.restore("before-stop");
    let tampered = person.run(&["proxy", "sandboxes"], "");
    assert_eq!(tampered.code, 3, "{}", tampered.stderr);
    // `klav proxy status` prints everything, then exits 3.
    let status = person.run(&["proxy", "status"], "");
    assert_eq!(status.code, 3, "{}", status.stderr);
    assert!(status.stdout.contains("klav-proxy"), "{}", status.stdout);
    assert!(!status.stdout.contains("Sandboxes:"), "{}", status.stdout);
    // The start of an ID needs the list that does not verify: exit 3, and
    // the error points to the whole ID, which revokes without it (below).
    let short: String = fourth.chars().take(8).collect();
    let out = person.run(&["proxy", "sandboxes", "revoke", &short], "");
    assert_eq!(out.code, 3, "{}", out.stderr);
    assert!(
        out.stderr.contains(
            "\nNext: give the whole ID to revoke without the list (`klav proxy sandboxes revoke <id>`)"
        ),
        "{}",
        out.stderr
    );
    let out = person.run(&["proxy", "sandboxes", "revoke", &fourth, "--json"], "");
    assert_eq!(out.code, 0, "{}", out.stderr);
    let one: Value = serde_json::from_str(&out.stdout).expect("revoke json");
    assert_eq!(
        (&one["outcome"], &one["sandbox_ids"]),
        (&Value::from("revoked"), &serde_json::json!([fourth])),
        "{one}"
    );
    // With `--wait`, the revocation is said first; the log that does not
    // verify while waiting exits 3, not 1. The restored server still has
    // the fifth live.
    let out = person.run(
        &["proxy", "sandboxes", "revoke", &fifth, "--wait", "--json"],
        "",
    );
    assert_eq!(out.code, 3, "{}", out.stderr);
    let first: Value =
        serde_json::from_str(out.stdout.lines().next().expect("a line")).expect("revoke json");
    assert_eq!(
        (&first["outcome"], &first["sandbox_ids"]),
        (&Value::from("revoked"), &serde_json::json!([fifth])),
        "{}",
        out.stdout
    );
    drop(runtime);
}

/// `sandbox_revoke` on the socket of an unlocked `klavd`: a `scope` that is
/// neither `all` nor a sandbox ID, in any spelling, and a field next to
/// `scope`, each come back `bad_request` (ADR 0036, the 5a questions), and
/// nothing reaches the server: the proxy named here does not exist.
#[test]
fn a_sandbox_revoke_with_a_bad_scope_is_a_bad_request_on_the_socket() {
    use std::io::{BufRead, BufReader, Write};
    let server = ServerProcess::start(900);
    let root = tempfile::tempdir().expect("tempdir");
    let person = Device::new(root.path(), "person");
    person.signup(&server, "ana@example.com");
    let _stop = StopDaemon(Device::new(root.path(), "person"));
    person.unlocked(&["unlock", "--idle-lock", "10m"], "").ok();
    let stream =
        std::os::unix::net::UnixStream::connect(Home::at(person.home.clone()).socket_path())
            .expect("klavd");
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .expect("timeout");
    let mut reader = BufReader::new(stream.try_clone().expect("clone"));
    let mut writer = stream;
    let proxy = "6f1c2b8e-4d3a-4f5b-9c7d-1e2f3a4b5c6d";
    // The scopes parse as a line and klavd refuses them by name; the extra
    // field makes the line itself unreadable.
    let scope = "scope must be all or a sandbox ID";
    let requests = [
        (
            serde_json::json!({"op": "sandbox_revoke", "proxy": proxy, "scope": ""}),
            scope,
        ),
        (
            serde_json::json!({"op": "sandbox_revoke", "proxy": proxy, "scope": "ALL"}),
            scope,
        ),
        (
            serde_json::json!({"op": "sandbox_revoke", "proxy": proxy, "scope": " all"}),
            scope,
        ),
        (
            serde_json::json!({"op": "sandbox_revoke", "proxy": proxy, "scope": "all", "sandbox": proxy}),
            "malformed request",
        ),
    ];
    for (id, (request, message)) in requests.into_iter().enumerate() {
        let mut line =
            serde_json::to_vec(&serde_json::json!({"v": 1, "id": id, "request": request}))
                .expect("json");
        line.push(b'\n');
        writer.write_all(&line).expect("write");
        let mut answer = String::new();
        reader.read_line(&mut answer).expect("answer");
        let answer: Value = serde_json::from_str(&answer).expect("answer json");
        assert_eq!(
            (&answer["error"]["code"], &answer["error"]["message"]),
            (&Value::from("bad_request"), &Value::from(message)),
            "{request}: {answer}"
        );
    }
    // The same socket still serves a request it can read.
    writer
        .write_all(b"{\"v\":1,\"id\":9,\"request\":{\"op\":\"status\"}}\n")
        .expect("write");
    let mut answer = String::new();
    reader.read_line(&mut answer).expect("answer");
    let answer: Value = serde_json::from_str(&answer).expect("answer json");
    assert!(answer.get("ok").is_some(), "{answer}");
}

/// The proxy on this machine (ADR 0036 E3.5, layer 11): with `klavd`
/// locked, `klav proxy local status` lists the live sandboxes and
/// `klav proxy local revoke` ends one by its first 8 characters, then all,
/// through the proxy's socket; the issuer's list is empty after, and the
/// person's verified log has the two `person_local` ends.
#[test]
fn the_person_revokes_through_the_local_socket_while_locked() {
    let server = ServerProcess::start(900);
    let root = tempfile::tempdir().expect("tempdir");
    let Setup {
        runtime: _runtime,
        port,
        person,
        issuer,
        _stop,
        ..
    } = person_proxy_and_issuer(root.path(), &server);
    let work = tempfile::tempdir().expect("work");
    let mut ids = Vec::new();
    for label in ["chat-1", "chat-2"] {
        let pkg = work.path().join(label);
        let out = issuer
            .run(
                &[
                    "sandbox",
                    "start",
                    "--label",
                    label,
                    "--profile",
                    "railway",
                    "--proxy-port",
                    &port,
                    "--package-file",
                    pkg.to_str().expect("path"),
                    "--json",
                ],
                "",
            )
            .ok();
        let started: Value = serde_json::from_str(&out.stdout).expect("start json");
        ids.push(started["sandbox_id"].as_str().expect("id").to_owned());
    }
    person.run(&["lock"], "").ok();

    let out = person.run(&["proxy", "local", "status", "--json"], "").ok();
    never_the_package(&out);
    let listed: Value = serde_json::from_str(&out.stdout).expect("status json");
    assert_eq!(listed["port"].to_string(), port, "{listed}");
    let mut got: Vec<&str> = listed["sandboxes"]
        .as_array()
        .expect("rows")
        .iter()
        .map(|r| r["sandbox_id"].as_str().unwrap_or(""))
        .collect();
    got.sort_unstable();
    let mut want: Vec<&str> = ids.iter().map(String::as_str).collect();
    want.sort_unstable();
    assert_eq!(got, want, "{listed}");
    let table = person.run(&["proxy", "local", "status"], "").ok();
    assert!(
        table.stdout.contains("\"chat-1\" (as its issuer says)"),
        "{}",
        table.stdout
    );

    let out = person
        .run(&["proxy", "local", "revoke", &ids[0][..8], "--json"], "")
        .ok();
    let revoked: Value = serde_json::from_str(&out.stdout).expect("revoke json");
    assert_eq!(revoked["revoked"], serde_json::json!([ids[0]]), "{revoked}");
    assert_eq!(revoked["logged"], true, "{revoked}");
    let out = person.run(&["proxy", "local", "revoke", "--all"], "").ok();
    assert!(
        out.stdout.starts_with("Revoked 1 sandbox on this machine"),
        "{}",
        out.stdout
    );
    let missing = person.run(&["proxy", "local", "revoke", &ids[0]], "").err();
    assert!(
        missing.stderr.contains("no live sandbox with that ID"),
        "{}",
        missing.stderr
    );
    assert!(live(&issuer, &port).is_empty());

    let log = person.unlocked(&["log", "--json"], "").ok();
    assert_eq!(
        log.stdout.matches("\"person_local\"").count(),
        2,
        "{}",
        log.stdout
    );
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// `klav <args>` from `dev` with `KLAV_HOSTED_PROXY_CHANNEL_ADDR` set to
/// `channel` (or unset).
fn run_with_channel(dev: &Device, channel: Option<&str>, args: &[&str]) -> common::Run {
    let mut cmd = dev.command();
    match channel {
        Some(addr) => cmd.env("KLAV_HOSTED_PROXY_CHANNEL_ADDR", addr),
        None => cmd.env_remove("KLAV_HOSTED_PROXY_CHANNEL_ADDR"),
    };
    let out = cmd.args(args).output().expect("run klav");
    common::Run {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8(out.stdout).expect("utf-8"),
        stderr: String::from_utf8(out.stderr).expect("utf-8"),
    }
}

/// A TCP relay to `to` on `runtime` that records what the client sends.
fn tap(
    runtime: &tokio::runtime::Runtime,
    to: std::net::SocketAddr,
) -> (String, std::sync::Arc<std::sync::Mutex<Vec<u8>>>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = runtime
        .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
        .expect("bind");
    let addr = listener.local_addr().expect("addr").to_string();
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let s = std::sync::Arc::clone(&seen);
    runtime.spawn(async move {
        while let Ok((inbound, _)) = listener.accept().await {
            let s = std::sync::Arc::clone(&s);
            tokio::spawn(async move {
                let Ok(outbound) = tokio::net::TcpStream::connect(to).await else {
                    return;
                };
                let (mut in_r, mut in_w) = tokio::io::split(inbound);
                let (mut out_r, mut out_w) = tokio::io::split(outbound);
                let up = async {
                    let mut buf = [0u8; 4096];
                    while let Ok(n) = in_r.read(&mut buf).await {
                        if n == 0 {
                            break;
                        }
                        s.lock().expect("lock").extend_from_slice(&buf[..n]);
                        if out_w.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                    let _ = out_w.shutdown().await;
                };
                let down = async {
                    let _ = tokio::io::copy(&mut out_r, &mut in_w).await;
                    let _ = in_w.shutdown().await;
                };
                tokio::join!(up, down);
            });
        }
    });
    (addr, seen)
}

/// ADR 0051 §6.4: `klav sandbox start | ls | stop` take Klav Cloud's
/// pinned channel only when the issuer's grant names the channel of its
/// own proxy agent (`tls://a<agent_id hex>.<domain>:<port>`), and the
/// loopback listener (`--proxy-port`) for anything else, as before:
/// - with the hosted URL, `ls` dials the channel with the account's name
///   as SNI (a tap reads it in the ClientHello) at
///   `KLAV_HOSTED_PROXY_CHANNEL_ADDR`, pinned to the grant's key, and never
///   `--proxy-port`; a self-hosted proxy's channel serves no issuer API,
///   so it refuses, and `start` there starts nothing;
/// - without the variable, the channel's own name is dialed (it doesn't
///   resolve here) and the error says Klav Cloud's channel didn't answer;
/// - an issuer whose URL names another agent's channel keeps the loopback
///   listener even with the variable set, and starts, lists and stops
///   there.
#[test]
fn the_issuer_takes_klav_clouds_channel_only_when_its_grant_names_it() {
    let server = ServerProcess::start(900);
    let root = tempfile::tempdir().expect("tempdir");
    let hosted = |proxy: klav_core::ids::AgentId| {
        format!("tls://a{}.proxy.klav.test:443", hex(proxy.as_bytes()))
    };
    // `local-agent`'s URL names another agent's channel.
    let other = format!("tls://a{}.proxy.klav.test:443", "ab".repeat(16));
    let setup = person_proxy_and_issuer_at(
        root.path(),
        &server,
        hosted,
        true,
        Some(("local-agent", &other)),
    );
    let channel = setup.channel.expect("channel");
    let proxy_id = klav_sdk::Agent::load(&Home::at(root.path().join("klav-proxy")), "klav-proxy")
        .expect("proxy agent")
        .id();
    let name = format!("a{}.proxy.klav.test", hex(proxy_id.as_bytes()));
    let (tapped, seen) = tap(&setup.runtime, channel);

    // `--proxy-port 9`: nothing listens there, so a local route would say
    // the proxy is unreachable. The hosted route reaches the channel, which
    // (self-hosted) has no issuer API: its fallback refuses a key bound to
    // no sandbox, which the CLI reports as a channel without the issuer
    // API, not as nothing listening.
    let out = run_with_channel(
        &setup.issuer,
        Some(&tapped),
        &["sandbox", "ls", "--proxy-port", "9", "--json"],
    );
    assert_ne!(out.code, 0, "{}", out.stderr);
    let error = json_error(&out);
    assert_eq!(error["error"], "klav_proxy_unreachable", "{error}");
    assert!(
        error["message"]
            .as_str()
            .unwrap_or_default()
            .contains("does not serve the sandbox issuer API"),
        "{error}"
    );
    let wire = seen.lock().expect("lock").clone();
    assert!(
        wire.windows(name.len()).any(|w| w == name.as_bytes()),
        "the ClientHello names the account's channel"
    );
    assert!(
        !wire.windows(16).any(|w| w == b"/_klav/sandboxes"),
        "the request is inside TLS"
    );
    let out = run_with_channel(
        &setup.issuer,
        Some(&tapped),
        &[
            "sandbox",
            "start",
            "--label",
            "chat-1",
            "--profile",
            "railway",
            "--proxy-port",
            "9",
            "--json",
            "--",
            "true",
        ],
    );
    assert_ne!(out.code, 0, "{}", out.stderr);
    never_the_package(&out);
    // The person's view (the server's log of the proxy): nothing started.
    let out = setup.person.run(&["proxy", "sandboxes", "--json"], "").ok();
    let v: Value = serde_json::from_str(&out.stdout).expect("list json");
    assert_eq!(
        v["sandboxes"],
        serde_json::json!([]),
        "nothing started: {v}"
    );

    // No relay: the channel's own name is dialed, and doesn't resolve.
    let out = run_with_channel(&setup.issuer, None, &["sandbox", "ls", "--json"]);
    let error = json_error(&out);
    assert_eq!(error["error"], "klav_proxy_unreachable", "{error}");
    assert!(
        error["next"]
            .as_str()
            .unwrap_or_default()
            .contains("Klav Cloud"),
        "{error}"
    );

    // Another agent's channel in the grant: the loopback listener, as before.
    let local = Device::new(root.path(), "local-agent");
    let file = root.path().join("package");
    let out = run_with_channel(
        &local,
        Some(&tapped),
        &[
            "sandbox",
            "start",
            "--label",
            "chat-2",
            "--profile",
            "railway",
            "--proxy-port",
            &setup.port,
            "--package-file",
            file.to_str().expect("path"),
        ],
    );
    assert_eq!(out.code, 0, "{}", out.stderr);
    never_the_package(&out);
    let out = run_with_channel(
        &local,
        Some(&tapped),
        &["sandbox", "ls", "--proxy-port", &setup.port, "--json"],
    );
    assert_eq!(out.code, 0, "{}", out.stderr);
    let v: Value = serde_json::from_str(&out.stdout).expect("ls json");
    assert_eq!(v["sandboxes"].as_array().expect("sandboxes").len(), 1);
    let out = run_with_channel(
        &local,
        Some(&tapped),
        &[
            "sandbox",
            "stop",
            "--all",
            "--proxy-port",
            &setup.port,
            "--json",
        ],
    );
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert!(live(&local, &setup.port).is_empty());
}
