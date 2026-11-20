//! `klav-native-host` as the browser runs it: length-prefixed JSON on
//! stdin/stdout, the caller's origin as an argument. It starts `klavd` on
//! demand, relays the extension's operations, refuses the others and never
//! talks to an extension it does not know.

use std::io::{Read, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::{Duration, Instant};

use klav_client::Home;
use klav_daemon::native::DEV_CHROMIUM_ID;
use serde_json::{Value, json};

fn host(home: &Path, caller: &[&str]) -> Child {
    host_allowing(home, &[], caller)
}

/// The host with extra allowed extensions (`--allow`, as the wrapper of
/// `klav extension install-host` passes them).
fn host_allowing(home: &Path, allow: &[&str], caller: &[&str]) -> Child {
    // klavd is found next to the host binary (both are in target/…).
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_klav-native-host"));
    cmd.arg("--home").arg(home);
    for id in allow {
        cmd.arg("--allow").arg(id);
    }
    cmd.args(caller)
        .env("KLAV_NO_TOUCH_ID", "1")
        .env_remove("KLAV_HOME")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn klav-native-host")
}

fn send(stdin: &mut ChildStdin, message: &Value) {
    let body = serde_json::to_vec(message).expect("io");
    stdin
        .write_all(&u32::try_from(body.len()).expect("io").to_ne_bytes())
        .expect("io");
    stdin.write_all(&body).expect("io");
    stdin.flush().expect("io");
}

fn receive(stdout: &mut ChildStdout) -> Value {
    let mut len = [0u8; 4];
    stdout.read_exact(&mut len).expect("a message");
    let mut body = vec![0u8; u32::from_ne_bytes(len) as usize];
    stdout.read_exact(&mut body).expect("io");
    serde_json::from_slice(&body).expect("io")
}

fn wait_exit(child: &mut Child) -> std::process::ExitStatus {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().expect("io") {
            return status;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    let _ = child.kill();
    child.wait().expect("io")
}

#[test]
fn the_host_bridges_the_extension_to_klavd() {
    let dir = tempfile::tempdir().unwrap();
    let home_dir = dir.path().join("h");
    let origin = format!("chrome-extension://{DEV_CHROMIUM_ID}/");
    // The development build, allowed as `install-host --dev` does.
    let mut child = host_allowing(&home_dir, &[&origin], &[&origin]);
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = child.stdout.take().unwrap();

    // klavd was not running: the host starts it, and it answers.
    send(
        &mut stdin,
        &json!({ "v": 1, "id": 1, "request": { "op": "status" } }),
    );
    let status = receive(&mut stdout);
    assert_eq!(status["id"], 1);
    assert_eq!(status["ok"]["protocol"], 1);
    assert_eq!(status["ok"]["logged_in"], false);
    assert!(Home::at(&home_dir).socket_path().exists());

    // Operations the extension may not use are refused by the host.
    send(
        &mut stdin,
        &json!({ "v": 1, "id": 2, "request": { "op": "resolve", "references": ["klav://a/b/c/d"] } }),
    );
    let refused = receive(&mut stdout);
    assert_eq!(refused["id"], 2);
    assert_eq!(refused["error"]["code"], "denied");
    send(
        &mut stdin,
        &json!({ "v": 1, "id": 3, "request": { "op": "shutdown" } }),
    );
    assert_eq!(receive(&mut stdout)["error"]["code"], "denied");

    // Allowed operations reach klavd (locked: no account here).
    send(
        &mut stdin,
        &json!({ "v": 1, "id": 4, "request": { "op": "suggest", "url": "https://github.com/login" } }),
    );
    let locked = receive(&mut stdout);
    assert_eq!(locked["id"], 4);
    assert_eq!(locked["error"]["code"], "locked");

    // A malformed message gets an error and the bridge keeps going.
    send(
        &mut stdin,
        &json!({ "v": 1, "id": 5, "request": { "op": "nope" } }),
    );
    assert_eq!(receive(&mut stdout)["error"]["code"], "bad_request");
    send(
        &mut stdin,
        &json!({ "v": 1, "id": 6, "request": { "op": "status" } }),
    );
    assert_eq!(receive(&mut stdout)["id"], 6);

    // The browser closes the port: the host exits, klavd keeps running.
    drop(stdin);
    assert!(wait_exit(&mut child).success());
    let mut again = host_allowing(&home_dir, &[&origin], &[&origin]);
    let mut stdin = again.stdin.take().unwrap();
    let mut stdout = again.stdout.take().unwrap();
    send(
        &mut stdin,
        &json!({ "v": 1, "id": 7, "request": { "op": "status" } }),
    );
    let pid = status["ok"]["pid"].clone();
    assert_eq!(receive(&mut stdout)["ok"]["pid"], pid);
    send(
        &mut stdin,
        &json!({ "v": 1, "id": 8, "request": { "op": "lock" } }),
    );
    assert_eq!(receive(&mut stdout)["id"], 8);
    drop(stdin);
    wait_exit(&mut again);

    // Stop klavd through its own socket (the host cannot).
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let mut client = klav_daemon::client::DaemonClient::connect(&Home::at(&home_dir))
            .await
            .expect("klavd running");
        let _: Result<(Value, _), _> = client.call(klav_daemon::protocol::Request::Shutdown).await;
    });
}

/// An extension the host does not allow gets one answer, the command that
/// allows it, and nothing from `klavd`.
#[test]
fn unknown_extensions_only_get_the_command() {
    let dir = tempfile::tempdir().unwrap();
    let home_dir = dir.path().join("h");
    let dev = format!("chrome-extension://{DEV_CHROMIUM_ID}/");
    for (caller, command) in [
        (
            vec!["chrome-extension://abcdefghijklmnopabcdefghijklmnop/"],
            Some("klav extension install-host --extension-id abcdefghijklmnopabcdefghijklmnop"),
        ),
        // The development build's key is public: not without `--dev`.
        (
            vec![dev.as_str()],
            Some("klav extension install-host --dev"),
        ),
        (
            vec!["/tmp/manifest.json", "someone@example.com"],
            Some("klav extension install-host --extension-id someone@example.com"),
        ),
        // Not a browser: it exits before reading.
        (vec![], None),
    ] {
        let mut child = host(&home_dir, &caller);
        let mut stdin = child.stdin.take().unwrap();
        // A broken pipe here is fine when the host does not read.
        let body = serde_json::to_vec(
            &json!({ "v": 1, "id": 7, "request": { "op": "unlock", "password": "MARKER-pass" } }),
        )
        .unwrap();
        let _ = stdin
            .write_all(&u32::try_from(body.len()).unwrap().to_ne_bytes())
            .and_then(|()| stdin.write_all(&body))
            .and_then(|()| stdin.flush());
        drop(stdin);
        let status = wait_exit(&mut child);
        assert!(!status.success(), "{caller:?}");
        let mut out = Vec::new();
        child.stdout.take().unwrap().read_to_end(&mut out).unwrap();
        let Some(command) = command else {
            assert!(out.is_empty(), "{caller:?}");
            continue;
        };
        assert!(!String::from_utf8_lossy(&out).contains("MARKER"));
        let len = u32::from_ne_bytes(out[..4].try_into().unwrap()) as usize;
        assert_eq!(out.len(), 4 + len, "one answer: {caller:?}");
        let answer: Value = serde_json::from_slice(&out[4..]).unwrap();
        assert_eq!(answer["id"], 7, "{answer}");
        assert!(answer.get("ok").is_none(), "{answer}");
        assert_eq!(answer["error"]["code"], "extension_not_allowed", "{answer}");
        let message = answer["error"]["message"].as_str().unwrap();
        assert!(message.contains(&format!("`{command}`")), "{message}");
        // stderr still says why, for the browser's log.
        let mut err = String::new();
        child
            .stderr
            .take()
            .unwrap()
            .read_to_string(&mut err)
            .unwrap();
        assert!(err.contains("is not allowed"), "{err}");
    }
    // It never started klavd for them.
    assert!(!Home::at(&home_dir).socket_path().exists());
    assert!(!home_dir.exists(), "nothing written in the home");
}

#[test]
fn firefox_and_extra_ids_are_allowed_when_listed() {
    let dir = tempfile::tempdir().unwrap();
    let home_dir = dir.path().join("h");
    let store = "abcdefghijklmnopabcdefghijklmnop";
    let mut child = Command::new(env!("CARGO_BIN_EXE_klav-native-host"))
        .arg("--home")
        .arg(&home_dir)
        .args(["--allow", store])
        .arg(format!("chrome-extension://{store}/"))
        .env("KLAV_NO_TOUCH_ID", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = child.stdout.take().unwrap();
    send(
        &mut stdin,
        &json!({ "v": 1, "id": 1, "request": { "op": "status" } }),
    );
    assert_eq!(receive(&mut stdout)["id"], 1);
    drop(stdin);
    wait_exit(&mut child);

    let mut firefox = host(&home_dir, &["/tmp/dev.klav.host.json", "klav@klav.dev"]);
    let mut stdin = firefox.stdin.take().unwrap();
    let mut stdout = firefox.stdout.take().unwrap();
    send(
        &mut stdin,
        &json!({ "v": 1, "id": 2, "request": { "op": "status" } }),
    );
    assert_eq!(receive(&mut stdout)["id"], 2);
    drop(stdin);
    wait_exit(&mut firefox);

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        if let Some(mut client) =
            klav_daemon::client::DaemonClient::connect(&Home::at(&home_dir)).await
        {
            let _: Result<(Value, _), _> =
                client.call(klav_daemon::protocol::Request::Shutdown).await;
        }
    });
}
