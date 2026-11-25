//! `klav` started as `klav-proxy` (ADR 0036 layer 11): the Mac app's
//! LaunchAgent runs the bundle's `klav` with `argv[0]` `klav-proxy serve
//! --if-registered`, so the binary must be the proxy under that name, and
//! the LaunchAgent must exit 0, not fail and be started again every 30 s,
//! when there is nothing it could serve.

mod common;

use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Output};

use common::{Device, ServerProcess};

/// The `klav` this build made, started as `klav-proxy`, with no variable
/// that the proxy refuses or that changes its memory settings.
fn as_proxy(home: &Path, args: &[&str]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_klav"));
    cmd.arg0("klav-proxy");
    for var in [
        "KLAV_AGENT_KEY",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "KLAV_PROXY_REQUIRE_MEMORY_LOCK",
        "KLAV_PROXY_MEMORY_LOCK",
        "KLAV_SERVER",
    ] {
        cmd.env_remove(var);
    }
    cmd.env("KLAV_NO_DEFAULT_SERVER", "1")
        .arg("--home")
        .arg(home)
        .args(args)
        .output()
        .expect("run klav as klav-proxy")
}

#[test]
fn klav_started_as_klav_proxy_is_the_proxy() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out = as_proxy(dir.path(), &["--version"]);
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.starts_with("klav-proxy "), "{text}");
    // The same build identity as `klav --version`: the binary holds one.
    let klav = Command::new(env!("CARGO_BIN_EXE_klav"))
        .arg("--version")
        .output()
        .expect("klav --version");
    assert_eq!(
        text.strip_prefix("klav-proxy "),
        String::from_utf8_lossy(&klav.stdout).strip_prefix("klav ")
    );

    let out = as_proxy(dir.path(), &["serve", "--help"]);
    let help = String::from_utf8_lossy(&out.stdout);
    assert!(help.contains("--if-registered"), "{help}");
    assert!(help.contains("--control-socket"), "{help}");

    // Nothing registered: exits 0 and leaves no socket.
    let out = as_proxy(dir.path(), &["serve", "--if-registered", "--port", "0"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!dir.path().join("agents/klav-proxy.sock").exists());
}

#[test]
fn the_launch_agent_exits_zero_while_the_proxy_waits_for_approval() {
    let server = ServerProcess::start(900);
    let root = tempfile::tempdir().expect("tempdir");
    let person = Device::new(root.path(), "person");
    person.signup(&server, "ana@example.com");
    let machine = Device::new(root.path(), "proxy");
    machine
        .run(
            &[
                "agent",
                "register",
                "--name",
                "klav-proxy",
                "--server",
                &server.url,
                "--email",
                "ana@example.com",
                "--key-store",
                "file",
            ],
            "",
        )
        .ok();

    // Pending: not an error launchd would start again.
    let out = as_proxy(&machine.home, &["serve", "--if-registered", "--port", "0"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    assert!(stderr.contains("not approved"), "{stderr}");
    assert!(!machine.home.join("agents/klav-proxy.sock").exists());

    // Without --if-registered, the same proxy still fails as before.
    let out = as_proxy(&machine.home, &["serve", "--port", "0"]);
    assert!(!out.status.success());
}
