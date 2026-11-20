//! The binary: it never takes its key from the environment, and nothing
//! on its command line can make it listen anywhere but loopback.

use std::process::Command;

/// The variables the binary refuses to start with.
const REFUSED: [&str; 3] = ["KLAV_AGENT_KEY", "SSL_CERT_FILE", "SSL_CERT_DIR"];

/// The binary, without the memory variables (ADR 0044 §3.2), whatever
/// the machine sets: `tests/memory.rs` tests them.
fn proxy() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_klav-proxy"));
    cmd.env_remove("KLAV_PROXY_REQUIRE_MEMORY_LOCK")
        .env_remove("KLAV_PROXY_MEMORY_LOCK");
    cmd
}

/// The binary with none of [`REFUSED`] set, whatever the machine running
/// the tests sets (a CI image may set `SSL_CERT_FILE`), except `only`.
fn proxy_with(only: Option<(&str, &str)>) -> Command {
    let mut cmd = proxy();
    for var in REFUSED {
        cmd.env_remove(var);
    }
    if let Some((var, value)) = only {
        cmd.env(var, value);
    }
    cmd
}

const SUBCOMMANDS: [&[&str]; 3] = [
    &["serve"],
    &["status"],
    &[
        "init",
        "--email",
        "ana@example.com",
        "--server",
        "http://127.0.0.1:9",
    ],
];

#[test]
fn the_key_in_the_environment_is_refused_before_anything_else() {
    let dir = tempfile::tempdir().expect("tempdir");
    for args in SUBCOMMANDS {
        let out = proxy_with(Some(("KLAV_AGENT_KEY", "kag1_not-a-real-key")))
            .arg("--home")
            .arg(dir.path())
            .args(args)
            .output()
            .expect("run klav-proxy");
        assert!(!out.status.success(), "{args:?}");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("KLAV_AGENT_KEY is set"),
            "{args:?}: {stderr}"
        );
        assert!(
            !stderr.contains("not-a-real-key"),
            "the value is never echoed"
        );
    }
    // Nothing was registered or written.
    assert_eq!(std::fs::read_dir(dir.path()).expect("dir").count(), 0);
}

#[test]
fn variables_that_replace_the_tls_roots_are_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    for var in ["SSL_CERT_FILE", "SSL_CERT_DIR"] {
        for args in SUBCOMMANDS {
            let out = proxy_with(Some((var, "/tmp/attacker-roots.pem")))
                .arg("--home")
                .arg(dir.path())
                .args(args)
                .output()
                .expect("run klav-proxy");
            assert!(!out.status.success(), "{var} {args:?}");
            let stderr = String::from_utf8_lossy(&out.stderr);
            assert!(stderr.contains(&format!("{var} is set")), "{stderr}");
            assert!(!stderr.contains("attacker-roots"), "never the value");
        }
    }
    assert_eq!(std::fs::read_dir(dir.path()).expect("dir").count(), 0);
}

#[test]
fn without_those_variables_it_gets_past_the_check() {
    // `status` with nothing registered fails, but for that reason: the
    // check passed on the real process environment.
    let dir = tempfile::tempdir().expect("tempdir");
    let out = proxy_with(None)
        .arg("--home")
        .arg(dir.path())
        .arg("status")
        .output()
        .expect("run klav-proxy");
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!stderr.contains(" is set"), "{stderr}");
}

#[test]
fn there_is_no_option_for_the_listen_address() {
    let out = proxy().args(["serve", "--help"]).output().expect("help");
    let help = String::from_utf8_lossy(&out.stdout).to_lowercase();
    assert!(help.contains("--port"));
    for flag in ["--listen", "--bind", "--host", "--address"] {
        assert!(!help.contains(flag), "{flag}");
    }
    let out = proxy()
        .args(["serve", "--listen", "0.0.0.0:8790"])
        .output()
        .expect("run");
    assert!(!out.status.success());
}

/// ADR 0042 §3: `serve` offers the option that turns local calls off.
#[test]
fn serve_offers_no_local_calls() {
    let out = proxy().args(["serve", "--help"]).output().expect("help");
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("--no-local-calls"));
}

/// `klav-proxy 0.0.0 (ce4fa5099092 2026-11-13T18:17:02Z)`, or `(commit
/// unknown)`, as `klav --version` (`crates/klav-daemon/build.rs`); one line,
/// and exactly one marker line in the file with the same text.
#[test]
fn version() {
    let out = proxy().arg("--version").output().expect("version");
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).expect("utf-8");
    let after = text
        .strip_prefix("klav-proxy ")
        .and_then(|t| t.strip_suffix('\n'))
        .unwrap_or_else(|| panic!("unexpected --version: {text:?}"));
    let rest = after
        .strip_prefix(&format!("{} (", env!("CARGO_PKG_VERSION")))
        .and_then(|r| r.strip_suffix(')'))
        .unwrap_or_else(|| panic!("unexpected --version: {text:?}"));
    if rest != "commit unknown" {
        let (short, time) = rest.split_once(' ').expect("hash and time");
        assert_eq!(short.len(), 12, "{rest}");
        assert!(
            short
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        );
        assert_eq!(time.len(), 20, "{time}");
        assert!(time.ends_with('Z') && time.as_bytes()[10] == b'T', "{time}");
    }
    let file = std::fs::read(env!("CARGO_BIN_EXE_klav-proxy")).expect("the binary");
    let marker = format!("klav-build-identity: {after}\n");
    let found = file
        .windows(marker.len())
        .filter(|w| *w == marker.as_bytes())
        .count();
    assert_eq!(found, 1, "{marker:?}");
}
