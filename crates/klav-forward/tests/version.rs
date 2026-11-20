//! `klav-forward --version` names the build as `klav --version` does
//! (`crates/klav-daemon/build.rs`), and the file carries the same marker.

use std::process::Command;

/// `klav-forward 0.0.0 (ce4fa5099092 2026-11-13T18:17:02Z)`, or `(commit
/// unknown)`; one line, and exactly one marker line in the file with the
/// same text.
#[test]
fn version_names_the_commit_and_its_time() {
    let bin = env!("CARGO_BIN_EXE_klav-forward");
    let out = Command::new(bin)
        .arg("--version")
        .output()
        .expect("klav-forward --version");
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).expect("utf-8");
    let after = text
        .strip_prefix("klav-forward ")
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
    let file = std::fs::read(bin).expect("the binary");
    let marker = format!("klav-build-identity: {after}\n");
    let found = file
        .windows(marker.len())
        .filter(|w| *w == marker.as_bytes())
        .count();
    assert_eq!(found, 1, "{marker:?}");
}
