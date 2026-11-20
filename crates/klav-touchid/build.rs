//! Compiles `swift/shim.swift` into a static library on macOS when the
//! Swift toolchain is installed (Xcode or the Command Line Tools), and
//! enables `cfg(klav_se_shim)`. Elsewhere (Linux CI, a Mac without
//! Swift, or `KLAV_NO_SWIFT=1`) nothing is compiled and the crate reports
//! Touch ID as unavailable, so `klavd` falls back to the master password.

use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo::rustc-check-cfg=cfg(klav_se_shim)");
    println!("cargo:rerun-if-changed=swift/shim.swift");
    println!("cargo:rerun-if-env-changed=KLAV_NO_SWIFT");
    println!("cargo:rerun-if-env-changed=MACOSX_DEPLOYMENT_TARGET");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos")
        || std::env::var_os("KLAV_NO_SWIFT").is_some()
    {
        return;
    }
    let Some(swiftc) = xcrun(&["--find", "swiftc"]) else {
        println!(
            "cargo:warning=swiftc not found: Touch ID support is disabled (install the Xcode Command Line Tools)"
        );
        return;
    };
    let Some(sdk) = xcrun(&["--sdk", "macosx", "--show-sdk-path"]) else {
        println!("cargo:warning=macOS SDK not found: Touch ID support is disabled");
        return;
    };
    let arch = match std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() {
        Ok("aarch64") => "arm64",
        Ok("x86_64") => "x86_64",
        other => panic!("unsupported macOS architecture {other:?}"),
    };
    let min = std::env::var("MACOSX_DEPLOYMENT_TARGET").unwrap_or_else(|_| "11.0".into());
    let out = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));
    let status = Command::new(&swiftc)
        .args(["-emit-library", "-static", "-O", "-parse-as-library"])
        .args(["-module-name", "KlavShim"])
        .args(["-sdk", &sdk])
        .args(["-target", &format!("{arch}-apple-macosx{min}")])
        .arg("-o")
        .arg(out.join("libKlavShim.a"))
        .arg("swift/shim.swift")
        .status()
        .expect("run swiftc");
    assert!(
        status.success(),
        "swiftc failed to compile swift/shim.swift"
    );

    let toolchain_lib = Path::new(&swiftc)
        .parent()
        .and_then(Path::parent)
        .map(|p| p.join("lib/swift/macosx"))
        .expect("toolchain directory");
    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-lib=static=KlavShim");
    println!("cargo:rustc-link-search=native={sdk}/usr/lib/swift");
    println!("cargo:rustc-link-search=native={}", toolchain_lib.display());
    for framework in [
        "CoreGraphics",
        "CryptoKit",
        "Foundation",
        "LocalAuthentication",
        "Security",
    ] {
        println!("cargo:rustc-link-lib=framework={framework}");
    }
    // `audit_token_to_pid` and `audit_token_to_pidversion` (the socket
    // peer's audit token, ADR 0041 §1.1).
    println!("cargo:rustc-link-lib=bsm");
    println!("cargo:rustc-cfg=klav_se_shim");
}

fn xcrun(args: &[&str]) -> Option<String> {
    let out = Command::new("xcrun").args(args).output().ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_owned())
        .filter(|s| !s.is_empty())
}
