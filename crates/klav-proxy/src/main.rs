//! `klav-proxy` (ADR 0036 §14): the whole program is
//! [`klav_proxy::cli::main`], which the `klav` binary also runs when it is
//! started as `klav-proxy`.

use std::process::ExitCode;

/// The commit this binary was built from (`klav-daemon/build.rs`): only
/// `--version` reads it.
#[allow(dead_code)]
mod build {
    include!(concat!(env!("OUT_DIR"), "/build_identity.rs"));
}

fn main() -> ExitCode {
    klav_proxy::cli::main(build::version())
}
