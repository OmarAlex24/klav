//! `klav-native-host`: native messaging host of the Klav browser
//! extension. The browser starts it; it bridges the extension to `klavd`.
//! See `klav_daemon::native` and `docs/extension.md`.

use std::process::ExitCode;

use klav_client::Home;
use klav_daemon::native::{caller_allowed, parse_args, refuse, run};

#[allow(clippy::print_stderr)] // stdout carries the protocol; the browser logs stderr
fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args = match parse_args(&args) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("klav-native-host: {e}");
            return ExitCode::FAILURE;
        }
    };
    if !caller_allowed(&args.caller, &args.allowed) {
        eprintln!(
            "klav-native-host: extension {} is not allowed (klav extension install-host --extension-id ID, or --dev for the development build)",
            args.caller.id()
        );
        // The browser only sees the port close: answer the first request
        // with the command, so the extension can show it. No home, no klavd.
        if let Ok(runtime) = tokio::runtime::Builder::new_current_thread().build() {
            let _ = runtime.block_on(refuse(
                &args.caller,
                &mut tokio::io::stdin(),
                &mut tokio::io::stdout(),
            ));
        }
        return ExitCode::FAILURE;
    }
    let home = match &args.home {
        Some(dir) => Home::at(dir),
        None => match Home::from_env() {
            Ok(h) => h,
            Err(e) => {
                eprintln!("klav-native-host: {e}");
                return ExitCode::FAILURE;
            }
        },
    };
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("klav-native-host: {e}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(run(home, tokio::io::stdin(), tokio::io::stdout())) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("klav-native-host: {e}");
            ExitCode::FAILURE
        }
    }
}
