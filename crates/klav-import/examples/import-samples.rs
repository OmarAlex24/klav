//! Writes the synthetic exports of `klav_import::samples` to a directory
//! (default `examples/import`), for the CLI, extension and iOS tests.
//!
//!   cargo run -p klav-import --features samples,qr-image --example import-samples [dir]

#![allow(clippy::print_stdout, clippy::expect_used)]

use std::path::PathBuf;

use klav_import::samples;

fn main() {
    let dir = PathBuf::from(
        std::env::args()
            .nth(1)
            .unwrap_or_else(|| "examples/import".into()),
    );
    std::fs::create_dir_all(&dir).expect("create the directory");
    let [first, second] = samples::google_links();
    let files: Vec<(&str, Vec<u8>)> = vec![
        ("bitwarden.json", samples::bitwarden_json().into_bytes()),
        ("1password.1pux", samples::onepux()),
        ("google-1-of-2.png", samples::qr_png(&first)),
        ("google-2-of-2.png", samples::qr_png(&second)),
        (
            "google-links.txt",
            format!("{first}\n{second}\n").into_bytes(),
        ),
        ("chrome.csv", samples::chrome_csv().into_bytes()),
        ("firefox.csv", samples::firefox_csv().into_bytes()),
        ("safari.csv", samples::safari_csv().into_bytes()),
    ];
    for (name, bytes) in files {
        std::fs::write(dir.join(name), bytes).expect("write a sample");
        println!("{}", dir.join(name).display());
    }
}
