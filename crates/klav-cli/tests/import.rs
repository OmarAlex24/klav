//! `klav import` with the synthetic exports of `examples/import/` (never
//! real data): in this process and through `klavd`, merges and the
//! password history, Google Authenticator from QR images and from pasted
//! links, and no value ever printed.

mod common;

use std::path::PathBuf;

use common::{Device, ServerProcess};

/// Stops the daemon even if the test fails.
struct StopDaemon<'a>(&'a Device);

impl Drop for StopDaemon<'_> {
    fn drop(&mut self) {
        let _ = self.0.run(&["lock", "--stop"], "");
    }
}

fn sample(name: &str) -> String {
    let path: PathBuf = [
        env!("CARGO_MANIFEST_DIR"),
        "..",
        "..",
        "examples",
        "import",
        name,
    ]
    .iter()
    .collect();
    assert!(path.exists(), "{} is missing", path.display());
    path.to_str().expect("utf-8 path").to_owned()
}

fn json(out: &str) -> serde_json::Value {
    serde_json::from_str(out).expect("json output")
}

/// No sample value reaches the output.
fn no_values(text: &str) {
    for marker in ["sample-", "JBSWY3DP", "4111111111111111", "otpauth"] {
        assert!(!text.contains(marker), "{marker} printed:\n{text}");
    }
}

#[test]
fn imports_merge_and_keep_every_password() {
    let server = ServerProcess::start(900);
    let root = tempfile::tempdir().expect("tempdir");
    let device = Device::new(root.path(), "home");
    device.signup(&server, "import@example.com");

    // In this process: a dry run changes nothing.
    let dry = device
        .unlocked(
            &[
                "--no-daemon",
                "import",
                &sample("bitwarden.json"),
                "--dry-run",
                "--json",
            ],
            "",
        )
        .ok();
    no_values(&dry.stdout);
    let preview = &json(&dry.stdout)["preview"];
    assert_eq!(preview["totals"]["new"], 5, "{}", dry.stdout);
    // The shop's passkey comes with its key: none is left out.
    assert_eq!(preview["passkeys"], 0);
    let shop = preview["rows"]
        .as_array()
        .expect("rows")
        .iter()
        .find(|r| r["title"] == "Passkey Shop")
        .expect("the shop's row");
    assert_eq!(shop["changes"], serde_json::json!(["passkey_added"]));
    assert_eq!(preview["vault"], "Personal");
    let ls = device.unlocked(&["--no-daemon", "item", "ls"], "").ok();
    assert!(!ls.stdout.contains("GitHub"), "{}", ls.stdout);

    // Bitwarden, for real.
    let bw = device
        .unlocked(&["--no-daemon", "import", &sample("bitwarden.json")], "")
        .ok();
    no_values(&bw.stdout);
    no_values(&bw.stderr);
    assert!(
        bw.stderr.contains("5 item(s) created")
            && !bw.stderr.contains("passkey(s) were not imported")
            && bw.stderr.contains("Delete the export files now")
            && bw.stderr.contains("in Bitwarden's trash"),
        "{}",
        bw.stderr
    );

    // Through klavd: 1Password, Google Authenticator's first QR code as an
    // image and the second one pasted on stdin.
    device.unlocked(&["unlock", "--idle-lock", "10m"], "").ok();
    let _stop = StopDaemon(&device);
    let links = std::fs::read_to_string(sample("google-links.txt")).expect("links");
    let second = links.lines().nth(1).expect("second link");
    let more = device
        .run(
            &[
                "import",
                &sample("1password.1pux"),
                &sample("google-1-of-2.png"),
                "-",
            ],
            &format!("{second}\n"),
        )
        .ok();
    no_values(&more.stdout);
    no_values(&more.stderr);
    assert!(
        more.stdout
            .contains("new password (the old one goes to its history)"),
        "{}",
        more.stdout
    );
    assert!(
        more.stderr.contains("2 item(s) created, 2 updated")
            && more.stderr.contains("not imported (counter-based (HOTP)"),
        "{}",
        more.stderr
    );
    assert!(!more.stderr.contains("QR codes and"), "both codes are here");
    let history = device
        .run(&["item", "history", "Example Bank", "--json"], "")
        .ok();
    assert_eq!(
        json(&history.stdout)["entries"].as_array().map(Vec::len),
        Some(2),
        "{}",
        history.stdout
    );
    let code = device.in_terminal(None, &["totp", "GitHub"], "").ok();
    assert_eq!(code.stdout.trim().len(), 6, "GitHub got its code");

    // Browsers, and everything again: nothing new, nothing lost.
    let again = device
        .run(
            &[
                "import",
                &sample("bitwarden.json"),
                &sample("1password.1pux"),
                &sample("google-1-of-2.png"),
                &sample("chrome.csv"),
                &sample("firefox.csv"),
                &sample("safari.csv"),
                "--json",
            ],
            "",
        )
        .ok();
    no_values(&again.stdout);
    let out = json(&again.stdout);
    assert_eq!(out["result"]["created"], 2, "{}", again.stdout);
    assert_eq!(out["preview"]["totals"]["merged"], 0, "{}", again.stdout);
    let bank = device
        .in_terminal(
            None,
            &[
                "item",
                "get",
                "klav://Personal/General/Example%20Bank/password",
                "--reveal",
            ],
            "",
        )
        .ok();
    assert_eq!(bank.stdout.trim(), "sample-bank-2026b");

    // Half an export: the missing QR code is named.
    let half = device
        .run(
            &[
                "import",
                &sample("google-1-of-2.png"),
                "--from",
                "google",
                "--dry-run",
            ],
            "",
        )
        .ok();
    assert!(
        half.stderr
            .contains("has 2 QR codes and number 2 not here yet"),
        "{}",
        half.stderr
    );
    let bad = device.run(
        &["import", &sample("chrome.csv"), "--from", "bitwarden"],
        "",
    );
    assert_ne!(bad.code, 0);
    assert!(bad.stderr.contains("chrome.csv"), "{}", bad.stderr);
    drop(server);
}

/// The passkey Bitwarden exported signs in Klav: `klavd` answers a sign-in
/// of its site, and the signature checks against the key in the export.
#[tokio::test(flavor = "multi_thread")]
async fn an_imported_passkey_signs() {
    use klav_daemon::client::DaemonClient;
    use klav_daemon::protocol::Request;

    let server = ServerProcess::start(900);
    let root = tempfile::tempdir().expect("tempdir");
    let device = Device::new(root.path(), "home");
    device.signup(&server, "import-passkey@example.com");
    device
        .unlocked(&["--no-daemon", "import", &sample("bitwarden.json")], "")
        .ok();
    let ls = json(
        &device
            .unlocked(&["--no-daemon", "item", "ls", "--json"], "")
            .ok()
            .stdout,
    );
    let shop = ls
        .as_array()
        .expect("items")
        .iter()
        .find(|i| i["title"] == "Passkey Shop")
        .expect("the shop");
    assert_eq!(shop["passkey"]["rp_id"], "shop.example.com");

    // The public key of the export's private key (a synthetic sample).
    let export = json(&std::fs::read_to_string(sample("bitwarden.json")).expect("sample"));
    let key_value = export["items"]
        .as_array()
        .expect("items")
        .iter()
        .find_map(|i| i["login"]["fido2Credentials"][0]["keyValue"].as_str())
        .expect("keyValue");
    let der = klav_proto::Blob::from_text(key_value)
        .expect("base64url")
        .into_bytes();
    let public = klav_core::crypto::passkey::PasskeyPrivateKey::from_pkcs8_der(&der)
        .expect("PKCS#8")
        .public_key();

    device.unlocked(&["unlock", "--idle-lock", "10m"], "").ok();
    let _stop = StopDaemon(&device);
    let home = klav_client::Home::at(&device.home);
    let mut client = DaemonClient::connect(&home).await.expect("klavd");
    let enc = |bytes: &[u8]| klav_proto::Blob::from(bytes).to_text();
    let dec = |text: &str| {
        klav_proto::Blob::from_text(text)
            .expect("base64url")
            .into_bytes()
    };
    let (candidates, _): (serde_json::Value, _) = client
        .call(Request::PasskeyCandidates {
            origin: "https://shop.example.com/login".into(),
            rp_id: None,
            allow_credentials: vec![enc(b"sample")],
        })
        .await
        .expect("candidates");
    let item = candidates["candidates"][0]["item"]
        .as_str()
        .expect("the imported passkey is offered")
        .to_owned();
    let (assertion, _): (serde_json::Value, _) = client
        .call(Request::PasskeyGet {
            origin: "https://shop.example.com".into(),
            rp_id: None,
            challenge: enc(b"import-challenge"),
            item,
            password: Some(klav_client::ops::SecretText::new(common::PASSWORD)),
        })
        .await
        .expect("get");
    assert_eq!(dec(assertion["credential_id"].as_str().unwrap()), b"sample");
    assert_eq!(dec(assertion["user_handle"].as_str().unwrap()), b"u");
    let mut message = dec(assertion["authenticator_data"].as_str().unwrap());
    message.extend_from_slice(&klav_core::passkey::webauthn::client_data_hash(&dec(
        assertion["client_data_json"].as_str().unwrap(),
    )));
    klav_core::crypto::passkey::verify_es256(
        &public,
        &message,
        &dec(assertion["signature"].as_str().unwrap()),
    )
    .expect("the export's key signed it");
}
