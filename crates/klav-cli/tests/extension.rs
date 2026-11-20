//! The browser extension's side of `klav`: `klav extension install-host`
//! writes the native messaging manifests, and `klavd` answers `suggest`
//! and `autofill` with the site rule (ADR 0017 §5).

mod common;

use common::{Device, ServerProcess, mode};
use klav_daemon::client::DaemonClient;
use klav_daemon::protocol::{ErrorCode, Request};
use serde_json::Value;

const PASSWORD: &str = "MARKER-ext-pass";

/// Stops the daemon even if the test fails.
struct StopDaemon<'a>(&'a Device);

impl Drop for StopDaemon<'_> {
    fn drop(&mut self) {
        let _ = self.0.run(&["lock", "--stop"], "");
    }
}

#[test]
fn install_host_writes_one_manifest_per_browser() {
    let root = tempfile::tempdir().expect("tempdir");
    let device = Device::new(root.path(), "home");
    let fake_home = root.path().join("user");
    let host = root.path().join("bin/klav-native-host");
    std::fs::create_dir_all(host.parent().expect("parent")).expect("dir");
    std::fs::write(&host, "#!/bin/sh\n").expect("host");
    let host_arg = host.to_str().expect("utf-8");
    let run = |args: &[&str]| {
        let mut cmd = device.command();
        cmd.env("HOME", &fake_home).args(args);
        let out = cmd.output().expect("run klav");
        (
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    };

    // No browser installed under this HOME and none named: nothing to do.
    let (code, _, err) = run(&["extension", "install-host", "--host", host_arg]);
    assert_ne!(code, 0);
    assert!(err.contains("no supported browser"), "{err}");

    // Dia (like Arc) only exists on macOS.
    let mut args = vec![
        "extension",
        "install-host",
        "--host",
        host_arg,
        "--browser",
        "chrome",
        "--browser",
        "firefox",
        "--extension-id",
        "abcdefghijklmnopabcdefghijklmnop",
        "--json",
    ];
    if cfg!(target_os = "macos") {
        args.extend(["--browser", "dia"]);
    }
    let (code, out, err) = run(&args);
    assert_eq!(code, 0, "{err}");
    let report: Value = serde_json::from_str(&out).expect("json");
    let wrapper = device.home.join("native-host/klav-native-host");
    assert_eq!(report["wrapper"], wrapper.to_str().expect("utf-8"));
    assert_eq!(mode(&wrapper), 0o700);
    let script = std::fs::read_to_string(&wrapper).expect("wrapper");
    assert!(script.starts_with("#!/bin/sh\n"), "{script}");
    assert!(
        script.contains(&format!("--home '{}'", device.home.display())),
        "{script}"
    );
    assert!(
        script.contains("--allow 'chrome-extension://abcdefghijklmnopabcdefghijklmnop/'"),
        "{script}"
    );
    assert!(script.trim_end().ends_with("\"$@\""), "{script}");

    let (chrome, dia, firefox) = if cfg!(target_os = "macos") {
        (
            "Library/Application Support/Google/Chrome/NativeMessagingHosts",
            "Library/Application Support/Dia/User Data/NativeMessagingHosts",
            "Library/Application Support/Mozilla/NativeMessagingHosts",
        )
    } else {
        (
            ".config/google-chrome/NativeMessagingHosts",
            "",
            ".mozilla/native-messaging-hosts",
        )
    };
    let read = |dir: &str| -> Value {
        let text = std::fs::read_to_string(fake_home.join(dir).join("dev.klav.host.json"))
            .expect("manifest");
        serde_json::from_str(&text).expect("manifest json")
    };
    let manifest = read(chrome);
    assert_eq!(manifest["name"], "dev.klav.host");
    assert_eq!(manifest["type"], "stdio");
    assert_eq!(manifest["path"], wrapper.to_str().expect("utf-8"));
    let origins: Vec<&str> = manifest["allowed_origins"]
        .as_array()
        .expect("origins")
        .iter()
        .filter_map(Value::as_str)
        .collect();
    // Without --dev, not the development build (its key is public).
    assert_eq!(
        origins,
        ["chrome-extension://abcdefghijklmnopabcdefghijklmnop/"]
    );
    assert!(
        !script.contains("niiplppgdljgimbnmokojdkofdcjkgao"),
        "{script}"
    );
    if cfg!(target_os = "macos") {
        assert_eq!(read(dia)["allowed_origins"], manifest["allowed_origins"]);
    }
    let ff = read(firefox);
    assert_eq!(ff["allowed_extensions"][0], "klav@klav.dev");
    assert!(ff.get("allowed_origins").is_none());

    // A throwaway Chromium profile: no Chromium extension to allow
    // without --extension-id or --dev.
    let profile = root.path().join("profile");
    let profile_arg = profile.to_str().expect("utf-8");
    let (code, _, err) = run(&[
        "extension",
        "install-host",
        "--host",
        host_arg,
        "--user-data-dir",
        profile_arg,
    ]);
    assert_ne!(code, 0);
    assert!(err.contains("--dev"), "{err}");
    assert!(
        !profile
            .join("NativeMessagingHosts/dev.klav.host.json")
            .exists()
    );
    let (code, _, err) = run(&[
        "extension",
        "install-host",
        "--host",
        host_arg,
        "--user-data-dir",
        profile_arg,
        "--dev",
    ]);
    assert_eq!(code, 0, "{err}");
    let text = std::fs::read_to_string(profile.join("NativeMessagingHosts/dev.klav.host.json"))
        .expect("manifest");
    let dev: Value = serde_json::from_str(&text).expect("manifest json");
    assert_eq!(
        dev["allowed_origins"][0],
        "chrome-extension://niiplppgdljgimbnmokojdkofdcjkgao/"
    );
    let script = std::fs::read_to_string(&wrapper).expect("wrapper");
    assert!(
        script.contains("--allow 'chrome-extension://niiplppgdljgimbnmokojdkofdcjkgao/'"),
        "{script}"
    );
    let (code, _, err) = run(&[
        "extension",
        "install-host",
        "--host",
        host_arg,
        "--user-data-dir",
        "x",
        "--browser",
        "firefox",
    ]);
    assert_ne!(code, 0);
    assert!(err.contains("one Chromium-based browser"), "{err}");

    // Uninstall removes the manifests and the wrapper.
    let mut args = vec![
        "extension",
        "uninstall-host",
        "--browser",
        "chrome",
        "--browser",
        "firefox",
    ];
    if cfg!(target_os = "macos") {
        args.extend(["--browser", "dia"]);
    }
    let (code, _, err) = run(&args);
    assert_eq!(code, 0, "{err}");
    assert!(!fake_home.join(chrome).join("dev.klav.host.json").exists());
    assert!(!fake_home.join(firefox).join("dev.klav.host.json").exists());
    let (code, _, _) = run(&["extension", "uninstall-host"]);
    assert_eq!(code, 0);
    assert!(!wrapper.exists());
}

/// Dia on macOS reads its host from Mozilla's directory, in Firefox's
/// format: `--browser dia` writes that manifest too, and removing Dia
/// alone leaves it for Firefox.
#[cfg(target_os = "macos")]
#[test]
fn dia_also_gets_the_mozilla_manifest() {
    let root = tempfile::tempdir().expect("tempdir");
    let device = Device::new(root.path(), "home");
    let fake_home = root.path().join("user");
    let host = root.path().join("bin/klav-native-host");
    std::fs::create_dir_all(host.parent().expect("parent")).expect("dir");
    std::fs::write(&host, "#!/bin/sh\n").expect("host");
    let host_arg = host.to_str().expect("utf-8");
    let run = |args: &[&str]| {
        let mut cmd = device.command();
        cmd.env("HOME", &fake_home).args(args);
        let out = cmd.output().expect("run klav");
        (
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    };
    let support = fake_home.join("Library/Application Support");
    let dia = support.join("Dia/User Data/NativeMessagingHosts/dev.klav.host.json");
    let mozilla = support.join("Mozilla/NativeMessagingHosts/dev.klav.host.json");

    // Dia is Chromium: its manifest needs an extension to allow (layer 09).
    let (code, err) = run(&[
        "extension",
        "install-host",
        "--host",
        host_arg,
        "--browser",
        "dia",
        "--dev",
    ]);
    assert_eq!(code, 0, "{err}");
    let read = |path: &std::path::Path| -> Value {
        serde_json::from_str(&std::fs::read_to_string(path).expect("manifest")).expect("json")
    };
    let wrapper = device.home.join("native-host/klav-native-host");
    assert_eq!(read(&dia)["path"], wrapper.to_str().expect("utf-8"));
    let ff = read(&mozilla);
    assert_eq!(ff["path"], wrapper.to_str().expect("utf-8"));
    assert_eq!(ff["allowed_extensions"][0], "klav@klav.dev");
    assert!(ff.get("allowed_origins").is_none());

    // Removing Dia alone keeps the file Firefox reads; with Firefox, it goes.
    let (code, err) = run(&["extension", "uninstall-host", "--browser", "dia"]);
    assert_eq!(code, 0, "{err}");
    assert!(!dia.exists());
    assert!(mozilla.exists());
    let (code, err) = run(&[
        "extension",
        "uninstall-host",
        "--browser",
        "dia",
        "--browser",
        "firefox",
    ]);
    assert_eq!(code, 0, "{err}");
    assert!(!mozilla.exists());
}

/// Ardia reads Chromium native messaging manifests from
/// `com.ardia.browser/Chromium/NativeMessagingHosts` on macOS and
/// `~/.config/ardia/NativeMessagingHosts` on Linux.
#[test]
fn ardia_gets_chromium_manifest() {
    let root = tempfile::tempdir().expect("tempdir");
    let device = Device::new(root.path(), "home");
    let fake_home = root.path().join("user");
    let host = root.path().join("bin/klav-native-host");
    std::fs::create_dir_all(host.parent().expect("parent")).expect("dir");
    std::fs::write(&host, "#!/bin/sh\n").expect("host");
    let host_arg = host.to_str().expect("utf-8");
    let run = |args: &[&str]| {
        let mut cmd = device.command();
        cmd.env("HOME", &fake_home).args(args);
        let out = cmd.output().expect("run klav");
        (
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    };
    let manifest = fake_home.join(if cfg!(target_os = "macos") {
        "Library/Application Support/com.ardia.browser/Chromium/NativeMessagingHosts/dev.klav.host.json"
    } else {
        ".config/ardia/NativeMessagingHosts/dev.klav.host.json"
    });

    let (code, _, err) = run(&[
        "extension",
        "install-host",
        "--host",
        host_arg,
        "--browser",
        "ardia",
        "--dev",
    ]);
    assert_eq!(code, 0, "{err}");
    let text = std::fs::read_to_string(&manifest).expect("manifest");
    let json: Value = serde_json::from_str(&text).expect("json");
    assert_eq!(
        json["allowed_origins"][0],
        "chrome-extension://niiplppgdljgimbnmokojdkofdcjkgao/"
    );
    assert!(json.get("allowed_extensions").is_none());

    let (code, out, err) = run(&["extension", "host-status", "--host", host_arg, "--json"]);
    assert_eq!(code, 0, "{err}");
    let status: Value = serde_json::from_str(&out).expect("status json");
    let ardia = status["manifests"]
        .as_array()
        .expect("manifests")
        .iter()
        .find(|m| m["browser"] == "ardia")
        .expect("ardia manifest");
    assert_eq!(ardia["current"], true, "{ardia}");

    let (code, _, err) = run(&["extension", "uninstall-host", "--browser", "ardia"]);
    assert_eq!(code, 0, "{err}");
    assert!(!manifest.exists());
}

#[tokio::test(flavor = "multi_thread")]
async fn klavd_suggests_and_fills_only_matching_sites() {
    let server = ServerProcess::start(900);
    let root = tempfile::tempdir().expect("tempdir");
    let device = Device::new(root.path(), "home");
    device.signup(&server, "ext@example.com");
    for (args, stdin) in [
        (
            vec![
                "item",
                "add",
                "login",
                "--title",
                "GitHub",
                "--username",
                "ana",
                "--url",
                "https://github.com/login",
                "--secret-stdin",
                "password",
                "--secret-stdin",
                "totp",
            ],
            format!("{PASSWORD}\nJBSWY3DPEHPK3PXP\n"),
        ),
        (
            vec![
                "item",
                "add",
                "login",
                "--title",
                "Other",
                "--username",
                "bob",
                "--url",
                "https://other.example",
                "--secret-stdin",
                "password",
            ],
            "MARKER-other\n".to_owned(),
        ),
        (
            vec![
                "item",
                "add",
                "card",
                "--title",
                "Visa",
                "--field",
                "cardholder=Ana Pérez",
                "--field",
                "expiry=2029-04",
                "--secret-stdin",
                "number",
                "--secret-stdin",
                "cvv",
            ],
            "4242 4242 4242 4242\n123\n".to_owned(),
        ),
        (
            vec![
                "item",
                "add",
                "identity",
                "--title",
                "Casa",
                "--field",
                "first_name=Ana",
                "--field",
                "last_name=Pérez",
                "--field",
                "city=Monterrey",
            ],
            String::new(),
        ),
    ] {
        device.unlocked(&args, &stdin).ok();
    }
    let _stop = StopDaemon(&device);
    device.unlocked(&["unlock", "--idle-lock", "10m"], "").ok();
    let home = klav_client::Home::at(&device.home);
    let mut client = DaemonClient::connect(&home).await.expect("klavd");

    let (s, _): (Value, _) = client
        .call(Request::Suggest {
            url: "https://gist.github.com/x".into(),
        })
        .await
        .expect("suggest");
    let text = s.to_string();
    assert!(
        !text.contains("MARKER") && !text.contains("4242 4242"),
        "{text}"
    );
    assert_eq!(s["host"], "gist.github.com");
    assert_eq!(s["logins"].as_array().expect("logins").len(), 1);
    assert_eq!(s["logins"][0]["title"], "GitHub");
    assert_eq!(s["logins"][0]["username"], "ana");
    assert_eq!(s["logins"][0]["totp"], true);
    assert_eq!(s["cards"][0]["hint"], "•••• 4242");
    assert_eq!(s["identities"][0]["hint"], "Ana Pérez");
    let github = s["logins"][0]["id"].as_str().expect("id").to_owned();
    let card = s["cards"][0]["id"].as_str().expect("id").to_owned();

    // A look-alike gets nothing, and a page Klav never fills neither.
    for url in [
        "https://github.com.evil.example/login",
        "http://github.com/login",
        "file:///etc/passwd",
    ] {
        let (s, _): (Value, _) = client
            .call(Request::Suggest { url: url.into() })
            .await
            .expect("suggest");
        assert_eq!(s["logins"].as_array().map_or(0, Vec::len), 0, "{url}");
    }

    let (values, _): (Value, _) = client
        .call(Request::Autofill {
            item: github.clone(),
            url: "https://github.com/login".into(),
            part: klav_client::fill::FillPart::All,
            chosen: false,
            password: None,
        })
        .await
        .expect("autofill");
    let names: Vec<&str> = values["fields"]
        .as_array()
        .expect("fields")
        .iter()
        .filter_map(|f| f["name"].as_str())
        .collect();
    assert_eq!(names, ["username", "password", "totp"]);
    assert_eq!(values["fields"][1]["value"], PASSWORD);
    assert_eq!(values["fields"][2]["value"].as_str().map(str::len), Some(6));

    // The phishing check runs in klavd too.
    let refused = client
        .call::<Value>(Request::Autofill {
            item: github.clone(),
            url: "https://github.com.evil.example/login".into(),
            part: klav_client::fill::FillPart::All,
            chosen: false,
            password: None,
        })
        .await
        .expect_err("refused");
    assert_eq!(refused.code, ErrorCode::Denied);
    assert!(!refused.message.contains(PASSWORD));
    // An item is named by its ID only.
    let by_title = client
        .call::<Value>(Request::Autofill {
            item: "GitHub".into(),
            url: "https://github.com/login".into(),
            part: klav_client::fill::FillPart::All,
            chosen: false,
            password: None,
        })
        .await
        .expect_err("by title");
    assert_eq!(by_title.code, ErrorCode::Invalid);

    // The second step of a login: only the code.
    let (code, _): (Value, _) = client
        .call(Request::Autofill {
            item: github,
            url: "https://github.com/sessions/two-factor".into(),
            part: klav_client::fill::FillPart::Totp,
            chosen: false,
            password: None,
        })
        .await
        .expect("totp");
    assert_eq!(code["fields"].as_array().map(Vec::len), Some(1));
    assert_eq!(code["fields"][0]["kind"], "totp");

    // A card fills on any https page, with the expiry as MM/YY.
    let (values, _): (Value, _) = client
        .call(Request::Autofill {
            item: card,
            url: "https://shop.example/pay".into(),
            part: klav_client::fill::FillPart::All,
            chosen: false,
            password: None,
        })
        .await
        .expect("card");
    let card: Vec<(String, String)> = values["fields"]
        .as_array()
        .expect("fields")
        .iter()
        .map(|f| {
            (
                f["name"].as_str().unwrap_or_default().to_owned(),
                f["value"].as_str().unwrap_or_default().to_owned(),
            )
        })
        .collect();
    assert!(
        card.contains(&("expiry".into(), "04/29".into())),
        "{card:?}"
    );
    assert!(card.contains(&("number".into(), "4242 4242 4242 4242".into())));
    drop(server);
}

/// ADR 0025: logins come exact host first, then subdomain, whatever their
/// titles; a login saved for a subdomain is offered apart on its parent
/// page and only fills when the person picked it (`chosen`).
#[tokio::test(flavor = "multi_thread")]
async fn klavd_orders_by_relation_and_fills_a_parent_only_when_chosen() {
    let server = ServerProcess::start(900);
    let root = tempfile::tempdir().expect("tempdir");
    let device = Device::new(root.path(), "home");
    device.signup(&server, "parent@example.com");
    // Titles sort the other way round on purpose: the relation wins.
    for (title, url) in [
        ("Zeta", "https://my.1password.com/signin"),
        ("Alpha", "https://1password.com"),
    ] {
        let args = [
            "item",
            "add",
            "login",
            "--title",
            title,
            "--username",
            "ana",
            "--url",
            url,
            "--secret-stdin",
            "password",
        ];
        device.unlocked(&args, &format!("{PASSWORD}\n")).ok();
    }
    let _stop = StopDaemon(&device);
    device.unlocked(&["unlock", "--idle-lock", "10m"], "").ok();
    let home = klav_client::Home::at(&device.home);
    let mut client = DaemonClient::connect(&home).await.expect("klavd");
    let suggest = |url: &'static str| Request::Suggest { url: url.into() };
    let titles = |v: &Value, group: &str| -> Vec<String> {
        v[group]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|s| s["title"].as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default()
    };

    // On `my.1password.com`: its own login first, then the domain's.
    let (s, _): (Value, _) = client
        .call(suggest("https://my.1password.com/signin"))
        .await
        .expect("suggest");
    assert_eq!(titles(&s, "logins"), ["Zeta", "Alpha"]);
    assert_eq!(s["logins"][0]["relation"], "exact");
    assert_eq!(s["logins"][1]["relation"], "subdomain");
    assert!(titles(&s, "parent").is_empty());

    // On `1password.com`: the domain's login, and the subdomain's apart,
    // with the host it was saved for.
    let (s, _): (Value, _) = client
        .call(suggest("https://1password.com/"))
        .await
        .expect("suggest");
    assert_eq!(titles(&s, "logins"), ["Alpha"]);
    assert_eq!(titles(&s, "parent"), ["Zeta"]);
    assert_eq!(s["parent"][0]["relation"], "parent");
    assert_eq!(s["parent"][0]["site"], "my.1password.com");
    let zeta = s["parent"][0]["id"].as_str().expect("id").to_owned();

    // A sibling gets the domain's login only, and `com` is no page.
    let (s, _): (Value, _) = client
        .call(suggest("https://start.1password.com/"))
        .await
        .expect("suggest");
    assert_eq!(titles(&s, "logins"), ["Alpha"]);
    assert!(titles(&s, "parent").is_empty());

    // Without the person's pick (a fill without a click, or anything that
    // is not the menu or the popup), the parent page gets nothing.
    let refused = client
        .call::<Value>(Request::Autofill {
            item: zeta.clone(),
            url: "https://1password.com/login".into(),
            part: klav_client::fill::FillPart::All,
            chosen: false,
            password: None,
        })
        .await
        .expect_err("refused");
    assert_eq!(refused.code, ErrorCode::Denied);
    assert!(!refused.message.contains(PASSWORD));
    // Chosen, it fills.
    let (values, _): (Value, _) = client
        .call(Request::Autofill {
            item: zeta.clone(),
            url: "https://1password.com/login".into(),
            part: klav_client::fill::FillPart::All,
            chosen: true,
            password: None,
        })
        .await
        .expect("chosen");
    assert_eq!(values["fields"][1]["value"], PASSWORD);
    // `chosen` never opens a sibling or a look-alike.
    for url in [
        "https://start.1password.com/",
        "https://1password.com.evil.example/",
    ] {
        let refused = client
            .call::<Value>(Request::Autofill {
                item: zeta.clone(),
                url: url.into(),
                part: klav_client::fill::FillPart::All,
                chosen: true,
                password: None,
            })
            .await
            .expect_err("refused");
        assert_eq!(refused.code, ErrorCode::Denied, "{url}");
    }
    drop(server);
}

/// Passkeys through `klavd` (ADR 0020): create with the master password
/// as the verification (Touch ID is off in tests), list, sign in (logged as
/// `passkey.used`), and no prompt or signature for a page that is not the
/// passkey's site.
#[tokio::test(flavor = "multi_thread")]
async fn klavd_creates_and_signs_with_passkeys() {
    use klav_client::ops::SecretText;
    use klav_client::passkeys::{PasskeyCreateOutcome, PasskeyCreateRequest};

    let server = ServerProcess::start(900);
    let root = tempfile::tempdir().expect("tempdir");
    let device = Device::new(root.path(), "home");
    device.signup(&server, "passkey@example.com");
    let _stop = StopDaemon(&device);
    device.unlocked(&["unlock", "--idle-lock", "10m"], "").ok();
    let home = klav_client::Home::at(&device.home);
    let mut client = DaemonClient::connect(&home).await.expect("klavd");
    let enc = |bytes: &[u8]| klav_proto::Blob::from(bytes).to_text();
    let dec = |text: &str| {
        klav_proto::Blob::from_text(text)
            .expect("base64url")
            .into_bytes()
    };
    let password = || Some(SecretText::new(common::PASSWORD));

    let request = PasskeyCreateRequest {
        origin: "https://shop.example".into(),
        rp_name: Some("Shop".into()),
        user_id: enc(b"ana-0001"),
        user_name: "ana".into(),
        challenge: enc(b"0123456789abcdef"),
        ..PasskeyCreateRequest::default()
    };
    // A wrong password is not a verification: nothing is created.
    let err = client
        .call::<Value>(Request::PasskeyCreate {
            request: request.clone(),
            password: Some(SecretText::new("wrong")),
        })
        .await
        .expect_err("wrong password");
    assert_eq!(err.code, ErrorCode::WrongCredentials);
    let (created, _): (PasskeyCreateOutcome, _) = client
        .call(Request::PasskeyCreate {
            request: request.clone(),
            password: password(),
        })
        .await
        .expect("create");
    let PasskeyCreateOutcome::Created(reg) = created else {
        panic!("not created: {created:?}");
    };
    assert_eq!(dec(&reg.authenticator_data)[32], 0x5d);

    // Saving into a chosen login: only one saved for this site (ADR 0030
    // §7: by the URLs the person confirmed).
    device
        .unlocked(
            &[
                "item",
                "add",
                "login",
                "--title",
                "Bank",
                "--url",
                "https://bank.example",
            ],
            "",
        )
        .ok();
    let other_account = PasskeyCreateRequest {
        user_id: enc(b"bea-0002"),
        user_name: "bea".into(),
        item: Some("Bank".into()),
        ..request.clone()
    };
    let err = client
        .call::<Value>(Request::PasskeyCreate {
            request: other_account.clone(),
            password: password(),
        })
        .await
        .expect_err("a login of another site");
    assert_eq!(err.code, ErrorCode::Denied);
    device
        .unlocked(
            &[
                "item",
                "add",
                "login",
                "--title",
                "Shop bea",
                "--url",
                "https://shop.example",
            ],
            "",
        )
        .ok();
    let (saved, _): (PasskeyCreateOutcome, _) = client
        .call(Request::PasskeyCreate {
            request: PasskeyCreateRequest {
                item: Some("Shop bea".into()),
                ..other_account
            },
            password: password(),
        })
        .await
        .expect("a login of this site");
    assert!(
        matches!(saved, PasskeyCreateOutcome::Created(_)),
        "{saved:?}"
    );

    let (candidates, _): (Value, _) = client
        .call(Request::PasskeyCandidates {
            origin: "https://shop.example/login".into(),
            rp_id: None,
            allow_credentials: vec![],
        })
        .await
        .expect("candidates");
    assert_eq!(candidates["rp_id"], "shop.example");
    assert_eq!(candidates["candidates"][0]["title"], "Shop");
    assert_eq!(candidates["candidates"][0]["user_name"], "ana");
    // Metadata only: no key, no handle.
    let text = candidates.to_string();
    assert!(!text.contains("\"key\"") && !text.contains("user_handle"));

    let (assertion, _): (Value, _) = client
        .call(Request::PasskeyGet {
            origin: "https://shop.example".into(),
            rp_id: None,
            challenge: enc(b"fedcba9876543210"),
            item: reg.item.to_string(),
            password: password(),
        })
        .await
        .expect("get");
    let auth = dec(assertion["authenticator_data"].as_str().unwrap());
    assert_eq!(auth[32], 0x1d);
    let spki = dec(&reg.public_key);
    let mut message = auth.clone();
    let client_data = dec(assertion["client_data_json"].as_str().unwrap());
    message.extend_from_slice(&klav_core::passkey::webauthn::client_data_hash(
        &client_data,
    ));
    klav_core::crypto::passkey::verify_es256(
        &spki[spki.len() - 65..],
        &message,
        &dec(assertion["signature"].as_str().unwrap()),
    )
    .expect("a relying party accepts it");

    // Another site: refused before any prompt (the wrong password is not
    // even checked), and an insecure origin goes to the browser.
    let err = client
        .call::<Value>(Request::PasskeyGet {
            origin: "https://other.example".into(),
            rp_id: None,
            challenge: enc(b"fedcba9876543210"),
            item: reg.item.to_string(),
            password: Some(SecretText::new("wrong")),
        })
        .await
        .expect_err("other site");
    assert_eq!(err.code, ErrorCode::NotFound);
    let err = client
        .call::<Value>(Request::PasskeyGet {
            origin: "http://shop.example".into(),
            rp_id: None,
            challenge: enc(b"fedcba9876543210"),
            item: reg.item.to_string(),
            password: password(),
        })
        .await
        .expect_err("insecure origin");
    assert_eq!(err.code, ErrorCode::Denied);
    // The sign-in goes to the audit log in the background as
    // `passkey.used`, with only the item; the refused ones do not.
    let mut used = Vec::new();
    for _ in 0..100 {
        let (lines, _): (Vec<Value>, _) = client
            .call(Request::AuditLog {
                filter: Default::default(),
            })
            .await
            .expect("log");
        used = lines
            .into_iter()
            .filter(|l| l["action"] == "passkey.used")
            .collect();
        if !used.is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert_eq!(used.len(), 1, "{used:?}");
    assert_eq!(used[0]["item_id"], reg.item.to_string());
    assert_eq!(used[0]["actor"], "you");
    assert!(used[0].get("domain").is_none() && used[0].get("agent_id").is_none());
    // The chain still verifies with the person's event in it.
    let (report, _): (Value, _) = client
        .call(Request::VerifyAudit)
        .await
        .expect("verify the log");
    assert!(report.get("events").is_some(), "{report}");
    let (browser, _): (PasskeyCreateOutcome, _) = client
        .call(Request::PasskeyCreate {
            request: PasskeyCreateRequest {
                origin: "http://shop.example".into(),
                ..request.clone()
            },
            password: Some(SecretText::new("wrong")),
        })
        .await
        .expect("browser");
    assert_eq!(browser, PasskeyCreateOutcome::Browser);

    // Locked: klavd says so, and the extension shows «Unlock».
    device.run(&["lock"], "").ok();
    let err = client
        .call::<Value>(Request::PasskeyCandidates {
            origin: "https://shop.example".into(),
            rp_id: None,
            allow_credentials: vec![],
        })
        .await
        .expect_err("locked");
    assert_eq!(err.code, ErrorCode::Locked);
}

/// The passkey verification window (ADR 0020 §8), with Touch ID off: every
/// verification is the master password. «Always» asks on every use except
/// the one Klav's passkey frame unlocked for; loosening needs the password;
/// a longer window covers later uses; locking closes it.
#[tokio::test(flavor = "multi_thread")]
async fn klavd_passkey_verification_window() {
    use klav_client::ops::SecretText;
    use klav_client::passkeys::{PasskeyCreateOutcome, PasskeyCreateRequest};
    use klav_daemon::protocol::DaemonStatus;
    use klav_daemon::uv::Window;

    let server = ServerProcess::start(900);
    let root = tempfile::tempdir().expect("tempdir");
    let device = Device::new(root.path(), "home");
    device.signup(&server, "uv@example.com");
    let _stop = StopDaemon(&device);
    device.unlocked(&["unlock", "--idle-lock", "10m"], "").ok();
    let home = klav_client::Home::at(&device.home);
    let mut client = DaemonClient::connect(&home).await.expect("klavd");
    let enc = |bytes: &[u8]| klav_proto::Blob::from(bytes).to_text();
    let password = || Some(SecretText::new(common::PASSWORD));

    let (created, _): (PasskeyCreateOutcome, _) = client
        .call(Request::PasskeyCreate {
            request: PasskeyCreateRequest {
                origin: "https://shop.example".into(),
                user_id: enc(b"ana-0001"),
                user_name: "ana".into(),
                challenge: enc(b"0123456789abcdef"),
                ..PasskeyCreateRequest::default()
            },
            password: password(),
        })
        .await
        .expect("create");
    let PasskeyCreateOutcome::Created(reg) = created else {
        panic!("not created: {created:?}");
    };
    let get = |password: Option<SecretText>| Request::PasskeyGet {
        origin: "https://shop.example".into(),
        rp_id: None,
        challenge: enc(b"fedcba9876543210"),
        item: reg.item.to_string(),
        password,
    };
    let uv = |window: Window, password: Option<SecretText>| Request::PasskeyUv {
        window: Some(window),
        password,
    };
    async fn status(client: &mut DaemonClient) -> DaemonStatus {
        client.call(Request::Status).await.expect("status").0
    }
    async fn unlock(client: &mut DaemonClient, passkey_flow: bool) {
        client.call::<Value>(Request::Lock).await.expect("lock");
        client
            .call::<Value>(Request::Unlock {
                password: Some(SecretText::new(common::PASSWORD)),
                passkey_flow,
            })
            .await
            .expect("unlock");
    }

    // «Always» by default: the CLI's unlock covers no passkey use.
    let s = status(&mut client).await;
    assert_eq!(
        (s.passkey_uv, s.passkey_verified),
        (Some(Window::Always), false)
    );
    let err = client.call::<Value>(get(None)).await.expect_err("asks");
    assert_eq!(err.code, ErrorCode::BiometryUnavailable);
    client
        .call::<Value>(get(password()))
        .await
        .expect("with the password");

    // Loosening needs a real verification; a wrong password is not one.
    let err = client
        .call::<Value>(uv(Window::Unlocked, None))
        .await
        .expect_err("no verification");
    assert_eq!(err.code, ErrorCode::BiometryUnavailable);
    let err = client
        .call::<Value>(uv(Window::Unlocked, Some(SecretText::new("wrong"))))
        .await
        .expect_err("wrong password");
    assert_eq!(err.code, ErrorCode::WrongCredentials);
    assert_eq!(status(&mut client).await.passkey_uv, Some(Window::Always));
    let (set, _): (Value, _) = client
        .call(uv(Window::Unlocked, password()))
        .await
        .expect("loosen");
    assert_eq!(set["window"], "unlocked");
    assert!(status(&mut client).await.passkey_verified);
    for _ in 0..2 {
        client
            .call::<Value>(get(None))
            .await
            .expect("within the window");
    }
    // Saved on disk, local to this home (not synced).
    let saved = std::fs::read_to_string(device.home.join("passkeys.json")).expect("passkeys.json");
    assert!(saved.contains("\"unlocked\""), "{saved}");

    // Tightening needs nothing. «Every 5 min» still counts the password
    // that loosened it a moment ago.
    client
        .call::<Value>(uv(Window::FiveMinutes, None))
        .await
        .expect("tighten");
    client
        .call::<Value>(get(None))
        .await
        .expect("within 5 minutes");
    client
        .call::<Value>(uv(Window::Always, None))
        .await
        .expect("tighten");
    let err = client
        .call::<Value>(get(None))
        .await
        .expect_err("asks again");
    assert_eq!(err.code, ErrorCode::BiometryUnavailable);

    // «Always»: an unlock in Klav's passkey frame covers one use, not two;
    // any other unlock covers none.
    unlock(&mut client, true).await;
    assert!(status(&mut client).await.passkey_verified);
    client
        .call::<Value>(get(None))
        .await
        .expect("the use it unlocked for");
    assert!(!status(&mut client).await.passkey_verified);
    let err = client.call::<Value>(get(None)).await.expect_err("one use");
    assert_eq!(err.code, ErrorCode::BiometryUnavailable);
    unlock(&mut client, false).await;
    assert!(!status(&mut client).await.passkey_verified);

    // «While unlocked»: the unlock counts until the lock, which closes it.
    client
        .call::<Value>(uv(Window::Unlocked, password()))
        .await
        .expect("loosen");
    unlock(&mut client, false).await;
    client
        .call::<Value>(get(None))
        .await
        .expect("the unlock counts");
    client.call::<Value>(Request::Lock).await.expect("lock");
    let s = status(&mut client).await;
    assert_eq!((s.unlocked, s.passkey_verified), (false, false));
}

/// `host-status` tells a manifest of another install (the Mac app asks
/// before replacing it, ADR 0027 §4) from this home's, and changes nothing.
#[test]
fn host_status_finds_a_manifest_from_another_install() {
    let root = tempfile::tempdir().expect("tempdir");
    let device = Device::new(root.path(), "home");
    let fake_home = root.path().join("user");
    let host = root.path().join("bin/klav-native-host");
    std::fs::create_dir_all(host.parent().expect("parent")).expect("dir");
    std::fs::write(&host, "#!/bin/sh\n").expect("host");
    let host_arg = host.to_str().expect("utf-8");
    let host_real = std::fs::canonicalize(&host).expect("canonical");
    let run = |args: &[&str]| {
        let mut cmd = device.command();
        cmd.env("HOME", &fake_home).args(args);
        let out = cmd.output().expect("run klav");
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_slice::<Value>(&out.stdout).expect("json")
    };
    let support = fake_home.join(if cfg!(target_os = "macos") {
        "Library/Application Support/Google/Chrome"
    } else {
        ".config/google-chrome"
    });
    let manifest = support.join("NativeMessagingHosts/dev.klav.host.json");
    std::fs::create_dir_all(manifest.parent().expect("parent")).expect("dir");

    // Another install's wrapper, as `cargo install` leaves it.
    let old_host = root.path().join("old/klav-native-host");
    let old_wrapper = root.path().join("old/wrapper");
    std::fs::create_dir_all(old_wrapper.parent().expect("parent")).expect("dir");
    std::fs::write(
        &old_wrapper,
        format!(
            "#!/bin/sh\nexec '{}' --home '/x' \"$@\"\n",
            old_host.display()
        ),
    )
    .expect("old wrapper");
    let old = serde_json::json!({ "name": "dev.klav.host", "path": old_wrapper, "type": "stdio" });
    std::fs::write(&manifest, old.to_string()).expect("manifest");

    let status = run(&["extension", "host-status", "--host", host_arg, "--json"]);
    let chrome = status["manifests"]
        .as_array()
        .expect("list")
        .iter()
        .find(|m| m["browser"] == "chrome")
        .expect("chrome")
        .clone();
    assert_eq!(chrome["exists"], true);
    assert_eq!(chrome["current"], false);
    assert_eq!(chrome["points_to"], old_wrapper.to_str().expect("utf-8"));
    assert_eq!(chrome["runs"], old_host.to_str().expect("utf-8"));
    assert_eq!(status["host"], host_real.to_str().expect("utf-8"));
    assert!(status["wrapper_host"].is_null(), "no wrapper yet: {status}");
    assert_eq!(
        std::fs::read_to_string(&manifest).expect("manifest"),
        old.to_string(),
        "host-status changes nothing"
    );

    // After install-host, it is this home's.
    run(&[
        "extension",
        "install-host",
        "--host",
        host_arg,
        "--dev",
        "--json",
    ]);
    let status = run(&["extension", "host-status", "--host", host_arg, "--json"]);
    assert_eq!(status["wrapper_host"], host_real.to_str().expect("utf-8"));
    for m in status["manifests"].as_array().expect("list") {
        assert_eq!(m["current"], true, "{m}");
        assert_eq!(m["runs"], host_real.to_str().expect("utf-8"));
    }

    // A different host for the same home: not current any more.
    let other = root.path().join("bin2/klav-native-host");
    std::fs::create_dir_all(other.parent().expect("parent")).expect("dir");
    std::fs::write(&other, "#!/bin/sh\n").expect("host");
    let status = run(&[
        "extension",
        "host-status",
        "--host",
        other.to_str().expect("utf-8"),
        "--json",
    ]);
    assert!(
        status["manifests"]
            .as_array()
            .expect("list")
            .iter()
            .all(|m| m["current"] == false),
        "{status}"
    );
}

/// `host-status` checks each manifest against the host it runs: a wrapper
/// written before `--dev` (when the development build was a default) left
/// it out, so the host refuses what the manifest lets in. That manifest is
/// not current, and says what to run.
#[test]
fn host_status_tells_when_the_host_would_refuse_a_listed_extension() {
    let root = tempfile::tempdir().expect("tempdir");
    let device = Device::new(root.path(), "home");
    let fake_home = root.path().join("user");
    let host = root.path().join("bin/klav-native-host");
    std::fs::create_dir_all(host.parent().expect("parent")).expect("dir");
    std::fs::write(&host, "#!/bin/sh\n").expect("host");
    let host_arg = host.to_str().expect("utf-8");
    let host_real = std::fs::canonicalize(&host).expect("canonical");
    let run = |args: &[&str]| {
        let mut cmd = device.command();
        cmd.env("HOME", &fake_home).args(args);
        let out = cmd.output().expect("run klav");
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        out
    };
    let status = || -> Vec<Value> {
        let out = run(&["extension", "host-status", "--host", host_arg, "--json"]);
        let report: Value = serde_json::from_slice(&out.stdout).expect("json");
        report["manifests"].as_array().expect("list").clone()
    };
    // Chrome, and Dia on macOS (its Chromium manifest and Mozilla's).
    let support = fake_home.join(if cfg!(target_os = "macos") {
        "Library/Application Support"
    } else {
        ".config"
    });
    if cfg!(target_os = "macos") {
        std::fs::create_dir_all(support.join("Google/Chrome")).expect("dir");
        std::fs::create_dir_all(support.join("Dia/User Data")).expect("dir");
    } else {
        std::fs::create_dir_all(support.join("google-chrome")).expect("dir");
    }
    let store = "abcdefghijklmnopabcdefghijklmnop";
    let store_origin = format!("chrome-extension://{store}/");
    let dev = format!(
        "chrome-extension://{}/",
        klav_daemon::native::DEV_CHROMIUM_ID
    );
    let install = || {
        run(&[
            "extension",
            "install-host",
            "--host",
            host_arg,
            "--dev",
            "--extension-id",
            store,
            "--json",
        ]);
    };
    install();
    let manifests = status();
    assert_eq!(
        manifests.len(),
        if cfg!(target_os = "macos") { 3 } else { 1 }
    );
    for m in &manifests {
        assert_eq!(m["current"], true, "{m}");
        assert!(
            m.get("refused").is_none() && m.get("reason").is_none(),
            "{m}"
        );
    }

    // The wrapper as install-host wrote it before `--dev`.
    let wrapper = device.home.join("native-host/klav-native-host");
    let script = std::fs::read_to_string(&wrapper).expect("wrapper");
    let old = script.replace(&format!(" --allow '{dev}'"), "");
    assert_ne!(old, script, "{script}");
    std::fs::write(&wrapper, &old).expect("wrapper");
    let chromium = |m: &Value| !m["path"].as_str().expect("path").contains("/Mozilla/");
    for m in status() {
        assert_eq!(m["points_to"], wrapper.to_str().expect("utf-8"), "{m}");
        assert_eq!(m["runs"], host_real.to_str().expect("utf-8"), "{m}");
        if chromium(&m) {
            // Chrome and Dia's own: they list the development build.
            assert_eq!(m["current"], false, "{m}");
            assert_eq!(m["refused"], serde_json::json!([dev]), "{m}");
            let reason = m["reason"].as_str().expect("reason");
            assert!(
                reason.contains("`klav extension install-host --dev`"),
                "{reason}"
            );
        } else {
            // Mozilla's lists Firefox's add-on, which the host takes.
            assert_eq!(m["current"], true, "{m}");
            assert!(m.get("refused").is_none(), "{m}");
        }
    }
    // Without --json, the reason is on the browser's line.
    let out = run(&["extension", "host-status", "--host", host_arg]);
    let text = String::from_utf8_lossy(&out.stderr);
    let chrome_line = text
        .lines()
        .find(|l| l.trim_start().starts_with("chrome"))
        .expect("chrome line");
    assert!(
        chrome_line.contains("this KLAV_HOME, but its host would refuse"),
        "{text}"
    );
    assert!(chrome_line.contains("--dev"), "{text}");
    if cfg!(target_os = "macos") {
        assert!(
            text.lines()
                .any(|l| l.contains("Dia/User Data") && l.contains("--dev")),
            "{text}"
        );
    }

    // The store build left out as well: each with its command.
    let older = old.replace(&format!(" --allow '{store_origin}'"), "");
    std::fs::write(&wrapper, &older).expect("wrapper");
    let chrome = status()
        .into_iter()
        .find(|m| m["browser"] == "chrome")
        .expect("chrome");
    assert_eq!(chrome["refused"], serde_json::json!([dev, store_origin]));
    let reason = chrome["reason"].as_str().expect("reason");
    assert!(
        reason.contains("`klav extension install-host --dev`"),
        "{reason}"
    );
    assert!(
        reason.contains(&format!(
            "`klav extension install-host --extension-id {store}`"
        )),
        "{reason}"
    );

    // install-host again: current.
    install();
    assert!(status().iter().all(|m| m["current"] == true));
}
