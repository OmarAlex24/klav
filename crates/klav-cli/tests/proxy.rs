//! `klav proxy …` through `klavd` (ADR 0036 §14, layer 4): `use`, `grant`
//! and `revoke` change nothing without presence (Touch ID is off in tests,
//! so the master password), the proxy's first credential needs its words,
//! `klav agent approve` refuses the proxy once `use` names it, and nothing
//! printed holds the value. klavd itself refuses, before presence, a
//! grant built on another version and the account's first per-item grant
//! without the acknowledgement.

mod common;

use common::{Device, ServerProcess};
use klav_client::Home;
use klav_client::proxy_admin::ProxyCredentialSpec;
use klav_daemon::client::DaemonClient;
use klav_daemon::protocol::{ErrorBody, Request};
use serde_json::Value;

const SECRET: &str = "MARKER-proxy-token-0123456789";

/// Stops the daemon even if the test fails.
struct StopDaemon<'a>(&'a Device);

impl Drop for StopDaemon<'_> {
    fn drop(&mut self) {
        let _ = self.0.run(&["lock", "--stop"], "");
    }
}

fn status(person: &Device) -> Value {
    let out = person.run(&["proxy", "status", "--json"], "").ok();
    assert!(!out.stdout.contains(SECRET) && !out.stderr.contains(SECRET));
    serde_json::from_str(&out.stdout).expect("status json")
}

fn grant_args<'a>(item: &'a str, profile: &'a str) -> Vec<&'a str> {
    vec![
        "proxy",
        "grant",
        item,
        "--profile",
        profile,
        "--upstream",
        "https://backboard.railway.app",
        "--header",
        "authorization",
        "--prefix",
        "Bearer ",
        "--method",
        "POST",
        "--path-prefix",
        "/graphql",
    ]
}

/// A request straight to klavd, as any client of its socket can send it.
fn raw(person: &Device, request: Request) -> Result<Value, ErrorBody> {
    let home = Home::at(person.home.clone());
    tokio::runtime::Runtime::new()
        .expect("runtime")
        .block_on(async {
            let mut daemon = DaemonClient::connect(&home).await.expect("klavd");
            daemon.call::<Value>(request).await.map(|(v, _)| v)
        })
}

fn railway_spec() -> ProxyCredentialSpec {
    ProxyCredentialSpec {
        profile: "railway".into(),
        upstream: "https://backboard.railway.app".into(),
        header: "authorization".into(),
        prefix: "Bearer ".into(),
        methods: vec!["POST".into()],
        path_prefixes: vec!["/graphql".into()],
        ..ProxyCredentialSpec::default()
    }
}

#[test]
fn proxy_commands_need_presence_and_never_print_the_value() {
    let server = ServerProcess::start(900);
    let root = tempfile::tempdir().expect("tempdir");
    let person = Device::new(root.path(), "person");
    person.signup(&server, "ana@example.com");
    let _stop = StopDaemon(&person);
    person.unlocked(&["unlock", "--idle-lock", "10m"], "").ok();
    for title in ["Railway", "Other"] {
        person
            .run(
                &[
                    "item",
                    "add",
                    "api-key",
                    "--title",
                    title,
                    "--secret-stdin",
                    "api_key",
                ],
                &format!("{SECRET}\n"),
            )
            .ok();
    }
    let machine = Device::new(root.path(), "proxy");
    let words = machine
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
        .ok()
        .stdout
        .trim()
        .to_owned();

    let before = status(&person);
    assert_eq!(before["mode"], "none");
    assert_eq!(before["lost"].as_array().map(Vec::len), Some(5));

    // Without presence nothing changes.
    person.run(&["proxy", "use", "own", "klav-proxy"], "").err();
    assert_eq!(status(&person)["mode"], "none");
    let out = person
        .unlocked(&["proxy", "use", "own", "klav-proxy"], "")
        .ok();
    assert!(
        out.stderr.contains("Update Klav on every device"),
        "{}",
        out.stderr
    );
    let after = status(&person);
    assert_eq!(after["mode"], "own");
    assert_eq!(after["agent"]["pairing_code"], words.as_str());

    // L4-a: never approved with projects once it is the proxy.
    let out = person
        .unlocked(
            &[
                "agent",
                "approve",
                "klav-proxy",
                "--project",
                "Personal/General",
                "--words",
                &words,
            ],
            "",
        )
        .err();
    assert!(out.stderr.contains("klav proxy grant"), "{}", out.stderr);

    // klavd refuses before presence a grant built on another version, and
    // the account's first per-item grant without the acknowledgement.
    let err = raw(
        &person,
        Request::ProxyGrant {
            item: "Railway".into(),
            credential: railway_spec(),
            base_version: 7,
            every_device_updated: true,
            shown_words: Some(words.clone()),
            shown_item: None,
            password: None,
        },
    )
    .expect_err("another version");
    assert!(
        err.message.contains("changed since it was shown"),
        "{}",
        err.message
    );
    let err = raw(
        &person,
        Request::ProxyGrant {
            item: "Railway".into(),
            credential: railway_spec(),
            base_version: 0,
            every_device_updated: false,
            shown_words: Some(words.clone()),
            shown_item: None,
            password: None,
        },
    )
    .expect_err("not acknowledged");
    assert!(
        err.message.contains("--every-device-is-updated") && err.message.contains("--rotate"),
        "{}",
        err.message
    );
    // A key other than the one whose words were shown (a swap between the
    // preview and the commit looks the same to klavd): refused, even
    // with the master password, which shows no dialog.
    let err = raw(
        &person,
        Request::ProxyGrant {
            item: "Railway".into(),
            credential: railway_spec(),
            base_version: 0,
            every_device_updated: true,
            shown_words: Some("one two three four five six".into()),
            shown_item: None,
            password: Some(klav_client::ops::SecretText::new(common::PASSWORD)),
        },
    )
    .expect_err("other words");
    assert!(
        err.message.contains("not the one whose words were shown"),
        "{}",
        err.message
    );
    let err = raw(
        &person,
        Request::ProxyGrant {
            item: "Railway".into(),
            credential: railway_spec(),
            base_version: 0,
            every_device_updated: true,
            shown_words: None,
            shown_item: None,
            password: Some(klav_client::ops::SecretText::new(common::PASSWORD)),
        },
    )
    .expect_err("no words shown");
    assert!(
        err.message.contains("not the one whose words were shown"),
        "{}",
        err.message
    );
    // The item is found again by its title at the commit: another item
    // than the one the preview showed (a title changed meanwhile) is
    // refused, even with every other check right.
    let other = raw(
        &person,
        Request::ProxyGrantPreview {
            item: "Other".into(),
            credential: railway_spec(),
        },
    )
    .expect("preview");
    assert_eq!(other["place"], "Personal/General", "{other}");
    let other_id: klav_core::ids::ItemId =
        serde_json::from_value(other["item_id"].clone()).expect("item id");
    let err = raw(
        &person,
        Request::ProxyGrant {
            item: "Railway".into(),
            credential: railway_spec(),
            base_version: 0,
            every_device_updated: true,
            shown_words: Some(words.clone()),
            shown_item: Some(other_id),
            password: Some(klav_client::ops::SecretText::new(common::PASSWORD)),
        },
    )
    .expect_err("another item");
    assert!(
        err.message
            .contains("names another item than the one shown"),
        "{}",
        err.message
    );
    assert!(
        status(&person)["credentials"]
            .as_array()
            .is_some_and(Vec::is_empty)
    );

    // The first credential: the acknowledgement, the words (no terminal
    // to ask), then presence. With neither, the first refusal names both.
    let out = person.unlocked(&grant_args("Railway", "railway"), "").err();
    assert!(
        out.stderr.contains("--every-device-is-updated") && out.stderr.contains("--words"),
        "{}",
        out.stderr
    );
    let mut with_words = grant_args("Railway", "railway");
    with_words.extend(["--words", &words]);
    let out = person.unlocked(&with_words, "").err();
    assert!(
        out.stderr.contains("--every-device-is-updated"),
        "{}",
        out.stderr
    );
    let mut acknowledged = grant_args("Railway", "railway");
    acknowledged.push("--every-device-is-updated");
    let out = person.unlocked(&acknowledged, "").err();
    assert!(out.stderr.contains("--words"), "{}", out.stderr);
    let mut with_words = acknowledged.clone();
    with_words.extend(["--words", "one two three four five six"]);
    let out = person.unlocked(&with_words, "").err();
    assert!(out.stderr.contains("do not match"), "{}", out.stderr);
    let mut with_words = acknowledged.clone();
    with_words.extend(["--words", &words]);
    person.run(&with_words, "").err();
    assert!(
        status(&person)["credentials"]
            .as_array()
            .is_some_and(Vec::is_empty)
    );
    let out = person.unlocked(&with_words, "").ok();
    assert!(out.stderr.contains("→ profile railway"), "{}", out.stderr);
    assert!(
        out.stderr.contains("Railway, which also hosts apps"),
        "{}",
        out.stderr
    );
    assert!(!out.stdout.contains(SECRET) && !out.stderr.contains(SECRET));
    person.unlocked(&grant_args("Other", "other"), "").ok();
    let held = status(&person);
    assert_eq!(
        held["credentials"].as_array().map(Vec::len),
        Some(2),
        "{held}"
    );
    assert_eq!(held["credentials"][0]["profile"]["prefix"], "Bearer ");

    // Revoking needs presence too, and changes the item's key.
    person.run(&["proxy", "revoke", "Other"], "").err();
    assert_eq!(
        status(&person)["credentials"].as_array().map(Vec::len),
        Some(2)
    );
    let out = person
        .unlocked(&["proxy", "revoke", "Other", "--json"], "")
        .ok();
    let report: Value = serde_json::from_str(&out.stdout).expect("report json");
    assert_eq!(report["granted"], true, "{report}");
    assert_eq!(report["rekeyed"].as_array().map(Vec::len), Some(1));
    let out = person.unlocked(&["proxy", "revoke", "Other"], "").err();
    assert!(
        out.stderr.contains("no other agent holds it"),
        "{}",
        out.stderr
    );
    let out = person.unlocked(&["proxy", "revoke", "Railway"], "").err();
    assert!(out.stderr.contains("klav agent revoke"), "{}", out.stderr);
}

/// Registers an agent from its own machine and returns its 6 words.
fn register(root: &std::path::Path, server: &ServerProcess, name: &str) -> String {
    Device::new(root, name)
        .run(
            &[
                "agent",
                "register",
                "--name",
                name,
                "--server",
                &server.url,
                "--email",
                "ana@example.com",
                "--key-store",
                "file",
            ],
            "",
        )
        .ok()
        .stdout
        .trim()
        .to_owned()
}

#[test]
fn issuer_add_and_remove_need_presence_and_pin_what_was_shown() {
    let server = ServerProcess::start(900);
    let root = tempfile::tempdir().expect("tempdir");
    let person = Device::new(root.path(), "person");
    person.signup(&server, "ana@example.com");
    let _stop = StopDaemon(&person);
    person.unlocked(&["unlock", "--idle-lock", "10m"], "").ok();
    person
        .run(
            &[
                "item",
                "add",
                "api-key",
                "--title",
                "Railway",
                "--secret-stdin",
                "api_key",
            ],
            &format!("{SECRET}\n"),
        )
        .ok();
    let proxy_words = register(root.path(), &server, "klav-proxy");
    person
        .unlocked(&["proxy", "use", "own", "klav-proxy"], "")
        .ok();
    let mut first = grant_args("Railway", "railway");
    first.extend(["--every-device-is-updated", "--words", &proxy_words]);
    person.unlocked(&first, "").ok();
    let words = register(root.path(), &server, "t3-code");
    // No issuers yet: an empty list, never left out.
    assert_eq!(status(&person)["issuers"], serde_json::json!([]));
    let out = person.run(&["proxy", "status"], "").ok();
    assert!(
        out.stdout
            .contains("No sandbox issuers (`klav proxy issuer add`)."),
        "{}",
        out.stdout
    );
    let add = [
        "proxy",
        "issuer",
        "add",
        "t3-code",
        "--profile",
        "railway",
        "--url",
        "tls://proxy.example.com:8443",
        "--every-device-is-updated",
        "--words",
        &words,
    ];

    // klavd refuses, before presence, an issuer or proxy other than the
    // one the preview showed: agents choose their own names.
    let spec = klav_client::issuers::IssuerSpec {
        profiles: vec!["railway".into()],
        url: "tls://proxy.example.com:8443".into(),
        ..klav_client::issuers::IssuerSpec::default()
    };
    let preview = raw(
        &person,
        Request::ProxyIssuerPreview {
            agent: "t3-code".into(),
            issuer: spec.clone(),
        },
    )
    .expect("preview");
    let id = |field: &str| -> klav_core::ids::AgentId {
        serde_json::from_value(preview[field].clone()).expect("agent id")
    };
    let err = raw(
        &person,
        Request::ProxyIssuerAdd {
            agent: "t3-code".into(),
            issuer: spec,
            proxy_base_version: preview["proxy_base_version"].as_u64().expect("version"),
            issuer_base_version: 0,
            shown_issuer: id("proxy_id"),
            shown_proxy: id("proxy_id"),
            every_device_updated: true,
            shown_words: Some(words.clone()),
            password: Some(klav_client::ops::SecretText::new(common::PASSWORD)),
        },
    )
    .expect_err("another issuer");
    assert!(
        err.message.contains("another agent than the one shown"),
        "{}",
        err.message
    );

    // Without presence nothing changes; with it, both grants do.
    person.run(&add, "").err();
    let out = person.unlocked(&add, "").ok();
    assert!(
        out.stderr.contains("may start sandboxes through the proxy"),
        "{}",
        out.stderr
    );
    assert!(!out.stdout.contains(SECRET) && !out.stderr.contains(SECRET));
    // `klav proxy status` lists it, from the proxy's verified grant.
    let issuers = status(&person)["issuers"].clone();
    assert_eq!(issuers.as_array().map(Vec::len), Some(1), "{issuers}");
    assert_eq!(issuers[0]["name"], "t3-code", "{issuers}");
    assert_eq!(issuers[0]["status"], "active", "{issuers}");
    assert_eq!(issuers[0]["profiles"], serde_json::json!(["railway"]));
    assert_eq!(issuers[0]["max_live"], 3, "{issuers}");
    assert_eq!(issuers[0]["max_ttl_secs"], 8 * 3600, "{issuers}");
    let out = person.run(&["proxy", "status"], "").ok();
    assert!(
        out.stdout.contains(&format!(
            "  \"t3-code\" ({}): profiles railway; up to 3 at once, each for at most 8h",
            issuers[0]["agent_id"].as_str().expect("id")
        )),
        "{}",
        out.stdout
    );
    let out = person.unlocked(&add, "").err();
    assert!(out.stderr.contains("already an issuer"), "{}", out.stderr);

    // A re-grant under the same profile name, wider, sent straight to
    // klavd as any client of its socket can: the issuer keeps the profile
    // under the new rules, and the preview names it before presence.
    let mut wider = railway_spec();
    wider.methods = vec!["GET".into(), "POST".into(), "DELETE".into()];
    wider.path_prefixes = vec!["/".into()];
    let preview = raw(
        &person,
        Request::ProxyGrantPreview {
            item: "Railway".into(),
            credential: wider.clone(),
        },
    )
    .expect("preview");
    assert_eq!(preview["issuers_keeping"], serde_json::json!(["t3-code"]));
    assert!(
        preview["warnings"]
            .as_array()
            .is_some_and(|w| w.iter().any(|w| w
                .as_str()
                .is_some_and(|w| w.starts_with("t3-code keeps the profile railway")))),
        "{preview}"
    );
    raw(
        &person,
        Request::ProxyGrant {
            item: "Railway".into(),
            credential: wider,
            base_version: preview["base_version"].as_u64().expect("version"),
            every_device_updated: true,
            shown_words: None,
            shown_item: serde_json::from_value(preview["item_id"].clone()).expect("item"),
            password: Some(klav_client::ops::SecretText::new(common::PASSWORD)),
        },
    )
    .expect("the wider grant");
    // The CLI's preview names it too, here on a grant that narrows the
    // rules back (unchanged rules: `klav-sdk`'s issuers test).
    let mut same = grant_args("Railway", "railway");
    same.push("--every-device-is-updated");
    let out = person.unlocked(&same, "").ok();
    assert!(
        out.stderr
            .contains("t3-code keeps the profile railway, with the rules above"),
        "{}",
        out.stderr
    );

    person
        .run(&["proxy", "issuer", "remove", "t3-code"], "")
        .err();
    let out = person
        .unlocked(&["proxy", "issuer", "remove", "t3-code"], "")
        .ok();
    assert!(
        out.stderr.contains("can no longer start sandboxes")
            || out.stdout.contains("can no longer start sandboxes"),
        "{}",
        out.stderr
    );
    let out = person
        .unlocked(&["proxy", "issuer", "remove", "t3-code"], "")
        .err();
    assert!(out.stderr.contains("among the issuers"), "{}", out.stderr);
    assert_eq!(status(&person)["issuers"], serde_json::json!([]));
}

/// `klav proxy grant --preset northflank` (ADR 0036 §7, layer 10), without
/// `klavd` (`--no-daemon`): the person reads the preset's note and the
/// final profile before it signs, and the proxy's grant then holds that
/// profile: GET, PATCH and POST through, DELETE asking, every path of
/// api.northflank.com. The `maple` preset likewise: POST, GET and DELETE
/// under /mcp of api.maple.dev, none asking. A preset whose mode the proxy
/// lacks grants nothing.
#[test]
fn the_northflank_preset_shows_and_grants_its_profile() {
    let server = ServerProcess::start(900);
    let root = tempfile::tempdir().expect("tempdir");
    let person = Device::new(root.path(), "person");
    person.signup(&server, "ana@example.com");
    let _stop = StopDaemon(&person);
    person
        .unlocked(
            &[
                "--no-daemon",
                "item",
                "add",
                "api-key",
                "--title",
                "Northflank",
                "--secret-stdin",
                "api_key",
            ],
            &format!("{SECRET}\n"),
        )
        .ok();
    let words = Device::new(root.path(), "proxy")
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
        .ok()
        .stdout
        .trim()
        .to_owned();
    person
        .unlocked(&["--no-daemon", "proxy", "use", "own", "klav-proxy"], "")
        .ok();

    // Presets without their mode, and unknown ones, are usage errors
    // (exit code 2) that grant nothing.
    for (name, says) in [
        ("railway", "mode (b)"),
        ("heroku", "the presets are northflank, maple"),
    ] {
        let refused = person
            .unlocked(
                &[
                    "--no-daemon",
                    "proxy",
                    "grant",
                    "Northflank",
                    "--preset",
                    name,
                ],
                "",
            )
            .err();
        assert_eq!(refused.code, 2, "{name}: {}", refused.stderr);
        assert!(refused.stderr.contains(says), "{name}: {}", refused.stderr);
    }

    let out = person
        .unlocked(
            &[
                "--no-daemon",
                "proxy",
                "grant",
                "Northflank",
                "--preset",
                "northflank",
                "--every-device-is-updated",
                "--words",
                &words,
            ],
            "",
        )
        .ok();
    assert!(!out.stdout.contains(SECRET) && !out.stderr.contains(SECRET));
    let shown = &out.stderr;
    let note = shown.find("The northflank preset").expect("the note");
    let profile = shown.find("→ profile northflank").expect("the profile");
    assert!(note < profile, "the note comes before the profile: {shown}");
    for line in [
        "upstream  https://api.northflank.com",
        "header    authorization: Bearer <value>",
        "allow     GET,PATCH,POST api.northflank.com /",
        "ask       DELETE api.northflank.com /",
        "PUT and every other method are refused",
        "Nothing in it guards role or token changes by path",
    ] {
        assert!(shown.contains(line), "{line:?} in {shown}");
    }

    // The MCP gate's preset (ADR 0036 §7, note of 2026-11-19).
    person
        .unlocked(
            &[
                "--no-daemon",
                "item",
                "add",
                "api-key",
                "--title",
                "Maple",
                "--secret-stdin",
                "api_key",
            ],
            "maple_ak_0123456789abcdef0123456789\n",
        )
        .ok();
    let out = person
        .unlocked(
            &[
                "--no-daemon",
                "proxy",
                "grant",
                "Maple",
                "--preset",
                "maple",
                "--every-device-is-updated",
                "--words",
                &words,
            ],
            "",
        )
        .ok();
    let shown = &out.stderr;
    assert!(!shown.contains("maple_ak_0123456789") && !out.stdout.contains("maple_ak_0123456789"));
    let note = shown.find("The maple preset").expect("the note");
    let profile = shown.find("→ profile maple").expect("the profile");
    assert!(note < profile, "the note comes before the profile: {shown}");
    for line in [
        "upstream  https://api.maple.dev",
        "header    authorization: Bearer <value>",
        "allow     DELETE,GET,POST api.maple.dev /mcp",
        "read-only key that expires within 90 days",
    ] {
        assert!(shown.contains(line), "{line:?} in {shown}");
    }
    assert!(!shown.contains("ask       "), "nothing asks: {shown}");

    let after: Value = serde_json::from_str(
        &person
            .unlocked(&["--no-daemon", "proxy", "status", "--json"], "")
            .ok()
            .stdout,
    )
    .expect("status json");
    let credentials = after["credentials"].as_array().expect("credentials");
    assert_eq!(credentials.len(), 2, "{after}");
    let maple = credentials
        .iter()
        .find(|c| c["profile"]["name"] == "maple")
        .expect("maple");
    assert_eq!(maple["profile"]["upstream"], "https://api.maple.dev");
    assert_eq!(maple["profile"]["prefix"], "Bearer ");
    let credentials: Vec<&Value> = credentials
        .iter()
        .filter(|c| c["profile"]["name"] == "northflank")
        .collect();
    let profile = &credentials[0]["profile"];
    assert_eq!(profile["name"], "northflank");
    assert_eq!(profile["upstream"], "https://api.northflank.com");
    assert_eq!(profile["header"], "authorization");
    assert_eq!(profile["prefix"], "Bearer ");
    let rules: Vec<(String, Vec<String>)> = credentials[0]["rules"]
        .as_array()
        .expect("rules")
        .iter()
        .map(|r| {
            (
                r["effect"].as_str().unwrap_or_default().to_owned(),
                serde_json::from_value(r["methods"].clone()).expect("methods"),
            )
        })
        .collect();
    assert!(
        rules.contains(&(
            "allow".into(),
            vec!["GET".into(), "PATCH".into(), "POST".into()]
        )),
        "{rules:?}"
    );
    assert!(
        rules.contains(&("ask".into(), vec!["DELETE".into()])),
        "{rules:?}"
    );
}

/// Klav Cloud's proxy (ADR 0051 §9, §14): this build pins the release
/// authority's keys, so `klav proxy use klav` asks the server whether the
/// account is entitled, and refuses one that isn't before it sends anything
/// to Klav Cloud (the endpoint here answers nothing), through klavd and
/// directly, and the setting stays. The other `cloud` commands need an
/// account that uses it.
#[test]
fn use_klav_refuses_an_account_without_the_entitlement() {
    let server = ServerProcess::start(900);
    let root = tempfile::tempdir().expect("tempdir");
    let person = Device::new(root.path(), "person");
    person.signup(&server, "kim@example.com");
    let _stop = StopDaemon(&person);
    // Through klavd.
    person.unlocked(&["unlock", "--idle-lock", "10m"], "").ok();
    let refused = person.unlocked(&["proxy", "use", "klav"], "").err();
    assert_eq!(refused.code, 1, "{}", refused.stderr);
    assert!(
        refused
            .stderr
            .contains("isn't entitled to Klav Cloud's proxy"),
        "{}",
        refused.stderr
    );
    assert_eq!(status(&person)["mode"], "none");
    let refused = raw(
        &person,
        Request::ProxyCloud {
            action: klav_client::hosted_proxy::CloudAction::Use,
            password: None,
        },
    )
    .expect_err("not entitled");
    assert!(refused.message.contains("isn't entitled"), "{refused:?}");
    // Without klavd.
    person.run(&["lock", "--stop"], "").ok();
    let mut direct = person.command();
    let out = direct
        .env("KLAV_NO_DAEMON", "1")
        .env("KLAV_HOSTED_PROXY_URL", "http://127.0.0.1:9")
        .args(["--password-stdin", "proxy", "use", "klav"])
        .spawn()
        .expect("spawn");
    let mut out = out;
    {
        use std::io::Write;
        out.stdin
            .take()
            .expect("stdin")
            .write_all(format!("{}\n", common::PASSWORD).as_bytes())
            .expect("password");
    }
    let out = out.wait_with_output().expect("wait");
    assert_eq!(
        out.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("isn't entitled to Klav Cloud's proxy"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    // Usage and state errors.
    person.unlocked(&["unlock", "--idle-lock", "10m"], "").ok();
    person
        .unlocked(&["proxy", "use", "klav", "some-agent"], "")
        .err();
    let not_used = person.unlocked(&["proxy", "cloud", "stop"], "").err();
    assert!(
        not_used.stderr.contains("doesn't use Klav Cloud's proxy"),
        "{}",
        not_used.stderr
    );
    let not_used = person.unlocked(&["proxy", "cloud", "status"], "").err();
    assert!(
        not_used.stderr.contains("`klav proxy use klav`"),
        "{}",
        not_used.stderr
    );
    assert_eq!(status(&person)["mode"], "none");
}
