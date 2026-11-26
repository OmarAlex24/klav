//! The MCP gateway from the person's CLI (ADR 0049, layer 5), through
//! `klavd` (Touch ID is off in tests, so the master password): `klav proxy
//! grant --mcp-url --tools-…` shows every pattern and needs the person's
//! word that every device is updated; the gateway's presets are refused
//! until hand-tested; `klav client connect cursor --mcp` signs a local
//! client token's digest and writes the entry with a backup, never
//! printing the token; the proxy takes that token and refuses another;
//! `klav sandbox start` writes the client lines of a custom MCP profile;
//! and `klav client disconnect --mcp` takes it all back.

mod common;

use std::path::Path;
use std::time::Duration;

use common::{Device, PASSWORD, ServerProcess};
use klav_client::Home;
use serde_json::Value;

const SECRET: &str = "MARKER-acme-mcp-key-0123456789";

/// Stops the daemon even if the test fails.
struct StopDaemon(Device);

impl Drop for StopDaemon {
    fn drop(&mut self) {
        let _ = self.0.run(&["lock", "--stop"], "");
    }
}

fn register(root: &Path, server: &ServerProcess, name: &str) -> String {
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

/// `klav --password-stdin <args>` with `$HOME` at `home`: the clients'
/// settings live there.
fn at_home(dev: &Device, home: &Path, args: &[&str]) -> common::Run {
    use std::io::Write;
    let mut cmd = dev.command();
    cmd.env("HOME", home)
        .env_remove("CODEX_HOME")
        .env_remove("CLAUDE_CONFIG_DIR")
        .arg("--password-stdin")
        .args(args);
    let mut child = cmd.spawn().expect("spawn klav");
    let _ = child
        .stdin
        .take()
        .expect("stdin")
        .write_all(format!("{PASSWORD}\n").as_bytes());
    let out = child.wait_with_output().expect("wait");
    common::Run {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8(out.stdout).expect("utf-8"),
        stderr: String::from_utf8(out.stderr).expect("utf-8"),
    }
}

fn status(person: &Device) -> Value {
    let out = person.run(&["proxy", "status", "--json"], "").ok();
    assert!(!out.stdout.contains(SECRET) && !out.stderr.contains(SECRET));
    serde_json::from_str(&out.stdout).expect("status json")
}

/// The token Cursor's entry carries, read back from its file.
fn cursor_token(home: &Path) -> Option<String> {
    let text = std::fs::read_to_string(home.join(".cursor/mcp.json")).ok()?;
    let v: Value = serde_json::from_str(
        &text
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n"),
    )
    .ok()?;
    v["mcpServers"]["acme-ops"]["headers"]["Authorization"]
        .as_str()
        .and_then(|b| b.strip_prefix("Bearer "))
        .map(str::to_owned)
}

#[test]
fn the_mcp_gateway_from_the_persons_cli() {
    let server = ServerProcess::start(900);
    let root = tempfile::tempdir().expect("tempdir");
    let person = Device::new(root.path(), "person");
    person.signup(&server, "ana@example.com");
    let _stop = StopDaemon(Device::new(root.path(), "person"));
    person.unlocked(&["unlock", "--idle-lock", "10m"], "").ok();
    person
        .run(
            &[
                "item",
                "add",
                "api-key",
                "--title",
                "Acme",
                "--secret-stdin",
                "api_key",
            ],
            &format!("{SECRET}\n"),
        )
        .ok();
    let words = register(root.path(), &server, "klav-proxy");
    person
        .unlocked(&["proxy", "use", "own", "klav-proxy"], "")
        .ok();

    // 1. The gateway's presets: refused until hand-tested, saying how to
    // grant by hand. Nothing is signed.
    for preset in ["github", "stripe"] {
        let out = person
            .unlocked(&["proxy", "grant", "Acme", "--preset", preset], "")
            .err();
        assert!(
            out.stderr.contains("hand test") && out.stderr.contains("--mcp-url"),
            "{}",
            out.stderr
        );
    }

    let grant = [
        "proxy",
        "grant",
        "Acme",
        "--profile",
        "acme-ops",
        "--mcp-url",
        "https://mcp.acme.invalid/v1/mcp",
        "--tools-allow",
        "get_*,list_*",
        "--tools-ask",
        "delete_*",
        "--tools-deny",
        "create_api_key",
        "--words",
        &words,
    ];
    // 2. Without the word that every device is updated: the sheet shows
    // every pattern and the warning, and nothing is signed.
    let out = person.unlocked(&grant, "").err();
    for shown in [
        "mcp       https://mcp.acme.invalid/v1/mcp",
        "tools allow get_*, list_*",
        "tools ask   delete_*",
        "tools deny  create_api_key",
        "tools other denied and hidden",
        "older than the MCP gateway",
        "--every-device-is-updated",
    ] {
        assert!(out.stderr.contains(shown), "{shown}: {}", out.stderr);
    }
    assert!(!out.stderr.contains(SECRET));
    assert!(
        status(&person)["credentials"]
            .as_array()
            .expect("list")
            .is_empty()
    );

    // 3. With it: signed, and the account's MCP gateway is on.
    let mut acked = grant.to_vec();
    acked.push("--every-device-is-updated");
    let out = person.unlocked(&acked, "").ok();
    assert!(!out.stdout.contains(SECRET) && !out.stderr.contains(SECRET));
    let s = status(&person);
    let credential = &s["credentials"][0];
    assert_eq!(credential["profile"]["mcp"]["endpoint"], "/v1/mcp");
    let tools: Vec<Value> = credential["rules"]
        .as_array()
        .expect("rules")
        .iter()
        .map(|r| r["mcp_tools"].clone())
        .collect();
    assert_eq!(
        tools,
        [
            Value::Null,
            serde_json::json!(["get_*", "list_*"]),
            serde_json::json!(["delete_*"]),
            serde_json::json!(["create_api_key"]),
        ]
    );

    // 4. `klav client connect cursor --mcp`: the plan first, then the
    // grant, then the entry, with a backup; the token is never printed.
    let home = root.path().join("home");
    std::fs::create_dir_all(home.join(".cursor")).expect("cursor dir");
    let original = "{\n  // mine\n  \"mcpServers\": {\n    \"other\": { \"command\": \"other-mcp\" }\n  }\n}\n";
    std::fs::write(home.join(".cursor/mcp.json"), original).expect("settings");
    let dry = at_home(
        &person,
        &home,
        &[
            "client",
            "connect",
            "cursor",
            "--mcp",
            "acme-ops",
            "--dry-run",
        ],
    )
    .ok();
    assert!(
        dry.stderr
            .contains("acme-ops      http://127.0.0.1:8790/acme-ops/v1/mcp  (add)"),
        "{}",
        dry.stderr
    );
    assert_eq!(
        std::fs::read_to_string(home.join(".cursor/mcp.json")).expect("read"),
        original
    );
    // A profile that is not one of the proxy's MCP profiles: refused.
    let out = at_home(
        &person,
        &home,
        &["client", "connect", "cursor", "--mcp", "nope", "--yes"],
    )
    .err();
    assert!(
        out.stderr.contains("is not an MCP profile"),
        "{}",
        out.stderr
    );
    let out = at_home(
        &person,
        &home,
        &[
            "client",
            "connect",
            "cursor",
            "--mcp",
            "acme-ops",
            "--proxy-port",
            "18790",
            "--yes",
        ],
    )
    .ok();
    let token = cursor_token(&home).expect("the entry's token");
    assert!(token.starts_with("klc1_") && token.len() == 5 + 44, "shape");
    assert!(!out.stdout.contains(&token) && !out.stderr.contains(&token));
    assert!(!out.stderr.contains(SECRET));
    let written = std::fs::read_to_string(home.join(".cursor/mcp.json")).expect("read");
    assert!(written.contains("// mine") && written.contains("\"other\""));
    assert!(written.contains("http://127.0.0.1:18790/acme-ops/v1/mcp"));
    assert!(!written.contains(SECRET), "never the provider's key");
    let backups: Vec<_> = std::fs::read_dir(person.home.join("client-backups/cursor"))
        .expect("backups")
        .flatten()
        .collect();
    assert_eq!(backups.len(), 1);
    assert_eq!(
        std::fs::read_to_string(backups[0].path()).expect("backup"),
        original
    );
    let s = status(&person);
    assert_eq!(s["local_clients"][0]["name"], "cursor");
    assert_eq!(s["local_clients"][0]["profiles"][0], "acme-ops");
    assert!(!serde_json::to_string(&s).expect("json").contains("klc1_"));

    // 5. An issuer whose sandboxes may use the MCP profile.
    let t3 = register(root.path(), &server, "t3-code");
    person
        .unlocked(
            &[
                "proxy",
                "issuer",
                "add",
                "t3-code",
                "--profile",
                "acme-ops",
                "--url",
                "tls://proxy.example.com:8443",
                "--every-device-is-updated",
                "--words",
                &t3,
            ],
            "",
        )
        .ok();

    // 6. The proxy, in this process, with the grant as signed: Cursor's
    // token passes the local client check (the upstream does not exist,
    // so the call fails later); another token gets `401`.
    let runtime = tokio::runtime::Runtime::new().expect("runtime");
    let bound = runtime
        .block_on(klav_proxy::app::bind(klav_proxy::app::ServeOptions {
            home: Home::at(root.path().join("klav-proxy")),
            name: "klav-proxy".into(),
            port: 0,
            channel: None,
            max_body: klav_proxy::proxy::DEFAULT_MAX_BODY,
            request_timeout: Duration::from_secs(30),
            no_local_calls: false,
            control_socket: klav_proxy::app::ControlSocket::Off,
            env: klav_proxy::app::StartEnv::default(),
        }))
        .expect("proxy");
    let port = bound.port();
    runtime.spawn(bound.run(std::future::pending()));
    let init = r#"{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}"#;
    // Plain HTTP/1.1 on loopback, as an MCP client sends it.
    let post = |bearer: &str| {
        use std::io::{Read, Write};
        let mut tcp = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect");
        tcp.set_read_timeout(Some(Duration::from_secs(60)))
            .expect("timeout");
        let request = format!(
            "POST /acme-ops/v1/mcp HTTP/1.1\r\nhost: 127.0.0.1:{port}\r\ncontent-type: application/json\r\naccept: application/json, text/event-stream\r\nauthorization: Bearer {bearer}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{init}",
            init.len()
        );
        tcp.write_all(request.as_bytes()).expect("write");
        let mut answer = String::new();
        let _ = tcp.read_to_string(&mut answer);
        let status: u16 = answer
            .split(' ')
            .nth(1)
            .and_then(|c| c.parse().ok())
            .unwrap_or(0);
        let error = answer
            .lines()
            .take_while(|l| !l.is_empty())
            .find_map(|l| {
                l.to_ascii_lowercase()
                    .strip_prefix("klav-error: ")
                    .map(|v| v.trim().to_owned())
            })
            .unwrap_or_default();
        (status, error)
    };
    let (status_code, error) = post(&token);
    assert_ne!(error, "klav_local_client_unknown", "{status_code}");
    assert_ne!(status_code, 401);
    let other = klav_core::crypto::mcp::LocalClientToken::generate();
    assert_eq!(
        post(other.expose()),
        (401, "klav_local_client_unknown".to_owned())
    );

    // 7. `klav sandbox start` for the MCP profile: its client lines point
    // at its own variable and endpoint, not at `maple`'s.
    let issuer = Device::new(root.path(), "t3-code");
    let work = tempfile::tempdir().expect("work");
    let pkg = work.path().join("pkg");
    let port_s = port.to_string();
    let out = issuer
        .run(
            &[
                "sandbox",
                "start",
                "--label",
                "ops-1",
                "--profile",
                "acme-ops",
                "--proxy-port",
                &port_s,
                "--package-file",
                pkg.to_str().expect("path"),
                "--json",
            ],
            "",
        )
        .ok();
    let started: Value = serde_json::from_str(&out.stdout).expect("start json");
    let setup: Vec<&str> = started["setup"]
        .as_array()
        .expect("setup")
        .iter()
        .map(|l| l.as_str().expect("line"))
        .collect();
    assert!(
        setup.iter().any(|l| l.contains(
            "claude mcp add --transport http --scope user acme-ops \"$KLAV_FORWARD_ACME_OPS_URL/v1/mcp\""
        )),
        "{setup:?}"
    );
    assert!(
        setup
            .iter()
            .any(|l| l
                .contains("codex mcp add acme-ops --url \"$KLAV_FORWARD_ACME_OPS_URL/v1/mcp\"")),
        "{setup:?}"
    );
    assert!(!setup.iter().any(|l| l.contains("maple")), "{setup:?}");
    let id = started["sandbox_id"].as_str().expect("id").to_owned();
    issuer
        .run(&["sandbox", "stop", &id, "--proxy-port", &port_s], "")
        .ok();

    // 8. `klav client disconnect cursor --mcp`: the grant first, then the
    // entry; the other server and the comment stay.
    let out = at_home(
        &person,
        &home,
        &["client", "disconnect", "cursor", "--mcp", "--yes"],
    )
    .ok();
    assert!(out.stderr.contains("acme-ops"), "{}", out.stderr);
    let after = std::fs::read_to_string(home.join(".cursor/mcp.json")).expect("read");
    assert!(
        !after.contains("acme-ops") && !after.contains("klc1_"),
        "{after}"
    );
    assert!(
        after.contains("// mine") && after.contains("\"other\""),
        "{after}"
    );
    let s = status(&person);
    assert!(s.get("local_clients").is_none(), "{s}");
    drop(runtime);
}
