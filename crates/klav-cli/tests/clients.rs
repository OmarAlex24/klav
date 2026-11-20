//! `klav client` and `klav skill` (ADR 0033 §1–§6) against a made-up Mac:
//! a temporary `HOME`, `CODEX_HOME` and system root, fixture settings, and
//! stand-ins for `claude` and `codex` that record their arguments. `PATH`
//! holds only the stand-ins and `/usr/bin:/bin`, and Klav looks for client
//! programs in those two under the system root: a `code` or `cursor` the
//! machine has never makes a client look installed, the real client CLIs
//! are never run, and no real settings are read or written. The stand-ins
//! themselves run with that `PATH` and find `sh`, `cp` and `grep` as usual.

mod common;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use common::{Device, PASSWORD, Run, ServerProcess};
use serde_json::{Value, json};

const SKILL: &str = include_str!("../../../skill/SKILL.md");
const LEGACY_SKILL: &str = include_str!("fixtures/skill-0.1.0.md");
const SYSTEM_PATH: &str = "/usr/bin:/bin";

struct Mac {
    _root: tempfile::TempDir,
    root: PathBuf,
    home: PathBuf,
    codex: PathBuf,
    sys: PathBuf,
    /// The stand-ins' folder, and what they play and record.
    fakes: PathBuf,
    plays: PathBuf,
    device: Device,
    path: String,
}

impl Mac {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().to_path_buf();
        let mac = Self {
            home: root.join("home"),
            codex: root.join("home/.codex"),
            sys: root.join("sys"),
            fakes: root.join("bin"),
            plays: root.join("plays"),
            device: Device::new(&root, "klav"),
            path: SYSTEM_PATH.to_owned(),
            root,
            _root: dir,
        };
        for d in [&mac.home, &mac.sys, &mac.fakes, &mac.plays] {
            std::fs::create_dir_all(d).expect("mkdir");
        }
        mac
    }

    fn run(&self, args: &[&str], stdin: &str) -> Run {
        self.run_with(args, stdin, |_| {})
    }

    /// [`Self::run`], with `tweak` applied to the command last.
    fn run_with(&self, args: &[&str], stdin: &str, tweak: impl FnOnce(&mut Command)) -> Run {
        let mut cmd = self.device.command();
        cmd.env("HOME", &self.home)
            .env("CODEX_HOME", &self.codex)
            .env("KLAV_SYSTEM_ROOT", &self.sys)
            .env("PATH", &self.path)
            .env_remove("CLAUDE_CONFIG_DIR")
            .env_remove("XDG_CONFIG_HOME")
            .stdin(Stdio::piped());
        tweak(&mut cmd);
        let mut child = cmd.args(args).spawn().expect("spawn klav");
        // A command that exits without reading its input closes the pipe
        // first: not a failure of the test, which checks the result below.
        match child
            .stdin
            .take()
            .expect("stdin")
            .write_all(stdin.as_bytes())
        {
            Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {}
            other => other.expect("stdin"),
        }
        let out = child.wait_with_output().expect("wait");
        Run {
            code: out.status.code().unwrap_or(-1),
            stdout: String::from_utf8(out.stdout).expect("utf-8"),
            stderr: String::from_utf8(out.stderr).expect("utf-8"),
        }
    }

    fn klav(&self, args: &[&str]) -> Run {
        self.run(args, "")
    }

    fn json(&self, args: &[&str]) -> Value {
        let out = self.klav(args).ok();
        serde_json::from_str(&out.stdout).unwrap_or_else(|e| panic!("{e}: {}", out.stdout))
    }

    fn unlocked(&self, args: &[&str]) -> Run {
        let mut all = vec!["--password-stdin"];
        all.extend_from_slice(args);
        self.run(&all, &format!("{PASSWORD}\n"))
    }

    fn signup(&self, server: &ServerProcess) {
        let kit = self.root.join("kit.txt");
        self.unlocked(&[
            "signup",
            "--server",
            &server.url,
            "--email",
            "ana@example.com",
            "--device-name",
            "test",
            "--emergency-kit",
            kit.to_str().expect("utf-8"),
        ])
        .ok();
    }

    /// Puts a stand-in for `name` first on `PATH`. It records its
    /// arguments and, for `mcp add` / `mcp remove`, copies over `target`
    /// (as the real CLI would rewrite it) `plays/<name>-add-<agent>` (the
    /// last argument) or `plays/<name>-add`, and `plays/<name>-remove`.
    /// `plays/<name>-fail` makes every call fail, `plays/<name>-fail-add-once`
    /// the next `add` (before writing), and `plays/<name>-fail-after-add-once`
    /// the next `add` right after it wrote, as a tool that writes and then
    /// errors (or is killed) would. A failing stand-in prints a marker on
    /// stderr that Klav must never pass on.
    ///
    /// The stand-in for `claude` parses `mcp add` as Claude Code does (its
    /// MCP docs): `--env` takes every value up to the next option or `--`,
    /// so a server name right after it is read as another `KEY=value` pair
    /// and refused; the name and a command after `--` are required. Like
    /// Claude Code, it refuses to add a server whose name is already there.
    fn fake(&mut self, name: &str, target: &Path) {
        const CLAUDE_ADD: &str = r#"
    shift 2; name=''; env_open=0; cmd=''
    while [ $# -gt 0 ]; do
      case "$1" in
        --) shift; cmd="${1:-}"; break ;;
        --scope|-s|--transport|-t) env_open=0; shift ;;
        --env|-e) env_open=1 ;;
        -*) echo "error: unknown option '$1'" >&2; exit 1 ;;
        *)
          if [ "$env_open" = 1 ]; then
            case "$1" in
              [A-Za-z_]*=*) ;;
              *) echo "Invalid environment variable format: $1, environment variables should be added as: -e KEY1=value1 -e KEY2=value2" >&2; exit 1 ;;
            esac
          elif [ -n "$name" ]; then echo "error: too many arguments before --" >&2; exit 1
          else name="$1"; fi ;;
      esac
      shift
    done
    if [ -z "$name" ]; then echo "error: missing required argument 'name'" >&2; exit 1; fi
    if [ -z "$cmd" ]; then echo "error: no command after --" >&2; exit 1; fi
    if [ -f '@TARGET@' ] && grep -q "\"$name\":" '@TARGET@'; then
      echo "MCP server $name already exists in user config" >&2; exit 1
    fi"#;
        const SCRIPT: &str = r#"#!/bin/sh
for a in "$@"; do printf '%s\n' "$a" >> '@PLAYS@/@NAME@.log'; done
printf '%s\n' '<end>' >> '@PLAYS@/@NAME@.log'
if [ -f '@PLAYS@/@NAME@-fail' ]; then echo 'stand-in @NAME@ refused: ghp_tool_stderr' >&2; exit 1; fi
for last in "$@"; do :; done
sub="$2"
case "$sub" in
  add)
    if [ -f '@PLAYS@/@NAME@-fail-add-once' ]; then
      rm '@PLAYS@/@NAME@-fail-add-once'; echo 'stand-in @NAME@ add refused: ghp_tool_stderr' >&2; exit 1
    fi
@VALIDATE@
    src='@PLAYS@/@NAME@-add'
    if [ -f "@PLAYS@/@NAME@-add-$last" ]; then src="@PLAYS@/@NAME@-add-$last"; fi ;;
  remove) src='@PLAYS@/@NAME@-remove' ;;
  *) exit 0 ;;
esac
if [ -f "$src" ]; then cp "$src" '@TARGET@'; fi
if [ "$sub" = add ] && [ -f '@PLAYS@/@NAME@-fail-after-add-once' ]; then
  rm '@PLAYS@/@NAME@-fail-after-add-once'; echo 'stand-in @NAME@ wrote, then failed: ghp_tool_stderr' >&2; exit 1
fi
"#;
        let script = SCRIPT
            .replace("@VALIDATE@", if name == "claude" { CLAUDE_ADD } else { "" })
            .replace("@PLAYS@", &self.plays.display().to_string())
            .replace("@NAME@", name)
            .replace("@TARGET@", &target.display().to_string());
        let path = self.fakes.join(name);
        std::fs::write(&path, script).expect("write fake");
        set_mode(&path, 0o755);
        self.path = format!("{}:{SYSTEM_PATH}", self.fakes.display());
    }

    fn play(&self, file: &str, text: &str) {
        std::fs::write(self.plays.join(file), text).expect("play");
    }

    /// The calls a stand-in got, each as its arguments.
    fn calls(&self, name: &str) -> Vec<Vec<String>> {
        let log =
            std::fs::read_to_string(self.plays.join(format!("{name}.log"))).unwrap_or_default();
        let mut out = vec![Vec::new()];
        for line in log.lines() {
            if line == "<end>" {
                out.push(Vec::new());
            } else {
                out.last_mut().expect("call").push(line.to_owned());
            }
        }
        out.pop();
        out
    }

    fn skill_copy(&self, dir: &str) -> PathBuf {
        self.home.join(dir).join("skills/klav/SKILL.md")
    }

    /// `clients.json` (`{}` before Klav wrote one).
    fn registry(&self) -> Value {
        let path = self.device.home.join("clients.json");
        if !path.exists() {
            return json!({});
        }
        serde_json::from_slice(
            &std::fs::read(self.device.home.join("clients.json")).expect("clients.json"),
        )
        .expect("json")
    }
}

fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("chmod");
}

fn klav_exe() -> String {
    std::fs::canonicalize(env!("CARGO_BIN_EXE_klav"))
        .expect("klav")
        .display()
        .to_string()
}

/// Makes the pending registrations of agent `name` lapse, in the server's
/// SQLite database. `false` without the `sqlite3` program.
fn lapse(server: &ServerProcess, name: &str) -> bool {
    let sql = format!(
        "PRAGMA busy_timeout = 5000; UPDATE agents SET expires_at = 1 WHERE name = '{name}' AND status = 'pending';"
    );
    match Command::new("sqlite3")
        .arg(server.dir.path().join("klav.db"))
        .arg(sql)
        .output()
    {
        Ok(out) => {
            assert!(
                out.status.success(),
                "sqlite3: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            true
        }
        Err(_) => {
            eprintln!("no sqlite3 here: the lapsed request is not checked");
            false
        }
    }
}

fn row<'a>(list: &'a Value, client: &str) -> &'a Value {
    list["clients"]
        .as_array()
        .expect("clients")
        .iter()
        .find(|r| r["id"] == client)
        .expect("row")
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

const CURSOR_SETTINGS: &str = r#"{
  // servers I use
  "mcpServers": {
    "github": {
      "command": "npx",
      "env": { "GITHUB_TOKEN": "ghp_do_not_show" }, // mine
    },
  },
  "theme": "dark",
}
"#;

/// Cursor (a JSONC file behind a link into a dotfiles repository): the
/// plan, the confirmation, the edit that keeps everything else, backups,
/// a changed entry, restore, a person's entry, disconnect and a denied
/// agent.
#[test]
fn cursor_settings_are_edited_in_place_and_restored() {
    let server = ServerProcess::start(900);
    let mac = Mac::new();
    mac.signup(&server);
    let dotfiles = mac.root.join("dotfiles");
    std::fs::create_dir_all(dotfiles.join(".git")).expect("repo");
    let real = dotfiles.join("cursor-mcp.json");
    std::fs::write(&real, CURSOR_SETTINGS).expect("settings");
    set_mode(&real, 0o640);
    std::fs::create_dir_all(mac.home.join(".cursor")).expect("cursor");
    let link = mac.home.join(".cursor/mcp.json");
    std::os::unix::fs::symlink(&real, &link).expect("link");

    // `agent register --json` (for the Mac app) on another name.
    let registered = mac.json(&[
        "agent",
        "register",
        "--name",
        "extra",
        "--key-store",
        "file",
        "--json",
    ]);
    assert_eq!(registered["name"], "extra");
    assert_eq!(
        registered["pairing_code"]
            .as_str()
            .expect("words")
            .split(' ')
            .count(),
        6
    );
    assert!(
        registered["public_identity"]
            .as_str()
            .is_some_and(|s| s.len() > 40),
        "{registered}"
    );
    assert!(
        registered["agent_id"].is_string() && registered["expires_at"].is_i64(),
        "{registered}"
    );

    // The list shows where, never other servers' values.
    let out = mac.klav(&["client", "list", "--json"]).ok();
    assert!(!out.stdout.contains("ghp_do_not_show"), "{}", out.stdout);
    let list: Value = serde_json::from_str(&out.stdout).expect("json");
    let cursor = row(&list, "cursor");
    assert_eq!(cursor["state"], "not_connected", "{cursor}");
    assert_eq!(
        cursor["config"]["link_to"],
        real.canonicalize().expect("real").display().to_string()
    );
    assert_eq!(cursor["method"], "file");
    assert!(list["checked"].is_string());

    // Without a terminal and without --yes nothing happens.
    let out = mac
        .klav(&["client", "connect", "cursor", "--key-store", "file"])
        .err();
    assert!(out.stderr.contains("--yes"), "{}", out.stderr);
    assert_eq!(read(&real), CURSOR_SETTINGS);
    assert!(!mac.device.home.join("agents/cursor.json").exists());

    // The plan, then a write bound to the file it showed.
    let plan = mac.json(&["client", "connect", "cursor", "--dry-run", "--json"]);
    assert_eq!(plan["mcp"]["action"], "add", "{plan}");
    assert_eq!(plan["agent"]["registers"], true);
    let sha = plan["mcp"]["file_sha256"].as_str().expect("sha").to_owned();
    let out = mac
        .klav(&[
            "client",
            "connect",
            "cursor",
            "--yes",
            "--key-store",
            "file",
            "--expect-sha256",
            "00",
        ])
        .err();
    assert!(
        out.stderr.contains("changed since the summary"),
        "{}",
        out.stderr
    );
    assert_eq!(read(&real), CURSOR_SETTINGS);

    let done = mac.json(&[
        "client",
        "connect",
        "cursor",
        "--yes",
        "--json",
        "--key-store",
        "file",
        "--expect-sha256",
        &sha,
    ]);
    let words = done["agent"]["words"].as_str().expect("words").to_owned();
    assert_eq!(words.split(' ').count(), 6);
    assert_eq!(done["agent"]["status"], "pending");
    let next = done["next"].as_str().expect("next");
    assert!(
        next.contains(&words) && next.contains("agent status --agent cursor --wait"),
        "{next}"
    );
    assert!(
        done["warnings"]
            .as_array()
            .expect("warnings")
            .iter()
            .any(|w| w.as_str().is_some_and(|w| w.contains("git repository"))),
        "{done}"
    );
    // Only Klav's member was added; the link is still a link.
    assert!(
        std::fs::symlink_metadata(&link)
            .expect("link")
            .file_type()
            .is_symlink()
    );
    let edited = read(&real);
    for kept in [
        "// servers I use",
        r#""env": { "GITHUB_TOKEN": "ghp_do_not_show" }, // mine"#,
        r#""theme": "dark","#,
    ] {
        assert!(edited.contains(kept), "{edited}");
    }
    assert_eq!(common::mode(&real), 0o640);
    let klav: Value = json5_entry(&edited);
    assert_eq!(klav["type"], "stdio");
    assert_eq!(klav["command"], klav_exe());
    assert_eq!(klav["args"], json!(["mcp", "--agent", "cursor"]));
    assert_eq!(
        klav["env"]["KLAV_HOME"],
        mac.device.home.display().to_string()
    );
    // A backup of what was there, private.
    let backups = mac.device.home.join("client-backups/cursor");
    assert_eq!(common::mode(&backups), 0o700);
    let copies: Vec<PathBuf> = std::fs::read_dir(&backups)
        .expect("backups")
        .map(|e| e.expect("e").path())
        .collect();
    assert_eq!(copies.len(), 1);
    assert_eq!(read(&copies[0]), CURSOR_SETTINGS);
    assert_eq!(common::mode(&copies[0]), 0o600);
    // The skill, and the record.
    assert_eq!(read(&mac.skill_copy(".agents")), SKILL);
    assert_eq!(common::mode(&mac.device.home.join("clients.json")), 0o600);
    assert_eq!(mac.registry()["clients"]["cursor"]["agent"], "cursor");
    let list = mac.json(&["client", "list", "--json"]);
    assert_eq!(row(&list, "cursor")["state"], "connected");

    // Again while pending: the same agent and words, nothing new.
    let again = mac.json(&[
        "client",
        "connect",
        "cursor",
        "--yes",
        "--json",
        "--key-store",
        "file",
    ]);
    assert_eq!(again["mcp"]["action"], "keep");
    assert_eq!(again["agent"]["id"], done["agent"]["id"]);
    assert_eq!(again["agent"]["words"], words.as_str());

    // A relative KLAV_HOME goes into the entry absolute: the client starts
    // `klav mcp` from another folder.
    let cwd = mac.root.canonicalize().expect("root");
    let out = mac
        .run_with(
            &["client", "connect", "cursor", "--dry-run", "--json"],
            "",
            |cmd| {
                cmd.current_dir(&cwd).env("KLAV_HOME", "klav");
            },
        )
        .ok();
    let plan: Value = serde_json::from_str(&out.stdout).expect("json");
    assert_eq!(
        plan["mcp"]["after"]["env"]["KLAV_HOME"],
        cwd.join("klav").display().to_string(),
        "{plan}"
    );

    // The person changes the entry: Klav no longer treats it as its own.
    std::fs::write(&real, edited.replace(r#""cursor""#, r#""someone""#)).expect("edit");
    let list = mac.json(&["client", "list", "--json"]);
    assert_eq!(row(&list, "cursor")["state"], "changed");
    let out = mac
        .klav(&[
            "client",
            "connect",
            "cursor",
            "--yes",
            "--key-store",
            "file",
        ])
        .err();
    assert!(
        out.stderr.contains("changed since Klav wrote it"),
        "{}",
        out.stderr
    );
    let out = mac.klav(&["client", "disconnect", "cursor", "--yes"]).err();
    assert!(out.stderr.contains("--force"), "{}", out.stderr);

    // Restore: the file changed since Klav wrote it, so only with --force;
    // what it had is kept as another backup.
    let out = mac.klav(&["client", "restore", "cursor"]).err();
    assert!(out.stderr.contains("--force"), "{}", out.stderr);
    let restored = mac.json(&["client", "restore", "cursor", "--force", "--json"]);
    assert_eq!(read(&real), CURSOR_SETTINGS, "{restored}");
    assert!(restored["current_kept_as"].is_string());
    assert_eq!(std::fs::read_dir(&backups).expect("backups").count(), 2);
    assert!(mac.registry()["clients"].get("cursor").is_none());
    // A second restore right after it changes nothing: it does not undo
    // the first.
    let again = mac.json(&["client", "restore", "cursor", "--force", "--json"]);
    assert_eq!(again["already"], true, "{again}");
    assert_eq!(read(&real), CURSOR_SETTINGS);
    assert_eq!(std::fs::read_dir(&backups).expect("backups").count(), 2);

    // A klav entry the person wrote: asked about, adopted only if it runs
    // a klav program with nothing that may hold a key, and replaced or
    // adopted only by the person at a terminal (never with just --yes).
    let theirs = CURSOR_SETTINGS.replace(
        "    \"github\": {",
        "    \"klav\": { \"command\": \"/nowhere/klav-old\", \"args\": [\"mcp\"] },\n    \"github\": {",
    );
    std::fs::write(&real, &theirs).expect("theirs");
    let out = mac
        .klav(&[
            "client",
            "connect",
            "cursor",
            "--yes",
            "--key-store",
            "file",
        ])
        .err();
    assert!(out.stderr.contains("did not write"), "{}", out.stderr);
    let plan = mac.json(&["client", "connect", "cursor", "--dry-run", "--json"]);
    assert_eq!(plan["mcp"]["action"], "conflict", "{plan}");
    assert_eq!(plan["mcp"]["owner"], "person");
    let out = mac
        .klav(&[
            "client",
            "connect",
            "cursor",
            "--yes",
            "--adopt",
            "--key-store",
            "file",
        ])
        .err();
    assert!(
        out.stderr.contains("does not run a klav program"),
        "{}",
        out.stderr
    );
    assert_eq!(read(&real), theirs);
    let with_key = CURSOR_SETTINGS.replace(
        "    \"github\": {",
        &format!(
            "    \"klav\": {{ \"command\": \"{}\", \"args\": [\"mcp\"], \"env\": {{ \"API_KEY\": \"sk-do-not-show\" }} }},\n    \"github\": {{",
            klav_exe()
        ),
    );
    std::fs::write(&real, &with_key).expect("with a key");
    for (flag, says) in [("--adopt", "carries more than"), ("--replace", "terminal")] {
        let out = mac
            .klav(&[
                "client",
                "connect",
                "cursor",
                "--yes",
                flag,
                "--key-store",
                "file",
            ])
            .err();
        assert!(out.stderr.contains(says), "{flag}: {}", out.stderr);
        assert!(!out.stderr.contains("sk-do-not-show"), "{}", out.stderr);
        assert_eq!(read(&real), with_key);
    }
    let plan = mac.json(&[
        "client",
        "connect",
        "cursor",
        "--replace",
        "--dry-run",
        "--json",
    ]);
    assert_eq!(plan["mcp"]["action"], "replace", "{plan}");
    assert!(!plan.to_string().contains("sk-do-not-show"), "{plan}");

    // The person takes theirs out: Klav's goes in, with the same agent.
    std::fs::write(&real, CURSOR_SETTINGS).expect("settings");
    let added = mac.json(&[
        "client",
        "connect",
        "cursor",
        "--yes",
        "--json",
        "--key-store",
        "file",
    ]);
    assert_eq!(added["mcp"]["action"], "add", "{added}");
    assert_eq!(added["agent"]["id"], done["agent"]["id"]);
    assert_eq!(json5_entry(&read(&real))["command"], klav_exe());

    // The person removes the skill: connect does not put it back.
    std::fs::remove_file(mac.skill_copy(".agents")).expect("rm skill");
    let kept = mac.json(&[
        "client",
        "connect",
        "cursor",
        "--yes",
        "--json",
        "--key-store",
        "file",
    ]);
    assert_eq!(kept["skill"][0]["action"], "leave", "{kept}");
    assert!(
        kept["skill"][0]["note"]
            .as_str()
            .is_some_and(|n| n.contains("klav skill install")),
        "{kept}"
    );
    assert!(!mac.skill_copy(".agents").exists());

    // Disconnect: Klav's entry and skill go, everything else stays, and
    // the agent keeps its access.
    let gone = mac.json(&["client", "disconnect", "cursor", "--yes", "--json"]);
    assert!(
        gone["notes"][0]
            .as_str()
            .expect("note")
            .contains("keeps its access"),
        "{gone}"
    );
    let after = read(&real);
    assert!(
        after.contains(r#""GITHUB_TOKEN": "ghp_do_not_show" }, // mine"#),
        "{after}"
    );
    assert!(!after.contains("\"klav\""), "{after}");
    assert!(!mac.skill_copy(".agents").exists());
    assert!(!mac.skill_copy(".agents").parent().expect("dir").exists());

    // The skill cannot be written: the entry is written and recorded all
    // the same, with a warning.
    let blocker = mac
        .skill_copy(".agents")
        .parent()
        .expect("dir")
        .to_path_buf();
    std::fs::write(&blocker, "not a folder").expect("blocker");
    let warned = mac.json(&[
        "client",
        "connect",
        "cursor",
        "--yes",
        "--json",
        "--key-store",
        "file",
    ]);
    assert_eq!(warned["mcp"]["action"], "add", "{warned}");
    assert_eq!(warned["skill"][0]["action"], "failed", "{warned}");
    assert!(
        warned["warnings"]
            .as_array()
            .expect("warnings")
            .iter()
            .any(|w| w
                .as_str()
                .is_some_and(|w| w.contains("skill was not installed"))),
        "{warned}"
    );
    assert_eq!(mac.registry()["clients"]["cursor"]["agent"], "cursor");
    assert_eq!(
        row(&mac.json(&["client", "list", "--json"]), "cursor")["state"],
        "connected"
    );
    std::fs::remove_file(&blocker).expect("rm blocker");

    // Disconnect, with a skill copy that cannot be removed: the entry goes
    // and `clients.json` forgets it all the same, with a warning.
    mac.json(&["skill", "install", "--client", "cursor", "--json"]);
    let skill_dir = mac
        .skill_copy(".agents")
        .parent()
        .expect("dir")
        .to_path_buf();
    set_mode(&skill_dir, 0o500);
    // As root (some CI containers), modes do not stop anything.
    let enforced = std::fs::write(skill_dir.join("probe"), "").is_err();
    let _ = std::fs::remove_file(skill_dir.join("probe"));
    if enforced {
        let out = mac.klav(&["client", "disconnect", "cursor", "--yes", "--json"]);
        set_mode(&skill_dir, 0o700);
        let gone: Value = serde_json::from_str(&out.ok().stdout).expect("json");
        assert_eq!(gone["skill"][0]["action"], "failed", "{gone}");
        assert!(
            gone["warnings"]
                .to_string()
                .contains("skill was not removed"),
            "{gone}"
        );
        assert!(!read(&real).contains("\"klav\""));
        assert!(mac.registry()["clients"].get("cursor").is_none());
        assert!(mac.skill_copy(".agents").exists());
    } else {
        set_mode(&skill_dir, 0o700);
        eprintln!("modes are not enforced here: the skill that cannot be removed is not checked");
    }

    // The request lapses without a decision: that is not a denial, and
    // connect asks again with a new registration.
    if lapse(&server, "cursor") {
        let state = mac.json(&["agent", "status", "--agent", "cursor", "--json"]);
        assert_eq!(state["status"], "denied", "{state}");
        assert_eq!(state["lapsed"], true, "{state}");
        let asked = mac.json(&[
            "client",
            "connect",
            "cursor",
            "--yes",
            "--json",
            "--key-store",
            "file",
        ]);
        assert_eq!(asked["agent"]["status"], "pending", "{asked}");
        assert_ne!(asked["agent"]["id"], done["agent"]["id"]);
        assert_ne!(asked["agent"]["words"], words.as_str());
        assert!(asked["notes"].to_string().contains("lapsed"), "{asked}");
    }

    // Once the person denied the agent, connect stops (exit 5), says the
    // way back that exists, and writes nothing.
    mac.unlocked(&["agent", "deny", "cursor"]).ok();
    let before = read(&real);
    let out = mac.klav(&[
        "client",
        "connect",
        "cursor",
        "--yes",
        "--key-store",
        "file",
    ]);
    assert_eq!(out.code, 5, "{}", out.stderr);
    assert!(out.stderr.contains("already decided"), "{}", out.stderr);
    assert!(
        out.stderr
            .contains("klav agent register --name <another name>")
            && out
                .stderr
                .contains("klav client connect cursor --agent <another name>"),
        "{}",
        out.stderr
    );
    assert_eq!(read(&real), before);
    let state = mac.json(&["agent", "status", "--agent", "cursor", "--json"]);
    assert_eq!(state["status"], "denied", "{state}");
    assert!(state.get("lapsed").is_none(), "{state}");
}

/// The `klav` member of a JSONC text: comments and trailing commas
/// dropped (the fixtures have no `//` or `,` inside strings).
fn json5_entry(text: &str) -> Value {
    let no_comments = text
        .lines()
        .map(|l| l.find("//").map_or(l, |i| &l[..i]))
        .collect::<Vec<_>>()
        .join("\n");
    let chars: Vec<char> = no_comments.chars().collect();
    let mut plain = String::new();
    for (i, c) in chars.iter().enumerate() {
        let trailing = *c == ','
            && chars[i + 1..]
                .iter()
                .find(|n| !n.is_whitespace())
                .is_some_and(|n| *n == '}' || *n == ']');
        if !trailing {
            plain.push(*c);
        }
    }
    let value: Value = serde_json::from_str(&plain).unwrap_or_else(|e| panic!("{e}: {plain}"));
    value["mcpServers"]["klav"].clone()
}

/// Claude Code is written only through its own `claude` command, never by
/// editing `~/.claude.json`; without it, or under an organization's
/// `managed-mcp.json`, nothing is written, and `restore` gives the commands
/// instead of putting a copy over the file.
#[test]
fn claude_code_goes_through_its_cli() {
    let server = ServerProcess::start(900);
    let mut mac = Mac::new();
    mac.signup(&server);
    std::fs::create_dir_all(mac.home.join(".claude")).expect("claude dir");
    let settings = mac.home.join(".claude.json");
    let original = json!({
        "numStartups": 3,
        "mcpServers": { "github": { "command": "npx", "env": { "GITHUB_TOKEN": "ghp_do_not_show" } } },
        "projects": { "/src": { "mcpServers": {} } }
    });
    let original_text = serde_json::to_string_pretty(&original).expect("json");
    std::fs::write(&settings, &original_text).expect("settings");
    let home_pair = format!("KLAV_HOME={}", mac.device.home.display());

    // No `claude` in PATH: the command to run by hand (the name before
    // `--env`), nothing written.
    let out = mac
        .klav(&[
            "client",
            "connect",
            "claude-code",
            "--yes",
            "--key-store",
            "file",
        ])
        .err();
    assert!(
        out.stderr
            .contains("claude mcp add --scope user --transport stdio klav --env"),
        "{}",
        out.stderr
    );
    assert!(!mac.device.home.join("agents/claude-code.json").exists());

    // Managed by the organization: nothing written.
    mac.fake("claude", &settings);
    let managed_dir = if cfg!(target_os = "macos") {
        mac.sys.join("Library/Application Support/ClaudeCode")
    } else {
        mac.sys.join("etc/claude-code")
    };
    std::fs::create_dir_all(&managed_dir).expect("managed");
    std::fs::write(managed_dir.join("managed-mcp.json"), "{\"mcpServers\":{}}").expect("managed");
    let out = mac
        .klav(&[
            "client",
            "connect",
            "claude-code",
            "--yes",
            "--key-store",
            "file",
        ])
        .err();
    assert!(out.stderr.contains("organization"), "{}", out.stderr);
    let list = mac.json(&["client", "list", "--json"]);
    assert_eq!(row(&list, "claude-code")["state"], "managed");
    std::fs::remove_dir_all(&managed_dir).expect("unmanage");
    assert!(mac.calls("claude").is_empty());

    // The stand-in reads `mcp add` as Claude Code does: a name right after
    // `--env` is taken for another pair and refused.
    let old_order = Command::new(mac.fakes.join("claude"))
        .args([
            "mcp",
            "add",
            "--scope",
            "user",
            "--transport",
            "stdio",
            "--env",
            &home_pair,
            "klav",
            "--",
            "/k",
            "mcp",
        ])
        .output()
        .expect("stand-in");
    assert!(!old_order.status.success());
    assert!(
        String::from_utf8_lossy(&old_order.stderr)
            .contains("Invalid environment variable format: klav"),
        "{old_order:?}"
    );
    std::fs::remove_file(mac.plays.join("claude.log")).expect("rm log");

    // The plan names the command, and binds the write to the klav member
    // only: Claude Code rewrites the rest of its file all the time.
    let plan = mac.json(&["client", "connect", "claude-code", "--dry-run", "--json"]);
    let add: Vec<String> =
        serde_json::from_value(plan["mcp"]["commands"][0].clone()).expect("command");
    assert_eq!(
        add,
        [
            "claude",
            "mcp",
            "add",
            "--scope",
            "user",
            "--transport",
            "stdio",
            "klav",
            "--env",
            &home_pair,
            "--",
            &klav_exe(),
            "mcp",
            "--agent",
            "claude-code"
        ]
        .map(String::from)
    );
    let expect = plan["mcp"]["expect_sha256"]
        .as_str()
        .expect("expect")
        .to_owned();
    assert_ne!(plan["mcp"]["file_sha256"], expect.as_str());

    // Claude Code wrote its file meanwhile; the stand-in plays a `claude`
    // that writes something else: Klav says so, and does not put a copy
    // over the file.
    let mut busy = original.clone();
    busy["numStartups"] = json!(4);
    std::fs::write(
        &settings,
        serde_json::to_string_pretty(&busy).expect("json"),
    )
    .expect("busy");
    let mut wrong = busy.clone();
    wrong["mcpServers"]["klav"] =
        json!({ "type": "stdio", "command": "/elsewhere/klav", "args": ["mcp"], "env": {} });
    let wrong_text = serde_json::to_string_pretty(&wrong).expect("json");
    mac.play("claude-add", &wrong_text);
    let out = mac
        .klav(&[
            "client",
            "connect",
            "claude-code",
            "--yes",
            "--key-store",
            "file",
            "--expect-sha256",
            &expect,
        ])
        .err();
    assert!(
        out.stderr.contains("not what Klav asked for")
            && out.stderr.contains("claude mcp get klav"),
        "{}",
        out.stderr
    );
    assert_eq!(read(&settings), wrong_text);
    assert_eq!(mac.calls("claude"), vec![add[1..].to_vec()]);
    let words =
        mac.json(&["agent", "status", "--agent", "claude-code", "--json"])["pairing_code"].clone();

    // `restore` does not write ~/.claude.json: it says where the copy is
    // and which `claude` commands go back to it.
    let out = mac
        .klav(&["client", "restore", "claude-code", "--force"])
        .err();
    assert!(
        out.stderr.contains("client-backups/claude-code")
            && out.stderr.contains("claude mcp remove klav --scope user")
            && out.stderr.contains("does not write"),
        "{}",
        out.stderr
    );
    assert!(!out.stderr.contains("ghp_do_not_show"), "{}", out.stderr);
    assert_eq!(read(&settings), wrong_text);
    assert_eq!(mac.calls("claude").len(), 1);

    // The klav entry there now is not Klav's: replacing it needs the person
    // at a terminal, even with --yes.
    let out = mac
        .klav(&[
            "client",
            "connect",
            "claude-code",
            "--yes",
            "--replace",
            "--key-store",
            "file",
        ])
        .err();
    assert!(out.stderr.contains("terminal"), "{}", out.stderr);
    assert_eq!(read(&settings), wrong_text);
    assert_eq!(mac.calls("claude").len(), 1);

    // The person takes it out. A `claude` that fails: its exit code and
    // the command to run by hand, never what it printed (it may quote
    // another server's key); nothing recorded.
    std::fs::write(&settings, &original_text).expect("settings");
    mac.play("claude-fail", "");
    let out = mac
        .klav(&[
            "client",
            "connect",
            "claude-code",
            "--yes",
            "--key-store",
            "file",
        ])
        .err();
    assert!(
        out.stderr.contains("`claude mcp add` failed (exit 1")
            && out
                .stderr
                .contains("run it by hand: `claude mcp add --scope user"),
        "{}",
        out.stderr
    );
    assert!(!out.stderr.contains("ghp_tool_stderr"), "{}", out.stderr);
    assert_eq!(read(&settings), original_text);
    assert!(
        mac.registry()
            .get("clients")
            .is_none_or(|c| c.get("claude-code").is_none())
    );
    std::fs::remove_file(mac.plays.join("claude-fail")).expect("rm");

    // Now a faithful `claude`: the entry is added, with the pending agent.
    let with_klav = |agent: &str| {
        let mut good = original.clone();
        good["mcpServers"]["klav"] = json!({
            "type": "stdio",
            "command": klav_exe(),
            "args": ["mcp", "--agent", agent],
            "env": { "KLAV_HOME": mac.device.home.display().to_string() }
        });
        serde_json::to_string_pretty(&good).expect("json")
    };
    mac.play("claude-remove", &original_text);
    mac.play("claude-add-claude-code", &with_klav("claude-code"));
    mac.play("claude-add-other", &with_klav("other"));
    let done = mac.json(&[
        "client",
        "connect",
        "claude-code",
        "--yes",
        "--json",
        "--key-store",
        "file",
    ]);
    assert_eq!(done["agent"]["words"], words, "{done}");
    assert_eq!(done["agent"]["registers"], false);
    assert_eq!(done["mcp"]["action"], "add");
    let calls = mac.calls("claude");
    assert_eq!(calls.len(), 3, "{calls:?}");
    assert_eq!(calls[2], add[1..]);
    assert_eq!(read(&settings), with_klav("claude-code"));
    assert_eq!(read(&mac.skill_copy(".claude")), SKILL);
    assert_eq!(mac.registry()["clients"]["claude-code"]["method"], "cli");
    let list = mac.json(&["client", "list", "--json"]);
    assert_eq!(row(&list, "claude-code")["state"], "connected");

    // Klav's entry, for another agent: `remove`, then `add`.
    let remove = ["mcp", "remove", "klav", "--scope", "user"].map(String::from);
    let other = mac.json(&[
        "client",
        "connect",
        "claude-code",
        "--agent",
        "other",
        "--yes",
        "--json",
        "--key-store",
        "file",
    ]);
    assert_eq!(other["mcp"]["action"], "replace", "{other}");
    let calls = mac.calls("claude");
    assert_eq!(calls.len(), 5, "{calls:?}");
    assert_eq!(calls[3], remove);
    assert_eq!(calls[4].last().map(String::as_str), Some("other"));
    assert_eq!(read(&settings), with_klav("other"));

    // `add` fails after `remove` took the old entry out: it was Klav's,
    // so Klav puts it back.
    mac.play("claude-fail-add-once", "");
    let out = mac
        .klav(&[
            "client",
            "connect",
            "claude-code",
            "--yes",
            "--key-store",
            "file",
        ])
        .err();
    assert!(
        out.stderr.contains("`claude mcp add` failed (exit 1")
            && out.stderr.contains("put it back"),
        "{}",
        out.stderr
    );
    assert!(!out.stderr.contains("ghp_tool_stderr"), "{}", out.stderr);
    let calls = mac.calls("claude");
    assert_eq!(calls.len(), 8, "{calls:?}");
    assert_eq!(calls[5], remove);
    assert_eq!(calls[6], add[1..]);
    assert_eq!(calls[7].last().map(String::as_str), Some("other"));
    assert_eq!(read(&settings), with_klav("other"));
    assert_eq!(
        row(&mac.json(&["client", "list", "--json"]), "claude-code")["state"],
        "connected"
    );

    // Like Claude Code, the stand-in refuses to add a name that is there:
    // Klav always removes first.
    let log = read(&mac.plays.join("claude.log"));
    let twice = Command::new(mac.fakes.join("claude"))
        .args(&add[1..])
        .output()
        .expect("stand-in");
    assert!(
        String::from_utf8_lossy(&twice.stderr).contains("already exists"),
        "{twice:?}"
    );
    std::fs::write(mac.plays.join("claude.log"), log).expect("log");

    // A `claude` that writes the new entry and then fails (or is killed by
    // the time limit right after writing), after `remove`: the file has
    // what Klav asked for, so it is Klav's, with a warning, and the next
    // connect keeps it instead of refusing it as the person's.
    mac.play("claude-fail-after-add-once", "");
    let replaced = mac.json(&[
        "client",
        "connect",
        "claude-code",
        "--yes",
        "--json",
        "--key-store",
        "file",
    ]);
    assert_eq!(replaced["mcp"]["action"], "replace", "{replaced}");
    assert!(
        replaced["warnings"]
            .to_string()
            .contains("counts it as written"),
        "{replaced}"
    );
    assert!(!replaced.to_string().contains("ghp_tool_stderr"));
    assert_eq!(read(&settings), with_klav("claude-code"));
    assert_eq!(
        mac.registry()["clients"]["claude-code"]["agent"],
        "claude-code"
    );
    let calls = mac.calls("claude");
    assert_eq!(calls.len(), 10, "{calls:?}");
    assert_eq!(calls[8], remove);
    assert_eq!(calls[9], add[1..]);
    let kept = mac.json(&[
        "client",
        "connect",
        "claude-code",
        "--yes",
        "--json",
        "--key-store",
        "file",
    ]);
    assert_eq!(kept["mcp"]["action"], "keep", "{kept}");
    assert_eq!(mac.calls("claude").len(), 10);

    // Disconnect goes through `claude mcp remove` too.
    mac.json(&["client", "disconnect", "claude-code", "--yes", "--json"]);
    let calls = mac.calls("claude");
    assert_eq!(calls.last().expect("call"), &remove);
    assert_eq!(read(&settings), original_text);
    assert!(!mac.skill_copy(".claude").exists());

    // The same with a plain `add`: written, then failed. Recorded as
    // Klav's, so `list` says connected, not the person's.
    mac.play("claude-fail-after-add-once", "");
    let added = mac.json(&[
        "client",
        "connect",
        "claude-code",
        "--yes",
        "--json",
        "--key-store",
        "file",
    ]);
    assert_eq!(added["mcp"]["action"], "add", "{added}");
    assert!(
        added["warnings"]
            .to_string()
            .contains("counts it as written"),
        "{added}"
    );
    assert_eq!(read(&settings), with_klav("claude-code"));
    assert_eq!(
        row(&mac.json(&["client", "list", "--json"]), "claude-code")["state"],
        "connected"
    );

    // Someone turns Klav's entry into one that hides a key in its
    // arguments. `--replace` puts Klav's back (no terminal needed for a
    // changed entry of Klav's); `add` fails after `remove`. The old entry
    // is not Klav-shaped: Klav neither prints it nor hands it to `claude`,
    // and says where the copy is. `restore` does the same.
    let marker = "ghp_hidden_in_args_1234";
    let mut hiding = original.clone();
    hiding["mcpServers"]["klav"] = json!({
        "command": "/bin/sh",
        "args": ["-c", format!("GITHUB_TOKEN={marker} exec klav mcp --agent claude-code")]
    });
    std::fs::write(
        &settings,
        serde_json::to_string_pretty(&hiding).expect("json"),
    )
    .expect("hiding");
    assert_eq!(
        row(&mac.json(&["client", "list", "--json"]), "claude-code")["state"],
        "changed"
    );
    mac.play("claude-fail-add-once", "");
    let out = mac.klav(&[
        "client",
        "connect",
        "claude-code",
        "--replace",
        "--yes",
        "--key-store",
        "file",
    ]);
    assert_ne!(out.code, 0, "{}", out.stderr);
    assert!(
        out.stderr.contains("put it back by hand") && out.stderr.contains("client-backups"),
        "{}",
        out.stderr
    );
    let restore = mac.klav(&["client", "restore", "claude-code"]);
    assert_ne!(restore.code, 0);
    assert!(
        restore.stderr.contains("back by hand") && restore.stderr.contains("client-backups"),
        "{}",
        restore.stderr
    );
    let log = read(&mac.plays.join("claude.log"));
    for text in [
        &out.stdout,
        &out.stderr,
        &restore.stdout,
        &restore.stderr,
        &log,
    ] {
        assert!(!text.contains(marker), "{text}");
        assert!(!text.contains("ghp_tool_stderr"), "{text}");
    }
    assert!(!log.contains("/bin/sh"), "{log}");
}

const CODEX_SETTINGS: &str = r#"# my Codex settings
model = "gpt-5"

[mcp_servers.docs]
command = "docs-mcp"
env = { API_KEY = "sk-do-not-show" } # keep

[profiles.fast]
model = "mini"
"#;

/// Codex: blocked by `requirements.toml`, a TOML edit without `codex`
/// (comments and other tables kept), `codex mcp remove` with it, and the
/// skill: an adopted older copy, flagged by `agent status` and updated.
#[test]
fn codex_settings_and_the_skill() {
    let server = ServerProcess::start(900);
    let mut mac = Mac::new();
    mac.signup(&server);
    std::fs::create_dir_all(&mac.codex).expect("codex home");
    let config = mac.codex.join("config.toml");
    std::fs::write(&config, CODEX_SETTINGS).expect("config");
    set_mode(&config, 0o600);

    // An organization's requirements.toml with no MCP servers.
    let requirements = mac.sys.join("etc/codex/requirements.toml");
    std::fs::create_dir_all(requirements.parent().expect("dir")).expect("etc");
    std::fs::write(&requirements, "[mcp_servers]\n").expect("requirements");
    let out = mac
        .klav(&["client", "connect", "codex", "--yes", "--key-store", "file"])
        .err();
    assert!(out.stderr.contains("MCP is off"), "{}", out.stderr);
    assert_eq!(read(&config), CODEX_SETTINGS);
    std::fs::remove_file(&requirements).expect("rm");

    // A skill Klav published before, put there by hand: adoptable.
    let copy = mac.skill_copy(".agents");
    std::fs::create_dir_all(copy.parent().expect("dir")).expect("skill dir");
    std::fs::write(&copy, LEGACY_SKILL).expect("legacy");
    let status = mac.json(&["skill", "status", "--json"]);
    let found = status["copies"]
        .as_array()
        .expect("copies")
        .iter()
        .find(|c| c["path"] == copy.display().to_string())
        .expect("copy")
        .clone();
    assert_eq!(found["state"], "unmanaged");
    assert_eq!(found["adoptable"], true);
    let skills = mac.home.join(".agents/skills");
    mac.json(&[
        "skill",
        "install",
        "--adopt",
        "--dir",
        skills.to_str().expect("utf-8"),
        "--json",
    ]);
    assert_eq!(read(&copy), LEGACY_SKILL);

    // Connected by editing the file (no `codex` here), without the skill.
    let done = mac.json(&[
        "client",
        "connect",
        "codex",
        "--yes",
        "--no-skill",
        "--json",
        "--key-store",
        "file",
    ]);
    assert_eq!(done["mcp"]["method"], "file", "{done}");
    let edited = read(&config);
    assert!(
        edited.starts_with(CODEX_SETTINGS.split("[profiles").next().expect("head")),
        "{edited}"
    );
    assert!(
        edited.contains("[profiles.fast]\nmodel = \"mini\""),
        "{edited}"
    );
    assert!(
        edited.contains("env = { API_KEY = \"sk-do-not-show\" } # keep"),
        "{edited}"
    );
    let table: toml::Table = edited.parse().expect("toml");
    let klav = &table["mcp_servers"]["klav"];
    assert_eq!(klav["command"].as_str(), Some(klav_exe().as_str()));
    assert_eq!(klav["args"].as_array().expect("args").len(), 3);
    assert_eq!(
        klav["env"]["KLAV_HOME"].as_str(),
        Some(mac.device.home.display().to_string().as_str())
    );
    assert_eq!(common::mode(&config), 0o600);
    assert!(!done.to_string().contains("sk-do-not-show"));

    // `agent status` points out the older skill until it is updated.
    let out = mac.klav(&["agent", "status", "--agent", "codex"]).ok();
    assert!(out.stderr.contains("klav skill update"), "{}", out.stderr);
    let updated = mac.json(&["skill", "update", "--json"]);
    assert_eq!(updated["copies"][0]["action"], "replace", "{updated}");
    assert_eq!(read(&copy), SKILL);
    let out = mac.klav(&["agent", "status", "--agent", "codex"]).ok();
    assert!(!out.stderr.contains("klav skill update"), "{}", out.stderr);

    // With `codex` installed, disconnect runs `codex mcp remove klav`.
    mac.fake("codex", &config);
    mac.play("codex-remove", CODEX_SETTINGS);
    mac.json(&[
        "client",
        "disconnect",
        "codex",
        "--yes",
        "--keep-skill",
        "--json",
    ]);
    assert_eq!(
        mac.calls("codex"),
        vec![["mcp", "remove", "klav"].map(String::from).to_vec()]
    );
    assert_eq!(read(&config), CODEX_SETTINGS);
    assert!(copy.exists(), "--keep-skill");
    assert!(mac.registry()["clients"].get("codex").is_none());
}

/// Codex's TOML with CRLF line ends and a byte order mark: the edit keeps
/// both, and taking the entry out gives the file back.
#[test]
fn codex_crlf_and_bom_are_kept() {
    let server = ServerProcess::start(900);
    let mac = Mac::new();
    mac.signup(&server);
    std::fs::create_dir_all(&mac.codex).expect("codex home");
    let config = mac.codex.join("config.toml");
    let original = format!("\u{feff}{}", CODEX_SETTINGS.replace('\n', "\r\n"));
    std::fs::write(&config, &original).expect("config");
    let done = mac.json(&[
        "client",
        "connect",
        "codex",
        "--yes",
        "--no-skill",
        "--json",
        "--key-store",
        "file",
    ]);
    assert_eq!(done["mcp"]["method"], "file", "{done}");
    let edited = read(&config);
    assert!(edited.starts_with('\u{feff}'), "{edited:?}");
    assert!(!edited.replace("\r\n", "").contains('\n'), "{edited:?}");
    assert!(edited.contains("[mcp_servers.klav]\r\n"), "{edited:?}");
    assert!(
        edited.contains("env = { API_KEY = \"sk-do-not-show\" } # keep\r\n"),
        "{edited:?}"
    );
    assert_eq!(
        row(&mac.json(&["client", "list", "--json"]), "codex")["state"],
        "connected"
    );
    mac.json(&["client", "disconnect", "codex", "--yes", "--json"]);
    assert_eq!(read(&config).trim_end(), original.trim_end());
}

/// What Klav refuses before it changes anything, without a server: a
/// malformed file (where, never what), a repeated `klav` entry, a client
/// folder that is not there, a link to nothing, a file in a system
/// directory, a client that is not there.
#[test]
fn refusals_change_nothing() {
    let mut mac = Mac::new();
    let cursor = mac.home.join(".cursor/mcp.json");
    std::fs::create_dir_all(cursor.parent().expect("dir")).expect("cursor");
    let broken = "{\n  \"mcpServers\": {\n    \"x\": { \"env\": { \"K\": \"sk-do-not-show\" } }\n    \"y\": 1\n";
    std::fs::write(&cursor, broken).expect("broken");
    let out = mac.klav(&["client", "list", "--json"]).ok();
    assert!(!out.stdout.contains("sk-do-not-show"), "{}", out.stdout);
    let list: Value = serde_json::from_str(&out.stdout).expect("json");
    let broken_row = row(&list, "cursor");
    assert_eq!(broken_row["state"], "malformed");
    assert_eq!(broken_row["config"]["malformed"]["line"], 3, "{broken_row}");
    let out = mac.klav(&["client", "connect", "cursor", "--yes"]).err();
    assert!(
        out.stderr.contains("line 3") && out.stderr.contains("\"klav\":"),
        "{}",
        out.stderr
    );
    assert!(!out.stderr.contains("sk-do-not-show"), "{}", out.stderr);
    assert_eq!(read(&cursor), broken);

    // A repeated klav entry: Cursor runs the last one, so the file counts
    // as malformed, never as connected.
    let twice = "{\n  \"mcpServers\": {\n    \"klav\": { \"command\": \"/a/klav\", \"args\": [\"mcp\"] },\n    \"klav\": { \"command\": \"/b/klav\", \"args\": [\"mcp\"] }\n  }\n}\n";
    std::fs::write(&cursor, twice).expect("twice");
    let list = mac.json(&["client", "list", "--json"]);
    let cursor_row = row(&list, "cursor");
    assert_eq!(cursor_row["state"], "malformed", "{cursor_row}");
    assert_eq!(cursor_row["config"]["malformed"]["line"], 4, "{cursor_row}");
    let out = mac.klav(&["client", "connect", "cursor", "--yes"]).err();
    assert!(out.stderr.contains("`klav` repeated"), "{}", out.stderr);
    let out = mac.klav(&["client", "disconnect", "cursor", "--yes"]).err();
    assert!(out.stderr.contains("`klav` repeated"), "{}", out.stderr);
    assert_eq!(read(&cursor), twice);

    // VS Code is installed but its folder is not there: Klav does not
    // create it.
    std::fs::create_dir_all(mac.sys.join("Applications/Visual Studio Code.app")).expect("app");
    let out = mac.klav(&["client", "connect", "vscode", "--yes"]).err();
    assert!(out.stderr.contains("has no folder"), "{}", out.stderr);
    assert!(!mac.home.join(".copilot").exists());

    // VS Code's file links to nothing.
    std::fs::create_dir_all(mac.home.join(".copilot")).expect("copilot");
    std::os::unix::fs::symlink(
        mac.root.join("missing.json"),
        mac.home.join(".copilot/mcp-config.json"),
    )
    .expect("link");
    let out = mac.klav(&["client", "connect", "vscode", "--yes"]).err();
    assert!(out.stderr.contains("does not exist"), "{}", out.stderr);
    assert!(!mac.root.join("missing.json").exists());

    // Codex settings in a system directory.
    mac.codex = mac.sys.join("etc/codex-home");
    std::fs::create_dir_all(&mac.codex).expect("codex");
    let out = mac.klav(&["client", "connect", "codex", "--yes"]).err();
    assert!(out.stderr.contains("system directory"), "{}", out.stderr);
    assert!(!mac.codex.join("config.toml").exists());

    // Claude Desktop is not installed (or not on this system).
    let out = mac
        .klav(&["client", "connect", "claude-desktop", "--yes"])
        .err();
    assert!(out.stderr.contains("not"), "{}", out.stderr);

    // Claude Code with a `claude` but no Klav account here: nothing is
    // run, nothing is written.
    let settings = mac.home.join(".claude.json");
    std::fs::write(&settings, "{}").expect("settings");
    mac.fake("claude", &settings);
    let out = mac
        .klav(&["client", "connect", "claude-code", "--yes"])
        .err();
    assert!(out.stderr.contains("no Klav account"), "{}", out.stderr);
    assert!(mac.calls("claude").is_empty());
    assert_eq!(read(&settings), "{}");
}

/// `/usr/local/bin/klav` is trusted only as the app's link (owned by root,
/// pointing at Klav), never by its path; and a run never hangs behind
/// another one that holds `clients.lock`.
#[test]
fn a_klav_link_is_trusted_only_as_the_apps_and_the_lock_never_hangs() {
    let mac = Mac::new();
    // A link the user put there, to this very klav: not the app's.
    let bin = mac.sys.join("usr/local/bin");
    std::fs::create_dir_all(&bin).expect("bin");
    let link = bin.join("klav");
    std::os::unix::fs::symlink(klav_exe(), &link).expect("link");
    let cursor = mac.home.join(".cursor/mcp.json");
    std::fs::create_dir_all(cursor.parent().expect("dir")).expect("cursor");
    let with = |command: &str| {
        format!(
            "{{ \"mcpServers\": {{ \"klav\": {{ \"command\": \"{command}\", \"args\": [\"mcp\"] }} }} }}\n"
        )
    };
    std::fs::write(&cursor, with(&link.display().to_string())).expect("settings");
    let list = mac.json(&["client", "list", "--json"]);
    assert_eq!(row(&list, "cursor")["unknown_command"], true, "{list}");
    // This klav itself is known.
    std::fs::write(&cursor, with(&klav_exe())).expect("settings");
    let list = mac.json(&["client", "list", "--json"]);
    assert!(
        row(&list, "cursor").get("unknown_command").is_none(),
        "{list}"
    );

    // Another run holds the lock (asking the person, say): `klav skill
    // update`, which the app runs when it starts, gives up with a clear
    // message instead of waiting forever.
    std::fs::create_dir_all(&mac.device.home).expect("klav home");
    let held = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(mac.device.home.join("clients.lock"))
        .expect("lock file");
    held.lock().expect("lock");
    let started = std::time::Instant::now();
    let out = mac.klav(&["skill", "update", "--json"]).err();
    assert!(
        started.elapsed() < std::time::Duration::from_secs(30),
        "{:?}",
        started.elapsed()
    );
    assert!(
        out.stderr
            .contains("another `klav client` or `klav skill` is running"),
        "{}",
        out.stderr
    );
    held.unlock().expect("unlock");
    mac.json(&["skill", "update", "--json"]);
}

/// `klav skill`: install, an edited copy never overwritten, keep-mine,
/// replace with the old one kept aside, a removed copy not put back by
/// itself, a copy that is not Klav's, uninstall.
#[test]
fn skill_copies_are_klavs_only_while_unchanged() {
    let mac = Mac::new();
    let dir = mac.root.join("skills");
    let dir_s = dir.to_str().expect("utf-8");
    let copy = dir.join("klav/SKILL.md");
    assert_eq!(mac.klav(&["skill", "show"]).ok().stdout, SKILL);

    // Nothing installed and no client: the folder must be named.
    let out = mac.klav(&["skill", "install"]);
    assert_eq!(out.code, 2, "{}", out.stderr);
    // VS Code's `code` in `/usr/bin` is a client; this machine's own
    // programs are not.
    let code = mac.sys.join("usr/bin/code");
    std::fs::create_dir_all(code.parent().expect("dir")).expect("usr/bin");
    std::fs::write(&code, "#!/bin/sh\n").expect("code");
    set_mode(&code, 0o755);
    let plan = mac.json(&["skill", "install", "--dry-run", "--json"]);
    assert_eq!(
        plan["copies"],
        json!([{
            "path": mac.skill_copy(".agents").display().to_string(),
            "action": "install",
        }]),
        "{plan}"
    );
    std::fs::remove_file(&code).expect("rm code");
    // Claude Desktop has no skill folder.
    let out = mac.klav(&["skill", "install", "--client", "claude-desktop"]);
    assert_eq!(out.code, 2, "{}", out.stderr);

    let plan = mac.json(&["skill", "install", "--dir", dir_s, "--dry-run", "--json"]);
    assert_eq!(plan["copies"][0]["action"], "install");
    assert!(!copy.exists());
    mac.json(&["skill", "install", "--dir", dir_s, "--json"]);
    assert_eq!(read(&copy), SKILL);
    assert_eq!(common::mode(&copy), 0o644);
    let status = mac.json(&["skill", "status", "--json"]);
    assert_eq!(status["bundled"]["version"], "0.3.2");
    let state = |status: &Value| {
        status["copies"]
            .as_array()
            .expect("copies")
            .iter()
            .find(|c| c["path"] == copy.display().to_string())
            .map(|c| c["state"].clone())
    };
    assert_eq!(state(&status), Some(json!("current")));

    // Edited: left alone, until the person says what to do.
    std::fs::write(&copy, format!("{SKILL}\nMy own rule.\n")).expect("edit");
    assert_eq!(
        state(&mac.json(&["skill", "status", "--json"])),
        Some(json!("edited"))
    );
    let update = mac.json(&["skill", "update", "--json"]);
    assert_eq!(update["copies"][0]["action"], "leave", "{update}");
    assert!(read(&copy).contains("My own rule."));
    let kept = mac.json(&["skill", "update", "--keep-mine", "--json"]);
    assert_eq!(kept["copies"][0]["action"], "keep_mine");
    assert!(mac.registry()["skills"][0]["kept_mine"] == "0.3.2");
    let install = mac.json(&["skill", "install", "--dir", dir_s, "--json"]);
    assert_eq!(install["copies"][0]["action"], "leave");
    let replaced = mac.json(&["skill", "install", "--dir", dir_s, "--replace", "--json"]);
    let aside = PathBuf::from(replaced["copies"][0]["saved_as"].as_str().expect("saved"));
    assert!(read(&aside).contains("My own rule."));
    assert_eq!(read(&copy), SKILL);
    std::fs::remove_file(&aside).expect("rm aside");

    // Removed: not put back by `update`, only by `install`.
    std::fs::remove_file(&copy).expect("rm");
    assert_eq!(
        state(&mac.json(&["skill", "status", "--json"])),
        Some(json!("removed"))
    );
    mac.json(&["skill", "update", "--json"]);
    assert!(!copy.exists());
    mac.json(&["skill", "install", "--dir", dir_s, "--json"]);
    assert_eq!(read(&copy), SKILL);

    // Uninstall removes it and its folder.
    mac.json(&["skill", "uninstall", "--dir", dir_s, "--json"]);
    assert!(!copy.exists() && !copy.parent().expect("dir").exists());
    assert_eq!(mac.registry()["skills"], json!([]));

    // A klav skill Klav never published: not adopted, not replaced unasked.
    std::fs::create_dir_all(copy.parent().expect("dir")).expect("dir");
    let mine = "---\nname: klav\ndescription: mine\n---\nmine\n";
    std::fs::write(&copy, mine).expect("mine");
    let adopt = mac.json(&["skill", "install", "--dir", dir_s, "--adopt", "--json"]);
    assert_eq!(adopt["copies"][0]["action"], "leave", "{adopt}");
    let out = mac.json(&["skill", "uninstall", "--dir", dir_s, "--json"]);
    assert_eq!(out["copies"][0]["action"], "leave");
    assert_eq!(read(&copy), mine);
}
