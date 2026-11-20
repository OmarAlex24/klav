//! A `klav mcp` child driven over its stdio pipes, recording every line
//! it writes to stdout.

use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, ChildStdout, Stdio};

use serde_json::{Value, json};

use super::Device;

pub struct Mcp {
    pub child: Child,
    pub stdin: Option<ChildStdin>,
    stdout: BufReader<ChildStdout>,
    next: u64,
    /// Every line read from stdout.
    pub seen: Vec<String>,
}

impl Mcp {
    /// Starts `klav mcp` in `cwd`; its stderr goes to `stderr` (or is
    /// discarded).
    pub fn start(agent: &Device, cwd: &Path, stderr: Option<&Path>) -> Self {
        Self::start_with(agent, cwd, stderr, &[])
    }

    /// [`Self::start`] with extra environment variables (such as
    /// `KLAV_BROWSER_HOME`, the home of the person's `klavd`).
    pub fn start_with(
        agent: &Device,
        cwd: &Path,
        stderr: Option<&Path>,
        env: &[(&str, &Path)],
    ) -> Self {
        let mut cmd = agent.command();
        for (name, value) in env {
            cmd.env(name, value);
        }
        cmd.current_dir(cwd).args(["mcp", "--wait", "1s"]).stderr(
            stderr.map_or(Stdio::null(), |p| {
                Stdio::from(std::fs::File::create(p).expect("stderr file"))
            }),
        );
        let mut child = cmd.spawn().expect("spawn klav mcp");
        let stdin = child.stdin.take().expect("stdin");
        let stdout = BufReader::new(child.stdout.take().expect("stdout"));
        Self {
            child,
            stdin: Some(stdin),
            stdout,
            next: 1,
            seen: Vec::new(),
        }
    }

    pub fn send_line(&mut self, line: &str) {
        let stdin = self.stdin.as_mut().expect("stdin open");
        writeln!(stdin, "{line}").expect("write");
        stdin.flush().expect("flush");
    }

    pub fn read(&mut self) -> Value {
        let mut line = String::new();
        self.stdout.read_line(&mut line).expect("read");
        assert!(!line.is_empty(), "klav mcp closed stdout");
        self.seen.push(line.clone());
        let value: Value = serde_json::from_str(&line).expect("every stdout line is JSON");
        assert_eq!(value["jsonrpc"], "2.0", "{line}");
        value
    }

    /// Sends a request without waiting for the reply; returns its ID.
    pub fn send(&mut self, method: &str, params: Value) -> u64 {
        let id = self.next;
        self.next += 1;
        self.send_line(
            &json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }).to_string(),
        );
        id
    }

    pub fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.send(method, params);
        let reply = self.read();
        assert_eq!(reply["id"], id);
        reply
    }

    /// `initialize` and `notifications/initialized`.
    pub fn initialize(&mut self) -> Value {
        let init = self.request(
            "initialize",
            json!({ "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": { "name": "test", "version": "0" } }),
        );
        self.send_line(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#);
        init
    }

    /// `(text, isError)` of a tool call's reply.
    pub fn tool_reply(reply: &Value) -> (String, bool) {
        let result = &reply["result"];
        (
            result["content"][0]["text"]
                .as_str()
                .expect("text")
                .to_owned(),
            result["isError"].as_bool().expect("isError"),
        )
    }

    /// `(text, isError)` of a tool call.
    pub fn tool(&mut self, name: &str, args: Value) -> (String, bool) {
        let reply = self.request("tools/call", json!({ "name": name, "arguments": args }));
        Self::tool_reply(&reply)
    }

    /// Closes stdin and waits for the server to exit.
    pub fn finish(mut self) -> std::process::ExitStatus {
        drop(self.stdin.take());
        self.child.wait().expect("wait")
    }
}
