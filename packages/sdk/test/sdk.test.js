// Checks the arguments the wrapper passes to `klav` (a fake binary that
// prints them as JSON), so no secret or option is lost on the way.
import assert from "node:assert/strict";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";

import {
  EXIT,
  KlavError,
  endTask,
  fill,
  getTask,
  inject,
  requestTask,
  run,
  totp,
  waitApproval,
  waitTask,
} from "../index.js";

const dir = mkdtempSync(join(tmpdir(), "klav-sdk-node-"));
after(() => rmSync(dir, { recursive: true, force: true }));
const fake = join(dir, "klav");
writeFileSync(
  fake,
  `#!/usr/bin/env node
const args = process.argv.slice(2);
if (args.includes("FAIL")) { process.stderr.write("error: the policy denies it\\n"); process.exit(5); }
if (args.includes("DELETING")) { process.stderr.write("error: account_deleting: do not retry\\n"); process.exit(8); }
if (args[1] === "totp") { process.stdout.write("123456\\n"); process.exit(0); }
if (args[1] === "task") {
  let input = "";
  if (args[3] === "-") input = require("node:fs").readFileSync(0, "utf8");
  process.stdout.write(JSON.stringify({ args, input }));
  process.exit(args[2] === "request" ? 4 : 0);
}
process.stdout.write(JSON.stringify(args));
process.exit(args[1] === "run" ? 7 : 0);
`,
);
chmodSync(fake, 0o755);
process.env.KLAV_BIN = fake;

const page = {
  context: () => ({
    newCDPSession: async () => ({
      send: async () => ({ targetInfo: { targetId: "T-1" } }),
      detach: async () => {},
    }),
  }),
};

test("a reason is mandatory", async () => {
  await assert.rejects(totp("x", {}), TypeError);
  await assert.rejects(totp("x", { reason: " " }), TypeError);
});

test("fill passes the reference, the target and the selectors", async () => {
  const args = await fill(page, "klav://V/P/Site", {
    reason: "log in",
    cdp: "http://127.0.0.1:9222",
    selectors: { password: "#pass" },
  });
  assert.deepEqual(args, [
    "agent", "fill", "klav://V/P/Site", "--reason", "log in", "--cdp", "http://127.0.0.1:9222",
    "--target", "T-1", "--selector", "password=#pass", "--json",
  ]);
  const submitted = await fill(page, "klav://V/P/Site", {
    reason: "log in",
    cdp: "http://127.0.0.1:9222",
    submit: true,
  });
  assert.ok(submitted.includes("--submit"));
});

test("run returns the exit code and the redacted output", async () => {
  const out = await run("npm", ["test"], { reason: "tests", env: { KEY: "klav://V/P/I/k" } });
  assert.equal(out.code, 7);
  assert.deepEqual(JSON.parse(out.stdout), [
    "agent", "run", "--reason", "tests", "-e", "KEY=klav://V/P/I/k", "--", "npm", "test",
  ]);
});

test("inject and totp", async () => {
  const work = join(dir, "work");
  mkdirSync(join(work, "config"), { recursive: true });
  await inject({ reason: "cfg", out: "config/x", cwd: work, reference: "klav://V/P/I/k" });
  assert.equal(await totp("klav://V/P/I", { reason: "2fa", wait: "1m" }), "123456");
});

test("inject writes only inside its working directory", async () => {
  const work = join(dir, "inside");
  mkdirSync(work, { recursive: true });
  symlinkSync(tmpdir(), join(work, "escape"));
  for (const out of ["/tmp/x", "../x", "escape/x", "nowhere/x"]) {
    await assert.rejects(inject({ reason: "cfg", out, cwd: work, reference: "klav://V/P/I/k" }), TypeError, out);
  }
});

test("failures carry klav's exit code", async () => {
  const error = await totp("FAIL", { reason: "x" }).catch((e) => e);
  assert.ok(error instanceof KlavError);
  assert.equal(error.code, EXIT.DENIED);
  assert.match(error.message, /policy denies/);
});

test("EXIT is klav's table of exit codes", async () => {
  // The same names and numbers as crates/klav-cli/src/error.rs, but the
  // usage error (2), which a program never handles.
  const rust = readFileSync(new URL("../../../crates/klav-cli/src/error.rs", import.meta.url), "utf8");
  const codes = Object.fromEntries(
    [...rust.matchAll(/pub\(crate\) const EXIT_([A-Z_]+): u8 = (\d+);/g)]
      .filter(([, name]) => name !== "USAGE")
      .map(([, name, code]) => [name, Number(code)]),
  );
  assert.deepEqual({ ...EXIT }, codes);
  const error = await totp("DELETING", { reason: "x" }).catch((e) => e);
  assert.equal(error.code, EXIT.ACCOUNT_DELETING);
});

test("approvalId and waitApproval", async () => {
  const out = await run("true", [], { reason: "retry", approvalId: "A-1" });
  assert.deepEqual(JSON.parse(out.stdout), [
    "agent", "run", "--reason", "retry", "--approval", "A-1", "--", "true",
  ]);
  assert.deepEqual(await waitApproval("A-1", { timeout: "5m", agent: "bot" }), [
    "approval", "wait", "A-1", "--json", "--timeout", "5m", "--agent", "bot",
  ]);
  assert.equal(EXIT.EXPIRED, 6);
});

test("tasks: the spec goes on stdin, the JSON comes back even when pending", async () => {
  const spec = {
    task: "Invoices",
    reason: "Reconcile",
    duration: "2h",
    access: [{ ref: "klav://V/P/AWS", permissions: ["fill"] }],
  };
  const out = await requestTask(spec, { wait: "5m", agent: "bot" });
  assert.deepEqual(out.args, [
    "agent", "task", "request", "-", "--json", "--agent", "bot", "--wait", "5m",
  ]);
  assert.deepEqual(JSON.parse(out.input), spec);
  await assert.rejects(requestTask({ ...spec, reason: "" }), TypeError);
  assert.deepEqual((await waitTask("T-1", { timeout: "1m" })).args, [
    "agent", "task", "wait", "T-1", "--json", "--timeout", "1m",
  ]);
  assert.deepEqual((await getTask("T-1")).args, ["agent", "task", "show", "T-1", "--json"]);
  assert.deepEqual((await endTask("T-1", { reason: "done" })).args, [
    "agent", "task", "end", "T-1", "--reason", "done", "--json",
  ]);
  await assert.rejects(endTask("T-1", {}), TypeError);
});

test("secret requests: metadata flags go to klav agent secret-request without any secret value", async () => {
  const { requestSecret, waitSecretRequest, getSecretRequest } = await import("../index.js");
  const out = await requestSecret(
    {
      reason: "Need Vercel AI Gateway key",
      title: "Vercel AI Gateway",
      type: "api-key",
      field: "api_key",
      project: "Personal/Dev",
      setupUrl: "https://vercel.com/dashboard/ai-gateway",
      proxyProposal: {
        profile: "vercel-ai",
        upstream: "https://ai-gateway.vercel.sh",
        methods: ["POST"],
        pathPrefixes: ["/v1"],
        ratePerMinute: 60,
      },
    },
    { wait: "2m", agent: "bot" },
  );
  assert.deepEqual(out, [
    "agent",
    "secret-request",
    "create",
    "--reason",
    "Need Vercel AI Gateway key",
    "--json",
    "--agent",
    "bot",
    "--type",
    "api-key",
    "--title",
    "Vercel AI Gateway",
    "--field",
    "api_key",
    "--project",
    "Personal/Dev",
    "--setup-url",
    "https://vercel.com/dashboard/ai-gateway",
    "--proxy-profile",
    "vercel-ai",
    "--proxy-upstream",
    "https://ai-gateway.vercel.sh",
    "--proxy-method",
    "POST",
    "--proxy-path-prefix",
    "/v1",
    "--proxy-rate",
    "60",
    "--wait",
    "2m",
  ]);
  await assert.rejects(requestSecret({ reason: "" }), TypeError);
  assert.deepEqual(await waitSecretRequest("SR-1", { timeout: "5m" }), [
    "agent", "secret-request", "wait", "SR-1", "--json", "--timeout", "5m",
  ]);
  assert.deepEqual(await getSecretRequest("SR-1"), [
    "agent", "secret-request", "show", "SR-1", "--json",
  ]);
});
