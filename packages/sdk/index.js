// Klav for agent runtimes in Node (ADR 0014 §9).
//
// A thin wrapper around the `klav` binary: every function runs
// `klav agent …` with the agent's own identity. Secrets never pass through
// this process: `fill` types into the browser from `klav`, `run` puts them
// in the child's environment, `inject` writes a 0600 file. Only `totp`
// returns a value (a one-time code), and only when the policy allows it.
//
// Arguments never carry secrets (they would show in `ps`): references,
// reasons and selectors only.

import { execFile } from "node:child_process";
import { realpath } from "node:fs/promises";
import { basename, dirname, resolve, sep } from "node:path";

/** Exit codes of `klav` (docs/cli.md). */
export const EXIT = Object.freeze({
  SECURITY: 3,
  PENDING: 4,
  DENIED: 5,
  EXPIRED: 6,
  PAUSED: 7,
  ACCOUNT_DELETING: 8,
  NO_TERMINAL: 9,
});

export class KlavError extends Error {
  constructor(message, code, stderr) {
    super(message);
    this.name = "KlavError";
    /**
     * `klav`'s exit code: 4 waits for the person, 5 denied, 6 expired,
     * 3 security, 7 paused, 8 the account is being deleted. On 7 and 8,
     * stop and tell the person; do not retry.
     */
    this.code = code;
    this.stderr = stderr;
  }
}

function binary() {
  return process.env.KLAV_BIN || "klav";
}

function common(options) {
  if (!options || typeof options.reason !== "string" || !options.reason.trim()) {
    throw new TypeError("options.reason is mandatory: say why the agent needs it");
  }
  const args = ["--reason", options.reason];
  if (options.agent) args.push("--agent", options.agent);
  if (options.wait) args.push("--wait", String(options.wait));
  if (options.approvalId) args.push("--approval", String(options.approvalId));
  return args;
}

function klav(args, { cwd, allowFailure = false, command = "agent", input } = {}) {
  return new Promise((resolve, reject) => {
    const child = execFile(
      binary(),
      [command, ...args],
      { cwd, maxBuffer: 16 * 1024 * 1024, encoding: "utf8" },
      (error, stdout, stderr) => {
        const code = error ? (typeof error.code === "number" ? error.code : 1) : 0;
        if (error && !allowFailure) {
          const message = stderr.trim().split("\n").pop() || error.message;
          reject(new KlavError(message, code, stderr));
          return;
        }
        resolve({ code, stdout, stderr });
      },
    );
    if (input !== undefined) child.stdin.end(input);
  });
}

/** The CDP target ID of a Playwright (Chromium) page. */
export async function targetId(page) {
  const session = await page.context().newCDPSession(page);
  try {
    const { targetInfo } = await session.send("Target.getTargetInfo");
    return targetInfo.targetId;
  } finally {
    await session.detach().catch(() => {});
  }
}

function cdpEndpoint(options) {
  const cdp = options.cdp || process.env.KLAV_CDP;
  if (!cdp) {
    throw new TypeError(
      "options.cdp (or KLAV_CDP) must be the browser's CDP address, e.g. http://127.0.0.1:9222",
    );
  }
  return cdp;
}

/**
 * Types a login (username and password), a card, or one field
 * (`…/Item/field`) into `page`. Klav checks the page's host against the
 * item's URLs and the policy first. With `submit: true` it then submits
 * the form. Resolves `{ url, filled, submitted?, navigated?, url_after? }`:
 * field names and addresses, never values.
 */
export async function fill(page, reference, options) {
  const args = ["fill", reference, ...common(options), "--cdp", cdpEndpoint(options)];
  args.push("--target", await targetId(page));
  for (const [field, selector] of Object.entries(options.selectors || {})) {
    args.push("--selector", `${field}=${selector}`);
  }
  if (options.submit) args.push("--submit");
  args.push("--json");
  const { stdout } = await klav(args, { cwd: options.cwd });
  return JSON.parse(stdout);
}

/**
 * Registers `page`'s browser as `sdk:<name>`, so `klav mcp` can fill into
 * it (`fill_login` with target `sdk:<name>`).
 */
export async function registerSession(name, page, options = {}) {
  const args = ["browser", "register", name, "--cdp", cdpEndpoint(options)];
  if (page) args.push("--target", await targetId(page));
  await klav(args);
}

/**
 * Runs `command` with secrets in its environment (`env`: NAME → reference,
 * plus `klav.toml` in `cwd`). Returns its exit code and its output with
 * the values redacted.
 */
export async function run(command, args, options) {
  const argv = ["run", ...common(options)];
  for (const [name, reference] of Object.entries(options.env || {})) {
    argv.push("-e", `${name}=${reference}`);
  }
  if (options.timeout) argv.push("--timeout", String(options.timeout));
  argv.push("--", command, ...(args || []));
  const { code, stdout, stderr } = await klav(argv, { cwd: options.cwd, allowFailure: true });
  return { code, stdout, stderr };
}

/**
 * `out` inside `cwd` (its directory must exist; symlinks resolved), as
 * `klav mcp` does: an agent never writes a secret outside its working
 * directory (layer 04).
 */
async function inside(cwd, out) {
  if (typeof out !== "string" || !out.trim()) throw new TypeError("options.out is mandatory");
  const joined = resolve(cwd, out);
  let parent;
  try {
    parent = await realpath(dirname(joined));
  } catch {
    throw new TypeError(`the directory of ${JSON.stringify(out)} does not exist`);
  }
  const root = await realpath(cwd);
  if (parent !== root && !parent.startsWith(root.endsWith(sep) ? root : root + sep)) {
    throw new TypeError(`${JSON.stringify(out)} is outside the working directory: inject only writes inside it`);
  }
  return resolve(parent, basename(joined));
}

/**
 * Writes a reference (`reference`) or a template file (`template`) into a
 * new 0600 file `out`, which must be inside `cwd` (the process's working
 * directory by default). A reference can name an attachment (an APNs
 * `.p8`): its bytes are written as they are (ADR 0016). Delete it when done.
 */
export async function inject(options) {
  const args = common(options);
  const out = await inside(options.cwd ?? process.cwd(), options.out);
  args.unshift("inject");
  args.push("-o", out);
  if (options.reference) args.push("-r", options.reference);
  else if (options.template) args.push("-i", options.template);
  else throw new TypeError("give options.reference or options.template");
  if (options.force) args.push("--force");
  await klav(args, { cwd: options.cwd });
}

/**
 * The current one-time code of an item (`totp` is `ask` by default: pass
 * `wait` to wait for the person). For the runtime to type, not for the LLM.
 */
export async function totp(reference, options) {
  const args = ["totp", reference, ...common(options)];
  if (options.field) args.push("--field", options.field);
  const { stdout } = await klav(args, { cwd: options.cwd });
  return stdout.trim();
}

/**
 * Waits for the person's decision on a request of this agent (ADR 0015):
 * resolves `{ approval_id, status, lease_until, used, expires_at }`, where
 * `status` is "approved", "pending" (the timeout passed), "denied" or
 * "expired". After "approved", retry the action with `approvalId`.
 */
export async function waitApproval(id, options = {}) {
  const args = ["wait", String(id), "--json"];
  if (options.timeout) args.push("--timeout", String(options.timeout));
  if (options.agent) args.push("--agent", options.agent);
  const { code, stdout, stderr } = await klav(args, {
    cwd: options.cwd,
    allowFailure: true,
    command: "approval",
  });
  const line = stdout.trim();
  if (!line) {
    const message = stderr.trim().split("\n").pop() || "klav approval wait failed";
    throw new KlavError(message, code, stderr);
  }
  return JSON.parse(line);
}

// ------------------------------------------------------------------ tasks

/** A task's JSON on stdout (it also comes with exit codes 4, 5 and 6). */
async function taskJson(args, options, input) {
  const { code, stdout, stderr } = await klav(["task", ...args], {
    cwd: options.cwd,
    allowFailure: true,
    input,
  });
  const text = stdout.trim();
  if (!text) {
    const message = stderr.trim().split("\n").pop() || "klav agent task failed";
    throw new KlavError(message, code, stderr);
  }
  return JSON.parse(text);
}

function agentArgs(options) {
  return options.agent ? ["--agent", options.agent] : [];
}

/**
 * Asks the person for a task (ADR 0021): several items and permissions for
 * one job, approved with one card. `spec` is
 * `{ task, reason, duration: "2h", access: [{ ref, permissions, domain? }] }`;
 * it goes to `klav` on stdin. With `options.wait` ("10m") it waits for the
 * person. Resolves the task as `klav agent task request --json` prints it:
 * `{ task_id, status, expires_at, access?, removed? }`, `status` being
 * "pending", "approved", "denied", "expired" or "ended". Work only with
 * what comes back in `access`.
 */
export async function requestTask(spec, options = {}) {
  if (!spec || typeof spec.reason !== "string" || !spec.reason.trim()) {
    throw new TypeError("spec.reason is mandatory: say why the agent needs the task");
  }
  const args = ["request", "-", "--json", ...agentArgs(options)];
  if (options.wait) args.push("--wait", String(options.wait));
  return taskJson(args, options, JSON.stringify(spec));
}

/** Waits for the person's decision on a task (exit codes as `klav agent task wait`). */
export async function waitTask(id, options = {}) {
  const args = ["wait", String(id), "--json", ...agentArgs(options)];
  if (options.timeout) args.push("--timeout", String(options.timeout));
  return taskJson(args, options);
}

/** A task of this agent and what the person approved. */
export async function getTask(id, options = {}) {
  return taskJson(["show", String(id), "--json", ...agentArgs(options)], options);
}

/** Ends a task of this agent when the job is done. */
export async function endTask(id, options) {
  if (!options || typeof options.reason !== "string" || !options.reason.trim()) {
    throw new TypeError("options.reason is mandatory");
  }
  return taskJson(
    ["end", String(id), "--reason", options.reason, "--json", ...agentArgs(options)],
    options,
  );
}

// -------------------------------------------------------- secret requests

/** A secret request's JSON on stdout (also exits 4, 5 or 6). */
async function secretRequestJson(args, options) {
  const { code, stdout, stderr } = await klav(["secret-request", ...args], {
    cwd: options.cwd,
    allowFailure: true,
  });
  const text = stdout.trim();
  if (!text) {
    const message = stderr.trim().split("\n").pop() || "klav agent secret-request failed";
    throw new KlavError(message, code, stderr);
  }
  return JSON.parse(text);
}

/**
 * Proposes a secret for the person to enter on their own device (ADR 0046).
 * Sends metadata only (never a secret value); resolves the verified outcome
 * `{ status, request_id, in_grant?, ref?, field?, proxy_profile?, expires_at? }`.
 */
export async function requestSecret(spec, options = {}) {
  if (!spec || typeof spec.reason !== "string" || !spec.reason.trim()) {
    throw new TypeError("spec.reason is mandatory: say why the agent needs this secret");
  }
  const args = ["create", "--reason", spec.reason, "--json", ...agentArgs(options)];
  if (spec.mode) args.push("--mode", spec.mode);
  if (spec.type) args.push("--type", spec.type);
  if (spec.title) args.push("--title", spec.title);
  if (spec.ref) args.push("--ref", spec.ref);
  if (spec.field) args.push("--field", spec.field);
  if (spec.project) args.push("--project", spec.project);
  if (spec.placeholder) args.push("--placeholder", spec.placeholder);
  if (spec.setupUrl) args.push("--setup-url", spec.setupUrl);
  if (spec.baseUrl) args.push("--base-url", spec.baseUrl);
  for (const url of spec.urls || []) {
    args.push("--url", url);
  }
  if (spec.notes) args.push("--notes", spec.notes);
  if (spec.proxyProposal) {
    const pp = spec.proxyProposal;
    if (pp.profile) args.push("--proxy-profile", pp.profile);
    if (pp.upstream) args.push("--proxy-upstream", pp.upstream);
    if (pp.header) args.push("--proxy-header", pp.header);
    if (pp.prefix !== undefined) args.push("--proxy-prefix", pp.prefix);
    if (pp.methods?.length) args.push("--proxy-method", pp.methods.join(","));
    if (pp.askMethods?.length) args.push("--proxy-ask-method", pp.askMethods.join(","));
    for (const prefix of pp.pathPrefixes || []) {
      args.push("--proxy-path-prefix", prefix);
    }
    if (pp.ratePerMinute !== undefined) args.push("--proxy-rate", String(pp.ratePerMinute));
  }
  if (options.wait) args.push("--wait", String(options.wait));
  return secretRequestJson(args, options);
}

/** Waits for the person to fulfill or deny a secret request (ADR 0046). */
export async function waitSecretRequest(id, options = {}) {
  const args = ["wait", String(id), "--json", ...agentArgs(options)];
  if (options.timeout) args.push("--timeout", String(options.timeout));
  return secretRequestJson(args, options);
}

/** Reads the verified state of one of this agent's secret requests. */
export async function getSecretRequest(id, options = {}) {
  return secretRequestJson(["show", String(id), "--json", ...agentArgs(options)], options);
}
