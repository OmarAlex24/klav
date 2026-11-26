// node --test apps/web/test/
// Auto-issued beta invites and the Turnstile check (ADR 0050), against one
// local mock that plays klav-server's internal route, Cloudflare Email
// Sending and Turnstile's siteverify.
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { after, afterEach, before, beforeEach, describe, test } from "node:test";
import { fileURLToPath } from "node:url";

import { autoInviteFromEnv, createSite, inlineHashes, inviteEmail, turnstileFromEnv } from "../server.mjs";

const WEB = join(dirname(fileURLToPath(import.meta.url)), "..");
const SERVER_TOKEN = "server-token-not-a-secret-0123456789abcdef";
const CF_TOKEN = "cf-email-token-not-a-secret";
const TS_SECRET = "turnstile-secret-not-a-secret";
const ACCOUNT = "0123456789abcdef0123456789abcdef";
const SITE_KEY = "1x00000000000000000000AA"; // Cloudflare's always-passes test key
const CODE = "KLAV-ABCDE-FGHJK-MNPQR-STVWX-YZ0123";

const dir = mkdtempSync(join(tmpdir(), "klav-web-auto-"));
after(() => rmSync(dir, { recursive: true, force: true }));
let n = 0;
const dbPath = () => join(dir, `a${++n}.db`);

/** The mock upstream: records every call, answers as `mock.behave` says. */
const mock = { calls: [], behave: {}, issued: 0, server: null, base: "" };
function resetMock() {
  mock.calls = [];
  mock.issued = 0;
  mock.behave = {
    issue: () => {
      mock.issued += 1;
      const id = `00000000-0000-4000-8000-${String(mock.issued).padStart(12, "0")}`;
      return [201, { id, code: CODE, expires_at: Date.UTC(2026, 11, 10, 18, 4) }];
    },
    revoke: () => [204, null],
    email: () => [200, { success: true, errors: [], messages: [], result: { delivered: [], queued: [], permanent_bounces: [], message_id: "m1" } }],
    verify: () => [200, { success: true }],
  };
}

before(async () => {
  resetMock();
  mock.server = createServer((req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const body = Buffer.concat(chunks).toString("utf8");
      const call = { method: req.method, path: req.url, headers: req.headers, body };
      mock.calls.push(call);
      let kind;
      if (req.url === "/v1/internal/invites/auto") kind = "issue";
      else if (/^\/v1\/internal\/invites\/auto\/[^/]+\/revoke$/.test(req.url)) kind = "revoke";
      else if (req.url === `/client/v4/accounts/${ACCOUNT}/email/sending/send`) kind = "email";
      else if (req.url === "/turnstile/v0/siteverify") kind = "verify";
      call.kind = kind;
      const [status, answer] = kind ? mock.behave[kind](call) : [404, { error: "nope" }];
      if (status === "hang") return; // never answers: the client's timeout or abort
      res.writeHead(status, answer ? { "Content-Type": "application/json" } : {});
      res.end(answer ? JSON.stringify(answer) : undefined);
    });
  });
  await new Promise((done) => mock.server.listen(0, "127.0.0.1", done));
  mock.base = `http://127.0.0.1:${mock.server.address().port}`;
});
after(() => new Promise((done) => {
  mock.server.close(done);
  mock.server.closeAllConnections();
}));
beforeEach(resetMock);

/** Every console line the site writes, to check no secret reaches it. */
const logged = [];
const original = { log: console.log, warn: console.warn, error: console.error };
before(() => {
  for (const name of Object.keys(original)) console[name] = (...args) => logged.push(args.map(String).join(" "));
});
after(() => Object.assign(console, original));

function autoEnv(extra = {}) {
  return {
    KLAV_BETA_AUTO_CAP: "3",
    KLAV_AUTO_INVITE_URL: mock.base,
    KLAV_AUTO_INVITE_TOKEN: SERVER_TOKEN,
    KLAV_CF_ACCOUNT_ID: ACCOUNT,
    KLAV_CF_EMAIL_TOKEN: CF_TOKEN,
    KLAV_CF_EMAIL_FROM: "Klav <invites@klav.dev>",
    KLAV_CF_EMAIL_API_BASE: `${mock.base}/client/v4`,
    ...extra,
  };
}
const turnstileEnv = (extra = {}) => ({
  KLAV_TURNSTILE_SITE_KEY: SITE_KEY,
  KLAV_TURNSTILE_SECRET: TS_SECRET,
  KLAV_TURNSTILE_VERIFY_URL: `${mock.base}/turnstile/v0/siteverify`,
  ...extra,
});

async function start(env, options = {}) {
  const site = createSite({ dbPath: dbPath(), publicDir: join(WEB, "public"), rateLimit: { max: 1000, windowMs: 60_000 }, issueRateLimit: { max: 1000, windowMs: 60_000 }, env, ...options });
  await new Promise((done) => site.server.listen(0, "127.0.0.1", done));
  const base = `http://127.0.0.1:${site.server.address().port}`;
  return {
    ...site,
    base,
    stop: () => new Promise((done) => site.server.close(done)),
    post: async (body) => {
      const res = await fetch(`${base}/api/waitlist`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
      return { status: res.status, body: await res.json() };
    },
    row: (email) => site.db.prepare("SELECT * FROM waitlist WHERE email = ?").get(email),
  };
}
const kinds = () => mock.calls.map((c) => c.kind);

describe("configuration from the environment", () => {
  test("auto invites are off without a cap, and off with a line naming what's missing, never its value", () => {
    const lines = [];
    const warn = (l) => lines.push(l);
    assert.equal(autoInviteFromEnv({}, warn), null);
    assert.equal(autoInviteFromEnv({ KLAV_BETA_AUTO_CAP: "0" }, warn), null);
    assert.deepEqual(lines, []);
    assert.equal(autoInviteFromEnv({ ...autoEnv(), KLAV_CF_EMAIL_TOKEN: "", KLAV_AUTO_INVITE_TOKEN: "short" }, warn), null);
    assert.match(lines.at(-1), /KLAV_AUTO_INVITE_TOKEN, KLAV_CF_EMAIL_TOKEN/);
    assert.equal(lines.at(-1).includes("short"), false);
    for (const [name, value] of [["KLAV_BETA_AUTO_CAP", "-1"], ["KLAV_BETA_AUTO_CAP", "5x"], ["KLAV_AUTO_INVITE_URL", "ftp://x"], ["KLAV_CF_ACCOUNT_ID", "nope"], ["KLAV_CF_EMAIL_FROM", "not an address"], ["KLAV_CF_EMAIL_API_BASE", "x"]]) {
      assert.equal(autoInviteFromEnv(autoEnv({ [name]: value }), warn), null, name);
      assert.match(lines.at(-1), new RegExp(name));
    }
    const on = autoInviteFromEnv(autoEnv(), warn);
    assert.equal(on.cap, 3);
    assert.deepEqual(on.from, { address: "invites@klav.dev", name: "Klav" });
    assert.equal(autoInviteFromEnv(autoEnv({ KLAV_CF_EMAIL_FROM: "invites@klav.dev" }), warn).from, "invites@klav.dev");
    assert.equal(autoInviteFromEnv(autoEnv({ KLAV_CF_EMAIL_API_BASE: "" }), warn).emailApi, "https://api.cloudflare.com/client/v4");
  });

  test("Turnstile needs both a well-formed site key and a secret", () => {
    const lines = [];
    const warn = (l) => lines.push(l);
    assert.equal(turnstileFromEnv({}, warn), null);
    assert.equal(turnstileFromEnv({ KLAV_TURNSTILE_SITE_KEY: SITE_KEY }, warn), null);
    assert.match(lines.at(-1), /KLAV_TURNSTILE_SECRET/);
    assert.equal(turnstileFromEnv({ KLAV_TURNSTILE_SECRET: TS_SECRET }, warn), null);
    assert.match(lines.at(-1), /KLAV_TURNSTILE_SITE_KEY/);
    for (const key of ['1x0000"><script>', "nope", "0x" + "A".repeat(200)]) {
      assert.equal(turnstileFromEnv({ KLAV_TURNSTILE_SITE_KEY: key, KLAV_TURNSTILE_SECRET: TS_SECRET }, warn), null, key);
    }
    assert.equal(lines.some((l) => l.includes(TS_SECRET)), false);
    const on = turnstileFromEnv({ KLAV_TURNSTILE_SITE_KEY: SITE_KEY, KLAV_TURNSTILE_SECRET: TS_SECRET }, warn);
    assert.equal(on.verifyUrl, "https://challenges.cloudflare.com/turnstile/v0/siteverify");
  });
});

describe("the page and its CSP, with and without Turnstile", () => {
  test("without Turnstile: no widget, no Cloudflare in the CSP, the same policy as a site with nothing configured", async () => {
    const plain = await start({});
    const auto = await start(autoEnv());
    for (const s of [plain, auto]) {
      const res = await fetch(`${s.base}/`);
      const html = await res.text();
      const csp = res.headers.get("content-security-policy");
      assert.equal(html.includes('class="cf-turnstile'), false);
      assert.equal(html.includes("challenges.cloudflare.com"), false);
      assert.equal(html.includes("<!--turnstile-->"), false, "the marker goes");
      assert.equal(csp.includes("challenges.cloudflare.com"), false);
      assert.equal(csp.includes("frame-src"), false);
    }
    assert.equal(auto.csp, plain.csp);
    await plain.stop();
    await auto.stop();
  });

  test("with Turnstile: the widget in the form, its script and iframe origin in the CSP, inline hashes unchanged", async () => {
    const plain = await start({});
    const s = await start(turnstileEnv());
    const res = await fetch(`${s.base}/`);
    const html = await res.text();
    const csp = res.headers.get("content-security-policy");
    const form = html.match(/<form class="waitlist"[\s\S]*?<\/form>/)[0];
    assert.match(form, new RegExp(`<div class="cf-turnstile wl-turnstile" id="wl-turnstile" data-sitekey="${SITE_KEY}"`));
    assert.match(form, /<script src="https:\/\/challenges\.cloudflare\.com\/turnstile\/v0\/api\.js" async defer><\/script>/);
    assert.match(csp, /script-src 'sha256-[^;]* https:\/\/challenges\.cloudflare\.com;/);
    assert.match(csp, /; frame-src https:\/\/challenges\.cloudflare\.com;/);
    assert.equal(csp.includes("unsafe-inline"), false);
    // The inline script and style hash the same as without Turnstile.
    for (const h of [...inlineHashes(html, "script"), ...inlineHashes(html, "style")]) assert.ok(csp.includes(h), h);
    assert.deepEqual(inlineHashes(html, "script"), inlineHashes(await (await fetch(`${plain.base}/`)).text(), "script"));
    // Only the page changes: the privacy policy keeps its own policy.
    const privacy = await fetch(`${s.base}/privacy`);
    assert.equal(privacy.headers.get("content-security-policy").includes("challenges.cloudflare.com"), false);
    await s.stop();
    await plain.stop();
  });

  test("the page sends the Turnstile token, resets the widget and has a message for every status, in both languages", () => {
    const html = readFileSync(join(WEB, "public", "index.html"), "utf8");
    const script = html.match(/<script>([\s\S]*?)<\/script>/)[1];
    assert.equal((html.match(/<!--turnstile-->/g) ?? []).length, 1);
    assert.ok(html.indexOf("<!--turnstile-->") > html.indexOf('<form class="waitlist"'));
    assert.ok(html.indexOf("<!--turnstile-->") < html.indexOf("</form>"));
    assert.match(script, /turnstile_token/);
    assert.match(script, /window\.turnstile\.reset/);
    for (const key of ["invited: (e) =>", "already: (e) =>", "check: \"", "checkFailed: \""]) {
      assert.equal(script.split(key).length - 1, 2, `${key} in en and es`);
    }
    assert.match(script, /already_invited: "already"/);
  });
});

describe("Turnstile on the form", () => {
  let s;
  before(async () => { s = await start(turnstileEnv()); });
  after(() => s.stop());

  test("a passing token goes to siteverify with the secret and no IP, and the address is stored", async () => {
    const r = await s.post({ email: "ana@example.com", lang: "en", turnstile_token: "tok-1" });
    assert.deepEqual(r, { status: 200, body: { ok: true } });
    const verify = mock.calls.find((c) => c.kind === "verify");
    const form = new URLSearchParams(verify.body);
    assert.equal(form.get("secret"), TS_SECRET);
    assert.equal(form.get("response"), "tok-1");
    assert.equal(form.has("remoteip"), false);
    assert.ok(s.row("ana@example.com"));
  });

  test("no token is 400, a failed check is 403, and nothing is stored", async () => {
    assert.deepEqual(await s.post({ email: "bo@example.com" }), { status: 400, body: { error: "turnstile_required" } });
    assert.deepEqual(kinds(), []);
    mock.behave.verify = () => [200, { success: false, "error-codes": ["invalid-input-response"] }];
    assert.deepEqual(await s.post({ email: "bo@example.com", turnstile_token: "bad" }), { status: 403, body: { error: "turnstile_failed" } });
    assert.equal(s.row("bo@example.com"), undefined);
  });

  test("fails closed when siteverify errs, answers garbage or can't be reached", async () => {
    for (const behave of [() => [500, { oops: true }], () => [200, { success: "yes" }]]) {
      mock.behave.verify = behave;
      const r = await s.post({ email: "cy@example.com", turnstile_token: "t" });
      assert.notEqual(r.status, 200);
    }
    const down = await start(turnstileEnv({ KLAV_TURNSTILE_VERIFY_URL: "http://127.0.0.1:1/siteverify" }));
    assert.deepEqual(await down.post({ email: "cy@example.com", turnstile_token: "t" }), { status: 503, body: { error: "turnstile_unavailable" } });
    assert.equal(s.row("cy@example.com"), undefined);
    assert.equal(down.row("cy@example.com"), undefined);
    await down.stop();
  });
});

describe("auto-issued invites", () => {
  let s;
  beforeEach(async () => { s = await start(autoEnv()); });
  afterEach(() => s.stop());

  test("a new address gets its invite by email, in English, and is marked", async () => {
    const r = await s.post({ email: " Ana@Example.com ", lang: "en" });
    assert.deepEqual(r, { status: 200, body: { ok: true, status: "invited" } });
    assert.deepEqual(kinds(), ["issue", "email"]);
    const [issue, email] = mock.calls;
    assert.equal(issue.headers.authorization, `Bearer ${SERVER_TOKEN}`);
    assert.deepEqual(JSON.parse(issue.body), { email: "ana@example.com" });
    assert.equal(email.headers.authorization, `Bearer ${CF_TOKEN}`);
    const sent = JSON.parse(email.body);
    assert.deepEqual(sent.from, { address: "invites@klav.dev", name: "Klav" });
    assert.deepEqual(sent.to, ["ana@example.com"]);
    assert.equal(sent.subject, "Your Klav beta invite");
    for (const part of [CODE, "ana@example.com", "https://klav.dev/download/mac", "https://docs.klav.dev", "December 10, 2026", "14 days", '"Set up this Mac" → "Create an account"', "klav signup", "support@klav.dev", "20 USD", "60 days"]) {
      assert.ok(sent.text.includes(part), part);
    }
    assert.equal(sent.html, undefined, "text only");
    const row = s.row("ana@example.com");
    assert.equal(row.note, "auto-beta");
    assert.match(row.invited_at, /^\d{4}-\d\d-\d\dT/);
  });

  test("in Spanish for a Spanish page, written natively", async () => {
    const r = await s.post({ email: "eva@example.com", lang: "es" });
    assert.equal(r.body.status, "invited");
    const sent = JSON.parse(mock.calls.find((c) => c.kind === "email").body);
    assert.equal(sent.subject, "Tu invitación a la beta de Klav");
    for (const part of [CODE, "eva@example.com", "https://klav.dev/download/mac", "https://docs.klav.dev", "10 de diciembre de 2026", "14 días", "«Configurar este Mac» → «Crear una cuenta»", "klav signup", "support@klav.dev", "20 USD", "60 días"]) {
      assert.ok(sent.text.includes(part), part);
    }
    assert.equal(sent.text.includes("Set up this Mac"), false);
  });

  test("an address already sent one hears already_invited, and nothing is called or sent again", async () => {
    await s.post({ email: "ana@example.com", lang: "en" });
    mock.calls = [];
    const r = await s.post({ email: "ANA@example.com", lang: "es" });
    assert.deepEqual(r.body, { ok: true, status: "already_invited" });
    assert.deepEqual(kinds(), []);
  });

  test("klav-server's already_invited is passed on, without an email or a mark", async () => {
    mock.behave.issue = () => [409, { error: "already_invited", message: "x" }];
    const r = await s.post({ email: "ana@example.com" });
    assert.deepEqual(r.body, { ok: true, status: "already_invited" });
    assert.deepEqual(kinds(), ["issue"]);
    assert.equal(s.row("ana@example.com").invited_at, null);
  });

  test("klav-server's cap_reached leaves the address waiting on the list", async () => {
    mock.behave.issue = () => [409, { error: "cap_reached", message: "x" }];
    const r = await s.post({ email: "ana@example.com" });
    assert.deepEqual(r.body, { ok: true, status: "waitlisted" });
    assert.deepEqual(kinds(), ["issue"]);
    assert.equal(s.row("ana@example.com").invited_at, null);
  });

  test("the site's own cap stops before calling klav-server", async () => {
    for (const e of ["a@example.com", "b@example.com", "c@example.com"]) assert.equal((await s.post({ email: e })).body.status, "invited");
    mock.calls = [];
    const r = await s.post({ email: "d@example.com" });
    assert.deepEqual(r.body, { ok: true, status: "waitlisted" });
    assert.deepEqual(kinds(), []);
    assert.equal(s.row("d@example.com").invited_at, null);
  });

  test("a failed email revokes the invite, so the seat isn't burned, and the address stays pending", async () => {
    const failures = [
      () => [500, { success: false, errors: [{ code: 10001, message: "x" }] }],
      () => [200, { success: false, errors: [] }],
      () => [200, { success: true, result: { delivered: [], permanent_bounces: ["f3@example.com"] } }],
      () => [200, { success: true, result: { delivered: [], suppressed_recipients: ["f4@example.com"] } }],
      () => [403, null],
    ];
    for (const [i, behave] of failures.entries()) {
      mock.calls = [];
      mock.behave.email = behave;
      const email = `f${i + 1}@example.com`;
      const r = await s.post({ email });
      assert.deepEqual(r.body, { ok: true, status: "waitlisted" }, email);
      assert.deepEqual(kinds(), ["issue", "email", "revoke"], email);
      const revoke = mock.calls[2];
      assert.equal(revoke.path, `/v1/internal/invites/auto/00000000-0000-4000-8000-${String(i + 1).padStart(12, "0")}/revoke`);
      assert.equal(revoke.headers.authorization, `Bearer ${SERVER_TOKEN}`);
      assert.equal(s.row(email).invited_at, null, email);
    }
    // A later try for the same address can still be sent its invite.
    mock.calls = [];
    mock.behave.email = () => [200, { success: true, result: { delivered: ["f1@example.com"] } }];
    assert.equal((await s.post({ email: "f1@example.com" })).body.status, "invited");
  });

  test("klav-server down, erring or answering garbage: the address waits, and a malformed answer is revoked", async () => {
    mock.behave.issue = () => [500, { error: "internal" }];
    assert.equal((await s.post({ email: "a@example.com" })).body.status, "waitlisted");
    mock.calls = [];
    mock.behave.issue = () => [201, { id: "00000000-0000-4000-8000-000000000009", code: "not a code", expires_at: 1 }];
    assert.equal((await s.post({ email: "b@example.com" })).body.status, "waitlisted");
    assert.deepEqual(kinds(), ["issue", "revoke"]);
    const down = await start(autoEnv({ KLAV_AUTO_INVITE_URL: "http://127.0.0.1:1" }));
    assert.deepEqual((await down.post({ email: "c@example.com" })).body, { ok: true, status: "waitlisted" });
    assert.ok(down.row("c@example.com"));
    await down.stop();
  });

  test("the honeypot answers like a real address that waits, and nothing is stored or called", async () => {
    const r = await s.post({ email: "bot@example.com", website: "http://spam" });
    assert.deepEqual(r, { status: 200, body: { ok: true, status: "waitlisted" } });
    assert.deepEqual(kinds(), []);
    assert.equal(s.row("bot@example.com"), undefined);
  });

  test("one client gets few invites sent automatically; more of its addresses wait on the list", async () => {
    const limited = await start(autoEnv({ KLAV_BETA_AUTO_CAP: "50" }), { issueRateLimit: { max: 2, windowMs: 60_000 } });
    const got = [];
    for (const e of ["a@example.com", "b@example.com", "c@example.com", "d@example.com"]) got.push((await limited.post({ email: e })).body.status);
    assert.deepEqual(got, ["invited", "invited", "waitlisted", "waitlisted"]);
    assert.equal(kinds().filter((k) => k === "issue").length, 2);
    assert.ok(limited.row("d@example.com"));
    await limited.stop();
  });

  test("with Turnstile too: the check comes first, then the invite", async () => {
    const both = await start({ ...autoEnv(), ...turnstileEnv() });
    assert.equal((await both.post({ email: "a@example.com" })).status, 400);
    assert.deepEqual(kinds(), []);
    assert.equal((await both.post({ email: "a@example.com", turnstile_token: "t" })).body.status, "invited");
    assert.deepEqual(kinds(), ["verify", "issue", "email"]);
    await both.stop();
  });
});

describe("the privacy policy names Cloudflare's part", () => {
  test("Turnstile and Email Sending, in both languages of the page and in privacidad.md", () => {
    const html = readFileSync(join(WEB, "public", "privacy", "index.html"), "utf8");
    const md = readFileSync(join(WEB, "..", "..", "docs", "privacidad.md"), "utf8").replace(/\s+/g, " ");
    const en = html.slice(html.indexOf('<article id="en"'), html.indexOf('<article id="es"'));
    const es = html.slice(html.indexOf('<article id="es"'));
    for (const text of [en, es, md]) {
      assert.match(text, /Cloudflare Email Sending/);
      assert.match(text, /Cloudflare Turnstile/);
    }
    assert.match(en, /Our site doesn’t send it your IP address, and doesn’t keep it/);
    assert.match(es, /Nuestro sitio no le manda tu IP ni la guarda/);
    assert.match(md, /Our site doesn't send it your IP address, and doesn't keep it/);
    assert.match(md, /Nuestro sitio no le manda tu IP ni la guarda/);
  });
});

describe("secrets in the log", () => {
  test("no code, token or secret was ever written to the console by these tests", () => {
    const all = logged.join("\n");
    assert.ok(all.includes("auto invite:"), "the failures above were logged");
    for (const secret of [CODE, SERVER_TOKEN, CF_TOKEN, TS_SECRET]) assert.equal(all.includes(secret), false, secret);
  });

  test("the email builder puts the code in the body only", () => {
    for (const lang of ["en", "es"]) {
      const { subject } = inviteEmail(lang, "a@example.com", CODE, Date.UTC(2026, 0, 1));
      assert.equal(subject.includes(CODE), false);
    }
  });
});
