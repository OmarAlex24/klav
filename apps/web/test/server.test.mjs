// node --test apps/web/test/
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { connect } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { after, before, describe, test } from "node:test";
import { fileURLToPath } from "node:url";
import vm from "node:vm";

import { createSite, DOWNLOADS, inlineHashes, OPENABLE, openDatabase, parseOpen, renderPage } from "../server.mjs";
import { ASSETS } from "../../../scripts/release/kit.mjs";

const WEB = join(dirname(fileURLToPath(import.meta.url)), "..");
const TOKEN = "test-token-not-a-secret";

// Every database lives here; removed after the suite, also when it fails.
const dir = mkdtempSync(join(tmpdir(), "klav-web-test-"));
after(() => rmSync(dir, { recursive: true, force: true }));
let n = 0;
const dbPath = () => join(dir, `w${++n}.db`);

/** Sends `request` byte for byte and returns the whole answer as text. */
function raw(site, request) {
  return new Promise((done, fail) => {
    const socket = connect(site.server.address().port, "127.0.0.1", () => socket.end(request));
    const chunks = [];
    socket.on("data", (chunk) => chunks.push(chunk));
    socket.on("end", () => done(Buffer.concat(chunks).toString("latin1")));
    socket.on("error", fail);
  });
}

async function start(options = {}) {
  const site = createSite({ dbPath: dbPath(), publicDir: join(WEB, "public"), ...options });
  await new Promise((done) => site.server.listen(0, "127.0.0.1", done));
  const base = `http://127.0.0.1:${site.server.address().port}`;
  return {
    ...site,
    base,
    stop: () => new Promise((done) => site.server.close(done)),
    post: (body, headers = {}) =>
      fetch(`${base}/api/waitlist`, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...headers },
        body: typeof body === "string" ? body : JSON.stringify(body),
      }),
    rows: () => site.db.prepare("SELECT * FROM waitlist ORDER BY id").all(),
  };
}

describe("waitlist signup", () => {
  let s;
  before(async () => { s = await start({ rateLimit: { max: 1000, windowMs: 60_000 } }); });
  after(() => s.stop());

  test("stores a valid email, lowercased and trimmed, with its language", async () => {
    const res = await s.post({ email: "  Ana@Example.COM ", lang: "es" });
    assert.equal(res.status, 200);
    assert.deepEqual(await res.json(), { ok: true });
    const rows = s.rows();
    assert.equal(rows.length, 1);
    assert.equal(rows[0].email, "ana@example.com");
    assert.equal(rows[0].lang, "es");
    assert.match(rows[0].created_at, /^\d{4}-\d\d-\d\dT/);
  });

  test("a repeat gets the same answer and no second row", async () => {
    const res = await s.post({ email: "ANA@example.com", lang: "en" });
    assert.equal(res.status, 200);
    assert.deepEqual(await res.json(), { ok: true });
    assert.equal(s.rows().length, 1);
  });

  test("an unknown language is stored as null", async () => {
    await s.post({ email: "bo@example.com", lang: "fr" });
    assert.equal(s.rows().find((r) => r.email === "bo@example.com").lang, null);
  });

  test("rejects emails that aren't one", async () => {
    for (const email of ["", "ana", "ana@", "ana@example", "a b@example.com", 42, `${"a".repeat(250)}@x.io`]) {
      const res = await s.post({ email });
      assert.equal(res.status, 400, String(email));
      assert.deepEqual(await res.json(), { error: "invalid_email" });
    }
  });

  test("the honeypot answers 200 and stores nothing", async () => {
    const before = s.rows().length;
    const res = await s.post({ email: "bot@example.com", website: "http://spam.example" });
    assert.equal(res.status, 200);
    assert.deepEqual(await res.json(), { ok: true });
    assert.equal(s.rows().length, before);
  });

  test("only JSON, only POST, nothing large, nothing malformed", async () => {
    const form = await fetch(`${s.base}/api/waitlist`, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: "email=a%40b.co" });
    assert.equal(form.status, 415);
    assert.equal((await fetch(`${s.base}/api/waitlist`)).status, 405);
    assert.equal((await s.post("{not json")).status, 400);
    assert.equal((await s.post("[1]")).status, 400);
    assert.equal((await s.post("null")).status, 400);
    const big = await s.post({ email: "c@example.com", pad: "x".repeat(4096) });
    assert.equal(big.status, 413);
    assert.equal(s.rows().some((r) => r.email === "c@example.com"), false);
  });

  test("refuses a post from another site's page", async () => {
    const res = await s.post({ email: "x@example.com" }, { Origin: "https://evil.example" });
    assert.equal(res.status, 403);
    const same = await s.post({ email: "x@example.com" }, { Origin: s.base });
    assert.equal(same.status, 200);
  });

  test("the table has no column for addresses or agents", () => {
    const cols = s.db.prepare("PRAGMA table_info(waitlist)").all().map((c) => c.name);
    assert.deepEqual(cols, ["id", "email", "lang", "created_at", "invited_at", "note"]);
  });

  test("a signup is pending: no invite date, no note", () => {
    for (const row of s.rows()) {
      assert.equal(row.invited_at, null);
      assert.equal(row.note, null);
    }
  });
});

describe("rate limit", () => {
  test("five tries per window, then 429 with Retry-After; other clients unaffected", async () => {
    let clock = 1_000_000;
    const s = await start({ rateLimit: { max: 5, windowMs: 600_000 }, now: () => clock, trustProxy: true });
    try {
      const from = (ip) => ({ "X-Real-IP": ip, "X-Forwarded-For": "203.0.113.9" });
      for (let i = 0; i < 5; i++) assert.equal((await s.post({ email: `r${i}@example.com` }, from("198.51.100.1"))).status, 200);
      const limited = await s.post({ email: "r9@example.com" }, from("198.51.100.1"));
      assert.equal(limited.status, 429);
      assert.ok(Number(limited.headers.get("retry-after")) > 0);
      assert.equal((await s.post({ email: "other@example.com" }, from("198.51.100.2"))).status, 200);
      clock += 600_000;
      assert.equal((await s.post({ email: "later@example.com" }, from("198.51.100.1"))).status, 200);
      // The client's address never reaches the database.
      const dump = JSON.stringify(s.rows());
      assert.equal(dump.includes("198.51.100"), false);
    } finally {
      await s.stop();
    }
  });
});

describe("export", () => {
  test("is 404 when no admin token is configured", async () => {
    const s = await start();
    try {
      const res = await fetch(`${s.base}/api/waitlist/export`, { headers: { Authorization: `Bearer ${TOKEN}` } });
      assert.equal(res.status, 404);
    } finally {
      await s.stop();
    }
  });

  test("needs the exact token and returns CSV", async () => {
    const s = await start({ adminToken: TOKEN });
    try {
      await s.post({ email: "ana@example.com", lang: "es" });
      await s.post({ email: "bo@example.com", lang: "en" });
      assert.equal((await fetch(`${s.base}/api/waitlist/export`)).status, 401);
      const wrong = await fetch(`${s.base}/api/waitlist/export`, { headers: { Authorization: "Bearer nope" } });
      assert.equal(wrong.status, 401);
      const res = await fetch(`${s.base}/api/waitlist/export`, { headers: { Authorization: `Bearer ${TOKEN}` } });
      assert.equal(res.status, 200);
      assert.match(res.headers.get("content-type"), /^text\/csv/);
      assert.equal(res.headers.get("cache-control"), "no-store");
      const lines = (await res.text()).trim().split("\r\n");
      assert.equal(lines[0], "email,lang,created_at,invited_at,note");
      assert.match(lines[1], /^ana@example\.com,es,\d{4}-[^,]+,,$/);
      assert.match(lines[2], /^bo@example\.com,en,[^,]+,,$/);
    } finally {
      await s.stop();
    }
  });

  test("defuses cells a spreadsheet would run", async () => {
    const s = await start({ adminToken: TOKEN });
    try {
      s.db.prepare("INSERT INTO waitlist (email, lang, created_at) VALUES (?, ?, ?)").run("=cmd@example.com", null, "2026-11-05T00:00:00.000Z");
      const text = await (await fetch(`${s.base}/api/waitlist/export`, { headers: { Authorization: `Bearer ${TOKEN}` } })).text();
      assert.match(text, /\r\n'=cmd@example\.com,,2026/);
    } finally {
      await s.stop();
    }
  });

  test("defuses the note too, and quotes what needs quoting", async () => {
    const s = await start({ adminToken: TOKEN });
    try {
      const add = s.db.prepare("INSERT INTO waitlist (email, lang, created_at, invited_at, note) VALUES (?, ?, ?, ?, ?)");
      add.run("a@example.com", "en", "2026-11-05T00:00:00.000Z", "2026-11-06T00:00:00.000Z", "=HYPERLINK(\"http://evil.example\")");
      add.run("b@example.com", "es", "2026-11-05T00:00:00.000Z", "2026-11-06T00:00:00.000Z", "@SUM(A1)");
      add.run("c@example.com", "es", "2026-11-05T00:00:00.000Z", "2026-11-06T00:00:00.000Z", "waitlist, wave 1");
      const text = await (await fetch(`${s.base}/api/waitlist/export`, { headers: { Authorization: `Bearer ${TOKEN}` } })).text();
      const lines = text.trim().split("\r\n");
      assert.equal(lines[1], 'a@example.com,en,2026-11-05T00:00:00.000Z,2026-11-06T00:00:00.000Z,"\'=HYPERLINK(""http://evil.example"")"');
      assert.equal(lines[2], "b@example.com,es,2026-11-05T00:00:00.000Z,2026-11-06T00:00:00.000Z,'@SUM(A1)");
      assert.equal(lines[3], 'c@example.com,es,2026-11-05T00:00:00.000Z,2026-11-06T00:00:00.000Z,"waitlist, wave 1"');
    } finally {
      await s.stop();
    }
  });

  test("?pending=1 keeps only who hasn't been sent an invite", async () => {
    const s = await start({ adminToken: TOKEN });
    const csv = async (query) => {
      const res = await fetch(`${s.base}/api/waitlist/export${query}`, { headers: { Authorization: `Bearer ${TOKEN}` } });
      assert.equal(res.status, 200, query);
      return (await res.text()).trim().split("\r\n");
    };
    try {
      for (const email of ["ana@example.com", "bo@example.com", "cy@example.com"]) await s.post({ email, lang: "en" });
      s.db.prepare("UPDATE waitlist SET invited_at = ?, note = ? WHERE email = ?").run("2026-11-25T10:00:00.000Z", "waitlist", "bo@example.com");
      const pending = await csv("?pending=1");
      assert.equal(pending[0], "email,lang,created_at,invited_at,note");
      assert.deepEqual(pending.slice(1).map((l) => l.split(",")[0]), ["ana@example.com", "cy@example.com"]);
      const every = await csv("");
      assert.deepEqual(every.slice(1).map((l) => l.split(",")[0]), ["ana@example.com", "bo@example.com", "cy@example.com"]);
      assert.match(every[2], /,2026-11-25T10:00:00\.000Z,waitlist$/);
      // Anything but 1 is the whole list.
      for (const query of ["?pending=0", "?pending=true", "?pending="]) assert.equal((await csv(query)).length, 4, query);
      // The token still decides, whatever the query.
      assert.equal((await fetch(`${s.base}/api/waitlist/export?pending=1`)).status, 401);
    } finally {
      await s.stop();
    }
  });
});

describe("mark-invited", () => {
  const URL_ = "/api/waitlist/mark-invited";
  const mark = (s, body, headers = {}) =>
    fetch(`${s.base}${URL_}`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${TOKEN}`, ...headers },
      body: typeof body === "string" ? body : JSON.stringify(body),
    });

  test("is 404 when no admin token is configured", async () => {
    const s = await start();
    try {
      const res = await mark(s, { emails: ["ana@example.com"] });
      assert.equal(res.status, 404);
    } finally {
      await s.stop();
    }
  });

  test("needs the exact token, and refuses before reading the body", async () => {
    const s = await start({ adminToken: TOKEN });
    try {
      await s.post({ email: "ana@example.com" });
      for (const auth of [undefined, "Bearer nope", `Basic ${TOKEN}`, TOKEN, `Bearer ${TOKEN}x`]) {
        const headers = { "Content-Type": "application/json" };
        if (auth) headers.Authorization = auth;
        const res = await fetch(`${s.base}${URL_}`, { method: "POST", headers, body: JSON.stringify({ emails: ["ana@example.com"] }) });
        assert.equal(res.status, 401, String(auth));
        assert.equal(res.headers.get("www-authenticate"), "Bearer");
      }
      // Not even a malformed or oversized body gets past a wrong token.
      assert.equal((await mark(s, "{nope", { Authorization: "Bearer nope" })).status, 401);
      assert.equal((await mark(s, "x".repeat(20_000), { Authorization: "Bearer nope", "Content-Type": "text/plain" })).status, 401);
      assert.equal(s.rows()[0].invited_at, null);
    } finally {
      await s.stop();
    }
  });

  test("only POST, only JSON, at most 16 KB, a well-formed body", async () => {
    const s = await start({ adminToken: TOKEN });
    try {
      const get = await fetch(`${s.base}${URL_}`, { headers: { Authorization: `Bearer ${TOKEN}` } });
      assert.equal(get.status, 405);
      assert.equal(get.headers.get("allow"), "POST");
      assert.equal((await mark(s, "emails=a%40b.co", { "Content-Type": "application/x-www-form-urlencoded" })).status, 415);
      assert.equal((await mark(s, JSON.stringify({ emails: ["a@b.co"] }), { "Content-Type": "text/plain" })).status, 415);
      // 16 KB is the limit: just under answers, just over is 413.
      const under = JSON.stringify({ emails: ["a@b.co"], pad: "" });
      assert.equal((await mark(s, under.replace('""', JSON.stringify("x".repeat(16 * 1024 - under.length))))).status, 200);
      const big = await mark(s, { emails: ["a@b.co"], pad: "x".repeat(16 * 1024) });
      assert.equal(big.status, 413);
      for (const body of ["{nope", "null", "[1]", "42", '"a@b.co"']) {
        assert.equal((await mark(s, body)).status, 400, body);
      }
      const shapes = [
        [{}, "emails_required"],
        [{ emails: [] }, "emails_required"],
        [{ emails: "ana@example.com" }, "emails_required"],
        [{ emails: ["ana@example.com", 42] }, "invalid_email"],
        [{ emails: ["ana@example.com", "not-an-email"] }, "invalid_email"],
        [{ emails: [`${"a".repeat(250)}@x.io`] }, "invalid_email"],
        [{ emails: ["ana@example.com"], note: 7 }, "invalid_note"],
        [{ emails: ["ana@example.com"], note: "n".repeat(201) }, "invalid_note"],
      ];
      for (const [body, error] of shapes) {
        const res = await mark(s, body);
        assert.equal(res.status, 400, JSON.stringify(body));
        assert.equal((await res.json()).error, error, JSON.stringify(body));
      }
    } finally {
      await s.stop();
    }
  });

  test("at most 200 emails in one call; more is 400 and marks none", async () => {
    const s = await start({ adminToken: TOKEN, rateLimit: { max: 1000, windowMs: 60_000 } });
    try {
      await s.post({ email: "u0@example.com" });
      const emails = Array.from({ length: 201 }, (_, i) => `u${i}@example.com`);
      const over = await mark(s, { emails });
      assert.equal(over.status, 400);
      assert.deepEqual(await over.json(), { error: "too_many_emails", max: 200 });
      assert.equal(s.rows()[0].invited_at, null);
      const ok = await mark(s, { emails: emails.slice(0, 200) });
      assert.equal(ok.status, 200);
      assert.deepEqual(await ok.json(), { marked: 1, unknown: 199 });
    } finally {
      await s.stop();
    }
  });

  test("marks the emails it has, counts the ones it doesn't, and keeps the note", async () => {
    let clock = Date.parse("2026-11-25T12:00:00.000Z");
    const s = await start({ adminToken: TOKEN, now: () => clock, rateLimit: { max: 1000, windowMs: 60_000 } });
    try {
      for (const email of ["ana@example.com", "bo@example.com", "cy@example.com"]) await s.post({ email });
      // The same address in another case or with spaces is the same row, counted once.
      const res = await mark(s, { emails: [" ANA@example.com", "ana@example.com", "bo@example.com", "nobody@example.com"], note: " wave 1 " });
      assert.equal(res.status, 200);
      assert.match(res.headers.get("content-type"), /^application\/json/);
      assert.equal(res.headers.get("cache-control"), "no-store");
      assert.deepEqual(await res.json(), { marked: 2, unknown: 1 });
      const byEmail = Object.fromEntries(s.rows().map((r) => [r.email, r]));
      assert.equal(byEmail["ana@example.com"].invited_at, "2026-11-25T12:00:00.000Z");
      assert.equal(byEmail["ana@example.com"].note, "wave 1");
      assert.equal(byEmail["bo@example.com"].invited_at, "2026-11-25T12:00:00.000Z");
      assert.equal(byEmail["cy@example.com"].invited_at, null);
      assert.equal(byEmail["cy@example.com"].note, null);
      // Nothing new is stored for an email that isn't on the list.
      assert.equal(s.rows().length, 3);

      // Marked again without a note: a new date, the note stays.
      clock += 86_400_000;
      assert.deepEqual(await (await mark(s, { emails: ["ana@example.com"] })).json(), { marked: 1, unknown: 0 });
      const ana = s.rows().find((r) => r.email === "ana@example.com");
      assert.equal(ana.invited_at, "2026-11-26T12:00:00.000Z");
      assert.equal(ana.note, "wave 1");
      // A null or blank note also leaves it; a new one replaces it.
      await mark(s, { emails: ["ana@example.com"], note: null });
      await mark(s, { emails: ["ana@example.com"], note: "   " });
      assert.equal(s.rows().find((r) => r.email === "ana@example.com").note, "wave 1");
      await mark(s, { emails: ["ana@example.com"], note: "resent" });
      assert.equal(s.rows().find((r) => r.email === "ana@example.com").note, "resent");

      // And the pending export no longer has them.
      const text = await (await fetch(`${s.base}/api/waitlist/export?pending=1`, { headers: { Authorization: `Bearer ${TOKEN}` } })).text();
      assert.deepEqual(text.trim().split("\r\n").slice(1).map((l) => l.split(",")[0]), ["cy@example.com"]);
    } finally {
      await s.stop();
    }
  });

  test("doesn't need an Origin, and one from elsewhere doesn't stop it: the token is the authentication", async () => {
    const s = await start({ adminToken: TOKEN });
    try {
      await s.post({ email: "ana@example.com" });
      const res = await mark(s, { emails: ["ana@example.com"] }, { Origin: "https://evil.example" });
      assert.equal(res.status, 200);
      assert.deepEqual(await res.json(), { marked: 1, unknown: 0 });
    } finally {
      await s.stop();
    }
  });
});

describe("static files and headers", () => {
  let s;
  before(async () => { s = await start(); });
  after(() => s.stop());

  test("serves the page with a CSP that hashes its inline script and style", async () => {
    const res = await fetch(`${s.base}/`);
    assert.equal(res.status, 200);
    const html = await res.text();
    const csp = res.headers.get("content-security-policy");
    assert.ok(csp);
    assert.equal(csp.includes("unsafe-inline"), false);
    const script = html.match(/<script>([\s\S]*?)<\/script>/)[1];
    const style = html.match(/<style>([\s\S]*?)<\/style>/)[1];
    const sha = (s) => `'sha256-${createHash("sha256").update(s).digest("base64")}'`;
    assert.ok(csp.includes(`script-src ${sha(script)}`));
    assert.ok(csp.includes(`style-src ${sha(style)}`));
    assert.deepEqual(inlineHashes(html, "script"), [sha(script)]);
    assert.match(csp, /default-src 'none'/);
    assert.match(csp, /frame-ancestors 'none'/);
    assert.equal(res.headers.get("x-content-type-options"), "nosniff");
    assert.equal(res.headers.get("referrer-policy"), "no-referrer");
    assert.equal(res.headers.get("x-frame-options"), "DENY");
    assert.match(res.headers.get("strict-transport-security"), /max-age=\d+/);
  });

  test("the page has no inline handlers or style attributes the CSP would block", () => {
    const html = readFileSync(join(WEB, "public", "index.html"), "utf8");
    assert.equal(/\son[a-z]+=/i.test(html), false);
    assert.equal(/\sstyle="/i.test(html), false);
    assert.equal((html.match(/<script/g) ?? []).length, 1);
    assert.equal((html.match(/<style/g) ?? []).length, 1);
  });

  test("serves the privacy policy at /privacy and /privacy/ with its own script-free CSP", async () => {
    assert.equal(existsSync(join(WEB, "drafts", "privacy", "index.html")), false);
    const html = readFileSync(join(WEB, "public", "privacy", "index.html"), "utf8");
    assert.equal(/<script/i.test(html), false);
    assert.equal(/\son[a-z]+=/i.test(html), false);
    assert.equal(/\sstyle="/i.test(html), false);
    assert.equal(html.includes("[REVISAR"), false);
    assert.equal((html.match(/<style/g) ?? []).length, 1);
    assert.ok(html.includes('<article id="en" lang="en">'));
    assert.ok(html.includes('<article id="es" lang="es">'));

    const style = html.match(/<style>([\s\S]*?)<\/style>/)[1];
    const sha = `'sha256-${createHash("sha256").update(style).digest("base64")}'`;
    for (const path of ["/privacy", "/privacy/"]) {
      const res = await fetch(`${s.base}${path}`);
      assert.equal(res.status, 200, path);
      assert.equal(res.headers.get("content-type"), "text/html; charset=utf-8");
      const csp = res.headers.get("content-security-policy");
      assert.ok(csp, path);
      assert.notEqual(csp, s.csp, "privacy policy has its own CSP");
      assert.ok(csp.includes("script-src 'none'"), csp);
      assert.ok(csp.includes(`style-src ${sha}`), csp);
      assert.equal(csp.includes("unsafe-inline"), false);
    }
    for (const path of ["/privacy/index.html", "/drafts/privacy/index.html"]) {
      const res = await fetch(`${s.base}${path}`);
      assert.equal(res.status, 404, path);
    }
  });

  test("serves fonts and the OG image with their types", async () => {
    for (const [path, type] of [["/fonts/geist.woff2", "font/woff2"], ["/fonts/departure-mono-400.woff2", "font/woff2"], ["/og.png", "image/png"]]) {
      const res = await fetch(`${s.base}${path}`);
      assert.equal(res.status, 200, path);
      assert.equal(res.headers.get("content-type"), type);
      assert.ok((await res.arrayBuffer()).byteLength > 1000);
    }
  });

  test("anything outside the list is 404", async () => {
    for (const path of ["/server.mjs", "/../server.mjs", "/%2e%2e/server.mjs", "/fonts/", "/fonts/LICENSE-geist.txt", "/data/waitlist.db", "/test/server.test.mjs", "/index.htm"]) {
      const res = await fetch(`${s.base}${path}`);
      assert.equal(res.status, 404, path);
    }
  });

  test("HEAD works, other methods don't, and there's a health check", async () => {
    const head = await fetch(`${s.base}/`, { method: "HEAD" });
    assert.equal(head.status, 200);
    assert.equal((await head.text()).length, 0);
    assert.equal((await fetch(`${s.base}/`, { method: "DELETE" })).status, 405);
    const health = await fetch(`${s.base}/healthz`);
    assert.equal(health.status, 200);
  });
});

describe("the beta invite on the page (ADR 0048 §4)", () => {
  const html = readFileSync(join(WEB, "public", "index.html"), "utf8");
  const script = html.match(/<script>([\s\S]*?)<\/script>/)[1];
  // The Spanish catalog, as the page's own script builds it.
  const ES = new Function(`${script.slice(script.indexOf("const ES = {"), script.indexOf("const META"))}; return ES;`)();
  const keys = [...html.matchAll(/data-i18n(?:-html|-placeholder)?="([^"]+)"/g)].map((m) => m[1]);
  const english = (key) => {
    // The element that carries the key, up to its own closing tag.
    const m = html.match(new RegExp(`<(\\w+)\\b[^>]*\\sdata-i18n(?:-html)?="${key.replace(".", "\\.")}"[^>]*>([\\s\\S]*?)</\\1>`));
    assert.ok(m, key);
    return m[2];
  };

  test("the inline script parses, and every translated element has its Spanish string", () => {
    assert.doesNotThrow(() => new vm.Script(script));
    assert.deepEqual(keys.filter((key) => typeof ES[key] !== "string"), []);
  });

  test("#beta and #waitlist each name exactly one element, so old and new links both land on the form", () => {
    for (const id of ["beta", "waitlist"]) assert.equal(html.match(new RegExp(`\\sid="${id}"`, "g"))?.length, 1, id);
    assert.match(html, /<article class="plan plan-hosted" id="beta">/);
    assert.match(html, /<form class="waitlist" id="waitlist" action="\/api\/waitlist"/);
    // Every in-page link to the request goes to #beta.
    assert.equal(/href=\\?"#waitlist\\?"/.test(html), false);
    assert.ok((html.match(/href=\\?"#beta\\?"/g) ?? []).length >= 4);
  });

  test("the call to action asks for a free beta invite, in both languages", () => {
    assert.equal(english("hero.waitlist"), "Request a free beta invite");
    assert.equal(english("wl.join"), "Request a free beta invite");
    assert.equal(ES["hero.waitlist"], "Pide una invitación a la beta gratuita");
    assert.equal(ES["wl.join"], "Pide una invitación a la beta gratuita");
  });

  test("under the form: free during the beta, 20 USD a year after it with 60 days' notice, set-server, self-hosting free", () => {
    for (const terms of [english("wl.terms"), ES["wl.terms"]]) {
      assert.ok(terms.includes("<code>api.klav.dev</code>"), terms);
      assert.ok(terms.includes("20 USD"), terms);
      assert.ok(terms.includes("60"), terms);
      assert.ok(terms.includes("<code>klav account set-server</code>"), terms);
      assert.equal(/href=/.test(terms), false, "no links in the terms");
    }
    assert.match(english("wl.terms"), /free while the beta is invite-only/);
    assert.match(english("wl.terms"), /stays free, for good/);
    assert.match(ES["wl.terms"], /gratis mientras la beta sea por invitación/);
    assert.match(ES["wl.terms"], /sigue siendo gratis, siempre/);
  });

  test("nothing on the page still says the hosted server is closed or only a paid plan", () => {
    const english = html.replace(/<script>[\s\S]*?<\/script>/, "");
    for (const stale of ["Join the waitlist", "isn’t open yet", "when it opens", "20 USD a year on ours", "A paid plan", "$20"]) {
      assert.equal(english.includes(stale), false, stale);
    }
    for (const stale of ["Unirme a la lista", "todavía no abre", "cuando abra", "20 USD al año en el nuestro", "Un plan de pago"]) {
      assert.equal(Object.values(ES).some((v) => v.includes(stale)), false, stale);
    }
    assert.equal(/when the hosted plan opens|cuando abra el plan alojado/.test(script), false);
  });

  test("the form is still email-only, with its honeypot", () => {
    const form = html.match(/<form class="waitlist"[\s\S]*?<\/form>/)[0];
    const fields = [...form.matchAll(/<input[^>]*\sname="([^"]+)"/g)].map((m) => m[1]);
    assert.deepEqual(fields, ["email", "website"]);
    assert.match(form, /<div class="wl-trap" aria-hidden="true">/);
  });
});

describe("downloads", () => {
  const TF = "https://testflight.apple.com/join/AbCd1234";
  const RELEASE = "https://github.com/OmarAlex24/klav/releases/latest/download/";
  const get = (s, path, method = "GET") => fetch(`${s.base}${path}`, { method, redirect: "manual" });
  const silent = { warn: () => {} };

  test("off by default: every download leads back to the page, the appcast is 404", async () => {
    const s = await start(silent);
    try {
      assert.equal(s.open.size, 0);
      for (const path of ["/download", "/download/", "/download/iphone", ...Object.keys(DOWNLOADS).filter((p) => p.startsWith("/download/"))]) {
        const res = await get(s, path);
        assert.equal(res.status, 302, path);
        assert.equal(res.headers.get("location"), "/#download", path);
        assert.equal(res.headers.get("cache-control"), "no-store", path);
      }
      const feed = await get(s, "/releases/mac/appcast.xml");
      assert.equal(feed.status, 404);
      assert.equal(feed.headers.get("cache-control"), "no-store");
    } finally {
      await s.stop();
    }
  });

  test("switched on, each goes to the latest release's file, by the kit's names", async () => {
    const s = await start({ open: OPENABLE.join(","), testflightUrl: TF, ...silent });
    try {
      const want = {
        "/download/mac": ASSETS.dmg,
        "/releases/mac/appcast.xml": ASSETS.appcast,
        "/download/extension/chromium": ASSETS.chromium,
        "/download/extension/firefox": ASSETS.firefox,
        "/download/linux": ASSETS.linux,
        "/download/checksums": ASSETS.sums,
      };
      assert.deepEqual(Object.keys(want).sort(), Object.keys(DOWNLOADS).sort());
      for (const [path, file] of Object.entries(want)) {
        for (const method of ["GET", "HEAD"]) {
          const res = await get(s, path, method);
          assert.equal(res.status, 302, `${method} ${path}`);
          assert.equal(res.headers.get("location"), RELEASE + file, path);
          assert.equal(res.headers.get("cache-control"), "no-store");
          assert.equal(res.headers.get("x-content-type-options"), "nosniff");
        }
      }
      assert.equal((await get(s, "/download/iphone")).headers.get("location"), TF);

      // Nothing in the request reaches Location: not the query, not a
      // path that looks like another host, not Host or X-Forwarded-Host,
      // not a request without Host.
      const dmg = RELEASE + ASSETS.dmg;
      const requests = [
        "GET /download/mac?x=https://evil.example HTTP/1.1\r\nHost: klav.dev\r\nConnection: close\r\n\r\n",
        "GET //evil.example/download/mac HTTP/1.1\r\nHost: klav.dev\r\nConnection: close\r\n\r\n",
        "GET /download/mac HTTP/1.1\r\nHost: evil.example\r\nX-Forwarded-Host: evil.example\r\nConnection: close\r\n\r\n",
        "GET /download/mac HTTP/1.0\r\n\r\n",
      ];
      for (const request of requests) {
        const answer = await raw(s, request);
        assert.match(answer, /^HTTP\/1\.1 302 /, request);
        assert.deepEqual(answer.match(/^location: .*$/gim), [`Location: ${dmg}`], request);
      }
    } finally {
      await s.stop();
    }
  });

  test("the page has the anchor every closed download leads back to, whatever is open", async () => {
    for (const options of [silent, { open: OPENABLE.join(","), testflightUrl: TF, ...silent }]) {
      const s = await start(options);
      try {
        const location = (await get(s, "/download/mac")).headers.get("location");
        const target = location.startsWith("/#") ? location.slice(2) : "download";
        const html = await (await fetch(`${s.base}/`)).text();
        assert.equal(html.match(new RegExp(`\\sid="${target}"`, "g"))?.length, 1, target);
      } finally {
        await s.stop();
      }
    }
  });

  test("a TestFlight link without the iphone switch stays off", async () => {
    const s = await start({ open: "", testflightUrl: TF, ...silent });
    try {
      assert.equal(s.open.has("iphone"), false);
      const res = await get(s, "/download/iphone");
      assert.equal(res.status, 302);
      assert.equal(res.headers.get("location"), "/#download");
      assert.equal((await fetch(`${s.base}/`)).ok, true);
      assert.equal((await (await fetch(`${s.base}/`)).text()).includes(TF), false);
    } finally {
      await s.stop();
    }
  });

  test("each switch opens only its own downloads", async () => {
    const s = await start({ open: "firefox", ...silent });
    try {
      assert.equal((await get(s, "/download/extension/firefox")).headers.get("location"), RELEASE + ASSETS.firefox);
      assert.equal((await get(s, "/download/checksums")).headers.get("location"), RELEASE + ASSETS.sums);
      for (const path of ["/download/mac", "/download/extension/chromium", "/download/linux", "/download/iphone"]) {
        assert.equal((await get(s, path)).headers.get("location"), "/#download", path);
      }
      assert.equal((await get(s, "/releases/mac/appcast.xml")).status, 404);
    } finally {
      await s.stop();
    }
  });

  test("an unknown download path is the same 404 as any unknown path, whatever the method; a known one answers 405 to other methods", async () => {
    const s = await start({ open: "mac", ...silent });
    // Everything but Date, which changes between two responses.
    const answer = async (path, method) => {
      const res = await get(s, path, method);
      const headers = [...res.headers].filter(([name]) => name !== "date");
      return { status: res.status, headers, body: await res.text() };
    };
    try {
      for (const method of ["GET", "HEAD", "POST", "OPTIONS"]) {
        const nope = await answer("/nope", method);
        assert.equal(nope.status, 404, method);
        assert.equal(nope.headers.some(([name]) => name === "cache-control"), false, method);
        for (const path of ["/download/windows", "/download/mac/", "/download/../server.mjs", "/download/constructor", "/download/__proto__", "/releases/mac/", "/releases/mac/Klav.dmg"]) {
          assert.deepEqual(await answer(path, method), nope, `${method} ${path}`);
        }
      }
      for (const path of ["/download", "/download/mac", "/download/iphone", "/releases/mac/appcast.xml"]) {
        for (const method of ["POST", "OPTIONS", "PUT"]) {
          const res = await get(s, path, method);
          assert.equal(res.status, 405, `${method} ${path}`);
          assert.equal(res.headers.get("allow"), "GET, HEAD");
        }
      }
    } finally {
      await s.stop();
    }
  });

  test("a wrong value never stops the site: unknown names and bad links stay off, with a line in the log", () => {
    const lines = [];
    const warn = (line) => lines.push(line);
    assert.deepEqual([...parseOpen(" MAC, firefox  mac,windows,,", "", warn)].sort(), ["firefox", "mac"]);
    assert.match(lines.join("\n"), /unknown "windows"/);
    for (const url of [undefined, "", "http://testflight.apple.com/join/AbCd1234", "https://testflight.apple.com.evil.example/join/AbCd1234", "https://testflight.apple.com/join/AbCd1234?x=1", "javascript:alert(1)"]) {
      lines.length = 0;
      assert.equal(parseOpen("iphone", url, warn).has("iphone"), false, String(url));
      assert.match(lines[0], /KLAV_WEB_TESTFLIGHT_URL/);
    }
    assert.equal(parseOpen("iphone", TF, warn).has("iphone"), true);
  });

  test("the page keeps only the blocks for what is open", () => {
    const html = "<p>a</p><!--open:mac--><a href=\"/download/mac\">Mac</a><!--/open:mac--><!--closed:mac--><span>Soon</span><!--/closed:mac-->";
    assert.equal(renderPage(html, new Set()), "<p>a</p><span>Soon</span>");
    assert.equal(renderPage(html, new Set(["mac"])), "<p>a</p><a href=\"/download/mac\">Mac</a>");
  });

  test("the page's switch markers are known, paired, not nested, and outside its script and style", () => {
    const html = readFileSync(join(WEB, "public", "index.html"), "utf8");
    const markers = [...html.matchAll(/<!--(\/?)(open|closed):([a-z]+)-->/g)];
    const stack = [];
    for (const [, close, kind, name] of markers) {
      assert.ok(OPENABLE.includes(name), `unknown switch ${name}`);
      if (close) assert.equal(stack.pop(), `${kind}:${name}`);
      else {
        assert.equal(stack.length, 0, `nested ${kind}:${name}`);
        stack.push(`${kind}:${name}`);
      }
    }
    assert.equal(stack.length, 0);
    for (const tag of ["script", "style"]) {
      const inner = html.match(new RegExp(`<${tag}>([\\s\\S]*?)</${tag}>`))[1];
      assert.equal(/<!--\/?(open|closed):/.test(inner), false, tag);
    }
  });

  test("every switch marker names a switch in OPENABLE, in the exact form renderPage reads", () => {
    for (const file of readdirSync(join(WEB, "public")).filter((f) => f.endsWith(".html"))) {
      const html = readFileSync(join(WEB, "public", file), "utf8");
      // Anything that looks like a marker, whatever its case or spacing: a
      // misspelled one would show both of its blocks, whatever is open.
      for (const [marker] of html.matchAll(/<!--\s*\/?\s*(?:open|closed)\s*:[^>]*?-->/gi)) {
        const m = marker.match(/^<!--\/?(open|closed):([a-z]+)-->$/);
        assert.ok(m, `${file}: malformed marker ${marker}`);
        assert.ok(OPENABLE.includes(m[2]), `${file}: ${marker} names no switch in OPENABLE`);
      }
      for (const open of [new Set(), new Set(OPENABLE)]) {
        assert.equal(/<!--\s*\/?\s*(open|closed)\s*:/i.test(renderPage(html, open)), false, `${file}: a marker survives renderPage`);
      }
    }
  });

  test("switched off, the page links only to itself: no GitHub, no docs, no download", async () => {
    // Links outside <script>, plus the ES catalog's inline links, which are escaped (href=\"…\").
    const links = (html) => [
      ...[...html.replace(/<script[\s\S]*?<\/script>/g, "").matchAll(/href="([^"]*)"/g)].map((m) => m[1]),
      ...[...html.matchAll(/href=\\"([^"\\]*)\\"/g)].map((m) => m[1]),
    ];
    const self = (href) => href.startsWith("#") || href === "/privacy" || href === "https://klav.dev/" || href === "fonts/geist.woff2" || href.startsWith("data:image/svg+xml,");
    const closed = await start(silent);
    const opened = await start({ open: OPENABLE.join(","), testflightUrl: TF, ...silent });
    try {
      const off = links(await (await fetch(`${closed.base}/`)).text());
      assert.ok(off.length > 0);
      assert.deepEqual(off.filter((href) => !self(href)), []);
      const on = links(await (await fetch(`${opened.base}/`)).text()).filter((href) => !self(href));
      for (const href of on) {
        assert.ok(
          href.startsWith("/download/") || href === "https://github.com/OmarAlex24/klav" || href.startsWith("https://docs.klav.dev/"),
          href,
        );
      }
      for (const path of ["/download/mac", "/download/linux", "/download/extension/chromium", "/download/extension/firefox", "/download/iphone"]) {
        assert.ok(on.includes(path), path);
      }
    } finally {
      await closed.stop();
      await opened.stop();
    }
  });

  test("the CSP is the same whatever is open", async () => {
    const closed = await start(silent);
    const opened = await start({ open: OPENABLE.join(","), testflightUrl: TF, ...silent });
    try {
      assert.equal(closed.csp, opened.csp);
      const res = await fetch(`${opened.base}/`);
      assert.equal(res.headers.get("content-security-policy"), opened.csp);
      assert.equal(/<!--\/?(open|closed):/.test(await res.text()), false);
    } finally {
      await closed.stop();
      await opened.stop();
    }
  });
});

describe("database", () => {
  test("creates schema 2 and keeps rows across restarts", async () => {
    const path = dbPath();
    const s = await start({ dbPath: path });
    await s.post({ email: "keep@example.com" });
    await s.stop();
    const db = new DatabaseSync(path);
    try {
      assert.equal(db.prepare("PRAGMA user_version").get().user_version, 2);
      assert.deepEqual(db.prepare("PRAGMA table_info(waitlist)").all().map((c) => c.name), ["id", "email", "lang", "created_at", "invited_at", "note"]);
      assert.equal(db.prepare("SELECT count(*) AS c FROM waitlist").get().c, 1);
    } finally {
      db.close();
    }
    const again = await start({ dbPath: path });
    try {
      assert.equal(again.rows()[0].email, "keep@example.com");
    } finally {
      await again.stop();
    }
  });

  test("brings a schema 1 database to 2, keeping its rows and their uniqueness", async () => {
    const path = dbPath();
    const old = new DatabaseSync(path);
    // Schema 1 exactly as the previous server created it.
    old.exec(`
      CREATE TABLE waitlist (
        id INTEGER PRIMARY KEY,
        email TEXT NOT NULL UNIQUE COLLATE NOCASE,
        lang TEXT,
        created_at TEXT NOT NULL
      );
      PRAGMA user_version = 1;
    `);
    old.prepare("INSERT INTO waitlist (email, lang, created_at) VALUES (?, ?, ?)").run("old@example.com", "es", "2026-11-05T00:00:00.000Z");
    old.close();

    const s = await start({ dbPath: path, adminToken: TOKEN });
    try {
      assert.equal(s.db.prepare("PRAGMA user_version").get().user_version, 2);
      assert.deepEqual(s.rows().map((r) => ({ ...r })), [{ id: 1, email: "old@example.com", lang: "es", created_at: "2026-11-05T00:00:00.000Z", invited_at: null, note: null }]);
      await s.post({ email: "OLD@example.com" });
      assert.equal(s.rows().length, 1);
      const text = await (await fetch(`${s.base}/api/waitlist/export?pending=1`, { headers: { Authorization: `Bearer ${TOKEN}` } })).text();
      assert.equal(text, "email,lang,created_at,invited_at,note\r\nold@example.com,es,2026-11-05T00:00:00.000Z,,\r\n");
    } finally {
      await s.stop();
    }
  });

  test("after a rollback by hand (user_version = 1, columns left), comes forward again without losing a mark", () => {
    const path = dbPath();
    let db = openDatabase(path);
    db.prepare("INSERT INTO waitlist (email, lang, created_at, invited_at, note) VALUES (?, ?, ?, ?, ?)").run("x@example.com", "en", "2026-11-05T00:00:00.000Z", "2026-11-25T00:00:00.000Z", "waitlist");
    db.exec("PRAGMA user_version = 1");
    db.close();
    db = openDatabase(path);
    try {
      assert.equal(db.prepare("PRAGMA user_version").get().user_version, 2);
      const row = db.prepare("SELECT invited_at, note FROM waitlist").get();
      assert.equal(row.invited_at, "2026-11-25T00:00:00.000Z");
      assert.equal(row.note, "waitlist");
    } finally {
      db.close();
    }
  });

  test("a fresh database goes from nothing to schema 2 in one open", () => {
    const db = openDatabase(":memory:");
    try {
      assert.equal(db.prepare("PRAGMA user_version").get().user_version, 2);
      assert.deepEqual(db.prepare("PRAGMA table_info(waitlist)").all().map((c) => c.name), ["id", "email", "lang", "created_at", "invited_at", "note"]);
    } finally {
      db.close();
    }
  });

  test("refuses a database from a newer server", () => {
    const path = dbPath();
    const db = new DatabaseSync(path);
    db.exec("PRAGMA user_version = 99");
    db.close();
    assert.throws(() => openDatabase(path), /schema 99/);
  });
});
