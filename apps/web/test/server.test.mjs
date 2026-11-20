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
    assert.deepEqual(cols, ["id", "email", "lang", "created_at"]);
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
      assert.equal(lines[0], "email,lang,created_at");
      assert.match(lines[1], /^ana@example\.com,es,\d{4}-/);
      assert.match(lines[2], /^bo@example\.com,en,/);
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
  test("creates schema 1 and keeps rows across restarts", async () => {
    const path = dbPath();
    const s = await start({ dbPath: path });
    await s.post({ email: "keep@example.com" });
    await s.stop();
    const db = new DatabaseSync(path);
    try {
      assert.equal(db.prepare("PRAGMA user_version").get().user_version, 1);
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

  test("refuses a database from a newer server", () => {
    const path = dbPath();
    const db = new DatabaseSync(path);
    db.exec("PRAGMA user_version = 99");
    db.close();
    assert.throws(() => openDatabase(path), /schema 99/);
  });
});
