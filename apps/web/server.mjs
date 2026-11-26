// klav.dev: the site and its waitlist (docs/sitio-web.md).
//
// Zero dependencies: node:http and node:sqlite (Node >= 22.13). It serves a
// fixed list of files from public/, takes emails on POST /api/waitlist and
// hands them back as CSV on GET /api/waitlist/export to whoever holds
// KLAV_WEB_ADMIN_TOKEN, who also marks the ones already sent a beta invite
// with POST /api/waitlist/mark-invited (ADR 0048 §4). It never stores IP
// addresses.
//
// Auto-issued beta invites (ADR 0050): with KLAV_BETA_AUTO_CAP above 0 and
// every variable it needs, a new signup is sent a bound, single-use invite
// right away, while seats last: klav-server issues it on its internal route
// and the site emails it through Cloudflare Email Sending. An optional
// Cloudflare Turnstile check guards the form. Without them, the waitlist
// works as before.
//
// Downloads (docs/releasing.md): /download/... and /releases/mac/appcast.xml
// redirect to the latest GitHub Release, but only for what KLAV_WEB_OPEN
// switches on. Until then they lead back to the page's honest state, and
// the page leaves out what isn't open (`<!--open:NAME-->` blocks).

import { createHash, timingSafeEqual } from "node:crypto";
import { mkdirSync, readFileSync } from "node:fs";
import { createServer } from "node:http";
import { dirname, join, resolve } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));

/** The only files the site serves: URL path → [file in public/, type, cache]. */
const STATIC = {
  "/": ["index.html", "text/html; charset=utf-8", "no-cache"],
  "/privacy": ["privacy/index.html", "text/html; charset=utf-8", "no-cache"],
  "/og.png": ["og.png", "image/png", "public, max-age=86400"],
  "/fonts/geist.woff2": ["fonts/geist.woff2", "font/woff2", "public, max-age=604800"],
  "/fonts/geist-mono-400.woff2": ["fonts/geist-mono-400.woff2", "font/woff2", "public, max-age=604800"],
  "/fonts/departure-mono-400.woff2": ["fonts/departure-mono-400.woff2", "font/woff2", "public, max-age=604800"],
};

/**
 * What KLAV_WEB_OPEN can switch on, each on its own day: `repo` (links to
 * the repository, once it is public), `docs` (links to the docs site at
 * docs.klav.dev, once it is served there), `mac` (the DMG and the appcast),
 * `chromium` (the extension zip), `firefox` (the signed .xpi), `linux` (the CLI tarball)
 * and `iphone` (the TestFlight public link, KLAV_WEB_TESTFLIGHT_URL).
 */
export const OPENABLE = ["repo", "docs", "mac", "chromium", "firefox", "linux", "iphone"];
/** Where the release files live; the names are scripts/release/kit.mjs's ASSETS. */
const RELEASES = "https://github.com/OmarAlex24/klav/releases/latest/download";
/** URL path → [switch, file in the latest release]. */
export const DOWNLOADS = {
  "/download/mac": ["mac", "Klav.dmg"],
  "/releases/mac/appcast.xml": ["mac", "appcast.xml"],
  "/download/extension/chromium": ["chromium", "klav-extension-chromium.zip"],
  "/download/extension/firefox": ["firefox", "klav-extension-firefox.xpi"],
  "/download/linux": ["linux", "klav-linux-x86_64.tar.gz"],
  "/download/checksums": [["mac", "chromium", "firefox", "linux"], "SHA256SUMS"],
};
/** TestFlight's public links: https://testflight.apple.com/join/<code>. */
const TESTFLIGHT = /^https:\/\/testflight\.apple\.com\/join\/[A-Za-z0-9]{4,32}$/;

/**
 * The set of open things from KLAV_WEB_OPEN ("mac,firefox"). Anything it
 * doesn't know is left off and named in the log: a typo on Railway must
 * never stop the site from starting. `iphone` needs a TestFlight link.
 */
export function parseOpen(value, testflightUrl, warn = console.warn) {
  const open = new Set();
  for (const raw of String(value ?? "").split(/[\s,]+/).filter(Boolean)) {
    const name = raw.toLowerCase();
    if (OPENABLE.includes(name)) open.add(name);
    else warn(`KLAV_WEB_OPEN: unknown "${raw}" left off (known: ${OPENABLE.join(", ")})`);
  }
  if (open.has("iphone") && !TESTFLIGHT.test(String(testflightUrl ?? ""))) {
    open.delete("iphone");
    warn("KLAV_WEB_OPEN: iphone left off: KLAV_WEB_TESTFLIGHT_URL is not a https://testflight.apple.com/join/… link");
  }
  return open;
}

/**
 * The page for this set: `<!--open:NAME-->…<!--/open:NAME-->` stays only if
 * NAME is open, `<!--closed:NAME-->…<!--/closed:NAME-->` only if it isn't.
 * The markers go; nothing inside <script> or <style> may carry them, so the
 * CSP hashes don't depend on the switch.
 */
export function renderPage(html, open) {
  return html.replace(/<!--(open|closed):([a-z]+)-->([\s\S]*?)<!--\/\1:\2-->/g, (_, kind, name, inner) =>
    (kind === "open") === open.has(name) ? inner : "",
  );
}

const SCHEMA_VERSION = 2;
const MAX_BODY = 2048;
/** mark-invited: up to 200 emails and a note, so a larger body than a signup. */
const MAX_ADMIN_BODY = 16 * 1024;
const MAX_MARK = 200;
const MAX_NOTE = 200;
const MAX_EMAIL = 254;
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const LANGS = new Set(["en", "es"]);

/** Every outbound call (Turnstile, klav-server, Cloudflare) gives up after this. */
const OUTBOUND_TIMEOUT_MS = 10_000;
/** The note on waitlist rows sent an invite automatically; also klav-server's. */
export const AUTO_NOTE = "auto-beta";
/** Turnstile site keys: "0x4AAAA…", or Cloudflare's test keys "1x0000…". */
const TURNSTILE_SITE_KEY = /^[0-9]x[A-Za-z0-9_-]{10,100}$/;
const TURNSTILE_ORIGIN = "https://challenges.cloudflare.com";
const TURNSTILE_VERIFY = `${TURNSTILE_ORIGIN}/turnstile/v0/siteverify`;
const CF_API = "https://api.cloudflare.com/client/v4";
/** klav-server refuses a shorter token (MIN_AUTO_INVITE_TOKEN_BYTES). */
const MIN_INVITE_TOKEN = 32;
/** A Cloudflare account ID: 32 hex characters. */
const CF_ACCOUNT = /^[0-9a-f]{32}$/i;
/** "invites@klav.dev" or "Klav <invites@klav.dev>". */
const FROM = /^(?:([^<>\r\n]{1,64}?)\s*<([^\s@<>]+@[^\s@<>]+\.[^\s@<>]+)>|([^\s@<>]+@[^\s@<>]+\.[^\s@<>]+))$/;

/** An http(s) base URL without a trailing slash, or null. */
function baseUrl(value) {
  try {
    const url = new URL(String(value));
    if (url.protocol !== "https:" && url.protocol !== "http:") return null;
    if (url.search || url.hash || url.username || url.password) return null;
    return url.href.replace(/\/+$/, "");
  } catch {
    return null;
  }
}

/**
 * Turnstile from the environment: on only with a well-formed site key and
 * a secret. One without the other, or a malformed key, stays off with a
 * line in the log naming the variable (never its value): a typo on Railway
 * must never stop the site.
 */
export function turnstileFromEnv(env = {}, warn = console.warn) {
  const siteKey = String(env.KLAV_TURNSTILE_SITE_KEY ?? "").trim();
  const secret = String(env.KLAV_TURNSTILE_SECRET ?? "").trim();
  if (!siteKey && !secret) return null;
  if (!siteKey || !secret) {
    warn(`Turnstile off: ${siteKey ? "KLAV_TURNSTILE_SECRET" : "KLAV_TURNSTILE_SITE_KEY"} is not set`);
    return null;
  }
  if (!TURNSTILE_SITE_KEY.test(siteKey)) {
    warn("Turnstile off: KLAV_TURNSTILE_SITE_KEY doesn't look like a Turnstile site key");
    return null;
  }
  const verifyUrl = env.KLAV_TURNSTILE_VERIFY_URL ? baseUrl(env.KLAV_TURNSTILE_VERIFY_URL) : TURNSTILE_VERIFY;
  if (!verifyUrl) {
    warn("Turnstile off: KLAV_TURNSTILE_VERIFY_URL is not an http(s) URL");
    return null;
  }
  return { siteKey, secret, verifyUrl };
}

/**
 * Auto-issued invites from the environment (ADR 0050): on only with
 * KLAV_BETA_AUTO_CAP above 0 and every other variable well formed.
 * Anything missing or malformed leaves the site waitlist-only, with a line
 * naming the variables (never their values).
 */
export function autoInviteFromEnv(env = {}, warn = console.warn) {
  const rawCap = String(env.KLAV_BETA_AUTO_CAP ?? "").trim();
  if (rawCap === "" || rawCap === "0") return null;
  if (!/^[0-9]{1,9}$/.test(rawCap)) {
    warn("auto invites off: KLAV_BETA_AUTO_CAP is not a whole number");
    return null;
  }
  const cap = Number(rawCap);
  const bad = [];
  const serverUrl = baseUrl(env.KLAV_AUTO_INVITE_URL ?? "");
  if (!serverUrl) bad.push("KLAV_AUTO_INVITE_URL");
  const serverToken = String(env.KLAV_AUTO_INVITE_TOKEN ?? "");
  if (serverToken.length < MIN_INVITE_TOKEN) bad.push("KLAV_AUTO_INVITE_TOKEN");
  const accountId = String(env.KLAV_CF_ACCOUNT_ID ?? "").trim();
  if (!CF_ACCOUNT.test(accountId)) bad.push("KLAV_CF_ACCOUNT_ID");
  const emailToken = String(env.KLAV_CF_EMAIL_TOKEN ?? "").trim();
  if (!emailToken) bad.push("KLAV_CF_EMAIL_TOKEN");
  const from = String(env.KLAV_CF_EMAIL_FROM ?? "").trim().match(FROM);
  if (!from) bad.push("KLAV_CF_EMAIL_FROM");
  const emailApi = env.KLAV_CF_EMAIL_API_BASE ? baseUrl(env.KLAV_CF_EMAIL_API_BASE) : CF_API;
  if (!emailApi) bad.push("KLAV_CF_EMAIL_API_BASE");
  if (bad.length) {
    warn(`auto invites off: ${bad.join(", ")} missing or malformed`);
    return null;
  }
  // The REST API takes a named sender as { address, name }.
  const sender = from[3] ? from[3] : { address: from[2], name: from[1].trim() };
  return { cap, serverUrl, serverToken, accountId, emailToken, from: sender, emailApi };
}

const MONTHS = {
  en: ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"],
  es: ["enero", "febrero", "marzo", "abril", "mayo", "junio", "julio", "agosto", "septiembre", "octubre", "noviembre", "diciembre"],
};

/** The invite email, in the language of the page: { subject, text }. */
export function inviteEmail(lang, email, code, expiresAt) {
  const d = new Date(expiresAt);
  const [y, m, day] = [d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()];
  if (lang === "es") {
    return {
      subject: "Tu invitación a la beta de Klav",
      text: `Hola:

Aquí tienes tu código para crear una cuenta en la beta de Klav, en nuestro servidor (api.klav.dev):

    ${code}

Sirve una sola vez y solo con este correo (${email}). Vence el ${day} de ${MONTHS.es[m]} de ${y} (UTC), 14 días después de este mensaje.

Cómo crear tu cuenta:
1. Descarga Klav para Mac: https://klav.dev/download/mac
2. Crea tu cuenta: en la app de Mac, «Configurar este Mac» → «Crear una cuenta»; en Linux, con la línea de comandos, klav signup. Usa este correo y pega el código cuando Klav te lo pida.
3. La documentación, también para conectar a tus agentes: https://docs.klav.dev

La beta es gratis. Cuando termine, nuestro servidor pasa a ser un plan de 20 USD al año, y te avisamos por lo menos 60 días antes de cobrarte nada. Montar tu propio servidor sigue siendo gratis, siempre.

Te llega porque pediste una invitación en klav.dev. Si no fuiste tú, ignora este correo: nadie puede usar el código con otra dirección. ¿Dudas? Escríbenos a support@klav.dev.

Klav
`,
    };
  }
  return {
    subject: "Your Klav beta invite",
    text: `Hi,

Here's your code to create an account in the Klav beta, on our server (api.klav.dev):

    ${code}

It works once, and only with this email address (${email}). It expires on ${MONTHS.en[m]} ${day}, ${y} (UTC), 14 days from this message.

To sign up:
1. Download Klav for Mac: https://klav.dev/download/mac
2. Create your account: in the Mac app, "Set up this Mac" → "Create an account"; on Linux, with the command line, klav signup. Use this email address, and paste the code when Klav asks for it.
3. The docs, including how to connect your agents: https://docs.klav.dev

The beta is free. When it ends, our server becomes a plan of 20 USD a year, and we'll tell you at least 60 days before you'd pay anything. Running your own server stays free, for good.

You're getting this because you asked for an invite at klav.dev. If that wasn't you, ignore this email: nobody can use the code with another address. Questions? Write to support@klav.dev.

Klav
`,
  };
}

/** The Turnstile widget and its script, for the form; empty without Turnstile. */
export function turnstileMarkup(turnstile) {
  if (!turnstile) return "";
  return `<div class="cf-turnstile wl-turnstile" id="wl-turnstile" data-sitekey="${turnstile.siteKey}" data-size="flexible" data-response-field-name="cf-turnstile-response"></div>
          <script src="${TURNSTILE_ORIGIN}/turnstile/v0/api.js" async defer></script>`;
}
/** sha256 CSP sources for every inline <script> and <style> in `html`. */
export function inlineHashes(html, tag) {
  const re = new RegExp(`<${tag}>([\\s\\S]*?)</${tag}>`, "g");
  return [...html.matchAll(re)].map((m) => `'sha256-${createHash("sha256").update(m[1], "utf8").digest("base64")}'`);
}

/**
 * The page's CSP. With `turnstile`, Turnstile's script and its iframe from
 * challenges.cloudflare.com, and nothing else, are added (Cloudflare's CSP
 * reference); without it the policy is exactly as before.
 */
function contentSecurityPolicy(html, turnstile = false) {
  const scripts = inlineHashes(html, "script");
  if (turnstile) scripts.push(TURNSTILE_ORIGIN);
  const styles = inlineHashes(html, "style");
  return [
    "default-src 'none'",
    `script-src ${scripts.length ? scripts.join(" ") : "'none'"}`,
    `style-src ${styles.length ? styles.join(" ") : "'none'"}`,
    "img-src 'self' data:",
    "font-src 'self'",
    "connect-src 'self'",
    ...(turnstile ? [`frame-src ${TURNSTILE_ORIGIN}`] : []),
    "base-uri 'none'",
    "form-action 'self'",
    "frame-ancestors 'none'",
  ].join("; ");
}

const BASE_HEADERS = {
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
  "X-Frame-Options": "DENY",
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Resource-Policy": "same-origin",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=(), interest-cohort=()",
  "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
};

/** Opens (or creates) the waitlist database and brings its schema up to date. */
export function openDatabase(path) {
  if (path !== ":memory:") mkdirSync(dirname(resolve(path)), { recursive: true });
  const db = new DatabaseSync(path);
  db.exec("PRAGMA journal_mode = WAL; PRAGMA busy_timeout = 5000;");
  const { user_version: version } = db.prepare("PRAGMA user_version").get();
  if (version > SCHEMA_VERSION) {
    db.close();
    throw new Error(`waitlist database is at schema ${version}, newer than this server (${SCHEMA_VERSION})`);
  }
  if (version < 1) {
    db.exec(`
      BEGIN;
      CREATE TABLE IF NOT EXISTS waitlist (
        id INTEGER PRIMARY KEY,
        email TEXT NOT NULL UNIQUE COLLATE NOCASE,
        lang TEXT,
        created_at TEXT NOT NULL
      );
      PRAGMA user_version = 1;
      COMMIT;
    `);
  }
  if (version < 2) {
    // Schema 2 (ADR 0048 §4): when the beta invite went out, and a note
    // for Omar. Each column is added only if it's missing: rolling back is
    // setting user_version = 1 by hand and leaving the columns, so coming
    // forward again must not trip over them (docs/sitio-web.md §2).
    const has = new Set(db.prepare("PRAGMA table_info(waitlist)").all().map((c) => c.name));
    db.exec("BEGIN");
    try {
      if (!has.has("invited_at")) db.exec("ALTER TABLE waitlist ADD COLUMN invited_at TEXT");
      if (!has.has("note")) db.exec("ALTER TABLE waitlist ADD COLUMN note TEXT");
      db.exec("PRAGMA user_version = 2; COMMIT");
    } catch (err) {
      db.exec("ROLLBACK");
      db.close();
      throw err;
    }
  }
  return db;
}

/** A sliding count of attempts per key, kept only in memory. */
function rateLimiter({ max, windowMs, now }) {
  const hits = new Map();
  return {
    /** Seconds to wait, or 0 if `key` may go ahead (and counts it). */
    take(key) {
      const t = now();
      const recent = (hits.get(key) ?? []).filter((at) => t - at < windowMs);
      if (recent.length >= max) {
        hits.set(key, recent);
        return Math.max(1, Math.ceil((windowMs - (t - recent[0])) / 1000));
      }
      recent.push(t);
      hits.set(key, recent);
      return 0;
    },
    sweep() {
      const t = now();
      for (const [key, list] of hits) if (list.every((at) => t - at >= windowMs)) hits.delete(key);
    },
  };
}

/** A CSV cell; a leading = + - @ is defused so a spreadsheet can't run it. */
function csvCell(value) {
  let s = value == null ? "" : String(value);
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

function sameToken(given, expected) {
  const a = createHash("sha256").update(given).digest();
  const b = createHash("sha256").update(expected).digest();
  return timingSafeEqual(a, b);
}

/**
 * The site as an `http.Server` (not listening yet). Options:
 * `dbPath`, `adminToken` (export is 404 without one), `publicDir`,
 * `trustProxy` (read the client from X-Real-IP, as behind Railway),
 * `open` (KLAV_WEB_OPEN's value), `testflightUrl`,
 * `env` (the Turnstile and auto-invite variables, ADR 0050),
 * `rateLimit` ({ max, windowMs }), `issueRateLimit` ({ max, windowMs }:
 * automatic invites per client) and `now` (for tests).
 */
export function createSite(options = {}) {
  const publicDir = options.publicDir ?? join(HERE, "public");
  const adminToken = options.adminToken || "";
  const now = options.now ?? Date.now;
  const db = openDatabase(options.dbPath ?? join(HERE, "data", "waitlist.db"));
  const insert = db.prepare("INSERT OR IGNORE INTO waitlist (email, lang, created_at) VALUES (?, ?, ?)");
  const all = db.prepare("SELECT email, lang, created_at, invited_at, note FROM waitlist ORDER BY id");
  const pending = db.prepare("SELECT email, lang, created_at, invited_at, note FROM waitlist WHERE invited_at IS NULL ORDER BY id");
  // A note left out keeps the one already there; a mark again moves the date.
  const markOne = db.prepare("UPDATE waitlist SET invited_at = ?, note = coalesce(?, note) WHERE email = ?");
  const limiter = rateLimiter({ max: options.rateLimit?.max ?? 5, windowMs: options.rateLimit?.windowMs ?? 10 * 60_000, now });
  // Invites sent automatically from one client: past this, its signups
  // still land on the list, but wait there (ADR 0050 §3.2).
  const issueLimiter = rateLimiter({ max: options.issueRateLimit?.max ?? 2, windowMs: options.issueRateLimit?.windowMs ?? 60 * 60_000, now });
  const sweep = setInterval(() => {
    limiter.sweep();
    issueLimiter.sweep();
  }, 60_000);
  sweep.unref();

  const warn = options.warn ?? console.warn;
  const turnstile = turnstileFromEnv(options.env, warn);
  const auto = autoInviteFromEnv(options.env, warn);
  const row = db.prepare("SELECT invited_at, lang FROM waitlist WHERE email = ?");
  const autoSent = db.prepare("SELECT count(*) AS n FROM waitlist WHERE note = ? AND invited_at IS NOT NULL");
  const markAuto = db.prepare("UPDATE waitlist SET invited_at = ?, note = ? WHERE email = ? AND invited_at IS NULL");

  const open = parseOpen(options.open, options.testflightUrl, options.warn);
  const testflightUrl = open.has("iphone") ? options.testflightUrl : "";

  const files = {};
  for (const [route, [file, type, cache]] of Object.entries(STATIC)) {
    try {
      files[route] = { body: readFileSync(join(publicDir, file)), type, cache };
    } catch (err) {
      if (route === "/") throw err; // the page itself must exist
    }
  }
  // The Turnstile widget goes where the page has <!--turnstile-->, outside
  // its inline script and style, so their hashes never move.
  const page = renderPage(files["/"].body.toString("utf8"), open).replace("<!--turnstile-->", turnstileMarkup(turnstile));
  files["/"].body = Buffer.from(page);
  for (const [route, entry] of Object.entries(files)) {
    if (entry.type.startsWith("text/html")) {
      entry.csp = contentSecurityPolicy(entry.body.toString("utf8"), route === "/" && Boolean(turnstile));
    }
  }
  const csp = files["/"].csp;

  function send(res, status, body, headers = {}) {
    const buf = typeof body === "string" ? Buffer.from(body) : body;
    res.writeHead(status, { ...BASE_HEADERS, "Content-Length": buf.length, ...headers });
    res.end(res.req.method === "HEAD" ? undefined : buf);
  }
  const json = (res, status, value, headers = {}) =>
    send(res, status, JSON.stringify(value), { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", ...headers });
  const text = (res, status, body, headers = {}) => send(res, status, body, { "Content-Type": "text/plain; charset=utf-8", ...headers });

  // Behind Railway the socket is the proxy's. Railway documents that it
  // sets X-Real-IP (not how it treats X-Forwarded-For; docs/self-hosting.md
  // §8), so that's the only header read, and only with trustProxy.
  function clientKey(req) {
    if (options.trustProxy) {
      const real = String(req.headers["x-real-ip"] ?? "").trim();
      if (real) return real;
    }
    return req.socket.remoteAddress ?? "unknown";
  }

  function crossOrigin(req) {
    const origin = req.headers.origin;
    if (!origin) return false;
    try {
      return new URL(origin).host !== req.headers.host;
    } catch {
      return true;
    }
  }

  function readBody(req, max = MAX_BODY) {
    return new Promise((done, fail) => {
      const declared = Number(req.headers["content-length"] ?? 0);
      if (declared > max) return fail(Object.assign(new Error("too large"), { status: 413 }));
      const chunks = [];
      let size = 0;
      req.on("data", (chunk) => {
        size += chunk.length;
        if (size > max) {
          req.removeAllListeners("data");
          req.resume();
          fail(Object.assign(new Error("too large"), { status: 413 }));
        } else chunks.push(chunk);
      });
      req.on("end", () => done(Buffer.concat(chunks).toString("utf8")));
      req.on("error", fail);
    });
  }

  /** A POST with a timeout; resolves to the Response, or throws. */
  function post(url, headers, body) {
    return fetch(url, { method: "POST", headers, body, redirect: "error", signal: AbortSignal.timeout(OUTBOUND_TIMEOUT_MS) });
  }

  /**
   * Turnstile's verdict on `token`: "ok", "failed", or "unavailable" (the
   * verifier didn't answer properly: the form fails closed). The client's
   * IP is not sent: it's optional, and the site keeps no IPs.
   */
  async function verifyTurnstile(token) {
    try {
      const res = await post(turnstile.verifyUrl, { "Content-Type": "application/x-www-form-urlencoded" }, new URLSearchParams({ secret: turnstile.secret, response: token }).toString());
      if (!res.ok) {
        console.warn(`turnstile: siteverify answered ${res.status}`);
        return "unavailable";
      }
      const verdict = await res.json();
      return verdict && verdict.success === true ? "ok" : "failed";
    } catch (err) {
      console.warn(`turnstile: siteverify failed (${err instanceof Error ? err.name : "error"})`);
      return "unavailable";
    }
  }

  /**
   * Sends `email` an invite if seats are left (ADR 0050 §3): the status for
   * the page. Never logs the code or a token; failures log a reason only.
   */
  async function autoInvite(email, lang, key) {
    if (row.get(email)?.invited_at) return "already_invited";
    if (autoSent.get(AUTO_NOTE).n >= auto.cap) return "waitlisted";
    if (issueLimiter.take(key)) return "waitlisted";
    const auth = { "Content-Type": "application/json", Authorization: `Bearer ${auto.serverToken}` };
    let issued;
    try {
      const res = await post(`${auto.serverUrl}/v1/internal/invites/auto`, auth, JSON.stringify({ email }));
      if (res.status === 409) {
        const reason = (await res.json().catch(() => ({})))?.error;
        if (reason === "already_invited") return "already_invited";
        if (reason !== "cap_reached") console.warn(`auto invite: klav-server answered 409 ${String(reason).slice(0, 40)}`);
        return "waitlisted";
      }
      if (res.status !== 201) {
        console.warn(`auto invite: klav-server answered ${res.status}`);
        return "waitlisted";
      }
      issued = await res.json();
    } catch (err) {
      console.warn(`auto invite: klav-server unreachable (${err instanceof Error ? err.name : "error"})`);
      return "waitlisted";
    }
    const { id, code, expires_at: expiresAt } = issued ?? {};
    if (typeof id !== "string" || !/^[0-9a-f-]{36}$/.test(id) || typeof code !== "string" || !/^KLAV-[0-9A-Z-]{26,40}$/.test(code) || !Number.isSafeInteger(expiresAt)) {
      console.warn("auto invite: klav-server's answer is malformed");
      if (typeof id === "string" && /^[0-9a-f-]{36}$/.test(id)) await revokeInvite(id, auth);
      return "waitlisted";
    }
    const failure = await sendInvite(email, lang, code, expiresAt);
    if (failure) {
      console.warn(`auto invite: email not sent (${failure}); revoking ${id}`);
      await revokeInvite(id, auth);
      return "waitlisted";
    }
    markAuto.run(new Date(now()).toISOString(), AUTO_NOTE, email);
    console.log(`auto invite: sent ${id}`);
    return "invited";
  }

  /** null if Cloudflare took the email for `email`; otherwise a reason to log. */
  async function sendInvite(email, lang, code, expiresAt) {
    const { subject, text: body } = inviteEmail(lang, email, code, expiresAt);
    try {
      const res = await post(
        `${auto.emailApi}/accounts/${auto.accountId}/email/sending/send`,
        { "Content-Type": "application/json", Authorization: `Bearer ${auto.emailToken}` },
        JSON.stringify({ from: auto.from, to: [email], subject, text: body }),
      );
      const answer = await res.json().catch(() => null);
      if (!res.ok) return `Cloudflare answered ${res.status}${Array.isArray(answer?.errors) && answer.errors[0]?.code ? ` code ${Number(answer.errors[0].code)}` : ""}`;
      if (!answer || answer.success === false) return "Cloudflare answered success: false";
      const result = answer.result ?? {};
      const listed = (name) => Array.isArray(result[name]) && result[name].some((a) => String(a).toLowerCase() === email);
      if (listed("permanent_bounces")) return "permanent bounce";
      if (listed("suppressed_recipients")) return "suppressed recipient";
      return null;
    } catch (err) {
      return `Cloudflare unreachable (${err instanceof Error ? err.name : "error"})`;
    }
  }

  /** Best effort: gives the seat back when the email didn't go out. */
  async function revokeInvite(id, auth) {
    try {
      const res = await post(`${auto.serverUrl}/v1/internal/invites/auto/${id}/revoke`, auth, "");
      if (res.status !== 204) console.warn(`auto invite: revoke of ${id} answered ${res.status}`);
    } catch (err) {
      console.warn(`auto invite: revoke of ${id} failed (${err instanceof Error ? err.name : "error"})`);
    }
  }

  async function signUp(req, res) {
    if (crossOrigin(req)) return json(res, 403, { error: "cross_origin" });
    const type = String(req.headers["content-type"] ?? "").split(";")[0].trim().toLowerCase();
    if (type !== "application/json") return json(res, 415, { error: "json_only" });
    const wait = limiter.take(clientKey(req));
    if (wait) return json(res, 429, { error: "rate_limited" }, { "Retry-After": String(wait) });
    let body;
    try {
      body = JSON.parse(await readBody(req));
    } catch (err) {
      if (err.status === 413) return json(res, 413, { error: "too_large" }, { Connection: "close" });
      return json(res, 400, { error: "bad_json" });
    }
    if (!body || typeof body !== "object") return json(res, 400, { error: "bad_json" });
    // Turnstile first, when it's on, so the honeypot's answer below is the
    // same as a real signup's. Tokens are single-use; the page resets the
    // widget after every try.
    if (turnstile) {
      const token = typeof body.turnstile_token === "string" ? body.turnstile_token : "";
      if (!token || token.length > 2048) return json(res, 400, { error: "turnstile_required" });
      const verdict = await verifyTurnstile(token);
      if (verdict === "failed") return json(res, 403, { error: "turnstile_failed" });
      if (verdict !== "ok") return json(res, 503, { error: "turnstile_unavailable" });
    }
    // What a new address on the list hears: with auto invites on, it says
    // so; without them, the answer is the same as before ADR 0050.
    const waitlisted = auto ? { ok: true, status: "waitlisted" } : { ok: true };
    // The honeypot: people never see it, so anything in it is a bot. Same
    // answer as a real signup that waits on the list, nothing stored.
    if (typeof body.website === "string" && body.website.trim() !== "") return json(res, 200, waitlisted);
    const email = typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
    if (email.length > MAX_EMAIL || !EMAIL.test(email)) return json(res, 400, { error: "invalid_email" });
    const lang = LANGS.has(body.lang) ? body.lang : null;
    // INSERT OR IGNORE: without auto invites, a repeat gets the same 200, so
    // the form can't tell anyone whether an address is already on the list.
    // With them, "already_invited" does tell (ADR 0050 §4, residual risk).
    insert.run(email, lang, new Date(now()).toISOString());
    if (!auto) return json(res, 200, waitlisted);
    const status = await autoInvite(email, lang ?? row.get(email)?.lang ?? "en", clientKey(req));
    return json(res, 200, status === "waitlisted" ? waitlisted : { ok: true, status });
  }

  /** The admin routes: 404 without a token configured, 401 with a wrong one. True if it answered. */
  function refuseAdmin(req, res) {
    if (!adminToken) {
      text(res, 404, "Not found\n");
      return true;
    }
    const auth = String(req.headers.authorization ?? "");
    const given = auth.startsWith("Bearer ") ? auth.slice(7) : "";
    if (!given || !sameToken(given, adminToken)) {
      json(res, 401, { error: "unauthorized" }, { "WWW-Authenticate": "Bearer" });
      return true;
    }
    return false;
  }

  /** The list as CSV; `?pending=1` keeps only who hasn't been sent an invite. */
  function exportList(req, res, query) {
    if (refuseAdmin(req, res)) return;
    const rows = (query.get("pending") === "1" ? pending : all).all();
    const lines = [
      "email,lang,created_at,invited_at,note",
      ...rows.map((r) => [r.email, r.lang, r.created_at, r.invited_at, r.note].map(csvCell).join(",")),
    ];
    return send(res, 200, `${lines.join("\r\n")}\r\n`, {
      "Content-Type": "text/csv; charset=utf-8",
      "Content-Disposition": 'attachment; filename="klav-waitlist.csv"',
      "Cache-Control": "no-store",
    });
  }

  /**
   * `{ "emails": [...], "note"?: "..." }` → `{ "marked", "unknown" }`. Called
   * with curl after sending invites by hand (docs/sitio-web.md §3), so it
   * doesn't look at Origin: the token is the only authentication. Emails
   * are compared as signup stores them (trimmed, lowercased) and counted
   * once each; an email already marked is marked again with today's date.
   */
  async function markInvited(req, res) {
    if (refuseAdmin(req, res)) return;
    const type = String(req.headers["content-type"] ?? "").split(";")[0].trim().toLowerCase();
    if (type !== "application/json") return json(res, 415, { error: "json_only" });
    let body;
    try {
      body = JSON.parse(await readBody(req, MAX_ADMIN_BODY));
    } catch (err) {
      if (err.status === 413) return json(res, 413, { error: "too_large" }, { Connection: "close" });
      return json(res, 400, { error: "bad_json" });
    }
    if (!body || typeof body !== "object" || Array.isArray(body)) return json(res, 400, { error: "bad_json" });
    const { emails, note } = body;
    if (!Array.isArray(emails) || emails.length === 0) return json(res, 400, { error: "emails_required" });
    if (emails.length > MAX_MARK) return json(res, 400, { error: "too_many_emails", max: MAX_MARK });
    const wanted = new Set();
    for (const raw of emails) {
      const email = typeof raw === "string" ? raw.trim().toLowerCase() : "";
      if (email.length > MAX_EMAIL || !EMAIL.test(email)) return json(res, 400, { error: "invalid_email" });
      wanted.add(email);
    }
    if (note !== undefined && note !== null && (typeof note !== "string" || note.length > MAX_NOTE)) {
      return json(res, 400, { error: "invalid_note", max: MAX_NOTE });
    }
    const keep = typeof note === "string" && note.trim() !== "" ? note.trim() : null;
    const at = new Date(now()).toISOString();
    let marked = 0;
    db.exec("BEGIN IMMEDIATE");
    try {
      for (const email of wanted) marked += Number(markOne.run(at, keep, email).changes);
      db.exec("COMMIT");
    } catch (err) {
      db.exec("ROLLBACK");
      throw err;
    }
    return json(res, 200, { marked, unknown: wanted.size - marked });
  }

  /**
   * A download: to the latest release when it is open; otherwise back to
   * the page's download section, where it says what isn't out yet. The
   * appcast is for Sparkle, not people: 404 until the Mac app is out, with
   * `no-store` so no cache keeps that 404 past the day `mac` goes on (a 404
   * is cacheable by default). A path that isn't a download is the same 404
   * as any other unknown path, whatever the method; only a known route
   * checks the method.
   */
  function download(req, res, path) {
    const index = path === "/download" || path === "/download/";
    const known = index || path === "/download/iphone" || Object.hasOwn(DOWNLOADS, path);
    if (!known) return text(res, 404, "Not found\n");
    if (req.method !== "GET" && req.method !== "HEAD") return text(res, 405, "Method not allowed\n", { Allow: "GET, HEAD" });
    const noStore = { "Cache-Control": "no-store" };
    if (index) return send(res, 302, "", { ...noStore, Location: "/#download" });
    if (path === "/download/iphone") {
      return send(res, 302, "", { ...noStore, Location: testflightUrl || "/#download" });
    }
    const [needs, file] = DOWNLOADS[path];
    const isOpen = Array.isArray(needs) ? needs.some((n) => open.has(n)) : open.has(needs);
    if (isOpen) return send(res, 302, "", { ...noStore, Location: `${RELEASES}/${file}` });
    if (path.startsWith("/releases/")) return text(res, 404, "Not found\n", noStore);
    return send(res, 302, "", { ...noStore, Location: "/#download" });
  }

  const server = createServer(async (req, res) => {
    let path;
    let query;
    try {
      ({ pathname: path, searchParams: query } = new URL(req.url ?? "/", "http://localhost"));
    } catch {
      return text(res, 400, "Bad request\n");
    }
    try {
      if (path === "/api/waitlist") {
        if (req.method !== "POST") return json(res, 405, { error: "method" }, { Allow: "POST" });
        return await signUp(req, res);
      }
      if (path === "/api/waitlist/export") {
        if (req.method !== "GET") return json(res, 405, { error: "method" }, { Allow: "GET" });
        return exportList(req, res, query);
      }
      if (path === "/api/waitlist/mark-invited") {
        if (req.method !== "POST") return json(res, 405, { error: "method" }, { Allow: "POST" });
        return await markInvited(req, res);
      }
      if (path === "/healthz") return text(res, 200, "ok\n", { "Cache-Control": "no-store" });
      if (path === "/download" || path.startsWith("/download/") || path === "/releases/mac/appcast.xml") return download(req, res, path);
      const route = path === "/index.html" ? "/" : path === "/privacy/" ? "/privacy" : path;
      const file = files[route];
      if (!file) return text(res, 404, "Not found\n");
      if (req.method !== "GET" && req.method !== "HEAD") return text(res, 405, "Method not allowed\n", { Allow: "GET, HEAD" });
      const headers = { "Content-Type": file.type, "Cache-Control": file.cache };
      if (file.csp) headers["Content-Security-Policy"] = file.csp;
      return send(res, 200, file.body, headers);
    } catch (err) {
      console.error("request failed:", err instanceof Error ? err.message : err);
      if (!res.headersSent) return json(res, 500, { error: "server" });
      res.destroy();
    }
  });
  server.on("close", () => {
    clearInterval(sweep);
    db.close();
  });
  return { server, db, csp, open, turnstile: Boolean(turnstile), autoInvite: Boolean(auto) };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const port = Number(process.env.PORT ?? 8080);
  const host = process.env.HOST ?? "0.0.0.0";
  const dbPath = process.env.KLAV_WEB_DB ?? join(HERE, "data", "waitlist.db");
  const { server, open, turnstile, autoInvite } = createSite({
    dbPath,
    adminToken: process.env.KLAV_WEB_ADMIN_TOKEN,
    trustProxy: process.env.KLAV_WEB_TRUST_PROXY === "1",
    open: process.env.KLAV_WEB_OPEN,
    testflightUrl: process.env.KLAV_WEB_TESTFLIGHT_URL,
    env: process.env,
  });
  server.listen(port, host, () => {
    // The path, what is on and what is open; never a token, a secret or a cap's emails.
    const opened = OPENABLE.filter((name) => open.has(name)).join(",") || "nothing";
    const auto = autoInvite ? `on, cap ${process.env.KLAV_BETA_AUTO_CAP}` : "off";
    console.log(`klav-web on http://${host}:${port} · db ${dbPath} · export ${process.env.KLAV_WEB_ADMIN_TOKEN ? "on" : "off"} · open ${opened} · turnstile ${turnstile ? "on" : "off"} · auto invites ${auto}`);
  });
  const stop = () => server.close(() => process.exit(0));
  process.on("SIGTERM", stop);
  process.on("SIGINT", stop);
}
