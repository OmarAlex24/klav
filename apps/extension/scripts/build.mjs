// Builds the extension for Chromium browsers and Firefox from one source:
// bundles the TypeScript with esbuild (no runtime code loading), copies the
// pages, fonts, icons, the message catalogs (_locales: English by default,
// Spanish) and klav-wasm, and writes one manifest per target.
//
//   node scripts/build.mjs            → dist/chromium, dist/firefox
//   node scripts/build.mjs --zip      → also dist/klav-chromium.zip, dist/klav-firefox.zip
//   KLAV_STORE=1 …                   → Chromium build without the dev `key`
//   KLAV_DIST=DIR …                  → into DIR instead of dist/ (scripts/extension/package.sh)
import { execFileSync } from "node:child_process";
import { copyFileSync, cpSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import * as esbuild from "esbuild";

const here = dirname(fileURLToPath(import.meta.url));
const app = join(here, "..");
const dist = process.env.KLAV_DIST ? resolve(process.env.KLAV_DIST) : join(app, "dist");
const pkg = JSON.parse(readFileSync(join(app, "package.json"), "utf8"));
const zip = process.argv.includes("--zip");
const store = process.env.KLAV_STORE === "1";

/** The public half of the development key: fixes the Chromium ID to
 * niiplppgdljgimbnmokojdkofdcjkgao. The private half was discarded. */
const DEV_KEY = readFileSync(join(app, "static", "dev-key.txt"), "utf8").trim();
const FIREFOX_ID = "klav@klav.dev";

const ENTRIES = ["background", "content", "webauthn", "webauthn-page", "popup", "menu", "save", "card", "find", "notice", "passkey", "offscreen", "import"];
const PAGES = ["popup.html", "menu.html", "save.html", "card.html", "find.html", "notice.html", "passkey.html", "offscreen.html", "import.html"];
const MATCHES = ["http://*/*", "https://*/*"];

function manifest(target) {
  const base = {
    manifest_version: 3,
    name: "__MSG_ext_name__",
    version: pkg.version === "0.0.0" ? "0.1.0" : pkg.version,
    description: "__MSG_ext_description__",
    default_locale: "en",
    icons: { 16: "icons/16.png", 32: "icons/32.png", 48: "icons/48.png", 128: "icons/128.png" },
    action: {
      default_popup: "popup.html",
      default_title: "Klav",
      default_icon: { 16: "icons/16.png", 32: "icons/32.png" },
    },
    permissions: ["nativeMessaging", "alarms", "clipboardWrite", "storage"],
    content_scripts: [
      { matches: MATCHES, js: ["content.js"], all_frames: true, run_at: "document_idle" },
      // Passkeys (ADR 0020): from the start of the page, before its own
      // scripts call WebAuthn. The bridge is isolated; the hook runs in the
      // page's world, where `navigator.credentials` lives.
      { matches: MATCHES, js: ["webauthn.js"], all_frames: true, run_at: "document_start" },
      { matches: MATCHES, js: ["webauthn-page.js"], all_frames: true, run_at: "document_start", world: "MAIN" },
    ],
    web_accessible_resources: [{ resources: ["menu.html", "save.html", "card.html", "find.html", "notice.html", "passkey.html"], matches: MATCHES }],
    commands: {
      fill: {
        suggested_key: { default: "Ctrl+Shift+L", mac: "Command+Shift+L" },
        description: "__MSG_command_fill__",
      },
    },
    content_security_policy: {
      extension_pages: "script-src 'self' 'wasm-unsafe-eval'; object-src 'none'; base-uri 'none'; form-action 'none'",
    },
  };
  // Parts whose code arrives in later layers are only declared once built.
  const has = (entry) => existsSync(join(app, "src", entryFile(entry)));
  if (!has("content")) {
    delete base.content_scripts;
    delete base.commands;
  }
  base.web_accessible_resources[0].resources = base.web_accessible_resources[0].resources.filter((r) =>
    has(r.replace(".html", "")),
  );
  if (base.web_accessible_resources[0].resources.length === 0) delete base.web_accessible_resources;
  if (target === "chromium") {
    base.minimum_chrome_version = "120";
    base.background = { service_worker: "background.js" };
    // A service worker has no clipboard: an offscreen document clears it.
    // `favicon`: the site icons the browser already has (`_favicon`, a local lookup).
    base.permissions.push("offscreen", "favicon");
    if (base.web_accessible_resources) base.web_accessible_resources[0].use_dynamic_url = true;
    if (!store) base.key = DEV_KEY;
  } else {
    base.background = { scripts: ["background.js"] };
    base.browser_specific_settings = {
      gecko: {
        id: FIREFOX_ID,
        strict_min_version: "140.0",
        // Nothing leaves the computer: the extension only talks to the native host.
        data_collection_permissions: { required: ["none"] },
      },
    };
  }
  return base;
}

async function build(target) {
  const out = join(dist, target);
  rmSync(out, { recursive: true, force: true });
  mkdirSync(join(out, "fonts"), { recursive: true });
  mkdirSync(join(out, "icons"), { recursive: true });
  const entryPoints = Object.fromEntries(
    ENTRIES.filter((e) => existsSync(join(app, "src", entryFile(e))) && !(e === "offscreen" && target === "firefox")).map((e) => [
      e,
      join(app, "src", entryFile(e)),
    ]),
  );
  await esbuild.build({
    entryPoints,
    outdir: out,
    bundle: true,
    format: "iife",
    target: target === "chromium" ? "chrome120" : "firefox140",
    platform: "browser",
    sourcemap: false,
    minify: false,
    legalComments: "none",
    define: { __TARGET__: JSON.stringify(target) },
    logLevel: "warning",
    // wasm-bindgen's default URL is never used: we pass the module's URL.
    logOverride: { "empty-import-meta": "silent" },
  });
  // Firefox's background page has a clipboard of its own: no offscreen document.
  for (const page of PAGES.filter((p) => !(p === "offscreen.html" && target === "firefox"))) {
    const file = join(app, "src", "ui", page);
    if (existsSync(file)) copyFileSync(file, join(out, page));
  }
  for (const css of readdirSync(join(app, "src", "ui")).filter((f) => f.endsWith(".css"))) {
    copyFileSync(join(app, "src", "ui", css), join(out, css));
  }
  // Geist, Geist Mono and Departure Mono (OFL), with their licences.
  for (const font of readdirSync(join(app, "static", "fonts"))) {
    copyFileSync(join(app, "static", "fonts", font), join(out, "fonts", font));
  }
  for (const icon of readdirSync(join(app, "static", "icons"))) {
    copyFileSync(join(app, "static", "icons", icon), join(out, "icons", icon));
  }
  cpSync(join(app, "_locales"), join(out, "_locales"), { recursive: true });
  // The logos of common sites (scripts/site-icons.mjs), shared with the iOS app.
  copyFileSync(join(app, "..", "..", "assets", "site-icons", "site-icons.json"), join(out, "site-icons.json"));
  const wasm = join(app, "src", "wasm-gen", "klav_wasm_bg.wasm");
  if (!existsSync(wasm)) throw new Error("klav-wasm is not built: run `pnpm wasm` first");
  copyFileSync(wasm, join(out, "klav_wasm_bg.wasm"));
  writeFileSync(join(out, "manifest.json"), JSON.stringify(manifest(target), null, 2) + "\n");
  if (zip) {
    const archive = join(dist, `klav-${target}.zip`);
    rmSync(archive, { force: true });
    execFileSync("zip", ["-q", "-r", "-X", archive, "."], { cwd: out });
  }
  console.log(`${target} → ${out}`);
}

function entryFile(name) {
  if (name === "background") return "background/index.ts";
  if (name === "content") return "content/index.ts";
  if (name === "webauthn") return "content/webauthn.ts";
  if (name === "webauthn-page") return "page/index.ts";
  return `ui/${name}.ts`;
}

for (const target of ["chromium", "firefox"]) await build(target);
