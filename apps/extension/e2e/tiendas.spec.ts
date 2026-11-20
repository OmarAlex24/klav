/**
 * The store screenshots (docs/publicar-extension.md §4): 1280×800, the real
 * extension on a sample site, with sample data only. Not part of the usual
 * run; to make them again:
 *
 *   STORE_SHOTS=1 pnpm --filter @klav/extension e2e tiendas
 *
 * They land in store/screenshots/{en,es}/. The sample site is served over
 * HTTPS with a throwaway certificate, and Chromium maps its fictional domain
 * (`.example`, reserved) to 127.0.0.1, so the extension sees a normal site.
 */
import { execFileSync } from "node:child_process";
import { mkdirSync, readFileSync } from "node:fs";
import { createServer, type Server } from "node:https";
import { join, resolve } from "node:path";
import { expect, type Page, test } from "@playwright/test";
import { type Browser, clickIn, frameOf, KLAV_BIN, launch, openMenu, registerAgent, settled, type Stack, startStack, waitArmed } from "./harness";
import { McpClient } from "./mcp";

test.skip(process.env.STORE_SHOTS !== "1", "store screenshots: STORE_SHOTS=1");

const HOST = "app.northwind.example";
const VIEW = { width: 1280, height: 800 };
const OUT = resolve(import.meta.dirname, "..", "store", "screenshots");

type Lang = "en" | "es";

const WORDS = {
  en: {
    nav: ["Projects", "Invoices", "Team"],
    signIn: "Sign in to Northwind",
    signInLead: "Welcome back. Use your work email.",
    email: "Email",
    password: "Password",
    submit: "Sign in",
    forgot: "Forgot your password?",
    signUp: "Create your Northwind account",
    signUpLead: "Free for teams of up to five.",
    newPassword: "Password",
    again: "Repeat the password",
    create: "Create account",
    home: "Good morning, Ana",
    homeLead: "Three invoices are waiting for review.",
    rows: [
      ["INV-2041", "Harbor Freight Co.", "€1,240.00"],
      ["INV-2040", "Lumen Studio", "€860.00"],
      ["INV-2038", "Quarry & Sons", "€3,115.50"],
    ],
    reason: "sign in to download the March invoice",
  },
  es: {
    nav: ["Proyectos", "Facturas", "Equipo"],
    signIn: "Entra en Northwind",
    signInLead: "Hola de nuevo. Usa tu correo del trabajo.",
    email: "Correo",
    password: "Contraseña",
    submit: "Entrar",
    forgot: "¿Olvidaste tu contraseña?",
    signUp: "Crea tu cuenta de Northwind",
    signUpLead: "Gratis para equipos de hasta cinco personas.",
    newPassword: "Contraseña",
    again: "Repite la contraseña",
    create: "Crear cuenta",
    home: "Buenos días, Ana",
    homeLead: "Hay tres facturas pendientes de revisar.",
    rows: [
      ["INV-2041", "Harbor Freight Co.", "1240,00 €"],
      ["INV-2040", "Lumen Studio", "860,00 €"],
      ["INV-2038", "Quarry & Sons", "3115,50 €"],
    ],
    reason: "entrar para descargar la factura de marzo",
  },
} as const;

/** The sample site: a fictional invoicing app, in the screenshot's language. */
function sitePage(lang: Lang, title: string, main: string): string {
  const w = WORDS[lang];
  return `<!doctype html>
<html lang="${lang}"><head><meta charset="utf-8"><title>${title} · Northwind</title>
<style>
  * { box-sizing: border-box; }
  body { margin: 0; font: 15px/1.5 -apple-system, "Helvetica Neue", Arial, sans-serif; background: #eef1ee; color: #1b2a22; }
  header { height: 60px; display: flex; align-items: center; gap: 32px; padding: 0 40px; background: #12392b; color: #e8f0eb; }
  header b { font-size: 18px; letter-spacing: .02em; }
  header nav { display: flex; gap: 22px; font-size: 14px; color: #a9c2b4; }
  main { width: 420px; margin: 72px auto 0; background: #fff; border: 1px solid #d5ddd7; border-radius: 6px; padding: 32px 36px 36px; }
  main.wide { width: 560px; margin-left: 120px; }
  h1 { font-size: 24px; margin: 0 0 4px; }
  p.lead { margin: 0 0 22px; color: #5b6b62; }
  label { display: block; font-size: 13px; font-weight: 600; margin: 16px 0 6px; color: #33463b; }
  input { width: 100%; font: inherit; padding: 10px 12px; border: 1px solid #b9c6bd; border-radius: 4px; background: #fff; }
  button { margin-top: 24px; width: 100%; font: inherit; font-weight: 600; padding: 11px; border: 0; border-radius: 4px; background: #1f6b4e; color: #fff; }
  a { display: block; margin-top: 16px; font-size: 13px; color: #1f6b4e; }
  table { width: 100%; border-collapse: collapse; margin-top: 8px; }
  td { padding: 12px 0; border-top: 1px solid #e3e8e4; }
  td:last-child { text-align: right; font-variant-numeric: tabular-nums; }
</style></head><body>
<header><b>Northwind</b><nav>${w.nav.map((n) => `<span>${n}</span>`).join("")}</nav></header>
${main}
</body></html>`;
}

function pages(lang: Lang): Record<string, string> {
  const w = WORDS[lang];
  const login = sitePage(
    lang,
    w.submit,
    `<main><h1>${w.signIn}</h1><p class="lead">${w.signInLead}</p>
    <form method="post" action="/session">
      <label for="email">${w.email}</label>
      <input id="email" name="email" type="email" autocomplete="username">
      <label for="password">${w.password}</label>
      <input id="password" name="password" type="password" autocomplete="current-password">
      <button>${w.submit}</button>
    </form><a>${w.forgot}</a></main>`,
  );
  const signup = sitePage(
    lang,
    w.create,
    `<main><h1>${w.signUp}</h1><p class="lead">${w.signUpLead}</p>
    <form method="post" action="/session">
      <label for="email">${w.email}</label>
      <input id="email" name="email" type="email" autocomplete="email">
      <label for="new">${w.newPassword}</label>
      <input id="new" name="password" type="password" autocomplete="new-password">
      <label for="again">${w.again}</label>
      <input id="again" name="password_confirmation" type="password" autocomplete="new-password">
      <button>${w.create}</button>
    </form></main>`,
  );
  const home = sitePage(
    lang,
    w.home,
    `<main class="wide"><h1>${w.home}</h1><p class="lead">${w.homeLead}</p>
    <table>${w.rows.map((r) => `<tr>${r.map((c) => `<td>${c}</td>`).join("")}</tr>`).join("")}</table></main>`,
  );
  return { "/login": login, "/signup": signup, "/home": home };
}

async function startSampleSite(dir: string, lang: Lang): Promise<{ port: number; close(): Promise<void> }> {
  // A certificate for this run only; Chromium is told to accept it.
  execFileSync(
    "openssl",
    ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", `/CN=${HOST}`, "-keyout", join(dir, "site.key"), "-out", join(dir, "site.crt")],
    { stdio: "ignore" },
  );
  const html = pages(lang);
  const server: Server = createServer({ key: readFileSync(join(dir, "site.key")), cert: readFileSync(join(dir, "site.crt")) }, (req, res) => {
    const path = new URL(req.url ?? "/", "https://x").pathname;
    if (req.method === "POST") {
      req.resume();
      req.on("end", () => {
        res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
        res.end(html["/home"]);
      });
      return;
    }
    const body = html[path];
    res.writeHead(body ? 200 : 404, { "content-type": "text/html; charset=utf-8" });
    res.end(body ?? "not found");
  });
  await new Promise<void>((done) => server.listen(0, "127.0.0.1", done));
  const address = server.address();
  const port = typeof address === "object" && address ? address.port : 0;
  return {
    port,
    close: () =>
      new Promise((done) => {
        server.closeAllConnections();
        server.close(() => {
          done();
        });
      }),
  };
}

/** Klav's own words, from the catalog the browser uses. */
function catalog(lang: Lang): (key: string, ...subs: string[]) => string {
  const messages = JSON.parse(readFileSync(resolve(import.meta.dirname, "..", "_locales", lang, "messages.json"), "utf8")) as Record<
    string,
    { message: string }
  >;
  return (key, ...subs) => {
    const entry = messages[key];
    if (!entry) throw new Error(`no message ${key}`);
    return subs.reduce((text, sub, i) => text.replace(`$${String(i + 1)}`, sub), entry.message);
  };
}

/**
 * Shows the popup as it drops from the toolbar: its picture over the page,
 * at the top right, with the border and shadow of what floats (diseno-visual §2).
 */
async function withPopup(page: Page, popup: Page): Promise<void> {
  const png = await popup.screenshot();
  await page.evaluate(async (src) => {
    const img = document.createElement("img");
    img.src = src;
    img.width = 360;
    img.height = 560;
    Object.assign(img.style, {
      position: "fixed",
      top: "8px",
      right: "24px",
      border: "1px solid #09090B",
      boxShadow: "0 12px 32px -12px rgb(9 9 11 / .35)",
      zIndex: "2147483647",
    });
    document.body.append(img);
    await img.decode();
  }, `data:image/png;base64,${png.toString("base64")}`);
}

const TOTP = ["JBSWY3DPEHPK3PXP", "KRSXG5CTMVRXEZLU", "GEZDGNBVGY3TQOJQ"];

for (const lang of ["en", "es"] as const) {
  test.describe(`store screenshots (${lang})`, () => {
    const w = WORDS[lang];
    const m = catalog(lang);
    const dir = join(OUT, lang);
    let stack: Stack;
    let site: Awaited<ReturnType<typeof startSampleSite>>;
    let browser: Browser;
    const clients: McpClient[] = [];

    test.beforeAll(async () => {
      mkdirSync(dir, { recursive: true });
      stack = await startStack();
      site = await startSampleSite(stack.dir, lang);
      const add = (title: string, username: string, url: string, totp?: string): void => {
        const args = ["item", "add", "login", "--title", title, "--username", username, "--url", url, "--secret-stdin", "password"];
        stack.klav(totp ? [...args, "--secret-stdin", "totp"] : args, {
          unlocked: true,
          stdin: `sample-${title.length.toString()}-password\n${totp ? `${totp}\n` : ""}`,
        });
      };
      add("Northwind", "ana.garcia@example.com", `https://${HOST}`, TOTP[0]);
      add("Northwind (admin)", "admin@example.com", `https://${HOST}`);
      add("GitHub", "ana-garcia", "https://github.com", TOTP[1]);
      add("Linear", "ana.garcia@example.com", "https://linear.app");
      add("Figma", "ana.garcia@example.com", "https://figma.com");
      add("Stripe", "ana.garcia@example.com", "https://dashboard.stripe.com", TOTP[2]);
      add("Vercel", "ana-garcia", "https://vercel.com");
      add("Notion", "ana.garcia@example.com", "https://notion.so");
      browser = await launch(stack, {
        lang,
        args: [`--host-resolver-rules=MAP ${HOST} 127.0.0.1:${String(site.port)}`, "--ignore-certificate-errors"],
      });
      stack.klav(["unlock"], { unlocked: true });
    });

    test.afterAll(async () => {
      for (const c of clients) c.close();
      await browser.context.close().catch(() => undefined);
      await site.close();
      stack.stop();
    });

    async function open(path: string): Promise<Page> {
      const page = await browser.context.newPage();
      await page.setViewportSize(VIEW);
      await page.goto(`https://${HOST}${path}`);
      await page.bringToFront();
      return page;
    }

    test("fill from the field", async () => {
      const page = await open("/login");
      const menu = await openMenu(page, page.locator("#email"));
      await expect(menu.getByText("admin@example.com")).toBeVisible();
      await waitArmed(page);
      await page.screenshot({ path: join(dir, "1-rellenar.png") });
      await page.close();
    });

    test("the vault, with its codes in view", async () => {
      const page = await open("/home");
      const popup = await browser.popup();
      await expect(popup.getByText(m("your_vault"))).toBeVisible();
      await expect(popup.locator(".row", { hasText: "GitHub" }).getByText(/^\d{3}\s?\d{3}$/)).toBeVisible();
      await popup.waitForTimeout(500);
      await page.bringToFront();
      await withPopup(page, popup);
      await page.screenshot({ path: join(dir, "2-boveda.png") });
      await popup.close();
      await page.close();
    });

    test("a strong password for a new account", async () => {
      const page = await open("/signup");
      await page.locator("#email").fill("ana.garcia@example.com");
      const menu = await openMenu(page, page.locator("#new"));
      await expect(menu.getByLabel(m("generated_password"), { exact: true })).toBeVisible();
      await waitArmed(page);
      await page.screenshot({ path: join(dir, "3-generar.png") });
      await page.close();
    });

    test("save what you type", async () => {
      const page = await open("/login");
      await page.locator("#email").fill("facturas@example.com");
      await page.locator("#password").fill("sample-new-password");
      await page.getByRole("button", { name: w.submit }).click();
      await expect(page.getByRole("heading", { name: w.home })).toBeVisible();
      const bar = await frameOf(page, "/save.html");
      await expect(bar.getByText(`facturas@example.com · ${HOST}`)).toBeVisible();
      await settled(bar);
      await page.waitForTimeout(300);
      await page.screenshot({ path: join(dir, "4-guardar.png") });
      await page.close();
    });

    test("an agent asks, the person approves", async () => {
      const agent = registerAgent(stack, "claude-code", ["--ask", "fill"]);
      const page = await open("/login");
      const mcp = new McpClient(KLAV_BIN, agent.repo, { KLAV_HOME: agent.home, KLAV_BROWSER_HOME: stack.home, KLAV_NO_TOUCH_ID: "1" });
      clients.push(mcp);
      await mcp.initialize();
      // The extension attaches when the browser starts; ask until it has.
      let pending: Promise<unknown> | undefined;
      for (let i = 0; i < 30 && !pending; i++) {
        const asked = mcp.tool("fill_login", { ref: "Northwind", target: "extension", reason: w.reason, wait_seconds: 90 });
        const quick = await Promise.race([asked, new Promise((r) => setTimeout(r, 1_500, "waiting"))]);
        if (quick === "waiting") pending = asked;
        else await new Promise((r) => setTimeout(r, 300));
      }
      if (!pending) throw new Error("the agent's request never waited for the person");
      pending.catch(() => undefined);
      await expect
        .poll(() => (JSON.parse(stack.klav(["approval", "list", "--json"], { unlocked: true })) as unknown[]).length, { timeout: 20_000 })
        .toBe(1);
      // The top card of the login page would sit over the popup's picture.
      const card = await frameOf(page, "/card.html");
      await waitArmed(page);
      await clickIn(card.getByRole("button", { name: m("close") }));
      await expect.poll(() => page.frames().some((f) => f.url().includes("/card.html"))).toBe(false);
      const popup = await browser.popup();
      await expect(popup.getByText(m("agent_waits", "claude-code"))).toBeVisible({ timeout: 20_000 });
      await popup.waitForTimeout(500);
      await page.bringToFront();
      await withPopup(page, popup);
      await page.screenshot({ path: join(dir, "5-agentes.png") });
      await popup.close();
      await page.close();
    });
  });
}
