/**
 * Klav's surfaces inside a page besides the field menu: the top card
 * («Iniciar sesión como ana · localhost») and the central palette, with
 * its confirmation before filling a login of another site.
 */
import { resolve } from "node:path";
import { expect, type Page, test } from "@playwright/test";
import { type Browser, clickIn, frameOf, launch, openMenu, shoot, startStack, type Stack, waitArmed } from "./harness";
import { type Site, startSite } from "./site";

const shots = process.env.SCREENSHOTS === "1" ? resolve(import.meta.dirname, "..", "..", "..", "docs", "img", "extension") : undefined;
const SECRET = "MARKER-pagina";
let stack: Stack;
let site: Site;
let browser: Browser;
/** Set once the browser started (cleanup runs even if it did not). */
let started: Browser | undefined;

test.beforeAll(async () => {
  stack = await startStack();
  site = await startSite();
  stack.klav(
    ["item", "add", "login", "--title", "Sitio local", "--username", "ana", "--url", site.url("/"), "--secret-stdin", "password"],
    { unlocked: true, stdin: `${SECRET}\n` },
  );
  stack.klav(["item", "add", "login", "--title", "Otro sitio", "--username", "bea", "--url", "https://example.org", "--secret-stdin", "password"], {
    unlocked: true,
    stdin: "MARKER-otro\n",
  });
  browser = await launch(stack);
  started = browser;
  // The card only shows while Klav is unlocked.
  stack.klav(["unlock"], { unlocked: true });
});

test.afterAll(async () => {
  // Even if the browser never started: no server or klavd left behind.
  await started?.context.close().catch(() => undefined);
  await site.close();
  stack.stop();
});

function hasFrame(page: Page, file: string): boolean {
  return page.frames().some((f) => f.url().includes(file));
}

test("the top card offers the site's login and fills only on a click", async () => {
  const page = await browser.context.newPage();
  await page.goto(site.url("/login"));
  const card = await frameOf(page, "/card.html");
  await expect(card.getByText("Sign in as")).toBeVisible();
  await expect(card.locator(".card-what strong")).toHaveText("ana");
  await expect(card.getByText("· localhost")).toBeVisible();
  // It never fills by itself.
  await page.waitForTimeout(1_000);
  await expect(page.locator("#password")).toHaveValue("");
  await shoot(page, shots, "tarjeta-arriba");
  await waitArmed(page);
  await clickIn(card.getByRole("button", { name: "Sign in" }));
  await expect(page.locator("#username")).toHaveValue("ana");
  await expect(page.locator("#password")).toHaveValue(SECRET);
  await expect.poll(() => hasFrame(page, "/card.html")).toBe(false);
  await page.close();
});

test("on a narrow window the top card is centred", async () => {
  const page = await browser.context.newPage();
  await page.setViewportSize({ width: 480, height: 700 });
  await page.goto(site.url("/login"));
  const card = await frameOf(page, "/card.html");
  const box = await (await card.frameElement()).boundingBox();
  expect(box).not.toBeNull();
  if (box) expect(Math.abs(box.x + box.width / 2 - 240)).toBeLessThanOrEqual(1);
  await page.close();
});

test("typing in the form sends the top card away", async () => {
  const page = await browser.context.newPage();
  await page.goto(site.url("/login"));
  await frameOf(page, "/card.html");
  await page.locator("#username").pressSequentially("a");
  await expect.poll(() => hasFrame(page, "/card.html")).toBe(false);
  await expect(page.locator("#password")).toHaveValue("");
  await page.close();
});

test("«Buscar otro elemento» opens the palette, with this site's logins first", async () => {
  const page = await browser.context.newPage();
  await page.goto(site.url("/login"));
  const menu = await openMenu(page, page.locator("#username"));
  await waitArmed(page);
  await clickIn(menu.getByRole("button", { name: /^Find another item/ }));
  const find = await frameOf(page, "/find.html");
  await expect.poll(() => hasFrame(page, "/menu.html")).toBe(false);
  await expect(find.getByRole("heading", { name: "On localhost" })).toBeVisible();
  await expect(find.getByRole("heading", { name: "Other logins" })).toBeVisible();
  const first = find.locator(".choice").first();
  await expect(first).toContainText("Sitio local");
  await waitArmed(page);
  await clickIn(first);
  await expect(page.locator("#username")).toHaveValue("ana");
  await expect(page.locator("#password")).toHaveValue(SECRET);
  await expect.poll(() => hasFrame(page, "/find.html")).toBe(false);
  await page.close();
});

test("the palette fills another site's login only after confirming the host", async () => {
  const page = await browser.context.newPage();
  await page.goto(site.lookAlike("/login"));
  const menu = await openMenu(page, page.locator("#username"));
  await expect(menu.getByText(/No Klav login is for/)).toBeVisible();
  await waitArmed(page);
  await clickIn(menu.getByRole("button", { name: /^Find another item/ }));
  const find = await frameOf(page, "/find.html");
  await expect(find.getByRole("heading", { name: "Other logins" })).toBeVisible();
  await find.getByLabel("Search for a login").fill("sitio lo");
  await expect(find.locator(".choice")).toHaveCount(1);
  await shoot(page, shots, "buscador");
  await waitArmed(page);
  await clickIn(find.getByRole("button", { name: /^Sitio local/ }));
  // One click only reaches the question, with both hosts in view.
  await expect(find.getByRole("heading", { name: "Fill Sitio local on 127.0.0.1?" })).toBeVisible();
  await expect(find.locator(".site-host")).toHaveText(["localhost", "127.0.0.1"]);
  await expect(page.locator("#password")).toHaveValue("");
  await shoot(page, shots, "buscador-confirmar");
  // Each view change resizes the frame, and the clickjacking guard ignores
  // clicks until it has been fully visible again for a moment.
  await waitArmed(page);
  await clickIn(find.getByRole("button", { name: "Back" }));
  await expect(find.getByLabel("Search for a login")).toBeVisible();
  await expect(page.locator("#password")).toHaveValue("");
  await waitArmed(page);
  await clickIn(find.getByRole("button", { name: /^Sitio local/ }));
  await expect(find.getByRole("button", { name: "Fill on 127.0.0.1" })).toBeVisible();
  await waitArmed(page);
  await clickIn(find.getByRole("button", { name: "Fill on 127.0.0.1" }));
  await expect(page.locator("#username")).toHaveValue("ana");
  await expect(page.locator("#password")).toHaveValue(SECRET);
  await expect.poll(() => hasFrame(page, "/find.html")).toBe(false);
  await page.close();
});
