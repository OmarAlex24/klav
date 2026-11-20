import { resolve } from "node:path";
import { expect, type Frame, test } from "@playwright/test";
import { type Browser, clickIn, launch, openMenu, shoot, startStack, type Stack, unlockForm, waitArmed } from "./harness";
import { type Site, startSite } from "./site";

const shots = process.env.SCREENSHOTS === "1" ? resolve(import.meta.dirname, "..", "..", "..", "docs", "img", "extension") : undefined;
const SECRET = "MARKER-sitio-local";
let stack: Stack;
let site: Site;
let browser: Browser;

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
});

/** Each test can run alone (a retry restarts klavd): unlock from the menu if needed. */
async function unlockIfLocked(menu: Frame): Promise<void> {
  const locked = menu.getByText("Klav is locked.");
  const ready = menu.locator(".choice, .empty");
  await expect(locked.or(ready).first()).toBeVisible();
  if (await locked.isVisible()) {
    await unlockForm(menu);
    await expect(ready.first()).toBeVisible();
  }
}

test.afterAll(async () => {
  await browser.context.close();
  await site.close();
  stack.stop();
});

test("fills a login on its own site after unlocking from the menu", async () => {
  const page = await browser.context.newPage();
  await page.goto(site.url("/login"));
  // Nothing is filled on load.
  await expect(page.locator("#password")).toHaveValue("");
  const menu = await openMenu(page, page.locator("#username"));
  await expect(menu.getByText("Klav is locked.")).toBeVisible();
  await unlockForm(menu);
  const choice = menu.getByRole("button", { name: /Sitio local/ });
  await expect(choice).toBeVisible();
  // Only the site's own login is offered.
  await expect(menu.getByRole("button", { name: /Otro sitio/ })).toHaveCount(0);
  await waitArmed(page);
  await shoot(page, shots, "menu-en-pagina");
  await clickIn(choice);
  await expect(page.locator("#username")).toHaveValue("ana");
  await expect(page.locator("#password")).toHaveValue(SECRET);
  // The menu closed itself.
  await expect.poll(() => page.frames().some((f) => f.url().includes("/menu.html"))).toBe(false);
  await page.close();
});

test("offers nothing on a look-alike address and fills nothing", async () => {
  const page = await browser.context.newPage();
  await page.goto(site.lookAlike("/login"));
  const menu = await openMenu(page, page.locator("#username"));
  await unlockIfLocked(menu);
  await expect(menu.getByText(/No Klav login is for/)).toBeVisible();
  await expect(menu.locator(".empty strong")).toHaveText("127.0.0.1");
  await expect(menu.getByRole("button", { name: /Sitio local/ })).toHaveCount(0);
  await shoot(page, shots, "menu-parecido");
  await expect(page.locator("#username")).toHaveValue("");
  await expect(page.locator("#password")).toHaveValue("");
  await page.close();
});

test("fills a login inside a same-origin frame", async () => {
  const page = await browser.context.newPage();
  await page.goto(site.url("/frame"));
  const frame = page.frameLocator("iframe[title=Entrar]");
  const menu = await openMenu(page, frame.locator("#username"));
  await unlockIfLocked(menu);
  const choice = menu.getByRole("button", { name: /Sitio local/ });
  await expect(choice).toBeVisible();
  await waitArmed(page);
  await clickIn(choice);
  await expect(frame.locator("#password")).toHaveValue(SECRET);
  await page.close();
});
