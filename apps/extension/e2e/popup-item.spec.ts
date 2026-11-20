import { resolve } from "node:path";
import { expect, type Page, test } from "@playwright/test";
import { type Browser, launch, shoot, type Stack, startStack } from "./harness";
import { type Site, startSite } from "./site";

const shots = process.env.SCREENSHOTS === "1" ? resolve(import.meta.dirname, "..", "..", "..", "docs", "img", "extension") : undefined;
const SECRET = "MARKER-popup";
let stack: Stack;
let site: Site;
let browser: Browser;

test.beforeAll(async () => {
  stack = await startStack();
  site = await startSite();
  stack.klav(
    ["item", "add", "login", "--title", "Sitio local", "--username", "ana", "--url", site.url("/"), "--secret-stdin", "password", "--secret-stdin", "totp"],
    { unlocked: true, stdin: `${SECRET}\nJBSWY3DPEHPK3PXP\n` },
  );
  browser = await launch(stack);
  stack.klav(["unlock"], { unlocked: true });
  await browser.context.grantPermissions(["clipboard-read", "clipboard-write"], { origin: site.url("/").replace(/\/$/, "") });
});

test.afterAll(async () => {
  await browser.context.close();
  await site.close();
  stack.stop();
});

async function clipboard(page: Page): Promise<string> {
  await page.bringToFront();
  return page.evaluate(() => navigator.clipboard.readText());
}

test("an item opens masked, reveals and copies, and the clipboard is cleared later", async () => {
  const page = await browser.context.newPage();
  await page.goto(site.url("/"));
  const popup = await browser.popup();
  await popup.getByLabel("Search your vault").fill("Sitio");
  await popup.getByRole("button", { name: /^Sitio local/ }).click();
  await expect(popup.getByRole("heading", { name: "Sitio local" })).toBeVisible();
  await expect(popup.getByText("ana", { exact: true })).toBeVisible();
  await expect(popup.getByText(/^\d{3} \d{3}$/)).toBeVisible();
  // The password is not in the page until the person asks.
  expect(await popup.content()).not.toContain(SECRET);
  await shoot(popup, shots, "popup-elemento");

  await popup.getByRole("button", { name: "Show Password" }).click();
  await expect(popup.getByText(SECRET)).toBeVisible();
  await popup.getByRole("button", { name: "Hide Password" }).click();
  await expect(popup.getByText(SECRET)).toHaveCount(0);

  await popup.getByRole("button", { name: "Copy Password" }).click();
  await expect(popup.getByRole("status")).toHaveText("Copied");
  await shoot(popup, shots, "popup-copiado");
  // A confirmation, not a countdown: it goes after about 2 s, sooner than
  // the 5 s of other messages.
  await expect(popup.locator(".toast")).toHaveCount(0, { timeout: 4_000 });
  expect(await clipboard(page)).toBe(SECRET);

  // The background clears it when its alarm fires (moved earlier here: an
  // unpacked extension may use short alarms).
  await browser.worker.evaluate(() => chrome.alarms.create("clear-clipboard", { when: Date.now() + 300 }));
  await expect.poll(() => clipboard(page), { timeout: 10_000 }).toBe("");
  // And it left no record of a clear that failed.
  expect(await browser.worker.evaluate(() => chrome.storage.local.get("clipboardNotCleared"))).toEqual({});

  await popup.getByRole("button", { name: "Copy One-time code" }).click();
  await expect.poll(() => clipboard(page)).toMatch(/^\d{6}$/);
  await popup.close();
  await page.close();
});

test("the popup fills the page's login into the active tab", async () => {
  const page = await browser.context.newPage();
  await page.goto(site.url("/login"));
  // The popup is a tab here: open it behind the page, which stays active.
  const popup = await browser.context.newPage();
  await page.bringToFront();
  await popup.setViewportSize({ width: 360, height: 560 });
  await popup.goto(browser.extensionUrl("popup.html"));
  await expect(popup.getByText("On localhost")).toBeVisible();
  if (shots) {
    await popup.bringToFront();
    await shoot(popup, shots, "popup-en-pagina");
    await page.bringToFront();
  }
  const closed = popup.waitForEvent("close");
  await popup.getByRole("button", { name: "Fill Sitio local" }).click();
  await closed;
  await expect(page.locator("#username")).toHaveValue("ana");
  await expect(page.locator("#password")).toHaveValue(SECRET);
  await page.close();
});

test("the current site's login shows its live code, and ⌘C copies it", async () => {
  const page = await browser.context.newPage();
  await page.goto(site.url("/login"));
  const popup = await browser.context.newPage();
  await page.bringToFront();
  await popup.setViewportSize({ width: 360, height: 560 });
  await popup.goto(browser.extensionUrl("popup.html"));
  const code = popup.getByRole("group", { name: "One-time code for Sitio local" });
  await expect(code).toContainText(/^\d{3} \d{3}$/);
  // ⌘C (Ctrl+C elsewhere) with nothing selected copies that code.
  await popup.bringToFront();
  await popup.keyboard.press("ControlOrMeta+c");
  await expect(popup.getByRole("status")).toHaveText("Copied");
  await expect.poll(() => clipboard(page)).toMatch(/^\d{6}$/);
  await popup.close();
  await page.close();
});
