/**
 * The popup's type tabs and «Codes»: counts per type under the search, one
 * type at a time, and the codes view where one click copies a code. With
 * SCREENSHOTS=1 it also takes the pictures of docs/extension.md.
 */
import { resolve } from "node:path";
import { expect, type Page, test } from "@playwright/test";
import { type Browser, launch, shoot, type Stack, startStack } from "./harness";
import { type Site, startSite } from "./site";

const shots = process.env.SCREENSHOTS === "1" ? resolve(import.meta.dirname, "..", "..", "..", "docs", "img", "extension") : undefined;
/** Example seeds (RFC 6238-style test values), never real accounts. */
const SEEDS = ["JBSWY3DPEHPK3PXP", "GEZDGNBVGY3TQOJQ", "MFRGGZDFMZTWQ2LK"];
let stack: Stack;
let site: Site;
let browser: Browser;

test.beforeAll(async () => {
  stack = await startStack();
  site = await startSite();
  const add = (args: string[], stdin = ""): void => {
    stack.klav(["item", "add", ...args], { unlocked: true, stdin });
  };
  add(["login", "--title", "GitHub", "--username", "ana", "--url", "https://github.com", "--secret-stdin", "password", "--secret-stdin", "totp"], `MARKER-gh\n${SEEDS[0]}\n`);
  add(["login", "--title", "AWS", "--username", "ana@example.com", "--url", "https://aws.amazon.com", "--secret-stdin", "password", "--secret-stdin", "totp"], `MARKER-aws\n${SEEDS[1]}\n`);
  add(["login", "--title", "Linear", "--username", "ana@example.com", "--url", "https://linear.app", "--secret-stdin", "password"], "MARKER-linear\n");
  add(["totp", "--title", "Google", "--secret-stdin", "totp"], `${SEEDS[2]}\n`);
  add(["api-key", "--title", "Stripe", "--secret-stdin", "api_key"], "MARKER-stripe\n");
  add(["card", "--title", "Visa", "--field", "cardholder=Ana López"]);
  add(["note", "--title", "Router"]);
  add(["ssh-key", "--title", "Servidor", "--field", "fingerprint=SHA256:example"]);
  stack.klav(["unlock"], { unlocked: true });
  browser = await launch(stack);
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

test("the tabs count each type and show one at a time", async () => {
  const popup = await browser.popup();
  const tabs = popup.getByRole("tablist", { name: "Filter by type" });
  // «Codes» arrives right after the first paint, with its count.
  await expect(tabs.getByRole("tab")).toHaveText(["All8", "Logins3", "Codes3", "Cards1", "Notes1", "SSH keys1", "API keys1"]);
  await expect(tabs.getByRole("tab", { name: "All, 8" })).toHaveAttribute("aria-selected", "true");
  await shoot(popup, shots, "popup-tipos");

  await tabs.getByRole("tab", { name: "Cards, 1" }).click();
  await expect(popup.locator(".list .row-title")).toHaveText(["Visa"]);
  await expect(popup.getByRole("heading", { name: "Cards" })).toBeVisible();

  // ← and → move between the tabs and show each one.
  await tabs.getByRole("tab", { name: "Cards, 1" }).focus();
  await popup.keyboard.press("ArrowRight");
  await expect(tabs.getByRole("tab", { name: "Notes, 1" })).toBeFocused();
  await expect(popup.locator(".list .row-title")).toHaveText(["Router"]);
  await popup.keyboard.press("Home");
  await expect(popup.locator(".list .row-title")).toHaveCount(8);

  // A search counts again; a tab it empties stays, and says so.
  await tabs.getByRole("tab", { name: "Logins, 3" }).click();
  await popup.getByLabel("Search your vault").fill("stripe");
  await expect(tabs.getByRole("tab", { name: "Logins, 0" })).toHaveAttribute("aria-selected", "true");
  await expect(popup.getByText("Nothing in Logins matches “stripe”.")).toBeVisible();
  await popup.close();
});

test("«Codes» shows every code large, and one click copies it", async () => {
  const page = await browser.context.newPage();
  await page.goto(site.url("/"));
  const popup = await browser.popup();
  await popup.getByRole("tab", { name: "Codes, 3" }).click();
  const rows = popup.locator(".code-row");
  await expect(rows).toHaveCount(3);
  await expect(rows.locator(".row-title")).toHaveText(["AWS", "GitHub", "Google"]);
  for (const code of await rows.locator(".code").all()) await expect(code).toHaveText(/^\d{3} \d{3}$/);
  // Nothing but the codes on screen: no password left the vault.
  expect(await popup.content()).not.toContain("MARKER-");
  await shoot(popup, shots, "popup-codigos");

  const shown = (await rows.nth(1).locator(".code").textContent())?.replace(" ", "") ?? "";
  await popup.getByRole("button", { name: "Copy code for GitHub" }).click();
  await expect(popup.getByRole("status")).toHaveText("Copied");
  await expect.poll(() => clipboard(page)).toMatch(/^\d{6}$/);
  // The code copied is the one on screen (or the next one, at the edge of a period).
  const copied = await clipboard(page);
  expect(copied.length).toBe(shown.length);

  // A search keeps the view; an item opened and closed comes back to it.
  await popup.bringToFront();
  await popup.getByLabel("Search your vault").fill("git");
  await expect(rows.locator(".row-title")).toHaveText(["GitHub"]);
  await popup.getByLabel("Search your vault").fill("");
  await popup.getByRole("tab", { name: "All, 8" }).click();
  await popup.getByRole("button", { name: /^Linear/ }).click();
  await popup.getByRole("button", { name: "Your vault" }).click();
  await expect(popup.getByRole("tab", { name: "All, 8" })).toHaveAttribute("aria-selected", "true");
  await popup.getByRole("tab", { name: "Codes, 3" }).click();
  await popup.locator(".list-codes").waitFor();
  await popup.getByRole("tab", { name: "Codes, 3" }).focus();
  await popup.keyboard.press("ArrowLeft");
  await popup.getByRole("button", { name: /^AWS/ }).click();
  await popup.getByRole("button", { name: "Your vault" }).click();
  await expect(popup.getByRole("tab", { name: "Logins, 3" })).toHaveAttribute("aria-selected", "true");
  await popup.close();
  await page.close();
});

test("a vault without codes has no «Codes» tab", async () => {
  const other = await startStack();
  try {
    other.klav(["item", "add", "note", "--title", "Wi-Fi"], { unlocked: true });
    other.klav(["item", "add", "login", "--title", "Linear", "--username", "ana", "--secret-stdin", "password"], { unlocked: true, stdin: "MARKER-x\n" });
    other.klav(["unlock"], { unlocked: true });
    const mine = await launch(other);
    try {
      const popup = await mine.popup();
      await expect(popup.locator(".list .row")).toHaveCount(2);
      // Long enough for the codes to have been asked for.
      await popup.waitForTimeout(500);
      await expect(popup.getByRole("tab")).toHaveText(["All2", "Logins1", "Notes1"]);
    } finally {
      await mine.context.close();
    }
  } finally {
    other.stop();
  }
});
