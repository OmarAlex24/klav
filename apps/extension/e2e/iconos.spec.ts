/**
 * Site icons (docs/extension.md §7): the logo Klav ships, the favicon the
 * browser already has, or the initial; a site is asked for its own icon
 * only when the person turns that on, and nobody else ever is.
 */
import { resolve } from "node:path";
import { expect, type Page, test } from "@playwright/test";
import { type Browser, launch, openMenu, shoot, startStack, type Stack, waitArmed, unlockInBrowser } from "./harness";
import { type Site, startSite } from "./site";

const shots = process.env.SCREENSHOTS === "1" ? resolve(import.meta.dirname, "..", "..", "..", "docs", "img", "extension") : undefined;
let stack: Stack;
let site: Site;
let browser: Browser;
let other: string;

test.beforeAll(async () => {
  stack = await startStack();
  site = await startSite();
  other = new URL(site.lookAlike("/")).host;
  const add = (title: string, username: string, url: string): void => {
    stack.klav(["item", "add", "login", "--title", title, "--username", username, "--url", url, "--secret-stdin", "password"], {
      unlocked: true,
      stdin: `MARKER-${username}\n`,
    });
  };
  add("GitHub", "ana", "https://github.com");
  add("Gist", "ana-gists", "https://gist.github.com");
  add("Sitio local", "ana", site.url("/"));
  add("Panel interno", "ops", site.lookAlike("/"));
  stack.klav(["item", "add", "card", "--title", "Visa", "-f", "cardholder=Ana Pérez", "--secret-stdin", "number"], {
    unlocked: true,
    stdin: "4111111111111111\n",
  });
  browser = await launch(stack);
  await unlockInBrowser(stack, browser);
});

test.afterAll(async () => {
  await browser.context.close();
  await site.close();
  stack.stop();
});

function row(popup: Page, title: string) {
  return popup.locator(".row", { has: popup.locator(".row-title", { hasText: new RegExp(`^${title}$`) }) });
}

test("the popup draws shipped logos and initials, and asks no site for an icon", async () => {
  const popup = await browser.popup();
  await expect(row(popup, "GitHub").locator(".tile.tile-logo svg")).toBeVisible();
  // A subdomain takes its parent's logo.
  await expect(row(popup, "Gist").locator(".tile.tile-logo svg")).toBeVisible();
  await expect(row(popup, "Visa").locator(".tile")).toHaveText("V");
  await expect(row(popup, "Panel interno").locator(".tile")).toHaveText("P");
  await popup.waitForTimeout(1_000);
  await expect(row(popup, "Panel interno").locator(".tile img")).toHaveCount(0);
  expect(site.favicons.filter((f) => f.host === other)).toEqual([]);
  await shoot(popup, shots, "iconos-popup");
  await popup.close();
});

test("on a page of the site, the menu shows the favicon the browser already has", async () => {
  const page = await browser.context.newPage();
  await page.goto(site.url("/login"));
  // The browser asked for it when it showed the page, as with any page.
  await expect.poll(() => site.favicons.some((f) => f.host.startsWith("localhost"))).toBe(true);
  const menu = await openMenu(page, page.locator("#username"));
  await expect(menu.locator(".choice .tile.tile-favicon img")).toBeVisible();
  await waitArmed(page);
  await shoot(page, shots, "iconos-menu");
  await page.close();
});

test("«Ask each site for its icon» asks the item's own site, without a referrer", async () => {
  const popup = await browser.popup();
  await popup.getByRole("button", { name: "Settings" }).click();
  const box = popup.getByRole("checkbox", { name: /Ask each site for its icon/ });
  await expect(box).not.toBeChecked();
  await box.click();
  await expect(popup.getByRole("status").filter({ hasText: "ask each site" })).toBeVisible();
  await shoot(popup, shots, "iconos-ajustes");
  await popup.getByRole("button", { name: "Your vault" }).first().click();
  await expect(row(popup, "Panel interno").locator(".tile.tile-favicon img")).toBeVisible();
  const asked = site.favicons.filter((f) => f.host === other);
  expect(asked.length).toBeGreaterThan(0);
  expect(asked.every((f) => f.referer === undefined)).toBe(true);
  // Logos Klav ships still win: GitHub is never asked.
  await expect(row(popup, "GitHub").locator(".tile.tile-logo svg")).toBeVisible();
  // Off again, for whoever runs next.
  await popup.getByRole("button", { name: "Settings" }).click();
  await popup.getByRole("checkbox", { name: /Ask each site for its icon/ }).click();
  await popup.close();
});
