/**
 * ADR 0025: a login saved for a subdomain (`my.app.localhost`) on the page
 * of its parent (`app.localhost`). The menu offers it apart, «Saved for a
 * subdomain», with the saved host in view; nothing fills it by itself, the
 * person's click does, and the save bar then offers «Add this site». After
 * that it matches exactly. On the subdomain itself, its own login comes
 * before the domain's, whatever the titles.
 */
import { resolve } from "node:path";
import { expect, test } from "@playwright/test";
import { type Browser, clickIn, frameOf, launch, openMenu, settled, shoot, startStack, type Stack, waitArmed, unlockInBrowser } from "./harness";
import { type Site, startSite } from "./site";

const shots = process.env.SCREENSHOTS === "1" ? resolve(import.meta.dirname, "..", "..", "..", "docs", "img", "extension") : undefined;
const SUB = "MARKER-subdominio";
const DOMAIN = "MARKER-dominio";
let stack: Stack;
let site: Site;
let browser: Browser;
const at = (host: string, path: string): string => `http://${host}:${String(site.port)}${path}`;

test.beforeAll(async () => {
  stack = await startStack();
  site = await startSite();
  // Titles in the opposite order of the relation, on purpose.
  stack.klav(["item", "add", "login", "--title", "Zeta", "--username", "ana", "--url", at("my.app.localhost", "/"), "--secret-stdin", "password"], {
    unlocked: true,
    stdin: `${SUB}\n`,
  });
  browser = await launch(stack);
  await unlockInBrowser(stack, browser);
});

test.afterAll(async () => {
  await browser.context.close();
  await site.close();
  stack.stop();
});

function urlsOf(title: string): string[] {
  const items = JSON.parse(stack.klav(["item", "ls", "--json"], { unlocked: true })) as { title: string; urls: string[] }[];
  return items.find((i) => i.title === title)?.urls ?? [];
}

test("offers a subdomain's login apart on its parent, fills it on click and adds the site", async () => {
  const page = await browser.context.newPage();
  await page.goto(at("app.localhost", "/login"));
  // Nothing is filled on load, and no card offers it by itself.
  await expect(page.locator("#password")).toHaveValue("");
  const menu = await openMenu(page, page.locator("#username"));
  await expect(menu.getByRole("heading", { name: "Saved for a subdomain" })).toBeVisible();
  const choice = menu.getByRole("button", { name: /Zeta/ });
  await expect(choice).toContainText("Saved for my.app.localhost");
  await expect(menu.getByText(/No Klav login is for/)).toHaveCount(0);
  expect(page.frames().some((f) => f.url().includes("/card.html"))).toBe(false);
  await waitArmed(page);
  await shoot(page, shots, "menu-subdominio");
  await clickIn(choice);
  await expect(page.locator("#username")).toHaveValue("ana");
  await expect(page.locator("#password")).toHaveValue(SUB);

  const bar = await frameOf(page, "/save.html");
  await expect(bar.getByText("Add app.localhost to this item?")).toBeVisible();
  await settled(bar);
  // The bar's «Add this site» goes through the same guard as «Save» (T62).
  await waitArmed(page);
  await shoot(page, shots, "anadir-sitio");
  await clickIn(bar.getByRole("button", { name: "Add this site" }));
  await expect(bar.getByText(/Added app\.localhost to Zeta/)).toBeVisible({ timeout: 40_000 });
  expect(urlsOf("Zeta")).toContain(at("app.localhost", ""));

  // Now it is a login of this page: in the main group.
  await page.goto(at("app.localhost", "/login"));
  const again = await openMenu(page, page.locator("#username"));
  await expect(again.getByRole("button", { name: /Zeta/ })).toBeVisible();
  await expect(again.getByRole("heading", { name: "Saved for a subdomain" })).toHaveCount(0);
  await page.close();
});

test("on the subdomain, its own login comes before the domain's", async () => {
  // Titles in the opposite order of the relation, on purpose.
  for (const [title, host, value] of [
    ["Zulu", "my.ord.localhost", SUB],
    ["Alpha", "ord.localhost", DOMAIN],
  ] as const) {
    stack.klav(["item", "add", "login", "--title", title, "--username", "bea", "--url", at(host, "/"), "--secret-stdin", "password"], {
      unlocked: true,
      stdin: `${value}\n`,
    });
  }
  const page = await browser.context.newPage();
  await page.goto(at("my.ord.localhost", "/login"));
  const menu = await openMenu(page, page.locator("#username"));
  await expect(menu.locator(".choice[data-id]").first()).toBeVisible();
  expect(await menu.locator(".choice[data-id] .row-title").allTextContents()).toEqual(["Zulu", "Alpha"]);
  await expect(menu.getByRole("heading", { name: "Saved for a subdomain" })).toHaveCount(0);

  // On the parent, the other way round: Alpha is exact, Zulu goes apart.
  await page.goto(at("ord.localhost", "/login"));
  const parent = await openMenu(page, page.locator("#username"));
  await expect(parent.getByRole("heading", { name: "Saved for a subdomain" })).toBeVisible();
  expect(await parent.locator(".choice[data-id] .row-title").allTextContents()).toEqual(["Alpha", "Zulu"]);
  await expect(parent.getByRole("button", { name: /Zulu/ })).toContainText("Saved for my.ord.localhost");
  await page.close();
});
