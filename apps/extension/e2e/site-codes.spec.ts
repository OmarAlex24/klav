/**
 * «Codes» starts with the page's codes: those of its logins and the codes
 * saved on their own whose issuer names its site (klavd's `suggest`,
 * `codes`), under «On <host>», and nothing up there repeats in the list
 * below. A page without codes shows the tab as before, and a page cannot
 * steer the match with the labels before its own domain.
 */
import { expect, type Page, test } from "@playwright/test";
import { type Browser, launch, type Stack, startStack } from "./harness";
import { type Site, startSite } from "./site";

/** Example seeds (RFC 6238-style test values), never real accounts. */
const SEEDS = ["JBSWY3DPEHPK3PXP", "GEZDGNBVGY3TQOJQ", "MFRGGZDFMZTWQ2LK", "KRSXG5CTMVRXEZLU", "ONSWG4TFOQZDGNBV"];
let stack: Stack | undefined;
let site: Site | undefined;
let browser: Browser | undefined;

function running(): { stack: Stack; site: Site; browser: Browser } {
  if (!stack || !site || !browser) throw new Error("the stack did not start");
  return { stack, site, browser };
}
const at = (host: string, path: string): string => `http://${host}:${String(running().site.port)}${path}`;

test.beforeAll(async () => {
  const mine = await startStack();
  stack = mine;
  site = await startSite();
  const add = (args: string[], stdin = ""): void => {
    mine.klav(["item", "add", ...args], { unlocked: true, stdin });
  };
  // The page's login, with its code.
  const acme = `http://acme.localhost:${String(site.port)}/`;
  add(["login", "--title", "Acme", "--username", "ana", "--url", acme, "--secret-stdin", "password", "--secret-stdin", "totp"], `MARKER-acme\n${SEEDS[0]}\n`);
  // A code on its own whose title does not name the site: its issuer does.
  add(["totp", "--title", "Second factor", "--secret-stdin", "totp"], `otpauth://totp/ana?secret=${SEEDS[1]}&issuer=Acme\n`);
  // Another site's code and another site's login with a code: below.
  add(["totp", "--title", "Globex", "--secret-stdin", "totp"], `${SEEDS[2]}\n`);
  add(["login", "--title", "Initech", "--username", "ana", "--url", "https://initech.example", "--secret-stdin", "password", "--secret-stdin", "totp"], `MARKER-initech\n${SEEDS[3]}\n`);
  // A login with a code saved for a subdomain of hooli.localhost (ADR 0025).
  const hooli = `http://my.hooli.localhost:${String(site.port)}/`;
  add(["login", "--title", "Hooli", "--username", "ana", "--url", hooli, "--secret-stdin", "password", "--secret-stdin", "totp"], `MARKER-hooli\n${SEEDS[4]}\n`);
  mine.klav(["unlock"], { unlocked: true });
  browser = await launch(mine);
});

// Everything started is stopped, also when the start failed halfway.
test.afterAll(async () => {
  await browser?.context.close();
  await site?.close();
  stack?.stop();
});

/** The popup in a tab behind `url`, which stays the active tab. */
async function popupOn(url: string): Promise<{ page: Page; popup: Page }> {
  const { browser } = running();
  const page = await browser.context.newPage();
  await page.goto(url);
  const popup = await browser.context.newPage();
  await page.bringToFront();
  await popup.setViewportSize({ width: 360, height: 560 });
  await popup.goto(browser.extensionUrl("popup.html"));
  return { page, popup };
}

test("«Codes» shows the page's codes first, and not again below", async () => {
  const { page, popup } = await popupOn(at("acme.localhost", "/login"));
  // «All» as before: the page's login with its code, the code on its own in the list.
  await expect(popup.getByRole("heading", { name: "On acme.localhost" })).toBeVisible();
  await expect(popup.getByRole("group", { name: "One-time code for Acme" })).toContainText(/^\d{3} \d{3}$/);
  await expect(popup.locator(".list .row-title").filter({ hasText: "Second factor" })).toHaveCount(1);

  await popup.getByRole("tab", { name: "Codes, 5" }).click();
  const top = popup.locator("section", { has: popup.getByRole("heading", { name: "On acme.localhost" }) });
  const below = popup.locator("section", { has: popup.getByRole("heading", { name: "Codes", exact: true }) });
  await expect(top.locator(".code-row .row-title")).toHaveText(["Acme", "Second factor"]);
  for (const code of await top.locator(".code").all()) await expect(code).toHaveText(/^\d{3} \d{3}$/);
  await expect(below.locator(".code-row .row-title")).toHaveText(["Globex", "Hooli", "Initech"]);
  // One row per code in the whole tab.
  await expect(popup.locator(".code-row")).toHaveCount(5);
  // Nothing but codes on screen: no password left the vault.
  expect(await popup.content()).not.toContain("MARKER-");

  // A search narrows the list below; the page's codes stay up top.
  await popup.getByLabel("Search your vault").fill("glob");
  await expect(below.locator(".code-row .row-title")).toHaveText(["Globex"]);
  await expect(top.locator(".code-row .row-title")).toHaveText(["Acme", "Second factor"]);
  // Every match is up top: no list, and no «No codes yet» under them.
  await popup.getByLabel("Search your vault").fill("acme");
  await expect(top.locator(".code-row .row-title")).toHaveText(["Acme", "Second factor"]);
  await expect(below).toBeHidden();
  await expect(popup.getByText("No one-time codes yet.")).toHaveCount(0);

  // Back to «All»: as before.
  await popup.getByLabel("Search your vault").fill("");
  await popup.getByRole("tab", { name: "All, 5" }).click();
  await expect(popup.getByRole("button", { name: "Fill Acme" })).toBeVisible();
  await expect(popup.locator(".code-row")).toHaveCount(0);
  await popup.close();
  await page.close();
});

test("on a page without codes, «Codes» is the list it always was", async () => {
  // On hooli.localhost, Hooli is a login saved for a subdomain (ADR 0025):
  // offered apart in «All», never filled by itself. Its code stays in the
  // list, as in «All», so this page has no codes up top.
  const { page, popup } = await popupOn(at("hooli.localhost", "/login"));
  await expect(popup.getByRole("heading", { name: "Saved for a subdomain" })).toBeVisible();
  await expect(popup.getByRole("button", { name: "Copy code for Hooli" })).toBeVisible();
  await popup.getByRole("tab", { name: "Codes, 5" }).click();
  await expect(popup.locator(".code-row .row-title")).toHaveText(["Acme", "Globex", "Hooli", "Initech", "Second factor"]);
  await expect(popup.getByRole("heading", { name: /^On / })).toHaveCount(0);
  await popup.close();
  await page.close();
});

test("a page that puts the site's name before its own domain gets none of its codes", async () => {
  // acme.evil.localhost chooses the label «acme»: only its last two labels
  // (evil.localhost) count, so neither Acme's login nor «Second factor»
  // (issued by «Acme») goes up top.
  const { page, popup } = await popupOn(at("acme.evil.localhost", "/login"));
  await popup.getByRole("tab", { name: "Codes, 5" }).click();
  await expect(popup.locator(".code-row")).toHaveCount(5);
  await expect(popup.getByRole("heading", { name: /^On / })).toHaveCount(0);
  await popup.close();
  await page.close();
});
