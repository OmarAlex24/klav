// Layer 09 (T62): a page that covers Klav's menu with an overlay that
// lets clicks through (`pointer-events: none`) and a decoy, or that keeps
// restyling Klav's host, gets nothing filled; Klav says the page covers it.
import { expect, type Page, test } from "@playwright/test";
import { type Browser, clickIn, launch, openMenu, startStack, type Stack, waitArmed } from "./harness";
import { type Site, startSite } from "./site";

const SECRET = "MARKER-tapado";
const COVERED = "The page is covering part of this box.";
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
  browser = await launch(stack);
  stack.klav(["unlock"], { unlocked: true });
});

test.afterAll(async () => {
  await browser.context.close();
  await site.close();
  stack.stop();
});

async function menuOn(page: Page) {
  await page.goto(site.url("/login"));
  const menu = await openMenu(page, page.locator("#username"));
  const choice = menu.getByRole("button", { name: /Sitio local/ });
  await expect(choice).toBeVisible();
  return { menu, choice };
}

test("an overlay that lets the click through, with a decoy, fills nothing", async () => {
  const page = await browser.context.newPage();
  const { menu, choice } = await menuOn(page);
  await page.evaluate(() => {
    // Over everything, after Klav's host: the person sees the decoy, the click reaches Klav.
    const veil = document.createElement("div");
    veil.style.cssText = "position:fixed;inset:0;z-index:2147483647;pointer-events:none;background:#fff;display:grid;place-items:center";
    veil.textContent = "¡Haz clic para ganar un premio!";
    document.documentElement.append(veil);
  });
  await waitArmed(page);
  await clickIn(choice);
  await expect(menu.getByText(COVERED)).toBeVisible();
  await expect(page.locator("#password")).toHaveValue("");
});

test("a page that keeps moving Klav's host fills nothing", async () => {
  const page = await browser.context.newPage();
  const { menu, choice } = await menuOn(page);
  await page.evaluate(() => {
    const host = document.querySelector("klav-ui");
    if (host instanceof HTMLElement) {
      setInterval(() => {
        host.style.setProperty("transform", "translate(0px, 0px) scale(1.0001)", "important");
      }, 50);
    }
  });
  await waitArmed(page);
  await clickIn(choice);
  await expect(menu.getByText(COVERED)).toBeVisible();
  await expect(page.locator("#password")).toHaveValue("");
});

test("a transform on <html> fills nothing", async () => {
  const page = await browser.context.newPage();
  const { menu, choice } = await menuOn(page);
  await page.evaluate(() => {
    document.documentElement.style.transform = "translate(1px, 1px)";
  });
  await waitArmed(page);
  await clickIn(choice);
  await expect(menu.getByText(COVERED)).toBeVisible();
  await expect(page.locator("#password")).toHaveValue("");
});
