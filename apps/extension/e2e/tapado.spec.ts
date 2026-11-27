// Layer 09 (T62): a page that covers Klav's menu with an overlay that
// lets clicks through (`pointer-events: none`) and a decoy, or that keeps
// restyling Klav's host, gets nothing filled; Klav says the page covers it.
// And a page that leaves the menu alone still gets it filled: with another
// extension's node after Klav's host from before the menu opened, or in a
// window too short for the whole menu on either side of the field.
import { expect, type Page, test } from "@playwright/test";
import { type Browser, clickIn, launch, openMenu, startStack, type Stack, waitArmed, unlockInBrowser } from "./harness";
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
  await unlockInBrowser(stack, browser);
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

test("another extension's node after Klav's host, from before the menu opened, does not block filling", async () => {
  const page = await browser.context.newPage();
  await page.goto(site.url("/login"));
  // Klav's host comes with the glyph, on the first focus.
  await page.locator("#password").click();
  await page.evaluate(() => {
    // What another extension appends to <html>, with a closed shadow root, after Klav's host.
    const other = document.createElement("other-extension");
    other.style.cssText = "position:fixed;left:0;top:0;width:24px;height:24px;z-index:2147483647";
    other.attachShadow({ mode: "closed" });
    document.documentElement.append(other);
  });
  const menu = await openMenu(page, page.locator("#username"));
  const choice = menu.getByRole("button", { name: /Sitio local/ });
  await expect(choice).toBeVisible();
  await waitArmed(page);
  await clickIn(choice);
  await expect(page.locator("#password")).toHaveValue(SECRET);
  await expect(page.locator("other-extension")).toHaveCount(1);
});

test("a menu in a window too short for all of it fills, its list scrolling inside", async () => {
  const page = await browser.context.newPage();
  await page.setViewportSize({ width: 800, height: 300 });
  await page.goto(site.url("/login"));
  // The field a little above the middle: more room below, but not for the whole menu.
  await page.evaluate(() => {
    const field = document.getElementById("username");
    const main = document.querySelector("main");
    if (!field || !main) throw new Error("no form");
    const r = field.getBoundingClientRect();
    const top = (innerHeight - r.height) / 2 - 8;
    main.style.marginTop = `${String(56 + top - r.top)}px`;
  });
  const menu = await openMenu(page, page.locator("#username"));
  const choice = menu.getByRole("button", { name: /Sitio local/ });
  await expect(choice).toBeVisible();
  const frame = await menu.frameElement();
  await expect.poll(async () => (await frame.boundingBox())?.height ?? 0).toBeGreaterThan(40);
  const box = await frame.boundingBox();
  expect(box && box.y + box.height).toBeLessThanOrEqual(300);
  // Taller than the room: it scrolls inside instead of going past the window.
  expect(await menu.evaluate(() => document.body.scrollHeight > innerHeight)).toBe(true);
  await waitArmed(page);
  // Enter on the row: a trusted click that goes through the same guards. A
  // mouse click here can reach the page instead: right after the frame
  // grows from its first 64 px into a box that scrolls, Chromium may still
  // route pointer events by the old size (seen locally with and without
  // this change).
  await choice.focus();
  await page.keyboard.press("Enter");
  await expect(menu.getByText(COVERED)).toHaveCount(0);
  await expect(page.locator("#password")).toHaveValue(SECRET);
});
