// An agent logs in to a site with Playwright and Klav (docs/probar-hito-a.md).
//
//   LOGIN_URL=https://example.com/login ITEM=klav://Personal/Web/Example npm start
//   (CHROME=/path/to/chrome to use an installed browser, HEADLESS=0 to see it)
//
// The agent must be registered and approved (`klav agent register`,
// `klav agent approve` with `fill` allowed for the site). The browser opens
// a CDP port on 127.0.0.1 so `klav` can type into it; this script only
// passes the item reference and the reason.

import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { chromium } from "playwright";
import { fill } from "@klav/sdk";

const url = process.env.LOGIN_URL;
const item = process.env.ITEM;
if (!url || !item) {
  console.error("set LOGIN_URL and ITEM (klav://Vault/Project/Item)");
  process.exit(2);
}

// A private profile and a CDP port the OS picks: never another browser's
// port (9222 is often taken by a browser you use every day).
const profile = await mkdtemp(join(tmpdir(), "klav-playwright-"));
const context = await chromium.launchPersistentContext(profile, {
  headless: process.env.HEADLESS !== "0",
  // Optional: an installed Chrome, if Playwright's own build is missing.
  executablePath: process.env.CHROME || undefined,
  args: ["--remote-debugging-port=0", "--remote-debugging-address=127.0.0.1"],
});
try {
  const port = (await readFile(join(profile, "DevToolsActivePort"), "utf8")).split("\n")[0];
  const cdp = `http://127.0.0.1:${port}`;
  const page = context.pages()[0] ?? (await context.newPage());
  await page.goto(url);

  // Username and password go from Klav to the page; nothing comes back.
  await fill(page, item, { cdp, reason: "log in to run the nightly report" });
  await Promise.all([page.waitForEvent("load"), page.keyboard.press("Enter")]);
  console.log(`logged in: ${await page.title()}`);
} finally {
  await context.close();
  await rm(profile, { recursive: true, force: true });
}
