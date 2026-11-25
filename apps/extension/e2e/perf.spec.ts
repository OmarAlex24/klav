/**
 * How long the popup takes to show the vault, with a far server: 350
 * logins, and a proxy that adds `KLAV_PERF_RTT` ms (270 by default, about
 * Mexico to us-west2) to every round trip between klavd and klav-server.
 * Opt-in (`KLAV_PERF=1 pnpm e2e perf`): it waits past klavd's sync
 * interval several times. Prints a table; `KLAV_PERF_OUT` also writes it
 * as JSON.
 */
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { expect, type Page, test } from "@playwright/test";
import { type Browser, launch, type Stack, startStack, unlockInBrowser } from "./harness";

const RTT = Number(process.env.KLAV_PERF_RTT ?? "270");
const ITEMS = 350;
const RUNS = Number(process.env.KLAV_PERF_RUNS ?? "5");
/** klavd syncs reads older than this (SYNC_AFTER). */
const STALE_MS = 31_000;

test.skip(process.env.KLAV_PERF !== "1", "set KLAV_PERF=1 to measure");
test.describe.configure({ timeout: 15 * 60_000 });

let stack: Stack | undefined;
let browser: Browser | undefined;

function running(): { stack: Stack; browser: Browser } {
  if (!stack || !browser) throw new Error("the stack did not start");
  return { stack, browser };
}
const results: Record<string, number[]> = {};

function record(name: string, ms: number): void {
  (results[name] ??= []).push(Math.round(ms));
}

function median(values: number[]): number {
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.floor(sorted.length / 2)] ?? NaN;
}

test.beforeAll(async () => {
  stack = await startStack({ latency: true });
  // Throwaway logins in Chrome's export format, imported in one go.
  const rows = ["name,url,username,password,note"];
  for (let i = 0; i < ITEMS; i++) {
    rows.push(`Site ${String(i).padStart(3, "0")},https://site${String(i)}.example.com/login,user${String(i)},pw-${String(i)}-${Math.random().toString(36).slice(2)},`);
  }
  const csv = join(stack.dir, "logins.csv");
  writeFileSync(csv, `${rows.join("\n")}\n`);
  stack.klav(["import", "--from", "chrome", csv], { unlocked: true });
  browser = await launch(stack);
  await unlockInBrowser(stack, browser);
  await stack.latency?.set(RTT / 2);
});

test.afterAll(async () => {
  const out = [`\nPopup timings, RTT ${String(RTT)} ms, ${String(ITEMS)} items (ms; median of each):`];
  for (const [name, values] of Object.entries(results)) {
    out.push(`  ${name.padEnd(34)} ${String(median(values)).padStart(6)}   [${values.join(", ")}]`);
  }
  process.stdout.write(`${out.join("\n")}\n`);
  if (process.env.KLAV_PERF_OUT) writeFileSync(process.env.KLAV_PERF_OUT, JSON.stringify({ rtt: RTT, items: ITEMS, results }, null, 2));
  await browser?.context.close();
  stack?.stop();
});

/** Opens the popup and returns when its vault rows showed, in ms since navigation. */
async function openPopup(): Promise<{ page: Page; rows: number }> {
  const page = await running().browser.popup();
  await expect(page.locator(".list .row").first()).toBeVisible({ timeout: 30_000 });
  const rows = await page.evaluate(() => performance.getEntriesByName("klav:rows")[0]?.startTime ?? NaN);
  return { page, rows };
}

test("the native host's cold start", async () => {
  // A fresh port starts a fresh klav-native-host: the first answer pays
  // for the process, the second only for the trip.
  for (let i = 0; i < RUNS; i++) {
    const [cold, warm] = await running().browser.worker.evaluate(async () => {
      const port = chrome.runtime.connectNative("dev.klav.host");
      const ask = (id: number): Promise<number> =>
        new Promise((done) => {
          const start = performance.now();
          const listener = (message: { id?: number }): void => {
            if (message.id !== id) return;
            port.onMessage.removeListener(listener);
            done(performance.now() - start);
          };
          port.onMessage.addListener(listener);
          port.postMessage({ v: 1, id, request: { op: "status" } });
        });
      const first = await ask(1);
      const second = await ask(2);
      port.disconnect();
      return [first, second];
    });
    record("host: first status (cold)", cold);
    record("host: second status (warm)", warm);
  }
});

test("the popup with a fresh local copy", async () => {
  running().stack.klav(["sync"]);
  for (let i = 0; i < RUNS; i++) {
    const { page, rows } = await openPopup();
    record("popup rows, copy < 30 s old", rows);
    await page.close();
  }
});

test("the popup when klavd's copy is older than 30 s", async () => {
  for (let i = 0; i < RUNS; i++) {
    await new Promise((r) => setTimeout(r, STALE_MS));
    const { page, rows } = await openPopup();
    record("popup rows, copy > 30 s old", rows);
    await page.close();
  }
});

test("a search typed as soon as the vault shows", async () => {
  // What the person does most: open, type. The answer must not wait on
  // the requests to the server that follow the first paint (agents').
  for (let i = 0; i < RUNS; i++) {
    await new Promise((r) => setTimeout(r, 4_000));
    const { page } = await openPopup();
    const start = Date.now();
    await page.getByRole("searchbox").fill(`Site ${String(100 + i)}`);
    await expect(page.locator(".list .row-title").first()).toHaveText(`Site ${String(100 + i)}`, { timeout: 30_000 });
    record("search right after the first paint", Date.now() - start);
    await page.close();
  }
});
