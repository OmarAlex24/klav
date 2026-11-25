// The presence gate in the browser (ADR 0041, layer 4; on by default since
// layer 6): with klavd started with Touch ID off, an agent's first fill through
// the extension asks for the master password in Klav's own frame, and with
// a second browser connection attached, values go only when exactly one
// connection reports focus, the one that gets them (P25).
import { type ChildProcess, spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { createConnection, type Socket } from "node:net";
import { join } from "node:path";
import { expect, type Page, test } from "@playwright/test";
import { type Agent, type Browser, clickIn, frameOf, KLAV_BIN, launch, openMenu, PASSWORD, registerAgent, type Stack, startStack, unlockForm, waitArmed } from "./harness";
import { McpClient } from "./mcp";
import { type Site, startSite } from "./site";

const SECRET = "MARKER-presencia-sitio";
let stack: Stack;
let site: Site;
let browser: Browser;
let klavd: ChildProcess | undefined;
let agent: Agent;
const clients: McpClient[] = [];

/** klavd for the stack's home again, now with Touch ID off, unlocked with the master password. */
async function gatedKlavd(): Promise<ChildProcess> {
  stack.klav(["lock", "--stop"]);
  const socket = join(stack.home, "klavd.sock");
  await expect.poll(() => existsSync(socket), { timeout: 10_000 }).toBe(false);
  const child = spawn(join(stack.dir, "bin", "klavd"), ["--no-touch-id", "--idle-lock", "10m"], {
    env: { ...process.env, KLAV_HOME: stack.home, KLAV_NO_DEFAULT_SERVER: "1" },
    stdio: "ignore",
  });
  await expect.poll(() => existsSync(socket), { timeout: 30_000 }).toBe(true);
  stack.klav(["unlock"], { unlocked: true });
  return child;
}

test.beforeAll(async () => {
  stack = await startStack();
  site = await startSite();
  stack.klav(
    ["item", "add", "login", "--title", "Sitio local", "--username", "ana", "--url", site.url("/"), "--secret-stdin", "password"],
    { unlocked: true, stdin: `${SECRET}\n` },
  );
  agent = registerAgent(stack, "claude-code");
  klavd = await gatedKlavd();
  browser = await launch(stack);
});

test.afterAll(async () => {
  for (const c of clients) c.close();
  await browser.context.close();
  await site.close();
  stack.stop();
  klavd?.kill();
});

async function mcp(): Promise<McpClient> {
  const client = new McpClient(KLAV_BIN, agent.repo, { KLAV_HOME: agent.home, KLAV_BROWSER_HOME: stack.home, KLAV_NO_TOUCH_ID: "1" });
  clients.push(client);
  await client.initialize();
  return client;
}

/** The extension attaches when the browser starts; give it a moment. */
async function fill(client: McpClient): Promise<{ text: string; isError: boolean }> {
  for (let i = 0; i < 30; i++) {
    const result = await client.tool("fill_login", { ref: "Sitio local", target: "extension", reason: "entrar para revisar la CI" });
    if (!result.isError || !/no browser with Klav's extension|klavd, with the person's browser/.test(result.text)) return result;
    await new Promise((r) => setTimeout(r, 300));
  }
  throw new Error("the extension never attached to klavd");
}

/** The login page, in front. */
async function loginPage(): Promise<Page> {
  const page = await browser.context.newPage();
  await page.goto(site.url("/login"));
  await page.bringToFront();
  return page;
}

/**
 * Another browser with Klav's extension, as klavd sees it: a raw
 * connection to its socket that attaches and answers each `tab` with the
 * focus the test gives it. It never gets a value: klavd only sends values to the tab the
 * agent picked, in the real browser.
 */
class OtherBrowser {
  /** What it answers to the next `tab` events, in order; then `false`. */
  answers: boolean[] = [];
  readonly kinds: string[] = [];
  private constructor(private readonly socket: Socket) {}

  static async attach(): Promise<OtherBrowser> {
    const socket = createConnection(join(stack.home, "klavd.sock"));
    await new Promise<void>((ok, fail) => {
      socket.once("connect", ok);
      socket.once("error", fail);
    });
    const other = new OtherBrowser(socket);
    let buffer = "";
    socket.on("data", (chunk) => {
      buffer += chunk.toString("utf8");
      for (let at = buffer.indexOf("\n"); at >= 0; at = buffer.indexOf("\n")) {
        const line = JSON.parse(buffer.slice(0, at)) as { event?: { id: number; kind: string } };
        buffer = buffer.slice(at + 1);
        if (!line.event) continue;
        other.kinds.push(line.event.kind);
        const reply =
          line.event.kind === "tab"
            ? { ok: { tab_id: 1, url: "https://elsewhere.example", focused: other.answers.shift() ?? false } }
            : { error: { code: "denied", message: "not in this test" } };
        other.send({ op: "extension_reply", event: line.event.id, ...reply });
      }
    });
    other.send({ op: "extension_attach", browser: "Firefox" });
    return other;
  }

  private next = 1;
  send(request: Record<string, unknown>): void {
    this.socket.write(`${JSON.stringify({ v: 1, id: this.next++, request })}\n`);
  }

  close(): void {
    this.socket.destroy();
  }
}

test("an agent's first fill asks for the master password in Klav's frame, never in the page", async () => {
  const page = await loginPage();
  const client = await mcp();
  const pending = fill(client);
  const frame = await frameOf(page, "/passkey.html");
  await expect(frame.getByText("Confirm it’s you")).toBeVisible();
  // Klav's frames ignore what happens before they have been seen (T62).
  await waitArmed(page);
  await expect(frame.getByText(/^Klav wants to let agents fill (in a browser|through this browser connection) until Klav locks, starting with “claude-code”'s fill of “Sitio local”\.$/)).toBeVisible();
  // A wrong password asks again, in the same frame; nothing is filled.
  await frame.getByLabel("Master password, to confirm").fill("not the password");
  await frame.getByRole("button", { name: "Confirm" }).click();
  await expect(frame.getByRole("alert")).toBeVisible();
  await expect(page.locator("#password")).toHaveValue("");
  await frame.getByLabel("Master password, to confirm").fill(PASSWORD);
  await frame.getByRole("button", { name: "Confirm" }).click();
  const result = await pending;
  expect(result.isError, result.text).toBe(false);
  await expect(page.locator("#password")).toHaveValue(SECRET);
  expect(client.seen.join("\n")).not.toContain(SECRET);
  // Until Klav locks, this connection doesn't ask again.
  await page.locator("#password").fill("");
  const again = await fill(client);
  expect(again.isError, again.text).toBe(false);
  await expect(page.locator("#password")).toHaveValue(SECRET);
  expect(page.frames().some((f) => f.url().includes("/passkey.html"))).toBe(false);
  await page.close();
});

/** Whether this browser reports focus: minimized, it doesn't; restored, it does. */
async function front(focused: boolean): Promise<void> {
  await browser.worker.evaluate(async (focused) => {
    const win = await chrome.windows.getLastFocused({});
    if (win.id !== undefined && win.focused !== focused) {
      await chrome.windows.update(win.id, focused ? { state: "normal", focused: true } : { state: "minimized" });
    }
  }, focused);
  // The window manager takes a moment.
  await expect.poll(() => browser.worker.evaluate(async () => (await chrome.windows.getLastFocused({})).focused), { timeout: 5_000 }).toBe(focused);
}

test("with two browsers attached, values go only when exactly one is in front, the one with the tab", async () => {
  const page = await loginPage();
  const client = await mcp();
  const other = await OtherBrowser.attach();
  const ambiguous = "more than one browser is connected to Klav, and not exactly one of them is in front";
  // [this browser, the other at `browser_tab`, the other right before the fill]
  const cases: [boolean, boolean, boolean, "filled" | "ambiguous" | "elsewhere"][] = [
    // Unfocused first: once a test focused a window, minimizing it no
    // longer unfocuses it in headless Chromium.
    [false, false, false, "ambiguous"], // neither
    [false, true, true, "elsewhere"], // one: the other browser, so the agent's tab is there
    [true, true, true, "ambiguous"], // both
    [true, false, true, "ambiguous"], // one at first, both right before the fill
    [true, false, false, "filled"], // one: this one
  ];
  try {
    for (const [mine, atTab, atFill, outcome] of cases) {
      await front(mine);
      other.answers = [atTab, atFill];
      await page.locator("#password").fill("");
      const result = await fill(client);
      const label = `${String(mine)} ${String(atTab)} ${String(atFill)}`;
      if (outcome === "filled") {
        expect(result.isError, `${label}: ${result.text}`).toBe(false);
        await expect(page.locator("#password")).toHaveValue(SECRET);
      } else {
        expect(result.isError, label).toBe(true);
        expect(result.text, label).toContain(outcome === "ambiguous" ? ambiguous : "the active tab is on elsewhere.example");
        await expect(page.locator("#password")).toHaveValue("");
      }
    }
    // The other browser was only ever asked which tab is in front.
    expect(new Set(other.kinds)).toEqual(new Set(["tab"]));
  } finally {
    other.close();
    await front(true);
  }
  expect(client.seen.join("\n")).not.toContain(SECRET);
  await page.close();
});

test("the person's own fill asks once in Klav's frame, and a password unlock opens what it says", async () => {
  const page = await loginPage();
  const fillFromMenu = async (): Promise<void> => {
    // A fresh page each time: after a fill the field's menu stays closed.
    await page.reload();
    const menu = await openMenu(page, page.locator("#username"));
    const choice = menu.getByRole("button", { name: /Sitio local/ });
    await expect(choice).toBeVisible();
    await waitArmed(page);
    await clickIn(choice);
  };

  // No window for this browser yet (the CLI's unlock opened none for it):
  // the fill asks in Klav's frame, never in the page.
  await fillFromMenu();
  const frame = await frameOf(page, "/passkey.html");
  await expect(frame.getByText("Klav wants to let this browser use your vault for 5 minutes.")).toBeVisible();
  await waitArmed(page);
  await frame.getByLabel("Master password, to confirm").fill(PASSWORD);
  await frame.getByRole("button", { name: "Confirm" }).click();
  await expect(page.locator("#password")).toHaveValue(SECRET);

  // Within the window: no question.
  await fillFromMenu();
  await expect(page.locator("#password")).toHaveValue(SECRET);
  expect(page.frames().some((f) => f.url().includes("/passkey.html"))).toBe(false);

  // Locked, the menu's unlock says what the password also opens, and opens
  // it (`shown`): the next fill asks nothing.
  stack.klav(["lock"]);
  await page.reload();
  const menu = await openMenu(page, page.locator("#username"));
  await expect(menu.getByText("Unlocking also lets this browser use your vault for 5 minutes.")).toBeVisible();
  await unlockForm(menu);
  const choice = menu.getByRole("button", { name: /Sitio local/ });
  await expect(choice).toBeVisible();
  await waitArmed(page);
  await clickIn(choice);
  await expect(page.locator("#password")).toHaveValue(SECRET);
  expect(page.frames().some((f) => f.url().includes("/passkey.html"))).toBe(false);
  await page.close();
});
