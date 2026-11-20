import { resolve } from "node:path";
import { expect, test } from "@playwright/test";
import { type Browser, frameOf, KLAV_BIN, launch, PASSWORD, registerAgent, shoot, type Stack, startStack, unlockForm } from "./harness";
import { McpClient } from "./mcp";
import { type Site, startSite } from "./site";

const shots = process.env.SCREENSHOTS === "1" ? resolve(import.meta.dirname, "..", "..", "..", "docs", "img", "extension") : undefined;
const SECRET = "MARKER-agente-sitio";
let stack: Stack;
let site: Site;
let browser: Browser;
const clients: McpClient[] = [];

test.beforeAll(async () => {
  stack = await startStack();
  site = await startSite();
  stack.klav(
    ["item", "add", "login", "--title", "Sitio local", "--username", "ana", "--url", site.url("/"), "--secret-stdin", "password"],
    { unlocked: true, stdin: `${SECRET}\n` },
  );
  browser = await launch(stack);
});

test.afterAll(async () => {
  for (const c of clients) c.close();
  await browser.context.close();
  await site.close();
  stack.stop();
});

function mcpFor(agent: { home: string; repo: string }): McpClient {
  const client = new McpClient(KLAV_BIN, agent.repo, {
    KLAV_HOME: agent.home,
    // The person's klavd, where the browser is attached.
    KLAV_BROWSER_HOME: stack.home,
    KLAV_NO_TOUCH_ID: "1",
  });
  clients.push(client);
  return client;
}

/** The extension attaches when the browser starts; give it a moment. */
async function fillWhenAttached(mcp: McpClient, args: Record<string, unknown>): Promise<{ text: string; isError: boolean }> {
  for (let i = 0; i < 30; i++) {
    const result = await mcp.tool("fill_login", args);
    if (!result.isError || !/no browser with Klav's extension|klavd, with the person's browser/.test(result.text)) return result;
    await new Promise((r) => setTimeout(r, 300));
  }
  throw new Error("the extension never attached to klavd");
}

test("an agent fills the open tab through the extension and never sees the password", async () => {
  const agent = registerAgent(stack, "claude-code");
  const page = await browser.context.newPage();
  await page.goto(site.url("/login"));
  await page.bringToFront();
  const mcp = mcpFor(agent);
  await mcp.initialize();
  const result = await fillWhenAttached(mcp, { ref: "Sitio local", target: "extension", reason: "entrar para revisar la CI" });
  expect(result.isError, result.text).toBe(false);
  expect(result.text).toContain("password");
  await expect(page.locator("#username")).toHaveValue("ana");
  await expect(page.locator("#password")).toHaveValue(SECRET);
  // The person sees who filled and why.
  const notice = await frameOf(page, "/notice.html");
  await expect(notice.getByText("Klav filled this page for “claude-code” (the name the agent gave)")).toBeVisible();
  await expect(notice.getByText("“entrar para revisar la CI”")).toBeVisible();
  await shoot(page, shots, "aviso-agente");
  // The value never reached the agent.
  expect(mcp.seen.join("\n")).not.toContain(SECRET);
  // And it is in the audit log as a fill on that host.
  const log = stack.klav(["log", "--json"], { unlocked: true });
  expect(log).toContain("claude-code");
  expect(log).toContain("localhost");
  await page.close();
});

test("an agent cannot fill a look-alike address", async () => {
  const agent = registerAgent(stack, "otro-agente");
  const page = await browser.context.newPage();
  await page.goto(site.lookAlike("/login"));
  await page.bringToFront();
  const mcp = mcpFor(agent);
  await mcp.initialize();
  const result = await fillWhenAttached(mcp, { ref: "Sitio local", target: "extension", reason: "entrar" });
  expect(result.isError).toBe(true);
  expect(result.text).toContain("not one of the item's addresses");
  await expect(page.locator("#password")).toHaveValue("");
  expect(mcp.seen.join("\n")).not.toContain(SECRET);
  await page.close();
});

test("a fill that needs approval is approved from the popup", async () => {
  const agent = registerAgent(stack, "ayudante", ["--ask", "fill"]);
  const page = await browser.context.newPage();
  await page.goto(site.url("/login"));
  await page.bringToFront();
  const mcp = mcpFor(agent);
  await mcp.initialize();
  const pending = fillWhenAttached(mcp, { ref: "Sitio local", target: "extension", reason: "iniciar sesión para descargar la factura", wait_seconds: 90 });

  // In tests the popup is a tab: open it only once the agent has looked at
  // the active tab and is waiting for the person.
  await expect
    .poll(() => (JSON.parse(stack.klav(["approval", "list", "--json"], { unlocked: true })) as unknown[]).length, { timeout: 20_000 })
    .toBe(1);
  const popup = await browser.popup();
  const locked = popup.getByRole("heading", { name: "Klav is locked" });
  await expect(locked.or(popup.getByText("Your vault"))).toBeVisible();
  if (await locked.isVisible()) {
    await unlockForm(popup);
  }
  await expect(popup.getByText("ayudante is waiting for your permission")).toBeVisible({ timeout: 20_000 });
  await expect(popup.getByText("“iniciar sesión para descargar la factura”")).toBeVisible();
  await expect(popup.getByRole("button", { name: /^Sitio local/ }).first()).toBeVisible();
  await shoot(popup, shots, "popup-aprobacion");
  await popup.getByRole("button", { name: "Approve" }).click();
  await popup.getByLabel("Master password to approve").fill(PASSWORD);
  await popup.getByRole("button", { name: "Confirm" }).click();
  await expect(popup.getByText("ayudante is waiting for your permission")).toBeHidden({ timeout: 15_000 });

  const result = await pending;
  expect(result.isError, result.text).toBe(false);
  await expect(page.locator("#password")).toHaveValue(SECRET);
  expect(mcp.seen.join("\n")).not.toContain(SECRET);
  await popup.close();
  await page.close();
});
