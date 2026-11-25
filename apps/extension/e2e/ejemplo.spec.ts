/**
 * The site of the manual guide (examples/sitio-extension, docs/probar-fase-5.md):
 * cards and addresses filled from the menu, with the items the guide creates,
 * and the guide's agent step (the agent in the person's own KLAV_HOME).
 */
import { type ChildProcess, spawn } from "node:child_process";
import { resolve } from "node:path";
import { expect, test } from "@playwright/test";
import { type Browser, clickIn, freePort, launch, openMenu, PASSWORD, shoot, startStack, type Stack, waitArmed, unlockInBrowser, confirmPresence } from "./harness";

const shots = process.env.SCREENSHOTS === "1" ? resolve(import.meta.dirname, "..", "..", "..", "docs", "img", "extension") : undefined;
const SERVER = resolve(import.meta.dirname, "..", "..", "..", "examples", "sitio-extension", "server.mjs");
let stack: Stack;
let browser: Browser;
let site: ChildProcess;
let base: string;

test.beforeAll(async () => {
  stack = await startStack();
  const port = await freePort();
  base = `http://localhost:${String(port)}`;
  site = spawn(process.execPath, [SERVER], { env: { ...process.env, PORT: String(port) }, stdio: "ignore" });
  await expect.poll(() => fetch(base).then((r) => r.ok).catch(() => false), { timeout: 10_000 }).toBe(true);
  // The guide's commands, with the values on stdin instead of the TTY.
  stack.klav(["item", "add", "card", "--title", "Visa", "-f", "cardholder=Ana Pérez", "-f", "expiry=2030-12", "--secret-stdin", "number", "--secret-stdin", "cvv"], {
    unlocked: true,
    stdin: "4111111111111111\n123\n",
  });
  stack.klav(
    [
      "item", "add", "identity", "--title", "Casa",
      "-f", "first_name=Ana", "-f", "last_name=Pérez", "-f", "address=Av. Reforma 1", "-f", "city=Ciudad de México",
      "-f", "postal_code=06600", "-f", "country=México", "-f", "phone=+52 55 1234 5678",
    ],
    { unlocked: true },
  );
  stack.klav(["item", "add", "login", "--title", "Sitio de prueba", "--username", "ana", "--url", base, "--secret-stdin", "password"], {
    unlocked: true,
    stdin: "MARKER-guia\n",
  });
  browser = await launch(stack);
  await unlockInBrowser(stack, browser);
});

test.afterAll(async () => {
  await browser.context.close();
  site.kill();
  stack.stop();
});

test("fills a card on the guide's payment page", async () => {
  const page = await browser.context.newPage();
  await page.goto(`${base}/pago`);
  const menu = await openMenu(page, page.locator("#numero"));
  const choice = menu.getByRole("button", { name: /^Visa/ });
  await expect(choice).toBeVisible();
  await waitArmed(page);
  await shoot(page, shots, "menu-tarjeta");
  await clickIn(choice);
  await expect(page.locator("#titular")).toHaveValue("Ana Pérez");
  await expect(page.locator("#numero")).toHaveValue("4111111111111111");
  await expect(page.locator("#caducidad")).toHaveValue("12/30");
  await expect(page.locator("#cvc")).toHaveValue("123");
  await page.close();
});

test("fills an address, choosing the country in its list", async () => {
  const page = await browser.context.newPage();
  await page.goto(`${base}/envio`);
  const menu = await openMenu(page, page.locator("#nombre"));
  const choice = menu.getByRole("button", { name: /^Casa/ });
  await expect(choice).toBeVisible();
  await waitArmed(page);
  await clickIn(choice);
  await expect(page.locator("#apellidos")).toHaveValue("Pérez");
  await expect(page.locator("#direccion")).toHaveValue("Av. Reforma 1");
  await expect(page.locator("#cp")).toHaveValue("06600");
  await expect(page.locator("#pais")).toHaveValue("MX");
  await expect(page.locator("#tel")).toHaveValue("+52 55 1234 5678");
  await page.close();
});

test("the guide's agent step: an agent in the same KLAV_HOME fills the active tab", async () => {
  const words = stack.klav(["agent", "register", "--name", "prueba", "--key-store", "file"]).trim();
  stack.klav(["agent", "approve", "prueba", "--project", "Personal/General", "--words", words], { unlocked: true, stdin: `${PASSWORD}\n` });
  const page = await browser.context.newPage();
  await page.goto(`${base}/entrar`);
  await page.bringToFront();
  const fill = ["agent", "fill", "klav://Personal/General/Sitio de prueba", "--extension", "--agent", "prueba", "--reason", "probar la extensión", "--json"];
  // The extension attaches to klavd a moment after the browser starts.
  const attached = (): boolean => {
    const status = JSON.parse(stack.klav(["status", "--json"])) as { klavd?: { browsers?: { connected: boolean }[] } };
    return status.klavd?.browsers?.some((b) => b.connected) ?? false;
  };
  await expect.poll(attached, { timeout: 15_000 }).toBe(true);
  // The first fill through this browser asks in Klav's frame (ADR 0041
  // §3.1), so the command runs while the test answers it.
  const pending = stack.klavInTerminal(fill);
  await confirmPresence(page);
  const out = await pending;
  expect(out).toContain("username");
  expect(out).not.toContain("MARKER-guia");
  await expect(page.locator("#usuario")).toHaveValue("ana");
  await expect(page.locator("#clave")).toHaveValue("MARKER-guia");
  await page.close();
});
