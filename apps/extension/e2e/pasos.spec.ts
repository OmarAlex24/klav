/**
 * Sign-ins in several steps on the guide's site (examples/sitio-extension):
 * the account first and then the password on the same page, after a
 * navigation or in a frame of another subdomain (idmsa.localhost), then a
 * code in one box per digit. Klav stops at a captcha and when the
 * password never shows, and «Solo rellenar, no pulsar» leaves the buttons
 * to the person.
 */
import { type ChildProcess, spawn } from "node:child_process";
import { resolve } from "node:path";
import { expect, type Page, test } from "@playwright/test";
import { type Browser, clickIn, freePort, launch, openMenu, shoot, startStack, type Stack, waitArmed } from "./harness";

const shots = process.env.SCREENSHOTS === "1" ? resolve(import.meta.dirname, "..", "..", "..", "docs", "img", "extension") : undefined;
const SERVER = resolve(import.meta.dirname, "..", "..", "..", "examples", "sitio-extension", "server.mjs");
const SECRET = "MARKER-pasos";
const ACCOUNT = "ana@example.com";
let stack: Stack;
let browser: Browser;
/** Set once the browser started (cleanup runs even if it did not). */
let started: Browser | undefined;
let site: ChildProcess;
let base: string;
let port: number;

test.beforeAll(async () => {
  stack = await startStack();
  port = await freePort();
  base = `http://localhost:${String(port)}`;
  site = spawn(process.execPath, [SERVER], { env: { ...process.env, PORT: String(port) }, stdio: "ignore" });
  await expect.poll(() => fetch(base).then((r) => r.ok).catch(() => false), { timeout: 10_000 }).toBe(true);
  stack.klav(
    ["item", "add", "login", "--title", "Sitio de pasos", "--username", ACCOUNT, "--url", base, "--secret-stdin", "password", "--secret-stdin", "totp"],
    { unlocked: true, stdin: `${SECRET}\nJBSWY3DPEHPK3PXP\n` },
  );
  browser = await launch(stack);
  started = browser;
  stack.klav(["unlock"], { unlocked: true });
});

test.afterAll(async () => {
  // Even if the browser never started: no server or klavd left behind.
  site.kill();
  await started?.context.close().catch(() => undefined);
  stack.stop();
});

/** Chooses the login in the menu of the account field. */
async function chooseLogin(page: Page): Promise<void> {
  const menu = await openMenu(page, page.locator("#correo"));
  await waitArmed(page);
  await clickIn(menu.getByRole("button", { name: /^Sitio de pasos/ }));
}

/** The text of the menus open in `page` (the first step's menu may still be closing). */
async function menuText(page: Page): Promise<string> {
  const texts = await Promise.all(
    page
      .frames()
      .filter((f) => f.url().includes("/menu.html"))
      .map((f) => f.locator("body").textContent().catch(() => "")),
  );
  return texts.join(" | ");
}

/** «Solo rellenar, no pulsar», from the popup's settings. */
async function onlyFill(on: boolean): Promise<void> {
  const popup = await browser.popup();
  await popup.getByRole("button", { name: "Settings" }).click();
  const box = popup.getByRole("checkbox", { name: /Only fill, don’t press/ });
  if ((await box.isChecked()) !== on) await box.click();
  await expect(popup.getByRole("status")).toContainText(on ? "you’ll press" : "for you");
  if (on) await shoot(popup, shots, "popup-ajustes");
  await popup.close();
}

test("the account, «Continuar», then the password on the same page, and «Iniciar sesión»", async () => {
  const page = await browser.context.newPage();
  await page.goto(`${base}/pasos`);
  await chooseLogin(page);
  await expect(page.getByRole("heading", { name: "Recibido" })).toBeVisible({ timeout: 15_000 });
  await expect(page.getByText(`username: ${String(ACCOUNT.length)} caracteres`)).toBeVisible();
  await expect(page.getByText(`password: ${String(SECRET.length)} caracteres`)).toBeVisible();
  await page.close();
});

test("the password on the next page, after a navigation of the same site", async () => {
  const page = await browser.context.newPage();
  await page.goto(`${base}/pasos-navega`);
  await chooseLogin(page);
  await expect(page.getByRole("heading", { name: "Recibido" })).toBeVisible({ timeout: 15_000 });
  await expect(page.getByText(`password: ${String(SECRET.length)} caracteres`)).toBeVisible();
  await page.close();
});

test("the password in a frame of another subdomain of the item's site", async () => {
  const page = await browser.context.newPage();
  await page.goto(`${base}/pasos-marco`);
  await chooseLogin(page);
  await expect.poll(() => page.frames().some((f) => f.url().startsWith(`http://idmsa.localhost:${String(port)}/`))).toBe(true);
  const frame = page.frames().find((f) => f.url().startsWith(`http://idmsa.localhost:${String(port)}/`));
  if (!frame) throw new Error("no frame");
  await expect(frame.getByRole("heading", { name: "Recibido" })).toBeVisible({ timeout: 15_000 });
  await expect(frame.getByText(`password: ${String(SECRET.length)} caracteres`)).toBeVisible();
  await page.close();
});

test("never types the password into a frame of another site, and says where it was asked for", async () => {
  test.setTimeout(45_000);
  const page = await browser.context.newPage();
  await page.goto(`${base}/pasos-marco-ajeno`);
  await chooseLogin(page);
  const foreign = `http://127.0.0.1:${String(port)}/`;
  await expect.poll(() => page.frames().some((f) => f.url().startsWith(foreign))).toBe(true);
  await expect.poll(() => menuText(page), { timeout: 20_000 }).toContain("frame of another site");
  const frame = page.frames().find((f) => f.url().startsWith(foreign));
  await expect(frame?.locator("#clave") ?? page.locator("#nada")).toHaveValue("");
  await page.close();
});

test("then the one-time code, a digit in each box", async () => {
  const page = await browser.context.newPage();
  await page.goto(`${base}/pasos-2fa`);
  await chooseLogin(page);
  await expect(page.getByRole("heading", { name: "Recibido" })).toBeVisible({ timeout: 20_000 });
  for (const box of ["d1", "d2", "d3", "d4", "d5", "d6"]) await expect(page.getByText(`${box}: 1 caracteres`)).toBeVisible();
  await page.close();
});

test("stops at a captcha and says so on the field", async () => {
  const page = await browser.context.newPage();
  await page.goto(`${base}/pasos-captcha`);
  await chooseLogin(page);
  await expect(page.locator("#correo")).toHaveValue(ACCOUNT);
  await expect.poll(() => menuText(page)).toContain("The page wants to check you’re a person");
  await expect(page.getByRole("heading", { name: "Entrar" })).toBeVisible();
  await page.close();
});

test("stops when the password never shows", async () => {
  test.setTimeout(45_000);
  const page = await browser.context.newPage();
  await page.goto(`${base}/pasos-sin-clave`);
  await chooseLogin(page);
  await expect(page.locator("#correo")).toHaveValue(ACCOUNT);
  // The menu that explains opens after the wait for the password.
  await expect.poll(() => menuText(page), { timeout: 20_000 }).toContain("the password never showed up");
  await shoot(page, shots, "pasos-sin-clave");
  await page.close();
});

test("«Solo rellenar, no pulsar»: Klav types each step and the person presses", async () => {
  await onlyFill(true);
  const page = await browser.context.newPage();
  await page.goto(`${base}/pasos`);
  await chooseLogin(page);
  await expect(page.locator("#correo")).toHaveValue(ACCOUNT);
  await page.waitForTimeout(800);
  await expect(page.locator("#clave")).toBeHidden();
  await page.getByRole("button", { name: "Continuar" }).click();
  await expect(page.locator("#clave")).toHaveValue(SECRET);
  await page.waitForTimeout(800);
  await expect(page.getByRole("heading", { name: "Entrar" })).toBeVisible();
  await page.close();
});

test("«Solo rellenar, no pulsar» across a navigation: no top card over the form Klav fills", async () => {
  // Still with «Solo rellenar, no pulsar».
  const page = await browser.context.newPage();
  await page.goto(`${base}/pasos-navega`);
  await chooseLogin(page);
  await expect(page.locator("#correo")).toHaveValue(ACCOUNT);
  await page.getByRole("button", { name: "Continuar" }).click();
  await expect(page.getByRole("heading", { name: "Contraseña" })).toBeVisible();
  await expect(page.locator("#clave")).toHaveValue(SECRET);
  await page.waitForTimeout(800);
  expect(page.frames().some((f) => f.url().includes("/card.html"))).toBe(false);
  await expect(page.getByRole("heading", { name: "Contraseña" })).toBeVisible();
  await page.close();
});

test("typing by hand stops a sign-in in steps", async () => {
  // Still with «Solo rellenar, no pulsar», so there is time to type.
  const page = await browser.context.newPage();
  await page.goto(`${base}/pasos`);
  await chooseLogin(page);
  await expect(page.locator("#correo")).toHaveValue(ACCOUNT);
  await page.locator("#correo").pressSequentially("x");
  await page.getByRole("button", { name: "Continuar" }).click();
  await expect(page.locator("#clave")).toBeVisible();
  await page.waitForTimeout(1_000);
  await expect(page.locator("#clave")).toHaveValue("");
  await page.close();
  await onlyFill(false);
});
