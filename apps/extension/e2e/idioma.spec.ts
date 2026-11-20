/**
 * Klav in Spanish: the browser's interface is in Spanish, so the popup,
 * the field menu and the save bar speak Spanish (the other specs run in
 * English, the default).
 */
import { resolve } from "node:path";
import { expect, test } from "@playwright/test";
import { type Browser, clickIn, frameOf, launch, openMenu, PASSWORD, settled, shoot, startStack, type Stack, UNLOCK_MS, waitArmed } from "./harness";
import { type Site, startSite } from "./site";

const shots = process.env.SCREENSHOTS === "1" ? resolve(import.meta.dirname, "..", "..", "..", "docs", "img", "extension") : undefined;
const SECRET = "MARKER-idioma";
let stack: Stack;
let site: Site;
let browser: Browser;

test.beforeAll(async () => {
  stack = await startStack();
  site = await startSite();
  stack.klav(
    ["item", "add", "login", "--title", "Sitio local", "--username", "ana", "--url", site.url("/"), "--secret-stdin", "password", "--secret-stdin", "totp"],
    { unlocked: true, stdin: `${SECRET}\nJBSWY3DPEHPK3PXP\n` },
  );
  stack.klav(["item", "add", "login", "--title", "Banco", "--username", "ana.banco", "--url", "https://banco.example", "--secret-stdin", "password"], {
    unlocked: true,
    stdin: "MARKER-banco\n",
  });
  browser = await launch(stack, { lang: "es" });
});

test.afterAll(async () => {
  await browser.context.close();
  await site.close();
  stack.stop();
});

test("the popup speaks Spanish: unlock, the vault, the page's login and an item", async () => {
  stack.klav(["lock"]);
  const page = await browser.context.newPage();
  await page.goto(site.url("/login"));
  const popup = await browser.context.newPage();
  await page.bringToFront();
  await popup.setViewportSize({ width: 360, height: 560 });
  await popup.goto(browser.extensionUrl("popup.html"));
  await expect(popup.locator("html")).toHaveAttribute("lang", "es");
  await expect(popup.getByRole("heading", { name: "Klav está bloqueado" })).toBeVisible();
  await popup.getByLabel("Contraseña maestra").fill("contraseña equivocada");
  await popup.getByRole("button", { name: "Desbloquear" }).click();
  // `unlockForm` looks for the English labels, so this spec presses the
  // button itself and gives klavd the same time to answer.
  await expect(popup.getByRole("alert")).toHaveText("La contraseña maestra no es correcta.", { timeout: UNLOCK_MS });
  await popup.getByLabel("Contraseña maestra").fill(PASSWORD);
  await popup.getByRole("button", { name: "Desbloquear" }).click();
  await expect(popup.getByText("Tu bóveda")).toBeVisible({ timeout: UNLOCK_MS });
  await expect(popup.getByRole("heading", { name: "En localhost" })).toBeVisible();
  await expect(popup.getByRole("button", { name: "Rellenar Sitio local" })).toBeVisible();
  await expect(popup.getByRole("group", { name: "Código de un solo uso de Sitio local" })).toContainText(/^\d{3} \d{3}$/);
  await expect(popup.getByRole("button", { name: "Ajustes" })).toBeVisible();
  await expect(popup.getByRole("button", { name: "Bloquear" })).toBeVisible();
  await popup.bringToFront();
  await shoot(popup, shots, "idioma-popup");

  await popup.getByLabel("Buscar en tu bóveda").fill("Banco");
  await popup.getByRole("button", { name: /^Banco/ }).click();
  await expect(popup.getByRole("heading", { name: "Banco" })).toBeVisible();
  await expect(popup.getByText("Login · Personal / General")).toBeVisible();
  await expect(popup.getByRole("button", { name: "Mostrar Contraseña" })).toBeVisible();
  await expect(popup.getByText("Para agentes")).toBeVisible();
  await popup.getByRole("button", { name: "Tu bóveda" }).click();
  await expect(popup.getByLabel("Buscar en tu bóveda")).toBeVisible();
  await popup.close();
  await page.close();
});

test("the field menu and the save bar speak Spanish", async () => {
  stack.klav(["unlock"], { unlocked: true });
  const page = await browser.context.newPage();
  await page.goto(site.url("/login"));
  const menu = await openMenu(page, page.locator("#username"));
  await expect(menu.locator("html")).toHaveAttribute("lang", "es");
  await expect(menu.getByRole("button", { name: /^Buscar otro elemento/ })).toBeVisible();
  await expect(menu.getByText("Otra cuenta o algo que no sale aquí")).toBeVisible();
  const choice = menu.getByRole("button", { name: /^Sitio local/ });
  await expect(choice).toBeVisible();
  await waitArmed(page);
  await shoot(page, shots, "idioma-menu");
  await clickIn(choice);
  await expect(page.locator("#password")).toHaveValue(SECRET);

  // A look-alike address: the menu says why it offers nothing, in Spanish.
  const other = await browser.context.newPage();
  await other.goto(site.lookAlike("/login"));
  const empty = await openMenu(other, other.locator("#username"));
  await expect(empty.getByText(/Ningún login de Klav es de/)).toBeVisible();
  await expect(empty.locator(".empty strong")).toHaveText("127.0.0.1");
  await other.close();

  // Sending a new login: the save bar asks in Spanish.
  await page.goto(site.url("/login"));
  await page.locator("#username").fill("nueva");
  await page.locator("#password").fill("MARKER-nueva");
  await page.getByRole("button", { name: "Entrar" }).click();
  const bar = await frameOf(page, "/save.html");
  await expect(bar.getByText("¿Guardar este login en Klav?")).toBeVisible();
  await expect(bar.getByText("nueva · localhost")).toBeVisible();
  await expect(bar.getByLabel("Título")).toBeVisible();
  await settled(bar);
  await expect(bar.getByRole("button", { name: "Guardar" })).toBeVisible();
  await expect(bar.getByRole("button", { name: "Ahora no" })).toBeVisible();
  await page.close();
});
