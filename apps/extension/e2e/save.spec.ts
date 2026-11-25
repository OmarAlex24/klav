import { resolve } from "node:path";
import { expect, test } from "@playwright/test";
import { type Browser, clickIn, frameOf, launch, openMenu, settled, shoot, startStack, type Stack, unlockForm, waitArmed, unlockInBrowser } from "./harness";
import { type Site, startSite } from "./site";

const shots = process.env.SCREENSHOTS === "1" ? resolve(import.meta.dirname, "..", "..", "..", "docs", "img", "extension") : undefined;
let stack: Stack;
let site: Site;
let browser: Browser;

test.beforeAll(async () => {
  stack = await startStack();
  site = await startSite();
  stack.klav(
    ["item", "add", "login", "--title", "Sitio local", "--username", "ana", "--url", site.url("/"), "--secret-stdin", "password", "--secret-stdin", "totp"],
    { unlocked: true, stdin: "MARKER-viejo\nJBSWY3DPEHPK3PXP\n" },
  );
  browser = await launch(stack);
  // Unlocked in the browser, so the bars and menus show their main state.
  await unlockInBrowser(stack, browser);
});

test.afterAll(async () => {
  await browser.context.close();
  await site.close();
  stack.stop();
});

interface Listed {
  title: string;
  username?: string;
}

function items(): Listed[] {
  return JSON.parse(stack.klav(["item", "ls", "--json"], { unlocked: true })) as Listed[];
}

test("offers to save a new login after the form is sent, with the duplicate-title rule", async () => {
  const page = await browser.context.newPage();
  await page.goto(site.url("/login"));
  await page.locator("#username").fill("nuevo");
  await page.locator("#password").fill("MARKER-nuevo");
  await page.getByRole("button", { name: "Entrar" }).click();
  await expect(page.getByRole("heading", { name: "Hola" })).toBeVisible();
  const bar = await frameOf(page, "/save.html");
  await expect(bar.getByText("Save this login to Klav?")).toBeVisible();
  await expect(bar.getByText("nuevo · localhost")).toBeVisible();
  await settled(bar);
  // Like the menu, the bar ignores clicks until it has been in view for a
  // moment (clickjacking, T62): a person reads it before choosing.
  await waitArmed(page);
  await shoot(page, shots, "guardar-login");
  await clickIn(bar.getByRole("button", { name: "Save" }));
  await expect(bar.getByText("Saved to Klav")).toBeVisible({ timeout: 40_000 });
  expect(items().some((i) => i.title === "localhost" && i.username === "nuevo")).toBe(true);

  // Another user on the same site: «localhost» is already taken, so the bar
  // suggests an available title («localhost (otra)») and still warns + offers
  // a one-click fix if the person types a duplicate title manually.
  await page.goto(site.url("/login"));
  await page.locator("#username").fill("otra");
  await page.locator("#password").fill("MARKER-otra");
  await page.getByRole("button", { name: "Entrar" }).click();
  const second = await frameOf(page, "/save.html");
  await expect(second.getByLabel("Title")).toHaveValue("localhost (otra)");
  await settled(second);
  await waitArmed(page);
  await second.getByLabel("Title").fill("localhost");
  await clickIn(second.getByRole("button", { name: "Save" }));
  await expect(second.getByRole("alert")).toContainText("There’s already a login with that title");
  // The message pushes «Save» down: wait for the bar to grow around it.
  await settled(second);
  // While it grew, the bar was not all in view, so the guard (T62) counts
  // a click only after it has been in view for a moment again: without
  // this wait, the click got «The page is covering part of this box» on
  // CI (run 42666203652).
  await waitArmed(page);
  await clickIn(second.getByRole("button", { name: "Use “localhost (otra)”" }));
  await expect(second.getByLabel("Title")).toHaveValue("localhost (otra)");
  await settled(second);
  await waitArmed(page);
  await clickIn(second.getByRole("button", { name: "Save" }));
  await expect(second.getByText("Saved to Klav")).toBeVisible();
  expect(items().some((i) => i.title === "localhost (otra)" && i.username === "otra")).toBe(true);
  await page.close();
});

test("offers to update the password of a known login", async () => {
  const page = await browser.context.newPage();
  await page.goto(site.url("/login"));
  await page.locator("#username").fill("ana");
  await page.locator("#password").fill("MARKER-nueva-clave");
  await page.getByRole("button", { name: "Entrar" }).click();
  const bar = await frameOf(page, "/save.html");
  await expect(bar.getByText("Update the password of")).toBeVisible();
  await settled(bar);
  await waitArmed(page);
  await clickIn(bar.getByRole("button", { name: "Update" }));
  await expect(bar.getByText("Saved to Klav")).toBeVisible({ timeout: 40_000 });
  const view = await stack.klavInTerminal(["item", "get", "klav://Personal/General/Sitio%20local/password", "--reveal"], { unlocked: true });
  expect(view).toContain("MARKER-nueva-clave");
  // The same password again: nothing to offer.
  await page.goto(site.url("/login"));
  await page.locator("#username").fill("ana");
  await page.locator("#password").fill("MARKER-nueva-clave");
  await page.getByRole("button", { name: "Entrar" }).click();
  await expect(page.getByRole("heading", { name: "Hola" })).toBeVisible();
  await page.waitForTimeout(1_500);
  expect(page.frames().some((f) => f.url().includes("/save.html"))).toBe(false);
  await page.close();
});

test("generates a password for a sign-up form and offers to save it", async () => {
  const page = await browser.context.newPage();
  await page.goto(site.url("/signup"));
  await page.locator("#email").fill("gen@example.com");
  const menu = await openMenu(page, page.locator("#new"));
  await expect(menu.getByText("New password")).toBeVisible();
  const generated = (await menu.getByLabel("Generated password", { exact: true }).textContent()) ?? "";
  expect(generated).toHaveLength(20);
  await waitArmed(page);
  await shoot(page, shots, "generador");
  await clickIn(menu.getByRole("button", { name: "Use this password" }));
  await expect(page.locator("#new")).toHaveValue(generated);
  await expect(page.locator("#again")).toHaveValue(generated);
  await page.getByRole("button", { name: "Crear cuenta" }).click();
  const bar = await frameOf(page, "/save.html");
  await expect(bar.getByText("gen@example.com · localhost")).toBeVisible();
  await settled(bar);
  await waitArmed(page);
  await bar.getByLabel("Title").fill("Sitio local (registro)");
  await clickIn(bar.getByRole("button", { name: "Save" }));
  await expect(bar.getByText("Saved to Klav")).toBeVisible({ timeout: 40_000 });
  const view = await stack.klavInTerminal(["item", "get", "klav://Personal/General/Sitio%20local%20(registro)/password", "--reveal"], { unlocked: true });
  expect(view).toContain(generated);
  await page.close();
});

test("after filling a login, the code page offers its one-time code", async () => {
  const page = await browser.context.newPage();
  await page.goto(site.url("/login-2fa"));
  const menu = await openMenu(page, page.locator("#username"));
  const choice = menu.getByRole("button", { name: /Sitio local/ }).first();
  await expect(choice).toBeVisible();
  await waitArmed(page);
  await clickIn(choice);
  await expect(page.locator("#password")).not.toHaveValue("");
  await page.getByRole("button", { name: "Entrar" }).click();
  await expect(page.getByRole("heading", { name: "Código de verificación" })).toBeVisible();
  // The code field has the focus: Klav opens its menu, and waits for a click.
  const codes = await frameOf(page, "/menu.html");
  await expect(codes.getByText("One-time code").first()).toBeVisible();
  await expect(page.locator("#code")).toHaveValue("");
  await waitArmed(page);
  await shoot(page, shots, "codigo-tras-login");
  await clickIn(codes.getByRole("button", { name: /Sitio local/ }));
  await expect(page.locator("#code")).toHaveValue(/^\d{6}$/);
  await page.close();
});

test("the menu unlocks with the master password when Klav is locked", async () => {
  stack.klav(["lock"]);
  const page = await browser.context.newPage();
  await page.goto(site.url("/login"));
  const menu = await openMenu(page, page.locator("#username"));
  await unlockForm(menu);
  await expect(menu.getByRole("button", { name: /^Sitio local ana/ })).toBeVisible();
  await page.close();
});

test("a password-only form offers nothing when Klav already has that password", async () => {
  stack.klav(
    ["item", "add", "login", "--title", "Sitio local (bea)", "--username", "bea", "--url", site.url("/"), "--secret-stdin", "password"],
    { unlocked: true, stdin: "MARKER-bea\n" },
  );
  // A password no login has: the bar offers to save it, with an editable username field.
  const unknown = await browser.context.newPage();
  await unknown.goto(site.url("/confirm"));
  await unknown.locator("#password").fill("MARKER-desconocida");
  await unknown.getByRole("button", { name: "Confirmar" }).click();
  await expect(unknown.getByRole("heading", { name: "Hola" })).toBeVisible();
  const bar = await frameOf(unknown, "/save.html");
  await expect(bar.getByText("Save this login to Klav?")).toBeVisible();
  await expect(bar.getByText("no username · localhost")).toBeVisible();
  await bar.getByLabel("Username").fill("paso2@example.com");
  await expect(bar.getByText("paso2@example.com · localhost")).toBeVisible();
  await unknown.close();
  // bea's password, sent without her username (it is not a box here).
  const known = await browser.context.newPage();
  await known.goto(site.url("/confirm"));
  await known.locator("#password").fill("MARKER-bea");
  await known.getByRole("button", { name: "Confirmar" }).click();
  await expect(known.getByRole("heading", { name: "Hola" })).toBeVisible();
  await known.waitForTimeout(1_500);
  // The bar may open while klavd compares the site's logins: it closes itself.
  await expect.poll(() => known.frames().some((f) => f.url().includes("/save.html"))).toBe(false);
  await known.close();
});
