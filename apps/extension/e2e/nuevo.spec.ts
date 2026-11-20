/**
 * «Nuevo elemento» in the popup: a login with the active tab's site and a
 * generated password, and a secure note, created with klavd's `create`
 * and found in the vault (the CLI and the popup's list). The values never
 * reach the page's HTML, and the generated password is linked in the
 * generator history to the login that keeps it (ADR 0022 §2).
 */
import { resolve } from "node:path";
import { expect, type Page, test } from "@playwright/test";
import { type Browser, launch, shoot, type Stack, startStack } from "./harness";
import { type Site, startSite } from "./site";

const shots = process.env.SCREENSHOTS === "1" ? resolve(import.meta.dirname, "..", "..", "..", "docs", "img", "extension") : undefined;
/** Sample text: what a note might say (never a real secret in the screenshots). */
const NOTE = "Red Casa-5G. La clave está en la etiqueta del router.";
let stack: Stack;
let site: Site;
let browser: Browser;

interface Listed {
  id: string;
  title: string;
  kind: string;
  username?: string;
  urls: string[];
  project: string;
}

interface Generated {
  host?: string;
  saved_in_title?: string;
}

const items = (): Listed[] => JSON.parse(stack.klav(["item", "ls", "--json"], { unlocked: true })) as Listed[];
const generated = (): Generated[] => JSON.parse(stack.klav(["generated", "ls", "--json"], { unlocked: true })) as Generated[];

test.beforeAll(async () => {
  stack = await startStack();
  site = await startSite();
  // A second project, so the view offers where to save.
  stack.klav(["project", "create", "Trabajo"], { unlocked: true });
  stack.klav(["item", "add", "note", "--title", "Plan", "--project", "Trabajo"], { unlocked: true });
  browser = await launch(stack);
  stack.klav(["unlock"], { unlocked: true });
});

test.afterAll(async () => {
  // A bounded close: a stuck browser must not keep the stack alive.
  await Promise.race([browser.context.close(), new Promise((r) => setTimeout(r, 15_000))]);
  await site.close();
  stack.stop();
});

/** The popup in a tab behind `page`, which stays the active tab. */
async function popupBehind(page: Page): Promise<Page> {
  const popup = await browser.context.newPage();
  await page.bringToFront();
  await popup.setViewportSize({ width: 360, height: 600 });
  await popup.goto(browser.extensionUrl("popup.html"));
  await expect(popup.getByLabel("Search your vault")).toBeVisible();
  return popup;
}

test("a login from the popup takes the tab's site and a generated password", async () => {
  const page = await browser.context.newPage();
  await page.goto(site.url("/login"));
  const popup = await popupBehind(page);
  await popup.getByRole("button", { name: "New item" }).click();
  await expect(popup.getByRole("heading", { name: "New item" })).toBeVisible();
  await expect(popup.getByRole("radio", { name: "Login" })).toHaveAttribute("aria-checked", "true");
  const origin = new URL(site.url("/")).origin;
  await expect(popup.getByLabel("Website")).toHaveValue(origin);
  await expect(popup.getByLabel("Title")).toHaveValue(new URL(origin).hostname);
  await expect(popup.getByLabel("Where")).toBeVisible();

  await popup.getByLabel("Title").fill("Sitio de prueba");
  await popup.getByLabel("Username").fill("ana@example.com");
  const password = popup.getByLabel("Password", { exact: true });
  await expect(password).toHaveAttribute("type", "password");
  await popup.getByRole("button", { name: "Generate a password" }).click();
  await popup.getByRole("button", { name: "Use this password" }).click();
  await expect(password).not.toHaveValue("");
  const value = await password.inputValue();
  // Kept in the generator history before the field got it.
  expect(generated().some((g) => g.host === new URL(origin).hostname)).toBe(true);
  // A property of the input, never in the page's HTML.
  expect(await popup.content()).not.toContain(value);
  if (shots) {
    await popup.bringToFront();
    await popup.mouse.move(0, 0);
    await shoot(popup, shots, "popup-nuevo");
    await page.bringToFront();
  }
  await popup.getByRole("button", { name: "Show Password" }).click();
  await expect(password).toHaveAttribute("type", "text");
  await popup.getByRole("button", { name: "Hide Password" }).click();

  await popup.getByRole("button", { name: "Save", exact: true }).click();
  // The new item opens, masked like any other.
  await expect(popup.getByRole("heading", { name: "Sitio de prueba" })).toBeVisible();
  await expect(popup.getByText("ana@example.com", { exact: true })).toBeVisible();
  expect(await popup.content()).not.toContain(value);

  const login = items().find((i) => i.title === "Sitio de prueba");
  expect(login).toMatchObject({ kind: "login", username: "ana@example.com", project: "General" });
  expect(login?.urls).toEqual([origin]);
  // The generator history knows where that password went.
  await expect.poll(() => generated().some((g) => g.saved_in_title === "Sitio de prueba"), { timeout: 10_000 }).toBe(true);
  // klavd fills it on the site it was created for.
  await popup.getByRole("button", { name: "Your vault" }).click();
  await expect(popup.getByText(`On ${new URL(origin).hostname}`)).toBeVisible();
  await popup.close();
  await page.close();
});

test("a secure note from the popup goes to the project chosen and shows in the vault", async () => {
  const popup = await browser.popup();
  await popup.getByRole("button", { name: "New item" }).click();
  await popup.getByRole("radio", { name: "Secure note" }).click();
  await expect(popup.getByLabel("Website")).toHaveCount(0);
  await popup.getByLabel("Title").fill("Wi-Fi de casa");
  await popup.getByLabel("Note").fill(NOTE);
  await popup.getByLabel("Where").selectOption({ label: "Personal / Trabajo" });
  await shoot(popup, shots, "popup-nuevo-nota");
  // Esc leaves without saving; «+» starts over, empty.
  await popup.keyboard.press("Escape");
  await expect(popup.getByLabel("Search your vault")).toBeVisible();
  await popup.getByRole("button", { name: "New item" }).click();
  await popup.getByRole("radio", { name: "Secure note" }).click();
  await expect(popup.getByLabel("Note")).toHaveValue("");
  expect(items().some((i) => i.title === "Wi-Fi de casa")).toBe(false);

  await popup.getByLabel("Title").fill("Wi-Fi de casa");
  await popup.getByLabel("Note").fill(NOTE);
  await popup.getByLabel("Where").selectOption({ label: "Personal / Trabajo" });
  await popup.getByRole("button", { name: "Save", exact: true }).click();
  await expect(popup.getByRole("heading", { name: "Wi-Fi de casa" })).toBeVisible();
  // The note stays masked until «Show».
  expect(await popup.content()).not.toContain(NOTE);
  await popup.getByRole("button", { name: "Show the note" }).click();
  await expect(popup.getByText(NOTE)).toBeVisible();

  expect(items().find((i) => i.title === "Wi-Fi de casa")).toMatchObject({ kind: "note", project: "Trabajo" });
  await popup.getByRole("button", { name: "Your vault" }).click();
  await popup.getByLabel("Search your vault").fill("casa");
  await expect(popup.getByRole("button", { name: /^Wi-Fi de casa/ })).toBeVisible();
  await popup.close();
});

test("a second item with the same title is refused on the title", async () => {
  const popup = await browser.popup();
  await popup.getByRole("button", { name: "New item" }).click();
  await popup.getByRole("radio", { name: "Secure note" }).click();
  await popup.getByLabel("Title").fill("Plan");
  await popup.getByLabel("Where").selectOption({ label: "Personal / Trabajo" });
  await popup.getByRole("button", { name: "Save", exact: true }).click();
  await expect(popup.getByText("There’s already an item with that title in that project")).toBeVisible();
  await expect(popup.getByLabel("Title")).toHaveAttribute("aria-invalid", "true");
  expect(items().filter((i) => i.title === "Plan")).toHaveLength(1);
  await popup.close();
});

test("a one-time code from a pasted otpauth:// link, checked by klav-core in the popup", async () => {
  const popup = await browser.popup();
  await popup.getByRole("button", { name: "New item" }).click();
  await popup.getByRole("radio", { name: "Code" }).click();
  const key = popup.getByLabel("Setup key or otpauth:// link");
  await expect(key).toHaveAttribute("type", "password");
  await key.fill("no es una clave!");
  await expect(popup.getByText("That isn’t a one-time code key")).toBeVisible();
  // The RFC 6238 example key, nobody's secret.
  await key.fill("otpauth://totp/ACME:ana%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=ACME");
  await expect(popup.getByText("6 digits every 30 s · ACME · ana@example.com")).toBeVisible();
  await expect(popup.getByLabel("Title")).toHaveValue("ACME");
  await shoot(popup, shots, "popup-nuevo-codigo");
  await popup.getByRole("button", { name: "Save", exact: true }).click();
  await expect(popup.getByRole("heading", { name: "ACME" })).toBeVisible();
  await expect(popup.getByRole("group", { name: "One-time code for ACME" })).toContainText(/^\d{3} \d{3}$/);
  expect(await popup.content()).not.toContain("JBSWY3DPEHPK3PXP");
  expect(items().find((i) => i.title === "ACME")).toMatchObject({ kind: "totp" });
  await popup.close();
});
