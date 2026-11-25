/**
 * The import wizard (ADR 0024) with the synthetic exports of
 * `examples/import/` (never real data): Bitwarden, then Google
 * Authenticator in two QR codes (one as a picture, one pasted), the
 * preview without values, the import and the reminder to delete the
 * export. Then the same wizard in Spanish.
 */
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { expect, type Page, test } from "@playwright/test";
import { type Browser, launch, shoot, startStack, type Stack, unlockInBrowser } from "./harness";

const shots = process.env.SCREENSHOTS === "1" ? resolve(import.meta.dirname, "..", "..", "..", "docs", "img", "extension") : undefined;
const samples = resolve(import.meta.dirname, "..", "..", "..", "examples", "import");
const sample = (name: string): string => resolve(samples, name);
let stack: Stack;
let browser: Browser | undefined;

/** No sample value ever reaches the page. */
async function noValues(page: Page): Promise<void> {
  const text = await page.locator("body").innerText();
  for (const marker of ["sample-", "JBSWY3DP", "4111111111111111", "otpauth-migration://offline?data"]) {
    expect(text, marker).not.toContain(marker);
  }
}

async function wizard(b: Browser): Promise<Page> {
  const page = await b.context.newPage();
  await page.setViewportSize({ width: 900, height: 900 });
  await page.goto(b.extensionUrl("import.html"));
  return page;
}

test.beforeAll(async () => {
  stack = await startStack();
});

test.afterAll(async () => {
  await browser?.context.close();
  stack.stop();
});

test("imports Bitwarden and Google Authenticator, merging and keeping every password", async () => {
  browser = await launch(stack);
  await unlockInBrowser(stack, browser);
  // The popup opens the wizard in a tab: from an empty vault, and from the settings.
  const popup = await browser.popup();
  const opened = browser.context.waitForEvent("page");
  await popup.getByRole("button", { name: "Import from another app" }).click();
  const fromPopup = await opened;
  await expect(fromPopup).toHaveURL(/\/import\.html$/);
  await fromPopup.close();
  const page = await wizard(browser);
  await expect(page.getByRole("heading", { name: "Where are you coming from?" })).toBeVisible();
  await shoot(page, shots, "importar-origen");

  // Authy: no export, the way to move each code.
  await page.getByRole("button", { name: /^Authy/ }).click();
  await expect(page.getByRole("heading", { name: "Authy has no export" })).toBeVisible();
  await expect(page.getByText("Only then remove the site from Authy.")).toBeVisible();
  await page.getByRole("button", { name: "All sources" }).click();

  // Bitwarden.
  await page.getByRole("button", { name: /^Bitwarden/ }).click();
  await expect(page.getByRole("heading", { name: "From Bitwarden" })).toBeVisible();
  await expect(page.getByText("Choose the file format .json.", { exact: false })).toBeVisible();
  await page.locator('input[type="file"]').setInputFiles(sample("bitwarden.json"));
  await expect(page.getByText("5 entries")).toBeVisible();
  await expect(page.getByText("item 6: not imported (in Bitwarden's trash)")).toBeVisible();
  // The shop's passkey comes with its key: nothing to warn about.
  await expect(page.getByText("won’t be imported:", { exact: false })).toHaveCount(0);
  await shoot(page, shots, "importar-archivo", { fullPage: true });
  await page.getByRole("button", { name: "Review import" }).click();
  await expect(page.getByText("5 new items.")).toBeVisible();
  await expect(page.getByText("Into Personal / General.")).toBeVisible();
  await expect(page.getByText("earlier passwords kept in its history")).toBeVisible();
  await expect(page.getByText("passkey added")).toBeVisible();
  await noValues(page);
  // The preview changed nothing.
  expect(JSON.parse(stack.klav(["item", "ls", "--json"])) as unknown[]).toHaveLength(0);
  await page.getByRole("button", { name: "Import 5 items" }).click();
  await expect(page.getByRole("heading", { name: "Imported" })).toBeVisible();
  await expect(page.getByText("Created 5, updated 0, into Personal / General.")).toBeVisible();
  await expect(page.getByRole("heading", { name: "Now delete the export" })).toBeVisible();
  await expect(page.getByText("bitwarden.json", { exact: true })).toBeVisible();
  const imported = JSON.parse(stack.klav(["item", "ls", "--json"])) as { title: string; passkey?: { rp_id: string } }[];
  expect(imported).toHaveLength(5);
  expect(imported.find((i) => i.title === "Passkey Shop")?.passkey?.rp_id).toBe("shop.example.com");

  // Google Authenticator: the first QR code as a picture, the second pasted.
  await page.getByRole("button", { name: "Import from somewhere else" }).click();
  await page.getByRole("button", { name: /^Google Authenticator/ }).click();
  await page.locator('input[type="file"]').setInputFiles(sample("google-1-of-2.png"));
  await expect(page.getByText("This export has 2 QR codes and 2 aren’t here yet. Add them too.")).toBeVisible();
  const links = readFileSync(sample("google-links.txt"), "utf8").trim().split("\n");
  await page.getByLabel("Or paste the otpauth-migration:// links, one per line").fill(links[1] ?? "");
  await page.getByRole("button", { name: "Add links" }).click();
  await expect(page.getByText("This export has 2 QR codes", { exact: false })).toHaveCount(0);
  await expect(page.getByText("not imported (counter-based (HOTP) codes are not supported)", { exact: false })).toBeVisible();
  await noValues(page);
  await page.getByRole("button", { name: "Review import" }).click();
  await expect(page.getByText("1 new item and 1 merged into an item you have.")).toBeVisible();
  await expect(page.getByText("one-time code added")).toBeVisible();
  await expect(page.getByText("no matching login, its own one-time code item")).toBeVisible();
  await shoot(page, shots, "importar-revision", { fullPage: true });
  await page.getByRole("button", { name: "Import 2 items" }).click();
  await expect(page.getByText("Created 1, updated 1, into Personal / General.")).toBeVisible();
  await expect(page.getByText("delete their photos too", { exact: false })).toBeVisible();
  await shoot(page, shots, "importar-hecho", { fullPage: true });
  // GitHub has its code now.
  expect((await stack.klavInTerminal(["totp", "GitHub"])).trim()).toMatch(/^\d{6}$/);

  // A file Klav can't read says so, with its name.
  await page.getByRole("button", { name: "Import from somewhere else" }).click();
  await page.getByRole("button", { name: /^Firefox/ }).click();
  await page.locator('input[type="file"]').setInputFiles(sample("bitwarden.json"));
  await expect(page.getByRole("alert")).toContainText("bitwarden.json: this looks like a Bitwarden export, not Firefox");
  await expect(page.getByRole("button", { name: "Review import" })).toBeDisabled();
  await page.close();
  await browser.context.close();
  browser = undefined;
});

test("the wizard speaks Spanish", async () => {
  browser = await launch(stack, { lang: "es" });
  const page = await wizard(browser);
  await expect(page.locator("html")).toHaveAttribute("lang", "es");
  await expect(page.getByRole("heading", { name: "¿De dónde vienes?" })).toBeVisible();
  await shoot(page, shots, "importar-origen-es");
  await page.getByRole("button", { name: /^1Password/ }).click();
  await expect(page.getByRole("heading", { name: "Desde 1Password" })).toBeVisible();
  await page.locator('input[type="file"]').setInputFiles(sample("1password.1pux"));
  await expect(page.getByText("2 entradas")).toBeVisible();
  await page.getByRole("button", { name: "Revisar la importación" }).click();
  await expect(page.getByText("1 elemento nuevo y 1 se une a un elemento que ya tienes.")).toBeVisible();
  await expect(page.getByText("contraseña nueva, la anterior pasa a su historial")).toBeVisible();
  await shoot(page, shots, "importar-revision-es", { fullPage: true });
  await noValues(page);
  await page.getByRole("button", { name: "Importar 2 elementos" }).click();
  await expect(page.getByRole("heading", { name: "Ahora borra la exportación" })).toBeVisible();
  // The bank keeps both passwords: 1Password's is current, Bitwarden's in its history.
  const history = JSON.parse(stack.klav(["item", "history", "Example Bank", "--json"])) as { entries: unknown[] };
  expect(history.entries).toHaveLength(2);
});
