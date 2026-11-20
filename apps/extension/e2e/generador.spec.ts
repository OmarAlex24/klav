/**
 * The generator (ADR 0022): the field menu follows the field's
 * `passwordrules`, switches type, keeps every password in the generator
 * history before typing it, and the popup shows the history and an item's
 * previous passwords.
 */
import { resolve } from "node:path";
import { expect, test } from "@playwright/test";
import { type Browser, clickIn, launch, openMenu, settled, shoot, startStack, type Stack, waitArmed } from "./harness";
import { type Site, startSite } from "./site";

const shots = process.env.SCREENSHOTS === "1" ? resolve(import.meta.dirname, "..", "..", "..", "docs", "img", "extension") : undefined;
const OLD = "MARKER-anterior";
let stack: Stack;
let site: Site;
let browser: Browser;

interface Generated {
  created_at: number;
  host?: string;
  pending: boolean;
}

function history(): Generated[] {
  return JSON.parse(stack.klav(["generated", "ls", "--json"], { unlocked: true })) as Generated[];
}

test.beforeAll(async () => {
  stack = await startStack();
  site = await startSite();
  stack.klav(["item", "add", "login", "--title", "Banco", "--username", "ana", "--url", "https://banco.example", "--secret-stdin", "password"], {
    unlocked: true,
    stdin: `${OLD}\n`,
  });
  // A new password: the old one goes to the item's previous passwords.
  stack.klav(["item", "edit", "Banco", "-g", "password"], { unlocked: true });
  browser = await launch(stack);
  stack.klav(["unlock"], { unlocked: true });
});

test.afterAll(async () => {
  await browser.context.close();
  await site.close();
  stack.stop();
});

test("the field menu follows the field's rules, switches type and keeps what it fills", async () => {
  const page = await browser.context.newPage();
  await page.goto(site.url("/signup-rules"));
  const menu = await openMenu(page, page.locator("#new"));
  const value = menu.getByLabel("Generated password", { exact: true });
  await expect(menu.getByText(/^Follows the rules this field gives\./)).toBeVisible();
  await expect(value).toHaveText(/^[a-z0-9]{8}$/);
  expect(await value.textContent()).toMatch(/\d/);
  await expect(menu.getByText(/^(Weak|Fair) · \d+ bits$/)).toBeVisible();

  // PIN: digits only, its length changes with − and +.
  await clickIn(menu.getByRole("radio", { name: "PIN" }));
  await expect(value).toHaveText(/^\d{6}$/);
  await clickIn(menu.getByRole("button", { name: "Digits: More" }));
  await expect(value).toHaveText(/^\d{7}$/);
  // Memorable: five words with a separator (four of the list's words carry a
  // hyphen of their own, such as `drop-down`); random: letters, digits and symbols.
  await clickIn(menu.getByRole("radio", { name: "Memorable" }));
  await expect(value).toHaveText(/^[A-Za-z0-9]+(-[A-Za-z0-9]+){4,9}$/);
  await clickIn(menu.getByRole("radio", { name: "Random" }));
  await expect(value).toHaveText(/^.{20}$/);
  await expect(menu.getByRole("button", { name: "Length: More" })).toBeVisible();

  await clickIn(menu.getByRole("radio", { name: "Smart" }));
  await expect(value).toHaveText(/^[a-z0-9]{8}$/);
  await settled(menu);
  await waitArmed(page);
  await shoot(page, shots, "generador-reglas");
  const chosen = (await value.textContent()) ?? "";
  const before = history().length;
  await clickIn(menu.getByRole("button", { name: "Use this password" }));
  await expect(page.locator("#new")).toHaveValue(chosen);
  await expect(page.locator("#again")).toHaveValue(chosen);
  // Kept before it was typed: it is in the history, for this site.
  const after = history();
  expect(after.length).toBe(before + 1);
  expect(after[0]?.host).toBe("localhost");
  const shown = stack.klav(["generated", "show", "0"], { unlocked: true }).trim();
  expect(shown).toBe(chosen);
  await page.close();
});

test("the menu's history lists what Klav generated, without values", async () => {
  const page = await browser.context.newPage();
  await page.goto(site.url("/signup"));
  const menu = await openMenu(page, page.locator("#new"));
  await clickIn(menu.getByRole("button", { name: "Generator history" }));
  await expect(menu.getByText("localhost").first()).toBeVisible();
  await expect(menu.getByRole("button", { name: /^Copy the password generated/ }).first()).toBeVisible();
  const shown = stack.klav(["generated", "show", "0"], { unlocked: true }).trim();
  expect(await menu.locator("body").textContent()).not.toContain(shown);
  await settled(menu);
  await shoot(page, shots, "generador-historial");
  await clickIn(menu.getByRole("button", { name: "Password generator" }));
  await expect(menu.getByLabel("Generated password", { exact: true })).toHaveText(/^.{20}$/);
  await page.close();
});

test("the popup generates, copies into the history, and shows an item's previous passwords", async () => {
  const popup = await browser.popup();
  await popup.getByRole("button", { name: "Generate a password" }).click();
  await expect(popup.getByRole("heading", { name: "Password generator" })).toBeVisible();
  await expect(popup.getByLabel("Generated password", { exact: true })).toHaveText(/^.{20}$/);
  await expect(popup.getByText(/^Very strong · \d+ bits$/)).toBeVisible();
  await shoot(popup, shots, "popup-generador");
  const before = history().length;
  await popup.getByRole("button", { name: "Copy the generated password" }).click();
  await expect(popup.locator(".toast")).toHaveText("Copied");
  expect(history().length).toBe(before + 1);

  await popup.getByRole("button", { name: "Your vault" }).click();
  await popup.getByLabel("Search your vault").fill("Banco");
  await popup.getByRole("button", { name: /^Banco/ }).click();
  await expect(popup.getByRole("heading", { name: "Previous passwords" })).toBeVisible();
  expect(await popup.content()).not.toContain(OLD);
  await shoot(popup, shots, "popup-anteriores", { fullPage: true });
  await popup.getByRole("button", { name: /^Show the previous Password/ }).click();
  await expect(popup.getByText(OLD)).toBeVisible();
  await popup.close();
});
