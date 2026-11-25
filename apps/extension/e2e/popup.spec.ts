import { mkdirSync } from "node:fs";
import { resolve } from "node:path";
import { expect, test } from "@playwright/test";
import { launch, shoot, type Stack, startStack, unlockForm, unlockInBrowser } from "./harness";

const shots = process.env.SCREENSHOTS === "1" ? resolve(import.meta.dirname, "..", "..", "..", "docs", "img", "extension") : undefined;
let stack: Stack;

test.beforeAll(async () => {
  stack = await startStack();
  stack.klav(
    ["item", "add", "login", "--title", "GitHub", "--username", "ana", "--url", "https://github.com", "--secret-stdin", "password"],
    { unlocked: true, stdin: "MARKER-gh\n" },
  );
  if (shots) mkdirSync(shots, { recursive: true });
});

test.afterAll(() => {
  stack.stop();
});

test("the popup unlocks through klavd with the master password and locks again", async () => {
  const browser = await launch(stack);
  const popup = await browser.popup();
  // klavd is not running yet: the host starts it, locked.
  await expect(popup.getByRole("heading", { name: "Klav is locked" })).toBeVisible();
  await expect(popup.getByText("ana@example.com")).toBeVisible();
  await shoot(popup, shots, "popup-bloqueado");

  await unlockForm(popup, "wrong password");
  await expect(popup.getByRole("alert")).toHaveText("The master password isn’t correct.");

  await unlockForm(popup);
  await expect(popup.getByText("Your vault", { exact: true })).toBeVisible();
  await expect(popup.getByText("GitHub")).toBeVisible();
  await shoot(popup, shots, "popup-boveda");
  // The status the CLI sees is the same klavd.
  expect(stack.klav(["status", "--json"])).toContain('"unlocked": true');

  await popup.getByRole("button", { name: "Lock" }).click();
  await expect(popup.getByRole("heading", { name: "Klav is locked" })).toBeVisible();
  expect(stack.klav(["status", "--json"])).toContain('"unlocked": false');
  await browser.context.close();
});

test("the open popup shows a change once klavd syncs it, without reopening", async () => {
  const browser = await launch(stack);
  await unlockInBrowser(stack, browser);
  const popup = await browser.popup();
  await expect(popup.getByText("GitHub")).toBeVisible();
  // Another process adds an item; klavd learns of it when it syncs, and
  // `revision` in `status` tells the popup to list again (ADR 0026).
  stack.klav(["--no-daemon", "item", "add", "login", "--title", "GitLab", "--username", "ana", "--secret-stdin", "password"], {
    unlocked: true,
    stdin: "MARKER-gl\n",
  });
  await popup.waitForTimeout(500);
  await expect(popup.getByText("GitLab")).toHaveCount(0);
  stack.klav(["sync"]);
  await expect(popup.getByText("GitLab")).toBeVisible({ timeout: 10_000 });
  await browser.context.close();
});
