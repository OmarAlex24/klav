/**
 * Task requests in the popup (ADR 0021): the card for the whole job, the
 * request that falls outside it («Add to the task») and the running task
 * with «End task». The agent runs the real `klav` in its own KLAV_HOME.
 */
import { spawnSync } from "node:child_process";
import { writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { expect, type Page, test } from "@playwright/test";
import { type Agent, type Browser, KLAV_BIN, launch, PASSWORD, registerAgent, shoot, type Stack, startStack, unlockForm } from "./harness";

const shots = process.env.SCREENSHOTS === "1" ? resolve(import.meta.dirname, "..", "..", "..", "docs", "img", "extension") : undefined;
const SECRET = "MARKER-tarea-popup";
// RFC 6238's example seed: a test value, not anyone's second factor.
const SEED = "JBSWY3DPEHPK3PXP";
let stack: Stack;
let browser: Browser;
let agent: Agent;

const TASK = `
task = "Download the October invoices"
reason = "Reconcile the month's expenses"
duration = "2h"

[[access]]
ref = "klav://Personal/General/Invoices"
permissions = ["fill"]

[[access]]
ref = "klav://Personal/General/Bank"
permissions = ["fill", "inject"]
`;

function login(title: string, url: string, totp: boolean): void {
  const args = ["item", "add", "login", "--title", title, "--username", "ana", "--url", url, "--secret-stdin", "password"];
  if (totp) args.push("--secret-stdin", "totp");
  stack.klav(args, { unlocked: true, stdin: `${SECRET}\n${totp ? `${SEED}\n` : ""}` });
}

/** Runs `klav` as the agent; returns the exit code and stdout (never printed). */
function asAgent(args: string[]): { code: number | null; out: string; err: string } {
  const run = spawnSync(KLAV_BIN, args, {
    encoding: "utf8",
    cwd: agent.repo,
    env: { ...process.env, KLAV_HOME: agent.home, KLAV_NO_TOUCH_ID: "1" },
  });
  return { code: run.status, out: run.stdout, err: run.stderr };
}

async function unlocked(popup: Page): Promise<void> {
  const locked = popup.getByRole("heading", { name: "Klav is locked" });
  await expect(locked.or(popup.getByText("Your vault"))).toBeVisible();
  if (await locked.isVisible()) {
    await unlockForm(popup);
  }
}

async function confirmWithPassword(popup: Page): Promise<void> {
  await popup.getByLabel("Master password to approve").fill(PASSWORD);
  await popup.getByRole("button", { name: "Confirm" }).click();
}

test.beforeAll(async () => {
  stack = await startStack();
  login("Invoices", "https://invoices.example.com/login", true);
  login("Bank", "https://bank.example.com/login", false);
  login("Other", "https://other.example.com/login", true);
  agent = registerAgent(stack, "contador", ["--ask", "fill,totp", "--deny", "inject"]);
  browser = await launch(stack);
});

test.afterAll(async () => {
  await browser.context.close();
  stack.stop();
});

test("a task is approved, extended and ended from the popup", async () => {
  const file = join(stack.dir, "task.toml");
  writeFileSync(file, TASK);
  const asked = asAgent(["agent", "task", "request", file, "--json"]);
  expect(asked.code, asked.err).toBe(4);
  const id = (JSON.parse(asked.out) as { task_id: string }).task_id;

  // The card: the whole job, completed by the person's client.
  const popup = await browser.popup();
  await unlocked(popup);
  const card = popup.locator(".approval.task").first();
  await expect(card.getByText("contador asks for a task")).toBeVisible({ timeout: 20_000 });
  await expect(card.getByText("Download the October invoices")).toBeVisible();
  await expect(card.getByText("“Reconcile the month's expenses”")).toBeVisible();
  await expect(card.getByText("Added by Klav")).toBeVisible();
  await expect(card.getByText("2FA stops being a second factor for this agent")).toBeVisible();
  await expect(card.getByText("Your policy denies it")).toBeVisible();
  await shoot(popup, shots, "popup-tarea", { fullPage: true });

  // The person unchecks the bank and shortens the task to one hour.
  await card.getByRole("checkbox", { name: "Bank" }).uncheck();
  await card.getByLabel("Duration").selectOption({ label: "1 h" });
  await card.getByRole("button", { name: "Approve" }).click();
  await confirmWithPassword(popup);

  // The running task: what is left of it.
  const live = popup.locator(".task-live");
  await expect(live.getByText("contador is working on a task")).toBeVisible({ timeout: 15_000 });
  await expect(live.getByText(/left · ends at/)).toBeVisible();
  const view = JSON.parse(asAgent(["agent", "task", "show", id, "--json"]).out) as {
    status: string;
    expires_at: number;
    access: { ref: string; permissions: string[] }[];
    removed: unknown[];
  };
  expect(view.status).toBe("approved");
  expect(view.access.map((a) => a.ref)).toEqual(["klav://Personal/General/Invoices"]);
  expect(view.access[0]?.permissions).toEqual(["fill", "totp"]);
  expect(view.expires_at - Date.now()).toBeLessThanOrEqual(3600_000);
  await shoot(popup, shots, "popup-tarea-vigente", { fullPage: true });

  // Outside the task: Other's code waits for the person, who adds it.
  const outside = asAgent(["agent", "totp", "klav://Personal/General/Other", "--reason", "the other site asks for a code too"]);
  expect(outside.code, outside.err).toBe(4);
  const request = popup.locator(".approval").filter({ hasText: "Outside the task “Download the October invoices”" });
  await expect(request).toBeVisible({ timeout: 15_000 });
  await expect(request.getByRole("button", { name: "Deny" })).toBeVisible();
  await expect(request.getByRole("button", { name: "Approve once" })).toBeVisible();
  // The viewport only: the vault's list below shows one-time codes.
  await shoot(popup, shots, "popup-fuera-de-la-tarea");
  await request.getByRole("button", { name: "Add to the task" }).click();
  await confirmWithPassword(popup);
  await expect(request).toBeHidden({ timeout: 15_000 });
  const revised = JSON.parse(asAgent(["agent", "task", "show", id, "--json"]).out) as typeof view & { revision: number };
  expect(revised.revision).toBe(2);
  expect(revised.expires_at).toBe(view.expires_at);
  expect(revised.access.some((a) => a.ref.endsWith("/Other") && a.permissions.includes("totp"))).toBe(true);
  // Inside the task now: the next code needs no approval.
  const again = asAgent(["agent", "totp", "klav://Personal/General/Other", "--reason", "one more code"]);
  expect(again.code, again.err).toBe(0);

  // «End task»: the agent's task is over.
  await live.getByRole("button", { name: "End task" }).click();
  await expect(live).toBeHidden({ timeout: 15_000 });
  const ended = JSON.parse(asAgent(["agent", "task", "show", id, "--json"]).out) as { status: string; ended_by: string };
  expect(ended).toMatchObject({ status: "ended", ended_by: "person" });
  await popup.close();
});
