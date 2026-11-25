/**
 * Assisted password changes (ADR 0022 §5–7) end to end: the real server,
 * the person's `klavd`, Chromium with the extension and an agent on
 * `klav mcp` in its own KLAV_HOME. The person approves a task with
 * `rotate` from the popup; the agent opens the site's change page
 * (`change_password_url`), calls `rotate_password` with `target:
 * "extension"`, submits and confirms or cancels. The page gets the
 * passwords; the agent never does.
 *
 * It also closes the phase's end-to-end checks (roadmap): a sign-up form
 * the site refuses loses no generated password (the agent's, made with
 * `create_item` and `generate: true`, stays in the new item; the person's,
 * from the field menu, stays in the generator history), and an agent
 * changes the password two sites share, inside one task, where the second
 * site refuses the new one and both the current and the pending one stay.
 */
import { expect, type Page, test } from "@playwright/test";
import { type Agent, type Browser, clickIn, KLAV_BIN, launch, openMenu, PASSWORD, registerAgent, type Stack, startStack, unlockForm, waitArmed, confirmPresence } from "./harness";
import { McpClient, type ToolResult } from "./mcp";
import { type Site, startSite } from "./site";

const BANK = "klav://Personal/General/Banco";
const FORUM = "klav://Personal/General/Foro";
const SHOP = "klav://Personal/General/Tienda";
/** Two sites with the same password: the club here, the mail on another host. */
const CLUB = "klav://Personal/General/Club";
const MAIL = "klav://Personal/General/Correo";
const SHARED = "MARKER-cambio-compartida";
const SIGNUP = "klav://Personal/General/Registro";
const TAKEN = "Ese correo ya tiene una cuenta";
const REFUSED = "La contraseña nueva no cumple las reglas del sitio";
const OLD: Record<string, string> = {
  Banco: "MARKER-cambio-banco-viejo",
  Foro: "MARKER-cambio-foro-viejo",
  Tienda: "MARKER-cambio-tienda-viejo",
};

let stack: Stack;
let site: Site;
/** The second site: the same pages on `127.0.0.1`, which no `localhost` item matches. */
let other: Site;
let browser: Browser;
let agent: Agent;
let mcp: McpClient;
let task: string;
/** Every password of the run, old and new: none may reach the agent. */
const secrets: string[] = [...Object.values(OLD), SHARED];

test.describe.configure({ mode: "serial" });

test.beforeAll(async () => {
  stack = await startStack();
  site = await startSite();
  other = await startSite({ name: "127.0.0.1" });
  const logins: [string, string, string][] = [
    ...Object.entries(OLD).map(([title, password]): [string, string, string] => [title, password, site.url("/")]),
    ["Club", SHARED, site.url("/")],
    ["Correo", SHARED, other.url("/")],
  ];
  for (const [title, password, url] of logins) {
    stack.klav(["item", "add", "login", "--title", title, "--username", "ana", "--url", url, "--secret-stdin", "password"], {
      unlocked: true,
      stdin: `${password}\n`,
    });
  }
  agent = registerAgent(stack, "cambiador");
  browser = await launch(stack);
  mcp = new McpClient(KLAV_BIN, agent.repo, {
    KLAV_HOME: agent.home,
    // The person's klavd, where the browser is attached.
    KLAV_BROWSER_HOME: stack.home,
    KLAV_NO_TOUCH_ID: "1",
  });
  await mcp.initialize();
});

test.afterAll(async () => {
  try {
    mcp.close();
    // Closing Chromium can hang on this Mac (the browser exits with the
    // worker anyway): the stack stops whatever happens.
    await Promise.race([browser.context.close(), new Promise((r) => setTimeout(r, 15_000))]);
  } finally {
    await Promise.all([site.close(), other.close()]);
    stack.stop();
  }
});

/** The item's password now, as the person sees it. */
async function current(title: string): Promise<string> {
  const view = JSON.parse(await stack.klavInTerminal(["item", "get", title, "--reveal", "--json"], { unlocked: true })) as {
    fields: { name: string; value?: string }[];
  };
  const value = view.fields.find((f) => f.name === "password")?.value;
  if (value === undefined) throw new Error(`${title} has no password`);
  return value;
}

interface History {
  pending: boolean;
  entries: { index: number; field: string; unconfirmed?: boolean }[];
}

function history(title: string): History {
  return JSON.parse(stack.klav(["item", "history", title, "--json"], { unlocked: true })) as History;
}

/** How many `action` events the log has for the agent, by the agent or by the person. */
function events(action: string, by: "agent" | "person"): number {
  const lines = JSON.parse(stack.klav(["log", "--agent", "cambiador", "--json"], { unlocked: true })) as { action: string; actor: string }[];
  return lines.filter((l) => l.action === action && (l.actor === "you") === (by === "person")).length;
}

/** A previous password's value («Contraseñas anteriores»). */
async function previous(title: string, index: number): Promise<string> {
  return (await stack.klavInTerminal(["item", "history", title, "--reveal", String(index)], { unlocked: true })).trim();
}

/** The tab the agent works on: in front, so `klavd` sees it as the active tab. */
async function open(url: string): Promise<Page> {
  const page = await browser.context.newPage();
  await page.goto(url);
  await page.bringToFront();
  return page;
}

/** `rotate_password` once the extension is attached to `klavd` (it attaches when the browser starts). */
async function rotate(ref: string, reason: string, taskId: string = task): Promise<ToolResult> {
  for (let i = 0; i < 30; i++) {
    const result = await mcp.tool("rotate_password", { ref, target: "extension", task_id: taskId, reason });
    if (!result.isError || !/no browser with Klav's extension|klavd, with the person's browser/.test(result.text)) return result;
    await new Promise((r) => setTimeout(r, 300));
  }
  throw new Error("the extension never attached to klavd");
}

function pendingOf(result: ToolResult): string {
  expect(result.isError, result.text).toBe(false);
  const answer = JSON.parse(result.text) as { filled: string[]; pending_id: string };
  // Field names and the change's ID: nothing else.
  expect(Object.keys(answer).sort()).toEqual(["filled", "pending_id"]);
  return answer.pending_id;
}

/** The new password, read from the page (the test's eyes, not the agent's). */
async function typed(page: Page, selector: string): Promise<string> {
  const value = await page.locator(selector).inputValue();
  expect(value.length).toBeGreaterThanOrEqual(12);
  secrets.push(value);
  return value;
}

async function popup(): Promise<Page> {
  const p = await browser.popup();
  const locked = p.getByRole("heading", { name: "Klav is locked" });
  await expect(locked.or(p.getByText("Your vault", { exact: true }))).toBeVisible();
  if (await locked.isVisible()) {
    await unlockForm(p);
  }
  return p;
}

/** The agent asks for a task with `rotate` on `refs`, and the person approves it in the popup. Returns its ID. */
async function approvedTask(name: string, reason: string, refs: string[]): Promise<string> {
  const asked = await mcp.tool("request_task", {
    task: name,
    reason,
    duration: "1h",
    access: refs.map((ref) => ({ ref, permissions: ["rotate"] })),
    // Answer at once: the person decides in the popup below.
    wait_seconds: 0,
  });
  expect(asked.isError, asked.text).toBe(false);
  const id = (JSON.parse(asked.text) as { pending_task_id: string }).pending_task_id;
  expect(id).toBeTruthy();

  const p = await popup();
  // The asking card, not the card of a task already running.
  const card = p.locator(".approval.task:not(.task-live)").filter({ hasText: name });
  await expect(card.getByText("cambiador asks for a task")).toBeVisible({ timeout: 20_000 });
  await card.getByRole("button", { name: "Approve" }).click();
  await p.getByLabel("Master password to approve").fill(PASSWORD);
  await p.getByRole("button", { name: "Confirm" }).click();
  await expect(p.locator(".task-live").filter({ hasText: name }).getByText("cambiador is working on a task")).toBeVisible({ timeout: 15_000 });
  await p.close();
  return id;
}

/** `klav log --task`: each site of the task, by title, with its state. */
function sites(taskId: string): Record<string, string> {
  const log = JSON.parse(stack.klav(["log", "--task", taskId, "--json"], { unlocked: true })) as { sites: { title: string; state: string }[] };
  return Object.fromEntries(log.sites.map((s) => [s.title, s.state]));
}

test("the person approves a task with rotate from the popup", async () => {
  task = await approvedTask("Change the reused passwords", "They are the same on three sites", [BANK, FORUM, SHOP]);

  const listed = await mcp.tool("list_tasks", {});
  expect(listed.isError, listed.text).toBe(false);
  const mine = (JSON.parse(listed.text) as { tasks: { task_id: string; status: string; access: { ref: string; permissions: string[] }[] }[] }).tasks.find(
    (t) => t.task_id === task,
  );
  expect(mine?.status).toBe("approved");
  expect(mine?.access.map((a) => a.permissions)).toEqual([["rotate"], ["rotate"], ["rotate"]]);
});

test("the agent changes a password on the site's change page and confirms it", async () => {
  const url = await mcp.tool("change_password_url", { ref: BANK, reason: "find the bank's change page" });
  expect(url.isError, url.text).toBe(false);
  const where = JSON.parse(url.text) as { url: string; source: string };
  // The site's own page, on the item's port (always https: the local
  // test site speaks http, so the agent goes to its change page directly).
  expect(where).toMatchObject({ url: `https://localhost:${String(site.port)}/.well-known/change-password`, source: "well_known" });

  const page = await open(site.url("/password"));
  // The first change through this browser asks in Klav's frame (ADR 0041
  // §3.1); until Klav locks, the next ones don't.
  const rotating = rotate(BANK, "the bank password is reused");
  await confirmPresence(page);
  const pending = pendingOf(await rotating);
  await expect(page.locator("#current")).toHaveValue(OLD.Banco ?? "");
  const next = await typed(page, "#new");
  expect(next).not.toBe(OLD.Banco);
  await expect(page.locator("#confirm")).toHaveValue(next);
  // Nothing changes in the item before the agent confirms; the new one waits as pending.
  expect(await current("Banco")).toBe(OLD.Banco);
  expect(history("Banco").pending).toBe(true);

  // The agent submits the form: the site gets the old and the new one.
  await page.getByRole("button", { name: "Cambiar" }).click();
  await expect.poll(() => site.posts.length).toBeGreaterThan(0);
  const sent = site.posts.at(-1);
  expect(sent?.get("current_password")).toBe(OLD.Banco);
  expect(sent?.get("new_password")).toBe(next);
  expect(sent?.get("confirm_password")).toBe(next);

  const confirmed = await mcp.tool("rotate_confirm", { ref: BANK, pending_id: pending, reason: "the site said the password changed" });
  expect(confirmed.isError, confirmed.text).toBe(false);
  expect(JSON.parse(confirmed.text)).toEqual({ ok: true });
  expect(await current("Banco")).toBe(next);
  const after = history("Banco");
  expect(after.pending).toBe(false);
  expect(after.entries[0]?.unconfirmed ?? false).toBe(false);
  expect(await previous("Banco", after.entries[0]?.index ?? -1)).toBe(OLD.Banco);
  await page.close();
});

test("cancelling keeps the current password and files the new one as not confirmed", async () => {
  const before = await current("Banco");
  const page = await open(site.url("/password"));
  const pending = pendingOf(await rotate(BANK, "try another password"));
  const next = await typed(page, "#new");
  await expect(page.locator("#current")).toHaveValue(before);

  const cancelled = await mcp.tool("rotate_cancel", { ref: BANK, pending_id: pending, reason: "the site said the password is too long" });
  expect(cancelled.isError, cancelled.text).toBe(false);
  expect(JSON.parse(cancelled.text)).toEqual({ ok: true });
  expect(await current("Banco")).toBe(before);
  const after = history("Banco");
  expect(after.pending).toBe(false);
  expect(after.entries[0]?.unconfirmed).toBe(true);
  expect(await previous("Banco", after.entries[0]?.index ?? -1)).toBe(next);
  // The CLI says so in words too.
  expect(stack.klav(["item", "history", "Banco"], { unlocked: true })).toContain("generated, not confirmed");
  await page.close();
});

test("on a form Klav cannot read, the new password goes into the focused password box", async () => {
  const page = await open(site.url("/settings"));
  await page.locator("#k2").focus();
  const pending = pendingOf(await rotate(FORUM, "change the forum password"));
  const next = await typed(page, "#k2");
  expect(next).not.toBe(OLD.Foro);
  // The form's other password box reads as the current one; the text box gets nothing.
  await expect(page.locator("#k1")).toHaveValue(OLD.Foro ?? "");
  await expect(page.locator("#alias")).toHaveValue("");
  const cancelled = await mcp.tool("rotate_cancel", { ref: FORUM, pending_id: pending, reason: "checking where it went" });
  expect(cancelled.isError, cancelled.text).toBe(false);
  await page.close();
});

test("a focused text box gets nothing", async () => {
  const page = await open(site.url("/settings"));
  await page.locator("#alias").focus();
  const result = await rotate(FORUM, "change the forum password");
  expect(result.isError).toBe(true);
  expect(result.text).toContain("no password box");
  for (const box of ["#alias", "#k1", "#k2"]) await expect(page.locator(box)).toHaveValue("");
  // The change was closed for the agent: nothing is left pending, and the
  // password klavd generated is kept as not confirmed (and must not leak).
  const after = history("Foro");
  expect(after.pending).toBe(false);
  expect(after.entries[0]?.unconfirmed).toBe(true);
  secrets.push(await previous("Foro", after.entries[0]?.index ?? -1));
  expect(await current("Foro")).toBe(OLD.Foro);
  await page.close();
});

test("a tab on a host that is not the item's gets nothing", async () => {
  const page = await open(site.lookAlike("/password"));
  await page.locator("#new").focus();
  const result = await rotate(FORUM, "change the forum password");
  expect(result.isError).toBe(true);
  expect(result.text).toContain("phishing");
  for (const box of ["#current", "#new", "#confirm"]) await expect(page.locator(box)).toHaveValue("");
  expect(history("Foro").pending).toBe(false);
  await page.close();
});

test("the popup's «Pending change» card uses the new password or keeps the current one", async () => {
  // Use the new one: Banco.
  let page = await open(site.url("/password"));
  const bankBefore = await current("Banco");
  const bankPending = pendingOf(await rotate(BANK, "change it once more"));
  const bankNext = await typed(page, "#new");
  await page.close();
  let p = await popup();
  await p.getByLabel("Search your vault").fill("Banco");
  await p.getByRole("button", { name: /^Banco/ }).click();
  let card = p.locator(".pending-change");
  await expect(card.getByText("Pending change: did the new password work?")).toBeVisible();
  await card.getByRole("button", { name: "Use the new one" }).click();
  await expect(card).toBeHidden({ timeout: 15_000 });
  await p.close();
  expect(await current("Banco")).toBe(bankNext);
  let after = history("Banco");
  expect(after.pending).toBe(false);
  expect(await previous("Banco", after.entries[0]?.index ?? -1)).toBe(bankBefore);
  // The person's klavd recorded the decision with the server. The agent's
  // confirm afterwards is told the person decided, and logs nothing.
  expect(events("rotate.confirmed", "person")).toBe(1);
  const confirmedByAgent = events("rotate.confirmed", "agent");
  const late = await mcp.tool("rotate_confirm", { ref: BANK, pending_id: bankPending, reason: "the site took the new password" });
  expect(late.isError).toBe(true);
  expect(late.text).toContain("the person may have decided already");
  expect(events("rotate.confirmed", "agent")).toBe(confirmedByAgent);
  expect(await current("Banco")).toBe(bankNext);

  // Keep the current one: Tienda.
  page = await open(site.url("/password"));
  const shopPending = pendingOf(await rotate(SHOP, "change the shop password"));
  const shopNext = await typed(page, "#new");
  await page.close();
  p = await popup();
  await p.getByLabel("Search your vault").fill("Tienda");
  await p.getByRole("button", { name: /^Tienda/ }).click();
  card = p.locator(".pending-change");
  await expect(card.getByText("Pending change: did the new password work?")).toBeVisible();
  await card.getByRole("button", { name: "Keep the current one" }).click();
  await expect(card).toBeHidden({ timeout: 15_000 });
  await p.close();
  expect(await current("Tienda")).toBe(OLD.Tienda);
  after = history("Tienda");
  expect(after.pending).toBe(false);
  expect(after.entries[0]?.unconfirmed).toBe(true);
  expect(await previous("Tienda", after.entries[0]?.index ?? -1)).toBe(shopNext);
  // Kept: the person's cancel is the one in the log. klavd no longer holds
  // the change's password, so the agent's cancel afterwards is told so and
  // logs nothing.
  expect(events("rotate.cancelled", "person")).toBe(1);
  const cancelledByAgent = events("rotate.cancelled", "agent");
  const kept = await mcp.tool("rotate_cancel", { ref: SHOP, pending_id: shopPending, reason: "the person decided" });
  expect(kept.isError, kept.text).toBe(true);
  expect(kept.text).toContain("no pending password");
  expect(events("rotate.cancelled", "agent")).toBe(cancelledByAgent);

  // The task's log: Banco changed; the forum and the shop failed.
  expect(sites(task)).toEqual({ Banco: "changed", Foro: "failed", Tienda: "failed" });
});

test("on two sites, the second refuses the new password: the current and the pending one stay", async () => {
  const both = await approvedTask("Change the password two sites share", "The club and the mail use the same one", [CLUB, MAIL]);

  // The club takes the new one, and the agent confirms it.
  let page = await open(site.url("/password"));
  const clubPending = pendingOf(await rotate(CLUB, "the club password is reused", both));
  await expect(page.locator("#current")).toHaveValue(SHARED);
  const clubNext = await typed(page, "#new");
  await page.getByRole("button", { name: "Cambiar" }).click();
  await expect(page.getByRole("heading", { name: "Hola" })).toBeVisible();
  const confirmed = await mcp.tool("rotate_confirm", { ref: CLUB, pending_id: clubPending, reason: "the club said the password changed" });
  expect(confirmed.isError, confirmed.text).toBe(false);
  expect(await current("Club")).toBe(clubNext);
  await page.close();

  // The mail, on another host, refuses it: the agent reads the error and cancels.
  other.refuse("/changed", REFUSED);
  page = await open(other.url("/password"));
  const mailPending = pendingOf(await rotate(MAIL, "the mail password is reused", both));
  await expect(page.locator("#current")).toHaveValue(SHARED);
  const mailNext = await typed(page, "#new");
  expect(mailNext).not.toBe(clubNext);
  await page.getByRole("button", { name: "Cambiar" }).click();
  await expect(page.getByRole("alert")).toHaveText(REFUSED);
  const sent = other.posts.at(-1);
  expect(sent?.get("current_password")).toBe(SHARED);
  expect(sent?.get("new_password")).toBe(mailNext);
  const cancelled = await mcp.tool("rotate_cancel", { ref: MAIL, pending_id: mailPending, reason: "the mail site refused the new password" });
  expect(cancelled.isError, cancelled.text).toBe(false);
  expect(JSON.parse(cancelled.text)).toEqual({ ok: true });
  await page.close();

  // Nothing lost: the old one is still the mail's password, the refused one
  // is in its history as generated, not confirmed, and the club kept its old
  // one among its previous passwords.
  expect(await current("Correo")).toBe(SHARED);
  const mail = history("Correo");
  expect(mail.pending).toBe(false);
  expect(mail.entries[0]?.unconfirmed).toBe(true);
  expect(await previous("Correo", mail.entries[0]?.index ?? -1)).toBe(mailNext);
  const club = history("Club");
  expect(club.entries[0]?.unconfirmed ?? false).toBe(false);
  expect(await previous("Club", club.entries[0]?.index ?? -1)).toBe(SHARED);
  expect(sites(both)).toEqual({ Club: "changed", Correo: "failed" });
});

test("a sign-up the site refuses keeps the password the agent generated, in the new item", async () => {
  site.refuse("/welcome", TAKEN);
  const created = await mcp.tool("create_item", {
    type: "login",
    title: "Registro",
    urls: [site.url("/")],
    fields: { username: "ana@example.com" },
    generate: true,
    reason: "create an account on the local site",
  });
  expect(created.isError, created.text).toBe(false);
  // Sealed in the item before any page sees it; the agent gets its metadata only.
  stack.klav(["sync"], { unlocked: true });
  const generated = await current("Registro");
  secrets.push(generated);
  expect(generated.length).toBeGreaterThanOrEqual(12);

  const page = await open(site.url("/signup"));
  const result = await mcp.tool("fill_login", { ref: SIGNUP, target: "extension", submit: true, reason: "sign up on the local site" });
  expect(result.isError, result.text).toBe(false);
  expect((JSON.parse(result.text) as { filled: string[] }).filled.sort()).toEqual(["password", "username"]);
  await expect(page.getByRole("alert")).toHaveText(TAKEN);
  // The site got the generated password twice (the password and its confirmation), and refused the form.
  const sent = site.posts.at(-1);
  expect(sent?.get("email")).toBe("ana@example.com");
  expect(sent?.get("password")).toBe(generated);
  expect(sent?.get("password_confirmation")).toBe(generated);
  // The form is gone; the password is not: the item still has it.
  expect(await current("Registro")).toBe(generated);
  await page.close();
});

interface Generated {
  host?: string;
}

test("a sign-up the site refuses keeps the password the person generated, in the generator history", async () => {
  const page = await open(site.url("/signup"));
  await page.locator("#email").fill("ana@example.com");
  const menu = await openMenu(page, page.locator("#new"));
  const value = menu.getByLabel("Generated password", { exact: true });
  await expect(value).toHaveText(/^.{20}$/);
  // The site's logins follow the generator, so the menu scrolls inside its
  // frame (it never fits, as `settled` expects): wait for it to arm.
  await waitArmed(page);
  const chosen = (await value.textContent()) ?? "";
  await clickIn(menu.getByRole("button", { name: "Use this password" }));
  await expect(page.locator("#new")).toHaveValue(chosen);
  await expect(page.locator("#again")).toHaveValue(chosen);
  await page.getByRole("button", { name: "Crear cuenta" }).click();
  await expect(page.getByRole("alert")).toHaveText(TAKEN);
  expect(site.posts.at(-1)?.get("password")).toBe(chosen);
  // The page lost it; Klav did not: the generator history has it, for this site.
  const kept = JSON.parse(stack.klav(["generated", "ls", "--json"], { unlocked: true })) as Generated[];
  expect(kept[0]?.host).toBe("localhost");
  expect((await stack.klavInTerminal(["generated", "show", "0"], { unlocked: true })).trim() === chosen, "the generator history lost the password").toBe(true);
  await page.close();
});

test("no answer of klav mcp, on stdout or stderr, holds a password", () => {
  const said = mcp.seen.join("\n");
  const logged = mcp.errors.join("");
  expect(secrets.length).toBeGreaterThan(Object.keys(OLD).length);
  for (const value of secrets) {
    // Booleans, not the values: a failure must not print the secret.
    expect(said.includes(value), "a password reached the agent's stdout").toBe(false);
    expect(logged.includes(value), "a password reached the agent's stderr").toBe(false);
  }
});
