/**
 * An agent signs in with the person's passkey (ADR 0020 §9), end to end:
 * the real server, the person's `klavd`, Chromium with the extension, a
 * relying party that verifies the assertion on its own (`rp.ts`) and an
 * agent on `klav mcp` in its own KLAV_HOME.
 *
 * The person saves a passkey in Klav and approves a task with `passkey`
 * on that login. Then `passkey_sign_in` signs the page in, with no frame
 * for the person and the blue notice: armed before the site asks (the
 * agent clicks the button next) and at once when the page already asks.
 * Outside the task, on another site and with `sdk:` it does not sign.
 * The agent never gets the key nor the assertion.
 */
import { expect, type Frame, type Page, test } from "@playwright/test";
import { type Agent, type Browser, clickIn, confirmPresence, frameOf, KLAV_BIN, launch, PASSWORD, registerAgent, settled, type Stack, startStack, unlockForm, waitArmed } from "./harness";
import { McpClient, type ToolResult } from "./mcp";
import { KLAV_AAGUID, type RelyingParty, startRelyingParty } from "./rp";

const LOGIN = "klav://Personal/General/Tienda";
const NOTICE = "Klav signed in with the passkey of “Tienda” for “agente” (the name the agent gave)";

let stack: Stack;
let rp: RelyingParty;
let browser: Browser;
let agent: Agent;
let mcp: McpClient;
let task: string;
let credentialId: string | undefined;

test.describe.configure({ mode: "serial" });

test.beforeAll(async () => {
  stack = await startStack();
  rp = await startRelyingParty("Tienda");
  agent = registerAgent(stack, "agente");
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
    // Closing Chromium can hang on this Mac: the stack stops whatever happens.
    await Promise.race([browser.context.close(), new Promise((r) => setTimeout(r, 15_000))]);
  } finally {
    await rp.close();
    stack.stop();
  }
});

async function passkeyFrame(page: Page): Promise<Frame> {
  const frame = await frameOf(page, "/passkey.html");
  await settled(frame);
  return frame;
}

function frameOpen(page: Page): boolean {
  return page.frames().some((f) => f.url().includes("/passkey.html"));
}

/** The tab the agent works on: in front, so `klavd` sees it as the active tab. */
async function open(url: string): Promise<Page> {
  const page = await browser.context.newPage();
  await page.goto(url);
  await page.bringToFront();
  return page;
}

/** `passkey_sign_in` once the extension is attached to `klavd` (it attaches when the browser starts). */
async function signIn(args: Record<string, unknown> = {}): Promise<ToolResult> {
  for (let i = 0; i < 30; i++) {
    const result = await mcp.tool("passkey_sign_in", { ref: LOGIN, target: "extension", reason: "revisar el pedido", ...args });
    if (!result.isError || !/no browser with Klav's extension|klavd, with the person's browser/.test(result.text)) return result;
    await new Promise((r) => setTimeout(r, 300));
  }
  throw new Error("the extension never attached to klavd");
}

/** The agent's answer: whether the page was signed in, and nothing that signs. */
function answer(result: ToolResult): { used: boolean; rp_id: string; armed?: boolean; expires_in_s?: number } {
  expect(result.isError, result.text).toBe(false);
  for (const secret of ["signature", "authenticator_data", "client_data_json", "private", "token", "kpa_"]) {
    expect(result.text).not.toContain(secret);
  }
  return JSON.parse(result.text) as { used: boolean; rp_id: string; armed?: boolean; expires_in_s?: number };
}

/** The RP checked one more sign-in, with Klav's credential and the flags of a verified use. */
async function signedInOnceMore(page: Page, before: number): Promise<void> {
  await expect(page.locator("#out")).toHaveText("dentro como ana");
  await expect.poll(() => rp.signedIn.length).toBe(before + 1);
  expect(rp.failures).toEqual([]);
  // UP, UV, BE and BS: klavd verified the use with the task, not with the person.
  expect(rp.signedIn[before]).toMatchObject({ credentialId, flags: 0x1d });
}

test("the person saves a passkey in Klav", async () => {
  const page = await browser.context.newPage();
  await page.goto(rp.url("/passkeys"));
  await page.getByRole("button", { name: "Crear passkey" }).click();
  const frame = await passkeyFrame(page);
  const locked = frame.getByText("Klav is locked.");
  const save = frame.getByRole("button", { name: "Save passkey" });
  await expect(locked.or(save)).toBeVisible();
  const unlockedHere = await locked.isVisible();
  if (unlockedHere) {
    await unlockForm(frame);
  }
  await waitArmed(page);
  await clickIn(save);
  if (!unlockedHere) {
    await frame.getByLabel("Confirm with your master password").fill(PASSWORD);
    await clickIn(frame.getByRole("button", { name: "Confirm" }));
  }
  await expect(page.locator("#out")).toHaveText(`registrada ${KLAV_AAGUID}`);
  credentialId = rp.registered[0]?.credentialId;
  expect(credentialId).toBeTruthy();
  await page.close();
});

test("outside a task the agent cannot sign in", async () => {
  const page = await open(rp.url("/passkeys"));
  const result = await signIn();
  expect(result.isError).toBe(true);
  expect(result.text).toMatch(/no running task covers `passkey`/);
  // Nothing armed: the page's own sign-in goes to Klav's frame, for the person.
  await page.getByRole("button", { name: "Entrar con passkey" }).click();
  await passkeyFrame(page);
  expect(rp.signedIn).toHaveLength(0);
  await page.close();
});

test("the person approves a task with passkey from the popup", async () => {
  const asked = await mcp.tool("request_task", {
    task: "Revisar el pedido",
    reason: "Ver si ya salió",
    duration: "1h",
    access: [{ ref: LOGIN, permissions: ["passkey"] }],
    wait_seconds: 0,
  });
  expect(asked.isError, asked.text).toBe(false);
  task = (JSON.parse(asked.text) as { pending_task_id: string }).pending_task_id;
  expect(task).toBeTruthy();

  const p = await browser.popup();
  const locked = p.getByRole("heading", { name: "Klav is locked" });
  await expect(locked.or(p.getByText("Your vault", { exact: true }))).toBeVisible();
  if (await locked.isVisible()) {
    await unlockForm(p);
  }
  const card = p.locator(".approval.task:not(.task-live)").filter({ hasText: "Revisar el pedido" });
  await expect(card.getByText("agente asks for a task")).toBeVisible({ timeout: 20_000 });
  await card.getByRole("button", { name: "Approve" }).click();
  await p.getByLabel("Master password to approve").fill(PASSWORD);
  await p.getByRole("button", { name: "Confirm" }).click();
  await expect(p.locator(".task-live").filter({ hasText: "Revisar el pedido" })).toBeVisible({ timeout: 15_000 });
  await p.close();
});

test("armed before the site asks: the next sign-in of the tab gets it, with no frame and the blue notice", async () => {
  const page = await open(rp.url("/passkeys"));
  const before = rp.signedIn.length;
  // The first time an agent acts in this browser, the person confirms in
  // Klav's frame (ADR 0041 §3.1); that holds until Klav locks.
  const signing = signIn();
  await confirmPresence(page);
  const armed = answer(await signing);
  expect(armed).toMatchObject({ used: false, armed: true, rp_id: "localhost", expires_in_s: 60 });

  await page.getByRole("button", { name: "Entrar con passkey" }).click();
  await signedInOnceMore(page, before);
  // klavd signed: the person's frame never opened.
  expect(frameOpen(page)).toBe(false);
  const notice = await frameOf(page, "/notice.html");
  await expect(notice.getByText(NOTICE)).toBeVisible();

  // One use: the next sign-in is the person's again.
  await page.getByRole("button", { name: "Entrar con passkey" }).click();
  await passkeyFrame(page);
  expect(rp.signedIn).toHaveLength(before + 1);
  await page.close();
});

test("when the page already asks, the agent's call signs it at once", async () => {
  const page = await open(rp.url("/passkeys"));
  const before = rp.signedIn.length;
  await page.getByRole("button", { name: "Entrar con passkey" }).click();
  await passkeyFrame(page);

  const used = answer(await signIn());
  expect(used).toEqual({ used: true, rp_id: "localhost" });
  await signedInOnceMore(page, before);
  // Klav's frame closed with the call.
  await expect.poll(() => frameOpen(page)).toBe(false);
  const notice = await frameOf(page, "/notice.html");
  await expect(notice.getByText(NOTICE)).toBeVisible();
  await page.close();
});

test("on another site Klav does not sign (phishing protection)", async () => {
  // The same RP reached as 127.0.0.1: another origin, which `localhost`'s passkey does not serve.
  const page = await open(rp.url("/passkeys").replace("//localhost:", "//127.0.0.1:"));
  const before = rp.signedIn.length;
  const result = await signIn();
  expect(result.isError).toBe(true);
  expect(result.text).toMatch(/phishing protection/);
  expect(rp.signedIn).toHaveLength(before);
  await page.close();
});

test("with sdk: it does not sign: the page's origin would come from the agent", async () => {
  const page = await open(rp.url("/passkeys"));
  const before = rp.signedIn.length;
  const result = await signIn({ target: "sdk:runtime" });
  expect(result.isError).toBe(true);
  expect(result.text).toMatch(/never in a browser of your runtime/);
  // And nothing was armed: the page's sign-in goes to the person.
  await page.getByRole("button", { name: "Entrar con passkey" }).click();
  await passkeyFrame(page);
  expect(rp.signedIn).toHaveLength(before);
  await page.close();
});
