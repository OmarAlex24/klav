/**
 * Passkeys in the browser (ADR 0020), end to end: a page registers and
 * signs in with WebAuthn, Klav answers through its frame (master password
 * in Klav's frame, as without Touch ID), and a relying party verifies both
 * on its own (`rp.ts`, `node:crypto`). What Klav does not take goes to the
 * browser's own authenticator: here a virtual one, through CDP.
 */
import { expect, type Frame, type Page, test } from "@playwright/test";
import { type Browser, clickIn, frameOf, launch, PASSWORD, settled, type Stack, startStack, unlockForm, waitArmed } from "./harness";
import { KLAV_AAGUID, type RelyingParty, startRelyingParty } from "./rp";

let stack: Stack;
let rp: RelyingParty;
let browser: Browser;

// The tests build on each other (the first one's passkey, the RP's count of
// sign-ins, Klav unlocked in its frame): after a failure, the rest would
// fail only because of it.
test.describe.configure({ mode: "serial" });

test.beforeAll(async () => {
  stack = await startStack();
  rp = await startRelyingParty();
  browser = await launch(stack);
});

test.afterAll(async () => {
  try {
    // Closing Chromium can hang on this Mac: the stack stops whatever happens.
    await Promise.race([browser.context.close(), new Promise((r) => setTimeout(r, 15_000))]);
    await rp.close();
  } finally {
    // The server (and klavd) must not outlive the run (CLAUDE.md).
    stack.stop();
  }
});

/** The browser's own authenticator, as a virtual security key (CTAP2 over USB, with UV). */
async function virtualAuthenticator(page: Page): Promise<void> {
  const cdp = await browser.context.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      transport: "usb",
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });
}

/** The frame closed with the call (the next one is a new frame). */
async function frameGone(page: Page): Promise<void> {
  await expect.poll(() => page.frames().some((f) => f.url().includes("/passkey.html"))).toBe(false);
}

async function passkeyFrame(page: Page): Promise<Frame> {
  const frame = await frameOf(page, "/passkey.html");
  await settled(frame);
  return frame;
}

/** Without Touch ID, Klav's frame asks for the master password: type it there. */
async function confirmWithPassword(frame: Frame): Promise<void> {
  const input = frame.getByLabel("Confirm with your master password");
  await expect(input).toBeVisible();
  await input.fill(PASSWORD);
  await clickIn(frame.getByRole("button", { name: "Confirm" }));
}

/** Unlocks in the frame if Klav is locked; whether it did (ADR 0020 §8: that unlock is the use's verification). */
async function unlockIfLocked(frame: Frame): Promise<boolean> {
  const locked = frame.getByText("Klav is locked.");
  const ready = frame.locator(".choice:not(.choice-quiet), .card");
  await expect(locked.or(ready).first()).toBeVisible();
  if (!(await locked.isVisible())) return false;
  await unlockForm(frame);
  await expect(ready.first()).toBeVisible();
  return true;
}

test("registers a passkey in Klav and signs in with it; the RP verifies both", async () => {
  const page = await browser.context.newPage();
  await page.goto(rp.url("/passkeys"));
  await page.getByRole("button", { name: "Crear passkey" }).click();
  let frame = await passkeyFrame(page);
  // Unlocking here is the verification of this save: no password again.
  const unlockedHere = await unlockIfLocked(frame);
  await expect(frame.getByText("Save a passkey for ana in Klav")).toBeVisible();
  await waitArmed(page);
  await clickIn(frame.getByRole("button", { name: "Save passkey" }));
  if (!unlockedHere) await confirmWithPassword(frame);
  await expect(page.locator("#out")).toHaveText(`registrada ${KLAV_AAGUID}`);
  expect(rp.failures).toEqual([]);
  const [reg] = rp.registered;
  // Klav's AAGUID reaches the RP: the browser never sees the attestation object (ADR 0020, check 1).
  expect(reg?.aaguid).toBe(KLAV_AAGUID);
  expect(reg?.fmt).toBe("none");
  expect(reg?.flags).toBe(0x5d);
  // The frame closed with the call.
  await expect.poll(() => page.frames().some((f) => f.url().includes("/passkey.html"))).toBe(false);
  // The passkey went into a new login named after the site.
  const items = JSON.parse(stack.klav(["item", "ls", "--json"], { unlocked: true })) as { title: string; passkey?: { rp_id: string } }[];
  expect(items.find((i) => i.title === "Sitio RP")?.passkey?.rp_id).toBe("localhost");

  // Sign in: the site's passkey in Klav's frame, the password, and the RP checks the signature.
  await page.getByRole("button", { name: "Entrar con passkey" }).click();
  frame = await passkeyFrame(page);
  await unlockIfLocked(frame);
  const choice = frame.getByRole("button", { name: /Sitio RP/ });
  await expect(choice).toContainText("ana");
  await waitArmed(page);
  await clickIn(choice);
  await confirmWithPassword(frame);
  await expect(page.locator("#out")).toHaveText("dentro como ana");
  expect(rp.failures).toEqual([]);
  expect(rp.signedIn[0]).toMatchObject({ credentialId: reg?.credentialId, flags: 0x1d, signCount: 0 });
  await page.close();
});

test("a wrong master password does not sign, and closing the frame is NotAllowedError", async () => {
  const page = await browser.context.newPage();
  await page.goto(rp.url("/passkeys"));
  await page.getByRole("button", { name: "Entrar con passkey" }).click();
  const frame = await passkeyFrame(page);
  await unlockIfLocked(frame);
  await waitArmed(page);
  await clickIn(frame.getByRole("button", { name: /Sitio RP/ }));
  const input = frame.getByLabel("Confirm with your master password");
  await input.fill("not the password");
  await clickIn(frame.getByRole("button", { name: "Confirm" }));
  await expect(frame.getByRole("alert")).toBeVisible();
  await expect(page.locator("#out")).toHaveText("…");
  await clickIn(frame.getByRole("button", { name: "Close" }).first());
  // The person's close, not another end of the call: a new call or leaving
  // the page say so, and the timeout (5 minutes) comes after the test's.
  await expect(page.locator("#out")).toHaveText("error NotAllowedError The operation either timed out or was not allowed.");
  expect(page.frames().some((f) => f.url().includes("/passkey.html"))).toBe(false);
  expect(rp.signedIn).toHaveLength(1);
  await page.close();
});

test("what Klav does not take goes to the browser's own authenticator", async () => {
  const page = await browser.context.newPage();
  await page.goto(rp.url("/passkeys"));
  await virtualAuthenticator(page);
  const before = rp.registered.length;

  // A security key (cross-platform): the browser, with no frame from Klav.
  rp.user = { name: "bea", id: new Uint8Array(16).fill(7) };
  await page.getByRole("button", { name: "Crear con llave de seguridad" }).click();
  await expect(page.locator("#out")).toHaveText(/^registrada /);
  expect(page.frames().some((f) => f.url().includes("/passkey.html"))).toBe(false);
  const key = rp.registered[before];
  expect(key?.aaguid).not.toBe(KLAV_AAGUID);

  // A sign-in that allows only that key: Klav has nothing for it, silently the browser (T86).
  await page.getByRole("button", { name: "Entrar con la última llave" }).click();
  await expect(page.locator("#out")).toHaveText("dentro como bea");
  expect(page.frames().some((f) => f.url().includes("/passkey.html"))).toBe(false);

  // «Use another device» in Klav's frame: the browser again.
  rp.user = { name: "carla", id: new Uint8Array(16).fill(9) };
  await page.getByRole("button", { name: "Crear passkey" }).click();
  const frame = await passkeyFrame(page);
  await unlockIfLocked(frame);
  await waitArmed(page);
  await clickIn(frame.getByRole("button", { name: /Use another device/ }));
  await expect(page.locator("#out")).toHaveText(/^registrada /);
  expect(rp.registered[rp.registered.length - 1]?.aaguid).not.toBe(KLAV_AAGUID);
  expect(rp.failures).toEqual([]);
  await page.close();
});

test("a page that writes its own origin or another site's rpId gets nothing from them (T80)", async () => {
  const page = await browser.context.newPage();
  await page.goto(rp.url("/passkeys"));
  // The page talks to Klav's bridge directly, with a forged origin, then with another site's rpId.
  const ask = (extra: Record<string, unknown>): Promise<void> =>
    page.evaluate(async (extra) => {
      const res = await fetch("/options/sign-in", { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
      const o = (await res.json()) as { challenge: string };
      const id = crypto.randomUUID();
      const w = window as unknown as { forged?: Promise<unknown> };
      w.forged = new Promise((resolve) => {
        addEventListener("message", (event: MessageEvent<{ klav?: string; id?: string; outcome?: unknown }>) => {
          if (event.data.klav === "webauthn-done" && event.data.id === id) resolve(event.data.outcome);
        });
      });
      window.postMessage({ klav: "webauthn-call", id, call: { kind: "get", challenge: o.challenge, allow: [], ...extra } }, "*");
    }, extra);
  const outcome = (): Promise<{ status: string; credential?: { client_data_json: string } }> =>
    page.evaluate(() => (window as unknown as { forged: Promise<{ status: string; credential?: { client_data_json: string } }> }).forged);

  await ask({ rp_id: "example.com" });
  expect((await outcome()).status).toBe("browser");
  expect(page.frames().some((f) => f.url().includes("/passkey.html"))).toBe(false);

  await ask({ origin: "https://bank.example", rp_id: "localhost" });
  const frame = await passkeyFrame(page);
  await unlockIfLocked(frame);
  await waitArmed(page);
  await clickIn(frame.getByRole("button", { name: /Sitio RP/ }));
  await confirmWithPassword(frame);
  const signed = await outcome();
  expect(signed.status).toBe("asserted");
  const clientData = JSON.parse(Buffer.from(signed.credential?.client_data_json ?? "", "base64url").toString("utf8")) as { origin: string };
  expect(clientData.origin).toBe(rp.origin);
  await page.close();
});

/** The field menu, opened by itself when the page waits for a passkey and the person focuses its `webauthn` field. */
async function menuOnFocus(page: Page): Promise<Frame> {
  await page.locator("#password").click();
  await page.locator("#username").click();
  const menu = await frameOf(page, "/menu.html");
  await settled(menu);
  return menu;
}

test("conditional mediation: Klav's passkeys first in the field menu, presence in Klav's frame", async () => {
  const page = await browser.context.newPage();
  await page.goto(rp.url("/passkeys"));
  const before = rp.signedIn.length;
  await page.getByRole("button", { name: "Esperar passkey en el campo" }).click();
  await expect(page.locator("#out")).toHaveText("…");
  // No frame of Klav while the page waits: only the field menu offers the passkey.
  await page.waitForTimeout(1000);
  expect(page.frames().some((f) => f.url().includes("/passkey.html"))).toBe(false);
  const menu = await menuOnFocus(page);
  await unlockIfLocked(menu);
  await expect(menu.getByRole("heading", { name: "Passkeys" })).toBeVisible();
  const row = menu.getByRole("button", { name: /Passkey · ana/ });
  await waitArmed(page);
  await clickIn(row);
  const frame = await passkeyFrame(page);
  await confirmWithPassword(frame);
  await expect(page.locator("#out")).toHaveText("dentro como ana");
  expect(rp.failures).toEqual([]);
  expect(rp.signedIn).toHaveLength(before + 1);
  await page.close();
});

test("conditional mediation: closing Klav's frame keeps the page waiting, «Use another device» hands it to the browser", async () => {
  const page = await browser.context.newPage();
  try {
    await page.goto(rp.url("/passkeys"));
    await page.getByRole("button", { name: "Esperar passkey en el campo" }).click();
    let menu = await menuOnFocus(page);
    await waitArmed(page);
    await clickIn(menu.getByRole("button", { name: /Passkey · ana/ }));
    const frame = await passkeyFrame(page);
    await waitArmed(page);
    await clickIn(frame.getByRole("button", { name: "Close" }).first());
    await expect.poll(() => page.frames().some((f) => f.url().includes("/passkey.html"))).toBe(false);
    // Still waiting: no error for the page, and the menu offers the passkey again.
    await expect(page.locator("#out")).toHaveText("…");
    menu = await menuOnFocus(page);
    await waitArmed(page);
    await clickIn(menu.getByRole("button", { name: /Use another device/ }));
    await menuGone(page, menu);
    // The browser's own conditional request now: Klav's menu no longer opens by itself.
    await page.locator("#password").click();
    await page.locator("#username").click();
    await page.waitForTimeout(1500);
    expect(page.frames().some((f) => f.url().includes("/menu.html"))).toBe(false);
    await expect(page.locator("#out")).toHaveText("…");
  } finally {
    await page.close();
  }
});

/**
 * The field menu closed after a choice. If not, the failure says what the
 * menu showed: a message (the request was over, the page covered it), Klav
 * locked, or the same rows (the click did not count).
 */
async function menuGone(page: Page, menu: Frame): Promise<void> {
  try {
    await expect.poll(() => page.frames().some((f) => f.url().includes("/menu.html"))).toBe(false);
  } catch (e) {
    const shown = await menu.locator("body").innerText().catch(() => "(unreadable)");
    throw new Error(`the field menu is still open; it shows: ${JSON.stringify(shown)}`, { cause: e });
  }
}

/** «Passkeys» in the popup's settings: pick a window; loosening asks for the master password (no Touch ID here). */
async function passkeyWindow(name: RegExp, password: boolean): Promise<void> {
  const popup = await browser.popup();
  // The vault, not the locked or unavailable screen: say which, not a 120 s timeout.
  const settings = popup.getByRole("button", { name: "Settings" });
  try {
    await expect(settings).toBeVisible({ timeout: 10_000 });
  } catch (e) {
    const shown = await popup.locator("body").innerText().catch(() => "(unreadable)");
    throw new Error(`the popup is locked or unavailable, not on the vault; it shows: ${JSON.stringify(shown)}`, { cause: e });
  }
  await settings.click();
  await popup.getByRole("radio", { name }).click();
  if (password) {
    await expect(popup.getByText("Confirm with your master password to ask less often.")).toBeVisible();
    // Not changed yet.
    await expect(popup.getByRole("radio", { name })).not.toBeChecked();
    await popup.getByLabel("Master password to approve").fill(PASSWORD);
    await popup.getByRole("button", { name: "Confirm" }).click();
  }
  await expect(popup.getByText("Saved.", { exact: true })).toBeVisible();
  await expect(popup.getByRole("radio", { name })).toBeChecked();
  await popup.close();
}

test("the verification window: «While Klav is unlocked» after one verification signs with the click alone; «Every time» asks again", async () => {
  await passkeyWindow(/While Klav is unlocked/, true);
  const page = await browser.context.newPage();
  try {
    await page.goto(rp.url("/passkeys"));
    const before = rp.signedIn.length;
    for (let i = 1; i <= 2; i++) {
      await page.getByRole("button", { name: "Entrar con passkey" }).click();
      const frame = await passkeyFrame(page);
      await waitArmed(page);
      await clickIn(frame.getByRole("button", { name: /Sitio RP/ }));
      // Loosening the window opens nothing (ADR 0041 §3): the first use
      // still asks, and its verification holds until Klav locks.
      if (i === 1) await confirmWithPassword(frame);
      await expect(page.locator("#out")).toHaveText("dentro como ana");
      expect(rp.signedIn).toHaveLength(before + i);
      // Still a real verification behind it: UV is set.
      expect(rp.signedIn[before + i - 1]).toMatchObject({ flags: 0x1d });
      await frameGone(page);
    }
  } finally {
    await page.close();
  }

  // Tightening asks for nothing; then every sign-in asks again. (A new tab:
  // headless Chromium does not route clicks to a tab's extension frames
  // after another tab was in front of it.)
  await passkeyWindow(/Every time/, false);
  const again = await browser.context.newPage();
  await again.goto(rp.url("/passkeys"));
  await again.getByRole("button", { name: "Entrar con passkey" }).click();
  const frame = await passkeyFrame(again);
  await waitArmed(again);
  await clickIn(frame.getByRole("button", { name: /Sitio RP/ }));
  await confirmWithPassword(frame);
  await expect(again.locator("#out")).toHaveText("dentro como ana");
  await again.close();
});
