/**
 * Passkeys in the browser (ADR 0020, docs/extension.md §13): the
 * background decides what to do with each WebAuthn call a page makes, with
 * the frame's address as the browser reports it (`sender`), never the
 * page's word (T80).
 *
 * - Klav answers only calls it can: a secure top frame (or a frame of the
 *   same origin), an rpId klavd accepts for that origin, ES256, not a
 *   security key. Everything else goes to the browser's own authenticator,
 *   silently, as if Klav were not there; so does a `get` for which Klav has
 *   no passkey (T86), and any call when klavd is not installed (P13).
 * - Otherwise the person decides in Klav's frame (the passkey surface): it
 *   lists the site's passkeys or offers to save the new one, asks for
 *   Touch ID or the master password through klavd, and always offers «Use
 *   another device» (the browser). Closing it is `NotAllowedError`.
 * - Conditional mediation (`get` with `mediation: "conditional"`) shows no
 *   frame: the call waits, and the site's passkeys go at the top of Klav's
 *   field menu in that same frame, with «Use another device» (ADR 0020 P9).
 *   Picking one opens Klav's frame only to confirm presence; closing it
 *   leaves the call waiting, as browsers do.
 * - The private key never leaves klavd: it signs and returns the
 *   assertion, which goes back to the frame that asked.
 */
import { ext } from "../shared/ext";
import type { ContentMessage, PasskeyReply, PasskeyState, ToContent } from "../shared/messages";
import {
  type Assertion,
  cleanCall,
  klavCanCreate,
  type PasskeyCall,
  type PasskeyCandidate,
  type PasskeyCandidates,
  type PasskeyErrorName,
  type PasskeyOutcome,
} from "../shared/passkey";
import { DaemonError, type DaemonStatus, type PasskeyCreateOutcome, type Suggestions } from "../shared/protocol";
import type { NativeBridge } from "./native";

/** How long a call waits for the person (WebAuthn's own timeouts are around this). */
const TTL_MS = 5 * 60_000;
/** A conditional call waits as long as its page does; this only bounds a page that never ends it. */
const CONDITIONAL_TTL_MS = 60 * 60_000;

interface Pending {
  id: string;
  tabId: number;
  frameId: number;
  documentId: string | undefined;
  /** The frame's URL, as the browser reported it: klavd takes the origin from it. */
  url: string;
  call: PasskeyCall;
  timer: ReturnType<typeof setTimeout>;
  /** Conditional: the passkey the person picked in the field menu (Klav's frame is open to confirm it). */
  chosen?: string;
}

/** A field menu's frame. */
export interface MenuFrame {
  tabId: number;
  frameId: number;
  documentId?: string | undefined;
}

const pending = new Map<string, Pending>();
let bridge: NativeBridge | undefined;

/**
 * One passkey use an agent armed in a tab (ADR 0020 §9): the next sign-in
 * of `rp_id` on `host` there gets it, once, before `expires`, without
 * Klav's frame. klavd checks it all again (token, tab, host, site, login).
 */
export interface AgentArm {
  token: string;
  host: string;
  rp_id: string;
  item: string;
  expires: number;
  /** Shows the blue notice in the tab. */
  notify: () => void;
}

const arms = new Map<number, AgentArm>();
/** Klav's frame opens in a tab: the top card there goes (the same corner). */
let onShow: (tabId: number) => void = () => undefined;

export function startPasskeys(native: NativeBridge, shown?: (tabId: number) => void): void {
  bridge = native;
  if (shown) onShow = shown;
  ext.tabs.onRemoved.addListener((tabId) => {
    for (const p of pending.values()) if (p.tabId === tabId) forget(p.id);
    arms.delete(tabId);
  });
}

function daemon(): NativeBridge {
  if (!bridge) throw new DaemonError("internal", "passkeys are not started");
  return bridge;
}

const BROWSER: PasskeyOutcome = { status: "browser" };

function failure(name: PasskeyErrorName, message: string): PasskeyOutcome {
  return { status: "error", name, message };
}

function toFrame(p: Pending, message: ToContent): Promise<unknown> {
  const options: { frameId: number; documentId?: string } = { frameId: p.frameId };
  if (__TARGET__ === "chromium" && p.documentId) options.documentId = p.documentId;
  return ext.tabs.sendMessage(p.tabId, message, options).catch(() => undefined);
}

function toTop(tabId: number, message: ToContent): Promise<unknown> {
  return ext.tabs.sendMessage(tabId, message, { frameId: 0 }).catch(() => undefined);
}

function forget(id: string): Pending | undefined {
  const p = pending.get(id);
  if (!p) return undefined;
  pending.delete(id);
  clearTimeout(p.timer);
  void toTop(p.tabId, { type: "passkey_hide", id });
  return p;
}

/** Ends a pending call: the surface closes and the frame gets `outcome`. */
function finish(id: string, outcome: PasskeyOutcome): void {
  const p = forget(id);
  if (p) void toFrame(p, { type: "passkey_result", id, outcome });
}

function live(id: string): Pending {
  const p = pending.get(id);
  if (!p) throw new DaemonError("not_found", "this passkey request is over");
  return p;
}

/**
 * Opens Klav's frame in the tab's top frame. The top card sits in the same
 * corner and is drawn by another script: it closes first, or it could
 * cover the frame, and the frame then ignores the clicks as covered (T62).
 */
async function showFrame(tabId: number, id: string): Promise<void> {
  onShow(tabId);
  await toTop(tabId, { type: "passkey_show", id });
}

/** Whether Klav's passkey frame is open in `tab` (no top card meanwhile). */
export function passkeyFrameIn(tabId: number): boolean {
  for (const p of pending.values()) {
    if (p.tabId !== tabId) continue;
    const conditional = p.call.kind === "get" && p.call.conditional === true;
    if (!conditional || p.chosen !== undefined) return true;
  }
  return false;
}

/** The tab of a call still waiting, whose top frame draws its passkey frame. */
export function passkeyTab(id: string): number {
  return live(id).tabId;
}

type GetCall = Extract<PasskeyCall, { kind: "get" }>;

/** What the page gets from an assertion: WebAuthn's fields only (not which login signed). */
function credentialOf(assertion: Assertion): Omit<Assertion, "item"> {
  return {
    credential_id: assertion.credential_id,
    client_data_json: assertion.client_data_json,
    authenticator_data: assertion.authenticator_data,
    signature: assertion.signature,
    user_handle: assertion.user_handle,
  };
}

/**
 * The agent's armed use, if tab `tabId` has one for this sign-in: the
 * site's passkeys (`found`) must hold the armed login. Taken once whatever
 * klavd answers; a refusal leaves the call to the person.
 */
async function agentUse(
  tabId: number,
  url: string,
  call: GetCall,
  found: PasskeyCandidates,
): Promise<Omit<Assertion, "item"> | undefined> {
  const arm = arms.get(tabId);
  if (!arm) return undefined;
  if (arm.expires <= Date.now()) {
    arms.delete(tabId);
    return undefined;
  }
  if (new URL(url).hostname !== arm.host || found.rp_id !== arm.rp_id) return undefined;
  if (!found.candidates.some((c) => c.item === arm.item)) return undefined;
  arms.delete(tabId);
  try {
    const assertion = await daemon().call<Assertion>({
      op: "agent_passkey_use",
      tab_id: tabId,
      origin: url,
      ...(call.rp_id !== undefined ? { rp_id: call.rp_id } : {}),
      challenge: call.challenge,
      token: arm.token,
    });
    arm.notify();
    return credentialOf(assertion);
  } catch {
    return undefined;
  }
}

/**
 * An agent armed a passkey use in `tabId` (ADR 0020 §9). If the page there
 * already waits for a sign-in of that site, it gets it now (Klav's frame,
 * if open, closes); else the next one does. Returns whether it was used.
 */
export async function armPasskey(tabId: number, arm: AgentArm): Promise<boolean> {
  arms.set(tabId, arm);
  setTimeout(
    () => {
      if (arms.get(tabId) === arm) arms.delete(tabId);
    },
    Math.max(0, arm.expires - Date.now()),
  );
  for (const p of pending.values()) {
    if (p.tabId !== tabId || p.call.kind !== "get") continue;
    let found: PasskeyCandidates;
    try {
      found = await candidatesFor(p);
    } catch {
      return false;
    }
    const credential = await agentUse(tabId, p.url, p.call, found);
    if (!credential) return false;
    finish(p.id, { status: "asserted", credential });
    return true;
  }
  return false;
}

/** The passkeys klavd has for the call's site; `rp_id` absent: not a site Klav answers. */
async function candidatesFor(p: { url: string; call: PasskeyCall }): Promise<PasskeyCandidates> {
  return daemon().call<PasskeyCandidates>({
    op: "passkey_candidates",
    origin: p.url,
    ...(p.call.rp_id !== undefined ? { rp_id: p.call.rp_id } : {}),
    allow_credentials: p.call.kind === "get" ? p.call.allow : [],
  });
}

/**
 * A WebAuthn call from a frame. Decided at once when Klav does not take it
 * (the browser does), else pending until the person decides in Klav's
 * frame, shown in the tab's top frame.
 */
export async function onPasskeyRequest(
  message: Extract<ContentMessage, { type: "passkey_request" }>,
  sender: chrome.runtime.MessageSender,
): Promise<PasskeyReply> {
  const tabId = sender.tab?.id;
  const url = sender.url;
  const browser: PasskeyReply = { outcome: BROWSER };
  if (tabId === undefined || sender.frameId === undefined || !url || !/^https?:/.test(url)) return browser;
  // A sandboxed frame has an opaque origin, whatever its URL says.
  if ((sender as { origin?: string }).origin === "null") return browser;
  // Frames of another origin than the page on top go to the browser (P10).
  if (sender.frameId !== 0 && !message.same_origin_as_top) return browser;
  const call = cleanCall(message.call);
  if (!call || (call.kind === "create" && !klavCanCreate(call))) return browser;
  let status: DaemonStatus;
  try {
    status = await daemon().call<DaemonStatus>({ op: "status" });
  } catch {
    // klavd is not installed or does not answer: as if Klav were not here (P13).
    return browser;
  }
  if (!status.logged_in) return browser;
  let found: PasskeyCandidates | undefined;
  if (status.unlocked) {
    try {
      found = await candidatesFor({ url, call });
      // Not a site Klav answers (rpId, origin), or a sign-in Klav has no passkey for (T86).
      if (!found.rp_id || (call.kind === "get" && found.candidates.length === 0)) return browser;
    } catch {
      return browser;
    }
  }
  // One call per tab: a new one ends the previous one, as browsers do.
  for (const p of pending.values()) if (p.tabId === tabId) finish(p.id, failure("NotAllowedError", "Another request started."));
  // An agent's armed use (ADR 0020 §9): klavd signs, no frame for the person.
  if (call.kind === "get" && found) {
    const credential = await agentUse(tabId, url, call, found);
    if (credential) return { outcome: { status: "asserted", credential } };
  }
  const id = crypto.randomUUID();
  const conditional = call.kind === "get" && call.conditional === true;
  const timer = setTimeout(
    () => {
      finish(id, failure("NotAllowedError", "The operation either timed out or was not allowed."));
    },
    conditional ? CONDITIONAL_TTL_MS : TTL_MS,
  );
  pending.set(id, { id, tabId, frameId: sender.frameId, documentId: sender.documentId, url, call, timer });
  // Conditional: no frame; the field menu offers the passkeys.
  if (!conditional) await showFrame(tabId, id);
  return { pending: id };
}

/** The page aborted its call (`AbortSignal`). */
export function onPasskeyCancel(id: string, sender: chrome.runtime.MessageSender): void {
  const p = pending.get(id);
  if (p?.tabId !== sender.tab?.id || p?.frameId !== sender.frameId) return;
  finish(id, failure("AbortError", "The operation was aborted."));
}

/** What the surface shows. A sign-in Klav has nothing for (after an unlock) goes to the browser. */
export async function passkeyLoad(id: string): Promise<PasskeyState> {
  const p = live(id);
  const status = await daemon().call<DaemonStatus>({ op: "status" });
  const host = new URL(p.url).hostname;
  const state: PasskeyState = { kind: p.call.kind, page: p.url, status, rp_id: p.call.rp_id ?? host };
  if (p.call.kind === "create") {
    state.rp_name = p.call.rp_name;
    state.user_name = p.call.user_name;
  }
  if (!status.unlocked) return state;
  const found = await candidatesFor(p);
  if (!found.rp_id || (p.call.kind === "get" && found.candidates.length === 0)) {
    finish(id, BROWSER);
    throw new DaemonError("not_found", "Klav has no passkey for this site");
  }
  state.rp_id = found.rp_id;
  if (p.call.kind === "get") {
    // Picked in the field menu: only that one, and presence right away.
    const chosen = p.chosen === undefined ? undefined : found.candidates.find((c) => c.item === p.chosen);
    state.candidates = chosen ? [chosen] : found.candidates;
    if (chosen) state.chosen = chosen.item;
  } else {
    // Logins of this page the passkey can go into (klavd refuses one that
    // holds another account's passkey); the account's own login first.
    const s = await daemon().call<Suggestions>({ op: "suggest", url: p.url });
    const name = p.call.user_name;
    state.logins = [...s.logins].sort((a, b) => Number(b.username === name) - Number(a.username === name));
  }
  return state;
}

/** Signs in with the passkey of `item`; klavd asks for presence (Touch ID, or `password`). */
export async function passkeySignIn(id: string, item: string, password: string | undefined): Promise<null> {
  const p = live(id);
  if (p.call.kind !== "get") throw new DaemonError("bad_request", "not a sign-in");
  const assertion = await daemon().call<Assertion>({
    op: "passkey_get",
    origin: p.url,
    ...(p.call.rp_id !== undefined ? { rp_id: p.call.rp_id } : {}),
    challenge: p.call.challenge,
    item,
    ...(password !== undefined ? { password } : {}),
  });
  finish(id, { status: "asserted", credential: credentialOf(assertion) });
  return null;
}

/**
 * Saves the new passkey (in `item`, else a new login). `exists`: the
 * account already has a passkey in Klav; the surface asks and retries with
 * `replace`.
 */
export async function passkeySave(
  id: string,
  options: { item?: string; replace?: boolean; password?: string },
): Promise<{ exists?: { item: string; title: string } }> {
  const p = live(id);
  const call = p.call;
  if (call.kind !== "create") throw new DaemonError("bad_request", "not a registration");
  const outcome = await daemon().call<PasskeyCreateOutcome>({
    op: "passkey_create",
    request: {
      origin: p.url,
      ...(call.rp_id !== undefined ? { rp_id: call.rp_id } : {}),
      ...(call.rp_name ? { rp_name: call.rp_name } : {}),
      user_id: call.user_id,
      user_name: call.user_name,
      ...(call.user_display_name ? { user_display_name: call.user_display_name } : {}),
      challenge: call.challenge,
      exclude_credentials: call.exclude,
      ...(options.item ? { item: options.item } : {}),
      ...(options.replace ? { replace: true } : {}),
    },
    ...(options.password !== undefined ? { password: options.password } : {}),
  });
  switch (outcome.status) {
    case "created": {
      const credential = {
        credential_id: outcome.credential_id,
        client_data_json: outcome.client_data_json,
        attestation_object: outcome.attestation_object,
        authenticator_data: outcome.authenticator_data,
        public_key: outcome.public_key,
        public_key_algorithm: outcome.public_key_algorithm,
        transports: outcome.transports,
      };
      finish(id, { status: "created", credential, cred_props: call.cred_props });
      return {};
    }
    case "browser":
      finish(id, BROWSER);
      return {};
    case "excluded":
      // Only now, after the person agreed (T86).
      finish(id, failure("InvalidStateError", "The authenticator already holds one of the excluded credentials."));
      return {};
    case "exists":
      return { exists: { item: outcome.item, title: outcome.title } };
  }
}

/** «Use another device»: the browser's own authenticator. */
export function passkeyBrowser(id: string): null {
  live(id);
  finish(id, BROWSER);
  return null;
}

/**
 * The person closed the surface. A conditional call goes back to waiting
 * in the field menu (the person may still type a password); any other is
 * `NotAllowedError`.
 */
export function passkeyClosed(id: string): void {
  const p = pending.get(id);
  if (p?.chosen !== undefined) {
    delete p.chosen;
    void toTop(p.tabId, { type: "passkey_hide", id });
    return;
  }
  finish(id, failure("NotAllowedError", "The operation either timed out or was not allowed."));
}

/** The conditional call waiting in the menu's frame, if any (the same document). */
function conditionalIn(menu: MenuFrame): Pending | undefined {
  for (const p of pending.values()) {
    if (p.call.kind !== "get" || p.call.conditional !== true) continue;
    if (p.tabId !== menu.tabId || p.frameId !== menu.frameId) continue;
    if (p.documentId && menu.documentId && p.documentId !== menu.documentId) continue;
    return p;
  }
  return undefined;
}

/** Whether the page waits for a passkey in this frame and the person has not picked one yet. */
export function passkeyWaiting(frame: MenuFrame): boolean {
  const p = conditionalIn(frame);
  return p !== undefined && p.chosen === undefined;
}

/**
 * The passkeys the field menu offers (Klav unlocked): those of the
 * conditional call waiting in its frame. None for the site: the call goes
 * to the browser, which may have some (T86).
 */
export async function menuPasskeys(menu: MenuFrame): Promise<PasskeyCandidate[] | undefined> {
  const p = conditionalIn(menu);
  if (!p) return undefined;
  let found: PasskeyCandidates;
  try {
    found = await candidatesFor(p);
  } catch {
    finish(p.id, BROWSER);
    return undefined;
  }
  if (!found.rp_id || found.candidates.length === 0) {
    finish(p.id, BROWSER);
    return undefined;
  }
  return found.candidates;
}

/** The person picked `item` in the field menu: Klav's frame opens to confirm presence. */
export async function menuPasskeyChoose(menu: MenuFrame, item: string): Promise<void> {
  const p = conditionalIn(menu);
  if (!p) throw new DaemonError("not_found", "this passkey request is over");
  const found = await candidatesFor(p);
  if (!found.candidates.some((c) => c.item === item)) throw new DaemonError("not_found", "Klav has no such passkey for this site");
  p.chosen = item;
  await showFrame(p.tabId, p.id);
}

/** «Use another device» in the field menu: the browser's own conditional UI. */
export function menuPasskeyBrowser(menu: MenuFrame): void {
  const p = conditionalIn(menu);
  if (!p) throw new DaemonError("not_found", "this passkey request is over");
  finish(p.id, BROWSER);
}
