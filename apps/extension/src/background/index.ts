import { ext, fromExtensionPage } from "../shared/ext";
import type {
  Advance,
  CardState,
  ContentMessage,
  FieldRole,
  FieldRules,
  FillReply,
  FindState,
  Group,
  MenuState,
  PageMessage,
  Reply,
  StepRole,
  StopReason,
  Surface,
  ToContent,
} from "../shared/messages";
import { cleanRules, forgetValues, toErrorBody } from "../shared/messages";
import {
  type AutofillValues,
  DaemonError,
  type DaemonStatus,
  type FillValue,
  type ItemView,
  type Request,
  type Suggestion,
  type Suggestions,
} from "../shared/protocol";
import { klavCore } from "../shared/wasm";
import { notices, onHere, onRotateHere, startAgents, whereIs } from "./agents";
import { copied, startClipboard } from "./clipboard";
import { NativeBridge } from "./native";
import {
  menuPasskeyBrowser,
  menuPasskeyChoose,
  menuPasskeys,
  onPasskeyCancel,
  onPasskeyRequest,
  passkeyBrowser,
  passkeyClosed,
  passkeyFrameIn,
  passkeyLoad,
  passkeySave,
  passkeySignIn,
  passkeyTab,
  passkeyWaiting,
  startPasskeys,
} from "./passkeys";
import { endFlow, FLOW_MS, type Flow, type FlowFrame, flowOf, nextStage, setFlow } from "./flow";
import { closeSave, doSave, forgetTab, loadSave, offerSite, pendingFor, siteOfferHere, submitSeen, tabOfSave } from "./save";
import { GUARDED_IN_MENU, mayCall, pageOf } from "./surfaces";

const bridge = new NativeBridge();
startAgents(bridge);
startClipboard();
startPasskeys(bridge, (tabId) => {
  closeCardsOf(tabId, false);
});

/**
 * A frame Klav may fill, as the browser describes it (`sender`), never as
 * the page does: the URL decides which logins match, and the frame and
 * document decide where values go.
 */
interface Frame {
  tabId: number;
  frameId: number;
  documentId: string | undefined;
  url: string;
  opened: number;
}

/** A frame plus the token its content script fills with (a menu, a form, a palette). */
interface Target extends Frame {
  token: string;
}

interface Menu extends Frame {
  groups: Group[];
  role: FieldRole;
  stopped?: StopReason;
  rules?: FieldRules;
}

/**
 * The field's rules as a page sent them: only the three known keys, a
 * string of at most 2000 characters and lengths from 1 to 4096 (klav-core
 * checks the rest).
 */
interface Card extends Target {
  host: string;
  logins: Suggestion[];
}

const TTL_MS = 10 * 60_000;
const menus = new Map<string, Menu>();
const cards = new Map<string, Card>();
const finds = new Map<string, Target>();
/** Tabs and hosts where the person closed the top card: not again this session. */
const dismissed = new Set<string>();

function live<T extends Frame>(map: Map<string, T>, id: string, what: string): T {
  const v = map.get(id);
  if (!v || Date.now() - v.opened > TTL_MS) {
    map.delete(id);
    throw new DaemonError("not_found", `this ${what} is closed: focus the field again`);
  }
  return v;
}

/**
 * The login just filled in each tab, when it has a one-time code: the next
 * page's code field offers it first (two-step sign-ins). Two minutes.
 */
const RECENT_MS = 2 * 60_000;
const recent = new Map<number, { login: Suggestion; at: number }>();

function recentFor(tabId: number): Suggestion | undefined {
  const r = recent.get(tabId);
  if (!r) return undefined;
  if (Date.now() - r.at > RECENT_MS) {
    recent.delete(tabId);
    return undefined;
  }
  return r.login;
}

/** A login with a code was just filled in `tabId`: its code page will offer it. */
function rememberLogin(tabId: number, values: AutofillValues): void {
  if (values.kind === "login" && values.fields.some((f) => f.kind === "totp")) {
    const username = values.fields.find((f) => f.kind === "username")?.value;
    const login: Suggestion = { id: values.id, kind: "login", title: values.title, location: "", totp: true, ...(username ? { username } : {}) };
    recent.set(tabId, { login, at: Date.now() });
  }
}

/** Sends a message to one frame (and document). */
function toFrame<T>(f: Pick<Frame, "tabId" | "frameId" | "documentId">, message: ToContent): Promise<T> {
  const options: { frameId: number; documentId?: string } = { frameId: f.frameId };
  // Firefox has no documentId; there the content script checks the token.
  if (__TARGET__ === "chromium" && f.documentId) options.documentId = f.documentId;
  return ext.tabs.sendMessage<ToContent, T>(f.tabId, message, options);
}

/**
 * Acts on a choice made in a surface only if the page in which it is drawn
 * (`where`) leaves it alone: shown long enough, nothing over it, not
 * restyled or moved (T62; `content/cover.ts`). Also where the browser has
 * no IntersectionObserver v2 (Firefox).
 */
async function ensureClear(where: Pick<Frame, "tabId" | "frameId" | "documentId">, surface: Surface, id: string): Promise<void> {
  const clear = await toFrame<boolean | undefined>(where, { type: "clear", surface, id }).catch(() => undefined);
  if (clear !== true) throw new DaemonError("covered", "the page covers Klav's frame: nothing was done");
}

/** The top frame of a tab, where the card, palette and save bar are drawn. */
function topOf(tabId: number): Pick<Frame, "tabId" | "frameId" | "documentId"> {
  return { tabId, frameId: 0, documentId: undefined };
}

/** Sends a message to the top frame of a tab (the card, palette, save bar and notices live there). */
function toTop(tabId: number, message: ToContent): Promise<unknown> {
  return ext.tabs.sendMessage(tabId, message, { frameId: 0 }).catch(() => undefined);
}

function hostOf(url: string): string | undefined {
  try {
    return new URL(url).hostname;
  } catch {
    return undefined;
  }
}

/**
 * What matches a frame. A login goes to a frame inside another page only
 * if it also matches the page on top (the address bar the person sees):
 * a framed sign-in of the same site (`idmsa.apple.com` inside
 * `appleid.apple.com`, for an item of `apple.com`), never a login of the
 * framed site inside someone else's page.
 */
async function suggestionsFor(f: Frame): Promise<Suggestions> {
  const s = await bridge.call<Suggestions>({ op: "suggest", url: f.url });
  if (f.frameId === 0) return s;
  // Logins saved for a subdomain (ADR 0025) only for the page on top, where
  // the person sees the address.
  const framed = { ...s, parent: [] };
  if (s.logins.length === 0) return framed;
  const top = await whereIs(f.tabId).catch(() => undefined);
  if (!top) return { ...framed, logins: [] };
  const onTop = await bridge.call<Suggestions>({ op: "suggest", url: top.url });
  const ids = new Set(onTop.logins.map((l) => l.id));
  return { ...framed, logins: s.logins.filter((l) => ids.has(l.id)) };
}

/**
 * The login `item` of the «Saved for a subdomain» group that the person
 * picked for the page at `url` (ADR 0025 §2): klavd offered it as `parent`
 * there, and klav-core (WASM) says the same of the item's URLs. Throws
 * `denied` otherwise.
 */
async function parentLogin(url: string, item: string, offered?: Suggestions): Promise<Suggestion> {
  const s = offered ?? (await bridge.call<Suggestions>({ op: "suggest", url }));
  const login = s.parent?.find((l) => l.id === item);
  const core = await klavCore();
  const host = core.fillableHost(url);
  const view = login ? await bridge.call<ItemView>({ op: "view", query: item, reveal: false }) : undefined;
  if (!login || !host || view?.kind !== "login" || core.hostRelation(host, view.urls) !== "parent") {
    throw new DaemonError("denied", "this login is not saved for a subdomain of this page");
  }
  return login;
}

/** After a login of the parent group was filled: «Add <host> to this item» in the save bar. */
async function offerAddSite(tabId: number, url: string, login: Suggestion): Promise<void> {
  const host = (await klavCore()).fillableHost(url);
  if (!host) return;
  const id = offerSite(tabId, url, host, login);
  await toTop(tabId, { type: "show", surface: "save", id }).catch(() => undefined);
}

/**
 * A login's values for a frame where it does not match, after the person
 * confirmed it in the palette with that frame's host in view. Only the
 * username and password; never the one-time code's seed.
 */
async function valuesElsewhere(item: string): Promise<AutofillValues> {
  const view = await bridge.call<ItemView>({ op: "view", query: item, reveal: true });
  try {
    if (view.kind !== "login") throw new DaemonError("denied", "only logins need a confirmation");
    const fields: FillValue[] = [];
    for (const f of view.fields) {
      if ((f.kind === "username" || f.kind === "password") && f.filled && f.value) fields.push({ name: f.name, kind: f.kind, value: f.value });
    }
    return { id: view.id, kind: "login", title: view.title, fields };
  } finally {
    for (const f of view.fields) delete f.value;
  }
}

/**
 * Fills `item` into the frame of `target`. klavd checks the item against
 * the frame's URL (anti-phishing); a framed sign-in must also match the
 * page on top. `confirmed` (palette only) fills a login of another site
 * the person chose knowingly.
 */
interface Filled extends FillReply {
  /** The item has a one-time code (a next step may ask for it). */
  hasTotp: boolean;
  /** A login of the «Saved for a subdomain» group went in (ADR 0025): no steps follow. */
  parent?: Suggestion;
}

async function fillItem(
  target: Target,
  item: string,
  options: { part?: "all" | "totp" | "pending"; confirmed?: boolean; advance?: Advance; parent?: boolean } = {},
): Promise<Filled> {
  let values: AutofillValues;
  const offered = await suggestionsFor(target);
  const matching = offered.logins.some((l) => l.id === item);
  // The person picked a login saved for a subdomain of this page: klavd
  // fills it only with `chosen`, and never its code alone or a pending one.
  const parent = options.parent && !matching ? await parentLogin(target.url, item, offered) : undefined;
  try {
    values = await bridge.call<AutofillValues>({
      op: "autofill",
      item,
      url: target.url,
      ...(options.part && !parent ? { part: options.part } : {}),
      ...(parent ? { chosen: true } : {}),
    });
    if (values.kind === "login" && !matching && !parent) {
      values.fields.length = 0;
      throw new DaemonError("denied", "this login is not of the page on top");
    }
  } catch (e) {
    // A login of another site: only after the person confirmed it, and only
    // into a page Klav fills at all (https, or http on this machine): the
    // confirmation never sends a password over plain http to another host.
    // One saved for a subdomain of the page never goes this way.
    if (parent || !(e instanceof DaemonError && e.code === "denied" && options.confirmed)) throw e;
    if (!(await klavCore()).fillableHost(target.url)) {
      throw new DaemonError("denied", "Klav only fills into https pages (or http on this machine)");
    }
    values = await valuesElsewhere(item);
  }
  if (options.part !== "totp" && matching) rememberLogin(target.tabId, values);
  const hasTotp = values.kind === "login" && values.fields.some((f) => f.kind === "totp");
  // Pressing buttons is only for logins of the page (never after a confirmation).
  const advance = matching && values.kind === "login" ? options.advance : undefined;
  try {
    const message: ToContent = { type: "fill", token: target.token, kind: values.kind, values: values.fields, ...(advance ? { advance } : {}) };
    const reply = await toFrame<FillReply | undefined>(target, message);
    if (!reply) throw new DaemonError("disconnected", "the page closed before Klav could fill it");
    return { ...reply, hasTotp, ...(parent ? { parent } : {}) };
  } finally {
    values.fields.length = 0;
  }
}

// ------------------------------------------------- sign-in in steps --

/** «Solo rellenar, no pulsar» (popup settings): Klav types but presses nothing. */
async function pressButtons(): Promise<boolean> {
  const stored: Record<string, unknown> = await ext.storage.local.get("onlyFill").catch(() => ({}));
  return stored.onlyFill !== true;
}

/** The first fill of a login presses «Continuar» only on a form that asks just for the account. */
async function firstAdvance(): Promise<Advance | undefined> {
  return (await pressButtons()) ? "identifier" : undefined;
}

/** After a login went into `frame`: follow its next step, if there is one. */
async function followSteps(frame: FlowFrame, item: string, reply: Filled): Promise<void> {
  if (reply.blocked) {
    endFlow(frame.tabId);
    await toFrameOrTop(frame, { type: "flow_stop", reason: reply.blocked });
    return;
  }
  // The code goes in by itself only while Klav drives the sign-in (it pressed
  // a button, or it is already following the steps). After a one-page login
  // the person sent, the code page offers the code and waits for a click.
  const old = flowOf(frame.tabId);
  const driving = reply.submitted === true || old?.item === item;
  const stage = nextStage(reply, reply.hasTotp && driving);
  if (!stage) {
    endFlow(frame.tabId);
    return;
  }
  const until = Date.now() + FLOW_MS;
  setFlow(
    frame.tabId,
    { item, stage, until: old?.item === item ? old.until : until, press: await pressButtons(), last: frame },
    (stuck) => {
      endFlow(frame.tabId);
      void toFrameOrTop(stuck.last, { type: "flow_stop", reason: stuck.elsewhere ? "other_site" : "no_password" });
    },
  );
  // Every frame of the tab watches for the next field (a new document asks with `flow_ask`).
  await ext.tabs.sendMessage(frame.tabId, { type: "flow", until } satisfies ToContent).catch(() => undefined);
}

/** To the frame of the last step; if that document is gone (it navigated), to the tab's top frame. */
async function toFrameOrTop(frame: FlowFrame, message: ToContent): Promise<void> {
  try {
    await toFrame(frame, message);
  } catch {
    await toTop(frame.tabId, message);
  }
}

/** A frame of the tab shows the field of the step Klav waits for: fill it. */
async function onStep(frame: Frame, role: StepRole, token: string): Promise<void> {
  const flow = flowOf(frame.tabId);
  if (!flow || flow.busy || flow.stage !== role) return;
  // Each step checks the frame again: a frame of another site gets nothing
  // (the wait then ends saying where the password was asked for).
  const s = await suggestionsFor(frame).catch(() => undefined);
  if (!s?.logins.some((l) => l.id === flow.item)) {
    if (role === "password") flow.elsewhere = true;
    return;
  }
  // Another report may have started this step meanwhile (TypeScript cannot see it change across the await).
  if ((flow.busy as boolean) || flowOf(frame.tabId) !== flow) return;
  flow.busy = true;
  let reply: Filled;
  try {
    reply = await fillItem({ ...frame, token }, flow.item, {
      ...(role === "otp" ? { part: "totp" as const } : {}),
      ...(flow.press ? { advance: "always" as const } : {}),
    });
  } catch (e) {
    endFlow(frame.tabId);
    // Not this item's site (klavd or the page on top said no): say so on the field.
    if (e instanceof DaemonError && e.code === "denied" && role === "password") await toFrameOrTop(frame, { type: "flow_stop", reason: "other_site" });
    return;
  } finally {
    flow.busy = false;
  }
  if (reply.filled.length === 0) return;
  // The step's form may have brought the top card back: Klav already filled it.
  closeCardsOf(frame.tabId, false);
  const last: FlowFrame = { tabId: frame.tabId, frameId: frame.frameId, documentId: frame.documentId };
  if (role === "otp") {
    endFlow(frame.tabId);
    if (reply.blocked) await toFrameOrTop(last, { type: "flow_stop", reason: reply.blocked });
    return;
  }
  await followSteps(last, flow.item, reply);
}

/** A new top document: if the tab left the item's site, the sign-in in steps is over. */
async function checkFlowSite(frame: Frame, flow: Flow): Promise<boolean> {
  if (frame.frameId !== 0) return true;
  const s = await bridge.call<Suggestions>({ op: "suggest", url: frame.url }).catch(() => undefined);
  if (s?.logins.some((l) => l.id === flow.item)) return true;
  endFlow(frame.tabId);
  return false;
}

/** The active tab's address for the popup, or null if Klav does not run there. */
async function popupHere(): Promise<{ url: string } | null> {
  const [tab] = await ext.tabs.query({ active: true, lastFocusedWindow: true });
  if (tab?.id === undefined) return null;
  try {
    return { url: (await whereIs(tab.id)).url };
  } catch {
    return null;
  }
}

/**
 * Fills `item` into the active tab, from the popup. The address comes from
 * the browser (`whereIs`), klavd checks the item against it, and the
 * values go only to that tab's top document.
 */
async function popupFill(item: string, fromParent = false): Promise<{ filled: number }> {
  const [tab] = await ext.tabs.query({ active: true, lastFocusedWindow: true });
  if (tab?.id === undefined) throw new DaemonError("not_found", "no tab is open in the browser");
  const here = await whereIs(tab.id);
  // A login of «Saved for a subdomain» (ADR 0025): only with `chosen`, and
  // only if it still is one for this page.
  let parent: Suggestion | undefined;
  if (fromParent) {
    const s = await bridge.call<Suggestions>({ op: "suggest", url: here.url });
    if (!s.logins.some((l) => l.id === item)) parent = await parentLogin(here.url, item, s);
  }
  const values = await bridge.call<AutofillValues>({ op: "autofill", item, url: here.url, ...(parent ? { chosen: true } : {}) });
  if (!parent) rememberLogin(tab.id, values);
  const options: { frameId: number; documentId?: string } = { frameId: 0 };
  if (__TARGET__ === "chromium" && here.documentId) options.documentId = here.documentId;
  const hasTotp = values.kind === "login" && values.fields.some((f) => f.kind === "totp");
  const advance = values.kind === "login" && !parent ? await firstAdvance() : undefined;
  const result = await ext.tabs
    .sendMessage<ToContent, FillReply | undefined>(tab.id, { type: "popup_fill", doc: here.doc, kind: values.kind, values: values.fields, ...(advance ? { advance } : {}) }, options)
    .finally(() => {
      values.fields.length = 0;
    });
  if (!result) throw new DaemonError("disconnected", "the page did not answer: reload it and try again");
  if (parent) {
    if (result.filled.length > 0) await offerAddSite(tab.id, here.url, parent);
    return { filled: result.filled.length };
  }
  await followSteps({ tabId: tab.id, frameId: 0, documentId: options.documentId }, item, { ...result, hasTotp });
  return { filled: result.filled.length };
}

/** Opens the palette in the top frame, to fill `target`'s frame. */
async function openFind(target: Target): Promise<void> {
  for (const [id, f] of finds) if (f.tabId === target.tabId || Date.now() - f.opened > TTL_MS) finds.delete(id);
  finds.set(target.token, target);
  await toTop(target.tabId, { type: "show", surface: "find", id: target.token });
}

function closeCard(id: string, dismiss: boolean): void {
  const c = cards.get(id);
  cards.delete(id);
  if (!c) return;
  if (dismiss) dismissed.add(`${String(c.tabId)}|${c.host}`);
  void toTop(c.tabId, { type: "hide", surface: "card", id });
}

/** The person typed or filled: the tab's card goes away. */
function closeCardsOf(tabId: number, dismiss: boolean): void {
  for (const [id, c] of cards) if (c.tabId === tabId) closeCard(id, dismiss);
}

/** A sign-in form appeared: offer the top card if Klav has a login for it. */
async function offerCard(target: Target): Promise<void> {
  const host = hostOf(target.url);
  if (!host || dismissed.has(`${String(target.tabId)}|${host}`)) return;
  // Klav is already following a sign-in in steps in this tab, or its passkey frame is open there.
  if (flowOf(target.tabId) || passkeyFrameIn(target.tabId)) return;
  for (const c of cards.values()) if (c.tabId === target.tabId) return;
  const status = await bridge.call<DaemonStatus>({ op: "status" });
  if (!status.unlocked) return;
  const s = await suggestionsFor(target);
  if (s.logins.length === 0) return;
  const id = crypto.randomUUID();
  cards.set(id, { ...target, host: s.host ?? host, logins: s.logins });
  await toTop(target.tabId, { type: "show", surface: "card", id });
}

async function handlePage(message: PageMessage, sender: chrome.runtime.MessageSender): Promise<unknown> {
  switch (message.type) {
    case "daemon": {
      // Each page only what it shows (`surfaces.ts`).
      const op = (message.request as { op?: unknown } | undefined)?.op;
      if (!mayCall(sender.url, op)) throw new DaemonError("denied", "this part of the extension cannot do that");
      // Copying or clearing the generator history from a menu in a page: only on an uncovered menu.
      if (pageOf(sender.url) === "menu.html" && GUARDED_IN_MENU.has(op as never)) {
        const menuId = new URL(sender.url ?? "").hash.slice(1);
        await ensureClear(live(menus, menuId, "menu"), "menu", menuId);
      }
      // Only Klav's passkey frame unlocks «for» a passkey use (ADR 0020 §8),
      // whatever a page put in the request.
      const request: Request =
        message.request.op === "unlock" ? { ...message.request, passkey_flow: pageOf(sender.url) === "passkey.html" } : message.request;
      try {
        return await bridge.call(request);
      } finally {
        forgetValues(message.request);
      }
    }
    case "menu_load": {
      const m = live(menus, message.menuId, "menu");
      const status = await bridge.call<DaemonStatus>({ op: "status" });
      const host = hostOf(m.url);
      const state: MenuState = { groups: m.groups, role: m.role, status, page: m.url, ...(host ? { host } : {}), ...(m.stopped ? { stopped: m.stopped } : {}), ...(m.rules ? { rules: m.rules } : {}) };
      if (status.unlocked) {
        state.suggestions = await suggestionsFor(m);
        const last = m.role === "otp" ? recentFor(m.tabId) : undefined;
        // Only if it is still one of this page's logins.
        if (last && state.suggestions.logins.some((l) => l.id === last.id)) state.recent = last;
        // The page waits for a passkey in this frame (conditional mediation): on a sign-in field.
        if (m.role === "login") {
          const passkeys = await menuPasskeys(m);
          if (passkeys) state.passkeys = passkeys;
        }
      }
      return state;
    }
    case "menu_passkey": {
      const m = live(menus, message.menuId, "menu");
      await ensureClear(m, "menu", message.menuId);
      await menuPasskeyChoose(m, message.item);
      menus.delete(message.menuId);
      await toFrame(m, { type: "hide", surface: "menu", id: message.menuId }).catch(() => undefined);
      return null;
    }
    case "menu_passkey_browser": {
      const m = live(menus, message.menuId, "menu");
      menuPasskeyBrowser(m);
      menus.delete(message.menuId);
      await toFrame(m, { type: "hide", surface: "menu", id: message.menuId }).catch(() => undefined);
      return null;
    }
    case "menu_fill": {
      const m = live(menus, message.menuId, "menu");
      await ensureClear(m, "menu", message.menuId);
      const part = message.part === "totp" || message.part === "pending" ? message.part : undefined;
      const advance = part === "totp" ? undefined : await firstAdvance();
      const parent = message.parent === true;
      const reply = await fillItem({ ...m, token: message.menuId }, message.item, {
        ...(part ? { part } : {}),
        ...(advance && !parent ? { advance } : {}),
        ...(parent ? { parent } : {}),
      });
      menus.delete(message.menuId);
      closeCardsOf(m.tabId, false);
      if (reply.parent) {
        if (reply.filled.length > 0) await offerAddSite(m.tabId, m.url, reply.parent);
      } else if (message.part !== "totp") {
        await followSteps(m, message.item, reply);
      }
      return { filled: reply.filled.length };
    }
    case "menu_generated": {
      const m = live(menus, message.menuId, "menu");
      await ensureClear(m, "menu", message.menuId);
      const result = await toFrame<{ filled: number } | undefined>(m, { type: "fill_generated", menuId: message.menuId, value: message.value });
      menus.delete(message.menuId);
      return result ?? { filled: 0 };
    }
    case "menu_find": {
      const m = live(menus, message.menuId, "menu");
      await ensureClear(m, "menu", message.menuId);
      const token = crypto.randomUUID();
      // The field's frame learns the palette's token before its menu closes.
      await toFrame(m, { type: "expect", token, menuId: message.menuId }).catch(() => undefined);
      menus.delete(message.menuId);
      await toFrame(m, { type: "hide", surface: "menu", id: message.menuId }).catch(() => undefined);
      await openFind({ tabId: m.tabId, frameId: m.frameId, documentId: m.documentId, url: m.url, opened: Date.now(), token });
      return null;
    }
    case "card_load": {
      const c = live(cards, message.cardId, "card");
      const [login] = c.logins;
      if (!login) throw new DaemonError("not_found", "nothing to offer");
      return { host: c.host, page: c.url, login, others: c.logins.length - 1 } satisfies CardState;
    }
    case "card_fill": {
      const c = live(cards, message.cardId, "card");
      await ensureClear(topOf(c.tabId), "card", message.cardId);
      const item = message.item ?? c.logins[0]?.id;
      if (!item || !c.logins.some((l) => l.id === item)) throw new DaemonError("not_found", "that login is not offered here");
      const advance = await firstAdvance();
      const reply = await fillItem(c, item, advance ? { advance } : {});
      closeCard(message.cardId, false);
      await followSteps(c, item, reply);
      return { filled: reply.filled.length };
    }
    case "card_find": {
      const c = live(cards, message.cardId, "card");
      await ensureClear(topOf(c.tabId), "card", message.cardId);
      closeCard(message.cardId, false);
      await openFind({ ...c, opened: Date.now() });
      return null;
    }
    case "find_load": {
      const f = live(finds, message.findId, "palette");
      const status = await bridge.call<DaemonStatus>({ op: "status" });
      const host = (await klavCore()).fillableHost(f.url);
      const state: FindState = { status, page: f.url, ...(host ? { host } : {}) };
      if (status.unlocked) state.suggestions = await suggestionsFor(f);
      return state;
    }
    case "find_fill": {
      const f = live(finds, message.findId, "palette");
      await ensureClear(topOf(f.tabId), "find", message.findId);
      const advance = await firstAdvance();
      const parent = message.parent === true;
      const reply = await fillItem(f, message.item, {
        ...(message.confirmed && !parent ? { confirmed: true } : {}),
        ...(advance && !parent ? { advance } : {}),
        ...(parent ? { parent } : {}),
      });
      finds.delete(message.findId);
      // A login of another site, filled after a confirmation, is not followed
      // further; one saved for a subdomain offers to add this site.
      if (reply.parent) {
        if (reply.filled.length > 0) await offerAddSite(f.tabId, f.url, reply.parent);
      } else if (!message.confirmed) {
        await followSteps(f, message.item, reply);
      }
      closeCardsOf(f.tabId, false);
      await toTop(f.tabId, { type: "hide", surface: "find", id: message.findId });
      return { filled: reply.filled.length };
    }
    case "notice_load": {
      const n = notices.get(message.noticeId);
      if (!n) throw new DaemonError("not_found", "this notice expired");
      return { agent: n.agent, reason: n.reason, ...(n.rotated ? { rotated: true } : {}), ...(n.passkey !== undefined ? { passkey: n.passkey } : {}) };
    }
    case "size": {
      if (message.surface === "menu") {
        const m = live(menus, message.id, "menu");
        await toFrame(m, { type: "size", surface: "menu", id: message.id, height: message.height }).catch(() => undefined);
      } else if (sender.tab?.id !== undefined) {
        // The other surfaces are frames of the top document of their tab.
        await toTop(sender.tab.id, { type: "size", surface: message.surface, id: message.id, height: message.height });
      }
      return null;
    }
    case "close":
      await closeSurface(message.surface, message.id, sender.tab?.id);
      return null;
    case "copied":
      await copied();
      return null;
    case "popup_here":
      return popupHere();
    case "popup_fill":
      return popupFill(message.item, message.parent === true);
    case "save_load":
      return (await loadSave(bridge, message.saveId)) ?? null;
    case "save_do": {
      const tab = tabOfSave(message.saveId);
      if (tab === undefined) throw new DaemonError("not_found", "nothing to save any more");
      await ensureClear(topOf(tab), "save", message.saveId);
      if (message.action === "add_site") await siteOfferHere(message.saveId, (await whereIs(tab)).url);
      // The bar says "saved" and then closes itself.
      return doSave(bridge, message.saveId, message.action, message.title, message.project, message.item);
    }
    case "passkey_load":
      return passkeyLoad(message.passkeyId);
    case "passkey_sign_in":
      await ensureClear(topOf(passkeyTab(message.passkeyId)), "passkey", message.passkeyId);
      return passkeySignIn(message.passkeyId, message.item, message.password);
    case "passkey_save":
      await ensureClear(topOf(passkeyTab(message.passkeyId)), "passkey", message.passkeyId);
      return passkeySave(message.passkeyId, {
        ...(message.item ? { item: message.item } : {}),
        ...(message.replace ? { replace: true } : {}),
        ...(message.password !== undefined ? { password: message.password } : {}),
      });
    case "passkey_browser":
      return passkeyBrowser(message.passkeyId);
  }
}

/** Closes a surface (asked by the surface itself, from its own page). */
async function closeSurface(surface: Surface, id: string, tabId: number | undefined): Promise<void> {
  switch (surface) {
    case "menu": {
      const m = menus.get(id);
      menus.delete(id);
      if (m) await toFrame(m, { type: "hide", surface, id }).catch(() => undefined);
      return;
    }
    case "card":
      closeCard(id, true);
      return;
    case "find": {
      const f = finds.get(id);
      finds.delete(id);
      const tab = f?.tabId ?? tabId;
      if (tab !== undefined) await toTop(tab, { type: "hide", surface, id });
      return;
    }
    case "save": {
      const tab = tabId ?? tabOfSave(id);
      closeSave(id);
      if (tab !== undefined) await toTop(tab, { type: "hide", surface, id });
      return;
    }
    case "notice":
      if (tabId !== undefined) await toTop(tabId, { type: "hide", surface, id });
      return;
    case "passkey":
      passkeyClosed(id);
      return;
  }
}

function frameOf(sender: chrome.runtime.MessageSender): Frame {
  const tabId = sender.tab?.id;
  const url = sender.url;
  if (tabId === undefined || sender.frameId === undefined || !url || !/^https?:/.test(url)) {
    throw new DaemonError("denied", "not a web page");
  }
  return { tabId, frameId: sender.frameId, documentId: sender.documentId, url, opened: Date.now() };
}

function handleContent(message: ContentMessage, sender: chrome.runtime.MessageSender): unknown {
  // WebAuthn calls decide for themselves (a frame Klav does not answer goes to the browser).
  if (message.type === "passkey_request") return onPasskeyRequest(message, sender);
  if (message.type === "passkey_cancel") {
    if (typeof message.id === "string") onPasskeyCancel(message.id, sender);
    return null;
  }
  const frame = frameOf(sender);
  const { tabId } = frame;
  switch (message.type) {
    case "menu_open": {
      for (const [id, m] of menus) if (Date.now() - m.opened > TTL_MS || m.tabId === tabId) menus.delete(id);
      const menuId = crypto.randomUUID();
      // The page's process sent this: keep only known groups.
      const known = new Set<unknown>(["login", "card", "identity"]);
      const groups = (Array.isArray(message.groups) ? message.groups : []).filter((g) => known.has(g));
      const roles = new Set<unknown>(["login", "new-password", "otp", "card", "identity"]);
      const role: FieldRole = roles.has(message.role) ? message.role : "login";
      const stops = new Set<unknown>(["no_password", "captcha", "other_site"]);
      const stopped = stops.has(message.stopped) ? message.stopped : undefined;
      const rules = role === "new-password" ? cleanRules(message.rules) : undefined;
      menus.set(menuId, { ...frame, groups, role, ...(stopped ? { stopped } : {}), ...(rules ? { rules } : {}) });
      return { menuId };
    }
    case "login_seen":
      if (typeof message.token === "string" && message.token.length >= 16) void offerCard({ ...frame, token: message.token }).catch(() => undefined);
      return null;
    case "find_open": {
      const token = crypto.randomUUID();
      void openFind({ ...frame, token });
      return { findId: token };
    }
    case "typing":
      // The person took over: no top card, and no more steps.
      closeCardsOf(tabId, true);
      endFlow(tabId);
      return null;
    case "flow_ask": {
      const flow = flowOf(tabId);
      if (!flow) return null;
      return checkFlowSite(frame, flow).then((ok) => (ok ? { until: flow.until } : null));
    }
    case "step_seen":
      // The page's process sent this: check what it says.
      if (new Set<unknown>(["password", "otp"]).has(message.role) && typeof message.token === "string" && message.token.length >= 16) {
        void onStep(frame, message.role, message.token).catch(() => undefined);
      }
      return null;
    case "step_blocked": {
      const flow = flowOf(tabId);
      if (flow && (message.reason as unknown) === "captcha") {
        endFlow(tabId);
        void toFrame(frame, { type: "flow_stop", reason: "captcha" }).catch(() => undefined);
      }
      return null;
    }
    case "recent_login":
      // A code field: was a login with a code just filled in this tab?
      return recentFor(tabId) !== undefined;
    case "passkey_waiting":
      return passkeyWaiting(frame);
    case "submit_seen":
      if (typeof message.password === "string" && typeof message.username === "string") {
        void submitSeen(tabId, frame.url, message.username, message.password);
      }
      return null;
    case "save_pending":
      // Only the top document of the same site the login was sent from.
      return sender.frameId === 0 ? pendingFor(tabId, frame.url).then((id) => id ?? null) : null;
    case "here":
      onHere(message.nonce, message.doc, sender);
      return null;
    case "rotate_here":
      onRotateHere(message, sender);
      return null;
    case "close": {
      // A frame may only close what belongs to it.
      if (message.surface === "menu") {
        const m = menus.get(message.id);
        if (m?.tabId === tabId && m.frameId === sender.frameId) menus.delete(message.id);
      } else if (message.surface === "find") {
        if (finds.get(message.id)?.tabId === tabId) finds.delete(message.id);
      } else if (message.surface === "card") {
        if (cards.get(message.id)?.tabId === tabId) closeCard(message.id, true);
      }
      return null;
    }
    default:
      throw new DaemonError("bad_request", "unknown message");
  }
}

ext.runtime.onMessage.addListener(
  (message: unknown, sender: chrome.runtime.MessageSender, sendResponse: (reply: Reply<unknown>) => void) => {
    if (sender.id !== ext.runtime.id || typeof message !== "object" || message === null) return false;
    // Only our own pages may talk to klavd; content scripts (inside web
    // pages) only open menus, and never receive vault data from here.
    const work: Promise<unknown> = fromExtensionPage(sender)
      ? handlePage(message as PageMessage, sender)
      : Promise.resolve().then(() => handleContent(message as ContentMessage, sender));
    work.then(
      (value) => {
        sendResponse({ ok: true, value });
      },
      (e: unknown) => {
        sendResponse({ ok: false, error: toErrorBody(e) });
      },
    );
    return true;
  },
);

ext.tabs.onRemoved.addListener((tabId) => {
  for (const map of [menus, cards, finds] as Map<string, Frame>[]) {
    for (const [id, f] of map) if (f.tabId === tabId) map.delete(id);
  }
  for (const key of dismissed) if (key.startsWith(`${String(tabId)}|`)) dismissed.delete(key);
  recent.delete(tabId);
  endFlow(tabId);
  // A login waiting to be saved goes with its tab.
  forgetTab(tabId);
});

ext.commands.onCommand.addListener((command: string, tab?: chrome.tabs.Tab) => {
  if (command !== "fill") return;
  void (async () => {
    const id = tab?.id ?? (await ext.tabs.query({ active: true, currentWindow: true }))[0]?.id;
    // Every frame hears it; only the one with the focus answers: its field's
    // menu, or the palette when no field is focused.
    if (id !== undefined) await ext.tabs.sendMessage(id, { type: "shortcut" } satisfies ToContent).catch(() => undefined);
  })();
});
