/**
 * Agents filling the active tab (ADR 0017). The background attaches its
 * native port to klavd (`extension_attach`) and answers klavd's events:
 * `tab` (which tab is active, and where it is) and `fill` (type an agent's
 * values there if the tab is still on the host the agent checked). Page
 * addresses always come from the browser (`sender.url` of a `here`
 * message), never from what a page says.
 */
import { ext } from "../shared/ext";
import { type AgentFillResult, type AgentSelector, cleanRules, type ContentMessage, type FieldRules, type ToContent } from "../shared/messages";
import { DaemonError, type FillValue, type ItemKind } from "../shared/protocol";
import { originOf } from "../shared/origin";
import { klavCore } from "../shared/wasm";
import type { NativeBridge } from "./native";
import { armPasskey } from "./passkeys";

export interface Here {
  url: string;
  documentId: string | undefined;
  doc: string;
}

const WHERE_WAIT_MS = 3_000;

const SUBMIT_WAIT_MS = 10_000;
const waiting = new Map<string, { tabId: number; resolve: (here: Here) => void }>();

/** What the in-page notice says after an agent filled a tab or used a passkey there (kept a minute, never values). */
export const notices = new Map<string, { agent: string; reason: string; rotated?: boolean; passkey?: string }>();

/** A `here` message from a top frame (called by the message router). */
export function onHere(nonce: string, doc: string, sender: chrome.runtime.MessageSender): void {
  const w = waiting.get(nonce);
  if (!w || sender.tab?.id !== w.tabId || sender.frameId !== 0 || !sender.url) return;
  waiting.delete(nonce);
  w.resolve({ url: sender.url, documentId: sender.documentId, doc });
}

/** Where the top frame of `tabId` is, as the browser says. */
export async function whereIs(tabId: number): Promise<Here> {
  const nonce = crypto.randomUUID();
  const unreachable = (): DaemonError =>
    new DaemonError("denied", "Klav cannot fill this tab: it is not a web page, or it was open before the extension (reload it)");
  let fail: (error: DaemonError) => void = () => undefined;
  const here = new Promise<Here>((resolve, reject) => {
    fail = reject;
    waiting.set(nonce, { tabId, resolve });
    setTimeout(() => {
      if (waiting.delete(nonce)) reject(unreachable());
    }, WHERE_WAIT_MS);
  });
  // No content script in the tab (a new tab, a browser page): the browser
  // says so at once, so do not wait out WHERE_WAIT_MS.
  await ext.tabs.sendMessage(tabId, { type: "where", nonce } satisfies ToContent, { frameId: 0 }).catch(() => {
    if (waiting.delete(nonce)) fail(unreachable());
  });
  return here;
}

function browserName(): string {
  if (__TARGET__ === "firefox") return "Firefox";
  const brands = (navigator as Navigator & { userAgentData?: { brands?: { brand: string }[] } }).userAgentData?.brands ?? [];
  const named = brands.map((b) => b.brand).find((b) => !/not.a.brand|chromium/i.test(b));
  return named ?? "Chromium";
}

async function activeTab(): Promise<{ tab_id: number; url: string; focused: boolean }> {
  const win = await ext.windows.getLastFocused({});
  const [tab] = await ext.tabs.query({ active: true, lastFocusedWindow: true });
  if (tab?.id === undefined) throw new DaemonError("not_found", "no tab is open in the browser");
  const here = await whereIs(tab.id);
  return { tab_id: tab.id, url: originOf(here.url), focused: win.focused };
}

interface FillEvent {
  id: number;
  tab_id: number;
  host: string;
  agent: string;
  reason: string;
  item_kind: ItemKind;
  fields: FillValue[];
  selectors?: AgentSelector[];
  submit?: boolean;
}

async function fillTab(event: FillEvent): Promise<Record<string, unknown>> {
  const before = await whereIs(event.tab_id);
  const core = await klavCore();
  const host = core.fillableHost(before.url);
  if (host !== event.host) {
    throw new DaemonError(
      "denied",
      `the tab is now on ${host ?? "a page Klav does not fill"}, not ${event.host}: nothing was filled`,
    );
  }
  const options: { frameId: number; documentId?: string } = { frameId: 0 };
  if (__TARGET__ === "chromium" && before.documentId) options.documentId = before.documentId;
  const noticeId = crypto.randomUUID();
  notices.set(noticeId, { agent: event.agent, reason: event.reason });
  setTimeout(() => notices.delete(noticeId), 60_000);
  const message: ToContent = {
    type: "agent_fill",
    // The document whose address was checked: a new one (Firefox has no documentId) gets nothing.
    doc: before.doc,
    kind: event.item_kind,
    values: event.fields,
    noticeId,
    selectors: event.selectors ?? [],
    submit: event.submit === true,
  };
  const result = await ext.tabs.sendMessage<ToContent, AgentFillResult | undefined>(event.tab_id, message, options);
  event.fields.length = 0;
  if (!result) throw new DaemonError("not_found", "the page did not answer: reload it and try again");
  if (result.filled.length === 0) {
    throw new DaemonError("not_found", `no fields for this item on ${originOf(before.url)}: pass selectors, or ask the person to open the form`);
  }
  const report: Record<string, unknown> = { url: originOf(before.url), filled: result.filled };
  if (event.submit) {
    report.submitted = result.submitted;
    if (result.submitted) Object.assign(report, await afterSubmit(event.tab_id, before));
  }
  return report;
}

/** After a submit: whether a new page loaded in the tab within 10 s, and where it is. */
async function afterSubmit(tabId: number, before: Here): Promise<{ navigated: boolean; url_after: string }> {
  const deadline = Date.now() + SUBMIT_WAIT_MS;
  let after = before;
  while (Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 300));
    try {
      after = await whereIs(tabId);
    } catch {
      continue; // loading
    }
    if (after.doc !== before.doc) break;
  }
  return { navigated: after.doc !== before.doc, url_after: originOf(after.url) };
}

// ------------------------------------------- assisted password change --

/** How long the frames of a tab have to say they hold the focused password box. */
const PROBE_MS = 700;

interface RotateHere {
  frameId: number;
  documentId: string | undefined;
  url: string;
  token: string;
  focused: boolean;
  rules?: FieldRules;
}

const probes = new Map<string, { tabId: number; answers: RotateHere[]; focused: () => void }>();

/** A `rotate_here` from any frame of the probed tab (called by the message router). */
export function onRotateHere(message: Extract<ContentMessage, { type: "rotate_here" }>, sender: chrome.runtime.MessageSender): void {
  const p = probes.get(message.nonce);
  if (!p || sender.tab?.id !== p.tabId || sender.frameId === undefined || !sender.url) return;
  if (typeof message.token !== "string" || message.token.length < 16) return;
  const rules = cleanRules(message.rules);
  // The page's process sent this: only a real `true` counts.
  const focused = (message.focused as unknown) === true;
  p.answers.push({
    frameId: sender.frameId,
    documentId: sender.documentId,
    url: sender.url,
    token: message.token,
    focused,
    ...(rules ? { rules } : {}),
  });
  if (focused) p.focused();
}

interface ProbeEvent {
  id: number;
  tab_id: number;
  host: string;
  urls: string[];
}

/**
 * Where an assisted change (ADR 0022 §5) would fill: the frame with the
 * focused password box, if the browser says that frame is on the item's
 * site and on the host the agent signed (T61); else the top frame's change
 * form, under the same check. The address is always the browser's.
 */
async function rotateProbe(event: ProbeEvent): Promise<Record<string, unknown>> {
  const nonce = crypto.randomUUID();
  const answers: RotateHere[] = [];
  const waited = new Promise<void>((resolve) => {
    const timer = setTimeout(resolve, PROBE_MS);
    probes.set(nonce, {
      tabId: event.tab_id,
      answers,
      focused: () => {
        // The top frame answers too; give it a moment.
        setTimeout(() => {
          clearTimeout(timer);
          resolve();
        }, 100);
      },
    });
  });
  // Every frame of the tab hears it.
  await ext.tabs.sendMessage(event.tab_id, { type: "rotate_probe", nonce } satisfies ToContent).catch(() => undefined);
  await waited;
  probes.delete(nonce);
  const core = await klavCore();
  const onSite = (a: RotateHere): boolean => core.fillableHost(a.url) === event.host && core.pageMatches(a.url, event.urls);
  const pick = answers.find((a) => a.focused && onSite(a)) ?? answers.find((a) => a.frameId === 0 && onSite(a));
  if (!pick) {
    const top = answers.find((a) => a.frameId === 0);
    throw new DaemonError(
      "denied",
      top ? `the tab is on ${core.fillableHost(top.url) ?? "a page Klav does not fill"}, not on ${event.host}: nothing was filled` : "Klav cannot fill this tab: it is not a web page, or it was open before the extension (reload it)",
    );
  }
  return {
    frame_id: pick.frameId,
    ...(pick.documentId ? { document_id: pick.documentId } : {}),
    url: pick.url,
    focused: pick.focused,
    token: pick.token,
    rules: pick.rules ?? {},
  };
}

interface RotateFillEvent {
  id: number;
  tab_id: number;
  frame_id: number;
  document_id?: string;
  token: string;
  host: string;
  agent: string;
  reason: string;
  current: string;
  new: string;
  submit?: boolean;
}

/** Types an assisted change into the frame the probe found. */
async function rotateFill(event: RotateFillEvent): Promise<Record<string, unknown>> {
  const before = event.frame_id === 0 ? await whereIs(event.tab_id) : undefined;
  if (before) {
    const host = (await klavCore()).fillableHost(before.url);
    if (host !== event.host) {
      throw new DaemonError("denied", `the tab is now on ${host ?? "a page Klav does not fill"}, not ${event.host}: nothing was filled`);
    }
  }
  const options: { frameId: number; documentId?: string } = { frameId: event.frame_id };
  if (__TARGET__ === "chromium" && event.document_id) options.documentId = event.document_id;
  const noticeId = crypto.randomUUID();
  notices.set(noticeId, { agent: event.agent, reason: event.reason, rotated: true });
  setTimeout(() => notices.delete(noticeId), 60_000);
  const message: ToContent = {
    type: "rotate_fill",
    token: event.token,
    current: event.current,
    next: event.new,
    noticeId,
    submit: event.submit === true,
  };
  event.current = "";
  event.new = "";
  let result: AgentFillResult | undefined;
  try {
    result = await ext.tabs.sendMessage<ToContent, AgentFillResult | undefined>(event.tab_id, message, options);
  } finally {
    message.current = "";
    message.next = "";
  }
  if (!result) throw new DaemonError("not_found", "the page did not answer: reload it and try again");
  if (result.filled.length > 0) {
    await ext.tabs.sendMessage(event.tab_id, { type: "show", surface: "notice", id: noticeId } satisfies ToContent, { frameId: 0 }).catch(() => undefined);
  }
  if (!result.filled.includes("new_password")) {
    throw new DaemonError("not_found", "no password box to type the new password into: select the new-password field, or open the site's change form");
  }
  const report: Record<string, unknown> = { filled: result.filled };
  if (event.submit) {
    report.submitted = result.submitted;
    if (result.submitted && before) Object.assign(report, await afterSubmit(event.tab_id, before));
  }
  return report;
}

interface PasskeyArmEvent {
  id: number;
  tab_id: number;
  host: string;
  rp_id: string;
  item: string;
  title: string;
  agent: string;
  reason: string;
  token: string;
  expires_in_ms: number;
}

/**
 * An agent armed a passkey use in a tab (ADR 0020 §9): only if the tab is
 * still on the host klavd checked. The page signs in without Klav's frame,
 * and a blue notice says which passkey, for which agent and why.
 */
async function armTab(event: PasskeyArmEvent): Promise<{ used: boolean }> {
  const here = await whereIs(event.tab_id);
  const core = await klavCore();
  const host = core.fillableHost(here.url);
  if (host !== event.host) {
    throw new DaemonError("denied", `the tab is now on ${host ?? "a page Klav does not sign in"}, not ${event.host}: nothing was armed`);
  }
  const tabId = event.tab_id;
  const notify = (): void => {
    const noticeId = crypto.randomUUID();
    notices.set(noticeId, { agent: event.agent, reason: event.reason, passkey: event.title });
    setTimeout(() => notices.delete(noticeId), 60_000);
    void ext.tabs.sendMessage(tabId, { type: "agent_notice", noticeId } satisfies ToContent, { frameId: 0 }).catch(() => undefined);
  };
  const used = await armPasskey(tabId, {
    token: event.token,
    host: event.host,
    rp_id: event.rp_id,
    item: event.item,
    expires: Date.now() + Math.min(event.expires_in_ms, 60_000),
    notify,
  });
  event.token = "";
  return { used };
}

/** Attaches to klavd now and after every reconnection. */
export function startAgents(bridge: NativeBridge): void {
  const answer = (id: number, work: () => Promise<unknown>): void => {
    void work().then(
      (ok) => bridge.call({ op: "extension_reply", event: id, ok }),
      (e: unknown) => {
        const error = e instanceof DaemonError ? { code: e.code, message: e.message } : { code: "internal", message: "the extension failed" };
        return bridge.call({ op: "extension_reply", event: id, error });
      },
    ).catch(() => undefined);
  };
  bridge.onEvent((event) => {
    const id = typeof event.id === "number" ? event.id : undefined;
    if (id === undefined) return;
    if (event.kind === "tab") answer(id, activeTab);
    else if (event.kind === "fill") answer(id, () => fillTab(event as unknown as FillEvent));
    else if (event.kind === "rotate_probe") answer(id, () => rotateProbe(event as unknown as ProbeEvent));
    else if (event.kind === "rotate_fill") answer(id, () => rotateFill(event as unknown as RotateFillEvent));
    else if (event.kind === "passkey_arm") answer(id, () => armTab(event as unknown as PasskeyArmEvent));
  });
  let delay = 1_000;
  const attach = (): void => {
    bridge.call({ op: "extension_attach", browser: browserName() }).then(
      () => {
        delay = 1_000;
      },
      (e: unknown) => {
        // Not installed: wait for the person (the popup explains it).
        if (e instanceof DaemonError && e.code === "host_missing") return;
        setTimeout(attach, delay);
        delay = Math.min(delay * 2, 60_000);
      },
    );
  };
  bridge.onDisconnect((error) => {
    if (error.code !== "host_missing") setTimeout(attach, delay);
  });
  attach();
}
