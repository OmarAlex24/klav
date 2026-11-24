/**
 * Offering to save or update a login after the person sends a form. The
 * content script reports the username and password it saw at submit; the
 * background keeps them in memory only (never in extension storage), for
 * one minute, for that tab. The save bar (an extension page) never sees
 * the password: it shows the host and username and sends back a decision.
 */
import type { SaveState } from "../shared/messages";
import {
  type AutofillValues,
  DaemonError,
  type DaemonStatus,
  type ErrorCode,
  type ItemSummary,
  type ProjectSummary,
  type Suggestion,
  type Suggestions,
} from "../shared/protocol";
import { klavCore } from "../shared/wasm";
import type { NativeBridge } from "./native";

const SAVE_TTL_MS = 60_000;

/** `autofill` errors about one item, not about klavd: comparing goes on without it. */
const ITEM_ERRORS = new Set<ErrorCode>(["not_found", "invalid", "internal", "denied"]);

interface Pending {
  id: string;
  tabId: number;
  url: string;
  host: string;
  username: string;
  password: string;
  seen: number;
  timer: ReturnType<typeof setTimeout>;
}

const pending = new Map<number, Pending>();

/**
 * Step-1 username seen in a multi-step sign-in (e.g. email first, password on
 * the next screen). Kept in memory only, per tab, for 60 s and dropped if the
 * tab leaves the site or closes.
 */
interface RecentUsername {
  host: string;
  username: string;
  seen: number;
  timer: ReturnType<typeof setTimeout>;
}

const recentUsernames = new Map<number, RecentUsername>();

function forgetRecentUsername(tabId: number): void {
  const r = recentUsernames.get(tabId);
  if (r) clearTimeout(r.timer);
  recentUsernames.delete(tabId);
}

/** Records a username typed on step 1 of a multi-step sign-in. */
export async function usernameSeen(tabId: number, url: string, username: string): Promise<void> {
  const name = username.trim();
  if (!name) return;
  const host = (await klavCore()).fillableHost(url);
  if (!host) return;
  forgetRecentUsername(tabId);
  const timer = setTimeout(() => {
    if (recentUsernames.get(tabId)?.timer === timer) forgetRecentUsername(tabId);
  }, SAVE_TTL_MS + 1_000);
  recentUsernames.set(tabId, { host, username: name, seen: Date.now(), timer });
}

/**
 * Picks a free title for `base` in a project whose live items already use
 * `taken`: `base` itself if free, then `base (username)` when a username is
 * known, then `base (2)`, `base (3)`, …
 */
export function suggestFreeTitle(base: string, username: string, taken: Iterable<string>): string {
  const used = new Set<string>();
  for (const t of taken) used.add(t.trim().toLowerCase());
  const cleanBase = base.trim() || base;
  if (!used.has(cleanBase.toLowerCase())) return cleanBase;
  const user = username.trim();
  if (user) {
    const withUser = `${cleanBase} (${user})`;
    if (!used.has(withUser.toLowerCase())) return withUser;
  }
  for (let n = 2; n < 1000; n++) {
    const candidate = `${cleanBase} (${String(n)})`;
    if (!used.has(candidate.toLowerCase())) return candidate;
  }
  return cleanBase;
}

/**
 * «Add <host> to this item» (ADR 0025 §2): offered in the save bar after the
 * person filled a login saved for a subdomain of the page. It holds no
 * secret: only the item, its title and the page's address.
 */
interface SiteOffer {
  id: string;
  tabId: number;
  url: string;
  host: string;
  item: Suggestion;
  seen: number;
}

const siteOffers = new Map<string, SiteOffer>();

/** After a login of the parent group went into `url`: the bar's ID. */
export function offerSite(tabId: number, url: string, host: string, item: Suggestion): string {
  for (const [id, o] of siteOffers) if (o.tabId === tabId || Date.now() - o.seen > SAVE_TTL_MS) siteOffers.delete(id);
  const id = crypto.randomUUID();
  siteOffers.set(id, { id, tabId, url, host, item, seen: Date.now() });
  return id;
}

function forget(tabId: number): void {
  const p = pending.get(tabId);
  if (p) {
    p.password = "";
    clearTimeout(p.timer);
  }
  pending.delete(tabId);
}

/**
 * The tab closed: its login waiting to be saved goes too, and its «Add
 * this site». A login still being recorded is then not kept.
 */
export function forgetTab(tabId: number): void {
  recording.delete(tabId);
  forget(tabId);
  forgetRecentUsername(tabId);
  for (const [id, o] of siteOffers) if (o.tabId === tabId) siteOffers.delete(id);
}

/**
 * Submits still being recorded, by tab. `submitSeen` waits for klav-core
 * before it keeps anything, and the form's page navigates at once: the
 * next page's `pendingFor` can arrive first (the WebAssembly loads when a
 * stopped service worker wakes). It waits for these.
 */
const recording = new Map<number, Promise<void>>();

/**
 * A form with a password was sent in a top or same-origin frame of `tabId`.
 * The same login sent again (the click on the button, then the `submit`)
 * keeps the save it already has.
 */
export function submitSeen(tabId: number, url: string, username: string, password: string): Promise<void> {
  const done = record(tabId, url, username, password).finally(() => {
    if (recording.get(tabId) === done) recording.delete(tabId);
  });
  recording.set(tabId, done);
  return done;
}

async function record(tabId: number, url: string, username: string, password: string): Promise<void> {
  const host = (await klavCore()).fillableHost(url);
  // The tab closed meanwhile (`forgetTab`): keep nothing of it.
  if (!recording.has(tabId)) return;
  if (!host || !password) return;
  let name = username.trim();
  if (!name) {
    const recent = recentUsernames.get(tabId);
    if (recent && Date.now() - recent.seen <= SAVE_TTL_MS && sameSite(recent.host, host)) {
      name = recent.username;
    }
  }
  forgetRecentUsername(tabId);
  const before = pending.get(tabId);
  // The same login again keeps its save; so does the same password seen
  // without a username (another scope of the page), which never takes away
  // the one already captured. A username may fill in an empty one.
  const sameLogin = name === before?.username || name === "";
  if (before && before.host === host && sameLogin && before.password === password && Date.now() - before.seen <= SAVE_TTL_MS) return;
  forget(tabId);
  const timer = setTimeout(() => {
    if (pending.get(tabId)?.timer === timer) forget(tabId);
  }, SAVE_TTL_MS + 1_000);
  pending.set(tabId, { id: crypto.randomUUID(), tabId, url, host, username: name, password, seen: Date.now(), timer });
}

/**
 * Whether the host a login was `sent` from and the host `here` belong to
 * the same name: equal, one under the other, or siblings under a parent of
 * two or more labels. Without the Public Suffix List, siblings under a
 * public suffix (`a.github.io`, `b.github.io`) also match; harmless, since
 * the bar shows and saves the host the login was sent from.
 */
export function sameSite(sent: string, here: string): boolean {
  const under = (child: string, parent: string): boolean => child === parent || child.endsWith(`.${parent}`);
  if (under(here, sent) || under(sent, here)) return true;
  // accounts.example.com → www.example.com, after signing in.
  const labels = sent.split(".");
  if (labels.length < 3) return false;
  const parent = labels.slice(1).join(".");
  return under(here, parent);
}

/**
 * The save waiting for `tabId`, if any, asked by the top document at
 * `url`. Only on the site the login was sent from (`sender.url`, never the
 * page's word): a tab that went to another site drops it.
 */
export async function pendingFor(tabId: number, url: string): Promise<string | undefined> {
  await recording.get(tabId)?.catch(() => undefined);
  const p = pending.get(tabId);
  if (!p) return undefined;
  if (Date.now() - p.seen > SAVE_TTL_MS) {
    forget(tabId);
    return undefined;
  }
  const here = (await klavCore()).fillableHost(url);
  if (pending.get(tabId) !== p) return undefined;
  if (!here || !sameSite(p.host, here)) {
    forget(tabId);
    return undefined;
  }
  return p.id;
}

function bySave(saveId: string): Pending {
  for (const p of pending.values()) if (p.id === saveId) return p;
  throw new DaemonError("not_found", "nothing to save any more");
}

export function tabOfSave(saveId: string): number | undefined {
  for (const p of pending.values()) if (p.id === saveId) return p.tabId;
  return siteOffers.get(saveId)?.tabId;
}

export function closeSave(saveId: string): void {
  for (const p of pending.values()) if (p.id === saveId) forget(p.tabId);
  siteOffers.delete(saveId);
}

/**
 * «Add this site» only while the tab is still on the host it was offered
 * for, like a login waiting to be saved: a tab that went to another site
 * drops it. `url` is where the browser says the tab's top document is.
 */
export async function siteOfferHere(saveId: string, url: string): Promise<void> {
  const o = liveOffer(saveId);
  if (!o) return;
  const here = (await klavCore()).fillableHost(url);
  if (siteOffers.get(saveId) !== o) return;
  if (here !== o.host) {
    siteOffers.delete(saveId);
    throw new DaemonError("not_found", "nothing to add any more");
  }
}

function liveOffer(saveId: string): SiteOffer | undefined {
  const o = siteOffers.get(saveId);
  if (o && Date.now() - o.seen > SAVE_TTL_MS) {
    siteOffers.delete(saveId);
    return undefined;
  }
  return o;
}

/** What the bar should offer; `undefined` when Klav already has exactly this. */
export async function loadSave(bridge: NativeBridge, saveId: string): Promise<SaveState | undefined> {
  const offer = liveOffer(saveId);
  if (offer) {
    const status = await bridge.call<DaemonStatus>({ op: "status" });
    return { status, host: offer.host, page: offer.url, username: offer.item.username ?? "", addSite: offer.item };
  }
  const p = bySave(saveId);
  const status = await bridge.call<DaemonStatus>({ op: "status" });
  const base: SaveState = { status, host: p.host, page: p.url, username: p.username };
  if (!status.unlocked) return base;
  const suggestions = await bridge.call<Suggestions>({ op: "suggest", url: p.url });
  const same = suggestions.logins.filter((l) => (l.username ?? "") === p.username);
  // A form that sent no username (a password-only step, or Klav typed into
  // a form whose account is not a box) is Klav's when any login of the page
  // has that password. Only the page's own logins, never `parent`.
  const compared = p.username === "" ? suggestions.logins : same;
  for (const login of compared) {
    let values: AutofillValues;
    try {
      values = await bridge.call<AutofillValues>({ op: "autofill", item: login.id, url: p.url });
    } catch (e) {
      // One login this device cannot fill (it cannot open it, or it went
      // away since `suggest`) is skipped. Anything about klavd itself
      // (locked, gone, timed out…) fails the bar as before.
      if (e instanceof DaemonError && ITEM_ERRORS.has(e.code)) continue;
      throw e;
    }
    const stored = values.fields.find((f) => f.kind === "password")?.value;
    values.fields.length = 0;
    if (stored === p.password) {
      // Nothing new: Klav already has this login.
      forget(p.tabId);
      return undefined;
    }
  }
  if (same.length > 0) return { ...base, updates: same };
  const projects = await bridge.call<ProjectSummary[]>({ op: "projects" });
  const takenTitles: Record<string, string[]> = {};
  const addTaken = (key: string, title: string): void => {
    const list = (takenTitles[key] ??= []);
    if (!list.includes(title)) list.push(title);
  };
  // Collect live item titles per project so we avoid duplicate-title errors.
  try {
    const listed = await bridge.call<ItemSummary[] | null>({ op: "list", filter: { trash: false } });
    if (Array.isArray(listed)) {
      for (const item of listed) {
        if (!item.trashed) addTaken(`${item.vault}\u0000${item.project}`, item.title);
      }
    }
  } catch {
    // Non-fatal: fall back to site suggestions below.
  }
  for (const login of suggestions.logins) {
    const sep = login.location.indexOf(" / ");
    if (sep > 0) {
      const key = `${login.location.slice(0, sep)}\u0000${login.location.slice(sep + 3)}`;
      addTaken(key, login.title);
    }
  }
  const firstProject = projects[0] ? `${projects[0].vault}\u0000${projects[0].name}` : "";
  const suggestedTitle = suggestFreeTitle(p.host, p.username, firstProject ? (takenTitles[firstProject] ?? []) : []);
  return {
    ...base,
    projects,
    title: suggestedTitle,
    ...(Object.keys(takenTitles).length > 0 ? { takenTitles } : {}),
    ...(suggestions.logins.length > 0 ? { siteLogins: suggestions.logins } : {}),
  };
}

/** Saves a new login or updates the password, as the person chose in the bar. */
export async function doSave(
  bridge: NativeBridge,
  saveId: string,
  action: "create" | "update" | "add_site",
  title: string | undefined,
  project: string | undefined,
  item?: string,
  username?: string,
): Promise<ItemSummary> {
  if (action === "add_site") {
    // A normal edit of the item: this page's address joins its URLs.
    const offer = liveOffer(saveId);
    if (!offer) throw new DaemonError("not_found", "nothing to add any more");
    const saved = await bridge.call<ItemSummary>({
      op: "edit",
      query: offer.item.id,
      patch: { set: [], remove: [], add_urls: [new URL(offer.url).origin], add_tags: [] },
    });
    siteOffers.delete(saveId);
    return saved;
  }
  const p = bySave(saveId);
  const password = { name: "password", value: p.password, kind: "password" as const, secret: true };
  let saved: ItemSummary;
  if (action === "update") {
    const state = await loadSave(bridge, saveId);
    const updates = state?.updates ?? [];
    const candidates = updates.length > 0 ? updates : (state?.siteLogins ?? []);
    if (candidates.length === 0) throw new DaemonError("not_found", "the login to update is gone");
    // With several, only the one the person picked (and only one of these).
    const chosen = item === undefined ? (candidates.length === 1 ? candidates[0] : undefined) : candidates.find((u) => u.id === item);
    if (!chosen) throw new DaemonError("bad_request", "choose which login to update");
    saved = await bridge.call<ItemSummary>({
      op: "edit",
      query: chosen.id,
      patch: { set: [password], remove: [], add_urls: [], add_tags: [] },
    });
  } else {
    const where = project?.split("\u0000");
    const origin = new URL(p.url).origin;
    const finalUsername = (username !== undefined ? username : p.username).trim();
    saved = await bridge.call<ItemSummary>({
      op: "create",
      item: {
        kind: "login",
        title: (title ?? p.host).trim() || p.host,
        ...(where?.[0] ? { vault: where[0] } : {}),
        ...(where?.[1] ? { project: where[1] } : {}),
        fields: [
          ...(finalUsername ? [{ name: "username", value: finalUsername, kind: "username" as const, secret: false }] : []),
          password,
        ],
        urls: [origin],
        tags: [],
      },
    });
  }
  forget(p.tabId);
  return saved;
}
