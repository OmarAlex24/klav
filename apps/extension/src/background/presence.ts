/**
 * The master password in Klav's own frame, with the presence gate on (ADR
 * 0041 §3.2): the passkey frame (`passkey.html`, top right of the tab),
 * never a field of the page. Two things open it:
 *
 * - klavd's `presence` event, before an agent's values reach this browser
 *   connection (§3.1): the frame says what klavd's Touch ID dialog would,
 *   and the password goes back with `extension_presence` on this same
 *   connection. Closing the frame, or no answer in time, declines.
 * - `presence_required` for a fill the extension itself asked for: the
 *   same request goes again with `password`, on the same connection
 *   (own choice 32: klavd checks a password only against the last ask it
 *   sent on that connection).
 *
 * One frame at a time for the whole extension: every ask shares the one
 * native connection, and klavd keeps only its last ask there. Without the
 * gate klavd sends neither, so nothing here runs.
 */
import { t } from "../shared/i18n";
import { DaemonError, type PresenceAsk, type Request } from "../shared/protocol";
import type { NativeBridge } from "./native";

/** How long the frame has to load before the ask counts as declined. */
const LOAD_MS = 5_000;
/** How long the person has to answer: under klavd's own 120 s. */
const ANSWER_MS = 110_000;
/** A third new question in a row (the setting changed, an item renamed) ends it. */
const MAX_ASKS = 3;

const PREFIX = "presence-";

interface Open {
  id: string;
  tabId: number;
  ask: PresenceAsk;
  asks: number;
  loaded: boolean;
  /** Tries one password; throws what klavd answered. */
  attempt: (password: string) => Promise<void>;
  /** Ends the ask: `undefined` once klavd took the password. */
  settle: (error?: DaemonError) => void;
}

const open = new Map<string, Open>();
let queue: Promise<unknown> = Promise.resolve();

let showFrame: (tabId: number, id: string) => Promise<void> = () => Promise.resolve();
let hideFrame: (tabId: number, id: string) => void = () => undefined;

/** How the frame is shown and hidden (the passkey bridge's, `passkeys.ts`). */
export function startPresence(show: (tabId: number, id: string) => Promise<void>, hide: (tabId: number, id: string) => void): void {
  showFrame = show;
  hideFrame = hide;
}

/** Whether `id` is a presence frame's (not a passkey call's). */
export function isPresenceId(id: string): boolean {
  return id.startsWith(PREFIX);
}

const DECLINED = "the person declined in the browser";
const NO_FRAME = "Klav could not show its frame in this tab";
const LATE = "the person did not answer in the browser in time";

export function declined(message = DECLINED): DaemonError {
  return new DaemonError("denied", message);
}

/** A refusal this module made (the person, the frame or the clock), not klavd's. */
function isDecline(e: DaemonError): boolean {
  return e.message === DECLINED || e.message === NO_FRAME || e.message === LATE;
}

/**
 * Asks for the master password in Klav's frame in `tabId` and runs
 * `attempt` with it, until klavd takes one: a wrong password asks again in
 * the same frame, and a new `presence_required` rewords the question.
 * Rejects with `denied` if the person closes the frame, doesn't answer in
 * time, or the frame can't show in that tab.
 */
export function askInTab<T>(tabId: number, ask: PresenceAsk, attempt: (password: string) => Promise<T>): Promise<T> {
  const run = (): Promise<T> =>
    new Promise<T>((resolve, reject) => {
      const id = `${PREFIX}${crypto.randomUUID()}`;
      let result: T | undefined;
      const timers: ReturnType<typeof setTimeout>[] = [];
      const entry: Open = {
        id,
        tabId,
        ask,
        asks: 1,
        loaded: false,
        attempt: async (password) => {
          result = await attempt(password);
        },
        settle: (error) => {
          if (!open.delete(id)) return;
          for (const timer of timers) clearTimeout(timer);
          hideFrame(tabId, id);
          if (error) reject(error);
          else resolve(result as T);
        },
      };
      open.set(id, entry);
      timers.push(
        setTimeout(() => {
          if (!entry.loaded) entry.settle(declined(NO_FRAME));
        }, LOAD_MS),
        setTimeout(() => {
          entry.settle(declined(LATE));
        }, ANSWER_MS),
      );
      void showFrame(tabId, id);
    });
  const next = queue.then(run, run);
  queue = next.catch(() => undefined);
  return next;
}

function live(id: string, tabId: number | undefined): Open {
  const o = open.get(id);
  if (!o || o.tabId !== tabId) throw new DaemonError("not_found", "this question is over");
  return o;
}

/** The tab of an open ask (to check its frame is uncovered). */
export function presenceTab(id: string): number {
  const o = open.get(id);
  if (!o) throw new DaemonError("not_found", "this question is over");
  return o.tabId;
}

/** The frame loaded: what to ask. Only for the frame in the ask's own tab. */
export function presenceLoad(id: string, tabId: number | undefined): PresenceAsk {
  const o = live(id, tabId);
  o.loaded = true;
  return o.ask;
}

/**
 * The person typed the master password in the frame. Done: the frame
 * closes. A wrong password, or a new question, goes back to the frame,
 * which asks again; anything else ends the ask.
 */
export async function presenceAnswer(id: string, tabId: number | undefined, password: string): Promise<null> {
  const o = live(id, tabId);
  try {
    await o.attempt(password);
  } catch (e) {
    const error = e instanceof DaemonError ? e : new DaemonError("internal", "the extension failed");
    if (error.code === "wrong_credentials") throw error;
    if (error.code === "presence_required" && error.presence && o.asks < MAX_ASKS) {
      o.asks += 1;
      o.ask = error.presence;
      throw error;
    }
    o.settle(error);
    throw error;
  }
  o.settle();
  return null;
}

/** The person closed the frame: declined. */
export function presenceClosed(id: string): void {
  open.get(id)?.settle(declined());
}

/** The tab went away: every ask in it is declined. */
export function presenceTabGone(tabId: number): void {
  for (const o of [...open.values()]) if (o.tabId === tabId) o.settle(declined());
}

/**
 * klavd's `presence` event (ADR 0041 §3.1): the frame in the event's tab,
 * the password back on this connection. Declined, klavd gets an error
 * reply and tells the agent; an event klavd no longer waits for (it timed
 * out, the connection reconnected) needs no reply.
 */
export function onPresenceEvent(bridge: NativeBridge, event: Record<string, unknown>): void {
  const id = event.id as number;
  const tabId = event.tab_id;
  const ask: unknown = event.presence;
  const decline = (message: string): void => {
    void bridge.call({ op: "extension_reply", event: id, error: { code: "denied", message } }).catch(() => undefined);
  };
  if (typeof tabId !== "number" || typeof ask !== "object" || ask === null) {
    decline("the extension cannot show this question");
    return;
  }
  void askInTab(tabId, ask as PresenceAsk, async (password) => {
    await bridge.call({ op: "extension_presence", event: id, password });
  }).catch((e: unknown) => {
    if (e instanceof DaemonError && e.code === "not_found") return;
    decline(e instanceof DaemonError ? e.message : "the person declined in the browser");
  });
}

/** Requests that hand a value out and may get `presence_required` from the gate. */
type Gated = Extract<Request, { op: "autofill" | "view" }>;

/**
 * `request` for a fill into `tabId`: with the gate on and no window open,
 * klavd answers `presence_required`, and the same request goes again with
 * the password typed in Klav's frame in that tab. Without the gate, one
 * call, as always.
 */
export async function callInTab<T>(bridge: NativeBridge, tabId: number, request: Gated): Promise<T> {
  try {
    return await bridge.call<T>(request);
  } catch (e) {
    if (!(e instanceof DaemonError) || e.code !== "presence_required" || !e.presence) throw e;
    return askInTab(tabId, e.presence, (password) => bridge.call<T>({ ...request, password })).catch((declinedOrNot: unknown) => {
      // The person's own fill: why nothing was filled, in their language.
      if (declinedOrNot instanceof DaemonError && declinedOrNot.code === "denied" && isDecline(declinedOrNot)) {
        throw new DaemonError("denied", t(declinedOrNot.message === NO_FRAME ? "presence_no_frame" : "presence_declined"));
      }
      throw declinedOrNot;
    });
  }
}
