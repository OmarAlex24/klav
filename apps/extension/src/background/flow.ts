/**
 * Sign-ins in several steps (docs/diseno-visual §4.3): the account first,
 * «Continuar», then the password (on the same page, after a navigation of
 * the same site or in a frame of another subdomain of it), then maybe a
 * one-time code. After the person chooses a login, Klav follows it step by
 * step. The state lives here, in memory, per tab, for a short time; each
 * step is filled like any other fill (klavd checks the frame's address,
 * and a framed sign-in must match the page on top too).
 */
import type { FillReply, StepRole } from "../shared/messages";

/** How long a sign-in in steps may take in all. */
export const FLOW_MS = 60_000;
/** How long Klav waits for the password after pressing «Continuar». */
export const PASSWORD_WAIT_MS = 10_000;

/** Where to say that Klav stopped: the frame of the last step it filled. */
export interface FlowFrame {
  tabId: number;
  frameId: number;
  documentId: string | undefined;
}

export interface Flow {
  item: string;
  stage: StepRole;
  until: number;
  /** Press the next step's button (off with «Solo rellenar, no pulsar»). */
  press: boolean;
  last: FlowFrame;
  /** A step is being filled: ignore other reports meanwhile. */
  busy: boolean;
  /** A password box showed up in a frame of another site (Klav does not fill there). */
  elsewhere?: boolean;
  timer?: ReturnType<typeof setTimeout>;
}

const flows = new Map<number, Flow>();

/**
 * The next step after a fill, if any: the password when the form asked
 * only for the account; the code when the password went in and the item
 * has one (and it was not typed already).
 */
export function nextStage(reply: FillReply, hasTotp: boolean): StepRole | undefined {
  if (reply.waiting === "password") return "password";
  if (hasTotp && reply.filled.includes("password") && !reply.filled.includes("totp")) return "otp";
  return undefined;
}

export function flowOf(tabId: number, now = Date.now()): Flow | undefined {
  const flow = flows.get(tabId);
  if (flow && now > flow.until) {
    endFlow(tabId);
    return undefined;
  }
  return flow;
}

/** Starts (or moves on) the tab's sign-in in steps. */
export function setFlow(tabId: number, flow: Omit<Flow, "busy" | "timer">, onStuck?: (flow: Flow) => void): Flow {
  const old = flows.get(tabId);
  if (old?.timer) clearTimeout(old.timer);
  const next: Flow = { ...flow, busy: false };
  if (flow.stage === "password" && onStuck) {
    next.timer = setTimeout(() => {
      if (flows.get(tabId) === next && next.stage === "password" && !next.busy) onStuck(next);
    }, PASSWORD_WAIT_MS);
  }
  flows.set(tabId, next);
  return next;
}

export function endFlow(tabId: number): void {
  const flow = flows.get(tabId);
  if (flow?.timer) clearTimeout(flow.timer);
  flows.delete(tabId);
}
