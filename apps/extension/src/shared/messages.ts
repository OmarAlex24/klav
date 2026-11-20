import type { PasskeyCall, PasskeyCandidate, PasskeyOutcome } from "./passkey";
import type { DaemonStatus, ErrorBody, FillValue, ItemKind, ProjectSummary, Request, Suggestion, Suggestions } from "./protocol";
import { DaemonError } from "./protocol";
import { ext } from "./ext";

/** What a focused field offers: logins, cards or addresses. */
export type Group = "login" | "card" | "identity";

/** What Klav draws in a page, each an extension page in a frame. The menu
 * lives in the frame of its field; the others in the top frame. The
 * passkey surface is drawn by the passkey bridge (`content/webauthn.ts`),
 * which runs from `document_start`. */
export type Surface = "menu" | "save" | "card" | "find" | "notice" | "passkey";

/** Messages from our own pages (popup, menu, save bar, card, palette) to the background. */
export type PageMessage =
  | { type: "daemon"; request: Request }
  /** The menu asks what to show. */
  | { type: "menu_load"; menuId: string }
  /** The person chose `item` in the menu (`totp`: only its code; `parent`: from «Saved for a subdomain»). */
  | { type: "menu_fill"; menuId: string; item: string; part?: "all" | "totp" | "pending"; parent?: boolean }
  /** The person chose the generated password. */
  | { type: "menu_generated"; menuId: string; value: string }
  /** «Buscar otro elemento»: the palette, for the menu's field. */
  | { type: "menu_find"; menuId: string }
  /** The save bar asks what to show, and what the person decided. */
  | { type: "save_load"; saveId: string }
  /** `item`: which login to update, when several of the site have this username. */
  | { type: "save_do"; saveId: string; action: "create" | "update" | "add_site"; title?: string; project?: string; item?: string }
  /** The top card: what to show, and «Iniciar sesión». */
  | { type: "card_load"; cardId: string }
  | { type: "card_fill"; cardId: string; item?: string }
  | { type: "card_find"; cardId: string }
  /** The palette: what to show, and the item chosen (`confirmed`: on another site). */
  | { type: "find_load"; findId: string }
  | { type: "find_fill"; findId: string; item: string; confirmed?: boolean; parent?: boolean }
  /** The agent notice asks what to say. */
  | { type: "notice_load"; noticeId: string }
  /** A surface's height changed, or it closes itself. */
  | { type: "size"; surface: Surface; id: string; height: number }
  | { type: "close"; surface: Surface; id: string }
  /** The popup copied a value: clear the clipboard later. */
  | { type: "copied" }
  /** The popup asks where the active tab is (the browser's word, not the page's). */
  | { type: "popup_here" }
  /** The popup asks to fill `item` into the active tab (`parent`: from «Saved for a subdomain»). */
  | { type: "popup_fill"; item: string; parent?: boolean }
  /** The passkey surface (ADR 0020): what to show, and what the person chose. */
  | { type: "passkey_load"; passkeyId: string }
  /** Sign in with the passkey of `item` (`password`: the master password, without Touch ID). */
  | { type: "passkey_sign_in"; passkeyId: string; item: string; password?: string }
  /** Save the new passkey: in `item`, else a new login; `replace`: the person confirmed replacing the account's passkey. */
  | { type: "passkey_save"; passkeyId: string; item?: string; replace?: boolean; password?: string }
  /** «Use another device»: hand the call to the browser. */
  | { type: "passkey_browser"; passkeyId: string }
  /** In the field menu, while the page waits for a passkey (conditional mediation): sign in with `item`'s. */
  | { type: "menu_passkey"; menuId: string; item: string }
  /** In the field menu: the browser's own passkeys instead. */
  | { type: "menu_passkey_browser"; menuId: string };

/** Messages from content scripts (inside web pages) to the background. */
export type ContentMessage =
  /** `stopped`: a sign-in in several steps stopped here, and why. */
  | { type: "menu_open"; groups: Group[]; role: FieldRole; stopped?: StopReason; rules?: FieldRules }
  /** A form with a password was sent: maybe offer to save it. */
  | { type: "submit_seen"; username: string; password: string }
  /** A page loaded in the top frame: is a save waiting for it? */
  | { type: "save_pending" }
  /** A one-time code field got the focus: offer the login just filled? */
  | { type: "recent_login" }
  /** A field marked `webauthn`: does the page wait for a passkey in this frame (conditional mediation)? */
  | { type: "passkey_waiting" }
  /** This frame has a sign-in form (`token` names it for a fill). */
  | { type: "login_seen"; token: string }
  /** The shortcut with no field to fill: open the palette for this frame. */
  | { type: "find_open" }
  /** The person typed in a field: the top card goes away, a sign-in in steps stops. */
  | { type: "typing" }
  /** A new document: is a sign-in in steps going on in this tab? */
  | { type: "flow_ask" }
  /** During a sign-in in steps: the next step's field showed up (`token` names its form). */
  | { type: "step_seen"; role: StepRole; token: string }
  /** During a sign-in in steps: something Klav must not get past (a captcha). */
  | { type: "step_blocked"; reason: "captcha" }
  | { type: "close"; surface: Surface; id: string }
  /** Answer to `where`: the browser attests the frame's address. */
  | { type: "here"; nonce: string; doc: string }
  /**
   * Answer to `rotate_probe` (ADR 0022 §5): this frame has the focused
   * password box (`focused`), or it is the top frame and offers its change
   * form. The browser attests the frame's address; `token` ties the fill
   * to the box found.
   */
  | { type: "rotate_here"; nonce: string; token: string; focused: boolean; rules?: FieldRules }
  /**
   * A WebAuthn call from this frame (ADR 0020), as the page-world hook
   * reduced it. `same_origin_as_top`: the frame has the top frame's origin
   * (others go to the browser). The answer is either the outcome now or a
   * `pending` ID whose outcome comes later as `passkey_result`.
   */
  | { type: "passkey_request"; call: PasskeyCall; same_origin_as_top: boolean }
  /** The page aborted the call (`AbortSignal`). */
  | { type: "passkey_cancel"; id: string };

/** The steps after the first one of a sign-in in several steps. */
export type StepRole = "password" | "otp";

/** Why Klav stopped a sign-in in steps (the menu says it on the field). */
export type StopReason = "no_password" | "captcha" | "other_site";

/**
 * What to press after typing a login: on the first step, «Continuar» only
 * if the form asked just for the account; on the next steps, the form's
 * button. Absent: type only («Solo rellenar, no pulsar»).
 */
export type Advance = "identifier" | "always";

/**
 * What a new-password field says about the passwords it takes: its
 * `passwordrules`, `minlength` and `maxlength` (the generator follows them).
 */
export interface FieldRules {
  password_rules?: string;
  min_length?: number;
  max_length?: number;
}

/** The kind of field a menu opened on (what to offer first). */
export type FieldRole = "login" | "new-password" | "otp" | "card" | "identity";

/** A field an agent pointed at with a CSS selector. */
export interface AgentSelector {
  field: string;
  selector: string;
}

/** Messages from the background to one frame's content script. */
export type ToContent =
  /** Type an item's values into the form `token` names (a menu, the card's form, the palette's field). */
  | { type: "fill"; token: string; kind: ItemKind; values: FillValue[]; advance?: Advance }
  /** Type a generated password into the new-password fields of the menu's form. */
  | { type: "fill_generated"; menuId: string; value: string }
  /** Before acting on a choice made in a surface: does the page leave it alone (answers a boolean)? */
  | { type: "clear"; surface: Surface; id: string }
  /** Show, resize or close one of Klav's surfaces. */
  | { type: "show"; surface: Surface; id: string }
  | { type: "size"; surface: Surface; id: string; height: number }
  | { type: "hide"; surface: Surface; id: string }
  /** The palette opened from this frame's menu will fill with this token. */
  | { type: "expect"; token: string; menuId: string }
  | { type: "shortcut" }
  /** The person chose an item in the popup: fill the focused (or best) form of document `doc` (what it answered to `where`). */
  | { type: "popup_fill"; doc: string; kind: ItemKind; values: FillValue[]; advance?: Advance }
  /** A sign-in in steps is going on in this tab until `until`: watch for its next field. */
  | { type: "flow"; until: number }
  /** A sign-in in steps stopped: open the menu on the form and say why. */
  | { type: "flow_stop"; reason: StopReason }
  /** Report this document's address (through a `here` message). */
  | { type: "where"; nonce: string }
  /** An assisted change is coming: the frame with a focused password box (and the top frame) answers `rotate_here`. */
  | { type: "rotate_probe"; nonce: string }
  /** Type an assisted change into the box `token` names (or the change form); `noticeId` tells the person. */
  | { type: "rotate_fill"; token: string; current: string; next: string; noticeId: string; submit: boolean }
  /** Type an agent's values into this page (only document `doc`); `noticeId` tells the person. */
  | {
      type: "agent_fill";
      doc: string;
      kind: ItemKind;
      values: FillValue[];
      noticeId: string;
      selectors: AgentSelector[];
      submit: boolean;
    }
  /** Klav signed in with a passkey for an agent here (ADR 0020 §9): show the notice (top frame only). */
  | { type: "agent_notice"; noticeId: string }
  /** The passkey surface (only the passkey bridge of the top frame draws it). */
  | { type: "passkey_show"; id: string }
  | { type: "passkey_hide"; id: string }
  /** The outcome of a pending `passkey_request` of this frame. */
  | { type: "passkey_result"; id: string; outcome: PasskeyOutcome };

/** What a frame answers to `fill`. */
export interface FillReply {
  /** Names of the values typed (`username`, `password`…). */
  filled: string[];
  /** Klav pressed the form's button. */
  submitted?: boolean;
  /** The form asked only for the account: the password comes in a next step. */
  waiting?: "password";
  /** Klav did not press anything: the page asks for a captcha. */
  blocked?: "captcha";
}

/** What the content script answers to `agent_fill`. */
export interface AgentFillResult {
  filled: string[];
  submitted: boolean;
}

/** What the menu shows. */
export interface MenuState {
  /** The frame's address: only to find the site's icon in the browser's own cache. */
  page?: string;
  host?: string;
  groups: Group[];
  role: FieldRole;
  status: DaemonStatus;
  suggestions?: Suggestions;
  /** On a one-time code field: the login just filled in this tab. */
  recent?: Suggestion;
  /** A sign-in in steps stopped on this field, and why. */
  stopped?: StopReason;
  /** On a new-password field: what it says about the passwords it takes. */
  rules?: FieldRules;
  /**
   * The page waits for a passkey in this frame (conditional mediation,
   * ADR 0020 P9): the site's passkeys in Klav, first in the menu.
   */
  passkeys?: PasskeyCandidate[];
}

/** What the top card shows. */
export interface CardState {
  /** The frame's address: only to find the site's icon in the browser's own cache. */
  page?: string;
  host: string;
  login: Suggestion;
  others: number;
}

/** What the palette shows. */
export interface FindState {
  /** The frame's address: only to find the site's icon in the browser's own cache. */
  page?: string;
  status: DaemonStatus;
  /** The host of the frame it fills (what the person must see before filling another site's login). */
  host?: string;
  /** The logins, cards and addresses that match that frame. */
  suggestions?: Suggestions;
}

/** What the save bar shows. */
export interface SaveState {
  /** The frame's address: only to find the site's icon in the browser's own cache. */
  page?: string;
  status: DaemonStatus;
  host: string;
  username: string;
  /**
   * The logins of this site with this username and another password: one
   * is updated as is; with several the person picks one (each shows its
   * vault and project).
   */
  updates?: Suggestion[];
  /** Where a new login can go, and the suggested title. */
  projects?: ProjectSummary[];
  title?: string;
  /**
   * After the person filled a login saved for a subdomain (ADR 0025 §2):
   * «Add <host> to this item», so it matches exactly next time.
   */
  addSite?: Suggestion;
}

/** The answer to `passkey_request`. */
export type PasskeyReply = { outcome: PasskeyOutcome } | { pending: string };

/** What the passkey surface shows. */
export interface PasskeyState {
  kind: "create" | "get";
  /** The frame's address: only to find the site's icon in the browser's own cache. */
  page: string;
  status: DaemonStatus;
  /** The rpId, once klavd checked it (unlocked); the page's host before. */
  rp_id: string;
  /** Create: what the page says about the site and the account (the page wrote these). */
  rp_name?: string;
  user_name?: string;
  /** Get: the logins with a passkey for this site. */
  candidates?: PasskeyCandidate[];
  /** Get: the one the person picked in the field menu (conditional mediation); presence right away. */
  chosen?: string;
  /** Create: logins of this site the passkey may go into (the first one is suggested). */
  logins?: Suggestion[];
}

/** What the background answers. */
export type Reply<T> = { ok: true; value: T } | { ok: false; error: ErrorBody };

/** Sends a message to the background and unwraps its reply. */
export async function ask<T>(message: unknown): Promise<T> {
  const reply = await ext.runtime.sendMessage<unknown, Reply<T> | undefined>(message);
  if (!reply) throw new DaemonError("disconnected", "the extension's background did not answer");
  if (!reply.ok) throw new DaemonError(reply.error.code, reply.error.message);
  return reply.value;
}

/**
 * Drops the values a `create` or `edit` carried once klavd answered (the
 * port already sent them): the request object outlives the call in the
 * page and in the background, as `rotateFill` does with its passwords.
 */
export function forgetValues(request: Request): void {
  if (request.op === "create") {
    for (const f of request.item.fields) f.value = "";
    request.item.fields.length = 0;
    if (request.item.notes !== undefined) request.item.notes = "";
  } else if (request.op === "edit") {
    for (const f of request.patch.set) f.value = "";
    request.patch.set.length = 0;
  } else if (request.op === "generator_record") {
    request.value = "";
  }
}

/** Calls klavd through the background (only from our own pages). */
export function daemon<T>(request: Request): Promise<T> {
  return ask<T>({ type: "daemon", request } satisfies PageMessage);
}

export function toErrorBody(e: unknown): ErrorBody {
  if (e instanceof DaemonError) return { code: e.code, message: e.message };
  return { code: "internal", message: e instanceof Error ? e.message : "unexpected error" };
}

/** Rules a page's process sent, kept only if they look like rules. */
export function cleanRules(raw: unknown): FieldRules | undefined {
  if (typeof raw !== "object" || raw === null) return undefined;
  const r = raw as Record<string, unknown>;
  const out: FieldRules = {};
  if (typeof r.password_rules === "string" && r.password_rules.length <= 2000) out.password_rules = r.password_rules;
  const length = (v: unknown): number | undefined => (typeof v === "number" && Number.isInteger(v) && v >= 1 && v <= 4096 ? v : undefined);
  const min = length(r.min_length);
  const max = length(r.max_length);
  if (min !== undefined) out.min_length = min;
  if (max !== undefined) out.max_length = max;
  return Object.keys(out).length > 0 ? out : undefined;
}
