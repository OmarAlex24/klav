/**
 * Content script, in every http(s) frame. It finds login, card and address
 * fields, shows Klav's glyph on the focused one, reports sign-in forms (the
 * top card) and, when the person picks an item in one of Klav's surfaces,
 * types that item's values into that form. It never talks to klavd and
 * holds no vault data until a fill, which it drops right after typing.
 * Nothing a page posts (`postMessage`, events) can start a fill: only the
 * background, after a click inside one of Klav's frames.
 */
import { ext } from "../shared/ext";
import type { Advance, ContentMessage, FieldRole, FieldRules, FillReply, Reply, StepRole, StopReason, ToContent } from "../shared/messages";
import type { FillValue, ItemKind } from "../shared/protocol";
import { agentFill, bestScope, submitScope } from "./agent";
import { candidates, deepActiveElement, type Field, fieldsOf, groupOf, groupsFor, isCandidate, scopeOf } from "./detect";
import { fillFields, isPasswordBox, isVisible, setValue } from "./fill";
import { focusedPassword, rotateFill, rotateTargets } from "./rotate";
import { asksOnlyForAccount, canPressOnward, captchaShown, isSendButton, pressOnward, stepScope } from "./steps";
import { InPage } from "./ui";

interface Active {
  field: Field;
  scope: Element | Document;
  menuId?: string;
}

let active: Active | undefined;
/** This document, so the background can tell a new page from the old one. */
const DOC = crypto.randomUUID();
const ui = new InPage(
  () => {
    void openMenu(false);
  },
  (findId) => {
    ui.hide("find", findId);
    void send({ type: "close", surface: "find", id: findId }).catch(() => undefined);
  },
);

type Scope = Element | Document;
/**
 * Fills this document accepts, by token: the open menu, the sign-in form
 * this document reported (the top card) and the palette opened from here.
 * Each resolves the form to fill when the values arrive.
 */
const tokens = new Map<string, (kind: ItemKind) => Scope | undefined>();

/** The classified field for `el`, with its form, if Klav offers anything there. */
function lookUp(el: Element | null): Active | undefined {
  if (!el || !isCandidate(el)) return undefined;
  const scope = scopeOf(el);
  const field = fieldsOf(scope).find((f) => f.el === el);
  if (!field) return undefined;
  // Logins in frames of another site are offered only if the background
  // finds they also match the page on top (it checks every fill).
  return { field, scope };
}

async function send<T>(message: ContentMessage): Promise<T> {
  const reply = await ext.runtime.sendMessage<ContentMessage, Reply<T> | undefined>(message);
  if (!reply?.ok) throw new Error(reply ? reply.error.message : "no reply");
  return reply.value;
}

function fieldRole(field: Field): FieldRole {
  if (field.role === "new-password" || field.role === "otp") return field.role;
  return groupOf(field.role);
}

/** What a new-password field says about the passwords it takes (the generator follows it). */
function fieldRules(el: Field["el"]): FieldRules | undefined {
  if (!(el instanceof HTMLInputElement)) return undefined;
  const rules: FieldRules = {};
  const text = el.getAttribute("passwordrules")?.trim();
  if (text) rules.password_rules = text.slice(0, 2000);
  if (el.minLength > 0) rules.min_length = el.minLength;
  if (el.maxLength > 0) rules.max_length = el.maxLength;
  return Object.keys(rules).length > 0 ? rules : undefined;
}

async function openMenu(fromKeyboard: boolean, stopped?: StopReason): Promise<void> {
  const current = active;
  if (!current) return;
  const groups = groupsFor(current.field, fieldsOf(current.scope));
  try {
    const rules = current.field.role === "new-password" ? fieldRules(current.field.el) : undefined;
    const { menuId } = await send<{ menuId: string }>({ type: "menu_open", groups, role: fieldRole(current.field), ...(stopped ? { stopped } : {}), ...(rules ? { rules } : {}) });
    if (active !== current) return;
    if (current.menuId) tokens.delete(current.menuId);
    current.menuId = menuId;
    tokens.set(menuId, () => current.scope);
    ui.show("menu", menuId, fromKeyboard, current.field.role === "new-password");
  } catch {
    // The background is restarting; the next focus tries again.
  }
}

/**
 * An event on another of Klav's hosts (`klav-ui`): the passkey bridge
 * draws Klav's frame in its own, and the presence gate's master password
 * goes there while a fill from this menu waits (ADR 0041 §3.2). Typing it
 * must not close the menu, or the fill would find its form gone. At worst
 * a page's own `klav-ui` keeps the menu open, which fills nothing.
 */
function inKlavFrame(event: Event): boolean {
  return event.composedPath().some((n) => n instanceof Element && n.localName === "klav-ui");
}

function closeMenu(refocus: boolean): void {
  if (!active?.menuId) return;
  const id = active.menuId;
  delete active.menuId;
  tokens.delete(id);
  ui.hide("menu");
  void send({ type: "close", surface: "menu", id }).catch(() => undefined);
  if (refocus && active.field.el.isConnected) active.field.el.focus({ preventScroll: true });
}

document.addEventListener(
  "focusin",
  (event) => {
    if (ui.owns(event) || inKlavFrame(event)) return;
    const target = event.composedPath()[0];
    const found = target instanceof Element ? lookUp(target) : undefined;
    if (found) {
      if (active?.field.el !== found.field.el) {
        closeMenu(false);
        active = found;
      }
      ui.showIcon(found.field.el);
      // During a sign-in in steps the code goes in by itself; else offer it.
      if (found.field.role === "otp" && !ui.menuOpen && !flowWatching()) void offerCode(found);
      // A field the page marked for passkeys (`autocomplete="username webauthn"`): offer them, as browsers do.
      else if (marksWebauthn(found.field.el) && !ui.menuOpen) void offerPasskeys(found);
    } else {
      closeMenu(false);
      ui.hideIcon();
      active = undefined;
    }
  },
  true,
);

document.addEventListener(
  "pointerdown",
  (event) => {
    if (ui.owns(event) || inKlavFrame(event) || !ui.menuOpen) return;
    closeMenu(false);
  },
  true,
);

document.addEventListener(
  "keydown",
  (event) => {
    if (event.key === "Escape" && ui.menuOpen) closeMenu(true);
  },
  true,
);

function marksWebauthn(el: Element): boolean {
  return (el.getAttribute("autocomplete") ?? "").toLowerCase().split(/\s+/).includes("webauthn");
}

/** On a `webauthn` field while the page waits for a passkey (conditional mediation): open the menu. */
async function offerPasskeys(found: Active): Promise<void> {
  try {
    if ((await send<boolean>({ type: "passkey_waiting" })) && active === found && !ui.menuOpen) await openMenu(false);
  } catch {
    // nothing to offer
  }
}

/** On a code field right after Klav filled a login with a code: open the menu (never fill by itself). */
async function offerCode(found: Active): Promise<void> {
  try {
    if ((await send<boolean>({ type: "recent_login" })) && active === found && !ui.menuOpen) await openMenu(false);
  } catch {
    // nothing to offer
  }
}

// ------------------------------------------------------------ top card --

/** A visible sign-in form: a current password, or the first step that asks only for the account. */
function signInScope(): Scope | undefined {
  const scopes = new Set<Scope>(candidates(document).map((el) => scopeOf(el)));
  for (const scope of scopes) {
    const fields = fieldsOf(scope).filter((f) => isVisible(f.el));
    if (fields.some((f) => f.role === "current-password")) return scope;
    if (fields.length === 1 && fields[0]?.role === "username" && scope instanceof HTMLFormElement) return scope;
  }
  return undefined;
}

let loginToken: string | undefined;
let lookTimer: ReturnType<typeof setTimeout> | undefined;
const startedAt = Date.now();

/**
 * Reports this document's sign-in form once, so the background may offer
 * the top card. The card fills that very form while it is in the page; if
 * a single-page app swaps it for another, the card fills nothing. The
 * token goes away after its first fill.
 */
function lookForSignIn(): void {
  if (loginToken) return;
  const scope = signInScope();
  if (!scope) return;
  loginToken = crypto.randomUUID();
  tokens.set(loginToken, () => (scope instanceof Document || scope.isConnected ? scope : undefined));
  void send({ type: "login_seen", token: loginToken }).catch(() => undefined);
}

// Forms rendered late (single-page apps): look again for a minute.
new MutationObserver(() => {
  if (loginToken || Date.now() - startedAt > 60_000) return;
  clearTimeout(lookTimer);
  lookTimer = setTimeout(lookForSignIn, 400);
}).observe(document.documentElement, { childList: true, subtree: true });

/** The person typed in a field: the top card goes away (once per page), a sign-in in steps stops. */
let typed = false;
document.addEventListener(
  "input",
  (event) => {
    if (!event.isTrusted || ui.owns(event)) return;
    if (typed && !flowWatching()) return;
    const target = event.composedPath()[0];
    if (!(target instanceof Element) || !isCandidate(target)) return;
    typed = true;
    stopWatching();
    void send({ type: "typing" }).catch(() => undefined);
  },
  true,
);

// ---------------------------------------------------- sign-in in steps --

// While the background follows a sign-in in steps in this tab, every frame
// looks for the next step's field (a password, a code) and tells it once;
// the background then fills it like any other fill. A captcha stops it.
let flowUntil = 0;
let flowTimer: ReturnType<typeof setInterval> | undefined;
const stepsSeen = new Set<StepRole | "captcha">();

function flowWatching(): boolean {
  return Date.now() < flowUntil;
}

function watchFlow(until: number): void {
  flowUntil = Math.min(until, Date.now() + 60_000);
  // A new step after a fill on this same page: look for it again.
  stepsSeen.clear();
  flowTimer ??= setInterval(checkSteps, 250);
  checkSteps();
}

function stopWatching(): void {
  flowUntil = 0;
  clearInterval(flowTimer);
  flowTimer = undefined;
}

function checkSteps(): void {
  if (!flowWatching()) {
    stopWatching();
    return;
  }
  if (!stepsSeen.has("captcha") && captchaShown(document)) {
    stepsSeen.add("captcha");
    stopWatching();
    void send({ type: "step_blocked", reason: "captcha" }).catch(() => undefined);
    return;
  }
  for (const role of ["password", "otp"] as const) {
    if (stepsSeen.has(role)) continue;
    const scope = stepScope(document, role);
    if (!scope) continue;
    stepsSeen.add(role);
    const token = crypto.randomUUID();
    tokens.set(token, () => stepScope(document, role) ?? scope);
    void send({ type: "step_seen", role, token }).catch(() => undefined);
  }
}

/**
 * Types an item into `scope`. For a login it also decides whether to press
 * the form's button (pressed after the reply, see `pressLater`): on the
 * first step only when the form asks just for the account («Continuar»),
 * on the next ones always, never past a captcha.
 */
function typeItem(
  kind: ItemKind,
  values: FillValue[],
  scope: Scope | undefined,
  advance: Advance | undefined,
): { reply: FillReply; press: boolean; anchor?: Element } {
  const fields = scope ? fieldsOf(scope) : [];
  const accountOnly = kind === "login" && asksOnlyForAccount(fields) && values.some((v) => v.kind === "password");
  const filled = scope ? fillFields(kind, values, fields) : [];
  const reply: FillReply = { filled };
  if (kind !== "login" || filled.length === 0 || !scope) return { reply, press: false };
  if (accountOnly) reply.waiting = "password";
  let press = advance === "always" || (advance === "identifier" && accountOnly);
  if (press && captchaShown(document)) {
    reply.blocked = "captcha";
    press = false;
  }
  // The field that took the last value: the button is looked for near it.
  const anchor = fields.filter((f) => isVisible(f.el) && f.el.value !== "").pop()?.el;
  // Never a button (or form) that sends to another origin (T68).
  if (press && !canPressOnward(scope, anchor)) press = false;
  if (press) reply.submitted = true;
  return { reply, press, ...(anchor ? { anchor } : {}) };
}

// ---------------------------------------------------------------- save --

// Saving: when a form with a password is sent, report what was typed so
// the next page can offer to save it (the background keeps it in memory
// for one minute; the save bar never sees the password). Nothing of it
// stays here: the background drops a repeated report of the same login.
let askTimer: ReturnType<typeof setTimeout> | undefined;
function reportSubmit(scope: Element | Document): void {
  if (window.top !== window && !sameOriginAsTop()) return;
  const fields = fieldsOf(scope);
  const value = (f: Field | undefined): string => (f && "value" in f.el ? f.el.value : "");
  // Only what the person typed into a password box they can see: never a
  // text box the page marks as a password, nor a hidden one.
  const typed = (f: Field): boolean => isPasswordBox(f.el) && value(f) !== "" && isVisible(f.el);
  const fresh = fields.filter((f) => f.role === "new-password" && typed(f));
  const current = fields.find((f) => f.role === "current-password" && typed(f));
  // A sign-up or a password change saves the new one.
  const password = value(fresh[fresh.length - 1]) || value(current);
  const username = value(fields.find((f) => f.role === "username" && value(f) !== "" && isVisible(f.el)));
  if (!password) {
    // Step 1 of a multi-step sign-in (e.g. email first, password next): remember the username briefly.
    if (username && asksOnlyForAccount(fields)) {
      void send({ type: "username_seen", username }).catch(() => undefined);
    }
    return;
  }
  void send({ type: "submit_seen", username, password }).catch(() => undefined);
  // A page that does not navigate (fetch): ask a moment later, once.
  clearTimeout(askTimer);
  askTimer = setTimeout(() => void askSave(), 1_500);
}

/** Whether this frame has the top frame's origin (saving stays with the page's own forms). */
function sameOriginAsTop(): boolean {
  try {
    return window.top?.location.origin === location.origin;
  } catch {
    return false;
  }
}

async function askSave(): Promise<void> {
  if (window.top !== window) return;
  try {
    const saveId = await send<string | null>({ type: "save_pending" });
    if (saveId) ui.show("save", saveId);
  } catch {
    // the background is restarting
  }
}

// The person's last gesture (a press or a key), and the one a `submit` was
// last reported for. A page's `requestSubmit()` fires a trusted `submit`
// too, so a `submit` only counts right after a gesture of the person, and
// once per gesture: a page cannot fake them in a loop.
const GESTURE_MS = 1_000;
let gestureAt = 0;
let reportedAt = -1;
for (const type of ["pointerdown", "keydown"] as const) {
  document.addEventListener(
    type,
    (event) => {
      if (event.isTrusted && !ui.owns(event)) gestureAt = Date.now();
    },
    true,
  );
}

document.addEventListener(
  "submit",
  (event) => {
    if (!event.isTrusted || gestureAt === 0 || Date.now() - gestureAt > GESTURE_MS || reportedAt === gestureAt) return;
    reportedAt = gestureAt;
    const form = event.composedPath()[0];
    if (form instanceof HTMLFormElement) reportSubmit(form);
  },
  true,
);

document.addEventListener(
  "click",
  (event) => {
    if (!event.isTrusted || ui.owns(event)) return;
    const target = event.composedPath()[0];
    if (!(target instanceof Element)) return;
    const button = target.closest("button, input[type=submit], input[type=image], [role=button]");
    // A button that sends the form, not a «show password» eye.
    if (!button || !isSendButton(button)) return;
    const scope = scopeOf(button);
    const fields = fieldsOf(scope);
    if (fields.some((f) => f.role === "current-password" || f.role === "new-password") || asksOnlyForAccount(fields)) reportSubmit(scope);
  },
  true,
);

document.addEventListener(
  "keydown",
  (event) => {
    if (event.key !== "Enter" || !event.isTrusted) return;
    const target = event.composedPath()[0];
    if (!(target instanceof HTMLInputElement)) return;
    if (target.type === "password") {
      reportSubmit(scopeOf(target));
    } else if (target.value.trim() !== "") {
      const scope = scopeOf(target);
      if (asksOnlyForAccount(fieldsOf(scope))) reportSubmit(scope);
    }
  },
  true,
);

addEventListener("pagehide", () => {
  ui.reset();
  active = undefined;
});

/** Presses the form's button right after the fill's reply went back. */
function pressLater(scope: Scope, anchor: Element | undefined): void {
  setTimeout(() => {
    if (!captchaShown(document)) pressOnward(scope, anchor);
  }, 60);
}

/** Klav stopped a sign-in in steps: the menu opens on the form's field and says why. */
async function showStop(reason: StopReason): Promise<void> {
  const field =
    (active?.field.el.isConnected ? active.field.el : undefined) ??
    (() => {
      const scope = stepScope(document, "password") ?? bestScope(document, "login");
      const fields = scope ? fieldsOf(scope).filter((f) => isVisible(f.el)) : [];
      return (fields.find((f) => f.role === "current-password") ?? fields.find((f) => f.role === "username") ?? fields[0])?.el;
    })();
  const found = lookUp(field ?? null);
  if (!found) return;
  closeMenu(false);
  active = found;
  ui.showIcon(found.field.el);
  await openMenu(false, reason);
}

/** The palette was asked for with no field focused: it fills the form that fits the item best. */
async function openFind(): Promise<void> {
  try {
    const { findId } = await send<{ findId: string }>({ type: "find_open" });
    tokens.set(findId, (kind) => (active?.field.el.isConnected ? active.scope : bestScope(document, kind)));
  } catch {
    // the background is restarting
  }
}

/**
 * Assisted changes this document offered (ADR 0022 §5), by token: the
 * password box that had the focus, or none (the change form is found when
 * the values arrive). Kept a minute.
 */
const rotations = new Map<string, { box: HTMLInputElement | undefined; at: number }>();

function rotateProbe(nonce: string): void {
  const now = Date.now();
  for (const [token, r] of rotations) if (now - r.at > 60_000) rotations.delete(token);
  const box = focusedHere() ? focusedPassword(document) : undefined;
  // Frames without the focused box stay quiet; the top frame offers its form.
  if (!box && window.top !== window) return;
  const target = box ?? rotateTargets(document).next[0];
  const token = crypto.randomUUID();
  rotations.set(token, { box, at: now });
  const rules = target ? fieldRules(target) : undefined;
  const message: ContentMessage = { type: "rotate_here", nonce, token, focused: box !== undefined, ...(rules ? { rules } : {}) };
  void ext.runtime.sendMessage(message).catch(() => undefined);
}

/** How far up from a formless field Klav looks for its confirmation box. */
const GENERATED_LEVELS = 4;

/**
 * Where a generated password goes: the new-password boxes of the field's
 * form. Without a form (a whole document), only the field and the boxes of
 * the nearest container around it that has another one (its
 * confirmation), never every new-password box of the page.
 */
function generatedTargets(current: Active): Field[] {
  const boxes = fieldsOf(current.scope).filter((f) => f.role === "new-password" && isPasswordBox(f.el) && isVisible(f.el));
  if (!(current.scope instanceof Document)) return boxes;
  const own = boxes.find((f) => f.el === current.field.el);
  if (!own) return [];
  let node = own.el.parentElement;
  for (let level = 0; node && level < GENERATED_LEVELS; level++, node = node.parentElement) {
    const near = boxes.filter((f) => node?.contains(f.el));
    if (near.length > 1) return near;
  }
  return [own];
}

/** Whether this document itself has the keyboard (not one of its frames). */
function focusedHere(): boolean {
  if (!document.hasFocus()) return false;
  const el = document.activeElement;
  return !(el instanceof HTMLIFrameElement || el?.localName === "frame");
}

ext.runtime.onMessage.addListener(
  (message: ToContent, sender: chrome.runtime.MessageSender, sendResponse: (reply?: unknown) => void) => {
    if (sender.id !== ext.runtime.id) return false;
    switch (message.type) {
      case "fill": {
        // Only into a form this document offered: its menu, its sign-in form, its palette.
        const resolve = tokens.get(message.token);
        if (!resolve) return false;
        const scope = resolve(message.kind);
        if (active?.menuId === message.token) {
          delete active.menuId;
          ui.hide("menu");
        }
        const { reply, press, anchor } = typeItem(message.kind, message.values, scope, message.advance);
        message.values.length = 0;
        // Each token fills once; the sign-in form's stays until a fill reaches it (a retry, «Otra cuenta»).
        if (message.token !== loginToken || reply.filled.length > 0) tokens.delete(message.token);
        // Answer first, then press: a navigation must not lose the reply.
        sendResponse(reply satisfies FillReply);
        if (press && scope) pressLater(scope, anchor);
        return false;
      }
      case "expect":
        // The palette opened from this frame's menu fills this field's form.
        if (active?.menuId === message.menuId) {
          const scope = active.scope;
          tokens.set(message.token, (kind) => (scope instanceof Document || scope.isConnected ? scope : bestScope(document, kind)));
        }
        return false;
      case "fill_generated": {
        if (!active?.menuId || active.menuId !== message.menuId) return false;
        // The new-password boxes of the field's form (the password and its confirmation).
        const targets = generatedTargets(active);
        let filled = 0;
        for (const f of targets) if (setValue(f.el, message.value)) filled++;
        tokens.delete(active.menuId);
        delete active.menuId;
        ui.hide("menu");
        sendResponse({ filled });
        return false;
      }
      case "show":
        if (message.surface === "menu" || window.top === window) ui.show(message.surface, message.id);
        return false;
      case "size":
        ui.size(message.surface, message.id, message.height);
        return false;
      case "clear":
        // The passkey frame is the passkey bridge's (`content/webauthn.ts`): it answers.
        if (message.surface === "passkey") return false;
        // The background asks before acting on a choice in one of our frames.
        sendResponse(ui.isClear(message.surface, message.id));
        return false;
      case "hide":
        if (message.surface === "menu") {
          if (active?.menuId === message.id) closeMenu(true);
        } else {
          ui.hide(message.surface, message.id);
        }
        return false;
      case "where":
        // The background reads the address from `sender`, not from us.
        if (window.top === window) {
          void ext.runtime.sendMessage({ type: "here", nonce: message.nonce, doc: DOC } satisfies ContentMessage).catch(() => undefined);
        }
        return false;
      case "popup_fill": {
        // Only the document the popup was told about (Firefox has no documentId).
        if (window.top !== window || message.doc !== DOC) return false;
        // The form the person is in, else the one that fits the item best.
        const scope = active?.scope ?? bestScope(document, message.kind);
        const { reply, press, anchor } = typeItem(message.kind, message.values, scope, message.advance);
        message.values.length = 0;
        sendResponse(reply satisfies FillReply);
        if (press && scope) pressLater(scope, anchor);
        return false;
      }
      case "flow":
        watchFlow(message.until);
        return false;
      case "flow_stop":
        stopWatching();
        void showStop(message.reason);
        return false;
      case "agent_notice":
        if (window.top === window) ui.show("notice", message.noticeId);
        return false;
      case "agent_fill": {
        if (window.top !== window || message.doc !== DOC) return false;
        const { filled, scope, passwordFilled } = agentFill(document, message.kind, message.values, message.selectors);
        message.values.length = 0;
        let submitted = false;
        if (filled.length > 0) {
          ui.show("notice", message.noticeId);
          // Only a form that got the password is sent (G7).
          if (message.submit && passwordFilled) submitted = submitScope(scope);
        }
        sendResponse({ filled, submitted });
        return false;
      }
      case "rotate_probe":
        rotateProbe(message.nonce);
        return false;
      case "rotate_fill": {
        // Only a change this document offered, once.
        const offered = rotations.get(message.token);
        if (!offered) return false;
        rotations.delete(message.token);
        const targets = rotateTargets(document, offered.box);
        const filled = rotateFill(targets, message.current, message.next);
        message.current = "";
        message.next = "";
        let submitted = false;
        // The notice goes in the top frame (the background shows it there).
        if (filled.length > 0 && message.submit) submitted = submitScope(targets.scope);
        sendResponse({ filled, submitted });
        return false;
      }
      case "shortcut": {
        if (!focusedHere()) return false;
        const found = lookUp(deepActiveElement(document));
        if (found) {
          active = found;
          ui.showIcon(found.field.el);
          void openMenu(true);
        } else {
          void openFind();
        }
        return false;
      }
    }
  },
);

// A field focused before this script ran (`autofocus`): show the glyph, never fill.
{
  const found = lookUp(deepActiveElement(document));
  if (found) {
    active = found;
    ui.showIcon(found.field.el);
  }
  // A sign-in in steps going on in this tab: watch for its next field; else
  // a code field may offer the login just filled.
  void send<{ until: number } | null>({ type: "flow_ask" })
    .catch(() => null)
    .then((flow) => {
      if (flow) watchFlow(flow.until);
      else if (found?.field.role === "otp" && active === found) void offerCode(found);
    });
}

// A login sent from the previous page may be waiting to be saved; a
// sign-in form may deserve the top card.
void askSave();
lookForSignIn();
