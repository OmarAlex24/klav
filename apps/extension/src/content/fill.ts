/**
 * Typing values into a form. Only the fields of the form the person chose,
 * only visible ones (a hidden field is a classic way to collect a password
 * the person never sees being typed), and through the native value setter
 * plus `input`/`change` events so that framework-controlled inputs notice.
 */
import type { FillValue, ItemKind } from "../shared/protocol";
import type { Field, FieldElement, Role } from "./detect";

export type Visible = (el: FieldElement) => boolean;

/** Smallest box a person can see and type into (a 2×2 input is a hidden one). */
const MIN_SIDE = 6;

/**
 * Whether a person can see `el` (docs/extension.md §5, "Hidden fields"):
 * - at least 6×6 px;
 * - inside the page: not left of or above it (where nobody can scroll),
 *   nor past its right or bottom end; a field further down a long form
 *   still counts, since the person scrolls to it;
 * - not cut away by an ancestor that hides its overflow (`hidden`, `clip`);
 * - no `display: none`, `visibility: hidden`, opacity or `filter: opacity()`
 *   under 0.1, legacy `clip` or a `clip-path` that leaves nothing, on it or
 *   on any ancestor (across shadow roots).
 */
export function isVisible(el: FieldElement): boolean {
  const rect = el.getBoundingClientRect();
  if (rect.width < MIN_SIDE || rect.height < MIN_SIDE) return false;
  const doc = el.ownerDocument;
  const view = doc.defaultView ?? window;
  const root = doc.documentElement;
  const pageWidth = Math.max(root.scrollWidth, view.innerWidth);
  const pageHeight = Math.max(root.scrollHeight, view.innerHeight);
  const x = view.scrollX;
  const y = view.scrollY;
  if (rect.right + x <= 0 || rect.bottom + y <= 0 || rect.left + x >= pageWidth || rect.top + y >= pageHeight) return false;
  for (let node: Element | null = el; node; node = parentAcrossShadow(node)) {
    const style = view.getComputedStyle(node);
    if (style.display === "none" || style.visibility === "hidden" || style.visibility === "collapse") return false;
    if (Number(style.opacity) < 0.1 || filterOpacity(style.filter) < 0.1) return false;
    if (cutAway(style)) return false;
    if (node !== el && clipsOut(node, style, rect)) return false;
  }
  return true;
}

/** The smallest `opacity()` in a `filter` (1 without one). */
function filterOpacity(filter: string): number {
  let lowest = 1;
  for (const m of filter.matchAll(/opacity\(\s*([\d.]+)(%?)\s*\)/g)) {
    const v = Number(m[1]) / (m[2] === "%" ? 100 : 1);
    if (!Number.isNaN(v)) lowest = Math.min(lowest, v);
  }
  return lowest;
}

/**
 * A `clip` (legacy, only ever used to hide) or a `clip-path` that leaves
 * nothing: `inset()` of half or more, a circle or ellipse of radius zero.
 */
function cutAway(style: CSSStyleDeclaration): boolean {
  const clip = style.getPropertyValue("clip");
  if (clip && clip !== "auto" && style.position !== "static" && style.position !== "relative") return true;
  const path = style.clipPath;
  if (!path || path === "none") return false;
  if (/^inset\(\s*(5\d|[6-9]\d|100)(\.\d+)?%/.test(path)) return true;
  return /^(circle|ellipse)\(\s*0(px|%)?(\s|\)|$)/.test(path);
}

/** Whether `node` hides its overflow and `rect` lies wholly outside it. */
function clipsOut(node: Element, style: CSSStyleDeclaration, rect: DOMRect): boolean {
  const shorthand = style.overflow.split(/\s+/);
  const clips = (v: string | undefined): boolean => v === "hidden" || v === "clip";
  const clipsX = clips(style.overflowX) || clips(shorthand[0]);
  const clipsY = clips(style.overflowY) || clips(shorthand[1] ?? shorthand[0]);
  if (!clipsX && !clipsY) return false;
  const box = node.getBoundingClientRect();
  if (clipsX && (rect.right <= box.left || rect.left >= box.right)) return true;
  return clipsY && (rect.bottom <= box.top || rect.top >= box.bottom);
}

/** An `<input type=password>`: the only kind of box a password goes into, or is read from. */
export function isPasswordBox(el: Element): el is HTMLInputElement {
  return el instanceof HTMLInputElement && el.type.toLowerCase() === "password";
}

function parentAcrossShadow(node: Element): Element | null {
  if (node.parentElement) return node.parentElement;
  const root = node.getRootNode();
  return root instanceof ShadowRoot ? root.host : null;
}

const inputValue = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value");
const selectValue = Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, "value");

/** Sets a value the way typing would, so page frameworks see it. */
export function setValue(el: FieldElement, value: string): boolean {
  if (el instanceof HTMLSelectElement) {
    const option = matchOption(el, value);
    if (!option) return false;
    selectValue?.set?.call(el, option.value);
  } else {
    inputValue?.set?.call(el, value);
  }
  el.dispatchEvent(new Event("input", { bubbles: true, composed: true }));
  el.dispatchEvent(new Event("change", { bubbles: true }));
  return true;
}

function normalize(text: string): string {
  return text
    .normalize("NFD")
    .replace(/\p{Diacritic}/gu, "")
    .trim()
    .toLowerCase();
}

/** The option of a `<select>` that means `value` (by value or by text; numbers ignore leading zeros). */
export function matchOption(select: HTMLSelectElement, value: string): HTMLOptionElement | undefined {
  const wanted = normalize(value);
  const options = [...select.options];
  const asNumber = /^\d+$/.test(wanted) ? Number(wanted) : undefined;
  return (
    options.find((o) => normalize(o.value) === wanted || normalize(o.text) === wanted) ??
    (asNumber === undefined
      ? options.find((o) => wanted.length > 3 && normalize(o.text).startsWith(wanted))
      : options.find((o) => Number(o.value) === asNumber || Number(o.text) === asNumber))
  );
}

/** "MM/YY" in the shape a field asks for. */
function expiryFor(el: FieldElement, mmYY: string, role: Role): string | undefined {
  const match = /^(\d{2})\/(\d{2})$/.exec(mmYY);
  if (!match) return undefined;
  const [, mm = "", yy = ""] = match;
  const yyyy = `20${yy}`;
  const hints = `${el.getAttribute("placeholder") ?? ""} ${el.getAttribute("aria-label") ?? ""}`.toLowerCase();
  const max = el instanceof HTMLInputElement ? el.maxLength : -1;
  if (role === "cc-exp-month") return mm;
  if (role === "cc-exp-year") {
    if (el instanceof HTMLSelectElement) return [...el.options].some((o) => o.value.length === 4 || o.text.trim().length === 4) ? yyyy : yy;
    return max === 2 || /\byy\b|\baa\b/.test(hints) ? yy : yyyy;
  }
  if (/yyyy|aaaa/.test(hints) || max >= 7) return `${mm}/${yyyy}`;
  return `${mm}/${yy}`;
}

/** Which roles take a value of an item, by the value's name. */
const CARD: Record<string, Role[]> = {
  cardholder: ["cc-name"],
  number: ["cc-number"],
  expiry: ["cc-exp", "cc-exp-month", "cc-exp-year"],
  cvv: ["cc-csc"],
};
const IDENTITY: Record<string, Role[]> = {
  first_name: ["given-name"],
  last_name: ["family-name"],
  email: ["email"],
  phone: ["tel"],
  address: ["address"],
  city: ["city"],
  region: ["region"],
  postal_code: ["postal-code"],
  country: ["country"],
};

export interface FillOptions {
  /**
   * A sign-up: in a form without a current-password box, a login's
   * password goes into every new-password box (the password and its
   * confirmation). Only for an agent, which names the item it just created
   * (`create_item` with `generate`, ADR 0022 §7); the person's menu never
   * offers a saved login on a sign-up form.
   */
  signUp?: boolean;
}

/**
 * Types the values of one item into `fields` (one form). Returns the names
 * of the values typed (`username`, `password`…), each once.
 */
export function fillFields(kind: ItemKind, values: FillValue[], fields: Field[], visible: Visible = isVisible, options: FillOptions = {}): string[] {
  const shown = fields.filter((f) => visible(f.el));
  const byRole = (role: Role): Field[] => shown.filter((f) => f.role === role);
  const filled = new Set<string>();
  let current = "";
  const put = (targets: Field[], value: string | ((f: Field) => string | undefined)): void => {
    for (const f of targets) {
      const v = typeof value === "string" ? value : value(f);
      if (v !== undefined && setValue(f.el, v)) filled.add(current);
    }
  };
  if (kind === "login") {
    for (const v of values) {
      current = v.name;
      if (v.kind === "username") put(byRole("username"), v.value);
      if (v.kind === "totp") {
        const boxes = byRole("otp");
        const oneEach = boxes.length > 1 && boxes.length === v.value.length && boxes.every((f) => f.el instanceof HTMLInputElement && f.el.maxLength === 1);
        // A code in one box per digit: each digit in its box.
        if (oneEach) boxes.forEach((f, i) => { put([f], v.value[i] ?? ""); });
        else put(boxes, v.value);
      }
      if (v.kind === "password") {
        // Only into real password boxes: a field the page marks
        // `current-password` but shows as text (a search box) is not one.
        const current = byRole("current-password").filter((f) => isPasswordBox(f.el));
        const fresh = byRole("new-password").filter((f) => isPasswordBox(f.el));
        // A change-password form: only the current one. One lone password
        // box marked "new" by mistake still is the login's.
        put(current.length > 0 ? current : options.signUp || fresh.length === 1 ? fresh : [], v.value);
      }
    }
  } else if (kind === "card") {
    for (const v of values) {
      current = v.name;
      for (const role of CARD[v.name] ?? []) {
        put(byRole(role), v.name === "expiry" ? (f) => expiryFor(f.el, v.value, role) : v.value);
      }
    }
  } else if (kind === "identity") {
    const first = values.find((v) => v.name === "first_name")?.value;
    const last = values.find((v) => v.name === "last_name")?.value;
    const full = [first, last].filter(Boolean).join(" ");
    current = "first_name";
    if (full) put(byRole("name"), full);
    for (const v of values) {
      current = v.name;
      for (const role of IDENTITY[v.name] ?? []) put(byRole(role), v.value);
    }
  }
  return [...filled];
}
