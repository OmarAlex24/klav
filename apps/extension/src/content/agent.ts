/**
 * Filling for an agent: no menu, so Klav picks the form itself (the one
 * with the most fields for the item), or the fields the agent named with
 * CSS selectors, and then tells the person what happened.
 */
import type { AgentSelector } from "../shared/messages";
import type { FillValue, ItemKind } from "../shared/protocol";
import { candidates, type Field, fieldsOf, groupOf, isCandidate, type Role, scopeOf } from "./detect";
import { fillFields, isVisible, type Visible } from "./fill";

const WANTED: Record<ItemKind, string> = {
  login: "login",
  card: "card",
  identity: "identity",
  ssh_key: "",
  file: "",
  totp: "login",
  note: "",
  api_key: "",
};

/** The role a value takes when the agent gives its field a selector. */
function roleFor(value: FillValue): Role | undefined {
  switch (value.kind) {
    case "username":
      return "username";
    case "password":
      return "current-password";
    case "totp":
      return "otp";
    default:
      break;
  }
  const byName: Record<string, Role> = {
    cardholder: "cc-name",
    number: "cc-number",
    expiry: "cc-exp",
    cvv: "cc-csc",
    first_name: "given-name",
    last_name: "family-name",
    email: "email",
    phone: "tel",
    address: "address",
    city: "city",
    region: "region",
    postal_code: "postal-code",
    country: "country",
  };
  return byName[value.name];
}

/** The best form of `doc` for an item of `kind`, by how many of its fields are visible there. */
export function bestScope(doc: Document, kind: ItemKind, visible: Visible = isVisible): Element | Document | undefined {
  const scopes = new Set<Element | Document>(candidates(doc).map((el) => scopeOf(el)));
  let best: { scope: Element | Document; score: number } | undefined;
  for (const scope of scopes) {
    const fields = fieldsOf(scope).filter((f) => groupOf(f.role) === WANTED[kind] && visible(f.el));
    const score = fields.reduce((n, f) => n + (f.role === "current-password" ? 3 : f.role === "username" ? 2 : 1), 0);
    if (score > 0 && (!best || score > best.score)) best = { scope, score };
  }
  return best?.scope;
}

export interface AgentFill {
  filled: string[];
  scope: Element | Document | undefined;
  /** A password value was typed: only then may the form be sent. */
  passwordFilled: boolean;
}

/**
 * Whether the element an agent's selector picked may take `value` (layer
 * 04, G7): the agent (an LLM) chooses the selector, so a password or a
 * one-time code only goes into a password input, or a field Klav itself
 * reads as that role; never a search box the page reads as you type.
 */
function fitsValue(el: Element, value: FillValue): boolean {
  if (value.kind !== "password" && value.kind !== "totp") return true;
  if (el instanceof HTMLInputElement && el.type.toLowerCase() === "password") return true;
  if (value.kind === "password") return false;
  const detected = fieldsOf(scopeOf(el)).find((f) => f.el === el)?.role;
  return detected === "otp";
}

/** Types `values` into `doc`; selectors win over detection for their fields. */
export function agentFill(
  doc: Document,
  kind: ItemKind,
  values: FillValue[],
  selectors: AgentSelector[],
  visible: Visible = isVisible,
): AgentFill {
  const chosen: Field[] = [];
  for (const s of selectors) {
    const value = values.find((v) => v.name === s.field);
    let el: Element | null;
    try {
      el = doc.querySelector(s.selector);
    } catch {
      el = null; // not a valid selector
    }
    const role = value ? roleFor(value) : undefined;
    if (el && value && role && isCandidate(el) && fitsValue(el, value)) chosen.push({ el, role });
  }
  const scope = chosen[0] ? scopeOf(chosen[0].el) : bestScope(doc, kind, visible);
  const detected = scope ? fieldsOf(scope).filter((f) => !chosen.some((c) => c.role === f.role)) : [];
  // TOTP alone (`…/totp`): any visible one-time code field of the page.
  const fields = [...chosen, ...detected];
  if (!fields.some((f) => f.role === "otp") && values.some((v) => v.kind === "totp")) {
    for (const el of candidates(doc)) {
      const f = fieldsOf(scopeOf(el)).find((g) => g.el === el && g.role === "otp");
      if (f) fields.push(f);
    }
  }
  // An agent may sign up with a login it created (`create_item` with `generate`).
  const filled = fillFields(kind === "totp" ? "login" : kind, values, fields, visible, { signUp: true });
  const passwordFilled = values.some((v) => v.kind === "password" && filled.includes(v.name));
  return { filled, scope, passwordFilled };
}

/** Whether `form` sends to the page's own origin. */
function sameOrigin(form: HTMLFormElement): boolean {
  try {
    return new URL(form.action, location.href).origin === location.origin;
  } catch {
    return false;
  }
}

/** Submits the form that was filled (or its page's submit button). */
export function submitScope(scope: Element | Document | undefined): boolean {
  if (scope instanceof HTMLFormElement) {
    // Never to another site than the one the agent checked.
    if (!sameOrigin(scope)) return false;
    scope.requestSubmit();
    return true;
  }
  const root = scope ?? document;
  const button = [...root.querySelectorAll<HTMLButtonElement | HTMLInputElement>("button[type=submit], input[type=submit]")].find(
    (b) => !b.form && !b.hasAttribute("formaction"),
  );
  if (!button) return false;
  button.click();
  return true;
}
