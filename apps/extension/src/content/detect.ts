/**
 * Form detection: which inputs of a page are a username, a password, a
 * one-time code, card fields or address fields. Pure functions over the
 * DOM (no layout), so they run the same in jsdom fixtures and in pages.
 * Visibility is checked separately, at fill time (`fill.ts`).
 */
import type { Group } from "../shared/messages";

export type { Group };

export type Role =
  | "username"
  | "current-password"
  | "new-password"
  | "otp"
  | "cc-name"
  | "cc-number"
  | "cc-exp"
  | "cc-exp-month"
  | "cc-exp-year"
  | "cc-csc"
  | "given-name"
  | "family-name"
  | "name"
  | "email"
  | "tel"
  | "address"
  | "city"
  | "region"
  | "postal-code"
  | "country";


export type FieldElement = HTMLInputElement | HTMLSelectElement;

export interface Field {
  el: FieldElement;
  role: Role;
}

export function groupOf(role: Role): Group {
  if (role === "username" || role === "current-password" || role === "new-password" || role === "otp") return "login";
  if (role.startsWith("cc-")) return "card";
  return "identity";
}

const TEXT_TYPES = new Set(["", "text", "email", "tel", "password", "number", "search", "url"]);

const AUTOCOMPLETE: Record<string, Role> = {
  username: "username",
  "current-password": "current-password",
  "new-password": "new-password",
  "one-time-code": "otp",
  "cc-name": "cc-name",
  "cc-number": "cc-number",
  "cc-exp": "cc-exp",
  "cc-exp-month": "cc-exp-month",
  "cc-exp-year": "cc-exp-year",
  "cc-csc": "cc-csc",
  "given-name": "given-name",
  "family-name": "family-name",
  name: "name",
  email: "email",
  tel: "tel",
  "tel-national": "tel",
  "street-address": "address",
  "address-line1": "address",
  "address-level2": "city",
  "address-level1": "region",
  "postal-code": "postal-code",
  country: "country",
  "country-name": "country",
};

/** Hints in English and Spanish, tried in this order (first match wins). */
const HINTS: [RegExp, Role][] = [
  [/(card.?holder|name.?on.?card|cc.?name|titular|nombre.?en.?la.?tarjeta)/, "cc-name"],
  [/(card.?num|cc.?num|credit.?card|n[uú]mero.?de.?(la.?)?tarjeta|tarjeta)/, "cc-number"],
  [/(\bcvv2?\b|\bcvc2?\b|\bcsc\b|\bcid\b|card.?(security|verification)|c[oó]digo.?de.?seguridad)/, "cc-csc"],
  // "MM/YY" in one box before the month-only and year-only patterns.
  [/(\bmm\s*\/?\s*(yy|aa)|month.?\/.?year|mes.?\/.?a[nñ]o)/, "cc-exp"],
  [/((exp|venc|caduc).*(month|mes|\bmm\b)|cc.?month|exp.?m\b)/, "cc-exp-month"],
  [/((exp|venc|caduc).*(year|a[nñ]o|\byy)|cc.?year|exp.?y\b)/, "cc-exp-year"],
  [/(expir|expiry|exp.?date|cc.?exp|vencimiento|caducidad|mm.?\/.?yy)/, "cc-exp"],
  [
    /(\botp\b|one.?time|\b2fa\b|\bmfa\b|totp|verification.?code|auth(entication|enticator)?.?code|two.?factor|security.?code|c[oó]digo.?de.?(verificaci[oó]n|acceso|un.?solo.?uso|seguridad))/,
    "otp",
  ],
  [/(user.?name|user.?id|\buser\b|\blogin\b|log.?in.?id|usuario|identifier|account.?name|nombre.?de.?usuario)/, "username"],
  [/(e.?mail|correo)/, "email"],
  [/(phone|\btel\b|tel[eé]fono|mobile|m[oó]vil|celular)/, "tel"],
  [/(first.?name|given.?name|fname|\bnombres?\b|primer.?nombre)/, "given-name"],
  [/(last.?name|family.?name|surname|lname|apellidos?)/, "family-name"],
  [/(full.?name|your.?name|nombre.?completo|^name$)/, "name"],
  [/(zip|postal|post.?code|c[oó]digo.?postal|\bcp\b)/, "postal-code"],
  [/(address|street|direcci[oó]n|\bcalle\b|domicilio)/, "address"],
  [/(\bcity\b|\btown\b|ciudad|localidad|municipio|poblaci[oó]n)/, "city"],
  [/(\bstate\b|province|region|\bestado\b|provincia|regi[oó]n)/, "region"],
  [/(country|\bpa[ií]s\b)/, "country"],
];

const NEW_PASSWORD = /(new|confirm|repeat|again|retype|create|sign.?up|register|nueva|confirma|repite|rep[ií]te|crear|registr)/;

/** Words only a one-time code uses (not «security code», which a card's CVV also is). */
const ONE_TIME_CODE = /(\botp\b|one.?time|\b2fa\b|\bmfa\b|totp|verification.?code|auth(entication|enticator)?.?code|two.?factor|c[oó]digo.?de.?(verificaci[oó]n|acceso|un.?solo.?uso))/;

/** Whether `el` says by itself that it takes a one-time code. */
function saysOneTimeCode(el: FieldElement): boolean {
  return fromAutocomplete(el) === "otp" || ONE_TIME_CODE.test(hintText(el));
}

/** Whether `el` could take a typed value at all. */
export function isCandidate(el: Element): el is FieldElement {
  if (el instanceof HTMLSelectElement) return !el.disabled;
  if (!(el instanceof HTMLInputElement)) return false;
  if (el.disabled || el.readOnly) return false;
  return TEXT_TYPES.has(el.type.toLowerCase());
}

/** The text a person sees next to a field: its labels and placeholders. */
export function hintText(el: FieldElement): string {
  const parts: (string | null | undefined)[] = [el.name, el.id, el.getAttribute("placeholder"), el.getAttribute("aria-label"), el.getAttribute("data-testid")];
  for (const label of el.labels ?? []) parts.push(label.textContent);
  const labelledBy = el.getAttribute("aria-labelledby");
  if (labelledBy) {
    const root = el.getRootNode() as Document | ShadowRoot;
    for (const id of labelledBy.split(/\s+/)) parts.push(root.getElementById(id)?.textContent);
  }
  return parts
    .filter((p): p is string => typeof p === "string" && p.length > 0)
    .join(" ")
    .toLowerCase()
    .replace(/[_\-[\]]+/g, " ");
}

function fromAutocomplete(el: FieldElement): Role | undefined {
  const tokens = (el.getAttribute("autocomplete") ?? "").toLowerCase().split(/\s+/).filter(Boolean);
  for (let i = tokens.length - 1; i >= 0; i--) {
    const role = AUTOCOMPLETE[tokens[i] ?? ""];
    if (role) return role;
  }
  return undefined;
}

/** The role of one field by itself (before looking at its form). */
export function classify(el: FieldElement): Role | undefined {
  const auto = fromAutocomplete(el);
  const type = el instanceof HTMLInputElement ? el.type.toLowerCase() : "select";
  const hints = hintText(el);
  if (type === "password") {
    if (auto === "current-password" || auto === "new-password" || auto === "otp" || auto === "cc-csc") return auto;
    if (/(\bcvv|\bcvc|\bcsc\b)/.test(hints)) return "cc-csc";
    if (/(\botp\b|one.?time|\b2fa\b|totp|verification.?code|c[oó]digo.?de.?verificaci[oó]n)/.test(hints)) return "otp";
    return NEW_PASSWORD.test(hints) ? "new-password" : "current-password";
  }
  if (auto) return auto;
  if (type === "email") return "email";
  if (type === "tel") return "tel";
  for (const [pattern, role] of HINTS) {
    if (pattern.test(hints)) return role;
  }
  if (el instanceof HTMLInputElement && (el.getAttribute("inputmode") === "numeric" || type === "number")) {
    const max = el.maxLength;
    if (max >= 4 && max <= 8 && /(code|c[oó]digo|pin|token)/.test(hints)) return "otp";
  }
  return undefined;
}

/** The form a field belongs to, across open shadow roots; else its document. */
export function scopeOf(el: Element): Element | Document {
  let node: Node = el;
  for (;;) {
    const form = node instanceof Element ? node.closest("form") : null;
    if (form) return form;
    const root = node.getRootNode();
    if (root instanceof ShadowRoot) {
      node = root.host;
      continue;
    }
    return root instanceof Document ? root : el.ownerDocument;
  }
}

/** Every candidate field under `root`, in document order, through open shadow roots. */
export function candidates(root: ParentNode): FieldElement[] {
  const out: FieldElement[] = [];
  const walk = (node: ParentNode): void => {
    for (const el of node.querySelectorAll("*")) {
      if (isCandidate(el)) out.push(el);
      if (el.shadowRoot) walk(el.shadowRoot);
    }
  };
  walk(root);
  return out;
}

/**
 * The classified fields of one scope (a form, or a document without one).
 * Context fixes what a field cannot say alone: next to a password, an
 * e-mail or an unnamed text box before it is the username.
 */
export function fieldsOf(scope: ParentNode): Field[] {
  const elements = candidates(scope).filter((el) => {
    // A form inside a formless document belongs to that form's scope.
    if (scope instanceof Document) return scopeOf(el) === scope;
    return true;
  });
  const fields = elements.map((el) => ({ el, role: classify(el) }));
  const firstPassword = fields.findIndex((f) => f.role === "current-password" || f.role === "new-password");
  const hasUsername = fields.some((f) => f.role === "username");
  const out: Field[] = [];
  fields.forEach((f, i) => {
    let role = f.role;
    if (firstPassword >= 0 && i < firstPassword && !hasUsername && f.el instanceof HTMLInputElement) {
      // The text or e-mail box right before the password.
      const isLast = !fields.slice(i + 1, firstPassword).some((g) => g.el instanceof HTMLInputElement && (g.role === undefined || g.role === "email" || g.role === "tel"));
      if (isLast && (role === undefined || role === "email" || role === "tel")) role = "username";
    }
    if (role === "email" && firstPassword >= 0 && !hasUsername && out.every((o) => o.role !== "username")) role = "username";
    if (role) out.push({ el: f.el, role });
  });
  // A one-time code split in one box per digit (4 to 8 boxes of one character).
  const digitBoxes = fields.filter(
    (f) =>
      (f.role === undefined || f.role === "otp") &&
      f.el instanceof HTMLInputElement &&
      f.el.maxLength === 1 &&
      (f.el.inputMode === "numeric" || f.el.type === "tel" || f.el.type === "number" || /\d/.test(f.el.pattern) || f.el.autocomplete === "one-time-code"),
  );
  if (digitBoxes.length >= 4 && digitBoxes.length <= 8) {
    for (const f of digitBoxes) if (!out.some((o) => o.el === f.el)) out.push({ el: f.el, role: "otp" });
    out.sort((a, b) => (a.el.compareDocumentPosition(b.el) & Node.DOCUMENT_POSITION_FOLLOWING ? -1 : 1));
  }
  // Next to card fields, a "security code" is the card's: only an ambiguous
  // one, in the card number's own form. A box that says it is a one-time
  // code (`one-time-code`, «verification code», one box per digit) keeps
  // that role: the CVV never goes into it.
  const number = out.find((f) => f.role === "cc-number");
  if (number) {
    for (const f of out) {
      if (f.role === "otp" && f.el.form === number.el.form && !digitBoxes.some((d) => d.el === f.el) && !saysOneTimeCode(f.el)) f.role = "cc-csc";
    }
  }
  // A sign-in step that asks only for the account ("username first").
  const only = out.length === 1 ? out[0] : undefined;
  if (firstPassword < 0 && only?.role === "email" && scope instanceof HTMLFormElement) {
    const signIn = /(identifier|login|log.?in|sign.?in|session|user|account|cuenta|iniciar|acceder|entrar)/;
    const formHints = `${scope.id} ${scope.getAttribute("action") ?? ""} ${scope.getAttribute("name") ?? ""}`.toLowerCase();
    if (signIn.test(hintText(only.el)) || signIn.test(formHints)) only.role = "username";
  }
  return out;
}

/** The groups a focused field should offer. */
export function groupsFor(field: Field, all: Field[]): Group[] {
  const group = groupOf(field.role);
  if (group !== "identity") return [group];
  // An e-mail in a form with a password is a username (handled above); an
  // identity form with card fields offers both.
  const groups = new Set<Group>(all.map((f) => groupOf(f.role)));
  return groups.has("card") ? ["identity", "card"] : ["identity"];
}

/** The deepest focused element, through open shadow roots. */
export function deepActiveElement(doc: Document): Element | null {
  let active = doc.activeElement;
  while (active?.shadowRoot?.activeElement) active = active.shadowRoot.activeElement;
  return active;
}
