/**
 * The page side of sign-ins in several steps: which button moves a form
 * on («Continuar», «Iniciar sesión»), whether the page asks for a captcha
 * (Klav stops there, it never tries to get past one), and where the next
 * step's field is once it shows.
 */
import type { StepRole } from "../shared/messages";
import { candidates, type Field, fieldsOf, scopeOf } from "./detect";
import { isVisible } from "./fill";

type Scope = Element | Document;

/** Words of a button that moves a sign-in on. */
const ONWARD =
  /^(continuar|continue|siguiente|next|seguir|iniciar sesi[oó]n|inicia sesi[oó]n|entrar|acceder|ingresar|sign in|sign on|log ?in|verificar|verify|confirmar|confirm|enviar|submit)\b/;
/** Buttons that look onward but go elsewhere: another way in, help, a new account. */
const ELSEWHERE = /(google|apple|github|microsoft|facebook|passkey|llave de acceso|sso|olvid|forgot|crear|create|registr|sign ?up|ayuda|help|cancel|atr[aá]s|back)/;

function textOf(el: Element): string {
  const value = el instanceof HTMLInputElement ? el.value : el.textContent;
  return `${value} ${el.getAttribute("aria-label") ?? ""}`.replace(/\s+/g, " ").trim().toLowerCase();
}

function usable(el: Element): boolean {
  if ((el as HTMLButtonElement).disabled || el.getAttribute("aria-disabled") === "true") return false;
  const rect = el.getBoundingClientRect();
  if (rect.width < 2 || rect.height < 2) return false;
  const style = getComputedStyle(el);
  return style.visibility !== "hidden" && style.display !== "none" && Number(style.opacity) >= 0.1;
}

function buttonsIn(root: ParentNode): HTMLElement[] {
  return [...root.querySelectorAll<HTMLElement>("button, input[type=submit], input[type=button], [role=button]")].filter(
    (b) => usable(b) && !ELSEWHERE.test(textOf(b)),
  );
}

/**
 * The button that moves `scope` on: its submit button, else one whose
 * words say so. Never a «Sign in with Google», «Forgot password» or
 * «Create account». Without a `<form>`, only near the filled field
 * (`anchor`): up to five levels around it, never a cookie banner across
 * the page.
 */
export function onwardButton(scope: Scope, anchor?: Element): HTMLElement | undefined {
  if (scope instanceof Document) {
    let node = anchor?.parentElement ?? null;
    for (let level = 0; node && level < 5; level++, node = node.parentElement) {
      const found = buttonsIn(node).find((b) => ONWARD.test(textOf(b)));
      if (found) return found;
    }
    return undefined;
  }
  const buttons = buttonsIn(scope);
  const isSubmit = (b: HTMLElement): boolean =>
    (b instanceof HTMLButtonElement && b.type === "submit") || (b instanceof HTMLInputElement && b.type === "submit");
  return buttons.find(isSubmit) ?? buttons.find((b) => ONWARD.test(textOf(b)));
}

/** A button that sends its form: `<button>` of type submit, `<input type=submit|image>`. */
function submits(el: Element): el is HTMLButtonElement | HTMLInputElement {
  if (el instanceof HTMLButtonElement) return el.type === "submit";
  return el instanceof HTMLInputElement && (el.type === "submit" || el.type === "image");
}

/** The origin of a form address, or `undefined` if it is not one. */
function originOf(action: string, base: string): string | undefined {
  try {
    return new URL(action, base).origin;
  } catch {
    return undefined;
  }
}

/**
 * Whether pressing `button` (or sending `form`) keeps the values on this
 * page's origin: the button's `formaction`, else its form's `action`
 * (layer 09; T68). A button that does not send a form (its page's script
 * handles it) stays on the page.
 */
export function sendsHome(button: HTMLElement | undefined, form: HTMLFormElement | null | undefined): boolean {
  const doc = (button ?? form)?.ownerDocument ?? document;
  const here = doc.location.origin;
  const base = doc.baseURI;
  if (button && !submits(button)) return true;
  const owner = button && submits(button) ? button.form : form;
  const formaction = button?.getAttribute("formaction");
  if (button && formaction !== null && formaction !== undefined && formaction.trim() !== "") return originOf(formaction, base) === here;
  if (!owner) return true;
  const action = owner.getAttribute("action");
  if (action === null || action.trim() === "") return true;
  return originOf(action, base) === here;
}

/** What Klav would press to move `scope` on, if it sends to this page's own origin. */
function onwardTarget(scope: Scope, anchor?: Element): HTMLElement | HTMLFormElement | undefined {
  const button = onwardButton(scope, anchor);
  if (button) return sendsHome(button, undefined) ? button : undefined;
  if (scope instanceof HTMLFormElement) return sendsHome(undefined, scope) ? scope : undefined;
  return undefined;
}

/** Whether Klav may press something to move `scope` on (never to another origin). */
export function canPressOnward(scope: Scope, anchor?: Element): boolean {
  return onwardTarget(scope, anchor) !== undefined;
}

/** Presses the button that moves `scope` on (as a click, so the page's handlers run); never one that sends elsewhere. */
export function pressOnward(scope: Scope, anchor?: Element): boolean {
  const target = onwardTarget(scope, anchor);
  if (target instanceof HTMLFormElement) {
    target.requestSubmit();
    return true;
  }
  if (target) {
    target.click();
    return true;
  }
  return false;
}

/** Words of a button that sends a password: signing in, signing up, saving a new one. */
const SENDS_PASSWORD =
  /^(continuar|continue|siguiente|next|seguir|iniciar sesi[oó]n|inicia sesi[oó]n|entrar|acceder|ingresar|sign in|sign on|sign up|log ?in|registr|register|crear|create|guardar|save|cambiar|change|actualizar|update|enviar|submit|confirmar|confirm)/;

/**
 * Whether a click on `el` sends its form: a submit button, or a button
 * whose words say so. Not a «show password» eye or «generate» button.
 */
export function isSendButton(el: Element): boolean {
  if (submits(el)) return true;
  return SENDS_PASSWORD.test(textOf(el));
}

const CAPTCHA =
  'iframe[src*="recaptcha"], iframe[src*="hcaptcha.com"], iframe[src*="challenges.cloudflare.com"], iframe[title*="captcha" i], .g-recaptcha, .h-captcha, .cf-turnstile, [data-sitekey]';

/** Whether `doc` shows a captcha (Klav does not press anything past it). */
export function captchaShown(doc: Document): boolean {
  return [...doc.querySelectorAll(CAPTCHA)].some((el) => {
    const rect = el.getBoundingClientRect();
    return rect.width >= 10 && rect.height >= 10 && getComputedStyle(el).visibility !== "hidden";
  });
}

/** The form of the first visible field of a step: a current password, or a one-time code. */
export function stepScope(doc: Document, role: StepRole): Scope | undefined {
  const wanted = (f: Field): boolean => (role === "password" ? f.role === "current-password" : f.role === "otp");
  for (const el of candidates(doc)) {
    const scope = scopeOf(el);
    const field = fieldsOf(scope).find((f) => f.el === el);
    if (field && wanted(field) && isVisible(field.el)) return scope;
  }
  return undefined;
}

/** Whether `fields` (of one form) ask only for the account: no visible password box. */
export function asksOnlyForAccount(fields: Field[]): boolean {
  const shown = fields.filter((f) => isVisible(f.el));
  return shown.some((f) => f.role === "username") && !shown.some((f) => f.role === "current-password" || f.role === "new-password");
}
