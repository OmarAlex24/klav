/**
 * Where an assisted password change (ADR 0022 §5) types its two values.
 * Only `<input type=password>` boxes, never anything else: a text box
 * would show the password in the clear.
 *
 * - The new password goes into the password box that has the keyboard
 *   (the one the agent selected), and into the form's confirmation box if
 *   it has one. With no password box focused, into the form's
 *   `new-password` boxes (the detection of `detect.ts`).
 * - The current password goes into the form's `current-password` box:
 *   changing a password implies filling the old one there.
 */
import { candidates, deepActiveElement, fieldsOf, isCandidate, scopeOf } from "./detect";
import { isVisible, setValue, type Visible } from "./fill";

/** A box Klav may type a password into: an enabled, editable `type=password` input. */
export function isPasswordBox(el: Element | null | undefined): el is HTMLInputElement {
  return el instanceof HTMLInputElement && el.type.toLowerCase() === "password" && isCandidate(el);
}

/** The password box with the keyboard in `doc` (through open shadow roots), if any. */
export function focusedPassword(doc: Document): HTMLInputElement | undefined {
  const el = deepActiveElement(doc);
  return isPasswordBox(el) ? el : undefined;
}

export interface RotateTargets {
  /** The form (or the document) of the change. */
  scope: Element | Document | undefined;
  /** Where the new password goes: the focused box (or the first new one), then its confirmation. */
  next: HTMLInputElement[];
  /** Where the current password goes. */
  current: HTMLInputElement[];
}

/** The visible password boxes of `scope`, by role. */
function boxes(scope: Element | Document, visible: Visible): { current: HTMLInputElement[]; next: HTMLInputElement[] } {
  const current: HTMLInputElement[] = [];
  const next: HTMLInputElement[] = [];
  for (const f of fieldsOf(scope)) {
    if (!isPasswordBox(f.el) || !visible(f.el)) continue;
    if (f.role === "new-password") next.push(f.el);
    else if (f.role === "current-password") current.push(f.el);
  }
  return { current, next };
}

/**
 * The boxes of the change form: around `focused` when the agent selected
 * one, else the form of `doc` with the most new-password boxes.
 */
export function rotateTargets(doc: Document, focused?: HTMLInputElement, visible: Visible = isVisible): RotateTargets {
  if (focused && isPasswordBox(focused) && focused.isConnected) {
    const scope = scopeOf(focused);
    const found = boxes(scope, visible);
    return {
      scope,
      next: [focused, ...found.next.filter((el) => el !== focused)],
      current: found.current.filter((el) => el !== focused),
    };
  }
  let best: RotateTargets = { scope: undefined, next: [], current: [] };
  for (const scope of new Set(candidates(doc).map((el) => scopeOf(el)))) {
    const found = boxes(scope, visible);
    if (found.next.length > best.next.length) best = { scope, ...found };
  }
  return best;
}

/** The roles filled, as the agent sees them: never values. */
export type RotateRole = "current_password" | "new_password" | "confirm_password";

/** Types the change: `next` into the new boxes, `current` into the old one. Returns the roles filled. */
export function rotateFill(targets: RotateTargets, current: string, next: string, visible: Visible = isVisible): RotateRole[] {
  const filled = new Set<RotateRole>();
  // Checked again right before typing: the page may have changed a box since the probe.
  const ok = (el: HTMLInputElement): boolean => el.isConnected && isPasswordBox(el) && visible(el);
  targets.next.forEach((el, i) => {
    if (ok(el) && setValue(el, next)) filled.add(i === 0 ? "new_password" : "confirm_password");
  });
  if (filled.size > 0) {
    for (const el of targets.current) if (ok(el) && setValue(el, current)) filled.add("current_password");
  }
  return [...filled];
}
