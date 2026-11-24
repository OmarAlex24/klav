/**
 * Pieces shared by Klav's frames inside pages (menu, card, palette, save
 * bar): the header, the small locked state and errors in plain words.
 */
import { t } from "../shared/i18n";
import { daemon } from "../shared/messages";
import { DaemonError, type DaemonStatus } from "../shared/protocol";
import { ditherCanvas, keyhole } from "../shared/dither";
import { h } from "./dom";
import { errorText } from "./strings";
import { unlockOpens } from "../shared/presence";

export const isMac = navigator.platform.toLowerCase().includes("mac");
/** The shortcut that opens the field menu (or the palette, with no field). */
export const SHORTCUT = isMac ? "⌘⇧L" : "Ctrl+Shift+L";

export function errorOf(e: unknown): DaemonError {
  return e instanceof DaemonError ? e : new DaemonError("internal", e instanceof Error ? e.message : "error");
}

export function alertText(e: unknown): string {
  const error = errorOf(e);
  return errorText(error.code, error.message);
}

/** A message in the slot `slot` (role=alert, so screen readers say it). */
export function say(slot: HTMLElement, text: string, tone: "error" | "info" = "error"): void {
  slot.replaceChildren(h("p", { class: tone === "error" ? "notice" : "notice notice-info", role: "alert" }, text));
}

/** «klav · host» on the left, `end` (a shortcut, a close button) on the right. */
export function frameHead(host: string | undefined, ...end: (Node | null)[]): HTMLElement {
  return h(
    "header",
    { class: "head" },
    h("span", { class: "head-title" }, host ? `Klav · ${host}` : "Klav"),
    h("span", { class: "head-end" }, ...end.filter((n): n is Node => n !== null)),
  );
}

export function shortcutKey(): HTMLElement {
  return h("span", { class: "kbd", title: t("shortcut_opens", SHORTCUT) }, SHORTCUT);
}

/**
 * «Klav está bloqueado.» with Touch ID or the master password, next to a
 * small closed keyhole in dither. `onUnlocked` runs after klavd unlocks.
 */
export function lockedForm(status: DaemonStatus, onUnlocked: () => void, problem?: DaemonError, extra?: Node): HTMLFormElement {
  const touchId = status.touch_id.available && status.touch_id.enrolled && !status.touch_id.password_required;
  const hole = ditherCanvas(document, keyhole(0), { palette: "blue", pixel: 1 });
  const form = h(
    "form",
    { class: "unlock" },
    h(
      "div",
      { class: "unlock-head" },
      h("span", { class: "unlock-hole" }, hole.canvas),
      h("p", { class: "unlock-what" }, t("locked_short")),
    ),
  );
  const slot = h("div", { class: "notice-slot" });
  if (problem) say(slot, errorText(problem.code, problem.message));
  form.append(slot);
  const unlock = (password?: string): void => {
    const { shown } = unlockOpens(status);
    const request = password === undefined ? { op: "unlock" as const } : { op: "unlock" as const, password, ...(shown ? { shown } : {}) };
    void daemon<DaemonStatus>(request).then(onUnlocked, (e: unknown) => {
      form.replaceWith(lockedForm(status, onUnlocked, errorOf(e), extra));
    });
  };
  if (touchId && problem?.code !== "biometry_unavailable") {
    const button = h("button", { class: "btn btn-primary", type: "submit" }, t("unlock_touch_id"));
    form.append(h("div", { class: "unlock-row" }, button, extra ?? null));
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      button.disabled = true;
      unlock();
    });
  } else {
    const input = h("input", {
      class: "input",
      type: "password",
      autocomplete: "current-password",
      placeholder: t("master_password"),
      "aria-label": t("master_password"),
      required: true,
    });
    const button = h("button", { class: "btn btn-primary", type: "submit" }, t("unlock"));
    form.append(h("div", { class: "unlock-row" }, input, button));
    // With the presence gate, what the password also opens (ADR 0041, own choice 34).
    const opens = unlockOpens(status).line;
    if (opens) form.append(h("p", { class: "row-sub unlock-opens" }, opens));
    if (extra) form.append(extra);
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      const password = input.value;
      input.value = "";
      button.disabled = true;
      unlock(password);
    });
    queueMicrotask(() => {
      input.focus();
    });
  }
  requestAnimationFrame(() => {
    hole.repaint();
  });
  return form;
}

/** Up/down arrows move between `.choice` buttons; Escape runs `onEscape`. */
export function keyboard(root: HTMLElement, onEscape: () => void): void {
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") {
      onEscape();
      return;
    }
    if (event.key !== "ArrowDown" && event.key !== "ArrowUp") return;
    const buttons = [...root.querySelectorAll<HTMLButtonElement>(".choice:not(:disabled)")];
    if (buttons.length === 0) return;
    event.preventDefault();
    const at = buttons.indexOf(document.activeElement as HTMLButtonElement);
    const next = event.key === "ArrowDown" ? (at + 1) % buttons.length : (at - 1 + buttons.length) % buttons.length;
    buttons[next]?.focus();
  });
}
