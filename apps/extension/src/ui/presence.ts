/**
 * Presence before approving (ADR 0014): Touch ID goes straight on; without
 * it, the actions turn into a master-password form that keeps `keep`
 * (usually «Deny») next to «Confirm». Also the presence gate's question
 * for a value the popup or the menu asked for (ADR 0041 §3.2).
 */
import { t } from "../shared/i18n";
import { daemon } from "../shared/messages";
import { presenceQuestion } from "../shared/presence";
import { DaemonError, type PresenceAsk, type Request } from "../shared/protocol";
import { h } from "./dom";
import { errorText } from "./strings";

export function presence(actions: HTMLElement, touchId: boolean, go: (password?: string) => void, keep: HTMLElement[]): void {
  if (touchId) {
    go();
    return;
  }
  const input = h("input", {
    class: "input",
    type: "password",
    autocomplete: "current-password",
    placeholder: t("master_password"),
    "aria-label": t("password_to_approve"),
    required: true,
  });
  const confirm = h("button", { class: "btn btn-primary", type: "submit" }, t("confirm"));
  const form = h("form", { class: "approval-password" }, input, h("div", { class: "approval-actions" }, confirm, ...keep));
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    const password = input.value;
    input.value = "";
    go(password);
  });
  actions.replaceChildren(form);
  input.focus();
}

/** Requests that hand out a value and may get `presence_required` (ADR 0041). */
type GatedRequest = Extract<Request, { op: "view" | "totp" | "previous_password" | "generated_value" | "resolve" }>;

/** How many new questions in a row before giving up (the CLI stops at a third too). */
const MAX_ASKS = 3;

/**
 * Asks for the master password over this page, saying what klavd asks it
 * for. `undefined`: the person said «Not now».
 */
export function askPassword(asked: PresenceAsk, problem?: DaemonError): Promise<string | undefined> {
  return passwordDialog(presenceQuestion(asked), problem);
}

/**
 * The master password for `question` (lowering an environment's
 * protection on a Mac without Touch ID, ADR 0032 §3), over this page.
 * `undefined`: the person said «Not now».
 */
export function passwordDialog(question: string, problem?: DaemonError): Promise<string | undefined> {
  return new Promise((resolve) => {
    const slot = h("div", { class: "notice-slot" });
    if (problem) slot.append(h("p", { class: "notice", role: "alert" }, errorText(problem.code, problem.message)));
    const actions = h("div", {});
    const cancel = h("button", { class: "btn", type: "button" }, t("presence_cancel"));
    const dialog = h(
      "div",
      { class: "presence-modal", role: "dialog", "aria-modal": "true", "aria-label": t("presence_title") },
      h(
        "div",
        { class: "presence-box" },
        h("p", { class: "section-title" }, t("presence_title")),
        h("p", { class: "presence-question" }, question),
        actions,
        slot,
      ),
    );
    const done = (password?: string): void => {
      dialog.remove();
      resolve(password);
    };
    cancel.addEventListener("click", () => {
      done();
    });
    dialog.addEventListener("keydown", (event) => {
      if (event.key === "Escape") {
        event.stopPropagation();
        done();
      }
    });
    document.body.append(dialog);
    presence(actions, false, (password) => {
      done(password ?? "");
    }, [cancel]);
    actions.querySelector("input")?.setAttribute("aria-label", t("presence_password"));
  });
}

/**
 * `request` through klavd; with the presence gate on and no window open,
 * klavd answers `presence_required`, and the same request goes again with
 * the master password the person types here (a wrong one asks again).
 * Without the gate, one call, as always.
 */
export async function gated<T>(request: GatedRequest): Promise<T> {
  let error: DaemonError;
  try {
    return await daemon<T>(request);
  } catch (e) {
    error = errorOf(e);
  }
  let asked = error.presence;
  let problem: DaemonError | undefined;
  for (let asks = 0; error.code === "presence_required" || error.code === "wrong_credentials"; ) {
    if (error.code === "presence_required") {
      asked = error.presence;
      asks += 1;
      problem = undefined;
    } else {
      problem = error;
    }
    if (!asked || asks > MAX_ASKS) break;
    const password = await askPassword(asked, problem);
    if (password === undefined) throw new DaemonError("denied", t("presence_canceled"));
    try {
      return await daemon<T>({ ...request, password });
    } catch (e) {
      error = errorOf(e);
    }
  }
  throw error;
}

function errorOf(e: unknown): DaemonError {
  return e instanceof DaemonError ? e : new DaemonError("internal", e instanceof Error ? e.message : "error");
}
