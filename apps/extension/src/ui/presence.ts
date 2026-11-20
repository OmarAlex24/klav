/**
 * Presence before approving (ADR 0014): Touch ID goes straight on; without
 * it, the actions turn into a master-password form that keeps `keep`
 * (usually «Deny») next to «Confirm».
 */
import { t } from "../shared/i18n";
import { h } from "./dom";

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
