/**
 * Environments in the popup (ADR 0032 §6): one environment's variables with
 * their values hidden, «Show» and «Copy» on each (klavd asks for Touch ID
 * every time in a protected one), where a reference comes from, what an
 * agent changed, adding, changing and removing variables, the protected
 * flag and the trash; and the form of a new environment.
 *
 * Nothing here talks to klavd: the popup passes `hooks` that do. A value
 * lives only in the masked field that shows it, and goes when it hides or
 * the screen closes. Importing a `.env` stays the CLI's (§6).
 */
import { plural, t } from "../shared/i18n";
import type { EnvironmentDetail, EnvironmentEdit, ProjectSummary, VariableView } from "../shared/protocol";
import { h } from "./dom";
import { icon, iconButton } from "./kit";

/** A variable's name (ADR 0032 §1): case-sensitive, like the shell's. */
export const VARIABLE_NAME = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;
/** An environment's name: what `--env` and `klav://` write without quotes. */
export const ENVIRONMENT_NAME = /^[a-z0-9][a-z0-9_-]{0,63}$/;

/** `production` and `prod` start protected (ADR 0032 §3). */
export function protectedByDefault(name: string): boolean {
  return /^(production|prod)$/i.test(name.trim());
}

/** The text of a `resolve` value: base64url without padding, UTF-8. */
export function decodeValue(base64url: string): string {
  const base64 = base64url.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));
  return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
}

/** Where a variable's value comes from, in words: «Its own value», «From Stripe › api_key». */
export function originText(v: VariableView): string {
  if (v.origin === "value") return t("env_own_value");
  const from = v.target ? t("env_from", v.target) : t("env_from_unknown");
  return v.protected ? t("env_target_protected", from) : from;
}

/** The edit that sets `name` to its own `value`. */
export function setValueEdit(name: string, value: string): EnvironmentEdit {
  return { set: [{ name, value }] };
}

/** The edit that points `name` at another item's field. */
export function setReferenceEdit(name: string, reference: string): EnvironmentEdit {
  return { set: [{ name, reference: reference.trim() }] };
}

export function removeEdit(name: string): EnvironmentEdit {
  return { remove: [name] };
}

export function protectEdit(on: boolean): EnvironmentEdit {
  return { protected: on };
}

/** A new environment: created, never over an existing one. */
export function newEnvironmentEdit(protectedOn: boolean): EnvironmentEdit {
  return { create: true, must_be_new: true, protected: protectedOn };
}

/** What a draft of a variable lacks, or `undefined` when it can be saved. */
export function variableProblem(name: string, source: "value" | "reference", text: string): string | undefined {
  if (!VARIABLE_NAME.test(name)) return t("env_bad_variable");
  if (source === "reference" && !text.trim().startsWith("klav://")) return t("env_bad_reference");
  if (source === "value" && text === "") return t("env_empty_value");
  return undefined;
}

/** The masked field the popup draws (dither noise until «Show»). */
export interface Masked {
  el: HTMLElement;
  show: (text: string) => Promise<void>;
  hide: () => void;
}

export interface EnvironmentHooks {
  masked: () => Masked;
  /** One variable's value, through klavd (Touch ID in a protected environment). */
  value: (v: VariableView) => Promise<string>;
  copy: (value: string) => Promise<void>;
  /** Saves `edit`; `lowers`: it turns the protection off. Resolves once the screen may redraw. */
  save: (edit: EnvironmentEdit, lowers: boolean) => Promise<void>;
  trash: () => Promise<void>;
  failed: (e: unknown) => void;
}

/**
 * The environment's page below its header: the protected notice, what an
 * agent changed, the variables and their form, the protected flag and the
 * trash. `canChange` false (an account the server deleted) leaves only
 * «Show» and «Copy».
 */
export function environmentSections(detail: EnvironmentDetail, hooks: EnvironmentHooks, canChange = true): HTMLElement {
  const env = detail.environment;
  const root = h("div", { class: "env" });
  if (env.protected) {
    root.append(h("p", { class: "env-protected", role: "note" }, icon("lock"), h("span", {}, t("env_protected_notice"))));
  }
  const changes = detail.agent_changes;
  if (changes && changes.variables.length > 0) {
    root.append(h("p", { class: "notice", role: "alert" }, t("env_agent_changed", changes.agent ?? t("env_an_agent"), changes.variables.join(", "))));
  }

  const form = variableForm(hooks, canChange);
  const rows = h("dl", { class: "fields cross env-variables" });
  for (const v of detail.variables) rows.append(variableRow(v, hooks, canChange, form));
  root.append(detail.variables.length > 0 ? rows : h("p", { class: "sub env-none" }, t("env_none")));
  if (canChange) root.append(form.el);

  if (canChange) {
    const box = h("input", { class: "check", type: "checkbox", "aria-describedby": "env-protect-text" });
    box.checked = env.protected;
    box.addEventListener("change", () => {
      const on = box.checked;
      box.disabled = true;
      void hooks.save(protectEdit(on), !on).catch((e: unknown) => {
        box.checked = !on;
        hooks.failed(e);
      }).finally(() => {
        box.disabled = false;
      });
    });
    root.append(
      h(
        "label",
        { class: "setting env-protect" },
        box,
        h("span", { class: "setting-text" }, h("span", { class: "setting-title" }, t("env_protect_title")), h("span", { class: "sub", id: "env-protect-text" }, t("env_protect_text"))),
      ),
    );
    root.append(trashButton(env.name, hooks));
  }
  return root;
}

interface VariableForm {
  el: HTMLElement;
  /** Opens the form on an existing variable (its name kept, a new value). */
  edit: (name: string) => void;
}

function variableForm(hooks: EnvironmentHooks, canChange: boolean): VariableForm {
  const name = h("input", { class: "input mono", type: "text", autocomplete: "off", spellcheck: "false", "aria-label": t("env_name"), placeholder: "STRIPE_KEY" });
  const source = h(
    "select",
    { class: "input env-source", "aria-label": t("env_source") },
    h("option", { value: "value" }, t("env_value")),
    h("option", { value: "reference" }, t("env_reference")),
  );
  const text = h("input", { class: "input mono", type: "password", autocomplete: "off", spellcheck: "false", "aria-label": t("env_value") });
  const hint = h("p", { class: "sub new-hint", hidden: true }, t("env_reference_hint"));
  const error = h("p", { class: "notice new-error", role: "alert" });
  const save = h("button", { class: "btn btn-primary", type: "submit" }, t("save"));
  const el = h(
    "form",
    { class: "env-form new-form", hidden: !canChange },
    h("h2", { class: "label" }, t("env_add")),
    h("div", { class: "new-field" }, h("span", { class: "field-label" }, t("env_name")), name),
    h("div", { class: "new-field" }, h("span", { class: "field-label" }, t("env_source")), source),
    h("div", { class: "new-field" }, text, hint),
    error,
    h("div", { class: "env-form-actions" }, save),
  );
  const sourceChanged = (): void => {
    const reference = source.value === "reference";
    text.type = reference ? "text" : "password";
    text.placeholder = reference ? "klav://" : "";
    text.setAttribute("aria-label", t(reference ? "env_reference" : "env_value"));
    hint.hidden = !reference;
  };
  source.addEventListener("change", sourceChanged);
  el.addEventListener("submit", (event) => {
    event.preventDefault();
    const kind = source.value === "reference" ? "reference" : "value";
    const problem = variableProblem(name.value.trim(), kind, text.value);
    error.textContent = problem ?? "";
    name.setAttribute("aria-invalid", problem === t("env_bad_variable") ? "true" : "false");
    if (problem) return;
    const edit = kind === "reference" ? setReferenceEdit(name.value.trim(), text.value) : setValueEdit(name.value.trim(), text.value);
    // The value leaves the input as soon as it is sent.
    text.value = "";
    save.disabled = true;
    void hooks.save(edit, false).catch(hooks.failed).finally(() => {
      save.disabled = false;
    });
  });
  return {
    el,
    edit(variable: string) {
      name.value = variable;
      text.value = "";
      error.textContent = "";
      text.focus();
    },
  };
}

function variableRow(v: VariableView, hooks: EnvironmentHooks, canChange: boolean, form: VariableForm): HTMLElement {
  const value = hooks.masked();
  const toggle = h("button", { class: "btn btn-s", type: "button", "aria-label": t("show_field", v.name) }, t("show"));
  let shown = false;
  const hide = (): void => {
    value.hide();
    shown = false;
    toggle.textContent = t("show");
    toggle.setAttribute("aria-label", t("show_field", v.name));
  };
  toggle.addEventListener("click", () => {
    if (shown) {
      hide();
      return;
    }
    toggle.disabled = true;
    void hooks
      .value(v)
      .then(async (text) => {
        shown = true;
        toggle.textContent = t("hide");
        toggle.setAttribute("aria-label", t("hide_field", v.name));
        await value.show(text);
      }, hooks.failed)
      .finally(() => {
        toggle.disabled = false;
      });
  });
  // Every copy asks klavd again: a protected value asks for Touch ID each time.
  const copy = iconButton("copy", t("copy_field", v.name), () => {
    void hooks.value(v).then(hooks.copy, hooks.failed);
  });
  const actions: HTMLElement[] = [toggle, copy];
  if (canChange) {
    actions.push(
      iconButton("refresh", t("env_change", v.name), () => {
        hide();
        form.edit(v.name);
      }),
      iconButton("trash", t("env_remove", v.name), () => {
        void hooks.save(removeEdit(v.name), false).catch(hooks.failed);
      }),
    );
  }
  return h(
    "div",
    { class: "field-row env-variable", "data-name": v.name },
    h(
      "div",
      { class: "field-main" },
      h("dt", { class: "field-label mono" }, v.name),
      h("dd", { class: "field-value" }, value.el, h("span", { class: "sub env-origin" }, originText(v))),
    ),
    h("div", { class: "field-actions" }, ...actions),
  );
}

/** «Move to trash», then «Move production to the trash?» with Confirm and Cancel. */
function trashButton(name: string, hooks: EnvironmentHooks): HTMLElement {
  const slot = h("div", { class: "env-trash" });
  const first = h("button", { class: "btn btn-danger", type: "button" }, t("env_trash"));
  first.addEventListener("click", () => {
    const yes = h("button", { class: "btn btn-danger", type: "button" }, t("confirm"));
    const no = h("button", { class: "btn", type: "button" }, t("cancel"));
    yes.addEventListener("click", () => {
      yes.disabled = true;
      void hooks.trash().catch((e: unknown) => {
        yes.disabled = false;
        hooks.failed(e);
      });
    });
    no.addEventListener("click", () => {
      slot.replaceChildren(first);
    });
    slot.replaceChildren(h("p", { class: "sub" }, t("env_trash_confirm", name)), h("div", { class: "env-form-actions" }, yes, no));
    yes.focus();
  });
  slot.append(first);
  return slot;
}

/** An environment row's second line: «Personal / acme-api · 3 variables». */
export function environmentSub(vault: string, project: string, variables: number | undefined): string {
  return variables === undefined ? `${vault} / ${project}` : t("env_row_sub", vault, project, plural("env_variables", variables));
}

export interface NewEnvironmentHooks {
  create: (projectId: string, name: string, protectedOn: boolean) => Promise<void>;
  failed: (e: unknown) => void;
}

/**
 * The form of a new environment: its project, its name and the protected
 * flag, on by itself for `production` and `prod` until the person
 * touches it.
 */
export function newEnvironmentForm(projects: readonly ProjectSummary[], hooks: NewEnvironmentHooks): HTMLElement {
  const project = h(
    "select",
    { class: "input", "aria-label": t("env_project") },
    ...projects.map((p) => h("option", { value: p.id }, `${p.vault} / ${p.name}`)),
  );
  const name = h("input", { class: "input mono", type: "text", autocomplete: "off", spellcheck: "false", "aria-label": t("env_name"), placeholder: "development" });
  const box = h("input", { class: "check", type: "checkbox" });
  let touched = false;
  box.addEventListener("change", () => {
    touched = true;
  });
  name.addEventListener("input", () => {
    if (!touched) box.checked = protectedByDefault(name.value);
  });
  const error = h("p", { class: "notice new-error", role: "alert" });
  const create = h("button", { class: "btn btn-primary btn-block", type: "submit" }, t("env_create"));
  const form = h(
    "form",
    { class: "new-form env-new" },
    h("div", { class: "new-field" }, h("span", { class: "field-label" }, t("env_project")), project),
    h("div", { class: "new-field" }, h("span", { class: "field-label" }, t("env_name")), name),
    h(
      "label",
      { class: "setting" },
      box,
      h("span", { class: "setting-text" }, h("span", { class: "setting-title" }, t("env_protect_title")), h("span", { class: "sub" }, t("env_protect_text"))),
    ),
    error,
    create,
  );
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    const value = name.value.trim();
    if (!ENVIRONMENT_NAME.test(value)) {
      error.textContent = t("env_bad_name");
      name.setAttribute("aria-invalid", "true");
      return;
    }
    error.textContent = "";
    name.setAttribute("aria-invalid", "false");
    create.disabled = true;
    void hooks.create(project.value, value, box.checked).catch(hooks.failed).finally(() => {
      create.disabled = false;
    });
  });
  return form;
}
