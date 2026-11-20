/**
 * The save bar: after the person sends a login form, offer to save it (or
 * to update the password of the login Klav has for that username). It
 * never sees the password: the background keeps it and saves it.
 */
import { localizePage, t, tNodes } from "../shared/i18n";
import { ask, type SaveState } from "../shared/messages";
import type { ItemSummary, Suggestion } from "../shared/protocol";
import { h } from "./dom";
import { framePage } from "./frame";
import { COVERED, personClicked } from "./guard";
import { alertText, errorOf, lockedForm, say } from "./inpage";
import { icon, iconButton } from "./kit";
import { siteTile } from "./siteicon";

localizePage("frame_save");
const root = document.getElementById("save") as HTMLElement;
const page = framePage("save", root);
const saveId = page.id;

function render(...children: (Node | null)[]): void {
  root.replaceChildren(...children.filter((c): c is Node => c !== null));
  page.resize();
}

function problem(e: unknown): HTMLElement {
  const text = /already exists/.test(errorOf(e).message)
    ? t("title_taken")
    : alertText(e);
  return h("p", { class: "notice", role: "alert" }, text);
}

function close(): HTMLButtonElement {
  return iconButton("close", t("close"), page.close);
}

/** The question and who it is about: «¿Guardar este login en Klav?» / «ana · github.com». */
function question(what: Node | string, state: SaveState, tileTitle: string): HTMLElement {
  return h(
    "div",
    { class: "save-head" },
    siteTile(tileTitle, state.host, state.page),
    h("div", { class: "row-main" }, h("p", { class: "save-what" }, what), h("p", { class: "row-sub" }, `${state.username || t("no_username")} · ${state.host}`)),
    close(),
  );
}

function saved(title: string): void {
  render(h("p", { class: "save-done", role: "status" }, icon("check"), h("span", {}, ...tNodes("saved", h("strong", {}, title)))));
  setTimeout(page.close, 2_500);
}

function later(): HTMLButtonElement {
  return h("button", { class: "btn", type: "button", onclick: page.close }, t("not_now"));
}

function showLocked(state: SaveState): void {
  render(
    question(t("save_question"), state, state.title ?? state.host),
    h("p", { class: "sub save-hint" }, t("unlock_to_decide")),
    lockedForm(state.status, () => void load(), undefined, later()),
  );
}

/** Only the person's own click (or Enter), on a bar nothing covers: like the menu (T62). */
function decided(event: Event, message: HTMLElement): boolean {
  event.preventDefault();
  return personClicked(event, () => {
    say(message, COVERED);
    page.resize();
  });
}

/** «Vault / Project» of a login, so the person tells two of the same site apart. */
function placeOf(login: Suggestion): string {
  return login.location;
}

function showUpdate(state: SaveState, updates: Suggestion[]): void {
  const message = h("div", { class: "notice-slot" });
  const go = h("button", { class: "btn btn-primary", type: "submit" }, t("update"));
  const [only] = updates;
  // Several logins of the site with this username: the person picks which one.
  const which =
    updates.length > 1
      ? h(
          "select",
          { class: "input", name: "item", required: true },
          h("option", { value: "" }, t("save_update_pick")),
          ...updates.map((u) => h("option", { value: u.id }, `${u.title} · ${placeOf(u)}`)),
        )
      : null;
  const form = h(
    "form",
    { class: "save-form" },
    only && !which ? h("p", { class: "row-sub" }, placeOf(only)) : null,
    which ? h("label", { class: "save-field" }, h("span", { class: "field-label" }, t("save_update_which")), which) : null,
    message,
    h("div", { class: "save-actions" }, go, later()),
  );
  form.addEventListener("submit", (event) => {
    if (!decided(event, message)) return;
    const item = which ? which.value : only?.id;
    if (!item) return;
    go.disabled = true;
    ask<ItemSummary>({ type: "save_do", saveId, action: "update", item }).then(
      (item) => {
        saved(item.title);
      },
      (e: unknown) => {
        message.replaceChildren(problem(e));
        go.disabled = false;
        page.resize();
      },
    );
  });
  const title = only && !which ? only.title : state.host;
  render(question(h("span", {}, ...tNodes("update_question", h("strong", {}, title))), state, title), form);
}

/**
 * After a login saved for a subdomain went into this page (ADR 0025 §2):
 * «Add <host> to this item», a normal edit of the item, so the login is
 * offered first here next time.
 */
function showAddSite(state: SaveState, item: Suggestion): void {
  const message = h("div", { class: "notice-slot" });
  const go = h("button", { class: "btn btn-primary", type: "submit" }, t("add_site"));
  const hint = h("p", { class: "sub save-hint" }, ...tNodes("add_site_hint", h("strong", {}, item.title), h("strong", {}, item.site ?? t("another_site"))));
  const form = h("form", { class: "save-form" }, message, h("div", { class: "save-actions" }, go, later()));
  form.addEventListener("submit", (event) => {
    if (!decided(event, message)) return;
    go.disabled = true;
    ask<ItemSummary>({ type: "save_do", saveId, action: "add_site" }).then(
      (saved) => {
        render(h("p", { class: "save-done", role: "status" }, icon("check"), h("span", {}, ...tNodes("site_added", h("strong", {}, state.host), h("strong", {}, saved.title)))));
        setTimeout(page.close, 2_500);
      },
      (e: unknown) => {
        message.replaceChildren(problem(e));
        go.disabled = false;
        page.resize();
      },
    );
  });
  render(question(h("span", {}, ...tNodes("add_site_question", h("strong", {}, state.host))), state, item.title), hint, form);
}

function showCreate(state: SaveState): void {
  const message = h("div", { class: "notice-slot" });
  const title = h("input", { class: "input", name: "title", value: state.title ?? state.host, required: true });
  const projects = state.projects ?? [];
  const where = h(
    "select",
    { class: "input", name: "project" },
    ...projects.map((p) => h("option", { value: `${p.vault}\u0000${p.name}` }, `${p.vault} / ${p.name}`)),
  );
  const go = h("button", { class: "btn btn-primary", type: "submit" }, t("save"));
  const form = h(
    "form",
    { class: "save-form" },
    h("label", { class: "save-field" }, h("span", { class: "field-label" }, t("title")), title),
    projects.length > 1 ? h("label", { class: "save-field" }, h("span", { class: "field-label" }, t("where")), where) : null,
    message,
    h("div", { class: "save-actions" }, go, later()),
  );
  form.addEventListener("submit", (event) => {
    if (!decided(event, message)) return;
    go.disabled = true;
    ask<ItemSummary>({ type: "save_do", saveId, action: "create", title: title.value, ...(where.value ? { project: where.value } : {}) }).then(
      (item) => {
        saved(item.title);
      },
      (e: unknown) => {
        message.replaceChildren(problem(e));
        go.disabled = false;
        page.resize();
      },
    );
  });
  render(question(t("save_question"), state, state.title ?? state.host), form);
}

async function load(): Promise<void> {
  try {
    const state = await ask<SaveState | null>({ type: "save_load", saveId });
    if (!state) {
      page.close();
      return;
    }
    if (state.addSite) {
      // Nothing to decide while locked: the login was just filled.
      if (state.status.unlocked) showAddSite(state, state.addSite);
      else page.close();
    } else if (!state.status.unlocked) showLocked(state);
    else if (state.updates && state.updates.length > 0) showUpdate(state, state.updates);
    else showCreate(state);
  } catch (e) {
    if (errorOf(e).code === "not_found") {
      page.close();
      return;
    }
    render(problem(e));
  }
}

document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") page.close();
});

void load();
