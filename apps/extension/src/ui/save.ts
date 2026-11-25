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

function showUpdate(state: SaveState, updates: Suggestion[], onBack?: () => void): void {
  const message = h("div", { class: "notice-slot" });
  const go = h("button", { class: "btn btn-primary", type: "submit" }, t("update"));
  const [only] = updates;
  const optionLabel = (u: Suggestion): string => {
    const showUser = Boolean(u.username && u.username !== state.username);
    const detail = [showUser ? u.username : undefined, placeOf(u)].filter(Boolean).join(" · ");
    return detail ? `${u.title} · ${detail}` : u.title;
  };
  // Several logins of the site with this username: the person picks which one.
  const which =
    updates.length > 1
      ? h(
          "select",
          { class: "input", name: "item", required: true },
          h("option", { value: "" }, t("save_update_pick")),
          ...updates.map((u) => h("option", { value: u.id }, optionLabel(u))),
        )
      : null;
  const backBtn = onBack ? h("button", { class: "btn-link", type: "button", onclick: onBack }, t("save_create_instead")) : null;
  const onlyDetail =
    only && !which
      ? [only.username && only.username !== state.username ? only.username : undefined, placeOf(only)].filter(Boolean).join(" · ")
      : "";
  const form = h(
    "form",
    { class: "save-form" },
    onlyDetail ? h("p", { class: "row-sub" }, onlyDetail) : null,
    which ? h("label", { class: "save-field" }, h("span", { class: "field-label" }, t("save_update_which")), which) : null,
    message,
    h("div", { class: "save-actions" }, go, later()),
    backBtn ? h("div", { class: "save-alt" }, backBtn) : null,
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

/** Picks a free title in the selected project: `base`, `base (user)`, then `base (2)…`. */
function nextFreeTitle(base: string, username: string, taken: Iterable<string>): string {
  const used = new Set<string>();
  for (const item of taken) used.add(item.trim().toLowerCase());
  const cleanBase = base.trim() || base;
  if (!used.has(cleanBase.toLowerCase())) return cleanBase;
  const user = username.trim();
  if (user) {
    const withUser = `${cleanBase} (${user})`;
    if (!used.has(withUser.toLowerCase())) return withUser;
  }
  for (let n = 2; n < 1000; n++) {
    const candidate = `${cleanBase} (${String(n)})`;
    if (!used.has(candidate.toLowerCase())) return candidate;
  }
  return cleanBase;
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
  const projects = state.projects ?? [];
  const where = h(
    "select",
    { class: "input", name: "project" },
    ...projects.map((p) => h("option", { value: `${p.vault}\u0000${p.name}` }, `${p.vault} / ${p.name}`)),
  );
  const takenFor = (projectKey: string): string[] => (projectKey ? (state.takenTitles?.[projectKey] ?? []) : []);
  const username = h("input", {
    class: "input",
    name: "username",
    value: state.username,
    placeholder: t("save_username_placeholder"),
    autocomplete: "username",
  });
  const title = h("input", { class: "input", name: "title", value: state.title ?? state.host, required: true });
  let titleEdited = false;

  const head = question(t("save_question"), state, state.title ?? state.host);
  const headSub = head.querySelector(".row-sub");

  const syncSuggestion = (): void => {
    const user = username.value.trim();
    if (headSub) headSub.textContent = `${user || t("no_username")} · ${state.host}`;
    if (!titleEdited) {
      title.value = nextFreeTitle(state.host, user, takenFor(where.value));
    }
  };
  username.addEventListener("input", syncSuggestion);
  where.addEventListener("change", () => {
    if (!titleEdited) {
      title.value = nextFreeTitle(state.host, username.value.trim(), takenFor(where.value));
    }
  });
  title.addEventListener("input", () => {
    titleEdited = true;
  });

  const siteLogins = state.siteLogins ?? [];
  const openUpdate = (targets: Suggestion[] = siteLogins): void => {
    showUpdate({ ...state, username: username.value.trim() }, targets, () => {
      showCreate({ ...state, username: username.value.trim() });
    });
  };

  const go = h("button", { class: "btn btn-primary", type: "submit" }, t("save"));
  const updateAlt =
    siteLogins.length > 0
      ? h(
          "button",
          {
            class: "btn-link",
            type: "button",
            onclick: () => {
              openUpdate();
            },
          },
          siteLogins.length === 1 && siteLogins[0] ? t("save_update_one_instead", siteLogins[0].title) : t("save_update_existing"),
        )
      : null;

  const usernameField = h("label", { class: "save-field" }, h("span", { class: "field-label" }, t("field_username")), username);
  const titleField = h("label", { class: "save-field" }, h("span", { class: "field-label" }, t("title")), title);
  const form = h(
    "form",
    { class: "save-form" },
    // When no username was detected (e.g. 2-step login), put the username field first so it is easy to fill in.
    ...(state.username === "" ? [usernameField, titleField] : [titleField, usernameField]),
    projects.length > 1 ? h("label", { class: "save-field" }, h("span", { class: "field-label" }, t("where")), where) : null,
    message,
    h("div", { class: "save-actions" }, go, later()),
    updateAlt ? h("div", { class: "save-alt" }, updateAlt) : null,
  );

  form.addEventListener("submit", (event) => {
    if (!decided(event, message)) return;
    go.disabled = true;
    ask<ItemSummary>({
      type: "save_do",
      saveId,
      action: "create",
      title: title.value,
      username: username.value.trim(),
      ...(where.value ? { project: where.value } : {}),
    }).then(
      (item) => {
        saved(item.title);
      },
      (e: unknown) => {
        const isTaken = /already exists/.test(errorOf(e).message);
        if (isTaken) {
          const taken = [...takenFor(where.value), title.value.trim()];
          const suggestion = nextFreeTitle(state.host, username.value.trim(), taken);
          const matching = siteLogins.find((l) => l.title.toLowerCase() === title.value.trim().toLowerCase());
          const useSuggested = h(
            "button",
            {
              class: "btn-link",
              type: "button",
              onclick: () => {
                title.value = suggestion;
                titleEdited = true;
                message.replaceChildren();
                page.resize();
              },
            },
            t("save_use_title", suggestion),
          );
          const updateMatching = matching
            ? h(
                "button",
                {
                  class: "btn-link",
                  type: "button",
                  onclick: () => {
                    openUpdate([matching]);
                  },
                },
                t("save_update_one_instead", matching.title),
              )
            : null;
          message.replaceChildren(problem(e), h("div", { class: "save-recovery" }, useSuggested, updateMatching));
        } else {
          message.replaceChildren(problem(e));
        }
        go.disabled = false;
        page.resize();
      },
    );
  });
  render(head, form);
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
