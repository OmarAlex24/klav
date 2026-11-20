/**
 * The central palette: a search over the vault, opened with the shortcut
 * (no field focused) or from the field menu («Buscar otro elemento»).
 * What matches the page comes first. A login of another site is listed
 * too, but filling it asks first, with the page's host in view: that is
 * how phishing works, so it is never one click.
 */
import { localizePage, t, tNodes } from "../shared/i18n";
import { ask, daemon, type FindState } from "../shared/messages";
import type { ItemSummary, Suggestion } from "../shared/protocol";
import { h } from "./dom";
import { framePage } from "./frame";
import { COVERED, personClicked } from "./guard";
import { alertText, keyboard, lockedForm, say } from "./inpage";
import { icon } from "./kit";
import { siteTile } from "./siteicon";

localizePage("frame_find");
const root = document.getElementById("find") as HTMLElement;
const page = framePage("find", root);
const findId = page.id;

/** A row of the palette: a suggestion (matches this page) or another site's login. */
interface Entry {
  id: string;
  title: string;
  sub: string;
  /** For logins of other sites: their site, shown again in the confirmation. */
  elsewhere?: string;
  /** A login saved for a subdomain of this page (ADR 0025): one click, as the person picks it. */
  parent?: boolean;
  /** Where its logo or favicon comes from: the item's first URL, or this page's host. */
  site?: string;
  /** This page's address, for a login of this site. */
  page?: string;
  words: string;
}

function siteOf(url: string): string {
  try {
    return new URL(url.includes("://") ? url : `https://${url}`).hostname.replace(/^www\./, "");
  } catch {
    return url;
  }
}

function fromSuggestion(s: Suggestion, host?: string, page?: string): Entry {
  const sub = s.username ?? s.hint ?? s.location;
  return { id: s.id, title: s.title, sub, ...(host && s.kind === "login" ? { site: host, ...(page ? { page } : {}) } : {}), words: `${s.title} ${sub} ${s.location}`.toLowerCase() };
}

/** A login saved for a subdomain of this page: the host it was saved for in view. */
function fromParent(s: Suggestion, host?: string, page?: string): Entry {
  const sub = [s.username, t("saved_for", s.site ?? "")].filter(Boolean).join(" · ");
  return { ...fromSuggestion(s, host, page), sub, parent: true, words: `${s.title} ${sub} ${s.site ?? ""} ${s.location}`.toLowerCase() };
}

function fromSummary(item: ItemSummary): Entry {
  const site = item.urls[0] ? siteOf(item.urls[0]) : t("no_site");
  return {
    id: item.id,
    title: item.title,
    sub: item.username ?? `${item.vault} / ${item.project}`,
    elsewhere: site,
    ...(item.urls[0] ? { site: item.urls[0] } : {}),
    words: `${item.title} ${item.username ?? ""} ${item.urls.join(" ")} ${item.project}`.toLowerCase(),
  };
}

function render(...children: (Node | null)[]): void {
  root.replaceChildren(...children.filter((c): c is Node => c !== null));
  page.resize();
}

/** What a frame without a host can be called. */
function hostText(state: FindState): string {
  return state.host ?? t("this_page");
}

function fill(entry: Entry, confirmed: boolean, slot: HTMLElement, buttons: HTMLButtonElement[]): void {
  for (const b of buttons) b.disabled = true;
  ask<{ filled: number }>({ type: "find_fill", findId, item: entry.id, ...(confirmed ? { confirmed: true } : {}), ...(entry.parent ? { parent: true } : {}) }).then(
    ({ filled }) => {
      if (filled > 0) return;
      say(slot, t("nowhere_page"));
      for (const b of buttons) b.disabled = false;
      page.resize();
    },
    (e: unknown) => {
      say(slot, alertText(e));
      for (const b of buttons) b.disabled = false;
      page.resize();
    },
  );
}

/** «¿Rellenar GitHub en example.org?»: the two sites side by side, red where they differ. */
function confirm(state: FindState, entry: Entry, back: () => void): void {
  const slot = h("div", { class: "notice-slot" });
  const host = hostText(state);
  const go = h("button", { class: "btn btn-primary", type: "button" }, t("fill_on_host", host));
  const cancel = h("button", { class: "btn", type: "button" }, t("back"));
  go.addEventListener("click", (event) => {
    if (!personClicked(event, () => { say(slot, COVERED); page.resize(); })) return;
    fill(entry, true, slot, [go, cancel]);
  });
  cancel.addEventListener("click", back);
  const title = h("h2", { class: "confirm-title", tabindex: "-1" }, t("fill_question", entry.title, host));
  render(
    h(
      "section",
      { class: "confirm" },
      title,
      h(
        "div",
        { class: "sites cross" },
        h("div", { class: "site" }, h("span", { class: "site-label" }, t("login_is_for")), h("span", { class: "site-host" }, entry.elsewhere ?? t("another_site"))),
        h("div", { class: "site site-here" }, h("span", { class: "site-label" }, t("typing_on")), h("span", { class: "site-host" }, host)),
      ),
      h("p", { class: "mismatch" }, t("mismatch")),
      h("p", { class: "sub" }, t("phishing_note")),
      slot,
      h("div", { class: "confirm-actions" }, go, cancel),
    ),
  );
  title.focus();
}

function showList(state: FindState): void {
  const s = state.suggestions;
  const here = [...(s?.logins ?? [])].map((l) => fromSuggestion(l, state.host, state.page));
  const parent = (s?.parent ?? []).map((l) => fromParent(l, state.host, state.page));
  const cards = (s?.cards ?? []).map((c) => fromSuggestion(c));
  const identities = (s?.identities ?? []).map((i) => fromSuggestion(i));
  let others: Entry[] = [];
  const slot = h("div", { class: "notice-slot" });
  const search = h("input", {
    class: "find-input",
    type: "search",
    placeholder: t("search_login"),
    "aria-label": t("search_login_label"),
    autocomplete: "off",
    spellcheck: "false",
  });
  const results = h("div", { class: "results" });

  const row = (entry: Entry): HTMLButtonElement => {
    const button = h(
      "button",
      { class: "choice", type: "button", "data-id": entry.id },
      siteTile(entry.title, entry.site, entry.page),
      h("span", { class: "row-main" }, h("span", { class: "row-title" }, entry.title), h("span", { class: "row-sub" }, entry.sub)),
      entry.elsewhere ? h("span", { class: "choice-site" }, entry.elsewhere) : null,
      h("span", { class: "kbd choice-enter", "aria-hidden": "true" }, "↵"),
    );
    button.addEventListener("click", (event) => {
      if (entry.elsewhere) {
        // Only a step to the confirmation: no values move here.
        if (!event.isTrusted) return;
        confirm(state, entry, () => {
          showList(state);
        });
        return;
      }
      if (!personClicked(event, () => { say(slot, COVERED); page.resize(); })) return;
      fill(entry, false, slot, [...results.querySelectorAll<HTMLButtonElement>(".choice")]);
    });
    return button;
  };

  const section = (title: string, entries: Entry[]): HTMLElement[] =>
    entries.length === 0 ? [] : [h("h2", { class: "section-title" }, title), ...entries.map(row)];

  const draw = (): void => {
    const q = search.value.trim().toLowerCase();
    const keep = (e: Entry): boolean => q === "" || q.split(/\s+/).every((w) => e.words.includes(w));
    const parts = [
      ...section(t("on_host", hostText(state)), here.filter(keep)),
      ...section(t("group_parent"), parent.filter(keep)),
      ...section(t("other_logins"), others.filter(keep)),
      ...section(t("group_cards"), cards.filter(keep)),
      ...section(t("group_addresses"), identities.filter(keep)),
    ];
    if (here.length === 0 && q === "") {
      parts.unshift(h("p", { class: "empty" }, ...tNodes("no_login_for", h("strong", {}, hostText(state)))));
    }
    if (parts.length === 0) parts.push(h("p", { class: "empty" }, ...tNodes("nothing_matches", h("strong", {}, t("quote", search.value.trim())))));
    results.replaceChildren(...parts);
    page.resize();
  };

  search.addEventListener("input", draw);
  search.addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
      event.preventDefault();
      // Enter in the search box: the first result, as a click would.
      results.querySelector<HTMLButtonElement>(".choice")?.focus();
    }
  });

  render(
    h("div", { class: "find-bar" }, icon("search"), search, h("span", { class: "kbd" }, "Esc")),
    slot,
    results,
    h(
      "footer",
      { class: "find-foot" },
      h("span", {}, h("span", { class: "kbd" }, "↑"), h("span", { class: "kbd" }, "↓"), ` ${t("find_choose")}`),
      h("span", {}, h("span", { class: "kbd" }, "↵"), ` ${t("find_fill")}`),
      h("span", { class: "find-foot-end" }, ...tNodes("find_only_host", h("strong", {}, hostText(state)))),
    ),
  );
  draw();
  search.focus();

  // The rest of the vault's logins, for another account or a site saved under another address.
  void daemon<ItemSummary[]>({ op: "list", filter: { trash: false } }).then(
    (items) => {
      const seen = new Set([...here, ...parent].map((e) => e.id));
      others = items.filter((i) => i.kind === "login" && !seen.has(i.id)).map(fromSummary);
      draw();
    },
    () => undefined,
  );
}

async function load(): Promise<void> {
  try {
    const state = await ask<FindState>({ type: "find_load", findId });
    if (!state.status.logged_in) {
      render(h("p", { class: "empty" }, ...tNodes("no_account_run", h("strong", {}, "klav login"))));
    } else if (!state.status.unlocked) {
      render(h("div", { class: "find-locked" }, lockedForm(state.status, () => void load())));
    } else {
      showList(state);
    }
  } catch (e) {
    render(h("p", { class: "notice find-error", role: "alert" }, alertText(e)));
  }
}

keyboard(root, page.close);
void load();
