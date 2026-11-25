/**
 * The popup: unlock, the vault, one item, agents' requests. Secrets come
 * from klavd only when the person asks (`Mostrar`, `Copiar`) and are
 * forgotten when the item closes. One-time codes are asked for only while
 * they are on screen.
 */
import { animate, band, ditherCanvas, keyhole, mask } from "../shared/dither";
import { ext, installCommand } from "../shared/ext";
import { formatNumber, locale, localizePage, type MessageKey, plural, t } from "../shared/i18n";
import { ask, daemon, type PageMessage } from "../shared/messages";
import {
  DaemonError,
  type DaemonStatus,
  type FieldView,
  type ItemSummary,
  type ItemView,
  type PasskeyUv,
  type Suggestion,
  type Suggestions,
} from "../shared/protocol";
import { gated, presence } from "./presence";
import { watchApprovals } from "./approvals";
import { clear, h } from "./dom";
import { blocks, glyph, icon, iconButton, kindIcon, spaced } from "./kit";
import { settingChanged, siteTile } from "./siteicon";
import { errorText, fieldName, kindName } from "./strings";
import { filterLabel, ofKind, tabs, type VaultFilter } from "./filters";
import { CodeTicker } from "./totp";
import { klavCore } from "../shared/wasm";
import { generatorPanel, historyPanel } from "./generator";
import { mountHealth } from "./health";
import { agentSites } from "./agentsites";
import type { PasswordHistoryView } from "../shared/protocol";
import type { TotpInfo } from "./newitem";
import { unlockOpens } from "../shared/presence";

localizePage();
const app = document.getElementById("app") as HTMLElement;
const ticker = new CodeTicker();
const isMac = navigator.platform.toLowerCase().includes("mac");
const COPY_KEY = isMac ? "⌘C" : "Ctrl+C";
const PAGE_KEY = isMac ? "⌘⇧L" : "Ctrl+Shift+L";

function errorOf(e: unknown): DaemonError {
  return e instanceof DaemonError ? e : new DaemonError("internal", e instanceof Error ? e.message : "error");
}

function notice(text: string, tone: "error" | "info" = "error"): HTMLElement {
  return h("p", { class: tone === "error" ? "notice" : "notice notice-info", role: tone === "error" ? "alert" : "status" }, text);
}

/** Leaves the current screen: stops its timers and keyboard handlers. */
let leave: (() => void) | undefined;
function screen(className: string): void {
  leave?.();
  leave = undefined;
  ticker.stopAll();
  clear(app);
  app.className = `screen ${className}`;
}

/** The page in the active tab, if Klav runs there (the background asks the browser). */
async function activeTabUrl(): Promise<string | undefined> {
  const here = await ask<{ url: string } | null>({ type: "popup_here" } satisfies PageMessage);
  return here?.url;
}

async function start(): Promise<void> {
  let status: DaemonStatus;
  try {
    status = await daemon<DaemonStatus>({ op: "status" });
  } catch (e) {
    showUnavailable(errorOf(e));
    return;
  }
  if (!status.logged_in) showNoAccount();
  else if (!status.unlocked) showLocked(status);
  else await showVault(status);
}

function brand(): HTMLElement {
  return h("span", { class: "brand" }, glyph("brand-glyph"), h("span", { class: "brand-name" }, "klav"));
}

function showUnavailable(error: DaemonError): void {
  screen("screen-plain");
  app.append(
    h("header", { class: "bar" }, brand()),
    h(
      "section",
      { class: "plain" },
      h("h1", { class: "title" }, t("unavailable_title")),
      h("p", { class: "lede" }, errorText(error.code, error.message)),
      error.code === "host_missing"
        ? h(
            "div",
            { class: "steps" },
            h("p", {}, t("unavailable_install")),
            h("code", { class: "command" }, installCommand()),
            h("p", { class: "sub" }, t("unavailable_restart")),
          )
        : h("button", { class: "btn", type: "button", onclick: () => void start() }, t("retry")),
    ),
  );
}

function showNoAccount(): void {
  screen("screen-plain");
  app.append(
    h("header", { class: "bar" }, brand()),
    h(
      "section",
      { class: "plain" },
      h("h1", { class: "title" }, t("no_account_title")),
      h("p", { class: "lede" }, t("no_account_lede")),
      h("code", { class: "command" }, "klav login"),
    ),
  );
}

// ----------------------------------------------------------------- lock --

type Repaint = (field?: ReturnType<typeof keyhole>) => void;

function showLocked(status: DaemonStatus, problem?: DaemonError): void {
  screen("screen-locked");
  const touchId = status.touch_id.available && status.touch_id.enrolled && !status.touch_id.password_required;
  const usePassword = !touchId || problem?.code === "biometry_unavailable" || problem?.code === "biometry_failed";
  const field = ditherCanvas(document, keyhole(), { palette: "blue", pixel: 2 });
  const message = h("div", { class: "message" }, problem ? notice(errorText(problem.code, problem.message)) : null);

  const passwordForm = (): HTMLFormElement => {
    const input = h("input", {
      type: "password",
      class: "input",
      name: "password",
      autocomplete: "current-password",
      "aria-label": t("master_password"),
      placeholder: t("master_password"),
      required: true,
    });
    const submit = h("button", { class: "btn btn-primary", type: "submit" }, t("unlock"));
    // With the presence gate, what the password also opens (ADR 0041, own choice 34).
    const opens = unlockOpens(status).line;
    const form = h("form", { class: "unlock-form" }, input, submit, opens ? h("p", { class: "sub unlock-opens" }, opens) : null);
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      const password = input.value;
      input.value = "";
      submit.disabled = true;
      submit.textContent = t("checking");
      void unlock(status, field.repaint, password);
    });
    queueMicrotask(() => {
      input.focus();
    });
    return form;
  };

  const actions = h("div", { class: "actions" });
  if (usePassword) {
    actions.append(passwordForm());
    if (status.touch_id.password_required) {
      actions.append(h("p", { class: "sub" }, t("touch_id_needs_password", status.touch_id.password_required)));
    }
  } else {
    const button = h("button", { class: "btn btn-primary btn-block", type: "button" }, t("unlock_touch_id"));
    button.addEventListener("click", () => {
      button.disabled = true;
      button.textContent = t("waiting_touch_id");
      void unlock(status, field.repaint);
    });
    const other = h("button", { class: "btn-link", type: "button" }, t("use_master_password"));
    other.addEventListener("click", () => {
      actions.replaceChildren(passwordForm());
    });
    actions.append(button, other);
  }

  app.append(
    h("div", { class: "lock-field" }, field.canvas),
    h(
      "section",
      { class: "lock-body" },
      h("h1", { class: "title" }, t("locked_title")),
      status.email ? h("p", { class: "sub" }, status.email) : null,
      message,
      actions,
    ),
  );
  field.repaint();
}

async function unlock(previous: DaemonStatus, repaint: Repaint, password?: string): Promise<void> {
  try {
    const { shown } = unlockOpens(previous);
    const status = await daemon<DaemonStatus>(
      password === undefined ? { op: "unlock" } : { op: "unlock", password, ...(shown ? { shown } : {}) },
    );
    // The keyhole's light floods the field before the vault appears.
    await animate(400, (t) => {
      repaint(keyhole(t));
    });
    await showVault(status);
    if (status.already_unlocked === true) toast(t("already_unlocked"));
  } catch (e) {
    showLocked(previous, errorOf(e));
  }
}

// ------------------------------------------------------------ clipboard --

/** How long a message stays: long enough to read a sentence. */
const TOAST_MS = 5_000;
/**
 * «Copied» confirms what the person just did: one word, to notice rather
 * than to read, so it goes sooner and stops covering the rows below it
 * (Android's short toast is 2 s too).
 */
const COPIED_MS = 2_000;
let toastTimer: number | undefined;

/** A short message at the bottom; a copy's «Copied» comes with a check. */
function toast(text: string, copied = false): void {
  document.querySelector(".toast")?.remove();
  window.clearTimeout(toastTimer);
  const el = h("div", { class: "toast float", role: "status" }, copied ? icon("check") : null, h("span", { class: "toast-text" }, text));
  document.body.append(el);
  toastTimer = window.setTimeout(() => {
    el.remove();
  }, copied ? COPIED_MS : TOAST_MS);
}

/** Copies a value from the vault and asks the background to clear it later. */
async function copy(value: string): Promise<void> {
  try {
    await navigator.clipboard.writeText(value);
  } catch {
    toast(t("copy_failed"));
    return;
  }
  await ask({ type: "copied" } satisfies PageMessage).catch(() => undefined);
  toast(t("copied"), true);
}

async function copyCode(id: string): Promise<void> {
  try {
    const shown = ticker.current(id);
    const code = shown && shown.remaining > 1 ? shown.code : (await gated<{ code: string }>({ op: "totp", query: id })).code;
    await copy(code);
  } catch (e) {
    const error = errorOf(e);
    toast(errorText(error.code, error.message));
  }
}

/** Whether ⌘C / Ctrl+C should copy the site's code instead of selected text. */
function nothingSelected(): boolean {
  const active = document.activeElement;
  if (active instanceof HTMLInputElement && active.selectionStart !== active.selectionEnd) return false;
  return window.getSelection()?.isCollapsed !== false;
}

// ---------------------------------------------------------------- vault --

/** Rows the vault list draws at most, and how many before the first paint. */
const MAX_ROWS = 100;
const FIRST_ROWS = 20;
/**
 * Agents' requests are asked for once the vault shows and the search box is
 * quiet: this long after the first paint, and after the last key.
 */
const QUIET_AFTER_PAINT_MS = 700;
const QUIET_AFTER_KEY_MS = 1_500;
/** How often the vault asks klavd whether its copy changed: while it syncs, and after. */
const REVISION_FAST_MS = 250;
const REVISION_SLOW_MS = 3_000;

/** Runs `then` when the browser is idle (soon in any case). */
function whenIdle(then: () => void): void {
  if (typeof requestIdleCallback === "function") requestIdleCallback(then, { timeout: 200 });
  else setTimeout(then, 0);
}

/** What the vault screen remembers while an item is open. */
interface VaultContext {
  status: DaemonStatus;
  query: string;
  /** The type tab: «All», a type or «Codes». Kept while an item is open. */
  filter: VaultFilter;
  here?: { host: string; ids: Set<string> };
}

/** A live code: the pixel digits and the time blocks, one per second. */
function liveCode(id: string, title: string, size: "s" | "l"): { el: HTMLElement; stop: () => void } {
  const digits = h("span", { class: size === "l" ? "code" : "code-s" }, "··· ···");
  const bar = blocks();
  const el = h("span", { class: `live live-${size}`, role: "group", "aria-label": t("live_code", title) }, digits, bar.el);
  const stop = ticker.watch(id, (code) => {
    if (!code) {
      digits.textContent = "—";
      bar.set(0);
      return;
    }
    digits.textContent = spaced(code.code);
    bar.set(code.remaining);
  });
  return { el, stop };
}

function itemRow(item: { id: string; title: string; sub: string; site?: string; page?: string }, open: (id: string) => void, end?: Node): HTMLElement {
  return h(
    "li",
    { class: "row" },
    h(
      "button",
      { class: "row-open", type: "button", onclick: () => { open(item.id); } },
      siteTile(item.title, item.site, item.page),
      h("span", { class: "row-main" }, h("span", { class: "row-title" }, item.title), h("span", { class: "row-sub" }, item.sub)),
    ),
    end ?? null,
  );
}

/**
 * A row of «Codes», like an authenticator app: the title and user on top,
 * the code large under them, its time blocks, and one click copies it.
 * The code is asked of klavd only while the row is on screen (the `slot`
 * is watched by the caller). `site` and `page` pick its icon.
 */
function codeRow(
  item: { id: string; title: string; username?: string; site?: string; page?: string },
  copyIt: (id: string) => void,
): { el: HTMLElement; slot: HTMLElement } {
  const done = h("span", { class: "code-done", "aria-hidden": "true" }, icon("copy"));
  const button = h(
    "button",
    { class: "code-copy", type: "button", "data-id": item.id, "aria-label": t("copy_code_of", item.title), title: t("codes_copy_hint") },
    siteTile(item.title, item.site, item.page),
    h(
      "span",
      { class: "code-main" },
      h("span", { class: "code-name" }, h("span", { class: "row-title" }, item.title), item.username ? h("span", { class: "row-sub" }, item.username) : null),
      h("span", { class: "code" }, "··· ···"),
      blocks().el,
    ),
    done,
  );
  button.addEventListener("click", () => {
    copyIt(item.id);
    done.replaceChildren(icon("check"));
    button.classList.add("is-copied");
    setTimeout(() => {
      done.replaceChildren(icon("copy"));
      button.classList.remove("is-copied");
    }, 1_500);
  });
  return { el: h("li", { class: "code-row" }, button), slot: button };
}

/** Fills `id` into the active tab and closes the popup. */
async function fillFromPopup(id: string, button: HTMLButtonElement, parent = false): Promise<void> {
  button.disabled = true;
  try {
    const { filled } = await ask<{ filled: number }>({ type: "popup_fill", item: id, ...(parent ? { parent: true } : {}) } satisfies PageMessage);
    if (filled === 0) {
      toast(t("nowhere_page"));
      button.disabled = false;
      return;
    }
    window.close();
  } catch (e) {
    const error = errorOf(e);
    toast(errorText(error.code, error.message));
    button.disabled = false;
  }
}

/**
 * A login saved for a subdomain of the current site (ADR 0025): «Rellenar»
 * with the host it was saved for in view. Once filled, the page offers to
 * add this site to the item.
 */
function parentRow(login: Suggestion, host: string, page: string, open: (id: string) => void): HTMLElement {
  const fill = h("button", { class: "btn", type: "button", "aria-label": t("fill_item", login.title) }, t("fill"));
  fill.addEventListener("click", () => void fillFromPopup(login.id, fill, true));
  const sub = [login.username, t("saved_for", login.site ?? "")].filter(Boolean).join(" · ");
  return itemRow({ id: login.id, title: login.title, sub, site: host, page }, open, fill);
}

/** A login of the current site: «Rellenar» and, with a code, the live code under it. */
function hereRow(login: Suggestion, host: string, page: string, open: (id: string) => void): { el: HTMLElement; stop?: () => void; codeId?: string } {
  const fill = h("button", { class: "btn", type: "button", "aria-label": t("fill_item", login.title) }, t("fill"));
  fill.addEventListener("click", () => void fillFromPopup(login.id, fill));
  const row = itemRow({ id: login.id, title: login.title, sub: login.username ?? login.hint ?? "", site: host, page }, open, fill);
  if (!login.totp) return { el: row };
  const code = liveCode(login.id, login.title, "s");
  row.classList.add("row-here");
  row.append(
    h(
      "div",
      { class: "row-code" },
      code.el,
      iconButton("copy", t("copy_code_of", login.title), () => void copyCode(login.id)),
      h("span", { class: "kbd", title: t("copy_key_hint", COPY_KEY) }, COPY_KEY),
    ),
  );
  return { el: row, stop: code.stop, codeId: login.id };
}

async function showVault(status: DaemonStatus, query = "", filter: VaultFilter = "all"): Promise<void> {
  screen("screen-vault");
  const lock = h("button", { class: "btn", type: "button" }, t("lock"));
  lock.addEventListener("click", () => {
    void daemon<DaemonStatus>({ op: "lock" }).then(
      (s) => {
        showLocked(s);
      },
      (e: unknown) => {
        showUnavailable(errorOf(e));
      },
    );
  });
  const search = h("input", {
    type: "search",
    class: "input search",
    placeholder: t("search_vault"),
    "aria-label": t("search_vault"),
    autocomplete: "off",
    spellcheck: "false",
  });
  search.value = query;
  const approvals = h("section", { class: "approvals-wrap", "aria-label": t("agent_requests") });
  const here = h("section", { class: "group", "aria-label": t("on_this_page") });
  // «Codes» has its own: the codes of the page's logins and the codes on their own that name it.
  const hereCodes = h("section", { class: "group", "aria-label": t("on_this_page"), hidden: true });
  const results = h("ul", { class: "list" });
  const heading = h("h2", { class: "label" }, t("your_vault"));
  const all = h("section", { class: "group" }, heading, results);
  // The type tabs, under the search: drawn once the list says what there is.
  const kinds = h("div", { class: "kinds", role: "tablist", "aria-label": t("filter_by_type"), hidden: true });
  const settings = iconButton("gear", t("settings"), () => void showSettings(status));
  const generate = iconButton("asterisk", t("gen_open"), () => void showGenerator(status));
  const health = iconButton("pulse", t("health_open"), () => { showHealth(status); });
  const add = iconButton("plus", t("new_open"), () => void showNewItem(status));
  app.append(
    h("header", { class: "bar" }, brand(), h("span", { class: "bar-end" }, add, health, generate, settings, lock)),
    h("div", { class: "content" }, approvals, h("div", { class: "search-wrap" }, search, h("span", { class: "kbd search-key" }, "/")), kinds, here, hereCodes, all),
  );
  queueMicrotask(() => {
    search.focus();
  });

  const context: VaultContext = { status, query, filter };
  const open = (id: string): void => {
    context.query = search.value;
    void showItem(id, context);
  };

  // ⌘C / Ctrl+C copies the current site's code; "/" goes to the search box.
  let siteCode: string | undefined;
  const onKey = (event: KeyboardEvent): void => {
    if (event.key === "/" && document.activeElement !== search) {
      event.preventDefault();
      search.focus();
      return;
    }
    if (siteCode && (event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "c" && nothingSelected()) {
      event.preventDefault();
      void copyCode(siteCode);
    }
  };
  document.addEventListener("keydown", onKey);

  // Codes in the list: asked of klavd only while their row is on screen.
  const stops = new Map<Element, () => void>();
  const visible = new IntersectionObserver((entries) => {
    for (const entry of entries) {
      const slot = entry.target as HTMLElement;
      if (entry.isIntersecting && !stops.has(slot)) {
        const stop = ticker.watch(slot.dataset.id ?? "", (code) => {
          if (!code) {
            visible.unobserve(slot);
            const big = slot.querySelector(".code");
            // A row of «Codes» keeps its place; a list row shows its kind instead.
            if (big) big.textContent = "—";
            else slot.replaceWith(h("span", { class: "row-end" }, h("span", { class: "mono" }, kindName(slot.dataset.kind ?? "", true))));
            return;
          }
          const digits = slot.querySelector(".code-s, .code");
          if (digits) digits.textContent = spaced(code.code);
          slot.querySelectorAll(".blocks > i").forEach((b, i) => b.classList.toggle("on", i < code.remaining));
        });
        stops.set(slot, stop);
      } else if (!entry.isIntersecting) {
        stops.get(slot)?.();
        stops.delete(slot);
      }
    }
  });
  let hereStops: (() => void)[] = [];
  let watching: ReturnType<typeof setTimeout> | undefined;
  leave = () => {
    document.removeEventListener("keydown", onKey);
    visible.disconnect();
    clearTimeout(watching);
    for (const stop of [...stops.values(), ...hereStops]) stop();
  };

  /** The end of a list row: its live code (logins may have one) or its kind. */
  const rowEnd = (i: ItemSummary): HTMLElement => {
    const onPage = context.filter === "all" && context.here?.ids.has(i.id) === true;
    const mayHaveCode = (i.kind === "login" || i.kind === "totp") && !CodeTicker.hasNone(i.id) && !onPage;
    if (!mayHaveCode) return h("span", { class: "row-end" }, h("span", { class: "mono" }, kindName(i.kind, true)));
    const slot = h(
      "button",
      { class: "row-end row-totp", type: "button", "data-id": i.id, "data-kind": i.kind, "aria-label": t("copy_code_of", i.title) },
      h("span", { class: "code-s" }, "··· ···"),
      blocks().el,
    );
    slot.addEventListener("click", () => void copyCode(i.id));
    visible.observe(slot);
    return slot;
  };
  const listRow = (i: ItemSummary): HTMLElement =>
    itemRow({ id: i.id, title: i.title, sub: i.username ?? `${i.vault} / ${i.project}`, site: i.urls[0] }, open, rowEnd(i));

  const codeListRow = (i: ItemSummary): HTMLElement => {
    const row = codeRow({ id: i.id, title: i.title, username: i.username, site: i.urls[0] }, (id) => void copyCode(id));
    visible.observe(row.slot);
    return row.el;
  };

  /**
   * The page's codes, at the top of «Codes» (showHere fills it): those of
   * its logins and the codes on their own that name it. Not those of a
   * login saved for a subdomain (ADR 0025): like in «All», they stay in
   * the list. What shows here is left out of the list below.
   */
  let pageCodes: { host: string; page: string; items: Suggestion[] } | undefined;
  let pageCodeIds = new Set<string>();
  let pageSlots: HTMLElement[] = [];
  const drawPageCodes = (): void => {
    for (const slot of pageSlots) {
      stops.get(slot)?.();
      stops.delete(slot);
      visible.unobserve(slot);
    }
    pageSlots = [];
    const codes = pageCodes;
    if (context.filter !== "codes" || !codes) {
      hereCodes.replaceChildren();
      hereCodes.hidden = true;
      return;
    }
    const rows = codes.items.map((s) =>
      codeRow({ id: s.id, title: s.title, username: s.username, site: codes.host, page: codes.page }, (id) => void copyCode(id)),
    );
    pageSlots = rows.map((r) => r.slot);
    hereCodes.replaceChildren(h("h2", { class: "label" }, t("on_host", codes.host)), h("ul", { class: "list list-codes" }, ...rows.map((r) => r.el)));
    hereCodes.hidden = false;
    for (const slot of pageSlots) visible.observe(slot);
  };

  /** Everything the search found, of every type: the tabs count it. */
  let listed: ItemSummary[] = [];
  /**
   * The items with a code (klavd's `list` with `codes`), asked once the
   * vault shows, or at once for «Codes». Kept until `revision` moves.
   */
  let codeIds: Set<string> | undefined;
  let codesFailed: DaemonError | undefined;
  let codesAsked: Promise<void> | undefined;
  const loadCodes = (): Promise<void> =>
    (codesAsked ??= daemon<ItemSummary[]>({ op: "list", filter: { trash: false, codes: true } }).then(
      (items) => {
        codeIds = new Set(items.map((i) => i.id));
        codesFailed = undefined;
      },
      (e: unknown) => {
        codesFailed = errorOf(e);
        codesAsked = undefined;
      },
    ));

  const drawTabs = (): void => {
    const ids = codeIds;
    const codes = ids ? listed.filter((i) => ids.has(i.id)).length : undefined;
    const list = tabs(listed, codes, context.filter);
    const hadFocus = kinds.contains(document.activeElement);
    kinds.hidden = list.length === 0;
    kinds.replaceChildren(
      ...list.map((tab) => {
        const on = tab.filter === context.filter;
        const name = t(filterLabel(tab.filter));
        const button = h(
          "button",
          {
            class: on ? "kind-tab is-on" : "kind-tab",
            type: "button",
            role: "tab",
            "aria-selected": on ? "true" : "false",
            tabindex: on ? "0" : "-1",
            "data-filter": tab.filter,
            ...(tab.count === undefined ? {} : { "aria-label": t("filter_tab", name, tab.count) }),
          },
          kindIcon(tab.filter),
          name,
          tab.count === undefined ? null : h("span", { class: "kind-count", "aria-hidden": "true" }, formatNumber(tab.count)),
        );
        button.addEventListener("click", () => {
          choose(tab.filter);
        });
        return button;
      }),
    );
    const on = kinds.querySelector<HTMLElement>(".is-on");
    if (hadFocus) on?.focus();
    on?.scrollIntoView({ block: "nearest", inline: "nearest" });
    edges();
  };
  /** Marks the ends of the tab row that hide more tabs (popup.css fades them). */
  const edges = (): void => {
    const end = kinds.scrollWidth - kinds.clientWidth - kinds.scrollLeft;
    kinds.classList.toggle("more-start", kinds.scrollLeft > 1);
    kinds.classList.toggle("more-end", end > 1);
  };
  kinds.addEventListener("scroll", edges, { passive: true });

  const emptyRow = (q: string): HTMLElement => {
    const filter = context.filter;
    if (filter === "codes" && codesFailed) return h("li", {}, notice(errorText(codesFailed.code, codesFailed.message)));
    if (filter === "codes" && !q) {
      return h(
        "li",
        { class: "empty empty-codes" },
        h("span", { class: "empty-title" }, t("codes_none")),
        h("span", {}, t("codes_none_text")),
        h("button", { class: "btn-link empty-import", type: "button", onclick: openImport }, t("imp_open")),
      );
    }
    if (filter !== "all") {
      const name = t(filterLabel(filter));
      return h("li", { class: "empty" }, q ? t("nothing_in", name, t("quote", q)) : t("filter_empty", name));
    }
    return h(
      "li",
      { class: "empty" },
      q ? t("nothing_with", t("quote", q)) : t("vault_empty"),
      q ? null : h("button", { class: "btn-link empty-import", type: "button", onclick: openImport }, t("imp_open")),
    );
  };

  let seq = 0;
  /** Whether the list was drawn once: until then, a change on the page waits for that first paint. */
  let painted = false;
  /** Draws `listed` through the chosen tab, without asking klavd again. */
  const paint = async (mine: number): Promise<void> => {
    const filter = context.filter;
    if (filter === "codes" && !codeIds) {
      await loadCodes();
      if (mine !== seq) return;
    }
    painted = true;
    drawTabs();
    for (const stop of stops.values()) stop();
    stops.clear();
    visible.disconnect();
    here.hidden = filter !== "all";
    drawPageCodes();
    heading.textContent = filter === "all" ? t("your_vault") : t(filterLabel(filter));
    const ids = codeIds;
    const inTab = filter === "codes" ? listed.filter((i) => ids?.has(i.id) === true) : ofKind(listed, filter);
    // In «Codes», what the page's section shows is not repeated below.
    const shown = filter === "codes" ? inTab.filter((i) => !pageCodeIds.has(i.id)) : inTab;
    // Every code is up there: no list, and no «No codes yet» under them.
    all.hidden = shown.length === 0 && inTab.length > 0;
    results.classList.toggle("list-codes", filter === "codes");
    if (shown.length === 0) {
      results.replaceChildren(emptyRow(search.value.trim()));
      return;
    }
    // What fits on screen first; the rest once the browser is idle.
    const row = filter === "codes" ? codeListRow : listRow;
    const capped = shown.slice(0, MAX_ROWS);
    results.replaceChildren(...capped.slice(0, FIRST_ROWS).map(row));
    if (capped.length > FIRST_ROWS) {
      whenIdle(() => {
        if (mine === seq && results.isConnected) results.append(...capped.slice(FIRST_ROWS).map(row));
      });
    }
  };

  const choose = (next: VaultFilter): void => {
    if (next === context.filter) return;
    context.filter = next;
    void paint(++seq);
  };
  // ← → between the tabs, as in any tab list; choosing one shows it.
  kinds.addEventListener("keydown", (event) => {
    const order = [...kinds.querySelectorAll<HTMLButtonElement>(".kind-tab")];
    const at = order.findIndex((b) => b === document.activeElement);
    if (at < 0) return;
    const step: Record<string, number> = { ArrowRight: at + 1, ArrowLeft: at - 1, Home: 0, End: order.length - 1 };
    const next = step[event.key];
    if (next === undefined) return;
    event.preventDefault();
    order[(next + order.length) % order.length]?.click();
  });

  const refresh = async (): Promise<void> => {
    const mine = ++seq;
    const q = search.value.trim();
    try {
      const items = await daemon<ItemSummary[]>({ op: "list", filter: { trash: false, ...(q ? { query: q } : {}) } });
      if (mine !== seq) return;
      listed = items;
      await paint(mine);
      // For perf.spec.ts: when the vault first shows.
      if (performance.getEntriesByName("klav:rows").length === 0) performance.mark("klav:rows");
    } catch (e) {
      const error = errorOf(e);
      if (error.code === "locked") {
        void start();
        return;
      }
      all.hidden = false;
      results.replaceChildren(h("li", {}, notice(errorText(error.code, error.message))));
    }
  };

  /** The logins of the page in the active tab, above the vault. */
  const showHere = async (): Promise<void> => {
    const url = await activeTabUrl().catch(() => undefined);
    if (!url) return;
    let s: Suggestions;
    try {
      s = await daemon<Suggestions>({ op: "suggest", url });
    } catch {
      return; // Suggestions are optional here.
    }
    if (!here.isConnected) return;
    for (const stop of hereStops) stop();
    hereStops = [];
    siteCode = undefined;
    const had = context.here?.ids;
    const hadCodes = pageCodeIds;
    context.here = undefined;
    here.replaceChildren();
    // «Codes»: the logins' codes first, then the codes on their own (an older klavd sends none).
    const codes = [...s.logins.filter((l) => l.totp), ...(s.codes ?? [])];
    pageCodes = s.host && codes.length > 0 ? { host: s.host, page: url, items: codes } : undefined;
    pageCodeIds = new Set(pageCodes?.items.map((c) => c.id));
    if (s.host && s.logins.length > 0) {
      context.here = { host: s.host, ids: new Set(s.logins.map((l: Suggestion) => l.id)) };
      const rows = s.logins.map((l) => hereRow(l, s.host ?? "", url, open));
      for (const r of rows) if (r.stop) hereStops.push(r.stop);
      siteCode = rows.find((r) => r.codeId)?.codeId;
      here.append(h("h2", { class: "label" }, t("on_host", s.host)), h("ul", { class: "list" }, ...rows.map((r) => r.el)));
    }
    // Saved for a subdomain of this page (ADR 0025): apart, and after.
    if (s.host && s.parent && s.parent.length > 0) {
      const host = s.host;
      here.append(h("h2", { class: "label" }, t("group_parent")), h("ul", { class: "list" }, ...s.parent.map((l) => parentRow(l, host, url, open))));
    }
    // A login of this page shows its code up here, not again in the list;
    // in «Codes», neither do the codes of the page's section.
    const now = context.here?.ids;
    const changed = (a?: Set<string>, b?: Set<string>): boolean => (a?.size ?? 0) !== (b?.size ?? 0) || [...(a ?? [])].some((id) => !b?.has(id));
    if (painted && (changed(had, now) || changed(hadCodes, pageCodeIds))) await refresh();
    else drawPageCodes();
  };

  /**
   * klavd answers from its local copy and syncs behind it (ADR 0026):
   * ask again only when `revision` moves. Quickly while a sync is in
   * flight, every few seconds after.
   */
  let revision = status.revision;
  const watchRevision = (delay: number): void => {
    watching = setTimeout(() => {
      void daemon<DaemonStatus>({ op: "status" }).then(
        async (now) => {
          const onScreen = (): boolean => results.isConnected;
          if (!onScreen()) return;
          if (!now.unlocked) {
            void start();
            return;
          }
          if (now.revision !== revision) {
            revision = now.revision;
            // Which items have a code may have changed too.
            codesAsked = undefined;
            if (context.filter === "codes") codeIds = undefined;
            await Promise.all([refresh(), showHere()]);
            if (context.filter !== "codes") void loadCodes().then(drawTabs);
          }
          if (onScreen()) watchRevision(now.syncing === true ? REVISION_FAST_MS : REVISION_SLOW_MS);
        },
        () => {
          if (results.isConnected) watchRevision(REVISION_SLOW_MS);
        },
      );
    }, delay);
  };

  let quietFrom = 0;
  search.addEventListener("input", () => {
    quietFrom = Date.now() + QUIET_AFTER_KEY_MS;
    void refresh();
  });
  // The vault first, the page's logins at the same time; agents' requests
  // (which go to the server) once the vault shows and nobody is typing.
  const vault = refresh().then(() => {
    // The «Codes» tab and its count: right after the first paint.
    void loadCodes().then(() => {
      if (results.isConnected) drawTabs();
    });
    quietFrom = Math.max(quietFrom, Date.now() + QUIET_AFTER_PAINT_MS);
    watchApprovals(approvals, status, () => Date.now() >= quietFrom);
    watchRevision(REVISION_FAST_MS);
  });
  await Promise.all([vault, showHere()]);
}

// ----------------------------------------------------------------- item --

function hostOf(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return url;
  }
}

/** A secret hidden as dither noise; «Mostrar» dissolves it into the text. */
function maskedValue(): { el: HTMLElement; show: (text: string) => Promise<void>; hide: () => void } {
  const text = h("span", { class: "secret-text" });
  const noise = ditherCanvas(document, mask(), { palette: "mask", pixel: 2 });
  const el = h("span", { class: "value secret is-hidden" }, text, h("span", { class: "secret-mask" }, noise.canvas));
  requestAnimationFrame(() => {
    noise.repaint();
  });
  let run = 0;
  return {
    el,
    async show(value: string) {
      const mine = ++run;
      text.textContent = value;
      el.classList.remove("is-hidden");
      // The text appears pixel by pixel, by the same thresholds.
      noise.repaint(undefined, 0);
      await animate(200, (t) => {
        if (mine === run) noise.repaint(undefined, t);
      });
    },
    hide() {
      run++;
      text.textContent = "";
      el.classList.add("is-hidden");
      noise.repaint(undefined, 0);
    },
  };
}

/** One item, its fields masked until the person asks. */
async function showItem(id: string, context: VaultContext): Promise<void> {
  let view: ItemView;
  try {
    view = await gated<ItemView>({ op: "view", query: id, reveal: false });
  } catch (e) {
    const error = errorOf(e);
    if (error.code === "locked") {
      void start();
      return;
    }
    toast(errorText(error.code, error.message));
    return;
  }
  screen("screen-item");
  let revealed: ItemView | undefined;
  const back = (): void => {
    void showVault(context.status, context.query, context.filter);
  };
  const onKey = (event: KeyboardEvent): void => {
    if (event.key === "Escape") {
      event.preventDefault();
      back();
    }
  };
  document.addEventListener("keydown", onKey);
  const stops: (() => void)[] = [];
  leave = () => {
    document.removeEventListener("keydown", onKey);
    for (const stop of stops) stop();
    revealed = undefined;
  };

  /** The values of secret fields, fetched once and only when asked. */
  const secret = async (name: string): Promise<string | undefined> => {
    revealed ??= await gated<ItemView>({ op: "view", query: id, reveal: true });
    return name === "\u0000notes" ? revealed.notes : revealed.fields.find((f) => f.name === name)?.value;
  };

  const rows = h("dl", { class: "fields cross" });
  const fieldRow = (label: string, value: Node, ...actions: HTMLElement[]): void => {
    rows.append(
      h(
        "div",
        { class: "field-row" },
        h("div", { class: "field-main" }, h("dt", { class: "field-label" }, label), h("dd", { class: "field-value" }, value)),
        h("div", { class: "field-actions" }, ...actions),
      ),
    );
  };
  const copyButton = (label: string, get: () => Promise<string | undefined>): HTMLButtonElement =>
    iconButton("copy", t("copy_field", label), () => {
      void get().then(
        (v) => (v === undefined ? undefined : copy(v)),
        (e: unknown) => {
          const error = errorOf(e);
          toast(errorText(error.code, error.message));
        },
      );
    });

  const shown = (f: FieldView): boolean => f.filled && f.kind !== "file";
  for (const f of view.fields.filter(shown)) {
    const label = fieldName(f);
    if (f.kind === "totp") {
      const code = liveCode(id, view.title, "l");
      stops.push(code.stop);
      fieldRow(label, code.el, copyButton(label, async () => (await gated<{ code: string }>({ op: "totp", query: id, field: f.name })).code));
      continue;
    }
    if (!f.secret) {
      fieldRow(label, h("span", { class: "value" }, f.value ?? ""), copyButton(label, () => Promise.resolve(f.value)));
      continue;
    }
    const value = maskedValue();
    const toggle = h("button", { class: "btn btn-s", type: "button", "aria-label": t("show_field", label) }, t("show"));
    toggle.addEventListener("click", () => {
      if (value.el.classList.contains("is-hidden")) {
        void secret(f.name).then(
          (v) => {
            toggle.textContent = t("hide");
            toggle.setAttribute("aria-label", t("hide_field", label));
            void value.show(v ?? "");
          },
          (e: unknown) => {
            const error = errorOf(e);
            toast(errorText(error.code, error.message));
          },
        );
      } else {
        value.hide();
        toggle.textContent = t("show");
        toggle.setAttribute("aria-label", t("show_field", label));
      }
    });
    fieldRow(label, value.el, toggle, copyButton(label, () => secret(f.name)));
  }
  // The sites Klav fills; those an agent added and the person has not confirmed go apart.
  const sites = view.pending_urls?.length ? (view.confirmed_urls ?? []) : view.urls;
  if (sites.length > 0) {
    fieldRow(plural("sites", sites.length), h("span", { class: "value" }, sites.map(hostOf).join(", ")));
  }
  const added = agentSites(view, {
    changed: () => {
      void showItem(id, context);
    },
    failed: (e) => {
      const error = errorOf(e);
      toast(errorText(error.code, error.message));
    },
  });
  if (view.has_notes) {
    const note = maskedValue();
    const toggle = h("button", { class: "btn btn-s", type: "button", "aria-label": t("show_note") }, t("show"));
    toggle.addEventListener("click", () => {
      void secret("\u0000notes").then((v) => {
        void note.show(v ?? "");
        toggle.remove();
      });
    });
    fieldRow(t("note"), note.el, toggle);
  }
  const previous = h("section", { class: "group previous", hidden: true });
  const pending = h("section", { class: "pending-wrap", hidden: true });
  void previousPasswords(id, previous, pending, () => void showItem(id, context));
  fieldRow(
    t("for_agents"),
    h("span", { class: "value reference" }, view.reference),
    copyButton(t("agent_reference"), () => Promise.resolve(view.reference)),
  );

  const backButton = h("button", { class: "back", type: "button" }, icon("back"), t("your_vault"));
  backButton.addEventListener("click", back);
  const fill =
    context.here?.ids.has(id) === true
      ? h("button", { class: "btn btn-primary btn-block", type: "button" }, t("fill_on_host", context.here.host))
      : null;
  fill?.addEventListener("click", () => void fillFromPopup(id, fill));

  app.append(
    h("header", { class: "bar" }, backButton, glyph("brand-glyph")),
    h(
      "div",
      { class: "content" },
      h(
        "section",
        { class: "item-head" },
        h("h1", { class: "title-l", tabindex: "-1" }, view.title),
        h("p", { class: "sub" }, t("kind_where", kindName(view.kind), view.vault, view.project)),
      ),
      pending,
      rows,
      added,
      previous,
      fill ? h("div", { class: "item-foot" }, fill) : null,
    ),
  );
  // The new screen takes the focus (Esc goes back), without a focus ring on load.
  app.querySelector<HTMLElement>(".title-l")?.focus({ preventScroll: true });
}

function day(ms: number): string {
  return new Intl.DateTimeFormat(locale(), { dateStyle: "medium" }).format(new Date(ms));
}

/**
 * «Contraseñas anteriores» (ADR 0022 §3): the values an item's password
 * and hidden fields had, newest first, masked until the person asks. The
 * list comes without values; each one is fetched on «Mostrar» or «Copiar».
 */
async function previousPasswords(id: string, section: HTMLElement, pendingSlot: HTMLElement, reload: () => void): Promise<void> {
  let history: PasswordHistoryView;
  try {
    history = await daemon<PasswordHistoryView>({ op: "password_history", query: id });
  } catch {
    return;
  }
  if (history.pending) {
    pendingSlot.append(pendingCard(id, history.pending_since, reload));
    pendingSlot.hidden = false;
  }
  if (history.entries.length === 0) return;
  const rows = h("dl", { class: "fields" });
  for (const p of history.entries) {
    const label = fieldName({ name: p.field, label: p.label });
    const range = p.from_ms === undefined ? t("previous_until", label, day(p.to_ms)) : t("previous_range", label, day(p.from_ms), day(p.to_ms));
    const when = p.unconfirmed ? t("previous_unconfirmed", range) : range;
    const value = maskedValue();
    let cached: string | undefined;
    const get = async (): Promise<string> => (cached ??= await gated<string>({ op: "previous_password", query: id, index: p.index }));
    const toggle = h("button", { class: "btn btn-s", type: "button", "aria-label": t("previous_show", label, day(p.to_ms)) }, t("show"));
    toggle.addEventListener("click", () => {
      if (value.el.classList.contains("is-hidden")) {
        void get().then(
          (v) => {
            toggle.textContent = t("hide");
            void value.show(v);
          },
          (e: unknown) => {
            const error = errorOf(e);
            toast(errorText(error.code, error.message));
          },
        );
      } else {
        value.hide();
        toggle.textContent = t("show");
      }
    });
    const copyIt = iconButton("copy", t("previous_copy", label, day(p.to_ms)), () => {
      void get().then(copy, (e: unknown) => {
        const error = errorOf(e);
        toast(errorText(error.code, error.message));
      });
    });
    rows.append(
      h(
        "div",
        { class: "field-row" },
        h("div", { class: "field-main" }, h("dt", { class: "field-label" }, when), h("dd", { class: "field-value" }, value.el)),
        h("div", { class: "field-actions" }, toggle, copyIt),
      ),
    );
  }
  section.append(h("h2", { class: "label" }, t("previous_passwords")), rows);
  section.hidden = false;
}

/**
 * «Cambio pendiente» (ADR 0022 §5): an agent changed this login's password
 * on its site and nobody said whether the site took the new one. The
 * person decides here: «Usar la nueva» makes it current (the old one goes
 * to the previous passwords), «Mantener la actual» keeps the current one
 * and files the new one as generated, not confirmed. Blue, like
 * everything agents do.
 */
function pendingCard(id: string, since: number | undefined, reload: () => void): HTMLElement {
  const slot = h("p", { class: "notice", role: "alert", hidden: true });
  const useNew = h("button", { class: "btn btn-primary btn-s", type: "button" }, t("pending_use_new"));
  const keep = h("button", { class: "btn btn-s", type: "button" }, t("pending_keep"));
  const decide = (accept: boolean): void => {
    useNew.disabled = keep.disabled = true;
    daemon<PasswordHistoryView>({ op: "resolve_pending", query: id, accept }).then(
      () => {
        toast(accept ? t("pending_used_new") : t("pending_kept"));
        reload();
      },
      (e: unknown) => {
        const error = errorOf(e);
        slot.textContent = errorText(error.code, error.message);
        slot.hidden = false;
        useNew.disabled = keep.disabled = false;
      },
    );
  };
  useNew.addEventListener("click", () => {
    decide(true);
  });
  keep.addEventListener("click", () => {
    decide(false);
  });
  const stripe = ditherCanvas(document, band(), { palette: "blue", pixel: 2 });
  requestAnimationFrame(() => {
    stripe.repaint();
  });
  return h(
    "div",
    { class: "approval pending-change", role: "group", "aria-label": t("pending_title") },
    h("div", { class: "approval-band" }, stripe.canvas),
    h(
      "div",
      { class: "approval-body" },
      h("p", { class: "agent-mark" }, t("pending_title")),
      h("p", { class: "approval-reason" }, since === undefined ? t("pending_body") : t("pending_body_since", day(since))),
      h("div", { class: "approval-actions" }, useNew, keep),
      slot,
    ),
  );
}

/**
 * The generator in the popup: the same as in the field menu, for the
 * active tab's site, without «Usar» (there is no field here). Copying
 * keeps the password in the generator history first.
 */
async function showGenerator(status: DaemonStatus): Promise<void> {
  screen("screen-generator");
  const url = await activeTabUrl();
  const host = url ? (await klavCore()).fillableHost(url) : undefined;
  const back = (): void => {
    void showVault(status);
  };
  const onKey = (event: KeyboardEvent): void => {
    if (event.key === "Escape" && !event.defaultPrevented) {
      event.preventDefault();
      back();
    }
  };
  document.addEventListener("keydown", onKey);
  leave = () => {
    document.removeEventListener("keydown", onKey);
  };
  const backButton = h("button", { class: "back", type: "button" }, icon("back"), t("your_vault"));
  backButton.addEventListener("click", back);
  const title = h("h1", { class: "title", tabindex: "-1" }, t("gen_title"));
  const slot = h("div", { class: "gen-slot" });
  const body = h("div", { class: "gen-wrap" });
  const tell = (text: string, tone: "error" | "info" = "error"): void => {
    if (tone === "error") slot.replaceChildren(notice(text));
    else toast(text);
  };
  const showPanel = async (): Promise<void> => {
    slot.replaceChildren();
    title.textContent = t("gen_title");
    body.replaceChildren(
      await generatorPanel({
        host: host ?? undefined,
        say: tell,
        resized: () => undefined,
        copy,
        history: () => void showHistory(),
      }),
    );
  };
  const showHistory = async (): Promise<void> => {
    slot.replaceChildren();
    title.textContent = t("gen_history");
    body.replaceChildren(await historyPanel({ say: tell, resized: () => undefined, copy, back: () => void showPanel(), guard: (event) => event.isTrusted }));
  };
  app.append(h("header", { class: "bar" }, backButton, glyph("brand-glyph")), h("div", { class: "content" }, title, slot, body));
  await showPanel();
  title.focus({ preventScroll: true });
}

/**
 * «Nuevo elemento» (newitem.ts): a login, a note, a card or a code typed
 * by hand, saved with klavd's `create`. Its code runs only once opened.
 */
async function showNewItem(status: DaemonStatus): Promise<void> {
  const { mountNewItem } = await import("./newitem");
  screen("screen-new");
  const back = (): void => {
    void showVault(status);
  };
  const onKey = (event: KeyboardEvent): void => {
    if (event.key === "Escape" && !event.defaultPrevented) {
      event.preventDefault();
      back();
    }
  };
  document.addEventListener("keydown", onKey);
  const backButton = h("button", { class: "back", type: "button" }, icon("back"), t("your_vault"));
  backButton.addEventListener("click", back);
  const title = h("h1", { class: "title", tabindex: "-1" }, t("new_title"));
  const content = h("div", { class: "content" }, title);
  app.append(h("header", { class: "bar" }, backButton, glyph("brand-glyph")), content);
  const stop = mountNewItem(content, {
    daemon,
    here: () => activeTabUrl().catch(() => undefined),
    fillableHost: async (url) => (await klavCore()).fillableHost(url),
    checkTotp: async (value) => JSON.parse((await klavCore()).totpCheck(value)) as TotpInfo,
    generator: (host, use) =>
      generatorPanel({ host, say: (text) => { toast(text); }, resized: () => undefined, copy, use, history: () => void showGenerator(status) }),
    created: (item) => {
      toast(t("saved", item.title));
      void showItem(item.id, { status, query: "", filter: "all" });
    },
  });
  leave = () => {
    document.removeEventListener("keydown", onKey);
    stop();
  };
}

/** «Salud» (ADR 0022 §4, §6): the report and «Arreglar mis contraseñas repetidas» (health.ts). */
function showHealth(status: DaemonStatus): void {
  screen("screen-health");
  const back = (): void => {
    void showVault(status);
  };
  const onKey = (event: KeyboardEvent): void => {
    if (event.key === "Escape" && !event.defaultPrevented) {
      event.preventDefault();
      back();
    }
  };
  document.addEventListener("keydown", onKey);
  const backButton = h("button", { class: "back", type: "button" }, icon("back"), t("your_vault"));
  backButton.addEventListener("click", back);
  const title = h("h1", { class: "title", tabindex: "-1" }, t("health_title"));
  const content = h("div", { class: "content" }, title);
  app.append(h("header", { class: "bar" }, backButton, glyph("brand-glyph")), content);
  const stop = mountHealth(content, status, {
    say: (text) => {
      toast(text);
    },
    tile: (name, host) => siteTile(name, host),
    open: (id) => void showItem(id, { status, query: "", filter: "all" }),
  });
  leave = () => {
    document.removeEventListener("keydown", onKey);
    stop();
  };
  title.focus({ preventScroll: true });
}

/**
 * Settings: one so far. In a sign-in in several steps Klav presses
 * «Continuar» and «Iniciar sesión» by itself; «Solo rellenar, no pulsar»
 * leaves the pressing to the person. Kept in `storage.local`, read by the
 * background.
 */
/** From strict to loose (ADR 0020 §8): moving right asks for Touch ID or the password. */
const UV_WINDOWS: readonly PasskeyUv[] = ["always", "5m", "unlocked"];
const UV_TEXT: Record<PasskeyUv, [MessageKey, MessageKey]> = {
  always: ["passkey_uv_always", "passkey_uv_always_text"],
  "5m": ["passkey_uv_5m", "passkey_uv_5m_text"],
  unlocked: ["passkey_uv_unlocked", "passkey_uv_unlocked_text"],
};

/**
 * «Passkeys»: when signing in with a passkey asks for Touch ID or the
 * master password again (klavd's setting, of this device only). Loosening
 * it asks klavd for Touch ID, or here for the master password.
 */
function passkeySettings(status: DaemonStatus): HTMLElement {
  let current: PasskeyUv = status.passkey_uv ?? "always";
  const saved = h("p", { class: "sub settings-saved", role: "status" });
  const actions = h("div", { class: "uv-confirm" });
  const radios = new Map<PasskeyUv, HTMLInputElement>();
  const show = (window: PasskeyUv): void => {
    current = window;
    for (const [w, r] of radios) r.checked = w === window;
  };
  // The master password for `window`, here (Klav's own page), with «Cancel».
  const askPassword = (window: PasskeyUv, why: string): void => {
    saved.textContent = why;
    const cancel = h("button", { class: "btn", type: "button" }, t("passkey_uv_cancel"));
    cancel.addEventListener("click", () => {
      actions.replaceChildren();
      saved.textContent = "";
    });
    presence(actions, false, (pw) => { set(window, pw); }, [cancel]);
  };
  const set = (window: PasskeyUv, password?: string): void => {
    void daemon<{ window: PasskeyUv }>({ op: "passkey_uv", window, ...(password !== undefined ? { password } : {}) }).then(
      (r) => {
        show(r.window);
        actions.replaceChildren();
        saved.textContent = t("passkey_uv_saved");
      },
      (e: unknown) => {
        const error = errorOf(e);
        show(current);
        if (error.code === "biometry_unavailable" || error.code === "biometry_failed" || error.code === "wrong_credentials") {
          askPassword(window, error.code === "wrong_credentials" ? t("error_wrong_credentials") : t("passkey_uv_confirm"));
        } else {
          saved.textContent = t("settings_save_failed");
        }
      },
    );
  };
  const options = UV_WINDOWS.map((w) => {
    const id = `passkey-uv-${w}`;
    const radio = h("input", { type: "radio", class: "check", name: "passkey-uv", id, value: w });
    radios.set(w, radio);
    radio.addEventListener("change", () => {
      if (!radio.checked || w === current) return;
      saved.textContent = "";
      const looser = UV_WINDOWS.indexOf(w) > UV_WINDOWS.indexOf(current);
      const touchId = status.touch_id.available && status.touch_id.enrolled && !status.touch_id.password_required;
      // Without Touch ID, loosening goes straight to the password.
      if (looser && !touchId) {
        show(current);
        askPassword(w, t("passkey_uv_confirm"));
        return;
      }
      set(w);
    });
    const [title, text] = UV_TEXT[w];
    return h(
      "label",
      { class: "setting", for: id },
      radio,
      h("span", { class: "setting-text" }, h("span", { class: "setting-title" }, t(title)), h("span", { class: "sub" }, t(text))),
    );
  });
  show(current);
  // The daemon's own value, in case the status was older.
  void daemon<{ window: PasskeyUv }>({ op: "passkey_uv" }).then((r) => { show(r.window); }, () => undefined);
  return h(
    "section",
    { class: "group" },
    h("h2", { class: "label", id: "passkey-uv-label" }, t("passkeys_heading")),
    h("p", { class: "sub" }, t("passkey_uv_intro")),
    h("div", { role: "radiogroup", "aria-labelledby": "passkey-uv-label" }, ...options),
    saved,
    actions,
  );
}

/** The import wizard, in a tab of its own (ADR 0024). */
function openImport(): void {
  void ext.tabs.create({ url: ext.runtime.getURL("import.html") }).then(() => {
    window.close();
  });
}

async function showSettings(status: DaemonStatus): Promise<void> {
  screen("screen-settings");
  const stored: Record<string, unknown> = await ext.storage.local.get(["onlyFill", "askSites"]).catch(() => ({}));
  const box = h("input", { type: "checkbox", class: "check", id: "only-fill" });
  box.checked = stored.onlyFill === true;
  const saved = h("p", { class: "sub settings-saved", role: "status" });
  box.addEventListener("change", () => {
    void ext.storage.local.set({ onlyFill: box.checked }).then(
      () => {
        saved.textContent = box.checked ? t("settings_only_fill_on") : t("settings_only_fill_off");
      },
      () => {
        saved.textContent = t("settings_save_failed");
      },
    );
  });
  const askBox = h("input", { type: "checkbox", class: "check", id: "ask-sites" });
  askBox.checked = stored.askSites === true;
  const askSaved = h("p", { class: "sub settings-saved", role: "status" });
  askBox.addEventListener("change", () => {
    void ext.storage.local.set({ askSites: askBox.checked }).then(
      () => {
        settingChanged();
        askSaved.textContent = askBox.checked ? t("ask_sites_on") : t("ask_sites_off");
      },
      () => {
        askSaved.textContent = t("settings_save_failed");
      },
    );
  });
  const backButton = h("button", { class: "back", type: "button" }, icon("back"), t("your_vault"));
  backButton.addEventListener("click", () => void showVault(status));
  const onKey = (event: KeyboardEvent): void => {
    if (event.key === "Escape" && !event.defaultPrevented) {
      event.preventDefault();
      void showVault(status);
    }
  };
  document.addEventListener("keydown", onKey);
  leave = () => {
    document.removeEventListener("keydown", onKey);
  };
  app.append(
    h("header", { class: "bar" }, backButton, glyph("brand-glyph")),
    h(
      "div",
      { class: "content" },
      h("h1", { class: "title", tabindex: "-1" }, t("settings")),
      h(
        "section",
        { class: "group" },
        h("h2", { class: "label" }, t("settings_steps")),
        h(
          "label",
          { class: "setting", for: "only-fill" },
          box,
          h(
            "span",
            { class: "setting-text" },
            h("span", { class: "setting-title" }, t("only_fill")),
            h("span", { class: "sub" }, t("only_fill_text")),
          ),
        ),
        saved,
      ),
      h(
        "section",
        { class: "group" },
        h("h2", { class: "label" }, t("site_icons")),
        h(
          "label",
          { class: "setting", for: "ask-sites" },
          askBox,
          h("span", { class: "setting-text" }, h("span", { class: "setting-title" }, t("ask_sites")), h("span", { class: "sub" }, t("ask_sites_text"))),
        ),
        askSaved,
      ),
      passkeySettings(status),
      h(
        "section",
        { class: "group" },
        h("h2", { class: "label" }, t("imp_heading")),
        h(
          "button",
          { class: "setting setting-button", type: "button", onclick: openImport },
          h("span", { class: "setting-text" }, h("span", { class: "setting-title" }, t("imp_open")), h("span", { class: "sub" }, t("imp_open_text"))),
        ),
      ),
      h(
        "section",
        { class: "group" },
        h("h2", { class: "label" }, t("shortcuts")),
        h("p", { class: "shortcut" }, h("span", { class: "kbd" }, PAGE_KEY), h("span", {}, t("shortcut_page"))),
        h("p", { class: "shortcut" }, h("span", { class: "kbd" }, COPY_KEY), h("span", {}, t("shortcut_copy"))),
      ),
    ),
  );
  app.querySelector<HTMLElement>(".title")?.focus({ preventScroll: true });
}

void start();
