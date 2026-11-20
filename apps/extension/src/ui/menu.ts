/**
 * The field menu: an extension page the content script frames under a
 * field. It shows what matches the frame's site (only names, never values)
 * and asks the background to fill the one the person clicks. «Buscar otro
 * elemento» opens the central palette for the same field.
 *
 * When the page waits for a passkey in this frame (conditional mediation,
 * ADR 0020 P9), the site's passkeys in Klav go first, with «Use another
 * device» for the browser's own: picking one opens Klav's frame to
 * confirm presence.
 */
import { type MessageKey, localizePage, t, tNodes } from "../shared/i18n";
import { ask } from "../shared/messages";
import type { Group, MenuState } from "../shared/messages";
import type { PasskeyCandidate } from "../shared/passkey";
import type { Suggestion } from "../shared/protocol";
import { writeWith } from "../background/clipboard";
import { h } from "./dom";
import { generatorPanel, historyPanel } from "./generator";
import { framePage } from "./frame";
import { COVERED, personClicked } from "./guard";
import { alertText, frameHead, keyboard, lockedForm, say, shortcutKey } from "./inpage";
import { icon } from "./kit";
import { siteTile } from "./siteicon";
import { stopText } from "./strings";

localizePage();
const root = document.getElementById("menu") as HTMLElement;
const page = framePage("menu", root);
const menuId = page.id;

const TITLES: Record<Group, MessageKey> = { login: "group_logins", card: "group_cards", identity: "group_addresses" };

function render(...children: (Node | null)[]): void {
  root.replaceChildren(...children.filter((c): c is Node => c !== null));
  page.resize();
}

function choices(): HTMLButtonElement[] {
  return [...root.querySelectorAll<HTMLButtonElement>(".choice")];
}

function disableAll(disabled: boolean): void {
  for (const b of choices()) b.disabled = disabled;
}

function covered(slot: HTMLElement): () => void {
  return () => {
    say(slot, COVERED);
    page.resize();
  };
}

/**
 * One row: the item's initial, its title and who/what it is, and ↵ on the
 * focused row. `parent`: a login saved for a subdomain of the page (ADR
 * 0025), with the host it was saved for in view.
 */
function choice(s: Suggestion, slot: HTMLElement, state: MenuState, part?: "totp" | "pending" | "parent"): HTMLButtonElement {
  const sub =
    part === "totp"
      ? [t("code"), s.username || s.location].filter(Boolean).join(" · ")
      : part === "pending"
        ? [t("pending_choice"), s.username].filter(Boolean).join(" · ")
        : part === "parent"
          ? [s.username, t("saved_for", s.site ?? "")].filter(Boolean).join(" · ")
          : (s.username ?? s.hint ?? s.location);
  const fillPart = part === "parent" ? undefined : part;
  const button = h(
    "button",
    { class: "choice", type: "button", "data-id": s.id },
    s.kind === "login" ? siteTile(s.title, state.host, state.page) : siteTile(s.title),
    h("span", { class: "row-main" }, h("span", { class: "row-title" }, s.title), h("span", { class: "row-sub" }, sub)),
    h("span", { class: "kbd choice-enter", "aria-hidden": "true" }, "↵"),
  );
  button.addEventListener("click", (event) => {
    if (!personClicked(event, covered(slot))) return;
    disableAll(true);
    ask<{ filled: number }>({ type: "menu_fill", menuId, item: s.id, ...(fillPart ? { part: fillPart } : {}), ...(part === "parent" ? { parent: true } : {}) }).then(
      ({ filled }) => {
        if (filled > 0) return;
        say(slot, t("nowhere_form"));
        disableAll(false);
        page.resize();
      },
      (e: unknown) => {
        say(slot, alertText(e));
        disableAll(false);
        page.resize();
      },
    );
  });
  return button;
}

/** A passkey the page waits for (conditional mediation): Klav's frame confirms presence. */
function passkeyChoice(c: PasskeyCandidate, slot: HTMLElement, state: MenuState): HTMLButtonElement {
  const button = h(
    "button",
    { class: "choice", type: "button", "data-id": c.item },
    siteTile(c.title, state.host, state.page),
    h(
      "span",
      { class: "row-main" },
      h("span", { class: "row-title" }, c.title),
      h("span", { class: "row-sub" }, [t("passkey"), c.user_name].filter(Boolean).join(" · ")),
    ),
    h("span", { class: "kbd choice-enter", "aria-hidden": "true" }, "↵"),
  );
  button.addEventListener("click", (event) => {
    if (!personClicked(event, covered(slot))) return;
    disableAll(true);
    ask({ type: "menu_passkey", menuId, item: c.item }).catch((e: unknown) => {
      say(slot, alertText(e));
      disableAll(false);
      page.resize();
    });
  });
  return button;
}

/** «Use another device» while the page waits for a passkey: the browser's own. */
function otherDeviceRow(slot: HTMLElement): HTMLButtonElement {
  const button = h(
    "button",
    { class: "choice choice-quiet", type: "button" },
    h("span", { class: "tile tile-dashed", "aria-hidden": "true" }, icon("key")),
    h(
      "span",
      { class: "row-main" },
      h("span", { class: "row-title" }, t("passkey_other_device")),
      h("span", { class: "row-sub" }, t("passkey_other_device_sub")),
    ),
  );
  button.addEventListener("click", (event) => {
    if (!personClicked(event, covered(slot))) return;
    ask({ type: "menu_passkey_browser", menuId }).catch((e: unknown) => {
      say(slot, alertText(e));
      page.resize();
    });
  });
  return button;
}

/** «Buscar otro elemento»: the palette, for when the right item is not listed. */
function findRow(slot: HTMLElement): HTMLButtonElement {
  const button = h(
    "button",
    { class: "choice choice-quiet", type: "button" },
    h("span", { class: "tile tile-dashed", "aria-hidden": "true" }, icon("search")),
    h(
      "span",
      { class: "row-main" },
      h("span", { class: "row-title" }, t("find_other")),
      h("span", { class: "row-sub" }, t("find_other_sub")),
    ),
    h("span", { class: "kbd choice-enter", "aria-hidden": "true" }, "↵"),
  );
  button.addEventListener("click", (event) => {
    if (!personClicked(event, covered(slot))) return;
    void ask({ type: "menu_find", menuId }).catch((e: unknown) => {
      say(slot, alertText(e));
      page.resize();
    });
  });
  return button;
}

/**
 * The generator, for a sign-up or change form: klav-core (WASM) follows
 * the field's rules or the site's, and the password is kept in the
 * generator history before it is typed or copied (ADR 0022).
 */
function generator(slot: HTMLElement, state: MenuState): HTMLElement {
  const box = h("section", { class: "generated" });
  const historySlot = h("span", { class: "generated-end" });
  const head = h(
    "div",
    { class: "generated-head" },
    h("span", { class: "tile tile-dashed", "aria-hidden": "true" }, icon("plus")),
    h("span", { class: "row-main" }, h("span", { class: "row-title" }, t("new_password")), h("span", { class: "row-sub" }, t("new_password_hint"))),
    historySlot,
  );
  const tell = (text: string, tone: "error" | "info" = "error"): void => {
    say(slot, text, tone);
    page.resize();
  };
  const copy = async (value: string): Promise<void> => {
    if (!writeWith(document, value)) {
      tell(t("copy_failed"));
      return;
    }
    await ask({ type: "copied" }).catch(() => undefined);
    tell(t("copied"), "info");
  };
  const showPanel = async (): Promise<void> => {
    const panel = await generatorPanel({
      host: state.host,
      ...(state.rules ? { rules: state.rules } : {}),
      say: tell,
      resized: page.resize,
      copy,
      // Only the person's own click, on a frame nothing covers.
      guard: (event) => personClicked(event, covered(slot)),
      use: async (value) => {
        try {
          const { filled } = await ask<{ filled: number }>({ type: "menu_generated", menuId, value });
          if (filled === 0) tell(t("nowhere_form_password"));
        } catch (e) {
          tell(alertText(e));
        }
      },
      history: () => void showHistory(),
      historyIn: historySlot,
    });
    box.replaceChildren(head, panel);
    page.resize();
  };
  const showHistory = async (): Promise<void> => {
    const panel = await historyPanel({
      say: tell,
      resized: page.resize,
      copy,
      back: () => void showPanel(),
      // Only the person's own click, on a frame nothing covers.
      guard: (event) => personClicked(event, covered(slot)),
    });
    box.replaceChildren(panel);
    page.resize();
  };
  void showPanel();
  return box;
}

function showSuggestions(state: MenuState): void {
  const s = state.suggestions;
  const slot = h("div", { class: "notice-slot" });
  // A sign-in in steps stopped here: say why before anything else.
  if (state.stopped) say(slot, stopText(state.stopped), "info");
  const body: HTMLElement[] = [];
  const passkeys = state.passkeys ?? [];
  if (passkeys.length > 0) {
    body.push(h("h2", { class: "section-title" }, t("group_passkeys")), h("div", { class: "list" }, ...passkeys.map((c) => passkeyChoice(c, slot, state))));
  }
  const otp = state.role === "otp";
  // Codes first: the login just filled in this tab, then any login with a code.
  const withCode = otp ? [...(state.recent ? [state.recent] : []), ...(s?.logins ?? []).filter((l) => l.totp && l.id !== state.recent?.id)] : [];
  if (withCode.length > 0) {
    body.push(h("h2", { class: "section-title" }, t("one_time_code")), h("div", { class: "list" }, ...withCode.map((item) => choice(item, slot, state, "totp"))));
  } else {
    const lists: Record<Group, Suggestion[]> = { login: s?.logins ?? [], card: s?.cards ?? [], identity: s?.identities ?? [] };
    // Logins saved for a subdomain of this page (ADR 0025): their own group,
    // after the page's logins, and only for a sign-in field.
    const parent = state.role === "login" && state.groups.includes("login") ? (s?.parent ?? []) : [];
    for (const group of state.groups) {
      const items = lists[group];
      if (items.length === 0) {
        if (group === "login" && state.role !== "new-password" && parent.length === 0) {
          if (passkeys.length === 0) {
            body.push(h("p", { class: "empty" }, ...tNodes("no_login_for_site", h("strong", {}, state.host ?? t("this_page")))));
          }
        }
        continue;
      }
      if (state.groups.length > 1 || group !== "login" || passkeys.length > 0) body.push(h("h2", { class: "section-title" }, t(TITLES[group])));
      // A login with a pending change (ADR 0022 §5): its new password too,
      // so the person is not locked out if the site took it.
      const rows = items.flatMap((item) =>
        group === "login" && item.pending ? [choice(item, slot, state), choice(item, slot, state, "pending")] : [choice(item, slot, state)],
      );
      body.push(h("div", { class: "list" }, ...rows));
    }
    if (parent.length > 0) {
      body.push(h("h2", { class: "section-title" }, t("group_parent")), h("div", { class: "list" }, ...parent.map((item) => choice(item, slot, state, "parent"))));
    }
    if (body.length === 0 && state.role !== "new-password") {
      body.push(h("p", { class: "empty" }, state.groups.includes("card") ? t("no_cards") : t("no_addresses")));
    }
  }
  const foot = h("div", { class: "list list-foot" }, ...(passkeys.length > 0 ? [otherDeviceRow(slot)] : []), findRow(slot));
  const scroll = h("div", { class: "scroll" }, slot, ...body, foot);
  if (state.role === "new-password") scroll.insertBefore(generator(slot, state), slot.nextSibling);
  render(frameHead(state.host, shortcutKey()), scroll);
  // Opened from the keyboard, the frame has the focus: start on the first choice.
  if (document.hasFocus()) choices()[0]?.focus();
}

async function load(): Promise<void> {
  try {
    const state = await ask<MenuState>({ type: "menu_load", menuId });
    if (!state.status.logged_in) {
      render(
        frameHead(state.host),
        h("p", { class: "empty" }, ...tNodes("no_account_run", h("strong", {}, "klav login"))),
      );
    } else if (!state.status.unlocked) {
      render(frameHead(state.host, shortcutKey()), lockedForm(state.status, () => void load()));
    } else {
      showSuggestions(state);
    }
  } catch (e) {
    render(frameHead(undefined), h("p", { class: "notice", role: "alert" }, alertText(e)));
  }
}

keyboard(root, page.close);
void load();
