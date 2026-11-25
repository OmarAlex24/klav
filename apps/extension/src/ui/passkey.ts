/**
 * The passkey surface (ADR 0020): Klav's frame, top right, when a page
 * asks to sign in with a passkey or to create one and Klav can answer.
 *
 * - Sign in: the site's passkeys in Klav (title, account, vault); a click
 *   on one signs. Create: «Save a passkey for <account> in Klav», in a new
 *   login or one of the site's.
 * - Presence: klavd asks for Touch ID; without it (or when it fails) the
 *   master password goes here, in Klav's frame, never in the page. Within
 *   the verification window (ADR 0020 §8) neither: the click is enough.
 * - Always «Use another device» (the browser's own authenticator); closing
 *   the frame tells the page the person declined.
 * - Locked: unlock here first (P13).
 *
 * The page wrote the site's name and the account's name: they only go in
 * as text.
 */
import { localizePage, t, tNodes } from "../shared/i18n";
import { ask, type PasskeyState } from "../shared/messages";
import type { PasskeyCandidate } from "../shared/passkey";
import { presenceQuestion } from "../shared/presence";
import type { DaemonError, DaemonStatus, PresenceAsk } from "../shared/protocol";
import { h } from "./dom";
import { framePage } from "./frame";
import { armed, COVERED, personClicked } from "./guard";
import { alertText, errorOf, frameHead, keyboard, lockedForm, say } from "./inpage";
import { icon, iconButton } from "./kit";
import { presence } from "./presence";
import { siteTile } from "./siteicon";

localizePage("frame_passkey");
const root = document.getElementById("passkey") as HTMLElement;
const page = framePage("passkey", root);
const passkeyId = page.id;

function render(...children: (Node | null)[]): void {
  root.replaceChildren(...children.filter((c): c is Node => c !== null));
  page.resize();
}

function covered(slot: HTMLElement): () => void {
  return () => {
    say(slot, COVERED);
    page.resize();
  };
}

function touchIdUsable(status: DaemonStatus): boolean {
  return status.touch_id.available && status.touch_id.enrolled && !status.touch_id.password_required;
}

/**
 * Runs `act` with presence: Touch ID first when it is usable, else (or
 * when it is unavailable or fails) the master password in `actions`, with
 * `keep` next to «Confirm». A wrong password asks again.
 */
function withPresence(
  status: DaemonStatus,
  slot: HTMLElement,
  actions: HTMLElement,
  keep: HTMLElement[],
  act: (password?: string) => Promise<void>,
): void {
  const askPassword = (): void => {
    presence(actions, false, go, keep);
    const hint = actions.querySelector("input");
    hint?.setAttribute("aria-label", t("passkey_confirm_hint"));
    page.resize();
  };
  const go = (password?: string): void => {
    for (const b of root.querySelectorAll<HTMLButtonElement>("button")) b.disabled = true;
    act(password).catch((e: unknown) => {
      for (const b of root.querySelectorAll<HTMLButtonElement>("button")) b.disabled = false;
      const error = errorOf(e);
      say(slot, alertText(e));
      if (error.code === "biometry_unavailable" || error.code === "biometry_failed" || error.code === "wrong_credentials") {
        askPassword();
      }
      page.resize();
    });
  };
  // Within the verification window (ADR 0020 §8), or Touch ID: klavd
  // asks for nothing more, or prompts itself.
  if (status.passkey_verified === true || touchIdUsable(status)) go();
  else askPassword();
}

/** «Use another device»: the browser's own passkeys, a phone, a security key. */
function otherDevice(slot: HTMLElement): HTMLButtonElement {
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
    void ask({ type: "passkey_browser", passkeyId }).catch((e: unknown) => {
      say(slot, alertText(e));
      page.resize();
    });
  });
  return button;
}

function head(state: PasskeyState): HTMLElement {
  return frameHead(state.rp_id, iconButton("close", t("close"), page.close));
}

/**
 * Runs `go` once the frame counts as seen (the same rule as a click, T62),
 * for what starts without a click in this frame: a passkey picked in the
 * field menu. If the page keeps the frame covered, says so and leaves the
 * rows to a click.
 */
function whenArmed(slot: HTMLElement, go: () => void, deadline = performance.now() + 2000): void {
  const ready = armed();
  if (ready === "yes") {
    go();
  } else if (performance.now() >= deadline) {
    covered(slot)();
  } else {
    setTimeout(() => {
      whenArmed(slot, go, deadline);
    }, 100);
  }
}

function signIn(state: PasskeyState, candidates: PasskeyCandidate[]): void {
  const slot = h("div", { class: "notice-slot" });
  const actions = h("div", { class: "passkey-actions" });
  const sign = (c: PasskeyCandidate): void => {
    const back = h("button", { class: "btn", type: "button" }, t("close"));
    back.addEventListener("click", page.close);
    withPresence(state.status, slot, actions, [back], async (password) => {
      await ask({ type: "passkey_sign_in", passkeyId, item: c.item, ...(password !== undefined ? { password } : {}) });
    });
  };
  const rows = candidates.map((c) => {
    const button = h(
      "button",
      { class: "choice", type: "button", "data-id": c.item },
      siteTile(c.title, state.rp_id, state.page),
      h(
        "span",
        { class: "row-main" },
        h("span", { class: "row-title" }, c.title),
        h("span", { class: "row-sub" }, [c.user_name, c.vault].filter(Boolean).join(" · ")),
      ),
      h("span", { class: "kbd choice-enter", "aria-hidden": "true" }, "↵"),
    );
    button.addEventListener("click", (event) => {
      if (!personClicked(event, covered(slot))) return;
      sign(c);
    });
    return button;
  });
  render(
    head(state),
    h("p", { class: "section-title" }, t("passkey_sign_in_title")),
    h("div", { class: "list" }, ...rows),
    actions,
    slot,
    h("div", { class: "list list-foot" }, otherDevice(slot)),
  );
  // Picked in the field menu (conditional mediation): straight to presence.
  const chosen = candidates.find((c) => c.item === state.chosen);
  if (chosen) {
    whenArmed(slot, () => {
      sign(chosen);
    });
  } else {
    rows[0]?.focus();
  }
}

function create(state: PasskeyState): void {
  const slot = h("div", { class: "notice-slot" });
  const logins = state.logins ?? [];
  const select = h("select", { class: "input", "aria-label": t("passkey_save_in") });
  select.append(h("option", { value: "" }, t("passkey_new_login")));
  for (const l of logins) select.append(h("option", { value: l.id }, [l.title, l.username].filter(Boolean).join(" · ")));
  // The login of this same account, when there is one.
  if (logins[0] && state.user_name && logins[0].username === state.user_name) select.value = logins[0].id;
  const save = h("button", { class: "btn btn-primary", type: "button" }, t("passkey_save"));
  const actions = h("div", { class: "card-actions" }, save);
  const where = logins.length > 0 ? h("label", { class: "passkey-where" }, h("span", { class: "field-label" }, t("passkey_save_in")), select) : null;
  const who = state.user_name || state.rp_id;
  const saveWith = (options: { item?: string; replace?: boolean }) => async (password?: string) => {
    const reply = await ask<{ exists?: { item: string; title: string } }>({
      type: "passkey_save",
      passkeyId,
      ...options,
      ...(password !== undefined ? { password } : {}),
    });
    if (reply.exists) replace(state, reply.exists);
  };
  save.addEventListener("click", (event) => {
    if (!personClicked(event, covered(slot))) return;
    const item = select.value || undefined;
    const back = h("button", { class: "btn", type: "button" }, t("close"));
    back.addEventListener("click", page.close);
    withPresence(state.status, slot, actions, [back], saveWith(item ? { item } : {}));
  });
  render(
    head(state),
    h(
      "div",
      { class: "card" },
      siteTile(state.rp_name || state.rp_id, state.rp_id, state.page),
      h(
        "div",
        { class: "card-main" },
        h("p", { class: "card-what passkey-what" }, ...tNodes("passkey_save_for", h("strong", {}, who))),
        h("p", { class: "row-sub" }, [state.rp_name, state.rp_id].filter(Boolean).join(" · ")),
        where,
        actions,
        slot,
      ),
    ),
    h("div", { class: "list list-foot" }, otherDevice(slot)),
  );
  save.focus();
}

/** The account already has a passkey in `exists`: replace it (klavd asks for presence again), or keep it. */
function replace(state: PasskeyState, exists: { item: string; title: string }): void {
  const slot = h("div", { class: "notice-slot" });
  const yes = h("button", { class: "btn btn-primary", type: "button" }, t("passkey_replace"));
  const keep = h("button", { class: "btn", type: "button" }, t("passkey_keep"));
  const actions = h("div", { class: "card-actions" }, yes, keep);
  keep.addEventListener("click", page.close);
  yes.addEventListener("click", (event) => {
    if (!personClicked(event, covered(slot))) return;
    withPresence(state.status, slot, actions, [keep], async (password) => {
      await ask({ type: "passkey_save", passkeyId, item: exists.item, replace: true, ...(password !== undefined ? { password } : {}) });
    });
  });
  render(
    head(state),
    h(
      "div",
      { class: "card" },
      siteTile(exists.title, state.rp_id, state.page),
      h("div", { class: "card-main" }, h("p", { class: "passkey-question" }, t("passkey_replace_question", exists.title)), actions, slot),
    ),
  );
  yes.focus();
}

function locked(state: PasskeyState): void {
  const slot = h("div", { class: "notice-slot" });
  render(head(state), lockedForm(state.status, () => void load()), slot, h("div", { class: "list list-foot" }, otherDevice(slot)));
}

async function load(): Promise<void> {
  let state: PasskeyState;
  try {
    state = await ask<PasskeyState>({ type: "passkey_load", passkeyId });
  } catch {
    // Over (answered elsewhere, or nothing for Klav here): the background closes the frame.
    return;
  }
  if (!state.status.unlocked) locked(state);
  else if (state.kind === "get") signIn(state, state.candidates ?? []);
  else create(state);
}

/**
 * The presence gate's question (ADR 0041 §3.2): klavd wants the master
 * password before a value reaches this browser, and this frame asks for
 * it, never a field of the page. The text says what klavd's Touch ID
 * dialog would; closing the frame declines.
 */
function presenceFrame(question: PresenceAsk, problem?: DaemonError): void {
  const slot = h("div", { class: "notice-slot" });
  if (problem) say(slot, alertText(problem));
  const actions = h("div", { class: "passkey-actions" });
  const cancel = h("button", { class: "btn", type: "button" }, t("presence_cancel"));
  cancel.addEventListener("click", page.close);
  const go = (password?: string): void => {
    for (const b of root.querySelectorAll<HTMLButtonElement>("button")) b.disabled = true;
    ask({ type: "presence_answer", presenceId: passkeyId, password: password ?? "" }).catch((e: unknown) => {
      const error = errorOf(e);
      // klavd now asks something else: the new question. Anything else (a
      // wrong password, a frame the page covered) asks again with why; a
      // question that is over closes the frame from the background.
      if (error.code === "presence_required" && error.presence) presenceFrame(error.presence);
      else presenceFrame(question, error);
    });
  };
  render(
    frameHead(undefined, iconButton("close", t("close"), page.close)),
    h(
      "div",
      { class: "card" },
      h(
        "div",
        { class: "card-main" },
        h("p", { class: "section-title" }, t("presence_title")),
        h("p", { class: "passkey-question presence-question" }, presenceQuestion(question)),
        actions,
        slot,
      ),
    ),
  );
  presence(actions, false, go, [cancel]);
  actions.querySelector("input")?.setAttribute("aria-label", t("presence_password"));
  page.resize();
}

async function loadPresence(): Promise<void> {
  try {
    presenceFrame(await ask<PresenceAsk>({ type: "presence_load", presenceId: passkeyId }));
  } catch {
    // Over (answered, declined or timed out): the background closes the frame.
  }
}

keyboard(root, page.close);
if (passkeyId.startsWith("presence-")) void loadPresence();
else void load();
