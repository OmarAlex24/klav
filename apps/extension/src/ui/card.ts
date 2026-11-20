/**
 * The top card: when a page has a sign-in form and Klav has a login for
 * it, a small card at the top right offers «Iniciar sesión como ana ·
 * github.com». It never fills without a click; it goes away when the
 * person closes it or starts typing in the form.
 */
import { localizePage, plural, t, tNodes } from "../shared/i18n";
import { ask, type CardState } from "../shared/messages";
import { h } from "./dom";
import { framePage } from "./frame";
import { COVERED, personClicked } from "./guard";
import { alertText, say } from "./inpage";
import { iconButton } from "./kit";
import { siteTile } from "./siteicon";

localizePage("frame_card");
const root = document.getElementById("card") as HTMLElement;
const page = framePage("card", root);
const cardId = page.id;

function render(state: CardState): void {
  const slot = h("div", { class: "notice-slot" });
  const who = state.login.username ?? state.login.title;
  const covered = (): void => {
    say(slot, COVERED);
    page.resize();
  };
  const go = h("button", { class: "btn btn-primary", type: "button" }, t("sign_in"));
  go.addEventListener("click", (event) => {
    if (!personClicked(event, covered)) return;
    go.disabled = true;
    ask<{ filled: number }>({ type: "card_fill", cardId }).then(
      ({ filled }) => {
        if (filled > 0) return;
        say(slot, t("nowhere_form"));
        go.disabled = false;
        page.resize();
      },
      (e: unknown) => {
        say(slot, alertText(e));
        go.disabled = false;
        page.resize();
      },
    );
  });
  const actions = h("div", { class: "card-actions" }, go);
  if (state.others > 0) {
    const other = h("button", { class: "btn", type: "button" }, plural("other_accounts", state.others));
    other.addEventListener("click", (event) => {
      if (!personClicked(event, covered)) return;
      void ask({ type: "card_find", cardId }).catch((e: unknown) => {
        say(slot, alertText(e));
        page.resize();
      });
    });
    actions.append(other);
  }
  root.replaceChildren(
    h(
      "div",
      { class: "card" },
      siteTile(state.login.title, state.host, state.page),
      h(
        "div",
        { class: "card-main" },
        h("p", { class: "card-what" }, ...tNodes("sign_in_as", h("strong", {}, who)), h("span", { class: "card-host" }, ` · ${state.host}`)),
        h("p", { class: "row-sub" }, `${state.login.title} · ${state.login.location}`),
        actions,
        slot,
      ),
      iconButton("close", t("close"), page.close),
    ),
  );
  page.resize();
}

async function load(): Promise<void> {
  try {
    render(await ask<CardState>({ type: "card_load", cardId }));
  } catch {
    // Expired or locked meanwhile: the card has nothing to offer.
    page.close();
  }
}

document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") page.close();
});

void load();
