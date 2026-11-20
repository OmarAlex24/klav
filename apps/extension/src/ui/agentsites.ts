/**
 * «Sitios añadidos por un agente» in the popup's item view (ADR 0030 §7):
 * the URLs an agent wrote into a login that the person has not confirmed.
 * Klav neither suggests nor fills the login there (klav-client applies the
 * rule); here the person sees them and confirms or removes them.
 *
 * Both act on all of them at once, like `klav item sites`: any edit by the
 * person makes a version of hers, which confirms every site it keeps, so
 * removing one site alone would confirm the others without asking.
 * Confirming asks twice and names the sites.
 */
import { t } from "../shared/i18n";
import { daemon } from "../shared/messages";
import type { ItemPatch, ItemSummary, ItemView } from "../shared/protocol";
import { h } from "./dom";

export interface AgentSitesOptions {
  /** After a confirmation or a removal (show the item again). */
  changed: () => void;
  failed: (e: unknown) => void;
  /** Whether a click counts (the person's own: `isTrusted`). */
  trusted?: (event: Event) => boolean;
}

function hostOf(url: string): string {
  try {
    return new URL(url).host || url;
  } catch {
    return url;
  }
}

const EMPTY: ItemPatch = { set: [], remove: [], add_urls: [], add_tags: [] };

/** The section for `view`'s pending sites, or `null` if it has none. */
export function agentSites(view: ItemView, o: AgentSitesOptions): HTMLElement | null {
  const pending = view.pending_urls ?? [];
  if (pending.length === 0) return null;
  const trusted = o.trusted ?? ((event: Event) => event.isTrusted);
  const hosts = pending.map(hostOf).join(", ");
  const edit = (patch: ItemPatch, buttons: HTMLButtonElement[]): void => {
    for (const b of buttons) b.disabled = true;
    daemon<ItemSummary>({ op: "edit", query: view.id, patch }).then(o.changed, (e: unknown) => {
      for (const b of buttons) b.disabled = false;
      o.failed(e);
    });
  };
  const actions = h("div", { class: "agent-sites-actions" });
  const confirm = h("button", { class: "btn btn-s", type: "button" }, t("agent_sites_confirm"));
  const remove = h("button", { class: "btn btn-s btn-danger", type: "button" }, t("agent_sites_remove"));
  const start = (): void => {
    actions.replaceChildren(confirm, remove);
  };
  confirm.addEventListener("click", (event) => {
    if (!trusted(event)) return;
    // A second step that says what confirming means.
    const yes = h("button", { class: "btn btn-s btn-primary", type: "button" }, t("agent_sites_confirm_yes"));
    const no = h("button", { class: "btn btn-s", type: "button" }, t("gen_history_clear_keep"));
    yes.addEventListener("click", (e) => {
      if (trusted(e)) edit(EMPTY, [yes, no]);
    });
    no.addEventListener("click", (e) => {
      if (trusted(e)) start();
    });
    actions.replaceChildren(h("p", { class: "sub", role: "alert" }, t("agent_sites_confirm_sure", hosts)), yes, no);
  });
  remove.addEventListener("click", (event) => {
    if (trusted(event)) edit({ ...EMPTY, remove_urls: pending }, [confirm, remove]);
  });
  start();
  return h(
    "section",
    { class: "group agent-sites" },
    h("h2", { class: "label" }, t("agent_sites_title")),
    h("p", { class: "value" }, hosts),
    h("p", { class: "sub" }, t("agent_sites_hint")),
    actions,
  );
}
