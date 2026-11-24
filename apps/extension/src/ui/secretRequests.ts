/**
 * Agent secret request cards in the popup (ADR 0046).
 *
 * The person types or pastes the secret into a hidden field right here and
 * Klav encrypts and saves it E2E via `klavd` — the value never reaches the
 * agent or server in clear text, and the input is cleared on save, deny, or
 * pagehide.
 *
 * Security invariants enforced on the card:
 * - T234: agent-suggested `login` URLs stay unchecked by default.
 * - T235: `setup_url` is never auto-opened and shows its full host + warning
 *   (plus a punycode/IDN alert when applicable).
 * - T239: the browser extension never grants `klav-proxy` access (`grant_proxy`
 *   is always `false`; the card informs the person if a proxy proposal was
 *   attached).
 */
import { band, ditherCanvas } from "../shared/dither";
import { t } from "../shared/i18n";
import { daemon } from "../shared/messages";
import {
  DaemonError,
  type FulfillSecretRequestInput,
  type FulfillSecretResult,
  type ProjectSummary,
  type SecretRequestCard,
} from "../shared/protocol";
import { h } from "./dom";
import { errorText } from "./strings";

export interface ShownSecretRequest {
  el: HTMLElement;
  paint: () => void;
}

export function pendingSecretRequest(card: SecretRequestCard, done: () => void): ShownSecretRequest {
  const proposal = card.proposal ?? null;
  const message = h("div", {});
  const actions = h("div", { class: "approval-actions" });

  const secretInput = h("input", {
    class: "input",
    type: "password",
    autocomplete: "off",
    spellcheck: false,
    placeholder: proposal?.placeholder ?? "",
  });

  const wipeInput = (): void => {
    secretInput.value = "";
  };
  addEventListener("pagehide", wipeInput, { once: true });

  const titleInput =
    card.mode === "create"
      ? h("input", {
          class: "input",
          type: "text",
          autocomplete: "off",
          value: proposal?.title ?? "",
        })
      : null;

  const projectSelect = card.mode === "create" ? h("select", { class: "input" }) : null;
  if (projectSelect && proposal) {
    const granted = new Set((card.agent_projects ?? []).map(([v, p]) => `${v}/${p}`));
    void daemon<ProjectSummary[]>({ op: "projects" })
      .then((projects) => {
        projectSelect.replaceChildren();
        for (const p of projects) {
          const isShared = granted.has(`${p.vault_id}/${p.id}`);
          const label = isShared
            ? t("sr_project_shared", `${p.vault} / ${p.name}`, card.agent)
            : t("sr_project_not_shared", `${p.vault} / ${p.name}`, card.agent);
          const opt = h("option", { value: `${p.vault_id}::${p.id}` }, label);
          if (proposal.vault_id === p.vault_id && proposal.project_id === p.id) {
            opt.selected = true;
          }
          projectSelect.append(opt);
        }
      })
      .catch(() => {});
  }

  // T234: agent-suggested `login` URLs stay unchecked by default.
  const urlBoxes: { url: string; box: HTMLInputElement }[] = [];
  const suggestedUrls = card.mode === "create" && proposal?.kind === "login" ? (proposal.urls ?? []) : [];
  const urlList =
    suggestedUrls.length > 0
      ? h(
          "div",
          { class: "sr-urls" },
          h("p", { class: "sub" }, t("sr_urls_heading", card.agent)),
          h(
            "ul",
            { class: "perms" },
            ...suggestedUrls.map((url) => {
              const box = h("input", { type: "checkbox", class: "check" });
              box.checked = false;
              urlBoxes.push({ url, box });
              return h("li", { class: "perm" }, h("label", { class: "perm-line" }, box, h("span", { class: "perm-name" }, url)));
            }),
          ),
        )
      : null;

  const setBusy = (busy: boolean): void => {
    for (const b of actions.querySelectorAll("button")) b.disabled = busy;
    secretInput.disabled = busy;
    if (titleInput) titleInput.disabled = busy;
    if (projectSelect) projectSelect.disabled = busy;
  };

  const showError = (e: unknown): void => {
    const error = e instanceof DaemonError ? e : new DaemonError("internal", String(e));
    message.replaceChildren(h("p", { class: "notice", role: "alert" }, errorText(error.code, error.message)));
  };

  const canSave = !card.proposal_error && proposal !== null && (card.mode === "create" || Boolean(card.target_reference));
  const save = h("button", { class: "btn btn-primary", type: "button", disabled: !canSave }, t("sr_save"));
  const deny = h("button", { class: "btn", type: "button" }, t("deny"));

  save.addEventListener("click", () => {
    const value = secretInput.value;
    if (!value) {
      message.replaceChildren(h("p", { class: "notice", role: "alert" }, t("sr_secret_empty")));
      secretInput.focus();
      return;
    }
    const input: FulfillSecretRequestInput = {
      digest: card.proposal_digest,
      secret: value,
      grant_proxy: false,
    };
    if (card.mode === "create") {
      if (titleInput?.value.trim()) input.title = titleInput.value.trim();
      if (projectSelect?.value) {
        const [vaultId, projectId] = projectSelect.value.split("::");
        if (vaultId) input.vault = vaultId;
        if (projectId) input.project = projectId;
      }
      const confirmedUrls = urlBoxes.filter((u) => u.box.checked).map((u) => u.url);
      if (confirmedUrls.length > 0) input.urls = confirmedUrls;
    }
    setBusy(true);
    message.replaceChildren();
    daemon<FulfillSecretResult>({
      op: "fulfill_secret_request",
      request: card.id,
      input,
    }).then(
      () => {
        wipeInput();
        done();
      },
      (e: unknown) => {
        setBusy(false);
        showError(e);
      },
    );
  });

  deny.addEventListener("click", () => {
    setBusy(true);
    message.replaceChildren();
    daemon<SecretRequestCard>({
      op: "deny_secret_request",
      request: card.id,
      digest: card.proposal_digest,
    }).then(
      () => {
        wipeInput();
        done();
      },
      (e: unknown) => {
        setBusy(false);
        showError(e);
      },
    );
  });

  actions.append(save, deny);

  const heading =
    card.mode === "update"
      ? h("p", { class: "approval-what" }, t("sr_update_title", proposal?.field ?? "secret", card.target_title ?? card.target_reference ?? "?"))
      : h("p", { class: "approval-what" }, t("sr_create_title", proposal?.kind ?? "api_key"));

  const setup = card.setup_url;
  const setupBlock = setup
    ? h(
        "div",
        { class: "sr-setup" },
        h("p", { class: "sub" }, t("sr_setup_warning", card.agent, setup.host)),
        setup.has_punycode ? h("p", { class: "notice", role: "alert" }, t("sr_setup_punycode")) : null,
        h("a", { class: "link", href: setup.url, target: "_blank", rel: "noopener noreferrer" }, t("sr_setup_open", setup.host)),
      )
    : null;

  const proxyNote = proposal?.proxy_proposal
    ? h("p", { class: "sub" }, t("sr_proxy_note", proposal.proxy_proposal.profile, proposal.proxy_proposal.upstream))
    : null;

  const stripe = ditherCanvas(document, band(), { palette: "blue", pixel: 2 });
  const el = h(
    "li",
    { class: "approval cross" },
    h("div", { class: "approval-band" }, stripe.canvas),
    h(
      "div",
      { class: "approval-body" },
      h("p", { class: "agent-mark" }, t("sr_agent_asks", card.agent)),
      heading,
      card.mode === "update" && card.target_reference ? h("p", { class: "sub" }, card.target_reference) : null,
      card.mode === "update" && !card.target_reference ? h("p", { class: "notice", role: "alert" }, t("sr_target_missing")) : null,
      card.mode === "update" ? h("p", { class: "sub" }, t("sr_update_history")) : null,
      h("p", { class: "approval-reason" }, t("quote", card.reason)),
      card.proposal_error ? h("p", { class: "notice", role: "alert" }, card.proposal_error) : null,
      titleInput ? h("label", { class: "field" }, h("span", { class: "label" }, t("sr_title_label")), titleInput) : null,
      projectSelect ? h("label", { class: "field" }, h("span", { class: "label" }, t("sr_project_label")), projectSelect) : null,
      urlList,
      setupBlock,
      proxyNote,
      canSave
        ? h("label", { class: "field" }, h("span", { class: "label" }, t("sr_secret_label", proposal.field)), secretInput)
        : null,
      message,
      actions,
    ),
  );

  return {
    el,
    paint: () => {
      stripe.repaint();
    },
  };
}
