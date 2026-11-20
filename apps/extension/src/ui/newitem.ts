/**
 * «Nuevo elemento» in the popup: a login, a secure note, a card or a
 * one-time code typed by hand. It ends in klavd's `create`, the same
 * operation the save bar uses, so nothing new reads a secret back. Values
 * live in the form's inputs only: they are set as properties (never as
 * attributes, so they are not in the page's HTML) and cleared when the
 * item is saved or the view closes. Loaded only when the person opens it
 * (popup.ts imports it on «+»).
 */
import { t } from "../shared/i18n";
import type { MessageKey } from "../shared/i18n";
import { forgetValues } from "../shared/messages";
import { DaemonError, type ItemSummary, type NewItem, type ProjectSummary, type Request } from "../shared/protocol";
import { h } from "./dom";
import { iconButton } from "./kit";
import { errorText } from "./strings";

/** What the view can create: kinds klav-core has templates for and the popup can type. */
export type NewKind = "login" | "note" | "card" | "totp";
export const NEW_KINDS: NewKind[] = ["login", "note", "card", "totp"];
const KIND_NAME: Record<NewKind, MessageKey> = { login: "kind_login", note: "new_kind_note", card: "kind_card", totp: "kind_totp" };

/** What the person typed. Every value is optional; empty ones are left out. */
export interface Draft {
  title: string;
  username?: string;
  password?: string;
  site?: string;
  notes?: string;
  cardholder?: string;
  number?: string;
  expiry?: string;
  cvv?: string;
  totp?: string;
}

/** What a pasted key says about itself (klav-wasm `totpCheck`): never the secret. */
export interface TotpInfo {
  issuer?: string;
  account?: string;
  digits: number;
  period: number;
}

/** A problem with one input, shown under it. */
export class DraftError extends Error {
  constructor(
    readonly field: keyof Draft,
    message: string,
  ) {
    super(message);
    this.name = "DraftError";
  }
}

/**
 * A site typed by the person, as an origin (`https://github.com`), the way
 * the save bar keeps them. `github.com` means `https://github.com`.
 */
export function siteOrigin(text: string | undefined): string | undefined {
  const trimmed = text?.trim() ?? "";
  if (trimmed === "") return undefined;
  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
  let url: URL;
  try {
    url = new URL(withScheme);
  } catch {
    throw new DraftError("site", t("new_site_invalid"));
  }
  if ((url.protocol !== "https:" && url.protocol !== "http:") || url.hostname === "") throw new DraftError("site", t("new_site_invalid"));
  return url.origin;
}

/**
 * A card's expiry as klav-core keeps it (`YYYY-MM`), from what is printed
 * on the card: `MM/YY`, `MM/YYYY` or `YYYY-MM`.
 */
export function expiryValue(text: string | undefined): string | undefined {
  const trimmed = text?.replace(/\s+/g, "") ?? "";
  if (trimmed === "") return undefined;
  let year: number;
  let month: number;
  const printed = /^(\d{1,2})[/.-](\d{2}|\d{4})$/.exec(trimmed);
  const iso = /^(\d{4})-(\d{2})$/.exec(trimmed);
  if (iso) {
    year = Number(iso[1]);
    month = Number(iso[2]);
  } else if (printed) {
    month = Number(printed[1]);
    year = Number(printed[2]);
    if (year < 100) year += 2000;
  } else {
    throw new DraftError("expiry", t("new_expiry_invalid"));
  }
  if (month < 1 || month > 12) throw new DraftError("expiry", t("new_expiry_invalid"));
  return `${String(year)}-${String(month).padStart(2, "0")}`;
}

/** `vault\0project` from the destination list (the save bar's format) as `NewItem` fields. */
function destination(where: string | undefined): Pick<NewItem, "vault" | "project"> {
  const [vault, project] = where?.split("\u0000") ?? [];
  return { ...(vault ? { vault } : {}), ...(project ? { project } : {}) };
}

/**
 * The `create` request for a draft. Secret values go with `secret: true`
 * (klav-core refuses a secret field sent as plain text); empty ones are
 * left out, so the item keeps its template's empty fields.
 */
export function newItemRequest(kind: NewKind, draft: Draft, where?: string): NewItem {
  const title = draft.title.trim();
  if (title === "") throw new DraftError("title", t("new_title_missing"));
  const fields: NewItem["fields"] = [];
  const add = (name: string, value: string | undefined, kind: NonNullable<NewItem["fields"][number]["kind"]>, secret: boolean): void => {
    if (value !== undefined && value !== "") fields.push({ name, value, kind, secret });
  };
  const item: NewItem = { kind, title, ...destination(where), fields, urls: [], tags: [] };
  switch (kind) {
    case "login": {
      add("username", draft.username?.trim(), "username", false);
      add("password", draft.password, "password", true);
      const site = siteOrigin(draft.site);
      if (site) item.urls.push(site);
      break;
    }
    case "note":
      if (draft.notes && draft.notes.trim() !== "") item.notes = draft.notes;
      break;
    case "card":
      add("cardholder", draft.cardholder?.trim(), "text", false);
      add("number", draft.number?.replace(/[\s-]+/g, ""), "concealed", true);
      add("expiry", expiryValue(draft.expiry), "month_year", false);
      add("cvv", draft.cvv?.trim(), "concealed", true);
      break;
    case "totp": {
      const key = draft.totp?.trim() ?? "";
      if (key === "") throw new DraftError("totp", t("new_totp_missing"));
      add("totp", key, "totp", true);
      break;
    }
  }
  return item;
}

/** The title a pasted key suggests: its issuer, or its account. */
export function totpTitle(info: TotpInfo): string | undefined {
  return info.issuer ?? info.account;
}

/** «6 digits every 30 s · ACME · ana@example.com». */
export function totpSummary(info: TotpInfo): string {
  return [t("new_totp_ok", info.digits, info.period), info.issuer, info.account].filter(Boolean).join(" · ");
}

/** What the view needs from the popup (injected, so tests run without the extension). */
export interface NewItemDeps {
  daemon: <T>(request: Request) => Promise<T>;
  /** The active tab's page, if Klav runs there. */
  here: () => Promise<string | undefined>;
  /** klav-core through WASM. */
  fillableHost: (url: string) => Promise<string | undefined>;
  /** klav-core reads a pasted key; throws if it is not one. */
  checkTotp: (value: string) => Promise<TotpInfo>;
  /**
   * The generator for `host`, whose «Usar esta contraseña» keeps the
   * password in its history (ADR 0022 §2) before `use` gets it.
   */
  generator?: (host: string | undefined, use: (value: string) => Promise<void>) => Promise<HTMLElement>;
  /** The item was created. */
  created: (item: ItemSummary) => void;
}

interface Input {
  el: HTMLInputElement | HTMLTextAreaElement;
  error: HTMLElement;
}

/** Mounts the form into `content`; the function it returns clears every value. */
export function mountNewItem(content: HTMLElement, deps: NewItemDeps, start: NewKind = "login"): () => void {
  let kind: NewKind = start;
  let pageUrl: string | undefined;
  let pageHost: string | undefined;
  let projects: ProjectSummary[] = [];
  let titleTouched = false;
  let busy = false;
  const inputs = new Map<keyof Draft, Input>();

  const tabs = h("div", { class: "new-kinds", role: "radiogroup", "aria-label": t("new_kind") });
  const fields = h("div", { class: "new-fields" });
  const whereSlot = h("div", { class: "new-where" });
  const message = h("div", { class: "new-message" });
  const save = h("button", { class: "btn btn-primary btn-block", type: "submit" }, t("save"));
  const form = h("form", { class: "new-form", novalidate: true }, tabs, fields, whereSlot, message, save);

  const clearAll = (): void => {
    for (const i of inputs.values()) i.el.value = "";
  };

  /** A labelled input; its value is only ever set as a property. */
  const field = (
    name: keyof Draft,
    label: string,
    attrs: Record<string, string | boolean>,
    options: { textarea?: boolean; end?: HTMLElement[]; hint?: HTMLElement } = {},
  ): HTMLElement => {
    const id = `new-${name}`;
    const el = options.textarea
      ? h("textarea", { class: "input new-textarea", id, name, rows: "6", spellcheck: "false", ...attrs })
      : h("input", { class: "input", id, name, autocomplete: "off", spellcheck: "false", ...attrs });
    const error = h("p", { class: "notice new-error", id: `${id}-error`, role: "alert" });
    el.setAttribute("aria-describedby", error.id);
    el.addEventListener("input", () => {
      error.textContent = "";
      el.removeAttribute("aria-invalid");
    });
    inputs.set(name, { el, error });
    const control = options.end ? h("div", { class: "new-control" }, el, ...options.end) : el;
    return h("div", { class: "new-field" }, h("label", { class: "field-label", for: id }, label), control, options.hint ?? null, error);
  };

  const value = (name: keyof Draft): string | undefined => inputs.get(name)?.el.value;

  const showError = (name: keyof Draft, text: string): void => {
    const i = inputs.get(name);
    if (!i) {
      message.replaceChildren(h("p", { class: "notice", role: "alert" }, text));
      return;
    }
    i.error.textContent = text;
    i.el.setAttribute("aria-invalid", "true");
    i.el.focus();
  };

  /** The title follows the site (or the key) until the person types one. */
  const suggestTitle = (text: string | undefined): void => {
    const title = inputs.get("title")?.el;
    if (!title || titleTouched || !text) return;
    title.value = text;
  };

  const passwordField = (): HTMLElement => {
    const label = t("field_password");
    const show = h("button", { class: "btn btn-s", type: "button", "aria-label": t("show_field", label) }, t("show"));
    const generate = iconButton("asterisk", t("gen_open"));
    const panel = h("div", { class: "new-gen", hidden: true });
    const wrap = field("password", label, { type: "password", autocomplete: "new-password" }, { end: [show, generate] });
    const input = inputs.get("password")?.el as HTMLInputElement;
    show.addEventListener("click", () => {
      const hidden = input.type === "password";
      input.type = hidden ? "text" : "password";
      show.textContent = hidden ? t("hide") : t("show");
      show.setAttribute("aria-label", t(hidden ? "hide_field" : "show_field", label));
    });
    if (!deps.generator) generate.hidden = true;
    generate.setAttribute("aria-expanded", "false");
    generate.addEventListener("click", () => {
      if (!panel.hidden) {
        panel.hidden = true;
        panel.replaceChildren();
        generate.setAttribute("aria-expanded", "false");
        return;
      }
      void deps.generator?.(pageHost, (v) => {
        input.value = v;
        input.dispatchEvent(new Event("input"));
        panel.hidden = true;
        panel.replaceChildren();
        generate.setAttribute("aria-expanded", "false");
        input.focus();
        return Promise.resolve();
      }).then((el) => {
        panel.replaceChildren(el);
        panel.hidden = false;
        generate.setAttribute("aria-expanded", "true");
      });
    });
    wrap.append(panel);
    return wrap;
  };

  const totpField = (): HTMLElement => {
    const hint = h("p", { class: "sub new-hint", role: "status" }, t("new_totp_hint"));
    const wrap = field("totp", t("new_totp_key"), { type: "password", autocomplete: "off", placeholder: "otpauth://totp/… · JBSW Y3DP…" }, { hint });
    const input = inputs.get("totp")?.el as HTMLInputElement;
    let seq = 0;
    input.addEventListener("input", () => {
      const mine = ++seq;
      const text = input.value.trim();
      if (text === "") {
        hint.textContent = t("new_totp_hint");
        return;
      }
      void deps.checkTotp(text).then(
        (info) => {
          if (mine !== seq) return;
          hint.textContent = totpSummary(info);
          suggestTitle(totpTitle(info));
        },
        () => {
          if (mine !== seq) return;
          hint.textContent = t("new_totp_invalid");
        },
      );
    });
    return wrap;
  };

  const paintFields = (): void => {
    // Values of the kind left behind go: nothing typed stays out of sight.
    const title = value("title") ?? "";
    clearAll();
    inputs.clear();
    message.replaceChildren();
    const rows: HTMLElement[] = [field("title", t("title"), { type: "text", required: true })];
    const titleInput = inputs.get("title")?.el as HTMLInputElement;
    titleInput.value = title;
    titleInput.addEventListener("input", () => {
      titleTouched = titleInput.value.trim() !== "";
    });
    if (kind === "login") {
      rows.push(field("username", t("field_username"), { type: "text", autocomplete: "off" }), passwordField(), field("site", t("new_site"), { type: "text", inputmode: "url", placeholder: "example.com" }));
      const site = inputs.get("site")?.el as HTMLInputElement;
      site.value = pageUrl && pageHost ? new URL(pageUrl).origin : "";
      site.addEventListener("input", () => {
        try {
          const origin = siteOrigin(site.value);
          suggestTitle(origin ? new URL(origin).host : undefined);
        } catch {
          // Said on «Guardar».
        }
      });
      if (!titleTouched && pageHost && title === "") titleInput.value = pageHost;
    } else if (kind === "note") {
      rows.push(field("notes", t("note"), {}, { textarea: true }));
    } else if (kind === "card") {
      rows.push(
        field("cardholder", t("field_cardholder"), { type: "text", autocomplete: "off" }),
        field("number", t("field_number"), { type: "password", inputmode: "numeric", autocomplete: "off" }),
        h(
          "div",
          { class: "new-pair" },
          field("expiry", t("field_expiry"), { type: "text", inputmode: "numeric", placeholder: t("new_expiry_placeholder") }),
          field("cvv", t("field_cvv"), { type: "password", inputmode: "numeric", autocomplete: "off" }),
        ),
      );
    } else {
      rows.push(totpField());
    }
    fields.replaceChildren(...rows);
  };

  const paintTabs = (): void => {
    tabs.replaceChildren(
      ...NEW_KINDS.map((k) => {
        const on = k === kind;
        const tab = h("button", { class: on ? "new-kind is-on" : "new-kind", type: "button", role: "radio", "aria-checked": on ? "true" : "false", "data-kind": k }, t(KIND_NAME[k]));
        tab.addEventListener("click", () => {
          if (kind === k) return;
          kind = k;
          if (!titleTouched) {
            const title = inputs.get("title")?.el;
            if (title) title.value = "";
          }
          paintTabs();
          paintFields();
        });
        return tab;
      }),
    );
  };

  const where = h("select", { class: "input", id: "new-where", name: "where" });
  const paintWhere = (): void => {
    if (projects.length < 2) {
      whereSlot.replaceChildren();
      return;
    }
    where.replaceChildren(...projects.map((p) => h("option", { value: `${p.vault}\u0000${p.name}` }, `${p.vault} / ${p.name}`)));
    whereSlot.replaceChildren(h("div", { class: "new-field" }, h("label", { class: "field-label", for: "new-where" }, t("where")), where));
  };

  form.addEventListener("submit", (event) => {
    event.preventDefault();
    if (busy) return;
    message.replaceChildren();
    for (const i of inputs.values()) i.error.textContent = "";
    const draft: Draft = { title: value("title") ?? "" };
    for (const name of inputs.keys()) if (name !== "title") draft[name] = value(name);
    let request: Request;
    try {
      request = { op: "create", item: newItemRequest(kind, draft, where.value || undefined) };
    } catch (e) {
      if (e instanceof DraftError) showError(e.field, e.message);
      else message.replaceChildren(h("p", { class: "notice", role: "alert" }, e instanceof Error ? e.message : String(e)));
      return;
    } finally {
      for (const k of Object.keys(draft) as (keyof Draft)[]) draft[k] = "";
    }
    busy = true;
    save.disabled = true;
    deps
      .daemon<ItemSummary>(request)
      .then(
        (item) => {
          clearAll();
          deps.created(item);
        },
        (e: unknown) => {
          const error = e instanceof DaemonError ? e : new DaemonError("internal", e instanceof Error ? e.message : "error");
          if (/already exists/.test(error.message)) showError("title", t("new_title_taken"));
          else if (/TOTP/i.test(error.message)) showError("totp", t("new_totp_invalid"));
          else if (/URL/i.test(error.message)) showError("site", t("new_site_invalid"));
          else message.replaceChildren(h("p", { class: "notice", role: "alert" }, errorText(error.code, error.message)));
        },
      )
      .finally(() => {
        forgetValues(request);
        busy = false;
        save.disabled = false;
      });
  });

  content.append(form);
  paintTabs();
  paintFields();
  queueMicrotask(() => inputs.get("title")?.el.focus({ preventScroll: true }));

  // The active tab's site and the destinations, once; nothing waits on them.
  void deps
    .here()
    .then(async (url) => {
      const host = url ? await deps.fillableHost(url) : undefined;
      if (!url || !host) return;
      pageUrl = url;
      pageHost = host;
      if (kind !== "login") return;
      const site = inputs.get("site")?.el;
      if (site && site.value === "") site.value = new URL(url).origin;
      suggestTitle(host);
    })
    .catch(() => undefined);
  void deps
    .daemon<ProjectSummary[]>({ op: "projects" })
    .then((list) => {
      projects = list;
      paintWhere();
    })
    .catch(() => undefined);

  return () => {
    clearAll();
    inputs.clear();
  };
}
