/**
 * The password generator (ADR 0022 §1–§2), shared by the field menu and
 * the popup. klav-core (WASM) makes the password, following the field's
 * own rules or the site's bundled ones; every password is kept in the
 * generator history (through klavd) before it is typed or copied, so a
 * form that fails never loses it.
 */
import { daemon } from "../shared/messages";
import type { FieldRules } from "../shared/messages";
import { DaemonError } from "../shared/protocol";
import type { GeneratedView } from "../shared/protocol";
import { ext } from "../shared/ext";
import { locale, t } from "../shared/i18n";
import type { MessageKey } from "../shared/i18n";
import { klavCore } from "../shared/wasm";
import { h } from "./dom";
import { icon, iconButton } from "./kit";
import { errorText } from "./strings";
import { gated } from "./presence";

/** What went wrong, in the words of the rest of Klav. */
function why(e: unknown): string {
  if (e instanceof DaemonError) return errorText(e.code, e.message);
  return e instanceof Error ? e.message : String(e);
}

export type GeneratorKind = "smart" | "random" | "memorable" | "pin";
type Strength = "weak" | "fair" | "strong" | "very_strong";
type RulesSource = { source: "field" } | { source: "bundled"; domain: string } | { source: "lengths" };

/** What klav-core answers (`generate` in klav-wasm). */
export interface Generated {
  value: string;
  kind: GeneratorKind;
  bits: number;
  strength: Strength;
  rules: RulesSource | null;
  limited: boolean;
  fallback: "unreadable" | "impossible" | null;
}

/** The options the person can change; the rest are klav-core's defaults. */
export interface GeneratorOptions {
  kind: GeneratorKind;
  length: number;
  digits: boolean;
  symbols: boolean;
  words: number;
  pin_length: number;
}

export const KINDS: GeneratorKind[] = ["smart", "random", "memorable", "pin"];
const KIND_NAME: Record<GeneratorKind, MessageKey> = {
  smart: "gen_kind_smart",
  random: "gen_kind_random",
  memorable: "gen_kind_memorable",
  pin: "gen_kind_pin",
};
const STRENGTH_NAME: Record<Strength, MessageKey> = {
  weak: "strength_weak",
  fair: "strength_fair",
  strong: "strength_strong",
  very_strong: "strength_very_strong",
};
const STRENGTH_STEPS: Record<Strength, number> = { weak: 1, fair: 2, strong: 3, very_strong: 4 };

/** The default type, kept in `storage.local` («Usar como predeterminada»). */
export const DEFAULT_KIND_KEY = "generatorDefaultKind";

export const DEFAULT_OPTIONS: GeneratorOptions = { kind: "smart", length: 20, digits: true, symbols: true, words: 5, pin_length: 6 };

const LIMITS = { length: [8, 64], words: [3, 10], pin_length: [4, 12] } as const;

export async function defaultKind(): Promise<GeneratorKind> {
  try {
    const stored = (await ext.storage.local.get(DEFAULT_KIND_KEY))[DEFAULT_KIND_KEY];
    return KINDS.includes(stored as GeneratorKind) ? (stored as GeneratorKind) : "smart";
  } catch {
    return "smart";
  }
}

async function setDefaultKind(kind: GeneratorKind): Promise<void> {
  try {
    await ext.storage.local.set({ [DEFAULT_KIND_KEY]: kind });
  } catch {
    // Not kept: the menu opens with «Inteligente» next time.
  }
}

/** klav-core's generator, through WASM. */
export async function generate(options: GeneratorOptions, host: string | undefined, rules: FieldRules | undefined): Promise<Generated> {
  const core = await klavCore();
  const site = { ...(host ? { host } : {}), ...(rules ?? {}) };
  const full = {
    kind: options.kind,
    length: options.length,
    digits: options.digits,
    symbols: options.symbols,
    avoid_ambiguous: true,
    words: options.words,
    pin_length: options.pin_length,
  };
  return JSON.parse(core.generate(JSON.stringify(full), JSON.stringify(site))) as Generated;
}

/** Keeps `value` in the generator history before anyone types it. */
export function record(value: string, host: string | undefined): Promise<unknown> {
  return daemon({ op: "generator_record", value, ...(host ? { host } : {}) });
}

/**
 * The password with each character's class as a class name (G10): letters
 * in ink, digits in grey, symbols in ink on mist. Spaces stay visible.
 * A PIN (only digits) stays in ink: grey alone reads like a placeholder.
 */
export function colored(value: string): DocumentFragment {
  const out = document.createDocumentFragment();
  let run = "";
  let runClass = "";
  const flush = (): void => {
    if (run === "") return;
    out.append(runClass ? h("span", { class: runClass }, run) : run);
    run = "";
  };
  const pin = /^[0-9]+$/.test(value);
  for (const ch of value) {
    const cls = /[A-Za-z]/.test(ch) ? "" : /[0-9]/.test(ch) ? (pin ? "" : "ch-digit") : "ch-symbol";
    // Each symbol is its own cell; letters and digits run together.
    if (cls !== runClass || cls === "ch-symbol") flush();
    runClass = cls;
    run += ch === " " ? " " : ch;
  }
  flush();
  return out;
}

function strengthMeter(g: Generated): HTMLElement {
  const steps = STRENGTH_STEPS[g.strength];
  const bar = h("span", { class: `meter meter-${g.strength}`, "aria-hidden": "true" });
  for (let i = 1; i <= 4; i++) bar.append(h("i", { class: i <= steps ? "on" : "" }));
  return h("div", { class: "strength" }, bar, h("span", { class: "strength-text" }, t("gen_strength", t(STRENGTH_NAME[g.strength]), Math.round(g.bits))));
}

function rulesNote(g: Generated): string | undefined {
  if (g.fallback === "unreadable") return t("gen_fallback_unreadable");
  if (g.fallback === "impossible") return t("gen_fallback_impossible");
  const lines: string[] = [];
  if (g.kind === "smart") {
    if (g.rules?.source === "bundled") lines.push(t("gen_rules_bundled", g.rules.domain));
    else if (g.rules?.source === "field") lines.push(t("gen_rules_field"));
    else if (g.rules?.source === "lengths") lines.push(t("gen_rules_lengths"));
    else lines.push(t("gen_rules_none"));
  }
  if (g.limited) lines.push(t("gen_limited"));
  return lines.length > 0 ? lines.join(" ") : undefined;
}

/** − value + for a number option. */
function stepper(label: MessageKey, value: number, [min, max]: readonly [number, number], change: (n: number) => void): HTMLElement {
  const less = h("button", { class: "icon-btn", type: "button", "aria-label": `${t(label)}: ${t("gen_less")}` }, "−");
  const more = h("button", { class: "icon-btn", type: "button", "aria-label": `${t(label)}: ${t("gen_more")}` }, "+");
  less.disabled = value <= min;
  more.disabled = value >= max;
  less.addEventListener("click", () => {
    change(Math.max(min, value - 1));
  });
  more.addEventListener("click", () => {
    change(Math.min(max, value + 1));
  });
  return h("div", { class: "opt opt-step" }, h("span", { class: "opt-label" }, t(label)), less, h("output", { class: "opt-value" }, String(value)), more);
}

function toggle(label: MessageKey, on: boolean, change: (on: boolean) => void): HTMLElement {
  const box = h("input", { type: "checkbox", ...(on ? { checked: true } : {}) });
  box.addEventListener("change", () => {
    change(box.checked);
  });
  return h("label", { class: "opt opt-check" }, box, h("span", {}, t(label)));
}

export interface PanelOptions {
  host: string | undefined;
  rules?: FieldRules;
  /** Where messages go (an alert slot). */
  say: (text: string, tone?: "error" | "info") => void;
  /** The panel changed size. */
  resized: () => void;
  /** Copies to the clipboard; resolves when it did. */
  copy: (value: string) => Promise<void>;
  /** «Usar esta contraseña» (the field menu only): types it into the form. */
  use?: (value: string) => Promise<void>;
  /** «Historial del generador». */
  history: () => void;
  /** Where «Historial del generador» goes (default: the panel's foot). */
  historyIn?: HTMLElement;
  /** Whether a click on «Copiar» or «Usar» counts (the menu's clickjacking guard). */
  guard?: (event: Event) => boolean;
}

/** The generator: type, options, the password, its strength and what to do with it. */
export async function generatorPanel(o: PanelOptions): Promise<HTMLElement> {
  const options: GeneratorOptions = { ...DEFAULT_OPTIONS, kind: await defaultKind() };
  let current: Generated | undefined;
  let busy = false;
  const root = h("section", { class: "gen", "aria-label": t("gen_title") });
  const tabs = h("div", { class: "gen-kinds", role: "radiogroup", "aria-label": t("gen_type") });
  const value = h("output", { class: "gen-value", "aria-label": t("generated_password"), "aria-live": "polite" });
  const meter = h("div", { class: "gen-meter" });
  const note = h("p", { class: "gen-note" });
  const opts = h("div", { class: "gen-opts" });
  const copyButton = iconButton("copy", t("gen_copy_label"));
  const again = iconButton("refresh", t("generate_another"));
  const defaultBox = h("input", { type: "checkbox" });
  defaultBox.addEventListener("change", () => {
    void setDefaultKind(defaultBox.checked ? options.kind : "smart");
  });

  const refresh = async (): Promise<void> => {
    try {
      current = await generate(options, o.host, o.rules);
    } catch (e) {
      o.say(why(e));
      return;
    }
    value.replaceChildren(colored(current.value));
    meter.replaceChildren(strengthMeter(current));
    const text = rulesNote(current);
    note.textContent = text ?? "";
    note.hidden = text === undefined;
    o.resized();
  };

  const paintOptions = (): void => {
    const set = (patch: Partial<GeneratorOptions>): void => {
      Object.assign(options, patch);
      paintOptions();
      void refresh();
    };
    const rows: HTMLElement[] = [];
    if (options.kind === "random") {
      rows.push(
        stepper("gen_length", options.length, LIMITS.length, (n) => {
          set({ length: n });
        }),
        toggle("gen_digits", options.digits, (on) => {
          set({ digits: on });
        }),
        toggle("gen_symbols", options.symbols, (on) => {
          set({ symbols: on });
        }),
      );
    } else if (options.kind === "memorable") {
      rows.push(
        stepper("gen_words", options.words, LIMITS.words, (n) => {
          set({ words: n });
        }),
      );
    } else if (options.kind === "pin") {
      rows.push(
        stepper("gen_digits", options.pin_length, LIMITS.pin_length, (n) => {
          set({ pin_length: n });
        }),
      );
    }
    opts.replaceChildren(...rows);
    opts.hidden = rows.length === 0;
  };

  const paintTabs = (): void => {
    tabs.replaceChildren(
      ...KINDS.map((kind) => {
        const on = kind === options.kind;
        const tab = h("button", { class: on ? "gen-kind is-on" : "gen-kind", type: "button", role: "radio", "aria-checked": on ? "true" : "false", "data-kind": kind }, t(KIND_NAME[kind]));
        tab.addEventListener("click", () => {
          if (options.kind === kind) return;
          options.kind = kind;
          void defaultKind().then((d) => {
            defaultBox.checked = d === kind;
          });
          paintTabs();
          paintOptions();
          void refresh();
        });
        return tab;
      }),
    );
  };

  /** Keeps it in the history first; `then` only runs if that worked, unless `anyway`. */
  const kept = async (then: (v: string) => Promise<void>, anyway: boolean): Promise<void> => {
    if (!current || busy) return;
    busy = true;
    const v = current.value;
    try {
      try {
        await record(v, o.host);
      } catch (e) {
        o.say(t("gen_not_kept", why(e)));
        if (!anyway) return;
      }
      await then(v);
    } finally {
      busy = false;
    }
  };

  const allowed = (event: Event): boolean => !o.guard || o.guard(event);
  copyButton.addEventListener("click", (event) => {
    if (!allowed(event)) return;
    void kept(o.copy, true);
  });
  again.addEventListener("click", () => {
    void refresh();
  });

  const historyButton = o.historyIn
    ? h("button", { class: "btn-link gen-history-link", type: "button", "aria-label": t("gen_history") }, t("gen_history_short"))
    : h("button", { class: "btn-link gen-history-link", type: "button" }, t("gen_history"));
  historyButton.addEventListener("click", o.history);

  let use: HTMLButtonElement | null = null;
  if (o.use) {
    const fill = o.use;
    use = h("button", { class: "btn btn-primary btn-use", type: "button" }, t("use_this_password"));
    const button = use;
    button.addEventListener("click", (event) => {
      if (!allowed(event)) return;
      button.disabled = true;
      void kept(fill, false).finally(() => {
        button.disabled = false;
      });
    });
  }

  defaultBox.checked = options.kind === (await defaultKind());
  paintTabs();
  paintOptions();
  root.append(
    tabs,
    h("div", { class: "gen-row" }, value, h("div", { class: "gen-actions" }, copyButton, again)),
    meter,
    note,
    opts,
    ...(use ? [use] : []),
    h("div", { class: "gen-foot" }, h("label", { class: "opt opt-check" }, defaultBox, h("span", {}, t("gen_default"))), o.historyIn ? null : historyButton),
  );
  o.historyIn?.replaceChildren(historyButton);
  await refresh();
  return root;
}

function when(ms: number): string {
  return new Intl.DateTimeFormat(locale(), { dateStyle: "medium", timeStyle: "short" }).format(new Date(ms));
}

export interface HistoryOptions {
  say: (text: string, tone?: "error" | "info") => void;
  resized: () => void;
  copy: (value: string) => Promise<void>;
  back: () => void;
  /**
   * Whether a click counts: in a page, only the person's own on a frame
   * nothing covers (`personClicked`, T62); in the popup, a trusted one.
   */
  guard: (event: Event) => boolean;
}

/** The generator history: newest first, values only on «Copiar». */
export async function historyPanel(o: HistoryOptions): Promise<HTMLElement> {
  const back = h("button", { class: "back", type: "button" }, icon("back"), t("gen_title"));
  back.addEventListener("click", o.back);
  const list = h("div", { class: "list gen-list" });
  const root = h("section", { class: "gen gen-hist", "aria-label": t("gen_history") }, h("div", { class: "gen-hist-head" }, back), list);
  let entries: GeneratedView[];
  try {
    entries = await daemon<GeneratedView[]>({ op: "generator_history" });
  } catch (e) {
    o.say(why(e));
    return root;
  }
  if (entries.length === 0) {
    list.append(h("p", { class: "empty" }, t("gen_history_empty")));
    return root;
  }
  for (const e of entries) {
    const sub = [when(e.created_at), e.saved_in_title ? t("gen_history_saved_in", e.saved_in_title) : null, e.pending ? t("gen_history_pending") : null].filter(Boolean).join(" · ");
    const copy = iconButton("copy", t("gen_copy_entry", when(e.created_at)), (event) => {
      if (!o.guard(event)) return;
      void gated<string>({ op: "generated_value", created_at: e.created_at }).then(o.copy, (err: unknown) => {
        o.say(why(err));
      });
    });
    list.append(
      h(
        "div",
        { class: "gen-entry" },
        h("span", { class: "row-main" }, h("span", { class: "row-title" }, e.host ?? t("gen_history_no_site")), h("span", { class: "row-sub" }, sub)),
        copy,
      ),
    );
  }
  // «Borrar el historial» asks first: it also purges the versions kept in klavd.
  const foot = h("div", { class: "gen-foot" });
  const clearAll = h("button", { class: "btn-link gen-history-clear", type: "button" }, t("gen_history_clear"));
  const ask = (): void => {
    const sure = h("button", { class: "btn btn-danger btn-s", type: "button" }, t("gen_history_clear_yes"));
    const keep = h("button", { class: "btn btn-s", type: "button" }, t("gen_history_clear_keep"));
    keep.addEventListener("click", (event) => {
      if (!o.guard(event)) return;
      foot.replaceChildren(clearAll);
      o.resized();
    });
    sure.addEventListener("click", (event) => {
      if (!o.guard(event)) return;
      sure.disabled = true;
      void daemon({ op: "generator_delete", which: "all" }).then(
        () => {
          list.replaceChildren(h("p", { class: "empty" }, t("gen_history_cleared")));
          foot.remove();
          o.resized();
        },
        (err: unknown) => {
          sure.disabled = false;
          o.say(why(err));
        },
      );
    });
    foot.replaceChildren(h("p", { class: "sub gen-history-sure", role: "alert" }, t("gen_history_clear_sure")), h("div", { class: "gen-actions" }, sure, keep));
    o.resized();
  };
  clearAll.addEventListener("click", (event) => {
    if (o.guard(event)) ask();
  });
  foot.append(clearAll);
  root.append(foot);
  return root;
}
