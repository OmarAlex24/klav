/**
 * Klav's words, from `_locales/<lang>/messages.json`: English by default
 * and Spanish, as the browser's language says (`chrome.i18n`). Numbers and
 * plurals go through `Intl` with the catalog's own language, so a page in
 * Spanish never mixes in an English number format.
 */
import type catalog from "../../_locales/en/messages.json";

export type MessageKey = keyof typeof catalog;
type Sub = string | number;

interface I18n {
  getMessage(key: string, substitutions?: string | string[]): string;
}

function api(): I18n | undefined {
  const g = globalThis as unknown as { browser?: { i18n?: I18n }; chrome?: { i18n?: I18n } };
  return g.browser?.i18n ?? g.chrome?.i18n;
}

/** The message `key` with `$1`…`$9` filled in. A missing key shows itself, never a blank. */
export function t(key: MessageKey, ...subs: Sub[]): string {
  const text = api()?.getMessage(key, subs.map((s) => (typeof s === "number" ? formatNumber(s) : s)));
  return text || key;
}

/** The catalog in use (`en`, `es`): for `Intl` and the pages' `lang`. */
export function locale(): string {
  return api()?.getMessage("locale") || "en";
}

export function formatNumber(n: number): string {
  return new Intl.NumberFormat(locale()).format(n);
}

/** `<base>_one` or `<base>_other` for `n`, with `n` as `$1`. */
export type PluralBase = "other_accounts" | "sites" | "env_variables" | "imp_entries" | "imp_passkeys" | "imp_new" | "imp_merged" | "imp_dupes" | "imp_apply";

export function plural(base: PluralBase, n: number): string {
  const form = new Intl.PluralRules(locale()).select(n) === "one" ? "one" : "other";
  return t(`${base}_${form}`, n);
}

/**
 * A message with nodes in it (a host in bold, a command): the text is
 * split where `$1`…`$9` go and each node takes its place.
 */
export function tNodes(key: MessageKey, ...parts: Node[]): (Node | string)[] {
  const marks = parts.map((_, i) => `${String(i)}`);
  const text = t(key, ...marks);
  const out: (Node | string)[] = [];
  for (const piece of text.split(/(\d+)/)) {
    if (piece === "") continue;
    const at = /^(\d+)$/.exec(piece);
    const node = at ? parts[Number(at[1])] : undefined;
    out.push(node ?? piece);
  }
  return out;
}

/** Sets the page's `lang` and, when given, its title. */
export function localizePage(title?: MessageKey): void {
  document.documentElement.lang = locale();
  if (title) document.title = t(title);
}
