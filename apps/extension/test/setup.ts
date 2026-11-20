/**
 * `chrome.i18n` for unit tests: reads the catalogs in `_locales`, English
 * unless a test calls `useLocale("es")`.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";

type Catalog = Record<string, { message: string }>;
const catalogs: Record<string, Catalog> = {};
let current = "en";

function catalog(lang: string): Catalog {
  catalogs[lang] ??= JSON.parse(readFileSync(join(import.meta.dirname, "..", "_locales", lang, "messages.json"), "utf8")) as Catalog;
  return catalogs[lang];
}

export function useLocale(lang: string): void {
  current = lang;
}

(globalThis as unknown as { chrome: unknown }).chrome = {
  i18n: {
    getMessage(key: string, subs?: string | string[]): string {
      const list = typeof subs === "string" ? [subs] : (subs ?? []);
      const text = catalog(current)[key]?.message ?? "";
      return text.replace(/\$(\d)/g, (_, n: string) => list[Number(n) - 1] ?? "").replace(/\$\$/g, "$");
    },
  },
};
