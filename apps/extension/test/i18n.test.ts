import { readFileSync } from "node:fs";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { formatNumber, plural, t } from "../src/shared/i18n";
import { useLocale } from "./setup";

type Catalog = Record<string, { message: string; description?: string }>;
const read = (lang: string): Catalog =>
  JSON.parse(readFileSync(join(import.meta.dirname, "..", "_locales", lang, "messages.json"), "utf8")) as Catalog;
const en = read("en");
const es = read("es");
const placeholders = (text: string): string[] => [...new Set(text.match(/\$\d/g) ?? [])].sort();

afterEach(() => {
  useLocale("en");
});

describe("catalogs", () => {
  it("have the same keys in English and Spanish", () => {
    expect(Object.keys(es).sort()).toEqual(Object.keys(en).sort());
  });

  it("use the same $n substitutions in both languages", () => {
    for (const [key, { message }] of Object.entries(en)) {
      expect(placeholders(es[key]?.message ?? ""), key).toEqual(placeholders(message));
    }
  });

  it("have valid keys and no empty message", () => {
    for (const [key, { message }] of [...Object.entries(en), ...Object.entries(es)]) {
      expect(key).toMatch(/^[A-Za-z0-9_]+$/);
      expect(message.trim(), key).not.toBe("");
    }
  });

  it("name their own language", () => {
    expect(en.locale?.message).toBe("en");
    expect(es.locale?.message).toBe("es");
  });
});

describe("t, plural and numbers", () => {
  it("fills substitutions, in each language", () => {
    expect(t("fill_on_host", "github.com")).toBe("Fill on github.com");
    useLocale("es");
    expect(t("fill_on_host", "github.com")).toBe("Rellenar en github.com");
  });

  it("picks the plural form with Intl", () => {
    expect(plural("other_accounts", 1)).toBe("Another account");
    expect(plural("other_accounts", 3)).toBe("3 other accounts");
    useLocale("es");
    expect(plural("other_accounts", 1)).toBe("Otra cuenta");
    expect(plural("other_accounts", 2)).toBe("Otras 2 cuentas");
    expect(plural("sites", 2)).toBe("Sitios");
  });

  it("formats numbers in the catalog's language", () => {
    expect(formatNumber(12345)).toBe("12,345");
    useLocale("es");
    expect(formatNumber(12345)).toBe("12.345");
  });
});
