import { describe, expect, it } from "vitest";
import { FILTERS, filterLabel, isFilter, ofKind, tabs } from "../src/ui/filters";
import { t } from "../src/shared/i18n";
import type { ItemKind, ItemSummary } from "../src/shared/protocol";
import { useLocale } from "./setup";

let next = 0;
function item(kind: ItemKind, title = `${kind} ${String(next++)}`): ItemSummary {
  return {
    id: `id-${String(next++)}`,
    reference: `klav://Personal/General/${title}`,
    vault_id: "v",
    vault: "Personal",
    project_id: "p",
    project: "General",
    kind,
    title,
    urls: [],
    tags: [],
    version: 1,
    updated_at: 0,
    trashed: false,
  };
}

const vault = [item("login"), item("login"), item("login"), item("card"), item("note"), item("totp"), item("ssh_key")];

describe("tabs", () => {
  it("count each type, in a fixed order, and leave out the empty ones", () => {
    expect(tabs(vault, 2, "all")).toEqual([
      { filter: "all", count: 7 },
      { filter: "login", count: 3 },
      { filter: "codes", count: 2 },
      { filter: "card", count: 1 },
      { filter: "note", count: 1 },
      { filter: "ssh_key", count: 1 },
    ]);
  });

  it("show «Codes» without a count until klavd answers, and hide it with none", () => {
    expect(tabs(vault, undefined, "all").map((t) => t.filter)).not.toContain("codes");
    expect(tabs(vault, 0, "all").map((t) => t.filter)).not.toContain("codes");
    expect(tabs(vault, undefined, "codes").find((t) => t.filter === "codes")).toEqual({ filter: "codes" });
  });

  it("keep the chosen tab when a search empties it", () => {
    const found = [item("login")];
    expect(tabs(found, 0, "card")).toEqual([
      { filter: "all", count: 1 },
      { filter: "login", count: 1 },
      { filter: "card", count: 0 },
    ]);
  });

  it("are not drawn for a vault of one type without codes", () => {
    expect(tabs([item("login"), item("login")], 0, "all")).toEqual([]);
    expect(tabs([], undefined, "all")).toEqual([]);
    // Two types are worth a choice.
    expect(tabs([item("login"), item("note")], 0, "all")).toHaveLength(3);
  });

  it("give standalone codes no tab of their own: they are «Codes»", () => {
    expect(tabs([item("totp"), item("totp"), item("login")], 2, "all").map((t) => t.filter)).toEqual(["all", "login", "codes"]);
  });
});

describe("ofKind", () => {
  it("keeps one type, or everything", () => {
    expect(ofKind(vault, "login")).toHaveLength(3);
    expect(ofKind(vault, "api_key")).toEqual([]);
    expect(ofKind(vault, "all")).toEqual(vault);
  });
});

describe("labels", () => {
  it("name every tab in both languages", () => {
    for (const filter of FILTERS) expect(t(filterLabel(filter))).not.toBe(filterLabel(filter));
    expect(t(filterLabel("codes"))).toBe("Codes");
    useLocale("es");
    expect(t(filterLabel("codes"))).toBe("Códigos");
    expect(t(filterLabel("ssh_key"))).toBe("Llaves SSH");
    useLocale("en");
  });

  it("knows its filters", () => {
    expect(isFilter("codes")).toBe(true);
    expect(isFilter("totp")).toBe(false);
    expect(isFilter(undefined)).toBe(false);
  });
});
