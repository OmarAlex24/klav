import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { licenseProblem, normalize, serialize } from "../../../scripts/site-icons.mjs";
import { logoFor, siteHost } from "../src/ui/siteicon";

interface IconMap {
  source: string;
  viewBox: number;
  icons: { slug: string; title: string; domains: string[]; path: string }[];
}
const map = JSON.parse(readFileSync(join(import.meta.dirname, "..", "..", "..", "assets", "site-icons", "site-icons.json"), "utf8")) as IconMap;

describe("site icons map", () => {
  it("is Simple Icons on a 24 grid, with each domain once", () => {
    expect(map.source).toMatch(/^simple-icons \d+\.\d+\.\d+ \(CC0-1\.0/);
    expect(map.viewBox).toBe(24);
    expect(map.icons.length).toBeGreaterThan(200);
    const domains = map.icons.flatMap((i) => i.domains);
    expect(new Set(domains).size).toBe(domains.length);
  });

  it("uses only absolute M, L, C, Q and Z (what the iOS app draws)", () => {
    for (const icon of map.icons) {
      expect(icon.path, icon.slug).toMatch(/^M[-\d. MLCQZ]+$/);
    }
  });
});

describe("logoFor and siteHost", () => {
  const logos = new Map(map.icons.flatMap((i) => i.domains.map((d) => [d, i.path] as const)));

  it("finds a site's logo, or its parent domain's", () => {
    expect(logoFor(logos, "github.com")).toBeDefined();
    expect(logoFor(logos, "gist.github.com")).toBe(logoFor(logos, "github.com"));
    expect(logoFor(logos, "github.com.evil.example")).toBeUndefined();
    expect(logoFor(logos, "evilgithub.com")).toBeUndefined();
    expect(logoFor(logos, "localhost")).toBeUndefined();
  });

  it("reads hosts from URLs and bare hosts, without www.", () => {
    expect(siteHost("https://www.GitHub.com/login?x=1")).toBe("github.com");
    expect(siteHost("github.com")).toBe("github.com");
    expect(siteHost("http://localhost:8443/")).toBe("localhost");
    expect(siteHost("not a url")).toBeUndefined();
  });
});

describe("path normalisation (scripts/site-icons.mjs)", () => {
  it("makes everything absolute and expands shorthands", () => {
    expect(serialize(normalize("m1 2h3v4H0Zl1 1"))).toBe("M1 2L4 2L4 6L0 6ZL2 3");
    expect(serialize(normalize("M0 0c1 1 2 1 3 0s2-1 3 0"))).toBe("M0 0C1 1 2 1 3 0C4-1 5-1 6 0");
    expect(serialize(normalize("M0 0q1 1 2 0t2 0"))).toBe("M0 0Q1 1 2 0Q3-1 4 0");
  });

  it("reads arc flags that touch the next number, and turns arcs into curves", () => {
    const cmds = normalize("M0 1a1 1 0 00 1 1");
    expect(cmds.map((c) => c[0])).toEqual(["M", "C"]);
    expect(cmds[1]?.slice(-2)).toEqual([1, 2]);
    // A half circle of radius 1 from (-1,0) to (1,0) through (0,-1).
    const half = normalize("M-1 0A1 1 0 0 1 1 0");
    expect(half.length).toBe(3);
    // (-0 rounds to -0: add 0 so it compares equal to 0)
    expect(half[1]?.slice(5, 7).map((v) => Math.round(Number(v) * 1000) / 1000 + 0)).toEqual([0, -1]);
  });

  it("writes the shortest form at two decimals", () => {
    expect(serialize([["M", 0.5, -0.25], ["L", 12.004, 3.999], ["Z"]])).toBe("M.5-.25L12 4Z");
    expect(serialize([["M", 1.5, 0.5]])).toBe("M1.5.5");
  });
});

describe("license gate (scripts/site-icons.mjs)", () => {
  it("ships an icon with no license data or CC0-1.0", () => {
    expect(licenseProblem("github", { title: "GitHub" })).toBeUndefined();
    expect(licenseProblem("x", { title: "X", license: { type: "CC0-1.0" } })).toBeUndefined();
  });

  it("refuses any other license, naming the icon and the license", () => {
    expect(licenseProblem("vivaldi", { title: "Vivaldi", license: { type: "CC-BY-4.0" } })).toBe("vivaldi (Vivaldi): license CC-BY-4.0, not CC0-1.0");
    expect(licenseProblem("letsencrypt", { title: "Let's Encrypt", license: { type: "CC-BY-NC-4.0" } })).toMatch(/^letsencrypt .*CC-BY-NC-4\.0/);
    expect(licenseProblem("gnuprivacyguard", { title: "GnuPG", license: { type: "GPL-3.0-or-later" } })).toMatch(/GPL-3\.0-or-later/);
  });

  it("fails closed on an unknown shape or a slug missing from the data", () => {
    expect(licenseProblem("a", { title: "A", license: { type: "custom", url: "https://example.com" } })).toMatch(/custom/);
    expect(licenseProblem("b", { title: "B", license: "CC0-1.0" })).toMatch(/not CC0-1\.0/);
    expect(licenseProblem("c", { title: "C", license: null })).toMatch(/null/);
    expect(licenseProblem("d", undefined)).toBe("d: not in data/simple-icons.json");
  });
});

describe("site icons map licenses", () => {
  it("leaves out the icons Simple Icons licenses other than CC0", () => {
    const slugs = new Set(map.icons.map((i) => i.slug));
    for (const slug of ["gnuprivacyguard", "letsencrypt", "vivaldi"]) expect(slugs.has(slug), slug).toBe(false);
  });
});
