// The extension's site rule is klav-core's, compiled to WebAssembly: these
// cases must give the same answers as `klav_core::site` in Rust.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { beforeAll, describe, expect, it } from "vitest";
import { fillableHost, generate, hostMatches, hostRelation, initSync, pageMatches, totpCheck } from "../src/wasm-gen/klav_wasm";

beforeAll(() => {
  initSync({ module: readFileSync(join(import.meta.dirname, "..", "src", "wasm-gen", "klav_wasm_bg.wasm")) });
});

describe("site rule (klav-core via WASM)", () => {
  it("fills only the item's host and its subdomains", () => {
    const urls = ["https://github.com/login", "example.org"];
    expect(hostMatches("github.com", urls)).toBe(true);
    expect(hostMatches("gist.github.com", urls)).toBe(true);
    expect(hostMatches("example.org", urls)).toBe(true);
    expect(hostMatches("github.com.evil.io", urls)).toBe(false);
    expect(hostMatches("evilgithub.com", urls)).toBe(false);
    expect(hostMatches("github.co", urls)).toBe(false);
    expect(hostMatches("github.com", [])).toBe(false);
  });

  it("only https pages, or http on this machine", () => {
    expect(fillableHost("https://GitHub.com/x")).toBe("github.com");
    expect(fillableHost("http://127.0.0.1:8080/")).toBe("127.0.0.1");
    expect(fillableHost("http://localhost:3000/")).toBe("localhost");
    expect(fillableHost("http://github.com/")).toBeUndefined();
    expect(fillableHost("file:///etc/passwd")).toBeUndefined();
    expect(fillableHost("https://github.com@evil.io/")).toBe("evil.io");
  });

  it("compares look-alikes in punycode and IPs exactly", () => {
    expect(pageMatches("https://gіthub.com/", ["https://github.com"])).toBe(false);
    expect(pageMatches("http://127.0.0.1:4000/login", ["http://localhost:4000"])).toBe(false);
    expect(pageMatches("http://localhost:4000/login", ["http://localhost:4000"])).toBe(true);
    expect(pageMatches("https://login.example.com/", ["https://www.example.com"])).toBe(true);
    expect(pageMatches("https://mail.example.com/", ["https://accounts.example.com"])).toBe(false);
  });
});

describe("relation to the page (ADR 0025)", () => {
  it("tells exact, subdomain and parent apart; parent never matches", () => {
    const my = ["https://my.1password.com/signin"];
    expect(hostRelation("my.1password.com", my)).toBe("exact");
    expect(hostRelation("a.my.1password.com", my)).toBe("subdomain");
    expect(hostRelation("1password.com", my)).toBe("parent");
    expect(hostMatches("1password.com", my)).toBe(false);
    expect(pageMatches("https://1password.com/", my)).toBe(false);
    expect(hostRelation("com", my)).toBeUndefined();
    expect(hostRelation("start.1password.com", my)).toBeUndefined();
    expect(hostRelation("mail.example.com", ["https://accounts.example.com"])).toBeUndefined();
  });

  it("takes the best relation over all of an item's URLs", () => {
    expect(hostRelation("1password.com", ["https://my.1password.com", "https://1password.com"])).toBe("exact");
  });
});

describe("generator (klav-core via WASM)", () => {
  const make = (options: object, site: object = {}): { value: string; kind: string; strength: string; rules: { source: string; domain?: string } | null; fallback: string | null } =>
    JSON.parse(generate(JSON.stringify(options), JSON.stringify(site))) as never;

  it("makes each type with its size", () => {
    const a = make({});
    expect(a.value).toHaveLength(20);
    expect(a.value).not.toBe(make({}).value);
    expect(a.strength).toBe("very_strong");
    expect(make({ kind: "random", length: 32, symbols: false }).value).toMatch(/^[A-Za-z0-9]{32}$/);
    // Four words; a word such as `drop-down` brings a hyphen of its own.
    expect(make({ kind: "memorable", words: 4 }).value).toMatch(/^[A-Za-z0-9]+(-[A-Za-z0-9]+){3,7}$/);
    expect(make({ kind: "pin", pin_length: 8 }).value).toMatch(/^\d{8}$/);
    expect(() => make({ kind: "pin", pin_length: 2 })).toThrow();
    expect(() => make({ nope: 1 })).toThrow();
  });

  it("follows the field's rules, then the site's bundled ones", () => {
    const field = make({}, { password_rules: "minlength: 6; maxlength: 6; allowed: digit;" });
    expect(field.value).toMatch(/^\d{6}$/);
    expect(field.rules?.source).toBe("field");
    const bundled = make({}, { host: "all.accor.com" });
    expect(bundled.rules).toEqual({ source: "bundled", domain: "accor.com" });
    expect(make({}, { password_rules: "required: nonsense" }).fallback).toBe("unreadable");
  });
});

describe("one-time code keys (klav-core via WASM)", () => {
  it("reads a bare key and an otpauth:// link, and never answers with the secret", () => {
    expect(JSON.parse(totpCheck("jbsw y3dp-ehpk 3pxp"))).toEqual({ digits: 6, period: 30 });
    const uri = "otpauth://totp/ACME:ana%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=ACME&digits=8&period=60";
    const out = totpCheck(uri);
    expect(out).not.toContain("JBSWY3DPEHPK3PXP");
    expect(JSON.parse(out)).toEqual({ issuer: "ACME", account: "ana@example.com", digits: 8, period: 60 });
  });

  it("refuses what is not a key", () => {
    expect(() => totpCheck("")).toThrow();
    expect(() => totpCheck("not base32!")).toThrow();
    expect(() => totpCheck("otpauth://hotp/A?secret=JBSWY3DPEHPK3PXP&counter=1")).toThrow();
  });
});
