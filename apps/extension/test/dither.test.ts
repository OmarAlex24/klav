// @vitest-environment jsdom
import { describe, expect, it } from "vitest";
import { band, BAYER, ditherPixels, keyhole, keyholeDistance, mask, parseHex, pick, threshold, valueNoise } from "../src/shared/dither";
import { buildGlyph, KEY, keyCells } from "../src/shared/glyph";

describe("ordered dither", () => {
  it("uses each Bayer value once", () => {
    expect([...BAYER.flat()].sort((a, b) => a - b)).toEqual(Array.from({ length: 64 }, (_, i) => i));
    expect(threshold(0, 0)).toBeCloseTo(0.5 / 64);
    expect(threshold(8, 8)).toBe(threshold(0, 0));
  });

  it("picks the palette colour as the spec's function does", () => {
    // Two colours: brighter than the threshold → the second.
    expect(pick(0.3, 2, 0.5)).toBe(0);
    expect(pick(0.7, 2, 0.5)).toBe(1);
    // Three colours: 0.5 is exactly the middle one; 1 is always the last.
    expect(pick(0.5, 3, 0.01)).toBe(1);
    expect(pick(1, 3, 0.99)).toBe(2);
    expect(pick(0, 3, 0.01)).toBe(0);
    expect(pick(0.75, 3, 0.4)).toBe(2);
    expect(pick(0.75, 3, 0.6)).toBe(1);
  });

  it("mixes colours in proportion to the brightness", () => {
    const pixels = ditherPixels(64, 64, () => 0.25, [parseHex("#000"), parseHex("#fff")]);
    let white = 0;
    for (let i = 0; i < pixels.length; i += 4) if (pixels[i] === 255) white++;
    expect(white / (64 * 64)).toBeCloseTo(0.25, 2);
  });

  it("leaves pixels transparent below the reveal threshold", () => {
    const half = ditherPixels(8, 8, () => 1, [parseHex("#000"), parseHex("#fff")], 0.5);
    let clear = 0;
    for (let i = 3; i < half.length; i += 4) if (half[i] === 0) clear++;
    expect(clear).toBe(32);
    const all = ditherPixels(8, 8, () => 1, [parseHex("#000"), parseHex("#fff")], 1);
    expect(all.every((v) => v === 0)).toBe(true);
  });

  it("reads colours", () => {
    expect(parseHex("#2337FF")).toEqual([0x23, 0x37, 0xff]);
    expect(parseHex(" #fff ")).toEqual([255, 255, 255]);
    expect(parseHex("nope")).toEqual([0, 0, 0]);
  });
});

describe("fields", () => {
  it("stay within 0…1 and are deterministic", () => {
    for (const field of [keyhole(), keyhole(0.5), band(), mask()]) {
      for (let i = 0; i < 200; i++) {
        const u = (i * 37) % 101 / 100;
        const v = (i * 53) % 97 / 96;
        const b = field(u, v, 1.2);
        expect(b).toBeGreaterThanOrEqual(0);
        expect(b).toBeLessThanOrEqual(1);
        expect(field(u, v, 1.2)).toBe(b);
      }
    }
    expect(valueNoise(3.3, 1.7)).toBe(valueNoise(3.3, 1.7));
  });

  it("lights the keyhole and keeps the corners dark", () => {
    const f = keyhole();
    expect(f(0.5, 0.36, 1.2)).toBe(1);
    expect(f(0.5, 0.55, 1.2)).toBe(1); // the slot
    expect(f(0.02, 0.02, 1.2)).toBeLessThan(0.45);
    expect(keyholeDistance(0, 0, 0.5, 0.36, 0.13)).toBeGreaterThan(0);
  });

  it("floods the whole field when it opens", () => {
    const f = keyhole(1);
    expect(f(0.02, 0.02, 1.2)).toBe(1);
    expect(f(0.98, 0.98, 1.2)).toBe(1);
  });

  it("brightens the band downwards", () => {
    const f = band();
    const avg = (v: number): number => Array.from({ length: 50 }, (_, i) => f(i / 49, v, 0.5)).reduce((a, b) => a + b) / 50;
    expect(avg(0.9)).toBeGreaterThan(avg(0.1));
  });
});

describe("glyph", () => {
  it("is an 8×8 key with a ring and teeth", () => {
    expect(KEY).toHaveLength(8);
    expect(KEY.every((row) => row.length === 8)).toBe(true);
    expect(keyCells().length).toBeGreaterThan(10);
    const svg = buildGlyph(document);
    expect(svg.getAttribute("viewBox")).toBe("0 1 8 5");
    expect(svg.querySelector("path")?.getAttribute("fill")).toBe("currentColor");
  });
});
