/**
 * Klav's ordered dither (docs/diseno-visual §3): a field is a function
 * `(u, v) → brightness 0…1` spread over a palette of 2 or 3 colours with
 * an 8×8 Bayer matrix. Locked or hidden things look like pixel noise; when
 * they open, the threshold rises and they dissolve into something sharp.
 *
 * The pixel maths is pure (tested in jsdom); `paint` puts it on a canvas.
 */

/** The 8×8 Bayer matrix (each value 0…63 once). */
export const BAYER: readonly (readonly number[])[] = [
  [0, 32, 8, 40, 2, 34, 10, 42],
  [48, 16, 56, 24, 50, 18, 58, 26],
  [12, 44, 4, 36, 14, 46, 6, 38],
  [60, 28, 52, 20, 62, 30, 54, 22],
  [3, 35, 11, 43, 1, 33, 9, 41],
  [51, 19, 59, 27, 49, 17, 57, 25],
  [15, 47, 7, 39, 13, 45, 5, 37],
  [63, 31, 55, 23, 61, 29, 53, 21],
];

/** The threshold of pixel (x, y), in (0, 1). */
export function threshold(x: number, y: number): number {
  return ((BAYER[y & 7]?.[x & 7] ?? 0) + 0.5) / 64;
}

/** The palette index for brightness `b` (0…1) over `n` colours at threshold `th`. */
export function pick(b: number, n: number, th: number): number {
  const steps = n - 1;
  const s = Math.min(1, Math.max(0, b)) * steps;
  const i = Math.min(steps - 1, Math.floor(s));
  return s - i > th ? i + 1 : i;
}

/** A brightness field over the unit square; `aspect` is width / height. */
export type Field = (u: number, v: number, aspect: number) => number;

// ---------------------------------------------------------------- noise --

function hash(x: number, y: number, seed: number): number {
  let h = (x * 374761393 + y * 668265263 + seed * 2147483647) | 0;
  h = Math.imul(h ^ (h >>> 13), 1274126177);
  return ((h ^ (h >>> 16)) >>> 0) / 4294967295;
}

/** Smooth value noise in 0…1 (deterministic: the same picture every time). */
export function valueNoise(x: number, y: number, seed = 7): number {
  const xi = Math.floor(x);
  const yi = Math.floor(y);
  const fx = x - xi;
  const fy = y - yi;
  const sx = fx * fx * (3 - 2 * fx);
  const sy = fy * fy * (3 - 2 * fy);
  const a = hash(xi, yi, seed);
  const b = hash(xi + 1, yi, seed);
  const c = hash(xi, yi + 1, seed);
  const d = hash(xi + 1, yi + 1, seed);
  return a + (b - a) * sx + (c - a) * sy + (a - b - c + d) * sx * sy;
}

/** Horizontal streaks: noise stretched along x. */
function streaks(u: number, v: number, aspect: number, rows: number): number {
  return valueNoise(u * aspect * 2.2, v * rows) * 0.65 + valueNoise(u * aspect * 9, v * rows * 2, 11) * 0.35;
}

const clamp = (n: number): number => Math.min(1, Math.max(0, n));

// --------------------------------------------------------------- fields --

/**
 * Distance (in units of the field's height) from (x, y) to a keyhole
 * centred at (cx, cy): a circle and a slot that widens downwards. Negative
 * inside.
 */
export function keyholeDistance(x: number, y: number, cx: number, cy: number, r: number): number {
  const circle = Math.hypot(x - cx, y - cy) - r;
  // The slot: from the circle's centre down to 2.6 r, half-width 0.42 r → 0.78 r.
  const top = cy;
  const bottom = cy + r * 2.6;
  const t = clamp((y - top) / (bottom - top));
  const half = r * (0.42 + 0.36 * t);
  const dx = Math.abs(x - cx) - half;
  const dy = Math.max(top - y, y - bottom);
  const slot = Math.max(dx, dy);
  return Math.min(circle, slot);
}

/**
 * The lock screen: a keyhole of light with an exponential glow, over a
 * navy ground that lightens downwards with horizontal streaks.
 * `open` (0…1) floods the field with the keyhole's light (unlocking).
 */
export function keyhole(open = 0): Field {
  return (u, v, aspect) => {
    const x = u * aspect;
    const cx = aspect / 2;
    const d = keyholeDistance(x, v, cx, 0.36, 0.13);
    if (d <= 0) return 1;
    const glow = Math.exp(-d * 16) * 0.75;
    const ground = 0.12 + v * 0.42 + (streaks(u, v, aspect, 34) - 0.5) * 0.5;
    // A few bright rows near the bottom, like the mockup.
    const sparks = v > 0.72 ? Math.max(0, valueNoise(u * aspect * 5, v * 60, 3) - 0.78) * 2.4 : 0;
    const base = clamp(Math.max(ground + sparks, glow + ground * 0.4));
    if (open <= 0) return base;
    // The light spreads from the keyhole outwards and rises everywhere.
    const reach = open * 1.6 - d * 1.2;
    return clamp(base + Math.max(0, reach) + open * open * 0.9);
  };
}

/** Agents' requests and notices: a vertical gradient with streaks. */
export function band(): Field {
  return (u, v, aspect) => clamp(0.08 + v * 0.95 + (streaks(u, v, aspect, 22) - 0.5) * 0.45);
}

/** A hidden secret: two light greys of noise on paper (instead of ••••). */
export function mask(): Field {
  return (u, v, aspect) => clamp(valueNoise(u * aspect * 6, v * 3, 5) * 0.55 + valueNoise(u * aspect * 24, v * 9, 9) * 0.45);
}

// --------------------------------------------------------------- pixels --

/** An RGB colour. */
export type Rgb = readonly [number, number, number];

/** `#rrggbb` (or `#rgb`) as RGB; black if it cannot be read. */
export function parseHex(hex: string): Rgb {
  const h = hex.trim().replace(/^#/, "");
  const full = h.length === 3 ? h.replace(/./g, "$&$&") : h;
  const n = Number.parseInt(full, 16);
  if (full.length !== 6 || Number.isNaN(n)) return [0, 0, 0];
  return [(n >> 16) & 255, (n >> 8) & 255, n & 255];
}

/**
 * The RGBA pixels of `field` at `width`×`height` dither pixels. `reveal`
 * (0…1) makes pixels transparent once their threshold is below it: the
 * mask dissolving into the text under it.
 */
export function ditherPixels(width: number, height: number, field: Field, palette: readonly Rgb[], reveal = 0): Uint8ClampedArray {
  const out = new Uint8ClampedArray(width * height * 4);
  const aspect = width / Math.max(1, height);
  for (let y = 0; y < height; y++) {
    const v = height > 1 ? y / (height - 1) : 0;
    for (let x = 0; x < width; x++) {
      const th = threshold(x, y);
      const o = (y * width + x) * 4;
      if (reveal > 0 && th < reveal) continue; // transparent
      const u = width > 1 ? x / (width - 1) : 0;
      const colour = palette[pick(field(u, v, aspect), palette.length, th)] ?? [0, 0, 0];
      out[o] = colour[0];
      out[o + 1] = colour[1];
      out[o + 2] = colour[2];
      out[o + 3] = 255;
    }
  }
  return out;
}

// --------------------------------------------------------------- canvas --

/** CSS custom properties of each palette (klav.css defines them per scheme). */
export const PALETTES = {
  blue: ["--dither-0", "--dither-1", "--dither-2"],
  mask: ["--mask-0", "--mask-1", "--mask-2"],
} as const;

/** Reads a palette from the CSS of `el` (light or dark, as the system says). */
export function paletteOf(el: Element, name: keyof typeof PALETTES): Rgb[] {
  const style = getComputedStyle(el);
  return PALETTES[name].map((prop) => parseHex(style.getPropertyValue(prop)));
}

export interface PaintOptions {
  /** Size of one dither pixel in CSS pixels (2 in the popup). */
  pixel?: number;
  palette: readonly Rgb[];
  reveal?: number;
}

/** Draws `field` on `canvas`, filling its CSS box with `pixel`-sized dots. */
export function paint(canvas: HTMLCanvasElement, field: Field, options: PaintOptions): void {
  const pixel = options.pixel ?? 2;
  const rect = canvas.getBoundingClientRect();
  const width = Math.max(1, Math.round((rect.width || canvas.clientWidth || 1) / pixel));
  const height = Math.max(1, Math.round((rect.height || canvas.clientHeight || 1) / pixel));
  if (canvas.width !== width) canvas.width = width;
  if (canvas.height !== height) canvas.height = height;
  const ctx = canvas.getContext("2d");
  if (!ctx) return;
  const image = ctx.createImageData(width, height);
  image.data.set(ditherPixels(width, height, field, options.palette, options.reveal ?? 0));
  ctx.putImageData(image, 0, 0);
}

/** Whether the person asked the system for less motion. */
export function reducedMotion(): boolean {
  return typeof matchMedia === "function" && matchMedia("(prefers-reduced-motion: reduce)").matches;
}

/**
 * Runs `frame(t)` with t from 0 to 1 over `ms` (in steps: dither moves by
 * thresholds, not smoothly). With reduced motion, only the last frame.
 */
export function animate(ms: number, frame: (t: number) => void): Promise<void> {
  if (reducedMotion() || ms <= 0) {
    frame(1);
    return Promise.resolve();
  }
  return new Promise((done) => {
    const start = performance.now();
    const step = (now: number): void => {
      const t = Math.min(1, (now - start) / ms);
      frame(t);
      if (t < 1) requestAnimationFrame(step);
      else done();
    };
    requestAnimationFrame(step);
  });
}

/**
 * A canvas that keeps `field` painted with a palette from the CSS, and
 * repaints when the system switches between light and dark.
 */
export function ditherCanvas(
  doc: Document,
  field: Field,
  options: { palette: keyof typeof PALETTES; pixel?: number; className?: string },
): { canvas: HTMLCanvasElement; repaint: (next?: Field, reveal?: number) => void } {
  const canvas = doc.createElement("canvas");
  canvas.className = `dither ${options.className ?? ""}`.trim();
  canvas.setAttribute("aria-hidden", "true");
  let current = field;
  let reveal = 0;
  const repaint = (next?: Field, nextReveal?: number): void => {
    if (next) current = next;
    if (nextReveal !== undefined) reveal = nextReveal;
    if (!canvas.isConnected) return;
    paint(canvas, current, { palette: paletteOf(canvas, options.palette), pixel: options.pixel ?? 2, reveal });
  };
  const scheme = typeof matchMedia === "function" ? matchMedia("(prefers-color-scheme: dark)") : undefined;
  scheme?.addEventListener("change", () => {
    repaint();
  });
  if (typeof ResizeObserver === "function") {
    new ResizeObserver(() => {
      repaint();
    }).observe(canvas);
  }
  return { canvas, repaint };
}
