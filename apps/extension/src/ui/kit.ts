/**
 * Small building blocks shared by Klav's pages (klav.css has their
 * styles): line icons, the item tile, the one-time code's time blocks and
 * the field glyph. Everything is built with DOM calls.
 */
import { buildGlyph } from "../shared/glyph";
import { h } from "./dom";
import type { VaultFilter } from "./filters";

const NS = "http://www.w3.org/2000/svg";

/** 16×16 line icons, 1.5 px strokes, square ends. */
const ICONS = {
  copy: "M5.5 5.5h7v7h-7zM3.5 10.5v-7h7",
  close: "M4 4l8 8M12 4l-8 8",
  back: "M10 3.5 5.5 8 10 12.5",
  plus: "M8 3.5v9M3.5 8h9",
  enter: "M12.5 4v4.5h-8M7 6 4.5 8.5 7 11",
  check: "M3.5 8.5 6.5 11.5 12.5 5",
  refresh: "M12.5 8a4.5 4.5 0 1 1-1.32-3.18M12.5 3v2.5H10",
  asterisk: "M8 3v10M3.67 5.5l8.66 5M3.67 10.5l8.66-5",
  search: "M7 3.5a3.5 3.5 0 1 1 0 7 3.5 3.5 0 0 1 0-7zM9.5 10l3 3",
  key: "M5.5 4a2.5 2.5 0 1 1 0 5 2.5 2.5 0 0 1 0-5zM7.3 8.3l5.2 5.2M10.4 11.4l1.6-1.6M11.8 12.8l1.2-1.2",
  pulse: "M2 8.5h3l1.5-3.5 3 7 1.5-3.5h3",
  gear: "M8 5.75a2.25 2.25 0 1 1 0 4.5 2.25 2.25 0 0 1 0-4.5zM8 2v2M8 12v2M2 8h2M12 8h2M3.8 3.8l1.4 1.4M10.8 10.8l1.4 1.4M3.8 12.2l1.4-1.4M10.8 5.2l1.4-1.4",
  // The kinds of items, the same paths as `Icon` in the apps'
  // `Shared/Theme.swift` (docs/diseno-visual §7). A dot is a stroke of
  // almost no length: the square cap draws it.
  grid: "M3.5 3.5h3.5v3.5h-3.5zM9 3.5h3.5v3.5H9zM3.5 9h3.5v3.5h-3.5zM9 9h3.5v3.5H9z",
  field: "M2.5 5h11v6h-11zM5.25 8h.01M8 8h.01M10.75 8h.01",
  timer: "M8 4.5a4.5 4.5 0 1 1 0 9 4.5 4.5 0 0 1 0-9zM8 9V6.75M6.25 2.5h3.5",
  card: "M2.5 4h11v8h-11zM2.5 7h11M5 9.75h2",
  page: "M3.5 2.5h9v11h-9zM6 6h4M6 8.5h4M6 11h2",
  file: "M3.5 2.5H9l3.5 3.5v7.5h-9zM9 2.5V6h3.5",
  braces: "M5.5 3h-1v3.75L3 8l1.5 1.25V13h1M10.5 3h1v3.75L13 8l-1.5 1.25V13h-1",
  prompt: "M3.5 4.5 7 8l-3.5 3.5M8.5 12h4",
  house: "M3 7.5 8 3l5 4.5v6H3z",
} as const;

export type IconName = keyof typeof ICONS;

/** The icon of each type tab, as `VaultFilter.icon` in the iOS app. */
const KIND_ICONS: Record<VaultFilter, IconName> = {
  all: "grid",
  login: "field",
  codes: "timer",
  card: "card",
  note: "page",
  ssh_key: "prompt",
  api_key: "braces",
  identity: "house",
  file: "file",
};

export function kindIcon(filter: VaultFilter): SVGSVGElement {
  return icon(KIND_ICONS[filter]);
}

export function icon(name: IconName): SVGSVGElement {
  const svg = document.createElementNS(NS, "svg");
  svg.setAttribute("viewBox", "0 0 16 16");
  svg.setAttribute("aria-hidden", "true");
  svg.setAttribute("fill", "none");
  const path = document.createElementNS(NS, "path");
  path.setAttribute("d", ICONS[name]);
  path.setAttribute("stroke", "currentColor");
  path.setAttribute("stroke-width", "1.5");
  path.setAttribute("stroke-linecap", "square");
  svg.append(path);
  return svg;
}

/** A 28px square action button with an icon and an accessible name. */
export function iconButton(name: IconName, label: string, onClick?: (event: MouseEvent) => void): HTMLButtonElement {
  const button = h("button", { class: "icon-btn", type: "button", "aria-label": label, title: label }, icon(name));
  if (onClick) button.addEventListener("click", onClick);
  return button;
}

/** The item's initial in a 28px square (or a glyph for "generate"). */
export function tile(title: string): HTMLElement {
  const first = new Intl.Segmenter().segment(title.trim())[Symbol.iterator]().next().value?.segment;
  const letter = first?.toUpperCase() ?? "·";
  return h("span", { class: "tile", "aria-hidden": "true" }, letter);
}

/** The Klav key glyph, cropped to the key. */
export function glyph(className = "glyph"): SVGSVGElement {
  return buildGlyph(document, { className });
}

/** The one-time code's period as 30 blocks, `remaining` of them lit. */
export function blocks(period = 30): { el: HTMLElement; set: (remaining: number) => void } {
  const cells = Array.from({ length: period }, () => h("i", {}));
  const el = h("span", { class: "blocks", "aria-hidden": "true" }, ...cells);
  return {
    el,
    set(remaining: number) {
      cells.forEach((c, i) => c.classList.toggle("on", i < remaining));
    },
  };
}

/** Groups a one-time code as 289 591 (easier to read aloud). */
export function spaced(code: string): string {
  if (code.length === 6) return `${code.slice(0, 3)} ${code.slice(3)}`;
  if (code.length === 8) return `${code.slice(0, 4)} ${code.slice(4)}`;
  return code;
}
