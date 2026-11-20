/**
 * Klav's logo: a key drawn on an 8×8 pixel grid, on its own (no letter;
 * docs/diseno-visual/README.md §7). Built with DOM calls (never parsed
 * from a string) so the content script can draw it inside pages, where no
 * stylesheet of ours applies.
 */
const NS = "http://www.w3.org/2000/svg";

/** The key, row by row: a ring on the left, the shaft and two teeth. */
export const KEY: readonly string[] = [
  "........",
  ".##.....",
  "#..#....",
  "#..#####",
  "#..#.#.#",
  ".##.....",
  "........",
  "........",
];

/** The lit cells of the key as [x, y] pairs. */
export function keyCells(): [number, number][] {
  const cells: [number, number][] = [];
  KEY.forEach((row, y) => {
    for (let x = 0; x < row.length; x++) if (row[x] === "#") cells.push([x, y]);
  });
  return cells;
}

/**
 * The key as an SVG. `color` defaults to `currentColor`; the box is cropped
 * to the key (8×5 cells) unless `square` keeps the whole 8×8 grid.
 */
export function buildGlyph(doc: Document, options: { color?: string; square?: boolean; className?: string } = {}): SVGSVGElement {
  const top = options.square ? 0 : 1;
  const rows = options.square ? 8 : 5;
  const svg = doc.createElementNS(NS, "svg");
  svg.setAttribute("viewBox", `0 ${String(top)} 8 ${String(rows)}`);
  svg.setAttribute("aria-hidden", "true");
  svg.setAttribute("shape-rendering", "crispEdges");
  if (options.className) svg.setAttribute("class", options.className);
  const path = doc.createElementNS(NS, "path");
  path.setAttribute("d", keyCells().map(([x, y]) => `M${String(x)} ${String(y)}h1v1h-1z`).join(""));
  path.setAttribute("fill", options.color ?? "currentColor");
  svg.append(path);
  return svg;
}
