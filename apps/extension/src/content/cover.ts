/**
 * Whether the page covers, hides or moves one of Klav's frames (T62), seen
 * from the page's side. The frame's own guard (`ui/guard.ts`) only knows
 * what IntersectionObserver v2 tells it, and Firefox has none; this check
 * runs in the content script, in every browser, before the background acts
 * on a choice made in a frame.
 *
 * Klav's host `<klav-ui>` is the last child of `<html>`, `position: fixed`
 * with the highest `z-index`. So only these can paint over its frames:
 * - an element after it in `<html>`, or `html::after`;
 * - the top layer (a modal `<dialog>`, a popover, fullscreen);
 * - and `<html>` itself, with opacity, a filter, a transform or a clip.
 * An overlay with `pointer-events: none` lets the click through to the
 * frame and `elementFromPoint` does not see it: that is why the rules are
 * about structure, not about hit testing (which is checked too).
 */

export interface Rect {
  left: number;
  top: number;
  width: number;
  height: number;
}

/** Why a frame does not count as seen. */
export type Cover = "detached" | "restyled" | "ancestor" | "moved" | "top_layer" | "after" | "overlay";

/** How far (px) a frame may be from where Klav put it (rounding). */
const SLACK = 1.5;

const NONE = new Set(["", "none", "normal", "auto"]);

function plain(value: string | undefined): boolean {
  return value === undefined || NONE.has(value.trim());
}

/** Whether a computed style leaves its box as it is: opaque, unfiltered, untransformed, unclipped. */
function untouched(style: CSSStyleDeclaration): boolean {
  if (style.opacity !== "" && Number(style.opacity) < 1) return false;
  const get = (name: string): string => style.getPropertyValue(name);
  for (const name of ["filter", "transform", "clip-path", "mask", "mask-image", "translate", "scale", "rotate", "perspective", "backdrop-filter"]) {
    if (!plain(get(name))) return false;
  }
  const zoom = get("zoom");
  if (zoom !== "" && zoom !== "1" && zoom !== "normal" && zoom !== "100%") return false;
  return get("content-visibility") === "" || get("content-visibility") === "visible";
}

/** Whether the page has something in the top layer (above every `z-index`). */
function topLayer(doc: Document): boolean {
  if (doc.fullscreenElement) return true;
  for (const selector of [":modal", ":popover-open"]) {
    try {
      if (doc.querySelector(selector)) return true;
    } catch {
      // a browser without that selector
    }
  }
  return false;
}

/** Whether something comes after `host` in `<html>` and can paint over it. */
function somethingAfter(host: HTMLElement, view: Window): boolean {
  for (let node = host.nextElementSibling; node; node = node.nextElementSibling) {
    if (view.getComputedStyle(node).display !== "none") return true;
  }
  try {
    const after = view.getComputedStyle(host.ownerDocument.documentElement, "::after");
    if (!plain(after.content) && after.position !== "static" && after.position !== "") return true;
  } catch {
    // no pseudo-element styles here
  }
  return false;
}

/**
 * Why `target` (a frame or the glyph inside `host`) does not count as
 * seen, or `undefined` if nothing of the page can be over it or move it.
 * `expected` is where Klav placed it; `point`, the click, if known.
 */
export function coverOf(host: HTMLElement, target: HTMLElement, expected: Rect, point?: { x: number; y: number }): Cover | undefined {
  const doc = host.ownerDocument;
  const view = doc.defaultView;
  if (!view || !host.isConnected || !target.isConnected || host.parentNode !== doc.documentElement) return "detached";
  const own = view.getComputedStyle(host);
  if (own.position !== "fixed" || own.display === "none" || own.visibility === "hidden" || !untouched(own)) return "restyled";
  if (!untouched(view.getComputedStyle(doc.documentElement))) return "ancestor";
  const rect = target.getBoundingClientRect();
  const off = (a: number, b: number): boolean => Math.abs(a - b) > SLACK;
  if (off(rect.left, expected.left) || off(rect.top, expected.top) || off(rect.width, expected.width) || off(rect.height, expected.height)) return "moved";
  if (rect.left < -SLACK || rect.top < -SLACK || rect.right > view.innerWidth + SLACK || rect.bottom > view.innerHeight + SLACK) return "moved";
  if (topLayer(doc)) return "top_layer";
  if (somethingAfter(host, view)) return "after";
  // What a click there would hit: the host (the shadow root is closed, so
  // the page sees the host), at the centre and at the click.
  if (typeof doc.elementsFromPoint === "function") {
    const points = [{ x: rect.left + rect.width / 2, y: rect.top + rect.height / 2 }, ...(point ? [point] : [])];
    for (const p of points) {
      const [top] = doc.elementsFromPoint(p.x, p.y);
      if (top !== undefined && top !== host) return "overlay";
    }
  }
  return undefined;
}

/** Where Klav put `el`, from its own inline style (`left`/`top` or `bottom`, `width`, `height`). */
export function placed(el: HTMLElement, view: Window): Rect {
  const px = (v: string): number => Number.parseFloat(v) || 0;
  const width = px(el.style.width);
  const height = px(el.style.height);
  const top = el.style.top !== "" ? px(el.style.top) : view.innerHeight - px(el.style.bottom) - height;
  return { left: px(el.style.left), top, width, height };
}
