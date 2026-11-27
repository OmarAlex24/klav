/**
 * Clickjacking guard for Klav's frames inside pages. A page can try to
 * hide a frame (opacity, overlays, moving it under the cursor) and trick a
 * click on it. Where the browser tells (IntersectionObserver v2, Chromium),
 * a choice only counts while the frame has been fully visible for a
 * moment; everywhere, clicks in the first 400 ms are ignored and only
 * trusted events count (a page cannot synthesize them in our origin).
 */
import { t } from "../shared/i18n";

const shownAt = performance.now();
const ARM_MS = 400;
const VISIBLE_MS = 300;

/**
 * How much of the frame (px, per side) the window may cut and still count
 * as whole: sub-pixel rounding at fractional zoom or device pixel ratios.
 * The content script separately refuses a frame more than 1.5 px outside
 * the window (`content/cover.ts`), so this only absorbs rounding.
 */
const ROUNDING_PX = 1;

let visibleSince: number | undefined;

/** Whether an entry says the whole frame is on screen with nothing painted over it. */
export function wholeAndVisible(entry: IntersectionObserverEntry): boolean {
  if ((entry as IntersectionObserverEntry & { isVisible?: boolean }).isVisible !== true) return false;
  const box = entry.boundingClientRect;
  const seen = entry.intersectionRect;
  return box.width - seen.width <= ROUNDING_PX && box.height - seen.height <= ROUNDING_PX;
}

const tracksVisibility = typeof IntersectionObserverEntry !== "undefined" && "isVisible" in IntersectionObserverEntry.prototype;
if (tracksVisibility) {
  const observer = new IntersectionObserver(
    (entries) => {
      for (const entry of entries) {
        visibleSince = wholeAndVisible(entry) ? (visibleSince ?? performance.now()) : undefined;
      }
    },
    // Not just [1]: below the threshold Chromium reports `isVisible: false`
    // even with nothing over the frame, so a frame cut by a rounding pixel
    // would never arm. 0.99 still reports a cut beyond that, which
    // `wholeAndVisible` refuses; `isVisible` alone keeps catching anything
    // painted over it (an overlay, a popover, a faded or moved ancestor).
    { threshold: [0.99, 1], trackVisibility: true, delay: 100 } as IntersectionObserverInit,
  );
  // The whole frame, not the body: a long list scrolls, and the body is then taller than the frame.
  const edge = document.querySelector(".frame-edge");
  if (edge) observer.observe(edge);
}

/** Whether a click now is the person's, on a frame they can see. */
export function armed(): "yes" | "early" | "hidden" {
  const now = performance.now();
  if (now - shownAt < ARM_MS) return "early";
  if (!tracksVisibility) return "yes";
  return visibleSince !== undefined && now - visibleSince >= VISIBLE_MS ? "yes" : "hidden";
}

/** The text Klav shows when the page covers one of its frames. */
export const COVERED = t("covered");

/** A trusted click (or Enter) on a frame the person can see; `onHidden` explains a covered one. */
export function personClicked(event: Event, onHidden: () => void): boolean {
  if (!event.isTrusted) return false;
  const ready = armed();
  if (ready === "early") return false;
  if (ready === "hidden") {
    onHidden();
    return false;
  }
  return true;
}
