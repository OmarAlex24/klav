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

let visibleSince: number | undefined;
const tracksVisibility = typeof IntersectionObserverEntry !== "undefined" && "isVisible" in IntersectionObserverEntry.prototype;
if (tracksVisibility) {
  const observer = new IntersectionObserver(
    (entries) => {
      for (const entry of entries) {
        const visible = (entry as IntersectionObserverEntry & { isVisible?: boolean }).isVisible === true;
        visibleSince = visible ? (visibleSince ?? performance.now()) : undefined;
      }
    },
    { threshold: [1], trackVisibility: true, delay: 100 } as IntersectionObserverInit,
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
