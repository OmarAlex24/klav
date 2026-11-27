/**
 * Shared plumbing of Klav's frames inside pages (menu, card, palette, save
 * bar, notice): the ID from the URL, telling the page how tall the frame
 * is, and closing it.
 */
import { ask, type Surface } from "../shared/messages";

/** How long a frame waits to grow before its content may scroll instead. */
const GROW_MS = 300;

export interface FramePage {
  id: string;
  resize: () => void;
  close: () => void;
}

export function framePage(surface: Surface, root: HTMLElement): FramePage {
  const id = location.hash.slice(1);
  const html = document.documentElement;
  /** The height last asked for: a frame shorter than that was capped, and its list scrolls. */
  let asked = 0;
  let growing: ReturnType<typeof setTimeout> | undefined;
  const grown = (): void => {
    clearTimeout(growing);
    growing = undefined;
    html.classList.remove("growing");
  };
  const resize = (): void => {
    requestAnimationFrame(() => {
      const height = root.offsetHeight;
      // Taller than the frame, which got all it asked for so far: it is
      // about to grow, so no scrollbar until it has (or, capped, until a
      // moment has passed and the list must scroll).
      if (height > innerHeight + 1 && innerHeight + 1 >= asked) {
        html.classList.add("growing");
        clearTimeout(growing);
        growing = setTimeout(grown, GROW_MS);
      }
      asked = height;
      void ask({ type: "size", surface, id, height }).catch(() => undefined);
    });
  };
  // The frame took its new height.
  addEventListener("resize", grown);
  // Late fonts and inserted sections change the height too.
  new ResizeObserver(resize).observe(root);
  const close = (): void => {
    void ask({ type: "close", surface, id }).catch(() => undefined);
  };
  return { id, resize, close };
}
