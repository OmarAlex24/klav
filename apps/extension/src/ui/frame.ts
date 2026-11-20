/**
 * Shared plumbing of Klav's frames inside pages (menu, card, palette, save
 * bar, notice): the ID from the URL, telling the page how tall the frame
 * is, and closing it.
 */
import { ask, type Surface } from "../shared/messages";

export interface FramePage {
  id: string;
  resize: () => void;
  close: () => void;
}

export function framePage(surface: Surface, root: HTMLElement): FramePage {
  const id = location.hash.slice(1);
  const resize = (): void => {
    requestAnimationFrame(() => {
      void ask({ type: "size", surface, id, height: root.offsetHeight }).catch(() => undefined);
    });
  };
  // Late fonts and inserted sections change the height too.
  new ResizeObserver(resize).observe(root);
  const close = (): void => {
    void ask({ type: "close", surface, id }).catch(() => undefined);
  };
  return { id, resize, close };
}
