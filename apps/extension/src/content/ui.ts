/**
 * What Klav draws inside a web page, all in one closed shadow root: the
 * glyph at the end of the focused field and Klav's surfaces, each an
 * extension page in an iframe the page cannot read: the field menu, the
 * top card, the central palette, the save bar and the agent notice.
 * Styles go through the CSSOM (no `<style>` the page's CSP could block).
 */
import { ext } from "../shared/ext";
import { buildGlyph } from "../shared/glyph";
import { type MessageKey, t } from "../shared/i18n";
import type { Surface } from "../shared/messages";
import { coverOf, placed } from "./cover";

const ICON = 20;
const MENU_WIDTH = 320;
const MENU_MAX = 380;
/** A menu with the generator (a new-password field) may grow this much, within the window. */
const MENU_TALL = 600;
const SHADOW = "0 12px 32px -12px rgb(9 9 11 / 0.35)";

type Style = Record<string, string>;

function style(el: HTMLElement | SVGElement, props: Style): void {
  for (const [k, v] of Object.entries(props)) el.style.setProperty(k, v, "important");
}

/** The page of each surface. */
const PAGES: Record<Surface, string> = {
  menu: "menu.html",
  save: "save.html",
  card: "card.html",
  find: "find.html",
  notice: "notice.html",
  passkey: "passkey.html",
};
const TITLES: Record<Surface, MessageKey | undefined> = {
  menu: undefined,
  save: "frame_save",
  card: "frame_card",
  find: "frame_find",
  notice: "frame_notice",
  passkey: "frame_passkey",
};
const MAX_HEIGHT: Record<Surface, number> = { menu: MENU_MAX, save: 420, card: 200, find: 520, notice: 120, passkey: 460 };

/** A frame's choices count only after it has been shown this long (like `ui/guard.ts`). */
const ARM_MS = 400;
/** …and after nothing of the page has covered or moved it for this long. */
const CLEAR_MS = 300;
/** How often an open frame is checked. */
const SAMPLE_MS = 100;

/** The host's own style: reset (`all: initial`) and fixed above everything. */
const HOST_STYLE: Style = { all: "initial", position: "fixed", top: "0", left: "0", width: "0", height: "0", "z-index": "2147483647" };

interface Shown {
  id: string;
  el: HTMLIFrameElement;
  tall?: boolean;
  /** When it was shown (`Date.now()`). */
  at: number;
  /** The last time a check found it covered, hidden or moved. */
  coveredAt?: number;
}

export class InPage {
  private host: HTMLElement | undefined;
  private root: ShadowRoot | undefined;
  private icon: HTMLButtonElement | undefined;
  private anchor: Element | undefined;
  private raf = 0;
  private readonly frames = new Map<Surface, Shown>();
  private backdrop: HTMLElement | undefined;
  private noticeTimer: ReturnType<typeof setTimeout> | undefined;
  /** The `style` attribute Klav last gave the host (anything else is the page's). */
  private hostStyle: string | null = null;
  private watcher: MutationObserver | undefined;
  private sampler: ReturnType<typeof setInterval> | undefined;

  constructor(
    private readonly onIcon: () => void,
    private readonly onBackdrop: (findId: string) => void,
  ) {}

  get menuOpen(): boolean {
    return this.frames.has("menu");
  }

  /** The ID of an open surface. */
  idOf(surface: Surface): string | undefined {
    return this.frames.get(surface)?.id;
  }

  /** Whether an event happened on Klav's own elements. */
  owns(event: Event): boolean {
    return this.host !== undefined && event.composedPath().includes(this.host);
  }

  private ensure(): ShadowRoot {
    if (this.root && this.host?.isConnected && this.host.parentNode === document.documentElement) return this.root;
    this.detach();
    const host = document.createElement("klav-ui");
    style(host, HOST_STYLE);
    this.hostStyle = host.getAttribute("style");
    const root = host.attachShadow({ mode: "closed" });
    document.documentElement.append(host);
    this.host = host;
    this.root = root;
    this.frames.clear();
    addEventListener("scroll", this.reposition, { capture: true, passive: true });
    addEventListener("resize", this.reposition, { passive: true });
    // The page may restyle the host, move it, or put something after it.
    this.watcher = new MutationObserver(this.watch);
    this.watcher.observe(host, { attributes: true });
    this.watcher.observe(document.documentElement, { childList: true, attributes: true });
    return root;
  }

  /**
   * Puts the host back at the end of `<html>` when something was appended
   * after it since Klav created it (another extension's element, a page's
   * late node). Anything after the host counts as covering Klav's frames
   * (T62, `cover.ts`), so without this a node that came later would block
   * every frame for the rest of the page's life. Only right before Klav
   * shows something (the person focused a field or opened a surface),
   * never from the MutationObserver, so two scripts that each want to be
   * last do not chase each other.
   *
   * It stops before another `<klav-ui>`: the passkey bridge
   * (`webauthn.ts`) draws Klav's passkey frame in a host of its own, and
   * passing it would cover that frame. Klav's hosts keep the order they
   * had; a page that names its node `klav-ui` only gets the old behaviour
   * (its node counts as covering).
   *
   * `moveBefore` (Chromium) moves the host with its frames alive; a plain
   * move would reload them, so without it the host moves only while no
   * frame is open. Frames that were open count as covered for a moment
   * after the move, as after any change the page made.
   */
  private keepLast(): void {
    const host = this.host;
    if (!host) return;
    let stop = host.nextElementSibling;
    while (stop !== null && stop.localName !== "klav-ui") stop = stop.nextElementSibling;
    if (host.nextElementSibling === stop) return;
    const html = document.documentElement as HTMLElement & { moveBefore?: (node: Node, child: Node | null) => void };
    try {
      if (typeof html.moveBefore === "function") {
        html.moveBefore(host, stop);
        this.markCovered();
        return;
      }
    } catch {
      // A browser that refuses the move: as if it had none.
    }
    if (this.frames.size === 0) html.insertBefore(host, stop);
  }

  /** Drops the host the page took away or moved (its frames went with it). */
  private detach(): void {
    this.watcher?.disconnect();
    this.watcher = undefined;
    clearInterval(this.sampler);
    this.sampler = undefined;
    if (this.host?.isConnected) this.host.remove();
    this.host = undefined;
    this.root = undefined;
    this.icon = undefined;
    this.frames.clear();
    this.backdrop = undefined;
  }

  private readonly watch = (records: MutationRecord[]): void => {
    const host = this.host;
    if (!host) return;
    if (!host.isConnected || host.parentNode !== document.documentElement) {
      // Taken out or moved into the page: everything Klav showed is gone.
      this.detach();
      this.anchor = undefined;
      return;
    }
    if (records.some((r) => r.target === host) && host.getAttribute("style") !== this.hostStyle) {
      // The page restyled the host: put Klav's style back, and its frames
      // do not count as seen for a moment.
      host.removeAttribute("class");
      host.setAttribute("style", "");
      style(host, HOST_STYLE);
      this.hostStyle = host.getAttribute("style");
      this.markCovered();
    }
    this.sample();
  };

  private markCovered(): void {
    const now = Date.now();
    for (const f of this.frames.values()) f.coveredAt = now;
  }

  /** Checks every open frame now; while one is open, every SAMPLE_MS. */
  private sample(): void {
    const host = this.host;
    if (!host || (this.frames.size === 0 && !this.icon)) {
      clearInterval(this.sampler);
      this.sampler = undefined;
      return;
    }
    this.sampler ??= setInterval(() => {
      this.sample();
    }, SAMPLE_MS);
    const now = Date.now();
    for (const f of this.frames.values()) {
      if (coverOf(host, f.el, placed(f.el, window)) !== undefined) f.coveredAt = now;
    }
  }

  /**
   * Whether a choice in the frame of `surface` (with `id`) counts: shown
   * for ARM_MS, nothing of the page over it, hiding it or moving it now,
   * and none of that during the last CLEAR_MS (T62). Asked by the
   * background before it acts on the choice.
   */
  isClear(surface: Surface, id: string): boolean {
    const f = this.frames.get(surface);
    const host = this.host;
    if (f?.id !== id || !host) return false;
    const now = Date.now();
    if (now - f.at < ARM_MS) return false;
    if (coverOf(host, f.el, placed(f.el, window)) !== undefined) {
      f.coveredAt = now;
      return false;
    }
    return f.coveredAt === undefined || now - f.coveredAt >= CLEAR_MS;
  }

  /** Shows Klav's glyph in a small box at the end of `field`. */
  showIcon(field: Element): void {
    const rect = field.getBoundingClientRect();
    if (rect.width < 80 || rect.height < 16) {
      this.hideIcon();
      return;
    }
    const root = this.ensure();
    this.keepLast();
    this.anchor = field;
    if (!this.icon) {
      const icon = document.createElement("button");
      icon.type = "button";
      icon.title = t("fill_with_klav");
      icon.setAttribute("aria-label", t("fill_with_klav"));
      style(icon, {
        all: "initial",
        position: "fixed",
        width: `${String(ICON)}px`,
        height: `${String(ICON)}px`,
        "box-sizing": "border-box",
        display: "grid",
        "place-items": "center",
        cursor: "pointer",
        background: "#ffffff",
        border: "1px solid #09090b",
        "border-radius": "0",
      });
      const mark = buildGlyph(document, { color: "#09090b" });
      style(mark, { width: "12px", height: "7.5px", display: "block" });
      icon.append(mark);
      // Keep the focus in the field.
      icon.addEventListener("pointerdown", (event) => {
        event.preventDefault();
      });
      icon.addEventListener("click", (event) => {
        // Only a real click (the page cannot synthesize trusted events) on
        // a glyph the page does not cover, hide or move.
        if (!event.isTrusted) return;
        event.preventDefault();
        event.stopPropagation();
        if (!this.iconClear({ x: event.clientX, y: event.clientY })) return;
        this.onIcon();
      });
      root.append(icon);
      this.icon = icon;
    }
    this.place();
  }

  /** Whether the glyph is where Klav put it, with nothing of the page over it. */
  iconClear(point?: { x: number; y: number }): boolean {
    const host = this.host;
    const icon = this.icon;
    if (!host || !icon) return false;
    const at = placed(icon, window);
    return coverOf(host, icon, { ...at, width: ICON, height: ICON }, point) === undefined;
  }

  hideIcon(): void {
    this.icon?.remove();
    this.icon = undefined;
    if (!this.frames.has("menu")) this.anchor = undefined;
  }

  /** Opens a surface (an extension page in a frame); `focus` gives it the keyboard; `tall`: the menu has the generator. */
  show(surface: Surface, id: string, focus = false, tall = false): void {
    if (this.frames.get(surface)?.id === id) return;
    this.hide(surface);
    const root = this.ensure();
    this.keepLast();
    const frame = document.createElement("iframe");
    frame.src = `${ext.runtime.getURL(PAGES[surface])}#${id}`;
    const title = TITLES[surface];
    frame.title = title ? t(title) : "Klav";
    frame.setAttribute("allow", "");
    style(frame, {
      all: "initial",
      position: "fixed",
      border: "0",
      "box-shadow": SHADOW,
      background: "transparent",
      height: surface === "find" ? "320px" : "64px",
      "color-scheme": "normal",
    });
    if (focus || surface === "find") {
      frame.addEventListener(
        "load",
        () => {
          frame.focus();
        },
        { once: true },
      );
    }
    if (surface === "find") {
      const backdrop = document.createElement("div");
      style(backdrop, { all: "initial", position: "fixed", inset: "0", background: "rgb(9 9 11 / 0.28)" });
      backdrop.addEventListener("click", (event) => {
        if (event.isTrusted) this.onBackdrop(id);
      });
      root.append(backdrop);
      this.backdrop = backdrop;
    }
    root.append(frame);
    this.frames.set(surface, { id, el: frame, at: Date.now(), ...(tall ? { tall } : {}) });
    if (surface === "notice") {
      clearTimeout(this.noticeTimer);
      this.noticeTimer = setTimeout(() => {
        this.hide("notice", id);
      }, 12_000);
    }
    this.place();
    this.sample();
  }

  size(surface: Surface, id: string, height: number): void {
    const f = this.frames.get(surface);
    if (f?.id !== id) return;
    const max =
      surface === "find"
        ? Math.min(MAX_HEIGHT.find, Math.round(innerHeight * 0.76))
        : surface === "menu"
          ? this.menuMax(f.tall === true)
          : MAX_HEIGHT[surface];
    style(f.el, { height: `${String(Math.max(40, Math.min(max, Math.ceil(height))))}px` });
    this.place();
  }

  /**
   * How tall the menu may be: up to MENU_MAX (MENU_TALL with the
   * generator), but never past the window on the side of the field where
   * it opens. A frame cut by the window counts as covered, both here
   * (`cover.ts`) and for IntersectionObserver v2 in the frame, so a menu
   * taller than the room would refuse every click; capped, its list
   * scrolls inside instead.
   */
  private menuMax(tall: boolean): number {
    const cap = tall ? MENU_TALL : MENU_MAX;
    const rect = this.anchor?.getBoundingClientRect();
    if (!rect) return cap;
    const room = Math.max(innerHeight - rect.bottom, rect.top) - 12;
    return Math.min(cap, room);
  }

  /** Closes a surface (only if it is still the one with `id`, when given). */
  hide(surface: Surface, id?: string): void {
    const f = this.frames.get(surface);
    if (!f || (id !== undefined && f.id !== id)) return;
    f.el.remove();
    this.frames.delete(surface);
    if (surface === "find") {
      this.backdrop?.remove();
      this.backdrop = undefined;
    }
  }

  /** Removes the field's glyph and menu (the page navigated, or the field went away). */
  reset(): void {
    this.hide("menu");
    this.hideIcon();
    this.anchor = undefined;
  }

  private readonly reposition = (): void => {
    cancelAnimationFrame(this.raf);
    this.raf = requestAnimationFrame(() => {
      this.place();
    });
  };

  private place(): void {
    const narrow = innerWidth < 560;
    for (const [surface, { el }] of this.frames) {
      if (surface === "menu") continue;
      const width = surface === "find" ? Math.min(560, innerWidth - 24) : Math.min(surface === "card" || surface === "passkey" ? 380 : 360, innerWidth - 16);
      const props: Style = { width: `${String(width)}px` };
      if (surface === "find") {
        props.left = `${String(Math.round((innerWidth - width) / 2))}px`;
        props.top = `${String(Math.round(innerHeight * 0.12))}px`;
      } else if (surface === "notice") {
        // Along the bottom of the page, the whole width.
        props.width = `${String(innerWidth)}px`;
        props.left = "0px";
        props.bottom = "0px";
      } else {
        // The card and the save bar: top right, centred on narrow screens.
        props.top = "12px";
        props.left = narrow ? `${String(Math.round((innerWidth - width) / 2))}px` : `${String(innerWidth - width - 12)}px`;
      }
      style(el, props);
    }
    const anchor = this.anchor;
    if (!anchor?.isConnected) {
      if (this.anchor) {
        this.hide("menu");
        this.hideIcon();
        this.anchor = undefined;
      }
      return;
    }
    const rect = anchor.getBoundingClientRect();
    if (this.icon) {
      style(this.icon, {
        left: `${String(Math.round(rect.right - ICON - 6))}px`,
        top: `${String(Math.round(rect.top + (rect.height - ICON) / 2))}px`,
      });
    }
    const menu = this.frames.get("menu")?.el;
    if (menu) {
      const height = menu.getBoundingClientRect().height || 120;
      const below = innerHeight - rect.bottom;
      const top = below >= height + 8 || below >= rect.top ? rect.bottom + 4 : rect.top - height - 4;
      const left = Math.max(8, Math.min(rect.left, innerWidth - MENU_WIDTH - 8));
      style(menu, {
        width: `${String(MENU_WIDTH)}px`,
        left: `${String(Math.round(left))}px`,
        top: `${String(Math.round(Math.max(4, top)))}px`,
      });
    }
  }
}
