// @vitest-environment jsdom
// T62 inside Klav's frames (`ui/guard.ts`): where the browser has
// IntersectionObserver v2 (Chromium), a click counts only once the whole
// frame has been visible for 300 ms. Something painted over it, or the
// window cutting it, still refuses clicks; a cut of a rounding pixel (a
// fractional zoom or pixel ratio) does not. jsdom has no IntersectionObserver:
// these tests stand in for Chromium's, with the entries it reports.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

type Callback = (entries: IntersectionObserverEntry[]) => void;

let callback: Callback | undefined;
let options: (IntersectionObserverInit & { trackVisibility?: boolean; delay?: number }) | undefined;
let observed: Element[] = [];
let now = 0;

/** What Chromium reports for the frame's edge, a 320×`height` box at the top of the window. */
function entry(seenHeight: number, isVisible: boolean, height = 172, seenWidth = 320): IntersectionObserverEntry {
  const box = { x: 0, y: 0, left: 0, top: 0, width: 320, height, right: 320, bottom: height, toJSON: () => ({}) };
  const seen = { ...box, width: seenWidth, height: seenHeight, right: seenWidth, bottom: seenHeight };
  return {
    boundingClientRect: box,
    intersectionRect: seen,
    intersectionRatio: (seenWidth * seenHeight) / (320 * height),
    isIntersecting: seenHeight > 0,
    isVisible,
    rootBounds: null,
    target: observed[0],
    time: now,
  } as unknown as IntersectionObserverEntry;
}

function report(e: IntersectionObserverEntry): void {
  if (!callback) throw new Error("no observer");
  callback([e]);
}

async function loadGuard(): Promise<typeof import("../src/ui/guard")> {
  vi.resetModules();
  return import("../src/ui/guard");
}

beforeEach(() => {
  callback = undefined;
  options = undefined;
  observed = [];
  now = 0;
  vi.spyOn(performance, "now").mockImplementation(() => now);
  const edge = document.createElement("div");
  edge.className = "frame-edge";
  document.body.replaceChildren(edge);
  (globalThis as unknown as { IntersectionObserverEntry: unknown }).IntersectionObserverEntry = class {
    isVisible = false;
  };
  Object.defineProperty((globalThis as unknown as { IntersectionObserverEntry: { prototype: object } }).IntersectionObserverEntry.prototype, "isVisible", {
    configurable: true,
    get: () => false,
  });
  (globalThis as unknown as { IntersectionObserver: unknown }).IntersectionObserver = class {
    constructor(cb: Callback, init: IntersectionObserverInit) {
      callback = cb;
      options = init;
    }
    observe(el: Element): void {
      observed.push(el);
    }
  };
});

afterEach(() => {
  vi.restoreAllMocks();
  Reflect.deleteProperty(globalThis, "IntersectionObserver");
  Reflect.deleteProperty(globalThis, "IntersectionObserverEntry");
});

describe("the frame's own guard", () => {
  it("watches the frame's edge, tracking what is painted over it", async () => {
    await loadGuard();
    expect(observed.map((el) => el.className)).toEqual(["frame-edge"]);
    expect(options?.trackVisibility).toBe(true);
    // Not only 1: below its lowest threshold Chromium says "not visible"
    // even with nothing over the frame.
    expect(options?.threshold).toEqual([0.99, 1]);
  });

  it("ignores clicks in the first 400 ms, then counts them once the frame has been whole and visible for 300 ms", async () => {
    const guard = await loadGuard();
    report(entry(172, true));
    now = 200;
    expect(guard.armed()).toBe("early");
    now = 299;
    expect(guard.armed()).toBe("early");
    now = 450;
    expect(guard.armed()).toBe("yes");
  });

  it("counts a frame the window cuts by a rounding pixel (a fractional zoom or pixel ratio)", async () => {
    const guard = await loadGuard();
    // 172 px tall, 171.2 seen: intersectionRatio 0.995.
    const e = entry(171.2, true);
    expect(e.intersectionRatio).toBeCloseTo(0.995, 3);
    report(e);
    now = 450;
    expect(guard.armed()).toBe("yes");
  });

  it("does not count a frame the window cuts by more than that", async () => {
    const guard = await loadGuard();
    report(entry(169, true));
    now = 450;
    expect(guard.armed()).toBe("hidden");
    report(entry(172, true, 172, 316));
    now = 900;
    expect(guard.armed()).toBe("hidden");
  });

  it("does not count with something painted over it, even with all of it on screen", async () => {
    const guard = await loadGuard();
    report(entry(172, false));
    now = 450;
    expect(guard.armed()).toBe("hidden");
  });

  it("starts over when the frame is covered for a moment", async () => {
    const guard = await loadGuard();
    report(entry(172, true));
    now = 500;
    expect(guard.armed()).toBe("yes");
    report(entry(172, false));
    expect(guard.armed()).toBe("hidden");
    now = 600;
    report(entry(172, true));
    now = 850;
    expect(guard.armed()).toBe("hidden");
    now = 900;
    expect(guard.armed()).toBe("yes");
  });

  it("keeps counting while the frame grows and stays whole (the menu starts at 64 px)", async () => {
    const guard = await loadGuard();
    report(entry(64, true, 64));
    now = 100;
    report(entry(172, true, 172));
    now = 450;
    expect(guard.armed()).toBe("yes");
  });

  it("explains a refused click on a covered frame, and only counts trusted clicks", async () => {
    const guard = await loadGuard();
    report(entry(172, false));
    now = 450;
    const hidden = vi.fn();
    const trusted = { isTrusted: true } as Event;
    expect(guard.personClicked(trusted, hidden)).toBe(false);
    expect(hidden).toHaveBeenCalledTimes(1);
    report(entry(172, true));
    now = 800;
    expect(guard.personClicked(trusted, hidden)).toBe(true);
    expect(guard.personClicked({ isTrusted: false } as Event, hidden)).toBe(false);
    expect(hidden).toHaveBeenCalledTimes(1);
  });
});

describe("a frame that grows", () => {
  it("shows no scrollbar while it waits for its new height, and scrolls once capped", async () => {
    vi.useFakeTimers();
    try {
      const main = document.createElement("main");
      document.body.append(main);
      let height = 64;
      Object.defineProperty(main, "offsetHeight", { configurable: true, get: () => height });
      const sizes: number[] = [];
      const chrome = (globalThis as unknown as { chrome: Record<string, unknown> }).chrome;
      Object.assign(chrome, {
        runtime: {
          id: "klav",
          sendMessage: (m: { type: string; height?: number }) => {
            if (m.type === "size" && m.height !== undefined) sizes.push(m.height);
            return Promise.resolve({ ok: true, value: null });
          },
        },
      });
      let resize: (() => void) | undefined;
      (globalThis as unknown as { ResizeObserver: unknown }).ResizeObserver = class {
        constructor(cb: () => void) {
          resize = cb;
        }
        observe(): void {}
      };
      const inner = vi.spyOn(window, "innerHeight", "get").mockReturnValue(64);
      const { framePage } = await import("../src/ui/frame");
      framePage("menu", main);
      const growing = (): boolean => document.documentElement.classList.contains("growing");
      // A notice makes the menu 172 px tall in a 64 px frame.
      height = 172;
      resize?.();
      vi.advanceTimersByTime(20);
      expect(sizes.at(-1)).toBe(172);
      expect(growing()).toBe(true);
      // The frame takes its height: back to normal.
      inner.mockReturnValue(172);
      window.dispatchEvent(new Event("resize"));
      expect(growing()).toBe(false);
      // A long list: the frame is capped at 380 px, so the list must scroll.
      height = 500;
      resize?.();
      vi.advanceTimersByTime(20);
      expect(growing()).toBe(true);
      inner.mockReturnValue(380);
      window.dispatchEvent(new Event("resize"));
      expect(growing()).toBe(false);
      // Already capped: more rows do not hide the scrollbar again.
      height = 520;
      resize?.();
      vi.advanceTimersByTime(20);
      expect(growing()).toBe(false);
      // Not resized at all (capped at the height it already had): it scrolls after a moment.
      height = 380;
      resize?.();
      vi.advanceTimersByTime(20);
      height = 400;
      resize?.();
      vi.advanceTimersByTime(20);
      expect(growing()).toBe(true);
      vi.advanceTimersByTime(300);
      expect(growing()).toBe(false);
    } finally {
      vi.useRealTimers();
    }
  });
});
