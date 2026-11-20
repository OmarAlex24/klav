// @vitest-environment jsdom
// Layer 09 (T62): Klav's frames inside a page only count as seen when the
// page leaves them alone, checked from the content script in every browser
// (IntersectionObserver v2 exists only in Chromium, and jsdom has none, as
// Firefox): shown for 400 ms, nothing after the host in <html>, nothing in
// the top layer, <html> not faded or transformed, the host not restyled or
// moved, the frame where Klav put it, and none of that in the last 300 ms.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { InPage } from "../src/content/ui";

const chrome = (globalThis as unknown as { chrome: Record<string, unknown> }).chrome;
Object.assign(chrome, { runtime: { id: "klav", getURL: (path: string) => `chrome-extension://klav/${path}` } });

/** Frames, the glyph and the host lie where their inline style puts them (jsdom has no layout). */
let shift = 0;
HTMLElement.prototype.getBoundingClientRect = function (this: HTMLElement) {
  const px = (v: string): number => Number.parseFloat(v) || 0;
  const width = this.localName === "input" ? 200 : px(this.style.width);
  const height = this.localName === "input" ? 30 : px(this.style.height);
  const left = this.localName === "input" ? 10 : px(this.style.left) + shift;
  const top = this.localName === "input" ? 10 : this.style.top !== "" ? px(this.style.top) : innerHeight - px(this.style.bottom) - height;
  return { left, top, width, height, right: left + width, bottom: top + height, x: left, y: top, toJSON: () => ({}) };
};

// jsdom does not compute pseudo-elements (`html::after`): none here.
const computed = window.getComputedStyle.bind(window);
window.getComputedStyle = (el: Element, pseudo?: string | null) =>
  pseudo ? ({ content: "none", position: "static" } as CSSStyleDeclaration) : computed(el);

let ui: InPage;

beforeEach(() => {
  vi.useFakeTimers();
  shift = 0;
  document.documentElement.removeAttribute("style");
  for (const el of [...document.documentElement.children]) if (el !== document.head && el !== document.body) el.remove();
  const field = document.createElement("input");
  field.id = "field";
  document.body.replaceChildren(field);
  ui = new InPage(
    () => undefined,
    () => undefined,
  );
});

afterEach(() => {
  ui.reset();
  for (const s of ["card", "save", "find", "notice"] as const) ui.hide(s);
  vi.useRealTimers();
});

function host(): HTMLElement {
  const el = document.querySelector("klav-ui");
  if (!(el instanceof HTMLElement)) throw new Error("no host");
  return el;
}

/** Lets the MutationObserver run. */
async function settle(): Promise<void> {
  await Promise.resolve();
  await Promise.resolve();
}

describe("a frame inside a page", () => {
  it("counts only after it has been shown for a moment", () => {
    ui.show("card", "c1");
    expect(ui.isClear("card", "c1")).toBe(false);
    vi.advanceTimersByTime(450);
    expect(ui.isClear("card", "c1")).toBe(true);
    expect(ui.isClear("card", "another")).toBe(false);
  });

  it("does not count with an overlay after Klav's host, even one that lets clicks through", async () => {
    ui.show("save", "s1");
    vi.advanceTimersByTime(450);
    const decoy = document.createElement("div");
    decoy.setAttribute("style", "position: fixed; inset: 0; pointer-events: none; z-index: 2147483647");
    document.documentElement.append(decoy);
    await settle();
    expect(ui.isClear("save", "s1")).toBe(false);
    // Gone again: it still does not count for a moment.
    decoy.remove();
    await settle();
    expect(ui.isClear("save", "s1")).toBe(false);
    vi.advanceTimersByTime(350);
    expect(ui.isClear("save", "s1")).toBe(true);
  });

  it("does not count while <html> is faded or transformed", () => {
    ui.show("card", "c1");
    vi.advanceTimersByTime(450);
    document.documentElement.style.opacity = "0.01";
    expect(ui.isClear("card", "c1")).toBe(false);
    document.documentElement.style.opacity = "";
    document.documentElement.style.transform = "translateX(300px)";
    expect(ui.isClear("card", "c1")).toBe(false);
  });

  it("puts back the host's style when the page changes it, and waits", async () => {
    ui.show("card", "c1");
    vi.advanceTimersByTime(450);
    host().style.transform = "scale(0.01)";
    host().style.setProperty("opacity", "0", "important");
    await settle();
    expect(host().style.transform).toBe("");
    expect(host().style.getPropertyValue("opacity")).toBe("");
    expect(host().style.getPropertyValue("position")).toBe("fixed");
    expect(ui.isClear("card", "c1")).toBe(false);
    vi.advanceTimersByTime(350);
    expect(ui.isClear("card", "c1")).toBe(true);
  });

  it("drops everything when the page moves the host into its own markup", async () => {
    ui.show("card", "c1");
    vi.advanceTimersByTime(450);
    const box = document.createElement("div");
    box.style.transform = "scale(3)";
    document.body.append(box);
    box.append(host());
    await settle();
    expect(ui.isClear("card", "c1")).toBe(false);
    expect(ui.idOf("card")).toBeUndefined();
  });

  it("does not count when the frame is not where Klav put it", () => {
    ui.show("card", "c1");
    vi.advanceTimersByTime(450);
    shift = 120;
    expect(ui.isClear("card", "c1")).toBe(false);
  });

  it("does not count with something in the top layer", () => {
    ui.show("find", "f1");
    vi.advanceTimersByTime(450);
    const fullscreen = Object.getOwnPropertyDescriptor(Document.prototype, "fullscreenElement");
    Object.defineProperty(document, "fullscreenElement", { configurable: true, get: () => document.body });
    expect(ui.isClear("find", "f1")).toBe(false);
    if (fullscreen) Object.defineProperty(document, "fullscreenElement", fullscreen);
    else Reflect.deleteProperty(document, "fullscreenElement");
  });
});

describe("the glyph", () => {
  it("does not count under an overlay after the host", () => {
    const field = document.getElementById("field") as HTMLInputElement;
    ui.showIcon(field);
    expect(ui.iconClear()).toBe(true);
    const decoy = document.createElement("div");
    decoy.setAttribute("style", "position: fixed; inset: 0; pointer-events: none");
    document.documentElement.append(decoy);
    expect(ui.iconClear()).toBe(false);
  });
});
