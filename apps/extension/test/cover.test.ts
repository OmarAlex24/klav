// @vitest-environment jsdom
// Layer 09 (T62): Klav's frames inside a page only count as seen when the
// page leaves them alone, checked from the content script in every browser
// (IntersectionObserver v2 exists only in Chromium, and jsdom has none, as
// Firefox): shown for 400 ms, nothing after the host in <html>, nothing in
// the top layer, <html> not faded or transformed, the host not restyled or
// moved, the frame where Klav put it, and none of that in the last 300 ms.
import { afterEach, beforeEach, describe, expect, it, type MockInstance, vi } from "vitest";
import { InPage } from "../src/content/ui";

const chrome = (globalThis as unknown as { chrome: Record<string, unknown> }).chrome;
Object.assign(chrome, { runtime: { id: "klav", getURL: (path: string) => `chrome-extension://klav/${path}` } });

/** Frames, the glyph and the host lie where their inline style puts them (jsdom has no layout). */
let shift = 0;
/** Where the field is, from the top of the window (jsdom's is 768 px tall). */
let fieldTop = 10;
HTMLElement.prototype.getBoundingClientRect = function (this: HTMLElement) {
  const px = (v: string): number => Number.parseFloat(v) || 0;
  const width = this.localName === "input" ? 200 : px(this.style.width);
  const height = this.localName === "input" ? 30 : px(this.style.height);
  const left = this.localName === "input" ? 10 : px(this.style.left) + shift;
  const top = this.localName === "input" ? fieldTop : this.style.top !== "" ? px(this.style.top) : innerHeight - px(this.style.bottom) - height;
  return { left, top, width, height, right: left + width, bottom: top + height, x: left, y: top, toJSON: () => ({}) };
};

// jsdom does not compute pseudo-elements (`html::after`): none here.
const computed = window.getComputedStyle.bind(window);
window.getComputedStyle = (el: Element, pseudo?: string | null) =>
  pseudo ? ({ content: "none", position: "static" } as CSSStyleDeclaration) : computed(el);

let ui: InPage;
let created: MockInstance<(tag: string) => HTMLElement>;

beforeEach(() => {
  vi.useFakeTimers();
  // Every element Klav makes: its shadow root is closed, so tests find its frames here.
  created = vi.spyOn(document, "createElement");
  shift = 0;
  fieldTop = 10;
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
  vi.restoreAllMocks();
});

/** Makes `document.querySelector(selector)` find `el` (jsdom has no top layer). */
function inTopLayer(selector: ":modal" | ":popover-open", el: Element): void {
  vi.spyOn(document, "querySelector").mockImplementation((s: string) => (s === selector ? el : document.documentElement.querySelector(s)));
}

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

describe("a page that covers Klav (T62) still gets nothing", () => {
  it("does not count with a modal <dialog>, wherever it is", () => {
    ui.show("card", "c1");
    vi.advanceTimersByTime(450);
    expect(ui.isClear("card", "c1")).toBe(true);
    const dialog = document.createElement("dialog");
    document.body.append(dialog);
    inTopLayer(":modal", dialog);
    expect(ui.isClear("card", "c1")).toBe(false);
  });

  it("does not count with an open popover, even a small one away from the frame", () => {
    // Its paint is not bounded by its box (fixed children, shadows, its
    // ::backdrop), and Chromium's own check counts it too.
    ui.show("card", "c1");
    vi.advanceTimersByTime(450);
    const toast = document.createElement("div");
    toast.setAttribute("popover", "manual");
    toast.setAttribute("style", "position: fixed; right: 8px; bottom: 8px; width: 120px; height: 30px");
    document.body.append(toast);
    inTopLayer(":popover-open", toast);
    expect(ui.isClear("card", "c1")).toBe(false);
  });

  it("does not count with a 0×0 node after the host whose child covers everything", async () => {
    ui.show("menu", "m1");
    vi.advanceTimersByTime(450);
    const wrapper = document.createElement("div");
    wrapper.setAttribute("style", "width: 0; height: 0");
    const veil = document.createElement("div");
    veil.setAttribute("style", "position: fixed; inset: 0; pointer-events: none");
    wrapper.append(veil);
    document.documentElement.append(wrapper);
    await settle();
    expect(ui.isClear("menu", "m1")).toBe(false);
    // Klav does not move its host while a frame is open (its frame would reload).
    expect(document.documentElement.lastElementChild).toBe(wrapper);
  });

  it("without moveBefore, does not move its host while a frame is open (it would reload), even to open another", () => {
    ui.show("card", "c1");
    vi.advanceTimersByTime(450);
    const decoy = document.createElement("div");
    decoy.setAttribute("style", "position: fixed; inset: 0; pointer-events: none");
    document.documentElement.append(decoy);
    ui.show("save", "s1");
    vi.advanceTimersByTime(450);
    expect(document.documentElement.lastElementChild).toBe(decoy);
    expect(ui.isClear("save", "s1")).toBe(false);
    expect(ui.isClear("card", "c1")).toBe(false);
  });
});

describe("a page that leaves Klav alone", () => {
  it("does not keep refusing because of a node that came after the host before the menu opened", () => {
    // The host is made with the glyph, on focus; another extension (or the
    // page) appends its own element to <html> afterwards.
    const field = document.getElementById("field") as HTMLInputElement;
    ui.showIcon(field);
    const other = document.createElement("other-extension");
    document.documentElement.append(other);
    expect(ui.iconClear()).toBe(false);
    // Opening the menu puts Klav's host back at the end, before its frame exists.
    ui.show("menu", "m1");
    expect(document.documentElement.lastElementChild).toBe(host());
    expect(other.isConnected).toBe(true);
    vi.advanceTimersByTime(450);
    expect(ui.isClear("menu", "m1")).toBe(true);
    expect(ui.iconClear()).toBe(true);
  });

  it("with moveBefore (Chromium), moves its host past such a node with frames open, and they count only after a moment", () => {
    const moves: Node[] = [];
    const proto = Element.prototype as Element & { moveBefore?: (node: Node, child: Node | null) => void };
    proto.moveBefore = function (this: Element, node: Node, child: Node | null) {
      moves.push(node);
      this.insertBefore(node, child);
    };
    try {
      ui.show("card", "c1");
      vi.advanceTimersByTime(450);
      const card = frameOf();
      const other = document.createElement("other-extension");
      document.documentElement.append(other);
      expect(ui.isClear("card", "c1")).toBe(false);
      ui.show("save", "s1");
      expect(moves).toEqual([host()]);
      expect(document.documentElement.lastElementChild).toBe(host());
      // The card's frame is the same one, not a new one.
      expect(card.isConnected).toBe(true);
      expect(ui.isClear("card", "c1")).toBe(false);
      vi.advanceTimersByTime(250);
      expect(ui.isClear("card", "c1")).toBe(false);
      vi.advanceTimersByTime(100);
      expect(ui.isClear("card", "c1")).toBe(true);
      // The save bar, new, waits its own 400 ms.
      expect(ui.isClear("save", "s1")).toBe(false);
      vi.advanceTimersByTime(100);
      expect(ui.isClear("save", "s1")).toBe(true);
      // A decoy that comes after that still counts.
      const decoy = document.createElement("div");
      decoy.setAttribute("style", "position: fixed; inset: 0; pointer-events: none");
      document.documentElement.append(decoy);
      expect(ui.isClear("card", "c1")).toBe(false);
    } finally {
      Reflect.deleteProperty(proto, "moveBefore");
    }
  });

  it("never moves its host past the passkey bridge's own host, only past other nodes", () => {
    // The passkey bridge (webauthn.ts) draws Klav's passkey frame in a host of its own.
    const bridge = new InPage(
      () => undefined,
      () => undefined,
    );
    try {
      const field = document.getElementById("field") as HTMLInputElement;
      ui.showIcon(field);
      const own = host();
      const other = document.createElement("other-extension");
      document.documentElement.append(other);
      bridge.show("passkey", "p1", true);
      const hosts = (): Element[] => [...document.documentElement.children].filter((e) => e !== document.head && e !== document.body);
      const [, , passkeyHost] = hosts();
      expect(hosts()).toEqual([own, other, passkeyHost]);
      expect(passkeyHost?.localName).toBe("klav-ui");
      vi.advanceTimersByTime(450);
      expect(bridge.isClear("passkey", "p1")).toBe(true);
      // The field is focused again (the glyph): Klav's host passes the other
      // extension's node, and stops before the bridge's host.
      ui.showIcon(field);
      expect(hosts()).toEqual([other, own, passkeyHost]);
      expect(bridge.isClear("passkey", "p1")).toBe(true);
    } finally {
      bridge.hide("passkey");
    }
  });

  it("puts its host back at the end when the glyph shows again", () => {
    const field = document.getElementById("field") as HTMLInputElement;
    ui.showIcon(field);
    document.documentElement.append(document.createElement("other-extension"));
    expect(ui.iconClear()).toBe(false);
    ui.showIcon(field);
    expect(document.documentElement.lastElementChild).toBe(host());
    expect(ui.iconClear()).toBe(true);
  });

  it("keeps a menu inside the window when neither side of the field has room for all of it", () => {
    // 768 px of window, the field in the middle: 360 px above, 378 below.
    fieldTop = 360;
    const field = document.getElementById("field") as HTMLInputElement;
    ui.showIcon(field);
    ui.show("menu", "m1");
    // The list wants 380 px (the most a menu has); cut by the window it
    // would count as covered and refuse every click, so it gets the room.
    ui.size("menu", "m1", 380);
    const box = frameOf().getBoundingClientRect();
    expect(box.height).toBe(366);
    expect(box.bottom).toBeLessThanOrEqual(innerHeight);
    expect(box.top).toBeGreaterThanOrEqual(0);
    vi.advanceTimersByTime(450);
    expect(ui.isClear("menu", "m1")).toBe(true);
  });

  it("gives a short menu the height it asks for", () => {
    fieldTop = 360;
    ui.showIcon(document.getElementById("field") as HTMLInputElement);
    ui.show("menu", "m1");
    ui.size("menu", "m1", 172);
    expect(frameOf().getBoundingClientRect().height).toBe(172);
  });
});

/** The only frame Klav shows. */
function frameOf(): HTMLIFrameElement {
  const frames = created.mock.results.map((r) => r.value as unknown).filter((el): el is HTMLIFrameElement => el instanceof HTMLIFrameElement && el.isConnected);
  const [frame] = frames;
  if (frames.length !== 1 || !frame) throw new Error(`${String(frames.length)} frames`);
  return frame;
}
