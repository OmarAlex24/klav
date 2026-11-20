// @vitest-environment jsdom
// Layer 09, the content script (`content/index.ts`) with a fake `chrome`:
// it reports only the person's own submits, binds the popup's and agents'
// fills to its document, the top card's token to the form it reported (and
// to one fill), and a generated password to the field's own container.
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import type { ToContent } from "../src/shared/messages";

type Listener = (message: ToContent, sender: { id: string }, reply: (r?: unknown) => void) => boolean | undefined;

/** Everything the content script sent to the background. */
const sent: Record<string, unknown>[] = [];
const menuIds: string[] = [];
let listener: Listener | undefined;

const chrome = (globalThis as unknown as { chrome: Record<string, unknown> }).chrome;
Object.assign(chrome, {
  runtime: {
    id: "klav",
    getURL: (path: string) => `chrome-extension://klav/${path}`,
    sendMessage: (message: Record<string, unknown>) => {
      sent.push(message);
      if (message.type === "menu_open") {
        const id = `menu-${String(sent.length)}`;
        menuIds.push(id);
        return Promise.resolve({ ok: true, value: { menuId: id } });
      }
      return Promise.resolve({ ok: true, value: null });
    },
    onMessage: {
      addListener: (l: Listener) => {
        listener = l;
      },
    },
  },
});

/** Sends a message from the background; returns what the content script answered (or `undefined`). */
function deliver(message: ToContent): unknown {
  let answer: unknown;
  listener?.(message, { id: "klav" }, (r) => {
    answer = r;
  });
  return answer;
}

function byId(id: string): HTMLInputElement {
  const el = document.getElementById(id);
  if (!el) throw new Error(`no #${id}`);
  return el as HTMLInputElement;
}

async function sentOf(type: string): Promise<Record<string, unknown>> {
  return vi.waitFor(() => {
    const m = sent.find((x) => x.type === type);
    if (!m) throw new Error(`no ${type} yet`);
    return m;
  });
}

const login = () => [
  { name: "username", kind: "username" as const, value: "ana" },
  { name: "password", kind: "password" as const, value: "MARKER-pw" },
];

let doc = "";

/** Parses markup into nodes of this document (never through `innerHTML`). */
function nodes(markup: string): Node[] {
  const parsed = new DOMParser().parseFromString(markup, "text/html");
  return [...parsed.body.childNodes].map((n) => document.importNode(n, true));
}

// The in-page UI samples its frames with an interval; clear it before jsdom
// goes away, or a late tick reads a `window` that no longer exists.
const intervals: ReturnType<typeof setInterval>[] = [];
const realSetInterval = globalThis.setInterval;

afterAll(() => {
  for (const h of intervals) clearInterval(h);
  vi.restoreAllMocks();
});

beforeAll(async () => {
  vi.spyOn(globalThis, "setInterval").mockImplementation(((...args: Parameters<typeof setInterval>) => {
    const h = realSetInterval(...args);
    intervals.push(h);
    return h;
  }) as typeof setInterval);
  // jsdom has no layout: every element a normal box on screen.
  HTMLElement.prototype.getBoundingClientRect = function () {
    return { left: 10, top: 10, width: 200, height: 30, right: 210, bottom: 40, x: 10, y: 10, toJSON: () => ({}) };
  };
  document.body.replaceChildren(...nodes(`<form id=login action=/session><input id=u autocomplete=username><input id=p type=password><button id=go>Entrar</button></form>`));
  await import("../src/content/index");
  // The document's ID, as it tells the background.
  deliver({ type: "where", nonce: "n1" });
  doc = String((await sentOf("here")).doc);
});

describe("saving", () => {
  it("ignores a submit the page fakes with requestSubmit()", () => {
    byId("u").value = "ana";
    byId("p").value = "MARKER-pw";
    const form = document.getElementById("login") as HTMLFormElement;
    const stop = (e: Event): void => {
      e.preventDefault();
    };
    form.addEventListener("submit", stop);
    form.requestSubmit();
    form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    form.removeEventListener("submit", stop);
    expect(sent.filter((m) => m.type === "submit_seen")).toEqual([]);
  });
});

describe("binding fills to this document", () => {
  it("fills from the popup only into the document it was told about", () => {
    byId("u").value = "";
    byId("p").value = "";
    expect(deliver({ type: "popup_fill", doc: "another-document", kind: "login", values: login() })).toBeUndefined();
    expect([byId("u").value, byId("p").value]).toEqual(["", ""]);
    expect(deliver({ type: "popup_fill", doc, kind: "login", values: login() })).toMatchObject({ filled: ["username", "password"] });
    expect(byId("p").value).toBe("MARKER-pw");
  });

  it("fills for an agent only into the document whose address was checked", () => {
    byId("u").value = "";
    byId("p").value = "";
    const fill = (d: string): unknown =>
      deliver({ type: "agent_fill", doc: d, kind: "login", values: login(), noticeId: "n", selectors: [], submit: false });
    expect(fill("another-document")).toBeUndefined();
    expect(byId("p").value).toBe("");
    expect(fill(doc)).toMatchObject({ filled: ["username", "password"] });
  });
});

describe("the top card's form", () => {
  it("fills the form it reported, once", async () => {
    const token = String((await sentOf("login_seen")).token);
    byId("u").value = "";
    byId("p").value = "";
    expect(deliver({ type: "fill", token, kind: "login", values: login() })).toMatchObject({ filled: ["username", "password"] });
    // Used: the same token fills nothing more.
    byId("p").value = "";
    expect(deliver({ type: "fill", token, kind: "login", values: login() })).toBeUndefined();
    expect(byId("p").value).toBe("");
  });
});

describe("a generated password", () => {
  it("goes only into the field's own container, not every new-password box of the page", async () => {
    document.body.append(
      ...nodes(`<div id=mine><input id=n1 type=password autocomplete=new-password><input id=n2 type=password autocomplete=new-password></div>
       <section><div><div><div><div><div><input id=other type=password autocomplete=new-password></div></div></div></div></div></section>`),
    );
    byId("n1").focus();
    deliver({ type: "shortcut" });
    expect((await sentOf("menu_open")).role).toBe("new-password");
    const menuId = await vi.waitFor(() => {
      const id = menuIds.at(-1);
      if (!id) throw new Error("not yet");
      return id;
    });
    // Wait for the menu to be registered as this field's.
    await new Promise((r) => setTimeout(r, 0));
    expect(deliver({ type: "fill_generated", menuId, value: "MARKER-gen" })).toEqual({ filled: 2 });
    expect([byId("n1").value, byId("n2").value, byId("other").value]).toEqual(["MARKER-gen", "MARKER-gen", ""]);
  });
});
