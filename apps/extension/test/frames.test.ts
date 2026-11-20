// @vitest-environment jsdom
// Layer 09, Klav's own pages: the generator history only acts on clicks
// its guard accepts and asks before «Borrar el historial»; the popup's
// «Sitios añadidos por un agente» confirms (twice) or removes them all.
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { ItemView } from "../src/shared/protocol";

vi.mock("../src/shared/wasm", () => ({ klavCore: () => Promise.reject(new Error("no wasm in tests")) }));

const asked: Record<string, unknown>[] = [];
const chrome = (globalThis as unknown as { chrome: Record<string, unknown> }).chrome;
Object.assign(chrome, {
  runtime: {
    id: "klav",
    getURL: (path: string) => `chrome-extension://klav/${path}`,
    sendMessage: (message: { type: string; request?: { op: string } }) => {
      asked.push(message.request ?? message);
      const op = message.request?.op;
      const value = op === "generator_history" ? [{ created_at: 1_700_000_000_000, host: "site.example", pending: false }] : null;
      return Promise.resolve({ ok: true, value });
    },
  },
  storage: { local: { get: () => Promise.resolve({}) } },
});

const ops = (): unknown[] => asked.map((m) => (m as { op?: string }).op);

beforeEach(() => {
  asked.length = 0;
  document.body.replaceChildren();
});

function button(root: ParentNode, text: string | RegExp): HTMLButtonElement {
  const b = [...root.querySelectorAll("button")].find((x) => (typeof text === "string" ? x.textContent === text : text.test(x.getAttribute("aria-label") ?? x.textContent)));
  if (!b) throw new Error(`no button ${String(text)}`);
  return b;
}

describe("the generator history", () => {
  async function panel(guard: (e: Event) => boolean): Promise<HTMLElement> {
    const { historyPanel } = await import("../src/ui/generator");
    const el = await historyPanel({ say: () => undefined, resized: () => undefined, copy: () => Promise.resolve(), back: () => undefined, guard });
    document.body.append(el);
    asked.length = 0;
    return el;
  }

  it("copies and clears nothing on a click its guard refuses (a covered frame)", async () => {
    const el = await panel(() => false);
    button(el, /Copy/).click();
    button(el, "Delete history").click();
    await Promise.resolve();
    expect(ops()).toEqual([]);
    expect(el.textContent).not.toContain("Delete all");
  });

  it("asks before clearing everything", async () => {
    const el = await panel(() => true);
    button(el, "Delete history").click();
    await Promise.resolve();
    expect(ops()).toEqual([]);
    expect(el.textContent).toContain("Delete the whole generator history?");
    button(el, "Cancel").click();
    expect(el.textContent).not.toContain("Delete the whole generator history?");
    button(el, "Delete history").click();
    button(el, "Delete all").click();
    await Promise.resolve();
    expect(asked).toEqual([{ op: "generator_delete", which: "all" }]);
  });
});

describe("sites an agent added", () => {
  const view = (pending: string[]): ItemView =>
    ({ id: "i1", title: "Banco", urls: ["https://banco.example", ...pending], confirmed_urls: ["https://banco.example"], pending_urls: pending }) as unknown as ItemView;

  it("shows nothing without them", async () => {
    const { agentSites } = await import("../src/ui/agentsites");
    expect(agentSites(view([]), { changed: () => undefined, failed: () => undefined })).toBeNull();
  });

  it("ignores clicks that are not the person's", async () => {
    const { agentSites } = await import("../src/ui/agentsites");
    const el = agentSites(view(["https://evil.example"]), { changed: () => undefined, failed: () => undefined });
    if (!el) throw new Error("no section");
    button(el, "Confirm").click();
    button(el, "Remove").click();
    expect(asked).toEqual([]);
  });

  it("confirms after a second click that names the sites, and removes them all at once", async () => {
    const { agentSites } = await import("../src/ui/agentsites");
    const changed = vi.fn();
    const el = agentSites(view(["https://evil.example", "https://other.example/x"]), { changed, failed: () => undefined, trusted: () => true });
    if (!el) throw new Error("no section");
    expect(el.textContent).toContain("evil.example, other.example");
    button(el, "Confirm").click();
    expect(asked).toEqual([]);
    expect(el.textContent).toContain("Klav will fill this login on evil.example, other.example");
    button(el, "Yes, confirm").click();
    expect(asked).toEqual([{ op: "edit", query: "i1", patch: { set: [], remove: [], add_urls: [], add_tags: [] } }]);
    asked.length = 0;
    const again = agentSites(view(["https://evil.example", "https://other.example/x"]), { changed, failed: () => undefined, trusted: () => true });
    if (!again) throw new Error("no section");
    button(again, "Remove").click();
    expect(asked).toEqual([
      { op: "edit", query: "i1", patch: { set: [], remove: [], add_urls: [], add_tags: [], remove_urls: ["https://evil.example", "https://other.example/x"] } },
    ]);
  });
});

describe("the save bar", () => {
  it("saves nothing on a submit that is not the person's", async () => {
    asked.length = 0;
    const edge = document.createElement("div");
    edge.className = "frame-edge";
    const main = document.createElement("main");
    main.id = "save";
    document.body.replaceChildren(edge, main);
    location.hash = "#save-1";
    (globalThis as unknown as { ResizeObserver: unknown }).ResizeObserver = class {
      observe(): void {}
    };
    // The guard reads the clock when it loads and ignores the first 400 ms.
    // The test owns that clock: on a slow runner the real one would arm the
    // bar before the "early" submit below.
    let now = 0;
    const clock = vi.spyOn(performance, "now").mockImplementation(() => now);
    const send = (chrome.runtime as { sendMessage: unknown }).sendMessage;
    (chrome.runtime as { sendMessage: unknown }).sendMessage = (message: { type: string }) => {
      asked.push(message);
      if (message.type === "save_load") {
        return Promise.resolve({
          ok: true,
          value: {
            status: { logged_in: true, unlocked: true, touch_id: { available: false, enrolled: false } },
            host: "site.example",
            username: "ana",
            updates: [
              { id: "a", kind: "login", title: "Site", username: "ana", location: "Personal / General" },
              { id: "b", kind: "login", title: "Site", username: "ana", location: "Trabajo / Web" },
            ],
          },
        });
      }
      if (message.type === "save_do") {
        return Promise.resolve({ ok: true, value: { id: "b", kind: "login", title: "Site", username: "ana", urls: ["https://site.example"] } });
      }
      return Promise.resolve({ ok: true, value: null });
    };
    const saves = (): unknown[] => asked.filter((m) => m.type === "save_do");
    try {
      await import("../src/ui/save");
      const form = await vi.waitFor(() => {
        const f = document.querySelector("form");
        if (!f) throw new Error("not yet");
        return f;
      });
      // Two logins of the site with this username: the bar asks which one.
      const which = form.querySelector("select");
      expect([...(which?.options ?? [])].map((o) => o.text)).toEqual(["Choose the login to update", "Site · Personal / General", "Site · Trabajo / Web"]);
      if (which) which.value = "b";
      // jsdom marks requestSubmit's event trusted, like the person's Enter:
      // in the first 400 ms it still does not count.
      now = 100;
      form.requestSubmit();
      // Armed, a submit the page makes up (untrusted) does not count either.
      now = 10_000;
      form.dispatchEvent(new Event("submit", { cancelable: true }));
      await Promise.resolve();
      expect(saves()).toEqual([]);
      // The same trusted submit once armed does save: the guard refused both above.
      form.requestSubmit();
      expect(saves()).toEqual([{ type: "save_do", saveId: "save-1", action: "update", item: "b" }]);
      await vi.waitFor(() => {
        expect(document.body.textContent).toContain("Saved to Klav: Site");
      });
    } finally {
      clock.mockRestore();
      (chrome.runtime as { sendMessage: unknown }).sendMessage = send;
    }
  });
});
