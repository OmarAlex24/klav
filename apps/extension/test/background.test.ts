// Layer 09, the background (`background/index.ts`) with a fake `chrome`,
// klavd and klav-core: each page asks klavd only for what it shows, a
// login of another site is never filled into plain http, the popup's fill
// names its document, choices wait for the page to leave the frame alone,
// and a login waiting to be saved (or «Add this site», after a login saved
// for a subdomain) stays with its tab and its site.
import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { DaemonError, type ErrorCode, type Request } from "../src/shared/protocol";

type Handler = (request: Request) => unknown;
const calls: Request[] = [];
let daemon: Handler = () => null;

vi.mock("../src/background/native", () => ({
  NativeBridge: class {
    onEvent(): void {}
    onDisconnect(): void {}
    call(request: Request): Promise<unknown> {
      calls.push(request);
      try {
        return Promise.resolve(daemon(request));
      } catch (e) {
        return Promise.reject(e instanceof Error ? e : new Error(String(e)));
      }
    }
  },
}));

/** How long klav-core takes to answer: a service worker that just woke loads its WebAssembly first. */
let coreDelayMs = 0;

/** klav-core's site rule, enough for these tests: https, or http on this machine. */
vi.mock("../src/shared/wasm", () => ({
  klavCore: async () => {
    if (coreDelayMs > 0) await new Promise((r) => setTimeout(r, coreDelayMs));
    return {
      fillableHost(url: string): string | undefined {
        const u = new URL(url);
        if (u.protocol === "https:") return u.hostname;
        return u.protocol === "http:" && (u.hostname === "localhost" || u.hostname === "127.0.0.1") ? u.hostname : undefined;
      },
      hostRelation(host: string, urls: string[]): string | undefined {
        const hosts = urls.map((u) => new URL(u).hostname);
        if (hosts.includes(host)) return "exact";
        if (hosts.some((h) => host.endsWith(`.${h}`))) return "subdomain";
        return hosts.some((h) => h.endsWith(`.${host}`)) ? "parent" : undefined;
      },
    };
  },
}));

type Sender = { id: string; url?: string; tab?: { id: number }; frameId?: number; documentId?: string };
type Listener = (message: unknown, sender: Sender, reply: (r: unknown) => void) => boolean;
let listener: Listener | undefined;
let removed: ((tabId: number) => void) | undefined;
/** Where each tab is, as the browser says. */
const tabUrl = new Map<number, string>();
/** What each tab's content script answers to `clear`. */
let clear = true;
const toTabs: { tabId: number; message: Record<string, unknown> }[] = [];

const chrome = (globalThis as unknown as { chrome: Record<string, unknown> }).chrome;
Object.assign(chrome, {
  runtime: {
    id: "klav",
    getURL: (path: string) => `chrome-extension://klav/${path}`,
    onMessage: {
      addListener: (l: Listener) => {
        listener = l;
      },
    },
  },
  tabs: {
    query: () => Promise.resolve([{ id: 3 }]),
    onRemoved: {
      addListener: (l: (tabId: number) => void) => {
        removed = l;
      },
    },
    sendMessage: (tabId: number, message: Record<string, unknown>) => {
      toTabs.push({ tabId, message });
      switch (message.type) {
        case "clear":
          return Promise.resolve(clear);
        case "where":
          // The top frame answers with `here`, as the content script does.
          setTimeout(() => {
            listener?.({ type: "here", nonce: message.nonce, doc: `DOC-${String(tabId)}` }, content(tabId), () => undefined);
          }, 0);
          return Promise.resolve(undefined);
        case "fill":
        case "popup_fill":
          return Promise.resolve({ filled: ["password"] });
        default:
          return Promise.resolve(undefined);
      }
    },
  },
  commands: { onCommand: { addListener: () => undefined } },
  alarms: { onAlarm: { addListener: () => undefined } },
  windows: { getLastFocused: () => Promise.resolve({ focused: true }) },
  storage: { local: { get: () => Promise.resolve({}) } },
});

function content(tabId: number, frameId = 0): Sender {
  return { id: "klav", url: tabUrl.get(tabId) ?? "https://site.example/login", tab: { id: tabId }, frameId, documentId: `doc-${String(tabId)}` };
}

function page(name: string, hash = ""): Sender {
  return { id: "klav", url: `chrome-extension://klav/${name}${hash}` };
}

type Reply = { ok: true; value: unknown } | { ok: false; error: { code: string; message: string } };

function send(message: Record<string, unknown>, sender: Sender): Promise<Reply> {
  return new Promise((resolve) => {
    listener?.(message, sender, (r) => {
      resolve(r as Reply);
    });
  });
}

async function value<T>(message: Record<string, unknown>, sender: Sender): Promise<T> {
  const reply = await send(message, sender);
  if (!reply.ok) throw new Error(`${reply.error.code}: ${reply.error.message}`);
  return reply.value as T;
}

const unlocked = { logged_in: true, unlocked: true, touch_id: { available: false, enrolled: false } };

beforeAll(async () => {
  await import("../src/background/index");
});

beforeEach(() => {
  calls.length = 0;
  toTabs.length = 0;
  clear = true;
  daemon = () => null;
  coreDelayMs = 0;
});

describe("what each page may ask klavd", () => {
  it("lets frames inside pages ask only for what they show", async () => {
    const reveal: Request = { op: "view", query: "Banco", reveal: true };
    for (const name of ["menu.html#m", "find.html#f", "save.html#s", "passkey.html#p", "card.html#c", "notice.html#n"]) {
      const reply = await send({ type: "daemon", request: reveal }, page(name));
      expect(reply.ok, name).toBe(false);
    }
    expect((await send({ type: "daemon", request: { op: "totp", query: "Banco" } }, page("menu.html#m"))).ok).toBe(false);
    expect((await send({ type: "daemon", request: { op: "status" } }, page("card.html#c"))).ok).toBe(false);
    expect(calls).toEqual([]);
  });

  it("lets the popup ask what the native host allows, and the menu use its generator", async () => {
    await value({ type: "daemon", request: { op: "view", query: "Banco", reveal: true } }, page("popup.html"));
    await value({ type: "daemon", request: { op: "generator_history" } }, page("menu.html#m"));
    await value({ type: "daemon", request: { op: "list", filter: { trash: false } } }, page("find.html#f"));
    await value({ type: "daemon", request: { op: "unlock" } }, page("passkey.html#p"));
    expect(calls.map((c) => c.op)).toEqual(["view", "generator_history", "list", "unlock"]);
  });

  it("marks an unlock as for a passkey only from Klav's passkey frame (ADR 0020 §8)", async () => {
    const flow = (r: Request): unknown => (r as { passkey_flow?: unknown }).passkey_flow;
    await value({ type: "daemon", request: { op: "unlock", password: "pw" } }, page("passkey.html#p"));
    // Whatever another page puts in the request, it is not that frame.
    await value({ type: "daemon", request: { op: "unlock", passkey_flow: true } }, page("menu.html#m"));
    await value({ type: "daemon", request: { op: "unlock", passkey_flow: true } }, page("popup.html"));
    expect(calls.map(flow)).toEqual([true, false, false]);
    expect(calls[0]).toMatchObject({ op: "unlock", password: "pw" });
  });
});

describe("the passkey frame", () => {
  it("signs only while the page leaves the frame alone (T62)", async () => {
    tabUrl.set(7, "https://shop.example/login");
    daemon = (r) => {
      if (r.op === "status") return unlocked;
      if (r.op === "passkey_candidates") return { rp_id: "shop.example", candidates: [{ item: "i1", title: "Shop", user_name: "ana" }] };
      if (r.op === "passkey_get") return { credential_id: "AA", client_data_json: "AA", authenticator_data: "AA", signature: "AA", user_handle: "AA", item: "i1" };
      return null;
    };
    const call = { kind: "get", rp_id: "shop.example", challenge: "A".repeat(22), allow: [] };
    const reply = await value<{ pending: string }>({ type: "passkey_request", call, same_origin_as_top: true }, content(7));
    const passkeyId = reply.pending;
    clear = false;
    const covered = await send({ type: "passkey_sign_in", passkeyId, item: "i1" }, page("passkey.html", `#${passkeyId}`));
    expect(covered).toMatchObject({ ok: false, error: { code: "covered" } });
    expect(calls.some((c) => c.op === "passkey_get")).toBe(false);
    clear = true;
    await value({ type: "passkey_sign_in", passkeyId, item: "i1" }, page("passkey.html", `#${passkeyId}`));
    expect(calls.filter((c) => c.op === "passkey_get")).toHaveLength(1);
    expect(toTabs.some((t) => t.message.type === "clear" && t.message.surface === "passkey")).toBe(true);
  });
});

describe("the top card and the passkey frame (same corner)", () => {
  it("closes the card when the frame opens, and offers none while it is open", async () => {
    tabUrl.set(9, "https://shop.example/login");
    const login = { id: "i1", kind: "login", title: "Shop", username: "ana", location: "Personal / General" };
    daemon = (r) => {
      if (r.op === "status") return unlocked;
      if (r.op === "suggest") return { host: "shop.example", logins: [login], cards: [], identities: [] };
      if (r.op === "passkey_candidates") return { rp_id: "shop.example", candidates: [{ item: "i1", title: "Shop", user_name: "ana" }] };
      return null;
    };
    const shown = (surface: string) => toTabs.filter((t) => t.tabId === 9 && t.message.type === "show" && t.message.surface === surface);
    const hidden = (surface: string) => toTabs.filter((t) => t.tabId === 9 && t.message.type === "hide" && t.message.surface === surface);
    await value({ type: "login_seen", token: "t".repeat(16) }, content(9));
    await vi.waitFor(() => {
      expect(shown("card")).toHaveLength(1);
    });
    const call = { kind: "get", rp_id: "shop.example", challenge: "A".repeat(22), allow: [] };
    const { pending } = await value<{ pending: string }>({ type: "passkey_request", call, same_origin_as_top: true }, content(9));
    expect(hidden("card")).toHaveLength(1);
    // The page reports its form again (the tab came back to the front): no card over the frame.
    await value({ type: "login_seen", token: "u".repeat(16) }, content(9));
    await new Promise((r) => setTimeout(r, 20));
    expect(shown("card")).toHaveLength(1);
    // Closed for now, not dismissed: with the frame gone, the card comes back.
    await value({ type: "close", surface: "passkey", id: pending }, page("passkey.html", `#${pending}`));
    await value({ type: "login_seen", token: "v".repeat(16) }, content(9));
    await vi.waitFor(() => {
      expect(shown("card")).toHaveLength(2);
    });
  });
});

describe("a login of another site, confirmed in the palette", () => {
  it("never goes into a plain http page", async () => {
    tabUrl.set(2, "http://evil.example/login");
    const { findId } = await value<{ findId: string }>({ type: "find_open" }, content(2));
    daemon = (r) => {
      if (r.op === "suggest") return { logins: [], cards: [], identities: [] };
      if (r.op === "autofill") throw new DaemonError("denied", "not this site");
      if (r.op === "view") return { id: "i1", kind: "login", title: "Banco", fields: [{ name: "password", kind: "password", filled: true, value: "MARKER" }] };
      return null;
    };
    await new Promise((r) => setTimeout(r, 0));
    const reply = await send({ type: "find_fill", findId, item: "i1", confirmed: true }, page("find.html", `#${findId}`));
    expect(reply).toMatchObject({ ok: false, error: { code: "denied" } });
    expect(calls.some((c) => c.op === "view")).toBe(false);
    expect(toTabs.some((t) => t.message.type === "fill")).toBe(false);
  });
});

describe("the popup's fill", () => {
  it("names the document whose address klavd checked", async () => {
    tabUrl.set(3, "https://site.example/login");
    daemon = (r) =>
      r.op === "autofill" ? { id: "i1", kind: "login", title: "Sitio", fields: [{ name: "password", kind: "password", value: "MARKER" }] } : null;
    await value({ type: "popup_fill", item: "i1" }, page("popup.html"));
    const fill = toTabs.find((t) => t.message.type === "popup_fill");
    expect(fill?.message.doc).toBe("DOC-3");
  });
});

describe("choices in a frame the page covers", () => {
  it("fill nothing, and say why", async () => {
    tabUrl.set(6, "https://site.example/login");
    const { menuId } = await value<{ menuId: string }>({ type: "menu_open", groups: ["login"], role: "login" }, content(6));
    clear = false;
    const reply = await send({ type: "menu_fill", menuId, item: "i1" }, page("menu.html", `#${menuId}`));
    expect(reply).toMatchObject({ ok: false, error: { code: "covered" } });
    expect(calls.some((c) => c.op === "autofill")).toBe(false);
    // The history's «Copiar» in that menu too.
    const copy = await send({ type: "daemon", request: { op: "generated_value", created_at: 1 } }, page("menu.html", `#${menuId}`));
    expect(copy).toMatchObject({ ok: false, error: { code: "covered" } });
    expect(calls).toEqual([]);
  });

  it("choose no passkey from the field menu (conditional mediation)", async () => {
    tabUrl.set(8, "https://shop.example/login");
    daemon = (r) => {
      if (r.op === "status") return unlocked;
      if (r.op === "passkey_candidates") return { rp_id: "shop.example", candidates: [{ item: "i1", title: "Shop", user_name: "ana" }] };
      return null;
    };
    const call = { kind: "get", rp_id: "shop.example", challenge: "A".repeat(22), allow: [], conditional: true };
    await value({ type: "passkey_request", call, same_origin_as_top: true }, content(8));
    const { menuId } = await value<{ menuId: string }>({ type: "menu_open", groups: ["login"], role: "login" }, content(8));
    toTabs.length = 0;
    clear = false;
    const reply = await send({ type: "menu_passkey", menuId, item: "i1" }, page("menu.html", `#${menuId}`));
    expect(reply).toMatchObject({ ok: false, error: { code: "covered" } });
    expect(toTabs.some((t) => t.message.type === "passkey_show")).toBe(false);
    clear = true;
    await value({ type: "menu_passkey", menuId, item: "i1" }, page("menu.html", `#${menuId}`));
    expect(toTabs.some((t) => t.message.type === "passkey_show")).toBe(true);
  });
});

describe("a login waiting to be saved", () => {
  async function submitted(tabId: number, username = "ana", password = "MARKER-new"): Promise<void> {
    await value({ type: "submit_seen", username, password }, content(tabId));
    await new Promise((r) => setTimeout(r, 0));
  }
  const pending = (tabId: number, url?: string): Promise<string | null> =>
    value<string | null>({ type: "save_pending" }, { ...content(tabId), ...(url ? { url } : {}) });

  it("keeps one save for the same login sent twice", async () => {
    tabUrl.set(10, "https://site.example/login");
    await submitted(10);
    const first = await pending(10);
    await submitted(10);
    expect(first).toEqual(expect.any(String));
    expect(await pending(10)).toBe(first);
  });

  it("is there for the next page even while klav-core still loads", async () => {
    // The form's page reports the login and navigates at once; the next
    // page asks before the background has the site rule (CI run
    // 42804447794: the bar never showed).
    tabUrl.set(11, "https://site.example/login");
    coreDelayMs = 50;
    const seen = send({ type: "submit_seen", username: "ana", password: "MARKER-new" }, content(11));
    const asked = pending(11);
    await seen;
    expect(await asked).toEqual(expect.any(String));
  });

  it("is not kept for a tab that closed while it was being recorded", async () => {
    tabUrl.set(12, "https://site.example/login");
    coreDelayMs = 50;
    await value({ type: "submit_seen", username: "ana", password: "MARKER-new" }, content(12));
    removed?.(12);
    await new Promise((r) => setTimeout(r, 100));
    expect(await pending(12)).toBeNull();
  });

  it("goes away with its tab", async () => {
    tabUrl.set(4, "https://site.example/login");
    await submitted(4);
    expect(await pending(4)).toEqual(expect.any(String));
    removed?.(4);
    expect(await pending(4)).toBeNull();
  });

  it("is offered only on its own site, and dropped elsewhere", async () => {
    tabUrl.set(5, "https://accounts.site.example/login");
    await submitted(5);
    // After signing in, another subdomain of the same name.
    expect(await pending(5, "https://www.site.example/")).toEqual(expect.any(String));
    expect(await pending(5, "https://evil.example/")).toBeNull();
    expect(await pending(5, "https://www.site.example/")).toBeNull();
  });

  it("updates only the login the person picked, when several have this username", async () => {
    tabUrl.set(7, "https://site.example/login");
    await submitted(7);
    const saveId = await pending(7);
    daemon = (r) => {
      if (r.op === "status") return unlocked;
      if (r.op === "suggest")
        return { logins: [{ id: "a", kind: "login", title: "Site", username: "ana", location: "Personal / General" }, { id: "b", kind: "login", title: "Site", username: "ana", location: "Trabajo / Web" }], cards: [], identities: [] };
      if (r.op === "autofill") return { id: r.item, kind: "login", title: "Site", fields: [{ name: "password", kind: "password", value: "old" }] };
      if (r.op === "edit") return { id: r.query, title: "Site" };
      return null;
    };
    const state = await value<{ updates: { id: string; location: string }[] }>({ type: "save_load", saveId }, page("save.html", `#${String(saveId)}`));
    expect(state.updates.map((u) => [u.id, u.location])).toEqual([
      ["a", "Personal / General"],
      ["b", "Trabajo / Web"],
    ]);
    const unpicked = await send({ type: "save_do", saveId, action: "update" }, page("save.html", `#${String(saveId)}`));
    expect(unpicked).toMatchObject({ ok: false, error: { code: "bad_request" } });
    await value({ type: "save_do", saveId, action: "update", item: "b" }, page("save.html", `#${String(saveId)}`));
    expect(calls.filter((c) => c.op === "edit").map((c) => (c as { query: string }).query)).toEqual(["b"]);
  });

  /**
   * klavd for these tests: two logins of the page with their usernames and
   * passwords, and one saved for a subdomain (never fetched to compare).
   */
  function siteWith(passwords: Record<string, string>, failing: Record<string, ErrorCode> = {}): void {
    daemon = (r) => {
      if (r.op === "status") return unlocked;
      if (r.op === "suggest")
        return {
          logins: [
            { id: "a", kind: "login", title: "Site", username: "ana", location: "Personal / General" },
            { id: "b", kind: "login", title: "Site (work)", username: "bea", location: "Work / Web" },
          ],
          parent: [{ id: "p", kind: "login", title: "Shop", username: "ana", location: "Personal / General", site: "shop.site.example" }],
          cards: [],
          identities: [],
        };
      const fails = r.op === "autofill" ? failing[r.item] : undefined;
      if (fails) throw new DaemonError(fails, "this login cannot be filled");
      if (r.op === "autofill") return { id: r.item, kind: "login", title: "Site", fields: [{ name: "password", kind: "password", value: passwords[r.item] ?? "" }] };
      if (r.op === "projects") return [{ id: "pr", vault_id: "v", vault: "Personal", name: "General" }];
      return null;
    };
  }
  const fetched = (): { item: string; chosen?: boolean }[] =>
    calls.filter((c) => c.op === "autofill").map((c) => c as unknown as { item: string; chosen?: boolean });

  it("offers nothing when the form sent no username and one of the site's logins has that password", async () => {
    // A password-only step (or a form whose account is not a visible box):
    // Klav itself may have typed that password.
    tabUrl.set(20, "https://site.example/login");
    await submitted(20, "", "MARKER-bea");
    const saveId = await pending(20);
    siteWith({ a: "MARKER-ana", b: "MARKER-bea", p: "MARKER-bea" });
    const state = await value<unknown>({ type: "save_load", saveId }, page("save.html", `#${String(saveId)}`));
    expect(state).toBeNull();
    // Only the page's own logins are compared, never a subdomain's, and never as the person's pick.
    expect(fetched().map((c) => c.item)).toEqual(["a", "b"]);
    expect(fetched().every((c) => c.chosen === undefined)).toBe(true);
    // Klav already has it: the save is gone.
    expect(await pending(20)).toBeNull();
  });

  it("still offers to create a login when the form sent no username and no login has that password", async () => {
    tabUrl.set(21, "https://site.example/login");
    await submitted(21, "", "MARKER-new");
    const saveId = await pending(21);
    siteWith({ a: "MARKER-ana", b: "MARKER-bea" });
    const state = await value<{ username: string; title?: string; projects?: unknown[]; updates?: unknown[] }>(
      { type: "save_load", saveId },
      page("save.html", `#${String(saveId)}`),
    );
    expect(state).toMatchObject({ username: "", title: "site.example", projects: [{ id: "pr" }] });
    expect(state.updates).toBeUndefined();
    expect(fetched().map((c) => c.item)).toEqual(["a", "b"]);
  });

  it("keeps the save with its username when the same password comes again without one", async () => {
    tabUrl.set(22, "https://site.example/login");
    await submitted(22, "ana", "MARKER-new");
    const first = await pending(22);
    // The same submit seen again from a scope whose account box is gone.
    await submitted(22, "", "MARKER-new");
    expect(await pending(22)).toBe(first);
    siteWith({ a: "MARKER-ana", b: "MARKER-bea" });
    const state = await value<{ username: string }>({ type: "save_load", saveId: first }, page("save.html", `#${String(first)}`));
    expect(state.username).toBe("ana");
    // A username may still fill in an empty one.
    await submitted(22, "", "MARKER-other");
    const empty = await pending(22);
    await submitted(22, "ana", "MARKER-other");
    const named = await pending(22);
    expect(named).toEqual(expect.any(String));
    expect(named).not.toBe(empty);
  });

  it("skips a login this device cannot fill, and compares the others", async () => {
    // `suggest` lists a login even when this device cannot open it; its
    // `autofill` fails. The bar still decides with the rest.
    tabUrl.set(24, "https://site.example/login");
    await submitted(24, "", "MARKER-bea");
    const known = await pending(24);
    siteWith({ b: "MARKER-bea" }, { a: "internal" });
    expect(await value<unknown>({ type: "save_load", saveId: known }, page("save.html", `#${String(known)}`))).toBeNull();
    expect(fetched().map((c) => c.item)).toEqual(["a", "b"]);
    // No login has it: the create offer, not an error.
    await submitted(24, "", "MARKER-new");
    const fresh = await pending(24);
    const state = await value<{ title?: string; projects?: unknown[] }>({ type: "save_load", saveId: fresh }, page("save.html", `#${String(fresh)}`));
    expect(state).toMatchObject({ title: "site.example", projects: [{ id: "pr" }] });
  });

  it("still fails when klavd locks while comparing", async () => {
    tabUrl.set(25, "https://site.example/login");
    await submitted(25, "", "MARKER-new");
    const saveId = await pending(25);
    siteWith({ b: "MARKER-bea" }, { a: "locked" });
    const reply = await send({ type: "save_load", saveId }, page("save.html", `#${String(saveId)}`));
    expect(reply).toMatchObject({ ok: false, error: { code: "locked" } });
    expect(fetched().map((c) => c.item)).toEqual(["a"]);
  });

  it("remembers a step-1 username for step 2 on the same site and allows editing username on create", async () => {
    tabUrl.set(26, "https://accounts.example.com/step1");
    await send({ type: "username_seen", username: "omar@example.com" }, content(26));
    tabUrl.set(26, "https://accounts.example.com/step2");
    await submitted(26, "", "MARKER-step2");
    const saveId = await pending(26);
    daemon = (r) => {
      if (r.op === "status") return unlocked;
      if (r.op === "suggest") return { logins: [], cards: [], identities: [] };
      if (r.op === "projects") return [{ id: "pr", vault_id: "v", vault: "Personal", name: "General" }];
      if (r.op === "list") return [];
      if (r.op === "create") return { id: "new1", title: r.item.title };
      return null;
    };
    const state = await value<{ username: string; title?: string }>({ type: "save_load", saveId }, page("save.html", `#${String(saveId)}`));
    expect(state.username).toBe("omar@example.com");
    expect(state.title).toBe("accounts.example.com");
    await value(
      { type: "save_do", saveId, action: "create", title: "Example", username: "edited@example.com", project: "Personal\u0000General" },
      page("save.html", `#${String(saveId)}`),
    );
    const created = calls.find((c) => c.op === "create") as { item: { fields: { name: string; value: string }[] } } | undefined;
    expect(created?.item.fields.find((f) => f.name === "username")?.value).toBe("edited@example.com");
  });

  it("suggests an available title when the default host title already exists and allows updating siteLogins", async () => {
    tabUrl.set(27, "https://site.example/login");
    await submitted(27, "otra", "MARKER-otra");
    const saveId = await pending(27);
    daemon = (r) => {
      if (r.op === "status") return unlocked;
      if (r.op === "suggest")
        return {
          logins: [{ id: "a", kind: "login", title: "site.example", username: "ana", location: "Personal / General" }],
          cards: [],
          identities: [],
        };
      if (r.op === "autofill") return { id: r.item, kind: "login", title: "site.example", fields: [{ name: "password", kind: "password", value: "old" }] };
      if (r.op === "projects") return [{ id: "pr", vault_id: "v", vault: "Personal", name: "General" }];
      if (r.op === "list")
        return [{ id: "a", vault: "Personal", project: "General", title: "site.example", trashed: false }];
      if (r.op === "edit") return { id: r.query, title: "site.example" };
      return null;
    };
    const state = await value<{ title?: string; siteLogins?: { id: string }[]; takenTitles?: Record<string, string[]> }>(
      { type: "save_load", saveId },
      page("save.html", `#${String(saveId)}`),
    );
    expect(state.title).toBe("site.example (otra)");
    expect(state.siteLogins?.map((l) => l.id)).toEqual(["a"]);
    expect(state.takenTitles?.["Personal\u0000General"]).toContain("site.example");
    // Updating a site login from create mode works cleanly.
    await value({ type: "save_do", saveId, action: "update", item: "a" }, page("save.html", `#${String(saveId)}`));
    expect(calls.filter((c) => c.op === "edit").map((c) => (c as { query: string }).query)).toEqual(["a"]);
  });

  it("with a username, compares only that username's logins, as before", async () => {
    tabUrl.set(23, "https://site.example/login");
    await submitted(23, "ana", "MARKER-bea");
    const saveId = await pending(23);
    // bea's password, sent with ana's name: ana's login gets the update offer.
    siteWith({ a: "MARKER-ana", b: "MARKER-bea" });
    const state = await value<{ updates?: { id: string }[] }>({ type: "save_load", saveId }, page("save.html", `#${String(saveId)}`));
    expect(state.updates?.map((u) => u.id)).toEqual(["a"]);
    expect(fetched().map((c) => c.item)).toEqual(["a"]);
  });
});

describe("«Add this site» after a login saved for a subdomain (ADR 0025)", () => {
  const parentLogin = { id: "p1", kind: "login", title: "1Password", username: "ana", location: "Personal / General", site: "my.1password.com" };

  /** The popup fills the parent group's login into tab 3; the bar's ID. */
  async function offered(): Promise<string> {
    tabUrl.set(3, "https://1password.com/");
    daemon = (r) => {
      if (r.op === "status") return unlocked;
      if (r.op === "suggest") return { logins: [], parent: [parentLogin], cards: [], identities: [] };
      if (r.op === "view") return { id: "p1", kind: "login", title: "1Password", urls: ["https://my.1password.com"], fields: [] };
      if (r.op === "autofill") return { id: "p1", kind: "login", title: "1Password", fields: [{ name: "password", kind: "password", value: "MARKER" }] };
      if (r.op === "edit") return { id: "p1", title: "1Password" };
      return null;
    };
    await value({ type: "popup_fill", item: "p1", parent: true }, page("popup.html"));
    const show = toTabs.find((t) => t.message.type === "show" && t.message.surface === "save");
    expect(show).toBeDefined();
    return String(show?.message.id);
  }
  const addSite = (saveId: string): Promise<Reply> => send({ type: "save_do", saveId, action: "add_site" }, page("save.html", `#${saveId}`));
  const edits = (): Request[] => calls.filter((c) => c.op === "edit");

  it("adds the page's origin, on the page it was offered for", async () => {
    const saveId = await offered();
    expect(calls.find((c) => c.op === "autofill")).toMatchObject({ chosen: true });
    await value({ type: "save_do", saveId, action: "add_site" }, page("save.html", `#${saveId}`));
    expect(edits()).toMatchObject([{ query: "p1", patch: { add_urls: ["https://1password.com"] } }]);
  });

  it("adds nothing once the tab went to another site", async () => {
    const saveId = await offered();
    tabUrl.set(3, "https://evil.example/");
    expect(await addSite(saveId)).toMatchObject({ ok: false, error: { code: "not_found" } });
    tabUrl.set(3, "https://1password.com/");
    expect(await addSite(saveId)).toMatchObject({ ok: false, error: { code: "not_found" } });
    expect(edits()).toEqual([]);
  });

  it("goes away with its tab", async () => {
    const saveId = await offered();
    removed?.(3);
    expect(await addSite(saveId)).toMatchObject({ ok: false, error: { code: "not_found" } });
    expect(edits()).toEqual([]);
  });

  it("waits for the page to leave the bar alone", async () => {
    const saveId = await offered();
    clear = false;
    expect(await addSite(saveId)).toMatchObject({ ok: false, error: { code: "covered" } });
    expect(edits()).toEqual([]);
  });
});

describe("an agent's passkey use (ADR 0020 §9)", () => {
  const assertion = { credential_id: "AA", client_data_json: "AA", authenticator_data: "AA", signature: "AA", user_handle: "AA", item: "i1" };
  const call = { kind: "get", rp_id: "shop.example", challenge: "A".repeat(22), allow: [] };
  let refuse = false;
  beforeEach(() => {
    refuse = false;
    daemon = (r) => {
      if (r.op === "status") return unlocked;
      if (r.op === "passkey_candidates") return { rp_id: "shop.example", candidates: [{ item: "i1", title: "Shop", user_name: "ana" }] };
      if (r.op === "agent_passkey_use") {
        if (refuse) throw new DaemonError("denied", "no agent's passkey use is armed in this tab");
        return assertion;
      }
      return null;
    };
  });
  const arm = (notify: () => void = () => undefined) => ({
    token: "kpa_token",
    host: "shop.example",
    rp_id: "shop.example",
    item: "i1",
    expires: Date.now() + 60_000,
    notify,
  });
  const frames = (tabId: number) => toTabs.filter((t) => t.tabId === tabId && t.message.type === "passkey_show");
  const uses = () => calls.filter((c) => c.op === "agent_passkey_use");

  it("signs the next sign-in of the site in that tab, once, without Klav's frame", async () => {
    const { armPasskey } = await import("../src/background/passkeys");
    tabUrl.set(11, "https://shop.example/login");
    const notify = vi.fn();
    expect(await armPasskey(11, arm(notify))).toBe(false);
    const reply = await value<{ outcome?: { status: string }; pending?: string }>({ type: "passkey_request", call, same_origin_as_top: true }, content(11));
    expect(reply.outcome?.status).toBe("asserted");
    expect(uses()).toEqual([{ op: "agent_passkey_use", tab_id: 11, origin: "https://shop.example/login", rp_id: "shop.example", challenge: call.challenge, token: "kpa_token" }]);
    expect(frames(11)).toHaveLength(0);
    expect(notify).toHaveBeenCalledOnce();
    // Once: the next sign-in is the person's.
    const again = await value<{ pending?: string }>({ type: "passkey_request", call, same_origin_as_top: true }, content(11));
    expect(again.pending).toBeDefined();
    expect(uses()).toHaveLength(1);
    expect(frames(11)).toHaveLength(1);
  });

  it("not in another tab, nor on another host of the tab", async () => {
    const { armPasskey } = await import("../src/background/passkeys");
    tabUrl.set(12, "https://shop.example/login");
    tabUrl.set(13, "https://login.shop.example/");
    await armPasskey(12, arm());
    const other = await value<{ pending?: string }>({ type: "passkey_request", call, same_origin_as_top: true }, content(13));
    expect(other.pending).toBeDefined();
    tabUrl.set(12, "https://login.shop.example/");
    const moved = await value<{ pending?: string }>({ type: "passkey_request", call, same_origin_as_top: true }, content(12));
    expect(moved.pending).toBeDefined();
    expect(uses()).toHaveLength(0);
  });

  it("a page already waiting gets it at once, and Klav's frame closes", async () => {
    const { armPasskey } = await import("../src/background/passkeys");
    tabUrl.set(14, "https://shop.example/login");
    const { pending } = await value<{ pending: string }>({ type: "passkey_request", call, same_origin_as_top: true }, content(14));
    expect(await armPasskey(14, arm())).toBe(true);
    const result = toTabs.find((t) => t.tabId === 14 && t.message.type === "passkey_result");
    expect(result?.message).toMatchObject({ id: pending, outcome: { status: "asserted" } });
    expect(toTabs.some((t) => t.tabId === 14 && t.message.type === "passkey_hide" && t.message.id === pending)).toBe(true);
  });

  it("klavd refusing it leaves the sign-in to the person", async () => {
    const { armPasskey } = await import("../src/background/passkeys");
    tabUrl.set(15, "https://shop.example/login");
    refuse = true;
    const notify = vi.fn();
    await armPasskey(15, arm(notify));
    const reply = await value<{ pending?: string }>({ type: "passkey_request", call, same_origin_as_top: true }, content(15));
    expect(reply.pending).toBeDefined();
    expect(frames(15)).toHaveLength(1);
    expect(notify).not.toHaveBeenCalled();
  });
});
