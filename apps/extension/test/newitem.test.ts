// @vitest-environment jsdom
// «Nuevo elemento» in the popup: the `create` request for each kind, the
// active tab's site, the destination, the generator handing its password
// over, errors on their field, and every value gone when it is over.
import { afterEach, describe, expect, it } from "vitest";
import { forgetValues } from "../src/shared/messages";
import { DaemonError, type ItemSummary, type ProjectSummary, type Request } from "../src/shared/protocol";
import { type Draft, expiryValue, mountNewItem, type NewItemDeps, newItemRequest, siteOrigin, type TotpInfo } from "../src/ui/newitem";

const MARKER = "MARKER-new-item";

afterEach(() => {
  document.body.replaceChildren();
});

describe("the create request", () => {
  const draft = (over: Partial<Draft>): Draft => ({ title: "GitHub", ...over });

  it("sends a login's secret as secret and its site as an origin", () => {
    const item = newItemRequest("login", draft({ username: " ana ", password: MARKER, site: "github.com/login" }), "Personal\u0000Trabajo");
    expect(item).toEqual({
      kind: "login",
      title: "GitHub",
      vault: "Personal",
      project: "Trabajo",
      fields: [
        { name: "username", value: "ana", kind: "username", secret: false },
        { name: "password", value: MARKER, kind: "password", secret: true },
      ],
      urls: ["https://github.com"],
      tags: [],
    });
  });

  it("leaves empty values and the default destination out", () => {
    expect(newItemRequest("login", draft({ username: "", password: "", site: " " }))).toEqual({ kind: "login", title: "GitHub", fields: [], urls: [], tags: [] });
  });

  it("puts a note's text in notes", () => {
    const item = newItemRequest("note", draft({ title: "Wi-Fi", notes: MARKER }));
    expect(item.kind).toBe("note");
    expect(item.fields).toEqual([]);
    expect(item.notes).toBe(MARKER);
  });

  it("keeps a card's number and code secret and its expiry as YYYY-MM", () => {
    const item = newItemRequest("card", draft({ title: "Visa", cardholder: "Ana Pérez", number: "4111 1111 1111 1111", expiry: "7/29", cvv: "123" }));
    expect(item.fields).toEqual([
      { name: "cardholder", value: "Ana Pérez", kind: "text", secret: false },
      { name: "number", value: "4111111111111111", kind: "concealed", secret: true },
      { name: "expiry", value: "2029-07", kind: "month_year", secret: false },
      { name: "cvv", value: "123", kind: "concealed", secret: true },
    ]);
  });

  it("sends a one-time code key as a secret totp field", () => {
    expect(newItemRequest("totp", draft({ totp: ` ${MARKER} ` })).fields).toEqual([{ name: "totp", value: MARKER, kind: "totp", secret: true }]);
    expect(() => newItemRequest("totp", draft({ totp: "" }))).toThrow(expect.objectContaining({ field: "totp" }) as Error);
  });

  it("asks for a title", () => {
    expect(() => newItemRequest("note", { title: "  " })).toThrow(expect.objectContaining({ field: "title" }) as Error);
  });

  it("reads sites and expiry dates as people write them", () => {
    expect(siteOrigin("https://accounts.example.com/x?y")).toBe("https://accounts.example.com");
    expect(siteOrigin("localhost:8443")).toBe("https://localhost:8443");
    expect(siteOrigin("")).toBeUndefined();
    expect(() => siteOrigin("ftp://example.com")).toThrow();
    expect(() => siteOrigin("https://")).toThrow();
    expect(expiryValue("07/2031")).toBe("2031-07");
    expect(expiryValue("2031-07")).toBe("2031-07");
    expect(expiryValue("")).toBeUndefined();
    expect(() => expiryValue("13/29")).toThrow();
    expect(() => expiryValue("julio")).toThrow();
  });
});

describe("forgetting values", () => {
  it("empties a create's fields and notes once klavd answered", () => {
    const request: Request = { op: "create", item: newItemRequest("login", { title: "A", password: MARKER }) };
    request.item.notes = MARKER;
    const field = request.item.fields[0];
    forgetValues(request);
    expect(request.item.fields).toEqual([]);
    expect(field?.value).toBe("");
    expect(request.item.notes).toBe("");
    expect(JSON.stringify(request)).not.toContain(MARKER);
  });

  it("empties an edit's values and a recorded password", () => {
    const edit: Request = { op: "edit", query: "A", patch: { set: [{ name: "password", value: MARKER, secret: true }], remove: [], add_urls: [], add_tags: [] } };
    forgetValues(edit);
    expect(JSON.stringify(edit)).not.toContain(MARKER);
    const record: Request = { op: "generator_record", value: MARKER };
    forgetValues(record);
    expect(JSON.stringify(record)).not.toContain(MARKER);
  });
});

const summary = (title: string): ItemSummary => ({
  id: `id-${title}`,
  reference: `klav://Personal/General/${title}`,
  vault_id: "v",
  vault: "Personal",
  project_id: "p",
  project: "General",
  kind: "login",
  title,
  urls: [],
  tags: [],
  version: 1,
  updated_at: 0,
  trashed: false,
});

const projects: ProjectSummary[] = [
  { id: "p1", vault_id: "v", vault: "Personal", name: "General" },
  { id: "p2", vault_id: "v", vault: "Personal", name: "Trabajo" },
];

interface Harness {
  root: HTMLElement;
  sent: string[];
  created: ItemSummary[];
  stop: () => void;
  answer: (fn: (request: Request) => unknown) => void;
}

function mount(over: Partial<NewItemDeps> = {}, start?: "login" | "note" | "card" | "totp"): Harness {
  const root = document.createElement("div");
  document.body.append(root);
  const sent: string[] = [];
  const created: ItemSummary[] = [];
  let reply: (request: Request) => unknown = (r) => (r.op === "projects" ? projects : r.op === "create" ? summary(r.item.title) : null);
  const deps: NewItemDeps = {
    daemon: <T>(request: Request): Promise<T> => {
      // What the background would send to klavd, as it was sent.
      sent.push(JSON.stringify(request));
      return new Promise<T>((resolve) => {
        resolve(reply(request) as T);
      });
    },
    here: () => Promise.resolve("https://github.com/login"),
    fillableHost: (url) => Promise.resolve(new URL(url).host),
    checkTotp: (value): Promise<TotpInfo> =>
      value.startsWith("otpauth://") ? Promise.resolve({ issuer: "ACME", account: "ana", digits: 6, period: 30 }) : Promise.reject(new Error("invalid TOTP secret")),
    created: (item) => created.push(item),
    ...over,
  };
  const stop = mountNewItem(root, deps, start);
  return { root, sent, created, stop, answer: (fn) => (reply = fn) };
}

const settle = (): Promise<void> => new Promise((r) => setTimeout(r, 0));
const input = (root: HTMLElement, name: string): HTMLInputElement | HTMLTextAreaElement => {
  const el = root.querySelector<HTMLInputElement | HTMLTextAreaElement>(`[name="${name}"]`);
  if (!el) throw new Error(`no ${name}`);
  return el;
};
const type = (root: HTMLElement, name: string, value: string): void => {
  const el = input(root, name);
  el.value = value;
  el.dispatchEvent(new Event("input"));
};
const submit = async (root: HTMLElement): Promise<void> => {
  root.querySelector("form")?.dispatchEvent(new Event("submit", { cancelable: true }));
  await settle();
  await settle();
};
const kind = (root: HTMLElement, k: string): void => {
  root.querySelector<HTMLButtonElement>(`.new-kind[data-kind="${k}"]`)?.click();
};

describe("the view", () => {
  it("offers the four kinds, with the active tab's site and the destinations", async () => {
    const { root } = mount();
    await settle();
    await settle();
    const kinds = [...root.querySelectorAll<HTMLElement>(".new-kind")].map((b) => [b.dataset.kind, b.getAttribute("aria-checked")]);
    expect(kinds).toEqual([["login", "true"], ["note", "false"], ["card", "false"], ["totp", "false"]]);
    expect(input(root, "site").value).toBe("https://github.com");
    expect(input(root, "title").value).toBe("github.com");
    expect([...root.querySelectorAll("select option")].map((o) => o.textContent)).toEqual(["Personal / General", "Personal / Trabajo"]);
    const password = input(root, "password") as HTMLInputElement;
    expect(password.type).toBe("password");
    expect(password.autocomplete).toBe("new-password");
  });

  it("has no site on a page Klav does not fill", async () => {
    const { root } = mount({ here: () => Promise.resolve("chrome://settings"), fillableHost: () => Promise.resolve(undefined) });
    await settle();
    await settle();
    expect(input(root, "site").value).toBe("");
    expect(input(root, "title").value).toBe("");
  });

  it("creates a login, then forgets what was typed", async () => {
    const h = mount();
    await settle();
    await settle();
    type(h.root, "username", "ana");
    type(h.root, "password", MARKER);
    const where = h.root.querySelector<HTMLSelectElement>("select");
    if (where) where.value = "Personal\u0000Trabajo";
    // The value is a property, never in the page's HTML.
    expect(new XMLSerializer().serializeToString(h.root)).not.toContain(MARKER);
    await submit(h.root);
    const create = JSON.parse(h.sent.find((s) => s.includes('"create"')) ?? "{}") as { item: Record<string, unknown> };
    expect(create.item).toMatchObject({ kind: "login", title: "github.com", vault: "Personal", project: "Trabajo", urls: ["https://github.com"] });
    expect(h.created.map((i) => i.title)).toEqual(["github.com"]);
    expect(input(h.root, "password").value).toBe("");
    expect(input(h.root, "username").value).toBe("");
  });

  it("shows and hides the password", () => {
    const { root } = mount();
    const show = root.querySelector<HTMLButtonElement>('button[aria-label="Show Password"]');
    show?.click();
    expect((input(root, "password") as HTMLInputElement).type).toBe("text");
    expect(show?.getAttribute("aria-label")).toBe("Hide Password");
    show?.click();
    expect((input(root, "password") as HTMLInputElement).type).toBe("password");
  });

  it("takes the generator's password once it is kept", async () => {
    let use: ((v: string) => Promise<void>) | undefined;
    let host: string | undefined;
    const { root } = mount({
      generator: (h, u) => {
        host = h;
        use = u;
        return Promise.resolve(document.createElement("section"));
      },
    });
    await settle();
    await settle();
    const generate = root.querySelector<HTMLButtonElement>('button[aria-label="Generate a password"]');
    generate?.click();
    await settle();
    expect(host).toBe("github.com");
    expect(generate?.getAttribute("aria-expanded")).toBe("true");
    await use?.(MARKER);
    expect(input(root, "password").value).toBe(MARKER);
    expect(root.querySelector<HTMLElement>(".new-gen")?.hidden).toBe(true);
  });

  it("creates a note and a card", async () => {
    const h = mount({}, "note");
    type(h.root, "title", "Wi-Fi");
    type(h.root, "notes", MARKER);
    await submit(h.root);
    expect(h.sent.some((s) => s.includes('"kind":"note"') && s.includes(MARKER))).toBe(true);
    kind(h.root, "card");
    expect(h.root.querySelector('[name="notes"]')).toBeNull();
    type(h.root, "title", "Visa");
    type(h.root, "number", "4111 1111 1111 1111");
    type(h.root, "expiry", "99/99");
    await submit(h.root);
    expect(input(h.root, "expiry").getAttribute("aria-invalid")).toBe("true");
    expect(h.root.textContent).toContain("MM/YY");
    type(h.root, "expiry", "07/31");
    await submit(h.root);
    expect(h.sent.some((s) => s.includes('"kind":"card"') && s.includes('"2031-07"'))).toBe(true);
  });

  it("checks a pasted key with klav-core and titles the item after its issuer", async () => {
    const h = mount({}, "totp");
    type(h.root, "totp", "nope");
    await settle();
    expect(h.root.querySelector(".new-hint")?.textContent).toContain("isn’t a one-time code key");
    type(h.root, "totp", "otpauth://totp/ACME:ana?secret=X");
    await settle();
    expect(h.root.querySelector(".new-hint")?.textContent).toBe("6 digits every 30 s · ACME · ana");
    expect(input(h.root, "title").value).toBe("ACME");
    await submit(h.root);
    expect(h.created.map((i) => i.title)).toEqual(["ACME"]);
  });

  it("says a title is taken on the title, and klavd's TOTP error on the key", async () => {
    const h = mount({}, "totp");
    h.answer((r) => {
      if (r.op === "projects") return projects;
      throw new DaemonError("invalid", "field \"totp\": not a valid TOTP secret");
    });
    type(h.root, "title", "A");
    type(h.root, "totp", "AAAA");
    await submit(h.root);
    expect(input(h.root, "totp").getAttribute("aria-invalid")).toBe("true");
    h.answer(() => {
      throw new DaemonError("invalid", "klav://Personal/General/A already exists (item x)");
    });
    await submit(h.root);
    expect(input(h.root, "title").getAttribute("aria-invalid")).toBe("true");
    expect(h.root.textContent).toContain("There’s already an item with that title");
    expect(h.created).toEqual([]);
  });

  it("clears every value when the view closes", () => {
    const h = mount();
    type(h.root, "password", MARKER);
    const password = input(h.root, "password");
    h.stop();
    expect(password.value).toBe("");
  });
});
