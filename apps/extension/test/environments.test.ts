// @vitest-environment jsdom
// Environments in the popup (ADR 0032 §6): the variables with their values
// hidden until «Show», «Copy» asking klavd every time, where a reference
// comes from, what an agent changed, the edits sent to klavd (add, change,
// remove, protect), the trash, the new environment's form, the
// «Environments» tab and the strings in both languages.
import { afterEach, describe, expect, it } from "vitest";
import type { EnvironmentDetail, EnvironmentEdit, ItemSummary, VariableView } from "../src/shared/protocol";
import {
  decodeValue,
  environmentSections,
  environmentSub,
  type EnvironmentHooks,
  type Masked,
  newEnvironmentEdit,
  newEnvironmentForm,
  originText,
  protectedByDefault,
  variableProblem,
} from "../src/ui/environments";
import { filterLabel, ofKind, tabs } from "../src/ui/filters";
import { kindName } from "../src/ui/strings";
import { t } from "../src/shared/i18n";
import { useLocale } from "./setup";

afterEach(() => {
  useLocale("en");
  document.body.replaceChildren();
});

const SECRET = "sk_live_MARKER";

const value = (name: string): VariableView => ({ name, origin: "value", resolve: `klav://v/p/e/${name}` });
const reference = (name: string, target: string | undefined, isProtected = false): VariableView => ({
  name,
  origin: "reference",
  reference: "klav://v/p/i/f",
  ...(target === undefined ? {} : { target }),
  protected: isProtected,
  resolve: `klav://v/p/e/${name}`,
});

const detail = (over: Partial<EnvironmentDetail["environment"]> = {}, variables = [value("DATABASE_URL"), reference("STRIPE_KEY", "Stripe › api_key", true)]): EnvironmentDetail => ({
  environment: {
    id: "env-1",
    vault_id: "v",
    vault: "Personal",
    project_id: "p",
    project: "acme-api",
    name: "production",
    variables: variables.length,
    protected: true,
    updated_at: 0,
    ...over,
  },
  variables,
});

/** A masked field that keeps its text out of the DOM until shown. */
function masked(): Masked {
  const el = document.createElement("span");
  el.className = "value secret is-hidden";
  return {
    el,
    show: (text) => {
      el.textContent = text;
      el.classList.remove("is-hidden");
      return Promise.resolve();
    },
    hide: () => {
      el.textContent = "";
      el.classList.add("is-hidden");
    },
  };
}

interface Calls {
  asked: string[];
  copied: string[];
  saved: { edit: EnvironmentEdit; lowers: boolean }[];
  trashed: number;
  failed: unknown[];
}

function hooks(): { hooks: EnvironmentHooks; calls: Calls } {
  const calls: Calls = { asked: [], copied: [], saved: [], trashed: 0, failed: [] };
  return {
    calls,
    hooks: {
      masked,
      value: (v) => {
        calls.asked.push(v.resolve);
        return Promise.resolve(SECRET);
      },
      copy: (text) => {
        calls.copied.push(text);
        return Promise.resolve();
      },
      save: (edit, lowers) => {
        calls.saved.push({ edit, lowers });
        return Promise.resolve();
      },
      trash: () => {
        calls.trashed += 1;
        return Promise.resolve();
      },
      failed: (e) => calls.failed.push(e),
    },
  };
}

const settle = (): Promise<void> => new Promise((r) => setTimeout(r, 0));

function button(root: HTMLElement, label: string): HTMLButtonElement {
  const found = [...root.querySelectorAll("button")].find((b) => b.getAttribute("aria-label") === label || b.textContent === label);
  if (!found) throw new Error(`no button ${label}`);
  return found;
}

describe("an environment's page", () => {
  it("lists every variable with its value hidden and where it comes from", () => {
    const { hooks: h } = hooks();
    const root = environmentSections(detail(), h);
    document.body.append(root);
    const rows = [...root.querySelectorAll<HTMLElement>(".env-variable")];
    expect(rows.map((r) => r.dataset.name)).toEqual(["DATABASE_URL", "STRIPE_KEY"]);
    expect(root.textContent).not.toContain(SECRET);
    expect(rows.every((r) => r.querySelector(".secret.is-hidden"))).toBe(true);
    expect(rows[0]?.textContent).toContain(t("env_own_value"));
    expect(rows[1]?.textContent).toContain(t("env_target_protected", t("env_from", "Stripe › api_key")));
    expect(root.querySelector(".env-protected")?.textContent).toBe(t("env_protected_notice"));
  });

  it("shows a value only when asked, and hides it again", async () => {
    const { hooks: h, calls } = hooks();
    const root = environmentSections(detail(), h);
    document.body.append(root);
    const show = button(root, t("show_field", "DATABASE_URL"));
    show.click();
    await settle();
    expect(calls.asked).toEqual(["klav://v/p/e/DATABASE_URL"]);
    const row = root.querySelector<HTMLElement>('[data-name="DATABASE_URL"]');
    expect(row?.querySelector(".secret")?.textContent).toBe(SECRET);
    expect(show.textContent).toBe(t("hide"));
    show.click();
    expect(row?.querySelector(".secret")?.textContent).toBe("");
    expect(root.textContent).not.toContain(SECRET);
  });

  it("asks klavd again for every copy", async () => {
    const { hooks: h, calls } = hooks();
    const root = environmentSections(detail(), h);
    const copy = button(root, t("copy_field", "STRIPE_KEY"));
    copy.click();
    copy.click();
    await settle();
    expect(calls.asked).toEqual(["klav://v/p/e/STRIPE_KEY", "klav://v/p/e/STRIPE_KEY"]);
    expect(calls.copied).toEqual([SECRET, SECRET]);
    expect(root.textContent).not.toContain(SECRET);
  });

  it("says which variables an agent changed", () => {
    const d = { ...detail(), agent_changes: { agent_id: "a", agent: "ci-bot", at: 0, variables: ["DATABASE_URL", "REDIS_URL"] } };
    const root = environmentSections(d, hooks().hooks);
    expect(root.querySelector('[role="alert"]')?.textContent).toBe(t("env_agent_changed", "ci-bot", "DATABASE_URL, REDIS_URL"));
  });

  it("adds a value and a reference, and clears the typed value", async () => {
    const { hooks: h, calls } = hooks();
    const root = environmentSections(detail({ protected: false, name: "development" }, []), h);
    document.body.append(root);
    expect(root.textContent).toContain(t("env_none"));
    const form = root.querySelector<HTMLFormElement>(".env-form");
    const [name, text] = [...(form?.querySelectorAll<HTMLInputElement>("input") ?? [])];
    const source = form?.querySelector("select");
    if (!form || !name || !text || !source) throw new Error("form");
    name.value = "API_TOKEN";
    text.value = SECRET;
    form.requestSubmit();
    await settle();
    expect(calls.saved).toEqual([{ edit: { set: [{ name: "API_TOKEN", value: SECRET }] }, lowers: false }]);
    expect(text.value).toBe("");

    name.value = "STRIPE_KEY";
    source.value = "reference";
    source.dispatchEvent(new Event("change"));
    expect(text.type).toBe("text");
    text.value = "klav://Personal/General/Stripe/api_key";
    form.requestSubmit();
    await settle();
    expect(calls.saved[1]).toEqual({ edit: { set: [{ name: "STRIPE_KEY", reference: "klav://Personal/General/Stripe/api_key" }] }, lowers: false });
  });

  it("refuses a bad name, a reference without klav:// and an empty value", () => {
    const { hooks: h, calls } = hooks();
    const root = environmentSections(detail({ protected: false }, []), h);
    const form = root.querySelector<HTMLFormElement>(".env-form");
    const [name, text] = [...(form?.querySelectorAll<HTMLInputElement>("input") ?? [])];
    if (!form || !name || !text) throw new Error("form");
    document.body.append(root);
    name.value = "1BAD";
    text.value = "x";
    form.requestSubmit();
    expect(root.querySelector(".new-error")?.textContent).toBe(t("env_bad_variable"));
    expect(name.getAttribute("aria-invalid")).toBe("true");
    expect(calls.saved).toEqual([]);
    expect(variableProblem("STRIPE_KEY", "reference", "https://x")).toBe(t("env_bad_reference"));
    expect(variableProblem("STRIPE_KEY", "value", "")).toBe(t("env_empty_value"));
    expect(variableProblem("stripe_key", "value", "x")).toBeUndefined();
  });

  it("removes a variable and changes one through the form", async () => {
    const { hooks: h, calls } = hooks();
    const root = environmentSections(detail(), h);
    document.body.append(root);
    button(root, t("env_remove", "DATABASE_URL")).click();
    await settle();
    expect(calls.saved).toEqual([{ edit: { remove: ["DATABASE_URL"] }, lowers: false }]);
    button(root, t("env_change", "STRIPE_KEY")).click();
    const name = root.querySelector<HTMLInputElement>(".env-form input");
    expect(name?.value).toBe("STRIPE_KEY");
  });

  it("turns protection off as a lowering, and on as not", async () => {
    const { hooks: h, calls } = hooks();
    const root = environmentSections(detail(), h);
    const box = root.querySelector<HTMLInputElement>(".env-protect input");
    if (!box) throw new Error("box");
    expect(box.checked).toBe(true);
    box.checked = false;
    box.dispatchEvent(new Event("change"));
    await settle();
    box.checked = true;
    box.dispatchEvent(new Event("change"));
    await settle();
    expect(calls.saved).toEqual([
      { edit: { protected: false }, lowers: true },
      { edit: { protected: true }, lowers: false },
    ]);
  });

  it("puts the box back when lowering fails", async () => {
    const { hooks: h, calls } = hooks();
    h.save = () => Promise.reject(new Error("touch id"));
    const root = environmentSections(detail(), h);
    const box = root.querySelector<HTMLInputElement>(".env-protect input");
    if (!box) throw new Error("box");
    box.checked = false;
    box.dispatchEvent(new Event("change"));
    await settle();
    await settle();
    expect(box.checked).toBe(true);
    expect(calls.failed).toHaveLength(1);
  });

  it("moves to the trash only after Confirm", async () => {
    const { hooks: h, calls } = hooks();
    const root = environmentSections(detail(), h);
    document.body.append(root);
    button(root, t("env_trash")).click();
    expect(root.textContent).toContain(t("env_trash_confirm", "production"));
    button(root, t("cancel")).click();
    expect(calls.trashed).toBe(0);
    button(root, t("env_trash")).click();
    button(root, t("confirm")).click();
    await settle();
    expect(calls.trashed).toBe(1);
  });

  it("leaves only Show and Copy when the vault can't change", () => {
    const root = environmentSections(detail(), hooks().hooks, false);
    expect(root.querySelector(".env-protect")).toBeNull();
    expect(root.querySelector(".env-trash")).toBeNull();
    expect(root.querySelector<HTMLFormElement>(".env-form")).toBeNull();
    expect(root.querySelectorAll(".env-variable button")).toHaveLength(4);
  });
});

describe("a new environment", () => {
  it("protects production by itself until the person chooses", async () => {
    const created: [string, string, boolean][] = [];
    const form = newEnvironmentForm(
      [
        { id: "p1", vault_id: "v", vault: "Personal", name: "General" },
        { id: "p2", vault_id: "v", vault: "Work", name: "acme-api" },
      ],
      {
        create: (p, n, on) => {
          created.push([p, n, on]);
          return Promise.resolve();
        },
        failed: () => undefined,
      },
    );
    document.body.append(form);
    const select = form.querySelector("select");
    const [name, box] = [...form.querySelectorAll<HTMLInputElement>("input")];
    if (!select || !name || !box) throw new Error("form");
    expect([...select.options].map((o) => o.textContent)).toEqual(["Personal / General", "Work / acme-api"]);
    name.value = "production";
    name.dispatchEvent(new Event("input"));
    expect(box.checked).toBe(true);
    name.value = "Prod Env";
    name.dispatchEvent(new Event("input"));
    form.requestSubmit();
    expect(form.querySelector(".new-error")?.textContent).toBe(t("env_bad_name"));
    name.value = "prod";
    name.dispatchEvent(new Event("input"));
    box.checked = false;
    box.dispatchEvent(new Event("change"));
    name.value = "production";
    name.dispatchEvent(new Event("input"));
    expect(box.checked).toBe(false);
    select.value = "p2";
    form.requestSubmit();
    await settle();
    expect(created).toEqual([["p2", "production", false]]);
    expect(newEnvironmentEdit(true)).toEqual({ create: true, must_be_new: true, protected: true });
  });
});

describe("the helpers", () => {
  it("know production and prod", () => {
    expect(protectedByDefault("production")).toBe(true);
    expect(protectedByDefault("PROD")).toBe(true);
    expect(protectedByDefault("preprod")).toBe(false);
  });

  it("decode klavd's base64url values as UTF-8", () => {
    const text = "postgres://ñandú:p@ss/db?x=1";
    const bytes = new TextEncoder().encode(text);
    const b64 = btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    expect(decodeValue(b64)).toBe(text);
    expect(decodeValue("")).toBe("");
  });

  it("name a reference whose item this device can't see", () => {
    expect(originText(reference("X", undefined))).toBe(t("env_from_unknown"));
    expect(originText(reference("X", "Stripe › api_key"))).toBe(t("env_from", "Stripe › api_key"));
  });

  it("count variables in a row's second line", () => {
    expect(environmentSub("Personal", "acme-api", undefined)).toBe("Personal / acme-api");
    expect(environmentSub("Personal", "acme-api", 1)).toBe("Personal / acme-api · 1 variable");
    useLocale("es");
    expect(environmentSub("Personal", "acme-api", 3)).toBe("Personal / acme-api · 3 variables");
  });
});

describe("the Environments tab", () => {
  const item = (id: string, kind: ItemSummary["kind"]): ItemSummary => ({
    id,
    reference: "",
    vault_id: "v",
    vault: "Personal",
    project_id: "p",
    project: "acme-api",
    kind,
    title: id,
    urls: [],
    tags: [],
    version: 1,
    updated_at: 0,
    trashed: false,
  });

  it("shows up with environments and filters them", () => {
    const items = [item("GitHub", "login"), item("development", "environment"), item("production", "environment")];
    const list = tabs(items, 0, "all");
    expect(list.map((tab) => tab.filter)).toEqual(["all", "login", "environment"]);
    expect(list.find((tab) => tab.filter === "environment")?.count).toBe(2);
    expect(ofKind(items, "environment").map((i) => i.id)).toEqual(["development", "production"]);
  });

  it("is named natively in both languages", () => {
    expect(t(filterLabel("environment"))).toBe("Environments");
    expect(kindName("environment", true)).toBe("environment");
    useLocale("es");
    expect(t(filterLabel("environment"))).toBe("Entornos");
    expect(kindName("environment")).toBe("Entorno");
    expect(t("env_protected_notice")).toBe("Protegido: mostrar o copiar un valor pide Touch ID cada vez.");
  });
});
