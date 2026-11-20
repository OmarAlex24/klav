// @vitest-environment jsdom
// Form detection and filling over HTML fixtures (test/fixtures). jsdom has
// no layout, so visibility is passed in.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { beforeEach, describe, expect, it } from "vitest";
import { type Field, fieldsOf, groupsFor, scopeOf } from "../src/content/detect";
import { agentFill } from "../src/content/agent";
import { fillFields, matchOption } from "../src/content/fill";
import type { FillValue } from "../src/shared/protocol";

function load(name: string): void {
  const html = readFileSync(join(import.meta.dirname, "fixtures", name), "utf8");
  const parsed = new DOMParser().parseFromString(html, "text/html");
  document.body.replaceChildren(...[...parsed.body.childNodes].map((n) => document.importNode(n, true)));
}

function byId(id: string): HTMLInputElement {
  const el = document.getElementById(id);
  if (!el) throw new Error(`no #${id}`);
  return el as HTMLInputElement;
}

/** The roles of the scope of `#id`, as `{ id: role }`. */
function roles(id: string): Record<string, string> {
  return Object.fromEntries(fieldsOf(scopeOf(byId(id))).map((f) => [f.el.id, f.role]));
}

const always = (): boolean => true;
const login = (username: string, password: string, totp?: string): FillValue[] => [
  { name: "username", kind: "username", value: username },
  { name: "password", kind: "password", value: password },
  ...(totp ? [{ name: "totp", kind: "totp" as const, value: totp }] : []),
];

beforeEach(() => {
  document.body.replaceChildren();
});

describe("detection", () => {
  it("reads autocomplete and ignores search boxes", () => {
    load("login-autocomplete.html");
    expect(roles("u")).toEqual({ u: "username", p: "current-password" });
  });

  it("finds a Spanish login by its labels; an e-mail before a password is the username", () => {
    load("login-plain-es.html");
    expect(roles("correo")).toEqual({ correo: "username", clave: "current-password" });
  });

  it("takes an unnamed text box right before the password as the username", () => {
    load("login-unnamed.html");
    expect(roles("f1")).toEqual({ f1: "username", f2: "current-password" });
  });

  it("tells sign-up and change-password forms by their new passwords", () => {
    load("signup.html");
    expect(roles("email")).toEqual({ nombre: "given-name", email: "username", new1: "new-password", new2: "new-password" });
    load("change-password.html");
    expect(roles("old")).toEqual({ old: "current-password", new: "new-password", again: "new-password" });
  });

  it("reads GitHub's sign-in form: the account box is the username, the honeypot nothing", () => {
    // The first username of the scope is what a submit reports
    // (`reportSubmit`): here GitHub's `login`, never its hidden honeypot.
    load("github-login.html");
    const fields = fieldsOf(scopeOf(byId("password"))).map((f) => [f.el.name, f.role]);
    expect(fields).toEqual([
      ["login", "username"],
      ["password", "current-password"],
    ]);
  });

  it("sees a username-first sign-in step, but not a newsletter box", () => {
    load("username-first.html");
    expect(roles("identifier")).toEqual({ identifier: "username" });
    load("formless.html");
    expect(roles("news")).toEqual({ news: "email" });
  });

  it("finds one-time code fields, not promo codes", () => {
    load("otp.html");
    expect(roles("code")).toEqual({ code: "otp" });
    expect(roles("otp2")).toEqual({ otp2: "otp" });
    expect(roles("promo")).toEqual({});
  });

  it("finds card fields in Spanish, with month and year selects", () => {
    load("card-es.html");
    expect(roles("numero")).toEqual({
      titular: "cc-name",
      numero: "cc-number",
      mes: "cc-exp-month",
      anio: "cc-exp-year",
      cvv: "cc-csc",
    });
  });

  it("reads a security code next to a card number as the card's", () => {
    load("card-exp.html");
    expect(roles("cc")).toEqual({ cc: "cc-number", exp: "cc-exp", exp4: "cc-exp", sec: "cc-csc" });
  });

  it("finds address fields in Spanish (código postal is not a one-time code)", () => {
    load("address-es.html");
    expect(roles("cp")).toEqual({
      nom: "given-name",
      ape: "family-name",
      tel: "tel",
      mail: "email",
      dir: "address",
      cp: "postal-code",
      ciudad: "city",
      estado: "region",
      pais: "country",
    });
  });

  it("groups fields outside any form by their document", () => {
    load("formless.html");
    expect(roles("user")).toEqual({ user: "username", pass: "current-password" });
  });

  it("looks inside open shadow roots", () => {
    const host = document.createElement("x-login");
    const form = document.createElement("form");
    document.body.append(form);
    form.append(host);
    const shadow = host.attachShadow({ mode: "open" });
    const user = document.createElement("input");
    user.id = "su";
    user.autocomplete = "username";
    const pass = document.createElement("input");
    pass.type = "password";
    pass.id = "sp";
    shadow.append(user, pass);
    expect(scopeOf(pass)).toBe(form);
    expect(fieldsOf(form).map((f) => [f.el.id, f.role])).toEqual([
      ["su", "username"],
      ["sp", "current-password"],
    ]);
  });

  it("offers logins on login fields and cards next to addresses", () => {
    load("login-plain-es.html");
    const fields = fieldsOf(scopeOf(byId("clave")));
    expect(groupsFor(fields[1] as Field, fields)).toEqual(["login"]);
    load("address-es.html");
    const address = fieldsOf(scopeOf(byId("dir")));
    expect(groupsFor(address[4] as Field, address)).toEqual(["identity"]);
  });
});

describe("filling", () => {
  it("types the username and password and fires input events", () => {
    load("login-autocomplete.html");
    const seen: string[] = [];
    byId("u").addEventListener("input", () => seen.push("u"));
    byId("p").addEventListener("change", () => seen.push("p"));
    const names = fillFields("login", login("ana", "s3cret"), fieldsOf(scopeOf(byId("u"))), always);
    expect(names).toEqual(["username", "password"]);
    expect(byId("u").value).toBe("ana");
    expect(byId("p").value).toBe("s3cret");
    expect(seen).toEqual(["u", "p"]);
  });

  it("skips fields the person cannot see", () => {
    load("login-autocomplete.html");
    const visible = (el: Element): boolean => el.id !== "p";
    fillFields("login", login("ana", "s3cret"), fieldsOf(scopeOf(byId("u"))), visible);
    expect(byId("u").value).toBe("ana");
    expect(byId("p").value).toBe("");
  });

  it("fills only the current password of a change-password form", () => {
    load("change-password.html");
    fillFields("login", login("ana", "old-one"), fieldsOf(scopeOf(byId("old"))), always);
    expect([byId("old").value, byId("new").value, byId("again").value]).toEqual(["old-one", "", ""]);
  });

  it("does not put a login's password into a sign-up form", () => {
    load("signup.html");
    fillFields("login", login("ana@example.com", "pw"), fieldsOf(scopeOf(byId("email"))), always);
    expect(byId("email").value).toBe("ana@example.com");
    expect([byId("new1").value, byId("new2").value]).toEqual(["", ""]);
  });

  it("types an agent's login into a sign-up form: the password and its confirmation", () => {
    load("signup.html");
    const { filled } = agentFill(document, "login", login("ana@example.com", "pw"), [], always);
    expect(filled.sort()).toEqual(["password", "username"]);
    expect([byId("email").value, byId("new1").value, byId("new2").value]).toEqual(["ana@example.com", "pw", "pw"]);
  });

  it("types an agent's login only into the current password of a change-password form", () => {
    load("change-password.html");
    agentFill(document, "login", login("ana", "old-one"), [], always);
    expect([byId("old").value, byId("new").value, byId("again").value]).toEqual(["old-one", "", ""]);
  });

  it("types the one-time code with the login", () => {
    load("otp.html");
    fillFields("login", login("ana", "pw", "123456"), fieldsOf(scopeOf(byId("code"))), always);
    expect(byId("code").value).toBe("123456");
  });

  it("types a code split in one box per digit, a digit in each", () => {
    load("otp-digits.html");
    expect(roles("d1")).toEqual({ d1: "otp", d2: "otp", d3: "otp", d4: "otp", d5: "otp", d6: "otp" });
    expect(roles("p1")).toEqual({});
    const filled = fillFields("login", [{ name: "totp", kind: "totp", value: "289591" }], fieldsOf(scopeOf(byId("d1"))), always);
    expect(filled).toEqual(["totp"]);
    expect(["d1", "d2", "d3", "d4", "d5", "d6"].map((id) => byId(id).value).join("")).toBe("289591");
  });

  it("types card expiry dates in the shape each field asks for", () => {
    const card: FillValue[] = [
      { name: "cardholder", kind: "text", value: "Ana Pérez" },
      { name: "number", kind: "concealed", value: "4242424242424242" },
      { name: "expiry", kind: "month_year", value: "09/27" },
      { name: "cvv", kind: "concealed", value: "123" },
    ];
    load("card-es.html");
    fillFields("card", card, fieldsOf(scopeOf(byId("numero"))), always);
    expect(byId("titular").value).toBe("Ana Pérez");
    expect(byId("numero").value).toBe("4242424242424242");
    expect((document.getElementById("mes") as HTMLSelectElement).value).toBe("9");
    expect((document.getElementById("anio") as HTMLSelectElement).value).toBe("2027");
    expect(byId("cvv").value).toBe("123");
    load("card-exp.html");
    fillFields("card", card, fieldsOf(scopeOf(byId("cc"))), always);
    expect(byId("exp").value).toBe("09/27");
    expect(byId("exp4").value).toBe("09/2027");
    expect(byId("sec").value).toBe("123");
  });

  it("fills an address, choosing select options by their text", () => {
    load("address-es.html");
    const identity: FillValue[] = [
      { name: "first_name", kind: "text", value: "Ana" },
      { name: "last_name", kind: "text", value: "Pérez" },
      { name: "email", kind: "email", value: "ana@example.com" },
      { name: "postal_code", kind: "text", value: "44100" },
      { name: "region", kind: "text", value: "Jalisco" },
      { name: "country", kind: "text", value: "mexico" },
    ];
    fillFields("identity", identity, fieldsOf(scopeOf(byId("nom"))), always);
    expect([byId("nom").value, byId("ape").value, byId("mail").value, byId("cp").value]).toEqual([
      "Ana",
      "Pérez",
      "ana@example.com",
      "44100",
    ]);
    expect((document.getElementById("estado") as HTMLSelectElement).value).toBe("JAL");
    expect((document.getElementById("pais") as HTMLSelectElement).value).toBe("MX");
  });

  it("matches select options by number ignoring leading zeros", () => {
    load("card-es.html");
    const mes = document.getElementById("mes") as HTMLSelectElement;
    expect(matchOption(mes, "01")?.value).toBe("1");
    expect(matchOption(mes, "13")).toBeUndefined();
  });
});

describe("approvals", () => {
  it("shows an item reference as its title and place", async () => {
    const { describeTarget } = await import("../src/ui/strings");
    expect(describeTarget("klav://Personal/General/Sitio%20local")).toEqual({ title: "Sitio local", where: "Personal / General" });
    expect(describeTarget("klav://Personal/Café con leche/Sitio local/password")).toEqual({
      title: "Sitio local (password)",
      where: "Personal / Café con leche",
    });
    expect(describeTarget("klav://Personal/General/50%25 off")).toEqual({ title: "50% off", where: "Personal / General" });
    expect(describeTarget("klav://Trabajo/Backend/Stripe/api_key")).toEqual({ title: "Stripe (api_key)", where: "Trabajo / Backend" });
    expect(describeTarget("something else")).toEqual({ title: "something else" });
  });
});
