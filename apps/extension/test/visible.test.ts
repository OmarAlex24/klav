// @vitest-environment jsdom
// Layer 09: what counts as a field the person can see (docs/extension.md
// §5), passwords only into password boxes, the CVV never into a box that
// says it is a one-time code, and Klav never presses a button that sends
// the form to another origin. jsdom has no layout: each element's box is
// set by hand.
import { beforeEach, describe, expect, it } from "vitest";
import { fieldsOf, scopeOf } from "../src/content/detect";
import { fillFields, isVisible } from "../src/content/fill";
import { canPressOnward, isSendButton, pressOnward, sendsHome } from "../src/content/steps";
import type { FillValue } from "../src/shared/protocol";

type Box = { left: number; top: number; width: number; height: number };

/** Gives `el` a box (viewport coordinates). */
function box(el: Element, b: Box): void {
  const rect = { ...b, x: b.left, y: b.top, right: b.left + b.width, bottom: b.top + b.height, toJSON: () => b };
  el.getBoundingClientRect = () => rect;
}

function load(html: string): void {
  const parsed = new DOMParser().parseFromString(html, "text/html");
  document.body.replaceChildren(...[...parsed.body.childNodes].map((n) => document.importNode(n, true)));
  // Every element a normal box, unless a test says otherwise.
  for (const el of document.querySelectorAll("*")) box(el, { left: 10, top: 10, width: 200, height: 30 });
  box(document.body, { left: 0, top: 0, width: 1024, height: 768 });
}

function byId(id: string): HTMLInputElement {
  const el = document.getElementById(id);
  if (!el) throw new Error(`no #${id}`);
  return el as HTMLInputElement;
}

function formById(id: string): HTMLFormElement {
  const el = document.getElementById(id);
  if (!(el instanceof HTMLFormElement)) throw new Error(`no form #${id}`);
  return el;
}

const always = (): boolean => true;

beforeEach(() => {
  document.body.replaceChildren();
});

describe("isVisible", () => {
  it("takes a normal field, and one further down the page", () => {
    load(`<input id=a><input id=b>`);
    expect(isVisible(byId("a"))).toBe(true);
    // Below the window: the person scrolls to it.
    Object.defineProperty(document.documentElement, "scrollHeight", { configurable: true, value: 3000 });
    box(byId("b"), { left: 10, top: 2000, width: 200, height: 30 });
    expect(isVisible(byId("b"))).toBe(true);
    Reflect.deleteProperty(document.documentElement, "scrollHeight");
  });

  it("refuses tiny fields and fields out of the page", () => {
    load(`<input id=tiny><input id=left><input id=above><input id=far>`);
    box(byId("tiny"), { left: 10, top: 10, width: 2, height: 2 });
    box(byId("left"), { left: -10000, top: 10, width: 200, height: 30 });
    box(byId("above"), { left: 10, top: -500, width: 200, height: 30 });
    box(byId("far"), { left: 50_000, top: 10, width: 200, height: 30 });
    for (const id of ["tiny", "left", "above", "far"]) expect(isVisible(byId(id)), id).toBe(false);
  });

  it("refuses fields clipped, filtered away or cut out by their container", () => {
    load(`
      <input id=path style="clip-path: inset(50%)">
      <input id=circle style="clip-path: circle(0)">
      <input id=filter style="filter: opacity(0)">
      <input id=clip style="position: absolute; clip: rect(0px, 0px, 0px, 0px)">
      <div id=wrap style="overflow: hidden"><input id=cut></div>
      <input id=rounded style="clip-path: inset(0 round 8px)">`);
    box(byId("wrap"), { left: 0, top: 0, width: 300, height: 40 });
    box(byId("cut"), { left: 400, top: 10, width: 200, height: 30 });
    for (const id of ["path", "circle", "filter", "clip", "cut"]) expect(isVisible(byId(id)), id).toBe(false);
    // Rounded corners are not a way to hide.
    expect(isVisible(byId("rounded"))).toBe(true);
  });
});

describe("passwords only in password boxes", () => {
  const login = (): FillValue[] => [
    { name: "username", kind: "username", value: "ana" },
    { name: "password", kind: "password", value: "MARKER-pw" },
  ];

  it("never types the password into a text box the page marks current-password", () => {
    load(`<form><input id=u autocomplete=username><input id=fake type=search autocomplete=current-password><input id=p type=password></form>`);
    fillFields("login", login(), fieldsOf(scopeOf(byId("u"))), always);
    expect(byId("fake").value).toBe("");
    expect(byId("p").value).toBe("MARKER-pw");
  });

  it("types nothing when the only «password» is a text box", () => {
    load(`<form><input id=u autocomplete=username><input id=fake autocomplete=current-password></form>`);
    const filled = fillFields("login", login(), fieldsOf(scopeOf(byId("u"))), always);
    expect(byId("fake").value).toBe("");
    expect(filled).toEqual(["username"]);
  });
});

describe("one-time codes next to a card", () => {
  it("keeps a box that says one-time-code out of the card's CVV", () => {
    load(`<form>
      <input id=cc autocomplete=cc-number>
      <input id=sec name=security_code placeholder="Security code">
      <input id=otp autocomplete=one-time-code>
      <input id=verify name=verification_code placeholder="Verification code" inputmode=numeric maxlength=6>
    </form>`);
    const roles = Object.fromEntries(fieldsOf(scopeOf(byId("cc"))).map((f) => [f.el.id, f.role]));
    expect(roles).toEqual({ cc: "cc-number", sec: "cc-csc", otp: "otp", verify: "otp" });
    fillFields("card", [{ name: "cvv", kind: "concealed", value: "123" }], fieldsOf(scopeOf(byId("cc"))), always);
    expect([byId("sec").value, byId("otp").value, byId("verify").value]).toEqual(["123", "", ""]);
  });
});

describe("pressing onward", () => {
  it("never presses a button whose formaction sends to another origin", () => {
    load(`<form id=f action=/session><input id=u autocomplete=username>
      <button id=go formaction="https://evil.example/steal">Continuar</button></form>`);
    let sent = 0;
    formById("f").addEventListener("submit", (e) => {
      e.preventDefault();
      sent++;
    });
    const form = formById("f");
    expect(canPressOnward(form)).toBe(false);
    expect(pressOnward(form)).toBe(false);
    expect(sent).toBe(0);
    byId("go").removeAttribute("formaction");
    expect(pressOnward(form)).toBe(true);
    expect(sent).toBe(1);
  });

  it("never sends a form whose action is another origin", () => {
    load(`<form id=f action="https://evil.example/steal"><input id=u autocomplete=username></form>`);
    const form = formById("f");
    let sent = 0;
    form.addEventListener("submit", (e) => {
      e.preventDefault();
      sent++;
    });
    expect(pressOnward(form)).toBe(false);
    expect(sent).toBe(0);
    expect(sendsHome(undefined, form)).toBe(false);
  });

  it("reads a send button, not a «show password» eye", () => {
    load(`<form><button id=eye type=button aria-label="Show password">👁</button><button id=send>Sign in</button>
      <div id=div role=button>Iniciar sesión</div></form>`);
    expect(isSendButton(byId("eye"))).toBe(false);
    expect(isSendButton(byId("send"))).toBe(true);
    expect(isSendButton(byId("div"))).toBe(true);
  });
});
