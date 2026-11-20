// @vitest-environment jsdom
// Filling for an agent (layer 04, G7): the agent picks the selectors, so a
// password or a one-time code only goes into an input fit for it, and the
// form is sent only if it got the password and sends to the same origin.
import { beforeEach, describe, expect, it } from "vitest";
import { agentFill, submitScope } from "../src/content/agent";
import { originOf } from "../src/shared/origin";
import type { FillValue } from "../src/shared/protocol";

const always = (): boolean => true;
const values = (): FillValue[] => [
  { name: "username", kind: "username", value: "ana" },
  { name: "password", kind: "password", value: "MARKER-pw" },
];

function byId(id: string): HTMLInputElement {
  const el = document.getElementById(id);
  if (!el) throw new Error(`no #${id}`);
  return el as HTMLInputElement;
}

beforeEach(() => {
  const parsed = new DOMParser().parseFromString(`
    <form id=search action=/search><input type=search id=q name=q><button>Go</button></form>
    <form id=login action=/session>
      <input id=user name=username autocomplete=username>
      <input id=pass name=password type=password>
      <input id=code name=otp autocomplete=one-time-code>
      <button>Sign in</button>
    </form>`, "text/html");
  document.body.replaceChildren(...[...parsed.body.childNodes].map((n) => document.importNode(n, true)));
});

describe("agentFill", () => {
  it("never types a password into a search box the agent names", () => {
    const out = agentFill(document, "login", values(), [{ field: "password", selector: "#q" }], always);
    expect(byId("q").value).toBe("");
    expect(out.scope).not.toBe(byId("search"));
  });

  it("types into the inputs fit for each value", () => {
    const out = agentFill(document, "login", values(), [{ field: "password", selector: "#pass" }], always);
    expect(byId("pass").value).toBe("MARKER-pw");
    expect(out.passwordFilled).toBe(true);
  });

  it("puts a one-time code only into a password or one-time code field", () => {
    const code: FillValue[] = [{ name: "totp", kind: "totp", value: "123456" }];
    agentFill(document, "totp", code, [{ field: "totp", selector: "#q" }], always);
    expect(byId("q").value).toBe("");
    agentFill(document, "totp", code, [{ field: "totp", selector: "#code" }], always);
    expect(byId("code").value).toBe("123456");
  });

  it("does not send a form that got no password", () => {
    const user: FillValue[] = [{ name: "username", kind: "username", value: "ana" }];
    const out = agentFill(document, "login", user, [{ field: "username", selector: "#user" }], always);
    expect(out.filled).toEqual(["username"]);
    expect(out.passwordFilled).toBe(false);
  });
});

describe("submitScope", () => {
  it("sends only to the page's own origin", () => {
    const form = byId("login") as unknown as HTMLFormElement;
    let sent = 0;
    form.addEventListener("submit", (e) => {
      e.preventDefault();
      sent += 1;
    });
    expect(submitScope(form)).toBe(true);
    expect(sent).toBe(1);
    form.action = "https://evil.example/steal";
    expect(submitScope(form)).toBe(false);
    expect(sent).toBe(1);
  });
});

describe("originOf", () => {
  it("keeps the scheme, host and port only", () => {
    expect(originOf("https://github.com/login?token=MARKER#code=1")).toBe("https://github.com");
    expect(originOf("http://127.0.0.1:8080/cb?code=x")).toBe("http://127.0.0.1:8080");
    expect(originOf("about:blank")).toBe("about:");
    expect(originOf("not a url")).not.toContain("not a url");
  });
});
