// @vitest-environment jsdom
// Where an assisted password change (ADR 0022 §5) types its two values:
// the focused password box first, else the change form's new-password
// boxes; the old value into «current password»; never a box that is not
// type=password. jsdom has no layout, so visibility is passed in.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { beforeEach, describe, expect, it } from "vitest";
import { focusedPassword, isPasswordBox, rotateFill, rotateTargets } from "../src/content/rotate";

function load(name: string): void {
  const html = readFileSync(join(import.meta.dirname, "fixtures", name), "utf8");
  const parsed = new DOMParser().parseFromString(html, "text/html");
  document.body.replaceChildren(...[...parsed.body.childNodes].map((n) => document.importNode(n, true)));
}

function html(markup: string): void {
  const parsed = new DOMParser().parseFromString(markup, "text/html");
  document.body.replaceChildren(...[...parsed.body.childNodes].map((n) => document.importNode(n, true)));
}

function box(id: string): HTMLInputElement {
  const el = document.getElementById(id);
  if (!el) throw new Error(`no #${id}`);
  return el as HTMLInputElement;
}

const always = (): boolean => true;
const ids = (els: HTMLInputElement[]): string[] => els.map((el) => el.id);

beforeEach(() => {
  document.body.replaceChildren();
});

describe("assisted change targets", () => {
  it("fills the change form when no password box has the focus", () => {
    load("change-password.html");
    const targets = rotateTargets(document, undefined, always);
    expect(ids(targets.next)).toEqual(["new", "again"]);
    expect(ids(targets.current)).toEqual(["old"]);
    expect(rotateFill(targets, "OLD-secret", "NEW-secret", always)).toEqual(["new_password", "confirm_password", "current_password"]);
    expect([box("old").value, box("new").value, box("again").value]).toEqual(["OLD-secret", "NEW-secret", "NEW-secret"]);
  });

  it("puts the new password where the agent put the focus, and its confirmation", () => {
    // Nothing on this form says which box is new: the focus does.
    html(`<form>
      <input type="password" id="a" name="pw1">
      <input type="password" id="b" name="pw2" placeholder="Repite la contraseña">
      <input type="password" id="c" name="pw0" autocomplete="current-password">
    </form>`);
    box("a").focus();
    const focused = focusedPassword(document);
    expect(focused?.id).toBe("a");
    const targets = rotateTargets(document, focused, always);
    expect(ids(targets.next)).toEqual(["a", "b"]);
    expect(ids(targets.current)).toEqual(["c"]);
    rotateFill(targets, "old", "new", always);
    expect([box("a").value, box("b").value, box("c").value]).toEqual(["new", "new", "old"]);
  });

  it("never types into a box that is not type=password", () => {
    // A text box that calls itself a password (autocomplete) would show the
    // value in the clear: neither the focus nor detection may pick it.
    html(`<form>
      <input type="text" id="shown-old" autocomplete="current-password">
      <input type="text" id="shown-new" autocomplete="new-password">
      <input type="password" id="new" autocomplete="new-password">
    </form>`);
    box("shown-new").focus();
    expect(focusedPassword(document)).toBeUndefined();
    expect(isPasswordBox(box("shown-new"))).toBe(false);
    const targets = rotateTargets(document, undefined, always);
    expect(ids(targets.next)).toEqual(["new"]);
    expect(targets.current).toEqual([]);
    rotateFill(targets, "old", "new", always);
    expect(box("shown-old").value).toBe("");
    expect(box("shown-new").value).toBe("");
    expect(box("new").value).toBe("new");
    // Even if a text box is handed in as the focused one.
    const forced = rotateTargets(document, box("shown-new"), always);
    expect(ids(forced.next)).toEqual(["new"]);
  });

  it("types nothing without a box for the new password", () => {
    html(`<form><input type="password" id="old" autocomplete="current-password"></form>`);
    const targets = rotateTargets(document, undefined, always);
    expect(targets.next).toEqual([]);
    expect(rotateFill(targets, "old", "new", always)).toEqual([]);
    // The old password does not go out alone.
    expect(box("old").value).toBe("");
  });

  it("checks the boxes again right before typing", () => {
    load("change-password.html");
    const targets = rotateTargets(document, undefined, always);
    // The page turned the confirmation into a text box after the probe.
    box("again").type = "text";
    box("old").remove();
    expect(rotateFill(targets, "old", "new", always)).toEqual(["new_password"]);
    expect(box("again").value).toBe("");
    // Hidden boxes are skipped too.
    load("change-password.html");
    const hidden = (el: Element): boolean => el.id !== "again";
    expect(rotateFill(rotateTargets(document, undefined, hidden), "o", "n", hidden)).toEqual(["new_password", "current_password"]);
  });
});
