// The presence gate in the extension (ADR 0041 §3.2, layer 4): the
// frame's words match klavd's Touch ID dialog, a password unlock says what
// it opens and sends `shown` only with the gate on, and the background asks
// for the master password in Klav's frame and sends it on the connection
// that asked, one question at a time.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { envelope, type NativeBridge } from "../src/background/native";
import {
  askInTab,
  callInTab,
  onPresenceEvent,
  presenceAnswer,
  presenceClosed,
  presenceLoad,
  startPresence,
} from "../src/background/presence";
import { browserReason, presenceQuestion, unlockOpens } from "../src/shared/presence";
import { type BrowserAsk, DaemonError, type DaemonStatus, type PresenceAsk, type Request } from "../src/shared/protocol";
import { useLocale } from "./setup";

afterEach(() => {
  useLocale("en");
});

const ask = (event: BrowserAsk["event"], title: string | undefined, site: string | undefined, attached: number | undefined, connection: boolean): BrowserAsk => ({
  event,
  agent: "claude-code",
  ...(title !== undefined ? { title } : {}),
  ...(site !== undefined ? { site } : {}),
  ...(attached !== undefined ? { attached } : {}),
  ...(connection ? { connection } : {}),
});

// The same table as `prompt.rs`'s
// `an_extension_connections_prompt_names_the_event_that_caused_it`: the
// frame says what klavd's Touch ID dialog says.
const TABLE: [BrowserAsk, boolean, string, string][] = [
  [
    ask("fill", "GitHub", undefined, undefined, false),
    true,
    "let agents fill in a browser until Klav locks, starting with “claude-code”'s fill of “GitHub”",
    "dejar que los agentes rellenen en un navegador hasta que Klav se bloquee, empezando por el relleno de «GitHub» que pidió «claude-code»",
  ],
  [
    ask("fill", "GitHub", undefined, undefined, true),
    true,
    "let agents fill through this browser connection until Klav locks, starting with “claude-code”'s fill of “GitHub”",
    "dejar que los agentes rellenen por esta conexión del navegador hasta que Klav se bloquee, empezando por el relleno de «GitHub» que pidió «claude-code»",
  ],
  [
    ask("password_change", "GitHub", undefined, undefined, false),
    true,
    "let agents fill in a browser until Klav locks, starting with “claude-code”'s password change for “GitHub”",
    "dejar que los agentes rellenen en un navegador hasta que Klav se bloquee, empezando por el cambio de contraseña de «GitHub» que pidió «claude-code»",
  ],
  [
    ask("password_change", "GitHub", undefined, undefined, true),
    true,
    "let agents fill through this browser connection until Klav locks, starting with “claude-code”'s password change for “GitHub”",
    "dejar que los agentes rellenen por esta conexión del navegador hasta que Klav se bloquee, empezando por el cambio de contraseña de «GitHub» que pidió «claude-code»",
  ],
  [
    ask("passkey_sign_in", "GitHub", "github.com", undefined, false),
    true,
    "let agents fill in a browser until Klav locks, starting with “claude-code”'s passkey sign-in to “github.com”",
    "dejar que los agentes rellenen en un navegador hasta que Klav se bloquee, empezando por el inicio de sesión con passkey en «github.com» que pidió «claude-code»",
  ],
  [
    ask("passkey_sign_in", "GitHub", "github.com", undefined, true),
    true,
    "let agents fill through this browser connection until Klav locks, starting with “claude-code”'s passkey sign-in to “github.com”",
    "dejar que los agentes rellenen por esta conexión del navegador hasta que Klav se bloquee, empezando por el inicio de sesión con passkey en «github.com» que pidió «claude-code»",
  ],
  [
    ask("fill", undefined, undefined, undefined, false),
    true,
    "let agents fill in a browser until Klav locks, starting with a fill “claude-code” asked for",
    "dejar que los agentes rellenen en un navegador hasta que Klav se bloquee, empezando por un relleno que pidió «claude-code»",
  ],
  [
    ask("fill", "GitHub", undefined, undefined, false),
    false,
    "let a browser connection receive “claude-code”'s values for “GitHub”",
    "dejar que una conexión del navegador reciba los valores de «claude-code» para «GitHub»",
  ],
  [
    ask("passkey_sign_in", "GitHub", "github.com", undefined, true),
    false,
    "let a browser connection receive “claude-code”'s values for “GitHub”",
    "dejar que una conexión del navegador reciba los valores de «claude-code» para «GitHub»",
  ],
  [
    ask("fill", "GitHub", undefined, 2, false),
    true,
    "let agents fill in a browser until Klav locks, starting with “claude-code”'s fill of “GitHub”; 2 browser connections are attached",
    "dejar que los agentes rellenen en un navegador hasta que Klav se bloquee, empezando por el relleno de «GitHub» que pidió «claude-code»; hay 2 conexiones del navegador activas",
  ],
  [
    ask("password_change", "GitHub", undefined, 3, true),
    false,
    "let a browser connection receive “claude-code”'s values for “GitHub”; 3 browser connections are attached",
    "dejar que una conexión del navegador reciba los valores de «claude-code» para «GitHub»; hay 3 conexiones del navegador activas",
  ],
];

describe("the frame's words", () => {
  it("are klavd's dialog's, in English and Spanish", () => {
    for (const [browser, untilLock, en, es] of TABLE) {
      useLocale("en");
      expect(browserReason(browser, untilLock)).toBe(en);
      useLocale("es");
      expect(browserReason(browser, untilLock)).toBe(es);
    }
  });

  it("ask a whole question, from `lasts`, never from `window` alone", () => {
    const browser = ask("fill", "GitHub", undefined, undefined, true);
    expect(presenceQuestion({ key: "connection", window: "5m", lasts: "until_lock", browser })).toBe(
      "Klav wants to let agents fill through this browser connection until Klav locks, starting with “claude-code”'s fill of “GitHub”.",
    );
    expect(presenceQuestion({ key: "connection", window: "always", browser })).toBe(
      "Klav wants to let a browser connection receive “claude-code”'s values for “GitHub”.",
    );
    useLocale("es");
    expect(presenceQuestion({ key: "parent", window: "5m", lasts: "5m" })).toBe("Klav quiere dejar que este navegador use tu bóveda durante 5 minutos.");
    expect(presenceQuestion({ key: "parent", window: "always", value: { kind: "fill", title: "GitHub" } })).toBe("Klav quiere rellenar «GitHub» en este navegador.");
  });

  it("keep a name's own quote marks from closing the quote", () => {
    const browser = { ...ask("fill", "Git”Hub", undefined, undefined, false), agent: "evil” and approve" };
    expect(browserReason(browser, false)).toBe("let a browser connection receive “evil' and approve”'s values for “Git'Hub”");
  });
});

describe("a password unlock", () => {
  const status = (presence?: DaemonStatus["presence"]): DaemonStatus =>
    ({ unlocked: false, touch_id: { available: false, enrolled: false }, ...(presence ? { presence } : {}) }) as DaemonStatus;

  it("says nothing and sends no `shown` without the gate", () => {
    expect(unlockOpens(status())).toEqual({});
    expect(unlockOpens(undefined)).toEqual({});
  });

  it("sends the window its own question named (own choice 34)", () => {
    expect(unlockOpens(status({ key: "parent", lasts: "5m" }))).toEqual({ shown: "5m", line: "Unlocking also lets this browser use your vault for 5 minutes." });
    expect(unlockOpens(status({ key: "parent", lasts: "until_lock" }))).toEqual({
      shown: "unlocked",
      line: "Unlocking also lets this browser use your vault until Klav locks.",
    });
    // The first unlock since klavd started: no window, and the question names none.
    expect(unlockOpens(status({ key: "parent" }))).toEqual({ shown: "always" });
  });

  it("puts `shown` in the envelope, never `untyped`", () => {
    expect(envelope(3, { op: "unlock", password: "pw", shown: "5m" })).toEqual({ v: 1, id: 3, request: { op: "unlock", password: "pw" }, shown: "5m" });
    expect(envelope(4, { op: "unlock", password: "pw" })).toEqual({ v: 1, id: 4, request: { op: "unlock", password: "pw" } });
  });
});

/** The native connection, as the background sees it: every call recorded, answered by `answer`. */
function fakeBridge(answer: (request: Request) => Promise<unknown>): { bridge: NativeBridge; calls: Request[] } {
  const calls: Request[] = [];
  const bridge = {
    call: (request: Request) => {
      calls.push(structuredClone(request));
      return answer(request);
    },
  } as unknown as NativeBridge;
  return { bridge, calls };
}

const ASK: PresenceAsk = { key: "connection", window: "5m", lasts: "until_lock", browser: ask("fill", "GitHub", undefined, 2, true) };

describe("the background's question", () => {
  const shown: { tabId: number; id: string }[] = [];
  const hidden: string[] = [];

  beforeEach(() => {
    shown.length = 0;
    hidden.length = 0;
    startPresence(
      (tabId, id) => {
        shown.push({ tabId, id });
        return Promise.resolve();
      },
      (_, id) => hidden.push(id),
    );
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  const settled = (): Promise<void> => new Promise((r) => setTimeout(r, 0));

  it("sends klavd's presence event's password on the same connection, and asks again after a wrong one", async () => {
    let right = false;
    const { bridge, calls } = fakeBridge((request) => {
      if (request.op === "extension_presence") {
        if (request.password !== "right") return Promise.reject(new DaemonError("wrong_credentials", "wrong"));
        right = true;
        return Promise.resolve({});
      }
      return Promise.resolve(null);
    });
    onPresenceEvent(bridge, { kind: "presence", id: 7, tab_id: 4, presence: ASK });
    await settled();
    expect(shown).toHaveLength(1);
    const id = shown[0]?.id ?? "";
    expect(shown[0]?.tabId).toBe(4);
    // Only the frame in the event's own tab.
    expect(() => presenceLoad(id, 5)).toThrow("over");
    expect(presenceLoad(id, 4)).toEqual(ASK);
    await expect(presenceAnswer(id, 4, "wrong")).rejects.toMatchObject({ code: "wrong_credentials" });
    expect(hidden).toEqual([]);
    await presenceAnswer(id, 4, "right");
    await settled();
    expect(right).toBe(true);
    expect(hidden).toEqual([id]);
    expect(calls).toEqual([
      { op: "extension_presence", event: 7, password: "wrong" },
      { op: "extension_presence", event: 7, password: "right" },
    ]);
  });

  it("declines when the person closes the frame", async () => {
    const { bridge, calls } = fakeBridge(() => Promise.resolve(null));
    onPresenceEvent(bridge, { kind: "presence", id: 8, tab_id: 4, presence: ASK });
    await settled();
    const id = shown[0]?.id ?? "";
    presenceLoad(id, 4);
    presenceClosed(id);
    await settled();
    expect(calls).toEqual([{ op: "extension_reply", event: 8, error: { code: "denied", message: "the person declined in the browser" } }]);
    expect(hidden).toEqual([id]);
  });

  it("declines when the frame never shows (a tab Klav can't draw in)", async () => {
    vi.useFakeTimers();
    const { bridge, calls } = fakeBridge(() => Promise.resolve(null));
    onPresenceEvent(bridge, { kind: "presence", id: 9, tab_id: 4, presence: ASK });
    await vi.advanceTimersByTimeAsync(5_000);
    expect(calls).toEqual([{ op: "extension_reply", event: 9, error: { code: "denied", message: "Klav could not show its frame in this tab" } }]);
  });

  it("sends a fill again with the password, the same request on the same connection", async () => {
    const { bridge, calls } = fakeBridge((request) =>
      request.op === "autofill" && request.password === undefined
        ? Promise.reject(new DaemonError("presence_required", "presence", { key: "parent", window: "5m", value: { kind: "fill", title: "GitHub" } }))
        : Promise.resolve({ kind: "login", fields: [] }),
    );
    const filled = callInTab(bridge, 4, { op: "autofill", item: "A", url: "https://github.com/login" });
    await settled();
    const id = shown[0]?.id ?? "";
    expect(presenceLoad(id, 4).value).toEqual({ kind: "fill", title: "GitHub" });
    await presenceAnswer(id, 4, "pw");
    await expect(filled).resolves.toEqual({ kind: "login", fields: [] });
    expect(calls).toEqual([
      { op: "autofill", item: "A", url: "https://github.com/login" },
      { op: "autofill", item: "A", url: "https://github.com/login", password: "pw" },
    ]);
  });

  it("tells the person, in their language, why their own fill filled nothing", async () => {
    const { bridge } = fakeBridge(() =>
      Promise.reject(new DaemonError("presence_required", "presence", { key: "parent", window: "5m", value: { kind: "fill", title: "GitHub" } })),
    );
    useLocale("es");
    const filled = callInTab(bridge, 4, { op: "autofill", item: "A", url: "https://github.com/login" });
    await settled();
    presenceClosed(shown[0]?.id ?? "");
    await expect(filled).rejects.toMatchObject({ code: "denied", message: "Dijiste que no: no se rellenó nada." });
  });

  it("without the gate, fills with one call and shows nothing", async () => {
    const { bridge, calls } = fakeBridge(() => Promise.resolve({ kind: "login", fields: [] }));
    await callInTab(bridge, 4, { op: "autofill", item: "A", url: "https://github.com/login" });
    expect(calls).toHaveLength(1);
    expect(shown).toEqual([]);
  });

  it("asks one question at a time: klavd keeps only the last one per connection", async () => {
    const first = askInTab(4, ASK, () => Promise.resolve("one"));
    const second = askInTab(5, ASK, () => Promise.resolve("two"));
    await settled();
    expect(shown.map((s) => s.tabId)).toEqual([4]);
    await presenceAnswer(shown[0]?.id ?? "", 4, "pw");
    await expect(first).resolves.toBe("one");
    await settled();
    expect(shown.map((s) => s.tabId)).toEqual([4, 5]);
    presenceClosed(shown[1]?.id ?? "");
    await expect(second).rejects.toMatchObject({ code: "denied" });
  });
});
