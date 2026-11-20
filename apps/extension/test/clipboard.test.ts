// Clearing the clipboard through Chromium's offscreen document.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { CLEAR_ATTEMPTS, clearNow, NOT_CLEARED_KEY } from "../src/background/clipboard";

const chrome = (globalThis as unknown as { chrome: Record<string, unknown> }).chrome;
let open: boolean;
let replies: unknown[];
const createDocument = vi.fn(() => {
  open = true;
  return Promise.resolve();
});
const closeDocument = vi.fn(() => {
  open = false;
  return Promise.resolve();
});
const sendMessage = vi.fn(() => {
  const reply = replies.shift();
  return reply instanceof Error ? Promise.reject(reply) : Promise.resolve(reply);
});
const set = vi.fn(() => Promise.resolve());

beforeEach(() => {
  vi.useFakeTimers();
  open = false;
  replies = [];
  vi.clearAllMocks();
  Object.assign(chrome, {
    runtime: {
      getURL: (path: string) => `chrome-extension://klav/${path}`,
      getContexts: () => Promise.resolve(open ? [{ contextType: "OFFSCREEN_DOCUMENT" }] : []),
      ContextType: { OFFSCREEN_DOCUMENT: "OFFSCREEN_DOCUMENT" },
      sendMessage,
    },
    offscreen: { createDocument, closeDocument, Reason: { CLIPBOARD: "CLIPBOARD" } },
    storage: { local: { set } },
  });
});

afterEach(() => {
  vi.useRealTimers();
});

async function run(): Promise<boolean> {
  const done = clearNow();
  await vi.runAllTimersAsync();
  return done;
}

describe("clearing the clipboard", () => {
  it("leaves the offscreen document open after clearing, so the write is not thrown away", async () => {
    replies = [true, true];
    expect(await run()).toBe(true);
    expect(await run()).toBe(true);
    expect(createDocument).toHaveBeenCalledOnce();
    expect(closeDocument).not.toHaveBeenCalled();
    expect(sendMessage).toHaveBeenCalledWith({ type: "offscreen_clear" });
    expect(set).not.toHaveBeenCalled();
  });

  it("tries again when the document did not answer, or could not write", async () => {
    replies = [new Error("Receiving end does not exist."), undefined, false, true];
    expect(await run()).toBe(true);
    expect(sendMessage).toHaveBeenCalledTimes(4);
    expect(set).not.toHaveBeenCalled();
  });

  it("leaves a record when every try failed", async () => {
    replies = Array<boolean>(CLEAR_ATTEMPTS).fill(false);
    expect(await run()).toBe(false);
    expect(sendMessage).toHaveBeenCalledTimes(CLEAR_ATTEMPTS);
    expect(set).toHaveBeenCalledWith({ [NOT_CLEARED_KEY]: expect.any(Number) as number });
  });
});
