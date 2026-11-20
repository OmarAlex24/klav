// Sign-ins in several steps: what comes after each fill, and the short wait for the password.
import { afterEach, describe, expect, it, vi } from "vitest";
import { endFlow, flowOf, nextStage, PASSWORD_WAIT_MS, setFlow } from "../src/background/flow";

const frame = { tabId: 7, frameId: 0, documentId: "doc" };

afterEach(() => {
  endFlow(7);
  vi.useRealTimers();
});

describe("sign-in in steps", () => {
  it("waits for the password after a form that asked only for the account", () => {
    expect(nextStage({ filled: ["username"], waiting: "password" }, false)).toBe("password");
  });

  it("waits for the code after the password, only if the item has one and it was not typed", () => {
    expect(nextStage({ filled: ["username", "password"] }, true)).toBe("otp");
    expect(nextStage({ filled: ["username", "password", "totp"] }, true)).toBeUndefined();
    expect(nextStage({ filled: ["username", "password"] }, false)).toBeUndefined();
    expect(nextStage({ filled: ["username"] }, true)).toBeUndefined();
  });

  it("gives up on the password after a short wait, and on everything after its deadline", () => {
    vi.useFakeTimers();
    const stuck = vi.fn();
    setFlow(7, { item: "gh", stage: "password", until: Date.now() + 60_000, press: true, last: frame }, stuck);
    vi.advanceTimersByTime(PASSWORD_WAIT_MS - 1);
    expect(stuck).not.toHaveBeenCalled();
    vi.advanceTimersByTime(1);
    expect(stuck).toHaveBeenCalledOnce();
    expect(flowOf(7, Date.now() + 61_000)).toBeUndefined();
  });

  it("does not give up while a step is being filled, nor once it moved on", () => {
    vi.useFakeTimers();
    const stuck = vi.fn();
    const flow = setFlow(7, { item: "gh", stage: "password", until: Date.now() + 60_000, press: true, last: frame }, stuck);
    flow.busy = true;
    vi.advanceTimersByTime(PASSWORD_WAIT_MS);
    expect(stuck).not.toHaveBeenCalled();
    setFlow(7, { item: "gh", stage: "otp", until: Date.now() + 60_000, press: true, last: frame }, stuck);
    vi.advanceTimersByTime(PASSWORD_WAIT_MS);
    expect(stuck).not.toHaveBeenCalled();
    expect(flowOf(7)?.stage).toBe("otp");
  });
});
