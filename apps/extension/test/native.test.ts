// The native messaging bridge (`background/native.ts`) with a fake port:
// when klav-native-host refuses this build (`extension_not_allowed`) and
// exits, the pages get `host_missing` with the host's command, not a bare
// «connection closed»; a port that just closes is still `disconnected`.
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { NativeBridge } from "../src/background/native";
import { DaemonError } from "../src/shared/protocol";

type Listener = (message: unknown) => void;

class FakePort {
  readonly posted: { id: number }[] = [];
  private readonly messages: Listener[] = [];
  private readonly disconnects: (() => void)[] = [];
  readonly onMessage = { addListener: (l: Listener) => this.messages.push(l) };
  readonly onDisconnect = { addListener: (l: () => void) => this.disconnects.push(l) };
  postMessage(message: { id: number }): void {
    this.posted.push(message);
  }
  /** A message from the host. */
  answer(message: unknown): void {
    for (const l of this.messages) l(message);
  }
  /** The host exits; Chromium puts its reason in `runtime.lastError`. */
  close(why: string): void {
    runtime.lastError = { message: why };
    for (const l of this.disconnects) l();
    runtime.lastError = undefined;
  }
}

const ports: FakePort[] = [];
const runtime: { id: string; lastError?: { message: string }; connectNative: (name: string) => FakePort } = {
  id: "niiplppgdljgimbnmokojdkofdcjkgao",
  connectNative: () => {
    const port = new FakePort();
    ports.push(port);
    return port;
  },
};
Object.assign((globalThis as unknown as { chrome: Record<string, unknown> }).chrome, { runtime });

/** The `n`th port the bridge opened. */
function portAt(n: number): FakePort {
  const port = ports[n];
  if (!port) throw new Error(`no port ${String(n)}`);
  return port;
}

const REFUSAL = "this extension is not allowed to use Klav here: run `klav extension install-host --dev`";

/** Rejection of `promise` as a DaemonError. */
async function failure(promise: Promise<unknown>): Promise<DaemonError> {
  try {
    await promise;
  } catch (e) {
    if (e instanceof DaemonError) return e;
    throw e;
  }
  throw new Error("resolved");
}

describe("NativeBridge", () => {
  let bridge: NativeBridge;
  let closed: DaemonError[];

  beforeEach(() => {
    bridge = new NativeBridge();
    closed = [];
    bridge.onDisconnect((error) => closed.push(error));
  });

  afterEach(() => {
    ports.length = 0;
  });

  it("shows the host's refusal as a missing host, with its command", async () => {
    const first = bridge.call({ op: "status" });
    const second = bridge.call({ op: "extension_attach", browser: "Dia" });
    const port = portAt(0);
    expect(port.posted.map((m) => m.id)).toEqual([1, 2]);
    // The host answers the first request, then exits without reading more.
    port.answer({ v: 1, id: 1, error: { code: "extension_not_allowed", message: REFUSAL } });
    const refused = await failure(first);
    expect(refused.code).toBe("host_missing");
    expect(refused.message).toContain("`klav extension install-host --dev`");
    port.close("Native host has exited.");
    // The request it never read, and the disconnect handlers (the agents
    // layer stops retrying on `host_missing`), get the same.
    const pending = await failure(second);
    expect(pending.code).toBe("host_missing");
    expect(pending.message).toBe(REFUSAL);
    expect(closed.map((e) => [e.code, e.message])).toEqual([["host_missing", REFUSAL]]);
    expect(bridge.connected).toBe(false);
  });

  it("takes the refusal even when its id is not one it sent", async () => {
    const call = bridge.call({ op: "status" });
    portAt(0).answer({ v: 1, id: 0, error: { code: "extension_not_allowed", message: REFUSAL } });
    portAt(0).close("Native host has exited.");
    expect((await failure(call)).code).toBe("host_missing");
  });

  it("a port that just closes is still disconnected, also after a refusal", async () => {
    const refusedCall = bridge.call({ op: "status" });
    portAt(0).answer({ v: 1, id: 1, error: { code: "extension_not_allowed", message: REFUSAL } });
    portAt(0).close("Native host has exited.");
    await failure(refusedCall);
    // The person ran the command: a new port, and this time klavd went away.
    const call = bridge.call({ op: "status" });
    expect(ports).toHaveLength(2);
    portAt(1).close("Native host has exited.");
    expect((await failure(call)).code).toBe("disconnected");
    expect(closed.map((e) => e.code)).toEqual(["host_missing", "disconnected"]);
  });

  it("other errors from klavd pass through as they are", async () => {
    const call = bridge.call({ op: "status" });
    portAt(0).answer({ v: 1, id: 1, error: { code: "locked", message: "klavd is locked" } });
    const error = await failure(call);
    expect([error.code, error.message]).toEqual(["locked", "klavd is locked"]);
    expect(bridge.connected).toBe(true);
  });

  it("a host that is not installed is still host_missing", async () => {
    const call = bridge.call({ op: "status" });
    portAt(0).close("Specified native messaging host not found.");
    const error = await failure(call);
    expect(error.code).toBe("host_missing");
    expect(error.message).toContain("klav extension install-host --dev");
  });
});
