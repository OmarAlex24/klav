import { ext, installCommand } from "../shared/ext";
import {
  DaemonError,
  type ErrorBody,
  HOST_NAME,
  PROTOCOL_VERSION,
  type Request,
  type ResponseEnvelope,
} from "../shared/protocol";

/**
 * An error from the host as the pages see it. `extension_not_allowed` is
 * the host refusing this build (its wrapper does not list it): it is
 * shown like a missing host, with the command to run, which the host's
 * message names.
 */
function hostError(error: ErrorBody): DaemonError {
  return error.code === "extension_not_allowed"
    ? new DaemonError("host_missing", error.message)
    : new DaemonError(error.code, error.message, error.presence);
}

/**
 * The line for `request`. An unlock's `shown` (ADR 0041, own choice 34)
 * belongs to the envelope, next to `id`: klavd reads it there.
 */
export function envelope(id: number, request: Request): Record<string, unknown> {
  if (request.op === "unlock" && request.shown !== undefined) {
    const { shown, ...rest } = request;
    return { v: PROTOCOL_VERSION, id, request: rest, shown };
  }
  return { v: PROTOCOL_VERSION, id, request };
}

/** How long to wait for klavd (Touch ID prompts can take a while). */
const TIMEOUT_MS = 120_000;

interface Pending {
  resolve: (value: unknown) => void;
  reject: (error: DaemonError) => void;
  timer: ReturnType<typeof setTimeout>;
}

/** A line from klavd that is not a response: an event (agents layer). */
export type EventHandler = (event: Record<string, unknown>) => void;

/**
 * One long-lived native messaging port to `klav-native-host`. The port is
 * opened on the first call and again after it closes; while it is open,
 * Chromium keeps the service worker alive.
 */
export class NativeBridge {
  private port: chrome.runtime.Port | undefined;
  private nextId = 1;
  private readonly pending = new Map<number, Pending>();
  private readonly eventHandlers: EventHandler[] = [];
  private readonly disconnectHandlers: ((error: DaemonError) => void)[] = [];

  onEvent(handler: EventHandler): void {
    this.eventHandlers.push(handler);
  }

  /** Called when the port closes (klavd or the host went away). */
  onDisconnect(handler: (error: DaemonError) => void): void {
    this.disconnectHandlers.push(handler);
  }

  get connected(): boolean {
    return this.port !== undefined;
  }

  /** Opens the port now (to receive events without a request). */
  connect(): chrome.runtime.Port {
    if (this.port) return this.port;
    const port = ext.runtime.connectNative(HOST_NAME);
    // The host's refusal of this build, if it answered with one: the
    // reason this port closes (the browser only says the host exited).
    let refused: DaemonError | undefined;
    port.onMessage.addListener((message: unknown) => {
      refused = this.receive(message) ?? refused;
    });
    port.onDisconnect.addListener(() => {
      // Firefox reports the reason on the port itself.
      const portError = (port as { error?: { message?: string } }).error;
      const why = ext.runtime.lastError?.message ?? portError?.message ?? "";
      // Not installed, or the manifest does not list this extension:
      // Chromium says "forbidden". Listed, but the host's wrapper leaves it
      // out (the development build needs `--dev`): the host said so.
      const missing = /not found|no such native application|forbidden/i.test(why);
      const error =
        refused ??
        (missing
          ? new DaemonError("host_missing", `klav-native-host is not installed for this extension: run \`${installCommand()}\``)
          : new DaemonError("disconnected", "the connection to klavd closed"));
      this.port = undefined;
      for (const [id, p] of this.pending) {
        clearTimeout(p.timer);
        p.reject(error);
        this.pending.delete(id);
      }
      for (const handler of this.disconnectHandlers) handler(error);
    });
    this.port = port;
    return port;
  }

  /** Sends one request to klavd and resolves with its `ok` value. */
  call<T>(request: Request): Promise<T> {
    const port = this.connect();
    const id = this.nextId++;
    return new Promise<T>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new DaemonError("timeout", "klavd did not answer in time"));
      }, TIMEOUT_MS);
      this.pending.set(id, { resolve: resolve as (v: unknown) => void, reject, timer });
      try {
        port.postMessage(envelope(id, request));
      } catch {
        clearTimeout(timer);
        this.pending.delete(id);
        reject(new DaemonError("disconnected", "the connection to klavd closed"));
      }
    });
  }

  /** Sends a line that expects no answer of its own (event replies). */
  post(message: Record<string, unknown>): void {
    this.connect().postMessage(message);
  }

  /** Handles one message; returns the host's refusal if it is one. */
  private receive(message: unknown): DaemonError | undefined {
    if (typeof message !== "object" || message === null) return undefined;
    const record = message as Record<string, unknown>;
    if ("event" in record && typeof record.event === "object" && record.event !== null) {
      for (const handler of this.eventHandlers) handler(record.event as Record<string, unknown>);
      return undefined;
    }
    const response = message as ResponseEnvelope;
    const error = response.error ? hostError(response.error) : undefined;
    const pending = this.pending.get(response.id);
    if (pending) {
      this.pending.delete(response.id);
      clearTimeout(pending.timer);
      if (error) pending.reject(error);
      else pending.resolve(response.ok);
    }
    return response.error?.code === "extension_not_allowed" ? error : undefined;
  }
}
