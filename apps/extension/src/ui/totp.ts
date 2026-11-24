/**
 * Live one-time codes for the popup. A code is asked of klavd only while
 * its row is on screen and the popup is visible; between requests the
 * time blocks count down locally, one per second.
 */
import { DaemonError } from "../shared/protocol";
import { gated } from "./presence";

export interface Code {
  code: string;
  remaining: number;
}

type Listener = (code: Code | null) => void;

interface Watch {
  id: string;
  listeners: Set<Listener>;
  code?: Code;
  fetching?: boolean;
}

/** Items known to have no code (klavd answered `not_found`). */
const none = new Set<string>();

export class CodeTicker {
  private readonly watches = new Map<string, Watch>();
  private timer: number | undefined;

  constructor() {
    document.addEventListener("visibilitychange", () => {
      if (document.hidden) this.pause();
      else this.resume();
    });
  }

  /** Whether klavd said this item has no code. */
  static hasNone(id: string): boolean {
    return none.has(id);
  }

  /** Calls `listener` with the item's code now and every second; returns a stop function. */
  watch(id: string, listener: Listener): () => void {
    if (none.has(id)) {
      listener(null);
      return () => undefined;
    }
    let w = this.watches.get(id);
    if (!w) {
      w = { id, listeners: new Set() };
      this.watches.set(id, w);
      void this.fetch(w);
    } else if (w.code) {
      listener(w.code);
    }
    w.listeners.add(listener);
    this.resume();
    const watch = w;
    return () => {
      watch.listeners.delete(listener);
      if (watch.listeners.size === 0) this.watches.delete(id);
      if (this.watches.size === 0) this.pause();
    };
  }

  /** The code on screen for `id`, if any (for copying without another request). */
  current(id: string): Code | undefined {
    return this.watches.get(id)?.code;
  }

  stopAll(): void {
    this.watches.clear();
    this.pause();
  }

  private async fetch(w: Watch): Promise<void> {
    if (w.fetching) return;
    w.fetching = true;
    try {
      const code = await gated<Code>({ op: "totp", query: w.id });
      w.code = code;
      for (const l of w.listeners) l(code);
    } catch (e) {
      if (e instanceof DaemonError && (e.code === "not_found" || e.code === "invalid")) none.add(w.id);
      delete w.code;
      for (const l of w.listeners) l(null);
      this.watches.delete(w.id);
    } finally {
      w.fetching = false;
    }
  }

  private resume(): void {
    if (this.timer !== undefined || document.hidden || this.watches.size === 0) return;
    this.timer = window.setInterval(() => {
      this.tick();
    }, 1000);
  }

  private pause(): void {
    window.clearInterval(this.timer);
    this.timer = undefined;
    // Codes on screen are stale after a pause: ask again when it resumes.
    for (const w of this.watches.values()) delete w.code;
  }

  private tick(): void {
    for (const w of this.watches.values()) {
      if (!w.code) {
        void this.fetch(w);
        continue;
      }
      w.code = { code: w.code.code, remaining: w.code.remaining - 1 };
      if (w.code.remaining <= 0) void this.fetch(w);
      else for (const l of w.listeners) l(w.code);
    }
  }
}
