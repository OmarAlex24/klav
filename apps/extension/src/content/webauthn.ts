/**
 * The passkey bridge (ADR 0020), an isolated content script in every
 * http(s) frame from `document_start`: it hears the WebAuthn calls of the
 * page-world hook (`page/webauthn.ts`) on this window only, keeps the
 * well-formed ones and passes them to the background, which decides with
 * the address the browser gives for this frame. The top frame's bridge
 * also draws Klav's passkey surface, so it can show even while the page is
 * still loading (the main content script waits for `document_idle`).
 *
 * It never sees the master password or a private key: the surface talks
 * to the background directly, and what comes back here is what the page
 * gets anyway (a credential, or «ask the browser»).
 */
import { ext } from "../shared/ext";
import type { ContentMessage, PasskeyReply, Reply, ToContent } from "../shared/messages";
import { cleanCall, type PageWire, type PasskeyOutcome } from "../shared/passkey";
import { InPage } from "./ui";

/** Calls waiting for the background, by its ID → the page's ID, and back. */
const waiting = new Map<string, string>();
const byPage = new Map<string, string>();
let ui: InPage | undefined;

function toPage(message: PageWire): void {
  window.postMessage(message, "*");
}

function done(pageId: string, outcome: PasskeyOutcome): void {
  toPage({ klav: "webauthn-done", id: pageId, outcome });
}

async function send<T>(message: ContentMessage): Promise<T> {
  const reply = await ext.runtime.sendMessage<ContentMessage, Reply<T> | undefined>(message);
  if (!reply?.ok) throw new Error(reply ? reply.error.message : "no reply");
  return reply.value;
}

/** Whether this frame has the top frame's origin (frames of another origin go to the browser, ADR 0020 P10). */
function sameOriginAsTop(): boolean {
  if (window.top === window) return true;
  try {
    return window.top?.location.origin === location.origin;
  } catch {
    return false;
  }
}

async function request(pageId: string, raw: unknown): Promise<void> {
  const call = cleanCall(raw);
  if (!call) {
    done(pageId, { status: "browser" });
    return;
  }
  let reply: PasskeyReply;
  try {
    reply = await send<PasskeyReply>({ type: "passkey_request", call, same_origin_as_top: sameOriginAsTop() });
  } catch {
    // No background (the extension was reloaded): as if Klav were not here.
    done(pageId, { status: "browser" });
    return;
  }
  if ("outcome" in reply) {
    done(pageId, reply.outcome);
    return;
  }
  waiting.set(reply.pending, pageId);
  byPage.set(pageId, reply.pending);
}

addEventListener("message", (event: MessageEvent) => {
  // Only this window's own page world (another frame cannot post here as it).
  if (event.source !== window) return;
  const m = event.data as Partial<Record<string, unknown>> | null;
  if (typeof m !== "object" || m === null || typeof m.id !== "string" || m.id.length > 64) return;
  if (m.klav === "webauthn-call") {
    toPage({ klav: "webauthn-ack", id: m.id });
    void request(m.id, m.call);
  } else if (m.klav === "webauthn-abort") {
    const id = byPage.get(m.id);
    if (!id) return;
    byPage.delete(m.id);
    waiting.delete(id);
    void send({ type: "passkey_cancel", id }).catch(() => undefined);
  }
});

ext.runtime.onMessage.addListener((message: ToContent, sender: chrome.runtime.MessageSender, sendResponse: (reply?: unknown) => void) => {
  if (sender.id !== ext.runtime.id) return false;
  switch (message.type) {
    case "clear":
      // Before the background signs or saves for a choice in the passkey
      // frame: the page must leave the frame alone (T62). Only the top
      // frame draws it; the main content script leaves this one to us.
      if (message.surface !== "passkey" || window.top !== window) return false;
      sendResponse(ui?.isClear("passkey", message.id) ?? false);
      return false;
    case "passkey_result": {
      const pageId = waiting.get(message.id);
      if (pageId === undefined) return false;
      waiting.delete(message.id);
      byPage.delete(pageId);
      done(pageId, message.outcome);
      return false;
    }
    case "passkey_show":
      if (window.top !== window) return false;
      ui ??= new InPage(
        () => undefined,
        () => undefined,
      );
      ui.show("passkey", message.id, true);
      return false;
    case "passkey_hide":
      ui?.hide("passkey", message.id);
      return false;
    case "size":
      if (message.surface === "passkey") ui?.size("passkey", message.id, message.height);
      return false;
    default:
      return false;
  }
});

addEventListener("pagehide", () => {
  ui?.hide("passkey");
  // The page is going: its calls are over (a conditional one could wait an hour).
  // If it comes back from the back-forward cache, its calls end as declined.
  for (const [id, pageId] of waiting) {
    void send({ type: "passkey_cancel", id }).catch(() => undefined);
    done(pageId, { status: "error", name: "NotAllowedError", message: "The page was left." });
  }
  waiting.clear();
  byPage.clear();
});
