/**
 * Clearing the clipboard 30 seconds after the popup copies a value. The
 * popup may be closed by then, so the background keeps an alarm (it fires
 * even if the service worker slept). Chromium's service worker has no
 * clipboard: an offscreen document clears it. Firefox's background page
 * can do it itself.
 *
 * Without `clipboardRead` Klav cannot tell whether the clipboard still
 * holds its value: it clears it anyway, unless the person copied again
 * from Klav (each copy moves the alarm).
 */
import { ext } from "../shared/ext";

export const CLEAR_AFTER_S = 30;
const ALARM = "clear-clipboard";
/** Tries before giving up, and the wait between them (it grows each time). */
export const CLEAR_ATTEMPTS = 5;
export const RETRY_MS = 250;
/**
 * When the last clear failed (`storage.local`, a timestamp): a password
 * may have stayed in the clipboard. The console is off limits (ADR 0017).
 */
export const NOT_CLEARED_KEY = "clipboardNotCleared";

/** Called when the popup copied something from the vault. */
export async function copied(): Promise<void> {
  await ext.alarms.clear(ALARM);
  await ext.alarms.create(ALARM, { when: Date.now() + CLEAR_AFTER_S * 1000 });
}

/** Writes an empty string to the clipboard from a document with a DOM. */
export function clearWith(doc: Document): boolean {
  return writeWith(doc, "");
}

/**
 * Writes `text` to the clipboard from a document with a DOM: what the
 * field menu does, from a frame without the Clipboard API (its `allow` is
 * empty), right after the person's click.
 */
export function writeWith(doc: Document, text: string): boolean {
  const onCopy = (event: ClipboardEvent): void => {
    event.clipboardData?.setData("text/plain", text);
    event.preventDefault();
  };
  doc.addEventListener("copy", onCopy);
  try {
    // Deprecated, but the only way to write the clipboard without focus.
    // eslint-disable-next-line @typescript-eslint/no-deprecated
    return doc.execCommand("copy");
  } finally {
    doc.removeEventListener("copy", onCopy);
  }
}

/**
 * Opens the offscreen document unless it is open already. It stays open:
 * its `execCommand("copy")` answers before the browser has written the
 * clipboard (the write travels apart from the message), and closing the
 * document then throws away the write. That left the password in the
 * clipboard now and then.
 */
async function offscreenDocument(): Promise<void> {
  const url = ext.runtime.getURL("offscreen.html");
  const open = await ext.runtime.getContexts({ contextTypes: [ext.runtime.ContextType.OFFSCREEN_DOCUMENT], documentUrls: [url] });
  if (open.length > 0) return;
  await ext.offscreen.createDocument({
    url,
    reasons: [ext.offscreen.Reason.CLIPBOARD],
    justification: "Clear a password Klav copied, 30 seconds later",
  });
}

/** One try: whether the document that cleared said it did. */
async function clearOnce(): Promise<boolean> {
  if (__TARGET__ === "firefox") return clearWith(document);
  await offscreenDocument();
  const reply: unknown = await ext.runtime.sendMessage({ type: "offscreen_clear" });
  return reply === true;
}

/** Clears the clipboard, trying again a few times; leaves a record if it could not. */
export async function clearNow(): Promise<boolean> {
  for (let attempt = 0; attempt < CLEAR_ATTEMPTS; attempt++) {
    if (attempt > 0) await new Promise((done) => setTimeout(done, RETRY_MS * attempt));
    if (await clearOnce().catch(() => false)) return true;
  }
  await ext.storage.local.set({ [NOT_CLEARED_KEY]: Date.now() }).catch(() => undefined);
  return false;
}

/** One clear at a time: two at once could both try to open the document. */
let clearing: Promise<unknown> = Promise.resolve();

export function startClipboard(): void {
  ext.alarms.onAlarm.addListener((alarm) => {
    if (alarm.name === ALARM) clearing = clearing.then(clearNow, clearNow);
  });
}
