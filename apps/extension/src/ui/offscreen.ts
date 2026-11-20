/** Chromium's offscreen document: clears the clipboard for the background. */
import { clearWith } from "../background/clipboard";
import { ext } from "../shared/ext";

ext.runtime.onMessage.addListener((message: unknown, sender: chrome.runtime.MessageSender, sendResponse: (ok: boolean) => void) => {
  if (sender.id !== ext.runtime.id || (message as { type?: unknown } | null)?.type !== "offscreen_clear") return false;
  sendResponse(clearWith(document));
  return false;
});
