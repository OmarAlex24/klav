/**
 * The WebExtension API. Firefox exposes promise-based `browser.*`; Chromium
 * (MV3) returns promises from `chrome.*`. Both have the shape of the
 * `chrome` types for what Klav uses.
 */
export const ext: typeof chrome =
  (globalThis as unknown as { browser?: typeof chrome }).browser ?? chrome;

/** The Chromium development build's ID (fixed by the public `key` of its manifest). */
export const DEV_CHROMIUM_ID = "niiplppgdljgimbnmokojdkofdcjkgao";

/**
 * The command that lets this build talk to klavd: the development build
 * needs `--dev`, since its ID comes from a public key (layer 09).
 */
export function installCommand(): string {
  return ext.runtime.id === DEV_CHROMIUM_ID ? "klav extension install-host --dev" : "klav extension install-host";
}

/** The extension's own origin (`chrome-extension://…/`, `moz-extension://…/`). */
export function extensionOrigin(): string {
  return ext.runtime.getURL("");
}

/**
 * Whether a message comes from one of our own pages (popup, menu, save
 * bar), as opposed to a content script running inside a web page.
 */
export function fromExtensionPage(sender: chrome.runtime.MessageSender): boolean {
  return sender.id === ext.runtime.id && typeof sender.url === "string" && sender.url.startsWith(extensionOrigin());
}
