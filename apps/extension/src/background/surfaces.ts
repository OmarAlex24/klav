/**
 * Which `klavd` operations each of the extension's pages may send through
 * the background (`daemon` messages; docs/extension.md §3). The native
 * host already keeps a closed list for the whole extension; this one is
 * per page, so the frames Klav draws inside web pages (menu, palette, save
 * bar) can only ask for what they show. Defence in depth: a bug in one of
 * them, or a page that tricks one, does not reach `view` with `reveal`,
 * `totp`, approvals, tasks or edits.
 */
import type { Request } from "../shared/protocol";

type Op = Request["op"];

/** The popup is a page of its own, out of reach of web pages: everything the native host allows. */
const POPUP = "popup.html";

const ONLY: Record<string, ReadonlySet<Op>> = {
  // The import wizard, in a tab of its own.
  "import.html": new Set<Op>(["status", "unlock", "projects", "import_add", "import_preview", "import_apply", "import_cancel"]),
  // The field menu: unlock and the generator with its history. Fills go
  // through `menu_fill`, which the background checks.
  "menu.html": new Set<Op>(["unlock", "generator_record", "generator_history", "generated_value", "generator_delete"]),
  // The palette: unlock and the list of other items (metadata only).
  "find.html": new Set<Op>(["unlock", "list"]),
  // The save bar: unlock (saving goes through `save_do`).
  "save.html": new Set<Op>(["unlock"]),
  // The passkey frame: unlock (signing and saving go through
  // `passkey_sign_in` and `passkey_save`, which the background checks).
  "passkey.html": new Set<Op>(["unlock"]),
};

/** The page of an extension URL (`menu.html` from `chrome-extension://…/menu.html#id`). */
export function pageOf(url: string | undefined): string | undefined {
  if (!url) return undefined;
  try {
    return new URL(url).pathname.replace(/^\//, "");
  } catch {
    return undefined;
  }
}

/** Whether the extension page at `url` may send `op` to klavd. The card, the notice and any other page: nothing. */
export function mayCall(url: string | undefined, op: unknown): boolean {
  const page = pageOf(url);
  if (page === POPUP) return true;
  const allowed = page === undefined ? undefined : ONLY[page];
  return allowed?.has(op as Op) ?? false;
}

/** Operations of an in-page frame that act on what it shows: they need the frame uncovered (T62). */
export const GUARDED_IN_MENU: ReadonlySet<Op> = new Set<Op>(["generated_value", "generator_delete"]);
