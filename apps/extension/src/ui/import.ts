/**
 * The import wizard (ADR 0024): «¿De dónde vienes?», how to export from
 * there, the files, a preview without values (new, merged, already in
 * Klav), the import, and a last reminder to delete the export.
 *
 * The files are read into memory only to be sent to klavd, in pieces
 * that fit a native message; klavd parses and merges them (`import_*`),
 * and nothing is stored here. Pictures of Google Authenticator's QR codes
 * are redrawn as PNG first, so a photo in any format the browser opens
 * works.
 */
import { animate, ditherCanvas, keyhole } from "../shared/dither";
import { installCommand } from "../shared/ext";
import { formatNumber, locale, type MessageKey, localizePage, plural, t } from "../shared/i18n";
import { daemon } from "../shared/messages";
import {
  DaemonError,
  type DaemonStatus,
  type ImportAdded,
  type ImportChange,
  type ImportPreview,
  type ImportResult,
  type ImportRow,
  type ImportSource,
  type ProjectSummary,
} from "../shared/protocol";
import { clear, h } from "./dom";
import { glyph, icon, tile } from "./kit";
import { siteTile } from "./siteicon";
import { errorText, kindName } from "./strings";

localizePage("imp_page_title");
const app = document.getElementById("app") as HTMLElement;

/** One piece of a file per `import_add`: 512 KiB is 683 KiB in base64, under the 1 MiB of a native message. */
const PIECE = 512 * 1024;
/** klav-import's limit. */
const MAX_FILE = 256 * 1024 * 1024;
/** A picture is redrawn at most this wide or tall: plenty for a QR code. */
const MAX_SIDE = 2400;

interface SourceDef {
  id: ImportSource | "authy";
  name: MessageKey;
  sub: MessageKey;
  /** For the logo (Simple Icons) when there is one. */
  site?: string;
  steps: MessageKey[];
  accept: string;
  images?: boolean;
}

const SOURCES: SourceDef[] = [
  {
    id: "bitwarden",
    name: "imp_src_bitwarden",
    sub: "imp_sub_bitwarden",
    site: "bitwarden.com",
    steps: ["imp_steps_bitwarden_1", "imp_steps_bitwarden_2", "imp_steps_bitwarden_3"],
    accept: ".json,.csv,application/json,text/csv",
  },
  {
    id: "1password",
    name: "imp_src_1password",
    sub: "imp_sub_1password",
    site: "1password.com",
    steps: ["imp_steps_1password_1", "imp_steps_1password_2", "imp_steps_1password_3"],
    accept: ".1pux,.csv",
  },
  {
    id: "google",
    name: "imp_src_google",
    sub: "imp_sub_google",
    site: "google.com",
    steps: ["imp_steps_google_1", "imp_steps_google_2", "imp_steps_google_3"],
    accept: "image/*,.txt",
    images: true,
  },
  {
    id: "chrome",
    name: "imp_src_chrome",
    sub: "imp_sub_chrome",
    steps: ["imp_steps_chrome_1", "imp_steps_chrome_2", "imp_steps_chrome_3"],
    accept: ".csv,text/csv",
  },
  {
    id: "firefox",
    name: "imp_src_firefox",
    sub: "imp_sub_firefox",
    site: "firefox.com",
    steps: ["imp_steps_firefox_1", "imp_steps_firefox_2", "imp_steps_firefox_3"],
    accept: ".csv,text/csv",
  },
  {
    id: "safari",
    name: "imp_src_safari",
    sub: "imp_sub_safari",
    steps: ["imp_steps_safari_1", "imp_steps_safari_2", "imp_steps_safari_3"],
    accept: ".csv,text/csv",
  },
  { id: "authy", name: "imp_src_authy", sub: "imp_sub_authy", steps: [], accept: "" },
  {
    id: "csv",
    name: "imp_src_csv",
    sub: "imp_sub_csv",
    steps: ["imp_steps_csv_1", "imp_steps_csv_2"],
    accept: ".csv,text/csv",
  },
];

/** The import in progress: klavd's session and what it read so far. */
interface Pending {
  source: SourceDef;
  session?: string;
  added?: ImportAdded;
  /** File names, for the last reminder. */
  names: string[];
  /** `vault/project`, as chosen. */
  destination?: { vault: string; project: string };
}

let pending: Pending | undefined;

function errorOf(e: unknown): DaemonError {
  return e instanceof DaemonError ? e : new DaemonError("internal", e instanceof Error ? e.message : "error");
}

/** `append`, skipping what is not there. */
function put(el: Element, ...children: (Node | string | null | undefined | false)[]): void {
  for (const child of children) if (child !== null && child !== undefined && child !== false) el.append(child);
}

function notice(text: string): HTMLElement {
  return h("p", { class: "notice", role: "alert" }, text);
}

function screen(className = ""): HTMLElement {
  clear(app);
  document.body.className = className;
  const bar = h(
    "header",
    { class: "imp-bar" },
    h("span", { class: "brand" }, glyph("brand-glyph"), h("span", { class: "brand-name" }, "klav")),
    h("span", { class: "imp-bar-sep", "aria-hidden": "true" }),
    h("span", { class: "imp-bar-title" }, t("imp_heading")),
  );
  const body = h("div", { class: "imp" });
  app.append(bar, body);
  window.scrollTo(0, 0);
  return body;
}

function heading(text: string, lede?: string): HTMLElement {
  const title = h("h1", { class: "title-l imp-title", tabindex: "-1" }, text);
  queueMicrotask(() => {
    title.focus({ preventScroll: true });
  });
  return h("div", { class: "imp-head" }, title, lede ? h("p", { class: "imp-lede" }, lede) : null);
}

function back(label: string, go: () => void): HTMLElement {
  return h("button", { class: "back", type: "button", onclick: go }, icon("back"), label);
}

function sourceTile(source: SourceDef): HTMLElement {
  return source.site ? siteTile(t(source.name), source.site) : tile(t(source.name));
}

/** Forgets klavd's session, if any (leaving, starting over). */
async function cancel(): Promise<void> {
  const session = pending?.session;
  pending = undefined;
  if (session) await daemon({ op: "import_cancel", session }).catch(() => undefined);
}

// ------------------------------------------------------------------ start

async function start(): Promise<void> {
  let status: DaemonStatus;
  try {
    status = await daemon<DaemonStatus>({ op: "status" });
  } catch (e) {
    showProblem(errorOf(e));
    return;
  }
  if (!status.logged_in) showProblem(new DaemonError("not_logged_in", ""));
  else if (!status.unlocked) showLocked(status);
  else showSources();
}

function showProblem(error: DaemonError): void {
  const body = screen();
  put(body,
    heading(t("unavailable_title"), errorText(error.code, error.message)),
    // As in the popup: what to run so this build can reach klavd.
    error.code === "host_missing" &&
      h(
        "div",
        { class: "imp-install" },
        h("p", {}, t("unavailable_install")),
        h("code", { class: "imp-command" }, installCommand()),
        h("p", { class: "imp-rule" }, t("unavailable_restart")),
      ),
    h("div", { class: "imp-actions" }, h("button", { class: "btn", type: "button", onclick: () => void start() }, t("retry"))),
  );
}

function showLocked(status: DaemonStatus, problem?: DaemonError): void {
  const body = screen();
  const message = h("div", {}, problem ? notice(errorText(problem.code, problem.message)) : null);
  const input = h("input", {
    type: "password",
    class: "input",
    autocomplete: "current-password",
    "aria-label": t("master_password"),
    placeholder: t("master_password"),
    required: true,
  });
  const submit = h("button", { class: "btn btn-primary", type: "submit" }, t("unlock"));
  const form = h("form", { class: "imp-unlock" }, input, submit);
  const unlock = async (password?: string): Promise<void> => {
    submit.disabled = true;
    try {
      const now = await daemon<DaemonStatus>(password === undefined ? { op: "unlock" } : { op: "unlock", password });
      if (now.unlocked) showSources();
      else showLocked(now);
    } catch (e) {
      showLocked(status, errorOf(e));
    }
  };
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    const password = input.value;
    input.value = "";
    void unlock(password);
  });
  const touchId = status.touch_id.available && status.touch_id.enrolled && !status.touch_id.password_required;
  put(body,
    heading(t("imp_locked_title"), status.email),
    message,
    form,
    touchId ? h("button", { class: "btn-link", type: "button", onclick: () => void unlock() }, t("unlock_touch_id")) : null,
  );
  queueMicrotask(() => {
    input.focus();
  });
}

// ---------------------------------------------------------------- sources

function showSources(): void {
  const body = screen();
  const list = h(
    "div",
    { class: "imp-sources" },
    ...SOURCES.map((source) =>
      h(
        "button",
        {
          class: "imp-source",
          type: "button",
          onclick: () => {
            if (source.id === "authy") showAuthy();
            else void showSource(source);
          },
        },
        sourceTile(source),
        h("span", { class: "row-main" }, h("span", { class: "row-title" }, t(source.name)), h("span", { class: "row-sub" }, t(source.sub))),
      ),
    ),
  );
  put(body,heading(t("imp_title"), t("imp_lede")), list, h("p", { class: "imp-rule" }, t("imp_rule")));
}

function showAuthy(): void {
  const body = screen();
  put(body,
    back(t("imp_all_sources"), showSources),
    heading(t("imp_authy_title"), t("imp_authy_text")),
    h("ol", { class: "imp-steps" }, ...(["imp_authy_1", "imp_authy_2", "imp_authy_3", "imp_authy_4"] as const).map((k) => h("li", {}, t(k)))),
    h("p", { class: "sub" }, t("imp_authy_note")),
  );
}

// ------------------------------------------------------------------ files

function base64url(bytes: Uint8Array): string {
  let text = "";
  for (let i = 0; i < bytes.length; i += 0x8000) text += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** A picture, redrawn as PNG (klavd reads QR codes from PNG). */
async function asPng(file: File): Promise<Uint8Array> {
  if (file.type === "image/png") return new Uint8Array(await file.arrayBuffer());
  let bitmap: ImageBitmap;
  try {
    bitmap = await createImageBitmap(file);
  } catch {
    throw new DaemonError("invalid", t("imp_not_image", file.name));
  }
  const scale = Math.min(1, MAX_SIDE / Math.max(bitmap.width, bitmap.height));
  const canvas = new OffscreenCanvas(Math.round(bitmap.width * scale), Math.round(bitmap.height * scale));
  const ctx = canvas.getContext("2d");
  if (!ctx) throw new DaemonError("internal", "no canvas");
  ctx.drawImage(bitmap, 0, 0, canvas.width, canvas.height);
  bitmap.close();
  const blob = await canvas.convertToBlob({ type: "image/png" });
  return new Uint8Array(await blob.arrayBuffer());
}

/** Sends one file to klavd, in pieces. */
async function send(p: Pending, name: string, bytes: Uint8Array): Promise<void> {
  const from = p.source.id === "authy" ? undefined : p.source.id;
  let offset = 0;
  do {
    const piece = bytes.subarray(offset, offset + PIECE);
    offset += PIECE;
    const more = offset < bytes.length;
    p.added = await daemon<ImportAdded>({
      op: "import_add",
      ...(p.session ? { session: p.session } : {}),
      name,
      ...(from ? { from } : {}),
      data: base64url(piece),
      ...(more ? { more } : {}),
    });
    p.session = p.added.session;
  } while (offset < bytes.length);
  p.names.push(name);
}

async function addFile(p: Pending, file: File): Promise<void> {
  if (file.size > MAX_FILE) throw new DaemonError("invalid", t("imp_too_large", file.name));
  const isText = file.name.toLowerCase().endsWith(".txt") || file.type.startsWith("text/");
  const bytes = p.source.images && !isText ? await asPng(file) : new Uint8Array(await file.arrayBuffer());
  await send(p, file.name, bytes);
}

// ----------------------------------------------------------------- source

async function showSource(source: SourceDef, keep?: Pending): Promise<void> {
  if (!keep) await cancel();
  const p: Pending = keep ?? { source, names: [] };
  pending = p;
  const body = screen();
  const projects = await daemon<ProjectSummary[]>({ op: "projects" }).catch(() => [] as ProjectSummary[]);

  const status = h("div", { class: "imp-status", role: "status" });
  const errors = h("div", {});
  const files = h("div", { class: "imp-files" });
  const warnings = h("div", { class: "imp-group" });
  const review = h("button", { class: "btn btn-primary", type: "button", disabled: true }, t("imp_review"));
  const over = h("button", { class: "btn-link", type: "button", hidden: true }, t("imp_start_over"));

  const render = (): void => {
    clear(files);
    clear(warnings);
    const added = p.added;
    review.disabled = !added || added.entries === 0;
    over.hidden = !p.session;
    if (!added) return;
    for (const s of added.sources) {
      files.append(
        h(
          "div",
          { class: "imp-file" },
          h(
            "div",
            { class: "imp-file-head" },
            h("span", { class: "imp-file-name" }, s.name),
            h("span", { class: "imp-file-count" }, plural("imp_entries", s.items)),
          ),
          ...s.skipped.map((r) => h("p", { class: "imp-remark" }, t("imp_skipped", r.at, r.reason))),
          ...s.notes.map((r) => h("p", { class: "imp-remark" }, t("imp_note", r.at, r.reason))),
          s.more_remarks ? h("p", { class: "imp-remark" }, t("imp_more_remarks", s.more_remarks)) : null,
        ),
      );
    }
    for (const m of added.missing) warnings.append(h("p", { class: "imp-warn" }, missingText(m.size, m.missing)));
    if (added.passkeys > 0) warnings.append(h("p", { class: "imp-warn" }, plural("imp_passkeys", added.passkeys)));
  };

  const take = async (list: Iterable<File>): Promise<void> => {
    clear(errors);
    for (const file of list) {
      status.textContent = t("imp_reading", file.name);
      try {
        await addFile(p, file);
      } catch (e) {
        const err = errorOf(e);
        errors.append(notice(err.message.startsWith(file.name) ? err.message : `${file.name}: ${errorText(err.code, err.message)}`));
      }
      render();
    }
    status.textContent = "";
  };

  const picker = h("input", { type: "file", accept: source.accept, multiple: true, hidden: true, "aria-label": t(source.images ? "imp_choose_images" : "imp_choose_file") });
  picker.addEventListener("change", () => {
    const chosen = [...(picker.files ?? [])];
    picker.value = "";
    void take(chosen);
  });
  const choose = h("button", { class: "btn", type: "button" }, t(source.images ? "imp_choose_images" : "imp_choose_file"));
  choose.addEventListener("click", () => {
    picker.click();
  });
  const drop = h("div", { class: "imp-drop" }, h("p", { class: "imp-drop-title" }, t(source.images ? "imp_drop_images" : "imp_drop_file")), choose, picker);
  drop.addEventListener("dragover", (event) => {
    event.preventDefault();
    drop.classList.add("is-over");
  });
  drop.addEventListener("dragleave", () => {
    drop.classList.remove("is-over");
  });
  drop.addEventListener("drop", (event) => {
    event.preventDefault();
    drop.classList.remove("is-over");
    void take([...(event.dataTransfer?.files ?? [])]);
  });

  let paste: HTMLElement | null = null;
  if (source.id === "google") {
    const area = h("textarea", { id: "imp-links", spellcheck: "false", autocomplete: "off" });
    const add = h("button", { class: "btn", type: "button" }, t("imp_add_links"));
    add.addEventListener("click", () => {
      const text = area.value.trim();
      area.value = "";
      if (!text) return;
      clear(errors);
      void send(p, t("imp_pasted"), new TextEncoder().encode(text))
        .catch((e: unknown) => {
          const err = errorOf(e);
          errors.append(notice(errorText(err.code, err.message)));
        })
        .then(render);
    });
    paste = h("div", { class: "imp-paste" }, h("label", { for: "imp-links" }, t("imp_paste_label")), area, add);
  }

  const select = h("select", { id: "imp-into" });
  for (const pr of projects) {
    const option = h("option", { value: JSON.stringify([pr.vault, pr.name]) }, `${pr.vault} / ${pr.name}`);
    if (p.destination ? p.destination.vault === pr.vault && p.destination.project === pr.name : pr.vault === "Personal" && pr.name === "General") option.selected = true;
    select.append(option);
  }
  const chosenDestination = (): Pending["destination"] => {
    try {
      const [vault, project] = JSON.parse(select.value) as [string, string];
      return { vault, project };
    } catch {
      return undefined;
    }
  };

  review.addEventListener("click", () => {
    p.destination = chosenDestination();
    void showPreview(p);
  });
  over.addEventListener("click", () => void showSource(source));

  put(body,
    back(t("imp_all_sources"), () => {
      void cancel().then(showSources);
    }),
    heading(t("imp_from", t(source.name))),
    h("section", { class: "imp-group" }, h("h2", { class: "label" }, t("imp_how")), h("ol", { class: "imp-steps" }, ...source.steps.map((k) => h("li", {}, t(k))))),
    drop,
    paste,
    status,
    errors,
    files,
    warnings,
    projects.length > 1 ? h("div", { class: "imp-field" }, h("label", { for: "imp-into" }, t("imp_into")), select) : null,
    h("div", { class: "imp-actions" }, review, over),
  );
  render();
}

function missingText(size: number, missing: number[]): string {
  return t("imp_missing", size, missing.map(formatNumber).join(", "));
}

// ---------------------------------------------------------------- preview

function changeText(c: ImportChange): string {
  return t(`imp_ch_${c}`);
}

function rowWhat(r: ImportRow): string {
  const parts: string[] = [];
  if (r.target !== r.title) {
    if (r.action === "merge") parts.push(t("imp_into_item", r.target));
    else if (r.action === "new") parts.push(t("imp_as_item", r.target));
    else parts.push(t("imp_same_as", r.target));
  }
  for (const c of r.changes) {
    if (c === "renamed") continue;
    // Named, so a file cannot add a site unseen (T119).
    if (c === "urls_added" && r.sites_added?.length) parts.push(t("imp_ch_urls_added_named", r.sites_added.join(", ")));
    else parts.push(changeText(c));
  }
  return parts.join(" · ");
}

function rowView(r: ImportRow): HTMLElement {
  const sub = [r.username, r.host].filter(Boolean).join(" · ");
  return h(
    "li",
    { class: "imp-row" },
    siteTile(r.title, r.host),
    h(
      "span",
      { class: "imp-row-main" },
      h("span", { class: "row-title" }, r.title),
      sub ? h("span", { class: "row-sub" }, sub) : null,
      h("span", { class: "imp-row-what" }, rowWhat(r)),
    ),
    h("span", { class: "imp-kind" }, kindName(r.kind, true)),
  );
}

async function showPreview(p: Pending): Promise<void> {
  const body = screen();
  const session = p.session;
  if (!session) {
    void showSource(p.source, p);
    return;
  }
  let preview: ImportPreview;
  try {
    preview = await daemon<ImportPreview>({ op: "import_preview", session, ...(p.destination ?? {}) });
  } catch (e) {
    const err = errorOf(e);
    put(body,back(t("imp_back_files"), () => void showSource(p.source, p)), notice(errorText(err.code, err.message)));
    return;
  }
  const total = preview.totals.new + preview.totals.merged;
  const counts = [
    preview.totals.new > 0 ? plural("imp_new", preview.totals.new) : null,
    preview.totals.merged > 0 ? plural("imp_merged", preview.totals.merged) : null,
    preview.totals.duplicates > 0 ? plural("imp_dupes", preview.totals.duplicates) : null,
  ].filter((c) => c !== null);
  const summary = counts.length > 0 ? `${new Intl.ListFormat(locale(), { type: "conjunction" }).format(counts)}.` : t("imp_nothing");
  const groups = (["new", "merge", "duplicate"] as const)
    .map((action) => {
      const rows = preview.rows.filter((r) => r.action === action);
      if (rows.length === 0) return null;
      const label: MessageKey = action === "new" ? "imp_group_new" : action === "merge" ? "imp_group_merge" : "imp_group_duplicate";
      return h("section", { class: "imp-group" }, h("h2", { class: "label" }, t(label)), h("ul", {}, ...rows.map(rowView)));
    })
    .filter((g) => g !== null);
  const more = preview.rows_total - preview.rows.length;
  const message = h("div", {});
  const apply = h("button", { class: "btn btn-primary", type: "button", disabled: total === 0 }, total === 0 ? t("imp_nothing") : plural("imp_apply", total));
  apply.addEventListener("click", () => {
    apply.disabled = true;
    apply.textContent = t("imp_importing");
    clear(message);
    void daemon<ImportResult>({ op: "import_apply", session, ...(p.destination ?? {}) }).then(
      (result) => {
        p.session = undefined;
        pending = undefined;
        void showDone(result, p);
      },
      (e: unknown) => {
        const err = errorOf(e);
        message.append(notice(errorText(err.code, err.message)));
        apply.disabled = false;
        apply.textContent = plural("imp_apply", total);
      },
    );
  });
  put(body,
    back(t("imp_back_files"), () => void showSource(p.source, p)),
    heading(t("imp_review_title")),
    h("div", { class: "imp-head" }, h("p", { class: "imp-summary" }, summary), h("p", { class: "sub" }, t("imp_into_place", `${preview.vault} / ${preview.project}`))),
    ...preview.missing.map((m) => h("p", { class: "imp-warn" }, missingText(m.size, m.missing))),
    preview.passkeys > 0 ? h("p", { class: "imp-warn" }, plural("imp_passkeys", preview.passkeys)) : null,
    ...groups,
    more > 0 ? h("p", { class: "sub" }, t("imp_more_rows", more)) : null,
    h("p", { class: "imp-rule" }, t("imp_rule")),
    message,
    h("div", { class: "imp-actions" }, apply),
  );
}

// ------------------------------------------------------------------- done

async function showDone(result: ImportResult, p: Pending): Promise<void> {
  clear(app);
  document.body.className = "imp-done";
  const field = ditherCanvas(document, keyhole(1), { palette: "blue", pixel: 3 });
  const body = h("div", { class: "imp" });
  app.append(
    h(
      "header",
      { class: "imp-bar" },
      h("span", { class: "brand" }, glyph("brand-glyph"), h("span", { class: "brand-name" }, "klav")),
      h("span", { class: "imp-bar-sep", "aria-hidden": "true" }),
      h("span", { class: "imp-bar-title" }, t("imp_heading")),
    ),
    h("div", { class: "imp-sealed" }, field.canvas),
    body,
  );
  put(body,
    heading(t("imp_done_title"), t("imp_done_text", result.created, result.updated, `${result.vault} / ${result.project}`)),
    result.passkeys > 0 ? h("p", { class: "imp-warn" }, plural("imp_passkeys", result.passkeys)) : null,
    result.passkeys_failed?.length
      ? h(
          "div",
          { class: "imp-warn" },
          h(
            "div",
            {},
            t("imp_passkeys_failed"),
            h("ul", {}, ...result.passkeys_failed.map((why) => h("li", {}, why))),
          ),
        )
      : null,
    h(
      "section",
      { class: "imp-delete cross" },
      h("h2", { class: "imp-delete-title" }, t("imp_delete_title")),
      h("p", {}, t("imp_delete_text")),
      h("ul", {}, ...p.names.filter((n) => n !== t("imp_pasted")).map((n) => h("li", {}, n))),
      p.source.id === "google" ? h("p", { class: "sub" }, t("imp_delete_google")) : null,
    ),
    h(
      "div",
      { class: "imp-actions" },
      h("button", { class: "btn btn-primary", type: "button", onclick: showSources }, t("imp_again")),
      h("button", { class: "btn-link", type: "button", onclick: closeTab }, t("imp_close")),
    ),
  );
  // The file's contents are sealed now: the light closes into the keyhole.
  field.repaint();
  await animate(700, (k) => {
    field.repaint(keyhole(1 - k));
  });
}

function closeTab(): void {
  window.close();
}

window.addEventListener("pagehide", () => {
  void cancel();
});

void start();
