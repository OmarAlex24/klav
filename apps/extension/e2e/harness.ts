/**
 * End-to-end harness: a real klav-server (SQLite), a person signed up with
 * the real `klav` CLI in a temporary KLAV_HOME, the native messaging host
 * registered in a throwaway Chromium profile, and Chromium with the
 * unpacked extension. Nothing touches the user's own browsers or homes.
 */
import { type ChildProcess, execFileSync, spawn, spawnSync } from "node:child_process";
import { chmodSync, closeSync, copyFileSync, existsSync, mkdirSync, mkdtempSync, openSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { type BrowserContext, chromium, expect, type Frame, type Locator, type Page, type Worker } from "@playwright/test";
import { type Latency, startLatency } from "./latency";

export const PASSWORD = "correct horse battery staple";
export const DEV_ID = "niiplppgdljgimbnmokojdkofdcjkgao";
const root = resolve(import.meta.dirname, "..", "..", "..");
/** The binaries: target/debug, or `KLAV_E2E_BIN` (a copy that another build cannot replace mid-run). */
const bin = (name: string): string => join(process.env.KLAV_E2E_BIN ?? join(root, "target", "debug"), name);
/** The unpacked extension: dist/chromium, or `KLAV_E2E_EXTENSION` (to measure another build). */
export const EXTENSION = process.env.KLAV_E2E_EXTENSION ?? resolve(import.meta.dirname, "..", "dist", "chromium");

export async function freePort(): Promise<number> {
  return new Promise((done, fail) => {
    const server = createServer();
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      server.close(() => {
        if (address && typeof address === "object") done(address.port);
        else fail(new Error("no port"));
      });
    });
  });
}

/**
 * How long a klav-server that is alive but not answering yet may take. It
 * listens only after creating its data directory and database, and those
 * writes wait on the disk. 10 s was less than the shared CI disk stalled
 * for: not listening yet after 10 s in run 42319489094, and the disk busy
 * for up to 24 s in a row in run 42328423371. A server that exits fails at
 * once, with what it wrote.
 */
const SERVER_START_MS = 60_000;

/** Waits until klav-server answers; if it exits or never does, fails with what it wrote. */
async function serverUp(server: ChildProcess, url: string, log: string): Promise<void> {
  let spawnError: Error | undefined;
  server.on("error", (e) => {
    spawnError = e;
  });
  const gone = (): string | undefined => {
    if (spawnError) return `did not start (${spawnError.message})`;
    if (server.exitCode !== null || server.signalCode !== null) return `exited (${String(server.signalCode ?? server.exitCode)})`;
    return undefined;
  };
  const started = Date.now();
  for (;;) {
    try {
      if ((await fetch(`${url}/v1/health`, { signal: AbortSignal.timeout(5_000) })).ok) return;
    } catch {
      // not listening yet
    }
    const why = gone() ?? (Date.now() - started > SERVER_START_MS ? `did not answer in ${String(SERVER_START_MS / 1000)} s` : undefined);
    if (why) {
      server.kill();
      throw new Error(`klav-server ${why}:\n${readFileSync(log, "utf8")}`);
    }
    await new Promise((r) => setTimeout(r, 100));
  }
}

export interface Stack {
  dir: string;
  home: string;
  profile: string;
  serverUrl: string;
  /** With `latency`: the proxy klavd and the CLI talk to the server through. */
  latency?: Latency;
  /** Runs `klav` as the person (first stdin line: the master password if `unlocked`). */
  klav(args: string[], options?: { stdin?: string; unlocked?: boolean; env?: Record<string, string> }): string;
  /**
   * Like `klav`, in a terminal of its own, for the commands that read a
   * value from klavd: with the presence gate (ADR 0041) they ask for the
   * master password on their controlling terminal, never on stdin, and
   * this types it there each time the question shows, as a person would.
   */
  klavInTerminal(args: string[], options?: { stdin?: string; unlocked?: boolean }): Promise<string>;
  stop(): void;
}

export interface StackOptions {
  /** Put a delaying proxy between the clients and the server (perf.spec.ts). */
  latency?: boolean;
  /** Extra lines for server.toml (for example a `[sessions]` table). */
  serverToml?: string;
}

export async function startStack(options: StackOptions = {}): Promise<Stack> {
  // Under the run's directory (global-setup.ts), removed even if a test crashes.
  const dir = mkdtempSync(join(process.env.KLAV_E2E_ROOT ?? tmpdir(), "klav-e2e-"));
  const home = join(dir, "home");
  const profile = join(dir, "profile");
  const port = await freePort();
  writeFileSync(
    join(dir, "server.toml"),
    `listen = "127.0.0.1:${port}"
database_url = "sqlite://${join(dir, "klav.db")}"
data_dir = "${join(dir, "data")}"
[log]
format = "pretty"
filter = "warn"
[rate_limit]
auth_ip_burst = 10000
auth_email_burst = 10000
ip_burst = 100000
account_burst = 100000
${options.serverToml ?? ""}`,
  );
  // What the server writes goes to a file in the stack's directory: if it
  // never comes up, the error says why.
  const serverLog = join(dir, "server.log");
  const out = openSync(serverLog, "a");
  const server: ChildProcess = spawn(bin("klav-server"), ["--config", join(dir, "server.toml")], {
    stdio: ["ignore", out, out],
  });
  closeSync(out);
  const direct = `http://127.0.0.1:${port}`;
  await serverUp(server, direct, serverLog);
  const latency = options.latency ? await startLatency(port) : undefined;
  const serverUrl = latency?.url ?? direct;
  // klavd and the host inherit this from the browser: never wait on a
  // fingerprint in tests.
  process.env.KLAV_NO_TOUCH_ID = "1";
  // Nothing here may reach the real server by forgetting --server
  // (ADR 0028 §2): without one, a command fails as it used to.
  process.env.KLAV_NO_DEFAULT_SERVER = "1";
  const klav: Stack["klav"] = (args, options = {}) => {
    const all = options.unlocked ? ["--password-stdin", ...args] : args;
    const stdin = options.unlocked ? `${PASSWORD}\n${options.stdin ?? ""}` : (options.stdin ?? "");
    const out = spawnSync(bin("klav"), all, {
      input: stdin,
      encoding: "utf8",
      env: { ...process.env, KLAV_HOME: home, KLAV_NO_TOUCH_ID: "1", ...options.env },
    });
    if (out.status !== 0) {
      throw new Error(`klav ${args.join(" ")} failed (${String(out.status)}): ${out.stderr}`);
    }
    return out.stdout;
  };
  const klavInTerminal: Stack["klavInTerminal"] = (args, options = {}) =>
    inTerminal(dir, home, options.unlocked ? ["--password-stdin", ...args] : args, options.unlocked ? `${PASSWORD}\n${options.stdin ?? ""}` : (options.stdin ?? ""));
  klav(
    ["signup", "--server", serverUrl, "--email", "ana@example.com", "--device-name", "e2e", "--emergency-kit", join(dir, "kit.txt")],
    { unlocked: true },
  );
  // The browser runs the host (and the host klavd) from a copy in the
  // run's directory: target/ may live on an external disk, which macOS
  // does not let a freshly launched browser open without asking.
  const hostDir = join(dir, "bin");
  mkdirSync(hostDir);
  for (const name of ["klav-native-host", "klavd"]) {
    copyFileSync(bin(name), join(hostDir, name));
    chmodSync(join(hostDir, name), 0o755);
  }
  klav(["extension", "install-host", "--user-data-dir", profile, "--dev", "--host", join(hostDir, "klav-native-host")]);
  return {
    dir,
    home,
    profile,
    serverUrl,
    ...(latency ? { latency } : {}),
    klav,
    klavInTerminal,
    stop() {
      try {
        execFileSync(bin("klav"), ["lock", "--stop"], { env: { ...process.env, KLAV_HOME: home }, stdio: "ignore" });
      } catch {
        // not running
      }
      server.kill();
      latency?.close();
      rmSync(dir, { recursive: true, force: true });
    },
  };
}

/** What every presence question of the CLI ends with (`crates/klav-cli/src/presence.rs`). */
const QUESTION = "Master password for ";
let terminals = 0;

/**
 * `klav <args>` under `script`, a new pseudo-terminal that is its
 * controlling terminal, with `stdin` as its standard input and its standard
 * output and error kept apart in files. Each presence question gets
 * `PASSWORD`. Fails with stderr if the command does.
 */
async function inTerminal(dir: string, home: string, args: string[], stdin: string): Promise<string> {
  const work = join(dir, `tty-${String(terminals++)}`);
  mkdirSync(work);
  const input = join(work, "stdin");
  const out = join(work, "stdout");
  const err = join(work, "stderr");
  writeFileSync(input, stdin);
  const quote = (arg: string): string => `'${arg.replaceAll("'", "'\\''")}'`;
  const line = `${quote(bin("klav"))} ${args.map(quote).join(" ")} < ${quote(input)} > ${quote(out)} 2> ${quote(err)}; echo "KLAV-EXIT $?"`;
  // `script` reads the keys from a real pipe (`cat`): fed straight from
  // Node's socket, macOS's `script` shows nothing.
  const run = process.platform === "darwin" ? 'cat | script -q /dev/null /bin/sh -c "$0"' : 'cat | script -q -e -c "$0" /dev/null';
  const child = spawn("/bin/sh", ["-c", run, line], {
    env: { ...process.env, KLAV_HOME: home, KLAV_NO_TOUCH_ID: "1" },
    stdio: ["pipe", "pipe", "ignore"],
  });
  let shown = "";
  let answered = 0;
  const code = await new Promise<number>((done, fail) => {
    const timer = setTimeout(() => {
      child.stdin.end();
      child.kill();
      fail(new Error(`klav ${args.join(" ")} did not finish in its terminal:\n${shown}`));
    }, 120_000);
    child.stdout.on("data", (chunk: Buffer) => {
      shown += chunk.toString("utf8");
      // `klav` writes the question once echo is off and what was typed
      // before it is thrown away.
      while (shown.split(QUESTION).length - 1 > answered) {
        answered += 1;
        child.stdin.write(`${PASSWORD}\n`);
      }
      const exit = /KLAV-EXIT (\d+)/.exec(shown);
      if (exit) {
        clearTimeout(timer);
        child.stdin.end();
        done(Number(exit[1]));
      }
    });
  });
  const stdout = readFileSync(out, "utf8");
  const stderr = readFileSync(err, "utf8");
  rmSync(work, { recursive: true, force: true });
  if (code !== 0) throw new Error(`klav ${args.join(" ")} failed (${String(code)}): ${stderr}`);
  return stdout;
}

/**
 * Klav's frame in `page` (`passkey.html`) for the presence gate (ADR
 * 0041), answered with the master password: the person's own fill after an
 * unlock that opened no window, or an agent's first value through this
 * browser. Sent with Enter, as a person may: after another tab was in
 * front (the popup), Chromium under test does not route a click to the
 * tab's extension frame, but it does route the keyboard.
 */
export async function confirmPresence(page: Page): Promise<void> {
  const frame = await frameOf(page, "/passkey.html");
  await expect(frame.getByText("Confirm it’s you")).toBeVisible();
  await waitArmed(page);
  const field = frame.getByLabel("Master password, to confirm");
  await field.fill(PASSWORD);
  await field.press("Enter");
}

/**
 * Unlocks klavd from the extension's popup, as the person would in the
 * browser: locked first, so the unlock is the popup's. With the presence
 * gate (ADR 0041) a password unlock opens what its question says for the
 * browser's key (`shown`); an unlock through the CLI (`--password-stdin`)
 * opens none, and the browser's first value would ask. In any language.
 */
export async function unlockInBrowser(stack: Stack, browser: Browser): Promise<void> {
  stack.klav(["lock"]);
  const popup = await browser.popup();
  const form = popup.locator("form.unlock-form");
  await expect(form).toBeVisible({ timeout: UNLOCK_MS });
  await form.locator("input[type=password]").fill(PASSWORD);
  await form.locator("button[type=submit]").click();
  await expect(form).toHaveCount(0, { timeout: UNLOCK_MS });
  await popup.close();
}

/** `klav` from target/debug (for the MCP client). */
export const KLAV_BIN = bin("klav");

export interface Agent {
  home: string;
  /** A working directory whose klav.toml points at Personal/General. */
  repo: string;
  words: string;
}

/**
 * Registers an agent in its own KLAV_HOME and approves it from the person's
 * account for Personal/General (extra `approve` options: `--ask fill`…).
 */
export function registerAgent(stack: Stack, name: string, approve: string[] = []): Agent {
  const home = join(stack.dir, `agent-${name}`);
  const repo = join(stack.dir, `repo-${name}`);
  mkdirSync(repo, { recursive: true });
  writeFileSync(join(repo, "klav.toml"), 'project = "Personal/General"\n');
  const words = stack
    .klav(["agent", "register", "--name", name, "--server", stack.serverUrl, "--email", "ana@example.com", "--key-store", "file"], {
      env: { KLAV_HOME: home },
    })
    .trim();
  // Approving needs presence: without Touch ID the CLI asks for the master
  // password again (after the unlock, when klavd was locked).
  stack.klav(["agent", "approve", name, "--project", "Personal/General", "--words", words, ...approve], {
    unlocked: true,
    stdin: `${PASSWORD}\n`,
  });
  return { home, repo, words };
}

export interface Browser {
  context: BrowserContext;
  worker: Worker;
  extensionUrl(page: string): string;
  popup(): Promise<Page>;
}

/** The language of Klav's words in tests: English unless a test asks for Spanish. */
export type Lang = "en" | "es";

/**
 * Chromium with the browser's interface (and so `chrome.i18n`) in `lang`.
 * Linux and Windows take `--lang`. Chromium on macOS ignores it and reads
 * the system's `AppleLanguages`; Cocoa also reads `-AppleLanguages (es)`
 * from the command line, but Chromium would take "(es)" as a page to open,
 * so a small script in the stack's directory drops Playwright's
 * about:blank and passes the pair at the end. Nothing outside the run's
 * directory changes.
 */
function browserFor(stack: Stack, lang: Lang): { executablePath?: string; args: string[] } {
  const args = [`--lang=${lang === "es" ? "es" : "en-US"}`];
  if (process.platform !== "darwin") return { args };
  const wrapper = join(stack.dir, `chromium-${lang}`);
  writeFileSync(
    wrapper,
    `#!/bin/sh\nfor a; do shift; [ "$a" = about:blank ] || set -- "$@" "$a"; done\nexec "${chromium.executablePath()}" "$@" -AppleLanguages "(${lang === "es" ? "es" : "en-US"})"\n`,
  );
  chmodSync(wrapper, 0o755);
  return { executablePath: wrapper, args };
}

/** `args`: more Chromium switches (tiendas.spec.ts maps a sample domain to its local site). */
export async function launch(stack: Stack, options: { extension?: string; lang?: Lang; args?: string[] } = {}): Promise<Browser> {
  const extension = options.extension ?? EXTENSION;
  const lang = options.lang ?? "en";
  // The presence gate (ADR 0041): the first unlock since klavd started
  // opens no window (Omar's decision A), so the first value after it asks.
  // A person has unlocked before; so has this klavd: started here, unlocked
  // once and locked again, the extension's own unlock opens what its
  // question says. presencia.spec.ts starts a fresh klavd to test the first
  // unlock.
  if (!existsSync(join(stack.home, "klavd.sock"))) {
    stack.klav(["unlock"], { unlocked: true });
    stack.klav(["lock"]);
  }
  const browser = browserFor(stack, lang);
  const context = await chromium.launchPersistentContext(stack.profile, {
    ...(browser.executablePath ? { executablePath: browser.executablePath } : { channel: "chromium" }),
    headless: process.env.HEADED !== "1",
    // Sharp screenshots for the docs.
    deviceScaleFactor: process.env.SCREENSHOTS === "1" ? 2 : 1,
    locale: lang === "es" ? "es-ES" : "en-US",
    args: [...browser.args, ...(options.args ?? []), `--disable-extensions-except=${extension}`, `--load-extension=${extension}`],
  });
  const worker = context.serviceWorkers()[0] ?? (await context.waitForEvent("serviceworker"));
  const id = new URL(worker.url()).host;
  if (id !== DEV_ID) throw new Error(`unexpected extension ID ${id}`);
  const ui = await worker.evaluate(() => chrome.i18n.getMessage("locale"));
  if (ui !== lang) throw new Error(`the browser speaks ${ui}, not ${lang}`);
  const extensionUrl = (page: string): string => `chrome-extension://${id}/${page}`;
  return {
    context,
    worker,
    extensionUrl,
    async popup() {
      const page = await context.newPage();
      await page.setViewportSize({ width: 360, height: 560 });
      await page.goto(extensionUrl("popup.html"));
      return page;
    },
  };
}

/** Clicks Klav's glyph at the end of `field` and returns the menu's frame. */
export async function openMenu(page: Page, field: Locator): Promise<Frame> {
  await field.click();
  const box = await field.boundingBox();
  if (!box) throw new Error("the field is not visible");
  // The glyph lives in a closed shadow root: click where it is drawn.
  await page.mouse.click(box.x + box.width - 6 - 11, box.y + box.height / 2);
  const frame = await expect
    .poll(() => page.frames().find((f) => f.url().includes("/menu.html")), { timeout: 10_000 })
    .toBeTruthy()
    .then(() => page.frames().find((f) => f.url().includes("/menu.html")));
  if (!frame) throw new Error("no menu");
  return frame;
}

/** The frame of one of Klav's pages in `page` (`/save.html`, `/find.html`…), once it shows. */
export async function frameOf(page: Page, file: string): Promise<Frame> {
  await expect.poll(() => page.frames().some((f) => f.url().includes(file)), { timeout: 10_000 }).toBe(true);
  const frame = page.frames().find((f) => f.url().includes(file));
  if (!frame) throw new Error(`no ${file}`);
  return frame;
}

/**
 * Waits until one of Klav's frames has grown to fit its content. A frame
 * follows its content's height asynchronously (frame.ts asks the content
 * script to resize the iframe), and meanwhile the content scrolls inside
 * it: a button pushed down by a new message is out of view, and a click
 * aimed at it while the frame grows lands on something else.
 */
export async function settled(frame: Frame): Promise<void> {
  let last = -1;
  await expect
    .poll(
      async () => {
        const [content, view] = await frame.evaluate(() => [document.body.scrollHeight, innerHeight]);
        const fits = content <= view + 1 && view === last;
        last = view;
        return fits;
      },
      { timeout: 10_000, intervals: [50] },
    )
    .toBe(true);
}

/**
 * Clicks `target` inside one of Klav's frames in a page (menu, palette,
 * card, passkey frame, save bar). Many of these clicks remove their own
 * frame: a fill closes the menu, «Find another item» swaps it for the
 * palette, a signed passkey closes its frame. Chromium answers the mouse
 * release Playwright dispatches only once the frame under it has handled
 * it, and a frame removed before that never answers: Playwright's click
 * then waits until the test times out, with the click's effect already on
 * the page (CI runs 42687556855, 42746392582, 42783626001, 42834077629;
 * locally, every time the menu's click handler is still busy when the
 * content script removes the frame). So the click also ends when its frame
 * goes; the test's next lines check what it did.
 *
 * Only the click itself may end that way. A trial run first waits until
 * the target is visible, stable, enabled and the one under the pointer: a
 * frame that goes before then (closed on its own, by a bug or a timeout)
 * fails here as it would with `click()`. The trial does send the mouse
 * events, but Playwright stops them in the frame before any of Klav's
 * listeners, so nothing removes the frame and Chromium answers them.
 */
export async function clickIn(target: Locator): Promise<void> {
  const handle = await target.elementHandle();
  const frame = await handle.ownerFrame();
  await handle.dispose();
  if (!frame) throw new Error("the target is in no frame");
  await target.click({ trial: true });
  const page = target.page();
  let onDetached: ((detached: Frame) => void) | undefined;
  const gone = new Promise<void>((resolve) => {
    onDetached = (detached) => {
      if (detached === frame) resolve();
    };
    page.on("framedetached", onDetached);
  });
  const clicked = target.click();
  try {
    await Promise.race([clicked, gone]);
  } finally {
    if (onDetached) page.off("framedetached", onDetached);
    // Once the frame is gone, the click may never settle, or fail when the page closes.
    clicked.catch(() => undefined);
  }
}

/**
 * How long klavd may take to answer an unlock. It derives the key with
 * Argon2id (256 MiB, t = 3, p = 4) and then syncs before the form goes.
 * On CI, with the Rust tasks on all eight CPUs and 15 to 28 % steal, the
 * menu showed its list 6.5 s after the click (run 42832467508), past
 * `expect`'s default 5 s.
 */
export const UNLOCK_MS = 30_000;

/**
 * Types the master password into one of Klav's locked forms (popup, menu,
 * palette, passkey frame, save bar), presses «Unlock», and waits until
 * klavd has answered. While it checks, the form's button is disabled; the
 * form then goes (unlocked) or comes back with an alert (a wrong password).
 */
export async function unlockForm(where: Page | Frame, password = PASSWORD): Promise<void> {
  const button = ":is(form.unlock, form.unlock-form) button[type=submit]";
  const unlock = where.locator(button);
  // The wait below passes when no such button is disabled: a selector that
  // a renamed form no longer matches would pass it at once. So the button
  // must be there first, once, and be «Unlock».
  await expect(unlock).toHaveAccessibleName("Unlock");
  await where.getByLabel("Master password").fill(password);
  await unlock.click();
  await expect(where.locator(`${button}:disabled`)).toHaveCount(0, { timeout: UNLOCK_MS });
}

/** Klav's frames in pages (menu, card, palette, save bar) ignore clicks until visible for a moment (clickjacking). */
export async function waitArmed(page: Page): Promise<void> {
  await page.waitForTimeout(900);
}

/**
 * Screenshots for the docs (SCREENSHOTS=1): `name.png` in light and
 * `name-oscuro.png` in dark. The dither repaints itself when the scheme
 * changes, so wait a moment between the two.
 */
export async function shoot(target: Page, dir: string | undefined, name: string, options: { fullPage?: boolean } = {}): Promise<void> {
  if (!dir) return;
  const { join } = await import("node:path");
  await target.emulateMedia({ colorScheme: "light" });
  await target.waitForTimeout(250);
  await target.screenshot({ path: join(dir, `${name}.png`), ...options });
  await target.emulateMedia({ colorScheme: "dark" });
  await target.waitForTimeout(350);
  await target.screenshot({ path: join(dir, `${name}-oscuro.png`), ...options });
  await target.emulateMedia({ colorScheme: "light" });
  await target.waitForTimeout(150);
}
