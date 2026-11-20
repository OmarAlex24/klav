/**
 * Failure extractors used by ci-task-extract.ts, one per kind of tool output.
 * Each receives the cleaned log (no ANSI, no runner timestamps) and returns a
 * section with the lines that explain the failure plus the code locations it
 * points at, or null when it recognises nothing.
 *
 * Covered: bun test, go test (failures and panics), cargo-nextest, Playwright
 * `list` reporter, TAP / pgTAP, `file:line:col` diagnostics (tsc, eslint,
 * oxlint, golangci-lint, go vet, ruff, mypy...) and, as a fallback, the
 * de-noised tail of the log.
 *
 * To support another tool, add an extractor with the same signature and list
 * it in EXTRACTORS (ci-task-extract.ts).
 */

const TAIL_LINES = 150;

export type SectionKind =
  | "bun"
  | "errors"
  | "go"
  | "locations"
  | "nextest"
  | "playwright"
  | "tail"
  | "tap";

/** A place in the code the log points at, before it becomes a repo path. */
export interface LogLocation {
  readonly col?: number | undefined;
  readonly file: string;
  readonly line: number;
  readonly message: string;
  /** Go import path of the package, to resolve a bare `foo_test.go:12`. */
  readonly pkg?: string | undefined;
  readonly title?: string | undefined;
}

export interface Section {
  readonly body: readonly string[];
  /** Number of failures found; 0 when the section is context only. */
  readonly count: number;
  readonly heading: string;
  /** "3 Bun tests": used in the check title; empty for context sections. */
  readonly headline: string;
  readonly kind: SectionKind;
  readonly locations: readonly LogLocation[];
}

// --- bun test ----------------------------------------------------------------

const BUN_RESULT_RE = /^\((pass|fail|skip|todo)\) /;
const BUN_FAIL_RE = /^\(fail\) (.+?)(?: \[[\d.]+m?s\])?$/;
const BUN_FRAME_START_RE = /^\s*\d+ \| /;
const BUN_ERROR_RE = /^(?:error: |# Unhandled error)/;
// Not Bun errors: `bun run`'s exit line, and the last line of a failed
// `cargo test` or `cargo nextest run`, which only says that tests failed.
const BUN_SCRIPT_EXIT_RE =
  /^error: (?:script ".*" exited with code|test run failed$|test failed, to rerun pass )/;
const BUN_STACK_RE = /^\s+at (?:.*\()?([^\s()]+):(\d+):(\d+)\)?$/;
const MAX_BLOCK_LINES = 60;

function bunBoundary(line: string): boolean {
  return (
    BUN_RESULT_RE.test(line) ||
    /^(?:::|##\[)(?:end)?group/.test(line) ||
    line.startsWith("::error") ||
    line.startsWith("bun test v") ||
    /^\s*\d+ (?:pass|fail)$/.test(line) ||
    /^Ran \d+ tests?/.test(line)
  );
}

function startsBunBlock(line: string): boolean {
  return (
    BUN_FRAME_START_RE.test(line) ||
    (BUN_ERROR_RE.test(line) && !BUN_SCRIPT_EXIT_RE.test(line))
  );
}

/** From the code frame or `error:` up to its `(fail)` or the next result. */
function readBunBlock(lines: readonly string[], from: number): string[] {
  const block: string[] = [];
  for (let i = from; i < lines.length && block.length < MAX_BLOCK_LINES; i++) {
    const line = lines[i] ?? "";
    if (i > from && bunBoundary(line)) {
      if (BUN_FAIL_RE.test(line)) {
        block.push(line);
      }
      break;
    }
    block.push(line);
  }
  return trimBlank(block);
}

function bunLocation(block: readonly string[]): LogLocation | null {
  const message = block.find((line) => BUN_ERROR_RE.test(line)) ?? "";
  for (const line of block) {
    const frame = BUN_STACK_RE.exec(line);
    if (frame?.[1]?.includes("/") && !frame[1].includes("node_modules")) {
      return {
        file: frame[1],
        line: Number(frame[2]),
        col: Number(frame[3]),
        message,
      };
    }
  }
  return null;
}

/**
 * Failed Bun tests and the error of each. Several `bun test` processes may
 * run at once and interleave their output, so error blocks are found by shape
 * (code frame, `error:`, stack) and the `(fail)` lines separately.
 */
export function extractBun(lines: readonly string[]): Section | null {
  const fails = unique(
    lines.filter((line) => BUN_FAIL_RE.test(line)).map((line) => line.trim())
  );
  const blocks: string[][] = [];
  for (let i = 0; i < lines.length; i++) {
    if (!startsBunBlock(lines[i] ?? "")) {
      continue;
    }
    const block = readBunBlock(lines, i);
    i += Math.max(block.length - 1, 0);
    if (block.some((line) => BUN_ERROR_RE.test(line))) {
      blocks.push(block);
    }
  }
  const distinct = uniqueBlocks(blocks);
  if (fails.length === 0 && distinct.length === 0) {
    return null;
  }
  return {
    kind: "bun",
    heading:
      fails.length > 0
        ? `Bun: ${plural(fails.length, "test failed", "tests failed")}`
        : "Bun: errors",
    count: fails.length || distinct.length,
    headline:
      fails.length > 0
        ? plural(fails.length, "Bun test", "Bun tests")
        : plural(distinct.length, "Bun error", "Bun errors"),
    body: [...fails, ...distinct.flatMap((block) => ["", ...block])],
    locations: distinct.flatMap((block) => bunLocation(block) ?? []),
  };
}

// --- go test -----------------------------------------------------------------

const GO_FAIL_RE = /^(\s*)--- FAIL: (\S+)/;
const GO_PKG_FAIL_RE = /^FAIL\s+(\S+)(?:\s|$)/;
const GO_TEST_LOCATION_RE = /^\s+([\w.-]+\.go):(\d+): (.*)$/;
const GO_FRAME_RE = /^\t(\S+\.go):(\d+)(?: \+0x[0-9a-f]+)?$/;
const MAX_PANIC_LINES = 40;

function readIndented(
  lines: readonly string[],
  from: number,
  max: number
): string[] {
  const block = [lines[from] ?? ""];
  for (let i = from + 1; i < lines.length && block.length < max; i++) {
    const line = lines[i] ?? "";
    if (!/^(?:\s{2,}|\t)/.test(line) || GO_FAIL_RE.test(line)) {
      break;
    }
    block.push(line);
  }
  return block;
}

function readPanic(lines: readonly string[], from: number): string[] {
  const block: string[] = [];
  for (let i = from; i < lines.length && block.length < MAX_PANIC_LINES; i++) {
    const line = lines[i] ?? "";
    if (
      i > from &&
      (GO_PKG_FAIL_RE.test(line) || /^(?:ok|---|===) /.test(line))
    ) {
      break;
    }
    block.push(line);
  }
  return trimBlank(block);
}

function goTestLocations(block: readonly string[]): LogLocation[] {
  return block.flatMap((line) => {
    const match = GO_TEST_LOCATION_RE.exec(line);
    return match?.[1]
      ? [{ file: match[1], line: Number(match[2]), message: match[3] ?? "" }]
      : [];
  });
}

function goPanicLocation(block: readonly string[]): LogLocation | null {
  const message = block[0] ?? "";
  for (const line of block) {
    const frame = GO_FRAME_RE.exec(line);
    if (
      frame?.[1] &&
      !frame[1].includes("/go/src/") &&
      !frame[1].includes("/libexec/src/")
    ) {
      return { file: frame[1], line: Number(frame[2]), message };
    }
  }
  return null;
}

interface GoScan {
  readonly blocks: string[][];
  readonly packages: string[];
  readonly pending: LogLocation[];
  readonly resolved: LogLocation[];
  topLevel: number;
}

/** A bare `foo_test.go:12` gets the package of the `FAIL\t<pkg>` that closes it. */
function closePackage(scan: GoScan, pkg: string): void {
  scan.packages.push(pkg);
  for (const location of scan.pending.splice(0)) {
    scan.resolved.push({ ...location, pkg });
  }
}

function scanGoLine(scan: GoScan, lines: readonly string[], i: number): number {
  const line = lines[i] ?? "";
  const fail = GO_FAIL_RE.exec(line);
  if (fail) {
    const block = readIndented(lines, i, 30);
    scan.blocks.push(block);
    scan.pending.push(...goTestLocations(block));
    scan.topLevel += fail[1] === "" ? 1 : 0;
    return block.length - 1;
  }
  if (line.startsWith("panic: ")) {
    const block = readPanic(lines, i);
    scan.blocks.push(block);
    const location = goPanicLocation(block);
    if (location) {
      scan.resolved.push(location);
    }
    return block.length - 1;
  }
  const pkg = GO_PKG_FAIL_RE.exec(line)?.[1];
  if (pkg) {
    closePackage(scan, pkg);
  }
  return 0;
}

export function extractGo(lines: readonly string[]): Section | null {
  const scan: GoScan = {
    blocks: [],
    packages: [],
    pending: [],
    resolved: [],
    topLevel: 0,
  };
  for (let i = 0; i < lines.length; i++) {
    i += scanGoLine(scan, lines, i);
  }
  if (scan.blocks.length === 0 && scan.packages.length === 0) {
    return null;
  }
  const count = scan.topLevel || scan.packages.length;
  return {
    kind: "go",
    heading: `Go: ${plural(count, "test failed", "tests failed")}`,
    count,
    headline: plural(count, "Go test", "Go tests"),
    body: [
      ...scan.blocks.flatMap((block) => [...block, ""]),
      ...unique(scan.packages).map((pkg) => `FAIL\t${pkg}`),
    ],
    locations: [...scan.resolved, ...scan.pending],
  };
}

// --- cargo-nextest -------------------------------------------------------------

// `        FAIL [   0.009s] ( 3/11) klav-cli::agents a3_fails`; the counter is
// `(─────)` on SLOW and TERMINATING lines, and retries prefix `TRY 2 `.
const NEXTEST_STATUS_RE =
  /^\s*(?:TRY \d+ )?([A-Z][A-Z0-9-]*) \[[\s>]*[\d.]+s\] \([^)]*\) (\S+) (\S.*?)\s*$/;
const NEXTEST_NOT_FAILED = new Set([
  "FLAKY",
  "LEAK",
  "PASS",
  "SKIP",
  "SLOW",
  "TERMINATING",
  "TMPASS",
]);
const NEXTEST_SUMMARY_RE = /^\s*Summary \[/;
const NEXTEST_RULE_RE = /^─{4,}$/;
const NEXTEST_OUTPUT_HEADER_RE = /^\s{2}(?:stdout|stderr|output) ─+$/;
// What libtest prints around one test in a process of its own: no news.
const NEXTEST_NOISE_RE = [
  /^\s*running \d+ tests?$/,
  /^\s*test \S+ \.\.\. (?:FAILED|ok)$/,
  /^\s*failures:$/,
  /^\s*test result: /,
  /^\s*note: run with `RUST_BACKTRACE=1`/,
];
// Rust >= 1.73 (`panicked at src/x.rs:3:5:`) and older (`panicked at 'msg', src/x.rs:3:5`).
const RUST_PANIC_RE = /panicked at (?:'.*', )?(\S+?):(\d+):(\d+):?$/;
const MAX_NEXTEST_BLOCK = 80;

interface NextestFailure {
  readonly block: string[];
  readonly status: string;
  readonly test: string;
}

function nextestBoundary(line: string): boolean {
  return (
    NEXTEST_STATUS_RE.test(line) ||
    NEXTEST_SUMMARY_RE.test(line) ||
    NEXTEST_RULE_RE.test(line.trim()) ||
    (line.trim() !== "" && !line.startsWith("  "))
  );
}

/** The output under a status line, without libtest's noise, capped. */
function readNextestBlock(
  lines: readonly string[],
  from: number,
  name: string
): string[] {
  const block: string[] = [];
  for (let i = from + 1; i < lines.length; i++) {
    const line = lines[i] ?? "";
    if (nextestBoundary(line)) {
      break;
    }
    if (
      NEXTEST_NOISE_RE.some((re) => re.test(line)) ||
      line.trim() === name ||
      (line.trim() === "" && (block.at(-1) ?? "").trim() === "")
    ) {
      continue;
    }
    block.push(line);
  }
  // A `stdout ───` header with nothing left under it.
  const shown = block.filter((line, index) => {
    if (!NEXTEST_OUTPUT_HEADER_RE.test(line)) {
      return true;
    }
    const next = block.slice(index + 1).find((text) => text.trim() !== "");
    return next !== undefined && !NEXTEST_OUTPUT_HEADER_RE.test(next);
  });
  return capNextestBlock(trimBlank(shown));
}

/**
 * Long output (a helper that dumps a server log into its panic message)
 * keeps the panic and what follows it: that is what failed.
 */
function capNextestBlock(block: readonly string[]): string[] {
  if (block.length <= MAX_NEXTEST_BLOCK) {
    return [...block];
  }
  const panic = block.findIndex((line) => RUST_PANIC_RE.test(line));
  const from = panic >= MAX_NEXTEST_BLOCK - 1 ? panic : 0;
  const kept = block.slice(from, from + MAX_NEXTEST_BLOCK - 1);
  const after = block.length - from - kept.length;
  return [
    ...(from > 0 ? [`    … (${from} lines above in the full log)`] : []),
    ...kept,
    ...(after > 0 ? [`    … (${after} more lines in the full log)`] : []),
  ];
}

function nextestLocations(failure: NextestFailure): LogLocation[] {
  return failure.block.flatMap((line, index) => {
    const match = RUST_PANIC_RE.exec(line);
    if (!match?.[1]) {
      return [];
    }
    const message =
      failure.block
        .slice(index + 1)
        .find((text) => text.trim() !== "")
        ?.trim() ?? "";
    return [
      {
        file: match[1],
        line: Number(match[2]),
        col: Number(match[3]),
        message,
        title: failure.test,
      },
    ];
  });
}

/**
 * Tests that failed under cargo-nextest, each with its output. The last
 * status line of a test decides: with `failure-output = "immediate-final"`
 * the copies after the summary win, and a retry that passed is no failure.
 */
export function extractNextest(lines: readonly string[]): Section | null {
  const last = new Map<string, NextestFailure | null>();
  for (let i = 0; i < lines.length; i++) {
    const status = NEXTEST_STATUS_RE.exec(lines[i] ?? "");
    if (!status?.[1] || status[1] === "SLOW" || status[1] === "TERMINATING") {
      continue;
    }
    const test = `${status[2]} ${status[3]}`;
    last.delete(test);
    last.set(
      test,
      NEXTEST_NOT_FAILED.has(status[1])
        ? null
        : {
            status: status[1],
            test,
            block: readNextestBlock(lines, i, status[3] ?? ""),
          }
    );
  }
  const failures = [...last.values()].filter(
    (failure): failure is NextestFailure => failure !== null
  );
  if (failures.length === 0) {
    return null;
  }
  const summary = lines.filter((line) => NEXTEST_SUMMARY_RE.test(line)).at(-1);
  return {
    kind: "nextest",
    heading: `nextest: ${plural(failures.length, "test failed", "tests failed")}`,
    count: failures.length,
    headline: plural(failures.length, "Rust test", "Rust tests"),
    body: [
      ...(summary ? [summary.trim()] : []),
      ...failures.map((failure) => `${failure.status} ${failure.test}`),
      ...failures.flatMap((failure) => [
        "",
        `${failure.status} ${failure.test}`,
        ...failure.block,
      ]),
    ],
    locations: failures.flatMap(nextestLocations),
  };
}

// --- Playwright (list / line reporter) ----------------------------------------

const PW_HEADER_RE =
  /^\s{2}(\d+)\) \[[^\]]+\] › (\S+?):(\d+):(\d+) › (.*?)\s*$/;
const PW_SUMMARY_RE =
  /^\s{2}\d+ (?:failed|flaky|passed|skipped|interrupted|did not run)\b/;
const PW_WEBSERVER_RE =
  /Timed out waiting \d+ ?ms from config\.webServer|Error: Process from config\.webServer/;

function readPlaywrightBlock(lines: readonly string[], from: number): string[] {
  const block = [lines[from] ?? ""];
  for (
    let i = from + 1;
    i < lines.length && block.length < MAX_BLOCK_LINES;
    i++
  ) {
    const line = lines[i] ?? "";
    if (PW_HEADER_RE.test(line) || PW_SUMMARY_RE.test(line)) {
      break;
    }
    block.push(line);
  }
  return trimBlank(block);
}

function playwrightSummary(lines: readonly string[]): string[] {
  const start = lines.findIndex((line) => /^\s{2}\d+ failed\b/.test(line));
  if (start === -1) {
    return [];
  }
  const summary: string[] = [];
  for (const line of lines.slice(start, start + 40)) {
    if (summary.length > 0 && !/^\s{2}/.test(line)) {
      break;
    }
    summary.push(line);
  }
  return summary;
}

/** The numbered failure blocks of the reporter, plus a webServer that never came up. */
export function extractPlaywright(lines: readonly string[]): Section | null {
  const blocks: string[][] = [];
  const locations: LogLocation[] = [];
  const seen = new Set<string>();
  for (let i = 0; i < lines.length; i++) {
    const header = PW_HEADER_RE.exec(lines[i] ?? "");
    if (!header || seen.has(header[1] ?? "")) {
      continue;
    }
    seen.add(header[1] ?? "");
    const block = readPlaywrightBlock(lines, i);
    blocks.push(block);
    locations.push({
      file: header[2] ?? "",
      line: Number(header[3]),
      col: Number(header[4]),
      message: block.find((line) => /^\s*Error: /.test(line))?.trim() ?? "",
      title: header[5],
    });
  }
  const webServer = lines.filter((line) => PW_WEBSERVER_RE.test(line));
  if (blocks.length === 0 && webServer.length === 0) {
    return null;
  }
  const count = blocks.length || 1;
  return {
    kind: "playwright",
    heading: `Playwright: ${plural(count, "test failed", "tests failed")}`,
    count,
    headline: plural(count, "Playwright test", "Playwright tests"),
    body: [
      ...unique(webServer),
      ...blocks.flatMap((block) => [...block, ""]),
      ...playwrightSummary(lines),
    ],
    locations,
  };
}

// --- TAP / pgTAP ---------------------------------------------------------------

const TAP_NOT_OK_RE = /^\s*not ok \d+/;
const TAP_DIAG_RE = /^\s*# /;

function tapLine(line: string): string {
  return line.replace(/\s*\+$/, "").trim();
}

export function extractTap(lines: readonly string[]): Section | null {
  const body: string[] = [];
  let count = 0;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] ?? "";
    if (TAP_NOT_OK_RE.test(line)) {
      count++;
      body.push(tapLine(line));
      for (
        let j = i + 1;
        j < lines.length && j <= i + 15 && TAP_DIAG_RE.test(lines[j] ?? "");
        j++
      ) {
        body.push(`  ${tapLine(lines[j] ?? "")}`);
      }
    } else if (/^\s*# Looks like you failed/.test(line)) {
      body.push(tapLine(line));
    }
  }
  if (count === 0) {
    return null;
  }
  return {
    kind: "tap",
    heading: `TAP: ${plural(count, "test failed", "tests failed")}`,
    count,
    headline: plural(count, "TAP test", "TAP tests"),
    body: unique(body),
    locations: [],
  };
}

// --- file:line:col (tsc, eslint, oxlint, golangci-lint, go vet, ruff...) ------

const FILE = String.raw`[\w@.+\-/]+\.[A-Za-z]{1,5}`;
const COLON_LOCATION_RE = new RegExp(
  String.raw`^\s*(?:vet: )?(${FILE}):(\d+):(\d+)(?::| -) ?(.+)$`
);
const PAREN_LOCATION_RE = new RegExp(
  String.raw`^\s*(${FILE})\((\d+),(\d+)\): (.+)$`
);
const STYLISH_FILE_RE = new RegExp(String.raw`^(/?${FILE})$`);
const STYLISH_ROW_RE = /^\s+(\d+):(\d+)\s+error\s+(.+)$/;
const NOT_AN_ERROR_RE = /^(?:warning|notice|note|info|hint)\b|^NOTICE:/i;
const MAX_LOCATION_LINES = 100;

function locationFrom(line: string): LogLocation | null {
  const match = COLON_LOCATION_RE.exec(line) ?? PAREN_LOCATION_RE.exec(line);
  if (!match?.[1] || match[1].includes("node_modules")) {
    return null;
  }
  const message = (match[4] ?? "").trim();
  if (NOT_AN_ERROR_RE.test(message)) {
    return null;
  }
  return {
    file: match[1],
    line: Number(match[2]),
    col: Number(match[3]),
    message,
  };
}

/** eslint's `stylish` format: the path alone on a line, its rows below. */
function stylishLocations(lines: readonly string[]): LogLocation[] {
  const found: LogLocation[] = [];
  let file = "";
  for (const line of lines) {
    const header = STYLISH_FILE_RE.exec(line);
    if (header?.[1]) {
      file = header[1];
      continue;
    }
    const row = STYLISH_ROW_RE.exec(line);
    if (row && file) {
      found.push({
        file,
        line: Number(row[1]),
        col: Number(row[2]),
        message: row[3]?.trim() ?? "",
      });
    } else if (line.trim() === "") {
      file = "";
    }
  }
  return found;
}

export function extractLocations(lines: readonly string[]): Section | null {
  const locations = [
    ...lines.flatMap((line) => locationFrom(line) ?? []),
    ...stylishLocations(lines),
  ];
  if (locations.length === 0) {
    return null;
  }
  const body = unique(
    locations.map(
      (loc) => `${loc.file}:${loc.line}:${loc.col ?? 1}: ${loc.message}`
    )
  );
  return {
    kind: "locations",
    heading: `${plural(body.length, "error", "errors")} with file and line`,
    count: body.length,
    headline: plural(
      body.length,
      "error with file and line",
      "errors with file and line"
    ),
    body: body.slice(0, MAX_LOCATION_LINES),
    locations,
  };
}

// --- Generic tail ----------------------------------------------------------------

const NOISE_RE = [
  /^(?:::|##\[)(?:end)?group/,
  /^\((?:pass|skip|todo)\) /,
  /^ok\s+\S+\s/,
  /^\?\s+\S+\s+\[no test files\]/,
  /^(?:Setting up|Processing triggers|Unpacking|Preparing to unpack|Selecting previously|Get:\d+|Hit:\d+) /,
  /^\(Reading database \.\.\./,
  /^\s*[·°×✓]+\s*$/,
];

/** The last useful lines of the log: the fallback when no extractor matches. */
export function extractTail(
  lines: readonly string[],
  keep = TAIL_LINES
): Section {
  const useful: string[] = [];
  for (const line of lines) {
    if (NOISE_RE.some((re) => re.test(line))) {
      continue;
    }
    if (line.trim() === "" && useful.at(-1)?.trim() === "") {
      continue;
    }
    useful.push(line);
  }
  return {
    kind: "tail",
    heading: `Last ${Math.min(keep, useful.length)} log lines (noise removed)`,
    count: 0,
    headline: "",
    body: trimBlank(useful.slice(-keep)),
    locations: [],
  };
}

// --- Utilities -------------------------------------------------------------------

export function unique(values: readonly string[]): string[] {
  return [...new Set(values)];
}

function uniqueBlocks(blocks: readonly string[][]): string[][] {
  const seen = new Set<string>();
  return blocks.filter((block) => {
    const key = block.join("\n");
    if (seen.has(key)) {
      return false;
    }
    seen.add(key);
    return true;
  });
}

export function trimBlank(lines: readonly string[]): string[] {
  let start = 0;
  let end = lines.length;
  while (start < end && (lines[start] ?? "").trim() === "") {
    start++;
  }
  while (end > start && (lines[end - 1] ?? "").trim() === "") {
    end--;
  }
  return lines.slice(start, end);
}

export function plural(count: number, one: string, many: string): string {
  return `${count} ${count === 1 ? one : many}`;
}
