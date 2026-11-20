import { describe, expect, test } from "bun:test";

import {
  cleanLine,
  cleanLog,
  extractBun,
  extractGo,
  extractLocations,
  extractNextest,
  extractPlaywright,
  extractTap,
  failureExcerpt,
  makeResolver,
  parseCommand,
  renderSections,
  scriptDirs,
} from "./ci-task-extract";

const ROOT = "/home/runner/work/app/app";

function resolverFor(files: readonly string[], dirs: readonly string[] = []) {
  const known = new Set(files);
  return makeResolver({ root: ROOT, dirs, exists: (path) => known.has(path) });
}

describe("cleanLine", () => {
  test("drops ANSI, runner timestamps and \\r progress", () => {
    expect(cleanLine("2026-10-30T19:52:06.6593363Z \u001B[31mred\u001B[0m done")).toBe("red done");
    expect(cleanLine("10%\r50%\rready\r")).toBe("ready");
    expect(cleanLine("x".repeat(5000))).toHaveLength(1002);
  });
});

describe("parseCommand", () => {
  test("reads level, decoded properties and message", () => {
    const command = parseCommand("··::error file=src/a.ts,line=3,title=Bad%3A thing::boom%0Anext");
    expect(command?.level).toBe("error");
    expect(command?.props.get("title")).toBe("Bad: thing");
    expect(command?.message).toBe("boom\nnext");
  });
});

describe("extractBun", () => {
  const log = [
    "bun test v1.2.0",
    "(pass) math > adds [1ms]",
    "12 |   expect(sum(1, 1)).toBe(3);",
    "error: expect(received).toBe(expected)",
    "Expected: 3",
    "Received: 2",
    `      at <anonymous> (${ROOT}/packages/math/sum.test.ts:12:21)`,
    "(fail) math > sums [2ms]",
    " 1 pass",
    " 1 fail",
  ];
  test("lists failed tests and their error block with a location", () => {
    const section = extractBun(log);
    expect(section?.headline).toBe("1 Bun test");
    expect(section?.body).toContain("(fail) math > sums [2ms]");
    expect(section?.body).toContain("Received: 2");
    expect(section?.locations[0]).toMatchObject({ line: 12, col: 21 });
  });
});

describe("extractGo", () => {
  const log = [
    "=== RUN   TestParse",
    "--- FAIL: TestParse (0.00s)",
    "    parse_test.go:42: want 3, got 4",
    "FAIL",
    "FAIL\texample.com/svc/internal/parse\t0.012s",
    "ok  \texample.com/svc/internal/other\t0.010s",
  ];
  test("attributes a bare file to the package that failed", () => {
    const section = extractGo(log);
    expect(section?.headline).toBe("1 Go test");
    expect(section?.locations[0]).toMatchObject({ file: "parse_test.go", line: 42, pkg: "example.com/svc/internal/parse" });
    const resolve = resolverFor(["svc/internal/parse/parse_test.go"]);
    expect(resolve("parse_test.go", "example.com/svc/internal/parse")).toBe("svc/internal/parse/parse_test.go");
  });
});

describe("extractNextest", () => {
  const failed = (counter: string) => [
    `        FAIL [   0.009s] (${counter}) klav-cli::agents denies_it`,
    "  stdout ───",
    "",
    "    running 1 test",
    "    test denies_it ... FAILED",
    "",
    "    failures:",
    "",
    "    failures:",
    "        denies_it",
    "",
    "    test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 2 filtered out; finished in 0.00s",
    "",
    "  stderr ───",
    "",
    "    thread 'denies_it' (4242) panicked at crates/klav-cli/tests/agents.rs:6:5:",
    "    assertion `left == right` failed: the value",
    "      left: 1",
    "     right: 2",
    "    note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace",
    "",
  ];
  const log = [
    "    Starting 4 tests across 2 binaries",
    "        PASS [   0.300s] (1/4) klav-cli::agents approves_it",
    ...failed("2/4"),
    "        SLOW [> 120.000s] (───) klav-ffi::ffi waits_out_the_timeout",
    "    TRY 1 FAIL [   0.010s] (3/4) klav-server::sync streams_end",
    "    TRY 2 PASS [   0.010s] (3/4) klav-server::sync streams_end",
    "        PASS [ 125.000s] (4/4) klav-ffi::ffi waits_out_the_timeout",
    "────────────",
    "     Summary [ 125.100s] 4 tests run: 3 passed (1 slow, 1 flaky), 1 failed, 0 skipped",
    ...failed("2/4"),
    "error: test run failed",
  ];

  test("one block per failed test, without libtest's noise, and its panic as annotation", () => {
    const section = extractNextest(log);
    expect(section?.headline).toBe("1 Rust test");
    expect(section?.body.slice(0, 2)).toEqual([
      "Summary [ 125.100s] 4 tests run: 3 passed (1 slow, 1 flaky), 1 failed, 0 skipped",
      "FAIL klav-cli::agents denies_it",
    ]);
    expect(section?.body.join("\n")).not.toMatch(/running 1 test|test result|failures:|stdout ───|RUST_BACKTRACE|streams_end/);
    expect(section?.body).toContain("      left: 1");
    expect(section?.locations).toEqual([
      {
        file: "crates/klav-cli/tests/agents.rs",
        line: 6,
        col: 5,
        message: "assertion `left == right` failed: the value",
        title: "klav-cli::agents denies_it",
      },
    ]);
  });

  test("a long output keeps its panic", () => {
    const dump = Array.from({ length: 300 }, (_, i) => `    {"message":"server line ${i}"}`);
    const section = extractNextest([
      "     TIMEOUT [ 360.000s] (1/1) klav-cli::cli hangs",
      "  stderr ───",
      ...dump,
      "    thread 'hangs' (1) panicked at crates/klav-cli/tests/common/server.rs:154:13:",
      "    klav-server did not listen within 20s and is still running; server.log:",
      ...dump,
      "error: test run failed",
    ]);
    expect(section?.body).toContain("    … (301 lines above in the full log)");
    expect(section?.body).toContain("    thread 'hangs' (1) panicked at crates/klav-cli/tests/common/server.rs:154:13:");
    expect(section?.body.at(-1)).toMatch(/more lines in the full log/);
    expect(section?.locations[0]).toMatchObject({ line: 154, message: "klav-server did not listen within 20s and is still running; server.log:" });
  });

  test("nothing when every test passed", () => {
    expect(extractNextest(log.filter((line) => !line.includes("FAIL [")))).toBeNull();
  });

  test("the excerpt names the tests, not cargo's last line", () => {
    const excerpt = failureExcerpt(log.join("\n"), resolverFor(["crates/klav-cli/tests/agents.rs"]));
    expect(excerpt.headline).toBe("1 Rust test");
    expect(excerpt.text).not.toContain("Bun");
    expect(excerpt.annotations[0]).toMatchObject({ path: "crates/klav-cli/tests/agents.rs", start_line: 6 });
  });

  test("a failed cargo test falls back to the tail", () => {
    const excerpt = failureExcerpt(
      "---- denies_it stdout ----\nthread 'denies_it' panicked at crates/a.rs:1:1:\nboom\n\nerror: test failed, to rerun pass `-p klav-cli --test agents`\n",
      resolverFor([])
    );
    expect(excerpt.headline).toBe("");
    expect(excerpt.text).toContain("boom");
  });
});

describe("extractPlaywright", () => {
  test("reads numbered failures", () => {
    const section = extractPlaywright([
      "  1) [chromium] › tests/login.spec.ts:10:5 › login › shows error",
      "    Error: expect(locator).toBeVisible() failed",
      "",
      "  1 failed",
      "  9 passed (30s)",
    ]);
    expect(section?.headline).toBe("1 Playwright test");
    expect(section?.locations[0]).toMatchObject({ file: "tests/login.spec.ts", line: 10, title: "login › shows error" });
  });
});

describe("extractTap", () => {
  test("keeps not-ok lines and their diagnostics", () => {
    const section = extractTap(["ok 1 - a", "not ok 2 - policy denies", "# Failed test 2", "#   have: 1", "ok 3 - c"]);
    expect(section?.count).toBe(1);
    expect(section?.body).toEqual(["not ok 2 - policy denies", "  # Failed test 2", "  #   have: 1"]);
  });
});

describe("extractLocations", () => {
  test("tsc, golangci-lint and eslint stylish formats; warnings ignored", () => {
    const section = extractLocations([
      "src/app.ts(3,7): error TS2322: Type 'string' is not assignable to type 'number'.",
      "internal/x.go:9:2: unused variable (unused)",
      "src/b.ts:1:1: warning something",
      "/repo/src/c.ts",
      "  4:10  error  'x' is defined but never used  no-unused-vars",
      "",
    ]);
    expect(section?.count).toBe(3);
    expect(section?.locations.map((l) => l.file)).toEqual(["src/app.ts", "internal/x.go", "/repo/src/c.ts"]);
  });
});

describe("failureExcerpt", () => {
  test("falls back to the de-noised tail when nothing is recognised", () => {
    const excerpt = failureExcerpt("::group::setup\nnoise\n::endgroup::\nSomething odd happened\nexit 3\n", resolverFor([]));
    expect(excerpt.headline).toBe("");
    expect(excerpt.text).toContain("Something odd happened");
    expect(excerpt.text).not.toContain("::group::");
  });

  test("turns ::error file= commands into annotations only for repo files", () => {
    const log = "::error file=src/a.ts,line=3::bad\n::error file=/usr/lib/x.ts,line=1::outside\nsrc/a.ts:3:1: bad\n";
    const excerpt = failureExcerpt(log, resolverFor(["src/a.ts"]));
    expect(excerpt.annotations).toHaveLength(1);
    expect(excerpt.annotations[0]).toMatchObject({ path: "src/a.ts", start_line: 3 });
  });

  test("never exceeds the size budget", () => {
    const sections = [{ kind: "tail" as const, heading: "h", count: 0, headline: "", body: Array(5000).fill("y".repeat(100)), locations: [] }];
    expect(renderSections(sections, 2000).length).toBeLessThanOrEqual(2000);
  });
});

describe("paths", () => {
  test("scriptDirs finds cd targets; resolver tries them", () => {
    expect(scriptDirs('cd "$GITHUB_WORKSPACE/services/api" && go test ./...')).toEqual(["services/api"]);
    const resolve = resolverFor(["services/api/main.go"], ["services/api"]);
    expect(resolve("main.go")).toBe("services/api/main.go");
    expect(resolve("node_modules/x/y.js")).toBeNull();
    expect(cleanLog("a\nb\n")).toEqual(["a", "b"]);
  });
});
