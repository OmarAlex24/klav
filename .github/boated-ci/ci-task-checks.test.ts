import { describe, expect, test } from "bun:test";

import { checkName, checkNameOverrides } from "./ci-task-checks";
import { findPassedRun } from "./ci-task-skip";

// The names the PR orchestrator merges by (Klav's ci.yml).
const KLAV = JSON.stringify({
  fmt: "fmt",
  clippy: "clippy",
  test: "test",
  "test-postgres": "test (postgres)",
  docker: "docker",
  extension: "extension",
  "cargo-deny": "cargo-deny",
  docs: "docs",
});

describe("check names", () => {
  test("default is <job> / <task>", () => {
    expect(checkName("ci", "e2e", {})).toBe("ci / e2e");
  });

  test("CI_TASK_CHECK_NAMES gives exact names, including spaces and parentheses", () => {
    const overrides = checkNameOverrides({ CI_TASK_CHECK_NAMES: KLAV });
    expect(checkName("ci", "test-postgres", overrides)).toBe("test (postgres)");
    expect(checkName("ci", "fmt", overrides)).toBe("fmt");
    expect(checkName("ci", "other", overrides)).toBe("ci / other");
  });

  test("reads process.env by default", () => {
    const before = process.env.CI_TASK_CHECK_NAMES;
    process.env.CI_TASK_CHECK_NAMES = KLAV;
    try {
      expect(checkName("ci", "cargo-deny")).toBe("cargo-deny");
    } finally {
      if (before === undefined) {
        delete process.env.CI_TASK_CHECK_NAMES;
      } else {
        process.env.CI_TASK_CHECK_NAMES = before;
      }
    }
  });

  test("bad JSON, arrays and non-string values fall back to the default", () => {
    expect(checkNameOverrides({ CI_TASK_CHECK_NAMES: "{nope" })).toEqual({});
    expect(checkNameOverrides({ CI_TASK_CHECK_NAMES: '["fmt"]' })).toEqual({});
    expect(checkNameOverrides({ CI_TASK_CHECK_NAMES: '{"fmt": 1, "test": "test", "x": " "}' })).toEqual({ test: "test" });
  });

  test("skip-on-rerun matches the overridden name", () => {
    const before = process.env.CI_TASK_CHECK_NAMES;
    process.env.CI_TASK_CHECK_NAMES = KLAV;
    try {
      const run = {
        id: 7,
        name: "test (postgres)",
        app: { id: 15368 },
        external_id: "test-postgres@abc",
        conclusion: "success",
        html_url: "https://example.test/7",
        output: { summary: "<!-- boated-ci run=1 attempt=1 -->" },
      };
      expect(findPassedRun("ci", "test-postgres", "abc", [run])?.checkUrl).toBe("https://example.test/7");
      expect(findPassedRun("ci", "test-postgres", "abc", [{ ...run, name: "ci / test-postgres" }])).toBeNull();
    } finally {
      if (before === undefined) {
        delete process.env.CI_TASK_CHECK_NAMES;
      } else {
        process.env.CI_TASK_CHECK_NAMES = before;
      }
    }
  });
});
