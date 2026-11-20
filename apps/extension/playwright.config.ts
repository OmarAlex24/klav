import { defineConfig } from "@playwright/test";

/** The specs that run on their own after the rest (see `projects`). */
const SERIAL = /\/(passkeys(-agentes)?|save)\.spec\.ts$/;

export default defineConfig({
  testDir: "e2e",
  globalSetup: "./e2e/global-setup.ts",
  globalTeardown: "./e2e/global-teardown.ts",
  timeout: 120_000,
  // One spec file per worker at a time; its tests still run in order. Each
  // file starts its own stack in beforeAll (klav-server on a free port, a
  // KLAV_HOME with its own klavd socket, a Chromium profile with its own
  // native host manifest), so files share nothing. CI runs four at a time.
  // Locally, one: on a Mac with traces off, four made save.spec.ts:38 and
  // passkeys.spec.ts's T80 test fail in about half the runs (PR #231).
  // `--workers=4` runs locally what CI runs.
  workers: process.env.CI ? 4 : 1,
  projects: [
    // `teardown` only orders the two: `serial` starts once every test of
    // `parallel` has ended, and it runs even if one of them failed.
    { name: "parallel", testIgnore: SERIAL, teardown: "serial" },
    // These specs run alone, one after the other. They were split out after
    // two CI failures blamed on the load beside them (runs 42339324334 and
    // 42382579723), but both had other causes, since fixed in the harness:
    // a click whose frame went before Chromium acknowledged it (`clickIn`),
    // and a click on the save bar right after it grew (`waitArmed`). A
    // filter for other files runs these too; `--no-deps` leaves them out.
    { name: "serial", testMatch: SERIAL, workers: 1 },
  ],
  reporter: [["list"]],
  // On CI a failure keeps its trace in test-results/; locally, none.
  use: { trace: process.env.CI ? "retain-on-failure" : "off" },
});
