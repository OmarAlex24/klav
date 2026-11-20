/**
 * One temporary directory per run: every stack (KLAV_HOME, Chromium
 * profile, server database) lives under it, and global-teardown.ts removes
 * it whatever happened to the tests.
 */
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

export default function globalSetup(): void {
  process.env.KLAV_E2E_ROOT = mkdtempSync(join(tmpdir(), "klav-e2e-run-"));
}
