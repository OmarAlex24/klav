// Validates dist/firefox with addons-linter (what addons.mozilla.org runs on
// upload). Fails on any error or warning, except the one about Firefox for
// Android: it has no native messaging, so Klav is not offered there.
//
//   node scripts/lint-firefox.mjs [DIR]   (default: dist/firefox)
import { execFileSync } from "node:child_process";
import { join, resolve } from "node:path";

const app = join(import.meta.dirname, "..");
const target = process.argv[2] ? resolve(process.argv[2]) : join(app, "dist", "firefox");
const ALLOWED = new Set(["KEY_FIREFOX_ANDROID_UNSUPPORTED_BY_MIN_VERSION"]);

let out;
try {
  out = execFileSync("addons-linter", ["--output", "json", target], { encoding: "utf8" });
} catch (e) {
  // addons-linter exits non-zero when it finds errors; the JSON is still there.
  out = e.stdout;
}
const report = JSON.parse(out);
const problems = [...report.errors, ...report.warnings.filter((w) => !ALLOWED.has(w.code))];
for (const p of problems) console.error(`${p.code}: ${p.message} (${p.file ?? "manifest"})`);
if (problems.length > 0) process.exit(1);
console.log(`${target}: addons-linter OK (${String(report.warnings.length)} warning(s) allowed)`);
