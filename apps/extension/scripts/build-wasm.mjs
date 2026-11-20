// Builds klav-wasm (klav-core's site rule and generator) for the
// extension: cargo for wasm32-unknown-unknown, then wasm-bindgen with the
// exact version of the wasm-bindgen crate in Cargo.lock. Honors
// CARGO_TARGET_DIR (a target on another disk).
import { execFileSync } from "node:child_process";
import { mkdirSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const app = join(here, "..");
const root = join(app, "..", "..");
const out = join(app, "src", "wasm-gen");
// Where cargo writes: CARGO_TARGET_DIR if set (relative to the workspace), or target/.
const targetDir = process.env.CARGO_TARGET_DIR ? resolve(root, process.env.CARGO_TARGET_DIR) : join(root, "target");

const lock = readFileSync(join(root, "Cargo.lock"), "utf8");
const wanted = /name = "wasm-bindgen"\nversion = "([^"]+)"/.exec(lock)?.[1];
let have;
try {
  have = execFileSync("wasm-bindgen", ["--version"], { encoding: "utf8" }).trim().split(" ")[1] ?? "";
} catch {
  have = "";
}
if (!wanted || have !== wanted) {
  console.error(
    `wasm-bindgen ${wanted ?? "?"} is needed (found ${have || "none"}): cargo install wasm-bindgen-cli --version ${wanted ?? "<version>"} --locked`,
  );
  process.exit(1);
}

execFileSync(
  "cargo",
  ["build", "-p", "klav-wasm", "--target", "wasm32-unknown-unknown", "--release", "--locked"],
  { cwd: root, stdio: "inherit" },
);
mkdirSync(out, { recursive: true });
execFileSync(
  "wasm-bindgen",
  [
    join(targetDir, "wasm32-unknown-unknown", "release", "klav_wasm.wasm"),
    "--target",
    "web",
    "--out-dir",
    out,
    "--out-name",
    "klav_wasm",
  ],
  { stdio: "inherit" },
);
console.log(`klav-wasm → ${out}`);
