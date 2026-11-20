import init, * as core from "../wasm-gen/klav_wasm";
import { ext } from "./ext";

let ready: Promise<typeof core> | undefined;

/**
 * klav-core compiled to WebAssembly (site rule and generator), loaded once
 * from the extension package. Never in content scripts.
 */
export function klavCore(): Promise<typeof core> {
  ready ??= init({ module_or_path: ext.runtime.getURL("klav_wasm_bg.wasm") }).then(() => core);
  return ready;
}
