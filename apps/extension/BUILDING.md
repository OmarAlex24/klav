# Building Klav's browser extension from this source

These steps rebuild the extension packages from the source archive `klav-<version>-source.zip`. They are for addons.mozilla.org's reviewers, and for anyone who wants to check that a published package is this code. The archive has this file and `BUILD-INFO.txt` at its root. `BUILD-INFO.txt` lists the exact versions that built the uploaded package.

## Requirements (macOS or Linux)

- Node 22, and pnpm 12 (`corepack enable`).
- Rust, at the release that `rust-toolchain.toml` pins, with the WebAssembly target: `rustup target add wasm32-unknown-unknown`.
- `wasm-bindgen-cli` 0.2.130: `cargo install wasm-bindgen-cli --version 0.2.130 --locked`.
- `zip`.

## Build

```sh
unzip klav-<version>-source.zip && cd klav-<version>-source
pnpm install --frozen-lockfile
scripts/extension/package.sh
```

The Firefox package is `target/extension/klav-<version>-firefox.zip`, unpacked in `target/extension/build/firefox`.

## What the script does

- It builds `crates/klav-wasm` with `--remap-path-prefix` for the home folder, Cargo's home and the unpacked source, in that order: rustc applies the last prefix that matches, so the source always becomes `/klav` and the dependencies `/cargo`, even when both are inside the home folder. With the Rust release in `BUILD-INFO.txt`, the WebAssembly doesn't depend on where the source is unpacked.
- It bundles `apps/extension/src` with esbuild (`apps/extension/scripts/build.mjs`). The bundle isn't minified.
- It runs `addons-linter` on the Firefox build.

The files in `target/extension/build/firefox` match the uploaded package byte for byte: compare them with `diff -r` against the unzipped upload. The `.zip` itself differs only in file timestamps.
