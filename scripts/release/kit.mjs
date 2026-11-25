#!/usr/bin/env node
// The release kit (docs/releasing.md): puts one release's files in one
// directory, under the stable names the site's download links rely on,
// checks that the set is complete and writes SHA256SUMS.
//
//   node scripts/release/kit.mjs assemble --tag vX.Y.Z --chromium dev|store|none [options]
//   node scripts/release/kit.mjs seal --tag vX.Y.Z [--out DIR]
//   node scripts/release/kit.mjs firefox --tag vX.Y.Z --xpi FILE [--extension DIR] [--out DIR]
//
// assemble copies what the existing scripts produced:
//   --dmg FILE          the Mac app's DMG (default: the one Klav-<version>.dmg
//                       in target/macos/dist, from scripts/macos/build-app.sh release)
//   --extension DIR     scripts/extension/package.sh's output, checked against
//                       its SHA256SUMS (default target/extension)
//   --chromium dev      the keyed build (klav-<v>-chromium-dev.zip): fixed ID,
//                       needs `klav extension install-host --dev`
//   --chromium store    the store build (klav-<v>-chromium.zip): no key, so
//                       Chromium gives it an ID from the folder it's loaded from
//   --chromium none     no Chromium asset in this release
//   --firefox-xpi FILE  the .xpi Mozilla signed from package.sh's Firefox zip
//                       (optional). Without it the release has no Firefox file:
//                       the unsigned zip is never published
//   --linux FILE        klav-linux-x86_64.tar.gz, from the CI build (optional)
//   --server-linux FILE klav-server-linux-x86_64.tar.gz, from the same CI build
//                       (optional): klav-server, its systemd unit and example
//                       configuration
//   --out DIR           default target/release-kit/<tag>
// It then prints the command that signs the appcast for this tag. Signing
// is the owner's step; this script never signs, notarizes, tags or uploads.
//
// seal checks the directory: every file present, nothing else in it, the
// appcast pointing at this tag's Klav.dmg with its exact length and version,
// and both of its EdDSA signatures verifying with the Mac app's public key
// (KLAV_SPARKLE_PUBLIC_KEY in apps/ios/Config/Base.xcconfig). Then it writes
// SHA256SUMS. It prints the upload steps, tag on the commit RELEASE.txt
// names; it runs none.
//
// firefox adds Mozilla's signed .xpi to a release that is already sealed (the
// signature can take a day): it checks that nothing changed since seal and
// the .xpi, rewrites RELEASE.txt and SHA256SUMS, and prints the
// `gh release upload` command.
//
// Each command takes only its own flags, each once. assemble runs only in a
// clean checkout: RELEASE.txt records its commit, and the tag names it.
//
// No dependencies: it reads the zip and tar files itself, and checks Sparkle's
// Ed25519 signatures with Node's own crypto. It verifies signatures; it never
// makes one.
import { createHash, createPublicKey, verify } from "node:crypto";
import { execFileSync } from "node:child_process";
import {
  copyFileSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { gunzipSync, inflateRawSync } from "node:zlib";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const TARGET = resolve(process.env.CARGO_TARGET_DIR || join(ROOT, "target"));
const TAG = /^v(\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?)$/;
const FIREFOX_ID = "klav@klav.dev";
const XCCONFIG = join(ROOT, "apps", "ios", "Config", "Base.xcconfig");

/**
 * The release's files, by the names apps/web/server.mjs redirects to
 * (`/download/...` and `/releases/mac/appcast.xml`). Renaming one breaks
 * every link to it: change both together. `server_linux` has no route on the
 * site: Homebrew and the self-hosting docs name it by the tag's GitHub URL
 * (ADR 0048 §5.2), so renaming it breaks those instead.
 */
export const ASSETS = {
  dmg: "Klav.dmg",
  appcast: "appcast.xml",
  chromium: "klav-extension-chromium.zip",
  firefox: "klav-extension-firefox.xpi",
  linux: "klav-linux-x86_64.tar.gz",
  server_linux: "klav-server-linux-x86_64.tar.gz",
  info: "RELEASE.txt",
  sums: "SHA256SUMS",
};
/** What the Linux tarball holds, under klav-linux-x86_64/. */
export const LINUX_BINARIES = ["klav", "klavd", "klav-native-host"];
/** What the server tarball holds, under klav-server-linux-x86_64/. */
export const SERVER_LINUX_FILES = ["klav-server", "klav-server.service", "server.toml.example"];
/** Of those, the ones that must be executable. */
const SERVER_LINUX_BINARIES = ["klav-server"];

/** The flags each command takes. Anything else, or a flag given twice, fails. */
export const FLAGS = {
  assemble: ["tag", "chromium", "dmg", "extension", "firefox-xpi", "linux", "server-linux", "out"],
  seal: ["tag", "out"],
  firefox: ["tag", "xpi", "extension", "out"],
};

export class KitError extends Error {}
const fail = (why) => {
  throw new KitError(why);
};

const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
/**
 * A path or word for the printed commands, safe to paste into a shell. A
 * word that starts with `=` is quoted: zsh expands `=cmd` to a path.
 */
export const q = (s) => (/^[\w./:@+-][\w./:@=+-]*$/.test(s) ? s : `'${String(s).replace(/'/g, `'\\''`)}'`);

/**
 * What the commands read from outside their flags. Tests pass their own, so
 * the environment never changes a result.
 */
export function defaults() {
  return {
    /** Where the releases live. A fork sets KLAV_RELEASE_REPO=owner/name. */
    repo: process.env.KLAV_RELEASE_REPO || "OmarAlex24/klav",
    /** The key every Mac app build checks updates with (SUPublicEDKey). */
    sparklePublicKey: () => readSparklePublicKey(XCCONFIG),
    git: () => gitState(ROOT),
  };
}

/** KLAV_SPARKLE_PUBLIC_KEY from an xcconfig file (apps/ios/Config/Base.xcconfig). */
export function readSparklePublicKey(xcconfig) {
  const m = readFileSync(xcconfig, "utf8").match(/^KLAV_SPARKLE_PUBLIC_KEY\s*=\s*(\S+)\s*$/m);
  if (!m) fail(`no KLAV_SPARKLE_PUBLIC_KEY in ${xcconfig}`);
  return m[1];
}

/**
 * A checkout's commit, and whether anything in it differs from that commit.
 * Git's own variables are left out: a hook sets GIT_DIR, GIT_INDEX_FILE and
 * others, and `-C dir` doesn't override them, so git would read another
 * repository. --no-optional-locks: reading never rewrites the index.
 */
export function gitState(dir) {
  const env = Object.fromEntries(Object.entries(process.env).filter(([name]) => !name.startsWith("GIT_")));
  const git = (...args) => execFileSync("git", ["--no-optional-locks", "-C", dir, ...args], { encoding: "utf8", env, stdio: ["ignore", "pipe", "ignore"] });
  try {
    return { commit: git("rev-parse", "HEAD").trim(), dirty: git("status", "--porcelain").trim() !== "" };
  } catch {
    fail(`can't read this checkout's commit with git (${dir})`);
  }
}

/** The entries of a zip archive: name → bytes (stored or deflated only). */
export function readZip(buf) {
  const u16 = (at) => (at >= 0 && at + 2 <= buf.length ? buf.readUInt16LE(at) : fail("damaged zip file"));
  const u32 = (at) => (at >= 0 && at + 4 <= buf.length ? buf.readUInt32LE(at) : fail("damaged zip file"));
  // The end of central directory record: the last PK\5\6 in the file.
  let end = -1;
  for (let i = buf.length - 22; i >= Math.max(0, buf.length - 22 - 0xffff); i--) {
    if (buf.readUInt32LE(i) === 0x06054b50) {
      end = i;
      break;
    }
  }
  if (end < 0) fail("not a zip file");
  const count = u16(end + 10);
  let at = u32(end + 16);
  const entries = new Map();
  const seen = new Set();
  for (let n = 0; n < count; n++) {
    if (u32(at) !== 0x02014b50) fail("damaged zip central directory");
    const method = u16(at + 10);
    const size = u32(at + 20);
    const nameLen = u16(at + 28);
    const extraLen = u16(at + 30);
    const commentLen = u16(at + 32);
    const local = u32(at + 42);
    if (at + 46 + nameLen > buf.length) fail("damaged zip central directory");
    const name = buf.subarray(at + 46, at + 46 + nameLen).toString("utf8");
    at += 46 + nameLen + extraLen + commentLen;
    // Two entries with one name: which one a reader takes is up to the reader.
    if (seen.has(name)) fail(`the zip has two entries named ${name}`);
    seen.add(name);
    if (name.endsWith("/")) continue;
    if (u32(local) !== 0x04034b50) fail(`damaged zip entry ${name}`);
    const start = local + 30 + u16(local + 26) + u16(local + 28);
    if (start + size > buf.length) fail(`damaged zip entry ${name}`);
    const data = buf.subarray(start, start + size);
    if (method === 0) entries.set(name, data);
    else if (method === 8) {
      try {
        entries.set(name, inflateRawSync(data));
      } catch {
        fail(`damaged zip entry ${name}: it doesn't inflate`);
      }
    } else fail(`zip entry ${name} uses compression method ${method}`);
  }
  return entries;
}

/** The regular files of a .tar.gz: name → { size, mode }. */
export function listTarGz(buf) {
  let tar;
  try {
    tar = gunzipSync(buf);
  } catch {
    fail("not a .tar.gz file");
  }
  const files = new Map();
  for (let at = 0; at + 512 <= tar.length; ) {
    const header = tar.subarray(at, at + 512);
    if (header.every((b) => b === 0)) break;
    const field = (from, len) => header.subarray(from, from + len).toString("utf8").replace(/\0.*$/s, "").trim();
    const prefix = field(345, 155);
    const name = (prefix ? `${prefix}/` : "") + field(0, 100);
    const size = parseInt(field(124, 12) || "0", 8);
    const mode = parseInt(field(100, 8) || "0", 8);
    const type = String.fromCharCode(header[156] || 48);
    // Only regular files: a symlink or a link named like a binary is not one.
    if (type === "0") files.set(name.replace(/^\.\//, ""), { size, mode });
    at += 512 + Math.ceil(size / 512) * 512;
  }
  return files;
}

function manifestOf(zipPath) {
  const entries = readZip(readFileSync(zipPath));
  const manifest = entries.get("manifest.json");
  if (!manifest) fail(`${basename(zipPath)} has no manifest.json at its root`);
  return JSON.parse(manifest.toString("utf8"));
}

/** Mozilla's signature files: the COSE one and the PKCS #7 one. */
const XPI_SIGNATURES = ["META-INF/cose.sig", "META-INF/mozilla.rsa"];

/**
 * Checks Mozilla's signed .xpi against package.sh's unsigned Firefox zip:
 * a signature file is there and not empty, and every other file is the same,
 * byte for byte, so it is the build that was uploaded. This does not verify
 * the signature; Firefox does that when it installs the file, which is why
 * docs/releasing.md has the owner install it before publishing.
 */
export function checkXpi(xpiPath, firefoxZip) {
  if (!existsSync(xpiPath)) fail(`no file at ${xpiPath}`);
  const signed = readZip(readFileSync(xpiPath));
  const built = readZip(readFileSync(firefoxZip));
  const sigs = XPI_SIGNATURES.filter((name) => signed.has(name));
  if (!sigs.length) {
    fail(`${basename(xpiPath)} carries no Mozilla signature (META-INF/cose.sig or mozilla.rsa): download the signed file from addons.mozilla.org`);
  }
  for (const name of sigs) {
    if (signed.get(name).length === 0) fail(`${basename(xpiPath)} has an empty ${name}: download the signed file from addons.mozilla.org again`);
  }
  const content = [...signed.keys()].filter((name) => !name.startsWith("META-INF/")).sort();
  const want = [...built.keys()].sort();
  const missing = want.filter((name) => !signed.has(name));
  const extra = content.filter((name) => !built.has(name));
  if (missing.length || extra.length) {
    fail(`${basename(xpiPath)} is not ${basename(firefoxZip)} signed: ${[...missing.map((n) => `missing ${n}`), ...extra.map((n) => `extra ${n}`)].slice(0, 5).join(", ")}`);
  }
  for (const name of want) {
    if (!signed.get(name).equals(built.get(name))) fail(`${basename(xpiPath)} has another ${name} than ${basename(firefoxZip)}`);
  }
  const manifest = JSON.parse(signed.get("manifest.json").toString("utf8"));
  if (manifest.browser_specific_settings?.gecko?.id !== FIREFOX_ID) fail(`the .xpi's ID is not ${FIREFOX_ID}`);
  return manifest;
}

/** The files of package.sh's SHA256SUMS whose hash matches; fails on any other. */
function checkedSums(dir) {
  const sums = join(dir, "SHA256SUMS");
  if (!existsSync(sums)) fail(`no SHA256SUMS in ${dir}: run scripts/extension/package.sh`);
  const good = new Set();
  for (const line of readFileSync(sums, "utf8").split("\n").filter(Boolean)) {
    const m = line.match(/^([0-9a-f]{64}) [ *](.+)$/);
    if (!m) fail(`unreadable line in ${sums}: ${line}`);
    const file = join(dir, m[2]);
    if (!existsSync(file)) fail(`${m[2]} is in ${sums} but missing`);
    if (sha256(readFileSync(file)) !== m[1]) fail(`${m[2]} doesn't match ${sums}: rebuild it`);
    good.add(m[2]);
  }
  return good;
}

/** `command --flag value …`, with only that command's flags, each once. */
export function parseArgs(argv) {
  const [command, ...rest] = argv;
  const allowed = FLAGS[command];
  if (!allowed) return { command, opts: null };
  const opts = {};
  for (let i = 0; i < rest.length; i++) {
    const flag = rest[i];
    if (!flag.startsWith("--")) fail(`${command}: unexpected argument ${flag}`);
    const name = flag.slice(2);
    if (!allowed.includes(name)) fail(`${command}: unknown flag ${flag} (it takes ${allowed.map((f) => `--${f}`).join(", ")})`);
    if (Object.hasOwn(opts, name)) fail(`${command}: ${flag} given twice`);
    const value = rest[++i];
    if (value === undefined || value.startsWith("--")) fail(`${command}: ${flag} needs a value`);
    opts[name] = value;
  }
  return { command, opts };
}

function tagOf(opts) {
  const m = String(opts.tag ?? "").match(TAG);
  if (!m) fail("--tag must look like v0.9.0 (or v0.9.0-beta.1)");
  return { tag: opts.tag, version: m[1] };
}

const outOf = (opts, tag) => resolve(opts.out ?? join(TARGET, "release-kit", tag));
const releaseUrl = (repo, tag, file) => `https://github.com/${repo}/releases/download/${tag}/${file}`;

/** Whether `path` is `dir` or inside it, symlinks resolved. */
function inside(path, dir) {
  const real = (p) => {
    try {
      return realpathSync(p);
    } catch {
      return resolve(p);
    }
  };
  const rel = relative(real(dir), real(path));
  return rel === "" || (!isAbsolute(rel) && rel.split(sep)[0] !== "..");
}

/**
 * Empties `out` for a new kit. It deletes only the kit's own files: a
 * directory holding anything else (a checkout, a home folder) is refused,
 * as is an input that lives in it.
 */
function prepareOut(out, inputs) {
  for (const input of inputs.filter(Boolean)) {
    if (inside(input, out)) fail(`${input} is inside --out ${out}: keep the inputs elsewhere`);
  }
  if (!existsSync(out)) {
    mkdirSync(out, { recursive: true });
    return;
  }
  if (!statSync(out).isDirectory()) fail(`${out} is not a directory: use a new or empty --out`);
  const kit = new Set(Object.values(ASSETS));
  const names = readdirSync(out);
  const other = names.filter((f) => !kit.has(f) || !lstatSync(join(out, f)).isFile());
  if (other.length) fail(`${out} holds files that aren't a kit's (${other.slice(0, 5).join(", ")}): use a new or empty --out`);
  for (const f of names) rmSync(join(out, f));
}

function findDmg(opts, version) {
  if (opts.dmg) return resolve(opts.dmg);
  const dist = join(TARGET, "macos", "dist");
  const want = `Klav-${version}.dmg`;
  if (!existsSync(join(dist, want))) {
    const found = existsSync(dist) ? readdirSync(dist).filter((f) => /^Klav-.*\.dmg$/.test(f)) : [];
    fail(`no ${want} in ${dist}${found.length ? ` (found ${found.join(", ")}: is MARKETING_VERSION in apps/ios/project.yml right?)` : ": run scripts/macos/build-app.sh release"}`);
  }
  return join(dist, want);
}

export function assemble(opts, log = console.log, ctx = {}) {
  const { repo, git } = { ...defaults(), ...ctx };
  const { tag, version } = tagOf(opts);
  const chromium = opts.chromium;
  if (!["dev", "store", "none"].includes(chromium)) {
    fail("--chromium must be dev, store or none (docs/releasing.md, \"The browser extension\")");
  }
  const out = outOf(opts, tag);
  // The tag will name this commit (seal prints `--target`), so the checkout
  // must be exactly that commit.
  const { commit, dirty } = git();
  if (dirty) fail("the checkout has changes (git status): release from a clean checkout of the release commit");
  if (!/^[0-9a-f]{40}$/.test(commit)) fail(`unexpected commit ${commit}`);

  // The Mac app. A DMG ends with its UDIF trailer, "koly".
  const dmg = findDmg(opts, version);
  if (!existsSync(dmg)) fail(`no DMG at ${dmg}`);
  const dmgBytes = readFileSync(dmg);
  if (dmgBytes.length < 512 || dmgBytes.subarray(dmgBytes.length - 512, dmgBytes.length - 508).toString("latin1") !== "koly") {
    fail(`${dmg} is not a disk image`);
  }

  // The extension, from package.sh, checked against its own SHA256SUMS.
  const extDir = resolve(opts.extension ?? join(TARGET, "extension"));
  const good = checkedSums(extDir);
  const pick = (suffix) => {
    const names = [...good].filter((f) => f.endsWith(suffix));
    if (names.length !== 1) fail(`expected one *${suffix} in ${extDir}/SHA256SUMS, found ${names.length || "none"}`);
    return join(extDir, names[0]);
  };
  // The unsigned Firefox zip is the reference: it is never published, only
  // the .xpi Mozilla signed from it.
  const firefoxZip = pick("-firefox.zip");
  const firefox = manifestOf(firefoxZip);
  if (firefox.browser_specific_settings?.gecko?.id !== FIREFOX_ID) fail(`the Firefox package's ID is not ${FIREFOX_ID}`);
  const xpi = opts["firefox-xpi"] ? resolve(opts["firefox-xpi"]) : null;
  if (xpi) checkXpi(xpi, firefoxZip);

  let chromiumZip = null;
  if (chromium !== "none") {
    chromiumZip = pick(chromium === "dev" ? "-chromium-dev.zip" : "-chromium.zip");
    const manifest = manifestOf(chromiumZip);
    if (manifest.version !== firefox.version) fail("the Chromium and Firefox packages have different versions");
    const devKey = readFileSync(join(ROOT, "apps", "extension", "static", "dev-key.txt"), "utf8").trim();
    if (chromium === "dev" && manifest.key !== devKey) fail(`${basename(chromiumZip)} doesn't carry the development key`);
    if (chromium === "store" && "key" in manifest) fail(`${basename(chromiumZip)} carries a key; the store build has none`);
  }

  // Linux, from CI: the files at the top of one folder, the binaries executable.
  const linux = opts.linux ? checkTarball(opts.linux, "klav-linux-x86_64", LINUX_BINARIES, LINUX_BINARIES) : null;
  const serverLinux = opts["server-linux"]
    ? checkTarball(opts["server-linux"], "klav-server-linux-x86_64", SERVER_LINUX_FILES, SERVER_LINUX_BINARIES)
    : null;

  // Everything is checked: only now is anything in `out` removed.
  prepareOut(out, [dmg, xpi, linux, serverLinux, extDir, firefoxZip, chromiumZip]);
  copyFileSync(dmg, join(out, ASSETS.dmg));
  if (xpi) copyFileSync(xpi, join(out, ASSETS.firefox));
  if (chromiumZip) copyFileSync(chromiumZip, join(out, ASSETS.chromium));
  if (linux) copyFileSync(linux, join(out, ASSETS.linux));
  if (serverLinux) copyFileSync(serverLinux, join(out, ASSETS.server_linux));

  const info = [
    `Klav ${tag}`,
    `commit: ${commit}`,
    `mac: ${ASSETS.dmg} (from ${basename(dmg)})`,
    `extension: ${firefox.version}`,
    firefoxLine(xpi, firefoxZip),
    chromiumZip
      ? `  chromium: ${ASSETS.chromium} (from ${basename(chromiumZip)}, ${chromium === "dev" ? "development key: needs install-host --dev" : "no key: ID from the folder it's loaded from"})`
      : "  chromium: none",
    `linux: ${linux ? `${ASSETS.linux} (${LINUX_BINARIES.join(", ")})` : "none"}`,
    `server-linux: ${serverLinux ? `${ASSETS.server_linux} (${SERVER_LINUX_FILES.join(", ")})` : "none"}`,
    "",
  ].join("\n");
  writeFileSync(join(out, ASSETS.info), info);

  log(info.trimEnd());
  log(`\nAssembled in ${out}. Next, sign the appcast (only the owner; docs/macos.md §6):`);
  log(
    `  klav item get "klav://Personal/Release/Sparkle EdDSA/api_key" --reveal \\\n` +
      `    | scripts/macos/appcast.sh make --key-file - \\\n` +
      `        --url-base ${q(`https://github.com/${repo}/releases/download/${tag}`)} \\\n` +
      `        --out ${q(join(out, ASSETS.appcast))} ${q(join(out, ASSETS.dmg))}`,
  );
  log(`Then: node scripts/release/kit.mjs seal --tag ${q(tag)}${opts.out ? ` --out ${q(out)}` : ""}`);
  return { out };
}

/**
 * A CI tarball: each of `files` under `folder/`, as a regular file, and each
 * of `binaries` executable. Returns its resolved path.
 */
function checkTarball(path, folder, files, binaries) {
  const file = resolve(path);
  if (!existsSync(file)) fail(`no file at ${file}`);
  const entries = listTarGz(readFileSync(file));
  for (const name of files) {
    const entry = entries.get(`${folder}/${name}`);
    if (!entry) fail(`${basename(file)} has no ${folder}/${name} (as a regular file)`);
    if (binaries.includes(name) && !(entry.mode & 0o100)) fail(`${folder}/${name} is not executable`);
  }
  return file;
}

function firefoxLine(xpi, firefoxZip) {
  return xpi
    ? `  firefox: ${ASSETS.firefox} (signed by Mozilla from ${basename(firefoxZip)}, ID ${FIREFOX_ID})`
    : `  firefox: none yet (${basename(firefoxZip)} waits for Mozilla's signature; add it with \`kit.mjs firefox\`)`;
}

/** SHA256SUMS over every other file of the kit, sorted; returns those files. */
function writeSums(out) {
  const files = readdirSync(out).filter((f) => f !== ASSETS.sums).sort();
  const sums = files.map((f) => `${sha256(readFileSync(join(out, f)))}  ${f}`).join("\n") + "\n";
  writeFileSync(join(out, ASSETS.sums), sums);
  return { files, sums };
}

/** The appcast's item, as appcast.sh writes it. */
export function readAppcast(xml) {
  const attr = (tag, name) => xml.match(new RegExp(`<${tag}\\b[^>]*\\s${name}="([^"]*)"`))?.[1];
  const text = (tag) => xml.match(new RegExp(`<${tag}>([^<]*)</${tag}>`))?.[1];
  return {
    items: (xml.match(/<item>/g) ?? []).length,
    url: attr("enclosure", "url")?.replace(/&amp;/g, "&"),
    length: Number(attr("enclosure", "length")),
    edSignature: attr("enclosure", "sparkle:edSignature"),
    version: text("sparkle:shortVersionString"),
    build: text("sparkle:version"),
  };
}

/**
 * The feed's own signature, read as Sparkle 2.10.0 reads it
 * (SPUExtractAppcastContent): the signed bytes are everything before the
 * last "<!-- sparkle-signatures:\n", and the block holds `edSignature:` and
 * `length:` lines. Null when the feed has no such block. A block with two
 * lines of either is refused: appcast.sh signs the feed once, and which line
 * Sparkle would keep isn't checked here.
 */
export function splitSignedFeed(buf) {
  const prefix = Buffer.from("<!-- sparkle-signatures:\n");
  const at = buf.lastIndexOf(prefix);
  if (at < 0) return null;
  const end = buf.indexOf("-->", at + prefix.length);
  if (end < 0) return null;
  let signature;
  let length = 0;
  let lengthLines = 0;
  for (const line of buf.subarray(at + prefix.length, end).toString("utf8").split(/\r\n|\n|\r/)) {
    // The value starts after "edSignature: " or "length: ": parsing trims it.
    if (line.startsWith("edSignature:")) {
      if (signature !== undefined) fail("the appcast's signature block has two edSignature lines: sign it again");
      signature = line.slice("edSignature:".length).trim();
    } else if (line.startsWith("length:")) {
      if (++lengthLines > 1) fail("the appcast's signature block has two length lines: sign it again");
      length = Number(line.slice("length:".length).trim());
    }
  }
  return { content: buf.subarray(0, at), signature, length };
}

/**
 * Base64 as strictly as Foundation reads it: exactly `bytes` bytes, and the
 * text must be their canonical encoding, padding included and nothing else:
 * no whitespace around it either. Node's own decoder skips what it doesn't
 * understand, so a signature or key the app would refuse could otherwise
 * pass here. Stricter than Sparkle on purpose where it isn't known whether
 * Sparkle trims: a kit refused here costs a new signature, while a kit
 * accepted here that the app refuses ships an update nobody can install.
 * Null if it isn't.
 */
const strictBase64 = (text, bytes) => {
  const s = String(text ?? "");
  const decoded = Buffer.from(s, "base64");
  return decoded.length === bytes && decoded.toString("base64") === s ? decoded : null;
};

/** An Ed25519 check, as Sparkle makes it: a raw 32-byte key, a 64-byte signature, both base64. */
function edVerifies(publicKey, data, signature) {
  const raw = strictBase64(publicKey, 32);
  if (!raw) fail("KLAV_SPARKLE_PUBLIC_KEY is not a 32-byte Ed25519 key in base64");
  const key = createPublicKey({ key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), raw]), format: "der", type: "spki" });
  const sig = strictBase64(signature, 64);
  return sig !== null && verify(null, data, key, sig);
}

export function seal(opts, log = console.log, ctx = {}) {
  const { repo, sparklePublicKey } = { ...defaults(), ...ctx };
  const { tag, version } = tagOf(opts);
  const out = outOf(opts, tag);
  if (!existsSync(out)) fail(`no kit at ${out}: run assemble first`);
  const present = new Set(readdirSync(out));
  const allowed = new Set(Object.values(ASSETS));
  const stray = [...present].filter((f) => !allowed.has(f));
  if (stray.length) fail(`not part of a release, remove: ${stray.join(", ")}`);
  for (const need of [ASSETS.dmg, ASSETS.info]) {
    if (!present.has(need)) fail(`${need} is missing: run assemble again`);
  }
  if (!present.has(ASSETS.appcast)) fail(`${ASSETS.appcast} is missing: sign it with the command assemble printed`);
  const commit = readFileSync(join(out, ASSETS.info), "utf8").match(/^commit: ([0-9a-f]{40})$/m)?.[1];
  if (!commit) fail(`${ASSETS.info} names no commit: run assemble again`);

  // Installed Mac apps check both signatures with SUPublicEDKey and refuse
  // the update if either fails (a failed feed signature, until Sparkle's
  // SUSignedFeedFailureExpirationInterval has passed): check them here first.
  const publicKey = sparklePublicKey();
  const signed = splitSignedFeed(readFileSync(join(out, ASSETS.appcast)));
  if (!signed?.signature) fail("the appcast itself is not signed (the app requires SURequireSignedFeed)");
  const feed = readAppcast(signed.content.toString("utf8"));
  const dmgBytes = readFileSync(join(out, ASSETS.dmg));
  const wantUrl = releaseUrl(repo, tag, ASSETS.dmg);
  if (feed.items !== 1) fail(`the appcast has ${feed.items} items; appcast.sh writes one`);
  if (feed.url !== wantUrl) fail(`the appcast points at ${feed.url}, not ${wantUrl}: sign it again with --url-base https://github.com/${repo}/releases/download/${tag}`);
  if (feed.length !== dmgBytes.length) fail(`the appcast says the DMG is ${feed.length} bytes; ${ASSETS.dmg} is ${dmgBytes.length}: it was signed for another DMG`);
  if (feed.version !== version) fail(`the appcast is for version ${feed.version}, the tag for ${version}`);
  if (!feed.edSignature) fail("the appcast's enclosure has no EdDSA signature");
  if (!edVerifies(publicKey, dmgBytes, feed.edSignature)) {
    fail(`the enclosure's EdDSA signature doesn't verify for ${ASSETS.dmg} with KLAV_SPARKLE_PUBLIC_KEY (apps/ios/Config/Base.xcconfig): it was made with another key (appcast.sh test-key?) or for another file, and installed Mac apps would refuse the update`);
  }
  if (signed.length !== signed.content.length) fail(`the appcast's signature block says ${signed.length} bytes; the signed part is ${signed.content.length}: sign it again`);
  if (!edVerifies(publicKey, signed.content, signed.signature)) {
    fail("the appcast's own signature doesn't verify with KLAV_SPARKLE_PUBLIC_KEY (apps/ios/Config/Base.xcconfig): it was edited after signing or signed with another key; sign it again");
  }

  const { files, sums } = writeSums(out);

  log(`Klav ${tag}, sealed in ${out}:`);
  log(sums.replace(/^/gm, "  ").trimEnd());
  log(`\nThe owner's steps (docs/releasing.md, "Publish"): nothing here runs them. Write the notes in NOTES.md first.`);
  log(`  gh release create ${q(tag)} --repo ${q(repo)} --target ${commit} --draft --title ${q(`Klav ${version}`)} --notes-file NOTES.md \\`);
  log(`    ${[...files, ASSETS.sums].map((f) => q(join(out, f))).join(" \\\n    ")}`);
  log(`  then check the draft and publish it; ${ASSETS.dmg} goes up with the appcast, so the feed never names a missing file.`);
  log(`  The tag names ${commit}, the commit assemble ran on: build the Mac app and run the Linux workflow from that same commit.`);
  return { out, commit, files: [...files, ASSETS.sums] };
}

/**
 * A sealed kit, unchanged: every file SHA256SUMS lists is there with its
 * hash, and nothing else is, apart from SHA256SUMS and the Firefox file.
 */
function checkSealed(out) {
  const listed = new Map();
  for (const line of readFileSync(join(out, ASSETS.sums), "utf8").split("\n").filter(Boolean)) {
    const m = line.match(/^([0-9a-f]{64}) {2}(.+)$/);
    if (!m) fail(`unreadable line in ${join(out, ASSETS.sums)}: ${line}`);
    listed.set(m[2], m[1]);
  }
  const stray = readdirSync(out).filter((f) => f !== ASSETS.sums && f !== ASSETS.firefox && !listed.has(f));
  if (stray.length) fail(`not in the sealed ${ASSETS.sums}, remove: ${stray.join(", ")}`);
  const missing = [...listed.keys()].filter((f) => !existsSync(join(out, f)));
  if (missing.length) fail(`missing since seal: ${missing.join(", ")}: assemble and seal again`);
  const changed = [...listed].filter(([f, hash]) => sha256(readFileSync(join(out, f))) !== hash).map(([f]) => f);
  if (changed.length) fail(`changed since seal: ${changed.join(", ")}: assemble and seal again`);
}

export function addFirefox(opts, log = console.log, ctx = {}) {
  const { repo } = { ...defaults(), ...ctx };
  const { tag } = tagOf(opts);
  const out = outOf(opts, tag);
  if (!existsSync(join(out, ASSETS.sums))) fail(`no sealed kit at ${out}: assemble and seal the release first`);
  if (!opts.xpi) fail("--xpi is the signed file from addons.mozilla.org");
  checkSealed(out);
  const extDir = resolve(opts.extension ?? join(TARGET, "extension"));
  const zips = [...checkedSums(extDir)].filter((f) => f.endsWith("-firefox.zip"));
  if (zips.length !== 1) fail(`expected one *-firefox.zip in ${extDir}/SHA256SUMS, found ${zips.length || "none"}`);
  const firefoxZip = join(extDir, zips[0]);
  const xpi = resolve(opts.xpi);
  if (inside(xpi, out)) fail(`${xpi} is inside the kit: keep the downloaded .xpi elsewhere`);
  checkXpi(xpi, firefoxZip);
  copyFileSync(xpi, join(out, ASSETS.firefox));
  const info = readFileSync(join(out, ASSETS.info), "utf8").replace(/^ {2}firefox: .*$/m, firefoxLine(xpi, firefoxZip));
  writeFileSync(join(out, ASSETS.info), info);
  const { sums } = writeSums(out);
  log(`Added ${ASSETS.firefox} to ${out}:`);
  log(sums.replace(/^/gm, "  ").trimEnd());
  log(`\nThe owner's step (docs/releasing.md §2, step 10): nothing here runs it.`);
  log(`  gh release upload ${q(tag)} --repo ${q(repo)} --clobber \\`);
  log(`    ${[ASSETS.firefox, ASSETS.info, ASSETS.sums].map((f) => q(join(out, f))).join(" \\\n    ")}`);
  return { out };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const { command, opts } = parseArgs(process.argv.slice(2));
    if (command === "assemble") assemble(opts);
    else if (command === "seal") seal(opts);
    else if (command === "firefox") addFirefox(opts);
    else {
      console.error("usage: node scripts/release/kit.mjs assemble|seal|firefox --tag vX.Y.Z [options] (see the top of this file)");
      process.exit(2);
    }
  } catch (err) {
    if (!(err instanceof KitError)) throw err;
    console.error(`kit: ${err.message}`);
    process.exit(1);
  }
}
