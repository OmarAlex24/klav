// node --test scripts/release/test/*.test.mjs
// The release kit with made-up inputs: no build, and a signing key made here
// for the test, never the real one. Every call passes CTX, so neither the
// environment (KLAV_RELEASE_REPO) nor the state of this checkout changes a
// result; one test reads this checkout's commit through defaults(), so the
// suite needs git and a Git checkout. Scratch files go in target/kit-test-*, inside the checkout, and are
// removed when the suite ends, also when it fails.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, rmdirSync, rmSync, symlinkSync, utimesSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { after, describe, test } from "node:test";
import { fileURLToPath } from "node:url";
import { gzipSync } from "node:zlib";

import {
  ASSETS,
  KitError,
  LINUX_BINARIES,
  addFirefox,
  assemble,
  checkXpi,
  defaults,
  gitState,
  listTarGz,
  parseArgs,
  q,
  readAppcast,
  readSparklePublicKey,
  readZip,
  seal,
  splitSignedFeed,
} from "../kit.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const DEV_KEY = readFileSync(join(ROOT, "apps", "extension", "static", "dev-key.txt"), "utf8").trim();
const TAG = "v0.9.0";
const COMMIT = "0123456789abcdef0123456789abcdef01234567";
const quiet = () => {};

/** A Sparkle key pair for the test, and another one standing for appcast.sh's test-key. */
const keyPair = () => {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return { privateKey, public64: Buffer.from(publicKey.export({ format: "jwk" }).x, "base64url").toString("base64") };
};
const KEY = keyPair();
const OTHER_KEY = keyPair();
const edSign = (bytes, key = KEY) => sign(null, bytes, key.privateKey).toString("base64");

// Git variables inherited from a hook or a worktree (GIT_DIR, GIT_INDEX_FILE,
// GIT_WORK_TREE, ...) would point the gitState test at another repository.
for (const name of Object.keys(process.env)) if (name.startsWith("GIT_")) delete process.env[name];

const CTX = { repo: "OmarAlex24/klav", sparklePublicKey: () => KEY.public64, git: () => ({ commit: COMMIT, dirty: false }) };

// Everything lives here; removed after the suite, also when it fails. target/
// is ignored by git (and may be a link to another disk: it is never replaced).
const TARGET = join(ROOT, "target");
const madeTarget = !existsSync(TARGET);
mkdirSync(TARGET, { recursive: true });
const dir = mkdtempSync(join(TARGET, "kit-test-"));
after(() => {
  rmSync(dir, { recursive: true, force: true });
  if (madeTarget) {
    try {
      rmdirSync(TARGET);
    } catch {
      // Something else put files there meanwhile: leave it.
    }
  }
});
let n = 0;
const fresh = () => {
  const d = join(dir, `c${++n}`);
  mkdirSync(d, { recursive: true });
  return d;
};

/**
 * A zip of stored entries (the reader ignores CRCs), from { name: text } or
 * from [name, text] pairs, which may repeat a name. `deflated` names entries
 * written with method 8, their bytes as given.
 */
function zip(files, { deflated = [] } = {}) {
  const list = Array.isArray(files) ? files : Object.entries(files);
  const locals = [];
  const centrals = [];
  let offset = 0;
  for (const [name, text] of list) {
    const nameBuf = Buffer.from(name);
    const data = Buffer.from(text);
    const method = deflated.includes(name) ? 8 : 0;
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(method, 8);
    local.writeUInt32LE(data.length, 18);
    local.writeUInt32LE(data.length, 22);
    local.writeUInt16LE(nameBuf.length, 26);
    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(method, 10);
    central.writeUInt32LE(data.length, 20);
    central.writeUInt32LE(data.length, 24);
    central.writeUInt16LE(nameBuf.length, 28);
    central.writeUInt32LE(offset, 42);
    locals.push(local, nameBuf, data);
    centrals.push(central, nameBuf);
    offset += 30 + nameBuf.length + data.length;
  }
  const cd = Buffer.concat(centrals);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(list.length, 8);
  end.writeUInt16LE(list.length, 10);
  end.writeUInt32LE(cd.length, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, cd, end]);
}

/** A .tar.gz of { name: mode } entries, each a few bytes long; `types` overrides an entry's type flag. */
function tarGz(files, types = {}) {
  const blocks = [];
  for (const [name, mode] of Object.entries(files)) {
    const type = types[name] ?? "0";
    const body = type === "0" ? Buffer.from("#!/bin/sh\n") : Buffer.alloc(0);
    const h = Buffer.alloc(512);
    h.write(name, 0);
    h.write(`${mode.toString(8).padStart(7, "0")}\0`, 100);
    h.write(`${body.length.toString(8).padStart(11, "0")}\0`, 124);
    h.write(type, 156);
    if (type === "2") h.write("/bin/sh", 157);
    blocks.push(h);
    if (body.length) blocks.push(body, Buffer.alloc(512 - body.length));
  }
  return gzipSync(Buffer.concat([...blocks, Buffer.alloc(1024)]));
}

const LINUX_OK = Object.fromEntries(LINUX_BINARIES.map((b) => [`klav-linux-x86_64/${b}`, 0o755]));

/** The inputs build-app.sh, package.sh and CI would leave. */
function inputs({ chromiumKey = DEV_KEY, storeKey = null, chromiumVersion = "0.1.0", firefoxId = "klav@klav.dev", linux = LINUX_OK, linuxTypes = {} } = {}) {
  const d = fresh();
  const dmg = join(d, "Klav-0.9.0.dmg");
  writeFileSync(dmg, Buffer.concat([Buffer.alloc(4096, 7), Buffer.from("koly"), Buffer.alloc(508)]));
  const ext = join(d, "extension");
  mkdirSync(ext);
  const manifest = (extra, version = "0.1.0") => JSON.stringify({ manifest_version: 3, name: "Klav", version, ...extra });
  const firefoxFiles = { "manifest.json": manifest({ browser_specific_settings: { gecko: { id: firefoxId } } }), "background.js": "run()" };
  const zips = {
    "klav-0.1.0-chromium.zip": zip({ "manifest.json": manifest(storeKey ? { key: storeKey } : {}, chromiumVersion), "background.js": "" }),
    "klav-0.1.0-chromium-dev.zip": zip({ "manifest.json": manifest(chromiumKey ? { key: chromiumKey } : {}, chromiumVersion) }),
    "klav-0.1.0-firefox.zip": zip(firefoxFiles),
  };
  const sums = [];
  for (const [name, bytes] of Object.entries(zips)) {
    writeFileSync(join(ext, name), bytes);
    sums.push(`${createHash("sha256").update(bytes).digest("hex")}  ${name}`);
  }
  writeFileSync(join(ext, "SHA256SUMS"), sums.join("\n") + "\n");
  const tarball = join(d, "klav-linux-x86_64.tar.gz");
  writeFileSync(tarball, tarGz(linux, linuxTypes));
  // What addons.mozilla.org gives back: the same files plus its signature.
  const xpi = join(d, "klav-0.1.0-signed.xpi");
  writeFileSync(xpi, zip({ ...firefoxFiles, "META-INF/cose.sig": "sig", "META-INF/mozilla.rsa": "rsa", "META-INF/manifest.mf": "mf" }));
  return { d, dmg, ext, tarball, xpi, firefoxFiles, firefoxZip: join(ext, "klav-0.1.0-firefox.zip"), out: join(d, "kit") };
}

/**
 * An appcast as appcast.sh writes it: the enclosure signed over `dmg`, then
 * the whole feed signed as Sparkle's sign_update does (signature over every
 * byte before the block, and their count).
 */
function appcast({ dmg, url = `https://github.com/OmarAlex24/klav/releases/download/${TAG}/Klav.dmg`, length = dmg.length, version = "0.9.0", items = 1, enclosureSig = edSign(dmg), feedKey = KEY, signed = true, tamper = (s) => s, blockLength } = {}) {
  const item = `    <item>
      <title>Klav ${version}</title>
      <sparkle:version>12</sparkle:version>
      <sparkle:shortVersionString>${version}</sparkle:shortVersionString>
      <enclosure url="${url}" type="application/octet-stream"${enclosureSig ? ` sparkle:edSignature="${enclosureSig}"` : ""} length="${length}"/>
    </item>
`;
  const content = Buffer.from(`<?xml version="1.0" encoding="utf-8"?>
<rss version="2.0" xmlns:sparkle="http://www.andymatuschak.org/xml-namespaces/sparkle">
  <channel>
    <title>Klav</title>
${item.repeat(items)}  </channel>
</rss>
`);
  if (!signed) return content;
  const block = `<!-- sparkle-signatures:\nedSignature: ${edSign(content, feedKey)}\nlength: ${blockLength ?? content.length}\n-->\n`;
  return Buffer.from(tamper(content.toString("utf8")) + block);
}

describe("assemble", () => {
  test("copies each file under its stable name, with the keyed Chromium build, and records the commit", () => {
    const i = inputs();
    assemble({ tag: TAG, chromium: "dev", dmg: i.dmg, extension: i.ext, linux: i.tarball, "firefox-xpi": i.xpi, out: i.out }, quiet, CTX);
    assert.deepEqual(readFileSync(join(i.out, ASSETS.dmg)), readFileSync(i.dmg));
    assert.deepEqual(readFileSync(join(i.out, ASSETS.chromium)), readFileSync(join(i.ext, "klav-0.1.0-chromium-dev.zip")));
    assert.deepEqual(readFileSync(join(i.out, ASSETS.firefox)), readFileSync(i.xpi));
    assert.deepEqual(readFileSync(join(i.out, ASSETS.linux)), readFileSync(i.tarball));
    const info = readFileSync(join(i.out, ASSETS.info), "utf8");
    assert.match(info, /^Klav v0\.9\.0\ncommit: 0123456789abcdef0123456789abcdef01234567\n/);
    assert.match(info, /development key: needs install-host --dev/);
    assert.match(info, /firefox: klav-extension-firefox\.xpi \(signed by Mozilla/);
  });

  test("refuses a checkout with changes: the tag must name exactly what was built", () => {
    const i = inputs();
    const dirty = { ...CTX, git: () => ({ commit: COMMIT, dirty: true }) };
    assert.throws(() => assemble({ tag: TAG, chromium: "dev", dmg: i.dmg, extension: i.ext, out: i.out }, quiet, dirty), /clean checkout/);
    assert.equal(existsSync(i.out), false);
    // Only a full commit hash goes in RELEASE.txt, and from there into --target.
    for (const commit of ["HEAD", COMMIT.slice(0, 12), COMMIT.toUpperCase(), `${COMMIT}0`, `0${COMMIT}`]) {
      const odd = { ...CTX, git: () => ({ commit, dirty: false }) };
      assert.throws(() => assemble({ tag: TAG, chromium: "dev", dmg: i.dmg, extension: i.ext, out: i.out }, quiet, odd), /unexpected commit/);
    }
  });

  test("without a signed .xpi there is no Firefox file: the unsigned zip is never published", () => {
    const i = inputs();
    assemble({ tag: TAG, chromium: "dev", dmg: i.dmg, extension: i.ext, out: i.out }, quiet, CTX);
    assert.throws(() => readFileSync(join(i.out, ASSETS.firefox)), /ENOENT/);
    assert.match(readFileSync(join(i.out, ASSETS.info), "utf8"), /firefox: none yet/);
  });

  test("refuses an .xpi that isn't the uploaded build signed", () => {
    const i = inputs();
    const base = { tag: TAG, chromium: "none", dmg: i.dmg, extension: i.ext, out: i.out };
    const write = (name, bytes) => {
      const path = join(i.d, name);
      writeFileSync(path, bytes);
      return path;
    };
    const sig = { "META-INF/cose.sig": "sig" };
    const cases = [
      [zip(i.firefoxFiles), /no Mozilla signature/],
      [zip({ ...i.firefoxFiles, "META-INF/cose.sig": "" }), /empty META-INF\/cose\.sig/],
      [zip({ ...i.firefoxFiles, "META-INF/mozilla.rsa": "rsa", "META-INF/cose.sig": "" }), /empty META-INF\/cose\.sig/],
      [zip({ ...i.firefoxFiles, "background.js": "evil()", ...sig }), /another background\.js/],
      [zip({ ...i.firefoxFiles, "extra.js": "", ...sig }), /extra extra\.js/],
      [zip({ "manifest.json": i.firefoxFiles["manifest.json"], ...sig }), /missing background\.js/],
      [zip([...Object.entries(i.firefoxFiles), ["background.js", "evil()"], ...Object.entries(sig)]), /two entries named background\.js/],
    ];
    for (const [bytes, why] of cases) assert.throws(() => assemble({ ...base, "firefox-xpi": write(`case${++n}.xpi`, bytes) }, quiet, CTX), why);
    assert.equal(existsSync(i.out), false);
  });

  test("checkXpi checks the signed file's own ID, not only the zip's", () => {
    const i = inputs({ firefoxId: "evil@example.com" });
    const xpi = join(i.d, "evil.xpi");
    writeFileSync(xpi, zip({ ...i.firefoxFiles, "META-INF/cose.sig": "sig" }));
    assert.throws(() => checkXpi(xpi, i.firefoxZip), /the \.xpi's ID is not klav@klav\.dev/);
  });

  test("the store build, or no Chromium at all", () => {
    const i = inputs();
    assemble({ tag: TAG, chromium: "store", dmg: i.dmg, extension: i.ext, out: i.out }, quiet, CTX);
    assert.deepEqual(readFileSync(join(i.out, ASSETS.chromium)), readFileSync(join(i.ext, "klav-0.1.0-chromium.zip")));
    assert.match(readFileSync(join(i.out, ASSETS.info), "utf8"), /linux: none/);
    const j = inputs();
    assemble({ tag: TAG, chromium: "none", dmg: j.dmg, extension: j.ext, out: j.out }, quiet, CTX);
    assert.throws(() => readFileSync(join(j.out, ASSETS.chromium)), /ENOENT/);
  });

  test("the Chromium choice is never implied", () => {
    const i = inputs();
    assert.throws(() => assemble({ tag: TAG, dmg: i.dmg, extension: i.ext, out: i.out }, quiet, CTX), /--chromium must be/);
  });

  test("refuses a bad tag, a file that isn't a DMG, or a package that doesn't match its sums", () => {
    const i = inputs();
    const base = { chromium: "dev", dmg: i.dmg, extension: i.ext, out: i.out };
    for (const tag of ["0.9.0", "v0.9", "latest", "v0.9.0;rm"]) assert.throws(() => assemble({ ...base, tag }, quiet, CTX), /--tag/);
    const short = join(i.d, "short.dmg");
    writeFileSync(short, "hello");
    assert.throws(() => assemble({ ...base, tag: TAG, dmg: short }, quiet, CTX), /not a disk image/);
    // Long enough, but without the UDIF trailer.
    const noTrailer = join(i.d, "no-trailer.dmg");
    writeFileSync(noTrailer, Buffer.alloc(8192, 7));
    assert.throws(() => assemble({ ...base, tag: TAG, dmg: noTrailer }, quiet, CTX), /not a disk image/);
    writeFileSync(join(i.ext, "klav-0.1.0-firefox.zip"), zip({ "manifest.json": "{}" }));
    assert.throws(() => assemble({ ...base, tag: TAG }, quiet, CTX), /doesn't match/);
  });

  test("checks the keys, the versions and the Firefox ID", () => {
    const run = (i, chromium) => () => assemble({ tag: TAG, chromium, dmg: i.dmg, extension: i.ext, out: i.out }, quiet, CTX);
    assert.throws(run(inputs({ chromiumKey: null }), "dev"), /development key/);
    assert.throws(run(inputs({ chromiumKey: "MIIBsomeoneelse" }), "dev"), /development key/);
    assert.throws(run(inputs({ storeKey: DEV_KEY }), "store"), /carries a key; the store build has none/);
    assert.throws(run(inputs({ chromiumVersion: "0.2.0" }), "dev"), /different versions/);
    assert.throws(run(inputs({ firefoxId: "evil@example.com" }), "none"), /klav@klav\.dev/);
  });

  test("the Linux tarball needs every binary, executable, as a regular file", () => {
    const run = (i) => () => assemble({ tag: TAG, chromium: "none", dmg: i.dmg, extension: i.ext, linux: i.tarball, out: i.out }, quiet, CTX);
    assert.throws(run(inputs({ linux: { "klav-linux-x86_64/klav": 0o755 } })), /klav-linux-x86_64\/klavd/);
    assert.throws(run(inputs({ linux: Object.fromEntries(LINUX_BINARIES.map((b) => [`klav-linux-x86_64/${b}`, 0o644])) })), /not executable/);
    assert.throws(run(inputs({ linuxTypes: { "klav-linux-x86_64/klav": "2" } })), /no klav-linux-x86_64\/klav \(as a regular file\)/);
  });

  test("--out: never deletes what isn't a kit's, and never an input", () => {
    const i = inputs();
    const base = { tag: TAG, chromium: "dev", dmg: i.dmg, extension: i.ext };
    // A folder with other files in it (a checkout, a home folder) is refused, untouched.
    mkdirSync(i.out);
    writeFileSync(join(i.out, "Cargo.toml"), "[workspace]");
    writeFileSync(join(i.out, ASSETS.dmg), "old");
    assert.throws(() => assemble({ ...base, out: i.out }, quiet, CTX), /holds files that aren't a kit's \(Cargo\.toml\): use a new or empty --out/);
    assert.equal(readFileSync(join(i.out, "Cargo.toml"), "utf8"), "[workspace]");
    assert.equal(readFileSync(join(i.out, ASSETS.dmg), "utf8"), "old");
    // So is the directory the inputs are in.
    assert.throws(() => assemble({ ...base, out: i.d }, quiet, CTX), /is inside --out/);
    assert.equal(existsSync(i.dmg), true);
    // An input inside --out, even in a kit-only folder, is refused before anything is removed.
    rmSync(join(i.out, "Cargo.toml"));
    const dmgInside = join(i.out, ASSETS.dmg);
    writeFileSync(dmgInside, readFileSync(i.dmg));
    assert.throws(() => assemble({ ...base, dmg: dmgInside, out: i.out }, quiet, CTX), /inside --out/);
    assert.deepEqual(readFileSync(dmgInside), readFileSync(i.dmg));
    // A file is not a folder.
    const file = join(i.d, "a-file");
    writeFileSync(file, "x");
    assert.throws(() => assemble({ ...base, out: file }, quiet, CTX), /is not a directory: use a new or empty --out/);
    // A link named like a kit file is not a kit file, even when it points at
    // a real file; the file it points at stays.
    const linked = join(i.d, "linked-out");
    mkdirSync(linked);
    symlinkSync(i.dmg, join(linked, ASSETS.dmg));
    assert.throws(() => assemble({ ...base, out: linked }, quiet, CTX), /holds files that aren't a kit's \(Klav\.dmg\)/);
    assert.equal(lstatSync(join(linked, ASSETS.dmg)).isSymbolicLink(), true);
    assert.equal(existsSync(i.dmg), true);
    // A folder named like a kit file is not a kit file.
    const other = join(i.d, "other-out");
    mkdirSync(join(other, ASSETS.dmg), { recursive: true });
    assert.throws(() => assemble({ ...base, out: other }, quiet, CTX), /holds files that aren't a kit's \(Klav\.dmg\)/);
    assert.equal(existsSync(join(other, ASSETS.dmg)), true);
    // A folder with only a kit's files is emptied first: a file of the old kit doesn't stay.
    assemble({ ...base, linux: i.tarball, out: i.out }, quiet, CTX);
    assert.equal(existsSync(join(i.out, ASSETS.linux)), true);
    assemble({ ...base, out: i.out }, quiet, CTX);
    assert.equal(existsSync(join(i.out, ASSETS.linux)), false);
  });

  test("prints the appcast command with every path quoted", () => {
    const i = inputs();
    const out = join(i.d, "it's a kit");
    const lines = [];
    assemble({ tag: TAG, chromium: "dev", dmg: i.dmg, extension: i.ext, out }, (l) => lines.push(l), CTX);
    const text = lines.join("\n");
    assert.ok(text.includes(`--out '${join(i.d, "it'\\''s a kit")}/appcast.xml'`), text);
    assert.ok(text.includes(`--url-base https://github.com/OmarAlex24/klav/releases/download/v0.9.0`), text);
  });

  test("q quotes what a shell would change, and nothing else", () => {
    for (const plain of ["v0.9.0", "/a/b/Klav.dmg", "OmarAlex24/klav", "a=b", "https://github.com/x/y"]) assert.equal(q(plain), plain);
    // zsh expands a word that starts with `=` to a command's path.
    assert.equal(q("=ls"), "'=ls'");
    assert.equal(q("it's"), "'it'\\''s'");
    assert.equal(q("a b"), "'a b'");
    assert.equal(q(""), "''");
    // Whatever a shell could expand, glob or split is quoted, `{` alone too.
    for (const w of ["~", "~/x", "#a", "*", "a?", "[a]", "{a,b}", "$HOME", "`id`", "a;b", "a{1..2}", "a{b", "{"]) assert.equal(q(w), `'${w}'`);
  });
});

describe("seal", () => {
  const ready = () => {
    const i = inputs();
    assemble({ tag: TAG, chromium: "dev", dmg: i.dmg, extension: i.ext, out: i.out }, quiet, CTX);
    return { ...i, dmgBytes: readFileSync(join(i.out, ASSETS.dmg)) };
  };

  test("writes SHA256SUMS once both signatures verify, and prints a tag on the recorded commit", () => {
    const i = ready();
    writeFileSync(join(i.out, ASSETS.appcast), appcast({ dmg: i.dmgBytes }));
    const lines = [];
    const { files, commit } = seal({ tag: TAG, out: i.out }, (l) => lines.push(l), CTX);
    assert.equal(commit, COMMIT);
    assert.deepEqual(files, ["Klav.dmg", "RELEASE.txt", "appcast.xml", "klav-extension-chromium.zip", "SHA256SUMS"]);
    const sums = readFileSync(join(i.out, ASSETS.sums), "utf8").trim().split("\n");
    assert.equal(sums.length, 4);
    for (const line of sums) {
      const [hash, name] = line.split("  ");
      assert.equal(hash, createHash("sha256").update(readFileSync(join(i.out, name))).digest("hex"), name);
    }
    const text = lines.join("\n");
    assert.match(text, /gh release create v0\.9\.0 --repo OmarAlex24\/klav --target 0123456789abcdef0123456789abcdef01234567 --draft --title 'Klav 0\.9\.0' --notes-file NOTES\.md/);
    assert.doesNotMatch(text, /<notes>/);
  });

  test("refuses an appcast for another tag, DMG or version, or that isn't one item", () => {
    const i = ready();
    const cases = [
      [{ url: "https://klav.dev/releases/mac/Klav-0.9.0.dmg" }, /--url-base/],
      [{ url: `https://github.com/OmarAlex24/klav/releases/download/v0.8.0/Klav.dmg` }, /not https/],
      [{ length: i.dmgBytes.length + 1 }, /signed for another DMG/],
      [{ version: "0.8.0" }, /version 0\.8\.0/],
      [{ items: 2 }, /has 2 items/],
      [{ items: 0 }, /has 0 items/],
    ];
    for (const [feed, why] of cases) {
      writeFileSync(join(i.out, ASSETS.appcast), appcast({ dmg: i.dmgBytes, ...feed }));
      assert.throws(() => seal({ tag: TAG, out: i.out }, quiet, CTX), why);
    }
    assert.equal(existsSync(join(i.out, ASSETS.sums)), false);
  });

  test("verifies both signatures with the Mac app's key, not only that they are there", () => {
    const i = ready();
    const cases = [
      [{ signed: false }, /not signed/],
      [{ enclosureSig: null }, /enclosure has no EdDSA signature/],
      // appcast.sh test-key, or the right key over other bytes.
      [{ enclosureSig: edSign(i.dmgBytes, OTHER_KEY) }, /enclosure's EdDSA signature doesn't verify/],
      [{ enclosureSig: edSign(Buffer.from("another dmg")) }, /enclosure's EdDSA signature doesn't verify/],
      [{ enclosureSig: "c2lnbmF0dXJl" }, /enclosure's EdDSA signature doesn't verify/],
      // Base64 that Node would decode but Foundation refuses.
      [{ enclosureSig: edSign(i.dmgBytes).replace(/=+$/, "") }, /enclosure's EdDSA signature doesn't verify/],
      [{ enclosureSig: edSign(i.dmgBytes).replace(/^(.{20})/, "$1 ") }, /enclosure's EdDSA signature doesn't verify/],
      // Whitespace around it: whether Sparkle trims it isn't known, so the kit refuses it.
      [{ enclosureSig: ` ${edSign(i.dmgBytes)}` }, /enclosure's EdDSA signature doesn't verify/],
      [{ enclosureSig: `${edSign(i.dmgBytes)} ` }, /enclosure's EdDSA signature doesn't verify/],
      [{ feedKey: OTHER_KEY }, /appcast's own signature doesn't verify/],
      [{ tamper: (s) => s.replace("<title>Klav</title>", "<title>KLAV</title>") }, /appcast's own signature doesn't verify/],
      [{ blockLength: 600 }, /signature block says 600 bytes/],
    ];
    for (const [feed, why] of cases) {
      writeFileSync(join(i.out, ASSETS.appcast), appcast({ dmg: i.dmgBytes, ...feed }));
      assert.throws(() => seal({ tag: TAG, out: i.out }, quiet, CTX), why);
    }
    // Two signature blocks: Sparkle reads the last one, which covers every
    // byte before it, the first block included. A copy of the first block's
    // signature there (its length line made to match) doesn't verify.
    const good = appcast({ dmg: i.dmgBytes });
    const block = good.subarray(good.lastIndexOf(Buffer.from("<!-- sparkle-signatures:\n"))).toString("utf8");
    writeFileSync(join(i.out, ASSETS.appcast), Buffer.concat([good, Buffer.from(block.replace(/^length: \d+$/m, `length: ${good.length}`))]));
    assert.throws(() => seal({ tag: TAG, out: i.out }, quiet, CTX), /appcast's own signature doesn't verify/);
    // A block without an edSignature line is no signature.
    const content = appcast({ dmg: i.dmgBytes, signed: false });
    writeFileSync(join(i.out, ASSETS.appcast), Buffer.concat([content, Buffer.from(`<!-- sparkle-signatures:\nlength: ${content.length}\n-->\n`)]));
    assert.throws(() => seal({ tag: TAG, out: i.out }, quiet, CTX), /not signed/);
    // A block with two edSignature lines, or two length lines, is refused
    // whichever one is good: appcast.sh signs the feed once.
    const once = `<!-- sparkle-signatures:\nedSignature: ${edSign(content)}\nlength: ${content.length}\n-->\n`;
    for (const [twice, why] of [
      [once.replace("edSignature:", `edSignature: ${edSign(content, OTHER_KEY)}\nedSignature:`), /two edSignature lines/],
      [once.replace(/(edSignature: .*\n)/, `$1edSignature: ${edSign(content, OTHER_KEY)}\n`), /two edSignature lines/],
      [once.replace("length:", `length: ${content.length}\nlength:`), /two length lines/],
    ]) {
      writeFileSync(join(i.out, ASSETS.appcast), Buffer.concat([content, Buffer.from(twice)]));
      assert.throws(() => seal({ tag: TAG, out: i.out }, quiet, CTX), why);
    }
    writeFileSync(join(i.out, ASSETS.appcast), Buffer.concat([content, Buffer.from(once)]));
    seal({ tag: TAG, out: i.out }, quiet, CTX);
    // A key the app couldn't read is refused before any check.
    writeFileSync(join(i.out, ASSETS.appcast), good);
    // Whitespace around the key: the xcconfig reader never returns it, and the
    // check refuses it.
    const badKeys = ["", Buffer.alloc(31, 1).toString("base64"), Buffer.alloc(33, 1).toString("base64"), ` ${KEY.public64}`, `${KEY.public64}\n`, `${KEY.public64.slice(0, 10)}!${KEY.public64.slice(10)}`, KEY.public64.replace(/=$/, "")];
    for (const bad of badKeys) {
      assert.throws(() => seal({ tag: TAG, out: i.out }, quiet, { ...CTX, sparklePublicKey: () => bad }), /not a 32-byte Ed25519 key/, JSON.stringify(bad));
    }
    // The real key is read from Base.xcconfig: the test key fails against it.
    writeFileSync(join(i.out, ASSETS.appcast), appcast({ dmg: i.dmgBytes }));
    const { sparklePublicKey, ...withRealKey } = CTX;
    assert.equal(typeof sparklePublicKey, "function");
    assert.throws(() => seal({ tag: TAG, out: i.out }, quiet, withRealKey), /doesn't verify/);
  });

  test("refuses without the appcast, the DMG or the commit, or with a file that isn't part of a release", () => {
    const i = ready();
    assert.throws(() => seal({ tag: TAG, out: i.out }, quiet, CTX), /appcast\.xml is missing/);
    writeFileSync(join(i.out, ASSETS.appcast), appcast({ dmg: i.dmgBytes }));
    for (const stray of ["notes.txt", ".DS_Store"]) {
      writeFileSync(join(i.out, stray), "x");
      assert.throws(() => seal({ tag: TAG, out: i.out }, quiet, CTX), new RegExp(stray.replace(".", "\\.")));
      rmSync(join(i.out, stray));
    }
    const info = readFileSync(join(i.out, ASSETS.info), "utf8");
    writeFileSync(join(i.out, ASSETS.info), info.replace(/^commit: .*\n/m, ""));
    assert.throws(() => seal({ tag: TAG, out: i.out }, quiet, CTX), /names no commit/);
    // Only a full commit hash: `--target HEAD` would tag whatever main is then.
    for (const odd of ["HEAD", COMMIT.slice(0, 12), "main", "g".repeat(40), COMMIT.toUpperCase(), `${COMMIT}0`, `$(id)${"a".repeat(35)}`]) {
      writeFileSync(join(i.out, ASSETS.info), info.replace(/^commit: .*$/m, `commit: ${odd}`));
      assert.throws(() => seal({ tag: TAG, out: i.out }, quiet, CTX), /names no commit/, odd);
    }
    // Only a line that starts with "commit:".
    writeFileSync(join(i.out, ASSETS.info), info.replace(/^commit: .*$/m, `not the commit: ${COMMIT}`));
    assert.throws(() => seal({ tag: TAG, out: i.out }, quiet, CTX), /names no commit/);
    writeFileSync(join(i.out, ASSETS.info), info);
    rmSync(join(i.out, ASSETS.dmg));
    assert.throws(() => seal({ tag: TAG, out: i.out }, quiet, CTX), /Klav\.dmg is missing/);
  });
});

describe("firefox", () => {
  const sealed = () => {
    const i = inputs();
    assemble({ tag: TAG, chromium: "dev", dmg: i.dmg, extension: i.ext, out: i.out }, quiet, CTX);
    writeFileSync(join(i.out, ASSETS.appcast), appcast({ dmg: readFileSync(join(i.out, ASSETS.dmg)) }));
    seal({ tag: TAG, out: i.out }, quiet, CTX);
    return i;
  };

  test("adds the signed .xpi to a sealed release, with RELEASE.txt and SHA256SUMS rewritten", () => {
    const i = inputs();
    assemble({ tag: TAG, chromium: "dev", dmg: i.dmg, extension: i.ext, out: i.out }, quiet, CTX);
    assert.throws(() => addFirefox({ tag: TAG, xpi: i.xpi, extension: i.ext, out: i.out }, quiet, CTX), /no sealed kit/);
    writeFileSync(join(i.out, ASSETS.appcast), appcast({ dmg: readFileSync(join(i.out, ASSETS.dmg)) }));
    seal({ tag: TAG, out: i.out }, quiet, CTX);
    addFirefox({ tag: TAG, xpi: i.xpi, extension: i.ext, out: i.out }, quiet, CTX);
    assert.deepEqual(readFileSync(join(i.out, ASSETS.firefox)), readFileSync(i.xpi));
    assert.match(readFileSync(join(i.out, ASSETS.info), "utf8"), /firefox: klav-extension-firefox\.xpi \(signed/);
    const names = readFileSync(join(i.out, ASSETS.sums), "utf8").trim().split("\n").map((l) => l.split("  ")[1]);
    assert.deepEqual(names, ["Klav.dmg", "RELEASE.txt", "appcast.xml", "klav-extension-chromium.zip", "klav-extension-firefox.xpi"]);
    // Again, with the same file: what it added is now part of the seal.
    addFirefox({ tag: TAG, xpi: i.xpi, extension: i.ext, out: i.out }, quiet, CTX);
  });

  test("refuses a kit that changed since seal, and certifies nothing new", () => {
    const run = (i) => () => addFirefox({ tag: TAG, xpi: i.xpi, extension: i.ext, out: i.out }, quiet, CTX);
    const changed = sealed();
    const before = readFileSync(join(changed.out, ASSETS.sums), "utf8");
    writeFileSync(join(changed.out, ASSETS.dmg), "a different DMG");
    assert.throws(run(changed), /changed since seal: Klav\.dmg: assemble and seal again/);
    assert.equal(readFileSync(join(changed.out, ASSETS.sums), "utf8"), before);
    assert.equal(existsSync(join(changed.out, ASSETS.firefox)), false);
    for (const stray of ["notes.txt", ".DS_Store"]) {
      const i = sealed();
      writeFileSync(join(i.out, stray), "x");
      assert.throws(run(i), new RegExp(`not in the sealed SHA256SUMS, remove: ${stray.replace(".", "\\.")}`));
    }
    const gone = sealed();
    rmSync(join(gone.out, ASSETS.appcast));
    assert.throws(run(gone), /missing since seal: appcast\.xml/);
  });

  test("refuses an .xpi that is already inside the kit", () => {
    const i = sealed();
    const inKit = join(i.out, ASSETS.firefox);
    writeFileSync(inKit, readFileSync(i.xpi));
    assert.throws(() => addFirefox({ tag: TAG, xpi: inKit, extension: i.ext, out: i.out }, quiet, CTX), /inside the kit/);
  });

  test("checks the .xpi as assemble does", () => {
    const i = sealed();
    const unsigned = join(i.d, "unsigned.xpi");
    writeFileSync(unsigned, zip(i.firefoxFiles));
    assert.throws(() => addFirefox({ tag: TAG, xpi: unsigned, extension: i.ext, out: i.out }, quiet, CTX), /no Mozilla signature/);
    assert.equal(existsSync(join(i.out, ASSETS.firefox)), false);
  });
});

describe("what the kit reads from the checkout", () => {
  test("the Sparkle key from an xcconfig file, and the real one is a key the app can read", () => {
    const d = fresh();
    const file = join(d, "Base.xcconfig");
    writeFileSync(file, `// KLAV_SPARKLE_PUBLIC_KEY = old\nKLAV_SPARKLE_FEED_URL = https:/$()/klav.dev/x\nKLAV_SPARKLE_PUBLIC_KEY = ${KEY.public64}\n`);
    assert.equal(readSparklePublicKey(file), KEY.public64);
    // Spaces after the value are not part of it.
    writeFileSync(file, `KLAV_SPARKLE_PUBLIC_KEY = ${KEY.public64}   \n`);
    assert.equal(readSparklePublicKey(file), KEY.public64);
    // A value of two words is no key: Xcode would hand the app both.
    writeFileSync(file, `KLAV_SPARKLE_PUBLIC_KEY = ${KEY.public64} extra\n`);
    assert.throws(() => readSparklePublicKey(file), /no KLAV_SPARKLE_PUBLIC_KEY in/);
    writeFileSync(file, "KLAV_SPARKLE_FEED_URL = x\n");
    assert.throws(() => readSparklePublicKey(file), /no KLAV_SPARKLE_PUBLIC_KEY in/);
    const real = readSparklePublicKey(join(ROOT, "apps", "ios", "Config", "Base.xcconfig"));
    assert.equal(Buffer.from(real, "base64").length, 32);
    assert.equal(Buffer.from(real, "base64").toString("base64"), real);
  });

  test("the commit and whether the checkout has changes, from a real repository", () => {
    const repo = fresh();
    const git = (...args) =>
      execFileSync("git", ["-C", repo, "-c", "user.name=Kit test", "-c", "user.email=kit@example.invalid", "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null", ...args], {
        encoding: "utf8",
        stdio: ["ignore", "pipe", "ignore"],
      });
    git("init", "-q");
    writeFileSync(join(repo, "a.txt"), "a\n");
    git("add", "a.txt");
    git("commit", "-q", "-m", "a");
    const head = git("rev-parse", "HEAD").trim();
    assert.deepEqual(gitState(repo), { commit: head, dirty: false });
    assert.match(head, /^[0-9a-f]{40}$/);
    // Reading never rewrites the index: a file whose time changed but whose
    // bytes didn't would otherwise make `git status` refresh it.
    const index = join(repo, ".git", "index");
    const later = new Date(Date.now() + 86_400_000);
    utimesSync(join(repo, "a.txt"), later, later);
    const indexBefore = readFileSync(index);
    assert.deepEqual(gitState(repo), { commit: head, dirty: false });
    assert.deepEqual(readFileSync(index), indexBefore);
    writeFileSync(join(repo, "a.txt"), "changed\n");
    assert.deepEqual(gitState(repo), { commit: head, dirty: true });
    writeFileSync(join(repo, "a.txt"), "a\n");
    writeFileSync(join(repo, "new.txt"), "untracked\n");
    assert.equal(gitState(repo).dirty, true);
    assert.throws(() => gitState(join(fresh(), "missing")), /can't read this checkout's commit/);

    // Git variables from a hook don't move it to another repository: with
    // GIT_DIR or GIT_INDEX_FILE pointing at a second repository, it still
    // reads this one, and the second one's index is untouched.
    writeFileSync(join(repo, "a.txt"), "a\n");
    rmSync(join(repo, "new.txt"));
    const other = fresh();
    execFileSync("git", ["-C", other, "init", "-q"], { stdio: "ignore" });
    for (const [name, value] of [
      ["GIT_DIR", join(other, ".git")],
      ["GIT_INDEX_FILE", join(other, ".git", "index")],
      ["GIT_WORK_TREE", other],
    ]) {
      process.env[name] = value;
      try {
        assert.deepEqual(gitState(repo), { commit: head, dirty: false }, name);
      } finally {
        delete process.env[name];
      }
    }
    assert.equal(existsSync(join(other, ".git", "index")), false);
  });

  test("by default it reads this checkout, wherever it is run from", () => {
    const own = execFileSync("git", ["-C", ROOT, "rev-parse", "HEAD"], { encoding: "utf8" }).trim();
    // From inside another repository, so a path relative to the working
    // directory would read that one's commit instead.
    const elsewhere = fresh();
    const git = (...args) =>
      execFileSync("git", ["-C", elsewhere, "-c", "user.name=Kit test", "-c", "user.email=kit@example.invalid", "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null", ...args], { stdio: "ignore" });
    git("init", "-q");
    git("commit", "-q", "--allow-empty", "-m", "elsewhere");
    const cwd = process.cwd();
    process.chdir(elsewhere);
    try {
      const state = defaults().git();
      assert.equal(state.commit, own);
      assert.equal(typeof state.dirty, "boolean");
    } finally {
      process.chdir(cwd);
    }
  });
});

describe("arguments", () => {
  test("each command takes only its own flags, each once", () => {
    assert.deepEqual(parseArgs(["seal", "--tag", TAG]), { command: "seal", opts: { tag: TAG } });
    assert.throws(() => parseArgs(["assemble", "--tag", TAG, "--xpi", "f.xpi"]), /assemble: unknown flag --xpi/);
    assert.throws(() => parseArgs(["seal", "--tag", TAG, "--chromium", "dev"]), /seal: unknown flag --chromium/);
    assert.throws(() => parseArgs(["firefox", "--firefox-xpi", "f.xpi"]), /firefox: unknown flag --firefox-xpi/);
    assert.throws(() => parseArgs(["assemble", "--tag", TAG, "--tag", "v1.0.0"]), /assemble: --tag given twice/);
    assert.throws(() => parseArgs(["seal", "--out", "--tag", TAG]), /seal: --out needs a value/);
    assert.throws(() => parseArgs(["seal", "--tag"]), /seal: --tag needs a value/);
    assert.throws(() => parseArgs(["seal", "v0.9.0"]), /seal: unexpected argument v0\.9\.0/);
    assert.deepEqual(parseArgs(["publish"]), { command: "publish", opts: null });
  });
});

describe("readers", () => {
  test("zip and tar round trips", () => {
    assert.equal(readZip(zip({ "a/b.txt": "hi" })).get("a/b.txt").toString(), "hi");
    assert.deepEqual([...listTarGz(tarGz({ "x/y": 0o755 })).keys()], ["x/y"]);
    assert.deepEqual([...listTarGz(tarGz({ "x/y": 0o755, "x/z": 0o777 }, { "x/z": "2" })).keys()], ["x/y"]);
  });

  test("a damaged zip is the kit's error, not a crash", () => {
    const bad = [
      zip({ "a.js": Buffer.from([0xff, 0xff, 0xff]) }, { deflated: ["a.js"] }),
      zip([["a.js", "1"], ["a.js", "2"]]),
      zip({ "a.js": "hello" }).subarray(10),
      Buffer.from("not a zip"),
    ];
    for (const bytes of bad) assert.throws(() => readZip(bytes), KitError);
  });

  test("the appcast as appcast.sh writes it, and its signature block as Sparkle reads it", () => {
    const dmg = Buffer.from("dmg");
    const signedFeed = splitSignedFeed(appcast({ dmg }));
    assert.equal(signedFeed.length, signedFeed.content.length);
    assert.equal(signedFeed.signature, edSign(signedFeed.content));
    const feed = readAppcast(signedFeed.content.toString("utf8"));
    assert.equal(feed.items, 1);
    assert.equal(feed.length, 3);
    assert.equal(feed.version, "0.9.0");
    assert.equal(feed.edSignature, edSign(dmg));
    assert.match(feed.url, /\/releases\/download\/v0\.9\.0\/Klav\.dmg$/);
    assert.equal(splitSignedFeed(appcast({ dmg, signed: false })), null);
  });
});
