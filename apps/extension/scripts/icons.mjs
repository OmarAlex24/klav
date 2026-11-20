// Draws Klav's toolbar icons (static/icons/{16,32,48,128}.png) from the
// pixel key of src/shared/glyph.ts: the key in paper on an ink square, at
// a whole number of pixels per cell so it stays sharp. Run when the glyph
// changes: node scripts/icons.mjs
//
// Also the 300×300 logo Edge Add-ons asks for (store/images/logo-300.png,
// docs/publicar-extension.md §4): the same key, 26 px per cell.
import { writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { deflateSync } from "node:zlib";
import * as esbuild from "esbuild";

const app = join(dirname(fileURLToPath(import.meta.url)), "..");

// Load glyph.ts without a browser: bundle it to an ES module in memory.
const bundle = await esbuild.build({
  entryPoints: [join(app, "src", "shared", "glyph.ts")],
  bundle: true,
  format: "esm",
  write: false,
});
const { keyCells } = await import(`data:text/javascript;base64,${Buffer.from(bundle.outputFiles[0].text).toString("base64")}`);

const INK = [9, 9, 11];
const PAPER = [255, 255, 255];

/** Size → pixels per cell. The key is 8×5 cells (rows 1…5 of its grid). */
const CELL = { 16: 1, 32: 3, 48: 4, 128: 11 };

export function render(size, cell = CELL[size]) {
  const px = new Uint8Array(size * size * 4);
  const set = (x, y, [r, g, b]) => {
    const o = (y * size + x) * 4;
    px[o] = r;
    px[o + 1] = g;
    px[o + 2] = b;
    px[o + 3] = 255;
  };
  for (let y = 0; y < size; y++) for (let x = 0; x < size; x++) set(x, y, INK);
  const ox = Math.floor((size - 8 * cell) / 2);
  const oy = Math.floor((size - 5 * cell) / 2);
  for (const [cx, cy] of keyCells()) {
    for (let y = 0; y < cell; y++) {
      for (let x = 0; x < cell; x++) set(ox + cx * cell + x, oy + (cy - 1) * cell + y, PAPER);
    }
  }
  return png(size, size, px);
}

// ------------------------------------------------------------ tiny PNG --
const CRC = new Int32Array(256).map((_, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c;
});
function crc32(buf) {
  let c = -1;
  for (const b of buf) c = CRC[(c ^ b) & 255] ^ (c >>> 8);
  return (c ^ -1) >>> 0;
}
function chunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length);
  const body = Buffer.concat([Buffer.from(type), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(body));
  return Buffer.concat([len, body, crc]);
}
function png(width, height, rgba) {
  const header = Buffer.alloc(13);
  header.writeUInt32BE(width, 0);
  header.writeUInt32BE(height, 4);
  header[8] = 8; // bit depth
  header[9] = 6; // RGBA
  const raw = Buffer.alloc((width * 4 + 1) * height);
  for (let y = 0; y < height; y++) {
    raw[y * (width * 4 + 1)] = 0;
    Buffer.from(rgba.buffer, y * width * 4, width * 4).copy(raw, y * (width * 4 + 1) + 1);
  }
  return Buffer.concat([
    Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]),
    chunk("IHDR", header),
    chunk("IDAT", deflateSync(raw)),
    chunk("IEND", Buffer.alloc(0)),
  ]);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  for (const size of [16, 32, 48, 128]) {
    writeFileSync(join(app, "static", "icons", `${size}.png`), render(size));
  }
  writeFileSync(join(app, "store", "images", "logo-300.png"), render(300, 26));
  console.log("icons written");
}
