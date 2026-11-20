#!/usr/bin/env node
// Builds assets/site-icons/site-icons.json: the monochrome logos of common
// sites (Simple Icons, CC0 1.0 or no license data, see below) that the
// extension and the iOS app draw next to an item, so neither ever asks a
// third-party icon service which sites a
// person uses. The input is assets/site-icons/sites.txt (one line per icon:
// its Simple Icons slug and the domains it stands for).
//
//   node scripts/site-icons.mjs
//
// It downloads the pinned simple-icons package from the npm registry,
// checks its integrity, and rewrites each path with absolute M, L, C, Q and
// Z commands only (arcs become cubic curves), rounded to two decimals, so
// the iOS app needs no SVG parser beyond those five commands.
//
// Simple Icons is CC0, but some icons carry another license in the `license`
// field of data/simple-icons.json. The script ships only icons whose entry
// has no `license` or says CC0-1.0, and stops naming any other.
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const VERSION = "16.36.0";
const INTEGRITY = "sha512-+VNPPkqSOLidFeSgBKUWX4n50WPpDC09hav+BgS26anIF1oQOlGBb8LvwGR+6fYRjo+B6CiKzNBceMPkSVXANQ==";
const TARBALL = `https://registry.npmjs.org/simple-icons/-/simple-icons-${VERSION}.tgz`;

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const dir = join(root, "assets", "site-icons");

async function download() {
  const res = await fetch(TARBALL);
  if (!res.ok) throw new Error(`${TARBALL}: HTTP ${res.status}`);
  const bytes = Buffer.from(await res.arrayBuffer());
  const got = `sha512-${createHash("sha512").update(bytes).digest("base64")}`;
  if (got !== INTEGRITY) throw new Error(`simple-icons ${VERSION}: integrity ${got}, expected ${INTEGRITY}`);
  return bytes;
}

// ----------------------------------------------------------- license --

/**
 * Why the icon `slug` may not ship, or undefined if it may. `entry` is its
 * object in data/simple-icons.json. Only an entry without `license`, or with
 * `license.type` "CC0-1.0", ships: any other license, or a shape this script
 * doesn't know, is refused.
 */
export function licenseProblem(slug, entry) {
  if (entry === undefined) return `${slug}: not in data/simple-icons.json`;
  const license = entry.license;
  if (license === undefined) return undefined;
  if (license !== null && typeof license === "object" && license.type === "CC0-1.0") return undefined;
  const name = license !== null && typeof license === "object" && typeof license.type === "string" ? license.type : JSON.stringify(license);
  return `${slug} (${entry.title}): license ${name}, not CC0-1.0`;
}

// ------------------------------------------------------------- paths --

/**
 * Splits an SVG path into commands and numbers. An arc's two flags are one
 * character each and may touch what follows ("a1 1 0 00-.7 1" has flags 0
 * and 0), so they are read by position.
 */
function tokens(d) {
  const out = [];
  const number = /^[\s,]*(-?(?:\d+\.?\d*|\.\d+)(?:[eE][-+]?\d+)?)/;
  const flag = /^[\s,]*([01])/;
  let rest = d;
  let cmd = "";
  let index = 0; // position within the current command's parameters
  for (;;) {
    rest = rest.replace(/^[\s,]+/, "");
    if (rest === "") return out;
    const c = /^[MmLlHhVvCcSsQqTtAaZz]/.exec(rest);
    if (c) {
      cmd = c[0].toUpperCase();
      index = 0;
      out.push(c[0]);
      rest = rest.slice(1);
      continue;
    }
    const isFlag = cmd === "A" && (index % 7 === 3 || index % 7 === 4);
    const m = (isFlag ? flag : number).exec(rest);
    if (!m) throw new Error(`cannot read path at "${rest.slice(0, 20)}"`);
    out.push(Number(m[1]));
    rest = rest.slice(m[0].length);
    index++;
  }
}

const ARITY = { M: 2, L: 2, H: 1, V: 1, C: 6, S: 4, Q: 4, T: 2, A: 7, Z: 0 };

/** Arc endpoint parametrisation → cubic Béziers (SVG 1.1 implementation notes, F.6). */
function arcToCubics(x1, y1, rx, ry, phi, large, sweep, x2, y2) {
  if (rx === 0 || ry === 0) return [[x1, y1, x2, y2, x2, y2]];
  const sin = Math.sin((phi * Math.PI) / 180);
  const cos = Math.cos((phi * Math.PI) / 180);
  const dx = (x1 - x2) / 2;
  const dy = (y1 - y2) / 2;
  const xp = cos * dx + sin * dy;
  const yp = -sin * dx + cos * dy;
  rx = Math.abs(rx);
  ry = Math.abs(ry);
  const lambda = (xp * xp) / (rx * rx) + (yp * yp) / (ry * ry);
  if (lambda > 1) {
    rx *= Math.sqrt(lambda);
    ry *= Math.sqrt(lambda);
  }
  const num = rx * rx * ry * ry - rx * rx * yp * yp - ry * ry * xp * xp;
  const den = rx * rx * yp * yp + ry * ry * xp * xp;
  let k = Math.sqrt(Math.max(0, num / den));
  if (large === sweep) k = -k;
  const cxp = (k * rx * yp) / ry;
  const cyp = (-k * ry * xp) / rx;
  const cx = cos * cxp - sin * cyp + (x1 + x2) / 2;
  const cy = sin * cxp + cos * cyp + (y1 + y2) / 2;
  const angle = (ux, uy, vx, vy) => {
    const a = Math.atan2(ux * vy - uy * vx, ux * vx + uy * vy);
    return a;
  };
  const t1 = angle(1, 0, (xp - cxp) / rx, (yp - cyp) / ry);
  let dt = angle((xp - cxp) / rx, (yp - cyp) / ry, (-xp - cxp) / rx, (-yp - cyp) / ry);
  if (!sweep && dt > 0) dt -= 2 * Math.PI;
  if (sweep && dt < 0) dt += 2 * Math.PI;
  const segments = Math.ceil(Math.abs(dt) / (Math.PI / 2));
  const step = dt / segments;
  const alpha = (4 / 3) * Math.tan(step / 4);
  const point = (t) => {
    const ex = rx * Math.cos(t);
    const ey = ry * Math.sin(t);
    return [cos * ex - sin * ey + cx, sin * ex + cos * ey + cy];
  };
  const deriv = (t) => {
    const ex = -rx * Math.sin(t);
    const ey = ry * Math.cos(t);
    return [cos * ex - sin * ey, sin * ex + cos * ey];
  };
  const out = [];
  for (let i = 0; i < segments; i++) {
    const a = t1 + i * step;
    const b = a + step;
    const [ax, ay] = point(a);
    const [bx, by] = point(b);
    const [dax, day] = deriv(a);
    const [dbx, dby] = deriv(b);
    out.push([ax + alpha * dax, ay + alpha * day, bx - alpha * dbx, by - alpha * dby, bx, by]);
  }
  // The last point is exactly the arc's end, not a rounding of it.
  out[out.length - 1][4] = x2;
  out[out.length - 1][5] = y2;
  return out;
}

/** Rewrites `d` with absolute M, L, C, Q and Z only. */
export function normalize(d) {
  const t = tokens(d);
  const out = [];
  let i = 0;
  let cmd = "";
  let x = 0;
  let y = 0;
  let sx = 0;
  let sy = 0;
  let lastC; // last cubic control point, for S
  let lastQ; // last quadratic control point, for T
  while (i < t.length) {
    if (typeof t[i] === "string") cmd = t[i++];
    else if (!cmd) throw new Error(`path starts with a number: ${d.slice(0, 30)}`);
    const up = cmd.toUpperCase();
    const rel = cmd !== up;
    if (up === "Z") {
      out.push(["Z"]);
      x = sx;
      y = sy;
      lastC = lastQ = undefined;
      continue;
    }
    const n = t.slice(i, i + ARITY[up]);
    if (n.length < ARITY[up] || n.some((v) => typeof v !== "number")) throw new Error(`bad ${cmd} in ${d.slice(0, 30)}`);
    i += ARITY[up];
    const ox = rel ? x : 0;
    const oy = rel ? y : 0;
    let nextC;
    let nextQ;
    switch (up) {
      case "M":
        x = n[0] + ox;
        y = n[1] + oy;
        sx = x;
        sy = y;
        out.push(["M", x, y]);
        // Numbers after a moveto are linetos.
        cmd = rel ? "l" : "L";
        break;
      case "L":
        x = n[0] + ox;
        y = n[1] + oy;
        out.push(["L", x, y]);
        break;
      case "H":
        x = n[0] + ox;
        out.push(["L", x, y]);
        break;
      case "V":
        y = n[0] + oy;
        out.push(["L", x, y]);
        break;
      case "C": {
        const c = [n[0] + ox, n[1] + oy, n[2] + ox, n[3] + oy, n[4] + ox, n[5] + oy];
        out.push(["C", ...c]);
        nextC = [c[2], c[3]];
        x = c[4];
        y = c[5];
        break;
      }
      case "S": {
        const c1 = lastC ? [2 * x - lastC[0], 2 * y - lastC[1]] : [x, y];
        const c = [...c1, n[0] + ox, n[1] + oy, n[2] + ox, n[3] + oy];
        out.push(["C", ...c]);
        nextC = [c[2], c[3]];
        x = c[4];
        y = c[5];
        break;
      }
      case "Q": {
        const c = [n[0] + ox, n[1] + oy, n[2] + ox, n[3] + oy];
        out.push(["Q", ...c]);
        nextQ = [c[0], c[1]];
        x = c[2];
        y = c[3];
        break;
      }
      case "T": {
        const c1 = lastQ ? [2 * x - lastQ[0], 2 * y - lastQ[1]] : [x, y];
        const c = [...c1, n[0] + ox, n[1] + oy];
        out.push(["Q", ...c]);
        nextQ = c1;
        x = c[2];
        y = c[3];
        break;
      }
      case "A": {
        const ex = n[5] + ox;
        const ey = n[6] + oy;
        for (const c of arcToCubics(x, y, n[0], n[1], n[2], n[3] !== 0, n[4] !== 0, ex, ey)) out.push(["C", ...c]);
        x = ex;
        y = ey;
        break;
      }
    }
    lastC = nextC;
    lastQ = nextQ;
  }
  return out;
}

/** 12.30 → "12.3", -0.50 → "-.5": the shortest exact form at two decimals. */
function num(v) {
  const r = Math.round(v * 100) / 100;
  const s = (Object.is(r, -0) ? 0 : r).toString();
  return s.replace(/^(-?)0\./, "$1.");
}

/** Writes commands back as compact text: "M1 2L3 4C…Z". */
export function serialize(cmds) {
  let s = "";
  for (const [c, ...v] of cmds) {
    s += c;
    let prev = "";
    for (const n of v) {
      const text = num(n);
      // A sign or a leading dot (after a number with a dot) separates by itself.
      if (prev !== "" && !text.startsWith("-") && !(text.startsWith(".") && prev.includes("."))) s += " ";
      s += text;
      prev = text;
    }
  }
  return s;
}

// -------------------------------------------------------------- main --

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const work = mkdtempSync(join(tmpdir(), "klav-site-icons-"));
  try {
    writeFileSync(join(work, "simple-icons.tgz"), await download());
    execFileSync("tar", ["-xzf", "simple-icons.tgz", "package/data/simple-icons.json", "package/icons"], { cwd: work });
    const data = JSON.parse(readFileSync(join(work, "package", "data", "simple-icons.json"), "utf8"));
    const entries = new Map();
    for (const icon of data) entries.set(icon.slug ?? "", icon);
    const icons = [];
    const seen = new Map();
    const refused = [];
    for (const line of readFileSync(join(dir, "sites.txt"), "utf8").split("\n")) {
      const clean = line.replace(/#.*/, "").trim();
      if (!clean) continue;
      const [slug, ...domains] = clean.split(/\s+/);
      if (domains.length === 0) throw new Error(`sites.txt: ${slug} has no domain`);
      const problem = licenseProblem(slug, entries.get(slug));
      if (problem) {
        refused.push(problem);
        continue;
      }
      let svg;
      try {
        svg = readFileSync(join(work, "package", "icons", `${slug}.svg`), "utf8");
      } catch {
        throw new Error(`sites.txt: simple-icons ${VERSION} has no icon "${slug}"`);
      }
      for (const domain of domains) {
        if (!/^[a-z0-9.-]+\.[a-z]{2,}$/.test(domain)) throw new Error(`sites.txt: bad domain ${domain}`);
        if (seen.has(domain)) throw new Error(`sites.txt: ${domain} is listed for ${seen.get(domain)} and ${slug}`);
        seen.set(domain, slug);
      }
      const d = /<path d="([^"]+)"/.exec(svg)?.[1];
      if (!d || !svg.includes('viewBox="0 0 24 24"')) throw new Error(`${slug}: unexpected SVG`);
      icons.push({ slug, title: entries.get(slug)?.title ?? /<title>([^<]+)<\/title>/.exec(svg)?.[1] ?? slug, domains, path: serialize(normalize(d)) });
    }
    if (refused.length > 0) {
      throw new Error(`sites.txt: simple-icons ${VERSION} licenses these icons other than CC0-1.0; remove them:\n  ${refused.join("\n  ")}`);
    }
    icons.sort((a, b) => a.slug.localeCompare(b.slug));
    const out = {
      source: `simple-icons ${VERSION} (CC0-1.0, https://simpleicons.org)`,
      viewBox: 24,
      icons,
    };
    writeFileSync(join(dir, "site-icons.json"), JSON.stringify(out) + "\n");
    const bytes = Buffer.byteLength(JSON.stringify(out));
    console.log(`${icons.length} icons, ${seen.size} domains, ${(bytes / 1024).toFixed(0)} KiB → assets/site-icons/site-icons.json`);
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
}
