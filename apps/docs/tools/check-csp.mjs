// Checks the built site against the headers in dist/_headers:
// - there is exactly one /* rule (a second one replaces the first, and the
//   headers in it are no longer served), and it holds the
//   Content-Security-Policy;
// - while dist/robots.txt disallows every crawler, that rule also holds
//   `X-Robots-Tag: noindex` (the opening-day change removes both together);
// - every inline <script> the browser runs (including import maps and
//   speculation rules) has its sha256 listed in script-src, every listed hash
//   still matches an inline script, and script-src has no 'unsafe-inline';
// - no page carries an inline event handler (onclick="…") or a javascript:
//   URL, which the policy blocks.
// Run after `pnpm build`, from apps/docs: `node tools/check-csp.mjs`.
// No dependencies, so it runs anywhere the build does (CI and predeploy).
import { createHash } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

const dist = "dist";
const lines = readFileSync(join(dist, "_headers"), "utf8").split("\n").map((line) => line.trim());
const starts = lines.flatMap((line, i) => (line === "/*" ? [i] : []));
if (starts.length !== 1) {
  console.error(`check-csp: dist/_headers has ${starts.length} /* rules; a second one replaces the first, so keep exactly one`);
  process.exit(1);
}
const block = [];
for (const line of lines.slice(starts[0] + 1)) {
  if (line.startsWith("/")) break;
  block.push(line);
}
const policy = block.find((line) => line.startsWith("Content-Security-Policy:"));
if (!policy) {
  console.error("check-csp: no Content-Security-Policy in the /* rule of dist/_headers");
  process.exit(1);
}
// robots.txt closed to everyone means the review period: the noindex header
// must be served too. Once robots.txt opens, the header may go.
const robots = readFileSync(join(dist, "robots.txt"), "utf8");
const closed = /^user-agent:\s*\*\s*$/im.test(robots) && /^disallow:\s*\/\s*$/im.test(robots);
if (closed && !block.some((line) => /^X-Robots-Tag:\s*noindex$/i.test(line))) {
  console.error("check-csp: robots.txt disallows every crawler, but the /* rule of dist/_headers has no X-Robots-Tag: noindex");
  process.exit(1);
}
const scriptSrc = policy.split(";").find((d) => d.trim().startsWith("script-src")) ?? "";
const listed = new Set(scriptSrc.match(/'sha256-[A-Za-z0-9+/=]+'/g) ?? []);
if (/'unsafe-inline'/.test(scriptSrc)) {
  console.error("check-csp: script-src must not allow 'unsafe-inline'");
  process.exit(1);
}

function* htmlFiles(dir) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) yield* htmlFiles(path);
    else if (entry.name.endsWith(".html")) yield path;
  }
}

// Script types the browser runs; anything else (ld+json, a JSON island) is data.
const runs = (type) => !type || /^(text\/javascript|module|application\/javascript|importmap|speculationrules)$/i.test(type);
const missing = new Map();
const used = new Set();
const blocked = [];
let pages = 0;
for (const file of htmlFiles(dist)) {
  pages += 1;
  const html = readFileSync(file, "utf8");
  for (const [, attrs, body] of html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)) {
    if (/\ssrc=/i.test(attrs)) continue;
    if (!runs(attrs.match(/\stype=["']?([^"'\s>]*)/i)?.[1])) continue;
    const hash = `'sha256-${createHash("sha256").update(body, "utf8").digest("base64")}'`;
    if (listed.has(hash)) used.add(hash);
    else missing.set(hash, file);
  }
  for (const [match] of html.matchAll(/<[^>]+\son[a-z]+=["'][^>]*>/gi)) blocked.push(`${file}: ${match.slice(0, 80)}`);
  for (const [match] of html.matchAll(/(?:href|src|action)=["']\s*javascript:/gi)) blocked.push(`${file}: ${match}`);
}

if (pages === 0) {
  console.error("check-csp: no HTML in dist/");
  process.exit(1);
}
const stale = [...listed].filter((hash) => !used.has(hash));
let failed = false;
if (missing.size > 0) {
  failed = true;
  console.error("check-csp: inline scripts whose hash isn't in public/_headers' script-src:");
  for (const [hash, file] of missing) console.error(`  ${hash} (first in ${file})`);
}
if (stale.length > 0) {
  failed = true;
  console.error("check-csp: hashes in script-src that no inline script matches any more (remove them):");
  for (const hash of stale) console.error(`  ${hash}`);
}
if (blocked.length > 0) {
  failed = true;
  console.error("check-csp: inline handlers or javascript: URLs, which the policy blocks:");
  for (const line of blocked.slice(0, 20)) console.error(`  ${line}`);
}
if (failed) process.exit(1);
console.log(`check-csp: ${pages} pages, ${used.size} inline script hashes, all listed`);
