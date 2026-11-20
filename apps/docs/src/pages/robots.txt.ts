import { withBase } from "@cloudflare/nimbus-docs/runtime";
import { config } from "virtual:nimbus/config";

export const prerender = true;

// Open to crawlers (ADR 0039 §5, Q5 and Q6): Nimbus's default robots.txt with
// the Content Signals Omar chose. Flipping this to false also requires
// `X-Robots-Tag: noindex` in the /* rule of public/_headers (enforced by
// tools/check-csp.mjs).
const OPEN_TO_CRAWLERS = true;

export function GET() {
  const body = OPEN_TO_CRAWLERS
    ? [
        "User-agent: *",
        // Content Signals (https://contentsignals.org). If any signal becomes
        // "no", paste the policy text from that site above this block so the
        // restriction is an express reservation.
        "Content-Signal: ai-train=yes, search=yes, ai-input=yes",
        "Allow: /",
        "",
        `Sitemap: ${new URL(withBase("/sitemap-index.xml", import.meta.env.BASE_URL), config.site).href}`,
        "",
      ]
    : ["User-agent: *", "Disallow: /", ""];

  return new Response(body.join("\n"), {
    headers: { "Content-Type": "text/plain; charset=utf-8" },
  });
}
