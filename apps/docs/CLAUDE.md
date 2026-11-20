# Klav's public docs site

Read these in this order; the first one wins where they disagree:

1. The repository's [`CLAUDE.md`](../../CLAUDE.md): its rules and workflow hold here too.
2. [ADR 0039](../../docs/decisiones/0039-public-docs-site.md): what this site is, what it publishes, how it stays in step with the code, and how it is upgraded.
3. [`AGENT.md`](./AGENT.md): Nimbus's own guide to how the framework works. It is third-party text that changes with upgrades; where it says something this file or ADR 0039 rules out, follow them.

What differs from the Nimbus starter:

- **Its own pnpm project.** The root workspace excludes `apps/docs`; install and run everything from this folder, with this folder's `pnpm-lock.yaml`. `pnpm-workspace.yaml` holds the supply-chain settings: never add `minimumReleaseAgeExclude`, and decline every build script.
- **Exact pins.** Every direct dependency is pinned exact; an upgrade follows ADR 0039 §2, one PR per Nimbus minor version, never mixed with content.
- **One static share card.** `public/og.png`, drawn from `tools/og.html` (the command is at its top). The generated cards (`src/pages/og/`, `satori`, `@resvg/resvg-js`) are gone, so ignore `AGENT.md`'s line about `src/pages/og/_card.ts`.
- **Closed to crawlers** until the repository is public: `src/pages/robots.txt.ts`.
- **Starter files edited by hand** (an upgrade merges these by hand instead of taking `nimbus-docs diff --apply`): `astro.config.ts`, `package.json`, `pnpm-workspace.yaml`, `wrangler.jsonc`, `src/pages/[...slug].astro` (the share card fallback), `src/pages/robots.txt.ts`, `src/components/Header.astro` and `src/layouts/DocsLayout.astro` (the wordmark), `src/components/Logo.astro` and `src/components/logo.ts` (Klav's key), `public/favicon.svg` and `public/favicon.ico`, and `src/layouts/BaseLayout.astro` (one import of `src/styles/klav.css`), `public/_headers` (the `.mdx` content type, and one `/*` rule with the review period's `X-Robots-Tag: noindex`, the security headers and the CSP; `tools/check-csp.mjs` checks that rule and the CSP's script hashes), and `src/content/docs/`. Deleted: `src/pages/og/`, `src/pages/og.png.ts` and `src/content/partials/example.mdx`.
- **Our own CSS** lives in `src/styles/klav.css`, unlayered so it beats Tailwind's utilities: the previous/next links take the site's radius tokens instead of pills, their `[` `]` keycaps the sans face, and table headers wrap on a phone so a table fits its scroll box. Override starter components there instead of editing them.
- **Everything in a page file is public**, its `.mdx` source included, comments too. Write for two readers, a person and an agent reading the `.md` version, as ADR 0039 §3 says.
- **No telemetry.** The scripts set `ASTRO_TELEMETRY_DISABLED=1`; set it, and `WRANGLER_SEND_METRICS=false`, in any shell that runs `astro` or `wrangler` directly.
- **Deploys go out from Omar's Mac only,** with the Cloudflare session `wrangler` keeps there. Since 2026-11-12 the agent working in Omar's own session redeploys after a merge to `main` that changes the site, and runs the checks under "Después de cada despliegue" in [`docs/sitio-web.md`](../../docs/sitio-web.md) §7. Anywhere else (a contributor's machine, CI, a sandbox), never deploy and never sign in to Cloudflare. The site's `workers.dev` address and the account's identifiers stay out of the repository.

Before calling a change done, run what the `docs` CI task runs, from this folder:

```sh
pnpm install --frozen-lockfile
pnpm audit --audit-level low
pnpm exec nimbus-docs check
pnpm exec astro check
pnpm build
pnpm run check:csp
pnpm exec nimbus-docs lint
```

Then look at the rendered pages and their `.md` versions.
