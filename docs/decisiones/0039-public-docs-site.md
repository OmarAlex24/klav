# 0039 · Public docs site: Nimbus in `apps/docs`, static and in English, with what works today and an "On the way" section

- Status: accepted (Omar accepted it on 2026-11-10 with option (a) for each of Q1–Q6; see "Omar's answers"). Amended on 2026-11-13; Omar accepted the amendment that day
- Date: 2026-11-10

## Context

### What Omar decided on 2026-11-10
Klav gets a public documentation site. Omar chose:

- **Framework:** Nimbus (<https://nimbus-docs.com/>, repository `cloudflare/nimbus`, npm `@cloudflare/nimbus-docs`, scaffolder `@cloudflare/create-nimbus-docs`), with the version pinned exact.
- **Language:** English only, like the rest of the repository ([ADR 0031](0031-repositorio-en-ingles-y-open-source.md)).
- **Content of the first version:** what works today, plus a separate, clearly marked section for what has an accepted ADR and is not finished: sandboxes with an ephemeral credential ([ADR 0036](0036-sandboxes-de-agentes.md), code in progress), deployed services behind a credential proxy ([ADR 0038](0038-deployed-services.md)) and environments instead of `.env` files ([ADR 0032](0032-entornos-por-repositorio.md)). It explains the idea and gives no dates.

### What exists today
- **`apps/web`** is the page at `klav.dev` with the hosted plan's waitlist ([sitio-web.md](../sitio-web.md)). It has no npm dependencies on purpose: one HTML file, a `node:http` and `node:sqlite` server, and a Docker image for Railway. Its tests run inside the `extension` CI task. The page is in English and Spanish, and it marks what is not built yet as "Coming soon", with no dates (§6 of that doc).
- **The pnpm workspace** (`pnpm-workspace.yaml`) holds `apps/*` and `packages/*`: today `apps/extension` (`@klav/extension`) and `packages/sdk`. The root `pnpm-lock.yaml` has 3,263 lines. It allows no install scripts: `allowBuilds: esbuild: false`.
- **The internal docs** are long, design-level, and mostly in Spanish: [cli.md](../cli.md) (1,683 lines), [extension.md](../extension.md) (1,363), [api.md](../api.md) (1,100), [ios.md](../ios.md) (1,070), [especificacion-cripto.md](../especificacion-cripto.md) (911), [klavd.md](../klavd.md) (806), [self-hosting.md](../self-hosting.md) (690), [modelo-de-amenazas.md](../modelo-de-amenazas.md) (457), [macos.md](../macos.md) (446). Each mixes how to use a part with how it is built, signed and tested. `skill/SKILL.md`, `SECURITY.md` and `CONTRIBUTING.md` are already in English. `README.md` has 21 lines.
- **`docs/features.md`**, the feature map, is being written by another agent now. It gives each feature one of three statuses: works today, accepted and not built, or idea. It is not on `main` yet (checked on 2026-11-10).
- **The repository was private** (`gh repo view`, 2026-11-10). `klav.dev` uses Cloudflare's name servers (`dig NS klav.dev`: `kelly.ns.cloudflare.com`, `trevor.ns.cloudflare.com`). The default server is `api.klav.dev` on Railway ([ADR 0028](0028-servidor-por-defecto-klav-dev.md)).

### Why this needs an ADR
A docs site brings to the repository:

- the first dependency tree for a website (`apps/web` has none);
- a build step;
- a CI task;
- a hosting decision.

### What I verified about Nimbus (2026-11-10)
Each claim below comes from Nimbus's own docs, its npm metadata, or running it. Where they disagree, both are given.

| Topic | What I found | Source |
|---|---|---|
| Versions | `@cloudflare/nimbus-docs` 0.19.4, published 2026-11-06. `@cloudflare/create-nimbus-docs` 0.8.3, published 2026-11-05. Both MIT, from `github.com/cloudflare/nimbus`, published by Cloudflare's CI accounts with npm provenance attestations | `registry.npmjs.org/@cloudflare/nimbus-docs` and `/@cloudflare/create-nimbus-docs` |
| Stability | "Pre-1.0. The public API can change between minor releases. Pin your versions and read each package's changelog … before upgrading." Seven minor releases in two months: 0.13.0 on 2026-09-06 to 0.19.4 on 2026-11-06 | [README](https://github.com/cloudflare/nimbus/blob/main/README.md), [changelog](https://nimbus-docs.com/changelog/llms.txt) |
| Node | `engines.node` is `>=22.12.0`, and the quickstart says "Node 22.12 or later". The README says "Requires Node.js 22.23.4 or later". They disagree; this ADR follows the stricter one | npm metadata, [quickstart](https://nimbus-docs.com/quickstart/), README |
| Astro | Peer `astro >=7.2.6 <8.0.0`. The 0.8.3 starter pins `astro` 7.3.3 | npm metadata, the scaffolded `package.json` |
| Output | Static by default, "any host that serves files can run it". Request rendering, the remote MCP server and Markdown at page URLs need a server adapter: Cloudflare, Netlify, Node or Vercel | [Deploy to other hosts](https://nimbus-docs.com/deploy/other-hosts/), [Deploy to Cloudflare](https://nimbus-docs.com/deploy/cloudflare/) |
| Cloudflare | The scaffolder's default target is Cloudflare Workers with Workers Static Assets (`wrangler.jsonc`, a `deploy` script). A static site needs no adapter. The pages describe Workers, not Cloudflare Pages | [Deploy to Cloudflare](https://nimbus-docs.com/deploy/cloudflare/) |
| Content | MDX under `src/content/docs/`. "The directory structure under `src/content/docs/` is the URL structure **and** the sidebar." A page collection's files "can live anywhere", including "a folder outside `src/`, such as a shared folder in a monorepo" | [Project structure](https://nimbus-docs.com/project-structure/), [Collections](https://nimbus-docs.com/writing/collections/) |
| Files for agents | Every site publishes `/<slug>/index.md` (clean Markdown), `/<slug>/index.mdx` (the authored source), `/llms.txt`, one `llms.txt` per section and `/llms-full.txt`. Discovery files: `/.well-known/ard.json` and `/.well-known/ai-catalog.json`, a homepage `Link` header (on hosts that read `_headers`), and `/robots.txt` with `Content-Signal: ai-train=yes, search=yes, ai-input=yes` by default. A `skills/` folder is published at `/.well-known/agent-skills/`. `agents.discovery: false` turns the discovery files off "when another site owns the domain" | [Markdown and llms.txt](https://nimbus-docs.com/ai/publish-markdown/), [Agent discovery](https://nimbus-docs.com/ai/agent-discovery/), [Agent Skills](https://nimbus-docs.com/ai/agent-skills/) |
| Remote MCP server | `agents: { mcp: true }` serves `/mcp` with two tools, `list_pages` and `get_page`, and "There is no search tool". It needs a server adapter and the optional `@modelcontextprotocol/server` package (about 140 KB gzipped). It is public, has no authentication, and "Rate limiting is the host's job" | [Remote MCP server](https://nimbus-docs.com/ai/remote-mcp/) |
| Search | Pagefind, indexed at build time and served as static files | [Search](https://nimbus-docs.com/navigation/search/) |
| `check` and `lint` | `nimbus-docs check` is "a build-free preflight" and exits `1` only on an error. It checks links only when an earlier build left `.nimbus/routes.json`. "To gate CI on links, run `astro build` and then `nimbus-docs lint`" with `nimbus/internal-link` on. Lint rules are "off by default" | [CLI](https://nimbus-docs.com/cli/), [Linting](https://nimbus-docs.com/writing/linting/) |
| Upgrades | `nimbus-docs migrate` lists the breaking changes between `lastReviewedNimbusVersion` in `nimbus.json` and the installed version. `outdated` and `diff` compare the starter files with their upstream `templates-v*` tag | [Upgrading](https://nimbus-docs.com/publish/upgrading/), [CLI](https://nimbus-docs.com/cli/) |
| Recipes | `nimbus-docs add <feature>` copies nothing: it prints "a markdown prompt the agent reads, adapts to your project, and applies" | [CLI](https://nimbus-docs.com/cli/) |
| Git dates | "Last updated" and the sitemap's dates need full history; a shallow clone leaves them out | [Metadata and SEO](https://nimbus-docs.com/publish/metadata-and-seo/) |
| i18n | **None found.** The docs index (<https://nimbus-docs.com/llms.txt>) has no i18n page. A search of the full text (<https://nimbus-docs.com/llms-full.txt>, 458,574 characters) for `i18n`, `locale`, `translat`, `multilingual` and `language` finds only code-sample languages, one component's `locale` prop and route examples under `[locale]`. Pagefind reported "Discovered 1 language: en" on the starter | The two files, and the build log |

### What I measured (2026-11-10, darwin-arm64, outside the repository)
I scaffolded in a new, empty directory next to the real `target/` on the external disk, with a private pnpm store, and deleted it all afterwards. Nothing ran from inside the repository.

```sh
pnpm dlx @cloudflare/create-nimbus-docs@0.8.3 site --yes --content starter \
  --deploy other --package-manager pnpm --no-git --skip-install
```

- **What it writes.** `astro.config.ts`, `nimbus.json`, `package.json`, `pnpm-workspace.yaml`, `tsconfig.json`, `public/`, `src/`, plus `AGENT.md` (13 KB of instructions for coding agents) and a `CLAUDE.md` that points to it. `nimbus.json` records `templatesTag: templates-v0.8.3` and `lastReviewedNimbusVersion: 0.19.3`.
- **Versions are not exact.** Every dependency gets a caret except `astro` 7.3.3 and `@astrojs/language-server` 2.16.13. `"@cloudflare/nimbus-docs": "^0.19.3"` resolved to 0.19.4. The direct dependencies resolved to:
  - `dependencies`: `@cloudflare/nimbus-docs` 0.19.4, `@fontsource-variable/inter` 5.3.0, `@fontsource-variable/jetbrains-mono` 5.3.0, `@iconify-json/ph` 1.2.2, `@resvg/resvg-js` 2.6.2, `astro` 7.3.3, `clsx` 2.1.1, `satori` 0.26.0, `sharp` 0.35.5, `tailwind-merge` 3.7.0;
  - `devDependencies`: `@astrojs/check` 0.9.12, `@astrojs/language-server` 2.16.13, `@tailwindcss/vite` 4.3.5, `pagefind` 1.6.0, `tailwindcss` 4.3.5, `typescript` 5.9.3.
- **Size of the tree.**
  - The lockfile lists 551 package versions (518 names); 138 of them are platform-specific binaries, of which a machine installs only its own.
  - On this Mac, 430 packages installed, 321 MB in `node_modules`, 627 MB in the store, in 11 s.
  - With `--deploy cloudflare`, the starter adds `wrangler` and its `deploy` scripts: 578 package versions.
  - CI runs on Linux x64, so its counts differ slightly.
- **Install scripts.** Only `esbuild` declares one (`postinstall`). The starter's own `pnpm-workspace.yaml` turns off the build scripts of `esbuild` and `sharp` ("they ship prebuilds"), as the root workspace already does for `esbuild`. Native code arrives as prebuilt optional packages: Astro's compiler, `esbuild`, `sharp` and `libvips`, Pagefind, `resvg`, Rolldown, Tailwind's `oxide`, `lightningcss` and `satteri`.
- **Build.** `astro build`: 4.1 s for the three starter pages, 1.6 MB in `dist/`. `nimbus-docs check`: exit 0 in 1.7 s, one warning (the placeholder `site`). `astro check`: 0 errors. `nimbus-docs lint`: clean.
- **What the output loads.** Nothing from other origins: the fonts are bundled, and the only absolute URLs in the HTML and JS are the placeholder site, XML namespaces, one `github.com` link and `schema.org`. It does carry two inline `<script>` elements (one theme script, one JSON-LD) and `style="…"` attributes, so a strict CSP like `apps/web`'s needs hashes.
- **`pnpm audit`.** One moderate advisory: `satori` [GHSA-wx4j-mvgx-mqwp](https://github.com/advisories/GHSA-wx4j-mvgx-mqwp) (CVE-2026-94545), "Satori-generated SVG has improper escaping", affected `< 0.33.5`. Nimbus's peer range is `satori >=0.26.0 <0.27.0`, so no fixed version fits. Satori and `@resvg/resvg-js` only draw the generated share cards, at build time, from the page titles. Both are optional peers of Nimbus.
- **Without generated share cards** (a second, fresh scaffold with `--content empty --deploy cloudflare`):
  - I removed `satori` and `@resvg/resvg-js` from `package.json` and deleted the card routes (`src/pages/og/` and `src/pages/og.png.ts`).
  - A fresh resolve has no `satori` package: 544 package versions instead of 578, and `pnpm audit` finds nothing.
  - Pages still point `og:image` at their generated card, because the page route falls back to it. I changed one line in `src/pages/[...slug].astro` (`entry.data.socialImage ?? "/og.png"`) and set `socialImage: "/og.png"` in `astro.config.ts`. Then every page used one static 1200 × 630 image, and the build and `check` passed.
  - (An earlier try that ran `pnpm remove` on a copy with its old lockfile kept `satori` in the tree. The fresh resolve is the one that counts.)
- **A 7-day release age today.** With `minimumReleaseAge: 10080` on 2026-11-10, the 0.8.3 starter's `"@cloudflare/nimbus-docs": "^0.19.3"` doesn't resolve: "`@cloudflare/nimbus-docs@0.19.3` was published at 2026-11-05T10:17:05.377Z, within the minimumReleaseAge cutoff" (`ERR_PNPM_NO_MATURE_MATCHING_VERSION`). Pinning 0.19.2 resolves, but the starter refuses it: "nimbus.json was reviewed with Nimbus 0.19.3, newer than installed Nimbus 0.19.2", and the build stops. Under the floor, the other direct dependencies resolved as listed above, except `tailwindcss` and `@tailwindcss/vite` at 4.3.4.
- **Astro telemetry.** `@astrojs/telemetry` 3.3.3 is in the tree and sends to `telemetry.astro.build`. It turns itself off in CI (`ci-info`) and when `ASTRO_TELEMETRY_DISABLED` is set (read in its `dist/index.js`).
- **Inside or beside the root workspace.** I tried both on a copy of the workspace manifests:
  - **Inside** (`apps/docs` matched by `apps/*`): the root lockfile grows from 3,263 to 7,473 lines, and five of the extension's resolved entries change. Their versions stay, but their peer sets gain `jiti` and `yaml`: `@eslint/js`, `addons-linter`, `eslint`, `typescript-eslint` and `vitest`.
  - **Beside** (`!apps/docs` in the root `pnpm-workspace.yaml`, and the site keeps its own `pnpm-workspace.yaml` and `pnpm-lock.yaml`): the root lockfile stays byte for byte the same, and `pnpm install --frozen-lockfile` and the build work inside `apps/docs`.

## Decision

### 1. Where it lives: `apps/docs`, its own pnpm project
- **`apps/docs`** holds the site, scaffolded with `@cloudflare/create-nimbus-docs` 0.8.3 (`--content empty --deploy cloudflare --package-manager pnpm --no-git`). The deploy target follows Q1.
- **Its own pnpm project, outside the root workspace** (recommended in Q2): the root `pnpm-workspace.yaml` adds `"!apps/docs"`, and `apps/docs` keeps its own `pnpm-workspace.yaml` and `pnpm-lock.yaml`. Reasons, from the measurement above:
  - the extension's lockfile entries don't move each time Nimbus moves, and a Nimbus upgrade PR touches only `apps/docs/`;
  - the starter's `pnpm-workspace.yaml` (build-script and architecture settings) stays where the starter writes it, and the supply-chain settings of §2 apply to the docs alone. Inside the root workspace I expect they would have to move to the root file; I did not test that;
  - a separate CI task can install it at the same time as the `extension` task, each into its own `node_modules` (§6). Two installs into one workspace at once may conflict; I did not test that either.
- **The cost:** two lockfiles and two `pnpm install` runs. Q2 also offers the other way, inside the root workspace with one lockfile, and what it costs.
- **Every direct dependency is pinned exact** (no `^` or `~`), at the newest version of each that is at least 7 days old when layer 1 runs (§2). That PR lists the versions.
  - The 0.8.3 starter needs `@cloudflare/nimbus-docs` 0.19.3 or later (measured), and 0.19.3 turns 7 days old on 2026-11-12 at 10:17 UTC. So layer 1 starts on or after that day, with 0.19.3, or 0.19.4 from 2026-11-13.
  - It doesn't use `minimumReleaseAgeExclude` to skip the wait.
- **`nimbus.json` stays committed.** `templatesTag` says which starter the files came from, and `lastReviewedNimbusVersion` matches the installed `@cloudflare/nimbus-docs` once `nimbus-docs migrate` has run.
- **The package is `@klav/docs`**, `private: true`, license Apache-2.0 like the rest of the apps ([ADR 0003](0003-licencias.md)), with `engines.node` `>=22.23.4`.
- **`AGENT.md` and `CLAUDE.md` from the starter.** `AGENT.md` stays: it is Nimbus's guide for agents working on the site, and `nimbus-docs outdated` compares it with upstream. `apps/docs/CLAUDE.md` is replaced by a short file in our words: the repository's `CLAUDE.md` comes first, then this ADR, then `AGENT.md` for how Nimbus works.

### 2. Supply chain
- **What the site is.** A static website built from MDX. It has no Rust, no `klav-wasm`, no calls to `klav-server` or `klavd`, no forms, no cookies and no analytics. It holds no secret and touches neither the vault nor any cryptography. The `CLAUDE.md` rules on crypto dependencies don't apply to it, and nothing in it may change that: a page that wants live data from Klav needs a new ADR.
- **What `cargo-deny` doesn't cover.** `deny.toml` checks the Rust graph only. For `apps/docs`, these take its place:
  - **Exact pins and a committed lockfile,** installed with `pnpm install --frozen-lockfile` in CI.
  - **No install scripts.** `allowBuilds` names only packages set to `false` (today `esbuild` and `sharp`). `strictDepBuilds` stays `true`, its default: "the installation will exit with a non-zero exit code if any dependencies have unreviewed build scripts" (<https://pnpm.io/settings/build>). So a new package with a build script fails the install until a PR lists it, with a reason.
  - **A release-age floor and no trust downgrades,** in `apps/docs/pnpm-workspace.yaml`:
    - `minimumReleaseAge: 10080` makes pnpm refuse any version less than 7 days old (measured: it refused 0.19.3 on 2026-11-10). pnpm's default is 1,440 minutes (1 day). A pre-1.0 framework that ships often gets a week for others to find a bad release. The cost is that each upgrade, and layer 1 itself, waits a week after a release.
    - `trustPolicy: no-downgrade` makes the install fail when a package's trust level drops from its earlier releases.
    - `blockExoticSubdeps` stays `true`, its default: no git or tarball URLs below the direct dependencies.
    - Source for all three: <https://pnpm.io/settings/dependency-resolution>. The installed pnpm 12.15.0 knows them: its binary contains the setting names, and it printed "Lockfile passes supply-chain policies" during the measurement.
  - **`pnpm audit` in the CI task** (§6). An advisory that has to be ignored is named by its GHSA ID, with its reason in a comment, the way `deny.toml` ignores by RUSTSEC ID. The first version needs none: without generated share cards the audit was clean (measured).
  - **Telemetry off.** The `package.json` scripts set `ASTRO_TELEMETRY_DISABLED=1`, so a build on a laptop sends nothing either.
- **Reviewing an upgrade.** One PR per Nimbus minor version, never mixed with content:
  1. read the changelog of both packages;
  2. update the package;
  3. run `nimbus-docs migrate`, then `outdated`, and take starter changes with `diff --apply` only for files we never edited;
  4. run `check`, `astro check`, the build and the lint;
  5. look at the rendered site;
  6. list in the PR the packages added or removed in the lockfile.
  A patch release follows the same steps without `migrate`. Neither runs before the version is 7 days old.
- **Share cards: one static image, no generated cards.** `satori` and `@resvg/resvg-js` leave the tree, with the moderate `satori` advisory that no version in Nimbus's range fixes, and about 34 fewer packages (measured).
  - The cost is a deleted card route, one changed line in the page route and `socialImage` in `astro.config.ts`. An upgrade that changes the page route needs a hand merge there.
  - The image is drawn like `apps/web/public/og.png`, from its own HTML source ([sitio-web.md](../sitio-web.md) §5).

### 3. Content model
**Two readers.** A person setting Klav up, and an AI agent reading the docs through `llms.txt` and the Markdown versions. Every page is written so that its `.md` version reads well on its own:

- the first paragraph says what the page is for;
- commands sit in code blocks, with their expected output;
- no step is hidden in a tab or a collapsed block (Nimbus's [style guide](https://nimbus-docs.com/style-guide/example/) says hidden code is "unfindable and unextractable").

**Sections and pages of the first version.** "New" means new writing in English. "Adapted" means taken from an internal doc, cut to what a user needs, and written in English (not translated line by line).

| Section | Pages | Source | |
|---|---|---|---|
| **Overview** | What Klav is: a password manager where agents get actions, not values; what works today; where to start | `apps/web` claims ([sitio-web.md](../sitio-web.md) §6), [diseno.md](../diseno.md), `docs/features.md` | New |
| **Get started** | Install (Mac app, CLI, browser extension, iPhone) · Create an account (the default server, or your own) · Import from Bitwarden, 1Password, Google Authenticator or a browser · Add a device with a QR code | [macos.md](../macos.md) §3, [cli.md](../cli.md) §3–4, [extension.md](../extension.md) §2 and §12, [ios.md](../ios.md) §8, ADR 0029 | Adapted |
| **Apps** | Mac app · iPhone app · Browser extension (autofill, codes, passkeys) · CLI | The user-facing parts of macos.md, ios.md, extension.md and cli.md. Build, signing and budget sections stay internal | Adapted |
| **Agents** | How agents work (identity, the six words, `allow`/`ask`/`deny` and the permissions) · Connect an agent (`klav client connect`, `klav mcp`, the skill) · Approvals and task requests · Use secrets without seeing them (`klav agent run`, `inject`, `fill`, `klav.toml` and `klav run`) · The activity log and "what it saw" · Pause agents | cli.md §5–9, [skill/SKILL.md](../../skill/SKILL.md), ADRs 0014, 0015, 0021 and 0033 | Adapted |
| **Self-hosting** | Quick start with Docker Compose · Configuration · TLS and a reverse proxy · Data and backups · Postgres · Railway | [self-hosting.md](../self-hosting.md) | Adapted |
| **Security** | How Klav protects your data (end-to-end encryption, OPAQUE, the Secret Key, what the server sees) · What Klav defends against, and what it doesn't · Report a vulnerability | [especificacion-cripto.md](../especificacion-cripto.md), [modelo-de-amenazas.md](../modelo-de-amenazas.md), [privacidad.md](../privacidad.md), `SECURITY.md` | New summary; the vulnerability page is `SECURITY.md` itself (single source, below) |
| **Reference** | CLI commands · Glossary of product terms | cli.md, [glossary.md](../glossary.md) | Adapted |
| **On the way** | Sandboxes with an ephemeral credential (ADR 0036) · Deployed services behind a credential proxy (ADR 0038) · Environments instead of `.env` files (ADR 0032) | The accepted ADRs | New |

**Out of the first version:** the server API ([api.md](../api.md)) and the `klavd` protocol ([klavd.md](../klavd.md)). They serve people who build their own client, not people who set Klav up, and Klav has no OpenAPI spec for Nimbus's API reference. They can come later, through a new page or an OpenAPI file.

**"On the way."** Its own section in the sidebar, last. Each page:

- opens with an aside: "Not available yet. This page describes an accepted design.";
- explains the problem and the idea, links the ADR once the repository is public, and gives no date;
- never appears in Get started, Apps or Agents.

The set of items matches `apps/web`'s "Coming soon" list ([sitio-web.md](../sitio-web.md) §6). A PR that changes one changes the other.

**How the docs and the code stay in step: the rule.**

1. **`docs/features.md` decides where a feature may appear.**
   - "Works today": any section.
   - "Accepted, not built": only under On the way.
   - "Idea": nowhere.
   The PR that ships a feature, and marks it in `features.md`, moves or writes its page in the same PR.
2. **The public page owns the how-to; the internal doc owns the design.**
   - The PR that adapts a page adds, at the top of the matching section of the internal doc, one line that links to the public page. While that doc is still in Spanish the line is in Spanish (CLAUDE.md), and it is the only change to the doc.
   - From then on, a change to the user steps goes to the public page first.
   - The translation wave of ADR 0031 that reaches the internal doc removes the steps the public page now owns, keeps the architecture, protocol, build, signing and test sections, and updates whatever cites the removed steps (for example the sources table in [sitio-web.md](../sitio-web.md) §6, which cites `cli.md` sections).
3. **A file that is already English and public is loaded, not copied.** `SECURITY.md` becomes the "Report a vulnerability" page through a collection that reads the root file: Nimbus allows page collections in "a folder outside `src/`". Layer 2 verifies that this works for a single file; if it doesn't, the page is a short summary that links to `SECURITY.md`.
4. **Facts the code owns** (command names, flags, permission names, error codes) are quoted verbatim in backticks and checked against the code by the PR that writes them. Generating the CLI reference from `klav --help` is for later.
5. **A PR that changes user-visible behavior updates its public page.** Layer 1 adds this line to the "Workflow" part of `CLAUDE.md`.

**Security pages** state only what the spec and the threat model say, and link them by section. Layer 1 adds `/apps/docs/src/content/docs/security/` to `CODEOWNERS` next to the spec and the threat model, as ADR 0031 §4 proposes for those files.

### 4. Agent-facing output
**On in the first version** (all of them static, built with the site):

- `llms.txt`, one `llms.txt` per section, `llms-full.txt`, and the Markdown version of each page;
- the discovery files (`/.well-known/ard.json`, `/.well-known/ai-catalog.json`, the homepage `Link` header), because the site owns its host under Q1's recommendation. If the site ends up under `klav.dev/docs`, `agents.discovery` is `false`, as Nimbus's base-path page says;
- the starter's WebMCP search tool: nothing loads until an agent in the reader's browser calls it;
- JSON-LD, the sitemap and `robots.txt`, with the signals of Q5.

**Kept, with a rule:** the `.mdx` source of each page is published too (`/<slug>/index.mdx`). Anything written in a page file is public, comments included.

**Off in the first version:**

- **The remote MCP server** (Q3 recommends later). It needs a server adapter and one more package, and it adds a public endpoint whose rate limiting would be ours. It offers `list_pages` and `get_page`, which `llms.txt` and the `.md` URLs already give. An agent could also confuse a "Klav docs" MCP server with `klav mcp`, the product's own MCP server.
- **Publishing the skill at `/.well-known/agent-skills/`** (Q4 recommends not yet). ADR 0033 puts the skill inside the `klav` binary and keeps it current there. A second copy on the web could differ from the version an agent's `klav` expects. The Agents section shows how `klav client connect` installs it.
- **Markdown at page URLs** (content negotiation): it needs a server adapter.

### 5. Hosting and domain
| | (a) `docs.klav.dev` on Cloudflare Workers Static Assets | (b) `klav.dev/docs` behind `apps/web` on Railway | (c) `docs.klav.dev` as its own Railway service |
|---|---|---|---|
| Setup | The scaffolder's default: `wrangler.jsonc` and `deploy`. `klav.dev` is already on Cloudflare DNS | `apps/web`'s server serves a fixed list of files and answers `404` to the rest, with a CSP built from `index.html`'s hashes ([sitio-web.md](../sitio-web.md) §2). It would need a static file server for `/docs/**` with its own headers, and a Node build in its image | A container with a small static server, a second service in the `klav` project |
| Headers | Workers read `_headers`: the agent `Link` header, the `.md` content types and a CSP work as Nimbus writes them | Written by hand in `server.mjs` | Written by hand; `_headers` is ignored |
| Discovery files | At the root of `docs.klav.dev` | `agents.discovery: false`: the root belongs to `apps/web` | At the root |
| What changes in `apps/web` | One link from the landing page | Its "no npm dependencies" image gains a Node build, or a committed `dist/` | One link |
| Railway | Not involved | Same service as the waitlist | One more service |

**Recommendation: (a).** It is what Nimbus is built and tested for, needs no server of ours, and keeps `apps/web` free of dependencies. A Railway incident like October 2026's ([ADR 0038](0038-deployed-services.md)) doesn't take the docs down, and the docs hold no secret anyway. The cost is a Cloudflare account and adding `wrangler` to the tree (27 more package versions, measured). Cloudflare's free-plan limits were not checked.

**Before the repository is public (Q6).** The docs describe a product that a reader can't fully install yet, and links to source files would `404`. What can be deployed:

- the site at its `*.workers.dev` address, unlinked, with a `robots.txt` that disallows everything, so Omar can review it rendered;
- `docs.klav.dev`, indexing and the link from `klav.dev` on the day the repository opens.

Links to files in the repository are left out until then.

**How it deploys.** Omar runs `pnpm run deploy` locally at first: `wrangler` asks for a sign-in on that machine, and no Cloudflare token goes into GitHub. Deploying from CI on `main` would need a token scoped to this one Worker as a repository secret, and a step in the `ci` job on `main` only. It is left for a later PR, once the deploy is routine.

### 6. CI: a `docs` task in the same `ci` job
**Recommendation: a new task, `docs`, with its own check** (Q2). Boat bills a start per job that gets a machine, not per task ([ADR 0034](0034-ci-en-boat.md)). A new task inside the one `ci` job costs no start, only its seconds on a machine already running. In exchange it gets:

- its own check, so a broken docs link doesn't turn `extension` red. `docs` is a new check name: whatever merges by check names (the workflow's header names the PR orchestrator) has to learn it. `main` has no branch protection and no rulesets today (`gh api`, 2026-11-10), so no required check changes;
- its own skip on a rerun, so fixing a docs page doesn't rerun the extension's e2e;
- its own install, running at the same time as the extension's: possible because `apps/docs` is its own pnpm project (§1).

`apps/web`'s tests went into `extension` because they are one `node --test` line with no install. That reason doesn't hold here.

**The three things with the same name** (CLAUDE.md, "CI"):

1. `.github/ci-tasks.json`: `{ "name": "docs", "uses": ["node"] }`;
2. the workflow: a `docs: start` step and a `docs: result` step (`wait docs 4800`), shaped like the others;
3. `CI_TASK_CHECK_NAMES`: `"docs": "docs"`.

Plus: `actions/setup-node`'s pnpm cache needs `cache-dependency-path` to list both lockfiles. The engine's tests run with `cd .github/boated-ci && bun test`.

**The task's script.** Every command that can fail goes inside it:

```sh
cd apps/docs
pnpm install --frozen-lockfile
pnpm audit --audit-level low     # §2: clean without generated share cards
pnpm exec nimbus-docs check
pnpm exec astro check
pnpm build                       # astro build, then Pagefind
pnpm exec nimbus-docs lint       # nimbus/internal-link as "error": dead internal links fail
```

- **Network.** `pnpm audit` asks the registry. A new advisory turns `docs` red on any PR, as a new RUSTSEC turns `cargo-deny` red. That is intended.
- **History.** The checkout stays shallow. The build then leaves out the "Last updated" dates, which CI doesn't need. The deploy build runs on a full clone.
- **Expected time:** well under a minute after the install, from the measured 4 s build of three pages. The real figure comes from the task metrics table of the first runs.

### 7. Rejected alternatives
- **Starlight** (Astro's docs theme). Mature, and it has built-in i18n: "Starlight provides built-in support for multilingual sites, including routing, fallback content, and full right-to-left (RTL) language support" (<https://starlight.astro.build/guides/i18n/>). Omar chose Nimbus, and English only, so i18n doesn't decide it today. Nimbus gives Klav's second reader, agents, more out of the box: Markdown versions, `llms.txt` per section, discovery files and a docs MCP server when wanted. Starlight stays the exit if Nimbus stalls or Spanish docs become a goal (Risks).
- **Mintlify.** Hosted: "Mintlify runs the site infrastructure while your team focuses on the content"; self-hosting is listed only for Enterprise. Its free Starter plan includes a custom domain for up to five editors; Pro is $450 a month billed yearly (<https://www.mintlify.com/pricing>, read 2026-11-10). The site would be built and served by a third party from the repository, and its source would not live in `apps/`.
- **Only Markdown in the repository.** No dependencies at all, and GitHub renders it. But it has no search, no `llms.txt`, no Markdown versions with absolute links, no own domain, and nothing until the repository is public. The internal docs are also design documents in Spanish, not a user's path through the product.

## Consequences
- The repository gets its first website dependency tree: about 545 package versions with the Cloudflare target and no generated share cards (544 measured on a Mac; 430 installed there in the larger starter), with prebuilt native binaries, against zero in `apps/web`. §2 says what guards it.
- `apps/docs` has its own lockfile; the root lockfile and the extension's resolved packages don't change (measured).
- One more check, `docs`, on every PR, at no extra Boat start.
- Writing docs becomes part of shipping: the PR that changes user-visible behavior updates its page, and `features.md` decides which section may mention it.
- Internal docs slowly lose their user steps to the public site and keep the design.
- Two public sites: `klav.dev` (landing and waitlist, en/es) and the docs (English). The landing page links to the docs; its "Coming soon" list and the docs' "On the way" section list the same items.

## Risks
- **Pre-1.0 churn.** Seven minor releases in two months, and any minor can break the API (README). Mitigations:
  - exact pins, the 7-day release age, and one reviewed upgrade PR per minor (§2);
  - few custom components in pages (asides, steps, code blocks and tabs only), so a move to Starlight or plain Astro means rewriting layouts, not content. The content is MDX in standard Astro content collections either way.
  - If Nimbus stops shipping or breaks too often, a new ADR picks the exit.
- **No i18n.** Nimbus has none (verified as absent from its docs). If Spanish docs are wanted later, the options are a second site, Astro's own routing by hand, or a move to Starlight. Each needs its own ADR. The UI stays in English and Spanish; only the docs are English.
- **Two sites to keep in sync.** The landing page's claims ([sitio-web.md](../sitio-web.md) §6) and the docs can disagree. The shared rule is `features.md`: both sites only claim what it marks "works today".
- **Public claims about security.** A wrong sentence on a Security page is a security bug in the docs. Those pages only restate the spec and the threat model, with links, and go through `CODEOWNERS`.
- **Advisories with no fix in Nimbus's ranges.** `satori` was one; the static share card keeps it out. The next one may sit in a package the site can't drop. Then it is ignored by ID with its reason, re-checked on every upgrade, or the site waits for Nimbus.
- **A third-party agent guide in the repository.** `AGENT.md` is Nimbus's text and changes with upgrades; agents read it as instructions. `apps/docs/CLAUDE.md` puts the repository's rules first, and the upgrade PR shows its diff.

## Plan in layers
One branch per layer, stacked with `gh stack`; Omar merges.

1. **`docs/site-scaffold`: the site and its CI.**
   - On or after 2026-11-12 (§1): scaffold `apps/docs` with Q1's deploy target, exact pins, its own lockfile per Q2, the pnpm settings and audit of §2, and the static share card in place of the generated ones.
   - Telemetry off; `apps/docs/CLAUDE.md`; `site`, title and description; `robots.txt` per Q5 and Q6.
   - The `docs` CI task (§6).
   - The `CLAUDE.md` workflow line and the `CODEOWNERS` entry (§3).
   - Empty sections with their index pages. The roadmap box stays open.
2. **`docs/site-content-*`: content by section.** One branch each, in this order:
   1. Overview and Get started;
   2. Agents;
   3. Apps;
   4. Self-hosting;
   5. Security (with the `SECURITY.md` collection check of §3);
   6. Reference and On the way.
   Each PR checks every claim against `features.md` and the code, replaces the user steps in the internal doc with a link (§3, rule 2), and looks at the rendered pages and their `.md` versions.
3. **`docs/site-deploy`: publish.**
   - The Cloudflare Worker per Q1, at its `workers.dev` address per Q6.
   - [sitio-web.md](../sitio-web.md) gets a section on the docs site.
   - On the day the repository opens: the domain, indexing on, repository links, and the link from `klav.dev`, then the roadmap box is checked.

## Defaults I chose (not questions)
1. Scaffolder 0.8.3 with `--content empty`, so no starter pages to delete. Every direct dependency pinned exact at its newest version that is at least 7 days old; layer 1 starts on or after 2026-11-12, when `@cloudflare/nimbus-docs` 0.19.3 qualifies.
2. Static output, no server adapter.
3. `minimumReleaseAge: 10080`, `trustPolicy: no-downgrade`, `blockExoticSubdeps: true`, no build scripts allowed.
4. `pnpm audit` in the task, with no ignores in the first version.
5. One static share card instead of generated ones, which drops `satori` and its advisory (§2).
6. `ASTRO_TELEMETRY_DISABLED=1` in the scripts.
7. `AGENT.md` stays; `apps/docs/CLAUDE.md` is ours.
8. The section is called "On the way", with the aside "Not available yet. This page describes an accepted design." The landing page keeps its "Coming soon" badge.
9. The `.mdx` versions stay published.
10. The WebMCP search tool stays, as the starter ships it.
11. Lint: `nimbus/internal-link` as `error`; other rules as the layer 1 PR proposes, as warnings.
12. No analytics and no cookies, like `apps/web`.
13. The server API and the `klavd` protocol are not in the first version.
14. Node: the CI's Node 22, at least 22.23.4.
15. Omar deploys by hand, locally, until a later PR moves it to CI.

## Questions for Omar
Answered on 2026-11-10 (see "Omar's answers"). Each could be answered alone, and the first option was the recommended one.

| # | Question | Options |
|---|---|---|
| Q1 | Where is the public docs site served? | **(a) `docs.klav.dev` on Cloudflare (Workers Static Assets), the host Nimbus is built for; `klav.dev` is already on Cloudflare DNS, and Railway isn't involved (Recommended)**<br>(b) `klav.dev/docs`, served by the `apps/web` server on Railway; its image would need a Node build and its server a file route for `/docs`<br>(c) `docs.klav.dev` as its own small service on Railway, next to `klav-web` |
| Q2 | How does the docs site join the repository and its CI? | **(a) `apps/docs` as its own pnpm project, with its own lockfile, and its own `docs` check in the same CI job (no extra Boat start); the extension's lockfile doesn't move with each docs upgrade (Recommended)**<br>(b) `apps/docs` inside the root pnpm workspace, one lockfile, its steps added to the `extension` CI task; a docs failure turns `extension` red, and the extension's lockfile gains peer changes (measured)<br>(c) Its own pnpm project, but its steps inside the `extension` task |
| Q3 | Does the first version of the docs run Nimbus's MCP server, a public `/mcp` with `list_pages` and `get_page`? | **(a) Not now: `llms.txt` and a Markdown version of every page already serve agents, the site stays static with no server, and agents won't confuse it with `klav mcp` (Recommended)**<br>(b) Yes, with Cloudflare's server adapter and a rate-limit rule on `/mcp`<br>(c) Only when the site has a search tool worth exposing |
| Q4 | Does the docs site publish the Klav skill at `/.well-known/agent-skills/`, where agents that find the site can install it? | **(a) No: the skill lives in the `klav` binary and `klav client connect` installs the version that matches it; the docs explain that (Recommended)**<br>(b) Yes, built from `skill/SKILL.md` on every deploy<br>(c) Yes, once the repository is public |
| Q5 | What does the docs site tell crawlers in `robots.txt` about AI use? | **(a) Nimbus's default, `ai-train=yes, search=yes, ai-input=yes`: open-source docs that models learn from help agents use Klav correctly (Recommended)**<br>(b) `ai-train=no`, with search and answers allowed |
| Q6 | What goes online before the repository is public? | **(a) The site at its unlisted `workers.dev` address, closed to crawlers, for review; `docs.klav.dev`, indexing and the link from `klav.dev` on the day the repository opens (Recommended)**<br>(b) `docs.klav.dev` public now, without links into the repository<br>(c) Nothing until the repository is public |

## Omar's answers (2026-11-10)

Omar accepted the ADR as it is, with the recommendation for each question:

- **Q1:** `docs.klav.dev` on Cloudflare (Workers Static Assets). Railway isn't involved.
- **Q2:** `apps/docs` as its own pnpm project, with its own lockfile and its own `docs` check in the same CI job.
- **Q3:** no MCP server for the docs now. `llms.txt` and the Markdown version of every page serve agents, and the site stays static.
- **Q4:** the site doesn't publish the skill. It lives in the `klav` binary, `klav client connect` installs the matching version, and the docs explain that.
- **Q5:** Nimbus's default in `robots.txt`: `ai-train=yes, search=yes, ai-input=yes`.
- **Q6:** before the repository is public, only the unlisted `workers.dev` address, closed to crawlers, for review. `docs.klav.dev`, indexing and the link from `klav.dev` come on the day the repository opens.

## Amendment of 2026-11-13: "On the way" is also the public roadmap

- Status: accepted by Omar on 2026-11-13.

On 2026-11-13 Omar decided that pending work is shown to the public through "On the way", and the other two lists name the same items. That widens §3: besides accepted designs, the section lists what is decided about how Klav is distributed and hosted and isn't out yet. Today that means the Chrome Web Store, addons.mozilla.org, the App Store, and Klav's own server at `api.klav.dev`, a paid plan with a waitlist ([ADR 0010](0010-decisiones-fase-3-y-plan-alojado.md)). These items come from the [roadmap](../roadmap.md), not from a design ADR.

- Such a page opens with "Not available yet. This page lists what is decided and not out yet." instead of the design aside.
- Everything else in §3 holds: no dates; nothing there appears as available in Get started, Apps or Agents; `docs/features.md` lists the items under "Accepted, not built"; and the landing's "Coming soon" list ([sitio-web.md](../sitio-web.md) §6) names the same items.
- The landing's downloads section links to the section, behind the `docs` switch ([sitio-web.md](../sitio-web.md) §2).
- **The items today,** the same in the three lists: sandboxes (ADR 0036), environments (ADR 0032), deployed services (ADR 0038), the stores, and Klav's own server. Accepted designs that `features.md` marks "Accepted, not built" and that none of the lists names yet (adding a device with a QR code, ADR 0029; changing an agent's permissions from the iPhone, ADR 0033's amendment) need Omar's go-ahead before any list names them. What `features.md` marks "Idea, no ADR" stays out of all three, as §3 says.
