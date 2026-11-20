import { defineConfig } from "astro/config";
import tailwindcss from "@tailwindcss/vite";
import nimbus, {
  defineConfig as defineNimbusConfig,
} from "@cloudflare/nimbus-docs";
import { tableScroll } from "@cloudflare/nimbus-docs/markdown";

const nimbusConfig = defineNimbusConfig({
  // The canonical origin (ADR 0039 §5, Q1).
  site: "https://docs.klav.dev",
  title: "Klav",
  description:
    "Docs for Klav, the open-source, end-to-end encrypted password manager for the age of agents: agents get actions, not values.",
  locale: "en",
  github: "https://github.com/OmarAlex24/klav",
  // One static share card for every page (public/og.png, drawn from
  // tools/og.html) instead of generated ones, so satori and @resvg/resvg-js
  // stay out of the tree (ADR 0039 §2).
  socialImage: "/og.png",
  socialImageAlt: "Klav docs: docs for you and your agents.",
  // The home page leads the sidebar; every other page joins it automatically.
  // Each section's index page is its group's first link, labelled by its
  // `sidebar.label` ("Security overview"), instead of the starter's fixed
  // "Overview", which repeated the Overview section's name in every group.
  sidebar: {
    items: ["index", { autogenerate: { collection: "docs" } }],
    indexDisplay: "overview-leaf",
  },
});

export default defineConfig({
  // nimbus:adapter
  output: "static",
  // Tailwind v4 via its Vite plugin (the integration Astro recommends for
  // Tailwind v4 — replaces the PostCSS plugin, which doesn't build under
  // Astro 7's Vite 8 bundler).
  vite: {
    plugins: [tailwindcss()],
  },
  // Hover-prefetch link targets so full-page navigations feel instant without
  // a client-side router.
  prefetch: {
    prefetchAll: true,
    defaultStrategy: "hover",
  },
  integrations: [
    nimbus(nimbusConfig, {
      // Authoring rules are opt-in by design — your repo, your taste. The
      // two below are the load-bearing pair: frontmatter has to validate
      // against the content schema for the page to render properly, and
      // broken internal links are 404s for your readers. Add the others
      // (heading hierarchy, code-block language, style, etc.) when you're
      // ready to enforce them — see `nimbus-docs lint --help`.
      rules: {
        "nimbus/frontmatter-shape": "error",
        "nimbus/internal-link": "error",
        // Proposed as warnings in ADR 0039's layer 1 (Defaults, item 11):
        // structure an agent reading the .md version relies on. Left off:
        // the style rules (emphasis, list markers, heading punctuation) and
        // code-block-prompt-prefix, since a command with its output may show
        // a prompt.
        "nimbus/description-required": "warn",
        "nimbus/single-h1": "warn",
        "nimbus/heading-hierarchy": "warn",
        "nimbus/duplicate-heading-text": "warn",
        "nimbus/code-block-lang": "warn",
        "nimbus/bare-url": "warn",
        "nimbus/image-ref": "warn",
        "nimbus/redirected-link": "warn",
        "nimbus/no-self-host-url": "warn",
      },
      markdown: {
        // Wrap wide tables so they scroll instead of overflowing the page
        // (styled by `.nb-table-scroll` in src/styles/prose.css).
        hastPlugins: [tableScroll()],
        // `## Install {#install}` gives a heading a fixed id. A heading that
        // ends in other `{…}` text, such as `{account_id}` in a .md file, is
        // read as attributes too; remove this to keep it as text.
        features: { headingAttributes: true },
      },
    }),
  ],
});
