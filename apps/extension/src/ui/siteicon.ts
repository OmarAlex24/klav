/**
 * The square next to an item, in three layers, none of which tells a third
 * party which sites the person keeps in Klav:
 *
 * 1. the site's logo, if Klav ships it (Simple Icons: CC0 1.0 or no license
 *    data, see THIRD-PARTY-NOTICES.md), drawn in ink;
 * 2. in Chromium, the favicon the browser already has in its own cache
 *    (`_favicon`, permission `favicon`): a local lookup, never a request;
 * 3. the item's initial.
 *
 * Off by default, «Ask each site for its icon» (`askSites` in
 * `storage.local`) asks the item's own site for `/favicon.ico` when the
 * first two have nothing. Never another service.
 */
import { ext } from "../shared/ext";
import { h } from "./dom";
import { tile } from "./kit";

const NS = "http://www.w3.org/2000/svg";

interface IconMap {
  icons: { slug: string; domains: string[]; path: string }[];
}

let logos: Promise<Map<string, string>> | undefined;

/** Domain → path of the logo, from the map the build copies (assets/site-icons). */
function logoMap(): Promise<Map<string, string>> {
  logos ??= fetch(ext.runtime.getURL("site-icons.json"))
    .then((r) => r.json() as Promise<IconMap>)
    .then((m) => {
      const map = new Map<string, string>();
      for (const icon of m.icons) for (const domain of icon.domains) map.set(domain, icon.path);
      return map;
    })
    .catch(() => new Map<string, string>());
  return logos;
}

/** `https://www.github.com/login` or `github.com` → `github.com`. */
export function siteHost(site: string): string | undefined {
  try {
    const host = new URL(site.includes("://") ? site : `https://${site}`).hostname.toLowerCase();
    return host.replace(/^www\./, "") || undefined;
  } catch {
    return undefined;
  }
}

/** The logo for `host` or the closest parent domain that has one (`gist.github.com` → github.com). */
export function logoFor(map: Map<string, string>, host: string): string | undefined {
  for (let h = host; ; ) {
    const path = map.get(h);
    if (path) return path;
    const dot = h.indexOf(".");
    if (dot < 0) return undefined;
    h = h.slice(dot + 1);
  }
}

function logo(path: string): SVGSVGElement {
  const svg = document.createElementNS(NS, "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("aria-hidden", "true");
  const p = document.createElementNS(NS, "path");
  p.setAttribute("d", path);
  p.setAttribute("fill", "currentColor");
  svg.append(p);
  return svg;
}

// ------------------------------------------------- the browser's cache --

function faviconUrl(page: string): string {
  const url = new URL(ext.runtime.getURL("/_favicon/"));
  url.searchParams.set("pageUrl", page);
  url.searchParams.set("size", "32");
  return url.toString();
}

async function digest(url: string): Promise<string | undefined> {
  const res = await fetch(url);
  if (!res.ok) return undefined;
  const hash = await crypto.subtle.digest("SHA-256", await res.arrayBuffer());
  return [...new Uint8Array(hash)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** What the browser answers for a page it has never seen: its generic globe. */
let globe: Promise<string | undefined> | undefined;

/**
 * The browser's cached favicon for the first of `pages` it has a real one
 * for. Chromium matches the exact address of a page it showed (not its
 * origin), so the frame's own address goes first.
 */
async function cachedFavicon(pages: string[]): Promise<string | undefined> {
  if (__TARGET__ !== "chromium") return undefined;
  try {
    globe ??= digest(faviconUrl("https://klav.invalid/"));
    const generic = await globe;
    for (const page of pages) {
      const url = faviconUrl(page);
      const mine = await digest(url);
      if (mine && mine !== generic) return url;
    }
  } catch {
    // no favicon then
  }
  return undefined;
}

// ------------------------------------------------------ the site itself --

let askSites: Promise<boolean> | undefined;

function asksSites(): Promise<boolean> {
  askSites ??= ext.storage.local.get("askSites").then(
    (s: Record<string, unknown>) => s.askSites === true,
    () => false,
  );
  return askSites;
}

/** `/favicon.ico` from the item's own site, without a referrer. */
function fromSite(origin: string): Promise<string | undefined> {
  return new Promise((done) => {
    const img = new Image();
    img.referrerPolicy = "no-referrer";
    img.onload = () => {
      done(img.naturalWidth > 0 ? img.src : undefined);
    };
    img.onerror = () => {
      done(undefined);
    };
    img.src = `${origin}/favicon.ico`;
  });
}

function originOf(site: string, host: string): string {
  try {
    const url = new URL(site);
    if (url.protocol === "https:" || url.protocol === "http:") return url.origin;
  } catch {
    // a bare host
  }
  return `https://${host}`;
}

// ------------------------------------------------------------- the tile --

function picture(src: string): HTMLImageElement {
  const img = h("img", { src, alt: "", referrerpolicy: "no-referrer", draggable: "false" });
  return img;
}

let observer: IntersectionObserver | undefined;
const onScreen = new WeakMap<Element, () => void>();

/** Runs `then` once `el` is on screen (at once where the browser cannot tell). */
function whenVisible(el: HTMLElement, then: () => void): void {
  if (typeof IntersectionObserver === "undefined") {
    then();
    return;
  }
  observer ??= new IntersectionObserver((entries) => {
    for (const entry of entries) {
      if (!entry.isIntersecting) continue;
      observer?.unobserve(entry.target);
      const run = onScreen.get(entry.target);
      onScreen.delete(entry.target);
      run?.();
    }
  });
  onScreen.set(el, then);
  observer.observe(el);
}

/**
 * The item's square: its initial at once, then its logo or its favicon
 * when one turns up, looked up only once the square is on screen. `site` is the item's first URL, or the host it was
 * offered for; without one it stays a letter (cards, addresses). `page`,
 * when Klav is showing it on a page of that site, is that page's address.
 */
export function siteTile(title: string, site?: string, page?: string): HTMLElement {
  const el = tile(title);
  const host = site ? siteHost(site) : undefined;
  if (!host) return el;
  whenVisible(el, () => void (async () => {
    const path = logoFor(await logoMap(), host);
    if (path) {
      el.replaceChildren(logo(path));
      el.classList.add("tile-logo");
      return;
    }
    const address = site?.includes("://") ? site : `https://${host}/`;
    const origin = originOf(address, host);
    const pages = [...new Set([page, address, `${origin}/`].filter((p): p is string => p !== undefined))];
    const cached = await cachedFavicon(pages);
    const src = cached ?? ((await asksSites()) ? await fromSite(origin) : undefined);
    if (!src) return;
    el.replaceChildren(picture(src));
    el.classList.add("tile-favicon");
  })());
  return el;
}

/** Forgets the setting read earlier (the popup changes it). */
export function settingChanged(): void {
  askSites = undefined;
}
