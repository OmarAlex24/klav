/**
 * What klavd (and the agent) may learn about a page: its origin, never the
 * path, query or fragment, where sign-in pages put tokens (layer 04, G7).
 * The same rule as `klav_core::site::origin`.
 */
export function originOf(url: string): string {
  try {
    const parsed = new URL(url);
    return parsed.host ? `${parsed.protocol}//${parsed.host}` : parsed.protocol;
  } catch {
    return "a page that is not a web address";
  }
}
