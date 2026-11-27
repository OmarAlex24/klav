/**
 * The vault's type filter in the popup: «All», one tab per item type and
 * «Codes» (items with a one-time code, of any type). Counts come from the
 * list the popup already has; «Codes» needs klavd (`list` with `codes`),
 * so its count arrives later. A standalone `totp` item has no tab of its
 * own: it is what «Codes» is for.
 */
import type { MessageKey } from "../shared/i18n";
import type { ItemKind, ItemSummary } from "../shared/protocol";

export type VaultFilter = "all" | "codes" | Exclude<ItemKind, "totp">;

/** Tabs in this order; the ones with nothing in them stay hidden. */
export const FILTERS: readonly VaultFilter[] = ["all", "login", "codes", "card", "note", "ssh_key", "api_key", "environment", "identity", "file"];

const LABELS: Record<VaultFilter, MessageKey> = {
  all: "filter_all",
  codes: "filter_codes",
  login: "filter_login",
  card: "filter_card",
  note: "filter_note",
  ssh_key: "filter_ssh_key",
  api_key: "filter_api_key",
  environment: "filter_environment",
  identity: "filter_identity",
  file: "filter_file",
};

export function filterLabel(filter: VaultFilter): MessageKey {
  return LABELS[filter];
}

export interface Tab {
  filter: VaultFilter;
  /** Undefined while klavd has not said how many items have a code. */
  count?: number;
}

/**
 * The tabs to draw: «All» and every filter with something in it, plus the
 * chosen one even if a search left it empty. One type and no codes need
 * no tabs at all.
 */
export function tabs(items: readonly ItemSummary[], codes: number | undefined, chosen: VaultFilter): Tab[] {
  const counts = new Map<VaultFilter, number>();
  for (const item of items) {
    if (item.kind === "totp") continue;
    counts.set(item.kind, (counts.get(item.kind) ?? 0) + 1);
  }
  const out: Tab[] = [];
  for (const filter of FILTERS) {
    if (filter === "all") out.push({ filter, count: items.length });
    else if (filter === "codes") {
      if ((codes ?? 0) > 0 || chosen === "codes") out.push(codes === undefined ? { filter } : { filter, count: codes });
    } else {
      const count = counts.get(filter) ?? 0;
      if (count > 0 || chosen === filter) out.push({ filter, count });
    }
  }
  return out.length <= 2 && chosen === "all" ? [] : out;
}

/** The items a type tab shows («Codes» is listed by klavd itself). */
export function ofKind(items: readonly ItemSummary[], filter: VaultFilter): ItemSummary[] {
  if (filter === "all" || filter === "codes") return [...items];
  return items.filter((i) => i.kind === filter);
}

/** Whether `value` names a filter (what the popup keeps between screens). */
export function isFilter(value: unknown): value is VaultFilter {
  return typeof value === "string" && (FILTERS as readonly string[]).includes(value);
}
