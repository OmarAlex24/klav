/**
 * «Salud» in the popup (ADR 0022 §4, §6): the vault health report from
 * klavd (reused, weak, old and, if the person turned the check on,
 * breached passwords), and «Arreglar mis contraseñas repetidas».
 *
 * The fix is a task the person offers an agent: pick the agent, review
 * the logins (uncheck what should stay), approve once with Touch ID or
 * the master password. The agent gets only the sites, never which ones
 * share a password. While such a task runs, its card shows each site as
 * changed, pending or failed, from the task's `rotate.*` events.
 *
 * Nothing here holds a value: the report names items, hosts and reasons.
 */
import { band, ditherCanvas } from "../shared/dither";
import { type MessageKey, locale, t } from "../shared/i18n";
import { daemon } from "../shared/messages";
import type {
  DaemonStatus,
  HealthItem,
  HealthSettingsView,
  OfferBlock,
  OfferRequest,
  OfferRow,
  ReusedOffer,
  SiteProgress,
  TaskCard,
  TaskProgress,
  VaultHealth,
} from "../shared/protocol";
import { h } from "./dom";
import { tile } from "./kit";
import { presence } from "./presence";
import { STEPS, WARNINGS, clock, duration, failure } from "./tasks";

/** How often a running task's progress is read while «Salud» is open. */
const PROGRESS_EVERY_MS = 5000;
/** An offered task lasts 2 hours unless the person picks otherwise. */
const DEFAULT_SECS = 2 * 3600;

const BLOCKS: Record<OfferBlock, MessageKey> = {
  not_granted: "health_block_not_granted",
  no_site: "health_block_no_site",
  not_login: "health_block_not_login",
  other_field: "health_block_other_field",
};

// ------------------------------------------------------------ pure parts --

/** The logins the person left checked, in the card's order; blocked ones never. */
export function pickedItems(rows: OfferRow[], checked: (item: string) => boolean): string[] {
  return rows.filter((r) => r.blocked === undefined && checked(r.item_id)).map((r) => r.item_id);
}

/** What the popup sends with `offer_task`: the person's own (neutral) title and reason. */
export function offerRequest(agent: string, rows: OfferRow[], checked: (item: string) => boolean, durationSecs: number): OfferRequest {
  return {
    agent,
    items: pickedItems(rows, checked),
    task: t("health_offer_task"),
    reason: t("health_offer_reason"),
    duration_secs: durationSecs,
  };
}

/** How a site of a running task reads. */
export function siteLabel(site: SiteProgress): MessageKey {
  if (site.state === "changed") return "health_site_changed";
  if (site.state === "failed") return "health_site_failed";
  return site.started ? "health_site_running" : "health_site_pending";
}

/** How many sites are changed, pending and failed. */
export function progressCounts(sites: SiteProgress[]): { changed: number; pending: number; failed: number } {
  const changed = sites.filter((s) => s.state === "changed").length;
  const failed = sites.filter((s) => s.state === "failed").length;
  return { changed, pending: sites.length - changed - failed, failed };
}

/** Durations the person can pick for the task: 15 min to 24 h, 2 h first. */
export function offerSteps(): number[] {
  return [DEFAULT_SECS, ...STEPS.filter((s) => s !== DEFAULT_SECS)];
}

/** A task worth following here: offered by the person, running, with `rotate`. */
export function isFixTask(card: TaskCard, now: number): boolean {
  return (
    card.offered === true &&
    card.status === "approved" &&
    (card.expires_at ?? 0) > now &&
    card.rows.some((r) => r.permissions.some((p) => p.permission === "rotate" && p.checked))
  );
}

function day(ms: number): string {
  return new Intl.DateTimeFormat(locale(), { dateStyle: "medium" }).format(new Date(ms));
}

// ------------------------------------------------------------- the report --

export interface HealthHooks {
  /** The item's tile (the popup passes its site icons). */
  tile?: (title: string, host?: string) => HTMLElement;
  /** Opens an item. */
  open?: (id: string) => void;
  /** «Arreglar mis contraseñas repetidas». */
  fix?: () => void;
  /** The breach check switch. */
  breach?: (on: boolean) => Promise<void>;
}

function healthRow(item: HealthItem, end: string, hooks: HealthHooks): HTMLElement {
  const host = item.hosts[0];
  const title = item.field === "password" ? item.title : `${item.title} (${item.field_label})`;
  const main = h(
    "span",
    { class: "row-main" },
    h("span", { class: "row-title" }, title),
    h("span", { class: "row-sub" }, host ?? item.username ?? item.reference),
  );
  const tileEl = (hooks.tile ?? ((t: string) => tile(t)))(item.title, host);
  const open = hooks.open;
  const body = open
    ? h("button", { class: "row-open", type: "button", onclick: () => { open(item.id); } }, tileEl, main)
    : h("span", { class: "row-open" }, tileEl, main);
  return h("li", { class: "row" }, body, end ? h("span", { class: "row-end" }, h("span", { class: "mono" }, end)) : null);
}

function heading(key: MessageKey, n?: number): HTMLElement {
  return h("h2", { class: "label" }, n === undefined ? t(key) : t(key, n));
}

/** The report's sections. Pure DOM: the caller wires the actions. */
export function healthSections(report: VaultHealth, settings: HealthSettingsView | undefined, hooks: HealthHooks): HTMLElement {
  const out = h("div", { class: "health" });
  out.append(
    h(
      "p",
      { class: "sub health-scope" },
      t("health_checked", report.passwords, report.items),
      report.skipped ? ` ${t("health_skipped", report.skipped)}` : "",
    ),
  );

  // Reused: one block per group of logins that share a password.
  const reused = h("section", { class: "group health-reused" }, heading("health_reused", report.reused.length));
  if (report.reused.length === 0) {
    reused.append(h("p", { class: "empty" }, t("health_reused_none")));
  } else {
    for (const group of report.reused) {
      reused.append(
        h(
          "div",
          { class: "health-group" },
          h("p", { class: "field-label" }, t("health_same_in", group.items.length)),
          h("ul", { class: "list" }, ...group.items.map((i) => healthRow(i, "", hooks))),
        ),
      );
    }
    if (hooks.fix) {
      const fix = hooks.fix;
      reused.append(
        h("button", { class: "btn btn-primary btn-block health-fix", type: "button", onclick: () => { fix(); } }, t("health_fix")),
        h("p", { class: "sub" }, t("health_fix_hint")),
      );
    }
  }
  out.append(reused);

  const weak = h("section", { class: "group health-weak" }, heading("health_weak", report.weak.length));
  if (report.weak.length === 0) weak.append(h("p", { class: "empty" }, t("health_weak_none")));
  else
    weak.append(
      h(
        "ul",
        { class: "list" },
        ...report.weak.map((w) =>
          healthRow(w.item, w.generated_bits !== undefined && w.generated_bits < 40 ? t("health_bits", w.generated_bits) : t("health_score", w.score), hooks),
        ),
      ),
    );
  out.append(weak);

  const old = h("section", { class: "group health-old" }, heading("health_old", report.old.length));
  if (report.old.length === 0) old.append(h("p", { class: "empty" }, t("health_old_none")));
  else old.append(h("ul", { class: "list" }, ...report.old.map((o) => healthRow(o.item, t("health_since", day(o.since_ms)), hooks))));
  out.append(old);

  // Breached: off by default; the switch says what turning it on sends.
  const breached = h("section", { class: "group health-breached" });
  const b = report.breaches;
  breached.append(heading(b.status === "checked" ? "health_breached_n" : "health_breached", b.status === "checked" ? b.found.length : undefined));
  if (b.status === "checked") {
    if (b.found.length === 0) breached.append(h("p", { class: "empty" }, t("health_breached_none")));
    else breached.append(h("ul", { class: "list" }, ...b.found.map((f) => healthRow(f.item, t("health_seen", f.count), hooks))));
  } else if (b.status === "failed") {
    breached.append(h("p", { class: "notice", role: "alert" }, t("health_breach_failed", b.message)));
  }
  if (settings && hooks.breach) {
    const breach = hooks.breach;
    const box = h("input", { type: "checkbox", class: "check", id: "breach-check" });
    box.checked = settings.breach_check;
    const saved = h("div", { hidden: true });
    box.addEventListener("change", () => {
      box.disabled = true;
      breach(box.checked).catch((e: unknown) => {
        box.checked = !box.checked;
        box.disabled = false;
        saved.hidden = false;
        failure(saved, e);
      });
    });
    breached.append(
      h(
        "label",
        { class: "setting", for: "breach-check" },
        box,
        h("span", { class: "setting-text" }, h("span", { class: "setting-title" }, t("health_breach_switch")), h("span", { class: "sub" }, t("health_breach_notice"))),
      ),
      saved,
    );
  }
  out.append(breached);

  if (report.reused.length + report.weak.length + report.old.length === 0 && (b.status !== "checked" || b.found.length === 0)) {
    out.prepend(h("p", { class: "lede health-clean" }, t("health_clean")));
  }
  return out;
}

// --------------------------------------------------------- the offer card --

/**
 * «Arreglar mis contraseñas repetidas»: the agent, the logins (each with
 * its change page and what the task holds) and one approval. Blue, like
 * everything agents do.
 */
function offerCard(offer: ReusedOffer, status: DaemonStatus, pick: (agent: string) => void, done: (card: TaskCard) => void, cancel: () => void): HTMLElement {
  const touchId = status.touch_id.available && status.touch_id.enrolled && !status.touch_id.password_required;
  const message = h("div", {});
  const boxes = new Map<string, HTMLInputElement>();

  const agentLine = (): HTMLElement => {
    if (offer.agents.length === 0) {
      return h("div", { class: "health-noagent" }, h("p", { class: "notice" }, t("health_no_agent")), h("code", { class: "command" }, "klav agent register"));
    }
    const select = h(
      "select",
      { class: "input task-select", "aria-label": t("health_agent") },
      offer.agent ? null : h("option", { value: "" }, t("health_pick_agent")),
      ...offer.agents.map((a) => {
        const o = h("option", { value: a.id }, a.name);
        if (offer.agent?.id === a.id) o.selected = true;
        return o;
      }),
    );
    select.addEventListener("change", () => {
      if (select.value) pick(select.value);
    });
    return h("label", { class: "task-time" }, h("span", { class: "field-label" }, t("health_agent")), h("span", { class: "task-time-line" }, select));
  };

  const rows = offer.rows.map((row) => {
    const blocked = row.blocked !== undefined || !offer.agent;
    const box = h("input", { type: "checkbox", class: "check", disabled: blocked, "aria-label": row.title });
    box.checked = !blocked;
    boxes.set(row.item_id, box);
    const where = row.hosts.join(", ");
    const totp = row.permissions.includes("totp");
    const warn = WARNINGS.totp;
    const user = [row.username, row.group !== undefined ? t("health_group", row.group) : undefined].filter(Boolean).join(" · ");
    return h(
      "li",
      { class: row.blocked ? "task-row is-blocked" : "task-row" },
      h("label", { class: "task-item" }, box, h("span", { class: "task-title" }, row.title), where ? h("span", { class: "task-host" }, where) : null),
      user ? h("p", { class: "task-user" }, user) : null,
      row.blocked ? h("p", { class: "task-flag" }, t(BLOCKS[row.blocked])) : null,
      !row.blocked && row.change_url ? h("p", { class: "task-user" }, t("health_change_at", row.change_url.url.replace(/^https:\/\//, ""))) : null,
      !row.blocked && totp
        ? h(
            "ul",
            { class: "perms" },
            h(
              "li",
              { class: "perm" },
              h("span", { class: "perm-line" }, h("span", { class: "perm-name" }, t("perm_totp")), h("span", { class: "perm-tag" }, t("task_added_by_klav"))),
              warn ? h("p", { class: "perm-warn" }, t(warn)) : null,
            ),
          )
        : null,
    );
  });

  const select = h(
    "select",
    { class: "input task-select", "aria-label": t("task_shorten") },
    ...offerSteps().map((s) => h("option", { value: String(s) }, duration(s))),
  );
  const until = h("span", { class: "sub" });
  const showUntil = (): void => {
    until.textContent = t("health_until", clock(Date.now() + Number(select.value) * 1000));
  };
  select.addEventListener("change", showUntil);
  showUntil();

  const actions = h("div", { class: "approval-actions" });
  const back = h("button", { class: "btn", type: "button" }, t("health_cancel"));
  back.addEventListener("click", cancel);
  const approve = h("button", { class: "btn btn-primary", type: "button", disabled: !offer.agent }, touchId ? t("approve_touch_id") : t("approve"));
  const send = (password?: string): void => {
    const agent = offer.agent;
    if (!agent) return;
    const request = offerRequest(agent.id, offer.rows, (id) => boxes.get(id)?.checked ?? false, Number(select.value));
    for (const b of actions.querySelectorAll("button")) b.disabled = true;
    daemon<TaskCard>({ op: "offer_task", offer: request, ...(password ? { password } : {}) }).then(done, (e: unknown) => {
      failure(message, e);
      actions.replaceChildren(approve, back);
      approve.disabled = back.disabled = false;
    });
  };
  approve.addEventListener("click", () => {
    if (pickedItems(offer.rows, (id) => boxes.get(id)?.checked ?? false).length === 0) {
      message.replaceChildren(h("p", { class: "notice", role: "alert" }, t("health_nothing")));
      return;
    }
    message.replaceChildren();
    presence(actions, touchId, send, [back]);
  });
  actions.append(approve, back);

  const stripe = ditherCanvas(document, band(), { palette: "blue", pixel: 2 });
  requestAnimationFrame(() => {
    stripe.repaint();
  });
  return h(
    "div",
    { class: "approval task health-offer", role: "group", "aria-label": t("health_fix") },
    h("div", { class: "approval-band" }, stripe.canvas),
    h(
      "div",
      { class: "approval-body" },
      h("p", { class: "agent-mark" }, t("health_fix")),
      h("p", { class: "approval-reason" }, t("health_fix_lede")),
      agentLine(),
      h("ul", { class: "task-rows" }, ...rows),
      h("p", { class: "perm-warn health-rotate-warn" }, t("health_rotate_warn")),
      h("label", { class: "task-time" }, h("span", { class: "field-label" }, t("task_shorten")), h("span", { class: "task-time-line" }, select, until)),
      message,
      actions,
    ),
  );
}

// ------------------------------------------------------ the running task --

function progressCard(progress: TaskProgress): HTMLElement {
  const card = progress.card;
  const n = progressCounts(progress.sites);
  const stripe = ditherCanvas(document, band(), { palette: "blue", pixel: 2 });
  requestAnimationFrame(() => {
    stripe.repaint();
  });
  return h(
    "div",
    { class: "approval task task-live health-progress", role: "group", "aria-label": card?.task ?? "" },
    h("div", { class: "approval-band" }, stripe.canvas),
    h(
      "div",
      { class: "approval-body" },
      h("p", { class: "agent-mark" }, t("health_running", card?.agent ?? "")),
      h("p", { class: "task-name" }, card?.task ?? ""),
      h("p", { class: "sub" }, t("health_counts", n.changed, n.pending, n.failed), card?.expires_at ? ` · ${t("health_until", clock(card.expires_at))}` : ""),
      h(
        "ul",
        { class: "task-covers" },
        ...progress.sites.map((s) =>
          h(
            "li",
            { class: `task-cover site-${s.state}` },
            h("span", { class: "task-title" }, s.title ?? s.reference ?? s.item_id),
            h("span", { class: "task-host" }, `${s.hosts[0] ?? ""} · ${t(siteLabel(s))}`),
          ),
        ),
      ),
    ),
  );
}

// ----------------------------------------------------------------- mount --

export interface MountHooks extends Pick<HealthHooks, "tile" | "open"> {
  /** A short message at the bottom of the popup. */
  say: (text: string) => void;
}

/**
 * Fills `root` with «Salud» and keeps the running fix tasks' progress up
 * to date while it is on screen. Returns what to call when leaving.
 */
export function mountHealth(root: HTMLElement, status: DaemonStatus, hooks: MountHooks): () => void {
  const progress = h("div", { class: "health-running" });
  const body = h("div", { class: "health-body" }, h("p", { class: "sub" }, t("health_checking")));
  root.append(progress, body);
  let gone = false;

  const refreshProgress = async (): Promise<void> => {
    try {
      const cards = await daemon<TaskCard[]>({ op: "tasks", all: false });
      const now = Date.now();
      const all = await Promise.all(cards.filter((c) => isFixTask(c, now)).map((c) => daemon<TaskProgress>({ op: "task_progress", task: c.id })));
      if (!gone) progress.replaceChildren(...all.map(progressCard));
    } catch {
      // Progress is optional here.
    }
  };
  const timer = window.setInterval(() => void refreshProgress(), PROGRESS_EVERY_MS);

  const load = async (): Promise<void> => {
    try {
      const [report, settings] = await Promise.all([
        daemon<VaultHealth>({ op: "vault_health" }),
        daemon<HealthSettingsView>({ op: "health_settings" }).catch(() => undefined),
      ]);
      if (gone) return;
      body.replaceChildren(
        healthSections(report, settings, {
          ...(hooks.tile ? { tile: hooks.tile } : {}),
          ...(hooks.open ? { open: hooks.open } : {}),
          fix: () => void showOffer(),
          breach: async (on) => {
            await daemon<HealthSettingsView>({ op: "health_settings", breach_check: on });
            body.replaceChildren(h("p", { class: "sub" }, t("health_checking")));
            await load();
          },
        }),
      );
    } catch (e) {
      if (gone) return;
      const slot = h("div", {});
      failure(slot, e);
      body.replaceChildren(slot);
    }
  };

  const showOffer = async (agent?: string): Promise<void> => {
    let offer: ReusedOffer;
    try {
      offer = await daemon<ReusedOffer>({ op: "reused_offer", ...(agent ? { agent } : {}) });
    } catch (e) {
      const slot = h("div", {});
      failure(slot, e);
      body.prepend(slot);
      return;
    }
    if (gone) return;
    body.replaceChildren(
      offerCard(
        offer,
        status,
        (picked) => void showOffer(picked),
        (card) => {
          hooks.say(t("health_offered", card.agent));
          void refreshProgress();
          void load();
        },
        () => void load(),
      ),
    );
    body.querySelector<HTMLElement>(".health-offer")?.scrollIntoView({ block: "start" });
  };

  void load();
  void refreshProgress();
  return () => {
    gone = true;
    window.clearInterval(timer);
  };
}
