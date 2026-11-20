/**
 * Task requests in the popup (ADR 0021): one card for a whole job, as the
 * person's client completed it (titles and sites from the vault, a TOTP
 * Klav added, what the policy denies struck through), and the running
 * task with what is left of it and «End task».
 *
 * The running task's band is the time: the blue dither shrinks from the
 * top as the task runs out.
 */
import { band, ditherCanvas } from "../shared/dither";
import { type MessageKey, locale, t } from "../shared/i18n";
import { daemon } from "../shared/messages";
import { DaemonError, type DaemonStatus, type Permission, type TaskCard, type TaskChoice } from "../shared/protocol";
import { presence } from "./presence";
import { h } from "./dom";
import { errorText } from "./strings";

export const NAMES: Partial<Record<Permission, MessageKey>> = {
  fill: "perm_fill",
  totp: "perm_totp",
  inject: "perm_inject",
  update: "perm_update",
  passkey: "perm_passkey",
  rotate: "perm_rotate",
};

export const WARNINGS: Partial<Record<Permission, MessageKey>> = {
  totp: "task_warn_totp",
  passkey: "task_warn_passkey",
  rotate: "task_warn_rotate",
};

/** Shorter durations the person can pick (never longer than asked). */
export const STEPS = [15 * 60, 30 * 60, 3600, 2 * 3600, 4 * 3600, 8 * 3600, 24 * 3600];

export function duration(secs: number): string {
  const mins = Math.max(0, Math.round(secs / 60));
  if (mins < 60) return `${String(mins)} min`;
  const rest = mins % 60;
  return rest ? `${String(Math.floor(mins / 60))} h ${String(rest)} min` : `${String(mins / 60)} h`;
}

export function clock(ms: number): string {
  return new Intl.DateTimeFormat(locale(), { hour: "2-digit", minute: "2-digit" }).format(new Date(ms));
}

/**
 * What the person changed against the proposal: unchecked items and
 * permissions go in `without`, checked ones Klav offered unchecked in
 * `with`.
 */
export function choiceOf(card: TaskCard, checked: (item: string, permission: Permission) => boolean, forSecs?: number): TaskChoice {
  const choice: TaskChoice = { without: [], with: [] };
  for (const row of card.rows) {
    for (const p of row.permissions) {
      if (blockedPermission(row, p)) continue;
      const now = checked(row.item_id, p.permission);
      if (p.checked && !now) choice.without.push([row.item_id, p.permission]);
      if (!p.checked && now) choice.with.push([row.item_id, p.permission]);
    }
  }
  if (forSecs !== undefined && forSecs < card.duration_secs) choice.for_secs = forSecs;
  return choice;
}

/** What never gets checked (T92, ADR 0030 §6): a policy deny, a missing item, a site that does not match, no site. */
export function blockedPermission(row: TaskCard["rows"][number], p: TaskCard["rows"][number]["permissions"][number]): boolean {
  return p.denied_by_policy || p.no_site === true || row.missing || row.domain_mismatch;
}

interface Shown {
  el: HTMLElement;
  paint: () => void;
  tick?: () => void;
}

export function failure(message: HTMLElement, e: unknown): void {
  const error = e instanceof DaemonError ? e : new DaemonError("internal", "error");
  message.replaceChildren(h("p", { class: "notice", role: "alert" }, errorText(error.code, error.message)));
}

/** A pending task: the card to approve, with its rows and the duration. */
export function pendingTask(card: TaskCard, status: DaemonStatus, done: () => void): Shown {
  const touchId = status.touch_id.available && status.touch_id.enrolled && !status.touch_id.password_required;
  const boxes = new Map<string, HTMLInputElement>();
  const key = (item: string, p: Permission): string => `${item}:${p}`;
  const message = h("div", {});

  const rows = card.rows.map((row) => {
    const title = row.title ?? row.reference;
    const usable = row.permissions.filter((p) => !blockedPermission(row, p));
    const all = h("input", {
      type: "checkbox",
      class: "check",
      "aria-label": title,
      disabled: usable.length === 0,
    });
    const sync = (): void => {
      const states = usable.map((p) => boxes.get(key(row.item_id, p.permission))?.checked ?? false);
      all.checked = states.length > 0 && states.every(Boolean);
      all.indeterminate = states.some(Boolean) && !all.checked;
    };
    const perms = row.permissions.map((p) => {
      const name = t(NAMES[p.permission] ?? "perm_fill");
      const blocked = blockedPermission(row, p);
      const box = h("input", { type: "checkbox", class: "check", disabled: blocked });
      box.checked = p.checked && !blocked;
      boxes.set(key(row.item_id, p.permission), box);
      box.addEventListener("change", sync);
      const warning = WARNINGS[p.permission];
      return h(
        "li",
        { class: blocked ? "perm is-blocked" : "perm" },
        h(
          "label",
          { class: "perm-line" },
          box,
          h("span", { class: "perm-name" }, NAMES[p.permission] ? name : p.permission),
          p.added_by_klav ? h("span", { class: "perm-tag" }, t("task_added_by_klav")) : null,
          p.denied_by_policy ? h("span", { class: "perm-why" }, t("task_denied_by_policy")) : null,
          !p.denied_by_policy && p.no_site ? h("span", { class: "perm-why" }, t("task_no_site")) : null,
        ),
        warning && !blocked ? h("p", { class: "perm-warn" }, t(warning)) : null,
      );
    });
    all.addEventListener("change", () => {
      for (const p of usable) {
        const box = boxes.get(key(row.item_id, p.permission));
        if (box) box.checked = all.checked;
      }
      all.indeterminate = false;
    });
    sync();
    const where = row.domains.join(", ");
    return h(
      "li",
      { class: "task-row" },
      h(
        "label",
        { class: "task-item" },
        all,
        h("span", { class: "task-title" }, title),
        where ? h("span", { class: "task-host" }, row.domain_claimed ? t("task_host_claimed", where) : where) : null,
      ),
      row.username ? h("p", { class: "task-user" }, row.username) : null,
      row.missing ? h("p", { class: "task-flag" }, t("task_missing")) : null,
      row.domain_mismatch ? h("p", { class: "task-flag" }, t("task_site_mismatch", row.asked_domain ?? "?")) : null,
      row.no_site ? h("p", { class: "task-flag" }, t("task_no_site_row")) : null,
      h("ul", { class: "perms" }, ...perms),
    );
  });

  const steps = [card.duration_secs, ...STEPS.filter((s) => s < card.duration_secs && s >= 5 * 60).reverse()];
  const select = h(
    "select",
    { class: "input task-select", "aria-label": t("task_shorten") },
    ...steps.map((s) => h("option", { value: String(s) }, duration(s))),
  );
  const until = h("span", { class: "sub" });
  const showUntil = (): void => {
    until.textContent = t("task_lasts", duration(Number(select.value)), clock(Date.now() + Number(select.value) * 1000));
  };
  select.addEventListener("change", showUntil);
  showUntil();

  const actions = h("div", { class: "approval-actions" });
  const decide = (approve: boolean, password?: string): void => {
    const choice = choiceOf(card, (item, p) => boxes.get(key(item, p))?.checked ?? false, Number(select.value));
    for (const b of actions.querySelectorAll("button")) b.disabled = true;
    daemon<TaskCard>({
      op: "decide_task",
      task: card.id,
      approve,
      digest: card.request_digest,
      ...(approve ? { choice } : {}),
      ...(password ? { password } : {}),
    }).then(
      done,
      (e: unknown) => {
        failure(message, e);
        for (const b of actions.querySelectorAll("button")) b.disabled = false;
      },
    );
  };
  const approve = h("button", { class: "btn btn-primary", type: "button" }, touchId ? t("approve_touch_id") : t("approve"));
  const deny = h("button", { class: "btn", type: "button" }, t("deny"));
  approve.addEventListener("click", () => {
    if (![...boxes.values()].some((b) => b.checked)) {
      message.replaceChildren(h("p", { class: "notice", role: "alert" }, t("task_nothing")));
      return;
    }
    message.replaceChildren();
    presence(actions, touchId, (password) => {
      decide(true, password);
    }, [deny]);
  });
  deny.addEventListener("click", () => {
    decide(false);
  });
  actions.append(approve, deny);

  const stripe = ditherCanvas(document, band(), { palette: "blue", pixel: 2 });
  const el = h(
    "li",
    { class: "approval task cross" },
    h("div", { class: "approval-band" }, stripe.canvas),
    h(
      "div",
      { class: "approval-body" },
      h("p", { class: "agent-mark" }, t("task_asks", card.agent)),
      h("p", { class: "task-name" }, card.task),
      h("p", { class: "approval-reason" }, t("quote", card.reason)),
      h("p", { class: "task-said" }, t("task_by_agent")),
      h("ul", { class: "task-rows" }, ...rows),
      h("label", { class: "task-time" }, h("span", { class: "field-label" }, t("task_shorten")), h("span", { class: "task-time-line" }, select, until)),
      message,
      actions,
    ),
  );
  return {
    el,
    paint: () => {
      stripe.repaint();
    },
  };
}

/** A running task: what it covers, what is left of it, «End task». */
export function liveTask(card: TaskCard, done: () => void): Shown {
  // From the request, not `decided_at`: each «Add to the task» signs a new
  // `decided_at` with the same end, and the band must not refill.
  const total = Math.max(1, (card.expires_at ?? 0) - card.created_at);
  const spent = h("div", { class: "task-spent" });
  const left = h("p", { class: "sub" });
  const tick = (): void => {
    const remaining = Math.max(0, (card.expires_at ?? 0) - Date.now());
    left.textContent = t("task_left", duration(remaining / 1000), clock(card.expires_at ?? 0));
    spent.style.height = `${String(Math.min(100, Math.round((1 - remaining / total) * 100)))}%`;
  };
  tick();
  const message = h("div", {});
  const end = h("button", { class: "btn btn-s", type: "button" }, t("task_end"));
  end.addEventListener("click", () => {
    end.disabled = true;
    daemon<TaskCard>({ op: "end_task", task: card.id }).then(done, (e: unknown) => {
      failure(message, e);
      end.disabled = false;
    });
  });
  const covers = card.rows
    .filter((r) => r.permissions.some((p) => p.checked))
    .map((r) =>
      h(
        "li",
        { class: "task-cover" },
        h("span", { class: "task-title" }, r.title ?? r.reference),
        h(
          "span",
          { class: "task-host" },
          r.permissions
            .filter((p) => p.checked)
            .map((p) => t(NAMES[p.permission] ?? "perm_fill"))
            .join(", "),
        ),
      ),
    );
  const stripe = ditherCanvas(document, band(), { palette: "blue", pixel: 2 });
  const el = h(
    "li",
    { class: "approval task task-live" },
    h("div", { class: "approval-band task-band" }, stripe.canvas, spent),
    h(
      "div",
      { class: "approval-body" },
      h("p", { class: "agent-mark" }, t("task_running", card.agent)),
      h("p", { class: "task-name" }, card.task),
      left,
      h("ul", { class: "task-covers" }, ...covers),
      message,
      h("div", { class: "approval-actions" }, end),
    ),
  );
  return {
    el,
    paint: () => {
      stripe.repaint();
    },
    tick,
  };
}
