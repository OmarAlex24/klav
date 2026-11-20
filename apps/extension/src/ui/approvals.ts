/**
 * Agents' pending requests (`ask` in their policy) and task requests
 * (ADR 0021), decided from the popup. Approving asks klavd for presence:
 * Touch ID, or the master password when Touch ID is not available
 * (ADR 0014). Blue marks what agents do.
 */
import { band, ditherCanvas } from "../shared/dither";
import { type MessageKey, t, tNodes } from "../shared/i18n";
import { daemon } from "../shared/messages";
import { type ApprovalView, DaemonError, type DaemonStatus, type Permission, type TaskCard } from "../shared/protocol";
import { h } from "./dom";
import { presence } from "./presence";
import { describeTarget, errorText } from "./strings";
import { liveTask, pendingTask } from "./tasks";

const WANTS: Record<Permission, MessageKey> = {
  list: "want_list",
  fill: "want_fill",
  inject: "want_inject",
  totp: "want_totp",
  reveal: "want_reveal",
  create: "want_create",
  update: "want_update",
  delete: "want_delete",
  passkey: "want_passkey",
  rotate: "want_rotate",
};

/** «Quiere rellenar **GitHub**», with the title in bold. The site the agent names goes apart, as its claim. */
function wants(permission: Permission, title: HTMLElement): (Node | string)[] {
  return tNodes(WANTS[permission], title);
}

interface Shown {
  el: HTMLElement;
  paint: () => void;
  tick?: () => void;
}

/**
 * One request. When a task of the same agent is running, the card says it
 * falls outside that task and, where the ADR allows it, offers «Add to the
 * task» (ADR 0021 §6): [Deny] [Approve once] [Add to the task].
 */
function card(approval: ApprovalView, status: DaemonStatus, done: () => void): Shown {
  const target = describeTarget(approval.target);
  const touchId = status.touch_id.available && status.touch_id.enrolled && !status.touch_id.password_required;
  const task = approval.task;
  const message = h("div", {});
  const actions = h("div", { class: "approval-actions" });
  const settle = (call: Promise<unknown>): void => {
    for (const b of actions.querySelectorAll("button")) b.disabled = true;
    call.then(done, (e: unknown) => {
      const error = e instanceof DaemonError ? e : new DaemonError("internal", "error");
      message.replaceChildren(h("p", { class: "notice", role: "alert" }, errorText(error.code, error.message)));
      for (const b of actions.querySelectorAll("button")) b.disabled = false;
    });
  };
  const decide = (approve: boolean, password?: string): void => {
    settle(
      daemon<ApprovalView>({
        op: "decide_approval",
        approval: approval.id,
        approve,
        digest: approval.request_digest,
        ...(password ? { password } : {}),
      }),
    );
  };
  const addToTask = (password?: string): void => {
    settle(daemon<TaskCard>({ op: "add_to_task", approval: approval.id, digest: approval.request_digest, ...(password ? { password } : {}) }));
  };
  const approveLabel = task ? t("approve_once") : touchId ? t("approve_touch_id") : t("approve");
  const approve = h("button", { class: "btn btn-primary", type: "button" }, approveLabel);
  const deny = h("button", { class: "btn", type: "button" }, t("deny"));
  approve.addEventListener("click", () => {
    presence(actions, touchId, (password) => {
      decide(true, password);
    }, [deny]);
  });
  deny.addEventListener("click", () => {
    decide(false);
  });
  if (task) {
    actions.classList.add("approval-actions-wrap");
    actions.append(deny, approve);
    if (task.can_add) {
      const add = h("button", { class: "btn", type: "button" }, t("add_to_task"));
      add.addEventListener("click", () => {
        presence(actions, touchId, addToTask, [deny]);
      });
      actions.append(add);
    }
  } else {
    actions.append(approve, deny);
  }
  const stripe = ditherCanvas(document, band(), { palette: "blue", pixel: 2 });
  const el = h(
    "li",
    { class: "approval cross" },
    h("div", { class: "approval-band" }, stripe.canvas),
    h(
      "div",
      { class: "approval-body" },
      h("p", { class: "agent-mark" }, t("agent_waits", approval.agent)),
      task ? h("p", { class: "approval-outside" }, t("task_outside", task.task)) : null,
      h("p", { class: "approval-what" }, ...wants(approval.permission, h("strong", {}, target.title))),
      target.where ? h("p", { class: "sub" }, target.where) : null,
      approval.domain ? h("p", { class: "approval-site" }, t("site_claimed", approval.domain)) : null,
      h("p", { class: "approval-reason" }, t("quote", approval.reason)),
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

/**
 * Fills `section` with the pending task requests, the pending approvals
 * and the running tasks, and keeps it current while the popup is open.
 * A card that is still there keeps its element, so boxes the person has
 * unchecked survive the next poll. `quiet` says when klavd may be asked:
 * these requests go to the server and hold klavd meanwhile, so the popup
 * keeps them away from a search being typed.
 */
export function watchApprovals(section: HTMLElement, status: DaemonStatus, quiet: () => boolean = () => true): void {
  let shown = "";
  let kept = new Map<string, Shown>();
  let retry: ReturnType<typeof setTimeout> | undefined;
  const refresh = async (): Promise<void> => {
    if (!section.isConnected) return;
    if (!quiet()) {
      retry ??= setTimeout(() => {
        retry = undefined;
        void refresh();
      }, 250);
      return;
    }
    let pending: ApprovalView[];
    let tasks: TaskCard[];
    try {
      [pending, tasks] = await Promise.all([
        daemon<ApprovalView[]>({ op: "approvals", all: false }),
        daemon<TaskCard[]>({ op: "tasks", all: false }).catch((): TaskCard[] => []),
      ]);
    } catch {
      return;
    }
    const now = Date.now();
    const again = (): void => void refresh();
    const wanted: [string, () => Shown][] = [
      ...tasks.filter((c) => c.status === "pending").map((c): [string, () => Shown] => [`ask:${c.id}:${c.request_digest}`, () => pendingTask(c, status, again)]),
      ...pending.map((a): [string, () => Shown] => [`approval:${a.id}:${a.request_digest}:${a.task?.id ?? ""}:${String(a.task?.can_add ?? false)}`, () => card(a, status, again)]),
      ...tasks
        .filter((c) => c.status === "approved" && (c.expires_at ?? 0) > now)
        .map((c): [string, () => Shown] => [`live:${c.id}:${String(c.revision)}`, () => liveTask(c, again)]),
    ];
    const key = wanted.map(([k]) => k).join(",");
    if (key === shown) return;
    shown = key;
    const next = new Map<string, Shown>();
    for (const [k, make] of wanted) next.set(k, kept.get(k) ?? make());
    kept = next;
    if (next.size === 0) {
      section.replaceChildren();
      return;
    }
    const cards = [...next.values()];
    section.replaceChildren(h("ul", { class: "approvals" }, ...cards.map((c) => c.el)));
    for (const c of cards) c.paint();
  };
  void refresh();
  const timer = setInterval(() => {
    if (!section.isConnected) {
      clearInterval(timer);
      return;
    }
    for (const c of kept.values()) c.tick?.();
    void refresh();
  }, 3_000);
  addEventListener("pagehide", () => {
    clearInterval(timer);
    clearTimeout(retry);
  });
}
