import { describe, expect, it } from "vitest";
import type { Permission, TaskCard, TaskCardPermission, TaskCardRow } from "../src/shared/protocol";
import { blockedPermission, choiceOf, duration } from "../src/ui/tasks";

const perm = (permission: Permission, over: Partial<TaskCardPermission> = {}): TaskCardPermission => ({
  permission,
  checked: true,
  asked: true,
  added_by_klav: false,
  denied_by_policy: false,
  ...over,
});

const card: TaskCard = {
  id: "t1",
  status: "pending",
  agent_id: "a1",
  agent: "facturas",
  task: "Descargar las facturas de octubre",
  reason: "lo pidió la persona",
  duration_secs: 3600,
  created_at: 0,
  decide_by: 600_000,
  revision: 0,
  request_digest: "00",
  rows: [
    {
      vault_id: "v",
      project_id: "p",
      item_id: "i1",
      reference: "klav://v/p/i1",
      title: "CFE",
      missing: false,
      domain_mismatch: false,
      domains: ["cfe.mx"],
      permissions: [perm("fill"), perm("totp", { asked: false, added_by_klav: true })],
    },
    {
      vault_id: "v",
      project_id: "p",
      item_id: "i2",
      reference: "klav://v/p/i2",
      title: "Banco",
      missing: false,
      domain_mismatch: false,
      domains: ["banco.mx"],
      permissions: [perm("fill"), perm("passkey", { checked: false }), perm("update", { checked: false, denied_by_policy: true })],
    },
    {
      vault_id: "v",
      project_id: "p",
      item_id: "i3",
      reference: "klav://v/p/i3",
      missing: true,
      domain_mismatch: false,
      domains: [],
      permissions: [perm("fill", { checked: false })],
    },
  ],
};

describe("choiceOf", () => {
  it("sends nothing when the person changes nothing", () => {
    const as = (item: string, p: Permission): boolean =>
      card.rows.find((r) => r.item_id === item)?.permissions.find((x) => x.permission === p)?.checked ?? false;
    expect(choiceOf(card, as, 3600)).toEqual({ without: [], with: [] });
  });

  it("puts what was unchecked in `without` and what was checked by hand in `with`", () => {
    const now: Record<string, boolean> = { "i1:fill": true, "i1:totp": false, "i2:fill": true, "i2:passkey": true };
    expect(choiceOf(card, (item, p) => now[`${item}:${p}`] ?? false, 1800)).toEqual({
      without: [["i1", "totp"]],
      with: [["i2", "passkey"]],
      for_secs: 1800,
    });
  });

  it("never sends what the policy denies or an item the vault lacks", () => {
    const choice = choiceOf(card, () => true);
    expect(choice.with).toEqual([["i2", "passkey"]]);
    expect(choice.without).toEqual([]);
  });
});

describe("rows that cannot be approved (T92, ADR 0030 §6)", () => {
  const base: TaskCardRow = {
    vault_id: "v",
    project_id: "p",
    item_id: "m",
    reference: "klav://v/p/m",
    missing: false,
    domain_mismatch: true,
    domains: ["banco.mx"],
    permissions: [perm("fill", { checked: false })],
  };
  const mismatch = base;
  const noSite: TaskCardRow = {
    ...base,
    item_id: "n",
    domain_mismatch: false,
    no_site: true,
    domains: [],
    permissions: [perm("fill", { checked: false, no_site: true }), perm("inject")],
  };
  const [fill, inject] = noSite.permissions as [TaskCardPermission, TaskCardPermission];

  it("never ticks a row whose site does not match, nor fill without a site", () => {
    expect(blockedPermission(mismatch, base.permissions[0] as TaskCardPermission)).toBe(true);
    expect(blockedPermission(noSite, fill)).toBe(true);
    expect(blockedPermission(noSite, inject)).toBe(false);
    expect(choiceOf({ ...card, rows: [mismatch, noSite] }, () => true)).toEqual({ without: [], with: [] });
  });
});

describe("duration", () => {
  it("reads in minutes, then hours", () => {
    expect(duration(15 * 60)).toBe("15 min");
    expect(duration(3600)).toBe("1 h");
    expect(duration(5400)).toBe("1 h 30 min");
  });
});
